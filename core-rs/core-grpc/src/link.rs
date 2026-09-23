use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};

use crate::proto::analytics_client::AnalyticsClient;
use crate::proto::{AnomalyScore, FlowBatch};

pub const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const BATCH_QUEUE: usize = 8;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
}

impl LinkState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => LinkState::Connecting,
            2 => LinkState::Connected,
            _ => LinkState::Disconnected,
        }
    }
}

#[derive(Debug)]
pub enum LinkError {
    BadEndpoint(String),
    Runtime(std::io::Error),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::BadEndpoint(e) => write!(f, "invalid analytics endpoint: {e}"),
            LinkError::Runtime(e) => write!(f, "cannot start analytics runtime: {e}"),
        }
    }
}

impl std::error::Error for LinkError {}

#[derive(Default)]
struct Counters {
    state: AtomicU8,
    sent: AtomicU64,
    dropped: AtomicU64,
    reconnects: AtomicU64,
}

pub struct AnalyticsLink {
    batches: mpsc::Sender<FlowBatch>,
    scores: Mutex<std_mpsc::Receiver<AnomalyScore>>,
    counters: Arc<Counters>,
    shutdown: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl AnalyticsLink {
    pub fn start(endpoint: &str) -> Result<Self, LinkError> {
        let endpoint = Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| LinkError::BadEndpoint(e.to_string()))?
            .connect_timeout(CONNECT_TIMEOUT);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(LinkError::Runtime)?;

        let (batch_tx, batch_rx) = mpsc::channel(BATCH_QUEUE);
        let (score_tx, score_rx) = std_mpsc::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let counters = Arc::new(Counters::default());

        let worker = Worker {
            endpoint,
            batches: batch_rx,
            scores: score_tx,
            counters: Arc::clone(&counters),
            shutdown: shutdown_rx,
        };
        let handle = std::thread::Builder::new()
            .name("analytics-link".into())
            .spawn(move || runtime.block_on(worker.run()))
            .map_err(LinkError::Runtime)?;

        Ok(AnalyticsLink {
            batches: batch_tx,
            scores: Mutex::new(score_rx),
            counters,
            shutdown: shutdown_tx,
            worker: Some(handle),
        })
    }

    pub fn offer(&self, batch: FlowBatch) -> bool {
        let accepted = self.state() == LinkState::Connected && self.batches.try_send(batch).is_ok();
        if !accepted {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
        accepted
    }

    pub fn drain_scores(&self) -> Vec<AnomalyScore> {
        let rx = self.scores.lock().unwrap_or_else(|p| p.into_inner());
        rx.try_iter().collect()
    }

    pub fn state(&self) -> LinkState {
        LinkState::from_u8(self.counters.state.load(Ordering::Relaxed))
    }

    pub fn sent(&self) -> u64 {
        self.counters.sent.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    pub fn reconnects(&self) -> u64 {
        self.counters.reconnects.load(Ordering::Relaxed)
    }
}

impl Drop for AnalyticsLink {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

struct Worker {
    endpoint: Endpoint,
    batches: mpsc::Receiver<FlowBatch>,
    scores: std_mpsc::Sender<AnomalyScore>,
    counters: Arc<Counters>,
    shutdown: watch::Receiver<bool>,
}

enum Outcome {
    Shutdown,
    Lost,
}

impl Worker {
    async fn run(mut self) {
        let mut backoff = INITIAL_BACKOFF;
        loop {
            self.set_state(LinkState::Connecting);
            if let Ok(channel) = self.endpoint.connect().await {
                self.set_state(LinkState::Connected);
                backoff = INITIAL_BACKOFF;
                if let Outcome::Shutdown = self.stream(channel).await {
                    break;
                }
            }
            self.set_state(LinkState::Disconnected);
            self.counters.reconnects.fetch_add(1, Ordering::Relaxed);
            if let Outcome::Shutdown = self.wait(backoff).await {
                break;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        self.set_state(LinkState::Disconnected);
    }

    async fn stream(&mut self, channel: Channel) -> Outcome {
        let (tx, rx) = mpsc::channel(BATCH_QUEUE);
        let mut client = AnalyticsClient::new(channel);
        let call = client.analyze(ReceiverStream::new(rx));
        tokio::pin!(call);

        // bazi sunucular header'i ilk cevapla yolluyor, beklerken batch akmaya devam etmeli
        let mut responses = loop {
            tokio::select! {
                _ = self.shutdown.changed() => return Outcome::Shutdown,
                batch = self.batches.recv() => {
                    if let Some(outcome) = self.forward(&tx, batch).await {
                        return outcome;
                    }
                }
                started = &mut call => match started {
                    Ok(r) => break r.into_inner(),
                    Err(_) => return Outcome::Lost,
                },
            }
        };

        loop {
            tokio::select! {
                _ = self.shutdown.changed() => return Outcome::Shutdown,
                batch = self.batches.recv() => {
                    if let Some(outcome) = self.forward(&tx, batch).await {
                        return outcome;
                    }
                }
                msg = responses.message() => match msg {
                    Ok(Some(score)) => { let _ = self.scores.send(score); }
                    Ok(None) | Err(_) => return Outcome::Lost,
                },
            }
        }
    }

    async fn forward(&self, tx: &mpsc::Sender<FlowBatch>, batch: Option<FlowBatch>) -> Option<Outcome> {
        let Some(batch) = batch else { return Some(Outcome::Shutdown) };
        if tx.send(batch).await.is_err() {
            return Some(Outcome::Lost);
        }
        self.counters.sent.fetch_add(1, Ordering::Relaxed);
        None
    }

    async fn wait(&mut self, delay: Duration) -> Outcome {
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => return Outcome::Lost,
                _ = self.shutdown.changed() => return Outcome::Shutdown,
                batch = self.batches.recv() => {
                    if batch.is_none() {
                        return Outcome::Shutdown;
                    }
                    self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn set_state(&self, state: LinkState) {
        self.counters.state.store(state as u8, Ordering::Relaxed);
    }
}
