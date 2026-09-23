use std::net::SocketAddr;
use std::pin::Pin;
use std::thread;
use std::time::{Duration, Instant};

use netcore_grpc::proto::analytics_server::{Analytics, AnalyticsServer};
use netcore_grpc::proto::{AnomalyScore, FlowBatch, FlowFeatures, HealthReply, HealthRequest};
use netcore_grpc::{AnalyticsLink, LinkState};
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

const WAIT_LIMIT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(20);

struct Echo;

struct Lazy;

#[tonic::async_trait]
impl Analytics for Lazy {
    type AnalyzeStream = ScoreStream;

    async fn analyze(&self, request: Request<Streaming<FlowBatch>>) -> Result<Response<ScoreStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound.message().await?.ok_or_else(|| Status::cancelled("no batch"))?;
        let score = AnomalyScore {
            batch_id: first.batch_id,
            host: "lazy".into(),
            ..AnomalyScore::default()
        };
        Ok(Response::new(Box::pin(tokio_stream::once(Ok(score)).chain(tokio_stream::pending()))))
    }

    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthReply>, Status> {
        Ok(Response::new(HealthReply::default()))
    }
}

type ScoreStream = Pin<Box<dyn Stream<Item = Result<AnomalyScore, Status>> + Send>>;

#[tonic::async_trait]
impl Analytics for Echo {
    type AnalyzeStream = ScoreStream;

    async fn analyze(&self, request: Request<Streaming<FlowBatch>>) -> Result<Response<ScoreStream>, Status> {
        let stream = request.into_inner().map(|batch| {
            let batch = batch?;
            Ok(AnomalyScore {
                batch_id: batch.batch_id,
                host: batch.flows.first().map(|f| f.src.clone()).unwrap_or_default(),
                score: 0.9,
                threshold: 0.6,
                reason: "echo".into(),
                ts_us: batch.window_end_us,
            })
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthReply>, Status> {
        Ok(Response::new(HealthReply::default()))
    }
}

struct TestServer {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(addr: SocketAddr) -> (Self, SocketAddr) {
        Self::start_with(addr, AnalyticsServer::new(Echo))
    }

    fn start_with<S: Analytics>(addr: SocketAddr, service: AnalyticsServer<S>) -> (Self, SocketAddr) {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let serve = tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming(TcpListenerStream::new(listener));
                // runtime dusunce acik baglantilar da kopar, python cokmesi gibi
                tokio::select! {
                    _ = serve => {}
                    _ = stop_rx => {}
                }
            });
        });
        let bound = addr_rx.recv().unwrap();
        (TestServer { stop: Some(stop_tx), thread: Some(thread) }, bound)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

fn batch(id: u64, src: &str) -> FlowBatch {
    FlowBatch {
        batch_id: id,
        window_end_us: id * 1_000,
        flows: vec![FlowFeatures {
            src: src.into(),
            dst: "10.0.0.5".into(),
            packets_fwd: 1,
            ..FlowFeatures::default()
        }],
    }
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < WAIT_LIMIT {
        if cond() {
            return true;
        }
        thread::sleep(POLL);
    }
    false
}

fn receive_one(link: &AnalyticsLink, id: u64, src: &str) -> AnomalyScore {
    let mut got = Vec::new();
    assert!(wait_for(|| {
        if got.is_empty() {
            link.offer(batch(id, src));
        }
        got.extend(link.drain_scores());
        !got.is_empty()
    }));
    got.remove(0)
}

#[test]
fn server_that_waits_for_first_batch_does_not_deadlock() {
    let (_server, addr) = TestServer::start_with("127.0.0.1:0".parse().unwrap(), AnalyticsServer::new(Lazy));
    let link = AnalyticsLink::start(&format!("http://{addr}")).unwrap();
    assert!(wait_for(|| link.state() == LinkState::Connected));
    let score = receive_one(&link, 3, "10.0.0.1");
    assert_eq!((score.batch_id, score.host.as_str()), (3, "lazy"));
}

#[test]
fn rejects_bad_endpoint() {
    assert!(AnalyticsLink::start("not a uri").is_err());
}

#[test]
fn offers_are_dropped_while_disconnected() {
    let link = AnalyticsLink::start("http://127.0.0.1:1").unwrap();
    assert!(!link.offer(batch(1, "a")));
    assert_eq!(link.dropped(), 1);
    assert_ne!(link.state(), LinkState::Connected);
}

#[test]
fn round_trip_and_reconnect_after_server_restart() {
    let (server, addr) = TestServer::start("127.0.0.1:0".parse().unwrap());
    let link = AnalyticsLink::start(&format!("http://{addr}")).unwrap();
    assert!(wait_for(|| link.state() == LinkState::Connected));

    let score = receive_one(&link, 7, "10.0.0.66");
    assert_eq!((score.batch_id, score.host.as_str(), score.ts_us), (7, "10.0.0.66", 7_000));
    assert!(link.sent() >= 1);

    drop(server);
    assert!(wait_for(|| link.state() != LinkState::Connected));

    let (_server, _) = TestServer::start(addr);
    assert!(wait_for(|| link.state() == LinkState::Connected));
    let score = receive_one(&link, 8, "10.0.0.77");
    assert_eq!(score.host, "10.0.0.77");
    assert!(link.reconnects() >= 1);
}
