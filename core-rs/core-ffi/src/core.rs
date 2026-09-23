use std::collections::VecDeque;
use std::ffi::c_void;
use std::num::NonZeroUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use netcore_engine::rules::{RuleEngine, RuleSpec};
use netcore_engine::{Alert, Engine, EngineConfig, Frame, LinkType};

mod rules {
    use netcore_engine::rules::{self, RuleSpec, DEFAULT_RULES_YAML};

    use crate::types::{CoreError, NcStatus};

    pub fn parse_builtin() -> Vec<RuleSpec> {
        rules::parse(DEFAULT_RULES_YAML).expect("bundled rules are valid")
    }

    pub fn parse_file(path: &str) -> Result<Vec<RuleSpec>, CoreError> {
        rules::load(std::path::Path::new(path)).map_err(|e| CoreError::new(NcStatus::Rules, e.to_string()))
    }
}

use crate::analytics::Analytics;
use crate::sniffer::{self, Sniffer};
use crate::types::{CoreError, NcAnalyticsState, NcCaptureState, NcConfig, NcFlow, NcStats, NcStatus};
use netcore_grpc::LinkState;

pub const ALERT_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_SNAPLEN: u32 = 65_535;
const MICROS_PER_MILLI: u64 = 1_000;

pub struct Shared {
    engine: Mutex<Engine>,
    alerts: Mutex<VecDeque<Alert>>,
    alerts_total: AtomicU64,
    alerts_dropped: AtomicU64,
}

impl Shared {
    fn ingest(&self, ts_us: u64, wire_len: u32, data: &[u8]) {
        let frame = Frame { ts_us, wire_len, data };
        let alerts = {
            let mut engine = lock(&self.engine);
            // parse hatasi engine sayacinda tutuluyor
            let _ = engine.process(&frame);
            engine.drain_alerts()
        };
        for alert in alerts {
            self.push_alert(alert);
        }
    }

    pub fn with_engine<R>(&self, f: impl FnOnce(&Engine) -> R) -> R {
        f(&lock(&self.engine))
    }

    pub fn push_alert(&self, alert: Alert) {
        self.alerts_total.fetch_add(1, Ordering::Relaxed);
        let mut queue = lock(&self.alerts);
        if queue.len() == ALERT_QUEUE_CAPACITY {
            queue.pop_front();
            self.alerts_dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(alert);
    }
}

pub struct NcCore {
    analytics: Mutex<Option<Analytics>>,
    capture: Mutex<Option<Sniffer>>,
    shared: Arc<Shared>,
    config: EngineConfig,
    snaplen: u32,
    rule_specs: Mutex<Vec<RuleSpec>>,
    last_error: Mutex<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

unsafe extern "C" fn on_frame(frame: *const sniffer::Frame, user: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let (Some(frame), Some(shared)) = (frame.as_ref(), (user as *const Shared).as_ref()) else {
            return;
        };
        let data = if frame.caplen == 0 || frame.data.is_null() {
            &[][..]
        } else {
            slice::from_raw_parts(frame.data, frame.caplen as usize)
        };
        shared.ingest(frame.ts_us, frame.len, data);
    }));
}

fn engine_config(cfg: &NcConfig) -> Result<EngineConfig, CoreError> {
    let mut out = EngineConfig::default();
    if let Some(max) = NonZeroUsize::new(cfg.max_flows as usize) {
        out.max_flows = max;
    }
    if cfg.flow_idle_timeout_ms != 0 {
        out.flow_idle_timeout_us = u64::from(cfg.flow_idle_timeout_ms) * MICROS_PER_MILLI;
    }
    if cfg.top_n != 0 {
        out.top_n = cfg.top_n as usize;
    }
    // 0 = varsayilan ethernet, null link sadece capture'dan gelir
    out.link = match cfg.link_type {
        0 => LinkType::Ethernet,
        raw => LinkType::from_raw(raw).ok_or_else(|| CoreError::new(NcStatus::InvalidArg, format!("unsupported link type {raw}")))?,
    };
    Ok(out)
}

impl NcCore {
    pub fn new(cfg: &NcConfig) -> Result<Self, CoreError> {
        let config = engine_config(cfg)?;
        let specs = rules::parse_builtin();
        Ok(NcCore {
            analytics: Mutex::new(None),
            capture: Mutex::new(None),
            rule_specs: Mutex::new(specs.clone()),
            shared: Arc::new(Shared {
                engine: Mutex::new(Engine::new(config).with_rules(RuleEngine::from_specs(specs))),
                alerts: Mutex::new(VecDeque::new()),
                alerts_total: AtomicU64::new(0),
                alerts_dropped: AtomicU64::new(0),
            }),
            config,
            snaplen: if cfg.snaplen == 0 { DEFAULT_SNAPLEN } else { cfg.snaplen },
            last_error: Mutex::new(String::new()),
        })
    }

    pub fn feed(&self, ts_us: u64, data: &[u8], wire_len: u32) {
        self.shared.ingest(ts_us, wire_len, data);
    }

    pub fn open_live(&self, iface: &str, promisc: bool) -> Result<(), CoreError> {
        self.install(|| Sniffer::open_live(iface, self.snaplen, promisc))
    }

    pub fn open_file(&self, path: &str, realtime: bool) -> Result<(), CoreError> {
        self.install(|| {
            let mut s = Sniffer::open_file(path)?;
            s.set_realtime(realtime)?;
            Ok(s)
        })
    }

    fn install(&self, open: impl FnOnce() -> Result<Sniffer, CoreError>) -> Result<(), CoreError> {
        let mut capture = lock(&self.capture);
        if capture.as_ref().is_some_and(Sniffer::is_running) {
            return Err(CoreError::new(NcStatus::State, "stop the running capture first"));
        }
        *capture = None;

        let mut sniffer = open()?;
        let raw_link = u32::try_from(sniffer.link_type()).unwrap_or(u32::MAX);
        let link = LinkType::from_raw(raw_link)
            .ok_or_else(|| CoreError::new(NcStatus::Format, format!("unsupported link type {raw_link}")))?;

        let rules = RuleEngine::from_specs(lock(&self.rule_specs).clone());
        *lock(&self.shared.engine) = Engine::new(EngineConfig { link, ..self.config }).with_rules(rules);
        let user = Arc::as_ptr(&self.shared) as *mut c_void;
        unsafe { sniffer.set_callback(on_frame, user)? };
        *capture = Some(sniffer);
        Ok(())
    }

    pub fn load_rules(&self, path: &str) -> Result<usize, CoreError> {
        let specs = rules::parse_file(path)?;
        let engine = RuleEngine::from_specs(specs.clone());
        let active = engine.len();
        lock(&self.shared.engine).set_rules(Some(engine));
        *lock(&self.rule_specs) = specs;
        Ok(active)
    }

    pub fn connect_analytics(&self, endpoint: &str) -> Result<(), CoreError> {
        let mut slot = lock(&self.analytics);
        *slot = None;
        *slot = Some(Analytics::start(endpoint, Arc::clone(&self.shared))?);
        Ok(())
    }

    pub fn disconnect_analytics(&self) {
        lock(&self.analytics).take();
    }

    pub fn start(&self) -> Result<(), CoreError> {
        let mut capture = lock(&self.capture);
        let sniffer = capture
            .as_mut()
            .ok_or_else(|| CoreError::new(NcStatus::State, "no capture source opened"))?;
        sniffer.start()
    }

    pub fn stop(&self) -> Result<(), CoreError> {
        let mut capture = lock(&self.capture);
        match capture.as_mut() {
            Some(s) if s.is_running() => s.stop(),
            _ => Err(CoreError::new(NcStatus::State, "capture is not running")),
        }
    }

    pub fn stats(&self) -> NcStats {
        let (counters, flows, evicted, expired, last_ts, rule_count) = {
            let engine = lock(&self.shared.engine);
            let snap = engine.flows();
            let rule_count = engine.rules().map_or(0, RuleEngine::len);
            (*engine.counters(), snap.len(), snap.evicted(), snap.expired(), engine.last_ts_us(), rule_count)
        };
        let mut out = NcStats::from_counters(&counters);
        out.rules_loaded = rule_count as u64;
        out.active_flows = flows as u64;
        out.evicted_flows = evicted;
        out.expired_flows = expired;
        out.last_ts_us = last_ts;
        out.alerts_total = self.shared.alerts_total.load(Ordering::Relaxed);
        out.alerts_dropped = self.shared.alerts_dropped.load(Ordering::Relaxed);
        if let Some(a) = lock(&self.analytics).as_ref() {
            out.analytics_state = match a.state() {
                LinkState::Connected => NcAnalyticsState::Connected,
                LinkState::Connecting | LinkState::Disconnected => NcAnalyticsState::Connecting,
            } as u64;
            out.analytics_sent = a.sent();
            out.analytics_dropped = a.dropped();
        }
        if let Some(s) = lock(&self.capture).as_mut() {
            out.capture_dropped = s.stats().map(|st| st.dropped).unwrap_or(0);
            out.capture_state = self.capture_state(s) as u64;
        }
        out
    }

    fn capture_state(&self, sniffer: &mut Sniffer) -> NcCaptureState {
        if !sniffer.is_running() {
            return NcCaptureState::Idle;
        }
        match sniffer.finished() {
            None => NcCaptureState::Running,
            Some(Ok(())) => NcCaptureState::Finished,
            Some(Err(e)) => {
                self.set_error(&e.message);
                NcCaptureState::Failed
            }
        }
    }

    pub fn top_flows(&self, out: &mut [NcFlow]) -> usize {
        let top = lock(&self.shared.engine).flows().top_by_bytes(out.len());
        for (slot, (key, stats)) in out.iter_mut().zip(&top) {
            *slot = NcFlow::new(key, stats);
        }
        top.len()
    }

    pub fn pop_alert(&self) -> Option<Alert> {
        lock(&self.shared.alerts).pop_front()
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    pub fn set_error(&self, message: &str) {
        let mut e = lock(&self.last_error);
        e.clear();
        e.push_str(message);
    }

    pub fn last_error(&self) -> String {
        lock(&self.last_error).clone()
    }
}

impl Drop for NcCore {
    fn drop(&mut self) {
        // sniffer shared'dan once kapanmali, callback shared'a isaret ediyor
        lock(&self.analytics).take();
        lock(&self.capture).take();
    }
}
