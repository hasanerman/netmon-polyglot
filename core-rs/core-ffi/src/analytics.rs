use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use netcore_engine::{Alert, AlertSource, FlowKey, FlowStats, Severity};
use netcore_grpc::proto::{AnomalyScore, FlowBatch, FlowFeatures};
use netcore_grpc::{AnalyticsLink, LinkState};

use crate::core::Shared;
use crate::types::{CoreError, NcStatus};

pub const EXPORT_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_FLOWS_PER_BATCH: usize = 20_000;
const STOP_POLL: Duration = Duration::from_millis(50);
const HIGH_SEVERITY_MARGIN: f64 = 0.1;
pub const ANOMALY_RULE_ID: &str = "ml-anomaly";
pub const ANOMALY_COOLDOWN_US: u64 = 15_000_000;
const MAX_COOLDOWN_HOSTS: usize = 10_000;

pub struct Analytics {
    link: Arc<AnalyticsLink>,
    stop: Arc<AtomicBool>,
    exporter: Option<JoinHandle<()>>,
}

impl Analytics {
    pub fn start(endpoint: &str, shared: Arc<Shared>) -> Result<Self, CoreError> {
        let link = Arc::new(AnalyticsLink::start(endpoint).map_err(|e| CoreError::new(NcStatus::InvalidArg, e.to_string()))?);
        let stop = Arc::new(AtomicBool::new(false));
        let exporter = Exporter {
            link: Arc::clone(&link),
            shared,
            stop: Arc::clone(&stop),
            last_export_us: 0,
            batch_id: 0,
            cooldown: Cooldown::default(),
        };
        let handle = thread::Builder::new()
            .name("analytics-export".into())
            .spawn(move || exporter.run())
            .map_err(|e| CoreError::new(NcStatus::Capture, format!("cannot start exporter: {e}")))?;
        Ok(Analytics {
            link,
            stop,
            exporter: Some(handle),
        })
    }

    pub fn state(&self) -> LinkState {
        self.link.state()
    }

    pub fn sent(&self) -> u64 {
        self.link.sent()
    }

    pub fn dropped(&self) -> u64 {
        self.link.dropped()
    }
}

impl Drop for Analytics {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.exporter.take() {
            let _ = handle.join();
        }
    }
}

struct Exporter {
    link: Arc<AnalyticsLink>,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    last_export_us: u64,
    batch_id: u64,
    cooldown: Cooldown,
}

#[derive(Default)]
pub struct Cooldown {
    last_alert_us: HashMap<String, u64>,
}

impl Cooldown {
    pub fn admit(&mut self, host: &str, ts_us: u64) -> bool {
        match self.last_alert_us.get(host) {
            Some(&last) if ts_us >= last && ts_us - last < ANOMALY_COOLDOWN_US => false,
            _ => {
                if self.last_alert_us.len() >= MAX_COOLDOWN_HOSTS {
                    self.last_alert_us.clear();
                }
                self.last_alert_us.insert(host.to_string(), ts_us);
                true
            }
        }
    }
}

impl Exporter {
    fn run(mut self) {
        while self.sleep_interval() {
            self.export();
            for score in self.link.drain_scores() {
                if self.cooldown.admit(&score.host, score.ts_us) {
                    self.shared.push_alert(to_alert(&score));
                }
            }
        }
    }

    fn sleep_interval(&self) -> bool {
        let mut waited = Duration::ZERO;
        while waited < EXPORT_INTERVAL {
            if self.stop.load(Ordering::Relaxed) {
                return false;
            }
            thread::sleep(STOP_POLL);
            waited += STOP_POLL;
        }
        !self.stop.load(Ordering::Relaxed)
    }

    fn export(&mut self) {
        if self.link.state() != LinkState::Connected {
            return;
        }
        let (flows, window_end) = self.shared.with_engine(|engine| {
            // yeni capture baslayinca zaman geri gidebilir
            if engine.last_ts_us() < self.last_export_us {
                self.last_export_us = 0;
            }
            let since = self.last_export_us;
            let flows: Vec<FlowFeatures> = engine
                .flows()
                .iter()
                .filter(|(_, s)| s.last_seen_us > since)
                .take(MAX_FLOWS_PER_BATCH)
                .map(|(k, s)| features(k, s))
                .collect();
            (flows, engine.last_ts_us())
        });
        if flows.is_empty() {
            return;
        }
        self.last_export_us = window_end;
        self.batch_id += 1;
        self.link.offer(FlowBatch {
            batch_id: self.batch_id,
            window_end_us: window_end,
            flows,
        });
    }
}

pub fn features(key: &FlowKey, stats: &FlowStats) -> FlowFeatures {
    // yuksek port genelde istemcidir; icmp gibi portsuzda cok gonderen taraf
    let client_is_b = match key.b.port.cmp(&key.a.port) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => stats.packets[1] > stats.packets[0],
    };
    let (client, server, fwd, rev) = if client_is_b { (key.b, key.a, 1, 0) } else { (key.a, key.b, 0, 1) };
    FlowFeatures {
        src: client.addr.to_string(),
        dst: server.addr.to_string(),
        src_port: u32::from(client.port),
        dst_port: u32::from(server.port),
        proto: u32::from(key.proto),
        packets_fwd: stats.packets[fwd],
        packets_rev: stats.packets[rev],
        bytes_fwd: stats.bytes[fwd],
        bytes_rev: stats.bytes[rev],
        duration_us: stats.duration_us(),
        tcp_flags: u32::from(stats.tcp_flags),
        last_seen_us: stats.last_seen_us,
    }
}

pub fn to_alert(score: &AnomalyScore) -> Alert {
    let severity = if score.score >= score.threshold + HIGH_SEVERITY_MARGIN {
        Severity::High
    } else {
        Severity::Medium
    };
    Alert {
        ts_us: score.ts_us,
        source: AlertSource::Anomaly,
        severity,
        rule_id: ANOMALY_RULE_ID.to_string(),
        message: format!("{}: anomaly score {:.2} ({})", score.host, score.score, score.reason),
        src: score.host.parse::<IpAddr>().ok(),
        score: score.score,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use netcore_engine::{Endpoint, FlowKey, FlowStats};

    use super::*;

    fn ep(last: u8, port: u16) -> Endpoint {
        Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        }
    }

    #[test]
    fn flow_is_oriented_from_the_ephemeral_side() {
        let (key, _) = FlowKey::canonical(ep(66, 49152), ep(5, 22), 6);
        assert_eq!(key.a.addr, ep(5, 22).addr);
        let stats = FlowStats {
            packets: [3, 1],
            bytes: [300, 60],
            tcp_flags: 0x02,
            ..FlowStats::default()
        };
        let f = features(&key, &stats);
        assert_eq!((f.src.as_str(), f.src_port, f.dst.as_str(), f.dst_port), ("10.0.0.66", 49152, "10.0.0.5", 22));
        assert_eq!((f.packets_fwd, f.packets_rev, f.bytes_fwd, f.bytes_rev), (1, 3, 60, 300));
    }

    #[test]
    fn portless_flow_is_oriented_from_the_sender() {
        let (key, dir) = FlowKey::canonical(ep(30, 0), ep(1, 0), 1);
        assert_eq!(key.a.addr, ep(1, 0).addr);
        let mut stats = FlowStats::default();
        stats.packets[dir as usize] = 4;
        let f = features(&key, &stats);
        assert_eq!((f.src.as_str(), f.dst.as_str(), f.packets_fwd), ("10.0.0.30", "10.0.0.1", 4));
    }

    #[test]
    fn cooldown_suppresses_repeats_per_host() {
        let mut c = Cooldown::default();
        assert!(c.admit("a", 0));
        assert!(!c.admit("a", ANOMALY_COOLDOWN_US - 1));
        assert!(c.admit("b", 1));
        assert!(c.admit("a", ANOMALY_COOLDOWN_US));
        assert!(c.admit("a", 5), "time going backwards means a new capture");
    }

    #[test]
    fn scores_become_anomaly_alerts() {
        let score = AnomalyScore {
            host: "10.0.0.66".into(),
            score: 0.75,
            threshold: 0.6,
            reason: "distinct_dst_ports z=40.0".into(),
            ts_us: 9,
            ..AnomalyScore::default()
        };
        let a = to_alert(&score);
        assert_eq!((a.source, a.severity, a.rule_id.as_str()), (AlertSource::Anomaly, Severity::High, ANOMALY_RULE_ID));
        assert_eq!(a.src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66))));
        assert!(a.message.contains("0.75"));
        let mild = to_alert(&AnomalyScore { score: 0.65, ..score });
        assert_eq!(mild.severity, Severity::Medium);
    }
}
