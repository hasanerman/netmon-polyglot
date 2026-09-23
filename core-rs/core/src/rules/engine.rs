use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

use super::loader::{RuleKind, RuleSpec};
use super::window::{CountWindow, DistinctWindow};
use crate::alert::{Alert, AlertSource};
use crate::packet::{App, Packet, Transport};

pub const MAX_TRACKED_SOURCES: usize = 10_000;
const MICROS_PER_SEC: f64 = 1_000_000.0;
const LABEL_SEPARATOR: char = '.';

enum Tracker {
    Ports(DistinctWindow<u16>),
    Hosts(DistinctWindow<IpAddr>),
    Count(CountWindow),
}

struct SourceState {
    tracker: Tracker,
    last_fired_us: Option<u64>,
}

pub(super) struct CompiledRule {
    pub(super) spec: RuleSpec,
    window_us: u64,
    cooldown_us: u64,
    sources: LruCache<IpAddr, SourceState>,
}

impl CompiledRule {
    pub(super) fn new(spec: RuleSpec) -> Self {
        let capacity = NonZeroUsize::new(MAX_TRACKED_SOURCES).expect("non-zero constant");
        CompiledRule {
            window_us: (spec.window_secs * MICROS_PER_SEC) as u64,
            cooldown_us: (spec.cooldown_secs * MICROS_PER_SEC) as u64,
            sources: LruCache::new(capacity),
            spec,
        }
    }

    pub(super) fn evaluate(&mut self, packet: &Packet) -> Option<Alert> {
        let ip = packet.ip.as_ref()?;
        let observed = self.observe(packet, ip.src, ip.dst)?;
        if observed < self.spec.threshold as usize {
            return None;
        }
        let state = self.sources.get_mut(&ip.src)?;
        if state
            .last_fired_us
            .is_some_and(|last| packet.ts_us < last.saturating_add(self.cooldown_us))
        {
            return None;
        }
        state.last_fired_us = Some(packet.ts_us);
        Some(self.alert(packet.ts_us, ip.src, observed))
    }

    fn observe(&mut self, packet: &Packet, src: IpAddr, dst: IpAddr) -> Option<usize> {
        let window = self.window_us;
        let kind = self.spec.kind;
        let event = match kind {
            RuleKind::PortScan => match packet.transport {
                Transport::Tcp(h) if h.is_syn_only() => Event::Port(h.dst_port),
                _ => return None,
            },
            RuleKind::HostSweep => Event::Host(dst),
            RuleKind::PacketRate => Event::Tick,
            RuleKind::DnsTunnel => {
                if !self.is_tunnel_like(packet) {
                    return None;
                }
                Event::Tick
            }
        };
        let state = self.sources.get_or_insert_mut(src, || SourceState {
            tracker: new_tracker(kind),
            last_fired_us: None,
        });
        Some(match (&mut state.tracker, event) {
            (Tracker::Ports(w), Event::Port(port)) => w.add(packet.ts_us, port, window),
            (Tracker::Hosts(w), Event::Host(host)) => w.add(packet.ts_us, host, window),
            (Tracker::Count(w), Event::Tick) => w.add(packet.ts_us, window),
            _ => return None,
        })
    }

    fn is_tunnel_like(&self, packet: &Packet) -> bool {
        let App::Dns(info) = &packet.app else { return false };
        if info.is_response {
            return false;
        }
        let Some(q) = &info.question else { return false };
        q.name.split(LABEL_SEPARATOR).any(|label| {
            label.len() >= self.spec.min_label_len && shannon_entropy(label) >= self.spec.min_entropy
        })
    }

    fn alert(&self, ts_us: u64, src: IpAddr, observed: usize) -> Alert {
        let what = match self.spec.kind {
            RuleKind::PortScan => "distinct ports probed",
            RuleKind::HostSweep => "distinct hosts contacted",
            RuleKind::DnsTunnel => "high-entropy dns queries",
            RuleKind::PacketRate => "packets",
        };
        Alert {
            ts_us,
            source: AlertSource::Rule,
            severity: self.spec.severity,
            rule_id: self.spec.id.clone(),
            message: format!("{src}: {observed} {what} in {}s", self.spec.window_secs),
            src: Some(src),
            score: observed as f64 / f64::from(self.spec.threshold),
        }
    }
}

#[derive(Clone, Copy)]
enum Event {
    Port(u16),
    Host(IpAddr),
    Tick,
}

fn new_tracker(kind: RuleKind) -> Tracker {
    match kind {
        RuleKind::PortScan => Tracker::Ports(DistinctWindow::new()),
        RuleKind::HostSweep => Tracker::Hosts(DistinctWindow::new()),
        RuleKind::DnsTunnel | RuleKind::PacketRate => Tracker::Count(CountWindow::new()),
    }
}

pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in text.as_bytes() {
        freq[usize::from(b)] += 1;
    }
    let len = text.len() as f64;
    freq.iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum()
}
