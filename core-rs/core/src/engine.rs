use std::num::NonZeroUsize;

use crate::alert::Alert;
use crate::error::ParseError;
use crate::rules::RuleEngine;
use crate::flow::{Endpoint, FlowKey, FlowStats, FlowTable, FlowUpdate};
use crate::packet::{self, App, Frame, LinkType, Packet, Transport};

pub const DEFAULT_MAX_FLOWS: usize = 100_000;
pub const DEFAULT_FLOW_IDLE_TIMEOUT_US: u64 = 120_000_000;
pub const DEFAULT_TOP_N: usize = 10;
const EXPIRY_INTERVAL_US: u64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub link: LinkType,
    pub max_flows: NonZeroUsize,
    pub flow_idle_timeout_us: u64,
    pub top_n: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            link: LinkType::Ethernet,
            max_flows: NonZeroUsize::new(DEFAULT_MAX_FLOWS).expect("non-zero constant"),
            flow_idle_timeout_us: DEFAULT_FLOW_IDLE_TIMEOUT_US,
            top_n: DEFAULT_TOP_N,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other_l4: u64,
    pub non_ip: u64,
    pub fragments: u64,
    pub dns: u64,
    pub dns_errors: u64,
    pub parse_errors: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub counters: Counters,
    pub active_flows: usize,
    pub evicted_flows: u64,
    pub expired_flows: u64,
    pub last_ts_us: u64,
    pub top_flows: Vec<(FlowKey, FlowStats)>,
}

pub struct Engine {
    config: EngineConfig,
    flows: FlowTable,
    counters: Counters,
    last_ts_us: u64,
    next_expiry_us: u64,
    rules: Option<RuleEngine>,
    alerts: Vec<Alert>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        Engine {
            flows: FlowTable::new(config.max_flows, config.flow_idle_timeout_us),
            config,
            counters: Counters::default(),
            last_ts_us: 0,
            next_expiry_us: 0,
            rules: None,
            alerts: Vec::new(),
        }
    }

    pub fn with_rules(mut self, rules: RuleEngine) -> Self {
        self.rules = Some(rules);
        self
    }

    pub fn set_rules(&mut self, rules: Option<RuleEngine>) {
        self.rules = rules;
    }

    pub fn rules(&self) -> Option<&RuleEngine> {
        self.rules.as_ref()
    }

    pub fn drain_alerts(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.alerts)
    }

    pub fn process(&mut self, frame: &Frame<'_>) -> Result<Packet, ParseError> {
        self.counters.packets += 1;
        self.counters.bytes += u64::from(frame.wire_len);
        self.advance_clock(frame.ts_us);

        let packet = packet::parse(self.config.link, frame).inspect_err(|_| {
            self.counters.parse_errors += 1;
        })?;
        self.count(&packet);
        self.track_flow(&packet);
        if let Some(rules) = &mut self.rules {
            rules.evaluate(&packet, &mut self.alerts);
        }
        Ok(packet)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            counters: self.counters,
            active_flows: self.flows.len(),
            evicted_flows: self.flows.evicted(),
            expired_flows: self.flows.expired(),
            last_ts_us: self.last_ts_us,
            top_flows: self.flows.top_by_bytes(self.config.top_n),
        }
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn flows(&self) -> &FlowTable {
        &self.flows
    }

    pub fn last_ts_us(&self) -> u64 {
        self.last_ts_us
    }

    fn advance_clock(&mut self, ts_us: u64) {
        self.last_ts_us = self.last_ts_us.max(ts_us);
        if self.last_ts_us >= self.next_expiry_us {
            self.flows.expire(self.last_ts_us);
            self.next_expiry_us = self.last_ts_us + EXPIRY_INTERVAL_US;
        }
    }

    fn count(&mut self, p: &Packet) {
        let c = &mut self.counters;
        let Some(ip) = &p.ip else {
            c.non_ip += 1;
            return;
        };
        if ip.src.is_ipv4() {
            c.ipv4 += 1;
        } else {
            c.ipv6 += 1;
        }
        if ip.is_fragment() {
            c.fragments += 1;
        }
        match p.transport {
            Transport::Tcp(_) => c.tcp += 1,
            Transport::Udp(_) => c.udp += 1,
            Transport::Icmp(_) => c.icmp += 1,
            Transport::Other(_) => c.other_l4 += 1,
            Transport::None | Transport::LaterFragment => {}
        }
        match p.app {
            App::Dns(_) => c.dns += 1,
            App::DnsError(_) => c.dns_errors += 1,
            App::None => {}
        }
    }

    fn track_flow(&mut self, p: &Packet) {
        let Some(ip) = &p.ip else { return };
        if p.transport == Transport::LaterFragment {
            return;
        }
        let (sport, dport) = p.transport.ports();
        let tcp_flags = match p.transport {
            Transport::Tcp(h) => h.flags,
            _ => 0,
        };
        let (key, direction) = FlowKey::canonical(
            Endpoint {
                addr: ip.src,
                port: sport,
            },
            Endpoint {
                addr: ip.dst,
                port: dport,
            },
            ip.proto,
        );
        self.flows.update(&FlowUpdate {
            key,
            direction,
            ts_us: p.ts_us,
            bytes: p.wire_len,
            tcp_flags,
        });
    }
}
