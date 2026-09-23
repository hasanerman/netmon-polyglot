use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;

use netcore_engine::flow::{Direction, Endpoint, FlowKey, FlowTable, FlowUpdate};
use netcore_engine::packet::{tcp, PROTO_TCP};
use netcore_engine::synth::{self, Scenario};
use netcore_engine::{Engine, EngineConfig, Frame};

const TIMEOUT_US: u64 = 10_000_000;
const SCANNER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);
const SCAN_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const SCANNER_PORT: u16 = 49_152;

fn ep(last: u8, port: u16) -> Endpoint {
    Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        port,
    }
}

fn update(key: FlowKey, direction: Direction, ts_us: u64, bytes: u32) -> FlowUpdate {
    FlowUpdate {
        key,
        direction,
        ts_us,
        bytes,
        tcp_flags: 0,
    }
}

fn table(capacity: usize) -> FlowTable {
    FlowTable::new(NonZeroUsize::new(capacity).unwrap(), TIMEOUT_US)
}

#[test]
fn both_directions_share_one_flow() {
    let (k1, d1) = FlowKey::canonical(ep(1, 5000), ep(2, 80), PROTO_TCP);
    let (k2, d2) = FlowKey::canonical(ep(2, 80), ep(1, 5000), PROTO_TCP);
    assert_eq!(k1, k2);
    assert_ne!(d1, d2);

    let mut t = table(8);
    t.update(&update(k1, d1, 1, 100));
    let stats = t.update(&update(k2, d2, 2, 40));
    assert_eq!(t.len(), 1);
    assert_eq!(stats.total_packets(), 2);
    assert_eq!(stats.bytes[d1 as usize], 100);
    assert_eq!(stats.bytes[d2 as usize], 40);
    assert_eq!(stats.duration_us(), 1);
}

#[test]
fn idle_flows_expire() {
    let mut t = table(8);
    let (old, d) = FlowKey::canonical(ep(1, 1), ep(2, 2), PROTO_TCP);
    let (fresh, _) = FlowKey::canonical(ep(3, 3), ep(4, 4), PROTO_TCP);
    t.update(&update(old, d, 0, 1));
    t.update(&update(fresh, d, TIMEOUT_US, 1));

    assert_eq!(t.expire(TIMEOUT_US + 1), 1);
    assert!(t.get(&old).is_none());
    assert!(t.get(&fresh).is_some());
    assert_eq!(t.expired(), 1);
}

#[test]
fn capacity_evicts_least_recent() {
    let mut t = table(2);
    let keys: Vec<_> = (1..=3).map(|i| FlowKey::canonical(ep(i, 1), ep(100, 2), PROTO_TCP).0).collect();
    t.update(&update(keys[0], Direction::AtoB, 1, 1));
    t.update(&update(keys[1], Direction::AtoB, 2, 1));
    t.update(&update(keys[0], Direction::AtoB, 3, 1));
    t.update(&update(keys[2], Direction::AtoB, 4, 1));

    assert_eq!(t.len(), 2);
    assert_eq!(t.evicted(), 1);
    assert!(t.get(&keys[1]).is_none());
    assert!(t.get(&keys[0]).is_some());
}

#[test]
fn top_flows_sorted_by_bytes() {
    let mut t = table(16);
    for i in 1..=5u8 {
        let (k, d) = FlowKey::canonical(ep(i, 1), ep(100, 2), PROTO_TCP);
        t.update(&update(k, d, u64::from(i), u32::from(i) * 100));
    }
    let top = t.top_by_bytes(3);
    let bytes: Vec<u64> = top.iter().map(|(_, s)| s.total_bytes()).collect();
    assert_eq!(bytes, vec![500, 400, 300]);
    assert!(t.top_by_bytes(0).is_empty());
}

fn run_scenario(scenario: Scenario, packets: usize) -> Engine {
    let mut engine = Engine::new(EngineConfig::default());
    synth::generate(scenario, packets, 42, |ts, data| {
        let frame = Frame {
            ts_us: ts,
            wire_len: data.len() as u32,
            data,
        };
        engine.process(&frame).expect("synthetic traffic parses");
        Ok(())
    })
    .unwrap();
    engine
}

#[test]
fn mixed_traffic_counters_add_up() {
    let engine = run_scenario(Scenario::Mixed, 5_000);
    let c = engine.counters();
    assert_eq!(c.packets, 5_000);
    assert_eq!(c.parse_errors, 0);
    assert_eq!(c.ipv4, 5_000);
    assert_eq!(c.tcp + c.udp + c.icmp, 5_000);
    assert_eq!(c.dns, c.udp);
    assert!(c.tcp > c.udp && c.udp > c.icmp);
}

#[test]
fn portscan_creates_one_syn_flow_per_probed_port() {
    let packets = 4_000;
    let engine = run_scenario(Scenario::PortScan, packets);
    let flows = engine.flows();
    let probed_ports = (packets / 4) as u16;

    let syn_flows = (1..=probed_ports)
        .filter(|&port| {
            let (k, _) = FlowKey::canonical(
                Endpoint {
                    addr: IpAddr::V4(SCANNER),
                    port: SCANNER_PORT,
                },
                Endpoint {
                    addr: IpAddr::V4(SCAN_TARGET),
                    port,
                },
                PROTO_TCP,
            );
            flows.get(&k).is_some_and(|s| s.tcp_flags == tcp::FLAG_SYN)
        })
        .count();
    assert_eq!(syn_flows, usize::from(probed_ports));
}

#[test]
fn flow_table_stays_bounded_under_flood() {
    let engine = run_scenario(Scenario::Flood, 150_000);
    let max = EngineConfig::default().max_flows.get();
    assert_eq!(engine.flows().len(), max);
    assert!(engine.flows().evicted() >= 49_000, "evicted {}", engine.flows().evicted());
}

#[test]
fn snapshot_reports_top_n() {
    let engine = run_scenario(Scenario::Mixed, 2_000);
    let snap = engine.snapshot();
    assert_eq!(snap.top_flows.len(), EngineConfig::default().top_n);
    assert!(snap.active_flows >= snap.top_flows.len());
    assert!(snap.last_ts_us > synth::START_TS_US);
}
