use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use netcore_engine::rules::{shannon_entropy, RuleEngine, RuleError};
use netcore_engine::synth::{self, Scenario};
use netcore_engine::{Alert, Engine, EngineConfig, Frame, Severity};

const SEED: u64 = 42;

fn run(scenario: Scenario, packets: usize, rules: RuleEngine) -> Vec<Alert> {
    let mut engine = Engine::new(EngineConfig::default()).with_rules(rules);
    let mut alerts = Vec::new();
    synth::generate(scenario, packets, SEED, |ts, data| {
        let frame = Frame {
            ts_us: ts,
            wire_len: data.len() as u32,
            data,
        };
        engine.process(&frame).expect("synthetic traffic parses");
        alerts.extend(engine.drain_alerts());
        Ok(())
    })
    .unwrap();
    alerts
}

fn by_rule(alerts: &[Alert]) -> HashMap<&str, usize> {
    let mut map = HashMap::new();
    for a in alerts {
        *map.entry(a.rule_id.as_str()).or_insert(0) += 1;
    }
    map
}

#[test]
fn builtin_rules_load() {
    let rules = RuleEngine::builtin();
    let ids: Vec<_> = rules.rule_ids().collect();
    assert_eq!(ids, ["port-scan", "host-sweep", "dns-tunnel", "packet-flood"]);
}

#[test]
fn normal_traffic_raises_nothing() {
    let alerts = run(Scenario::Mixed, 50_000, RuleEngine::builtin());
    assert!(alerts.is_empty(), "false positives: {:?}", by_rule(&alerts));
}

#[test]
fn port_scan_is_detected_with_cooldown() {
    let alerts = run(Scenario::PortScan, 40_000, RuleEngine::builtin());
    let counts = by_rule(&alerts);
    assert_eq!(counts.keys().copied().collect::<Vec<_>>(), ["port-scan"]);

    let first = &alerts[0];
    assert_eq!(first.src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66))));
    assert_eq!(first.severity, Severity::High);
    assert!(first.score >= 1.0);
    assert!(first.message.contains("distinct ports"));
    for pair in alerts.windows(2) {
        assert!(pair[1].ts_us - pair[0].ts_us >= 15_000_000, "cooldown violated");
    }
}

#[test]
fn dns_tunnel_is_detected() {
    let alerts = run(Scenario::DnsTunnel, 20_000, RuleEngine::builtin());
    let counts = by_rule(&alerts);
    assert!(counts.get("dns-tunnel").copied().unwrap_or(0) >= 1, "{counts:?}");
    assert_eq!(counts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Critical);
    assert_eq!(alerts[0].src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77))));
}

#[test]
fn threshold_is_respected_exactly() {
    let yaml = "version: 1\nrules:\n  - id: tiny\n    kind: port_scan\n    severity: low\n    window_secs: 1000\n    threshold: 5\n    cooldown_secs: 100000\n";
    let alerts = run(Scenario::PortScan, 4 * 5, RuleEngine::from_yaml(yaml).unwrap());
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].score, 1.0);
}

#[test]
fn disabled_rules_are_skipped() {
    let yaml = "version: 1\nrules:\n  - id: off\n    kind: packet_rate\n    severity: low\n    window_secs: 1\n    threshold: 1\n    enabled: false\n";
    let rules = RuleEngine::from_yaml(yaml).unwrap();
    assert!(rules.is_empty());
}

#[test]
fn bad_rule_files_are_rejected_with_reason() {
    let cases = [
        ("version: 2\nrules: []\n", "version"),
        ("version: 1\nrules:\n  - id: x\n    kind: nope\n    severity: low\n    window_secs: 1\n    threshold: 1\n", "unknown variant"),
        ("version: 1\nrules:\n  - id: x\n    kind: port_scan\n    severity: low\n    window_secs: 0\n    threshold: 1\n", "window_secs"),
        ("version: 1\nrules:\n  - id: x\n    kind: port_scan\n    severity: low\n    window_secs: 1\n    threshold: 0\n", "threshold"),
        ("version: 1\nrules:\n  - id: x\n    kind: port_scan\n    severity: low\n    window_secs: 1\n    threshold: 1\n    typo: 3\n", "unknown field"),
        ("version: 1\nrules:\n  - {id: a, kind: port_scan, severity: low, window_secs: 1, threshold: 1}\n  - {id: a, kind: host_sweep, severity: low, window_secs: 1, threshold: 1}\n", "duplicate"),
    ];
    for (yaml, expected) in cases {
        let err = RuleEngine::from_yaml(yaml).err().unwrap_or_else(|| panic!("accepted: {yaml}"));
        assert!(err.to_string().contains(expected), "{err} should mention {expected}");
    }
    assert!(matches!(
        RuleEngine::load(std::path::Path::new("missing.yaml")),
        Err(RuleError::Io(_))
    ));
}

#[test]
fn entropy_separates_words_from_random_labels() {
    assert_eq!(shannon_entropy(""), 0.0);
    assert_eq!(shannon_entropy("aaaa"), 0.0);
    assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
    assert!(shannon_entropy("github") < 3.0);
    assert!(shannon_entropy("mzxw6ytboi4tqmrzgq3dknbwgy2tsnzxgaytcmrt") > 3.5);
}
