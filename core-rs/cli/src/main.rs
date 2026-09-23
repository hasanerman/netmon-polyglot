mod args;

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use args::{Command, RulesChoice};
use netcore_engine::pcap::{PcapReader, PcapWriter};
use netcore_engine::rules::{RuleEngine, RuleError};
use netcore_engine::synth::{self, Scenario};
use netcore_engine::{Alert, Engine, EngineConfig, Frame, LinkType, Snapshot};

const SNAPLEN: u32 = 65_535;
const MAX_PRINTED_ALERTS: usize = 10;
const BYTES_PER_MB: f64 = 1_048_576.0;
const MICROS_PER_SEC: f64 = 1_000_000.0;

fn main() -> ExitCode {
    let command = match args::parse(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n{}", args::USAGE);
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Help => {
            println!("{}", args::USAGE);
            Ok(())
        }
        Command::Gen {
            scenario,
            out,
            packets,
            seed,
        } => generate(scenario, &out, packets, seed),
        Command::Replay { file, top, rules } => replay(&file, top, &rules),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn generate(scenario: Scenario, out: &Path, packets: usize, seed: u64) -> Result<(), Box<dyn std::error::Error>> {
    let file = BufWriter::new(File::create(out)?);
    let mut writer = PcapWriter::new(file, LinkType::Ethernet, SNAPLEN)?;
    synth::generate(scenario, packets, seed, |ts, frame| writer.write_record(ts, frame))?;
    writer.into_inner().flush()?;
    println!("wrote {packets} packets to {}", out.display());
    Ok(())
}

fn load_rules(choice: &RulesChoice) -> Result<Option<RuleEngine>, RuleError> {
    match choice {
        RulesChoice::Builtin => Ok(Some(RuleEngine::builtin())),
        RulesChoice::File(path) => RuleEngine::load(path).map(Some),
        RulesChoice::Off => Ok(None),
    }
}

fn replay(path: &Path, top: usize, rules: &RulesChoice) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = PcapReader::new(BufReader::new(File::open(path)?))?;
    let mut engine = Engine::new(EngineConfig {
        link: reader.link_type(),
        top_n: top,
        ..EngineConfig::default()
    });
    engine.set_rules(load_rules(rules)?);

    let started = Instant::now();
    let mut buf = Vec::new();
    let mut alerts = Vec::new();
    while let Some(rec) = reader.next_record(&mut buf)? {
        let frame = Frame {
            ts_us: rec.ts_us,
            wire_len: rec.wire_len,
            data: &buf,
        };
        // hata sayaca yaziliyor, replay durmasin
        let _ = engine.process(&frame);
        alerts.extend(engine.drain_alerts());
    }
    let elapsed = started.elapsed().as_secs_f64();

    print_report(path, reader.link_type(), &engine.snapshot(), elapsed);
    print_alerts(engine.rules().map_or(0, RuleEngine::len), &alerts);
    Ok(())
}

fn print_alerts(rule_count: usize, alerts: &[Alert]) {
    println!("rules       : {rule_count} active, {} alert(s)", alerts.len());
    for a in alerts.iter().take(MAX_PRINTED_ALERTS) {
        println!(
            "  [{:<8}] {:<12} {}  (score {:.2})",
            format!("{:?}", a.severity).to_lowercase(),
            a.rule_id,
            a.message,
            a.score
        );
    }
    if alerts.len() > MAX_PRINTED_ALERTS {
        println!("  ... {} more", alerts.len() - MAX_PRINTED_ALERTS);
    }
}

fn print_report(path: &Path, link: LinkType, s: &Snapshot, elapsed: f64) {
    let c = &s.counters;
    let pps = c.packets as f64 / elapsed.max(f64::EPSILON);
    let mbps = c.bytes as f64 / BYTES_PER_MB / elapsed.max(f64::EPSILON);
    println!("file        : {} ({link:?})", path.display());
    println!("packets     : {}  bytes: {}  parse errors: {}", c.packets, c.bytes, c.parse_errors);
    println!("elapsed     : {elapsed:.3} s  ({pps:.0} pkt/s, {mbps:.1} MB/s)");
    println!(
        "layers      : ipv4 {}  ipv6 {}  non-ip {}  fragments {}",
        c.ipv4, c.ipv6, c.non_ip, c.fragments
    );
    println!(
        "transport   : tcp {}  udp {}  icmp {}  other {}",
        c.tcp, c.udp, c.icmp, c.other_l4
    );
    println!("dns         : ok {}  malformed {}", c.dns, c.dns_errors);
    println!(
        "flows       : active {}  evicted {}  expired {}",
        s.active_flows, s.evicted_flows, s.expired_flows
    );
    if s.top_flows.is_empty() {
        return;
    }
    println!("top flows by bytes:");
    println!("  {:<5} {:<46} {:>9} {:>12} {:>9}", "proto", "endpoints", "packets", "bytes", "secs");
    for (key, stats) in &s.top_flows {
        let endpoints = format!("{}:{} <-> {}:{}", key.a.addr, key.a.port, key.b.addr, key.b.port);
        println!(
            "  {:<5} {:<46} {:>9} {:>12} {:>9.2}",
            key.proto,
            endpoints,
            stats.total_packets(),
            stats.total_bytes(),
            stats.duration_us() as f64 / MICROS_PER_SEC
        );
    }
}
