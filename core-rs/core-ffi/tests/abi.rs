use std::ffi::{c_char, CStr, CString};
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use netcore::*;
use netcore_engine::packet::tcp;
use netcore_engine::synth;

const SAMPLE_FRAMES: u64 = 200;
const WAIT_LIMIT: Duration = Duration::from_secs(10);
const POLL_EVERY: Duration = Duration::from_millis(5);

fn sample_path() -> CString {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sniffer-c/tests/data/sample.pcap");
    CString::new(p.to_str().unwrap()).unwrap()
}

struct Core(*mut NcCore);

impl Core {
    fn new() -> Self {
        let raw = unsafe { core_create(ptr::null()) };
        assert!(!raw.is_null());
        Core(raw)
    }

    fn stats(&self) -> NcStats {
        let mut s = NcStats::default();
        assert_eq!(unsafe { core_poll_stats(self.0, &mut s) }, NcStatus::Ok as i32);
        s
    }

    fn last_error(&self) -> String {
        let mut buf = [0 as c_char; 256];
        unsafe { core_last_error(self.0, buf.as_mut_ptr(), buf.len() as u32) };
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    }

    fn feed(&self, ts: u64, frame: &[u8]) -> i32 {
        unsafe { core_feed_packet(self.0, ts, frame.as_ptr(), frame.len() as u32, frame.len() as u32) }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        unsafe { core_destroy(self.0) };
    }
}

#[test]
fn struct_layout_matches_contract() {
    assert_eq!(size_of::<NcConfig>(), 20);
    assert_eq!(size_of::<NcStats>(), 200);
    assert_eq!(size_of::<NcFlow>(), 88);
    assert_eq!(offset_of!(NcFlow, a_port), 32);
    assert_eq!(offset_of!(NcFlow, packets_ab), 40);
    assert_eq!(size_of::<NcAlert>(), 304);
    assert_eq!(offset_of!(NcAlert, src_addr), 24);
    assert_eq!(offset_of!(NcAlert, rule_id), 48);
    assert_eq!(offset_of!(NcAlert, message), 112);
    assert_eq!(size_of::<NcDevice>(), 516);
    assert_eq!(core_abi_version(), NC_ABI_VERSION);
}

#[test]
fn feed_updates_stats_and_flows() {
    let core = Core::new();
    let client = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let server = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443);
    let syn = synth::tcp_segment(client, server, tcp::FLAG_SYN, 0);
    let reply = synth::tcp_segment(server, client, tcp::FLAG_SYN | tcp::FLAG_ACK, 0);
    assert_eq!(core.feed(1_000, &syn), 0);
    assert_eq!(core.feed(2_000, &reply), 0);
    assert_eq!(core.feed(3_000, &[0xFF; 5]), 0);

    let s = core.stats();
    assert_eq!((s.packets, s.tcp, s.parse_errors, s.active_flows), (3, 2, 1, 1));
    assert_eq!(s.last_ts_us, 3_000);

    let mut flows = [NcFlow::default(); 4];
    let mut written = 0u32;
    let rc = unsafe { core_poll_top_flows(core.0, flows.as_mut_ptr(), flows.len() as u32, &mut written) };
    assert_eq!((rc, written), (0, 1));
    let f = flows[0];
    assert_eq!(f.family, NC_FAMILY_IPV4);
    assert_eq!(&f.a_addr[..4], &[10, 0, 0, 1]);
    assert_eq!((f.a_port, f.b_port, f.proto), (40000, 443, 6));
    assert_eq!((f.packets_ab, f.packets_ba), (1, 1));
    assert_eq!(f.tcp_flags, tcp::FLAG_SYN | tcp::FLAG_ACK);
}

fn poll_alert(core: &Core) -> Option<NcAlert> {
    let mut alert = std::mem::MaybeUninit::<NcAlert>::uninit();
    match unsafe { core_poll_alert(core.0, alert.as_mut_ptr()) } {
        1 => Some(unsafe { alert.assume_init() }),
        0 => None,
        rc => panic!("core_poll_alert failed: {rc}"),
    }
}

fn cstr(bytes: &[u8]) -> &str {
    CStr::from_bytes_until_nul(bytes).unwrap().to_str().unwrap()
}

#[test]
fn builtin_rules_raise_port_scan_alert() {
    let core = Core::new();
    assert_eq!(core.stats().rules_loaded, 4);
    assert!(poll_alert(&core).is_none());

    synth::generate(synth::Scenario::PortScan, 1_000, 1, |ts, frame| {
        assert_eq!(core.feed(ts, frame), 0);
        Ok(())
    })
    .unwrap();

    let alert = poll_alert(&core).expect("port scan alert");
    assert_eq!(cstr(&alert.rule_id), "port-scan");
    assert!(cstr(&alert.message).contains("10.0.0.66"));
    assert_eq!(alert.severity, NcSeverity::High as u32);
    assert_eq!(alert.source, NcAlertSource::Rule as u32);
    assert_eq!((alert.family, &alert.src_addr[..4]), (NC_FAMILY_IPV4, &[10, 0, 0, 66][..]));
    assert_eq!(core.stats().alerts_total, 1);
}

#[test]
fn rules_can_be_reloaded_from_yaml() {
    let dir = std::env::temp_dir();
    let good = dir.join(format!("netcore-rules-ok-{}.yaml", std::process::id()));
    let bad = dir.join(format!("netcore-rules-bad-{}.yaml", std::process::id()));
    std::fs::write(&good, "version: 1\nrules:\n  - {id: any, kind: packet_rate, severity: low, window_secs: 1, threshold: 2}\n").unwrap();
    std::fs::write(&bad, "version: 1\nrules:\n  - {id: x, kind: port_scan}\n").unwrap();

    let core = Core::new();
    let good_c = CString::new(good.to_str().unwrap()).unwrap();
    let bad_c = CString::new(bad.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { core_load_rules(core.0, good_c.as_ptr()) }, 1);
    assert_eq!(core.stats().rules_loaded, 1);

    let frame = synth::tcp_segment(
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 1),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 8), 2),
        tcp::FLAG_ACK,
        0,
    );
    core.feed(1, &frame);
    core.feed(2, &frame);
    assert_eq!(cstr(&poll_alert(&core).expect("rate alert").rule_id), "any");

    assert_eq!(unsafe { core_load_rules(core.0, bad_c.as_ptr()) }, NcStatus::Rules as i32);
    assert!(core.last_error().contains("missing field"), "{}", core.last_error());
    assert_eq!(core.stats().rules_loaded, 1);

    std::fs::remove_file(good).unwrap();
    std::fs::remove_file(bad).unwrap();
}

#[test]
fn null_arguments_are_rejected() {
    let core = Core::new();
    unsafe {
        assert_eq!(core_poll_stats(ptr::null_mut(), ptr::null_mut()), NcStatus::NullArg as i32);
        assert_eq!(core_poll_stats(core.0, ptr::null_mut()), NcStatus::NullArg as i32);
        assert_eq!(core_feed_packet(core.0, 0, ptr::null(), 10, 10), NcStatus::NullArg as i32);
        assert_eq!(core_open_file(core.0, ptr::null(), 0), NcStatus::NullArg as i32);
        core_destroy(ptr::null_mut());
    }
    assert!(core.last_error().contains("null"));
}

#[test]
fn invalid_config_is_refused() {
    let cfg = NcConfig {
        link_type: 9999,
        ..NcConfig::default()
    };
    assert!(unsafe { core_create(&cfg) }.is_null());
}

#[test]
fn state_errors_carry_messages() {
    let core = Core::new();
    assert_eq!(unsafe { core_start(core.0) }, NcStatus::State as i32);
    assert!(core.last_error().contains("no capture source"));
    assert_eq!(unsafe { core_stop(core.0) }, NcStatus::State as i32);

    let missing = CString::new("no/such/file.pcap").unwrap();
    assert_eq!(unsafe { core_open_file(core.0, missing.as_ptr(), 0) }, NcStatus::Io as i32);
    assert!(core.last_error().contains("cannot open"));
}

#[test]
fn file_replay_through_c_sniffer() {
    let core = Core::new();
    let path = sample_path();
    assert_eq!(unsafe { core_open_file(core.0, path.as_ptr(), 0) }, 0, "{}", core.last_error());
    assert_eq!(unsafe { core_start(core.0) }, 0);

    let started = Instant::now();
    while core.stats().capture_state == NcCaptureState::Running as u64 && started.elapsed() < WAIT_LIMIT {
        thread::sleep(POLL_EVERY);
    }
    assert_eq!(core.stats().capture_state, NcCaptureState::Finished as u64);
    assert_eq!(unsafe { core_stop(core.0) }, 0);

    let s = core.stats();
    assert_eq!(s.capture_state, NcCaptureState::Idle as u64);
    assert_eq!(s.packets, SAMPLE_FRAMES);
    assert_eq!(s.parse_errors, 0);
    assert_eq!(s.tcp + s.udp + s.icmp, SAMPLE_FRAMES);
    assert!(s.active_flows > 0);
}

#[test]
fn destroy_while_running_is_safe() {
    let core = Core::new();
    let path = sample_path();
    assert_eq!(unsafe { core_open_file(core.0, path.as_ptr(), 1) }, 0);
    assert_eq!(unsafe { core_start(core.0) }, 0);
    let again = unsafe { core_open_file(core.0, path.as_ptr(), 0) };
    assert_eq!(again, NcStatus::State as i32);
}

#[test]
fn device_listing_or_missing_library() {
    let mut total = 0u32;
    let rc = unsafe { core_list_devices(ptr::null_mut(), 0, &mut total) };
    let tolerated = [0, NcStatus::NoLibrary as i32, NcStatus::Capture as i32];
    assert!(tolerated.contains(&rc), "rc {rc}");
    if rc != 0 || total == 0 {
        return;
    }
    let mut devices = vec![NcDevice { name: [0; 256], description: [0; 256], flags: 0 }; total as usize];
    let rc = unsafe { core_list_devices(devices.as_mut_ptr(), total, &mut total) };
    assert_eq!(rc, 0);
    assert!(devices.iter().all(|d| d.name[0] != 0));
}

#[test]
fn demo_pcap_is_written_and_replayable() {
    let path = std::env::temp_dir().join(format!("netcore-demo-{}.pcap", std::process::id()));
    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    let rc = unsafe { core_write_demo_pcap(c_path.as_ptr(), NcScenario::PortScan as u32, 400, 1) };
    assert_eq!(rc, 0);

    let core = Core::new();
    assert_eq!(unsafe { core_open_file(core.0, c_path.as_ptr(), 0) }, 0);
    assert_eq!(unsafe { core_start(core.0) }, 0);
    let started = Instant::now();
    while core.stats().capture_state == NcCaptureState::Running as u64 && started.elapsed() < WAIT_LIMIT {
        thread::sleep(POLL_EVERY);
    }
    assert_eq!(unsafe { core_stop(core.0) }, 0);
    assert_eq!(core.stats().packets, 400);
    drop(core);
    std::fs::remove_file(&path).unwrap();

    let bad = unsafe { core_write_demo_pcap(c_path.as_ptr(), 99, 1, 1) };
    assert_eq!(bad, NcStatus::InvalidArg as i32);
}

#[test]
fn status_strings_are_static() {
    let text = unsafe { CStr::from_ptr(core_status_str(NcStatus::Permission as i32)) };
    assert_eq!(text.to_str().unwrap(), "permission denied");
    let unknown = unsafe { CStr::from_ptr(core_status_str(12345)) };
    assert_eq!(unknown.to_str().unwrap(), "unknown status");
}
