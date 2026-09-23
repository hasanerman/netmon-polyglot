use std::fmt;
use std::net::IpAddr;

use netcore_engine::{Alert, Counters, FlowKey, FlowStats};

pub const NC_ABI_VERSION: u32 = 1;
pub const NC_ADDR_LEN: usize = 16;
pub const NC_RULE_ID_LEN: usize = 64;
pub const NC_MESSAGE_LEN: usize = 192;
pub const NC_DEVICE_NAME_LEN: usize = 256;
pub const NC_FAMILY_IPV4: u8 = 4;
pub const NC_FAMILY_IPV6: u8 = 6;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcStatus {
    Ok = 0,
    NullArg = -1,
    InvalidArg = -2,
    State = -3,
    Io = -4,
    Capture = -5,
    NoLibrary = -6,
    Permission = -7,
    Panic = -8,
    Rules = -9,
    Format = -10,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcAlertSource {
    Rule = 0,
    Anomaly = 1,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcCaptureState {
    Idle = 0,
    Running = 1,
    Finished = 2,
    Failed = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcAnalyticsState {
    Off = 0,
    Connecting = 1,
    Connected = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcScenario {
    Mixed = 0,
    PortScan = 1,
    DnsTunnel = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NcConfig {
    pub max_flows: u32,
    pub flow_idle_timeout_ms: u32,
    pub top_n: u32,
    pub snaplen: u32,
    pub link_type: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NcStats {
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
    pub active_flows: u64,
    pub evicted_flows: u64,
    pub expired_flows: u64,
    pub last_ts_us: u64,
    pub capture_dropped: u64,
    pub alerts_total: u64,
    pub alerts_dropped: u64,
    pub capture_state: u64,
    pub rules_loaded: u64,
    pub analytics_state: u64,
    pub analytics_sent: u64,
    pub analytics_dropped: u64,
}

impl NcStats {
    pub fn from_counters(c: &Counters) -> Self {
        NcStats {
            packets: c.packets,
            bytes: c.bytes,
            ipv4: c.ipv4,
            ipv6: c.ipv6,
            tcp: c.tcp,
            udp: c.udp,
            icmp: c.icmp,
            other_l4: c.other_l4,
            non_ip: c.non_ip,
            fragments: c.fragments,
            dns: c.dns,
            dns_errors: c.dns_errors,
            parse_errors: c.parse_errors,
            ..NcStats::default()
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NcFlow {
    pub a_addr: [u8; NC_ADDR_LEN],
    pub b_addr: [u8; NC_ADDR_LEN],
    pub a_port: u16,
    pub b_port: u16,
    pub proto: u8,
    pub family: u8,
    pub tcp_flags: u8,
    pub reserved: u8,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

impl NcFlow {
    pub fn new(key: &FlowKey, stats: &FlowStats) -> Self {
        let (a_addr, family) = addr_bytes(key.a.addr);
        let (b_addr, _) = addr_bytes(key.b.addr);
        NcFlow {
            a_addr,
            b_addr,
            a_port: key.a.port,
            b_port: key.b.port,
            proto: key.proto,
            family,
            tcp_flags: stats.tcp_flags,
            reserved: 0,
            packets_ab: stats.packets[0],
            packets_ba: stats.packets[1],
            bytes_ab: stats.bytes[0],
            bytes_ba: stats.bytes[1],
            first_seen_us: stats.first_seen_us,
            last_seen_us: stats.last_seen_us,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NcAlert {
    pub ts_us: u64,
    pub score: f64,
    pub severity: u32,
    pub source: u32,
    pub src_addr: [u8; NC_ADDR_LEN],
    pub family: u8,
    pub reserved: [u8; 7],
    pub rule_id: [u8; NC_RULE_ID_LEN],
    pub message: [u8; NC_MESSAGE_LEN],
}

impl NcAlert {
    pub fn new(alert: &Alert) -> Self {
        let (src_addr, family) = alert.src.map(addr_bytes).unwrap_or(([0; NC_ADDR_LEN], 0));
        let mut out = NcAlert {
            ts_us: alert.ts_us,
            score: alert.score,
            severity: alert.severity as u32,
            source: alert.source as u32,
            src_addr,
            family,
            reserved: [0; 7],
            rule_id: [0; NC_RULE_ID_LEN],
            message: [0; NC_MESSAGE_LEN],
        };
        write_cstr(&mut out.rule_id, &alert.rule_id);
        write_cstr(&mut out.message, &alert.message);
        out
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NcDevice {
    pub name: [u8; NC_DEVICE_NAME_LEN],
    pub description: [u8; NC_DEVICE_NAME_LEN],
    pub flags: u32,
}

impl NcDevice {
    pub fn new(name: &str, description: &str, flags: u32) -> Self {
        let mut d = NcDevice {
            name: [0; NC_DEVICE_NAME_LEN],
            description: [0; NC_DEVICE_NAME_LEN],
            flags,
        };
        write_cstr(&mut d.name, name);
        write_cstr(&mut d.description, description);
        d
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub status: NcStatus,
    pub message: String,
}

impl CoreError {
    pub fn new(status: NcStatus, message: impl Into<String>) -> Self {
        CoreError {
            status,
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.status, self.message)
    }
}

pub fn addr_bytes(addr: IpAddr) -> ([u8; NC_ADDR_LEN], u8) {
    let mut out = [0u8; NC_ADDR_LEN];
    match addr {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            (out, NC_FAMILY_IPV4)
        }
        IpAddr::V6(v6) => (v6.octets(), NC_FAMILY_IPV6),
    }
}

pub fn write_cstr(dst: &mut [u8], s: &str) {
    if dst.is_empty() {
        return;
    }
    let mut n = s.len().min(dst.len() - 1);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    dst[n..].fill(0);
}
