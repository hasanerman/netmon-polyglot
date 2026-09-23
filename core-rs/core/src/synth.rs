use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::packet::{tcp, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

const ETH_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_ECHO_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const DEFAULT_TTL: u8 = 64;
const TCP_WINDOW: u16 = 64_240;
const ICMP_ECHO_REQUEST: u8 = 8;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_TXT: u16 = 16;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

pub fn ethernet_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(IPV4_HEADER_LEN + l4.len()).expect("synthetic packet fits in 64k");
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + IPV4_HEADER_LEN + l4.len());
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&ETHERTYPE_IPV4);

    let mut ip = [0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[8] = DEFAULT_TTL;
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let checksum = internet_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    frame.extend_from_slice(&ip);
    frame.extend_from_slice(l4);
    frame
}

pub fn tcp_segment(src: SocketAddrV4, dst: SocketAddrV4, flags: u8, payload_len: usize) -> Vec<u8> {
    let mut seg = vec![0u8; TCP_HEADER_LEN + payload_len];
    seg[0..2].copy_from_slice(&src.port().to_be_bytes());
    seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
    seg[12] = ((TCP_HEADER_LEN / 4) as u8) << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&TCP_WINDOW.to_be_bytes());
    ethernet_ipv4(*src.ip(), *dst.ip(), PROTO_TCP, &seg)
}

pub fn udp_datagram(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(UDP_HEADER_LEN + payload.len()).expect("synthetic datagram fits in 64k");
    let mut dgram = Vec::with_capacity(usize::from(len));
    dgram.extend_from_slice(&src.port().to_be_bytes());
    dgram.extend_from_slice(&dst.port().to_be_bytes());
    dgram.extend_from_slice(&len.to_be_bytes());
    dgram.extend_from_slice(&[0, 0]);
    dgram.extend_from_slice(payload);
    ethernet_ipv4(*src.ip(), *dst.ip(), PROTO_UDP, &dgram)
}

pub fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut msg = [0u8; ICMP_ECHO_LEN];
    msg[0] = ICMP_ECHO_REQUEST;
    msg[6..8].copy_from_slice(&seq.to_be_bytes());
    let checksum = internet_checksum(&msg);
    msg[2..4].copy_from_slice(&checksum.to_be_bytes());
    ethernet_ipv4(src, dst, PROTO_ICMP, &msg)
}

pub fn dns_query_payload(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&DNS_FLAG_RECURSION_DESIRED.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0; 6]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        msg.push(u8::try_from(label.len()).expect("label under 64 bytes"));
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    msg
}

pub fn dns_query(src: SocketAddrV4, dst: SocketAddrV4, id: u16, name: &str, qtype: u16) -> Vec<u8> {
    udp_datagram(src, dst, &dns_query_payload(id, name, qtype))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Mixed,
    PortScan,
    DnsTunnel,
    Flood,
}

impl Scenario {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "mixed" => Some(Scenario::Mixed),
            "portscan" => Some(Scenario::PortScan),
            "dnstunnel" => Some(Scenario::DnsTunnel),
            "flood" => Some(Scenario::Flood),
            _ => None,
        }
    }
}

pub const START_TS_US: u64 = 1_700_000_000_000_000;
const MAX_GAP_US: u64 = 2_000;
const INJECT_EVERY: usize = 4;
const CLIENT_COUNT: u64 = 50;
const CLIENT_BASE: u8 = 10;
const MAX_TCP_PAYLOAD: u64 = 1_400;
const EPHEMERAL_BASE: u16 = 49_152;
const SCAN_FIRST_PORT: u16 = 1;

const RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53);
const SCANNER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);
const SCAN_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const TUNNEL_CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 77), 53_001);
const TUNNEL_DOMAIN: &str = "t.exfil-example.net";
const TUNNEL_LABEL_LEN: usize = 48;
const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const FLOOD_NET: u8 = 172;
const FLOOD_TARGET: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 80);

const SERVERS: [SocketAddrV4; 4] = [
    SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
    SocketAddrV4::new(Ipv4Addr::new(140, 82, 121, 4), 443),
    SocketAddrV4::new(Ipv4Addr::new(151, 101, 1, 69), 80),
    SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 22),
];
const DOMAINS: [&str; 5] = [
    "example.com",
    "github.com",
    "api.github.com",
    "crates.io",
    "nuget.org",
];

pub fn generate<F>(scenario: Scenario, packets: usize, seed: u64, mut sink: F) -> io::Result<()>
where
    F: FnMut(u64, &[u8]) -> io::Result<()>,
{
    let mut rng = Rng::new(seed);
    let mut ts = START_TS_US;
    let mut scan_port = SCAN_FIRST_PORT;
    for i in 0..packets {
        ts += 1 + rng.below(MAX_GAP_US);
        let inject = scenario != Scenario::Mixed && i % INJECT_EVERY == 0;
        let frame = match scenario {
            Scenario::Flood => flood_syn(&mut rng),
            _ if !inject => background_packet(&mut rng, i),
            Scenario::PortScan => {
                let frame = scan_probe(scan_port);
                scan_port = scan_port.checked_add(1).unwrap_or(SCAN_FIRST_PORT);
                frame
            }
            _ => tunnel_query(&mut rng, i),
        };
        sink(ts, &frame)?;
    }
    Ok(())
}

fn background_packet(rng: &mut Rng, i: usize) -> Vec<u8> {
    let client_idx = rng.below(CLIENT_COUNT);
    let client_ip = Ipv4Addr::new(10, 0, 0, CLIENT_BASE + client_idx as u8);
    match rng.below(100) {
        0..=69 => {
            let server_idx = rng.below(SERVERS.len() as u64);
            let server = SERVERS[server_idx as usize];
            let port = EPHEMERAL_BASE + (client_idx * SERVERS.len() as u64 + server_idx) as u16;
            let client = SocketAddrV4::new(client_ip, port);
            let payload = rng.below(MAX_TCP_PAYLOAD) as usize;
            let flags = tcp::FLAG_ACK | tcp::FLAG_PSH;
            if rng.below(2) == 0 {
                tcp_segment(client, server, flags, payload)
            } else {
                tcp_segment(server, client, flags, payload)
            }
        }
        70..=89 => {
            let domain = DOMAINS[rng.below(DOMAINS.len() as u64) as usize];
            let client = SocketAddrV4::new(client_ip, EPHEMERAL_BASE + client_idx as u16);
            dns_query(client, RESOLVER, i as u16, domain, DNS_TYPE_A)
        }
        _ => icmp_echo(client_ip, *RESOLVER.ip(), i as u16),
    }
}

fn scan_probe(port: u16) -> Vec<u8> {
    let src = SocketAddrV4::new(SCANNER, EPHEMERAL_BASE);
    let dst = SocketAddrV4::new(SCAN_TARGET, port);
    tcp_segment(src, dst, tcp::FLAG_SYN, 0)
}

fn flood_syn(rng: &mut Rng) -> Vec<u8> {
    let [_, b, c, d] = (rng.next_u64() as u32).to_be_bytes();
    let src = SocketAddrV4::new(Ipv4Addr::new(FLOOD_NET, b, c, d), EPHEMERAL_BASE + (rng.below(1024) as u16));
    tcp_segment(src, FLOOD_TARGET, tcp::FLAG_SYN, 0)
}

fn tunnel_query(rng: &mut Rng, i: usize) -> Vec<u8> {
    let label: String = (0..TUNNEL_LABEL_LEN)
        .map(|_| char::from(BASE32[rng.below(BASE32.len() as u64) as usize]))
        .collect();
    let name = format!("{label}.{TUNNEL_DOMAIN}");
    dns_query(TUNNEL_CLIENT, RESOLVER, i as u16, &name, DNS_TYPE_TXT)
}
