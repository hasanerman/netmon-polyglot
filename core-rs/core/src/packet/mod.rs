pub mod dns;
pub mod ethernet;
pub mod icmp;
mod ipv4;
mod ipv6;
pub mod tcp;
pub mod udp;

use std::net::IpAddr;

use crate::error::{Layer, ParseError};

pub use dns::{DnsInfo, DnsQuestion};
pub use icmp::IcmpHeader;
pub use tcp::TcpHeader;
pub use udp::UdpHeader;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const NULL_HEADER_LEN: usize = 4;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Null = 0,
    Ethernet = 1,
    Raw = 101,
}

impl LinkType {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(LinkType::Null),
            1 => Some(LinkType::Ethernet),
            12 | 14 | 101 => Some(LinkType::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub ts_us: u64,
    pub wire_len: u32,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpHeader {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ttl: u8,
    pub more_fragments: bool,
    pub fragment_offset: u16,
}

impl IpHeader {
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    None,
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    LaterFragment,
    Other(u8),
}

impl Transport {
    pub fn ports(&self) -> (u16, u16) {
        match self {
            Transport::Tcp(h) => (h.src_port, h.dst_port),
            Transport::Udp(h) => (h.src_port, h.dst_port),
            _ => (0, 0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum App {
    None,
    Dns(DnsInfo),
    DnsError(ParseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ts_us: u64,
    pub wire_len: u32,
    pub ethertype: Option<u16>,
    pub ip: Option<IpHeader>,
    pub transport: Transport,
    pub app: App,
}

pub fn parse(link: LinkType, frame: &Frame<'_>) -> Result<Packet, ParseError> {
    let (ethertype, l3) = match link {
        LinkType::Ethernet => {
            let (eth, rest) = ethernet::parse(frame.data)?;
            (Some(eth.ethertype), rest)
        }
        LinkType::Null => {
            need(frame.data, NULL_HEADER_LEN, Layer::Link)?;
            (None, &frame.data[NULL_HEADER_LEN..])
        }
        LinkType::Raw => (None, frame.data),
    };

    let mut packet = Packet {
        ts_us: frame.ts_us,
        wire_len: frame.wire_len,
        ethertype,
        ip: None,
        transport: Transport::None,
        app: App::None,
    };

    let ip_version = match ethertype {
        Some(ethernet::ETHERTYPE_IPV4) => 4,
        Some(ethernet::ETHERTYPE_IPV6) => 6,
        Some(_) => return Ok(packet),
        None => {
            need(l3, 1, Layer::Link)?;
            l3[0] >> 4
        }
    };

    let (ip, l4) = match ip_version {
        4 => ipv4::parse(l3)?,
        6 => ipv6::parse(l3)?,
        _ => {
            return Err(ParseError::Malformed {
                layer: Layer::Link,
                reason: "unknown ip version",
            })
        }
    };
    packet.ip = Some(ip);

    if ip.fragment_offset != 0 {
        packet.transport = Transport::LaterFragment;
        return Ok(packet);
    }

    let payload = match ip.proto {
        PROTO_TCP => {
            let (tcp, _) = tcp::parse(l4)?;
            packet.transport = Transport::Tcp(tcp);
            return Ok(packet);
        }
        PROTO_UDP => {
            let (udp, payload) = udp::parse(l4)?;
            packet.transport = Transport::Udp(udp);
            payload
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            packet.transport = Transport::Icmp(icmp::parse(l4, ip.proto == PROTO_ICMPV6)?);
            return Ok(packet);
        }
        other => {
            packet.transport = Transport::Other(other);
            return Ok(packet);
        }
    };

    let (sport, dport) = packet.transport.ports();
    if (sport == dns::PORT || dport == dns::PORT) && !payload.is_empty() {
        packet.app = match dns::parse(payload) {
            Ok(info) => App::Dns(info),
            Err(e) => App::DnsError(e),
        };
    }
    Ok(packet)
}

pub(crate) fn need(buf: &[u8], len: usize, layer: Layer) -> Result<(), ParseError> {
    if buf.len() < len {
        return Err(ParseError::Truncated {
            layer,
            needed: len,
            available: buf.len(),
        });
    }
    Ok(())
}

pub(crate) fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

pub(crate) fn be32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}
