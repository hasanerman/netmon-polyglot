use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use netcore_engine::packet::{self, tcp, App, Frame, LinkType, Transport, PROTO_UDP};
use netcore_engine::synth;
use netcore_engine::{Layer, ParseError};
use proptest::prelude::*;

const TS: u64 = 1_000_000;

fn parse_eth(data: &[u8]) -> Result<netcore_engine::Packet, ParseError> {
    packet::parse(
        LinkType::Ethernet,
        &Frame {
            ts_us: TS,
            wire_len: data.len() as u32,
            data,
        },
    )
}

fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
}

#[test]
fn tcp_syn_fields() {
    let frame = synth::tcp_segment(addr(10, 0, 0, 1, 40000), addr(10, 0, 0, 2, 443), tcp::FLAG_SYN, 0);
    let p = parse_eth(&frame).unwrap();
    let ip = p.ip.unwrap();
    assert_eq!(ip.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(ip.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let Transport::Tcp(h) = p.transport else { panic!("expected tcp") };
    assert_eq!((h.src_port, h.dst_port), (40000, 443));
    assert!(h.is_syn_only());
}

#[test]
fn dns_query_name_and_type() {
    let frame = synth::dns_query(addr(10, 0, 0, 9, 5000), addr(10, 0, 0, 1, 53), 77, "Api.GitHub.com", synth::DNS_TYPE_A);
    let p = parse_eth(&frame).unwrap();
    let App::Dns(info) = p.app else { panic!("expected dns, got {:?}", p.app) };
    assert_eq!(info.id, 77);
    assert!(!info.is_response);
    let q = info.question.unwrap();
    assert_eq!(q.name, "api.github.com");
    assert_eq!(q.qtype, synth::DNS_TYPE_A);
}

#[test]
fn icmp_echo_type() {
    let frame = synth::icmp_echo(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 1), 1);
    let p = parse_eth(&frame).unwrap();
    let Transport::Icmp(h) = p.transport else { panic!("expected icmp") };
    assert_eq!((h.icmp_type, h.code, h.v6), (8, 0, false));
}

#[test]
fn vlan_tag_is_skipped() {
    let plain = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), tcp::FLAG_ACK, 0);
    let mut tagged = plain[..12].to_vec();
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x2A]);
    tagged.extend_from_slice(&plain[12..]);
    let p = parse_eth(&tagged).unwrap();
    assert!(matches!(p.transport, Transport::Tcp(_)));
}

#[test]
fn arp_is_non_ip() {
    let mut frame = vec![0u8; 42];
    frame[12] = 0x08;
    frame[13] = 0x06;
    let p = parse_eth(&frame).unwrap();
    assert_eq!(p.ethertype, Some(0x0806));
    assert!(p.ip.is_none());
}

#[test]
fn ethernet_padding_is_trimmed_by_ip_length() {
    let mut frame = synth::dns_query(addr(10, 0, 0, 9, 5000), addr(10, 0, 0, 1, 53), 1, "a.io", synth::DNS_TYPE_A);
    frame.extend_from_slice(&[0xEE; 20]);
    let p = parse_eth(&frame).unwrap();
    assert!(matches!(p.app, App::Dns(_)));
}

#[test]
fn truncated_ipv4_header() {
    let frame = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), 0, 0);
    let err = parse_eth(&frame[..14 + 10]).unwrap_err();
    assert!(matches!(err, ParseError::Truncated { layer: Layer::Ipv4, .. }));
}

#[test]
fn bad_ihl_is_malformed() {
    let mut frame = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), 0, 0);
    frame[14] = 0x44;
    let err = parse_eth(&frame).unwrap_err();
    assert!(matches!(err, ParseError::Malformed { layer: Layer::Ipv4, .. }));
}

#[test]
fn truncated_tcp_header() {
    let frame = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), 0, 0);
    let err = parse_eth(&frame[..14 + 20 + 10]).unwrap_err();
    assert_eq!(err.layer(), Layer::Tcp);
}

#[test]
fn later_fragment_has_no_transport() {
    let mut frame = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), 0, 0);
    frame[14 + 6] = 0x00;
    frame[14 + 7] = 0x10;
    let p = parse_eth(&frame).unwrap();
    assert_eq!(p.transport, Transport::LaterFragment);
    assert!(p.ip.unwrap().is_fragment());
}

#[test]
fn dns_pointer_loop_is_reported() {
    let mut payload = synth::dns_query_payload(1, "x", synth::DNS_TYPE_A);
    payload.truncate(12);
    payload.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    let frame = synth::udp_datagram(addr(10, 0, 0, 1, 999), addr(10, 0, 0, 2, 53), &payload);
    let p = parse_eth(&frame).unwrap();
    let App::DnsError(e) = p.app else { panic!("expected dns error, got {:?}", p.app) };
    assert!(matches!(e, ParseError::Malformed { layer: Layer::Dns, .. }));
}

fn ipv6_udp_with_hop_by_hop() -> Vec<u8> {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let udp = [0x13, 0x88, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let hop_by_hop = [PROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
    let payload_len = (hop_by_hop.len() + udp.len()) as u16;

    let mut pkt = vec![0x60, 0, 0, 0];
    pkt.extend_from_slice(&payload_len.to_be_bytes());
    pkt.push(0);
    pkt.push(64);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(&hop_by_hop);
    pkt.extend_from_slice(&udp);
    pkt
}

#[test]
fn ipv6_extension_header_walk_on_raw_link() {
    let pkt = ipv6_udp_with_hop_by_hop();
    let p = packet::parse(
        LinkType::Raw,
        &Frame {
            ts_us: TS,
            wire_len: pkt.len() as u32,
            data: &pkt,
        },
    )
    .unwrap();
    let ip = p.ip.unwrap();
    assert!(ip.src.is_ipv6());
    assert_eq!(ip.proto, PROTO_UDP);
    assert_eq!(p.transport.ports(), (5000, 53));
}

#[test]
fn null_link_uses_version_nibble() {
    let eth = synth::tcp_segment(addr(10, 0, 0, 1, 1), addr(10, 0, 0, 2, 2), 0, 0);
    let mut null = vec![2, 0, 0, 0];
    null.extend_from_slice(&eth[14..]);
    let p = packet::parse(
        LinkType::Null,
        &Frame {
            ts_us: TS,
            wire_len: null.len() as u32,
            data: &null,
        },
    )
    .unwrap();
    assert!(matches!(p.transport, Transport::Tcp(_)));
}

proptest! {
    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        for link in [LinkType::Ethernet, LinkType::Null, LinkType::Raw] {
            let _ = packet::parse(link, &Frame { ts_us: TS, wire_len: data.len() as u32, data: &data });
        }
    }

    #[test]
    fn mutated_dns_never_panics(idx in 0usize..80, byte in any::<u8>(), cut in 0usize..80) {
        let mut frame = synth::dns_query(addr(10, 0, 0, 9, 5000), addr(10, 0, 0, 1, 53), 5, "mail.example.org", synth::DNS_TYPE_A);
        let i = idx % frame.len();
        frame[i] = byte;
        frame.truncate(frame.len() - cut.min(frame.len()));
        let _ = parse_eth(&frame);
    }
}
