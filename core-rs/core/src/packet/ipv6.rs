use std::net::{IpAddr, Ipv6Addr};

use super::{be16, need, IpHeader};
use crate::error::{Layer, ParseError};

const HEADER_LEN: usize = 40;
const MAX_EXTENSION_HEADERS: usize = 8;

const NH_HOP_BY_HOP: u8 = 0;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_AUTH: u8 = 51;
const NH_DEST_OPTS: u8 = 60;

const FRAGMENT_HEADER_LEN: usize = 8;
const FRAGMENT_OFFSET_SHIFT: u16 = 3;
const FRAGMENT_MORE_BIT: u16 = 0x0001;

pub fn parse(buf: &[u8]) -> Result<(IpHeader, &[u8]), ParseError> {
    need(buf, HEADER_LEN, Layer::Ipv6)?;
    if buf[0] >> 4 != 6 {
        return Err(malformed("version is not 6"));
    }
    let payload_len = usize::from(be16(buf, 4));
    let end = (HEADER_LEN + payload_len).min(buf.len());
    let packet = &buf[..end];

    let mut header = IpHeader {
        src: IpAddr::V6(addr_at(buf, 8)),
        dst: IpAddr::V6(addr_at(buf, 24)),
        proto: buf[6],
        ttl: buf[7],
        more_fragments: false,
        fragment_offset: 0,
    };

    let mut offset = HEADER_LEN;
    for _ in 0..MAX_EXTENSION_HEADERS {
        let ext_len = match header.proto {
            NH_HOP_BY_HOP | NH_ROUTING | NH_DEST_OPTS => {
                need(packet, offset + 2, Layer::Ipv6)?;
                (usize::from(packet[offset + 1]) + 1) * 8
            }
            NH_AUTH => {
                need(packet, offset + 2, Layer::Ipv6)?;
                (usize::from(packet[offset + 1]) + 2) * 4
            }
            NH_FRAGMENT => {
                need(packet, offset + FRAGMENT_HEADER_LEN, Layer::Ipv6)?;
                let field = be16(packet, offset + 2);
                header.fragment_offset = field >> FRAGMENT_OFFSET_SHIFT;
                header.more_fragments = field & FRAGMENT_MORE_BIT != 0;
                FRAGMENT_HEADER_LEN
            }
            _ => return Ok((header, &packet[offset..])),
        };
        need(packet, offset + ext_len, Layer::Ipv6)?;
        header.proto = packet[offset];
        offset += ext_len;
    }
    Err(malformed("too many extension headers"))
}

fn addr_at(buf: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[at..at + 16]);
    Ipv6Addr::from(octets)
}

fn malformed(reason: &'static str) -> ParseError {
    ParseError::Malformed {
        layer: Layer::Ipv6,
        reason,
    }
}
