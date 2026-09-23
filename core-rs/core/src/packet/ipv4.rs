use std::net::{IpAddr, Ipv4Addr};

use super::{be16, need, IpHeader};
use crate::error::{Layer, ParseError};

const MIN_HEADER_LEN: usize = 20;
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;

pub fn parse(buf: &[u8]) -> Result<(IpHeader, &[u8]), ParseError> {
    need(buf, MIN_HEADER_LEN, Layer::Ipv4)?;
    if buf[0] >> 4 != 4 {
        return Err(malformed("version is not 4"));
    }
    let header_len = usize::from(buf[0] & 0x0F) * 4;
    if header_len < MIN_HEADER_LEN {
        return Err(malformed("header length below 20"));
    }
    need(buf, header_len, Layer::Ipv4)?;

    let total_len = usize::from(be16(buf, 2));
    if total_len < header_len {
        return Err(malformed("total length smaller than header"));
    }
    let payload_end = total_len.min(buf.len());

    let flags_offset = be16(buf, 6);
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    let header = IpHeader {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        proto: buf[9],
        ttl: buf[8],
        more_fragments: flags_offset & FLAG_MORE_FRAGMENTS != 0,
        fragment_offset: flags_offset & FRAGMENT_OFFSET_MASK,
    };
    Ok((header, &buf[header_len..payload_end]))
}

fn malformed(reason: &'static str) -> ParseError {
    ParseError::Malformed {
        layer: Layer::Ipv4,
        reason,
    }
}
