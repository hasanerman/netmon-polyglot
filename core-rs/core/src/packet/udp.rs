use super::{be16, need};
use crate::error::{Layer, ParseError};

const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

pub fn parse(buf: &[u8]) -> Result<(UdpHeader, &[u8]), ParseError> {
    need(buf, HEADER_LEN, Layer::Udp)?;
    let header = UdpHeader {
        src_port: be16(buf, 0),
        dst_port: be16(buf, 2),
        length: be16(buf, 4),
    };
    let declared = usize::from(header.length);
    if declared != 0 && declared < HEADER_LEN {
        return Err(ParseError::Malformed {
            layer: Layer::Udp,
            reason: "length below header size",
        });
    }
    // 0 ipv6 jumbogramda gecerli, kalanin hepsini al
    let end = if declared == 0 {
        buf.len()
    } else {
        declared.min(buf.len())
    };
    Ok((header, &buf[HEADER_LEN..end]))
}
