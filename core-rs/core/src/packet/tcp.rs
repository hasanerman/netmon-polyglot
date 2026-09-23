use super::{be16, be32, need};
use crate::error::{Layer, ParseError};

const MIN_HEADER_LEN: usize = 20;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

impl TcpHeader {
    pub fn is_syn_only(&self) -> bool {
        self.flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN
    }
}

pub fn parse(buf: &[u8]) -> Result<(TcpHeader, &[u8]), ParseError> {
    need(buf, MIN_HEADER_LEN, Layer::Tcp)?;
    let header_len = usize::from(buf[12] >> 4) * 4;
    if header_len < MIN_HEADER_LEN {
        return Err(ParseError::Malformed {
            layer: Layer::Tcp,
            reason: "data offset below 5",
        });
    }
    need(buf, header_len, Layer::Tcp)?;

    let header = TcpHeader {
        src_port: be16(buf, 0),
        dst_port: be16(buf, 2),
        seq: be32(buf, 4),
        ack: be32(buf, 8),
        flags: buf[13],
        window: be16(buf, 14),
    };
    Ok((header, &buf[header_len..]))
}
