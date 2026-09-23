use super::need;
use crate::error::{Layer, ParseError};

const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub v6: bool,
}

pub fn parse(buf: &[u8], v6: bool) -> Result<IcmpHeader, ParseError> {
    need(buf, HEADER_LEN, Layer::Icmp)?;
    Ok(IcmpHeader {
        icmp_type: buf[0],
        code: buf[1],
        v6,
    })
}
