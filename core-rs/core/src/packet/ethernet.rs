use super::{be16, need};
use crate::error::{Layer, ParseError};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

pub const HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
const MAX_VLAN_TAGS: u8 = 2;
const MAC_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: [u8; MAC_LEN],
    pub src: [u8; MAC_LEN],
    pub ethertype: u16,
    pub vlan_tags: u8,
}

pub fn parse(buf: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseError> {
    need(buf, HEADER_LEN, Layer::Link)?;
    let mut dst = [0u8; MAC_LEN];
    let mut src = [0u8; MAC_LEN];
    dst.copy_from_slice(&buf[0..MAC_LEN]);
    src.copy_from_slice(&buf[MAC_LEN..2 * MAC_LEN]);

    let mut ethertype = be16(buf, 12);
    let mut offset = HEADER_LEN;
    let mut vlan_tags = 0u8;
    while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        if vlan_tags == MAX_VLAN_TAGS {
            return Err(ParseError::Malformed {
                layer: Layer::Link,
                reason: "too many vlan tags",
            });
        }
        need(buf, offset + VLAN_TAG_LEN, Layer::Link)?;
        ethertype = be16(buf, offset + 2);
        offset += VLAN_TAG_LEN;
        vlan_tags += 1;
    }

    let header = EthernetHeader {
        dst,
        src,
        ethertype,
        vlan_tags,
    };
    Ok((header, &buf[offset..]))
}
