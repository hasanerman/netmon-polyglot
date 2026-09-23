use super::{be16, need};
use crate::error::{Layer, ParseError};

pub const PORT: u16 = 53;
const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 253;
const MAX_POINTER_JUMPS: u8 = 16;
const LABEL_KIND_MASK: u8 = 0xC0;
const LABEL_POINTER: u8 = 0xC0;
const LABEL_LITERAL: u8 = 0x00;
const QR_BIT: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub question: Option<DnsQuestion>,
}

pub fn parse(msg: &[u8]) -> Result<DnsInfo, ParseError> {
    need(msg, HEADER_LEN, Layer::Dns)?;
    let question_count = be16(msg, 4);
    let question = if question_count == 0 {
        None
    } else {
        let (name, end) = read_name(msg, HEADER_LEN)?;
        need(msg, end + 2, Layer::Dns)?;
        Some(DnsQuestion {
            name,
            qtype: be16(msg, end),
        })
    };

    Ok(DnsInfo {
        id: be16(msg, 0),
        is_response: msg[2] & QR_BIT != 0,
        opcode: (msg[2] >> 3) & 0x0F,
        rcode: msg[3] & 0x0F,
        question_count,
        answer_count: be16(msg, 6),
        question,
    })
}

fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut name = String::new();
    let mut pos = start;
    let mut resume_at = None;
    let mut jumps = 0u8;

    loop {
        let len_byte = *msg.get(pos).ok_or_else(|| truncated(pos + 1, msg.len()))?;
        match len_byte & LABEL_KIND_MASK {
            LABEL_LITERAL if len_byte == 0 => {
                pos += 1;
                break;
            }
            LABEL_LITERAL => {
                let len = usize::from(len_byte);
                let label = msg
                    .get(pos + 1..pos + 1 + len)
                    .ok_or_else(|| truncated(pos + 1 + len, msg.len()))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| printable_lower(b)));
                if name.len() > MAX_NAME_LEN {
                    return Err(malformed("name longer than 253"));
                }
                pos += 1 + len;
            }
            LABEL_POINTER => {
                let low = *msg.get(pos + 1).ok_or_else(|| truncated(pos + 2, msg.len()))?;
                resume_at.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(malformed("compression pointer loop"));
                }
                pos = (usize::from(len_byte & !LABEL_KIND_MASK) << 8) | usize::from(low);
            }
            _ => return Err(malformed("reserved label type")),
        }
    }
    Ok((name, resume_at.unwrap_or(pos)))
}

fn printable_lower(b: u8) -> char {
    if b.is_ascii_graphic() {
        char::from(b.to_ascii_lowercase())
    } else {
        '?'
    }
}

fn truncated(needed: usize, available: usize) -> ParseError {
    ParseError::Truncated {
        layer: Layer::Dns,
        needed,
        available,
    }
}

fn malformed(reason: &'static str) -> ParseError {
    ParseError::Malformed {
        layer: Layer::Dns,
        reason,
    }
}
