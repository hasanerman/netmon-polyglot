use std::fmt;
use std::io::{self, Read, Write};

use crate::packet::LinkType;

const MAGIC_MICROS: u32 = 0xA1B2_C3D4;
const MAGIC_NANOS: u32 = 0xA1B2_3C4D;
const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const MAX_RECORD_LEN: u32 = 262_144;
const MICROS_PER_SEC: u64 = 1_000_000;
const NANOS_PER_MICRO: u64 = 1_000;

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    BadMagic(u32),
    UnsupportedLinkType(u32),
    RecordTooLarge(u32),
    TruncatedRecord,
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "pcap io: {e}"),
            PcapError::BadMagic(m) => write!(f, "not a pcap file (magic {m:#010x})"),
            PcapError::UnsupportedLinkType(t) => write!(f, "unsupported link type {t}"),
            PcapError::RecordTooLarge(n) => write!(f, "record of {n} bytes exceeds limit"),
            PcapError::TruncatedRecord => f.write_str("file ends in the middle of a record"),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub ts_us: u64,
    pub cap_len: u32,
    pub wire_len: u32,
}

pub struct PcapReader<R> {
    inner: R,
    link: LinkType,
    swapped: bool,
    nanos: bool,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut inner: R) -> Result<Self, PcapError> {
        let mut header = [0u8; GLOBAL_HEADER_LEN];
        inner.read_exact(&mut header)?;
        let raw_magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let (swapped, nanos) = match raw_magic {
            MAGIC_MICROS => (false, false),
            MAGIC_NANOS => (false, true),
            m if m.swap_bytes() == MAGIC_MICROS => (true, false),
            m if m.swap_bytes() == MAGIC_NANOS => (true, true),
            m => return Err(PcapError::BadMagic(m)),
        };
        let raw_link = read_u32(&header[20..24], swapped);
        let link = LinkType::from_raw(raw_link).ok_or(PcapError::UnsupportedLinkType(raw_link))?;
        Ok(PcapReader {
            inner,
            link,
            swapped,
            nanos,
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link
    }

    pub fn next_record(&mut self, buf: &mut Vec<u8>) -> Result<Option<RecordHeader>, PcapError> {
        let mut header = [0u8; RECORD_HEADER_LEN];
        match read_full_or_eof(&mut self.inner, &mut header)? {
            ReadOutcome::Eof => return Ok(None),
            ReadOutcome::Partial => return Err(PcapError::TruncatedRecord),
            ReadOutcome::Full => {}
        }
        let sec = u64::from(read_u32(&header[0..4], self.swapped));
        let frac = u64::from(read_u32(&header[4..8], self.swapped));
        let cap_len = read_u32(&header[8..12], self.swapped);
        let wire_len = read_u32(&header[12..16], self.swapped);
        if cap_len > MAX_RECORD_LEN {
            return Err(PcapError::RecordTooLarge(cap_len));
        }

        buf.resize(cap_len as usize, 0);
        self.inner.read_exact(buf).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => PcapError::TruncatedRecord,
            _ => PcapError::Io(e),
        })?;

        let micros = if self.nanos { frac / NANOS_PER_MICRO } else { frac };
        Ok(Some(RecordHeader {
            ts_us: sec * MICROS_PER_SEC + micros,
            cap_len,
            wire_len,
        }))
    }
}

pub struct PcapWriter<W> {
    inner: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut inner: W, link: LinkType, snaplen: u32) -> io::Result<Self> {
        let mut header = Vec::with_capacity(GLOBAL_HEADER_LEN);
        header.extend_from_slice(&MAGIC_MICROS.to_le_bytes());
        header.extend_from_slice(&VERSION_MAJOR.to_le_bytes());
        header.extend_from_slice(&VERSION_MINOR.to_le_bytes());
        header.extend_from_slice(&0i32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&snaplen.to_le_bytes());
        header.extend_from_slice(&(link as u32).to_le_bytes());
        inner.write_all(&header)?;
        Ok(PcapWriter { inner })
    }

    pub fn write_record(&mut self, ts_us: u64, data: &[u8]) -> io::Result<()> {
        let len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;
        let sec = u32::try_from(ts_us / MICROS_PER_SEC)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timestamp past 2106"))?;
        let usec = (ts_us % MICROS_PER_SEC) as u32;
        self.inner.write_all(&sec.to_le_bytes())?;
        self.inner.write_all(&usec.to_le_bytes())?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(data)
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

enum ReadOutcome {
    Full,
    Partial,
    Eof,
}

fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(ReadOutcome::Eof),
            Ok(0) => return Ok(ReadOutcome::Partial),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ReadOutcome::Full)
}

fn read_u32(bytes: &[u8], swapped: bool) -> u32 {
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if swapped {
        raw.swap_bytes()
    } else {
        raw
    }
}
