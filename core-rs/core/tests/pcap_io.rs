use netcore_engine::pcap::{PcapError, PcapReader, PcapWriter};
use netcore_engine::LinkType;

const SNAPLEN: u32 = 65_535;

fn written(records: &[(u64, &[u8])]) -> Vec<u8> {
    let mut w = PcapWriter::new(Vec::new(), LinkType::Ethernet, SNAPLEN).unwrap();
    for (ts, data) in records {
        w.write_record(*ts, data).unwrap();
    }
    w.into_inner()
}

fn read_all(bytes: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, PcapError> {
    let mut r = PcapReader::new(bytes)?;
    let mut out = Vec::new();
    let mut buf = Vec::new();
    while let Some(h) = r.next_record(&mut buf)? {
        assert_eq!(h.cap_len as usize, buf.len());
        out.push((h.ts_us, buf.clone()));
    }
    Ok(out)
}

#[test]
fn roundtrip_preserves_records() {
    let a = [1u8, 2, 3];
    let b = [9u8; 60];
    let bytes = written(&[(1_700_000_000_123_456, &a), (1_700_000_001_000_001, &b)]);
    let back = read_all(&bytes).unwrap();
    assert_eq!(back, vec![(1_700_000_000_123_456, a.to_vec()), (1_700_000_001_000_001, b.to_vec())]);
    assert_eq!(PcapReader::new(&bytes[..]).unwrap().link_type(), LinkType::Ethernet);
}

#[test]
fn big_endian_nanosecond_file() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xA1B2_3C4Du32.to_be_bytes());
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&SNAPLEN.to_be_bytes());
    bytes.extend_from_slice(&101u32.to_be_bytes());
    bytes.extend_from_slice(&5u32.to_be_bytes());
    bytes.extend_from_slice(&7_000u32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0xAB, 0xCD]);

    let r = PcapReader::new(&bytes[..]).unwrap();
    assert_eq!(r.link_type(), LinkType::Raw);
    assert_eq!(read_all(&bytes).unwrap(), vec![(5_000_007, vec![0xAB, 0xCD])]);
}

#[test]
fn rejects_bad_magic() {
    let bytes = [0u8; 24];
    assert!(matches!(PcapReader::new(&bytes[..]), Err(PcapError::BadMagic(0))));
}

#[test]
fn rejects_unknown_link_type() {
    let mut bytes = written(&[]);
    bytes[20..24].copy_from_slice(&147u32.to_le_bytes());
    assert!(matches!(PcapReader::new(&bytes[..]), Err(PcapError::UnsupportedLinkType(147))));
}

#[test]
fn truncated_record_is_an_error() {
    let bytes = written(&[(1, &[1, 2, 3, 4])]);
    let cut = &bytes[..bytes.len() - 2];
    assert!(matches!(read_all(cut), Err(PcapError::TruncatedRecord)));
    let header_cut = &bytes[..24 + 7];
    assert!(matches!(read_all(header_cut), Err(PcapError::TruncatedRecord)));
}

#[test]
fn oversized_record_is_rejected() {
    let mut bytes = written(&[(1, &[0])]);
    bytes[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(read_all(&bytes), Err(PcapError::RecordTooLarge(_))));
}
