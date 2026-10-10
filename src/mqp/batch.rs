use super::addr::{AddrHeader, TargetAddrRef};
use super::error::MqpError;
use bytes::Bytes;

pub const MQP_DGRAM_BATCH: u8 = 0x06;
pub const BATCH_PREFIX_LEN: usize = 1 + 4;
pub const MAX_BATCH_ITEMS: usize = 16;
pub const BATCH_ITEM_OVERHEAD: usize = 2;
pub const BATCH_SMALL_MAX: usize = 512;

pub fn is_batch(b: &[u8]) -> bool {
    b.first() == Some(&MQP_DGRAM_BATCH)
}

pub fn batch_sess(b: &[u8]) -> Option<u32> {
    if b.len() < BATCH_PREFIX_LEN + 1 || b[0] != MQP_DGRAM_BATCH {
        return None;
    }
    Some(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))
}

pub fn encode_batch(
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payloads: &[&[u8]],
    limit: usize,
) -> Option<Bytes> {
    if payloads.is_empty() || payloads.len() > MAX_BATCH_ITEMS {
        return None;
    }
    let header = addr.header().ok()?;
    let mut total = BATCH_PREFIX_LEN + header.len() + 1;
    for p in payloads {
        total = total.saturating_add(BATCH_ITEM_OVERHEAD + p.len());
    }
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(MQP_DGRAM_BATCH);
    v.extend_from_slice(&sess.to_le_bytes());
    let hdr_len = header.len();
    v.resize(v.len() + hdr_len, 0);
    let start = v.len() - hdr_len;
    let n = header.encode_into(&mut v[start..]);
    debug_assert_eq!(n, hdr_len);
    v.push(payloads.len() as u8);
    for p in payloads {
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
    }
    Some(Bytes::from(v))
}

pub fn encode_batch_with_header(
    sess: u32,
    header: &AddrHeader<'_>,
    payloads: &[&[u8]],
    limit: usize,
) -> Option<Bytes> {
    if payloads.is_empty() || payloads.len() > MAX_BATCH_ITEMS {
        return None;
    }
    let mut total = BATCH_PREFIX_LEN + header.len() + 1;
    for p in payloads {
        total = total.saturating_add(BATCH_ITEM_OVERHEAD + p.len());
    }
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(MQP_DGRAM_BATCH);
    v.extend_from_slice(&sess.to_le_bytes());
    let hdr_len = header.len();
    v.resize(v.len() + hdr_len, 0);
    let start = v.len() - hdr_len;
    let n = header.encode_into(&mut v[start..]);
    debug_assert_eq!(n, hdr_len);
    v.push(payloads.len() as u8);
    for p in payloads {
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
    }
    Some(Bytes::from(v))
}

pub struct BatchRef<'a> {
    pub sess: u32,
    pub addr: TargetAddrRef<'a>,
    pub payloads: Vec<&'a [u8]>,
}

pub fn decode_batch_ref(b: &[u8]) -> Result<BatchRef<'_>, MqpError> {
    if b.len() < BATCH_PREFIX_LEN + 1 || b[0] != MQP_DGRAM_BATCH {
        return Err(MqpError::Malformed("bad batch"));
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (addr, n) = TargetAddrRef::decode(&b[BATCH_PREFIX_LEN..])?;
    let mut off = BATCH_PREFIX_LEN + n;
    if off >= b.len() {
        return Err(MqpError::Malformed("bad batch count"));
    }
    let count = b[off] as usize;
    off += 1;
    if count == 0 || count > MAX_BATCH_ITEMS {
        return Err(MqpError::BadBatchCount(count as u8));
    }
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 2 > b.len() {
            return Err(MqpError::Malformed("bad batch item len"));
        }
        let len = u16::from_le_bytes([b[off], b[off + 1]]) as usize;
        off += 2;
        if off + len > b.len() {
            return Err(MqpError::Malformed("bad batch item body"));
        }
        payloads.push(&b[off..off + len]);
        off += len;
    }
    if off != b.len() {
        return Err(MqpError::Malformed("bad batch trailing bytes"));
    }
    Ok(BatchRef {
        sess,
        addr,
        payloads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::addr::TargetAddr;

    #[test]
    fn batch_roundtrip() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let r = addr.as_ref();
        let payloads: Vec<&[u8]> = vec![b"hello", b"world!"];
        let b = encode_batch(7, &r, &payloads, 1472).expect("encode");
        assert!(is_batch(&b));
        assert_eq!(batch_sess(&b), Some(7));
        let d = decode_batch_ref(&b).expect("decode");
        assert_eq!(d.sess, 7);
        assert_eq!(d.payloads.len(), 2);
        assert_eq!(d.payloads[0], b"hello");
        assert_eq!(d.payloads[1], b"world!");
    }

    #[test]
    fn batch_rejects_bad_shapes() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let r = addr.as_ref();
        assert!(encode_batch(1, &r, &[], 1472).is_none());
        let many: Vec<&[u8]> = vec![b"x"; MAX_BATCH_ITEMS + 1];
        assert!(encode_batch(1, &r, &many, 1472).is_none());
        let big = vec![0u8; 2000];
        let big_refs: Vec<&[u8]> = vec![&big];
        assert!(encode_batch(1, &r, &big_refs, 1472).is_none());
        assert!(decode_batch_ref(b"\x06\x01").is_err());
        assert!(decode_batch_ref(b"\x02\x01\x02\x03\x04\x05").is_err());
    }

    #[test]
    fn batch_single_item_matches_datagram_budget() {
        let addr = TargetAddr::Ip("10.0.0.1:443".parse().unwrap());
        let r = addr.as_ref();
        let p: &[u8] = b"abc";
        let b = encode_batch(3, &r, &[p], 1472).expect("encode");
        let d = decode_batch_ref(&b).expect("decode");
        assert_eq!(d.payloads, vec![p]);
    }
}
