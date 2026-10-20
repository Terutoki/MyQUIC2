use super::addr::{AddrHeader, TargetAddrRef};
use super::error::MqpError;
use bytes::Bytes;

pub const MQP_DGRAM_BATCH: u8 = 0x06;
pub const BATCH_PREFIX_LEN: usize = 1 + 4;
pub const MAX_BATCH_ITEMS: usize = 16;
pub const BATCH_ITEM_OVERHEAD: usize = 2;
pub const BATCH_SMALL_MAX: usize = 512;

/// Wire length of one BATCH frame carrying `items` payloads whose bodies total
/// `payload_bytes`, for an address header of `header_len` bytes.
///
/// This is the single definition of the budget arithmetic: [`encode_batch_with_header`]
/// uses it to decide whether the frame fits, and send-side stagers use it to
/// avoid copying a payload into a run that the encoder would refuse later. All
/// terms saturate, because `limit` is a live path budget and this runs under
/// panic=abort; an absurd value must clamp rather than wrap.
#[must_use]
pub fn batch_frame_len(header_len: usize, items: usize, payload_bytes: usize) -> usize {
    BATCH_PREFIX_LEN
        .saturating_add(header_len)
        .saturating_add(1)
        .saturating_add(BATCH_ITEM_OVERHEAD.saturating_mul(items))
        .saturating_add(payload_bytes)
}

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
    let header = addr.header().ok()?;
    encode_batch_with_header(sess, &header, payloads, limit)
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
    let payload_bytes = payloads
        .iter()
        .fold(0usize, |n, p| n.saturating_add(p.len()));
    let total = batch_frame_len(header.len(), payloads.len(), payload_bytes);
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

/// Borrowed, allocation-free view of one BATCH frame: the session id, the
/// shared address, and a lazy iterator over the payloads.
///
/// [`decode_batch_ref`] owns the wire validation and is the reference
/// implementation; this is its twin for the receive paths, which decode one
/// BATCH frame per burst and used to pay one `Vec` allocation per frame — on
/// the very path the batching exists to make cheaper. Both validate the whole
/// frame up front (count, every item boundary, exact end), so a malformed
/// frame is rejected before a single item is yielded and [`BatchItems`] can
/// slice without re-checking.
pub struct BatchFrame<'a> {
    pub sess: u32,
    pub addr: TargetAddrRef<'a>,
    /// Everything after the `count` byte: `len u16 LE | body` repeated.
    items: &'a [u8],
    count: u8,
}

impl<'a> BatchFrame<'a> {
    /// Number of payloads in the frame (1..=[`MAX_BATCH_ITEMS`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.count as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// A fresh iterator over the payloads; callable more than once.
    #[must_use]
    pub fn payloads(&self) -> BatchItems<'a> {
        BatchItems {
            rest: self.items,
            left: self.count,
        }
    }
}

/// Lazy payload iterator of a [`BatchFrame`]; see there for the validation
/// contract.
pub struct BatchItems<'a> {
    rest: &'a [u8],
    left: u8,
}

impl<'a> Iterator for BatchItems<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.left == 0 {
            return None;
        }
        // Bounds are proven by `decode_batch`'s up-front validation, which
        // walked exactly this parse.
        let len = u16::from_le_bytes([self.rest[0], self.rest[1]]) as usize;
        let body = &self.rest[2..2 + len];
        self.rest = &self.rest[2 + len..];
        self.left -= 1;
        Some(body)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}

impl ExactSizeIterator for BatchItems<'_> {}

/// Validate one BATCH frame and return a borrowing view of it.
pub fn decode_batch(b: &[u8]) -> Result<BatchFrame<'_>, MqpError> {
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
    // Full validation before any item is handed out: `BatchItems::next` slices
    // with `rest[..]` indexing and must not be able to panic on a hostile frame.
    let mut seen = 0usize;
    let mut cursor = off;
    while seen < count {
        if cursor + 2 > b.len() {
            return Err(MqpError::Malformed("bad batch item len"));
        }
        let len = u16::from_le_bytes([b[cursor], b[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + len > b.len() {
            return Err(MqpError::Malformed("bad batch item body"));
        }
        cursor += len;
        seen += 1;
    }
    if cursor != b.len() {
        return Err(MqpError::Malformed("bad batch trailing bytes"));
    }
    Ok(BatchFrame {
        sess,
        addr,
        items: &b[off..],
        count: count as u8,
    })
}

/// Owning-index form of [`decode_batch`] (test/tooling convenience: it
/// allocates one `Vec` per frame). Production receive paths use
/// [`decode_batch`] and iterate [`BatchFrame::payloads`].
pub fn decode_batch_ref(b: &[u8]) -> Result<BatchRef<'_>, MqpError> {
    let f = decode_batch(b)?;
    Ok(BatchRef {
        sess: f.sess,
        addr: f.addr,
        payloads: f.payloads().collect(),
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

    /// The allocation-free decoder must accept exactly what the `Vec` form
    /// accepts, yield the same payloads in the same order, be re-iterable, and
    /// still reject every malformed shape (the iterator slices without
    /// re-checking, so the up-front validation is what keeps it panic-free).
    #[test]
    fn batch_iter_matches_the_vec_form_and_rejects_malformed() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let r = addr.as_ref();
        let payloads: Vec<&[u8]> = vec![b"", b"a", &[0x5Au8; 400], b"tail"];
        let body = encode_batch(9, &r, &payloads, 4096).expect("encode");
        let f = decode_batch(&body).expect("decode");
        assert_eq!(f.sess, 9);
        assert_eq!(f.len(), payloads.len());
        assert!(!f.is_empty());
        assert_eq!(f.payloads().collect::<Vec<_>>(), payloads);
        // Re-iterable: two passes must agree (the server's batch branch walks
        // the frame once per arm).
        assert_eq!(f.payloads().collect::<Vec<_>>(), payloads);
        // Same bytes, same verdict as the allocating form.
        let v = decode_batch_ref(&body).expect("vec form decodes too");
        assert_eq!(v.sess, f.sess);
        assert_eq!(v.payloads, payloads);
        assert_eq!(v.addr, f.addr);

        // Truncations at every prefix must be `Err`, never a panic or a short
        // item list: that is the property the lazy iterator relies on.
        for cut in 0..body.len() {
            let head = &body[..cut];
            assert!(
                decode_batch(head).is_err(),
                "a {cut}-byte prefix must be rejected"
            );
            assert!(decode_batch_ref(head).is_err(), "forms must agree at {cut}");
        }
        // Trailing bytes, a zero count and an over-cap count stay rejected.
        let mut trailing = body.to_vec();
        trailing.push(0);
        assert!(decode_batch(&trailing).is_err());
        assert!(decode_batch_ref(&trailing).is_err());
        assert!(decode_batch(b"\x06\x01").is_err());
        assert!(decode_batch(b"\x02\x01\x02\x03\x04\x05").is_err());
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

    /// The budget helper and the encoder must agree byte-for-byte: every
    /// accepted frame is exactly the predicted length, and a frame one byte
    /// over the predicted limit is refused. This is the arithmetic the client
    /// stager uses to decide whether to append before copying, so a drift here
    /// would either waste a staging copy or stage a frame the encoder rejects.
    #[test]
    fn batch_frame_len_is_the_encoder_budget() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let header = addr.as_ref().header().unwrap();
        let payloads: Vec<&[u8]> = vec![b"", b"a", &[0x5Au8; 28], b"query"];
        let bytes: usize = payloads.iter().map(|p| p.len()).sum();
        let want = batch_frame_len(header.len(), payloads.len(), bytes);

        let body = encode_batch(7, &addr.as_ref(), &payloads, want).expect("exact fit");
        assert_eq!(body.len(), want);
        assert!(encode_batch(7, &addr.as_ref(), &payloads, want - 1).is_none());

        // Empty/over-cap counts are refused by the encoder regardless of the
        // (otherwise zero-sized) budget.
        assert!(encode_batch(7, &addr.as_ref(), &[], usize::MAX).is_none());
        let many: Vec<&[u8]> = vec![b"x"; MAX_BATCH_ITEMS + 1];
        assert!(encode_batch(7, &addr.as_ref(), &many, usize::MAX).is_none());
    }
}
