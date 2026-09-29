use super::addr::{AddrHeader, TargetAddr, TargetAddrRef};
use anyhow::Result;
use bytes::Bytes;

/// MQP-2 datagram frame type: the first byte of every DATAGRAM body (TCP-open
/// streams start with the address `atyp` instead, so the two cannot be confused).
pub const MQP_DGRAM_TYPE: u8 = 0x02;

/// `type u8 | sess u32 LE` — the fixed prefix every MQP-2 datagram carries
/// before its address header.
pub const DGRAM_PREFIX_LEN: usize = 1 + 4;

/// Standalone default for [`encode_datagram`], used only by callers that have
/// no live connection to ask (tests, tooling).
///
/// Both relays must instead pass `Connection::max_datagram_size()`, which is
/// the largest DATAGRAM body QUIC will actually carry on the *current* path.
/// Hard-coding this value in a relay is what made every UDP payload above
/// 1338 B silently disappear on a 1472 B path (see `dgram_payload_cap`).
pub const DGRAM_DEFAULT_LIMIT: usize = 1350;

/// Build a UDP DATAGRAM body: type + sess + addr header + payload.
/// sess scopes the packet to one UDP ASSOCIATE so concurrent associations sharing
/// a QUIC connection never steal each other's replies. Returns None if exceeds limit.
pub fn encode_datagram(sess: u32, addr: &TargetAddr, payload: &[u8]) -> Option<Bytes> {
    encode_datagram_with_limit(sess, addr, payload, DGRAM_DEFAULT_LIMIT)
}

/// UDP payload bytes that fit in a datagram of `limit` **total** MQP-2 bytes
/// for `address`, i.e. `limit` minus the fixed prefix and the address header.
///
/// `limit` is the value of `Connection::max_datagram_size()`: quinn already
/// subtracts the QUIC packet overhead and the DATAGRAM frame header, so the
/// returned number *is* the usable UDP payload budget on the current path —
/// not a guess and not a policy cap. Saturates to 0 when the address header
/// alone does not fit, which the encoder then reports as `TooLarge`.
pub fn dgram_payload_cap(limit: usize, address: &TargetAddrRef<'_>) -> usize {
    match address.header() {
        Ok(h) => limit.saturating_sub(DGRAM_PREFIX_LEN + h.len()),
        Err(_) => 0,
    }
}

pub fn encode_datagram_with_limit(
    sess: u32,
    addr: &TargetAddr,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    encode_datagram_ref_with_limit(sess, &addr.as_ref(), payload, limit)
}

/// Same as [`encode_datagram_with_limit`] but takes the borrowed address form,
/// keeping the per-packet path free of domain `String` allocations.
///
/// quinn's `send_datagram` takes an owned `Bytes`, so one allocation per
/// outbound datagram is inherent to the API — and it cannot be pooled: the
/// driver frees that allocation on its own task once the datagram is
/// transmitted, where no reservation could ever hand it back. What this
/// function does avoid is *reallocation*: the address header is validated and
/// measured up front so the buffer is `with_capacity`ed to the exact final
/// size and then filled in a single pass, instead of starting at 40 bytes and
/// growing (copying the payload) on the way.
pub fn encode_datagram_ref_with_limit(
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let header = addr.header().ok()?;
    encode_datagram_with_header(sess, &header, payload, limit)
}

/// Encode with a pre-validated [`AddrHeader`]: the single-validation fast path
/// for [`DgramFragmenter::send`], which already measured the header once to
/// derive the payload/fragment budgets. Byte-identical to
/// [`encode_datagram_ref_with_limit`].
pub(crate) fn encode_datagram_with_header(
    sess: u32,
    header: &AddrHeader<'_>,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let total = DGRAM_PREFIX_LEN + header.len() + payload.len();
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(MQP_DGRAM_TYPE);
    v.extend_from_slice(&sess.to_le_bytes());
    let hdr_len = header.len();
    v.resize(v.len() + hdr_len, 0);
    let start = v.len() - hdr_len;
    let n = header.encode_into(&mut v[start..]);
    debug_assert_eq!(n, hdr_len);
    debug_assert_eq!(v.len(), DGRAM_PREFIX_LEN + hdr_len);
    v.extend_from_slice(payload);
    Some(Bytes::from(v))
}

pub fn decode_datagram(b: &[u8]) -> Result<(u32, TargetAddr, &[u8])> {
    let (sess, a, p) = decode_datagram_ref(b)?;
    Ok((sess, a.into_owned(), p))
}

/// Allocation-free variant of [`decode_datagram`] for the UDP fast paths.
pub fn decode_datagram_ref(b: &[u8]) -> Result<(u32, TargetAddrRef<'_>, &[u8])> {
    if b.len() < DGRAM_PREFIX_LEN + 1 || b[0] != MQP_DGRAM_TYPE {
        anyhow::bail!("bad dgram");
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (a, n) = TargetAddrRef::decode(&b[DGRAM_PREFIX_LEN..])?;
    Ok((sess, a, &b[DGRAM_PREFIX_LEN + n..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::addr::TargetAddrRef;

    /// P0-1 pin: `encode_datagram_with_header` (pre-measured `AddrHeader`,
    /// single `header()` call on the relay path) must stay byte-identical to
    /// `encode_datagram_ref_with_limit`, including the over-limit `None`.
    #[test]
    fn encode_with_header_byte_identical() {
        let addrs = [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 53),
            TargetAddr::Domain("a".repeat(255), 65535),
        ];
        for a in &addrs {
            let r = a.as_ref();
            let h = r.header().unwrap();
            for (sess, payload, limit) in [
                (7, &b""[..], 4096),
                (7, &b"x"[..], 4096),
                (9, &[0xabu8; 1200][..], 4096),
            ] {
                assert_eq!(
                    encode_datagram_with_header(sess, &h, payload, limit),
                    encode_datagram_ref_with_limit(sess, &r, payload, limit),
                );
            }
            // Boundary: exact-fit encodes, one byte more is `None` on both.
            let cap = 1350usize.saturating_sub(DGRAM_PREFIX_LEN + h.len());
            let fit = vec![0u8; cap];
            assert_eq!(
                encode_datagram_with_header(1, &h, &fit, 1350),
                encode_datagram_ref_with_limit(1, &r, &fit, 1350)
            );
            let over = vec![0u8; cap + 1];
            assert!(encode_datagram_with_header(1, &h, &over, 1350).is_none());
            assert!(encode_datagram_ref_with_limit(1, &r, &over, 1350).is_none());
        }
        let scoped = TargetAddrRef::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1,
            0,
            3,
        )));
        assert!(scoped.header().is_err());
        assert!(encode_datagram_ref_with_limit(0, &scoped, b"x", 4096).is_none());
    }
}
