use super::addr::{AddrHeader, TargetAddr, TargetAddrRef};
use super::error::MqpError;
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

/// Encode from a pre-encoded [`DgramPrefixCache`] prefix: byte-identical to
/// [`encode_datagram_with_header`], but the header is neither validated nor
/// re-encoded here — the cache did both once, on the destination change.
///
/// **Single copy, by construction.** The buffer is `with_capacity`ed to the
/// exact final size, the payload is copied into it once, and `Bytes::from(Vec)`
/// takes that allocation over (`len == capacity`, so no reallocation and no
/// copy). An earlier revision staged the frame through a thread-local
/// `BytesMut` and then `Bytes::copy_from_slice`d it out, which paid a *second*
/// full payload memcpy per relayed datagram. The staging saved nothing: the
/// `Bytes` handed to quinn must own a private allocation regardless, because
/// quinn's driver frees it on its own task, where no reservation could ever
/// hand it back (see `encode_datagram_ref_with_limit`).
pub(crate) fn encode_datagram_with_prefix(
    prefix: &[u8],
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let total = prefix.len() + payload.len();
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(prefix);
    v.extend_from_slice(payload);
    Some(Bytes::from(v))
}

/// Pre-encoded `type | sess | addr` prefix for one steady destination.
///
/// One instance lives in each [`DgramFragmenter`](crate::udp::DgramFragmenter)
/// (one per SOCKS association / UDP session), so the steady-state N=1 packet
/// — same sess, same dst — skips both the [`TargetAddrRef::header`]
/// validation and the [`AddrHeader::encode_into`] re-encode. Any sess or dst
/// change (including a dst that fails validation) invalidates the entry and
/// revalidates exactly once. IPv4 steady state is 12 cached bytes
/// (`1 type + 4 sess + 7 addr`).
#[derive(Debug)]
pub(crate) struct DgramPrefixCache {
    sess: u32,
    addr: Option<TargetAddr>,
    prefix: [u8; DgramPrefixCache::PREFIX_MAX],
    prefix_len: usize,
    /// `header()` validations performed; the steady-state proof for tests.
    validations: u64,
}

impl Default for DgramPrefixCache {
    fn default() -> Self {
        Self {
            sess: 0,
            addr: None,
            prefix: [0u8; Self::PREFIX_MAX],
            prefix_len: 0,
            validations: 0,
        }
    }
}

impl DgramPrefixCache {
    /// Largest prefix this cache can hold (`type | sess` + largest address).
    pub(crate) const PREFIX_MAX: usize = DGRAM_PREFIX_LEN + AddrHeader::MAX_LEN;

    /// Refresh the entry for `(sess, addr)` and return the cached prefix.
    ///
    /// Cache hit: no validation, no encode, just the stored bytes. Cache miss:
    /// exactly one `header()` validation + one prefix materialization, or
    /// `None` (entry cleared) when the address is refused — the caller reports
    /// that exactly like the old `header().is_err()` branch.
    pub(crate) fn prefix_for(&mut self, sess: u32, addr: &TargetAddrRef<'_>) -> Option<&[u8]> {
        // Compare against the owned key without allocating on the hot path:
        // `Ip` compares a `SocketAddr` copy, `Domain` compares bytes.
        let same = self.prefix_len != 0
            && self.sess == sess
            && match (&self.addr, addr) {
                (Some(TargetAddr::Ip(a)), TargetAddrRef::Ip(b)) => *a == *b,
                (Some(TargetAddr::Domain(a, ap)), TargetAddrRef::Domain(b, bp)) => {
                    *ap == *bp && a.as_str() == *b
                }
                _ => false,
            };
        if same {
            return Some(&self.prefix[..self.prefix_len]);
        }
        let Ok(header) = addr.header() else {
            // A refused dst stores nothing: the stale prefix (if any) is
            // dropped so the next lookup revalidates from scratch.
            self.addr = None;
            self.prefix_len = 0;
            return None;
        };
        self.validations += 1;
        self.sess = sess;
        self.addr = Some(addr.into_owned());
        self.prefix[0] = MQP_DGRAM_TYPE;
        self.prefix[1..DGRAM_PREFIX_LEN].copy_from_slice(&sess.to_le_bytes());
        let n = header.encode_into(&mut self.prefix[DGRAM_PREFIX_LEN..]);
        debug_assert_eq!(n, header.len());
        self.prefix_len = DGRAM_PREFIX_LEN + n;
        Some(&self.prefix[..self.prefix_len])
    }

    /// `header()` validations so far. Steady dst + sess performs exactly one,
    /// no matter how many packets are encoded.
    #[cfg(test)]
    pub(crate) fn validations(&self) -> u64 {
        self.validations
    }
}

pub fn decode_datagram(b: &[u8]) -> Result<(u32, TargetAddr, &[u8]), MqpError> {
    let (sess, a, p) = decode_datagram_ref(b)?;
    Ok((sess, a.into_owned(), p))
}

/// Allocation-free variant of [`decode_datagram`] for the UDP fast paths.
pub fn decode_datagram_ref(b: &[u8]) -> Result<(u32, TargetAddrRef<'_>, &[u8]), MqpError> {
    if b.len() < DGRAM_PREFIX_LEN + 1 || b[0] != MQP_DGRAM_TYPE {
        return Err(MqpError::Malformed("bad dgram"));
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (a, n) = TargetAddrRef::decode(&b[DGRAM_PREFIX_LEN..])?;
    Ok((sess, a, &b[DGRAM_PREFIX_LEN + n..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::addr::TargetAddrRef;

    /// N=1 fast path pin: `DgramPrefixCache` + `encode_datagram_with_prefix`
    /// (thread-local scratch, single-pass build) must stay byte-identical to
    /// `encode_datagram_ref_with_limit`, including the over-limit `None` and
    /// the refused-address `None`.
    #[test]
    fn prefix_fast_path_byte_identical() {
        let addrs = [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 53),
            TargetAddr::Domain("a".repeat(255), 65535),
        ];
        for a in &addrs {
            let r = a.as_ref();
            let mut cache = DgramPrefixCache::default();
            for (sess, payload, limit) in [
                (7u32, &b""[..], 4096usize),
                (7, &b"x"[..], 4096),
                (9, &[0xabu8; 1200][..], 4096),
            ] {
                let prefix = cache.prefix_for(sess, &r).unwrap().to_vec();
                assert_eq!(
                    encode_datagram_with_prefix(&prefix, payload, limit),
                    encode_datagram_ref_with_limit(sess, &r, payload, limit),
                );
                // Second lookup is a cache hit and still identical.
                let prefix2 = cache.prefix_for(sess, &r).unwrap().to_vec();
                assert_eq!(prefix, prefix2);
                assert_eq!(
                    encode_datagram_with_prefix(&prefix2, payload, limit),
                    encode_datagram_ref_with_limit(sess, &r, payload, limit),
                );
            }
            // Boundary: exact-fit encodes, one byte more is `None` on both.
            let h = r.header().unwrap();
            let cap = 1350usize.saturating_sub(DGRAM_PREFIX_LEN + h.len());
            let fit = vec![0u8; cap];
            let prefix = cache.prefix_for(1, &r).unwrap().to_vec();
            assert_eq!(
                encode_datagram_with_prefix(&prefix, &fit, 1350),
                encode_datagram_ref_with_limit(1, &r, &fit, 1350)
            );
            let over = vec![0u8; cap + 1];
            assert!(encode_datagram_with_prefix(&prefix, &over, 1350).is_none());
            assert!(encode_datagram_ref_with_limit(1, &r, &over, 1350).is_none());
        }
        // Refused address: `None` on both, and the failed lookup stores nothing.
        let scoped = TargetAddrRef::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1,
            0,
            3,
        )));
        let mut cache = DgramPrefixCache::default();
        assert!(cache.prefix_for(0, &scoped).is_none());
        assert!(encode_datagram_ref_with_limit(0, &scoped, b"x", 4096).is_none());
    }

    /// Steady-state bound: one `header()` validation no matter how many
    /// same-dst packets are encoded, and any sess/dst change revalidates
    /// exactly once. The encode itself is allocation-flat by construction
    /// (one exact-size `Vec` per frame, handed to `Bytes` whole — see
    /// `encode_datagram_with_prefix`), which is why there is no scratch
    /// capacity to assert on any more.
    #[test]
    fn prefix_cache_steady_state_one_validation() {
        let a = TargetAddr::Ip("10.0.0.1:53".parse().unwrap());
        let b = TargetAddr::Domain("example.com".into(), 53);
        let r = a.as_ref();
        let mut cache = DgramPrefixCache::default();
        let payload = [0x5au8; 128];
        for _ in 0..32 {
            let prefix = cache.prefix_for(7, &r).unwrap().to_vec();
            let d = encode_datagram_with_prefix(&prefix, &payload, 4096).unwrap();
            assert_eq!(d.len(), prefix.len() + payload.len());
        }
        assert_eq!(cache.validations(), 1);
        // Sess change revalidates once; dst change revalidates once more.
        let _ = cache.prefix_for(8, &r).unwrap().to_vec();
        assert_eq!(cache.validations(), 2);
        let rb = b.as_ref();
        let _ = cache.prefix_for(8, &rb).unwrap().to_vec();
        assert_eq!(cache.validations(), 3);
        for _ in 0..8 {
            let _ = cache.prefix_for(8, &rb).unwrap().to_vec();
        }
        assert_eq!(cache.validations(), 3);
        // IPv4 steady prefix is the documented 12 bytes.
        let prefix = cache.prefix_for(7, &r).unwrap().to_vec();
        assert_eq!(prefix.len(), DGRAM_PREFIX_LEN + 7);
    }
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
