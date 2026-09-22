//! MyQUIC2 common: MQP-2 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

/// Compile the wrapped statements only in a statistics-enabled build (the
/// default). `--no-default-features` removes them entirely: the per-packet
/// counters are shared atomics, and at a few hundred thousand packets per
/// second their cache lines are the contention, not the code.
macro_rules! stats_only {
    ($($t:tt)*) => {
        #[cfg(feature = "stats")]
        {
            $($t)*
        }
    };
}

// ---------------- Address codec (MQP-2) ----------------
// wire: atyp u8 | addr | port u16 BE ; atyp: 0x01 v4, 0x04 v6, 0x03 domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// Borrowed form of [`TargetAddr`], used on per-datagram hot paths so a
/// domain-typed packet never allocates a `String` just to hit the DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAddrRef<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl TargetAddr {
    pub fn as_ref(&self) -> TargetAddrRef<'_> {
        match self {
            TargetAddr::Ip(s) => TargetAddrRef::Ip(*s),
            TargetAddr::Domain(d, p) => TargetAddrRef::Domain(d, *p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.as_ref().encode(out)
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        let (a, n) = TargetAddrRef::decode(b)?;
        Ok((a.into_owned(), n))
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            TargetAddr::Ip(s) => Some(*s),
            _ => None,
        }
    }
}

/// A [`TargetAddrRef`] that has already been validated and measured, so the
/// caller can size its output buffer exactly once instead of encoding twice.
///
/// Both operations are pure, so splitting them out of [`TargetAddrRef::encode`]
/// never changes which addresses are accepted — `encode` remains the single
/// definition of the wire format and the validation rules.
#[derive(Debug, Clone, Copy)]
pub struct AddrHeader<'a> {
    addr: TargetAddrRef<'a>,
    len: usize,
}

impl<'a> AddrHeader<'a> {
    /// Wire length of the largest address form (`atyp | addr | port`).
    pub const MAX_LEN: usize = 1 + 1 + 255 + 2;

    /// Wire length of `addr` (`atyp | addr | port`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append the header to `out`, returning the byte count written.
    ///
    /// The allocation-free twin of [`AddrHeader::encode`], for per-connection
    /// paths that own a fixed buffer ([`AddrHeader::MAX_LEN`] bytes covers every
    /// form). Validation already happened in [`TargetAddrRef::header`], so this
    /// only writes bytes; a debug build asserts the two agree on the length.
    ///
    /// # Panics
    /// Panics if `out` is shorter than the encoded header.
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        let n = match self.addr {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                out[0] = 0x01;
                out[1..5].copy_from_slice(&a.ip().octets());
                out[5..7].copy_from_slice(&a.port().to_be_bytes());
                7
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                out[0] = 0x04;
                out[1..17].copy_from_slice(&a.ip().octets());
                out[17..19].copy_from_slice(&a.port().to_be_bytes());
                19
            }
            TargetAddrRef::Domain(d, p) => {
                let b = d.as_bytes();
                out[0] = 0x03;
                out[1] = b.len() as u8;
                out[2..2 + b.len()].copy_from_slice(b);
                out[2 + b.len()..4 + b.len()].copy_from_slice(&p.to_be_bytes());
                4 + b.len()
            }
        };
        debug_assert_eq!(n, self.len, "encoder and header() disagree");
        n
    }

    /// Append the header to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.addr.encode(out)
    }
}

impl<'a> TargetAddrRef<'a> {
    pub fn into_owned(self) -> TargetAddr {
        match self {
            TargetAddrRef::Ip(s) => TargetAddr::Ip(s),
            TargetAddrRef::Domain(d, p) => TargetAddr::Domain(d.to_owned(), p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match *self {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v4");
                }
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v6");
                }
                if a.scope_id() != 0 {
                    anyhow::bail!("v6 scope_id dropped on wire, refuse scoped addr");
                }
                out.push(0x04);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddrRef::Domain(d, p) => {
                let bytes = d.as_bytes();
                if bytes.is_empty() {
                    anyhow::bail!("empty domain");
                }
                if bytes.len() > 255 {
                    anyhow::bail!("domain too long");
                }
                out.push(0x03);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Validate and measure this address once, so a hot-path encoder can
    /// `with_capacity` the exact size (no growth reallocation) and skip the
    /// second validation pass that a separate `encode` call would repeat.
    pub fn header(&self) -> Result<AddrHeader<'a>> {
        let len = match *self {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v4");
                }
                1 + 4 + 2
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v6");
                }
                if a.scope_id() != 0 {
                    anyhow::bail!("v6 scope_id dropped on wire, refuse scoped addr");
                }
                1 + 16 + 2
            }
            TargetAddrRef::Domain(d, _) => {
                let n = d.len();
                if n == 0 {
                    anyhow::bail!("empty domain");
                }
                if n > 255 {
                    anyhow::bail!("domain too long");
                }
                1 + 1 + n + 2
            }
        };
        Ok(AddrHeader { addr: *self, len })
    }

    pub fn decode(b: &'a [u8]) -> Result<(Self, usize)> {
        if b.is_empty() {
            anyhow::bail!("empty addr");
        }
        let atyp = b[0];
        match atyp {
            0x01 => {
                if b.len() < 7 {
                    anyhow::bail!("short v4");
                }
                let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
                if ip.is_unspecified() {
                    anyhow::bail!("refuse unspecified v4 target");
                }
                let port = u16::from_be_bytes([b[5], b[6]]);
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 7))
            }
            0x04 => {
                if b.len() < 19 {
                    anyhow::bail!("short v6");
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[1..17]);
                let ip = IpAddr::from(o);
                if ip.is_unspecified() {
                    anyhow::bail!("refuse unspecified v6 target");
                }
                let port = u16::from_be_bytes([b[17], b[18]]);
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 19))
            }
            0x03 => {
                if b.len() < 2 {
                    anyhow::bail!("short domain");
                }
                let n = b[1] as usize;
                if n == 0 {
                    anyhow::bail!("bad domain len");
                }
                if b.len() < 2 + n + 2 {
                    anyhow::bail!("short domain body");
                }
                let d = std::str::from_utf8(&b[2..2 + n]).context("bad domain utf8")?;
                let port = u16::from_be_bytes([b[2 + n], b[3 + n]]);
                Ok((TargetAddrRef::Domain(d, port), 4 + n))
            }
            _ => anyhow::bail!("bad atyp {atyp}"),
        }
    }
}

/// Versioned ALPN identifier. Bumped to `/2` together with the MQP-2 TCP-open
/// ACK (status byte + bound address); a version-skewed peer now fails the TLS
/// handshake with a clear error instead of misparsing the ACK as app data.
/// The default config ALPN is now `h3` (see `normalize_alpn`); set
/// `alpn = "myquic2/2"` explicitly to restore this identifier and its
/// fail-closed skew guard.
pub const MQP_ALPN: &[u8] = b"myquic2/2";

/// Resolve the configured ALPN: empty/unset keeps the default `h3`
/// masquerade. `h3` hides only the ALPN label — the self-signed cert and the
/// MQP framing stay fingerprintable, so this is obfuscation, not a full
/// HTTP/3 disguise. Explicit `myquic2/2` restores the versioned identifier
/// (and its fail-closed skew guard against real HTTP/3 peers); either way
/// both sides must run the same value.
pub fn normalize_alpn(configured: Option<&str>) -> Vec<u8> {
    match configured {
        Some(s) if !s.is_empty() => s.as_bytes().to_vec(),
        _ => b"h3".to_vec(),
    }
}

/// MQP-2 TCP open acknowledgement (server -> client).
///
/// `status u8 (0x00) | atyp u8 | addr | port u16 BE` — the bound address is
/// the server-side socket it dialed the target from, so the client can put the
/// real BND.ADDR/BND.PORT into its SOCKS5 success reply (RFC 1928).
///
/// Both sides must run the same version: the client MUST wait for exactly
/// this byte and fail the flow otherwise. There is intentionally NO silent
/// fallback for old peers — falling back would let the first application
/// byte be mistaken for (or polluted by) the ACK (see B1).
pub const MQP_TCP_ACK: u8 = 0x00;

/// Wire cap for the connection-auth token: the server reads at most this many
/// bytes, so a longer configured token can never authenticate and must be
/// rejected at startup instead of failing every handshake.
pub const AUTH_TOKEN_MAX_BYTES: usize = 256;

/// Encode a bound address for the ACK (no status byte). Datagram/stream
/// target encoding rejects unspecified addresses; BND may legitimately be
/// `0.0.0.0:0`, so this is a dedicated encoder that is never used to dial.
pub fn encode_bnd_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + MAX_BND_LEN, 0);
    let n = encode_bnd_addr_into(addr, &mut out[start..]);
    out.truncate(start + n);
}

/// Number of bytes [`encode_bnd_addr_into`] can write: `atyp | addr | port`
/// for the largest address form.
pub const MAX_BND_LEN: usize = 1 + 16 + 2;

/// Allocation-free form of [`encode_bnd_addr`] for hot paths that already own a
/// fixed buffer (the MQP-2 ACK is at most [`MAX_BND_LEN`] bytes). `out` must be
/// at least that long. Returns the number of bytes written.
///
/// # Panics
/// Panics if `out` is shorter than [`MAX_BND_LEN`].
pub fn encode_bnd_addr_into(addr: SocketAddr, out: &mut [u8]) -> usize {
    assert!(out.len() >= MAX_BND_LEN, "bnd buffer too small");
    match addr {
        SocketAddr::V4(a) => {
            out[0] = 0x01;
            out[1..5].copy_from_slice(&a.ip().octets());
            out[5..7].copy_from_slice(&a.port().to_be_bytes());
            7
        }
        SocketAddr::V6(a) => {
            out[0] = 0x04;
            out[1..17].copy_from_slice(&a.ip().octets());
            out[17..19].copy_from_slice(&a.port().to_be_bytes());
            19
        }
    }
}

/// Decode the address portion of an ACK (`atyp | addr | port`).
/// Returns the address and the number of bytes consumed.
pub fn decode_bnd_addr(b: &[u8]) -> Result<(SocketAddr, usize)> {
    if b.is_empty() {
        anyhow::bail!("empty bnd");
    }
    match b[0] {
        0x01 => {
            if b.len() < 7 {
                anyhow::bail!("short bnd v4");
            }
            let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Ok((SocketAddr::new(ip, port), 7))
        }
        0x04 => {
            if b.len() < 19 {
                anyhow::bail!("short bnd v6");
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Ok((SocketAddr::new(IpAddr::from(o), port), 19))
        }
        a => anyhow::bail!("bad bnd atyp {a}"),
    }
}

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

/// MQP-2 fragmented-datagram frame type.
///
/// `0x02` is the single-frame datagram and the address atyp values are
/// `0x01/0x03/0x04`, so `0x05` is free. A peer that predates fragmentation
/// rejects this type in `decode_datagram_ref` and drops the datagram — the
/// pre-fix behaviour for oversized payloads, never a misparse.
pub const MQP_DGRAM_FRAG: u8 = 0x05;

/// Fixed part of a fragment header: `type | sess | id | idx | total`.
pub const FRAG_PREFIX_LEN: usize = 1 + 4 + 2 + 1 + 1;

/// Largest UDP payload the protocol will carry or reassemble.
///
/// # Why 8 KiB rather than the 65507 B UDP maximum
///
/// 8192 B is 5.5x the largest datagram any real-time medium produces (1472 B
/// on a 1500 B MTU), so it is not a limit the target workload can reach. The
/// reason not to go higher is **loss amplification**: a payload split into `F`
/// fragments arrives only if all `F` do, so a datagram's delivery probability is
/// `(1-p)^F` while its cost stays `F` fragments. On a 1 %-loss link a 64 KiB
/// payload is 47 fragments — 62 % delivery at 47x the bytes, and at 5 % loss it
/// is 9 %, i.e. bandwidth spent on a datagram that will not arrive.
///
/// Fragmentation still beats the alternative (dropping it outright), so the wire
/// format is sized to reach the full UDP maximum — see
/// [`MQP_FRAG_MAX_TOTAL`] — and raising this constant is a one-line change if a
/// deployment needs NFS-over-UDP or outsized EDNS0 responses.
pub const MQP_FRAG_MAX_PAYLOAD: usize = 8192;

/// Largest number of fragments one payload may be split into.
///
/// `u8` on the wire, and deliberately large enough to carry
/// [`UDP_PAYLOAD_MAX`] at QUIC's *minimum* path MTU, so raising
/// [`MQP_FRAG_MAX_PAYLOAD`] to the UDP maximum never becomes a wire-format
/// change. The compile-time assertion below proves that.
pub const MQP_FRAG_MAX_TOTAL: u8 = 64;

/// Maximum UDP payload for IPv4 (65535 - 20 IP - 8 UDP) or IPv6
/// (65535 - 40 - 8, ignoring jumbograms): 65507 either way.
pub const UDP_PAYLOAD_MAX: usize = 65507;

/// quinn's DATAGRAM budget at QUIC's minimum 1200 B path MTU: the smallest
/// limit any conforming path can produce, and therefore the worst case for
/// fragment sizing.
pub const MIN_PATH_DGRAM_BUDGET: usize = 1162;

const _: () = {
    // Smallest chunk a fragment can carry: the minimum path budget minus the
    // fragment prefix and the largest (IPv6) address header.
    let min_chunk = MIN_PATH_DGRAM_BUDGET - FRAG_PREFIX_LEN - (1 + 16 + 2);
    let needed = (UDP_PAYLOAD_MAX as u64).div_ceil(min_chunk as u64);
    assert!(
        needed <= MQP_FRAG_MAX_TOTAL as u64,
        "u8 fragment count cannot reach the UDP maximum at the minimum MTU"
    );
};

/// Read buffer for the UDP relays. On the server this holds a bare payload; on
/// the client it must additionally cover the SOCKS5 UDP header, so the client
/// sizes its socket buffer as `UDP_RECV_MAX + SOCKS_UDP_HDR_MAX`. Either way the
/// buffer must cover everything the protocol can carry, or the kernel truncates
/// the datagram — a silent loss with no counter behind it.
pub const UDP_RECV_MAX: usize = MQP_FRAG_MAX_PAYLOAD;

/// Largest SOCKS5 UDP framing in front of a payload:
/// `RSV(2) | FRAG(1) | atyp(1) | addr(≤16) | port(2)`.
pub const SOCKS_UDP_HDR_MAX: usize = 3 + 1 + 16 + 2;

/// One byte of slack on every relay read buffer.
///
/// `recv_from` reports the buffer length both when a datagram exactly filled it
/// and when the kernel truncated a larger one, so the two are indistinguishable
/// at `n == buf.len()`. With a byte to spare, that equality means "truncated"
/// and nothing else — otherwise every maximum-size datagram would log a false
/// truncation warning.
pub const UDP_RECV_SLACK: usize = 1;

/// How long a partial reassembly is held before it is discarded. A datagram
/// missing a fragment is undeliverable, and UDP gives the peer no reason to
/// wait longer than a retransmit-free round trip.
pub const FRAG_TIMEOUT_MS: u64 = 2_000;

/// Reassembly memory bound per connection. A partial is at most
/// [`MQP_FRAG_MAX_PAYLOAD`], and past this the oldest partial is evicted — so
/// this is also what caps how many datagrams may be in flight at once.
pub const FRAG_MAX_HELD_BYTES: usize = 256 * 1024;

/// Reassembly partial-count bound per connection.
///
/// `held` only accounts payload bytes, but each partial also owns a
/// `vec![None; total]` slot table (up to 64 `Option<Bytes>` ≈ 2 KiB) plus a
/// HashMap entry. Without a count cap a peer can force ~128 MiB of slot
/// tables with 65k single-byte fragments while `held` barely moves. The count
/// cap also bounds the `min_by_key` eviction scan to 256 entries per eviction.
pub const FRAG_MAX_PARTIALS: usize = 256;

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
fn encode_datagram_with_header(
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

// ---------------- QUIC DATAGRAM fragmentation (MQP-2 large UDP) ----------------
// A QUIC DATAGRAM cannot carry a full 1472 B UDP payload: the 12 B MQP header
// plus the QUIC packet and DATAGRAM-frame overhead exceed the path MTU, so a
// proxy built only on single-frame datagrams is strictly worse than a direct
// UDP path for large media packets (DTLS handshake flights, non-WebRTC
// conferencing stacks, TURN-wrapped payloads, modest IP fragmentation). These
// frames lift that ceiling to `MQP_FRAG_MAX_PAYLOAD` without giving up UDP
// semantics: a datagram missing any fragment is dropped, never retransmitted.

/// One decoded [`MQP_DGRAM_FRAG`] frame.
///
/// The address header is repeated on *every* fragment, which costs 7 B (IPv4)
/// or 19 B (IPv6) per fragment and buys a reassembler that needs no special
/// case for out-of-order arrival or for a lost fragment 0: every fragment is
/// self-describing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentRef<'a> {
    pub sess: u32,
    pub id: u16,
    pub idx: u8,
    pub total: u8,
    pub address: TargetAddrRef<'a>,
    pub chunk: &'a [u8],
}

/// Session id of any relay datagram, single-frame or fragment.
///
/// Both forms start `type u8 | sess u32 LE`, so routing reads the same bytes
/// either way. **A dispatcher must not switch on the type**: doing so silently
/// drops fragments before the reassembler ever sees them, which looks exactly
/// like the pre-fragmentation oversize loss. This helper is the single place
/// that knows which types are routable.
pub fn dgram_sess(b: &[u8]) -> Option<u32> {
    match b.first() {
        Some(&MQP_DGRAM_TYPE) | Some(&MQP_DGRAM_FRAG) if b.len() >= DGRAM_PREFIX_LEN => {
            Some(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))
        }
        _ => None,
    }
}

/// Largest chunk one fragment can carry for `address` under `limit`.
pub fn fragment_chunk_len(limit: usize, address: &TargetAddrRef<'_>) -> usize {
    match address.header() {
        Ok(h) => limit.saturating_sub(FRAG_PREFIX_LEN + h.len()),
        Err(_) => 0,
    }
}

/// Encode one fragment. Returns `None` if the chunk does not fit `limit`.
pub fn encode_fragment(
    sess: u32,
    id: u16,
    idx: u8,
    total: u8,
    address: &TargetAddrRef<'_>,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let header = address.header().ok()?;
    encode_fragment_with_header(sess, id, idx, total, &header, chunk, limit)
}

/// Pre-validated-header variant of [`encode_fragment`]; see
/// `encode_datagram_with_header` for why it exists.
fn encode_fragment_with_header(
    sess: u32,
    id: u16,
    idx: u8,
    total: u8,
    header: &AddrHeader<'_>,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let total_len = FRAG_PREFIX_LEN + header.len() + chunk.len();
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(MQP_DGRAM_FRAG);
    v.extend_from_slice(&sess.to_le_bytes());
    v.extend_from_slice(&id.to_le_bytes());
    v.push(idx);
    v.push(total);
    let hdr_len = header.len();
    v.resize(v.len() + hdr_len, 0);
    let start = v.len() - hdr_len;
    let n = header.encode_into(&mut v[start..]);
    debug_assert_eq!(n, hdr_len);
    debug_assert_eq!(v.len(), FRAG_PREFIX_LEN + hdr_len);
    v.extend_from_slice(chunk);
    Some(Bytes::from(v))
}

pub fn decode_fragment(b: &[u8]) -> Result<FragmentRef<'_>> {
    if b.len() < FRAG_PREFIX_LEN + 1 || b[0] != MQP_DGRAM_FRAG {
        anyhow::bail!("bad fragment");
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let id = u16::from_le_bytes([b[5], b[6]]);
    let (idx, total) = (b[7], b[8]);
    let (address, n) = TargetAddrRef::decode(&b[FRAG_PREFIX_LEN..])?;
    Ok(FragmentRef {
        sess,
        id,
        idx,
        total,
        address,
        chunk: &b[FRAG_PREFIX_LEN + n..],
    })
}

// ---------------- Config files ----------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConf {
    pub listen: String,      // e.g. 0.0.0.0:8443
    pub cert_file: String,   // server cert PEM (self-signed)
    pub key_file: String,    // server key PEM
    pub server_name: String, // e.g. myquic2, used for self-sign SAN + SNI
    #[serde(default = "d_bbr")]
    pub congestion: String, // bbr | cubic
    #[serde(default = "d_true")]
    pub gso: bool, // informational: quinn-udp auto-enables; false = log warn only
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_false")]
    pub allow_private: bool,
    /// Optional shared secret. When non-empty, every client must present it on
    /// connection setup; empty disables authentication (rely on network
    /// isolation / firewall).
    #[serde(default)]
    pub auth_token: String,
    // ---- Transport tuning (all optional; None = low-latency default) ----
    // Larger windows trade loaded latency for peak throughput: 4/8/4 MB
    // reaches ~240 Mb/s @140 ms and 8/16/8 MB reaches ~300 Mb/s, against the
    // 2/4/2 MB default (~114 Mb/s). ACK threshold 8 + 10 ms delay saves
    // reverse-path CPU at the cost of coarser RTT/loss feedback.
    #[serde(default)]
    pub stream_receive_window_mb: Option<u64>,
    #[serde(default)]
    pub receive_window_mb: Option<u64>,
    #[serde(default)]
    pub send_window_mb: Option<u64>,
    #[serde(default)]
    pub ack_threshold: Option<u32>,
    #[serde(default)]
    pub max_ack_delay_ms: Option<u64>,
    /// ALPN override (e.g. `myquic2/2` to restore the versioned identifier).
    /// Unset/empty = `h3` masquerade.
    #[serde(default)]
    pub alpn: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConf {
    pub socks_listen: String,     // e.g. 127.0.0.1:1080
    pub server_addr: String,      // e.g. 127.0.0.1:8443
    pub server_name: String,      // SNI, must match cert SAN
    pub server_cert_file: String, // pinned self-signed cert PEM
    #[serde(default = "d_bbr")]
    pub congestion: String,
    #[serde(default = "d_true")]
    pub gso: bool,
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_5")]
    pub reconnect_timeout_secs: u64,
    /// Must match the server's `auth_token` (both empty = no authentication).
    #[serde(default)]
    pub auth_token: String,
    // ---- Transport tuning (mirrors ServerConf) ----
    #[serde(default)]
    pub stream_receive_window_mb: Option<u64>,
    #[serde(default)]
    pub receive_window_mb: Option<u64>,
    #[serde(default)]
    pub send_window_mb: Option<u64>,
    #[serde(default)]
    pub ack_threshold: Option<u32>,
    #[serde(default)]
    pub max_ack_delay_ms: Option<u64>,
    // ---- Connection isolation ----
    // TCP pool size: bulk TCP spreads round-robin across the bulk slots while
    // ports in `interactive_ports` pin to slot 0, so a latency probe never
    // queues behind bulk on the same cwnd. Unset = DEFAULT_QUIC_CONNS (4); 1
    // restores the legacy single shared TCP connection; clamped to
    // 1..=MAX_POOL_CONNS. UDP egress is a separate, additional connection (see
    // `udp_fail_closed`) — it is never one of these slots.
    // quinn 0.11 exposes no per-stream priority API, so separate cwnds are
    // the only reliable isolation.
    #[serde(default)]
    pub quic_conns: Option<usize>,
    #[serde(default)]
    pub interactive_ports: Option<Vec<u16>>,
    /// What UDP egress does when its dedicated connection is down. `true`
    /// (default) drops the datagram — counted in `dgram_drops::NO_EGRESS` —
    /// instead of putting it on a TCP connection's congestion window. `false`
    /// restores the pre-separation behaviour: fall back to the interactive
    /// connection, then to the bulk slots, so UDP keeps flowing while sharing a
    /// cwnd with TCP traffic.
    #[serde(default)]
    pub udp_fail_closed: Option<bool>,
    /// ALPN override (e.g. `myquic2/2` to restore the versioned identifier).
    /// Unset/empty = `h3` masquerade.
    #[serde(default)]
    pub alpn: Option<String>,
}

fn d_bbr() -> String {
    "bbr".into()
}
fn d_true() -> bool {
    true
}
fn d_false() -> bool {
    false
}
fn d_keepalive() -> u64 {
    5
}
fn d_5() -> u64 {
    5
}

/// Default client TCP pool size, i.e. `quic_conns` unset: four QUIC
/// connections sharing one Endpoint/UDP socket. Bulk TCP spreads round-robin
/// across the three bulk slots while `interactive_ports` pin to the interactive
/// slot, so one heavy flow cannot queue every other flow behind its cwnd.
/// A fifth, separate connection carries UDP egress exclusively (see
/// `ClientConf::udp_fail_closed`), so TCP and UDP never share a congestion
/// window or a packet payload. Independent of the server, which accepts any
/// number of them.
pub const DEFAULT_QUIC_CONNS: usize = 4;

/// Hard cap on the client **TCP** connection pool. Every slot owns a QUIC
/// connection (dial loop, DATAGRAM dispatcher, keepalives, its own 0-RTT ticket
/// state), so this cap — not the config parser — is what bounds the per-client
/// cost a `quic_conns` typo can request. The dedicated UDP egress connection is
/// one slot beyond this, so a client's worst case is `MAX_POOL_CONNS + 1`.
pub const MAX_POOL_CONNS: usize = 8;

/// Runtime transport tuning resolved from optional TOML fields.
/// Defaults are the low-latency preset for ~140 ms links (2/4/2 MB windows,
/// ACK every 2nd, 5 ms delay): ~114 Mb/s @140 ms with minimal loaded queue.
/// Raise the windows to 4/8/4 MB for ~240 Mb/s or 8/16/8 MB for 300 Mb/s peak
/// throughput at the cost of ~2x/4x loaded latency.
#[derive(Debug, Clone, Copy)]
pub struct TransportTuning {
    pub stream_receive_window: u64,
    pub receive_window: u64,
    pub send_window: u64,
    pub ack_threshold: u32,
    pub max_ack_delay: Duration,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            stream_receive_window: 2 * 1024 * 1024,
            receive_window: 4 * 1024 * 1024,
            send_window: 2 * 1024 * 1024,
            ack_threshold: 2,
            max_ack_delay: Duration::from_millis(5),
        }
    }
}

fn clamp_window_mb(v: Option<u64>, def_mb: u64) -> u64 {
    let mb = v.unwrap_or(def_mb).clamp(1, 64);
    mb * 1024 * 1024
}

impl ServerConf {
    pub fn tuning(&self) -> TransportTuning {
        TransportTuning {
            stream_receive_window: clamp_window_mb(self.stream_receive_window_mb, 2),
            receive_window: clamp_window_mb(self.receive_window_mb, 4),
            send_window: clamp_window_mb(self.send_window_mb, 2),
            ack_threshold: self.ack_threshold.unwrap_or(2).clamp(1, 32),
            max_ack_delay: Duration::from_millis(self.max_ack_delay_ms.unwrap_or(5).clamp(1, 25)),
        }
    }

    pub fn alpn_bytes(&self) -> Vec<u8> {
        normalize_alpn(self.alpn.as_deref())
    }
}

impl ClientConf {
    pub fn tuning(&self) -> TransportTuning {
        TransportTuning {
            stream_receive_window: clamp_window_mb(self.stream_receive_window_mb, 2),
            receive_window: clamp_window_mb(self.receive_window_mb, 4),
            send_window: clamp_window_mb(self.send_window_mb, 2),
            ack_threshold: self.ack_threshold.unwrap_or(2).clamp(1, 32),
            max_ack_delay: Duration::from_millis(self.max_ack_delay_ms.unwrap_or(5).clamp(1, 25)),
        }
    }

    /// Pool size: [`DEFAULT_QUIC_CONNS`] (4) when `quic_conns` is unset,
    /// clamped to `1..=`[`MAX_POOL_CONNS`]. 1 restores the legacy single
    /// connection.
    pub fn conn_count(&self) -> usize {
        self.quic_conns
            .unwrap_or(DEFAULT_QUIC_CONNS)
            .clamp(1, MAX_POOL_CONNS)
    }

    pub fn interactive_port_list(&self) -> Vec<u16> {
        self.interactive_ports
            .clone()
            .unwrap_or_else(|| vec![53, 123, 3478, 3479, 3480, 3481])
    }

    /// Whether UDP egress is confined to its dedicated connection. Default
    /// `true`: a datagram that has nowhere isolated to go is dropped and
    /// counted, rather than queued behind TCP traffic on a shared connection.
    pub fn udp_fail_closed(&self) -> bool {
        self.udp_fail_closed.unwrap_or(true)
    }

    pub fn alpn_bytes(&self) -> Vec<u8> {
        normalize_alpn(self.alpn.as_deref())
    }
}

pub fn load_toml<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    Ok(toml::from_str(&s)?)
}

// ---------------- Self-signed cert (TLS1.3 + AES-128-GCM fastest) ----------------
/// Generate self-signed cert for `san`, save PEM files, return (cert_pem, key_pem).
/// Algorithm: Ed25519 (fastest sign/verify, smallest cert). Validity: 500 years,
/// backdated 7 days so devices without a battery clock (NTP not yet synced at
/// first boot) never fail with "certificate not valid yet".
pub fn gen_self_signed_files(san: &str, cert_path: &str, key_path: &str) -> Result<()> {
    let mut params = rcgen::CertificateParams::new(vec![san.to_string()])?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(7);
    params.not_after = now + time::Duration::days(500 * 365);
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = params.self_signed(&key_pair)?;
    std::fs::write(cert_path, cert.pem()).context("write cert")?;
    std::fs::write(key_path, key_pair.serialize_pem()).context("write key")?;
    Ok(())
}

pub fn load_cert_der(pem_path: &str) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(pem_path)?);
    let v: Vec<_> = rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?;
    v.into_iter().next().context("no cert in file")
}

pub fn load_key_der(pem_path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(pem_path)?);
    rustls_pemfile::private_key(&mut r)?.context("no key in file")
}

/// Server TLS: TLS1.3 only (QUIC mandates it; single version = min handshake RTT).
/// Cipher: ring default negotiates AES-128-GCM first on AES-NI => fastest path.
pub fn server_tls_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![alpn.to_vec()];
    // rustls' default stateful store holds only 256 sessions; with the 4096
    // connection cap and 2 tickets per handshake that thrashes, so 0-RTT and
    // (1-RTT) resumption would silently degrade to full handshakes. Size the
    // store for the connection cap instead.
    const TLS_SESSION_CACHE: usize = 8192;
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(TLS_SESSION_CACHE);
    // KEEP rustls' default ticketer (NeverProducesTickets): that selects STATEFUL
    // resumption via the in-memory session store, which is the only mode where
    // rustls accepts 0-RTT early data (RFC8446 8.1 anti-replay rule).
    // Accept QUIC 0-RTT early data on resumption. quinn requires exactly 0 or u32::MAX here.
    // Replay caveat: tickets are single-use and short-lived; worst case is a duplicated
    // outbound dial, no amplification.
    // quinn (and QUIC itself) only permits 0 or u32::MAX here — anything else is
    // a protocol violation, so the bound cannot be lowered at this layer; replay
    // exposure is limited by single-use short-lived tickets instead.
    cfg.max_early_data_size = u32::MAX;
    Ok(Arc::new(cfg))
}

/// Client TLS: pin exact self-signed cert, no WebPKI roots (skip chain building => min RTT/CPU).
pub fn client_tls_config(
    pinned: rustls::pki_types::CertificateDer<'static>,
    alpn: &[u8],
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pinned)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.enable_early_data = true; // allow QUIC 0-RTT on resumption
    Ok(Arc::new(cfg))
}

// ---------------- QUIC transport: BBR + DATAGRAM + keepalive ----------------
pub fn parse_congestion(name: &str) -> bool {
    name.eq_ignore_ascii_case("cubic") || name.eq_ignore_ascii_case("bbr")
}

/// Placeholder secrets shipped in the sample configs. Deploying one is
/// equivalent to an open proxy with a false sense of security, so both
/// binaries warn when they see it.
pub fn is_placeholder_token(token: &str) -> bool {
    matches!(token, "change-me" | "change-me-6b1f0c2d47a9")
}

/// Target bandwidth for the TCP tuning below: 300Mb/s.
///
/// The deployment this build is tuned for is a ~140ms RTT WAN link (e.g. a
/// trans-Pacific hop) where one TCP flow must reach 300Mb/s.
pub const TARGET_LINK_BYTES_PER_SEC: u64 = 300 * 1000 * 1000 / 8;
/// The RTT the window sizing is derived from.
pub const TARGET_LINK_RTT: Duration = Duration::from_millis(140);
/// Bytes in flight required to fill [`TARGET_LINK_BYTES_PER_SEC`] over
/// [`TARGET_LINK_RTT`]: 37.5MB/s x 140ms = 5.25MB (~5.0MiB of stream payload;
/// the QUIC short header plus IPv4/UDP headers put the wire figure slightly
/// above this, which the 8MB windows cover with room to spare).
pub const TARGET_BDP_BYTES: u64 = TARGET_LINK_BYTES_PER_SEC * 140 / 1000;

// Flow control, not the congestion controller, is what caps single-stream
// throughput on a high-RTT link: every window below is a hard ceiling of
// `window / RTT`, applied before BBR's cwnd is consulted. The 2026-09 gaps-death
// pass deliberately shrank them (2MB per stream / 8MB aggregate / 4MB send),
// which capped one stream at ~114Mb/s at 140ms. These values supersede that for
// the 300Mb/s target.
//
// KNOWN COST of the re-widening: quinn kills a connection once a single stream's
// reassembly holds `MAX_CHUNKS = 1024` distinct spans. A larger window allows
// more packets in flight per RTT (~6200 at 1350B, ~3700 at the 1472B PMTU
// ceiling), so a burst-loss or reordering episode has more room than 2MB did to
// approach that cliff. A clean path is unaffected; on a lossy one, step
// `SEND_WINDOW` and `STREAM_RECEIVE_WINDOW` back to 4MB (=240Mb/s) rather than
// reverting the ACK-frequency and PMTU work, which is loss-independent.

/// Per-stream receive window. 8MB rather than the 5.25MB BDP: quinn only
/// announces a `MAX_STREAM_DATA` once the advertised window is short by
/// `STREAM_RECEIVE_WINDOW / 8`, so the cushion that must still cover a full BDP
/// is `8MB - 1MB = 7MB`. At 6MB the cushion would be 5.25MB -- the BDP exactly,
/// with nothing left for scheduler jitter or a stalled application read.
pub const STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
/// Aggregate connection receive window. MUST be set explicitly: quinn's default
/// is `VarInt::MAX`, which would otherwise allow 1024 streams x 8MB of receive
/// buffering per connection. 16MB covers the BDP with margin for a few
/// concurrent streams; 4096 conns x 16MB is the 64GB worst case documented in
/// the README limits table (halved to 4GB for the 256 pre-auth connections).
pub const RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;
/// Send-side budget: the upper bound on data this endpoint may keep buffered and
/// unacknowledged on one connection. quinn blocks a writer once
/// `min(peer's stream window, SEND_WINDOW) - buffered_data` reaches zero, so on
/// a high-RTT link this is a throughput ceiling of `SEND_WINDOW / RTT` for the
/// write direction. See the flow-control note above for the 8MB tradeoff.
pub const SEND_WINDOW: u64 = 8 * 1024 * 1024;

pub fn build_transport(congestion: &str, keep_alive_secs: u64) -> Arc<quinn::TransportConfig> {
    build_transport_tuned(congestion, keep_alive_secs, TransportTuning::default())
}

pub fn build_transport_tuned(
    congestion: &str,
    keep_alive_secs: u64,
    tuning: TransportTuning,
) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // BBR default; cubic only as escape hatch. Callers validate + log the
    // configured value via `parse_congestion`; unknown values fall back to BBR.
    if congestion.eq_ignore_ascii_case("cubic") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    } else {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    // GSO/GRO: no flag in quinn API — quinn-udp auto-probes UDP_SEGMENT/UDP_GRO.
    // Datagrams are a lossy best-effort path drained by a dedicated reader, so
    // 1MB (~740 x 1350B datagrams) absorbs bursts without the per-connection
    // 4MB x 4096-connection worst case (16GB of queueable user memory).
    t.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    t.datagram_send_buffer_size(DATAGRAM_BUFFER);
    // Invariant required by `try_send_datagram`: quinn's `datagram_send_buffer_size`
    // must be large enough to hold a datagram of the maximum size we can encode.
    // A buffer smaller than one datagram makes `send_datagram_wait` report
    // `Blocked` forever (nothing could ever be queued), and it is also what made
    // the old drop-oldest path reachable with an empty queue. The bound is
    // `DGRAM_MAX_WIRE`, not the 264 B header bound: since the relays pass the
    // live `max_datagram_size()` unclamped, the largest body actually queued is
    // a full-path one. `build_transport` is the only place these meet.
    const _: () = assert!(DATAGRAM_BUFFER >= DGRAM_MAX_WIRE);
    // ...and the largest possible body must be able to hold the largest
    // possible MQP-2 header, or a maximum-length domain target could never be
    // encoded at any path MTU.
    const _: () = assert!(DGRAM_MAX_WIRE > MQP_DGRAM_MAX);
    // 1024 concurrent streams cover high-concurrency tests with margin.
    t.max_concurrent_bidi_streams(1024u32.into());
    t.max_concurrent_uni_streams(100u32.into());
    // Window sizing: every flow-control window must exceed the target BDP, or
    // it -- not the congestion controller -- becomes the throughput ceiling.
    // The numbers live in named constants so `tcp_windows_cover_the_300mb_s_bdp`
    // can prove the invariant instead of restating it.
    t.stream_receive_window(quinn::VarInt::from_u32(
        u32::try_from(tuning.stream_receive_window).expect("stream window fits a VarInt"),
    ));
    t.receive_window(quinn::VarInt::from_u32(
        u32::try_from(tuning.receive_window).expect("connection window fits a VarInt"),
    ));
    t.send_window(tuning.send_window);
    // ACK frequency (draft-ietf-quic-ack-frequency): this is what we *request
    // the peer to use* when we are the receiver, so it bounds the reverse-path
    // ACK rate. quinn's default (threshold 1) ACKs every other packet: at
    // 300Mb/s that is ~14k ACK/s for a single stream, all of it paid for by
    // the one writer thread. 8 cuts that 8x while max_ack_delay = 10ms keeps
    // BBR's bandwidth estimate and loss detection sharp; >=32 makes the
    // estimate too coarse and slows the startup ramp. reordering_threshold
    // stays at quinn's recommended packet_threshold - 1 = 2.
    // Tunable: threshold 2 + small delay trades reverse-path CPU for sharper
    // RTT/loss feedback under interactive load. Note quinn fires when the
    // count *exceeds* the threshold, so 2 means every 3rd packet, not 2nd.
    let mut ack_freq = quinn::AckFrequencyConfig::default();
    ack_freq
        .ack_eliciting_threshold(quinn::VarInt::from_u32(tuning.ack_threshold))
        .max_ack_delay(Some(tuning.max_ack_delay))
        .reordering_threshold(quinn::VarInt::from_u32(2));
    t.ack_frequency_config(Some(ack_freq));
    // Seed the RTT estimator for the link this build targets. quinn's 333ms
    // default is a spec-derived placeholder that makes the first PTO and
    // BBR's initial bandwidth estimate far too pessimistic at 140ms.
    t.initial_rtt(Duration::from_millis(190));
    // Raise the PMTU search ceiling from quinn's 1452 to 1472 (the endpoint's
    // `max_udp_payload_size` default, so this is the hard limit anyway): 20
    // more bytes per packet is ~1.4% fewer packets for the same payload, which
    // a single-threaded sender pays directly. The search still starts at the
    // 1200B QUIC minimum and only climbs on successful probes, so a smaller
    // path MTU is still discovered correctly.
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(1472);
    t.mtu_discovery_config(Some(mtud));
    // Clamp so absurd config values cannot overflow the QUIC VarInt timeout.
    let keep_alive_secs = keep_alive_secs.clamp(1, 3600);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs)));
    // Idle timeout derives from keepalive so custom keep_alive_secs can never
    // self-kill a healthy connection: idle must stay well above the keepalive
    // interval (QUIC requires inbound traffic before idle fires). 15s floor
    // preserves the old silent-blackhole bound; larger keepalives scale up.
    let idle_secs = (keep_alive_secs.saturating_mul(3)).max(15);
    t.max_idle_timeout(Some(
        Duration::from_secs(idle_secs)
            .try_into()
            .expect("idle timeout must fit in a QUIC VarInt"),
    ));
    // NOTE: quinn-udp auto-probes GSO/GRO (UDP_SEGMENT) + PMTU discovery;
    // there is no explicit max_udp_payload flag in the quinn API. The outgoing
    // datagram budget is the live `Connection::max_datagram_size()`, which
    // quinn derives from the discovered path MTU; see `dgram_payload_cap`.
    Arc::new(t)
}

/// Server-side DNS with IPv4 preference (many targets are v4-only).
/// Uses a short-lived cache so per-packet domain lookups cannot stall the
/// datagram fast path or amplify upstream DNS.
pub async fn resolve_server_side(host: &str, port: u16) -> Result<SocketAddr> {
    resolve_all_cached(host, port)
        .await?
        .first()
        .copied()
        .context("dns empty")
}

/// All resolved addresses, IPv4 first. Caller tries each until one dials (dual-stack fallback).
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await
}

async fn resolve_all_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::time::timeout(timeout, async {
        let mut v: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        v.sort_by_key(|s| if s.is_ipv4() { 0 } else { 1 });
        Ok::<Vec<SocketAddr>, anyhow::Error>(v)
    })
    .await
    .context("dns lookup timed out")??;
    Ok(addrs)
}

/// Cache key encoding: `host` bytes + NUL separator + decimal port. This is
/// injective (the decimal port never contains NUL, so splitting at the last
/// NUL recovers the exact host/port), so it is safe to build on the stack and
/// look up with the borrowed `&str` form of `HashMap<String, _>` — no `String`
/// allocation on the per-datagram hot path.
type DnsCacheKey = String;
/// `Arc<[SocketAddr]>` so cache hits and single-flight waiters clone a
/// refcount instead of duplicating the address vector.
type DnsCacheVal = (Instant, Arc<[SocketAddr]>);
const DNS_KEY_BUF: usize = 255 + 1 + 5;

/// Normalize a DNS name for cache keys: DNS is case-insensitive and an
/// absolute (trailing-dot) name is equivalent to its relative form.
fn dns_name_bytes(host: &str) -> &[u8] {
    let mut hb = host.as_bytes();
    while hb.len() > 1 && hb.last() == Some(&b'.') {
        hb = &hb[..hb.len() - 1];
    }
    hb
}

/// Owned fallback for hosts above the wire-format limit; MUST normalize the
/// same way as [`dns_key`] so both forms address the same cache entry.
fn dns_key_owned(host: &str, port: u16) -> String {
    let hb = dns_name_bytes(host);
    let mut bytes = Vec::with_capacity(hb.len() + 6);
    bytes.extend(hb.iter().map(|b| b.to_ascii_lowercase()));
    bytes.push(0);
    bytes.extend_from_slice(port.to_string().as_bytes());
    String::from_utf8(bytes).expect("ascii lowercasing preserves UTF-8")
}

/// Build the cache key into `buf`, returning a borrowed `&str`.
/// Returns `None` only when `host` is longer than the wire-format limit.
fn dns_key<'a>(host: &str, port: u16, buf: &'a mut [u8; DNS_KEY_BUF]) -> Option<&'a str> {
    let hb = dns_name_bytes(host);
    if hb.len() + 1 + 5 > DNS_KEY_BUF {
        return None;
    }
    for (dst, b) in buf.iter_mut().zip(hb) {
        *dst = b.to_ascii_lowercase();
    }
    let mut pos = hb.len();
    buf[pos] = 0;
    pos += 1;
    let mut digits = [0u8; 5];
    let mut p = port;
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (p % 10) as u8;
        p /= 10;
        if p == 0 {
            break;
        }
    }
    buf[pos..pos + (5 - i)].copy_from_slice(&digits[i..]);
    pos += 5 - i;
    std::str::from_utf8(&buf[..pos]).ok()
}

/// Shard count for the DNS tables. A single global `RwLock`/`Mutex` puts every
/// packet-path reader on one reader count / one mutex cache line; sharding by
/// key keeps the per-entry critical sections identical while spreading
/// cross-core contention, the same pattern as the server session table and the
/// client dispatcher hub.
const DNS_SHARDS: usize = 16;

/// Key-hash shard selector. Manual fold (no SipHash): this runs on the
/// per-packet path and only needs spreading, not DoS resistance (keys are
/// DNS names, and a collision only shares a lock, never a cache entry).
fn dns_shard(key: &str) -> usize {
    const K: u64 = 0x9e3779b97f4a7c15;
    let mut h: u64 = 0;
    for b in key.as_bytes() {
        h = h.wrapping_mul(K).wrapping_add(*b as u64);
    }
    (h as usize) % DNS_SHARDS
}

fn dns_caches() -> &'static [std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>; DNS_SHARDS] {
    static CACHES: std::sync::OnceLock<
        [std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>; DNS_SHARDS],
    > = std::sync::OnceLock::new();
    CACHES.get_or_init(|| std::array::from_fn(|_| std::sync::RwLock::new(HashMap::new())))
}

fn dns_cache_for(key: &str) -> &'static std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>> {
    &dns_caches()[dns_shard(key)]
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_NEG_TTL: Duration = Duration::from_secs(10);
/// Soft cap for the negative cache; past this the table is reaped instead of
/// growing without bound under a failing-domain flood.
const DNS_NEG_MAX: usize = 4096;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn dns_neg_caches() -> &'static [std::sync::RwLock<HashMap<DnsCacheKey, Instant>>; DNS_SHARDS] {
    static NEGS: std::sync::OnceLock<
        [std::sync::RwLock<HashMap<DnsCacheKey, Instant>>; DNS_SHARDS],
    > = std::sync::OnceLock::new();
    NEGS.get_or_init(|| std::array::from_fn(|_| std::sync::RwLock::new(HashMap::new())))
}

fn dns_neg_cache_for(key: &str) -> &'static std::sync::RwLock<HashMap<DnsCacheKey, Instant>> {
    &dns_neg_caches()[dns_shard(key)]
}

/// Poison-safe lock helpers. The previous `if let Ok(..)` handling silently
/// disabled all DNS caching forever after any panic while a lock was held;
/// recovering the guard keeps the cache functional (a HashMap cannot be left
/// in a half-formed state by such a panic).
fn warn_poisoned() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| tracing::warn!("a cache lock was poisoned; recovering"));
}

pub fn lock_read<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_write<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_mutex<T>(l: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    l.lock().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

/// Non-blocking packet-path variants: never park a Tokio worker. `None` means
/// "contended right now" and the caller must fail fast (UDP drop semantics or
/// treat-as-miss), never block. Poison is still recovered the same way.
pub fn try_lock_read<T>(l: &std::sync::RwLock<T>) -> Option<std::sync::RwLockReadGuard<'_, T>> {
    match l.try_read() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

pub fn try_lock_write<T>(l: &std::sync::RwLock<T>) -> Option<std::sync::RwLockWriteGuard<'_, T>> {
    match l.try_write() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

pub fn try_lock_mutex<T>(l: &std::sync::Mutex<T>) -> Option<std::sync::MutexGuard<'_, T>> {
    match l.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

struct DnsInflightEntry {
    /// Own copy of the key so the cleanup guard can remove the entry even when
    /// the owner is a takeover task that did not insert it.
    key: DnsCacheKey,
    cell: tokio::sync::OnceCell<Result<Arc<[SocketAddr]>, String>>,
    notify: tokio::sync::Notify,
    owner: std::sync::atomic::AtomicBool,
}

/// Releases singleflight ownership when the resolving task exits for any
/// reason (completion, cancellation, panic), so waiters can take over instead
/// of sleeping forever.
struct OwnerReset<'a> {
    entry: &'a DnsInflightEntry,
}

impl Drop for OwnerReset<'_> {
    fn drop(&mut self) {
        self.entry
            .owner
            .store(false, std::sync::atomic::Ordering::Release);
        self.entry.notify.notify_waiters();
    }
}

/// Removes the inflight entry when the owner's future is dropped for any
/// reason. Without this, cancellation between `cell.set()` and the explicit
/// removal left a permanently stale entry behind: every later lookup returned
/// the old result without ever re-resolving the name.
struct InflightCleanup<'a> {
    entry: &'a Arc<DnsInflightEntry>,
}

impl Drop for InflightCleanup<'_> {
    fn drop(&mut self) {
        let mut inf = lock_mutex(dns_inflight_for(&self.entry.key));
        if let Some(cur) = inf.get(&self.entry.key) {
            if Arc::ptr_eq(cur, self.entry) {
                inf.remove(&self.entry.key);
            }
        }
    }
}

/// Sharded single-flight table: one mutex per shard (see `DNS_SHARDS`).
type DnsInflightTable = std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>>;

fn dns_inflights() -> &'static [DnsInflightTable; DNS_SHARDS] {
    static INFS: std::sync::OnceLock<[DnsInflightTable; DNS_SHARDS]> = std::sync::OnceLock::new();
    INFS.get_or_init(|| std::array::from_fn(|_| std::sync::Mutex::new(HashMap::new())))
}

fn dns_inflight_for(key: &str) -> &'static DnsInflightTable {
    &dns_inflights()[dns_shard(key)]
}

pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1024)))
}

pub fn dns_is_inflight(host: &str, port: u16) -> bool {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // Packet path: contended => pretend inflight so we skip spawning instead
    // of parking the worker on the singleflight mutex during a miss storm.
    try_lock_mutex(dns_inflight_for(key))
        .map(|inf| inf.contains_key(key))
        .unwrap_or(true)
}

pub fn mono_millis() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// Thread-local memo of the most recent lookups, keyed by the *full* normalized
/// key. A 64-bit hash here would let two different `(host, port)` pairs collide
/// and serve each other's address for the whole TTL, so the hash is only ever a
/// filter: a slot matches only when the stored key bytes compare equal too.
///
/// Two-way set-associative over 64 sets (128 slots), replacing a single
/// 32-slot direct-mapped table. The old shape was fine for one hot target but
/// degraded exactly when the proxy is busiest: a worker thread serving N
/// distinct domains misses on roughly `1 - 32/N` of lookups, so 32 concurrent
/// domains already cost ~31 % penetration into the shared cache and 128 cost
/// ~76 % (measured, 10 threads). Conflict misses dominate a direct-mapped
/// table this small; two ways removes them, and the measured penetration at 32
/// and 64 domains per thread drops to 0 % and ~5 %, for 6.8 ns/op versus
/// 15.5 ns/op at 32 domains and 8.1 ns versus 25.8 ns at 64.
///
/// Keys are stored as a hash plus up to 64 inline bytes, so the table stays
/// small enough to afford 128 slots. A key longer than 64 bytes simply never
/// populates the memo and takes the shared-cache path every time: that is a
/// miss, never a mis-serve. Domain names are capped at 255 bytes on the wire,
/// so this deliberately trades a rare slow path for a smaller slot.
#[derive(Clone, Copy)]
struct DnsMemoSlot {
    hash: u64,
    empty: bool,
    /// `None` = negatively cached (NXDOMAIN / lookup failure).
    addr: Option<SocketAddr>,
    len: u8,
    key: [u8; MEMO_KEY_BYTES],
    expires: Instant,
}

/// Keys longer than this are not memoized (see [`DnsMemoSlot`]).
const MEMO_KEY_BYTES: usize = 64;
const MEMO_SETS: usize = 64;
const MEMO_WAYS: usize = 2;

impl DnsMemoSlot {
    const EMPTY: Self = Self {
        hash: 0,
        empty: true,
        addr: None,
        len: 0,
        key: [0; MEMO_KEY_BYTES],
        // Never read on an empty slot (guarded by `empty`), and `Instant` has no
        // const constructor, so zeroed is the only value available in a const.
        expires: unsafe { std::mem::zeroed() },
    };

    /// A slot for `key`, or `None` when it is too long to store inline.
    fn new(key: &str, hash: u64, addr: Option<SocketAddr>, expires: Instant) -> Option<Self> {
        if key.len() > MEMO_KEY_BYTES {
            return None;
        }
        let mut s = Self::EMPTY;
        s.empty = false;
        s.hash = hash;
        s.addr = addr;
        s.len = key.len() as u8;
        s.key[..key.len()].copy_from_slice(key.as_bytes());
        s.expires = expires;
        Some(s)
    }

    /// Full-key compare. The hash is only a filter: two different keys that
    /// collide on it must still not match, or one domain would serve another
    /// domain's address for the whole TTL.
    #[inline]
    fn matches(&self, hash: u64, key: &str) -> bool {
        !self.empty
            && self.hash == hash
            && self.len as usize == key.len()
            && &self.key[..self.len as usize] == key.as_bytes()
    }
}

thread_local! {
    static DNS_MEMO: std::cell::RefCell<[[DnsMemoSlot; MEMO_WAYS]; MEMO_SETS]> =
        const { std::cell::RefCell::new([[DnsMemoSlot::EMPTY; MEMO_WAYS]; MEMO_SETS]) };
}

/// Multiply-fold plus a finalizer. The finalizer matters here in a way it did
/// not for the old direct-mapped table: the set index comes from the low bits
/// of the result, and DNS names share long suffixes (`…example.com`, `…cdn.net`),
/// so the raw fold leaves those bits correlated between unrelated names and
/// would pile them into the same set — the exact conflict the associativity is
/// meant to remove. ~4 ns per lookup, paid once per packet.
#[inline]
fn dns_memo_hash(key: &str) -> u64 {
    const K: u64 = 0x9e3779b97f4a7c15;
    let mut h: u64 = 0;
    for b in key.as_bytes() {
        h = h.wrapping_mul(K).wrapping_add(*b as u64);
    }
    h ^= h >> 29;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^ (h >> 32)
}

/// Set index. `MEMO_SETS` is a power of two, so this is a mask, and the low
/// bits of a finalized hash are well mixed.
#[inline]
fn dns_memo_set(hash: u64) -> usize {
    (hash as usize) & (MEMO_SETS - 1)
}

/// A matching memo slot, copied out so the borrow of the thread-local ends with
/// the call.
#[derive(Clone, Copy)]
struct MemoHit {
    addr: Option<SocketAddr>,
    expires: Instant,
}

/// Probe both ways of our key's set, returning the positive and negative hits
/// separately. Deliberately does *not* read the clock: the caller reads it once,
/// and only after a key match, so a memo miss is never charged a
/// `clock_gettime` — the whole point of the memo is that a hit is cheaper than
/// the global cache lookup, and a miss must not cost more than one.
fn memo_peek_both(key: &str) -> (Option<MemoHit>, Option<MemoHit>) {
    let hash = dns_memo_hash(key);
    let set = dns_memo_set(hash);
    DNS_MEMO.with(|c| {
        let c = c.borrow();
        for s in c[set].iter() {
            if s.matches(hash, key) {
                let hit = MemoHit {
                    addr: s.addr,
                    expires: s.expires,
                };
                return if s.addr.is_none() {
                    (None, Some(hit))
                } else {
                    (Some(hit), None)
                };
            }
        }
        (None, None)
    })
}

/// Insert into the set, promoting to way 0 and demoting the previous way 0.
/// A write is two `Copy`s of an inline struct: no allocation and no key
/// `String`, which is why the slot stores key bytes rather than a `Box<str>`.
fn memo_put(key: &str, addr: Option<SocketAddr>, expires: Instant) {
    let hash = dns_memo_hash(key);
    let set = dns_memo_set(hash);
    let Some(slot) = DnsMemoSlot::new(key, hash, addr, expires) else {
        return; // too long for an inline slot: stays a cache-path-only name
    };
    DNS_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        let ways = &mut c[set];
        if ways[0].matches(hash, key) {
            // Same key already newest: overwrite in place (its address or TTL
            // may have changed) without disturbing way 1.
            ways[0] = slot;
        } else if ways[1].matches(hash, key) {
            // Resident in way 1: promote it and drop the old way 0, so one key
            // can never occupy both ways of the set.
            ways[1] = ways[0];
            ways[0] = slot;
        } else {
            // New key: demote the current occupant of way 0.
            ways[1] = ways[0];
            ways[0] = slot;
        }
    });
}

/// Result of a synchronous cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedLookup {
    /// A fresh address is cached.
    Addr(SocketAddr),
    /// A fresh negative entry says the name will not resolve; do not spawn a
    /// resolver task for this packet.
    Negative,
    /// Not cached; the caller must use the async resolver.
    Unknown,
}

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
/// Consults the thread-local memo, then the positive cache, then the negative
/// cache, so a known-bad name never costs a task spawn. A hit performs no heap
/// allocation (stack-built key + full-key compare against the memo) and, on the
/// memo hit path, exactly one clock read — it never touches a lock at all.
pub fn lookup_cached_fast(host: &str, port: u16) -> CachedLookup {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // Memo first, and only then the clock: a memo hit costs one `Instant::now()`
    // and a byte compare instead of two global read locks.
    let (pos, neg) = memo_peek_both(key);
    if pos.is_some() || neg.is_some() {
        let now = Instant::now();
        if let Some(m) = pos {
            if now < m.expires {
                return match m.addr {
                    Some(a) => CachedLookup::Addr(a),
                    None => CachedLookup::Unknown,
                };
            }
        }
        if let Some(m) = neg {
            if now < m.expires {
                return CachedLookup::Negative;
            }
        }
    }
    // One clock read for both global caches: they are checked back to back and
    // only their TTLs differ.
    let now = Instant::now();
    {
        let Some(m) = try_lock_read(dns_cache_for(key)) else {
            return CachedLookup::Unknown;
        };
        if let Some((t, v)) = m.get(key) {
            // Expiry is anchored to the global entry's insertion time, so the
            // memo can never outlive the cache TTL.
            let expires = *t + DNS_CACHE_TTL;
            if now < expires {
                if let Some(a) = v.first().copied() {
                    memo_put(key, Some(a), expires);
                    return CachedLookup::Addr(a);
                }
            }
        }
    }
    {
        let Some(n) = try_lock_read(dns_neg_cache_for(key)) else {
            return CachedLookup::Unknown;
        };
        if let Some(t) = n.get(key) {
            let expires = *t + DNS_NEG_TTL;
            if now < expires {
                memo_put(key, None, expires);
                return CachedLookup::Negative;
            }
        }
    }
    CachedLookup::Unknown
}

/// Back-compat helper returning only the positive form.
pub fn lookup_cached_sync(host: &str, port: u16) -> Option<SocketAddr> {
    match lookup_cached_fast(host, port) {
        CachedLookup::Addr(a) => Some(a),
        _ => None,
    }
}

const DNS_CACHE_MAX: usize = 4096;
/// Per-shard positive-cache cap: shards share the process-wide total evenly,
/// so the aggregate bound stays `DNS_CACHE_MAX` while no single write lock
/// ever covers the whole table.
const DNS_CACHE_MAX_SHARD: usize = DNS_CACHE_MAX / DNS_SHARDS;
/// Per-shard negative-cache cap, same even split of `DNS_NEG_MAX`.
const DNS_NEG_MAX_SHARD: usize = DNS_NEG_MAX / DNS_SHARDS;

/// Batch eviction with a bounded write-lock hold: once the table crosses the
/// cap, drop enough entries in one pass to cover the whole overflow, then
/// leave the next few hundred inserts alone. Eviction is arbitrary (hash
/// order) rather than oldest-first on purpose: oldest-first needed a full
/// O(n) collect + `select_nth_unstable` plus per-victim key clones *while
/// holding the write lock*, stalling every DNS reader on the packet fast
/// path during a miss storm. Expired entries need no eager `retain` either:
/// reads already treat them as misses via the TTL check, so they just wait
/// for arbitrary eviction. Work per call is O(over) clones + removes.
fn evict_if_needed(m: &mut HashMap<DnsCacheKey, DnsCacheVal>) {
    const SLACK: usize = 32;
    if m.len() <= DNS_CACHE_MAX_SHARD + SLACK {
        return;
    }
    let over = m.len().saturating_sub(DNS_CACHE_MAX_SHARD);
    if over == 0 {
        return;
    }
    let victims: Vec<DnsCacheKey> = m.keys().take(over).cloned().collect();
    for k in victims {
        m.remove(&k);
    }
}

pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Arc<[SocketAddr]>> {
    // Stack-built key: no allocation on the positive-cache fast path. The
    // fallback only triggers for hosts longer than the 255-byte wire limit.
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // 1. Positive cache. Try-lock: contended => treat as miss and fall
    // through to singleflight instead of parking this task.
    {
        if let Some(m) = try_lock_read(dns_cache_for(key)) {
            if let Some((t, v)) = m.get(key) {
                if t.elapsed() < DNS_CACHE_TTL {
                    return Ok(v.clone());
                }
            }
        }
    }
    // 2. Negative cache.
    {
        if let Some(n) = try_lock_read(dns_neg_cache_for(key)) {
            if let Some(t) = n.get(key) {
                if t.elapsed() < DNS_NEG_TTL {
                    anyhow::bail!("dns negative cached");
                }
            }
        }
    }
    // 3. Singleflight: exactly one owner resolves; everyone else waits on the
    //    cell. Ownership is claimed atomically. If the owner is cancelled or
    //    panics, `OwnerReset` clears the claim and wakes the waiters; the next
    //    waiter re-claims it, so no waiter can sleep forever on a cell that
    //    nobody will ever fill.
    let entry = {
        let mut inf = lock_mutex(dns_inflight_for(key));
        match inf.get(key) {
            Some(c) => c.clone(),
            None => {
                let c = Arc::new(DnsInflightEntry {
                    key: key.to_owned(),
                    cell: tokio::sync::OnceCell::new(),
                    notify: tokio::sync::Notify::new(),
                    owner: std::sync::atomic::AtomicBool::new(false),
                });
                inf.insert(c.key.clone(), c.clone());
                c
            }
        }
    };
    loop {
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.swap(true, std::sync::atomic::Ordering::AcqRel) {
            break; // this caller is the owner
        }
        // Waiter: register before re-checking the cell (`notify_waiters` stores
        // no permit, so an unregistered waiter could otherwise miss completion).
        let notified = entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.load(std::sync::atomic::Ordering::Acquire) {
            // The owner died without publishing; yield once so N woken
            // waiters desynchronize instead of CAS-herding on `owner`.
            tokio::task::yield_now().await;
            continue;
        }
        notified.await;
    }

    // Owner path. Both guards live across the await: `_reset` releases the
    // claim and wakes waiters on any exit path, `cleanup` removes the inflight
    // entry once the caches are warm.
    let _reset = OwnerReset { entry: &entry };
    let cleanup = InflightCleanup { entry: &entry };

    // A racing caller may have completed and removed the inflight entry between
    // the initial cache checks and the registration above; re-check before
    // issuing a duplicate upstream lookup.
    {
        if let Some(m) = try_lock_read(dns_cache_for(key)) {
            if let Some((t, v)) = m.get(key) {
                if t.elapsed() < DNS_CACHE_TTL {
                    return Ok(v.clone());
                }
            }
        }
    }

    let r: Result<Arc<[SocketAddr]>, String> =
        match resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await {
            Ok(v) => Ok(Arc::from(v)),
            Err(e) => Err(format!("{e:#}")),
        };
    let now = Instant::now();
    // Warm the caches and the thread memo BEFORE publishing the result, so a
    // caller that observes the cell also observes a cache hit, and only the
    // owner ever pays for the insert + eviction sweep (previously every waiter
    // re-inserted and re-swept the whole map).
    match &r {
        Ok(v) => {
            {
                let mut m = lock_write(dns_cache_for(key));
                m.insert(key.to_owned(), (now, v.clone()));
                evict_if_needed(&mut m);
            }
            lock_write(dns_neg_cache_for(key)).remove(key);
            if let Some(a) = v.first().copied() {
                memo_put(key, Some(a), now + DNS_CACHE_TTL);
            }
        }
        Err(_) => {
            {
                let mut n = lock_write(dns_neg_cache_for(key));
                // Bounded hold: evict one arbitrary entry instead of a full
                // O(n) `retain` scan under the write lock. Expired entries
                // are already treated as misses by the TTL check on read,
                // so eager reaping buys nothing while stalling every packet
                // path reader during a failing-domain flood. Per-shard cap
                // keeps the process-wide total at `DNS_NEG_MAX`.
                if n.len() >= DNS_NEG_MAX_SHARD {
                    if let Some(k) = n.keys().next().cloned() {
                        n.remove(&k);
                    }
                }
                if n.len() < DNS_NEG_MAX_SHARD {
                    n.insert(key.to_owned(), now);
                }
            }
            memo_put(key, None, now + DNS_NEG_TTL);
        }
    }
    let _ = entry.cell.set(r.clone());
    entry.notify.notify_waiters();
    drop(cleanup);
    match r {
        Ok(v) => Ok(v),
        Err(msg) => anyhow::bail!("{msg}"),
    }
}

/// Accept `IP:port` or `hostname:port` for the QUIC server address.
pub async fn resolve_server_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = s
        .rsplit_once(':')
        .context("bad server_addr, want host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad server port")?;
    let v = resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await?;
    v.into_iter().next().context("dns empty")
}

/// True for globally routable targets; used to enforce `allow_private=false`.
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
                || v.is_unspecified()
                // CGNAT 100.64/10, TEST-NETs, 0/8, 192.0.0.0/24
                || v.octets()[0] == 0
                || (v.octets()[0] == 100 && (v.octets()[1] & 0b1100_0000) == 64)
                || (v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 0)
                || (v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 2)
                // 198.18.0.0/15 benchmarking (198.18.x + 198.19.x), TEST-NET-2 198.51.100.0/24
                || (v.octets()[0] == 198 && (v.octets()[1] & 0xFE) == 18)
                || (v.octets()[0] == 198
                    && v.octets()[1] == 51
                    && v.octets()[2] == 100)
                || (v.octets()[0] == 203 && v.octets()[1] == 0 && v.octets()[2] == 113)
                // 192.88.99.0/24 6to4 relay (deprecated, never a dial target)
                || (v.octets()[0] == 192 && v.octets()[1] == 88 && v.octets()[2] == 99)
                // 192.175.48.0/24 AS112 direct-delegation anycast
                || (v.octets()[0] == 192 && v.octets()[1] == 175 && v.octets()[2] == 48)
                // 192.31.196.0/24 AS112-v4 and 192.52.193.0/24 AMT (RFC 7450)
                || (v.octets()[0] == 192 && v.octets()[1] == 31 && v.octets()[2] == 196)
                || (v.octets()[0] == 192 && v.octets()[1] == 52 && v.octets()[2] == 193)
                // 240.0.0.0/4 reserved (240-255)
                || (v.octets()[0] >= 240))
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            let s = v.segments();
            // RFC 2765 IPv4-translated (SIIT) `::ffff:0:a.b.c.d` is a distinct
            // prefix from IPv4-mapped; on stacks that translate it, the
            // embedded IPv4 decides reachability, so validate it recursively.
            if s[0..4].iter().all(|x| *x == 0) && s[4] == 0xffff && s[5] == 0 {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
            // 64:ff9b::/96 (well-known NAT64 prefix): validate the embedded
            // IPv4 so private/loopback targets cannot slip through via NAT64.
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
            // Deprecated IPv4-compatible ::a.b.c.d: validate embedded IPv4 too,
            // closing a platform-dependent allow_private bypass.
            if s[0..6].iter().all(|x| *x == 0) {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
            !(v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || ((s[0] & 0xfe00) == 0xfc00)
                || ((s[0] & 0xffc0) == 0xfe80)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0064 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || (s[0] == 0x2001 && s[1] == 0x0000)
                || s[0] == 0x0100
                // 2001:2::/48 benchmarking (RFC 5180)
                || (s[0] == 0x2001 && s[1] == 0x0002)
                // 3fff::/20 documentation (RFC 9637)
                || ((s[0] & 0xfff0) == 0x3ff0)
                // 2001:10::/28 ORCHIDv1 and 2001:20::/28 ORCHIDv2 (RFC 7343)
                || (s[0] == 0x2001
                    && (((s[1] & 0xfff0) == 0x0010) || ((s[1] & 0xfff0) == 0x0020)))
                // 2001:1::1/128 PCP Anycast, ::2/128 TURN Anycast, ::3/128 DNS-SD SRP
                || (s[0] == 0x2001
                    && s[1] == 0x0001
                    && s[2..7].iter().all(|x| *x == 0)
                    && s[7] <= 3)
                // 2001:3::/32 AMT (RFC 7450)
                || (s[0] == 0x2001 && s[1] == 0x0003)
                // 2001:4:112::/48 AS112-v6
                || (s[0] == 0x2001 && s[1] == 0x0004 && s[2] == 0x0112)
                // 2001:30::/28 Drone Remote ID (RFC 9374)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0030)
                // 5f00::/16 SRv6 SIDs (RFC 9602)
                || s[0] == 0x5f00
                // 2620:4f:8000::/48 Direct Delegation AS112
                || (s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
                || ((s[0] & 0xffc0) == 0xfec0))
        }
    }
}

/// Strip ::ffff:0:0/96 mapping so SOCKS replies carry a dialable address.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// Map IPv4 to ::ffff:0:0/96 for sending via a dual-stack IPv6 socket.
/// Linux maps in-kernel; macOS/BSD return EINVAL without it. Harmless everywhere.
pub fn map_for_dual(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        v6 => v6,
    }
}

// ---------------- QUIC DATAGRAM send (never the drop-oldest path) ----------------
/// DATAGRAM send/receive buffer per connection (see [`build_transport`]).
const DATAGRAM_BUFFER: usize = 1024 * 1024;

/// Upper bound for one MQP-2 datagram on the wire: the largest address form
/// (1 + 1 + 255 + 2) plus the type/session header. Kept as a named constant so
/// the tests below can prove the send-buffer invariant rather than assert it.
const MQP_DGRAM_MAX: usize = 5 + 1 + 1 + 255 + 2;

/// Largest MQP-2 datagram body that can ever be handed to quinn.
///
/// The body is `min(Connection::max_datagram_size(), ...)` and quinn's own
/// ceiling is the endpoint's `max_udp_payload_size` (1472), so no datagram can
/// exceed that. This — not [`MQP_DGRAM_MAX`], which is only the header bound —
/// is what the send buffer has to hold at least one of for
/// `send_datagram_wait` to ever make progress.
pub const DGRAM_MAX_WIRE: usize = 1472;

/// Outcome of [`try_send_datagram`]. Mirrors quinn's error surface, but a full
/// send buffer is a plain `Blocked` (the datagram was dropped) instead of an
/// await point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramSend {
    /// Queued for transmission.
    Sent,
    /// The send buffer is full; the datagram was dropped (UDP semantics).
    Blocked,
    /// Larger than the current path allows; the caller should refresh its
    /// cached `max_datagram_size()` and drop this packet.
    TooLarge,
    /// The peer never negotiated DATAGRAM support.
    Unsupported,
    /// The connection is gone; the caller should tear the flow down.
    ConnectionLost,
}

/// Poll a future exactly once with a no-op waker.
///
/// Sound for futures that are polled to completion elsewhere or dropped right
/// after: a `Pending` result may leave a waker registered, but the no-op waker
/// is a valid `RawWaker` and the future is dropped immediately, so nothing is
/// ever woken on a dangling task.
///
/// Cancellation-safety for the one caller ([`try_send_datagram`], verified
/// against quinn 0.11.12 `connection.rs` `SendDatagram`): on `Blocked` quinn
/// puts the datagram bytes back into the future (`this.data.replace(data)`)
/// and parks on `datagrams_unblocked.notified()` (tokio `Notified`, whose
/// `Drop` unregisters the waiter). Dropping the future after `Pending` therefore
/// drops the bytes with it and leaves no waiter behind — no byte-count drift,
/// no notify-queue residue. `cancelled_datagram_waits_leave_no_residue` pins this.
///
/// Primitive behind [`try_send_datagram`]: `send_datagram_wait` takes quinn's
/// connection-state mutex on every poll, so the non-blocking variant has to be
/// able to ask once without parking a task.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Non-blocking DATAGRAM send that MUST be used instead of quinn's
/// `Connection::send_datagram`.
///
/// `send_datagram` is documented as "drop the oldest queued datagram when the
/// buffer is full", and that path used to be broken: quinn-proto 0.11.17's
/// `Connection::drop_oversized` (called whenever the path MTU shrinks) removed
/// datagrams from the outgoing queue and decremented `payload_bytes` for each,
/// yet a datagram re-queued by `DatagramState::write` had already been
/// decremented by `pop_front` — so the byte counter was decremented twice. It
/// underflowed to `usize::MAX`, `memory_used()` then looked astronomically large
/// while the queue was empty, and the next `send_datagram` panicked on
/// `.expect("datagrams.outgoing.payload_bytes desynchronized")` inside quinn's
/// connection-state mutex, poisoning it and aborting the whole process.
/// Reproduced on loopback with a 1200-byte payload against a peer whose
/// `max_datagram_size()` had shrunk to 1162 bytes, so it was reachable by any
/// PMTU reduction — i.e. by normal network conditions, not just a hostile peer.
///
/// Upstream fixed the bookkeeping (the counter now lives inside the datagram
/// buffer and `drop_oversized` only decrements what it actually removes), so the
/// crash is gone. This wrapper is kept because the relay still wants its
/// semantics: `send_datagram_wait` failing with the bounded (`Blocked`) path
/// reports the drop to the caller and discards the *newest* datagram, whereas
/// `send_datagram` silently evicts the *oldest* queued one and returns `Ok`. The
/// callers count and log `Blocked`, so switching would quietly erase the
/// per-connection drop accounting. Bytes are copied per datagram regardless
/// (quinn assembles each datagram frame with `extend_from_slice`), so this costs
/// nothing extra.
pub fn try_send_datagram(conn: &quinn::Connection, d: Bytes) -> DatagramSend {
    match poll_once(conn.send_datagram_wait(d)) {
        Some(Ok(())) => DatagramSend::Sent,
        Some(Err(quinn::SendDatagramError::TooLarge)) => DatagramSend::TooLarge,
        Some(Err(quinn::SendDatagramError::UnsupportedByPeer)) => DatagramSend::Unsupported,
        Some(Err(quinn::SendDatagramError::ConnectionLost(_))) => DatagramSend::ConnectionLost,
        Some(Err(quinn::SendDatagramError::Disabled)) => DatagramSend::ConnectionLost,
        // Full send buffer: `send_datagram_wait` parks the datagram in its own
        // future, which `poll_once` drops here, so nothing leaks.
        None => DatagramSend::Blocked,
    }
}

/// Process-wide UDP DATAGRAM drop accounting.
///
/// Every dropped datagram is a packet the peer's own UDP stack would have
/// carried, so these counters are the honest measure of how much the tunnel is
/// degrading UDP. Both drop paths used to be `debug!`-only, which made a
/// silent 100 % loss of large datagrams invisible at the default log level.
pub mod dgram_drops {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Payload did not fit the current path's DATAGRAM budget (oversized).
    pub static TOO_LARGE: AtomicU64 = AtomicU64::new(0);
    /// Send buffer full: dropped per UDP semantics (quinn `Blocked`).
    pub static BUFFER_FULL: AtomicU64 = AtomicU64::new(0);
    /// Session or DNS slow-path budget exhausted: dropped before a socket or
    /// lookup was created (UDP semantics, fail-closed under flood).
    pub static SESSION_FULL: AtomicU64 = AtomicU64::new(0);
    /// The name's resolution was already in flight, so this datagram was
    /// dropped rather than queued behind it (single-flight delivers only the
    /// packet that spawned the resolver). Counted apart from `SESSION_FULL`
    /// because charging relay loss to a budget counter is exactly the
    /// misreport that counter's note warns about.
    pub static DNS_INFLIGHT: AtomicU64 = AtomicU64::new(0);
    /// No usable egress connection at the moment the datagram was ready: the
    /// dedicated UDP connection had not come up yet, was reconnecting, or the
    /// single-flight refresh was already owned by another thread. The client
    /// drops the datagram (UDP semantics) — before this counter existed that
    /// loss was a bare `continue` with no counter and no log at all.
    ///
    /// On the server there is no egress-connection choice, so a non-zero value
    /// here is client-only.
    pub static NO_EGRESS: AtomicU64 = AtomicU64::new(0);
    /// The egress connection was gone (or the peer stopped offering DATAGRAM
    /// support) at send time. The datagram is lost; the client invalidates its
    /// cached egress handle and the next datagram re-picks a connection.
    pub static EGRESS_DEAD: AtomicU64 = AtomicU64::new(0);

    /// Every drop counter in one read, so the 60 s report cannot silently omit
    /// one. Named fields rather than a tuple: a 6-tuple read at two call sites
    /// is exactly the shape that pairs a socket with the wrong field elsewhere
    /// in this codebase (see the client's `SessEntry` note).
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DropSnapshot {
        pub too_large: u64,
        pub buffer_full: u64,
        pub session_full: u64,
        pub dns_inflight: u64,
        pub no_egress: u64,
        pub egress_dead: u64,
    }

    impl DropSnapshot {
        pub fn since(&self, prev: &Self) -> Self {
            let d = |a: u64, b: u64| a.saturating_sub(b);
            Self {
                too_large: d(self.too_large, prev.too_large),
                buffer_full: d(self.buffer_full, prev.buffer_full),
                session_full: d(self.session_full, prev.session_full),
                dns_inflight: d(self.dns_inflight, prev.dns_inflight),
                no_egress: d(self.no_egress, prev.no_egress),
                egress_dead: d(self.egress_dead, prev.egress_dead),
            }
        }

        /// Drops that mean "the tunnel degraded this packet", i.e. everything
        /// except a datagram that was already destined for a dead connection's
        /// peers. Used by the reporter to decide whether the line is worth
        /// printing at all.
        pub fn lost(&self) -> u64 {
            self.too_large
                .saturating_add(self.buffer_full)
                .saturating_add(self.session_full)
                .saturating_add(self.dns_inflight)
                .saturating_add(self.no_egress)
                .saturating_add(self.egress_dead)
        }
    }

    /// Totals since process start.
    ///
    /// **Batching bound, stated because a line reading `0` is not proof of no
    /// loss.** `too_large`, `buffer_full`, `session_full` and `dns_inflight`
    /// accumulate in a thread-local cell and reach the global when they hit 64 or
    /// when `snapshot` runs *on that thread*. A reporter task runs on its own
    /// thread, so a loss under 64 drops on a worker thread is not "delayed to the
    /// next report" — it stays invisible until that thread drops 63 more, and a
    /// thread that exits takes its pending count with it. Treat those four as
    /// flood indicators, and the per-packet `warn` lines (which carry the total
    /// `bump` returned) as the immediate signal.
    ///
    /// `no_egress` and `egress_dead` are exempt by construction: they are counted
    /// with a direct `fetch_add` (see `bump`), so a two-second fail-closed outage
    /// that drops twenty datagrams shows up in the very next report. That is
    /// deliberate — they describe a discrete state of the egress connection, not a
    /// flood, and they are the numbers an operator uses to decide whether
    /// `udp_fail_closed` is costing them anything.
    pub fn snapshot() -> DropSnapshot {
        flush_locals();
        DropSnapshot {
            too_large: TOO_LARGE.load(Ordering::Relaxed),
            buffer_full: BUFFER_FULL.load(Ordering::Relaxed),
            session_full: SESSION_FULL.load(Ordering::Relaxed),
            dns_inflight: DNS_INFLIGHT.load(Ordering::Relaxed),
            no_egress: NO_EGRESS.load(Ordering::Relaxed),
            egress_dead: EGRESS_DEAD.load(Ordering::Relaxed),
        }
    }

    fn flush_locals() {
        L_TOO_LARGE.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                TOO_LARGE.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_BUFFER_FULL.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                BUFFER_FULL.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_SESSION_FULL.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                SESSION_FULL.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_DNS_INFLIGHT.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                DNS_INFLIGHT.fetch_add(v, Ordering::Relaxed);
            }
        });
    }

    thread_local! {
        static L_TOO_LARGE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_BUFFER_FULL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_SESSION_FULL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_DNS_INFLIGHT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn batched(
        counter: &AtomicU64,
        local: &'static std::thread::LocalKey<std::cell::Cell<u64>>,
    ) -> u64 {
        let v = local.with(|c| {
            let v = c.get().wrapping_add(1);
            if v >= 64 {
                c.set(0);
                64
            } else {
                c.set(v);
                0
            }
        });
        if v != 0 {
            counter.fetch_add(v, Ordering::Relaxed).saturating_add(v)
        } else {
            counter.load(Ordering::Relaxed).saturating_add(1)
        }
    }

    /// `counter` must be one of this module's statics. Four of them batch per
    /// thread (flushed at 64, or by a `snapshot` on the *same* thread), which is
    /// what keeps a flood off the shared cache lines; each of those needs its own
    /// arm here *and* its own `flush_locals` arm, or its count would sit in a
    /// thread-local cell and never reach the snapshot.
    ///
    /// The two **egress** states deliberately do not batch and fall through to
    /// the direct `fetch_add` below. A fail-closed outage is a discrete event
    /// that lasts seconds, and batching let a short one hide in a worker thread's
    /// cell indefinitely: this thread only flushes at 64, and the reporter's
    /// `snapshot` flushes its own cells, not this thread's — so a 20-datagram
    /// outage could go unreported forever, and a thread that exits takes its
    /// pending count with it. One RMW per *dropped* datagram (never per sent
    /// datagram) is the right price for a number that has to be true;
    /// `egress_drops_are_exact_across_threads` pins it.
    pub fn bump(counter: &AtomicU64) -> u64 {
        if std::ptr::eq(counter, &TOO_LARGE) {
            batched(counter, &L_TOO_LARGE)
        } else if std::ptr::eq(counter, &BUFFER_FULL) {
            batched(counter, &L_BUFFER_FULL)
        } else if std::ptr::eq(counter, &SESSION_FULL) {
            batched(counter, &L_SESSION_FULL)
        } else if std::ptr::eq(counter, &DNS_INFLIGHT) {
            batched(counter, &L_DNS_INFLIGHT)
        } else {
            counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
        }
    }

    /// Which egress state a warning is about. An enum rather than a reason
    /// string: the slot is picked from it, and a typo in a substring match would
    /// silently merge two different faults into one rate limit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EgressDrop {
        /// No usable egress connection at all: the dedicated UDP connection had
        /// not come up, was reconnecting, or the single-flight refresh was owned
        /// by another thread.
        NoConnection,
        /// The connection was gone (or the peer stopped offering DATAGRAM) at
        /// send time.
        ConnectionLost,
    }

    /// Rate-limited, once-per-state warning for a datagram dropped because its
    /// **egress connection** was unusable.
    ///
    /// Split from `warn_datagram_drop`: that helper's text is about the packet
    /// ("a packet this size would have been carried by a direct UDP path") and its
    /// three slots are shared with the size/buffer cases, so folding egress drops
    /// into them would both misdescribe the fault and let one class starve the
    /// other's warning. The two states get a slot each, limited to one line per
    /// `DROP_WARN_INTERVAL_MS`, so the *first* drop of an outage is in the log
    /// immediately — before this existed the whole fail-closed loss mode was
    /// visible only in the 60 s aggregate, and (for a short outage) sometimes not
    /// even there, because of the batching bound.
    ///
    /// Costs one clock read per *dropped* datagram (the rate limiter needs it) and
    /// builds `detail` only when a line is actually emitted.
    pub fn warn_egress_drop(kind: EgressDrop, total: u64, detail: impl FnOnce() -> String) {
        use crate::{claim_drop_warning, NEVER_WARNED};
        static LAST_NO_CONNECTION: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        static LAST_LOST: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        let slot = match kind {
            EgressDrop::NoConnection => &LAST_NO_CONNECTION,
            EgressDrop::ConnectionLost => &LAST_LOST,
        };
        if !claim_drop_warning(slot) {
            return;
        }
        let reason = match kind {
            EgressDrop::NoConnection => "no usable udp egress connection",
            EgressDrop::ConnectionLost => "udp egress connection lost at send",
        };
        let detail = detail();
        tracing::warn!("udp datagram dropped ({reason}): {total} so far{detail}");
    }
}

/// UDP relay activity, so "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" is answerable from the log rather than a packet
/// capture — on a QUIC tunnel a capture can only ever show ciphertext.
///
/// [`UdpSnapshot::max_payload`] is a **high-water mark, not a limit**: it is the
/// empirical answer to "is `MQP_FRAG_MAX_PAYLOAD` big enough for this
/// deployment", measured on real traffic instead of argued from protocol specs.
/// A deployment whose high-water mark stays under `UDP_RECV_MAX` never needs a
/// larger cap, whatever its workload is.
pub mod udp_stats {
    use crate::UdpSnapshot;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DATAGRAMS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);
    static FRAGMENTED: AtomicU64 = AtomicU64::new(0);
    static MAX_PAYLOAD: AtomicU64 = AtomicU64::new(0);
    static SESSIONS: AtomicU64 = AtomicU64::new(0);
    static REASSEMBLY_EXPIRED: AtomicU64 = AtomicU64::new(0);
    static REASSEMBLY_EVICTED: AtomicU64 = AtomicU64::new(0);

    thread_local! {
        static L_DATAGRAMS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        /// This thread's payload high-water mark. It guards the shared
        /// `MAX_PAYLOAD` read on the per-payload path: the global is only
        /// touched when this thread sees a payload larger than any it has
        /// already recorded, so a steady flow costs one Cell compare and no
        /// shared cache-line access at all.
        static L_MAX_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[cfg(feature = "stats")]
    fn flush_locals() {
        L_DATAGRAMS.with(|c| {
            let v = c.get();
            if v != 0 {
                DATAGRAMS.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        L_BYTES.with(|c| {
            let v = c.get();
            if v != 0 {
                BYTES.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
    }

    /// One relayed UDP payload of `len` bytes.
    pub fn payload(len: usize) {
        stats_only! {
            L_DATAGRAMS.with(|c| {
                let v = c.get().wrapping_add(1);
                c.set(v);
                if v >= 1024 {
                    DATAGRAMS.fetch_add(v, Ordering::Relaxed);
                    c.set(0);
                }
            });
            L_BYTES.with(|c| {
                let v = c.get().wrapping_add(len as u64);
                c.set(v);
                if v >= 1_048_576 {
                    BYTES.fetch_add(v, Ordering::Relaxed);
                    c.set(0);
                }
            });
            let l = len as u64;
            L_MAX_SEEN.with(|c| {
                if l > c.get() {
                    c.set(l);
                    if l > MAX_PAYLOAD.load(Ordering::Relaxed) {
                        MAX_PAYLOAD.fetch_max(l, Ordering::Relaxed);
                    }
                }
            });
        }
        let _ = len;
    }

    /// One payload that needed `frames` frames to carry.
    pub fn fragmented(frames: u8) {
        stats_only! {
            if frames > 1 {
                FRAGMENTED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let _ = frames;
    }

    /// A new UDP session (server) or SOCKS association (client) was established.
    pub fn session() {
        stats_only! {
            SESSIONS.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A partial datagram was discarded because a fragment never arrived.
    pub fn reassembly_expired() {
        stats_only! {
            REASSEMBLY_EXPIRED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A partial datagram was discarded to stay inside [`FRAG_MAX_HELD_BYTES`].
    pub fn reassembly_evicted() {
        stats_only! {
            REASSEMBLY_EVICTED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `(expired, evicted)` reassembly losses since process start. These are the
    /// only drops that happen after the wire, so no send-side counter can see
    /// them: a fragment lost in transit shows up here, not in `udp_write`.
    pub fn reassembly_drops() -> (u64, u64) {
        (
            REASSEMBLY_EXPIRED.load(Ordering::Relaxed),
            REASSEMBLY_EVICTED.load(Ordering::Relaxed),
        )
    }

    pub fn snapshot() -> UdpSnapshot {
        #[cfg(feature = "stats")]
        flush_locals();
        UdpSnapshot {
            datagrams: DATAGRAMS.load(Ordering::Relaxed),
            bytes: BYTES.load(Ordering::Relaxed),
            fragmented: FRAGMENTED.load(Ordering::Relaxed),
            max_payload: MAX_PAYLOAD.load(Ordering::Relaxed),
            sessions: SESSIONS.load(Ordering::Relaxed),
        }
    }
}

/// See [`udp_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSnapshot {
    pub datagrams: u64,
    pub bytes: u64,
    pub fragmented: u64,
    /// High-water mark over the process lifetime; never differenced, because a
    /// maximum cannot be subtracted.
    pub max_payload: u64,
    pub sessions: u64,
}

impl UdpSnapshot {
    /// Counters accumulated since `prev`. `max_payload` stays the cumulative
    /// high-water mark for the reason above.
    pub fn since(&self, prev: &Self) -> Self {
        Self {
            datagrams: self.datagrams.saturating_sub(prev.datagrams),
            bytes: self.bytes.saturating_sub(prev.bytes),
            fragmented: self.fragmented.saturating_sub(prev.fragmented),
            max_payload: self.max_payload,
            sessions: self.sessions.saturating_sub(prev.sessions),
        }
    }

    /// Nothing happened in this interval; callers use it to stay quiet.
    pub fn is_idle(&self) -> bool {
        self.datagrams == 0 && self.sessions == 0
    }
}

impl std::fmt::Display for UdpSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} session(s), {} datagram(s) / {:.2} MiB, {} fragmented",
            self.sessions,
            self.datagrams,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.fragmented
        )
    }
}

/// Terminal outcomes of the last-hop UDP write.
///
/// These were the only paths in the relay that could lose a packet with no
/// counter behind them — `udp_try_send` dropped on a full retry budget, threw
/// away hard errors at `debug!`, and a reply with no recorded app address
/// returned silently. That is why a rate-dependent loss could be measured from
/// the outside while every existing counter stayed flat.
pub mod udp_write {
    use crate::UdpWriteSnapshot;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Written to the socket on the first attempt.
    pub static SENT: AtomicU64 = AtomicU64::new(0);
    /// `WouldBlock`: handed to a detached task that retries (not a loss).
    pub static RETRIED: AtomicU64 = AtomicU64::new(0);
    /// `WouldBlock` and the detached-retry budget was exhausted: dropped.
    pub static DROPPED_NO_PERMIT: AtomicU64 = AtomicU64::new(0);
    /// Hard send error. Previously `debug!`-only, i.e. invisible in production.
    pub static FAILED: AtomicU64 = AtomicU64::new(0);
    /// A reply arrived before any app address was known: nowhere to send it.
    pub static NO_APP: AtomicU64 = AtomicU64::new(0);
    /// A detached retry finished without writing.
    pub static RETRY_FAILED: AtomicU64 = AtomicU64::new(0);

    #[cfg(feature = "stats")]
    fn bump(c: &AtomicU64) -> u64 {
        c.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }
    thread_local! {
        static L_SENT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[cfg(feature = "stats")]
    fn flush_sent() {
        L_SENT.with(|c| {
            let v = c.get();
            if v != 0 {
                SENT.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
    }
    pub fn sent() {
        stats_only! {
            L_SENT.with(|c| {
                let v = c.get().wrapping_add(1);
                if v >= 1024 {
                    SENT.fetch_add(v, Ordering::Relaxed);
                    c.set(0);
                } else {
                    c.set(v);
                }
            });
        }
    }
    pub fn retried() -> u64 {
        #[cfg(feature = "stats")]
        return bump(&RETRIED);
        #[cfg(not(feature = "stats"))]
        return 1;
    }
    pub fn dropped_no_permit() -> u64 {
        #[cfg(feature = "stats")]
        return bump(&DROPPED_NO_PERMIT);
        #[cfg(not(feature = "stats"))]
        return 1;
    }
    pub fn failed() -> u64 {
        #[cfg(feature = "stats")]
        return bump(&FAILED);
        #[cfg(not(feature = "stats"))]
        return 1;
    }
    pub fn no_app() -> u64 {
        #[cfg(feature = "stats")]
        return bump(&NO_APP);
        #[cfg(not(feature = "stats"))]
        return 1;
    }
    pub fn retry_failed() -> u64 {
        #[cfg(feature = "stats")]
        return bump(&RETRY_FAILED);
        #[cfg(not(feature = "stats"))]
        return 1;
    }

    pub fn snapshot() -> UdpWriteSnapshot {
        #[cfg(feature = "stats")]
        flush_sent();
        UdpWriteSnapshot {
            sent: SENT.load(Ordering::Relaxed),
            retried: RETRIED.load(Ordering::Relaxed),
            dropped_no_permit: DROPPED_NO_PERMIT.load(Ordering::Relaxed),
            failed: FAILED.load(Ordering::Relaxed),
            no_app: NO_APP.load(Ordering::Relaxed),
            retry_failed: RETRY_FAILED.load(Ordering::Relaxed),
        }
    }
}

/// See [`udp_write`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpWriteSnapshot {
    pub sent: u64,
    pub retried: u64,
    pub dropped_no_permit: u64,
    pub failed: u64,
    pub no_app: u64,
    pub retry_failed: u64,
}

impl UdpWriteSnapshot {
    pub fn since(&self, prev: &Self) -> Self {
        let d = |a: u64, b: u64| a.saturating_sub(b);
        Self {
            sent: d(self.sent, prev.sent),
            retried: d(self.retried, prev.retried),
            dropped_no_permit: d(self.dropped_no_permit, prev.dropped_no_permit),
            failed: d(self.failed, prev.failed),
            no_app: d(self.no_app, prev.no_app),
            retry_failed: d(self.retry_failed, prev.retry_failed),
        }
    }
    /// Nothing was lost in this interval.
    pub fn clean(&self) -> bool {
        self.dropped_no_permit == 0
            && self.failed == 0
            && self.no_app == 0
            && self.retry_failed == 0
    }
}

impl std::fmt::Display for UdpWriteSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} sent, {} retried, {} dropped(no permit), {} failed, {} no-app, {} retry-failed",
            self.sent,
            self.retried,
            self.dropped_no_permit,
            self.failed,
            self.no_app,
            self.retry_failed
        )
    }
}

/// Minimum spacing between datagram-drop warnings, per process.
const DROP_WARN_INTERVAL_MS: u64 = 10_000;

/// Sentinel for "no drop warning has been emitted yet".
///
/// Using 0 here swallows the *first* drop: [`mono_millis`] establishes its base
/// on first call, so the elapsed value it returns starts near zero and
/// `now - 0 < INTERVAL` holds. That is exactly the case a fresh deployment
/// hits, so the first drop must warn unconditionally.
const NEVER_WARNED: u64 = u64::MAX;

/// Whether a drop warning is due. Split out from the atomic so the window logic
/// is testable without a clock or a global.
fn drop_warn_due(last: u64, now: u64) -> bool {
    last == NEVER_WARNED || now.saturating_sub(last) >= DROP_WARN_INTERVAL_MS
}

/// Claim this warning slot if one is due (at most one winner per
/// [`DROP_WARN_INTERVAL_MS`] per counter).
///
/// Split from the message so a flood of drops pays for building the detail
/// string only when the line will actually be emitted: formatting it before the
/// gate made the *logging* itself the per-drop cost.
fn claim_drop_warning(last: &std::sync::atomic::AtomicU64) -> bool {
    use std::sync::atomic::Ordering;
    let now = mono_millis();
    let prev = last.load(Ordering::Relaxed);
    drop_warn_due(prev, now)
        && last
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// Rate-limited (at most one per [`DROP_WARN_INTERVAL_MS`], process-wide)
/// warning for a dropped datagram. A per-packet `warn!` would itself become the
/// bottleneck under the flood that causes drops.
fn warn_datagram_drop(reason: &str, total: u64, detail: impl FnOnce() -> String) {
    use std::sync::atomic::AtomicU64;
    static LAST_LARGE: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_FULL: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_OTHER: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let slot = if reason.contains("buffer full") {
        &LAST_FULL
    } else if reason.contains("budget") || reason.contains("fragment") || reason.contains("header")
    {
        &LAST_LARGE
    } else {
        &LAST_OTHER
    };
    if !claim_drop_warning(slot) {
        return;
    }
    let detail = detail();
    tracing::warn!(
        "udp datagram dropped ({reason}): {total} so far{detail} — a packet this size would \
         have been carried by a direct UDP path, so the tunnel is degrading UDP here"
    );
}

/// Path-budget context for a drop warning.
fn budget_detail(limit: usize, cap: usize) -> String {
    format!("; path DATAGRAM limit {limit} B, usable UDP payload {cap} B")
}

/// Encode and send one UDP payload as a single MQP-2 DATAGRAM, accounting for
/// every drop.
///
/// `limit` must be [`quinn::Connection::max_datagram_size`] — see
/// [`dgram_payload_cap`] for the resulting UDP payload budget. A returned
/// [`DatagramSend::TooLarge`] means the payload exceeds what the current path
/// can carry in one frame; [`DgramFragmenter::send`] is the relay entry point
/// and splits such a payload instead of dropping it.
pub fn send_udp_datagram(
    conn: &quinn::Connection,
    sess: u32,
    address: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> DatagramSend {
    let Ok(header) = address.header() else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop("bad address header", n, String::new);
        return DatagramSend::TooLarge;
    };
    send_udp_datagram_with_header(conn, sess, &header, payload, limit)
}

fn send_udp_datagram_with_header(
    conn: &quinn::Connection,
    sess: u32,
    header: &AddrHeader<'_>,
    payload: &[u8],
    limit: usize,
) -> DatagramSend {
    let Some(d) = encode_datagram_with_header(sess, header, payload, limit) else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop("payload exceeds the path budget", n, || {
            budget_detail(limit, limit.saturating_sub(DGRAM_PREFIX_LEN + header.len()))
        });
        return DatagramSend::TooLarge;
    };
    send_encoded(conn, d)
}

/// Queue an already-encoded datagram body, counting a full send buffer.
fn send_encoded(conn: &quinn::Connection, body: Bytes) -> DatagramSend {
    let outcome = try_send_datagram(conn, body);
    if outcome == DatagramSend::Blocked {
        let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
        warn_datagram_drop("send buffer full", n, String::new);
    }
    outcome
}

/// Result of [`DgramFragmenter::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadSend {
    /// Frames actually queued (1 for the unfragmented fast path).
    pub frames: u8,
    /// The failure that stopped the send, if it did not complete. A partially
    /// sent payload is *not* rolled back: the peer discards it on reassembly
    /// timeout, which is the UDP answer to a lost fragment.
    pub failed: Option<DatagramSend>,
}

impl PayloadSend {
    pub fn complete(&self) -> bool {
        self.failed.is_none()
    }
    pub fn fragmented(&self) -> bool {
        self.frames > 1
    }
    /// Collapse to the single-frame outcome the relays already match on.
    pub fn outcome(&self) -> DatagramSend {
        self.failed.unwrap_or(DatagramSend::Sent)
    }
}

/// Splits oversized UDP payloads across [`MQP_DGRAM_FRAG`] frames.
///
/// One instance per sending context (a SOCKS association on the client, a UDP
/// session on the server), so `id` is unique within the `(sess, id)` key the
/// receiver reassembles on.
#[derive(Debug, Default)]
pub struct DgramFragmenter {
    next_id: u16,
}

impl DgramFragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode and send `payload`, fragmenting only when it does not fit one
    /// DATAGRAM. The unfragmented path is byte-identical to the pre-fragmentation
    /// wire format, so small packets pay nothing for this.
    pub fn send(
        &mut self,
        conn: &quinn::Connection,
        sess: u32,
        address: &TargetAddrRef<'_>,
        payload: &[u8],
        limit: usize,
    ) -> PayloadSend {
        let Ok(header) = address.header() else {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop("bad address header", n, String::new);
            return PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            };
        };
        let cap = limit.saturating_sub(DGRAM_PREFIX_LEN + header.len());
        // Every outbound relayed payload passes through here, so this is the one
        // place the activity counters need (see `udp_stats`).
        udp_stats::payload(payload.len());
        if payload.len() <= cap {
            let failed = match send_udp_datagram_with_header(conn, sess, &header, payload, limit) {
                DatagramSend::Sent => None,
                other => Some(other),
            };
            return PayloadSend {
                frames: u8::from(failed.is_none()),
                failed,
            };
        }

        let chunk = limit.saturating_sub(FRAG_PREFIX_LEN + header.len());
        // One fragment must carry something, and the reassembled result must
        // stay inside both the protocol's payload cap and the u8 fragment count.
        let total_usize = if chunk == 0 {
            usize::MAX
        } else {
            payload.len().div_ceil(chunk)
        };
        if total_usize > MQP_FRAG_MAX_TOTAL as usize || payload.len() > MQP_FRAG_MAX_PAYLOAD {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop("payload above the MQP-2 fragmentation limit", n, || {
                format!(
                    "; {} B exceeds the {MQP_FRAG_MAX_PAYLOAD} B reassembly cap",
                    payload.len()
                )
            });
            return PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            };
        }
        let total = total_usize as u8;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        udp_stats::fragmented(total);
        let mut frames = 0u8;
        for (i, part) in payload.chunks(chunk).enumerate() {
            let Some(body) =
                encode_fragment_with_header(sess, id, i as u8, total, &header, part, limit)
            else {
                // Only reachable if `chunk` and the encoder disagree; report it
                // rather than send a payload that can never reassemble.
                let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                warn_datagram_drop("fragment does not fit the path budget", n, String::new);
                return PayloadSend {
                    frames,
                    failed: Some(DatagramSend::TooLarge),
                };
            };
            match send_encoded(conn, body) {
                DatagramSend::Sent => frames += 1,
                other => {
                    return PayloadSend {
                        frames,
                        failed: Some(other),
                    }
                }
            }
        }
        PayloadSend {
            frames,
            failed: None,
        }
    }
}

/// A partially reassembled datagram.
struct Partial {
    total: u8,
    address: TargetAddr,
    chunks: Vec<Option<Bytes>>,
    got: u8,
    bytes: usize,
    first_ms: u64,
}

impl Partial {
    fn new(total: u8, address: &TargetAddrRef<'_>, now_ms: u64) -> Self {
        Self {
            total,
            address: address.into_owned(),
            chunks: vec![None; total as usize],
            got: 0,
            bytes: 0,
            first_ms: now_ms,
        }
    }

    fn assemble(self) -> Bytes {
        let mut out = bytes::BytesMut::with_capacity(self.bytes);
        for c in self.chunks.into_iter().flatten() {
            out.extend_from_slice(&c);
        }
        out.freeze()
    }
}

/// Reassembles [`MQP_DGRAM_FRAG`] frames into whole UDP payloads.
///
/// Keyed by `(sess, id)`. Because every fragment carries the address header,
/// out-of-order arrival needs no special case and a lost fragment 0 does not
/// strand the rest — the partial simply expires. Memory is bounded twice over:
/// per partial by [`MQP_FRAG_MAX_PAYLOAD`], and in aggregate by
/// [`FRAG_MAX_HELD_BYTES`], past which the oldest partial is evicted.
#[derive(Default)]
pub struct DgramReassembler {
    parts: HashMap<(u32, u16), Partial>,
    held: usize,
    last_sweep_ms: u64,
}

impl DgramReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn held_bytes(&self) -> usize {
        self.held
    }

    /// Number of datagrams currently waiting for their remaining fragments.
    pub fn inflight(&self) -> usize {
        self.parts.len()
    }

    /// Feed one fragment. Returns the payload once the last fragment lands.
    ///
    /// A duplicate fragment is ignored, a malformed one is rejected without
    /// disturbing the partial, and an incomplete datagram is dropped silently —
    /// the sender is UDP and will not retransmit, so there is nothing to report
    /// to a peer that never asked for reliability. A *complete* set replayed
    /// after delivery is delivered again: UDP permits duplicates, the id is
    /// freed on completion, and suppressing them would cost a window of
    /// completed ids for no semantic gain.
    pub fn push(&mut self, f: &FragmentRef<'_>, now_ms: u64) -> Option<(u32, TargetAddr, Bytes)> {
        if f.total < 2 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total {
            return None;
        }
        self.maybe_sweep(now_ms);

        let key = (f.sess, f.id);
        // Count cap first: `held` misses the per-partial slot-table cost, so a
        // flood of tiny single-fragment partials would otherwise grow memory
        // without ever tripping the byte bound. Evict-before-insert keeps the
        // `min_by_key` scan bounded to FRAG_MAX_PARTIALS entries.
        if !self.parts.contains_key(&key)
            && self.parts.len() >= FRAG_MAX_PARTIALS
            && (!self.evict_oldest() || self.parts.len() >= FRAG_MAX_PARTIALS)
        {
            return None;
        }
        let complete = {
            let entry = self
                .parts
                .entry(key)
                .or_insert_with(|| Partial::new(f.total, &f.address, now_ms));
            if entry.total != f.total {
                // A wrapped id reused with a different shape: restart rather
                // than splice two datagrams together. Release the old bytes
                // first or `held` overcounts forever.
                self.held = self.held.saturating_sub(entry.bytes);
                *entry = Partial::new(f.total, &f.address, now_ms);
            } else if entry.got > 0
                && (entry.address.as_ref() != f.address
                    || entry.chunks[f.idx as usize]
                        .as_ref()
                        .is_some_and(|old| old.as_ref() != f.chunk))
            {
                // Same shape but a different generation: the address changed,
                // or this index already holds different bytes. An identical
                // chunk is a plain replay and stays ignored below; a differing
                // one is a fast id reuse, so restart rather than splice (a
                // stale fragment landing on an *empty* slot stays
                // indistinguishable without a wire generation marker, but that
                // requires id reuse inside the 2s window plus exact
                // interleaving, and at most drops or reorders UDP payloads).
                self.held = self.held.saturating_sub(entry.bytes);
                *entry = Partial::new(f.total, &f.address, now_ms);
            }
            let slot = &mut entry.chunks[f.idx as usize];
            if slot.is_none() {
                *slot = Some(Bytes::copy_from_slice(f.chunk));
                entry.got += 1;
                entry.bytes += f.chunk.len();
                self.held = self.held.saturating_add(f.chunk.len());
            }
            entry.got == entry.total
        };

        if complete {
            let p = self.parts.remove(&key)?;
            self.held = self.held.saturating_sub(p.bytes);
            return Some((key.0, p.address.clone(), p.assemble()));
        }
        while self.held > FRAG_MAX_HELD_BYTES {
            if !self.evict_oldest() {
                break;
            }
        }
        None
    }

    /// Drop partials whose first fragment is older than [`FRAG_TIMEOUT_MS`].
    fn maybe_sweep(&mut self, now_ms: u64) {
        if self.last_sweep_ms != 0 && now_ms.saturating_sub(self.last_sweep_ms) < 1_000 {
            return;
        }
        self.last_sweep_ms = now_ms;
        let mut freed = 0usize;
        let mut expired = 0u64;
        self.parts.retain(|_, p| {
            let live = now_ms.saturating_sub(p.first_ms) < FRAG_TIMEOUT_MS;
            if !live {
                freed += p.bytes;
                expired += 1;
            }
            live
        });
        for _ in 0..expired {
            udp_stats::reassembly_expired();
        }
        self.held = self.held.saturating_sub(freed);
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(key) = self
            .parts
            .iter()
            .min_by_key(|(_, p)| p.first_ms)
            .map(|(k, _)| *k)
        else {
            return false;
        };
        if let Some(p) = self.parts.remove(&key) {
            self.held = self.held.saturating_sub(p.bytes);
            udp_stats::reassembly_evicted();
        }
        true
    }
}

/// One queued retry: the socket it must go out on, the destination and the
/// bytes.
///
/// `sock` is deliberately strong — the queue has to be able to write after the
/// caller returns — but that also makes this entry the socket's *last* owner once
/// the association (client relay) or session (server session socket) has dropped
/// its own handle. The retention is therefore bounded by
/// [`UDP_RETRY_TIMEOUT`], not by luck: see the note on the retry worker.
struct UdpRetry {
    sock: Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    payload: Bytes,
}

const UDP_RETRY_SHARDS: usize = 16;
const UDP_RETRY_DEPTH: usize = 256;

/// One shard's retry worker, published so it can be replaced.
///
/// The worker is a task on whatever runtime first needed the shard. That is the
/// process runtime in the shipped binaries -- but a test binary runs one
/// runtime per `#[tokio::test]` and an embedder may run several, and a task
/// dies with its runtime. The old shape kept the `Sender` in a `OnceLock`
/// forever, so after the first runtime ended every later `try_send` went into a
/// queue whose receiver was gone: the datagram was dropped and the caller
/// counted it under a resource budget it had not exceeded. The sender is behind
/// an `ArcSwap` instead, and `udp_retry_submit` re-arms the shard on the
/// runtime it is called from whenever it finds the worker gone.
struct RetryShard {
    tx: arc_swap::ArcSwap<tokio::sync::mpsc::Sender<UdpRetry>>,
}

fn retry_shards() -> &'static [RetryShard; UDP_RETRY_SHARDS] {
    static TX: std::sync::OnceLock<[RetryShard; UDP_RETRY_SHARDS]> = std::sync::OnceLock::new();
    TX.get_or_init(|| {
        std::array::from_fn(|_| RetryShard {
            tx: arc_swap::ArcSwap::from_pointee(spawn_retry_worker()),
        })
    })
}

/// Deadline on one detached retry.
///
/// A retry holds a **strong** `Arc<UdpSocket>` (see [`UdpRetry::sock`]) after the
/// association or session that owned the socket has already dropped its own
/// handle, so this queue is the socket's last owner for as long as the entry
/// lives. `send_to(...).await` parks until the socket is writable, and a
/// destination that never becomes writable — a peer that stopped reading, a full
/// qdisc, a black-holed route — parks it forever. That pinned the fd (and the
/// session's 2 x 256 KiB kernel buffers on the server) for the process lifetime
/// *and* wedged the whole shard: a worker parked in `send_to` retries nothing
/// else, so every later datagram hashing to that shard was silently dropped.
/// 200 ms is far above the loopback/LAN drain this path exists for and far below
/// any user-visible retry interval; the datagram is best-effort UDP either way,
/// and now the fd and the shard are released on a bounded schedule.
const UDP_RETRY_TIMEOUT: Duration = Duration::from_millis(200);

/// Await one send under [`UDP_RETRY_TIMEOUT`].
///
/// Generic over the future on purpose: it is the deadline itself that has to be
/// provable, and no portable socket stays unwritable on every platform, so
/// `retry_deadline_bounds_a_never_writable_socket` drives it with a future that
/// is never ready.
async fn under_retry_deadline<F: std::future::Future>(fut: F) -> Result<F::Output, ()> {
    tokio::time::timeout(UDP_RETRY_TIMEOUT, fut)
        .await
        .map_err(|_| ())
}

/// Send one queued retry under the retry deadline. Returns the reason on
/// failure, so the worker's only job is counting and logging.
async fn retry_one(req: &UdpRetry) -> Result<(), String> {
    match under_retry_deadline(req.sock.send_to(&req.payload, req.dst)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(()) => Err(format!("socket not writable within {UDP_RETRY_TIMEOUT:?}")),
    }
}

fn spawn_retry_worker() -> tokio::sync::mpsc::Sender<UdpRetry> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpRetry>(UDP_RETRY_DEPTH);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            // `req` is dropped here whatever the outcome, which is what releases
            // the last strong `Arc<UdpSocket>` on this path.
            if let Err(reason) = retry_one(&req).await {
                let n = udp_write::retry_failed();
                warn_udp_write("detached retry failed", n, || reason);
            }
        }
    });
    tx
}

/// Queue a datagram for a detached retry on the shard that owns `dst`.
///
/// Returns false when the shard is full (UDP semantics: drop). A shard whose
/// worker died with its runtime is re-armed here, so a retry never disappears
/// just because the queue outlived the task that was draining it.
fn udp_retry_submit(dst: &SocketAddr, req: UdpRetry) -> bool {
    let shard = retry_shard_for(dst);
    let cur = shard.tx.load_full();
    let tx = if cur.is_closed() {
        let fresh = std::sync::Arc::new(spawn_retry_worker());
        // One winner publishes; every caller then uses whichever sender won.
        shard.tx.compare_and_swap(&cur, fresh);
        shard.tx.load_full()
    } else {
        cur
    };
    tx.try_send(req).is_ok()
}

fn retry_shard_for(dst: &SocketAddr) -> &'static RetryShard {
    // Shard by ip+port: port-only sharding collapses DNS(:53) / HTTPS(:443)
    // heavy workloads into a single shard, reintroducing the HOL blocking
    // the sharded pool was created to remove. Manual fold (no SipHash) keeps
    // this at a few integer ops on the WouldBlock-only path.
    const K: usize = 0x9e3779b97f4a7c15;
    let h = match *dst {
        SocketAddr::V4(a) => (u32::from_ne_bytes(a.ip().octets()) as usize)
            .wrapping_mul(K)
            .wrapping_add(a.port() as usize),
        SocketAddr::V6(a) => {
            let mut h = a.port() as usize;
            for w in a.ip().segments() {
                h = h.wrapping_mul(K).wrapping_add(w as usize);
            }
            h
        }
    };
    &retry_shards()[h % UDP_RETRY_SHARDS]
}

/// Best-effort non-blocking UDP send for shared loops (one datagram reader per
/// connection, one relay per association).
///
/// `try_send_to` alone is not enough: tokio returns `WouldBlock` without even
/// attempting the syscall while a freshly registered socket has no cached
/// writable readiness, which would silently drop the first packet of every new
/// session. A genuinely full socket buffer is real backpressure too. In both
/// cases the packet is queued to a sharded global retry pool (one worker per
/// shard, selected by destination ip+port) so the caller never stalls, no task is
/// spawned per packet, and one slow destination cannot head-of-line-block every
/// other session behind a single queue; a full shard drops (UDP semantics).
pub fn udp_try_send(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: Bytes) {
    match sock.try_send_to(&payload, dst) {
        Ok(_) => udp_write::sent(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = udp_write::retried();
            let req = UdpRetry {
                sock: sock.clone(),
                dst,
                payload,
            };
            if !udp_retry_submit(&dst, req) {
                let n = udp_write::dropped_no_permit();
                warn_udp_write("retry budget exhausted", n, || {
                    "send buffer full".to_string()
                });
            }
        }
        Err(e) => {
            let n = udp_write::failed();
            warn_udp_write("send failed", n, || e.to_string());
        }
    }
}

/// Borrowed fast path for replies built into a reused scratch buffer.
///
/// `udp_try_send` needs an owned `Bytes` because the WouldBlock retry queue
/// owns the payload, which forced the reply path to `freeze()` its scratch
/// buffer (one allocation) on every datagram. The fast path only borrows the
/// slice for the syscall; only WouldBlock copies into an owned `Bytes` for
/// the queue, so steady-state replies allocate nothing and the scratch buffer
/// is reused across packets.
pub fn udp_try_send_slice(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: &[u8]) {
    match sock.try_send_to(payload, dst) {
        Ok(_) => udp_write::sent(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = udp_write::retried();
            let req = UdpRetry {
                sock: sock.clone(),
                dst,
                payload: Bytes::copy_from_slice(payload),
            };
            if !udp_retry_submit(&dst, req) {
                let n = udp_write::dropped_no_permit();
                warn_udp_write("retry budget exhausted", n, || {
                    "send buffer full".to_string()
                });
            }
        }
        Err(e) => {
            let n = udp_write::failed();
            warn_udp_write("send failed", n, || e.to_string());
        }
    }
}

/// Rate-limited warning for a last-hop UDP write failure.
fn warn_udp_write(reason: &str, total: u64, detail: impl FnOnce() -> String) {
    use std::sync::atomic::AtomicU64;
    static LAST_FAIL: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_NOPERM: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_OTHER: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let slot = if reason.contains("budget") || reason.contains("retry") {
        &LAST_NOPERM
    } else if reason.contains("failed") {
        &LAST_FAIL
    } else {
        &LAST_OTHER
    };
    if !claim_drop_warning(slot) {
        return;
    }
    let detail = detail();
    tracing::warn!("udp write dropped ({reason}): {total} so far; {detail}");
}

/// Dual-stack UDP socket (V6ONLY=0 when bound to ::). Buffer enlarged for GSO bursts.
/// `sess` sockets (per UDP association) should use the small variant to avoid
/// OOM on routers: 4MB x N sessions of kernel memory adds up fast (P3).
pub fn udp_socket_dual(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, 4 * 1024 * 1024)
}

/// Per-session / relay socket buffer, per direction.
///
/// These are *caps*, not reservations: the kernel only accounts for what is
/// actually queued, but the cap is what a burst can pin. One association moves
/// a single DATAGRAM flow whose data is already rate-limited by the QUIC
/// congestion window, so a few hundred milliseconds of headroom is plenty;
/// 256 KiB keeps the worst case for the configured session caps well below the
/// kernel-memory budget (8192 server sessions x 512 KiB ≈ 4 GiB) while still
/// absorbing a scheduling hiccup on a busy host.
pub const SESS_SOCKET_BUF: usize = 256 * 1024;

/// Per-session / relay sockets: see [`SESS_SOCKET_BUF`].
pub fn udp_socket_dual_small(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, SESS_SOCKET_BUF)
}

pub fn udp_socket_dual_with_size(bind: &str, buf: usize) -> Result<std::net::UdpSocket> {
    let addr: SocketAddr = bind.parse()?;
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    // No SO_REUSEADDR here: the QUIC socket is a singleton and reuse would let
    // a second instance bind the same port and silently steal packets.
    s.set_nonblocking(true)?;
    if s.set_send_buffer_size(buf).is_err() {
        tracing::debug!("udp send buffer {buf} unavailable (raise net.core.wmem_max)");
    }
    if s.set_recv_buffer_size(buf).is_err() {
        tracing::debug!("udp recv buffer {buf} unavailable (raise net.core.rmem_max)");
    }
    // Linux/macOS silently clamp to net.core.{w,r}mem_max; surface the real
    // value once per process — these calls run for every UDP session socket,
    // so warning per socket would flood the log on routers with default
    // (small) rmem_max/wmem_max.
    if let Ok(actual) = s.send_buffer_size() {
        if actual < buf {
            warn_buf_clamped("send", actual, buf);
        }
    }
    if let Ok(actual) = s.recv_buffer_size() {
        if actual < buf {
            warn_buf_clamped("recv", actual, buf);
        }
    }
    s.bind(&addr.into())?;
    Ok(s.into())
}

fn warn_buf_clamped(which: &str, actual: usize, want: usize) {
    // One flag per direction: a shared flag let whichever direction was probed
    // first permanently silence the other, so a host with a small `wmem_max`
    // but a large `rmem_max` never reported the send-side clamp at all.
    static WARNED_SEND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static WARNED_RECV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let (flag, sysctl) = if which == "send" {
        (&WARNED_SEND, "wmem_max")
    } else {
        (&WARNED_RECV, "rmem_max")
    };
    if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "udp {which} buffer clamped to {actual} (< {want}); raise net.core.{sysctl}; further buffer warnings suppressed"
        );
    }
}

/// Dual-stack TCP listener (V6ONLY=0 when bound to ::).
pub fn tcp_listener_dual(bind: &str) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = bind.parse()?;
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let s = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    Ok(s.into())
}

/// Consume the MQP-2 TCP-open ACK (`0x00 | atyp | addr | port`). A non-zero
/// status, a malformed address, or a stream reset (dial refused/timeout) is an
/// error. Used by the optimistic client reply path, which has already answered
/// SOCKS before this runs.
async fn read_mqp_ack(recv: &mut quinn::RecvStream) -> Result<()> {
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await.context("ack read")?;
    if status[0] != MQP_TCP_ACK {
        anyhow::bail!("bad mqp ack {:#x}", status[0]);
    }
    let mut buf = [0u8; 19];
    recv.read_exact(&mut buf[..1]).await.context("bnd atyp")?;
    let n = match buf[0] {
        0x01 => 7,
        0x04 => 19,
        a => anyhow::bail!("bad bnd atyp {a}"),
    };
    recv.read_exact(&mut buf[1..n]).await.context("bnd addr")?;
    decode_bnd_addr(&buf[..n])?;
    Ok(())
}

/// Bidirectional copy between TCP and QUIC stream halves.
/// Half-closes propagate in both directions so neither side hangs waiting
/// for EOF after the peer already finished.
///
/// Contract: `Ok` means both halves reached clean EOF (TCP closed with FIN);
/// `Err` means at least one direction failed, in which case the TCP socket
/// was aborted with RST so the application sees an explicit failure instead
/// of a truncated-but-clean transfer.
///
/// Delegates to [`copy_tcp_quic_idle`] with an effectively unbounded idle
/// window; the direct `join!` implementation this used to have could hang
/// forever when one direction failed while the other stayed blocked.
pub async fn copy_tcp_quic(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, Duration::from_secs(u32::MAX as u64), None).await
}

/// Same as [`copy_tcp_quic`] but bounds idle keep-alive streams: if no bytes
/// flow in either direction for `idle`, both halves are shut down and an
/// error is returned so the per-connection task can exit (B7).
/// Uses monotonic `Instant` (never wall-clock) and resets the QUIC stream
/// on any directional failure so the peer never hangs.
/// The TCP socket is RST (not FIN) on the idle timeout, like any abnormal end.
pub async fn copy_tcp_quic_idle(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle: Duration,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, idle, None).await
}

/// Like [`copy_tcp_quic_idle`], but the QUIC→TCP direction first consumes the
/// MQP-2 dial acknowledgement (status + bound address). The caller is expected
/// to have already answered SOCKS optimistically: a failed or timed-out ACK
/// tears the TCP flow down so the application sees the failure instead of
/// hanging (aborted with RST, never a FIN posing as an empty reply). The TCP→QUIC direction is NOT gated on the ACK, which saves one
/// client↔server RTT on every connection.
pub async fn copy_tcp_quic_acked(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle: Duration,
    ack_timeout: Duration,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, idle, Some(ack_timeout)).await
}

/// Copy chunk: large enough that a high-BDP stream is not syscall-bound, small
/// enough that thousands of them do not dominate the RSS.
const COPY_CHUNK: usize = 32 * 1024;

/// Writes at least this large are handed to quinn as an owned `Bytes`
/// (`write_chunk`, which moves the buffer straight into the send queue) instead
/// of being copied into it. Below it the copy is the better trade: the buffer
/// handed over is a full [`COPY_CHUNK`] however few bytes were read, so a
/// request/response workload would pin 32 KiB per in-flight small write where
/// quinn's own `to_owned()` allocates exactly the bytes it needs.
const ZEROCOPY_MIN_WRITE: usize = 8 * 1024;

/// Make room for a whole copy chunk before a `read_buf`.
///
/// `BytesMut::chunk_mut` only reserves 64 B once the buffer is full, so without
/// this a `read_buf` on a full buffer would perform 64-byte reads — correct,
/// but hundreds of times more wakeups per chunk than intended. Pure so the
/// invariant that keeps the pump fast is pinned by a test.
#[inline]
fn reserve_copy_chunk(buf: &mut BytesMut) {
    if buf.capacity() - buf.len() < COPY_CHUNK {
        buf.reserve(COPY_CHUNK);
    }
}

const COPY_BUF_POOL_DEPTH: usize = 4;

thread_local! {
    static COPY_BUF_POOL: std::cell::RefCell<Vec<BytesMut>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn copy_buf_acquire() -> BytesMut {
    COPY_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if let Some(mut b) = p.pop() {
            b.clear();
            reserve_copy_chunk(&mut b);
            b
        } else {
            BytesMut::with_capacity(COPY_CHUNK)
        }
    })
}

fn copy_buf_release(mut buf: BytesMut) {
    buf.clear();
    COPY_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < COPY_BUF_POOL_DEPTH && buf.capacity() >= COPY_CHUNK {
            // Cap retained memory: a buffer that grew far past one chunk
            // (read side overshoot) is dropped instead of pooling.
            if buf.capacity() <= COPY_CHUNK * 2 {
                p.push(buf);
            }
        }
    });
}

/// Throttled liveness stamp shared by the two copy directions.
///
/// `since_ms` is the caller's last observed elapsed time, kept in a local so the
/// hot loop never reloads the atomic; only an actual write goes to the shared
/// counter. Each direction still stamps at least once per `throttle`, so the
/// idle check in the select loop keeps its resolution.
#[inline]
fn touch_stamp(
    last: &std::sync::atomic::AtomicU64,
    since_ms: &mut u64,
    now_ms: u64,
    throttle: u64,
) {
    if now_ms.saturating_sub(*since_ms) >= throttle {
        *since_ms = now_ms;
        last.store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn write_batch_vectored<W>(tw: &mut W, bufs: &[Bytes]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::future::poll_fn;
    let mut off = 0usize;
    let mut skip = 0usize;
    while skip < bufs.len() {
        while skip < bufs.len() && off >= bufs[skip].len() {
            skip += 1;
            off = 0;
        }
        if skip >= bufs.len() {
            break;
        }
        let mut ios: [std::io::IoSlice<'_>; 8] = [std::io::IoSlice::new(&[]); 8];
        let mut nios = 0usize;
        for (i, b) in bufs[skip..].iter().enumerate() {
            let s = if i == 0 {
                &b[off.min(b.len())..]
            } else {
                &b[..]
            };
            if !s.is_empty() {
                ios[nios] = std::io::IoSlice::new(s);
                nios += 1;
            }
        }
        if nios == 0 {
            break;
        }
        let ios = &ios[..nios];
        let n = poll_fn(|cx| {
            tokio::io::AsyncWrite::poll_write_vectored(std::pin::Pin::new(&mut *tw), cx, ios)
        })
        .await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "tcp vectored write zero",
            ));
        }
        let mut left = n;
        while skip < bufs.len() {
            let avail = bufs[skip].len().saturating_sub(off);
            if left < avail {
                off += left;
                break;
            }
            left -= avail;
            skip += 1;
            off = 0;
            if left == 0 {
                break;
            }
        }
    }
    Ok(())
}

async fn copy_tcp_quic_inner(
    mut tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    idle: Duration,
    ack: Option<Duration>,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Monotonic base: all timestamps are ms since here, immune to NTP/wall jumps.
    let base = tokio::time::Instant::now();
    let last_ms = Arc::new(AtomicU64::new(0));
    // Borrowed halves: `tcp` itself stays owned here so the final disposition
    // (graceful FIN on clean EOF, RST on any abnormal end) is decided in one
    // place after both directions settle, instead of each direction racing to
    // shut the socket down on its own.
    let (mut tr, mut tw) = tcp.split();
    let l1 = last_ms.clone();
    let l2 = last_ms.clone();
    let b1 = base;
    let b2 = base;
    // Scope the pump futures: everything borrowing `tcp` ends at the block
    // end, so the final disposition below owns it outright.
    let outcome: Result<(u64, u64)> = {
        let c2s = async move {
            let mut buf = copy_buf_acquire();
            let mut total = 0u64;
            let mut stamped = 0u64;
            loop {
                reserve_copy_chunk(&mut buf);
                let n = match tr.read_buf(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        send.reset(0x04u32.into()).ok();
                        let total_copy = total;
                        let buf_ret = std::mem::replace(&mut buf, BytesMut::new());
                        copy_buf_release(buf_ret);
                        return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                            "tcp>quic tcp read failed after {total_copy}B up: {e:#}"
                        ));
                    }
                };
                // Hand the filled buffer to quinn as an owned `Bytes` so a bulk
                // chunk crosses no memcpy boundary at all (quinn's `write_chunk`
                // moves it into `unacked_segments`); the remaining allocation is
                // the one quinn's `to_owned()` used to perform, minus the copy.
                let res = if n >= ZEROCOPY_MIN_WRITE {
                    send.write_chunk(buf.split_to(n).freeze()).await
                } else {
                    let r = send.write_all(&buf[..n]).await;
                    if r.is_ok() {
                        buf.clear();
                    }
                    r
                };
                if let Err(e) = res {
                    send.reset(0x04u32.into()).ok();
                    let total_copy = total;
                    let buf_ret = std::mem::replace(&mut buf, BytesMut::new());
                    copy_buf_release(buf_ret);
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "tcp>quic quic write failed after {total_copy}B up: {e:#}"
                    ));
                }
                total += n as u64;
                // Stamp every chunk (throttled to 100ms inside): gating on a
                // chunk count starves slow trickle uploads past the 300s idle
                // reap while downloads stamp every batch.
                let now = b1.elapsed().as_millis() as u64;
                touch_stamp(&l1, &mut stamped, now, 100);
            }
            send.finish().ok();
            copy_buf_release(buf);
            Ok::<u64, anyhow::Error>(total)
        };
        let s2c = async move {
            let mut total = 0u64;
            let mut stamped = 0u64;
            // Optimistic SOCKS replies have already told the application the
            // connection is up, so the MQP-2 dial ACK only gates the reply
            // direction here. A failure means the remote dial failed (or the
            // server never acked); tear the TCP flow down so the app fails fast.
            if let Some(t) = ack {
                let ok = matches!(
                    tokio::time::timeout(t, read_mqp_ack(&mut recv)).await,
                    Ok(Ok(()))
                );
                if !ok {
                    // No FIN here: the final disposition aborts the TCP flow with
                    // RST so the application retries instead of accepting an
                    // empty reply as success.
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "remote dial failed or MQP ack timed out"
                    ));
                }
            }
            let mut batch: [Bytes; 8] = std::array::from_fn(|_| Bytes::new());
            loop {
                // Batched zero-copy receive: `read_chunks` drains up to 8
                // assembler segments under one connection-lock acquisition,
                // then a single vectored write pushes them to TCP. The old
                // `read_chunk(MAX)+write_all` paid one lock + one syscall per
                // ~1.4 KiB STREAM frame; batching amortizes both. Clock is
                // sampled once per batch, not per chunk.
                let n = match recv.read_chunks(&mut batch).await {
                    Ok(Some(n)) => n,
                    Ok(None) => break,
                    Err(e) => {
                        // Classify for the log line: a peer reset (e.g. refused
                        // dial) and a dead connection need different follow-ups.
                        let kind = match &e {
                            quinn::ReadError::Reset(code) => format!("peer reset {code:?}"),
                            quinn::ReadError::ConnectionLost(_) => "connection lost".to_string(),
                            _ => "quic read failed".to_string(),
                        };
                        return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                            "quic>tcp {kind} after {total}B down: {e:#}"
                        ));
                    }
                };
                if n == 0 {
                    continue;
                }
                let mut batch_bytes = 0usize;
                for b in batch.iter().take(n) {
                    batch_bytes += b.len();
                }
                if batch_bytes == 0 {
                    continue;
                }
                if let Err(e) = write_batch_vectored(&mut tw, &batch[..n]).await {
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "quic>tcp tcp write failed after {total}B down: {e:#}"
                    ));
                }
                total += batch_bytes as u64;
                let now = b2.elapsed().as_millis() as u64;
                touch_stamp(&l2, &mut stamped, now, 100);
            }
            // QUIC-recv EOF: half-close the TCP write side now. Without
            // this FIN the peer waits for EOF while our own c2s direction
            // waits for the peer's FIN — a deadlock in which neither side
            // ever finishes and every cleanly-closed flow lingers until the
            // idle reap (or connection death), pinning its task, both
            // sockets and the stream-task permit. The TCP read side stays
            // open: c2s may still be forwarding, and its own EOF (after the
            // peer reacts to this FIN) completes the other half
            // symmetrically. A shutdown error means the peer is already
            // gone; the transfer itself is complete, so it is ignored and
            // the direction still reports Ok.
            tw.shutdown().await.ok();
            Ok::<u64, anyhow::Error>(total)
        };
        // Drive both directions manually instead of `join!`: when one direction
        // fails, returning from this function drops the other future immediately,
        // which closes its TCP half and resets/stops its QUIC stream. `join!` left
        // the other side blocked in `read()` until the 300 s idle deadline, so a
        // dead QUIC connection could pin the target fd and buffers for minutes.
        tokio::pin!(c2s);
        tokio::pin!(s2c);
        let mut c2s_total: Option<u64> = None;
        let mut s2c_total: Option<u64> = None;
        // Idle watchdog on a *fixed* cadence. The previous shape created a fresh
        // `sleep(step)` on every loop iteration, and any progress in either
        // direction re-entered the loop — so a busy stream registered and cancelled
        // a timer per data chunk (thousands per second). One pinned sleep that is
        // never re-created fixes the cadence: it is polled again after each transfer
        // event, and only the elapsed-time comparison decides when the deadline has
        // passed.
        // The unbounded `copy_tcp_quic` path passes u32::MAX seconds as
        // "no idle timeout": arming a 5s tick for it wakes every stream
        // forever for a check that can never fire.
        let idle_enabled = idle < Duration::from_secs(u32::MAX as u64 / 2);
        let idle_step = Duration::from_secs(5).min(idle);
        let idle_tick = tokio::time::sleep(idle_step);
        tokio::pin!(idle_tick);
        loop {
            tokio::select! {
                r = &mut c2s, if c2s_total.is_none() => match r {
                    Ok(v) => c2s_total = Some(v),
                    Err(e) => break Err(e),
                },
                r = &mut s2c, if s2c_total.is_none() => match r {
                    Ok(v) => s2c_total = Some(v),
                    Err(e) => break Err(e),
                },
                _ = &mut idle_tick, if idle_enabled => {
                    let elapsed_ms = base.elapsed().as_millis() as u64;
                    let last = last_ms.load(Ordering::Relaxed);
                    if elapsed_ms.saturating_sub(last) >= idle.as_millis() as u64 {
                        break Err(anyhow::anyhow!(
                            "tcp stream idle>{idle:?} after {}B up/{}B down",
                            c2s_total.unwrap_or(0),
                            s2c_total.unwrap_or(0),
                        ));
                    }
                    // Re-arm towards the same fixed cadence rather than from "now":
                    // a chunk arriving just before the deadline must not push the
                    // check another full step into the future.
                    idle_tick
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_step);
                }
            }
            if let (Some(a), Some(b)) = (c2s_total, s2c_total) {
                break Ok((a, b));
            }
        }
    }; // pump futures (and their borrows of `tcp`) end here
    match outcome {
        Ok((a, b)) => {
            // Both halves reached clean EOF: graceful FIN close.
            tcp.shutdown().await.ok();
            Ok((a, b))
        }
        Err(e) => {
            // Any abnormal end aborts with RST (see `abort_tcp`): a FIN here
            // would pose as a complete transfer and silently corrupt downloads.
            abort_tcp(tcp);
            Err(e)
        }
    }
}

/// Abort a TCP socket with RST instead of FIN.
///
/// Used exclusively for abnormal pump ends (see `copy_tcp_quic_inner`): a
/// graceful FIN would tell the application the transfer completed, turning a
/// truncated download into silent corruption (curl exits 0 on a short file).
/// SO_LINGER=0 makes the close emit RST, so the application sees an explicit
/// failure and can retry or resume (e.g. HTTP Range).
fn abort_tcp(tcp: tokio::net::TcpStream) {
    // `into_std` failure is not actionable here; worst case the socket closes
    // gracefully while the caller still reports the error.
    if let Ok(std) = tcp.into_std() {
        let _ = socket2::SockRef::from(&std).set_linger(Some(Duration::ZERO));
        // `std` drops here: linger 0 => RST.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry pool outlives the runtime that first needed it.
    ///
    /// Every shard's worker is a task, and a task dies with its runtime. The
    /// pool used to keep the `Sender` in a `OnceLock` forever, so once the first
    /// runtime ended, every later `WouldBlock` retry went into a queue nobody
    /// was draining: `try_send` returned `Closed`, the datagram was dropped, and
    /// the drop was charged to a "budget exhausted" counter that had not been
    /// touched. That is not hypothetical — it is why the client's loopback
    /// dispatcher tests failed *every* time they ran serially (one runtime per
    /// `#[tokio::test]`) and intermittently when they ran in parallel. A shard
    /// whose worker is gone has to be re-armed on the runtime that needs it.
    #[test]
    fn retry_shard_is_rearmed_after_its_runtime_ends() {
        // Runtime 1 initializes the pool, exactly as the first test that hits a
        // `WouldBlock` send does.
        let rt1 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt1.block_on(async {
            let _ = retry_shards();
        });
        drop(rt1);

        // Runtime 2 queues a retry through the same process-wide shard; the
        // datagram still has to come out.
        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let delivered = rt2.block_on(async {
            let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            listener
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let dst = listener.local_addr().unwrap();
            let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            assert!(
                udp_retry_submit(
                    &dst,
                    UdpRetry {
                        sock,
                        dst,
                        payload: Bytes::from_static(b"rearmed"),
                    },
                ),
                "a retry queued after the pool's runtime ended must still be accepted"
            );
            tokio::time::sleep(Duration::from_millis(600)).await;
            let mut b = [0u8; 64];
            listener.recv_from(&mut b).is_ok()
        });
        assert!(
            delivered,
            "the re-armed shard must actually send the datagram it accepted"
        );
    }

    /// The retry deadline is what bounds the socket's retention.
    ///
    /// A queued retry is the *last* strong owner of its `Arc<UdpSocket>` once the
    /// association (client relay) or session (server session socket) has dropped
    /// its own handle, and the worker used to await `send_to` with no deadline:
    /// a socket that never became writable pinned the fd — and on the server its
    /// 2 x 256 KiB kernel buffers — for the process lifetime, and parked the
    /// whole shard with it, so no later datagram hashing to that shard was ever
    /// retried. `pending()` stands in for that socket: the point is that the
    /// deadline, not the kernel, ends the wait. Real time (no `test-util`
    /// dependency), so the assertion is a generous upper bound around the
    /// deadline rather than an exact instant.
    #[tokio::test]
    async fn retry_deadline_bounds_a_never_writable_socket() {
        let start = tokio::time::Instant::now();
        assert!(
            under_retry_deadline(std::future::pending::<()>())
                .await
                .is_err(),
            "a send that never completes must be abandoned by the deadline"
        );
        let waited = start.elapsed();
        assert!(
            waited >= UDP_RETRY_TIMEOUT && waited < UDP_RETRY_TIMEOUT * 20,
            "the wait must be the deadline ({UDP_RETRY_TIMEOUT:?}), not open-ended: {waited:?}"
        );
        assert!(
            UDP_RETRY_TIMEOUT <= Duration::from_millis(500),
            "the retry deadline is a retention bound, not a retry policy"
        );
    }

    /// Clear this thread's memo so a test starts from a known state. The memo is
    /// thread-local, so tests running in parallel cannot disturb each other.
    fn memo_reset() {
        DNS_MEMO.with(|c| *c.borrow_mut() = [[DnsMemoSlot::EMPTY; MEMO_WAYS]; MEMO_SETS]);
    }

    #[test]
    fn dns_memo_set_is_stable_and_in_range() {
        for h in [0u64, 1, 0x9e37_79b9_7f4a_7c15, u64::MAX] {
            let set = dns_memo_set(h);
            assert!(set < MEMO_SETS, "set index {set} out of range");
            assert_eq!(set, dns_memo_set(h), "set index must be deterministic");
        }
    }

    /// A same-set collision must not resurrect the evicted key, and — the part
    /// that actually matters for correctness — must never serve the wrong
    /// address. The old direct-mapped version could not mis-serve either, so
    /// this locks in the property the associativity was allowed to change.
    #[test]
    fn dns_memo_two_ways_hold_two_keys_and_never_mis_serve() {
        memo_reset();
        // Find two keys in the same set, so both ways get used.
        let mut by_set: Vec<Vec<String>> = vec![Vec::new(); MEMO_SETS];
        for i in 0..4096 {
            let k = format!("host-{i}.example.com\0443");
            by_set[dns_memo_set(dns_memo_hash(&k))].push(k);
            if by_set.iter().any(|v| v.len() >= 3) {
                break;
            }
        }
        let trio = by_set
            .iter()
            .find(|v| v.len() >= 3)
            .expect("a set with three keys");
        let (a, b, c) = (&trio[0], &trio[1], &trio[2]);
        assert_eq!(
            dns_memo_set(dns_memo_hash(a)),
            dns_memo_set(dns_memo_hash(b)),
            "test premise: a and b share a set"
        );

        let addr_a: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(60);

        // Two keys, two ways: both must be resident at once.
        memo_put(a, Some(addr_a), far);
        memo_put(b, Some(addr_b), far);
        let (pa, na) = memo_peek_both(a);
        let (pb, nb) = memo_peek_both(b);
        assert_eq!(pa.expect("a resident").addr, Some(addr_a));
        assert_eq!(pb.expect("b resident").addr, Some(addr_b));
        assert!(na.is_none() && nb.is_none());

        // A third key in the same set evicts the least recently used, and the
        // surviving entry still answers with its own address.
        memo_put(c, Some("10.0.0.3:443".parse().unwrap()), far);
        let (pb2, _) = memo_peek_both(b);
        let (pa2, _) = memo_peek_both(a);
        assert_eq!(pb2.expect("b promoted, still resident").addr, Some(addr_b));
        assert!(
            pa2.is_none(),
            "a was the LRU victim and must not answer for b's set"
        );
        // The critical invariant: b never answers with a's address.
        assert_ne!(memo_peek_both(b).0.unwrap().addr, Some(addr_a));
    }

    /// Re-putting a resident key must update it in place rather than let one key
    /// occupy both ways of its set.
    #[test]
    fn dns_memo_reput_of_way_one_does_not_duplicate() {
        memo_reset();
        let mut by_set: Vec<Vec<String>> = vec![Vec::new(); MEMO_SETS];
        let mut trio = None;
        for i in 0..8192 {
            let k = format!("h{i}.example.net\0443");
            let set = dns_memo_set(dns_memo_hash(&k));
            by_set[set].push(k);
            if let Some(v) = by_set.iter().find(|v| v.len() >= 2) {
                if trio.is_none() {
                    trio = Some((v[0].clone(), v[1].clone()));
                }
            }
            if trio.is_some() {
                break;
            }
        }
        let (a, b) = trio.expect("a set with two keys");
        let far = Instant::now() + Duration::from_secs(60);

        memo_put(&a, Some("10.1.1.1:1".parse().unwrap()), far);
        memo_put(&b, Some("10.1.1.2:1".parse().unwrap()), far); // a demoted to way 1
                                                                // Re-put a (now in way 1) with a new address: it must promote, and b
                                                                // must survive in way 1.
        memo_put(&a, Some("10.1.1.9:1".parse().unwrap()), far);
        assert_eq!(
            memo_peek_both(&a).0.expect("a resident").addr,
            Some("10.1.1.9:1".parse().unwrap())
        );
        assert_eq!(
            memo_peek_both(&b).0.expect("b survived the promotion").addr,
            Some("10.1.1.2:1".parse().unwrap())
        );
    }

    /// A key too long for the inline slot must be a plain miss, never a match.
    #[test]
    fn dns_memo_ignores_keys_it_cannot_store() {
        memo_reset();
        let long = format!("{}\0443", "a".repeat(MEMO_KEY_BYTES));
        assert!(long.len() > MEMO_KEY_BYTES);
        memo_put(
            &long,
            Some("10.2.2.2:2".parse().unwrap()),
            Instant::now() + Duration::from_secs(60),
        );
        let (pos, neg) = memo_peek_both(&long);
        assert!(
            pos.is_none() && neg.is_none(),
            "long key must not be memoized"
        );
    }

    /// A negative entry must be distinguishable from a positive one and from a
    /// miss, because the caller uses that to skip spawning a resolver.
    #[test]
    fn dns_memo_negative_entries_are_separate_from_positive() {
        memo_reset();
        let k = "bad.example.com\080".to_string();
        memo_put(&k, None, Instant::now() + Duration::from_secs(10));
        let (pos, neg) = memo_peek_both(&k);
        assert!(pos.is_none(), "negative entry must not look positive");
        assert!(neg.expect("negative hit").addr.is_none());

        // Replacing it with a positive answer must flip the classification.
        memo_put(
            &k,
            Some("10.3.3.3:80".parse().unwrap()),
            Instant::now() + Duration::from_secs(60),
        );
        let (pos2, neg2) = memo_peek_both(&k);
        assert_eq!(
            pos2.expect("now positive").addr,
            Some("10.3.3.3:80".parse().unwrap())
        );
        assert!(neg2.is_none());
    }

    #[test]
    fn addr_roundtrip() {
        for a in [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 80),
        ] {
            let mut v = Vec::new();
            a.encode(&mut v).unwrap();
            let (b, n) = TargetAddr::decode(&v).unwrap();
            assert_eq!(n, v.len());
            assert_eq!(a, b);
        }
    }
    #[test]
    fn global_ip_filter_extended() {
        // RFC 2765 IPv4-translated addresses are judged by their embedded IPv4.
        assert!(!is_global_ip("::ffff:0:127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:10.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("::ffff:0:8.8.8.8".parse().unwrap()));
        // IPv4-mapped must not be affected by the translated-prefix check.
        assert!(is_global_ip("::ffff:8.8.8.8".parse().unwrap()));
        // Newly added IANA "not globally reachable" ranges.
        assert!(!is_global_ip("192.31.196.1".parse().unwrap()));
        assert!(!is_global_ip("192.52.193.1".parse().unwrap()));
        assert!(!is_global_ip("2001:1::1".parse().unwrap()));
        assert!(!is_global_ip("2001:3::1".parse().unwrap()));
        assert!(!is_global_ip("2001:4:112::1".parse().unwrap()));
        assert!(!is_global_ip("2001:30::1".parse().unwrap()));
        assert!(!is_global_ip("5f00::1".parse().unwrap()));
        assert!(!is_global_ip("2620:4f:8000::1".parse().unwrap()));
        // Still globally routable.
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn dns_key_normalizes_case_and_trailing_dot() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        assert_eq!(
            dns_key("Example.COM.", 443, &mut a).unwrap(),
            dns_key("example.com", 443, &mut b).unwrap()
        );
        assert_eq!(
            dns_key("example.com", 80, &mut a).unwrap(),
            "example.com\u{0}80"
        );
        // The owned fallback must normalize identically to the stack form.
        assert_eq!(
            dns_key_owned("Example.COM.", 443),
            dns_key("example.com", 443, &mut b).unwrap()
        );
    }

    #[test]
    fn dgram_send_buffer_always_fits_one_wire_datagram() {
        // `try_send_datagram` (and any use of `send_datagram_wait`) can only work
        // if the configured send buffer holds at least one maximum-size MQP-2
        // datagram; a smaller buffer would report Blocked forever. Checked at
        // compile time so editing the DATAGRAM budget fails the build loudly
        // instead of under load; `build_transport` asserts the same bound.
        const { assert!(MQP_DGRAM_MAX == 264, "MQP-2 datagram bound changed") };
        // The header bound has to fit QUIC's minimum path MTU (1200 B) so a
        // maximum-length domain header still leaves room for a payload.
        const { assert!(MQP_DGRAM_MAX < 1200, "MQP-2 header must fit a 1200 B path") };
        // The buffer bound is the largest body we can hand quinn, not the
        // header bound: the relays no longer clamp `max_datagram_size()`.
        const { assert!(DATAGRAM_BUFFER >= DGRAM_MAX_WIRE) };
        const { assert!(DGRAM_DEFAULT_LIMIT <= DGRAM_MAX_WIRE) };
    }

    /// Regression for the silent large-datagram loss: clamping the DATAGRAM
    /// budget is clamping the *payload* budget. With `max_datagram_size()`
    /// clamped to 1350 the usable UDP payload was 1338 B (v4) / 1326 B (v6)
    /// regardless of how much the path could carry, so a 1400 B DTLS record —
    /// which a direct UDP path delivers fine — vanished with no log line.
    #[test]
    fn dgram_payload_cap_tracks_the_live_limit_not_a_hard_cap() {
        let v4 = TargetAddrRef::Ip("1.2.3.4:443".parse().unwrap());
        let v6 = TargetAddrRef::Ip("[2001:db8::1]:443".parse().unwrap());
        let dom = TargetAddrRef::Domain("example.com", 443); // header = 4 + 11

        // Overheads: 5 B MQP prefix, then 7 B (v4) / 19 B (v6) address header.
        assert_eq!(dgram_payload_cap(1350, &v4), 1338); // the old ceiling
        assert_eq!(dgram_payload_cap(1448, &v4), 1436); // a 1472 B path now
        assert_eq!(dgram_payload_cap(1448, &v6), 1424);
        assert_eq!(dgram_payload_cap(1448, &dom), 1428);
        assert!(dgram_payload_cap(1448, &v4) > 1338, "the hard cap is gone");
        // QUIC's minimum path MTU is 1200 B, where `max_datagram_size()` is
        // ~1162: that must still leave room for a typical 1100 B UDP payload.
        assert!(dgram_payload_cap(1162, &v4) >= 1100);
        // Saturates instead of underflowing when even the header cannot fit.
        assert_eq!(dgram_payload_cap(4, &v4), 0);
        assert_eq!(dgram_payload_cap(0, &v6), 0);
    }

    /// The cap must agree with the encoder byte for byte, in both directions:
    /// a payload of exactly `cap` encodes, one byte more is rejected.
    #[test]
    fn dgram_payload_cap_matches_the_encoder() {
        let addrs = [
            (
                TargetAddrRef::Ip("1.2.3.4:443".parse().unwrap()),
                1350usize,
                1338usize,
            ),
            (
                TargetAddrRef::Ip("[2001:db8::1]:443".parse().unwrap()),
                1350,
                1326,
            ),
            (TargetAddrRef::Domain("example.com", 443), 1350, 1330), // header = 4 + 11
        ];
        for (addr, limit, expected) in addrs {
            let cap = dgram_payload_cap(limit, &addr);
            assert_eq!(cap, expected, "cap for {addr:?}");
            assert!(
                encode_datagram_ref_with_limit(1, &addr, &vec![0u8; cap], limit).is_some(),
                "payload of exactly cap must encode for {addr:?}"
            );
            assert!(
                encode_datagram_ref_with_limit(1, &addr, &vec![0u8; cap + 1], limit).is_none(),
                "one byte over cap must be rejected for {addr:?}"
            );
        }
    }

    /// Drops are counted, and `bump` is what moves the counters, so a relay
    /// cannot drop a datagram without it showing up in `snapshot()`.
    #[test]
    fn dgram_drop_counters_are_monotonic() {
        use std::sync::atomic::AtomicU64;
        let c = AtomicU64::new(0);
        assert_eq!(dgram_drops::bump(&c), 1);
        assert_eq!(dgram_drops::bump(&c), 2);

        // The process-wide snapshot must observe a bump on the real counter.
        // Other tests may bump concurrently, so assert a lower bound only.
        let before = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::TOO_LARGE);
        let after = dgram_drops::snapshot();
        assert!(
            after.too_large > before.too_large,
            "snapshot must observe the bump"
        );
    }

    /// Every drop counter must reach its own named field in the snapshot: the
    /// six-field struct exists so the 60 s report cannot silently omit one, and
    /// the batching table (`bump` + `flush_locals`) is keyed on identity, so a
    /// counter missing one of the two arms would sit in a thread-local cell
    /// forever. One bump per counter, one field asserted per counter.
    #[test]
    fn every_drop_counter_has_its_own_snapshot_field() {
        let before = dgram_drops::snapshot();
        for c in [
            &dgram_drops::TOO_LARGE,
            &dgram_drops::BUFFER_FULL,
            &dgram_drops::SESSION_FULL,
            &dgram_drops::DNS_INFLIGHT,
            &dgram_drops::NO_EGRESS,
            &dgram_drops::EGRESS_DEAD,
        ] {
            dgram_drops::bump(c);
        }
        let after = dgram_drops::snapshot();
        assert!(after.too_large > before.too_large, "too_large");
        assert!(after.buffer_full > before.buffer_full, "buffer_full");
        assert!(after.session_full > before.session_full, "session_full");
        assert!(after.dns_inflight > before.dns_inflight, "dns_inflight");
        assert!(after.no_egress > before.no_egress, "no_egress");
        assert!(after.egress_dead > before.egress_dead, "egress_dead");
        let d = after.since(&before);
        assert!(d.lost() >= 6, "every drop counts as loss: {d:?}");
    }

    /// The two egress counters must be visible **immediately and from another
    /// thread**, which is the whole reason they do not batch.
    ///
    /// Batching (four of the six counters) keeps the count in the bumping
    /// thread's cell until it reaches 64, and `snapshot` only flushes the thread
    /// it runs on — so a worker thread's short outage stays invisible until that
    /// thread drops 63 more, and a thread that exits takes its pending count with
    /// it. This test spawns exactly such a thread: with the egress counters
    /// batched, the spawned thread's cell dies with it and the delta below is
    /// zero, deterministically. Other tests only ever *add* to these counters, so
    /// the assertions are lower bounds and cannot flake.
    #[test]
    fn egress_drops_are_exact_across_threads() {
        let before = dgram_drops::snapshot();
        std::thread::spawn(|| {
            // One outage's worth of drops, on a thread that never reports and
            // never reaches the batching threshold.
            for _ in 0..20 {
                dgram_drops::bump(&dgram_drops::NO_EGRESS);
            }
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        })
        .join()
        .expect("the drop thread must not panic");

        let after = dgram_drops::snapshot();
        assert!(
            after.no_egress >= before.no_egress + 20,
            "a 20-datagram fail-closed outage must be in the next snapshot: {} -> {}",
            before.no_egress,
            after.no_egress
        );
        assert!(
            after.egress_dead > before.egress_dead,
            "a dead-egress drop must be in the next snapshot: {} -> {}",
            before.egress_dead,
            after.egress_dead
        );
        assert!(
            after.since(&before).lost() >= 21,
            "both egress states count as loss"
        );
    }

    /// The warn helper picks its rate-limit slot from the enum, so two different
    /// egress faults cannot share one 10 s window and silently swallow each
    /// other's first line.
    #[test]
    fn egress_drop_warnings_use_independent_slots() {
        // Both kinds emit on a fresh process (the first call always warns), and
        // calling them repeatedly is safe: the second call inside the interval is
        // suppressed rather than panicking or blocking.
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, 1, String::new);
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::ConnectionLost, 1, String::new);
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, 2, String::new);
    }

    /// The first drop must warn, and only then does the interval apply. A rate
    /// limiter that swallows the first event is useless precisely when a fresh
    /// deployment first shows the symptom.
    #[test]
    fn drop_warning_fires_once_then_rate_limits() {
        assert!(drop_warn_due(NEVER_WARNED, 0), "first drop always warns");
        assert!(
            !drop_warn_due(1_000, 1_000),
            "immediately after: suppressed"
        );
        assert!(!drop_warn_due(1_000, 10_999), "just inside the window");
        assert!(
            drop_warn_due(1_000, 11_000),
            "exactly at the interval: warns"
        );
        assert!(drop_warn_due(1_000, 99_999), "well past the interval");
        assert!(!drop_warn_due(5_000, 4_999), "clock regression: suppressed");
    }

    /// The slot is claimed exactly once per interval: the message (and its
    /// detail string) must be built by the winner only, or a drop flood makes
    /// logging itself the per-drop cost.
    #[test]
    fn warning_slot_is_claimed_once_per_interval() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let slot = AtomicU64::new(NEVER_WARNED);
        assert!(claim_drop_warning(&slot), "a never-warned slot claims");
        assert!(slot.load(Ordering::Relaxed) != NEVER_WARNED);
        assert!(
            !claim_drop_warning(&slot),
            "a second claim inside the window is refused"
        );
    }

    /// Encode `payload` the way [`DgramFragmenter`] does, for reassembler tests
    /// that need no connection. The limit is generous so only `chunk` splits.
    fn frag_frames(
        id: u16,
        sess: u32,
        addr: &TargetAddrRef<'_>,
        payload: &[u8],
        chunk: usize,
    ) -> Vec<Bytes> {
        let total = payload.len().div_ceil(chunk) as u8;
        payload
            .chunks(chunk)
            .enumerate()
            .map(|(i, part)| {
                encode_fragment(sess, id, i as u8, total, addr, part, 64 * 1024).unwrap()
            })
            .collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The `u8` fragment count must reach the UDP maximum even at QUIC's
    /// minimum path MTU, so raising `MQP_FRAG_MAX_PAYLOAD` later is a one-line
    /// change and never a wire-format change. (The same bound is asserted at
    /// compile time next to `MQP_FRAG_MAX_TOTAL`.)
    #[test]
    fn the_fragment_count_reaches_the_udp_maximum_at_the_minimum_mtu() {
        let min_chunk = MIN_PATH_DGRAM_BUDGET - FRAG_PREFIX_LEN - (1 + 16 + 2);
        assert_eq!(min_chunk, 1134, "1200 B path, IPv6 target");
        assert_eq!(UDP_PAYLOAD_MAX.div_ceil(min_chunk), 58);
        assert!(UDP_PAYLOAD_MAX.div_ceil(min_chunk) <= MQP_FRAG_MAX_TOTAL as usize);

        // A full Ethernet path needs fewer, but the worst case is what bounds it.
        let eth_chunk = 1434 - FRAG_PREFIX_LEN - (1 + 4 + 2);
        assert_eq!(eth_chunk, 1418);
        assert_eq!(UDP_PAYLOAD_MAX.div_ceil(eth_chunk), 47);
    }

    /// Why `MQP_FRAG_MAX_PAYLOAD` is 8 KiB and not the 65507 B UDP maximum:
    /// reassembly is all-or-nothing, so a payload's survival is `(1-p)^F` while
    /// its cost stays `F` fragments. Pinning the numbers here forces any future
    /// change to argue with them rather than re-derive them wrongly.
    #[test]
    fn fragment_count_documents_the_loss_amplification_tradeoff() {
        let chunk = 1434 - FRAG_PREFIX_LEN - (1 + 4 + 2); // IPv4 target, 1472 B path
        let frags = |payload: usize| payload.div_ceil(chunk);
        let survives = |f: usize, p: f64| (1.0 - p).powi(f as i32);

        assert_eq!(frags(1472), 2, "a full Ethernet payload");
        assert_eq!(frags(MQP_FRAG_MAX_PAYLOAD), 6, "the protocol cap");
        assert_eq!(frags(UDP_PAYLOAD_MAX), 47, "the UDP maximum");

        // At 1 % loss everything up to the cap still lands ~95 %+ of the time...
        assert!(survives(frags(MQP_FRAG_MAX_PAYLOAD), 0.01) > 0.94);
        // ...while a 64 KiB payload is a coin flip that costs 47x the bytes.
        assert!(survives(frags(UDP_PAYLOAD_MAX), 0.01) < 0.63);
        // At 5 % loss the UDP maximum is effectively undeliverable.
        assert!(survives(frags(UDP_PAYLOAD_MAX), 0.05) < 0.10);
    }

    #[test]
    fn udp_snapshot_differences_counters_but_not_the_high_water_mark() {
        let a = UdpSnapshot {
            datagrams: 100,
            bytes: 9_000,
            fragmented: 4,
            max_payload: 1_400,
            sessions: 2,
        };
        let b = UdpSnapshot {
            datagrams: 130,
            bytes: 12_000,
            fragmented: 6,
            max_payload: 1_900,
            sessions: 3,
        };
        let d = b.since(&a);
        assert_eq!(
            (d.datagrams, d.bytes, d.fragmented, d.sessions),
            (30, 3_000, 2, 1)
        );
        assert_eq!(d.max_payload, 1_900, "a maximum cannot be differenced");
        assert!(!d.is_idle());
        assert!(b.since(&b).is_idle(), "an empty interval stays quiet");
        // Saturating, so a snapshot taken out of order cannot wrap into an
        // absurd delta.
        assert_eq!(a.since(&b).datagrams, 0);
    }

    /// The dispatcher's rule, in one place. A frame type the router does not
    /// recognise must be skipped, but *both* relay frames carry `sess` at the
    /// same offset — switching on the type is what silently dropped every
    /// fragmented reply before the reassembler could see it.
    #[test]
    fn dgram_sess_routes_both_frame_types() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let plain = encode_datagram(7, &addr, b"x").unwrap();
        let frag = encode_fragment(9, 1, 0, 2, &addr.as_ref(), b"y", 4096).unwrap();
        assert_eq!(dgram_sess(&plain), Some(7));
        assert_eq!(dgram_sess(&frag), Some(9));
        assert_eq!(dgram_sess(&frag), dgram_sess(&plain).map(|_| 9));

        // Not relay frames: an address atyp, an unknown type, a runt.
        assert_eq!(dgram_sess(&[0x01, 0, 0, 0, 0, 0]), None);
        assert_eq!(dgram_sess(&[0x7f, 0, 0, 0, 0, 0]), None);
        assert_eq!(dgram_sess(&[MQP_DGRAM_FRAG, 0, 0]), None);
        assert_eq!(dgram_sess(&[]), None);
    }

    /// The counters must actually move, and `max_payload` must be a high-water
    /// mark rather than the most recent value — that is what makes it the
    /// empirical answer to "is the 8 KiB cap big enough here?".
    #[cfg(feature = "stats")]
    #[test]
    fn udp_stats_records_payloads_and_sessions() {
        // Other tests drive `DgramFragmenter::send` concurrently, so assert
        // lower bounds rather than exact deltas.
        let before = udp_stats::snapshot();
        udp_stats::payload(1_472);
        udp_stats::fragmented(3);
        udp_stats::fragmented(1); // unfragmented: must not count
        udp_stats::session();
        let after = udp_stats::snapshot();
        let d = after.since(&before);
        assert!(d.datagrams >= 1 && d.bytes >= 1_472);
        assert!(d.fragmented >= 1);
        assert!(d.sessions >= 1);
        assert!(after.max_payload >= 1_472);

        // A later *smaller* payload must not lower the mark.
        udp_stats::payload(64);
        assert!(udp_stats::snapshot().max_payload >= 1_472);
    }

    #[test]
    fn fragment_reassembly_is_order_independent() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let payload = pattern(5000);
        let frames = frag_frames(7, 3, &addr.as_ref(), &payload, 1400);
        assert_eq!(frames.len(), 4, "5000 B over 1400 B chunks");

        for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]] {
            let mut r = DgramReassembler::new();
            let mut done = None;
            for i in order {
                if let Some(x) = r.push(&decode_fragment(&frames[i]).unwrap(), 1_000) {
                    done = Some(x);
                }
            }
            let (sess, got_addr, whole) = done.expect("every fragment arrived");
            assert_eq!(sess, 3);
            assert_eq!(got_addr, addr);
            assert_eq!(&whole[..], &payload[..], "order {order:?} must reassemble");
            assert_eq!(r.inflight(), 0, "the partial is released on completion");
            assert_eq!(r.held_bytes(), 0);
        }
    }

    #[test]
    fn a_lost_fragment_never_yields_a_short_payload() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let payload = pattern(3000);
        let frames = frag_frames(1, 1, &addr.as_ref(), &payload, 1400);
        assert_eq!(frames.len(), 3);

        // UDP semantics: an incomplete datagram is discarded, never delivered
        // short — a short read is exactly what the old 1338 B cap looked like
        // to the application.
        for missing in 0..frames.len() {
            let mut r = DgramReassembler::new();
            let mut completed = 0;
            for (i, fr) in frames.iter().enumerate() {
                if i == missing {
                    continue;
                }
                if r.push(&decode_fragment(fr).unwrap(), 0).is_some() {
                    completed += 1;
                }
            }
            assert_eq!(completed, 0, "missing fragment {missing} must not complete");
        }

        // Duplicates within a partial are idempotent: a replayed fragment must
        // not advance the count, or three distinct fragments plus one replay
        // would "complete" a four-fragment datagram.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        assert!(
            r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none(),
            "a replayed fragment must not advance the count"
        );
        assert!(r.push(&decode_fragment(&frames[1]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&frames[2]).unwrap(), 0);
        let (_, _, w) = done.expect("completes once all three distinct fragments arrive");
        assert_eq!(w.len(), payload.len());
    }

    #[test]
    fn malformed_fragments_are_rejected_without_allocating_state() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(3000), 1400);
        let mut r = DgramReassembler::new();

        let mut f = decode_fragment(&frames[0]).unwrap();
        f.total = 1; // that is the single-frame form, not a fragment
        assert!(r.push(&f, 0).is_none());
        let mut f = decode_fragment(&frames[0]).unwrap();
        f.idx = 9; // index outside the declared count
        assert!(r.push(&f, 0).is_none());
        let mut f = decode_fragment(&frames[0]).unwrap();
        f.total = MQP_FRAG_MAX_TOTAL + 1;
        assert!(r.push(&f, 0).is_none());
        assert_eq!(
            r.inflight(),
            0,
            "a malformed fragment must not allocate state"
        );

        // A wrapped id reused with a different shape restarts rather than
        // splicing two unrelated datagrams together: 3000 B is 3 fragments,
        // 6000 B is 5, and the first two of the new shape must not complete
        // against the old count.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        let other = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 1400);
        assert_eq!(other.len(), 5);
        for fr in &other[1..4] {
            assert!(r.push(&decode_fragment(fr).unwrap(), 0).is_none());
        }
        assert!(r.push(&decode_fragment(&other[4]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&other[0]).unwrap(), 0);
        assert!(done.is_some(), "the restarted partial completes");
        assert_eq!(done.unwrap().2.len(), 6000);
    }

    #[test]
    fn partials_expire_and_reassembly_memory_is_bounded() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 6000 B over 4000 B chunks is exactly two fragments; a payload equal to
        // its chunk would be a one-fragment "fragment", which is malformed.
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        assert_eq!(frames.len(), 2);

        // A fragment arriving after the partial expired starts a new partial
        // instead of completing the stale one.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        assert_eq!(r.inflight(), 1);
        assert!(r
            .push(
                &decode_fragment(&frames[1]).unwrap(),
                FRAG_TIMEOUT_MS + 1_500
            )
            .is_none());
        assert_eq!(
            r.inflight(),
            1,
            "the stale partial was swept, a new one began"
        );

        // A flood of never-completing datagrams cannot grow memory without
        // bound: past FRAG_MAX_HELD_BYTES the oldest partial is evicted.
        let mut r = DgramReassembler::new();
        let (_, ev0) = udp_stats::reassembly_drops();
        // 7000 B over 4000 B chunks: two fragments, so the first push allocates
        // a partial (a payload equal to its chunk would be a one-fragment
        // "fragment", which the reassembler rightly refuses).
        let big_frames = frag_frames(1, 1, &addr.as_ref(), &pattern(7000), 4000);
        assert_eq!(big_frames.len(), 2);
        for id in 0..200u16 {
            let mut f = decode_fragment(&big_frames[0]).unwrap();
            f.id = id;
            assert!(r.push(&f, 0).is_none());
        }
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "held {} B exceeds the {FRAG_MAX_HELD_BYTES} B cap",
            r.held_bytes()
        );
        assert!(
            r.inflight() > 0 && r.inflight() < 200,
            "old partials were evicted"
        );
        #[cfg(feature = "stats")]
        assert!(
            udp_stats::reassembly_drops().1 > ev0,
            "an evicted partial must be counted"
        );
        #[cfg(not(feature = "stats"))]
        let _ = ev0;
    }

    #[test]
    fn partial_count_cap_bounds_slot_table_memory() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // Small first-fragment chunks (700 B): 306 of them hold ~214 KiB,
        // under FRAG_MAX_HELD_BYTES, so only the count cap can bind. (With
        // 4000 B chunks the byte cap binds first at ~65 partials, which is a
        // different bound than the one pinned here.)
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(7000), 700);
        assert_eq!(frames.len(), 10);
        let mut r = DgramReassembler::new();
        for id in 0..(FRAG_MAX_PARTIALS as u16 + 50) {
            let mut f = decode_fragment(&frames[0]).unwrap();
            f.id = id;
            assert!(r.push(&f, 0).is_none());
        }
        assert_eq!(
            r.inflight(),
            FRAG_MAX_PARTIALS,
            "inflight partials must never exceed the count cap"
        );
    }

    #[test]
    fn same_shape_id_reuse_restarts_instead_of_splicing() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let first = pattern(3000);
        let frames_a = frag_frames(9, 1, &addr.as_ref(), &first, 1400);
        assert_eq!(frames_a.len(), 3);
        let mut second = pattern(3000);
        second[0] ^= 0xff;
        assert_ne!(second, first);
        let frames_b = frag_frames(9, 1, &addr.as_ref(), &second, 1400);
        assert_eq!(frames_b.len(), 3);

        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames_a[0]).unwrap(), 0).is_none());
        assert!(r.push(&decode_fragment(&frames_a[1]).unwrap(), 0).is_none());
        // Same (sess, id, total, idx) with different bytes: a fast reuse, not
        // a replay. The old partial must be discarded, so the stale third
        // fragment of generation A no longer completes anything.
        assert!(r.push(&decode_fragment(&frames_b[0]).unwrap(), 0).is_none());
        assert!(r.push(&decode_fragment(&frames_a[2]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&frames_b[1]).unwrap(), 0);
        let (_, _, whole) = done.expect("generation B completes with its own fragments");
        assert_eq!(&whole[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn restart_releases_the_old_bytes_from_held() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(3000), 1400);
        let other = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 1400);
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        let held_before = r.held_bytes();
        assert!(held_before > 0);
        // Different shape forces a restart: held must drop the old bytes and
        // count only the new fragment, never accumulate both.
        assert!(r.push(&decode_fragment(&other[0]).unwrap(), 0).is_none());
        let f0 = decode_fragment(&other[0]).unwrap();
        assert_eq!(r.held_bytes(), f0.chunk.len());
    }

    /// Half-close propagation between two pumps: when the app shuts down its
    /// write side, the FIN must travel app -> QUIC -> peer TCP and back,
    /// instead of each pump waiting for a FIN only the final disposition
    /// would send. Pre-fix this test hung on every await: both pumps lingered
    /// until the 300 s idle reap, pinning tasks, sockets and stream-task
    /// permits per cleanly-closed flow — so the idle budget here is
    /// deliberately 300 s and every await above it is bounded by a 10 s
    /// timeout. (A single pump against a far end that unconditionally
    /// finishes cannot catch this: the deadlock needs a symmetric peer whose
    /// own TCP never closes first, exactly like a real echo target.)
    #[tokio::test]
    async fn half_close_propagates_and_the_pump_finishes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let a = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (b, _) = listener.accept().await.unwrap();
            (a, b)
        }

        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        // The far accept only resolves after the first STREAM frame arrives
        // (quinn requires a write before accept_bi fires), so pump1 must be
        // running and the app must send before awaiting the far end.
        let far_conn = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (s, r) = conn.accept_bi().await.unwrap();
            (conn, s, r)
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();

        // App <-> pump1 <-> QUIC <-> pump2 <-> echo socket E1; the test holds
        // E2 (peer's TCP read side) open until the FIN arrives, mimicking an
        // echo target that only closes on EOF.
        let (mut app, pump_tcp) = tcp_pair().await;
        let (echo_ours, mut echo_theirs) = tcp_pair().await;
        let pump1 = tokio::spawn(copy_tcp_quic_idle(
            pump_tcp,
            send,
            recv,
            Duration::from_secs(300),
        ));
        app.write_all(b"hello-half-close").await.unwrap();
        let (_far, far_send, far_recv) = tokio::time::timeout(Duration::from_secs(10), far_conn)
            .await
            .expect("far accept fires once the first STREAM frame arrives")
            .unwrap();
        let pump2 = tokio::spawn(copy_tcp_quic_idle(
            echo_ours,
            far_send,
            far_recv,
            Duration::from_secs(300),
        ));
        app.shutdown().await.unwrap();
        // The full 16 B must still arrive before any FIN: shutdown propagation
        // must not truncate in-flight data.
        let mut got = vec![0u8; 16];
        tokio::time::timeout(Duration::from_secs(10), echo_theirs.read_exact(&mut got))
            .await
            .expect("echo side must receive the payload")
            .unwrap();
        assert_eq!(got, b"hello-half-close");
        // Far pump's s2c saw QUIC EOF and must have half-closed E1: without
        // propagation this EOF never arrives.
        let mut one = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(10), echo_theirs.read(&mut one))
            .await
            .expect("echo side must observe EOF promptly");
        assert_eq!(n.unwrap(), 0, "echo side must observe EOF");
        drop(echo_theirs);
        // E2's close EOFs pump2's c2s, which finishes its QUIC send; pump1's
        // s2c then EOFs and half-closes the app socket.
        let n = tokio::time::timeout(Duration::from_secs(10), app.read(&mut one))
            .await
            .expect("app must observe EOF promptly");
        assert_eq!(n.unwrap(), 0, "app must observe EOF, not data or reset");
        // Both pumps must finish on their own rather than at the idle reap.
        let (up, down) = tokio::time::timeout(Duration::from_secs(10), pump1)
            .await
            .expect("pump1 must finish without the idle reap")
            .unwrap()
            .expect("pump1 must end clean");
        assert_eq!((up, down), (16, 0));
        let (up, down) = tokio::time::timeout(Duration::from_secs(10), pump2)
            .await
            .expect("pump2 must finish without the idle reap")
            .unwrap()
            .expect("pump2 must end clean");
        assert_eq!((up, down), (0, 16));
    }

    /// End to end over a real connection: every size up to the protocol cap
    /// arrives whole, and the frame counts prove the split actually happened.
    #[tokio::test]
    async fn fragmentation_round_trips_large_udp_payloads() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let target = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        let sizes = [1usize, 1400, 3000, MQP_FRAG_MAX_PAYLOAD];
        let expected: Vec<Vec<u8>> = sizes.iter().map(|n| pattern(*n)).collect();

        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let mut reasm = DgramReassembler::new();
            let mut out: Vec<(u32, TargetAddr, Bytes)> = Vec::new();
            while let Ok(d) = conn.read_datagram().await {
                if d.first() == Some(&MQP_DGRAM_FRAG) {
                    let Ok(f) = decode_fragment(&d) else { continue };
                    if let Some(x) = reasm.push(&f, mono_millis()) {
                        out.push(x);
                    }
                } else {
                    let Ok((s, a, p)) = decode_datagram_ref(&d) else {
                        continue;
                    };
                    out.push((s, a.into_owned(), Bytes::copy_from_slice(p)));
                }
            }
            out
        });

        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let limit = conn.max_datagram_size().unwrap();
        let cap = dgram_payload_cap(limit, &target.as_ref());
        assert!(cap > 0);
        let mut frag = DgramFragmenter::new();
        let mut frames = 0u8;
        for (i, payload) in expected.iter().enumerate() {
            let r = frag.send(&conn, i as u32, &target.as_ref(), payload, limit);
            assert!(
                r.complete(),
                "{} B send failed: {:?}",
                payload.len(),
                r.failed
            );
            assert_eq!(r.fragmented(), payload.len() > cap);
            frames = frames.saturating_add(r.frames);
        }
        assert!(
            frames > expected.len() as u8,
            "at least one payload must have been split"
        );

        // Above the protocol cap the payload is refused outright rather than
        // silently truncated by the reassembler.
        let too_big = pattern(MQP_FRAG_MAX_PAYLOAD + 1);
        let r = frag.send(&conn, 99, &target.as_ref(), &too_big, limit);
        assert_eq!(r.failed, Some(DatagramSend::TooLarge));
        assert_eq!(r.frames, 0);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        conn.close(0u32.into(), b"done");
        let got = accept.await.unwrap();
        assert_eq!(
            got.len(),
            expected.len(),
            "every payload arrives exactly once"
        );
        for (i, (sess, addr, payload)) in got.iter().enumerate() {
            assert_eq!(*sess, i as u32);
            assert_eq!(*addr, target);
            assert_eq!(&payload[..], &expected[i][..], "payload {i} mismatch");
        }
    }

    #[test]
    fn dgram_encoder_never_exceeds_the_wire_bound() {
        // The longest encodable datagram: a 255-byte domain, vs the constant
        // used for the send-buffer invariant.
        let longest = TargetAddr::Domain("a".repeat(255), u16::MAX);
        let d = encode_datagram_with_limit(0, &longest, &[0u8; 1350], 4096).unwrap();
        assert_eq!(d.len(), MQP_DGRAM_MAX + 1350);
    }

    /// The single-allocation encoder must produce byte-identical output to the
    /// straightforward `header()` + `encode()` pair for every address form, and
    /// must reject exactly the same addresses.
    #[test]
    fn dgram_encoder_matches_the_reference_encoding() {
        let addrs = [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:4860:4860::8888]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 8443),
            TargetAddr::Domain("a".repeat(255), 1),
        ];
        for a in &addrs {
            let got = encode_datagram_ref_with_limit(7, &a.as_ref(), b"payload", 4096).unwrap();
            // Reference: build the same body by hand from `header()`.
            let mut want = Vec::new();
            want.push(MQP_DGRAM_TYPE);
            want.extend_from_slice(&7u32.to_le_bytes());
            let h = a.as_ref().header().unwrap();
            h.encode(&mut want).unwrap();
            assert_eq!(h.len(), want.len() - DGRAM_PREFIX_LEN);
            want.extend_from_slice(b"payload");
            assert_eq!(&got[..], &want[..], "wire form changed for {a:?}");
        }
        // Rejections must match too: a scoped v6 address (scope_id != 0) is
        // refused by the header validation exactly as `encode` refuses it.
        let scoped = TargetAddrRef::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1,
            0,
            3, // scope_id
        )));
        assert!(scoped.header().is_err());
        assert!(scoped.encode(&mut Vec::new()).is_err());
        assert!(encode_datagram_ref_with_limit(0, &scoped, b"x", 4096).is_none());
    }

    /// The ACK's bound-address encoder must agree with the `Vec` form it
    /// replaces, for both address families.
    #[test]
    fn bnd_addr_into_matches_the_vec_encoder() {
        for a in [
            "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            "192.0.2.7:65535".parse().unwrap(),
            "[::]:0".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let mut v = Vec::new();
            encode_bnd_addr(a, &mut v);
            let mut buf = [0u8; MAX_BND_LEN];
            let n = encode_bnd_addr_into(a, &mut buf);
            assert_eq!(n, v.len(), "length mismatch for {a}");
            assert_eq!(&buf[..n], &v[..], "encoding mismatch for {a}");
        }
    }

    /// The fixed-buffer header encoder must be byte-identical to the `Vec` one
    /// for every address form: the client writes the TCP-open header from a
    /// stack buffer on the hot path, so a divergence here would misparse every
    /// target.
    #[test]
    fn addr_header_into_matches_the_vec_encoder() {
        for a in [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 8443),
            TargetAddr::Domain("a".repeat(255), 65535),
        ] {
            let mut v = Vec::new();
            a.encode(&mut v).unwrap();
            let header = a.as_ref().header().unwrap();
            assert_eq!(header.len(), v.len(), "measured length for {a:?}");
            let mut buf = [0u8; AddrHeader::MAX_LEN];
            let n = header.encode_into(&mut buf);
            assert_eq!(n, v.len(), "encoded length for {a:?}");
            assert_eq!(&buf[..n], &v[..], "encoding mismatch for {a:?}");
        }
    }

    /// The pump's read path depends on this invariant: a `read_buf` into a full
    /// `BytesMut` would only ever read 64 B, so the reserve helper must always
    /// leave a whole chunk of headroom, including after a zero-copy split that
    /// hands the buffer's front to quinn.
    #[test]
    fn reserve_copy_chunk_always_leaves_a_full_chunk_of_room() {
        let mut buf = BytesMut::with_capacity(COPY_CHUNK);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);

        buf.extend_from_slice(&[0u8; COPY_CHUNK]);
        reserve_copy_chunk(&mut buf);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);

        // A zero-copy handover leaves the tail sharing the allocation; the
        // helper must still find (or make) a whole chunk of room.
        let taken = buf.split_to(buf.len()).freeze();
        assert_eq!(taken.len(), COPY_CHUNK);
        reserve_copy_chunk(&mut buf);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);
        assert_eq!(buf.len(), 0);

        // And a small whole buffer must grow rather than settle for 64 B.
        let mut tiny = BytesMut::with_capacity(8);
        tiny.extend_from_slice(b"12345678");
        reserve_copy_chunk(&mut tiny);
        assert!(tiny.capacity() - tiny.len() >= COPY_CHUNK);
    }

    #[test]
    fn dgram_roundtrip() {
        let a = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let d = encode_datagram(7, &a, b"hello").unwrap();
        let (s, a2, p) = decode_datagram(&d).unwrap();
        assert_eq!(s, 7);
        assert_eq!(a, a2);
        assert_eq!(p, b"hello");
    }
    #[test]
    fn dgram_ref_roundtrip() {
        let a = TargetAddr::Domain("example.com".into(), 443);
        let d = encode_datagram(9, &a, b"x").unwrap();
        let (s, aref, p) = decode_datagram_ref(&d).unwrap();
        assert_eq!(s, 9);
        assert_eq!(aref, TargetAddrRef::Domain("example.com", 443));
        assert_eq!(aref.into_owned(), a);
        assert_eq!(p, b"x");
    }
    #[test]
    fn global_ip_filter() {
        // NAT64 well-known prefix: the embedded IPv4 decides.
        assert!(!is_global_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("64:ff9b::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        // Deprecated IPv4-compatible form is validated via its embedded IPv4.
        assert!(!is_global_ip("::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("::8.8.8.8".parse().unwrap()));
        // IPv4-mapped unchanged.
        assert!(!is_global_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("8.8.8.8".parse().unwrap()));
        // Newly covered documentation/benchmark prefixes.
        assert!(!is_global_ip("2001:2::1".parse().unwrap()));
        assert!(!is_global_ip("3fff::1".parse().unwrap()));
        // ORCHIDv1/v2 + AS112.
        assert!(!is_global_ip("2001:10::1".parse().unwrap()));
        assert!(!is_global_ip("2001:20::1".parse().unwrap()));
        assert!(!is_global_ip("192.175.48.1".parse().unwrap()));
        assert!(is_global_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn dns_key_is_injective() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        let k1 = dns_key("example.com", 443, &mut a).unwrap();
        let k2 = dns_key("example.com", 80, &mut b).unwrap();
        assert_ne!(k1, k2);
        // A host containing the separator is still unambiguous: the split is
        // always at the last NUL, which the decimal port can never contain.
        let mut c = [0u8; DNS_KEY_BUF];
        let k3 = dns_key("a\0b", 1, &mut c).unwrap();
        assert_eq!(k3, "a\u{0}b\u{0}1");
        assert_eq!(dns_key("same", 1, &mut a).unwrap(), "same\u{0}1");
    }

    #[test]
    fn dns_shards_split_keys_and_preserve_total_caps() {
        assert_eq!(DNS_SHARDS, 16);
        assert_eq!(DNS_CACHE_MAX_SHARD * DNS_SHARDS, DNS_CACHE_MAX);
        assert_eq!(DNS_NEG_MAX_SHARD * DNS_SHARDS, DNS_NEG_MAX);
        // Deterministic: the same key always lands on the same shard, or
        // single-flight/warming would address a different lock than the lookup.
        let mut a = [0u8; DNS_KEY_BUF];
        let k = dns_key("example.com", 443, &mut a).unwrap().to_owned();
        assert_eq!(dns_shard(&k), dns_shard(&k));
        assert_eq!(dns_cache_for(&k) as *const _, dns_cache_for(&k) as *const _);
        // Spreading: distinct names must cover multiple shards, or the
        // sharding pays code without removing the single-lock contention.
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let h = format!("host{i}.example.com");
            let mut b = [0u8; DNS_KEY_BUF];
            let kk = dns_key(&h, 80, &mut b).unwrap().to_owned();
            seen.insert(dns_shard(&kk));
        }
        assert!(seen.len() > 1, "sharding must spread keys, got {seen:?}");
    }

    /// Live regression test for the quinn-proto datagram accounting.
    ///
    /// Saturation runs the send path that used to reach quinn's broken
    /// `datagrams.outgoing.payload_bytes` bookkeeping. With `try_send_datagram`
    /// a full buffer must surface as `Blocked` (the datagram is dropped) and
    /// must never panic; on quinn-proto 0.11.17 this test aborted the whole
    /// process with `datagrams.outgoing.payload_bytes desynchronized`. The
    /// underflow is fixed upstream, so the test now guards against a regression
    /// in that accounting.
    /// Loopback QUIC endpoint pair sharing the production transport config.
    /// Lives at module scope so both the send-buffer and fragmentation
    /// tests drive a real connection instead of a mock.
    async fn endpoint_pair() -> (quinn::Endpoint, quinn::Endpoint) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        scfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(scfg).unwrap();
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        server_cfg.transport_config(build_transport("bbr", 5));
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();

        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates({
                let mut r = rustls::RootCertStore::empty();
                r.add(cert.der().clone()).unwrap();
                r
            })
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(ccfg).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport("bbr", 5));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);
        (client, server)
    }

    #[tokio::test]
    async fn try_send_datagram_saturates_without_panicking() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        // The peer must complete the handshake; its datagram queue is never read,
        // which is what eventually fills our send buffer.
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();
        assert!(
            conn.max_datagram_size().unwrap() >= 1024,
            "loopback must allow ~1 KiB datagrams"
        );

        let payload: Bytes = Bytes::from(vec![0u8; 1024]);
        let mut sent = 0usize;
        let mut blocked = 0usize;
        // Far more than the 1 MiB send buffer can hold.
        for _ in 0..64 * 1024 {
            match try_send_datagram(&conn, payload.clone()) {
                DatagramSend::Sent => sent += 1,
                DatagramSend::Blocked => blocked += 1,
                other => panic!("unexpected datagram send result: {other:?}"),
            }
        }
        assert!(sent > 0, "at least some datagrams must be queued");
        assert!(
            blocked > 0,
            "the send buffer must saturate within 64k x 1 KiB sends"
        );
    }

    /// P1 residue pin: hammering the `Blocked` path (each hit polls
    /// `send_datagram_wait` once and drops the future) must leave the
    /// endpoint/connection fully usable. A leaked waiter would wedge the
    /// `datagrams_unblocked` notify queue and a leaked byte count would corrupt
    /// the send-buffer accounting, either of which shows up here as a wedged
    /// or unusable fresh connection on the same endpoint.
    #[tokio::test]
    async fn cancelled_datagram_waits_leave_no_residue() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let mut v = Vec::new();
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                v.push(incoming.accept().unwrap().await.unwrap());
            }
            v
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let payload: Bytes = Bytes::from(vec![0u8; 1024]);
        let mut blocked = 0usize;
        for _ in 0..16 * 1024 {
            match try_send_datagram(&conn, payload.clone()) {
                DatagramSend::Sent => {}
                DatagramSend::Blocked => blocked += 1,
                other => panic!("unexpected datagram send result: {other:?}"),
            }
        }
        assert!(
            blocked > 0,
            "must hit Blocked to exercise future cancellation"
        );
        assert!(conn.close_reason().is_none());
        assert!(conn.max_datagram_size().is_some());
        // Same endpoint, fresh connection: unaffected by the abandoned waiters.
        let conn2 = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _server_conns = accept.await.unwrap();
        let mut sent = 0usize;
        for _ in 0..16 {
            match try_send_datagram(&conn2, payload.clone()) {
                DatagramSend::Sent => sent += 1,
                DatagramSend::Blocked => break,
                other => panic!("fresh connection unexpected: {other:?}"),
            }
        }
        assert!(sent > 0, "fresh connection must still send");
    }

    #[tokio::test]
    async fn tcp_open_header_arrives_without_app_data() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut recv = conn.accept_bi().await.unwrap().1;
            let mut hdr = [0u8; 7];
            recv.read_exact(&mut hdr).await.unwrap();
            TargetAddr::decode(&hdr).unwrap().0
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let target = TargetAddr::Ip("93.184.216.34:80".parse().unwrap());
        let mut hdr = Vec::new();
        target.encode(&mut hdr).unwrap();
        send.write_all(&hdr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .expect("open header must arrive even when the app never sends")
            .unwrap();
        assert_eq!(got, target);
    }

    #[test]
    fn alpn_override_parses_and_defaults() {
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(base).unwrap();
        assert_eq!(c.alpn_bytes(), b"h3");
        let c2: ClientConf = toml::from_str(&format!("{base}alpn = 'myquic2/2'\n")).unwrap();
        assert_eq!(c2.alpn_bytes(), MQP_ALPN);
        assert_eq!(normalize_alpn(Some("")), b"h3");
        assert_eq!(normalize_alpn(None), b"h3");
        assert_eq!(normalize_alpn(Some("h3")), b"h3");
    }

    #[test]
    fn tuning_defaults_are_low_latency() {
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(base).unwrap();
        let t = c.tuning();
        assert_eq!(t.stream_receive_window, 2 * 1024 * 1024);
        assert_eq!(t.receive_window, 4 * 1024 * 1024);
        assert_eq!(t.send_window, 2 * 1024 * 1024);
        assert_eq!(t.ack_threshold, 2);
        assert_eq!(t.max_ack_delay, Duration::from_millis(5));
        assert_eq!(c.conn_count(), 4, "pool default is four connections");
        assert_eq!(DEFAULT_QUIC_CONNS, 4);
        let conf =
            |extra: &str| -> ClientConf { toml::from_str(&format!("{base}{extra}")).unwrap() };
        assert_eq!(conf("quic_conns = 1\n").conn_count(), 1);
        assert_eq!(conf("quic_conns = 3\n").conn_count(), 3);
        assert_eq!(conf("quic_conns = 0\n").conn_count(), 1, "clamped up");
        assert_eq!(
            conf("quic_conns = 999\n").conn_count(),
            MAX_POOL_CONNS,
            "a config typo cannot spawn an unbounded dial loop"
        );
    }

    /// Window sizing invariant: every flow-control window must clear the BDP of
    /// the link this build targets, or it -- not BBR's congestion window --
    /// becomes the single-stream throughput ceiling.
    ///
    /// This is a constants check rather than a live measurement on purpose.
    /// quinn exposes no window getters, and a loopback connection cannot detect
    /// the regression it guards against: with a 2MB window the cushion is still
    /// 1MB, which at a ~0.2ms loopback RTT is worth ~40Gb/s. Verified by
    /// reverting `STREAM_RECEIVE_WINDOW` to 2MB -- the live variant of this test
    /// passed. Only the constants carry the invariant, so only they are tested.
    #[test]
    fn tcp_windows_cover_the_300mb_s_bdp() {
        // Relations between constants are asserted at compile time, so a future
        // edit that re-tightens a window fails the build rather than only a WAN
        // measurement. Panic messages cannot be formatted in const context, so
        // each relation gets its own const block and the comments carry intent.
        //
        // `STREAM_RECEIVE_WINDOW` is the receiver-side advertisement, so it caps
        // a *download*; `SEND_WINDOW` caps the write side of an *upload*.
        const _: () = assert!(TARGET_LINK_RTT.as_millis() == 140);
        const _: () = assert!(TARGET_BDP_BYTES == 5_250_000);
        const _: () = assert!(STREAM_RECEIVE_WINDOW >= TARGET_BDP_BYTES);
        const _: () = assert!(SEND_WINDOW >= TARGET_BDP_BYTES);
        // The stream window is only useful if it still clears the BDP after the
        // cushion quinn withholds (`window / 8`) before announcing an update.
        const _: () = assert!(STREAM_RECEIVE_WINDOW - STREAM_RECEIVE_WINDOW / 8 > TARGET_BDP_BYTES);
        // The aggregate window must cover more than one stream's BDP, or a
        // single stream would exhaust the connection-level budget.
        const _: () = assert!(RECEIVE_WINDOW >= 2 * TARGET_BDP_BYTES);
        // Regression guards: these two are what capped single-stream at ~120Mb/s
        // (receive) and ~240Mb/s (send) at 140ms before the 2026-09 re-tuning.
        const _: () = assert!(STREAM_RECEIVE_WINDOW > 2 * 1024 * 1024);
        const _: () = assert!(SEND_WINDOW > 4 * 1024 * 1024);
        // Implied single-stream ceiling for the target RTT, in Mb/s.
        const _: () = assert!(STREAM_RECEIVE_WINDOW * 8 / 140 * 1000 / 1_000_000 >= 300);
    }
}
