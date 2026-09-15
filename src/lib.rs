//! MyQUIC2 common: MQP-2 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

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
    /// Wire length of `addr` (`atyp | addr | port`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
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

/// ALPN identifier. Bumped to `/2` together with the MQP-2 TCP-open ACK
/// (status byte + bound address); a version-skewed peer now fails the TLS
/// handshake with a clear error instead of misparsing the ACK as app data.
pub const MQP_ALPN: &[u8] = b"myquic2/2";

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
    let total = DGRAM_PREFIX_LEN + header.len() + payload.len();
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(MQP_DGRAM_TYPE);
    v.extend_from_slice(&sess.to_le_bytes());
    header.encode(&mut v).ok()?;
    debug_assert_eq!(v.len(), DGRAM_PREFIX_LEN + header.len());
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
    header.encode(&mut v).ok()?;
    debug_assert_eq!(v.len(), FRAG_PREFIX_LEN + header.len());
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
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
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
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pinned)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
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
        u32::try_from(STREAM_RECEIVE_WINDOW).expect("stream window fits a VarInt"),
    ));
    t.receive_window(quinn::VarInt::from_u32(
        u32::try_from(RECEIVE_WINDOW).expect("connection window fits a VarInt"),
    ));
    t.send_window(SEND_WINDOW);
    // ACK frequency (draft-ietf-quic-ack-frequency): this is what we *request
    // the peer to use* when we are the receiver, so it bounds the reverse-path
    // ACK rate. quinn's default (threshold 1) ACKs every other packet: at
    // 300Mb/s that is ~14k ACK/s for a single stream, all of it paid for by
    // the one writer thread. 8 cuts that 8x while max_ack_delay = 10ms keeps
    // BBR's bandwidth estimate and loss detection sharp; >=32 makes the
    // estimate too coarse and slows the startup ramp. reordering_threshold
    // stays at quinn's recommended packet_threshold - 1 = 2.
    let mut ack_freq = quinn::AckFrequencyConfig::default();
    ack_freq
        .ack_eliciting_threshold(quinn::VarInt::from_u32(8))
        .max_ack_delay(Some(Duration::from_millis(10)))
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

fn dns_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>> {
    static CACHE: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_NEG_TTL: Duration = Duration::from_secs(10);
/// Soft cap for the negative cache; past this the table is reaped instead of
/// growing without bound under a failing-domain flood.
const DNS_NEG_MAX: usize = 4096;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn dns_neg_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, Instant>> {
    static NEG: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, Instant>>> =
        std::sync::OnceLock::new();
    NEG.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
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
        let mut inf = lock_mutex(dns_inflight());
        if let Some(cur) = inf.get(&self.entry.key) {
            if Arc::ptr_eq(cur, self.entry) {
                inf.remove(&self.entry.key);
            }
        }
    }
}

fn dns_inflight() -> &'static std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>> {
    static INF: std::sync::OnceLock<std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>>> =
        std::sync::OnceLock::new();
    INF.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1024)))
}

pub fn mono_millis() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// Thread-local memo of the most recent lookups, keyed by the *full* normalized
/// key. A 64-bit hash here would let two different `(host, port)` pairs collide
/// and serve each other's address for the whole TTL, so the key is compared
/// byte-for-byte. Storing it inline keeps fast-path hits allocation-free.
struct DnsMemo {
    key: [u8; DNS_KEY_BUF],
    len: usize,
    /// `None` = negatively cached (NXDOMAIN / lookup failure).
    addr: Option<SocketAddr>,
    expires: Instant,
}

/// Positive and negative memos are kept in separate slots on purpose: an
/// interleaved stream of good and bad names on the same worker thread would
/// otherwise evict the other class on every single packet, and a negative hit
/// that falls through costs a global `RwLock` read per packet — precisely the
/// flood the negative cache exists to absorb.
const MEMO_SLOTS: usize = 2;

thread_local! {
    static DNS_MEMO: std::cell::RefCell<[Option<DnsMemo>; MEMO_SLOTS]> =
        const { std::cell::RefCell::new([None, None]) };
}

/// A matching memo slot, copied out so the borrow of the thread-local ends with
/// the call.
#[derive(Clone, Copy)]
struct MemoHit {
    addr: Option<SocketAddr>,
    expires: Instant,
}

/// Peek the memo slot that caches positive (`neg == false`) or negative
/// results, but only if it holds our key. Deliberately does *not* read the
/// clock: the caller reads it once, and only after a key match, so a memo miss
/// is never charged a `clock_gettime` — the whole point of the memo is that a
/// hit is cheaper than the global cache lookup, and a miss must not cost more
/// than one.
fn memo_peek(key: &str, neg: bool) -> Option<MemoHit> {
    let slot = usize::from(neg);
    DNS_MEMO.with(|c| {
        let c = c.borrow();
        match c[slot].as_ref() {
            Some(m) if &m.key[..m.len] == key.as_bytes() => Some(MemoHit {
                addr: m.addr,
                expires: m.expires,
            }),
            _ => None,
        }
    })
}

fn memo_put(key: &str, addr: Option<SocketAddr>, expires: Instant) {
    let kb = key.as_bytes();
    if kb.len() > DNS_KEY_BUF {
        return; // only reachable through the owned fallback for >255-byte names
    }
    DNS_MEMO.with(|c| {
        let slot = usize::from(addr.is_none());
        let mut m = DnsMemo {
            key: [0u8; DNS_KEY_BUF],
            len: kb.len(),
            addr,
            expires,
        };
        m.key[..kb.len()].copy_from_slice(kb);
        c.borrow_mut()[slot] = Some(m);
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
    let pos = memo_peek(key, false);
    let neg = memo_peek(key, true);
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
        let m = lock_read(dns_cache());
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
        let n = lock_read(dns_neg_cache());
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
    const SLACK: usize = 512;
    if m.len() <= DNS_CACHE_MAX + SLACK {
        return;
    }
    let over = m.len().saturating_sub(DNS_CACHE_MAX);
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
    // 1. Positive cache.
    {
        let m = lock_read(dns_cache());
        if let Some((t, v)) = m.get(key) {
            if t.elapsed() < DNS_CACHE_TTL {
                return Ok(v.clone());
            }
        }
    }
    // 2. Negative cache.
    {
        let n = lock_read(dns_neg_cache());
        if let Some(t) = n.get(key) {
            if t.elapsed() < DNS_NEG_TTL {
                anyhow::bail!("dns negative cached");
            }
        }
    }
    // 3. Singleflight: exactly one owner resolves; everyone else waits on the
    //    cell. Ownership is claimed atomically. If the owner is cancelled or
    //    panics, `OwnerReset` clears the claim and wakes the waiters; the next
    //    waiter re-claims it, so no waiter can sleep forever on a cell that
    //    nobody will ever fill.
    let entry = {
        let mut inf = lock_mutex(dns_inflight());
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
            // The owner died without publishing; re-enter and try to take over.
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
        let m = lock_read(dns_cache());
        if let Some((t, v)) = m.get(key) {
            if t.elapsed() < DNS_CACHE_TTL {
                return Ok(v.clone());
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
                let mut m = lock_write(dns_cache());
                m.insert(key.to_owned(), (now, v.clone()));
                evict_if_needed(&mut m);
            }
            lock_write(dns_neg_cache()).remove(key);
            if let Some(a) = v.first().copied() {
                memo_put(key, Some(a), now + DNS_CACHE_TTL);
            }
        }
        Err(_) => {
            {
                let mut n = lock_write(dns_neg_cache());
                // Bounded hold: evict one arbitrary entry instead of a full
                // O(n) `retain` scan under the write lock. Expired entries
                // are already treated as misses by the TTL check on read,
                // so eager reaping buys nothing while stalling every packet
                // path reader during a failing-domain flood.
                if n.len() >= DNS_NEG_MAX {
                    if let Some(k) = n.keys().next().cloned() {
                        n.remove(&k);
                    }
                }
                if n.len() < DNS_NEG_MAX {
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

    /// `(too_large, buffer_full)` totals since process start.
    pub fn snapshot() -> (u64, u64) {
        (
            TOO_LARGE.load(Ordering::Relaxed),
            BUFFER_FULL.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
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

    /// One relayed UDP payload of `len` bytes.
    pub fn payload(len: usize) {
        DATAGRAMS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(len as u64, Ordering::Relaxed);
        MAX_PAYLOAD.fetch_max(len as u64, Ordering::Relaxed);
    }

    /// One payload that needed `frames` frames to carry.
    pub fn fragmented(frames: u8) {
        if frames > 1 {
            FRAGMENTED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A new UDP session (server) or SOCKS association (client) was established.
    pub fn session() {
        SESSIONS.fetch_add(1, Ordering::Relaxed);
    }

    /// A partial datagram was discarded because a fragment never arrived.
    pub fn reassembly_expired() {
        REASSEMBLY_EXPIRED.fetch_add(1, Ordering::Relaxed);
    }

    /// A partial datagram was discarded to stay inside [`FRAG_MAX_HELD_BYTES`].
    pub fn reassembly_evicted() {
        REASSEMBLY_EVICTED.fetch_add(1, Ordering::Relaxed);
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

    fn bump(c: &AtomicU64) -> u64 {
        c.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }
    pub fn sent() {
        bump(&SENT);
    }
    pub fn retried() -> u64 {
        bump(&RETRIED)
    }
    pub fn dropped_no_permit() -> u64 {
        bump(&DROPPED_NO_PERMIT)
    }
    pub fn failed() -> u64 {
        bump(&FAILED)
    }
    pub fn no_app() -> u64 {
        bump(&NO_APP)
    }
    pub fn retry_failed() -> u64 {
        bump(&RETRY_FAILED)
    }

    pub fn snapshot() -> UdpWriteSnapshot {
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

/// Monotonic milliseconds since first use. Interval logic deliberately avoids
/// wall-clock reads, which an NTP step would corrupt.
fn mono_ms() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// Minimum spacing between datagram-drop warnings, per process.
const DROP_WARN_INTERVAL_MS: u64 = 10_000;

/// Sentinel for "no drop warning has been emitted yet".
///
/// Using 0 here swallows the *first* drop: `mono_ms()` establishes its base on
/// first call, so the elapsed value it returns starts near zero and
/// `now - 0 < INTERVAL` holds. That is exactly the case a fresh deployment
/// hits, so the first drop must warn unconditionally.
const NEVER_WARNED: u64 = u64::MAX;

/// Whether a drop warning is due. Split out from the atomic so the window logic
/// is testable without a clock or a global.
fn drop_warn_due(last: u64, now: u64) -> bool {
    last == NEVER_WARNED || now.saturating_sub(last) >= DROP_WARN_INTERVAL_MS
}

/// Rate-limited (at most one per [`DROP_WARN_INTERVAL_MS`], process-wide)
/// warning for a dropped datagram. A per-packet `warn!` would itself become the
/// bottleneck under the flood that causes drops.
fn warn_datagram_drop(reason: &str, total: u64, detail: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let now = mono_ms();
    let last = LAST.load(Ordering::Relaxed);
    if !drop_warn_due(last, now)
        || LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
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
    let Some(d) = encode_datagram_ref_with_limit(sess, address, payload, limit) else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(
            "payload exceeds the path budget",
            n,
            &budget_detail(limit, dgram_payload_cap(limit, address)),
        );
        return DatagramSend::TooLarge;
    };
    send_encoded(conn, d)
}

/// Queue an already-encoded datagram body, counting a full send buffer.
fn send_encoded(conn: &quinn::Connection, body: Bytes) -> DatagramSend {
    let outcome = try_send_datagram(conn, body);
    if outcome == DatagramSend::Blocked {
        let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
        warn_datagram_drop("send buffer full", n, "");
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
        let cap = dgram_payload_cap(limit, address);
        // Every outbound relayed payload passes through here, so this is the one
        // place the activity counters need (see `udp_stats`).
        udp_stats::payload(payload.len());
        if payload.len() <= cap {
            let failed = match send_udp_datagram(conn, sess, address, payload, limit) {
                DatagramSend::Sent => None,
                other => Some(other),
            };
            return PayloadSend {
                frames: u8::from(failed.is_none()),
                failed,
            };
        }

        let chunk = fragment_chunk_len(limit, address);
        // One fragment must carry something, and the reassembled result must
        // stay inside both the protocol's payload cap and the u8 fragment count.
        let total_usize = if chunk == 0 {
            usize::MAX
        } else {
            payload.len().div_ceil(chunk)
        };
        if total_usize > MQP_FRAG_MAX_TOTAL as usize || payload.len() > MQP_FRAG_MAX_PAYLOAD {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop(
                "payload above the MQP-2 fragmentation limit",
                n,
                &format!(
                    "; {} B exceeds the {MQP_FRAG_MAX_PAYLOAD} B reassembly cap",
                    payload.len()
                ),
            );
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
            let Some(body) = encode_fragment(sess, id, i as u8, total, address, part, limit) else {
                // Only reachable if `chunk` and the encoder disagree; report it
                // rather than send a payload that can never reassemble.
                let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                warn_datagram_drop("fragment does not fit the path budget", n, "");
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
        let complete = {
            let entry = self
                .parts
                .entry(key)
                .or_insert_with(|| Partial::new(f.total, &f.address, now_ms));
            if entry.total != f.total {
                // A wrapped id reused with a different shape: restart rather
                // than splice two datagrams together.
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

fn udp_send_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4096)))
}

/// Best-effort non-blocking UDP send for shared loops (one datagram reader per
/// connection, one relay per association).
///
/// `try_send_to` alone is not enough: tokio returns `WouldBlock` without even
/// attempting the syscall while a freshly registered socket has no cached
/// writable readiness, which would silently drop the first packet of every new
/// session. A genuinely full socket buffer is real backpressure too. In both
/// cases the packet is handed to a bounded detached task so the caller never
/// stalls on one destination; past the permit limit it is dropped (UDP
/// semantics).
///
/// Takes `Bytes` so the slow path *moves* the payload into the task. The
/// borrowed form would force a fresh `to_vec()` allocation plus a copy on a
/// path that already holds an owned, refcounted buffer, and that copy is pure
/// overhead. A `Bytes` that is *not* shared with other consumers (e.g. one just
/// built by `encode_datagram*`) is unwrapped back to its `Vec` first, so the
/// common case runs zero-copy and reuses the caller's allocation for the
/// queued write.
pub fn udp_try_send(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: Bytes) {
    match sock.try_send_to(&payload, dst) {
        Ok(_) => udp_write::sent(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            if let Ok(permit) = udp_send_limiter().clone().try_acquire_owned() {
                let n = udp_write::retried();
                let sock = sock.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let r = match payload.try_into_mut() {
                        Ok(v) => sock.send_to(&v, dst).await,
                        Err(b) => sock.send_to(&b, dst).await,
                    };
                    if let Err(e) = r {
                        let n = udp_write::retry_failed();
                        warn_udp_write("detached retry failed", n, &e.to_string());
                    }
                });
                let _ = n;
            } else {
                // Retry budget exhausted: this packet is gone. Counted now,
                // because this is exactly the loss that had no counter before.
                let n = udp_write::dropped_no_permit();
                warn_udp_write("retry budget exhausted", n, "send buffer full");
            }
        }
        Err(e) => {
            let n = udp_write::failed();
            warn_udp_write("send failed", n, &e.to_string());
        }
    }
}

/// Rate-limited warning for a last-hop UDP write failure.
fn warn_udp_write(reason: &str, total: u64, detail: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let now = mono_ms();
    let last = LAST.load(Ordering::Relaxed);
    if !drop_warn_due(last, now)
        || LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
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

/// One direction's read buffer for [`copy_tcp_quic`] and friends.
///
/// Every stream used to allocate (and free) its own 32 KiB `Vec`, so a proxy
/// carrying thousands of concurrent short flows paid an allocator round trip
/// per flow per direction for a buffer whose lifetime is one connection. The
/// buffers are checked out of a per-thread free list and returned on drop, so a
/// steady stream of flows on a worker thread reuses the same memory. Overflow
/// beyond [`COPY_POOL_MAX`] is freed instead of cached, which keeps a burst of
/// spawned tasks from leaving idle memory behind on every worker thread.
struct CopyBuf(&'static mut [u8]);

/// Copy chunk: large enough that a high-BDP stream is not syscall-bound, small
/// enough that thousands of them do not dominate the RSS.
const COPY_CHUNK: usize = 32 * 1024;
/// Per-thread pool depth. Two directions per flow are active at a time, so a
/// handful of slots covers the common case without hoarding memory.
const COPY_POOL_MAX: usize = 8;

thread_local! {
    static COPY_POOL: std::cell::RefCell<Vec<Box<[u8]>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

impl CopyBuf {
    fn take() -> Self {
        let pooled = COPY_POOL.with(|p| p.borrow_mut().pop());
        match pooled {
            Some(b) => Self(Box::leak(b)),
            None => Self(Box::leak(vec![0u8; COPY_CHUNK].into_boxed_slice())),
        }
    }
}

impl std::ops::Deref for CopyBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl std::ops::DerefMut for CopyBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Drop for CopyBuf {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `Box::leak` of a boxed slice in `take` and
        // has not been freed or aliased since; reconstructing the `Box` returns
        // exclusive ownership of exactly that allocation.
        let b: Box<[u8]> = unsafe { Box::from_raw(self.0) };
        COPY_POOL.with(|p| {
            let mut p = p.borrow_mut();
            if p.len() < COPY_POOL_MAX {
                p.push(b);
            }
        });
    }
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
            let mut buf = CopyBuf::take();
            let mut total = 0u64;
            let mut chunks = 0u64;
            let mut stamped = 0u64;
            loop {
                let n = match tr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        send.reset(0x04u32.into()).ok();
                        return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                            "tcp>quic tcp read failed after {total}B up: {e:#}"
                        ));
                    }
                };
                if let Err(e) = send.write_all(&buf[..n]).await {
                    send.reset(0x04u32.into()).ok();
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "tcp>quic quic write failed after {total}B up: {e:#}"
                    ));
                }
                total += n as u64;
                chunks += 1;
                // One clock read per chunk, one shared store per 100ms: the atomic
                // comparison the old code ran on every non-multiple-of-8 chunk was
                // itself the per-chunk cost it was trying to avoid.
                let now = b1.elapsed().as_millis() as u64;
                let throttle = if chunks.is_multiple_of(8) { 100 } else { 500 };
                touch_stamp(&l1, &mut stamped, now, throttle);
            }
            send.finish().ok();
            Ok::<u64, anyhow::Error>(total)
        };
        let s2c = async move {
            let mut buf = CopyBuf::take();
            let mut total = 0u64;
            let mut chunks = 0u64;
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
            loop {
                let n = match recv.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) => break,
                    Ok(Some(n)) => n,
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
                    break;
                }
                if let Err(e) = tw.write_all(&buf[..n]).await {
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "quic>tcp tcp write failed after {total}B down: {e:#}"
                    ));
                }
                total += n as u64;
                chunks += 1;
                let now = b2.elapsed().as_millis() as u64;
                let throttle = if chunks.is_multiple_of(8) { 100 } else { 500 };
                touch_stamp(&l2, &mut stamped, now, throttle);
            }
            // No FIN here either: the final disposition below closes the socket
            // once both directions are clean.
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
                _ = &mut idle_tick => {
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
        let (before, _) = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::TOO_LARGE);
        let (after, _) = dgram_drops::snapshot();
        assert!(after > before, "snapshot must observe the bump");
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
        assert!(
            udp_stats::reassembly_drops().1 > ev0,
            "an evicted partial must be counted"
        );
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
                    if let Some(x) = reasm.push(&f, mono_ms()) {
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

    /// The copy buffer pool must hand out independent, correctly sized buffers
    /// and recycle them instead of reallocating.
    #[test]
    fn copy_buf_pool_reuses_buffers() {
        assert_eq!(CopyBuf::take().len(), COPY_CHUNK);
        // Check one out, write to it, and drop it: the same allocation must come
        // back out of the pool with its contents intact (no zeroing, no realloc).
        let addr = {
            let mut b = CopyBuf::take();
            b[0] = 0xAB;
            b[COPY_CHUNK - 1] = 0xCD;
            b.0.as_ptr() as usize
        };
        let again = CopyBuf::take();
        assert_eq!(again.0.as_ptr() as usize, addr, "buffer was not pooled");
        assert_eq!(again[0], 0xAB);
        assert_eq!(again[COPY_CHUNK - 1], 0xCD);
        // Overflow past the pool depth is freed rather than cached, so a burst
        // cannot leave unbounded memory behind on a worker thread.
        let held: Vec<CopyBuf> = (0..COPY_POOL_MAX + 4).map(|_| CopyBuf::take()).collect();
        assert_eq!(held.len(), COPY_POOL_MAX + 4);
        drop(held);
        let depth = COPY_POOL.with(|p| p.borrow().len());
        assert!(depth <= COPY_POOL_MAX, "pool overfilled: {depth}");
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
