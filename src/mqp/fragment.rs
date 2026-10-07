use super::{
    addr::{AddrHeader, TargetAddrRef},
    datagram::{DGRAM_PREFIX_LEN, MQP_DGRAM_TYPE},
};
use anyhow::Result;
use bytes::Bytes;

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
/// `RSV(2) | FRAG(1) | atyp(1) | addr | port(2)`, where the address is largest
/// in its domain form (`len(1) | host(≤255)`), not its IPv6 form (16 B) — an
/// IPv6-sized reservation silently truncates app datagrams that pair a long
/// domain name with a near-maximum payload, before the fragmenter ever sees
/// them.
pub const SOCKS_UDP_HDR_MAX: usize = 3 + 1 + 1 + 255 + 2;

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
///
/// This is a real deadline only because both datagram readers drive
/// [`DgramReassembler::expire`] from a [`FRAG_SWEEP_INTERVAL_MS`] tick.
pub const FRAG_TIMEOUT_MS: u64 = 2_000;

/// Cadence of the readers' reassembly-expiry tick.
///
/// The reassembler cannot expire itself: `push` is only reached when a fragment
/// *arrives*, so a peer that stops sending datagrams (keeping its connection
/// alive on keepalives) would hold its partials forever. Both datagram readers
/// therefore tick this often and call [`DgramReassembler::expire`], which bounds
/// a partial's life to `FRAG_TIMEOUT_MS + FRAG_SWEEP_INTERVAL_MS`.
pub const FRAG_SWEEP_INTERVAL_MS: u64 = 500;

/// How long a sending context must wait after exhausting the 16-bit fragment id
/// space before it may reuse an id.
///
/// Must cover the receiver's *whole* partial lifetime (a partial expires at
/// `FRAG_TIMEOUT_MS`, but only when a sweep runs: up to one
/// `FRAG_SWEEP_INTERVAL_MS` later) with margin, or a fragment of the newer
/// generation can land in the older generation's partial and splice two
/// datagrams together — which the receiver cannot detect without a wire
/// generation marker, and which delivers the mix to the older target. See
/// [`DgramFragmenter::send`].
///
/// **This is a per-cycle pause, not a rate limit.** Every wrap refuses *every*
/// oversized payload for this long, because the guard's reference must be an
/// upper bound on when each id in the new cycle was last used, and only the
/// cycle's own start is such a bound without a per-id timestamp ring. The
/// resulting loss is `W / (65536 * 1000 / payloads_per_s + W)`: ~0.5% at 100
/// fragmented payloads/s, ~4% at 1000/s, ~8% at 2000/s, ~15% at 4000/s, and
/// 50% at `65536 / W` = 21845/s — the number often mistaken for a clean
/// ceiling, but where half the oversized payloads are dropped. No rate avoids
/// it entirely; it only becomes negligible at very high rates.
///
/// So `65536 / FRAG_ID_SAFE_WINDOW_MS` is **not** a throughput ceiling: it is
/// the rate at which this guard costs half of all oversized payloads. Closing
/// that gap needs a generation counter on the wire (or 65536 timestamps per
/// sending context), not a different constant.
pub const FRAG_ID_SAFE_WINDOW_MS: u64 = FRAG_TIMEOUT_MS + FRAG_SWEEP_INTERVAL_MS + 500;

const _: () = assert!(
    FRAG_ID_SAFE_WINDOW_MS > FRAG_TIMEOUT_MS + FRAG_SWEEP_INTERVAL_MS,
    "the id-reuse window must outlast the partial lifetime it protects"
);

/// Reassembly memory bound per connection, counted over the bytes partials
/// actually **retain**: the owned chunk bytes plus the slot table each partial
/// owns, past which the oldest partial is evicted — so this is also what caps how
/// many datagrams may be in flight at once.
///
/// Retained, not payload, bytes: every partial owns a `vec![None; total]` slot
/// table (`total x 32 B` = up to 2 KiB) that a peer can fill with empty chunks,
/// and each stored chunk is an owned copy of exactly its own length (see
/// `DgramReassembler::push` for why the chunks are not aliases of the received
/// datagram). At the protocol's 8 KiB payload ceiling a full partial costs
/// roughly 10-11 KiB, i.e. on the order of 20-25 concurrent partials per
/// connection — far above any real RTT's worth of unfragmented arrivals, while
/// still bounding what a fragment flood can pin.
pub const FRAG_MAX_HELD_BYTES: usize = 256 * 1024;

/// Reassembly partial-count bound per connection: a defense-in-depth backstop
/// on top of [`FRAG_MAX_HELD_BYTES`], and the bound on the `min_by_key` eviction
/// scan (at most 256 entries per eviction).
///
/// The byte bound already charges each partial's slot table, so a flood of
/// never-completing partials is caught there first; this cap only matters if a
/// future change makes the byte accounting miss a cost (e.g. the HashMap entry
/// itself).
pub const FRAG_MAX_PARTIALS: usize = 256;

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
pub(crate) fn encode_fragment_with_header(
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
