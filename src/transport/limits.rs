use std::time::Duration;

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
// `window / RTT`, applied before BBR's cwnd is consulted.
//
// **These are the opt-in 300Mb/s preset, not the shipped default.** The shipped
// default is `TransportTuning::default()`'s low-latency 2/4/2 MB preset
// (~114Mb/s at 140ms), documented in `config-*.toml` and the README limits
// table; operators raise it with `stream_receive_window_mb = 8`,
// `receive_window_mb = 16`, `send_window_mb = 8` (plus `ack_threshold = 8`,
// `max_ack_delay_ms = 10`) on **both** sides. The constants exist so that opt-in
// configuration has one definition and a guard test that actually exercises the
// config path (`tcp_windows_cover_the_300mb_s_bdp`); an earlier revision of this
// comment claimed they "supersede" the defaults, which no code read.
//
// KNOWN COST of the wide preset: quinn kills a connection once a single stream's
// reassembly holds `MAX_CHUNKS = 1024` distinct spans. A larger window allows
// more packets in flight per RTT (~6200 at 1350B, ~3700 at the 1472B PMTU
// ceiling), so a burst-loss or reordering episode has more room than 2MB did to
// approach that cliff. A clean path is unaffected; on a lossy one, step this
// preset's `SEND_WINDOW` and `STREAM_RECEIVE_WINDOW` back to 4MB (=240Mb/s)
// rather than reverting the ACK-frequency and PMTU work, which is
// loss-independent.

/// Per-stream receive window. 8MB rather than the 5.25MB BDP: quinn only
/// announces a `MAX_STREAM_DATA` once the advertised window is short by
/// `STREAM_RECEIVE_WINDOW / 8`, so the cushion that must still cover a full BDP
/// is `8MB - 1MB = 7MB`. At 6MB the cushion would be 5.25MB -- the BDP exactly,
/// with nothing left for scheduler jitter or a stalled application read.
pub const STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
/// Aggregate connection receive window. MUST be set explicitly: quinn's default
/// is `VarInt::MAX`, which would otherwise allow 1024 streams x 8MB of receive
/// buffering per connection. 16MB covers the BDP with margin for a few
/// concurrent streams. This is the term that dominates the memory ceiling, and
/// the README's *Limits & memory* table carries the numbers:
/// `per_connection_memory_bytes` is 26.25 MiB at this preset (16 MB receive +
/// 8 MB send + 2 x 1 MB DATAGRAM + 256 KiB reassembly), so 4096 connections
/// represent ~105 GiB of peer-pinnable transport memory with no budget set —
/// 64 GiB of that being this window alone — and 256 pre-auth connections
/// 6.56 GiB. `max_peer_memory_mb` is the knob that bounds it.
pub const RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;
/// Send-side budget: the upper bound on data this endpoint may keep buffered and
/// unacknowledged on one connection. quinn blocks a writer once
/// `min(peer's stream window, SEND_WINDOW) - buffered_data` reaches zero, so on
/// a high-RTT link this is a throughput ceiling of `SEND_WINDOW / RTT` for the
/// write direction. See the flow-control note above for the 8MB tradeoff.
pub const SEND_WINDOW: u64 = 8 * 1024 * 1024;

const _: () = {
    // The opt-in preset must be *reachable* through the config clamp
    // (`clamp_window_mb`, 1..=64 MB), or the documentation would be pointing at
    // values an operator cannot actually set. This is the link between the
    // constants and the only code that consumes window sizes.
    const MB: u64 = 1024 * 1024;
    assert!(STREAM_RECEIVE_WINDOW / MB >= 1 && STREAM_RECEIVE_WINDOW / MB <= 64);
    assert!(RECEIVE_WINDOW / MB >= 1 && RECEIVE_WINDOW / MB <= 64);
    assert!(SEND_WINDOW / MB >= 1 && SEND_WINDOW / MB <= 64);
};

/// DATAGRAM send/receive buffer per connection (see [`build_transport`]).
///
/// Shared by every session on the connection, and `send_datagram_wait`
/// backpressure drops the *newest* datagram — so two UDP flows on one connection
/// are not isolated from each other: a high-rate flow can starve a
/// latency-sensitive one out of the buffer. Only UDP-vs-TCP isolation is
/// structural (the client gives UDP its own connection, see `ConnPool` in the
/// client bin); UDP-vs-UDP fairness would need per-session queues that DATAGRAM
/// semantics deliberately do not provide.
pub(crate) const DATAGRAM_BUFFER: usize = 1024 * 1024;

/// Bulk-class DATAGRAM buffer: 2MB absorbs bursts on the bulk UDP/TCP
/// connections without the 4MB worst case per connection.
pub(crate) const DATAGRAM_BUFFER_BULK: usize = 2 * 1024 * 1024;

/// Upper bound for one MQP-2 datagram on the wire: the largest address form
/// (1 + 1 + 255 + 2) plus the type/session header. Kept as a named constant so
/// the tests below can prove the send-buffer invariant rather than assert it.
pub(crate) const MQP_DGRAM_MAX: usize = 5 + 1 + 1 + 255 + 2;

/// Largest MQP-2 datagram body that can ever be handed to quinn.
///
/// The body is `min(Connection::max_datagram_size(), ...)` and quinn's own
/// ceiling is the endpoint's `max_udp_payload_size` (1472), so no datagram can
/// exceed that. This — not [`MQP_DGRAM_MAX`], which is only the header bound —
/// is what the send buffer has to hold at least one of for
/// `send_datagram_wait` to ever make progress.
pub const DGRAM_MAX_WIRE: usize = 1472;
