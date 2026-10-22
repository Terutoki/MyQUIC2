use std::sync::Arc;
use std::time::Duration;

use super::limits::{DATAGRAM_BUFFER, DATAGRAM_BUFFER_BULK, DGRAM_MAX_WIRE, MQP_DGRAM_MAX};
use crate::{SERVER_PRE_AUTH_BIDI_CREDIT, SERVER_UNI_STREAM_CREDIT, TransportTuning};

/// QUIC congestion controller selection.
///
/// `Bbr` is the default; `Cubic` is the escape hatch. `clap::ValueEnum`
/// gives CLI `--congestion` parsing/validation for free, and `serde`
/// keeps TOML `congestion = "bbr"|"cubic"` working. Unknown strings fall
/// back to `Bbr` via [`Congestion::from_config`] to preserve the previous
/// `&str` behaviour (warn + BBR) instead of failing the process.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Congestion {
    /// BBR (default).
    #[default]
    Bbr,
    /// Cubic escape hatch.
    Cubic,
}

impl Congestion {
    /// Lossy conversion from operator config: `cubic` (any case) → `Cubic`,
    /// everything else → `Bbr`. Callers validate with `parse_congestion`
    /// first so unknown values warn instead of silently falling back.
    pub fn from_config(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cubic") {
            Self::Cubic
        } else {
            Self::Bbr
        }
    }
}

impl std::fmt::Display for Congestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bbr => write!(f, "bbr"),
            Self::Cubic => write!(f, "cubic"),
        }
    }
}

impl std::str::FromStr for Congestion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else {
            Err(format!("want bbr|cubic, got {s:?}"))
        }
    }
}

pub fn build_transport(
    congestion: Congestion,
    keep_alive_secs: u64,
) -> Arc<quinn::TransportConfig> {
    build_transport_tuned(congestion, keep_alive_secs, TransportTuning::default())
}

/// Upper clamp for `keep_alive_secs`.
///
/// The idle timeout is `3 x keepalive` and the client's silence watchdog
/// `2 x keepalive`, so an unbounded value (the clamp used to be 3600) put
/// silent-path detection 3-4 *hours* out — a black hole on a router, and a
/// silent contradiction of the documented ~8-15 s detection. 300 s bounds the
/// `2 x` watchdog at 10 minutes and the `3 x` idle timeout at 15 minutes while
/// leaving every sane NAT keepalive alone; larger values are clamped **and
/// warned about**, never obeyed silently.
pub const KEEP_ALIVE_MAX_SECS: u64 = 300;

/// One definition of the keepalive bound, testable without a `TransportConfig`
/// getter (quinn exposes setters only). Warns on the clamp: it changes how fast
/// a silent path is noticed, which is what setting the field asks about.
pub(crate) fn clamp_keep_alive(keep_alive_secs: u64) -> u64 {
    if keep_alive_secs > KEEP_ALIVE_MAX_SECS {
        tracing::warn!(
            "keep_alive_secs {keep_alive_secs} exceeds the {KEEP_ALIVE_MAX_SECS} s cap; \
             clamped (silent-path detection scales 2-3x with it)"
        );
    }
    keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS)
}

/// QUIC idle timeout derived from the keepalive interval: `3 x keepalive`,
/// floor 15 s (quinn requires the idle timeout to stay well above the
/// keepalive interval, and a lower floor would let a few lost keepalives kill
/// a healthy connection).
///
/// Shared with the client binary so its silence watchdog can be derived from
/// the *same* clamped keepalive value and proven to fire first — see
/// [`watchdog_silence_secs`].
#[must_use]
pub fn idle_timeout_secs(keep_alive_secs: u64) -> u64 {
    clamp_keep_alive(keep_alive_secs).saturating_mul(3).max(15)
}

/// Client silence-watchdog budget derived from the keepalive interval:
/// `2 x keepalive`, floor 8 s.
///
/// It is deliberately **strictly below** [`idle_timeout_secs`] for every legal
/// keepalive: the watchdog used to be `4 x keepalive` with a 20 s floor while
/// the peer/QUIC idle timeout was `3 x keepalive` with a 15 s floor, so the
/// watchdog could never fire first — it was dead code and path death was
/// always detected by the idle timer instead (~15 s). With `2 x`/8 s the two
/// independent detectors in the client's reconnect loop (downlink silence and
/// ACK stall) actually bound failover, and the idle timeout can later be
/// re-tuned upward without slowing recovery. A build-time/unit-test invariant
/// proves `watchdog < idle` across the whole clamp range.
#[must_use]
pub fn watchdog_silence_secs(keep_alive_secs: u64) -> u64 {
    clamp_keep_alive(keep_alive_secs).saturating_mul(2).max(8)
}

pub fn build_transport_tuned(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
) -> Arc<quinn::TransportConfig> {
    build_transport_inner(congestion, keep_alive_secs, tuning, false, false)
}

/// Per-class transport builder.
/// `is_bulk` selects the bulk preset (ACK threshold 8, 10ms delay; 2MB DATAGRAM
/// buffers) that trades reverse-path CPU for coarser feedback; interactive
/// keeps the tuned values (default ACK threshold 2 / 5 ms) and 1MB DATAGRAM
/// buffers. Flow-control windows come from `tuning` unchanged (default
/// 4/8/4 MB).
///
/// This is the **server** (and symmetric test peer) shape: it advertises the
/// stream credit a client needs for its SOCKS TCP relays and auth stream.
pub fn build_transport_tuned_class(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
    is_bulk: bool,
) -> Arc<quinn::TransportConfig> {
    build_transport_inner(congestion, keep_alive_secs, tuning, is_bulk, false)
}

/// Client-side transport builder: identical tuning, but the client advertises
/// **zero** incoming stream credit.
///
/// The client initiates every stream it uses (one QUIC bidi stream per SOCKS
/// TCP relay; one uni stream for the auth token). A server never opens a
/// stream to the client — replies travel on the stream the client opened — so
/// advertising credit only hands the peer a memory lever: quinn-proto keeps a
/// receive assembler per peer-opened stream that buffers up to
/// `MAX_CHUNKS = 1024` distinct gap spans (56 B `Buffer` node plus the retained
/// packet allocation each), while flow control counts payload bytes, not span
/// metadata. With a symmetric 8192-stream handshake credit (the pre-fix shape)
/// one malicious server could park hundreds of MiB on a client that never
/// accepts a stream. At `(0, 0)` a peer that still opens one is violating our
/// transport parameters, and quinn rejects the stream id (closing the
/// connection) before buffering data (`validate_receive_id`), so the lever is
/// removed rather than merely charged.
pub fn build_client_transport_tuned(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
) -> Arc<quinn::TransportConfig> {
    build_transport_inner(congestion, keep_alive_secs, tuning, false, true)
}

/// Per-class form of [`build_client_transport_tuned`]: `is_bulk` selects the
/// bulk ACK/DATAGRAM preset (see [`build_transport_tuned_class`]).
pub fn build_client_transport_tuned_class(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
    is_bulk: bool,
) -> Arc<quinn::TransportConfig> {
    build_transport_inner(congestion, keep_alive_secs, tuning, is_bulk, true)
}

/// Incoming-stream credit `(bidi, uni)` the **handshake** advertises to the
/// peer.
///
/// Only the server accepts streams: clients open them. `(0, 0)` on the client
/// is a security bound, not a tuning value — see
/// [`build_client_transport_tuned`]. The server starts at the small pre-auth
/// credit and raises it to [`MAX_BIDI_STREAMS_PER_CONN`] with MAX_STREAMS right
/// after the token check (`myquic2-server`'s accept loop), so an unauthenticated
/// peer cannot park the full per-stream receive-assembler bound before it
/// proves it holds the token; see [`SERVER_PRE_AUTH_BIDI_CREDIT`].
pub(crate) fn incoming_stream_credits(is_client: bool) -> (u32, u32) {
    if is_client {
        (0, 0)
    } else {
        (SERVER_PRE_AUTH_BIDI_CREDIT, SERVER_UNI_STREAM_CREDIT)
    }
}

fn build_transport_inner(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
    is_bulk: bool,
    is_client: bool,
) -> Arc<quinn::TransportConfig> {
    let tuning = if is_bulk {
        TransportTuning {
            ack_threshold: 8,
            max_ack_delay: Duration::from_millis(10),
            ..tuning
        }
    } else {
        tuning
    };
    let dgram_buf = if is_bulk {
        DATAGRAM_BUFFER_BULK
    } else {
        DATAGRAM_BUFFER
    };
    let mut t = quinn::TransportConfig::default();
    // BBR default; cubic only as escape hatch. Callers validate + log the
    // configured value via `parse_congestion`; unknown values fall back to BBR.
    match congestion {
        Congestion::Cubic => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        Congestion::Bbr => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }
    // GSO/GRO: no flag in quinn API — quinn-udp auto-probes UDP_SEGMENT/UDP_GRO.
    // Datagrams are a lossy best-effort path drained by a dedicated reader, so
    // 1MB (~740 x 1350B datagrams) absorbs bursts without the per-connection
    // 4MB x 4096-connection worst case (16GB of queueable user memory).
    t.datagram_receive_buffer_size(Some(dgram_buf));
    t.datagram_send_buffer_size(dgram_buf);
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
    // Incoming stream credit. The client advertises `(0, 0)`: it never accepts
    // a peer-opened stream, and every advertised stream slot is a
    // peer-pinnable quinn receive assembler (up to 1024 gap spans each), which
    // is exactly the memory lever [`build_client_transport_tuned`] closes. The
    // server advertises the small **pre-auth** credit here and raises it to
    // `MAX_BIDI_STREAMS_PER_CONN` with MAX_STREAMS right after the token check,
    // so the full client-facing credit is never granted to an unauthenticated
    // peer; the post-auth bound is charged as a process-wide fixed term (see
    // `stream_assembler_memory_bytes`).
    let (bidi_credit, uni_credit) = incoming_stream_credits(is_client);
    t.max_concurrent_bidi_streams(bidi_credit.into());
    t.max_concurrent_uni_streams(uni_credit.into());
    // Window sizing: every flow-control window must exceed the target BDP, or
    // it -- not the congestion controller -- becomes the throughput ceiling.
    // The shipped defaults are 4/8/4 MB (stream/connection/send) from
    // `TransportTuning::default()`, ~240Mb/s on the target 140ms link, and
    // operators tune them per side. The opt-in 8/16/8 MB preset lives in named
    // constants (`transport::limits`) so `tcp_windows_cover_the_300mb_s_bdp`
    // can prove its invariant instead of restating it.
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
    // BBR's initial bandwidth estimate far too pessimistic at 140ms. The
    // seed is `DEFAULT_INITIAL_RTT_MS` (190) unless `initial_rtt_ms`
    // overrides it; operators on a known link set it to the measured RTT
    // (140 shortens the first PTO from ~575ms to ~435ms). It only lives
    // until the first RTT sample, so it is a first-flight tail knob, never a
    // steady-state one.
    t.initial_rtt(tuning.initial_rtt);
    // Raise the PMTU search ceiling from quinn's 1452 to 1472 (the endpoint's
    // `max_udp_payload_size` default, so this is the hard limit anyway): 20
    // more bytes per packet is ~1.4% fewer packets for the same payload, which
    // a single-threaded sender pays directly.
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(1472);
    t.mtu_discovery_config(Some(mtud));
    // Start at the configured path MTU. The shipped default is the 1200-byte
    // QUIC floor (`DEFAULT_INITIAL_MTU`) — the most conservative start a QUIC
    // endpoint may use — and a deployment with a known path should raise it:
    // 1360 B is 1388/1408 wire bytes after the IPv4/IPv6 + UDP headers and
    // therefore safe on WireGuard-1420 and similar tunnel paths; a known
    // 1500-byte Ethernet path can use 1400/1472. This is the larger half of the
    // PMTU story: quinn's discovery is a binary search that needs one probe/ACK
    // round trip per step (starting at the floor: 1200 -> 1336 -> 1404 -> 1438
    // -> 1472), and probes are only emitted from a transmit poll that builds no
    // payload packet (`quinn-proto connection/mod.rs`), so a busy connection can
    // sit at its start value for a long time. While it does, every packet
    // carries up to ~19% fewer payload bytes and quinn's DATAGRAM budget is
    // `mtu - 38` (1162 at 1200), so every UDP payload above 1150 B splits into
    // two MQP-2 fragments. `min_mtu` stays at the 1200-byte QUIC floor and
    // quinn's black-hole detector drops back to it if the configured start is
    // larger than the real path, so a raised value is a recoverable loss burst,
    // not a wedge.
    t.initial_mtu(tuning.initial_mtu);
    let keep_alive_secs = clamp_keep_alive(keep_alive_secs);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs)));
    // Idle timeout derives from keepalive so custom keep_alive_secs can never
    // self-kill a healthy connection: idle must stay well above the keepalive
    // interval (QUIC requires inbound traffic before idle fires). 15s floor
    // preserves the old silent-blackhole bound; larger keepalives scale up.
    let idle_secs = idle_timeout_secs(keep_alive_secs);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_BIDI_STREAMS_PER_CONN;

    // The pre-auth credit must be a strict subset of the post-auth one: if the
    // handshake advertised the full credit there would be nothing to raise (and
    // the pre-auth memory bound would be the post-auth one).
    const _: () = assert!(SERVER_PRE_AUTH_BIDI_CREDIT < MAX_BIDI_STREAMS_PER_CONN);

    /// The client must never advertise an incoming stream slot: quinn buffers
    /// one receive assembler per peer-opened stream (up to `MAX_CHUNKS = 1024`
    /// gap spans each), and flow control does not account for that metadata —
    /// so a credit here is a peer-controlled memory lever on a side that never
    /// accepts a stream.
    #[test]
    fn client_advertises_no_incoming_stream_credit() {
        assert_eq!(incoming_stream_credits(true), (0, 0));
    }

    /// The server advertises the small pre-auth credit at handshake time and
    /// raises it to `MAX_BIDI_STREAMS_PER_CONN` after authentication (see the
    /// server's accept loop). The old symmetric 8192/100 handshake credit let
    /// an unauthenticated peer park a receive assembler per advertised stream.
    #[test]
    fn server_advertises_only_the_pre_auth_stream_credit() {
        assert_eq!(
            incoming_stream_credits(false),
            (SERVER_PRE_AUTH_BIDI_CREDIT, SERVER_UNI_STREAM_CREDIT)
        );
        assert_eq!(
            SERVER_UNI_STREAM_CREDIT, 2,
            "one auth uni stream plus one slot of margin; the server never opens one"
        );
    }
}
