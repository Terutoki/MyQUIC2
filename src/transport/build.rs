use std::sync::Arc;
use std::time::Duration;

use super::limits::{DATAGRAM_BUFFER, DATAGRAM_BUFFER_BULK, DGRAM_MAX_WIRE, MQP_DGRAM_MAX};
use crate::{MAX_BIDI_STREAMS_PER_CONN, TransportTuning};

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
    build_transport_tuned_class(congestion, keep_alive_secs, tuning, false)
}

/// Per-class transport builder.
/// `is_bulk` selects the bulk preset (ACK threshold 8, 10ms delay; 2MB DATAGRAM
/// buffers) that trades reverse-path CPU for coarser feedback; interactive
/// keeps the tuned values (default ACK threshold 2 / 5 ms) and 1MB DATAGRAM
/// buffers. Flow-control windows come from `tuning` unchanged (default
/// 4/8/4 MB).
pub fn build_transport_tuned_class(
    congestion: Congestion,
    keep_alive_secs: u64,
    tuning: TransportTuning,
    is_bulk: bool,
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
    // Bidi credit: must cover the client's whole admission cap, since
    // interactive-port pinning can put every admitted TCP flow on one
    // connection — see `MAX_BIDI_STREAMS_PER_CONN`.
    t.max_concurrent_bidi_streams(MAX_BIDI_STREAMS_PER_CONN.into());
    t.max_concurrent_uni_streams(100u32.into());
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
    // Start at the configured path MTU instead of quinn's 1200-byte QUIC
    // floor. The default start is 1360 B (DEFAULT_INITIAL_MTU), which is
    // 1388/1408 wire bytes after the IPv4/IPv6 + UDP headers and therefore
    // safe on WireGuard-1420 and similar tunnel paths; a known 1500-byte
    // Ethernet path can raise it to 1400/1472. This is the other half of the
    // PMTU story and the larger one: quinn's discovery is a binary search that
    // needs one probe/ACK round trip per step (starting at the floor:
    // 1200 -> 1336 -> 1404 -> 1438 -> 1472), and probes are only
    // emitted from a transmit poll that builds no payload packet
    // (`quinn-proto connection/mod.rs`), so a busy connection can sit at its
    // start value for a long time. While it does, every packet carries up to
    // ~19% fewer payload bytes and quinn's DATAGRAM budget is
    // `mtu - 38` (1162 at 1200), so every UDP payload above 1150 B splits into
    // two MQP-2 fragments. `min_mtu` stays at the 1200-byte QUIC floor and
    // quinn's black-hole detector drops back to it if the configured start is
    // larger than the real path, so a too-high value is a recoverable loss
    // burst, not a wedge.
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
