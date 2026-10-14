use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

use super::client_conf::ClientConf;
use super::server_conf::ServerConf;

// `DATAGRAM_BUFFER` still lives in `src/lib.rs` (transport section, not yet
// split); refer to it at the crate root until it moves with that section.
use crate::DATAGRAM_BUFFER;
use crate::FRAG_MAX_HELD_BYTES;

pub(super) fn d_bbr() -> String {
    "bbr".into()
}
pub(super) fn d_true() -> bool {
    true
}
pub(super) fn d_false() -> bool {
    false
}
pub(super) fn d_keepalive() -> u64 {
    5
}
pub(super) fn d_5() -> u64 {
    5
}

/// Default client TCP pool size, i.e. `quic_conns` unset: four QUIC
/// connections sharing one Endpoint/UDP socket. Bulk TCP spreads round-robin
/// across the three bulk slots while `interactive_ports` pin to the interactive
/// slot, so one heavy flow cannot queue every other flow behind its cwnd.
/// Separate connections carry UDP egress per egress class (interactive and bulk,
/// see `ClientConf::udp_split`), so TCP and UDP never share a congestion window
/// or a packet payload. Independent of the server, which accepts any number of
/// them.
pub const DEFAULT_QUIC_CONNS: usize = 4;

/// Hard cap on the client **TCP** connection pool. Every slot owns a QUIC
/// connection (dial loop, DATAGRAM dispatcher, keepalives, its own 0-RTT ticket
/// state), so this cap — not the config parser — is what bounds the per-client
/// cost a `quic_conns` typo can request. The UDP egress slots are beyond this:
/// a client's worst case is `MAX_POOL_CONNS + 2` with `udp_split` (the default)
/// and `MAX_POOL_CONNS + 1` without it.
pub const MAX_POOL_CONNS: usize = 8;

/// Concurrent bidirectional streams one QUIC connection may carry.
///
/// This is the credit each endpoint advertises, and `Connection::open_bi()`
/// parks until the *peer's* credit allows — so it must cover the largest number
/// of TCP flows that can land on a single connection. The client admits up to
/// `MAX_SOCKS_CONNS` (8192) SOCKS connections process-wide and
/// `interactive_ports` pinning can put every TCP flow on slot 0, hence 8192;
/// every smaller value lets an *admitted* flow stall in `open_bi()` for the
/// client's 5 s timeout and then answer SOCKS `REP=0x01` while the process still
/// has stream-task capacity. The server's `MAX_STREAM_TASKS` process-wide task
/// bound stays the overload backstop, exactly as before.
///
/// (An earlier revision hard-coded 1024 here, which was inconsistent with the
/// client's 8192-connection admission cap: with the default four-connection
/// pool only 4096 concurrent TCP flows could ever be open, and the 4097th+
/// stalled before failing. The client bin asserts `MAX_SOCKS_CONNS <=
/// MAX_BIDI_STREAMS_PER_CONN` so the two can never drift apart again.)
pub const MAX_BIDI_STREAMS_PER_CONN: u32 = 8192;

/// Concurrent UDP associations one *client process* may admit.
///
/// Deliberately one number shared with the server's per-connection session
/// target (`LOCAL_SESS_TARGET`; the server asserts the two are equal at compile
/// time): a client's admission cap is only useful if it matches what the server
/// will actually keep alive, and a mismatch is invisible to the application
/// because UDP DATAGRAMs carry no back-channel.
///
/// It is a *budget*, not a guarantee. The server's real ceiling for one
/// connection is its live **fair share**, `clamp(MAX_SESSIONS_GLOBAL / holders,
/// MIN_SESSION_SHARE, LOCAL_SESS_MAX)`, where `holders` counts the connections
/// that currently hold at least one session (`fair_sess_cap()` in
/// `myquic2-server.rs`). A lone client is the only holder, so the fair share
/// (4096) sits above this cap and the client's own limit binds; a server shared
/// by N session-holding connections gives each `8192 / N`, never below the 1024
/// floor. Nothing on the wire tells the client which it got, so a deployment
/// that shares a server must size its per-client capacity against the shared
/// budget, not this number.
pub const MAX_UDP_ASSOCS: usize = 4032;

/// Default RTT seed in ms for the loss-detection estimator before the first
/// measured sample (see `TransportTuning::initial_rtt`). 190 is the tuned
/// value for the ~140 ms WAN link this build targets: quinn's 333 ms default
/// makes the first PTO and the initial pacing rate far too pessimistic there.
pub const DEFAULT_INITIAL_RTT_MS: u64 = 190;
/// Lower clamp for `initial_rtt_ms`.
pub const INITIAL_RTT_MS_MIN: u64 = 1;
/// Upper clamp for `initial_rtt_ms`; a seed above a few seconds can only be a
/// typo and would postpone first-flight loss recovery absurdly.
pub const INITIAL_RTT_MS_MAX: u64 = 3_000;

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
    /// Seed for quinn's RTT estimator (and thus the first PTO) until the first
    /// measured sample lands. Only tail-relevant: set it to the link's real
    /// RTT (e.g. 140 on a 140 ms link) to shorten first-flight loss recovery;
    /// steady state re-measures and ignores the seed.
    pub initial_rtt: Duration,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            stream_receive_window: 2 * 1024 * 1024,
            receive_window: 4 * 1024 * 1024,
            send_window: 2 * 1024 * 1024,
            ack_threshold: 2,
            max_ack_delay: Duration::from_millis(5),
            initial_rtt: Duration::from_millis(DEFAULT_INITIAL_RTT_MS),
        }
    }
}

fn initial_rtt_from_ms(v: Option<u64>) -> Duration {
    Duration::from_millis(
        v.unwrap_or(DEFAULT_INITIAL_RTT_MS)
            .clamp(INITIAL_RTT_MS_MIN, INITIAL_RTT_MS_MAX),
    )
}

fn clamp_window_mb(v: Option<u64>, def_mb: u64) -> u64 {
    let mb = v.unwrap_or(def_mb).clamp(1, 64);
    mb * 1024 * 1024
}

/// Worst-case peer-pinnable memory one admitted connection can represent under
/// `tuning`, in bytes — the **transport** term only.
///
/// Deliberately conservative and simple, because it feeds an *admission* bound:
///
/// - `receive_window`: unread inbound stream data quinn buffers for us (the
///   connection window caps the sum over all of that connection's streams);
/// - `send_window`: queued outbound stream data a peer that stops reading can
///   make us hold before our writers block;
/// - both DATAGRAM buffers: not flow-controlled at all, so a flood fills them
///   whatever the application does;
/// - the per-connection reassembly budget ([`FRAG_MAX_HELD_BYTES`]): a peer that
///   sends fragments it never completes pins this until the partial expires.
///
/// Per-stream windows are not added: they are bounded by the connection window.
/// The result is a ceiling, not a reservation — quinn allocates on demand — which
/// is exactly what "how many connections may this host admit" has to be based
/// on. See [`ServerConf::max_peer_memory_mb`].
///
/// **UDP sessions are a second, process-wide term.** Every session owns a kernel
/// socket plus a userspace read buffer (see [`per_session_memory_bytes`]), and
/// the number of them is bounded by the *global* session pool rather than per
/// connection — so adding "sessions per connection x per-session" here would
/// double-count a budget shared by every peer. The server's `admission_cap`
/// subtracts the pool from the operator's budget once, globally; see
/// [`session_pool_memory_bytes`].
pub fn per_connection_memory_bytes(tuning: &TransportTuning) -> u64 {
    tuning
        .receive_window
        .saturating_add(tuning.send_window)
        .saturating_add(2 * DATAGRAM_BUFFER as u64)
        .saturating_add(FRAG_MAX_HELD_BYTES as u64)
}

/// Worst-case memory one UDP session can pin, in bytes: the session socket's
/// send *and* receive caps (`sess_socket_buf()` each way) plus the reply
/// reader's userspace receive buffer (`UDP_RECV_MAX + UDP_RECV_SLACK`).
///
/// These are caps, not reservations — the kernel only accounts what is actually
/// queued — but they are what a peer can hold, and a cap is what an admission
/// bound has to be built from. The receive direction is the easy one to pin (a
/// target that answers faster than the reader drains, or many sessions whose
/// readers are starved); the send direction fills only against a black-holed
/// route or a full qdisc. `MYQUIC2_SESS_SOCKET_BUF` lowers both.
#[must_use]
pub fn per_session_memory_bytes() -> u64 {
    (2 * crate::sess_socket_buf() + crate::UDP_RECV_MAX + crate::UDP_RECV_SLACK) as u64
}

/// Worst-case memory the *whole* UDP session pool can pin: the process-wide
/// session cap times [`per_session_memory_bytes`].
///
/// This term is global, not per connection: `MAX_SESSIONS_GLOBAL` permits are
/// shared by every admitted peer, so it must be charged against
/// `max_peer_memory_mb` exactly once. Before this existed the admission bound
/// counted only the transport windows, so an operator could set a 512 MiB budget
/// and still have the process pin ~1 GiB of session socket buffers plus the
/// transport windows — the knob bounded a fraction of what its log line claimed.
#[must_use]
pub fn session_pool_memory_bytes(max_sessions: usize) -> u64 {
    (max_sessions as u64).saturating_mul(per_session_memory_bytes())
}

impl ServerConf {
    pub fn tuning(&self) -> TransportTuning {
        TransportTuning {
            stream_receive_window: clamp_window_mb(self.stream_receive_window_mb, 2),
            receive_window: clamp_window_mb(self.receive_window_mb, 4),
            send_window: clamp_window_mb(self.send_window_mb, 2),
            ack_threshold: self.ack_threshold.unwrap_or(2).clamp(1, 32),
            max_ack_delay: Duration::from_millis(self.max_ack_delay_ms.unwrap_or(5).clamp(1, 25)),
            initial_rtt: initial_rtt_from_ms(self.initial_rtt_ms),
        }
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
            initial_rtt: initial_rtt_from_ms(self.initial_rtt_ms),
        }
    }
}

pub fn load_toml<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    // The path is in the context: with `deny_unknown_fields` a typo is a hard
    // error, and "unknown field ... in config-client.toml" is what makes it
    // actionable without the operator guessing which file was parsed.
    toml::from_str(&s).with_context(|| format!("parse {path}"))
}
