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
/// a client's worst case is `MAX_POOL_CONNS + 1 + MAX_UDP_EGRESS_CONNS` with
/// `udp_split` (the default) and `MAX_POOL_CONNS + 1` without it.
///
/// 16 rather than 8: separate congestion windows are the only per-flow
/// isolation quinn 0.11 offers (no stream priorities), so the pool width is
/// what a many-core client's bulk TCP uplink scales with — one connection per
/// core is a reasonable ceiling, and the cap only bounds what a config can
/// request. The server is what ultimately pays for a wide pool, and it already
/// prices each connection through its admission budget, so a raised
/// `quic_conns` consumes that budget instead of multiplying anything silently.
pub const MAX_POOL_CONNS: usize = 16;

/// Default number of dedicated **bulk** UDP egress connections ("shards") the
/// client dials with `udp_split` on.
///
/// Every UDP association is bound to one shard for life (see
/// `ConnPool::udp_bind`), so the shard count is how many of the client's
/// connections — and, on the server, how many per-connection DATAGRAM readers
/// and `ConnectionDriver` tasks — the bulk association population spreads
/// across. One bulk connection was the measured aggregate ceiling on
/// multi-association UDP loads (all associations funneled into one
/// connection's encrypt/ACK/send pipeline and one server-side reader); two is
/// the shipped default because it doubles that ceiling at the cost of one
/// extra dial, and many-core hosts should raise it toward cores/2 up to
/// [`MAX_UDP_EGRESS_CONNS`]. 1 restores the single bulk connection.
pub const DEFAULT_UDP_EGRESS_CONNS: usize = 2;

/// Hard cap on the bulk UDP egress shards. Each shard is a full QUIC
/// connection in both directions (its own congestion window, DATAGRAM buffers,
/// dispatcher task, and a server-side connection + reader), so the cap keeps a
/// `udp_egress_conns` typo from dialing an unbounded fan-out. Sized to the TCP
/// pool's order of magnitude; on a host with more usable cores than this, the
/// remaining parallelism comes from the TCP pool and per-association tasks.
pub const MAX_UDP_EGRESS_CONNS: usize = 8;

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

/// Hard cap on a server's QUIC ingress endpoints (`quic_endpoints`).
///
/// Each endpoint is a full quinn `Endpoint`: its own UDP socket (a
/// `SO_REUSEPORT` group member), receive buffer, CID table and driver task.
/// On Linux the kernel spreads incoming connections across the group, which
/// is how the server's packet ingress — one `recv`-loop task and one CID
/// lookup per datagram before this — uses more than one core; platforms that
/// do not spread default to a single endpoint, so see
/// [`default_quic_endpoints`] for the real rule. The cap bounds the kernel
/// receive-buffer footprint (`cap × rmem_max`) and the per-endpoint driver
/// wakeups an overloaded host pays; past it the extra parallelism is better
/// spent on per-connection tasks. Sized to the same order as the client's
/// connection fan-out (`MAX_POOL_CONNS`, 16): on Linux the default is already
/// one endpoint per usable core, so the cap only binds on hosts with more than
/// 16 cores (and bounds what an explicit `quic_endpoints` may request).
pub const MAX_QUIC_ENDPOINTS: usize = 16;

/// Default [`ServerConf::quic_endpoints`] when the key is unset.
///
/// Linux spreads a `SO_REUSEPORT` group across its members by connection
/// 4-tuple, so one endpoint per usable core is the useful default there —
/// bounded by [`MAX_QUIC_ENDPOINTS`], and derived from
/// `available_parallelism` so a cgroup's CPU limit is respected rather than
/// the host's core count.
///
/// Everywhere else the default is 1, because every other platform we can
/// measure does not spread at all: macOS (verified on this codebase, see the
/// `udp_reuseport_group_*` tests) delivers the whole group's traffic to a
/// single member — the most recently bound one — so extra members there are
/// sockets and idle driver tasks, not ingress parallelism. An explicit
/// `quic_endpoints > 1` is still honored on those platforms (the server warns
/// that it buys nothing) rather than silently ignored, because the
/// measurement is a property of the kernel, not of this binary.
pub fn default_quic_endpoints() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, MAX_QUIC_ENDPOINTS)
    } else {
        1
    }
}

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

/// Default path MTU (max UDP payload) every new connection starts from before
/// PMTU discovery runs, in bytes.
///
/// quinn's default is the 1200-byte QUIC floor, and its discovery is
/// opportunistic: probes are only emitted from a transmit poll that builds
/// no payload packet (`quinn-proto connection/mod.rs`), so a busy connection
/// can spend a long time at whatever value it started at. Starting at 1360
/// removes most of that ramp and is safe on tunnel paths too: 1360 B of
/// payload is 1388 wire bytes with IPv4+UDP overhead and 1408 with IPv6+UDP,
/// both inside the 1420-byte WireGuard interface MTU (and inside PPPoE's 1492
/// and a 1500-byte Ethernet MTU). It is not a claim that every path is 1500:
/// operators on a known 1500-byte Ethernet path can raise `initial_mtu` to
/// 1400 or 1472. A path smaller than the configured start is handled by
/// quinn's black-hole detector, which resets to `min_mtu` (1200) on
/// suspicious loss.
pub const DEFAULT_INITIAL_MTU: u16 = 1360;
/// Lower clamp for `initial_mtu`: the QUIC minimum.
pub const INITIAL_MTU_MIN: u16 = 1200;
/// Upper clamp for `initial_mtu`: quinn's default endpoint
/// `max_udp_payload_size` (1500 - 28). Larger values would only be a typo.
pub const INITIAL_MTU_MAX: u16 = 1472;

/// Runtime transport tuning resolved from optional TOML fields.
/// Defaults are the high-throughput preset for ~140 ms links (4/8/4 MB
/// windows, ACK threshold 2, 5 ms delay): ~240 Mb/s @140 ms with a modest
/// loaded queue. The old 2/4/2 MB low-memory preset (~114 Mb/s) is available
/// by setting all three windows explicitly, and 8/16/8 MB reaches ~300 Mb/s
/// peak at the cost of ~2x/4x loaded latency.
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
    /// Path MTU (max UDP payload) a connection uses before PMTU discovery
    /// starts, in bytes: `INITIAL_MTU_MIN..=INITIAL_MTU_MAX`. See
    /// [`DEFAULT_INITIAL_MTU`] for why starting above quinn's 1200-byte floor
    /// is a direct latency/throughput win.
    pub initial_mtu: u16,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            stream_receive_window: 4 * 1024 * 1024,
            receive_window: 8 * 1024 * 1024,
            send_window: 4 * 1024 * 1024,
            ack_threshold: 2,
            max_ack_delay: Duration::from_millis(5),
            initial_rtt: Duration::from_millis(DEFAULT_INITIAL_RTT_MS),
            initial_mtu: DEFAULT_INITIAL_MTU,
        }
    }
}

fn initial_rtt_from_ms(v: Option<u64>) -> Duration {
    Duration::from_millis(
        v.unwrap_or(DEFAULT_INITIAL_RTT_MS)
            .clamp(INITIAL_RTT_MS_MIN, INITIAL_RTT_MS_MAX),
    )
}

fn initial_mtu_from(v: Option<u16>) -> u16 {
    v.unwrap_or(DEFAULT_INITIAL_MTU)
        .clamp(INITIAL_MTU_MIN, INITIAL_MTU_MAX)
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
///
/// **Linux doubles the value.** `setsockopt(SO_RCVBUF/SO_SNDBUF, n)` stores
/// `2 * n` inside the kernel (bookkeeping overhead) and `getsockopt` returns
/// the doubled value, so the socket memory cap actually pinned per session is
/// `4 * sess_socket_buf()` on Linux — must be charged here or the admission
/// bound under-counts the pool by ~2x (`session_pool_memory_bytes`), which is
/// exactly the kind of under-count an OOM on a 128 MiB router rides in on.
/// Other platforms keep the requested value.
#[must_use]
pub fn per_session_memory_bytes() -> u64 {
    let socket_terms = if cfg!(target_os = "linux") {
        // SO_RCVBUF and SO_SNDBUF, each doubled by the kernel.
        2 * (2 * crate::sess_socket_buf())
    } else {
        2 * crate::sess_socket_buf()
    };
    (socket_terms + crate::UDP_RECV_MAX + crate::UDP_RECV_SLACK) as u64
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
            stream_receive_window: clamp_window_mb(self.stream_receive_window_mb, 4),
            receive_window: clamp_window_mb(self.receive_window_mb, 8),
            send_window: clamp_window_mb(self.send_window_mb, 4),
            ack_threshold: self.ack_threshold.unwrap_or(2).clamp(1, 32),
            max_ack_delay: Duration::from_millis(self.max_ack_delay_ms.unwrap_or(5).clamp(1, 25)),
            initial_rtt: initial_rtt_from_ms(self.initial_rtt_ms),
            initial_mtu: initial_mtu_from(self.initial_mtu),
        }
    }
}

impl ClientConf {
    pub fn tuning(&self) -> TransportTuning {
        TransportTuning {
            stream_receive_window: clamp_window_mb(self.stream_receive_window_mb, 4),
            receive_window: clamp_window_mb(self.receive_window_mb, 8),
            send_window: clamp_window_mb(self.send_window_mb, 4),
            ack_threshold: self.ack_threshold.unwrap_or(2).clamp(1, 32),
            max_ack_delay: Duration::from_millis(self.max_ack_delay_ms.unwrap_or(5).clamp(1, 25)),
            initial_rtt: initial_rtt_from_ms(self.initial_rtt_ms),
            initial_mtu: initial_mtu_from(self.initial_mtu),
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
