use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

use super::client_conf::ClientConf;
use super::server_conf::ServerConf;

// `DATAGRAM_BUFFER` still lives in `src/lib.rs` (transport section, not yet
// split); refer to it at the crate root until it moves with that section.
use crate::DATAGRAM_BUFFER;
use crate::FRAG_MAX_HELD_BYTES;
use crate::dns::resolve::DNS_SLOW_PATH_PERMITS;
use crate::mqp::r2_flow::{FlowBinding, R2_MAX_FLOWS_PER_CONN, SessionFlows};
use crate::mqp::v3::MQP3_FLOW_TABLE_MAX_BYTES;
use crate::transport::{DEFAULT_IDLE_TIMEOUT_SECS, resolve_idle_timeout_secs};
use crate::udp::r2_stage::{R2_STAGE_MAX_BYTES, R2_STAGE_MAX_ITEMS, R2StageItem};
use crate::udp::retry::{UDP_RETRY_DEPTH, UDP_RETRY_INFLIGHT, UDP_RETRY_SHARDS};
use crate::udp::{BURST_SLOT, LAST_HOP_DRAIN};

/// Rev2 ingress state outside the transport windows and outside this crate's
/// type-visible per-connection structures: the pre-HELLO frame buffer
/// (16 KiB, `accept.rs::PRE_HELLO_MAX_BYTES`), the fast session table, and the
/// small fixed maps next to them. A conservative single term keeps the
/// admission bound from depending on binary-private types.
///
/// The fast session table (`FAST_SESS_SLOTS` in `myquic2-server/accept.rs`) is
/// sized from the same array budget the old 128 × 432 B table used. Each
/// `FastSess` is now 128 B — the inline `ConnPin` moved to the bounded
/// `DOMAIN_PIN_SLOTS` side cache because its only reader is the INLINE/legacy
/// path — so the same ~55.4 KiB carries ~405 slots. The side cache adds
/// 48 × ~304 B ≈ 14 KiB. With the 16 KiB pre-HELLO buffer and the surrounding
/// maps, 96 KiB remains a round, conservative charge; the slot count is
/// derived from `size_of::<FastSess>()` in `accept.rs`, so the arithmetic
/// cannot drift silently.
pub const R2_INGRESS_FIXED_BYTES: u64 = 96 * 1024;

/// Per-flow allocation slack on top of `size_of::<FlowBinding>()`: the `Arc`
/// header (16 B), the target's domain name up to the 255-byte wire limit, and
/// the bounded resolved set (`R2_MAX_RESOLVED_ADDRS` × 32-byte `SocketAddr`
/// plus the `Arc`/`Vec` headers). That is 823 B; 832 keeps the arithmetic
/// round. Name and resolved set exist only for domain flows, but admission
/// must bound the peer-fillable worst case.
///
/// The newer per-binding `reply_src` `ArcSwapOption<SocketAddr>` allocation and
/// the transient retention of a previous copy-on-write snapshot are not in the
/// 823 B derivation; they are small (~48 B + one retired snapshot) relative to
/// this slack and are left to the round-up, but a layout change that grows
/// `FlowBinding` must re-derive the figure (the size term above picks up inline
/// fields automatically; heap fields do not).
pub const R2_FLOW_HEAP_SLACK_BYTES: u64 = 832;

/// `VecDeque` allocates a minimum of eight slots on its first push. With one
/// item in each of `R2_STAGE_MAX_ITEMS` sessions, the stager's item storage is
/// therefore eight slots per queued item, not one — the packed-burst average is
/// much lower, but admission has to bound the worst case.
pub const R2_STAGER_SLOT_FACTOR: usize = 8;

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
/// a client's worst case is
/// `MAX_POOL_CONNS + MAX_UDP_INTERACTIVE_CONNS + MAX_UDP_EGRESS_CONNS` with
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

/// Default number of dedicated **interactive** UDP egress connections.
///
/// The interactive class is the latency-sensitive population (STUN/DTLS media,
/// games, DNS, anything whose first datagram is ≤ 512 B), and every association
/// in it shares its connection's 1 MiB DATAGRAM send buffer, 256 KiB stager and
/// one congestion window. One connection therefore makes the class a single
/// shared queue: an association that bursts can push every other one into a
/// `Blocked` drop, and one loss event shrinks the window for all of them. Two
/// halves that contention for one extra dial; raise it toward
/// [`MAX_UDP_INTERACTIVE_CONNS`] on hosts that front many small-flow
/// associations, and set 1 to keep the single stable connection.
pub const DEFAULT_UDP_INTERACTIVE_CONNS: usize = 2;

/// Hard cap on the interactive UDP egress shards: the same full-connection cost
/// as [`MAX_UDP_EGRESS_CONNS`], and the two together bound the UDP egress range
/// at `MAX_UDP_SLOTS` (`MAX_UDP_INTERACTIVE_CONNS + MAX_UDP_EGRESS_CONNS`, 16)
/// scratch slots in `myquic2-client::egress`.
pub const MAX_UDP_INTERACTIVE_CONNS: usize = 8;

/// Hard cap on the bulk UDP egress shards. Each shard is a full QUIC
/// connection in both directions (its own congestion window, DATAGRAM buffers,
/// dispatcher task, and a server-side connection + reader), so the cap keeps a
/// `udp_egress_conns` typo from dialing an unbounded fan-out. Sized to the TCP
/// pool's order of magnitude; on a host with more usable cores than this, the
/// remaining parallelism comes from the TCP pool and per-association tasks.
pub const MAX_UDP_EGRESS_CONNS: usize = 8;

/// Concurrent bidirectional streams one QUIC connection may carry **after
/// authentication**.
///
/// This is the credit the server raises to once the client's token is verified,
/// and `Connection::open_bi()` parks until the *peer's* credit allows — so it
/// must cover the largest number of TCP flows that can land on a single
/// connection. The client admits up to `MAX_SOCKS_CONNS` (8192) SOCKS
/// connections process-wide and `interactive_ports` pinning can put every TCP
/// flow on slot 0, hence 8192; every smaller value lets an *admitted* flow stall
/// in `open_bi()` for the client's 5 s timeout and then answer SOCKS `REP=0x01`
/// while the process still has stream-task capacity. The server's
/// `MAX_STREAM_TASKS` process-wide task bound stays the overload backstop,
/// exactly as before.
///
/// The handshake itself advertises only
/// [`SERVER_PRE_AUTH_BIDI_CREDIT`] bidi streams: every advertised slot is a
/// peer-pinnable quinn receive assembler, and an unauthenticated peer must not
/// be able to park them. MAX_STREAMS is increase-only, so raising to this value
/// after the token check is protocol-legal.
///
/// (An earlier revision hard-coded 1024 here, which was inconsistent with the
/// client's 8192-connection admission cap: with the default four-connection
/// pool only 4096 concurrent TCP flows could ever be open, and the 4097th+
/// stalled before failing. The client bin asserts `MAX_SOCKS_CONNS <=
/// MAX_BIDI_STREAMS_PER_CONN` so the two can never drift apart again.)
pub const MAX_BIDI_STREAMS_PER_CONN: u32 = 8192;

/// Bidirectional-stream credit the server advertises **before authentication**.
///
/// The full [`MAX_BIDI_STREAMS_PER_CONN`] credit is what an authenticated client
/// needs, but a peer that completes the handshake and then stalls the token
/// exchange can fill the whole connection receive window with gapped one-byte
/// frames; each peer-opened stream keeps up to quinn's `MAX_CHUNKS = 1024` gap
/// spans, so advertising the full credit in the handshake would let one
/// unauthenticated connection pin hundreds of MiB before proving it holds the
/// token. The handshake therefore advertises this bounded credit, and the server
/// raises it to [`MAX_BIDI_STREAMS_PER_CONN`] with MAX_STREAMS as soon as
/// authentication succeeds.
///
/// It is **64, not 4**, because MAX_STREAMS is increase-only *and* 0-RTT clients
/// use the credit they remember from the previous handshake's ServerHello
/// (quinn-proto `Connection::init_0rtt` restores the ticket's transport
/// parameters). A resumed client can therefore open TCP relay streams in its
/// very first flight, long before the post-auth MAX_STREAMS arrives: with a
/// pre-auth credit of 4 only four concurrent TCP flows per connection could ride
/// 0-RTT early data, which at the shipped 4-connection pool is 16 early flows on
/// a redial — a thundering-herd sized cliff for exactly the reconnect burst the
/// pool produces. 64 covers one connection's share of a realistic reconnect
/// burst (`MAX_POOL_CONNS` x 64 = 1024 early flows process-wide) while still
/// bounding an unauthenticated peer to 64 x 1024 x 96 B = 6 MiB of quinn receive
/// assemblers for the 5 s pre-auth window; the much larger
/// [`MAX_BIDI_STREAMS_PER_CONN`] credit stays post-auth only. The extra
/// peer-pinnable memory is charged through [`pre_auth_stream_memory_bytes`].
pub const SERVER_PRE_AUTH_BIDI_CREDIT: u32 = 64;

/// Unidirectional-stream credit the server advertises (and keeps).
///
/// The protocol uses at most two client→server uni streams: the auth token sent
/// in 0-RTT early data and, when that early data is rejected (or its stream
/// write failed structurally), the same token re-sent on a fresh 1-RTT stream
/// after the handshake completes. 8 leaves margin for that retry (a
/// structurally failed early attempt can consume one stream slot per dial) and
/// for a peer that opens a few extra streams, while keeping the peer-pinnable
/// assembler charge bounded; the client never opens one for data and the server
/// never opens one at all.
pub const SERVER_UNI_STREAM_CREDIT: u32 = 8;

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

/// Concurrent TCP relay connections one *client process* may admit, shared by
/// the SOCKS5 `CONNECT` accept loop and every `[[tcp_forward]]` listener.
///
/// It lives here, next to [`MAX_UDP_ASSOCS`], because the client config derives
/// the forwarded-connection budget from it: if the config's idea of the cap and
/// the runtime semaphore's size ever diverged, a `[[tcp_forward]]` entry could
/// reserve more permits than the process actually owns, and the deliberate
/// "forwarding cannot multiply the fd/task ceiling" property would silently
/// break. The client bin imports this through `myquic2::*`.
pub const MAX_SOCKS_CONNS: usize = 8192;

/// Default process-wide budget for `[[tcp_forward]]` connections: 3/4 of
/// [`MAX_SOCKS_CONNS`], so at least 1/4 of the relay permits always stays
/// available to the SOCKS5 endpoint.
///
/// Before this budget existed a forward listener had no admission cap at all:
/// one exposed listener could hold all 8192 permits (a zero-byte flow keeps its
/// permit for the 300 s idle window) and refuse every subsequent SOCKS5
/// CONNECT. The budget bounds that shared-resource denial; an operator who
/// really wants the whole cap for forwarding raises `max_forward_conns`.
pub const DEFAULT_FORWARD_CONNS: usize = MAX_SOCKS_CONNS - MAX_SOCKS_CONNS / 4;

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
/// spent on per-connection tasks. Sized to half the client's TCP pool cap
/// (`MAX_POOL_CONNS`, 16): on Linux the default is already one
/// endpoint per usable core, so the cap only binds on hosts with more than
/// 8 cores (and bounds what an explicit `quic_endpoints` may request).
pub const MAX_QUIC_ENDPOINTS: usize = 8;

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
/// PMTU discovery runs, in bytes: the 1200-byte QUIC floor, the smallest start
/// a QUIC endpoint may use.
///
/// QUIC cannot go below 1200: Initial packets are padded to at least 1200 B,
/// smaller ones must be discarded, and `max_udp_payload_size` is only legal
/// down to 1200 — quinn's `TransportConfig::initial_mtu()` raises anything
/// lower, as does this crate's `initial_mtu_from`. Staying at the floor costs
/// throughput until discovery climbs: quinn's PMTU discovery is opportunistic
/// (probes are only emitted from a transmit poll that builds no payload packet,
/// `quinn-proto connection/mod.rs`), so a busy connection can sit at 1200 for a
/// long time — ~18-23% more packets, and every UDP payload above 1150 B splits
/// into two MQP-2 fragments (the DATAGRAM budget is 1162 B at 1200).
///
/// A deployment whose path is known should raise it: 1360 B of payload is 1388
/// wire bytes with IPv4+UDP overhead and 1408 with IPv6+UDP, both inside the
/// 1420-byte WireGuard interface MTU (and inside PPPoE's 1492 and a 1500-byte
/// Ethernet MTU); a known 1500-byte Ethernet path can use 1400 or 1472. A
/// configured start above the real path is handled by quinn's black-hole
/// detector, which resets to `min_mtu` (1200) on suspicious loss.
pub const DEFAULT_INITIAL_MTU: u16 = 1200;
/// Lower clamp for `initial_mtu`: the QUIC minimum, and the shipped default.
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
    /// starts, in bytes: `INITIAL_MTU_MIN..=INITIAL_MTU_MAX`. The default is
    /// the 1200-byte QUIC floor; see [`DEFAULT_INITIAL_MTU`] for what starting
    /// at the floor costs and how to raise it on a known path.
    pub initial_mtu: u16,
    /// QUIC idle timeout in seconds, independent of the keepalive interval.
    ///
    /// The default is [`DEFAULT_IDLE_TIMEOUT_SECS`] (60 s) with the shipped
    /// 5 s keepalive: the client derives a 40 s silence watchdog (`2/3 x
    /// idle`) and a 22 s selection-time stale gate from it. `keep_alive_secs`
    /// remains the NAT refresh cadence; it no longer sets the liveness window.
    pub idle_timeout_secs: u64,
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
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
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
/// - both per-connection reassembly budgets ([`FRAG_MAX_HELD_BYTES`] each): the
///   legacy MQP-2 and the rev2 reassembler run side by side during the wire
///   transition, and a peer that sends fragments it never completes pins each
///   until the partials expire;
/// - the rev2 egress stager (its byte cap plus the per-item queue-node/`Bytes`
///   overhead), the pre-HELLO/fast-session ingress state, and the connection's
///   flow registry at its 4096-binding cap (each binding is an `Arc` plus its
///   target/resolved set). Those are peer-fillable even though they are not
///   part of quinn's transport state;
/// - the quinn receive assemblers for the streams the **handshake** advertises
///   (see [`pre_auth_stream_memory_bytes`]): an unauthenticated connection can
///   hold that many stream slots for the authentication budget, so it is
///   charged per admitted connection. The larger post-auth parked-header bound
///   is a process-wide fixed term instead.
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
    let stager = R2_STAGE_MAX_BYTES as u64
        + (R2_STAGE_MAX_ITEMS * std::mem::size_of::<R2StageItem>() * R2_STAGER_SLOT_FACTOR) as u64;
    let registry = R2_MAX_FLOWS_PER_CONN as u64
        * (std::mem::size_of::<FlowBinding>() as u64 + R2_FLOW_HEAP_SLACK_BYTES);
    tuning
        .receive_window
        .saturating_add(tuning.send_window)
        .saturating_add(2 * DATAGRAM_BUFFER as u64)
        .saturating_add(2 * FRAG_MAX_HELD_BYTES as u64)
        .saturating_add(stager)
        .saturating_add(R2_INGRESS_FIXED_BYTES)
        .saturating_add(registry)
        .saturating_add(pre_auth_stream_memory_bytes())
}

/// Inline size of the rev2 reverse table ([`SessionFlows`]): a fixed
/// `[Option<Arc<FlowBinding>>; R2_MAX_FLOWS_PER_SESSION]` array. Computed from
/// the type itself so a layout change cannot silently escape admission.
const SESSION_FLOWS_BYTES: u64 = std::mem::size_of::<SessionFlows>() as u64;

/// Inline size of the server's `RecentAddrs` destination ring
/// (`src/bin/myquic2-server/pin.rs`, binary-private): a 16-slot
/// `[Option<IpAddr>; 16]` array (272 B — [`IpAddr`](std::net::IpAddr) is 17 B
/// and `Option<IpAddr>` has no niche to shrink it) plus the 8-byte write
/// position = 280 B.
///
/// **Cross-crate invariant.** The 16 here mirrors `RECENT_DST_CAP` in the
/// server binary, which cannot be imported (binary-private). The server's tests
/// assert `RECENT_DST_CAP` against a matching constant, so a future change that
/// raises the ring must update this derivation too — otherwise admission
/// silently under-counts the per-session tables by
/// `(cap - 16) * size_of::<Option<IpAddr>>()` per session.
const RECENT_ADDRS_BYTES: u64 =
    (16 * std::mem::size_of::<Option<std::net::IpAddr>>() + std::mem::size_of::<usize>()) as u64;

/// Conservative per-session charge for the server's rev2 bookkeeping tables,
/// on top of the MQP-3 v0.2 flow table covered by
/// [`MQP3_FLOW_TABLE_MAX_BYTES`] and the socket/reader terms in
/// [`per_session_memory_bytes`].
///
/// The server keeps two more per-session tables, both published as
/// clone-on-write `ArcSwap` snapshots so the reply reader validates a source
/// without taking a lock:
///
/// - [`SessionFlows`]: the rev2 reverse table, `SESSION_FLOWS_BYTES` inline
///   (512 B on a 64-bit host);
/// - `RecentAddrs`: the destination allowlist, `RECENT_ADDRS_BYTES` inline
///   (280 B on a 64-bit host).
///
/// 792 B of inline data is not the bound. An `ArcSwap` store keeps the
/// previous snapshot alive until every reader's hazard pointer is released, so
/// two copies of each can coexist, and each snapshot is itself a heap
/// allocation with an `Arc` header:
/// `2 x (16 + 512) + 2 x (16 + 280) = 1,648 B` on a 64-bit host. The charge
/// derives from the two table sizes and rounds up to the next power of two
/// (2,048 B, asserted below), which also covers allocator size-class rounding.
pub const R2_SESSION_TABLES_BYTES: u64 = {
    let arc_header = std::mem::size_of::<usize>() as u64;
    let two_snapshots =
        2 * (arc_header + SESSION_FLOWS_BYTES) + 2 * (arc_header + RECENT_ADDRS_BYTES);
    two_snapshots.next_power_of_two()
};

// Pin the round charge: the derived worst case must stay inside the documented
// 2 KiB figure, or admission is under-counting the copy-on-write tables.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(R2_SESSION_TABLES_BYTES == 2048);

/// Worst-case memory one UDP session can pin, in bytes: the session socket's
/// send *and* receive caps (`sess_socket_buf()` each way) plus the reply
/// reader's userspace receive buffer (`UDP_RECV_MAX + UDP_RECV_SLACK`), plus
/// the session's two flow tables — the MQP-3 v0.2 table at its domain-target
/// worst case ([`MQP3_FLOW_TABLE_MAX_BYTES`]) and the rev2 copy-on-write
/// bookkeeping ([`R2_SESSION_TABLES_BYTES`]).
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
    (socket_terms + crate::UDP_RECV_MAX + crate::UDP_RECV_SLACK + MQP3_FLOW_TABLE_MAX_BYTES) as u64
        + R2_SESSION_TABLES_BYTES
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

/// Bytes of userspace receive buffer quinn allocates per QUIC endpoint at
/// construction, before any connection exists: `max_udp_payload_size (1472) x
/// GRO segments x BATCH_SIZE`. On Linux quinn-udp 0.5.16 enables `UDP_GRO` and
/// sizes its receive scratch for `UDP_GRO_CNT_MAX` = 64 segments x 32-message
/// `recvmmsg` batches (`unix.rs`), i.e. 1472 x 64 x 32 = **3,014,656 B
/// (2.875 MiB) per endpoint**. Other platforms do not GRO (one segment), so the
/// charge there is a single datagram. This is a *resident* allocation made by
/// `Endpoint::new_with_abstract_socket`, not a per-connection cap, and
/// `per_connection_memory_bytes` does not cover it — admission charges
/// [`endpoint_memory_bytes`] as a process-wide fixed term instead.
pub const fn endpoint_recv_buffer_bytes() -> u64 {
    if cfg!(target_os = "linux") {
        1472 * 64 * 32
    } else {
        1472
    }
}

/// Worst-case memory one QUIC endpoint pins: its resident userspace receive
/// buffer plus both kernel socket caps at the Linux-doubled
/// [`ENDPOINT_SOCKET_BUF`](crate::ENDPOINT_SOCKET_BUF) (4 MiB requested per
/// direction x 2 for the kernel doubling x 2 directions = 16 MiB on Linux).
///
/// These are caps, not reservations, except the userspace buffer which is
/// `vec![0; ...]` at construction. Charged once per endpoint (client pool slot
/// / server `quic_endpoints` member) because neither is covered by the
/// per-connection term.
#[must_use]
pub fn endpoint_memory_bytes(count: usize) -> u64 {
    let socket_caps = if cfg!(target_os = "linux") {
        2 * (2 * crate::ENDPOINT_SOCKET_BUF)
    } else {
        2 * crate::ENDPOINT_SOCKET_BUF
    };
    (count as u64).saturating_mul(endpoint_recv_buffer_bytes() + socket_caps as u64)
}

/// Worst-case buffers held by `max_streams` concurrent TCP <-> QUIC pump
/// flows.
///
/// Two parts per flow, because the relay holds memory in two places:
///
/// - **userspace**: two [`COPY_CHUNK`](crate::tcp::pump::COPY_CHUNK) buffers
///   (the c2s double buffer, held for the flow's whole life);
/// - **kernel**: the relay TCP socket's send/receive buffers. Those are not
///   covered by the QUIC transport windows and are peer-drivable (the peer
///   points a flow at a target that stops reading, or that floods while the app
///   stops reading), so they are charged here.
///   [`crate::linux::relay_tcp_kernel_bytes_per_flow`] prices the effective
///   configuration: by default the Linux initial sysctl allowance
///   (128 KiB rcv + 16 KiB snd = 144 KiB; autotuning can exceed it), or the
///   exact doubled cap when `MYQUIC2_RELAY_SOCKET_BUF` sets explicit
///   `SO_SNDBUF`/`SO_RCVBUF`.
///
/// The flow count is bounded by the server's `MAX_STREAM_TASKS` / the client's
/// `MAX_SOCKS_CONNS`, and neither term is part of
/// `per_connection_memory_bytes`, so admission charges the product as a
/// process-wide fixed term. At the default allowance the server's 16,384-flow
/// bound is ~2.8 GiB (512 MiB userspace + ~2.25 GiB kernel allowance), which is
/// why the startup line prints this term separately; an operator on a
/// memory-tight host lowers it with `MYQUIC2_RELAY_SOCKET_BUF` (the charge
/// follows the env override) or by accepting fewer concurrent flows.
#[must_use]
pub fn stream_pump_memory_bytes(max_streams: usize) -> u64 {
    let per_flow =
        2 * crate::tcp::pump::COPY_CHUNK as u64 + crate::linux::relay_tcp_kernel_bytes_per_flow();
    (max_streams as u64).saturating_mul(per_flow)
}

/// Worst-case payload bytes the process-wide UDP retry pools can hold.
///
/// Each of the `UDP_RETRY_SHARDS` shard workers owns a `UDP_RETRY_DEPTH`-slot
/// pending queue plus up to `UDP_RETRY_INFLIGHT` sends waiting on their
/// retransmit timers, and every entry carries one payload buffer of up to
/// [`UDP_RECV_MAX`](crate::UDP_RECV_MAX) bytes (the retry units are whole
/// datagrams, so the payload is copied into the pool, not borrowed from the
/// caller).
///
/// This is not a transient burst allowance: it is a pool a peer can drive to
/// its cap. A datagram addressed to a black-holed target is retried until the
/// retry deadline, and on a saturated uplink (full `SO_SNDBUF`, where
/// `WouldBlock` is the steady state rather than an exception) every send goes
/// through this queue, so the depth stays full as long as the peer keeps
/// sending. Charged once, process-wide, because every peer shares the shards.
#[must_use]
pub fn retry_pool_memory_bytes() -> u64 {
    let per_shard = (UDP_RETRY_DEPTH + UDP_RETRY_INFLIGHT) as u64 * crate::UDP_RECV_MAX as u64;
    (UDP_RETRY_SHARDS as u64).saturating_mul(per_shard)
}

/// Host-name bytes counted per DNS slow-path waiter: the DNS wire limit.
const DNS_WAITER_HOST_BYTES: u64 = 255;

/// Fixed structure overhead counted per DNS slow-path waiter, on top of the
/// payload and host name: the spawned task's header, the future state the
/// resolver await holds, and the `Arc` handles it clones into the task. The
/// payload retention is already covered by the payload term above.
const DNS_WAITER_STRUCT_BYTES: u64 = 512;

/// Worst-case resolver-waiter state the DNS slow path can hold.
///
/// The slow path is gated by the [`DNS_SLOW_PATH_PERMITS`]-permit semaphore in
/// `dns::resolve`; a permit can have one spawned resolver task alive, and that
/// task owns the datagram payload it was spawned for (at most
/// [`UDP_RECV_MAX`](crate::UDP_RECV_MAX) bytes) plus an owned copy of the host
/// name (at most the 255-byte DNS wire limit) plus fixed task/future structure
/// (`DNS_WAITER_STRUCT_BYTES`). A peer drives this to the cap with unique
/// unresolvable domain targets — every one spawns a waiter that sits in the
/// upstream query until it times out — so admission charges the full permit
/// count, once, process-wide.
#[must_use]
pub fn dns_inflight_memory_bytes() -> u64 {
    (DNS_SLOW_PATH_PERMITS as u64).saturating_mul(
        crate::UDP_RECV_MAX as u64 + DNS_WAITER_HOST_BYTES + DNS_WAITER_STRUCT_BYTES,
    )
}

/// Idle session read buffers the server pools per worker thread.
///
/// Mirrors `SESS_BUF_POOL_DEPTH` in `src/bin/myquic2-server/reader.rs` (binary
/// private, so it cannot be imported here): the thread-local pool holds at most
/// this many buffers, each `UDP_RECV_MAX + UDP_RECV_SLACK` bytes. A change
/// there must update this constant.
const SERVER_SESS_BUF_POOL_DEPTH: usize = 8;

/// Worst-case per-thread scratch memory the server's datagram paths allocate.
///
/// Two thread-locals live on every server worker thread that runs an ingress
/// or dispatcher path, and neither is released while the thread lives:
///
/// - the `recvmmsg` burst scratch ([`LAST_HOP_DRAIN`] slots of [`BURST_SLOT`]
///   bytes each) — a peer filling every slot drives it to the full size;
/// - the session read-buffer pool (`SERVER_SESS_BUF_POOL_DEPTH` buffers of
///   `UDP_RECV_MAX + UDP_RECV_SLACK` bytes), which a peer fills by keeping that
///   many session readers idle-but-live on one thread.
///
/// `threads` is the number of OS worker threads running those paths (the
/// server's shard runtimes), not the number of tasks; charged once as a
/// process-wide fixed term because the thread count is bounded by the runtime
/// topology, not by the admitted-connection count.
#[must_use]
pub fn worker_scratch_bytes(threads: usize) -> u64 {
    let burst = (LAST_HOP_DRAIN * BURST_SLOT) as u64;
    let sess_pool =
        (SERVER_SESS_BUF_POOL_DEPTH * (crate::UDP_RECV_MAX + crate::UDP_RECV_SLACK)) as u64;
    (threads as u64).saturating_mul(burst + sess_pool)
}

/// quinn-proto 0.11's per-stream reassembly cap: `src/connection/assembler.rs`
/// keeps at most `MAX_CHUNKS = 1024` gap spans per stream (`Assembler::insert`
/// calls `defragment()` once the span count would exceed it).
const QUINN_ASSEMBLER_MAX_CHUNKS: usize = 1024;

/// Bytes charged per quinn assembler span: the span itself plus its retained
/// allocation.
///
/// In quinn-proto 0.11.19 (`src/connection/assembler.rs`, `struct Buffer`) a
/// span is `offset: u64` + `bytes: Bytes` (32 B) + `allocation_size: usize` +
/// `defragmented: bool` = 56 B after padding; each span also pins the packet
/// allocation it was sliced from, of which 40 B is the conservative minimum for
/// the retained datagram/allocator overhead. The admission charge uses this
/// 96-byte figure.
const QUINN_ASSEMBLER_SPAN_BYTES: u64 = 96;

/// Worst-case quinn stream-assembler memory for `parked_streams` streams.
///
/// A TCP stream that delivered a first payload byte but not a complete header
/// keeps quinn's per-stream reassembler state parked for the header-read budget
/// (5 s server-side), and each gap span in it retains a packet allocation. The
/// server bounds the header stage with `HEADER_TASK_CREDIT` parked streams
/// (`src/bin/myquic2-server/accept.rs`), so admission charges this term once as
/// a process-wide fixed cost. The previous bound charged none of it: 4,096
/// header-parked streams can hold 4,096 x 1024 spans, and a peer that never
/// sends a full header controls how many are parked.
#[must_use]
pub fn stream_assembler_memory_bytes(parked_streams: usize) -> u64 {
    let per_stream = (QUINN_ASSEMBLER_MAX_CHUNKS as u64) * QUINN_ASSEMBLER_SPAN_BYTES;
    (parked_streams as u64).saturating_mul(per_stream)
}

/// Worst-case quinn stream-assembler metadata one **pre-auth** connection can
/// park, in bytes.
///
/// The handshake advertises [`SERVER_PRE_AUTH_BIDI_CREDIT`] bidi and
/// [`SERVER_UNI_STREAM_CREDIT`] uni stream slots, and each of those slots can
/// hold a quinn assembler with up to `MAX_CHUNKS = 1024` gap spans. Charged per
/// admitted connection because any connection slot can be in its pre-auth
/// phase; the larger post-auth parked-stream bound is the process-wide
/// [`stream_assembler_memory_bytes`] term instead. Without this term an
/// unauthenticated peer could park stream-assembly state outside every
/// admission charge.
#[must_use]
pub fn pre_auth_stream_memory_bytes() -> u64 {
    let streams = (SERVER_PRE_AUTH_BIDI_CREDIT + SERVER_UNI_STREAM_CREDIT) as u64;
    streams.saturating_mul((QUINN_ASSEMBLER_MAX_CHUNKS as u64) * QUINN_ASSEMBLER_SPAN_BYTES)
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
            idle_timeout_secs: resolve_idle_timeout_secs(
                self.keep_alive_secs,
                self.idle_timeout_secs,
            ),
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
            idle_timeout_secs: resolve_idle_timeout_secs(
                self.keep_alive_secs,
                self.idle_timeout_secs,
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry pool is priced as shards x (queued + in-flight) x one
    /// max-size payload. Pin the product against the constants and the
    /// documented numbers: a typo here under-counts a peer-drivable pool that
    /// is tens of MiB, i.e. a real admission term.
    #[test]
    fn retry_pool_is_shards_times_slots_times_payload() {
        assert_eq!(UDP_RETRY_SHARDS, 16);
        assert_eq!(UDP_RETRY_DEPTH, 256);
        assert_eq!(UDP_RETRY_INFLIGHT, 16);
        assert_eq!(crate::UDP_RECV_MAX, 8192);
        assert_eq!(retry_pool_memory_bytes(), 16 * 272 * 8192);
        assert!(
            retry_pool_memory_bytes() > 32 * 1024 * 1024,
            "the retry pool is worth a fixed admission term (got {} B)",
            retry_pool_memory_bytes()
        );
    }

    /// The DNS term must price one full permit count of worst-case waiters
    /// (max payload + wire-limit name + fixed structure), not just the payload.
    #[test]
    fn dns_inflight_budget_covers_every_permit_at_the_worst_waiter() {
        assert_eq!(DNS_SLOW_PATH_PERMITS, 1024);
        let per_waiter =
            crate::UDP_RECV_MAX as u64 + DNS_WAITER_HOST_BYTES + DNS_WAITER_STRUCT_BYTES;
        assert_eq!(
            dns_inflight_memory_bytes(),
            DNS_SLOW_PATH_PERMITS as u64 * per_waiter
        );
        assert!(
            dns_inflight_memory_bytes() > 8 * 1024 * 1024,
            "a full waiter set must be charged in MiB (got {} B)",
            dns_inflight_memory_bytes()
        );
    }

    /// Worker scratch is linear in the thread count and must include both
    /// thread-locals: the burst scratch and the session read-buffer pool.
    #[test]
    fn worker_scratch_is_linear_in_threads_and_covers_both_thread_locals() {
        let burst = (LAST_HOP_DRAIN * BURST_SLOT) as u64;
        let pool =
            (SERVER_SESS_BUF_POOL_DEPTH * (crate::UDP_RECV_MAX + crate::UDP_RECV_SLACK)) as u64;
        assert_eq!(
            BURST_SLOT,
            crate::UDP_RECV_MAX + crate::SOCKS_UDP_HDR_MAX + crate::UDP_RECV_SLACK
        );
        assert_eq!(worker_scratch_bytes(0), 0);
        assert_eq!(worker_scratch_bytes(1), burst + pool);
        for threads in 1..8 {
            assert_eq!(
                worker_scratch_bytes(threads),
                threads as u64 * (burst + pool)
            );
        }
        assert!(
            worker_scratch_bytes(1) > 256 * 1024,
            "one worker's scratch is 256+ KiB (got {} B)",
            worker_scratch_bytes(1)
        );
    }

    /// The quinn assembler charge is `parked streams x MAX_CHUNKS x per-span`,
    /// with `MAX_CHUNKS = 1024` and 96 B per span (see the quinn-proto
    /// assembler citation on the constants).
    #[test]
    fn stream_assembler_charge_covers_parked_quinn_streams() {
        assert_eq!(QUINN_ASSEMBLER_MAX_CHUNKS, 1024);
        assert_eq!(QUINN_ASSEMBLER_SPAN_BYTES, 96);
        assert_eq!(stream_assembler_memory_bytes(0), 0);
        assert_eq!(stream_assembler_memory_bytes(1), 1024 * 96);
        for parked in [1usize, 2, 64, 4096] {
            assert_eq!(
                stream_assembler_memory_bytes(parked),
                parked as u64 * stream_assembler_memory_bytes(1)
            );
        }
        // The server's header credit is what admission multiplies: 4,096
        // parked streams x 1,024 spans x 96 B = 384 MiB, which is why the term
        // has to be charged.
        assert_eq!(stream_assembler_memory_bytes(4096), 384 * 1024 * 1024);
    }

    /// The per-session rev2 tables are real, bounded heap: a single-copy inline
    /// size plus the copy-on-write snapshot overhead must fit the constant.
    #[test]
    fn r2_session_tables_cover_two_live_snapshots() {
        let arcs = std::mem::size_of::<std::sync::Arc<()>>() as u64;
        assert_eq!(
            SESSION_FLOWS_BYTES,
            (crate::mqp::r2_flow::R2_MAX_FLOWS_PER_SESSION
                * std::mem::size_of::<Option<std::sync::Arc<FlowBinding>>>()) as u64,
            "SessionFlows is one fixed array of Arc slots"
        );
        // `RecentAddrs` is a 16-slot `[Option<IpAddr>; 16]` ring
        // (`Option<IpAddr>` is 17 B: IpAddr has no niche) plus the write pos.
        assert_eq!(
            RECENT_ADDRS_BYTES,
            16 * std::mem::size_of::<Option<std::net::IpAddr>>() as u64
                + std::mem::size_of::<usize>() as u64
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(SESSION_FLOWS_BYTES, 512);
            assert_eq!(RECENT_ADDRS_BYTES, 280);
        }
        let two_snapshots = 2 * (SESSION_FLOWS_BYTES + arcs) + 2 * (RECENT_ADDRS_BYTES + arcs);
        assert!(
            R2_SESSION_TABLES_BYTES >= two_snapshots,
            "the charge must cover two live COW snapshots of both tables ({} < {two_snapshots})",
            R2_SESSION_TABLES_BYTES
        );
    }

    /// The per-session charge is the socket/reader terms plus both flow tables;
    /// dropping a table term is an under-count of the whole global session pool.
    #[test]
    fn per_session_charge_includes_both_flow_tables() {
        let socket_terms = if cfg!(target_os = "linux") {
            2 * (2 * crate::sess_socket_buf())
        } else {
            2 * crate::sess_socket_buf()
        };
        let expected = (socket_terms
            + crate::UDP_RECV_MAX
            + crate::UDP_RECV_SLACK
            + MQP3_FLOW_TABLE_MAX_BYTES) as u64
            + R2_SESSION_TABLES_BYTES;
        assert_eq!(per_session_memory_bytes(), expected);
        assert!(
            per_session_memory_bytes()
                > (MQP3_FLOW_TABLE_MAX_BYTES as u64 + R2_SESSION_TABLES_BYTES),
            "both table terms must be visible in the total"
        );
    }

    /// The TCP relay pump term must price both memory sites per flow: the two
    /// userspace `COPY_CHUNK` buffers *and* the relay socket's kernel buffers
    /// (the initial sysctl allowance by default, the doubled explicit cap when
    /// `MYQUIC2_RELAY_SOCKET_BUF` sets one). Dropping the kernel half was a
    /// fixed-term under-count of gigabytes at the server's flow bound.
    #[test]
    fn stream_pump_charges_userspace_and_relay_kernel_buffers() {
        let userspace = 2 * crate::tcp::pump::COPY_CHUNK as u64;
        let kernel = crate::linux::relay_tcp_kernel_bytes_per_flow();
        let per_flow = userspace + kernel;
        assert!(
            kernel >= crate::linux::RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT,
            "the kernel term is at least the documented initial allowance"
        );
        assert_eq!(stream_pump_memory_bytes(0), 0);
        for flows in [1usize, 8192, 16_384] {
            assert_eq!(
                stream_pump_memory_bytes(flows),
                flows as u64 * per_flow,
                "the pump term must be linear in the flow count"
            );
        }
        // Default allowance: 512 MiB userspace + ~2.25 GiB kernel at the
        // server's 16,384-flow bound, i.e. a multi-GiB fixed term.
        assert!(
            stream_pump_memory_bytes(16_384) > 2 * 1024 * 1024 * 1024,
            "got {} B",
            stream_pump_memory_bytes(16_384)
        );
    }

    /// PERF-4: the rev2 ingress term grew for the fast session table (each slot
    /// carries an inline `ConnPin`); it must stay a round, conservative 96 KiB
    /// rather than drifting back to the 32 KiB figure that covered 16 slots.
    #[test]
    fn r2_ingress_term_covers_the_fast_table() {
        assert_eq!(R2_INGRESS_FIXED_BYTES, 96 * 1024);
        // 128 slots. The payload entry is 440 B today (an inline `ConnPin` is
        // 304 B of it) and the probe arrays add a 4 B tag plus an 8 B stamp per
        // slot, so charge the whole slot; the 16 KiB pre-HELLO buffer and the
        // surrounding maps ride along inside the same term.
        let slots = 128u64;
        let per_slot = 452;
        assert!(
            R2_INGRESS_FIXED_BYTES >= 16 * 1024 + slots * per_slot,
            "term must cover the pre-HELLO buffer and the fast table"
        );
    }

    /// W6: the handshake advertises the raised pre-auth bidi credit so a
    /// resumed client can open TCP relay streams in its **first flight**
    /// (quinn-proto restores the ticket's transport parameters at
    /// `init_0rtt`, so the remembered credit is the 0-RTT stream budget), and
    /// the uni credit leaves room for the early token plus its 1-RTT re-send.
    /// The admission charge must follow the constants: the whole point of the
    /// raise is that the extra peer-pinnable assembler memory is priced.
    /// The two pre-auth credits, read through a function so the assertions
    /// below are runtime checks (clippy rejects `assert!` on constants).
    fn pre_auth_credits() -> (u32, u32) {
        (SERVER_PRE_AUTH_BIDI_CREDIT, SERVER_UNI_STREAM_CREDIT)
    }

    #[test]
    fn pre_auth_stream_credit_covers_early_0rtt_tcp_streams() {
        assert_eq!(pre_auth_credits(), (64, 8));
        // The last four auth uni streams are margin over the two the protocol
        // can actually use (early token + 1-RTT resend), so the pre-auth memory
        // charge cannot be raised without a deliberate decision here.
        assert!(
            pre_auth_credits().1 >= 2,
            "the auth path needs the early token stream and its 1-RTT resend"
        );
        assert!(
            pre_auth_credits().0 <= MAX_BIDI_STREAMS_PER_CONN,
            "the pre-auth credit is raised to the post-auth one, never past it"
        );
        let per_stream = QUINN_ASSEMBLER_MAX_CHUNKS as u64 * QUINN_ASSEMBLER_SPAN_BYTES;
        assert_eq!(pre_auth_stream_memory_bytes(), (64 + 8) * per_stream);
        assert_eq!(pre_auth_stream_memory_bytes(), 72 * 1024 * 96);
        assert!(
            pre_auth_stream_memory_bytes() > 6 * 1024 * 1024,
            "the raised pre-auth credit is a multi-MiB per-connection admission term (got {} B)",
            pre_auth_stream_memory_bytes()
        );
        // And it is actually added into the per-connection admission figure.
        let per_conn = per_connection_memory_bytes(&TransportTuning::default());
        assert_eq!(
            per_conn - pre_auth_stream_memory_bytes() + 72 * 1024 * 96,
            per_conn
        );
    }

    #[test]
    fn session_pool_is_the_per_session_charge_times_the_cap() {
        for sessions in [0usize, 1, 4096, 8192] {
            assert_eq!(
                session_pool_memory_bytes(sessions),
                sessions as u64 * per_session_memory_bytes()
            );
        }
        assert!(
            session_pool_memory_bytes(8192) > 1024 * 1024 * 1024,
            "the global session pool is a GiB-scale fixed term"
        );
    }
}
