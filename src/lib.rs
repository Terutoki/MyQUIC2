//! MyQUIC2 common: MQP-2 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
// `Bytes`/`BytesMut` are used by the unit tests below through `use super::*`.
#[allow(unused_imports)]
use bytes::{Bytes, BytesMut};
// `Instant` is used by the unit tests below through `use super::*`.
#[allow(unused_imports)]
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

/// Relay counters (`udp_stats`/`udp_write`) use thread-local batching: one
/// shared atomic update per 256 records instead of one per packet, so the hot
/// path stays off shared cache lines.
macro_rules! stats_only {
    ($($t:tt)*) => {
        {
            $($t)*
        }
    };
}

pub mod config;
pub mod dns;
pub mod linux;
pub mod mqp;
pub mod stats;
pub mod sync;
pub mod tcp;
pub mod time;
pub mod tls;
pub mod transport;
pub mod udp;

pub use config::{
    client_conf::ClientConf,
    server_conf::ServerConf,
    tuning::{
        DEFAULT_INITIAL_MTU, DEFAULT_INITIAL_RTT_MS, DEFAULT_QUIC_CONNS, DEFAULT_UDP_EGRESS_CONNS,
        INITIAL_MTU_MAX, INITIAL_MTU_MIN, INITIAL_RTT_MS_MAX, INITIAL_RTT_MS_MIN,
        MAX_BIDI_STREAMS_PER_CONN, MAX_POOL_CONNS, MAX_QUIC_ENDPOINTS, MAX_UDP_ASSOCS,
        MAX_UDP_EGRESS_CONNS, TransportTuning, default_quic_endpoints, endpoint_memory_bytes,
        endpoint_recv_buffer_bytes, load_toml, per_connection_memory_bytes,
        per_session_memory_bytes, session_pool_memory_bytes, stream_pump_memory_bytes,
    },
};
pub use time::{coarse::coarse_millis, mono::mono_millis};

pub use mqp::ack::{
    AUTH_TOKEN_MAX_BYTES, MAX_BND_LEN, MAX_TCP_ACK_LEN, MQP_ALPN, MQP_TCP_ACK, MQP_TCP_ACK_MAGIC,
    decode_bnd_addr, encode_bnd_addr, encode_bnd_addr_into, encode_tcp_ack_into, normalize_alpn,
};
pub use mqp::addr::{AddrHeader, TargetAddr, TargetAddrRef};
pub use mqp::batch::{
    BATCH_ITEM_OVERHEAD, BATCH_PREFIX_LEN, BATCH_SMALL_MAX, BatchFrame, BatchItems, BatchRef,
    MAX_BATCH_ITEMS, MQP_DGRAM_BATCH, batch_frame_len, batch_sess, decode_batch, decode_batch_ref,
    encode_batch, is_batch,
};
pub use mqp::datagram::{
    DGRAM_DEFAULT_LIMIT, DGRAM_PREFIX_LEN, MQP_DGRAM_TYPE, decode_datagram, decode_datagram_ref,
    dgram_payload_cap, encode_datagram, encode_datagram_ref_with_limit, encode_datagram_with_limit,
};
pub use mqp::error::MqpError;
pub use mqp::fragment::{
    FRAG_ID_SAFE_WINDOW_MS, FRAG_MAX_HELD_BYTES, FRAG_MAX_PARTIALS, FRAG_PREFIX_LEN,
    FRAG_SWEEP_INTERVAL_MS, FRAG_TIMEOUT_MS, FragmentRef, MIN_PATH_DGRAM_BUDGET, MQP_DGRAM_FRAG,
    MQP_FRAG_MAX_PAYLOAD, MQP_FRAG_MAX_TOTAL, SOCKS_UDP_HDR_MAX, UDP_PAYLOAD_MAX, UDP_RECV_MAX,
    UDP_RECV_SLACK, decode_fragment, dgram_sess, encode_fragment, fragment_chunk_len,
};
pub use mqp::v3::{
    FlowTable, MQP3_FLOW_TABLE_MAX_BYTES, MQP3_FRAG, MQP3_FRAG_PREFIX_LEN, MQP3_KIND_MASK,
    MQP3_MAX_FLOWS, MQP3_MAX_TRAIN_ITEMS, MQP3_NO_FLOW, MQP3_SINGLE, MQP3_TRAIN,
    MQP3_TRAIN_HEADER_LEN, TrainFrame, TrainItem, TrainItemRef, TrainItems, decode_single,
    decode_train, encode_single, encode_train, is_v3, single_frame_len, train_item_len, train_sess,
    v3_sess, varint_len,
};
pub use tls::{
    client_tls_config, gen_self_signed_files, is_placeholder_token, load_cert_der, load_key_der,
    parse_congestion, server_tls_config,
};
pub use transport::{
    Congestion, DGRAM_MAX_WIRE, KEEP_ALIVE_MAX_SECS, RECEIVE_WINDOW, SEND_WINDOW,
    STREAM_RECEIVE_WINDOW, TARGET_BDP_BYTES, TARGET_LINK_BYTES_PER_SEC, TARGET_LINK_RTT,
    build_transport, build_transport_tuned, build_transport_tuned_class, idle_timeout_secs,
    watchdog_silence_secs,
};
// `MQP_DGRAM_MAX` / `clamp_keep_alive` are exercised by the unit tests below
// through `use super::*` (`DATAGRAM_BUFFER` is also read by `config::tuning`).
pub use dns::{
    CachedLookup, DNS_CACHE_TTL_MS, DNS_LOOKUP_TIMEOUT, IpPreference, dns_cache_seed,
    dns_cache_seed_aged, dns_cache_seed_set, dns_neg_cache_seed, dns_slow_path_limiter,
    ip_preference, is_global_ip, lookup_cached_fast, lookup_cached_fast_with_ttl,
    lookup_cached_sync, map_for_dual, resolve_all, resolve_all_cached, resolve_server_addr,
    resolve_server_side, set_ip_preference, unmap,
};
/// Test-only compatibility surface: the unit tests below address the moved
/// DNS internals through the crate root (`use super::*`).
#[allow(unused_imports)]
pub(crate) use dns::{
    DNS_CACHE_MAX, DNS_KEY_BUF, DNS_MEMO, DNS_NEG_MAX, DNS_NEG_TTL, DnsMemoSlot, MEMO_KEY_BYTES,
    MEMO_SETS, MEMO_WAYS, bump_neg_epoch, dns_key, dns_key_owned, dns_memo_hash, dns_memo_set,
    memo_peek_both, memo_put, neg_epoch, negatives, positives,
};
pub use stats::drops::dgram_drops;
pub use stats::udp_stats::{self, UdpSnapshot};
pub use stats::udp_write::{self, UdpWriteSnapshot};
pub use stats::warn::{claim_log_window, claim_log_window_counted, tcp_abort_log_due};
pub use tcp::{copy_tcp_quic, copy_tcp_quic_acked, copy_tcp_quic_idle};
#[allow(unused_imports)]
pub(crate) use transport::{DATAGRAM_BUFFER, MQP_DGRAM_MAX, clamp_keep_alive};
pub use udp::send_udp_batch;
pub use udp::{
    BURST_SLOT, DatagramSend, DgramFragmenter, DgramReassembler, LAST_HOP_DRAIN, PayloadSend,
    SendFrame, UdpWriteDrop, batch_backend, batch_report, burst_msg_copy, record_drain_batch,
    record_extra_syscalls, record_send_group, recv_burst, recvmmsg_available, send_udp_datagram,
    sendmmsg_available, try_send_datagram, udp_try_send, udp_try_send_grouped, udp_try_send_slice,
    with_burst_msg,
};
// `pub(crate)` re-exports for the unit tests below (`use super::*`); unused in
// the non-test build.
#[allow(unused_imports)]
pub(crate) use stats::{NEVER_WARNED, claim_drop_warning, drop_warn_due};
#[allow(unused_imports)]
pub(crate) use tcp::{COPY_CHUNK, reserve_copy_chunk};
#[allow(unused_imports)]
pub(crate) use udp::{
    Partial, UDP_RETRY_DEPTH, UDP_RETRY_INFLIGHT, UDP_RETRY_TIMEOUT, UdpRetry,
    frag_id_reuse_blocked, retry_shards, spawn_retry_worker, tombstone_bytes, udp_retry_submit,
    under_retry_deadline,
};

/// Requested `SO_SNDBUF`/`SO_RCVBUF` for every QUIC **endpoint** socket (one
/// per client pool slot, `quic_endpoints` of them on the server). The kernel
/// stores twice the requested value on Linux, so the real cap is
/// `2 x this` per direction; [`endpoint_memory_bytes`](crate::endpoint_memory_bytes)
/// is what admission charges for it. Session/relay sockets use the much smaller
/// [`sess_socket_buf`] instead: this size times thousands of sessions would OOM
/// a router.
pub const ENDPOINT_SOCKET_BUF: usize = 4 * 1024 * 1024;

/// Dual-stack UDP socket (V6ONLY=0 when bound to ::). Buffer enlarged for GSO bursts.
/// `sess` sockets (per UDP association) should use the small variant to avoid
/// OOM on routers: 4MB x N sessions of kernel memory adds up fast (P3).
pub fn udp_socket_dual(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, ENDPOINT_SOCKET_BUF)
}

/// One member of a `SO_REUSEPORT` group: a multi-endpoint server ingress
/// binds several of these on the same address and lets the kernel spread
/// datagrams across them.
///
/// Not the same thing as `SO_REUSEADDR` (which this crate deliberately does
/// not set on QUIC sockets — see [`udp_socket_dual_impl`]): REUSEPORT lets
/// several sockets of the *same* process bind one address and has the kernel
/// load-balance the datagrams between them. Each member is a full quinn
/// `Endpoint` with its own CID table, receive queue and driver task, so `n`
/// members move the server's receive syscalls and per-packet routing off one
/// core.
///
/// The kernel's spread policy decides whether this buys anything. Linux
/// hashes by connection 4-tuple, so every packet of one QUIC connection keeps
/// landing on the same member — which is what makes this work at all with
/// CID-routed endpoints — and distinct connections fan out across members.
/// macOS does not spread: measured on this codebase, it delivers the whole
/// group's traffic to the most recently bound member (see
/// [`default_quic_endpoints`]). The 4-tuple pinning has consequences worth
/// stating even where it works: a connection whose client changes its 4-tuple
/// (a NAT rebind) is re-hashed to another member whose CID table does not know
/// it and cannot follow it, and any process on the host that also sets
/// REUSEPORT could join the group. Both are why the connection-owning side
/// keeps this opt-in: bind it only when the endpoint count is > 1.
///
/// Returns `EADDRINUSE` on a second bind when REUSEPORT is unavailable; call
/// [`reuse_port_ingress_supported`] first.
#[cfg(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
))]
pub fn udp_socket_dual_reuseport(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_impl(bind, ENDPOINT_SOCKET_BUF, true)
}

/// Whether [`udp_socket_dual_reuseport`] exists on this target. Mirrors the
/// cfg gate of the function itself (rustix's `SO_REUSEPORT` support), so a
/// caller can pick a port-sharing ingress at compile time on every platform.
pub const fn reuse_port_ingress_supported() -> bool {
    cfg!(all(
        unix,
        not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_os = "cygwin"
        ))
    ))
}

/// Bind one QUIC ingress socket: a [`udp_socket_dual_reuseport`] group member
/// when `group` is set and the platform supports it, the strict
/// [`udp_socket_dual`] singleton otherwise.
///
/// `group` on a platform without REUSEPORT is a caller bug (a second grouped
/// bind would fail EADDRINUSE before reaching here), so it is debug-asserted
/// and quietly downgraded to the singleton in release builds rather than
/// panicking a server's startup.
pub fn udp_socket_dual_for_ingress(bind: &str, group: bool) -> Result<std::net::UdpSocket> {
    #[cfg(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    ))]
    if group {
        return udp_socket_dual_reuseport(bind);
    }
    #[cfg(not(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    )))]
    debug_assert!(
        !group,
        "caller must gate the group bind behind reuse_port_ingress_supported()"
    );
    udp_socket_dual(bind)
}

/// Per-session / relay socket buffer, per direction (the default; see
/// [`sess_socket_buf`] for the effective value).
///
/// These are *caps*, not reservations: the kernel only accounts for what is
/// actually queued, but the cap is what a burst can pin. One association moves
/// a single DATAGRAM flow that is already rate-limited by the QUIC congestion
/// window and drained in ≤32-datagram bursts. The kernel charges ~2 KiB of
/// skb overhead per small datagram, so the cap trades burst absorption for a
/// smaller worst case. The aarch64 burst test measured a fixed ~8 dropped
/// packets per association at 64 KiB and ~50 at 16 KiB (128 KiB was zero):
/// 64 KiB is the measured floor and the shipped default, while the kernel side
/// of a full house (8192 server sessions x 128 KiB across both directions) is
/// ~1 GiB. On a RAM-tight router set `MYQUIC2_SESS_SOCKET_BUF=32768` (or
/// `=131072` for zero measured loss on a server); a full-buffer clamp warning
/// names the sysctl to raise otherwise.
pub const SESS_SOCKET_BUF: usize = 64 * 1024;

/// Lower clamp for [`sess_socket_buf`] overrides: below the 16 KiB the burst
/// test measured ~50 drops/association, an override asks for a loss rate the
/// proxy cannot paper over.
pub const SESS_SOCKET_BUF_MIN: usize = 16 * 1024;

/// Upper clamp for [`sess_socket_buf`] overrides: 4 MiB matches the QUIC
/// endpoint's own socket, and past it the per-session kernel cost stops
/// scaling with any real burst.
pub const SESS_SOCKET_BUF_MAX: usize = 4 * 1024 * 1024;

/// Effective per-session / relay socket buffer: [`SESS_SOCKET_BUF`] unless
/// `MYQUIC2_SESS_SOCKET_BUF` (bytes) overrides it, clamped to
/// [`SESS_SOCKET_BUF_MIN`]..=[`SESS_SOCKET_BUF_MAX`].
///
/// Read once per process: the value feeds every session socket and an operator
/// tuning memory/throughput should not be able to change it mid-run per socket.
/// The override exists because the same binary ships to a 1 GiB server and a
/// 128 MiB router; an invalid value falls back to the default (never panics at
/// socket-creation time on a typo).
pub fn sess_socket_buf() -> usize {
    static OVERRIDE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        std::env::var("MYQUIC2_SESS_SOCKET_BUF")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(clamp_sess_socket_buf)
            .unwrap_or(SESS_SOCKET_BUF)
    })
}

/// Clamp an operator-supplied `MYQUIC2_SESS_SOCKET_BUF` value into the
/// supported range. Split out from the env read so the clamp itself is
/// testable without mutating process-global state.
fn clamp_sess_socket_buf(v: usize) -> usize {
    v.clamp(SESS_SOCKET_BUF_MIN, SESS_SOCKET_BUF_MAX)
}

/// The env var that disables the sharded runtime topology, shared by both
/// binaries (see [`shard_runtime_enabled`]).
pub const SHARD_RUNTIME_ENV: &str = "MYQUIC2_SHARD_RUNTIME";

/// Whether the per-slot sharded runtime topology is enabled (the default).
///
/// With sharding on, the server's ingress endpoints and the client's pool
/// slots each run inside their own pinned current-thread runtime, so the
/// endpoint driver, its accept/reconnect loop, its dispatcher and all of the
/// per-packet thread-local state they own stay on one core (see the server's
/// `spawn_ingress_shard` and the client's `spawn_slot_shard`). With
/// `MYQUIC2_SHARD_RUNTIME=0` (also `false`/`off`/`no`) both fall back to the
/// shared multi-thread runtime and work-stealing may migrate those tasks.
///
/// Read once per process: the topology is chosen at startup and a supervisor
/// restart is what applies a change, exactly like `quic_endpoints`.
#[must_use]
pub fn shard_runtime_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| parse_off_flag(std::env::var(SHARD_RUNTIME_ENV).ok().as_deref()))
}

/// Pure flag parser (testable without mutating the process environment):
/// only the documented "off" spellings disable the feature; unset or any
/// other value keeps it on.
fn parse_off_flag(v: Option<&str>) -> bool {
    !matches!(
        v.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
}

/// Per-session / relay sockets: see [`SESS_SOCKET_BUF`] / [`sess_socket_buf`].
pub fn udp_socket_dual_small(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_small_addr(bind.parse()?)
}

/// Per-session / relay sockets addressed by [`SocketAddr`].
///
/// Same contract as [`udp_socket_dual_small`], but for a caller that already
/// holds the address it wants to bind: it removes the `SocketAddr` →
/// `String` (format) → `parse` round trip that the string form forces on the
/// per-association client relay path.
pub fn udp_socket_dual_small_addr(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    udp_socket_dual_impl_addr(addr, sess_socket_buf(), false)
}

/// Dual-stack UDP socket with an explicit buffer size. See
/// [`udp_socket_dual_impl_addr`] for the socket's contract.
pub fn udp_socket_dual_with_size(bind: &str, buf: usize) -> Result<std::net::UdpSocket> {
    udp_socket_dual_impl(bind, buf, false)
}

fn udp_socket_dual_impl(bind: &str, buf: usize, reuse_port: bool) -> Result<std::net::UdpSocket> {
    udp_socket_dual_impl_addr(bind.parse()?, buf, reuse_port)
}

fn udp_socket_dual_impl_addr(
    addr: SocketAddr,
    buf: usize,
    reuse_port: bool,
) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    // No SO_REUSEADDR here: the singleton QUIC socket would let a second
    // instance bind the same port and silently steal packets. REUSEPORT —
    // deliberately *not* REUSEADDR: the two have historically shared a name in
    // configuration files but not semantics — is the one exception, and only
    // when the caller asks for a group member (`reuse_port`); it is set here
    // so it is in force before the bind below.
    #[cfg(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    ))]
    if reuse_port {
        rustix::net::sockopt::set_socket_reuseport(&s, true)
            .map_err(|e| anyhow::anyhow!("SO_REUSEPORT on {addr}: {e}"))?;
    }
    #[cfg(not(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    )))]
    {
        debug_assert!(
            !reuse_port,
            "callers must gate a REUSEPORT group behind reuse_port_ingress_supported()"
        );
        let _ = reuse_port;
    }
    s.set_nonblocking(true)?;
    // The buffer requests are always made: they are per-fd options. Only the
    // *diagnostics* that used to follow them are process-cached, see
    // [`probe_udp_socket_buffers`].
    if s.set_send_buffer_size(buf).is_err() {
        tracing::debug!("udp send buffer {buf} unavailable (raise net.core.wmem_max)");
    }
    if s.set_recv_buffer_size(buf).is_err() {
        tracing::debug!("udp recv buffer {buf} unavailable (raise net.core.rmem_max)");
    }
    probe_udp_socket_buffers(&s, buf);
    s.bind(&addr.into())?;
    // Linux-only, best-effort socket tuning (see `linux::tune_udp_socket`):
    // busy polling when `MYQUIC2_BUSY_POLL` opted in, applied to every UDP
    // socket this crate creates — QUIC endpoints, relay and session sockets.
    linux::tune_udp_socket(&s);
    Ok(s.into())
}

/// Process-wide verdict on one UDP buffer-size request, learned from the first
/// socket of that size and reused by every later one.
///
/// The kernel's clamp is `net.core.{w,r}mem_max` (a per-netns sysctl) plus, on
/// the forcing path, whether the process holds `CAP_NET_ADMIN` — both are
/// identical for every socket the process creates, so re-reading
/// `SO_SNDBUF`/`SO_RCVBUF` on each new session socket paid 4-5 `getsockopt`s
/// per new flow to re-learn an answer that cannot change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BufVerdict {
    /// The plain `SO_SNDBUF` request read back below the request.
    send_clamped: bool,
    /// The plain `SO_RCVBUF` request read back below the request.
    recv_clamped: bool,
    /// `SO_*BUFFFORCE` lifted both clamped directions to the request
    /// (`CAP_NET_ADMIN` present). Only meaningful when [`Self::clamped`];
    /// always false off Linux and when the capability is missing.
    force_ok: bool,
}

impl BufVerdict {
    /// A request is clamped if either direction comes back short.
    #[inline]
    fn clamped(self) -> bool {
        self.send_clamped || self.recv_clamped
    }

    /// Whether a later socket of the same size must re-apply the force.
    ///
    /// `SO_*BUFFFORCE` is per-fd, so a size whose plain request is clamped
    /// still needs the force on every new socket; a force that failed once
    /// (no `CAP_NET_ADMIN`) is not retried — that is the two syscalls per
    /// session socket the cache exists to remove.
    #[inline]
    fn needs_force(self) -> bool {
        self.clamped() && self.force_ok
    }
}

/// Pure first-socket classifier: `None` means the `getsockopt` failed, which is
/// not evidence of a clamp (same `is_some_and` rule the old inline code used,
/// so a kernel that merely refuses one read cannot page an operator).
fn classify_buf_verdict(
    buf: usize,
    send_actual: Option<usize>,
    recv_actual: Option<usize>,
) -> BufVerdict {
    let short = |actual: Option<usize>| actual.is_some_and(|a| a < buf);
    BufVerdict {
        send_clamped: short(send_actual),
        recv_clamped: short(recv_actual),
        force_ok: false,
    }
}

/// Which process-wide probe slot a buffer size uses.
///
/// Only the two sizes production asks for are cached: the per-session/relay
/// buffer ([`sess_socket_buf`], the per-new-flow hot path this exists for) and
/// the QUIC endpoint buffer ([`ENDPOINT_SOCKET_BUF`], created once per
/// endpoint). An arbitrary [`udp_socket_dual_with_size`] value keeps the full
/// per-socket diagnostics — correct, just uncached; only tests and embedders
/// reach it.
fn buf_probe_slot(buf: usize) -> Option<&'static std::sync::OnceLock<BufVerdict>> {
    static SESSION: std::sync::OnceLock<BufVerdict> = std::sync::OnceLock::new();
    static ENDPOINT: std::sync::OnceLock<BufVerdict> = std::sync::OnceLock::new();
    if buf == sess_socket_buf() {
        Some(&SESSION)
    } else if buf == ENDPOINT_SOCKET_BUF {
        Some(&ENDPOINT)
    } else {
        None
    }
}

/// Read both effective buffer sizes back; `None` when `getsockopt` failed.
fn udp_socket_buffer_actual(s: &socket2::Socket) -> (Option<usize>, Option<usize>) {
    (s.send_buffer_size().ok(), s.recv_buffer_size().ok())
}

/// Learn (once per process and buffer size) whether this host clamps a UDP
/// buffer request, apply `SO_*BUFFFORCE` when the request is clamped and the
/// capability is there, and warn once per direction if it stayed clamped.
///
/// First socket of a cached size pays the diagnostic reads (and the force when
/// needed); every later socket of that size skips them entirely. A force that
/// is known to work is re-applied per socket — it is a per-fd option — while a
/// force that is known to fail is not retried. On Linux this removes up to
/// 4-6 `getsockopt`/`setsockopt` calls from every new session/association
/// socket; pre-change the same diagnostics ran per socket even though their
/// answer is a per-netns + per-process constant.
///
/// Runtime `net.core.*mem_max` changes are not observed after the first
/// socket of a size: the verdict is a process-lifetime cache, like the
/// `MYQUIC2_SESS_SOCKET_BUF` override. A restart is what applies a sysctl
/// change, which is the deployment model the clamp warning already names.
fn probe_udp_socket_buffers(s: &socket2::Socket, buf: usize) {
    let slot = buf_probe_slot(buf);
    if let Some(cached) = slot.and_then(|slot| slot.get().copied()) {
        // `SO_*BUFFFORCE` is a per-fd option: a size whose plain request the
        // kernel clamps still needs the force on every new socket. A force
        // that failed once (no `CAP_NET_ADMIN`) is never retried.
        #[cfg(target_os = "linux")]
        {
            if cached.needs_force() {
                force_udp_buffers(s, buf);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            debug_assert!(
                !cached.needs_force(),
                "SO_*BUFFFORCE is Linux-only; a non-Linux verdict must never ask for it"
            );
            let _ = cached;
        }
        return;
    }
    let (send_actual, recv_actual) = udp_socket_buffer_actual(s);
    // `mut` is only needed by the Linux force path; keeping the declaration
    // unconditional avoids cfg-splitting this whole block.
    #[allow(unused_mut)]
    let mut verdict = classify_buf_verdict(buf, send_actual, recv_actual);
    // Linux caps a plain SO_*BUF request at net.core.{r,w}mem_max (OpenWrt
    // ships a small rmem_max). When that happened and the process holds
    // CAP_NET_ADMIN — the norm for an OpenWrt service running as root — retry
    // through SO_*BUFFFORCE, which ignores the sysctl. Best-effort: without
    // the capability the retry fails EPERM and the clamp warning below still
    // names the sysctl to raise.
    #[cfg(target_os = "linux")]
    {
        if verdict.clamped() {
            force_udp_buffers(s, buf);
            let (send_after, recv_after) = udp_socket_buffer_actual(s);
            verdict.force_ok = !classify_buf_verdict(buf, send_after, recv_after).clamped();
            // Warn from the post-force read: a host where the force worked must
            // not warn (that is the old behaviour — the warning is for a
            // request the process could not get). The pre-cache code did these
            // same reads on every socket; only the first one per size does now.
            if let Some(actual) = send_after
                && actual < buf
            {
                warn_buf_clamped("send", actual, buf);
            }
            if let Some(actual) = recv_after
                && actual < buf
            {
                warn_buf_clamped("recv", actual, buf);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if verdict.clamped() {
            // No SO_*BUFFFORCE off Linux: the clamp is reported, never forced.
            debug_assert!(
                !verdict.force_ok,
                "force_ok is only set on the Linux force path"
            );
            if let Some(actual) = send_actual
                && actual < buf
            {
                warn_buf_clamped("send", actual, buf);
            }
            if let Some(actual) = recv_actual
                && actual < buf
            {
                warn_buf_clamped("recv", actual, buf);
            }
        }
    }
    if let Some(slot) = slot {
        let _ = slot.set(verdict);
    }
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
            "udp {which} buffer clamped to {actual} (< {want}); raise net.core.{sysctl} or grant CAP_NET_ADMIN (SO_*BUFFFORCE); further buffer warnings suppressed"
        );
    }
}

/// Best-effort `SO_SNDBUFFORCE`/`SO_RCVBUFFORCE`: like the plain buffer
/// options, but not clamped by `net.core.{w,r}mem_max`. Requires
/// `CAP_NET_ADMIN`; an EPERM is ignored and the caller's clamp warning still
/// fires.
#[cfg(target_os = "linux")]
fn force_udp_buffers(s: &socket2::Socket, bytes: usize) {
    // rustix owns the Linux/musl ABI quirks and type-checks the borrows;
    // best-effort: without CAP_NET_ADMIN these fail EPERM and the caller
    // still emits its clamp warning.
    let _ = rustix::net::sockopt::set_socket_send_buffer_size_force(s, bytes);
    let _ = rustix::net::sockopt::set_socket_recv_buffer_size_force(s, bytes);
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
    // Linux-only, best-effort listener tuning (`linux::tune_tcp_listener`):
    // TCP_DEFER_ACCEPT=1s plus a TCP_FASTOPEN listener queue, armed between
    // bind and listen. SOCKS is client-first, so the deferred accept is free;
    // fast open only takes effect when `net.ipv4.tcp_fastopen` allows server
    // mode, and the kernel's refusal is logged once and ignored.
    linux::tune_tcp_listener(&s);
    s.listen(1024)?;
    Ok(s.into())
}

/// Resolve when the process receives a shutdown request: `SIGTERM` or `SIGINT`
/// on Unix, Ctrl-C elsewhere.
///
/// Both binaries hold this in their accept loops and, on resolution, close the
/// QUIC endpoint so connected peers receive a `CONNECTION_CLOSE` and redial
/// instead of blackholing until their silence watchdog fires. There is no drain
/// window: in-flight flows are interrupted by design (UDP has no
/// retransmission, and the client's reconnect loops re-establish TCP/UDP).
///
/// Signal handlers are registered on first poll, so pin this future once
/// outside the loop rather than rebuilding it per iteration. It performs no
/// work on the accept path until the signal actually arrives.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::warn!("cannot install SIGTERM handler ({e}); listening for ctrl_c only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Consume the MQP-2 TCP-open ACK (`magic | 0x00 | atyp | addr | port`). The
/// magic is checked first: raw application bytes from a pre-magic peer fail
/// here (never parsed as the ACK), as do a non-zero status, a malformed
/// address, or a stream reset (dial refused/timeout). Used by the optimistic
/// client reply path, which has already answered SOCKS before this runs.
pub(crate) async fn read_mqp_ack(recv: &mut quinn::RecvStream) -> Result<()> {
    let mut head = [0u8; 3];
    recv.read_exact(&mut head).await.context("ack head read")?;
    if head[0..2] != MQP_TCP_ACK_MAGIC {
        anyhow::bail!("bad mqp ack magic {:02x}{:02x}", head[0], head[1]);
    }
    if head[2] != MQP_TCP_ACK {
        anyhow::bail!("bad mqp ack {:#x}", head[2]);
    }
    let mut buf = [0u8; 19];
    recv.read_exact(&mut buf[..1]).await.context("bnd atyp")?;
    let n = match buf[0] {
        0x01 => 7,
        0x04 => 19,
        a => anyhow::bail!("bad bnd atyp {a}"),
    };
    recv.read_exact(&mut buf[1..n]).await.context("bnd addr")?;
    let (addr, consumed) = decode_bnd_addr(&buf[..n])?;
    // Minimal consistency with `encode_bnd_addr_into`: the decoder accepts any
    // well-formed atyp, but the dial ACK must carry the server's real bound
    // socket — never the unknown `0.0.0.0:0` the optimistic SOCKS reply uses,
    // and never a length the encoder could not have produced.
    if consumed != n {
        anyhow::bail!("bnd length mismatch");
    }
    if addr.ip().is_unspecified() && addr.port() == 0 {
        anyhow::bail!("refused bnd {addr}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session-socket override clamps instead of trusting the operator (or
    /// a typo) verbatim: 1 B and `usize::MAX` must land on the measured range,
    /// and the shipped default is the 64 KiB floor, not the 32 KiB value the
    /// burst test measured as lossy.
    #[test]
    fn sess_socket_buf_override_clamps_to_supported_range() {
        assert_eq!(clamp_sess_socket_buf(1), SESS_SOCKET_BUF_MIN);
        assert_eq!(clamp_sess_socket_buf(usize::MAX), SESS_SOCKET_BUF_MAX);
        assert_eq!(clamp_sess_socket_buf(96 * 1024), 96 * 1024);
        assert_eq!(SESS_SOCKET_BUF, 64 * 1024);
    }

    /// The process-level buffer probe classifies each direction on its own and
    /// never treats a failed `getsockopt` as a clamp: the pre-cache code used
    /// `is_some_and`, so a read error was already "not short", and a spurious
    /// warning here would page operators about a clamp that is not there.
    #[test]
    fn buf_verdict_classifies_each_direction_and_ignores_read_errors() {
        let send_only = classify_buf_verdict(64 * 1024, Some(16 * 1024), Some(128 * 1024));
        assert!(send_only.send_clamped && !send_only.recv_clamped);
        assert!(
            send_only.clamped(),
            "either short direction clamps the request"
        );
        assert!(
            !send_only.needs_force(),
            "a plain clamp is not a successful force"
        );

        let both_ok = classify_buf_verdict(64 * 1024, Some(128 * 1024), Some(128 * 1024));
        assert!(!both_ok.clamped() && !both_ok.needs_force());

        let unknown = classify_buf_verdict(4096, None, None);
        assert!(
            !unknown.clamped(),
            "a failed read-back is not evidence of a clamp"
        );

        let forced = BufVerdict {
            send_clamped: true,
            recv_clamped: false,
            force_ok: true,
        };
        assert!(
            forced.needs_force(),
            "a clamp with a working force must re-apply it per socket"
        );
        assert_eq!(
            forced,
            BufVerdict {
                send_clamped: true,
                recv_clamped: false,
                force_ok: true
            }
        );
    }

    /// The cache covers exactly the sizes production creates: the per-session
    /// buffer (per new flow) and the QUIC endpoint buffer (once per endpoint).
    /// An arbitrary explicit size is deliberately uncached — its diagnostics
    /// keep the pre-change cost and behaviour.
    #[test]
    fn buf_probe_cache_slots_cover_the_production_sizes() {
        assert!(
            buf_probe_slot(sess_socket_buf()).is_some(),
            "the per-session size is the per-new-flow hot path"
        );
        assert!(
            buf_probe_slot(ENDPOINT_SOCKET_BUF).is_some(),
            "the QUIC endpoint buffer is cached for its repeated startup binds"
        );
        assert!(
            buf_probe_slot(sess_socket_buf() + 1).is_none(),
            "an arbitrary udp_socket_dual_with_size keeps the uncached path"
        );
        if sess_socket_buf() != ENDPOINT_SOCKET_BUF {
            assert_ne!(
                buf_probe_slot(sess_socket_buf()).map(std::ptr::from_ref),
                buf_probe_slot(ENDPOINT_SOCKET_BUF).map(std::ptr::from_ref),
                "distinct sizes must not share one verdict slot"
            );
        }
    }

    /// The address-taking session constructor must bind the same usable
    /// dual-stack socket as the string form, and its second call (which takes
    /// the cached-probe branch) must still produce a working socket.
    #[test]
    fn udp_socket_dual_small_addr_binds_like_the_string_form() {
        let first = udp_socket_dual_small_addr("[::]:0".parse().unwrap())
            .expect("first session socket (probe path)");
        let string_form = udp_socket_dual_small("[::]:0").expect("string-form session socket");
        let cached = udp_socket_dual_small_addr("[::]:0".parse().unwrap())
            .expect("second session socket (cached-probe path)");
        for s in [&first, &string_form, &cached] {
            let local = s.local_addr().expect("bound address");
            assert_eq!(local.ip(), "::".parse::<std::net::IpAddr>().unwrap());
            assert_ne!(local.port(), 0, "the kernel must pick a real port");
        }
        // A v4 bind stays a v4 socket: the constructor keys the family off the
        // address it was given and only the v6 wildcard goes dual-stack.
        let v4 =
            udp_socket_dual_small_addr("127.0.0.1:0".parse().unwrap()).expect("v4 session socket");
        assert!(v4.local_addr().unwrap().is_ipv4());
    }

    /// `MYQUIC2_SHARD_RUNTIME` parsing: only the documented "off" spellings
    /// put the slot tasks back on the shared runtime; unset or anything else
    /// keeps the sharded (default) topology in both binaries. The decision
    /// itself is asserted at startup by each binary's topology log line; this
    /// pins the parser so a typo cannot silently flip the runtime model.
    #[test]
    fn shard_runtime_off_spellings_parse() {
        for off in ["0", "false", "FALSE", "off", " off ", "no"] {
            assert!(
                !parse_off_flag(Some(off)),
                "{off:?} must select the shared runtime"
            );
        }
        for on in ["1", "true", "on", "yes", "", "  ", "banana"] {
            assert!(
                parse_off_flag(Some(on)),
                "{on:?} must keep sharding enabled"
            );
        }
        assert!(parse_off_flag(None), "unset default is sharded");
    }

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

    /// A burst larger than the in-flight bound must still be delivered: the
    /// extra items exercise the worker's reap-and-wait path (a sequential drain
    /// could pass this too, but nothing may be dropped or abandoned before its
    /// send completes now that sends overlap).
    ///
    /// Drives its own worker (`spawn_retry_worker`) rather than the process-wide
    /// shard: the shard is shared with the other retry tests, whose
    /// current-thread runtimes come and go, and a worker on a runtime that is
    /// dropped mid-queue legitimately loses its queue (the next submit re-arms
    /// the shard — `retry_shard_is_rearmed_after_its_runtime_ends`). Sharing it
    /// here would make this test flaky for a reason that is not under test.
    #[tokio::test]
    async fn retry_pool_delivers_a_burst_past_the_inflight_bound() {
        // Both sockets are async and the wait is awaited: the worker runs on
        // this test's current-thread runtime, so a blocking `recv` here would
        // starve it and fail the test for its own harness's sake.
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tx = spawn_retry_worker();
        let n = UDP_RETRY_INFLIGHT * 3;
        for i in 0..n {
            assert!(
                tx.try_send(UdpRetry {
                    sock: sock.clone(),
                    dst,
                    payload: Bytes::copy_from_slice(&[0xAB, i as u8]),
                })
                .is_ok(),
                "retry {i} of {n} must be accepted (depth is {UDP_RETRY_DEPTH})"
            );
        }
        let mut got = vec![false; n];
        let mut seen = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b = [0u8; 16];
        while seen < n {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, listener.recv_from(&mut b)).await {
                Ok(Ok((2, _))) if b[0] == 0xAB => {
                    let i = b[1] as usize;
                    if i < n && !got[i] {
                        got[i] = true;
                        seen += 1;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(seen, n, "every queued retry must come out: {seen}/{n}");
    }

    /// The retry deadline is what bounds the socket's retention.
    ///
    /// A queued retry is the *last* strong owner of its `Arc<UdpSocket>` once the
    /// association (client relay) or session (server session socket) has dropped
    /// its own handle, and the worker used to await `send_to` with no deadline:
    /// a socket that never became writable pinned the fd — and on the server its
    /// 2 x 32 KiB kernel buffers — for the process lifetime, and parked the
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
            if let Some(v) = by_set.iter().find(|v| v.len() >= 2)
                && trio.is_none()
            {
                trio = Some((v[0].clone(), v[1].clone()));
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

    /// A negative *memo* entry must not outlive the shared negative verdict it
    /// was derived from.
    ///
    /// The memo is thread-private, and a resolution's success can only remove
    /// the shared negative entry plus the resolving thread's own memo — so a
    /// name that failed on one worker and then resolved on another stayed
    /// refused on the failing worker for the rest of `DNS_NEG_TTL`: every
    /// datagram for it dropped as `REFUSED`, every TCP flow failing with
    /// "dns negative cached". The `NEG_EPOCH` tag closes that: after another
    /// worker resolves the name, this worker's memo entry is stale and its
    /// lookup falls back to the shared caches — which the sync layer is
    /// memo-only, so the observable is `Unknown` (hand the datagram to the
    /// async path), never `Negative`. Two real threads drive the hole (it is
    /// cross-thread by construction); the seeds need no network.
    #[test]
    fn a_resolution_invalidates_another_threads_negative_memo() {
        let _serial = crate::dns::resolve::DNS_CACHE_TEST_LOCK.blocking_lock();
        let (host, port) = ("neg-memo-coherence.test", 19056u16);
        let addr: SocketAddr = "93.184.216.34:19056".parse().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();

        let w = std::thread::spawn(move || {
            // A current-thread runtime drives the async seed on THIS worker,
            // so the negative memo is written to this thread's memo.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // Premise: nothing is known about this name on this thread.
            assert_eq!(lookup_cached_fast(host, port), CachedLookup::Unknown);
            rt.block_on(dns_neg_cache_seed(host, port));
            assert_eq!(
                lookup_cached_fast(host, port),
                CachedLookup::Negative,
                "the recording worker must see its own negative memo"
            );
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            lookup_cached_fast(host, port)
        });

        ready_rx.recv().unwrap();
        // Another worker resolves the same name successfully.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(dns_cache_seed(host, port, addr));
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "a fresh positive seed answers on the seeding thread"
        );
        go_tx.send(()).unwrap();
        assert_eq!(
            w.join().unwrap(),
            CachedLookup::Unknown,
            "a successful resolution must invalidate another thread's negative \
             memo: the stale tag must fall through to the shared caches instead \
             of refusing the name for the rest of DNS_NEG_TTL"
        );
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

    /// Two IPv6 ranges that a per-RFC denylist kept missing.
    ///
    /// `fe00::/9` is IANA "Reserved by IETF" and sits exactly between the
    /// `fc00::/7` and `fe80::/10` rules, so a denylist naming only those two
    /// returned `true` for `fe00::1`. `2001::/23` is the IETF Protocol
    /// Assignments block, not global unicast — the old code denied only the
    /// sub-blocks someone had already written an RFC citation for, so
    /// `2001:5::/32` (the LISP EID block) and the reserved remainder passed.
    #[test]
    fn global_ip_filter_rejects_fe00_and_the_2001_ietf_block() {
        for ip in ["fe00::1", "fe01::1", "fe7f:ffff::1"] {
            assert!(
                !is_global_ip(ip.parse().unwrap()),
                "{ip} is Reserved by IETF, not global"
            );
        }
        for ip in ["2001:0::1", "2001:5::1", "2001:1ff::1"] {
            assert!(
                !is_global_ip(ip.parse().unwrap()),
                "{ip} is inside the IETF Protocol Assignments block"
            );
        }
        // The block boundary is exact: 2001:0200::/23 is the first RIR
        // allocation and must stay dialable, while the last address of the
        // IETF block must not.
        assert!(!is_global_ip("2001:1ff:ffff::1".parse().unwrap()));
        assert!(is_global_ip("2001:200::1".parse().unwrap()));
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    /// `3fff::/20` (RFC 9637) must be exactly that block — no wider.
    ///
    /// The mask used to be `(s[0] & 0xfff0) == 0x3ff0`, i.e. `3ff0::/12`: every
    /// address from `3ff0::` to `3ffe:ffff:...` was refused, 256x the space the
    /// RFC defines. Harmless while `3000::/4` stays IANA-reserved, but it is the
    /// third over-broad denylist mask in this predicate (`fe00::/9` and
    /// `2001::/23` were the first two), so the boundary is pinned here the same
    /// way `2001::/23`'s is.
    #[test]
    fn global_ip_filter_rejects_exactly_3fff_20() {
        // Sweep the whole s[1] nibble boundary: 0x0000..=0x0fff is 3fff::/20 and
        // must be denied, 0x1000 upward must be dialable. Checking sampled
        // addresses is not enough here — the bug was a wrong *mask width* on
        // s[1], which only some addresses expose.
        for hi in 0u32..=0xf {
            for lo in (0u32..0x1000).step_by(0x40) {
                let s1 = (hi << 12) | lo;
                let ip = std::net::Ipv6Addr::new(0x3fff, s1 as u16, 0, 0, 0, 0, 0, 1);
                if s1 <= 0x0fff {
                    assert!(
                        !is_global_ip(ip.into()),
                        "3fff:{s1:x}::1 is inside 3fff::/20"
                    );
                } else {
                    assert!(
                        is_global_ip(ip.into()),
                        "3fff:{s1:x}::1 is outside 3fff::/20"
                    );
                }
            }
        }
        // The neighbouring /16s the old /12 mask swallowed.
        for ip in [
            "3ff0::1",
            "3ff8::1",
            "3ffe:ffff::1",
            "3fff:1000::1",
            "3fff:ffff::1",
        ] {
            assert!(
                is_global_ip(ip.parse().unwrap()),
                "{ip} is outside 3fff::/20"
            );
        }
        // And the block is still denied at both ends of the /20.
        for ip in ["3fff::", "3fff:0fff:ffff::1"] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip} is in 3fff::/20");
        }
    }

    /// M1 regression: the whole reserved region *below* `2000::/3` is denied as
    /// blocks. The old denylist had one arm per RFC and no arm at all for most
    /// of the region, so `::/8` beyond `::1` and `::` (e.g.
    /// `::1:203:405:607:809:a0b`) read as globally routable. The CIDR table in
    /// `dns/policy.rs` denies all of it; the boundary at `2000::/3` and the
    /// embedded-IPv4 recurions stay.
    #[test]
    fn is_global_ip_denies_the_reserved_region_below_2000() {
        for ip in [
            "::1:203:405:607:809:a0b", // ::/8, not the ::/96 compatible form
            "::ffff:1:2:3",            // not the ::ffff:0:0/96 mapped prefix
            "100::1",                  // 0100::/16
            "200::1",                  // 0200::/7
            "400::1",                  // 0400::/6
            "800::1",                  // 0800::/5
            "1000::1",                 // 1000::/4
            "1fff:ffff::1",
        ] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip} is IETF-reserved");
        }
        // The boundary itself: 2000::/3 is global unicast.
        for ip in ["2000::1", "2600::1", "3fff:ffff::1"] {
            assert!(is_global_ip(ip.parse().unwrap()), "{ip} is global unicast");
        }
    }

    /// The TTL-exposing lookups must report the *remaining* life, not the full
    /// TTL: that remainder is what an adopting caller (the server's connection
    /// pin and session destination memo) has to clamp against.
    #[tokio::test]
    async fn lookup_ttl_reports_the_entries_remaining_life() {
        memo_reset();
        let addr: SocketAddr = "93.184.216.34:19057".parse().unwrap();
        let (host, port) = ("ttl-report.test", 19057u16);
        dns_cache_seed(host, port, addr).await;
        let (hit, ttl) = lookup_cached_fast_with_ttl(host, port);
        assert_eq!(hit, CachedLookup::Addr(addr));
        assert!(
            ttl > DNS_CACHE_TTL_MS - 2_000 && ttl <= DNS_CACHE_TTL_MS,
            "a fresh entry reports its full life, got {ttl} ms"
        );

        // Half a second before the TTL: that remainder is all an adopting
        // caller may use.
        let (aged, aged_port) = ("ttl-report-aged.test", 19058u16);
        dns_cache_seed_aged(
            aged,
            aged_port,
            addr,
            Duration::from_millis(DNS_CACHE_TTL_MS - 500),
        )
        .await;
        let (hit2, ttl2) = lookup_cached_fast_with_ttl(aged, aged_port);
        assert_eq!(hit2, CachedLookup::Addr(addr));
        assert!(
            ttl2 <= 1_500,
            "an aged entry must report only its remainder, got {ttl2} ms"
        );

        // A miss reports none.
        assert_eq!(
            lookup_cached_fast_with_ttl("ttl-report-miss.test", 19059).1,
            0
        );
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
    /// ten-field struct exists so the 60 s report cannot silently omit one, and
    /// the batching table (`bump` + `flush_locals`) is keyed on identity, so a
    /// counter missing one of the two arms would sit in a thread-local cell
    /// forever. One bump per counter, one field asserted per counter.
    #[test]
    fn every_drop_counter_has_its_own_snapshot_field() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let before = dgram_drops::snapshot();
        for c in [
            &dgram_drops::TOO_LARGE,
            &dgram_drops::BUFFER_FULL,
            &dgram_drops::SESSION_FULL,
            &dgram_drops::DNS_BUDGET,
            &dgram_drops::FAIR_SHARE,
            &dgram_drops::NO_EGRESS,
            &dgram_drops::EGRESS_DEAD,
            &dgram_drops::REFUSED,
            &dgram_drops::SESS_CREATE_FAILED,
        ] {
            dgram_drops::bump(c);
        }
        let after = dgram_drops::snapshot();
        assert!(after.too_large > before.too_large, "too_large");
        assert!(after.buffer_full > before.buffer_full, "buffer_full");
        assert!(after.session_full > before.session_full, "session_full");
        assert!(after.dns_budget > before.dns_budget, "dns_budget");
        assert!(after.fair_share > before.fair_share, "fair_share");
        assert!(after.no_egress > before.no_egress, "no_egress");
        assert!(after.egress_dead > before.egress_dead, "egress_dead");
        assert!(after.refused > before.refused, "refused");
        assert!(
            after.sess_create_failed > before.sess_create_failed,
            "sess_create_failed"
        );
        let d = after.since(&before);
        assert!(d.lost() >= 9, "every drop counts as loss: {d:?}");
    }

    /// A unique-domain flood must fail fast on the slow-path limiter: with the
    /// budget exhausted `try_acquire_owned` returns `Err` synchronously (it can
    /// never park the caller) and the budget recovers when permits release.
    /// No other lib test holds this limiter (only the binaries take it, in
    /// their own test processes), and nothing is awaited while the permits
    /// are held, so the drain lasts microseconds.
    #[test]
    fn dns_limiter_exhaustion_fails_fast() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let lim = dns_slow_path_limiter();
        let mut held = Vec::new();
        while lim.available_permits() > 0 {
            match lim.clone().try_acquire_owned() {
                Ok(p) => held.push(p),
                Err(_) => break,
            }
        }
        assert_eq!(
            lim.available_permits(),
            0,
            "the flood budget must be exhaustible"
        );
        assert!(
            lim.clone().try_acquire_owned().is_err(),
            "excess misses must fail fast, never park"
        );
        drop(held);
        assert!(
            lim.available_permits() > 0,
            "the budget must recover when permits release"
        );
    }

    /// Serializes the tests that assert exact slow-path counter deltas. The
    /// drop counters are process-wide and `bump` is exact (no batching), so
    /// two such tests racing would move each other's deltas; every test that
    /// bumps `REFUSED` / `DNS_BUDGET` / `SESSION_FULL` while it measures holds
    /// this.
    static SLOW_PATH_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// P1-4 slow-path budget lock: each drop arm owns exactly one counter and
    /// every arm counts as loss in the 60 s budget line.
    ///
    /// One bump per arm must move exactly one snapshot field by exactly one:
    /// a doubled bump (or two arms sharing a counter) would double-count one
    /// burst datagram in the budget the reporter prints. The dispatch-level
    /// tests pin that each relay path bumps once per refused datagram; this
    /// pins the counters themselves.
    #[test]
    fn slow_path_budget_arms_fire_exactly_once() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let before = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::REFUSED);
        dgram_drops::bump(&dgram_drops::DNS_BUDGET);
        dgram_drops::bump(&dgram_drops::SESSION_FULL);
        let d = dgram_drops::snapshot().since(&before);
        assert_eq!(d.refused, 1, "REFUSED (negative cache / policy) fires once");
        assert_eq!(d.dns_budget, 1, "DNS_BUDGET (resolver pool) fires once");
        assert_eq!(d.session_full, 1, "SESSION_FULL (session pool) fires once");
        assert_eq!(d.lost(), 3, "every slow-path drop is budget loss: {d:?}");
    }

    /// The two egress counters must be visible **immediately and from another
    /// thread**, which is the whole reason they do not batch.
    ///
    /// Batching (six of the nine counters) keeps the count in the bumping
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

    /// A never-claimed per-second log slot must claim immediately: the mono
    /// epoch starts near zero, so a 0-initialised slot would swallow the
    /// process's first one-second window — exactly the startup/reconnect burst
    /// the TCP-abort line exists for.
    #[test]
    fn log_window_claims_the_first_second() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let slot = AtomicU64::new(NEVER_WARNED);
        assert!(claim_log_window(&slot, 0), "first window always claims");
        assert!(!claim_log_window(&slot, 500), "same window: refused");
        assert!(claim_log_window(&slot, 1_000), "next window: claims");
        let counted = AtomicU64::new(NEVER_WARNED);
        let suppressed = AtomicU64::new(0);
        assert_eq!(
            claim_log_window_counted(&counted, &suppressed, 0),
            Some(0),
            "the counted variant claims the first window too"
        );
        assert_eq!(claim_log_window_counted(&counted, &suppressed, 5), None);
        assert_eq!(suppressed.load(Ordering::Relaxed), 1);
    }

    /// Encode `payload` the way [`DgramFragmenter`] does, for reassembler tests
    /// that need no connection. The limit is generous so only `chunk` splits.
    fn frag_frames(
        id: u32,
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

    /// The per-partial byte cap is enforced, not merely documented.
    ///
    /// `f.total` is bounded by `MQP_FRAG_MAX_TOTAL`, but nothing bounds a
    /// *chunk*: at the QUIC path MTU a hostile or buggy peer fits ~1.4 KiB in
    /// each of 64 fragments, which assembles to ~91 KiB — a datagram the
    /// fragmenter on the *sending* side would have refused outright, handed to
    /// `udp_try_send` and then to the kernel to IP-fragment. The aggregate
    /// `FRAG_MAX_HELD_BYTES` bound does not catch it (one such partial is well
    /// under 256 KiB), so the cap has to be checked per partial.
    #[test]
    fn a_partial_past_the_payload_cap_is_discarded_whole() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 8 x 1400 B = 11200 B, past MQP_FRAG_MAX_PAYLOAD (8192) but far inside
        // both the fragment-count cap and the aggregate byte cap.
        let over = frag_frames(1, 1, &addr.as_ref(), &pattern(11_200), 1400);
        assert_eq!(over.len(), 8);
        let mut r = DgramReassembler::new();
        for (i, fr) in over.iter().enumerate() {
            let got = r.push(&decode_fragment(fr).unwrap(), 1_000);
            assert!(
                got.is_none(),
                "fragment {i} completed a partial past the payload cap"
            );
        }
        assert!(
            r.held_bytes() <= MQP_FRAG_MAX_PAYLOAD,
            "the over-cap partial must be released, not retained: {} B held",
            r.held_bytes()
        );

        // Positive control: the same shape one fragment shorter *does* complete,
        // so the test cannot pass by rejecting everything.
        let under = frag_frames(2, 1, &addr.as_ref(), &pattern(7_000), 1400);
        assert_eq!(under.len(), 5);
        let mut r = DgramReassembler::new();
        let mut done = None;
        for fr in &under {
            done = r.push(&decode_fragment(fr).unwrap(), 1_000);
        }
        assert_eq!(
            done.expect("a 7000 B payload is inside the cap").2.len(),
            7_000
        );

        // A *duplicate* fragment adds no bytes, so a replay of an already-filled
        // index must not be what pushes a legal partial over the cap.
        let mut r = DgramReassembler::new();
        let exact = frag_frames(3, 1, &addr.as_ref(), &pattern(8_192), 1_024);
        assert_eq!(exact.len(), 8);
        for fr in &exact[..7] {
            assert!(r.push(&decode_fragment(fr).unwrap(), 1_000).is_none());
        }
        // Replaying index 0 must be ignored, and the last fragment must still
        // complete the datagram.
        assert!(
            r.push(&decode_fragment(&exact[0]).unwrap(), 1_000)
                .is_none()
        );
        let done = r.push(&decode_fragment(&exact[7]).unwrap(), 1_000);
        assert_eq!(
            done.expect("a payload exactly at the cap must complete")
                .2
                .len(),
            8_192
        );
    }

    /// The coarse epoch advances with wall time, on its own.
    ///
    /// This is the property that makes it a safe replacement for a per-packet
    /// `mono_millis()` in the throttles: a *packet-count* sampler freezes when
    /// packets stop arriving (see `TouchMemo`), so a trickle flow's stamp stops
    /// moving and the 180 s reaper kills a live session. An epoch driven by
    /// wall time (quanta's upkeep thread) cannot do that — and this test fails
    /// if the implementation is ever swapped for a counter.
    #[tokio::test]
    async fn coarse_millis_advances_without_traffic() {
        // The value must be a real sample of the shared clock, not an
        // uninitialized sentinel. A consumer stores the first value it sees as
        // its baseline and compares later samples against it, so a 0 read *long
        // after* process start would mean "idle since the epoch began" and its
        // very first deadline check would fire — which is why `coarse_millis`
        // falls back to the live clock until the upkeep thread has published
        // its first sample, and shares `mono_millis`'s START. (A literal 0 is
        // still legitimate during the process's first millisecond, when
        // `mono_millis` is 0 as well, so the assertion is about the *gap*
        // between the two clocks.)
        let first = coarse_millis();
        let fine = mono_millis();
        assert!(
            first <= fine,
            "the cursor is a sample of mono_millis and cannot run ahead of it"
        );
        assert!(
            fine.saturating_sub(first) < 1_000,
            "first sample {first} is more than one tick behind the fine clock {fine}: \
             the cursor was left at a sentinel instead of seeded"
        );

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let later = coarse_millis();
        assert!(
            later > first,
            "the epoch must advance with wall time ({first} -> {later}), with no \
             packets in flight: a count-based sampler would freeze here, which is \
             the liveness bug `TouchMemo` records"
        );
    }

    /// The coarse epoch keeps advancing across a runtime hand-off.
    ///
    /// This is the failure mode the whole design has to rule out: a frozen
    /// clock does not corrupt anything, it silently stops every idle watchdog
    /// and every reaper in the process — the exact liveness bug the epoch was
    /// chosen over a packet counter to avoid, arriving by a different route.
    /// The old ticker was a Tokio task, so a runtime hand-off (one runtime per
    /// `#[tokio::test]`; an embedder may run several) could freeze it;
    /// quanta's upkeep thread is runtime-independent, and this test still pins
    /// the property end to end rather than trusting that.
    ///
    /// The assertion is "the epoch advanced while a second runtime was live",
    /// which holds however the epoch is being driven — so it is a genuine test
    /// of the property rather than of one implementation's bookkeeping.
    #[test]
    fn the_coarse_epoch_is_rearmed_after_its_runtime_ends() {
        let rt1 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Both runtimes must live long enough for the epoch to read non-zero
        // (it counts from the process's first clock read). A test that dropped
        // the first runtime inside the process's first millisecond would read
        // 0 and could not tell a live clock from a frozen one.
        rt1.block_on(async {
            let _ = coarse_millis();
            tokio::time::sleep(Duration::from_millis(1_200)).await;
        });
        drop(rt1);

        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (first, later) = rt2.block_on(async {
            let first = coarse_millis();
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            (first, coarse_millis())
        });
        assert!(
            first > 0,
            "a zero epoch means this test cannot tell a live clock from a frozen one"
        );
        assert!(
            later > first,
            "the epoch froze across a runtime hand-off ({first} -> {later}): nothing \
             runtime-bound is keeping it alive"
        );
    }

    /// The `u8` fragment count must reach the UDP maximum even at QUIC's
    /// minimum path MTU, so raising `MQP_FRAG_MAX_PAYLOAD` later is a one-line
    /// change and never a wire-format change. (The same bound is asserted at
    /// compile time next to `MQP_FRAG_MAX_TOTAL`.)
    #[test]
    fn the_fragment_count_reaches_the_udp_maximum_at_the_minimum_mtu() {
        let min_chunk = MIN_PATH_DGRAM_BUDGET - FRAG_PREFIX_LEN - (1 + 16 + 2);
        assert_eq!(min_chunk, 1132, "1200 B path, IPv6 target");
        assert_eq!(UDP_PAYLOAD_MAX.div_ceil(min_chunk), 58);
        assert!(UDP_PAYLOAD_MAX.div_ceil(min_chunk) <= MQP_FRAG_MAX_TOTAL as usize);

        // A full Ethernet path needs fewer, but the worst case is what bounds it.
        let eth_chunk = 1434 - FRAG_PREFIX_LEN - (1 + 4 + 2);
        assert_eq!(eth_chunk, 1416);
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
            unsolicited: 1,
        };
        let b = UdpSnapshot {
            datagrams: 130,
            bytes: 12_000,
            fragmented: 6,
            max_payload: 1_900,
            sessions: 3,
            unsolicited: 5,
        };
        let d = b.since(&a);
        assert_eq!(
            (
                d.datagrams,
                d.bytes,
                d.fragmented,
                d.sessions,
                d.unsolicited
            ),
            (30, 3_000, 2, 1, 4)
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
    ///
    /// Also pins the batching contract of the two rarer counters: a
    /// sub-threshold `fragmented`/`unsolicited` pending count must still be
    /// published by a `snapshot` on the *counting* thread. That is what keeps a
    /// one-event observation (and a reporter that runs on a relay thread) able
    /// to see it; only the cross-thread case is subject to the documented 256
    /// bound.
    #[test]
    fn udp_stats_records_payloads_and_sessions() {
        // Other tests drive `DgramFragmenter::send` concurrently, so assert
        // lower bounds rather than exact deltas.
        let before = udp_stats::snapshot();
        udp_stats::payload(1_472);
        udp_stats::fragmented(3); // 1 pending: below the 256 flush threshold
        udp_stats::fragmented(1); // unfragmented: must not count
        udp_stats::unsolicited(); // 1 pending: below the 256 flush threshold
        udp_stats::session();
        let after = udp_stats::snapshot();
        let d = after.since(&before);
        assert!(d.datagrams >= 1 && d.bytes >= 1_472);
        assert!(
            d.fragmented >= 1,
            "a same-thread snapshot must flush the pending fragmented count"
        );
        assert!(
            d.unsolicited >= 1,
            "a same-thread snapshot must flush the pending unsolicited count"
        );
        assert!(d.sessions >= 1);
        assert!(after.max_payload >= 1_472);

        // A later *smaller* payload must not lower the mark.
        udp_stats::payload(64);
        assert!(udp_stats::snapshot().max_payload >= 1_472);
    }

    /// Reassembly losses must stay observable: they are drop-path counters, and
    /// the reassembly line is the only signal for a fragment lost in transit.
    #[test]
    fn reassembly_counters_are_live() {
        let (expired, evicted) = udp_stats::reassembly_drops();
        udp_stats::reassembly_expired();
        udp_stats::reassembly_evicted();
        let (expired2, evicted2) = udp_stats::reassembly_drops();
        assert!(expired2 > expired, "an expiry must reach the snapshot");
        assert!(evicted2 > evicted, "an eviction must reach the snapshot");
    }

    /// The fragment path must feed the same counters as the single-frame path.
    /// It used to call only `fragmented()`, so fragmented payloads — the exact
    /// size class the 8 KiB cap question is about — were invisible in
    /// `datagrams`/`bytes` and in the `high-water payload` line.
    ///
    /// Deliberately wired through a real connection and the real
    /// `DgramFragmenter::send`: the direct `udp_stats::payload()` test above
    /// cannot catch a caller that never calls it.
    #[tokio::test]
    async fn fragmented_send_counts_the_payload_and_the_high_water() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
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
        let limit = conn.max_datagram_size().unwrap();
        let payload = vec![0xABu8; 2_000];
        assert!(payload.len() <= MQP_FRAG_MAX_PAYLOAD);
        let addr = TargetAddr::Ip("93.184.216.34:53".parse().unwrap());

        let before = udp_stats::snapshot();
        let mut frag = DgramFragmenter::new();
        let sent = frag.send(&conn, 7, &addr.as_ref(), &payload, limit);
        assert!(
            sent.complete(),
            "a 2000 B payload must fragment cleanly: {sent:?}"
        );
        assert!(sent.fragmented(), "2000 B cannot fit one loopback frame");
        // Lower bounds only: sibling tests drive the same counters on other
        // threads (the same caveat `udp_stats_records_payloads_and_sessions`
        // documents), but `bytes` can only have moved from a counted send.
        let after = udp_stats::snapshot();
        let d = after.since(&before);
        assert!(
            d.datagrams >= 1 && d.bytes >= payload.len() as u64,
            "a fragmented payload must be counted: {d:?}"
        );
        assert!(
            after.max_payload >= payload.len() as u64,
            "the high-water mark must see fragmented payloads"
        );
    }

    /// `held_bytes` must be the *exact* memory a partial retains, and the
    /// aggregate cap must bound it.
    ///
    /// Retention used to be the received datagram's `Bytes` slice charged at the
    /// frame's length. That is not a bound at all: the frame is a slice of
    /// quinn's per-`recvmsg` receive batch (up to ~92 KiB with GRO), so a chunk
    /// could pin ~92 KiB while `held_bytes()` read 20 B. Chunks are owned copies
    /// now, so the retained figure is checkable exactly — chunk bytes plus the
    /// slot table — and the cap really bounds what a flood can pin.
    #[test]
    fn retained_bytes_are_exact_and_bounded() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let mut r = DgramReassembler::new();
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        assert_eq!(frames.len(), 2, "6000 B over 4000 B chunks");
        let f0 = decode_fragment(&frames[0]).unwrap();
        assert!(r.push(&f0, 0).is_none());
        assert_eq!(
            r.held_bytes(),
            f0.chunk.len() + Partial::slot_table_bytes(f0.total),
            "retained must be exactly the owned chunk plus its slot table"
        );
        // Completion files the delivered generation as the key's tombstone,
        // which now costs its fingerprint table only: the chunk bytes it used
        // to retain (and charge a second time) are released with the payload.
        assert!(r.push(&decode_fragment(&frames[1]).unwrap(), 0).is_some());
        assert_eq!(r.inflight(), 0);
        let f1 = decode_fragment(&frames[1]).unwrap();
        assert_eq!(r.held_bytes(), tombstone_bytes(f1.total));
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0, "the tombstone ages out with the window");

        // A flood of never-completing full-width partials is still bounded, and
        // the bound still evicts rather than merely reporting a number. With
        // exact accounting each such partial costs its 63 stored fragments plus
        // a 64-slot table (2 KiB), so 200 of them (~500 KiB) must be trimmed to
        // the 256 KiB cap — and the count cap (256) is not what does it.
        let addr = TargetAddr::Domain("a".repeat(255), 53);
        let chunk = [0u8; 8];
        let total = 64u8;
        let fed = 200u32;
        let mut r = DgramReassembler::new();
        let mut completed = 0;
        for id in 0..fed {
            for idx in 0..(total - 1) {
                let body =
                    encode_fragment(1, id, idx, total, &addr.as_ref(), &chunk, 4096).unwrap();
                let f = decode_fragment(&body).unwrap();
                if r.push(&f, 0).is_some() {
                    completed += 1;
                }
            }
        }
        assert_eq!(completed, 0, "each partial is one fragment short");
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "retained bytes must stay inside the aggregate cap: {} B",
            r.held_bytes()
        );
        assert!(
            r.inflight() < fed as usize,
            "the byte bound must evict full-width partials: {} of {fed} in flight",
            r.inflight()
        );
        assert!(r.inflight() > 0, "the newest partials stay");
    }

    /// A partial must expire on a clock tick, with no fragment arriving.
    ///
    /// `push` is the only other path that expires state, so without a tick a
    /// peer that sends fragments and then goes quiet (keeping its connection
    /// alive on keepalives) pins its partials — and every byte they retain —
    /// for the connection's lifetime.
    #[test]
    fn expire_drops_partials_without_a_following_fragment() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        let mut r = DgramReassembler::new();
        assert!(
            r.push(&decode_fragment(&frames[0]).unwrap(), 1_000)
                .is_none()
        );
        assert_eq!(r.inflight(), 1);
        assert!(r.held_bytes() > 0);

        // Still inside the window: nothing may be dropped.
        r.expire(1_000 + FRAG_TIMEOUT_MS - 1);
        assert_eq!(r.inflight(), 1, "a live partial survives the tick");

        r.expire(1_000 + FRAG_TIMEOUT_MS);
        assert_eq!(r.inflight(), 0, "the tick expires it with no push at all");
        assert_eq!(r.held_bytes(), 0, "and gives its bytes back");
    }

    /// The sender must refuse to reuse a fragment id while the receiver can
    /// still hold a partial for it, because reuse is what lets two datagrams
    /// splice (see `same_shape_id_reuse_restarts_instead_of_splicing` for the
    /// case the receiver *can* detect, and `push_with_chunk` for the case it
    /// cannot).
    #[test]
    fn fragment_id_reuse_is_blocked_inside_the_reassembly_window() {
        // Never wrapped (0): every id so far is a first use, nothing to guard.
        assert!(!frag_id_reuse_blocked(0, 1_000_000));
        // Wrapped just now: the ids of the new cycle were all in use a moment
        // ago, so reusing one could splice.
        assert!(frag_id_reuse_blocked(10_000, 10_000));
        assert!(frag_id_reuse_blocked(
            10_000,
            10_000 + FRAG_ID_SAFE_WINDOW_MS - 1
        ));
        // The receiver has had its whole window plus a sweep by now.
        assert!(!frag_id_reuse_blocked(
            10_000,
            10_000 + FRAG_ID_SAFE_WINDOW_MS
        ));
        // The window must outlast the partial lifetime it protects; that
        // invariant is asserted at the constant itself.
    }

    /// The 32-bit id space is what removed the old 16-bit reuse cliff: the
    /// guard must not fire at any rate a single sending context sustains, and
    /// it must still fire when the space genuinely wraps inside the window.
    ///
    /// Pure, so it runs without a live connection; it calls `try_claim_id` —
    /// the production gate — once per payload.
    #[test]
    fn id_reuse_guard_is_a_backstop_not_a_periodic_pause() {
        // A realistic high-rate context: 100k fragmented payloads/s (far above
        // any real association) for a full second. The old 16-bit space retired
        // in 0.65 s at this rate, so the guard dropped ~90% of oversized
        // payloads; the 32-bit space does not wrap at all.
        let mut f = DgramFragmenter::new();
        let mut now = 1_000_000u64;
        let start = f.next_id;
        for n in 0..100_000u64 {
            assert!(
                f.try_claim_id(now).is_some(),
                "the guard must not fire at 100k fragmented payloads/s"
            );
            if (n + 1).is_multiple_of(100) {
                now += 1;
            }
        }
        assert_eq!(f.next_id, start.wrapping_add(100_000));
        assert_eq!(f.last_wrap_ms, 0, "100k ids cannot wrap a 32-bit space");

        // A genuine wrap: seed the counter at the end of the space and drive it
        // over. The instant the counter wraps, the window starts and claims are
        // refused until it elapses — the splice-free disposition.
        let mut f = DgramFragmenter::new();
        f.next_id = u32::MAX - 1;
        let now = 1_000_000u64;
        assert_eq!(f.try_claim_id(now), Some(u32::MAX - 1));
        assert_eq!(f.try_claim_id(now), Some(u32::MAX)); // this claim wraps
        // The wrap stamp is set as the counter becomes 0; ids of the new cycle
        // are refused until the receiver's whole window has passed.
        assert!(f.try_claim_id(now).is_none());
        assert!(f.try_claim_id(now + FRAG_ID_SAFE_WINDOW_MS - 1).is_none());
        assert_eq!(
            f.try_claim_id(now + FRAG_ID_SAFE_WINDOW_MS),
            Some(0),
            "the first id of the new cycle is claimable once the window elapses"
        );
    }

    /// The guard is wired into `send`, not merely available as a predicate: a
    /// context whose id space just wrapped must refuse the oversized payload
    /// (counted as a size drop) and resume once the window has passed.
    #[tokio::test]
    async fn fragmenter_refuses_a_reused_id_inside_the_window() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _sconn = accept.await.unwrap();

        let addr = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        // Use the live DATAGRAM budget: a hard-coded limit above it would be
        // refused by the encoder for the wrong reason.
        let limit = conn.max_datagram_size().expect("DATAGRAM negotiated");
        let payload = pattern(limit + 200);
        let mut frag = DgramFragmenter::new();

        let before = dgram_drops::snapshot();
        // The id space just wrapped: the ids of the new cycle were all in use a
        // moment ago, so reusing one could splice. `next_id` is mid-cycle so the
        // stamp this arm sets is not immediately overwritten by the next wrap.
        // `max(1)`: the mono epoch's own first read is 0, and 0 is the "never
        // wrapped" sentinel — a test that seeded it raw could run before any
        // other clock read and silently disable the guard it is testing.
        frag.last_wrap_ms = mono_millis().max(1);
        frag.next_id = 7;
        let refused = frag.send(&conn, 1, &addr.as_ref(), &payload, limit);
        assert_eq!(refused.frames, 0);
        assert_eq!(refused.failed, Some(DatagramSend::TooLarge));
        assert!(
            dgram_drops::snapshot().too_large > before.too_large,
            "a refusal that loses an oversized payload must be counted"
        );

        frag.last_wrap_ms = mono_millis().max(1).saturating_sub(FRAG_ID_SAFE_WINDOW_MS);
        let sent = frag.send(&conn, 1, &addr.as_ref(), &payload, limit);
        assert!(
            sent.complete() && sent.frames > 1,
            "fragmenting resumes once the receiver cannot still hold the id: {sent:?}"
        );
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
            assert_eq!(
                r.held_bytes(),
                tombstone_bytes(4),
                "completion files the delivered generation's fingerprints against \
                 the budget, never its payload bytes again"
            );
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
        assert!(
            r.push(
                &decode_fragment(&frames[1]).unwrap(),
                FRAG_TIMEOUT_MS + 1_500
            )
            .is_none()
        );
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
        for id in 0..200u32 {
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

    #[test]
    fn slot_tables_are_charged_to_the_aggregate_byte_budget() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // Empty chunks pin nearly nothing themselves, which is exactly why the
        // slot table has to be charged: before this, `held` stayed tiny while
        // FRAG_MAX_PARTIALS x 64 x 32 B of table sat outside every byte bound.
        let one = encode_fragment(1, 0, 0, 64, &addr.as_ref(), &[], 1200).unwrap();
        let fr = decode_fragment(&one).unwrap();
        assert!(fr.chunk.is_empty());
        let mut r = DgramReassembler::new();
        assert!(r.push(&fr, 0).is_none());
        assert_eq!(
            r.held_bytes(),
            Partial::slot_table_bytes(64),
            "a partial whose chunk is empty still costs its slot table"
        );
        assert_eq!(r.inflight(), 1);

        // A flood of full-width, never-completing partials must therefore be
        // evicted by the *byte* bound, not merely parked under the count cap.
        let mut r = DgramReassembler::new();
        for id in 0..(FRAG_MAX_PARTIALS as u32 + 50) {
            let body = encode_fragment(1, id, 0, 64, &addr.as_ref(), &[], 1200).unwrap();
            let f = decode_fragment(&body).unwrap();
            assert!(r.push(&f, 0).is_none());
        }
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "held {} B exceeds the {FRAG_MAX_HELD_BYTES} B cap",
            r.held_bytes()
        );
        assert!(
            r.inflight() < FRAG_MAX_PARTIALS,
            "the byte bound must bind before the count cap: {} partials",
            r.inflight()
        );
    }

    /// A byte-cap overflow must reclaim tombstones before live partials.
    ///
    /// Every completed datagram leaves an id-reuse tombstone charged to the
    /// same [`FRAG_MAX_HELD_BYTES`] budget as the live partials, so a burst of
    /// large fragmented payloads used to fill the cap with tombstones from the
    /// payloads that had just completed and then evict the partials still
    /// mid-assembly — reported as `0 expired, 96 evicted`, losing about half of
    /// an 8 KiB sweep at a 16-deep send window. Tombstones are replay guards,
    /// not deliverable bytes; they go first.
    #[test]
    fn byte_cap_reclaims_tombstones_before_live_partials() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 7800 B over 1300 B chunks: six fragments, just under the 8 KiB cap.
        let whole = pattern(7800);

        // Fill the budget with tombstones from completed payloads.
        let mut r = DgramReassembler::new();
        for id in 0..64u32 {
            let frames = frag_frames(7, id, &addr.as_ref(), &whole, 1300);
            assert_eq!(frames.len(), 6);
            let mut done = false;
            for f in &frames {
                done = r.push(&decode_fragment(f).unwrap(), 0).is_some();
            }
            assert!(done, "every fragment must reassemble");
        }
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
        assert_eq!(r.inflight(), 0, "every payload completed");

        // Start live partials and leave them incomplete.
        let live_ids: Vec<u32> = (1000..1020).collect();
        for id in &live_ids {
            for f in frag_frames(7, *id, &addr.as_ref(), &whole, 1300)
                .iter()
                .take(3)
            {
                assert!(r.push(&decode_fragment(f).unwrap(), 0).is_none());
            }
        }
        // One more incomplete fragment tips `held` over the cap.
        let tipping = frag_frames(7, 2000, &addr.as_ref(), &whole, 1300);
        assert!(r.push(&decode_fragment(&tipping[0]).unwrap(), 0).is_none());

        assert_eq!(
            r.inflight(),
            live_ids.len() + 1,
            "the cap must reclaim tombstones, not live partials"
        );
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
    }

    /// A live partial restarted by an id reuse files the old generation, so
    /// a stale replay of it cannot occupy the new partial's empty slots.
    ///
    /// The generations below differ in *every* chunk: after the restart on
    /// index 0, the replay of A's index 1 matches the filed generation and
    /// is refused, and B completes with only its own fragments. (A form that
    /// differs in one chunk alone never reaches the tombstone — the
    /// occupied-slot check restarts on the differing index and the shared
    /// chunks are byte-identical either way, so mixing them is harmless.)
    #[test]
    fn same_shape_id_reuse_restarts_instead_of_splicing() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let first = pattern(3000);
        let mut second = pattern(3000);
        for b in second.iter_mut() {
            *b ^= 0xFF;
        }
        assert_ne!(second, first);
        let frames_a = frag_frames(9, 1, &addr.as_ref(), &first, 1400);
        let frames_b = frag_frames(9, 1, &addr.as_ref(), &second, 1400);
        assert_eq!((frames_a.len(), frames_b.len()), (3, 3));

        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames_a[0]).unwrap(), 0).is_none());
        assert!(r.push(&decode_fragment(&frames_a[1]).unwrap(), 0).is_none());
        // Same (sess, id, total, idx) with different bytes: a fast reuse, not
        // a replay. The old partial is discarded and filed as the key's
        // tombstone, so the stale prefix of generation A no longer completes
        // anything.
        assert!(r.push(&decode_fragment(&frames_b[0]).unwrap(), 0).is_none());
        assert_eq!(r.inflight(), 1);
        // A stale replay of A's index 1 lands on an empty slot of B's live
        // partial — the exact shape the occupied-slot check cannot see. It
        // matches the filed generation and is refused: nothing completes,
        // nothing restarts, nothing is retained.
        let held_before = r.held_bytes();
        assert!(r.push(&decode_fragment(&frames_a[1]).unwrap(), 0).is_none());
        assert_eq!(
            r.inflight(),
            1,
            "the replay must leave the live partial alone"
        );
        assert_eq!(
            r.held_bytes(),
            held_before,
            "a refused replay retains nothing"
        );
        assert!(r.push(&decode_fragment(&frames_b[1]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&frames_b[2]).unwrap(), 0);
        let (_, _, whole) = done.expect("generation B completes with its own fragments");
        assert_eq!(&whole[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);
    }

    /// H1: a stale generation's suffix on the *empty* slots of the next
    /// generation's live partial must not splice — same total, same address,
    /// no occupied-slot overlap for the restart heuristic to see.
    ///
    /// Generation A completes whole (filed as the key's tombstone), then B
    /// reuses `(sess, id)` with a different payload. Without the tombstone,
    /// the stale replay of A's last chunk fills B's last empty slot and the
    /// reassembler delivers `[B0, B1, A2]` to A's target; with it, the replay
    /// is refused and B completes with only its own fragments. The second
    /// half covers the same shape through the restart path instead of a
    /// completion.
    #[test]
    fn fragment_empty_slot_reuse_does_not_splice() {
        fn flipped(payload: &[u8]) -> Vec<u8> {
            payload.iter().map(|b| b ^ 0xFF).collect()
        }
        let addr = TargetAddr::Ip("10.9.8.7:53".parse().unwrap());
        let first = pattern(3000);
        let second = flipped(&first);
        let frames_a = frag_frames(11, 5, &addr.as_ref(), &first, 1400);
        let frames_b = frag_frames(11, 5, &addr.as_ref(), &second, 1400);
        assert_eq!((frames_a.len(), frames_b.len()), (3, 3));

        let mut r = DgramReassembler::new();
        // Generation A completes whole and is delivered verbatim.
        let mut done = None;
        for fr in &frames_a {
            done = r.push(&decode_fragment(fr).unwrap(), 1_000);
        }
        let (_, _, whole) = done.expect("generation A completes");
        assert_eq!(&whole[..], &first[..]);
        assert_eq!(r.inflight(), 0);

        // Generation B starts on the reused id: its prefix goes live.
        assert!(
            r.push(&decode_fragment(&frames_b[0]).unwrap(), 1_000)
                .is_none()
        );
        assert!(
            r.push(&decode_fragment(&frames_b[1]).unwrap(), 1_000)
                .is_none()
        );
        assert_eq!(r.inflight(), 1);
        let held_before = r.held_bytes();

        // A stale replay of A's suffix lands on B's last empty slot. This is
        // the splice: stored, it would complete `[B0, B1, A2]`.
        assert!(
            r.push(&decode_fragment(&frames_a[2]).unwrap(), 1_000)
                .is_none()
        );
        assert_eq!(
            r.inflight(),
            1,
            "the replay must neither complete nor restart the live partial"
        );
        assert_eq!(
            r.held_bytes(),
            held_before,
            "a refused replay retains nothing"
        );

        // B's own suffix completes a pure generation-B datagram.
        let done = r.push(&decode_fragment(&frames_b[2]).unwrap(), 1_000);
        let (_, _, whole) = done.expect("generation B completes with its own fragments");
        assert_eq!(&whole[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);

        // Completion files the delivered generation against the aggregate
        // budget — exactly its fingerprint table...
        assert_eq!(r.held_bytes(), tombstone_bytes(3));
        // ...and the tick releases it with the window.
        r.expire(1_000 + FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0);

        // Restart path: C's prefix goes live, D restarts it, and a stale
        // replay of C's prefix on D's empty slot is refused the same way.
        let third = pattern(3000);
        let fourth = flipped(&third);
        let frames_c = frag_frames(12, 5, &addr.as_ref(), &third, 1400);
        let frames_d = frag_frames(12, 5, &addr.as_ref(), &fourth, 1400);
        assert!(
            r.push(&decode_fragment(&frames_c[0]).unwrap(), 1_000)
                .is_none()
        );
        assert!(
            r.push(&decode_fragment(&frames_c[1]).unwrap(), 1_000)
                .is_none()
        );
        assert!(
            r.push(&decode_fragment(&frames_d[0]).unwrap(), 1_000)
                .is_none()
        );
        let held_before = r.held_bytes();
        assert!(
            r.push(&decode_fragment(&frames_c[1]).unwrap(), 1_000)
                .is_none()
        );
        assert_eq!(r.inflight(), 1);
        assert_eq!(r.held_bytes(), held_before);
        assert!(
            r.push(&decode_fragment(&frames_d[1]).unwrap(), 1_000)
                .is_none()
        );
        let done = r.push(&decode_fragment(&frames_d[2]).unwrap(), 1_000);
        let (_, _, whole) = done.expect("generation D completes with its own fragments");
        assert_eq!(&whole[..], &fourth[..], "must not splice C and D together");
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
        // Different shape forces a restart: held must drop the old bytes from
        // the live partial and file the retired generation's fingerprints as the
        // key's tombstone, counting the new fragment (payload + its slot table)
        // plus that table — never accumulating the old payload twice.
        let old = decode_fragment(&frames[0]).unwrap();
        assert!(r.push(&decode_fragment(&other[0]).unwrap(), 0).is_none());
        let f0 = decode_fragment(&other[0]).unwrap();
        let table = Partial::slot_table_bytes(f0.total);
        assert!(table > 0, "the slot table is charged, not free");
        let tomb = tombstone_bytes(old.total);
        assert!(tomb > 0, "the tombstone table is charged, not free");
        assert_eq!(r.held_bytes(), f0.chunk.len() + table + tomb);
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

    /// An abnormal pump end must be **told to the peer as a reset**, not dropped
    /// into a clean FIN.
    ///
    /// `Drop for quinn::SendStream` calls `finish()`, so before this was fixed a
    /// pump that gave up — because the other direction failed, or because the
    /// idle watchdog fired — left its send half to be dropped, and the peer's
    /// `read_chunks` returned a clean `Ok(None)`. The peer's own `abort_tcp`
    /// then never ran, so the application on that side saw EOF and accepted a
    /// truncated transfer as a whole one: precisely the silent corruption
    /// `abort_tcp` exists to prevent, one hop further out. The pump now resets
    /// the abandoned half explicitly.
    ///
    /// The test drives it from the *far* side: it resets its send stream (a
    /// download failure, the common case), which fails the near pump's `s2c`,
    /// and then asserts that the near pump's abandoned upload half arrives as a
    /// reset rather than as EOF. Falsified against the old code, which reported
    /// `Ok(0)` here.
    #[tokio::test]
    async fn abnormal_pump_end_resets_the_peer_stream_instead_of_finishing() {
        use tokio::io::AsyncWriteExt;

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
        let far = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            conn.accept_bi().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();

        let (mut app, pump_tcp) = tcp_pair().await;
        let pump = tokio::spawn(copy_tcp_quic_idle(
            pump_tcp,
            send,
            recv,
            Duration::from_secs(30),
        ));
        // The far accept only resolves once a STREAM frame arrives, so the app
        // must write first. It then stays open and silent: `c2s` has to be *in
        // flight* when `s2c` fails, or there would be nothing to abandon and the
        // completion gate would rightly decline to reset a finished half.
        app.write_all(b"up").await.unwrap();
        let (mut far_send, mut far_recv) = tokio::time::timeout(Duration::from_secs(10), far)
            .await
            .expect("far accept fires once the first STREAM frame arrives")
            .unwrap();
        // Kill the download half.
        far_send.write_all(b"x").await.unwrap();
        far_send.reset(7u32.into()).unwrap();

        let out = tokio::time::timeout(Duration::from_secs(10), pump)
            .await
            .expect("the pump must fail fast, not linger to the idle reap")
            .unwrap();
        assert!(
            out.is_err(),
            "a reset download half is not a clean end: {out:?}"
        );

        // The assertion that matters: the far side must observe a *reset*, which
        // is what makes it fail instead of believing the upload completed. Drain
        // whatever is legitimately queued first — the terminal event is what is
        // being judged.
        let mut buf = [0u8; 64];
        let mut drains = 0;
        let terminal = loop {
            match tokio::time::timeout(Duration::from_secs(10), far_recv.read(&mut buf)).await {
                Ok(Ok(Some(n))) if n > 0 && drains < 16 => {
                    drains += 1;
                    continue;
                }
                Ok(other) => break other,
                Err(_) => {
                    panic!("no terminal event within 10s: the stream neither reset nor finished")
                }
            }
        };
        match terminal {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(code.into_inner(), 0x04, "the pump's own reset code");
            }
            Ok(None) => panic!(
                "the peer saw a clean FIN on an abandoned stream: a truncated transfer \
                 would be accepted as a complete one"
            ),
            other => panic!("expected a reset, got {other:?}"),
        }
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

    /// L1 version-skew pin: the dial ACK opens with a magic no legacy
    /// `0x00`-led app prefix can carry, so a peer that sends raw application
    /// bytes first (a pre-magic server) fails the ACK gate instead of having
    /// 8/20 B silently stripped with a clean FIN. A valid ACK still parses.
    #[tokio::test]
    async fn tcp_dial_ack_rejects_a_zero_led_app_prefix() {
        async fn ack_result_for(wire: Vec<u8>) -> bool {
            let (client, server) = endpoint_pair().await;
            let server_addr = server.local_addr().unwrap();
            let accept = tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                // Ping first: a locally-opened stream is invisible to the peer
                // until its first STREAM frame arrives, so `accept_bi` above
                // only fires after the client's write below.
                let mut ping = [0u8; 4];
                recv.read_exact(&mut ping).await.unwrap();
                send.write_all(&wire).await.unwrap();
                send.finish().ok();
                // Hold the connection open until the client confirms its read:
                // exiting here drops the endpoint, whose close can otherwise
                // overtake the queued ACK on loopback.
                let mut done = [0u8; 2];
                recv.read_exact(&mut done).await.unwrap();
            });
            let conn = client
                .connect(server_addr, "test.com")
                .unwrap()
                .await
                .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            // Production always writes the MQP target header before reading
            // the ACK; the ping here plays that role for the test stream.
            send.write_all(b"ping").await.unwrap();
            let result = read_mqp_ack(&mut recv).await;
            send.write_all(b"ok").await.unwrap();
            accept.await.unwrap();
            result.is_ok()
        }

        // Same-version writer and reader agree, both families.
        for bnd in [
            "192.0.2.7:1234".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        ] {
            let mut ack = [0u8; MAX_TCP_ACK_LEN];
            let n = encode_tcp_ack_into(bnd, &mut ack);
            assert!(
                ack_result_for(ack[..n].to_vec()).await,
                "valid ACK for {bnd} must be accepted"
            );
        }
        // Legacy-shaped app prefixes: the old 8 B (v4) and 20 B (v6) forms a
        // pre-magic peer's first bytes could take. Both must fail the gate —
        // accepting either would strip app bytes and finish clean.
        let mut legacy_v4 = vec![0x00u8, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
        assert!(
            !ack_result_for(legacy_v4.clone()).await,
            "leading-0x00 app bytes must not parse as ACK"
        );
        let mut legacy_v6 = vec![0x00u8, 0x04];
        legacy_v6.extend_from_slice(&[0u8; 16]);
        legacy_v6.extend_from_slice(&[0x01, 0xbb]);
        assert!(
            !ack_result_for(legacy_v6).await,
            "leading-0x00 v6 app bytes must not parse as ACK"
        );
        // Right magic, wrong status: a refused dial is still an error, never
        // an ACK.
        legacy_v4[0] = MQP_TCP_ACK_MAGIC[0];
        legacy_v4[1] = MQP_TCP_ACK_MAGIC[1];
        legacy_v4[2] = 0x01;
        assert!(
            !ack_result_for(legacy_v4).await,
            "non-zero ACK status must be rejected"
        );
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
    fn dns_stores_are_configured_with_the_documented_bounds() {
        // The capacity/expiry bounds moved from per-shard arithmetic to the
        // moka caches' builders; the values themselves must not drift.
        assert_eq!(DNS_CACHE_MAX, 10_240);
        assert_eq!(DNS_NEG_MAX, 4096);
        assert!(
            DNS_NEG_TTL < Duration::from_millis(DNS_CACHE_TTL_MS),
            "a negative verdict must never outlive a positive one"
        );
        assert_eq!(
            positives().policy().max_capacity(),
            Some(DNS_CACHE_MAX as u64)
        );
        assert_eq!(
            negatives().policy().max_capacity(),
            Some(DNS_NEG_MAX as u64)
        );
        assert_eq!(
            positives().policy().time_to_live(),
            Some(Duration::from_millis(DNS_CACHE_TTL_MS))
        );
        assert_eq!(negatives().policy().time_to_live(), Some(DNS_NEG_TTL));
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
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
        server_cfg.transport_config(build_transport(Congestion::Bbr, 5));
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
        ccfg.transport_config(build_transport(Congestion::Bbr, 5));
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
        let c2: ClientConf = toml::from_str(&format!("{base}alpn = 'myquic2/3'\n")).unwrap();
        assert_eq!(c2.alpn_bytes(), MQP_ALPN);
        assert_eq!(normalize_alpn(Some("")), b"h3");
        assert_eq!(normalize_alpn(None), b"h3");
        assert_eq!(normalize_alpn(Some("h3")), b"h3");
    }

    /// A misspelled key must fail the parse instead of silently falling back.
    /// `auth_tokn` used to deserialize as an empty `auth_token` and disable
    /// client authentication with no diagnostic at all.
    #[test]
    fn unknown_config_keys_are_rejected() {
        let client = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let err = toml::from_str::<ClientConf>(&format!("{client}auth_tokn = 'secret'\n"))
            .expect_err("a typo must not silently disable auth");
        assert!(err.to_string().contains("auth_tokn"), "{err}");
        let ok: ClientConf = toml::from_str(&format!("{client}auth_token = 'secret'\n")).unwrap();
        assert_eq!(ok.auth_token, "secret");

        let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
        let err = toml::from_str::<ServerConf>(&format!("{server}allow_priv = true\n"))
            .expect_err("a typo must not silently flip the SSRF policy");
        assert!(err.to_string().contains("allow_priv"), "{err}");
        // ... and the same guard covers the multi-endpoint ingress knob.
        assert!(toml::from_str::<ServerConf>(&format!("{server}quic_endpoint = 2\n")).is_err());
    }

    /// `quic_endpoints` defaults per [`default_quic_endpoints`] (cores on
    /// Linux, 1 elsewhere — see the fn for the measured reason), and an
    /// explicit value clamps into `1..=MAX_QUIC_ENDPOINTS`.
    #[test]
    fn server_quic_endpoints_defaults_and_clamps() {
        let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
        let conf =
            |extra: &str| -> ServerConf { toml::from_str(&format!("{server}{extra}")).unwrap() };
        assert_eq!(
            conf("").endpoint_count(),
            default_quic_endpoints(),
            "unset means the platform's default rule"
        );
        assert!(
            conf("").endpoint_count() <= MAX_QUIC_ENDPOINTS,
            "the default may never exceed the socket-group cap"
        );
        assert_eq!(conf("quic_endpoints = 1\n").endpoint_count(), 1);
        assert_eq!(conf("quic_endpoints = 3\n").endpoint_count(), 3);
        assert_eq!(
            conf("quic_endpoints = 0\n").endpoint_count(),
            1,
            "clamped up"
        );
        assert_eq!(
            conf("quic_endpoints = 999\n").endpoint_count(),
            MAX_QUIC_ENDPOINTS,
            "a config typo cannot spawn an unbounded socket group"
        );
    }

    /// Full-cone UDP semantics are an explicit opt-in: the relay exposing a
    /// client app's UDP endpoint to unsolicited internet traffic must never be
    /// what an unset (or misspelled) config silently gets. A misspelled key is
    /// already a hard parse error via `deny_unknown_fields` (see
    /// `unknown_config_keys_are_rejected`).
    #[test]
    fn server_udp_full_cone_defaults_off() {
        let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
        let conf =
            |extra: &str| -> ServerConf { toml::from_str(&format!("{server}{extra}")).unwrap() };
        assert!(!conf("").udp_full_cone, "full-cone must stay opt-in");
        assert!(!conf("udp_full_cone = false\n").udp_full_cone);
        assert!(
            conf("udp_full_cone = true\n").udp_full_cone,
            "an explicit true must reach the server"
        );
    }

    /// REUSEPORT group ingress: two sockets bind the *same* address, every
    /// datagram lands on exactly one member, and the platform's spread
    /// behavior is pinned as measured — Linux hashes by connection 4-tuple
    /// (the property the multi-endpoint server relies on), while macOS hands
    /// the whole group to one member (most recently bound), which is why
    /// [`default_quic_endpoints`] is 1 there. A kernel that changed either way
    /// would make this test state loudly instead of the default quietly going
    /// wrong.
    #[cfg(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    ))]
    #[test]
    fn udp_reuseport_group_shares_the_port_with_measured_spread() {
        assert!(reuse_port_ingress_supported());
        let a = udp_socket_dual_reuseport("127.0.0.1:0").expect("first group member");
        let port = a.local_addr().expect("bound address").port();
        let b = udp_socket_dual_reuseport(&format!("127.0.0.1:{port}"))
            .expect("second group member must bind the same port");
        // A singleton cannot share the port while the group holds it: that is
        // exactly why the grouped bind is opt-in and `quic_endpoints = 1`
        // keeps the strict single socket.
        assert!(
            udp_socket_dual(&format!("127.0.0.1:{port}")).is_err(),
            "only REUSEPORT holders may share the port"
        );

        // 64 datagrams, each from a fresh source socket, kept alive: 64
        // distinct connection 4-tuples, which is what a flow hash spreads on.
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut sources = Vec::with_capacity(64);
        for i in 0..64u8 {
            let src = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            src.send_to(&[i, i, i], addr).unwrap();
            sources.push(src);
        }
        let drain = |s: &std::net::UdpSocket| {
            let mut n = 0usize;
            let mut buf = [0u8; 64];
            while s.recv_from(&mut buf).is_ok() {
                n += 1;
            }
            n
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let (mut a_hits, mut b_hits) = (0usize, 0usize);
        while a_hits + b_hits < 64 && std::time::Instant::now() < deadline {
            a_hits += drain(&a);
            b_hits += drain(&b);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            a_hits + b_hits,
            64,
            "every datagram must land on exactly one member"
        );
        #[cfg(target_os = "linux")]
        assert!(
            a_hits > 0 && b_hits > 0,
            "Linux spreads the group by connection 4-tuple (a={a_hits}, b={b_hits}); \
             without this, multiple server endpoints would not scale"
        );
        #[cfg(target_os = "macos")]
        {
            // Measured on macOS: the whole group's traffic goes to one member
            // (the most recently bound socket), with no spreading at all.
            // `default_quic_endpoints` returning 1 on this platform is based
            // on exactly this; if a future macOS starts spreading, this
            // assertion tells us the default can be raised again.
            assert!(
                a_hits == 0 || b_hits == 0,
                "macOS is not expected to spread a REUSEPORT group (a={a_hits}, b={b_hits})"
            );
            assert_eq!(
                (a_hits, b_hits),
                (0, 64),
                "the most recently bound member receives the whole group"
            );
        }
    }

    /// `dns_ip_preference` accepts exactly "ipv6"/"ipv4", defaults to the
    /// RFC 6724-style IPv6-first order on both sides, and a bad value fails
    /// the parse instead of silently keeping a preference the operator did
    /// not choose.
    #[test]
    fn dns_ip_preference_parses_and_defaults() {
        let client = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(client).unwrap();
        assert_eq!(c.dns_ip_preference, IpPreference::Ipv6);
        let c: ClientConf =
            toml::from_str(&format!("{client}dns_ip_preference = 'ipv4'\n")).unwrap();
        assert_eq!(c.dns_ip_preference, IpPreference::Ipv4);

        let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
        let s: ServerConf = toml::from_str(server).unwrap();
        assert_eq!(s.dns_ip_preference, IpPreference::Ipv6);
        let s: ServerConf =
            toml::from_str(&format!("{server}dns_ip_preference = 'ipv4'\n")).unwrap();
        assert_eq!(s.dns_ip_preference, IpPreference::Ipv4);

        let err = toml::from_str::<ClientConf>(&format!("{client}dns_ip_preference = 'v4'\n"))
            .expect_err("an unknown variant must not silently keep a default");
        assert!(err.to_string().contains("v4"), "{err}");
    }

    /// The keepalive clamp bounds the derived detection window: the QUIC idle
    /// timeout is `3x` and the client silence watchdog `2x`, so the old 3600
    /// clamp put silent-path detection hours out. A sane value must pass
    /// through untouched. The watchdog must stay strictly below the idle
    /// timeout for every legal keepalive — that invariant is what makes the
    /// watchdog an *independent* detector instead of dead code the idle timer
    /// always beats.
    #[test]
    fn keepalive_clamp_bounds_the_detection_window() {
        assert_eq!(clamp_keep_alive(3600), KEEP_ALIVE_MAX_SECS);
        assert_eq!(
            clamp_keep_alive(KEEP_ALIVE_MAX_SECS + 1),
            KEEP_ALIVE_MAX_SECS
        );
        assert_eq!(clamp_keep_alive(17), 17);
        assert_eq!(clamp_keep_alive(0), 1, "a zero keepalive cannot disable it");
        assert!(
            watchdog_silence_secs(KEEP_ALIVE_MAX_SECS) <= 1200,
            "the watchdog must stay inside 20 minutes"
        );
        // `watchdog < idle` over the whole accepted range, including the
        // clamp's low end: the client's detector has to fire before quinn's
        // idle timer (or the peer's CONNECTION_CLOSE) can.
        for k in 0..=KEEP_ALIVE_MAX_SECS {
            let watchdog = watchdog_silence_secs(k);
            let idle = idle_timeout_secs(k);
            assert!(
                watchdog < idle,
                "keepalive {k}s: watchdog {watchdog}s must fire before idle {idle}s"
            );
        }
        // The shipped default detects path death at ~10 s (2 x 5 s), and the
        // floors keep a 1 s keepalive from producing a hair-trigger detector.
        assert_eq!(watchdog_silence_secs(5), 10);
        assert_eq!(watchdog_silence_secs(1), 8);
        assert_eq!(idle_timeout_secs(1), 15);
    }

    /// The admission bound multiplies this figure by the admitted connection
    /// count, so it has to track the configured windows rather than restate a
    /// constant: a deployment that raises the windows must see the per-connection
    /// ceiling rise with them.
    #[test]
    fn per_connection_memory_tracks_the_windows() {
        let d = per_connection_memory_bytes(&TransportTuning::default());
        let stager = crate::udp::r2_stage::R2_STAGE_MAX_BYTES as u64
            + (crate::udp::r2_stage::R2_STAGE_MAX_ITEMS
                * std::mem::size_of::<crate::udp::r2_stage::R2StageItem>()
                * crate::config::tuning::R2_STAGER_SLOT_FACTOR) as u64;
        let registry = crate::mqp::r2_flow::R2_MAX_FLOWS_PER_CONN as u64
            * (std::mem::size_of::<crate::mqp::r2_flow::FlowBinding>() as u64
                + crate::config::tuning::R2_FLOW_HEAP_SLACK_BYTES);
        // 8 MB receive + 4 MB send + 2 x 1 MB DATAGRAM buffers + both
        // per-connection reassembly budgets (legacy MQP-2 + rev2) + the rev2
        // stager, ingress state, and flow registry.
        assert_eq!(
            d,
            8 * 1024 * 1024
                + 4 * 1024 * 1024
                + 2 * DATAGRAM_BUFFER as u64
                + 2 * FRAG_MAX_HELD_BYTES as u64
                + stager
                + crate::config::tuning::R2_INGRESS_FIXED_BYTES
                + registry
        );
        let wide = TransportTuning {
            receive_window: 16 * 1024 * 1024,
            send_window: 8 * 1024 * 1024,
            ..TransportTuning::default()
        };
        assert_eq!(per_connection_memory_bytes(&wide) - d, 12 * 1024 * 1024);
        // The per-stream window is bounded by the connection window and must not
        // be charged twice.
        let narrow_streams = TransportTuning {
            stream_receive_window: 1024 * 1024,
            ..TransportTuning::default()
        };
        assert_eq!(per_connection_memory_bytes(&narrow_streams), d);
        // A full house of the shipped defaults: 4096 x (transport 14 MB +
        // two reassembly budgets of 256 KiB + the rev2 data-plane ceilings).
        // The UDP session pool is a *separate*, global term
        // (`session_pool_memory_bytes`), charged once by the admission bound
        // rather than per connection.
        assert_eq!(
            d * 4096 / (1024 * 1024),
            78080,
            "4096 x 19.0625 MiB is the 76.25 GiB worst case for the default windows"
        );
        let pool = session_pool_memory_bytes(8192);
        // Linux stores/reports SO_{R,CVBUF}/SO_SNDBUF at 2x the requested
        // value, so each session's socket cap is 4 x 64 KiB there and the
        // pool term is ~2.09 GiB instead of the requested ~1.09 GiB. The
        // per-session MQP-3 flow-table charge adds 32 MiB over the whole pool.
        let pool_mib = if cfg!(target_os = "linux") {
            2144
        } else {
            1120
        };
        assert_eq!(
            pool / (1024 * 1024),
            pool_mib,
            "the session pool term must charge the kernel's doubled socket caps on Linux"
        );
        assert!(
            pool > 512 * 1024 * 1024,
            "the pool has to be a term worth charging"
        );
    }

    /// The endpoint and TCP-pump terms are process-wide fixed costs the
    /// admission math used to omit. Pin their arithmetic so the startup
    /// worst-case line cannot silently drift from the code.
    #[test]
    fn process_fixed_memory_terms_match_the_code() {
        let recv = endpoint_recv_buffer_bytes();
        let caps = if cfg!(target_os = "linux") {
            // 4 MiB requested per direction, stored at 2x by the kernel, both
            // directions.
            2 * (2 * ENDPOINT_SOCKET_BUF)
        } else {
            2 * ENDPOINT_SOCKET_BUF
        };
        if cfg!(target_os = "linux") {
            assert_eq!(recv, 1472 * 64 * 32, "quinn-udp GRO receive scratch");
        } else {
            assert_eq!(recv, 1472, "no GRO: one datagram of scratch");
        }
        assert_eq!(endpoint_memory_bytes(1), recv + caps as u64);
        assert_eq!(endpoint_memory_bytes(16), 16 * endpoint_memory_bytes(1));
        // Two 16 KiB pump buffers per active TCP relay flow.
        assert_eq!(stream_pump_memory_bytes(8192), 8192 * 32 * 1024);
    }

    #[test]
    fn tuning_defaults_are_low_latency() {
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(base).unwrap();
        let t = c.tuning();
        assert_eq!(t.stream_receive_window, 4 * 1024 * 1024);
        assert_eq!(t.receive_window, 8 * 1024 * 1024);
        assert_eq!(t.send_window, 4 * 1024 * 1024);
        assert_eq!(t.ack_threshold, 2);
        assert_eq!(t.max_ack_delay, Duration::from_millis(5));
        assert_eq!(t.initial_rtt, Duration::from_millis(DEFAULT_INITIAL_RTT_MS));
        assert_eq!(
            t.initial_mtu, DEFAULT_INITIAL_MTU,
            "the MTU a connection starts from must reach the transport builder"
        );
        assert_eq!(
            DEFAULT_INITIAL_MTU, 1200,
            "the shipped start is the QUIC floor: nothing smaller is legal"
        );
        assert_eq!(c.conn_count(), 4, "pool default is four connections");
        assert_eq!(DEFAULT_QUIC_CONNS, 4);
        let conf =
            |extra: &str| -> ClientConf { toml::from_str(&format!("{base}{extra}")).unwrap() };
        assert_eq!(
            conf("initial_rtt_ms = 140\n").tuning().initial_rtt,
            Duration::from_millis(140),
            "the documented 140 ms seed must reach the transport builder"
        );
        assert_eq!(
            conf("initial_rtt_ms = 0\n").tuning().initial_rtt,
            Duration::from_millis(INITIAL_RTT_MS_MIN),
            "a zero seed must clamp up, not zero the estimator"
        );
        assert_eq!(
            conf("initial_rtt_ms = 999_999\n").tuning().initial_rtt,
            Duration::from_millis(INITIAL_RTT_MS_MAX),
            "a typo must not postpone first-flight loss recovery absurdly"
        );
        // Initial MTU: unset takes the shipped default (the 1200-byte QUIC
        // floor), explicit values reach the builder, and anything outside
        // quinn's accepted range clamps up/down instead of being passed
        // through: below 1200 QUIC packets are illegal, and above 1472 can
        // only be a typo.
        assert_eq!(
            conf("initial_mtu = 1000\n").tuning().initial_mtu,
            INITIAL_MTU_MIN,
            "a sub-QUIC start must clamp up to 1200, never reach the transport"
        );
        assert_eq!(
            conf("initial_mtu = 1472\n").tuning().initial_mtu,
            1472,
            "the IPv4-only zero-ramp value must reach the builder"
        );
        assert_eq!(
            conf("initial_mtu = 0\n").tuning().initial_mtu,
            INITIAL_MTU_MIN
        );
        assert_eq!(
            conf("initial_mtu = 1500\n").tuning().initial_mtu,
            INITIAL_MTU_MAX
        );
        // The VPN port list classifies a tunnel by port before the
        // first-packet-size heuristic can put it on the interactive class.
        assert_eq!(c.udp_bulk_port_list(), vec![51820, 1194]);
        assert_eq!(
            conf("udp_bulk_ports = [51820, 1234]\n").udp_bulk_port_list(),
            vec![51820, 1234]
        );
        assert!(
            conf("udp_bulk_ports = []\n")
                .udp_bulk_port_list()
                .is_empty(),
            "an explicit empty list restores the pure size heuristic"
        );
        assert_eq!(conf("quic_conns = 1\n").conn_count(), 1);
        assert_eq!(conf("quic_conns = 3\n").conn_count(), 3);
        assert_eq!(conf("quic_conns = 0\n").conn_count(), 1, "clamped up");
        assert_eq!(
            conf("quic_conns = 999\n").conn_count(),
            MAX_POOL_CONNS,
            "a config typo cannot spawn an unbounded dial loop"
        );
        // Bulk UDP sharding: unset falls back to the shipped default, and the
        // value clamps to the dial-fan-out cap like `quic_conns` does.
        assert_eq!(c.udp_egress_cnt(), DEFAULT_UDP_EGRESS_CONNS);
        assert_eq!(conf("udp_egress_conns = 1\n").udp_egress_cnt(), 1);
        assert_eq!(
            conf("udp_egress_conns = 0\n").udp_egress_cnt(),
            1,
            "the bulk class always owns at least one dedicated connection"
        );
        assert_eq!(
            conf("udp_egress_conns = 999\n").udp_egress_cnt(),
            MAX_UDP_EGRESS_CONNS,
            "a config typo cannot dial an unbounded shard fan-out"
        );
        // Unknown keys stay a hard error: the new field must not open a hole.
        assert!(toml::from_str::<ClientConf>(&format!("{base}udp_egress_conn = 2\n")).is_err());
    }

    /// Window sizing invariant: the documented **opt-in** 300Mb/s configuration
    /// must actually produce flow-control windows that clear the BDP, or they —
    /// not BBR's congestion window — become the single-stream throughput ceiling.
    ///
    /// This is a config-path check rather than a live measurement on purpose:
    /// quinn exposes no window getters, and a loopback connection cannot detect
    /// the regression it guards against (with a 2MB window the cushion is still
    /// 1MB, worth ~40Gb/s at a ~0.2ms loopback RTT).
    ///
    /// **It used to assert only on the constants**, which `build_transport_tuned`
    /// never reads — it consumes `TransportTuning`, whose default is the 2/4/2
    /// low-latency preset. So the guard passed while proving nothing about any
    /// window that could reach the wire. It now drives `ClientConf::tuning()`
    /// with the exact values the sample configs document and checks both that
    /// they reproduce the constants and that they clear the BDP.
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

        // ...and the same invariant through the only path that reaches quinn:
        // the config, as the sample configs document it on both sides.
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(&format!(
            "{base}stream_receive_window_mb = 8\nreceive_window_mb = 16\n\
             send_window_mb = 8\nack_threshold = 8\nmax_ack_delay_ms = 10\n"
        ))
        .unwrap();
        let t = c.tuning();
        assert_eq!(
            t.stream_receive_window, STREAM_RECEIVE_WINDOW,
            "the documented 300Mb/s config must reproduce the stream window"
        );
        assert_eq!(t.receive_window, RECEIVE_WINDOW);
        assert_eq!(t.send_window, SEND_WINDOW);
        // The guarded invariant, on the values that actually go to
        // `build_transport_tuned`.
        assert!(
            t.stream_receive_window - t.stream_receive_window / 8 > TARGET_BDP_BYTES,
            "the advertised stream window must clear the BDP after quinn's cushion"
        );
        assert!(t.send_window >= TARGET_BDP_BYTES);
        assert!(t.receive_window >= 2 * TARGET_BDP_BYTES);
        // And the shipped default must be the high-throughput 4/8/4 preset the
        // README and the sample configs document; 2/4/2 is the low-memory
        // alternative, and 8/16/8 stays the explicit opt-in tested above.
        let default_conf: ClientConf = toml::from_str(base).unwrap();
        let d = default_conf.tuning();
        assert_eq!(d.stream_receive_window, 4 * 1024 * 1024);
        assert_eq!(d.receive_window, 8 * 1024 * 1024);
        assert_eq!(d.send_window, 4 * 1024 * 1024);
    }
}
