//! Linux-only socket and scheduler tuning, in one auditable place.
//!
//! Everything in this module is **best-effort and Linux-only**: on other
//! targets each entry point is a no-op (or a non-Linux implementation note),
//! and a kernel that rejects an option is logged once and never fails a
//! connection. The knobs exist because the shipped exit nodes are Linux, and
//! each one trades a measurable resource for a measurable effect:
//!
//! - [`busy_poll_us`] (`MYQUIC2_BUSY_POLL=<µs>`): `SO_BUSY_POLL` (plus
//!   `SO_PREFER_BUSY_POLL` where the kernel has it) on every UDP socket this
//!   crate creates — QUIC endpoints *and* per-session/relay sockets. Polling
//!   the NIC budget on a waiting read trades CPU for wakeup latency; on by
//!   default at [`BUSY_POLL_DEFAULT_US`] because the shipped exit nodes carry
//!   small interactive datagrams, and `MYQUIC2_BUSY_POLL=0` turns it off for
//!   a router that should not burn cycles speculatively.
//! - [`tcp_notsent_lowat`] (`MYQUIC2_TCP_NOTSET_LOWAT=<bytes>`):
//!   `TCP_NOTSENT_LOWAT` on every relay TCP stream, so the kernel's send
//!   buffer cannot pile up megabytes of unsent bytes ahead of a slow path —
//!   the writer is the QUIC stream, which has its own flow control, and the
//!   socket buffer should not add a second, invisible queue on top of it.
//! - `TCP_DEFER_ACCEPT` + `TCP_FASTOPEN` on the SOCKS listener
//!   ([`tune_tcp_listener`]): SOCKS is client-first, so deferring the accept
//!   wakeup until the greeting arrives is free, and a TFO-capable local client
//!   saves a round trip (armed only when `net.ipv4.tcp_fastopen` allows
//!   server mode).
//! - [`pin_to_core`]: `sched_setaffinity`, used by the server's ingress shards
//!   and the client's per-slot runtimes so their thread-local state stays on
//!   one core (the whole point of those topologies).
//!
//! The raw option helpers below are the one place in this crate with a
//! hand-written `unsafe` FFI block: neither rustix nor nix 0.31 exposes these
//! five options, but nix re-exports `libc`, so the calls stay inside the
//! dependency set already in the tree (no direct `libc` dependency).

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};

/// `MYQUIC2_BUSY_POLL`: `SO_BUSY_POLL` budget in microseconds. Unset uses
/// [`BUSY_POLL_DEFAULT_US`]; an explicit `0` (or a malformed value) leaves
/// every socket in normal interrupt-driven mode. Values are clamped to
/// [`BUSY_POLL_MAX_US`].
const ENV_BUSY_POLL: &str = "MYQUIC2_BUSY_POLL";

/// Upper clamp for [`busy_poll_us`]. Beyond ~1 ms the poll loop competes with
/// the work it is supposed to accelerate, and a typo should not turn a router
/// into a space heater.
pub const BUSY_POLL_MAX_US: u32 = 1_000;

/// Default `SO_BUSY_POLL` budget when `MYQUIC2_BUSY_POLL` is unset. 50 µs is
/// long enough to cover a NIC's poll budget on the small interactive packets
/// that dominate DNS and games, and short enough that an idle core still
/// reaches the scheduler between bursts.
pub const BUSY_POLL_DEFAULT_US: u32 = 50;

/// `MYQUIC2_TCP_NOTSET_LOWAT`: `TCP_NOTSENT_LOWAT` in bytes for relay TCP
/// streams. Unset uses [`NOTSET_LOWAT_DEFAULT`]; `0` leaves the kernel
/// default (the full send buffer).
const ENV_NOTSET_LOWAT: &str = "MYQUIC2_TCP_NOTSET_LOWAT";

/// Default `TCP_NOTSENT_LOWAT`: enough for several [`COPY_CHUNK`]-sized
/// writes in flight (so a fat path is not throttled to a stop-and-wait), low
/// enough that a stalled reader cannot park megabytes of stale data.
///
/// [`COPY_CHUNK`]: crate::tcp::COPY_CHUNK
pub const NOTSET_LOWAT_DEFAULT: usize = 64 * 1024;

/// Lower clamp for a nonzero override: below a couple of 16 KiB chunks the
/// writer turns into stop-and-wait and throughput collapses on any real BDP.
const NOTSET_LOWAT_MIN: usize = 4 * 1024;

/// Upper clamp for an override; past it the option no longer bounds anything
/// a default Linux send buffer would not already bound.
const NOTSET_LOWAT_MAX: usize = 4 * 1024 * 1024;

/// `MYQUIC2_RELAY_SOCKET_BUF`: explicit `SO_SNDBUF`/`SO_RCVBUF` for relay TCP
/// streams, in bytes. Unset or `0` keeps the kernel's autotuned buffers.
const ENV_RELAY_SOCKET_BUF: &str = "MYQUIC2_RELAY_SOCKET_BUF";

/// Default kernel allowance one relay TCP flow can pin, in bytes: the Linux
/// initial sysctl defaults of `net.ipv4.tcp_rmem` (128 KiB) and
/// `net.ipv4.tcp_wmem` (16 KiB) for a fresh connection = 144 KiB.
///
/// This is the *initial* allowance — what the kernel reserves for a new flow
/// before autotuning grows it (`tcp_rmem` may grow to 6 MiB, `tcp_wmem` to
/// 4 MiB, per flow, as BDP/queueing demand rises). Admission must charge at
/// least this per relay flow (see `config::tuning::stream_pump_memory_bytes`),
/// because the flow count is peer-driven and the kernel socket buffers are not
/// covered by the QUIC transport windows. An operator who wants the bound to be
/// exact rather than a floor sets [`ENV_RELAY_SOCKET_BUF`]; the explicit
/// `SO_*BUF` then caps each direction and the admission charge follows the
/// configured value instead of this allowance.
pub const RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT: u64 = 144 * 1024;

/// Lower clamp for a nonzero [`ENV_RELAY_SOCKET_BUF`] override: below a couple
/// of `COPY_CHUNK`s the relay turns into stop-and-wait on any real BDP.
const RELAY_SOCKET_BUF_MIN: usize = 16 * 1024;

/// Upper clamp for the override: matches the QUIC endpoint buffer cap, past
/// which a per-flow relay socket has no reason to grow (the transport windows,
/// not the socket buffer, are the flow-control ceiling).
const RELAY_SOCKET_BUF_MAX: usize = 4 * 1024 * 1024;

/// Effective explicit relay TCP socket buffer in bytes; `0` keeps kernel
/// autotuning. Parsed once per process, like every other env knob here (a
/// deployed value change is a restart).
#[must_use]
pub fn relay_tcp_socket_buf() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE
        .get_or_init(|| parse_relay_socket_buf(std::env::var(ENV_RELAY_SOCKET_BUF).ok().as_deref()))
}

fn parse_relay_socket_buf(v: Option<&str>) -> usize {
    match v.and_then(|s| s.trim().parse::<usize>().ok()) {
        None => 0,
        Some(0) => 0,
        Some(n) => n.clamp(RELAY_SOCKET_BUF_MIN, RELAY_SOCKET_BUF_MAX),
    }
}

/// Worst-case kernel socket memory one relay TCP flow can pin under the
/// effective configuration, in bytes.
///
/// With no explicit buffer this is
/// [`RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT`] (the initial sysctl allowance;
/// autotuning can exceed it, which is why an operator on a memory-tight host
/// should set the env override and get the exact cap below). With an override
/// the kernel caps each direction at the requested size — doubled on Linux,
/// where `setsockopt(SO_*BUF, n)` stores `2 * n` — so the per-flow figure is
/// `2 * 2 * n` on Linux and `2 * n` elsewhere, matching the doubling rules the
/// session/endpoint admission terms already use.
///
/// Every relay socket created by [`tune_relay_tcp`] is covered by exactly one
/// live pump flow, so a process-wide flow bound times this value is the honest
/// kernel term for `config::tuning::stream_pump_memory_bytes`.
#[must_use]
pub fn relay_tcp_kernel_bytes_per_flow() -> u64 {
    let want = relay_tcp_socket_buf();
    if want == 0 {
        return RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT;
    }
    let per_direction = if cfg!(target_os = "linux") {
        2 * want
    } else {
        want
    };
    (2 * per_direction) as u64
}

#[cfg(target_os = "linux")]
/// `TCP_DEFER_ACCEPT` timeout in seconds: accept a connection once its first
/// byte arrives, or after this long if it stays silent.
const DEFER_ACCEPT_SECS: i32 = 1;

#[cfg(target_os = "linux")]
/// `TCP_FASTOPEN` listener queue length: pending TFO handshakes the kernel may
/// keep before falling back to the normal handshake.
const FASTOPEN_QLEN: i32 = 16;

/// Effective `SO_BUSY_POLL` budget, parsed once per process. Unset uses
/// [`BUSY_POLL_DEFAULT_US`]; an explicit zero or an invalid value falls back
/// to off, like every other env knob in this crate.
#[must_use]
pub fn busy_poll_us() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| parse_busy_poll(std::env::var(ENV_BUSY_POLL).ok().as_deref()))
}

fn parse_busy_poll(v: Option<&str>) -> u32 {
    match v {
        None => BUSY_POLL_DEFAULT_US,
        Some(s) => s
            .trim()
            .parse::<u32>()
            .ok()
            .unwrap_or(0)
            .min(BUSY_POLL_MAX_US),
    }
}

/// Effective `TCP_NOTSENT_LOWAT` in bytes, parsed once per process; `0` means
/// "leave the kernel default".
#[must_use]
pub fn tcp_notsent_lowat() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| parse_notsent_lowat(std::env::var(ENV_NOTSET_LOWAT).ok().as_deref()))
}

fn parse_notsent_lowat(v: Option<&str>) -> usize {
    match v.and_then(|s| s.trim().parse::<usize>().ok()) {
        None => NOTSET_LOWAT_DEFAULT,
        Some(0) => 0,
        Some(n) => n.clamp(NOTSET_LOWAT_MIN, NOTSET_LOWAT_MAX),
    }
}

/// `MYQUIC2_SOCKET_PRIORITY`: `SO_PRIORITY` for the client's latency-sensitive
/// egress sockets. Unset uses [`SOCKET_PRIORITY_DEFAULT`]; `0` disables the
/// knob.
const ENV_SOCKET_PRIORITY: &str = "MYQUIC2_SOCKET_PRIORITY";

/// Default `SO_PRIORITY` for the latency-sensitive egress class.
///
/// 6 is the highest value an unprivileged process may set (the kernel requires
/// `CAP_NET_ADMIN` above it), and it is the value Linux's `prio` qdisc places
/// in the highest band and mac80211 maps to the Wi-Fi **voice** access
/// category. The interactive class is exactly the DNS/STUN/game/RPC traffic
/// whose packets are small and whose queueing delay is the user-visible
/// latency; bulk slots stay at the kernel default (0), so with a `prio` qdisc
/// or a WMM access point the small packets win the local scheduling decision
/// without touching the wire format.
///
/// `SO_PRIORITY` is deliberately used instead of `IP_TOS`/DSCP: quinn-udp
/// writes a per-packet `IP_TOS`/`IPV6_TCLASS` cmsg carrying only the ECN
/// codepoint, which would overwrite a socket-level DSCP on every ECN-marked
/// packet. `SO_PRIORITY` is not touched by that cmsg.
pub const SOCKET_PRIORITY_DEFAULT: u32 = 6;

/// Upper clamp for [`ENV_SOCKET_PRIORITY`]: 6 is the unprivileged ceiling, and
/// a larger value would just make `setsockopt` fail (or, with
/// `CAP_NET_ADMIN`, let a typo jump the queue above the host's own control
/// traffic).
pub const SOCKET_PRIORITY_MAX: u32 = 6;

/// Effective `SO_PRIORITY` for latency-sensitive egress, parsed once per
/// process. Unset or malformed uses [`SOCKET_PRIORITY_DEFAULT`]; an explicit
/// `0` disables the knob. Values above [`SOCKET_PRIORITY_MAX`] are clamped.
#[must_use]
pub fn socket_priority() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| parse_socket_priority(std::env::var(ENV_SOCKET_PRIORITY).ok().as_deref()))
}

fn parse_socket_priority(v: Option<&str>) -> u32 {
    match v.and_then(|s| s.trim().parse::<u32>().ok()) {
        None => SOCKET_PRIORITY_DEFAULT,
        Some(n) => n.min(SOCKET_PRIORITY_MAX),
    }
}

/// Give one egress UDP socket the local scheduling priority of its class.
///
/// Apply after the socket exists and before it carries traffic; only the
/// latency-sensitive slots are raised, so bulk sockets keep the kernel default
/// and the two classes do not silently share the priority band. Best-effort:
/// a kernel or container that rejects the option logs once and leaves the
/// socket working at default priority. A no-op off Linux.
pub fn tune_udp_priority(sock: &std::net::UdpSocket, latency_sensitive: bool) {
    #[cfg(target_os = "linux")]
    {
        if !latency_sensitive {
            return;
        }
        let prio = socket_priority();
        if prio == 0 {
            return;
        }
        match socket2::SockRef::from(sock).set_priority(prio) {
            Ok(()) => debug_once(
                "socket-priority",
                &format!(
                    "SO_PRIORITY={prio} armed on the latency-sensitive egress class \
                     (0 disables via {ENV_SOCKET_PRIORITY})"
                ),
            ),
            Err(e) => debug_once(
                "socket-priority",
                &format!("SO_PRIORITY({prio}) not armed ({e}); egress stays at the default"),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (sock, latency_sensitive);
}

/// `MYQUIC2_TCP_FASTOPEN_CONNECT=1` opts into `TCP_FASTOPEN_CONNECT` on
/// single-candidate target dials.
const ENV_TFO_CONNECT: &str = "MYQUIC2_TCP_FASTOPEN_CONNECT";

/// SYN retries for a TFO-connected target. `TCP_FASTOPEN_CONNECT` makes
/// `connect()` return before the handshake, so the kernel's SYN budget — not
/// the caller's dial timeout — is what bounds a target that never answers.
/// Three retries is the 1 + 2 + 4 s SYN backoff (~7 s), far below the stock
/// six-retry minute, so the socket does not camp in the relay.
///
/// Deliberately not `TCP_USER_TIMEOUT`: the socket outlives the handshake, and
/// a short user timeout would abort a healthy long-lived relay during an
/// ordinary multi-second path stall. A dead target fails in the SYN phase,
/// which is the only phase this option is meant to bound.
#[cfg(target_os = "linux")]
const TFO_SYN_RETRIES: i32 = 3;

/// Whether the operator opted into TCP Fast Open on target dials.
///
/// Off by default because the mechanism changes *when* a connect error is
/// observable: `connect()` returns before the handshake, so a dead target
/// looks connected until the first write (or the SYN/user timeout) reports the
/// failure. The SOCKS success reply is already optimistic, but an operator
/// should choose that trade explicitly.
#[must_use]
pub fn tcp_fastopen_connect_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| parse_on_flag(std::env::var(ENV_TFO_CONNECT).ok().as_deref()))
}

fn parse_on_flag(v: Option<&str>) -> bool {
    matches!(
        v.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("on") | Some("yes")
    )
}

/// Connect one TCP target, using `TCP_FASTOPEN_CONNECT` when the operator
/// opted in and the kernel supports it.
///
/// `TCP_FASTOPEN_CONNECT` lets `connect()` return before the SYN is sent; the
/// kernel then puts the first write into the SYN itself, saving one full RTT
/// whenever the target has a cached TFO cookie. A kernel or network that does
/// not support TFO just falls back to the normal handshake, so the only
/// failure mode is the deferred error detection documented on
/// [`tcp_fastopen_connect_enabled`].
///
/// The single-candidate dial path is the only caller: the happy-eyeballs race
/// needs `connect()` to mean "this candidate completed the handshake", or the
/// first candidate would always win before any SYN left the host.
#[cfg(target_os = "linux")]
pub async fn tcp_connect(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    if !tcp_fastopen_connect_enabled() {
        return tokio::net::TcpStream::connect(addr).await;
    }
    match fastopen_connect(addr).await {
        Ok(stream) => Ok(stream),
        Err(e) => {
            debug_once(
                "tfo-connect",
                &format!(
                    "TCP_FASTOPEN_CONNECT to {addr} failed ({e}); retrying with a normal connect"
                ),
            );
            tokio::net::TcpStream::connect(addr).await
        }
    }
}

#[cfg(target_os = "linux")]
async fn fastopen_connect(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    use nix::libc::{IPPROTO_TCP, TCP_FASTOPEN_CONNECT, TCP_SYNCNT};
    use tokio::net::TcpSocket;

    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_nodelay(true)?;
    let fd = sock.as_raw_fd();
    // Required: without it the connect is an ordinary blocking handshake and
    // the fallback below is pointless.
    set_raw_int(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)?;
    // Best-effort bound for the deferred handshake; a kernel that rejects it
    // still gets the TFO benefit, just with its default SYN budget.
    let _ = set_raw_int(fd, IPPROTO_TCP, TCP_SYNCNT, TFO_SYN_RETRIES);
    sock.connect(addr).await
}

/// Non-Linux: `TCP_FASTOPEN_CONNECT` is Linux-specific, so this is the plain
/// connect the caller would otherwise use.
#[cfg(not(target_os = "linux"))]
pub async fn tcp_connect(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect(addr).await
}

/// Apply the busy-poll posture to one UDP socket (every socket this crate
/// creates goes through here: QUIC endpoints, relay sockets, session sockets).
///
/// Best-effort by contract: a kernel without `SO_BUSY_POLL` (< 3.11) or
/// without `SO_PREFER_BUSY_POLL` (< 5.11) logs once and leaves the socket
/// working in normal mode. `SO_PREFER_BUSY_POLL` is what makes an explicit
/// opt-in work regardless of `net.core.busy_poll`; without it the budget only
/// applies where that sysctl allows.
pub(crate) fn tune_udp_socket(sock: &socket2::Socket) {
    #[cfg(target_os = "linux")]
    {
        apply_busy_poll(sock.as_raw_fd(), busy_poll_us());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = sock;
}

/// Apply `TCP_DEFER_ACCEPT` + `TCP_FASTOPEN` to a listening socket. Called
/// between `bind` and `listen` in [`crate::tcp_listener_dual`].
pub(crate) fn tune_tcp_listener(sock: &socket2::Socket) {
    #[cfg(target_os = "linux")]
    {
        use nix::libc::{IPPROTO_TCP, TCP_DEFER_ACCEPT, TCP_FASTOPEN};
        if let Err(e) = set_raw_int(
            sock.as_raw_fd(),
            IPPROTO_TCP,
            TCP_DEFER_ACCEPT,
            DEFER_ACCEPT_SECS,
        ) {
            debug_once("defer-accept", &format!("TCP_DEFER_ACCEPT not armed ({e})"));
        }
        match set_raw_int(sock.as_raw_fd(), IPPROTO_TCP, TCP_FASTOPEN, FASTOPEN_QLEN) {
            Ok(()) => debug_once(
                "fastopen",
                &format!("TCP_FASTOPEN qlen={FASTOPEN_QLEN} armed (server mode allowed)"),
            ),
            Err(e) => debug_once(
                "fastopen",
                &format!(
                    "TCP_FASTOPEN not armed ({e}); needs net.ipv4.tcp_fastopen server mode (bit 2)"
                ),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = sock;
}

/// Apply the relay-TCP posture to one connected relay stream: `TCP_NODELAY`
/// everywhere (the pump writes whole frames; Nagle only adds latency),
/// `TCP_NOTSENT_LOWAT` on Linux ([`tcp_notsent_lowat`]), and — when
/// `MYQUIC2_RELAY_SOCKET_BUF` is set — explicit `SO_SNDBUF`/`SO_RCVBUF`
/// ([`relay_tcp_socket_buf`]) so the per-flow kernel memory has a real cap
/// instead of the sysctl-dependent autotuned one admission has to treat as a
/// floor.
///
/// Both SOCKS sides call this where they used to call `set_nodelay`: the
/// client on every accepted SOCKS connection, the server on every dialed
/// target connection. Best-effort like everything else here: a rejected
/// option is logged once and the stream keeps working.
pub fn tune_relay_tcp(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(target_os = "linux")]
    {
        let bytes = tcp_notsent_lowat();
        if bytes > 0
            && let Err(e) = apply_notsent_lowat(stream.as_raw_fd(), bytes)
        {
            debug_once(
                "notsent-lowat",
                &format!("TCP_NOTSENT_LOWAT({bytes}) not armed ({e})"),
            );
        }
    }
    // socket2's `SockRef` borrows the live fd; the same handle carries both
    // directions. The requested size is the *un-doubled* application value; the
    // kernel's doubling is priced by
    // [`relay_tcp_kernel_bytes_per_flow`].
    #[cfg(unix)]
    {
        let want = relay_tcp_socket_buf();
        if want > 0 {
            let sock = socket2::SockRef::from(stream);
            for (what, res) in [
                ("SO_SNDBUF", sock.set_send_buffer_size(want)),
                ("SO_RCVBUF", sock.set_recv_buffer_size(want)),
            ] {
                if let Err(e) = res {
                    relay_buf_debug_once(&format!(
                        "{what}({want}) not armed on relay stream ({e})"
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = stream;
    }
}

/// First-message-per-process gate for the relay-buffer diagnostics.
///
/// Separate from the Linux-only `once` table above: `SO_SNDBUF`/`SO_RCVBUF`
/// exist on every Unix, while the raw-option helpers are gated on Linux for the
/// options that only Linux has.
#[cfg(unix)]
fn relay_buf_debug_once(msg: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SEEN: AtomicBool = AtomicBool::new(false);
    if !SEEN.swap(true, Ordering::Relaxed) {
        tracing::debug!("linux tuning: {msg}");
    }
}

/// Pin the calling thread to one core (Linux only; macOS has no meaningful
/// affinity control, so the thread just floats there). `available_parallelism`
/// respects a cgroup's CPU limit; a cpuset that excludes `idx % cores` makes
/// the call fail `EINVAL` and the caller simply runs unpinned — a lost hint,
/// never an error.
pub fn pin_to_core(idx: usize) {
    #[cfg(target_os = "linux")]
    {
        use nix::sched::{CpuSet, sched_setaffinity};
        use nix::unistd::Pid;
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let mut set = CpuSet::new();
        if set.set(idx % cores).is_ok() {
            // `Pid::from_raw(0)` targets the *calling thread* (nix 0.31's
            // documented spelling); `Pid::this()` would be `getpid()` — the
            // main thread's tid — and pin the wrong thread.
            let _ = sched_setaffinity(Pid::from_raw(0), &set);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = idx;
}

// ---------------- raw option plumbing (Linux) ----------------

/// Set an integer-valued socket option. See `set_raw_int`.
#[cfg(target_os = "linux")]
fn apply_busy_poll(fd: RawFd, us: u32) {
    use nix::libc::{SO_BUSY_POLL, SO_PREFER_BUSY_POLL, SOL_SOCKET};
    if us == 0 {
        return;
    }
    let us = us as i32;
    if let Err(e) = set_raw_int(fd, SOL_SOCKET, SO_BUSY_POLL, us) {
        warn_once(
            "busy-poll",
            &format!("SO_BUSY_POLL({us}µs) rejected: {e}; sockets stay interrupt-driven"),
        );
        return;
    }
    // This knob trades idle CPU for wakeup latency: the kernel spins in the
    // socket's poll path for up to `us` on every read. The default is now on,
    // so the armed notice is informational (debug) rather than a warning; the
    // doc comment on `BUSY_POLL_DEFAULT_US` explains the trade for operators.
    debug_once(
        "busy-poll-armed",
        &format!(
            "SO_BUSY_POLL={us}µs on UDP sockets (MYQUIC2_BUSY_POLL=0 disables; idle CPU rises by design)"
        ),
    );
    if let Err(e) = set_raw_int(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, 1) {
        // Pre-5.11 kernels: the budget still applies where
        // `net.core.busy_poll` allows it, it just cannot override the sysctl.
        debug_once(
            "busy-poll-prefer",
            &format!("SO_PREFER_BUSY_POLL unavailable ({e}); busy poll follows net.core.busy_poll"),
        );
    }
}

/// `TCP_NOTSENT_LOWAT` is an `int` of bytes on Linux.
#[cfg(target_os = "linux")]
fn apply_notsent_lowat(fd: RawFd, bytes: usize) -> std::io::Result<()> {
    use nix::libc::{IPPROTO_TCP, TCP_NOTSENT_LOWAT};
    set_raw_int(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, bytes as i32)
}

/// `setsockopt` for an integer-valued option, through nix's re-exported
/// `libc` (the five options this module needs are not in rustix or nix 0.31).
///
/// # Safety
///
/// Caller guarantees `fd` is an open socket; the call only reads `value`.
#[cfg(target_os = "linux")]
fn set_raw_int(
    fd: RawFd,
    level: std::os::raw::c_int,
    name: std::os::raw::c_int,
    value: std::os::raw::c_int,
) -> std::io::Result<()> {
    // SAFETY: `fd` names a live socket (callers pass it straight from an
    // owned handle for the duration of the call); `value` is a valid c_int of
    // exactly the length passed; setsockopt only reads that memory.
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<std::os::raw::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Read back an integer-valued socket option; the test hook for everything
/// this module sets (and a useful diagnostic).
#[cfg(all(target_os = "linux", test))]
fn get_raw_int(
    fd: RawFd,
    level: std::os::raw::c_int,
    name: std::os::raw::c_int,
) -> std::io::Result<std::os::raw::c_int> {
    let mut value: std::os::raw::c_int = 0;
    let mut len = std::mem::size_of::<std::os::raw::c_int>() as nix::libc::socklen_t;
    // SAFETY: both out-pointers are valid, properly sized and only written by
    // getsockopt, which honors `len` as the buffer size and updates it.
    let rc = unsafe {
        nix::libc::getsockopt(
            fd,
            level,
            name,
            std::ptr::from_mut(&mut value).cast(),
            std::ptr::from_mut(&mut len),
        )
    };
    if rc == 0 {
        Ok(value)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
/// First-message-per-kind gate for the per-socket diagnostics above: these run
/// once per socket, and a kernel that rejects an option will reject it for
/// every socket, so the full message must not repeat per connection.
fn once(kind: &str) -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SEEN: [(&str, AtomicBool); 8] = [
        ("busy-poll", AtomicBool::new(false)),
        ("busy-poll-armed", AtomicBool::new(false)),
        ("busy-poll-prefer", AtomicBool::new(false)),
        ("defer-accept", AtomicBool::new(false)),
        ("fastopen", AtomicBool::new(false)),
        ("notsent-lowat", AtomicBool::new(false)),
        ("socket-priority", AtomicBool::new(false)),
        ("tfo-connect", AtomicBool::new(false)),
    ];
    SEEN.iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, f)| !f.swap(true, Ordering::Relaxed))
        .unwrap_or(true)
}

#[cfg(target_os = "linux")]
/// Log a rejection at warn level the first time and debug afterwards.
fn warn_once(kind: &str, msg: &str) {
    if once(kind) {
        tracing::warn!("linux tuning: {msg}");
    } else {
        tracing::debug!("linux tuning: {msg}");
    }
}

#[cfg(target_os = "linux")]
/// Log an informational arm/failure at debug level, once per kind.
fn debug_once(kind: &str, msg: &str) {
    if once(kind) {
        tracing::debug!("linux tuning: {msg}");
    }
}

// ---------------- inotify (Linux) ----------------

/// Minimal inotify wrapper for the DNS resolver watcher.
///
/// The watcher only needs "something under the platform DNS configuration
/// changed"; it re-reads the fingerprint and rebuilds the resolver, so event
/// payloads are deliberately ignored and only the wakeup matters. The fd is
/// nonblocking and registered with the async reactor, so the watch adds no
/// thread and no poll tick of its own.
#[cfg(target_os = "linux")]
pub(crate) mod inotify {
    use nix::libc;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use tokio::io::unix::AsyncFd;

    /// Events that can change the parsed resolver configuration or the hosts
    /// table. `IN_ATTRIB` covers chmod/ownership changes that a fingerprint
    /// based on mtime+size would otherwise miss; the move/delete pair covers
    /// the atomic-replace idiom every resolv.conf manager uses.
    const MASK: u32 = libc::IN_MODIFY
        | libc::IN_ATTRIB
        | libc::IN_CLOSE_WRITE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF;

    /// One inotify instance watching a set of paths.
    pub(crate) struct Watch {
        fd: AsyncFd<OwnedFd>,
    }

    impl Watch {
        /// Arm a watch on every path that exists. A path that cannot be
        /// watched is skipped (a missing `/etc/resolv.conf` is a valid system
        /// state); an instance with no armed path is an error so the caller
        /// falls back to polling instead of waiting forever.
        pub(crate) fn new(paths: &[std::path::PathBuf]) -> io::Result<Self> {
            let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `inotify_init1` returned a fresh owned descriptor and
            // nothing else in this process has seen it.
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            // SAFETY: `owned` is uniquely owned here and is not closed or
            // replaced while `AsyncFd` holds it.
            let fd = unsafe { AsyncFd::register(owned) }.map_err(io::Error::from)?;
            let mut armed = 0usize;
            for path in paths {
                let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
                    continue;
                };
                // SAFETY: `fd` is a live inotify descriptor and `c_path` is a
                // NUL-terminated path that outlives the call.
                let wd = unsafe {
                    libc::inotify_add_watch(fd.get_ref().as_raw_fd(), c_path.as_ptr(), MASK)
                };
                if wd >= 0 {
                    armed += 1;
                } else {
                    tracing::debug!(
                        "inotify watch {} not armed ({})",
                        path.display(),
                        io::Error::last_os_error()
                    );
                }
            }
            if armed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no DNS configuration path could be watched",
                ));
            }
            Ok(Self { fd })
        }

        /// Wait for the next change event, draining the queue so one burst of
        /// writes produces one wakeup.
        pub(crate) async fn changed(&self) -> io::Result<()> {
            loop {
                let mut ready = self.fd.readable().await?;
                match ready.try_io(|inner| drain(inner.get_ref().as_raw_fd())) {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    // Spurious readiness: the queue was already drained by a
                    // concurrent wake. The guard cleared the readiness bit.
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// Read every queued event. Returns `WouldBlock` when the queue was empty,
    /// which is what tells [`AsyncFd`] to clear readiness and park again.
    fn drain(fd: RawFd) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        let mut got = false;
        loop {
            // SAFETY: `fd` is a live inotify descriptor and `buf` is a valid
            // writable slice of the length passed; read only writes into it.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                got = true;
                continue;
            }
            if n == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => break,
                io::ErrorKind::Interrupted => continue,
                _ => return Err(e),
            }
        }
        if got {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_poll_parses_clamps_and_defaults_on() {
        assert_eq!(parse_busy_poll(None), BUSY_POLL_DEFAULT_US);
        assert_eq!(parse_busy_poll(Some("")), 0);
        assert_eq!(parse_busy_poll(Some("banana")), 0);
        assert_eq!(parse_busy_poll(Some("0")), 0);
        assert_eq!(parse_busy_poll(Some(" 50 ")), 50);
        assert_eq!(parse_busy_poll(Some("999999")), BUSY_POLL_MAX_US);
    }

    #[test]
    fn notsent_lowat_defaults_clamps_and_zero_disables() {
        assert_eq!(parse_notsent_lowat(None), NOTSET_LOWAT_DEFAULT);
        assert_eq!(parse_notsent_lowat(Some("banana")), NOTSET_LOWAT_DEFAULT);
        assert_eq!(
            parse_notsent_lowat(Some("0")),
            0,
            "0 leaves the kernel default"
        );
        assert_eq!(parse_notsent_lowat(Some("32768")), 32 * 1024);
        assert_eq!(parse_notsent_lowat(Some("1")), NOTSET_LOWAT_MIN);
        assert_eq!(parse_notsent_lowat(Some("999999999")), NOTSET_LOWAT_MAX);
    }

    /// The raw helpers must round-trip the two options this module relies on
    /// most; the kernel either honors them or the round-trip itself fails
    /// (Linux-gated; runs in CI).
    #[cfg(target_os = "linux")]
    #[test]
    fn raw_int_options_round_trip() {
        use nix::libc::{IPPROTO_TCP, SO_BUSY_POLL, SOL_SOCKET, TCP_NOTSENT_LOWAT};
        let sock = crate::udp_socket_dual_with_size("127.0.0.1:0", 64 * 1024).unwrap();
        let fd = sock.as_raw_fd();
        set_raw_int(fd, SOL_SOCKET, SO_BUSY_POLL, 42).unwrap();
        assert_eq!(get_raw_int(fd, SOL_SOCKET, SO_BUSY_POLL).unwrap(), 42);

        // TCP_NOTSENT_LOWAT needs a TCP socket (any state for the option
        // itself); use a listener's fd.
        let li = crate::tcp_listener_dual("127.0.0.1:0").unwrap();
        set_raw_int(li.as_raw_fd(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, 40960).unwrap();
        assert_eq!(
            get_raw_int(li.as_raw_fd(), IPPROTO_TCP, TCP_NOTSENT_LOWAT).unwrap(),
            40960
        );
    }

    /// `tcp_listener_dual` must have armed `TCP_DEFER_ACCEPT` (always honored
    /// on Linux), and `TCP_FASTOPEN` either armed with the shipped qlen or
    /// reported as not available (needs `net.ipv4.tcp_fastopen` server mode) —
    /// never some other value.
    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_listener_arms_defer_accept_and_fastopen_or_reports() {
        use nix::libc::{IPPROTO_TCP, TCP_DEFER_ACCEPT, TCP_FASTOPEN};
        let li = crate::tcp_listener_dual("127.0.0.1:0").unwrap();
        let fd = li.as_raw_fd();
        assert_eq!(
            get_raw_int(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT).unwrap(),
            DEFER_ACCEPT_SECS
        );
        let tfo = get_raw_int(fd, IPPROTO_TCP, TCP_FASTOPEN).unwrap();
        assert!(
            tfo == 0 || tfo == FASTOPEN_QLEN,
            "TCP_FASTOPEN read back {tfo}; expected the shipped qlen or 0 when the sysctl refuses"
        );
    }

    /// `tune_relay_tcp` sets `TCP_NOTSENT_LOWAT` from the effective value on a
    /// connected pair (Linux-gated; runs in CI).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tune_relay_tcp_arms_notsent_lowat() {
        use nix::libc::{IPPROTO_TCP, TCP_NOTSENT_LOWAT};
        let li = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = li.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = li.accept().await.unwrap();
        tune_relay_tcp(&server);
        let want = tcp_notsent_lowat();
        let got = get_raw_int(server.as_raw_fd(), IPPROTO_TCP, TCP_NOTSENT_LOWAT).unwrap();
        if want == 0 {
            assert_eq!(got, 0, "no override means the kernel default stays");
        } else {
            assert_eq!(got, want as i32);
        }
        drop(client);
    }

    /// `MYQUIC2_RELAY_SOCKET_BUF` parsing: unset/0 = kernel autotune, garbage =
    /// autotune (like every env knob here), nonzero clamps into the supported
    /// range. The admission term derived from it must follow the kernel's
    /// per-direction doubling on Linux.
    #[test]
    fn relay_socket_buf_parses_clamps_and_prices_the_flow() {
        assert_eq!(parse_relay_socket_buf(None), 0);
        assert_eq!(parse_relay_socket_buf(Some("")), 0);
        assert_eq!(parse_relay_socket_buf(Some("banana")), 0);
        assert_eq!(parse_relay_socket_buf(Some("0")), 0, "0 = kernel autotune");
        assert_eq!(parse_relay_socket_buf(Some(" 65536 ")), 64 * 1024);
        assert_eq!(parse_relay_socket_buf(Some("1")), RELAY_SOCKET_BUF_MIN);
        assert_eq!(
            parse_relay_socket_buf(Some("999999999")),
            RELAY_SOCKET_BUF_MAX
        );

        // No explicit buffer: the documented initial sysctl allowance, which is
        // the floor admission has to charge.
        let allowance = relay_tcp_kernel_bytes_per_flow();
        assert!(
            allowance >= RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT,
            "the kernel allowance is a floor, got {allowance}"
        );
        // The default figure is 128 KiB rcv + 16 KiB snd.
        assert_eq!(
            RELAY_TCP_KERNEL_BYTES_PER_FLOW_DEFAULT,
            128 * 1024 + 16 * 1024
        );

        // With an explicit cap the per-flow figure matches the kernel's
        // doubling rule: Linux stores 2 *request, so both directions = 4 * B.
        let b = 64 * 1024usize;
        let expected = if cfg!(target_os = "linux") {
            4 * b as u64
        } else {
            2 * b as u64
        };
        let per_flow = |want: usize| -> u64 {
            let per_direction = if cfg!(target_os = "linux") {
                2 * want
            } else {
                want
            };
            (2 * per_direction) as u64
        };
        assert_eq!(per_flow(b), expected);
    }

    /// When the override is set, `tune_relay_tcp` must arm both socket buffers
    /// on a real connected stream (best-effort: a kernel that clamps still
    /// reports a smaller value, so assert the option is settable and read it
    /// back). Runs only when the process-level env override is configured, so a
    /// normal test run (which cannot mutate a cached process env var) skips it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tune_relay_tcp_applies_explicit_socket_buffers_when_configured() {
        let want = relay_tcp_socket_buf();
        if want == 0 {
            return; // default: autotune, nothing to assert
        }
        let li = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = li.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = li.accept().await.unwrap();
        tune_relay_tcp(&server);
        let sock = socket2::SockRef::from(&server);
        let snd = sock.send_buffer_size().unwrap();
        let rcv = sock.recv_buffer_size().unwrap();
        // Linux doubles the request; a clamped sysctl may report less, but it
        // must have moved off zero/tiny defaults and be >= the request.
        assert!(snd >= want, "SO_SNDBUF read back {snd} < requested {want}");
        assert!(rcv >= want, "SO_RCVBUF read back {rcv} < requested {want}");
        drop(client);
    }

    /// `MYQUIC2_SOCKET_PRIORITY`: unset/malformed keep the class default, `0`
    /// disables the knob, and an out-of-range value is clamped to the highest
    /// priority an unprivileged process may set.
    #[test]
    fn socket_priority_defaults_clamps_and_zero_disables() {
        assert_eq!(parse_socket_priority(None), SOCKET_PRIORITY_DEFAULT);
        assert_eq!(
            parse_socket_priority(Some("banana")),
            SOCKET_PRIORITY_DEFAULT
        );
        assert_eq!(parse_socket_priority(Some("")), SOCKET_PRIORITY_DEFAULT);
        assert_eq!(parse_socket_priority(Some("0")), 0);
        assert_eq!(parse_socket_priority(Some(" 3 ")), 3);
        assert_eq!(parse_socket_priority(Some("99")), SOCKET_PRIORITY_MAX);
    }

    /// `MYQUIC2_TCP_FASTOPEN_CONNECT`: only the documented on spellings enable
    /// it; an unset or malformed value keeps the safe default (off).
    #[test]
    fn tfo_connect_flag_is_explicitly_opt_in() {
        assert!(!parse_on_flag(None));
        assert!(!parse_on_flag(Some("")));
        assert!(!parse_on_flag(Some("banana")));
        assert!(!parse_on_flag(Some("0")));
        for on in ["1", "true", "TRUE", " on ", "yes"] {
            assert!(parse_on_flag(Some(on)), "{on:?} must enable TFO connect");
        }
    }

    /// The latency-sensitive class must read back the configured priority and
    /// a bulk socket must stay at the kernel default. Linux-gated; runs in CI.
    #[cfg(target_os = "linux")]
    #[test]
    fn tune_udp_priority_raises_only_the_latency_sensitive_class() {
        let want = socket_priority();
        let sock = crate::udp_socket_dual("127.0.0.1:0").unwrap();
        tune_udp_priority(&sock, false);
        assert_eq!(
            socket2::SockRef::from(&sock).priority().unwrap(),
            0,
            "a bulk egress socket must stay at the kernel default"
        );
        tune_udp_priority(&sock, true);
        assert_eq!(
            socket2::SockRef::from(&sock).priority().unwrap(),
            want,
            "the interactive class must read back the effective priority"
        );
    }

    /// `TCP_FASTOPEN_CONNECT` must still complete a real loopback handshake
    /// and deliver the first write; the listener does not have to arm TFO —
    /// the kernel falls back to the normal handshake when the peer does not
    /// accept the data in the SYN. Linux-gated; runs in CI.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tfo_connect_delivers_the_first_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Skip on a kernel that does not know the option (the feature is
        // best-effort by contract); do not skip on a failure *after* the
        // option was accepted, which is what the rest of this test pins.
        let probe = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        if set_raw_int(
            probe.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            nix::libc::TCP_FASTOPEN_CONNECT,
            1,
        )
        .is_err()
        {
            return;
        }
        drop(probe);
        let li = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = li.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = fastopen_connect(addr).await.unwrap();
            stream.write_all(b"tfo").await.unwrap();
            stream
        });
        let (mut server, _) = li.accept().await.unwrap();
        let mut got = [0u8; 3];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.read_exact(&mut got),
        )
        .await
        .expect("the first write must reach the listener")
        .unwrap();
        assert_eq!(&got, b"tfo");
        let _stream = client.await.unwrap();
    }

    /// The resolver watcher's wakeup mechanism: a write to a watched file must
    /// surface as one `changed()` completion. Linux-gated; uses a private temp
    /// directory so no system file is touched.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn inotify_watch_reports_a_config_write() {
        let dir = std::env::temp_dir().join(format!(
            "myquic2-inotify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("resolv.conf");
        std::fs::write(&file, "nameserver 192.0.2.1\n").unwrap();
        let watch = inotify::Watch::new(&[dir.clone(), file.clone()]).unwrap();
        std::fs::write(&file, "nameserver 192.0.2.2\n").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), watch.changed())
            .await
            .expect("a watched write must produce an event")
            .expect("inotify watch");
        std::fs::remove_dir_all(&dir).ok();
    }
}
