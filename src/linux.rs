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
//!   the NIC budget on a waiting read trades CPU for wakeup latency; off by
//!   default (a router should not burn cycles speculatively).
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

/// `MYQUIC2_BUSY_POLL`: `SO_BUSY_POLL` budget in microseconds. Unset or `0`
/// leaves every socket in normal interrupt-driven mode; values are clamped to
/// [`BUSY_POLL_MAX_US`].
const ENV_BUSY_POLL: &str = "MYQUIC2_BUSY_POLL";

/// Upper clamp for [`busy_poll_us`]. Beyond ~1 ms the poll loop competes with
/// the work it is supposed to accelerate, and a typo should not turn a router
/// into a space heater.
pub const BUSY_POLL_MAX_US: u32 = 1_000;

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

#[cfg(target_os = "linux")]
/// `TCP_DEFER_ACCEPT` timeout in seconds: accept a connection once its first
/// byte arrives, or after this long if it stays silent.
const DEFER_ACCEPT_SECS: i32 = 1;

#[cfg(target_os = "linux")]
/// `TCP_FASTOPEN` listener queue length: pending TFO handshakes the kernel may
/// keep before falling back to the normal handshake.
const FASTOPEN_QLEN: i32 = 16;

/// Effective `SO_BUSY_POLL` budget, parsed once per process (invalid values
/// fall back to off, like every other env knob in this crate).
#[must_use]
pub fn busy_poll_us() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| parse_busy_poll(std::env::var(ENV_BUSY_POLL).ok().as_deref()))
}

fn parse_busy_poll(v: Option<&str>) -> u32 {
    v.and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .min(BUSY_POLL_MAX_US)
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
/// everywhere (the pump writes whole frames; Nagle only adds latency) and
/// `TCP_NOTSENT_LOWAT` on Linux ([`tcp_notsent_lowat`], best-effort).
///
/// Both SOCKS sides call this where they used to call `set_nodelay`: the
/// client on every accepted SOCKS connection, the server on every dialed
/// target connection.
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
    #[cfg(not(target_os = "linux"))]
    let _ = stream;
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
    static SEEN: [(&str, AtomicBool); 5] = [
        ("busy-poll", AtomicBool::new(false)),
        ("busy-poll-prefer", AtomicBool::new(false)),
        ("defer-accept", AtomicBool::new(false)),
        ("fastopen", AtomicBool::new(false)),
        ("notsent-lowat", AtomicBool::new(false)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_poll_parses_clamps_and_defaults_off() {
        assert_eq!(parse_busy_poll(None), 0);
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
}
