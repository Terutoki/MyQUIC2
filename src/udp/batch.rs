//! Last-hop UDP batching: bounded drain loops + Linux-gated `sendmmsg`.
//!
//! Baseline finding: blast collapse is buffer drops, so batching must reduce
//! the syscall rate without growing queues unbounded. Every drain on this path
//! is therefore bounded by [`LAST_HOP_DRAIN`] (32/poll): one readiness event
//! moves at most 32 datagrams, and Tokio keeps readiness set until a
//! `WouldBlock`, so the remainder is picked up on the next poll instead of
//! queueing in userspace.
//!
//! Two batching layers, deliberately split by reactor ownership:
//!
//! - **Receive drain (portable).** The hot loops keep their `recv_from().await`
//!   for the first datagram (so Tokio's readiness integration is untouched)
//!   and then drain up to `LAST_HOP_DRAIN - 1` more with `try_recv_from`.
//!   This amortizes one task wakeup over up to 32 datagrams on every platform.
//!   `recvmmsg` is *probed* ([`recvmmsg_available`]) for measurement only: a
//!   raw `recvmmsg` on a Tokio-owned socket would bypass the reactor's
//!   readiness bookkeeping, so the portable drain loop is the deployed recv
//!   path and the probe exists so benches can report what the kernel offers.
//! - **Send grouping (Linux `sendmmsg`, portable fallback).**
//!   [`udp_try_send_grouped`](crate::udp::udp_try_send_grouped) sends up to
//!   `LAST_HOP_DRAIN` already-encoded frames for one destination in a single
//!   `sendmmsg` syscall on Linux; everywhere else — macOS, non-Linux, or a
//!   kernel that returns `ENOSYS` — it falls back to one `try_send_to` per
//!   frame. Either way each frame keeps exactly-once accounting (`sent`, or
//!   `WouldBlock` into the existing detached-retry pool, or `failed`), so the
//!   retry contract in `retry.rs` is unchanged: only the syscall count moves.
//!
//! Truncation detection is orthogonal and preserved: every drained receive
//! still checks `n == buf.len()` per datagram (see [`TRUNCATION_NOTE`]).

#[cfg(feature = "stats")]
use std::sync::atomic::{AtomicU64, Ordering};

/// Bound on one drain burst: first datagram from `recv_from().await`, the rest
/// from `try_recv_from`. 32 keeps one poll's work small enough that a flooding
/// flow cannot starve sibling branches, while amortizing the wakeup.
///
/// Truncation detection stays per datagram: the kernel truncates a datagram
/// larger than the receive buffer and reports only the buffer length, and
/// every receive site sizes its buffer one slack byte past the protocol cap
/// (`UDP_RECV_SLACK`) precisely so `n == buf.len()` means "truncated".
/// Draining changes *how many* receives run per poll, never the buffer
/// length, so the check fires exactly as before.
pub const LAST_HOP_DRAIN: usize = 32;

// ---------------------------------------------------------------------------
// Batch-size / syscall accounting (stats builds only)
// ---------------------------------------------------------------------------

/// Drain-burst sizes, bucketed by burst length: 1, 2-4, 5-8, 9-16, 17-32.
/// A healthy saturated link sits in the top buckets; a persistent bucket-0
/// with falling pps means the drain never fills (the peer, not the loop).
#[cfg(feature = "stats")]
static DRAIN_HIST: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Grouped-send flushes by group size, same buckets as [`DRAIN_HIST`].
#[cfg(feature = "stats")]
static SEND_HIST: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Actual last-hop send syscalls issued by the grouped path (one `sendmmsg`,
/// or one per frame on the fallback). `syscall_per_packet = SYSCALLS / pkts`.
#[cfg(feature = "stats")]
static SEND_SYSCALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "stats")]
fn bucket(n: usize) -> usize {
    match n {
        0 | 1 => 0,
        2..=4 => 1,
        5..=8 => 2,
        9..=16 => 3,
        _ => 4,
    }
}

/// Record one receive-drain burst of `n` datagrams (call once per poll).
pub fn record_drain_batch(n: usize) {
    stats_only! {
        if n > 0 {
            DRAIN_HIST[bucket(n)].fetch_add(1, Ordering::Relaxed);
        }
    }
    let _ = n;
}

/// Record one grouped-send flush of `n` frames issued in `syscalls` syscalls.
pub fn record_send_group(n: usize, syscalls: u64) {
    stats_only! {
        if n > 0 {
            SEND_HIST[bucket(n)].fetch_add(1, Ordering::Relaxed);
            SEND_SYSCALLS.fetch_add(syscalls, Ordering::Relaxed);
        }
    }
    let _ = (n, syscalls);
}

/// One-line burst-latency / syscall report for the 60 s budget line or benches:
/// drain-burst histogram, send-group histogram, and send syscalls issued.
pub fn batch_report() -> String {
    #[cfg(feature = "stats")]
    {
        let h = |a: &[AtomicU64; 5]| {
            format!(
                "1:{} 2-4:{} 5-8:{} 9-16:{} 17-32:{}",
                a[0].load(Ordering::Relaxed),
                a[1].load(Ordering::Relaxed),
                a[2].load(Ordering::Relaxed),
                a[3].load(Ordering::Relaxed),
                a[4].load(Ordering::Relaxed),
            )
        };
        format!(
            "drain[{}] send[{}] send_syscalls={}",
            h(&DRAIN_HIST),
            h(&SEND_HIST),
            SEND_SYSCALLS.load(Ordering::Relaxed),
        )
    }
    #[cfg(not(feature = "stats"))]
    {
        String::from("batch stats compiled out (--no-default-features)")
    }
}

// ---------------------------------------------------------------------------
// sendmmsg / recvmmsg availability probe (Linux-gated, runtime-checked)
// ---------------------------------------------------------------------------

/// Whether the running kernel serves `sendmmsg` on UDP.
///
/// Linux-only symbol *and* runtime-gated: a seccomp filter or an old kernel
/// can return `ENOSYS` where the symbol exists, so the first call performs one
/// real 1-message `sendmmsg` on a loopback socket (via `socket2` for
/// construction and `libc` for the call) and caches the answer. Non-Linux
/// targets report `false` without touching `libc`'s Linux-only symbols, so
/// macOS and musl-static builds compile and run on the portable fallback.
pub fn sendmmsg_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PROBE.get_or_init(probe_sendmmsg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Whether the running kernel serves `recvmmsg` on UDP. Same gating contract
/// as [`sendmmsg_available`]: probed once, cached, `false` off Linux.
/// Measurement-only (see the module docs): the deployed recv path is the
/// portable `try_recv_from` drain, which keeps Tokio's readiness intact.
pub fn recvmmsg_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PROBE.get_or_init(probe_recvmmsg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Which batched-I/O backend this process will actually use.
pub fn batch_backend() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        match (sendmmsg_available(), recvmmsg_available()) {
            (true, true) => "sendmmsg+recvmmsg",
            (true, false) => "sendmmsg-only",
            (false, true) => "recvmmsg-probe-only/send-fallback",
            (false, false) => "portable-fallback",
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        "portable-fallback"
    }
}

#[cfg(target_os = "linux")]
fn probe_sendmmsg() -> bool {
    use std::os::unix::io::AsRawFd;
    let tx = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rx = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    if rx.bind(&loopback.into()).is_err() {
        return false;
    }
    let dst: std::net::SocketAddr = rx
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .unwrap_or(loopback);
    if tx.set_nonblocking(true).is_err() {
        return false;
    }
    // One 1-byte message: proves the syscall exists and works, nothing more.
    let payload = [0x5Au8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut storage = sockaddr_storage_for(&dst);
    let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
    hdr.msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    hdr.msg_hdr.msg_namelen = sockaddr_len_for(&dst);
    hdr.msg_hdr.msg_iov = &mut iov;
    hdr.msg_hdr.msg_iovlen = 1;
    // SAFETY: fd is a live non-blocking UDP socket, hdrs points at one
    // initialised mmsghdr whose iovec points at a live 1-byte buffer.
    let r = unsafe { libc::sendmmsg(tx.as_raw_fd(), &mut hdr, 1, 0) };
    r == 1
}

#[cfg(target_os = "linux")]
fn probe_recvmmsg() -> bool {
    use std::os::unix::io::AsRawFd;
    let tx = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rx = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    if rx.bind(&loopback.into()).is_err() {
        return false;
    }
    if tx.set_nonblocking(true).is_err() || rx.set_nonblocking(true).is_err() {
        return false;
    }
    let dst: std::net::SocketAddr = rx
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .unwrap_or(loopback);
    // `send_to` needs a SockAddr; build it from the bound address.
    let dst_sa: socket2::SockAddr = dst.into();
    if tx.send_to(&[0x5Au8; 1], &dst_sa).is_err() {
        return false;
    }
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
    hdr.msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    hdr.msg_hdr.msg_iov = &mut iov;
    hdr.msg_hdr.msg_iovlen = 1;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    // SAFETY: fd is a live UDP socket with one datagram queued; hdrs points at
    // one initialised mmsghdr; timeout points at a live timespec.
    let r = unsafe { libc::recvmmsg(rx.as_raw_fd(), &mut hdr, 1, 0, &mut ts) };
    r == 1
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_for(addr: &std::net::SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(a) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()).to_be(),
            };
        }
        std::net::SocketAddr::V6(a) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = 0;
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: a.ip().octets(),
            };
            sin6.sin6_scope_id = a.scope_id();
        }
    }
    storage
}

#[cfg(target_os = "linux")]
fn sockaddr_len_for(addr: &std::net::SocketAddr) -> libc::socklen_t {
    match addr {
        std::net::SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        std::net::SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    }
}

/// Batch-send already-encoded frames to one destination on a Tokio UDP socket.
///
/// Returns the number of frames handed to the kernel. On Linux with a working
/// `sendmmsg` this is one syscall for up to `LAST_HOP_DRAIN` frames; on the
/// portable fallback it loops `try_send_to` once per frame. `EAGAIN` (or any
/// short send) stops the fast path at the first unsent frame and reports how
/// far it got — the caller sends the remainder per frame so each keeps its own
/// `WouldBlock` → detached-retry treatment. Never blocks, never spawns.
///
/// `fd` must be the socket's raw fd (already non-blocking via Tokio).
/// `dst` is the single destination every frame goes to.
#[cfg(target_os = "linux")]
pub(crate) fn sendmmsg_frames(
    fd: std::os::unix::io::RawFd,
    dst: &std::net::SocketAddr,
    frames: &[&[u8]],
) -> (usize, Option<std::io::Error>) {
    let n = frames.len().min(LAST_HOP_DRAIN);
    if n == 0 {
        return (0, None);
    }
    let mut iovs: Vec<libc::iovec> = frames[..n]
        .iter()
        .map(|f| libc::iovec {
            iov_base: f.as_ptr() as *mut libc::c_void,
            iov_len: f.len(),
        })
        .collect();
    let storage = sockaddr_storage_for(dst);
    let namelen = sockaddr_len_for(dst);
    let mut hdrs: Vec<libc::mmsghdr> = (0..n)
        .map(|i| {
            let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
            h.msg_hdr.msg_name = &storage as *const _ as *mut libc::c_void;
            h.msg_hdr.msg_namelen = namelen;
            // SAFETY: `iovs` outlives the syscall below; each entry borrows a
            // live frame for the call's duration.
            h.msg_hdr.msg_iov = unsafe { iovs.as_mut_ptr().add(i) };
            h.msg_hdr.msg_iovlen = 1;
            h
        })
        .collect();
    // SAFETY: fd is a live non-blocking UDP socket; hdrs holds n initialised
    // mmsghdrs sharing one destination storage; iovecs borrow live frames.
    let r = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), n as u32, 0) };
    if r < 0 {
        (0, Some(std::io::Error::last_os_error()))
    } else {
        (r as usize, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_bound_is_32() {
        assert_eq!(LAST_HOP_DRAIN, 32, "drain burst bound must stay 32/poll");
    }

    /// The probe is callable everywhere and reports the portable fallback off
    /// Linux (this host is macOS, so both must be false here without panicking).
    #[test]
    fn probes_report_a_backend_string() {
        let b = batch_backend();
        assert!(!b.is_empty(), "backend string must always be set: {b}");
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!sendmmsg_available(), "no sendmmsg off Linux");
            assert!(!recvmmsg_available(), "no recvmmsg off Linux");
            assert_eq!(b, "portable-fallback");
        }
    }

    /// Truncation detection survives drain loops: a datagram larger than the
    /// buffer still reports `n == buf.len()`, which is the predicate every
    /// drained receive site checks per datagram.
    #[test]
    fn truncation_predicate_fires_for_oversized_datagram() {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        // Small buffer on purpose: the kernel must truncate the 300 B payload.
        let mut buf = [0u8; 64];
        tx.send_to(&[0x5Au8; 300], rx.local_addr().unwrap())
            .unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(n, buf.len(), "oversized datagram must fill the buffer");
        assert!(
            n == buf.len(),
            "the truncation predicate must fire so drained sites drop it"
        );
    }

    /// Accounting helpers never panic on empty or oversized inputs.
    #[test]
    fn batch_report_handles_edge_inputs() {
        record_drain_batch(0);
        record_drain_batch(1);
        record_drain_batch(32);
        record_send_group(0, 0);
        record_send_group(17, 1);
        let r = batch_report();
        #[cfg(feature = "stats")]
        {
            assert!(r.contains("drain["), "report must carry drain hist: {r}");
            assert!(r.contains("send["), "report must carry send hist: {r}");
        }
        #[cfg(not(feature = "stats"))]
        {
            assert!(
                r.contains("compiled out"),
                "no-stats report must say so: {r}"
            );
        }
    }
}
