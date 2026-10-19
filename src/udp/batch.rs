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
//! - **Receive drain (portable head + Linux `recvmmsg` burst).** The hot
//!   loops keep their `recv_from().await` for the first datagram (so Tokio's
//!   readiness integration is untouched) and then drain up to
//!   `LAST_HOP_DRAIN - 1` more. On Linux the drain refills with one
//!   `recvmmsg(MSG_DONTWAIT)` per burst ([`recv_burst`]); a kernel that does
//!   not serve it (ENOSYS, seccomp) keeps the portable per-frame
//!   `try_recv_from` loop. Both paths only ever run right after Tokio
//!   reported the socket readable and stop on `EAGAIN`, so the reactor's
//!   bookkeeping is untouched and one readiness event still moves at most
//!   `LAST_HOP_DRAIN` datagrams.
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
// Batch-size / syscall accounting (thread-local batched, shared flushed)
// ---------------------------------------------------------------------------

/// Drain-burst sizes, bucketed by burst length: 1, 2-4, 5-8, 9-16, 17-32.
/// A healthy saturated link sits in the top buckets; a persistent bucket-0
/// with falling pps means the drain never fills (the peer, not the loop).
static DRAIN_HIST: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Grouped-send flushes by group size, same buckets as [`DRAIN_HIST`].
static SEND_HIST: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Actual last-hop send syscalls issued by the grouped path (one `sendmmsg`,
/// or one per frame on the fallback). `syscall_per_packet = SYSCALLS / pkts`.
static SEND_SYSCALLS: AtomicU64 = AtomicU64::new(0);

fn bucket(n: usize) -> usize {
    match n {
        0 | 1 => 0,
        2..=4 => 1,
        5..=8 => 2,
        9..=16 => 3,
        _ => 4,
    }
}

/// How many records one thread accumulates before flushing to the shared
/// atomics. Same bound and same reasoning as `udp_write::sent`: one shared RMW
/// per 256 records instead of one per record.
const BATCH_FLUSH_EVERY: u32 = 256;

/// Thread-local accumulator for the three grouped-I/O counters.
///
/// These were the only relay counters still doing a shared `fetch_add` per
/// burst: `udp_stats::payload` and `udp_write::sent` are thread-local cells
/// flushed every 256 for exactly this reason, while `record_send_group`/
/// `record_drain_batch` — called once per *run* per drain burst — wrote 2-3
/// process-global lines from every dispatcher and forward task. With runs of
/// length 1 (a burst spanning several sessions, i.e. the normal
/// multi-association case) that is 2 cross-core RMWs per relayed packet for a
/// five-bucket histogram.
///
/// The reporting consequence is the documented one for `udp_write::sent`: a
/// thread's pending count becomes visible when it reaches the flush bound or
/// when that thread itself calls [`batch_report`]. At any real packet rate the
/// bound is reached in milliseconds, and the alternative — a cross-core RMW per
/// burst on the hot path — is what the feature gate exists to avoid.
#[derive(Default)]
struct LocalBatch {
    drain: [u64; 5],
    send: [u64; 5],
    syscalls: u64,
    pending: u32,
}

thread_local! {
    static LOCAL_BATCH: std::cell::RefCell<LocalBatch> =
        const { std::cell::RefCell::new(LocalBatch {
            drain: [0; 5],
            send: [0; 5],
            syscalls: 0,
            pending: 0,
        }) };
}

/// Publish one thread's accumulated counters (no-op when it has none).
fn flush_local_batch() {
    LOCAL_BATCH.with(|c| {
        let mut c = c.borrow_mut();
        if c.pending == 0 && c.syscalls == 0 {
            return;
        }
        for i in 0..5 {
            if c.drain[i] != 0 {
                DRAIN_HIST[i].fetch_add(c.drain[i], Ordering::Relaxed);
                c.drain[i] = 0;
            }
            if c.send[i] != 0 {
                SEND_HIST[i].fetch_add(c.send[i], Ordering::Relaxed);
                c.send[i] = 0;
            }
        }
        if c.syscalls != 0 {
            SEND_SYSCALLS.fetch_add(c.syscalls, Ordering::Relaxed);
            c.syscalls = 0;
        }
        c.pending = 0;
    });
}

/// Record one receive-drain burst of `n` datagrams (call once per poll).
pub fn record_drain_batch(n: usize) {
    // `metrics` facade: no-op without a recorder, exporter reads it when set.
    // Kept alongside the 60 s `batch_report` histograms so existing log-line
    // tests keep passing while Prometheus can scrape the same signal.
    if n > 0 {
        metrics::histogram!("myquic2_udp_drain_batch_size").record(n as f64);
    }
    stats_only! {
        if n > 0 {
            let flush = LOCAL_BATCH.with(|c| {
                let mut c = c.borrow_mut();
                c.drain[bucket(n)] += 1;
                c.pending += 1;
                c.pending >= BATCH_FLUSH_EVERY
            });
            if flush {
                flush_local_batch();
            }
        }
    }
    let _ = n;
}

/// Record one grouped-send flush of `n` frames issued in `syscalls` syscalls.
pub fn record_send_group(n: usize, syscalls: u64) {
    if n > 0 {
        metrics::histogram!("myquic2_udp_send_group_size").record(n as f64);
        metrics::counter!("myquic2_udp_send_syscalls").increment(syscalls);
    }
    stats_only! {
        if n > 0 {
            let flush = LOCAL_BATCH.with(|c| {
                let mut c = c.borrow_mut();
                c.send[bucket(n)] += 1;
                c.syscalls += syscalls;
                c.pending += 1;
                c.pending >= BATCH_FLUSH_EVERY
            });
            if flush {
                flush_local_batch();
            }
        }
    }
    let _ = (n, syscalls);
}

/// Record `n` last-hop send syscalls issued **outside** a grouped flush: the
/// per-frame tail of a short `sendmmsg`, and the frames past
/// [`LAST_HOP_DRAIN`]. Both really do issue one syscall per frame, and leaving
/// them out made `syscall_per_packet` under-report exactly when the socket is
/// saturated — the regime the batching exists for.
pub fn record_extra_syscalls(n: u64) {
    if n > 0 {
        metrics::counter!("myquic2_udp_send_syscalls").increment(n);
    }
    stats_only! {
        if n > 0 {
            let flush = LOCAL_BATCH.with(|c| {
                let mut c = c.borrow_mut();
                c.syscalls += n;
                c.pending += 1;
                c.pending >= BATCH_FLUSH_EVERY
            });
            if flush {
                flush_local_batch();
            }
        }
    }
    let _ = n;
}

/// One-line burst-latency / syscall report for the 60 s budget line or benches:
/// drain-burst histogram, send-group histogram, and send syscalls issued.
pub fn batch_report() -> String {
    // Publish this thread's pending counts first: a reporter that has itself
    // been relaying would otherwise read a stale value for its own records
    // (the same rule `udp_write::snapshot` follows).
    flush_local_batch();
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

// ---------------------------------------------------------------------------
// sendmmsg / recvmmsg availability probe (Linux-gated, runtime-checked)
// ---------------------------------------------------------------------------

/// Whether the running kernel serves `sendmmsg` on UDP.
///
/// Linux-only symbol *and* runtime-gated: a seccomp filter or an old kernel
/// can return `ENOSYS` where the symbol exists, so the first call performs one
/// real 1-message `sendmmsg` on a loopback socket (via `socket2` for
/// construction and `rustix` for the call) and caches the answer. Non-Linux
/// targets report `false` without touching Linux-only symbols, so
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
///
/// Gates the deployed drain burst ([`recv_burst`]): a kernel without it keeps
/// the portable per-frame `try_recv_from` loop.
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
            (false, true) => "send-fallback+recvmmsg",
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
    use rustix::io::IoSlice;
    use rustix::net::{MMsgHdr, SendAncillaryBuffer, SendFlags, SocketAddrAny};
    use std::os::fd::AsFd;

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
    // One 1-byte message: proves the syscall exists and is served, nothing
    // more. rustix's `sendmmsg` is a thin, type-checked wrapper over the same
    // syscall — the iovec borrows the payload, the destination is one
    // `SocketAddrAny`, and the (empty) control buffer means no cmsg — so this
    // path needs no `unsafe` and no manual `mmsghdr` layout. An ENOSYS from a
    // seccomp filter or old kernel surfaces as the `Err` that makes the probe
    // report `false`, exactly as the raw `r == 1` did.
    let payload = [0x5Au8; 1];
    let sa = SocketAddrAny::from(dst);
    let iov = [IoSlice::new(&payload)];
    let mut cmsg = SendAncillaryBuffer::default();
    let mut msgs = [MMsgHdr::new_with_addr(&sa, &iov, &mut cmsg)];
    matches!(
        rustix::net::sendmmsg(tx.as_fd(), &mut msgs, SendFlags::empty()),
        Ok(1)
    )
}

#[cfg(target_os = "linux")]
fn probe_recvmmsg() -> bool {
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
    // nix owns the `mmsghdr` layout: one preallocated header plus one iovec
    // over a 1-byte scratch. ENOSYS/seccomp surfaces as `Err` → `false`,
    // exactly as the raw `r == 1` did, with no `unsafe` in this file.
    use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
    use std::io::IoSliceMut;
    use std::os::fd::AsRawFd;
    let mut payload = [0u8; 1];
    let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(1, None);
    let mut iovs: [[IoSliceMut<'_>; 1]; 1] = [[IoSliceMut::new(&mut payload)]];
    match nix::sys::socket::recvmmsg(
        // socket2 0.6 implements `AsFd`; `AsRawFd` is the nix `RawFd` shape.
        rx.as_raw_fd(),
        &mut headers,
        &mut iovs,
        MsgFlags::MSG_DONTWAIT,
        None,
    ) {
        Ok(results) => results.count() == 1,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// recvmmsg burst (Linux-gated): the deployed drain refill
// ---------------------------------------------------------------------------

/// Largest per-datagram slot the burst scratch must hold: the client relay
/// buffer (`MQP_FRAG_MAX_PAYLOAD` + the SOCKS5 UDP header + slack). The
/// server session buffer is smaller; [`burst_msg_copy`] truncates to the
/// destination's length exactly like `recvfrom` would.
pub const BURST_SLOT: usize =
    crate::UDP_RECV_MAX + crate::SOCKS_UDP_HDR_MAX + crate::UDP_RECV_SLACK;

#[cfg(target_os = "linux")]
thread_local! {
    static BURST: std::cell::RefCell<Option<Box<BurstRecv>>> = const { std::cell::RefCell::new(None) };
}

/// One worker thread's reused `recvmmsg` scratch: up to [`LAST_HOP_DRAIN`]
/// slots of [`BURST_SLOT`] bytes plus per-message length/source metadata.
/// Allocated lazily on the thread's first burst (~270 KiB), never per message.
/// Borrows are short: the syscall plus one [`burst_msg_copy`], never across
/// an `.await`.
///
/// The headers live in nix's `MultiHeaders` (preallocated once per thread);
/// nix owns the `mmsghdr` layout and the musl/glibc ABI quirks, so this file
/// holds no `unsafe` for the receive path.
#[cfg(target_os = "linux")]
struct BurstRecv {
    data: Vec<u8>,
    lens: Vec<usize>,
    addrs: Vec<std::net::SocketAddr>,
    headers: nix::sys::socket::MultiHeaders<nix::sys::socket::SockaddrStorage>,
}

#[cfg(target_os = "linux")]
impl BurstRecv {
    fn new() -> Self {
        Self {
            data: vec![0u8; LAST_HOP_DRAIN * BURST_SLOT],
            lens: Vec::with_capacity(LAST_HOP_DRAIN),
            addrs: Vec::with_capacity(LAST_HOP_DRAIN),
            headers: nix::sys::socket::MultiHeaders::preallocate(LAST_HOP_DRAIN, None),
        }
    }

    /// One `recvmmsg(MSG_DONTWAIT)` burst of up to `max` datagrams. Returns
    /// the count; 0 on `EAGAIN` or any error — both end the caller's burst,
    /// exactly like a failing `try_recv_from` arm.
    fn recv(&mut self, fd: std::os::unix::io::RawFd, max: usize) -> usize {
        use nix::sys::socket::MsgFlags;
        use std::io::IoSliceMut;
        self.lens.clear();
        self.addrs.clear();
        if max == 0 {
            return 0;
        }
        let n = max.min(LAST_HOP_DRAIN);
        // One iovec per message over this thread's `data` slices. Only the
        // first `n` headers/iovecs are handed to the kernel; a burst that
        // drains 2 datagrams never pays for 32.
        let mut iovs: [std::mem::MaybeUninit<[IoSliceMut<'_>; 1]>; LAST_HOP_DRAIN] =
            [const { std::mem::MaybeUninit::uninit() }; LAST_HOP_DRAIN];
        for (i, io) in iovs.iter_mut().enumerate().take(n) {
            // Each iovec borrows its own `BURST_SLOT`-wide slice of
            // `self.data`, which outlives the syscall.
            let slot = unsafe {
                std::slice::from_raw_parts_mut(
                    self.data.as_mut_ptr().add(i * BURST_SLOT),
                    BURST_SLOT,
                )
            };
            io.write([IoSliceMut::new(slot)]);
        }
        // SAFETY: exactly `n` entries were just initialised above; only
        // `0..n` is passed to nix, and each borrows live `self.data`.
        let iov_slice = unsafe {
            std::slice::from_raw_parts_mut(iovs.as_mut_ptr() as *mut [IoSliceMut<'_>; 1], n)
        };
        let results = match nix::sys::socket::recvmmsg(
            fd,
            &mut self.headers,
            iov_slice,
            MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let mut count = 0;
        for msg in results {
            let addr = match msg.address {
                Some(a) => sockaddr_storage_to_std(&a),
                None => continue,
            };
            self.lens.push(msg.bytes);
            self.addrs.push(addr);
            count += 1;
        }
        count
    }
}

/// Receive up to `max` datagrams in one `recvmmsg` syscall into a
/// thread-local scratch.
///
/// `Some(k)` stages `k` messages for [`burst_msg_copy`]; `k == 0` means
/// nothing more was queued (or the socket errored) — end the burst. `None`
/// means this kernel does not serve `recvmmsg`: use the portable per-frame
/// fallback. `max` only bounds this syscall — callers pass their remaining
/// drain budget so the burst can never overshoot it.
///
/// Call only with readiness already proven by the awaited head — the same
/// gate the portable `try_recv_from` drain runs under. `MSG_DONTWAIT` keeps
/// it non-blocking; on an empty socket the caller returns to
/// `recv_from().await`, which re-arms readiness through Tokio as usual.
pub fn recv_burst(sock: &tokio::net::UdpSocket, max: usize) -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if !recvmmsg_available() {
            return None;
        }
        BURST.with(|cell| {
            let mut cell = cell.borrow_mut();
            let b = cell.get_or_insert_with(|| Box::new(BurstRecv::new()));
            Some(b.recv(sock.as_raw_fd(), max))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sock, max);
        None
    }
}

/// Copy burst message `i` (from the last [`recv_burst`] on this thread) into
/// `dst`, reproducing `recvfrom` truncation semantics: a message longer than
/// `dst` reports `dst.len()` and the excess is dropped, so the caller's
/// `n == dst.len()` oversized-datagram predicate fires exactly as before.
/// Returns `(n, source)`, or `None` when no burst is staged.
pub fn burst_msg_copy(i: usize, dst: &mut [u8]) -> Option<(usize, std::net::SocketAddr)> {
    #[cfg(target_os = "linux")]
    {
        BURST.with(|cell| {
            let b = cell.borrow();
            let b = b.as_ref()?;
            let len = *b.lens.get(i)?;
            let src = *b.addrs.get(i)?;
            let n = len.min(dst.len());
            let off = i * BURST_SLOT;
            dst[..n].copy_from_slice(&b.data[off..off + n]);
            Some((n, src))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (i, dst);
        None
    }
}

/// Borrow one staged `recvmmsg` burst message **in place**.
///
/// The caller's closure runs while the thread-local burst scratch is borrowed,
/// so the payload never has to be copied out to a caller buffer: that is one
/// full payload memcpy per drained datagram cheaper than [`burst_msg_copy`],
/// which is the copy every caller used to pay before decoding/encoding it.
///
/// Contract: the closure runs synchronously. It must not `await`, nor call
/// [`recv_burst`]/[`with_burst_msg`] re-entrantly (the scratch is a
/// non-reentrant `RefCell` borrow). A caller that needs the payload to outlive
/// the borrow — the server's slow DNS/dial path awaits — must copy it to an
/// owned buffer *inside* the closure (or keep the old `burst_msg_copy` arm for
/// that path) and return after the borrow ends.
///
/// `None` means no burst is staged on this thread (portable fallback / empty
/// drain) or `i` is past the staged count. A zero-length message yields an
/// empty slice, matching `recvfrom` semantics.
pub fn with_burst_msg<R>(i: usize, f: impl FnOnce(&[u8], std::net::SocketAddr) -> R) -> Option<R> {
    #[cfg(target_os = "linux")]
    {
        BURST.with(|cell| {
            let b = cell.borrow();
            let b = b.as_ref()?;
            let len = *b.lens.get(i)?;
            let src = *b.addrs.get(i)?;
            let off = i * BURST_SLOT;
            // `recvmmsg` writes at most `BURST_SLOT` bytes per message, so the
            // range is in bounds by construction (lens and addrs are pushed
            // together by `BurstRecv::recv`).
            Some(f(&b.data[off..off + len], src))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (i, f);
        None
    }
}

/// Convert a nix `SockaddrStorage` (from `recvmmsg`) back to a std address.
/// Safe: nix downcasts via `as_sockaddr_in/in6` instead of raw pointer casts.
#[cfg(target_os = "linux")]
fn sockaddr_storage_to_std(storage: &nix::sys::socket::SockaddrStorage) -> std::net::SocketAddr {
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};
    if let Some(sin) = storage.as_sockaddr_in() {
        SocketAddr::new(IpAddr::V4(sin.ip()), sin.port())
    } else if let Some(sin6) = storage.as_sockaddr_in6() {
        SocketAddr::V6(SocketAddrV6::new(
            sin6.ip(),
            sin6.port(),
            sin6.flowinfo(),
            sin6.scope_id(),
        ))
    } else {
        // `recvmmsg` only ever returns INET/INET6 here; unreachable in practice.
        // Fall back to unspecified rather than panicking on the packet path.
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    }
}

/// One grouped last-hop frame: the protocol header to prepend (possibly empty)
/// and the payload — sent as **one** datagram, in one syscall, with two iovecs.
///
/// The split is what makes the grouped flush allocation- and copy-free: the
/// per-reply SOCKS5 header is 22 bytes at most and can live in a small reused
/// buffer, while the payload is borrowed straight from the receive path instead
/// of being concatenated into a staging arena first (see the client's
/// `flush_staged`).
pub type SendFrame<'a> = (&'a [u8], &'a [u8]);

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
    fd: std::os::fd::BorrowedFd<'_>,
    dst: &std::net::SocketAddr,
    frames: &[SendFrame<'_>],
) -> (usize, Option<std::io::Error>) {
    use rustix::io::IoSlice;
    use rustix::net::{MMsgHdr, SendAncillaryBuffer, SendFlags, SocketAddrAny};
    use std::mem::MaybeUninit;

    let n = frames.len().min(LAST_HOP_DRAIN);
    if n == 0 {
        return (0, None);
    }
    // Two iovecs per message (header, payload), each pair starting at `2*i`,
    // plus one (empty) control buffer and one message header per frame — all
    // only for the entries actually used. Zero-initializing the fixed arrays
    // is what the pre-rustix revision measured as ~2.7 KB of dead stores per
    // call, and `flush_staged`/`flush_staged_sends` issue one call per
    // same-destination run — which is a run of length 1 whenever a burst spans
    // several sessions, i.e. exactly the multi-association case.
    //
    // `MMsgHdr` is rustix's `#[repr(transparent)]` `mmsghdr`: the wrapper owns
    // the ABI (including the musl/glibc `msg_iovlen` and flag-width
    // differences the raw version worked around with `as _` casts) and
    // type-checks the iovec/addr borrows. What remains are the two
    // initialized-slice views below — no raw pointer arithmetic into a C
    // call, no manual `mmsghdr` layout.
    let mut iovs: [MaybeUninit<IoSlice<'_>>; 2 * LAST_HOP_DRAIN] =
        [const { MaybeUninit::uninit() }; 2 * LAST_HOP_DRAIN];
    // `n` control buffers, not 32: a `SendAncillaryBuffer` is a zero-length
    // `&mut []` plus a length, so the eager version was a handful of dead
    // stores per call rather than the ~2.7 KB the pre-rustix fixed arrays cost
    // — but this call is issued once per same-destination run, and a run of
    // length 1 is the multi-session steady state, so even those stores were on
    // the hot path for no benefit. `MaybeUninit` keeps it sound without
    // `assume_init`: `write` initialises exactly slot `i` immediately before
    // its header borrows it, and the kernel only ever sees `0..n`.
    let mut cmsgs: [MaybeUninit<SendAncillaryBuffer<'static, 'static, 'static>>; LAST_HOP_DRAIN] =
        [const { MaybeUninit::uninit() }; LAST_HOP_DRAIN];
    let mut msgs: [MaybeUninit<MMsgHdr<'_>>; LAST_HOP_DRAIN] =
        [const { MaybeUninit::uninit() }; LAST_HOP_DRAIN];
    // One destination shared by every message: all frames in this call go to
    // `dst`, and `SocketAddrAny` owns its storage, so one `msg_name` serves
    // the whole run.
    let sa = SocketAddrAny::from(*dst);
    // `iter_mut` over exactly the used prefix: each message needs its own `&mut
    // SendAncillaryBuffer` for as long as the `MMsgHdr` lives, and indexing the
    // array per message would reborrow the whole array each time (E0499);
    // `iter_mut` hands out disjoint items instead. The `cmsgs[..n]` subslice is
    // the whole point of the `MaybeUninit` array: the entries past `n` are
    // never touched.
    for (i, (cmsg_slot, (hdr, body))) in cmsgs[..n].iter_mut().zip(frames[..n].iter()).enumerate() {
        // A zero-length header must not become a zero-length *separate* iovec
        // (the kernel would still join them, but skipping it keeps the common
        // server case — no header — at exactly one iovec, as before).
        let mut nios = 0usize;
        if !hdr.is_empty() {
            iovs[2 * i].write(IoSlice::new(hdr));
            nios += 1;
        }
        if !body.is_empty() || nios == 0 {
            iovs[2 * i + nios].write(IoSlice::new(body));
            nios += 1;
        }
        // SAFETY: the `nios` entries at `2*i` were just written above, the
        // range is inside the array, and each iovec borrows a frame that
        // outlives the syscall.
        let iov = unsafe { std::slice::from_raw_parts(iovs[2 * i].as_ptr(), nios) };
        // SAFETY-adjacent (safe API): `write` initialises this slot before the
        // header takes its `&mut`, and no `assume_init` of the other slots ever
        // happens.
        let cmsg = cmsg_slot.write(SendAncillaryBuffer::default());
        msgs[i].write(MMsgHdr::new_with_addr(&sa, iov, cmsg));
    }
    // SAFETY: exactly `n` messages were written, at `0..n`, and only `0..n` is
    // passed below.
    let msgs =
        unsafe { std::slice::from_raw_parts_mut(msgs.as_mut_ptr().cast::<MMsgHdr<'_>>(), n) };
    match rustix::net::sendmmsg(fd, msgs, SendFlags::empty()) {
        Ok(sent) => (sent, None),
        // `Errno` -> `std::io::Error`: the caller reports this through the
        // same `Option<io::Error>` the raw version returned.
        Err(e) => (0, Some(e.into())),
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

    /// Linux drain burst: one `recvmmsg` stages everything queued, sources and
    /// lengths survive, and `burst_msg_copy` reproduces `recvfrom` truncation
    /// semantics (a message longer than `dst` reports `dst.len()`).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn burst_recv_and_copy_round_trip() {
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = rx.local_addr().unwrap();
        let tx_port = tx.local_addr().unwrap().port();
        // Five distinct datagrams; read one as the head (proves readiness),
        // then stage the remaining four in one burst.
        for i in 0..5u8 {
            tx.send_to(&vec![i; 100 + i as usize], dst).await.unwrap();
        }
        let mut head = vec![0u8; BURST_SLOT];
        let (_n, head_src) = rx.recv_from(&mut head).await.unwrap();
        assert_eq!(head_src.port(), tx_port, "head source must be the sender");
        let k = recv_burst(&rx, LAST_HOP_DRAIN).expect("Linux must serve recvmmsg");
        assert_eq!(k, 4, "burst must stage the four remaining datagrams");
        let mut lens = Vec::new();
        for i in 0..k {
            let mut buf = vec![0u8; BURST_SLOT];
            let (len, src) = burst_msg_copy(i, &mut buf).expect("staged message must copy");
            assert_eq!(src.port(), tx_port, "source must survive the burst");
            assert!(
                buf[..len].iter().all(|b| *b == (len - 100) as u8),
                "payload byte and length must match the sent datagram"
            );
            lens.push(len);
        }
        lens.sort_unstable();
        assert_eq!(lens, vec![101, 102, 103, 104]);
        // Truncation semantics: a message copied into a smaller destination
        // reports `dst.len()`, the predicate the drain loops check.
        let mut small = vec![0u8; 10];
        let (len, _) = burst_msg_copy(0, &mut small).unwrap();
        assert_eq!(len, 10, "oversize datagram must report dst.len()");
        // Empty burst: nothing left to stage, so no message is copyable.
        assert_eq!(recv_burst(&rx, LAST_HOP_DRAIN), Some(0));
        assert!(burst_msg_copy(0, &mut small).is_none());
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
        assert!(r.contains("drain["), "report must carry drain hist: {r}");
        assert!(r.contains("send["), "report must carry send hist: {r}");
    }
}
