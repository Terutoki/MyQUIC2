//! UDP `WouldBlock` 分片重试池：逐行搬运自 `src/lib.rs`（零改动抽取，`lib.rs` 未碰）。
//!
//! 搬运区间（以符号为准）：
//! - `UdpRetry`：lib.rs:1719-1731
//! - `UDP_RETRY_SHARDS`/`UDP_RETRY_DEPTH`：lib.rs:1733-1734
//! - `RetryShard`：lib.rs:1736-1749
//! - `retry_shards`：lib.rs:1751-1758
//! - `UDP_RETRY_TIMEOUT`：lib.rs:1760-1774
//! - `under_retry_deadline`：lib.rs:1776-1786
//! - `retry_one`：lib.rs:1788-1796
//! - `UDP_RETRY_INFLIGHT`：lib.rs:1798-1806
//! - `spawn_retry_worker`：lib.rs:1808-1839
//! - `udp_retry_submit`：lib.rs:1841-1858
//! - `retry_shard_for`：lib.rs:1860-1879
//! - `udp_try_send`：lib.rs:1881-1920
//! - `udp_try_send_slice`：lib.rs:1922-1958
//! - `UdpWriteDrop`：lib.rs:1960-1978
//! - `warn_udp_write`：lib.rs:1980-1996
//! - 止于 lib.rs:1998（`udp_socket_dual` 起为 socket 构造，非重试池，不搬）
//!
//! 接线：`stats`（`udp_write::*`、`claim_drop_warning`、`NEVER_WARNED`）
//! 经 `crate::stats` 绝对路径引用；`warn_udp_write`/`UdpWriteDrop` 为本文件内定义。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::stats::{NEVER_WARNED, claim_drop_warning};
use crate::udp_write;

use super::batch::SendFrame;

/// One queued retry: the socket it must go out on, the destination and the
/// bytes.
///
/// `sock` is deliberately strong — the queue has to be able to write after the
/// caller returns — but that also makes this entry the socket's *last* owner once
/// the association (client relay) or session (server session socket) has dropped
/// its own handle. The retention is therefore bounded by
/// [`UDP_RETRY_TIMEOUT`], not by luck: see the note on the retry worker.
pub(crate) struct UdpRetry {
    pub(crate) sock: Arc<tokio::net::UdpSocket>,
    pub(crate) dst: SocketAddr,
    pub(crate) payload: Bytes,
}

pub(crate) const UDP_RETRY_SHARDS: usize = 16;
pub(crate) const UDP_RETRY_DEPTH: usize = 256;

/// One shard's retry worker, published so it can be replaced.
///
/// The worker is a task on whatever runtime first needed the shard. That is the
/// process runtime in the shipped binaries -- but a test binary runs one
/// runtime per `#[tokio::test]` and an embedder may run several, and a task
/// dies with its runtime. The old shape kept the `Sender` in a `OnceLock`
/// forever, so after the first runtime ended every later `try_send` went into a
/// queue whose receiver was gone: the datagram was dropped and the caller
/// counted it under a resource budget it had not exceeded. The sender is behind
/// an `ArcSwap` instead, and `udp_retry_submit` re-arms the shard on the
/// runtime it is called from whenever it finds the worker gone.
pub(crate) struct RetryShard {
    tx: arc_swap::ArcSwap<tokio::sync::mpsc::Sender<UdpRetry>>,
}

pub(crate) fn retry_shards() -> &'static [RetryShard; UDP_RETRY_SHARDS] {
    static TX: std::sync::OnceLock<[RetryShard; UDP_RETRY_SHARDS]> = std::sync::OnceLock::new();
    TX.get_or_init(|| {
        std::array::from_fn(|_| RetryShard {
            tx: arc_swap::ArcSwap::from_pointee(spawn_retry_worker()),
        })
    })
}

/// Deadline on one detached retry.
///
/// A retry holds a **strong** `Arc<UdpSocket>` (see [`UdpRetry::sock`]) after the
/// association or session that owned the socket has already dropped its own
/// handle, so this queue is the socket's last owner for as long as the entry
/// lives. `send_to(...).await` parks until the socket is writable, and a
/// destination that never becomes writable — a peer that stopped reading, a full
/// qdisc, a black-holed route — parks it forever. That pinned the fd (and the
/// session's 2 x 32 KiB kernel buffers on the server) for the process lifetime
/// *and* wedged the whole shard: a worker parked in `send_to` retries nothing
/// else, so every later datagram hashing to that shard was silently dropped.
/// 200 ms is far above the loopback/LAN drain this path exists for and far below
/// any user-visible retry interval; the datagram is best-effort UDP either way,
/// and now the fd and the shard are released on a bounded schedule.
pub(crate) const UDP_RETRY_TIMEOUT: Duration = Duration::from_millis(200);

/// Await one send under [`UDP_RETRY_TIMEOUT`].
///
/// Generic over the future on purpose: it is the deadline itself that has to be
/// provable, and no portable socket stays unwritable on every platform, so
/// `retry_deadline_bounds_a_never_writable_socket` drives it with a future that
/// is never ready.
pub(crate) async fn under_retry_deadline<F: std::future::Future>(fut: F) -> Result<F::Output, ()> {
    tokio::time::timeout(UDP_RETRY_TIMEOUT, fut)
        .await
        .map_err(|_| ())
}

/// Send one queued retry under the retry deadline. Returns the reason on
/// failure, so the worker's only job is counting and logging.
async fn retry_one(req: &UdpRetry) -> Result<(), String> {
    match under_retry_deadline(req.sock.send_to(&req.payload, req.dst)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(()) => Err(format!("socket not writable within {UDP_RETRY_TIMEOUT:?}")),
    }
}

/// How many retries one shard runs concurrently.
///
/// A single sequential worker made one wedged destination delay every later
/// retry in the same shard — up to `UDP_RETRY_DEPTH` x [`UDP_RETRY_TIMEOUT`]
/// ≈ 51 s of head-of-line blocking, during which the shard also refused every
/// *new* retry, including ones for destinations that were perfectly writable.
/// Sixteen in flight bound the cost of one slow destination to one slot while
/// still bounding the tasks, sockets and payloads a shard can hold.
pub(crate) const UDP_RETRY_INFLIGHT: usize = 16;

pub(crate) fn spawn_retry_worker() -> tokio::sync::mpsc::Sender<UdpRetry> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpRetry>(UDP_RETRY_DEPTH);
    tokio::spawn(async move {
        let mut inflight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                // Reap finished sends first, so a continuously busy queue can
                // never grow the in-flight set past the bound.
                Some(_) = inflight.join_next(), if !inflight.is_empty() => {}
                maybe = rx.recv() => {
                    let Some(req) = maybe else { break };
                    while inflight.len() >= UDP_RETRY_INFLIGHT {
                        inflight.join_next().await;
                    }
                    inflight.spawn(async move {
                        // `req` is dropped here whatever the outcome, which is
                        // what releases the last strong `Arc<UdpSocket>`.
                        if let Err(reason) = retry_one(&req).await {
                            let n = udp_write::retry_failed();
                            warn_udp_write(UdpWriteDrop::RetryFailed, n, || reason);
                        }
                    });
                }
            }
        }
        // Channel closed: the shard is being re-armed or its runtime is ending.
        // The JoinSet drop aborts any send still in flight, so no retry (and no
        // socket it holds) outlives its worker.
    });
    tx
}

/// Queue a datagram for a detached retry on the shard that owns `dst`.
///
/// Returns false when the shard is full (UDP semantics: drop). A shard whose
/// worker died with its runtime is re-armed here, so a retry never disappears
/// just because the queue outlived the task that was draining it.
pub(crate) fn udp_retry_submit(dst: &SocketAddr, req: UdpRetry) -> bool {
    let shard = retry_shard_for(dst);
    let cur = shard.tx.load_full();
    let tx = if cur.is_closed() {
        let fresh = std::sync::Arc::new(spawn_retry_worker());
        // One winner publishes; every caller then uses whichever sender won.
        shard.tx.compare_and_swap(&cur, fresh);
        shard.tx.load_full()
    } else {
        cur
    };
    tx.try_send(req).is_ok()
}

fn retry_shard_for(dst: &SocketAddr) -> &'static RetryShard {
    // Shard by ip+port: port-only sharding collapses DNS(:53) / HTTPS(:443)
    // heavy workloads into a single shard, reintroducing the HOL blocking
    // the sharded pool was created to remove. Manual fold (no SipHash) keeps
    // this at a few integer ops on the WouldBlock-only path.
    const K: usize = 0x9e3779b97f4a7c15;
    let h = match *dst {
        SocketAddr::V4(a) => (u32::from_ne_bytes(a.ip().octets()) as usize)
            .wrapping_mul(K)
            .wrapping_add(a.port() as usize),
        SocketAddr::V6(a) => {
            let mut h = a.port() as usize;
            for w in a.ip().segments() {
                h = h.wrapping_mul(K).wrapping_add(w as usize);
            }
            h
        }
    };
    &retry_shards()[h % UDP_RETRY_SHARDS]
}

/// Best-effort non-blocking UDP send for shared loops (one datagram reader per
/// connection, one relay per association).
///
/// `try_send_to` alone is not enough: tokio returns `WouldBlock` without even
/// attempting the syscall while a freshly registered socket has no cached
/// writable readiness, which would silently drop the first packet of every new
/// session. A genuinely full socket buffer is real backpressure too. In both
/// cases the packet is queued to a sharded global retry pool (one worker per
/// shard, selected by destination ip+port) so the caller never stalls, no task is
/// spawned per packet, and one slow destination cannot head-of-line-block every
/// other session behind a single queue; a full shard drops (UDP semantics).
pub fn udp_try_send(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: Bytes) {
    match sock.try_send_to(&payload, dst) {
        Ok(_) => udp_write::sent(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let req = UdpRetry {
                sock: sock.clone(),
                dst,
                payload,
            };
            // Counted *after* the queue accepts it. `retried` means "handed to a
            // detached task", and the old order counted the hand-off before
            // knowing whether it happened, so a datagram dropped on a full shard
            // was booked as both retried and dropped — one datagram, two mutually
            // exclusive outcomes.
            if udp_retry_submit(&dst, req) {
                udp_write::retried();
            } else {
                let n = udp_write::dropped_no_permit();
                warn_udp_write(UdpWriteDrop::Budget, n, || {
                    format!("retry shard queue full ({UDP_RETRY_DEPTH} deep)")
                });
            }
        }
        Err(e) => {
            let n = udp_write::failed();
            warn_udp_write(UdpWriteDrop::SendFailed, n, || e.to_string());
        }
    }
}

/// Borrowed fast path for replies built into a reused scratch buffer.
///
/// `udp_try_send` needs an owned `Bytes` because the WouldBlock retry queue
/// owns the payload, which forced the reply path to `freeze()` its scratch
/// buffer (one allocation) on every datagram. The fast path only borrows the
/// slice for the syscall; only WouldBlock copies into an owned `Bytes` for
/// the queue, so steady-state replies allocate nothing and the scratch buffer
/// is reused across packets.
pub fn udp_try_send_slice(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: &[u8]) {
    match sock.try_send_to(payload, dst) {
        Ok(_) => udp_write::sent(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // The copy is paid before the queue decision; it only happens on
            // `WouldBlock`, which is already the exceptional path, and buying it
            // back would mean a capacity pre-check whose answer `try_send` can
            // invalidate anyway.
            let req = UdpRetry {
                sock: sock.clone(),
                dst,
                payload: Bytes::copy_from_slice(payload),
            };
            // See `udp_try_send`: counted only once the queue owns it.
            if udp_retry_submit(&dst, req) {
                udp_write::retried();
            } else {
                let n = udp_write::dropped_no_permit();
                warn_udp_write(UdpWriteDrop::Budget, n, || {
                    format!("retry shard queue full ({UDP_RETRY_DEPTH} deep)")
                });
            }
        }
        Err(e) => {
            let n = udp_write::failed();
            warn_udp_write(UdpWriteDrop::SendFailed, n, || e.to_string());
        }
    }
}

/// Batch-send already-encoded frames for one destination.
///
/// Up to [`LAST_HOP_DRAIN`](super::batch::LAST_HOP_DRAIN) frames share a single
/// `sendmmsg` syscall on Linux; everywhere else (macOS, `ENOSYS` kernels) this
/// is one `try_send_to` per frame. A one-frame group keeps header and payload
/// apart without entering the *batch* histogram path (see the n == 1 note
/// below). Either way each frame keeps exactly-once accounting: delivered
/// frames count `sent`, and every unsent frame rejoins the per-frame
/// [`udp_try_send_slice`] path below, so `WouldBlock` still queues into the
/// detached-retry pool (with the owned copy paid only there), a full shard
/// still drops under `dropped_no_permit` + one `Budget` warning, and hard
/// errors still count `failed`. Never blocks, never spawns: an `EAGAIN` or
/// short send stops the fast path at the first unsent frame.
///
/// Each frame is a [`SendFrame`] — `(header, payload)`, sent as one datagram.
/// On Linux the two are separate iovecs of one message, so a protocol header in
/// front of a payload costs no copy at all; the portable fallback has no
/// vectored datagram send, so it concatenates into a reused thread-local buffer
/// (per frame, only when there *is* a header — the same one copy the caller used
/// to pay for every frame unconditionally).
///
/// Callers stage consecutive same-destination replies of one drain burst here
/// (client dispatcher, server accept-target sends); batching therefore changes
/// the syscall count, never the per-datagram outcome. Note the grouping key
/// includes the *socket*, and a last-hop socket belongs to one session, so a
/// burst spanning several sessions is legitimately one run per frame — the
/// batching pays off for the single hot flow, and cannot be widened further
/// without merging sessions onto one socket.
///
/// A **one-frame group is not a batch**: it never records a size-1
/// `send_group` observation (there is no syscall to amortize within the group
/// histogram) and it books its own syscall through `record_extra_syscalls`.
/// What it does *not* do any more is concatenate a header into the payload:
/// on Linux a header-carrying frame (a client reply) goes out through the
/// same one-message `sendmmsg` the grouped path uses — header and payload stay
/// two iovecs, so the payload is never copied into GROUP_SCRATCH. Only the
/// empty-header fast path (server target sends) and non-Linux take the
/// per-frame send directly; a failed one-message `sendmmsg` falls back to the
/// per-frame path so `WouldBlock` still reaches the detached-retry pool.
pub fn udp_try_send_grouped(
    sock: &Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    frames: &[SendFrame<'_>],
) {
    use super::batch::{
        LAST_HOP_DRAIN, record_extra_syscalls, record_send_group, sendmmsg_available,
    };
    if frames.is_empty() {
        return;
    }
    // A one-frame run is the common per-run shape (a drain burst spanning
    // several sockets/sessions stages one frame per run), so it must not pay
    // the batch histogram or a payload copy. See the note above.
    if frames.len() == 1 {
        #[cfg(target_os = "linux")]
        {
            // Header + payload as two iovecs of one one-message `sendmmsg`.
            // `sendmmsg_frames` initialises only the 0..n slots (MaybeUninit),
            // so a size-1 call is one `mmsghdr` and one syscall — the scratch
            // cost that used to justify the per-frame bypass is gone.
            if !frames[0].0.is_empty() && sendmmsg_available() {
                use std::os::fd::AsFd;
                let (sent, _) = super::batch::sendmmsg_frames(sock.as_fd(), &dst, &frames[..1]);
                if sent == 1 {
                    // No size-1 `send_group` observation: one syscall for one
                    // frame amortizes nothing, and the histogram's job is to
                    // show whether grouping earns its keep.
                    udp_write::sent();
                    record_extra_syscalls(1);
                    return;
                }
                // The one-message syscall ran and did not put the frame on the
                // wire (EAGAIN under backpressure, or a hard error). Book it,
                // then hand the frame to the per-frame path so a `WouldBlock`
                // still takes the detached-retry route; that path's own
                // syscall is booked too.
                record_extra_syscalls(2);
                udp_try_send_frame(sock, dst, frames[0]);
                return;
            }
        }
        udp_try_send_frame(sock, dst, frames[0]);
        record_extra_syscalls(1);
        return;
    }
    let n = frames.len().min(LAST_HOP_DRAIN);
    #[cfg(target_os = "linux")]
    {
        if sendmmsg_available() {
            use std::os::fd::AsFd;
            let (sent, _) = super::batch::sendmmsg_frames(sock.as_fd(), &dst, &frames[..n]);
            // Book the group only when the syscall actually put frames on the
            // wire. A full send buffer (EAGAIN, the very saturation regime this
            // batching exists for) returns 0 sent, and recording that as a
            // "1-syscall group of n" both invented a send-group histogram
            // observation out of a failed syscall and let
            // `syscall_per_packet` under-report by one every saturated burst.
            if sent > 0 {
                record_send_group(sent, 1);
                for _ in &frames[..sent] {
                    udp_write::sent();
                }
            } else {
                // The syscall did run and did cost us; count it as a syscall
                // only, with no group observation.
                record_extra_syscalls(1);
            }
            // Remainder (short send or EAGAIN) rejoins the per-frame path so
            // each keeps its own WouldBlock -> retry treatment, and its own
            // syscall is accounted so `syscall_per_packet` stays honest when the
            // socket is saturated — the very regime the batching exists for.
            for f in &frames[sent..n] {
                udp_try_send_frame(sock, dst, *f);
            }
            record_extra_syscalls((n - sent) as u64);
            // Frames past the bound belong to the next burst, not this one:
            // sending them here would grow the syscall's iovec unbounded.
            for f in &frames[n..] {
                udp_try_send_frame(sock, dst, *f);
            }
            record_extra_syscalls((frames.len() - n) as u64);
            return;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = sendmmsg_available;
    record_send_group(n, n as u64);
    for f in &frames[..n] {
        udp_try_send_frame(sock, dst, *f);
    }
    for f in &frames[n..] {
        udp_try_send_frame(sock, dst, *f);
    }
    // Same accounting as the Linux arm: the frames past the drain bound really
    // do issue one syscall each, so `syscall_per_packet` must see them.
    record_extra_syscalls((frames.len() - n) as u64);
}

/// Send one [`SendFrame`] through the per-frame path.
///
/// An empty header takes the borrowed slice send and costs no copy anywhere.
/// A header frame only reaches the concatenation below when no vectored send is
/// available: the portable fallback, a Linux kernel whose `sendmmsg` probe
/// failed, the tail of a short `sendmmsg`, or a failed one-message `sendmmsg`
/// (the n == 1 header case normally goes through `sendmmsg_frames` with two
/// iovecs, so this is the exception, not the client reply path).
fn udp_try_send_frame(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, frame: SendFrame<'_>) {
    let (hdr, body) = frame;
    if hdr.is_empty() {
        udp_try_send_slice(sock, dst, body);
        return;
    }
    // Reused per thread, cleared per frame, never held across an await: only the
    // frames that actually carry a header touch it (the server's target sends
    // pass an empty header and stay copy-free everywhere).
    GROUP_SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        s.clear();
        s.reserve(hdr.len() + body.len());
        s.extend_from_slice(hdr);
        s.extend_from_slice(body);
        udp_try_send_slice(sock, dst, &s);
    });
}

thread_local! {
    /// Portable-fallback assembly buffer for [`udp_try_send_grouped`].
    static GROUP_SCRATCH: std::cell::RefCell<Vec<u8>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Which last-hop write fault a warning is about.
///
/// An enum rather than the substring-matched reason string this used to take,
/// for the same reason [`dgram_drops::EgressDrop`] is one: the substring version
/// tested `reason.contains("budget") || reason.contains("retry")` *first*, so
/// `"detached retry failed"` — the one message that describes a **send** failure
/// — matched "retry" and shared a 10 s window with queue exhaustion, silently
/// merging two different faults. Each variant now carries its own slot and its
/// own text, so neither can starve the other's first line and a rename cannot
/// re-merge them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpWriteDrop {
    /// `WouldBlock` and the detached-retry queue was full: no retry was queued.
    Budget,
    /// A direct (non-queued) last-hop send failed.
    SendFailed,
    /// A queued retry ran and its send failed, or it hit the retry deadline.
    RetryFailed,
}

/// Rate-limited warning for a last-hop UDP write failure.
fn warn_udp_write(kind: UdpWriteDrop, total: u64, detail: impl FnOnce() -> String) {
    use std::sync::atomic::AtomicU64;
    static LAST_FAIL: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_NOPERM: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_RETRY_FAIL: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let (slot, reason) = match kind {
        UdpWriteDrop::Budget => (&LAST_NOPERM, "retry budget exhausted"),
        UdpWriteDrop::SendFailed => (&LAST_FAIL, "send failed"),
        UdpWriteDrop::RetryFailed => (&LAST_RETRY_FAIL, "detached retry failed"),
    };
    if !claim_drop_warning(slot) {
        return;
    }
    let detail = detail();
    tracing::warn!("udp write dropped ({reason}): {total} so far; {detail}");
}

/// P1-3 contract lock for the relay `try_send` path (`udp_try_send` /
/// `udp_try_send_slice`).
///
/// Locked semantics (see the item docs above):
/// - `Ok` → `sent` (both variants; the slice variant borrows on this path).
/// - `WouldBlock` → detached retry queue; the slice variant copies into an
///   owned `Bytes` **only** on this path; a full shard (depth 256) drops under
///   `dropped_no_permit` + one `Budget` warning (newest-drop UDP semantics).
/// - any other error → `failed`.
/// - one detached retry runs under the 200 ms deadline; at most 16 in flight
///   per shard; shards are selected by destination ip+port; a shard whose
///   worker died with its runtime is re-armed via `ArcSwap`.
/// - `udp_try_send_grouped` shares one `sendmmsg` per same-destination burst
///   (Linux only; portable one-`try_send_to`-per-frame fallback elsewhere,
///   bounded by `LAST_HOP_DRAIN` = 32). Per-frame outcomes are identical to
///   the slice variant above; a short send or `EAGAIN` rejoins the per-frame
///   path, so batching changes the syscall count, never the outcome. A
///   one-frame group takes the per-frame path directly: one syscall booked
///   through `record_extra_syscalls`, no `send_group` histogram observation.
///
/// NOTE (last-hop batching, production): grouped sends are on the hot path
/// for same-destination reply bursts. Still no `UDP_SEGMENT` options
/// (quinn-udp owns GSO), no blocking `send_to().await` on the hot path, no
/// per-packet spawn.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::time::Instant;

    /// Serialises the counter-sensitive tests below. The `udp_write` totals
    /// are process-wide atomics (`sent` is thread-local batched and flushed
    /// by `snapshot` on the calling thread), so two tests taking
    /// before/after deltas concurrently could each observe the other's bump.
    /// No test outside this module touches these counters; holding this lock
    /// over the synchronous snapshot→send→snapshot section makes every delta
    /// exact. The lock is never held across an `.await`.
    static CONTRACT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn constants_lock_200ms_16_256() {
        assert_eq!(
            UDP_RETRY_TIMEOUT,
            Duration::from_millis(200),
            "retry deadline is a retention bound, not a retry policy"
        );
        assert_eq!(
            UDP_RETRY_INFLIGHT, 16,
            "in-flight bound per shard must stay 16"
        );
        assert_eq!(UDP_RETRY_DEPTH, 256, "shard depth must stay 256");
        assert_eq!(
            UDP_RETRY_SHARDS, 16,
            "shard count must stay 16 (inflight<=16/shard)"
        );
    }

    /// First send on a socket books exactly one outcome and delivers.
    ///
    /// A freshly registered socket may report `WouldBlock` without the
    /// syscall ever running (no cached writable readiness), so the first
    /// send can legally land on either `sent` or `retried`; what is locked
    /// is that it lands on exactly one of them — never both, never dropped,
    /// never failed — and the datagram arrives (directly or via the detached
    /// retry worker).
    #[tokio::test]
    async fn ok_path_counts_sent_and_delivers() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // Prime writable readiness: a fresh socket may report `WouldBlock`
        // before its first readiness edge, so drive one async send first and
        // drain it. The measured send below then takes the `Ok` arm.
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 32];
        let (pn, _) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();
        assert_eq!(&b[..pn], b"prime");
        let d = {
            let _guard = CONTRACT_LOCK.lock().unwrap();
            let before = udp_write::snapshot();
            udp_try_send(&sock, dst, Bytes::from_static(b"p1-3-ok"));
            udp_write::snapshot().since(&before)
        };
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("primed send must arrive directly")
            .unwrap();
        assert_eq!(&b[..n], b"p1-3-ok");
        assert_eq!(d.sent, 1, "primed Ok must count exactly one sent: {d:?}");
        assert_eq!(d.retried, 0, "primed Ok must not book a retry: {d:?}");
        assert_eq!(
            d.dropped_no_permit, 0,
            "a live loopback send must not drop: {d:?}"
        );
        assert_eq!(d.failed, 0, "a live loopback send must not fail: {d:?}");
    }

    /// Borrowed fast path delivers the same bytes with the same exactly-once
    /// booking; the owned `Bytes` copy is paid only on `WouldBlock`.
    #[tokio::test]
    async fn slice_ok_path_borrows_and_delivers() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // Prime readiness as above so the measured slice send takes `Ok`.
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 32];
        tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();
        let payload = [0x5Au8; 24];
        let d = {
            let _guard = CONTRACT_LOCK.lock().unwrap();
            let before = udp_write::snapshot();
            udp_try_send_slice(&sock, dst, &payload);
            udp_write::snapshot().since(&before)
        };
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("primed slice send must arrive directly")
            .unwrap();
        assert_eq!(&b[..n], &payload[..]);
        assert_eq!(
            d.sent, 1,
            "primed slice Ok must count exactly one sent: {d:?}"
        );
        assert_eq!(d.retried, 0, "primed slice Ok must not book a retry: {d:?}");
        assert_eq!(
            d.dropped_no_permit, 0,
            "a live loopback send must not drop: {d:?}"
        );
    }

    /// `WouldBlock` submit vs. full-shard drop are mutually exclusive outcomes:
    /// one datagram books exactly one of `retried` / `dropped_no_permit`,
    /// never both (no double-count).
    ///
    /// The full shard is modelled with an isolated `mpsc` channel at exactly
    /// `UDP_RETRY_DEPTH`: the production queue is drained by a detached worker,
    /// so filling the shared global shard deterministically would be racy and
    /// would steal budget from parallel tests. What is under lock here is the
    /// contract the production branch implements: `try_send` accepted →
    /// `retried`, `try_send` refused → `dropped_no_permit` (Budget, warn once).
    #[test]
    fn wouldblock_submit_vs_full_shard_drop_exactly_once() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let (tx, rx) = tokio::sync::mpsc::channel::<UdpRetry>(UDP_RETRY_DEPTH);
            std::mem::forget(rx);
            for _ in 0..UDP_RETRY_DEPTH {
                tx.try_send(UdpRetry {
                    sock: sock.clone(),
                    dst,
                    payload: Bytes::from_static(b"x"),
                })
                .expect("shard depth 256 must accept 256 queued retries");
            }
            assert!(
                tx.try_send(UdpRetry {
                    sock: sock.clone(),
                    dst,
                    payload: Bytes::from_static(b"x"),
                })
                .is_err(),
                "a full 256-deep shard must refuse the newest datagram"
            );
        });

        // Exactly-once booking: each outcome bumps exactly its own counter.
        let _guard = CONTRACT_LOCK.lock().unwrap();
        let before = udp_write::snapshot();
        udp_write::retried();
        let d = udp_write::snapshot().since(&before);
        assert_eq!(d.retried, 1, "submit must book exactly one retried: {d:?}");
        assert_eq!(
            d.dropped_no_permit, 0,
            "submit must not also book a drop: {d:?}"
        );
        let before = udp_write::snapshot();
        udp_write::dropped_no_permit();
        let d = udp_write::snapshot().since(&before);
        assert_eq!(
            d.dropped_no_permit, 1,
            "full shard must book exactly one drop: {d:?}"
        );
        assert_eq!(d.retried, 0, "drop must not also book a retry: {d:?}");
    }

    /// Grouped same-destination send delivers every frame with exactly-once
    /// booking per frame: N frames book N `sent` (primed socket takes the
    /// `Ok` arm for each), all N arrive, and the batch bound only caps the
    /// fast path — frames past 32 still go out through the per-frame path.
    #[tokio::test]
    async fn grouped_send_delivers_all_frames_with_exact_accounting() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 32];
        tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();
        const N: usize = 10;
        let frames: Vec<[u8; 8]> = (0..N).map(|i| [i as u8; 8]).collect();
        let empty: &[u8] = &[];
        let refs: Vec<SendFrame<'_>> = frames.iter().map(|f| (empty, &f[..])).collect();
        let d = {
            let _guard = CONTRACT_LOCK.lock().unwrap();
            let before = udp_write::snapshot();
            udp_try_send_grouped(&sock, dst, &refs);
            udp_write::snapshot().since(&before)
        };
        let mut got = [false; N];
        let mut seen = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while seen < N {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, listener.recv_from(&mut b)).await {
                Ok(Ok((8, _))) => {
                    let i = b[0] as usize;
                    if i < N && !got[i] && b[..8] == frames[i] {
                        got[i] = true;
                        seen += 1;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(seen, N, "every grouped frame must arrive: {seen}/{N}");
        // Primed loopback takes `Ok` per frame on either backend (sendmmsg
        // counts `sent` per delivered frame, fallback per try_send_to).
        assert_eq!(d.sent, N as u64, "N frames must book N sent: {d:?}");
        assert_eq!(d.retried, 0, "primed group must not book retries: {d:?}");
        assert_eq!(d.dropped_no_permit, 0, "live loopback must not drop: {d:?}");
        assert_eq!(d.failed, 0, "live loopback must not fail: {d:?}");
    }

    /// A grouped frame is `(header, payload)` and must land on the wire as **one**
    /// datagram, header first.
    ///
    /// That two-iovec shape is what lets the client's reply flush stage only the
    /// ≤22-byte SOCKS5 header and borrow the payload instead of concatenating
    /// both into a staging arena — one whole-payload memcpy per reply removed
    /// from the download path. The wire bytes therefore have to be pinned
    /// independently of the per-frame fallback, because on Linux the header and
    /// the body never meet in userspace at all.
    #[tokio::test]
    async fn grouped_header_and_payload_arrive_as_one_datagram() {
        const HDR: &[u8] = &[0, 0, 0, 0x01, 198, 51, 100, 7, 0, 53];
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();

        const N: usize = 6;
        let bodies: Vec<[u8; 4]> = (0..N).map(|i| [i as u8; 4]).collect();
        let refs: Vec<SendFrame<'_>> = bodies.iter().map(|x| (HDR, &x[..])).collect();
        udp_try_send_grouped(&sock, dst, &refs);

        let mut got = [false; N];
        let mut seen = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while seen < N {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, listener.recv_from(&mut b)).await {
                Ok(Ok((n, _))) => {
                    let want = HDR.len() + 4;
                    assert_eq!(n, want, "header and payload must arrive as one datagram");
                    assert_eq!(&b[..HDR.len()], HDR, "header must come first");
                    let i = b[HDR.len()] as usize;
                    assert!(i < N && !got[i] && b[HDR.len()..n] == bodies[i], "body {i}");
                    got[i] = true;
                    seen += 1;
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(seen, N, "every grouped frame must arrive: {seen}/{N}");
    }

    /// A one-frame group is not a batch: it must deliver header+payload as one
    /// datagram, book exactly one `sent`, and record **no** `send_group`
    /// histogram observation (one syscall is booked through
    /// `record_extra_syscalls` instead, whether it went out through the
    /// one-message `sendmmsg` or the per-frame fallback).
    ///
    /// The grouped machinery used to be entered for n == 1 as well, and that is
    /// the shape a drain burst spanning several sessions produces — one run per
    /// frame. On Linux it zeroed a 32-entry iovec/cmsg/mmsghdr scratch and
    /// issued a `sendmmsg` for a single datagram; the send-group histogram also
    /// gained a size-1 sample per such frame, which is noise in a report whose
    /// job is to show whether grouping amortizes. The scratch is now
    /// `MaybeUninit`-initialised for the used slots only, so the header frame
    /// keeps the zero-copy two-iovec send while still booking no histogram.
    #[tokio::test]
    async fn single_frame_group_books_one_syscall_and_no_group_observation() {
        /// The size-1 bucket of the 60 s send-group histogram (`send[1:..]`).
        fn size_one_groups() -> u64 {
            let r = crate::batch_report();
            let hist = r.split("send[").nth(1).expect("send hist in batch report");
            let first = hist.split_whitespace().next().expect("size-1 bucket");
            first
                .strip_prefix("1:")
                .expect("first bucket is the size-1 bucket")
                .parse()
                .expect("bucket count")
        }

        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // Prime writable readiness so the measured send takes the `Ok` arm.
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();

        const HDR: &[u8] = &[0x02, 0, 0, 1, 2, 3, 4];
        let body = [0x5Au8; 6];
        let one: [SendFrame<'_>; 1] = [(HDR, &body)];
        // The size-1 bucket has no other writer (the other grouped tests use
        // n = 6/10/40), so a delta here is exactly "a one-frame group was
        // recorded".
        let groups_before = size_one_groups();
        let d = {
            let _guard = CONTRACT_LOCK.lock().unwrap();
            let before = udp_write::snapshot();
            udp_try_send_grouped(&sock, dst, &one);
            udp_write::snapshot().since(&before)
        };
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("the single-frame group must arrive directly")
            .unwrap();
        assert_eq!(
            n,
            HDR.len() + body.len(),
            "header and payload must arrive as one datagram"
        );
        assert_eq!(&b[..HDR.len()], HDR, "header must come first");
        assert_eq!(&b[HDR.len()..n], &body[..]);
        assert_eq!(d.sent, 1, "one frame must book exactly one sent: {d:?}");
        assert_eq!(d.retried, 0, "a primed loopback send must not retry: {d:?}");
        assert_eq!(
            d.dropped_no_permit, 0,
            "a primed loopback send must not drop: {d:?}"
        );
        assert_eq!(d.failed, 0, "a primed loopback send must not fail: {d:?}");
        assert_eq!(
            size_one_groups(),
            groups_before,
            "a one-frame group must not record a send_group histogram observation"
        );
    }

    /// `record_extra_syscalls` corrects only the syscall tally: it must not move
    /// any per-datagram outcome. The grouped path charges `1` syscall for the
    /// `sendmmsg` itself and used to leave the per-frame tail uncounted, which
    /// under-reported `syscall_per_packet` exactly when the socket was
    /// saturated — the regime the batching exists for.
    #[test]
    fn extra_syscall_accounting_is_additive_only() {
        use crate::record_extra_syscalls;
        let before = udp_write::snapshot();
        record_extra_syscalls(7);
        let d = udp_write::snapshot().since(&before);
        assert!(d.clean(), "no drop outcome may move: {d:?}");
        assert_eq!(d.sent, 0, "no datagram outcome may move: {d:?}");
        assert_eq!(d.retried, 0, "no datagram outcome may move: {d:?}");
    }

    /// Empty groups are a no-op (no counters move, no syscall), and groups
    /// past the 32-frame bound still deliver every frame via the per-frame
    /// tail rather than truncating the burst.
    #[tokio::test]
    async fn grouped_send_empty_is_noop_and_oversize_delivers() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        sock.send_to(b"prime", dst).await.unwrap();
        let mut b = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut b))
            .await
            .expect("priming datagram must arrive")
            .unwrap();
        {
            let _guard = CONTRACT_LOCK.lock().unwrap();
            let before = udp_write::snapshot();
            udp_try_send_grouped(&sock, dst, &[]);
            let d = udp_write::snapshot().since(&before);
            assert_eq!(d.sent, 0, "empty group must book nothing: {d:?}");
            assert!(d.clean(), "empty group must book nothing: {d:?}");
        }
        const N: usize = 40;
        let frames: Vec<[u8; 4]> = (0..N).map(|i| [i as u8; 4]).collect();
        let empty: &[u8] = &[];
        let refs: Vec<SendFrame<'_>> = frames.iter().map(|f| (empty, &f[..])).collect();
        udp_try_send_grouped(&sock, dst, &refs);
        let mut seen = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while seen < N {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, listener.recv_from(&mut b)).await {
                Ok(Ok(_)) => seen += 1,
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(
            seen, N,
            "frames past the bound must still go out: {seen}/{N}"
        );
    }

    /// Shards are selected by destination ip+port: port-only sharding would
    /// collapse DNS(:53)/HTTPS(:443) workloads into one shard and reintroduce
    /// the head-of-line blocking the pool was created to remove.
    #[tokio::test]
    async fn shard_selected_by_ip_plus_port() {
        use std::ptr::eq as same;
        // Same destination always lands on the same shard.
        let a: SocketAddr = "10.0.0.1:53".parse().unwrap();
        assert!(same(retry_shard_for(&a), retry_shard_for(&a)));
        // Same port, different first octets must spread: proves the IP feeds
        // the hash. (The `% 16` shard index only sees the hash's low bits,
        // which carry the first octet on little-endian, so last-octet-only
        // sweeps legitimately collide; first-octet sweeps must not.)
        let same_port: Vec<SocketAddr> = (10u8..26)
            .map(|o| format!("{o}.0.0.1:53").parse().unwrap())
            .collect();
        let spread_ip = same_port
            .windows(2)
            .any(|w| !same(retry_shard_for(&w[0]), retry_shard_for(&w[1])));
        assert!(
            spread_ip,
            "different IPs on :53 must not all collapse into one shard"
        );
        // Same IP, different ports must spread: proves the port feeds the hash.
        let same_ip: Vec<SocketAddr> = [53u16, 443, 123, 3478, 5000, 8000, 9000, 10000]
            .iter()
            .map(|p| format!("10.0.0.99:{p}").parse().unwrap())
            .collect();
        let spread_port = same_ip
            .windows(2)
            .any(|w| !same(retry_shard_for(&w[0]), retry_shard_for(&w[1])));
        assert!(
            spread_port,
            "different ports on one IP must not all collapse into one shard"
        );
        // V6 selection is deterministic and in range.
        let v6a: SocketAddr = "[::1]:53".parse().unwrap();
        assert!(same(retry_shard_for(&v6a), retry_shard_for(&v6a)));
        // Every probed destination maps to a valid shard.
        for addr in same_port.iter().chain(same_ip.iter()).chain([v6a].iter()) {
            let idx = retry_shards()
                .iter()
                .position(|s| same(s, retry_shard_for(addr)))
                .unwrap();
            assert!(idx < UDP_RETRY_SHARDS, "shard index {idx} out of range");
        }
    }

    /// The 200 ms deadline — not the kernel — ends a parked retry, which is
    /// what bounds the strong `Arc<UdpSocket>` retention and releases the
    /// shard slot on a bounded schedule.
    #[tokio::test]
    async fn retry_deadline_bounds_a_parked_retry() {
        let start = Instant::now();
        assert!(
            under_retry_deadline(std::future::pending::<()>())
                .await
                .is_err(),
            "a send that never completes must be abandoned by the deadline"
        );
        let waited = start.elapsed();
        assert!(
            waited >= UDP_RETRY_TIMEOUT && waited < UDP_RETRY_TIMEOUT * 20,
            "the wait must be the 200 ms deadline, not open-ended: {waited:?}"
        );
        // A ready send is untouched by the deadline.
        assert_eq!(under_retry_deadline(async { 7u8 }).await, Ok(7));
    }

    /// `drop_warn_due` gives the Budget warning its warn-once-per-window
    /// behaviour: first drop warns unconditionally, floods are silenced.
    #[test]
    fn budget_warning_fires_once_per_window() {
        use crate::stats::{NEVER_WARNED, drop_warn_due};
        assert!(
            drop_warn_due(NEVER_WARNED, 0),
            "first Budget drop must warn"
        );
        assert!(
            !drop_warn_due(1_000, 1_000 + 9_999),
            "Budget flood inside the window must stay silent"
        );
        assert!(
            drop_warn_due(1_000, 1_000 + 10_000),
            "Budget drop after the window must warn again"
        );
    }
}
