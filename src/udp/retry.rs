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

use crate::stats::{claim_drop_warning, NEVER_WARNED};
use crate::udp_write;

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
/// session's 2 x 256 KiB kernel buffers on the server) for the process lifetime
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
