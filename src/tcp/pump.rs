//! TCP pump extracted verbatim from `src/lib.rs`.
//! Source lines cover `copy_tcp_quic` / `copy_tcp_quic_idle` / `copy_tcp_quic_acked`
//! plus `COPY_CHUNK` / `ZEROCOPY_MIN_WRITE` and the full helper set.
//! Crate-local items resolve via `crate::` (`coarse_millis` 经根重导出，
//! `read_mqp_ack` 留在 lib.rs 经 `crate::read_mqp_ack` 引用）。
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::time::Duration;

use crate::{coarse_millis, read_mqp_ack};

/// Bidirectional copy between TCP and QUIC stream halves.
/// Half-closes propagate in both directions so neither side hangs waiting
/// for EOF after the peer already finished.
///
/// Contract: `Ok` means both halves reached clean EOF (TCP closed with FIN);
/// `Err` means at least one direction failed, in which case the TCP socket
/// was aborted with RST so the application sees an explicit failure instead
/// of a truncated-but-clean transfer.
///
/// Delegates to [`copy_tcp_quic_idle`] with an effectively unbounded idle
/// window; the direct `join!` implementation this used to have could hang
/// forever when one direction failed while the other stayed blocked.
pub async fn copy_tcp_quic(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, Duration::from_secs(u32::MAX as u64), None).await
}

/// Same as [`copy_tcp_quic`] but bounds idle keep-alive streams: if no bytes
/// flow in either direction for `idle`, both halves are shut down and an
/// error is returned so the per-connection task can exit (B7).
/// Uses monotonic `Instant` (never wall-clock) and resets the QUIC stream
/// on any directional failure so the peer never hangs.
/// The TCP socket is RST (not FIN) on the idle timeout, like any abnormal end.
pub async fn copy_tcp_quic_idle(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle: Duration,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, idle, None).await
}

/// Like [`copy_tcp_quic_idle`], but the QUIC→TCP direction first consumes the
/// MQP-2 dial acknowledgement (status + bound address). The caller is expected
/// to have already answered SOCKS optimistically: a failed or timed-out ACK
/// tears the TCP flow down so the application sees the failure instead of
/// hanging (aborted with RST, never a FIN posing as an empty reply). The TCP→QUIC direction is NOT gated on the ACK, which saves one
/// client↔server RTT on every connection.
pub async fn copy_tcp_quic_acked(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle: Duration,
    ack_timeout: Duration,
) -> Result<(u64, u64)> {
    copy_tcp_quic_inner(tcp, send, recv, idle, Some(ack_timeout)).await
}

/// Copy chunk: large enough that a high-BDP stream is not syscall-bound, small
/// enough that thousands of them do not dominate the RSS.
pub(crate) const COPY_CHUNK: usize = 32 * 1024;

/// Writes at least this large are handed to quinn as an owned `Bytes`
/// (`write_chunk`, which moves the buffer straight into the send queue) instead
/// of being copied into it. Below it the copy is the better trade: the buffer
/// handed over is a full [`COPY_CHUNK`] however few bytes were read, so a
/// request/response workload would pin 32 KiB per in-flight small write where
/// quinn's own `to_owned()` allocates exactly the bytes it needs.
const ZEROCOPY_MIN_WRITE: usize = 8 * 1024;

/// Segments one batched download round moves to TCP.
///
/// Shared by the `Bytes` batch the receive side fills and the iovec array
/// [`write_batch_vectored`] fills, so the two cannot drift: the iovec array is
/// fixed-size, and a `bufs` longer than it would store out of bounds — a panic
/// inside a relay task, which skips the RST/stop disposition in
/// [`copy_tcp_quic_inner`] and so fails *silently* rather than loudly.
const COPY_BATCH: usize = 8;

/// Throttle on the shared idle stamp in [`copy_tcp_quic_inner`].
///
/// The stamp is only ever compared against the 300 s idle deadline, and it is
/// read from the coarse millisecond epoch, so the finest interval this can
/// resolve is one epoch step. It exists to keep [`touch_stamp`]'s contract
/// ("at most one shared store per interval") honest, not to buy resolution.
const IDLE_STAMP_THROTTLE_MS: u64 = 100;

/// Make room for a whole copy chunk before a `read_buf`.
///
/// `BytesMut::chunk_mut` only reserves 64 B once the buffer is full, so without
/// this a `read_buf` on a full buffer would perform 64-byte reads — correct,
/// but hundreds of times more wakeups per chunk than intended. Pure so the
/// invariant that keeps the pump fast is pinned by a test.
#[inline]
pub(crate) fn reserve_copy_chunk(buf: &mut BytesMut) {
    if buf.capacity() - buf.len() < COPY_CHUNK {
        buf.reserve(COPY_CHUNK);
    }
}

const COPY_BUF_POOL_DEPTH: usize = 4;

thread_local! {
    static COPY_BUF_POOL: std::cell::RefCell<Vec<BytesMut>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn copy_buf_acquire() -> BytesMut {
    COPY_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if let Some(mut b) = p.pop() {
            b.clear();
            reserve_copy_chunk(&mut b);
            b
        } else {
            BytesMut::with_capacity(COPY_CHUNK)
        }
    })
}

fn copy_buf_release(mut buf: BytesMut) {
    buf.clear();
    COPY_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < COPY_BUF_POOL_DEPTH && buf.capacity() >= COPY_CHUNK {
            // Cap retained memory: a buffer that grew far past one chunk
            // (read side overshoot) is dropped instead of pooling.
            if buf.capacity() <= COPY_CHUNK * 2 {
                p.push(buf);
            }
        }
    });
}

/// Return both halves of the c2s double-buffer to the pool (or drop them).
///
/// A `BytesMut::new()` empty slot is fine to pass through: zero capacity means
/// `copy_buf_release` skips the pool and the slot is simply left empty.
fn release_copy_bufs(bufs: &mut [BytesMut; 2]) {
    copy_buf_release(std::mem::replace(&mut bufs[0], BytesMut::new()));
    copy_buf_release(std::mem::replace(&mut bufs[1], BytesMut::new()));
}

/// Throttled liveness stamp shared by the two copy directions.
///
/// `since_ms` is the caller's last observed elapsed time, kept in a local so the
/// hot loop never reloads the atomic; only an actual write goes to the shared
/// counter. Each direction still stamps at least once per `throttle`, so the
/// idle check in the select loop keeps its resolution.
#[inline]
fn touch_stamp(
    last: &std::sync::atomic::AtomicU64,
    since_ms: &mut u64,
    now_ms: u64,
    throttle: u64,
) {
    if now_ms.saturating_sub(*since_ms) >= throttle {
        *since_ms = now_ms;
        last.store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn write_batch_vectored<W>(tw: &mut W, bufs: &[Bytes]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::future::poll_fn;
    let mut off = 0usize;
    let mut skip = 0usize;
    while skip < bufs.len() {
        while skip < bufs.len() && off >= bufs[skip].len() {
            skip += 1;
            off = 0;
        }
        if skip >= bufs.len() {
            break;
        }
        let mut ios: [std::io::IoSlice<'_>; COPY_BATCH] = [std::io::IoSlice::new(&[]); COPY_BATCH];
        let mut nios = 0usize;
        // `take(COPY_BATCH)`: the iovec array is fixed-size, and a `bufs` longer
        // than it would store out of bounds. Taking only what fits is also
        // *correct* for a longer slice — `skip` advances past the buffers that
        // were written and the outer loop comes back for the rest.
        for (i, b) in bufs[skip..].iter().take(COPY_BATCH).enumerate() {
            let s = if i == 0 {
                &b[off.min(b.len())..]
            } else {
                &b[..]
            };
            if !s.is_empty() {
                ios[nios] = std::io::IoSlice::new(s);
                nios += 1;
            }
        }
        if nios == 0 {
            break;
        }
        let ios = &ios[..nios];
        let n = poll_fn(|cx| {
            tokio::io::AsyncWrite::poll_write_vectored(std::pin::Pin::new(&mut *tw), cx, ios)
        })
        .await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "tcp vectored write zero",
            ));
        }
        let mut left = n;
        while skip < bufs.len() {
            let avail = bufs[skip].len().saturating_sub(off);
            if left < avail {
                off += left;
                break;
            }
            left -= avail;
            skip += 1;
            off = 0;
            if left == 0 {
                break;
            }
        }
    }
    Ok(())
}

async fn copy_tcp_quic_inner(
    mut tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    idle: Duration,
    ack: Option<Duration>,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Liveness stamp shared by both directions, in the coarse millisecond epoch
    // (see [`coarse_millis`]): the value is only ever compared against the 300 s
    // idle deadline, so it does not need a clock read per chunk. Seeded with
    // "now" rather than 0 because it is compared against that same epoch — a 0
    // would read as "idle since process start", and the first idle tick of a
    // long-running process would tear every flow down on the spot.
    // Stack stamp, not `Arc`: both pump futures only borrow it (shared `&`),
    // and they are driven to completion inside this function, so no heap
    // allocation per flow.
    let last_ms = AtomicU64::new(coarse_millis());
    // Per-direction progress stamps, same epoch and throttle as `last_ms`. A
    // shared stamp alone cannot see a stall in one direction while the other
    // keeps flowing: the live direction refreshes it, so a half-dead stream
    // (e.g. a bulk download with a wedged upload) never looks idle and the
    // watchdog never fires. Each direction therefore stamps its own counter
    // alongside the shared one, and the idle tick below fails a direction
    // that made no progress for the whole window provided the shared stamp
    // is expired too (AND gate): one live direction keeps a healthy
    // half-idle flow alive, so only a stall on top of global silence kills.
    let c2s_last = AtomicU64::new(coarse_millis());
    let s2c_last = AtomicU64::new(coarse_millis());
    // Borrowed halves: `tcp` itself stays owned here so the final disposition
    // (graceful FIN on clean EOF, RST on any abnormal end) is decided in one
    // place after both directions settle, instead of each direction racing to
    // shut the socket down on its own.
    let (mut tr, mut tw) = tcp.split();
    // Per-direction completion flags, declared outside the pump scope so the
    // error disposition below can tell a half that finished cleanly from one
    // that was abandoned mid-flight.
    let mut c2s_total: Option<u64> = None;
    let mut s2c_total: Option<u64> = None;
    // Scope the pump futures: everything borrowing `tcp`, `send` and `recv` ends
    // at the block end, so the final disposition below owns all three outright.
    // The futures deliberately *borrow* the two QUIC halves rather than taking
    // them (no `move`): a dropped `quinn::SendStream` calls `finish()`, so a
    // future that owned the send half would announce an abnormal end to the peer
    // as a clean FIN — see the disposition, and `peer_sees_reset_not_fin`.
    let outcome: Result<(u64, u64)> = {
        let c2s = async {
            // Double-buffer. `split_to(n).freeze()` promotes the remainder to
            // a shared handle while quinn holds the frozen half in
            // `unacked_segments`, so the next `reserve` on the same buffer
            // cannot reclaim in place and would allocate a fresh 32 KiB.
            // Rotating gives the ACK one full other-buffer cycle to drop the
            // first frozen half before we need its capacity again; when the
            // half is released within that window the alloc is skipped, and
            // when it is not the behaviour is the same as the old
            // single-buffer path (allocate on reserve). Small writes
            // (`write_all`) do not split, so they keep the current buffer and
            // clear it.
            let mut bufs = [copy_buf_acquire(), copy_buf_acquire()];
            let mut cur = 0usize;
            let mut total = 0u64;
            let mut stamped = 0u64;
            let mut stamped_dir = 0u64;
            loop {
                reserve_copy_chunk(&mut bufs[cur]);
                let n = match tr.read_buf(&mut bufs[cur]).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        let total_copy = total;
                        release_copy_bufs(&mut bufs);
                        return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                            "tcp>quic tcp read failed after {total_copy}B up: {e:#}"
                        ));
                    }
                };
                // Hand the filled buffer to quinn as an owned `Bytes` so a bulk
                // chunk crosses no memcpy boundary at all (quinn's `write_chunk`
                // moves it into `unacked_segments`); the remaining allocation is
                // the one quinn's `to_owned()` used to perform, minus the copy.
                let res = if n >= ZEROCOPY_MIN_WRITE {
                    let frozen = bufs[cur].split_to(n).freeze();
                    // Next read uses the other buffer; this one may be shared
                    // with `frozen` until the ACK drops it.
                    cur ^= 1;
                    send.write_chunk(frozen).await
                } else {
                    let r = send.write_all(&bufs[cur][..n]).await;
                    if r.is_ok() {
                        bufs[cur].clear();
                    }
                    r
                };
                if let Err(e) = res {
                    let total_copy = total;
                    release_copy_bufs(&mut bufs);
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "tcp>quic quic write failed after {total_copy}B up: {e:#}"
                    ));
                }
                total += n as u64;
                // Stamp every chunk (throttled inside): gating on a chunk count
                // starves slow trickle uploads past the 300s idle reap while
                // downloads stamp every batch. Both the shared stamp and this
                // direction's own progress stamp move here (separate throttle
                // locals: one `touch_stamp` call consumes the observation, so a
                // second call with the same local would never store).
                let now = coarse_millis();
                touch_stamp(&last_ms, &mut stamped, now, IDLE_STAMP_THROTTLE_MS);
                touch_stamp(&c2s_last, &mut stamped_dir, now, IDLE_STAMP_THROTTLE_MS);
            }
            send.finish().ok();
            release_copy_bufs(&mut bufs);
            Ok::<u64, anyhow::Error>(total)
        };
        let s2c = async {
            let mut total = 0u64;
            let mut stamped = 0u64;
            let mut stamped_dir = 0u64;
            // Optimistic SOCKS replies have already told the application the
            // connection is up, so the MQP-2 dial ACK only gates the reply
            // direction here. A failure means the remote dial failed (or the
            // server never acked); tear the TCP flow down so the app fails fast.
            if let Some(t) = ack {
                let ok = matches!(
                    tokio::time::timeout(t, read_mqp_ack(&mut recv)).await,
                    Ok(Ok(()))
                );
                if !ok {
                    // No FIN here: the final disposition aborts the TCP flow with
                    // RST so the application retries instead of accepting an
                    // empty reply as success.
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "remote dial failed or MQP ack timed out"
                    ));
                }
            }
            let mut batch: [Bytes; COPY_BATCH] = std::array::from_fn(|_| Bytes::new());
            loop {
                // Batched zero-copy receive: `read_chunks` drains up to
                // `COPY_BATCH` assembler segments under one connection-lock
                // acquisition, then a single vectored write pushes them to TCP.
                // The old `read_chunk(MAX)+write_all` paid one lock + one syscall
                // per ~1.4 KiB STREAM frame; batching amortizes both. The idle
                // stamp is written once per batch, not per chunk.
                let n = match recv.read_chunks(&mut batch).await {
                    Ok(Some(n)) => n,
                    Ok(None) => break,
                    Err(e) => {
                        // Classify for the log line: a peer reset (e.g. refused
                        // dial) and a dead connection need different follow-ups.
                        let kind = match &e {
                            quinn::ReadError::Reset(code) => format!("peer reset {code:?}"),
                            quinn::ReadError::ConnectionLost(_) => "connection lost".to_string(),
                            _ => "quic read failed".to_string(),
                        };
                        return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                            "quic>tcp {kind} after {total}B down: {e:#}"
                        ));
                    }
                };
                if n == 0 {
                    continue;
                }
                // quinn writes only `batch[..n]`; every entry above it still holds
                // the *previous* call's chunk, and those are slices of quinn
                // receive buffers the assembler has already dropped from its own
                // accounting (see `Assembler::read`). Leaving them there pins
                // those allocations for the flow's lifetime — a burst-then-trickle
                // flow (any bulk download that settles, a WebSocket, ssh) leaves up
                // to `COPY_BATCH - 1` of them — so the tail is cleared explicitly
                // instead of waiting for a later call to overwrite it.
                for stale in batch[n..].iter_mut() {
                    *stale = Bytes::new();
                }
                let mut batch_bytes = 0usize;
                for b in batch.iter().take(n) {
                    batch_bytes += b.len();
                }
                if batch_bytes == 0 {
                    continue;
                }
                if let Err(e) = write_batch_vectored(&mut tw, &batch[..n]).await {
                    return Err::<u64, anyhow::Error>(anyhow::anyhow!(
                        "quic>tcp tcp write failed after {total}B down: {e:#}"
                    ));
                }
                total += batch_bytes as u64;
                let now = coarse_millis();
                touch_stamp(&last_ms, &mut stamped, now, IDLE_STAMP_THROTTLE_MS);
                touch_stamp(&s2c_last, &mut stamped_dir, now, IDLE_STAMP_THROTTLE_MS);
            }
            // QUIC-recv EOF: half-close the TCP write side now. Without
            // this FIN the peer waits for EOF while our own c2s direction
            // waits for the peer's FIN — a deadlock in which neither side
            // ever finishes and every cleanly-closed flow lingers until the
            // idle reap (or connection death), pinning its task, both
            // sockets and the stream-task permit. The TCP read side stays
            // open: c2s may still be forwarding, and its own EOF (after the
            // peer reacts to this FIN) completes the other half
            // symmetrically. A shutdown error means the peer is already
            // gone; the transfer itself is complete, so it is ignored and
            // the direction still reports Ok.
            tw.shutdown().await.ok();
            Ok::<u64, anyhow::Error>(total)
        };
        // Drive both directions manually instead of `join!`: when one direction
        // fails, leaving the loop drops the other future immediately, which closes
        // its TCP half and (see the disposition below) resets/stops its QUIC
        // stream. `join!` left the other side blocked in `read()` until the 300 s
        // idle deadline, so a dead QUIC connection could pin the target fd and
        // buffers for minutes.
        tokio::pin!(c2s);
        tokio::pin!(s2c);
        // Idle watchdog on a *fixed* cadence. The previous shape created a fresh
        // `sleep(step)` on every loop iteration, and any progress in either
        // direction re-entered the loop — so a busy stream registered and cancelled
        // a timer per data chunk (thousands per second). One pinned sleep that is
        // never re-created fixes the cadence: it is polled again after each transfer
        // event, and only the elapsed-time comparison decides when the deadline has
        // passed.
        // The unbounded `copy_tcp_quic` path passes u32::MAX seconds as
        // "no idle timeout": arming a 5s tick for it wakes every stream
        // forever for a check that can never fire.
        let idle_enabled = idle < Duration::from_secs(u32::MAX as u64 / 2);
        let idle_step = Duration::from_secs(5).min(idle);
        let idle_tick = tokio::time::sleep(idle_step);
        tokio::pin!(idle_tick);
        loop {
            tokio::select! {
                r = &mut c2s, if c2s_total.is_none() => match r {
                    Ok(v) => c2s_total = Some(v),
                    Err(e) => break Err(e),
                },
                r = &mut s2c, if s2c_total.is_none() => match r {
                    Ok(v) => s2c_total = Some(v),
                    Err(e) => break Err(e),
                },
                _ = &mut idle_tick, if idle_enabled => {
                    let elapsed_ms = coarse_millis();
                    let idle_ms = idle.as_millis() as u64;
                    // Per-direction stall, AND-gated on the shared stamp below: a
                    // direction that already reached clean EOF is exempt — its
                    // stamp legitimately stops — and the `Err` runs the shared
                    // reset/stop+RST disposition, so the peer learns the stall
                    // as a reset.
                    let c2s_stalled = c2s_total.is_none()
                        && elapsed_ms.saturating_sub(c2s_last.load(Ordering::Relaxed))
                            >= idle_ms;
                    let s2c_stalled = s2c_total.is_none()
                        && elapsed_ms.saturating_sub(s2c_last.load(Ordering::Relaxed))
                            >= idle_ms;
                    // AND-gated on the shared stamp: a direction that went quiet
                    // on its own (e.g. c2s done sending while s2c downloads past
                    // the window) is healthy, not a stall — the old shared-stamp
                    // logic kept such flows alive. Kill only when some unfinished
                    // direction is silent AND nothing flowed anywhere, keeping
                    // the direction name for the log line.
                    let shared_expired = elapsed_ms
                        .saturating_sub(last_ms.load(Ordering::Relaxed))
                        >= idle_ms;
                    if (c2s_stalled || s2c_stalled) && shared_expired {
                        let dir = if c2s_stalled && s2c_stalled {
                            "both directions"
                        } else if c2s_stalled {
                            "c2s"
                        } else {
                            "s2c"
                        };
                        break Err(anyhow::anyhow!(
                            "tcp stream stall ({dir}) idle>{idle:?} after {}B up/{}B down",
                            c2s_total.unwrap_or(0),
                            s2c_total.unwrap_or(0),
                        ));
                    }
                    // Shared-only expiry (no unfinished direction silent, yet
                    // nothing flowed anywhere): kept as the overall-idle arm so
                    // this check is not dead code behind the gate above.
                    if shared_expired {
                        break Err(anyhow::anyhow!(
                            "tcp stream idle>{idle:?} after {}B up/{}B down",
                            c2s_total.unwrap_or(0),
                            s2c_total.unwrap_or(0),
                        ));
                    }
                    // Re-arm towards the same fixed cadence rather than from "now":
                    // a chunk arriving just before the deadline must not push the
                    // check another full step into the future.
                    idle_tick
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_step);
                }
            }
            if let (Some(a), Some(b)) = (c2s_total, s2c_total) {
                break Ok((a, b));
            }
        }
    }; // pump futures (and their borrows of `tcp`, `send` and `recv`) end here
    match outcome {
        Ok((a, b)) => {
            // Both halves reached clean EOF: graceful FIN close.
            tcp.shutdown().await.ok();
            Ok((a, b))
        }
        Err(e) => {
            // Any abnormal end aborts with RST (see `abort_tcp`): a FIN here
            // would pose as a complete transfer and silently corrupt downloads.
            abort_tcp(tcp);
            // ...and the *peer* has to learn the same thing, which is why the
            // pump futures only borrow the QUIC halves. `Drop for
            // quinn::SendStream` calls `finish()` — a graceful FIN — so an
            // upload direction abandoned because the download failed (or because
            // the idle watchdog fired) used to tell the peer "transfer
            // complete". The peer's `read_chunks` then returns a clean
            // `Ok(None)` instead of a reset, its own `abort_tcp` never runs, and
            // the application on that side accepts a truncated transfer as a
            // whole one: exactly the silent corruption `abort_tcp` exists to
            // prevent, one hop further out. `recv.stop` is the mirror image for a
            // download abandoned mid-flight — it makes the peer's `write_chunk`
            // fail with `Stopped` instead of succeeding into a void.
            //
            // Both are gated on the direction's own completion flag, because a
            // half that already reached clean EOF must *not* be reset: its data
            // was delivered and the peer may already have acted on it, and a
            // reset after FIN would retroactively mark a complete transfer as
            // aborted. (`stop` on a fully-read stream is a protocol no-op, so
            // skipping it costs nothing either.)
            if c2s_total.is_none() {
                send.reset(0x04u32.into()).ok();
            }
            if s2c_total.is_none() {
                recv.stop(0x04u32.into()).ok();
            }
            Err(e)
        }
    }
}

/// Abort a TCP socket with RST instead of FIN.
///
/// Used exclusively for abnormal pump ends (see `copy_tcp_quic_inner`): a
/// graceful FIN would tell the application the transfer completed, turning a
/// truncated download into silent corruption (curl exits 0 on a short file).
/// SO_LINGER=0 makes the close emit RST, so the application sees an explicit
/// failure and can retry or resume (e.g. HTTP Range).
fn abort_tcp(tcp: tokio::net::TcpStream) {
    // `into_std` failure is not actionable here; worst case the socket closes
    // gracefully while the caller still reports the error.
    if let Ok(std) = tcp.into_std() {
        let _ = socket2::SockRef::from(&std).set_linger(Some(Duration::ZERO));
        // `std` drops here: linger 0 => RST.
    }
}
