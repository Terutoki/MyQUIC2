//! QUIC DATAGRAM 发送路径：逐行搬运自 `src/lib.rs`（零改动抽取）。
//!
//! 搬运区间（以符号为准）：
//! - `DatagramSend`：旧 lib.rs `DatagramSend` 全体（含分隔线与文档）
//! - `poll_once`：旧 lib.rs `poll_once` 全体
//! - `try_send_datagram`：旧 lib.rs `try_send_datagram` 全体
//! - `send_udp_datagram` / `send_udp_datagram_with_header` / `send_encoded`：旧 lib.rs 同名项
//! - `PayloadSend`：旧 lib.rs `PayloadSend` 全体
//!
//! 接线：`mqp`（`AddrHeader`/`TargetAddrRef`/`encode_datagram_with_header`/`DGRAM_PREFIX_LEN`）、
//! `stats`（`dgram_drops::*`、`udp_stats::payload`、`warn_datagram_drop`、
//! `DatagramDropKind`、`budget_detail`）均经 `crate::` 绝对路径引用。

use std::future::Future;
use std::task::{Context as TaskContext, Poll, Waker};

use bytes::Bytes;

use crate::dgram_drops;
use crate::mqp::addr::{AddrHeader, TargetAddrRef};
use crate::mqp::datagram::{encode_datagram_with_header, DGRAM_PREFIX_LEN};
use crate::stats::{budget_detail, warn_datagram_drop, DatagramDropKind};

// ---------------- QUIC DATAGRAM send (never the drop-oldest path) ----------------
/// Outcome of [`try_send_datagram`]. Mirrors quinn's error surface, but a full
/// send buffer is a plain `Blocked` (the datagram was dropped) instead of an
/// await point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramSend {
    /// Queued for transmission.
    Sent,
    /// The send buffer is full; the datagram was dropped (UDP semantics).
    Blocked,
    /// Larger than the current path allows; the caller should refresh its
    /// cached `max_datagram_size()` and drop this packet.
    TooLarge,
    /// The peer never negotiated DATAGRAM support.
    Unsupported,
    /// The connection is gone; the caller should tear the flow down.
    ConnectionLost,
}

/// Poll a future exactly once with a no-op waker.
///
/// Sound for futures that are polled to completion elsewhere or dropped right
/// after: a `Pending` result may leave a waker registered, but the no-op waker
/// is a valid `RawWaker` and the future is dropped immediately, so nothing is
/// ever woken on a dangling task.
///
/// Cancellation-safety for the one caller ([`try_send_datagram`], verified
/// against quinn 0.11.12 `connection.rs` `SendDatagram`): on `Blocked` quinn
/// puts the datagram bytes back into the future (`this.data.replace(data)`)
/// and parks on `datagrams_unblocked.notified()` (tokio `Notified`, whose
/// `Drop` unregisters the waiter). Dropping the future after `Pending` therefore
/// drops the bytes with it and leaves no waiter behind — no byte-count drift,
/// no notify-queue residue. `cancelled_datagram_waits_leave_no_residue` pins this.
///
/// Primitive behind [`try_send_datagram`]: `send_datagram_wait` takes quinn's
/// connection-state mutex on every poll, so the non-blocking variant has to be
/// able to ask once without parking a task.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Non-blocking DATAGRAM send that MUST be used instead of quinn's
/// `Connection::send_datagram`.
///
/// `send_datagram` is documented as "drop the oldest queued datagram when the
/// buffer is full", and that path used to be broken: quinn-proto 0.11.17's
/// `Connection::drop_oversized` (called whenever the path MTU shrinks) removed
/// datagrams from the outgoing queue and decremented `payload_bytes` for each,
/// yet a datagram re-queued by `DatagramState::write` had already been
/// decremented by `pop_front` — so the byte counter was decremented twice. It
/// underflowed to `usize::MAX`, `memory_used()` then looked astronomically large
/// while the queue was empty, and the next `send_datagram` panicked on
/// `.expect("datagrams.outgoing.payload_bytes desynchronized")` inside quinn's
/// connection-state mutex, poisoning it and aborting the whole process.
/// Reproduced on loopback with a 1200-byte payload against a peer whose
/// `max_datagram_size()` had shrunk to 1162 bytes, so it was reachable by any
/// PMTU reduction — i.e. by normal network conditions, not just a hostile peer.
///
/// Upstream fixed the bookkeeping (the counter now lives inside the datagram
/// buffer and `drop_oversized` only decrements what it actually removes), so the
/// crash is gone. This wrapper is kept because the relay still wants its
/// semantics: `send_datagram_wait` failing with the bounded (`Blocked`) path
/// reports the drop to the caller and discards the *newest* datagram, whereas
/// `send_datagram` silently evicts the *oldest* queued one and returns `Ok`. The
/// callers count and log `Blocked`, so switching would quietly erase the
/// per-connection drop accounting. Bytes are copied per datagram regardless
/// (quinn assembles each datagram frame with `extend_from_slice`), so this costs
/// nothing extra.
pub fn try_send_datagram(conn: &quinn::Connection, d: Bytes) -> DatagramSend {
    match poll_once(conn.send_datagram_wait(d)) {
        Some(Ok(())) => DatagramSend::Sent,
        Some(Err(quinn::SendDatagramError::TooLarge)) => DatagramSend::TooLarge,
        Some(Err(quinn::SendDatagramError::UnsupportedByPeer)) => DatagramSend::Unsupported,
        Some(Err(quinn::SendDatagramError::ConnectionLost(_))) => DatagramSend::ConnectionLost,
        Some(Err(quinn::SendDatagramError::Disabled)) => DatagramSend::ConnectionLost,
        // Full send buffer: `send_datagram_wait` parks the datagram in its own
        // future, which `poll_once` drops here, so nothing leaks.
        None => DatagramSend::Blocked,
    }
}

/// Encode and send one UDP payload as a single MQP-2 DATAGRAM, accounting for
/// every drop.
///
/// `limit` must be [`quinn::Connection::max_datagram_size`] — see
/// [`dgram_payload_cap`] for the resulting UDP payload budget. A returned
/// [`DatagramSend::TooLarge`] means the payload exceeds what the current path
/// can carry in one frame; [`DgramFragmenter::send`] is the relay entry point
/// and splits such a payload instead of dropping it.
pub fn send_udp_datagram(
    conn: &quinn::Connection,
    sess: u32,
    address: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> DatagramSend {
    let Ok(header) = address.header() else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(
            DatagramDropKind::Large,
            "bad address header",
            n,
            String::new,
        );
        return DatagramSend::TooLarge;
    };
    send_udp_datagram_with_header(conn, sess, &header, payload, limit)
}

pub(crate) fn send_udp_datagram_with_header(
    conn: &quinn::Connection,
    sess: u32,
    header: &AddrHeader<'_>,
    payload: &[u8],
    limit: usize,
) -> DatagramSend {
    let Some(d) = encode_datagram_with_header(sess, header, payload, limit) else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(
            DatagramDropKind::Large,
            "payload exceeds the path budget",
            n,
            || budget_detail(limit, limit.saturating_sub(DGRAM_PREFIX_LEN + header.len())),
        );
        return DatagramSend::TooLarge;
    };
    send_encoded(conn, d)
}

/// Queue an already-encoded datagram body, counting a full send buffer.
///
/// This is also the only place that sees quinn's own verdict on a body the
/// encoder already accepted, so it is where quinn's `TooLarge` is accounted:
/// a path-MTU reduction under a cached budget is a *size* drop, and there is
/// no other point on the path that can tell it apart from a dead connection.
/// Leaving it uncounted made it invisible in the size counters; letting it
/// fall through to the callers made them report a healthy connection as lost.
pub(crate) fn send_encoded(conn: &quinn::Connection, body: Bytes) -> DatagramSend {
    let outcome = try_send_datagram(conn, body);
    if outcome == DatagramSend::Blocked {
        let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
        warn_datagram_drop(
            DatagramDropKind::BufferFull,
            "send buffer full",
            n,
            String::new,
        );
    } else if outcome == DatagramSend::TooLarge {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(
            DatagramDropKind::Large,
            "path budget shrank under the encoded datagram",
            n,
            String::new,
        );
    }
    outcome
}

/// Result of [`DgramFragmenter::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadSend {
    /// Frames actually queued (1 for the unfragmented fast path).
    pub frames: u8,
    /// The failure that stopped the send, if it did not complete. A partially
    /// sent payload is *not* rolled back: the peer discards it on reassembly
    /// timeout, which is the UDP answer to a lost fragment.
    pub failed: Option<DatagramSend>,
}

impl PayloadSend {
    pub fn complete(&self) -> bool {
        self.failed.is_none()
    }
    pub fn fragmented(&self) -> bool {
        self.frames > 1
    }
    /// Collapse to the single-frame outcome the relays already match on.
    pub fn outcome(&self) -> DatagramSend {
        self.failed.unwrap_or(DatagramSend::Sent)
    }
}
