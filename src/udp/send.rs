//! QUIC DATAGRAM 发送路径：逐行搬运自 `src/lib.rs`（零改动抽取）。
//!
//! 搬运区间（以符号为准）：
//! - `DatagramSend`：旧 lib.rs `DatagramSend` 全体（含分隔线与文档）
//! - `try_send_datagram`：旧 lib.rs `try_send_datagram` 全体
//! - `send_udp_datagram` / `send_udp_datagram_with_header` / `send_encoded`：旧 lib.rs 同名项
//! - `PayloadSend`：旧 lib.rs `PayloadSend` 全体
//!
//! 接线：`mqp`（`AddrHeader`/`TargetAddrRef`/`encode_datagram_with_header`/`DGRAM_PREFIX_LEN`）、
//! `stats`（`dgram_drops::*`、`udp_stats::payload`、`warn_datagram_drop`、
//! `DatagramDropKind`、`budget_detail`）均经 `crate::` 绝对路径引用。

use bytes::Bytes;
use futures_util::future::FutureExt;

use crate::dgram_drops;
use crate::mqp::addr::{AddrHeader, TargetAddrRef};
use crate::mqp::batch::{encode_batch_with_header, BATCH_SMALL_MAX, MAX_BATCH_ITEMS};
use crate::mqp::datagram::{
    encode_datagram_with_header, encode_datagram_with_prefix, DGRAM_PREFIX_LEN,
};
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
///
/// The single non-blocking poll is `FutureExt::now_or_never` (one poll with a
/// no-op waker; on `Pending` the future is dropped immediately, so nothing is
/// ever woken on a dangling task). Cancellation safety was verified against
/// quinn 0.11.12 `connection.rs` `SendDatagram`: on `Blocked` quinn puts the
/// datagram bytes back into the future (`this.data.replace(data)`) and parks
/// on `datagrams_unblocked.notified()` (tokio `Notified`, whose `Drop`
/// unregisters the waiter), so dropping the future after `Pending` drops the
/// bytes with it and leaves no waiter behind — no byte-count drift, no
/// notify-queue residue (`cancelled_datagram_waits_leave_no_residue` pins
/// this). `send_datagram_wait` takes the connection-state mutex on every poll
/// (`send_datagram` and `SendDatagram::poll` each take it exactly once per
/// frame; that irreducible mutex lives inside quinn), so the non-blocking
/// variant has to be able to ask once without parking a task.
pub fn try_send_datagram(conn: &quinn::Connection, d: Bytes) -> DatagramSend {
    match conn.send_datagram_wait(d).now_or_never() {
        Some(Ok(())) => DatagramSend::Sent,
        Some(Err(quinn::SendDatagramError::TooLarge)) => DatagramSend::TooLarge,
        Some(Err(quinn::SendDatagramError::UnsupportedByPeer)) => DatagramSend::Unsupported,
        Some(Err(quinn::SendDatagramError::ConnectionLost(_))) => DatagramSend::ConnectionLost,
        Some(Err(quinn::SendDatagramError::Disabled)) => DatagramSend::ConnectionLost,
        // Full send buffer: `send_datagram_wait` parks the datagram in its own
        // future, which `now_or_never` drops here, so nothing leaks.
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

/// N=1 fast-path twin of [`send_udp_datagram_with_header`]: `prefix` is the
/// [`DgramPrefixCache`](crate::mqp::datagram::DgramPrefixCache) `type | sess |
/// addr` bytes, so no header validation or re-encode happens here. Drop
/// accounting is identical to the slow path (same counters, same messages, same
/// `TooLarge` semantics); only the encoder differs, and it is byte-identical.
pub(crate) fn send_udp_datagram_with_prefix(
    conn: &quinn::Connection,
    prefix: &[u8],
    payload: &[u8],
    limit: usize,
) -> DatagramSend {
    let hdr_len = prefix.len().saturating_sub(DGRAM_PREFIX_LEN);
    let Some(d) = encode_datagram_with_prefix(prefix, payload, limit) else {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(
            DatagramDropKind::Large,
            "payload exceeds the path budget",
            n,
            || budget_detail(limit, limit.saturating_sub(DGRAM_PREFIX_LEN + hdr_len)),
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

/// Encode and send up to [`MAX_BATCH_ITEMS`] small payloads to one destination
/// as a single MQP-2 BATCH frame.
///
/// Same-destination, small-payload packing without added latency: callers pack
/// only datagrams already staged in the current drain burst, never waiting for
/// more. One quinn lock + one AEAD for N payloads instead of N.
/// Loss fate-sharing (one QUIC loss kills N app datagrams) bounds this to
/// `BATCH_SMALL_MAX` payloads; larger payloads keep the single-datagram path.
/// Returns the single-frame outcome collapsed like [`PayloadSend::outcome`].
pub fn send_udp_batch(
    conn: &quinn::Connection,
    sess: u32,
    address: &TargetAddrRef<'_>,
    payloads: &[&[u8]],
    limit: usize,
) -> DatagramSend {
    if payloads.is_empty() || payloads.len() > MAX_BATCH_ITEMS {
        return DatagramSend::TooLarge;
    }
    if payloads.iter().any(|p| p.len() > BATCH_SMALL_MAX) {
        return DatagramSend::TooLarge;
    }
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
    let Some(body) = encode_batch_with_header(sess, &header, payloads, limit) else {
        return DatagramSend::TooLarge;
    };
    let outcome = send_encoded(conn, body);
    if outcome == DatagramSend::Sent {
        for p in payloads {
            crate::udp_stats::payload(p.len());
        }
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
