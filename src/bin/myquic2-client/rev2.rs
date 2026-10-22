//! MQP-3 wire rev2: per-connection state, `HELLO`/`CAPS` handshake and the
//! client uplink staging for small UDP payloads.
//!
//! The wire codec lives in `myquic2::mqp::r2` and the connection/session flow
//! tables in `myquic2::mqp::r2_flow`; both are shared with the server and are
//! deliberately not modified here. This module is the client-side glue:
//!
//! * [`ConnRev2`] — one instance per QUIC connection, published on the pool
//!   slot so the slot's DATAGRAM dispatcher (downlink) and every UDP
//!   association (uplink) reach the *same* [`FlowRegistry`]/[`CtlState`].
//!   A fresh instance is created for every dial, so the wire-id namespace and
//!   the confirmation state are connection-scoped, exactly as the spec
//!   requires; its [`ConnRev2::epoch`] lets an association notice that a
//!   redial invalidated the bindings it holds.
//! * [`handshake`] — sends `CTL HELLO` immediately after a connection is
//!   published and retries until `CAPS` (or the ~2 s cap). The caller closes
//!   the connection when this fails, so a non-rev2 server is a redial, never a
//!   silent fallback to the old wire.
//! * [`UplinkFlows`] + [`send_uplink`] — the association-local uplink state
//!   machine: new target ⇒ `DATA OPEN` (repeated while the binding is
//!   `Opening`, which is idempotent on the server), confirmed flow ⇒ steady
//!   payload, and `DATA INLINE` as the fail-safe whenever a flow cannot be
//!   bound. Every payload size is rev2: one `DATA` frame when it fits the live
//!   limit, otherwise [`R2Fragmenter`] `FRAG` frames with the matching
//!   addressing form. No MQP-2 frame is produced for UDP any more; the legacy
//!   v3/MQP-2 decoders that remain in the client are for old-wire diagnostics
//!   only.
//! * **Phase 2:** small payloads are not sent here at all — they are pushed
//!   into the connection-scoped [`ConnRev2::stager`] and written by
//!   [`drain_assoc_stage`] at the association's burst end (also before a large
//!   standalone payload and on exit), which is what packs several
//!   associations' payloads into one cross-session `TRAIN dict`.
use super::*;
use bytes::Bytes;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{
    CtlState, FlowBinding, FlowIds, FlowRegistry, FlowState, R2_MAX_FLOWS_PER_CONN, SessionFlows,
};
use myquic2::udp::r2_frag::R2FragFlow;
use myquic2::udp::{
    R2DrainOutcome, R2Fragmenter, R2StageItem, R2StageKind, R2Stager, drain_staged,
};

/// Retry cadence for `CTL HELLO` until `CAPS` arrives.
pub(crate) const HELLO_RETRY: Duration = Duration::from_millis(200);
/// Hard cap on the `HELLO`/`CAPS` handshake. A server that never answers is not
/// a rev2 peer: the caller closes the connection and the redial loop retries,
/// which is the spec's fail-fast rule (no silent old-wire fallback).
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounded set of server-closed sessions recorded for the association to
/// consume. Bounded because a peer controls `SESS_CLOSE`: past the cap the
/// notification is dropped (compression just waits for the redial) instead of
/// growing an unbounded set.
const MAX_CLOSED_SESSIONS: usize = 64;

/// How long a target the server rejected (`CTL FLOW_REJECT`: policy / table
/// full / DNS failure) is sent `INLINE` before the uplink retries an `OPEN`.
///
/// The spec asks for exactly this fallback: retrying the OPEN on every payload
/// would be a rejected frame plus a lost payload each time, while `INLINE`
/// keeps the association working (the server can still forward a
/// self-describing frame) and re-tests the flow after the TTL.
const REJECT_TTL_MS: u64 = 10_000;

/// Upper bound on the rejected-target cache. A peer controls rejections, so the
/// set is bounded; past the cap the oldest entry is forgotten (the flow just
/// retries sooner).
const MAX_REJECTED_TARGETS: usize = 64;

/// Monotonic connection-generation counter: every [`ConnRev2`] gets a fresh
/// epoch, which is what lets an association tell "these bindings belong to the
/// connection I am about to send on" from "these bindings died with the
/// previous QUIC connection" without sharing a lock with the reconnect loop.
static NEXT_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Per-connection rev2 state, shared through the pool slot.
pub(crate) struct ConnRev2 {
    /// Unique per dial. An association resets its [`UplinkFlows`] when the
    /// epoch of the handle it is about to send on changes.
    pub(crate) epoch: u64,
    /// `wire_id -> Arc<FlowBinding>` for both directions on this connection.
    /// The uplink inserts newly opened flows; the dispatcher resolves
    /// compressed downlink frames through it. Ids are never reused while the
    /// connection lives, so a removed entry can only be hit by a stale frame
    /// that then fails lookup.
    pub(crate) registry: FlowRegistry,
    /// Client-owned (`owner = 0`) wire-id allocator, one per connection.
    pub(crate) ids: FlowIds,
    /// `HELLO`/`CAPS` negotiation state. The dispatcher records `CAPS` here;
    /// the reconnect loop and the egress cache read `is_ready()`.
    pub(crate) ctl: CtlState,
    /// `true` once a `CAPS` with the rev2 wire version was received. This is
    /// **not** a UDP usability gate: the first payload may be sent
    /// optimistically before `CAPS` (the server buffers pre-HELLO frames until
    /// the version gate opens). `CAPS` only replaces the boot limits with the
    /// peer's negotiated caps and enables the peer-advertised compression
    /// limits; the reconnect loop still treats a missing/wrong CAPS as fatal.
    ready: std::sync::atomic::AtomicBool,
    /// `CAPS.max_frame_bytes` (`0` = not negotiated), the peer's one-frame
    /// cap. The live limit for every rev2 send is `min(conn budget, this)`,
    /// read with one atomic load on the per-datagram path.
    max_frame_bytes: std::sync::atomic::AtomicU16,
    /// Connection-scoped Phase-2 egress stager: every association bound to
    /// this connection pushes its small ready-to-send payloads here, and
    /// whichever association drains next packs items from **different
    /// sessions** into one `TRAIN dict` on one DATAGRAM (round-robin fair).
    ///
    /// The primitive's `push`/`drain` need `&mut self`, so the shared queue is
    /// behind a mutex; it is held only for one push or one drain loop (encode +
    /// non-blocking send), never across an await, and never nested with another
    /// stager lock.
    pub(crate) stager: Arc<parking_lot::Mutex<R2Stager>>,
    /// Sessions the server closed (see [`MAX_CLOSED_SESSIONS`]).
    ///
    /// The `take` guard is the datagram's very first shared read, and the vector
    /// is empty in steady state (populated only by a server `SESS_CLOSE`): the
    /// `closed_len` counter below turns the per-datagram probe into one relaxed
    /// load, and the exclusive write lock is taken only while a close is
    /// actually pending.
    closed_sessions: parking_lot::RwLock<Vec<u32>>,
    /// Live `closed_sessions` length, maintained under the write lock. A stale
    /// *overshoot* is impossible (writes under the lock refresh it last); a
    /// stale zero short-takes one extra payload before the next sync re-checks,
    /// which is ordinary UDP loss. Updated with `Relaxed`: the caller treats
    /// `false` as "not closed on this datagram" and re-checks on the next sync.
    closed_len: std::sync::atomic::AtomicUsize,
    /// `(target, rejected_at_ms)` for targets the server rejected with
    /// `CTL FLOW_REJECT` (see [`REJECT_TTL_MS`]).
    rejected: parking_lot::RwLock<Vec<(TargetAddr, u64)>>,
}

impl std::fmt::Debug for ConnRev2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `R2Stager` is not `Debug`; report the observable queue size instead of
        // the whole primitive.
        f.debug_struct("ConnRev2")
            .field("epoch", &self.epoch)
            .field("registry_len", &self.registry.len())
            .field("ids_allocated", &self.ids.allocated())
            .field("ready", &self.is_ready())
            .field("stage_len", &self.stage_len())
            .finish()
    }
}

impl ConnRev2 {
    /// Fresh state for one dial.
    pub(crate) fn new() -> Arc<Self> {
        Self::with_stager(R2Stager::new())
    }

    /// Test seam: the same state with an explicitly sized stager queue, so a
    /// unit test can provoke the queue-full policy without 1024 pushed items.
    #[cfg(test)]
    pub(crate) fn with_stager_capacity(items: usize, bytes: usize) -> Arc<Self> {
        Self::with_stager(R2Stager::with_capacity(items, bytes))
    }

    fn with_stager(stager: R2Stager) -> Arc<Self> {
        Arc::new(Self {
            epoch: NEXT_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            registry: FlowRegistry::new(R2_MAX_FLOWS_PER_CONN),
            ids: FlowIds::new(false),
            ctl: CtlState::new(),
            ready: std::sync::atomic::AtomicBool::new(false),
            max_frame_bytes: std::sync::atomic::AtomicU16::new(0),
            stager: Arc::new(parking_lot::Mutex::new(stager)),
            closed_sessions: parking_lot::RwLock::new(Vec::new()),
            closed_len: std::sync::atomic::AtomicUsize::new(0),
            rejected: parking_lot::RwLock::new(Vec::new()),
        })
    }

    /// Record a decoded `CAPS`. Only `wire_ver == 2` makes the connection
    /// usable; any other version stays not-ready and the handshake loop closes
    /// the connection (fail-fast, no old-wire fallback).
    pub(crate) fn on_caps(&self, caps: r2::Caps) {
        self.ctl.set_caps(caps);
        counters::caps_rx();
        if caps.wire_ver != r2::R2_WIRE_VER {
            return;
        }
        let frame_bytes = if caps.max_frame_bytes == 0 {
            r2::R2_DEFAULT_MAX_FRAME_BYTES
        } else {
            caps.max_frame_bytes
        };
        self.max_frame_bytes
            .store(frame_bytes, std::sync::atomic::Ordering::Relaxed);
        self.stager.lock().set_max_train_items(caps.max_train_items);
        self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether `CAPS(wire_ver=2)` was received on this connection.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Live per-frame limit: the connection's DATAGRAM budget capped by the
    /// peer's negotiated `CAPS.max_frame_bytes`.
    ///
    /// Before `CAPS` the connection limit alone is the safe answer: the
    /// server's default cap is 1472 and a fresh connection's DATAGRAM budget
    /// is at most that (initial MTU 1200/1472 minus QUIC overhead), so an
    /// optimistic first frame cannot exceed what the server accepts.
    pub(crate) fn frame_limit(&self, conn_limit: usize) -> usize {
        let capped = self
            .max_frame_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        if capped == 0 {
            conn_limit
        } else {
            conn_limit.min(usize::from(capped))
        }
    }

    /// Queue one ready-to-send small payload for this connection.
    ///
    /// Returns the post-push queue length so `stage_or_count` can fire the
    /// opportunistic drain on the same lock hold (this used to be a second
    /// `MutexGuard` acquisition per staged payload just to read the length).
    /// The item comes back when the bounded queue is full; the caller owns
    /// the drop policy (see [`send_uplink`]).
    pub(crate) fn push_stage(&self, item: R2StageItem) -> Result<usize, R2StageItem> {
        self.stager.lock().push(item)
    }

    /// Two-phase drain of the connection's queued payloads.
    ///
    /// Each batch packs a bounded number of frames under one short lock hold;
    /// the QUIC writes happen outside it. The loop keeps draining until the
    /// queue is empty, the item budget for one call is spent, or a send fails.
    /// On a failure the unsent tail is requeued behind a fresh hold, so a full
    /// send buffer can never make every subsequent payload re-encode the whole
    /// queue. Packing is serialised by the stager lock, but the send phase is
    /// not: two concurrent associations drain disjoint batches, and their
    /// DATAGRAMs can interleave on the wire (a later-packed batch may be sent
    /// first). That is inside the UDP / MQP-3 contract — every frame is
    /// self-describing and FRAG reassembly is keyed by index — and it is the
    /// price of keeping quinn sends outside the stager lock.
    pub(crate) fn drain_stage(&self, conn: &quinn::Connection, limit: usize) -> R2DrainOutcome {
        drain_staged(conn, &self.stager, limit, || {
            counters::stage_full();
            let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
            warn_stage_full(n);
        })
    }

    /// Number of payloads currently queued on this connection.
    #[must_use]
    pub(crate) fn stage_len(&self) -> usize {
        self.stager.lock().len()
    }

    /// Drop the connection's queued payloads at teardown, accounting each as an
    /// egress death (the connection is the only thing that can have died).
    ///
    /// The stager's own `Drop` performs the same accounting when the last
    /// `Arc<ConnRev2>` goes away; doing it in the death commit makes the
    /// counters deterministic and leaves nothing for `Drop` to double count.
    pub(crate) fn clear_stage(&self) -> usize {
        let n = self.stager.lock().clear();
        for _ in 0..n {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        n
    }

    /// Record `CTL SESS_CLOSE` from the server for `sess`. Bounded (see
    /// [`MAX_CLOSED_SESSIONS`]) and idempotent.
    pub(crate) fn note_session_closed(&self, sess: u32) {
        let mut closed = self.closed_sessions.write();
        if closed.len() < MAX_CLOSED_SESSIONS && !closed.contains(&sess) {
            closed.push(sess);
        }
        // Refresh under the same lock hold: a concurrent `take` that saw the
        // pre-push length then did not find its id cannot pass a stale zero to
        // the *next* sync.
        self.closed_len
            .store(closed.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Consume a recorded `SESS_CLOSE` for `sess`.
    pub(crate) fn take_session_closed(&self, sess: u32) -> bool {
        // The steady-state short-circuit: an empty vector (the common case)
        // costs one relaxed load instead of an exclusive lock acquisition per
        // uplink datagram. `closed_len` only says "the lock may be worth
        // taking" — the vector itself stays the authority, so a concurrent
        // `note` racing an in-flight probe is refuted (not lost): it refreshes
        // the count under its own write hold and the next sync picks it up.
        if self.closed_len.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return false;
        }
        let mut closed = self.closed_sessions.write();
        match closed.iter().position(|&s| s == sess) {
            Some(i) => {
                closed.swap_remove(i);
                self.closed_len
                    .store(closed.len(), std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => {
                // Heal the counter (its earlier read raced a concurrent
                // drain); one fresh store can only ever be conservative.
                self.closed_len
                    .store(closed.len(), std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }

    /// Record that the server rejected a flow for `target`. The uplink then
    /// sends `INLINE` for it until [`REJECT_TTL_MS`] elapses, which is the
    /// spec's fallback for FLOW_REJECT (policy / table full / DNS failure).
    pub(crate) fn note_rejected(&self, target: TargetAddr, now_ms: u64) {
        let mut rejected = self.rejected.write();
        rejected.retain(|(_, at)| now_ms.saturating_sub(*at) < REJECT_TTL_MS);
        if let Some(slot) = rejected.iter_mut().find(|(t, _)| *t == target) {
            slot.1 = now_ms;
            return;
        }
        if rejected.len() >= MAX_REJECTED_TARGETS {
            rejected.remove(0);
        }
        rejected.push((target, now_ms));
    }

    /// Whether `addr` is inside an active rejection window.
    ///
    /// Read-mostly fast path: one shared-lock scan answers the common cases —
    /// no match, or a match while no entry has expired — without paying the
    /// exclusive lock the old shape took on every payload of a rejected
    /// target's window (and on every new-target payload in general). Only when
    /// the scan sees an expired entry, i.e. when the table actually needs
    /// pruning, does this upgrade to the write lock, prune and re-test under
    /// it. The TTL predicate is unchanged: an entry is live while
    /// `now_ms - at < REJECT_TTL_MS`, exactly what the prune retains and what
    /// [`Self::note_rejected`] maintains.
    pub(crate) fn is_rejected(&self, addr: &TargetAddrRef<'_>, now_ms: u64) -> bool {
        let expired = |at: &u64| now_ms.saturating_sub(*at) >= REJECT_TTL_MS;
        let rejected = self.rejected.read();
        let mut hit = false;
        let mut stale = false;
        for (t, at) in rejected.iter() {
            stale |= expired(at);
            hit |= t.as_ref() == *addr;
        }
        if !stale {
            return hit;
        }
        // An expired entry means the cache must be pruned. That is the rare
        // case (it happens once per entry per TTL at most), so the write lock
        // is paid only here; the re-test under it is authoritative against a
        // concurrent `note_rejected`.
        drop(rejected);
        let mut rejected = self.rejected.write();
        rejected.retain(|(_, at)| !expired(at));
        rejected.iter().any(|(t, _)| t.as_ref() == *addr)
    }

    /// Drop every binding (connection teardown). Bindings still referenced by
    /// an association are `Closed` logically by the epoch change; clearing the
    /// registry releases the map's references for the dead generation.
    pub(crate) fn clear_flows(&self) -> usize {
        self.registry.clear()
    }
}

/// `CTL HELLO`/`CAPS` handshake for one freshly published connection.
///
/// Sends `HELLO` immediately, then once per [`HELLO_RETRY`] until the
/// dispatcher stores a `CAPS` (see [`ConnRev2::on_caps`]) or
/// [`HANDSHAKE_TIMEOUT`] expires. UDP payloads are not blocked on this
/// function: the egress cache publishes the generation right after the state
/// is set, and the server buffers pre-HELLO frames until the gate opens. A `CAPS` for a different wire version fails
/// immediately: waiting out the timeout would only delay the mandated redial.
/// `false` means the caller must close the connection.
pub(crate) async fn handshake(conn: &quinn::Connection, rev2: &ConnRev2) -> bool {
    handshake_with(conn, rev2, HANDSHAKE_TIMEOUT, HELLO_RETRY).await
}

/// Testable form of [`handshake`] with explicit timing (keeps the 2 s
/// production budget out of the unit tests).
pub(crate) async fn handshake_with(
    conn: &quinn::Connection,
    rev2: &ConnRev2,
    timeout: Duration,
    retry: Duration,
) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        let hello = r2::encode_ctl(&r2::Ctl::Hello {
            wire_ver: r2::R2_WIRE_VER,
            flags: 0,
        });
        match try_send_datagram(conn, hello) {
            // The datagram queue is full (a fresh connection usually is not):
            // HELLO is idempotent, the next tick retries it.
            DatagramSend::Sent | DatagramSend::Blocked | DatagramSend::TooLarge => {}
            DatagramSend::ConnectionLost | DatagramSend::Unsupported => {
                counters::handshake_fail();
                return false;
            }
        }
        counters::hello_tx();
        if rev2.is_ready() {
            counters::handshake_ok();
            return true;
        }
        if rev2
            .ctl
            .caps()
            .is_some_and(|c| c.wire_ver != r2::R2_WIRE_VER)
        {
            counters::handshake_fail();
            return false;
        }
        if start.elapsed() >= timeout {
            counters::handshake_fail();
            return false;
        }
        tokio::time::sleep(retry).await;
    }
}

/// Best-effort `CTL SESS_CLOSE` on association exit: three datagrams on the
/// association's current egress connection, exactly as the spec's control
/// plane asks (the frame is idempotent and loss only delays reclamation; the
/// server's 180 s idle sweep is the backstop). Nothing is awaited and a
/// missing egress is not an error — the association is already gone.
pub(crate) fn send_sess_close(egress: &SharedEgress, pool: &ConnPool, bind: UdpBind, sess: u32) {
    let frame = r2::encode_ctl(&r2::Ctl::SessClose { sess, reason: 0 });
    let send = |conn: &quinn::Connection, rev2: &ConnRev2| {
        // Only a negotiated connection is allowed to carry rev2 frames; a
        // handshake-window connection would just count as REFUSED server-side.
        if !rev2.is_ready() {
            return;
        }
        // The association is gone: release its connection-scoped bindings
        // (client-owned and accepted server-owned alike) and any payload still
        // queued for it, so a later drain cannot send frames for a session the
        // server is about to reap. The stager books each dropped payload as an
        // egress death, exactly like a closed connection.
        let _ = rev2.registry.remove_session(sess);
        let _ = rev2.stager.lock().drop_session(sess);
        for _ in 0..3 {
            match try_send_datagram(conn, frame.clone()) {
                DatagramSend::Sent => counters::sess_close_tx(),
                DatagramSend::ConnectionLost | DatagramSend::Unsupported => return,
                DatagramSend::Blocked | DatagramSend::TooLarge => return,
            }
        }
    };
    let now = coarse_millis();
    if let Some(()) = egress.with_fresh(bind, now, |c, _limit, rev2| send(c, rev2)) {
        return;
    }
    // Generation read before the cached read, the same contract the per-datagram
    // miss path documents: a concurrent mutation then invalidates the memo.
    let generation = egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    if let Some(h) = egress.acquire(pool, bind, now) {
        egress.memo_store(bind, generation, &h.conn, h.limit, h.stamp_ms, &h.rev2);
        send(&h.conn, &h.rev2);
    }
}

/// Association-local uplink state for the rev2 small-packet path.
///
/// One per UDP association: [`SessionFlows`] maps a destination to its binding
/// (the binding itself is shared with the connection registry) and
/// [`Self::epoch`] records which connection generation the bindings belong to.
///
/// The ready-to-send queue is **not** association-local any more: Phase 2 moved
/// small-payload staging to the connection's [`ConnRev2::stager`], so one drain
/// can pack payloads from several associations into one cross-session `TRAIN
/// dict`. This struct keeps only the per-session routing state.
pub(crate) struct UplinkFlows {
    pub(crate) flows: SessionFlows,
    /// Connection epoch the current `flows` belong to.
    pub(crate) epoch: u64,
    /// One-slot memo of the binding the last uplink datagram used.
    ///
    /// A steady association sends to the same target it used microseconds ago:
    /// without the memo that hit cost a linear scan of [`UplinkFlows::flows`]
    /// (one probe per slot until the match, plus the matched `Arc<FlowBinding>`
    /// clone and its drop) on *every* datagram. The memo turns the common hit
    /// into one `TargetAddrRef` compare plus the state load the caller needs
    /// anyway. Set only when the slot is empty, so a steady flow pays zero
    /// extra allocations; invalidated by any reset below and by a miss (the
    /// next ensure re-derives it the normal way). A memo binding whose `state`
    /// became `Closed` fails the check here, so a later `FLOW_CLOSE`/session
    /// teardown is honoured even though the registry side already dropped it.
    pub(crate) last: Option<(TargetAddr, Arc<FlowBinding>)>,
}

impl UplinkFlows {
    pub(crate) fn new() -> Self {
        Self {
            flows: SessionFlows::new(),
            epoch: 0,
            last: None,
        }
    }

    /// Re-align the association's bindings with the connection generation of
    /// `rev2` (and with a server-side `SESS_CLOSE` for this session).
    ///
    /// A redial invalidates every binding: ids are connection-scoped and the
    /// new connection starts with an empty registry, so the association must
    /// re-`OPEN` its targets on the new wire. Payloads still queued on the old
    /// connection's stager travel with that connection — it accounts them when
    /// it is torn down; this association never clears another session's items.
    /// A server `SESS_CLOSE` means the same for this session even on a live
    /// connection (the server reaped the session; a steady frame would name ids
    /// it no longer holds), so the bindings are also removed from the registry
    /// and forgotten.
    pub(crate) fn sync(&mut self, rev2: &ConnRev2, sess: u32) {
        if self.epoch != rev2.epoch {
            self.flows = SessionFlows::new();
            self.epoch = rev2.epoch;
            self.last = None;
            counters::flow_table_reset();
            return;
        }
        if rev2.take_session_closed(sess) {
            for b in self.flows.iter() {
                b.mark_closed();
                let _ = rev2.registry.remove(b.wire_id);
            }
            self.flows = SessionFlows::new();
            self.last = None;
            counters::session_reset();
        }
    }
}

/// Uplink one SOCKS5 UDP payload of any size on the MQP-3 rev2 wire.
///
/// Small payloads (at most [`BATCH_SMALL_MAX`]) are pushed into the
/// **connection's** [`R2Stager`] instead of being sent here:
///
/// * binding `Open` → [`R2StageKind::Steady`] (can share a cross-session
///   `TRAIN dict` with other associations' items);
/// * binding `Opening` → [`R2StageKind::Open`] (standalone `DATA OPEN` until
///   the ack arrives; idempotent server-side);
/// * no flow id (table full / id space exhausted) → [`R2StageKind::Inline`]
///   (standalone `DATA INLINE`, the self-describing fail-safe).
///
/// The burst-end drain ([`drain_assoc_stage`]) is what actually writes them, so
/// a drain burst of one association still costs one DATAGRAM per packed run and
/// several associations' queued items share it. An opportunistic drain fires
/// when the connection queue reaches one full train's worth of items, which is
/// where cross-session items meet and which bounds the queue when an
/// association's burst is interrupted. A full queue is drained once and the
/// push retried; a still-full queue books `BUFFER_FULL` for this payload.
///
/// A payload above the staging cap is never queued (one large item would turn
/// one lost datagram into a lost run): the connection queue is drained first so
/// a session's earlier small payloads keep their order, then the payload goes
/// out as one `DATA` frame or [`R2Fragmenter`] frames, exactly as in Phase 1b.
/// The legacy MQP-2 fragmenter is not used on this path at all.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_uplink(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    bind: UdpBind,
    rev2: &ConnRev2,
    up: &mut UplinkFlows,
    frag: &mut R2Fragmenter,
) -> PayloadSend {
    // The queue is connection-scoped, so the caller's egress binding is not
    // consulted for scheduling here; it stays in the signature because the
    // caller derives `limit`/class policy from it and Phase-2 per-class quotas
    // (spec §7.2/§2.3) key on it.
    let _ = bind;
    up.sync(rev2, sess);
    let limit = rev2.frame_limit(limit);
    // An address that cannot be encoded can never be put on the wire. The
    // legacy fragmenter reported exactly this as a `TooLarge` drop and that is
    // still the right accounting (the app chose an impossible target).
    if addr.header().is_err() {
        let drained = drain_conn_stage(rev2, conn, limit);
        return prefer_severe(drained, bad_address_header());
    }
    let Some(binding) = ensure_binding(rev2, up, sess, addr) else {
        counters::inline_fallback();
        if payload.len() > BATCH_SMALL_MAX {
            let drained = drain_conn_stage(rev2, conn, limit);
            return prefer_severe(
                drained,
                send_standalone(conn, limit, sess, addr, payload, None, frag),
            );
        }
        let item = R2StageItem {
            session: sess,
            kind: R2StageKind::Inline {
                sess,
                addr: addr.into_owned(),
                src: false,
            },
            payload: Bytes::copy_from_slice(payload),
        };
        return stage_or_count(rev2, conn, limit, item);
    };
    if payload.len() <= BATCH_SMALL_MAX {
        let kind = if binding.is_open() {
            R2StageKind::Steady {
                wire_id: binding.wire_id,
            }
        } else {
            R2StageKind::Open {
                wire_id: binding.wire_id,
                sess,
                addr: addr.into_owned(),
                src: false,
            }
        };
        let item = R2StageItem {
            session: sess,
            kind,
            payload: Bytes::copy_from_slice(payload),
        };
        return stage_or_count(rev2, conn, limit, item);
    }
    // Larger than one staged item: drain the connection queue first so this
    // standalone payload cannot overtake a session's earlier small payloads.
    let drained = drain_conn_stage(rev2, conn, limit);
    prefer_severe(
        drained,
        send_standalone(conn, limit, sess, addr, payload, Some(&binding), frag),
    )
}

/// Push one staged item, draining once if the queue is full.
///
/// Returns a "queued" [`PayloadSend`] (`frames: 1`, no failure) on success so
/// the shared recovery path stays quiet; a drain verdict reached while making
/// room is still propagated (a dead connection must invalidate the egress
/// cache even though this payload was queued for the next drain).
fn stage_or_count(
    rev2: &ConnRev2,
    conn: &quinn::Connection,
    limit: usize,
    item: R2StageItem,
) -> PayloadSend {
    let mut item = item;
    let mut drained = PayloadSend {
        frames: 0,
        failed: None,
    };
    for attempt in 0..2 {
        match rev2.push_stage(item) {
            Ok(queued) => {
                counters::stage_push();
                // Opportunistic drain at one train's worth of queued items:
                // cross-session items meet here, and the queue stays bounded
                // even when the pushing association's burst is interrupted.
                // The push call itself now returns the post-push length, so
                // this no longer pays a second lock acquisition for the read.
                if queued >= r2::R2_MAX_TRAIN_ITEMS {
                    drained = prefer_severe(drained, drain_conn_stage(rev2, conn, limit));
                }
                return match drained.failed {
                    None => PayloadSend {
                        frames: 1,
                        failed: None,
                    },
                    Some(other) => PayloadSend {
                        frames: drained.frames,
                        failed: Some(other),
                    },
                };
            }
            Err(back) => {
                item = back;
                if attempt == 0 {
                    counters::stage_full();
                    drained = prefer_severe(drained, drain_conn_stage(rev2, conn, limit));
                }
            }
        }
    }
    // Still full after a drain: the payload is dropped and accounted with the
    // same verdict a full DATAGRAM send buffer produces — unless the drain saw
    // a more severe verdict (a dead connection), which the caller must still
    // act on.
    let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
    warn_stage_full(n);
    PayloadSend {
        frames: drained.frames,
        failed: drained.failed.or(Some(DatagramSend::Blocked)),
    }
}

/// Drain the connection's queued payloads onto `conn` and map the verdict.
fn drain_conn_stage(rev2: &ConnRev2, conn: &quinn::Connection, limit: usize) -> PayloadSend {
    map_drain_outcome(rev2.drain_stage(conn, limit))
}

/// Translate one [`R2DrainOutcome`] into the association's `PayloadSend`.
///
/// The stager has already booked per-payload/fragment/failure counters, so this
/// only records the client-visible drain counters: propagating a
/// `ConnectionLost`/`Unsupported` verdict is what keeps the egress cache honest
/// (the shared recovery invalidates it); `Blocked`/`TooLarge` are propagated
/// for the size/budget recovery arms as before (they book nothing extra there).
fn map_drain_outcome(out: R2DrainOutcome) -> PayloadSend {
    counters::stage_drains();
    for _ in 0..out.frames {
        counters::stage_frames();
    }
    for _ in 0..out.items_sent {
        counters::stage_items();
    }
    for _ in 0..out.items_dropped {
        counters::stage_drop();
    }
    PayloadSend {
        frames: out.frames.min(u32::from(u8::MAX)) as u8,
        failed: out.failed,
    }
}

/// Rate-limited warning for a payload dropped because the connection's stage
/// queue stayed full after a drain (the app controls the rate).
fn warn_stage_full(total: u64) {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).is_some() {
        tracing::warn!(
            "udp datagram dropped: connection stage queue full after a drain ({total} so far)"
        );
    }
}

/// Send `payload` as a standalone rev2 payload: one `DATA` frame when it fits
/// the live limit, `FRAG` frames otherwise.
///
/// `flow` is the binding the payload belongs to, or `None` for the `INLINE`
/// fail-safe. A `Blocked`/`TooLarge` single-frame verdict is retried as
/// fragments — the payload still has to be delivered and no legacy frame may be
/// emitted — while `ConnectionLost`/`Unsupported` are returned for the caller's
/// shared recovery.
fn send_standalone(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    flow: Option<&Arc<FlowBinding>>,
    frag: &mut R2Fragmenter,
) -> PayloadSend {
    if let Some(sent) = try_single_data(conn, limit, sess, addr, payload, flow)
        && (sent.complete()
            || !matches!(
                sent.failed,
                Some(DatagramSend::Blocked | DatagramSend::TooLarge)
            ))
    {
        return sent;
    }
    let frag_flow = match flow {
        Some(binding) if binding.is_open() => R2FragFlow::Steady {
            wire_id: binding.wire_id,
        },
        Some(binding) => R2FragFlow::Opening {
            wire_id: binding.wire_id,
            sess,
            addr: *addr,
            src: false,
        },
        None => R2FragFlow::Inline {
            sess,
            addr: *addr,
            src: false,
        },
    };
    let sent = frag.send(conn, limit, &frag_flow, payload);
    if sent.complete() {
        counters::frag_tx();
    }
    sent
}

/// Try to encode and send `payload` as exactly one `DATA` frame.
///
/// `None` means the encoder refused because the frame would not fit the live
/// limit (the caller then fragments); `Some` carries the send verdict, which
/// may itself be `Blocked`/`TooLarge` when the path budget shrank under the
/// limit this encoding used.
fn try_single_data(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    flow: Option<&Arc<FlowBinding>>,
) -> Option<PayloadSend> {
    let open = flow.is_some_and(|b| !b.is_open());
    let body = match flow {
        Some(binding) if binding.is_open() => {
            r2::encode_data_steady(binding.wire_id, payload, limit)?
        }
        Some(binding) => r2::encode_data_open(binding.wire_id, sess, addr, false, payload, limit)?,
        None => r2::encode_data_inline(sess, addr, false, payload, limit)?,
    };
    Some(match try_send_datagram(conn, body) {
        DatagramSend::Sent => {
            udp_stats::payload(payload.len());
            match flow {
                Some(_) if open => counters::open_tx(),
                Some(_) => counters::steady_tx(),
                None => counters::inline_tx(),
            }
            PayloadSend {
                frames: 1,
                failed: None,
            }
        }
        other => PayloadSend {
            frames: 0,
            failed: Some(other),
        },
    })
}

/// Accounting for a payload whose address cannot be encoded.
///
/// The same single `TOO_LARGE` drop the legacy fragmenter booked for a "bad
/// address header", plus a rate-limited warning: the app controls this rate, so
/// an unthrottled line here would let it turn one malformed target into a
/// logging flood.
fn bad_address_header() -> PayloadSend {
    let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).is_some() {
        tracing::warn!(
            "udp datagram dropped: the SOCKS5 address form cannot encode the target ({n} so far)"
        );
    }
    PayloadSend {
        frames: 0,
        failed: Some(DatagramSend::TooLarge),
    }
}

/// Find the binding for `addr`, opening a new flow when needed.
///
/// Returns `None` when the frame must be sent `INLINE`: no id left, the
/// connection registry is full, the session table is full, or the target is
/// inside a `FLOW_REJECT` window (the spec's fail-safe). A `Closed` binding for
/// the target is forgotten first: its id cannot be reused on this connection,
/// so the target gets a fresh one.
///
/// The association's one-slot memo (`UplinkFlows::last`) serves the steady
/// hit — same target, same live binding — without the per-slot scan and the
/// extra `Arc` clone/drop of a `SessionFlows::find`.
///
/// Everything past the memo miss is ordered cheapest-and-most-decisive first:
/// the session-table scan, the full-table fail-safe, the rejection window
/// (checked *before* any registry scan so a rejected target never pays the
/// connection-wide map walk on every payload of its window), the connection
/// registry's capacity probe (a full table can only fall back to `INLINE`,
/// so the server-owned-flow scan is skipped), then that scan, and finally the
/// atomic allocate-and-insert. [`FlowRegistry::insert_new`] re-checks capacity
/// under its write lock before allocating an id, so a table that fills between
/// the probe and the insert still cannot consume one: ids are never reused, and
/// such a leak would eventually force every payload to `INLINE`.
fn ensure_binding(
    rev2: &ConnRev2,
    up: &mut UplinkFlows,
    sess: u32,
    addr: &TargetAddrRef<'_>,
) -> Option<Arc<FlowBinding>> {
    if let Some((cached_addr, cached)) = &up.last
        && cached_addr.as_ref() == *addr
        && cached.session == sess
        && cached.state() != FlowState::Closed
    {
        return Some(cached.clone());
    }
    up.last = None;
    let flows = &mut up.flows;
    if let Some(existing) = flows.find(addr) {
        if existing.state() != FlowState::Closed {
            up.last = Some((addr.into_owned(), existing.clone()));
            return Some(existing);
        }
        let _ = flows.remove(existing.wire_id);
        let _ = rev2.registry.remove(existing.wire_id);
    }
    if flows.is_full() {
        return None;
    }
    // A rejected target stays `INLINE` for the TTL: re-opening it would cost
    // one rejected frame plus one lost payload per payload (see
    // [`REJECT_TTL_MS`]). Checked before any registry scan: the rejection is
    // the expected outcome for every payload of the window, so nothing can be
    // bound for it and the scans below could only waste work. `is_rejected` is
    // itself read-mostly (it takes the write lock only to prune expired
    // entries).
    if rev2.is_rejected(addr, coarse_millis()) {
        return None;
    }
    // A full connection registry means no flow can be bound: `INLINE` is the
    // only possible outcome, so skip the server-owned-flow scan (a full table
    // is exactly when that scan is longest). Advisory only — `insert_new`
    // re-checks the cap under its write lock and stays the authority.
    if !rev2.registry.has_capacity() {
        return None;
    }
    // Full-cone symmetry: the server may already own a flow for this exact
    // (session, target) — it announced it with `DATA OPEN|SRC` and the
    // dispatcher installed it. Reuse that id so the app's reply rides the same
    // flow (steady/stager/fragment encoders carry the owner bit already)
    // instead of opening a parallel client-owned one. The binding is already in
    // the registry, so it is never inserted again.
    if let Some(server) = rev2.registry.find_server_flow(sess, addr) {
        // Only a confirmed server-owned flow is reusable: it was announced by
        // an `OPEN|SRC` (which the dispatcher marks open), so steady/stager
        // frames are safe. Anything else falls through to a fresh client flow.
        if server.is_open() {
            if flows.insert(server.clone()) {
                counters::server_flow_reuse();
                up.last = Some((addr.into_owned(), server.clone()));
                return Some(server);
            }
            // Per-association table full: the documented INLINE fail-safe.
            return None;
        }
        if server.state() == FlowState::Closed {
            let _ = rev2.registry.remove(server.wire_id);
        }
    }
    // One write-lock hold: capacity re-check, id allocation, insert. An id
    // allocated before a refused insert would be lost for the connection's
    // life (wire ids are never reused).
    let binding = rev2
        .registry
        .insert_new(&rev2.ids, sess, addr.into_owned())
        .ok()?;
    if !flows.insert(binding.clone()) {
        let _ = rev2.registry.remove(binding.wire_id);
        return None;
    }
    counters::flow_open();
    up.last = Some((addr.into_owned(), binding.clone()));
    Some(binding)
}

/// Drain the connection's staged payloads at an association boundary: the end
/// of a recv burst, before a large standalone send, and on association exit
/// before `SESS_CLOSE`.
///
/// The queue is connection-scoped, so this drains **every** session's queued
/// items (that is the Phase-2 aggregation); a verdict is fed through the same
/// shared recovery the per-datagram path uses. When no egress connection is
/// available the items stay queued for the next drain: one association must
/// never clear another session's payloads, and a genuinely dead connection
/// accounts them at teardown (`ConnRev2::clear_stage` / the stager's `Drop`).
pub(crate) fn drain_assoc_stage(egress: &SharedEgress, pool: &ConnPool, bind: UdpBind) {
    let now = coarse_millis();
    let drained = egress.with_fresh(bind, now, |c, limit, rev2| {
        let limit = rev2.frame_limit(limit);
        map_drain_outcome(rev2.drain_stage(c, limit))
    });
    if let Some(sent) = drained {
        recover_send_outcome(egress, bind, sent);
        return;
    }
    // Generation read before the cached read, the same contract the
    // per-datagram miss path documents.
    let generation = egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    if let Some(h) = egress.acquire(pool, bind, now) {
        egress.memo_store(bind, generation, &h.conn, h.limit, h.stamp_ms, &h.rev2);
        let limit = h.rev2.frame_limit(h.limit);
        let sent = map_drain_outcome(h.rev2.drain_stage(&h.conn, limit));
        recover_send_outcome(egress, bind, sent);
    }
}

/// Client-local MQP-3 rev2 counters.
///
/// Deliberately in the client binary rather than the shared `udp_stats`
/// module: the codec/state slice this task is allowed to touch ends at the
/// client sources, and these counters only exist to answer "is the rev2 path
/// actually being used, and does it fall back" from the 60 s report and the
/// tests.
///
/// Two cost classes. The per-datagram/per-frame data-plane events (`open_tx`,
/// `steady_tx`, `inline_tx`, the `stage_*` family, `frag_*`, `rx_frame`) used
/// to pay one process-wide cache-line RMW *per event* from every relay task
/// and the per-slot dispatcher — the exact cost [`crate::udp_stats::payload`]
/// was converted away from when its counters went thread-local (the comment
/// above used to claim the two were the same class; that claim stopped being
/// true). Those events now accumulate in thread-local cells flushed into the
/// process-wide statics at the [`FLUSH_EVERY`] boundary, so the hot path pays
/// local `Cell` writes and the shared lines move only once per 256 events.
/// Control-plane events (handshake, CTL, unknown-id/refusal accounting) stay
/// direct shared increments: they are rare by definition and several are the
/// regression-test observables.
///
/// Read exactness follows the shipped `udp_stats` model: `snapshot()` /
/// `since()` flush the *caller's* cells first (tests and a reporter running on
/// the counting thread see their own records exactly); a pending count on a
/// *different* thread becomes visible at the next flush boundary instead of
/// immediately, bounded by 256 events — the reporter reads once per 60 s, so
/// the bound matches the existing documented behaviour.
pub(crate) mod counters {
    use std::sync::atomic::{AtomicU64, Ordering};

    macro_rules! rev2_counters {
        ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
            /// One relaxed counter per rev2 event worth reporting.
            #[derive(Debug, Default)]
            pub(crate) struct Rev2Counters {
                $($(#[$doc])* pub(crate) $name: AtomicU64,)*
            }

            /// Process-wide rev2 counters (one client process, one set).
            pub(crate) static COUNTERS: Rev2Counters = Rev2Counters {
                $($name: AtomicU64::new(0),)*
            };

            /// One read of every counter.
            #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
            pub(crate) struct Rev2Snapshot {
                $(pub(crate) $name: u64,)*
            }

            impl Rev2Snapshot {
                fn now() -> Self {
                    // Flush the caller's pending batch first: reporter and
                    // tests read on the collecting thread.
                    flush_locals();
                    Self {
                        $($name: COUNTERS.$name.load(Ordering::Relaxed),)*
                    }
                }
            }

            /// Subtracting read of every counter, saturating so a reset can
            /// never panic the reporter.
            pub(crate) fn since(prev: &Rev2Snapshot) -> Rev2Snapshot {
                let now = Rev2Snapshot::now();
                Rev2Snapshot {
                    $($name: now.$name.saturating_sub(prev.$name),)*
                }
            }
        };
    }

    macro_rules! rev2_counter_fns_direct {
        ($($name:ident),* $(,)?) => {
            $(
                #[inline]
                pub(crate) fn $name() {
                    COUNTERS.$name.fetch_add(1, Ordering::Relaxed);
                }
            )*
        };
    }

    macro_rules! rev2_counter_fns_tls {
        ($($name:ident),* $(,)?) => {
            /// Pending counts for the data-plane counters, per thread.
            #[derive(Debug, Default)]
            struct Rev2Locals {
                $($name: std::cell::Cell<u64>,)*
            }

            thread_local! {
                static LOCALS: Rev2Locals = Rev2Locals::default();
            }

            fn flush_locals() {
                LOCALS.with(|l| {
                    $(
                        let v = l.$name.get();
                        if v != 0 {
                            COUNTERS.$name.fetch_add(v, Ordering::Relaxed);
                            l.$name.set(0);
                        }
                    )*
                });
            }

            $(
                #[inline]
                pub(crate) fn $name() {
                    LOCALS.with(|l| {
                        let v = l.$name.get().wrapping_add(1);
                        if v >= FLUSH_EVERY {
                            COUNTERS.$name.fetch_add(v, Ordering::Relaxed);
                            l.$name.set(0);
                        } else {
                            l.$name.set(v);
                        }
                    });
                }
            )*
        };
    }

    rev2_counters! {
        /// `CTL HELLO` datagrams queued.
        hello_tx,
        /// Handshakes that reached `CAPS(wire_ver=2)`.
        handshake_ok,
        /// Handshakes that failed (no CAPS, wrong wire version, dead connection).
        handshake_fail,
        /// `CTL CAPS` frames decoded.
        caps_rx,
        /// `CTL FLOW_ACK` frames that resolved an uplink binding.
        flow_ack_rx,
        /// `CTL FLOW_REJECT` frames that closed an uplink binding.
        flow_reject_rx,
        /// `CTL FLOW_CLOSE` frames that closed a binding.
        flow_close_rx,
        /// `CTL SESS_CLOSE` frames decoded (from the server).
        sess_close_rx,
        /// `CTL SESS_CLOSE` frames queued (association exit).
        sess_close_tx,
        /// New uplink flows bound on this process's connections.
        flow_open,
        /// Server-owned flows accepted from a downlink `DATA OPEN|SRC`
        /// (full-cone / unsolicited reply).
        server_flow_accept,
        /// Uplink payloads that reused an accepted server-owned flow id.
        server_flow_reuse,
        /// `DATA OPEN` frames queued.
        open_tx,
        /// Steady `DATA` frames queued.
        steady_tx,
        /// `DATA INLINE` frames queued (fail-safe path).
        inline_tx,
        /// Payloads that had to fall back to `INLINE` because no flow could be
        /// bound (id space, registry or session table full).
        inline_fallback,
        /// Small payloads queued into the connection stager.
        stage_push,
        /// Connection-stager drain calls.
        stage_drains,
        /// DATAGRAM frames written by stager drains (a train counts once).
        stage_frames,
        /// Payloads booked as sent by stager drains.
        stage_items,
        /// Queued payloads the stager discarded (live path budget gone).
        stage_drop,
        /// Pushes that found the queue full and had to drain before retrying.
        stage_full,
        /// Payloads sent as rev2 `FRAG` (fragmented) frames.
        frag_tx,
        /// Rev2 `FRAG` frames decoded from the downlink.
        frag_rx,
        /// Rev2 fragmented payloads fully reassembled and staged.
        frag_complete,
        /// Compressed downlink `DATA`/`TRAIN` frames decoded (implicit ACK).
        rx_frame,
        /// Downlink frames/train items whose wire id was not installed here.
        rx_unknown_id,
        /// Downlink frames dropped as malformed/refused.
        rx_drop,
        /// Flow tables reset because the connection generation changed.
        flow_table_reset,
        /// Flow tables reset because the server sent `SESS_CLOSE`.
        session_reset,
        /// `CTL` frames dropped as malformed/unknown.
        ctl_drop,
    }

    /// Thread-local flush threshold for the data-plane counters: the hot path
    /// touches the shared line once instead of once per event (same bound the
    /// `udp_stats` reporter documents).
    const FLUSH_EVERY: u64 = 256;

    impl Rev2Snapshot {
        /// Whether nothing happened in the window (the reporter stays silent).
        pub(crate) fn is_idle(&self) -> bool {
            *self == Rev2Snapshot::default()
        }
    }

    /// Snapshot for the reporter and tests.
    pub(crate) fn snapshot() -> Rev2Snapshot {
        Rev2Snapshot::now()
    }

    // Data-plane hot counters (per uplink payload / per downlink frame / per
    // drained drain): thread-local cells, flushed into the shared statics at
    // `FLUSH_EVERY`. None of these is a regression-test observable read on a
    // different thread, which is what keeps cross-thread reads exact.
    rev2_counter_fns_tls! {
        steady_tx,
        stage_push,
        stage_drains,
        stage_frames,
        stage_items,
        frag_tx,
        frag_rx,
        frag_complete,
        rx_frame,
    }

    // Control-plane / test-observable counters: direct shared increments, the
    // exact cross-thread one-per-event cost the tests rely on.
    rev2_counter_fns_direct! {
        hello_tx,
        handshake_ok,
        handshake_fail,
        caps_rx,
        flow_ack_rx,
        flow_reject_rx,
        flow_close_rx,
        sess_close_rx,
        sess_close_tx,
        // Per-flow / queue-exception events: too rare for a TLS cell to reach
        // its flush boundary, so a direct increment is both simpler and exact.
        open_tx,
        inline_tx,
        stage_drop,
        stage_full,
        flow_open,
        server_flow_accept,
        server_flow_reuse,
        inline_fallback,
        rx_unknown_id,
        rx_drop,
        flow_table_reset,
        session_reset,
        ctl_drop,
    }

    impl std::fmt::Display for Rev2Snapshot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "hello={} handshake={}/{} caps={} frames_rx={} ack={} reject={} close={} \
                 sess_close={}/{} flow_open={} srv={}/{} open={} steady={} inline={}/{} \
                 stage={}p/{}d/{}f/{}i/{}x/{}full frag={}/{}/{} unknown_id={} drops={} \
                 resets={}/{}",
                self.hello_tx,
                self.handshake_ok,
                self.handshake_fail,
                self.caps_rx,
                self.rx_frame,
                self.flow_ack_rx,
                self.flow_reject_rx,
                self.flow_close_rx,
                self.sess_close_rx,
                self.sess_close_tx,
                self.flow_open,
                self.server_flow_accept,
                self.server_flow_reuse,
                self.open_tx,
                self.steady_tx,
                self.inline_tx,
                self.inline_fallback,
                self.stage_push,
                self.stage_drains,
                self.stage_frames,
                self.stage_items,
                self.stage_drop,
                self.stage_full,
                self.frag_tx,
                self.frag_rx,
                self.frag_complete,
                self.rx_unknown_id,
                self.rx_drop,
                self.flow_table_reset,
                self.session_reset,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_not_ready_and_allocates_client_ids() {
        let r = ConnRev2::new();
        assert!(!r.is_ready());
        assert!(r.ctl.caps().is_none());
        let a = r.ids.alloc().unwrap();
        assert!(!r2::wire_id_server_owned(a));
        assert_eq!(r2::wire_id_local(a), 1);
        assert_ne!(r.epoch, ConnRev2::new().epoch);
    }

    #[test]
    fn caps_make_the_connection_ready_and_store_limits() {
        let r = ConnRev2::new();
        r.on_caps(r2::Caps {
            wire_ver: r2::R2_WIRE_VER,
            max_train_items: 8,
            ..r2::Caps::default()
        });
        assert!(r.is_ready());
        assert_eq!(
            r.ctl.caps(),
            Some(r2::Caps {
                wire_ver: r2::R2_WIRE_VER,
                max_train_items: 8,
                ..r2::Caps::default()
            })
        );
    }

    #[test]
    fn wrong_wire_version_never_becomes_ready() {
        let r = ConnRev2::new();
        r.on_caps(r2::Caps {
            wire_ver: 9,
            ..r2::Caps::default()
        });
        assert!(!r.is_ready());
        assert_eq!(r.ctl.caps().map(|c| c.wire_ver), Some(9));
    }

    #[test]
    fn closed_sessions_are_bounded_and_consumed_once() {
        let r = ConnRev2::new();
        assert!(!r.take_session_closed(7));
        r.note_session_closed(7);
        assert!(r.take_session_closed(7));
        assert!(!r.take_session_closed(7));
        for s in 0..(MAX_CLOSED_SESSIONS as u32 * 3) {
            r.note_session_closed(s);
        }
        let mut hits = 0;
        for s in 0..(MAX_CLOSED_SESSIONS as u32 * 3) {
            if r.take_session_closed(s) {
                hits += 1;
            }
        }
        assert!(hits <= MAX_CLOSED_SESSIONS, "the set must stay bounded");
    }

    #[test]
    fn inline_fallback_when_registry_is_full() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        // Fill the connection registry by hand (its cap is the shared default).
        // The filler target differs from `addr`: ids are allocated from 1, so
        // the id `ensure_binding` tries would otherwise collide with a filler
        // entry for the same `(session, target)` and be accepted as the
        // idempotent duplicate-open case instead of hitting the full-table
        // fail-safe.
        let filler = TargetAddr::Ip("203.0.113.7:9".parse().unwrap());
        for i in 1..=R2_MAX_FLOWS_PER_CONN as u32 {
            let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 2, filler.clone());
            assert!(r.registry.insert(b).is_ok());
        }
        assert!(
            ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).is_none(),
            "a full registry must fall back to INLINE"
        );
        assert!(up.flows.is_empty());
        // The fail-safe must not consume a never-reused wire id: capacity is
        // checked before allocation.
        assert_eq!(r.ids.allocated(), 0, "a full registry must not leak ids");
    }

    /// A persistently full connection registry keeps taking new targets (the
    /// `INLINE` fail-safe): every attempt must cost zero ids, or the finite
    /// id space would eventually run dry and force `INLINE` even after the
    /// table drains.
    #[test]
    fn full_registry_never_consumes_flow_ids() {
        let r = ConnRev2::new();
        let filler = TargetAddr::Ip("203.0.113.7:9".parse().unwrap());
        for i in 1..=R2_MAX_FLOWS_PER_CONN as u32 {
            let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 2, filler.clone());
            assert!(r.registry.insert(b).is_ok());
        }
        assert!(!r.registry.has_capacity());
        let mut up = UplinkFlows::new();
        for i in 0..64u16 {
            let addr = SocketAddr::from(([198, 51, 100, 9], 4000 + i));
            assert!(
                ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).is_none(),
                "a full registry keeps falling back to INLINE"
            );
        }
        assert_eq!(
            r.ids.allocated(),
            0,
            "repeated new-target attempts against a full table must not leak ids"
        );
        assert!(up.flows.is_empty(), "no half-bound session entries either");
    }

    /// A target inside a `FLOW_REJECT` window takes the `INLINE` fail-safe: the
    /// decision must be made before the registry scans and must not allocate an
    /// id.
    #[test]
    fn rejected_target_path_consumes_no_id() {
        let r = ConnRev2::new();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        r.note_rejected(TargetAddr::Ip(addr), coarse_millis());
        let mut up = UplinkFlows::new();
        assert!(
            ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).is_none(),
            "a rejected target must fall back to INLINE"
        );
        assert_eq!(
            r.ids.allocated(),
            0,
            "the rejection short-circuit must not consume an id"
        );
        assert!(
            r.is_rejected(&TargetAddrRef::Ip(addr), coarse_millis()),
            "the live rejection window is unchanged by the probe"
        );
    }

    /// The read-lock fast path must never prune a live entry; expired entries
    /// are pruned exactly when the TTL makes the answer `false`.
    #[test]
    fn is_rejected_fast_path_keeps_live_entries_and_prunes_expired() {
        let r = ConnRev2::new();
        let a = TargetAddr::Ip("198.51.100.1:1".parse().unwrap());
        let b = TargetAddr::Ip("198.51.100.2:2".parse().unwrap());
        r.note_rejected(a.clone(), 1_000);
        r.note_rejected(b.clone(), 1_000);
        // Both windows are live: the probe answers from the shared lock and
        // leaves the table untouched.
        assert!(r.is_rejected(&a.as_ref(), 2_000));
        assert!(r.is_rejected(&b.as_ref(), 2_000));
        assert_eq!(r.rejected.read().len(), 2, "a live probe prunes nothing");
        // One TTL later both entries are expired: the probe upgrades to the
        // write lock, prunes them and answers `false`.
        assert!(!r.is_rejected(&a.as_ref(), 1_000 + REJECT_TTL_MS));
        assert_eq!(r.rejected.read().len(), 0, "expired entries are pruned");
    }

    #[test]
    fn closed_binding_is_reopened_with_a_fresh_id() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let first = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert_eq!(first.state(), FlowState::Opening);
        first.mark_closed();
        let second = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert_ne!(first.wire_id, second.wire_id);
        assert_eq!(up.flows.len(), 1);
        assert!(r.registry.get(first.wire_id).is_none());
        assert!(r.registry.get(second.wire_id).is_some());
    }

    #[test]
    fn uplink_sync_resets_on_epoch_change() {
        let mut up = UplinkFlows::new();
        let r1 = ConnRev2::new();
        up.sync(&r1, 7);
        assert_eq!(up.epoch, r1.epoch);
        let r2 = ConnRev2::new();
        up.sync(&r2, 7);
        assert_eq!(up.epoch, r2.epoch);
        assert!(up.flows.is_empty());
    }

    #[test]
    fn uplink_memo_serves_the_steady_target_without_a_second_binding() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let first = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        // The steady hit: same association, same target, live binding — served
        // by the one-slot memo, never re-scanned into a new binding.
        let second = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "the memo serves the same Arc");
        assert_eq!(up.flows.len(), 1, "no second binding was created");
        // A different target misses the memo (it holds only one slot): the
        // normal path opens the second target, and going back re-derives the
        // first one by id equality — no re-OPEN, no id change.
        let other: SocketAddr = "198.51.100.10:4242".parse().unwrap();
        let third = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(other)).unwrap();
        assert_ne!(third.wire_id, first.wire_id);
        let back = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert_eq!(
            back.wire_id, first.wire_id,
            "the scan re-finds the first flow"
        );
        assert_eq!(up.flows.len(), 2);
        // The memo slot now holds the first binding again. Close it as a late
        // `FLOW_CLOSE` would: the next call must fail the memo state check and
        // reopen a *fresh* binding, never serve the closed one.
        first.mark_closed();
        let after_close = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert_ne!(
            after_close.wire_id, first.wire_id,
            "a closed memo binding is not served"
        );
        assert_eq!(
            up.flows.len(),
            2,
            "the dead slot was replaced, not appended"
        );
        // An epoch reset drops the memo with the flow table.
        let r2 = ConnRev2::new();
        up.sync(&r2, 1);
        assert!(up.last.is_none(), "redial invalidates the memo");
    }

    #[test]
    fn conn_stager_queues_and_clear_accounts_each_item() {
        let r = ConnRev2::with_stager_capacity(4, 4096);
        let before = dgram_drops::snapshot();
        for i in 1..=3u32 {
            let item = R2StageItem {
                session: 1,
                kind: R2StageKind::Steady {
                    wire_id: r2::make_wire_id(i, false).unwrap(),
                },
                payload: Bytes::from_static(b"payload"),
            };
            assert!(r.push_stage(item).is_ok());
        }
        assert_eq!(r.stage_len(), 3);
        assert!(format!("{r:?}").contains("stage_len: 3"));
        assert_eq!(r.clear_stage(), 3);
        assert_eq!(r.stage_len(), 0);
        assert!(
            dgram_drops::snapshot().since(&before).egress_dead >= 3,
            "teardown must account every queued payload as an egress death"
        );
    }

    #[test]
    fn conn_stager_drop_accounts_remaining_items() {
        let before = dgram_drops::snapshot();
        {
            let r = ConnRev2::with_stager_capacity(4, 4096);
            for i in 1..=2u32 {
                let item = R2StageItem {
                    session: 7,
                    kind: R2StageKind::Steady {
                        wire_id: r2::make_wire_id(i, false).unwrap(),
                    },
                    payload: Bytes::from_static(b"x"),
                };
                assert!(r.push_stage(item).is_ok());
            }
            // Last Arc goes away with the items still queued: the stager's
            // `Drop` is the backstop that accounts them.
        }
        assert!(
            dgram_drops::snapshot().since(&before).egress_dead >= 2,
            "dropping a connection must not lose queued payloads silently"
        );
    }

    #[test]
    fn rejected_target_falls_back_to_inline_until_the_ttl() {
        let r = ConnRev2::new();
        let now = coarse_millis();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let mut up = UplinkFlows::new();
        let first = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        first.mark_open();
        // A reject closes the flow and arms the target's INLINE window.
        first.mark_closed();
        let _ = r.registry.remove(first.wire_id);
        r.note_rejected(TargetAddr::Ip(addr), now);
        assert!(r.is_rejected(&TargetAddrRef::Ip(addr), now));
        assert!(
            ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).is_none(),
            "a rejected target must fall back to INLINE inside the TTL"
        );
        // The window is TTL-wide; a probe at the TTL boundary expires it (that
        // probe uses the wall clock in production, so pruning is exact).
        assert!(r.is_rejected(&TargetAddrRef::Ip(addr), now + REJECT_TTL_MS - 1));
        assert!(
            !r.is_rejected(&TargetAddrRef::Ip(addr), now + REJECT_TTL_MS),
            "the rejection expires after the TTL"
        );
        // Expire the entry as the wall clock would, then the next payload
        // retries a fresh OPEN with a new (never reused) id.
        r.rejected.write().clear();
        let retried = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        assert_ne!(retried.wire_id, first.wire_id, "an id is never reused");
        assert_eq!(
            up.flows.len(),
            1,
            "the retried flow replaced the dead binding"
        );
        assert!(r.registry.get(retried.wire_id).is_some());
    }

    #[test]
    fn rejected_target_set_is_bounded() {
        let r = ConnRev2::new();
        for i in 0..(MAX_REJECTED_TARGETS as u16 * 2) {
            let a = SocketAddr::from(([203, 0, 113, 9], 4000 + i));
            r.note_rejected(TargetAddr::Ip(a), 0);
        }
        let live = r.rejected.read().len();
        assert_eq!(live, MAX_REJECTED_TARGETS, "the set stays bounded");
        // Re-rejecting a present target moves its stamp, it does not grow.
        let a = TargetAddr::Ip(SocketAddr::from(([203, 0, 113, 9], 4000)));
        r.note_rejected(a.clone(), 0);
        r.note_rejected(a, 0);
        assert_eq!(r.rejected.read().len(), MAX_REJECTED_TARGETS);
    }

    #[test]
    fn handshake_retry_constants_are_the_documented_budget() {
        assert_eq!(HELLO_RETRY, Duration::from_millis(200));
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(2));
        assert!(HANDSHAKE_TIMEOUT.as_millis() / HELLO_RETRY.as_millis() >= 10);
    }
}
