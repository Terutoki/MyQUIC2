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
use myquic2::mqp::ctl_stream;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{
    CtlState, FlowBinding, FlowIds, FlowRegistry, FlowState, R2_MAX_FLOWS_PER_CONN, SessionFlows,
};
use myquic2::mqp::r3::CtlMessage;
use myquic2::mqp::wire::{self, Wire};
use myquic2::udp::r2_frag::R2FragFlow;
use myquic2::udp::{
    R2DrainOutcome, R2Fragmenter, R2StageItem, R2StageKind, R2Stager, drain_staged,
};
use std::collections::VecDeque;

/// Retry cadence for `CTL HELLO` until `CAPS` arrives.
pub(crate) const HELLO_RETRY: Duration = Duration::from_millis(200);
/// Slow `HELLO` retry cadence once the fast window below has elapsed.
///
/// The server re-sends `CAPS` for a repeated `HELLO` (rate-limited to one per
/// 100 ms), so one more `HELLO` two seconds later recovers a lost `CAPS`
/// without ever taking the connection down (W2).
pub(crate) const HELLO_RETRY_SLOW: Duration = Duration::from_secs(2);
/// Bounded window of the **fast** (`HELLO_RETRY`) `HELLO` cadence.
///
/// It bounds only how long the initial negotiation is retried eagerly; it is
/// not a connection deadline. A missing or late `CAPS` after this window keeps
/// the connection alive and the retry continues in the background at
/// [`HELLO_RETRY_SLOW`] (W2): `CAPS` only tunes limits — the live frame limit
/// falls back to the connection's DATAGRAM budget ([`ConnRev2::frame_limit`])
/// and the stager keeps the codec's train bound — so there is no data-path
/// state that needs it.
pub(crate) const HELLO_FAST_WINDOW: Duration = Duration::from_secs(2);

/// Bounded set of server-closed sessions recorded for an association to
/// consume.
///
/// Only a session with a **live association** is recorded (the dispatcher
/// checks the hub before calling [`ConnRev2::note_session_closed`]) and the
/// association forgets its id when it exits
/// ([`ConnRev2::forget_session_closed`]), so the set only ever holds closes
/// something can still consume and returns to empty in steady state.
///
/// Bounded because a peer controls `SESS_CLOSE`. When the set is full the
/// **oldest** entry is evicted, never the newest: dropping a freshly arrived
/// close would blackhole that live session's traffic (the uplink never learns
/// to re-`OPEN`, and the server already purged its bindings), while evicting
/// an older id at worst makes that association wait for the redial / the
/// server's 180 s sweep.
const MAX_CLOSED_SESSIONS: usize = 64;

/// How long a target the server rejected (`CTL FLOW_REJECT`) is sent `INLINE`
/// before the uplink retries an `OPEN`.
///
/// The spec asks for exactly this fallback: retrying the OPEN on every payload
/// would be a rejected frame plus a lost payload each time, while `INLINE`
/// keeps the association working (the server can still forward a
/// self-describing frame) and re-tests the flow after the TTL.
///
/// The reason selects the window. `TABLE_FULL` and `DNS` are transient state
/// that can clear on its own (a registry slot freed, a resolver recovered), so
/// waiting the policy window would keep a healthy target on `INLINE` long
/// after it could be compressed again. A policy rejection is a stable property
/// of the destination (SSRF/owner/conflict), so retrying it often only burns a
/// rejected frame per second.
const REJECT_TTL_TRANSIENT_MS: u64 = 1_000;
const REJECT_TTL_POLICY_MS: u64 = 30_000;

/// Per-target rejection window for a `FLOW_REJECT` reason.
fn reject_ttl_ms(reason: u8) -> u64 {
    match reason {
        r2::R2_REJECT_TABLE_FULL | r2::R2_REJECT_DNS => REJECT_TTL_TRANSIENT_MS,
        _ => REJECT_TTL_POLICY_MS,
    }
}

/// One target inside a `FLOW_REJECT` window.
#[derive(Debug)]
struct RejectedTarget {
    target: TargetAddr,
    rejected_at_ms: u64,
    ttl_ms: u64,
}

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
    /// Application-layer wire revision of this connection.
    ///
    /// Chosen by configuration + ALPN for the whole connection (never sniffed
    /// from a frame). [`Wire::Rev2`] is the default so every existing
    /// construction keeps the shipped behaviour; rev3 changes the codec, the
    /// no-ACK sender policy and the control plane (see [`Self::new_with_wire`]).
    wire: Wire,
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
    /// optimistically before `CAPS` (Phase 0 removed the pre-HELLO buffer; the
    /// server dispatches frames as they arrive). `CAPS` only replaces the boot
    /// limits with the peer's negotiated caps and enables the peer-advertised
    /// compression limits; a missing/late CAPS is non-fatal, only an explicit
    /// wrong-version CAPS (or a dead connection) closes the dial.
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
    /// Sessions the server closed that an association has still to consume (see
    /// [`MAX_CLOSED_SESSIONS`]).
    ///
    /// The `take` guard is the datagram's very first shared read, and the deque
    /// is empty in steady state (populated only by a `SESS_CLOSE` for a **live**
    /// association, and forgotten when that association exits): the
    /// `closed_len` counter below turns the per-datagram probe into one relaxed
    /// load, and the exclusive write lock is taken only while a close is
    /// actually pending. Deque order is insertion order, i.e. eviction order.
    closed_sessions: parking_lot::RwLock<VecDeque<u32>>,
    /// Live `closed_sessions` length, maintained under the write lock. A stale
    /// *overshoot* is impossible (writes under the lock refresh it last); a
    /// stale zero short-takes one extra payload before the next sync re-checks,
    /// which is ordinary UDP loss. Updated with `Relaxed`: the caller treats
    /// `false` as "not closed on this datagram" and re-checks on the next sync.
    closed_len: std::sync::atomic::AtomicUsize,
    /// Targets the server rejected with `CTL FLOW_REJECT` / rev3 `REJECT`,
    /// with their window start and reason-selected TTL (see
    /// [`REJECT_TTL_TRANSIENT_MS`] / [`REJECT_TTL_POLICY_MS`]).
    rejected: parking_lot::RwLock<Vec<RejectedTarget>>,
    /// rev3 outbound control messages: the generation's control-stream task
    /// owns the stream and accepts messages here (see [`Self::send_ctl`]).
    /// `None` on rev2 and until the dispatcher installs the writer.
    ctl_tx: parking_lot::Mutex<Option<tokio::sync::mpsc::UnboundedSender<CtlMessage>>>,
    /// Sender-side rate budget for `NEED_CONTEXT` repairs: one hostile/broken
    /// peer can otherwise make an unknown-id frame storm turn into a control
    /// stream storm (the receiver-side [`ctl_stream::CtlRate`] bounds the
    /// opposite direction).
    ctx_repair_rate: parking_lot::Mutex<ctl_stream::CtlRate>,
    /// Memo of "this connection's handshake completed" (see
    /// [`Self::is_handshake_done`]). Only rev3 consults it: a payload sent on a
    /// not-yet-handshaked connection is 0-RTT early data whose DATAGRAMs QUIC
    /// may discard wholesale on a rejected resumption, so it must not spend the
    /// no-ACK binding-context budget.
    handshake_done: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for ConnRev2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `R2Stager` is not `Debug`; report the observable queue size instead of
        // the whole primitive.
        f.debug_struct("ConnRev2")
            .field("epoch", &self.epoch)
            .field("wire", &self.wire)
            .field("registry_len", &self.registry.len())
            .field("ids_allocated", &self.ids.allocated())
            .field("ready", &self.is_ready())
            .field("stage_len", &self.stage_len())
            .finish()
    }
}

impl ConnRev2 {
    /// Fresh state for one dial on the shipped rev2 wire.
    ///
    /// This constructor is the unchanged default: [`Wire::Rev2`],
    /// `HELLO`/`CAPS` negotiation, `FLOW_ACK`-gated compression and the CTL
    /// DATAGRAM control plane. The reconnect path selects the configured
    /// revision explicitly through [`Self::new_with_wire`]; this is the
    /// documented rev2 default/rollback entry point, kept for fixtures and the
    /// rollback contract.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new() -> Arc<Self> {
        Self::with_stager(R2Stager::new(), Wire::Rev2)
    }

    /// Fresh state for one dial on `wire`.
    ///
    /// Rev3 has no `HELLO`/`CAPS`: the revision comes from configuration (ALPN
    /// defaults to the shared `h3` label for both revisions, so it is not a
    /// version gate by default) and the caps are the static [`Wire::caps`]
    /// contract, so the state comes up **ready** with the
    /// default frame limit and the codec's own train bound (the data path never
    /// waited for `CAPS` on rev2 either — this merely skips the negotiation).
    /// The stager is constructed for the same wire so every encoded frame matches
    /// the connection.
    // The wiring task (config/ALPN plumbing, client/auth.rs) flips the default
    // constructor to this one; until then only tests exercise the rev3 path, so
    // a non-test client build sees it as unused.
    #[allow(dead_code)]
    pub(crate) fn new_with_wire(wire: Wire) -> Arc<Self> {
        Self::with_stager(R2Stager::new_with_wire(wire), wire)
    }

    /// Test seam: the same state with an explicitly sized stager queue, so a
    /// unit test can provoke the queue-full policy without 1024 pushed items.
    #[cfg(test)]
    pub(crate) fn with_stager_capacity(items: usize, bytes: usize) -> Arc<Self> {
        Self::with_stager(R2Stager::with_capacity(items, bytes), Wire::Rev2)
    }

    fn with_stager(mut stager: R2Stager, wire: Wire) -> Arc<Self> {
        stager.set_wire(wire);
        // rev3's static contract: ready immediately, default frame limit. rev2
        // stays not-ready until `CAPS` (behaviour unchanged).
        let static_caps = wire == Wire::Rev3;
        Arc::new(Self {
            epoch: NEXT_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            wire,
            registry: FlowRegistry::new(R2_MAX_FLOWS_PER_CONN),
            ids: FlowIds::new(false),
            ctl: CtlState::new(),
            ready: std::sync::atomic::AtomicBool::new(static_caps),
            max_frame_bytes: std::sync::atomic::AtomicU16::new(if static_caps {
                r2::R2_DEFAULT_MAX_FRAME_BYTES
            } else {
                0
            }),
            stager: Arc::new(parking_lot::Mutex::new(stager)),
            closed_sessions: parking_lot::RwLock::new(VecDeque::new()),
            closed_len: std::sync::atomic::AtomicUsize::new(0),
            rejected: parking_lot::RwLock::new(Vec::new()),
            ctl_tx: parking_lot::Mutex::new(None),
            ctx_repair_rate: parking_lot::Mutex::new(ctl_stream::CtlRate::default_budget()),
            handshake_done: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Application-layer wire revision of this connection.
    #[must_use]
    pub(crate) fn wire(&self) -> Wire {
        self.wire
    }

    /// Whether `conn`'s QUIC/TLS handshake has completed, memoized once seen.
    ///
    /// rev3 uses this to decide whether a payload may spend a binding's no-ACK
    /// context budget. A payload sent before the handshake completes can ride
    /// as 0-RTT early data, and QUIC **discards** early DATAGRAMs wholesale when
    /// the server rejects early data (a restarted server rejects the
    /// resumption): there is no app-level retransmission. Spending the 2-frame
    /// context budget on such a payload would leave the sender self-confirmed
    /// (`FlowBinding::take_context_slot` marks it open) on a binding the
    /// receiver never installed, so every later payload would be an
    /// unresolvable steady frame — exactly the "held datagram across a server
    /// restart leaves a persistent peer blackholed" regression.
    ///
    /// Once the handshake is known complete this is one relaxed load. Before
    /// that it costs one `quinn::Connection::handshake_data` probe per payload
    /// on the early-data path only (a payload on an open binding never asks);
    /// that path is at most the 0-RTT window of a dial, or a dead-egress
    /// outage.
    #[must_use]
    pub(crate) fn is_handshake_done(&self, conn: &quinn::Connection) -> bool {
        if self
            .handshake_done
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return true;
        }
        if conn.handshake_data().is_some() {
            self.handshake_done
                .store(true, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Install the generation's rev3 control-stream writer.
    ///
    /// Called synchronously by the dispatcher when it spawns the generation's
    /// control task, before any inbound datagram is handled — so a repair or a
    /// close queued from then on always has a writer. Rev2 never installs one.
    pub(crate) fn install_ctl_writer(&self, tx: tokio::sync::mpsc::UnboundedSender<CtlMessage>) {
        *self.ctl_tx.lock() = Some(tx);
    }

    /// Queue one rev3 control message for the reliable control stream.
    ///
    /// Non-blocking by design: the packet path (dispatcher, association exit)
    /// must never await an I/O write. The generation's control task owns the
    /// stream and writes messages in queue order; QUIC supplies reliability, so
    /// there is no app-level repeat. `false` means no writer is installed (rev2,
    /// or the generation's dispatcher has not run) or the task is gone; callers
    /// treat it as a dropped (idempotent) message.
    pub(crate) fn send_ctl(&self, msg: CtlMessage) -> bool {
        if self.wire != Wire::Rev3 {
            return false;
        }
        self.ctl_tx
            .lock()
            .as_ref()
            .is_some_and(|tx| tx.send(msg).is_ok())
    }

    /// Ask the peer to re-send binding context for `wire_id` (rev3 no-ACK
    /// repair), rate-limited per connection.
    ///
    /// A steady frame for an id the receiver never installed is the only
    /// recovery signal under the no-ACK policy: the receiver drops the frame
    /// and asks once (bounded by [`ctl_stream::CtlRate`]), instead of a control
    /// frame storm for a peer that keeps sending unknown ids.
    pub(crate) fn send_need_context(&self, wire_id: u32) -> bool {
        if self.wire != Wire::Rev3 {
            return false;
        }
        let Some(fid) = wire::fid_for(wire_id) else {
            return false;
        };
        if !self.ctx_repair_rate.lock().allow(coarse_millis()) {
            return false;
        }
        let sent = self.send_ctl(CtlMessage::NeedContext { fid });
        if sent {
            counters::need_context_tx();
        }
        sent
    }

    /// Record a decoded `CAPS`. Only `wire_ver == 2` makes the connection
    /// usable; any other version stays not-ready and the handshake loop closes
    /// the connection (fail-fast, no old-wire fallback).
    ///
    /// rev3 has no `CAPS` at all (a CTL DATAGRAM is never acted on there), so
    /// this is a rev2-only entry point in practice.
    pub(crate) fn on_caps(&self, caps: r2::Caps) {
        if self.wire != Wire::Rev2 {
            return;
        }
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
    ///
    /// The caller only records a close for a session whose association is still
    /// live (the dispatcher checks the hub): an id with no consumer would stay
    /// here forever, keeping the per-datagram `closed_len` short-circuit open
    /// and — at the cap — evicting a live association's close. The association
    /// drops its entry on exit ([`Self::forget_session_closed`]), which is the
    /// other half of "the set returns to empty".
    ///
    /// At the cap the **oldest** pending id is evicted, never the newest: see
    /// [`MAX_CLOSED_SESSIONS`]. A duplicate note for an already-present id is a
    /// no-op (the existing entry keeps its position, so a replayed frame cannot
    /// promote itself past older pending closes).
    pub(crate) fn note_session_closed(&self, sess: u32) {
        let mut closed = self.closed_sessions.write();
        if closed.contains(&sess) {
            return;
        }
        if closed.len() >= MAX_CLOSED_SESSIONS {
            closed.pop_front();
        }
        closed.push_back(sess);
        // Refresh under the same lock hold: a concurrent `take` that saw the
        // pre-push length then did not find its id cannot pass a stale zero to
        // the *next* sync.
        self.closed_len
            .store(closed.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Consume a recorded `SESS_CLOSE` for `sess`.
    pub(crate) fn take_session_closed(&self, sess: u32) -> bool {
        // The steady-state short-circuit: an empty deque (the common case)
        // costs one relaxed load instead of an exclusive lock acquisition per
        // uplink datagram. `closed_len` only says "the lock may be worth
        // taking" — the deque itself stays the authority, so a concurrent
        // `note` racing an in-flight probe is refuted (not lost): it refreshes
        // the count under its own write hold and the next sync picks it up.
        if self.closed_len.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return false;
        }
        let mut closed = self.closed_sessions.write();
        match closed.iter().position(|&s| s == sess) {
            Some(i) => {
                let _ = closed.remove(i);
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

    /// Drop a recorded `SESS_CLOSE` for `sess` without consuming it.
    ///
    /// The association-exit path is the only other consumer of a session's own
    /// close: once the association is gone nothing will call
    /// [`Self::take_session_closed`] for its id, so leaving it behind keeps the
    /// bounded set non-empty for the connection's life — the every-datagram
    /// exclusive lock of LOGIC-2 — and lets it occupy a slot that a live
    /// association's close could need. No-op when nothing is recorded (the
    /// common exit case, one relaxed load).
    pub(crate) fn forget_session_closed(&self, sess: u32) {
        if self.closed_len.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return;
        }
        let mut closed = self.closed_sessions.write();
        if let Some(i) = closed.iter().position(|&s| s == sess) {
            let _ = closed.remove(i);
        }
        self.closed_len
            .store(closed.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Live length of the closed-session set (test/observability probe).
    #[cfg(test)]
    pub(crate) fn closed_sessions_len(&self) -> usize {
        self.closed_len.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot of the closed-session set in insertion order (test probe).
    #[cfg(test)]
    pub(crate) fn closed_sessions_snapshot(&self) -> Vec<u32> {
        self.closed_sessions.read().iter().copied().collect()
    }

    /// Record that the server rejected a flow for `target` with `reason`. The
    /// uplink then sends `INLINE` for it until the reason's window elapses
    /// (see [`REJECT_TTL_TRANSIENT_MS`] / [`REJECT_TTL_POLICY_MS`]).
    pub(crate) fn note_rejected(&self, target: TargetAddr, reason: u8, now_ms: u64) {
        let ttl_ms = reject_ttl_ms(reason);
        let mut rejected = self.rejected.write();
        rejected.retain(|e| now_ms.saturating_sub(e.rejected_at_ms) < e.ttl_ms);
        if let Some(slot) = rejected.iter_mut().find(|e| e.target == target) {
            slot.rejected_at_ms = now_ms;
            slot.ttl_ms = ttl_ms;
            return;
        }
        if rejected.len() >= MAX_REJECTED_TARGETS {
            rejected.remove(0);
        }
        rejected.push(RejectedTarget {
            target,
            rejected_at_ms: now_ms,
            ttl_ms,
        });
    }

    /// Whether `addr` is inside an active rejection window.
    ///
    /// Read-mostly fast path: one shared-lock scan answers the common cases —
    /// no match, or a match while no entry has expired — without paying the
    /// exclusive lock the old shape took on every payload of a rejected
    /// target's window (and on every new-target payload in general). Only when
    /// the scan sees an expired entry, i.e. when the table actually needs
    /// pruning, does this upgrade to the write lock, prune and re-test under
    /// it. The TTL predicate is per entry: an entry is live while
    /// `now_ms - rejected_at < ttl_ms`, exactly what the prune retains and what
    /// [`Self::note_rejected`] maintains.
    pub(crate) fn is_rejected(&self, addr: &TargetAddrRef<'_>, now_ms: u64) -> bool {
        let expired = |e: &RejectedTarget| now_ms.saturating_sub(e.rejected_at_ms) >= e.ttl_ms;
        let rejected = self.rejected.read();
        let mut hit = false;
        let mut stale = false;
        for e in rejected.iter() {
            stale |= expired(e);
            hit |= e.target.as_ref() == *addr;
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
        rejected.retain(|e| !expired(e));
        rejected.iter().any(|e| e.target.as_ref() == *addr)
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
/// Sends `HELLO` immediately, then once per [`HELLO_RETRY`] for at most
/// [`HELLO_FAST_WINDOW`]. UDP payloads are not blocked on this function: the
/// egress cache publishes the generation right after the state is set, and the
/// server buffers pre-HELLO frames until the gate opens.
///
/// **A missing/late `CAPS` is not a connection failure (W2).** When the fast
/// window elapses without `CAPS`, a background task keeps advertising `HELLO`
/// at [`HELLO_RETRY_SLOW`] for the connection's life and this function returns
/// `true`: the connection is live and fully usable without negotiated caps (see
/// [`HELLO_FAST_WINDOW`]). `false` therefore means only the two definitive
/// failures: a `CAPS` that explicitly names another wire version (the mandated
/// fail-fast, no silent old-wire fallback), or a connection that died while
/// `HELLO` was being sent.
pub(crate) async fn handshake(conn: &quinn::Connection, rev2: &Arc<ConnRev2>) -> bool {
    handshake_with(conn, rev2, HELLO_FAST_WINDOW, HELLO_RETRY, HELLO_RETRY_SLOW).await
}

/// Testable form of [`handshake`] with explicit timing (keeps the 2 s/200 ms/
/// 2 s production cadences out of the unit tests).
pub(crate) async fn handshake_with(
    conn: &quinn::Connection,
    rev2: &Arc<ConnRev2>,
    fast_window: Duration,
    retry: Duration,
    slow_retry: Duration,
) -> bool {
    // rev3 has no `HELLO`/`CAPS`: ALPN selected the revision at the TLS
    // handshake, the caps are the static `Wire::caps` contract and the state is
    // ready as soon as it is published (0-RTT included). No HELLO byte is sent.
    if rev2.wire() == Wire::Rev3 {
        counters::handshake_ok();
        return true;
    }
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
        if caps_wrong_version(rev2) {
            counters::handshake_fail();
            return false;
        }
        if start.elapsed() >= fast_window {
            // W2: never tear down a live connection for a missing/late CAPS.
            // Hand the (much slower) retry to a background task and report the
            // connection as usable; the task keeps the negotiation alive and
            // still fails fast on an explicit wrong-version answer.
            counters::handshake_slow();
            spawn_hello_retry(conn.clone(), rev2.clone(), slow_retry);
            return true;
        }
        tokio::time::sleep(retry).await;
    }
}

/// Whether a decoded `CAPS` names a wire version other than this client's.
///
/// The only definitive mismatch: a server that explicitly answered another
/// version can never be a rev2 peer, so it is the one case that still fails
/// fast (W2 keeps a *missing* `CAPS` non-fatal).
fn caps_wrong_version(rev2: &ConnRev2) -> bool {
    rev2.ctl
        .caps()
        .is_some_and(|c| c.wire_ver != r2::R2_WIRE_VER)
}

/// Continue `HELLO` after the fast window without ever closing a live
/// connection (W2).
///
/// Stops on `CAPS` (counted as a late handshake success), on connection death,
/// or after closing a connection that answered another wire version. The task
/// holds a `Connection` clone for at most one slow-retry interval past death;
/// `close_reason` is checked before every send, so it cannot outlive the
/// generation meaningfully.
fn spawn_hello_retry(conn: quinn::Connection, rev2: Arc<ConnRev2>, slow_retry: Duration) {
    tokio::spawn(async move {
        let hello = r2::encode_ctl(&r2::Ctl::Hello {
            wire_ver: r2::R2_WIRE_VER,
            flags: 0,
        });
        loop {
            if rev2.is_ready() {
                counters::handshake_ok();
                return;
            }
            if caps_wrong_version(&rev2) {
                // Fail-fast is preserved for an explicit version answer, even
                // after the fast window: closing here is the same verdict the
                // foreground loop would have produced.
                counters::handshake_fail();
                conn.close(0u32.into(), b"rev2 wire version");
                return;
            }
            if conn.close_reason().is_some() {
                return;
            }
            match try_send_datagram(&conn, hello.clone()) {
                DatagramSend::Sent | DatagramSend::Blocked | DatagramSend::TooLarge => {
                    counters::hello_tx();
                }
                // No peer left to negotiate with; the reconnect loop owns the
                // redial, so this only ends the retry.
                DatagramSend::ConnectionLost | DatagramSend::Unsupported => return,
            }
            tokio::time::sleep(slow_retry).await;
        }
    });
}

/// Best-effort rev2 control frame on `conn`.
///
/// Mirrors the server's helper: control frames are loss-tolerant by design
/// (every opcode is idempotent and its sender retries or waits for the sweep),
/// so the verdict is reported for counting and nothing is retried here.
pub(crate) fn r2_send_ctl(conn: &quinn::Connection, ctl: &r2::Ctl) -> DatagramSend {
    try_send_datagram(conn, r2::encode_ctl(ctl))
}

/// Association-exit rev2 session teardown: release the session's
/// connection-scoped state unconditionally, then send the best-effort
/// `CTL SESS_CLOSE` when a negotiated, live connection is reachable.
///
/// The local cleanup half ([`FlowRegistry::remove_session`] +
/// [`R2Stager::drop_session`]) must not depend on `CAPS` or on winning an
/// egress refresh: an association that exits inside the 0-RTT→CAPS window, or
/// while another thread holds the per-binding single-flight gate, would
/// otherwise leave its bindings and staged payloads behind for the
/// connection's life and its server session to the 180 s sweep (whose later
/// reap notification is exactly the stale-close source LOGIC-2 used to leak).
/// The generation the association actually sent on is reached through the
/// egress cache (which names the pool slot the frames left on) and, when that
/// is empty, through the binding's own pool slot — neither requires
/// `is_ready()` or a fresh handle.
///
/// Only the datagram half is conditional: a handshake-window connection would
/// count as a refusal server-side, so `SESS_CLOSE` goes out only when the
/// reached generation negotiated rev2 (`is_ready`) and its connection is still
/// alive. Loss is harmless: the frame is idempotent and the server's 180 s idle
/// sweep is the correctness backstop.
///
/// `epoch` is the generation the association's [`UplinkFlows`] last synced to.
/// The local cleanup is gated on it: wire ids are connection-scoped and never
/// reused, so a newer generation's tables cannot hold this session's bindings,
/// and touching them could only clear another generation's fresh state (a
/// retired generation is already cleared by `retire_dead_slot`).
pub(crate) fn send_sess_close(
    egress: &SharedEgress,
    pool: &ConnPool,
    bind: Option<UdpBind>,
    sess: u32,
    epoch: u64,
) {
    // Reachable generation, in preference order: the published egress handle
    // (names the slot the association's frames actually left on), then the
    // binding's own pool slot. The handle is read without the freshness gate —
    // an expired stamp does not change which generation owns the state.
    let cached = bind.and_then(|b| egress.cached_handle(b));
    let fallback = match &cached {
        Some(_) => None,
        None => bind.and_then(|b| pool.slot(pool.udp_global_slot(b.index)).rev2()),
    };
    let reached = cached.as_ref().map(|(_, rev2)| rev2.clone()).or(fallback);
    if let Some(rev2) = &reached {
        if epoch != 0 && rev2.epoch == epoch {
            // Release the session's bindings (client-owned and accepted
            // server-owned alike) and any payload still queued for it, so a
            // later drain cannot send frames for a session the server is about
            // to reap. The stager books each dropped payload as an egress
            // death, exactly like a closed connection.
            let _ = rev2.registry.remove_session(sess);
            let _ = rev2.stager.lock().drop_session(sess);
        }
        // The association is the only consumer of its recorded close; drop it
        // so an exit that never syncs again cannot leave the bounded set
        // non-empty (LOGIC-2). Harmless when nothing is recorded.
        rev2.forget_session_closed(sess);
    }
    // Every dispatcher generation can hold a note for this session (the close
    // is recorded on whichever connection's dispatcher received it). A slot's
    // `rev2()` is a lock-free load, and exit is rare, so sweep them all: with
    // `bind == None` (an association that never sent) this is the only place
    // the note can be released.
    for i in 0..pool.slots_total() {
        if let Some(rev2) = pool.slot(i).rev2() {
            rev2.forget_session_closed(sess);
        }
    }

    // rev3: the exit signal is one `ASSOC_CLOSE` on the reliable control
    // stream (QUIC retransmits it, so the rev2 best-effort x3 repeat and its
    // `is_ready` gate are gone), and no DATAGRAM is sent.
    if reached
        .as_ref()
        .is_some_and(|rev2| rev2.wire() == Wire::Rev3)
    {
        if reached
            .as_ref()
            .is_some_and(|rev2| rev2.send_ctl(CtlMessage::AssocClose { sess, reason: 0 }))
        {
            counters::assoc_close_tx();
        }
        return;
    }

    // The SESS_CLOSE itself: three datagrams on the association's current
    // egress connection, exactly as the spec's control plane asks.
    let frame = r2::encode_ctl(&r2::Ctl::SessClose { sess, reason: 0 });
    let send = |conn: &quinn::Connection, rev2: &ConnRev2| -> bool {
        // Only a negotiated connection is allowed to carry rev2 frames; a
        // handshake-window connection would just count as REFUSED server-side.
        if !rev2.is_ready() || conn.close_reason().is_some() {
            return false;
        }
        for _ in 0..3 {
            match try_send_datagram(conn, frame.clone()) {
                DatagramSend::Sent => counters::sess_close_tx(),
                DatagramSend::ConnectionLost
                | DatagramSend::Unsupported
                | DatagramSend::Blocked
                | DatagramSend::TooLarge => return true,
            }
        }
        true
    };
    if let Some((conn, rev2)) = &cached
        && send(conn, rev2)
    {
        return;
    }
    // No usable cached handle (handshake window, or the cache was invalidated):
    // refresh once through the same single-flight gate an uplink datagram uses,
    // so a lost earlier refresh still lets this exit tell the server.
    let Some(b) = bind else { return };
    let now = coarse_millis();
    let generation = egress.generation[b.index].load(std::sync::atomic::Ordering::Acquire);
    if let Some(h) = egress.acquire(pool, b, now) {
        egress.memo_store(b, generation, &h.conn, h.limit, h.stamp_ms, &h.rev2);
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
/// dict`. This struct keeps only the per-session routing state plus the
/// bounded queue-until-publish hold ([`UplinkPending`], W3).
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
    /// Payloads held while no egress connection exists, bounded and flushed in
    /// order once a fresh handle appears (W3: queue-until-publish).
    pending: UplinkPending,
}

impl UplinkFlows {
    pub(crate) fn new() -> Self {
        Self {
            flows: SessionFlows::new(),
            epoch: 0,
            last: None,
            pending: UplinkPending::default(),
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

    /// Number of payloads currently held for a fresh egress handle (W3).
    #[must_use]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether any payload is held for a fresh egress handle (W3). One branch
    /// on the per-datagram path; the hold is empty in every steady state.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Hold `payload` until a fresh egress handle appears (W3).
    ///
    /// Returns `false` when the bounded hold is full (item or byte bound). The
    /// caller then drops the payload and books it exactly as the pre-W3 path
    /// did: drop **newest** past the bound, never the oldest, because the head
    /// of a burst is what a request/response protocol (DNS/STUN/game
    /// handshake) is waiting for.
    pub(crate) fn hold_pending(&mut self, target: &TargetAddrRef<'_>, payload: &[u8]) -> bool {
        self.push_pending(target, payload, mono_millis())
    }

    /// Test seam: [`Self::hold_pending`] with an explicit enqueue stamp, so the
    /// bounded TTL can be exercised without sleeping for it.
    #[cfg(test)]
    pub(crate) fn hold_pending_at(
        &mut self,
        target: &TargetAddrRef<'_>,
        payload: &[u8],
        now_ms: u64,
    ) -> bool {
        self.push_pending(target, payload, now_ms)
    }

    /// Shared body of [`Self::hold_pending`] / [`Self::hold_pending_at`].
    fn push_pending(&mut self, target: &TargetAddrRef<'_>, payload: &[u8], now_ms: u64) -> bool {
        if !self.pending.try_push(target, payload, now_ms) {
            return false;
        }
        counters::egress_queued();
        true
    }

    /// Age out held payloads past [`PENDING_TTL_MS`] (W3).
    ///
    /// Each dropped payload is booked as a `NO_EGRESS` loss: it was held
    /// precisely because no egress connection existed, and once the bounded
    /// window passes that loss is final — delivering a stale UDP datagram is
    /// worse than losing it. Returns how many were dropped.
    pub(crate) fn expire_pending(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        self.expire_pending_stamped(mono_millis())
    }

    /// Test seam: [`Self::expire_pending`] against an explicit clock, so the
    /// TTL can be exercised without a 500 ms sleep.
    #[cfg(test)]
    pub(crate) fn expire_pending_at(&mut self, now_ms: u64) -> usize {
        self.expire_pending_stamped(now_ms)
    }

    fn expire_pending_stamped(&mut self, now_ms: u64) -> usize {
        let n = self.pending.expire(now_ms);
        if n != 0 {
            book_hold_loss(n, "hold window elapsed");
        }
        n
    }

    /// Drop every held payload (association exit / peer-session teardown).
    ///
    /// Never silent: an exiting association's held payloads are as gone as a
    /// dead connection's stager items, so they are booked the same way.
    pub(crate) fn clear_pending(&mut self) -> usize {
        let n = self.pending.clear();
        if n != 0 {
            book_hold_loss(n, "association exit");
        }
        n
    }
}

/// Bound on payloads held per association while no egress connection exists
/// (W3). Sixty-four is the codec's train bound: one hold's worth fits exactly
/// one full cross-session `TRAIN dict` once it is flushed through the normal
/// path.
pub(crate) const PENDING_MAX_ITEMS: usize = 64;

/// Byte bound on the W3 hold (payload bytes only; the target/`Bytes` headers
/// add a few dozen bytes per item). Bounds the worst-case copy an outage can
/// make: a high-rate app during a dead-egress window pays at most one hold's
/// worth of `Bytes` allocations, after which new datagrams are dropped exactly
/// as before.
pub(crate) const PENDING_MAX_BYTES: usize = 64 * 1024;

/// How long a held payload may wait for a fresh egress handle (W3).
///
/// UDP delivery is only useful while the datagram is fresh (DNS/STUN/gaming
/// clients retransmit on their own timers, and a proxy-delivered stale datagram
/// is worse than a drop: it can reorder against the client's retry). Half a
/// second covers the cold-start publish window and the common
/// death→backoff→re-dial→publish reconnect path; longer outages fall back to
/// the pre-W3 fail-closed loss, which is the documented `udp_fail_closed`
/// semantics.
pub(crate) const PENDING_TTL_MS: u64 = 500;

/// Poll cadence of the association's pending-flush timer (W3).
///
/// The timer branch is armed only while the hold is non-empty, so a healthy
/// association pays nothing; during an outage it bounds how long a flushed
/// generation can sit unnoticed to one tick (plus the expiry check).
pub(crate) const PENDING_FLUSH_TICK: Duration = Duration::from_millis(100);

/// One payload waiting for an egress handle (W3).
struct HeldPayload {
    target: TargetAddr,
    payload: Bytes,
    enqueued_ms: u64,
}

/// Book `n` held payloads that aged out without being sent: one `NO_EGRESS`
/// loss each (the reason they were held), the stale-hold counter, and one
/// rate-limited warning naming the hold. Only ever called on the no-egress
/// path. The other drop reason — the hold was already at its bound — is booked
/// where the payload is refused, in `send_payload_uplink`.
fn book_hold_loss(n: usize, reason: &'static str) {
    let mut total = 0;
    for _ in 0..n {
        total = dgram_drops::bump(&dgram_drops::NO_EGRESS);
        counters::egress_hold_stale();
    }
    dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, total, || {
        format!("; {n} held datagram(s) dropped ({reason})")
    });
}

/// Bounded per-association queue of payloads whose egress connection was not
/// available (W3: queue-until-publish).
///
/// Before W3 every such payload was dropped (`NO_EGRESS`), which made a
/// reconnect — and the cold-start window before the first egress publish — a
/// total-loss window: a one-shot DNS query/STUN binding/game handshake waited
/// for the app's own multi-second retransmission, and a burst lost every
/// datagram after the first. This hold converts that into "delivered when a
/// fresh handle appears", bounded three ways so UDP semantics are preserved:
///
/// * [`PENDING_MAX_ITEMS`] items / [`PENDING_MAX_BYTES`] payload bytes: past
///   either bound the **newest** payload is refused (drop-newest, exactly
///   quinn's DATAGRAM-buffer policy), because the oldest datagrams of a burst
///   are the ones a request/response protocol is waiting for;
/// * [`PENDING_TTL_MS`]: a payload is only delivered while it is fresh; an
///   expired one is dropped and accounted as `NO_EGRESS` on the next flush
///   attempt, never delivered late;
/// * the flush is FIFO and re-enters the normal [`send_uplink`] path, so
///   per-target ordering is preserved and no encoder/id state is duplicated
///   here.
///
/// Payload bytes are copied on the hold path only (where the alternative is a
/// drop) and only up to the byte bound. The hold is per association (not
/// process-wide) so an exiting association takes its own payloads with it and
/// no cross-session encoding state is involved.
#[derive(Default)]
struct UplinkPending {
    items: VecDeque<HeldPayload>,
    bytes: usize,
}

impl UplinkPending {
    fn len(&self) -> usize {
        self.items.len()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Push one payload, or refuse it (`false`) when at either bound.
    fn try_push(&mut self, target: &TargetAddrRef<'_>, payload: &[u8], now_ms: u64) -> bool {
        if self.items.len() >= PENDING_MAX_ITEMS
            || self.bytes.saturating_add(payload.len()) > PENDING_MAX_BYTES
        {
            return false;
        }
        self.bytes += payload.len();
        self.items.push_back(HeldPayload {
            target: target.into_owned(),
            payload: Bytes::copy_from_slice(payload),
            enqueued_ms: now_ms,
        });
        true
    }

    fn pop_front(&mut self) -> Option<HeldPayload> {
        let item = self.items.pop_front()?;
        self.bytes -= item.payload.len();
        Some(item)
    }

    /// Return a payload that was not sent (dead handle) to the head of the
    /// FIFO, so order survives a flush that aborted mid-way.
    fn push_front(&mut self, item: HeldPayload) {
        self.bytes += item.payload.len();
        self.items.push_front(item);
    }

    /// Drop the payloads older than [`PENDING_TTL_MS`] and return how many.
    /// FIFO insertion order means the head is always the oldest.
    fn expire(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        while let Some(front) = self.items.front() {
            if now_ms.saturating_sub(front.enqueued_ms) < PENDING_TTL_MS {
                break;
            }
            let item = self.items.pop_front().expect("front was just observed");
            self.bytes -= item.payload.len();
            n += 1;
        }
        n
    }

    fn clear(&mut self) -> usize {
        let n = self.items.len();
        self.items.clear();
        self.bytes = 0;
        n
    }
}

/// Flush held payloads onto an already-resolved egress handle (W3).
///
/// FIFO order through the normal [`send_uplink`] path, so a held payload
/// re-enters exactly the encoding/id state machine a fresh datagram does (it is
/// not replayed as a special frame, and a generation bump re-`OPEN`s flows the
/// same way). The aggregate verdict is returned for the caller's shared
/// recovery.
///
/// A `ConnectionLost`/`Unsupported` verdict means the in-flight payload never
/// left: it goes back to the head of the hold and the flush stops, so it and
/// everything behind it can still go out on the next generation within their
/// TTL. `Blocked`/`TooLarge` were already booked where they were decided (the
/// send path's own drop accounting) and only lose that one payload.
fn flush_pending_on(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    bind: UdpBind,
    rev2: &ConnRev2,
    up: &mut UplinkFlows,
    frag: &mut R2Fragmenter,
) -> PayloadSend {
    let mut aggregate = PayloadSend {
        frames: 0,
        failed: None,
    };
    while let Some(item) = up.pending.pop_front() {
        let sent = send_uplink(
            conn,
            limit,
            sess,
            &item.target.as_ref(),
            &item.payload,
            bind,
            rev2,
            up,
            frag,
        );
        aggregate = PayloadSend {
            frames: aggregate.frames.saturating_add(sent.frames),
            failed: prefer_severe(aggregate, sent).failed,
        };
        match sent.failed {
            Some(DatagramSend::ConnectionLost | DatagramSend::Unsupported) => {
                up.pending.push_front(item);
                break;
            }
            _ => counters::egress_flushed(),
        }
    }
    aggregate
}

/// Try to publish everything held for `bind` into the current egress handle
/// (W3 flush trigger).
///
/// Called from the association's per-datagram send path *before* the current
/// payload (so the hold keeps FIFO order across the boundary), from its
/// pending-flush tick, and from the exit path. Returns `true` when the hold is
/// empty afterwards (flushed or expired), `false` when no egress handle exists
/// yet or the flush hit a dead one.
///
/// Resolution mirrors the send path's miss arm exactly (memo hit, then
/// [`SharedEgress::acquire`] + memo store): a flush publishes on the same
/// single-flight gate as a datagram and cannot bypass the class-isolation
/// rules. It deliberately does **not** consult `CAPS`/`is_ready()` — an
/// optimistic pre-`CAPS` (0-RTT) generation is publishable and usable.
#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_pending_uplink(
    egress: &SharedEgress,
    pool: &ConnPool,
    sess: u32,
    bind: UdpBind,
    up: &mut UplinkFlows,
    frag: &mut R2Fragmenter,
    now: u64,
) -> bool {
    if up.pending.is_empty() {
        return true;
    }
    up.expire_pending();
    if up.pending.is_empty() {
        return true;
    }
    let sent = match egress.with_fresh(bind, now, |c, limit, rev2| {
        let limit = rev2.frame_limit(limit);
        flush_pending_on(c, limit, sess, bind, rev2, up, frag)
    }) {
        Some(sent) => sent,
        None => {
            // Generation read before the cached read, the contract the
            // per-datagram miss path documents.
            let generation =
                egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
            match egress.acquire(pool, bind, now) {
                Some(h) => {
                    egress.memo_store(bind, generation, &h.conn, h.limit, h.stamp_ms, &h.rev2);
                    let limit = h.rev2.frame_limit(h.limit);
                    flush_pending_on(&h.conn, limit, sess, bind, &h.rev2, up, frag)
                }
                None => return false,
            }
        }
    };
    recover_send_outcome(egress, bind, sent);
    up.pending.is_empty()
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
    // The fragmenter is per association but the wire is per connection: pin it
    // on every send (cheap `Copy` field store) so a reconnect onto another
    // revision re-encodes fragments correctly, and rev2 keeps identical bytes.
    frag.set_wire(rev2.wire());
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
                send_standalone(
                    conn,
                    limit,
                    sess,
                    addr,
                    payload,
                    None,
                    frag,
                    rev2.wire(),
                    false,
                ),
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
    // Binding form or steady frame for this payload. rev2: ACK-gated
    // (`Opening` repeats OPEN). rev3: self-confirming, the first
    // `R3_CONTEXT_REPEATS` payloads carry context and the last one marks the
    // binding open locally (a `NEED_CONTEXT` repair re-arms it).
    let context = uses_binding_context(rev2, &binding, rev2.is_handshake_done(conn));
    if payload.len() <= BATCH_SMALL_MAX {
        let kind = if context {
            R2StageKind::Open {
                wire_id: binding.wire_id,
                sess,
                addr: addr.into_owned(),
                src: false,
            }
        } else {
            R2StageKind::Steady {
                wire_id: binding.wire_id,
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
        send_standalone(
            conn,
            limit,
            sess,
            addr,
            payload,
            Some(&binding),
            frag,
            rev2.wire(),
            context,
        ),
    )
}

/// Whether this payload must carry the binding form for `binding`.
///
/// * rev2 keeps the shipped ACK-gated rule: `Opening` sends `DATA OPEN` until a
///   `FLOW_ACK` (or a compressed downlink) moves the binding to `Open`.
/// * rev3 has no per-flow ACK: [`FlowBinding::take_context_slot`] hands out the
///   first [`myquic2::mqp::r2_flow::R3_CONTEXT_REPEATS`] context frames and
///   marks the binding open on the last one, so steady frames start on payload
///   three of a fresh flow with no round trip and no ACK wait. The slot is
///   consumed exactly once per payload, so a dropped payload only shortens the
///   redundancy (a receiver that still misses the binding repairs with
///   `NEED_CONTEXT`).
/// * rev3 **early-data rule**: a payload sent before the connection's handshake
///   completes is 0-RTT data and may be discarded without retransmission (a
///   rejected resumption drops every early DATAGRAM). Such a payload therefore
///   always carries the binding form and never spends the context budget — the
///   same free redundancy rev2 gets from repeating `OPEN` until an ACK. Once
///   `handshake_done` is true the normal K=2 window runs, so even if the whole
///   early window was lost the receiver still gets its context window after the
///   handshake.
///
/// `handshake_done` is passed in (instead of the connection) so the policy is a
/// pure, unit-testable rule: early data never confirms a binding.
pub(crate) fn uses_binding_context(
    rev2: &ConnRev2,
    binding: &FlowBinding,
    handshake_done: bool,
) -> bool {
    match rev2.wire() {
        Wire::Rev2 => !binding.is_open(),
        Wire::Rev3 => !handshake_done || binding.take_context_slot(),
    }
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
#[allow(clippy::too_many_arguments)]
fn send_standalone(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    flow: Option<&Arc<FlowBinding>>,
    frag: &mut R2Fragmenter,
    wire: Wire,
    context: bool,
) -> PayloadSend {
    if let Some(sent) = try_single_data(conn, limit, sess, addr, payload, flow, wire, context)
        && (sent.complete()
            || !matches!(
                sent.failed,
                Some(DatagramSend::Blocked | DatagramSend::TooLarge)
            ))
    {
        return sent;
    }
    let frag_flow = match flow {
        Some(binding) if !context => R2FragFlow::Steady {
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
#[allow(clippy::too_many_arguments)]
fn try_single_data(
    conn: &quinn::Connection,
    limit: usize,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    flow: Option<&Arc<FlowBinding>>,
    wire: Wire,
    context: bool,
) -> Option<PayloadSend> {
    let body = match flow {
        Some(binding) if !context => {
            wire::encode_data_steady(wire, binding.wire_id, payload, limit)?
        }
        Some(binding) => {
            wire::encode_data_open(wire, binding.wire_id, sess, addr, false, payload, limit)?
        }
        None => wire::encode_data_inline(wire, sess, addr, false, payload, limit)?,
    };
    Some(match try_send_datagram(conn, body) {
        DatagramSend::Sent => {
            udp_stats::payload(payload.len());
            match flow {
                Some(_) if context => counters::open_tx(),
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
/// connection-wide map walk on every payload of its window), the
/// server-owned-flow **reuse** scan (it needs no capacity: the binding is
/// already installed, and the shared API turns it into one lock-free counter
/// check for the common uplink-only client), then the capacity probe (a full
/// table can only fall back to `INLINE`, and only after reuse was ruled out),
/// and finally the atomic allocate-and-insert. [`FlowRegistry::insert_new`]
/// re-checks capacity under its write lock before allocating an id, so a table
/// that fills between the probe and the insert still cannot consume one: ids
/// are never reused, and such a leak would eventually force every payload to
/// `INLINE`.
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
    // A rejected target stays `INLINE` for its reason's window: re-opening it
    // would cost one rejected frame plus one lost payload per payload (see
    // [`REJECT_TTL_TRANSIENT_MS`] / [`REJECT_TTL_POLICY_MS`]). Checked before
    // any registry scan: the rejection is the expected outcome for every
    // payload of the window, so nothing can be bound for it and the scans below
    // could only waste work. `is_rejected` is itself read-mostly (it takes the
    // write lock only to prune expired entries).
    if rev2.is_rejected(addr, coarse_millis()) {
        return None;
    }
    // Full-cone symmetry: the server may already own a flow for this exact
    // (session, target) — it announced it with `DATA OPEN|SRC` and the
    // dispatcher installed it. Reuse that id so the app's reply rides the same
    // flow (steady/stager/fragment encoders carry the owner bit already)
    // instead of opening a parallel client-owned one. The binding is already in
    // the registry, so it is never inserted again — which is exactly why this
    // runs **before** the capacity probe: a full registry is the case where
    // reuse is the only way to keep the reply path compressed, and the probe
    // must never turn it into `INLINE`. For the common uplink-only client the
    // shared API's lock-free server-flow counter makes this a single atomic
    // load, not the O(registry) scan.
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
    // A full connection registry means no *new* flow can be bound: `INLINE` is
    // the only remaining outcome (reuse was ruled out above). Advisory only —
    // `insert_new` re-checks the cap under its write lock and stays the
    // authority.
    if !rev2.registry.has_capacity() {
        return None;
    }
    // One write-lock hold: capacity re-check, id allocation, insert. An id
    // allocated before a refused insert would be lost for the connection's
    // life (wire ids are never reused).
    // rev3: an id that cannot be a 14-bit `fid` is refused *before* it is
    // installed (and without burning it), so the caller falls back to `INLINE`
    // instead of installing an unencodable binding.
    let binding = rev2
        .registry
        .insert_new_for(rev2.wire(), &rev2.ids, sess, addr.into_owned())
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
        /// Handshakes that failed (wrong wire version or dead connection).
        handshake_fail,
        /// Connections whose fast `HELLO` window elapsed without `CAPS` and
        /// which moved to the slow background retry cadence (W2). Not a
        /// failure: the connection is live and `CAPS` only tunes limits.
        handshake_slow,
        /// `CTL CAPS` frames decoded.
        caps_rx,
        /// `CTL FLOW_ACK` frames that resolved an uplink binding.
        flow_ack_rx,
        /// `CTL FLOW_ACK` frames queued to confirm a learned `OPEN|SRC` reply
        /// source (client side of the binding-confirmation contract).
        flow_ack_tx,
        /// `CTL FLOW_REJECT` frames that closed an uplink binding.
        flow_reject_rx,
        /// `CTL FLOW_REJECT` frames queued for a binding frame this side could
        /// not install (`TABLE_FULL`/`POLICY`), so the peer stops re-sending it.
        flow_reject_tx,
        /// `CTL FLOW_CLOSE` frames that closed a binding.
        flow_close_rx,
        /// `CTL SESS_CLOSE` frames decoded (from the server).
        sess_close_rx,
        /// Peer `CTL` frames dropped by the per-connection rate budget.
        ctl_rate_limited,
        /// Best-effort `FLOW_ACK`/`FLOW_REJECT` sends that did not queue
        /// (blocked buffer or dead connection). Loss is recovered by the
        /// peer's idempotent rebind, so this only feeds the 60 s line.
        ctl_tx_fail,
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
        /// Payloads held in the bounded queue-until-publish hold because no
        /// egress connection existed (W3).
        egress_queued,
        /// Held payloads handed back to the normal uplink path when a fresh
        /// egress handle appeared (W3).
        egress_flushed,
        /// Held payloads dropped because the hold was already at its item/byte
        /// bound (W3: drop-newest past the bound).
        egress_hold_full,
        /// Held payloads dropped without being sent because the bounded window
        /// elapsed (or the owner exited) before egress returned (W3).
        egress_hold_stale,
        /// Flow tables reset because the connection generation changed.
        flow_table_reset,
        /// Flow tables reset because the server sent `SESS_CLOSE`.
        session_reset,
        /// `CTL` frames dropped as malformed/unknown.
        ctl_drop,
        /// rev3: `ASSOC_CLOSE` messages queued on the control stream
        /// (association exit; replaces the rev2 `SESS_CLOSE` x3 datagrams).
        assoc_close_tx,
        /// rev3: `NEED_CONTEXT` repair requests queued on the control stream.
        need_context_tx,
        /// rev3: `NEED_CONTEXT` repair requests received and applied (the peer
        /// missed our binding context; the window was re-armed).
        need_context_rx,
        /// rev3: control-stream messages handled (Reject/SessClose/FlowClose/
        /// NeedContext/Goaway).
        ctl_stream_rx,
        /// rev3: control-stream messages dropped without acting on them
        /// (receiver rate budget, unimplemented direction, malformed).
        ctl_stream_drop,
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
        egress_queued,
        egress_flushed,
    }

    // Control-plane / test-observable counters: direct shared increments, the
    // exact cross-thread one-per-event cost the tests rely on.
    rev2_counter_fns_direct! {
        hello_tx,
        handshake_ok,
        handshake_fail,
        handshake_slow,
        caps_rx,
        flow_ack_rx,
        flow_reject_rx,
        flow_close_rx,
        sess_close_rx,
        sess_close_tx,
        flow_ack_tx,
        flow_reject_tx,
        ctl_rate_limited,
        ctl_tx_fail,
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
        egress_hold_full,
        egress_hold_stale,
        flow_table_reset,
        session_reset,
        ctl_drop,
        assoc_close_tx,
        need_context_tx,
        need_context_rx,
        ctl_stream_rx,
        ctl_stream_drop,
    }

    impl std::fmt::Display for Rev2Snapshot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "hello={} handshake={}/{}/{} caps={} frames_rx={} ack={}/{} reject={}/{} \
                 close={} sess_close={}/{} flow_open={} srv={}/{} open={} steady={} \
                 inline={}/{} stage={}p/{}d/{}f/{}i/{}x/{}full hold={}q/{}f/{}full/{}stale \
                 frag={}/{}/{} unknown_id={} drops={} resets={}/{} ctl={}/{}/{} \
                 r3ctl={}/{} nctx={}/{} aclose={}",
                self.hello_tx,
                self.handshake_ok,
                self.handshake_fail,
                self.handshake_slow,
                self.caps_rx,
                self.rx_frame,
                self.flow_ack_rx,
                self.flow_ack_tx,
                self.flow_reject_rx,
                self.flow_reject_tx,
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
                self.egress_queued,
                self.egress_flushed,
                self.egress_hold_full,
                self.egress_hold_stale,
                self.frag_tx,
                self.frag_rx,
                self.frag_complete,
                self.rx_unknown_id,
                self.rx_drop,
                self.flow_table_reset,
                self.session_reset,
                self.ctl_drop,
                self.ctl_rate_limited,
                self.ctl_tx_fail,
                self.ctl_stream_rx,
                self.ctl_stream_drop,
                self.need_context_tx,
                self.need_context_rx,
                self.assoc_close_tx,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_SESSION;

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
    fn closed_sessions_are_consumed_once_and_the_set_empties() {
        let r = ConnRev2::new();
        assert_eq!(r.closed_sessions_len(), 0);
        assert!(!r.take_session_closed(7));
        r.note_session_closed(7);
        assert_eq!(r.closed_sessions_len(), 1);
        assert!(r.take_session_closed(7));
        assert!(
            !r.take_session_closed(7),
            "a close is consumed exactly once"
        );
        assert_eq!(
            r.closed_sessions_len(),
            0,
            "the len short-circuit must close again once consumed"
        );
        // A duplicate note is one id, not one per frame.
        r.note_session_closed(9);
        r.note_session_closed(9);
        assert_eq!(r.closed_sessions_len(), 1);
        assert_eq!(r.closed_sessions_snapshot(), vec![9]);
        assert!(r.take_session_closed(9));
        assert_eq!(r.closed_sessions_len(), 0);
    }

    #[test]
    fn closed_sessions_cap_evicts_the_oldest() {
        let r = ConnRev2::new();
        // One past the cap: the *oldest* id must be the one evicted, never the
        // newest (dropping a fresh close would blackhole a live association).
        for s in 1..=(MAX_CLOSED_SESSIONS as u32 + 1) {
            r.note_session_closed(s);
        }
        assert_eq!(r.closed_sessions_len(), MAX_CLOSED_SESSIONS);
        let kept = r.closed_sessions_snapshot();
        assert_eq!(kept.len(), MAX_CLOSED_SESSIONS);
        assert!(!kept.contains(&1), "the oldest id was evicted");
        assert!(kept.contains(&(MAX_CLOSED_SESSIONS as u32 + 1)));
        assert!(
            !r.take_session_closed(1),
            "the evicted id is not consumable"
        );
        assert!(
            r.take_session_closed(2),
            "the next-oldest entry is untouched"
        );
        assert!(r.take_session_closed(MAX_CLOSED_SESSIONS as u32 + 1));
    }

    #[test]
    fn forget_session_closed_returns_the_set_to_empty() {
        let r = ConnRev2::new();
        r.note_session_closed(1);
        r.note_session_closed(2);
        r.note_session_closed(3);
        // Association exit: its own pending close must not outlive it.
        r.forget_session_closed(2);
        assert_eq!(r.closed_sessions_len(), 2);
        assert!(!r.take_session_closed(2));
        // Forgetting an absent id (the common exit case) is a no-op.
        r.forget_session_closed(99);
        assert_eq!(r.closed_sessions_snapshot(), vec![1, 3]);
        // The final exit forgets the rest: the per-datagram short-circuit is
        // back to one relaxed load with no lock.
        r.forget_session_closed(1);
        r.forget_session_closed(3);
        assert_eq!(r.closed_sessions_len(), 0);
        assert!(!r.take_session_closed(1));
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

    /// PERF-8 regression: a **full** registry must still reuse an installed
    /// server-owned flow.
    ///
    /// `find_server_flow` needs no capacity (the binding is already there), so
    /// the reuse scan must run before the capacity probe. With the probe first
    /// (the 8f0d685 order), a full-cone client at cap sent every reply `INLINE`
    /// even though the server-owned id existed locally.
    #[test]
    fn full_registry_still_reuses_a_server_owned_flow() {
        let r = ConnRev2::new();
        let sess = 1u32;
        let addr: SocketAddr = "198.51.100.44:443".parse().unwrap();
        let server = FlowBinding::new_shared(
            r2::make_wire_id(1, true).unwrap(),
            sess,
            TargetAddr::Ip(addr),
        );
        server.set_reply_src(addr);
        server.mark_open();
        assert!(r.registry.insert(server.clone()).is_ok());
        // Fill the rest of the table; a full registry is exactly the state the
        // reuse path exists for.
        let filler = TargetAddr::Ip("203.0.113.7:9".parse().unwrap());
        for i in 2..=R2_MAX_FLOWS_PER_CONN as u32 {
            let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 2, filler.clone());
            assert!(r.registry.insert(b).is_ok());
        }
        assert!(!r.registry.has_capacity(), "premise: the table is full");
        let mut up = UplinkFlows::new();
        let reused = ensure_binding(&r, &mut up, sess, &TargetAddrRef::Ip(addr))
            .expect("a full registry must still reuse an installed server-owned flow");
        assert_eq!(reused.wire_id, server.wire_id);
        assert_eq!(up.flows.len(), 1, "the flow is joined, not re-created");
        assert_eq!(
            r.ids.allocated(),
            0,
            "reuse must not allocate a never-reused id"
        );
    }

    /// A target inside a `FLOW_REJECT` window takes the `INLINE` fail-safe: the
    /// decision must be made before the registry scans and must not allocate an
    /// id.
    #[test]
    fn rejected_target_path_consumes_no_id() {
        let r = ConnRev2::new();
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        r.note_rejected(
            TargetAddr::Ip(addr),
            r2::R2_REJECT_TABLE_FULL,
            coarse_millis(),
        );
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
        r.note_rejected(a.clone(), r2::R2_REJECT_POLICY, 1_000);
        r.note_rejected(b.clone(), r2::R2_REJECT_POLICY, 1_000);
        // Both windows are live: the probe answers from the shared lock and
        // leaves the table untouched.
        assert!(r.is_rejected(&a.as_ref(), 2_000));
        assert!(r.is_rejected(&b.as_ref(), 2_000));
        assert_eq!(r.rejected.read().len(), 2, "a live probe prunes nothing");
        // One TTL later both entries are expired: the probe upgrades to the
        // write lock, prunes them and answers `false`.
        assert!(!r.is_rejected(&a.as_ref(), 1_000 + REJECT_TTL_POLICY_MS));
        assert_eq!(r.rejected.read().len(), 0, "expired entries are pruned");
    }

    /// P2-6: a capacity/DNS rejection is transient and must be retried soon; a
    /// policy rejection is stable and must not cost a rejected frame every
    /// second.
    #[test]
    fn reject_ttl_is_reason_aware() {
        let r = ConnRev2::new();
        let table_full = TargetAddr::Ip("198.51.100.10:1".parse().unwrap());
        let dns = TargetAddr::Ip("198.51.100.11:2".parse().unwrap());
        let policy = TargetAddr::Ip("198.51.100.12:3".parse().unwrap());
        r.note_rejected(table_full.clone(), r2::R2_REJECT_TABLE_FULL, 0);
        r.note_rejected(dns.clone(), r2::R2_REJECT_DNS, 0);
        r.note_rejected(policy.clone(), r2::R2_REJECT_POLICY, 0);

        assert!(r.is_rejected(&table_full.as_ref(), REJECT_TTL_TRANSIENT_MS - 1));
        assert!(r.is_rejected(&dns.as_ref(), REJECT_TTL_TRANSIENT_MS - 1));
        assert!(
            !r.is_rejected(&table_full.as_ref(), REJECT_TTL_TRANSIENT_MS),
            "TABLE_FULL must retry on the short window"
        );
        assert!(
            !r.is_rejected(&dns.as_ref(), REJECT_TTL_TRANSIENT_MS),
            "DNS must retry on the short window"
        );
        assert!(
            r.is_rejected(&policy.as_ref(), REJECT_TTL_TRANSIENT_MS),
            "POLICY must stay INLINE past the transient window"
        );
        assert!(r.is_rejected(&policy.as_ref(), REJECT_TTL_POLICY_MS - 1));
        assert!(
            !r.is_rejected(&policy.as_ref(), REJECT_TTL_POLICY_MS),
            "POLICY expires on its long window"
        );
    }

    /// P1-1: 64 distinct rejected targets must not pin the association's 64
    /// reverse-table slots. The 65th new target has to open a flow (the
    /// registry is nearly empty), not fall back to `INLINE` forever.
    #[test]
    fn rejected_targets_reclaim_session_slots_for_new_targets() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new();
        let now = coarse_millis();
        // Open 64 distinct targets first: that is the state a burst of
        // FLOW_REJECTs lands on.
        let mut opened = Vec::new();
        for i in 0..R2_MAX_FLOWS_PER_SESSION as u16 {
            let addr = SocketAddr::from(([198, 51, 100, 9], 4000 + i));
            let binding = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr))
                .expect("the first 64 targets fit the session table");
            binding.mark_open();
            opened.push(binding);
        }
        assert_eq!(up.flows.len(), R2_MAX_FLOWS_PER_SESSION);
        assert!(up.flows.is_full());
        for binding in opened {
            // The production `FLOW_REJECT` close path: registry removal, the
            // binding marked closed, and the reason window armed.
            assert!(r.registry.remove(binding.wire_id).is_some());
            binding.mark_closed();
            assert_eq!(binding.state(), FlowState::Closed);
            r.note_rejected(binding.target.clone(), r2::R2_REJECT_TABLE_FULL, now);
        }
        assert_eq!(up.flows.len(), R2_MAX_FLOWS_PER_SESSION);
        assert!(
            !up.flows.is_full(),
            "closed bindings must not keep the session table full"
        );

        let fresh_addr = SocketAddr::from(([198, 51, 100, 10], 5000));
        let fresh = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(fresh_addr))
            .expect("the 65th target must reuse a closed slot");
        assert_eq!(fresh.state(), FlowState::Opening);
        assert_eq!(
            up.flows.len(),
            R2_MAX_FLOWS_PER_SESSION,
            "the reclaimed slot was replaced, not appended"
        );
        assert!(r.registry.get(fresh.wire_id).is_some());
    }

    /// N-1: a server-side purge can arrive without a consumable `SESS_CLOSE`
    /// note (the client's bounded set may have evicted it). The shared binding
    /// is marked closed by the purge, so the next uplink must re-open instead
    /// of sending steady frames for an id the server no longer holds.
    #[test]
    fn registry_purge_without_a_close_note_is_recovered() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new();
        up.sync(&r, 1);
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let first = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        first.mark_open();
        // The server reaped the session and the note was never recorded (or was
        // evicted at MAX_CLOSED_SESSIONS): `sync` sees nothing.
        assert_eq!(r.registry.remove_session(1), 1);
        assert_eq!(first.state(), FlowState::Closed);
        up.sync(&r, 1);
        assert!(
            up.last.is_some(),
            "premise: the memo still holds the dead flow"
        );

        let reopened = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr))
            .expect("the closed binding must not be reused");
        assert_ne!(reopened.wire_id, first.wire_id, "an id is never reused");
        assert_eq!(up.flows.len(), 1, "the dead slot was reclaimed");
        assert!(r.registry.get(reopened.wire_id).is_some());
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
        r.note_rejected(TargetAddr::Ip(addr), r2::R2_REJECT_POLICY, now);
        assert!(r.is_rejected(&TargetAddrRef::Ip(addr), now));
        assert!(
            ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).is_none(),
            "a rejected target must fall back to INLINE inside the TTL"
        );
        // The window is TTL-wide; a probe at the TTL boundary expires it (that
        // probe uses the wall clock in production, so pruning is exact).
        assert!(r.is_rejected(&TargetAddrRef::Ip(addr), now + REJECT_TTL_POLICY_MS - 1));
        assert!(
            !r.is_rejected(&TargetAddrRef::Ip(addr), now + REJECT_TTL_POLICY_MS),
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
            r.note_rejected(TargetAddr::Ip(a), r2::R2_REJECT_TABLE_FULL, 0);
        }
        let live = r.rejected.read().len();
        assert_eq!(live, MAX_REJECTED_TARGETS, "the set stays bounded");
        // Re-rejecting a present target moves its stamp, it does not grow.
        let a = TargetAddr::Ip(SocketAddr::from(([203, 0, 113, 9], 4000)));
        r.note_rejected(a.clone(), r2::R2_REJECT_TABLE_FULL, 0);
        r.note_rejected(a, r2::R2_REJECT_TABLE_FULL, 0);
        assert_eq!(r.rejected.read().len(), MAX_REJECTED_TARGETS);
    }

    #[test]
    fn handshake_retry_constants_are_the_documented_budget() {
        assert_eq!(HELLO_RETRY, Duration::from_millis(200));
        assert_eq!(HELLO_RETRY_SLOW, Duration::from_secs(2));
        assert_eq!(HELLO_FAST_WINDOW, Duration::from_secs(2));
        assert!(HELLO_FAST_WINDOW.as_millis() / HELLO_RETRY.as_millis() >= 10);
        assert!(
            HELLO_RETRY_SLOW > HELLO_RETRY,
            "the background cadence must be slower than the fast one"
        );
    }

    /// W2: the fast window is a negotiation-retry bound, not a connection
    /// deadline — a missing/late `CAPS` must never fail a live connection.
    /// The only fatal control answer is an explicit different wire version.
    #[test]
    fn caps_version_check_is_the_only_fatal_answer() {
        let r = ConnRev2::new();
        assert!(!caps_wrong_version(&r), "no CAPS yet is not a mismatch");
        r.on_caps(r2::Caps {
            wire_ver: r2::R2_WIRE_VER,
            ..r2::Caps::default()
        });
        assert!(!caps_wrong_version(&r));
        let wrong = ConnRev2::new();
        wrong.on_caps(r2::Caps {
            wire_ver: r2::R2_WIRE_VER + 1,
            ..r2::Caps::default()
        });
        assert!(caps_wrong_version(&wrong));
        assert!(!wrong.is_ready());
    }

    /// W3: the hold is bounded by items, by bytes, and drops the newest past
    /// either bound (never the oldest item of a burst).
    #[test]
    fn pending_hold_is_bounded_and_drops_the_newest() {
        let mut up = UplinkFlows::new();
        let addr: SocketAddr = "198.51.100.9:53".parse().unwrap();
        for i in 0..PENDING_MAX_ITEMS {
            let p = [i as u8];
            assert!(up.hold_pending(&TargetAddrRef::Ip(addr), &p), "item {i}");
        }
        assert_eq!(up.pending_len(), PENDING_MAX_ITEMS);
        assert!(up.has_pending());
        // One past the item bound: refused, not evicting the oldest item.
        assert!(!up.hold_pending(&TargetAddrRef::Ip(addr), b"newest"));
        assert_eq!(up.pending_len(), PENDING_MAX_ITEMS);
        assert_eq!(
            up.pending.bytes, PENDING_MAX_ITEMS,
            "one payload byte per held item"
        );

        // Byte bound: a second association with large payloads stops at the
        // byte cap with fewer than the item cap.
        let mut big = UplinkFlows::new();
        let chunk = vec![0u8; PENDING_MAX_BYTES / 2];
        assert!(big.hold_pending(&TargetAddrRef::Ip(addr), &chunk));
        assert!(big.hold_pending(&TargetAddrRef::Ip(addr), &chunk));
        assert_eq!(big.pending_len(), 2);
        assert!(!big.hold_pending(&TargetAddrRef::Ip(addr), b"x"));
        assert_eq!(big.pending_len(), 2);
    }

    /// W3: expiry is FIFO (the oldest payloads age out first) and exactly one
    /// `NO_EGRESS` loss is booked per expired payload.
    #[test]
    fn pending_hold_expires_oldest_first_and_books_each_loss() {
        let mut up = UplinkFlows::new();
        let addr: SocketAddr = "198.51.100.9:53".parse().unwrap();
        let t0 = mono_millis();
        assert!(up.pending.try_push(&TargetAddrRef::Ip(addr), b"old", t0));
        assert!(
            up.pending
                .try_push(&TargetAddrRef::Ip(addr), b"new", t0 + PENDING_TTL_MS / 2)
        );
        // Nothing is old enough yet.
        assert_eq!(up.pending.expire(t0 + PENDING_TTL_MS / 2), 0);
        assert_eq!(up.pending.len(), 2);
        // At exactly the TTL the head expires; the younger one stays.
        assert_eq!(up.pending.expire(t0 + PENDING_TTL_MS), 1);
        assert_eq!(up.pending.len(), 1);
        assert_eq!(up.pending.expire(t0 + 2 * PENDING_TTL_MS), 1);
        assert!(up.pending.is_empty());
        assert_eq!(up.pending.bytes, 0);
        // Booking is one `NO_EGRESS` loss and one reason counter per payload.
        // Both counters are process-wide while the test binary runs tests in
        // parallel, so these are lower bounds (the inline `expire` calls above
        // deliberately book nothing — that is `expire_pending`'s job).
        let before_drops = dgram_drops::snapshot();
        let before_counters = counters::snapshot();
        book_hold_loss(2, "test");
        assert!(dgram_drops::snapshot().since(&before_drops).no_egress >= 2);
        assert!(counters::since(&before_counters).egress_hold_stale >= 2);
    }
}
