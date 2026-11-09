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
use myquic2::udp::r2_stage::R2_STAGE_MAX_BYTES;
use myquic2::udp::r2_stage::{DirectSend, try_send_direct};
use myquic2::udp::{
    R2DrainAttempt, R2DrainOutcome, R2Fragmenter, R2StageItem, R2StageKind, R2Stager,
    drain_session_staged, drain_staged, try_drain_staged,
};
use std::collections::VecDeque;

/// Milliseconds of the path's own rate that the tuned preset admits ahead of
/// quinn's pacer.
///
/// The budget is `cwnd / srtt × this`, so it tracks the link the connection
/// actually has: 8 KiB (the floor) at 2 Mbps, about 125 KB at 100 Mbps, and the
/// whole stager past ~1 Gbps. That is the shape a fixed byte cap cannot express
/// — the same 256 KiB queue is a second of delay on a phone uplink and two
/// milliseconds on a LAN.
///
/// `cwnd` is an upper bound on the rate, not the rate itself: the BBR preset
/// targets two bandwidth-delay products, so the estimate runs about twice the
/// bottleneck rate and the real bound is nearer twenty milliseconds. That
/// direction is deliberate — the window is a ceiling on *queueing*, and `srtt`
/// rising under bufferbloat pulls it back down. `0` disables the cap; the bulk
/// preset always runs with `0` (see [`ConnRev2::configure_queue_window`]),
/// because a bulk flow is throughput-oriented and its DATAGRAM buffer is the
/// intended burst sink.
///
/// The window covers both paths that can put a payload in that buffer: staged
/// payloads (`stage_or_count`) and standalone payloads above `BATCH_SMALL_MAX`
/// (`admit_standalone`), whether they fit one frame or need fragmentation.
/// Without the latter, the largest packets — the ones that fill the buffer
/// fastest — would bypass the cap entirely.
pub(crate) const UDP_QUEUE_WINDOW_MS: u32 = 10;

/// Floor for the queue window's byte budget.
///
/// A congestion event collapses `cwnd` for a few RTTs. Without a floor the
/// budget would shrink to a few hundred bytes exactly while the path is
/// recovering, and one loss would turn into a run of deliberate drops. Eight
/// kilobytes is a handful of MTU-sized datagrams — enough to keep a burst
/// flowing, still below any queue that could add a visible delay at the rates
/// that reach the floor.
pub(crate) const UDP_QUEUE_FLOOR_BYTES: usize = 8 * 1024;

/// Minimum spacing between queue-window samples.
///
/// A sample calls `Connection::stats()`, which takes the connection state lock;
/// once per quarter second is invisible, once per datagram is not, and a
/// quarter second is still short against a congestion window that moves over
/// RTTs.
const QUEUE_SAMPLE_MS: u64 = 250;

/// Optimistic admission cache for quinn's DATAGRAM send-buffer space.
///
/// `Connection::datagram_send_buffer_space()` takes the connection-state mutex,
/// and the driver holds that same mutex across `process_conn_events` and up to
/// `MAX_TRANSMIT_DATAGRAMS` socket sends. On the sharded topology producer and
/// driver share one thread, so the probe is merely a lock tax; with
/// `MYQUIC2_SHARD_RUNTIME=0` it can park a worker for tens of microseconds —
/// once per payload, on the path whose purpose is latency.
///
/// The cache keeps the last exact reading and subtracts every byte admitted
/// since. Admitted bytes are >= bytes actually handed to quinn, and the driver
/// only ever *adds* space between samples, so [`Self::space`] is a **lower
/// bound** on the true space — equivalently, the derived occupancy is an upper
/// bound on the real one.
///
/// That direction is what makes the cache safe: a cached *fits* is therefore
/// also true of the exact reading, and a cached *does not fit* falls through to
/// an exact probe before the policy drop. Admission decisions are identical to
/// the unconditional-probe rule; only the number of probes changes — skipped
/// while the answer is unambiguous, taken as before while the queue is near or
/// over budget. A backlog makes the estimate more conservative (bytes still in
/// the stager are counted both there and in `since`), which costs probes, not
/// payloads.
///
/// Two limits on that statement. The bound is exact only against the state at
/// which the loaded word was produced: a relaxed load may return an older word
/// than another thread's latest admission, so on the shared runtime an
/// unobserved concurrent admission can still overshoot — exactly the
/// check-then-act window the unconditional probe already had, not a new one.
/// On the sharded default every admission runs on the connection's own thread,
/// so the loaded word is always current and the bound is literal.
///
/// This is deliberately *not* the reverted "backlog-only" gate (§23.1): that
/// skipped the occupancy term entirely on a slow path whose quinn buffer sat
/// above the window. Here the occupancy term is a real recent sample of the
/// same quantity; only its age is bounded.
#[derive(Debug, Default)]
struct SpaceCache {
    /// `(hint << 32) | since`.
    ///
    /// One packed word rather than two atomics: a reader must never pair a
    /// fresh hint with a stale `since` — that is the one combination that
    /// could over-admit — and two relaxed stores to separate locations may
    /// become visible in either order on a weak-memory target. Packing makes
    /// the pair a single atomic load. The capacity is at most a few MiB
    /// (1 MiB tuned / 2 MiB bulk), so 32 bits is ample for each half.
    packed: std::sync::atomic::AtomicU64,
}

/// Low half of [`SpaceCache::packed`]: payload bytes admitted since the hint.
const SINCE_MASK: u64 = u32::MAX as u64;

impl SpaceCache {
    /// Conservative estimate of the buffer space currently available.
    ///
    /// Never larger than the true space (see the type's note), so it can only
    /// make the window stricter.
    #[inline]
    fn space(&self) -> usize {
        let v = self.packed.load(std::sync::atomic::Ordering::Relaxed);
        let hint = (v >> 32) as usize;
        let since = (v & SINCE_MASK) as usize;
        hint.saturating_sub(since)
    }

    /// Account one payload that admission just accepted.
    #[inline]
    fn note_admitted(&self, len: usize) {
        // Saturating at the half-word keeps the offset from carrying into the
        // hint. The counter can only reach that bound if the hint itself were
        // 4 GiB, which the transport never configures.
        let len = (len as u64).min(SINCE_MASK);
        let mut v = self.packed.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let since = (v & SINCE_MASK).saturating_add(len).min(SINCE_MASK);
            let new = (v & !SINCE_MASK) | since;
            match self.packed.compare_exchange_weak(
                v,
                new,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(cur) => v = cur,
            }
        }
    }

    /// The word to pass back to [`Self::resample`] with a probe taken after it.
    #[inline]
    fn observe(&self) -> u64 {
        self.packed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Publish a fresh exact reading, unless a concurrent admission landed
    /// while the probe was in flight.
    ///
    /// A plain store would reset the offset to zero and erase that admission's
    /// accounting — the one way this cache could over-admit. The CAS makes the
    /// publish conditional on nothing having changed since [`Self::observe`];
    /// on a lost race the old (stale, conservative) sample stays and the next
    /// payload probes again. On the sharded topology every admission runs on
    /// the connection's own thread, so this CAS never loses.
    #[inline]
    fn resample(&self, observed: u64, space: usize) {
        debug_assert!(
            space <= u32::MAX as usize,
            "DATAGRAM send buffer exceeds 4 GiB"
        );
        let hint = (space as u64).min(u64::from(u32::MAX));
        let _ = self.packed.compare_exchange(
            observed,
            hint << 32,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Forget the sample (a new dial reconfigures the transport).
    #[inline]
    fn clear(&self) {
        self.packed.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

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

/// Depth of the rev3 outbound control queue (see
/// [`ConnRev2::send_ctl`]).
///
/// The queue only ever holds messages the peer has not been sent yet, and the
/// producer is the packet path — one `REJECT` per binding frame this side
/// refuses, i.e. at the peer's rate — while the consumer is a reliable stream
/// serialized by the peer's flow control. Bounding it turns a peer that floods
/// refused frames and stops reading into dropped idempotent notices instead of
/// process memory growth; the counter (`ctl_queue_full`) is what makes that
/// visible. The same number the server uses for its inbound handoff
/// (`CTL_IN_QUEUE`), so both ends of the control plane are sized alike.
pub(crate) const CTL_QUEUE: usize = 64;

/// How long the connection's stager-retry task waits before retrying a drain
/// that left payloads queued behind a full DATAGRAM send buffer.
///
/// This is the client-side tail bound for request/response traffic: a DNS
/// query or a game tick whose frame found the shared send buffer full must not
/// wait for the next uplink packet. Two milliseconds is below a DNS retry or a
/// game tick, and the timer only runs while the stager is non-empty.
const STAGE_RETRY_DELAY: Duration = Duration::from_millis(2);

/// Immediate re-tries of a `Busy` drain before the retry task sleeps.
///
/// A `Busy` verdict means another thread holds the stager mutex or the drain
/// gate for a few instructions — a forward listener's burst push, or a
/// cross-thread failover producer. Sleeping [`STAGE_RETRY_DELAY`] for that
/// would turn a microsecond of contention into two milliseconds of added
/// latency on exactly the notify-driven path this task exists for, so it
/// yields and re-probes a few times first. Past the bound the holder is a real
/// drainer making progress, and sleeping is the right answer.
const STAGE_BUSY_SPINS: u32 = 4;

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
    /// Targets the server rejected with `CTL FLOW_REJECT` / rev3 `REJECT`,
    /// with their window start and reason-selected TTL (see
    /// [`REJECT_TTL_TRANSIENT_MS`] / [`REJECT_TTL_POLICY_MS`]).
    rejected: parking_lot::RwLock<Vec<RejectedTarget>>,
    /// rev3 outbound control messages: the generation's control-stream task
    /// owns the stream and accepts messages here (see [`Self::send_ctl`]).
    /// `None` on rev2 and until the dispatcher installs the writer.
    ///
    /// **Bounded** ([`CTL_QUEUE`]): the queue is filled from the packet path,
    /// one message per refused binding frame, i.e. at the peer's send rate,
    /// while it drains at the rate the peer reads the reliable stream. An
    /// unbounded channel let a peer that keeps sending frames this side refuses
    /// and never reads the control stream grow it for the connection's
    /// lifetime. `try_send` + a drop counter is the same policy the server's
    /// `R2ConnState::queue_ctl` applies to its side of the same plane.
    ctl_tx: parking_lot::Mutex<Option<tokio::sync::mpsc::Sender<CtlMessage>>>,
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
    /// Wakes the connection's stager-retry task when a drain leaves payloads
    /// queued (the DATAGRAM send buffer was full). One task per connection
    /// retries the shared stager, so a one-shot request/response flow does not
    /// have to wait for the owner association's next uplink packet.
    stage_retry: tokio::sync::Notify,
    /// Milliseconds of path rate the uplink queue may hold; `0` disables the
    /// cap (bulk preset). Armed per dial by
    /// [`Self::configure_queue_window`], read with one relaxed load per
    /// admitted payload.
    queue_window_ms: std::sync::atomic::AtomicU32,
    /// DATAGRAM send-buffer bytes the transport was built with. quinn exposes
    /// only the setter, so the value rides in with the window
    /// ([`myquic2::transport::datagram_send_buffer_bytes`]); it turns
    /// `datagram_send_buffer_space()` into an occupancy figure.
    dg_send_bytes: std::sync::atomic::AtomicUsize,
    /// Conservative cache of the latest exact send-buffer space reading, so
    /// the steady admission path does not take the connection state lock for
    /// every payload (see [`SpaceCache`]).
    dg_space: SpaceCache,
    /// Last sampled byte budget (`cwnd / srtt × window`, clamped). `0` means
    /// "not sampled yet", which admits everything rather than stalling a
    /// connection that has no rate estimate.
    queue_cap_bytes: std::sync::atomic::AtomicUsize,
    /// `mono_millis()` of the last sample (see [`QUEUE_SAMPLE_MS`]).
    queue_sampled_ms: std::sync::atomic::AtomicU64,
    /// Mirror of the stager's `queued_bytes`, published after each push/drain
    /// so admission reads it without taking the stager mutex. A stale-high
    /// value after a `drop_session`/`drop_flow` is conservative (it refuses or
    /// probes, never over-admits); a drain refreshes it.
    staged_bytes: std::sync::atomic::AtomicUsize,
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
            rejected: parking_lot::RwLock::new(Vec::new()),
            ctl_tx: parking_lot::Mutex::new(None),
            ctx_repair_rate: parking_lot::Mutex::new(ctl_stream::CtlRate::default_budget()),
            handshake_done: std::sync::atomic::AtomicBool::new(false),
            stage_retry: tokio::sync::Notify::new(),
            queue_window_ms: std::sync::atomic::AtomicU32::new(0),
            dg_send_bytes: std::sync::atomic::AtomicUsize::new(
                myquic2::transport::datagram_send_buffer_bytes(false),
            ),
            dg_space: SpaceCache::default(),
            queue_cap_bytes: std::sync::atomic::AtomicUsize::new(0),
            queue_sampled_ms: std::sync::atomic::AtomicU64::new(0),
            staged_bytes: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Arm the uplink queue window for this connection generation.
    ///
    /// `window_ms` is milliseconds of path rate (`0` disables the cap) and
    /// `dg_send_bytes` the DATAGRAM send buffer the transport was built with
    /// ([`myquic2::transport::datagram_send_buffer_bytes`]). Called once per
    /// dial from the transport preset and before the connection is published,
    /// so no send can observe a half-armed window.
    pub(crate) fn configure_queue_window(&self, window_ms: u32, dg_send_bytes: usize) {
        self.queue_window_ms
            .store(window_ms, std::sync::atomic::Ordering::Relaxed);
        self.dg_send_bytes
            .store(dg_send_bytes, std::sync::atomic::Ordering::Relaxed);
        self.queue_cap_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.dg_space.clear();
    }

    /// Whether one more `len`-byte payload fits this connection's uplink queue
    /// window, with `batched` bytes already waiting in the association's
    /// pre-stager batch.
    ///
    /// Bounds *queueing delay*, not throughput: what is already waiting is the
    /// stager's backlog plus quinn's DATAGRAM send buffer, and the budget is
    /// [`UDP_QUEUE_WINDOW_MS`] of the path's own rate. A fast, healthy path
    /// never reaches it; a connection whose queue would otherwise sit for
    /// hundreds of milliseconds refuses the *newest* payload instead — the
    /// trade UDP recommends for exactly this case, and the one quinn itself
    /// makes when the buffer is full.
    ///
    /// The window is one aggregate FIFO: there is no per-flow isolation, so a
    /// neighbour that fills it can also cost an interactive flow a payload.
    /// That is the shared-queue trade P3-9 describes, bounded in time.
    ///
    /// Cost per call is the stager probe (a short `parking_lot` hold) and, only
    /// when the cached estimate would refuse, one
    /// `datagram_send_buffer_space()` read — which takes the connection state
    /// lock. It runs once per UDP payload, never per encoded frame.
    ///
    /// The state lock is quinn's, and its driver holds that same mutex across
    /// `process_conn_events` and up to `MAX_TRANSMIT_DATAGRAMS` socket sends, so
    /// a probe racing a busy driver can park this producer. A previous revision
    /// tried to skip the probe while the stager backlog alone was under half the
    /// window; that is not a sound substitution. The invariant is the *combined*
    /// occupancy (stager + quinn's unsent DATAGRAM bytes), and a slow path keeps
    /// quinn's 1 MiB buffer above the window on its own — exactly the state the
    /// window exists to shed.
    ///
    /// The probe is therefore still the source of truth, but it is no longer
    /// paid per payload: [`SpaceCache`] keeps the last exact reading and only
    /// the bytes admitted since, a lower bound on the true space. A payload the
    /// estimate admits is admitted with no lock (a conservative *fits* is also
    /// true exactly); one it refuses falls through to the exact probe — which
    /// also re-samples — before any policy drop. The admitted set is therefore
    /// unchanged; only the lock count is.
    ///
    /// `wire_len` is the encoded DATAGRAM body length (payload plus the exact
    /// MQP frame header), not the raw payload: quinn's buffer charges the body,
    /// so charging the payload alone let the window be overrun by every header
    /// and by uncounted control frames (ECHO review L7).
    ///
    /// `true` when the window is disabled or no rate has been sampled yet.
    #[must_use]
    pub(crate) fn admit_uplink(
        &self,
        conn: &quinn::Connection,
        wire_len: usize,
        batched: usize,
    ) -> bool {
        let Some(cap) = self.queue_window_cap(conn) else {
            return true;
        };
        let capacity = self
            .dg_send_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let staged = self.staged_bytes.load(std::sync::atomic::Ordering::Relaxed);
        if fits_queue_window(
            cap,
            capacity,
            self.dg_space.space(),
            staged,
            batched,
            wire_len,
        ) {
            self.dg_space.note_admitted(wire_len);
            return true;
        }
        let observed = self.dg_space.observe();
        let space = conn.datagram_send_buffer_space();
        self.dg_space.resample(observed, space);
        if fits_queue_window(cap, capacity, space, staged, batched, wire_len) {
            self.dg_space.note_admitted(wire_len);
            true
        } else {
            false
        }
    }

    /// Queue-window admission for a payload sent through the standalone path.
    ///
    /// Payloads above [`BATCH_SMALL_MAX`] do not enter the stager; they are
    /// encoded and handed to quinn directly (one DATA frame, or the fragmenter
    /// when they exceed it). They still share the connection's DATAGRAM send
    /// buffer, so the same ten-millisecond budget must cover them. The caller flushes the burst batch first, so there is no
    /// pre-stager occupancy (`batched == 0`); the stager's own backlog still
    /// counts, because those items are waiting for the same buffer.
    ///
    /// One exception: a payload larger than the whole window is judged by the
    /// backlog it would join, not by its own size. A 60 KiB datagram on a slow
    /// link is one payload, not a backlog, and refusing it would make large UDP
    /// payloads impossible there. It is admitted while the existing backlog is
    /// within the window and refused once a previous payload has pushed the
    /// queue over it.
    #[must_use]
    pub(crate) fn admit_standalone(&self, conn: &quinn::Connection, wire_len: usize) -> bool {
        let Some(cap) = self.queue_window_cap(conn) else {
            return true;
        };
        // The combined bound, exactly as `admit_uplink`: the stager backlog
        // alone cannot stand in for quinn's occupancy (see that function's
        // note on the cached estimate and its conservatism).
        let capacity = self
            .dg_send_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let staged = self.staged_bytes.load(std::sync::atomic::Ordering::Relaxed);
        if fits_standalone_window(cap, capacity, self.dg_space.space(), staged, wire_len) {
            self.dg_space.note_admitted(wire_len);
            return true;
        }
        let observed = self.dg_space.observe();
        let space = conn.datagram_send_buffer_space();
        self.dg_space.resample(observed, space);
        if fits_standalone_window(cap, capacity, space, staged, wire_len) {
            self.dg_space.note_admitted(wire_len);
            true
        } else {
            false
        }
    }

    /// Charge one control DATAGRAM (`HELLO`, `FLOW_ACK_SRC`, `SESS_CLOSE`)
    /// against the DATAGRAM buffer estimate.
    ///
    /// Control frames bypass the stager and were previously invisible to
    /// `SpaceCache`; enough of them could make a cached "fits" false. Only a
    /// successfully queued frame is charged (a refused one occupies nothing).
    pub(crate) fn note_control_sent(&self, wire_len: usize) {
        self.dg_space.note_admitted(wire_len);
    }

    /// Current queue-window byte budget, or `None` while the cap is disabled
    /// (bulk preset) or no rate has been sampled yet.
    fn queue_window_cap(&self, conn: &quinn::Connection) -> Option<usize> {
        let window_ms = self
            .queue_window_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if window_ms == 0 {
            return None;
        }
        self.refresh_queue_cap(conn, window_ms);
        let cap = self
            .queue_cap_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        (cap != 0).then_some(cap)
    }

    /// Re-sample [`Self::queue_cap_bytes`] from the live path.
    ///
    /// Throttled to one `stats()` per [`QUEUE_SAMPLE_MS`]: that call takes the
    /// connection state lock, so it must not ride the per-payload path.
    fn refresh_queue_cap(&self, conn: &quinn::Connection, window_ms: u32) {
        let now = mono_millis();
        let last = self
            .queue_sampled_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < QUEUE_SAMPLE_MS {
            return;
        }
        self.queue_sampled_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
        let path = conn.stats().path;
        self.queue_cap_bytes.store(
            queue_window_bytes(path.cwnd, path.rtt, window_ms),
            std::sync::atomic::Ordering::Relaxed,
        );
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
    pub(crate) fn install_ctl_writer(&self, tx: tokio::sync::mpsc::Sender<CtlMessage>) {
        *self.ctl_tx.lock() = Some(tx);
    }

    /// Queue one rev3 control message for the reliable control stream.
    ///
    /// Non-blocking by design: the packet path (dispatcher, association exit)
    /// must never await an I/O write. The generation's control task owns the
    /// stream and writes messages in queue order; QUIC supplies reliability, so
    /// there is no app-level repeat.
    ///
    /// The queue is bounded at [`CTL_QUEUE`], so a full one drops the message
    /// and counts `ctl_queue_full` rather than growing without bound. Only
    /// `REJECT`/`NEED_CONTEXT` notices can reach the full queue in practice
    /// (they are produced at the peer's frame rate and are re-derivable from
    /// the frames that follow), and dropping one costs the peer a retry —
    /// `ASSOC_CLOSE` would fall back to the server's idle sweep. `false` means
    /// no writer is installed (rev2, or the generation's dispatcher has not
    /// run), the task is gone, or the queue was full; callers treat it as a
    /// dropped (idempotent) message.
    pub(crate) fn send_ctl(&self, msg: CtlMessage) -> bool {
        if self.wire != Wire::Rev3 {
            return false;
        }
        match self.ctl_tx.lock().as_ref() {
            Some(tx) => match tx.try_send(msg) {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    counters::ctl_queue_full();
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            },
            None => false,
        }
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
    /// Test seam for the single-push shape; the association path stages a
    /// whole burst through [`Self::push_stage_batch`].
    #[cfg(test)]
    pub(crate) fn push_stage(&self, item: R2StageItem) -> Result<usize, R2StageItem> {
        let mut st = self.stager.lock();
        let result = st.push(item);
        self.staged_bytes
            .store(st.queued_bytes(), std::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Queue a whole burst of small payloads with one lock hold.
    ///
    /// The association stages every small payload of a receive burst here and
    /// pushes it only at the burst boundary, so the shared stager mutex is
    /// acquired once per burst instead of once per datagram. Items that do not
    /// fit remain in `items` for the caller's drain-and-retry; the accepted
    /// ones are counted on this side so the burst path does not pay one
    /// counter call per item.
    pub(crate) fn push_stage_batch(&self, items: &mut Vec<R2StageItem>) -> Result<usize, usize> {
        let before = items.len();
        let result = {
            let mut st = self.stager.lock();
            let result = st.push_batch(items);
            self.staged_bytes
                .store(st.queued_bytes(), std::sync::atomic::Ordering::Relaxed);
            result
        };
        for _ in 0..before - items.len() {
            counters::stage_push();
        }
        result
    }

    /// Drain only `session`'s queued items; other sessions keep their backlog.
    ///
    /// The large-standalone-payload ordering requirement is per session; the
    /// connection-wide drain made one large datagram flush up to 1024 items
    /// from unrelated associations (ECHO review L6).
    pub(crate) fn drain_session_stage(
        &self,
        conn: &quinn::Connection,
        limit: usize,
        session: u32,
    ) -> R2DrainOutcome {
        let outcome = drain_session_staged(conn, &self.stager, session, limit);
        if let Some(st) = self.stager.try_lock() {
            self.staged_bytes
                .store(st.queued_bytes(), std::sync::atomic::Ordering::Relaxed);
        }
        outcome
    }

    /// Two-phase drain of the connection's queued payloads.
    ///
    /// Each batch packs a bounded number of frames under one short lock hold;
    /// the QUIC writes happen outside it. The loop keeps draining until the
    /// queue is empty, the item budget for one call is spent, or a send fails.
    /// On a failure the unsent tail is requeued behind a fresh hold, so a full
    /// send buffer can never make every subsequent payload re-encode the whole
    /// queue. Claim and send are serialised per connection by the stager's
    /// drain gate (see `r2_stage::drain_staged`): two drainers — this path and
    /// the connection retry task — must not reorder each other's frames, since a
    /// later claim overtaking an earlier send would reorder one association's
    /// FIFO.
    pub(crate) fn drain_stage(&self, conn: &quinn::Connection, limit: usize) -> R2DrainOutcome {
        let outcome = drain_staged(conn, &self.stager, limit, |at| {
            counters::stage_full();
            let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
            warn_stage_full(n, at);
        });
        // The drain is the only writer; once it releases the lock, a non-empty
        // queue means the send buffer is full or the budget ran out. Wake the
        // per-connection retry task instead of waiting for the next app packet.
        //
        // `try_lock` on purpose: this runs on an association task, and a
        // blocking acquisition here would serialise the association behind the
        // drainer it is trying to notify. A lost race means somebody else is
        // inside the queue right now, so notifying is the safe answer either
        // way; the retry task tolerates an empty queue (one drain that finds
        // nothing).
        let has_backlog = match self.stager.try_lock() {
            Some(st) => {
                self.staged_bytes
                    .store(st.queued_bytes(), std::sync::atomic::Ordering::Relaxed);
                !st.is_empty()
            }
            None => true,
        };
        if has_backlog {
            self.stage_retry.notify_one();
        }
        outcome
    }

    /// Non-blocking drain for the retry task (see [`Self::spawn_stage_retry`]).
    ///
    /// This path runs on the slot's pinned current-thread runtime, which the
    /// slot's QUIC endpoint driver also runs on, so it must never block:
    /// contention is reported as [`R2DrainAttempt::Busy`] and retried on the
    /// next cadence. Accounting is the same as [`Self::drain_stage`]'s.
    pub(crate) fn try_drain_stage(&self, conn: &quinn::Connection, limit: usize) -> R2DrainAttempt {
        let attempt = try_drain_staged(conn, &self.stager, limit, |at| {
            counters::stage_full();
            let n = dgram_drops::bump(&dgram_drops::BUFFER_FULL);
            warn_stage_full(n, at);
        });
        if attempt.is_complete()
            && let Some(st) = self.stager.try_lock()
        {
            self.staged_bytes
                .store(st.queued_bytes(), std::sync::atomic::Ordering::Relaxed);
        }
        attempt
    }

    /// Whether the stager is known to be empty, without blocking.
    ///
    /// `false` for a contended stager: a producer holds it for a couple of
    /// instructions, and "unknown" must not be read as "drained" by the retry
    /// task.
    pub(crate) fn stage_known_empty(&self) -> bool {
        matches!(self.stager.try_lock().as_deref(), Some(st) if st.is_empty())
    }

    /// Spawn the connection's stager-retry task.
    ///
    /// Association burst-ends drain on their own path; a drain that leaves
    /// payloads queued wakes this task instead of waiting for the next app
    /// packet ([`Self::drain_stage`] notifies). It is per connection (not per
    /// association) because the stager is shared, and it exits with `conn`.
    /// Without it, a one-shot DNS query that hit a full send buffer had to wait
    /// for the next uplink packet, which for a request/response flow may never
    /// come.
    ///
    /// The task drains *before* it sleeps: the wakeup already proves frames are
    /// queued, and the common case — the send buffer had space again by the
    /// time the wakeup ran — is then served without the old unconditional
    /// [`STAGE_RETRY_DELAY`] of added latency. It drains with
    /// [`Self::try_drain_stage`] and probes emptiness with
    /// [`Self::stage_known_empty`], never with a blocking lock: this task
    /// shares its thread with the endpoint driver.
    pub(crate) fn spawn_stage_retry(self: &Arc<Self>, conn: quinn::Connection) {
        let rev2 = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = conn.closed() => return,
                    _ = rev2.stage_retry.notified() => {}
                }
                loop {
                    let mut busy_spins = 0u32;
                    let attempt = loop {
                        let Some(limit) = conn.max_datagram_size() else {
                            // None means the peer never negotiated DATAGRAM, so no
                            // retry can ever send. Account the queued payloads as
                            // egress death instead of leaving them for teardown.
                            let _ = rev2.clear_stage();
                            return;
                        };
                        let limit = rev2.frame_limit(limit);
                        let attempt = rev2.try_drain_stage(&conn, limit);
                        if attempt.is_busy() && busy_spins < STAGE_BUSY_SPINS {
                            busy_spins += 1;
                            tokio::task::yield_now().await;
                            continue;
                        }
                        break attempt;
                    };
                    if !attempt.is_busy() {
                        counters::stage_retry();
                    }
                    if attempt.is_complete() && rev2.stage_known_empty() {
                        break;
                    }
                    // Still backpressured, or another drainer holds the gate:
                    // the blocked send buffer is the only reason to wait, and
                    // the cadence below is a recovery tail, not the steady path.
                    tokio::select! {
                        _ = conn.closed() => return,
                        _ = tokio::time::sleep(STAGE_RETRY_DELAY) => {}
                    }
                }
            }
        });
    }

    /// Number of payloads currently queued on this connection.
    #[must_use]
    pub(crate) fn stage_len(&self) -> usize {
        self.stager.lock().len()
    }

    /// Wake this connection's stager-retry task.
    ///
    /// A producer that has pushed frames but must not drain them on its own
    /// thread calls this: the retry task runs on the slot runtime, next to the
    /// endpoint driver, so the encode and the `send_datagram` calls (and the
    /// connection-state mutex they take) stay on the driver's thread. The
    /// notify is harmless when a drain is already in flight — `Notify` stores
    /// a permit for the next wait — and a connection without the task (unit
    /// fixtures) simply keeps the permit.
    pub(crate) fn request_drain(&self) {
        self.stage_retry.notify_one();
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
        let hello_len = hello.len();
        match try_send_datagram(conn, hello) {
            // The datagram queue is full (a fresh connection usually is not):
            // HELLO is idempotent, the next tick retries it.
            DatagramSend::Sent => rev2.note_control_sent(hello_len),
            DatagramSend::Blocked | DatagramSend::TooLarge => {}
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
        let hello_len = hello.len();
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
                DatagramSend::Sent => {
                    rev2.note_control_sent(hello_len);
                    counters::hello_tx();
                }
                DatagramSend::Blocked | DatagramSend::TooLarge => {
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
pub(crate) fn r2_send_ctl(
    rev2: &ConnRev2,
    conn: &quinn::Connection,
    ctl: &r2::Ctl,
) -> DatagramSend {
    let body = r2::encode_ctl(ctl);
    let len = body.len();
    let verdict = try_send_datagram(conn, body);
    if verdict == DatagramSend::Sent {
        rev2.note_control_sent(len);
    }
    verdict
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
        None => bind.and_then(|b| pool.slot_ref(pool.udp_global_slot(b.index)).rev2()),
    };
    let reached = cached.as_ref().map(|(_, rev2)| rev2.clone()).or(fallback);
    if let Some(rev2) = &reached
        && epoch != 0
        && rev2.epoch == epoch
    {
        // Release the session's bindings (client-owned and accepted
        // server-owned alike) and any payload still queued for it, so a later
        // drain cannot send frames for a session the server is about to reap.
        // The stager books each dropped payload as an egress death, exactly
        // like a closed connection.
        let _ = rev2.registry.remove_session(sess);
        let _ = rev2.stager.lock().drop_session(sess);
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
                DatagramSend::Sent => {
                    rev2.note_control_sent(frame.len());
                    counters::sess_close_tx();
                }
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
        egress.memo_store(b, generation, &h.cache);
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
    /// This association's `SESS_CLOSE` signal, shared with its hub entry.
    ///
    /// The close is raised by whichever dispatcher received it (rev2 DATAGRAM
    /// or rev3 stream) and consumed here, by the association that owns the
    /// session — never by a connection-wide scan. An unraised signal costs one
    /// relaxed load per uplink payload; see [`CloseSignal`] for why this
    /// replaced the connection-level queue.
    closed: Arc<CloseSignal>,
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
    /// Small payloads staged during the current receive burst, not yet handed
    /// to the connection stager.
    ///
    /// The stager is shared by every association of a connection, so pushing
    /// each payload as it is produced made the same mutex the per-datagram
    /// serialisation point. The caller already processes up to
    /// `LAST_HOP_DRAIN` datagrams per burst, so it keeps them here and pushes
    /// them once with [`ConnRev2::push_stage_batch`] at the burst boundary.
    /// Order is the push order, which is the order [`send_uplink`] produced
    /// the items, so per-session FIFO is unchanged. The buffer is bounded by
    /// [`r2::R2_MAX_TRAIN_ITEMS`] (one train's worth) in `stage_or_count`.
    stage_batch: Vec<R2StageItem>,
    /// Payload bytes held in [`Self::stage_batch`], maintained in step with
    /// every push, flush and drop.
    ///
    /// The queue-window admission runs once per payload and used to sum the
    /// batch (`iter().map(..).sum()`) on every one of them. The batch is at most
    /// one train long, so the sum was small — but it is a second traversal of a
    /// `Vec` on the path whose whole point is one payload's latency, and the
    /// counter is one add on push and one store on flush.
    stage_batch_bytes: usize,
}

impl UplinkFlows {
    /// `closed` is the association's signal from its hub entry
    /// ([`AssocEntry::closed`]); tests that do not exercise `SESS_CLOSE` pass a
    /// fresh [`CloseSignal`].
    ///
    /// Small payloads are batched until the caller's burst boundary; the SOCKS
    /// association and the UDP-forward listeners both flush at that boundary
    /// (`drain_assoc_stage` / `flush_assoc_stage`).
    pub(crate) fn new(closed: Arc<CloseSignal>) -> Self {
        Self {
            flows: SessionFlows::new(),
            epoch: 0,
            closed,
            last: None,
            pending: UplinkPending::default(),
            stage_batch: Vec::new(),
            stage_batch_bytes: 0,
        }
    }

    /// Re-align the association's bindings with the connection generation of
    /// `rev2` (and with a server-side `SESS_CLOSE` for this session).
    ///
    /// A redial invalidates every binding: ids are connection-scoped and the
    /// new connection starts with an empty registry, so the association must
    /// re-`OPEN` its targets on the new wire. Payloads already pushed to the
    /// old connection's stager travel with that connection — it accounts them
    /// when it is torn down; this association never clears another session's
    /// items. The association-local batch has not been pushed yet, so it
    /// cannot travel: it is dropped here and accounted exactly like the old
    /// stager's teardown would have accounted those payloads. A server
    /// `SESS_CLOSE` means the same for this session even on a live connection
    /// (the server reaped the session; a steady frame would name ids it no
    /// longer holds), so the bindings are also removed from the registry and
    /// forgotten.
    ///
    /// The close signal is consumed *before* the epoch check: a redial already
    /// invalidates every binding, so a close raised for the previous
    /// generation is moot, and swallowing it here keeps the flag from leaking
    /// into a future `sync` that might otherwise reset fresh bindings.
    pub(crate) fn sync(&mut self, rev2: &ConnRev2) {
        let closed = self.closed.take();
        if self.epoch != rev2.epoch {
            self.drop_stage_batch();
            self.flows = SessionFlows::new();
            self.epoch = rev2.epoch;
            self.last = None;
            counters::flow_table_reset();
            return;
        }
        if closed {
            self.drop_stage_batch();
            for b in self.flows.iter() {
                b.mark_closed();
                let _ = rev2.registry.remove(b.wire_id);
            }
            self.flows = SessionFlows::new();
            self.last = None;
            counters::session_reset();
        }
    }

    /// Bytes held in [`Self::stage_batch`], for the queue-window admission.
    ///
    /// A maintained counter, not a sum: the admission check runs once per
    /// payload, and a second traversal of the batch there was pure overhead on
    /// the per-datagram path. Every mutation of the batch (push, flush, drop)
    /// updates it.
    fn stage_batch_bytes(&self) -> usize {
        self.stage_batch_bytes
    }

    /// Whether this association holds small payloads that a burst-end drain
    /// still has to push. When it does not, [`drain_assoc_stage`] can skip the
    /// whole gate/stager round trip: nothing of ours is waiting, and whatever
    /// another association staged has its own burst-end drain (or the
    /// connection retry task) to send it.
    #[must_use]
    pub(crate) fn has_staged_batch(&self) -> bool {
        !self.stage_batch.is_empty()
    }

    /// Push this burst's staged items into the connection stager with one lock
    /// hold, draining once if it is full.
    ///
    /// Returns the same shape [`stage_or_count`] returns: at least one frame
    /// when the batch was queued (plus any opportunistic drain's frames), or
    /// the drain verdict (and its frame count) when a drain was needed and
    /// failed. On a still-full queue
    /// after one drain, the remaining items are dropped with the per-payload
    /// `BUFFER_FULL` accounting that the single-push path used, and the first
    /// lost id is reported to the rate-limited warning.
    pub(crate) fn flush_stage(
        &mut self,
        rev2: &ConnRev2,
        conn: &quinn::Connection,
        limit: usize,
    ) -> PayloadSend {
        self.flush_stage_inner(rev2, conn, limit, true)
    }

    /// Push the association batch into the connection stager **without**
    /// draining it here.
    ///
    /// The `[[udp_forward]]` listener runs on the main runtime while the
    /// connection's driver, retry task and other associations live on the
    /// slot runtime; letting the push's opportunistic drain run there carries
    /// the encode, the `send_datagram` calls and quinn's state mutex across
    /// cores (ECHO review L3). On a full queue the batch is left in `up` for
    /// the deferred retry, never dropped: the listener's next deferred tick
    /// retries the push.
    pub(crate) fn flush_stage_no_drain(
        &mut self,
        rev2: &ConnRev2,
        conn: &quinn::Connection,
        limit: usize,
    ) -> PayloadSend {
        self.flush_stage_inner(rev2, conn, limit, false)
    }

    fn flush_stage_inner(
        &mut self,
        rev2: &ConnRev2,
        conn: &quinn::Connection,
        limit: usize,
        allow_drain: bool,
    ) -> PayloadSend {
        if self.stage_batch.is_empty() {
            return PayloadSend {
                frames: 0,
                failed: None,
            };
        }
        // A batch built for an older generation names a session the current
        // server never opened. This is the same loss the old connection's
        // stager books on teardown; `sync` normally drops it earlier, but the
        // epoch can also change between the last send of a burst and its
        // drain.
        if self.epoch != rev2.epoch {
            self.drop_stage_batch();
            return PayloadSend {
                frames: 0,
                failed: None,
            };
        }
        let mut drained = PayloadSend {
            frames: 0,
            failed: None,
        };
        for attempt in 0..2 {
            match rev2.push_stage_batch(&mut self.stage_batch) {
                Ok(queued) => {
                    // The batch moved into the connection stager; the admission
                    // counter's `staged` term now covers it.
                    self.stage_batch_bytes = 0;
                    // Same opportunistic drain as the single-push path: one
                    // train's worth of cross-session items is where the
                    // queue is worth a send even if this burst is over.
                    if allow_drain && queued >= r2::R2_MAX_TRAIN_ITEMS {
                        drained = prefer_severe(drained, drain_conn_stage(rev2, conn, limit));
                    }
                    return match drained.failed {
                        None => PayloadSend {
                            // One frame is queued for the common case; keep the
                            // opportunistic drain's count when it fired.
                            frames: drained.frames.max(1),
                            failed: None,
                        },
                        Some(failed) => PayloadSend {
                            frames: drained.frames,
                            failed: Some(failed),
                        },
                    };
                }
                // Push-only mode: never drain on the listener's thread. The
                // unaccepted tail stays in `stage_batch`; `flush_peer` sees
                // `has_staged_batch()` and arms the deferred retry.
                Err(_) if !allow_drain => {
                    counters::stage_full();
                    self.stage_batch_bytes = self.stage_batch.iter().map(|i| i.payload.len()).sum();
                    return PayloadSend {
                        frames: drained.frames,
                        failed: drained.failed.or(Some(DatagramSend::Blocked)),
                    };
                }
                Err(_) if attempt == 0 => {
                    counters::stage_full();
                    drained = prefer_severe(drained, drain_conn_stage(rev2, conn, limit));
                }
                Err(_) => break,
            }
        }
        let mut total = 0u64;
        let mut first = None;
        // A terminal drain verdict tears the generation down, so these payloads
        // were lost to a dead egress, not to buffer pressure; book them as such
        // (ECHO review L11). A still-full live queue keeps BUFFER_FULL.
        let dead = matches!(
            drained.failed,
            Some(DatagramSend::ConnectionLost | DatagramSend::Unsupported)
        );
        for item in self.stage_batch.drain(..) {
            if first.is_none() {
                first = Some(item.ids());
            }
            total = if dead {
                dgram_drops::bump(&dgram_drops::EGRESS_DEAD)
            } else {
                dgram_drops::bump(&dgram_drops::BUFFER_FULL)
            };
        }
        self.stage_batch_bytes = 0;
        if !dead {
            warn_stage_full(total, first);
        }
        PayloadSend {
            frames: drained.frames,
            failed: drained.failed.or(Some(DatagramSend::Blocked)),
        }
    }

    /// Send a lone staged payload directly, skipping the stager push/drain.
    ///
    /// The one-datagram request/response shape pays the item's payload copy in
    /// `send_uplink`, but the queue round trip (stager push + drain gate +
    /// claim) is pure overhead when there is nothing to pack. `try_send_direct`
    /// requires the connection queue empty and the gate free, so it cannot
    /// overtake an earlier frame; a `NotNow` returns the item to the batch and
    /// the caller falls through to the normal flush/drain.
    pub(crate) fn flush_lone_direct(
        &mut self,
        rev2: &ConnRev2,
        conn: &quinn::Connection,
        limit: usize,
    ) -> Option<PayloadSend> {
        if self.epoch != rev2.epoch || self.stage_batch.len() != 1 {
            return None;
        }
        let item = self.stage_batch.pop()?;
        self.stage_batch_bytes = 0;
        let len = item.payload.len();
        match try_send_direct(&rev2.stager, conn, item, limit) {
            DirectSend::Sent => {
                udp_stats::payload(len);
                Some(PayloadSend {
                    frames: 1,
                    failed: None,
                })
            }
            DirectSend::TooLarge => Some(PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            }),
            DirectSend::Terminal(verdict) => Some(PayloadSend {
                frames: 0,
                failed: Some(verdict),
            }),
            DirectSend::NotNow(item) => {
                self.stage_batch_bytes = item.payload.len();
                self.stage_batch.push(item);
                None
            }
        }
    }

    /// Test-only: seed the association batch directly, without an egress
    /// handle. Used to pin `flush_stage_no_drain`'s push-only contract.
    #[cfg(test)]
    pub(crate) fn test_stage_item(&mut self, item: R2StageItem) {
        self.stage_batch_bytes += item.payload.len();
        self.stage_batch.push(item);
    }

    /// Drop a batch that was built for a connection generation (or a session)
    /// that no longer exists.
    ///
    /// These payloads never reached the stager, so nothing else can account
    /// them; `EGRESS_DEAD` is the same category the stager uses when the
    /// connection's queue is cleared at teardown.
    fn drop_stage_batch(&mut self) {
        let dropped = self.stage_batch.len();
        self.stage_batch.clear();
        self.stage_batch_bytes = 0;
        for _ in 0..dropped {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
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

/// Book a burst batch that never reached the connection stager.
///
/// The normal paths flush at every burst boundary (`drain_assoc_stage` /
/// `flush_assoc_stage`), so this is a safety net for owners that disappear
/// mid-burst — a UDP forward peer evicted by an admission limit between two
/// datagrams of the same burst is the live case. The items were never handed
/// to the stager, so nothing else can account them; `EGRESS_DEAD` is the same
/// category the stager uses when the connection dies with a queue.
impl Drop for UplinkFlows {
    fn drop(&mut self) {
        if !self.stage_batch.is_empty() {
            self.drop_stage_batch();
        }
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
                    egress.memo_store(bind, generation, &h.cache);
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
    up.sync(rev2);
    // The fragmenter is per association but the wire is per connection: pin it
    // on every send (cheap `Copy` field store) so a reconnect onto another
    // revision re-encodes fragments correctly, and rev2 keeps identical bytes.
    frag.set_wire(rev2.wire());
    let limit = rev2.frame_limit(limit);
    // An address that cannot be encoded can never be put on the wire. The
    // legacy fragmenter reported exactly this as a `TooLarge` drop and that is
    // still the right accounting (the app chose an impossible target).
    if addr.header().is_err() {
        let flushed = up.flush_stage(rev2, conn, limit);
        let drained = map_drain_outcome(rev2.drain_session_stage(conn, limit, sess));
        return prefer_severe(prefer_severe(flushed, drained), bad_address_header());
    }
    let Some(binding) = ensure_binding(rev2, up, sess, addr) else {
        counters::inline_fallback();
        if payload.len() > BATCH_SMALL_MAX {
            let flushed = up.flush_stage(rev2, conn, limit);
            let drained = drain_conn_stage(rev2, conn, limit);
            // The window covers one-frame payloads too; without this check the
            // largest packets bypass it and can sit in the send buffer for a
            // path-rate fraction far above the intended ten milliseconds.
            let wire_len = uplink_wire_len(rev2.wire(), None, false, sess, addr, payload.len());
            let sent = if rev2.admit_standalone(conn, wire_len) {
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
                )
            } else {
                over_queue_window(rev2)
            };
            return prefer_severe(prefer_severe(flushed, drained), sent);
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
        return stage_or_count(rev2, conn, limit, up, item);
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
        return stage_or_count(rev2, conn, limit, up, item);
    }
    // Larger than one staged item: flush this burst's batch and drain the
    // connection queue first so this standalone payload cannot overtake a
    // session's earlier small payloads.
    let flushed = up.flush_stage(rev2, conn, limit);
    let drained = map_drain_outcome(rev2.drain_session_stage(conn, limit, sess));
    let wire_len = uplink_wire_len(
        rev2.wire(),
        Some(&binding),
        context,
        sess,
        addr,
        payload.len(),
    );
    let sent = if rev2.admit_standalone(conn, wire_len) {
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
        )
    } else {
        over_queue_window(rev2)
    };
    prefer_severe(prefer_severe(flushed, drained), sent)
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

/// Add one small payload to the association's burst batch.
///
/// The batch is pushed to the shared stager once per receive burst (or when it
/// reaches one train's worth), so the per-payload mutex acquisition and the
/// full-queue retry live in [`UplinkFlows::flush_stage`]. Returns a "queued"
/// [`PayloadSend`] (`frames: 1`, no failure) so the shared recovery path stays
/// quiet; a flush verdict reached through the batch bound is propagated as
/// before.
/// Exact encoded length of `item` on `wire` (see [`ConnRev2::admit_uplink`]).
fn item_wire_len(item: &R2StageItem, wire: Wire) -> usize {
    let payload = item.payload.len();
    match &item.kind {
        R2StageKind::Steady { wire_id } => match wire {
            Wire::Rev2 => r2::data_steady_len(*wire_id, payload),
            Wire::Rev3 => myquic2::mqp::r3::data_steady_len(payload),
        },
        R2StageKind::Open { wire_id, addr, .. } => {
            let addr_len = addr.as_ref().header().map_or(0, |h| h.len());
            match wire {
                Wire::Rev2 => r2::data_open_len(*wire_id, addr_len, payload),
                Wire::Rev3 => myquic2::mqp::r3::data_open_len(addr_len, payload),
            }
        }
        R2StageKind::Inline { addr, .. } => {
            let addr_len = addr.as_ref().header().map_or(0, |h| h.len());
            match wire {
                Wire::Rev2 => r2::data_inline_len(addr_len, payload),
                Wire::Rev3 => myquic2::mqp::r3::data_inline_len(addr_len, payload),
            }
        }
    }
}

/// Exact encoded length of a standalone payload (the same forms as
/// [`item_wire_len`]).
fn uplink_wire_len(
    wire: Wire,
    binding: Option<&Arc<FlowBinding>>,
    context: bool,
    _sess: u32,
    addr: &TargetAddrRef<'_>,
    payload_len: usize,
) -> usize {
    let addr_len = addr.header().map_or(0, |h| h.len());
    match (binding, context) {
        (Some(binding), false) => match wire {
            Wire::Rev2 => r2::data_steady_len(binding.wire_id, payload_len),
            Wire::Rev3 => myquic2::mqp::r3::data_steady_len(payload_len),
        },
        (Some(binding), true) => match wire {
            Wire::Rev2 => r2::data_open_len(binding.wire_id, addr_len, payload_len),
            Wire::Rev3 => myquic2::mqp::r3::data_open_len(addr_len, payload_len),
        },
        (None, _) => match wire {
            Wire::Rev2 => r2::data_inline_len(addr_len, payload_len),
            Wire::Rev3 => myquic2::mqp::r3::data_inline_len(addr_len, payload_len),
        },
    }
}

fn stage_or_count(
    rev2: &ConnRev2,
    conn: &quinn::Connection,
    limit: usize,
    up: &mut UplinkFlows,
    item: R2StageItem,
) -> PayloadSend {
    // The window is checked before the batch grows, so the payload that would
    // push the queue past ten milliseconds of path rate is the one refused. A
    // disabled window (`0`) short-circuits before any lock or `stats()` call.
    let wire_len = item_wire_len(&item, rev2.wire());
    if !rev2.admit_uplink(conn, wire_len, up.stage_batch_bytes()) {
        return over_queue_window(rev2);
    }
    stage_item_admitted(rev2, conn, limit, up, item)
}

/// Push one already-admitted item into the association batch.
fn stage_item_admitted(
    rev2: &ConnRev2,
    conn: &quinn::Connection,
    limit: usize,
    up: &mut UplinkFlows,
    item: R2StageItem,
) -> PayloadSend {
    up.stage_batch_bytes = up.stage_batch_bytes.saturating_add(item.payload.len());
    up.stage_batch.push(item);
    // One train's worth is the bound the single-push path used to fire its
    // opportunistic drain at. A receive burst is smaller than this, so the
    // normal flush point is the caller's burst boundary; a caller that stages
    // outside a burst still cannot grow the buffer without bound.
    if up.stage_batch.len() >= r2::R2_MAX_TRAIN_ITEMS {
        return up.flush_stage(rev2, conn, limit);
    }
    PayloadSend {
        frames: 1,
        failed: None,
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
/// queue stayed full after a drain (the app controls the rate). Reports the
/// session and flow id so the losing association is identifiable from the log
/// alone; the same drop is also visible in the 60 s `stage=…full` counter.
///
/// `None` is a defensive fallback for a caller that could not obtain an id:
/// both live call sites pass `Some`, including the requeue path, which reports
/// the first item it could not take back.
fn warn_stage_full(total: u64, at: Option<(u32, Option<u32>)>) {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).is_none() {
        return;
    }
    match at {
        Some((sess, Some(flow))) => tracing::warn!(
            "udp datagram dropped: connection stage queue full after a drain \
             ({total} so far; session {sess}, flow {flow})"
        ),
        Some((sess, None)) => tracing::warn!(
            "udp datagram dropped: connection stage queue full after a drain \
             ({total} so far; session {sess}, inline)"
        ),
        None => tracing::warn!(
            "udp datagram dropped: connection stage queue full after a drain ({total} so far)"
        ),
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

/// Byte budget for one queue window of a path: `cwnd / srtt × window`, clamped
/// to [`UDP_QUEUE_FLOOR_BYTES`]..=[`R2_STAGE_MAX_BYTES`].
///
/// Pure so the shape is testable without a live connection. The upper clamp is
/// the stager's own byte cap: a window wider than the queue it bounds would be
/// a no-op with extra arithmetic.
#[must_use]
fn queue_window_bytes(cwnd: u64, rtt: Duration, window_ms: u32) -> usize {
    if window_ms == 0 {
        return 0;
    }
    // A sub-millisecond sample would make the rate unbounded; a path cannot be
    // faster than the loopback floor, and one millisecond keeps the division
    // finite.
    let rtt = rtt.max(Duration::from_millis(1));
    let per_second = cwnd as f64 / rtt.as_secs_f64();
    let budget = per_second * (f64::from(window_ms) / 1000.0);
    // Float-to-int casts saturate, so a huge `cwnd` clamps instead of wrapping.
    (budget as usize).clamp(UDP_QUEUE_FLOOR_BYTES, R2_STAGE_MAX_BYTES)
}

/// Whether a `len`-byte payload fits `cap` once the bytes already waiting for
/// the wire are counted.
///
/// Occupancy is derived from the transport's configured buffer and the space
/// the connection still reports. `space > capacity` saturates to zero rather
/// than wrapping, so a capacity plumbed one preset off can only make the window
/// looser, never refuse every payload. Pure so the accounting is testable
/// without a live connection.
#[must_use]
fn fits_queue_window(
    cap: usize,
    capacity: usize,
    space: usize,
    staged: usize,
    batched: usize,
    len: usize,
) -> bool {
    let occupancy = capacity.saturating_sub(space);
    staged
        .saturating_add(occupancy)
        .saturating_add(batched)
        .saturating_add(len)
        <= cap
}

/// Whether a standalone `len`-byte payload may join a queue whose backlog is
/// `staged + occupancy`.
///
/// Unlike [`fits_queue_window`], a payload larger than the whole time budget is
/// judged by the *backlog* it would join, not by its own size: a 60 KiB
/// datagram on a slow link is one payload, not queueing delay, and rejecting it
/// would make large UDP payloads impossible there. Once the existing backlog is
/// over budget, the new payload is refused and the backlog waits for the retry
/// task instead of being deepened.
#[must_use]
fn fits_standalone_window(
    cap: usize,
    capacity: usize,
    space: usize,
    staged: usize,
    len: usize,
) -> bool {
    let occupancy = capacity.saturating_sub(space);
    let queued = staged.saturating_add(occupancy);
    if len > cap {
        queued <= cap
    } else {
        queued.saturating_add(len) <= cap
    }
}

/// A payload refused by the connection's uplink queue window.
///
/// Dropped rather than held: the queue is already longer than
/// [`UDP_QUEUE_WINDOW_MS`] of the path's rate, so retrying it would either add
/// stale data to the same backlog or move the wait from quinn's buffer into the
/// stager. `frames: 0, failed: None` keeps [`recover_send_outcome`] quiet — this
/// is a deliberate policy drop, not a connection fault, and nothing about the
/// egress handle is stale.
fn over_queue_window(rev2: &ConnRev2) -> PayloadSend {
    let cap = rev2
        .queue_cap_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let n = dgram_drops::bump(&dgram_drops::OVER_CAP);
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).is_some() {
        tracing::warn!(
            "udp datagram dropped: the {cap} B uplink queue window is full ({n} so far)"
        );
    }
    PayloadSend {
        frames: 0,
        failed: None,
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
///
/// `up` is the caller's burst batch: `Some` pushes it into the stager first
/// (one lock hold for the whole burst), `None` is the per-datagram forwarder
/// path, which already pushed everything it staged.
pub(crate) fn drain_assoc_stage(
    egress: &SharedEgress,
    pool: &ConnPool,
    bind: UdpBind,
    up: Option<&mut UplinkFlows>,
) {
    let mut up = up;
    let now = coarse_millis();
    let drained = egress.with_fresh(bind, now, |c, limit, rev2| {
        let limit = rev2.frame_limit(limit);
        if let Some(up) = up.as_deref_mut()
            && let Some(sent) = up.flush_lone_direct(rev2, c, limit)
        {
            return sent;
        }
        let flushed = flush_assoc_batch(&mut up, rev2, c, limit);
        prefer_severe(flushed, map_drain_outcome(rev2.drain_stage(c, limit)))
    });
    if let Some(sent) = drained {
        recover_send_outcome(egress, bind, sent);
        return;
    }
    // Generation read before the cached read, the same contract the
    // per-datagram miss path documents.
    let generation = egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    if let Some(h) = egress.acquire(pool, bind, now) {
        egress.memo_store(bind, generation, &h.cache);
        let limit = h.rev2.frame_limit(h.limit);
        let sent = if let Some(up) = up.as_deref_mut()
            && let Some(sent) = up.flush_lone_direct(&h.rev2, &h.conn, limit)
        {
            sent
        } else {
            let flushed = flush_assoc_batch(&mut up, &h.rev2, &h.conn, limit);
            prefer_severe(
                flushed,
                map_drain_outcome(h.rev2.drain_stage(&h.conn, limit)),
            )
        };
        recover_send_outcome(egress, bind, sent);
    }
}

/// Push the caller's burst batch before a drain, if this caller batches.
fn flush_assoc_batch(
    up: &mut Option<&mut UplinkFlows>,
    rev2: &ConnRev2,
    conn: &quinn::Connection,
    limit: usize,
) -> PayloadSend {
    match up {
        Some(up) => up.flush_stage(rev2, conn, limit),
        None => PayloadSend {
            frames: 0,
            failed: None,
        },
    }
}

/// Push this caller's burst batch into the connection stager and wake the
/// connection's retry task, **without** draining here.
///
/// The UDP forward listeners run on the main runtime, while the connection's
/// driver owns a pinned slot runtime. Draining from the listener would carry
/// the encode, the `send_datagram` calls and quinn's connection-state mutex
/// across cores on every burst; notifying the retry task moves that work onto
/// the driver's thread. The batch is still pushed here, so the stager can pack
/// it with other sessions' frames into one `TRAIN`.
///
/// A missing egress handle leaves the batch in `up` for the next burst (its
/// bytes keep counting toward admission); a failed push is accounted exactly
/// like [`drain_assoc_stage`]'s flush. When the connection later dies, the
/// stager books whatever was queued, and `UplinkFlows`'s `Drop` books a batch
/// that never reached it.
pub(crate) fn flush_assoc_stage(
    egress: &SharedEgress,
    pool: &ConnPool,
    bind: UdpBind,
    up: &mut UplinkFlows,
) {
    let now = coarse_millis();
    let flushed = egress.with_fresh(bind, now, |c, limit, rev2| {
        let limit = rev2.frame_limit(limit);
        let sent = up.flush_stage_no_drain(rev2, c, limit);
        rev2.request_drain();
        sent
    });
    if let Some(sent) = flushed {
        recover_send_outcome(egress, bind, sent);
        return;
    }
    // Generation read before the cached read, the same contract the
    // per-datagram miss path documents.
    let generation = egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    if let Some(h) = egress.acquire(pool, bind, now) {
        egress.memo_store(bind, generation, &h.cache);
        let limit = h.rev2.frame_limit(h.limit);
        let sent = up.flush_stage_no_drain(&h.rev2, &h.conn, limit);
        h.rev2.request_drain();
        recover_send_outcome(egress, bind, sent);
    }
}

/// Try to drain a connection's stager **without parking on its drain gate**.
///
/// Teardown needs the stager empty before [`send_sess_close`]: that function
/// calls `drop_session` on the stager, so any frames that were pushed but not
/// yet sent would be discarded. The old `drain_assoc_stage` used the blocking
/// `drain_stage`, which on a UDP-forward listener (main runtime) can park a
/// worker behind the slot-runtime retry task that owns the gate.
///
/// Returns `true` only when the queue was proven empty. On `false` the caller
/// must **skip** the close: a lost `SESS_CLOSE` is harmless (the server's idle
/// sweep is the backstop), while a close sent too early would lose payloads.
/// The connection's retry task was already notified by `flush_assoc_stage` and
/// will finish the drain on the driver's thread.
pub(crate) fn try_drain_connection_stage(
    egress: &SharedEgress,
    pool: &ConnPool,
    bind: UdpBind,
) -> bool {
    let now = coarse_millis();
    let attempt = egress.with_fresh(bind, now, |c, limit, rev2| {
        let limit = rev2.frame_limit(limit);
        try_drain_spins(rev2, c, limit)
    });
    if let Some(drained) = attempt {
        return drained;
    }
    // Generation read before the cached read, the same contract the
    // per-datagram miss path documents.
    let generation = egress.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    let Some(h) = egress.acquire(pool, bind, now) else {
        return false;
    };
    egress.memo_store(bind, generation, &h.cache);
    let limit = h.rev2.frame_limit(h.limit);
    try_drain_spins(&h.rev2, &h.conn, limit)
}

/// A `Busy` verdict means another thread holds the stager or the drain gate
/// for a few instructions. Bound the spin so a teardown never waits on a real
/// drainer; the retry task owns the remaining work.
fn try_drain_spins(rev2: &ConnRev2, conn: &quinn::Connection, limit: usize) -> bool {
    for _ in 0..STAGE_BUSY_SPINS {
        let attempt = rev2.try_drain_stage(conn, limit);
        if attempt.is_busy() {
            std::thread::yield_now();
            continue;
        }
        return attempt.is_complete() && rev2.stage_known_empty();
    }
    false
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
        /// Stager drains retried by the per-connection timer after a drain
        /// left payloads queued behind a full DATAGRAM send buffer.
        stage_retry,
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
        /// rev3: control-stream messages dropped because the outbound queue was
        /// full (`CTL_QUEUE`). A peer that floods frames this side refuses
        /// while not reading the control stream shows up here.
        ctl_queue_full,
        /// rev3: the generation's control-stream task exited (the stream died
        /// while the connection was still up), so the dispatcher retired the
        /// connection instead of keeping a generation without a reliable
        /// control plane. Seen after a hard server restart whose stale
        /// resumption ticket makes the peer reject the client's early data.
        ctl_stream_closed,
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
        stage_retry,
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
        ctl_queue_full,
        ctl_stream_closed,
    }

    impl std::fmt::Display for Rev2Snapshot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "hello={} handshake={}/{}/{} caps={} frames_rx={} ack={}/{} reject={}/{} \
                 close={} sess_close={}/{} flow_open={} srv={}/{} open={} steady={} \
                 inline={}/{} stage={}p/{}d/{}f/{}i/{}x/{}full/{}retry hold={}q/{}f/{}full/{}stale \
                 frag={}/{}/{} unknown_id={} drops={} resets={}/{} ctl={}/{}/{} \
                 r3ctl={}/{} nctx={}/{} aclose={} qfull={}",
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
                self.stage_retry,
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
                self.ctl_queue_full,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_SESSION;

    #[test]
    fn the_queue_window_follows_the_path_rate() {
        // 1 MB/s: ten milliseconds is 10 KB.
        assert_eq!(
            queue_window_bytes(100_000, Duration::from_millis(100), UDP_QUEUE_WINDOW_MS),
            10_000
        );
        // 100 MB/s: 1 MB, clamped to the stager's own byte cap.
        assert_eq!(
            queue_window_bytes(10_000_000, Duration::from_millis(100), UDP_QUEUE_WINDOW_MS),
            R2_STAGE_MAX_BYTES
        );
        // A collapsed cwnd must not shrink the queue below the floor, or one
        // loss would turn into a run of deliberate drops while it recovers.
        assert_eq!(
            queue_window_bytes(1_200, Duration::from_millis(100), UDP_QUEUE_WINDOW_MS),
            UDP_QUEUE_FLOOR_BYTES
        );
        // Zero disables the cap outright (the bulk preset, and the kill switch).
        assert_eq!(
            queue_window_bytes(10_000_000, Duration::from_millis(100), 0),
            0
        );
        // A sub-millisecond sample cannot divide by zero or run away.
        assert_eq!(
            queue_window_bytes(10_000_000, Duration::ZERO, UDP_QUEUE_WINDOW_MS),
            R2_STAGE_MAX_BYTES
        );
    }

    #[test]
    fn the_space_hint_can_only_understate_the_buffer() {
        let cache = SpaceCache::default();
        // Nothing sampled yet: the estimate is zero, so the first payload takes
        // the exact probe rather than trusting a default.
        assert_eq!(cache.space(), 0);
        cache.resample(cache.observe(), 4096);
        assert_eq!(cache.space(), 4096);
        // Every admission only shrinks the estimate; the driver draining the
        // buffer between samples is invisible here, which is what makes the
        // value a lower bound on the true space (it can refuse, never overfill).
        cache.note_admitted(1024);
        assert_eq!(cache.space(), 3072);
        cache.note_admitted(4096);
        assert_eq!(cache.space(), 0, "saturating, never wrapping");
        // A refresh restores the exact reading and resets the offset.
        cache.resample(cache.observe(), 64 * 1024);
        assert_eq!(cache.space(), 64 * 1024);
        cache.clear();
        assert_eq!(cache.space(), 0);
    }

    #[test]
    fn the_hint_refusal_falls_through_to_the_exact_probe() {
        // The two-step decision `admit_uplink` makes, with the arithmetic the
        // probe replaces: a stale-low estimate refuses, the fresh reading
        // admits, and only then is the payload counted as waiting.
        let cache = SpaceCache::default();
        let cap = 10_000;
        let capacity = 1 << 20;
        assert!(!fits_queue_window(cap, capacity, cache.space(), 0, 0, 1200));
        cache.resample(cache.observe(), capacity); // the exact probe: buffer empty
        assert!(fits_queue_window(cap, capacity, cache.space(), 0, 0, 1200));
        cache.note_admitted(1200);
        assert_eq!(cache.space(), capacity - 1200);
    }

    #[test]
    fn a_concurrent_admission_is_not_erased_by_a_resample() {
        let cache = SpaceCache::default();
        cache.resample(cache.observe(), 4096);
        // Thread B admits while thread A is inside the exact probe: A observed
        // the word before B's update, so A's publish must lose the CAS rather
        // than reset the offset and forget those bytes.
        let observed = cache.observe();
        cache.note_admitted(700);
        cache.resample(observed, 3000);
        assert_eq!(
            cache.space(),
            4096 - 700,
            "the lost race keeps the old sample"
        );
        // With no concurrent writer the publish succeeds and re-baselines.
        let observed = cache.observe();
        cache.resample(observed, 3000);
        assert_eq!(cache.space(), 3000);
    }

    #[test]
    fn reconfiguring_the_window_forgets_the_space_hint() {
        let r = ConnRev2::new();
        r.configure_queue_window(UDP_QUEUE_WINDOW_MS, 1 << 20);
        r.dg_space.resample(r.dg_space.observe(), 4096);
        r.dg_space.note_admitted(1024);
        assert_eq!(r.dg_space.space(), 3072);
        // A re-dial reconfigures the transport; a hint measured against the
        // old buffer must not survive into the new one.
        r.configure_queue_window(UDP_QUEUE_WINDOW_MS, 2 << 20);
        assert_eq!(r.dg_space.space(), 0);
    }

    #[test]
    fn a_payload_over_the_window_is_dropped_without_a_failure_verdict() {
        let r = ConnRev2::new();
        r.configure_queue_window(UDP_QUEUE_WINDOW_MS, 1024 * 1024);
        r.queue_cap_bytes
            .store(1024, std::sync::atomic::Ordering::Relaxed);
        let before = dgram_drops::snapshot().over_cap;
        let sent = over_queue_window(&r);
        // A deliberate policy drop: nothing was queued, and no recovery arm
        // (which would invalidate the shared egress handle) may fire.
        assert_eq!(sent.frames, 0);
        assert_eq!(sent.outcome(), DatagramSend::Sent);
        assert_eq!(dgram_drops::snapshot().over_cap, before + 1);
    }

    #[test]
    fn the_window_counts_everything_already_waiting() {
        // 500 B unsent in quinn, 200 B in the stager, 100 B in the batch: a
        // 200 B payload fills a 1 KiB window exactly.
        assert!(fits_queue_window(1000, 1_000_000, 999_500, 200, 100, 200));
        assert!(!fits_queue_window(1000, 1_000_000, 999_500, 200, 100, 201));
        // A capacity plumbed one preset off (space above it) cannot wrap into a
        // huge occupancy and refuse everything.
        assert!(fits_queue_window(1000, 1024, 2048, 0, 0, 1000));
        // Saturating math: a corrupt counter refuses rather than wraps around.
        assert!(!fits_queue_window(1000, 1024, 1024, usize::MAX, 0, 1));
    }

    #[test]
    fn a_standalone_payload_larger_than_the_window_is_admitted_when_alone() {
        // One 60 KiB datagram on a slow link: nothing is queued, so it is one
        // payload, not backlog, and must not be refused by the 8 KiB budget.
        assert!(fits_standalone_window(
            8 * 1024,
            1 << 20,
            1 << 20,
            0,
            60 * 1024
        ));
        // A large payload behind a backlog that is still within the window is
        // admitted too: its own size is not queueing delay.
        assert!(fits_standalone_window(
            8 * 1024,
            1 << 20,
            (1 << 20) - 4 * 1024,
            0,
            60 * 1024
        ));
        // A backlog already over the window is the signal to stop, not the
        // second payload's size.
        assert!(!fits_standalone_window(
            8 * 1024,
            1 << 20,
            (1 << 20) - 60 * 1024,
            0,
            1
        ));
        // A normal payload still obeys the ordinary window while queued.
        assert!(fits_standalone_window(
            8 * 1024,
            1 << 20,
            (1 << 20) - 1024,
            0,
            1024
        ));
        assert!(!fits_standalone_window(
            8 * 1024,
            1 << 20,
            (1 << 20) - 7 * 1024,
            0,
            2 * 1024
        ));
        // Saturating math never wraps into an admission.
        assert!(!fits_standalone_window(1000, 1024, 1024, usize::MAX, 1));
    }

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
    fn close_signal_is_consumed_once() {
        let sig = CloseSignal::new();
        assert!(!sig.take(), "a fresh signal is unraised");
        sig.raise();
        assert!(sig.take(), "raise is visible to take");
        assert!(!sig.take(), "a close is consumed exactly once");
        // Duplicate raises (rev2 sends the frame x3, rev3 retransmits) collapse
        // into one bit: both mean the same session is gone, so the reset must
        // run once and the next sync must not reset fresh bindings again.
        sig.raise();
        sig.raise();
        assert!(sig.take());
        assert!(!sig.take());
    }

    /// The server's `SESS_CLOSE` resets the association that owns the session,
    /// once, on its next uplink sync.
    #[test]
    fn session_close_resets_the_owning_uplinks_bindings() {
        let r = ConnRev2::new();
        let sig = Arc::new(CloseSignal::new());
        let mut up = UplinkFlows::new(sig.clone());
        up.sync(&r);
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let b = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        b.mark_open();

        // Unraised: the steady sync is a no-op.
        up.sync(&r);
        assert_eq!(up.flows.len(), 1);
        assert_eq!(b.state(), FlowState::Open);

        sig.raise();
        up.sync(&r);
        assert!(up.flows.is_empty(), "the bindings are forgotten");
        assert!(up.last.is_none(), "the memo is invalidated with them");
        assert_eq!(b.state(), FlowState::Closed);
        assert!(
            r.registry.get(b.wire_id).is_none(),
            "the dead binding is purged from the shared registry"
        );
        // Consumed: a second sync has nothing left to reset.
        up.sync(&r);
        assert!(up.flows.is_empty());
    }

    #[test]
    fn inline_fallback_when_registry_is_full() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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

    /// N-1: a server-side purge can arrive without its `SESS_CLOSE` ever
    /// reaching this association (the DATAGRAM was lost, or the association was
    /// not live when the dispatcher received it). The shared binding is marked
    /// closed by the purge, so the next uplink must re-open instead of sending
    /// steady frames for an id the server no longer holds.
    #[test]
    fn registry_purge_without_a_close_note_is_recovered() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
        up.sync(&r);
        let addr: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let first = ensure_binding(&r, &mut up, 1, &TargetAddrRef::Ip(addr)).unwrap();
        first.mark_open();
        // The server reaped the session and this association never got the
        // signal: `sync` sees nothing.
        assert_eq!(r.registry.remove_session(1), 1);
        assert_eq!(first.state(), FlowState::Closed);
        up.sync(&r);
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
        let r1 = ConnRev2::new();
        up.sync(&r1);
        assert_eq!(up.epoch, r1.epoch);
        let r2 = ConnRev2::new();
        up.sync(&r2);
        assert_eq!(up.epoch, r2.epoch);
        assert!(up.flows.is_empty());
    }

    #[test]
    fn uplink_memo_serves_the_steady_target_without_a_second_binding() {
        let r = ConnRev2::new();
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        up.sync(&r2);
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut big = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
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
    #[test]
    fn admission_charges_the_encoded_frame_not_just_the_payload() {
        let payload = Bytes::from_static(b"abc");
        let steady = R2StageItem {
            session: 1,
            kind: R2StageKind::Steady { wire_id: 5 },
            payload: payload.clone(),
        };
        assert_eq!(
            item_wire_len(&steady, Wire::Rev2),
            r2::data_steady_len(5, 3),
            "rev2 steady header is part of the buffer charge"
        );
        assert_eq!(
            item_wire_len(&steady, Wire::Rev3),
            myquic2::mqp::r3::data_steady_len(3)
        );
        let addr = TargetAddr::Ip("198.51.100.1:53".parse().unwrap());
        let open = R2StageItem {
            session: 1,
            kind: R2StageKind::Open {
                wire_id: 5,
                sess: 1,
                addr: addr.clone(),
                src: false,
            },
            payload: payload.clone(),
        };
        let addr_len = addr.as_ref().header().unwrap().len();
        assert_eq!(
            item_wire_len(&open, Wire::Rev2),
            r2::data_open_len(5, addr_len, 3)
        );
        assert_eq!(
            uplink_wire_len(Wire::Rev2, None, false, 1, &addr.as_ref(), 3),
            r2::data_inline_len(addr_len, 3)
        );
        let binding = FlowBinding::new_shared(5, 1, addr.clone());
        assert_eq!(
            uplink_wire_len(Wire::Rev2, Some(&binding), false, 1, &addr.as_ref(), 3),
            r2::data_steady_len(5, 3)
        );
    }
}
