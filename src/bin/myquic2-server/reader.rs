//! Per-session UDP reader and session creation.
use super::*;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{FlowBinding, FlowRegistry, FlowState, SessionFlows, SourceMatch};
use myquic2::mqp::wire::{self, Wire};
use myquic2::udp::r2_frag::R2FragFlow;
use myquic2::udp::r2_stage::encode_standalone_item_for;
use myquic2::udp::{
    R2Fragmenter, R2StageItem, R2StageKind, R2Stager, book_too_large, drain_staged,
};

/// Userspace receive buffer per session reader: one full-protocol-cap datagram
/// plus the truncation-detection slack byte (`n == buf.len()` means the kernel
/// truncated, so the length is load-bearing).
pub(crate) const SESS_RECV_BUF_LEN: usize = UDP_RECV_MAX + UDP_RECV_SLACK;

/// Compile-time userspace bound: one reader buffer per session, so the live
/// set can never exceed the session cap times it (~67 MiB worst case).
const _: () = assert!(SESS_RECV_BUF_LEN == UDP_RECV_MAX + UDP_RECV_SLACK);
const _: () = assert!(
    MAX_SESSIONS_GLOBAL * SESS_RECV_BUF_LEN <= 70 * 1024 * 1024,
    "8192 x 8 KiB must stay a bounded worst case"
);

/// Idle session-reader buffers retained per worker thread.
///
/// Each *live* reader holds its buffer for life, so the live set is already
/// bounded by `MAX_SESSIONS_GLOBAL` (`SESS_RECV_BUF_LEN` each, ~67 MiB worst
/// case) and sockets stay strictly per-session — pooled here are only the
/// userspace byte buffers, never sockets, tasks or permits. What churn
/// multiplies is allocator traffic: every create zeroes 8 KiB and every
/// teardown frees it. This pool recycles the freed buffers (moved, never
/// shared) up to this depth per thread; beyond it they drop as before.
/// Thread-local because the buffers are exclusive `&mut` scratch — sharing
/// them across threads would need a lock on the per-reply path.
pub(crate) const SESS_BUF_POOL_DEPTH: usize = 8;

thread_local! {
    static SESS_BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Take a session-reader buffer, recycled when one is idle.
pub(crate) fn sess_recv_buf() -> Vec<u8> {
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        while let Some(buf) = p.pop() {
            if buf.len() == SESS_RECV_BUF_LEN {
                return buf;
            }
        }
        vec![0u8; SESS_RECV_BUF_LEN]
    })
}

/// Return a session-reader buffer for reuse. Wrong-sized buffers (none exist
/// in the tree today; this is defence in depth) are dropped, and past the
/// depth the buffer drops as before — so the pool itself is bounded.
pub(crate) fn sess_recycle_buf(buf: Vec<u8>) {
    if buf.len() != SESS_RECV_BUF_LEN {
        return;
    }
    // No re-zeroing: `recv_from` overwrites the prefix on the next use and
    // only `buf[..n]` is ever read, so stale tail bytes are never observed.
    // All sessions live in this process, so there is no cross-tenant leak.
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < SESS_BUF_POOL_DEPTH {
            p.push(buf);
        }
    })
}

/// Minimum gap between live DATAGRAM-budget re-reads after a `TooLarge` send
/// verdict on this reader task. Mirrors the client's
/// `BUDGET_PROBE_INTERVAL_MS` (100 ms): without it a PMTU shrink costs one
/// quinn connection-state lock per oversized reply for the whole window, i.e.
/// a re-probe storm on exactly the mutex the steady path takes once per frame.
/// Inside the window the reader keeps the last known budget and the datagram
/// is dropped with size accounting (UDP semantics).
pub(crate) const READER_BUDGET_PROBE_INTERVAL_MS: u64 = 100;

/// Whether a `TooLarge` verdict may re-read the live budget now. Pure so the
/// throttle is testable without a live connection; `now_ms` is the
/// [`mono_millis`] epoch. Zero means never probed: the mono epoch counts from
/// process start, so a small `now` must not read as "probed 0 ms ago".
pub(crate) fn too_large_probe_due(last_probe_ms: u64, now_ms: u64) -> bool {
    last_probe_ms == 0 || now_ms.saturating_sub(last_probe_ms) >= READER_BUDGET_PROBE_INTERVAL_MS
}

#[cfg(test)]
pub(crate) fn sess_buf_pool_len() -> usize {
    SESS_BUF_POOL.with(|p| p.borrow().len())
}

/// Wire length of the `atyp | addr | port` header a packed frame carries for
/// `src`. A reply's source is always IP-form (the session reader reports the
/// address the target answered from), so this is 7 or 19 bytes.
#[cfg(test)]
fn reply_addr_len(src: SocketAddr) -> usize {
    match src {
        SocketAddr::V4(_) => 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 16 + 2,
    }
}

/// One reply waiting in the MQP-3 TRAIN arena.
///
/// `flow` is the inbound flow whose destination produced this source, or
/// [`MQP3_NO_FLOW`] for an unsolicited/full-cone source (and for a domain
/// target, whose resolved IP the client does not know). A no-flow item carries
/// its source inline; a known flow is compressed and the client's own flow
/// table supplies the source address.
#[cfg(test)]
pub(crate) struct ReplyItem {
    pub(crate) flow: u8,
    pub(crate) src: SocketAddr,
    pub(crate) off: usize,
    pub(crate) len: usize,
}

/// Stage one small reply into the current MQP-3 TRAIN.
///
/// Unlike the MQP-2 BATCH stager this does **not** require a shared source: a
/// train can mix destinations, which is the case that matters for DNS/game
/// fanout. `last_flow` is a one-entry memo of `(source, flow)` so a steady
/// source does not reload the flow snapshot or scan the table per reply.
///
/// `false` means the run is full or the next item would exceed the path
/// budget; the caller flushes and retries. Saturating arithmetic, because
/// `limit` is a live path budget.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn reply_stage_v3(
    arena: &mut Vec<u8>,
    staged: &mut Vec<ReplyItem>,
    staged_wire: &mut usize,
    flows: &arc_swap::ArcSwap<FlowTable>,
    last_flow: &mut Option<(SocketAddr, u8)>,
    src: SocketAddr,
    payload: &[u8],
    limit: usize,
) -> bool {
    if staged.len() >= MQP3_MAX_TRAIN_ITEMS {
        return false;
    }
    let flow = match *last_flow {
        Some((s, f)) if s == src => f,
        _ => {
            let snap = flows.load();
            let f = snap.flow_for_ip(src).unwrap_or(MQP3_NO_FLOW);
            *last_flow = Some((src, f));
            f
        }
    };
    // A known IP flow is compressed. A no-flow item (unsolicited source, a
    // source port that changed, or a domain target) carries its address inline:
    // the client resolves flow ids from its outbound destination table, which
    // for a domain is not a valid SOCKS reply source.
    let addr_len = if flow == MQP3_NO_FLOW {
        reply_addr_len(src)
    } else {
        0
    };
    let base = if staged.is_empty() {
        MQP3_TRAIN_HEADER_LEN
    } else {
        *staged_wire
    };
    let next = base.saturating_add(train_item_len(flow, addr_len, payload.len()));
    if next > limit {
        return false;
    }
    let off = arena.len();
    arena.extend_from_slice(payload);
    staged.push(ReplyItem {
        flow,
        src,
        off,
        len: payload.len(),
    });
    *staged_wire = next;
    true
}

// ---------------------------------------------------------------------------
// MQP-3 rev2 downlink: connection-level staging (Phase 2)
// ---------------------------------------------------------------------------

/// One-entry memo in front of [`SessionFlows::match_source`].
///
/// `match_source` is a linear scan of the session's ≤64 bindings (each domain
/// binding also scanning its ≤16-address resolved set): 20 ns / 36 ns / 164 ns
/// at 1 / 8 / 64 flows per the Lead's measurements, paid on **every** relayed
/// reply. A steady request/response flow sends every reply from the same
/// source, so the previous verdict is almost always still the answer — the
/// legacy v3 path had exactly this memo, and rev2 dropped it.
///
/// # Correctness
///
/// The memo is trusted only while every input `match_source` reads is
/// unchanged:
/// - the reverse-table snapshot is **pointer-identical** — the table is
///   copy-on-write and every insert/remove/reap publishes a whole new
///   `Arc<SessionFlows>`, so a rebind, a `FLOW_CLOSE`, a `SESS_CLOSE` or a
///   reaped entry can never be overridden;
/// - the matched binding is not `Closed` (the same filter the scan applies);
/// - the binding's two mutable classification fields still hold the values
///   observed when the verdict was recorded: `reply_src` (re-armed by every
///   `OPEN|SRC` send, so a rebind invalidates) and `reply_src_acked` (set by
///   `CTL FLOW_ACK` from the datagram-reader task, so a late ACK invalidates
///   and the flow becomes `Exact` on the next reply instead of re-sending
///   binding frames forever).
///
/// `target`, `resolved` and `state` transitions after publication cannot change
/// the classification: `target` is immutable, `resolved` is written only before
/// the binding is published, and `mark_open`/`mark_closed` are covered by the
/// snapshot-pointer and `Closed` checks. A miss falls through to the full scan,
/// which re-records the memo, so the entry never outlives a stale verdict.
struct ReplySourceMemo(Option<ReplySourceMemoEntry>);

struct ReplySourceMemoEntry {
    /// The reply source this verdict was recorded for (the memo key).
    src: SocketAddr,
    /// The reverse-table snapshot the verdict came from; keeps the allocation
    /// alive so the pointer comparison cannot alias a later snapshot (ABA).
    snapshot: Arc<SessionFlows>,
    /// The binding the scan chose.
    binding: Arc<FlowBinding>,
    /// The scan's verdict: `true` = `Exact`, `false` = `Rebind`.
    exact: bool,
    /// `binding.reply_src()` when the verdict was recorded.
    observed_reply_src: Option<SocketAddr>,
    /// `binding.reply_src_acked()` when the verdict was recorded.
    observed_acked: bool,
}

impl ReplySourceMemo {
    const EMPTY: Self = Self(None);

    /// The memoized verdict for `src`, or `None` when the memo is invalid for
    /// the current snapshot/binding state (the caller then runs the scan).
    fn lookup(&self, snapshot: &Arc<SessionFlows>, src: SocketAddr) -> Option<SourceMatch> {
        let entry = self.0.as_ref()?;
        if entry.src != src
            || !Arc::ptr_eq(snapshot, &entry.snapshot)
            || entry.binding.state() == FlowState::Closed
            || entry.binding.reply_src() != entry.observed_reply_src
            || entry.binding.reply_src_acked() != entry.observed_acked
        {
            return None;
        }
        Some(if entry.exact {
            SourceMatch::Exact(Arc::clone(&entry.binding))
        } else {
            SourceMatch::Rebind(Arc::clone(&entry.binding))
        })
    }

    /// Remember one scan verdict. The observed mutable fields are captured here,
    /// after the scan, so a mutation that races the scan only costs one more
    /// scan (never a wrong verdict).
    fn record(&mut self, src: SocketAddr, snapshot: Arc<SessionFlows>, matched: &SourceMatch) {
        let (binding, exact) = match matched {
            SourceMatch::Exact(b) => (b, true),
            SourceMatch::Rebind(b) => (b, false),
        };
        self.0 = Some(ReplySourceMemoEntry {
            src,
            snapshot,
            binding: Arc::clone(binding),
            exact,
            observed_reply_src: binding.reply_src(),
            observed_acked: binding.reply_src_acked(),
        });
    }
}

/// Per-session rev2 reply state: the reverse table used to classify a reply
/// source, plus the one-entry memo in front of its scan.
///
/// Phase 1 kept a per-session small-frame staging area here; Phase 2 moved all
/// small-reply staging to the connection-scoped [`R2Stager`] so replies from
/// different associations aggregate into one train. What remains is the
/// read-only lookup handle and the reply-source memo.
pub(crate) struct R2ReplyState {
    pub(crate) flows: Arc<arc_swap::ArcSwap<SessionFlows>>,
    /// The connection state when this reader belongs to a live connection: the
    /// full-cone path allocates a server-owned wire id from it and installs the
    /// binding in the connection registry. `None` only for fixtures.
    pub(crate) conn: Option<Arc<R2ConnState>>,
    /// Wire revision of the connection this reader serves. Derived from the
    /// connection state; fixtures without one are the rev2 default.
    wire: Wire,
    /// One-entry memo of the last `reply source -> binding` verdict (see
    /// [`ReplySourceMemo`]). Task-local, so it dies with the reply reader.
    memo: ReplySourceMemo,
    /// rev3 only: per-flow count of context-carrying frames already sent, while
    /// the flow is inside its K=2 no-ACK context window.
    ///
    /// rev2 waits for the client's `FLOW_ACK` before a learned reply source is
    /// trusted (`reply_src_acked`); rev3 has no ACK, so this reader emits the
    /// context form for the first [`R3_CONTEXT_K`] replies and then marks the
    /// source confirmed locally. The map only ever holds flows *inside* their
    /// window (entries are removed when the window closes), plus the bounded
    /// `NEED_CONTEXT` repair set, so it cannot grow with the flow count.
    ctx_sent: std::collections::HashMap<u32, u8>,
    /// rev3 only: last observed connection repair epoch (see
    /// [`R2ConnState::take_need_context`]).
    ctx_epoch: u64,
    /// Number of full `match_source` scans this reader paid (test probe: the
    /// memo's whole effect is "repeated source, one scan").
    #[cfg(test)]
    pub(crate) match_scans: u64,
}

/// rev3 no-ACK context redundancy: how many consecutive downlink frames carry
/// the binding context (`SRC`/`OPEN_SRC`) before the flow compresses. Two
/// covers one lost datagram; the reliable control stream's `NEED_CONTEXT` is the
/// repair path beyond that.
pub(crate) const R3_CONTEXT_K: u8 = 2;

impl R2ReplyState {
    pub(crate) fn new(
        flows: Arc<arc_swap::ArcSwap<SessionFlows>>,
        conn: Option<Arc<R2ConnState>>,
    ) -> Self {
        // The reply/output encoders follow the connection's revision; a fixture
        // without a connection is the shipped rev2 default.
        let wire = conn.as_ref().map_or(Wire::Rev2, |c| c.wire());
        Self {
            flows,
            conn,
            wire,
            memo: ReplySourceMemo::EMPTY,
            ctx_sent: std::collections::HashMap::new(),
            ctx_epoch: 0,
            #[cfg(test)]
            match_scans: 0,
        }
    }

    /// Wire revision of this reader's connection.
    pub(crate) fn wire(&self) -> Wire {
        self.wire
    }

    /// Pick up client→server `NEED_CONTEXT` repairs (rev3).
    ///
    /// The control-stream task bumps the connection's repair epoch when the
    /// peer says it missed a binding context; this reader rebuilds its forced
    /// window from the bounded hint list before classifying the next reply. The
    /// common case is one relaxed load (`None`) per reply.
    fn sync_ctx_repairs(&mut self) {
        if self.wire != Wire::Rev3 {
            return;
        }
        let mut seen = self.ctx_epoch;
        let repair = self
            .conn
            .as_ref()
            .and_then(|state| state.take_need_context(&mut seen));
        let Some(ids) = repair else {
            return;
        };
        self.ctx_epoch = seen;
        // A repair supersedes every in-flight K window: the peer's list is the
        // authority for what it is missing, and a stale window can only cause
        // redundant (harmless) context frames.
        self.ctx_sent.clear();
        for wire_id in ids {
            self.ctx_sent.insert(wire_id, 0);
        }
    }

    /// Whether this flow must send another context-carrying frame before
    /// compressing (rev3 only).
    fn context_due(&self, wire_id: u32) -> bool {
        self.wire == Wire::Rev3
            && self
                .ctx_sent
                .get(&wire_id)
                .is_some_and(|sent| *sent < R3_CONTEXT_K)
    }

    /// Record one context-carrying downlink frame for `binding` (rev3 only).
    ///
    /// After [`R3_CONTEXT_K`] sends the learned source is locally confirmed
    /// (`mark_reply_src_acked`), which is exactly what the client's `FLOW_ACK`
    /// does on rev2; the no-ACK contract replaces the round trip with bounded
    /// redundancy, and the `NEED_CONTEXT` stream message repairs a run of losses
    /// beyond that.
    fn note_ctx_sent(&mut self, binding: &Arc<FlowBinding>) {
        if self.wire != Wire::Rev3 {
            return;
        }
        let wire_id = binding.wire_id;
        let sent = self.ctx_sent.entry(wire_id).or_insert(0);
        *sent = sent.saturating_add(1);
        if *sent >= R3_CONTEXT_K {
            self.ctx_sent.remove(&wire_id);
            // Local confirmation of the learned reply source. Harmless for
            // flows whose target already names the source (it only affects the
            // `match_source` acked gate, which those already satisfy).
            binding.mark_reply_src_acked();
        }
    }

    /// Classify one reply source: the memo first, the full reverse-table scan on
    /// a miss.
    ///
    /// This is the per-reply entry point for the rev2 downlink direction; the
    /// scan it usually avoids is the largest single CPU cost on the reply path
    /// (see [`ReplySourceMemo`]).
    fn classify_reply_source(&mut self, src: SocketAddr) -> Option<SourceMatch> {
        // One snapshot load per reply either way: the memo compares against it
        // and the scan iterates it. `load_full` (rather than `load`) is what
        // lets the memo keep the snapshot alive, so the pointer comparison that
        // validates it cannot alias a later allocation.
        let snapshot = self.flows.load_full();
        if let Some(matched) = self.memo.lookup(&snapshot, src) {
            return Some(matched);
        }
        #[cfg(test)]
        {
            self.match_scans += 1;
        }
        let matched = snapshot.match_source(src).filter(|m| match m {
            SourceMatch::Exact(binding) | SourceMatch::Rebind(binding) => {
                binding.state() != FlowState::Closed
            }
        });
        if let Some(matched) = matched.as_ref() {
            self.memo.record(src, snapshot, matched);
        }
        matched
    }
}

/// Full-cone: install a **server-owned** flow for an unsolicited reply source.
///
/// This is the downlink-created half of the flow table: the server picks the id
/// (owner bit 1) and sends the first reply as `DATA OPEN|SRC`, which teaches the
/// client both the flow id and the actual source. The binding is published in
/// both tables so:
/// - later replies from the same source hit `SourceMatch::Exact` (via
///   `reply_src`) and compress;
/// - the client app can answer on the same id: an uplink steady/TRAIN item is
///   forwarded to `target = Ip(src)` (the peer that sent to the relay).
///
/// Returns `None` when a resource bound is reached (id space exhausted,
/// connection registry full, session reverse table full): the caller keeps the
/// `DATA INLINE` fail-safe of today. The registry insert is undone if publishing
/// into the session snapshot fails, so a failed install leaves no partial state.
fn install_unsolicited(
    conn: &Arc<R2ConnState>,
    flows: &Arc<arc_swap::ArcSwap<SessionFlows>>,
    sess: u32,
    src: SocketAddr,
) -> Option<Arc<FlowBinding>> {
    // Check both table bounds before allocating an id: the id space is
    // monotonic and never reused, so a failed install should not burn one.
    if flows.load().is_full() {
        return None;
    }
    if conn.registry.len() >= conn.registry.cap() {
        return None;
    }
    // rev3: an id past the 14-bit fid space cannot be represented on the wire,
    // so refuse the install *before* burning an id and let the caller keep the
    // `DATA INLINE` fail-safe. rev2 accepts every allocator id.
    let wire_id = wire::alloc_wire_id(&conn.ids, conn.wire())?;
    let binding = FlowBinding::new_shared(wire_id, sess, TargetAddr::Ip(src));
    binding.set_reply_src(src);
    binding.mark_open();
    let binding = match conn.registry.insert(binding) {
        Ok(binding) => binding,
        Err(_) => return None,
    };
    let mut published = false;
    flows.rcu(|old| {
        let mut next = (**old).clone();
        published = next.insert(binding.clone());
        Arc::new(next)
    });
    if !published {
        // The session table filled between the bounds check and the publish
        // (single-writer per session, but keep the failure path total).
        conn.registry.remove(wire_id);
        binding.mark_closed();
        return None;
    }
    r2_stats::bump(&r2_stats::FULL_CONE_FLOWS);
    Some(binding)
}

/// Reader-level disposition of one stager drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageDrain {
    /// Frames were sent (or the queue is simply empty); no action needed.
    Ok,
    /// The live path budget refused an encoded frame. The stager counted the
    /// refused payloads and left the rest queued; the caller re-reads the
    /// budget under the usual 100 ms probe throttle.
    TooLarge,
    /// DATAGRAM support / the connection is gone: the session reader must flush
    /// and exit (queued items are accounted by the stager's own drop path).
    Terminal,
}

/// Map a stager drain verdict to the reader's disposition.
///
/// `Blocked` is ordinary backpressure: the stager counted the refused frame's
/// payloads (`BUFFER_FULL`) and kept the remaining items queued for the next
/// drain, so the reader keeps running. `TooLarge` is a budget verdict (the
/// encoded frame is bigger than the *live* datagram budget; the stager dropped
/// and counted that frame) and re-arms the budget probe. `Unsupported` /
/// `ConnectionLost` are the only terminal verdicts.
pub(crate) fn stage_verdict(failed: Option<DatagramSend>) -> StageDrain {
    match failed {
        None | Some(DatagramSend::Blocked) => StageDrain::Ok,
        // `drain` only reports a verdict when a send was refused; a `Sent`
        // cannot appear, but map it defensively to the no-op disposition.
        Some(DatagramSend::Sent) => StageDrain::Ok,
        Some(DatagramSend::TooLarge) => StageDrain::TooLarge,
        Some(DatagramSend::Unsupported | DatagramSend::ConnectionLost) => StageDrain::Terminal,
    }
}

/// Drain the connection stager, mapping the verdict and re-probing the live
/// datagram budget when the path shrank under it.
///
/// The stager books sent payloads itself and accounts the refused frame's
/// payloads, so this function counts nothing — it must never double-book.
///
/// The drain packs bounded batches ([`drain_staged`]) so a full send buffer
/// cannot make every reply re-encode the queue; the QUIC writes happen outside
/// the stager lock, so this session's burst no longer blocks every other
/// session's `stage_push`. The post-send requeue takes a fresh hold and books
/// its (should-never-happen) overflow with the same full-queue policy
/// `stage_push` uses.
pub(crate) fn drain_stage(
    c2: &quinn::Connection,
    stage: &Arc<parking_lot::Mutex<R2Stager>>,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) -> StageDrain {
    let outcome = drain_staged(c2, stage, *limit, || {
        dgram_drops::bump(&dgram_drops::BUFFER_FULL);
        r2_stats::bump(&r2_stats::STAGE_FULL_DROPS);
    });
    let verdict = stage_verdict(outcome.failed);
    if verdict == StageDrain::TooLarge {
        reprobe_large(c2, limit, last_too_large_probe_ms);
    }
    verdict
}

/// Whether the stager still holds frames after a drain.
///
/// [`StageDrain::Ok`] conflates "everything sent" with "buffer full, the rest
/// stayed queued" (backpressure is not a fault, see [`stage_verdict`]). A
/// session reader uses this one-lock probe at its burst boundary to arm the
/// short retry timer ([`STAGE_RETRY_MS`]) only when frames are actually
/// stranded; an idle connection whose stager is empty never arms it, so steady
/// state pays nothing.
pub(crate) fn stage_has_backlog(stage: &Arc<parking_lot::Mutex<R2Stager>>) -> bool {
    !stage.lock().is_empty()
}

/// How long a session reader waits before retrying a drain that left frames
/// queued because the DATAGRAM send buffer was full.
///
/// Such a drain returns `StageDrain::Ok` and keeps the remaining items queued;
/// the only other trigger to drain is the end of some session's reply burst.
/// A quiet tail — the last replies of a burst, with no further traffic on any
/// session — therefore used to sit in the stager until connection close and was
/// then dropped (accounted only by the stager's own teardown path). Twenty
/// milliseconds bounds the tail's added latency well inside one app-visible
/// RTT while costing two wakeups per second and *only* while frames are
/// queued.
pub(crate) const STAGE_RETRY_MS: u64 = 20;

/// Push one staged item; when the bounded queue is full, drain once and retry.
///
/// A push that still fails after a drain is a local-buffer drop: the payload is
/// counted as `BUFFER_FULL` (the same class as a full send buffer) plus the
/// rev2 `STAGE_FULL_DROPS` counter, and is not booked as sent.
fn stage_push(
    c2: &quinn::Connection,
    stage: &Arc<parking_lot::Mutex<R2Stager>>,
    item: R2StageItem,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) -> StageDrain {
    let item = {
        let mut st = stage.lock();
        match st.push(item) {
            Ok(_) => return StageDrain::Ok,
            Err(item) => item,
        }
    };
    let verdict = drain_stage(c2, stage, limit, last_too_large_probe_ms);
    let mut st = stage.lock();
    if st.push(item).is_ok() {
        return verdict;
    }
    drop(st);
    dgram_drops::bump(&dgram_drops::BUFFER_FULL);
    r2_stats::bump(&r2_stats::STAGE_FULL_DROPS);
    verdict
}

/// Stage the first frame of a rebinding flow (`DATA OPEN|SRC`) and learn the
/// actual reply source only once that frame was really sent.
///
/// The `OPEN|SRC` is sent as a **standalone frame outside the stager lock**.
/// Packing the whole queue under one lock just to deliver this one frame used
/// to serialise every session reader behind the encode + every DATAGRAM send;
/// and the old "no failure and no dropped items" connection-level verdict
/// could not distinguish this frame's fate from another session's. Sending it
/// directly gives an exact per-frame verdict: `reply_src` is learned only on
/// `Sent`. On `Blocked` the payload is offered to the stager (the burst-end
/// drain will retry it) and `reply_src` stays unlearned, so the next reply
/// repeats the OPEN — which is exactly the idempotent rebind the protocol
/// wants. A queue that is also full is an ordinary UDP drop.
fn stage_open_src(
    c2: &quinn::Connection,
    stage: &Arc<parking_lot::Mutex<R2Stager>>,
    item: R2StageItem,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
    wire: Wire,
) -> (StageDrain, bool) {
    // Same revision-aware encoder a batched drain uses, so a directly-sent
    // binding frame is byte-identical to a staged one on both wires.
    let body = match encode_standalone_item_for(wire, &item, *limit) {
        Some(body) => body,
        None => {
            book_too_large(1);
            drop(item);
            reprobe_large(c2, limit, last_too_large_probe_ms);
            return (StageDrain::TooLarge, false);
        }
    };
    match try_send_datagram(c2, body) {
        DatagramSend::Sent => {
            udp_stats::payload(item.payload.len());
            (StageDrain::Ok, true)
        }
        DatagramSend::Blocked => {
            // Backpressure: keep the payload queued when possible. It carries
            // no learned `reply_src`; the next reply re-sends the OPEN.
            match stage.lock().push(item) {
                Ok(_) => (StageDrain::Ok, false),
                Err(item) => {
                    drop(item);
                    dgram_drops::bump(&dgram_drops::BUFFER_FULL);
                    r2_stats::bump(&r2_stats::STAGE_FULL_DROPS);
                    (StageDrain::Ok, false)
                }
            }
        }
        DatagramSend::TooLarge => {
            book_too_large(1);
            drop(item);
            reprobe_large(c2, limit, last_too_large_probe_ms);
            (StageDrain::TooLarge, false)
        }
        DatagramSend::Unsupported | DatagramSend::ConnectionLost => {
            drop(item);
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
            (StageDrain::Terminal, false)
        }
    }
}

/// Re-read the live path budget under the shared probe throttle.
fn reprobe_large(c2: &quinn::Connection, limit: &mut usize, last_too_large_probe_ms: &mut u64) {
    let now_probe = mono_millis().max(1);
    if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
        *last_too_large_probe_ms = now_probe;
        *limit = c2.max_datagram_size().unwrap_or(0);
    }
}

/// Outcome of the Phase 1b large-reply send (rev2 `DATA` or rev2 `FRAG`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R2LargeReply {
    /// Every frame was queued (per-reply payload accounting already done).
    Sent,
    /// A single-frame send found the DATAGRAM buffer full; the payload is an
    /// ordinary UDP drop and *nothing has counted it*, so the reader books
    /// `dgram_drops::BUFFER_FULL` (OBS-1).
    Blocked,
    /// A single-frame encoding does not fit the live path budget; the payload is
    /// a drop the reader books as `dgram_drops::TOO_LARGE` and re-probes the
    /// budget under the usual 100 ms throttle.
    TooLarge,
    /// A fragmented send dropped the payload. The shared fragmenter books its
    /// own per-payload drop (the udp module's contract: a partial fragmented
    /// payload is booked there, so the reader must not double-book), but a
    /// *size* verdict still re-probes the live budget here.
    FragDropped { reprobe: bool },
    /// DATAGRAM support / the connection is gone: the reader should flush and
    /// exit.
    Terminal,
}

impl R2LargeReply {
    fn from_send(sent: DatagramSend) -> Self {
        match sent {
            DatagramSend::Sent => Self::Sent,
            DatagramSend::Blocked => Self::Blocked,
            DatagramSend::TooLarge => Self::TooLarge,
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => Self::Terminal,
        }
    }

    /// Map a fragmented send's verdict. A dropped fragment set is accounted by
    /// the fragmenter itself (see the enum docs), so only the *size* verdict is
    /// surfaced for a budget re-probe.
    fn from_payload(sent: &PayloadSend) -> Self {
        match sent.outcome() {
            DatagramSend::Sent => Self::Sent,
            DatagramSend::TooLarge => Self::FragDropped { reprobe: true },
            DatagramSend::Blocked => Self::FragDropped { reprobe: false },
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => Self::Terminal,
        }
    }
}

/// Send one reply that does not fit the small-reply staging path.
///
/// Phase 1b replaces the legacy MQP-2 fragmenter on the server reply path:
/// every UDP reply now travels as rev2 `DATA` — steady (known flow), `OPEN|SRC`
/// (one rebind frame that also teaches the client the actual source, after
/// which the shared binding compresses), or `INLINE` (no flow: self-describing
/// session + source) — or, when it exceeds one frame, as rev2 `FRAG` in the
/// same addressing mode via the per-session [`R2Fragmenter`].
///
/// A payload is fragmented only when the matching single-frame encoding does
/// not fit the live budget; the accounting is per reply (a single frame books
/// its payload on `Sent`, the fragmenter books a whole fragmented payload
/// itself, and a partial fragmented payload is a normal UDP drop).
#[allow(clippy::too_many_arguments)]
fn r2_send_large_reply(
    c2: &quinn::Connection,
    s: u32,
    frag2: &mut R2Fragmenter,
    r2_match: Option<&SourceMatch>,
    src: SocketAddr,
    payload: &[u8],
    limit: usize,
    now_ms: u64,
    wire: Wire,
) -> R2LargeReply {
    let n = payload.len();
    let aref = r2::ip_ref(src);
    if aref.header().is_err() {
        // The reader normalized and validated the source before this call, so
        // an unencodable address is unreachable; never panic on it.
        return R2LargeReply::TooLarge;
    }
    match r2_match {
        Some(SourceMatch::Exact(binding)) => {
            // The encoder refuses a frame over the live budget (and, on rev3, an
            // id past the 14-bit fid space), which is the same verdict the
            // explicit length check used to produce — no separate length
            // helpers exist for both revisions.
            let encoded = wire::encode_data_steady(wire, binding.wire_id, payload, limit);
            if let Some(body) = encoded {
                let sent = try_send_datagram(c2, body);
                let out = R2LargeReply::from_send(sent);
                if out == R2LargeReply::Sent {
                    udp_stats::payload(n);
                    r2_stats::bump_steady_sent(now_ms);
                }
                out
            } else {
                let sent = frag2.send(
                    c2,
                    limit,
                    &R2FragFlow::Steady {
                        wire_id: binding.wire_id,
                    },
                    payload,
                );
                if sent.complete() {
                    r2_stats::bump_steady_sent(now_ms);
                }
                R2LargeReply::from_payload(&sent)
            }
        }
        Some(SourceMatch::Rebind(binding)) => {
            // The adapter picks the revision's context form: rev2 `OPEN|SRC`,
            // rev3 `SRC` (client-owned) / `OPEN_SRC` (server-owned).
            let encoded =
                wire::encode_data_open(wire, binding.wire_id, s, &aref, true, payload, limit);
            if let Some(body) = encoded {
                let sent = try_send_datagram(c2, body);
                let out = R2LargeReply::from_send(sent);
                if out == R2LargeReply::Sent {
                    binding.set_reply_src(src);
                    udp_stats::payload(n);
                    r2_stats::bump_open_src_sent(now_ms);
                }
                out
            } else {
                let sent = frag2.send(
                    c2,
                    limit,
                    &R2FragFlow::Opening {
                        wire_id: binding.wire_id,
                        sess: s,
                        addr: aref,
                        src: true,
                    },
                    payload,
                );
                if sent.complete() {
                    // The whole binding frame set was queued: the client learns
                    // the actual source when it reassembles, so the next reply
                    // from it compresses.
                    binding.set_reply_src(src);
                    r2_stats::bump_open_src_sent(now_ms);
                }
                R2LargeReply::from_payload(&sent)
            }
        }
        None => {
            let encoded = wire::encode_data_inline(wire, s, &aref, true, payload, limit);
            if let Some(body) = encoded {
                let sent = try_send_datagram(c2, body);
                let out = R2LargeReply::from_send(sent);
                if out == R2LargeReply::Sent {
                    udp_stats::payload(n);
                }
                out
            } else {
                let sent = frag2.send(
                    c2,
                    limit,
                    &R2FragFlow::Inline {
                        sess: s,
                        addr: aref,
                        src: true,
                    },
                    payload,
                );
                R2LargeReply::from_payload(&sent)
            }
        }
    }
}

/// Send one staged reply as a `SINGLE`, falling back to the MQP-2 fragment
/// sender. Returns true when a `TooLarge` verdict should trigger a budget
/// probe.
#[cfg(test)]
fn flush_reply_single(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    item: &ReplyItem,
    payload: &[u8],
    limit: usize,
) -> bool {
    let ta = TargetAddr::Ip(item.src);
    let inline = (item.flow == MQP3_NO_FLOW).then(|| ta.as_ref());
    let sent = match encode_single(s, item.flow, inline.as_ref(), false, payload, limit) {
        Some(body) => try_send_datagram(c2, body),
        None => DatagramSend::TooLarge,
    };
    match sent {
        DatagramSend::Sent => {
            udp_stats::payload(payload.len());
            false
        }
        DatagramSend::Blocked | DatagramSend::TooLarge => {
            frag.send(c2, s, &ta.as_ref(), payload, limit).outcome() == DatagramSend::TooLarge
        }
        // The caller's next action is the same for a dead/unsupported
        // connection: flush what remains, then leave the reader. Nothing is
        // counted here; the per-frame verdict is one event, not one per reply.
        DatagramSend::Unsupported | DatagramSend::ConnectionLost => false,
    }
}

/// Flush the staged replies as one MQP-3 TRAIN, or as per-reply
/// `SINGLE`/fragment sends if the frame is refused.
///
/// Accounting is per reply, never per frame: a successful train books every
/// payload, a refused train books nothing and the fallback books each payload
/// through `flush_reply_single`/`DgramFragmenter::send`.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn flush_reply_train(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    arena: &mut Vec<u8>,
    staged: &mut Vec<ReplyItem>,
    staged_wire: &mut usize,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) {
    if staged.is_empty() {
        *staged_wire = 0;
        arena.clear();
        return;
    }
    let mut too_large = false;
    if staged.len() == 1 {
        let item = &staged[0];
        too_large = flush_reply_single(
            c2,
            s,
            frag,
            item,
            &arena[item.off..item.off + item.len],
            *limit,
        );
    } else {
        let n = staged.len().min(MQP3_MAX_TRAIN_ITEMS);
        let mut addrs: [TargetAddr; MQP3_MAX_TRAIN_ITEMS] =
            std::array::from_fn(|_| TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))));
        let mut refs: [TrainItem<'_>; MQP3_MAX_TRAIN_ITEMS] = [TrainItem {
            flow: 0,
            inline: None,
            src_override: false,
            payload: &[],
        }; MQP3_MAX_TRAIN_ITEMS];
        for (i, item) in staged.iter().take(n).enumerate() {
            addrs[i] = TargetAddr::Ip(item.src);
        }
        for (i, item) in staged.iter().take(n).enumerate() {
            let inline = (item.flow == MQP3_NO_FLOW).then(|| addrs[i].as_ref());
            refs[i] = TrainItem {
                flow: item.flow,
                inline,
                src_override: false,
                payload: &arena[item.off..item.off + item.len],
            };
        }
        let sent = encode_train(s, &refs[..n], *limit)
            .map(|body| try_send_datagram(c2, body))
            .unwrap_or(DatagramSend::TooLarge);
        match sent {
            DatagramSend::Sent => {
                for item in staged.iter().take(n) {
                    udp_stats::payload(item.len);
                }
                tracing::debug!("udp session {s}: {n} replies sent as one MQP-3 train");
            }
            DatagramSend::Blocked | DatagramSend::TooLarge => {
                for item in staged.iter().take(n) {
                    too_large |= flush_reply_single(
                        c2,
                        s,
                        frag,
                        item,
                        &arena[item.off..item.off + item.len],
                        *limit,
                    );
                }
            }
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => {}
        }
    }
    staged.clear();
    arena.clear();
    *staged_wire = 0;
    if too_large {
        let now_probe = mono_millis().max(1);
        if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
            *last_too_large_probe_ms = now_probe;
            *limit = c2.max_datagram_size().unwrap_or(0);
        }
    }
}

/// Stage one small reply into the current run's arena.
///
/// `false` means "do not stage this reply": a different source, a full run, or
/// no room left in the frame budget. The caller flushes the run and retries; a
/// reply that still cannot be staged on its own is sent as a single datagram.
///
/// The budget check uses [`batch_frame_len`], the same arithmetic as
/// `encode_batch`: it charges the fixed part plus **every** item's 2-byte
/// length prefix, not just the one being added. A run that would hold
/// `staged.len() + 1` items therefore costs
/// `BATCH_PREFIX_LEN + addr + 1 + Σ(2 + len)`. Charging a single prefix (the
/// previous shape) under-counted an N-item run by `2 * N` bytes: 16 x 88 B
/// replies need `5 + 7 + 1 + 16 x 90 = 1453 B`, so at a 1452 B path budget the
/// 16th was admitted and `encode_batch` then refused the frame — the flush
/// degraded to 16 per-reply sends and the staging copy had been paid for
/// nothing, which is exactly the waste this budget exists to prevent.
/// Saturating arithmetic: `limit` is a live path budget and this runs under
/// panic=abort, so an absurd value must clamp, not wrap.
///
/// The arena is reused across bursts and cleared on every flush, so the steady
/// state allocates nothing per reply — the copy into the arena is the only one
/// the caller pays, and `encode_batch` reads the payloads straight out of it.
#[cfg(test)]
pub(crate) fn reply_stage(
    arena: &mut Vec<u8>,
    staged: &mut Vec<(usize, usize)>,
    staged_src: &mut Option<SocketAddr>,
    src: SocketAddr,
    payload: &[u8],
    limit: usize,
) -> bool {
    if staged_src.is_some_and(|s| s != src) || staged.len() >= MAX_BATCH_ITEMS {
        return false;
    }
    if batch_frame_len(
        reply_addr_len(src),
        staged.len().saturating_add(1),
        arena.len().saturating_add(payload.len()),
    ) > limit
    {
        return false;
    }
    let off = arena.len();
    arena.extend_from_slice(payload);
    staged.push((off, payload.len()));
    *staged_src = Some(src);
    true
}

/// Flush staged small replies for one target as a single MQP-2 BATCH frame.
///
/// Server-side mirror of the client association's N-pack: up to
/// [`MAX_BATCH_ITEMS`] replies that share one `(ip, port)` source ride one
/// DATAGRAM — one quinn connection-state lock and one AEAD instead of one
/// per reply. `arena`/`staged` are the run's reused buffers (see
/// [`reply_stage`]); both are cleared here, and staging never waits: the caller
/// flushes at burst end, on a source change, on a large reply and before every
/// `break 'session`, so nothing survives across awaits.
///
/// **Accounting is per reply, not per frame.** `send_udp_batch` books a full
/// send buffer once for the whole frame, so a blocked N-item batch would count
/// N lost app datagrams as one drop — and a frame that never fit has to fall
/// back to per-reply sends anyway. Both are avoided by driving the encode/send
/// here: a frame that was not queued counts nothing, and the per-reply fallback
/// re-sends each reply through `DgramFragmenter::send`, which does its own
/// exactly-once accounting — the same bookkeeping an unbatched reply gets. That
/// fallback now only fires when the path budget shrank under a staged run.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_reply_batch(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    arena: &mut Vec<u8>,
    staged: &mut Vec<(usize, usize)>,
    staged_src: &mut Option<SocketAddr>,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) {
    let Some(src) = staged_src.take() else {
        return;
    };
    if staged.is_empty() {
        arena.clear();
        return;
    }
    let ta = TargetAddr::Ip(src);
    let aref = ta.as_ref();
    // A run of one is not a batch: the BATCH wrapper buys a count byte, a
    // per-item length prefix and one extra decode on the client for a frame
    // that carries a single payload anyway, and the single-`0x02` path through
    // `DgramFragmenter::send` is the same encoder every unbatched reply already
    // uses (prefix cache, exactly-once drop accounting, fragmentation for an
    // oversized body). Low-rate flows — DNS-style request/response, a game's
    // keepalives — deliver one reply per wakeup, so this is their steady shape,
    // not a corner. It also makes the "N replies as one batch frame" debug line
    // below fire only when the grouping actually happened.
    if staged.len() == 1 {
        let (off, len) = staged[0];
        let sent = frag.send(c2, s, &aref, &arena[off..off + len], *limit);
        staged.clear();
        arena.clear();
        // Same 100 ms probe throttle as the per-reply fallback below (and the
        // main loop): a size verdict is a path-budget signal, never a
        // connection fault.
        if sent.outcome() == DatagramSend::TooLarge {
            let now_probe = mono_millis().max(1);
            if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
                *last_too_large_probe_ms = now_probe;
                *limit = c2.max_datagram_size().unwrap_or(0);
            }
        }
        return;
    }
    let mut refs: [&[u8]; MAX_BATCH_ITEMS] = [&[][..]; MAX_BATCH_ITEMS];
    let n = staged.len().min(MAX_BATCH_ITEMS);
    for (r, (off, len)) in refs.iter_mut().zip(staged.iter().take(n)) {
        *r = &arena[*off..*off + *len];
    }
    if let Some(body) = encode_batch(s, &aref, &refs[..n], *limit)
        && try_send_datagram(c2, body) == DatagramSend::Sent
    {
        for (_, len) in staged.iter().take(n) {
            udp_stats::payload(*len);
        }
        // Only true groups reach here (a run of one took the single-`0x02`
        // path above), so this line is the operational answer to "is the
        // batching earning its keep".
        tracing::debug!("udp session {s}: {n} replies sent as one batch frame");
        staged.clear();
        arena.clear();
        return;
    }
    // The frame was not queued and nothing was counted for it, so every reply
    // goes out on its own below — the same path (and the same per-datagram drop
    // accounting) an unstaged reply takes.
    let mut too_large = false;
    for (off, len) in staged.drain(..) {
        if frag
            .send(c2, s, &aref, &arena[off..off + len], *limit)
            .outcome()
            == DatagramSend::TooLarge
        {
            // A per-reply size verdict is the one real path-budget signal
            // here (the batch encoder declining to fit does not imply a
            // single reply would not). Probe under the same 100 ms throttle
            // the main loop uses, never per reply.
            too_large = true;
        }
    }
    arena.clear();
    if too_large {
        let now_probe = mono_millis().max(1);
        if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
            *last_too_large_probe_ms = now_probe;
            *limit = c2.max_datagram_size().unwrap_or(0);
        }
    }
}

/// What processing one reply did to the reader's drain loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyDisposition {
    /// Keep draining the current burst.
    Continue,
    /// Tear the reader down: the path budget collapsed to zero, or the
    /// connection reported DATAGRAM support lost / connection lost. Queued
    /// stager items are connection-scoped: another session reader may still
    /// drain them, and connection teardown accounts whatever is left.
    BreakSession,
}

/// Process one reply from the session's target socket.
///
/// This is the entire body of the reader's drain loop, and it is deliberately
/// **fully synchronous**: on Linux the `recvmmsg` burst arm runs it while
/// borrowing the thread-local burst scratch in place (`with_burst_msg`) instead
/// of copying the payload into the session buffer first — that copy was one full
/// payload memcpy per drained reply. Any future `await` in here would have to
/// move back behind an owned copy in the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_session_reply(
    c2: &quinn::Connection,
    s: u32,
    payload: &[u8],
    src_raw: SocketAddr,
    reply_filter: ReplyFilter,
    r2: &mut R2ReplyState,
    stage: &Arc<parking_lot::Mutex<R2Stager>>,
    frag2: &mut R2Fragmenter,
    flows: &arc_swap::ArcSwap<FlowTable>,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
    last_touch: &mut u64,
    last_limit_refresh: &mut u64,
    last2: &std::sync::atomic::AtomicU64,
    recent: &arc_swap::ArcSwap<RecentAddrs>,
    recent_epoch: &std::sync::atomic::AtomicU64,
    allow_snap: &mut Option<Arc<RecentAddrs>>,
    allow_epoch: &mut u64,
) -> ReplyDisposition {
    let n = payload.len();
    // N=1 CONTRACT (server reply path): a datagram sent through the cached
    // `limit` pays exactly one quinn take per frame — the `SendDatagram::poll`
    // lock inside `try_send_datagram`. Auxiliary takes are all throttled off
    // this path: the 60 s idle tick re-reads the budget at most once per tick,
    // active sessions refresh PMTU at most once per 10 s, `TooLarge` re-probes
    // at most once per `READER_BUDGET_PROBE_INTERVAL_MS`, and
    // `Unsupported`/`ConnectionLost` break the reader instead of re-acquiring
    // (DATAGRAM support is negotiated at the handshake, so a re-check could
    // never find a better budget — only spend another take per datagram).
    // Coarse epoch gates the per-reply intervals (the 1 s liveness touch and
    // the 10 s PMTU refresh); the liveness value itself is the mono epoch,
    // matching `touch_session_throttled` and every sweep reader.
    let now = coarse_millis();
    if now.saturating_sub(*last_touch) >= 1000 {
        *last_touch = now;
        last2.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
    }
    // Active sessions track PMTU growth without waiting for the 60 s idle tick:
    // at most one quinn lock per session per 10 s, and only while the session
    // is actually receiving replies.
    if now.saturating_sub(*last_limit_refresh) >= 10_000 {
        *last_limit_refresh = now;
        match c2.max_datagram_size() {
            Some(m) => *limit = m,
            None => return ReplyDisposition::BreakSession,
        }
    }
    // Truncation detection: the reader buffer is one slack byte past the
    // protocol cap (`SESS_RECV_BUF_LEN`), so a datagram *at least* that long is
    // exactly the shape `recv_from` would have reported as `n == buf.len()`.
    // The burst arm sees the kernel's own reported length (up to `BURST_SLOT`,
    // which is larger than this buffer), so `>=` reproduces the old predicate
    // for both arms instead of the burst path letting an over-long reply
    // through.
    if n >= SESS_RECV_BUF_LEN {
        // Rate-limited, exactly like every other drop on this path: the rate
        // is chosen by the *target* (any reply above the protocol cap), and an
        // unthrottled `warn!` here put a formatted line through tracing's
        // process-wide writer lock once per packet.
        let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        dgram_drops::warn_oversize_recv(dgram_drops::OversizeRecv::TargetReply, dropped, || {
            format!("; session {s}")
        });
        return ReplyDisposition::Continue;
    }
    if *limit == 0 {
        // Nothing can be sent on this path: draining with a zero budget makes
        // the stager account every queued payload as a `TooLarge` drop instead
        // of leaving them to connection teardown, then the reader exits.
        let _ = drain_stage(c2, stage, limit, &mut *last_too_large_probe_ms);
        return ReplyDisposition::BreakSession;
    }
    let src = SocketAddr::new(unmap(src_raw.ip()), src_raw.port());
    // Reply-source validation: the socket is unconnected, so any source that
    // reaches the ephemeral port would otherwise be forwarded as the target's
    // answer. The default drops anything sent from a host this session never
    // sent to (see `RecentAddrs`: the port is deliberately not part of the key,
    // so a server answering from a different port still gets through).
    // `ReplyFilter::FullCone` (`udp_full_cone`) is the operator opt-in that
    // behaves like a full-cone NAT's external endpoint — endpoint-independent
    // filtering, any source admitted — which is what lets a peer initiate to a
    // client app that has not sent to it yet.
    //
    // Full-cone still classifies the source against the allowlist (the same
    // epoch-gated mirror, so a steady flow is one relaxed load plus the 16-slot
    // scan): the classification only feeds the 60 s "unsolicited (full-cone)"
    // counter. It is *not* a drop decision.
    let on_allowlist = {
        // Epoch-gated mirror: the outbound path (and a spawned resolver task's
        // foreign push) bumps `recent_epoch` on every allowlist mutation, so a
        // steady flow validates against the task-local snapshot and only
        // reloads it when something actually moved. `remember_dst` moves the
        // epoch only when it really pushed a snapshot, so the steady slow-path
        // flow does not force a reload per reply.
        let epoch_now = recent_epoch.load(std::sync::atomic::Ordering::Relaxed);
        if *allow_epoch != epoch_now {
            *allow_snap = Some(recent.load_full());
            *allow_epoch = epoch_now;
        }
        allow_snap
            .as_ref()
            .is_some_and(|r| !r.is_empty() && r.contains(&src))
    };
    // A destination can fall out of the 16-entry recent ring while its flow is
    // still live (a 32-resolver DNS fanout is exactly that shape). The flow
    // table is an exact, session-scoped record of accepted IP targets, so it is
    // a second authorization source rather than a routing-only hint. Only
    // checked on a ring miss, and only IP flows match (`flow_for_ip` skips
    // domain entries, which have no resolved client-side address).
    let on_flow = !on_allowlist && flows.load().flow_for_ip(src).is_some();
    // MQP-3 rev2 reverse lookups: a reply source that matches a binding
    // installed by this session's `DATA OPEN` is authorized by that binding
    // (its addresses were SSRF/policy validated at install) and can be
    // compressed. Phase 1b uses the same match for every reply size: small ones
    // ride the steady/TRAIN staging below, large ones go out as one rev2 DATA
    // frame or rev2 FRAG (the legacy MQP-2 fragmenter is retired here).
    //
    // The one-entry memo in front of the scan is what makes a steady
    // request/response flow pay O(1) here instead of scanning up to 64
    // bindings; it invalidates itself on any snapshot replacement, close,
    // rebind (`reply_src`) or `FLOW_ACK` (`reply_src_acked`) — see
    // [`ReplySourceMemo`].
    let mut r2_match = r2.classify_reply_source(src);
    let on_r2 = r2_match.is_some();
    if !on_allowlist && !on_flow && !on_r2 {
        if reply_filter == ReplyFilter::FullCone {
            // Admitted anyway; counted so an operator can see whether (and how
            // much) unsolicited traffic is actually arriving.
            udp_stats::unsolicited();
        } else {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return ReplyDisposition::Continue;
        }
    }
    // Full-cone (and only full-cone): an unsolicited source with no matching
    // flow opens a *server-owned* flow. The first reply goes out as
    // `DATA OPEN|SRC` (an `Open` stage item) and the binding is installed in
    // both tables, so later replies from the same source compress and the client
    // app can answer on the same id. Any table bound falls back to the INLINE
    // fail-safe of today (non-full-cone never enters this branch).
    if r2_match.is_none()
        && reply_filter == ReplyFilter::FullCone
        && let Some(conn) = r2.conn.as_ref()
        && let Some(binding) = install_unsolicited(conn, &r2.flows, s, src)
    {
        r2_match = Some(SourceMatch::Rebind(binding));
    }
    // rev3 no-ACK context policy. `match_source` classifies a learned reply
    // source as `Exact` only once `reply_src_acked` is set; rev2 gets that from
    // the client's `FLOW_ACK`, rev3 has no ACK at all. Instead:
    // - pick up any client `NEED_CONTEXT` repairs first (bounded hint list);
    // - while a flow is inside its K=2 context window, force the context form
    //   even when the table says `Exact` — this is what carries the binding for
    //   a server-owned flow whose target names the source (otherwise the table
    //   short-circuits to `Exact` and the first reply would be steady);
    // - [`R2ReplyState::note_ctx_sent`] confirms the source locally after the
    //   K-th successful context frame, which is exactly the state the rev2 ACK
    //   would have produced.
    if r2.wire() == Wire::Rev3 {
        r2.sync_ctx_repairs();
        if let Some(SourceMatch::Exact(binding)) = r2_match.as_ref()
            && r2.context_due(binding.wire_id)
        {
            r2_match = Some(SourceMatch::Rebind(Arc::clone(binding)));
        }
    }
    // ------------------------------------------------------------------
    // Small replies: one connection-scoped staging queue (Phase 2).
    //
    // Every reply that fits one rev2 DATA frame is pushed as an item and sent
    // by whichever session reader next drains the shared stager, so replies
    // from different associations can share one cross-session `TRAIN dict`
    // (round-robin across sessions). The item shape mirrors the binding state:
    // - Exact  -> `Steady { wire_id }`, can join any train;
    // - Rebind -> `Open { wire_id, sess, addr, src: true }`, a standalone
    //   `DATA OPEN|SRC`; the reply source is learned only once the frame was
    //   actually sent (see `stage_open_src`);
    // - None   -> `Inline { sess, addr, src: true }`, a standalone DATA INLINE
    //   (the self-describing fail-safe, e.g. a full-cone reply).
    //
    // Payloads are owned copies: an item may be queued by this task and drained
    // by another session's reader.
    // ------------------------------------------------------------------
    if n <= BATCH_SMALL_MAX {
        let is_rebind = matches!(r2_match.as_ref(), Some(SourceMatch::Rebind(_)));
        let kind = match r2_match.as_ref() {
            Some(SourceMatch::Exact(binding)) => R2StageKind::Steady {
                wire_id: binding.wire_id,
            },
            Some(SourceMatch::Rebind(binding)) => R2StageKind::Open {
                wire_id: binding.wire_id,
                sess: s,
                addr: TargetAddr::Ip(src),
                src: true,
            },
            None => R2StageKind::Inline {
                sess: s,
                addr: TargetAddr::Ip(src),
                src: true,
            },
        };
        let item = R2StageItem {
            session: s,
            kind,
            payload: Bytes::copy_from_slice(payload),
        };
        let verdict = if is_rebind {
            let (verdict, sent) = stage_open_src(
                c2,
                stage,
                item,
                limit,
                &mut *last_too_large_probe_ms,
                r2.wire(),
            );
            if sent {
                if let Some(SourceMatch::Rebind(binding)) = r2_match.as_ref() {
                    binding.set_reply_src(src);
                    // rev3: count this context frame and confirm the source
                    // locally after K=2 (the no-ACK replacement for FLOW_ACK).
                    r2.note_ctx_sent(binding);
                }
                r2_stats::bump_open_src_sent(now);
            }
            verdict
        } else {
            stage_push(c2, stage, item, limit, &mut *last_too_large_probe_ms)
        };
        return match verdict {
            StageDrain::Terminal => ReplyDisposition::BreakSession,
            // `TooLarge` already re-armed the budget probe; the refused frame's
            // payloads were dropped and counted by the stager itself.
            StageDrain::Ok | StageDrain::TooLarge => ReplyDisposition::Continue,
        };
    }

    // A reply too large for one staged frame must not overtake smaller replies
    // already queued for this flow: drain the connection stager first (it may
    // carry this session's earlier payloads), then send directly.
    match drain_stage(c2, stage, limit, &mut *last_too_large_probe_ms) {
        StageDrain::Ok | StageDrain::TooLarge => {}
        StageDrain::Terminal => return ReplyDisposition::BreakSession,
    }
    // Phase 1b/2: a reply above the small threshold is rev2 as well — one
    // DATA/OPEN|SRC/INLINE frame when it fits the live budget, otherwise rev2
    // FRAG. The legacy MQP-2 fragmenter is not a production reply sender.
    // `now` is the reply handler's single coarse sample for this frame; the
    // stats flush gate reuses it instead of reading the clock again (W8b).
    let sent = r2_send_large_reply(
        c2,
        s,
        &mut *frag2,
        r2_match.as_ref(),
        src,
        payload,
        *limit,
        now,
        r2.wire(),
    );
    match large_reply_disposition(sent, c2, limit, last_too_large_probe_ms) {
        ReplyDisposition::Continue => {
            // rev3 no-ACK: a fully queued context frame counts toward the K=2
            // window (the fragmenter already learned the source above).
            if sent == R2LargeReply::Sent
                && let Some(SourceMatch::Rebind(binding)) = r2_match.as_ref()
            {
                r2.note_ctx_sent(binding);
            }
        }
        ReplyDisposition::BreakSession => return ReplyDisposition::BreakSession,
    }
    ReplyDisposition::Continue
}

/// Book one large-reply verdict and decide the reader's next move (OBS-1).
///
/// Kept separate from [`handle_session_reply`] so the OBS-1 accounting contract
/// is unit-testable: a single-frame `Blocked`/`TooLarge` drop is booked here
/// (nothing else sees it), a fragmented drop is **not** re-booked (the shared
/// fragmenter accounts its own per-payload drop), and a size verdict re-probes
/// the live path budget at most once per probe interval.
pub(crate) fn large_reply_disposition(
    sent: R2LargeReply,
    c2: &quinn::Connection,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) -> ReplyDisposition {
    // A size verdict (single-frame or fragmented) re-reads the live budget, at
    // most once per throttle interval: a PMTU shrink otherwise cost one quinn
    // connection-state lock per oversized reply on top of the send's own take.
    // `.max(1)`: the zero stamp means "never probed" (see
    // `too_large_probe_due`), and the mono epoch counts from process start, so
    // a verdict inside the first millisecond must still arm the throttle.
    let reprobe_budget = |limit: &mut usize, last: &mut u64| {
        let now_probe = mono_millis().max(1);
        if too_large_probe_due(*last, now_probe) {
            *last = now_probe;
            *limit = c2.max_datagram_size().unwrap_or(0);
        }
    };
    match sent {
        R2LargeReply::Sent => {}
        // The single-frame send was refused by the full DATAGRAM buffer and
        // nothing else books that drop. Without this counter a saturated
        // downlink silently loses exactly the replies larger than the staging
        // threshold, and the only signal ("UDP works for small replies") says
        // nothing.
        R2LargeReply::Blocked => {
            dgram_drops::bump(&dgram_drops::BUFFER_FULL);
        }
        // The live budget cannot carry one frame of this reply: booked as
        // `TOO_LARGE` (the MTU/path class), distinct from buffer pressure.
        R2LargeReply::TooLarge => {
            dgram_drops::bump(&dgram_drops::TOO_LARGE);
            reprobe_budget(limit, last_too_large_probe_ms);
        }
        // The shared fragmenter booked this payload's drop itself; only the
        // size verdict still needs the budget re-probe.
        R2LargeReply::FragDropped { reprobe } => {
            if reprobe {
                reprobe_budget(limit, last_too_large_probe_ms);
            }
        }
        R2LargeReply::Terminal => return ReplyDisposition::BreakSession,
    }
    ReplyDisposition::Continue
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sess_reader_task(
    conn_id: usize,
    s: u32,
    rs: Arc<tokio::net::UdpSocket>,
    ss2: SessTable,
    c2: quinn::Connection,
    last2: Arc<std::sync::atomic::AtomicU64>,
    recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
    flows: Arc<arc_swap::ArcSwap<FlowTable>>,
    r2_flows: Arc<arc_swap::ArcSwap<SessionFlows>>,
    r2_registry: Option<Arc<FlowRegistry>>,
    r2_conn: Option<Arc<R2ConnState>>,
    stage: Arc<parking_lot::Mutex<R2Stager>>,
    reply_filter: ReplyFilter,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Pooled (see `sess_recv_buf`): `SESS_RECV_BUF_LEN` is the truncation
    // witness (`handle_session_reply` drops a reply whose length reaches it),
    // and this buffer is the head/portable-fallback copy target: on Linux the
    // drained burst replies are handled in place from the recvmmsg scratch and
    // never touch it.
    let mut buf = sess_recv_buf();
    // MQP-3 sender for replies that do not fit one `DATA` frame, for the
    // connection's revision (rev2 = shipped wire; rev3 = `FRAG` with fids).
    // Small replies are staged on the connection-level `stage` instead
    // (Phase 2), so this session no longer keeps a legacy `DgramFragmenter`.
    let wire = r2_conn.as_ref().map_or(Wire::Rev2, |c| c.wire());
    let mut frag2 = R2Fragmenter::new_with_wire(wire);
    let mut limit = c2.max_datagram_size().unwrap_or(0);
    let mut last_touch = 0u64;
    let mut last_limit_refresh = coarse_millis();
    // Last live-budget re-read caused by a `TooLarge` verdict (mono epoch, 0 =
    // never). Gates the re-probe so a PMTU shrink cannot cost one quinn lock
    // per oversized reply; see `READER_BUDGET_PROBE_INTERVAL_MS`.
    let mut last_too_large_probe_ms = 0u64;
    // Task-local mirror of the reply-source allowlist. This task is the
    // allowlist's only reader, and every mutation of the shared snapshot bumps
    // `recent_epoch` — including a spawned resolver task's foreign push, which
    // this task cannot otherwise see. The snapshot is therefore reloaded only
    // when the epoch moves: one relaxed epoch load per reply instead of an
    // `ArcSwap` hazard-pointer read whose cache line a concurrent foreign push
    // would invalidate on the download hot path. `u64::MAX` can never be a
    // real epoch (it counts pushes), so the first reply always loads.
    let mut allow_snap: Option<Arc<RecentAddrs>> = None;
    let mut allow_epoch: u64 = u64::MAX;
    // The session's reverse table, used to classify each reply source, plus the
    // connection handles the full-cone path needs (server-owned id allocation
    // and binding install). Small replies are pushed to the connection-scoped
    // `stage`; nothing is retained in this task across awaits.
    let mut r2 = R2ReplyState::new(r2_flows, r2_conn);
    // Retry timer for a drain that left frames queued on a full DATAGRAM send
    // buffer (see `stage_has_backlog`/`STAGE_RETRY_MS`). The first `tick()`
    // consumes the interval's immediate first fire; from then on the arm only
    // exists while `stage_backlog` is true, so a connection with nothing queued
    // polls no timer at all.
    let mut stage_retry = tokio::time::interval(Duration::from_millis(STAGE_RETRY_MS));
    stage_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    stage_retry.tick().await;
    let mut stage_backlog = false;
    'session: loop {
        let (n, src) = tokio::select! {
            r = rs.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = stage_retry.tick(), if stage_backlog => {
                // Backpressure cleared our earlier drain: retry now. Terminal
                // keeps the reader's flush-and-exit contract; on success the
                // queue is empty and the arm disappears again.
                match drain_stage(&c2, &stage, &mut limit, &mut last_too_large_probe_ms) {
                    StageDrain::Terminal => break 'session,
                    StageDrain::Ok | StageDrain::TooLarge => {}
                }
                stage_backlog = stage_has_backlog(&stage);
                continue;
            }
            _ = tick.tick() => {
                if c2.close_reason().is_some()
                    || mono_millis()
                        .saturating_sub(last2.load(std::sync::atomic::Ordering::Relaxed))
                        >= SESS_IDLE_MS
                {
                    break;
                }
                limit = match c2.max_datagram_size() {
                    Some(m) => m,
                    // DATAGRAM support is negotiated at the handshake; a mid-life
                    // disable leaves this reader with nothing to deliver, so exit
                    // and let the entry self-reap instead of holding a socket.
                    None => break,
                };
                continue;
            }
        };
        // Bounded reply drain (mirrors the client relay loops): the awaited
        // head plus up to `LAST_HOP_DRAIN - 1` more, so one wakeup moves up to
        // 32 replies instead of one reply per wakeup. On Linux the extras come
        // from one `recvmmsg` burst per refill and are handled **in place**
        // through `with_burst_msg`: the burst scratch already holds the bytes,
        // so copying them into `buf` first (the old `burst_msg_copy` arm) was
        // one full payload memcpy per drained reply. The portable fallback
        // (non-Linux, or a kernel without `recvmmsg`) still copies into `buf`
        // and runs the same body there — `with_burst_msg` returns `None` off
        // Linux, so that is the arm macOS/BSD runs, unchanged.
        //
        // Tokio keeps recv readiness set until a `WouldBlock`, so the remainder
        // is picked up on the next poll; nothing queues in userspace. A drained
        // error ends the burst, not the session: the head already proved the
        // socket live this poll.
        let mut drained = 1usize;
        let mut head: Option<(usize, SocketAddr)> = Some((n, src));
        // recvmmsg burst state (Linux): `burst_i < burst_n` consumes staged
        // datagrams; otherwise one refill syscall covers the remaining
        // per-wakeup budget. Both counters stay 0 on the portable path, where
        // the `try_recv_from` arm below runs.
        let mut burst_n = 0usize;
        let mut burst_i = 0usize;
        // The per-reply body is fully synchronous, so every arm can run it
        // while a borrowed payload is live (the Linux burst arm does exactly
        // that). Kept as a macro so the argument list exists once.
        macro_rules! handle_reply {
            ($msg:expr, $src:expr) => {
                handle_session_reply(
                    &c2,
                    s,
                    $msg,
                    $src,
                    reply_filter,
                    &mut r2,
                    &stage,
                    &mut frag2,
                    flows.as_ref(),
                    &mut limit,
                    &mut last_too_large_probe_ms,
                    &mut last_touch,
                    &mut last_limit_refresh,
                    last2.as_ref(),
                    recent.as_ref(),
                    recent_epoch.as_ref(),
                    &mut allow_snap,
                    &mut allow_epoch,
                )
            };
        }
        loop {
            let disposition = if let Some((n, src)) = head.take() {
                // The head was already copied into `buf` by `recv_from`.
                handle_reply!(&buf[..n], src)
            } else if burst_i < burst_n {
                let i = burst_i;
                burst_i += 1;
                match with_burst_msg(i, |msg, src| handle_reply!(msg, src)) {
                    Some(disposition) => {
                        drained += 1;
                        disposition
                    }
                    // No burst scratch reachable here (portable fallback): copy
                    // the staged message out to `buf` and run the same body on
                    // it, exactly like the old drain arm.
                    None => match burst_msg_copy(i, &mut buf) {
                        Some((n, src)) => {
                            drained += 1;
                            handle_reply!(&buf[..n], src)
                        }
                        None => break,
                    },
                }
            } else {
                if drained >= LAST_HOP_DRAIN {
                    break;
                }
                match recv_burst(&rs, LAST_HOP_DRAIN - drained) {
                    Some(0) => break,
                    Some(k) => {
                        burst_n = k;
                        burst_i = 1;
                        match with_burst_msg(0, |msg, src| handle_reply!(msg, src)) {
                            Some(disposition) => {
                                drained += 1;
                                disposition
                            }
                            None => match burst_msg_copy(0, &mut buf) {
                                Some((n, src)) => {
                                    drained += 1;
                                    handle_reply!(&buf[..n], src)
                                }
                                None => break,
                            },
                        }
                    }
                    None => match rs.try_recv_from(&mut buf) {
                        Ok((n, src)) => {
                            drained += 1;
                            handle_reply!(&buf[..n], src)
                        }
                        Err(_) => break,
                    },
                }
            };
            match disposition {
                ReplyDisposition::Continue => {}
                ReplyDisposition::BreakSession => break 'session,
            }
        }
        // Drain-burst boundary: this is where a burst's small replies (from
        // this session and from any other that pushed in the meantime) go out,
        // aggregated by the connection stager into steady frames / one
        // cross-session dict TRAIN. A terminal verdict means DATAGRAM support or
        // the connection is gone: exit after the stager has accounted the
        // refused frame (remaining items stay queued for the connection drop).
        if drain_stage(&c2, &stage, &mut limit, &mut last_too_large_probe_ms)
            == StageDrain::Terminal
        {
            break 'session;
        }
        // A `Blocked` verdict left the remaining items queued; arm the retry
        // timer so a quiet tail cannot wait for another session's burst (or
        // connection close). One stager-lock probe per burst, and the timer is
        // disarmed as soon as the queue is empty.
        stage_backlog = stage_has_backlog(&stage);
        record_drain_batch(drained);
    }
    // Every exit above breaks to here, so the buffer is recycled exactly once
    // per reader lifetime, however the task ended (idle reap, abort-adjacent
    // error, lost DATAGRAM support).
    sess_recycle_buf(buf);
    sess_memo_forget(conn_id, s, &rs);
    let mut removed_r2 = None;
    // Bindings purged while the shard write guard that removed the dead entry
    // is still held (PERF-7: one registry write lock for the whole association
    // instead of one per binding).
    let mut purged_on_exit = 0usize;
    // Set by the removal block below; read after it to decide whether this
    // reader's exit is the reap the client must be told about.
    let removed_own;
    {
        let sh = ss2.shard(s);
        let mut w = sh.write();
        let mut removed = false;
        if let Some(cur) = w.get(&s)
            && Arc::ptr_eq(&cur.sock, &rs)
            && let Some(entry) = w.remove(&s)
        {
            removed = true;
            // Purge by session id under the shard write guard: the guard
            // excludes both a recreation of this session id and any in-flight
            // install (`r2_install` holds the same shard's read guard across its
            // registry insert), so every binding the registry still indexes
            // under `s` belongs to the entry just removed — one registry write
            // lock replaces one per binding, and the purge can only touch this
            // dead entry (wire ids are never reused).
            if let Some(registry) = r2_registry.as_ref() {
                // Singular purge: a session that never installed a rev2 binding
                // (the common TCP-only / INLINE shape) exits after one index
                // probe instead of taking the forward table's write lock.
                purged_on_exit = registry.remove_session(s);
            }
            removed_r2 = Some(entry.r2_flows);
        }
        if removed {
            ss2.note_live_remove(1);
        }
        removed_own = removed;
    }
    if purged_on_exit > 0 {
        r2_stats::SESSION_END_BINDINGS
            .fetch_add(purged_on_exit as u64, std::sync::atomic::Ordering::Relaxed);
    }
    // Tell the client this association is gone (idle reap, socket read error or
    // a terminal egress verdict). Without it the client keeps sending steady
    // frames for a session the server no longer has — each one fails lookup and
    // is silently dropped — until its own idle path notices. Best-effort and
    // idempotent, like every `SESS_CLOSE`; a connection that is already closed
    // needs no notification (the sends would only be dropped).
    if removed_own && c2.close_reason().is_none() {
        r2_send_sess_close(&c2, r2.conn.as_ref(), s);
    }
    // Mark this dead entry's bindings `Closed` from its own reverse-table
    // snapshot, so a reply reader still draining cannot match a torn-down
    // binding. The registry entries themselves were already purged above, under
    // the shard guard that removed the entry (LOGIC-9 removed the old
    // "does the table still hold an entry?" guard: it leaked the dead entry's
    // bindings whenever a same-id session had been recreated, and snapshot /
    // guard scoping is what protects a recreated session's fresh bindings —
    // wire ids are never reused, so those ids cannot appear here).
    if let Some(r2_flows) = removed_r2 {
        let flows = r2_flows.load();
        for binding in flows.iter() {
            binding.mark_closed();
        }
        if !flows.is_empty() {
            r2_flows.store(Arc::new(SessionFlows::new()));
        }
    }
    // The table may now be empty: if this was its last session, drop out of the
    // fair-share denominator so other connections immediately get their full
    // share back. Must run with the write guard above dropped (see
    // `note_empty_state`).
    ss2.note_empty_state();
}

/// Finish a reap batch whose rev2 registry purge already ran (batched under
/// the session shard's write lock by the caller): mark the dead entries'
/// reverse-table snapshots closed so a reply reader still draining cannot match
/// a torn-down binding, and account the removed bindings.
///
/// The purge itself is *not* done here: calling [`FlowRegistry::remove_session`]
/// per entry would take one registry write lock per session (the PERF-7 stall),
/// and purging by wire id one at a time is worse. The caller holds the shard
/// write guard that removed the entries, which is exactly the condition that
/// makes a single `remove_sessions(&sessions)` collision-safe.
fn r2_finish_reaped(r2: Option<&Arc<R2ConnState>>, entries: &[SessEntry], purged: usize) {
    if r2.is_none() {
        return;
    }
    r2_finish_reaped_entries(entries, purged);
}

/// Resolve this session's socket, creating it (and its reply reader) when the
/// datagram is the session's first.
///
/// The plain entry point: every caller here is a *live* datagram path whose
/// session cannot be cancelled behind its back, so there is nothing to check
/// before publishing. The two DNS lookup tasks — the rev2 `DATA OPEN` resolver
/// and the generic slow path (`forward_server_dgram`'s `Unresolved` arm), both
/// of which run after the client may already have closed the association — use
/// [`get_or_create_sess_guarded`] instead.
pub(crate) async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    dest: Option<(&str, u16, SocketAddr, u64)>,
    r2: Option<&Arc<R2ConnState>>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    get_or_create_sess_guarded(ss, cd, conn_id, s, dest, r2, None).await
}

/// [`get_or_create_sess`] with a cancellation flag for an association that a
/// `CTL SESS_CLOSE` may close while this creation is in flight.
///
/// Both DNS waiter tasks (rev2 `DATA OPEN`, and the generic datagram slow path
/// via its [`DnsWaiter`]) pass their own flag here. `SESS_CLOSE` sets the flag
/// *before* `take_session`, and the creation path re-reads it inside the shard
/// write critical section immediately before publishing the entry; together
/// those two facts mean the close either sees the flag (and the creation rolls
/// itself back) or is serialized after the publish (and removes the session).
/// Without the flag, a DNS lookup that outlived the client's `SESS_CLOSE`
/// recreated the session — socket, global permit and flow bindings included —
/// after the close had reaped it.
pub(crate) async fn get_or_create_sess_guarded(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    // `(host, port, resolved address)` when the caller already knows a *named*
    // destination, so the session can memoize it. An IP target passes `None`:
    // its address is already in every datagram it sends, and the memo is only
    // ever read back for domain targets (`sess_dest_store`).
    // `(host, port, resolved address, remaining life of that resolution)` — the
    // life is the source's, so the memo cannot outlive it (see `pin_life_ms`).
    dest: Option<(&str, u16, SocketAddr, u64)>,
    // The connection's rev2 state, when this session is being created by a
    // connection that speaks rev2 (production: always). The reply reader gets
    // the registry handle so a session that reaps itself can drop its bindings;
    // `None` is only used by unit fixtures that never install rev2 flows.
    r2: Option<&Arc<R2ConnState>>,
    // Set by `SESS_CLOSE` while this creation is in flight; see the type doc.
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Session 0 is reserved (never allocated by any client hub): a wire
    // datagram carrying it is malformed or hostile, not a new session.
    // Refusing here keeps it from pinning a global permit until the sweep.
    if s == 0 {
        dgram_drops::bump(&dgram_drops::REFUSED);
        return None;
    }
    // Zero-lock fast path: the common case (a burst of packets for one session)
    // allocates nothing and never touches the table. The memo's liveness check
    // is the same signal the table path uses (`JoinHandle::is_finished`) — one
    // atomic load — so a session whose reader has exited, aborted included,
    // still falls through and is recreated.
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, _, _) => {
            // Refresh liveness without the table lock; a session captured here is
            // scheduled by its reader and may be exiting, in which case one reply
            // is dropped and the next packet recreates it.
            touch_session_throttled(conn_id, s, &last);
            if let Some((h, p, d, life)) = dest {
                sess_dest_store(ss, s, h, p, d, life);
            }
            return Some(sock);
        }
        SessHit::Stale | SessHit::Miss => {}
    }
    // Fast path: single shard read + lock-free timestamp bump. A session whose
    // reply reader has already exited is treated as absent so its next packet
    // recreates it instead of black-holing.
    //
    // The read *blocks* rather than failing fast. Pass 21 made this a
    // `try_lock_read` that dropped the datagram on failure and counted it in
    // `SESSION_FULL`, reasoning that a packet path must never park a worker.
    // Pass 23 revisited that: the table is per-connection, so the only
    // cross-task writers are a session reader exiting (a `get` plus maybe a
    // `remove`), the 60 s sweeper's removal loop, and a DNS-spawned
    // `get_or_create_sess` -- all short, allocation-free critical sections. The
    // datagram reader is by far the commonest writer itself, so it cannot
    // contend with itself. Against that, the old behaviour silently dropped a
    // datagram every time any of those brief writers won the race, and charged
    // the drop to a counter documented as "budget exhausted", hiding relay loss
    // inside a resource-limit metric. `parking_lot`'s `RwLock::read` already
    // spin-tries before it parks, so the uncontended cost is unchanged; only the drop is
    // gone.
    {
        let sh = ss.shard(s);
        let r = sh.read();
        if let Some(e) = r.get(&s)
            && !e.reader.is_finished()
        {
            let sock = e.sock.clone();
            let last = e.last.clone();
            let abort = e.reader.abort_handle();
            let epoch = e.recent_epoch.clone();
            touch_session_throttled(conn_id, s, &e.last);
            drop(r);
            // Publish this thread's memo from the table. A session created
            // by a DNS-spawned resolver task lives on another worker's memo
            // (or on none), and without this the per-connection fast path
            // could never arm for it: the caller's `SessHit::Miss` would
            // clear the fast state on every datagram instead of adopting
            // the session that was just used.
            sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
            if let Some((h, p, d, life)) = dest {
                sess_dest_store(ss, s, h, p, d, life);
            }
            return Some(sock);
        }
    }
    // Fair share first: one connection must not grow past an equal split of the
    // process-wide budget while others live. Only expired sessions are
    // reclaimed here; live ones keep their sockets and the global semaphore
    // still caps the true total.
    //
    // The reap is **throttled** (per worker, 1/s) for the same reason the global
    // pool's failed-acquire path is: past the cap every further new-session
    // datagram reaches this branch, and an unthrottled `sweep_all` would walk
    // all shards and every session entry *per packet* — an O(sessions) CPU
    // amplifier any peer can drive with fabricated session ids, for a sweep
    // that can only ever free sessions that went idle >= SESS_IDLE_MS ago.
    let fair_cap = fair_sess_cap();
    // Served from the bounded sample (see `len_upper_bound`): past the cap every
    // further new-session datagram reaches this branch, so a fresh 8-lock
    // measurement per forged packet is pure lock traffic — but the bound counts
    // every insert since the sample, so a burst cannot outrun the share.
    // Re-measured exactly once the bound reaches the cap, and after a sweep
    // actually ran (it may have freed sessions).
    let now = mono_millis();
    if ss.len_upper_bound(now) >= fair_cap {
        if claim_fair_sweep(now) {
            // Each shard's bindings are purged in one registry call under that
            // shard's write lock (`sweep_all_with`); the notifications are sent
            // from a detached chunked task so this creation path is not blocked
            // for thousands of sends.
            let mut purged = 0usize;
            let evicted = ss.sweep_all_with(now, |ids| {
                if let Some(state) = r2 {
                    purged += state.registry.remove_sessions(ids);
                }
            });
            r2_finish_reaped(r2, &evicted, purged);
            // The client's association is gone on this side: tell it, so its
            // next steady frames do not target a session the server no longer
            // has (they could only fail lookup). Best-effort and idempotent.
            let ids: Vec<u32> = evicted.iter().map(|e| e.sess).collect();
            spawn_sess_close_notifications(cd.clone(), r2.cloned(), ids);
            abort_evicted(evicted);
            let now2 = mono_millis();
            let n2 = ss.len();
            ss.store_len(n2, now2);
            if n2 >= fair_cap {
                dgram_drops::bump(&dgram_drops::FAIR_SHARE);
                return None;
            }
        } else {
            dgram_drops::bump(&dgram_drops::FAIR_SHARE);
            return None;
        }
    }
    // No DATAGRAM support on this path: refuse before pinning a global permit,
    // a kernel socket and a reader task for a session whose replies would all
    // be dropped (`limit == 0` in the reader). Negotiated at the handshake, so
    // it never flaps mid-connection — and since a hit above can only be a
    // session that passed this check already, it stays off the per-packet path
    // instead of taking the connection-state lock for every datagram.
    //
    // Deliberately *after* the cheap fair-share gates: `max_datagram_size`
    // takes quinn's connection-state mutex, and a peer can force this branch
    // once per packet with a fabricated session id. The gates above need no
    // quinn lock, so a forged id that is over the connection's fair share is
    // refused without ever touching the mutex; only a datagram that could
    // really create a session pays the probe. (Before this move the probe ran
    // first, i.e. a forged-id flood took the state lock per packet to reach a
    // refusal that needed no lock at all.)
    cd.max_datagram_size()?;
    // Check the global pool BEFORE creating the socket: once every session slot
    // is held there is no point paying socket()+setsockopt()+bind() per packet.
    let permit = match session_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Throttled reap through the process-wide sweep window (see
            // `FAIR_SWEEP_LAST_MS`): a per-worker throttle here let W workers
            // run W full-table sweeps per second under permit pressure.
            if !claim_fair_sweep(mono_millis()) {
                dgram_drops::bump(&dgram_drops::SESSION_FULL);
                return None;
            }
            let mut purged = 0usize;
            let evicted = ss.sweep_all_with(mono_millis(), |ids| {
                if let Some(state) = r2 {
                    purged += state.registry.remove_sessions(ids);
                }
            });
            r2_finish_reaped(r2, &evicted, purged);
            let ids: Vec<u32> = evicted.iter().map(|e| e.sess).collect();
            spawn_sess_close_notifications(cd.clone(), r2.cloned(), ids);
            abort_evicted(evicted);
            match session_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    dgram_drops::bump(&dgram_drops::SESSION_FULL);
                    return None;
                }
            }
        }
    };
    // Create the socket outside the write lock: socket()/setsockopt()/bind()
    // are syscalls and must not stall the datagram reader for every session.
    // Both syscall failures are resource events the operator has to see, so
    // neither is allowed to return silently.
    let raw = match udp_socket_dual_small("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not created ({n} so far): {e:#}");
            }
            return None;
        }
    };
    let sock = match tokio::net::UdpSocket::from_std(raw) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not registered ({n} so far): {e}");
            }
            return None;
        }
    };
    let c2_pre = cd.clone();
    let rs_pre = sock.clone();
    let ss_pre = ss.clone();
    let last_pre = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let recent_pre: Arc<arc_swap::ArcSwap<RecentAddrs>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default()));
    let recent_epoch: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));
    let flows_pre: Arc<arc_swap::ArcSwap<FlowTable>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    // The rev2 reverse table starts empty and is filled by `DATA OPEN` installs;
    // the registry handle lets this session's reply reader drop its bindings if
    // the reader exits on its own (idle reap or a dead socket).
    let r2_flows_pre: Arc<arc_swap::ArcSwap<SessionFlows>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(SessionFlows::new()));
    let r2_registry_pre: Option<Arc<FlowRegistry>> = r2.map(|st| st.registry.clone());
    // Connection-scoped Phase-2 stager. A session created off a test fixture
    // without connection state gets a private empty one: it can stage and send
    // its replies, it just cannot aggregate across sessions.
    // The reply reader needs the same connection state for full-cone
    // server-owned flow creation (id allocation + registry install).
    let r2_conn_pre: Option<Arc<R2ConnState>> = r2.cloned();
    let r2_stage_pre: Arc<parking_lot::Mutex<R2Stager>> = r2.map_or_else(
        || Arc::new(parking_lot::Mutex::new(R2Stager::new())),
        |st| st.stage.clone(),
    );
    let h_pre = tokio::spawn(sess_reader_task(
        conn_id,
        s,
        rs_pre,
        ss_pre,
        c2_pre,
        last_pre.clone(),
        recent_pre.clone(),
        recent_epoch.clone(),
        flows_pre.clone(),
        r2_flows_pre.clone(),
        r2_registry_pre,
        r2_conn_pre,
        r2_stage_pre,
        ss.reply_filter,
    ));
    let reader_abort = h_pre.abort_handle();
    let mut stale_dead: Vec<SessEntry> = Vec::new();
    let mut swept: Vec<SessEntry> = Vec::new();
    // `cancelled_insert` is the third outcome of the publish critical section:
    // the owning domain-OPEN task was cancelled by `SESS_CLOSE` while this
    // creation was in flight, so the session must not be published at all.
    let (inserted, memo_data, reader_died, cancelled_insert, purged_reaped) = {
        let sh = ss.shard(s);
        // Blocks for the same reason the read path does: a losing `try_lock_write`
        // used to abort the freshly spawned reader, release the global permit and
        // drop the datagram, which is strictly worse than waiting out a short
        // `HashMap` mutation. The socket syscalls above deliberately stay outside
        // this critical section.
        let mut w = sh.write();
        if let Some(e) = w.get(&s) {
            if !e.reader.is_finished() {
                touch_session_throttled(conn_id, s, &e.last);
                let sock2 = e.sock.clone();
                let last2 = e.last.clone();
                let abort2 = e.reader.abort_handle();
                // The *live entry's* allowlist epoch, not the fresh one built for
                // the reader that is about to be aborted: the memo must describe
                // the session that stays in the table, or the mirror would never
                // see that session's pushes move.
                let epoch2 = e.recent_epoch.clone();
                drop(w);
                h_pre.abort();
                drop(permit);
                // Same reason as the read path above: adopt the live entry into
                // this thread's memo so the caller's fast path can arm.
                sess_memo_put(conn_id, s, sock2.clone(), last2, abort2, epoch2);
                if let Some((h, p, d, life)) = dest {
                    sess_dest_store(ss, s, h, p, d, life);
                }
                return Some(sock2);
            }
            if let Some(e) = w.remove(&s) {
                stale_dead.push(e);
            }
            if !stale_dead.is_empty() {
                ss.note_live_remove(stale_dead.len());
            }
        }
        // Over its fair share, this shard reaps its expired sessions now instead
        // of waiting for the 60 s sweeper. Live over-share is left alone (the
        // connection-level fair-share gate is the resource bound); the reap is
        // gated on the process-wide sweep window, or every forged new-session
        // datagram would run an O(shard) scan under this write lock — a CPU
        // amplifier any peer could drive.
        if shard_over_share(w.len(), fair_sess_cap()) && claim_fair_sweep(mono_millis()) {
            swept = sweep_local(&mut w);
            ss.note_live_remove(swept.len());
        }
        // Batched rev2 purge for both reap batches, under this shard's write
        // guard: purge-by-session is collision-safe here (no datagram path can
        // recreate an id or install a binding while the guard is held) and the
        // whole batch costs one registry write lock instead of one per
        // session/binding. PERF-7: this is the reap that runs on the datagram
        // reader under memory pressure, so the lock count matters.
        let mut purged_reaped = 0usize;
        if !stale_dead.is_empty() || !swept.is_empty() {
            let mut ids: Vec<u32> = stale_dead.iter().map(|e| e.sess).collect();
            ids.extend(swept.iter().map(|e| e.sess));
            if let Some(state) = r2 {
                purged_reaped = state.registry.remove_sessions(&ids);
            }
        }
        // The owning domain-OPEN task was cancelled by a `CTL SESS_CLOSE` while
        // this creation was in flight: do not publish the session. `SESS_CLOSE`
        // sets the flag *before* its `take_session` (which needs this same
        // shard write lock), so either the removal already happened — this
        // check sees the flag and rolls the abandoned insert back — or it will
        // happen after this guard drops and remove what we published. Both
        // orders leave no session behind, which is the point: the client closed
        // the association and a late DNS answer must not resurrect it. The
        // freshly spawned reader and the global permit are returned with the
        // abandoned insert; the reaped entries above are still cleaned up by
        // the caller's tail.
        if cancelled.is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed)) {
            h_pre.abort();
            drop(permit);
            (false, None, false, true, purged_reaped)
        } else {
            let dead = h_pre.is_finished();
            w.insert(
                s,
                SessEntry {
                    // The entry's own id, so reap paths outside the shard scan
                    // (sweep results, the reader's exit) can name the session in
                    // the `SESS_CLOSE` notification they send the client.
                    sess: s,
                    sock: sock.clone(),
                    reader: h_pre,
                    last: last_pre.clone(),
                    _permit: permit,
                    dest: dest
                        .and_then(|(h, p, a, life)| Some((PortKey::new(h, p)?, a, life)))
                        .map_or(DestMemo::NONE, |(key, addr, life)| DestMemo {
                            key,
                            addr,
                            expires: coarse_millis() + pin_life_ms(life),
                        }),
                    recent: recent_pre.clone(),
                    recent_epoch: recent_epoch.clone(),
                    flows: flows_pre.clone(),
                    r2_flows: r2_flows_pre,
                },
            );
            ss.note_live_insert();
            if dead || w.get(&s).map(|e| e.reader.is_finished()).unwrap_or(false) {
                if let Some(e) = w.remove(&s) {
                    e.reader.abort();
                }
                // The insert above is undone while this guard is still held, so
                // the decrement always pairs with its increment.
                ss.note_live_remove(1);
                (false, None, true, false, purged_reaped)
            } else {
                (
                    true,
                    Some((sock.clone(), last_pre.clone(), reader_abort.clone())),
                    false,
                    false,
                    purged_reaped,
                )
            }
        }
    };
    if cancelled_insert {
        // The close won the race: nothing was published, so there is no memo or
        // reader to hand out. Finish the shared tail (holder state + reaped
        // entries) and report "no session" to the caller, which rejects the
        // OPEN instead of ACKing a closed association.
        ss.note_empty_state();
        r2_finish_reaped(r2, &stale_dead, purged_reaped);
        r2_finish_reaped(r2, &swept, 0);
        let ids: Vec<u32> = swept.iter().map(|e| e.sess).collect();
        spawn_sess_close_notifications(cd.clone(), r2.cloned(), ids);
        abort_evicted(stale_dead);
        abort_evicted(swept);
        return None;
    }
    if inserted {
        udp_stats::session();
        ss.note_insert();
    }
    // This connection may have just become a session holder: join the fair-share
    // denominator. Called after the write guard is dropped (see
    // `note_empty_state`), and on the `dead` branch too, where the insert was
    // rolled back and the connection may not hold anything at all.
    ss.note_empty_state();
    if let Some((msock, mlast, mabort)) = memo_data {
        sess_memo_put(conn_id, s, msock, mlast, mabort, recent_epoch);
    }
    if reader_died {
        // The freshly spawned reply reader exited before the entry was
        // published (e.g. the session socket failed on first use). The datagram
        // is dropped; count it instead of leaving an operator with a session
        // that silently never comes up.
        let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
        if warn_sess_create_failed() {
            warn!("udp session {s} reader exited before publish ({n} so far)");
        }
    }
    r2_finish_reaped(r2, &stale_dead, purged_reaped);
    r2_finish_reaped(r2, &swept, 0);
    // The over-share reaps above removed live associations from this side: tell
    // the client (`SESS_CLOSE` ×3, idempotent, best-effort) from a detached
    // chunked task, so its steady frames do not target a session the server has
    // already dropped while this creation path is not blocked by the sends.
    // `stale_dead` needs no notification — those readers had already exited, so
    // the client's own idle/exit path is what closed them.
    let ids: Vec<u32> = swept.iter().map(|e| e.sess).collect();
    spawn_sess_close_notifications(cd.clone(), r2.cloned(), ids);
    abort_evicted(stale_dead);
    abort_evicted(swept);
    if inserted { Some(sock) } else { None }
}
