//! Per-connection cross-session egress stager for MQP-3 rev2 small payloads.
//!
//! With one QUIC connection carrying many UDP associations (the router/client
//! shape), the Phase-1 paths stage and send per association: one `TRAIN` per
//! session per drain burst. That already amortises the frame header, but a
//! burst of tiny payloads from N associations still becomes N MQP frames (and N
//! `send_datagram` calls). This module is the Phase-2 aggregation point:
//! associations push ready-to-send items into one connection-scoped queue, and
//! whichever task drains it packs **different sessions' flows into one
//! `TRAIN dict`**, round-robin across sessions so one busy association cannot
//! starve the others.
//!
//! # Item shapes
//!
//! * [`R2StageKind::Steady`] — a confirmed flow payload: can join a dict train
//!   with items from any session (rev2 wire ids are connection-scoped, so a
//!   train no longer needs a session header).
//! * [`R2StageKind::Open`] — the first frame of an opening flow: carries
//!   `sess + addr`, must be sent standalone (`DATA OPEN`).
//! * [`R2StageKind::Inline`] — the no-flow fail-safe: standalone `DATA INLINE`.
//!
//! `Open`/`Inline` items break a train run (they are self-describing frames,
//! not train items); ordering inside one session is preserved because each
//! session's queue is FIFO and the round-robin only ever pops from a queue's
//! head.
//!
//! # Ownership and accounting
//!
//! Payloads are owned [`Bytes`]: an item may be queued by one task and drained
//! by another, so a borrowed slice cannot outlive the push. A frame that quinn
//! accepted books `udp_stats::payload` per item; a refused frame accounts the
//! items it contained through [`crate::dgram_drops`] and leaves the rest queued
//! for the next drain. `clear` returns the number of items the caller must
//! account for when a connection dies.
//!
//! # Bounds
//!
//! The queue is bounded by item count and bytes; `push` returns the item back
//! when full so the caller can apply its own drop policy (e.g. count
//! `NO_EGRESS`/`BUFFER_FULL`). Every drain is itself bounded by the live
//! DATAGRAM budget and by a fixed batch size, so a hostile local application
//! cannot make one drain loop unbounded — and a full send buffer cannot make
//! every subsequent payload re-encode the whole queue.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use foldhash::HashSet;
use quinn::Connection;

use crate::dgram_drops;
use crate::mqp::addr::TargetAddr;
use crate::mqp::r2;
use crate::mqp::wire::{self, Wire};
use crate::udp::send::{DatagramSend, try_send_datagram};
use crate::udp_stats;

/// Default queue cap: items and bytes. A connection with 64 associations and a
/// full drain burst per association stays well below this; the caps exist to
/// bound a stalled/never-drained connection, not to shape normal traffic.
pub const R2_STAGE_MAX_ITEMS: usize = 1024;
pub const R2_STAGE_MAX_BYTES: usize = 256 * 1024;

/// One unlocked drain step packs at most this many frames / payloads. The
/// point is the *failure* path: a blocked send buffer used to make every new
/// payload re-pack the entire queue, only to have the first datagram refused
/// again. A small batch bounds that repeated work to a few frames while still
/// amortising enough payloads per DATAGRAM to keep the normal path cheap.
pub const R2_PACK_BATCH_FRAMES: usize = 4;
pub const R2_PACK_BATCH_ITEMS: usize = 64;

/// Addressing shape of one staged item.
#[derive(Debug, Clone)]
pub enum R2StageKind {
    /// Confirmed flow: only the wire id is needed; can join a dict train.
    Steady { wire_id: u32 },
    /// Opening flow: first frame carries session + address (`DATA OPEN`).
    Open {
        wire_id: u32,
        sess: u32,
        addr: TargetAddr,
        src: bool,
    },
    /// No flow id: self-describing `DATA INLINE`, standalone.
    Inline {
        sess: u32,
        addr: TargetAddr,
        src: bool,
    },
}

/// One ready-to-send payload.
#[derive(Debug, Clone)]
pub struct R2StageItem {
    /// Owning UDP session, for the round-robin fairness cursor.
    pub session: u32,
    pub kind: R2StageKind,
    pub payload: Bytes,
}

/// Result of one [`R2Stager::drain`] call.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct R2DrainOutcome {
    /// DATAGRAM frames actually queued to quinn.
    pub frames: u32,
    /// Payloads booked as sent.
    pub items_sent: u32,
    /// Payloads in the failed frame that were dropped (not sent).
    pub items_dropped: u32,
    /// The verdict that stopped the drain, if any. Remaining items stay queued.
    pub failed: Option<DatagramSend>,
}

/// One encoded DATAGRAM of a test-shape `next_frame` probe.
#[cfg(test)]
struct EncodedFrame {
    body: Bytes,
    items: u32,
}

/// One packed DATAGRAM of a [`R2Stager::pack`] batch: the encoded body plus
/// where its items sit in [`PackedFrames::items`].
#[derive(Debug)]
struct PackedFrame {
    body: Bytes,
    /// Index of the frame's first item in [`PackedFrames::items`] (the item
    /// ranges of consecutive frames ascend in frame order).
    item_off: u32,
    item_len: u32,
}

/// Phase-A/B handoff between [`R2Stager::pack`] and [`send_packed_frames`].
///
/// Produced under the stager's lock, consumed after it is released. Frames
/// carry their own item ranges into `items`, so phase B needs nothing from
/// the queues: the failed frame's payloads are where the drop accounting
/// happens, frames beyond it keep their items for [`R2Stager::requeue_unsent`].
#[derive(Debug, Default)]
pub struct PackedFrames {
    frames: Vec<PackedFrame>,
    items: Vec<R2StageItem>,
}

impl PackedFrames {
    /// Release a consumed batch. The send phase already moved the bodies into
    /// quinn (`Sent`) or accounted the failed frame; the item payloads are
    /// dead once their frames have been sent or requeued.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.items.clear();
    }
}

/// Per-connection stager. One instance lives next to the connection's
/// `FlowRegistry`/`CtlState`; associations and session readers share it.
pub struct R2Stager {
    /// Wire revision of the connection this stager belongs to.
    ///
    /// The encoder is the only thing that differs between revisions: the queue,
    /// fairness and packing policy are revision-agnostic. [`Wire::Rev2`] is the
    /// default so every existing construction site keeps byte-identical
    /// behaviour; a rev3 connection calls [`Self::set_wire`] (or
    /// [`Self::new_with_wire`]) when its state is created.
    wire: Wire,
    /// Per-session FIFO queues. A session's items are always sent in push order.
    sessions: HashMap<u32, VecDeque<R2StageItem>, foldhash::fast::RandomState>,
    /// Round-robin cursor over session ids that currently have items.
    order: VecDeque<u32>,
    /// Round-robin cursor over the subset of [`Self::order`] whose queue head is
    /// `Steady` — the only sessions a train run can draw from. A run used to
    /// scan [`Self::order`] once per packed item (O(items x sessions) when most
    /// heads are standalone `Open`/`Inline`); this cursor only ever holds
    /// sessions that can contribute, so [`Self::next_steady_session`] rotates
    /// over the steady subset instead.
    steady_order: VecDeque<u32>,
    /// Membership of [`Self::steady_order`], so a head transition (a push into
    /// an empty queue, or a pop revealing a new head) queues a session at most
    /// once. A slot whose session emptied or whose head stopped being `Steady`
    /// is dropped lazily by [`Self::next_steady_session`]; the session rejoins
    /// on its next transition.
    steady_mark: HashSet<u32>,
    queued_items: usize,
    queued_bytes: usize,
    max_items: usize,
    max_bytes: usize,
    /// Negotiated `CAPS.max_train_items`, clamped to the codec bound.
    max_train_items: usize,
    /// Scratch for the run being packed. Cleared per frame and owned by the
    /// stager, so packing a queue full of frames costs no fresh allocation:
    /// the per-frame `run`/`unique` `Vec`s this used to allocate are the two
    /// hot spots of every drain burst on both ends, and the dict item views
    /// live in a fixed stack array at the codec call (their payload borrows
    /// cannot live in a stager field) rather than a fresh per-frame `Vec`.
    run_scratch: Vec<R2StageItem>,
    unique_scratch: Vec<u32>,
    /// `wire_id -> index into the frame's dict flow list`, rebuilt per train
    /// frame from [`Self::unique_scratch`] and reused across frames (clear
    /// keeps the allocation). Replaces the per-item `flows_scratch.iter()
    /// .position(..)` scan, which was O(flows x items) inside the stager lock.
    flow_idx_scratch: HashMap<u32, u8, foldhash::fast::RandomState>,
}

impl Default for R2Stager {
    fn default() -> Self {
        Self::with_capacity_wire(R2_STAGE_MAX_ITEMS, R2_STAGE_MAX_BYTES, Wire::Rev2)
    }
}

impl R2Stager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A stager that encodes for `wire` (rev2 keeps the shipped behaviour,
    /// which is also [`Self::new`]).
    #[must_use]
    pub fn new_with_wire(wire: Wire) -> Self {
        Self::with_capacity_wire(R2_STAGE_MAX_ITEMS, R2_STAGE_MAX_BYTES, wire)
    }

    #[must_use]
    pub fn with_capacity(max_items: usize, max_bytes: usize) -> Self {
        Self::with_capacity_wire(max_items, max_bytes, Wire::Rev2)
    }

    /// Test/configuration seam: same queue bounds, explicit wire revision.
    #[must_use]
    pub fn with_capacity_wire(max_items: usize, max_bytes: usize, wire: Wire) -> Self {
        Self {
            wire,
            sessions: HashMap::with_hasher(foldhash::fast::RandomState::default()),
            order: VecDeque::new(),
            steady_order: VecDeque::new(),
            steady_mark: HashSet::with_hasher(foldhash::fast::RandomState::default()),
            queued_items: 0,
            queued_bytes: 0,
            max_items,
            max_bytes,
            max_train_items: r2::R2_MAX_TRAIN_ITEMS,
            run_scratch: Vec::new(),
            unique_scratch: Vec::new(),
            flow_idx_scratch: HashMap::with_hasher(foldhash::fast::RandomState::default()),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queued_items
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued_items == 0
    }

    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Set the wire revision this stager encodes for.
    ///
    /// Called by the connection state constructor (a stager is created before
    /// its connection's wire is known in a few test seams); changing it with
    /// items queued would re-encode them under another revision, so callers
    /// only do this before the first push.
    pub fn set_wire(&mut self, wire: Wire) {
        self.wire = wire;
    }

    /// Wire revision this stager encodes for.
    #[must_use]
    pub fn wire(&self) -> Wire {
        self.wire
    }

    /// Apply the negotiated `CAPS.max_train_items` (clamped to the codec bound;
    /// 0 means "peer did not advertise", keep the default 64).
    pub fn set_max_train_items(&mut self, n: u8) {
        if n > 0 {
            self.max_train_items = usize::from(n).min(r2::R2_MAX_TRAIN_ITEMS);
        }
    }

    /// Drop queue entries belonging to a closed session (`SESS_CLOSE`), returning
    /// how many payloads the caller should account for. A closed association's
    /// queued datagrams must not be sent to a session the server already reaped.
    pub fn drop_session(&mut self, session: u32) -> usize {
        let Some(queue) = self.sessions.remove(&session) else {
            return 0;
        };
        let mut removed = 0usize;
        for item in queue {
            self.queued_items = self.queued_items.saturating_sub(1);
            self.queued_bytes = self.queued_bytes.saturating_sub(item.payload.len());
            removed += 1;
        }
        // The order deque keeps a stale slot for `session`; next_session skips
        // sessions whose map entry is gone, so no explicit removal is needed.
        // The steady cursor is cleaned eagerly: it is a cold path, and a stale
        // mark would otherwise have to be validated before the session could
        // rejoin after a reopen.
        self.forget_steady(session);
        for _ in 0..removed {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        removed
    }

    /// Drop queue entries naming a closed flow (`FLOW_CLOSE`), preserving the
    /// order of the remaining items in each session queue.
    ///
    /// This scans every session's queue; [`Self::drop_flow_scoped`] is the
    /// session-local variant for callers that know the association. Both book
    /// one `EGRESS_DEAD` per removed item.
    pub fn drop_flow(&mut self, wire_id: u32) -> usize {
        let mut removed = 0usize;
        let mut touched = Vec::new();
        for (session, queue) in self.sessions.iter_mut() {
            let before = queue.len();
            queue.retain(|item| match &item.kind {
                R2StageKind::Steady { wire_id: id } | R2StageKind::Open { wire_id: id, .. } => {
                    *id != wire_id
                }
                R2StageKind::Inline { .. } => true,
            });
            let dropped = before - queue.len();
            if dropped > 0 {
                removed += dropped;
                touched.push(*session);
            }
        }
        if removed == 0 {
            return 0;
        }
        // Rebuild the accounting exactly (rare close path).
        let items: usize = self.sessions.values().map(VecDeque::len).sum();
        let bytes: usize = self
            .sessions
            .values()
            .flat_map(|q| q.iter())
            .map(|i| i.payload.len())
            .sum();
        self.queued_items = items;
        self.queued_bytes = bytes;
        // A retained queue may have lost its steady head; rebuild the steady
        // cursor from the surviving heads, then re-seat the sessions whose head
        // the purge revealed (cold path; the sort keeps the touched order
        // deterministic, since the map iteration order is not).
        let sessions = &self.sessions;
        self.steady_order.retain(|session| {
            sessions
                .get(session)
                .and_then(|q| q.front())
                .is_some_and(|item| matches!(item.kind, R2StageKind::Steady { .. }))
        });
        self.steady_mark = self.steady_order.iter().copied().collect();
        touched.sort_unstable();
        for session in touched {
            self.add_steady_head(session);
        }
        for _ in 0..removed {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        removed
    }

    /// Session-scoped [`Self::drop_flow`]: purge queued entries naming a closed
    /// flow from one association's queue only.
    ///
    /// The connection-scoped close path already knows which session the flow
    /// belonged to, so this scans a single queue instead of every session's.
    /// Returns how many payloads were removed and books one `EGRESS_DEAD` per
    /// payload, exactly like [`Self::drop_flow`]. An unknown session or a queue
    /// with no matching flow removes nothing, books nothing and returns 0.
    pub fn drop_flow_scoped(&mut self, session: u32, wire_id: u32) -> usize {
        let Some(queue) = self.sessions.get_mut(&session) else {
            return 0;
        };
        let before = queue.len();
        let mut freed = 0usize;
        queue.retain(|item| {
            let matches = match &item.kind {
                R2StageKind::Steady { wire_id: id } | R2StageKind::Open { wire_id: id, .. } => {
                    *id == wire_id
                }
                R2StageKind::Inline { .. } => false,
            };
            if matches {
                freed = freed.saturating_add(item.payload.len());
            }
            !matches
        });
        let removed = before - queue.len();
        if removed == 0 {
            return 0;
        }
        self.queued_items = self.queued_items.saturating_sub(removed);
        self.queued_bytes = self.queued_bytes.saturating_sub(freed);
        // Re-seat the session in the steady cursor: the purge may have removed
        // the queue head, emptying the queue or revealing a new one (cold
        // path; O(1) plus the mark lookup).
        let steady_head = self
            .sessions
            .get(&session)
            .and_then(|q| q.front())
            .is_some_and(|item| matches!(item.kind, R2StageKind::Steady { .. }));
        if steady_head {
            self.add_steady_head(session);
        } else {
            self.forget_steady(session);
        }
        for _ in 0..removed {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        removed
    }

    /// Queue one item. Returns the queue length after the push, so a caller
    /// can fire an opportunistic drain (`queued >= one train`) with the same
    /// lock hold instead of paying a second acquisition for a length read.
    /// On a full queue the item is returned unchanged so the caller can apply
    /// its own drop accounting (never silently lost here).
    pub fn push(&mut self, item: R2StageItem) -> Result<usize, R2StageItem> {
        if self.queued_items >= self.max_items
            || self
                .queued_bytes
                .saturating_add(item.payload.len())
                .gt(&self.max_bytes)
        {
            return Err(item);
        }
        let session = item.session;
        let bytes = item.payload.len();
        let queue = self.sessions.entry(session).or_default();
        let was_empty = queue.is_empty();
        if was_empty {
            self.order.push_back(session);
        }
        queue.push_back(item);
        self.queued_items += 1;
        self.queued_bytes += bytes;
        if was_empty {
            // The session (re)joins the round-robin; a steady head also joins
            // the steady cursor a train run rotates over.
            self.add_steady_head(session);
        }
        Ok(self.queued_items)
    }

    /// Drop everything, returning how many items the caller must account for
    /// (connection death / teardown).
    pub fn clear(&mut self) -> usize {
        let n = self.queued_items;
        self.sessions.clear();
        self.order.clear();
        self.steady_order.clear();
        self.steady_mark.clear();
        self.queued_items = 0;
        self.queued_bytes = 0;
        n
    }

    /// Phase A of the drain: pack up to `max_frames` DATAGRAM bodies, stopping
    /// before a new frame once `max_items` payloads have been moved, and moving
    /// item ownership into `q` in encounter order. (The frame already in
    /// progress may overshoot the item cap by up to one train; both bounds are
    /// still fixed.) Returns `true` when the queue still holds items after the
    /// batch (the caller can continue with another short lock hold).
    ///
    /// This runs under the caller's stager lock, which is the point of the
    /// split: the burst drains used to hold that lock across encode **and**
    /// the whole series of `try_send_datagram` calls, so every association's
    /// `push` waited behind one slow send. Packing is pointer moves and
    /// bookkeeping; [`send_packed_frames`] then writes to the wire without
    /// the lock, and [`Self::requeue_unsent`] returns anything left over
    /// behind a fresh (non-blocking-on-send) lock hold.
    ///
    /// The batch bound is what keeps a blocked send buffer cheap: the caller
    /// only re-encodes a few frames before the first `Blocked` verdict, not
    /// the entire queue on every payload.
    pub fn pack_batch(
        &mut self,
        limit: usize,
        max_frames: usize,
        max_items: usize,
        q: &mut PackedFrames,
    ) -> bool {
        let start_frames = q.frames.len();
        let start_items = q.items.len();
        while q.frames.len() - start_frames < max_frames && q.items.len() - start_items < max_items
        {
            if !self.pack_one_frame(limit, q) {
                break;
            }
        }
        !self.is_empty()
    }

    /// Pack exactly one DATAGRAM (returns `false` when the queue is empty).
    ///
    /// A run of confirmed flows from any sessions becomes one `TRAIN dict`; a
    /// single confirmed item becomes a 2 B steady `DATA`; `Open`/`Inline`
    /// items become standalone self-describing frames.
    fn pack_one_frame(&mut self, limit: usize, q: &mut PackedFrames) -> bool {
        let Some(session) = self.next_session() else {
            return false;
        };
        let head_is_standalone = self
            .sessions
            .get(&session)
            .and_then(|q| q.front())
            .is_some_and(|i| !matches!(i.kind, R2StageKind::Steady { .. }));
        if head_is_standalone {
            let Some(item) = self.pop_one(session) else {
                return true;
            };
            match self.encode_standalone(&item, limit) {
                Some(body) => {
                    let item_off = q.items.len() as u32;
                    q.items.push(item);
                    q.frames.push(PackedFrame {
                        body,
                        item_off,
                        item_len: 1,
                    });
                }
                // The live budget shrank below a queued standalone item: drop
                // it (counted) and keep packing.
                None => self.drop_too_large(1),
            }
            return true;
        }
        // Steady run into the reusable scratch, then encode. The scratch is
        // emptied per frame; `take`/restore keeps the allocations across
        // frames (and avoids double `&mut self` between the field and the
        // per-session pops).
        let mut run = std::mem::take(&mut self.run_scratch);
        let mut unique = std::mem::take(&mut self.unique_scratch);
        let mut flow_idx = std::mem::take(&mut self.flow_idx_scratch);
        run.clear();
        unique.clear();
        // Frame-header bytes before any item: rev2 has one byte each for
        // kind/form/count/nfl, rev3 folds the form into b0 (b0 + nfl + count).
        let mut cost = match self.wire {
            Wire::Rev2 => 4usize,
            Wire::Rev3 => 3usize,
        };
        let mut took_any = self.take_steady_head(session, limit, &mut run, &mut unique, &mut cost);
        while took_any && let Some(next) = self.next_steady_session() {
            took_any = self.take_steady_head(next, limit, &mut run, &mut unique, &mut cost);
        }
        let run_len = run.len();
        if run_len == 0 {
            // The steady head does not fit the live limit (or stopped being
            // the front): free the slot so the loop makes progress.
            let front_still_steady = self
                .sessions
                .get(&session)
                .and_then(|qq| qq.front())
                .is_some_and(|i| matches!(i.kind, R2StageKind::Steady { .. }));
            if front_still_steady {
                let _ = self.pop_one(session);
                self.drop_too_large(1);
            }
            self.run_scratch = run;
            self.unique_scratch = unique;
            self.flow_idx_scratch = flow_idx;
            return true;
        }
        let encoded = if run_len == 1 {
            let R2StageKind::Steady { wire_id } = run[0].kind else {
                unreachable!("a steady run only holds steady items");
            };
            wire::encode_data_steady(self.wire, wire_id, &run[0].payload, limit)
        } else {
            self.encode_train_run(unique.as_slice(), &mut flow_idx, &run, limit)
        };
        match encoded {
            Some(body) => {
                let item_off = q.items.len() as u32;
                q.items.append(&mut run);
                q.frames.push(PackedFrame {
                    body,
                    item_off,
                    item_len: run_len as u32,
                });
            }
            // The live budget shrank under queued items: drop this run
            // (counted) and keep packing the rest.
            None => self.drop_too_large(run_len),
        }
        // Restore the scratch for the next frame (capacity preserved; `run`
        // was appended into `q`, so the empty Vec keeps its allocation).
        self.run_scratch = run;
        self.unique_scratch = unique;
        self.flow_idx_scratch = flow_idx;
        true
    }

    /// Account `n` payloads dropped because the live path budget no longer fits
    /// the encoded frame.
    fn drop_too_large(&self, n: usize) {
        book_too_large(n);
    }

    /// Encode one standalone `Open`/`Inline` item for this stager's wire.
    fn encode_standalone(&self, item: &R2StageItem, limit: usize) -> Option<Bytes> {
        encode_standalone_item_for(self.wire, item, limit)
    }

    /// Pop heads round-robin while they are `Steady` and fit `limit`.
    ///
    /// `first` is the session already selected by [`Self::pack_one_frame`], so
    /// the run starts with that session's head and only then rotates.
    /// Per-session FIFO order is preserved; sessions interleave for fairness.
    fn take_steady_head(
        &mut self,
        session: u32,
        limit: usize,
        run: &mut Vec<R2StageItem>,
        unique: &mut Vec<u32>,
        cost: &mut usize,
    ) -> bool {
        let Some(front) = self.sessions.get(&session).and_then(|q| q.front()) else {
            return false;
        };
        let R2StageKind::Steady { wire_id } = front.kind else {
            return false;
        };
        if run.len() >= self.max_train_items {
            return false;
        }
        let payload_len = front.payload.len();
        // Per-item and per-new-flow wire cost, revision-specific. The rev3
        // figure is the DICT **upper bound** (idx byte + length field + the
        // 2-byte fid on first use); the encoder may pick the smaller SAME /
        // SAME_EQUAL form for a single-flow run, never a larger one, so the
        // packing decision stays conservative.
        let (item_cost, flow_cost) = match self.wire {
            Wire::Rev2 => (
                1 + r2::varint_len(payload_len as u32) + payload_len,
                r2::varint_len(wire_id),
            ),
            Wire::Rev3 => (1 + r3_item_len_len(payload_len) + payload_len, 2),
        };
        let mut add = item_cost;
        let new_flow = !unique.contains(&wire_id);
        if new_flow {
            if unique.len() >= u8::MAX as usize {
                return false;
            }
            add += flow_cost;
        }
        if cost.saturating_add(add) > limit {
            return false;
        }
        let item = self.pop_one(session).expect("peeked item exists");
        let R2StageKind::Steady { wire_id } = item.kind else {
            unreachable!("take_steady_head peeked a steady item");
        };
        // Keep the steady cursor in step with the general one: after serving a
        // session it must point at the sessions *after* it, so a multi-item
        // head still interleaves with the other steady sessions (the old
        // single cursor got this from rotating on every pop). A session that
        // `next_steady_session` just rotated to the back needs no move.
        self.rotate_steady_past(session);
        if new_flow {
            unique.push(wire_id);
        }
        *cost += add;
        run.push(item);
        true
    }

    /// Build the dict-form `TRAIN` for a multi-item steady run.
    ///
    /// `flows` is the run's deduped flow list in first-appearance order — the
    /// same list [`Self::take_steady_head`] already maintains for its cost
    /// bound, so no second scan of `run` rebuilds it. The item views are built
    /// into a fixed stack array (at most [`r2::R2_MAX_TRAIN_ITEMS`] entries, a
    /// few KiB) instead of a fresh per-frame `Vec`: their payload borrows are
    /// local to this call and cannot live in a stager field. Flow indices come
    /// from the reused [`Self::flow_idx_scratch`] map, so resolving an item's
    /// dict index is O(1) instead of the O(flows) `position` scan per item.
    fn encode_train_run(
        &self,
        flows: &[u32],
        flow_idx: &mut HashMap<u32, u8, foldhash::fast::RandomState>,
        run: &[R2StageItem],
        limit: usize,
    ) -> Option<Bytes> {
        debug_assert!(run.len() <= r2::R2_MAX_TRAIN_ITEMS);
        debug_assert!(flows.len() <= u8::MAX as usize);
        flow_idx.clear();
        for (i, wire_id) in flows.iter().enumerate() {
            flow_idx.insert(*wire_id, i as u8);
        }
        let mut items: [(u8, &[u8]); r2::R2_MAX_TRAIN_ITEMS] = [(0, &[]); r2::R2_MAX_TRAIN_ITEMS];
        for (view, item) in items[..run.len()].iter_mut().zip(run) {
            let R2StageKind::Steady { wire_id } = item.kind else {
                unreachable!("a steady run only holds steady items");
            };
            let idx = *flow_idx
                .get(&wire_id)
                .expect("every run flow was deduped into the flow list");
            *view = (idx, item.payload.as_ref());
        }
        // rev3 single-flow run: the SAME forms (equal-length first) are wire-
        // smaller than a one-entry DICT, so they are preferred; both are still
        // valid `TRAIN` frames for the receiver and the packing cost above
        // already bounded the larger DICT size. rev2 has no such form and keeps
        // the shipped DICT encoding byte-for-byte.
        if self.wire == Wire::Rev3 && flows.len() == 1 {
            let R2StageKind::Steady { wire_id } = run[0].kind else {
                unreachable!("a steady run only holds steady items");
            };
            let mut refs: [&[u8]; r2::R2_MAX_TRAIN_ITEMS] = [&[]; r2::R2_MAX_TRAIN_ITEMS];
            for (slot, item) in refs[..run.len()].iter_mut().zip(run) {
                *slot = item.payload.as_ref();
            }
            let equal_lengths = run.iter().all(|i| i.payload.len() == run[0].payload.len());
            let refs = &refs[..run.len()];
            let encoded = if equal_lengths {
                wire::encode_train_same_equal(self.wire, wire_id, refs, limit)
                    .or_else(|| wire::encode_train_same(self.wire, wire_id, refs, limit))
            } else {
                wire::encode_train_same(self.wire, wire_id, refs, limit)
            };
            if let Some(body) = encoded {
                return Some(body);
            }
        }
        wire::encode_train_dict(self.wire, flows, &items[..run.len()], limit)
    }

    /// Pop the next session that has a non-empty queue, rotating the cursor.
    fn next_session(&mut self) -> Option<u32> {
        let len = self.order.len();
        for _ in 0..len {
            let session = self.order.pop_front()?;
            let non_empty = self.sessions.get(&session).is_some_and(|q| !q.is_empty());
            if non_empty {
                self.order.push_back(session);
                return Some(session);
            }
        }
        None
    }

    /// Pop the next session whose head is a `Steady` item, rotating the steady
    /// cursor.
    ///
    /// Only sessions whose queue head was `Steady` when they joined the cursor
    /// are visited here; standalone-headed sessions are invisible to a train
    /// run (this used to walk the whole session cursor once per packed item).
    /// An entry whose session emptied or whose head is no longer steady is
    /// dropped — its mark is removed and it does not rejoin until the session's
    /// next head transition.
    fn next_steady_session(&mut self) -> Option<u32> {
        while let Some(session) = self.steady_order.pop_front() {
            let steady = self
                .sessions
                .get(&session)
                .and_then(|q| q.front())
                .is_some_and(|i| matches!(i.kind, R2StageKind::Steady { .. }));
            if steady {
                self.steady_order.push_back(session);
                return Some(session);
            }
            self.steady_mark.remove(&session);
        }
        None
    }

    /// Add `session` to the steady cursor when its queue head is a `Steady`
    /// item and it is not queued already. Called on the two head transitions:
    /// a push into an empty queue and a pop revealing a new head.
    fn add_steady_head(&mut self, session: u32) {
        let steady = self
            .sessions
            .get(&session)
            .and_then(|q| q.front())
            .is_some_and(|item| matches!(item.kind, R2StageKind::Steady { .. }));
        if steady && self.steady_mark.insert(session) {
            self.steady_order.push_back(session);
        }
    }

    /// Move the steady cursor past `session`. A no-op when the session is not
    /// queued — in particular when it already sits at the back because
    /// [`Self::next_steady_session`] just rotated it there (the fast path: the
    /// per-item move in a train run is O(1); only a run's first item, which is
    /// a session the general cursor picked, may need the scan).
    fn rotate_steady_past(&mut self, session: u32) {
        if self.steady_order.back() == Some(&session) {
            return;
        }
        let Some(pos) = self.steady_order.iter().position(|s| *s == session) else {
            return;
        };
        self.steady_order.rotate_left(pos + 1);
    }

    /// Drop `session` from the steady cursor (`SESS_CLOSE` teardown, cold path:
    /// O(steady sessions)).
    fn forget_steady(&mut self, session: u32) {
        if self.steady_mark.remove(&session) {
            self.steady_order.retain(|s| *s != session);
        }
    }

    fn pop_one(&mut self, session: u32) -> Option<R2StageItem> {
        let queue = self.sessions.get_mut(&session)?;
        let item = queue.pop_front()?;
        let emptied = queue.is_empty();
        if emptied {
            self.sessions.remove(&session);
        } else {
            // The pop may have revealed a steady head (Open/Inline items are
            // sent one at a time, so a session can enter a train run only after
            // its self-describing prefix has been popped).
            self.add_steady_head(session);
        }
        self.queued_items = self.queued_items.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(item.payload.len());
        Some(item)
    }

    /// Phase C of the unlocked drain: after [`send_packed_frames`] stopped at
    /// frame index `failed_frame`, requeue the items of every frame beyond it,
    /// in encounter order — per-session FIFO is exactly what pack popped, and
    /// the deque of round-robin candidates is rebuilt by the pushes (only the
    /// cursor's starting point can differ, which no invariant depends on).
    ///
    /// The failed frame's own items stay dead: the send phase already
    /// accounted them to the verdict's drop counter, so this must not
    /// double-book and must not resurrect them.
    ///
    /// Returns how many items could **not** be requeued because the bounded
    /// queue filled again during the unlocked send window (an ordinary drop,
    /// not a fault). The caller accounts each of those with its full-queue
    /// drop policy; this function books nothing (the item payloads are
    /// released here, the counter bump is the caller's business).
    pub fn requeue_unsent(&mut self, q: &mut PackedFrames, failed_frame: usize) -> usize {
        let start = match q.frames.get(failed_frame + 1) {
            Some(first_unsent) => first_unsent.item_off as usize,
            None => {
                // The failed frame was the last one packed: nothing unsent.
                q.frames.clear();
                return 0;
            }
        };
        if start > q.items.len() {
            q.frames.clear();
            return 0;
        }
        let mut overflow = 0usize;
        for item in q.items.drain(start..) {
            if self.push(item).is_err() {
                overflow += 1;
            }
        }
        // The frames list is dead weight after the requeue; a later reuse of
        // `q` must never re-send stale bodies.
        q.frames.clear();
        overflow
    }

    /// Pack exactly one frame for the shape tests: same selection as
    /// [`Self::pack_one_frame`] (so the tests pin the shipped packing), with
    /// the popped items released locally — only a caller that drains to
    /// exhaustion may use this wrapper on a production path.
    #[cfg(test)]
    fn next_frame(&mut self, limit: usize) -> Option<EncodedFrame> {
        let mut q = PackedFrames::default();
        loop {
            if !self.pack_one_frame(limit, &mut q) {
                return None;
            }
            if let Some(frame) = q.frames.pop() {
                return Some(EncodedFrame {
                    body: frame.body,
                    items: frame.item_len,
                });
            }
            // An over-limit head is dropped without producing a frame; the
            // production `pack` loop simply tries the next head, so this
            // wrapper must keep going instead of popping an empty batch.
        }
    }
}

impl Drop for R2Stager {
    fn drop(&mut self) {
        // A connection dying with queued payloads must not lose them silently:
        // account each as an egress death (the stager is connection-scoped, so
        // the connection is the only thing that can have died).
        for _ in 0..self.queued_items {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
    }
}

/// Phase B of the drain: put the packed frames on the wire **in order**,
/// stopping at the first verdict that is not `Sent` (the queue's ordering is
/// the wire's ordering; a blocked verdict must not reorder what follows).
///
/// This runs with the stager lock already released — that is the entire point
/// of the split ([`R2Stager::pack_batch`] comment). The *failed* frame's
/// payloads are accounted here, per item and exactly (drop accounting is
/// deliberately per-event): `Blocked` (the path's DATAGRAM budget is exhausted)
/// books `BUFFER_FULL`, `TooLarge` (the path MTU shrank under the cached
/// `limit`) books `TOO_LARGE`, and only `Unsupported`/`ConnectionLost` — the
/// verdicts that really mean the connection is unusable — book `EGRESS_DEAD`.
/// Sent payloads book `udp_stats::payload` here, not at encode time: a frame is
/// dropped (not retried) on a failed verdict, and must not be counted twice.
///
/// `q` keeps the unsent tail: its frames beyond the failure still own their
/// items, and frame bodies either moved into quinn (`Sent`) or were released
/// with the failed frame. [`R2Stager::requeue_unsent`] finalises the phase.
pub fn send_packed_frames(conn: &Connection, q: &mut PackedFrames) -> R2DrainOutcome {
    let mut out = R2DrainOutcome::default();
    let mut idx = 0usize;
    while idx < q.frames.len() {
        // Move the body out (a `Bytes` header swap, no payload copy): the
        // slot's body is dead after quinn owns it.
        let body = std::mem::take(&mut q.frames[idx].body);
        match try_send_datagram(conn, body) {
            DatagramSend::Sent => {
                out.frames = out.frames.saturating_add(1);
                out.items_sent = out.items_sent.saturating_add(q.frames[idx].item_len);
                let start = q.frames[idx].item_off as usize;
                let end = start + q.frames[idx].item_len as usize;
                for item in &q.items[start..end] {
                    udp_stats::payload(item.payload.len());
                }
            }
            other => {
                let dropped = q.frames[idx].item_len;
                out.items_dropped = dropped;
                out.failed = Some(other);
                match other {
                    DatagramSend::Blocked => {
                        for _ in 0..dropped {
                            dgram_drops::bump(&dgram_drops::BUFFER_FULL);
                        }
                    }
                    DatagramSend::TooLarge => {
                        // A size-class drop: the connection is alive and the
                        // caller only re-probes its budget, so this must not be
                        // booked as an egress death (the old code did exactly
                        // that, inventing `egress_dead` spikes).
                        book_too_large(dropped as usize);
                    }
                    // `Unsupported`/`ConnectionLost`: the connection is (or can
                    // never be) usable for DATAGRAMs.
                    _ => {
                        for _ in 0..dropped {
                            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
                        }
                    }
                }
                break;
            }
        }
        idx += 1;
    }
    out
}

/// Encode one standalone `Open`/`Inline` item against the live path budget.
///
/// Shared with the server's `stage_open_src` path, which sends a rebinding
/// `DATA OPEN|SRC` directly (outside the stager lock) and must use the exact
/// same wire encoder as a batched drain.
pub fn encode_standalone_item(item: &R2StageItem, limit: usize) -> Option<Bytes> {
    encode_standalone_item_for(Wire::Rev2, item, limit)
}

/// [`encode_standalone_item`] for a connection's wire revision.
///
/// The rev3 integration uses this so a stager-owned standalone frame (rev3
/// `DATA_EXT`/steady) is byte-identical to what a batched drain produces. The
/// rev2 signature above stays for call sites that are rev2-only (the server's
/// `stage_open_src` path); it is exactly the [`Wire::Rev2`] arm here.
pub fn encode_standalone_item_for(wire: Wire, item: &R2StageItem, limit: usize) -> Option<Bytes> {
    match &item.kind {
        R2StageKind::Open {
            wire_id,
            sess,
            addr,
            src,
        } => wire::encode_data_open(
            wire,
            *wire_id,
            *sess,
            &addr.as_ref(),
            *src,
            &item.payload,
            limit,
        ),
        R2StageKind::Inline { sess, addr, src } => {
            wire::encode_data_inline(wire, *sess, &addr.as_ref(), *src, &item.payload, limit)
        }
        R2StageKind::Steady { wire_id } => {
            wire::encode_data_steady(wire, *wire_id, &item.payload, limit)
        }
    }
}

/// Wire length of a rev3 `TRAIN` item-length field (1 B below the `0xFF`
/// escape, 3 B for the escape + `u16`); the stager's packing cost model uses
/// it. Payloads above `u16::MAX` cannot be staged.
fn r3_item_len_len(n: usize) -> usize {
    debug_assert!(n <= u16::MAX as usize, "staged payload above u16");
    if n < 0xFF { 1 } else { 3 }
}

/// Account `n` payloads dropped because the live path budget no longer fits
/// their encoded frame.
pub fn book_too_large(n: usize) {
    for _ in 0..n {
        let bumped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        if bumped == 1 {
            crate::stats::warn_datagram_drop(
                crate::stats::DatagramDropKind::Large,
                "staged rev2 payload no longer fits the path budget",
                bumped,
                String::new,
            );
        }
    }
}

/// Drain a connection stager in bounded batches, with the QUIC writes outside
/// the stager lock.
///
/// One call handles at most [`R2_STAGE_MAX_ITEMS`] queued payloads (the queue's
/// own cap): enough for a burst boundary to flush a full queue, bounded enough
/// that a producer cannot keep the drainer in this loop forever. Work stops
/// immediately on the first failed send; the failed frame's items are already
/// accounted by [`send_packed_frames`], and the unsent tail is requeued for the
/// next drain. `on_requeue_overflow` is invoked once per item the bounded queue
/// could not take back (a concurrent pusher refilled it during the unlocked
/// send window); the caller supplies its usual full-queue accounting.
///
/// The `datagram_send_buffer_space` check is the cheap backpressure gate: when
/// quinn's DATAGRAM buffer is already full, no amount of packing can get a
/// frame onto the wire, so the drain returns `Blocked` without encoding
/// anything. That is what turns the old "one full-queue pack per payload while
/// blocked" behaviour into O(1) per payload.
pub fn drain_staged(
    conn: &Connection,
    stage: &parking_lot::Mutex<R2Stager>,
    limit: usize,
    mut on_requeue_overflow: impl FnMut(),
) -> R2DrainOutcome {
    let mut total = R2DrainOutcome::default();
    let mut q = PackedFrames::default();
    let mut handled = 0usize;
    loop {
        if stage.lock().is_empty() {
            break;
        }
        if conn.datagram_send_buffer_space() == 0 {
            total.failed = Some(DatagramSend::Blocked);
            break;
        }
        let more = {
            let mut st = stage.lock();
            if st.is_empty() {
                false
            } else {
                let before = st.len();
                let more = st.pack_batch(limit, R2_PACK_BATCH_FRAMES, R2_PACK_BATCH_ITEMS, &mut q);
                // Every `pack_one_frame` call removes at least one item, so
                // this is also the loop's progress bound (including items
                // dropped as too large, which never enter `q`).
                handled = handled.saturating_add(before.saturating_sub(st.len()));
                more
            }
        };
        if q.frames.is_empty() {
            q.clear();
            if !more || handled >= R2_STAGE_MAX_ITEMS {
                break;
            }
            continue;
        }
        let outcome = send_packed_frames(conn, &mut q);
        total.frames = total.frames.saturating_add(outcome.frames);
        total.items_sent = total.items_sent.saturating_add(outcome.items_sent);
        total.items_dropped = total.items_dropped.saturating_add(outcome.items_dropped);
        if outcome.failed.is_some() {
            let overflow = stage.lock().requeue_unsent(&mut q, outcome.frames as usize);
            for _ in 0..overflow {
                on_requeue_overflow();
            }
            total.failed = outcome.failed;
            break;
        }
        q.clear();
        if !more || handled >= R2_STAGE_MAX_ITEMS {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::r3;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    fn id(local: u32) -> u32 {
        r2::make_wire_id(local, false).unwrap()
    }

    fn steady(session: u32, local: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Steady { wire_id: id(local) },
            payload: Bytes::from_static(payload),
        }
    }

    fn open(session: u32, local: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Open {
                wire_id: id(local),
                sess: session,
                addr: TargetAddr::Ip(v4(53)),
                src: false,
            },
            payload: Bytes::from_static(payload),
        }
    }

    fn inline(session: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Inline {
                sess: session,
                addr: TargetAddr::Ip(v4(53)),
                src: true,
            },
            payload: Bytes::from_static(payload),
        }
    }

    #[test]
    fn queue_bounds_return_the_item() {
        let mut s = R2Stager::with_capacity(2, 64);
        assert!(s.push(steady(1, 1, b"aa")).is_ok());
        assert!(s.push(steady(1, 2, b"bb")).is_ok());
        assert!(s.push(steady(1, 3, b"cc")).is_err());
        assert_eq!(s.len(), 2);
        let mut s = R2Stager::with_capacity(8, 2);
        assert!(s.push(steady(1, 1, b"aa")).is_ok());
        assert!(s.push(steady(1, 2, b"bb")).is_err());
    }

    #[test]
    fn cross_session_steady_items_become_one_dict_train() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(2, 2, b"bb")).unwrap();
        s.push(steady(3, 3, b"cc")).unwrap();
        let f = s.next_frame(1162).expect("a frame");
        assert_eq!(f.items, 3);
        let t = r2::decode_train(&f.body).expect("dict train");
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![
                (id(1), &b"aa"[..]),
                (id(2), &b"bb"[..]),
                (id(3), &b"cc"[..])
            ]
        );
        assert!(s.is_empty());
    }

    /// P2-3 lock-in: the dict form must carry one slot per distinct flow (in
    /// first-appearance order) while every item keeps its own flow's slot and
    /// the run's order. The encoder now reuses the `take_steady_head` dedupe
    /// list and an O(1) index map instead of re-scanning the run per item —
    /// the wire bytes must be identical to the old encoder.
    #[test]
    fn train_dict_keeps_one_slot_per_flow_and_item_order() {
        let mut s = R2Stager::new();
        // One session, three items across two flows, interleaved by flow.
        s.push(steady(1, 1, b"a1")).unwrap();
        s.push(steady(1, 2, b"b1")).unwrap();
        s.push(steady(1, 1, b"a2")).unwrap();
        let f = s.next_frame(1162).expect("a dict train");
        let t = r2::decode_train(&f.body).expect("dict train");
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![
                (id(1), &b"a1"[..]),
                (id(2), &b"b1"[..]),
                (id(1), &b"a2"[..])
            ],
            "repeated flows must reuse their dict slot without reordering items"
        );
    }

    #[test]
    fn per_session_order_is_preserved() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"a1")).unwrap();
        s.push(steady(1, 2, b"a2")).unwrap();
        s.push(steady(2, 3, b"b1")).unwrap();
        s.push(steady(2, 4, b"b2")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let t = r2::decode_train(&f.body).unwrap();
        let got: Vec<u32> = t.items().map(|(id, _)| id).collect();
        // Round-robin: session 1 head, session 2 head, then session 1, session 2.
        assert_eq!(got, vec![id(1), id(3), id(2), id(4)]);
    }

    #[test]
    fn standalone_items_break_the_train() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(open(2, 2, b"bb")).unwrap();
        s.push(steady(3, 3, b"cc")).unwrap();
        // The steady heads of sessions 1 and 3 can share a train; the Open item
        // from session 2 is a standalone frame and is sent next.
        let f1 = s.next_frame(1162).unwrap();
        assert_eq!(f1.items, 2);
        let train: Vec<u32> = r2::decode_train(&f1.body)
            .unwrap()
            .items()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(train, vec![id(1), id(3)]);
        let f2 = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f2.body).unwrap();
        assert_eq!(d.id, Some(id(2)));
        assert!(d.addr.is_some());
    }

    #[test]
    fn inline_item_is_self_describing() {
        let mut s = R2Stager::new();
        s.push(inline(7, b"zz")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, None);
        assert_eq!(d.sess, Some(7));
        assert_eq!(d.payload, b"zz");
    }

    #[test]
    fn budget_splits_a_large_run() {
        let mut s = R2Stager::new();
        for i in 0..32u32 {
            // ~100 B payloads: 32 fit the budget individually, not one frame.
            let payload = vec![0u8; 100];
            s.push(R2StageItem {
                session: i,
                kind: R2StageKind::Steady { wire_id: id(i + 1) },
                payload: Bytes::from(payload),
            })
            .unwrap();
        }
        let mut frames = 0;
        let mut items = 0;
        while let Some(f) = s.next_frame(1162) {
            let t = r2::decode_train(&f.body).unwrap();
            items += t.items().count();
            frames += 1;
        }
        assert!(frames > 1);
        assert_eq!(items, 32);
        assert!(s.is_empty());
    }

    #[test]
    fn one_steady_item_uses_the_short_data_frame() {
        let mut s = R2Stager::new();
        s.push(steady(1, 5, b"abc")).unwrap();
        let f = s.next_frame(1162).unwrap();
        assert!(f.body[0] == r2::R2_DATA);
        assert_eq!(r2::decode_data(&f.body).unwrap().payload, b"abc");
    }

    #[test]
    fn drop_session_and_flow_purge_queued_items() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(1, 2, b"bb")).unwrap();
        s.push(steady(2, 3, b"cc")).unwrap();
        assert_eq!(s.drop_session(1), 2);
        assert_eq!(s.len(), 1);
        // Session 1's items never come back.
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(3)));
        assert!(s.is_empty());
        // Flow purge keeps other flows.
        s.push(steady(1, 10, b"dd")).unwrap();
        s.push(steady(1, 11, b"ee")).unwrap();
        assert_eq!(s.drop_flow(id(10)), 1);
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(11)));
    }

    #[test]
    fn negotiated_train_items_splits_frames() {
        let mut s = R2Stager::new();
        s.set_max_train_items(2);
        for i in 0..5u32 {
            s.push(steady(1, i + 1, b"xx")).unwrap();
        }
        let mut frames = 0;
        let mut items = 0;
        while let Some(f) = s.next_frame(1162) {
            items += f.items as usize;
            frames += 1;
        }
        assert_eq!(items, 5);
        assert_eq!(frames, 3, "5 items at 2 per train => 3 frames");
    }

    #[test]
    fn clear_returns_the_item_count() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(2, 2, b"bb")).unwrap();
        assert_eq!(s.clear(), 2);
        assert!(s.is_empty());
        assert!(s.next_frame(1162).is_none());
    }

    #[test]
    fn fairness_lets_a_quiet_session_share_the_first_frame() {
        let mut s = R2Stager::new();
        for i in 0..100u32 {
            s.push(steady(1, i + 1, b"xx")).unwrap();
        }
        s.push(steady(2, 1000, b"yy")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let t = r2::decode_train(&f.body).unwrap();
        let ids: Vec<u32> = t.items().map(|(id, _)| id).collect();
        assert!(ids.contains(&id(1000)), "quiet session must not be starved");
        assert!(ids.len() > 1);
    }

    /// Requeue semantics of the two-phase drain: what failed to send rejoins
    /// its session's queue in the order pack popped it, per-session FIFO is
    /// bit-exact, the failed frame's own items stay dead, and `PackedFrames`
    /// is left clean for reuse.
    #[test]
    fn requeue_unsent_restores_the_tail_in_session_order() {
        let mut s = R2Stager::new();
        // Frame 0: cross-session dict train. Frame 1: standalone OPEN (its own
        // frame). Frame 2: another steady item in session 1.
        s.push(steady(1, 1, b"a1")).unwrap();
        s.push(steady(2, 2, b"b1")).unwrap();
        s.push(open(1, 9, b"o")).unwrap();
        s.push(steady(1, 3, b"a2")).unwrap();
        let mut q = PackedFrames::default();
        while s.pack_batch(1162, usize::MAX, usize::MAX, &mut q) {}
        assert_eq!(q.frames.len(), 3);
        assert_eq!(q.items.len(), 4);
        assert!(s.is_empty(), "pack moved every item out of the queue");
        // Frame 1's pack order is observed through the packed batch itself.
        assert_eq!(q.frames[0].item_len, 2, "frame 0 is the dict train");
        assert_eq!(q.frames[1].item_len, 1, "frame 1 is the standalone OPEN");
        assert_eq!(q.frames[2].item_len, 1);
        // Simulate: frame 1 failed (its item stays dead), so
        // `outcome.frames == 1` requeues only what is beyond the failure.
        let overflow = s.requeue_unsent(&mut q, 1);
        assert_eq!(overflow, 0);
        assert!(q.frames.is_empty(), "stale bodies must not survive");
        // The head items (the sent train's and the failed frame's) stay in
        // `q.items` until `q` itself is dropped: only frames *beyond* the
        // failure were resurrected, and requeueing them removed them.
        assert_eq!(s.len(), 1, "only the unsent tail rejoined");
        // The rest is session 1's steady item — the OPEN and the sent train
        // items are gone (drop accounting is the send phase's job, not the
        // requeue's).
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, Some(id(3)), "the steady item kept its id identity");
    }

    /// A queue that refilled inside the unlocked send window makes the
    /// requeue overflow: the items that do not fit are dropped and reported
    /// for the caller's policy counter, and the item budget stays exact.
    #[test]
    fn requeue_overflow_drops_items_that_cannot_rejoin() {
        let mut s = R2Stager::with_capacity(4, 256);
        s.push(steady(1, 1, b"a")).unwrap();
        s.push(open(2, 9, b"o")).unwrap();
        let mut q = PackedFrames::default();
        while s.pack_batch(1162, usize::MAX, usize::MAX, &mut q) {}
        assert_eq!(q.frames.len(), 2, "one steady frame + one standalone OPEN");
        assert_eq!(q.items.len(), 2);
        // The send window "stalls" while another association fills the queue
        // to its cap again; the tail (the OPEN item) then has no slot to
        // rejoin and must be reported as overflow instead of resurrected.
        s.push(steady(3, 3, b"r1")).unwrap();
        s.push(steady(4, 4, b"r2")).unwrap();
        s.push(steady(3, 5, b"r3")).unwrap();
        s.push(steady(4, 6, b"r4")).unwrap();
        assert_eq!(s.len(), 4);
        let overflow = s.requeue_unsent(&mut q, 0);
        assert_eq!(overflow, 1, "the unsent tail item did not fit back");
        assert_eq!(s.len(), 4, "the queue is exactly full again");
        assert!(q.frames.is_empty());
    }

    /// The blocked-send path must not re-encode the whole queue: one drain
    /// step stops at the frame cap, and a second at the item cap, leaving the
    /// tail queued for the next step.
    #[test]
    fn pack_batch_bounds_one_drain_step() {
        let mut s = R2Stager::new();
        let per_train = r2::R2_MAX_TRAIN_ITEMS;
        let total = (R2_PACK_BATCH_FRAMES + 2) * per_train;
        for _ in 0..total {
            s.push(steady(1, 1, b"x")).unwrap();
        }
        let mut q = PackedFrames::default();
        let more = s.pack_batch(1162, R2_PACK_BATCH_FRAMES, usize::MAX, &mut q);
        assert!(more, "items remain after one frame-bounded batch");
        assert_eq!(q.frames.len(), R2_PACK_BATCH_FRAMES);
        assert_eq!(q.items.len(), R2_PACK_BATCH_FRAMES * per_train);
        assert_eq!(s.len(), total - q.items.len());

        q.clear();
        let more = s.pack_batch(1162, usize::MAX, R2_PACK_BATCH_ITEMS, &mut q);
        assert!(more, "items remain after one item-bounded batch");
        assert_eq!(
            q.frames.len(),
            1,
            "the item cap stops before a second frame"
        );
        assert_eq!(q.items.len(), R2_PACK_BATCH_ITEMS);
        assert_eq!(s.len(), 2 * per_train - R2_PACK_BATCH_ITEMS);
    }

    /// The steady cursor must hold only steady-headed sessions: with a large
    /// standalone population ahead of a few steady sessions, a train run draws
    /// the steady items directly instead of walking every standalone session,
    /// and nothing is lost or duplicated.
    #[test]
    fn steady_cursor_ignores_standalone_heads() {
        let mut s = R2Stager::new();
        let standalone = 512u32;
        for i in 0..standalone {
            s.push(open(i, i + 1, b"o")).unwrap();
        }
        s.push(steady(standalone, 1, b"s1")).unwrap();
        s.push(steady(standalone + 1, 2, b"s2")).unwrap();
        // The general cursor knows every session; the steady cursor only the
        // two that can contribute to a train.
        assert_eq!(s.order.len(), standalone as usize + 2);
        assert_eq!(s.steady_order.len(), 2);
        assert_eq!(s.steady_mark.len(), 2);
        assert_eq!(s.next_steady_session(), Some(standalone));
        assert_eq!(s.next_steady_session(), Some(standalone + 1));
        // Drain everything: 512 standalone frames plus one two-item train.
        let mut frames = 0usize;
        let mut items = 0usize;
        while let Some(f) = s.next_frame(1162) {
            frames += 1;
            items += f.items as usize;
        }
        assert_eq!(items, standalone as usize + 2, "one delivery per payload");
        assert_eq!(frames, standalone as usize + 1);
        assert!(s.is_empty());
        assert!(s.steady_order.is_empty(), "every steady slot is retired");
    }

    /// A steady head revealed by popping a standalone item joins the steady
    /// cursor exactly once (the transition add), so the session's remaining
    /// payloads still train in per-session FIFO order.
    #[test]
    fn revealed_steady_head_joins_the_steady_cursor() {
        let mut s = R2Stager::new();
        s.push(open(1, 1, b"o1")).unwrap();
        s.push(steady(1, 2, b"s1")).unwrap();
        s.push(open(2, 2, b"o2")).unwrap();
        s.push(steady(2, 3, b"s2")).unwrap();
        assert!(s.steady_order.is_empty(), "both heads are standalone");
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(1)));
        // Popping session 1's Open revealed a steady head; session 2's head is
        // still its Open, so only session 1 is queued for train runs.
        assert_eq!(s.steady_order, VecDeque::from(vec![1]));
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(2)));
        assert_eq!(s.steady_order, VecDeque::from(vec![1, 2]));
        // The revealed steady items train together, in session order.
        let f = s.next_frame(1162).unwrap();
        let train: Vec<u32> = r2::decode_train(&f.body)
            .unwrap()
            .items()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(train, vec![id(2), id(3)]);
        assert!(s.is_empty());
        assert!(s.steady_order.is_empty());
    }

    /// Teardown paths keep the steady cursor consistent: a session or flow drop
    /// retires/refreshes the slots it invalidated, and `clear` empties every
    /// cursor.
    #[test]
    fn teardown_keeps_the_steady_cursor_consistent() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"a")).unwrap();
        s.push(steady(1, 2, b"b")).unwrap();
        s.push(steady(2, 3, b"c")).unwrap();
        assert_eq!(s.steady_order, VecDeque::from(vec![1, 2]));
        // A purge that does not touch a head leaves the cursor intact.
        assert_eq!(s.drop_flow(id(1)), 1);
        assert_eq!(s.steady_order, VecDeque::from(vec![1, 2]));
        assert_eq!(s.len(), 2);
        // A purge that empties a session's queue retires its steady slot.
        assert_eq!(s.drop_flow(id(2)), 1);
        assert_eq!(s.steady_order, VecDeque::from(vec![2]));
        assert_eq!(s.steady_mark.len(), 1);
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, Some(id(3)));
        assert_eq!(d.payload, b"c");
        // `SESS_CLOSE` drops a whole session from the cursor.
        s.push(steady(3, 4, b"d")).unwrap();
        s.push(steady(4, 5, b"e")).unwrap();
        assert_eq!(s.drop_session(3), 1);
        assert_eq!(s.steady_order, VecDeque::from(vec![4]));
        // `clear` empties every cursor.
        assert_eq!(s.clear(), 1);
        assert!(s.steady_order.is_empty());
        assert!(s.steady_mark.is_empty());
        // A purge that removes a standalone head reveals a steady one: the
        // session must rejoin the steady cursor.
        s.push(open(5, 20, b"o")).unwrap();
        s.push(steady(5, 21, b"p")).unwrap();
        assert!(s.steady_order.is_empty());
        assert_eq!(s.drop_flow(id(20)), 1);
        assert_eq!(s.steady_order, VecDeque::from(vec![5]));
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(21)));
    }

    /// Session-scoped flow purge: only the named session's queue is scanned,
    /// the same wire id in another session survives, `Steady` and `Open` items
    /// both match, `Inline` never does, and the item/byte accounting stays
    /// exact.
    #[test]
    fn drop_flow_scoped_is_session_local() {
        let mut s = R2Stager::new();
        s.push(steady(1, 10, b"aa")).unwrap(); // session 1, flow id(10)
        s.push(open(1, 20, b"bb")).unwrap(); // session 1, flow id(20)
        s.push(inline(1, b"cc")).unwrap(); // session 1, inline: never matched
        s.push(steady(2, 10, b"dd")).unwrap(); // session 2, same wire id
        let bytes = s.queued_bytes();
        assert_eq!(bytes, 8);
        // Unknown session / no matching flow: nothing removed, nothing booked.
        assert_eq!(s.drop_flow_scoped(99, id(10)), 0);
        assert_eq!(s.drop_flow_scoped(1, id(999)), 0);
        assert_eq!(s.len(), 4);
        assert_eq!(s.queued_bytes(), bytes);
        // Scoped to session 1: only its steady item for flow id(10) goes. The
        // other session's identical wire id and the inline item survive.
        assert_eq!(s.drop_flow_scoped(1, id(10)), 1);
        assert_eq!(s.len(), 3);
        assert_eq!(s.queued_bytes(), bytes - 2);
        // The `Open` form of a flow matches too.
        assert_eq!(s.drop_flow_scoped(1, id(20)), 1);
        assert_eq!(s.len(), 2);
        assert_eq!(s.queued_bytes(), bytes - 4);
        // Remaining frames keep their per-session FIFO order: session 1's inline
        // item, then session 2's steady item.
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, None);
        assert_eq!(d.sess, Some(1));
        assert_eq!(d.payload, b"cc");
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, Some(id(10)));
        assert_eq!(d.payload, b"dd");
        assert!(s.is_empty());
    }

    /// Mixed standalone and steady heads across many sessions: whatever the
    /// frame interleaving, every queued payload is delivered exactly once and
    /// each session's steady items keep their FIFO order. The steady cursor's
    /// transition add and rotation must neither drop nor duplicate a head.
    #[test]
    fn mixed_heads_deliver_every_payload_exactly_once() {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        enum Seen {
            Steady(u32, Vec<u8>),
            Open(u32, Vec<u8>),
            Inline(u32, Vec<u8>),
        }
        let mut s = R2Stager::new();
        let mut expected = Vec::new();
        // wire id -> (owning session, steady sequence number)
        let mut fifo = std::collections::HashMap::new();
        let mut next_local = 1u32;
        for session in 0..37u32 {
            match session % 3 {
                0 => {
                    let local = next_local;
                    next_local += 1;
                    s.push(open(session, local, b"open")).unwrap();
                    expected.push(Seen::Open(id(local), b"open".to_vec()));
                }
                1 => {
                    s.push(inline(session, b"inline")).unwrap();
                    expected.push(Seen::Inline(session, b"inline".to_vec()));
                }
                _ => {}
            }
            let n = 1 + session % 5;
            for seq in 0..n {
                let local = next_local;
                next_local += 1;
                let payload = vec![session as u8, seq as u8];
                s.push(R2StageItem {
                    session,
                    kind: R2StageKind::Steady { wire_id: id(local) },
                    payload: Bytes::from(payload.clone()),
                })
                .unwrap();
                fifo.insert(id(local), (session, seq));
                expected.push(Seen::Steady(id(local), payload));
            }
        }
        let mut received = Vec::new();
        let mut last_seq = std::collections::HashMap::new();
        while let Some(f) = s.next_frame(1162) {
            if f.body[0] == r2::R2_TRAIN {
                for (wire_id, payload) in r2::decode_train(&f.body).unwrap().items() {
                    received.push(Seen::Steady(wire_id, payload.to_vec()));
                    let (session, seq) = fifo[&wire_id];
                    if let Some(prev) = last_seq.insert(session, seq) {
                        assert!(
                            seq > prev,
                            "session {session} FIFO order: {prev} then {seq}"
                        );
                    }
                }
            } else {
                let d = r2::decode_data(&f.body).unwrap();
                match (d.id, d.addr) {
                    (Some(wire_id), None) => {
                        received.push(Seen::Steady(wire_id, d.payload.to_vec()));
                        let (session, seq) = fifo[&wire_id];
                        if let Some(prev) = last_seq.insert(session, seq) {
                            assert!(
                                seq > prev,
                                "session {session} FIFO order: {prev} then {seq}"
                            );
                        }
                    }
                    (Some(wire_id), Some(_)) => {
                        received.push(Seen::Open(wire_id, d.payload.to_vec()));
                    }
                    (None, _) => {
                        received.push(Seen::Inline(
                            d.sess.expect("inline carries sess"),
                            d.payload.to_vec(),
                        ));
                    }
                }
            }
        }
        assert_eq!(
            received.len(),
            expected.len(),
            "no payload lost or duplicated"
        );
        received.sort_unstable();
        expected.sort_unstable();
        assert_eq!(received, expected);
        assert!(s.is_empty());
    }
    /// rev3 stager: a single-flow run of equal-length payloads uses the
    /// `SAME_EQUAL` form (one shared item length, no per-item framing), and a
    /// mixed-length single-flow run uses `SAME`; both decode back to the same
    /// `(wire_id, payload)` sequence.
    #[test]
    fn rev3_single_flow_train_prefers_the_equal_length_form() {
        let mut s = R2Stager::new_with_wire(Wire::Rev3);
        assert_eq!(s.wire(), Wire::Rev3);
        let wid = 2u32; // client-owned local 1
        for _ in 0..3 {
            s.push(steady(1, 1, b"abc")).unwrap();
        }
        let f = s.next_frame(1162).expect("a same-equal train");
        let t = wire::decode_train(Wire::Rev3, &f.body).expect("rev3 train decodes");
        assert_eq!(
            t.form(),
            r3::TRAIN_FORM_SAME_EQUAL,
            "equal-length single-flow run must use SAME_EQUAL"
        );
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![(wid, &b"abc"[..]), (wid, &b"abc"[..]), (wid, &b"abc"[..])]
        );

        let mut s = R2Stager::new_with_wire(Wire::Rev3);
        for p in [&b"a"[..], b"bb", b"ccc"] {
            s.push(steady(1, 1, p)).unwrap();
        }
        let f = s.next_frame(1162).expect("a same train");
        let t = wire::decode_train(Wire::Rev3, &f.body).expect("rev3 train decodes");
        assert_eq!(
            t.form(),
            r3::TRAIN_FORM_SAME,
            "mixed lengths must use the per-item-length SAME form"
        );
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![(wid, &b"a"[..]), (wid, &b"bb"[..]), (wid, &b"ccc"[..])]
        );
        assert!(s.is_empty());
    }

    /// rev2 stays byte-identical: the same single-flow run encodes the shipped
    /// DICT form (never a rev3-only form).
    #[test]
    fn rev2_single_flow_train_stays_dict() {
        let mut s = R2Stager::new();
        for _ in 0..3 {
            s.push(steady(1, 1, b"abc")).unwrap();
        }
        let f = s.next_frame(1162).expect("a dict train");
        let t = r2::decode_train(&f.body).expect("rev2 train decodes");
        assert_eq!(t.form, r2::R2_TRAIN_FORM_DICT);
        assert_eq!(t.items().count(), 3);
    }

    /// rev3 standalone items are `DATA_EXT`/steady frames with the fixed
    /// 2-byte header; the rev2 default helper still emits the rev2 frame.
    #[test]
    fn rev3_standalone_items_encode_for_rev3() {
        let item = open(7, 2, b"hi");
        let body = encode_standalone_item_for(Wire::Rev3, &item, 1162).expect("encodes");
        let v = wire::decode_data(Wire::Rev3, &body).expect("rev3 data decodes");
        assert_eq!(v.wire_id, Some(id(2)));
        assert_eq!(v.sess, Some(7));
        assert_eq!(v.payload, b"hi");
        let rev2_body = encode_standalone_item(&item, 1162).expect("rev2 encodes");
        assert_eq!(r2::kind(&rev2_body), Some(r2::R2Kind::Data));
        assert_ne!(
            &body[..],
            &rev2_body[..],
            "rev3 encodes the fixed-header form, not the rev2 varint one"
        );
        // rev3 steady DATA is exactly a 2-byte header + payload.
        let steady = encode_standalone_item_for(
            Wire::Rev3,
            &R2StageItem {
                session: 1,
                kind: R2StageKind::Steady { wire_id: id(1) },
                payload: Bytes::from_static(b"ab"),
            },
            1162,
        )
        .unwrap();
        assert_eq!(steady.len(), 4);
    }
}
