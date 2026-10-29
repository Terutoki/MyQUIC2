//! MQP-3 rev2 reassembler: rebuild a UDP payload from rev2 `FRAG` frames.
//!
//! Key: `(wire_id, frag_id)` for flow-addressed fragments, or
//! `(INLINE, sess, frag_id)` when the sender had no flow id and used the
//! self-describing `INLINE` form. Unlike the MQP-2 [`DgramReassembler`]
//! ([`crate::udp::reassembler`]) there are **no id-reuse tombstones**: rev2 wire
//! ids are monotonic and never reused while the connection lives, so a fragment
//! can only ever belong to one generation. A `frag_id` is monotonic per sending
//! context, and wrapping a u32 inside the 2 s window would need >1.4M fragmented
//! payloads/s from that context.
//!
//! The first fragment of an `OPEN`-pending flow carries `session + address`;
//! later fragments are steady. Because datagrams may arrive out of order, the
//! partial learns its context from whichever fragment carries one and refuses a
//! fragment whose context disagrees — a peer cannot splice two sessions or
//! targets into one payload.
//!
//! The reassembler is revision-agnostic internally: [`R2Reassembler::push`]
//! keeps the shipped rev2 `FRAG` entry point, and
//! [`R2Reassembler::push_view`] accepts the revision-independent decoded view
//! from the [`crate::mqp::wire`] adapter (rev3 `FRAG` frames are decoded there
//! and mapped back to the same internal `wire_id` keys). The wire revision is
//! carried on the reassembler (`new_with_wire`/`set_wire`) so a connection's
//! reassembler is created for the right revision; keys, bounds and expiry are
//! identical for both.
//!
//! Bounds are the shipped ones: 8 KiB per payload, 256 partials, 256 KiB of
//! retained assembly/pending bytes per connection (the stale `order` slots left
//! by completed partials are charged to the same budget and kept bounded by
//! `R2Reassembler::prune_orders`), 2 s partial timeout. Everything is
//! validated before allocation; a malformed fragment only drops that fragment.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

use crate::dgram_drops;
use crate::mqp::addr::TargetAddr;
use crate::mqp::fragment::{
    FRAG_MAX_HELD_BYTES, FRAG_MAX_PARTIALS, FRAG_TIMEOUT_MS, MQP_FRAG_MAX_PAYLOAD,
    MQP_FRAG_MAX_TOTAL,
};
use crate::mqp::r2;
use crate::mqp::wire::{self, Wire};

/// `(inline, id, frag_id)` map on `foldhash`, like every packet-adjacent table
/// in this crate. The full key is compared, so a hash collision only costs a
/// probe.
type FragMap<V> = HashMap<FragKey, V, foldhash::fast::RandomState>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    /// `true` for the self-describing `INLINE` form (no wire id).
    inline: bool,
    /// `wire_id` (flow form) or the session id (inline form).
    id: u32,
    frag_id: u32,
}

/// Resident cost of one `order` entry. The deque slot outlives the partial it
/// named (completed/expired slots are skipped lazily), so it must be visible to
/// [`R2Reassembler::held_bytes`] — otherwise a tick that only runs while
/// `held_bytes() > 0` stops before the stale slots are swept.
const ORDER_SLOT_BYTES: usize = std::mem::size_of::<(FragKey, u64)>();

/// Stale-slot slack allowed on top of two `order` slots per live partial before
/// [`R2Reassembler::prune_orders`] rebuilds the deque. The slack keeps the
/// ordinary lazy sweep amortised (a rebuild is a sort of the live partials,
/// while the sweep is O(1) per retired slot) and, at its ceiling, keeps the
/// charged backlog to a small fraction of [`FRAG_MAX_HELD_BYTES`].
const ORDER_SLOT_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragCtx {
    sess: u32,
    addr: TargetAddr,
    src: bool,
}

/// Book one dropped/refused fragment against an existing process-wide counter.
///
/// The rev2 reassembler refuses and expires payloads in several distinct ways
/// and — unlike the legacy MQP-2 reassembler it replaces — used to book none of
/// them, so a peer that filled the 256 KiB budget made all later fragmented
/// traffic vanish from every counter. This module may not add stats fields, so
/// the closest existing [`crate::dgram_drops`] classes are used:
/// - `BUFFER_FULL`: the fragment was refused because a bounded capacity was
///   exhausted (the held-bytes budget, a partial cap or the payload cap), a
///   partial was evicted to make room, or a partial expired with fragments
///   still missing. That is capacity pressure causing payload loss.
/// - `TOO_LARGE`: a fragment claimed a position past the protocol payload cap
///   (hostile geometry), i.e. the frame is oversized for the payload it names.
/// - `REFUSED`: a fragment was rejected on policy/validation grounds (shape,
///   context splice, total or unit-width disagreement).
///
/// A duplicate fragment is *not* counted: UDP duplicates are expected, the
/// payload is still delivered (or will be) once, and booking them would report
/// ordinary duplication as tunnel loss.
fn book_drop(counter: &'static std::sync::atomic::AtomicU64) {
    dgram_drops::bump(counter);
}

/// One out-of-order-arrival chunk that cannot be written into the assembly
/// buffer yet: its position needs a determinator (the first fragment's length,
/// plus the unit width from the index 2) that has not landed.
///
/// The chunk **owns** exactly its bytes. The arrived frame `d` is a narrow
/// slice of quinn's per-`recvmsg` receive batch (up to `max_udp_payload_size x
/// gro_segments` ≈ 92 KiB on Linux, where quinn-udp enables `UDP_GRO`), and
/// [`Bytes`] cannot report the allocation behind a slice — so a refcount view
/// would pin the whole batch while the budget charged only the chunk's length
/// (a padded frame can carry a one-byte chunk: 49 charged bytes pinning up to
/// ~92 KiB would make [`FRAG_MAX_HELD_BYTES`] fiction). The legacy MQP-2
/// reassembler removed the same view for the same reason; this is its
/// out-of-order half. The copy is paid only for a fragment whose position is
/// not derivable yet, and the bytes are written into the assembly buffer when
/// a determinator unlocks it.
#[derive(Debug)]
struct PendingChunk {
    idx: u8,
    /// Owned copy of exactly this chunk's bytes (`bytes.len()` is the chunk
    /// length; there is no offset into a parent frame to keep).
    bytes: Bytes,
}

/// Cost of one [`PendingChunk`] **beyond** its owned `bytes.len()` in the
/// retained-bytes budget: the allocator's rounding of the exact-size chunk
/// allocation (the `Bytes` handle itself is counted through
/// `pending.capacity() * size_of::<PendingChunk>()` below). 48 B is the same
/// per-datagram bookkeeping charge the fragmenter uses and is a safe upper
/// bound on that per-allocation overhead, so `held_bytes()` never under-states
/// what the pending set retains.
const PENDING_CHUNK_COST: usize = 48;

/// Budget charge for one pending chunk arriving at `pending_len`/`pending_cap`
/// and owning `n` bytes: the bytes, the per-chunk overhead, and — when the
/// `pending` `Vec` has to grow — the **whole new slot array**, not just the
/// added slot. `Vec` amortises to at most 2x length, and charging the new
/// capacity (rather than the delta) keeps the admission bound honest across
/// the growth step instead of discovering the overshoot after the fact.
fn pending_charge(pending_len: usize, pending_cap: usize, n: usize) -> usize {
    let slots = if pending_len < pending_cap {
        0
    } else {
        // `RawVec`'s amortised grow for a 40-byte element: 4 on the first
        // allocation, then doubling; charging the whole new array is
        // conservative either way (a bigger growth only over-charges).
        let next = if pending_cap == 0 {
            4
        } else {
            pending_cap.saturating_mul(2)
        };
        next.saturating_mul(std::mem::size_of::<PendingChunk>())
    };
    n.saturating_add(PENDING_CHUNK_COST).saturating_add(slots)
}

#[derive(Debug)]
struct Partial {
    total: u8,
    ctx: Option<FragCtx>,
    /// Assembled bytes in index order. Chunk *i* owns the buffer range
    /// `[pos(i), pos(i) + len(i))` with `pos(0) = 0` and
    /// `pos(i) = len(0) + (i - 1) * unit` — the segmentation contract of the
    /// shipped fragmenter, which plans one split per payload: every
    /// non-first non-last fragment carries the same rest-chunk budget
    /// (`unit`), the first fragment its own budget, the last one a remainder.
    /// Positions resolve as the determinators land; a chunk that cannot be
    /// placed yet waits in [`Partial::pending`].
    ///
    /// This replaces the previous `Vec<Option<Bytes>>` slot table: one
    /// shared allocation instead of one heap chunk + one slot entry per
    /// fragment, and no second full-payload copy at completion.
    buf: Vec<u8>,
    /// Bit *i* set = chunk *i* landed. This is both the duplicate test and
    /// the completion test (all of the first `total` bits).
    got: u64,
    /// `len(0)` — set by the first fragment; every later position hangs off it.
    first_len: Option<usize>,
    /// The unit width: `len(i)` for any middle fragment (`1 <= i < total - 1`),
    /// locked by the first middle fragment that lands. A later middle
    /// fragment with a different length is refused: a sender splitting one
    /// payload with two different middle widths is not the shipped
    /// fragmenter (and the positions below would not be derivable).
    unit: Option<usize>,
    /// Chunks whose positions are not determinable yet, each owning exactly
    /// its own bytes (see [`PendingChunk`]).
    pending: Vec<PendingChunk>,
    /// Sum of accepted chunk lengths, bounded by [`MQP_FRAG_MAX_PAYLOAD`]
    /// per arrival — the assembled payload is at most that big.
    bytes: usize,
    /// Retained footprint: `buf.capacity()` + the owned pending bytes and
    /// their per-chunk/slot overhead. Charged against
    /// [`FRAG_MAX_HELD_BYTES`] like the previous scheme and re-derived after
    /// every mutation, because capacity-based accounting has no per-chunk
    /// free event.
    retained: usize,
    first_ms: u64,
}

impl Partial {
    fn new(total: u8, ctx: Option<FragCtx>, now_ms: u64) -> Self {
        Self {
            total,
            ctx,
            buf: Vec::new(),
            got: 0,
            first_len: None,
            unit: None,
            pending: Vec::new(),
            bytes: 0,
            retained: 0,
            first_ms: now_ms,
        }
    }

    /// Byte offset of chunk `idx` in the assembly buffer, or `None` while a
    /// determinator is missing: `first_len` for every later fragment and —
    /// except index 1, whose offset is directly after the first chunk — the
    /// `unit` width. Index 0 is always placed.
    fn pos_of(first_len: Option<usize>, unit: Option<usize>, idx: u8) -> Option<usize> {
        if idx == 0 {
            return Some(0);
        }
        let head = first_len?;
        let steps = usize::from(idx) - 1;
        let unit = if steps == 0 { 0 } else { unit? };
        head.checked_add(steps.checked_mul(unit)?)
    }

    /// Write `bytes` into `buf` at `pos`, growing it as needed. The buffer can
    /// never grow past the payload bound: `bytes` admission caps the sum of
    /// chunk lengths, but not the positions a hostile wide `unit` could
    /// pretend, so this is checked where the resize would happen.
    ///
    /// The in-order append case (`pos == buf.len()`, every fragment of a
    /// conforming sender's payload after the first) uses `extend_from_slice`:
    /// one pass that copies the chunk into spare capacity (growing without
    /// zero-filling), instead of `resize` zero-filling the tail and
    /// `copy_from_slice` immediately overwriting it.
    fn buf_write(buf: &mut Vec<u8>, pos: usize, bytes: &[u8]) -> bool {
        let Some(end) = pos.checked_add(bytes.len()) else {
            return false;
        };
        if end > MQP_FRAG_MAX_PAYLOAD {
            return false;
        }
        if pos == buf.len() {
            buf.extend_from_slice(bytes);
        } else {
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[pos..end].copy_from_slice(bytes);
        }
        true
    }

    /// Write every pending chunk whose position just became determinable;
    /// swap-remove re-examines the entry that lands at `i`. Unwritable
    /// entries (never for a conforming partial) stay queued and simply never
    /// complete the payload — a drop by timeout, not a fault.
    fn drain_pending(&mut self) {
        let mut i = 0;
        while i < self.pending.len() {
            let c = &self.pending[i];
            let Some(pos) = Self::pos_of(self.first_len, self.unit, c.idx) else {
                i += 1;
                continue;
            };
            let end = pos.checked_add(c.bytes.len());
            if !end.is_some_and(|end| end <= MQP_FRAG_MAX_PAYLOAD) {
                // Hostile geometry: the chunk never fits inside the payload.
                // Leave it queued (it can never be written).
                i += 1;
                continue;
            }
            let c = self.pending.swap_remove(i);
            let placed = Self::buf_write(&mut self.buf, pos, &c.bytes);
            debug_assert!(placed, "the bound check above keeps every drain in range");
        }
    }

    /// Re-derive the retained footprint (`Self::retained`) from the current
    /// buffer capacity, the owned pending chunks and their slot array.
    ///
    /// Charged: the assembly buffer's capacity, each pending chunk's owned
    /// bytes plus [`PENDING_CHUNK_COST`] (allocation rounding), the `pending`
    /// `Vec`'s slot array, and this `Partial` node itself (it lives in the
    /// partial `HashMap`, whose entry is not otherwise charged). The last two
    /// terms are what keep `retained` honest when the reassembler is full of
    /// small partials: without them the budget under-counts a few hundred
    /// bytes per live partial.
    fn recompute_retained(&mut self) {
        let pending: usize = self
            .pending
            .iter()
            .map(|c| c.bytes.len() + PENDING_CHUNK_COST)
            .sum::<usize>()
            + self.pending.capacity() * std::mem::size_of::<PendingChunk>();
        self.retained = self.buf.capacity() + pending + std::mem::size_of::<Partial>();
    }
}

/// A fully reassembled rev2 payload.
///
/// `wire_id` is `Some` for a flow-addressed payload and `None` for the inline
/// fail-safe form. `sess`/`addr` are present only when the first fragment
/// carried an `OPEN`/`INLINE` context; a steady fragment set resolves its route
/// through the receiver's flow registry instead.
#[derive(Debug)]
pub struct R2Assembled {
    pub wire_id: Option<u32>,
    pub sess: Option<u32>,
    pub addr: Option<TargetAddr>,
    pub src: bool,
    pub payload: Bytes,
}

/// Per-connection rev2/rev3 reassembly state.
pub struct R2Reassembler {
    /// Wire revision this reassembler serves (see [`Self::new_with_wire`]).
    wire: Wire,
    parts: FragMap<Partial>,
    /// Insertion order of the live partials, oldest first. `parts` is the
    /// authority; completed/expired/evicted entries leave a stale slot that the
    /// sweep and eviction paths skip lazily (the queued `first_ms` must still
    /// match the live entry), so maintaining the order costs no scan. The
    /// deque itself is bounded by [`Self::prune_orders`], which re-seats it from
    /// the live partials once the stale tail outgrows them.
    order: VecDeque<(FragKey, u64)>,
    held: usize,
    /// Resident bytes of the `order` deque, including the stale slots of
    /// completed partials. Kept separate from `held` (the fragment budget) but
    /// included in [`R2Reassembler::held_bytes`] so the sweep guard sees the
    /// memory it is responsible for.
    order_bytes: usize,
}

impl Default for R2Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// One `FRAG` frame normalized from either wire revision, so the assembly logic
/// below is written once.
struct FragIn<'a> {
    wire_id: Option<u32>,
    sess: Option<u32>,
    addr: Option<crate::mqp::addr::TargetAddrRef<'a>>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk_off: usize,
    chunk: &'a [u8],
}

impl<'a> FragIn<'a> {
    fn from_rev2(f: &r2::FragRef<'a>) -> Self {
        Self {
            wire_id: f.id,
            sess: f.sess,
            addr: f.addr,
            src: f.src,
            frag_id: f.frag_id,
            idx: f.idx,
            total: f.total,
            chunk_off: f.chunk_off,
            chunk: f.chunk,
        }
    }

    fn from_view(f: &wire::FragView<'a>) -> Self {
        Self {
            wire_id: f.wire_id,
            sess: f.sess,
            addr: f.addr,
            src: f.src,
            frag_id: f.frag_id,
            idx: f.idx,
            total: f.total,
            chunk_off: f.chunk_off,
            chunk: f.chunk,
        }
    }
}

impl R2Reassembler {
    /// A reassembler for the shipped rev2 wire.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_wire(Wire::Rev2)
    }

    /// A reassembler for `wire`. The wire only selects the accepted decoded view
    /// (`push` is rev2-compatible, `push_view` is either revision); keys, bounds
    /// and expiry are shared.
    #[must_use]
    pub fn new_with_wire(wire: Wire) -> Self {
        Self {
            wire,
            parts: FragMap::default(),
            order: VecDeque::new(),
            held: 0,
            order_bytes: 0,
        }
    }

    /// The wire revision this reassembler was created for.
    #[must_use]
    pub fn wire(&self) -> Wire {
        self.wire
    }

    /// Re-target the reassembler at another revision. Only meaningful before
    /// any fragment is pushed (a live connection's revision never changes).
    pub fn set_wire(&mut self, wire: Wire) {
        self.wire = wire;
    }

    /// Retained chunk/slot bytes across all live partials **and** the stale
    /// `order` slots left by completed ones — the quantity the sweep guard and
    /// telemetry see.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held + self.order_bytes
    }

    /// Number of datagrams waiting for their remaining fragments.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.parts.len()
    }

    /// Feed one decoded `FRAG` frame contiguous in `d` (the chunk sits at
    /// [`r2::FragRef::chunk_off`] of this very buffer). Returns the payload
    /// once every fragment has landed.
    ///
    /// Copy policy: a single-fragment payload is delivered as a **view** of
    /// `d` (zero copies); each multi-part chunk is copied exactly once —
    /// straight into its final position in the partial's assembly buffer, or,
    /// while its position is undeterminable, into an owned [`PendingChunk`]
    /// (a copy of exactly the chunk, never a view of the frame — see there)
    /// that is written into the assembly buffer when a later determinator
    /// unlocks it.
    pub fn push(&mut self, d: &Bytes, f: &r2::FragRef<'_>, now_ms: u64) -> Option<R2Assembled> {
        self.push_frame(d, FragIn::from_rev2(f), now_ms)
    }

    /// Feed one decoded fragment from the revision-independent [`wire`] adapter
    /// (rev2 and rev3 both arrive as a [`wire::FragView`]).
    ///
    /// Same contract and byte handling as [`Self::push`]; the view carries
    /// internal `wire_id`s already mapped from the wire's 14-bit `fid`s, so the
    /// keys, bounds and expiry are identical across revisions.
    pub fn push_view(
        &mut self,
        d: &Bytes,
        f: &wire::FragView<'_>,
        now_ms: u64,
    ) -> Option<R2Assembled> {
        self.push_frame(d, FragIn::from_view(f), now_ms)
    }

    fn push_frame(&mut self, d: &Bytes, f: FragIn<'_>, now_ms: u64) -> Option<R2Assembled> {
        // Shape checks before anything copies. A malformed FRAG is a refused
        // datagram like any other validation failure.
        if f.total < 1 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total || f.chunk.is_empty() {
            book_drop(&dgram_drops::REFUSED);
            return None;
        }
        if f.chunk.len() > MQP_FRAG_MAX_PAYLOAD {
            // Oversized chunk for the payload it names: the size class.
            book_drop(&dgram_drops::TOO_LARGE);
            return None;
        }
        // The caller contract: `f` is decoded from this very buffer (the
        // `total == 1` delivery below slices it). A violation is a caller bug
        // or a misdecoded frame, not a payload this module may hold.
        if f.chunk_off.checked_add(f.chunk.len()) != Some(d.len()) {
            book_drop(&dgram_drops::REFUSED);
            return None;
        }
        let key = match (f.wire_id, f.sess) {
            (Some(id), _) if id != 0 => FragKey {
                inline: false,
                id,
                frag_id: f.frag_id,
            },
            (None, Some(sess)) => FragKey {
                inline: true,
                id: sess,
                frag_id: f.frag_id,
            },
            _ => {
                book_drop(&dgram_drops::REFUSED);
                return None;
            }
        };
        // The inline form must be self-describing on every fragment; a flow
        // form may carry a one-time OPEN context on its first fragment.
        let incoming = match (f.sess, f.addr.as_ref()) {
            (Some(sess), Some(addr)) => Some(FragCtx {
                sess,
                addr: addr.into_owned(),
                src: f.src,
            }),
            (None, None) => None,
            _ => {
                book_drop(&dgram_drops::REFUSED);
                return None;
            }
        };
        if key.inline && incoming.is_none() {
            book_drop(&dgram_drops::REFUSED);
            return None;
        }

        // One-fragment payload: the chunk *is* the payload — slice it out of
        // the frame instead of copying it (the previous `copy_from_slice` was
        // the only whole-payload copy on the single-fragment fast path).
        if f.total == 1 {
            return Some(R2Assembled {
                wire_id: f.wire_id,
                sess: incoming.as_ref().map(|c| c.sess),
                addr: incoming.map(|c| c.addr),
                src: f.src,
                payload: d.slice(f.chunk_off..),
            });
        }

        let n = f.chunk.len();
        let idx = f.idx;
        let middle = idx >= 1 && idx != f.total - 1;
        let is_new = match self.parts.get(&key) {
            Some(p) => {
                if p.total != f.total {
                    book_drop(&dgram_drops::REFUSED);
                    return None;
                }
                match (&p.ctx, &incoming) {
                    (Some(old), Some(new)) if old != new => {
                        // A peer trying to splice two sessions/targets into one
                        // payload: refused on policy.
                        book_drop(&dgram_drops::REFUSED);
                        return None;
                    }
                    _ => {}
                }
                if p.got & (1u64 << idx) != 0 {
                    // Duplicate fragment: UDP permits it, delivery already
                    // happened (or will) once. Ignore, don't disturb the partial
                    // — and don't book it as a drop: the payload is not lost.
                    return None;
                }
                if middle
                    && let Some(w) = p.unit
                    && w != n
                {
                    // The segmentation contract: one unit width per payload; a
                    // second width means the positions below are not derivable.
                    book_drop(&dgram_drops::REFUSED);
                    return None;
                }
                if p.bytes.saturating_add(n) > MQP_FRAG_MAX_PAYLOAD {
                    // The payload cap: this fragment would push one partial past
                    // the protocol's payload ceiling.
                    book_drop(&dgram_drops::BUFFER_FULL);
                    return None;
                }
                let placeable = Partial::pos_of(p.first_len, p.unit, idx).is_some();
                // A placeable fragment can be the one that reserves the assembly
                // buffer (`Partial::buf_write` grows it to the fragment's final
                // position; the first placement also `reserve`s the whole payload
                // estimate). Charge that reservation up front, not just the
                // arriving chunk, so the budget check covers the allocation this
                // mutation makes instead of accepting it and discovering the
                // overshoot only after `recompute_retained()`.
                let charge = if placeable {
                    let reserve = if p.buf.capacity() == 0 {
                        (usize::from(f.total) * n).min(MQP_FRAG_MAX_PAYLOAD)
                    } else {
                        0
                    };
                    n.max(reserve)
                } else {
                    // Owned chunk: its exact bytes, its per-chunk overhead, and
                    // the slot-array growth when `pending` has to reallocate.
                    pending_charge(p.pending.len(), p.pending.capacity(), n)
                };
                // Charge the stale `order` backlog too: those slots are resident
                // bytes this type is responsible for. The prune bounds the backlog
                // to a small fraction of the budget, so normal multi-fragment
                // traffic is unaffected; a stale tail still cannot make the live
                // set overshoot the stated bound.
                if self.held_bytes().saturating_add(charge) > FRAG_MAX_HELD_BYTES {
                    // The 256 KiB held-bytes budget: this fragment cannot be
                    // retained without breaking the per-connection bound.
                    book_drop(&dgram_drops::BUFFER_FULL);
                    return None;
                }
                false
            }
            None => {
                // New partial: charge its physical footprint estimate (the first
                // fragment will reserve `total x len` assembly capacity at most,
                // later ones an owned pending chunk) **plus the `order` slot the
                // insertion queues**, and evict under the same pressures as
                // before — this cannot happen mid-payload. The budget is
                // `held_bytes` (live retained bytes plus the bounded stale-slot
                // backlog): eviction reclaims the slots it walks past, and the
                // prune keeps that overhead far below the fragment budget.
                let est = if idx == 0 {
                    (usize::from(f.total) * n).min(MQP_FRAG_MAX_PAYLOAD)
                } else {
                    pending_charge(0, 0, n)
                } + std::mem::size_of::<Partial>()
                    + ORDER_SLOT_BYTES;
                while self.parts.len() >= FRAG_MAX_PARTIALS
                    || self.held_bytes().saturating_add(est) > FRAG_MAX_HELD_BYTES
                {
                    // Every evicted partial is an incomplete payload a peer can no
                    // longer complete; the counters are booked per eviction below.
                    if !self.evict_oldest() {
                        // Nothing left to evict and the new partial still does not
                        // fit: capacity refusal.
                        book_drop(&dgram_drops::BUFFER_FULL);
                        return None;
                    }
                }
                true
            }
        };

        let completed = {
            let partial = self
                .parts
                .entry(key)
                .or_insert_with(|| Partial::new(f.total, incoming.clone(), now_ms));
            if partial.ctx.is_none() {
                partial.ctx = incoming.clone();
            }
            // The determinators as they will read after this fragment's own
            // contribution, so the fragment's position (and the payload bound
            // at that position) is known *before* anything is mutated: a
            // placement past the payload bound must leave the partial
            // untouched rather than half-written.
            let first_after = if idx == 0 { Some(n) } else { partial.first_len };
            let unit_after = if middle && partial.unit.is_none() {
                Some(n)
            } else {
                partial.unit
            };
            let pos = Partial::pos_of(first_after, unit_after, idx);
            if let Some(pos) = pos
                && pos.saturating_add(n) > MQP_FRAG_MAX_PAYLOAD
            {
                // Hostile geometry: the position sits past the payload bound
                // (a wide `unit` pretending room ahead of the payload). A
                // just-created empty partial cannot trigger this (its only
                // placeable fragment is index 0, whose position is `n`); a
                // live one keeps its state and the fragment is refused — the
                // payload times out rather than assembling garbage. The frame
                // is oversized for the payload it names.
                book_drop(&dgram_drops::TOO_LARGE);
                if partial.got == 0 {
                    self.parts.remove(&key);
                }
                return None;
            }
            let first_was = partial.first_len;
            let unit_was = partial.unit;
            let old_retained = partial.retained;
            partial.bytes += n;
            if idx == 0 {
                partial.first_len = Some(n);
            }
            if middle && partial.unit.is_none() {
                partial.unit = Some(n);
            }
            partial.got |= 1u64 << idx;
            match pos {
                Some(pos) => {
                    if partial.buf.capacity() == 0 {
                        // Reserve once, roughly for the whole payload, so a
                        // full set of fragments stops re-allocating per
                        // fragment; later growth still covers a hostile wide
                        // unit.
                        partial
                            .buf
                            .reserve((usize::from(f.total) * n).min(MQP_FRAG_MAX_PAYLOAD));
                    }
                    let placed = Partial::buf_write(&mut partial.buf, pos, f.chunk);
                    debug_assert!(placed, "the bound check above keeps every write in range");
                }
                None => {
                    // Own exactly the chunk's bytes: a refcount view of `d`
                    // would pin quinn's whole receive batch (see
                    // [`PendingChunk`]).
                    partial.pending.push(PendingChunk {
                        idx,
                        bytes: Bytes::copy_from_slice(f.chunk),
                    });
                }
            }
            // A determinator landed with this fragment: it may unlock queued
            // chunks (their writes grow `buf`, so retention is derived after
            // the drain).
            if partial.first_len != first_was || partial.unit != unit_was {
                partial.drain_pending();
            }
            partial.recompute_retained();
            self.held = self
                .held
                .saturating_sub(old_retained)
                .saturating_add(partial.retained);
            // Completion = every index landed. `total` may be the full 64
            // (`R2_MAX_FRAG_TOTAL`), and shifting a 64-bit mask by 64 panics
            // in debug and wraps to a zero mask in release, so the all-ones
            // mask is spelled out for that width.
            let want = 1u64
                .checked_shl(u32::from(f.total))
                .map_or(u64::MAX, |m| m - 1);
            partial.got == want
        };
        if is_new {
            self.order.push_back((key, now_ms));
            self.order_bytes = self.order_bytes.saturating_add(ORDER_SLOT_BYTES);
        }
        // Completed/expired slots are only reclaimed when the sweep reaches
        // them, so a completion flood behind one live blocker would grow the
        // deque without bound. Rebuilding is a single integer compare until the
        // stale tail actually outgrows the live set.
        self.prune_orders();
        if !completed {
            return None;
        }
        let partial = self.parts.remove(&key)?;
        self.held = self.held.saturating_sub(partial.retained);
        let buf = partial.buf;
        let ctx = partial.ctx;
        let src = ctx.as_ref().map_or(f.src, |c| c.src);
        Some(R2Assembled {
            wire_id: if key.inline { None } else { Some(key.id) },
            sess: ctx.as_ref().map(|c| c.sess),
            addr: ctx.map(|c| c.addr),
            src,
            // The assembly buffer *is* the payload: the previous completion
            // re-copied every chunk into a fresh `Vec` first.
            payload: Bytes::from(buf),
        })
    }

    /// Drop every partial belonging to `session` (SESS_CLOSE teardown), returning
    /// how many partials were released. This is best-effort strictness: without
    /// it a partial would expire after [`FRAG_TIMEOUT_MS`] anyway, but a closed
    /// association should not be able to complete a payload within that window.
    pub fn drop_session(&mut self, session: u32) -> usize {
        let mut revoked_bytes = 0usize;
        let mut removed = 0usize;
        self.parts.retain(|key, p| {
            let matches = p.ctx.as_ref().is_some_and(|c| c.sess == session)
                || (key.inline && key.id == session);
            if matches {
                revoked_bytes = revoked_bytes.saturating_add(p.retained);
                removed += 1;
                false
            } else {
                true
            }
        });
        self.held = self.held.saturating_sub(revoked_bytes);
        removed
    }

    /// Drop every partial belonging to one rev2 flow (`FLOW_CLOSE`), returning
    /// how many partials were released. Inline partials are keyed by session and
    /// are not affected.
    pub fn drop_flow(&mut self, wire_id: u32) -> usize {
        if wire_id == 0 {
            return 0;
        }
        let mut revoked_bytes = 0usize;
        let mut removed = 0usize;
        self.parts.retain(|key, p| {
            if !key.inline && key.id == wire_id {
                revoked_bytes = revoked_bytes.saturating_add(p.retained);
                removed += 1;
                false
            } else {
                true
            }
        });
        self.held = self.held.saturating_sub(revoked_bytes);
        removed
    }

    /// Drop partials older than [`FRAG_TIMEOUT_MS`]. The caller owns the clock
    /// tick (the relays already tick a reassembler), so a peer that stops
    /// sending cannot pin partials for the connection's lifetime.
    ///
    /// Every expired live partial is a payload that never completed: it books
    /// `BUFFER_FULL` (the closest existing capacity class — the partial was
    /// occupying the bounded held-bytes budget until the timeout released it).
    /// Stale `order` slots are not payloads and book nothing.
    pub fn expire(&mut self, now_ms: u64) {
        while let Some((key, first_ms)) = self.order.front().copied() {
            let expired = match self.parts.get(&key) {
                Some(p) if p.first_ms == first_ms => {
                    now_ms.saturating_sub(first_ms) >= FRAG_TIMEOUT_MS
                }
                // Stale queue slot (completed/evicted/replaced): drop it.
                Some(_) | None => true,
            };
            if !expired {
                break;
            }
            self.order.pop_front();
            self.order_bytes = self.order_bytes.saturating_sub(ORDER_SLOT_BYTES);
            if let Some(p) = self.parts.get(&key)
                && p.first_ms == first_ms
            {
                let p = self.parts.remove(&key).expect("checked above");
                self.held = self.held.saturating_sub(p.retained);
                book_drop(&dgram_drops::BUFFER_FULL);
            }
        }
        // The sweep can stop at the first live blocker while stale slots sit
        // behind it; compact them before returning so a single blocker cannot
        // pin an unbounded tail.
        self.prune_orders();
    }

    /// Re-seat the `order` deque from the live partials once the stale slots
    /// left by completed/expired/evicted ones outgrow them.
    ///
    /// A slot is only reclaimed by [`Self::expire`]/[`Self::evict_oldest`] when
    /// it reaches the front, so one long-lived blocker pins every slot queued
    /// behind it. The rebuild reproduces the sweep's contract — live partials
    /// oldest first — with `first_ms` as the primary key and [`FragKey`] as the
    /// deterministic tie-break; a rebuilt slot can never be mistaken for a live
    /// entry that replaced its key because the sweep matches `first_ms`
    /// exactly.
    fn prune_orders(&mut self) {
        let limit = self
            .parts
            .len()
            .saturating_mul(2)
            .saturating_add(ORDER_SLOT_LIMIT);
        if self.order.len() <= limit {
            return;
        }
        let mut live: Vec<(FragKey, u64)> = self
            .parts
            .iter()
            .map(|(key, partial)| (*key, partial.first_ms))
            .collect();
        live.sort_unstable_by_key(|(key, first_ms)| (*first_ms, key.inline, key.id, key.frag_id));
        self.order = VecDeque::from(live);
        self.order_bytes = self.order.len().saturating_mul(ORDER_SLOT_BYTES);
    }

    /// Evict the oldest live partial; `false` when none is left.
    ///
    /// An evicted partial is a payload a peer can no longer complete, dropped
    /// because a bounded capacity (partial count or held bytes) was exhausted:
    /// each live removal books `BUFFER_FULL`.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, first_ms)) = self.order.pop_front() {
            self.order_bytes = self.order_bytes.saturating_sub(ORDER_SLOT_BYTES);
            match self.parts.get(&key) {
                Some(p) if p.first_ms == first_ms => {
                    let p = self.parts.remove(&key).expect("checked above");
                    self.held = self.held.saturating_sub(p.retained);
                    book_drop(&dgram_drops::BUFFER_FULL);
                    return true;
                }
                _ => continue,
            }
        }
        // The order queue was empty/stale but `parts` is not: fall back to
        // removing any entry (cannot happen while every insertion pushes a slot,
        // but keep the eviction guarantee total).
        if let Some(key) = self.parts.keys().next().copied() {
            let p = self.parts.remove(&key).expect("just observed");
            self.held = self.held.saturating_sub(p.retained);
            book_drop(&dgram_drops::BUFFER_FULL);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::addr::TargetAddrRef;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    /// Test frame: the owned `Bytes` view (the "arrived datagram") plus the
    /// decoded view over it, with the chunk at a one-byte offset inside the
    /// frame — the shape decode_frag produces, so the reassembler exercises
    /// the same view arithmetic (and the same zero-copy slice) as in
    /// production. `feed` is the way tests hand these in.
    fn frag<'a>(
        id: Option<u32>,
        sess: Option<u32>,
        addr: Option<TargetAddrRef<'a>>,
        idx: u8,
        total: u8,
        frag_id: u32,
        chunk: &'a [u8],
    ) -> (Bytes, r2::FragRef<'a>) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(0u8);
        frame.extend_from_slice(chunk);
        let d = Bytes::from(frame);
        let f = r2::FragRef {
            id,
            sess,
            addr,
            src: false,
            frag_id,
            idx,
            total,
            chunk_off: 1,
            chunk,
        };
        (d, f)
    }

    /// Push one helper-built frame (`frag` above): the owned view is what the
    /// reassembler holds out-of-order chunks against, as a real datagram
    /// would be.
    fn feed(r: &mut R2Reassembler, input: (Bytes, r2::FragRef<'_>)) -> Option<R2Assembled> {
        r.push(&input.0, &input.1, 0)
    }

    #[test]
    fn steady_reassembly_out_of_order() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(1, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 2, 7, b"world")).is_none());
        assert_eq!(r.inflight(), 1);
        let done = feed(&mut r, frag(Some(id), None, None, 0, 2, 7, b"hello ")).unwrap();
        assert_eq!(done.wire_id, Some(id));
        assert_eq!(done.sess, None);
        assert_eq!(done.payload, Bytes::from_static(b"hello world"));
        assert_eq!(r.inflight(), 0);
        // The completed partial's order slot stays until the sweep; it is part
        // of the retained footprint (and of the tick guard).
        assert_eq!(r.held_bytes(), ORDER_SLOT_BYTES);
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0);
        assert!(r.order.is_empty());
    }

    #[test]
    fn open_context_is_kept_and_resolved() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(2, false).unwrap();
        let target = TargetAddrRef::Ip(v4(53));
        assert!(
            feed(
                &mut r,
                frag(Some(id), Some(7), Some(target), 1, 2, 9, b"de")
            )
            .is_none()
        );
        let done = feed(
            &mut r,
            frag(Some(id), Some(7), Some(target), 0, 2, 9, b"ab"),
        )
        .unwrap();
        assert_eq!(done.wire_id, Some(id));
        assert_eq!(done.sess, Some(7));
        assert_eq!(done.addr, Some(TargetAddr::Ip(v4(53))));
        assert_eq!(done.payload, Bytes::from_static(b"abde"));
    }

    /// rev3: fragments decoded through the [`wire`] adapter
    /// ([`wire::decode_frag`] → [`wire::FragView`]) reassemble with the same
    /// keys/bounds/expiry and produce the same `R2Assembled` shape as rev2.
    #[test]
    fn rev3_fragments_reassemble_through_the_wire_adapter() {
        use wire::Wire;

        let mut r = R2Reassembler::new_with_wire(Wire::Rev3);
        assert_eq!(r.wire(), Wire::Rev3);
        // Client-owned internal id local 1 => wire_id 2 (fid 0).
        let wire_id = 2u32;
        let target = TargetAddrRef::Ip(v4(53));
        // Build real rev3 frames: first fragment carries the OPEN context, the
        // second is a steady fragment (out of order on purpose).
        let f1 =
            wire::encode_frag_open(Wire::Rev3, wire_id, 7, &target, false, 9, 1, 2, b"de", 1500)
                .expect("r3 frag open encodes");
        let f0 = wire::encode_frag_steady(Wire::Rev3, wire_id, 9, 0, 2, b"ab", 1500)
            .expect("r3 frag steady encodes");
        let d1 = f1;
        let v1 = wire::decode_frag(Wire::Rev3, &d1).expect("r3 frag decodes");
        assert!(r.push_view(&d1, &v1, 0).is_none());
        let d0 = f0;
        let v0 = wire::decode_frag(Wire::Rev3, &d0).expect("r3 frag decodes");
        let done = r
            .push_view(&d0, &v0, 0)
            .expect("the payload completes when the last fragment lands");
        assert_eq!(done.wire_id, Some(wire_id));
        assert_eq!(done.sess, Some(7));
        assert_eq!(done.addr, Some(TargetAddr::Ip(v4(53))));
        assert_eq!(done.payload, Bytes::from_static(b"abde"));
        assert_eq!(r.inflight(), 0);

        // A one-fragment rev3 payload is a zero-copy view of the frame, exactly
        // like the rev2 path.
        let one = wire::encode_frag_steady(Wire::Rev3, wire_id, 10, 0, 1, b"whole", 1500).unwrap();
        let v = wire::decode_frag(Wire::Rev3, &one).unwrap();
        let done = r.push_view(&one, &v, 0).unwrap();
        assert_eq!(done.payload, Bytes::from_static(b"whole"));
        assert_eq!(
            done.payload.as_ptr(),
            v.chunk.as_ptr(),
            "single-fragment payloads stay views of the arrived frame"
        );
    }

    #[test]
    fn inline_reassembly_uses_session_key() {
        let mut r = R2Reassembler::new();
        let target = TargetAddrRef::Ip(v4(53));
        assert!(feed(&mut r, frag(None, Some(7), Some(target), 0, 2, 3, b"ab")).is_none());
        let done = feed(&mut r, frag(None, Some(7), Some(target), 1, 2, 3, b"cd")).unwrap();
        assert_eq!(done.wire_id, None);
        assert_eq!(done.sess, Some(7));
        assert_eq!(done.addr, Some(TargetAddr::Ip(v4(53))));
        assert_eq!(done.payload, Bytes::from_static(b"abcd"));
    }

    #[test]
    fn context_mismatch_is_refused() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(3, false).unwrap();
        // First fragment of a flow payload, carrying its `OPEN` context.
        assert!(
            feed(
                &mut r,
                frag(
                    Some(id),
                    Some(7),
                    Some(TargetAddrRef::Ip(v4(53))),
                    0,
                    2,
                    1,
                    b"a"
                )
            )
            .is_none()
        );
        // Different session for the same wire id: a peer trying to splice.
        assert!(
            feed(
                &mut r,
                frag(
                    Some(id),
                    Some(8),
                    Some(TargetAddrRef::Ip(v4(53))),
                    1,
                    2,
                    1,
                    b"b"
                )
            )
            .is_none()
        );
        assert_eq!(r.inflight(), 1);
    }

    #[test]
    fn total_mismatch_and_duplicates() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(4, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 3, 1, b"a")).is_none());
        // Same key with a different total: refuse, keep the partial.
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 2, 1, b"b")).is_none());
        // Duplicate index: ignore.
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 3, 1, b"a")).is_none());
        assert_eq!(r.inflight(), 1);
    }

    #[test]
    fn single_fragment_payload_is_returned_directly() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(5, false).unwrap();
        let done = feed(&mut r, frag(Some(id), None, None, 0, 1, 1, b"whole")).unwrap();
        assert_eq!(done.wire_id, Some(id));
        assert_eq!(done.payload, Bytes::from_static(b"whole"));
        assert_eq!(r.inflight(), 0);
    }

    /// The single-fragment fast path is a **view** of the frame: the payload
    /// shares the arrived `Bytes` allocation instead of being re-copied.
    #[test]
    fn single_fragment_payload_is_returned_zero_copy() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(5, false).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(b"padded!");
        let off = frame.len();
        frame.extend_from_slice(b"whole");
        let d = Bytes::from(frame);
        let f = r2::FragRef {
            id: Some(id),
            sess: None,
            addr: None,
            src: false,
            frag_id: 1,
            idx: 0,
            total: 1,
            chunk_off: off,
            chunk: &d[off..],
        };
        let done = r.push(&d, &f, 0).unwrap();
        assert_eq!(done.payload, Bytes::from_static(b"whole"));
        assert_eq!(done.payload.as_ptr(), &d[off..] as *const [u8] as *const u8);
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), 0);
    }

    #[test]
    fn expiry_releases_held_bytes() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(6, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"xx")).is_none());
        assert!(r.held_bytes() > 0);
        r.expire(FRAG_TIMEOUT_MS - 1);
        assert_eq!(r.inflight(), 1);
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), 0);
    }

    #[test]
    fn partial_cap_evicts_instead_of_growing() {
        let mut r = R2Reassembler::new();
        for i in 0..FRAG_MAX_PARTIALS as u32 {
            let id = r2::make_wire_id(i + 1, false).unwrap();
            assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"x")).is_none());
        }
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
        let id = r2::make_wire_id(10_000, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"y")).is_none());
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
    }

    #[test]
    fn drop_session_and_flow_release_partials() {
        let mut r = R2Reassembler::new();
        let id1 = r2::make_wire_id(1, false).unwrap();
        let id2 = r2::make_wire_id(2, false).unwrap();
        assert!(
            feed(
                &mut r,
                frag(
                    Some(id1),
                    Some(7),
                    Some(TargetAddrRef::Ip(v4(53))),
                    0,
                    2,
                    1,
                    b"aa"
                )
            )
            .is_none()
        );
        assert!(feed(&mut r, frag(Some(id2), None, None, 0, 2, 2, b"bb")).is_none());
        assert_eq!(r.drop_session(7), 1);
        assert_eq!(r.inflight(), 1);
        assert!(r.held_bytes() > 0);
        assert_eq!(r.drop_flow(id2), 1);
        assert_eq!(r.inflight(), 0);
        // Both partials are gone; their order slots remain until the sweep.
        assert_eq!(r.held_bytes(), 2 * ORDER_SLOT_BYTES);
        r.expire(0);
        assert_eq!(r.held_bytes(), 0);
        // Dropping an unknown id/session is a no-op.
        assert_eq!(r.drop_session(99), 0);
        assert_eq!(r.drop_flow(1234), 0);
    }

    #[test]
    fn oversized_chunk_is_refused() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(7, false).unwrap();
        let big = vec![0u8; MQP_FRAG_MAX_PAYLOAD + 1];
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 1, &big)).is_none());
        assert_eq!(r.inflight(), 0);
    }

    /// The last fragment can land first (quinn only forwards what arrived);
    /// its position cannot be derived from its own length, so the reassembler
    /// holds it as a view and writes it once the first fragment sets the
    /// layout. The payload must be byte-exact — zero padding must never leak
    /// into a final chunk shorter than the unit width.
    #[test]
    fn reassembly_survives_last_fragment_first_and_short_tails() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(8, false).unwrap();
        // total 3: first fragment, one middle fragment, a two-byte tail that
        // lands first.
        assert!(feed(&mut r, frag(Some(id), None, None, 2, 3, 4, b"rl")).is_none());
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 3, 4, b"head")).is_none());
        let done = feed(&mut r, frag(Some(id), None, None, 1, 3, 4, b"middl")).unwrap();
        assert_eq!(
            done.payload,
            Bytes::from_static(b"headmiddlrl"),
            "the short tail is written at its exact offset"
        );
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), ORDER_SLOT_BYTES);
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0);
    }

    /// total 2 has no middle fragment: the tail's position is directly after
    /// the first fragment, so its early arrival is served by `first_len`
    /// alone.
    #[test]
    fn reassembly_two_parts_resolve_from_the_first_fragment_alone() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(9, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 2, 5, b"cd")).is_none());
        let done = feed(&mut r, frag(Some(id), None, None, 0, 2, 5, b"ab")).unwrap();
        assert_eq!(done.payload, Bytes::from_static(b"abcd"));
        assert_eq!(r.inflight(), 0);
    }

    /// The unit width is a *contract* of the segmentation plan: a middle
    /// fragment disagreeing with a locked width cannot be placed consistently
    /// and is refused wholesale instead of corrupting the reassembly.
    #[test]
    fn a_middle_fragment_disagreeing_with_the_locked_unit_is_refused() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(10, false).unwrap();
        // total 4: fragment 1 locks the unit width at 5.
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 4, 6, b"five!")).is_none());
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 4, 6, b"x0")).is_none());
        // A second middle fragment with another width: refused, partial intact.
        assert!(feed(&mut r, frag(Some(id), None, None, 2, 4, 6, b"seven77")).is_none());
        assert_eq!(r.inflight(), 1);
        // The conforming width is accepted (a refusal was per-fragment) but
        // the payload is still one fragment short.
        assert!(feed(&mut r, frag(Some(id), None, None, 2, 4, 6, b"five!")).is_none());
        // The tail completes it (payload: chunk0 + five! + five! + tail).
        let done = feed(&mut r, frag(Some(id), None, None, 3, 4, 6, b"tail")).unwrap();
        assert_eq!(done.payload, Bytes::from_static(b"x0five!five!tail"));
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), ORDER_SLOT_BYTES);
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0);
    }

    /// `got` is a 64-bit mask and the wire allows the full width
    /// ([`MQP_FRAG_MAX_TOTAL`] = 64): completion must use the all-ones mask,
    /// not `1u64 << total`, which panics in debug builds and wraps to a zero
    /// mask in release (a legal 64-fragment payload would never complete).
    #[test]
    fn a_full_width_64_fragment_payload_completes() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(11, false).unwrap();
        let total = MQP_FRAG_MAX_TOTAL;
        for idx in 0..total {
            let chunk = [b'a' + idx];
            let done = feed(&mut r, frag(Some(id), None, None, idx, total, 7, &chunk));
            if idx + 1 == total {
                let done = done.expect("every index landed: the payload completes");
                assert_eq!(done.payload.len(), usize::from(total));
                assert_eq!(r.inflight(), 0);
                assert_eq!(r.held_bytes(), ORDER_SLOT_BYTES);
                r.expire(FRAG_TIMEOUT_MS);
                assert_eq!(r.held_bytes(), 0);
            } else {
                assert!(done.is_none(), "still partial after index {idx}");
            }
        }
    }

    /// A completed payload leaves its `order` slot behind for the sweep, so a
    /// single live blocker at the front pins a growing tail of stale slots
    /// (the deque used to be bounded only by the completion rate until the
    /// blocker timed out). `prune_orders` must rebuild it from the live
    /// partials, keeping the charged backlog (and thus `held_bytes`) bounded.
    #[test]
    fn stale_order_slots_behind_a_live_blocker_are_pruned() {
        let mut r = R2Reassembler::new();
        let blocker = r2::make_wire_id(900, false).unwrap();
        assert!(feed(&mut r, frag(Some(blocker), None, None, 0, 2, 1, b"blocker")).is_none());
        assert_eq!(r.inflight(), 1);
        // Each two-fragment payload completes and leaves one stale slot that
        // the sweep cannot reach: the live blocker sits in front of it.
        for i in 0..512u32 {
            let id = r2::make_wire_id(1_000 + i, false).unwrap();
            assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"aa")).is_none());
            let done = feed(&mut r, frag(Some(id), None, None, 1, 2, 1, b"bb"));
            assert!(done.is_some(), "two-fragment payload {i} completes");
        }
        assert_eq!(r.inflight(), 1, "only the blocker is still live");
        // The prune runs on the push that inserts the next partial, i.e. with
        // two partials in `parts`; its threshold is `2 * parts + slack`.
        let bound = (r.parts.len() + 1) * 2 + ORDER_SLOT_LIMIT;
        assert!(
            r.order.len() <= bound,
            "prune_orders must bound the stale backlog: {} slots for {} live partials",
            r.order.len(),
            r.parts.len()
        );
        assert_eq!(
            r.order_bytes,
            r.order.len() * ORDER_SLOT_BYTES,
            "the charged backlog must match the deque that is actually resident"
        );
        assert_eq!(
            r.order.front().map(|(_, first_ms)| *first_ms),
            Some(0),
            "the live blocker still leads the sweep"
        );
        // A tick short of the timeout keeps the blocker (and must not be fooled
        // by the stale slots into expiring it early).
        r.expire(FRAG_TIMEOUT_MS - 1);
        assert_eq!(r.inflight(), 1);
        // Once the blocker is due, the sweep drains everything.
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), 0);
        assert!(r.order.is_empty());
    }

    /// After a rebuild the deque must still encode the sweep's contract
    /// (`first_ms` order) and the eviction order: a tick stops at the first
    /// non-expired live partial, and `evict_oldest` removes the oldest live
    /// one — not whichever slot happens to sit first after the rebuild.
    #[test]
    fn rebuilt_order_keeps_expiry_and_eviction_order() {
        let mut r = R2Reassembler::new();
        let a = r2::make_wire_id(700, false).unwrap();
        let b = r2::make_wire_id(701, false).unwrap();
        let (d, f) = frag(Some(a), None, None, 0, 2, 1, b"aaaa");
        assert!(r.push(&d, &f, 0).is_none());
        let (d, f) = frag(Some(b), None, None, 0, 2, 2, b"bbbb");
        assert!(r.push(&d, &f, 10).is_none());
        // Grow the stale tail until the next sweep has to rebuild, without
        // tripping the push-side prune first: the payloads all complete, so
        // only their slots are left behind.
        while r.order.len() <= r.parts.len() * 2 + ORDER_SLOT_LIMIT {
            let id = r2::make_wire_id(1_000 + r.order.len() as u32, false).unwrap();
            let (d, f) = frag(Some(id), None, None, 0, 2, 1, b"cc");
            assert!(r.push(&d, &f, 20).is_none());
            let (d, f) = frag(Some(id), None, None, 1, 2, 1, b"dd");
            assert!(r.push(&d, &f, 20).is_some());
        }
        assert_eq!(r.inflight(), 2);
        // The sweep stops at `a` (live at 0), but the rebuild compacts the
        // stale tail and orders the live partials by `first_ms`: a then b.
        r.expire(FRAG_TIMEOUT_MS - 1);
        assert_eq!(r.inflight(), 2);
        let Some(&(front_key, front_ms)) = r.order.front() else {
            panic!("the rebuilt queue keeps the live partials");
        };
        assert_eq!((front_key.id, front_ms), (a, 0));
        assert_eq!(r.order.len(), 2, "only the two live partials keep slots");
        assert_eq!(r.order_bytes, 2 * ORDER_SLOT_BYTES);
        // Fill to the partial cap; the next push evicts the oldest live
        // partial the rebuilt queue names first (a), keeping b.
        for i in 0..FRAG_MAX_PARTIALS - 2 {
            let id = r2::make_wire_id(10_000 + i as u32, false).unwrap();
            let (d, f) = frag(Some(id), None, None, 0, 2, 1, b"x");
            assert!(r.push(&d, &f, FRAG_TIMEOUT_MS).is_none());
        }
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
        let id = r2::make_wire_id(99_999, false).unwrap();
        let (d, f) = frag(Some(id), None, None, 0, 2, 1, b"y");
        assert!(r.push(&d, &f, FRAG_TIMEOUT_MS).is_none());
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
        assert!(
            !r.parts.contains_key(&FragKey {
                inline: false,
                id: a,
                frag_id: 1
            }),
            "the oldest live partial is evicted first"
        );
        assert!(r.parts.contains_key(&FragKey {
            inline: false,
            id: b,
            frag_id: 2
        }));
    }

    /// The retained-bytes accounting must be exact: `held` is the sum of every
    /// live partial's `retained`, and `retained` is the partial's real
    /// footprint — assembly buffer capacity, owned pending bytes, per-chunk
    /// overhead, the pending slot array and the `Partial` node — plus the
    /// resident `order` deque. This is the invariant the old view-based scheme
    /// could not satisfy (it charged `len` while pinning a receive batch).
    fn assert_held_exact(r: &R2Reassembler) {
        let mut live = 0usize;
        for p in r.parts.values() {
            let pending_owned: usize = p.pending.iter().map(|c| c.bytes.len()).sum();
            let want = p.buf.capacity()
                + pending_owned
                + p.pending.len() * PENDING_CHUNK_COST
                + p.pending.capacity() * std::mem::size_of::<PendingChunk>()
                + std::mem::size_of::<Partial>();
            assert_eq!(
                p.retained, want,
                "partial retained must be its real footprint, not a view cost"
            );
            live = live.saturating_add(want);
        }
        assert_eq!(r.held, live, "held must equal the live partials' sum");
        assert_eq!(
            r.held_bytes(),
            live.saturating_add(r.order_bytes),
            "held_bytes must be the live partials plus the resident order deque"
        );
    }

    /// MEM-1 lock-in: a pending (out-of-order) chunk must **own** exactly its
    /// bytes. The arrived frame is a narrow slice of quinn's per-`recvmsg`
    /// receive batch (up to ~92 KiB with GRO on Linux), and `Bytes` cannot
    /// report the allocation behind a slice — so a stored view would pin the
    /// whole batch while the budget charged only the chunk's length.
    /// `Bytes::try_into_mut` only succeeds when no clone of the frame survived,
    /// and the payload must stay byte-exact after the parent batch is
    /// clobbered the way the next `recvmsg` reuses its buffer.
    #[test]
    fn pending_chunk_owns_its_bytes_and_never_pins_the_arrived_frame() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(12, false).unwrap();
        // One GRO batch worth of backing bytes; the fragment is a 20 B window
        // at its end (the frame must end at the chunk: chunk_off + len == d.len()).
        let mut batch = vec![0xABu8; 64 * 1472];
        let off = batch.len() - 20;
        let want: Vec<u8> = (0..20).map(|i| (i % 251) as u8).collect();
        batch[off..].copy_from_slice(&want);
        let d = Bytes::from(batch);
        let f = r2::FragRef {
            id: Some(id),
            sess: None,
            addr: None,
            src: false,
            frag_id: 1,
            idx: 1,
            total: 2,
            chunk_off: off,
            chunk: &d[off..],
        };
        assert!(r.push(&d, &f, 0).is_none());
        assert_held_exact(&r);
        assert!(
            r.held_bytes() < 1_000,
            "a 20 B pending chunk must charge ~20 B, not pin the 92 KiB frame: {}",
            r.held_bytes()
        );
        // No refcount view survived: the frame is uniquely owned again.
        let mut owner = d
            .try_into_mut()
            .expect("the pending chunk must own its bytes, not clone the arrived frame");
        owner.fill(0xFF);
        drop(owner);
        // The owned copy is unaffected by the clobbered batch, and the payload
        // is complete and byte-exact once the missing first fragment lands.
        let done = feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"hello ")).unwrap();
        let mut expect = b"hello ".to_vec();
        expect.extend_from_slice(&want);
        assert_eq!(done.payload, Bytes::from(expect));
        assert_held_exact(&r);
    }

    /// The charge for an out-of-order chunk is its real retained footprint:
    /// the owned bytes plus the per-chunk overhead show up in `held_bytes`,
    /// the determinator's drain gives them back, and every step keeps `held`
    /// exactly equal to the live partials' sum.
    #[test]
    fn held_bytes_tracks_owned_pending_bytes() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(13, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 2, 1, b"world")).is_none());
        assert_held_exact(&r);
        let partial = r.parts.values().next().expect("one live partial");
        assert_eq!(partial.pending.len(), 1, "the tail's position is unknown");
        assert_eq!(partial.pending[0].bytes, Bytes::from_static(b"world"));
        assert!(
            r.held_bytes() >= 5 + PENDING_CHUNK_COST,
            "the owned pending chunk is charged its bytes plus its overhead: {}",
            r.held_bytes()
        );
        let done = feed(&mut r, frag(Some(id), None, None, 0, 2, 1, b"hello ")).unwrap();
        assert_eq!(done.payload, Bytes::from_static(b"hello world"));
        assert_held_exact(&r);
        assert_eq!(
            r.held_bytes(),
            ORDER_SLOT_BYTES,
            "only the completed partial's stale order slot remains"
        );
        assert_eq!(r.order_bytes, ORDER_SLOT_BYTES);
        r.expire(FRAG_TIMEOUT_MS);
        assert_held_exact(&r);
        assert_eq!(r.held_bytes(), 0);
    }

    /// A fragment flood that never completes must not break the per-connection
    /// bound: every pending chunk owns exactly its bytes, the accounting is
    /// re-derived on every push, and eviction keeps `held_bytes()` (including
    /// the stale `order` slots) under [`FRAG_MAX_HELD_BYTES`] no matter how
    /// many partials arrive.
    #[test]
    fn pending_fragment_flood_stays_within_the_held_bytes_bound() {
        let mut r = R2Reassembler::new();
        let chunk = vec![0x5Au8; 3000];
        for i in 0..400u32 {
            let id = r2::make_wire_id(20_000 + i, false).unwrap();
            // Index 1 of a 2-fragment payload whose first fragment never
            // arrives: the chunk's position is unknown, so it is retained as
            // an owned pending chunk instead of being written into `buf`.
            assert!(feed(&mut r, frag(Some(id), None, None, 1, 2, 1, &chunk)).is_none());
            assert_held_exact(&r);
            assert!(
                r.held_bytes() <= FRAG_MAX_HELD_BYTES,
                "the held-bytes bound must hold on every push: {} after {i}",
                r.held_bytes()
            );
            assert!(
                r.inflight() <= FRAG_MAX_PARTIALS,
                "the partial cap must hold on every push"
            );
        }
        // Capacity, not the flood, bounded the live set.
        assert!(r.inflight() > 1, "the flood kept a bounded live set");
        assert!(r.inflight() <= FRAG_MAX_PARTIALS);
    }

    /// `dgram_drops` must see the rev2 reassembler's refusals: without them a
    /// peer that filled the budget made all later fragmented traffic vanish
    /// from every counter. Capacity refusals/expiry book `BUFFER_FULL`,
    /// hostile geometry books `TOO_LARGE` and policy refusals book `REFUSED`
    /// (the closest existing classes; see [`book_drop`]). Only lower bounds are
    /// asserted: these counters are process-wide and other modules' tests run
    /// concurrently, so a delta can only over-count, never under-count.
    #[test]
    fn refusals_expiry_and_eviction_are_counted() {
        let full = |before: &crate::stats::dgram_drops::DropSnapshot| {
            crate::stats::dgram_drops::snapshot().buffer_full - before.buffer_full
        };
        let too_large = |before: &crate::stats::dgram_drops::DropSnapshot| {
            crate::stats::dgram_drops::snapshot().too_large - before.too_large
        };
        let refused = |before: &crate::stats::dgram_drops::DropSnapshot| {
            crate::stats::dgram_drops::snapshot().refused - before.refused
        };

        let mut r = R2Reassembler::new();
        // REFUSED: a fragment whose context disagrees with the live partial
        // (a peer trying to splice two sessions into one payload).
        let id = r2::make_wire_id(14, false).unwrap();
        let target = TargetAddrRef::Ip(v4(53));
        assert!(feed(&mut r, frag(Some(id), Some(7), Some(target), 0, 2, 1, b"a")).is_none());
        let before = crate::stats::dgram_drops::snapshot();
        assert!(feed(&mut r, frag(Some(id), Some(8), Some(target), 1, 2, 1, b"b")).is_none());
        assert!(refused(&before) >= 1, "a context splice must book REFUSED");

        // TOO_LARGE: a locked wide unit makes the next position claim bytes
        // past the protocol payload cap (hostile geometry).
        let id = r2::make_wire_id(15, false).unwrap();
        let wide = vec![0u8; 4000];
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 4, 2, &wide)).is_none());
        assert!(feed(&mut r, frag(Some(id), None, None, 1, 4, 2, &wide)).is_none());
        let before = crate::stats::dgram_drops::snapshot();
        assert!(feed(&mut r, frag(Some(id), None, None, 3, 4, 2, b"x")).is_none());
        assert!(
            too_large(&before) >= 1,
            "a position past the payload cap must book TOO_LARGE"
        );

        // BUFFER_FULL: a partial that expires with fragments still missing is
        // a payload lost to the bounded reassembly budget.
        let id = r2::make_wire_id(16, false).unwrap();
        assert!(feed(&mut r, frag(Some(id), None, None, 0, 2, 3, b"ab")).is_none());
        let before = crate::stats::dgram_drops::snapshot();
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.inflight(), 0);
        assert!(
            full(&before) >= 1,
            "an expired incomplete partial must book BUFFER_FULL"
        );
    }

    /// P2-4: the in-order placement path writes each byte once. `buf_write`
    /// appends straight into spare capacity when the chunk continues the
    /// buffer; only the out-of-order gap case keeps the zero-fill + overwrite
    /// behaviour, and the payload bound is enforced in both cases.
    #[test]
    fn buf_write_appends_in_order_and_zero_fills_gaps_only() {
        let mut buf = b"ab".to_vec();
        assert!(Partial::buf_write(&mut buf, 2, b"cd"));
        assert_eq!(buf, b"abcd", "an in-order chunk appends at the end");
        // Out-of-order write with a gap in front of it: the gap is zero-filled
        // (the buffer must stay contiguous) and the chunk is written once.
        assert!(Partial::buf_write(&mut buf, 6, b"gh"));
        assert_eq!(buf, b"abcd\0\0gh");
        // Out-of-order overwrite of existing bytes keeps the old behaviour.
        assert!(Partial::buf_write(&mut buf, 1, b"XY"));
        assert_eq!(buf, b"aXYd\0\0gh");
        // A write past the protocol payload cap is refused without touching
        // the buffer.
        let before = buf.clone();
        assert!(!Partial::buf_write(&mut buf, MQP_FRAG_MAX_PAYLOAD, b"x"));
        assert_eq!(buf, before);
    }
}
