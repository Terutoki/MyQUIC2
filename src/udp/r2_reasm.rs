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
//! Bounds are the shipped ones: 8 KiB per payload, 256 partials, 256 KiB of
//! retained assembly/pending bytes per connection, 2 s partial timeout.
//! Everything is validated before allocation; a malformed fragment only drops
//! that fragment.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

use crate::mqp::addr::TargetAddr;
use crate::mqp::fragment::{
    FRAG_MAX_HELD_BYTES, FRAG_MAX_PARTIALS, FRAG_TIMEOUT_MS, MQP_FRAG_MAX_PAYLOAD,
    MQP_FRAG_MAX_TOTAL,
};
use crate::mqp::r2;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragCtx {
    sess: u32,
    addr: TargetAddr,
    src: bool,
}

/// One out-of-order-arrival chunk that cannot be written into the assembly
/// buffer yet: its position needs a determinator (the first fragment's length,
/// plus the unit width from the index 2) that has not landed.
///
/// The chunk is held as a *view* of the frame it arrived on (an owned
/// refcount clone of the [`Bytes`] plus offset/len), so it is copied exactly
/// once — into the assembly buffer when a later fragment unlocks it. The
/// clone is one atomic increment against the incoming frame; the per-index
/// slot table this replaces paid one owned heap allocation + a full chunk
/// memcpy per arrival *and* a whole-payload copy at completion.
#[derive(Debug)]
struct PendingChunk {
    idx: u8,
    /// The arrived frame (refcount view: the chunk never escapes the frame's
    /// allocation).
    d: Bytes,
    chunk_off: usize,
    len: usize,
}
/// Cost of one [`PendingChunk`] in the retained-bytes budget: the view
/// (idx + offset + len + the `Bytes` header) and its share of the frame it
/// pins. 48 B is the same per-datagram bookkeeping charge the fragmenter
/// uses.
const PENDING_CHUNK_COST: usize = 48;

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
    /// Chunks whose positions are not determinable yet.
    pending: Vec<PendingChunk>,
    /// Sum of accepted chunk lengths, bounded by [`MQP_FRAG_MAX_PAYLOAD`]
    /// per arrival — the assembled payload is at most that big.
    bytes: usize,
    /// Retained footprint: `buf.capacity()` + the pending views. Charged
    /// against [`FRAG_MAX_HELD_BYTES`] like the previous scheme and re-derived
    /// after every mutation, because capacity-based accounting has no
    /// per-chunk free event.
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
    fn buf_write(buf: &mut Vec<u8>, pos: usize, bytes: &[u8]) -> bool {
        let Some(end) = pos.checked_add(bytes.len()) else {
            return false;
        };
        if end > MQP_FRAG_MAX_PAYLOAD {
            return false;
        }
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[pos..end].copy_from_slice(bytes);
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
            let end = pos.checked_add(c.len);
            if !end.is_some_and(|end| {
                end <= MQP_FRAG_MAX_PAYLOAD
                    && c.chunk_off
                        .checked_add(c.len)
                        .is_some_and(|e| e <= c.d.len())
            }) {
                // Hostile geometry: the view never fits its own frame or the
                // payload. Leave it queued (it can never be written).
                i += 1;
                continue;
            }
            let end = end.expect("checked above");
            let c = self.pending.swap_remove(i);
            if self.buf.len() < end {
                self.buf.resize(end, 0);
            }
            self.buf[pos..end].copy_from_slice(&c.d[c.chunk_off..c.chunk_off + c.len]);
        }
    }

    /// Re-derive the retained footprint (`Self::retained`) from the current
    /// buffer capacity and pending views.
    fn recompute_retained(&mut self) {
        let pending: usize = self
            .pending
            .iter()
            .map(|c| c.len + PENDING_CHUNK_COST)
            .sum();
        self.retained = self.buf.capacity() + pending;
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

/// Per-connection rev2 reassembly state.
#[derive(Default)]
pub struct R2Reassembler {
    parts: FragMap<Partial>,
    /// Insertion order of the live partials, oldest first. `parts` is the
    /// authority; completed/expired/evicted entries leave a stale slot that the
    /// sweep and eviction paths skip lazily (the queued `first_ms` must still
    /// match the live entry), so maintaining the order costs no scan.
    order: VecDeque<(FragKey, u64)>,
    held: usize,
    /// Resident bytes of the `order` deque, including the stale slots of
    /// completed partials. Kept separate from `held` (the fragment budget) but
    /// included in [`R2Reassembler::held_bytes`] so the sweep guard sees the
    /// memory it is responsible for.
    order_bytes: usize,
}

impl R2Reassembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    /// straight into its final position in the partial's assembly buffer, or
    /// (while its position is undeterminable) held as a view of `d` and copied
    /// once a later determinator unlocks it.
    pub fn push(&mut self, d: &Bytes, f: &r2::FragRef<'_>, now_ms: u64) -> Option<R2Assembled> {
        // Shape checks before anything allocates.
        if f.total < 1 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total || f.chunk.is_empty() {
            return None;
        }
        if f.chunk.len() > MQP_FRAG_MAX_PAYLOAD {
            return None;
        }
        // The caller contract: `f` is decoded from this very buffer. The view
        // arithmetic below depends on it (and never worries about it again).
        if f.chunk_off.checked_add(f.chunk.len()) != Some(d.len()) {
            return None;
        }
        let key = match (f.id, f.sess) {
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
            _ => return None,
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
            _ => return None,
        };
        if key.inline && incoming.is_none() {
            return None;
        }

        // One-fragment payload: the chunk *is* the payload — slice it out of
        // the frame instead of copying it (the previous `copy_from_slice` was
        // the only whole-payload copy on the single-fragment fast path).
        if f.total == 1 {
            return Some(R2Assembled {
                wire_id: f.id,
                sess: incoming.as_ref().map(|c| c.sess),
                addr: incoming.map(|c| c.addr),
                src: f.src,
                payload: d.slice(f.chunk_off..),
            });
        }

        let n = f.chunk.len();
        let idx = f.idx;
        let middle = idx >= 1 && idx != f.total - 1;
        let is_new = !self.parts.contains_key(&key);
        if let Some(p) = self.parts.get(&key) {
            if p.total != f.total {
                return None;
            }
            match (&p.ctx, &incoming) {
                (Some(old), Some(new)) if old != new => return None,
                _ => {}
            }
            if p.got & (1u64 << idx) != 0 {
                // Duplicate fragment: UDP permits it, delivery already
                // happened (or will) once. Ignore, don't disturb the partial.
                return None;
            }
            if middle
                && let Some(w) = p.unit
                && w != n
            {
                // The segmentation contract: one unit width per payload; a
                // second width means the positions below are not derivable.
                return None;
            }
            if p.bytes.saturating_add(n) > MQP_FRAG_MAX_PAYLOAD {
                return None;
            }
            let placeable = Partial::pos_of(p.first_len, p.unit, idx).is_some();
            let charge = if placeable { n } else { n + PENDING_CHUNK_COST };
            if self.held.saturating_add(charge) > FRAG_MAX_HELD_BYTES {
                return None;
            }
        } else {
            // New partial: charge its physical footprint estimate (the first
            // fragment will reserve `total x len` assembly capacity at most,
            // later ones a view), and evict under the same pressures as
            // before — this cannot happen mid-payload.
            let est = if idx == 0 {
                (usize::from(f.total) * n).min(MQP_FRAG_MAX_PAYLOAD)
            } else {
                n + PENDING_CHUNK_COST
            };
            while self.parts.len() >= FRAG_MAX_PARTIALS
                || self.held.saturating_add(est) > FRAG_MAX_HELD_BYTES
            {
                if !self.evict_oldest() {
                    return None;
                }
            }
        }

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
                // payload times out rather than assembling garbage.
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
                None => partial.pending.push(PendingChunk {
                    idx,
                    d: d.clone(),
                    chunk_off: f.chunk_off,
                    len: n,
                }),
            }
            // A determinator landed with this fragment: it may unlock queued
            // views (their writes grow `buf`, so retention is derived after
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
            }
        }
    }

    /// Evict the oldest live partial; `false` when none is left.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, first_ms)) = self.order.pop_front() {
            self.order_bytes = self.order_bytes.saturating_sub(ORDER_SLOT_BYTES);
            match self.parts.get(&key) {
                Some(p) if p.first_ms == first_ms => {
                    let p = self.parts.remove(&key).expect("checked above");
                    self.held = self.held.saturating_sub(p.retained);
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
}
