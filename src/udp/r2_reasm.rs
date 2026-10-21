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
//! retained chunks per connection, 2 s partial timeout. Everything is validated
//! before allocation; a malformed fragment only drops that fragment.

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragCtx {
    sess: u32,
    addr: TargetAddr,
    src: bool,
}

#[derive(Debug)]
struct Partial {
    total: u8,
    ctx: Option<FragCtx>,
    chunks: Vec<Option<Bytes>>,
    got: u8,
    /// Assembled payload bytes held (bounded by [`MQP_FRAG_MAX_PAYLOAD`]).
    bytes: usize,
    /// Chunk bytes plus the slot-table allocation (bounded by
    /// [`FRAG_MAX_HELD_BYTES`] together with every other partial).
    retained: usize,
    first_ms: u64,
}

impl Partial {
    fn new(total: u8, ctx: Option<FragCtx>, now_ms: u64) -> Self {
        Self {
            total,
            ctx,
            chunks: vec![None; usize::from(total)],
            got: 0,
            bytes: 0,
            retained: 0,
            first_ms: now_ms,
        }
    }

    fn slot_table_bytes(total: u8) -> usize {
        usize::from(total) * std::mem::size_of::<Option<Bytes>>()
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
}

impl R2Reassembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retained chunk/slot bytes across all live partials — the quantity
    /// [`FRAG_MAX_HELD_BYTES`] bounds.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held
    }

    /// Number of datagrams waiting for their remaining fragments.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.parts.len()
    }

    /// Feed one decoded `FRAG` frame. Returns the payload once every fragment
    /// has landed.
    pub fn push(&mut self, f: &r2::FragRef<'_>, now_ms: u64) -> Option<R2Assembled> {
        // Shape checks before anything allocates.
        if f.total < 1 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total || f.chunk.is_empty() {
            return None;
        }
        if f.chunk.len() > MQP_FRAG_MAX_PAYLOAD {
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

        // One-fragment payload: assemble directly, no partial table entry.
        if f.total == 1 {
            return Some(R2Assembled {
                wire_id: f.id,
                sess: incoming.as_ref().map(|c| c.sess),
                addr: incoming.map(|c| c.addr),
                src: f.src,
                payload: Bytes::copy_from_slice(f.chunk),
            });
        }

        let is_new = !self.parts.contains_key(&key);
        let existing = self.parts.get(&key);
        if let Some(p) = existing {
            if p.total != f.total {
                return None;
            }
            match (&p.ctx, &incoming) {
                (Some(old), Some(new)) if old != new => return None,
                (None, Some(_)) => {}
                _ => {}
            }
        }

        // Admission: one owned copy per fragment (the chunk's backing batch is
        // far larger than the frame — see the MQP-2 reassembler note), charged
        // exactly. A partial also charges its slot table on the first chunk.
        let retained_chunk = f.chunk.len();
        if let Some(p) = self.parts.get(&key) {
            if p.bytes.saturating_add(retained_chunk) > MQP_FRAG_MAX_PAYLOAD {
                return None;
            }
            if self.held.saturating_add(retained_chunk) > FRAG_MAX_HELD_BYTES {
                return None;
            }
        } else {
            let slot = Partial::slot_table_bytes(f.total);
            let retained = retained_chunk.saturating_add(slot);
            if retained > FRAG_MAX_HELD_BYTES {
                return None;
            }
            while self.parts.len() >= FRAG_MAX_PARTIALS
                || self.held.saturating_add(retained) > FRAG_MAX_HELD_BYTES
            {
                if !self.evict_oldest() {
                    return None;
                }
            }
        }

        let (completed, first) = {
            let partial = self
                .parts
                .entry(key)
                .or_insert_with(|| Partial::new(f.total, incoming.clone(), now_ms));
            if partial.ctx.is_none() {
                partial.ctx = incoming;
            }
            let slot = &mut partial.chunks[usize::from(f.idx)];
            if slot.is_some() {
                // Duplicate fragment: UDP permits it, delivery already happened
                // (or will) once. Ignore, don't disturb the partial.
                return None;
            }
            *slot = Some(Bytes::copy_from_slice(f.chunk));
            partial.got += 1;
            partial.bytes += retained_chunk;
            partial.retained += retained_chunk;
            let first = partial.got == 1 && partial.got != partial.total;
            if first {
                // Charge the slot table with the first stored chunk, so a flood
                // of never-completing partials is covered by the byte budget
                // (same accounting as the MQP-2 reassembler).
                partial.retained += Partial::slot_table_bytes(partial.total);
            }
            (partial.got == partial.total, first)
        };
        if is_new {
            self.order.push_back((key, now_ms));
        }
        if !completed {
            self.held += if first {
                // `first` implies one stored chunk + the slot table.
                retained_chunk + Partial::slot_table_bytes(f.total)
            } else {
                retained_chunk
            };
            return None;
        }
        let partial = self.parts.remove(&key)?;
        self.held = self.held.saturating_sub(partial.retained);
        let mut out = Vec::with_capacity(partial.bytes);
        for chunk in partial.chunks {
            out.extend_from_slice(&chunk?);
        }
        let ctx = partial.ctx;
        let src = ctx.as_ref().map_or(f.src, |c| c.src);
        Some(R2Assembled {
            wire_id: if key.inline { None } else { Some(key.id) },
            sess: ctx.as_ref().map(|c| c.sess),
            addr: ctx.map(|c| c.addr),
            src,
            payload: Bytes::from(out),
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

    fn frag<'a>(
        id: Option<u32>,
        sess: Option<u32>,
        addr: Option<TargetAddrRef<'a>>,
        idx: u8,
        total: u8,
        frag_id: u32,
        chunk: &'a [u8],
    ) -> r2::FragRef<'a> {
        r2::FragRef {
            id,
            sess,
            addr,
            src: false,
            frag_id,
            idx,
            total,
            chunk,
        }
    }

    #[test]
    fn steady_reassembly_out_of_order() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(1, false).unwrap();
        assert!(
            r.push(&frag(Some(id), None, None, 1, 2, 7, b"world"), 0)
                .is_none()
        );
        assert_eq!(r.inflight(), 1);
        let done = r
            .push(&frag(Some(id), None, None, 0, 2, 7, b"hello "), 0)
            .unwrap();
        assert_eq!(done.wire_id, Some(id));
        assert_eq!(done.sess, None);
        assert_eq!(done.payload, Bytes::from_static(b"hello world"));
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), 0);
    }

    #[test]
    fn open_context_is_kept_and_resolved() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(2, false).unwrap();
        let target = TargetAddrRef::Ip(v4(53));
        assert!(
            r.push(&frag(Some(id), Some(7), Some(target), 1, 2, 9, b"de"), 0)
                .is_none()
        );
        let done = r
            .push(&frag(Some(id), Some(7), Some(target), 0, 2, 9, b"ab"), 0)
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
        assert!(
            r.push(&frag(None, Some(7), Some(target), 0, 2, 3, b"ab"), 0)
                .is_none()
        );
        let done = r
            .push(&frag(None, Some(7), Some(target), 1, 2, 3, b"cd"), 0)
            .unwrap();
        assert_eq!(done.wire_id, None);
        assert_eq!(done.sess, Some(7));
        assert_eq!(done.addr, Some(TargetAddr::Ip(v4(53))));
        assert_eq!(done.payload, Bytes::from_static(b"abcd"));
    }

    #[test]
    fn context_mismatch_is_refused() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(3, false).unwrap();
        assert!(
            r.push(
                &frag(
                    Some(id),
                    Some(7),
                    Some(TargetAddrRef::Ip(v4(53))),
                    0,
                    2,
                    1,
                    b"a"
                ),
                0
            )
            .is_none()
        );
        // Different session for the same wire id: a peer trying to splice.
        assert!(
            r.push(
                &frag(
                    Some(id),
                    Some(8),
                    Some(TargetAddrRef::Ip(v4(53))),
                    1,
                    2,
                    1,
                    b"b"
                ),
                0
            )
            .is_none()
        );
        assert_eq!(r.inflight(), 1);
    }

    #[test]
    fn total_mismatch_and_duplicates() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(4, false).unwrap();
        assert!(
            r.push(&frag(Some(id), None, None, 0, 3, 1, b"a"), 0)
                .is_none()
        );
        // Same key with a different total: refuse, keep the partial.
        assert!(
            r.push(&frag(Some(id), None, None, 1, 2, 1, b"b"), 0)
                .is_none()
        );
        // Duplicate index: ignore.
        assert!(
            r.push(&frag(Some(id), None, None, 0, 3, 1, b"a"), 0)
                .is_none()
        );
        assert_eq!(r.inflight(), 1);
    }

    #[test]
    fn single_fragment_payload_is_returned_directly() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(5, false).unwrap();
        let done = r
            .push(&frag(Some(id), None, None, 0, 1, 1, b"whole"), 0)
            .unwrap();
        assert_eq!(done.wire_id, Some(id));
        assert_eq!(done.payload, Bytes::from_static(b"whole"));
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn expiry_releases_held_bytes() {
        let mut r = R2Reassembler::new();
        let id = r2::make_wire_id(6, false).unwrap();
        assert!(
            r.push(&frag(Some(id), None, None, 0, 2, 1, b"xx"), 0)
                .is_none()
        );
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
            assert!(
                r.push(&frag(Some(id), None, None, 0, 2, 1, b"x"), 0)
                    .is_none()
            );
        }
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
        let id = r2::make_wire_id(10_000, false).unwrap();
        assert!(
            r.push(&frag(Some(id), None, None, 0, 2, 1, b"y"), 0)
                .is_none()
        );
        assert_eq!(r.inflight(), FRAG_MAX_PARTIALS);
    }

    #[test]
    fn drop_session_and_flow_release_partials() {
        let mut r = R2Reassembler::new();
        let id1 = r2::make_wire_id(1, false).unwrap();
        let id2 = r2::make_wire_id(2, false).unwrap();
        assert!(
            r.push(
                &frag(
                    Some(id1),
                    Some(7),
                    Some(TargetAddrRef::Ip(v4(53))),
                    0,
                    2,
                    1,
                    b"aa"
                ),
                0
            )
            .is_none()
        );
        assert!(
            r.push(&frag(Some(id2), None, None, 0, 2, 2, b"bb"), 0)
                .is_none()
        );
        assert_eq!(r.drop_session(7), 1);
        assert_eq!(r.inflight(), 1);
        assert!(r.held_bytes() > 0);
        assert_eq!(r.drop_flow(id2), 1);
        assert_eq!(r.inflight(), 0);
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
        assert!(
            r.push(&frag(Some(id), None, None, 0, 2, 1, &big), 0)
                .is_none()
        );
        assert_eq!(r.inflight(), 0);
    }
}
