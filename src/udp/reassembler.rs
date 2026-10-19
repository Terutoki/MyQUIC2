//! MQP-2 UDP 分片重组器：逐行搬运自 `src/lib.rs`（零改动抽取，`lib.rs` 未碰）。
//!
//! 搬运区间（以符号为准）：
//! - `Partial`（含 `impl`）：lib.rs:1240-1297
//! - `Tombstone`（含 `impl`）：lib.rs:1299-1344
//! - `DgramReassembler`（含 `impl` 全套：`new`/`held_bytes`/`inflight`/`push`/
//!   `is_stale_replay`/`remember`/`push_with_chunk`/`maybe_sweep`/`expire`/
//!   `evict_oldest_tombstone`/`evict_oldest`）：lib.rs:1346-1717
//!
//! 接线：`mqp`（`TargetAddr`/`TargetAddrRef`/`FragmentRef`/
//! `MQP_FRAG_MAX_PAYLOAD`/`MQP_FRAG_MAX_TOTAL`/`FRAG_MAX_HELD_BYTES`/
//! `FRAG_MAX_PARTIALS`/`FRAG_TIMEOUT_MS`）、`stats`（`udp_stats::*`）
//! 均经 `crate::` 绝对路径引用。

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

use crate::mqp::addr::{TargetAddr, TargetAddrRef};
use crate::mqp::fragment::{
    FRAG_MAX_HELD_BYTES, FRAG_MAX_PARTIALS, FRAG_TIMEOUT_MS, FragmentRef, MQP_FRAG_MAX_PAYLOAD,
    MQP_FRAG_MAX_TOTAL,
};
use crate::udp_stats;

/// `(sess, frag_id)` map on [`foldhash::fast::RandomState`] — the same hasher
/// every other packet-adjacent table in this crate uses (see the `foldhash`
/// note in Cargo.toml).
///
/// The key is eight bytes of peer-chosen session id and fragment id, and one
/// fragment probes the tables five to eight times (stale-replay probe, count
/// cap, payload cap, restart probe, `entry`, removal, tombstone insert), so
/// key hashing must be a fast fold rather than SipHash — and because the keys
/// come off the wire, the state must carry a random seed so a peer cannot
/// pre-compute a colliding set. `foldhash`'s `RandomState` seeds each map
/// instance independently (one `HashMap::default()` per field below), and a
/// collision still only costs a probe: the map compares the full key and can
/// never mis-serve.
type FragMap<V> = HashMap<(u32, u32), V, foldhash::fast::RandomState>;

/// A partially reassembled datagram.
pub(crate) struct Partial {
    total: u8,
    address: TargetAddr,
    chunks: Vec<Option<Bytes>>,
    got: u8,
    /// Payload bytes held. Bounds the *assembled* datagram
    /// ([`MQP_FRAG_MAX_PAYLOAD`]) and sizes `assemble`'s output buffer.
    bytes: usize,
    /// Bytes actually retained by the stored chunks, **plus the slot table
    /// itself** (see [`Partial::slot_table_bytes`]). Every stored chunk is an
    /// owned copy of exactly its own length (see `DgramReassembler::push`), so
    /// this is `bytes` once a chunk exists, and both are what
    /// [`DgramReassembler`] bounds against [`FRAG_MAX_HELD_BYTES`].
    retained: usize,
    first_ms: u64,
}

impl Partial {
    fn new(total: u8, address: &TargetAddrRef<'_>, now_ms: u64) -> Self {
        Self {
            total,
            address: address.into_owned(),
            chunks: vec![None; total as usize],
            got: 0,
            bytes: 0,
            retained: 0,
            first_ms: now_ms,
        }
    }

    /// Bytes the `chunks` slot table itself occupies. Charged to `retained`
    /// with the first stored chunk, so the aggregate `FRAG_MAX_HELD_BYTES`
    /// budget covers a flood of never-completing partials instead of letting
    /// 256 x `total` empty slots sit outside every byte bound.
    pub(crate) fn slot_table_bytes(total: u8) -> usize {
        total as usize * std::mem::size_of::<Option<Bytes>>()
    }
}

/// Concatenate a partial's stored chunks into the whole datagram.
///
/// One exact-size `BytesMut`, one pass, one allocation — the chunks are already
/// owned copies of exactly their own length (see [`DgramReassembler::push`]).
fn assemble(chunks: &[Option<Bytes>], bytes: usize) -> Bytes {
    let mut out = bytes::BytesMut::with_capacity(bytes);
    for c in chunks.iter().flatten() {
        out.extend_from_slice(c);
    }
    out.freeze()
}

/// One remembered chunk: the length of the bytes the old generation held at
/// that index, plus a seeded 64-bit fingerprint of them.
///
/// The tombstone used to keep the old generation's chunks *owned* (`Vec<Option<
/// Bytes>>`), which charged the delivered payload's bytes to the reassembly
/// budget a second time and kept them alive for the whole
/// [`FRAG_TIMEOUT_MS`] window — so a burst of completed 8 KiB payloads filled
/// the 256 KiB budget with tombstones and started evicting live partials (and,
/// once the tombstones were gone, stopped refusing replays at all). A
/// fingerprint answers the only question the guard asks ("is this the same
/// bytes the old generation held at this index?") in 24 bytes per index, with
/// no payload retention.
///
/// The disposition on a fingerprint match is unchanged and still fail-closed:
/// identical bytes always match (a real replay is still refused), and a
/// collision between two *different* chunks can only refuse a fresh fragment —
/// it can never splice two generations together, which is the failure the
/// tombstone exists to prevent. The seed is per-reassembler and per-process, so
/// a peer cannot precompute a colliding pair.
#[derive(Clone, Copy)]
struct ChunkFp {
    len: u32,
    hash: u64,
}

impl ChunkFp {
    #[inline]
    fn matches(&self, b: &[u8], seed: &foldhash::fast::RandomState) -> bool {
        self.len as usize == b.len() && self.hash == chunk_hash(b, seed)
    }
}

/// Seeded 64-bit fingerprint of one chunk.
fn chunk_hash(b: &[u8], seed: &foldhash::fast::RandomState) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = seed.build_hasher();
    h.write(b);
    h.finish()
}

/// The chunks of a generation the reassembler has already let go of — either
/// delivered whole ([`DgramReassembler::push`] completing a partial) or
/// discarded by an id-reuse restart — remembered for one [`FRAG_TIMEOUT_MS`]
/// window so a stale replay of that generation cannot mix into the *next*
/// generation on the same `(sess, id)`.
///
/// The restart heuristic in `push_with_chunk` can only see a stale fragment
/// that lands on an *occupied* slot (or carries a different address/total). A
/// replay of the old generation that lands on an *empty* slot of the new
/// generation's live partial is byte-for-byte indistinguishable from a
/// legitimate out-of-order fragment — unless the receiver remembers what the
/// old generation held at that index. That is what this stores (as
/// [`ChunkFp`] fingerprints, compared per fragment), so the check stays O(1).
///
/// Only the most recent generation per key is kept: a conforming sender
/// cannot reuse an id inside the window at all (see
/// [`FRAG_ID_SAFE_WINDOW_MS`]), so a second reuse inside one window is either
/// a replay or a non-conforming peer, and failing closed (dropping the replay)
/// is the safe disposition either way. The residual the tombstone cannot see
/// is a stale chunk the receiver *never stored* (an index the old generation
/// never delivered here); that shape is unreachable from a conforming peer
/// and stays documented at the restart heuristic rather than solved.
///
/// `retained` is the fingerprint table's own bytes (there are no payload bytes
/// to charge any more) and is charged to the same `held` budget as a live
/// partial, so every removal path — expiry, count-cap eviction, byte-cap
/// eviction, overwrite — must subtract it, exactly like a live partial.
struct Tombstone {
    total: u8,
    address: TargetAddr,
    prints: Box<[Option<ChunkFp>]>,
    at_ms: u64,
    retained: usize,
}

impl Tombstone {
    /// Bytes the fingerprint table itself occupies.
    fn retained_for(total: u8) -> usize {
        tombstone_bytes(total)
    }
}

/// Bytes one retired generation's fingerprint table occupies: what a
/// [`Tombstone`] charges to the reassembly budget.
///
/// Exposed to the crate's unit tests (see the re-export in `lib.rs`), which pin
/// `held_bytes()` exactly on every operation; production code reaches it
/// through [`Tombstone::retained_for`].
pub(crate) fn tombstone_bytes(total: u8) -> usize {
    total as usize * std::mem::size_of::<Option<ChunkFp>>()
}

/// Reassembles [`MQP_DGRAM_FRAG`] frames into whole UDP payloads.
///
/// Keyed by `(sess, id)`. Because every fragment carries the address header,
/// out-of-order arrival needs no special case and a lost fragment 0 does not
/// strand the rest — the partial simply expires. Memory is bounded twice over,
/// and both bounds are enforced on every push: per partial by
/// [`MQP_FRAG_MAX_PAYLOAD`] (a fragment whose chunk would push the partial past
/// the protocol's payload ceiling discards the whole partial, so a peer cannot
/// make this side relay a datagram the encoder on the other end would have
/// refused), and in aggregate by [`FRAG_MAX_HELD_BYTES`] over the bytes the
/// partials actually retain.
///
/// **Retained bytes are exact.** Each stored chunk is an owned copy of exactly
/// its own length, plus the partial's slot table; both are charged to `held`.
/// An earlier revision kept the received datagram's `Bytes` slice instead
/// (a refcount bump, no copy) and charged the *frame's* length for it — but the
/// frame is a narrow slice of quinn's per-`recvmsg` receive batch (up to
/// ~92 KiB with GRO), so a 20 B fragment could pin ~92 KiB while the budget read
/// 20 B. `Bytes` cannot report a slice's backing allocation, so the only exact
/// accounting is to own the chunk; see [`DgramReassembler::push`].
///
/// **Id reuse across generations.** Besides the live partials, the reassembler
/// keeps one [`Tombstone`] per recently completed or restarted `(sess, id)`
/// (see above). A fragment whose bytes match the remembered generation at its
/// index — same `total` and address — is a stale replay and is refused before
/// it can occupy an empty slot of the next generation's partial and splice
/// two datagrams together. A fragment that differs is the new generation and
/// is stored normally; a new generation whose chunk happens to be
/// byte-identical to the old one at some index is refused too (fail closed —
/// unreachable from a conforming sender, which never reuses an id inside the
/// window).
///
/// **Expiry is tick-driven.** [`expire`](Self::expire) must be called by a
/// caller that owns a clock tick: `push` is reached only when a fragment
/// arrives, so without it a peer that stops sending datagrams pins its partials
/// for the connection's lifetime.
#[derive(Default)]
pub struct DgramReassembler {
    parts: FragMap<Partial>,
    /// Insertion order of the live partials, oldest first — the order
    /// [`evict_oldest`](Self::evict_oldest) reclaims in. `parts` is the
    /// authority: a partial removed by completion, restart, over-cap discard or
    /// expiry leaves its queue slot behind, and the eviction/expiry paths pop
    /// such stale slots lazily (a slot is live only when the queued `first_ms`
    /// still equals the live entry's), so maintaining the order costs no scan.
    /// Because a partial's `first_ms` is set at insertion and the coarse epoch
    /// never runs backwards, insertion order **is** the oldest-first order the
    /// former `min_by_key` computed.
    part_order: VecDeque<((u32, u32), u64)>,
    /// Recently completed or restarted generations by `(sess, id)` — see
    /// [`Tombstone`]. Never awaited, never delivered; consulted on every push
    /// and reaped by [`expire`](Self::expire) after [`FRAG_TIMEOUT_MS`].
    recent: FragMap<Tombstone>,
    /// Insertion order of the live tombstones; same lazy-invalidation contract
    /// as `part_order`, with the queued `at_ms` identifying the generation — a
    /// key remembered again (a restart) leaves the older slot stale at the same
    /// key, and only the slot whose `at_ms` still matches is live.
    tomb_order: VecDeque<((u32, u32), u64)>,
    /// Retained bytes across all partials *and* tombstones — see
    /// [`Partial::retained`] and [`Tombstone`].
    held: usize,
    last_sweep_ms: u64,
    /// Per-reassembler seed for the tombstones' chunk fingerprints. Random per
    /// instance (foldhash's `RandomState`), so a peer cannot precompute a
    /// colliding pair for the bytes it sends; a collision could only refuse a
    /// fresh fragment, never splice two generations.
    fp_seed: foldhash::fast::RandomState,
}

impl DgramReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes the in-flight partials *and* the id-reuse tombstones retain
    /// (the owned chunk bytes plus each slot table, not payload length — see
    /// [`Partial::retained`]).
    /// This is the quantity [`FRAG_MAX_HELD_BYTES`] bounds.
    pub fn held_bytes(&self) -> usize {
        self.held
    }

    /// Number of datagrams currently waiting for their remaining fragments.
    pub fn inflight(&self) -> usize {
        self.parts.len()
    }

    /// Feed one fragment. Returns the payload once the last fragment lands.
    ///
    /// A duplicate fragment is ignored, a malformed one is rejected without
    /// disturbing the partial, and an incomplete datagram is dropped silently —
    /// the sender is UDP and will not retransmit, so there is nothing to report
    /// to a peer that never asked for reliability. A *complete* set replayed
    /// after delivery is delivered again: UDP permits duplicates, the id is
    /// freed on completion, and suppressing them would cost a window of
    /// completed ids for no semantic gain.
    ///
    /// The chunk is **copied**, deliberately, and this is the only entry point.
    ///
    /// There used to be a zero-copy variant that stored `parent.slice(..)` of
    /// the datagram the frame was decoded from. That is unsound as a *memory
    /// bound*: `Connection::read_datagram` hands out a narrow slice of quinn's
    /// per-`recvmsg` receive batch (`max_udp_payload_size x gro_segments`, i.e.
    /// up to 64 x 1472 B = ~92 KiB on Linux, where quinn-udp enables `UDP_GRO`),
    /// and `Bytes` cannot report the size of the allocation behind a slice. The
    /// charge was therefore the *frame's* length while the pin was the whole
    /// batch, so a 20 B fragment could hold ~92 KiB of RSS against a budget that
    /// read as 20 B — the aggregate bound, `held_bytes()` and every number
    /// derived from them were fiction. Owning the chunk makes the charge exact
    /// (one small allocation per fragment) and keeps the bound real.
    pub fn push(&mut self, f: &FragmentRef<'_>, now_ms: u64) -> Option<(u32, TargetAddr, Bytes)> {
        // Shape checks first, before anything can allocate. `push_with_chunk`
        // still owns the admission policy (it re-checks these); this is a
        // pre-filter so a malformed fragment — which a peer can send at line
        // rate — never pays for a chunk that gets thrown away one line later.
        if f.total < 2 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total {
            return None;
        }
        if self.is_stale_replay(f, now_ms) {
            return None;
        }
        self.push_with_chunk(f, now_ms)
    }

    /// Whether `f` is a replay of the generation this `(sess, id)` tombstone
    /// remembers: same shape and address, and a chunk fingerprint equal to what
    /// the old generation held at this index. Pure lookup, no mutation — O(1).
    fn is_stale_replay(&self, f: &FragmentRef<'_>, now_ms: u64) -> bool {
        let Some(t) = self.recent.get(&(f.sess, f.id)) else {
            return false;
        };
        if now_ms.saturating_sub(t.at_ms) >= FRAG_TIMEOUT_MS {
            return false;
        }
        if t.total != f.total || t.address.as_ref() != f.address {
            return false;
        }
        t.prints.get(f.idx as usize).is_some_and(|slot| {
            slot.as_ref()
                .is_some_and(|fp| fp.matches(f.chunk, &self.fp_seed))
        })
    }

    /// Fingerprint every stored chunk of a retired generation, in index order.
    ///
    /// One pass over the bytes the partial held — the same order of cost as the
    /// `assemble` memcpy it sits next to, once per *completed* fragmented
    /// payload — after which the chunks themselves are dropped instead of being
    /// pinned for the tombstone's window.
    fn prints_of(&self, chunks: &[Option<Bytes>]) -> Box<[Option<ChunkFp>]> {
        chunks
            .iter()
            .map(|c| {
                c.as_ref().map(|b| ChunkFp {
                    len: b.len() as u32,
                    hash: chunk_hash(b, &self.fp_seed),
                })
            })
            .collect()
    }

    /// File one generation's fingerprints as the `(sess, id)` tombstone,
    /// replacing any older one for the key. Charged to `held` like a live
    /// partial, so the count cap and the aggregate byte cap are enforced here —
    /// evicting tombstones only, never a live partial, which keeps this path's
    /// disposition identical to the pre-tombstone code when memory is tight.
    fn remember(
        &mut self,
        key: (u32, u32),
        total: u8,
        address: TargetAddr,
        prints: Box<[Option<ChunkFp>]>,
        now_ms: u64,
    ) {
        let retained = Tombstone::retained_for(total);
        if let Some(old) = self.recent.remove(&key) {
            self.held = self.held.saturating_sub(old.retained);
        }
        self.held = self.held.saturating_add(retained);
        self.recent.insert(
            key,
            Tombstone {
                total,
                address,
                prints,
                at_ms: now_ms,
                retained,
            },
        );
        // The order queue keeps this generation's slot; a replaced generation's
        // older slot at the same key stays behind and is skipped lazily when it
        // reaches the front (its `at_ms` no longer matches the live entry).
        self.tomb_order.push_back((key, now_ms));
        while self.recent.len() > FRAG_MAX_PARTIALS && self.evict_oldest_tombstone() {}
        while self.held > FRAG_MAX_HELD_BYTES && self.evict_oldest_tombstone() {}
    }

    fn push_with_chunk(
        &mut self,
        f: &FragmentRef<'_>,
        now_ms: u64,
    ) -> Option<(u32, TargetAddr, Bytes)> {
        if f.total < 2 || f.total > MQP_FRAG_MAX_TOTAL || f.idx >= f.total {
            return None;
        }
        self.maybe_sweep(now_ms);

        let key = (f.sess, f.id);
        // **One** immutable probe answers every decision that depends on the
        // existing partial: whether this key needs a fresh slot (count cap),
        // whether the fragment would push it past the payload ceiling
        // (discard-whole), and whether it belongs to a new generation
        // (restart). Fusing them is pure: the three checks read the same entry
        // and none of them mutates the map, so the ordering the previous
        // separate probes relied on (count cap, then payload cap, then restart)
        // is preserved exactly. `chunks.get` — not indexing — because the
        // restart decision below is only taken against a slot that
        // `f.idx < f.total == p.total` proves exists.
        let (present, over_cap, restart) = match self.parts.get(&key) {
            None => (false, false, false),
            Some(p) => {
                let stored = p.chunks.get(f.idx as usize);
                let duplicate = stored.is_some_and(Option::is_some);
                // The per-partial *payload* cap the module documents, actually
                // enforced. `total` is bounded by `MQP_FRAG_MAX_TOTAL`, but
                // nothing bounds a *chunk*: at the QUIC path MTU each fragment
                // carries ~1.4 KiB, so a 64-fragment partial assembles to ~91 KiB
                // — far past the payload ceiling this protocol states, and the
                // caller relays whatever comes out (`udp_try_send` would hand the
                // kernel a 91 KiB datagram to IP-fragment). Discarded whole
                // rather than truncated or partially kept: a prefix of a
                // datagram is not a short datagram, it is a *corrupt* one, and
                // UDP above this has no integrity check to notice. A duplicate
                // fragment is exempt (it adds no bytes) so a replayed fragment
                // cannot kill a partial that was already at the cap.
                let over_cap =
                    !duplicate && p.bytes.saturating_add(f.chunk.len()) > MQP_FRAG_MAX_PAYLOAD;
                let restart = if p.total != f.total {
                    true
                } else {
                    // A wrapped id reused with a different shape, or the same
                    // shape but a different generation (the address changed, or
                    // this index already holds different bytes — an identical
                    // chunk is a plain replay and stays ignored below).
                    let differs = stored
                        .is_some_and(|s| s.as_ref().is_some_and(|old| old.as_ref() != f.chunk));
                    p.got > 0 && (p.address.as_ref() != f.address || differs)
                };
                (true, over_cap, restart)
            }
        };
        // Count cap first: `held` misses the per-partial slot-table cost, so a
        // flood of tiny single-fragment partials would otherwise grow memory
        // without ever tripping the byte bound. Evict-before-insert pops the
        // oldest insertion-order slot, so the cost is the stale slots ahead of
        // the oldest live partial — not a full-map scan.
        if !present
            && self.parts.len() >= FRAG_MAX_PARTIALS
            && (!self.evict_oldest() || self.parts.len() >= FRAG_MAX_PARTIALS)
        {
            return None;
        }
        if over_cap {
            if let Some(p) = self.parts.remove(&key) {
                self.held = self.held.saturating_sub(p.retained);
                udp_stats::reassembly_evicted();
            }
            return None;
        }
        let complete = {
            // A restart needs the old partial *moved out* (its fingerprints
            // become the tombstone), which cannot happen through the entry
            // borrow held across a `remember` call — so the decision was read
            // above, and the removal below owns the value.
            if restart && let Some(old) = self.parts.remove(&key) {
                self.held = self.held.saturating_sub(old.retained);
                let total = old.total;
                let prints = self.prints_of(&old.chunks);
                self.remember(key, total, old.address, prints, now_ms);
            }
            let entry = match self.parts.entry(key) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let p = e.insert(Partial::new(f.total, &f.address, now_ms));
                    // Fresh partial: `first_ms` is the insertion time, so its
                    // order slot goes at the back of the oldest-first queue.
                    self.part_order.push_back((key, now_ms));
                    p
                }
            };
            // A wrapped id reused with a different shape, or the same shape
            // but a different generation (the address changed, or this index
            // already holds different bytes — an identical chunk is a plain
            // replay and stays ignored below): the removal above already
            // restarted rather than splice, and filed the old generation as
            // the key's tombstone so its replays cannot occupy the new
            // partial's empty slots either.
            //
            // The heuristic still cannot see a stale fragment the receiver
            // *never stored* (an index the old generation never delivered
            // here): with the same `(sess, id, total, address)` it fills an
            // empty slot exactly like a legitimate out-of-order fragment, and
            // a completed mix would deliver to the older target. That needs
            // the same key twice inside one reassembly window with no
            // occupied-slot overlap at all, which a sender can now only
            // produce by wrapping the 32-bit id at >1.4M fragmented
            // payloads/s; the sender refuses to do that (see
            // `FRAG_ID_SAFE_WINDOW_MS` and `DgramFragmenter::send`), so the
            // residue is unreachable from a conforming peer.
            let slot = &mut entry.chunks[f.idx as usize];
            if slot.is_none() {
                // Own the chunk **here**, not on entry. Everything above is a
                // rejection path (shape, count cap, payload cap, duplicate,
                // stale replay), and a duplicate or malformed fragment is
                // ordinary on a real link — it must not cost a malloc + memcpy
                // + free for bytes that are then dropped. `f.chunk` is still
                // borrowed for the two comparisons that need it, so the copy
                // happens exactly once, at the only point that keeps it.
                let len = f.chunk.len();
                *slot = Some(Bytes::copy_from_slice(f.chunk));
                entry.got += 1;
                entry.bytes += len;
                // The slot table is charged with the first stored chunk, once
                // per partial: every removal path subtracts `retained`, so
                // charging it here keeps `held` balanced for the partial's whole
                // life without touching the creation sites.
                let table = if entry.got == 1 {
                    Partial::slot_table_bytes(entry.total)
                } else {
                    0
                };
                entry.retained = entry.retained.saturating_add(len).saturating_add(table);
                self.held = self.held.saturating_add(len).saturating_add(table);
            }
            entry.got == entry.total
        };

        if complete {
            let mut p = self.parts.remove(&key)?;
            self.held = self.held.saturating_sub(p.retained);
            // File the delivered generation's **fingerprints** before its chunks
            // are freed. The old shape moved the slot table (and therefore every
            // owned chunk) into the tombstone, which kept the whole payload alive
            // for the tombstone window and charged it to `held` a second time —
            // so ~25 completed 8 KiB payloads filled the reassembly budget with
            // tombstones and the guard began evicting live partials (and, once
            // evicted, stopped refusing replays at all). The fingerprints cost
            // `total x 24 B`, carry no payload, and answer the same question.
            let tomb_total = p.total;
            let tomb_addr = p.address.clone();
            let bytes = p.bytes;
            let chunks = std::mem::take(&mut p.chunks);
            let prints = self.prints_of(&chunks);
            let address = p.address;
            let whole = assemble(&chunks, bytes);
            drop(chunks);
            self.remember(key, tomb_total, tomb_addr, prints, now_ms);
            return Some((key.0, address, whole));
        }
        // Reclaim tombstones first: they are id-reuse guards, not deliverable
        // payloads, so a byte-cap overflow must not sacrifice a partial that is
        // still mid-assembly while a tombstone could be dropped instead. Both
        // kinds share one budget, so a burst of large fragmented payloads fills
        // the cap with tombstones from the payloads that just completed; with
        // the oldest *partial* evicted here, 8 KiB payloads were lost under a
        // 16-deep send window (0 expired, all evicted). Only when no tombstone
        // remains is the oldest live partial evicted, the same backstop the
        // pre-tombstone code had.
        while self.held > FRAG_MAX_HELD_BYTES {
            if self.evict_oldest_tombstone() {
                continue;
            }
            if !self.evict_oldest() {
                break;
            }
        }
        None
    }

    /// Drop partials whose first fragment is older than [`FRAG_TIMEOUT_MS`].
    ///
    /// Throttled to one sweep per second; [`expire`](Self::expire) is the
    /// unthrottled form for a clock tick.
    fn maybe_sweep(&mut self, now_ms: u64) {
        if self.last_sweep_ms != 0 && now_ms.saturating_sub(self.last_sweep_ms) < 1_000 {
            return;
        }
        self.expire(now_ms);
    }

    /// Drop every partial whose first fragment is older than
    /// [`FRAG_TIMEOUT_MS`], regardless of the sweep throttle.
    ///
    /// A caller that owns a clock tick **must** call this even when no fragment
    /// is arriving. `push` is the only other path that can expire state, so a
    /// peer that sends its fragments and then stops sending datagrams — while
    /// its QUIC connection stays alive on keepalives — would otherwise pin its
    /// partials (and every byte they retain) for the connection's lifetime, and
    /// [`FRAG_TIMEOUT_MS`] would be a promise the code does not keep. Both
    /// datagram readers drive this from a
    /// [`FRAG_SWEEP_INTERVAL_MS`](crate::FRAG_SWEEP_INTERVAL_MS) tick.
    pub fn expire(&mut self, now_ms: u64) {
        self.last_sweep_ms = now_ms;
        let mut freed = 0usize;
        let mut expired = 0u64;
        self.parts.retain(|_, p| {
            let live = now_ms.saturating_sub(p.first_ms) < FRAG_TIMEOUT_MS;
            if !live {
                freed += p.retained;
                expired += 1;
            }
            live
        });
        for _ in 0..expired {
            udp_stats::reassembly_expired();
        }
        self.held = self.held.saturating_sub(freed);
        // Tombstones age out on the same window: past it the old generation
        // is forgotten everywhere, so an id reuse is a fresh generation by
        // definition. Every removal subtracts `retained`, keeping `held`
        // exact.
        let mut tomb_freed = 0usize;
        self.recent.retain(|_, t| {
            let live = now_ms.saturating_sub(t.at_ms) < FRAG_TIMEOUT_MS;
            if !live {
                tomb_freed += t.retained;
            }
            live
        });
        self.held = self.held.saturating_sub(tomb_freed);
        // Both order queues now hold slots for entries just removed here; drop
        // them so a sweep bounds the queues' size (this is also what keeps a
        // completion burst behind a long-lived head from accumulating slots
        // past one timeout window).
        self.prune_orders();
    }

    /// Pop stale slots off the front of both order queues until each front
    /// names a live entry, then rebuild a queue whose stale tail outgrew its
    /// live map. Stale = the key is gone, or the queued timestamp no longer
    /// matches the live entry's (the key was re-inserted after that slot was
    /// written). Amortized O(1) per slot: every slot is popped at most once.
    fn prune_orders(&mut self) {
        while let Some(&(key, first_ms)) = self.part_order.front() {
            match self.parts.get(&key) {
                Some(p) if p.first_ms == first_ms => break,
                _ => {
                    self.part_order.pop_front();
                }
            }
        }
        while let Some(&(key, at_ms)) = self.tomb_order.front() {
            match self.recent.get(&key) {
                Some(t) if t.at_ms == at_ms => break,
                _ => {
                    self.tomb_order.pop_front();
                }
            }
        }
        // A live head stops the pop loop, so completions (or replacements)
        // behind it can outgrow the live map for up to one timeout window.
        // Rebuild from the map, preserving the oldest-first order, when that
        // tail is no longer worth carrying; the sort is over the live entries
        // only, at most `FRAG_MAX_PARTIALS` of them.
        if self.part_order.len() > self.parts.len().saturating_mul(2).saturating_add(64) {
            let mut live: Vec<((u32, u32), u64)> = self
                .parts
                .iter()
                .map(|(key, p)| (*key, p.first_ms))
                .collect();
            live.sort_unstable_by_key(|&(key, first_ms)| (first_ms, key));
            self.part_order = live.into();
        }
        if self.tomb_order.len() > self.recent.len().saturating_mul(2).saturating_add(64) {
            let mut live: Vec<((u32, u32), u64)> =
                self.recent.iter().map(|(key, t)| (*key, t.at_ms)).collect();
            live.sort_unstable_by_key(|&(key, at_ms)| (at_ms, key));
            self.tomb_order = live.into();
        }
    }

    /// Drop the oldest tombstone, giving its bytes back to `held`. Tombstones
    /// only — a live partial is never sacrificed for a remembered one.
    ///
    /// "Oldest" is insertion order: the record window is a fixed
    /// [`FRAG_TIMEOUT_MS`] and every tombstone's `at_ms` is stamped at
    /// insertion, so the front of [`Self::tomb_order`] is the oldest entry.
    /// Stale slots (a tombstone replaced by a newer generation at the same key,
    /// or already evicted through its own slot) are popped and skipped; every
    /// slot is popped at most once, so this is amortized O(1) instead of the
    /// former full-map `min_by_key` scan — which ran once per completed
    /// fragmented payload as soon as the 256-entry count cap was saturated.
    fn evict_oldest_tombstone(&mut self) -> bool {
        loop {
            let Some(&(key, at_ms)) = self.tomb_order.front() else {
                return false;
            };
            self.tomb_order.pop_front();
            match self.recent.get(&key) {
                Some(t) if t.at_ms == at_ms => {}
                // Stale slot: the queued generation is gone (or was replaced).
                _ => continue,
            }
            if let Some(t) = self.recent.remove(&key) {
                self.held = self.held.saturating_sub(t.retained);
            }
            return true;
        }
    }

    /// Drop the oldest live partial (insertion order, see
    /// [`Self::part_order`]), giving its retained bytes back to `held`.
    fn evict_oldest(&mut self) -> bool {
        loop {
            let Some((key, first_ms)) = self.part_order.pop_front() else {
                return false;
            };
            match self.parts.get(&key) {
                Some(p) if p.first_ms == first_ms => {}
                // Stale slot: the partial completed, restarted, was discarded or
                // expired earlier; its slot is popped at most once.
                _ => continue,
            }
            if let Some(p) = self.parts.remove(&key) {
                self.held = self.held.saturating_sub(p.retained);
                udp_stats::reassembly_evicted();
            }
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::fragment::{decode_fragment, encode_fragment};

    fn v4() -> TargetAddr {
        TargetAddr::Ip("1.2.3.4:53".parse().unwrap())
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The P0-2 lock-in invariant: `held` is exactly the owned chunk bytes
    /// plus the slot tables, summed over live partials *and* tombstones.
    /// A slice-storing or mis-charging change breaks this on the op that
    /// introduces it, because every removal path must subtract `retained`.
    fn assert_held_exact(r: &DgramReassembler) {
        let mut expect = 0usize;
        for p in r.parts.values() {
            let sum: usize = p.chunks.iter().flatten().map(Bytes::len).sum();
            assert_eq!(p.bytes, sum, "payload bytes must equal stored chunk bytes");
            let want = if p.got == 0 {
                0
            } else {
                sum.saturating_add(Partial::slot_table_bytes(p.total))
            };
            assert_eq!(
                p.retained, want,
                "partial retained must be owned chunks plus its slot table"
            );
            expect = expect.saturating_add(p.retained);
        }
        for t in r.recent.values() {
            assert_eq!(
                t.retained,
                Tombstone::retained_for(t.total),
                "tombstone retained must be its fingerprint table"
            );
            assert_eq!(
                t.prints.len(),
                t.total as usize,
                "one fingerprint slot per fragment index"
            );
            expect = expect.saturating_add(t.retained);
        }
        assert_eq!(
            r.held, expect,
            "held must equal the sum over partials+tombstones"
        );
        assert_eq!(r.held_bytes(), expect);
    }

    fn push_bytes(r: &mut DgramReassembler, body: &Bytes, now_ms: u64) -> bool {
        let f = decode_fragment(body).unwrap();
        let done = r.push(&f, now_ms).is_some();
        assert_held_exact(r);
        done
    }

    /// P0-2 lock-in: `held_bytes() == sum(owned chunks + slot tables)` after
    /// every op — insert, duplicate, restart/overwrite, completion (tombstone
    /// file), refused replay, expiry of both kinds, count-cap eviction,
    /// tombstone-first byte-cap eviction, over-cap discard, malformed input.
    #[test]
    fn held_bytes_equal_sum_of_owned_chunks_plus_slot_tables_on_every_op() {
        let addr = v4();
        let aref = addr.as_ref();
        let mut r = DgramReassembler::new();
        assert_held_exact(&r);

        // Insert + duplicate (duplicate retains nothing new).
        let frames: Vec<Bytes> = pattern(3000)
            .chunks(1400)
            .enumerate()
            .map(|(i, c)| encode_fragment(1, 7, i as u8, 3, &aref, c, 64 * 1024).unwrap())
            .collect();
        assert_eq!(frames.len(), 3);
        assert!(!push_bytes(&mut r, &frames[0], 1_000));
        let held_after_first = r.held_bytes();
        assert!(!push_bytes(&mut r, &frames[0], 1_000));
        assert_eq!(r.held_bytes(), held_after_first);
        assert!(!push_bytes(&mut r, &frames[1], 1_000));

        // Overwrite with a different generation on an occupied slot: the old
        // partial is removed and filed as the tombstone, the new one charged.
        let mut other_payload = pattern(3000);
        for b in other_payload.iter_mut() {
            *b ^= 0xFF;
        }
        let others: Vec<Bytes> = other_payload
            .chunks(1400)
            .enumerate()
            .map(|(i, c)| encode_fragment(1, 7, i as u8, 3, &aref, c, 64 * 1024).unwrap())
            .collect();
        assert!(!push_bytes(&mut r, &others[0], 1_000));

        // Completion files the delivered generation as the tombstone.
        assert!(!push_bytes(&mut r, &others[1], 1_000));
        assert!(push_bytes(&mut r, &others[2], 1_000));
        assert_eq!(r.inflight(), 0);

        let held_before = r.held_bytes();
        let replay_of_filed_generation = &others[0];
        assert!(!push_bytes(&mut r, replay_of_filed_generation, 1_000));
        assert_eq!(r.held_bytes(), held_before);
        assert_eq!(r.inflight(), 0);

        // Expiry drops the live partial, then the tombstone with the window.
        assert!(!push_bytes(&mut r, &frames[0], 1_000));
        r.expire(1_000 + FRAG_TIMEOUT_MS);
        assert_held_exact(&r);
        assert_eq!(r.inflight(), 0);
        assert_eq!(r.held_bytes(), 0, "tombstone ages out with the window");

        // Eviction flood: ~1.5 KiB per partial, so the byte cap binds before
        // the count cap; both bounds must hold with `held` still exact.
        for id in 0..(FRAG_MAX_PARTIALS as u32 + 40) {
            let body = encode_fragment(1, id, 0, 4, &aref, &[9u8; 1400], 64 * 1024).unwrap();
            assert!(!push_bytes(&mut r, &body, 2_000));
        }
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
        assert!(r.inflight() <= FRAG_MAX_PARTIALS);

        // Tombstone-first byte-cap eviction: fill the budget with completed
        // generations, then overflow with live partials.
        let mut r = DgramReassembler::new();
        let big = pattern(7800);
        for id in 0..40u32 {
            let fs: Vec<Bytes> = big
                .chunks(1300)
                .enumerate()
                .map(|(i, c)| encode_fragment(7, id, i as u8, 6, &aref, c, 64 * 1024).unwrap())
                .collect();
            assert_eq!(fs.len(), 6);
            let mut done = false;
            for f in &fs {
                done = push_bytes(&mut r, f, 3_000);
            }
            assert!(done);
        }
        for id in 1000..1020u32 {
            let fs: Vec<Bytes> = big
                .chunks(1300)
                .enumerate()
                .map(|(i, c)| encode_fragment(7, id, i as u8, 6, &aref, c, 64 * 1024).unwrap())
                .collect();
            for f in fs.iter().take(3) {
                assert!(!push_bytes(&mut r, f, 3_000));
            }
        }
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);

        // Over-payload-cap discard releases the whole partial.
        let mut r = DgramReassembler::new();
        let over: Vec<Bytes> = pattern(11_200)
            .chunks(1400)
            .enumerate()
            .map(|(i, c)| encode_fragment(1, 21, i as u8, 8, &aref, c, 64 * 1024).unwrap())
            .collect();
        assert_eq!(over.len(), 8);
        for f in &over {
            assert!(!push_bytes(&mut r, f, 4_000));
        }
        assert!(r.held_bytes() <= MQP_FRAG_MAX_PAYLOAD);
        assert_eq!(
            r.inflight(),
            1,
            "the post-discard tail starts a new partial"
        );

        // Malformed input allocates no state.
        let mut bad = decode_fragment(&over[0]).unwrap();
        bad.total = 1;
        assert!(r.push(&bad, 4_000).is_none());
        assert_held_exact(&r);
        assert_eq!(r.inflight(), 1);

        r.expire(4_000 + FRAG_TIMEOUT_MS);
        assert_held_exact(&r);
        assert_eq!(r.held_bytes(), 0);
    }

    /// P0-2 lock-in, anti-splice: a stale replay that lands on an *empty*
    /// slot of the next generation is byte-identical to a legitimate
    /// out-of-order fragment, so only the tombstone (`is_stale_replay`) can
    /// refuse it. Without the tombstone the replay completes `[B0, B1, A2]`.
    #[test]
    fn stale_replay_on_empty_slot_is_refused_via_is_stale_replay() {
        let addr = v4();
        let aref = addr.as_ref();
        let first = pattern(3000);
        let second: Vec<u8> = first.iter().map(|b| b ^ 0xFF).collect();
        let mk = |id: u32, payload: &[u8]| -> Vec<Bytes> {
            payload
                .chunks(1400)
                .enumerate()
                .map(|(i, c)| encode_fragment(5, id, i as u8, 3, &aref, c, 64 * 1024).unwrap())
                .collect()
        };
        let frames_a = mk(11, &first);
        let frames_b = mk(11, &second);
        assert_eq!((frames_a.len(), frames_b.len()), (3, 3));

        let mut r = DgramReassembler::new();
        for f in &frames_a {
            let done = push_bytes(&mut r, f, 1_000);
            if *f != *frames_a.last().unwrap() {
                assert!(!done);
            }
        }
        assert_eq!(r.inflight(), 0, "generation A completes");
        assert!(!push_bytes(&mut r, &frames_b[0], 1_000));
        assert!(!push_bytes(&mut r, &frames_b[1], 1_000));
        assert_eq!(r.inflight(), 1);

        // The replay matches the filed generation at its index: stale.
        let stale = decode_fragment(&frames_a[2]).unwrap();
        assert!(
            r.is_stale_replay(&stale, 1_000),
            "a replay of the filed generation at its index is stale"
        );
        // The new generation's own suffix at the same index differs: fresh.
        let fresh = decode_fragment(&frames_b[2]).unwrap();
        assert!(
            !r.is_stale_replay(&fresh, 1_000),
            "the new generation's own chunk must not look stale"
        );
        // Past the window the same bytes are a fresh generation by definition.
        assert!(
            !r.is_stale_replay(&stale, 1_000 + FRAG_TIMEOUT_MS),
            "the tombstone ages out with the window"
        );

        let held_before = r.held_bytes();
        assert!(r.push(&stale, 1_000).is_none());
        assert_held_exact(&r);
        assert_eq!(r.inflight(), 1, "the replay restarts nothing");
        assert_eq!(
            r.held_bytes(),
            held_before,
            "a refused replay retains nothing"
        );

        let done = r
            .push(&fresh, 1_000)
            .expect("B completes with its own suffix");
        assert_held_exact(&r);
        assert_eq!(&done.2[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);
    }

    /// P0-2 lock-in, GRO pin: the frame handed to `push` is a narrow slice
    /// of quinn's per-`recvmsg` batch (up to 64 x 1472 B ≈ 92 KiB with GRO),
    /// and `Bytes` cannot report the backing allocation — so storing
    /// `parent.slice(..)` pins ~92 KiB while the budget reads 20 B. The chunk
    /// must be an owned copy (`Bytes::copy_from_slice` at `push`): 20 B in,
    /// 20 B charged, and the payload survives the parent being clobbered.
    #[test]
    fn twenty_byte_fragment_must_not_pin_ninety_two_kib_batch() {
        // One GRO batch worth of backing bytes; the fragment is a 20 B window.
        let mut batch = vec![0xABu8; 64 * 1472];
        let off = 1000usize;
        let want_first: Vec<u8> = (0..20).map(|i| (i % 251) as u8).collect();
        batch[off..off + 20].copy_from_slice(&want_first);

        let addr = v4();
        let aref = addr.as_ref();
        let total = 2u8;
        let mut r = DgramReassembler::new();
        {
            let f = FragmentRef {
                sess: 1,
                id: 9,
                idx: 0,
                total,
                address: aref,
                chunk: &batch[off..off + 20],
            };
            assert!(r.push(&f, 1_000).is_none());
        }
        assert_held_exact(&r);
        assert_eq!(
            r.held_bytes(),
            20 + Partial::slot_table_bytes(total),
            "a 20 B fragment charges 20 B plus its slot table, never the 92 KiB batch"
        );

        // Clobber the whole batch the way the next `recvmsg` reuses its buffer.
        // An owned chunk is unaffected; a stored slice would now be garbage.
        batch.fill(0xFF);

        let second = vec![0xCDu8; 20];
        let f1 = FragmentRef {
            sess: 1,
            id: 9,
            idx: 1,
            total,
            address: aref,
            chunk: &second,
        };
        let (_, _, whole) = r.push(&f1, 1_000).expect("pair completes");
        assert_held_exact(&r);
        let mut want = want_first.clone();
        want.extend_from_slice(&second);
        assert_eq!(
            &whole[..],
            &want[..],
            "the stored chunk must be an owned copy, not a slice of the batch"
        );
        assert_eq!(
            r.held_bytes(),
            Tombstone::retained_for(total),
            "completion must file fingerprints only: the delivered payload's \
             bytes are no longer retained by the id-reuse guard"
        );
        assert!(
            r.held_bytes() < 40 + Partial::slot_table_bytes(total),
            "a tombstone must cost less than the chunks it replaces"
        );
    }

    /// The tombstone's whole point is that a *completed* generation stays
    /// refused for its window without pinning the payload again. The old shape
    /// charged the delivered bytes to the reassembly budget a second time, so a
    /// burst of completed payloads filled the 256 KiB cap with tombstones and
    /// the guard started evicting live partials (and stopped refusing replays
    /// once the tombstones were gone).
    #[test]
    fn completed_payloads_do_not_refill_the_reassembly_budget() {
        let addr = v4();
        let aref = addr.as_ref();
        let payload = pattern(7800);
        let chunks: Vec<&[u8]> = payload.chunks(1300).collect();
        assert_eq!(chunks.len(), 6);
        let total = chunks.len() as u8;

        let mut r = DgramReassembler::new();
        // Twenty completed 7.8 KiB generations: ~156 KiB of payload passed
        // through, and twenty tombstones must remain — at `total x 24 B` each,
        // 2.9 KiB in all, where the old representation charged ~156 KiB and
        // would have been evicting live partials within four more payloads.
        for id in 0..20u32 {
            let mut done = false;
            for (i, c) in chunks.iter().enumerate() {
                let body = encode_fragment(3, id, i as u8, total, &aref, c, 64 * 1024).unwrap();
                let f = decode_fragment(&body).unwrap();
                done = r.push(&f, 4_000).is_some();
            }
            assert!(done, "generation {id} must complete");
        }
        assert_held_exact(&r);
        assert_eq!(
            r.held_bytes(),
            20 * Tombstone::retained_for(total),
            "twenty retired generations must cost their fingerprint tables only"
        );
        assert!(
            r.held_bytes() < 4 * 1024,
            "the guard must not retain payload bytes (held={})",
            r.held_bytes()
        );
        // ...and the guard still refuses a replay of a delivered generation.
        let body = encode_fragment(3, 19, 0, total, &aref, chunks[0], 64 * 1024).unwrap();
        let f = decode_fragment(&body).unwrap();
        assert!(
            r.is_stale_replay(&f, 4_000),
            "a completed generation must stay refused inside the window"
        );
    }

    /// Both order queues must name every live entry with its current timestamp
    /// stamp: the eviction order is derived from them, so a lost slot would
    /// silently downgrade to "nothing to evict", and a wrong stamp would evict
    /// the wrong generation.
    fn assert_order_covers_maps(r: &DgramReassembler) {
        for (key, p) in &r.parts {
            assert!(
                r.part_order
                    .iter()
                    .any(|&(k, first_ms)| k == *key && first_ms == p.first_ms),
                "live partial {key:?} missing from part_order"
            );
        }
        for (key, t) in &r.recent {
            assert!(
                r.tomb_order
                    .iter()
                    .any(|&(k, at_ms)| k == *key && at_ms == t.at_ms),
                "live tombstone {key:?} missing from tomb_order"
            );
        }
    }

    /// FIFO eviction lock-in: the tombstone count cap (saturated at any real
    /// fragmented rate) must reclaim the *oldest* generation, and the expiry
    /// sweep must prune the order queue, not just the map — a tombstone's slot
    /// is never popped by the map `retain`, so a leak there would grow the
    /// queue for the connection's lifetime.
    #[test]
    fn tombstone_eviction_is_insertion_order_and_queues_are_pruned() {
        let addr = v4();
        let aref = addr.as_ref();
        let mut r = DgramReassembler::new();
        const GEN: u32 = FRAG_MAX_PARTIALS as u32 + 44;
        // One completed 2-fragment generation per id, each with a distinct tick
        // so insertion order is unambiguous.
        for id in 0..GEN {
            let now = 1_000 + u64::from(id);
            for (i, c) in [&[1u8; 4][..], &[2u8; 4][..]].iter().enumerate() {
                let body = encode_fragment(5, id, i as u8, 2, &aref, c, 64 * 1024).unwrap();
                let f = decode_fragment(&body).unwrap();
                let done = r.push(&f, now).is_some();
                assert_eq!(
                    done,
                    i == 1,
                    "generation {id} completes on its last fragment"
                );
            }
        }
        assert_order_covers_maps(&r);
        assert_eq!(
            r.recent.len(),
            FRAG_MAX_PARTIALS,
            "the count cap keeps exactly FRAG_MAX_PARTIALS tombstones"
        );
        let oldest_kept = GEN - FRAG_MAX_PARTIALS as u32;
        for id in 0..GEN {
            let kept = r.recent.contains_key(&(5, id));
            assert_eq!(
                kept,
                id >= oldest_kept,
                "tombstone {id}: eviction must be oldest-first"
            );
        }
        assert!(
            r.tomb_order.len() <= FRAG_MAX_PARTIALS + 64,
            "the order queue must not grow past the live set: {} slots",
            r.tomb_order.len()
        );
        // Expiry empties the map *and* prunes the queue.
        r.expire(1_000 + u64::from(GEN) + FRAG_TIMEOUT_MS);
        assert_held_exact(&r);
        assert!(r.recent.is_empty(), "all tombstones age out together");
        assert!(
            r.tomb_order.is_empty(),
            "expiry must prune the stale order slots, not just the map"
        );
        assert_eq!(r.held_bytes(), 0);
    }

    /// FIFO eviction lock-in for partials: the byte cap must reclaim the oldest
    /// live partial (never a newer one), and the part-order queue must be
    /// bounded and prunable. A completion leaves a stale queue slot behind, so
    /// this also pins the lazy-invalidation path the eviction loop relies on.
    #[test]
    fn partial_eviction_is_insertion_order_and_queues_are_pruned() {
        let addr = v4();
        let aref = addr.as_ref();
        let mut r = DgramReassembler::new();
        // One 1400 B chunk each: the 256 KiB byte cap binds long before the
        // 256-partial count cap.
        const N: u32 = 300;
        for id in 0..N {
            let now = 2_000 + u64::from(id);
            let body =
                encode_fragment(9, 1_000 + id, 0, 2, &aref, &[0x5Au8; 1400], 64 * 1024).unwrap();
            let f = decode_fragment(&body).unwrap();
            assert!(r.push(&f, now).is_none());
            assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
        }
        assert_order_covers_maps(&r);
        let min_kept = r
            .parts
            .keys()
            .map(|(_, id)| *id)
            .min()
            .expect("live partials");
        assert!(
            r.inflight() < N as usize,
            "the byte cap evicted live partials"
        );
        assert_eq!(
            min_kept,
            1_000 + N - r.inflight() as u32,
            "insertion order must be preserved: the newest suffix is kept"
        );
        for id in 1_000..(1_000 + N) {
            assert_eq!(
                r.parts.contains_key(&(9, id)),
                id >= min_kept,
                "partial {id}: eviction must be oldest-first"
            );
        }
        // Expiry releases the partials and prunes the order queue.
        r.expire(2_000 + u64::from(N) + FRAG_TIMEOUT_MS);
        assert_held_exact(&r);
        assert!(r.parts.is_empty());
        assert!(
            r.part_order.is_empty(),
            "expiry must prune the stale order slots, not just the map"
        );
        assert_eq!(r.held_bytes(), 0);
    }
}
