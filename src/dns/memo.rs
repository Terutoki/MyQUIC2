//! DNS thread-local memo — verbatim extraction from `src/lib.rs` (zero logic change).
//! Symbols: DnsMemoSlot / MEMO_* / NEG_EPOCH / neg_epoch / bump_neg_epoch /
//! dns_memo_hash / dns_memo_set / MemoHit / memo_peek_both / memo_put (+ DNS_MEMO,
//! coarse_deadline as memo-internal helpers).
use std::net::SocketAddr;
use std::time::Instant;

use crate::coarse_millis;

/// Thread-local memo of the most recent lookups, keyed by the *full* normalized
/// key. A 64-bit hash here would let two different `(host, port)` pairs collide
/// and serve each other's address for the whole TTL, so the hash is only ever a
/// filter: a slot matches only when the stored key bytes compare equal too.
///
/// Two-way set-associative over 64 sets (128 slots), replacing a single
/// 32-slot direct-mapped table. The old shape was fine for one hot target but
/// degraded exactly when the proxy is busiest: a worker thread serving N
/// distinct domains misses on roughly `1 - 32/N` of lookups, so 32 concurrent
/// domains already cost ~31 % penetration into the shared cache and 128 cost
/// ~76 % (measured, 10 threads). Conflict misses dominate a direct-mapped
/// table this small; two ways removes them, and the measured penetration at 32
/// and 64 domains per thread drops to 0 % and ~5 %, for 6.8 ns/op versus
/// 15.5 ns/op at 32 domains and 8.1 ns versus 25.8 ns at 64.
///
/// Keys are stored as a hash plus up to 64 inline bytes, so the table stays
/// small enough to afford 128 slots. A key longer than 64 bytes simply never
/// populates the memo and takes the shared-cache path every time: that is a
/// miss, never a mis-serve. Domain names are capped at 255 bytes on the wire,
/// so this deliberately trades a rare slow path for a smaller slot.
#[derive(Clone, Copy)]
pub(crate) struct DnsMemoSlot {
    hash: u64,
    empty: bool,
    /// `None` = negatively cached (NXDOMAIN / lookup failure).
    addr: Option<SocketAddr>,
    len: u8,
    key: [u8; MEMO_KEY_BYTES],
    /// Same deadline expressed in the [`coarse_millis`] epoch, so the per-packet
    /// hit path compares two atomics instead of reading the clock.
    ///
    /// **Error bound, stated the right way round.** Both the deadline and the
    /// check sample the same lagging clock, so what remains is the *difference*
    /// between the lag at insert and the lag at check (each at most one tick) —
    /// not "one tick early" as an earlier revision of this comment claimed. An
    /// entry can therefore be served up to about one tick (~1 s) past its true
    /// TTL. The key is still compared in full, so this is never a mis-serve of
    /// another name's address; at worst a 60 s DNS answer is reused for one
    /// extra second.
    expires_ms: u64,
    /// [`NEG_EPOCH`] when this slot was written, for negative entries only (0
    /// for a positive). A negative memo is private to the thread that recorded
    /// the failure, so a *successful* resolution on another worker — which
    /// clears the global negative entry and writes a positive elsewhere — could
    /// not reach it: the recording worker kept refusing a name that resolved
    /// again for the rest of `DNS_NEG_TTL` (10 s). The tag makes the memo obey
    /// the same rule the global cache does — a *lookup* hit on a negative entry
    /// is honoured only while its epoch is current, so any "this name resolves
    /// now" mutation invalidates every thread's stale negative at once for one
    /// relaxed load, on the negative path only.
    neg_epoch: u64,
}

/// Keys longer than this are not memoized (see [`DnsMemoSlot`]).
pub(crate) const MEMO_KEY_BYTES: usize = 64;
pub(crate) const MEMO_SETS: usize = 64;
pub(crate) const MEMO_WAYS: usize = 2;

/// Epoch of the process-wide negative DNS cache's *good* verdicts.
///
/// Bumped whenever a name's negative entry is removed because it resolved again
/// (or a seeding helper rewrote it). A thread-local negative memo is only
/// trusted while the epoch it was written at is still current — see
/// [`DnsMemoSlot::neg_epoch`]. One relaxed load on the negative-hit path, and
/// the bump itself only on the rare "resolution succeeded after a failure" path.
static NEG_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Current [`NEG_EPOCH`].
#[inline]
pub(crate) fn neg_epoch() -> u64 {
    NEG_EPOCH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Record that some name's negative entry was dropped because it resolves now.
#[inline]
pub(crate) fn bump_neg_epoch() {
    NEG_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

impl DnsMemoSlot {
    pub(crate) const EMPTY: Self = Self {
        hash: 0,
        empty: true,
        addr: None,
        len: 0,
        key: [0; MEMO_KEY_BYTES],
        expires_ms: 0,
        neg_epoch: 0,
    };

    /// A slot for `key`, or `None` when it is too long to store inline.
    fn new(key: &str, hash: u64, addr: Option<SocketAddr>, expires: Instant) -> Option<Self> {
        if key.len() > MEMO_KEY_BYTES {
            return None;
        }
        let mut s = Self::EMPTY;
        s.empty = false;
        s.hash = hash;
        s.addr = addr;
        s.len = key.len() as u8;
        s.key[..key.len()].copy_from_slice(key.as_bytes());
        s.expires_ms = coarse_deadline(expires);
        // Only a negative slot needs the tag: a positive hit is never
        // invalidated by the epoch (its own deadline bounds it).
        s.neg_epoch = if addr.is_none() { neg_epoch() } else { 0 };
        Some(s)
    }

    /// Full-key compare. The hash is only a filter: two different keys that
    /// collide on it must still not match, or one domain would serve another
    /// domain's address for the whole TTL.
    #[inline]
    fn matches(&self, hash: u64, key: &str) -> bool {
        !self.empty
            && self.hash == hash
            && self.len as usize == key.len()
            && &self.key[..self.len as usize] == key.as_bytes()
    }
}

thread_local! {
    pub(crate) static DNS_MEMO: std::cell::RefCell<[[DnsMemoSlot; MEMO_WAYS]; MEMO_SETS]> =
        const { std::cell::RefCell::new([[DnsMemoSlot::EMPTY; MEMO_WAYS]; MEMO_SETS]) };
}

/// Multiply-fold plus a finalizer. The finalizer matters here in a way it did
/// not for the old direct-mapped table: the set index comes from the low bits
/// of the result, and DNS names share long suffixes (`…example.com`, `…cdn.net`),
/// so the raw fold leaves those bits correlated between unrelated names and
/// would pile them into the same set — the exact conflict the associativity is
/// meant to remove. ~4 ns per lookup, paid once per packet.
#[inline]
pub(crate) fn dns_memo_hash(key: &str) -> u64 {
    const K: u64 = 0x9e3779b97f4a7c15;
    let mut h: u64 = 0;
    for b in key.as_bytes() {
        h = h.wrapping_mul(K).wrapping_add(*b as u64);
    }
    h ^= h >> 29;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^ (h >> 32)
}

/// Set index. `MEMO_SETS` is a power of two, so this is a mask, and the low
/// bits of a finalized hash are well mixed.
#[inline]
pub(crate) fn dns_memo_set(hash: u64) -> usize {
    (hash as usize) & (MEMO_SETS - 1)
}

/// A matching memo slot, copied out so the borrow of the thread-local ends with
/// the call.
#[derive(Clone, Copy)]
pub(crate) struct MemoHit {
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) expires_ms: u64,
    /// See [`DnsMemoSlot::neg_epoch`]; 0 for a positive hit.
    pub(crate) neg_epoch: u64,
}

/// Probe both ways of our key's set, returning the positive and negative hits
/// separately. Deliberately does *not* read the clock: the caller reads it once,
/// and only after a key match, so a memo miss is never charged a
/// `clock_gettime` — the whole point of the memo is that a hit is cheaper than
/// the global cache lookup, and a miss must not cost more than one.
pub(crate) fn memo_peek_both(key: &str) -> (Option<MemoHit>, Option<MemoHit>) {
    let hash = dns_memo_hash(key);
    let set = dns_memo_set(hash);
    DNS_MEMO.with(|c| {
        let c = c.borrow();
        for s in c[set].iter() {
            if s.matches(hash, key) {
                let hit = MemoHit {
                    addr: s.addr,
                    expires_ms: s.expires_ms,
                    neg_epoch: s.neg_epoch,
                };
                return if s.addr.is_none() {
                    (None, Some(hit))
                } else {
                    (Some(hit), None)
                };
            }
        }
        (None, None)
    })
}

/// Insert into the set, promoting to way 0 and demoting the previous way 0.
/// A write is two `Copy`s of an inline struct: no allocation and no key
/// `String`, which is why the slot stores key bytes rather than a `Box<str>`.
pub(crate) fn memo_put(key: &str, addr: Option<SocketAddr>, expires: Instant) {
    let hash = dns_memo_hash(key);
    let set = dns_memo_set(hash);
    let Some(slot) = DnsMemoSlot::new(key, hash, addr, expires) else {
        return; // too long for an inline slot: stays a cache-path-only name
    };
    DNS_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        let ways = &mut c[set];
        if ways[0].matches(hash, key) {
            // Same key already newest: overwrite in place (its address or TTL
            // may have changed) without disturbing way 1.
            ways[0] = slot;
        } else if ways[1].matches(hash, key) {
            // Resident in way 1: promote it and drop the old way 0, so one key
            // can never occupy both ways of the set.
            ways[1] = ways[0];
            ways[0] = slot;
        } else {
            // New key: demote the current occupant of way 0.
            ways[1] = ways[0];
            ways[0] = slot;
        }
    });
}

/// Translate an `Instant` deadline into the [`coarse_millis`] epoch.
/// Paid once per memo insert (the miss path, which already holds locks); the
/// per-packet hit path then compares without any clock read.
///
/// The translation deliberately anchors on the coarse sample rather than the
/// precise remainder alone, so the residual error is the *change* in the
/// clock's lag between here and the check — bounded by one tick in either
/// direction (see [`DnsMemoSlot::expires_ms`]), not the "early only" this used
/// to claim.
fn coarse_deadline(expires: Instant) -> u64 {
    let remain_ms = expires
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    coarse_millis().saturating_add(remain_ms)
}
