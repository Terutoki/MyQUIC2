//! DNS verdict stores, backed by `moka::future::Cache`.
//!
//! Two caches, deliberately separate namespaces:
//!
//! - **positive**: `(inserted at, address set)` with a 120 s lifetime. Moka
//!   owns capacity bounding and eviction; the stored `Instant` is the authority
//!   for the remaining life a caller clamps its own deadlines against (moka
//!   exposes no remaining-TTL query).
//! - **negative**: verdict-only entries with a 10 s lifetime. A failed lookup
//!   must never be expressible in the positive keyspace: `try_get_with` treats
//!   any present value as the cached answer, so a negative sentinel stored
//!   there would be served as a resolution result forever (it would never
//!   re-resolve). Two caches keep the refusal check a plain `get` and make
//!   "resolution failed" and "resolution succeeded" writes disjoint.
//!
//! Both caches use `foldhash::fast::RandomState` (the crate-wide choice for
//! short, peer-influenced keys — see Cargo.toml): a per-instance random seed,
//! ~1-2 ns per short-key hash.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;

/// Owned cache key: `host` + NUL + decimal port, normalized by `dns::key`.
pub(crate) type DnsCacheKey = String;

/// `(inserted at, address set)`: the `Arc<[SocketAddr]>` makes a cache hit and
/// every single-flight waiter clone a refcount instead of the vector, and the
/// insertion instant keeps the TTL-exposing lookups honest (moka has no
/// per-entry remaining-life API).
pub(crate) type DnsCacheVal = (Instant, Arc<[SocketAddr]>);

/// Positive DNS cache TTL, in milliseconds. The `Duration` below is derived
/// from it so the two can never drift, and callers that arm their own deadline
/// from a cache hit clamp against the entry's *remaining* life measured with
/// these units.
///
/// 120 s is a deliberate middle ground: it halves the upstream query rate of
/// the 60 s it replaced, while keeping the stale-answer window in the same
/// order as common resolver/TTL floors (a name that moves is followed within
/// two minutes). The layers above (per-thread memo, session destination memo,
/// 30 s pin) all clamp to an entry's remaining life, so this value bounds the
/// worst-case staleness end to end.
pub const DNS_CACHE_TTL_MS: u64 = 120_000;
pub(crate) const DNS_CACHE_TTL: Duration = Duration::from_millis(DNS_CACHE_TTL_MS);
pub(crate) const DNS_NEG_TTL: Duration = Duration::from_secs(10);
/// Capacity bounds. Moka's TinyLFU admission + LRU eviction replace the old
/// per-shard batch eviction, and a failing-domain flood cannot evict
/// positives (separate cache). The positive bound was raised with the TTL —
/// entries live twice as long, so the resident working set roughly doubles —
/// while the negative cache keeps its smaller budget, which fits its 10 s
/// entries.
pub(crate) const DNS_CACHE_MAX: usize = 10_240;
pub(crate) const DNS_NEG_MAX: usize = 4096;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

type DnsHasher = foldhash::fast::RandomState;
pub(crate) type PosCache = Cache<DnsCacheKey, DnsCacheVal, DnsHasher>;
pub(crate) type NegCache = Cache<DnsCacheKey, (), DnsHasher>;

pub(crate) fn positives() -> &'static PosCache {
    static CACHES: std::sync::OnceLock<PosCache> = std::sync::OnceLock::new();
    CACHES.get_or_init(|| {
        Cache::builder()
            .name("dns-pos")
            .max_capacity(DNS_CACHE_MAX as u64)
            .time_to_live(DNS_CACHE_TTL)
            .build_with_hasher(DnsHasher::default())
    })
}

pub(crate) fn negatives() -> &'static NegCache {
    static CACHES: std::sync::OnceLock<NegCache> = std::sync::OnceLock::new();
    CACHES.get_or_init(|| {
        Cache::builder()
            .name("dns-neg")
            .max_capacity(DNS_NEG_MAX as u64)
            .time_to_live(DNS_NEG_TTL)
            .build_with_hasher(DnsHasher::default())
    })
}
