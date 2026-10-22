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
//! Both caches are keyed by the **normalized host only** (`dns::key`'s
//! [`dns_host_key`](super::key::dns_host_key)), never by `(host, port)`: A/AAAA
//! answers carry no port, so every port of one name must share the same entry
//! *and* the same `try_get_with` single-flight init. Keying by port meant a new
//! port of an already-resolved name missed both and paid a fresh upstream
//! query, and — for the negative cache — that a dead name had to be learned
//! once per port, each learning holding a `dns_slow_path_limiter` permit for
//! the lookup timeout. The caller's port is attached to the cached IPs when
//! `resolve_all_cached` returns the set.
//!
//! Both caches use `foldhash::fast::RandomState` (the crate-wide choice for
//! short, peer-influenced keys — see Cargo.toml): a per-instance random seed,
//! ~1-2 ns per short-key hash.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;

/// Owned cache key: the normalized host, no port — see the module docs.
pub(crate) type DnsCacheKey = String;

/// `(inserted at, address set)`: the `Arc<[IpAddr]>` makes a cache hit and
/// every single-flight waiter clone a refcount instead of the vector, and the
/// insertion instant keeps the TTL-exposing lookups honest (moka has no
/// per-entry remaining-life API). The addresses are **port-free** on purpose;
/// `resolve_all_cached` materializes `SocketAddr`s with the caller's port.
pub(crate) type DnsCacheVal = (Instant, Arc<[IpAddr]>);

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
/// entries. Host-only keys make each entry span every port of its name, so the
/// same capacities cover strictly more traffic than the per-port keys they
/// replaced.
///
/// These capacities are **entry** counts; the retained bytes per positive
/// entry are bounded separately by [`DNS_CACHE_MAX_ADDRS`], so `DNS_CACHE_MAX ×
/// (normalized name + 32 addresses)` is the cache's worst-case footprint. (A
/// byte-weighted moka `weigher` would express the same bound directly; the cap
/// is cheaper and keeps the "first N records" semantics callers already rely
/// on.)
pub(crate) const DNS_CACHE_MAX: usize = 10_240;
pub(crate) const DNS_NEG_MAX: usize = 4096;

/// Maximum addresses retained per positive-cache entry.
///
/// A DNS answer's size is not bounded by the query: an authoritative server can
/// return thousands of A/AAAA records (a truncated UDP answer is retried over
/// TCP, where a DNS message is length-prefixed by a `u16`), and the positive
/// cache above is bounded in **entries** (`DNS_CACHE_MAX`), not bytes. Retaining
/// the whole answer would let a peer that controls a domain pin hundreds of MiB
/// inside a 10,240-entry cache — far outside the DNS admission term
/// (`config::tuning::dns_inflight_memory_bytes`, which prices resolver waiters,
/// not cache values). The cached set is therefore the first
/// [`DNS_CACHE_MAX_ADDRS`] records in the caller's order; the init path has
/// already sorted the answer preferred-family-first, so the order semantics
/// every consumer sees are unchanged.
///
/// 32 is far more than any consumer uses: a rev2 flow retains at most
/// `R2_MAX_RESOLVED_ADDRS` (16), the server's TCP happy-eyeballs list at most 8,
/// and every UDP datagram uses the first address. A name that legitimately
/// answers with more records still gets enough of them for dual-stack and
/// multi-homed rotation; the dropped tail only bounds memory, never a lookup's
/// ability to find *a* usable address for a real service.
pub(crate) const DNS_CACHE_MAX_ADDRS: usize = 32;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

type DnsHasher = foldhash::fast::RandomState;
pub(crate) type PosCache = Cache<DnsCacheKey, DnsCacheVal, DnsHasher>;
/// Negative verdicts. The value is the instant the failure was recorded, not
/// `()`: a resolver that finds a host-keyed verdict while asking about a
/// *different* port must memoize that port with the verdict's **remaining**
/// life, so the sync packet path refuses it without spawning a resolver task
/// per datagram, while the memo can never outlive the shared entry it was
/// derived from.
pub(crate) type NegCache = Cache<DnsCacheKey, Instant, DnsHasher>;

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
