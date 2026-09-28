//! DNS positive/negative cache tables — extracted verbatim from `src/lib.rs`
//! (zero-logic-change split). Source lines: dns_caches/dns_cache_for/
//! DNS_CACHE_TTL_MS/DNS_CACHE_TTL/DNS_NEG_TTL/DNS_NEG_MAX/DNS_LOOKUP_TIMEOUT/
//! dns_neg_caches/dns_neg_cache_for. `lib.rs` untouched.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::key::{dns_shard, DnsCacheKey, DnsCacheVal, DNS_SHARDS};

fn dns_caches() -> &'static [std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>; DNS_SHARDS] {
    static CACHES: std::sync::OnceLock<
        [std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>; DNS_SHARDS],
    > = std::sync::OnceLock::new();
    CACHES.get_or_init(|| std::array::from_fn(|_| std::sync::RwLock::new(HashMap::new())))
}

pub(crate) fn dns_cache_for(
    key: &str,
) -> &'static std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>> {
    &dns_caches()[dns_shard(key)]
}

/// Positive DNS cache TTL, in milliseconds. The `Duration` below is derived from
/// it so the two can never drift, and callers that arm their own deadline from a
/// cache hit clamp against the entry's *remaining* life measured in these units.
pub const DNS_CACHE_TTL_MS: u64 = 60_000;
pub(crate) const DNS_CACHE_TTL: Duration = Duration::from_millis(DNS_CACHE_TTL_MS);
pub(crate) const DNS_NEG_TTL: Duration = Duration::from_secs(10);
/// Soft cap for the negative cache; past this the table is reaped instead of
/// growing without bound under a failing-domain flood.
pub(crate) const DNS_NEG_MAX: usize = 4096;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn dns_neg_caches() -> &'static [std::sync::RwLock<HashMap<DnsCacheKey, Instant>>; DNS_SHARDS] {
    static NEGS: std::sync::OnceLock<
        [std::sync::RwLock<HashMap<DnsCacheKey, Instant>>; DNS_SHARDS],
    > = std::sync::OnceLock::new();
    NEGS.get_or_init(|| std::array::from_fn(|_| std::sync::RwLock::new(HashMap::new())))
}

pub(crate) fn dns_neg_cache_for(
    key: &str,
) -> &'static std::sync::RwLock<HashMap<DnsCacheKey, Instant>> {
    &dns_neg_caches()[dns_shard(key)]
}
