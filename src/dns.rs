//! Server-side DNS: moka-backed verdict caches, single-flight resolution,
//! thread-local memos, and the egress policy filter.
pub mod key;
pub mod memo;
pub mod policy;
pub mod resolve;
pub mod store;

pub(crate) use key::{DNS_KEY_BUF, dns_key, dns_key_owned};
pub(crate) use memo::{
    DNS_MEMO, DnsMemoSlot, MEMO_KEY_BYTES, MEMO_SETS, MEMO_WAYS, bump_neg_epoch, dns_memo_hash,
    dns_memo_set, memo_peek_both, memo_put, neg_epoch,
};
pub use policy::{is_global_ip, map_for_dual, unmap};
pub use resolve::{
    CachedLookup, IpPreference, dns_cache_seed, dns_cache_seed_aged, dns_cache_seed_set,
    dns_neg_cache_seed, dns_slow_path_limiter, ip_preference, lookup_cached_fast,
    lookup_cached_fast_with_ttl, lookup_cached_sync, resolve_all, resolve_all_cached,
    resolve_server_addr, resolve_server_side, set_ip_preference,
};
pub(crate) use store::{DNS_CACHE_MAX, DNS_NEG_MAX, DNS_NEG_TTL, negatives, positives};
pub use store::{DNS_CACHE_TTL_MS, DNS_LOOKUP_TIMEOUT};
