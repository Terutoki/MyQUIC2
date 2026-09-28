pub mod cache;
pub mod inflight;
pub mod key;
pub mod memo;
pub mod policy;
pub mod resolve;

pub(crate) use cache::{dns_cache_for, dns_neg_cache_for, DNS_NEG_MAX};
pub use cache::{DNS_CACHE_TTL_MS, DNS_LOOKUP_TIMEOUT};
pub(crate) use inflight::dns_inflight_for;
pub use inflight::{dns_inflight_status, dns_is_inflight, dns_slow_path_limiter, DnsInflight};
pub(crate) use key::{dns_key, dns_key_owned, dns_shard, DNS_KEY_BUF, DNS_SHARDS};
pub(crate) use memo::{
    dns_memo_hash, dns_memo_set, memo_peek_both, memo_put, DnsMemoSlot, DNS_MEMO, MEMO_KEY_BYTES,
    MEMO_SETS, MEMO_WAYS,
};
pub use policy::{is_global_ip, map_for_dual, unmap};
pub use resolve::{
    dns_cache_seed, dns_cache_seed_aged, dns_cache_seed_set, dns_neg_cache_seed, is_dns_contended,
    lookup_cached_all_fast, lookup_cached_all_fast_with_ttl, lookup_cached_fast,
    lookup_cached_fast_with_ttl, lookup_cached_sync, resolve_all, resolve_all_cached,
    resolve_all_cached_with_contention_retry, resolve_server_addr, resolve_server_side,
    CachedLookup, DnsContended,
};
pub(crate) use resolve::{
    positive_entry_state, record_negative, PositiveState, DNS_CACHE_MAX, DNS_CACHE_MAX_SHARD,
    DNS_NEG_MAX_SHARD,
};
