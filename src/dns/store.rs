//! DNS verdict stores, backed by `moka::future::Cache`.
//!
//! Two caches, deliberately separate namespaces:
//!
//! - **positive**: `(inserted at, address set)` with a 120 s *freshness* life
//!   inside a longer (`+ DNS_STALE_WINDOW`) resident life. Moka owns capacity
//!   bounding and eviction; the stored `Instant` is the authority both for the
//!   remaining life a caller clamps its own deadlines against (moka exposes no
//!   remaining-TTL query) and for telling a fresh entry from a stale one: an
//!   entry past `inserted + DNS_CACHE_TTL` is stale, is still served (RFC 8767,
//!   see [`DNS_STALE_WINDOW`]), and must be paired with a background refresh
//!   ([`DNS_STALE_MEMO_TTL`] explains why the sync memo is let through again
//!   while that happens).
//! - **negative**: verdict-only entries with a 10 s lifetime. A failed lookup
//!   must never be expressible in the positive keyspace: `try_get_with` treats
//!   any present value as the cached answer, so a negative sentinel stored
//!   there would be served as a resolution result forever (it would never
//!   re-resolve). Two caches keep the refusal check a plain `get` and make
//!   "resolution failed" and "resolution succeeded" writes disjoint. The entry
//!   records its own **expiry** instant, so a lookup that did not learn a
//!   verdict — a timeout, a saturated fallback, an unreachable name server —
//!   can be refused for a much shorter `retry backoff`
//!   ([`DNS_INCONCLUSIVE_TTL`]) than a name the resolver actually answered for.
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
/// two minutes while the background refresh can reach upstream). The layers
/// above (per-thread memo, session destination memo, 30 s pin) all clamp to an
/// entry's remaining life, so this value bounds the worst-case staleness end to
/// end; `DNS_STALE_WINDOW` is what covers the case where the refresh cannot be
/// made at all.
pub const DNS_CACHE_TTL_MS: u64 = 120_000;
pub(crate) const DNS_CACHE_TTL: Duration = Duration::from_millis(DNS_CACHE_TTL_MS);

/// How long past its freshness deadline a positive entry may still answer.
///
/// The model is RFC 8767's serve-stale: an expired record is a far better
/// answer than a failed connection, and the refresh that every stale hit
/// schedules usually repairs the entry within one query RTT. The window only
/// becomes visible when that refresh cannot be made at all — upstream down,
/// permits exhausted, the resolver hung — which is exactly the case where the
/// old behaviour handed the caller an error and the client a failed dial.
///
/// It also bounds the worst case of a *changed* record: a stale answer is
/// served at most this long, and only while every refresh attempt keeps
/// failing. The layers above (per-thread memo, session destination memo, 30 s
/// pin) still clamp to the entry's own deadline, so they cannot extend it.
pub(crate) const DNS_STALE_WINDOW: Duration = Duration::from_secs(3_600);

/// How long a **stale** answer is memoized in the packet path's per-thread memo.
///
/// Short on purpose. The memo is what lets the sync probe answer without the
/// async path, but the async path is the only code that can schedule a refresh
/// (the sync path cannot spawn tasks). A stale memo life of a whole stale window
/// would hide the staleness from the one place that repairs it, so the packet
/// path is let through to the async path once a second; that path re-serves the
/// same stale answer from a moka hit (nanoseconds) while the refresh it already
/// started completes.
pub(crate) const DNS_STALE_MEMO_TTL: Duration = Duration::from_secs(1);

/// How long a negative entry that *is* a verdict is kept: the resolver
/// answered that the name does not resolve (NXDOMAIN/NODATA, or the blocking
/// fallback's own "name or service not known"). Refusing the name for this
/// long is the point — it is a fact about the name, not about our health, and
/// it is what stops a dead name from spawning a resolver task per datagram.
pub(crate) const DNS_NEG_TTL: Duration = Duration::from_secs(10);

/// How long a lookup that produced **no answer** is kept: the outer
/// [`DNS_LOOKUP_TIMEOUT`] expired, the blocking fallback had no permit, or the
/// resolver reported a transport/protocol failure. Nothing was learned about
/// the name, so it must not be refused for [`DNS_NEG_TTL`] — a name that
/// resolves fine would then stay broken on every port for 10 s after a
/// transient blip (a Wi-Fi roam, a name server restart, a paused laptop). It is
/// still recorded, briefly, for one reason: the negative entry is what bounds
/// the *rate* at which the datagram path spawns resolver tasks (the slow-path
/// limiter bounds concurrency, not rate), so dropping the entry entirely would
/// trade a 10 s false refusal for one resolver task per datagram during an
/// outage. 1 s is a retry backoff, not a verdict.
pub(crate) const DNS_INCONCLUSIVE_TTL: Duration = Duration::from_millis(1_000);
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
///
/// This is the budget for the *whole* lookup, retries included: it wraps the
/// hickory future ([`super::resolve::resolve_ips`]), so it is the only wall the
/// caller can rely on. The per-attempt timeout below has to be derived from it,
/// not set independently — see `DNS_QUERY_TIMEOUT`.
pub const DNS_LOOKUP_TIMEOUT_MS: u64 = 5_000;
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_millis(DNS_LOOKUP_TIMEOUT_MS);

/// Budget for **one** upstream query attempt, and how many extra attempts
/// hickory may make inside [`DNS_LOOKUP_TIMEOUT`].
///
/// hickory's own defaults are `timeout = 5 s` with `attempts = 2`, i.e. the
/// same wall as ours: the first attempt was allowed to consume the entire
/// budget, so the retry the resolver had been configured to make could never
/// run. A single lost UDP datagram then cost the full 5 s, and a name server
/// that would have answered the second try never got one.
///
/// 1.5 s per attempt fits three attempts (1 + `DNS_LOOKUP_ATTEMPTS`) inside the
/// 5 s wall with room to spare: a dropped query recovers at ~1.5 s, and a
/// resolver that is entirely unreachable still fails inside the same wall as
/// before. The `assert!` below is the invariant; `configure_resolver_options`
/// is the single place that installs both values.
pub(crate) const DNS_QUERY_TIMEOUT_MS: u64 = 1_500;
pub(crate) const DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(DNS_QUERY_TIMEOUT_MS);
pub(crate) const DNS_LOOKUP_ATTEMPTS: usize = 2;

/// The attempt budget must leave room for the retries, or the retries are dead
/// code (the state this constant pair replaced).
const _: () = assert!(
    DNS_QUERY_TIMEOUT_MS * (DNS_LOOKUP_ATTEMPTS as u64 + 1) < DNS_LOOKUP_TIMEOUT_MS,
    "one query attempt times (1 + retries) must fit inside DNS_LOOKUP_TIMEOUT"
);

type DnsHasher = foldhash::fast::RandomState;
/// Successful resolutions. The value's `Instant` is the **insertion** instant,
/// so freshness is `inserted + DNS_CACHE_TTL`; the cache's own TTL is that plus
/// [`DNS_STALE_WINDOW`], i.e. it only evicts answers that cannot be served
/// stale any more. Serving a stale entry is paired with a refresh by
/// `resolve::resolve_all_cached`, which is what keeps the window from being the
/// normal case.
pub(crate) type PosCache = Cache<DnsCacheKey, DnsCacheVal, DnsHasher>;
/// Negative verdicts. The value is the instant the refusal **expires** (not the
/// instant it was recorded): a resolver that finds a host-keyed verdict while
/// asking about a *different* port must memoize that port with the verdict's
/// **remaining** life, so the sync packet path refuses it without spawning a
/// resolver task per datagram, while the memo can never outlive the shared
/// entry it was derived from. Storing the deadline rather than the recording
/// instant is what lets one name carry two lifetimes — a 10 s verdict versus a
/// 1 s "we did not learn anything" backoff ([`DNS_INCONCLUSIVE_TTL`]) — in the
/// same cache, whose own 10 s moka TTL is only an eviction bound above them.
pub(crate) type NegCache = Cache<DnsCacheKey, Instant, DnsHasher>;

pub(crate) fn positives() -> &'static PosCache {
    static CACHES: std::sync::OnceLock<PosCache> = std::sync::OnceLock::new();
    CACHES.get_or_init(|| {
        Cache::builder()
            .name("dns-pos")
            .max_capacity(DNS_CACHE_MAX as u64)
            .time_to_live(DNS_CACHE_TTL + DNS_STALE_WINDOW)
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
