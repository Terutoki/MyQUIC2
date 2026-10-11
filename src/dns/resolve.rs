//! DNS resolve / cache lookup, on top of the moka-backed verdict stores
//! (`dns::store`) and the thread-local memo (`dns::memo`).
//!
//! Layering:
//!
//! - **sync fast path** ([`lookup_cached_fast`]): thread-local memo only. The
//!   packet path (server egress `resolve_pin`/`forward_server_dgram`, client
//!   `dispatch_stage*`) is synchronous in its staging phase and must not await;
//!   a memo hit costs two atomic loads and a byte compare, and a memo *miss*
//!   is reported as [`CachedLookup::Unknown`] so the caller takes the
//!   limiter-gated spawn path. `moka::future::Cache` has no synchronous read
//!   view, and one atomic Arc clone per hit to fetch a full address set from
//!   the memo would tax this path for a case (filtered first record) that the
//!   async slow path already handles — one datagram per session, after which
//!   the session destination memo and the pin serve the flow.
//! - **async path** ([`resolve_all_cached`]): positive-cache single flight via
//!   `try_get_with_by_ref`. Moka evaluates the init future exactly once per
//!   key among concurrent callers and wakes the rest with the same result; a
//!   cancelled or panicked owner hands the initialization to a waiter
//!   (`src/future/value_initializer.rs`, `EnclosingFutureAborted`), so the old
//!   `OwnerReset`/`InflightCleanup` guard pair is not needed. The negative
//!   cache is checked first and written explicitly on failure — `try_get_with`
//!   shares errors with concurrent waiters but never caches them.
//! - **upstream**: hickory, cancellable and TTL-clamped to the same windows.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::key::{DNS_KEY_BUF, dns_key, dns_key_owned};
use super::memo::{bump_neg_epoch, memo_peek_both, memo_put, neg_epoch};
use super::store::{DNS_CACHE_TTL, DNS_LOOKUP_TIMEOUT, DNS_NEG_TTL, negatives, positives};
use crate::coarse_millis;

/// Address-family preference for DNS resolution results, from the
/// `dns_ip_preference` config key (`"ipv6"` — the default — or `"ipv4"`).
///
/// Mirrors RFC 6724's model of a configurable precedence policy: IPv6 sorts
/// first by default, switchable to IPv4-first for exits or paths whose
/// targets/connectivity are mostly v4-only. The preference orders the address
/// list every consumer sees — UDP datagram sends and TCP's happy-eyeballs
/// take the first entry first, and the client's `server_addr` dial resolves
/// through the same list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpPreference {
    /// IPv6 addresses sort first (default; RFC 6724-style precedence).
    #[default]
    Ipv6,
    /// IPv4 addresses sort first.
    Ipv4,
}

impl IpPreference {
    /// `sort_by_key` key: the preferred family sorts first (`0`). The sort is
    /// stable, so the resolver's own order within a family is preserved.
    #[inline]
    pub(crate) fn sort_key(self, addr: SocketAddr) -> u8 {
        match self {
            IpPreference::Ipv6 => u8::from(addr.is_ipv4()),
            IpPreference::Ipv4 => u8::from(!addr.is_ipv4()),
        }
    }
}

/// Process-wide preference, set once at startup by the binary from its config
/// (`dns_ip_preference`), read on every resolution.
static IP_PREFERENCE: AtomicU8 = AtomicU8::new(IpPreference::Ipv6 as u8);

/// Set the process-wide [`IpPreference`] (call once at startup).
pub fn set_ip_preference(pref: IpPreference) {
    IP_PREFERENCE.store(pref as u8, Ordering::Relaxed);
}

/// Current process-wide [`IpPreference`].
#[must_use]
pub fn ip_preference() -> IpPreference {
    if IP_PREFERENCE.load(Ordering::Relaxed) == IpPreference::Ipv4 as u8 {
        IpPreference::Ipv4
    } else {
        IpPreference::Ipv6
    }
}

/// Server-side DNS with the configured address-family preference (default
/// IPv6 first; `dns_ip_preference = "ipv4"` restores the v4-first order for
/// v4-heavy exits). Uses the short-lived cache so per-packet domain lookups
/// cannot stall the datagram fast path or amplify upstream DNS.
pub async fn resolve_server_side(host: &str, port: u16) -> Result<SocketAddr> {
    resolve_all_cached(host, port)
        .await?
        .first()
        .copied()
        .context("dns empty")
}

/// All resolved addresses, the configured preferred family first. Caller
/// tries each until one dials (dual-stack fallback).
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await
}

async fn resolve_all_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::time::timeout(timeout, async {
        let mut v: Vec<SocketAddr> = match upstream_resolver() {
            // The IP-literal case is handled inside `lookup_ip` directly, and
            // the system hosts file is consulted before any upstream query
            // (`ResolveHosts::Auto` is the default), so `localhost` and other
            // /etc/hosts entries keep resolving.
            Ok(r) => {
                let lookup = r
                    .lookup_ip(host)
                    .await
                    .map_err(|e| anyhow::anyhow!("dns lookup failed: {e}"))?;
                lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect()
            }
            // The platform DNS configuration could not be read (see
            // `upstream_resolver`): degrade to the previous blocking
            // `getaddrinfo` path instead of losing name resolution entirely.
            Err(why) => {
                tracing::debug!("hickory resolver unavailable ({why}); using getaddrinfo");
                tokio::net::lookup_host((host, port)).await?.collect()
            }
        };
        // Preferred family first; the stable sort keeps the resolver's order
        // within each family (see [`IpPreference`]).
        let pref = ip_preference();
        v.sort_by_key(|s| pref.sort_key(*s));
        Ok::<Vec<SocketAddr>, anyhow::Error>(v)
    })
    .await
    .context("dns lookup timed out")??;
    Ok(addrs)
}

/// Process-wide upstream resolver, built once from the platform's own DNS
/// configuration: resolv.conf on Linux/OpenWrt, the System Configuration
/// dynamic store on macOS. Unlike `getaddrinfo` on the tokio blocking pool,
/// its lookups are cancellable async futures, so the `timeout` wrapper above
/// actually stops the work instead of leaving a blocking thread to finish it
/// after the caller gave up. Its internal response cache is TTL-clamped to
/// this module's positive/negative TTLs, so a name whose answer is still in
/// hickory's cache when the caches above expire can never be served an answer
/// older than the documented windows. `Err` is only the do-not-use-hickory
/// signal for the fallback above; the reason is logged once, at construction.
fn upstream_resolver() -> Result<&'static hickory_resolver::TokioResolver, &'static str> {
    static RESOLVER: std::sync::OnceLock<Result<hickory_resolver::TokioResolver, String>> =
        std::sync::OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            let built = hickory_resolver::TokioResolver::builder_tokio().and_then(|mut b| {
                let opts = b.options_mut();
                opts.positive_max_ttl = Some(DNS_CACHE_TTL);
                opts.negative_max_ttl = Some(DNS_NEG_TTL);
                b.build()
            });
            match built {
                Ok(r) => Ok(r),
                Err(e) => {
                    tracing::warn!(
                        "hickory resolver init failed ({e}); dns lookups fall back to getaddrinfo"
                    );
                    Err(e.to_string())
                }
            }
        })
        .as_ref()
        .map_err(String::as_str)
}

/// Process-wide budget for spawned resolution work (UDP waiter tasks and the
/// server's TCP dial path share it). Exhaustion fails fast — a datagram or
/// dial is refused and counted as `DNS_BUDGET` — instead of parking callers
/// behind an unbounded queue.
pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1024)))
}

/// Result of a synchronous cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedLookup {
    /// A fresh address is cached in this thread's memo.
    Addr(SocketAddr),
    /// A fresh negative entry says the name will not resolve; do not spawn a
    /// resolver task for this packet.
    Negative,
    /// Not in this thread's memo; the caller must use the async resolver.
    Unknown,
}

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
/// Consults the thread-local memo so a hit performs no heap allocation
/// (stack-built key + full-key compare) and, on the hit path, no precise
/// clock read (the deadline is compared in the coarse epoch) — it never
/// touches a lock at all. A memo miss is `Unknown`: the async path re-checks
/// the shared caches (warm entries there resolve without an upstream query).
pub fn lookup_cached_fast(host: &str, port: u16) -> CachedLookup {
    lookup_cached_fast_with_ttl(host, port).0
}

/// [`lookup_cached_fast`] plus the remaining life of what it returned.
///
/// `ttl_ms` is how much longer the answer may be used before it must be looked
/// up again: the *remaining* lifetime of this thread's memo of the entry (the
/// memo is written with the entry's own deadline, so the two agree) for a
/// positive hit, and 0 for a miss or a negative hit.
///
/// Callers that arm their **own** deadline from a cache hit must clamp with it.
/// The server's connection pin and per-session destination memo both used to
/// take a fresh `DEST_PIN_TTL_MS` (30 s) from whatever the lookup returned, so a
/// pin armed 0.1 s before its entry expired served that address for another
/// 30 s — 30 s past the entry, contradicting their own documented bound
/// ("deliberately shorter than the DNS cache TTL").
pub fn lookup_cached_fast_with_ttl(host: &str, port: u16) -> (CachedLookup, u64) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // Memo only, and only then the clock: a memo hit costs two atomic loads
    // and a byte compare. The deadline lives in the coarse epoch (see
    // `expires_ms`), so even the hit path reads no precise clock — only
    // whole-second TTLs are at stake.
    let (pos, neg) = memo_peek_both(key);
    if pos.is_some() || neg.is_some() {
        let now = coarse_millis();
        if let Some(m) = pos
            && now < m.expires_ms
        {
            return match m.addr {
                Some(a) => (CachedLookup::Addr(a), m.expires_ms - now),
                None => (CachedLookup::Unknown, 0),
            };
        }
        if let Some(m) = neg {
            // The epoch check is what keeps a negative memo coherent with a
            // resolution that succeeded on another worker: the memo is
            // thread-private, so the shared negative entry's removal cannot
            // reach it. Without the tag the recording worker kept answering
            // `Negative` — REFUSED datagrams, `dns negative cached` TCP
            // failures — for the rest of `DNS_NEG_TTL` while the caches held a
            // valid address. A stale tag simply falls through to the async
            // path, which reads the shared caches — the authority either way.
            if now < m.expires_ms && m.neg_epoch == neg_epoch() {
                return (CachedLookup::Negative, 0);
            }
        }
    }
    (CachedLookup::Unknown, 0)
}

/// Back-compat helper returning only the positive form.
pub fn lookup_cached_sync(host: &str, port: u16) -> Option<SocketAddr> {
    match lookup_cached_fast(host, port) {
        CachedLookup::Addr(a) => Some(a),
        _ => None,
    }
}

/// Resolve `(host, port)` through the shared caches with single-flight.
///
/// Concurrent callers for the same key are coalesced by moka: the first call
/// evaluates the resolution inside `try_get_with_by_ref`, all others wait and
/// receive the same `Arc<[SocketAddr]>` (or the same error). Cache warming and
/// the thread memo happen **inside the init future, before it returns**, so
/// every waiter that observes the outcome also observes a warmed cache and a
/// failed lookup is negatively cached before any waiter can retry (the old
/// publish-order contract, kept).
///
/// `Err` covers three cases with distinct meanings for the caller: a live
/// negative entry ("dns negative cached" — a policy refusal), a genuine
/// resolution failure, and (via [`resolve_all_timeout`]) a timeout.
pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Arc<[SocketAddr]>> {
    // Stack-built key: no allocation while the key is present in the caches.
    // The fallback only triggers for hosts longer than the 255-byte wire limit.
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // The negative check comes first: a known-bad name must be refused without
    // touching the single-flight machinery, and (unlike a positive sentinel in
    // the same keyspace) a present negative entry can never be returned by
    // `try_get_with` as a resolution result.
    if negatives().get(key).await.is_some() {
        anyhow::bail!("dns negative cached");
    }
    let outcome = positives()
        .try_get_with_by_ref(key, async {
            match resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await {
                Ok(v) => {
                    let now = Instant::now();
                    let v: Arc<[SocketAddr]> = Arc::from(v);
                    // A success clears the negative entry (the name resolves
                    // now) and bumps the epoch so other threads' stale
                    // negative memos stop refusing. Done before returning, so
                    // it precedes every waiter wake-up.
                    if negatives().remove(key).await.is_some() {
                        bump_neg_epoch();
                    }
                    if let Some(a) = v.first().copied() {
                        memo_put(key, Some(a), now + DNS_CACHE_TTL);
                    }
                    Ok((now, v))
                }
                Err(e) => {
                    let now = Instant::now();
                    negatives().insert(key.to_owned(), ()).await;
                    memo_put(key, None, now + DNS_NEG_TTL);
                    Err(format!("{e:#}"))
                }
            }
        })
        .await;
    outcome.map(|(_, v)| v).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Seed the positive cache as if `host:port` had just resolved to `addr`.
///
/// Bin unit tests need this to exercise a DNS-hit path without a live
/// resolver; production always warms the cache through `resolve_all_cached`.
#[doc(hidden)]
pub async fn dns_cache_seed(host: &str, port: u16, addr: SocketAddr) {
    dns_cache_seed_aged(host, port, addr, Duration::ZERO).await;
}

/// [`dns_cache_seed`] with an explicit entry age, so a test can drive the
/// "almost expired" case that `lookup_cached_fast_with_ttl` exists for.
///
/// `age` is subtracted from the entry's insertion instant (and from the memo's
/// deadline), i.e. the remaining life is `DNS_CACHE_TTL - age` — the input a TTL
/// clamp has to react to.
#[doc(hidden)]
pub async fn dns_cache_seed_aged(host: &str, port: u16, addr: SocketAddr, age: Duration) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    let now = Instant::now();
    let inserted = now.checked_sub(age).unwrap_or(now);
    positives()
        .insert(key.to_owned(), (inserted, Arc::from([addr])))
        .await;
    if negatives().remove(key).await.is_some() {
        bump_neg_epoch();
    }
    memo_put(key, Some(addr), inserted + DNS_CACHE_TTL);
}

/// Seed the negative cache as if `host:port` had just failed to resolve.
///
/// Same test-only purpose as [`dns_cache_seed`], for the other verdict: without
/// it a negative *memo* entry can only be produced by a real (network) resolver
/// failure, so the memo's coherence rules would be untestable.
#[doc(hidden)]
pub async fn dns_neg_cache_seed(host: &str, port: u16) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    record_negative(key).await;
}

/// Seed the positive cache with a full multi-record set, first record first.
/// Same test-only purpose as [`dns_cache_seed`]: the fast probe serves only
/// the first address, so a filtered-first multi-record name cannot be
/// exercised without seeding more than one.
#[doc(hidden)]
pub async fn dns_cache_seed_set(host: &str, port: u16, addrs: &[SocketAddr]) {
    let Some(first) = addrs.first().copied() else {
        return;
    };
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    let now = Instant::now();
    positives()
        .insert(key.to_owned(), (now, Arc::from(addrs)))
        .await;
    if negatives().remove(key).await.is_some() {
        bump_neg_epoch();
    }
    memo_put(key, Some(first), now + DNS_CACHE_TTL);
}

/// Record that resolving `key` failed, so the packet paths can refuse it
/// without spawning a resolver per datagram. Runs inside
/// [`resolve_all_cached`]'s init future, before the error is published to
/// waiters; the single-flight serialization is what makes the write safe —
/// no live positive entry can exist while the init that writes this runs (the
/// old "never downgrade a live positive" probe guarded a contention window
/// that no longer exists).
async fn record_negative(key: &str) {
    let now = Instant::now();
    negatives().insert(key.to_owned(), ()).await;
    memo_put(key, None, now + DNS_NEG_TTL);
}

/// Accept `IP:port` or `hostname:port` for the QUIC server address.
pub async fn resolve_server_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = s
        .rsplit_once(':')
        .context("bad server_addr, want host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad server port")?;
    let v = resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await?;
    v.into_iter().next().context("dns empty")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn preference_defaults_to_ipv6_first() {
        assert_eq!(IpPreference::default(), IpPreference::Ipv6);
        assert_eq!(ip_preference(), IpPreference::Ipv6);
    }

    #[test]
    fn sort_key_orders_the_preferred_family_first() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443));
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));

        assert!(IpPreference::Ipv6.sort_key(v6) < IpPreference::Ipv6.sort_key(v4));
        assert!(IpPreference::Ipv4.sort_key(v4) < IpPreference::Ipv4.sort_key(v6));

        let mut addrs = [v4, v6];
        addrs.sort_by_key(|s| IpPreference::Ipv6.sort_key(*s));
        assert!(!addrs[0].is_ipv4(), "v6-first must put the v6 entry first");
        let mut addrs = [v6, v4];
        addrs.sort_by_key(|s| IpPreference::Ipv4.sort_key(*s));
        assert!(addrs[0].is_ipv4(), "v4-first must put the v4 entry first");
    }

    /// A seeded name must resolve out of the positive cache without any
    /// upstream query, negative entry, or memo write on this thread beyond
    /// the seed's own.
    #[tokio::test]
    async fn seeded_name_resolves_from_the_cache() {
        let (host, port) = ("seeded.resolve.test", 19701u16);
        let addr: SocketAddr = "93.184.216.34:19701".parse().unwrap();
        dns_cache_seed(host, port, addr).await;
        let v = resolve_all_cached(host, port).await.expect("seeded hit");
        assert_eq!(&v[..], &[addr]);
        assert_eq!(lookup_cached_fast(host, port), CachedLookup::Addr(addr));
    }

    /// A live negative entry refuses without touching the resolver.
    #[tokio::test]
    async fn negative_entry_refuses_without_resolving() {
        let (host, port) = ("negative.resolve.test", 19702u16);
        dns_neg_cache_seed(host, port).await;
        let err = resolve_all_cached(host, port).await.unwrap_err();
        assert!(
            err.to_string().contains("dns negative cached"),
            "got: {err:#}"
        );
        assert_eq!(lookup_cached_fast(host, port), CachedLookup::Negative);
    }

    /// Concurrent callers of one cold key must all receive the same address
    /// set from a single-flight resolution. `127.0.0.1` is an IP literal, which
    /// hickory answers without any network query, so the init path (single
    /// flight, cache insert, memo write) runs deterministically.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cold_lookups_coalesce_and_all_get_the_answer() {
        let host = "127.0.0.1";
        let port = 19703u16;
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Unknown,
            "premise: the key is cold"
        );
        let mut tasks = Vec::new();
        for _ in 0..16 {
            tasks.push(tokio::spawn(
                async move { resolve_all_cached(host, port).await },
            ));
        }
        let mut seen: Vec<Arc<[SocketAddr]>> = Vec::new();
        for t in tasks {
            seen.push(t.await.expect("task joins").expect("literal resolves"));
        }
        let first = seen[0].clone();
        for v in &seen {
            assert_eq!(&v[..], &first[..], "every caller must see the same set");
        }
        assert_eq!(
            &first[..],
            &[SocketAddr::from(([127, 0, 0, 1], port))],
            "the literal must resolve to itself"
        );
        assert!(
            negatives().get("127.0.0.1\u{0}19703").await.is_none(),
            "a success must not leave a negative entry"
        );
    }

    /// The single-flight assumption this module rests on: when the
    /// initializing future's task is cancelled, a waiting caller must not
    /// hang — moka hands the initialization to a waiter. Pinned here against a
    /// private cache so a moka upgrade that broke it fails loudly in this
    /// suite instead of wedging a deployed proxy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_owner_does_not_strand_a_waiter() {
        use moka::future::Cache;
        let cache: Cache<&'static str, u32> = Cache::new(16);

        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let owner = tokio::spawn({
            let c = cache.clone();
            async move {
                let _ = c
                    .get_with("k", async move {
                        let _ = release_rx.await;
                        1u32
                    })
                    .await;
            }
        });
        // Let the owner register its init, then queue a waiter behind it.
        tokio::time::sleep(Duration::from_millis(25)).await;
        let waiter = tokio::spawn({
            let c = cache.clone();
            async move { c.get_with("k", async { 2u32 }).await }
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        owner.abort();
        let v = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the waiter must not hang behind a cancelled owner")
            .expect("waiter joins");
        assert_eq!(v, 2, "the waiter's own init must have run");
        drop(release_tx);
    }
}
