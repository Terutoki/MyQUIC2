//! DNS resolve / cache lookup, on top of the moka-backed verdict stores
//! (`dns::store`) and the thread-local memo (`dns::memo`).
//!
//! Layering:
//!
//! - **sync fast path** ([`lookup_cached_fast`]): thread-local memo only, keyed
//!   by `(host, port)` (`dns::key`). The packet path (server egress
//!   `resolve_pin`/`forward_server_dgram`, client `dispatch_stage*`) is
//!   synchronous in its staging phase and must not await; a memo hit costs two
//!   atomic loads and a byte compare, and a memo *miss* is reported as
//!   [`CachedLookup::Unknown`] so the caller takes the limiter-gated spawn
//!   path. `moka::future::Cache` has no synchronous read view, and one atomic
//!   Arc clone per hit to fetch a full address set from the memo would tax this
//!   path for a case (filtered first record) that the async slow path already
//!   handles — one datagram per session, after which the session destination
//!   memo and the pin serve the flow. The memo stores the full `SocketAddr`, so
//!   its key must carry the port; a *new* port of a known name is a memo miss
//!   and is answered by the shared host-keyed cache below.
//! - **async path** ([`resolve_all_cached`]): positive-cache single flight via
//!   `try_get_with_by_ref`, keyed by the normalized host *only* — A/AAAA
//!   records are port-independent, so every port of one name shares one entry
//!   and one upstream query, and the caller's port is attached when the set is
//!   returned. Moka evaluates the init future exactly once per key among
//!   concurrent callers and wakes the rest with the same result; a cancelled or
//!   panicked owner hands the initialization to a waiter
//!   (`src/future/value_initializer.rs`, `EnclosingFutureAborted`), so the old
//!   `OwnerReset`/`InflightCleanup` guard pair is not needed. The negative
//!   cache is checked first by the same host key and written explicitly on
//!   failure — `try_get_with` shares errors with concurrent waiters but never
//!   caches them. Negative verdicts are per name too: a dead name is dead for
//!   all ports, so port-diverse traffic to it learns the verdict once instead
//!   of once per port (each learning holding a `dns_slow_path_limiter` permit
//!   for the lookup budget).
//! - **upstream**: hickory, cancellable and TTL-clamped to the same windows.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::key::{
    DNS_HOST_KEY_BUF, DNS_KEY_BUF, dns_host_key, dns_host_key_owned, dns_key, dns_key_owned,
};
use super::memo::{bump_neg_epoch, memo_peek_both, memo_put, neg_epoch};
use super::store::{DNS_CACHE_TTL, DNS_LOOKUP_TIMEOUT, DNS_NEG_TTL, negatives, positives};
use crate::coarse_millis;

/// Serializes the few cache tests that assert on a *negative* thread memo or
/// deliberately bump the process-wide negative epoch. `NEG_EPOCH` is (by
/// design) global, so a concurrent positive seed in another test would
/// invalidate the memo under assertion. Production is unaffected; the lock is
/// test-only.
#[cfg(test)]
pub(crate) static DNS_CACHE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        self.sort_key_ip(addr.ip())
    }

    /// [`sort_key`](Self::sort_key) for a port-free address: family is an
    /// `IpAddr` property, so this is what the shared positive cache (which
    /// stores `IpAddr`s) sorts by. Kept in terms of one predicate so the two
    /// forms can never disagree about which family is preferred.
    #[inline]
    pub(crate) fn sort_key_ip(self, ip: IpAddr) -> u8 {
        match self {
            IpPreference::Ipv6 => u8::from(ip.is_ipv4()),
            IpPreference::Ipv4 => u8::from(!ip.is_ipv4()),
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

/// Uncached `(host, port)` resolution: the upstream lookup plus the caller's
/// port attached to every address.
///
/// This is the path for callers that must not be served a cached answer (the
/// client's `server_addr` dial) and for [`resolve_server_addr`]. The shared
/// caches only ever hold port-free addresses, so this composes the same
/// [`resolve_ips`] primitive the cache-fill path uses and materializes the
/// caller's port on the way out.
async fn resolve_all_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let ips = resolve_ips(host, port, timeout).await?;
    let mut addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    // Preferred family first; the stable sort keeps the resolver's order
    // within each family (see [`IpPreference`]).
    let pref = ip_preference();
    addrs.sort_by_key(|addr| pref.sort_key(*addr));
    Ok(addrs)
}

/// Resolve just the addresses of `host` — no port — in the resolver's own
/// order.
///
/// This is the upstream primitive behind both the uncached resolution path and
/// the host-keyed positive cache's init future: A/AAAA answers are independent
/// of the port the caller asked about, so the port is only carried along as the
/// `getaddrinfo` fallback's service hint (its returned ports are discarded).
/// The preference sort is applied by the callers, on their final address form —
/// `SocketAddr`s for the uncached path, `IpAddr`s before the cache insert — so
/// a cache hit always hands back a set in the same family order a fresh
/// resolution would.
async fn resolve_ips(host: &str, port: u16, timeout: Duration) -> Result<Vec<IpAddr>> {
    let ips = tokio::time::timeout(timeout, async {
        let ips: Vec<IpAddr> = match upstream_resolver() {
            // The IP-literal case is handled inside `lookup_ip` directly, and
            // the system hosts file is consulted before any upstream query
            // (`ResolveHosts::Auto` is the default), so `localhost` and other
            // /etc/hosts entries keep resolving.
            Ok(r) => {
                let lookup = r
                    .lookup_ip(host)
                    .await
                    .map_err(|e| anyhow::anyhow!("dns lookup failed: {e}"))?;
                lookup.iter().collect()
            }
            // The platform DNS configuration could not be read (see
            // `upstream_resolver`): degrade to the previous blocking
            // `getaddrinfo` path instead of losing name resolution entirely.
            Err(why) => {
                tracing::debug!("hickory resolver unavailable ({why}); using getaddrinfo");
                tokio::net::lookup_host((host, port))
                    .await?
                    .map(|sa| sa.ip())
                    .collect()
            }
        };
        Ok::<Vec<IpAddr>, anyhow::Error>(ips)
    })
    .await
    .context("dns lookup timed out")??;
    Ok(ips)
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
///
/// The memo key stays per-`(host, port)` even though the shared caches are
/// host-keyed: the memo's value is a full `SocketAddr` for the port that was
/// resolved, so a hit can answer with the right port and no work. A *new* port
/// of a known name is deliberately a miss here; `resolve_all_cached` answers it
/// from the host-keyed cache and then memoizes that port.
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
/// Both moka caches are keyed by the normalized **host only**: A/AAAA records
/// carry no port, so a second port of a name must hit the same positive entry
/// (and join the same in-flight upstream query) instead of paying a fresh
/// lookup, and a negative verdict is a property of the name — a dead name is
/// dead for every port. The caller's port is attached when the address set is
/// returned; every address in the set gets it.
///
/// Concurrent callers for the same *name* are coalesced by moka even when they
/// ask for different ports: the first call evaluates the resolution inside
/// `try_get_with_by_ref`, all others wait and receive the same `Arc<[IpAddr]>`
/// (or the same error). Cache warming happens inside the init future, and the
/// per-`(host, port)` *positive* memo is written on every caller's return path
/// — `materialize_cached` runs for the init owner and every waiter alike — so
/// a caller that observes the outcome also observes a warmed cache. A failed
/// lookup is negatively cached (host verdict + this port's memo) inside the
/// init, before the error is published to any waiter: the old publish-order
/// contract, kept.
///
/// **Lookup order.** A warm positive entry is probed *first*: it is the common
/// outcome for a name this process resolved in the last [`DNS_CACHE_TTL`], and
/// it needs no negative verdict to disambiguate it. The positive and negative
/// stores are disjoint by construction (a negative is only written by the
/// single-flight init that ran because no positive entry existed, and a
/// successful resolution clears it before publishing its entry — see
/// `record_negative` and `seed_positive`), so probing positive first cannot
/// serve an address for a refused name. The negative probe then runs only on a
/// positive miss, where it keeps its job: refuse a known-bad name without
/// touching the single-flight machinery. This removes one hashed `moka` probe
/// from every warm hit — the store's whole reason to exist is that the slow
/// path should answer without an upstream query, and the warm hit is what the
/// per-thread DNS memo falls back to for a new port or after its TTL.
///
/// `Err` covers three cases with distinct meanings for the caller: a live
/// negative entry ("dns negative cached" — a policy refusal), a genuine
/// resolution failure, and (via the init's timeout) a timeout.
pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Arc<[SocketAddr]>> {
    // Stack-built per-(host, port) key for this thread's memo. The fallback
    // only triggers for hosts longer than the 255-byte wire limit.
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let memo_key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // Stack-built host-only key for the shared caches. Separate buffer: both
    // borrowed keys are live across the awaits below.
    let mut hbuf = [0u8; DNS_HOST_KEY_BUF];
    let host_owned;
    let host_key: &str = match dns_host_key(host, &mut hbuf) {
        Some(k) => k,
        None => {
            host_owned = dns_host_key_owned(host);
            &host_owned
        }
    };
    // Warm positive hit: one cache probe, no single-flight, no negative probe
    // (see the lookup-order note above). The init future writes this entry, so
    // every TTL window's answer is already here for the callers that did not
    // own the init; they just attach their own port and warm their thread memo.
    if let Some((inserted, ips)) = positives().get(host_key).await {
        return Ok(materialize_cached(memo_key, inserted, &ips, port));
    }
    // The negative check comes before the single-flight machinery: a known-bad
    // name must be refused without spawning a resolution, and (unlike a
    // positive sentinel in the same keyspace) a present negative entry can
    // never be returned by `try_get_with` as a resolution result. Host-keyed,
    // so a verdict learned for one port refuses all of them.
    //
    // Warm *this* thread's per-(host, port) memo with the verdict's remaining
    // life before bailing. Only the init that learned the failure memoized its
    // own port, so without this a refused name reached through any other port
    // would miss the sync memo on every datagram and spawn a resolver task
    // each time, forever (the slow-path limiter bounds concurrency, not the
    // per-datagram task rate). The deadline cannot outlive the shared entry:
    // it is derived from the entry's own insertion instant, which the negative
    // cache stores for exactly this reason.
    if let Some(inserted_at) = negatives().get(host_key).await {
        let remaining = DNS_NEG_TTL.saturating_sub(inserted_at.elapsed());
        memo_put(memo_key, None, Instant::now() + remaining);
        anyhow::bail!("dns negative cached");
    }
    let outcome = positives()
        .try_get_with_by_ref(host_key, async {
            match resolve_ips(host, port, DNS_LOOKUP_TIMEOUT).await {
                Ok(mut ips) => {
                    let now = Instant::now();
                    // The cache's invariant: every stored set is ordered with
                    // the configured preferred family first (the resolver's own
                    // order within a family is kept by the stable sort), so a
                    // hit for another port hands back the same order a fresh
                    // resolution would.
                    let pref = ip_preference();
                    ips.sort_by_key(|ip| pref.sort_key_ip(*ip));
                    let ips: Arc<[IpAddr]> = Arc::from(ips);
                    // A success clears the negative entry (the name resolves
                    // now) and bumps the epoch so other threads' stale
                    // negative memos stop refusing. Done before returning, so
                    // it precedes every waiter wake-up.
                    if negatives().remove(host_key).await.is_some() {
                        bump_neg_epoch();
                    }
                    Ok((now, ips))
                }
                Err(e) => {
                    // Negatively cache the *name*, so every port of it is
                    // refused after one failure, and memoize this port too so
                    // the sync packet path refuses this exact target without
                    // spawning a resolver. Other ports hit the shared host
                    // verdict above, which memoizes their own port there.
                    record_negative(host_key, memo_key).await;
                    Err(format!("{e:#}"))
                }
            }
        })
        .await;
    match outcome {
        // The init owner and every single-flight waiter land here; the helper
        // also runs for the warm-hit arm above, so the port attachment and the
        // per-thread memo write can never drift between the two paths.
        Ok((inserted, ips)) => Ok(materialize_cached(memo_key, inserted, &ips, port)),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

/// Attach the caller's port to a cached, port-free address set and warm this
/// thread's per-`(host, port)` memo from the entry's own deadline.
///
/// The shared positive entry is keyed by the host alone and stores only
/// [`IpAddr`]s, so the port is attached last, when the answer is returned.
/// Attaching it does not reorder the set — the init path already sorted it
/// preferred-family-first.
///
/// The memo write is what makes the *next* datagram answerable by the sync
/// probe ([`lookup_cached_fast`]). Moka runs the init once per key on whichever
/// thread missed first, so a caller that merely finds the entry warm in moka
/// would otherwise keep reading the memo as `Unknown` and take the slow path
/// again: on the server's UDP ingress that is a spawned resolver task *per
/// datagram* for a domain target (see `forward_server_dgram`), which is exactly
/// the per-packet cost the session destination memo and the connection pin
/// exist to remove. A host-keyed hit for a *new* port is what makes that port
/// answerable by the sync probe from now on. The deadline is clamped to the
/// entry's remaining life (never extended).
fn materialize_cached(
    memo_key: &str,
    inserted: Instant,
    ips: &[IpAddr],
    port: u16,
) -> Arc<[SocketAddr]> {
    // Collect straight into the `Arc<[SocketAddr]>` slice: the `FromIterator`
    // impl sizes and fills one allocation, where the previous
    // `Vec` + `Arc::from(vec)` shape allocated twice and copied once for a
    // value the caller only ever iterates (and usually only reads the first
    // address of).
    let addrs: Arc<[SocketAddr]> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    if let Some(first) = addrs.first().copied() {
        let deadline = inserted + DNS_CACHE_TTL;
        if deadline > Instant::now() {
            memo_put(memo_key, Some(first), deadline);
        }
    }
    addrs
}

/// Seed the positive cache as if `host:port` had just resolved to `addr`.
///
/// Bin unit tests need this to exercise a DNS-hit path without a live
/// resolver; production always warms the cache through `resolve_all_cached`.
///
/// The shared positive entry is **host-keyed** and stores only `addr.ip()`, so
/// a lookup for a different port of `host` hits the same entry and gets *its*
/// port attached; the per-`(host, port)` memo stores the full `addr` verbatim,
/// so the sync probe for the seeded `port` answers exactly `addr`.
#[doc(hidden)]
pub async fn dns_cache_seed(host: &str, port: u16, addr: SocketAddr) {
    seed_positive(host, port, vec![addr.ip()], Some(addr), Duration::ZERO).await;
}

/// [`dns_cache_seed`] with an explicit entry age, so a test can drive the
/// "almost expired" case that `lookup_cached_fast_with_ttl` exists for.
///
/// `age` is subtracted from the entry's insertion instant (and from the memo's
/// deadline), i.e. the remaining life is `DNS_CACHE_TTL - age` — the input a TTL
/// clamp has to react to.
#[doc(hidden)]
pub async fn dns_cache_seed_aged(host: &str, port: u16, addr: SocketAddr, age: Duration) {
    seed_positive(host, port, vec![addr.ip()], Some(addr), age).await;
}

/// Seed the negative cache as if `host:port` had just failed to resolve.
///
/// Same test-only purpose as [`dns_cache_seed`], for the other verdict: without
/// it a negative *memo* entry can only be produced by a real (network) resolver
/// failure, so the memo's coherence rules would be untestable. The shared
/// verdict is host-keyed (every port refuses), and the per-port memo makes the
/// seeded port refuse synchronously.
#[doc(hidden)]
pub async fn dns_neg_cache_seed(host: &str, port: u16) {
    let host_key = dns_host_key_owned(host);
    let memo_key = dns_key_owned(host, port);
    record_negative(&host_key, &memo_key).await;
}

/// Seed the positive cache with a full multi-record set, first record first.
/// Same test-only purpose as [`dns_cache_seed`]: the fast probe serves only
/// the first address, so a filtered-first multi-record name cannot be
/// exercised without seeding more than one.
///
/// Like every positive entry this one is host-keyed and port-free: a lookup
/// for any port of `host` gets the set with *that* port attached, so seed
/// addresses of a different port are still served as their IPs.
#[doc(hidden)]
pub async fn dns_cache_seed_set(host: &str, port: u16, addrs: &[SocketAddr]) {
    let Some(first) = addrs.first().copied() else {
        return;
    };
    seed_positive(
        host,
        port,
        addrs.iter().map(|a| a.ip()).collect(),
        Some(first),
        Duration::ZERO,
    )
    .await;
}

/// Shared body of the positive seeding helpers: insert the host-keyed positive
/// entry holding `ips` as of `age` ago, clear any negative verdict for the
/// name (bumping [`NEG_EPOCH`](super::memo::neg_epoch) so other threads' stale
/// negative memos stop refusing), and memoize `memo_addr` under the caller's
/// per-`(host, port)` key.
async fn seed_positive(
    host: &str,
    port: u16,
    ips: Vec<IpAddr>,
    memo_addr: Option<SocketAddr>,
    age: Duration,
) {
    let host_key = dns_host_key_owned(host);
    let memo_key = dns_key_owned(host, port);
    let now = Instant::now();
    let inserted = now.checked_sub(age).unwrap_or(now);
    positives()
        .insert(host_key.clone(), (inserted, Arc::from(ips)))
        .await;
    if negatives().remove(host_key.as_str()).await.is_some() {
        bump_neg_epoch();
    }
    if let Some(addr) = memo_addr {
        memo_put(&memo_key, Some(addr), inserted + DNS_CACHE_TTL);
    }
}

/// Record that resolving the name `host_key` failed, so the packet paths can
/// refuse it without spawning a resolver per datagram: the shared verdict is
/// host-keyed (every port refuses), and `memo_key` is this thread's
/// per-`(host, port)` memo entry.
///
/// Runs inside [`resolve_all_cached`]'s init future, before the error is
/// published to waiters; the single-flight serialization is what makes the
/// write safe — no live positive entry can exist while the init that writes
/// this runs (the old "never downgrade a live positive" probe guarded a
/// contention window that no longer exists).
async fn record_negative(host_key: &str, memo_key: &str) {
    let now = Instant::now();
    negatives().insert(host_key.to_owned(), now).await;
    memo_put(memo_key, None, now + DNS_NEG_TTL);
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
    use super::super::key::dns_key_owned;
    use super::super::memo::MEMO_KEY_BYTES;
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

        // The port-free form the host-keyed positive cache sorts by must agree
        // with the `SocketAddr` form on the family ordering.
        for (addr, pref) in [
            (v4, IpPreference::Ipv6),
            (v6, IpPreference::Ipv6),
            (v4, IpPreference::Ipv4),
            (v6, IpPreference::Ipv4),
        ] {
            assert_eq!(pref.sort_key(addr), pref.sort_key_ip(addr.ip()));
        }
        assert!(IpPreference::Ipv6.sort_key_ip(v6.ip()) < IpPreference::Ipv6.sort_key_ip(v4.ip()));

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

    /// A/AAAA answers are port-independent, so a name seeded for one port must
    /// answer a *different* port from the same host-keyed entry — no resolver
    /// init (a network lookup of the `.test` name would fail) — and the hit
    /// must memoize that new port for the sync packet path.
    ///
    /// This is the port-amplifier fix: before host-keying, a new port of an
    /// already-resolved name missed the positive cache, the single-flight and
    /// the memo, and paid a fresh upstream query before the first
    /// datagram/CONNECT.
    #[tokio::test]
    async fn a_second_port_reuses_the_host_keyed_positive_entry() {
        let host = "port-shared.resolve.test";
        let seeded_port = 19_711u16;
        let other_port = 19_712u16;
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let seeded: SocketAddr = SocketAddr::new(ip, seeded_port);
        dns_cache_seed(host, seeded_port, seeded).await;

        // The shared entry is keyed by the host alone, and the seed's memo is
        // keyed by the seeded port.
        assert!(
            positives().get(host).await.is_some(),
            "the positive cache entry must be keyed by the host, not (host, port)"
        );
        assert_eq!(
            lookup_cached_fast(host, seeded_port),
            CachedLookup::Addr(seeded)
        );
        // The memo stays per-(host, port): a new port is a sync miss even while
        // the host's shared entry is warm, so the packet path falls through to
        // the async path exactly once.
        assert_eq!(
            lookup_cached_fast(host, other_port),
            CachedLookup::Unknown,
            "the thread memo must stay per-(host, port): it stores a full SocketAddr"
        );

        // The async path answers the new port from the host-keyed entry (the
        // `.test` name would fail if an init ran) and attaches its port.
        let want = SocketAddr::new(ip, other_port);
        let v = resolve_all_cached(host, other_port)
            .await
            .expect("a host-keyed cache hit must not need an upstream query");
        assert_eq!(&v[..], &[want], "the hit must attach the caller's port");
        assert_eq!(
            lookup_cached_fast(host, other_port),
            CachedLookup::Addr(want),
            "a shared-cache hit for a new port must memoize that port"
        );
        // ... and it must not have disturbed the seeded port's answer.
        assert_eq!(
            lookup_cached_fast(host, seeded_port),
            CachedLookup::Addr(seeded)
        );
    }

    /// A negative verdict is a property of the name, so one failed port must
    /// refuse the others without spawning a resolver for them.
    #[tokio::test]
    async fn a_negative_verdict_refuses_every_port_of_the_name() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
        let host = "host-negative.resolve.test";
        let port_a = 19_721u16;
        let port_b = 19_722u16;
        dns_neg_cache_seed(host, port_a).await;

        assert!(
            negatives().get(host).await.is_some(),
            "the negative verdict must be keyed by the host, not (host, port)"
        );
        assert_eq!(lookup_cached_fast(host, port_a), CachedLookup::Negative);
        assert_eq!(
            lookup_cached_fast(host, port_b),
            CachedLookup::Unknown,
            "premise: the other port's memo is cold (the verdict is shared)"
        );
        let err = resolve_all_cached(host, port_b).await.unwrap_err();
        assert!(
            err.to_string().contains("dns negative cached"),
            "a host-keyed negative entry must refuse another port, got: {err:#}"
        );
        // The refusing call must warm this port's thread memo, or every
        // datagram for that port would spawn a resolver task forever: the
        // shared verdict is only reachable from the async path, and only the
        // init that learned the failure can memoize a port it was asked about.
        assert_eq!(
            lookup_cached_fast(host, port_b),
            CachedLookup::Negative,
            "a host-keyed negative hit must memoize the queried port"
        );
    }

    /// A full multi-record set is cached port-free, so every port of the name
    /// gets the whole set with its own port attached, in the seeded order.
    #[tokio::test]
    async fn a_seeded_set_serves_every_port_with_the_whole_answer() {
        let host = "set-shared.resolve.test";
        let seeded_port = 19_741u16;
        let other_port = 19_742u16;
        let a: SocketAddr = "203.0.113.10:19741".parse().unwrap();
        let b: SocketAddr = "203.0.113.11:19741".parse().unwrap();
        dns_cache_seed_set(host, seeded_port, &[a, b]).await;

        let v = resolve_all_cached(host, other_port)
            .await
            .expect("host-keyed set hit");
        assert_eq!(
            &v[..],
            &[
                SocketAddr::new(a.ip(), other_port),
                SocketAddr::new(b.ip(), other_port),
            ],
            "the whole set must survive a port change, each address re-ported"
        );
        assert_eq!(lookup_cached_fast(host, seeded_port), CachedLookup::Addr(a));
    }

    /// The memo must store wire-length names (> the old 64-byte inline budget)
    /// instead of silently refusing them — a refused name re-entered the
    /// spawned-resolver path on every datagram.
    #[tokio::test]
    async fn a_long_name_is_memoized() {
        // 99-byte host (two legal labels + `.test`), past the old 64-byte slot
        // budget but well under the 255-byte wire limit.
        let host = format!("{}.{}.test", "a".repeat(60), "b".repeat(33));
        assert!(
            host.len() > 64 && host.len() <= 255,
            "premise: a long-but-legal name, got {} B",
            host.len()
        );
        let port = 19_751u16;
        let addr: SocketAddr = "203.0.113.12:19751".parse().unwrap();
        dns_cache_seed(&host, port, addr).await;

        let memo_key = dns_key_owned(&host, port);
        assert!(memo_key.len() > 64 && memo_key.len() <= MEMO_KEY_BYTES);
        assert_eq!(
            lookup_cached_fast(&host, port),
            CachedLookup::Addr(addr),
            "a {} B (host, port) key must fit the widened memo slot",
            memo_key.len()
        );
        let v = resolve_all_cached(&host, port)
            .await
            .expect("long name resolves from the host-keyed cache");
        assert_eq!(&v[..], &[addr]);
    }

    /// A shared-cache **hit** must warm this thread's memo.
    ///
    /// The memo is thread-local and was only ever written by the init future —
    /// which moka runs once per key per TTL, on whichever thread missed first.
    /// So a caller that found the entry already in the shared cache still read
    /// `lookup_cached_fast*` as `Unknown`, and on the server's UDP ingress that
    /// meant a spawned resolver task *per datagram* for a domain target. The
    /// seed runs on another thread, so the premise (this thread's memo is cold
    /// while the shared cache is warm) is exactly the production shape.
    #[tokio::test]
    async fn a_shared_cache_hit_warms_this_threads_memo() {
        let (host, port) = ("memo-warm.resolve.test", 19704u16);
        let addr: SocketAddr = "93.184.216.34:19704".parse().unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(dns_cache_seed(host, port, addr));
        })
        .join()
        .expect("seed thread");
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Unknown,
            "premise: the shared cache is warm, this thread's memo is not"
        );

        let v = resolve_all_cached(host, port).await.expect("seeded hit");
        assert_eq!(&v[..], &[addr]);
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "a cache hit must leave this thread able to answer without the cache"
        );
    }

    /// A live negative entry refuses without touching the resolver.
    #[tokio::test]
    async fn negative_entry_refuses_without_resolving() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
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
            negatives().get(host).await.is_none(),
            "a success must not leave a negative entry"
        );
    }

    /// The warm-hit lookup order (positive probe *before* the negative verdict)
    /// is only sound because one name can never hold a positive and a negative
    /// entry at once. Pin that invariant: if it ever broke, the warm path would
    /// serve an address for a name the negative store still refuses.
    #[tokio::test]
    async fn positive_and_negative_stores_are_disjoint_per_name() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
        let host = "disjoint.resolve.test";
        let port = 19_761u16;
        assert!(
            positives().get(host).await.is_none() && negatives().get(host).await.is_none(),
            "premise: a cold name starts in neither store"
        );
        dns_neg_cache_seed(host, port).await;
        assert!(
            negatives().get(host).await.is_some() && positives().get(host).await.is_none(),
            "a failed resolution writes the negative store only"
        );
        let addr: SocketAddr = "203.0.113.77:19761".parse().unwrap();
        dns_cache_seed(host, port, addr).await;
        assert!(
            negatives().get(host).await.is_none(),
            "a successful resolution clears the negative verdict"
        );
        assert!(
            positives().get(host).await.is_some(),
            "the success is the only entry left for the name"
        );
        // The warm positive-first arm must serve that entry, port attached.
        assert_eq!(
            &resolve_all_cached(host, port)
                .await
                .expect("warm positive hit")[..],
            &[addr]
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
