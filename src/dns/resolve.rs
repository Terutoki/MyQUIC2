//! DNS resolve / cache lookup — verbatim extraction from `src/lib.rs` (zero logic change).
//! Symbols: CachedLookup / lookup_cached_fast* / lookup_cached_sync /
//! lookup_cached_all_fast* / dns_cache_seed* / DNS_CACHE_MAX* / evict_if_needed /
//! DnsContended / is_dns_contended / resolve_all_cached* / PositiveState /
//! positive_entry_state / clear_negative / record_negative / resolve_server_addr /
//! resolve_server_side / resolve_all / resolve_all_timeout.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::cache::{
    dns_cache_for, dns_neg_cache_for, DNS_CACHE_TTL, DNS_LOOKUP_TIMEOUT, DNS_NEG_MAX, DNS_NEG_TTL,
};
use super::inflight::{dns_inflight_for, DnsInflightEntry, InflightCleanup, OwnerReset};
use super::key::{
    dns_key, dns_key_owned, DnsCacheKey, DnsCacheVal, DnsMap, DNS_KEY_BUF, DNS_SHARDS,
};
use super::memo::{bump_neg_epoch, memo_peek_both, memo_put, neg_epoch};
use crate::{coarse_millis, dgram_drops, lock_write, try_lock_mutex, try_lock_read};

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
/// v4-heavy exits). Uses a short-lived cache so per-packet domain lookups
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

/// Result of a synchronous cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedLookup {
    /// A fresh address is cached.
    Addr(SocketAddr),
    /// A fresh negative entry says the name will not resolve; do not spawn a
    /// resolver task for this packet.
    Negative,
    /// Not cached; the caller must use the async resolver.
    Unknown,
}

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
/// Consults the thread-local memo, then the positive cache, then the negative
/// cache, so a known-bad name never costs a task spawn. A hit performs no heap
/// allocation (stack-built key + full-key compare against the memo) and, on the
/// memo hit path, no precise clock read (the deadline is compared in the coarse
/// epoch) — it never touches a lock at all.
pub fn lookup_cached_fast(host: &str, port: u16) -> CachedLookup {
    lookup_cached_fast_with_ttl(host, port).0
}

/// [`lookup_cached_fast`] plus the remaining life of what it returned.
///
/// `ttl_ms` is how much longer the answer may be used before it must be looked
/// up again: the *remaining* lifetime of the cache entry (or of this thread's
/// memo of it — the memo is written with the entry's own deadline, so the two
/// agree) for a positive hit, and 0 for a miss or a negative hit.
///
/// Callers that arm their **own** deadline from a cache hit must clamp with it.
/// The server's connection pin and per-session destination memo both used to
/// take a fresh `DEST_PIN_TTL_MS` (30 s) from whatever the lookup returned, so a
/// pin armed at 59.9 s into a 60 s entry served that address for another 30 s —
/// 90 s after the resolution, contradicting their own documented bound
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
    // Memo first, and only then the clock: a memo hit costs two atomic loads
    // and a byte compare instead of two global read locks. The deadline lives
    // in the coarse epoch (see `expires_ms`), so even the hit path reads no
    // precise clock — only whole-second TTLs are at stake.
    let (pos, neg) = memo_peek_both(key);
    if pos.is_some() || neg.is_some() {
        let now = coarse_millis();
        if let Some(m) = pos {
            if now < m.expires_ms {
                return match m.addr {
                    Some(a) => (CachedLookup::Addr(a), m.expires_ms - now),
                    None => (CachedLookup::Unknown, 0),
                };
            }
        }
        if let Some(m) = neg {
            // The epoch check is what keeps a negative memo coherent with a
            // resolution that succeeded on another worker: the memo is
            // thread-private, so the global negative entry's removal cannot
            // reach it. Without the tag the recording worker kept answering
            // `Negative` — REFUSED datagrams, `dns negative cached` TCP
            // failures — for the rest of `DNS_NEG_TTL` while the cache held a
            // valid address. A stale tag simply falls through to the global
            // caches below, which are the authority either way.
            if now < m.expires_ms && m.neg_epoch == neg_epoch() {
                return (CachedLookup::Negative, 0);
            }
        }
    }
    // The clock is read **inside** each block, only once an entry actually has
    // to be compared against its deadline. A contended shard (`Unknown`) and a
    // full miss both return without needing it, and this lookup runs per domain
    // datagram while a name is cold — twice per datagram on the server
    // (`resolve_pin` then `forward_server_dgram`), so one vDSO read per call was
    // pure overhead on exactly the path that is already the expensive one. At
    // most one read happens either way: the positive block returns on a hit, and
    // the negative block is only reached when it missed.
    {
        let Some(m) = try_lock_read(dns_cache_for(key)) else {
            return (CachedLookup::Unknown, 0);
        };
        if let Some((t, v)) = m.get(key) {
            // Expiry is anchored to the global entry's insertion time, so the
            // memo can never outlive the cache TTL.
            let expires = *t + DNS_CACHE_TTL;
            let now = Instant::now();
            if now < expires {
                if let Some(a) = v.first().copied() {
                    memo_put(key, Some(a), expires);
                    return (
                        CachedLookup::Addr(a),
                        expires.saturating_duration_since(now).as_millis() as u64,
                    );
                }
            }
        }
    }
    {
        let Some(n) = try_lock_read(dns_neg_cache_for(key)) else {
            return (CachedLookup::Unknown, 0);
        };
        if let Some(t) = n.get(key) {
            let expires = *t + DNS_NEG_TTL;
            let now = Instant::now();
            if now < expires {
                memo_put(key, None, expires);
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

/// Full cached address set, read synchronously without spawning resolution.
///
/// The fast probe serves the first address only; when that one is filtered the
/// caller must scan the rest the way TCP does, but awaiting `resolve_all_cached`
/// on a packet path parks the reader task for up to a DNS timeout. This returns
/// the cached set — or `None` when it is not synchronously visible (contended
/// lock or expired entry) — so the caller stays off the async path whenever the
/// answer is already in memory.
pub fn lookup_cached_all_fast(host: &str, port: u16) -> Option<Arc<[SocketAddr]>> {
    lookup_cached_all_fast_with_ttl(host, port).map(|(v, _)| v)
}

/// [`lookup_cached_all_fast`] plus the remaining life of the set it returned.
///
/// Same contract as [`lookup_cached_fast_with_ttl`]: a caller that arms its own
/// deadline from a cached set must clamp against `ttl_ms`, or a set read at the
/// end of its life is re-used for the caller's whole (longer) TTL.
pub fn lookup_cached_all_fast_with_ttl(host: &str, port: u16) -> Option<(Arc<[SocketAddr]>, u64)> {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    let m = try_lock_read(dns_cache_for(key))?;
    let (t, v) = m.get(key)?;
    let expires = *t + DNS_CACHE_TTL;
    let now = Instant::now();
    if now < expires {
        Some((
            v.clone(),
            expires.saturating_duration_since(now).as_millis() as u64,
        ))
    } else {
        None
    }
}

/// Seed the positive DNS cache as if `host:port` had just resolved to `addr`.
///
/// Bin unit tests need this to exercise a DNS-hit path without a live
/// resolver; production always warms the cache through `resolve_all_cached`.
#[doc(hidden)]
pub fn dns_cache_seed(host: &str, port: u16, addr: SocketAddr) {
    dns_cache_seed_aged(host, port, addr, Duration::ZERO);
}

/// [`dns_cache_seed`] with an explicit entry age, so a test can drive the
/// "almost expired" case that `lookup_cached_fast_with_ttl` exists for.
///
/// `age` is subtracted from the entry's insertion instant (and from the memo's
/// deadline), i.e. the remaining life is `DNS_CACHE_TTL - age` — the input a TTL
/// clamp has to react to.
#[doc(hidden)]
pub fn dns_cache_seed_aged(host: &str, port: u16, addr: SocketAddr, age: Duration) {
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
    {
        let mut m = lock_write(dns_cache_for(key));
        m.insert(key.to_owned(), (inserted, Arc::from([addr])));
        evict_if_needed(&mut m);
    }
    clear_negative(key);
    memo_put(key, Some(addr), inserted + DNS_CACHE_TTL);
}

/// Seed the negative DNS cache as if `host:port` had just failed to resolve.
///
/// Same test-only purpose as [`dns_cache_seed`], for the other verdict: without
/// it a negative *memo* entry can only be produced by a real (network) resolver
/// failure, so the memo's coherence rules would be untestable.
#[doc(hidden)]
pub fn dns_neg_cache_seed(host: &str, port: u16) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    record_negative(key, Instant::now());
}

/// Seed the positive DNS cache with a full multi-record set, first record
/// first. Same test-only purpose as [`dns_cache_seed`]: the fast probe serves
/// only the first address, so a filtered-first multi-record name cannot be
/// exercised without seeding more than one.
#[doc(hidden)]
pub fn dns_cache_seed_set(host: &str, port: u16, addrs: &[SocketAddr]) {
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
    {
        let mut m = lock_write(dns_cache_for(key));
        m.insert(key.to_owned(), (now, Arc::from(addrs)));
        evict_if_needed(&mut m);
    }
    clear_negative(key);
    memo_put(key, Some(first), now + DNS_CACHE_TTL);
}

pub(crate) const DNS_CACHE_MAX: usize = 4096;
/// Per-shard positive-cache cap: shards share the process-wide total evenly,
/// so the aggregate bound stays `DNS_CACHE_MAX` while no single write lock
/// ever covers the whole table.
pub(crate) const DNS_CACHE_MAX_SHARD: usize = DNS_CACHE_MAX / DNS_SHARDS;
/// Per-shard negative-cache cap, same even split of `DNS_NEG_MAX`.
pub(crate) const DNS_NEG_MAX_SHARD: usize = DNS_NEG_MAX / DNS_SHARDS;

/// Batch eviction with a bounded write-lock hold: once the table crosses the
/// cap, drop enough entries in one pass to cover the whole overflow, then
/// leave the next few hundred inserts alone. Eviction is arbitrary (hash
/// order) rather than oldest-first on purpose: oldest-first needed a full
/// O(n) collect + `select_nth_unstable` plus per-victim key clones *while
/// holding the write lock*, stalling every DNS reader on the packet fast
/// path during a miss storm. Expired entries need no eager `retain` either:
/// reads already treat them as misses via the TTL check, so they just wait
/// for arbitrary eviction. Work per call is O(over) clones + removes.
pub(crate) fn evict_if_needed(m: &mut DnsMap<DnsCacheVal>) {
    const SLACK: usize = 32;
    if m.len() <= DNS_CACHE_MAX_SHARD + SLACK {
        return;
    }
    let over = m.len().saturating_sub(DNS_CACHE_MAX_SHARD);
    if over == 0 {
        return;
    }
    let victims: Vec<DnsCacheKey> = m.keys().take(over).cloned().collect();
    for k in victims {
        m.remove(&k);
    }
}

/// Single-flight registration hit a contended shard mutex. Distinct from a
/// failed lookup: nothing is known (the resolution may or may not be in
/// flight), so callers fail fast down the spawn path and count
/// `dgram_drops::DNS_CONTENTION` instead of charging a budget or policy
/// counter for what was only lock contention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsContended;

impl std::fmt::Display for DnsContended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dns single-flight shard contended")
    }
}

impl std::error::Error for DnsContended {}

/// Whether `err` is a [`DnsContended`] fail-fast from single-flight
/// registration, as opposed to a genuine resolution failure.
pub fn is_dns_contended(err: &anyhow::Error) -> bool {
    err.is::<DnsContended>()
}

/// Resolve with one fail-fast retry on single-flight contention, for callers
/// with no spawn fallback — the server TCP dial path only. UDP paths spawn a
/// resolver task on contention and must not use this.
///
/// A `DnsContended` here would otherwise kill a healthy TCP flow over
/// microseconds of shard-mutex hold time: the register critical section is one
/// hash lookup plus insert (no I/O), so yielding once lets the holder drain
/// and only a second *consecutive* contention fails the caller. The first
/// contention is counted even when the retry succeeds — the mutex was
/// genuinely busy, and the count is what makes a miss storm visible.
pub async fn resolve_all_cached_with_contention_retry(
    host: &str,
    port: u16,
) -> Result<Arc<[SocketAddr]>> {
    match resolve_all_cached(host, port).await {
        Err(e) if is_dns_contended(&e) => {
            dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
            tokio::task::yield_now().await;
            resolve_all_cached(host, port).await
        }
        r => r,
    }
}

pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Arc<[SocketAddr]>> {
    // Stack-built key: no allocation on the positive-cache fast path. The
    // fallback only triggers for hosts longer than the 255-byte wire limit.
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // 1. Positive cache. Try-lock: contended => treat as miss and fall
    // through to singleflight instead of parking this task.
    {
        if let Some(m) = try_lock_read(dns_cache_for(key)) {
            if let Some((t, v)) = m.get(key) {
                if t.elapsed() < DNS_CACHE_TTL {
                    return Ok(v.clone());
                }
            }
        }
    }
    // 2. Negative cache.
    {
        if let Some(n) = try_lock_read(dns_neg_cache_for(key)) {
            if let Some(t) = n.get(key) {
                if t.elapsed() < DNS_NEG_TTL {
                    anyhow::bail!("dns negative cached");
                }
            }
        }
    }
    // 3. Singleflight: exactly one owner resolves; everyone else waits on the
    //    cell. Ownership is claimed atomically. If the owner is cancelled or
    //    panics, `OwnerReset` clears the claim and wakes the waiters; the next
    //    waiter re-claims it, so no waiter can sleep forever on a cell that
    //    nobody will ever fill.
    let entry = {
        // Fail fast: parking this task on the shard mutex during a miss storm
        // would hold its slow-path permit (TCP) or stall the reply (spawned
        // UDP) for what is only lock contention. The caller counts the
        // `DnsContended` error as `DNS_CONTENTION` and takes the spawn path.
        let Some(mut inf) = try_lock_mutex(dns_inflight_for(key)) else {
            return Err(DnsContended.into());
        };
        match inf.get(key) {
            Some(c) => c.clone(),
            None => {
                let c = Arc::new(DnsInflightEntry {
                    key: key.to_owned(),
                    cell: tokio::sync::OnceCell::new(),
                    notify: tokio::sync::Notify::new(),
                    owner: std::sync::atomic::AtomicBool::new(false),
                });
                inf.insert(c.key.clone(), c.clone());
                c
            }
        }
    };
    loop {
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.swap(true, std::sync::atomic::Ordering::AcqRel) {
            break; // this caller is the owner
        }
        // Waiter: register before re-checking the cell (`notify_waiters` stores
        // no permit, so an unregistered waiter could otherwise miss completion).
        let notified = entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.load(std::sync::atomic::Ordering::Acquire) {
            // The owner died without publishing; yield once so N woken
            // waiters desynchronize instead of CAS-herding on `owner`.
            tokio::task::yield_now().await;
            continue;
        }
        notified.await;
    }

    // Owner path. Both guards live across the await: `_reset` releases the
    // claim and wakes waiters on any exit path, `cleanup` removes the inflight
    // entry once the caches are warm. Declared `_reset` then `cleanup`, so
    // drop runs `cleanup` first and `_reset` last; the explicit `drop(cleanup)`
    // below keeps that order (entry removed while the claim is still held).
    // Safe because publish (`cell.set` + `notify_waiters`) runs before either
    // drop, so a waiter that observes the cell also observes warm caches.
    let _reset = OwnerReset { entry: &entry };
    let cleanup = InflightCleanup { entry: &entry };

    // A racing caller may have completed and removed the inflight entry between
    // the initial cache checks and the registration above; re-check before
    // issuing a duplicate upstream lookup.
    {
        if let Some(m) = try_lock_read(dns_cache_for(key)) {
            if let Some((t, v)) = m.get(key) {
                if t.elapsed() < DNS_CACHE_TTL {
                    return Ok(v.clone());
                }
            }
        }
    }

    let r: Result<Arc<[SocketAddr]>, String> =
        match resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await {
            Ok(v) => Ok(Arc::from(v)),
            Err(e) => Err(format!("{e:#}")),
        };
    let now = Instant::now();
    // Warm the caches and the thread memo BEFORE publishing the result, so a
    // caller that observes the cell also observes a cache hit, and only the
    // owner ever pays for the insert + eviction sweep (previously every waiter
    // re-inserted and re-swept the whole map).
    match &r {
        Ok(v) => {
            {
                let mut m = lock_write(dns_cache_for(key));
                m.insert(key.to_owned(), (now, v.clone()));
                evict_if_needed(&mut m);
            }
            clear_negative(key);
            if let Some(a) = v.first().copied() {
                memo_put(key, Some(a), now + DNS_CACHE_TTL);
            }
        }
        Err(_) => record_negative(key, now),
    }
    let _ = entry.cell.set(r.clone());
    entry.notify.notify_waiters();
    drop(cleanup);
    match r {
        Ok(v) => Ok(v),
        Err(msg) => anyhow::bail!("{msg}"),
    }
}

/// Three-way positive-cache probe for [`record_negative`].
///
/// A contended shard is `Unknown`, not "absent": the entry behind it may be
/// perfectly valid, and treating contention as absence let a failed lookup
/// shadow a live positive answer (plus this thread's positive memo) with a
/// negative one. Callers that only need a fast-path hint keep using
/// `try_lock_read` miss semantics at their own call site; this helper exists
/// so the *write* path can fail open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PositiveState {
    Fresh,
    Absent,
    Unknown,
}

pub(crate) fn positive_entry_state(key: &str) -> PositiveState {
    let Some(m) = try_lock_read(dns_cache_for(key)) else {
        return PositiveState::Unknown;
    };
    if m.get(key).is_some_and(|(t, _)| t.elapsed() < DNS_CACHE_TTL) {
        PositiveState::Fresh
    } else {
        PositiveState::Absent
    }
}

/// Drop `key`'s negative cache entry because the name resolves now.
///
/// The single place that turns a "does not resolve" verdict into a good one, so
/// it is also the single place that has to invalidate the thread-local negative
/// memos derived from it (see [`bump_neg_epoch`]).
pub(crate) fn clear_negative(key: &str) {
    let removed = { lock_write(dns_neg_cache_for(key)).remove(key).is_some() };
    if removed {
        bump_neg_epoch();
    }
}

/// Record that resolving `key` failed, so the packet paths can refuse it without
/// spawning a resolver per datagram.
///
/// **Never downgrade a live positive answer.** The positive probes on the
/// resolution path are `try_lock_read`, so a *contended* — but perfectly valid —
/// entry makes the caller fall through to a real upstream lookup. If that
/// lookup then fails (SERVFAIL, timeout, an overloaded resolver), recording a
/// negative entry would shadow the valid answer: [`lookup_cached_fast`] consults
/// the thread-local memo before anything else and a memo set holds one slot per
/// key, so for `DNS_NEG_TTL` every datagram for that name is dropped as
/// `REFUSED` and every TCP flow fails with "dns negative cached" — while the
/// cached address was still good. The failure is still reported to the caller
/// that performed it; it just does not poison the cache.
pub(crate) fn record_negative(key: &str, now: Instant) {
    match positive_entry_state(key) {
        PositiveState::Fresh => return,
        // Fail open: on a contended shard the positive entry may be perfectly
        // valid. Recording a negative here would overwrite this thread's
        // positive memo (which the fast path trusts over the global positive
        // cache) and refuse the name for DNS_NEG_TTL while other threads keep
        // serving the good address. The lost shedding is bounded by the
        // slow-path limiter instead.
        PositiveState::Unknown => return,
        PositiveState::Absent => {}
    }
    {
        let mut n = lock_write(dns_neg_cache_for(key));
        // Bounded hold: evict one arbitrary entry instead of a full O(n)
        // `retain` scan under the write lock. Expired entries are already
        // treated as misses by the TTL check on read, so eager reaping buys
        // nothing while stalling every packet path reader during a
        // failing-domain flood. Per-shard cap keeps the process-wide total at
        // `DNS_NEG_MAX`.
        if n.len() >= DNS_NEG_MAX_SHARD {
            if let Some(k) = n.keys().next().cloned() {
                n.remove(&k);
            }
        }
        if n.len() < DNS_NEG_MAX_SHARD {
            n.insert(key.to_owned(), now);
        }
    }
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
}
