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
//!   for the lookup budget). A cached set retains at most
//!   [`DNS_CACHE_MAX_ADDRS`] addresses in preferred-family-first order: the
//!   cache is bounded in entries, not bytes, and a hostile authoritative server
//!   can answer with thousands of records.
//!   An entry past its freshness deadline is still **served** (RFC 8767
//!   serve-stale: see [`resolve_all_cached`]) while a background refresh —
//!   claimed once per name, drawn from its own permit pool — replaces it. That
//!   is what turns a TTL expiry from a stall into a repair: without it the first
//!   datagram after expiry waited a full upstream resolution (tens to hundreds
//!   of milliseconds) before leaving the server.
//! - **upstream**: hickory, cancellable, with its internal response cache
//!   disabled — the caches above are the only TTL authority (see
//!   [`upstream_resolver`]). When hickory cannot be built, the blocking
//!   `getaddrinfo` fallback runs under its own permit set so the timeout's
//!   inability to cancel it does not unbound live resolver threads.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::key::{
    DNS_HOST_KEY_BUF, DNS_KEY_BUF, dns_host_key, dns_host_key_owned, dns_key, dns_key_owned,
};
use super::memo::{bump_neg_epoch, memo_peek_both, memo_put, memo_put_with_epoch, neg_epoch};
use super::store::{
    DNS_CACHE_MAX, DNS_CACHE_MAX_ADDRS, DNS_CACHE_TTL, DNS_INCONCLUSIVE_TTL, DNS_LOOKUP_ATTEMPTS,
    DNS_LOOKUP_TIMEOUT, DNS_NEG_TTL, DNS_QUERY_TIMEOUT, DNS_RECORD_TTL_MAX, DNS_RECORD_TTL_MIN,
    DNS_STALE_MEMO_TTL, DNS_STALE_WINDOW, negatives, positives,
};
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
/// This is the path for callers that must not be served a cached answer
/// ([`resolve_all`]), and it is what the client's endpoint resolution used
/// before it moved onto the cache (see [`resolve_server_addrs`]). The shared caches only
/// ever hold port-free addresses, so this composes the same [`resolve_ips`]
/// primitive the cache-fill path uses and materializes the caller's port on the
/// way out.
async fn resolve_all_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let (ips, _) = resolve_ips(host, port, timeout)
        .await
        .map_err(LookupFailure::into_error)?;
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

/// Why a lookup produced no address set, split by what it says about the name.
///
/// The negative cache's TTL is a claim, so the two failure classes must not
/// share one: a **verdict** means the resolver answered that the name has no
/// address for us, and holding that for [`DNS_NEG_TTL`] is the point of the
/// cache; anything else — our own timeout, a saturated blocking fallback, a
/// name server that is down — says nothing about the name and may only be held
/// for the short [`DNS_INCONCLUSIVE_TTL`] backoff, or one transient blip would
/// refuse a perfectly good name on every port for 10 s.
#[derive(Debug)]
enum LookupFailure {
    /// The resolver answered: the name does not resolve.
    Verdict(anyhow::Error),
    /// No answer was obtained: timeout, saturation, transport/protocol error.
    Inconclusive(anyhow::Error),
}

impl LookupFailure {
    /// Classify a hickory lookup error. `NoRecordsFound` is the resolver
    /// reporting NXDOMAIN or NODATA — a fact about the name. Every other
    /// variant (`Timeout`, `Io`, `Proto`, `Busy`, `NoConnections`, …) is this
    /// process failing to reach an answer, which must not be cached as a
    /// verdict.
    fn from_resolver(err: hickory_resolver::net::NetError) -> Self {
        let verdict = err.is_no_records_found();
        let err = anyhow::anyhow!("dns lookup failed: {err}");
        if verdict {
            Self::Verdict(err)
        } else {
            Self::Inconclusive(err)
        }
    }

    /// How long a refusal derived from this failure may be cached.
    fn retry_ttl(&self) -> Duration {
        match self {
            Self::Verdict(_) => DNS_NEG_TTL,
            Self::Inconclusive(_) => DNS_INCONCLUSIVE_TTL,
        }
    }

    /// The underlying error, with its context chain intact.
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Verdict(e) | Self::Inconclusive(e) => e,
        }
    }
}

impl std::fmt::Display for LookupFailure {
    /// Renders the same `{e:#}` chain the plain `anyhow::Error` did, so the
    /// errors the callers hand back are unchanged by the classification.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verdict(e) | Self::Inconclusive(e) => write!(f, "{e:#}"),
        }
    }
}

/// The name to hand hickory for `host`: fully qualified when the target is
/// already a dotted name, untouched otherwise.
///
/// hickory tries the bare name first when it has more labels than `ndots`
/// (default 1), so a *successful* lookup of a dotted target costs one query
/// either way. The difference is the failure path: a relative name then walks
/// the whole resolv.conf search list, one serial round trip per suffix, before
/// the NXDOMAIN that produces the negative verdict. For a strict SOCKS target
/// the search list is never what was meant — `no-such-host.example.com` should
/// not become `no-such-host.example.com.corp.example` — so the dotted form is
/// both faster and more correct.
///
/// A single-label target (`intranet`, `printer`) keeps the search list: that is
/// the only way a short LAN name resolves at all. IP literals are left alone —
/// `lookup_ip` returns them without a query, and a trailing dot would make the
/// literal unparseable.
fn query_name(host: &str) -> std::borrow::Cow<'_, str> {
    let dotted = host.contains('.');
    if dotted && !host.ends_with('.') && host.parse::<IpAddr>().is_err() {
        std::borrow::Cow::Owned(format!("{host}."))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// Resolve just the addresses of `host` — no port — in the resolver's own
/// order, together with the TTL the answer asked to be cached for.
///
/// This is the upstream primitive behind both the uncached resolution path and
/// the host-keyed positive cache's init future: A/AAAA answers are independent
/// of the port the caller asked about, so the port is only carried along as the
/// `getaddrinfo` fallback's service hint (its returned ports are discarded).
/// The preference sort is applied by the callers, on their final address form —
/// `SocketAddr`s for the uncached path, `IpAddr`s before the cache insert — so
/// a cache hit always hands back a set in the same family order a fresh
/// resolution would.
///
/// The query is made fully qualified whenever the target already carries a dot
/// (see [`query_name`]): a search-list walk after a failure is one serial round
/// trip per suffix, and the failures are exactly the lookups whose cost the
/// negative cache's 10 s verdict is supposed to hide.
async fn resolve_ips(
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::result::Result<(Vec<IpAddr>, Duration), LookupFailure> {
    let query = query_name(host);
    let (ips, ttl) = tokio::time::timeout(timeout, async {
        let (ips, ttl): (Vec<IpAddr>, Duration) = match upstream_resolver() {
            // The IP-literal case is handled inside `lookup_ip` directly, and
            // the system hosts file is consulted before any upstream query
            // (`ResolveHosts::Auto` is the default; it compares against
            // fully-qualified keys, so the FQDN form below still matches
            // `/etc/hosts`), so `localhost` and other hosts entries keep
            // resolving.
            Ok(r) => match r.lookup_ip(query.as_ref()).await {
                Ok(lookup) => {
                    // The answer's own TTL — the minimum over its records, as
                    // hickory computes it for `valid_until`. This is what the
                    // name's owner asked us to cache for.
                    let ttl = lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now());
                    (lookup.iter().collect(), ttl)
                }
                Err(e) => return Err(LookupFailure::from_resolver(e)),
            },
            // The platform DNS configuration could not be read (see
            // `upstream_resolver`): degrade to the blocking `getaddrinfo` path
            // instead of losing name resolution entirely. That path is bounded
            // by its own permit set, because its work cannot be cancelled by
            // the timeout wrapping this future (see [`getaddrinfo_ips`]).
            Err(why) => {
                tracing::debug!("hickory resolver unavailable ({why}); using getaddrinfo");
                // `getaddrinfo` reports no TTL: the documented default applies,
                // clamped like any other answer.
                (getaddrinfo_ips(host, port).await?, DNS_CACHE_TTL)
            }
        };
        Ok::<(Vec<IpAddr>, Duration), LookupFailure>((ips, ttl))
    })
    .await
    .map_err(|_| {
        // The budget is ours, not the resolver's: we gave up waiting. The
        // name's status is unknown, so this must never become a verdict.
        LookupFailure::Inconclusive(anyhow::anyhow!("dns lookup timed out after {timeout:?}"))
    })??;
    Ok((ips, ttl))
}

/// Permits for the blocking `getaddrinfo` fallback.
///
/// One permit owns one Tokio blocking-pool thread for the whole libc resolver
/// call. The outer [`DNS_LOOKUP_TIMEOUT`] cannot stop that call: dropping the
/// future detaches the `spawn_blocking` closure (dropping a `JoinHandle` does
/// not abort it), so a permit released on future-drop would let a timed-out
/// caller start another libc resolve while the previous one still runs — the
/// limiter would then bound *waiters*, not live resolver work. The permit is
/// therefore acquired inside the blocking closure and released only when the
/// thread returns.
pub(crate) const DNS_BLOCKING_FALLBACK_PERMITS: usize = 128;

/// Process-wide permit set for [`getaddrinfo_ips`]. See
/// [`DNS_BLOCKING_FALLBACK_PERMITS`] for why the permit must outlive the
/// future.
fn dns_blocking_fallback_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(DNS_BLOCKING_FALLBACK_PERMITS))
    })
}

/// Resolve `(host, port)` through the platform's blocking `getaddrinfo`,
/// bounded by [`DNS_BLOCKING_FALLBACK_PERMITS`].
///
/// Runs in a `spawn_blocking` closure because `ToSocketAddrs` is synchronous.
/// The permit is taken *inside* that closure so it is held until the libc call
/// actually returns, not until this future is dropped: the caller's timeout can
/// abandon this future while the thread keeps running, and the bound has to
/// cover the thread. Exhaustion fails fast with a clear error instead of letting
/// the blocking pool grow to `max_blocking_threads`; the failure is then
/// single-flighted and cached as an *inconclusive* one by the callers (a
/// [`DNS_INCONCLUSIVE_TTL`] backoff, not a verdict).
///
/// Every failure of this path is inconclusive on purpose: libc gives no portable
/// way to tell "this name does not exist" from `EAI_AGAIN`, and this path only
/// runs at all when hickory could not be built — a state in which claiming a
/// verdict about a name is the least defensible thing we could do.
async fn getaddrinfo_ips(host: &str, port: u16) -> std::result::Result<Vec<IpAddr>, LookupFailure> {
    use std::net::ToSocketAddrs as _;
    let host = host.to_owned();
    let limiter = std::sync::Arc::clone(dns_blocking_fallback_limiter());
    let ips =
        tokio::task::spawn_blocking(move || -> std::result::Result<Vec<IpAddr>, LookupFailure> {
            let _permit = limiter.try_acquire_owned().map_err(|_| {
                LookupFailure::Inconclusive(anyhow::anyhow!(
                    "dns getaddrinfo fallback saturated ({DNS_BLOCKING_FALLBACK_PERMITS} blocking \
                     resolvers already running)"
                ))
            })?;
            let ips: Vec<IpAddr> = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| {
                    LookupFailure::Inconclusive(anyhow::Error::new(e).context("getaddrinfo"))
                })?
                .map(|sa| sa.ip())
                .collect();
            Ok(ips)
        })
        .await
        .map_err(|e| {
            // A panicked blocking task: our bug, not a fact about the name.
            LookupFailure::Inconclusive(anyhow::Error::new(e).context("getaddrinfo task join"))
        })??;
    Ok(ips)
}

/// Configure a hickory resolver for use behind this module's caches.
///
/// `cache_size = 0` disables hickory's internal response cache: hickory backs
/// it with a moka cache sized to this capacity, and a zero-capacity moka map is
/// disabled (inserts are no-ops and no housekeeping runs). The max-TTLs are
/// kept anyway, as defence in depth for anything that does not pass through the
/// outer caches (the hosts-file lookup / IP literals) and to keep the
/// resolver's own clamping consistent with the documented windows.
///
/// The per-attempt timeout and retry count are *derived* from the module's wall
/// ([`DNS_LOOKUP_TIMEOUT`]): hickory's defaults (5 s per attempt, 2 retries)
/// were the same 5 s as the wall, so the first attempt could consume the whole
/// budget and the retries never ran. [`DNS_QUERY_TIMEOUT`] documents the sizing.
///
/// Pure so the "hickory is not a second TTL authority" invariant is pinned by
/// a unit test.
fn configure_resolver_options(opts: &mut hickory_resolver::config::ResolverOpts) {
    // hickory clamps the TTLs of every answer it returns to this window, even
    // with its cache disabled (`ResponseCache::clamp_positive_ttls` rewrites the
    // TTLs before the `Lookup` is built). The ceiling therefore has to be the
    // store's own record-TTL cap, not the default 120 s window: with the old
    // value the outer cache could never see a TTL above 120 s, so a name whose
    // owner asked for 300 s was still re-resolved early.
    opts.positive_max_ttl = Some(DNS_RECORD_TTL_MAX);
    opts.negative_max_ttl = Some(DNS_NEG_TTL);
    opts.cache_size = 0;
    opts.timeout = DNS_QUERY_TIMEOUT;
    opts.attempts = DNS_LOOKUP_ATTEMPTS;
}

/// How often [`spawn_resolver_watch`] re-reads the platform's DNS
/// configuration. Long enough to be free (one file read on Linux/OpenWrt, one
/// dynamic-store query on macOS), short enough that a VPN coming up is picked
/// up before the stale window it would otherwise hide behind.
pub const RESOLVER_CONFIG_POLL: Duration = Duration::from_secs(30);

/// One generation of the process-wide upstream resolver.
struct ResolverGen {
    /// `Err` is the do-not-use-hickory signal for the `getaddrinfo` fallback;
    /// the reason is logged when the generation is built.
    resolver: Result<std::sync::Arc<hickory_resolver::TokioResolver>, String>,
    /// Nameserver addresses and search list this generation was built from, in
    /// a form that compares cheaply. Empty when the platform configuration
    /// could not be read at all.
    fingerprint: Vec<String>,
}

impl ResolverGen {
    fn error(reason: String, fingerprint: Vec<String>) -> Self {
        tracing::warn!(
            "hickory resolver init failed ({reason}); dns lookups fall back to getaddrinfo"
        );
        Self {
            resolver: Err(reason),
            fingerprint,
        }
    }
}

/// The platform configuration's nameservers and search list, as strings.
///
/// Only used to decide "did the network's DNS configuration change?", so it
/// covers exactly what a rebuild would pick up: the servers a query is sent to
/// and the suffixes a bare name is expanded with.
fn config_fingerprint(config: &hickory_resolver::config::ResolverConfig) -> Vec<String> {
    let mut f: Vec<String> = config
        .name_servers()
        .iter()
        .map(|ns| ns.ip.to_string())
        .collect();
    if let Some(domain) = config.domain() {
        f.push(domain.to_string().to_ascii_lowercase());
    }
    f.extend(
        config
            .search()
            .iter()
            .map(|name| name.to_string().to_ascii_lowercase()),
    );
    f
}

/// Read the platform configuration and build a resolver generation from it.
///
/// Blocking by design: reading the System Configuration dynamic store is a
/// syscall plus a plist parse, and parsing `resolv.conf` touches the
/// filesystem. Both callers (`spawn_resolver_watch` and the tests) run it off a
/// runtime worker.
fn build_resolver_gen() -> ResolverGen {
    let (config, _options) = match hickory_resolver::system_conf::read_system_conf() {
        Ok(pair) => pair,
        Err(e) => return ResolverGen::error(e.to_string(), Vec::new()),
    };
    let fingerprint = config_fingerprint(&config);
    tracing::info!(
        nameservers = ?config
            .name_servers()
            .iter()
            .map(|ns| ns.ip.to_string())
            .collect::<Vec<_>>(),
        domain = ?config.domain().map(|d| d.to_string()),
        search = ?config
            .search()
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>(),
        "dns resolver configuration"
    );
    let mut builder = hickory_resolver::TokioResolver::builder_with_config(
        config,
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    );
    configure_resolver_options(builder.options_mut());
    match builder.build() {
        Ok(resolver) => ResolverGen {
            resolver: Ok(std::sync::Arc::new(resolver)),
            fingerprint,
        },
        Err(e) => ResolverGen::error(e.to_string(), fingerprint),
    }
}

/// The current resolver generation (built on first access).
///
/// A plain `OnceLock` meant the resolver was built from whatever the platform
/// configuration said *at the first lookup* and never re-read: after a Wi-Fi
/// change, a VPN coming up or a DHCP renewal the process kept querying
/// nameservers that were no longer reachable, and every cold name paid the full
/// lookup budget until it gave up. Serve-stale then *hid* that failure behind
/// its window. Now the generation is swappable and [`spawn_resolver_watch`]
/// replaces it when the configuration changes.
fn resolver_gen() -> &'static arc_swap::ArcSwap<ResolverGen> {
    static GEN: std::sync::OnceLock<arc_swap::ArcSwap<ResolverGen>> = std::sync::OnceLock::new();
    GEN.get_or_init(|| arc_swap::ArcSwap::from_pointee(build_resolver_gen()))
}

/// Warm the resolver and keep following the platform's DNS configuration.
///
/// Idempotent; the binaries call it once at startup. The first build runs in a
/// blocking task, so the process's *first* lookup never pays for reading the
/// platform configuration (nor blocks a worker doing it), and each poll
/// compares the nameserver/search fingerprint before rebuilding — a rebuild is
/// a new [`hickory_resolver::TokioResolver`], so lookups already in flight
/// simply finish on the generation they started with.
pub fn spawn_resolver_watch() {
    static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async {
        // Warm: build the first generation off the runtime.
        if let Err(e) = tokio::task::spawn_blocking(|| {
            let _ = resolver_gen().load();
        })
        .await
        {
            tracing::debug!("dns resolver warm-up task failed ({e})");
        }
        loop {
            tokio::time::sleep(RESOLVER_CONFIG_POLL).await;
            let fresh = tokio::task::spawn_blocking(|| {
                hickory_resolver::system_conf::read_system_conf()
                    .ok()
                    .map(|(config, _)| config_fingerprint(&config))
            })
            .await
            .ok()
            .flatten();
            let Some(fresh) = fresh else { continue };
            if resolver_gen().load().fingerprint == fresh {
                continue;
            }
            match tokio::task::spawn_blocking(build_resolver_gen).await {
                Ok(next) => {
                    tracing::info!("dns configuration changed; rebuilt the upstream resolver");
                    resolver_gen().store(std::sync::Arc::new(next));
                }
                Err(e) => tracing::debug!("dns resolver rebuild task failed ({e})"),
            }
        }
    });
}

/// Process-wide upstream resolver, built from the platform's own DNS
/// configuration: resolv.conf on Linux/OpenWrt, the System Configuration
/// dynamic store on macOS. Its lookups are cancellable async futures, so the
/// `timeout` wrapper around the caller actually stops the work instead of
/// leaving a thread to finish it after the caller gave up.
///
/// The *fallback* when this resolver cannot be built is the blocking
/// `getaddrinfo` path ([`getaddrinfo_ips`]), which the same timeout cannot
/// cancel. That fallback therefore has its own permit set
/// ([`DNS_BLOCKING_FALLBACK_PERMITS`]) held until the blocking thread returns,
/// so a failed hickory init cannot turn the DNS budget into an unbounded number
/// of live libc resolver calls.
///
/// Its internal response cache is disabled (see
/// [`configure_resolver_options`]): the moka caches above (per-record positive,
/// [`DNS_NEG_TTL`] negative) plus their per-thread memos and moka's
/// single-flight are the only TTL authority. An earlier revision left hickory's
/// cache *enabled* with a TTL window of its own; because the two were
/// independent stores, hickory could serve an entry for its whole TTL *after*
/// the outer entry expired — up to ~240 s stale — and its hits bypassed the
/// thread memo the packet paths rely on to avoid even a cache probe.
///
/// hickory still *clamps* the TTL of every answer it returns, cache or not
/// (`ResponseCache::clamp_positive_ttls` rewrites the message before the
/// `Lookup` is built), so [`configure_resolver_options`] sets that clamp to
/// [`DNS_RECORD_TTL_MAX`] — the store's own ceiling. The clamp can therefore
/// never shorten a life the store would honour, and the store's `time_to_live`
/// (`DNS_RECORD_TTL_MAX + DNS_STALE_WINDOW`) is the only eviction bound.
fn upstream_resolver() -> Result<std::sync::Arc<hickory_resolver::TokioResolver>, String> {
    let generation = resolver_gen().load();
    match &generation.resolver {
        Ok(resolver) => Ok(std::sync::Arc::clone(resolver)),
        Err(reason) => Err(reason.clone()),
    }
}

/// Concurrent resolver waiters the DNS slow path admits process-wide.
///
/// A permit is held for the lifetime of a spawned UDP resolution waiter (the
/// datagram paths hand their payload to the task, so the wait is a real task,
/// not just a future) and of the server's TCP dial-time lookup. This is both
/// the concurrency cap and the memory bound admission charges
/// (`config::tuning::dns_inflight_memory_bytes`): each waiter can pin a
/// max-size datagram payload, a 255-byte host name, and its task/future
/// structure.
pub const DNS_SLOW_PATH_PERMITS: usize = 1024;

/// Process-wide budget for spawned resolution work (UDP waiter tasks and the
/// server's TCP dial path share it). Exhaustion fails fast — a datagram or
/// dial is refused and counted as `DNS_BUDGET` — instead of parking callers
/// behind an unbounded queue.
pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(DNS_SLOW_PATH_PERMITS)))
}

/// Permits for **background** refreshes (serve-stale repairs).
///
/// Deliberately a separate pool from [`dns_slow_path_limiter`]: a burst of
/// expired entries must never consume the admission budget of the datagrams
/// that have *no* answer to serve, whose latency the slow path exists to bound.
/// A refresh is best-effort — a refused refresh leaves the stale entry serving
/// until the next stale hit — so this count is smaller than the foreground pool
/// and is not charged by `config::tuning::dns_inflight_memory_bytes` (a refresh
/// holds a task and a lookup, not a staged maximum-size datagram payload).
const DNS_REFRESH_PERMITS: usize = 256;

fn dns_refresh_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(DNS_REFRESH_PERMITS)))
}

/// Result of a synchronous cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedLookup {
    /// An address is cached in this thread's memo: still fresh, or served stale
    /// while a background refresh runs (that memo life is at most
    /// [`DNS_STALE_MEMO_TTL`], so the packet path returns to the async path that
    /// can schedule the refresh). Either way it is the best answer available
    /// without waiting.
    Addr(SocketAddr),
    /// A negative entry says the name does not resolve right now; do not spawn a
    /// resolver task for this packet. The memo life is the refusal's remaining
    /// backoff ([`DNS_NEG_TTL`] for a verdict, [`DNS_INCONCLUSIVE_TTL`] for a
    /// lookup that produced no answer).
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
/// lookup is negatively cached (host-keyed refusal + this port's memo) inside
/// the init, before the error is published to any waiter: the old
/// publish-order contract, kept. How long that refusal lasts depends on what
/// the failure says about the name — see [`LookupFailure`].
///
/// **Lookup order.** A warm positive entry is probed *first*: it is the common
/// outcome for a name this process resolved in the last [`DNS_CACHE_TTL`], and
/// it needs no negative verdict to disambiguate it. The positive and negative
/// stores are disjoint by construction (a negative is only written by the
/// single-flight init that ran because no positive entry existed, and a
/// successful resolution clears it before publishing its entry — see
/// `record_refusal` and `seed_positive`), so probing positive first cannot
/// serve an address for a refused name. The negative probe then runs only on a
/// positive miss, where it keeps its job: refuse a known-bad name without
/// touching the single-flight machinery. This removes one hashed `moka` probe
/// from every warm hit — the store's whole reason to exist is that the slow
/// path should answer without an upstream query, and the warm hit is what the
/// per-thread DNS memo falls back to for a new port or after its TTL.
///
/// Whether a positive entry read from the store is still fresh, and if so how
/// much life it has left.
///
/// Answers from the entry's own freshness deadline, never from a remaining-life
/// query (moka has none for `time_to_live` caches): the cache keeps an entry for
/// the longest record TTL *plus* the stale window that lets it still answer
/// after that, so "is it resident" and "is it fresh" stopped being the same
/// question. `None` means stale — servable, but it owes a refresh.
///
/// The deadline comes from the answer itself ([`record_ttl`]), not from a flat
/// constant: a 30 s-TTL name used to stay "fresh" for 120 s (stale data served
/// as if current), and a 300 s-TTL name was re-resolved two to five times more
/// often than its owner asked for.
fn positive_life(deadline: Instant, now: Instant) -> Option<Duration> {
    (deadline > now).then(|| deadline - now)
}

/// The freshness window an answer may have: its own TTL, clamped to
/// [`DNS_RECORD_TTL_MIN`]..[`DNS_RECORD_TTL_MAX`].
fn record_ttl(ttl: Duration) -> Duration {
    ttl.clamp(DNS_RECORD_TTL_MIN, DNS_RECORD_TTL_MAX)
}

/// `Err` covers three cases with distinct meanings for the caller: a live
/// negative entry ("dns negative cached" — a policy refusal, whose remaining
/// life is the entry's own deadline), a resolution failure the resolver
/// reported as a verdict, and a lookup that produced no answer at all (a
/// short-backoff [`LookupFailure::Inconclusive`]).
///
/// **Stale serving.** An entry past its [`DNS_CACHE_TTL`] but still resident
/// (the store keeps it for the stale window) is returned immediately and a
/// background refresh is started, instead of blocking this caller on a fresh
/// lookup. That is the difference between a TTL cliff and a repair: the
/// datagram that arrives one millisecond after a popular name expires is
/// answered from the last known answer — the same address the previous
/// datagram was sent to — and the refresh lands beside it. The caller cannot
/// tell the two paths apart, by design; the entry it receives is a valid
/// answer either way, and the shorter memo life ([`DNS_STALE_MEMO_TTL`]) brings
/// the packet path back here to observe the repaired entry.
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
    //
    // A hit past the entry's freshness deadline is served just the same — see
    // the stale-serving note on this function — with one addition: it owes a
    // background refresh, claimed here so a burst of datagrams for the same
    // expired name starts exactly one upstream query, not one per datagram.
    if let Some((deadline, ips)) = positives().get(host_key).await {
        if positive_life(deadline, Instant::now()).is_none() {
            request_refresh(host_key, port);
        }
        return Ok(materialize_cached(memo_key, deadline, &ips, port));
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
    // it is read off the entry's own stored deadline, which the negative cache
    // keeps for exactly this reason.
    //
    // The epoch is sampled **before** the probe. A concurrent success removes
    // the negative entry and bumps `NEG_EPOCH`; if this write sampled the epoch
    // afterwards (as `memo_put` does) it would tag the just-read verdict with
    // the new epoch, the fast path would trust it as current, and this thread
    // would keep refusing a name that now resolves for up to `DNS_NEG_TTL`.
    // `memo_put_with_epoch` re-checks the epoch at publication and drops the
    // write if it moved; the shared caches stay the authority either way.
    let epoch_before_probe = neg_epoch();
    if let Some(expires_at) = negatives().get(host_key).await {
        // The entry stores its own deadline (a 10 s verdict, or a 1 s
        // inconclusive backoff — see [`LookupFailure`]), so the remaining life
        // is read off it rather than derived from a fixed TTL.
        let remaining = expires_at.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            let _ = memo_put_with_epoch(
                memo_key,
                None,
                Instant::now() + remaining,
                epoch_before_probe,
            );
            anyhow::bail!("dns negative cached");
        }
        // Logically expired but still resident (moka's own 10 s TTL is only an
        // eviction bound above the per-entry deadline): fall through to a fresh
        // lookup. The entry is left in place on purpose — removing it here could
        // delete a *fresher* refusal another thread just wrote for this name,
        // and `try_get_with_by_ref` below already single-flights the re-lookup.
    }
    let outcome = positives()
        .try_get_with_by_ref(host_key, async {
            match resolve_ips(host, port, DNS_LOOKUP_TIMEOUT).await {
                Ok((ips, ttl)) => {
                    let now = Instant::now();
                    // The cache's invariant: every stored set is ordered with
                    // the configured preferred family first (the resolver's own
                    // order within a family is kept by the stable sort), so a
                    // hit for another port hands back the same order a fresh
                    // resolution would. The retained set is then capped: a DNS
                    // answer can carry thousands of A/AAAA records (a truncated
                    // UDP answer is retried over TCP), and the cache is bounded
                    // in entries, not bytes (`store::DNS_CACHE_MAX_ADDRS`).
                    // Every consumer uses at most 16 addresses, so the cap
                    // bounds memory without changing which address leads.
                    let ips = prepare_cache_ips(ips);
                    let ips: Arc<[IpAddr]> = Arc::from(ips);
                    // The entry's freshness deadline is the answer's own TTL,
                    // clamped; the stale window is what makes it outlive that
                    // deadline in the cache.
                    let deadline = now + record_ttl(ttl);
                    // A success clears the negative entry (the name resolves
                    // now) and bumps the epoch so other threads' stale
                    // negative memos stop refusing. Done before returning, so
                    // it precedes every waiter wake-up.
                    if negatives().remove(host_key).await.is_some() {
                        bump_neg_epoch();
                    }
                    Ok((deadline, ips))
                }
                Err(failure) => {
                    // Negatively cache the *name*, so every port of it is
                    // refused after one failure, and memoize this port too so
                    // the sync packet path refuses this exact target without
                    // spawning a resolver. Other ports hit the shared host
                    // verdict above, which memoizes their own port there.
                    //
                    // The TTL comes from the failure's class: a name the
                    // resolver actually answered for is refused for
                    // `DNS_NEG_TTL`, while a lookup that never got an answer
                    // (timeout, saturated fallback) is only held off for the
                    // short `DNS_INCONCLUSIVE_TTL` backoff.
                    record_refusal(host_key, memo_key, failure.retry_ttl()).await;
                    Err(failure.to_string())
                }
            }
        })
        .await;
    match outcome {
        // The init owner and every single-flight waiter land here; the helper
        // also runs for the warm-hit arm above, so the port attachment and the
        // per-thread memo write can never drift between the two paths.
        Ok((deadline, ips)) => Ok(materialize_cached(memo_key, deadline, &ips, port)),
        Err(e) => {
            // The refusal was published inside the init future, where a probe of
            // the same key would deadlock (see the helper). A background refresh
            // may have answered the name in the meantime; outside the
            // single-flight that is safe to check and repair.
            withdraw_refusal_if_answered(host_key, memo_key, port).await;
            Err(anyhow::anyhow!("{e}"))
        }
    }
}

/// Order a resolved answer preferred-family-first and cap what the positive
/// cache retains ([`DNS_CACHE_MAX_ADDRS`]).
///
/// The order is part of the cache's contract: every stored set is ordered with
/// the configured preferred family first (the resolver's own order within a
/// family is kept by the stable sort), so a hit for another port hands back the
/// same order a fresh resolution would. The cap bounds the cache's bytes — it
/// is capacity-bounded in entries only — while keeping the head of that order,
/// which is the only part any consumer reads first.
fn prepare_cache_ips(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let pref = ip_preference();
    ips.sort_by_key(|ip| pref.sort_key_ip(*ip));
    ips.truncate(DNS_CACHE_MAX_ADDRS);
    ips
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
/// entry's remaining life (never extended); a **stale** entry is memoized for
/// [`DNS_STALE_MEMO_TTL`] instead, which is what lets the packet path keep
/// answering it while still returning to `resolve_all_cached` — the only place
/// that can schedule the repair — once per [`DNS_STALE_MEMO_TTL`].
fn materialize_cached(
    memo_key: &str,
    deadline: Instant,
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
        let now = Instant::now();
        // A fresh entry is memoized for exactly its remaining life, so the sync
        // probe can never outlive the store. A stale one gets the *short* stale
        // memo life rather than no memo at all: the packet path keeps answering
        // the published answer without returning to this async path on every
        // datagram, but it does come back within `DNS_STALE_MEMO_TTL` — and this
        // path is the only one that can schedule the refresh. (Writing no memo
        // for a stale entry would put every datagram of an expired-but-served
        // flow on the resolver-task slow path.)
        let memo_deadline = match positive_life(deadline, now) {
            Some(life) => now + life,
            None => {
                // Never memoize past the point where the entry itself leaves
                // the cache, or the sync probe would keep answering an address
                // the store has forgotten.
                let leaves = deadline + DNS_STALE_WINDOW;
                now + DNS_STALE_MEMO_TTL.min(leaves.saturating_duration_since(now))
            }
        };
        memo_put(memo_key, Some(first), memo_deadline);
    }
    addrs
}

/// How long a name is left alone after a refresh attempt, successful or not.
///
/// The claim below already collapses concurrent attempts to one, but a *failed*
/// attempt used to release its claim immediately, so the next stale hit — and
/// with upstream DNS down every hit is a stale hit — started another lookup.
/// The result was a retry loop paced by request rate rather than by time, on top
/// of the same upstream that is failing. This is the floor between attempts, per
/// name, independent of how many flows want one.
const DNS_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

/// Names with a refresh in flight, or one that failed within the cooldown.
///
/// The value is the earliest instant a *new* attempt may start; a running
/// attempt reserves its own slot until `DNS_LOOKUP_TIMEOUT + cooldown`, and the
/// claim's `Drop` rewrites that to `now + DNS_REFRESH_COOLDOWN`, so a crashed or
/// cancelled task cannot wedge a name forever.
fn refresh_registry() -> &'static parking_lot::Mutex<std::collections::HashMap<Arc<str>, Instant>> {
    static REGISTRY: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::HashMap<Arc<str>, Instant>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

/// Drop-guard for one name's refresh slot; leaves the cooldown running when the
/// attempt ends, including on cancellation.
struct RefreshClaim(Arc<str>);

impl Drop for RefreshClaim {
    fn drop(&mut self) {
        let until = Instant::now() + DNS_REFRESH_COOLDOWN;
        if let Some(slot) = refresh_registry().lock().get_mut(&*self.0) {
            *slot = (*slot).min(until);
        }
    }
}

/// Claim `host_key`'s refresh slot, or `None` while one is running or cooling
/// down.
fn claim_refresh(host_key: &str, now: Instant) -> Option<RefreshClaim> {
    let mut registry = refresh_registry().lock();
    if registry.get(host_key).is_some_and(|until| *until > now) {
        return None;
    }
    // The registry is keyed by name, so a long-lived process that sees many
    // failing names could grow it without bound. Prune on the way in, and give
    // up rather than exceed the cache's own entry budget.
    if registry.len() >= DNS_CACHE_MAX {
        registry.retain(|_, until| *until > now);
    }
    if registry.len() >= DNS_CACHE_MAX {
        return None;
    }
    let key: Arc<str> = Arc::from(host_key);
    registry.insert(
        Arc::clone(&key),
        now + DNS_LOOKUP_TIMEOUT + DNS_REFRESH_COOLDOWN,
    );
    Some(RefreshClaim(key))
}

/// Start the repair for a stale entry that was just served.
///
/// Deliberately detached: the datagram or dial that read the stale entry is
/// answered now, and the lookup that will make the *next* one fresh happens
/// beside it. The positive cache's `try_get_with` single flight cannot be
/// reused for this — a present (stale) entry is a hit, so that call would hand
/// back the stale value instead of running the init — hence [`RefreshClaim`].
fn request_refresh(host_key: &str, port: u16) {
    let Some(claim) = claim_refresh(host_key, Instant::now()) else {
        return;
    };
    tokio::spawn(async move {
        let claim = claim;
        refresh_positive(&claim.0, port).await;
    });
}

/// Re-resolve `host_key` and replace its stale entry, if the lookup succeeds.
///
/// A failure changes nothing: the stale entry keeps serving (that is the whole
/// point of the window), and no negative entry is written — the name demonstrably
/// resolves, we are answering from its own previous answer, and a refusal would
/// both flip the sync path's memo to `Negative` for a working name and break the
/// positive/negative disjointness the cache contract rests on. Retries are the
/// next stale hit's job; the stale memo life bounds how soon that can happen and
/// [`DNS_REFRESH_COOLDOWN`] bounds how often, so a failing upstream is polled on
/// a fixed schedule instead of at request rate.
async fn refresh_positive(host_key: &str, port: u16) {
    // Background work draws from its own pool, never from the foreground
    // admission budget `dns_slow_path_limiter` bounds: a burst of expired
    // entries must not queue in front of the datagrams that have no answer at
    // all — those are the ones whose latency this budget exists for. A refusal
    // is not a failure: the stale entry keeps answering and the next stale hit
    // asks again.
    let Ok(_permit) = dns_refresh_limiter().clone().try_acquire_owned() else {
        return;
    };
    if let Ok((ips, ttl)) = resolve_ips(host_key, port, DNS_LOOKUP_TIMEOUT).await {
        let now = Instant::now();
        // A foreground resolution may have refreshed the entry while this
        // lookup was in flight. Best effort: this check and the `insert` below
        // are not atomic, so a foreground write landing between them can be
        // replaced by this older answer. Both are valid answers for the name and
        // the freshness deadline only moves earlier, so the cost is one early
        // re-resolve at worst — not worth a second lock on the serving path.
        let already_fresh = positives()
            .get(host_key)
            .await
            .is_some_and(|(deadline, _)| positive_life(deadline, now).is_some());
        if already_fresh {
            return;
        }
        let deadline = now + record_ttl(ttl);
        let ips: Arc<[IpAddr]> = Arc::from(prepare_cache_ips(ips));
        // A plain `insert`, not `try_get_with`: this replaces a value that is
        // serving traffic, and the callers of the stale path must not wait for
        // it.
        positives()
            .insert(host_key.to_owned(), (deadline, ips))
            .await;
        // The name resolves, so any refusal it accumulated must go — the same
        // bookkeeping a foreground success does, for the same reason
        // (`resolve_all_cached`'s negative probe would otherwise keep the name
        // refused once this entry ages out).
        if negatives().remove(host_key).await.is_some() {
            bump_neg_epoch();
        }
    }
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
    mut ips: Vec<IpAddr>,
    memo_addr: Option<SocketAddr>,
    age: Duration,
) {
    let host_key = dns_host_key_owned(host);
    let memo_key = dns_key_owned(host, port);
    let now = Instant::now();
    // `age` is how long ago the entry was resolved, so its freshness deadline is
    // the default TTL minus that age (seeds describe entries the production path
    // would have written with [`DNS_CACHE_TTL`]).
    let deadline = (now + DNS_CACHE_TTL).checked_sub(age).unwrap_or(now);
    // Keep the test-only seeds under the same retained-set bound as production
    // inserts (the invariant is what the cache and its readers assume).
    ips.truncate(DNS_CACHE_MAX_ADDRS);
    positives()
        .insert(host_key.clone(), (deadline, Arc::from(ips)))
        .await;
    if negatives().remove(host_key.as_str()).await.is_some() {
        bump_neg_epoch();
    }
    if let Some(addr) = memo_addr {
        memo_put(&memo_key, Some(addr), deadline);
    }
}

/// Record that resolving the name `host_key` failed, for `ttl`.
///
/// The shared entry is host-keyed (every port refuses) and the value is the
/// instant the refusal **expires**, so a caller that finds it while asking about
/// another port can memoize *that* port for exactly the life the verdict has
/// left. `memo_key` is this thread's per-`(host, port)` memo entry, given the
/// same deadline.
///
/// Runs inside [`resolve_all_cached`]'s init future, before the error is
/// published to waiters; the single-flight serialization is what makes the
/// write safe — no live positive entry can exist while the init that writes
/// this runs (the old "never downgrade a live positive" probe guarded a
/// contention window that no longer exists).
async fn record_refusal(host_key: &str, memo_key: &str, ttl: Duration) {
    let now = Instant::now();
    let expires = now + ttl;
    // Sample the epoch before publishing the shared verdict, then fence the
    // thread-memo write on it: an unrelated success that bumps `NEG_EPOCH` in
    // between must not produce a memo tagged as newer than the entry it was
    // derived from (see `memo_put_with_epoch`). A dropped write only costs this
    // thread one slow-path probe on its next lookup; the shared negative entry
    // is still the authority for every port.
    let epoch = neg_epoch();
    negatives().insert(host_key.to_owned(), expires).await;
    let _ = memo_put_with_epoch(memo_key, None, expires, epoch);
}

/// Record a **verdict**: the resolver answered that the name does not resolve.
/// The seeding helper and its tests use this entry point; production failures go
/// through [`record_refusal`] with the TTL their class earns.
async fn record_negative(host_key: &str, memo_key: &str) {
    record_refusal(host_key, memo_key, DNS_NEG_TTL).await;
}

/// Withdraw a refusal that a background refresh has just falsified.
///
/// [`record_refusal`] runs inside the positive cache's init future, where a
/// same-key probe is not allowed: moka holds the key's single-flight for the
/// whole init, so a `positives().get(..)` from inside it waits for itself. A
/// refresh can still finish in between — it writes with a plain `insert` (it
/// must: `try_get_with` would hand back the present stale entry instead of
/// re-resolving), so it is not single-flighted against the init. If its answer
/// lands after this init's refusal, both stores hold a live entry for the name,
/// which is exactly the state the positive/negative split forbids: the warm arm
/// serves the answer, but a port that asks after the positive entry ages out
/// would be refused, and this thread's memo was tagged `Negative`.
///
/// Called after the init future has returned, i.e. once the single-flight is
/// released. A fresh positive means the refusal is stale by construction: remove
/// it (bumping `NEG_EPOCH` when it was there, so other threads' negative memos
/// stop trusting it) and rewrite this thread's memo with the live answer, so the
/// packet path agrees with the store.
async fn withdraw_refusal_if_answered(host_key: &str, memo_key: &str, port: u16) {
    let Some((deadline, ips)) = positives().get(host_key).await else {
        return;
    };
    if positive_life(deadline, Instant::now()).is_none() {
        return;
    }
    if negatives().remove(host_key).await.is_some() {
        bump_neg_epoch();
    }
    materialize_cached(memo_key, deadline, &ips, port);
}

/// Accept `IP:port` or `hostname:port` for the QUIC server address, taking the
/// most preferred address.
pub async fn resolve_server_addr(s: &str) -> Result<SocketAddr> {
    let mut addrs = resolve_server_addrs(s, 1).await?;
    Ok(addrs.remove(0))
}

/// Every address of a configured `host:port` endpoint, in preference order
/// ([`ip_preference`] first), capped at `max`. An IP literal is one address and
/// never touches the resolver.
///
/// Unlike [`resolve_all_timeout`], this goes through the shared positive cache:
/// single-flight, serve-stale, and a cached negative verdict. The client
/// re-resolves its own server endpoint on *every* reconnect attempt, so an
/// uncached lookup put one DNS round trip — or, when the resolver was down, one
/// timeout — in front of each of them, and returned a single address that the
/// dial loop then had no alternative to.
///
/// The list is what lets a dial fall through to the next address when the most
/// preferred one is a dead end (the classic: AAAA present in the answer, IPv6
/// unroutable on the network).
pub async fn resolve_server_addrs(s: &str, max: usize) -> Result<Vec<SocketAddr>> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(vec![a]);
    }
    let (host, port) = s
        .rsplit_once(':')
        .context("bad server_addr, want host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad server port")?;
    let addrs: Vec<SocketAddr> = resolve_all_cached(host, port)
        .await?
        .iter()
        .copied()
        .take(max.max(1))
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("dns empty");
    }
    Ok(addrs)
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

    /// hickory must not be a second TTL authority behind the outer caches. If
    /// its response cache stayed enabled, a name whose moka entry expired could
    /// still be answered from hickory's own entry — up to one full TTL window
    /// (~240 s) stale — and its hits would bypass the thread memo the packet
    /// paths rely on. Pin both the disabled cache and the retained TTL clamps.
    ///
    /// The attempt budget is pinned here too: it is the one option pair whose
    /// defaults silently disabled a documented feature (the retries could never
    /// fit inside the wall).
    #[test]
    fn hickory_response_cache_is_disabled_and_ttls_stay_bounded() {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        configure_resolver_options(&mut opts);
        assert_eq!(
            opts.cache_size, 0,
            "hickory's internal cache must be disabled; the outer moka caches are the only TTL authority"
        );
        assert_eq!(
            opts.positive_max_ttl,
            Some(DNS_RECORD_TTL_MAX),
            "hickory clamps every answer's TTL, so its ceiling must match the store's record-TTL cap"
        );
        assert_eq!(opts.negative_max_ttl, Some(DNS_NEG_TTL));
        // The attempt budget is *derived* from the module's lookup wall: a
        // per-attempt timeout at hickory's 5 s default made the first attempt
        // consume `DNS_LOOKUP_TIMEOUT` entirely, so the configured retries
        // could never run.
        assert_eq!(opts.timeout, DNS_QUERY_TIMEOUT);
        assert_eq!(opts.attempts, DNS_LOOKUP_ATTEMPTS);
        assert!(
            opts.timeout * (opts.attempts as u32 + 1) < DNS_LOOKUP_TIMEOUT,
            "one attempt x (1 + retries) must fit inside the lookup wall"
        );
    }

    /// The slow-path semaphore must be created with exactly
    /// [`DNS_SLOW_PATH_PERMITS`] permits: admission charges that count x
    /// per-waiter bytes, so the two drifting apart would under-count the DNS
    /// term (`config::tuning::dns_inflight_memory_bytes`).
    #[test]
    fn slow_path_limiter_has_the_charged_permit_count() {
        assert_eq!(
            dns_slow_path_limiter().available_permits(),
            DNS_SLOW_PATH_PERMITS
        );
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

    /// Freshness is a property of the entry's own insertion instant, not of the
    /// cache's residency: the store now keeps an entry for the stale window past
    /// its TTL (so a stale answer can still serve while the refresh runs), which
    /// means "it is in the cache" no longer implies "it is current".
    /// A failing upstream must be retried on a fixed schedule, not once per
    /// stale hit: every flow riding a stale entry asks for a refresh, and without
    /// the cooldown each of those asks became another lookup against the same
    /// failing server.
    #[test]
    fn a_failed_refresh_is_cooled_down_per_name() {
        let host = "cooldown-refresh.example.test";
        let t0 = Instant::now();
        let claim = claim_refresh(host, t0).expect("the first attempt is free");
        assert!(
            claim_refresh(host, t0).is_none(),
            "an attempt in flight must block a second one"
        );
        drop(claim);
        // The cooldown is anchored at the moment the attempt ended, not at the
        // moment it started.
        let ended = Instant::now();
        assert!(
            claim_refresh(host, ended).is_none(),
            "the cooldown must outlive the attempt that failed"
        );
        assert!(
            claim_refresh(
                host,
                ended + DNS_REFRESH_COOLDOWN - Duration::from_millis(1)
            )
            .is_none(),
            "the name stays unavailable until the cooldown is over"
        );
        assert!(
            claim_refresh(
                host,
                ended + DNS_REFRESH_COOLDOWN + Duration::from_millis(1)
            )
            .is_some(),
            "the name must become refreshable again once the cooldown ends"
        );
    }

    /// The generation key must move when the platform configuration moves — and
    /// only then. A stale key means the watcher either misses a nameserver
    /// change (the cliff it exists to close) or rebuilds the resolver on every
    /// poll (a new connection pool every 30 s).
    #[test]
    fn the_resolver_fingerprint_tracks_nameservers_and_search() {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};

        let base = ResolverConfig::default();
        let fingerprint = config_fingerprint(&base);
        assert_eq!(fingerprint, config_fingerprint(&ResolverConfig::default()));

        let mut nameserver = ResolverConfig::default();
        nameserver.add_name_server(NameServerConfig::udp([192, 0, 2, 53].into()));
        assert_ne!(
            config_fingerprint(&nameserver),
            fingerprint,
            "a different name server must be a different generation"
        );

        let mut search = ResolverConfig::default();
        search.add_search(
            hickory_resolver::proto::rr::Name::from_ascii("corp.example")
                .expect("test literal is a valid name"),
        );
        assert_ne!(
            config_fingerprint(&search),
            fingerprint,
            "a different search list must be a different generation"
        );
    }

    #[test]
    fn positive_life_splits_fresh_from_stale_at_the_deadline() {
        let now = Instant::now();
        let deadline = now + DNS_CACHE_TTL;
        assert_eq!(
            positive_life(deadline, now),
            Some(DNS_CACHE_TTL),
            "an entry written now has its whole window"
        );
        let one_ms_left = deadline - Duration::from_millis(1);
        assert_eq!(
            positive_life(deadline, one_ms_left),
            Some(Duration::from_millis(1)),
            "the remainder is what an adopting caller clamps against"
        );
        assert_eq!(
            positive_life(deadline, deadline),
            None,
            "the deadline itself is stale, not fresh"
        );
        assert_eq!(
            positive_life(deadline, deadline + Duration::from_secs(600)),
            None,
            "anything inside the stale window is stale, never fresh"
        );
    }

    /// The freshness window comes from the answer, not from a constant: a short
    /// TTL must not be served as fresh for the default window, and a long one
    /// must not be re-resolved early.
    #[test]
    fn the_freshness_window_is_the_answers_own_ttl_clamped() {
        assert_eq!(
            record_ttl(Duration::from_secs(1)),
            DNS_RECORD_TTL_MIN,
            "a tiny TTL is raised to the floor"
        );
        assert_eq!(
            record_ttl(Duration::from_secs(86_400)),
            DNS_RECORD_TTL_MAX,
            "a day-long TTL is capped"
        );
        assert_eq!(
            record_ttl(Duration::from_secs(60)),
            Duration::from_secs(60),
            "an ordinary TTL is taken as-is"
        );
        // The zero TTL an IP-literal answer effectively carries must not make
        // every datagram a lookup.
        assert_eq!(record_ttl(Duration::ZERO), DNS_RECORD_TTL_MIN);
    }

    /// The search list is for short LAN names, not for dotted targets: a dotted
    /// name is handed over fully qualified so a failure costs one query instead
    /// of one per resolv.conf suffix. Literals must come back untouched.
    #[test]
    fn query_name_makes_dotted_targets_fully_qualified() {
        assert_eq!(query_name("example.com"), "example.com.");
        assert_eq!(query_name("foo.corp."), "foo.corp.");
        assert_eq!(query_name("printer"), "printer");
        assert_eq!(query_name("localhost"), "localhost");
        assert_eq!(query_name("192.0.2.7"), "192.0.2.7");
        assert_eq!(query_name("::1"), "::1");
        assert_eq!(query_name("[::1]"), "[::1]");
    }

    /// The refusal race: a background refresh (plain `insert`) can land after a
    /// foreground init already wrote its refusal, which leaves both stores
    /// holding the name — the one state the positive/negative split forbids.
    /// The withdrawal puts the stores and this thread's memo back in agreement.
    #[tokio::test]
    async fn a_refusal_is_withdrawn_when_a_refresh_answered_first() {
        let _guard = DNS_CACHE_TEST_LOCK.lock().await;
        let host = "127.0.0.10";
        let port = 19_708u16;
        let addr: std::net::SocketAddr = "127.0.0.10:19708".parse().unwrap();
        // Both writes landed, in the order the race produces: the answer first,
        // the refusal after it.
        dns_cache_seed(host, port, addr).await;
        dns_neg_cache_seed(host, port).await;
        assert!(
            negatives().get(host).await.is_some(),
            "premise: a refusal and a live answer coexist"
        );
        assert_eq!(lookup_cached_fast(host, port), CachedLookup::Negative);

        let mut kbuf = [0u8; DNS_KEY_BUF];
        let memo_key = dns_key(host, port, &mut kbuf).unwrap().to_owned();
        let mut hbuf = [0u8; DNS_HOST_KEY_BUF];
        let host_key = dns_host_key(host, &mut hbuf).unwrap().to_owned();

        withdraw_refusal_if_answered(&host_key, &memo_key, port).await;

        assert!(
            negatives().get(host).await.is_none(),
            "a live answer must withdraw the refusal it raced"
        );
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "the packet path must follow the store instead of its own memo"
        );

        // Idempotent: nothing left to withdraw, nothing rewritten wrongly.
        withdraw_refusal_if_answered(&host_key, &memo_key, port).await;
        assert_eq!(lookup_cached_fast(host, port), CachedLookup::Addr(addr));
    }

    /// A stale entry is **served**, and the repair happens beside the caller:
    /// the datagram that arrives one millisecond after a name's TTL expires must
    /// not pay a cold lookup — the previous answer is still the answer — but the
    /// name does have to become fresh again without that caller waiting for it.
    ///
    /// The refresh is observable because the seeded host is a literal (so the
    /// background resolve needs no network) and the refresh rewrites the entry:
    /// the served *value* is identical, only the insertion instant moves.
    #[tokio::test]
    async fn a_stale_entry_is_served_and_refreshed() {
        let (host, port) = ("127.0.0.9", 19706u16);
        let addr: SocketAddr = "127.0.0.9:19706".parse().unwrap();
        // One TTL plus a minute: resident (inside the stale window), but no
        // longer fresh.
        dns_cache_seed_aged(host, port, addr, DNS_CACHE_TTL + Duration::from_secs(60)).await;
        let seeded = positives().get(host).await.expect("seeded entry").0;
        assert!(
            positive_life(seeded, Instant::now()).is_none(),
            "premise: the seeded entry is stale"
        );

        let v = resolve_all_cached(host, port)
            .await
            .expect("a stale entry must serve");
        assert_eq!(&v[..], &[addr], "the last known answer is still the answer");

        // The stale hit warms the memo for the *short* stale life, not for the
        // remaining TTL, so the packet path comes back to this async path (the
        // only place that can schedule the refresh) within `DNS_STALE_MEMO_TTL`.
        let (hit, life) = lookup_cached_fast_with_ttl(host, port);
        assert_eq!(hit, CachedLookup::Addr(addr));
        assert!(
            life <= DNS_STALE_MEMO_TTL.as_millis() as u64,
            "a stale hit must be memoized for the stale life, got {life} ms"
        );

        let refreshed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some((inserted, _)) = positives().get(host).await
                    && positive_life(inserted, Instant::now()).is_some()
                {
                    break inserted;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the stale hit must schedule a refresh");
        assert!(
            refreshed > seeded,
            "the refresh must move the entry's insertion instant forward"
        );
    }

    /// The other half of serve-stale: a fresh hit schedules nothing. A refresh
    /// would be invisible from the outside except for the entry's insertion
    /// instant, which is what this pins (the seeded host is a literal, so an
    /// unwanted refresh would succeed and rewrite it).
    #[tokio::test]
    async fn a_fresh_entry_does_not_schedule_a_refresh() {
        let (host, port) = ("127.0.0.8", 19707u16);
        let addr: SocketAddr = "127.0.0.8:19707".parse().unwrap();
        dns_cache_seed(host, port, addr).await;
        let before = positives().get(host).await.expect("seeded entry").0;
        for _ in 0..8 {
            let v = resolve_all_cached(host, port).await.expect("fresh serve");
            assert_eq!(&v[..], &[addr]);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = positives().get(host).await.expect("still seeded").0;
        assert_eq!(
            after, before,
            "a fresh hit must not rewrite the entry (it must not refresh)"
        );
        assert!(positive_life(after, Instant::now()).is_some());
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

    /// The negative cache's lifetime is a claim about the *name*, so only a
    /// resolver answer may be cached as one. `NoRecordsFound` (NXDOMAIN/NODATA)
    /// is the only hickory variant that qualifies; a timeout — and every other
    /// transport/protocol failure — says nothing about the name and may only be
    /// held for the short backoff.
    #[test]
    fn only_a_resolver_answer_is_cached_as_a_verdict() {
        let timeout = LookupFailure::from_resolver(hickory_resolver::net::NetError::Timeout);
        assert!(
            matches!(timeout, LookupFailure::Inconclusive(_)),
            "a timeout must not become a verdict about the name"
        );
        assert_eq!(timeout.retry_ttl(), DNS_INCONCLUSIVE_TTL);
        assert!(
            DNS_INCONCLUSIVE_TTL < DNS_NEG_TTL,
            "a backoff must be shorter than a verdict"
        );
        let verdict = LookupFailure::Verdict(anyhow::anyhow!("no records"));
        assert_eq!(verdict.retry_ttl(), DNS_NEG_TTL);
        assert_eq!(verdict.to_string(), "no records");
    }

    /// An inconclusive failure must not refuse the name for the verdict TTL: the
    /// shared entry carries a ~1 s deadline, and another port of the same name
    /// that finds it is memoized for exactly the life it has left, not for
    /// [`DNS_NEG_TTL`].
    #[tokio::test]
    async fn an_inconclusive_failure_backs_off_briefly() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
        let (host, port) = ("inconclusive.resolve.test", 19704u16);
        let other_port = port + 1;
        let host_key = dns_host_key_owned(host);
        let memo_key = dns_key_owned(host, port);
        record_refusal(&host_key, &memo_key, DNS_INCONCLUSIVE_TTL).await;

        let deadline = negatives()
            .get(host)
            .await
            .expect("the refusal is shared by name");
        let life = deadline.saturating_duration_since(Instant::now());
        assert!(
            life > Duration::ZERO && life <= DNS_INCONCLUSIVE_TTL,
            "an inconclusive failure must expire with the backoff, got {life:?}"
        );
        assert_eq!(lookup_cached_fast(host, port), CachedLookup::Negative);

        // A *different* port reaches the shared entry and memoizes its own
        // (host, port) with the entry's remaining life.
        let err = resolve_all_cached(host, other_port).await.unwrap_err();
        assert!(
            err.to_string().contains("dns negative cached"),
            "got: {err:#}"
        );
        let (probe, memo_life) = lookup_cached_fast_with_ttl(host, other_port);
        assert_eq!(probe, CachedLookup::Negative);
        assert!(
            memo_life <= DNS_INCONCLUSIVE_TTL.as_millis() as u64,
            "another port must not inherit the verdict TTL, got {memo_life} ms"
        );

        // The verdict path keeps the full claim, which is the whole difference.
        record_refusal(&host_key, &memo_key, DNS_NEG_TTL).await;
        let life = negatives()
            .get(host)
            .await
            .expect("the verdict replaced the backoff")
            .saturating_duration_since(Instant::now());
        assert!(
            life > DNS_INCONCLUSIVE_TTL,
            "a verdict must outlive the backoff, got {life:?}"
        );
    }

    /// A stored deadline that has passed must not refuse anything: the entry is
    /// a deadline, not a switch, and moka may keep it resident for the rest of
    /// its own 10 s TTL. An IP literal pins the fall-through deterministically
    /// (hickory answers it without a network query).
    #[tokio::test]
    async fn an_expired_refusal_falls_through_to_a_fresh_lookup() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
        // A literal no other test uses, so a warm positive entry cannot make
        // this test pass without exercising the fall-through.
        let (host, port) = ("127.0.0.2", 19705u16);
        negatives()
            .insert(host.to_owned(), Instant::now() - Duration::from_secs(1))
            .await;
        assert!(
            negatives().get(host).await.is_some(),
            "premise: the expired entry is still resident"
        );

        let got = resolve_all_cached(host, port)
            .await
            .expect("the literal resolves");
        assert_eq!(&got[..], &[SocketAddr::from(([127, 0, 0, 2], port))]);
        assert!(
            negatives().get(host).await.is_none(),
            "the success must clear the stale entry"
        );
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

    /// The cache is `DNS_CACHE_MAX` *entries*; a positive entry's value is
    /// attacker-sized unless it is capped. A hostile authoritative server can
    /// return thousands of A/AAAA records (truncated UDP → TCP retry), so the
    /// retained set must be the capped, preferred-family-first prefix — never
    /// the whole answer.
    #[test]
    fn cache_prefix_keeps_preferred_family_and_caps_the_retained_set() {
        let v6: Vec<IpAddr> = (1..=40u16)
            .map(|i| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect();
        let v4: Vec<IpAddr> = (1..=40u8)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)))
            .collect();
        let out = prepare_cache_ips([v4.clone(), v6.clone()].concat());
        assert_eq!(
            out.len(),
            DNS_CACHE_MAX_ADDRS,
            "a {}-record answer must be capped at {DNS_CACHE_MAX_ADDRS}",
            v4.len() + v6.len()
        );
        assert!(
            out.iter().all(IpAddr::is_ipv6),
            "the default preference keeps the IPv6 prefix ahead of IPv4"
        );
        assert_eq!(&out[..], &v6[..DNS_CACHE_MAX_ADDRS]);
        // And a small answer keeps every record, in the same order.
        let small = prepare_cache_ips(vec![v6[0], v4[0]]);
        assert_eq!(&small[..], &[v6[0], v4[0]]);
    }

    /// The seeding helpers must obey the same retained-set invariant as the
    /// production insert: a test/binary that seeds a huge answer must not be
    /// able to put an uncapped set in the cache.
    #[tokio::test]
    async fn seeded_name_retains_at_most_the_cap() {
        let host = "many-records.resolve.test";
        let port = 19_811u16;
        let addrs: Vec<SocketAddr> = (1..=(DNS_CACHE_MAX_ADDRS + 8))
            .map(|i| SocketAddr::from(([203, 0, 113, (i % 250 + 1) as u8], port)))
            .collect();
        dns_cache_seed_set(host, port, &addrs).await;
        let got = resolve_all_cached(host, port).await.expect("seeded hit");
        assert_eq!(got.len(), DNS_CACHE_MAX_ADDRS, "the seed must be capped");
        assert_eq!(
            &got[..],
            &addrs[..DNS_CACHE_MAX_ADDRS],
            "the retained prefix keeps its order (and each address its caller port)"
        );
        assert_eq!(
            positives().get(host).await.expect("entry present").1.len(),
            DNS_CACHE_MAX_ADDRS
        );
    }

    /// LOGIC-7 regression: the thread-memo epoch must be sampled *before* the
    /// negative-cache probe. If a concurrent success bumps the epoch between the
    /// probe and the memo write, the write must be refused — otherwise the fast
    /// path would trust a stale negative entry that was tagged with the newer
    /// epoch and keep refusing a name that now resolves for `DNS_NEG_TTL`.
    #[tokio::test]
    async fn negative_memo_write_is_refused_when_the_epoch_moved() {
        let _serial = super::DNS_CACHE_TEST_LOCK.lock().await;
        let key = dns_key_owned("epoch-race.resolve.test", 19_812);
        assert!(memo_peek_both(&key).1.is_none(), "premise: cold memo slot");

        // The epoch at the negative-cache probe…
        let epoch_at_probe = neg_epoch();
        // …then a concurrent success removes the negative entry and bumps it…
        bump_neg_epoch();
        // …so the memo write must be dropped instead of tagged as current.
        assert!(
            !memo_put_with_epoch(&key, None, Instant::now() + DNS_NEG_TTL, epoch_at_probe),
            "a negative memo tagged with a superseded epoch must not be written"
        );
        assert!(
            memo_peek_both(&key).1.is_none(),
            "the fast path must fall through to the shared caches, not serve the stale verdict"
        );

        // With the current epoch the same write is accepted (the non-race path).
        assert!(memo_put_with_epoch(
            &key,
            None,
            Instant::now() + DNS_NEG_TTL,
            neg_epoch()
        ));
        assert!(memo_peek_both(&key).1.is_some());

        // `memo_put` keeps serving callers that do not hold a pre-probe epoch
        // (it samples the epoch at write time).
        let plain = dns_key_owned("epoch-plain.resolve.test", 19_812);
        memo_put(&plain, None, Instant::now() + DNS_NEG_TTL);
        assert!(memo_peek_both(&plain).1.is_some());
    }

    /// LOGIC-10: the blocking fallback cannot be cancelled by the lookup
    /// timeout, so its permits must bound *live libc resolver threads*. Pin the
    /// permit count and the fail-fast behaviour: holding every permit must make
    /// the next acquisition fail (that is the error the blocking closure
    /// returns), not queue.
    #[test]
    fn blocking_fallback_permits_bound_live_resolvers() {
        assert_eq!(
            DNS_BLOCKING_FALLBACK_PERMITS, 128,
            "the charged/bounded fallback size is part of the contract"
        );
        let lim = dns_blocking_fallback_limiter();
        let available = lim.available_permits();
        assert!(
            available <= DNS_BLOCKING_FALLBACK_PERMITS,
            "the limiter can never hold more than the documented permits"
        );
        // Hold everything this process currently has; the next try must fail
        // fast instead of parking a caller behind the blocking pool.
        let mut held = Vec::with_capacity(available);
        while let Ok(permit) = lim.clone().try_acquire_owned() {
            held.push(permit);
        }
        assert_eq!(held.len(), available);
        assert!(
            lim.clone().try_acquire_owned().is_err(),
            "an exhausted fallback must fail fast"
        );
        drop(held);
        assert!(lim.available_permits() >= available, "permits are returned");
    }
}
