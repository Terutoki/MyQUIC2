//! DNS single-flight table — extracted verbatim from `src/lib.rs`
//! (zero-logic-change split). Source lines: DnsInflightEntry/OwnerReset/
//! InflightCleanup/DnsInflightTable/dns_inflights/dns_inflight_for/
//! dns_slow_path_limiter/DnsInflight/dns_inflight_status/dns_is_inflight.
//! `lib.rs` untouched.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use super::key::{dns_key, dns_key_owned, dns_shard, DnsCacheKey, DNS_KEY_BUF, DNS_SHARDS};
use crate::dgram_drops;
use crate::sync::guards::{lock_mutex, try_lock_mutex};

pub(crate) struct DnsInflightEntry {
    /// Own copy of the key so the cleanup guard can remove the entry even when
    /// the owner is a takeover task that did not insert it.
    pub(crate) key: DnsCacheKey,
    pub(crate) cell: tokio::sync::OnceCell<Result<Arc<[SocketAddr]>, String>>,
    pub(crate) notify: tokio::sync::Notify,
    pub(crate) owner: std::sync::atomic::AtomicBool,
}

/// Releases singleflight ownership when the resolving task exits for any
/// reason (completion, cancellation, panic), so waiters can take over instead
/// of sleeping forever.
pub(crate) struct OwnerReset<'a> {
    pub(crate) entry: &'a DnsInflightEntry,
}

impl Drop for OwnerReset<'_> {
    fn drop(&mut self) {
        self.entry
            .owner
            .store(false, std::sync::atomic::Ordering::Release);
        self.entry.notify.notify_waiters();
    }
}

/// Removes the inflight entry when the owner's future is dropped for any
/// reason. Without this, cancellation between `cell.set()` and the explicit
/// removal left a permanently stale entry behind: every later lookup returned
/// the old result without ever re-resolving the name.
pub(crate) struct InflightCleanup<'a> {
    pub(crate) entry: &'a Arc<DnsInflightEntry>,
}

impl Drop for InflightCleanup<'_> {
    fn drop(&mut self) {
        let mut inf = lock_mutex(dns_inflight_for(&self.entry.key));
        if let Some(cur) = inf.get(&self.entry.key) {
            if Arc::ptr_eq(cur, self.entry) {
                inf.remove(&self.entry.key);
            }
        }
    }
}

/// Sharded single-flight table: one mutex per shard (see `DNS_SHARDS`).
pub(crate) type DnsInflightTable = std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>>;

fn dns_inflights() -> &'static [DnsInflightTable; DNS_SHARDS] {
    static INFS: std::sync::OnceLock<[DnsInflightTable; DNS_SHARDS]> = std::sync::OnceLock::new();
    INFS.get_or_init(|| std::array::from_fn(|_| std::sync::Mutex::new(HashMap::new())))
}

pub(crate) fn dns_inflight_for(key: &str) -> &'static DnsInflightTable {
    &dns_inflights()[dns_shard(key)]
}

pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1024)))
}

/// Three-way outcome of a single-flight probe. `Contended` is distinct from
/// `Inflight`: the shard mutex was busy, so nothing is known — the resolution
/// may or may not be in flight. Collapsing it into `true` dropped datagrams
/// (charged to `DNS_INFLIGHT`) for what was only lock contention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsInflight {
    /// The name is registered in the single-flight table.
    Inflight,
    /// The name is not registered.
    Absent,
    /// The shard mutex was busy: unknown, never inflight.
    Contended,
}

pub fn dns_inflight_status(host: &str, port: u16) -> DnsInflight {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // Packet path: contended reads as unknown so the caller falls through to
    // the limiter-bounded spawn path instead of parking on the shard mutex.
    match try_lock_mutex(dns_inflight_for(key)) {
        Some(inf) => {
            if inf.contains_key(key) {
                DnsInflight::Inflight
            } else {
                DnsInflight::Absent
            }
        }
        None => DnsInflight::Contended,
    }
}

pub fn dns_is_inflight(host: &str, port: u16) -> bool {
    dns_inflight_status(host, port) == DnsInflight::Inflight
}

/// One datagram coalesced behind an in-flight resolution: the payload plus the
/// session context the owner needs to deliver it after the caches warm.
/// `Bytes::clone` shares the allocation (no copy); the queue itself is bounded
/// by [`DNS_COALESCE_CAP`].
#[derive(Debug, Clone)]
pub struct DnsCoalesced {
    pub payload: Bytes,
    pub conn_id: usize,
    pub sess: u32,
}

/// Design-A single-flight coalescing cap: at most this many waiter payloads
/// park behind one resolving owner per `(host, port)`.
///
/// 32 matches the drain-burst bound (`LAST_HOP_DRAIN`): one owner's drain
/// burst moves at most one burst worth of replies, so a coalesced queue can
/// never stage more than the dispatcher already stages per burst.
pub const DNS_COALESCE_CAP: usize = 32;

/// Outcome of parking one waiter behind a resolving owner. `Full` drops or
/// re-delivers per caller (server egress drops newest with exactly one
/// `DNS_INFLIGHT` bump; client ingress falls through to a self-delivering
/// spawn that joins single-flight as a waiter, so neither path strands); none
/// of `Full`/`Gone`/`Contended` is ever silently lost.
#[derive(Debug, PartialEq, Eq)]
pub enum CoalesceOutcome<T> {
    /// Parked; the resolving owner drains and delivers it.
    Pushed,
    /// The per-name queue is at [`DNS_COALESCE_CAP`]; item returned.
    Full(T),
    /// No resolution owns the name anymore; item returned so the caller falls
    /// through to the spawn path (a warm hit after the race).
    Gone(T),
    /// A shard mutex was busy: unknown, never queued; item returned. Callers
    /// count it apart as `DNS_CONTENTION` and fall through, never park —
    /// exactly like [`DnsInflight::Contended`].
    Contended(T),
}

/// Shared single-flight waiter queue: the ONE coalesce implementation both
/// the server egress (`DnsCoalesced`) and the client ingress (`CoalescedReply`,
/// in the client binary) park behind.
///
/// Sharded like the single-flight table (one mutex per shard, same
/// [`dns_shard`] index), keyed by the same stack-built `(host, port)` key, so
/// no allocation on the packet path beyond the queue slot itself. The packet
/// path ([`dns_coalesce_try_push_to`]) is `try_lock` only and never parks a
/// Tokio worker; the owner's drain retries a contended shard and falls back
/// to a blocking take rather than lose parked waiters to a missed drain
/// (silent loss with no counter — the critical section is a single map
/// remove).
pub struct DnsCoalesceQueue<T> {
    shards: [std::sync::Mutex<HashMap<DnsCacheKey, Vec<T>>>; DNS_SHARDS],
}

impl<T> Default for DnsCoalesceQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DnsCoalesceQueue<T> {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Remove one name's queue entry without taking the payloads (cancel-guard
    /// path: at that point no drain can run, the task is gone).
    fn remove_key(&self, key: &str) {
        if let Some(mut q) = try_lock_mutex(&self.shards[dns_shard(key)]) {
            q.remove(key);
        }
    }

    /// Single-try take for contexts that cannot await (the cancel guard,
    /// tests): a busy or absent shard reads as an empty queue. Callers that
    /// must not lose the queue use [`DnsCoalesceQueue::drain_coalesced`].
    pub fn take_now(&self, host: &str, port: u16) -> Vec<T> {
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let owned;
        let key: &str = match dns_key(host, port, &mut kbuf) {
            Some(k) => k,
            None => {
                owned = dns_key_owned(host, port);
                &owned
            }
        };
        match try_lock_mutex(&self.shards[dns_shard(key)]) {
            Some(mut q) => q.remove(key).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Take this name's coalesced queue for delivery, retrying a contended
    /// shard instead of stranding it: the only other holder is a follower
    /// mid-push (a microsecond critical section with no await under it), so
    /// the first try almost always succeeds. Falls back to a blocking take
    /// rather than leaking the queue — the owner is a background task, and an
    /// untaken queue after the entry is gone would never deliver.
    pub async fn drain_coalesced(&self, host: &str, port: u16) -> Vec<T> {
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let owned;
        let key: &str = match dns_key(host, port, &mut kbuf) {
            Some(k) => k,
            None => {
                owned = dns_key_owned(host, port);
                &owned
            }
        };
        for _ in 0..DNS_COALESCE_TAKE_SPINS {
            if let Some(mut q) = try_lock_mutex(&self.shards[dns_shard(key)]) {
                return q.remove(key).unwrap_or_default();
            }
            tokio::task::yield_now().await;
        }
        lock_mutex(&self.shards[dns_shard(key)])
            .remove(key)
            .unwrap_or_default()
    }
}

/// Yield budget for [`DnsCoalesceQueue::drain_coalesced`] before the blocking
/// fallback. A push holds the shard for microseconds (no await under it), so
/// this budget is generous; the fallback exists so a stuck holder parks one
/// background task instead of leaking the queue.
const DNS_COALESCE_TAKE_SPINS: usize = 64;

/// Queue `item` behind the in-flight resolution for `(host, port)` instead of
/// dropping it. `try_lock` only: a busy shard reads as
/// [`CoalesceOutcome::Contended`].
///
/// The single-flight shard is held across the push: the owner's removal takes
/// the same mutex, so it serializes after this push and the owner's drain
/// still collects it — a queued datagram can never strand behind a resolution
/// that finished mid-push. The critical section is one hash lookup plus a
/// bounded `Vec::push` (no I/O, no await), the same shape as the registration
/// it mirrors.
pub fn dns_coalesce_try_push_to<T>(
    q: &DnsCoalesceQueue<T>,
    host: &str,
    port: u16,
    item: T,
) -> CoalesceOutcome<T> {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    let shard = dns_shard(key);
    // Packet path: a busy shard is contention, so the caller falls through to
    // the spawn path instead of parking on the shard mutex.
    let Some(inf) = try_lock_mutex(&dns_inflights()[shard]) else {
        return CoalesceOutcome::Contended(item);
    };
    if !inf.contains_key(key) {
        return CoalesceOutcome::Gone(item);
    }
    let Some(mut qq) = try_lock_mutex(&q.shards[shard]) else {
        return CoalesceOutcome::Contended(item);
    };
    if let Some(v) = qq.get_mut(key) {
        if v.len() >= DNS_COALESCE_CAP {
            return CoalesceOutcome::Full(item);
        }
        v.push(item);
        return CoalesceOutcome::Pushed;
    }
    // First coalesced datagram for this name: the key allocation is once per
    // resolution, not per datagram.
    qq.insert(key.to_owned(), vec![item]);
    CoalesceOutcome::Pushed
}

/// The server egress's instance of the shared queue: one queue
/// implementation, one instance per waiter-payload type.
fn server_dns_coalesce() -> &'static DnsCoalesceQueue<DnsCoalesced> {
    static Q: std::sync::OnceLock<DnsCoalesceQueue<DnsCoalesced>> = std::sync::OnceLock::new();
    Q.get_or_init(DnsCoalesceQueue::new)
}

/// Server-egress form of [`dns_coalesce_try_push_to`]: queue `pkt` behind the
/// in-flight resolution for `(host, port)`. See the shared function for the
/// `try_lock`-only, strand-free contract.
pub fn dns_coalesce_try_push(
    host: &str,
    port: u16,
    pkt: DnsCoalesced,
) -> CoalesceOutcome<DnsCoalesced> {
    dns_coalesce_try_push_to(server_dns_coalesce(), host, port, pkt)
}

/// Take this name's coalesced queue for delivery. Retry form; see
/// [`DnsCoalesceQueue::drain_coalesced`].
pub async fn dns_coalesce_take(host: &str, port: u16) -> Vec<DnsCoalesced> {
    server_dns_coalesce().drain_coalesced(host, port).await
}

/// Single-try form of [`dns_coalesce_take`] for contexts that cannot await
/// (the cancel guard, tests): a busy or absent shard reads as an empty queue.
/// Callers that must not lose the queue use the retrying form instead.
pub fn dns_coalesce_take_now(host: &str, port: u16) -> Vec<DnsCoalesced> {
    server_dns_coalesce().take_now(host, port)
}

/// Drop this name's coalesced queue, counting every datagram once on
/// `counter`: the failure-path twin of the drain, so a resolution that fails
/// after followers coalesced still accounts each of them exactly once.
pub async fn dns_coalesce_drop(host: &str, port: u16, counter: &std::sync::atomic::AtomicU64) {
    for _ in dns_coalesce_take(host, port).await {
        dgram_drops::bump(counter);
    }
}

/// Cancel-safety for one name's coalesce queue, the [`OwnerReset`] twin for
/// the wait-free side: the owner's explicit paths take the key first (drain on
/// success, counted drop on failure), so this only ever fires when the owner
/// task is cancelled or panics before either ran. Takes whatever is left and
/// drops it: at that point no drain can run (the task is gone), and the
/// process is shutting down around it.
pub struct DnsCoalesceGuard {
    key: DnsCacheKey,
}

impl DnsCoalesceGuard {
    pub fn for_name(host: &str, port: u16) -> Self {
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let owned;
        let key: &str = match dns_key(host, port, &mut kbuf) {
            Some(k) => k,
            None => {
                owned = dns_key_owned(host, port);
                &owned
            }
        };
        Self {
            key: key.to_owned(),
        }
    }
}

impl Drop for DnsCoalesceGuard {
    fn drop(&mut self) {
        // Single try, never park: cancellation already means teardown.
        server_dns_coalesce().remove_key(&self.key);
    }
}

/// Test-only: register a single-flight entry that never completes, so binary
/// tests can drive the coalesce queue deterministically without racing a real
/// resolver. Paired with [`dns_inflight_unseed`].
#[doc(hidden)]
pub fn dns_inflight_seed(host: &str, port: u16) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    let c = Arc::new(DnsInflightEntry {
        key: key.to_owned(),
        cell: tokio::sync::OnceCell::new(),
        notify: tokio::sync::Notify::new(),
        owner: std::sync::atomic::AtomicBool::new(true),
    });
    lock_mutex(dns_inflight_for(key)).insert(c.key.clone(), c);
}

/// Test-only twin of [`dns_inflight_seed`]: remove the entry and any queued
/// datagrams left behind, so seeded tests cannot leak into each other.
#[doc(hidden)]
pub fn dns_inflight_unseed(host: &str, port: u16) {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    lock_mutex(dns_inflight_for(key)).remove(key);
    server_dns_coalesce().remove_key(key);
}
