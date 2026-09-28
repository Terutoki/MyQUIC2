//! DNS single-flight table — extracted verbatim from `src/lib.rs`
//! (zero-logic-change split). Source lines: DnsInflightEntry/OwnerReset/
//! InflightCleanup/DnsInflightTable/dns_inflights/dns_inflight_for/
//! dns_slow_path_limiter/DnsInflight/dns_inflight_status/dns_is_inflight.
//! `lib.rs` untouched.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use super::key::{dns_key, dns_key_owned, dns_shard, DnsCacheKey, DNS_KEY_BUF, DNS_SHARDS};
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
