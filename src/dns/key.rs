//! DNS cache key — extracted verbatim from `src/lib.rs` (zero-logic-change split).
//! Source lines: DnsCacheKey/DnsCacheVal/DNS_KEY_BUF/dns_name_bytes/
//! dns_key_owned/dns_key/DNS_SHARDS/dns_shard. `lib.rs` untouched.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Cache key encoding: `host` bytes + NUL separator + decimal port. This is
/// injective (the decimal port never contains NUL, so splitting at the last
/// NUL recovers the exact host/port), so it is safe to build on the stack and
/// look up with the borrowed `&str` form of `HashMap<String, _>` — no `String`
/// allocation on the per-datagram hot path.
pub(crate) type DnsCacheKey = String;
/// `Arc<[SocketAddr]>` so cache hits and single-flight waiters clone a
/// refcount instead of duplicating the address vector.
pub(crate) type DnsCacheVal = (Instant, Arc<[SocketAddr]>);
pub(crate) const DNS_KEY_BUF: usize = 255 + 1 + 5;

/// The positive/negative cache, inflight and coalesce tables' map type.
///
/// One alias so the hasher choice cannot drift between the four: the keys are
/// short (host+port) and target names come off the wire, so the hasher must be
/// fast *and* randomly seeded — see the `foldhash` note in `Cargo.toml`.
pub(crate) type DnsMap<V> = HashMap<DnsCacheKey, V, foldhash::fast::RandomState>;

/// Normalize a DNS name for cache keys: DNS is case-insensitive and an
/// absolute (trailing-dot) name is equivalent to its relative form.
fn dns_name_bytes(host: &str) -> &[u8] {
    let mut hb = host.as_bytes();
    while hb.len() > 1 && hb.last() == Some(&b'.') {
        hb = &hb[..hb.len() - 1];
    }
    hb
}

/// Owned fallback for hosts above the wire-format limit; MUST normalize the
/// same way as [`dns_key`] so both forms address the same cache entry.
pub(crate) fn dns_key_owned(host: &str, port: u16) -> String {
    let hb = dns_name_bytes(host);
    let mut bytes = Vec::with_capacity(hb.len() + 6);
    bytes.extend(hb.iter().map(|b| b.to_ascii_lowercase()));
    bytes.push(0);
    bytes.extend_from_slice(port.to_string().as_bytes());
    String::from_utf8(bytes).expect("ascii lowercasing preserves UTF-8")
}

/// Build the cache key into `buf`, returning a borrowed `&str`.
/// Returns `None` only when `host` is longer than the wire-format limit.
pub(crate) fn dns_key<'a>(
    host: &str,
    port: u16,
    buf: &'a mut [u8; DNS_KEY_BUF],
) -> Option<&'a str> {
    let hb = dns_name_bytes(host);
    if hb.len() + 1 + 5 > DNS_KEY_BUF {
        return None;
    }
    for (dst, b) in buf.iter_mut().zip(hb) {
        *dst = b.to_ascii_lowercase();
    }
    let mut pos = hb.len();
    buf[pos] = 0;
    pos += 1;
    let mut digits = [0u8; 5];
    let mut p = port;
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (p % 10) as u8;
        p /= 10;
        if p == 0 {
            break;
        }
    }
    buf[pos..pos + (5 - i)].copy_from_slice(&digits[i..]);
    pos += 5 - i;
    std::str::from_utf8(&buf[..pos]).ok()
}

/// Shard count for the DNS tables. A single global `RwLock`/`Mutex` puts every
/// packet-path reader on one reader count / one mutex cache line; sharding by
/// key keeps the per-entry critical sections identical while spreading
/// cross-core contention, the same pattern as the server session table and the
/// client dispatcher hub.
pub(crate) const DNS_SHARDS: usize = 16;

/// Key-hash shard selector. Manual fold (no SipHash): this runs on the
/// per-packet path and only needs spreading, not DoS resistance (keys are
/// DNS names, and a collision only shares a lock, never a cache entry).
pub(crate) fn dns_shard(key: &str) -> usize {
    const K: u64 = 0x9e3779b97f4a7c15;
    let mut h: u64 = 0;
    for b in key.as_bytes() {
        h = h.wrapping_mul(K).wrapping_add(*b as u64);
    }
    (h as usize) % DNS_SHARDS
}
