//! DNS cache key construction.
//!
//! Two key shapes share the normalization below (DNS is case-insensitive and a
//! trailing-dot absolute name equals its relative form):
//!
//! - **per-`(host, port)`** ([`dns_key`]): `host` bytes + NUL separator +
//!   decimal port. This is the thread-local memo key, whose stored value is the
//!   full [`SocketAddr`](std::net::SocketAddr) that was resolved *for that
//!   port*, so the port must be part of the key — two ports of one name are
//!   two memo entries pointing at the same set of IPs.
//! - **host only** ([`dns_host_key`]): the normalized host bytes, used by the
//!   shared moka verdict caches. A/AAAA records carry no port: the same
//!   answer serves every port, so a new port of an already-resolved name must
//!   share the cache entry *and* its single-flight init instead of paying a
//!   second upstream query. `resolve_all_cached` attaches the caller's port
//!   when it returns the set.
//!
//! Both encodings are injective, so it is safe to build them on the stack and
//! look up with the borrowed `&str` form of a `String` key — no `String`
//! allocation on the per-datagram hot path. The host-only form needs no
//! separator at all (the key *is* the name), and the per-port form splits at
//! its last NUL, which a decimal port can never contain. Moka's
//! `Equivalent`-based lookups (`get`, `try_get_with_by_ref`) accept exactly
//! this borrowed form.

/// Buffer size for a per-`(host, port)` key: 255-byte wire-max host + NUL +
/// up to 5 decimal port digits.
pub(crate) const DNS_KEY_BUF: usize = 255 + 1 + 5;

/// Buffer size for a host-only key: the normalized name is at most the DNS
/// wire-format limit, and it is the whole key (no separator, no port).
pub(crate) const DNS_HOST_KEY_BUF: usize = 255;

/// Normalize a DNS name for cache keys: DNS is case-insensitive and an
/// absolute (trailing-dot) name is equivalent to its relative form.
fn dns_name_bytes(host: &str) -> &[u8] {
    let mut hb = host.as_bytes();
    while hb.len() > 1 && hb.last() == Some(&b'.') {
        hb = &hb[..hb.len() - 1];
    }
    hb
}

/// Owned per-`(host, port)` key: `host` + NUL + decimal port.
///
/// Owned fallback for hosts above the wire-format limit; MUST normalize the
/// same way as [`dns_key`] so both forms address the same memo entry.
pub(crate) fn dns_key_owned(host: &str, port: u16) -> String {
    let hb = dns_name_bytes(host);
    let mut bytes = Vec::with_capacity(hb.len() + 6);
    bytes.extend(hb.iter().map(|b| b.to_ascii_lowercase()));
    bytes.push(0);
    bytes.extend_from_slice(port.to_string().as_bytes());
    String::from_utf8(bytes).expect("ascii lowercasing preserves UTF-8")
}

/// Build the per-`(host, port)` key into `buf`, returning a borrowed `&str`.
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

/// Owned host-only key for the shared moka verdict caches.
///
/// Owned fallback for hosts above the wire-format limit; MUST normalize the
/// same way as [`dns_host_key`] so both forms address the same cache entry.
pub(crate) fn dns_host_key_owned(host: &str) -> String {
    let hb = dns_name_bytes(host);
    let mut bytes = Vec::with_capacity(hb.len());
    bytes.extend(hb.iter().map(|b| b.to_ascii_lowercase()));
    String::from_utf8(bytes).expect("ascii lowercasing preserves UTF-8")
}

/// Build the host-only key into `buf`, returning a borrowed `&str`.
/// Returns `None` only when `host` is longer than the wire-format limit, in
/// which case the caller falls back to [`dns_host_key_owned`] — the same split
/// the per-port key uses.
pub(crate) fn dns_host_key<'a>(host: &str, buf: &'a mut [u8; DNS_HOST_KEY_BUF]) -> Option<&'a str> {
    let hb = dns_name_bytes(host);
    if hb.len() > DNS_HOST_KEY_BUF {
        return None;
    }
    for (dst, b) in buf.iter_mut().zip(hb) {
        *dst = b.to_ascii_lowercase();
    }
    std::str::from_utf8(&buf[..hb.len()]).ok()
}
