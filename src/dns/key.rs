//! DNS cache key construction.
//!
//! The key encoding is `host` bytes + NUL separator + decimal port. This is
//! injective (the decimal port never contains NUL, so splitting at the last
//! NUL recovers the exact host/port), so it is safe to build on the stack and
//! look up with the borrowed `&str` form of a `String` key — no `String`
//! allocation on the per-datagram hot path. Moka's `Equivalent`-based lookups
//! (`get`, `try_get_with_by_ref`) accept exactly this borrowed form.
pub(crate) const DNS_KEY_BUF: usize = 255 + 1 + 5;

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
