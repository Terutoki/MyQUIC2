//! DNS egress policy — the `is_global_ip` / `unmap` / `map_for_dual` predicates.
//!
//! The non-global space is **CIDR data, not hand-rolled masks**. This file
//! used to be a chain of octet comparisons and bit patterns
//! (`(s[0] & 0xfe00) == 0xfc00`, `o[0] == 192 && o[1] == 88 && ...`), and its
//! history is a list of near-misses that had to be corrected in place:
//! `fe00::/9` first read as global, `2001::/23` was built one allocation
//! block at a time, and `3fff::/20` masked `s[1]` with `0xf0` and denied 256x
//! the RFC's space. A CIDR table cannot mis-mask a prefix, and `new_assert`
//! turns a bad prefix length into a compile error.
//!
//! What the tables deliberately do **not** cover: address forms that embed an
//! IPv4 address — `::ffff:0:0/96` (mapped), `::ffff:0:a.b.c.d` (translated,
//! RFC 2765), `64:ff9b::/96` (NAT64 well-known) and `::a.b.c.d` (deprecated
//! IPv4-compatible). Stacks route those by the embedded IPv4, so
//! [`is_global_ip`] recurses on it *before* the tables are consulted; the
//! whole-block v6 entries below (`::/8`, `0100::/16`, ...) therefore never
//! see an ambiguous embedded form.

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Non-globally-routable IPv4 space — RFC 6890 plus the IANA special-purpose
/// registry. Every entry names its citation; the masks are the CIDR's own.
const NON_GLOBAL_V4: &[Ipv4Net] = &[
    Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8), // "this network" (RFC 1122) + unspecified
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8), // private (RFC 1918)
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10), // CGNAT (RFC 6598)
    Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8), // loopback
    Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16), // link-local
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12), // private (RFC 1918)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24), // IETF protocol assignments (RFC 6890)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 2, 0), 24), // TEST-NET-1 (documentation)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 88, 99, 0), 24), // 6to4 relay anycast (deprecated)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16), // private (RFC 1918)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 175, 48, 0), 24), // AS112 direct delegation
    Ipv4Net::new_assert(Ipv4Addr::new(192, 31, 196, 0), 24), // AS112-v4 (RFC 7535)
    Ipv4Net::new_assert(Ipv4Addr::new(192, 52, 193, 0), 24), // AMT (RFC 7450)
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15), // benchmarking (RFC 2544)
    Ipv4Net::new_assert(Ipv4Addr::new(198, 51, 100, 0), 24), // TEST-NET-2 (documentation)
    Ipv4Net::new_assert(Ipv4Addr::new(203, 0, 113, 0), 24), // TEST-NET-3 (documentation)
    Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4), // multicast
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4), // reserved (covers 255.255.255.255)
];

/// Non-globally-routable IPv6 space. The first six entries are everything
/// below `2000::/3` — IANA's "reserved by IETF" region, which the old code
/// denied one arm per RFC, or (for most of the region, e.g. `::/8` beyond
/// `::1` and `::`) not at all. The rest are special-purpose registrations
/// inside and above `2000::/3`; the `2001:0xxx::` sub-blocks sit inside the
/// `2001::/23` blanket and are kept for their citations.
const NON_GLOBAL_V6: &[Ipv6Net] = &[
    // --- reserved by IETF: everything below 2000::/3 ---
    Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8), // incl. ::1 / :: beyond the ::/96 compatible form
    Ipv6Net::new_assert(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 16), // discard-only is 0100::/64 (RFC 6660); the whole /16 stays denied, as before
    Ipv6Net::new_assert(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0), 7), // reserved by IETF (RFC 4291)
    Ipv6Net::new_assert(Ipv6Addr::new(0x0400, 0, 0, 0, 0, 0, 0, 0), 6), // reserved by IETF
    Ipv6Net::new_assert(Ipv6Addr::new(0x0800, 0, 0, 0, 0, 0, 0, 0), 5), // reserved by IETF
    Ipv6Net::new_assert(Ipv6Addr::new(0x1000, 0, 0, 0, 0, 0, 0, 0), 4), // reserved by IETF
    // --- IETF protocol assignments (RFC 2928) ---
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23), // blanket for every 2001:0xxx:: block below
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 1), 128), // PCP anycast
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 2), 128), // TURN anycast
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 3), 128), // DNS-SD SRP anycast
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48), // benchmarking (RFC 5180)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0003, 0, 0, 0, 0, 0, 0), 32), // AMT (RFC 7450)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 0), 48), // AS112-v6
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28), // ORCHIDv1 (RFC 7343)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28), // ORCHIDv2 (RFC 7343)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28), // Drone Remote ID (RFC 9374)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32), // documentation (RFC 3849)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),      // 6to4 (RFC 3056)
    Ipv6Net::new_assert(Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0), 48), // AS112 direct delegation
    Ipv6Net::new_assert(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20), // documentation (RFC 9637)
    Ipv6Net::new_assert(Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // SRv6 SIDs (RFC 9602)
    Ipv6Net::new_assert(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 32), // NAT64 well-known prefix (the ::/96 form recurses in `is_global_ip`)
    // --- non-global unicast ---
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // ULA (RFC 4193)
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 0), 9), // IETF "reserved by IETF"; covers fe80::/10 and fec0::/10 below (RFC 4291)
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local unicast
    Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10), // site-local (deprecated, RFC 3879)
    Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),  // multicast
];

/// The IPv4 address embedded in the low 32 bits of an IPv6 address. The three
/// forms that carry one — IPv4-mapped, IPv4-translated and the deprecated
/// IPv4-compatible — all place it in segments 6 and 7, big-endian.
const fn embedded_v4(s: &[u16; 8]) -> Ipv4Addr {
    Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8)
}

/// True for globally routable targets; used to enforce `allow_private=false`.
///
/// Embedded-IPv4 forms recurse on the embedded address **before** the tables
/// are consulted — see the module docs for why the order matters. Everything
/// else is one linear CIDR scan per family; the verdict is memoized by the
/// callers (`is_global_ip_cached`), so the scan runs on uncached addresses
/// only.
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !NON_GLOBAL_V4.iter().any(|net| net.contains(&v4)),
        IpAddr::V6(v6) => {
            // `::ffff:0:0/96` IPv4-mapped: std owns the prefix; the embedded
            // address decides.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            let s = v6.segments();
            // RFC 2765 IPv4-translated `::ffff:0:a.b.c.d` is a distinct prefix
            // from IPv4-mapped; on stacks that translate it, the embedded
            // IPv4 decides reachability.
            if s[0..4].iter().all(|x| *x == 0) && s[4] == 0xffff && s[5] == 0 {
                return is_global_ip(IpAddr::V4(embedded_v4(&s)));
            }
            // 64:ff9b::/96 (well-known NAT64 prefix): validate the embedded
            // IPv4 so private/loopback targets cannot slip through via NAT64.
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
                return is_global_ip(IpAddr::V4(embedded_v4(&s)));
            }
            // Deprecated IPv4-compatible `::a.b.c.d`: validate the embedded
            // IPv4 too, closing a platform-dependent `allow_private` bypass.
            if s[0..6].iter().all(|x| *x == 0) {
                return is_global_ip(IpAddr::V4(embedded_v4(&s)));
            }
            !NON_GLOBAL_V6.iter().any(|net| net.contains(&v6))
        }
    }
}

/// Strip ::ffff:0:0/96 mapping so SOCKS replies carry a dialable address.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// Map IPv4 to ::ffff:0:0/96 for sending via a dual-stack IPv6 socket.
/// Linux maps in-kernel; macOS/BSD return EINVAL without it. Harmless everywhere.
pub fn map_for_dual(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        v6 => v6,
    }
}
