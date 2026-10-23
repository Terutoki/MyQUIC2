//! Reconnect/backoff jitter.

/// Random milliseconds in `0..=199` for reconnect/backoff waits.
///
/// Draws from `rand`'s thread-local generator, which is per-thread seeded:
/// concurrent clients do not share one backoff sequence (the property the
/// hand-rolled xorshift this replaces was written to provide). All call
/// sites are cold — dial/redial backoff and the per-association idle-tick
/// phase — so the generator's cost is irrelevant there.
pub(crate) fn jitter_ms() -> u64 {
    rand::random_range(0..200u64)
}

/// Whether a configured listen address is loopback for warning purposes.
///
/// `IpAddr::is_loopback` is false for the IPv4-mapped IPv6 form
/// (`[::ffff:127.0.0.1]`), which is loopback-only traffic: the mapped v4
/// address is what the socket actually serves (an AF_INET6 socket with
/// `V6ONLY=0` reports mapped peers, and a mapped loopback peer can only be
/// local). Unmapping first keeps the "listener is not loopback, any host that
/// can reach it can use the tunnel" warning from firing on a configuration that
/// is in fact safe, while a genuine `::`/`0.0.0.0` wildcard still warns.
pub(crate) fn listen_is_loopback(addr: std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.is_loopback())
            .unwrap_or_else(|| v6.is_loopback()),
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
    }
}
