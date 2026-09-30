//! Destination pinning: recent-dst allowlist, dest memo, connection pin, resolve.
use super::*;

/// Destination IPs a session has recently sent to, for reply-source validation.
///
/// The match is on the **IP only**, not the full `(ip, port)` pair. An earlier
/// revision required the exact pair and thereby broke every protocol whose
/// server answers from a different port than it was queried on: TFTP is the
/// canonical case (the server replies from a fresh ephemeral port by design),
/// and game/voice stacks that redirect to a second port fail the same way. The
/// IP-only rule keeps the property that matters — an off-path attacker must
/// still spoof an address this session actually sent to, and the target's IP is
/// the hard half of that guess — while no longer filtering a legitimate peer on
/// that host.
///
/// A session may legally serve several targets (one association, many
/// datagrams), so this is a small allowlist rather than a single pin; past
/// [`RECENT_DST_CAP`] the oldest entry is evicted and a reply from it is dropped
/// until the session sends there again. Entries are normalized (IPv4 mappings
/// stripped) on both sides of the comparison.
#[derive(Clone, Debug, Default)]
pub(crate) struct RecentAddrs {
    /// Ring of the last [`RECENT_DST_CAP`] destination IPs sent to.
    pub(crate) slots: [Option<IpAddr>; RECENT_DST_CAP],
    /// Next write position.
    pub(crate) pos: usize,
}

/// How many distinct destination IPs one session remembers for reply
/// validation. 16 covers the multi-target session tests (2 alternating targets)
/// with room; a session talking to more distinct hosts concurrently re-learns
/// evicted ones on its next outbound datagram. It was 8, which a session
/// alternating over more than 8 hosts could outrun: a reply from an evicted
/// host was dropped as `REFUSED` until the session sent there again.
pub(crate) const RECENT_DST_CAP: usize = 16;

impl RecentAddrs {
    pub(crate) fn push(&mut self, dst: SocketAddr) {
        let ip = unmap(dst.ip());
        if self.slots.contains(&Some(ip)) {
            return;
        }
        self.slots[self.pos % RECENT_DST_CAP] = Some(ip);
        self.pos = self.pos.wrapping_add(1);
    }

    pub(crate) fn contains(&self, src: &SocketAddr) -> bool {
        self.slots.contains(&Some(unmap(src.ip())))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }
}
/// Where a session's target address came from, so a domain target is not
/// re-resolved on every datagram.
///
/// The UDP path is per-datagram: without this, a sustained flow to a domain
/// name went through `lookup_cached_fast` (hash + key build + full-key compare)
/// for *every* datagram, whose cost is real — measured at ~6 ns on a memo hit
/// but 15-26 ns/op once the memo's working set exceeds its associativity, which
/// is exactly the many-domains-per-worker case a busy proxy hits. The stream
/// head already pins one destination per quic stream; a session is the same
/// idea one layer down, so the resolution is stored here and every later
/// datagram for the session is a lock-free compare.
///
/// It is keyed on the target *name*, not on the session alone. A session is not
/// bound to one target — a client may send the same session id to a different
/// destination on the next datagram — so a memo that matched on the session
/// alone would answer a datagram naming B with the address resolved for A, and
/// the datagram would be relayed to the wrong target. That failure is silent
/// (replies come back from the wrong host), which is why the name is part of
/// the memo and is compared byte-for-byte, exactly like the DNS memo.
///
/// It is a *hint*, never a substitute for a lookup: it holds no negative state
/// and is ignored when expired, so a name that starts failing or rotates still
/// goes back through the resolver, and a target that moves is picked up within
/// `DEST_PIN_TTL` rather than for the lifetime of the session.
#[derive(Clone, Copy)]
pub(crate) struct DestMemo {
    /// The port and (for a domain target) the name this address was resolved
    /// for. An IP target stores an empty host: it has no name to re-check.
    pub(crate) key: PortKey,
    pub(crate) addr: SocketAddr,
    /// Monotonic deadline ([`mono_millis`] epoch). Read on the datagram path
    /// without a lock; the writer holds the table write lock already.
    pub(crate) expires: u64,
}

/// Domain names up to this length are stored inline in a [`DestMemo`]. Longer
/// names are simply never memoized and take the DNS path every time — a miss,
/// never a mis-route. 64 bytes covers all but a vanishing fraction of real
/// names, and a name longer than the 255-byte wire limit cannot occur here.
pub(crate) const DEST_KEY_BYTES: usize = 64;

/// What a memoized destination is valid *for*: the port always, and the
/// normalized target name when the target was a domain.
#[derive(Clone, Copy)]
pub(crate) struct PortKey {
    pub(crate) host_len: u8,
    pub(crate) host: [u8; DEST_KEY_BYTES],
    pub(crate) port: u16,
}

impl PortKey {
    pub(crate) const EMPTY: Self = Self {
        host_len: 0,
        host: [0; DEST_KEY_BYTES],
        port: 0,
    };

    /// `None` when the name is too long to store inline.
    pub(crate) fn new(host: &str, port: u16) -> Option<Self> {
        if host.len() > DEST_KEY_BYTES {
            return None;
        }
        let mut k = Self::EMPTY;
        k.host_len = host.len() as u8;
        k.host[..host.len()].copy_from_slice(host.as_bytes());
        k.port = port;
        Some(k)
    }

    #[inline]
    pub(crate) fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port
            && self.host_len as usize == host.len()
            && &self.host[..self.host_len as usize] == host.as_bytes()
    }
}

impl DestMemo {
    /// A fresh session has pinned nothing; `expires == 0` can never be `> now`,
    /// so the entry reads as absent without a separate flag.
    pub(crate) const NONE: Self = Self {
        key: PortKey::EMPTY,
        addr: SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        expires: 0,
    };

    /// The memoized address, but only for the target it was resolved for and
    /// only while it is live.
    #[inline]
    pub(crate) fn get(&self, now: u64, host: &str, port: u16) -> Option<SocketAddr> {
        (self.expires > now && self.key.matches(host, port)).then_some(self.addr)
    }

    /// True when this memo already names exactly `addr` for `(host, port)`,
    /// whatever its remaining life. The caller decides whether that life is
    /// short enough to be worth a refresh.
    #[inline]
    pub(crate) fn is_for(&self, host: &str, port: u16, addr: SocketAddr) -> bool {
        self.addr == addr && self.key.matches(host, port)
    }
}

/// How long a resolved destination is reused before it is re-resolved.
///
/// Deliberately shorter than the DNS cache TTL (60 s): DNS answers can change
/// while the cache entry is still live, so this bounds how long a session can
/// keep sending to an address the name no longer resolves to.
pub(crate) const DEST_PIN_TTL_MS: u64 = 30_000;

/// How close to expiry a memo must be before a datagram refreshes it.
///
/// A steady flow stores the same `(key, addr)` on every datagram, so refreshing
/// on each one turned the datagram path into a shard *write* lock per packet
/// (35 ns of lock plus a dirty line in the shared table, measured) for a value
/// that had not changed. Refreshing only in the last quarter of the TTL keeps
/// the entry continuously live with one write per ~7.5 s per session instead.
pub(crate) const DEST_PIN_REFRESH_MS: u64 = DEST_PIN_TTL_MS / 4;
/// The connection's pinned destination: the last `(session, name, port)` a
/// datagram was relayed to, plus the deadline that pin may still be trusted
/// for.
///
/// A per-connection shortcut for the per-session [`DestMemo`], and bounded the
/// same way on purpose. It carries its own deadline and is never refreshed on a
/// hit: a pin with no expiry kept a domain target's address for the whole
/// connection lifetime, so after a DNS change the flow was relayed to the old
/// address with no lookup ever consulted again — silently bypassing
/// [`DEST_PIN_TTL_MS`] for exactly the flow that never missed.
pub(crate) struct ConnPin {
    pub(crate) sess: u32,
    /// Length of the name in [`ConnPin::host`]. `u8` because the wire decoder
    /// caps a domain at 255 bytes.
    pub(crate) host_len: u8,
    /// The pinned name **inline**, up to the wire limit.
    ///
    /// It used to be a `String`, which made arming a pin a heap allocation —
    /// and `resolve_pin` arms on every pin *miss*, i.e. on every datagram of an
    /// interleaved multi-target session, with the reader re-arming the same name
    /// once more per slow path. So the one path this struct exists to keep
    /// cheap paid two malloc/free pairs per packet while the module documents
    /// the domain path as allocation-free. 255 bytes is the largest name the
    /// wire can carry, and the struct lives on the datagram reader's stack (one
    /// per connection), so the inline buffer costs nothing that matters.
    pub(crate) host: [u8; PIN_HOST_BYTES],
    pub(crate) port: u16,
    pub(crate) addr: SocketAddr,
    /// Monotonic deadline ([`mono_millis`] epoch), like [`DestMemo::expires`].
    pub(crate) expires: u64,
}

/// Bytes reserved for a pinned name: the MQP-2 wire limit (`u8` length prefix).
pub(crate) const PIN_HOST_BYTES: usize = 255;

/// Whether `pin` describes exactly `(name, port)`.
///
/// `pin.host_len` is a `u8`, so the comparison is against a slice that is always
/// in bounds, and a name that cannot be stored inline simply never matches.
pub(crate) fn pin_is_for(pin: &ConnPin, host: &str, port: u16) -> bool {
    pin.port == port
        && pin.host_len as usize == host.len()
        && &pin.host[..pin.host_len as usize] == host.as_bytes()
}

/// Arm `pin` for `(s, host, port)` with `life_ms` of life left.
///
/// Allocation-free by construction. A name longer than the inline buffer is not
/// pinned at all rather than truncated: a truncated key could match a different
/// name and mis-route the flow. That is unreachable today — the wire decoder
/// refuses a domain over 255 bytes and an IP target's name is empty — so this is
/// defence in depth, not a policy.
pub(crate) fn pin_arm(
    pin: &mut Option<ConnPin>,
    s: u32,
    host: &str,
    port: u16,
    addr: SocketAddr,
    life_ms: u64,
) {
    if host.len() > PIN_HOST_BYTES {
        return;
    }
    let mut cp = ConnPin {
        sess: s,
        host_len: host.len() as u8,
        host: [0; PIN_HOST_BYTES],
        port,
        addr,
        expires: coarse_millis() + pin_life_ms(life_ms),
    };
    let n = cp.host_len as usize;
    cp.host[..n].copy_from_slice(&host.as_bytes()[..n]);
    *pin = Some(cp);
}
pub(crate) const SLOTS: usize = 64;

/// Mix an IP into `0..SLOTS` with a manual multiply-add fold (no
/// SipHash on the packet path). A collision only shares a slot — the probe
/// compares the full key — so it can evict an entry but never mis-serve one.
pub(crate) fn ip_cache_idx(ip: IpAddr) -> usize {
    let mut h: u64 = 0;
    match ip {
        IpAddr::V4(v4) => {
            for o in v4.octets() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(o as u64);
            }
        }
        IpAddr::V6(v6) => {
            for s in v6.segments() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(s as u64);
            }
        }
    }
    (h % SLOTS as u64) as usize
}

/// Direct-mapped per-thread memo of `is_global_ip` verdicts.
///
/// Fixed-destination flows pay `is_global_ip` per inbound datagram, and the
/// predicate is pure over the IP, so the verdict is remembered thread-locally.
/// One hashed slot per address with a full-key compare makes a probe O(1)
/// instead of the O(SLOTS) linear scan the first revision used; a collision
/// only evicts the slot, so the security outcome is the same as calling the
/// predicate directly — only an exact key match is ever returned, never
/// another address's verdict.
pub(crate) fn is_global_ip_cached(ip: IpAddr) -> bool {
    thread_local! {
        static CACHE: std::cell::RefCell<[(Option<IpAddr>, bool); SLOTS]> =
            const { std::cell::RefCell::new([(None, false); SLOTS]) };
    }
    let idx = ip_cache_idx(ip);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c[idx].0 == Some(ip) {
            return c[idx].1;
        }
        let v = is_global_ip(ip);
        c[idx] = (Some(ip), v);
        v
    })
}

/// SSRF verdict for the connection reader's last fast-path destination.
///
/// `is_global_ip_cached` is already thread-local memoized, but a steady
/// single-target flow still paid its `RefCell` borrow plus hash-and-compare
/// on every datagram. This one-entry pin skips even that: a datagram for the
/// same `(session, dst)` reuses the verdict outright. It is keyed on the full
/// `SocketAddr` conservatively (a port change re-derives, which is always
/// safe), cleared wherever the allowlist mirror is, and — like the memo it
/// shadows — pure over the IP, so caching it changes no security outcome.
pub(crate) fn fast_allow_cached(
    cache: &mut Option<(u32, SocketAddr, bool)>,
    allow_private: bool,
    s: u32,
    dst: SocketAddr,
) -> bool {
    if allow_private {
        return true;
    }
    if let Some((cs, cd, v)) = *cache {
        if cs == s && cd == dst {
            return v;
        }
    }
    let v = is_global_ip_cached(dst.ip());
    *cache = Some((s, dst, v));
    v
}

/// The target a datagram names, as `(host, port)`. An IP target reports an
/// empty host: it has no name that could rotate to another address, so there is
/// nothing for a pin to re-check. A domain name is never empty on the wire
/// (`TargetAddrRef::decode` refuses a zero-length one), so the two forms cannot
/// collide in a [`ConnPin`].
pub(crate) fn target_name(a: TargetAddrRef<'_>) -> (&str, u16) {
    match a {
        TargetAddrRef::Ip(dst) => ("", dst.port()),
        TargetAddrRef::Domain(h, p) => (h, p),
    }
}

/// Resolve this datagram's target once, for both the fragment and the plain
/// branch. Order matters: the connection's pin first (free, and only trusted
/// while it still names the pinned session *and* has not expired), then the
/// session's own memo, then the DNS cache. `None` means "not known yet" --
/// `forward_server_dgram` spawns the resolver, so it is not an error.
pub(crate) fn resolve_pin(
    ss: &SessTable,
    pin: &mut Option<ConnPin>,
    pinned_sess: u32,
    s: u32,
    h: &str,
    p: u16,
    allow_private: bool,
) -> Option<SocketAddr> {
    // The coarse epoch: this value only ever feeds 30 s comparisons (the pin's
    // deadline and the session memo's TTL), and it sits on the per-datagram
    // domain path, so it must not be a vDSO `clock_gettime` per packet.
    // `sess_dest_store` writes the memo's `expires` from the same epoch, so the
    // two sides are directly comparable.
    let now = coarse_millis();
    // The connection-level pin is only trusted for the exact
    // (session, name, port) it was stored for, and only until its deadline.
    // Matching on the session alone would send a datagram naming a *different*
    // target to the address resolved for the previous one -- a silent
    // mis-route; ignoring the deadline would never re-resolve at all.
    if s == pinned_sess {
        if let Some(pin) = pin.as_ref() {
            if pin.sess == s && pin_is_for(pin, h, p) && pin.expires > now {
                return Some(pin.addr);
            }
        }
    }
    if let Some((dst, memo_life)) = sess_dest_lookup_ttl(ss, now, s, h, p) {
        // A filtered memo hit is unusable as-is, but the name may still
        // resolve to an allowed address in the full cached set (multi-record
        // names whose first address is private). Scan it here so the pin can
        // still arm on the fast path instead of forcing every packet through
        // the slow path for the rest of the DNS TTL.
        if allow_private || is_global_ip_cached(dst.ip()) {
            // Adopt the session's memo so the next datagram is a pure compare with
            // no table read at all -- for the memo's remaining life, never longer.
            pin_arm(pin, s, h, p, dst, memo_life);
            return Some(dst);
        }
        if let Some((set, set_life)) = lookup_cached_all_fast_with_ttl(h, p) {
            if let Some(d2) = set
                .iter()
                .copied()
                .find(|a| allow_private || is_global_ip_cached(a.ip()))
            {
                pin_arm(pin, s, h, p, d2, set_life);
                return Some(d2);
            }
        }
        return None;
    }
    let (lookup, ttl_ms) = lookup_cached_fast_with_ttl(h, p);
    match lookup {
        CachedLookup::Addr(dst) => {
            // The fast cache serves the first address only; a filtered first
            // address falls back to the full cached set before giving up, so
            // the pin arms the same way the slow path (`forward_server_dgram`)
            // would resolve it. Without this a name whose first record is
            // private never pinned and every packet paid the slow path.
            // A fallback into the full set inherits *that* set's remaining life,
            // not the first address's (they are the same entry here, but the
            // clamp must follow whichever address was actually adopted).
            let (addr, life) = if !allow_private && !is_global_ip_cached(dst.ip()) {
                lookup_cached_all_fast_with_ttl(h, p).and_then(|(set, life)| {
                    set.iter()
                        .copied()
                        .find(|a| allow_private || is_global_ip_cached(a.ip()))
                        .map(|a| (a, life))
                })?
            } else {
                (dst, ttl_ms)
            };
            // Adopt the DNS hit into the connection pin. Without this the pin
            // was only ever written from `sess_dest_lookup`, and a fast-path
            // success skips `forward_server_dgram` → `sess_dest_store` entirely:
            // the pin and the session dest expired together at T+30s while the
            // 60s DNS cache was still live, so every subsequent packet paid
            // `sess_dest_lookup` again for the rest of the DNS TTL (~50%
            // duty-cycle degradation on a steady domain flow). Same contract as
            // the memo branch above: pin for at most `DEST_PIN_TTL_MS`.
            pin_arm(pin, s, h, p, addr, life);
            Some(addr)
        }
        CachedLookup::Negative | CachedLookup::Unknown => None,
    }
}
/// Life to give a pin or destination memo armed from a source with `remaining_ms`
/// of its own life left.
///
/// `DEST_PIN_TTL_MS` is documented as "deliberately shorter than the DNS cache
/// TTL (60 s): DNS answers can change while the cache entry is still live, so
/// this bounds how long a session can keep sending to an address the name no
/// longer resolves to". Measured *from adoption* that bound was false: a pin
/// armed from an entry with 100 ms of life left (or from a session memo with the
/// same) lived its own full 30 s, so an address resolved 60 s ago could still be
/// used 90 s after resolution — 30 s past the TTL every other layer respects.
/// Every arming site therefore clamps to the source's remaining life; a fresh
/// resolution (the spawned resolver task) passes `DNS_CACHE_TTL_MS`, where the
/// 30 s pin wins and behaviour is unchanged.
pub(crate) fn pin_life_ms(remaining_ms: u64) -> u64 {
    DEST_PIN_TTL_MS.min(remaining_ms)
}

/// Record that session `s` sent to `dst`. Best effort: a vanished session is
/// simply not updated and its next datagram recreates it. Normalization lives
/// in [`RecentAddrs`] itself, so both sides of the comparison agree.
///
/// The session's allowlist epoch moves with the push, whether it lands from the
/// datagram reader's own task or from a spawned resolver task that the reader
/// cannot see; that is what `fast_last_dst` is validated against.
///
/// The push itself is a lock-free `rcu` publish: the reply reader loads a
/// snapshot for every datagram, so writers must not take a lock the readers
/// would have to contend with, and `rcu`'s retry makes two concurrent pushes
/// both land (a load-clone-store would drop one, and a dropped allowlist entry
/// is a silently refused reply).
pub(crate) fn remember_dst(ss: &SessTable, s: u32, dst: SocketAddr) {
    let sh = ss.shard(s);
    if let Some(e) = lock_read(sh).get(&s) {
        let ip = unmap(dst.ip());
        // Fast exit for the steady flow (one already-known destination): no
        // clone, no allocation, no CAS — just the epoch move below. A concurrent
        // push that evicts this very entry out of a full ring can slip between
        // this check and the skip, which costs at most one refused reply batch:
        // the epoch below still moves, so the reader's mirror re-records the
        // destination on its next outbound datagram.
        if !e.recent.load().slots.contains(&Some(ip)) {
            e.recent.rcu(|cur| {
                if cur.slots.contains(&Some(ip)) {
                    // Another writer got there first; keep its snapshot.
                    Arc::clone(cur)
                } else {
                    let mut next = (**cur).clone();
                    next.push(dst);
                    Arc::new(next)
                }
            });
        }
        e.recent_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Record `dst` for `s` unless this reader already did so and the session's
/// allowlist has not moved since.
///
/// `epoch` is the session's allowlist epoch; `None` means the reader has no
/// session armed, so the record always happens. A *foreign* push (the
/// resolver task `forward_server_dgram` spawns) moves the epoch without this
/// reader seeing it, and 17 of those evict a destination the ring still claims
/// is present — the mirror then suppressed the re-record for the rest of the
/// pin/DNS lifetime and the target's replies were dropped as forged, i.e. a
/// silent one-way flow. Comparing the epoch costs one relaxed load and catches
/// exactly that.
pub(crate) fn mirror_record(
    ss: &SessTable,
    mirror: &mut Option<(u32, SocketAddr, u64)>,
    s: u32,
    dst: SocketAddr,
    epoch: Option<&std::sync::atomic::AtomicU64>,
) {
    let Some(epoch) = epoch else {
        remember_dst(ss, s, dst);
        *mirror = None;
        return;
    };
    if *mirror != Some((s, dst, epoch.load(std::sync::atomic::Ordering::Relaxed))) {
        remember_dst(ss, s, dst);
        // Re-read after the push: the next datagram then skips the record until
        // something moves the epoch again.
        *mirror = Some((s, dst, epoch.load(std::sync::atomic::Ordering::Relaxed)));
    }
}
