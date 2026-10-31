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

/// Domain names up to this length are stored inline in a [`DestMemo`]; longer
/// names are never memoized and take the DNS path every time — a miss, never a
/// mis-route.
///
/// The bound is the **wire-format maximum**, not a compromise: `host_len` is a
/// `u8` length prefix, so 255 bytes is the longest name MQP-2 can carry and the
/// field can hold it exactly. It used to be 64 ("covers all but a vanishing
/// fraction of real names"), which was the wrong trade for this path: a name in
/// 65..=255 was never memoized, so every one of its datagrams re-entered the
/// spawned-resolver slow path (`forward_server_dgram`'s spawn arm cannot return
/// `Some`, so the connection fast table could never arm either) — a per-packet
/// resolution where a single store would have made the next packet a compare.
/// The cost of the wider key is the inline `PortKey` in every `DestMemo`
/// (`DestMemo` is embedded in `SessEntry`): `u8` length + 255-byte host +
/// `u16` port = 258 B, so `DestMemo` (key + `SocketAddr` + deadline) is
/// ~304 B. Bounded by the global `MAX_SESSIONS_GLOBAL` = 8192 session cap,
/// i.e. ~2.4 MiB in the pathological all-255-byte-names case — paid once per
/// session, not per packet.
pub(crate) const DEST_KEY_BYTES: usize = 255;

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
/// Deliberately shorter than the DNS cache TTL (120 s): DNS answers can change
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

/// SSRF verdict for a fast-path destination.
///
/// The fast slot used to carry a one-entry `(sess, dst, verdict)` pin to skip
/// this call. At 40 bytes per slot that pin cost more working-set capacity
/// than it saved: `is_global_ip_cached` is already an O(1) hashed per-thread
/// memo keyed by IP, and the verdict is pure, so recomputing it keeps the same
/// security outcome while the slot count grows by roughly 40%.
pub(crate) fn fast_allow(allow_private: bool, dst: SocketAddr) -> bool {
    allow_private || is_global_ip_cached(dst.ip())
}

/// Resolve this datagram's target once, for both the fragment and the plain
/// branch. Order matters: the caller's pin first (when supplied; free, and
/// only trusted while it still names the pinned session *and* has not
/// expired), then the session's own memo, then this thread's DNS memo. `None`
/// means "not known yet" -- `forward_server_dgram` spawns the resolver (which
/// resolves from the shared caches and stores the session memo), so it is not
/// an error. The fast table no longer carries a per-session pin; callers on
/// the INLINE/legacy path pass a stack-local scratch.
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
    // domain path, so it must not be a precise clock read per packet.
    // `sess_dest_store` writes the memo's `expires` from the same epoch, so the
    // two sides are directly comparable.
    let now = coarse_millis();
    // The pin is only trusted for the exact (session, name, port) it was
    // stored for, and only until its deadline.
    // Matching on the session alone would send a datagram naming a *different*
    // target to the address resolved for the previous one -- a silent
    // mis-route; ignoring the deadline would never re-resolve at all.
    if s == pinned_sess
        && let Some(pin) = pin.as_ref()
        && pin.sess == s
        && pin_is_for(pin, h, p)
        && pin.expires > now
    {
        // No SSRF recheck here. Every arm site filters *before* it pins
        // (`resolve_pin`'s own two arms below; the fast table no longer arms a
        // pin), the pinned address never changes for the pin's life, and
        // `is_global_ip` is a pure function of that address — so a recheck
        // could only ever re-derive `true`, at one thread-local hash per
        // datagram on this path. `allow_private` is a per-connection constant,
        // so neither branch can flip under a live pin either. (An earlier
        // revision argued a pin "could now read as non-global"; a pure
        // predicate over an immutable address cannot.)
        return Some(pin.addr);
    }
    if let Some((dst, memo_life)) = sess_dest_lookup_ttl(ss, now, s, h, p) {
        if allow_private || is_global_ip_cached(dst.ip()) {
            // Adopt the session's memo so the next datagram is a pure compare with
            // no table read at all -- for the memo's remaining life, never longer.
            pin_arm(pin, s, h, p, dst, memo_life);
            return Some(dst);
        }
        // A filtered memo hit is unusable as-is. The full address set is not
        // reachable from this synchronous path (the fast layer is the thread
        // memo, which holds the first address only); the async slow path
        // re-resolves from the shared caches, picks a usable record and stores
        // it into the session memo, which arms the pin on the next datagram.
        return None;
    }
    let (lookup, ttl_ms) = lookup_cached_fast_with_ttl(h, p);
    match lookup {
        CachedLookup::Addr(dst) => {
            // Filtered first address: same handoff as the memo branch above —
            // one slow-path datagram resolves the rest of the set. Without the
            // pin write-back below, a fast-path success skips
            // `forward_server_dgram` → `sess_dest_store` entirely: the pin and
            // the session dest expired together at T+30s while the DNS entry
            // (120 s) was still live, so every subsequent packet paid
            // `sess_dest_lookup` again for the rest of the TTL (~50%
            // duty-cycle degradation on a steady domain flow).
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                return None;
            }
            // Adopt the memo hit into the connection pin for at most
            // `DEST_PIN_TTL_MS`, clamped by the hit's own remaining life.
            pin_arm(pin, s, h, p, dst, ttl_ms);
            Some(dst)
        }
        CachedLookup::Negative | CachedLookup::Unknown => None,
    }
}
/// Life to give a pin or destination memo armed from a source with `remaining_ms`
/// of its own life left.
///
/// `DEST_PIN_TTL_MS` is documented as "deliberately shorter than the DNS cache
/// TTL (120 s): DNS answers can change while the cache entry is still live, so
/// this bounds how long a session can keep sending to an address the name no
/// longer resolves to". Measured *from adoption* that bound was false: a pin
/// armed from an entry with 100 ms of life left (or from a session memo with the
/// same) lived its own full 30 s, so an address resolved at the start of an
/// entry could still be used 30 s past its resolution's TTL — the one every
/// other layer respects. Every arming site therefore clamps to the source's
/// remaining life; a fresh resolution (the spawned resolver task) passes
/// `DNS_CACHE_TTL_MS`, where the 30 s pin wins and behaviour is unchanged.
///
/// Convergence bound: a public DNS flip is served stale for at most the pin's
/// remaining life (worst 30 s from adoption, usually far less via the clamp).
/// There is deliberately **no** pin-hit SSRF recheck: every arm site filters
/// before it pins, the pinned address never changes, and `is_global_ip` is a
/// pure function of that address. A name that now resolves to a filtered
/// (non-global) address therefore does not switch the flow to it; the old
/// address, which passed the filter when it was pinned, is served until the
/// pin expires and the next resolution applies the new policy. The
/// steady/TRAIN path resolves from the flow binding and does not read this
/// pin at all.
pub(crate) fn pin_life_ms(remaining_ms: u64) -> u64 {
    DEST_PIN_TTL_MS.min(remaining_ms)
}

/// Record that session `s` sent to `dst`. Best effort: a vanished session is
/// simply not updated and its next datagram recreates it. Normalization lives
/// in [`RecentAddrs`] itself, so both sides of the comparison agree.
///
/// The session's allowlist epoch moves **only when the snapshot actually
/// changes**, whether the push lands from the datagram reader's own task or from
/// a spawned resolver task that the reader cannot see; that is what
/// `fast_last_dst` is validated against. An earlier revision bumped it after
/// every call — including the steady-flow call that finds `dst` already in the
/// ring and publishes nothing — which defeated the epoch's whole purpose: the
/// reply reader (`sess_reader_task`) then reloaded the `ArcSwap` snapshot with
/// `load_full` on *every* reply instead of one relaxed load, and the datagram
/// side paid a cross-task cache-line RMW per packet. That is exactly the
/// slow-path flow the mirror exists to make cheap (multi-destination sessions,
/// unarmed/colliding fast slots), so the redundant bump was pure loss.
///
/// A skip that publishes nothing cannot make a reader's mirror stale: the only
/// way the mirrored `(session, dst, epoch)` triple stops describing the ring is
/// an actual push (its eviction or its insertion), and the writer that performs
/// that push is the one that bumps here. A racing writer's push therefore bumps
/// the epoch before/while the skip is observed, so no real change goes
/// unpublished.
///
/// The push itself is a lock-free `rcu` publish: the reply reader loads a
/// snapshot for every datagram, so writers must not take a lock the readers
/// would have to contend with, and `rcu`'s retry makes two concurrent pushes
/// both land (a load-clone-store would drop one, and a dropped allowlist entry
/// is a silently refused reply).
pub(crate) fn remember_dst(ss: &SessTable, s: u32, dst: SocketAddr) {
    let sh = ss.shard(s);
    if let Some(e) = sh.read().get(&s) {
        let ip = unmap(dst.ip());
        // Fast exit for the steady flow (one already-known destination): no
        // clone, no allocation, no CAS, and — the point of this function's
        // shape — no epoch RMW either.
        if !e.recent.load().slots.contains(&Some(ip)) {
            // `rcu` may retry the closure; a retry that observes another
            // writer's push and returns the current snapshot must still count as
            // a change (one of the attempts pushed). The epoch is only ever
            // over-bumped on that race, which is the safe direction.
            let pushed = std::cell::Cell::new(false);
            e.recent.rcu(|cur| {
                if cur.slots.contains(&Some(ip)) {
                    // Another writer got there first; keep its snapshot.
                    Arc::clone(cur)
                } else {
                    let mut next = (**cur).clone();
                    next.push(dst);
                    pushed.set(true);
                    Arc::new(next)
                }
            });
            if pushed.get() {
                e.recent_epoch
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
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
