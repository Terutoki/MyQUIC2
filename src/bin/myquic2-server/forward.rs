//! Datagram forwarding to the target.
use super::*;

// ---------------------------------------------------------------------------
// Per-connection DNS gate
// ---------------------------------------------------------------------------

/// Entries in one connection's [`DnsGate`]: at most this many distinct
/// `(session, name, port)` resolutions can be in flight or negatively cached at
/// once. Small on purpose — a connection's datagram-path names are the handful
/// of targets its sessions actually talk to, and a table overflow only costs
/// one extra spawned waiter (a miss, never a wrong decision).
pub(crate) const DNS_GATE_SLOTS: usize = 8;

/// How long an in-flight claim blocks later datagrams before it is treated as
/// abandoned.
///
/// A completed waiter always calls [`DnsGate::finish`]; this backstop only
/// matters when a spawned task panics (or its runtime is torn down) without
/// completing. Longer than the DNS lookup budget plus the session work it
/// chains into (5 s lookup + socket setup), so a legitimately slow resolution is
/// never re-spawned by the backstop.
pub(crate) const DNS_GATE_INFLIGHT_TTL_MS: u64 = 15_000;

/// Datagrams parked behind one in-flight resolution.
///
/// A cold name's burst used to be one spawn plus N drops: every datagram after
/// the first was refused, so the application waited out its own retransmit timer
/// (200 ms on QUIC PTO, ~1 s on a TCP-style RTO) for a name that was already
/// being resolved. Parking the followers removes that wait, at the cost of
/// holding their payloads for the length of one lookup. Four is enough for the
/// DNS-shaped case (a query and its retransmits, or a small burst of a new
/// flow); beyond that the datagram is ordinary UDP loss again, which the peer
/// already handles.
pub(crate) const DNS_GATE_PARK_ITEMS: usize = 4;

/// Payload bytes parked behind one in-flight resolution.
///
/// The item cap alone does not bound memory — one "datagram" can be up to
/// `UDP_RECV_MAX` — so the byte cap does, and it is charged in
/// [`myquic2::config::tuning::dns_inflight_memory_bytes`] as one park buffer per
/// slow-path permit (a parked set only exists while its claim's waiter holds a
/// permit).
pub(crate) const DNS_GATE_PARK_BYTES: usize = 8 * 1024;

/// Ceiling on how long a **policy** refusal is trusted.
///
/// This is the one refusal the DNS layer never sees: the resolver answered, but
/// every record was filtered by the egress policy (see [`filtered_ttl_ms`]). A
/// DNS failure carries its own class instead — `DNS_NEG_TTL` (10 s) for a
/// verdict, `DNS_INCONCLUSIVE_TTL` (1 s) for a backoff — and the gate mirrors
/// exactly that, so an application retransmitting at 1.2 s after a transient
/// timeout is not dropped for a name the shared cache would already re-resolve.
///
/// A filtered verdict is different from both: it is a property of the *answer*
/// (these records, in this order), and the answer cannot change while it is
/// cached. So the gate holds for the answer's own remaining life, capped here —
/// 60 s covers a full-TTL answer without letting one filtered name keep a gate
/// slot indefinitely, and the flat 5 s this replaced re-spawned the same doomed
/// resolution up to twenty-four times per cached answer.
pub(crate) const DNS_GATE_FILTERED_TTL_MS: u64 = 60_000;

/// The gate's deadline for a refused name, in milliseconds.
///
/// A DNS failure carries its own class (`DnsFailure::retry_ttl`: 10 s for a
/// verdict, 1 s for a backoff) and the gate trusts it, so a retransmit that the
/// shared cache would re-resolve is not dropped here. [`filtered_ttl_ms`] is the
/// third case: an answered name whose every record the egress policy filtered.
fn gate_ttl_ms(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)
}

/// How long "every record of this answer is filtered" stays true.
///
/// It stays true exactly as long as the cached answer does: the same record set,
/// filtered by the same policy, is the same verdict, and a fresh resolution
/// re-decides either way. So the window is the entry's remaining life, capped by
/// [`DNS_GATE_FILTERED_TTL_MS`] to bound one name's hold on a gate slot. A memo
/// miss (another thread overwrote the slot, or the answer was just seeded) falls
/// back to a full fresh-answer bound, because `resolve_all_cached` has just
/// memoized it for this thread.
pub(crate) fn filtered_ttl_ms(host: &str, port: u16) -> u64 {
    let (_, life) = lookup_cached_fast_with_ttl(host, port);
    let life = if life == 0 { DNS_CACHE_TTL_MS } else { life };
    life.min(DNS_GATE_FILTERED_TTL_MS)
}

/// Test-only count of spawned resolver waiters.
///
/// The gate's whole effect is "one waiter instead of one per datagram", and the
/// observable counters (delivery, REFUSED) cannot distinguish a spawn from an
/// inline refusal, so the regression test needs the spawn count itself — the
/// same shape as `BATCH_FAST_ARMS` for the fast-table arms.
#[cfg(test)]
pub(crate) static DNS_WAITER_SPAWNS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// What [`DnsGate::claim`] says about one datagram's name.
#[derive(Debug)]
pub(crate) enum GateClaim {
    /// No live entry existed; the gate has recorded an in-flight claim and the
    /// caller must spawn the waiter. The token goes to [`DnsGate::finish`].
    Proceed(u32),
    /// The same `(session, name, port)` is already being resolved: drop this
    /// datagram (UDP semantics) instead of spawning another task for it.
    InFlight,
    /// The last resolution produced no usable address; refuse inline until the
    /// verdict expires instead of spawning a waiter per datagram.
    Unusable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GateState {
    InFlight,
    Unusable,
}

struct GateEntry {
    /// Hash of the normalized `(session, host, port)` — see [`DnsGate::key`].
    key: u64,
    state: GateState,
    deadline: u64,
    /// Identifies one claim generation: a waiter that outlived its entry (the
    /// backstop expired and the slot was reused) must not clear or rewrite a
    /// newer claim for the same key.
    generation: u32,
    /// Followers that arrived while this claim was in flight, in arrival order.
    /// Delivered by the waiter once it has an answer (see [`DnsGate::park`]);
    /// anything still here when the claim completes without one is counted as
    /// dropped.
    parked: Vec<Bytes>,
    /// Payload bytes in `parked`, bounded by [`DNS_GATE_PARK_BYTES`].
    parked_bytes: usize,
}

struct GateInner {
    entries: [Option<GateEntry>; DNS_GATE_SLOTS],
    next_generation: u32,
}

/// Per-connection coalescing + short-lived negative cache for the domain-target
/// slow path.
///
/// Before this, every datagram whose name could not be answered by the thread's
/// DNS memo or the session destination memo spawned its own resolver task. For
/// a *new* session that is a whole drain burst's worth of tasks (up to 32) while
/// the first lookup is still in flight, and for a name whose records the SSRF
/// filter rejects it is *every datagram, forever*: the thread memo only ever
/// holds the first (`filtered`) address, so the spawn arm was re-entered
/// per packet — one `tokio::spawn`, one `String`, two `Arc` clones, one
/// slow-path permit, two moka lookups and two allocations per packet, on a path
/// a peer can drive with a public name that resolves to a private address.
///
/// The gate makes that one waiter per `(session, name, port)`: the datagrams
/// that arrive during the flight are parked behind the claim (bounded by
/// [`DNS_GATE_PARK_ITEMS`]/[`DNS_GATE_PARK_BYTES`], delivered as soon as the
/// answer lands — see [`DnsGate::park`]) and overflow is ordinary UDP loss, and
/// an unusable verdict is remembered for its class's window so the next packets
/// are refused inline for one hash + one mutex instead of a task spawn.
///
/// It never *admits* anything: a gate decision can only drop a datagram or let
/// it spawn, so the SSRF policy and `allow_private` semantics are unchanged.
pub(crate) struct DnsGate {
    inner: parking_lot::Mutex<GateInner>,
    seed: std::hash::RandomState,
    /// One-slot fast verdict hint in front of the mutex, published by the
    /// *authoritative* decision sites and refreshed whenever the slot verdict
    /// they installed was itself served through the lock:
    ///
    /// * `claim()` publishes every resolution it found or created, so the
    ///   repeated datagrams of a filtered name (or the followers of an
    ///   in-flight burst) skip the lock acquire plus the 8-slot scan for one
    ///   relaxed-load triple.
    /// * `finish()` publishes an `Unusable` verdict through the same slot and
    ///   *invalidates* the slot on a cleared (delivered) verdict — a
    ///   `Proceed`-then-finish must not leave an `InFlight` hint behind, since
    ///   the inner entry is gone and the gate would `Proceed` again. (The
    ///   evicted-then-unusable publish is likewise synchronous.) The only
    ///   drift left is a hint outliving the eviction of *its own* inner entry
    ///   by other claims, bounded by the entry's verdict TTL; a stale hit then
    ///   drops datagrams the gate would have let spawn, never the reverse in
    ///   any durable way, and never mis-routes anything.
    ///
    /// A zero `hot_key` means "no hint"; a claim key that hashes to 0 simply
    /// never hits the fast path and always takes the lock (a harmless
    /// conservative outcome for an astronomically rare collision). The key is
    /// stored with `Release` and read with `Acquire`, so a hint that is seen
    /// at all is seen *whole*: the state and deadline stores cannot be
    /// reordered past the key store, and an invalidation takes effect for
    /// every reader that starts after it. Everything else is `Relaxed` — the
    /// hint only decides drop-or-spawn, and expiry bounds any torn/stale
    /// window to one verdict TTL.
    hot_key: std::sync::atomic::AtomicU64,
    hot_state: std::sync::atomic::AtomicU64,
    hot_deadline: std::sync::atomic::AtomicU64,
    /// Test-only per-gate count of datagrams this gate refused (InFlight or a
    /// cached Unusable verdict). The process-wide `dgram_drops` counters are
    /// shared by every concurrently running test, so tests that assert exact
    /// accounting of *their own* burst must count locally.
    #[cfg(test)]
    refusals: std::sync::atomic::AtomicU64,
}

impl DnsGate {
    pub(crate) fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(GateInner {
                // `GateEntry` owns a parked-payload vector, so the array is
                // built element-wise instead of copied from `[None; N]`.
                entries: std::array::from_fn(|_| None),
                next_generation: 0,
            }),
            seed: std::hash::RandomState::new(),
            hot_key: std::sync::atomic::AtomicU64::new(0),
            hot_state: std::sync::atomic::AtomicU64::new(0),
            hot_deadline: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            refusals: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record one gate refusal (test-only, local to this gate instance).
    #[cfg(test)]
    pub(crate) fn note_refusal(&self) {
        self.refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Number of datagrams this gate refused so far (test-only; immune to the
    /// process-global counters other concurrent tests bump).
    #[cfg(test)]
    pub(crate) fn refusals(&self) -> u64 {
        self.refusals.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Publish the fast hint (see the field docs). The key is stored last with
    /// `Release`, so every reader that gates on it (`Acquire` load) sees the
    /// state and deadline a hint carries; an invalidated hint stores key 0 and
    /// takes effect for every subsequent reader.
    fn publish_hot(&self, key: u64, state: GateState, deadline: u64) {
        use std::sync::atomic::Ordering;
        self.hot_deadline.store(deadline, Ordering::Relaxed);
        self.hot_state.store(
            match state {
                GateState::InFlight => 1_u64,
                GateState::Unusable => 2_u64,
            },
            Ordering::Relaxed,
        );
        self.hot_key.store(key, Ordering::Release);
    }

    /// Invalidate the fast hint (verdict cleared / undecidable finish).
    fn clear_hot(&self) {
        self.hot_key.store(0, std::sync::atomic::Ordering::Release);
    }

    /// The key one `(session, name, port)` resolution is gated on.
    ///
    /// A 64-bit hash (randomly seeded, like `foldhash` in the session table) is
    /// enough: the gate only decides *drop vs spawn*, never where a datagram is
    /// routed, so a collision can at worst cost a dropped/missed spawn — never a
    /// mis-route. The name is normalized the way DNS treats it (case folded,
    /// trailing dots stripped), so two spellings of one name share a claim.
    fn key(&self, s: u32, host: &str, port: u16) -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = self.seed.build_hasher();
        h.write_u32(s);
        h.write_u16(port);
        let bytes = host.as_bytes();
        let mut end = bytes.len();
        while end > 1 && bytes[end - 1] == b'.' {
            end -= 1;
        }
        for b in &bytes[..end] {
            h.write_u8(b.to_ascii_lowercase());
        }
        h.write_usize(end);
        h.finish()
    }

    /// Claim the right to spawn a resolver for `(s, host, port)` at `now_ms`.
    ///
    /// `Proceed` records the in-flight claim before returning, so the caller
    /// must either spawn the waiter or (on a later failure before the spawn)
    /// [`finish`](Self::finish) it with `unusable = false`. The permit is taken
    /// *before* this call by the caller, so a claim always has its budget.
    ///
    /// The fast slot is consulted first: a published live verdict for this
    /// exact key returns without the mutex (and its 8-slot scan). A miss —
    /// which includes any *other* key overwriting the one-slot hint, an
    /// expired verdict, and any state whose slot was written by a generation
    /// this fast read cannot identify — falls through to the authoritative
    /// lock path below.
    pub(crate) fn claim(&self, s: u32, host: &str, port: u16, now_ms: u64) -> GateClaim {
        use std::sync::atomic::Ordering;
        let key = self.key(s, host, port);
        // The key load pairs `Release` with `Acquire`: a hint seen at all is
        // seen whole (state and deadline included).
        if key != 0 && self.hot_key.load(Ordering::Acquire) == key {
            let deadline = self.hot_deadline.load(Ordering::Relaxed);
            if deadline > now_ms {
                match self.hot_state.load(Ordering::Relaxed) {
                    1 => return GateClaim::InFlight,
                    2 => return GateClaim::Unusable,
                    _ => {}
                }
            }
        }
        let mut inner = self.inner.lock();
        if let Some(e) = inner
            .entries
            .iter()
            .flatten()
            .find(|e| e.key == key && e.deadline > now_ms)
        {
            // Refresh the hint with the authoritative verdict (this claim
            // already paid the lock; the followers do not have to).
            self.publish_hot(key, e.state, e.deadline);
            return match e.state {
                GateState::InFlight => GateClaim::InFlight,
                GateState::Unusable => GateClaim::Unusable,
            };
        }
        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        let slot = inner
            .entries
            .iter()
            .position(|e| e.as_ref().is_none_or(|x| x.deadline <= now_ms))
            // All slots live: overwrite round-robin. An evicted in-flight
            // claim's waiter still delivers its payload; its `finish` finds no
            // matching generation and is a no-op.
            .unwrap_or((generation as usize) % DNS_GATE_SLOTS);
        let deadline = now_ms.saturating_add(DNS_GATE_INFLIGHT_TTL_MS);
        inner.entries[slot] = Some(GateEntry {
            key,
            state: GateState::InFlight,
            deadline,
            generation,
            parked: Vec::new(),
            parked_bytes: 0,
        });
        self.publish_hot(key, GateState::InFlight, deadline);
        GateClaim::Proceed(generation)
    }

    /// Park a follower datagram behind the in-flight claim it arrived during.
    ///
    /// Returns `false` when there is no live in-flight claim for the key (the
    /// answer landed between the caller's `claim` and this call) or when the
    /// queue bounds are full — both are the old behaviour, ordinary UDP loss.
    ///
    /// The datagram is *delayed*, not admitted: it is sent only once the answer
    /// this claim is waiting for arrives, through the same delivery path as the
    /// datagram that spawned the waiter, so the address is one the egress policy
    /// already approved.
    pub(crate) fn park(&self, s: u32, host: &str, port: u16, now_ms: u64, payload: Bytes) -> bool {
        let key = self.key(s, host, port);
        let mut inner = self.inner.lock();
        let Some(entry) = inner
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.key == key && e.state == GateState::InFlight && e.deadline > now_ms)
        else {
            return false;
        };
        if entry.parked.len() >= DNS_GATE_PARK_ITEMS
            || entry.parked_bytes.saturating_add(payload.len()) > DNS_GATE_PARK_BYTES
        {
            return false;
        }
        entry.parked_bytes += payload.len();
        entry.parked.push(payload);
        true
    }

    /// Take the followers parked behind `generation`'s claim, in arrival order.
    ///
    /// Only that generation's claim may hand them back: a waiter that outlived
    /// its entry must not deliver a newer claim's datagrams.
    pub(crate) fn take_parked(&self, s: u32, host: &str, port: u16, generation: u32) -> Vec<Bytes> {
        let key = self.key(s, host, port);
        let mut inner = self.inner.lock();
        let Some(entry) = inner
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.key == key && e.generation == generation)
        else {
            return Vec::new();
        };
        entry.parked_bytes = 0;
        std::mem::take(&mut entry.parked)
    }

    /// Complete a claim taken by [`claim`](Self::claim).
    ///
    /// Clears the in-flight entry on a delivered/undecidable outcome, or — when
    /// the name yielded no usable address — replaces it with a short-lived
    /// `Unusable` verdict so the following datagrams refuse inline. The fast
    /// slot follows the same verdict it mirrors: published for `Unusable`,
    /// invalidated for a cleared verdict (see the field docs).
    pub(crate) fn finish(
        &self,
        s: u32,
        host: &str,
        port: u16,
        generation: u32,
        unusable: Option<Duration>,
        now_ms: u64,
    ) {
        let key = self.key(s, host, port);
        let now = now_ms;
        let mut inner = self.inner.lock();
        // Followers parked behind this claim are delivered by its waiter before
        // it finishes. Anything still here means the claim ended without an
        // answer (a verdict, a cancelled waiter, an evicted slot), so those
        // datagrams are ordinary UDP loss: counted, never silently discarded.
        // Taken before any branch below replaces the entry and its vectors.
        let parked_lost: usize = inner
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.key == key && e.generation == generation)
            .map(|e| {
                e.parked_bytes = 0;
                std::mem::take(&mut e.parked).len()
            })
            .sum();
        for _ in 0..parked_lost {
            dgram_drops::bump(&dgram_drops::REFUSED);
        }
        if let Some(slot) = inner
            .entries
            .iter_mut()
            .find(|e| e.as_ref().is_some_and(|x| x.key == key))
            && slot.as_ref().is_some_and(|e| e.generation == generation)
        {
            if let Some(ttl) = unusable {
                let deadline = now.saturating_add(gate_ttl_ms(ttl));
                *slot = Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline,
                    generation,
                    parked: Vec::new(),
                    parked_bytes: 0,
                });
                self.publish_hot(key, GateState::Unusable, deadline);
            } else {
                // The claim delivered (or was undecidable): the gate must
                // `Proceed` for the next datagrams, so the InFlight hint dies
                // with the entry.
                *slot = None;
                self.clear_hot();
            }
        } else if let Some(ttl) = unusable {
            // The claim was evicted (or its backstop expired and the slot was
            // reused) while the waiter ran: still publish the verdict, in the
            // first free/expired slot, so the next datagrams can refuse inline.
            if let Some(slot) = inner
                .entries
                .iter_mut()
                .find(|e| e.as_ref().is_none_or(|x| x.deadline <= now))
            {
                let deadline = now.saturating_add(gate_ttl_ms(ttl));
                *slot = Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline,
                    generation,
                    parked: Vec::new(),
                    parked_bytes: 0,
                });
                self.publish_hot(key, GateState::Unusable, deadline);
            }
        } else {
            // The slot was either evicted or its generation went stale (a
            // newer claim for the same key owns it). Only in the first case is
            // there no authoritative entry left for this key: an `InFlight`
            // hint would otherwise drop datagrams the gate lets spawn until
            // the (15 s) backstop expired, so the hint dies with it. When a
            // newer claim for the key *does* still exist, its own publish is
            // authoritative and a stale finish must not disturb it.
            if !inner.entries.iter().flatten().any(|x| x.key == key) {
                self.clear_hot();
            }
        }
    }

    /// Test-only view of the entry for `(s, host, port)`: `Some(true)` for an
    /// unusable verdict, `Some(false)` for an in-flight claim, `None` when the
    /// gate holds nothing live for it.
    #[cfg(test)]
    pub(crate) fn probe_for_test(
        &self,
        s: u32,
        host: &str,
        port: u16,
        now_ms: u64,
    ) -> Option<bool> {
        let key = self.key(s, host, port);
        let inner = self.inner.lock();
        inner
            .entries
            .iter()
            .flatten()
            .find(|e| e.key == key && e.deadline > now_ms)
            .map(|e| e.state == GateState::Unusable)
    }
}

/// Addresses whose last datagram the kernel refused with a *routing* error, and
/// how long to skip them.
///
/// This is the one loss signal a proxy can actually observe: `sendto` returning
/// `ENETUNREACH`/`EHOSTUNREACH` is not packet loss, it is a verdict that arrives
/// immediately, and on a network that advertises AAAA without a working IPv6
/// route it is the normal outcome for the preferred family. Without it the
/// answer's first address stays pinned for `DEST_PIN_TTL_MS` and the flow is a
/// black hole; with it the next allowed address is tried once and, if it works,
/// becomes the one the session memo and the fast table carry.
///
/// Thread-local, direct-mapped, exact-address matched: a collision only forgets
/// a hint, and an expired entry only costs one more datagram on a dead address.
/// It is never a correctness input — the SSRF policy still decides what may be
/// dialled, and "no allowed address" still fails closed through the gate.
const UNREACHABLE_SLOTS: usize = 16;

/// How long a routing verdict is trusted before the address is tried again.
const UNREACHABLE_TTL_MS: u64 = 10_000;

thread_local! {
    static UNREACHABLE: std::cell::RefCell<[(Option<SocketAddr>, u64); UNREACHABLE_SLOTS]> =
        const { std::cell::RefCell::new([(None, 0); UNREACHABLE_SLOTS]) };
}

fn unreachable_idx(addr: SocketAddr) -> usize {
    const K: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut h = 0u64;
    match addr.ip() {
        std::net::IpAddr::V4(a) => {
            for o in a.octets() {
                h = h.wrapping_mul(K).wrapping_add(u64::from(o));
            }
        }
        std::net::IpAddr::V6(a) => {
            for s in a.segments() {
                h = h.wrapping_mul(K).wrapping_add(u64::from(s));
            }
        }
    }
    h = h.wrapping_mul(K).wrapping_add(u64::from(addr.port()));
    (h as usize) & (UNREACHABLE_SLOTS - 1)
}

/// Remember that the kernel had no route to `addr` just now.
pub(crate) fn mark_unreachable(addr: SocketAddr) {
    let deadline = coarse_millis().saturating_add(UNREACHABLE_TTL_MS);
    UNREACHABLE.with(|c| c.borrow_mut()[unreachable_idx(addr)] = (Some(addr), deadline));
}

/// Was `addr` refused with a routing error within the last [`UNREACHABLE_TTL_MS`]?
pub(crate) fn is_unreachable(addr: SocketAddr) -> bool {
    let now = coarse_millis();
    UNREACHABLE.with(|c| {
        let slot = c.borrow()[unreachable_idx(addr)];
        slot.0 == Some(addr) && slot.1 > now
    })
}

/// A `sendto` error that means "this address cannot be reached from here",
/// as opposed to a socket-level problem that would hit every address equally.
pub(crate) fn is_routing_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    )
}

// ---------------------------------------------------------------------------
// One datagram's target resolution
// ---------------------------------------------------------------------------

/// Where one domain datagram's target address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardResolution {
    /// Negative-cached name: refuse without spawning.
    Negative,
    /// A usable address plus the remaining life of the source it came from; the
    /// caller's pin/memo must not outlive it.
    Addr(SocketAddr, u64),
    /// No usable address is cached here: the caller may spawn a gated waiter.
    Unresolved,
}

/// Resolve one domain datagram's target synchronously, cheapest source first.
///
/// Order: this thread's DNS memo (no lock), then the session's own destination
/// memo (one shard read lock, no DNS). The session memo is what lets a slow-path
/// datagram that a previously spawned resolver already answered be delivered
/// *inline* — and the `Some` result is what the reader needs to `arm_fast`
/// (accept.rs) so the next datagram takes the connection fast path.
///
/// **The thread memo is not authoritative for filtering.** It only ever holds
/// the resolution's first address; when the SSRF filter rejects that address, a
/// usable one may still be memoized for this session. The filtered branch
/// therefore falls through to the session memo instead of spawning — the bug
/// this ordering fixes: a name whose first record was filtered (or whose records
/// were *all* filtered) re-entered the spawn arm on every packet even after a
/// resolver had stored the usable answer, and the connection fast table could
/// never arm because the slow path never returned `Some`.
pub(crate) fn resolve_forward_target(
    ss: &SessTable,
    s: u32,
    host: &str,
    port: u16,
    allow_private: bool,
) -> ForwardResolution {
    // No clock up front: a memo hit already carries its own remaining life, and
    // this runs once per datagram on the slow path. Only the session-memo
    // fallbacks need "now", and they are the rarer arm.
    let addrs = match lookup_cached_fast_with_ttl(host, port) {
        (CachedLookup::Negative, _) => return ForwardResolution::Negative,
        (CachedLookup::Addr(dst), life) => {
            // Two reasons to distrust the memo's single address: the policy
            // filters it, or the kernel recently said it has no route to it
            // ([`mark_unreachable`]). Either way the session memo may already
            // hold an address this host *can* reach — that is what the fallback
            // in [`deliver_resolved_server_dgram`] stores — and only when it does
            // not is a resolution worth spawning. The clock read is paid on the
            // slow path only, and only after the policy check passed.
            if (allow_private || is_global_ip_cached(dst.ip())) && !is_unreachable(dst) {
                (dst, life)
            } else {
                // First record filtered (or unroutable): the session memo may
                // hold a usable address from an earlier resolver pass.
                match sess_dest_lookup_ttl(ss, coarse_millis(), s, host, port) {
                    Some(v) => v,
                    None => return ForwardResolution::Unresolved,
                }
            }
        }
        (CachedLookup::Unknown, _) => {
            match sess_dest_lookup_ttl(ss, coarse_millis(), s, host, port) {
                Some(v) => v,
                None => return ForwardResolution::Unresolved,
            }
        }
    };
    if allow_private || is_global_ip_cached(addrs.0.ip()) {
        ForwardResolution::Addr(addrs.0, addrs.1)
    } else {
        // The session memo only ever stores filtered-passing addresses, so this
        // is unreachable in practice; fail closed through the slow path (which
        // scans the full set for a usable record) rather than serve it.
        ForwardResolution::Unresolved
    }
}

// ---------------------------------------------------------------------------
// Forwarding
// ---------------------------------------------------------------------------

/// Relay one datagram to its target. `Some((dst, life_ms))` is the address
/// actually used plus the remaining life of the cache entry it came from, so the
/// caller's own pin cannot outlive it (see [`pin_life_ms`]); `None` means the
/// datagram was dropped (SSRF filter, negative cache, DNS overload, no session
/// slot, or the per-connection [`DnsGate`] coalescing an in-flight lookup).
///
/// `staged` is `Some` only on the steady/TRAIN fast-path drain: the resolved
/// send is pushed into the caller's burst buffer instead of an immediate
/// `udp_try_send`, so the burst-end `flush_staged_sends` can group same-flow
/// runs. The unresolved DNS arm always spawns/returns None and never stages.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    addr: TargetAddrRef<'_>,
    payload: Bytes,
    allow_private: bool,
    r2: Option<&Arc<R2ConnState>>,
    staged: Option<&mut Vec<StagedSend>>,
) -> Option<(SocketAddr, u64)> {
    match addr {
        TargetAddrRef::Ip(dst) => {
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return None;
            } // No destination memo for an IP target: `resolve_pin` — the memo's
            // only reader on the datagram path — consults it for domain targets
            // exclusively (an IP target's address is already in the datagram, so
            // it takes the `TargetAddrRef::Ip` arm and never reaches the memo).
            // An entry keyed `("", port)` *is* readable in principle — see
            // `session_dest_memo_distinguishes_ip_and_domain_targets`, which
            // stores and reads exactly that — but nothing on the datagram path
            // would ever ask for it, because the wire decoder refuses a
            // zero-length domain, so the lookup that could match it is
            // unreachable. Storing it was a shard write lock plus a 72-byte memo
            // write per datagram that nothing could read back.
            let sock = get_or_create_sess(ss, cd, conn_id, s, None, r2).await?;
            remember_dst(ss, s, dst);
            let mapped = map_for_dual(dst);
            match staged {
                Some(staged) => staged.push(StagedSend {
                    sock,
                    dst: mapped,
                    payload,
                }),
                None => udp_try_send(&sock, mapped, payload),
            }
            // An IP target has no DNS entry behind it: the pin's own TTL is the
            // only bound there is.
            Some((dst, DNS_CACHE_TTL_MS))
        }
        TargetAddrRef::Domain(h, p) => {
            match resolve_forward_target(ss, s, h, p, allow_private) {
                ForwardResolution::Negative => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return None;
                }
                ForwardResolution::Addr(dst, life) => {
                    let sock =
                        get_or_create_sess(ss, cd, conn_id, s, Some((h, p, dst, life)), r2).await?;
                    remember_dst(ss, s, dst);
                    let mapped = map_for_dual(dst);
                    match staged {
                        Some(staged) => staged.push(StagedSend {
                            sock,
                            dst: mapped,
                            payload,
                        }),
                        None => {
                            if let Err((kind, _)) = udp_try_send_or_return(&sock, mapped, payload)
                                && is_routing_error(kind)
                            {
                                // No route to the pinned address. Marking it is
                                // enough: the next datagram for this target
                                // treats a recently unroutable address as a miss
                                // in `resolve_forward_target`, the waiter that
                                // follows walks the rest of the answer, and the
                                // address that works is stored in the session
                                // memo. Retrying here would need the record set —
                                // one cache await on a path that is otherwise
                                // syscall-only — to save a single datagram.
                                mark_unreachable(dst);
                            }
                        }
                    }
                    return Some((dst, life));
                }
                ForwardResolution::Unresolved => {}
            }
            // Nothing cached. The budget gate stays fail-fast and comes first:
            // a datagram that cannot get a permit must not leave an in-flight
            // claim behind (the existing DNS_BUDGET accounting depends on this
            // order).
            let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    dgram_drops::bump(&dgram_drops::DNS_BUDGET);
                    return None;
                }
            };
            // One waiter per `(session, name, port)`. Burst followers and a
            // permanently-filtered name are dropped here instead of each spawning
            // its own resolver task; the dropped payload is ordinary UDP loss,
            // and the drop is counted (this is not a budget refusal).
            let now = coarse_millis();
            let generation = match ss.dns_gate.claim(s, h, p, now) {
                GateClaim::Proceed(generation) => generation,
                GateClaim::InFlight => {
                    // A follower: park it behind the claim so it is sent when the
                    // answer lands, instead of making the application wait out
                    // its own retransmit timer for a name that is already being
                    // resolved. A full queue or a claim that just completed is
                    // ordinary UDP loss.
                    if ss.dns_gate.park(s, h, p, now, payload) {
                        myquic2::dns::stats::parked();
                    } else {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        #[cfg(test)]
                        ss.dns_gate.note_refusal();
                    }
                    return None;
                }
                GateClaim::Unusable => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    #[cfg(test)]
                    ss.dns_gate.note_refusal();
                    return None;
                }
            };
            #[cfg(test)]
            DNS_WAITER_SPAWNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let task_ss = ss.clone();
            let cd = cd.clone();
            let host = h.to_owned();
            // The spawned resolver creates/uses a session, so it needs the
            // connection's rev2 state (the session's reverse table and, through
            // it, the reply reader's rev2 handle). Cloned here because the task
            // outlives this frame.
            let r2_task = r2.map(Arc::clone);
            // Register this waiter's cancellation flag **synchronously**, before
            // the spawn: the datagram reader processes frames in order, so a
            // `CTL SESS_CLOSE` that arrives after this datagram is handled after
            // the registration and will find the flag. Without it, a DNS answer
            // that lands after the close re-created the session (socket, reader
            // task and global permit leaked until the 180 s idle sweep) — this
            // generic path has no per-flow coalescing key for the close to
            // cancel (see `R2ConnState::dns_waiters`).
            let waiter = r2.map(|st| st.begin_dns_waiter(s));
            // From just before the spawn to the socket hand-off: the latency a
            // *datagram* pays for a cold name, which is what an application sees.
            let spawned = std::time::Instant::now();
            tokio::spawn(async move {
                let _permit = permit;
                let unusable = deliver_resolved_server_dgram(
                    &task_ss,
                    &cd,
                    conn_id,
                    s,
                    &host,
                    p,
                    payload,
                    allow_private,
                    r2_task.as_ref(),
                    waiter.as_ref(),
                )
                .await;
                waiter_took(spawned.elapsed());
                if unusable.is_none() {
                    // The answer landed: send the datagrams that arrived while it
                    // was in flight. They go through the same delivery path, so
                    // the session, the destination memo and the reply allowlist
                    // are already warm, and each is one DATAGRAM send instead of
                    // a packet the application had to retransmit.
                    let parked = task_ss.dns_gate.take_parked(s, &host, p, generation);
                    for payload in parked {
                        let _ = deliver_resolved_server_dgram(
                            &task_ss,
                            &cd,
                            conn_id,
                            s,
                            &host,
                            p,
                            payload,
                            allow_private,
                            r2_task.as_ref(),
                            None,
                        )
                        .await;
                        myquic2::dns::stats::parked_delivered();
                    }
                }
                // Success or a name-level failure: always complete the claim, or
                // every later datagram for this target would be dropped as
                // in-flight until the backstop expires. The waiter guard drops
                // after this, removing its cancellation registry entry.
                task_ss
                    .dns_gate
                    .finish(s, &host, p, generation, unusable, coarse_millis());
                drop(waiter);
            });
            // The resolution happens in the spawned task above (it awaits), so
            // this datagram is delivered there and there is no pin for the caller
            // to record yet. The spawned waiter stores the resolved address in
            // the session's destination memo, so the *next* datagram is answered
            // inline by `resolve_forward_target` — and then arms the connection
            // fast table in accept.rs.
            None
        }
    }
}

/// Deliver one datagram from a gated resolver waiter.
///
/// Returns `Some(ttl)` when the name itself yielded no usable address (every
/// record filtered, or the lookup failed): the outcome [`DnsGate`] caches for
/// that long. The TTL is the failure's own class for a DNS refusal, and
/// [`filtered_ttl_ms`] when the resolver answered but the policy filtered every
/// record. A resource refusal from `get_or_create_sess` is not a DNS verdict and
/// returns `None`, so it never suppresses the next datagram's retry.
///
/// The answer can hold several addresses, and the first one is not always the
/// reachable one: on a network that advertises AAAA without a working IPv6 route
/// the kernel refuses `sendto` immediately with `ENETUNREACH`. So the send walks
/// the allowed addresses in preference order, skips ones a recent routing error
/// condemned ([`mark_unreachable`]), and — when a later address works — stores it
/// in the session memo so the next datagram ([`resolve_forward_target`]) and the
/// fast-table pin armed from it use it instead of repeating the failure.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn deliver_resolved_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    host: &str,
    port: u16,
    payload: Bytes,
    allow_private: bool,
    r2: Option<&Arc<R2ConnState>>,
    waiter: Option<&DnsWaiter>,
) -> Option<Duration> {
    let addrs = match resolve_all_cached(host, port).await {
        Ok(v) => v,
        Err(e) => {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return Some(e.retry_ttl());
        }
    };
    // The DNS *entry* may be older than `DNS_CACHE_TTL_MS`: `resolve_all_cached`
    // serves a host-keyed cache hit (every port shares one entry) and only then
    // memoizes this `(host, port)`. Pass the entry's actual remaining life so
    // the session destination memo / pin cannot outlive the resolution behind
    // them (`pin_life_ms` clamping); a miss (e.g. the memo was overwritten by
    // another thread) falls back to the fresh-resolution bound.
    let remaining_ms = {
        let (_, life) = lookup_cached_fast_with_ttl(host, port);
        if life == 0 { DNS_CACHE_TTL_MS } else { life }
    };
    // The policy verdict is applied here, before any socket work, and the whole
    // allowed set is kept: the first address is a preference, not a decision.
    let allowed: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| allow_private || is_global_ip(a.ip()))
        .collect();
    let Some(&preferred) = allowed.first() else {
        // Every record filtered: policy refusal, counted like the inline
        // negative arm. The verdict is a property of the *answer*, so the gate
        // may hold it for the answer's own remaining life instead of a flat
        // window that re-spawned this doomed resolution every few seconds.
        dgram_drops::bump(&dgram_drops::REFUSED);
        return Some(Duration::from_millis(filtered_ttl_ms(host, port)));
    };
    // The client may have closed the association while the DNS lookup was in
    // flight. Check the close before paying socket()/permit and again through
    // the guarded creation (which re-reads the flag inside the session shard's
    // write critical section, so it cannot race `take_session`). A cancelled
    // waiter returns "not a DNS verdict" so the gate does not cache anything
    // for the next datagram.
    if waiter.is_some_and(DnsWaiter::is_cancelled) {
        return None;
    }
    let sock = match get_or_create_sess_guarded(
        ss,
        cd,
        conn_id,
        s,
        Some((host, port, preferred, remaining_ms)),
        r2,
        waiter.map(DnsWaiter::cancelled_flag),
    )
    .await
    {
        Some(v) => Some(v),
        // `get_or_create_sess_guarded` already bumps the specific budget
        // counter for every resource refusal (FAIR_SHARE / SESSION_FULL /
        // SESS_CREATE_FAILED); the only silent None is the no-DATAGRAM path,
        // counted here so the spawned datagram never vanishes from the 60 s
        // budget line. Guarded (not unconditional) so a refusal is never bumped
        // twice. A cancelled creation is not a resource refusal: it returns
        // `None` here with no counter, and the cancel check below turns it into
        // "nothing to deliver".
        None => {
            if cd.max_datagram_size().is_none() {
                dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            }
            None
        }
    };
    if let Some(sock) = sock {
        if waiter.is_some_and(DnsWaiter::is_cancelled) {
            return None;
        }
        let mut payload = payload;
        let mut sent_to = None;
        for (i, cand) in allowed.iter().copied().enumerate() {
            // The first candidate is always tried: a routing verdict is a hint
            // with a ten-second memory, not a fact, and giving up on the only
            // remaining address would turn "unreachable just now" into "never
            // tried again".
            if i > 0 && is_unreachable(cand) {
                continue;
            }
            match udp_try_send_or_return(&sock, map_for_dual(cand), payload) {
                Ok(()) => {
                    sent_to = Some(cand);
                    break;
                }
                Err((kind, back)) => {
                    payload = back;
                    if is_routing_error(kind) {
                        mark_unreachable(cand);
                        continue;
                    }
                    // Anything else is a socket-level problem that would hit
                    // every address equally: the loss is already booked by
                    // `udp_try_send_or_return`, so stop rather than multiply it.
                    break;
                }
            }
        }
        let target = sent_to.unwrap_or(preferred);
        remember_dst(ss, s, target);
        if target != preferred {
            // The preferred address could not be reached and a later one worked.
            // Store it where the next datagram looks: the preference list has
            // proven wrong for this host, so the session memo — and the pin
            // armed from it — must not keep choosing the dead address.
            sess_dest_store(ss, s, host, port, target, remaining_ms);
        }
    }
    None
}
