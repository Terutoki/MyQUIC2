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

/// How long an "unusable" verdict (every record filtered, or the lookup failed)
/// is trusted before the next datagram may spawn a fresh resolution.
///
/// Deliberately short: the shared DNS layer already negative-caches failures
/// for `DNS_NEG_TTL` (10 s), so this stands in for a verdict that already exists
/// upstream and cannot outlive it. It exists because that upstream verdict is
/// only reachable synchronously from a *warm* thread memo, and a spawned waiter
/// warms only its own worker's.
pub(crate) const DNS_GATE_UNUSABLE_TTL_MS: u64 = 5_000;

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

#[derive(Clone, Copy)]
struct GateEntry {
    /// Hash of the normalized `(session, host, port)` — see [`DnsGate::key`].
    key: u64,
    state: GateState,
    deadline: u64,
    /// Identifies one claim generation: a waiter that outlived its entry (the
    /// backstop expired and the slot was reused) must not clear or rewrite a
    /// newer claim for the same key.
    generation: u32,
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
/// The gate makes that one waiter per `(session, name, port)`: later datagrams
/// during the flight are dropped (UDP semantics — the application retries or the
/// answer arrives), and an unusable verdict is remembered briefly so the next
/// packets are refused inline for one hash + one mutex instead of a task spawn.
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
}

impl DnsGate {
    pub(crate) fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(GateInner {
                entries: [None; DNS_GATE_SLOTS],
                next_generation: 0,
            }),
            seed: std::hash::RandomState::new(),
            hot_key: std::sync::atomic::AtomicU64::new(0),
            hot_state: std::sync::atomic::AtomicU64::new(0),
            hot_deadline: std::sync::atomic::AtomicU64::new(0),
        }
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
            .position(|e| e.is_none_or(|x| x.deadline <= now_ms))
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
        });
        self.publish_hot(key, GateState::InFlight, deadline);
        GateClaim::Proceed(generation)
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
        unusable: bool,
        now_ms: u64,
    ) {
        let key = self.key(s, host, port);
        let now = now_ms;
        let mut inner = self.inner.lock();
        if let Some(slot) = inner
            .entries
            .iter_mut()
            .find(|e| e.is_some_and(|x| x.key == key))
            && slot.as_ref().is_some_and(|e| e.generation == generation)
        {
            if unusable {
                let deadline = now.saturating_add(DNS_GATE_UNUSABLE_TTL_MS);
                *slot = Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline,
                    generation,
                });
                self.publish_hot(key, GateState::Unusable, deadline);
            } else {
                // The claim delivered (or was undecidable): the gate must
                // `Proceed` for the next datagrams, so the InFlight hint dies
                // with the entry.
                *slot = None;
                self.clear_hot();
            }
        } else if unusable {
            // The claim was evicted (or its backstop expired and the slot was
            // reused) while the waiter ran: still publish the verdict, in the
            // first free/expired slot, so the next datagrams can refuse inline.
            if let Some(slot) = inner
                .entries
                .iter_mut()
                .find(|e| e.is_none_or(|x| x.deadline <= now))
            {
                let deadline = now.saturating_add(DNS_GATE_UNUSABLE_TTL_MS);
                *slot = Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline,
                    generation,
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
    let now = coarse_millis();
    let addrs = match lookup_cached_fast_with_ttl(host, port) {
        (CachedLookup::Negative, _) => return ForwardResolution::Negative,
        (CachedLookup::Addr(dst), life) => {
            if allow_private || is_global_ip_cached(dst.ip()) {
                (dst, life)
            } else {
                // First record filtered: the session memo may hold a usable
                // address from an earlier resolver pass.
                match sess_dest_lookup_ttl(ss, now, s, host, port) {
                    Some(v) => v,
                    None => return ForwardResolution::Unresolved,
                }
            }
        }
        (CachedLookup::Unknown, _) => match sess_dest_lookup_ttl(ss, now, s, host, port) {
            Some(v) => v,
            None => return ForwardResolution::Unresolved,
        },
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
            udp_try_send(&sock, map_for_dual(dst), payload);
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
                    udp_try_send(&sock, map_for_dual(dst), payload);
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
                GateClaim::InFlight | GateClaim::Unusable => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
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
/// Returns `true` when the name itself yielded no usable address (every record
/// filtered, or the lookup failed): the outcome [`DnsGate`] caches briefly. A
/// resource refusal from `get_or_create_sess` is not a DNS verdict and returns
/// `false`, so it never suppresses the next datagram's retry.
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
) -> bool {
    let dst = match resolve_all_cached(host, port).await {
        Ok(v) => match v
            .iter()
            .copied()
            .find(|a| allow_private || is_global_ip(a.ip()))
        {
            Some(v) => v,
            // Every record filtered: policy refusal, counted like the inline
            // negative arm.
            None => {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return true;
            }
        },
        Err(_) => {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return true;
        }
    };
    // The client may have closed the association while the DNS lookup was in
    // flight. Check the close before paying socket()/permit and again through
    // the guarded creation (which re-reads the flag inside the session shard's
    // write critical section, so it cannot race `take_session`). A cancelled
    // waiter returns "not a DNS verdict" so the gate does not cache anything
    // for the next datagram.
    if waiter.is_some_and(DnsWaiter::is_cancelled) {
        return false;
    }
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
    let sock = match get_or_create_sess_guarded(
        ss,
        cd,
        conn_id,
        s,
        Some((host, port, dst, remaining_ms)),
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
            return false;
        }
        remember_dst(ss, s, dst);
        udp_try_send(&sock, map_for_dual(dst), payload);
    }
    false
}
