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
}

impl DnsGate {
    pub(crate) fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(GateInner {
                entries: [None; DNS_GATE_SLOTS],
                next_generation: 0,
            }),
            seed: std::hash::RandomState::new(),
        }
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
    pub(crate) fn claim(&self, s: u32, host: &str, port: u16, now_ms: u64) -> GateClaim {
        let key = self.key(s, host, port);
        let mut inner = self.inner.lock();
        if let Some(e) = inner
            .entries
            .iter()
            .flatten()
            .find(|e| e.key == key && e.deadline > now_ms)
        {
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
        inner.entries[slot] = Some(GateEntry {
            key,
            state: GateState::InFlight,
            deadline: now_ms.saturating_add(DNS_GATE_INFLIGHT_TTL_MS),
            generation,
        });
        GateClaim::Proceed(generation)
    }

    /// Complete a claim taken by [`claim`](Self::claim).
    ///
    /// Clears the in-flight entry on a delivered/undecidable outcome, or — when
    /// the name yielded no usable address — replaces it with a short-lived
    /// `Unusable` verdict so the following datagrams refuse inline.
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
            *slot = if unusable {
                Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline: now.saturating_add(DNS_GATE_UNUSABLE_TTL_MS),
                    generation,
                })
            } else {
                None
            };
        } else if unusable {
            // The claim was evicted (or its backstop expired and the slot was
            // reused) while the waiter ran: still publish the verdict, in the
            // first free/expired slot, so the next datagrams can refuse inline.
            if let Some(slot) = inner
                .entries
                .iter_mut()
                .find(|e| e.is_none_or(|x| x.deadline <= now))
            {
                *slot = Some(GateEntry {
                    key,
                    state: GateState::Unusable,
                    deadline: now.saturating_add(DNS_GATE_UNUSABLE_TTL_MS),
                    generation,
                });
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
pub(crate) async fn forward_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    addr: TargetAddrRef<'_>,
    payload: Bytes,
    allow_private: bool,
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
            let sock = get_or_create_sess(ss, cd, conn_id, s, None).await?;
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
                        get_or_create_sess(ss, cd, conn_id, s, Some((h, p, dst, life))).await?;
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
                )
                .await;
                // Success or a name-level failure: always complete the claim, or
                // every later datagram for this target would be dropped as
                // in-flight until the backstop expires.
                task_ss
                    .dns_gate
                    .finish(s, &host, p, generation, unusable, coarse_millis());
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
async fn deliver_resolved_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    host: &str,
    port: u16,
    payload: Bytes,
    allow_private: bool,
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
    let sock = match get_or_create_sess(
        ss,
        cd,
        conn_id,
        s,
        Some((host, port, dst, DNS_CACHE_TTL_MS)),
    )
    .await
    {
        Some(v) => Some(v),
        // `get_or_create_sess` already bumps the specific budget counter for
        // every resource refusal (FAIR_SHARE / SESSION_FULL /
        // SESS_CREATE_FAILED); the only silent None is the no-DATAGRAM path,
        // counted here so the spawned datagram never vanishes from the 60 s
        // budget line. Guarded (not unconditional) so a refusal is never bumped
        // twice.
        None => {
            if cd.max_datagram_size().is_none() {
                dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            }
            None
        }
    };
    if let Some(sock) = sock {
        remember_dst(ss, s, dst);
        udp_try_send(&sock, map_for_dual(dst), payload);
    }
    false
}
