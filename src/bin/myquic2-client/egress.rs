//! Shared UDP egress cache (per-binding single-flight, generation-tagged memo).
use super::*;

/// Egress freshness window in ms, mirroring the old 1 s `EGRESS_REFRESH`.
/// Stored as `mono_millis()` so the relay loop reuses its single per-packet
/// clock read instead of taking a second `Instant::now()` per datagram.
pub(crate) const EGRESS_REFRESH_MS: u64 = 1000;
/// Thread-local single-slot memo for the shared egress handle.
///
/// The relay loop calls [`SharedEgress::with_fresh`] per outbound datagram.
/// A `quinn::Connection` clone is an Arc refcount RMW on a cache line shared
/// with quinn's connection driver, so doing it per packet ping-pongs that line
/// across every relay task. The memo pins one clone per worker thread per
/// binding and serves it with no lock and no refcount traffic; a generation
/// bump (any successful `cached` mutation) invalidates it without touching
/// other threads. An entry that has gone stale is *released* on the miss path
/// (`with_fresh`), so a dead generation's handle cannot be pinned here by a
/// binding that stops sending — see [`SharedEgress::forget_slot`].
pub(crate) struct EgressMemo {
    pub(crate) generation: u64,
    pub(crate) conn: quinn::Connection,
    pub(crate) limit: usize,
    pub(crate) stamp_ms: u64,
    /// MQP-3 rev2 state paired with `conn`. Served from the memo so the
    /// uplink hot path reaches the connection's flow registry without an
    /// extra slot load; pairing it with the cached connection is what keeps a
    /// frame from being encoded against one connection's ids and sent on
    /// another's.
    pub(crate) rev2: Arc<ConnRev2>,
}

/// Init shim for the thread-local memo array: `[None; N]` needs a const item
/// for a non-`Copy` element.
const NO_MEMO: Option<EgressMemo> = None;

thread_local! {
    static EGRESS_MEMO: std::cell::RefCell<[Option<EgressMemo>; MAX_UDP_SLOTS]> = const {
        std::cell::RefCell::new([NO_MEMO; MAX_UDP_SLOTS])
    };
}

/// The process-wide egress handle plus the freshness stamp it was published
/// with. Immutable once published, so a reader can hold it without a lock.
#[derive(Debug)]
pub(crate) struct EgressCache {
    pub(crate) conn: quinn::Connection,
    pub(crate) limit: usize,
    pub(crate) stamp_ms: u64,
    /// The pool slot this handle came from. Recorded so the fail-closed UDP
    /// policy can assert (and re-check) that the cache never serves a TCP
    /// connection, and so the 60 s line can name which connection egress is on.
    pub(crate) slot: usize,
    /// Per-connection MQP-3 rev2 state, published with the connection. A
    /// cached entry is never served without it: rev2 frames carry ids from
    /// this exact registry, and using another generation's registry would
    /// produce frames the peer cannot resolve.
    pub(crate) rev2: Arc<ConnRev2>,
}

/// A resolved egress connection plus everything a rev2 frame needs: the live
/// DATAGRAM budget and the connection generation's flow state.
///
/// A struct rather than a tuple because the three values must stay paired:
/// an encoder validated against one connection's budget but sent with
/// another's registry is exactly the kind of mix-up a positional tuple makes
/// easy.
pub(crate) struct EgressHandle {
    pub(crate) conn: quinn::Connection,
    pub(crate) limit: usize,
    pub(crate) stamp_ms: u64,
    pub(crate) rev2: Arc<ConnRev2>,
}

#[derive(Debug)]
pub(crate) struct SharedEgress {
    /// `ArcSwapOption` replaces the `RwLock` this used to be. The old code used
    /// `try_write` and treated a lost publish as "stamp 0" — a memo that could
    /// never be served as fresh, so the next packet retried the whole refresh.
    /// `ArcSwap::store` is lock-free and always commits, which deletes that
    /// whole failure mode: every publish lands and carries a real stamp.
    ///
    /// One element per **egress binding** (index = [`UdpBind::index`]): the
    /// interactive class's slot and each bulk shard have separate caches and
    /// separate single-flight gates, so a refresh for one shard can never
    /// *write* another's slot. They can still end up holding the same
    /// connection: with `udp_fail_closed = false` the slot scan falls back to
    /// sibling shards, the other class (and then to the TCP slots), and
    /// stickiness then keeps it there while that connection lives — see
    /// [`SharedEgress::egress_order`].
    pub(crate) cached: [ArcSwapOption<EgressCache>; MAX_UDP_SLOTS],
    pub(crate) warned: std::sync::atomic::AtomicBool,
    /// Single-flight refresh gate, per binding: only one association task pays
    /// the two quinn locks (`close_reason` + `max_datagram_size`) per refresh
    /// window. The rest fail fast (UDP drop semantics) instead of herding on
    /// the same mutexes the moment the 1 s window expires on 4096 associations
    /// at once.
    pub(crate) refreshing: [std::sync::atomic::AtomicBool; MAX_UDP_SLOTS],
    /// Bumped (Release) after every mutation of that binding's `cached` — the
    /// publish in `refresh_global` and the clear in `invalidate`. With
    /// `ArcSwap` a mutation can no longer be lost, so this is bumped exactly
    /// once per mutation and never spuriously. The thread-local memo tags
    /// itself with the generation observed *before* its cached read, so a
    /// mutation concurrent with an acquire invalidates every thread's memo at
    /// once without a lock or a per-thread scan.
    pub(crate) generation: [std::sync::atomic::AtomicU64; MAX_UDP_SLOTS],
    /// Last `TooLarge` budget re-read per binding (coarse epoch). The re-read
    /// takes quinn's connection-state lock, so a PMTU shrink must not cost
    /// one lock per oversized datagram for the whole memo window: at most one
    /// re-read per interval, the rest keep the last known budget.
    pub(crate) budget_probed_ms: [std::sync::atomic::AtomicU64; MAX_UDP_SLOTS],
}

impl Default for SharedEgress {
    fn default() -> Self {
        Self {
            cached: std::array::from_fn(|_| ArcSwapOption::const_empty()),
            warned: std::sync::atomic::AtomicBool::new(false),
            refreshing: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            generation: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
            budget_probed_ms: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl SharedEgress {
    /// Serve the memoized handle when it is current and still fresh.
    ///
    /// `f` runs synchronously against the borrowed handle, so the hot path
    /// costs one generation load and one `RefCell` borrow — no Arc RMW, no
    /// quinn lock. A *fresh* miss leaves the memo untouched; a stale entry
    /// (generation mismatch or expired refresh window) is released on the miss
    /// path so its cloned `Connection` cannot outlive its generation on this
    /// thread — the hit path keeps its exact shape and pays nothing.
    ///
    /// N=1 CONTRACT (client egress): a memo hit followed by `frag.send` pays
    /// exactly one quinn take per frame — the `SendDatagram::poll` lock inside
    /// `try_send_datagram`. The 1 s memo (`EGRESS_REFRESH_MS`), the
    /// per-binding single-flight gate, and the 100 ms `refresh_budget` probe
    /// exist to keep
    /// every auxiliary take (`close_reason` / `max_datagram_size`) off this
    /// path: refresh winner only, once per window; losers fail fast;
    /// `TooLarge` re-probes at most once per 100 ms; `Unsupported` never
    /// re-acquires (the condition is static for the connection's life, so a
    /// re-acquire could only add two takes per datagram without finding a
    /// better slot).
    ///
    /// Dead-handle bound: **liveness is the send's verdict, not a gate here.**
    /// The hit used to take one extra `close_reason` (a quinn `state` mutex
    /// take plus an error clone — `quinn-0.11.12/src/connection.rs:400-402`),
    /// which doubled the per-frame takes and, worse, is the one per-frame cost
    /// that does not parallelize: its partner is the connection driver, which
    /// holds that same mutex while it processes every received packet, so a
    /// lost race parks a worker in a futex. It bought nothing measurable: a
    /// dead handle's very next `frag.send` returns `ConnectionLost`, and the
    /// caller already invalidates the cache and counts `EGRESS_DEAD` on that
    /// arm (see the `Unsupported` arm's identical reasoning in `assoc.rs`).
    /// So a hit now serves the handle whatever its state, the first send after
    /// a death reports `ConnectionLost`, and the cache is invalidated with the
    /// same exactly-once accounting as before. The stale window is at most one
    /// datagram, and that datagram was going to be dropped either way.
    /// `with_fresh` never invalidates the *shared* cache (avoids write
    /// amplification on this hot path); it only drops its own thread-local
    /// stale entry, on the miss path.
    pub(crate) fn with_fresh<R>(
        &self,
        bind: UdpBind,
        now_ms: u64,
        f: impl FnOnce(&quinn::Connection, usize, &Arc<ConnRev2>) -> R,
    ) -> Option<R> {
        let generation = self.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
        EGRESS_MEMO.with(|slots| {
            let mut memo = slots.borrow_mut();
            let entry = memo[bind.index].as_ref()?;
            if entry.generation == generation
                && now_ms.saturating_sub(entry.stamp_ms) < EGRESS_REFRESH_MS
            {
                return Some(f(&entry.conn, entry.limit, &entry.rev2));
            }
            // Stale (generation bump or expired refresh window): release this
            // thread's clone of the handle before returning None. The clone is
            // what used to pin a dead generation's quinn state after a redial
            // when the binding saw no further datagrams (see `forget_slot` and
            // the note on [`EgressMemo`]). The caller re-acquires here and
            // `memo_store` re-populates the slot with the fresh handle, so the
            // hit path above is unchanged and the stale path pays only the
            // write it was already about to pay in `memo_store`.
            memo[bind.index] = None;
            None
        })
    }

    /// Publish a handle into this thread's memo (one clone per thread per
    /// generation, not per packet). `generation` is the generation observed before the
    /// acquire's cached read, so a mutation racing the acquire cannot leave a
    /// stale memo entry behind.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn memo_store(
        &self,
        bind: UdpBind,
        generation: u64,
        conn: &quinn::Connection,
        limit: usize,
        stamp_ms: u64,
        rev2: &Arc<ConnRev2>,
    ) {
        EGRESS_MEMO.with(|slots| {
            slots.borrow_mut()[bind.index] = Some(EgressMemo {
                generation,
                conn: conn.clone(),
                limit,
                stamp_ms,
                rev2: rev2.clone(),
            });
        });
    }

    /// Drop this thread's memo entry (releasing a stale `Connection` promptly
    /// when the cache has no usable handle at all).
    pub(crate) fn memo_clear(&self, bind: UdpBind) {
        EGRESS_MEMO.with(|slots| slots.borrow_mut()[bind.index] = None);
    }

    /// The published handle for `bind`, **without** the freshness/liveness
    /// gates of [`Self::acquire`].
    ///
    /// Exists for the association-exit path: releasing a session's
    /// connection-scoped state must not depend on winning a refresh window or
    /// on the generation being ready (an exit inside the handshake window would
    /// otherwise leak its bindings/staged payloads for the connection's life),
    /// and the cached handle also names the exact pool slot the association's
    /// frames left on. Whether the returned connection may carry a datagram is
    /// still decided at the call site (ready + not closed).
    pub(crate) fn cached_handle(
        &self,
        bind: UdpBind,
    ) -> Option<(quinn::Connection, Arc<ConnRev2>)> {
        self.cached[bind.index]
            .load()
            .as_ref()
            .map(|c| (c.conn.clone(), c.rev2.clone()))
    }

    /// Resolve a usable `(connection, limit, stamp)` from the process-wide
    /// cache, refreshing through the single-flight gate when the cached handle
    /// is expired. Returns `None` only when no handle is available, in which
    /// case the caller drops the datagram (UDP semantics) and counts it in
    /// `dgram_drops::NO_EGRESS`.
    pub(crate) fn acquire(
        &self,
        pool: &ConnPool,
        bind: UdpBind,
        now_ms: u64,
    ) -> Option<EgressHandle> {
        let cached = &self.cached[bind.index];
        if let Some(c) = cached.load().as_ref() {
            // A fail-closed pool only ever publishes a slot of this class (see
            // `egress_order`), so this is an invariant check, not a filter.
            debug_assert!(
                !pool.udp_fail_closed()
                    || (c.slot >= pool.tcp_slots
                        && pool
                            .udp_class_slots(bind.class)
                            .contains(&(c.slot - pool.tcp_slots))),
                "fail-closed egress must never cache another class's (or a TCP) slot"
            );
            if now_ms.saturating_sub(c.stamp_ms) < EGRESS_REFRESH_MS {
                return Some(EgressHandle {
                    conn: c.conn.clone(),
                    limit: c.limit,
                    stamp_ms: c.stamp_ms,
                    rev2: c.rev2.clone(),
                });
            }
        }
        if let Some(h) = self.refresh_global(pool, bind, now_ms) {
            return Some(h);
        }
        // Stale-while-revalidate: an expired (or contended) handle is reused
        // optimistically, but only after one cheap liveness gate
        // (`close_reason`, the same check the refresh stickiness path uses):
        // a dead handle is invalidated here so the caller counts NO_EGRESS
        // instead of sending a packet that can never arrive (the kill-9
        // restart blackholed the whole expiry window before this gate). The
        // loser path therefore costs at most one quinn lock and never parks.
        if let Some(c) = cached.load().as_ref() {
            if c.conn.close_reason().is_none() {
                return Some(EgressHandle {
                    conn: c.conn.clone(),
                    limit: c.limit,
                    stamp_ms: c.stamp_ms,
                    rev2: c.rev2.clone(),
                });
            }
            self.invalidate(bind);
        }
        self.memo_clear(bind);
        None
    }

    /// Slot scan order for `bind`: its own slot first, then — the fail-closed
    /// boundary — the rest of its class's dedicated slots, then, fail-open
    /// only, the other class's slots and the TCP slots.
    ///
    /// A fail-closed pool stops after the class's own UDP slots, which is what
    /// makes UDP independent of TCP: when a dedicated connection is down the
    /// datagram fails over inside its class's shard set (a sibling bulk shard
    /// is still a UDP-only connection — the isolation contract is
    /// UDP-vs-TCP, not shard-vs-shard) and, when even that is empty, is
    /// dropped rather than queued on a connection whose congestion window and
    /// packet payload it would compete with (quinn writes DATAGRAM frames
    /// before STREAM frames, so a bulk UDP flow on a shared connection starves
    /// the TCP streams on it). The wider order is kept for operators who would
    /// rather lose isolation than lose packets, via `udp_fail_closed = false`.
    ///
    /// Stack-array, not a `Vec`: this runs once per refresh window on the
    /// single-flight winner, and the pool's slot count bounds it.
    pub(crate) fn egress_order(
        &self,
        pool: &ConnPool,
        bind: UdpBind,
    ) -> ([usize; MAX_POOL_CONNS + MAX_UDP_SLOTS], usize) {
        let mut order = [0usize; MAX_POOL_CONNS + MAX_UDP_SLOTS];
        let own = pool.udp_global_slot(bind.index);
        order[0] = own;
        let mut k = 1;
        let push =
            |slot: usize, order: &mut [usize; MAX_POOL_CONNS + MAX_UDP_SLOTS], k: &mut usize| {
                if slot != own && !order[..*k].contains(&slot) {
                    order[*k] = slot;
                    *k += 1;
                }
            };
        // Same-class siblings first: the rest of this class's dedicated slots.
        for i in pool.udp_class_slots(bind.class) {
            push(pool.udp_global_slot(i), &mut order, &mut k);
        }
        if !pool.udp_fail_closed() {
            // UDP-over-UDP beats UDP-over-TCP, so the other class comes before
            // the TCP slots.
            for i in 0..pool.udp_slot_count() {
                push(pool.udp_global_slot(i), &mut order, &mut k);
            }
            for i in 0..pool.tcp_slots() {
                push(i, &mut order, &mut k);
            }
        }
        (order, k)
    }

    /// Refresh `bind`'s cache under its single-flight gate. Returns the fresh
    /// handle and the stamp to tag it with, which is always `now_ms`:
    /// `ArcSwap::store` cannot lose, so there is no unpublished-handle case to
    /// keep cold.
    pub(crate) fn refresh_global(
        &self,
        pool: &ConnPool,
        bind: UdpBind,
        now_ms: u64,
    ) -> Option<EgressHandle> {
        // Single-flight: a loser drops fast (UDP semantics) instead of paying
        // the quinn locks while a winner is already refreshing. The losing
        // datagram is counted in `dgram_drops::NO_EGRESS` by the caller.
        if self.refreshing[bind.index].swap(true, std::sync::atomic::Ordering::AcqRel) {
            return None;
        }
        struct RefreshGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for RefreshGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _guard = RefreshGuard(&self.refreshing[bind.index]);
        let cached = &self.cached[bind.index];
        // Stickiness first: while the cached connection is still usable, keep it
        // and only re-read its DATAGRAM budget (the path MTU can have changed
        // under it). Re-running the slot scan here instead is what used to move
        // every UDP association back onto the interactive slot the moment that
        // slot recovered — a second target-side source-port change (and a new
        // server-side session) for a flow that had already failed over, i.e.
        // exactly the flap-back churn the docs promise not to do. A fail-closed
        // pool can only have published a slot of this class, so stickiness
        // cannot keep it on a TCP connection.
        let current = cached.load();
        if let Some(c) = current.as_ref()
            && c.conn.close_reason().is_none()
            && let Some(m) = c.conn.max_datagram_size()
        {
            cached.store(Some(Arc::new(EgressCache {
                conn: c.conn.clone(),
                limit: m,
                stamp_ms: now_ms,
                slot: c.slot,
                rev2: c.rev2.clone(),
            })));
            self.generation[bind.index].fetch_add(1, std::sync::atomic::Ordering::Release);
            return Some(EgressHandle {
                conn: c.conn.clone(),
                limit: m,
                stamp_ms: now_ms,
                rev2: c.rev2.clone(),
            });
        }
        drop(current);
        // The cached connection is gone (or lost DATAGRAM support): walk the
        // egress order above.
        let (order, k) = self.egress_order(pool, bind);
        for &i in &order[..k] {
            let Some(slot) = pool.slots.get(i) else {
                continue;
            };
            // Lock-free read: no `try_read` that can fail, so a refresh can
            // never be skipped just because a reconnect is publishing.
            let g = slot.shared.load();
            match g.as_ref() {
                // A rev2 generation is usable for UDP as soon as its state is
                // published, **before** `CAPS`: the first payload is sent
                // optimistically instead of waiting one HELLO/CAPS RTT. The
                // server keeps the version gate authoritative by buffering
                // these frames until a valid HELLO arrives, then flushing them;
                // `CAPS` only updates the negotiated caps and the compression
                // limits. `HELLO` itself is sent immediately by the reconnect
                // loop, so the server-side buffer usually holds nothing.
                Some(c) if c.close_reason().is_none() => {
                    // Coherent pair: the rev2 state is re-checked against the
                    // still-published connection (see `ConnSlot::rev2_for`), so
                    // a death+redial between the `shared` load above and this
                    // read can never pair the old connection with the next
                    // generation's id tables.
                    let Some(rev2) = slot.rev2_for(c) else {
                        continue;
                    };
                    match c.max_datagram_size() {
                        Some(m) => {
                            // Lock-free publish: cannot lose, cannot park the
                            // executor, and always carries a real stamp.
                            cached.store(Some(Arc::new(EgressCache {
                                conn: (**c).clone(),
                                limit: m,
                                stamp_ms: now_ms,
                                slot: i,
                                rev2: rev2.clone(),
                            })));
                            self.generation[bind.index]
                                .fetch_add(1, std::sync::atomic::Ordering::Release);
                            return Some(EgressHandle {
                                conn: (**c).clone(),
                                limit: m,
                                stamp_ms: now_ms,
                                rev2,
                            });
                        }
                        None => {
                            if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                                warn!("peer does not support QUIC DATAGRAM; dropping outbound UDP");
                            }
                            return None;
                        }
                    }
                }
                _ => continue,
            }
        }
        None
    }

    pub(crate) fn invalidate(&self, bind: UdpBind) {
        self.cached[bind.index].store(None);
        // The clear always lands, so the memo invalidation is never skipped.
        self.generation[bind.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Drop every cached handle that was published from pool slot `slot`.
    ///
    /// Called on the dead-connection path (`spawn_conn_loop`) once
    /// [`ConnSlot::clear_if_and_mark_dead`] has committed the redial: the
    /// per-binding `cached` slots are the only place outside the pool that hold
    /// a strong `quinn::Connection`, and a generation that dies while its
    /// binding sees no further datagrams is otherwise never invalidated — the
    /// dead handle, and the whole `quinn-proto` connection state behind it,
    /// would outlive the redial for the process lifetime. The clear is scoped
    /// by [`EgressCache::slot`], so a healthy slot's cache is untouched; the
    /// generation bump is the same one [`Self::invalidate`] performs, so every
    /// thread-local memo tied to a cleared binding misses and re-acquires on
    /// its next datagram.
    pub(crate) fn forget_slot(&self, slot: usize) {
        for i in 0..MAX_UDP_SLOTS {
            if self.cached[i]
                .load()
                .as_ref()
                .is_some_and(|e| e.slot == slot)
            {
                self.cached[i].store(None);
                self.generation[i].fetch_add(1, std::sync::atomic::Ordering::Release);
            }
        }
    }

    /// Re-read the live DATAGRAM budget on the cached handle, keeping it.
    ///
    /// The recovery for a `TooLarge` send. That outcome is a **size** verdict,
    /// never a connection fault: the payload is past the protocol's own
    /// fragmentation cap, or the path MTU shrank under the budget this handle
    /// was memoized with. Either way the connection is healthy and must keep
    /// carrying the next datagram, so this deliberately does *not* go through
    /// the single-flight gate or the slot scan — those exist to *choose* a
    /// connection, and there is nothing to choose here.
    ///
    /// A no-op when the budget has not actually moved, which is the case for
    /// every payload past `MQP_FRAG_MAX_PAYLOAD` (the fragmenter rejects those
    /// before quinn ever sees them, and its `limit` was already correct).
    pub(crate) fn refresh_budget(&self, bind: UdpBind) {
        const BUDGET_PROBE_INTERVAL_MS: u64 = 100;
        // Precise clock for the throttle: `coarse_millis` advances in 1 s
        // steps, so a 100 ms interval measured on it is really 0~1 s and a
        // PMTU shrink keeps dropping on a stale budget for up to a second.
        // `mono_millis` is a TSC (x86) or OS-clock read paid only on the
        // `TooLarge` path.
        // `.max(1)`: the zero stamp means "never probed", and the mono epoch
        // counts from process start, so a verdict inside the first millisecond
        // must still arm the throttle instead of probing once per datagram.
        let now = mono_millis().max(1);
        let probed = &self.budget_probed_ms[bind.index];
        // Zero means never probed: the mono epoch counts from process start,
        // so a small `now` must not read as "probed 0 ms ago".
        let last = probed.load(std::sync::atomic::Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < BUDGET_PROBE_INTERVAL_MS {
            return;
        }
        probed.store(now, std::sync::atomic::Ordering::Relaxed);
        let cached = &self.cached[bind.index];
        let current = cached.load();
        let Some(c) = current.as_ref() else {
            return;
        };
        let Some(m) = c.conn.max_datagram_size() else {
            return;
        };
        if m == c.limit {
            return;
        }
        cached.store(Some(Arc::new(EgressCache {
            conn: c.conn.clone(),
            limit: m,
            stamp_ms: coarse_millis(),
            slot: c.slot,
            rev2: c.rev2.clone(),
        })));
        self.generation[bind.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

/// Test hook: whether this thread's memo slot for `bind` is empty.
///
/// The memo is private to this module, and the retention fix is precisely "a
/// stale entry must release its cloned handle", so a test has to observe the
/// slot itself, not just the shared cache.
#[cfg(test)]
pub(crate) fn memo_is_empty(bind: UdpBind) -> bool {
    EGRESS_MEMO.with(|slots| slots.borrow()[bind.index].is_none())
}
