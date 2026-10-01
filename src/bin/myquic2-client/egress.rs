//! Shared UDP egress cache (per-class single-flight, generation-tagged memo).
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
/// across every relay task. The memo pins one clone per worker thread and
/// serves it with no lock and no refcount traffic; a generation bump (any
/// successful `cached` mutation) invalidates it without touching other threads.
pub(crate) struct EgressMemo {
    pub(crate) gen: u64,
    pub(crate) conn: quinn::Connection,
    pub(crate) limit: usize,
    pub(crate) stamp_ms: u64,
}

thread_local! {
    static EGRESS_MEMO: std::cell::RefCell<[Option<EgressMemo>; EgressClass::COUNT]> =
        const { std::cell::RefCell::new([None, None]) };
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
}

#[derive(Debug)]
pub(crate) struct SharedEgress {
    /// `ArcSwapOption` replaces the `RwLock` this used to be. The old code used
    /// `try_write` and treated a lost publish as "stamp 0" — a memo that could
    /// never be served as fresh, so the next packet retried the whole refresh.
    /// `ArcSwap::store` is lock-free and always commits, which deletes that
    /// whole failure mode: every publish lands and carries a real stamp.
    ///
    /// One element per [`EgressClass`] (index `class.index()`): the classes have
    /// separate caches and separate single-flight gates, so a refresh for one
    /// class can never *write* the other's slot. They can still end up holding
    /// the same connection: with `udp_fail_closed = false` the slot scan falls
    /// back to the other class's UDP connection (and then to the TCP slots), and
    /// stickiness then keeps it there while that connection lives — see
    /// [`SharedEgress::egress_order`].
    pub(crate) cached: [ArcSwapOption<EgressCache>; EgressClass::COUNT],
    pub(crate) warned: std::sync::atomic::AtomicBool,
    /// Single-flight refresh gate, per class: only one association task pays
    /// the two quinn locks (`close_reason` + `max_datagram_size`) per refresh
    /// window. The rest fail fast (UDP drop semantics) instead of herding on
    /// the same mutexes the moment the 1 s window expires on 4096 associations
    /// at once.
    pub(crate) refreshing: [std::sync::atomic::AtomicBool; EgressClass::COUNT],
    /// Bumped (Release) after every mutation of that class's `cached` — the
    /// publish in `refresh_global` and the clear in `invalidate`. With
    /// `ArcSwap` a mutation can no longer be lost, so this is bumped exactly
    /// once per mutation and never spuriously. The thread-local memo tags
    /// itself with the generation observed *before* its cached read, so a
    /// mutation concurrent with an acquire invalidates every thread's memo at
    /// once without a lock or a per-thread scan.
    pub(crate) generation: [std::sync::atomic::AtomicU64; EgressClass::COUNT],
    /// Last `TooLarge` budget re-read per class (coarse epoch). The re-read
    /// takes quinn's connection-state lock, so a PMTU shrink must not cost
    /// one lock per oversized datagram for the whole memo window: at most one
    /// re-read per interval, the rest keep the last known budget.
    pub(crate) budget_probed_ms: [std::sync::atomic::AtomicU64; EgressClass::COUNT],
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
    /// quinn lock. A miss leaves the memo untouched; the caller re-acquires.
    ///
    /// N=1 CONTRACT (client egress): a memo hit followed by `frag.send` pays
    /// exactly one quinn take per frame — the `SendDatagram::poll` lock inside
    /// `try_send_datagram`. The 1 s memo (`EGRESS_REFRESH_MS`), the per-class
    /// single-flight gate, and the 100 ms `refresh_budget` probe exist to keep
    /// every auxiliary take (`close_reason` / `max_datagram_size`) off this
    /// path: refresh winner only, once per window; losers fail fast or reuse
    /// the stale handle behind one liveness gate; `TooLarge` re-probes at most
    /// once per 100 ms; `Unsupported` never re-acquires (the condition is
    /// static for the connection's life, so a re-acquire could only add two
    /// takes per datagram without finding a better slot).
    ///
    /// Dead-handle bound: the gen+stamp hit carries one extra `close_reason`
    /// gate, which in quinn 0.11 is a `state` mutex take plus an error clone
    /// (see `quinn-0.11.12/src/connection.rs:400-402`), not a local atomic
    /// read: each memo hit therefore pays one uncontended mutex take (~20 ns
    /// order, negligible against the ~25 us packet budget), and N=1 becomes
    /// worst-case 2 takes/frame (this gate plus the `SendDatagram::poll` lock
    /// inside `frag.send`). A dead handle serves at most 0 times — it misses
    /// here directly, so the caller falls into `acquire` → `invalidate` and
    /// counts `NO_EGRESS` precisely.
    /// `with_fresh` never invalidates itself (avoids write amplification on
    /// this hot path).
    pub(crate) fn with_fresh<R>(
        &self,
        class: EgressClass,
        now_ms: u64,
        f: impl FnOnce(&quinn::Connection, usize) -> R,
    ) -> Option<R> {
        let gen = self.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
        EGRESS_MEMO.with(|slots| {
            let memo = slots.borrow();
            let entry = memo[class.index()].as_ref()?;
            if entry.gen == gen && now_ms.saturating_sub(entry.stamp_ms) < EGRESS_REFRESH_MS {
                if entry.conn.close_reason().is_some() {
                    return None;
                }
                Some(f(&entry.conn, entry.limit))
            } else {
                None
            }
        })
    }

    /// Publish a handle into this thread's memo (one clone per thread per
    /// generation, not per packet). `gen` is the generation observed before the
    /// acquire's cached read, so a mutation racing the acquire cannot leave a
    /// stale memo entry behind.
    pub(crate) fn memo_store(
        &self,
        class: EgressClass,
        gen: u64,
        conn: &quinn::Connection,
        limit: usize,
        stamp_ms: u64,
    ) {
        EGRESS_MEMO.with(|slots| {
            slots.borrow_mut()[class.index()] = Some(EgressMemo {
                gen,
                conn: conn.clone(),
                limit,
                stamp_ms,
            });
        });
    }

    /// Drop this thread's memo entry (releasing a stale `Connection` promptly
    /// when the cache has no usable handle at all).
    pub(crate) fn memo_clear(&self, class: EgressClass) {
        EGRESS_MEMO.with(|slots| slots.borrow_mut()[class.index()] = None);
    }

    /// Resolve a usable `(connection, limit, stamp)` from the process-wide
    /// cache, refreshing through the single-flight gate when the cached handle
    /// is expired. Returns `None` only when no handle is available, in which
    /// case the caller drops the datagram (UDP semantics) and counts it in
    /// `dgram_drops::NO_EGRESS`.
    pub(crate) fn acquire(
        &self,
        pool: &ConnPool,
        class: EgressClass,
        now_ms: u64,
    ) -> Option<(quinn::Connection, usize, u64)> {
        let cached = &self.cached[class.index()];
        if let Some(c) = cached.load().as_ref() {
            // A fail-closed pool only ever publishes that class's UDP slot (see
            // `egress_order`), so this is an invariant check, not a filter.
            debug_assert!(
                !pool.udp_fail_closed() || c.slot == pool.udp_slot(class),
                "fail-closed egress must never cache a shared TCP slot"
            );
            if now_ms.saturating_sub(c.stamp_ms) < EGRESS_REFRESH_MS {
                return Some((c.conn.clone(), c.limit, c.stamp_ms));
            }
        }
        if let Some((c, m, stamp)) = self.refresh_global(pool, class, now_ms) {
            return Some((c, m, stamp));
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
                return Some((c.conn.clone(), c.limit, c.stamp_ms));
            }
            self.invalidate(class);
        }
        self.memo_clear(class);
        None
    }

    /// Slot scan order for `class`: its own UDP slot first, then — fail-open
    /// only — the other UDP class's slot, then the TCP slots.
    ///
    /// A fail-closed pool stops after the first entry, which is what makes UDP
    /// independent of TCP: when the dedicated connection is down the datagram is
    /// dropped rather than queued on a connection whose congestion window and
    /// packet payload it would compete with (quinn writes DATAGRAM frames before
    /// STREAM frames, so a bulk UDP flow on a shared connection starves the TCP
    /// streams on it). The shared order is kept for operators who would rather
    /// lose isolation than lose packets, via `udp_fail_closed = false`.
    ///
    /// Stack-array, not a `Vec`: this runs once per refresh window on the
    /// single-flight winner, and the pool's slot count bounds it.
    pub(crate) fn egress_order(
        &self,
        pool: &ConnPool,
        class: EgressClass,
    ) -> ([usize; MAX_POOL_CONNS + EgressClass::COUNT], usize) {
        let mut order = [0usize; MAX_POOL_CONNS + EgressClass::COUNT];
        let own = pool.udp_slot(class);
        order[0] = own;
        let mut k = 1;
        if !pool.udp_fail_closed() {
            // UDP-over-UDP beats UDP-over-TCP, so the other class comes first.
            let other = pool.udp_slot(class.other());
            if other != own {
                order[k] = other;
                k += 1;
            }
            for i in 0..pool.tcp_slots() {
                if i != own {
                    order[k] = i;
                    k += 1;
                }
            }
        }
        (order, k)
    }

    /// Refresh `class`'s cache under its single-flight gate. Returns the fresh
    /// handle and the stamp to tag it with, which is always `now_ms`:
    /// `ArcSwap::store` cannot lose, so there is no unpublished-handle case to
    /// keep cold.
    pub(crate) fn refresh_global(
        &self,
        pool: &ConnPool,
        class: EgressClass,
        now_ms: u64,
    ) -> Option<(quinn::Connection, usize, u64)> {
        // Single-flight: a loser drops fast (UDP semantics) instead of paying
        // the quinn locks while a winner is already refreshing. The losing
        // datagram is counted in `dgram_drops::NO_EGRESS` by the caller.
        if self.refreshing[class.index()].swap(true, std::sync::atomic::Ordering::AcqRel) {
            return None;
        }
        struct RefreshGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for RefreshGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _guard = RefreshGuard(&self.refreshing[class.index()]);
        let cached = &self.cached[class.index()];
        // Stickiness first: while the cached connection is still usable, keep it
        // and only re-read its DATAGRAM budget (the path MTU can have changed
        // under it). Re-running the slot scan here instead is what used to move
        // every UDP association back onto the interactive slot the moment that
        // slot recovered — a second target-side source-port change (and a new
        // server-side session) for a flow that had already failed over, i.e.
        // exactly the flap-back churn the docs promise not to do. A fail-closed
        // pool can only have published that class's UDP slot, so stickiness
        // cannot keep it on a TCP connection.
        let current = cached.load();
        if let Some(c) = current.as_ref() {
            if c.conn.close_reason().is_none() {
                if let Some(m) = c.conn.max_datagram_size() {
                    cached.store(Some(Arc::new(EgressCache {
                        conn: c.conn.clone(),
                        limit: m,
                        stamp_ms: now_ms,
                        slot: c.slot,
                    })));
                    self.generation[class.index()]
                        .fetch_add(1, std::sync::atomic::Ordering::Release);
                    return Some((c.conn.clone(), m, now_ms));
                }
            }
        }
        drop(current);
        // The cached connection is gone (or lost DATAGRAM support): walk the
        // egress order above.
        let (order, k) = self.egress_order(pool, class);
        for &i in &order[..k] {
            let Some(slot) = pool.slots.get(i) else {
                continue;
            };
            // Lock-free read: no `try_read` that can fail, so a refresh can
            // never be skipped just because a reconnect is publishing.
            let g = slot.shared.load();
            match g.as_ref() {
                Some(c) if c.close_reason().is_none() => match c.max_datagram_size() {
                    Some(m) => {
                        // Lock-free publish: cannot lose, cannot park the
                        // executor, and always carries a real stamp.
                        cached.store(Some(Arc::new(EgressCache {
                            conn: (**c).clone(),
                            limit: m,
                            stamp_ms: now_ms,
                            slot: i,
                        })));
                        self.generation[class.index()]
                            .fetch_add(1, std::sync::atomic::Ordering::Release);
                        return Some(((**c).clone(), m, now_ms));
                    }
                    None => {
                        if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            warn!("peer does not support QUIC DATAGRAM; dropping outbound UDP");
                        }
                        return None;
                    }
                },
                _ => continue,
            }
        }
        None
    }

    pub(crate) fn invalidate(&self, class: EgressClass) {
        self.cached[class.index()].store(None);
        // The clear always lands, so the memo invalidation is never skipped.
        self.generation[class.index()].fetch_add(1, std::sync::atomic::Ordering::Release);
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
    pub(crate) fn refresh_budget(&self, class: EgressClass) {
        const BUDGET_PROBE_INTERVAL_MS: u64 = 100;
        // Precise clock for the throttle: `coarse_millis` advances in 1 s
        // steps, so a 100 ms interval measured on it is really 0~1 s and a
        // PMTU shrink keeps dropping on a stale budget for up to a second.
        // `mono_millis` is a vDSO read paid only on the `TooLarge` path.
        // `.max(1)`: the zero stamp means "never probed", and the mono epoch
        // counts from process start, so a verdict inside the first millisecond
        // must still arm the throttle instead of probing once per datagram.
        let now = mono_millis().max(1);
        let probed = &self.budget_probed_ms[class.index()];
        // Zero means never probed: the mono epoch counts from process start,
        // so a small `now` must not read as "probed 0 ms ago".
        let last = probed.load(std::sync::atomic::Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < BUDGET_PROBE_INTERVAL_MS {
            return;
        }
        probed.store(now, std::sync::atomic::Ordering::Relaxed);
        let cached = &self.cached[class.index()];
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
        })));
        self.generation[class.index()].fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}
