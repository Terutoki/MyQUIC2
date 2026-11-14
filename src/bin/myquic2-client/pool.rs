//! Client connection pool: ConnSlot, ConnPool, EgressClass, shared constants.
use super::*;

/// Width of the UDP egress range the egress cache and the pool's scratch
/// arrays must cover: the largest interactive shard set plus the largest bulk
/// one.
pub(crate) const MAX_UDP_SLOTS: usize = MAX_UDP_INTERACTIVE_CONNS + MAX_UDP_EGRESS_CONNS;

/// The pool slot's published connection.
///
/// `ArcSwapOption` replaces the `tokio::sync::RwLock` this used to be: readers
/// (`wait_conn`, per TCP flow) are lock-free and, unlike `RwLock::read()`, can
/// never park a worker behind a writer, while the writers (dial / teardown, once
/// per connection generation) are lock-free too. The published value is
/// immutable, so a reader that wins the load keeps a consistent handle for as
/// long as it holds the guard.
pub(crate) type SharedConn = Arc<ArcSwapOption<quinn::Connection>>;
/// Bump the connection-generation counter.
///
/// `send_modify` takes the watch write lock once and mutates the value in
/// place, so the increment is atomic across concurrent writers and there is no
/// read guard to drop first (the old `send_replace(tx.borrow() + 1)` shape
/// self-deadlocked by holding the read guard across the write lock).
pub(crate) fn bump_gen(tx: &watch::Sender<u64>) {
    tx.send_modify(|generation| *generation = generation.wrapping_add(1));
}

/// 0-RTT handshake phase of the connection a [`ConnSlot`] currently publishes.
///
/// The reconnect loop publishes a resumed connection as soon as quinn's
/// `Connecting::into_0rtt()` succeeds, i.e. **before the handshake completes**,
/// so that TCP flows and UDP payloads can ride the first flight. The peer may
/// still discard that early data (`ZeroRttAccepted` then resolves `false`), and
/// quinn reports such a discard only later, as `ZeroRttRejected` errors from the
/// 0-RTT streams/datagrams. This state is how the rest of the client learns
/// which of the four windows the published connection is in:
///
/// - [`Self::NONE`] — the dial was a full handshake that was awaited to
///   completion; every stream is 1-RTT (the pre-0-RTT behaviour);
/// - [`Self::PENDING`] — 0-RTT offered, handshake still in flight: streams
///   opened now ride early data and may be discarded;
/// - [`Self::ACCEPTED`] — the peer kept the early data: the early token and any
///   first-flight TCP/UDP bytes were delivered;
/// - [`Self::REJECTED`] — the peer discarded it: the early token is re-sent by
///   the dial's monitor and TCP opens must retry on a 1-RTT stream.
///
/// The phase is scoped to a **dial attempt**, not to the slot. Every dial starts
/// with [`Self::begin_attempt`], which resets the phase and returns an attempt
/// id; every later write (the dial's `mark_pending`/`set_token_early` and the
/// detached monitor's `mark_settled`) must present that id. The phase, the
/// early-token flag and the attempt id live in one atomic word and are updated
/// by compare-and-swap, so a monitor whose attempt has been superseded — e.g. a
/// candidate address that failed before publication while the reconnect loop
/// moved on to the next candidate — cannot overwrite the next attempt's phase.
///
/// A reader that already holds an older `quinn::Connection` still reads
/// whichever attempt is current; the phase only gates an optimisation
/// (waiting/retrying on 0-RTT rejection), and the stream's own
/// `ZeroRttRejected` error remains the authority.
#[derive(Debug)]
pub(crate) struct ZeroRttState {
    /// `attempt` (bits 3..) | `token_early` (bit 2) | `phase` (bits 0..=1).
    ///
    /// One word so the identity check and the update it guards commit
    /// together: a compare-and-swap that still sees the caller's attempt is the
    /// only way a write lands.
    state: std::sync::atomic::AtomicU64,
}

impl ZeroRttState {
    /// No 0-RTT attempt on this generation (full handshake awaited).
    pub(crate) const NONE: u8 = 0;
    /// 0-RTT offered; the handshake (and with it acceptance) is still pending.
    pub(crate) const PENDING: u8 = 1;
    /// The peer kept the early data.
    pub(crate) const ACCEPTED: u8 = 2;
    /// The peer discarded the early data; only 1-RTT streams work now.
    pub(crate) const REJECTED: u8 = 3;

    const PHASE_MASK: u64 = 0b11;
    const TOKEN_BIT: u64 = 1 << 2;
    const ATTEMPT_SHIFT: u32 = 3;
    /// 61 bits of attempt id; a wrap would take 2^61 dials and can be ignored.
    const ATTEMPT_MASK: u64 = u64::MAX >> Self::ATTEMPT_SHIFT;

    fn pack(attempt: u64, phase: u8, token_early: bool) -> u64 {
        ((attempt & Self::ATTEMPT_MASK) << Self::ATTEMPT_SHIFT)
            | (u64::from(phase) & Self::PHASE_MASK)
            | if token_early { Self::TOKEN_BIT } else { 0 }
    }

    fn unpack(word: u64) -> (u64, u8, bool) {
        (
            word >> Self::ATTEMPT_SHIFT,
            (word & Self::PHASE_MASK) as u8,
            word & Self::TOKEN_BIT != 0,
        )
    }

    /// Apply `f` only while `attempt` is still the current dial. The CAS makes
    /// "still current" and "the write lands" one step: a concurrent
    /// [`Self::begin_attempt`] either wins the word first (this call then sees a
    /// different attempt and does nothing) or loses to it (this call's write is
    /// overwritten by the new attempt's reset).
    fn update(&self, attempt: u64, f: impl Fn(u8, bool) -> (u8, bool)) -> bool {
        let mut cur = self.state.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let (current, phase, token_early) = Self::unpack(cur);
            if current != attempt {
                return false;
            }
            let (phase, token_early) = f(phase, token_early);
            let next = Self::pack(current, phase, token_early);
            match self.state.compare_exchange_weak(
                cur,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed,
            }
        }
    }

    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::atomic::AtomicU64::new(Self::pack(0, Self::NONE, false)),
        })
    }

    /// Current phase. One relaxed load; the value only gates an optimisation
    /// (waiting/retrying on 0-RTT rejection), never a correctness decision:
    /// the stream's own `ZeroRttRejected` error remains the authority.
    pub(crate) fn phase(&self) -> u8 {
        Self::unpack(self.state.load(std::sync::atomic::Ordering::Relaxed)).1
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.phase() == Self::PENDING
    }

    pub(crate) fn is_rejected(&self) -> bool {
        self.phase() == Self::REJECTED
    }

    #[cfg(test)]
    pub(crate) fn is_accepted(&self) -> bool {
        self.phase() == Self::ACCEPTED
    }

    /// Start a dial attempt: reset the phase and return the id every later
    /// write for this attempt must present. Called at the top of every
    /// `dial_once`, including each candidate of a multi-address dial.
    pub(crate) fn begin_attempt(&self) -> u64 {
        let mut cur = self.state.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let attempt = (cur >> Self::ATTEMPT_SHIFT).wrapping_add(1) & Self::ATTEMPT_MASK;
            let next = Self::pack(attempt, Self::NONE, false);
            match self.state.compare_exchange_weak(
                cur,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return attempt,
                Err(observed) => cur = observed,
            }
        }
    }

    /// A resumed dial entered its 0.5-RTT window.
    pub(crate) fn mark_pending(&self, attempt: u64) {
        let _ = self.update(attempt, |_, token_early| (Self::PENDING, token_early));
    }

    /// The handshake completed: `accepted` is quinn's `ZeroRttAccepted` value.
    /// Returns whether the verdict was committed; `false` means this attempt
    /// has been superseded (its connection will never be the slot's).
    pub(crate) fn mark_settled(&self, attempt: u64, accepted: bool) -> bool {
        self.update(attempt, move |_, token_early| {
            (
                if accepted {
                    Self::ACCEPTED
                } else {
                    Self::REJECTED
                },
                token_early,
            )
        })
    }

    pub(crate) fn set_token_early(&self, attempt: u64, sent: bool) {
        let _ = self.update(attempt, move |phase, _| (phase, sent));
    }

    #[cfg(test)]
    pub(crate) fn token_early(&self) -> bool {
        Self::unpack(self.state.load(std::sync::atomic::Ordering::Relaxed)).2
    }

    /// Wait (bounded by `deadline`) until the handshake phase is known.
    ///
    /// Polled at [`ZERO_RTT_SETTLE_POLL`]. The callers are the TCP open retry
    /// after a `ZeroRttRejected` error and the rev3 control-stream task waiting
    /// for a resumed dial to settle, so the handshake is already complete or
    /// about to be; the monitor task publishes the phase, and a single 10 ms
    /// tick covers the scheduling gap without adding a wakeup channel to the
    /// per-flow path.
    pub(crate) async fn wait_settled(&self, deadline: tokio::time::Instant) {
        while self.is_pending() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return;
            }
            tokio::time::sleep(ZERO_RTT_SETTLE_POLL.min(deadline - now)).await;
        }
    }
}

/// Poll interval while waiting for the handshake phase to become known (see
/// [`ZeroRttState::wait_settled`]).
pub(crate) const ZERO_RTT_SETTLE_POLL: Duration = Duration::from_millis(10);

/// One QUIC connection slot: the shared handle plus its generation channel.
/// Bumped on every swap so waiters sleep without polling and dispatchers drop
/// a stale connection without a per-packet timer.
#[derive(Clone, Debug)]
pub(crate) struct ConnSlot {
    pub(crate) shared: SharedConn,
    pub(crate) gen_tx: watch::Sender<u64>,
    pub(crate) gen_rx: watch::Receiver<u64>,
    /// 0-RTT phase of the connection in `shared` (see [`ZeroRttState`]):
    /// published with the connection, reset on every dial. The TCP open path
    /// reads it to retry an early stream after a rejection.
    pub(crate) zero_rtt: Arc<ZeroRttState>,
    /// Routing hint, maintained by the connection loop: `shared` holds a
    /// connection with no close reason. One atomic load where `close_reason()`
    /// takes quinn's connection-state mutex and clones the error, which
    /// `pick_tcp` would otherwise pay twice per TCP flow. `wait_conn` remains
    /// the authority that fails a flow fast.
    pub(crate) live: Arc<std::sync::atomic::AtomicBool>,
    /// MQP-3 rev2 state for the connection currently published in `shared`:
    /// the per-connection flow registry, the client wire-id allocator, the
    /// `HELLO`/`CAPS` negotiation result and the generation epoch.
    ///
    /// Published by the reconnect loop *before* the connection (and before the
    /// generation bump), so a dispatcher or association that wakes on a new
    /// generation always finds the state that belongs to the connection it is
    /// about to use. Cleared on the connection-death path before the next
    /// dial, which is what makes "no rev2 state" mean "this generation cannot
    /// carry rev2 frames".
    pub(crate) rev2: Arc<arc_swap::ArcSwapOption<ConnRev2>>,
    /// Inbound-progress stamp (coarse-epoch milliseconds), published by the
    /// reconnect loop's 1 Hz silence watchdog whenever its `ConnectionStats`
    /// snapshot shows `udp_rx.datagrams` advanced, and seeded at connection
    /// establishment. `udp_rx.datagrams` grows on every inbound datagram
    /// (ACKs, keepalive PINGs, stream data), so a healthy — even completely
    /// idle — connection advances the stamp at least once per keepalive
    /// interval, while a blackholed path (NAT rebind, Wi-Fi handover,
    /// SIGKILLed peer) freezes the counter and the stamp with it. That freeze
    /// is the signal `live` cannot express: a blackholed connection still has
    /// no `close_reason()` and keeps `live` true until the watchdog's
    /// `2/3 x idle` window (40 s at the shipped defaults) expires. `0` means
    /// "no progress observed yet" and is treated as *not* stale (see
    /// [`ConnSlot::is_data_stale`]):
    /// the clear path resets it on death, so a restored live hint can never
    /// pair a fresh generation with the previous one's stale stamp.
    pub(crate) last_rx_ms: Arc<std::sync::atomic::AtomicU64>,
    /// This slot's runtime handle, installed by `spawn_slot_shard` once the
    /// slot thread has built its current-thread runtime.
    ///
    /// The sharded topology runs one QUIC endpoint, one driver and one DATAGRAM
    /// dispatcher per slot on a pinned thread; the associations that ride a
    /// slot were, until now, still driven from the multi-threaded main runtime,
    /// so every uplink datagram crossed cores for quinn's connection-state lock
    /// and a driver wake. An association whose egress class is decided (it is,
    /// by its first datagram) can move its steady-state loop here, which makes
    /// the send, the driver poll and the DATAGRAM packing all local to one
    /// thread. `None` in the shared-runtime topology and in unit tests, which
    /// is exactly when the loop runs inline on the caller's runtime.
    pub(crate) runtime: Arc<std::sync::OnceLock<tokio::runtime::Handle>>,
}

impl ConnSlot {
    pub(crate) fn fresh() -> Self {
        let (gen_tx, gen_rx) = watch::channel(0u64);
        Self {
            shared: Arc::new(ArcSwapOption::const_empty()),
            gen_tx,
            gen_rx,
            zero_rtt: ZeroRttState::new(),
            live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rev2: Arc::new(arc_swap::ArcSwapOption::const_empty()),
            last_rx_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            runtime: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Install this slot's runtime handle (called once, from the slot thread).
    pub(crate) fn set_runtime(&self, handle: tokio::runtime::Handle) {
        let _ = self.runtime.set(handle);
    }

    /// The slot's runtime handle, or `None` while the slot thread has not
    /// started one (shared-runtime topology, unit tests).
    pub(crate) fn runtime(&self) -> Option<tokio::runtime::Handle> {
        self.runtime.get().cloned()
    }

    /// This slot's 0-RTT phase handle (cheap `Arc` clone; see
    /// [`ZeroRttState`]). The reconnect loop passes it to `dial_once`, which
    /// resets and then advances it as the dial's handshake progresses.
    pub(crate) fn zero_rtt_state(&self) -> Arc<ZeroRttState> {
        self.zero_rtt.clone()
    }

    /// Publish the rev2 state for the connection this slot is about to carry.
    pub(crate) fn set_rev2(&self, rev2: Arc<ConnRev2>) {
        self.rev2.store(Some(rev2));
    }

    /// Current rev2 state, if the published connection is a rev2 generation.
    pub(crate) fn rev2(&self) -> Option<Arc<ConnRev2>> {
        self.rev2.load().as_ref().cloned()
    }

    /// The rev2 state of `conn`'s generation, read **coherently** with the
    /// connection handle.
    ///
    /// `shared` and `rev2` are two separate publications, so a handle obtained
    /// earlier (a `wait_conn` return, an egress-cache load) can be stale by the
    /// time `rev2()` is read: a death + redial in between would pair the old
    /// connection with the *next* generation's id tables, and wire ids restart
    /// from 1 on every dial, so a buffered old-generation frame could resolve
    /// against an unrelated live binding.
    ///
    /// This re-checks that the slot still publishes `conn` (by `stable_id`)
    /// after loading the state, and that no generation bump happened across the
    /// read. Either mismatch means "read again", never a pair.
    ///
    /// The re-check is sound because of the publication order: `set_rev2` runs
    /// only while the slot is empty (the previous generation was retired
    /// first), then `publish`, then `bump_gen`. A generation bump observed here
    /// therefore means the connection was replaced or cleared; a `shared` load
    /// that still holds `conn` can only see the state published for it.
    pub(crate) fn rev2_for(&self, conn: &quinn::Connection) -> Option<Arc<ConnRev2>> {
        let generation = *self.gen_rx.borrow();
        let rev2 = self.rev2();
        let still_published = self
            .shared
            .load()
            .as_ref()
            .is_some_and(|c| c.stable_id() == conn.stable_id());
        let stable = generation == *self.gen_rx.borrow();
        if still_published && stable {
            rev2
        } else {
            None
        }
    }

    /// Clear the rev2 state of the dead generation (connection-death path, in
    /// the same commit that clears `shared`).
    ///
    /// Compare-and-clear on the generation identity, not a blind store: the
    /// death commit can run from two writers (the reconnect loop and a SOCKS
    /// `open_bi` failure), and either one may lose the race to a redial that
    /// published a fresh generation. A blind `store(None)` would strip the
    /// fresh connection's rev2 state and blackhole its UDP traffic until the
    /// next redial; a failed compare means the caller already lost the
    /// generation and must leave the slot alone. Returns whether this call
    /// cleared it.
    pub(crate) fn clear_rev2_if(&self, dead: &Arc<ConnRev2>) -> bool {
        let mut cleared = false;
        self.rev2.rcu(|cur| {
            if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, dead)) {
                cleared = true;
                None
            } else {
                cleared = false;
                cur.clone()
            }
        });
        cleared
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Publish "inbound progress observed now". Called at connection
    /// establishment (the handshake just delivered inbound datagrams) and then
    /// from the reconnect loop's watchdog tick whenever `udp_rx.datagrams`
    /// moved. The coarse clock is the right one here: the value is compared
    /// against a seconds-scale threshold, and the write runs on the 1 Hz
    /// reconnect loop while the read runs once per new TCP flow.
    pub(crate) fn note_rx_progress(&self) {
        self.last_rx_ms
            .store(coarse_millis(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Forget the previous generation's progress stamp (`0` = unknown, never
    /// stale). Called only on the path that commits a connection to `None`,
    /// next to the `live = false` store: leaving a stale stamp behind for the
    /// next generation would make a healthy redial look dead to one selection.
    /// The unknown default is the safe direction — a slot with no live
    /// connection cannot be selected anyway, and the publisher seeds the stamp
    /// before setting `live`.
    pub(crate) fn reset_rx_progress(&self) {
        self.last_rx_ms
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// True when this slot's inbound progress has been frozen for at least
    /// `threshold_ms` as of `now_ms`: the path-health gate
    /// [`ConnPool::pick_tcp_index`] applies to a `live` slot. A `0` stamp
    /// ("unknown", never observed since the last clear) is not stale — only the
    /// death path leaves it at `0`, where the `live` bit already excludes the
    /// slot, and treating it as fresh keeps the clear/publish race from
    /// rejecting a just-installed generation.
    pub(crate) fn is_data_stale(&self, now_ms: u64, threshold_ms: u64) -> bool {
        let stamp = self.last_rx_ms.load(std::sync::atomic::Ordering::Relaxed);
        stamp != 0 && now_ms.saturating_sub(stamp) >= threshold_ms
    }

    /// Synchronous dead-handle probe for the routing path: true when the slot
    /// currently publishes a connection whose `close_reason()` is populated.
    /// This is the stale-true window — QUIC died but the conn loop has not yet
    /// run `clear_if_and_mark_dead` + `bump_gen` — where the maintained `live`
    /// bit still reads true. One quinn state-lock acquisition, no await, no
    /// `std` lock held; `wait_conn` stays the authority that fails a flow.
    pub(crate) fn holds_dead_handle(&self) -> bool {
        let g = self.shared.load();
        let dead = g.as_ref().is_some_and(|c| c.close_reason().is_some());
        drop(g);
        dead
    }

    /// Publish `conn` as this slot's connection.
    pub(crate) fn publish(&self, conn: &quinn::Connection) {
        self.shared.store(Some(Arc::new(conn.clone())));
    }

    /// Clear the slot when it still holds `conn` (matched by `stable_id`, which
    /// survives a reconnect installing a different connection in the meantime).
    /// Returns true when this call is the one that cleared it.
    ///
    /// `rcu` keeps the read-then-write atomicity the `RwLock` version had with a
    /// single re-checked write: the closure runs again whenever a concurrent
    /// writer wins the swap, so a fresh connection installed during the clear is
    /// never blackholed. The closure is `FnMut` and its last run is the one whose
    /// result is committed, so `cleared` reflects the committed decision. The
    /// `live` bit is folded into the same decision by
    /// [`ConnSlot::clear_if_and_mark_dead`], whose store runs inside this
    /// closure on the path that commits to `None` — a trailing
    /// `live.store(false)` after `clear_if` returns would let a concurrent
    /// `publish` of a different `stable_id` land between the decision and the
    /// store and leave the fresh connection marked dead.
    ///
    /// Test-only: every production path uses `clear_if_and_mark_dead`. Kept
    /// so the BUG-2 regression test can pin the old two-step's (C, false)
    /// outcome against the helper.
    #[cfg(test)]
    pub(crate) fn clear_if(&self, conn: &quinn::Connection) -> bool {
        let mut cleared = false;
        self.shared.rcu(|cur| {
            if cur
                .as_ref()
                .is_some_and(|c| c.stable_id() == conn.stable_id())
            {
                cleared = true;
                None
            } else {
                cleared = false;
                cur.clone()
            }
        });
        cleared
    }

    /// Clear-if plus the `live = false` folded into the same atomic decision:
    /// the store runs inside the `rcu` closure, only on the path that commits
    /// to `None`, so a concurrent `publish` of a different `stable_id` can
    /// never be marked dead by the gap the old `clear_if` +
    /// `live.store(false)` sequence had (a publish landing between the decision
    /// and the store). Returns true when this call is the one that cleared it;
    /// the caller still owns the `bump_gen` on every committed swap.
    ///
    /// Retry note: `rcu` re-runs the closure when another writer wins the swap,
    /// so a losing first run may have stored `false` before the re-run saw the
    /// fresh connection. `marked && !cleared` detects exactly that tail and
    /// restores `true` when the slot now holds a different connection; a slot
    /// holding nothing (or still `conn`) keeps the `false` the clear committed.
    pub(crate) fn clear_if_and_mark_dead(&self, conn: &quinn::Connection) -> bool {
        let mut cleared = false;
        let mut marked = false;
        self.shared.rcu(|cur| {
            if cur
                .as_ref()
                .is_some_and(|c| c.stable_id() == conn.stable_id())
            {
                cleared = true;
                marked = true;
                self.live.store(false, std::sync::atomic::Ordering::Relaxed);
                // Same decision, same commit: the dead generation's inbound
                // stamp must not outlive it, or the next generation's first
                // selections would re-pick off a stamp that never described it.
                self.reset_rx_progress();
                None
            } else {
                cleared = false;
                cur.clone()
            }
        });
        if marked && !cleared {
            self.restore_live_if_replaced(conn.stable_id());
        }
        cleared
    }

    /// Undo the transient `live = false` of a clear whose CAS lost to a
    /// concurrent publish, and wake the waiters.
    ///
    /// The bump is not optional. A reader (`wait_conn`) wakes only on a
    /// generation bump or its deadline, and the reader that consumed the
    /// *publish's* own bump can go on to observe the `false` this clear stored
    /// before losing its race — so a restore that does not bump leaves a live
    /// connection unusable until that reader's whole timeout (10 s for a
    /// dispatcher: every inbound datagram on that egress connection stalls
    /// silently; the flow timeout for a TCP caller, whose SOCKS reply is then a
    /// spurious `REP=0x04`). A redundant bump only costs one re-check.
    ///
    /// Returns true when the slot holds a connection other than
    /// `dead_stable_id`, i.e. when the bit was actually restored.
    pub(crate) fn restore_live_if_replaced(&self, dead_stable_id: usize) -> bool {
        let g = self.shared.load();
        let restored = g.as_ref().is_some_and(|c| c.stable_id() != dead_stable_id);
        if restored {
            self.live.store(true, std::sync::atomic::Ordering::Relaxed);
            bump_gen(&self.gen_tx);
        }
        drop(g);
        restored
    }

    /// Wait for a live connection, waking on a generation bump or the deadline.
    ///
    /// Authority is `close_reason()`; the maintained `live` bit is only a hint
    /// that lets a known-dead slot skip quinn's connection-state mutex (`live`
    /// false waits without taking the lock). A `live` true handle is confirmed
    /// via `close_reason()` before it is handed out, so a stale-true window —
    /// `read_datagram` failing before the conn loop clears `live` + `bump_gen`
    /// — waits instead of returning a dead handle for the dispatcher to spin
    /// on. Cost is one quinn lock per `wait_conn` return (per TCP flow / per
    /// dispatcher generation, never per packet). Race window: `close_reason()`
    /// may flip right after this check; the TCP `open_bi` failure path
    /// (`clear_if_and_mark_dead` + `bump_gen`) stays the authoritative
    /// self-heal, so a handle that dies in flight still heals in one flow.
    pub(crate) async fn wait_conn(
        &self,
        gen_rx: &mut watch::Receiver<u64>,
        timeout: Duration,
    ) -> Result<quinn::Connection> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Lock-free read. The old `try_read`/`read().await` pair had a
            // fallback that parked this worker whenever a writer held the lock;
            // `ArcSwap::load` borrows the published handle instead, so a flow
            // opening during a reconnect never blocks a runtime thread.
            let g = self.shared.load();
            if let Some(c) = g.as_ref()
                && self.is_live()
                && c.close_reason().is_none()
            {
                return Ok((**c).clone());
            }
            drop(g);
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("quic unavailable (server restarting?)");
            }
            tokio::select! {
                _ = gen_rx.changed() => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }
}

/// Pure routing decision for tests: index of the TCP slot a new TCP flow uses.
///
/// A pinned (interactive) flow uses slot 0, the interactive connection. A bulk
/// flow rotates over the *other* TCP slots: slot 0 is what every
/// `interactive_ports` flow rides, so a bulk flow on it would put a latency probe
/// behind a bulk queue — which is exactly what `rr % n` used to do for one flow
/// in every n, making the isolation the pool exists for only (n-1)/n effective.
///
/// Failover is class-preserving **and rotated**. A dead preference continues the
/// rotation over the live slots of the class instead of collapsing onto the
/// first live one: the pre-fix `(0..n).find`/`(1..n).find` shape put every
/// interactive flow on bulk slot 1 while slot 0 reconnected, and dumped a dead
/// bulk slot's whole round-robin share on the lowest live sibling — i.e. it
/// broke the isolation precisely when a connection was already degraded. Both
/// classes share the rotation position `1 + rr % (n - 1)` over the bulk slots,
/// so a bulk flow continues from its own preference while a pinned flow (slot 0
/// down) starts at the shared cursor; `pick_tcp_index` advances that cursor on
/// every flow, pinned ones included, so successive fallbacks start at
/// successive bulk slots. A bulk class with no live slot at all falls back to
/// slot 0 (and only if it is actually carrying traffic); the pinned class has
/// nowhere else to go. When nothing is live the preference is kept, so
/// `wait_conn` bounds the stall and fails the flow fast instead of the pool
/// inventing a slot that has no connection behind it.
///
/// `live` describes the **TCP** slots only. The dedicated UDP egress slot lives
/// outside this range (see [`ConnPool::udp_bind`]) and is never a TCP target.
pub(crate) fn select_slot(pinned: bool, rr: usize, live: &[bool]) -> usize {
    debug_assert!(!live.is_empty(), "the pool always has at least one slot");
    let n = live.len();
    if n == 1 {
        return 0;
    }
    let bulk = n - 1;
    let preferred = if pinned { 0 } else { 1 + rr % bulk };
    if live[preferred] {
        return preferred;
    }
    // Rotated scan over the bulk set from the shared rotation position. For a
    // bulk flow that position is the dead preference itself; for a pinned flow
    // it is the common cursor, so its fallbacks spread over slots 1..n instead
    // of all taking the first live one. Continuing forward (rather than
    // restarting at the lowest index) is what moves a reconnect's flows to the
    // dead slot's successor instead of doubling the lowest sibling.
    for k in 0..bulk {
        let i = 1 + (rr + k) % bulk;
        if live[i] {
            return i;
        }
    }
    // No bulk slot is live. Bulk shares the interactive connection rather than
    // stall, but only if it is actually carrying traffic; pinned keeps slot 0
    // (the preference) so `wait_conn` fails the flow fast.
    if !pinned && live[0] { 0 } else { preferred }
}

/// Selection-time path-health threshold in milliseconds: how long a `live`
/// slot's inbound progress may be frozen before [`ConnPool::pick_tcp_index`]
/// stops preferring it (see [`ConnSlot::is_data_stale`]).
///
/// Derived from the same keepalive/watchdog pair the transport and the
/// reconnect loop use, as the midpoint between the two bounds that matter:
///
/// - **Lower bound — a healthy idle connection must never be rejected.** The
///   shipped 5 s keepalive makes the peer's ACKs and keepalive PINGs arrive at
///   least every keepalive interval, and the 1 Hz watchdog samples
///   `udp_rx.datagrams` after at most one `WATCHDOG_POLL` tick, so the stamp's
///   age on a healthy idle connection stays below `keepalive + poll`.
/// - **Upper bound — the gate must win while the slot is still live.** The
///   watchdog force-closes at `2/3 x idle` (40 s at the shipped defaults) and
///   needs a poll tick to notice, so a threshold at or above that would never
///   be reached while the blackholed slot was still selectable.
///
/// The midpoint is provably strictly between the bounds for every legal
/// keepalive/idle pair (locked by
/// `data_stale_threshold_sits_between_healthy_idle_and_watchdog`). With the
/// shipped 5 s keepalive and 40 s watchdog it is 22 s, so a path that
/// blackholes stops receiving *new* flows 18 s before the watchdog would even
/// notice, instead of accepting every CONNECT for the whole 40 s window.
pub(crate) fn data_stale_threshold_ms(keep_alive_secs: u64, watchdog_secs: u64) -> u64 {
    // Same clamp the transport applies (`clamp_keep_alive`); no warning here —
    // `main` clamped and validated the configured value already, and this is
    // also called from the tests' default constructor.
    let keepalive = keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    debug_assert!(
        watchdog_secs > keepalive,
        "watchdog {watchdog_secs}s must exceed keepalive {keepalive}s"
    );
    (keepalive + watchdog_secs) / 2 * 1_000
}

/// A resolved UDP egress binding: which dedicated UDP connection an
/// association's datagrams ride, fixed from its first datagram for the
/// association's life (see [`ConnPool::udp_bind`]).
///
/// `index` addresses the UDP **range**, not the pool: `0` is the interactive
/// slot, `1..=bulk_shards` the bulk shards, and [`ConnPool::udp_global_slot`]
/// maps it to a pool slot. The egress cache in `SharedEgress` is keyed by the
/// same index, so once an association has bound, its datagrams (and all
/// fragments of a payload — they must stay on one connection) never consult
/// the class again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UdpBind {
    pub(crate) class: EgressClass,
    pub(crate) index: usize,
}

/// UDP egress class: which dedicated connection an association's datagrams ride.
///
/// The bulk class carries large or steady flows (HTTP/3, WireGuard, big
/// transfers); the interactive one carries latency-sensitive flows. Without the
/// split every association shares one connection, and quinn drops the *newest*
/// datagram when that connection's 1 MB DATAGRAM send buffer fills and lets
/// every DATAGRAM jump the STREAM queue — so a bulk flow starves a
/// latency-sensitive one with no isolation at all.
///
/// An association is classified once, from its first datagram, and keeps its
/// class — and, for bulk, one of several shard connections — for life:
/// switching mid-flow would move the server session to another connection and
/// change the source port the target sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EgressClass {
    /// An `interactive_ports` destination, or a first payload no larger than
    /// [`UDP_INTERACTIVE_MAX`] on any other port (STUN/DTLS/RTP-sized media,
    /// DNS, games).
    Interactive,
    /// Everything else, plus every destination port in `udp_bulk_ports`: a VPN
    /// tunnel is steady bulk traffic whose first packet is small.
    Bulk,
}

impl EgressClass {
    pub(crate) fn name(self) -> &'static str {
        match self {
            EgressClass::Interactive => "interactive",
            EgressClass::Bulk => "bulk",
        }
    }
}

/// First-datagram payload size at or below which a UDP association is treated
/// as interactive.
///
/// The motivating case is realtime media on *ephemeral* ports, which
/// `interactive_ports` cannot name: a WebRTC association's first datagram is a
/// STUN binding request (tens of bytes) or a DTLS ClientHello (a few hundred),
/// while a bulk flow's first datagram is a full-size padded QUIC Initial
/// (~1200 B or more). 512 B separates those while staying above the media-size
/// range. A misclassified flow degrades to the pre-split behaviour — it shares
/// its class's connection — so the worst case is never worse than before.
pub(crate) const UDP_INTERACTIVE_MAX: usize = 512;

/// Resolved pool shape for one config: the TCP slots plus the dedicated UDP
/// egress range, every count clamped to the hard caps.
///
/// This is the **single** definition of the layout. [`ConnPool::new_with_bulk_ports`],
/// [`planned_slot_count`] and the client's fd budget all derive from it, so a
/// new clamp can never leave one of them describing a different pool (the
/// scratch arrays in the routing and egress paths are sized from
/// [`MAX_POOL_CONNS`] / [`MAX_UDP_SLOTS`] and depend on the same caps).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotLayout {
    /// TCP slots (`0..tcp`): slot 0 interactive, the rest bulk.
    pub(crate) tcp: usize,
    /// Interactive UDP shards (UDP-range indices `0..interactive`).
    pub(crate) interactive: usize,
    /// Bulk UDP shards (UDP-range indices `interactive..interactive + bulk`).
    pub(crate) bulk: usize,
    /// Width of the UDP range: `interactive + bulk`, or 1 without the split.
    pub(crate) udp: usize,
    /// `tcp + udp`.
    pub(crate) total: usize,
}

impl SlotLayout {
    /// Resolve a layout from the config knobs, applying the same clamps the
    /// pool has always applied: at least one TCP slot, at least one shard per
    /// class when split, and nothing wider than the caps the scratch arrays
    /// assume. `udp_split = false` collapses the range to one shared slot.
    pub(crate) fn for_config(
        conns: usize,
        udp_split: bool,
        udp_interactive: usize,
        udp_bulk: usize,
    ) -> Self {
        let tcp = conns.clamp(1, MAX_POOL_CONNS);
        let (interactive, bulk) = if udp_split {
            (
                udp_interactive.clamp(1, MAX_UDP_INTERACTIVE_CONNS),
                udp_bulk.clamp(1, MAX_UDP_EGRESS_CONNS),
            )
        } else {
            (1, 1)
        };
        let udp = if udp_split { interactive + bulk } else { 1 };
        Self {
            tcp,
            interactive,
            bulk,
            udp,
            total: tcp + udp,
        }
    }
}

/// The client's QUIC connection pool: `n` TCP slots indexed `0..n`, where
/// `n = ClientConf::conn_count()` (4 by default, `quic_conns`), plus a
/// **dedicated UDP egress range** past the TCP slots.
///
/// Slot 0 is the interactive connection: every port in `interactive_ports` rides
/// it, and it is the sole TCP slot when `quic_conns == 1`. The other TCP slots
/// absorb their share of the bulk TCP streams, so each cwnd holds ~1/n of the
/// queue instead of all of it. quinn 0.11 has no per-stream priority, so separate
/// congestion windows are the isolation mechanism.
///
/// The UDP range is *additional*, not carved out of the TCP range: making UDP
/// independent must not cost TCP a congestion window, and `quic_conns` keeps its
/// documented meaning ("TCP pool size"). UDP and TCP on one connection is not a
/// theoretical concern — quinn fills every packet with queued DATAGRAM frames
/// *before* STREAM frames (`quinn-proto` `populate_packet`) and both share one
/// congestion window, so a bulk UDP flow (HTTP/3, WireGuard, video) starves the
/// TCP streams on the same connection, and a bulk TCP flow makes every UDP
/// datagram hit the 1 MiB datagram-send-buffer `Blocked` drop. One connection per
/// class is the only isolation QUIC gives without stream priorities.
///
/// With `udp_split` (the default) the UDP range starts with the **interactive**
/// class's `udp_interactive_conns` shards (indices `0..`) followed by
/// `udp_egress_conns` **bulk** shards, so a bulk UDP flow's congestion window
/// and DATAGRAM buffer cannot starve a latency-sensitive flow, and each
/// association population spreads across several connections instead of
/// funneling into one connection's driver, dispatcher and server-side reader.
/// The interactive class is sharded too: every association in it shares its
/// connection's 1 MiB DATAGRAM buffer, 256 KiB stager and congestion window, so
/// a single slot turns the whole latency-sensitive population into one queue
/// that any bursting association can drain into `Blocked` drops. Every
/// association is assigned its shard once, from its first datagram
/// ([`ConnPool::udp_bind`]); `udp_split = false` restores the single shared UDP
/// slot (index 0) and disables sharding.
///
/// The slots live in a plain `Arc<Vec<ConnSlot>>` indexed by slot number. The
/// set is fixed at startup and never mutated, so a routing read is one indexed
/// load — no pin, no hash, no reclamation — and a `ConnPool` clone
/// (once per accepted SOCKS connection) stays one refcount bump.
#[derive(Clone, Debug)]
pub(crate) struct ConnPool {
    pub(crate) slots: Arc<Vec<ConnSlot>>,
    pub(crate) rr: Arc<std::sync::atomic::AtomicUsize>,
    /// Round-robin cursor for bulk shard assignment (see [`ConnPool::udp_bind`]).
    pub(crate) udp_rr: Arc<std::sync::atomic::AtomicUsize>,
    /// Round-robin cursor for interactive shard assignment. Separate from
    /// [`Self::udp_rr`] so a burst of bulk associations cannot shift the
    /// shard a latency-sensitive association lands on.
    pub(crate) udp_irr: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) interactive_ports: Arc<std::collections::HashSet<u16, foldhash::fast::RandomState>>,
    /// Destination ports forced to the **bulk** class whatever their first
    /// payload size (see [`ConnPool::udp_class`]). A VPN tunnel's first packet
    /// is small — WireGuard's handshake is 148 B — so the size heuristic alone
    /// would keep the whole tunnel on the interactive connections next to
    /// DNS/STUN/games, where it can never use the bulk shards. Empty from the
    /// size-only test constructor, i.e. the pure size heuristic.
    pub(crate) bulk_ports: Arc<std::collections::HashSet<u16, foldhash::fast::RandomState>>,
    /// TCP slots: the routing range is `0..tcp_slots` (0 interactive, rest
    /// bulk). Never includes the UDP range.
    pub(crate) tcp_slots: usize,
    /// Whether UDP egress is split into one dedicated connection for the
    /// interactive class plus `bulk_shards` for the bulk class (the default)
    /// or shares a single one.
    pub(crate) udp_split: bool,
    /// Interactive UDP shards (UDP-range indices `0..interactive_shards`). 1
    /// when `udp_split` is off, in which case every class shares index 0.
    pub(crate) interactive_shards: usize,
    /// Bulk UDP shards (UDP-range indices
    /// `interactive_shards..interactive_shards + bulk_shards`). 1 when
    /// `udp_split` is off.
    pub(crate) bulk_shards: usize,
    /// Width of the UDP range ([`SlotLayout::udp`]): `interactive_shards +
    /// bulk_shards` with the split on, 1 without it.
    pub(crate) udp_slots: usize,
    /// When set, UDP only ever uses dedicated UDP slots *of its own class*: if
    /// every one of them is down the datagram is dropped (counted in
    /// `dgram_drops::NO_EGRESS`) instead of sharing a TCP connection's
    /// congestion window.
    pub(crate) udp_fail_closed: bool,
    /// Selection-time path-health threshold in coarse-epoch milliseconds (see
    /// [`data_stale_threshold_ms`]): a `live` TCP slot whose published
    /// inbound-progress stamp ([`ConnSlot::last_rx_ms`]) is older than this is
    /// re-picked away from in [`ConnPool::pick_tcp_index`]. Computed once at
    /// startup from the resolved keepalive/watchdog pair, so the routing path's
    /// check is two relaxed loads and a cached-clock read.
    pub(crate) data_stale_ms: u64,
}

impl ConnPool {
    /// The pre-bulk-port-constructor pool shape: the same slots as
    /// [`ConnPool::new_with_bulk_ports`] with the bulk-port override list
    /// empty, i.e. the pure size heuristic every existing test was written
    /// against. Test-only because production always passes the configured
    /// list — keeping it as the single implementation of the slot layout is
    /// what makes "no bulk ports" a supported configuration rather than a
    /// second code path.
    #[cfg(test)]
    pub(crate) fn new(
        n: usize,
        interactive_ports: Vec<u16>,
        udp_fail_closed: bool,
        udp_split: bool,
        udp_bulk_shards: usize,
    ) -> Self {
        Self::new_with_bulk_ports(
            n,
            interactive_ports,
            Vec::new(),
            udp_fail_closed,
            udp_split,
            // The legacy shape the size-heuristic tests were written against:
            // one interactive slot. Tests that exercise interactive sharding
            // go through `new_with_bulk_ports` directly.
            1,
            udp_bulk_shards,
            // The shipped defaults (5 s keepalive, 60 s idle -> 40 s watchdog)
            // drive the selection-time path-health threshold, so the routing
            // table the existing tests were written against keeps its shape.
            // Tests that exercise the gate set `pool.data_stale_ms` (and the
            // slots' stamps) directly.
            data_stale_threshold_ms(5, 40),
        )
    }

    /// Build the process pool: `tcp` TCP slots indexed `0..tcp`, then the UDP
    /// range — with `udp_split` on, `udp_interactive_shards` interactive slots
    /// at UDP indices `0..` followed by `udp_bulk_shards` bulk shards, clamped
    /// here so no caller can build a pool wider than the scratch arrays the
    /// routing and egress paths size from [`MAX_POOL_CONNS`] /
    /// [`MAX_UDP_SLOTS`].
    ///
    /// `bulk_ports` is the destination-port override list (see
    /// [`ConnPool::udp_class`]): ports classified as bulk whatever their first
    /// payload size. It only affects classification, never the slot layout.
    ///
    /// `data_stale_ms` is the selection-time path-health threshold (see
    /// [`data_stale_threshold_ms`]), derived by `main` from the same resolved
    /// idle timeout as the transport and the watchdog.
    // One argument per tuning knob it mirrors — folding them into a struct
    // would hide the call sites' intent behind field names.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_bulk_ports(
        n: usize,
        interactive_ports: Vec<u16>,
        bulk_ports: Vec<u16>,
        udp_fail_closed: bool,
        udp_split: bool,
        udp_interactive_shards: usize,
        udp_bulk_shards: usize,
        data_stale_ms: u64,
    ) -> Self {
        let layout = SlotLayout::for_config(n, udp_split, udp_interactive_shards, udp_bulk_shards);
        let slots: Vec<ConnSlot> = (0..layout.total).map(|_| ConnSlot::fresh()).collect();
        Self {
            slots: Arc::new(slots),
            rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            udp_rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            udp_irr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            interactive_ports: Arc::new(interactive_ports.into_iter().collect()),
            bulk_ports: Arc::new(bulk_ports.into_iter().collect()),
            tcp_slots: layout.tcp,
            udp_split,
            interactive_shards: layout.interactive,
            bulk_shards: layout.bulk,
            udp_slots: layout.udp,
            udp_fail_closed,
            data_stale_ms,
        }
    }

    /// TCP slots; slot indices are `0..tcp_slots`.
    pub(crate) fn tcp_slots(&self) -> usize {
        self.tcp_slots
    }

    /// UDP-range width: the interactive shards plus the bulk ones with the
    /// split on, a single shared slot with it off.
    pub(crate) fn udp_slot_count(&self) -> usize {
        self.udp_slots
    }

    /// Interactive UDP shards (the class's UDP-range width).
    pub(crate) fn interactive_shards(&self) -> usize {
        self.interactive_shards
    }

    /// Pool slot holding UDP-range index `index`.
    pub(crate) fn udp_global_slot(&self, index: usize) -> usize {
        self.tcp_slots + index
    }

    /// UDP-range indices carrying `class`. With the split on, the interactive
    /// class is `0..interactive_shards` and the bulk class is everything after
    /// it; with it off both classes share index 0. This is the fail-closed
    /// boundary: a datagram may fail over inside its own class's set but never
    /// leaves it.
    pub(crate) fn udp_class_slots(&self, class: EgressClass) -> std::ops::Range<usize> {
        match class {
            EgressClass::Interactive if self.udp_split => 0..self.interactive_shards,
            EgressClass::Bulk if self.udp_split => self.interactive_shards..self.udp_slot_count(),
            _ => 0..1,
        }
    }

    /// Every slot, TCP first then the UDP range: the range to walk when
    /// spawning per-slot tasks or scanning the registry.
    pub(crate) fn slots_total(&self) -> usize {
        self.tcp_slots + self.udp_slot_count()
    }

    /// Bind `class` to a UDP-range index: associations rotate over their own
    /// class's shards, with the interactive class on its own cursor. Called
    /// once per association, from its first datagram — see [`UdpBind`].
    ///
    /// Rotation (not hashing): associations arrive in an arbitrary order and
    /// live for a long time, so a cursor spreads them as evenly as a hash
    /// would while staying one relaxed fetch_add and trivially testable. Two
    /// cursors keep a burst of bulk associations from shifting which
    /// interactive connection a latency-sensitive one lands on.
    pub(crate) fn udp_bind(&self, class: EgressClass) -> UdpBind {
        let shard = match class {
            EgressClass::Interactive if self.udp_split => self
                .udp_irr
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            EgressClass::Bulk if self.udp_split => self
                .udp_rr
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            _ => 0,
        };
        self.udp_bind_shard(class, shard)
    }

    /// The explicit-shard form of [`ConnPool::udp_bind`]: `shard` is reduced
    /// modulo the class's shard count, so callers that carry their own stable
    /// association key (and tests) never need the cursor.
    pub(crate) fn udp_bind_shard(&self, class: EgressClass, shard: usize) -> UdpBind {
        let index = match class {
            EgressClass::Interactive if self.udp_split => shard % self.interactive_shards,
            EgressClass::Bulk if self.udp_split => {
                self.interactive_shards + shard % self.bulk_shards
            }
            _ => 0,
        };
        UdpBind { class, index }
    }

    /// Egress class for a UDP association, from its first datagram. Precedence:
    /// a known interactive port, then a known bulk port (a VPN data port is
    /// bulk whatever the first payload size — its handshake is small), then
    /// the first-payload heuristic (see [`EgressClass`] and
    /// [`UDP_INTERACTIVE_MAX`]).
    pub(crate) fn udp_class(&self, addr: &TargetAddrRef<'_>, first_payload: usize) -> EgressClass {
        let port = match *addr {
            TargetAddrRef::Ip(s) => s.port(),
            TargetAddrRef::Domain(_, p) => p,
        };
        // Interactive first: an operator who lists a port in both sets has
        // stated it is latency-sensitive, and the explicit class must win.
        if self.interactive_ports.contains(&port) {
            return EgressClass::Interactive;
        }
        // The bulk override exists because the size heuristic cannot see the
        // protocol behind the port: WireGuard's 148 B handshake, OpenVPN's
        // small control packets, i.e. the flows most likely to be steady bulk
        // traffic are exactly the ones that look like a STUN binding request.
        if self.bulk_ports.contains(&port) {
            return EgressClass::Bulk;
        }
        if first_payload <= UDP_INTERACTIVE_MAX {
            EgressClass::Interactive
        } else {
            EgressClass::Bulk
        }
    }

    pub(crate) fn udp_fail_closed(&self) -> bool {
        self.udp_fail_closed
    }

    /// The slot at `i`, borrowed. Prefer this on the per-flow paths: `slot`
    /// clones the six `Arc`s and the watch pair (~9 refcount operations) for a
    /// value whose only shared state is those very `Arc`s.
    pub(crate) fn slot_ref(&self, i: usize) -> &ConnSlot {
        self.slots
            .get(i)
            .expect("pool slots are installed at startup and never removed")
    }

    /// The slot at `i`, owned. Only for callers that need a `'static` value
    /// (`tokio::spawn`) or that store it; everything else should use
    /// [`ConnPool::slot_ref`]. Slots are installed by `new` and never removed,
    /// so the index is always in range; out-of-range would mean the pool was
    /// not built by `new`.
    pub(crate) fn slot(&self, i: usize) -> ConnSlot {
        self.slot_ref(i).clone()
    }

    pub(crate) fn target_port(t: &TargetAddr) -> u16 {
        match t {
            TargetAddr::Ip(s) => s.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Index of the TCP slot a new TCP flow should use (see [`select_slot`]).
    ///
    /// `n` indexed liveness reads and two stack arrays: no lock, no per-flow
    /// allocation, and no `close_reason()` per slot (which takes quinn's
    /// connection-state mutex) — the maintained `live` bit and the reconnect
    /// loop's inbound-progress stamp are what routing reads, and `wait_conn`
    /// remains the authority that fails a flow fast.
    ///
    /// Two overlays, applied in order to the **candidate that will be
    /// returned** so neither can undo the other. Each re-picks at most once over
    /// the same class rules, so a flow can never oscillate and an all-unusable
    /// pool keeps the preference for the bounded `wait_conn` stall:
    ///
    /// 1. **Dead handle (L2)**: `live` is only a hint, so a slot whose QUIC
    ///    connection died in the window before the conn loop clears the bit
    ///    still reads true; `close_reason()` is the authority. A dead candidate
    ///    is excluded from both the liveness and the freshness set before the
    ///    re-pick (a dead handle is unusable whatever its progress stamp says).
    /// 2. **Path health (L3)**: a *blackholed* connection has no close reason
    ///    and still reads live — NAT rebind, Wi-Fi handover, SIGKILLed peer —
    ///    so `close_reason()` cannot see it until the silence watchdog fires
    ///    (`2/3 x idle`, 40 s at the shipped defaults). Its published
    ///    inbound-progress stamp goes stale first (see
    ///    [`ConnSlot::is_data_stale`] and [`data_stale_threshold_ms`]), so a
    ///    `live` candidate whose progress is stale is re-picked over the
    ///    live-and-fresh set. This changes
    ///    *selection only*: the slot stays live, the watchdog stays the
    ///    authority that force-closes and redials, and nothing here can trigger
    ///    a reconnect.
    ///
    /// The dead-handle probe is repeated on the L3 result, because a sibling
    /// can die inside its stamp window; the common path pays one probe and a
    /// failover at most two.
    pub(crate) fn pick_tcp_index(&self, t: &TargetAddr) -> usize {
        self.pick_tcp_index_inner(t, coarse_millis())
    }

    /// Test seam for the path-health gate: [`ConnPool::pick_tcp_index`] with the
    /// caller-supplied coarse-epoch reading, so a unit test can place a slot's
    /// stamp seconds in the past without sleeping out a seconds-scale threshold
    /// (the coarse clock only advances in ~1 s upkeep steps, so a real sleep
    /// would make these tests slow and flaky). Production goes through
    /// `pick_tcp_index`, whose only extra job is to supply the clock — so a
    /// test and the real path can never disagree about which clock the stamps
    /// use.
    #[cfg(test)]
    pub(crate) fn pick_tcp_index_at(&self, t: &TargetAddr, now_ms: u64) -> usize {
        self.pick_tcp_index_inner(t, now_ms)
    }

    /// The routing decision itself; `now_ms` is the coarse-epoch reading the
    /// inbound-progress stamps are compared against.
    fn pick_tcp_index_inner(&self, t: &TargetAddr, now_ms: u64) -> usize {
        let n = self.tcp_slots();
        debug_assert!(n <= MAX_POOL_CONNS);
        let mut live = [false; MAX_POOL_CONNS];
        // `live` with the inbound-progress gate applied: the set the L3
        // re-pick rotates over. Kept alongside `live` because `select_slot`'s
        // class rules (interactive pin, bulk fallback to slot 0) must hold for
        // both sets.
        let mut fresh = [false; MAX_POOL_CONNS];
        for i in 0..n {
            let slot = self.slots.get(i);
            let l = slot.is_some_and(ConnSlot::is_live);
            live[i] = l;
            fresh[i] = l && slot.is_some_and(|s| !s.is_data_stale(now_ms, self.data_stale_ms));
        }
        let pinned = self.is_interactive(t);
        // The cursor advances on every flow, pinned ones included. The pinned
        // class does not consult it while slot 0 is live, but when slot 0 is
        // down its fallback rotation does — and a cursor only bulk flows
        // advanced would restart every pinned fallback at the same bulk slot
        // instead of spreading over the live set. One relaxed RMW per flow is
        // the same cost the old bulk-only increment paid.
        let rr = self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut pick = select_slot(pinned, rr, &live[..n]);
        // L2 dead-handle failover: a slot whose QUIC connection died in the
        // window before the conn loop clears the bit still reads true and
        // `select_slot` keeps preferring it. `wait_conn` would then sit on that
        // slot's generation until the reconnect timeout even with live bulk
        // siblings available. Confirm the candidate with `close_reason()` and,
        // when it holds a dead handle, re-pick once with the same `rr` and that
        // slot overlaid dead — class rules unchanged, and an all-dead pool
        // keeps the preference for the bounded stall. The candidate is dropped
        // from `fresh` too: a dead handle is unusable whatever its stamp says,
        // and the L3 overlay must not select it again.
        let mut pick_checked = false;
        if live[pick] {
            pick_checked = true;
            if self
                .slots
                .get(pick)
                .is_some_and(ConnSlot::holds_dead_handle)
            {
                live[pick] = false;
                fresh[pick] = false;
                pick = select_slot(pinned, rr, &live[..n]);
                pick_checked = false;
            }
        }
        // L3 path-health gate: the candidate is live but its inbound progress
        // has been frozen for the threshold — a blackholed path that
        // `close_reason()` cannot see yet. Re-pick once over the live-and-fresh
        // set with the same `rr` and class rules, excluding the candidate just
        // rejected. When every live slot is stale (a whole-pool outage, or a
        // stalled clock) keep the candidate: a stale sibling would stall just
        // the same, and `wait_conn` bounds the wait. Nothing is written here —
        // the watchdog remains the only authority that closes and redials a
        // slot.
        if live[pick] && !fresh[pick] && fresh[..n].iter().any(|&f| f) {
            fresh[pick] = false;
            pick = select_slot(pinned, rr, &fresh[..n]);
            pick_checked = false;
        }
        // The L3 re-pick is stamp-checked only: its connection can have died
        // after the last progress sample. Confirm the final candidate once
        // (unless the L2 probe above already covered it) and, when it is dead,
        // prefer any fresh sibling left. With none, keep it: every alternative
        // is dead too, and `wait_conn`'s bounded stall plus the conn loop's
        // retire are the authority.
        if !pick_checked
            && live[pick]
            && self
                .slots
                .get(pick)
                .is_some_and(ConnSlot::holds_dead_handle)
        {
            fresh[pick] = false;
            if fresh[..n].iter().any(|&f| f) {
                pick = select_slot(pinned, rr, &fresh[..n]);
            }
        }
        pick
    }

    /// Pick the slot for a new TCP flow. Returning flows stick to their slot
    /// for life, so nothing oscillates.
    ///
    /// Test-only since the SOCKS dead-slot cleanup needs the *index* as well as
    /// the slot (`pick_tcp_index` + `slot`); kept as the single definition of
    /// "the slot a new flow would use" for the routing tests.
    #[cfg(test)]
    pub(crate) fn pick_tcp(&self, t: &TargetAddr) -> ConnSlot {
        self.slot(self.pick_tcp_index(t))
    }

    pub(crate) fn is_interactive(&self, t: &TargetAddr) -> bool {
        self.interactive_ports.contains(&Self::target_port(t))
    }
}

/// Whether pool slot `i` dials with the coarse **bulk** transport preset
/// (ACK threshold 8 / 10 ms delay / 2 MB DATAGRAM buffers) instead of the
/// tuned interactive one (2 / 5 ms / 1 MB).
///
/// Exactly the bulk UDP shards do. The TCP pool and the *interactive* UDP
/// class — whose whole point is latency-sensitive flows — keep the tuned
/// preset, as `build_transport_tuned_class` documents. With `udp_split` off
/// the single shared UDP slot keeps the bulk preset it had before the
/// per-class split.
pub(crate) fn slot_uses_bulk_preset(pool: &ConnPool, i: usize) -> bool {
    if i < pool.tcp_slots {
        return false;
    }
    // UDP range: with the split, index 0 is the interactive slot and every
    // shard after it is bulk; without it, the single shared slot is bulk.
    !pool.udp_split || i > pool.tcp_slots
}

/// Whether pool slot `i` carries the latency-sensitive egress class and should
/// therefore be raised above the kernel's default local scheduling priority.
///
/// That is slot 0 of the TCP pool (`interactive_ports`: SSH, RDP, DNS-over-TCP)
/// and every **interactive** UDP shard. The other TCP slots and the bulk UDP
/// shards are throughput classes and stay at priority 0. With `udp_split` off,
/// the one shared UDP slot carries both classes and is left alone: marking it
/// would promote a bulk flow that happens to share the socket.
///
/// This is deliberately a *narrower* predicate than
/// [`slot_uses_bulk_preset`], which treats every TCP slot as tuned: transport
/// presets are about ACK cadence and buffer depth, while the socket priority is
/// the local qdisc/WMM verdict on the flow's latency budget.
pub(crate) fn slot_is_latency_sensitive(pool: &ConnPool, i: usize) -> bool {
    if i < pool.tcp_slots {
        return i == 0;
    }
    pool.udp_split && i < pool.tcp_slots + pool.interactive_shards
}

/// Number of pool slots [`ConnPool::new_with_bulk_ports`] would build for a
/// config with these clamped values, without allocating the slots.
///
/// `main` needs the slot count *before* the runtime exists: the sharded
/// topology pins one current-thread runtime per slot, and the main runtime's
/// worker count is sized to the cores those pinned threads leave over (see
/// `main_runtime_workers`). Keeping the arithmetic in one function that mirrors
/// `new_with_bulk_ports` is what stops the two from drifting — a worker count
/// computed from a stale slot layout silently reintroduces the oversubscription
/// the split exists to avoid.
#[must_use]
pub(crate) fn planned_slot_count(
    conns: usize,
    udp_split: bool,
    udp_interactive: usize,
    udp_egress: usize,
) -> usize {
    SlotLayout::for_config(conns, udp_split, udp_interactive, udp_egress).total
}

#[cfg(test)]
mod planned_slot_count_tests {
    use super::*;

    #[test]
    fn planned_slots_match_the_built_pool() {
        for (conns, split, interactive, egress) in [
            (None, true, None, None),
            (Some(1), true, Some(1), Some(1)),
            (Some(16), true, Some(8), Some(8)),
            (Some(3), false, Some(8), Some(8)),
            (Some(0), true, Some(0), Some(0)),
            (Some(99), true, Some(99), Some(99)),
        ] {
            let conns = conns.unwrap_or(crate::DEFAULT_QUIC_CONNS);
            let interactive = interactive.unwrap_or(crate::DEFAULT_UDP_INTERACTIVE_CONNS);
            let egress = egress.unwrap_or(crate::DEFAULT_UDP_EGRESS_CONNS);
            let pool = ConnPool::new_with_bulk_ports(
                conns,
                Vec::new(),
                Vec::new(),
                true,
                split,
                interactive,
                egress,
                1,
            );
            let layout = SlotLayout::for_config(conns, split, interactive, egress);
            assert_eq!(
                planned_slot_count(conns, split, interactive, egress),
                pool.slots_total(),
                "config ({conns:?}, split={split}, interactive={interactive:?}, egress={egress:?})"
            );
            // The layout is the single definition: the built pool and the
            // planned count must both be its fields, not a second arithmetic.
            assert_eq!(
                (
                    layout.tcp,
                    layout.interactive,
                    layout.bulk,
                    layout.udp,
                    layout.total
                ),
                (
                    pool.tcp_slots(),
                    pool.interactive_shards(),
                    pool.bulk_shards,
                    pool.udp_slot_count(),
                    pool.slots_total()
                ),
                "layout ({conns:?}, split={split}, interactive={interactive:?}, egress={egress:?})"
            );
        }
    }

    #[test]
    fn shipped_defaults_build_eight_slots() {
        // 4 TCP + 2 interactive UDP shards + 2 bulk shards = 8 pool slots at
        // the shipped defaults; the runtime topology is sized against this
        // number.
        assert_eq!(
            planned_slot_count(
                crate::DEFAULT_QUIC_CONNS,
                true,
                crate::DEFAULT_UDP_INTERACTIVE_CONNS,
                crate::DEFAULT_UDP_EGRESS_CONNS,
            ),
            8
        );
    }
}
