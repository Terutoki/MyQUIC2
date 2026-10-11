//! Client connection pool: ConnSlot, ConnPool, EgressClass, shared constants.
use super::*;

/// The pool slot's published connection.
///
/// `ArcSwapOption` replaces the `tokio::sync::RwLock` this used to be: readers
/// (`wait_conn`, per TCP flow) are lock-free and, unlike `RwLock::read()`, can
/// never park a worker behind a writer, while the writers (dial / teardown, once
/// per connection generation) are lock-free too. The published value is
/// immutable, so a reader that wins the load keeps a consistent handle for as
/// long as it holds the guard.
pub(crate) type SharedConn = Arc<ArcSwapOption<quinn::Connection>>;
/// Bump the connection-generation counter. Split across two statements on
/// purpose: the borrow's read guard must drop before `send_replace` takes
/// the write lock, otherwise this self-deadlocks inside one statement.
pub(crate) fn bump_gen(tx: &watch::Sender<u64>) {
    let next = tx.borrow().wrapping_add(1);
    tx.send_replace(next);
}

/// One QUIC connection slot: the shared handle plus its generation channel.
/// Bumped on every swap so waiters sleep without polling and dispatchers drop
/// a stale connection without a per-packet timer.
#[derive(Clone, Debug)]
pub(crate) struct ConnSlot {
    pub(crate) shared: SharedConn,
    pub(crate) gen_tx: watch::Sender<u64>,
    pub(crate) gen_rx: watch::Receiver<u64>,
    /// Routing hint, maintained by the connection loop: `shared` holds a
    /// connection with no close reason. One atomic load where `close_reason()`
    /// takes quinn's connection-state mutex and clones the error, which
    /// `pick_tcp` would otherwise pay twice per TCP flow. `wait_conn` remains
    /// the authority that fails a flow fast.
    pub(crate) live: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnSlot {
    pub(crate) fn fresh() -> Self {
        let (gen_tx, gen_rx) = watch::channel(0u64);
        Self {
            shared: Arc::new(ArcSwapOption::const_empty()),
            gen_tx,
            gen_rx,
            live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live.load(std::sync::atomic::Ordering::Relaxed)
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
/// Failover is class-preserving. A dead bulk preference falls back to another
/// **bulk** slot first, and only a pool with no live bulk slot at all falls back
/// to slot 0. The first version of this function scanned `0..n` and therefore
/// took slot 0 whenever the round-robin preference happened to be the dead slot,
/// even with two live bulk slots available: any single bulk reconnect put
/// `1/(n-1)` of new bulk flows onto the interactive connection, i.e. it broke the
/// isolation precisely when a connection was already degraded. For a two-slot
/// pool the two rules coincide, so the old dual-pool truth table still holds.
/// When nothing is live the preference is kept, so `wait_conn` bounds the stall
/// and fails the flow fast instead of the pool inventing a slot that has no
/// connection behind it.
///
/// `live` describes the **TCP** slots only. The dedicated UDP egress slot lives
/// outside this range (see [`ConnPool::udp_slot`]) and is never a TCP target.
pub(crate) fn select_slot(pinned: bool, rr: usize, live: &[bool]) -> usize {
    debug_assert!(!live.is_empty(), "the pool always has at least one slot");
    let n = live.len();
    if n == 1 {
        return 0;
    }
    let preferred = if pinned { 0 } else { 1 + rr % (n - 1) };
    if live[preferred] {
        return preferred;
    }
    if pinned {
        // The interactive class has nowhere else to go: first live slot.
        return (0..n).find(|&i| live[i]).unwrap_or(preferred);
    }
    // Bulk stays in its own class while any bulk slot is live.
    if let Some(i) = (1..n).find(|&i| live[i]) {
        return i;
    }
    // Every bulk slot is down: share the interactive connection rather than
    // stall, but only if it is actually carrying traffic.
    if live[0] { 0 } else { preferred }
}

/// UDP egress class: which dedicated connection an association's datagrams ride.
///
/// The bulk connection carries large or steady flows (HTTP/3, WireGuard, big
/// transfers); the interactive one carries latency-sensitive flows. Without the
/// split every association shares one connection, and quinn drops the *newest*
/// datagram when that connection's 1 MB DATAGRAM send buffer fills and lets
/// every DATAGRAM jump the STREAM queue — so a bulk flow starves a
/// latency-sensitive one with no isolation at all.
///
/// An association is classified once, from its first datagram, and keeps its
/// class for life: switching mid-flow would move the server session to another
/// connection and change the source port the target sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EgressClass {
    /// An `interactive_ports` destination, or a first payload no larger than
    /// [`UDP_INTERACTIVE_MAX`] (STUN/DTLS/RTP-sized media, DNS, games).
    Interactive,
    /// Everything else.
    Bulk,
}

impl EgressClass {
    /// Number of classes, i.e. how many dedicated UDP slots `udp_split` dials.
    pub(crate) const COUNT: usize = 2;

    /// Slot offset within the UDP range.
    pub(crate) fn index(self) -> usize {
        match self {
            EgressClass::Interactive => 0,
            EgressClass::Bulk => 1,
        }
    }

    pub(crate) fn other(self) -> Self {
        match self {
            EgressClass::Interactive => EgressClass::Bulk,
            EgressClass::Bulk => EgressClass::Interactive,
        }
    }

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

/// The client's QUIC connection pool: `n` TCP slots indexed `0..n`, where
/// `n = ClientConf::conn_count()` (4 by default, `quic_conns`), plus one or two
/// **dedicated UDP egress slots** past the TCP range.
///
/// Slot 0 is the interactive connection: every port in `interactive_ports` rides
/// it, and it is the sole TCP slot when `quic_conns == 1`. The other TCP slots
/// absorb their share of the bulk TCP streams, so each cwnd holds ~1/n of the
/// queue instead of all of it. quinn 0.11 has no per-stream priority, so separate
/// congestion windows are the isolation mechanism.
///
/// The UDP slots are *additional*, not carved out of the TCP range: making UDP
/// independent must not cost TCP a congestion window, and `quic_conns` keeps its
/// documented meaning ("TCP pool size"). UDP and TCP on one connection is not a
/// theoretical concern — quinn fills every packet with queued DATAGRAM frames
/// *before* STREAM frames (`quinn-proto` `populate_packet`) and both share one
/// congestion window, so a bulk UDP flow (HTTP/3, WireGuard, video) starves the
/// TCP streams on the same connection, and a bulk TCP flow makes every UDP
/// datagram hit the 1 MiB datagram-send-buffer `Blocked` drop. One connection per
/// class is the only isolation QUIC gives without stream priorities.
///
/// With `udp_split` (the default) there are **two** UDP slots, one per
/// [`EgressClass`], so a bulk UDP flow's congestion window and DATAGRAM buffer
/// cannot starve a latency-sensitive flow either; `udp_split = false` restores
/// the single shared UDP slot and one fewer dial.
///
/// The slots live in a plain `Arc<Vec<ConnSlot>>` indexed by slot number. The
/// set is fixed at startup and never mutated, so a routing read is one indexed
/// load — no pin, no hash, no reclamation — and a `ConnPool` clone
/// (once per accepted SOCKS connection) stays one refcount bump.
#[derive(Clone, Debug)]
pub(crate) struct ConnPool {
    pub(crate) slots: Arc<Vec<ConnSlot>>,
    pub(crate) rr: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) interactive_ports: Arc<std::collections::HashSet<u16, foldhash::fast::RandomState>>,
    /// TCP slots: the routing range is `0..tcp_slots` (0 interactive, rest
    /// bulk). Never includes the UDP slots.
    pub(crate) tcp_slots: usize,
    /// Whether UDP egress is split into one dedicated connection per
    /// [`EgressClass`] (the default) or shares a single one.
    pub(crate) udp_split: bool,
    /// When set, UDP only ever uses its class's dedicated slot: if that
    /// connection is down the datagram is dropped (counted in
    /// `dgram_drops::NO_EGRESS`) instead of sharing a TCP connection's
    /// congestion window.
    pub(crate) udp_fail_closed: bool,
}

impl ConnPool {
    /// Build the process pool: `tcp` TCP slots indexed `0..tcp`, then one
    /// dedicated UDP slot per egress class (one with `udp_split` off).
    /// `tcp` is re-clamped here so no caller can build a pool wider than the
    /// stack liveness array the routing path uses to describe it.
    pub(crate) fn new(
        n: usize,
        interactive_ports: Vec<u16>,
        udp_fail_closed: bool,
        udp_split: bool,
    ) -> Self {
        let tcp = n.clamp(1, MAX_POOL_CONNS);
        let udp_slots = if udp_split { EgressClass::COUNT } else { 1 };
        let slots: Vec<ConnSlot> = (0..tcp + udp_slots).map(|_| ConnSlot::fresh()).collect();
        Self {
            slots: Arc::new(slots),
            rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            interactive_ports: Arc::new(interactive_ports.into_iter().collect()),
            tcp_slots: tcp,
            udp_split,
            udp_fail_closed,
        }
    }

    /// TCP slots; slot indices are `0..tcp_slots`.
    pub(crate) fn tcp_slots(&self) -> usize {
        self.tcp_slots
    }

    /// Every slot, TCP first then the UDP egress slots: the range to walk when
    /// spawning per-slot tasks or scanning the registry.
    pub(crate) fn slots_total(&self) -> usize {
        self.tcp_slots
            + if self.udp_split {
                EgressClass::COUNT
            } else {
                1
            }
    }

    /// The dedicated UDP egress slot for `class`. One past the TCP range (so
    /// never a TCP routing target); with `udp_split` off both classes map to
    /// the same slot.
    pub(crate) fn udp_slot(&self, class: EgressClass) -> usize {
        if self.udp_split {
            self.tcp_slots + class.index()
        } else {
            self.tcp_slots
        }
    }

    /// Egress class for a UDP association, from its first datagram: a known
    /// interactive port or a small first payload is the interactive class,
    /// everything else is bulk. See [`EgressClass`] and [`UDP_INTERACTIVE_MAX`].
    pub(crate) fn udp_class(&self, addr: &TargetAddrRef<'_>, first_payload: usize) -> EgressClass {
        let port = match *addr {
            TargetAddrRef::Ip(s) => s.port(),
            TargetAddrRef::Domain(_, p) => p,
        };
        if self.interactive_ports.contains(&port) || first_payload <= UDP_INTERACTIVE_MAX {
            EgressClass::Interactive
        } else {
            EgressClass::Bulk
        }
    }

    pub(crate) fn udp_fail_closed(&self) -> bool {
        self.udp_fail_closed
    }

    /// The slot at `i`. Slots are installed by `new` and never removed, so the
    /// index is always in range; out-of-range would mean the pool was not
    /// built by `new`.
    pub(crate) fn slot(&self, i: usize) -> ConnSlot {
        self.slots
            .get(i)
            .cloned()
            .expect("pool slots are installed at startup and never removed")
    }

    pub(crate) fn target_port(t: &TargetAddr) -> u16 {
        match t {
            TargetAddr::Ip(s) => s.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Index of the TCP slot a new TCP flow should use (see [`select_slot`]).
    ///
    /// `n` indexed liveness reads and a stack liveness array: no lock, no
    /// per-flow allocation, and no `close_reason()` (which takes quinn's
    /// connection-state mutex) — the maintained `live` bit is what routing
    /// reads, and `wait_conn` remains the authority that fails a flow fast.
    pub(crate) fn pick_tcp_index(&self, t: &TargetAddr) -> usize {
        let n = self.tcp_slots();
        debug_assert!(n <= MAX_POOL_CONNS);
        let mut live = [false; MAX_POOL_CONNS];
        for (i, l) in live[..n].iter_mut().enumerate() {
            *l = self.slots.get(i).is_some_and(ConnSlot::is_live);
        }
        let pinned = self.is_interactive(t);
        let rr = if pinned {
            0
        } else {
            self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        };
        let preferred = select_slot(pinned, rr, &live[..n]);
        // L2 stale-live failover: `live` is only a hint, so a slot whose QUIC
        // connection died in the window before the conn loop clears the bit
        // still reads true and `select_slot` keeps preferring it. `wait_conn`
        // would then sit on that slot's generation until the reconnect timeout
        // even with live bulk siblings available. Confirm the preference with
        // `close_reason()` and, when it holds a dead handle, re-pick once with
        // the same `rr` and that slot overlaid dead — class rules unchanged,
        // and an all-dead pool keeps the preference for the bounded stall.
        if live[preferred]
            && self
                .slots
                .get(preferred)
                .is_some_and(ConnSlot::holds_dead_handle)
        {
            live[preferred] = false;
            return select_slot(pinned, rr, &live[..n]);
        }
        preferred
    }

    /// Pick the slot for a new TCP flow. Returning flows stick to their slot
    /// for life, so nothing oscillates.
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
/// Exactly the dedicated bulk UDP class connection does. The TCP pool and
/// the *interactive* UDP class — whose whole point is latency-sensitive
/// flows — keep the tuned preset, as `build_transport_tuned_class`
/// documents. With `udp_split` off the two UDP classes share one slot,
/// which keeps the bulk preset it had before the per-class split (same
/// index as `udp_slot(Bulk)`).
pub(crate) fn slot_uses_bulk_preset(pool: &ConnPool, i: usize) -> bool {
    i == pool.udp_slot(EgressClass::Bulk)
}
