//! Client connection pool: ConnSlot, ConnPool, EgressClass, shared constants.
use super::*;

/// Width of the UDP egress range the egress cache and the pool's scratch
/// arrays must cover: the interactive slot plus the largest shard set.
pub(crate) const MAX_UDP_SLOTS: usize = 1 + MAX_UDP_EGRESS_CONNS;

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
    /// `max(2x keepalive, 8 s)` window expires. `0` means "no progress observed
    /// yet" and is treated as *not* stale (see [`ConnSlot::is_data_stale`]):
    /// the clear path resets it on death, so a restored live hint can never
    /// pair a fresh generation with the previous one's stale stamp.
    pub(crate) last_rx_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl ConnSlot {
    pub(crate) fn fresh() -> Self {
        let (gen_tx, gen_rx) = watch::channel(0u64);
        Self {
            shared: Arc::new(ArcSwapOption::const_empty()),
            gen_tx,
            gen_rx,
            live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rev2: Arc::new(arc_swap::ArcSwapOption::const_empty()),
            last_rx_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Publish the rev2 state for the connection this slot is about to carry.
    pub(crate) fn set_rev2(&self, rev2: Arc<ConnRev2>) {
        self.rev2.store(Some(rev2));
    }

    /// Current rev2 state, if the published connection is a rev2 generation.
    pub(crate) fn rev2(&self) -> Option<Arc<ConnRev2>> {
        self.rev2.load().as_ref().cloned()
    }

    /// Clear the rev2 state of the dead generation (connection-death path, in
    /// the same commit that clears `shared`).
    pub(crate) fn clear_rev2(&self) {
        self.rev2.store(None);
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
/// Derived from the same clamped keepalive the transport and the reconnect
/// loop's silence watchdog use, as the midpoint between the two bounds that
/// matter:
///
/// - **Lower bound — a healthy idle connection must never be rejected.** The
///   shipped 5 s keepalive makes the peer's ACKs and keepalive PINGs arrive at
///   least every keepalive interval, and the 1 Hz watchdog samples
///   `udp_rx.datagrams` after at most one `WATCHDOG_POLL` tick, so the stamp's
///   age on a healthy idle connection stays below `keepalive + poll`.
/// - **Upper bound — the gate must win while the slot is still live.** The
///   watchdog force-closes at `max(2x keepalive, 8 s)` (and needs a poll tick
///   to notice), so a threshold at or above that would never be reached while
///   the blackholed slot was still selectable.
///
/// The midpoint is provably strictly between the bounds for every legal
/// keepalive, 1..=300 s (locked by
/// `data_stale_threshold_sits_between_healthy_idle_and_watchdog`): it keeps the
/// healthy-idle case at least one poll tick of margin and still stops selecting
/// a blackholed slot minutes before the watchdog on large keepalives. With the
/// shipped 5 s keepalive (10 s watchdog window) it is 7 s, so a path that
/// blackholes stops receiving *new* flows ~3 s before the watchdog would even
/// notice, instead of accepting every CONNECT for the whole ~10 s window.
pub(crate) fn data_stale_threshold_ms(keep_alive_secs: u64) -> u64 {
    // Same clamp the transport applies (`clamp_keep_alive`); no warning here —
    // `main` clamped and validated the configured value already, and this is
    // also called from the tests' default constructor.
    let keepalive = keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    let watchdog_secs = watchdog_silence_secs(keepalive);
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
/// class's single slot (index 0) followed by `udp_egress_conns` **bulk** shards
/// (indices 1..), so a bulk UDP flow's congestion window and DATAGRAM buffer
/// cannot starve a latency-sensitive flow, and the bulk association population
/// spreads across several connections instead of funneling every bulk flow into
/// one connection's driver, dispatcher and server-side reader. A bulk
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
    pub(crate) interactive_ports: Arc<std::collections::HashSet<u16, foldhash::fast::RandomState>>,
    /// Destination ports forced to the **bulk** class whatever their first
    /// payload size (see [`ConnPool::udp_class`]). A VPN tunnel's first packet
    /// is small — WireGuard's handshake is 148 B — so the size heuristic alone
    /// would keep the whole tunnel on the single interactive connection next to
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
    /// Bulk UDP shards (indices `1..1 + bulk_shards` of the UDP range). 1 when
    /// `udp_split` is off, in which case the single shared slot is index 0.
    pub(crate) bulk_shards: usize,
    /// When set, UDP only ever uses dedicated UDP slots *of its own class*: if
    /// every one of them is down the datagram is dropped (counted in
    /// `dgram_drops::NO_EGRESS`) instead of sharing a TCP connection's
    /// congestion window.
    pub(crate) udp_fail_closed: bool,
    /// Selection-time path-health threshold in coarse-epoch milliseconds (see
    /// [`data_stale_threshold_ms`]): a `live` TCP slot whose published
    /// inbound-progress stamp ([`ConnSlot::last_rx_ms`]) is older than this is
    /// re-picked away from in [`ConnPool::pick_tcp_index`]. Computed once at
    /// startup from the clamped keepalive, so the routing path's check is two
    /// relaxed loads and a cached-clock read.
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
            udp_bulk_shards,
            // The shipped default keepalive (5 s) drives the selection-time
            // path-health threshold, so the routing table the existing tests
            // were written against keeps its shape. Tests that exercise the
            // gate set `pool.data_stale_ms` (and the slots' stamps) directly.
            data_stale_threshold_ms(5),
        )
    }

    /// Build the process pool: `tcp` TCP slots indexed `0..tcp`, then the UDP
    /// range — with `udp_split` on, the interactive class's slot at UDP index
    /// 0 plus `udp_bulk_shards` bulk shards at `1..`, clamped here so no
    /// caller can build a pool wider than the scratch arrays the routing and
    /// egress paths size from [`MAX_POOL_CONNS`] / [`MAX_UDP_SLOTS`].
    ///
    /// `bulk_ports` is the destination-port override list (see
    /// [`ConnPool::udp_class`]): ports classified as bulk whatever their first
    /// payload size. It only affects classification, never the slot layout.
    ///
    /// `data_stale_ms` is the selection-time path-health threshold (see
    /// [`data_stale_threshold_ms`]), derived by `main` from the same clamped
    /// keepalive as the transport and the watchdog.
    pub(crate) fn new_with_bulk_ports(
        n: usize,
        interactive_ports: Vec<u16>,
        bulk_ports: Vec<u16>,
        udp_fail_closed: bool,
        udp_split: bool,
        udp_bulk_shards: usize,
        data_stale_ms: u64,
    ) -> Self {
        let tcp = n.clamp(1, MAX_POOL_CONNS);
        let bulk_shards = if udp_split {
            udp_bulk_shards.clamp(1, MAX_UDP_EGRESS_CONNS)
        } else {
            1
        };
        let udp_slots = if udp_split { 1 + bulk_shards } else { 1 };
        let slots: Vec<ConnSlot> = (0..tcp + udp_slots).map(|_| ConnSlot::fresh()).collect();
        Self {
            slots: Arc::new(slots),
            rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            udp_rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            interactive_ports: Arc::new(interactive_ports.into_iter().collect()),
            bulk_ports: Arc::new(bulk_ports.into_iter().collect()),
            tcp_slots: tcp,
            udp_split,
            bulk_shards,
            udp_fail_closed,
            data_stale_ms,
        }
    }

    /// TCP slots; slot indices are `0..tcp_slots`.
    pub(crate) fn tcp_slots(&self) -> usize {
        self.tcp_slots
    }

    /// UDP-range width: the interactive slot plus the bulk shards with the
    /// split on, a single shared slot with it off.
    pub(crate) fn udp_slot_count(&self) -> usize {
        if self.udp_split {
            1 + self.bulk_shards
        } else {
            1
        }
    }

    /// Pool slot holding UDP-range index `index`.
    pub(crate) fn udp_global_slot(&self, index: usize) -> usize {
        self.tcp_slots + index
    }

    /// UDP-range indices carrying `class`. The interactive class is always the
    /// single index 0; the bulk class is `1..` with the split on and the
    /// shared index 0 with it off. This is the fail-closed boundary: a
    /// datagram may fail over inside its own class's set but never leaves it.
    pub(crate) fn udp_class_slots(&self, class: EgressClass) -> std::ops::Range<usize> {
        match class {
            EgressClass::Interactive => 0..1,
            EgressClass::Bulk if self.udp_split => 1..self.udp_slot_count(),
            EgressClass::Bulk => 0..1,
        }
    }

    /// Every slot, TCP first then the UDP range: the range to walk when
    /// spawning per-slot tasks or scanning the registry.
    pub(crate) fn slots_total(&self) -> usize {
        self.tcp_slots + self.udp_slot_count()
    }

    /// Bind `class` to a UDP-range index: the interactive class is always
    /// index 0; bulk associations rotate over the shards. Called once per
    /// association, from its first datagram — see [`UdpBind`].
    ///
    /// Rotation (not hashing): associations arrive in an arbitrary order and
    /// live for a long time, so a cursor spreads them as evenly as a hash
    /// would while staying one relaxed fetch_add and trivially testable.
    pub(crate) fn udp_bind(&self, class: EgressClass) -> UdpBind {
        let shard = match class {
            EgressClass::Interactive => 0,
            EgressClass::Bulk if self.udp_split => self
                .udp_rr
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            EgressClass::Bulk => 0,
        };
        self.udp_bind_shard(class, shard)
    }

    /// The explicit-shard form of [`ConnPool::udp_bind`]: `shard` is reduced
    /// modulo the class's shard count, so callers that carry their own stable
    /// association key (and tests) never need the cursor. Interactive
    /// bindings always resolve to index 0 — the class is never sharded.
    pub(crate) fn udp_bind_shard(&self, class: EgressClass, shard: usize) -> UdpBind {
        let index = match class {
            EgressClass::Interactive => 0,
            EgressClass::Bulk if self.udp_split => 1 + shard % self.bulk_shards,
            EgressClass::Bulk => 0,
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
    /// `n` indexed liveness reads and two stack arrays: no lock, no per-flow
    /// allocation, and no `close_reason()` per slot (which takes quinn's
    /// connection-state mutex) — the maintained `live` bit and the reconnect
    /// loop's inbound-progress stamp are what routing reads, and `wait_conn`
    /// remains the authority that fails a flow fast.
    ///
    /// Two failovers, each a single re-pick over the same class rules, so a
    /// flow can never oscillate and an all-unusable pool keeps the preference
    /// for the bounded `wait_conn` stall:
    ///
    /// 1. **Dead handle (L2)**: `live` is only a hint, so a slot whose QUIC
    ///    connection died in the window before the conn loop clears the bit
    ///    still reads true; `close_reason()` is the authority.
    /// 2. **Path health (L3)**: a *blackholed* connection has no close reason
    ///    and still reads live — NAT rebind, Wi-Fi handover, SIGKILLed peer —
    ///    so `close_reason()` cannot see it until the silence watchdog fires
    ///    (`max(2x keepalive, 8 s)` later). Its published inbound-progress
    ///    stamp goes stale first (see [`ConnSlot::is_data_stale`] and
    ///    [`data_stale_threshold_ms`]), so a `live` preference whose progress
    ///    is stale is re-picked over the live-and-fresh set. This changes
    ///    *selection only*: the slot stays live, the watchdog stays the
    ///    authority that force-closes and redials, and nothing here can trigger
    ///    a reconnect.
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
        let preferred = select_slot(pinned, rr, &live[..n]);
        // L2 stale-live failover: a slot whose QUIC connection died in the
        // window before the conn loop clears the bit still reads true and
        // `select_slot` keeps preferring it. `wait_conn` would then sit on that
        // slot's generation until the reconnect timeout even with live bulk
        // siblings available. Confirm the preference with `close_reason()` and,
        // when it holds a dead handle, re-pick once with the same `rr` and that
        // slot overlaid dead — class rules unchanged, and an all-dead pool
        // keeps the preference for the bounded stall.
        if live[preferred]
            && self
                .slots
                .get(preferred)
                .is_some_and(ConnSlot::holds_dead_handle)
        {
            live[preferred] = false;
            return select_slot(pinned, rr, &live[..n]);
        }
        // L3 path-health gate: the preference is live but its inbound progress
        // has been frozen for the threshold — a blackholed path that
        // `close_reason()` cannot see yet. Re-pick once over the
        // live-and-fresh set with the same `rr` and class rules. When every
        // live slot is stale (a whole-pool outage, or a stalled clock) keep the
        // preference: a stale sibling would stall just the same, and
        // `wait_conn` bounds the wait. Nothing is written here — the watchdog
        // remains the only authority that closes and redials a slot.
        if live[preferred] && !fresh[preferred] && fresh[..n].iter().any(|&f| f) {
            return select_slot(pinned, rr, &fresh[..n]);
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
