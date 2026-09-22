//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-client.toml")]
    config: String,
}

/// The pool slot's published connection.
///
/// `ArcSwapOption` replaces the `tokio::sync::RwLock` this used to be: readers
/// (`wait_conn`, per TCP flow) are lock-free and, unlike `RwLock::read()`, can
/// never park a worker behind a writer, while the writers (dial / teardown, once
/// per connection generation) are lock-free too. The published value is
/// immutable, so a reader that wins the load keeps a consistent handle for as
/// long as it holds the guard.
type SharedConn = Arc<ArcSwapOption<quinn::Connection>>;

/// Must cover the server's worst-case dial path:
/// 5s header read + 3s DNS permit + 5s DNS lookup + 2s dial permit +
/// 4s TCP connect + scheduling jitter, with margin for a loaded host.
const TCP_DIAL_ACK_TIMEOUT: Duration = Duration::from_secs(25);

/// Egress freshness window in ms, mirroring the old 1 s `EGRESS_REFRESH`.
/// Stored as `mono_millis()` so the relay loop reuses its single per-packet
/// clock read instead of taking a second `Instant::now()` per datagram.
const EGRESS_REFRESH_MS: u64 = 1000;

/// Process-wide caps on client-side resources. Without these a local or LAN
/// peer can spawn unbounded tasks / relay sockets (each with 512 KB kernel
/// buffers) and exhaust fds and memory on the proxy host.
const MAX_SOCKS_CONNS: usize = 8192;
/// Server-side live sessions one client connection can keep. The server's
/// session table evicts as soon as a shard crosses `LOCAL_SESS_MAX / SESS_SHARDS`
/// and settles back to `LOCAL_SESS_TARGET / SESS_SHARDS`, i.e.
/// `LOCAL_SESS_TARGET = LOCAL_SESS_MAX - 64 = 4032` sessions per connection
/// (`myquic2-server.rs`). A client that admits more concurrent associations than
/// the server will keep alive loses live flows at the ceiling, so this cap is
/// aligned to that target rather than to `LOCAL_SESS_MAX`: all of a client's UDP
/// associations ride one egress connection (the dedicated UDP slot), so the
/// per-connection target is exactly this client's ceiling.
const MAX_UDP_ASSOCS: usize = 4032;

fn socks_conn_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_SOCKS_CONNS)))
}

/// Bump the connection-generation counter. Split across two statements on
/// purpose: the borrow's read guard must drop before `send_replace` takes
/// the write lock, otherwise this self-deadlocks inside one statement.
fn bump_gen(tx: &watch::Sender<u64>) {
    let next = tx.borrow().wrapping_add(1);
    tx.send_replace(next);
}

/// One QUIC connection slot: the shared handle plus its generation channel.
/// Bumped on every swap so waiters sleep without polling and dispatchers drop
/// a stale connection without a per-packet timer.
#[derive(Clone, Debug)]
struct ConnSlot {
    shared: SharedConn,
    gen_tx: watch::Sender<u64>,
    gen_rx: watch::Receiver<u64>,
    /// Routing hint, maintained by the connection loop: `shared` holds a
    /// connection with no close reason. One atomic load where `close_reason()`
    /// takes quinn's connection-state mutex and clones the error, which
    /// `pick_tcp` would otherwise pay twice per TCP flow. `wait_conn` remains
    /// the authority that fails a flow fast.
    live: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnSlot {
    fn fresh() -> Self {
        let (gen_tx, gen_rx) = watch::channel(0u64);
        Self {
            shared: Arc::new(ArcSwapOption::const_empty()),
            gen_tx,
            gen_rx,
            live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn is_live(&self) -> bool {
        self.live.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Publish `conn` as this slot's connection.
    fn publish(&self, conn: &quinn::Connection) {
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
    /// result is committed, so `cleared` reflects the committed decision.
    fn clear_if(&self, conn: &quinn::Connection) -> bool {
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

    /// Wait for a live connection, waking on a generation bump or the deadline.
    ///
    /// The maintained `live` bit is trusted in the common case: it is one
    /// atomic load where `close_reason()` takes quinn's connection-state mutex
    /// and clones the error. `close_reason()` is still the authority when the
    /// bit is false, which is the accepted race window before the reconnect
    /// loop clears `shared`.
    async fn wait_conn(
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
            if let Some(c) = g.as_ref() {
                if self.is_live() || c.close_reason().is_none() {
                    return Ok((**c).clone());
                }
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
fn select_slot(pinned: bool, rr: usize, live: &[bool]) -> usize {
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
    if live[0] {
        0
    } else {
        preferred
    }
}

/// The client's QUIC connection pool: `n` TCP slots indexed `0..n`, where
/// `n = ClientConf::conn_count()` (4 by default, `quic_conns`), plus one
/// **dedicated UDP egress slot** at index `n`.
///
/// Slot 0 is the interactive connection: every port in `interactive_ports` rides
/// it, and it is the sole TCP slot when `quic_conns == 1`. The other TCP slots
/// absorb their share of the bulk TCP streams, so each cwnd holds ~1/n of the
/// queue instead of all of it. quinn 0.11 has no per-stream priority, so separate
/// congestion windows are the isolation mechanism.
///
/// The UDP slot is *additional*, not carved out of the TCP range: making UDP
/// independent must not cost TCP a congestion window, and `quic_conns` keeps its
/// documented meaning ("TCP pool size"). UDP and TCP on one connection is not a
/// theoretical concern — quinn fills every packet with queued DATAGRAM frames
/// *before* STREAM frames (`quinn-proto` `populate_packet`) and both share one
/// congestion window, so a bulk UDP flow (HTTP/3, WireGuard, video) starves the
/// TCP streams on the same connection, and a bulk TCP flow makes every UDP
/// datagram hit the 1 MiB datagram-send-buffer `Blocked` drop. One connection per
/// class is the only isolation QUIC gives without stream priorities.
///
/// The slots live in a lock-free `papaya::HashMap` keyed by slot index. Three
/// properties of this pool are what make that a fit rather than decoration:
///
/// - Slots are inserted once at startup and never removed, so a routing read is
///   a pin plus a hash lookup on an integer key, and papaya's reclamation never
///   has a retired value to collect on the per-flow path.
/// - The `Arc` is load-bearing: `papaya::HashMap`'s own `Clone` deep-copies the
///   table, and this pool is cloned once per accepted SOCKS connection. Behind
///   the `Arc` a clone is one refcount bump.
/// - A pin guard is `!Send`, so a future edit that holds one across an `.await`
///   fails to compile instead of silently pinning a runtime thread.
#[derive(Clone, Debug)]
struct ConnPool {
    slots: Arc<papaya::HashMap<usize, ConnSlot>>,
    rr: Arc<std::sync::atomic::AtomicUsize>,
    interactive_ports: Arc<std::collections::HashSet<u16>>,
    /// TCP slots: the routing range is `0..tcp_slots` (0 interactive, rest
    /// bulk). Never includes the UDP slot.
    tcp_slots: usize,
    /// Index of the dedicated UDP egress slot, one past the TCP range.
    udp_slot: usize,
    /// When set, UDP only ever uses `udp_slot`: if that connection is down the
    /// datagram is dropped (counted in `dgram_drops::NO_EGRESS`) instead of
    /// sharing a TCP connection's congestion window.
    udp_fail_closed: bool,
}

impl ConnPool {
    /// Build the process pool: `tcp + 1` fresh (unconnected) slots — `tcp` TCP
    /// slots indexed `0..tcp`, then the dedicated UDP slot at index `tcp`.
    /// `tcp` is re-clamped here so no caller can build a pool wider than the
    /// stack liveness array the routing path uses to describe it.
    fn new(n: usize, interactive_ports: Vec<u16>, udp_fail_closed: bool) -> Self {
        let tcp = n.clamp(1, MAX_POOL_CONNS);
        let slots = papaya::HashMap::with_capacity(tcp + 1);
        {
            let g = slots.pin();
            for i in 0..=tcp {
                g.insert(i, ConnSlot::fresh());
            }
        }
        Self {
            slots: Arc::new(slots),
            rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            interactive_ports: Arc::new(interactive_ports.into_iter().collect()),
            tcp_slots: tcp,
            udp_slot: tcp,
            udp_fail_closed,
        }
    }

    /// TCP slots; slot indices are `0..tcp_slots`.
    fn tcp_slots(&self) -> usize {
        self.tcp_slots
    }

    /// Every slot, TCP first then the UDP egress slot: the range to walk when
    /// spawning per-slot tasks or scanning the registry.
    fn slots_total(&self) -> usize {
        self.tcp_slots + 1
    }

    /// The dedicated UDP egress slot. Equal to `tcp_slots`, i.e. outside every
    /// TCP routing range by construction.
    fn udp_slot(&self) -> usize {
        self.udp_slot
    }

    fn udp_fail_closed(&self) -> bool {
        self.udp_fail_closed
    }

    /// The slot at `i`. Slots are installed by `new` and never removed, so the
    /// key is always present; a miss would mean the pool was not built by
    /// `new`.
    fn slot(&self, i: usize) -> ConnSlot {
        self.slots
            .pin()
            .get(&i)
            .cloned()
            .expect("pool slots are installed at startup and never removed")
    }

    fn target_port(t: &TargetAddr) -> u16 {
        match t {
            TargetAddr::Ip(s) => s.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Index of the TCP slot a new TCP flow should use (see [`select_slot`]).
    ///
    /// One pin, `n` lookups and a stack liveness array: no lock, no per-flow
    /// allocation, and no `close_reason()` (which takes quinn's
    /// connection-state mutex) — the maintained `live` bit is what routing
    /// reads, and `wait_conn` remains the authority that fails a flow fast.
    fn pick_tcp_index(&self, t: &TargetAddr) -> usize {
        let n = self.tcp_slots();
        debug_assert!(n <= MAX_POOL_CONNS);
        let g = self.slots.pin();
        let mut live = [false; MAX_POOL_CONNS];
        for (i, l) in live[..n].iter_mut().enumerate() {
            *l = g.get(&i).is_some_and(ConnSlot::is_live);
        }
        let pinned = self.is_interactive(t);
        let rr = if pinned {
            0
        } else {
            self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        };
        select_slot(pinned, rr, &live[..n])
    }

    /// Pick the slot for a new TCP flow. Returning flows stick to their slot
    /// for life, so nothing oscillates.
    fn pick_tcp(&self, t: &TargetAddr) -> ConnSlot {
        self.slot(self.pick_tcp_index(t))
    }

    fn is_interactive(&self, t: &TargetAddr) -> bool {
        self.interactive_ports.contains(&Self::target_port(t))
    }
}

/// Thread-local single-slot memo for the shared egress handle.
///
/// The relay loop calls [`SharedEgress::with_fresh`] per outbound datagram.
/// A `quinn::Connection` clone is an Arc refcount RMW on a cache line shared
/// with quinn's connection driver, so doing it per packet ping-pongs that line
/// across every relay task. The memo pins one clone per worker thread and
/// serves it with no lock and no refcount traffic; a generation bump (any
/// successful `cached` mutation) invalidates it without touching other threads.
struct EgressMemo {
    gen: u64,
    conn: quinn::Connection,
    limit: usize,
    stamp_ms: u64,
}

thread_local! {
    static EGRESS_MEMO: std::cell::RefCell<Option<EgressMemo>> =
        const { std::cell::RefCell::new(None) };
}

/// The process-wide egress handle plus the freshness stamp it was published
/// with. Immutable once published, so a reader can hold it without a lock.
#[derive(Debug)]
struct EgressCache {
    conn: quinn::Connection,
    limit: usize,
    stamp_ms: u64,
    /// The pool slot this handle came from. Recorded so the fail-closed UDP
    /// policy can assert (and re-check) that the cache never serves a TCP
    /// connection, and so the 60 s line can name which connection egress is on.
    slot: usize,
}

#[derive(Debug, Default)]
struct SharedEgress {
    /// `ArcSwapOption` replaces the `RwLock` this used to be. The old code used
    /// `try_write` and treated a lost publish as "stamp 0" — a memo that could
    /// never be served as fresh, so the next packet retried the whole refresh.
    /// `ArcSwap::store` is lock-free and always commits, which deletes that
    /// whole failure mode: every publish lands and carries a real stamp.
    cached: ArcSwapOption<EgressCache>,
    warned: std::sync::atomic::AtomicBool,
    /// Single-flight refresh gate: only one association task pays the two
    /// quinn locks (`close_reason` + `max_datagram_size`) per refresh window.
    /// The rest fail fast (UDP drop semantics) instead of herding on the same
    /// mutexes the moment the 1 s window expires on 4096 associations at once.
    refreshing: std::sync::atomic::AtomicBool,
    /// Bumped (Release) after every mutation of `cached` — the publish in
    /// `refresh_global` and the clear in `invalidate`. With `ArcSwap` a mutation
    /// can no longer be lost, so this is bumped exactly once per mutation and
    /// never spuriously. The thread-local memo tags itself with the generation
    /// observed *before* its cached read, so a mutation concurrent with an
    /// acquire invalidates every thread's memo at once without a lock or a
    /// per-thread scan.
    generation: std::sync::atomic::AtomicU64,
}

impl SharedEgress {
    /// Serve the memoized handle when it is current and still fresh.
    ///
    /// `f` runs synchronously against the borrowed handle, so the hot path
    /// costs one generation load and one `RefCell` borrow — no Arc RMW, no
    /// quinn lock. A miss leaves the memo untouched; the caller re-acquires.
    fn with_fresh<R>(
        &self,
        now_ms: u64,
        f: impl FnOnce(&quinn::Connection, usize) -> R,
    ) -> Option<R> {
        let gen = self.generation.load(std::sync::atomic::Ordering::Acquire);
        EGRESS_MEMO.with(|slot| {
            let memo = slot.borrow();
            let entry = memo.as_ref()?;
            if entry.gen == gen && now_ms.saturating_sub(entry.stamp_ms) < EGRESS_REFRESH_MS {
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
    fn memo_store(&self, gen: u64, conn: &quinn::Connection, limit: usize, stamp_ms: u64) {
        EGRESS_MEMO.with(|slot| {
            *slot.borrow_mut() = Some(EgressMemo {
                gen,
                conn: conn.clone(),
                limit,
                stamp_ms,
            });
        });
    }

    /// Drop this thread's memo entry (releasing a stale `Connection` promptly
    /// when the cache has no usable handle at all).
    fn memo_clear(&self) {
        EGRESS_MEMO.with(|slot| *slot.borrow_mut() = None);
    }

    /// Resolve a usable `(connection, limit, stamp)` from the process-wide
    /// cache, refreshing through the single-flight gate when the cached handle
    /// is expired. Returns `None` only when no handle is available, in which
    /// case the caller drops the datagram (UDP semantics) and counts it in
    /// `dgram_drops::NO_EGRESS`.
    fn acquire(&self, pool: &ConnPool, now_ms: u64) -> Option<(quinn::Connection, usize, u64)> {
        if let Some(c) = self.cached.load().as_ref() {
            // A fail-closed pool only ever publishes the UDP slot (see
            // `egress_order`), so this is an invariant check, not a filter.
            debug_assert!(
                !pool.udp_fail_closed() || c.slot == pool.udp_slot(),
                "fail-closed egress must never cache a shared TCP slot"
            );
            if now_ms.saturating_sub(c.stamp_ms) < EGRESS_REFRESH_MS {
                return Some((c.conn.clone(), c.limit, c.stamp_ms));
            }
        }
        if let Some((c, m, stamp)) = self.refresh_global(pool, now_ms) {
            return Some((c, m, stamp));
        }
        // Stale-while-revalidate: an expired (or contended) handle is reused
        // optimistically with no liveness check. A dead one surfaces as
        // `ConnectionLost` on send and invalidates the cache there, so the
        // expiry window costs zero quinn locks.
        if let Some(c) = self.cached.load().as_ref() {
            return Some((c.conn.clone(), c.limit, c.stamp_ms));
        }
        self.memo_clear();
        None
    }

    /// Slot scan order for the UDP egress: the dedicated UDP slot first, then
    /// the interactive TCP slot, then the bulk TCP slots in index order.
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
    /// single-flight winner, and `MAX_POOL_CONNS + 1` bounds it.
    fn egress_order(&self, pool: &ConnPool) -> ([usize; MAX_POOL_CONNS + 1], usize) {
        let mut order = [0usize; MAX_POOL_CONNS + 1];
        let udp = pool.udp_slot();
        order[0] = udp;
        let mut k = 1;
        if !pool.udp_fail_closed() {
            for i in 0..pool.slots_total() {
                if i != udp {
                    order[k] = i;
                    k += 1;
                }
            }
        }
        (order, k)
    }

    /// Refresh `cached` under the single-flight gate. Returns the fresh handle
    /// and the stamp to tag it with, which is always `now_ms`: `ArcSwap::store`
    /// cannot lose, so there is no unpublished-handle case to keep cold.
    fn refresh_global(
        &self,
        pool: &ConnPool,
        now_ms: u64,
    ) -> Option<(quinn::Connection, usize, u64)> {
        // Single-flight: a loser drops fast (UDP semantics) instead of paying
        // the quinn locks while a winner is already refreshing. The losing
        // datagram is counted in `dgram_drops::NO_EGRESS` by the caller.
        if self
            .refreshing
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        struct RefreshGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for RefreshGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _guard = RefreshGuard(&self.refreshing);
        // Stickiness first: while the cached connection is still usable, keep it
        // and only re-read its DATAGRAM budget (the path MTU can have changed
        // under it). Re-running the slot scan here instead is what used to move
        // every UDP association back onto the interactive slot the moment that
        // slot recovered — a second target-side source-port change (and a new
        // server-side session) for a flow that had already failed over, i.e.
        // exactly the flap-back churn the docs promise not to do. A fail-closed
        // pool can only have published the UDP slot, so stickiness cannot keep it
        // on a TCP connection.
        let current = self.cached.load();
        if let Some(c) = current.as_ref() {
            if c.conn.close_reason().is_none() {
                if let Some(m) = c.conn.max_datagram_size() {
                    self.cached.store(Some(Arc::new(EgressCache {
                        conn: c.conn.clone(),
                        limit: m,
                        stamp_ms: now_ms,
                        slot: c.slot,
                    })));
                    self.generation
                        .fetch_add(1, std::sync::atomic::Ordering::Release);
                    return Some((c.conn.clone(), m, now_ms));
                }
            }
        }
        drop(current);
        // The cached connection is gone (or lost DATAGRAM support): walk the
        // egress order above.
        let (order, k) = self.egress_order(pool);
        let slots = pool.slots.pin();
        for &i in &order[..k] {
            let Some(slot) = slots.get(&i) else { continue };
            // Lock-free read: no `try_read` that can fail, so a refresh can
            // never be skipped just because a reconnect is publishing.
            let g = slot.shared.load();
            match g.as_ref() {
                Some(c) if c.close_reason().is_none() => match c.max_datagram_size() {
                    Some(m) => {
                        // Lock-free publish: cannot lose, cannot park the
                        // executor, and always carries a real stamp.
                        self.cached.store(Some(Arc::new(EgressCache {
                            conn: (**c).clone(),
                            limit: m,
                            stamp_ms: now_ms,
                            slot: i,
                        })));
                        self.generation
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

    fn invalidate(&self) {
        self.cached.store(None);
        // The clear always lands, so the memo invalidation is never skipped.
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
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
    fn refresh_budget(&self) {
        let current = self.cached.load();
        let Some(c) = current.as_ref() else {
            return;
        };
        let Some(m) = c.conn.max_datagram_size() else {
            return;
        };
        if m == c.limit {
            return;
        }
        self.cached.store(Some(Arc::new(EgressCache {
            conn: c.conn.clone(),
            limit: m,
            stamp_ms: coarse_millis(),
            slot: c.slot,
        })));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

/// Routes inbound QUIC DATAGRAMs to their UDP ASSOCIATE by sess_id.
/// One dispatcher serves the whole process across reconnects; subscriptions
/// die with their association, so no immortal task can steal another's packets.
/// The table is sharded because the dispatcher reads it for every inbound
/// DATAGRAM: a single RwLock there is a cross-core cache-line bottleneck.
const HUB_SHARDS: usize = 32;

/// One live UDP association, as the dispatchers see it.
///
/// This replaces the per-association `mpsc::Sender<Bytes>` the dispatcher used
/// to push inbound datagrams into. The dispatcher now builds the SOCKS5 reply
/// header and writes the relay socket itself, so an entry carries the socket and
/// the app address rather than a queue. Three consequences are deliberate:
///
/// - The per-association reply task is gone. So is its 256-deep queue and the
///   `TrySendError::Full` arm that dropped datagrams when it filled — an entire
///   loss mode disappears rather than being tuned.
/// - The queue hop measured 52-57 ns per datagram (`hotpath_bench chan`). The
///   dispatcher pays that back as the `send_to` it now performs inline, on a
///   stage that is single-threaded per connection either way, because one
///   `read_datagram` stream admits exactly one poller.
/// - `alive` replaces the `Closed` signal the dropped receiver used to provide,
///   so a dispatcher stops writing into a socket nobody reads as soon as the
///   association exits, instead of holding the socket open until its cache slot
///   is recycled by a collision.
///
/// Fragment reassembly deliberately does *not* live here. `DgramReassembler` is
/// already keyed by `(sess, id)` and is therefore connection-wide — the server
/// has always used exactly one per connection — so the dispatcher owns a single
/// reassembler and no per-session mutable state exists anywhere.
struct AssocEntry {
    relay: Arc<tokio::net::UdpSocket>,
    /// The app's source address, published by the relay loop when it first sees
    /// a datagram from the app, read by whichever dispatcher has a reply to
    /// deliver. Lock-free in both directions.
    app: ArcSwapOption<SocketAddr>,
    /// Cleared by the association as it exits.
    alive: std::sync::atomic::AtomicBool,
    /// Inbound activity, as one bit: set (relaxed) by whichever dispatcher
    /// writes a reply to this association, consumed by the association's own
    /// idle tick.
    ///
    /// This exists so the **reply path never reads a clock** — true for every
    /// unfragmented datagram, which is the steady state. (A *fragmented* reply
    /// still reads one, in `dispatch_one`: `DgramReassembler::push` takes its
    /// timestamp as an argument because the 2 s reassembly timeout genuinely
    /// wants sub-second resolution, so the caller samples `mono_millis` per
    /// fragment frame.) Stamping `last` directly per reply cost a
    /// `clock_gettime` through the vDSO (~25 ns) on every datagram, forever, for
    /// a signal that only has to prove "something happened in the last 180 s" —
    /// and the tick that folds this flag into the stamp already reads a clock
    /// once per [`ASSOC_IDLE_TICK_SECS`]. The store is idempotent and has one
    /// writer per association in steady state (a session's replies arrive on the
    /// one connection that carried its datagrams), so it cannot lose an update
    /// the way a read-modify-write could, and it never shares a cache line's
    /// write ownership per packet with the app direction, whose stamp stays
    /// throttled to 1 Hz.
    replied: std::sync::atomic::AtomicBool,
    /// Last activity stamp ([`coarse_millis`] epoch — the same clock as
    /// [`mono_millis`], sampled once per second). Written by the association
    /// task only: the relay loop on an app datagram (throttled to
    /// [`ASSOC_TOUCH_INTERVAL_MS`]), the idle tick when it consumes [`Self::replied`],
    /// and the SOCKS control-readiness branch.
    ///
    /// The reply direction has to feed it — that is what [`Self::replied`] and
    /// [`Self::idle_since_tick`] are for. It used to live as a local in the relay
    /// loop fed only by app-side traffic, so an association whose flow was
    /// receive-only after the first request (RTSP/RTP after SETUP, a market-data
    /// or log subscription, anything NAT-kept-alive by the far end) was reaped at
    /// 180 s while the server's own session — whose reader *does* refresh on
    /// target replies (`sess_reader_task`) — was still live. The app then lost a
    /// working flow, which is the same "evicted a session the client was using"
    /// failure the server-side sweeper was fixed for.
    last: std::sync::atomic::AtomicU64,
}

/// The association's own idle cadence and the deadline it is checked against.
///
/// The reply direction's activity bit is consumed on this tick, so the tick
/// period is also the worst-case staleness of `last`. It must stay far below the
/// deadline (18x here) or a receive-only flow could be reaped while replies are
/// still arriving. The reap *schedule* is unchanged by folding the flag at the
/// tick instead of stamping per reply: the flag is consumed before the deadline
/// is evaluated, and the association is only reported idle when no tick in the
/// preceding `ASSOC_IDLE_MS` observed activity.
const ASSOC_IDLE_TICK_SECS: u64 = 10;
const ASSOC_IDLE_MS: u64 = 180_000;

/// App-direction stamp throttle. One relaxed load plus one store per second,
/// not per datagram: the relay loop reads a clock anyway (the egress memo's
/// freshness stamp needs it), but the shared stamp must not be rewritten per
/// packet or it would steal the cache line from the dispatcher's [`AssocEntry::replied`]
/// store on every datagram.
const ASSOC_TOUCH_INTERVAL_MS: u64 = 1000;

impl AssocEntry {
    fn new(relay: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            relay,
            app: ArcSwapOption::const_empty(),
            alive: std::sync::atomic::AtomicBool::new(true),
            replied: std::sync::atomic::AtomicBool::new(false),
            last: std::sync::atomic::AtomicU64::new(mono_millis()),
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that a reply was written. One relaxed store — no clock read.
    fn mark_replied(&self) {
        self.replied
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// One idle tick: fold any reply activity into the stamp, then report whether
    /// the association has gone idle.
    ///
    /// Folding here is exact rather than approximate. `replied` is consumed
    /// *before* the deadline is evaluated, so an association whose replies are
    /// still arriving can never be reported idle; and because the flag is read at
    /// the tick after the last reply, `last` is stamped at or after that reply —
    /// the reap can only be later than an exactly-stamped association's, never
    /// earlier. Called from the association task, the only writer of `last` on
    /// the reply side.
    fn idle_since_tick(&self, now_ms: u64, idle_limit_ms: u64) -> bool {
        if self
            .replied
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            self.last
                .store(now_ms, std::sync::atomic::Ordering::Relaxed);
        }
        self.idle_ms(now_ms) >= idle_limit_ms
    }

    /// Refresh the idle stamp (app direction), at most once per
    /// [`ASSOC_TOUCH_INTERVAL_MS`].
    fn touch(&self, now_ms: u64) {
        if now_ms.saturating_sub(self.last.load(std::sync::atomic::Ordering::Relaxed))
            >= ASSOC_TOUCH_INTERVAL_MS
        {
            self.last
                .store(now_ms, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// The app's address, if the app has sent anything yet. The returned borrow
    /// means no refcount traffic on the per-datagram path.
    fn app(&self) -> Option<SocketAddr> {
        self.app.load().as_ref().map(|a| **a)
    }
}

/// Clears an entry's liveness bit on every exit path out of the association,
/// including `?` early returns, so dispatchers drop their cached handle promptly
/// instead of writing replies into a socket nobody reads.
struct AliveGuard(Arc<AssocEntry>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0
            .alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Returns an `UdpHub` reservation on every exit path out of
/// `handle_udp_associate`, including unwinding.
///
/// A bare `hub.release(sess)` after the `.await` covers `Ok` and `Err` returns
/// but not a panic in the association body: unwinding skips it, and the reserved
/// process-wide slot plus the shard's strong `Arc<AssocEntry>` (the relay
/// socket's last owner) then survive every later sweep, because nothing else
/// removes a hub entry. `len` decrementing exactly once per `alloc_sess` is the
/// invariant the `MAX_UDP_ASSOCS` cap is documented on, so a single leaked slot
/// is a permanent budget loss and the entry is a permanent fd.
struct SessReservation<'a> {
    hub: &'a UdpHub,
    sess: u32,
}

impl Drop for SessReservation<'_> {
    fn drop(&mut self) {
        self.hub.release(self.sess);
    }
}

struct UdpHub {
    /// One immutable map per shard, published through `ArcSwap`.
    ///
    /// This used to be `RwLock<HashMap>` read with `try_lock_read`, whose
    /// failure mode was a **silently dropped inbound datagram** whenever the
    /// read lock was momentarily held by an association being created or torn
    /// down. `ArcSwap::load` cannot fail, so the dispatcher's lookup is now
    /// lock-free *and* total: a miss means the session genuinely has no
    /// subscription, never that a lock was busy.
    ///
    /// Writes are clone-on-publish (`rcu`), which is affordable because they
    /// happen once per association open / close and each shard holds at most
    /// `MAX_UDP_ASSOCS / HUB_SHARDS` entries.
    subs: Vec<arc_swap::ArcSwap<HashMap<u32, Arc<AssocEntry>>>>,
    next: std::sync::atomic::AtomicU32,
    /// Exact process-wide association count across all shards.
    len: std::sync::atomic::AtomicUsize,
}

impl UdpHub {
    fn new() -> Self {
        Self {
            subs: (0..HUB_SHARDS)
                .map(|_| arc_swap::ArcSwap::from_pointee(HashMap::new()))
                .collect(),
            next: std::sync::atomic::AtomicU32::new(1),
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn shard(&self, s: u32) -> &arc_swap::ArcSwap<HashMap<u32, Arc<AssocEntry>>> {
        &self.subs[(s as usize) % HUB_SHARDS]
    }

    /// Reserves a process-wide association slot and a free session id. `None`
    /// when the cap is reached (caller replies SOCKS5 REP=0x01).
    ///
    /// Allocation and publication are split because the relay socket has to
    /// exist before an entry can name it: the id is reserved here, the socket is
    /// created by the association, and [`Self::publish`] installs the entry. The
    /// caller must pair every successful `alloc_sess` with exactly one
    /// [`Self::release`] — [`SessReservation`] is what enforces it — including
    /// when it fails before publishing.
    ///
    /// **Why a bare `u32` counter cannot misroute after it wraps.** An id is only
    /// dangerous once reused while a reply for its previous owner is still in
    /// flight, and the reuse distance here is fixed by the counter, not by luck:
    /// `next` is a single `fetch_add`, so an id is handed out again only after
    /// `u32::MAX - 2` other allocations (0 and `u32::MAX` are skipped). A reply
    /// lives for the RTT plus the server's session lifetime, seconds at most, so
    /// reaching the wrap needs on the order of 4.3e9 associations inside that
    /// window — more than a million associations per second sustained for an
    /// hour, against a 4032-association cap. The live-id check below (`contains_key`)
    /// covers the remaining case where the previous owner is still published.
    fn alloc_sess(&self) -> Option<u32> {
        use std::sync::atomic::Ordering;
        // Reserve a global slot first so the cap stays exact across shards.
        loop {
            let cur = self.len.load(Ordering::Relaxed);
            if cur >= MAX_UDP_ASSOCS {
                return None;
            }
            if self
                .len
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        loop {
            let s = self.next.fetch_add(1, Ordering::Relaxed);
            // 0 is reserved; skip it and avoid reusing a live id after wraparound.
            if s == 0 || s == u32::MAX {
                continue;
            }
            if self.shard(s).load().contains_key(&s) {
                continue;
            }
            return Some(s);
        }
    }

    /// Installs an association's reply endpoint under its reserved id.
    ///
    /// `rcu` re-runs against the latest map, so two associations publishing to
    /// the same shard concurrently cannot lose each other's insert (a
    /// load-clone-store would).
    fn publish(&self, s: u32, entry: Arc<AssocEntry>) {
        self.shard(s).rcu(|m| {
            let mut next = (**m).clone();
            next.insert(s, entry.clone());
            next
        });
    }

    /// Tears an association down: removes the published entry (if any) and
    /// releases its reserved slot. Must be called exactly once per successful
    /// [`Self::alloc_sess`], whether or not `publish` ever ran — which is why the
    /// count is released unconditionally rather than only when a map entry was
    /// found.
    fn release(&self, s: u32) {
        self.unpublish(s);
        self.len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Removes a published entry without touching the process-wide count. Split
    /// from [`Self::release`] so the slot accounting stays paired with
    /// `alloc_sess` alone and cannot be driven negative by a stray removal.
    fn unpublish(&self, s: u32) {
        self.shard(s).rcu(|m| {
            if !m.contains_key(&s) {
                return (**m).clone();
            }
            let mut next = (**m).clone();
            next.remove(&s);
            next
        });
    }

    /// Look up an association's reply endpoint. Lock-free and infallible: the
    /// returned `None` means "no such association", never "try again".
    fn entry(&self, s: u32) -> Option<Arc<AssocEntry>> {
        self.shard(s).load().get(&s).cloned()
    }

    /// Test-only publish with an explicit session id, so `dispatch_one` can be
    /// driven against a known key without going through `alloc_sess`'s counter.
    #[cfg(test)]
    fn subscribe(&self, s: u32, entry: Arc<AssocEntry>) {
        self.publish(s, entry);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let a = Args::parse();
    let c: ClientConf = load_toml(&a.config)?;
    if c.auth_token.len() > AUTH_TOKEN_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_TOKEN_MAX_BYTES} B wire cap (server only reads the first {AUTH_TOKEN_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
        );
    }
    if is_placeholder_token(&c.auth_token) {
        warn!("auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)");
    }
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?, &c.alpn_bytes())?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_client));
    ccfg.transport_config(build_transport_tuned(
        &c.congestion,
        c.keep_alive_secs,
        c.tuning(),
    ));
    let ccfg = Arc::new(ccfg);
    let server_str = c.server_addr.clone();
    let server_str_log = server_str.clone();

    // Single Endpoint for the process lifetime: one UDP socket, shared session-ticket
    // cache (0-RTT resumption) and CID routing for every dial. Never recreate per dial.
    // Tuned socket buffers so bursts do not drop before quinn sees them.
    let rt = Arc::new(quinn::TokioRuntime);
    let std_sock = udp_socket_dual("[::]:0")?;
    let mut ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        rt.wrap_udp_socket(std_sock)?,
        rt,
    )?;
    ep.set_default_client_config((*ccfg).clone());

    let conns = c.conn_count();
    let udp_fail_closed = c.udp_fail_closed();
    let pool = ConnPool::new(conns, c.interactive_port_list(), udp_fail_closed);
    // One extra connection is dialed for UDP, so `quic_conns` keeps meaning
    // "TCP pool size" and the dedicated UDP connection never takes a congestion
    // window away from the bulk TCP class.
    info!(
        "quic pool: {conns} TCP connection(s){} + 1 dedicated UDP connection (slot {}){}",
        if conns > 1 {
            " (bulk round-robin + interactive pin)"
        } else {
            " (single connection: interactive and bulk share slot 0)"
        },
        pool.udp_slot(),
        if udp_fail_closed {
            ", UDP is fail-closed: dropped rather than shared while it reconnects"
        } else {
            ", UDP may fall back to a TCP connection while it reconnects"
        }
    );
    let hub: Arc<UdpHub> = Arc::new(UdpHub::new());
    let egress_shared: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // One DATAGRAM dispatcher and one reconnect loop per pool slot, all sharing
    // the same Endpoint (one UDP socket, one ticket cache, one CID router).
    // Every slot keeps its own reassembler, which is correct because a
    // payload's fragments all travel on the connection that carried them.
    // Each connection carries its own class: the interactive ports and the UDP
    // associations have connections no bulk flow can queue on.
    let keep_alive_secs = c.keep_alive_secs.clamp(1, 3600);
    let watchdog_silence = Duration::from_secs(keep_alive_secs.saturating_mul(4).max(20));
    for i in 0..pool.slots_total() {
        spawn_dispatcher(pool.slot(i), hub.clone());
    }
    for i in 0..pool.slots_total() {
        spawn_conn_loop(
            ep.clone(),
            server_str.clone(),
            c.server_name.clone(),
            c.auth_token.clone(),
            pool.slot(i),
            watchdog_silence,
        );
    }

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!("socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, token={}, tls13-pinned, 0rtt)",
        if c.auth_token.is_empty() { "off" } else { "on" });
    spawn_udp_reporter();
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    loop {
        let (sock, peer) = match li.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (EMFILE/ECONNABORTED) must not kill
                // the proxy for every other client.
                warn!("accept failed: {e:#}; continuing");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let permit = match socks_conn_limiter().clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("socks connection limit {MAX_SOCKS_CONNS} reached; dropping {peer}");
                continue; // socket closes on drop
            }
        };
        let pool = pool.clone();
        let hub = hub.clone();
        let egress_shared = egress_shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks(sock, pool, hub, egress_shared, timeout).await {
                warn!("socks {peer} end: {e:#}");
            }
        });
    }
}

fn jitter_ms() -> u64 {
    use std::cell::Cell;
    thread_local! { static S: Cell<u64> = const { Cell::new(0) }; }
    S.with(|s| {
        let mut x = s.get();
        if x == 0 {
            // Seed per-thread from time + thread id so concurrent clients
            // do not share one backoff sequence and thundering-herd.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e3779b97f4a7c15);
            let tid = format!("{:?}", std::thread::current().id());
            let mut h = t.wrapping_add(0x9e3779b97f4a7c15);
            for b in tid.bytes() {
                h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
            }
            x = h | 1;
        }
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) % 200
    })
}

fn tcp_abort_log_due() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if LAST
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let n = SUPPRESSED.swap(0, Ordering::Relaxed);
        if n > 0 {
            tracing::warn!("tcp aborts suppressed in the last window: {n}");
        }
        true
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Direct-mapped dispatcher cache, one slot per session id modulo the table
/// size. A collision only means the slot is re-probed, never that a packet is
/// misrouted (the slot validates the exact id *and* the entry's liveness).
///
/// **Collisions are expected, not exceptional.** Session ids come from the
/// hub's monotonic `AtomicU32`, but they are handed out *consecutively*, so two
/// live associations `DISPATCH_CACHE` apart collide by construction and more
/// than `DISPATCH_CACHE` live associations collide by pigeonhole — and
/// `MAX_UDP_ASSOCS` is 4032, four times this table. An earlier revision of this
/// comment claimed a window of ≤ `DISPATCH_CACHE` live ids "maps
/// collision-free", which is exactly backwards: it is the ≤ `DISPATCH_CACHE`-live
/// case that cannot collide, and the busy case this cache exists for is the one
/// where both sessions in a colliding pair pay the hub probe on every datagram.
/// Sizing it to `MAX_UDP_ASSOCS` would remove that, at 4x the per-dispatcher
/// footprint (each of the pool's connections keeps its own).
/// Must be a power of two (the index is a mask).
const DISPATCH_CACHE: usize = 1024;

/// One cached session → endpoint binding. A slot is a hit only when it names the
/// exact session *and* the entry is still alive: a cached absence, a collision,
/// or a torn-down association re-probes the hub. Treating absence as a hit would
/// blackhole a session id if it were ever reused after `u32` wrap, and treating a
/// dead entry as a hit would keep writing into a socket nobody reads.
///
/// The entry is `Weak` on purpose. This cache lives in a dispatcher task that
/// outlives every association, so a strong reference here made the cache the
/// relay socket's *last* owner once `UdpHub::release` dropped the hub's and the
/// association task exited: up to `DISPATCH_CACHE` dead relay sockets — an fd
/// plus its 2 x 256 KiB kernel buffers each — stayed open until a session id
/// colliding on the same index happened to arrive (or the connection was
/// redialed, which rebuilds the cache). Measured before the fix: 1200
/// short-lived associations left **1024** UDP fds open in the client, which on a
/// 1024-fd router exhausts the table by itself. Upgrading on a hit costs two
/// atomics (the `Weak` CAS and the `Arc` drop that follows it), not one, on a
/// path that already performs a `send_to`.
struct DispatchSlot {
    sess: u32,
    entry: Option<std::sync::Weak<AssocEntry>>,
}

/// Route one inbound DATAGRAM to its association, writing the relay socket
/// directly.
///
/// This is the pass-23 replacement for "push into the association's queue and let
/// its reply task do the work". Nothing per-session is mutable here: the
/// reassembler is keyed by `(sess, id)` and therefore connection-wide, and the
/// scratch buffer is reused across datagrams, so the escape path stays
/// allocation-free.
fn dispatch_one(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
    pkt: &mut bytes::BytesMut,
) {
    let idx = (sess as usize) & (DISPATCH_CACHE - 1);
    // A hit needs the exact session *and* an endpoint that is still alive. The
    // upgrade also answers "has the association exited?": once it has, the weak
    // reference is dead (so nothing keeps its relay socket open) and the hub
    // would no longer serve the session either.
    let cached = if cache[idx].sess == sess {
        cache[idx]
            .entry
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .filter(|e| e.is_alive())
    } else {
        None
    };
    let entry = match cached {
        Some(e) => e,
        None => {
            // Miss, collision, torn-down association, or an upgrade that lost to
            // the association's exit: re-probe the hub.
            let Some(fresh) = hub.entry(sess) else {
                cache[idx] = DispatchSlot { sess, entry: None };
                // No such association: the reply belongs to a session that has
                // already been torn down. Still dropped — best-effort UDP, and
                // the server's own reap is what stops it — but *counted*, because
                // this fires in a perfectly ordinary race: the client reaps an
                // idle association (or the app closes the control TCP) at 180 s
                // while the server's session is still live and its target keeps
                // answering, so every reply until the server's own timeout shows
                // up here. It used to be a bare `return`, which made the 60 s
                // budget line's silence a claim the code could not support.
                dgram_drops::bump(&dgram_drops::UNKNOWN_SESS);
                return;
            };
            // `hub.entry` answers "is it published", not "is it alive": between
            // `AliveGuard` clearing the bit and `UdpHub::release` unpublishing
            // (and permanently, if that release is ever skipped) the map still
            // serves the entry. Without this filter the reply would be written
            // into a socket nobody reads, which is exactly what the cache-hit
            // path above filters with `is_alive`.
            if !fresh.is_alive() {
                cache[idx] = DispatchSlot { sess, entry: None };
                return;
            }
            cache[idx] = DispatchSlot {
                sess,
                entry: Some(Arc::downgrade(&fresh)),
            };
            fresh
        }
    };
    // `ArcSwapOption::load` borrows, so this costs no refcount traffic on the
    // per-datagram path; the 200 ms app-address cache the reply task needed is
    // gone with the lock it was working around.
    let Some(app) = entry.app() else {
        udp_write::no_app();
        return;
    };

    if d.first() == Some(&MQP_DGRAM_FRAG) {
        let Ok(f) = decode_fragment(&d) else {
            return;
        };
        let Some((_, a, whole)) = reasm.push(&f, mono_millis()) else {
            return;
        };
        udp_stats::payload(whole.len());
        match a.as_ref() {
            TargetAddrRef::Ip(dst) => send_reply_addr(&entry, app, dst, &whole, pkt),
            TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => send_reply_addr(&entry, app, dst, &whole, pkt),
                CachedLookup::Negative | CachedLookup::Unknown => {}
            },
        }
        return;
    }

    let Ok((_, a, p)) = decode_datagram_ref(&d) else {
        return;
    };
    let off = d.len() - p.len();
    let payload = d.slice(off..);
    udp_stats::payload(payload.len());
    match a {
        TargetAddrRef::Ip(dst) => send_reply_addr(&entry, app, dst, &payload, pkt),
        TargetAddrRef::Domain(h, p) => {
            // The server always echoes replies with an IP-form source address, so
            // this branch is defensive; the negative cache is still consulted
            // synchronously so a known-bad name never spawns a resolver task.
            match lookup_cached_fast(h, p) {
                CachedLookup::Negative => {}
                CachedLookup::Addr(dst) => send_reply_addr(&entry, app, dst, &payload, pkt),
                CachedLookup::Unknown => {
                    // Both of these are counted. The server's equivalent drop
                    // (`forward_server_dgram`) charges `DNS_INFLIGHT`, and an
                    // uncounted drop here showed up only as missing replies: a
                    // 40-datagram burst at one uncached name silently loses 39
                    // of them, and under contention (`dns_is_inflight` reports
                    // `true` when its shard mutex is busy, `lookup_cached_fast`
                    // reports `Unknown` when its read lock is) that can be a
                    // sustained loss with no counter and no log at all.
                    if dns_is_inflight(h, p) {
                        dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
                        return;
                    }
                    if dns_slow_path_limiter().available_permits() == 0 {
                        dgram_drops::bump(&dgram_drops::SESSION_FULL);
                        return;
                    }
                    let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            dgram_drops::bump(&dgram_drops::SESSION_FULL);
                            return;
                        }
                    };
                    // Hand the resolver task its own handle on the association.
                    // It checks nothing else: a reply resolved after the
                    // association died writes into a socket the entry keeps
                    // alive, which is the same best-effort UDP semantics as a
                    // reply that arrives late on any other path.
                    let entry = entry.clone();
                    let host = h.to_string();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let dst = match resolve_all_cached(&host, p).await {
                            Ok(v) => match v.first().copied() {
                                Some(s) => s,
                                None => return,
                            },
                            Err(_) => return,
                        };
                        let mut pkt = bytes::BytesMut::with_capacity(256);
                        send_reply(&entry, dst, &payload, &mut pkt);
                    });
                }
            }
        }
    }
}

fn spawn_dispatcher(slot: ConnSlot, hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        let mut gen = slot.gen_rx.clone();
        loop {
            let conn = match slot.wait_conn(&mut gen, Duration::from_secs(10)).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let reader = conn.read_datagram();
            tokio::pin!(reader);
            let mut cache: [DispatchSlot; DISPATCH_CACHE] = std::array::from_fn(|_| DispatchSlot {
                sess: u32::MAX,
                entry: None,
            });
            // One reassembler for the whole connection, exactly as the server's
            // datagram reader has always used: it is keyed by `(sess, id)`, so a
            // per-association copy would only duplicate state. Each pool slot
            // keeps its own, which is correct because a payload's fragments all
            // travel on the connection that carried them.
            let mut reasm = DgramReassembler::new();
            let mut pkt = bytes::BytesMut::with_capacity(256);
            let mut reader_failed = false;
            loop {
                tokio::select! {
                    d = &mut reader => {
                        let d: Bytes = match d {
                            Ok(d) => d,
                            Err(_) => { reader_failed = true; break; }
                        };
                        let Some(sess) = dgram_sess(&d) else {
                            continue;
                        };
                        dispatch_one(&mut cache, &hub, sess, d, &mut reasm, &mut pkt);
                    }
                    _ = gen.changed() => break,
                }
            }
            if reader_failed {
                // A read error can fire before the connection loop clears the
                // live bit; without this, wait_conn would immediately hand back
                // the same dead connection and the dispatcher would busy-spin.
                // Wait for the generation bump, with a short backstop.
                tokio::select! {
                    _ = gen.changed() => {}
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        }
    });
}

fn spawn_conn_loop(
    ep: quinn::Endpoint,
    server_str: String,
    sname: String,
    auth: String,
    slot: ConnSlot,
    watchdog_silence: Duration,
) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(200);
        loop {
            let server: SocketAddr = match resolve_server_addr(&server_str).await {
                Ok(a) => a,
                Err(e) => {
                    warn!("resolve {server_str} failed: {e:#}; retry in {backoff:?}");
                    tokio::time::sleep(backoff + Duration::from_millis(jitter_ms())).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            match dial_once(&ep, server, &sname, &auth).await {
                Ok(conn) => {
                    info!("QUIC connected to {server}");
                    slot.publish(&conn);
                    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
                    bump_gen(&slot.gen_tx);
                    let connected_at = std::time::Instant::now();
                    let watchdog = async {
                        let mut last_rx = conn.stats().udp_rx.datagrams;
                        let mut quiet_since = std::time::Instant::now();
                        info!("watchdog armed rx={last_rx} silence_limit={watchdog_silence:?}");
                        loop {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            if conn.close_reason().is_some() {
                                break;
                            }
                            let rx = conn.stats().udp_rx.datagrams;
                            if rx != last_rx {
                                last_rx = rx;
                                quiet_since = std::time::Instant::now();
                            } else if quiet_since.elapsed() >= watchdog_silence {
                                warn!(
                                    "QUIC path silent {watchdog_silence:?}, force-closing {server}"
                                );
                                conn.close(0u32.into(), b"watchdog");
                                break;
                            }
                        }
                    };
                    tokio::select! {
                        _ = conn.closed() => {}
                        _ = watchdog => {}
                    }
                    warn!("QUIC connection lost, reconnecting...");
                    if let Some(reason) = conn.close_reason() {
                        warn!("QUIC close reason: {reason}");
                    }
                    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
                    if slot.clear_if(&conn) {
                        bump_gen(&slot.gen_tx);
                    }
                    if connected_at.elapsed() >= Duration::from_secs(5) {
                        backoff = Duration::from_millis(200);
                    }
                    let wait = backoff + Duration::from_millis(jitter_ms());
                    tokio::time::sleep(wait).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
                Err(e) => {
                    warn!("dial {server} failed: {e:#}; retry in {backoff:?}");
                    tokio::time::sleep(backoff + Duration::from_millis(jitter_ms())).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    });
}
/// Cap on a single dial attempt.
///
/// Without an explicit bound a dead path costs ~15 s per attempt: QUIC keeps
/// retransmitting the Initial until the handshake PTO budget runs out, and the
/// reconnect loop only regains control after that. The loop already retries with
/// backoff, so a shorter attempt is strictly better: it shrinks the window in
/// which `shared` still holds the previous, dead connection, and it lets the
/// first attempt that lands after a server restart succeed instead of waiting
/// out the previous attempt's timeout.
const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Confirm that a freshly dialed connection is actually alive before it is
/// published to the shared slot.
///
/// quinn-0.11's `Connecting` resolved `Ok` even when the underlying connection
/// terminated instead of completing its handshake, which let the reconnect loop
/// publish a connection that was already closed, log "QUIC connected", and hand
/// every new SOCKS flow a dead handle until quinn's idle timeout expired ~15 s
/// later. quinn 0.12 reports the terminal error from `Connecting` itself, so
/// this is now a cheap belt-and-braces guard rather than the only defence:
/// yielding once lets the connection driver deliver any terminal event, after
/// which `close_reason()` is populated and the dial is reported as the failure
/// it is.
async fn ensure_dialed_alive(conn: &quinn::Connection) -> bool {
    if conn.close_reason().is_some() {
        return false;
    }
    tokio::task::yield_now().await;
    conn.close_reason().is_none()
}

async fn dial_once(
    ep: &quinn::Endpoint,
    server: SocketAddr,
    name: &str,
    auth_token: &str,
) -> Result<quinn::Connection> {
    let t0 = tokio::time::Instant::now();
    let connecting = ep.connect(server, name)?;
    // 0-RTT: send the auth token in early data, then WAIT for the handshake to
    // complete before handing the connection to application flows. quinn
    // discards every stream and DATAGRAM sent in rejected early data (and
    // resets stream ids), so using the connection before the handshake is known
    // to have completed would silently lose SOCKS requests and could make a
    // stale stream handle alias a newly opened stream. The token still rides
    // early data, which is the part that actually saves a round trip on
    // resumption.
    //
    // 0.11 API: `into_0rtt()` yields `(Connection, ZeroRttAccepted)`; the
    // future resolves when the handshake completes with true = early data
    // kept, false = rejected OR the connection died first. The timeout plus
    // the `ensure_dialed_alive` gate below keep a dead dial from ever being
    // published (0.11's `Connecting` resolves `Ok` even for dead dials).
    let conn = match connecting.into_0rtt() {
        Ok((conn, accepted_fut)) => {
            let token = auth_token.to_owned();
            let needs_auth = !token.is_empty();
            // A failed early-data write must not fail the whole dial: the
            // handshake may still complete at 1-RTT, in which case the token is
            // re-sent below.
            let early_ok = if needs_auth {
                match send_auth_stream(&conn, &token).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::debug!("0-RTT auth write failed ({e:#}); will re-send at 1-RTT");
                        false
                    }
                }
            } else {
                true
            };
            let accepted = match tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, accepted_fut).await {
                Ok(a) => a,
                Err(_) => anyhow::bail!("0-RTT offered but the handshake did not complete"),
            };
            tracing::debug!("QUIC resumption: 0-RTT accepted={accepted}");
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection lost during handshake");
            }
            // Rejected early data discarded the auth stream; re-send it on the
            // now-established connection so the server does not sit out its auth
            // timeout and close us. A failed early write needs the same recovery
            // even when the server kept 0-RTT.
            if needs_auth && (!accepted || !early_ok) {
                tracing::debug!("QUIC 0-RTT rejected: re-sending auth at 1-RTT");
                send_auth(&conn, &token).await?;
            }
            conn
        }
        Err(connecting) => {
            let conn = match tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, connecting).await {
                Ok(r) => r?,
                Err(_) => anyhow::bail!("handshake timed out after {DIAL_ATTEMPT_TIMEOUT:?}"),
            };
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection closed immediately after the handshake");
            }
            info!("QUIC full handshake in {:?}", t0.elapsed());
            if !auth_token.is_empty() {
                send_auth(&conn, auth_token).await?;
            }
            conn
        }
    };
    if !ensure_dialed_alive(&conn).await {
        anyhow::bail!("connection not usable after dial");
    }
    Ok(conn)
}

/// Open a uni stream and write the auth token into it (early data on 0-RTT).
///
/// Rejection is learned via the `ZeroRttAccepted` future, not from this handle.
async fn send_auth_stream(conn: &quinn::Connection, token: &str) -> Result<quinn::SendStream> {
    let mut uni = tokio::time::timeout(Duration::from_secs(5), conn.open_uni())
        .await
        .context("auth stream open timed out")??;
    uni.write_all(token.as_bytes())
        .await
        .context("auth write failed")?;
    uni.finish().ok();
    Ok(uni)
}

async fn send_auth(conn: &quinn::Connection, token: &str) -> Result<()> {
    send_auth_stream(conn, token).await.map(|_| ())
}

/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
fn spawn_udp_reporter() {
    // One reporter per process: `main` calls this once today, and a second call
    // would double every 60 s line (the server's reporter has carried this guard
    // since it was written).
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if ONCE.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately; skip it
        let mut prev = udp_stats::snapshot();
        let mut prev_w = udp_write::snapshot();
        let mut prev_r = udp_stats::reassembly_drops();
        let mut prev_d = dgram_drops::snapshot();
        loop {
            tick.tick().await;
            let now = udp_stats::snapshot();
            let now_w = udp_write::snapshot();
            let d = now.since(&prev);
            let dw = now_w.since(&prev_w);
            if !d.is_idle() {
                info!(
                    "udp relay (60s): {d}; high-water payload {} B",
                    now.max_payload
                );
            }
            // The last-hop write outcomes, always logged: a silent drop here is
            // what a flat relay counter cannot show.
            if !(dw.sent == 0 && dw.retried == 0) || !dw.clean() {
                info!("udp write (60s): {dw}");
            }
            let now_r = udp_stats::reassembly_drops();
            if now_r != prev_r {
                info!(
                    "udp reassembly (60s): {} expired (missing fragment), {} evicted (cap)",
                    now_r.0.saturating_sub(prev_r.0),
                    now_r.1.saturating_sub(prev_r.1)
                );
                prev_r = now_r;
            }
            // Every dropped datagram, including the two client-only egress paths
            // and the DNS ones this side used to drop without a counter. Without
            // this line the counters existed but nothing ever read them: the
            // server's reporter printed the same block, the client's did not.
            let now_d = dgram_drops::snapshot();
            let dd = now_d.since(&prev_d);
            if dd.lost() > 0 {
                info!(
                    "udp budget (60s): {} dropped (no egress connection), {} dropped (egress died), {} dropped (resolution in flight), {} dropped (DNS/session cap); totals too_large={} buffer_full={} no_egress={} egress_dead={} dns_inflight={} session_full={}",
                    dd.no_egress,
                    dd.egress_dead,
                    dd.dns_inflight,
                    dd.session_full,
                    now_d.too_large,
                    now_d.buffer_full,
                    now_d.no_egress,
                    now_d.egress_dead,
                    now_d.dns_inflight,
                    now_d.session_full
                );
            }
            // Reported on its own line, and outside `lost()`: a late reply to a
            // session this side already closed is not a packet the tunnel failed
            // to carry, so folding it into the budget line would make every
            // ordinary association teardown look like loss. It is still worth a
            // line of its own — a number that only ever grows means the client is
            // reaping associations the server still considers live.
            if dd.unknown_sess > 0 {
                info!(
                    "udp late replies (60s): {} dropped (no such association); total {}",
                    dd.unknown_sess, now_d.unknown_sess
                );
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
        }
    });
}

// ---- SOCKS5 (RFC1928, no-auth only) ----

/// One deadline for a whole SOCKS negotiation (greeting + request + target).
/// The app is local, so this only has to bound a stuck or hostile peer; the
/// previous shape re-armed a fresh 10 s timeout per field, making the worst
/// case a multiple of it and registering several timers per connection at the
/// connection rate.
const SOCKS_NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the client asked for, once its whole negotiation has been read.
enum SocksRequest {
    Connect(TargetAddr),
    Associate,
}

/// Reads the greeting (only the no-auth method is offered) and the request.
/// Framing only; the caller owns the deadline (see [`SOCKS_NEGOTIATE_TIMEOUT`]).
async fn negotiate(s: &mut tokio::net::TcpStream) -> Result<SocksRequest> {
    // handshake: VER NMETHODS METHODS; we only support 0x00
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.context("socks greeting")?;
    if h[0] != 0x05 {
        anyhow::bail!("bad ver");
    }
    if h[1] == 0 {
        anyhow::bail!("no methods offered");
    }
    let mut m = [0u8; u8::MAX as usize];
    s.read_exact(&mut m[..h[1] as usize])
        .await
        .context("socks methods")?;
    if !m[..h[1] as usize].contains(&0x00) {
        write_socks(s, &[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    write_socks(s, &[0x05, 0x00]).await?;

    let mut r = [0u8; 3];
    s.read_exact(&mut r).await.context("socks request")?;
    if r[0] != 0x05 {
        anyhow::bail!("bad req ver");
    }
    if r[2] != 0x00 {
        anyhow::bail!("bad req rsv {:#x}", r[2]);
    }
    match r[1] {
        0x01 => match read_socks_addr(s).await {
            Ok(t) => Ok(SocksRequest::Connect(t)),
            Err(_) => {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad connect target");
            }
        },
        0x03 => {
            // UDP ASSOCIATE: outer addr is a hint only (often 0.0.0.0:0) and
            // is always ignored, so read it leniently without TargetAddr
            // validation. Real packet targets inside DATAGRAMs stay strict.
            if read_socks_addr_lenient(s).await.is_err() {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad associate target");
            }
            Ok(SocksRequest::Associate)
        }
        _ => {
            write_socks(s, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("unsupported cmd");
        }
    }
}

async fn handle_socks(
    mut s: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
    timeout: Duration,
) -> Result<()> {
    let request = match tokio::time::timeout(SOCKS_NEGOTIATE_TIMEOUT, negotiate(&mut s)).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("socks negotiation timed out"),
    };
    let target = match request {
        SocksRequest::Connect(t) => t,
        SocksRequest::Associate => return handle_udp_associate(s, pool, hub, egress_shared).await,
    };
    let bnd: SocketAddr = bnd_for(&s).unwrap_or_else(|_| {
        s.peer_addr()
            .map(|p| SocketAddr::new(unmap(p.ip()), 0))
            .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0))
    });

    let slot = pool.pick_tcp(&target);
    let mut gen_rx = slot.gen_rx.clone();
    let gen_tx = slot.gen_tx.clone();
    let conn = match slot.wait_conn(&mut gen_rx, timeout).await {
        Ok(c) => c,
        Err(e) => {
            // Answer the SOCKS client instead of just dropping the TCP
            // connection (a reset looks like a proxy crash to the app).
            write_socks_reply(&mut s, 0x04, bnd).await.ok();
            return Err(e);
        }
    };
    let (mut send, recv) = match tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await
    {
        Ok(Ok((s, r))) => {
            let prio = if pool.is_interactive(&target) { 10 } else { 0 };
            let _ = s.set_priority(prio);
            (s, r)
        }
        _ => {
            if conn.close_reason().is_some() {
                // Atomic read-then-clear with re-check: a reconnect may install
                // a fresh connection between a read and a later clear, and
                // clearing unconditionally would blackhole the new connection
                // until it dies. `clear_if` matches on `stable_id` inside the
                // `rcu` closure, so the re-check and the store cannot be split.
                // Matches the reconnect loop's own clear path.
                if slot.clear_if(&conn) {
                    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
                    bump_gen(&gen_tx);
                }
                write_socks_reply(&mut s, 0x04, bnd).await.ok();
                anyhow::bail!("quic connection dead, retry");
            }
            write_socks_reply(&mut s, 0x01, bnd).await.ok();
            anyhow::bail!("quic stream open failed (limit?), retry without killing conn");
        }
    };
    // The open header is deliberately its own write, flushed before any
    // application byte is read: a peer that waits for its first reply
    // (game login, banner protocols) must see the header within ~100ms
    // without the client ever sending payload. Never batch it behind the
    // first app chunk; `tcp_open_header_arrives_without_app_data` pins this.
    // Stack buffer: the header is at most 259 B, so the per-flow `Vec` this
    // used to allocate was one heap round trip for bytes that live one write.
    let mut hdr = [0u8; AddrHeader::MAX_LEN];
    let hdr_len = target.as_ref().header()?.encode_into(&mut hdr);
    send.write_all(&hdr[..hdr_len]).await?;
    // Optimistic SOCKS success: the application's first bytes must not be
    // serialized behind the server-side dial. Waiting for the MQP-2 ACK here
    // costs one full client<->server RTT on every connection (Hysteria/
    // juicity-class clients answer immediately for exactly this reason).
    // BND.ADDR is unknown at this point, so report 0.0.0.0:0 (the conventional
    // "not available" value); the ACK is consumed by the reply direction and a
    // failed dial tears the TCP flow down instead of returning a SOCKS error.
    let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    write_socks_reply(&mut s, 0x00, unknown).await?;
    match copy_tcp_quic_acked(
        s,
        send,
        recv,
        Duration::from_secs(300),
        TCP_DIAL_ACK_TIMEOUT,
    )
    .await
    {
        Ok((up, down)) => {
            tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
        }
        Err(e) => {
            // Abnormal ends already RST the TCP flow inside the pump; log the
            // path snapshot so loss-driven kills are diagnosable in one line.
            // Sampled: `stats()` takes the quinn lock, so an abort storm must
            // not pay it per flow.
            if tcp_abort_log_due() {
                let st = conn.stats();
                tracing::warn!(
                    "tcp {target:?} aborted: {e:#} (rtt={:?} cwnd={} lost={}/{} pkts)",
                    st.path.rtt,
                    st.path.cwnd,
                    st.path.lost_packets,
                    st.path.sent_packets,
                );
            }
        }
    }
    Ok(())
}

/// NOTE: the `read_exact`-per-field read shape is kept on purpose.
/// An earlier stack-buffer rewrite (one buffer + a `read`-loop tail) was
/// implemented and reverted: on macOS it reproducibly lost the final port byte
/// of a domain target (`bad connect target` on every domain CONNECT), while the
/// `read_exact`-per-field shape passes 30/30. This version changes only *where*
/// the bytes land (one stack buffer instead of assembled `Vec`s); every read
/// keeps the proven size and order. No per-field deadline here: `negotiate`'s
/// caller bounds the whole negotiation with one timeout.
async fn read_socks_addr(s: &mut tokio::net::TcpStream) -> Result<TargetAddr> {
    let mut buf = [0u8; AddrHeader::MAX_LEN];
    s.read_exact(&mut buf[..1]).await.context("socks atyp")?;
    let len = match buf[0] {
        0x01 => {
            s.read_exact(&mut buf[1..7]).await.context("socks v4")?;
            7
        }
        0x04 => {
            s.read_exact(&mut buf[1..19]).await.context("socks v6")?;
            19
        }
        0x03 => {
            s.read_exact(&mut buf[1..2])
                .await
                .context("socks domain len")?;
            let n = buf[1] as usize;
            if n == 0 {
                anyhow::bail!("empty domain");
            }
            s.read_exact(&mut buf[2..4 + n])
                .await
                .context("socks domain")?;
            4 + n
        }
        x => anyhow::bail!("bad atyp {x}"),
    };
    Ok(TargetAddr::decode(&buf[..len])?.0)
}

async fn read_socks_addr_lenient(s: &mut tokio::net::TcpStream) -> Result<()> {
    let mut t = [0u8; 1];
    s.read_exact(&mut t).await.context("socks atyp")?;
    match t[0] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.context("socks v4")?;
            Ok(())
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await.context("socks v6")?;
            Ok(())
        }
        0x03 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await.context("socks domain len")?;
            if n[0] == 0 {
                anyhow::bail!("empty domain");
            }
            let mut b = vec![0u8; n[0] as usize + 2];
            s.read_exact(&mut b).await.context("socks domain")?;
            Ok(())
        }
        x => anyhow::bail!("bad atyp {x}"),
    }
}

/// SOCKS control writes are tiny; a stalled local reader must not pin this
/// task (and its connection permit) indefinitely.
async fn write_socks(s: &mut tokio::net::TcpStream, buf: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), s.write_all(buf))
        .await
        .context("socks write timed out")??;
    Ok(())
}

fn bnd_for(s: &tokio::net::TcpStream) -> Result<SocketAddr> {
    let local = s.local_addr()?;
    let ip = unmap(local.ip());
    // An accepted socket's local address is concrete in practice; the
    // unspecified branch only fires for an unbound/odd socket. Falling back
    // to the peer (client) address there misreports BND as the client itself,
    // so report an unavailable address instead (the error REP is what the app
    // acts on; BND is informational on failures).
    let ip = if ip.is_unspecified() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        ip
    };
    Ok(SocketAddr::new(ip, local.port()))
}

async fn write_socks_reply(s: &mut tokio::net::TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    let mut v = [0u8; 3 + MAX_BND_LEN];
    v[0] = 0x05;
    v[1] = rep;
    v[2] = 0x00;
    let n = 3 + encode_bnd_addr_into(bnd, &mut v[3..]);
    write_socks(s, &v[..n]).await
}

// ---- UDP ASSOCIATE: app <-> local relay <-> QUIC DATAGRAM ----
async fn handle_udp_associate(
    mut tcp: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
) -> Result<()> {
    let sess = match hub.alloc_sess() {
        Some(s) => s,
        None => {
            let bnd = bnd_for(&tcp)
                .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0));
            write_socks_reply(&mut tcp, 0x01, bnd).await.ok();
            anyhow::bail!("udp association limit {MAX_UDP_ASSOCS} reached");
        }
    };
    udp_stats::session();
    // The reservation is released by a `Drop` guard, not by a statement after
    // the call: `udp_associate_inner` is a large function whose body can panic
    // (and a task can be dropped at an await point), and unwinding past a plain
    // `hub.release(sess)` would leak the hub's `len` slot *and* leave the shard's
    // `Arc<AssocEntry>` — hence the relay socket, its fd and its kernel buffers —
    // reachable for the process lifetime. That is exactly the defect
    // `SessMemo`'s strong `Arc` was in the server; the sibling `AliveGuard`
    // inside the inner function was already RAII, so this is the same discipline
    // applied to the reservation. `release` is unconditional because `alloc_sess`
    // reserved the slot whether or not an entry was ever published.
    let _reservation = SessReservation { hub: &hub, sess };
    udp_associate_inner(tcp, pool, hub.clone(), egress_shared, sess).await
}

async fn udp_associate_inner(
    mut tcp: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
    sess: u32,
) -> Result<()> {
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0")?)?;
    let relay_port = relay.local_addr()?.port();
    // BND.ADDR must be THIS proxy's address (the IP the app connected to), not
    // the app's own address: a LAN client sending datagrams to its own
    // IP:port would never reach the relay, breaking UDP off-host entirely.
    // Computed directly (not via `bnd_for`, whose unknown fallback is
    // 0.0.0.0): prefer the concrete local interface, else the peer address
    // (correct for same-host testing), else localhost.
    let relay_ip = match tcp.local_addr().map(|l| unmap(l.ip())) {
        Ok(ip) if !ip.is_unspecified() => ip,
        _ => tcp
            .peer_addr()
            .map(|p| unmap(p.ip()))
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    };
    let relay_reply = SocketAddr::new(relay_ip, relay_port);
    let relay = Arc::new(relay);
    // Publish the association's reply endpoint *before* the app is told the relay
    // address, so a reply can never arrive for a session the dispatchers cannot
    // resolve. The app address is still unknown at this point and is filled in by
    // the relay loop below; a reply that arrives before the app has sent anything
    // is dropped by `udp_write::no_app`, exactly as it was when the reply task
    // owned this state.
    let entry = Arc::new(AssocEntry::new(relay.clone()));
    hub.publish(sess, entry.clone());
    // Cleared on every exit path out of this function, including the `?` below.
    let _alive = AliveGuard(entry.clone());
    write_socks_reply(&mut tcp, 0x00, relay_reply).await?;
    // Pin the app's source IP to the SOCKS control connection's peer. The
    // relay binds [::]:0 (all interfaces), so without this the last datagram
    // sender (any host that can reach the ephemeral port) would hijack replies.
    // Ports are intentionally not pinned: RFC 1928 clients commonly send UDP
    // from a different socket/port than the TCP control connection.
    let expected_app_ip = tcp.peer_addr().ok().map(|p| unmap(p.ip()));
    // The idle stamp lives on the entry (`AssocEntry::last`), because the reply
    // direction has to refresh it too — see the field's note. This is only this
    // loop's local copy of "when did I last store it", so the store stays at one
    // per second instead of one per app datagram.
    let mut activity_stamp = mono_millis();
    // app -> QUIC with this association's sess. Idle assoc (no packets
    // either way for 180s) is reaped so leaked TCP controls cannot hold
    // relay sockets forever (B6).
    //
    // `UDP_RECV_MAX`, not 2048: the socket must be able to hold any datagram
    // the protocol can carry, or the kernel truncates it before the fragmenter
    // ever sees it. The SOCKS5 header sits in front of the payload, so the
    // buffer covers both (`n == buf.len()` below reports a truncation).
    let mut buf = vec![0u8; UDP_RECV_MAX + SOCKS_UDP_HDR_MAX + UDP_RECV_SLACK];
    // One id counter per association: `(sess, id)` is the receiver's key.
    let mut frag = DgramFragmenter::new();
    // Fixed-schedule interval (not a re-armed sleep): TCP control chatter must
    // not reset the idle timer and keep an otherwise dead association alive.
    let mut idle_tick = tokio::time::interval(Duration::from_secs(ASSOC_IDLE_TICK_SECS));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Local copy of the last published app address: the value almost never
    // changes (one UDP socket per association), so only publish on change
    // instead of storing per packet.
    let mut published_app: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            r = relay.recv_from(&mut buf) => {
                let (n, app) = match r {
                    Ok(x) => x,
                    // A transient socket error must end this association only;
                    // the wrapper still removes the hub subscription.
                    Err(_) => break,
                };
                if n == buf.len() {
                    // The kernel truncates a datagram larger than the buffer and
                    // reports only the buffer length, so the excess is already
                    // gone. Say so instead of dropping it without a trace.
                    warn!(
                        "udp assoc {sess}: app datagram of >= {} B truncated; raise \
                         MQP_FRAG_MAX_PAYLOAD to carry it",
                        buf.len()
                    );
                    continue;
                }
                // Pin the source IP: any host that can reach the relay port
                // could otherwise become "the app" and steal all replies.
                if let Some(expected) = expected_app_ip {
                    if unmap(app.ip()) != expected {
                        tracing::debug!("udp assoc {sess}: datagram from unauthorized app {app} ignored");
                        continue;
                    }
                }
                // The coarse epoch: this value feeds the 1 s liveness throttle
                // and the egress memo's 1 s freshness window, and both are whole
                // seconds. `mono_millis()` here was a vDSO `clock_gettime` on
                // every app datagram — the same cost the reply path already had
                // removed for the same reason (see `AssocEntry::replied`).
                let now = coarse_millis();
                if now.saturating_sub(activity_stamp) >= ASSOC_TOUCH_INTERVAL_MS {
                    activity_stamp = now;
                    entry.touch(now);
                }
                if published_app != Some(app) {
                    // Cannot lose: the publish always lands, so `published_app`
                    // and the shared slot can never drift apart. This is the
                    // hand-off to every dispatcher holding this entry.
                    entry.app.store(Some(Arc::new(app)));
                    published_app = Some(app);
                }
                if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0x00 {
                    continue;
                }
                // Single decode: reuse header length for the payload offset.
                let (addr, hdr_len) = match TargetAddrRef::decode(&buf[3..n]) {
                    Ok((a, n)) => (a, n),
                    Err(_) => continue,
                };
                let payload_off = 3 + hdr_len;
                if payload_off > n { continue; }
                let payload = &buf[payload_off..n];
                // Shared egress: the common case is a thread-local memo hit
                // (one generation load, zero Arc RMWs and zero quinn locks);
                // the lock path runs only on a generation change or once the
                // memo's stamp expires, and the single-flight winner still
                // pays close_reason/max_datagram_size at most once per refresh
                // window. Stale handles are reused optimistically with no
                // liveness check: a dead one surfaces as ConnectionLost on
                // send and invalidates the cache there.
                //
                // `limit` is the connection's live `max_datagram_size()`: the
                // real DATAGRAM budget for the discovered path MTU, with the
                // QUIC overhead already subtracted. It is deliberately NOT
                // clamped — a hard cap here is really a *payload* cap, and the
                // old `min(1350)` made every UDP payload above 1338 B vanish on
                // a 1472 B path (see `dgram_payload_cap`). Payloads past a single
                // frame are split by the fragmenter rather than dropped.
                let sent = match egress_shared.with_fresh(now, |c, limit| {
                    frag.send(c, sess, &addr, payload, limit)
                }) {
                    Some(s) => s,
                    None => {
                        // Load the generation *before* the cached read: any
                        // mutation concurrent with `acquire` then bumps past
                        // this tag, so the memo below is never served for a
                        // value the mutation replaced.
                        let gen = egress_shared
                            .generation
                            .load(std::sync::atomic::Ordering::Acquire);
                        match egress_shared.acquire(&pool, now) {
                            Some((conn, limit, stamp)) => {
                                egress_shared.memo_store(gen, &conn, limit, stamp);
                                frag.send(&conn, sess, &addr, payload, limit)
                            }
                            None => {
                                // No isolated egress connection right now: the
                                // dedicated UDP slot has not come up, is
                                // reconnecting, or another thread owns the
                                // refresh gate. Counted *exactly* (this counter is
                                // not batched) and warned once per
                                // `DROP_WARN_INTERVAL_MS`, because "is
                                // `udp_fail_closed` costing me anything" is only
                                // answerable if a short outage is visible at all.
                                // The detail separates the three causes, which is
                                // the difference between "the WAN is flapping" and
                                // "another thread won the refresh race".
                                let n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
                                dgram_drops::warn_egress_drop(
                                    dgram_drops::EgressDrop::NoConnection,
                                    n,
                                    || {
                                        format!(
                                            "; udp_fail_closed={} udp_slot_live={} refresh_in_flight={}",
                                            pool.udp_fail_closed(),
                                            pool.slot(pool.udp_slot()).is_live(),
                                            egress_shared
                                                .refreshing
                                                .load(std::sync::atomic::Ordering::Relaxed),
                                        )
                                    },
                                );
                                continue;
                            }
                        }
                    }
                };
                if sent.fragmented() {
                    tracing::debug!(
                        "udp assoc {sess}: {} B sent as {} fragments",
                        payload.len(),
                        sent.frames
                    );
                }
                let outcome = sent.outcome();
                match outcome {
                    DatagramSend::Sent => {}
                    // `Blocked`/`TooLarge` are counted where they are decided —
                    // `DgramFragmenter::send` for the protocol's own size caps,
                    // `send_encoded` for quinn's path-budget verdict — each with
                    // its own rate-limited size warning.
                    DatagramSend::Blocked => {
                        tracing::debug!("client datagram dropped: send buffer full");
                    }
                    // A **size** verdict, not a connection fault: either the
                    // payload is past the protocol's fragmentation cap or the
                    // path's DATAGRAM budget shrank since this handle was
                    // memoized. Both are already counted as size drops. The
                    // recovery is to re-read the live budget so the next datagram
                    // is encoded against it — and emphatically *not* to
                    // invalidate: this arm used to be folded in with
                    // `ConnectionLost`, so one oversized payload flushed the
                    // process-wide egress cache (costing every thread two quinn
                    // state-mutex acquisitions), bumped the connection-lost
                    // counter, and logged "udp egress connection lost at send"
                    // about a connection that was perfectly healthy.
                    DatagramSend::TooLarge => {
                        tracing::debug!(
                            "client datagram dropped: past the path's DATAGRAM budget"
                        );
                        egress_shared.refresh_budget();
                    }
                    DatagramSend::ConnectionLost => {
                        tracing::debug!("client egress stale, invalidating shared cache");
                        let n = dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
                        dgram_drops::warn_egress_drop(
                            dgram_drops::EgressDrop::ConnectionLost,
                            n,
                            || format!("; send outcome {outcome:?}, cached handle invalidated"),
                        );
                        egress_shared.invalidate();
                    }
                    DatagramSend::Unsupported => {
                        tracing::debug!("client datagram dropped: peer does not support DATAGRAM");
                        let n = dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
                        dgram_drops::warn_egress_drop(
                            dgram_drops::EgressDrop::Unsupported,
                            n,
                            String::new,
                        );
                        // Deliberately *not* invalidated. The condition is static
                        // for the life of the connection, so a re-acquire cannot
                        // find a better slot — but it does pay two quinn
                        // state-mutex acquisitions per datagram, which is strictly
                        // more than the failed send this arm is reacting to.
                        // Keeping the handle memoized leaves each datagram at one
                        // send attempt and one counted drop, and the dedicated
                        // warning class above keeps the cause visible.
                    }
                }
            }
            _ = tcp.readable() => {
                let mut closed = false;
                let mut got = false;
                // Bounded drain (8 KiB per readiness event): an unbounded loop
                // inside one select branch lets a flooding local app starve the
                // relay and idle branches. Tokio keeps readiness set until a
                // `WouldBlock`, so the remainder is picked up on the next poll.
                // Hoisted out of the loop: the buffer's contents are discarded
                // (RFC 1928 puts no data on the control connection after the
                // reply), so zeroing it once per iteration was up to 8 KiB of
                // dead stores per readiness event.
                let mut b = [0u8; 512];
                for _ in 0..16 {
                    match tcp.try_read(&mut b) {
                        Ok(0) => { closed = true; break; }
                        Ok(_) => { got = true; }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => { closed = true; break; }
                    }
                }
                if got {
                    // An open control connection that is actively used counts
                    // as activity; only truly abandoned associations idle out.
                    // Stored directly, not through `touch`: this is already
                    // gated on an actual read.
                    entry
                        .last
                        .store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
                }
                if closed {
                    break;
                }
            }
            _ = idle_tick.tick() => {
                // Both directions count, but only one of them reads a clock: the
                // relay loop stamps `last` for app-side traffic, and this tick
                // folds the dispatcher's `replied` flag in for the reply side, so
                // a receive-only flow is not reaped out from under the app and
                // the per-reply path stays clock-free.
                if entry.idle_since_tick(mono_millis(), ASSOC_IDLE_MS) {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Build a SOCKS5 UDP reply (RSV/FRAG + source address + payload) for the app
/// and try to send it.
///
/// The address encoder writes directly into the caller's scratch buffer, and
/// the payload is appended without an intermediate copy when the caller already
/// holds it as `Bytes` (the received datagram). A full app socket buffer drops
/// the datagram instead of stalling this association's reply task.
///
/// The scratch buffer is reused across replies: the fast path borrows it for
/// the syscall and only WouldBlock copies into the retry queue, so there is
/// no per-reply allocation and no aliasing with another task.
fn send_reply(entry: &AssocEntry, dst: SocketAddr, payload: &Bytes, pkt: &mut bytes::BytesMut) {
    let Some(app) = entry.app() else {
        udp_write::no_app();
        return;
    };
    send_reply_addr(entry, app, dst, payload, pkt);
}

fn send_reply_addr(
    entry: &AssocEntry,
    app: SocketAddr,
    dst: SocketAddr,
    payload: &Bytes,
    pkt: &mut bytes::BytesMut,
) {
    // A reply is activity. This is the whole of the reply path's liveness cost:
    // one relaxed store, folded into the stamp by the association's next idle
    // tick. It used to be a `mono_millis()` here — a vDSO `clock_gettime` per
    // datagram — for a signal whose only consumer compares it against 180 s.
    entry.mark_replied();
    pkt.truncate(0);
    pkt.extend_from_slice(&[0, 0, 0]);
    // The destination of a reply is always the source address the server
    // reported, which is IP-form; encode it straight into the scratch buffer.
    match dst {
        SocketAddr::V4(a) => {
            pkt.extend_from_slice(&[0x01]);
            pkt.extend_from_slice(&a.ip().octets());
            pkt.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            pkt.extend_from_slice(&[0x04]);
            pkt.extend_from_slice(&a.ip().octets());
            pkt.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    pkt.extend_from_slice(payload);
    udp_try_send_slice(&entry.relay, map_for_dual(app), &pkt[..]);
}

#[cfg(test)]
mod tests {
    //! Guards for the SOCKS5 address reader. `read_socks_addr` keeps its
    //! original two-`read_exact` shape (see the note above it), so these tests
    //! exist to catch a framing regression in any future rewrite.
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Serve `bytes` on a loopback socket and run the real reader against it,
    /// exactly as `handle_socks` drives it.
    async fn feed(bytes: &[u8], lenient: bool) -> Result<TargetAddr> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let payload = bytes.to_vec();
        let server = tokio::spawn(async move {
            let (mut t, _) = l.accept().await.unwrap();
            t.write_all(&payload).await.unwrap();
            // Wait for a byte from the client before closing: a plain
            // `shutdown()`/drop right after `write_all` races the loopback
            // stack on macOS and the last byte can be lost, which would make
            // this reader test fail for reasons that have nothing to do with
            // the reader.
            let mut ack = [0u8; 1];
            t.read_exact(&mut ack).await.ok();
        });
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = if lenient {
            read_socks_addr_lenient(&mut c)
                .await
                .map(|()| TargetAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))))
        } else {
            read_socks_addr(&mut c).await
        };
        // Unblock the server (see above) once the reader is done, then let it
        // exit cleanly.
        let _ = c.write_all(b"\n").await;
        let _ = server.await;
        r
    }

    #[tokio::test]
    async fn socks_reader_decodes_v4_v6_and_domain() {
        assert_eq!(
            feed(&[0x01, 127, 0, 0, 1, 0x46, 0xA1], false)
                .await
                .unwrap(),
            TargetAddr::Ip("127.0.0.1:18081".parse().unwrap())
        );

        let mut v6 = vec![0x04];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            feed(&v6, false).await.unwrap(),
            TargetAddr::Ip("[::1]:443".parse().unwrap())
        );

        let d = b"localhost";
        let mut dm = vec![0x03, d.len() as u8];
        dm.extend_from_slice(d);
        dm.extend_from_slice(&18081u16.to_be_bytes());
        assert_eq!(
            feed(&dm, false).await.unwrap(),
            TargetAddr::Domain("localhost".into(), 18081)
        );
    }

    #[tokio::test]
    async fn socks_reader_rejects_bad_atyp_and_empty_domain() {
        assert!(feed(&[0x02, 0, 0, 0, 0, 0, 0], false).await.is_err());
        assert!(feed(&[0x03, 0x00, 0x00, 0x00], false).await.is_err());
    }

    #[tokio::test]
    async fn socks_lenient_reader_accepts_the_same_framing() {
        let d = b"example.com";
        let mut dm = vec![0x03, d.len() as u8];
        dm.extend_from_slice(d);
        dm.extend_from_slice(&8443u16.to_be_bytes());
        assert!(feed(&dm, true).await.is_ok());
        assert!(feed(&[0x01, 0, 0, 0, 0, 0, 0], true).await.is_ok());
    }

    /// The whole negotiation is a linear read of greeting + request; the tests
    /// pin the two request forms and a version mismatch, so the single-deadline
    /// refactor cannot change which bytes are consumed.
    #[tokio::test]
    async fn negotiate_reads_connect_and_associate() {
        async fn feed(bytes: &[u8]) -> Result<SocksRequest> {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let payload = bytes.to_vec();
            let server = tokio::spawn(async move {
                let (mut t, _) = l.accept().await.unwrap();
                t.write_all(&payload).await.unwrap();
                // Drain until the client closes: half-closing early races the
                // client's remaining reads on macOS loopback.
                let mut sink = [0u8; 64];
                while let Ok(n) = t.read(&mut sink).await {
                    if n == 0 {
                        break;
                    }
                }
            });
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let r = negotiate(&mut c).await;
            drop(c);
            let _ = server.await;
            r
        }

        let mut connect = vec![0x05, 0x01, 0x00];
        connect.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0xA1]);
        match feed(&connect).await.unwrap() {
            SocksRequest::Connect(t) => {
                assert_eq!(t, TargetAddr::Ip("127.0.0.1:18081".parse().unwrap()));
            }
            SocksRequest::Associate => panic!("expected CONNECT"),
        }

        let mut assoc = vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00];
        assoc.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            feed(&assoc).await.unwrap(),
            SocksRequest::Associate
        ));

        assert!(feed(&[0x04, 0x01, 0x00]).await.is_err(), "bad ver");
    }

    /// Routing must read the maintained atomic: the old shape took the
    /// `shared` lock and `close_reason()` (quinn's connection-state mutex) per
    /// slot per flow, and a slot whose `shared` is empty still has to report
    /// whatever the connection loop last published.
    #[test]
    fn slot_liveness_is_the_maintained_atomic() {
        let slot = ConnSlot::fresh();
        assert!(!slot.is_live(), "no connection yet");
        slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(slot.is_live(), "the hint is what routing reads");
        slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!slot.is_live());
    }

    /// The routing table, row by row; the first three blocks are the *old*
    /// dual-pool assertions restated for the generalized selector, so a
    /// two-slot pool still behaves exactly as it did (including "keep the
    /// preference and fail fast" when both are down).
    #[test]
    fn slot_routing_table() {
        // Single slot: always slot 0, whatever the liveness says.
        assert_eq!(select_slot(false, 0, &[false]), 0);
        assert_eq!(select_slot(true, 1, &[true]), 0);
        assert_eq!(select_slot(false, 7, &[false]), 0);
        // Dual, all live: pinned -> a (0), bulk -> b (1) only.
        assert_eq!(select_slot(true, 0, &[true, true]), 0);
        assert_eq!(select_slot(false, 0, &[true, true]), 1);
        assert_eq!(select_slot(false, 1, &[true, true]), 1);
        // Dual, `a` down: everything fails over to `b` (1).
        assert_eq!(select_slot(true, 0, &[false, true]), 1);
        assert_eq!(select_slot(false, 0, &[false, true]), 1);
        assert_eq!(select_slot(false, 1, &[false, true]), 1);
        // Dual, `b` down: bulk falls back to `a`, pinned stays.
        assert_eq!(select_slot(true, 0, &[true, false]), 0);
        assert_eq!(select_slot(false, 0, &[true, false]), 0);
        assert_eq!(select_slot(false, 1, &[true, false]), 0);
        // Dual, both down: keep the preference for a bounded fail-fast.
        assert_eq!(select_slot(true, 0, &[false, false]), 0);
        assert_eq!(select_slot(false, 0, &[false, false]), 1);
        assert_eq!(select_slot(false, 1, &[false, false]), 1);
        // Four slots live: bulk cycles the three *non-interactive* slots and
        // never takes slot 0, while pinned never leaves it. This is the
        // isolation the pool exists for.
        for rr in 0..8 {
            assert_eq!(select_slot(false, rr, &[true; 4]), 1 + rr % 3);
            assert_eq!(select_slot(true, rr, &[true; 4]), 0);
        }
        // Four slots, 0 down: pinned and bulk both fail over to the first live.
        assert_eq!(select_slot(true, 0, &[false, true, true, true]), 1);
        assert_eq!(select_slot(false, 0, &[false, true, true, true]), 1);
        // ...but a live preference is never abandoned just because a lower slot
        // is dead: rr = 2 prefers slot 3 and keeps it.
        assert_eq!(select_slot(false, 2, &[false, true, true, true]), 3);
        assert_eq!(select_slot(true, 0, &[false, false, true, false]), 2);
        // Every slot down: the round-robin preference is kept, so each flow
        // waits on a real slot and fails fast rather than picking a random one.
        assert_eq!(select_slot(false, 0, &[false; 4]), 1);
        assert_eq!(select_slot(false, 2, &[false; 4]), 3);
        assert_eq!(select_slot(true, 2, &[false; 4]), 0);
    }

    /// The pool is a real papaya registry: N distinct TCP slots plus the
    /// dedicated UDP slot, bulk flows cycling through every *non-interactive* TCP
    /// slot, the interactive port pinned to slot 0, and failover driven by the
    /// maintained liveness bits.
    #[test]
    fn pool_round_robins_bulk_over_every_non_interactive_slot() {
        let pool = ConnPool::new(4, vec![53], true);
        assert_eq!(pool.tcp_slots(), 4, "every TCP slot is registered");
        assert_eq!(pool.udp_slot(), 4, "UDP is one past the TCP range");
        assert_eq!(pool.slots_total(), 5);
        assert_eq!(pool.slots.pin().len(), 5, "papaya holds all five");
        assert!(
            !Arc::ptr_eq(&pool.slot(0).live, &pool.slot(1).live),
            "each index is its own slot, not one shared handle"
        );
        let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
        let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
        // All slots still down: bulk keeps its round-robin preference (bounded
        // stall), the pinned port keeps slot 0.
        assert_eq!(pool.pick_tcp_index(&bulk), 1);
        assert_eq!(pool.pick_tcp_index(&bulk), 2);
        assert_eq!(pool.pick_tcp_index(&interactive), 0);
        for i in 0..4 {
            pool.slot(i)
                .live
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
        let seq: Vec<usize> = (0..8).map(|_| pool.pick_tcp_index(&bulk)).collect();
        assert_eq!(
            seq,
            vec![1, 2, 3, 1, 2, 3, 1, 2],
            "bulk spreads over the three non-interactive slots and never takes slot 0"
        );
        for _ in 0..4 {
            assert_eq!(pool.pick_tcp_index(&interactive), 0, "pinned to slot 0");
        }
        // Slot 0 down: both pinned and bulk fail over to the first live slot,
        // and `pick_tcp` hands back that slot's handle rather than slot 0's.
        pool.slot(0)
            .live
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(pool.pick_tcp_index(&interactive), 1);
        // rr has advanced to 8 by now, so the bulk preference is slot 3 — still
        // live, so it is kept rather than collapsed onto slot 1.
        assert_eq!(pool.pick_tcp_index(&bulk), 3);
        assert!(Arc::ptr_eq(
            &pool.pick_tcp(&interactive).live,
            &pool.slot(1).live
        ));
    }

    /// The regression the class-preserving failover exists for: with one bulk
    /// slot reconnecting, a bulk flow whose round-robin preference lands on that
    /// dead slot must take *another bulk slot*, never the interactive slot. The
    /// pre-fix selector scanned `0..n` and returned 0 here — one flow in three
    /// sharing the connection every interactive port rides, precisely while a
    /// connection was degraded.
    #[test]
    fn bulk_failover_never_takes_the_interactive_slot() {
        // Slots 0 (interactive), 1 (bulk), 3 (bulk) live; slot 2 (bulk) down.
        let live = [true, true, false, true];
        // rr = 1 prefers slot 2, which is down: fail over inside the bulk class.
        assert_eq!(select_slot(false, 1, &live), 1);
        assert_eq!(select_slot(false, 4, &live), 1);
        // A live preference is still kept.
        assert_eq!(select_slot(false, 0, &live), 1);
        assert_eq!(select_slot(false, 2, &live), 3);
        // Only when *no* bulk slot is live does slot 0 become the fallback.
        assert_eq!(select_slot(false, 1, &[true, false, false, false]), 0);
        assert_eq!(select_slot(false, 1, &[false, false, false, false]), 2);
        // ...and a pinned flow still prefers slot 0 or the first live slot.
        assert_eq!(select_slot(true, 0, &live), 0);
        assert_eq!(select_slot(true, 0, &[false, true, false, true]), 1);
        // The pool-level form of the same case.
        let pool = ConnPool::new(4, vec![], true);
        for i in [0usize, 1, 3] {
            pool.slot(i)
                .live
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
        let rr0 = pool.rr.load(std::sync::atomic::Ordering::Relaxed);
        // Walk enough flows to hit the dead slot's round-robin turn.
        let mut hits = [0usize; 4];
        for _ in 0..30 {
            hits[pool.pick_tcp_index(&bulk)] += 1;
        }
        assert_eq!(hits[0], 0, "bulk never lands on the interactive slot");
        assert_eq!(hits[2], 0, "the dead bulk slot is never selected");
        assert!(hits[1] > 0 && hits[3] > 0, "both live bulk slots are used");
        assert!(rr0 < pool.rr.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// A one-slot pool is the legacy single-TCP-connection mode: every flow,
    /// pinned or bulk, resolves to slot 0 no matter what the liveness bit says.
    /// UDP still gets its own connection (slot 1), so even the legacy mode keeps
    /// the two classes off one congestion window.
    #[test]
    fn pool_of_one_slot_always_routes_to_slot_zero() {
        let pool = ConnPool::new(1, vec![], true);
        assert_eq!(pool.tcp_slots(), 1);
        assert_eq!(pool.udp_slot(), 1);
        assert_eq!(pool.slots_total(), 2);
        let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
        assert_eq!(pool.pick_tcp_index(&bulk), 0);
        assert_eq!(pool.pick_tcp_index(&bulk), 0);
        pool.slot(0)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(pool.pick_tcp_index(&bulk), 0);
        // The constructor clamps, so a wider pool can never be built than the
        // routing path's stack liveness array can describe.
        assert_eq!(ConnPool::new(999, vec![], true).tcp_slots(), MAX_POOL_CONNS);
        assert_eq!(ConnPool::new(0, vec![], true).tcp_slots(), 1);
        // Clamping holds for the physical registry too: `tcp + 1` slots.
        assert_eq!(
            ConnPool::new(999, vec![], true).slots_total(),
            MAX_POOL_CONNS + 1
        );
    }

    /// The dedicated UDP slot is outside every TCP range, and the fail-closed
    /// policy keeps egress on it: a datagram is never handed a TCP slot's
    /// connection, whatever the rest of the pool is doing.
    #[test]
    fn udp_egress_is_confined_to_the_dedicated_slot() {
        let pool = ConnPool::new(4, vec![], true);
        assert_eq!(pool.udp_slot(), 4);
        assert!(pool.udp_slot() >= pool.tcp_slots());
        // Bulk rotation can never reach the UDP slot, live or dead.
        for rr in 0..16 {
            let i = select_slot(false, rr, &[true; 4]);
            assert!(i < pool.tcp_slots(), "rr={rr} picked {i}");
        }
        // Fail-closed: exactly one candidate.
        let egress = SharedEgress::default();
        let (order, k) = egress.egress_order(&pool);
        assert_eq!(k, 1, "fail-closed egress has a single candidate");
        assert_eq!(order[0], pool.udp_slot());
        // Fallback allowed: UDP first, then interactive, then bulk — and the UDP
        // slot appears exactly once.
        let pool = ConnPool::new(4, vec![], false);
        let (order, k) = egress.egress_order(&pool);
        assert_eq!(k, pool.slots_total());
        assert_eq!(&order[..5], &[4, 0, 1, 2, 3]);
        assert_eq!(
            order[..k].iter().filter(|&&i| i == pool.udp_slot()).count(),
            1
        );
        // The one-slot legacy pool still separates the classes.
        let pool = ConnPool::new(1, vec![], true);
        let (order, k) = egress.egress_order(&pool);
        assert_eq!((order[0], k), (1, 1));
    }

    /// Loopback QUIC endpoint pair through the same public TLS/transport
    /// helpers `main` uses, for tests that need a real `quinn::Connection`.
    /// The endpoints are returned alongside the client connection because
    /// dropping them closes it.
    async fn real_connection() -> (quinn::Connection, quinn::Endpoint, quinn::Endpoint) {
        let certified = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
        let alpn = normalize_alpn(None);
        let server_tls = server_tls_config(
            certified.cert.der().clone(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
            &alpn,
        )
        .unwrap();
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        scfg.transport_config(build_transport("bbr", 5));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let client_tls = client_tls_config(certified.cert.der().clone(), &alpn).unwrap();
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport("bbr", 5));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);

        let accept = async {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        };
        let (conn, _server_conn) =
            tokio::join!(client.connect(server_addr, "test.com").unwrap(), accept);
        (conn.unwrap(), client, server)
    }

    /// The memo is served only while it is both current (generation matches)
    /// and fresh (stamp inside the window); `invalidate` bumps the generation
    /// so every thread's memo misses without a scan.
    #[tokio::test]
    async fn egress_memo_honours_generation_and_freshness() {
        let (conn, _client, _server) = real_connection().await;
        let e = SharedEgress::default();
        let now = mono_millis();
        e.cached.store(Some(Arc::new(EgressCache {
            conn: conn.clone(),
            limit: 1200,
            stamp_ms: now,
            slot: 0,
        })));
        e.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        let gen = e.generation.load(std::sync::atomic::Ordering::Acquire);
        e.memo_store(gen, &conn, 1200, now);
        assert_eq!(e.with_fresh(now, |_, limit| limit), Some(1200));
        assert!(
            e.with_fresh(now + EGRESS_REFRESH_MS, |_, _| ()).is_none(),
            "a stamp past the refresh window must miss"
        );
        e.invalidate();
        assert!(
            e.with_fresh(now, |_, _| ()).is_none(),
            "a successful invalidate bumps the generation and drops the memo"
        );
        // A memo tagged before a later bump is not served even while its stamp
        // is still inside the window.
        let old_gen = e.generation.load(std::sync::atomic::Ordering::Acquire);
        e.memo_store(old_gen, &conn, 1200, now);
        assert!(e.with_fresh(now, |_, _| ()).is_some());
        e.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        assert!(e.with_fresh(now, |_, _| ()).is_none());
    }

    /// A `TooLarge` send refreshes the cached DATAGRAM budget instead of
    /// throwing the handle away.
    ///
    /// The two reactions are not interchangeable. `invalidate` drops the
    /// process-wide cache, so the next datagram on *every* thread re-acquires
    /// through `refresh_global` — two quinn state-mutex acquisitions — and the
    /// connection-lost counter and warning both lie about a healthy connection.
    /// `refresh_budget` keeps the handle and only re-reads the one number that
    /// moved.
    #[tokio::test]
    async fn too_large_refreshes_the_budget_without_discarding_the_handle() {
        let (conn, _client, _server) = real_connection().await;
        let live = conn
            .max_datagram_size()
            .expect("both ends negotiate DATAGRAM");
        let e = SharedEgress::default();
        // A deliberately stale, too-small budget, as if the path MTU had shrunk
        // under a memoized handle.
        e.cached.store(Some(Arc::new(EgressCache {
            conn: conn.clone(),
            limit: live.saturating_sub(64).max(1),
            stamp_ms: mono_millis(),
            slot: 0,
        })));
        let gen_before = e.generation.load(std::sync::atomic::Ordering::Acquire);
        let cached_before = e.cached.load_full().expect("published above");

        e.refresh_budget();

        let after = e.cached.load_full().expect("the handle must survive");
        assert_eq!(
            after.conn.stable_id(),
            cached_before.conn.stable_id(),
            "refresh_budget must keep the same connection, not re-pick one"
        );
        assert_eq!(
            after.limit, live,
            "the stale budget must be replaced by the live one"
        );
        assert_eq!(after.slot, cached_before.slot);
        assert_eq!(
            e.generation.load(std::sync::atomic::Ordering::Acquire),
            gen_before + 1,
            "every thread's memo must be invalidated so the new budget is used"
        );

        // And it is a no-op once the budget already matches — the case for a
        // payload past MQP_FRAG_MAX_PAYLOAD, where the fragmenter rejects the
        // datagram before quinn ever sees it and nothing moved.
        let gen_now = e.generation.load(std::sync::atomic::Ordering::Acquire);
        e.refresh_budget();
        assert_eq!(
            e.generation.load(std::sync::atomic::Ordering::Acquire),
            gen_now,
            "an unchanged budget must not churn the generation"
        );

        // With no cached handle at all it must not resurrect one.
        e.invalidate();
        e.refresh_budget();
        assert!(
            e.cached.load().is_none(),
            "refresh_budget never re-picks a connection; that is acquire's job"
        );
    }

    fn empty_dispatch_cache() -> [DispatchSlot; DISPATCH_CACHE] {
        std::array::from_fn(|_| DispatchSlot {
            sess: u32::MAX,
            entry: None,
        })
    }

    /// The dispatcher cache must never be the last owner of an association's
    /// relay socket.
    ///
    /// A cached binding outlives the association: the hub drops its entry and the
    /// association task exits, but the cache entry is only re-validated when
    /// another datagram for the *same session id* arrives. With a strong `Arc`
    /// there, every retired association stayed cached — up to `DISPATCH_CACHE`
    /// dead relay sockets, each an fd plus 2 x 256 KiB of kernel buffers, per
    /// dispatcher — until a colliding session id happened to arrive or the
    /// connection was redialed. Measured before the fix: 1200 short-lived
    /// associations left 1024 UDP fds open in the client.
    #[tokio::test]
    async fn dispatch_cache_does_not_own_the_relay_socket() {
        let hub = Arc::new(UdpHub::new());
        let a = test_assoc().await;
        hub.subscribe(7, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        dispatch_one(
            &mut cache,
            &hub,
            7,
            dgram(7, b"hello"),
            &mut reasm,
            &mut pkt,
        );
        assert!(
            cache[7 & (DISPATCH_CACHE - 1)].entry.is_some(),
            "the dispatcher must have cached the binding"
        );

        let weak = Arc::downgrade(&a.entry);
        let weak_relay = Arc::downgrade(&a.entry.relay);
        hub.release(7); // the association exits: hub entry and slot released
        drop(a); // ... and its own Arc goes with the task
                 // The relay socket can still be in the global `WouldBlock` retry pool for
                 // a moment — the first send on a fresh socket is answered with
                 // `WouldBlock` on this platform — so poll briefly instead of demanding
                 // instant release.
        let mut released = false;
        for _ in 0..100 {
            if weak.upgrade().is_none() && weak_relay.upgrade().is_none() {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            released,
            "the dispatcher cache must not keep a retired association's relay socket alive"
        );
    }

    /// UDP egress must stay on the connection it first used while that
    /// connection is alive.
    ///
    /// Re-running the slot scan on every refresh moved every association back
    /// onto the interactive slot the moment that slot recovered: a second
    /// target-side source-port change (the server builds a new session on the new
    /// connection) for a flow that had already failed over, which is the
    /// flap-back the docs promise not to do. The pool here has *no* live slot,
    /// which is the sharpest form of the check: a scan-based refresh gives up
    /// (`None`, so the datagram is dropped), while the sticky path still serves
    /// the live cached handle.
    #[tokio::test]
    async fn egress_stays_on_its_connection_while_it_lives() {
        let (conn, _c, _s) = real_connection().await;
        let pool = ConnPool::new(2, Vec::new(), true);
        let e = SharedEgress::default();
        let now = mono_millis();
        // Cached, but past the freshness window, so a refresh is required. Slot
        // 2 is this pool's dedicated UDP slot, which is what a fail-closed pool
        // can legitimately hold.
        e.cached.store(Some(Arc::new(EgressCache {
            conn: conn.clone(),
            limit: 1200,
            stamp_ms: now.saturating_sub(EGRESS_REFRESH_MS),
            slot: pool.udp_slot(),
        })));
        let (got, limit, stamp) = e
            .refresh_global(&pool, now)
            .expect("a live cached connection must be reused, not re-picked");
        assert_eq!(
            got.stable_id(),
            conn.stable_id(),
            "the cached connection must survive the refresh"
        );
        assert_eq!(stamp, now, "the refresh re-stamps the cached handle");
        assert!(
            limit > 0,
            "the DATAGRAM budget is re-read from the live path"
        );
        assert_eq!(
            e.cached.load().as_ref().map(|c| c.conn.stable_id()),
            Some(conn.stable_id()),
            "the published handle must still be that same connection"
        );

        // Once it is really gone the refresh falls back to the pool scan — and
        // with nothing live there is nothing to select, so the caller drops the
        // datagram instead of writing into a dead connection.
        conn.close(0u32.into(), b"test");
        for _ in 0..1000 {
            if conn.close_reason().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(conn.close_reason().is_some(), "close must be observable");
        assert!(
            e.refresh_global(&pool, now).is_none(),
            "a dead cached handle with no live slot must not be re-served"
        );
    }

    /// A fake association: a dual-stack relay socket (the production shape —
    /// `map_for_dual` maps the reply destination to a v4-mapped address, so a
    /// v4-only relay could not send), an "app" socket that receives replies, and
    /// the entry the hub would hold, with the app address already published.
    struct TestAssoc {
        entry: Arc<AssocEntry>,
        app: tokio::net::UdpSocket,
    }

    async fn test_assoc() -> TestAssoc {
        let relay =
            tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap();
        let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app_addr = app.local_addr().unwrap();
        let entry = Arc::new(AssocEntry::new(Arc::new(relay)));
        entry.app.store(Some(Arc::new(app_addr)));
        TestAssoc { entry, app }
    }

    /// How long a *positive* delivery assertion waits.
    ///
    /// 2 s, not the 300 ms this used to be: the reply is a loopback datagram
    /// sent by `dispatch_one` from *this* process, so it cannot be lost on the
    /// wire — but the suite runs several real-QUIC loopback tests concurrently,
    /// and while those saturate the loopback path a 300 ms window misses the
    /// datagram often enough that the client bin went red in roughly half of
    /// back-to-back `cargo test --all-targets` runs. Nothing here is sensitive
    /// to how long a *successful* wait takes.
    const REPLY_WAIT: Duration = Duration::from_secs(2);

    /// How long a *negative* probe waits before concluding "nothing arrived".
    ///
    /// Deliberately short, and it must stay well under `FRAG_TIMEOUT_MS`
    /// (2 s): `dispatch_reassembles_fragments_for_two_interleaved_sessions`
    /// probes *between* the fragments of one payload, so a 2 s probe would let
    /// the partial expire and the completed datagram could never be delivered —
    /// the assertion would fail for a reason that has nothing to do with the
    /// dispatcher. A reply sent synchronously by `dispatch_one` lands in
    /// microseconds, so 300 ms is a generous margin for a wrong-reply check.
    const REPLY_PROBE: Duration = Duration::from_millis(300);

    async fn recv_reply_in(app: &tokio::net::UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut b = vec![0u8; 2048];
        match tokio::time::timeout(wait, app.recv_from(&mut b)).await {
            Ok(Ok((n, _))) => Some(b[..n].to_vec()),
            _ => None,
        }
    }

    /// Drain one reply from the fake app, or `None` if nothing arrives within
    /// [`REPLY_WAIT`] — the timeout is what lets a "must be dropped" assertion
    /// terminate.
    async fn recv_reply(app: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
        recv_reply_in(app, REPLY_WAIT).await
    }

    /// True when no reply arrives within [`REPLY_PROBE`].
    async fn no_reply(app: &tokio::net::UdpSocket) -> bool {
        recv_reply_in(app, REPLY_PROBE).await.is_none()
    }

    /// A well-formed MQP-2 datagram carrying `payload` for `sess`.
    fn dgram(sess: u32, payload: &[u8]) -> Bytes {
        encode_datagram(
            sess,
            &TargetAddr::Ip("203.0.113.7:53".parse().unwrap()),
            payload,
        )
        .unwrap()
    }

    /// The SOCKS5 reply header is RSV(3) + ATYP(1) + v4(4) + port(2).
    const REPLY_HDR_V4: usize = 10;

    #[tokio::test]
    async fn dispatch_first_packet_probes_hub_and_delivers() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = hub.alloc_sess().unwrap();
        hub.publish(sess, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"hello"),
            &mut reasm,
            &mut pkt,
        );
        let got = recv_reply(&a.app).await.expect("reply must be delivered");
        assert_eq!(got[0..3], [0, 0, 0]);
        assert_eq!(got[3], 0x01, "ATYP must be IPv4");
        assert_eq!(&got[REPLY_HDR_V4..], b"hello");
        assert_eq!(cache[(sess as usize) & (DISPATCH_CACHE - 1)].sess, sess);
    }

    /// The dispatcher writes the relay socket itself, so a cached live entry must
    /// keep delivering even after the hub has forgotten the session. This is the
    /// replacement for the old "receiver still alive after `hub.remove`" case.
    #[tokio::test]
    async fn dispatch_cache_hit_does_not_reprobe_the_hub() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = hub.alloc_sess().unwrap();
        hub.publish(sess, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"a"),
            &mut reasm,
            &mut pkt,
        );
        assert_eq!(
            &recv_reply(&a.app).await.expect("first reply")[REPLY_HDR_V4..],
            b"a"
        );
        // Unpublish but leave the entry alive: the cache must still serve it.
        hub.release(sess);
        assert!(a.entry.is_alive());
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"b"),
            &mut reasm,
            &mut pkt,
        );
        assert_eq!(
            &recv_reply(&a.app).await.expect("cached reply")[REPLY_HDR_V4..],
            b"b"
        );
    }

    /// `alive` replaces the `Closed` signal the dropped `mpsc::Receiver` used to
    /// give: once the association clears it, the dispatcher must re-probe, find
    /// nothing, and drop — not keep writing into a socket nobody reads.
    #[tokio::test]
    async fn dispatch_dead_entry_reprobes_and_drops() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = hub.alloc_sess().unwrap();
        hub.publish(sess, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"a"),
            &mut reasm,
            &mut pkt,
        );
        assert!(recv_reply(&a.app).await.is_some());

        a.entry
            .alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        hub.release(sess);
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"b"),
            &mut reasm,
            &mut pkt,
        );
        assert!(
            no_reply(&a.app).await,
            "a torn-down association must not receive further replies"
        );
        assert!(
            cache[(sess as usize) & (DISPATCH_CACHE - 1)]
                .entry
                .is_none(),
            "the dead slot must have been re-probed away"
        );
    }

    /// The hub-probe path must filter liveness, not just publication.
    ///
    /// `dispatch_dead_entry_reprobes_and_drops` above releases the hub entry, so
    /// the map is already empty and `hub.entry` returns `None`. The window that
    /// test does not cover is the real one: `AliveGuard` clears the bit when the
    /// association exits, and the entry leaves the shard only later (in
    /// `UdpHub::release`, or never if that release is unwound past). A reply in
    /// that window was written into a socket nobody reads — the exact thing the
    /// cache-hit path filters with `is_alive`.
    #[tokio::test]
    async fn dispatch_published_but_dead_entry_is_dropped() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = hub.alloc_sess().unwrap();
        hub.publish(sess, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"a"),
            &mut reasm,
            &mut pkt,
        );
        assert!(recv_reply(&a.app).await.is_some());

        // The association has exited, but its entry is still published: this is
        // the `AliveGuard`-before-`release` window.
        a.entry
            .alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(hub.entry(sess).is_some(), "the entry is still published");
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"b"),
            &mut reasm,
            &mut pkt,
        );
        assert!(
            no_reply(&a.app).await,
            "a published-but-dead association must not receive replies"
        );
        assert!(
            cache[(sess as usize) & (DISPATCH_CACHE - 1)]
                .entry
                .is_none(),
            "the dead entry must not be cached"
        );
    }

    /// A reply is activity: it sets the association's activity bit, and the
    /// association's next idle tick folds that bit into the stamp, so a flow that
    /// is receive-only after its first request is not reaped at 180 s while the
    /// server-side session is still live.
    ///
    /// Both halves are driven with explicit clocks (the send path no longer reads
    /// one at all), so this asserts the semantics rather than the test process's
    /// uptime: a test binary is younger than one idle tick, so no real-clock run
    /// could observe both "the flag was consumed" and "the deadline passed".
    #[tokio::test]
    async fn replies_mark_the_association_active_until_the_next_tick() {
        let a = test_assoc().await;
        let mut pkt = bytes::BytesMut::with_capacity(256);
        let dst: SocketAddr = "203.0.113.7:53".parse().unwrap();
        let payload = Bytes::from_static(b"reply");
        let app = a.entry.app().expect("the app address is published");

        // The association was last active at t=0 and its deadline has just passed.
        a.entry.last.store(0, std::sync::atomic::Ordering::Relaxed);
        let now = ASSOC_IDLE_MS + ASSOC_IDLE_TICK_SECS * 1000;
        assert!(
            a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
            "without activity the deadline must be reported"
        );

        // One reply, then the tick that follows it: the flag is folded into the
        // stamp and the association stays alive, however stale the old stamp was.
        send_reply_addr(&a.entry, app, dst, &payload, &mut pkt);
        assert!(
            a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
            "a written reply must set the activity bit"
        );
        assert_eq!(
            a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the reply path itself must not touch the stamp (no clock read)"
        );
        assert!(
            !a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
            "a reply inside the window must keep the association alive"
        );
        assert_eq!(
            a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
            now,
            "the tick folds the bit into the stamp"
        );
        assert!(
            recv_reply(&a.app).await.is_some(),
            "the reply still goes out"
        );

        // The bit is consumed exactly once: the next tick with no further replies
        // reports idle at the deadline, and no earlier.
        assert!(
            !a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
            "the tick must consume the bit"
        );
        assert!(!a.entry.idle_since_tick(now + 1000, ASSOC_IDLE_MS));
        assert!(
            !a.entry
                .idle_since_tick(now + ASSOC_IDLE_MS - 1, ASSOC_IDLE_MS),
            "one millisecond short of the deadline is not idle"
        );
        assert!(
            a.entry.idle_since_tick(now + ASSOC_IDLE_MS, ASSOC_IDLE_MS),
            "the deadline itself is idle"
        );
    }

    /// A receive-only association is never reaped while replies flow, even when
    /// its stamp is older than the deadline on every single tick: this is the
    /// property the per-reply stamp existed for, restated for the bit.
    #[tokio::test]
    async fn flowing_replies_never_let_the_deadline_fire() {
        let a = test_assoc().await;
        let mut pkt = bytes::BytesMut::with_capacity(256);
        let dst: SocketAddr = "203.0.113.7:53".parse().unwrap();
        let payload = Bytes::from_static(b"stream");
        let app = a.entry.app().expect("the app address is published");
        a.entry.last.store(0, std::sync::atomic::Ordering::Relaxed);

        // 60 ticks, one reply in each: the app never sends anything.
        let mut now = ASSOC_IDLE_TICK_SECS * 1000;
        for _ in 0..60 {
            send_reply_addr(&a.entry, app, dst, &payload, &mut pkt);
            assert!(
                !a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
                "replies are still arriving at t={now}ms"
            );
            now += ASSOC_IDLE_TICK_SECS * 1000;
        }
        assert_eq!(
            a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
            now - ASSOC_IDLE_TICK_SECS * 1000,
            "the stamp tracks the last tick that saw activity"
        );
    }

    /// The dispatcher path (not just `send_reply_addr`) is what production uses,
    /// so pin that `dispatch_one` sets the same activity bit. No clock is read on
    /// either side of this assertion any more, which is why the test needs no
    /// sleep: it used to have to wait out a full touch interval.
    #[tokio::test]
    async fn dispatch_marks_the_association_active() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = hub.alloc_sess().unwrap();
        hub.publish(sess, a.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        assert!(!a.entry.replied.load(std::sync::atomic::Ordering::Relaxed));
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"reply"),
            &mut reasm,
            &mut pkt,
        );
        assert!(recv_reply(&a.app).await.is_some());
        assert!(
            a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
            "the dispatcher must mark the association active"
        );
        hub.release(sess);
    }

    /// The hub reservation is released by a `Drop` guard, so a panic in the
    /// association body cannot leak the process-wide slot or the shard's strong
    /// `Arc<AssocEntry>` (the relay socket's last owner). The reservation is the
    /// one release in this file that used to be a plain statement after an
    /// `.await`, which unwinding skips.
    #[tokio::test]
    async fn association_reservation_survives_a_panicking_body() {
        let hub = Arc::new(UdpHub::new());
        let sess = hub.alloc_sess().unwrap();
        let before = hub.len.load(std::sync::atomic::Ordering::Acquire);
        assert_eq!(before, 1, "one association reserved");

        let h = hub.clone();
        let joined = tokio::spawn(async move {
            let _res = SessReservation { hub: &h, sess };
            // A body that panics for any reason: a `?`-less failure, an
            // unexpected `None`, a poisoned helper.
            panic!("association body panicked");
        })
        .await;
        assert!(joined.is_err(), "the task must have unwound");

        assert_eq!(
            hub.len.load(std::sync::atomic::Ordering::Acquire),
            0,
            "the reserved slot must come back on unwinding"
        );
        assert!(
            hub.entry(sess).is_none(),
            "the released id must not stay published"
        );
        // The budget is reusable: a later association still gets an id. Ids are
        // not recycled by a monotonic counter (`alloc_sess`'s reuse-distance
        // note), so this asserts availability, not identity.
        let next = hub.alloc_sess().expect("the budget must be reusable");
        assert_ne!(next, 0);
        hub.release(next);
        assert_eq!(hub.len.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dispatch_absent_slot_reprobes_the_hub() {
        let hub = UdpHub::new();
        let a = test_assoc().await;
        let sess = 7777u32;
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        // Not published yet: the packet is dropped and the slot caches absent.
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"x"),
            &mut reasm,
            &mut pkt,
        );
        assert!(no_reply(&a.app).await);
        hub.publish(sess, a.entry.clone());
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"y"),
            &mut reasm,
            &mut pkt,
        );
        assert_eq!(
            &recv_reply(&a.app).await.expect("reply after publish")[REPLY_HDR_V4..],
            b"y"
        );
    }

    #[tokio::test]
    async fn dispatch_collision_reprobes_and_delivers_both() {
        let hub = UdpHub::new();
        let s1 = 100u32;
        let s2 = s1 + DISPATCH_CACHE as u32;
        assert_eq!(
            (s1 as usize) & (DISPATCH_CACHE - 1),
            (s2 as usize) & (DISPATCH_CACHE - 1)
        );
        let a1 = test_assoc().await;
        let a2 = test_assoc().await;
        hub.publish(s1, a1.entry.clone());
        hub.publish(s2, a2.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        for (s, want) in [(s1, &b"1"[..]), (s2, &b"2"[..]), (s1, &b"3"[..])] {
            dispatch_one(&mut cache, &hub, s, dgram(s, want), &mut reasm, &mut pkt);
        }
        let f = |v: Vec<u8>| v[REPLY_HDR_V4..].to_vec();
        assert_eq!(f(recv_reply(&a1.app).await.unwrap()), b"1");
        assert_eq!(f(recv_reply(&a2.app).await.unwrap()), b"2");
        assert_eq!(f(recv_reply(&a1.app).await.unwrap()), b"3");
    }

    /// Phase 3 moved fragment reassembly out of the per-association reply task
    /// and into the dispatcher, relying on `DgramReassembler` being keyed by
    /// `(sess, id)` — i.e. connection-wide, exactly as the server has always used
    /// it. This pins that a payload split across fragments still arrives whole,
    /// and that two sessions reassembling *concurrently* on the one dispatcher
    /// reassembler do not cross-contaminate.
    #[tokio::test]
    async fn dispatch_reassembles_fragments_for_two_interleaved_sessions() {
        let hub = UdpHub::new();
        let s1 = 11u32;
        let s2 = 12u32;
        let a1 = test_assoc().await;
        let a2 = test_assoc().await;
        hub.publish(s1, a1.entry.clone());
        hub.publish(s2, a2.entry.clone());
        let mut cache = empty_dispatch_cache();
        let mut reasm = DgramReassembler::new();
        let mut pkt = bytes::BytesMut::with_capacity(256);
        let addr = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
        let limit = 1400usize;
        let send = |reasm: &mut DgramReassembler,
                    cache: &mut [DispatchSlot; DISPATCH_CACHE],
                    pkt: &mut bytes::BytesMut,
                    sess: u32,
                    id: u16,
                    total: u8,
                    idx: u8,
                    chunk: &[u8]| {
            let f = encode_fragment(sess, id, idx, total, &addr.as_ref(), chunk, limit).unwrap();
            dispatch_one(cache, &hub, sess, f, reasm, pkt);
        };
        // Interleave the two sessions' fragments deliberately.
        send(&mut reasm, &mut cache, &mut pkt, s1, 5, 2, 0, b"AAAA");
        send(&mut reasm, &mut cache, &mut pkt, s2, 9, 2, 0, b"BBBB");
        assert!(
            no_reply(&a1.app).await,
            "a half-reassembled payload must not be delivered"
        );
        send(&mut reasm, &mut cache, &mut pkt, s1, 5, 2, 1, b"aaaa");
        send(&mut reasm, &mut cache, &mut pkt, s2, 9, 2, 1, b"bbbb");
        assert_eq!(
            &recv_reply(&a1.app).await.expect("s1 reassembled")[REPLY_HDR_V4..],
            b"AAAAaaaa"
        );
        assert_eq!(
            &recv_reply(&a2.app).await.expect("s2 reassembled")[REPLY_HDR_V4..],
            b"BBBBbbbb"
        );
    }

    /// The dispatcher's lookup is *total*: `sender` reports `None` only for a
    /// session that genuinely has no subscription, never because a lock was
    /// busy. This is the property the old `try_lock_read` violated — a losing
    /// `try_read` returned `None` and the inbound datagram was silently dropped.
    ///
    /// Hammered from several threads, a subscribed id must be observable on
    /// every single probe until it is removed, and `remove` must be the only
    /// thing that makes it disappear.
    #[tokio::test]
    async fn hub_sender_never_fails_because_of_concurrency() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let hub = Arc::new(UdpHub::new());
        const PROBES: u32 = 4096;
        // Subscribe everything *before* any reader runs, so from this point on
        // every id in 1..=PROBES is continuously subscribed and a `None` can
        // only mean a lost lookup.
        // One socket shared by every stub entry: these tests only exercise the
        // hub's lookup, never a dispatch, so 4096 real sockets would only risk
        // the fd limit.
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        for s in 1..=PROBES {
            hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let hub = hub.clone();
            let stop = stop.clone();
            readers.push(std::thread::spawn(move || {
                let mut seen = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    for s in 1..=PROBES {
                        assert!(
                            hub.entry(s).is_some(),
                            "subscribed session {s} probed as absent"
                        );
                        seen += 1;
                    }
                }
                seen
            }));
        }
        let mut churn = Vec::new();
        for t in 0..2u32 {
            let hub = hub.clone();
            let sock = sock.clone();
            churn.push(std::thread::spawn(move || {
                // A disjoint id range, hashed across the same 32 shards, so the
                // writers keep re-publishing maps the readers are loading.
                for i in 0..256u32 {
                    let s = 1_000_000 + t * 1000 + i;
                    hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
                    hub.unpublish(s);
                }
            }));
        }
        for c in churn {
            let _ = c.join();
        }
        stop.store(true, Ordering::Relaxed);
        let total: u64 = readers.into_iter().map(|r| r.join().unwrap()).sum();
        assert!(total > 0, "readers never ran");
        // Everything subscribed must still be present, and nothing else.
        for s in 1..=PROBES {
            assert!(hub.entry(s).is_some(), "session {s} lost after churn");
        }
        assert!(hub.entry(PROBES + 1).is_none());
    }

    /// `rcu` re-runs against the latest published map, so two associations
    /// subscribing to the same shard concurrently cannot lose each other's
    /// insert (which a load-clone-store would).
    #[tokio::test]
    async fn hub_concurrent_subscribes_on_one_shard_all_land() {
        let hub = Arc::new(UdpHub::new());
        // HUB_SHARDS == 32, so ids 0..32 spread over every shard exactly once
        // per round; each thread therefore contends on all shards.
        const PER_THREAD: u32 = 512;
        let mut threads = Vec::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        for t in 0..8u32 {
            let hub = hub.clone();
            let sock = sock.clone();
            threads.push(std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let s = 1 + t * PER_THREAD + i;
                    hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
                }
            }));
        }
        for t in threads {
            let _ = t.join();
        }
        for s in 1..=(8 * PER_THREAD) {
            assert!(
                hub.entry(s).is_some(),
                "concurrent subscribe lost session {s}"
            );
        }
        assert_eq!(
            hub.len.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "subscribe must not move the global association counter"
        );
    }

    /// `wait_conn` trusts the maintained live bit (no `close_reason()` mutex in
    /// the common case) and still fails fast once the bit is false, with
    /// `close_reason()` as the authority.
    #[tokio::test]
    async fn wait_conn_trusts_the_live_bit_and_bounds_the_dead_case() {
        let (conn, _client, _server) = real_connection().await;
        let slot = ConnSlot::fresh();
        slot.publish(&conn);
        slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
        let (_gen_tx, mut gen_rx) = watch::channel(0u64);

        // The live bit is the maintained hint: a locally closed connection is
        // still handed out while the bit is set (the accepted race window).
        conn.close(0u32.into(), b"test");
        assert!(slot
            .wait_conn(&mut gen_rx, Duration::from_secs(1))
            .await
            .is_ok());

        slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            slot.wait_conn(&mut gen_rx, Duration::from_millis(50))
                .await
                .is_err(),
            "a dead slot must fail at the deadline, not hand out a dead handle"
        );
    }
}
