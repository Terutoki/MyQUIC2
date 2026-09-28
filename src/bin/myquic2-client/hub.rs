//! UDP association hub.
use super::*;

/// Routes inbound QUIC DATAGRAMs to their UDP ASSOCIATE by sess_id.
/// One dispatcher serves the whole process across reconnects; subscriptions
/// die with their association, so no immortal task can steal another's packets.
/// The table is sharded because the dispatcher reads it for every inbound
/// DATAGRAM: a single RwLock there is a cross-core cache-line bottleneck.
///
/// Sized so a *write* stays cheap: a shard is a clone-on-publish map, and each
/// `publish`/`unpublish` clones the whole shard (one refcount RMW per entry, and
/// those counters share cache lines with the dispatcher's per-reply
/// `Weak::upgrade`). At `MAX_UDP_ASSOCS = 4032` a full house is ~16 entries per
/// shard here, versus ~126 at 32 shards; the read path pays nothing for the
/// extra shards (a shard is one `ArcSwap` and a modulo).
pub(crate) const HUB_SHARDS: usize = 256;

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
pub(crate) struct AssocEntry {
    pub(crate) relay: Arc<tokio::net::UdpSocket>,
    /// The app's source address, published by the relay loop when it first sees
    /// a datagram from the app, read by whichever dispatcher has a reply to
    /// deliver. Lock-free in both directions.
    pub(crate) app: ArcSwapOption<SocketAddr>,
    /// Cleared by the association as it exits.
    pub(crate) alive: std::sync::atomic::AtomicBool,
    /// Inbound activity, as one bit: set (relaxed) by whichever dispatcher
    /// writes a reply to this association, consumed by the association's own
    /// idle tick.
    ///
    /// This exists so the **reply path never reads a precise clock** — true for every
    /// unfragmented datagram, which is the steady state. (A *fragmented* reply
    /// still samples the coarse 1 s epoch in `dispatch_one`: `DgramReassembler::push`
    /// takes its timestamp as an argument, and the 2 s reassembly timeout plus the
    /// 1 s sweep throttle only need second-scale resolution, so `coarse_millis`
    /// — same epoch as `mono_millis`, at most one tick behind — is sufficient.) Stamping `last` directly per reply cost a
    /// `clock_gettime` through the vDSO (~25 ns) on every datagram, forever, for
    /// a signal that only has to prove "something happened in the last 180 s" —
    /// and the tick that folds this flag into the stamp already reads a clock
    /// once per [`ASSOC_IDLE_TICK_SECS`]. The store is idempotent and has one
    /// writer per association in steady state (a session's replies arrive on the
    /// one connection that carried its datagrams), so it cannot lose an update
    /// the way a read-modify-write could, and it never shares a cache line's
    /// write ownership per packet with the app direction, whose stamp stays
    /// throttled to 1 Hz.
    pub(crate) replied: std::sync::atomic::AtomicBool,
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
    pub(crate) last: std::sync::atomic::AtomicU64,
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
pub(crate) const ASSOC_IDLE_TICK_SECS: u64 = 10;
pub(crate) const ASSOC_IDLE_MS: u64 = 180_000;

/// App-direction stamp throttle. One relaxed load plus one store per second,
/// not per datagram: the relay loop reads a clock anyway (the egress memo's
/// freshness stamp needs it), but the shared stamp must not be rewritten per
/// packet or it would steal the cache line from the dispatcher's [`AssocEntry::replied`]
/// store on every datagram.
pub(crate) const ASSOC_TOUCH_INTERVAL_MS: u64 = 1000;

impl AssocEntry {
    pub(crate) fn new(relay: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            relay,
            app: ArcSwapOption::const_empty(),
            alive: std::sync::atomic::AtomicBool::new(true),
            replied: std::sync::atomic::AtomicBool::new(false),
            last: std::sync::atomic::AtomicU64::new(mono_millis()),
        }
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that a reply was written. One relaxed store — no clock read.
    pub(crate) fn mark_replied(&self) {
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
    pub(crate) fn idle_since_tick(&self, now_ms: u64, idle_limit_ms: u64) -> bool {
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
    pub(crate) fn touch(&self, now_ms: u64) {
        if now_ms.saturating_sub(self.last.load(std::sync::atomic::Ordering::Relaxed))
            >= ASSOC_TOUCH_INTERVAL_MS
        {
            self.last
                .store(now_ms, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(crate) fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// The app's address, if the app has sent anything yet. The returned borrow
    /// means no refcount traffic on the per-datagram path.
    pub(crate) fn app(&self) -> Option<SocketAddr> {
        self.app.load().as_ref().map(|a| **a)
    }
}

/// Clears an entry's liveness bit on every exit path out of the association,
/// including `?` early returns, so dispatchers drop their cached handle promptly
/// instead of writing replies into a socket nobody reads.
pub(crate) struct AliveGuard(pub(crate) Arc<AssocEntry>);

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
pub(crate) struct SessReservation<'a> {
    pub(crate) hub: &'a UdpHub,
    pub(crate) sess: u32,
}

impl Drop for SessReservation<'_> {
    fn drop(&mut self) {
        self.hub.release(self.sess);
    }
}

pub(crate) struct UdpHub {
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
    pub(crate) subs: Vec<arc_swap::ArcSwap<HashMap<u32, Arc<AssocEntry>>>>,
    pub(crate) next: std::sync::atomic::AtomicU32,
    /// Exact process-wide association count across all shards.
    pub(crate) len: std::sync::atomic::AtomicUsize,
}

impl UdpHub {
    pub(crate) fn new() -> Self {
        Self {
            subs: (0..HUB_SHARDS)
                .map(|_| arc_swap::ArcSwap::from_pointee(HashMap::new()))
                .collect(),
            next: std::sync::atomic::AtomicU32::new(1),
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn shard(&self, s: u32) -> &arc_swap::ArcSwap<HashMap<u32, Arc<AssocEntry>>> {
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
    pub(crate) fn alloc_sess(&self) -> Option<u32> {
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
    pub(crate) fn publish(&self, s: u32, entry: Arc<AssocEntry>) {
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
    pub(crate) fn release(&self, s: u32) {
        self.unpublish(s);
        self.len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Removes a published entry without touching the process-wide count. Split
    /// from [`Self::release`] so the slot accounting stays paired with
    /// `alloc_sess` alone and cannot be driven negative by a stray removal.
    /// An absent key returns the loaded handle unchanged (one refcount bump)
    /// instead of cloning the whole shard map for a no-op.
    pub(crate) fn unpublish(&self, s: u32) {
        self.shard(s).rcu(|m| {
            if !m.contains_key(&s) {
                return Arc::clone(m);
            }
            let mut next = (**m).clone();
            next.remove(&s);
            Arc::new(next)
        });
    }

    /// Look up an association's reply endpoint. Lock-free and infallible: the
    /// returned `None` means "no such association", never "try again".
    pub(crate) fn entry(&self, s: u32) -> Option<Arc<AssocEntry>> {
        self.shard(s).load().get(&s).cloned()
    }

    /// Test-only publish with an explicit session id, so `dispatch_one` can be
    /// driven against a known key without going through `alloc_sess`'s counter.
    #[cfg(test)]
    pub(crate) fn subscribe(&self, s: u32, entry: Arc<AssocEntry>) {
        self.publish(s, entry);
    }
}
