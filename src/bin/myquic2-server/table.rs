//! Session table: entries, sharding, sweeps, destination memos.
use super::*;

/// One live UDP session: the socket replies are read from, plus the bookkeeping
/// the connection needs to reap it.
///
/// A named struct rather than the 4-tuple this used to be, because the
/// destination memo below is the fifth field and `(Arc<..>, JoinHandle, Arc<..>,
/// OwnedPermit, DestMemo)` destructured at nine call sites is no longer
/// readable — and a mis-ordered tuple here would silently pair a socket with
/// the wrong field.
pub(crate) struct SessEntry {
    pub(crate) sock: Arc<tokio::net::UdpSocket>,
    /// The reply reader. `is_finished` is the liveness signal everywhere.
    pub(crate) reader: tokio::task::JoinHandle<()>,
    /// The session's idle stamp, shared with the memo so a memo hit can refresh
    /// liveness without the table lock.
    pub(crate) last: Arc<std::sync::atomic::AtomicU64>,
    /// Held for the session's lifetime; dropping it returns the global slot.
    pub(crate) _permit: tokio::sync::OwnedSemaphorePermit,
    /// Per-session destination memo — see [`DestMemo`].
    pub(crate) dest: DestMemo,
    /// Destination IPs this session actually sent to, consulted by the reply
    /// reader to drop forged replies. A session may legally serve several
    /// targets (one association, many datagrams), so this is a small allowlist
    /// rather than a single pin; past [`RECENT_DST_CAP`] the oldest entry is
    /// evicted and a reply from it is dropped until the session sends there
    /// again.
    ///
    /// A clone-on-write snapshot behind an [`arc_swap::ArcSwap`], not a mutex:
    /// the reply reader validates **every** inbound datagram against it, the
    /// outbound path pushes into it, and those are two different tasks of the
    /// same session — so a mutex there made the download hot path and the upload
    /// hot path ping-pong one cache line. Readers now take a hazard-pointer
    /// snapshot (no lock), and writers publish a new snapshot through `rcu`,
    /// which also means two concurrent pushes can no longer lose each other's
    /// insert. The snapshot is 280 B: `[Option<IpAddr>; 16]` is 272 B
    /// (`IpAddr` is 17 B, `Option<IpAddr>` has no niche) plus the `usize`
    /// write position (`RecentAddrs`).
    pub(crate) recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
    /// Bumped by every [`remember_dst`] for this session — including the push a
    /// spawned DNS resolver task makes from *its own* task
    /// (`forward_server_dgram`), which is the case the datagram reader cannot
    /// see. The reader's fast path mirrors the allowlist so a steady flow does
    /// not take the shard read lock plus the allowlist mutex per datagram; the
    /// epoch is what keeps that mirror honest when a foreign push evicts a
    /// destination the mirror still claims is recorded (which silently dropped
    /// that destination's replies as forged until the pin and DNS entry both
    /// expired).
    pub(crate) recent_epoch: Arc<std::sync::atomic::AtomicU64>,
}
pub(crate) type SessTable = Arc<ShardedSessTable>;

/// The session-table shard map type. `foldhash` rather than the std default:
/// a session get/insert hashes a 4-byte peer-influenced key, so the hasher
/// must be fast *and* randomly seeded against collision precomputation — see
/// the `foldhash` note in `Cargo.toml`.
pub(crate) type SessMap = HashMap<u32, SessEntry, foldhash::fast::RandomState>;

pub(crate) const SESS_SHARDS: usize = 8;

/// How a connection's session readers validate the source of inbound datagrams.
///
/// A session's relay socket is unconnected, so any host that reaches its
/// ephemeral port could otherwise be forwarded to the client app as the
/// target's answer. The shipped default is [`ReplyFilter::Restricted`]: only
/// sources on the session's recent-destination IP list pass (an
/// address-restricted cone; the port is deliberately not part of the key).
///
/// [`ReplyFilter::FullCone`] is the server's `udp_full_cone` opt-in: the relay
/// accepts any source, which gives the client app the endpoint-independent
/// filtering of a full-cone NAT — and exposes its UDP endpoint to unsolicited
/// internet traffic, which is why it is off by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyFilter {
    /// Only hosts this session has sent to may answer (default).
    Restricted,
    /// Any source may answer (`udp_full_cone = true`).
    FullCone,
}

pub(crate) struct ShardedSessTable {
    pub(crate) shards: Vec<parking_lot::RwLock<SessMap>>,
    /// Reply-source policy shared by every session in this table. A property of
    /// the *connection* (the server-wide `udp_full_cone` is read once at startup
    /// and snapshotted per connection at accept time): a changed config takes
    /// effect after a server restart, and live connections keep the policy they
    /// were accepted with.
    pub(crate) reply_filter: ReplyFilter,
    /// Whether this table is currently counted in [`session_holders`]. Kept in
    /// step by [`ShardedSessTable::note_empty_state`] on every insert/removal
    /// that can change emptiness.
    pub(crate) counted: std::sync::atomic::AtomicBool,
    /// Cached [`ShardedSessTable::len`] plus its sample time (`mono_millis`
    /// epoch). `len` takes all 8 shard read locks, and past the fair-share cap
    /// every forged new-session datagram reaches it — an attacker-drivable
    /// 8-lock amplifier. The cache serves readings up to 1 s old: a stale-high
    /// value refuses for at most 1 s (counted, self-correcting), a stale-low
    /// one admits over the share for at most 1 s (bounded by the global
    /// semaphore plus the per-insert bounded eviction).
    pub(crate) cached_len: std::sync::atomic::AtomicUsize,
    pub(crate) cached_len_ms: std::sync::atomic::AtomicU64,
    /// Inserts since `cached_len` was last refreshed. The sample alone is *not*
    /// a bound: an insert does not touch it, so between two samples the
    /// fair-share gate compared a frozen number and a burst of new sessions
    /// sailed past it — one connection could take every one of the
    /// `MAX_SESSIONS_GLOBAL` permits inside one sample window, and hold them
    /// forever by touching each session every <180 s. `cached_len + since` is a
    /// conservative upper bound (removals only make it larger), so the gate is
    /// exact at the moment it matters; see `len_upper_bound`.
    pub(crate) inserts_since_sample: std::sync::atomic::AtomicUsize,
}

impl ShardedSessTable {
    pub(crate) fn new(reply_filter: ReplyFilter) -> Self {
        Self {
            shards: (0..SESS_SHARDS)
                .map(|_| parking_lot::RwLock::new(SessMap::default()))
                .collect(),
            reply_filter,
            counted: std::sync::atomic::AtomicBool::new(false),
            cached_len: std::sync::atomic::AtomicUsize::new(0),
            cached_len_ms: std::sync::atomic::AtomicU64::new(0),
            inserts_since_sample: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn shard(&self, s: u32) -> &parking_lot::RwLock<SessMap> {
        &self.shards[(s as usize) % SESS_SHARDS]
    }

    /// Keep the process-wide holder count in step with whether this table holds
    /// any session.
    ///
    /// The fair share must divide the global session budget among connections
    /// that actually *hold* sessions. Counting every live QUIC connection made a
    /// client's four idle TCP slots dilute its own UDP connection by 5x (and a
    /// busy server's pool by much more), so a lone client could only ever reach
    /// `8192 / (quic_conns + 1)` associations instead of the documented
    /// `MAX_UDP_ASSOCS`.
    ///
    /// Must be called with **no** guard on any of `self.shards` held —
    /// `is_empty()` takes the shard read locks, and `parking_lot::RwLock` is
    /// not reentrant. Two concurrent calls can transiently mis-count by one (the
    /// emptiness check and the `counted` swap are not one atomic step); the
    /// error self-corrects on the next insert/removal and only ever moves the
    /// share, never a data path.
    pub(crate) fn note_empty_state(&self) {
        use std::sync::atomic::Ordering;
        let any = self.shards.iter().any(|sh| !sh.read().is_empty());
        if any {
            if !self.counted.swap(true, Ordering::AcqRel) {
                session_holders().fetch_add(1, Ordering::AcqRel);
            }
        } else if self.counted.swap(false, Ordering::AcqRel) {
            session_holders().fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Sessions live on this connection. Summed under short read locks; used
    /// only on the session-creation path (never per datagram) to bound one
    /// connection's share of the process-wide session budget.
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|sh| sh.read().len()).sum()
    }

    /// `len` with a bound on how stale it can be, for the fair-share gate.
    ///
    /// The cached sample is refreshed at most once a second, and an insert
    /// deliberately does not touch it (`len` is the 8-lock measurement the cache
    /// exists to avoid). Alone that let a connection outrun its share: the gate
    /// compared a number frozen at the start of the window while the inserts
    /// kept coming, so N forged session ids in one second were all admitted —
    /// the per-shard sweep cannot compensate (its over-cap trim only reaps
    /// sessions already idle for `SESS_IDLE_MS`), and the global semaphore it
    /// fell back on is the pool being monopolized. Every insert is therefore
    /// counted since the sample, making the returned value a conservative upper
    /// bound (removals are not subtracted).
    ///
    /// **Only a stale sample re-measures.** An earlier revision re-measured
    /// whenever the bound reached `cap` "so the gate can never be wrong in the
    /// admitting direction" — but `cached_len` stays at or above `cap` until a
    /// sweep resyncs it, so *every* over-cap new-session datagram paid the
    /// 8-shard read-lock `len()`: an attacker-drivable 8-lock amplifier on the
    /// datagram path, charged exactly where the peer is already over its share.
    /// The bound is enough there — it can only be too high, which refuses — and
    /// the exact number comes from the caller's own sweep window, which
    /// republishes `len` through [`store_len`](Self::store_len) once per second
    /// process-wide. So an over-share connection is still let back in as soon as
    /// its sessions are actually reaped, and no datagram pays 8 locks to learn
    /// that it is refused.
    pub(crate) fn len_upper_bound(&self, now_ms: u64) -> usize {
        use std::sync::atomic::Ordering;
        // Timestamp FIRST, then the pair it timestamps: that ordering is what
        // makes the returned value a bound. A concurrent re-measure below
        // (`inserts_since_sample` reset, then `len()`, then the two publishes)
        // can then be observed either as "stale sample" — in which case this
        // call re-measures too — or as a consistent generation. Reading the
        // counters first and the stamp last would allow the torn combination
        // *old* `cached_len` + *post-reset* `inserts_since_sample` (= 0) +
        // *fresh* stamp, which under-counts and lets one session past the
        // fair-share gate. (`cached_len` and the stamp are two separate atomics,
        // so there is no single-load alternative; the ordering is the guard.)
        let stamp = self.cached_len_ms.load(Ordering::Acquire);
        let est = self
            .cached_len
            .load(Ordering::Acquire)
            .saturating_add(self.inserts_since_sample.load(Ordering::Acquire));
        if now_ms.saturating_sub(stamp) < 1000 {
            return est;
        }
        // Reset the insert counter *before* measuring: an insert racing this
        // window is then either inside `n` or counted in the new generation,
        // never dropped between the two (which would admit one over the share).
        self.inserts_since_sample.store(0, Ordering::Release);
        let n = self.len();
        self.cached_len.store(n, Ordering::Release);
        self.cached_len_ms.store(now_ms, Ordering::Release);
        n
    }

    /// One session inserted on this connection (see `inserts_since_sample`).
    pub(crate) fn note_insert(&self) {
        self.inserts_since_sample
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Publish a freshly measured `len` (call after a sweep actually ran).
    pub(crate) fn store_len(&self, n: usize, now_ms: u64) {
        use std::sync::atomic::Ordering;
        self.cached_len.store(n, Ordering::Release);
        self.cached_len_ms.store(now_ms, Ordering::Release);
        self.inserts_since_sample.store(0, Ordering::Release);
    }

    pub(crate) fn drain_all(&self) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            out.extend(sh.write().drain().map(|(_, v)| v));
        }
        self.note_empty_state();
        out
    }

    pub(crate) fn sweep_all(&self, now: u64) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            let expired: Vec<u32> = {
                let m = sh.read();
                m.iter()
                    .filter(|(_, e)| {
                        now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed))
                            >= SESS_IDLE_MS
                    })
                    .map(|(k, _)| *k)
                    .collect()
            };
            if expired.is_empty() {
                continue;
            }
            let mut m = sh.write();
            out.extend(take_idle(&mut m, &expired, now));
        }
        self.note_empty_state();
        out
    }
}

/// Remove the snapshotted keys that are *still* idle, returning the entries so
/// the caller can abort their readers after the lock is dropped.
///
/// The key list is collected under a read lock, so between the snapshot and
/// this write-locked removal the client can touch the session — or the key can
/// be recreated outright. Removing unconditionally destroyed a live session and
/// aborted its freshly started reader (its socket, its destination memo and the
/// replies in flight went with it). Every key is therefore re-tested against
/// the same `now` before it is removed — and that re-test is needed on *both*
/// sweep paths, not just this one: `sweep_local` scans and removes under one
/// write guard, but a touch lands through the lock-free atomic stamp
/// (`touch_session_throttled` takes no table lock), so it can land between the
/// scan and the removal even with the write guard held.
pub(crate) fn take_idle(w: &mut SessMap, keys: &[u32], now: u64) -> Vec<SessEntry> {
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let idle = w.get(k).is_some_and(|e| {
            now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS
        });
        if idle && let Some(e) = w.remove(k) {
            out.push(e);
        }
    }
    out
}
/// Process-wide UDP session cap. Each session owns a kernel socket with a
/// `SESS_SOCKET_BUF` send buffer and the same again for receive (see
/// `udp_socket_dual_small`), i.e. 64 KiB per direction by default. Linux
/// stores/reports `SO_*BUF` at **twice** the requested value, so a full house
/// (8192 sessions x 2 directions x 2 x 64 KiB) is ~2.06 GiB of kernel caps
/// there, and ~1.03 GiB where the kernel keeps the requested value;
/// `per_session_memory_bytes` charges the doubled figure on Linux.
/// These are caps, not reservations: the kernel only accounts for what is
/// actually queued, but the cap is what a burst can pin.
///
/// (This note has tracked the buffer through its changes — 512 KiB → 256 →
/// 128 → 64 → 32, then a 64 KiB default with a `MYQUIC2_SESS_SOCKET_BUF`
/// override — so the operator-facing bound always matches `sess_socket_buf()`.)
pub(crate) const MAX_SESSIONS_GLOBAL: usize = 8192;
pub(crate) const LOCAL_SESS_MAX: usize = 4096;
pub(crate) const LOCAL_SESS_TARGET: usize = LOCAL_SESS_MAX - 64;
/// The client's per-process UDP-association cap and this connection's static
/// session target are one number, defined once in `lib.rs`: if either drifts,
/// the client admits associations the server will refuse — a silent black hole,
/// because UDP DATAGRAMs carry no back-channel. Fail the build instead.
const _: () = assert!(LOCAL_SESS_TARGET == MAX_UDP_ASSOCS);
pub(crate) const SESS_IDLE_MS: u64 = 180_000;
pub(crate) fn session_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS_GLOBAL)))
}

/// Connections currently holding at least one UDP session, across the process.
///
/// This is the denominator of the per-connection session fair share. It counts
/// *session holders*, not live QUIC connections: a client's idle TCP slots must
/// not dilute its own UDP connection's budget, which is what made a default
/// client (four TCP slots + one UDP slot) cap out at `8192 / 5` sessions instead
/// of [`MAX_UDP_ASSOCS`]. Maintained by
/// [`ShardedSessTable::note_empty_state`].
pub(crate) fn session_holders() -> &'static std::sync::atomic::AtomicUsize {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    &N
}

/// Sessions one connection may hold: its own cap, or an equal share of the
/// process-wide budget across the connections that are *using* it — whichever
/// is smaller. Without the share term, two connections at `LOCAL_SESS_MAX` fill
/// `MAX_SESSIONS_GLOBAL` and every later connection's sessions fail, so one
/// busy client starves the rest.
///
/// The floor is [`MIN_SESSION_SHARE`], not 256. The divisor counts *holders*,
/// and it is trivially cheap to become one: 32 connections that each send a
/// single UDP datagram and then a keepalive every <180 s used to drag every
/// other client's per-connection cap down to `8192 / 32 = 256` — a 16x
/// availability hit bought with 32 mostly-idle connections. At 1024 (1/8 of the
/// global budget) the same gossip still cannot take a legitimate client below
/// an eighth of the pool, and beyond 8 holders the global semaphore becomes the
/// binding constraint (first-come, counted `SESSION_FULL`), which is the honest
/// capacity signal rather than a share nobody can reach.
pub(crate) fn fair_sess_cap() -> usize {
    let holders = session_holders()
        .load(std::sync::atomic::Ordering::Relaxed)
        .max(1);
    (MAX_SESSIONS_GLOBAL / holders).clamp(MIN_SESSION_SHARE, LOCAL_SESS_MAX)
}

/// Lower bound for [`fair_sess_cap`] — see its note on why this is not 256.
pub(crate) const MIN_SESSION_SHARE: usize = 1024;

/// Process-wide throttle for the over-cap `sweep_all` reaps in
/// `get_or_create_sess`: at most one sweep per second across all workers and
/// connections. Per-worker thread-local throttles let W workers run W sweeps
/// per second (each O(sessions)) under a forged-session flood. A refused sweep
/// still refuses the session, counted against the gate that refused it
/// (`FAIR_SHARE` for the per-connection share, `SESSION_FULL` for the global
/// pool); the reap is deferred at most 1 s, and any sweep benefits every
/// connection since all of them reap only expired sessions.
pub(crate) static FAIR_SWEEP_LAST_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Claim the global sweep window for `now_ms`. Exactly one contender wins per
/// second; losers skip the sweep (their session is still refused and counted).
pub(crate) fn claim_fair_sweep(now_ms: u64) -> bool {
    use std::sync::atomic::Ordering;
    let last = FAIR_SWEEP_LAST_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 1000 {
        return false;
    }
    FAIR_SWEEP_LAST_MS
        .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Whether this shard holds at least its fair share of the connection's session
/// budget, i.e. whether an insert should reap its expired sessions *now* instead
/// of waiting for the 60 s sweeper.
///
/// This used to return an over-cap *target* as well, and the caller fed it to a
/// ranked eviction that could never fire: `sweep_local` reaps expired entries
/// through `take_idle` first, and the ranking re-tested exactly the same
/// predicate against the same `now`, so nothing could be left to remove —
/// an O(shard) collect plus `select_nth_unstable` under the shard *write* lock,
/// once per unthrottled sweep, whose result was empty by construction. A live
/// over-share is deliberately not trimmed here (that would abort sessions the
/// client is using, and a client whose sessions are all live is the documented
/// normal case): the resource bound is the connection-level fair-share gate in
/// `get_or_create_sess` (`len_upper_bound`), and this trigger is only the
/// latency half — it frees budget seconds earlier than `sweep_all` would.
pub(crate) fn shard_over_share(shard_len: usize, fair_cap: usize) -> bool {
    // Floored here so no future caller can inherit a zero share (and the
    // trigger with it) from a tiny `fair_cap`; the production caller is
    // already clamped via `fair_sess_cap`, this is defense in depth.
    shard_len >= (fair_cap / SESS_SHARDS).max(1)
}

/// Reap this shard's expired sessions, because the shard is over its fair share.
///
/// Expired only: every session that is still live keeps its socket, its memo and
/// its reader. `take_idle` re-tests idleness against one `now`, so a session the
/// client touched while the scan ran survives (see its note) — the re-test is
/// the whole reason this cannot be an unconditional removal of the scanned keys.
pub(crate) fn sweep_local(w: &mut SessMap) -> Vec<SessEntry> {
    let now = mono_millis();
    let expired: Vec<u32> = w
        .iter()
        .filter(|(_, e)| {
            now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS
        })
        .map(|(k, _)| *k)
        .collect();
    take_idle(w, &expired, now)
}

pub(crate) fn abort_evicted(evicted: Vec<SessEntry>) {
    for e in evicted {
        e.reader.abort();
    }
}

/// The session's pinned destination, if it still has one.
///
/// Lock-free on the common path: the fast path only needs the shard read guard
/// (the same one `get_or_create_sess` takes) and the memo is a `Copy` field, so
/// there is no atomic traffic and no allocation. A memo miss costs the same as
/// any other session-table probe and simply means "resolve and store again".
#[cfg(test)]
pub(crate) fn sess_dest_lookup(
    ss: &SessTable,
    now: u64,
    s: u32,
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    sess_dest_lookup_ttl(ss, now, s, host, port).map(|(a, _)| a)
}

/// [`sess_dest_lookup`] plus the memo's remaining life, so a caller that adopts
/// the memo as its own pin cannot extend it past the memo's deadline.
pub(crate) fn sess_dest_lookup_ttl(
    ss: &SessTable,
    now: u64,
    s: u32,
    host: &str,
    port: u16,
) -> Option<(SocketAddr, u64)> {
    let sh = ss.shard(s);
    if let Some(e) = sh.read().get(&s)
        && let Some(addr) = e.dest.get(now, host, port)
    {
        return Some((addr, e.dest.expires.saturating_sub(now)));
    }
    None
}

/// Record (or refresh) the session's pinned destination. Best effort: a session
/// that vanished between the send and this call is simply not memoized, and the
/// next datagram re-resolves and tries again.
///
/// Read first, write only when the memo actually needs it. The datagram path
/// calls this for every domain-target packet, and the answer for a steady flow
/// is the same `(key, addr)` every time — so an unconditional write lock made
/// every packet of that flow take the shard exclusively. Now a packet whose
/// memo already names the right address and still has more than
/// [`DEST_PIN_REFRESH_MS`] of life left takes only the read lock it would take
/// anyway, and the write happens once per refresh window instead of per packet.
///
/// `remaining_ms` is the *source's* remaining life (a DNS cache entry, another
/// memo, or `DNS_CACHE_TTL_MS` for a fresh resolution); the memo never outlives
/// it — see [`pin_life_ms`].
pub(crate) fn sess_dest_store(
    ss: &SessTable,
    s: u32,
    host: &str,
    port: u16,
    addr: SocketAddr,
    remaining_ms: u64,
) {
    // A name too long for the inline key is not memoized. Storing it under a
    // truncated key would be worse than not storing it: a later datagram for a
    // different name sharing that prefix would match.
    let Some(key) = PortKey::new(host, port) else {
        return;
    };
    // Same coarse epoch `resolve_pin` compares against; a fresher stamp here
    // would only make the memo look shorter-lived than the reader believes.
    let now = coarse_millis();
    {
        let r = ss.shard(s).read();
        if let Some(e) = r.get(&s)
            && e.dest.is_for(host, port, addr)
            && e.dest.expires.saturating_sub(now) > DEST_PIN_REFRESH_MS
        {
            return;
        }
    }
    let mut w = ss.shard(s).write();
    if let Some(e) = w.get_mut(&s) {
        e.dest = DestMemo {
            key,
            addr,
            expires: now + pin_life_ms(remaining_ms),
        };
    }
}
