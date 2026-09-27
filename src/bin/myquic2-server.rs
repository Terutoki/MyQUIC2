//! myquic2-server: QUIC ingress -> TCP/UDP dial-out. BBR+GSO defaults, self-signed TLS13.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-server.toml")]
    config: String,
}

/// One live UDP session: the socket replies are read from, plus the bookkeeping
/// the connection needs to reap it.
///
/// A named struct rather than the 4-tuple this used to be, because the
/// destination memo below is the fifth field and `(Arc<..>, JoinHandle, Arc<..>,
/// OwnedPermit, DestMemo)` destructured at nine call sites is no longer
/// readable — and a mis-ordered tuple here would silently pair a socket with
/// the wrong field.
struct SessEntry {
    sock: Arc<tokio::net::UdpSocket>,
    /// The reply reader. `is_finished` is the liveness signal everywhere.
    reader: tokio::task::JoinHandle<()>,
    /// The session's idle stamp, shared with the memo so a memo hit can refresh
    /// liveness without the table lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// Held for the session's lifetime; dropping it returns the global slot.
    _permit: tokio::sync::OwnedSemaphorePermit,
    /// Per-session destination memo — see [`DestMemo`].
    dest: DestMemo,
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
    /// snapshot (no lock), and writers publish a new 136-byte snapshot through
    /// `rcu`, which also means two concurrent pushes can no longer lose each
    /// other's insert.
    recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
    /// Bumped by every [`remember_dst`] for this session — including the push a
    /// spawned DNS resolver task makes from *its own* task
    /// (`forward_server_dgram`), which is the case the datagram reader cannot
    /// see. The reader's fast path mirrors the allowlist so a steady flow does
    /// not take the shard read lock plus the allowlist mutex per datagram; the
    /// epoch is what keeps that mirror honest when a foreign push evicts a
    /// destination the mirror still claims is recorded (which silently dropped
    /// that destination's replies as forged until the pin and DNS entry both
    /// expired).
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
}

/// Destination IPs a session has recently sent to, for reply-source validation.
///
/// The match is on the **IP only**, not the full `(ip, port)` pair. An earlier
/// revision required the exact pair and thereby broke every protocol whose
/// server answers from a different port than it was queried on: TFTP is the
/// canonical case (the server replies from a fresh ephemeral port by design),
/// and game/voice stacks that redirect to a second port fail the same way. The
/// IP-only rule keeps the property that matters — an off-path attacker must
/// still spoof an address this session actually sent to, and the target's IP is
/// the hard half of that guess — while no longer filtering a legitimate peer on
/// that host.
///
/// A session may legally serve several targets (one association, many
/// datagrams), so this is a small allowlist rather than a single pin; past
/// [`RECENT_DST_CAP`] the oldest entry is evicted and a reply from it is dropped
/// until the session sends there again. Entries are normalized (IPv4 mappings
/// stripped) on both sides of the comparison.
#[derive(Clone, Debug, Default)]
struct RecentAddrs {
    /// Ring of the last [`RECENT_DST_CAP`] destination IPs sent to.
    slots: [Option<IpAddr>; RECENT_DST_CAP],
    /// Next write position.
    pos: usize,
}

/// How many distinct destination IPs one session remembers for reply
/// validation. 16 covers the multi-target session tests (2 alternating targets)
/// with room; a session talking to more distinct hosts concurrently re-learns
/// evicted ones on its next outbound datagram. It was 8, which a session
/// alternating over more than 8 hosts could outrun: a reply from an evicted
/// host was dropped as `REFUSED` until the session sent there again.
const RECENT_DST_CAP: usize = 16;

impl RecentAddrs {
    fn push(&mut self, dst: SocketAddr) {
        let ip = unmap(dst.ip());
        if self.slots.contains(&Some(ip)) {
            return;
        }
        self.slots[self.pos % RECENT_DST_CAP] = Some(ip);
        self.pos = self.pos.wrapping_add(1);
    }

    fn contains(&self, src: &SocketAddr) -> bool {
        self.slots.contains(&Some(unmap(src.ip())))
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }
}

/// Where a session's target address came from, so a domain target is not
/// re-resolved on every datagram.
///
/// The UDP path is per-datagram: without this, a sustained flow to a domain
/// name went through `lookup_cached_fast` (hash + key build + full-key compare)
/// for *every* datagram, whose cost is real — measured at ~6 ns on a memo hit
/// but 15-26 ns/op once the memo's working set exceeds its associativity, which
/// is exactly the many-domains-per-worker case a busy proxy hits. The stream
/// head already pins one destination per quic stream; a session is the same
/// idea one layer down, so the resolution is stored here and every later
/// datagram for the session is a lock-free compare.
///
/// It is keyed on the target *name*, not on the session alone. A session is not
/// bound to one target — a client may send the same session id to a different
/// destination on the next datagram — so a memo that matched on the session
/// alone would answer a datagram naming B with the address resolved for A, and
/// the datagram would be relayed to the wrong target. That failure is silent
/// (replies come back from the wrong host), which is why the name is part of
/// the memo and is compared byte-for-byte, exactly like the DNS memo.
///
/// It is a *hint*, never a substitute for a lookup: it holds no negative state
/// and is ignored when expired, so a name that starts failing or rotates still
/// goes back through the resolver, and a target that moves is picked up within
/// `DEST_PIN_TTL` rather than for the lifetime of the session.
#[derive(Clone, Copy)]
struct DestMemo {
    /// The port and (for a domain target) the name this address was resolved
    /// for. An IP target stores an empty host: it has no name to re-check.
    key: PortKey,
    addr: SocketAddr,
    /// Monotonic deadline ([`mono_millis`] epoch). Read on the datagram path
    /// without a lock; the writer holds the table write lock already.
    expires: u64,
}

/// Domain names up to this length are stored inline in a [`DestMemo`]. Longer
/// names are simply never memoized and take the DNS path every time — a miss,
/// never a mis-route. 64 bytes covers all but a vanishing fraction of real
/// names, and a name longer than the 255-byte wire limit cannot occur here.
const DEST_KEY_BYTES: usize = 64;

/// What a memoized destination is valid *for*: the port always, and the
/// normalized target name when the target was a domain.
#[derive(Clone, Copy)]
struct PortKey {
    host_len: u8,
    host: [u8; DEST_KEY_BYTES],
    port: u16,
}

impl PortKey {
    const EMPTY: Self = Self {
        host_len: 0,
        host: [0; DEST_KEY_BYTES],
        port: 0,
    };

    /// `None` when the name is too long to store inline.
    fn new(host: &str, port: u16) -> Option<Self> {
        if host.len() > DEST_KEY_BYTES {
            return None;
        }
        let mut k = Self::EMPTY;
        k.host_len = host.len() as u8;
        k.host[..host.len()].copy_from_slice(host.as_bytes());
        k.port = port;
        Some(k)
    }

    #[inline]
    fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port
            && self.host_len as usize == host.len()
            && &self.host[..self.host_len as usize] == host.as_bytes()
    }
}

impl DestMemo {
    /// A fresh session has pinned nothing; `expires == 0` can never be `> now`,
    /// so the entry reads as absent without a separate flag.
    const NONE: Self = Self {
        key: PortKey::EMPTY,
        addr: SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        expires: 0,
    };

    /// The memoized address, but only for the target it was resolved for and
    /// only while it is live.
    #[inline]
    fn get(&self, now: u64, host: &str, port: u16) -> Option<SocketAddr> {
        (self.expires > now && self.key.matches(host, port)).then_some(self.addr)
    }

    /// True when this memo already names exactly `addr` for `(host, port)`,
    /// whatever its remaining life. The caller decides whether that life is
    /// short enough to be worth a refresh.
    #[inline]
    fn is_for(&self, host: &str, port: u16, addr: SocketAddr) -> bool {
        self.addr == addr && self.key.matches(host, port)
    }
}

/// How long a resolved destination is reused before it is re-resolved.
///
/// Deliberately shorter than the DNS cache TTL (60 s): DNS answers can change
/// while the cache entry is still live, so this bounds how long a session can
/// keep sending to an address the name no longer resolves to.
const DEST_PIN_TTL_MS: u64 = 30_000;

/// How close to expiry a memo must be before a datagram refreshes it.
///
/// A steady flow stores the same `(key, addr)` on every datagram, so refreshing
/// on each one turned the datagram path into a shard *write* lock per packet
/// (35 ns of lock plus a dirty line in the shared table, measured) for a value
/// that had not changed. Refreshing only in the last quarter of the TTL keeps
/// the entry continuously live with one write per ~7.5 s per session instead.
const DEST_PIN_REFRESH_MS: u64 = DEST_PIN_TTL_MS / 4;

/// The connection's pinned destination: the last `(session, name, port)` a
/// datagram was relayed to, plus the deadline that pin may still be trusted
/// for.
///
/// A per-connection shortcut for the per-session [`DestMemo`], and bounded the
/// same way on purpose. It carries its own deadline and is never refreshed on a
/// hit: a pin with no expiry kept a domain target's address for the whole
/// connection lifetime, so after a DNS change the flow was relayed to the old
/// address with no lookup ever consulted again — silently bypassing
/// [`DEST_PIN_TTL_MS`] for exactly the flow that never missed.
struct ConnPin {
    sess: u32,
    /// Length of the name in [`ConnPin::host`]. `u8` because the wire decoder
    /// caps a domain at 255 bytes.
    host_len: u8,
    /// The pinned name **inline**, up to the wire limit.
    ///
    /// It used to be a `String`, which made arming a pin a heap allocation —
    /// and `resolve_pin` arms on every pin *miss*, i.e. on every datagram of an
    /// interleaved multi-target session, with the reader re-arming the same name
    /// once more per slow path. So the one path this struct exists to keep
    /// cheap paid two malloc/free pairs per packet while the module documents
    /// the domain path as allocation-free. 255 bytes is the largest name the
    /// wire can carry, and the struct lives on the datagram reader's stack (one
    /// per connection), so the inline buffer costs nothing that matters.
    host: [u8; PIN_HOST_BYTES],
    port: u16,
    addr: SocketAddr,
    /// Monotonic deadline ([`mono_millis`] epoch), like [`DestMemo::expires`].
    expires: u64,
}

/// Bytes reserved for a pinned name: the MQP-2 wire limit (`u8` length prefix).
const PIN_HOST_BYTES: usize = 255;

/// Whether `pin` describes exactly `(name, port)`.
///
/// `pin.host_len` is a `u8`, so the comparison is against a slice that is always
/// in bounds, and a name that cannot be stored inline simply never matches.
fn pin_is_for(pin: &ConnPin, host: &str, port: u16) -> bool {
    pin.port == port
        && pin.host_len as usize == host.len()
        && &pin.host[..pin.host_len as usize] == host.as_bytes()
}

/// Arm `pin` for `(s, host, port)` with `life_ms` of life left.
///
/// Allocation-free by construction. A name longer than the inline buffer is not
/// pinned at all rather than truncated: a truncated key could match a different
/// name and mis-route the flow. That is unreachable today — the wire decoder
/// refuses a domain over 255 bytes and an IP target's name is empty — so this is
/// defence in depth, not a policy.
fn pin_arm(
    pin: &mut Option<ConnPin>,
    s: u32,
    host: &str,
    port: u16,
    addr: SocketAddr,
    life_ms: u64,
) {
    if host.len() > PIN_HOST_BYTES {
        return;
    }
    let mut cp = ConnPin {
        sess: s,
        host_len: host.len() as u8,
        host: [0; PIN_HOST_BYTES],
        port,
        addr,
        expires: coarse_millis() + pin_life_ms(life_ms),
    };
    let n = cp.host_len as usize;
    cp.host[..n].copy_from_slice(&host.as_bytes()[..n]);
    *pin = Some(cp);
}

type SessTable = Arc<ShardedSessTable>;

const SESS_SHARDS: usize = 8;

struct ShardedSessTable {
    shards: Vec<std::sync::RwLock<HashMap<u32, SessEntry>>>,
    /// Whether this table is currently counted in [`session_holders`]. Kept in
    /// step by [`ShardedSessTable::note_empty_state`] on every insert/removal
    /// that can change emptiness.
    counted: std::sync::atomic::AtomicBool,
    /// Cached [`ShardedSessTable::len`] plus its sample time (`mono_millis`
    /// epoch). `len` takes all 8 shard read locks, and past the fair-share cap
    /// every forged new-session datagram reaches it — an attacker-drivable
    /// 8-lock amplifier. The cache serves readings up to 1 s old: a stale-high
    /// value refuses for at most 1 s (counted, self-correcting), a stale-low
    /// one admits over the share for at most 1 s (bounded by the global
    /// semaphore plus the per-insert bounded eviction).
    cached_len: std::sync::atomic::AtomicUsize,
    cached_len_ms: std::sync::atomic::AtomicU64,
    /// Inserts since `cached_len` was last refreshed. The sample alone is *not*
    /// a bound: an insert does not touch it, so between two samples the
    /// fair-share gate compared a frozen number and a burst of new sessions
    /// sailed past it — one connection could take every one of the
    /// `MAX_SESSIONS_GLOBAL` permits inside one sample window, and hold them
    /// forever by touching each session every <180 s. `cached_len + since` is a
    /// conservative upper bound (removals only make it larger), so the gate is
    /// exact at the moment it matters; see `len_upper_bound`.
    inserts_since_sample: std::sync::atomic::AtomicUsize,
}

impl ShardedSessTable {
    fn new() -> Self {
        Self {
            shards: (0..SESS_SHARDS)
                .map(|_| std::sync::RwLock::new(HashMap::new()))
                .collect(),
            counted: std::sync::atomic::AtomicBool::new(false),
            cached_len: std::sync::atomic::AtomicUsize::new(0),
            cached_len_ms: std::sync::atomic::AtomicU64::new(0),
            inserts_since_sample: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn shard(&self, s: u32) -> &std::sync::RwLock<HashMap<u32, SessEntry>> {
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
    /// `is_empty()` takes the shard read locks, and `std::sync::RwLock` is not
    /// reentrant. Two concurrent calls can transiently mis-count by one (the
    /// emptiness check and the `counted` swap are not one atomic step); the
    /// error self-corrects on the next insert/removal and only ever moves the
    /// share, never a data path.
    fn note_empty_state(&self) {
        use std::sync::atomic::Ordering;
        let any = self.shards.iter().any(|sh| !lock_read(sh).is_empty());
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
    fn len(&self) -> usize {
        self.shards.iter().map(|sh| lock_read(sh).len()).sum()
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
    /// bound (removals are not subtracted), and the exact `len` is re-measured
    /// as soon as that bound reaches `cap`. Cost: one cached load per insert
    /// under the share, one 8-lock measurement per second per connection — the
    /// same order as before, now with a bound that cannot be outrun.
    fn len_upper_bound(&self, now_ms: u64, cap: usize) -> usize {
        use std::sync::atomic::Ordering;
        // Timestamp first, exactly as the old cache did: a racing writer either
        // makes this look stale (re-measure) or leaves a consistent generation
        // visible.
        if now_ms.saturating_sub(self.cached_len_ms.load(Ordering::Acquire)) < 1000 {
            let est = self
                .cached_len
                .load(Ordering::Acquire)
                .saturating_add(self.inserts_since_sample.load(Ordering::Acquire));
            if est < cap {
                return est;
            }
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
    fn note_insert(&self) {
        self.inserts_since_sample
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Publish a freshly measured `len` (call after a sweep actually ran).
    fn store_len(&self, n: usize, now_ms: u64) {
        use std::sync::atomic::Ordering;
        self.cached_len.store(n, Ordering::Release);
        self.cached_len_ms.store(now_ms, Ordering::Release);
        self.inserts_since_sample.store(0, Ordering::Release);
    }

    fn drain_all(&self) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            out.extend(lock_write(sh).drain().map(|(_, v)| v));
        }
        self.note_empty_state();
        out
    }

    fn sweep_all(&self, now: u64) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            let expired: Vec<u32> = {
                let m = lock_read(sh);
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
            let mut m = lock_write(sh);
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
fn take_idle(w: &mut HashMap<u32, SessEntry>, keys: &[u32], now: u64) -> Vec<SessEntry> {
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let idle = w.get(k).is_some_and(|e| {
            now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS
        });
        if idle {
            if let Some(e) = w.remove(k) {
                out.push(e);
            }
        }
    }
    out
}

/// Hard process-wide bounds: new QUIC connections are refused past this count
/// and new UDP sessions borrow from a shared permit pool, so a single peer
/// cannot exhaust fds/kernel memory (the server is unauthenticated by default).
const MAX_CONNECTIONS: usize = 4096;
/// Concurrent connections that have not completed token authentication.
/// Bounds the receive-window memory an unauthenticated peer can pin while the
/// process-wide cap still allows 4096 *authenticated* connections. With an
/// empty `auth_token` every peer is implicitly authenticated, so this cap is a
/// no-op and the operator must rely on the firewall + the lowered transport
/// windows.
const MAX_UNAUTH_CONNECTIONS: usize = 256;
/// Process-wide UDP session cap. Each session owns a kernel socket with a
/// `SESS_SOCKET_BUF` send buffer and the same again for receive (see
/// `udp_socket_dual_small`), i.e. 256 KiB per direction, so 8192 sessions bound
/// the kernel side to ~4 GiB worst case instead of ~32 GiB. These are caps,
/// not reservations: the kernel only accounts for what is actually queued,
/// but the cap is what a burst can pin.
///
/// (This said "512KB send + 512KB receive … ~8GB" until `SESS_SOCKET_BUF` was
/// halved from 512 KiB to 256 KiB; `lib.rs`'s own note on that constant was
/// updated at the time and this one was not, so the number an operator would
/// size a router against was double the real bound.)
const MAX_SESSIONS_GLOBAL: usize = 8192;
const LOCAL_SESS_MAX: usize = 4096;
const LOCAL_SESS_TARGET: usize = LOCAL_SESS_MAX - 64;
/// The client's per-process UDP-association cap and this connection's static
/// session target are one number, defined once in `lib.rs`: if either drifts,
/// the client admits associations the server will refuse — a silent black hole,
/// because UDP DATAGRAMs carry no back-channel. Fail the build instead.
const _: () = assert!(LOCAL_SESS_TARGET == MAX_UDP_ASSOCS);
const SESS_IDLE_MS: u64 = 180_000;
/// Process-wide cap on concurrent TCP dials. Per-connection caps alone cannot
/// bound fd usage when an unauthenticated peer can open many connections.
const MAX_DIALS_GLOBAL: usize = 4096;
/// Wall-clock budget for the handshake wait of a connection that holds
/// one of the [`MAX_UNAUTH_CONNECTIONS`] slots. The token exchange gets its
/// own fresh [`AUTH_TIMEOUT`] deadline re-armed after the handshake completes,
/// so a slow handshake cannot consume the authentication budget and fail a
/// healthy client with `unauthorized`. Without re-arming, one 5 s deadline for
/// both phases let handshake latency starve the token read.
const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Fresh budget for the token exchange (`accept_uni` + token read) once the
/// handshake has completed. Re-armed from handshake completion — no extra RTT,
/// only a deadline re-arm — and the pre-auth slot stays held until
/// `authenticate` returns.
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for completing the QUIC handshake when **no** pre-auth slot is held
/// (`auth_token` unset, so there is no memory budget to defend). With
/// authentication enabled, [`PRE_AUTH_TIMEOUT`] bounds the handshake instead.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn session_limiter() -> &'static Arc<tokio::sync::Semaphore> {
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
fn session_holders() -> &'static std::sync::atomic::AtomicUsize {
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
fn fair_sess_cap() -> usize {
    let holders = session_holders()
        .load(std::sync::atomic::Ordering::Relaxed)
        .max(1);
    (MAX_SESSIONS_GLOBAL / holders).clamp(MIN_SESSION_SHARE, LOCAL_SESS_MAX)
}

/// Lower bound for [`fair_sess_cap`] — see its note on why this is not 256.
const MIN_SESSION_SHARE: usize = 1024;

/// Process-wide throttle for the over-cap `sweep_all` reaps in
/// `get_or_create_sess`: at most one sweep per second across all workers and
/// connections. Per-worker thread-local throttles let W workers run W sweeps
/// per second (each O(sessions)) under a forged-session flood. A refused sweep
/// still refuses the session, counted against the gate that refused it
/// (`FAIR_SHARE` for the per-connection share, `SESSION_FULL` for the global
/// pool); the reap is deferred at most 1 s, and any sweep benefits every
/// connection since all of them reap only expired sessions.
static FAIR_SWEEP_LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Claim the global sweep window for `now_ms`. Exactly one contender wins per
/// second; losers skip the sweep (their session is still refused and counted).
fn claim_fair_sweep(now_ms: u64) -> bool {
    use std::sync::atomic::Ordering;
    let last = FAIR_SWEEP_LAST_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 1000 {
        return false;
    }
    FAIR_SWEEP_LAST_MS
        .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

fn dial_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_DIALS_GLOBAL)))
}

/// TCP dial refusal counters, kept separate so a dial-permit exhaustion flood
/// is distinguishable from a dial-connect failure in debug logs (same split
/// the stream_task_limiter fail-fast path reports via its own reset code).
static DIAL_PERMIT_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DIAL_CONNECT_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-wide cap on concurrently handled QUIC bidi streams. The transport's
/// per-connection stream credit ([`MAX_BIDI_STREAMS_PER_CONN`], now 8192 so one
/// admitted client can never stall in `open_bi`) times the connection cap is far
/// more live stream tasks than any host wants; this bounds the worst case to a
/// fixed number of tasks, and excess streams are reset by the accept loop. The
/// permit covers the dial/auth work only — the 5 s header read runs before it
/// is acquired, so trickle headers cannot exhaust the pool.
const MAX_STREAM_TASKS: usize = 16_384;

/// Lower bound on one connection's share of [`MAX_STREAM_TASKS`].
///
/// Two connections can open [`MAX_BIDI_STREAMS_PER_CONN`] = 8192 streams each —
/// more than the whole process-wide pool — so without a per-connection share the
/// first two peers to arrive consume every stream-task permit and every other
/// client's CONNECT is reset (the reset is a *stream* failure, after the client
/// already answered SOCKS optimistically, so the app sees a broken flow with no
/// server-side counter behind it). The share is `MAX_STREAM_TASKS` divided by the
/// admitted connection count, floored here: becoming a connection is cheap, so a
/// crowd of mostly-idle peers must not push a real client down to a handful of
/// flows. At 1024 the floor is also what makes the divisor's precision secondary
/// — above 16 admitted connections the global semaphore is the binding
/// constraint, exactly as it is for UDP sessions ([`MIN_SESSION_SHARE`]).
const MIN_STREAM_SHARE: usize = 1024;

/// Stream-task permits refused by the *per-connection* share rather than by the
/// process-wide pool. Split out because the two mean different things: the global
/// pool being empty is "the host is at capacity", this is "one peer took its
/// share and then some".
static STREAM_SHARE_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One stream's admission reservation: decrements its connection's held-stream
/// count on every exit path, including the `reset` early returns and unwinding.
struct StreamShareGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for StreamShareGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// One connection's share of the process-wide stream-task pool.
///
/// `admitted` is the number of connections currently admitted (the accept loop
/// holds one permit each). The `MIN_STREAM_SHARE` floor is what keeps the
/// divisor's precision secondary: past 16 admitted connections the global
/// semaphore is the binding constraint, exactly as it is for UDP sessions.
/// Pure so the arithmetic — and the floor that makes it safe — is testable
/// without a live connection.
fn stream_share(admitted: usize) -> usize {
    (MAX_STREAM_TASKS / admitted.max(1)).clamp(MIN_STREAM_SHARE, MAX_BIDI_STREAMS_PER_CONN as usize)
}

/// Rate limit for the per-connection stream-share refusal line (1/s, with a
/// suppressed count, like the other per-flow abort logs).
fn warn_stream_share_refused() -> bool {
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
            tracing::warn!("tcp stream-share refusals suppressed in the last window: {n}");
        }
        true
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

fn stream_task_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_STREAM_TASKS)))
}

/// One-way token authentication: the client opens a uni stream and writes the
/// configured shared secret before any other traffic. Empty = disabled.
const AUTH_MAX_BYTES: usize = 256;

async fn authenticate(
    conn: &quinn::Connection,
    expected: &[u8],
    deadline: tokio::time::Instant,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let got = tokio::time::timeout_at(deadline, async {
        let mut uni = conn.accept_uni().await?;
        uni.read_to_end(AUTH_MAX_BYTES)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .context("auth timeout")??;
    if !ct_eq(&got, expected) {
        anyhow::bail!("auth token mismatch");
    }
    Ok(())
}

/// Constant-time token compare that never short-circuits on the first
/// mismatching byte: mismatched lengths contribute a single flag and the loop
/// runs over `max(len)` bytes with zero padding.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Length inequality is folded in as a 0/1 flag: casting `(len_a ^ len_b)`
    // to u8 could wrap to 0 for lengths 256 apart (e.g. 256 vs 0) and compare
    // equal if every common byte matched. Only *whether* the lengths differ
    // is revealed, never the token bytes.
    let mut diff = if a.len() == b.len() { 0u8 } else { 1u8 };
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Rate limit for "refusing new connection" logs under a flood.
fn warn_once_per_sec() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        return false;
    }
    LAST.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Rate limit for session-socket setup failures (fd or memory exhaustion).
/// A separate slot from [`warn_once_per_sec`] on purpose: an fd-exhaustion
/// storm must not silence the connection-limit warning, and vice versa.
fn warn_sess_create_failed() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        return false;
    }
    LAST.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Rate limit for per-flow abort lines: the `conn.stats()` snapshot takes the
/// quinn connection-state mutex, so an abort storm must not pay it per flow.
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

/// Connection cap actually admitted, i.e. `conn_cap` bounded by the optional
/// peer-memory budget.
///
/// `per_conn_bytes` is [`per_connection_memory_bytes`] for this server's
/// effective transport tuning, so raising the windows admits proportionally
/// fewer connections instead of silently multiplying the memory ceiling. A
/// budget too small for even one connection clamps to one rather than zero: an
/// endpoint that admits nothing cannot be diagnosed from the outside.
///
/// Pure so the arithmetic is testable without a live endpoint.
fn admission_cap(conn_cap: usize, budget_mb: Option<u64>, per_conn_bytes: u64) -> usize {
    let by_count = conn_cap.max(1);
    match budget_mb {
        None => by_count,
        Some(mb) => {
            let budget = mb.clamp(1, 1 << 20).saturating_mul(1024 * 1024);
            let by_memory = (budget / per_conn_bytes.max(1)).max(1);
            by_count.min(usize::try_from(by_memory).unwrap_or(usize::MAX))
        }
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
    let c: ServerConf = load_toml(&a.config)?;
    if c.auth_token.len() > AUTH_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_MAX_BYTES} B wire cap (server only reads the first {AUTH_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
        );
    }
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let listen: SocketAddr = c.listen.parse().context("bad listen")?;

    if is_placeholder_token(&c.auth_token) {
        warn!("auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)");
    }
    // Self-signed cert: auto-generate on first run (fast path, no external CA RTT).
    // Regenerate only when BOTH files are absent: silently recreating one over
    // an existing counterpart would invalidate every client's pinned cert.
    let cert_exists = Path::new(&c.cert_file).exists();
    let key_exists = Path::new(&c.key_file).exists();
    match (cert_exists, key_exists) {
        (true, true) => {}
        (false, false) => {
            info!("generating self-signed cert for {}", c.server_name);
            gen_self_signed_files(&c.server_name, &c.cert_file, &c.key_file)?;
        }
        _ => anyhow::bail!(
            "cert/key pair incomplete: cert_file {} and key_file {}; refusing to overwrite \
             the surviving file (restore the missing one, or delete both to regenerate)",
            if cert_exists { "exists" } else { "is missing" },
            if key_exists { "exists" } else { "is missing" }
        ),
    }
    let cert = load_cert_der(&c.cert_file)?;
    let key = load_key_der(&c.key_file)?;
    let tls = server_tls_config(cert, key, &c.alpn_bytes())?;
    if c.alpn.as_deref().is_some_and(|s| !s.is_empty()) {
        info!("custom ALPN in use (masquerade: skew guard weakened, upgrade both sides together)");
    }
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let tuning = c.tuning();
    scfg.transport_config(build_transport_tuned(
        &c.congestion,
        c.keep_alive_secs,
        tuning,
    ));
    // Dual-stack QUIC socket: explicit V6ONLY=0 so [::] also serves IPv4-mapped clients.
    let rt = Arc::new(quinn::TokioRuntime);
    let std_sock = udp_socket_dual(&c.listen)?;
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(scfg),
        rt.wrap_udp_socket(std_sock)?,
        rt,
    )?;
    info!(
        "server listening on {listen} congestion={} gso_auto={} (quinn-udp probes UDP_SEGMENT/GRO)",
        c.congestion, c.gso
    );
    if !c.gso {
        warn!("gso=false requested: quinn still uses GRO/GSO if kernel supports; set only affects logging");
    }
    let auth_token = Arc::new(c.auth_token.clone().into_bytes());
    let auth_enabled = !auth_token.is_empty();
    // Admission: a connection *count* cap plus — when configured — a
    // peer-pinnable *memory* cap. Both are needed and neither is redundant: a
    // count alone cannot bound memory (each admitted connection may hold its
    // receive window, its send budget and both DATAGRAM buffers, all of which a
    // peer controls), while a memory bound alone cannot bound fds/tasks.
    let conn_cap = c
        .max_connections
        .unwrap_or(if auth_enabled {
            MAX_CONNECTIONS
        } else {
            // With no token every peer is unauthenticated, so the pre-auth budget
            // *is* the connection budget: the shipped default must not admit
            // `MAX_CONNECTIONS` x windows of pinnable memory just because the
            // pre-auth slot is only held during the handshake.
            MAX_UNAUTH_CONNECTIONS
        })
        .clamp(1, MAX_CONNECTIONS);
    let per_conn_bytes = per_connection_memory_bytes(&tuning);
    let cap = admission_cap(conn_cap, c.max_peer_memory_mb, per_conn_bytes);
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(cap));
    let pending_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UNAUTH_CONNECTIONS.min(cap)));
    let worst_mib = (per_conn_bytes as u128 * cap as u128) / (1024 * 1024);
    info!(
        "admission: up to {cap} connection(s); worst case {worst_mib} MiB pinned \
         ({per_conn_bytes} B/connection, auth={}, configured cap={conn_cap}{})",
        if auth_enabled { "on" } else { "off" },
        match c.max_peer_memory_mb {
            Some(mb) => format!(", memory budget {mb} MiB"),
            None => String::new(),
        }
    );
    if worst_mib > 1024 {
        warn!(
            "admission: worst case {worst_mib} MiB of peer-pinnable memory at {cap} \
             connection(s); set max_peer_memory_mb (e.g. 128) on a host with less RAM than that"
        );
    }
    if !auth_enabled
        && c.max_connections
            .is_some_and(|n| n > MAX_UNAUTH_CONNECTIONS)
    {
        warn!(
            "max_connections={conn_cap} on a tokenless endpoint: every admitted peer is \
             unauthenticated, and each one may pin {per_conn_bytes} B of this host's memory"
        );
    }
    if let Some(mb) = c.max_peer_memory_mb {
        if cap < conn_cap {
            info!(
                "memory budget {mb} MiB binds the connection cap: {cap} of {conn_cap} \
                 admitted (raise max_peer_memory_mb or lower the windows to admit more)"
            );
        }
    }
    if !auth_enabled {
        warn!("auth_token is empty: the QUIC endpoint accepts any peer (rely on firewall/network isolation)");
        // Spell out the shipped-default combination, because each half looks
        // benign alone: with no token `allow_private` lets any peer make this
        // host dial its own loopback/LAN (the router's admin UI included), and
        // the admission budget is the tokenless one above.
        if c.allow_private && !listen.ip().is_loopback() {
            warn!(
                "open-proxy posture: auth_token is empty AND allow_private = true AND \
                 listen = {listen} (not loopback) — any host that can reach this port gets \
                 an unauthenticated proxy into loopback/LAN targets; set auth_token, bind \
                 loopback, or firewall the port"
            );
        }
    } else {
        info!("client token authentication enabled");
    }
    spawn_udp_reporter();
    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => {
                error!("QUIC endpoint driver stopped (socket failure?); exiting");
                break;
            }
        };
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if warn_once_per_sec() {
                    warn!("connection limit {cap} reached; refusing new connection");
                }
                drop(incoming); // implicit refuse
                continue;
            }
        };
        // Bound pre-auth receive-window memory: a peer that never sends a
        // token must not pin the whole MAX_CONNECTIONS budget. Released as
        // soon as `authenticate` returns.
        let pending = if auth_enabled {
            match pending_limit.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    if warn_once_per_sec() {
                        warn!(
                            "pre-auth connection limit {MAX_UNAUTH_CONNECTIONS} reached; refusing"
                        );
                    }
                    drop(incoming);
                    continue;
                }
            }
        } else {
            None
        };
        let allow_private = c.allow_private;
        let auth_token = auth_token.clone();
        // Read by `handle_conn` to size this connection's share of the
        // process-wide stream-task pool (a clone per accepted connection).
        let conn_limit_for_conn = conn_limit.clone();
        // One deadline for the handshake while a slot is held (see
        // `PRE_AUTH_TIMEOUT`); without a token there is no slot to free and the
        // more generous handshake budget applies. The token exchange below gets
        // a fresh `AUTH_TIMEOUT` deadline re-armed after the handshake, so a
        // slow handshake cannot starve it.
        let handshake_budget = if pending.is_some() {
            PRE_AUTH_TIMEOUT
        } else {
            HANDSHAKE_TIMEOUT
        };
        let deadline = tokio::time::Instant::now() + handshake_budget;
        // Accept + handshake per connection: never await a handshake inline, or
        // one slow/malicious client stalls every other new connection.
        tokio::spawn(async move {
            let _permit = permit;
            // 0.5-RTT accept: streams usable before handshake completes on resumption.
            let conn = match incoming.accept() {
                Ok(connecting) => match connecting.into_0rtt() {
                    Ok((c, accepted_fut)) => {
                        // Incoming conversion always succeeds and `accepted`
                        // always resolves true, but an unfinished handshake
                        // must not hold the connection permit: awaiting it
                        // (bounded) gates the permit on handshake completion.
                        // A dead client resolves false via the channel close,
                        // and the timeout backstops a stall; either way the
                        // close_reason check keeps a dead handle out.
                        match tokio::time::timeout_at(deadline, accepted_fut).await {
                            Ok(_) if c.close_reason().is_none() => c,
                            Ok(_) => {
                                warn!("client handshake failed: {:?}", c.close_reason());
                                return;
                            }
                            Err(_) => {
                                warn!("handshake timed out after {handshake_budget:?}");
                                return;
                            }
                        }
                    }
                    Err(connecting) => match tokio::time::timeout_at(deadline, connecting).await {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            warn!("accept err: {e:#}");
                            return;
                        }
                        Err(_) => {
                            warn!("handshake timed out after {handshake_budget:?}");
                            return;
                        }
                    },
                },
                Err(e) => {
                    warn!("accept err: {e:#}");
                    return;
                }
            };
            if let Err(e) = authenticate(
                &conn,
                &auth_token,
                tokio::time::Instant::now() + AUTH_TIMEOUT,
            )
            .await
            {
                warn!("auth failed from {}: {e:#}", conn.remote_address());
                conn.close(0x01u32.into(), b"unauthorized");
                return;
            }
            // Authentication done: free the pre-auth slot so other new peers
            // can handshake while this connection lives on.
            drop(pending);
            if let Err(e) = handle_conn(conn, allow_private, conn_limit_for_conn, cap).await {
                warn!("conn end: {e:#}");
            }
        });
    }
    Ok(())
}

/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
fn spawn_udp_reporter() {
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
                    "udp reassembly (60s): {} expired (missing fragment), {} evicted (memory cap)",
                    now_r.0.saturating_sub(prev_r.0),
                    now_r.1.saturating_sub(prev_r.1)
                );
                prev_r = now_r;
            }
            let now_d = dgram_drops::snapshot();
            let dd = now_d.since(&prev_d);
            // The budget paths only: `too_large`/`buffer_full` have their own
            // rate-limited per-packet warning and would double-report here.
            if dd.session_full > 0
                || dd.fair_share > 0
                || dd.dns_inflight > 0
                || dd.dns_contention > 0
                || dd.sess_create_failed > 0
                || dd.refused > 0
            {
                info!(
                    "udp budget (60s): {} dropped (session/DNS cap), {} dropped (connection fair share), {} dropped (resolution in flight), {} dropped (DNS lock contention), {} dropped (session setup failed), {} refused (policy); totals too_large={} buffer_full={} session_full={} fair_share={} dns_inflight={} dns_contention={} sess_create_failed={} refused={}",
                    dd.session_full,
                    dd.fair_share,
                    dd.dns_inflight,
                    dd.dns_contention,
                    dd.sess_create_failed,
                    dd.refused,
                    now_d.too_large,
                    now_d.buffer_full,
                    now_d.session_full,
                    now_d.fair_share,
                    now_d.dns_inflight,
                    now_d.dns_contention,
                    now_d.sess_create_failed,
                    now_d.refused
                );
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
        }
    });
}

async fn handle_conn(
    conn: quinn::Connection,
    allow_private: bool,
    conn_limit: Arc<tokio::sync::Semaphore>,
    conn_cap: usize,
) -> Result<()> {
    info!("new QUIC conn from {}", conn.remote_address());
    let conn_id = next_conn_id();
    // One UDP socket per sess_id: replies are inherently demuxed, concurrent
    // ASSOCIATEs sharing this QUIC connection never cross-talk.
    // The connection joins the fair-share denominator only once it actually
    // holds a session (`ShardedSessTable::note_empty_state`); an idle TCP-only
    // connection must not dilute anyone's session budget.
    let sess: SessTable = Arc::new(ShardedSessTable::new());
    {
        let sess = sess.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        // Shard-by-shard sweep, abort after all locks drop.
                        let evicted = sess.sweep_all(now);
                        abort_evicted(evicted);
                    }
                    _ = conn.closed() => {
                        let drained = sess.drain_all();
                        abort_evicted(drained);
                        break;
                    }
                }
            }
        });
    }
    // Uni streams carry only the auth token, which `authenticate` already
    // consumed. Without a reader quinn would buffer up to the whole connection
    // receive window for extra uni streams, so drain and refuse them explicitly.
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut uni) = conn.accept_uni().await {
                let _ = uni.stop(0u32.into());
            }
        });
    }
    // QUIC DATAGRAMs -> per-sess UDP sockets
    let cd = conn.clone();
    let ss = sess.clone();
    tokio::spawn(async move {
        // One receive future per connection instead of one per datagram:
        // `read_datagram` is cancel-safe (a buffered datagram is returned before
        // its first await point), and its `Notify` is inline, so rebuilding it
        // per packet was pure overhead. The connection-state mutex that quinn
        // takes per datagram still applies — that part is inside quinn.
        let reader = cd.read_datagram();
        tokio::pin!(reader);
        // Large app datagrams arrive as MQP-2 fragments; reassemble before they
        // reach a target socket, so the target sees the datagram the app sent.
        let mut reasm = DgramReassembler::new();
        // The reassembler can only expire state it is asked about, and `push` is
        // reached only when a fragment arrives — so a peer that sends fragments
        // and then goes quiet (its connection stays alive on keepalives) would pin
        // its partials for the connection's lifetime. This tick is what makes
        // `FRAG_TIMEOUT_MS` a real deadline.
        let mut reasm_tick = tokio::time::interval(Duration::from_millis(FRAG_SWEEP_INTERVAL_MS));
        reasm_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Per-connection fast path: the thread-local memo is shared by every
        // connection on this worker, so a burst to one session still pays two
        // RefCell scans per packet. This slot lives in the reader task itself.
        let mut fast_sess: u32 = u32::MAX;
        // **Weak**, exactly like [`SessMemo::sock`], and for the same reason: a
        // strong handle here is a second owner of the session's socket, and it
        // outlives the session. The 180 s sweeper removes the table entry and
        // aborts the reply reader, which drops both of *their* handles — but a
        // strong `fast_sock` would keep the socket (and its 2 x 256 KiB kernel
        // buffers) alive outside the `MAX_SESSIONS_GLOBAL` budget until the next
        // datagram on this connection happened to take the slow path, or until
        // the connection closed. `abort.is_finished()` already stops the fast
        // path from *using* such a socket, so retaining it bought nothing. An
        // `upgrade` that fails is also the sharpest possible liveness signal: the
        // session is gone, and the datagram falls through to the slow path, which
        // recreates it.
        let mut fast_sock: Option<std::sync::Weak<tokio::net::UdpSocket>> = None;
        let mut fast_last: Option<Arc<std::sync::atomic::AtomicU64>> = None;
        let mut fast_abort: Option<tokio::task::AbortHandle> = None;
        // The session's allowlist epoch, so a re-record happens whenever a push
        // this reader did not make (a spawned resolver task's) moved the
        // allowlist out from under the mirror below.
        let mut fast_epoch: Option<Arc<std::sync::atomic::AtomicU64>> = None;
        // The address the pinned session resolves to, so a domain target's
        // datagrams skip the DNS lookup entirely instead of paying a hash, a
        // key build and a key compare on every packet. Only meaningful while
        // `fast_sess` names the session it was resolved for; it is cleared
        // whenever the pin is, and it expires on its own — see [`ConnPin`].
        let mut fast_pin: Option<ConnPin> = None;
        // Last destination recorded into the session's reply allowlist on this
        // fast path. The allowlist update takes the table read lock, so it runs
        // only when the destination actually changed (steady single-target
        // flows pay nothing after the first datagram).
        let mut fast_last_dst: Option<(u32, SocketAddr, u64)> = None;
        loop {
            let d: Bytes = tokio::select! {
                r = reader.as_mut() => match r {
                    Ok(d) => d,
                    Err(_) => break,
                },
                _ = reasm_tick.tick() => {
                    reasm.expire(mono_millis());
                    continue;
                }
            };
            // `d` is already owned (from `read_datagram`), so payload slices borrow
            // it directly: one refcount bump per slice, no extra clone per packet.
            // (`decode_*_ref` borrows are shared, coexisting with `slice`.)
            if d.first() == Some(&MQP_DGRAM_FRAG) {
                let Ok(f) = decode_fragment(&d) else {
                    continue;
                };
                let Some((s, a, whole)) = reasm.push(&f, mono_millis()) else {
                    continue;
                };
                udp_stats::payload(whole.len());
                // One resolution for this datagram: the session's own pin, else
                // the DNS cache. A domain target whose session is already pinned
                // never reaches `forward_server_dgram` at all.
                let want = match a.as_ref() {
                    TargetAddrRef::Ip(dst) => Some(dst),
                    TargetAddrRef::Domain(h, p) => {
                        resolve_pin(&ss, &mut fast_pin, fast_sess, s, h, p, allow_private)
                    }
                };
                if let Some(dst) = want {
                    let mut fast_hit = false;
                    if s == fast_sess {
                        if let (Some(sock), Some(last), Some(ab)) =
                            (fast_sock.as_ref(), fast_last.as_ref(), fast_abort.as_ref())
                        {
                            if !ab.is_finished() && (allow_private || is_global_ip_cached(dst.ip()))
                            {
                                // A failed upgrade means the session exited since
                                // the handle check; treat it as a miss so the slow
                                // path rebuilds the slot, and note that it is the
                                // *only* signal that releases the socket — see
                                // `fast_sock`.
                                if let Some(sock) = sock.upgrade() {
                                    touch_session_throttled(conn_id, s, last);
                                    // Record *before* the send: the reply reader
                                    // validates the source against this
                                    // allowlist, and a failable fast path (a
                                    // local echo target, a LAN DNS resolver)
                                    // can answer inside the window between the
                                    // two calls. `forward_server_dgram` has
                                    // always ordered it this way.
                                    mirror_record(
                                        &ss,
                                        &mut fast_last_dst,
                                        s,
                                        dst,
                                        fast_epoch.as_deref(),
                                    );
                                    udp_try_send(&sock, map_for_dual(dst), whole.clone());
                                    fast_hit = true;
                                }
                            }
                        }
                    }
                    if fast_hit {
                        continue;
                    }
                }
                // The slow path records destinations itself, so this task-local
                // mirror of the allowlist can no longer describe it: clear it so
                // the next fast-path send re-records. Without this a destination
                // pushed by the slow path can fall out of `RecentAddrs` (8
                // entries) while `fast_last_dst` still claims it is present, and
                // that destination's replies are dropped as REFUSED until it is
                // sent to again.
                fast_last_dst = None;
                let used =
                    forward_server_dgram(&ss, &cd, conn_id, s, a.as_ref(), whole, allow_private)
                        .await;
                if let Some((dst, life)) = used {
                    match sess_memo_lookup(conn_id, s) {
                        SessHit::Fresh(sock, last, ab, epoch) => {
                            fast_sess = s;
                            fast_sock = Some(Arc::downgrade(&sock));
                            fast_last = Some(last);
                            fast_abort = Some(ab);
                            fast_epoch = Some(epoch.clone());
                            let (ph, pp) = target_name(a.as_ref());
                            pin_arm(&mut fast_pin, s, ph, pp, dst, life);
                        }
                        SessHit::Stale | SessHit::Miss => {
                            fast_sess = u32::MAX;
                            fast_sock = None;
                            fast_last = None;
                            fast_abort = None;
                            fast_epoch = None;
                            fast_pin = None;
                            fast_last_dst = None;
                        }
                    }
                }
            } else {
                let Ok((s, a, p)) = decode_datagram_ref(&d) else {
                    continue;
                };
                let want = match a {
                    TargetAddrRef::Ip(dst) => Some(dst),
                    TargetAddrRef::Domain(h, p) => {
                        resolve_pin(&ss, &mut fast_pin, fast_sess, s, h, p, allow_private)
                    }
                };
                if let Some(dst) = want {
                    let mut fast_hit = false;
                    if s == fast_sess {
                        if let (Some(sock), Some(last), Some(ab)) =
                            (fast_sock.as_ref(), fast_last.as_ref(), fast_abort.as_ref())
                        {
                            if !ab.is_finished() && (allow_private || is_global_ip_cached(dst.ip()))
                            {
                                // See the fragment branch above, and `fast_sock`.
                                if let Some(sock) = sock.upgrade() {
                                    let off = d.len() - p.len();
                                    udp_stats::payload(p.len());
                                    touch_session_throttled(conn_id, s, last);
                                    // Record before the send — see the fragment
                                    // branch above.
                                    mirror_record(
                                        &ss,
                                        &mut fast_last_dst,
                                        s,
                                        dst,
                                        fast_epoch.as_deref(),
                                    );
                                    udp_try_send(&sock, map_for_dual(dst), d.slice(off..));
                                    fast_hit = true;
                                }
                            }
                        }
                    }
                    if fast_hit {
                        continue;
                    }
                }
                // Keep the allowlist mirror honest across the slow path — see
                // the fragment branch above.
                fast_last_dst = None;
                let off = d.len() - p.len();
                let payload = d.slice(off..);
                udp_stats::payload(payload.len());
                let used =
                    forward_server_dgram(&ss, &cd, conn_id, s, a, payload, allow_private).await;
                if let Some((dst, life)) = used {
                    match sess_memo_lookup(conn_id, s) {
                        SessHit::Fresh(sock, last, ab, epoch) => {
                            fast_sess = s;
                            fast_sock = Some(Arc::downgrade(&sock));
                            fast_last = Some(last);
                            fast_abort = Some(ab);
                            fast_epoch = Some(epoch.clone());
                            let (ph, pp) = target_name(a);
                            pin_arm(&mut fast_pin, s, ph, pp, dst, life);
                        }
                        SessHit::Stale | SessHit::Miss => {
                            fast_sess = u32::MAX;
                            fast_sock = None;
                            fast_last = None;
                            fast_abort = None;
                            fast_epoch = None;
                            fast_pin = None;
                            fast_last_dst = None;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // TCP: one QUIC bidi stream per connection. First bytes = MQP addr header.
    // Concurrent streams are already capped by the transport; dials are bounded
    // process-wide (not per connection) so many connections cannot exhaust fds
    // together.
    //
    // The *stream-task* pool is process-wide too, and one connection may open
    // `MAX_BIDI_STREAMS_PER_CONN` (8192) streams — more than the whole pool — so
    // each connection also has to stay inside its own share of it. Without this,
    // the first two peers to arrive hold every permit while their flows sit idle
    // and every other client's CONNECT is reset after its SOCKS success
    // reply — with nothing logged server-side. The 5 s header read runs before
    // either pool is touched (see `handle_tcp_stream`), so a stream that never
    // sends its header parks only its own task for the budget instead of a
    // permit plus a share slot, and the trickle treadmill is no longer cheap.
    let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => break,
        };
        // Admitted connections (the accept loop holds one permit each). The
        // denominator is this endpoint's actual cap, which the admission budget
        // may have lowered, not `MAX_CONNECTIONS`.
        let admitted = conn_cap
            .saturating_sub(conn_limit.available_permits())
            .max(1);
        let share = stream_share(admitted);
        let stat_conn = conn.clone();
        // One task per accepted stream, bounded by the transport's
        // per-connection stream credit — never by the pools below. The task
        // reads the header before touching either pool.
        tokio::spawn(handle_tcp_stream(
            send,
            recv,
            streams_held.clone(),
            share,
            admitted,
            allow_private,
            stat_conn,
        ));
    }
    Ok(())
}

/// One accepted TCP bidi stream: header first, admission second, dial last.
///
/// The 5 s header read runs *before* the per-connection share check and the
/// process-wide stream-task permit, and holds neither: a stream that trickles
/// one byte per 4.9 s parks only its own task for the budget instead of a
/// `MAX_STREAM_TASKS` permit plus a share slot, so a slowloris treadmill can
/// no longer exhaust the pool. Spawning is still bounded — one task per
/// accepted stream, capped by the transport's per-connection stream credit —
/// and the share/permit are taken fail-fast (`try_acquire`, `0x05` reset) once
/// the header is in, so they bound only the dial/auth work.
async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    streams_held: Arc<std::sync::atomic::AtomicUsize>,
    share: usize,
    admitted: usize,
    allow_private: bool,
    stat_conn: quinn::Connection,
) {
    let target: TargetAddr =
        match tokio::time::timeout(Duration::from_secs(5), read_mqp_target(&mut recv)).await {
            Ok(Ok(t)) => t,
            _ => {
                send.reset(0x01u32.into()).ok();
                return;
            }
        };
    if streams_held.load(std::sync::atomic::Ordering::Relaxed) >= share {
        let n = STREAM_SHARE_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if warn_stream_share_refused() {
            warn!(
                "tcp stream share reached ({share} of {MAX_STREAM_TASKS} across \
                 {admitted} connection(s), {n} refused so far); resetting the stream"
            );
        }
        send.reset(0x05u32.into()).ok();
        return;
    }
    let _stream_permit = match stream_task_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Fail the stream immediately instead of queueing unbounded work.
            send.reset(0x05u32.into()).ok();
            return;
        }
    };
    streams_held.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let _stream_share_guard = StreamShareGuard(streams_held);
    // Candidate addresses for the dial. Both branches produce a plain
    // `&[SocketAddr]`: the IP-literal path (the dominant case) borrows
    // the decoded target and allocates nothing, while the domain path
    // resolves into a local buffer whose scope covers the dial.
    let ip_cand;
    let mut dns_cand = [SocketAddr::from(([0, 0, 0, 0], 0)); 8];
    let dns_n;
    let cands: &[SocketAddr] = match &target {
        TargetAddr::Ip(s) => {
            ip_cand = *s;
            std::slice::from_ref(&ip_cand)
        }
        TargetAddr::Domain(h, p) => {
            // Fail fast when the global slow-path budget is exhausted
            // instead of parking this stream task (and its
            // stream-task permit) in a 3s queue: a unique-domain
            // flood would otherwise hold up to MAX_STREAM_TASKS
            // permits while IP-literal flows starve behind them.
            // Matches the UDP path's try_acquire; the client retries.
            let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            dns_n = match resolve_all_cached_with_contention_retry(h, *p).await {
                Ok(v) => {
                    // `resolve_all_cached` sorts IPv4 first, so a flat
                    // prefix cut would starve IPv6 whenever upstream
                    // returns more than 8 v4 records. Alternate
                    // families instead, keeping v4 preference while
                    // guaranteeing v6 gets tried.
                    let mut n = 0;
                    let mut v4 = v.iter().filter(|a| a.is_ipv4());
                    let mut v6 = v.iter().filter(|a| !a.is_ipv4());
                    // Alternate families so v6 is never starved, but
                    // keep filling from whichever family still has
                    // records until the 8-slot buffer is full (a
                    // v4-only answer must still yield up to 8).
                    let mut want_v4 = true;
                    while n < dns_cand.len() {
                        let next = if want_v4 {
                            v4.next().or_else(|| v6.next())
                        } else {
                            v6.next().or_else(|| v4.next())
                        };
                        match next {
                            Some(a) => {
                                dns_cand[n] = *a;
                                n += 1;
                            }
                            None => break,
                        }
                        want_v4 = !want_v4;
                    }
                    n
                }
                Err(e) => {
                    if is_dns_contended(&e) {
                        dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                    }
                    0
                }
            };
            drop(permit);
            &dns_cand[..dns_n]
        }
    };
    // Hold the global dial permit only for the connect phase; the copy
    // phase is bounded by the transport's stream limit instead.
    // Fail fast instead of parking this stream task (and its
    // stream-task permit) in a DIAL_PERMIT_WAIT queue: a dial flood
    // would otherwise hold up to MAX_STREAM_TASKS permits while
    // later flows starve behind them. Matches the stream_task_limiter
    // and dns_slow_path_limiter try_acquire paths; the client retries.
    let _dial_permit = match dial_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let n = DIAL_PERMIT_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::debug!("tcp dial permit refused ({n} so far)");
            send.reset(0x04u32.into()).ok();
            return;
        }
    };
    let tcp = match dial_happy_eyeballs(cands, allow_private).await {
        Some(t) => t,
        None => {
            let n = DIAL_CONNECT_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::debug!("tcp dial failed ({n} so far)");
            send.reset(0x04u32.into()).ok();
            return;
        }
    };
    drop(_dial_permit);
    let _ = tcp.set_nodelay(true);
    // MQP-2: report the bound address of the dialed socket so the
    // client can answer SOCKS with the real BND.ADDR/PORT (RFC 1928)
    // instead of a placeholder.
    let bnd = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    // Fixed-size stack buffer: the ACK is at most magic + status + the
    // v6 bnd form (`MAX_TCP_ACK_LEN`), so the per-stream `Vec` this
    // used to allocate bought nothing.
    let mut ack = [0u8; MAX_TCP_ACK_LEN];
    let n = encode_tcp_ack_into(bnd, &mut ack);
    // Bounded: a stalled stream must not pin this task and its
    // stream-task permit until connection death; the client tears the
    // flow down on a missing ACK, so a slow write here buys nothing.
    // Reset symmetrically with the dial-failure paths above so the
    // client fails fast instead of waiting out its 25s ACK timeout.
    let ack_sent = tokio::time::timeout(Duration::from_secs(5), send.write_all(&ack[..n]))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !ack_sent {
        send.reset(0x04u32.into()).ok();
        return;
    }
    match copy_tcp_quic_idle(tcp, send, recv, Duration::from_secs(300)).await {
        Ok((up, down)) => {
            tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
        }
        Err(e) => {
            if tcp_abort_log_due() {
                let st = stat_conn.stats();
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
}

/// Byte length of the complete MQP-2 TCP header for a given `atyp`: how much
/// the header reader must collect before it can decode. The domain form needs
/// its length byte first, which is why this is two-staged. Pure so the lengths
/// are unit-testable without a live QUIC stream.
fn mqp_hdr_len(atyp: u8, domain_len: u8) -> Result<usize> {
    Ok(match atyp {
        0x01 => 1 + 6,
        0x04 => 1 + 18,
        0x03 => {
            if domain_len == 0 {
                anyhow::bail!("empty domain");
            }
            1 + 1 + domain_len as usize + 2
        }
        a => anyhow::bail!("bad atyp {a}"),
    })
}

async fn read_mqp_target(recv: &mut quinn::RecvStream) -> Result<TargetAddr> {
    // No per-read timeout here: the caller wraps the whole header read in a
    // single 5s budget, and an inner timeout just registered extra timers.
    //
    // The header is decoded from one stack buffer instead of assembling a
    // temporary `Vec` per field and then decoding that: a domain target used to
    // cost four heap allocations (three `Vec`s plus the owned `String`) before
    // the dial even started. Now only the final `TargetAddr` allocates.
    const HDR_MAX: usize = 1 + 1 + 255 + 2;
    let mut buf = [0u8; HDR_MAX];
    recv.read_exact(&mut buf[..1]).await.context("hdr read")?;
    let (len, rest_at) = match buf[0] {
        0x03 => {
            recv.read_exact(&mut buf[1..2])
                .await
                .context("hdr domain len")?;
            (mqp_hdr_len(0x03, buf[1])?, 2)
        }
        atyp => (mqp_hdr_len(atyp, 0)?, 1),
    };
    recv.read_exact(&mut buf[rest_at..len])
        .await
        .context("hdr read")?;
    Ok(TargetAddr::decode(&buf[..len])?.0)
}

/// Connect to the first candidate that succeeds.
///
/// `cands` is borrowed so the IP-literal path allocates nothing. The filtered
/// candidate list and the task set live in fixed arrays: the old `Vec::collect`
/// plus `JoinSet` allocated two or three times per flow just to set up a dial
/// that, in the single-candidate case, needs one `connect`.
async fn dial_happy_eyeballs(
    cands: &[SocketAddr],
    allow_private: bool,
) -> Option<tokio::net::TcpStream> {
    const DIAL_CAND_MAX: usize = 8;
    let mut accept = [SocketAddr::from(([0, 0, 0, 0], 0)); DIAL_CAND_MAX];
    let mut n = 0;
    for a in cands
        .iter()
        .filter(|a| allow_private || is_global_ip(a.ip()))
    {
        accept[n] = *a;
        n += 1;
        if n == DIAL_CAND_MAX {
            break;
        }
    }
    let cands = &accept[..n];
    if cands.is_empty() {
        return None;
    }
    // Total budget 4s; the client-side ACK wait is sized to cover it.
    let budget = tokio::time::sleep(Duration::from_secs(4));
    tokio::pin!(budget);
    if let [only] = cands {
        tokio::select! {
            r = tokio::net::TcpStream::connect(*only) => {
                let s = r.ok()?;
                let _ = s.set_nodelay(true);
                return Some(s);
            }
            _ = &mut budget => return None,
        }
    }
    // Event-driven cancellation: losers are woken by a watch value instead of
    // polling a flag every 50ms (which cost extra wakeups on hot dial paths).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(1);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::with_capacity(cands.len());
    for (i, a) in cands.iter().enumerate() {
        let tx = tx.clone();
        let mut cancel = cancel_rx.clone();
        let a = *a;
        tasks.push(tokio::spawn(async move {
            if i > 0 {
                let delay = Duration::from_millis(250 * i.min(4) as u64);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.wait_for(|v| *v) => return,
                }
            }
            if *cancel.borrow() || tx.is_closed() {
                return;
            }
            let connected = tokio::select! {
                r = tokio::net::TcpStream::connect(a) => r.ok(),
                _ = cancel.wait_for(|v| *v) => None,
            };
            if let Some(s) = connected {
                let _ = s.set_nodelay(true);
                // Capacity 1: the first winner wins, the rest drop their socket.
                let _ = tx.try_send(s);
            }
        }));
    }
    drop(tx);
    let res = tokio::select! {
        r = rx.recv() => r,
        _ = &mut budget => None,
    };
    let _ = cancel_tx.send(true);
    for t in tasks {
        t.abort();
    }
    res
}

const SLOTS: usize = 64;

/// Mix an IP into `0..SLOTS` with a manual multiply-add fold (no
/// SipHash on the packet path). A collision only shares a slot — the probe
/// compares the full key — so it can evict an entry but never mis-serve one.
fn ip_cache_idx(ip: IpAddr) -> usize {
    let mut h: u64 = 0;
    match ip {
        IpAddr::V4(v4) => {
            for o in v4.octets() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(o as u64);
            }
        }
        IpAddr::V6(v6) => {
            for s in v6.segments() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(s as u64);
            }
        }
    }
    (h % SLOTS as u64) as usize
}

/// Direct-mapped per-thread memo of `is_global_ip` verdicts.
///
/// Fixed-destination flows pay `is_global_ip` per inbound datagram, and the
/// predicate is pure over the IP, so the verdict is remembered thread-locally.
/// One hashed slot per address with a full-key compare makes a probe O(1)
/// instead of the O(SLOTS) linear scan the first revision used; a collision
/// only evicts the slot, so the security outcome is the same as calling the
/// predicate directly — only an exact key match is ever returned, never
/// another address's verdict.
fn is_global_ip_cached(ip: IpAddr) -> bool {
    thread_local! {
        static CACHE: std::cell::RefCell<[(Option<IpAddr>, bool); SLOTS]> =
            const { std::cell::RefCell::new([(None, false); SLOTS]) };
    }
    let idx = ip_cache_idx(ip);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c[idx].0 == Some(ip) {
            return c[idx].1;
        }
        let v = is_global_ip(ip);
        c[idx] = (Some(ip), v);
        v
    })
}

/// The target a datagram names, as `(host, port)`. An IP target reports an
/// empty host: it has no name that could rotate to another address, so there is
/// nothing for a pin to re-check. A domain name is never empty on the wire
/// (`TargetAddrRef::decode` refuses a zero-length one), so the two forms cannot
/// collide in a [`ConnPin`].
fn target_name(a: TargetAddrRef<'_>) -> (&str, u16) {
    match a {
        TargetAddrRef::Ip(dst) => ("", dst.port()),
        TargetAddrRef::Domain(h, p) => (h, p),
    }
}

/// Resolve this datagram's target once, for both the fragment and the plain
/// branch. Order matters: the connection's pin first (free, and only trusted
/// while it still names the pinned session *and* has not expired), then the
/// session's own memo, then the DNS cache. `None` means "not known yet" --
/// `forward_server_dgram` spawns the resolver, so it is not an error.
fn resolve_pin(
    ss: &SessTable,
    pin: &mut Option<ConnPin>,
    pinned_sess: u32,
    s: u32,
    h: &str,
    p: u16,
    allow_private: bool,
) -> Option<SocketAddr> {
    // The coarse epoch: this value only ever feeds 30 s comparisons (the pin's
    // deadline and the session memo's TTL), and it sits on the per-datagram
    // domain path, so it must not be a vDSO `clock_gettime` per packet.
    // `sess_dest_store` writes the memo's `expires` from the same epoch, so the
    // two sides are directly comparable.
    let now = coarse_millis();
    // The connection-level pin is only trusted for the exact
    // (session, name, port) it was stored for, and only until its deadline.
    // Matching on the session alone would send a datagram naming a *different*
    // target to the address resolved for the previous one -- a silent
    // mis-route; ignoring the deadline would never re-resolve at all.
    if s == pinned_sess {
        if let Some(pin) = pin.as_ref() {
            if pin.sess == s && pin_is_for(pin, h, p) && pin.expires > now {
                return Some(pin.addr);
            }
        }
    }
    if let Some((dst, memo_life)) = sess_dest_lookup_ttl(ss, now, s, h, p) {
        // A filtered memo hit is unusable as-is, but the name may still
        // resolve to an allowed address in the full cached set (multi-record
        // names whose first address is private). Scan it here so the pin can
        // still arm on the fast path instead of forcing every packet through
        // the slow path for the rest of the DNS TTL.
        if allow_private || is_global_ip_cached(dst.ip()) {
            // Adopt the session's memo so the next datagram is a pure compare with
            // no table read at all -- for the memo's remaining life, never longer.
            pin_arm(pin, s, h, p, dst, memo_life);
            return Some(dst);
        }
        if let Some((set, set_life)) = lookup_cached_all_fast_with_ttl(h, p) {
            if let Some(d2) = set
                .iter()
                .copied()
                .find(|a| allow_private || is_global_ip_cached(a.ip()))
            {
                pin_arm(pin, s, h, p, d2, set_life);
                return Some(d2);
            }
        }
        return None;
    }
    let (lookup, ttl_ms) = lookup_cached_fast_with_ttl(h, p);
    match lookup {
        CachedLookup::Addr(dst) => {
            // The fast cache serves the first address only; a filtered first
            // address falls back to the full cached set before giving up, so
            // the pin arms the same way the slow path (`forward_server_dgram`)
            // would resolve it. Without this a name whose first record is
            // private never pinned and every packet paid the slow path.
            // A fallback into the full set inherits *that* set's remaining life,
            // not the first address's (they are the same entry here, but the
            // clamp must follow whichever address was actually adopted).
            let (addr, life) = if !allow_private && !is_global_ip_cached(dst.ip()) {
                lookup_cached_all_fast_with_ttl(h, p).and_then(|(set, life)| {
                    set.iter()
                        .copied()
                        .find(|a| allow_private || is_global_ip_cached(a.ip()))
                        .map(|a| (a, life))
                })?
            } else {
                (dst, ttl_ms)
            };
            // Adopt the DNS hit into the connection pin. Without this the pin
            // was only ever written from `sess_dest_lookup`, and a fast-path
            // success skips `forward_server_dgram` → `sess_dest_store` entirely:
            // the pin and the session dest expired together at T+30s while the
            // 60s DNS cache was still live, so every subsequent packet paid
            // `sess_dest_lookup` again for the rest of the DNS TTL (~50%
            // duty-cycle degradation on a steady domain flow). Same contract as
            // the memo branch above: pin for at most `DEST_PIN_TTL_MS`.
            pin_arm(pin, s, h, p, addr, life);
            Some(addr)
        }
        CachedLookup::Negative | CachedLookup::Unknown => None,
    }
}

/// Relay one datagram to its target. `Some((dst, life_ms))` is the address
/// actually used plus the remaining life of the cache entry it came from, so the
/// caller's own pin cannot outlive it (see [`pin_life_ms`]); `None` means the
/// datagram was dropped (SSRF filter, negative cache, DNS overload, or no
/// session slot).
async fn forward_server_dgram(
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
            }
            // No destination memo for an IP target: `resolve_pin` — the memo's
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
        TargetAddrRef::Domain(h, p) => match lookup_cached_fast_with_ttl(h, p) {
            (CachedLookup::Negative, _) => {
                dgram_drops::bump(&dgram_drops::REFUSED);
                None
            }
            (CachedLookup::Addr(dst), life) if allow_private || is_global_ip_cached(dst.ip()) => {
                let sock = get_or_create_sess(ss, cd, conn_id, s, Some((h, p, dst, life))).await?;
                remember_dst(ss, s, dst);
                udp_try_send(&sock, map_for_dual(dst), payload);
                Some((dst, life))
            }
            // Filtered first address or uncached: scan the full cached set
            // synchronously so this reader never awaits DNS on a cache hit.
            // Only a set that is not synchronously visible (contended lock or
            // expired entry) reaches the resolving send below.
            _ => {
                let full = lookup_cached_all_fast_with_ttl(h, p);
                let usable = full.as_ref().and_then(|(v, life)| {
                    v.iter()
                        .copied()
                        .find(|a| allow_private || is_global_ip_cached(a.ip()))
                        .map(|a| (a, *life))
                });
                match usable {
                    Some((d2, life)) => {
                        let sock =
                            get_or_create_sess(ss, cd, conn_id, s, Some((h, p, d2, life))).await?;
                        remember_dst(ss, s, d2);
                        udp_try_send(&sock, map_for_dual(d2), payload);
                        Some((d2, life))
                    }
                    None if full.is_some() => {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        None
                    }
                    None => {
                        match dns_inflight_status(h, p) {
                            // Single-flight: the packet that spawned the
                            // resolver is delivered by that task, this one has
                            // no owner. Counted so the loss shows up in the
                            // 60 s budget line instead of being invisible.
                            DnsInflight::Inflight => {
                                dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
                                return None;
                            }
                            // Contended shard mutex: nothing is known, so this
                            // is not an inflight drop. Count it apart and fall
                            // through to the spawn path below, not a return.
                            DnsInflight::Contended => {
                                dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                            }
                            DnsInflight::Absent => {}
                        }
                        // Fail fast on the slow-path budget with exactly one bump
                        // per refusal: `try_acquire_owned` is the only check,
                        // so a permit freed between a probe and the acquire is
                        // still usable and an exhausted budget is counted once
                        // (a separate `available_permits() == 0` pre-check both
                        // dropped usable permits and double-counted the race).
                        let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                dgram_drops::bump(&dgram_drops::SESSION_FULL);
                                return None;
                            }
                        };
                        let ss = ss.clone();
                        let cd = cd.clone();
                        let host = h.to_owned();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let dst = match resolve_all_cached(&host, p).await {
                                Ok(v) => match v
                                    .iter()
                                    .copied()
                                    .find(|a| allow_private || is_global_ip(a.ip()))
                                {
                                    Some(v) => v,
                                    None => {
                                        dgram_drops::bump(&dgram_drops::REFUSED);
                                        return;
                                    }
                                },
                                Err(e) => {
                                    if is_dns_contended(&e) {
                                        dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                                    } else {
                                        dgram_drops::bump(&dgram_drops::REFUSED);
                                    }
                                    return;
                                }
                            };
                            let sock = match get_or_create_sess(
                                &ss,
                                &cd,
                                conn_id,
                                s,
                                Some((&host, p, dst, DNS_CACHE_TTL_MS)),
                            )
                            .await
                            {
                                Some(v) => v,
                                // `get_or_create_sess` already bumps the
                                // specific budget counter for every resource
                                // refusal (FAIR_SHARE / SESSION_FULL /
                                // SESS_CREATE_FAILED); the only silent None is
                                // the no-DATAGRAM path, counted here so the
                                // spawned datagram never vanishes from the 60 s
                                // budget line. Guarded (not unconditional) so a
                                // refusal is never bumped twice.
                                None => {
                                    if cd.max_datagram_size().is_none() {
                                        dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
                                    }
                                    return;
                                }
                            };
                            remember_dst(&ss, s, dst);
                            udp_try_send(&sock, map_for_dual(dst), payload);
                        });
                        // The resolution happens in the spawned task above (it awaits),
                        // so this datagram is delivered there and there is no pin for
                        // the caller to record yet. The next datagram for this session
                        // finds the answer in the DNS cache -- or, once one datagram has
                        // completed this path, in the session's own destination memo.
                        None
                    }
                }
            }
        },
    }
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
fn shard_over_share(shard_len: usize, fair_cap: usize) -> bool {
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
fn sweep_local(w: &mut HashMap<u32, SessEntry>) -> Vec<SessEntry> {
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

fn abort_evicted(evicted: Vec<SessEntry>) {
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
fn sess_dest_lookup(ss: &SessTable, now: u64, s: u32, host: &str, port: u16) -> Option<SocketAddr> {
    sess_dest_lookup_ttl(ss, now, s, host, port).map(|(a, _)| a)
}

/// [`sess_dest_lookup`] plus the memo's remaining life, so a caller that adopts
/// the memo as its own pin cannot extend it past the memo's deadline.
fn sess_dest_lookup_ttl(
    ss: &SessTable,
    now: u64,
    s: u32,
    host: &str,
    port: u16,
) -> Option<(SocketAddr, u64)> {
    let sh = ss.shard(s);
    if let Some(e) = lock_read(sh).get(&s) {
        if let Some(addr) = e.dest.get(now, host, port) {
            return Some((addr, e.dest.expires.saturating_sub(now)));
        }
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
fn sess_dest_store(
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
        let r = lock_read(ss.shard(s));
        if let Some(e) = r.get(&s) {
            if e.dest.is_for(host, port, addr)
                && e.dest.expires.saturating_sub(now) > DEST_PIN_REFRESH_MS
            {
                return;
            }
        }
    }
    let mut w = lock_write(ss.shard(s));
    if let Some(e) = w.get_mut(&s) {
        e.dest = DestMemo {
            key,
            addr,
            expires: now + pin_life_ms(remaining_ms),
        };
    }
}

/// Monotonic connection ids for the session memos.
///
/// Session ids are allocated per client — every client hub counts from 1 — so
/// `(conn, sess)` is the identity of a session and the connection half must
/// never repeat. `Connection::stable_id` is a heap address, and the allocator
/// hands the same address to the next connection after a reconnect, so a memo
/// entry left behind by a dead connection could match a different one. A
/// process-wide counter cannot alias.
fn next_conn_id() -> usize {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Per-thread memo of the most recently used session socket.
///
/// A datagram-heavy flow sends a long run of packets to the *same* session, so
/// the connection-level `RwLock` read plus hash lookup in `get_or_create_sess`
/// is pure per-packet overhead for all but the first packet of the run. The
/// memo is direct-mapped on purpose: a miss simply falls through to the table.
/// The key is `(conn, sess)`, never `sess` alone: session ids are allocated per
/// client, so two connections sharing this thread would otherwise serve each
/// other's sockets and route replies onto the wrong QUIC connection.
struct SessMemo {
    /// Owning connection id ([`next_conn_id`]): the slot is shared by every
    /// connection whose DATAGRAM reader runs on this worker thread.
    conn: usize,
    sess: u32,
    /// Weak on purpose: the table entry and the reply reader own the socket, so
    /// the memo must never be its last owner. A strong `Arc` here outlived the
    /// connection — a slot is only rewritten by a later session hashing to the
    /// same index on the same thread, and `next_conn_id` never repeats, so the
    /// fd and its kernel buffers were pinned for the process lifetime. A failed
    /// `upgrade` is also the sharpest liveness signal available: it means the
    /// session's socket is gone.
    sock: std::sync::Weak<tokio::net::UdpSocket>,
    /// The session table's liveness stamp, kept so a memo hit can refresh it
    /// without re-taking the table lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// The reply reader's abort handle. `is_finished` is the liveness signal,
    /// the same one the table path uses: a flag the reader cleared on its way
    /// out would stay set when the sweeper or a connection close aborts the
    /// reader mid-await, and that path runs no cleanup at all.
    abort: tokio::task::AbortHandle,
    /// The session's allowlist epoch (see [`SessEntry::recent_epoch`]), so the
    /// fast path can tell whether the allowlist it recorded into is still the
    /// one it saw.
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
}

/// 128 direct-mapped slots: session ids hash uniformly (odd multiplier is a
/// bijection mod power-of-two), so 32 interleaved sessions already thrashed the
/// old 32-slot table back to the table lock on every packet. 128 covers
/// multi-association concurrency; past it entries still just miss through to the
/// table — a miss is never a mis-serve, the key compare guarantees that.
const SESS_MEMO_SLOTS: usize = 128;

thread_local! {
    static SESS_MEMO: std::cell::RefCell<[Option<SessMemo>; SESS_MEMO_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

fn sess_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % SESS_MEMO_SLOTS
}

/// Publish `(conn, sess)` into this thread's memo. The socket is stored weakly
/// (see [`SessMemo::sock`]); callers hand over a strong `Arc` purely as the
/// upgrade source while the session is alive.
fn sess_memo_put(
    conn: usize,
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    last: Arc<std::sync::atomic::AtomicU64>,
    abort: tokio::task::AbortHandle,
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        m[idx] = Some(SessMemo {
            conn,
            sess,
            sock: Arc::downgrade(&sock),
            last,
            abort,
            recent_epoch,
        });
    });
}

/// Drop the memo when it still points at this reader generation. Called by a
/// reply reader as it exits, so the next inbound packet for that session
/// recreates it instead of sending into a socket nobody reads.
///
/// The slot is cleared only when it still names the exiting reader's own
/// socket (same allocation, via `Weak::ptr_eq`): a session recreated after
/// this reader started carries a freshly bound socket, so clearing on
/// `(conn, sess)` alone wiped the *new* session's memo when the old reader
/// exited after the recreate. A false clear only costs one table slow path
/// (the table re-put fills the memo again); a false keep would serve a dead
/// socket, and the lookup already treats that as `Stale`.
fn sess_memo_forget(conn: usize, sess: u32, sock: &Arc<tokio::net::UdpSocket>) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        let expected = Arc::downgrade(sock);
        if m[idx].as_ref().is_some_and(|x| {
            x.conn == conn && x.sess == sess && std::sync::Weak::ptr_eq(&x.sock, &expected)
        }) {
            m[idx] = None;
        }
    });
}

/// Outcome of a session-memo probe.
enum SessHit {
    Miss,
    /// A live session socket, its liveness stamp, its reader abort handle (the
    /// abort handle lets per-connection fast paths validate liveness without
    /// re-probing the thread-local memo) and its allowlist epoch.
    Fresh(
        Arc<tokio::net::UdpSocket>,
        Arc<std::sync::atomic::AtomicU64>,
        tokio::task::AbortHandle,
        Arc<std::sync::atomic::AtomicU64>,
    ),
    /// The memo cannot serve `(conn, sess)`: either its reader has exited or its
    /// socket is gone (see [`SessMemo::sock`]). The table (not the memo) must
    /// decide, so this falls through and lets the table path recreate the
    /// session.
    Stale,
}

/// Probe the thread-local session memo for `(conn, sess)`.
///
/// The connection is part of the key because a session id is only unique
/// within one connection (every client hub allocates ids from 1), and this slot
/// is shared by every connection whose DATAGRAM reader runs on this worker
/// thread. Matching on `sess` alone served one connection's socket to another,
/// so that connection's datagrams went out on the wrong session.
fn sess_memo_lookup(conn: usize, sess: u32) -> SessHit {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        match m[idx].as_ref() {
            Some(x) if x.conn == conn && x.sess == sess => {
                // Live means the reader has not exited *and* something still
                // owns the socket: `upgrade` fails once the table entry and the
                // reader are gone, which is exactly when the slot must be
                // released instead of pinning a dead fd.
                let live = if x.abort.is_finished() {
                    None
                } else {
                    x.sock.upgrade()
                };
                if let Some(sock) = live {
                    SessHit::Fresh(
                        sock,
                        x.last.clone(),
                        x.abort.clone(),
                        x.recent_epoch.clone(),
                    )
                } else {
                    m[idx] = None;
                    SessHit::Stale
                }
            }
            _ => SessHit::Miss,
        }
    })
}

/// Per-thread view of the last liveness refresh, so the throttling decision
/// costs no table lock. A `(connection, session, ms)` triple: session ids are
/// only unique within a connection, so `(session, ms)` alone let two
/// connections share — and thereby defeat — one throttle window.
///
/// NOTE: an earlier revision sampled the clock 1/64 by packet count. That
/// starved trickle flows: a burst past 64 packets froze `tick` large without
/// a store, and every later trickle packet kept skipping the clock read, so
/// `last` froze until the 180s reap. The clock read (~20ns vdso) is an order
/// of magnitude cheaper than the hash lookup + table lock it replaces, so the
/// throttle is purely time-based now: at most one shared store per second per
/// session, every packet pays one clock read.
struct TouchMemo {
    conn: usize,
    sess: u32,
    ms: u64,
}

/// Same 128-slot sizing as the session memo above: the throttle decision must
/// not itself become the per-packet cost, and 32 interleaved sessions thrashed
/// the old table into an unconditional store per packet pair.
const TOUCH_SLOTS: usize = 128;

thread_local! {
    static TOUCH_MEMO: std::cell::RefCell<[Option<TouchMemo>; TOUCH_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

fn touch_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % TOUCH_SLOTS
}

/// Refresh `last` at most once per [`TOUCH_INTERVAL_MS`], using a thread-local
/// copy of the last refresh time.
///
/// Single clock for liveness: the throttle gate runs on the cheap
/// [`coarse_millis`] epoch (one relaxed load per datagram), but the value
/// stored into `last` is [`mono_millis`]. Every other writer of `last`
/// (session creation) and every reader (`sweep_all`, `take_idle`,
/// `sweep_local`, the reader idle tick) already uses the mono epoch, so
/// storing the 1 s-quantized coarse sample here made the sweep subtract a
/// stamp up to one tick older than the true touch — reaping a live session up
/// to ~1 s before its 180 s budget ran out. The precise read costs one vDSO
/// call and runs only when the touch is actually due (at most once per
/// second per session), so the per-packet cost stays one coarse read.
fn touch_session_throttled(conn: usize, sess: u32, last: &std::sync::atomic::AtomicU64) {
    const TOUCH_INTERVAL_MS: u64 = 1000;
    // Throttle gate only: cheap, advances on its own (unlike a packet-count
    // sampler, which froze `last` on trickle flows — see `TouchMemo`).
    let gate = coarse_millis();
    let due = TOUCH_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        let idx = touch_memo_idx(conn, sess);
        match c[idx].as_mut() {
            Some(e) if e.conn == conn && e.sess == sess => {
                if gate.saturating_sub(e.ms) >= TOUCH_INTERVAL_MS {
                    e.ms = gate;
                    true
                } else {
                    false
                }
            }
            _ => {
                c[idx] = Some(TouchMemo {
                    conn,
                    sess,
                    ms: gate,
                });
                true
            }
        }
    });
    if due {
        last.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
    }
}

/// Life to give a pin or destination memo armed from a source with `remaining_ms`
/// of its own life left.
///
/// `DEST_PIN_TTL_MS` is documented as "deliberately shorter than the DNS cache
/// TTL (60 s): DNS answers can change while the cache entry is still live, so
/// this bounds how long a session can keep sending to an address the name no
/// longer resolves to". Measured *from adoption* that bound was false: a pin
/// armed from an entry with 100 ms of life left (or from a session memo with the
/// same) lived its own full 30 s, so an address resolved 60 s ago could still be
/// used 90 s after resolution — 30 s past the TTL every other layer respects.
/// Every arming site therefore clamps to the source's remaining life; a fresh
/// resolution (the spawned resolver task) passes `DNS_CACHE_TTL_MS`, where the
/// 30 s pin wins and behaviour is unchanged.
fn pin_life_ms(remaining_ms: u64) -> u64 {
    DEST_PIN_TTL_MS.min(remaining_ms)
}

/// Record that session `s` sent to `dst`. Best effort: a vanished session is
/// simply not updated and its next datagram recreates it. Normalization lives
/// in [`RecentAddrs`] itself, so both sides of the comparison agree.
///
/// The session's allowlist epoch moves with the push, whether it lands from the
/// datagram reader's own task or from a spawned resolver task that the reader
/// cannot see; that is what `fast_last_dst` is validated against.
///
/// The push itself is a lock-free `rcu` publish: the reply reader loads a
/// snapshot for every datagram, so writers must not take a lock the readers
/// would have to contend with, and `rcu`'s retry makes two concurrent pushes
/// both land (a load-clone-store would drop one, and a dropped allowlist entry
/// is a silently refused reply).
fn remember_dst(ss: &SessTable, s: u32, dst: SocketAddr) {
    let sh = ss.shard(s);
    if let Some(e) = lock_read(sh).get(&s) {
        let ip = unmap(dst.ip());
        // Fast exit for the steady flow (one already-known destination): no
        // clone, no allocation, no CAS — just the epoch move below. A concurrent
        // push that evicts this very entry out of a full ring can slip between
        // this check and the skip, which costs at most one refused reply batch:
        // the epoch below still moves, so the reader's mirror re-records the
        // destination on its next outbound datagram.
        if !e.recent.load().slots.contains(&Some(ip)) {
            e.recent.rcu(|cur| {
                if cur.slots.contains(&Some(ip)) {
                    // Another writer got there first; keep its snapshot.
                    Arc::clone(cur)
                } else {
                    let mut next = (**cur).clone();
                    next.push(dst);
                    Arc::new(next)
                }
            });
        }
        e.recent_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Record `dst` for `s` unless this reader already did so and the session's
/// allowlist has not moved since.
///
/// `epoch` is the session's allowlist epoch; `None` means the reader has no
/// session armed, so the record always happens. A *foreign* push (the
/// resolver task `forward_server_dgram` spawns) moves the epoch without this
/// reader seeing it, and 17 of those evict a destination the ring still claims
/// is present — the mirror then suppressed the re-record for the rest of the
/// pin/DNS lifetime and the target's replies were dropped as forged, i.e. a
/// silent one-way flow. Comparing the epoch costs one relaxed load and catches
/// exactly that.
fn mirror_record(
    ss: &SessTable,
    mirror: &mut Option<(u32, SocketAddr, u64)>,
    s: u32,
    dst: SocketAddr,
    epoch: Option<&std::sync::atomic::AtomicU64>,
) {
    let Some(epoch) = epoch else {
        remember_dst(ss, s, dst);
        *mirror = None;
        return;
    };
    if *mirror != Some((s, dst, epoch.load(std::sync::atomic::Ordering::Relaxed))) {
        remember_dst(ss, s, dst);
        // Re-read after the push: the next datagram then skips the record until
        // something moves the epoch again.
        *mirror = Some((s, dst, epoch.load(std::sync::atomic::Ordering::Relaxed)));
    }
}

/// Userspace receive buffer per session reader: one full-protocol-cap datagram
/// plus the truncation-detection slack byte (`n == buf.len()` means the kernel
/// truncated, so the length is load-bearing).
const SESS_RECV_BUF_LEN: usize = UDP_RECV_MAX + UDP_RECV_SLACK;

/// Compile-time userspace bound: one reader buffer per session, so the live
/// set can never exceed the session cap times it (~67 MiB worst case).
const _: () = assert!(SESS_RECV_BUF_LEN == UDP_RECV_MAX + UDP_RECV_SLACK);
const _: () = assert!(
    MAX_SESSIONS_GLOBAL * SESS_RECV_BUF_LEN <= 70 * 1024 * 1024,
    "8192 x 8 KiB must stay a bounded worst case"
);

/// Idle session-reader buffers retained per worker thread.
///
/// Each *live* reader holds its buffer for life, so the live set is already
/// bounded by `MAX_SESSIONS_GLOBAL` (`SESS_RECV_BUF_LEN` each, ~67 MiB worst
/// case) and sockets stay strictly per-session — pooled here are only the
/// userspace byte buffers, never sockets, tasks or permits. What churn
/// multiplies is allocator traffic: every create zeroes 8 KiB and every
/// teardown frees it. This pool recycles the freed buffers (moved, never
/// shared) up to this depth per thread; beyond it they drop as before.
/// Thread-local because the buffers are exclusive `&mut` scratch — sharing
/// them across threads would need a lock on the per-reply path.
const SESS_BUF_POOL_DEPTH: usize = 8;

thread_local! {
    static SESS_BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Take a session-reader buffer, recycled when one is idle.
fn sess_recv_buf() -> Vec<u8> {
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        while let Some(buf) = p.pop() {
            if buf.len() == SESS_RECV_BUF_LEN {
                return buf;
            }
        }
        vec![0u8; SESS_RECV_BUF_LEN]
    })
}

/// Return a session-reader buffer for reuse. Wrong-sized buffers (none exist
/// in the tree today; this is defence in depth) are dropped, and past the
/// depth the buffer drops as before — so the pool itself is bounded.
fn sess_recycle_buf(buf: Vec<u8>) {
    if buf.len() != SESS_RECV_BUF_LEN {
        return;
    }
    // No re-zeroing: `recv_from` overwrites the prefix on the next use and
    // only `buf[..n]` is ever read, so stale tail bytes are never observed.
    // All sessions live in this process, so there is no cross-tenant leak.
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < SESS_BUF_POOL_DEPTH {
            p.push(buf);
        }
    })
}

#[cfg(test)]
fn sess_buf_pool_len() -> usize {
    SESS_BUF_POOL.with(|p| p.borrow().len())
}

async fn sess_reader_task(
    conn_id: usize,
    s: u32,
    rs: Arc<tokio::net::UdpSocket>,
    ss2: SessTable,
    c2: quinn::Connection,
    last2: Arc<std::sync::atomic::AtomicU64>,
    recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Pooled (see `sess_recv_buf`): same length as the old per-session `vec!`,
    // so the `n == buf.len()` truncation check below is unchanged.
    let mut buf = sess_recv_buf();
    let mut frag = DgramFragmenter::new();
    let mut limit = c2.max_datagram_size().unwrap_or(0);
    let mut last_touch = 0u64;
    let mut last_limit_refresh = coarse_millis();
    loop {
        let (n, src) = tokio::select! {
            r = rs.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = tick.tick() => {
                if c2.close_reason().is_some()
                    || mono_millis()
                        .saturating_sub(last2.load(std::sync::atomic::Ordering::Relaxed))
                        >= SESS_IDLE_MS
                {
                    break;
                }
                limit = match c2.max_datagram_size() {
                    Some(m) => m,
                    // DATAGRAM support is negotiated at the handshake; a mid-life
                    // disable leaves this reader with nothing to deliver, so exit
                    // and let the entry self-reap instead of holding a socket.
                    None => break,
                };
                continue;
            }
        };
        // Coarse epoch gates the per-reply intervals (the 1 s liveness touch
        // and the 10 s PMTU refresh); the liveness value itself is the mono
        // epoch, matching `touch_session_throttled` and every sweep reader.
        let now = coarse_millis();
        if now.saturating_sub(last_touch) >= 1000 {
            last_touch = now;
            last2.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
        }
        // Active sessions track PMTU growth without waiting for the 60 s idle
        // tick: at most one quinn lock per session per 10 s, and only while the
        // session is actually receiving replies.
        if now.saturating_sub(last_limit_refresh) >= 10_000 {
            last_limit_refresh = now;
            match c2.max_datagram_size() {
                Some(m) => limit = m,
                None => break,
            }
        }
        if n == buf.len() {
            warn!(
                "udp session {s}: target reply above {MQP_FRAG_MAX_PAYLOAD} B truncated; \
                 raise MQP_FRAG_MAX_PAYLOAD to carry it"
            );
            dgram_drops::bump(&dgram_drops::TOO_LARGE);
            continue;
        }
        if limit == 0 {
            break;
        }
        let src = SocketAddr::new(unmap(src.ip()), src.port());
        // Reply-source validation: the socket is unconnected, so any source
        // that reaches the ephemeral port would otherwise be forwarded as the
        // target's answer. Drop anything sent from a host this session never
        // sent to (see `RecentAddrs`: the port is deliberately not part of the
        // key, so a server answering from a different port still gets through).
        // Lock-free snapshot: the outbound path pushes into the same allowlist
        // from another task, so a lock here was the only per-reply mutex on the
        // download path (and the only place the two directions shared a cache
        // line). `load` is a hazard-pointer read, not a refcount RMW.
        let r = recent.load();
        let allowed = !r.is_empty() && r.contains(&src);
        drop(r);
        if !allowed {
            dgram_drops::bump(&dgram_drops::REFUSED);
            continue;
        }
        let ta = TargetAddr::Ip(src);
        let sent = frag.send(&c2, s, &ta.as_ref(), &buf[..n], limit);
        if sent.fragmented() {
            tracing::debug!("udp session {s}: {} B sent as {} fragments", n, sent.frames);
        }
        match sent.outcome() {
            DatagramSend::Sent => {}
            DatagramSend::Blocked => {}
            DatagramSend::TooLarge => {
                limit = c2.max_datagram_size().unwrap_or(0);
            }
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => break,
        }
    }
    // Every exit above breaks to here, so the buffer is recycled exactly once
    // per reader lifetime, however the task ended (idle reap, abort-adjacent
    // error, lost DATAGRAM support).
    sess_recycle_buf(buf);
    sess_memo_forget(conn_id, s, &rs);
    {
        let sh = ss2.shard(s);
        let mut w = lock_write(sh);
        if let Some(cur) = w.get(&s) {
            if Arc::ptr_eq(&cur.sock, &rs) {
                w.remove(&s);
            }
        }
    }
    // The table may now be empty: if this was its last session, drop out of the
    // fair-share denominator so other connections immediately get their full
    // share back. Must run with the write guard above dropped (see
    // `note_empty_state`).
    ss2.note_empty_state();
}

async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    // `(host, port, resolved address)` when the caller already knows a *named*
    // destination, so the session can memoize it. An IP target passes `None`:
    // its address is already in every datagram it sends, and the memo is only
    // ever read back for domain targets (`sess_dest_store`).
    // `(host, port, resolved address, remaining life of that resolution)` — the
    // life is the source's, so the memo cannot outlive it (see `pin_life_ms`).
    dest: Option<(&str, u16, SocketAddr, u64)>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Session 0 is reserved (never allocated by any client hub): a wire
    // datagram carrying it is malformed or hostile, not a new session.
    // Refusing here keeps it from pinning a global permit until the sweep.
    if s == 0 {
        dgram_drops::bump(&dgram_drops::REFUSED);
        return None;
    }
    // Zero-lock fast path: the common case (a burst of packets for one session)
    // allocates nothing and never touches the table. The memo's liveness check
    // is the same signal the table path uses (`JoinHandle::is_finished`) — one
    // atomic load — so a session whose reader has exited, aborted included,
    // still falls through and is recreated.
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, _, _) => {
            // Refresh liveness without the table lock; a session captured here is
            // scheduled by its reader and may be exiting, in which case one reply
            // is dropped and the next packet recreates it.
            touch_session_throttled(conn_id, s, &last);
            if let Some((h, p, d, life)) = dest {
                sess_dest_store(ss, s, h, p, d, life);
            }
            return Some(sock);
        }
        SessHit::Stale | SessHit::Miss => {}
    }
    // Fast path: single shard read + lock-free timestamp bump. A session whose
    // reply reader has already exited is treated as absent so its next packet
    // recreates it instead of black-holing.
    //
    // The read *blocks* rather than failing fast. Pass 21 made this a
    // `try_lock_read` that dropped the datagram on failure and counted it in
    // `SESSION_FULL`, reasoning that a packet path must never park a worker.
    // Pass 23 revisited that: the table is per-connection, so the only
    // cross-task writers are a session reader exiting (a `get` plus maybe a
    // `remove`), the 60 s sweeper's removal loop, and a DNS-spawned
    // `get_or_create_sess` -- all short, allocation-free critical sections. The
    // datagram reader is by far the commonest writer itself, so it cannot
    // contend with itself. Against that, the old behaviour silently dropped a
    // datagram every time any of those brief writers won the race, and charged
    // the drop to a counter documented as "budget exhausted", hiding relay loss
    // inside a resource-limit metric. `std::sync::RwLock::read` already tries
    // before it parks, so the uncontended cost is unchanged; only the drop is
    // gone.
    {
        let sh = ss.shard(s);
        let r = lock_read(sh);
        if let Some(e) = r.get(&s) {
            if !e.reader.is_finished() {
                let sock = e.sock.clone();
                let last = e.last.clone();
                let abort = e.reader.abort_handle();
                let epoch = e.recent_epoch.clone();
                touch_session_throttled(conn_id, s, &e.last);
                drop(r);
                // Publish this thread's memo from the table. A session created
                // by a DNS-spawned resolver task lives on another worker's memo
                // (or on none), and without this the per-connection fast path
                // could never arm for it: the caller's `SessHit::Miss` would
                // clear the fast state on every datagram instead of adopting
                // the session that was just used.
                sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
                if let Some((h, p, d, life)) = dest {
                    sess_dest_store(ss, s, h, p, d, life);
                }
                return Some(sock);
            }
        }
    }
    // No DATAGRAM support on this path: refuse before pinning a global permit,
    // a kernel socket and a reader task for a session whose replies would all
    // be dropped (`limit == 0` in the reader). Negotiated at the handshake, so
    // it never flaps mid-connection — and since a hit above can only be a
    // session that passed this check already, it stays off the per-packet path
    // instead of taking the connection-state lock for every datagram.
    cd.max_datagram_size()?;
    // Fair share first: one connection must not grow past an equal split of the
    // process-wide budget while others live. Only expired sessions are
    // reclaimed here; live ones keep their sockets and the global semaphore
    // still caps the true total.
    //
    // The reap is **throttled** (per worker, 1/s) for the same reason the global
    // pool's failed-acquire path is: past the cap every further new-session
    // datagram reaches this branch, and an unthrottled `sweep_all` would walk
    // all shards and every session entry *per packet* — an O(sessions) CPU
    // amplifier any peer can drive with fabricated session ids, for a sweep
    // that can only ever free sessions that went idle >= SESS_IDLE_MS ago.
    let fair_cap = fair_sess_cap();
    // Served from the bounded sample (see `len_upper_bound`): past the cap every
    // further new-session datagram reaches this branch, so a fresh 8-lock
    // measurement per forged packet is pure lock traffic — but the bound counts
    // every insert since the sample, so a burst cannot outrun the share.
    // Re-measured exactly once the bound reaches the cap, and after a sweep
    // actually ran (it may have freed sessions).
    let now = mono_millis();
    if ss.len_upper_bound(now, fair_cap) >= fair_cap {
        if claim_fair_sweep(now) {
            let evicted = ss.sweep_all(now);
            abort_evicted(evicted);
            let now2 = mono_millis();
            let n2 = ss.len();
            ss.store_len(n2, now2);
            if n2 >= fair_cap {
                dgram_drops::bump(&dgram_drops::FAIR_SHARE);
                return None;
            }
        } else {
            dgram_drops::bump(&dgram_drops::FAIR_SHARE);
            return None;
        }
    }
    // Check the global pool BEFORE creating the socket: once every session slot
    // is held there is no point paying socket()+setsockopt()+bind() per packet.
    let permit = match session_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Throttled reap through the process-wide sweep window (see
            // `FAIR_SWEEP_LAST_MS`): a per-worker throttle here let W workers
            // run W full-table sweeps per second under permit pressure.
            if !claim_fair_sweep(mono_millis()) {
                dgram_drops::bump(&dgram_drops::SESSION_FULL);
                return None;
            }
            let evicted = ss.sweep_all(mono_millis());
            abort_evicted(evicted);
            match session_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    dgram_drops::bump(&dgram_drops::SESSION_FULL);
                    return None;
                }
            }
        }
    };
    // Create the socket outside the write lock: socket()/setsockopt()/bind()
    // are syscalls and must not stall the datagram reader for every session.
    // Both syscall failures are resource events the operator has to see, so
    // neither is allowed to return silently.
    let raw = match udp_socket_dual_small("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not created ({n} so far): {e:#}");
            }
            return None;
        }
    };
    let sock = match tokio::net::UdpSocket::from_std(raw) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not registered ({n} so far): {e}");
            }
            return None;
        }
    };
    let c2_pre = cd.clone();
    let rs_pre = sock.clone();
    let ss_pre = ss.clone();
    let last_pre = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let recent_pre: Arc<arc_swap::ArcSwap<RecentAddrs>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default()));
    let recent_epoch: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));
    let h_pre = tokio::spawn(sess_reader_task(
        conn_id,
        s,
        rs_pre,
        ss_pre,
        c2_pre,
        last_pre.clone(),
        recent_pre.clone(),
    ));
    let reader_abort = h_pre.abort_handle();
    let mut stale_dead: Vec<SessEntry> = Vec::new();
    let mut swept: Vec<SessEntry> = Vec::new();
    let (inserted, memo_data, reader_died) = {
        let sh = ss.shard(s);
        // Blocks for the same reason the read path does: a losing `try_lock_write`
        // used to abort the freshly spawned reader, release the global permit and
        // drop the datagram, which is strictly worse than waiting out a short
        // `HashMap` mutation. The socket syscalls above deliberately stay outside
        // this critical section.
        let mut w = lock_write(sh);
        if let Some(e) = w.get(&s) {
            if !e.reader.is_finished() {
                touch_session_throttled(conn_id, s, &e.last);
                let sock2 = e.sock.clone();
                let last2 = e.last.clone();
                let abort2 = e.reader.abort_handle();
                // The *live entry's* allowlist epoch, not the fresh one built for
                // the reader that is about to be aborted: the memo must describe
                // the session that stays in the table, or the mirror would never
                // see that session's pushes move.
                let epoch2 = e.recent_epoch.clone();
                drop(w);
                h_pre.abort();
                drop(permit);
                // Same reason as the read path above: adopt the live entry into
                // this thread's memo so the caller's fast path can arm.
                sess_memo_put(conn_id, s, sock2.clone(), last2, abort2, epoch2);
                if let Some((h, p, d, life)) = dest {
                    sess_dest_store(ss, s, h, p, d, life);
                }
                return Some(sock2);
            }
            if let Some(e) = w.remove(&s) {
                stale_dead.push(e);
            }
        }
        // Over its fair share, this shard reaps its expired sessions now instead
        // of waiting for the 60 s sweeper. Live over-share is left alone (the
        // connection-level fair-share gate is the resource bound); the reap is
        // gated on the process-wide sweep window, or every forged new-session
        // datagram would run an O(shard) scan under this write lock — a CPU
        // amplifier any peer could drive.
        if shard_over_share(w.len(), fair_sess_cap()) && claim_fair_sweep(mono_millis()) {
            swept = sweep_local(&mut w);
        }
        let dead = h_pre.is_finished();
        w.insert(
            s,
            SessEntry {
                sock: sock.clone(),
                reader: h_pre,
                last: last_pre.clone(),
                _permit: permit,
                dest: dest
                    .and_then(|(h, p, a, life)| Some((PortKey::new(h, p)?, a, life)))
                    .map_or(DestMemo::NONE, |(key, addr, life)| DestMemo {
                        key,
                        addr,
                        expires: coarse_millis() + pin_life_ms(life),
                    }),
                recent: recent_pre.clone(),
                recent_epoch: recent_epoch.clone(),
            },
        );
        if dead || w.get(&s).map(|e| e.reader.is_finished()).unwrap_or(false) {
            if let Some(e) = w.remove(&s) {
                e.reader.abort();
            }
            (false, None, true)
        } else {
            (
                true,
                Some((sock.clone(), last_pre.clone(), reader_abort.clone())),
                false,
            )
        }
    };
    if inserted {
        udp_stats::session();
        ss.note_insert();
    }
    // This connection may have just become a session holder: join the fair-share
    // denominator. Called after the write guard is dropped (see
    // `note_empty_state`), and on the `dead` branch too, where the insert was
    // rolled back and the connection may not hold anything at all.
    ss.note_empty_state();
    if let Some((msock, mlast, mabort)) = memo_data {
        sess_memo_put(conn_id, s, msock, mlast, mabort, recent_epoch);
    }
    if reader_died {
        // The freshly spawned reply reader exited before the entry was
        // published (e.g. the session socket failed on first use). The datagram
        // is dropped; count it instead of leaving an operator with a session
        // that silently never comes up.
        let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
        if warn_sess_create_failed() {
            warn!("udp session {s} reader exited before publish ({n} so far)");
        }
    }
    abort_evicted(stale_dead);
    abort_evicted(swept);
    if inserted {
        Some(sock)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that mutate the process-global session-holder
    /// count, so their exact reads cannot race each other.
    static HOLDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn hdr(atyp: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![atyp];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn mqp_hdr_len_matches_each_wire_form() {
        assert_eq!(mqp_hdr_len(0x01, 0).unwrap(), 7);
        assert_eq!(mqp_hdr_len(0x04, 0).unwrap(), 19);
        assert_eq!(mqp_hdr_len(0x03, 1).unwrap(), 5);
        assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
        assert!(
            mqp_hdr_len(0x03, 0).is_err(),
            "empty domain must be refused"
        );
        assert!(
            mqp_hdr_len(0x02, 0).is_err(),
            "unknown atyp must be refused"
        );
    }

    /// The stack-buffer reader must consume exactly the bytes the framed header
    /// names, so the caller's stream position equals the pre-refactor one.
    /// The length the stream-header reader collects and the length the decoder
    /// consumes must agree for **every** form, or the server splits the stream at
    /// the wrong offset and misparses every following byte of that flow. The
    /// fixed cases above pin the four wire forms; this drives the same invariant
    /// differentially over randomized addresses (including every port and the
    /// whole domain-length range) against the encoder itself.
    #[test]
    fn mqp_hdr_len_agrees_with_the_encoder_for_random_addresses() {
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut checked = 0;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let pick = x % 3;
            let addr = match pick {
                0 => TargetAddr::Ip(SocketAddr::from((
                    std::net::Ipv4Addr::from((x >> 16) as u32),
                    x as u16,
                ))),
                1 => {
                    let mut o = [0u8; 16];
                    o[..8].copy_from_slice(&x.to_be_bytes());
                    o[8..].copy_from_slice(&x.rotate_left(29).to_be_bytes());
                    TargetAddr::Ip(SocketAddr::from((std::net::Ipv6Addr::from(o), x as u16)))
                }
                _ => {
                    let n = (x % 256) as usize;
                    if n == 0 {
                        continue;
                    }
                    TargetAddr::Domain("d".repeat(n), x as u16)
                }
            };
            // Random draws include unspecified addresses and scoped v6 forms the
            // encoder legitimately refuses; only encodable ones can reach a peer.
            let mut buf = Vec::new();
            if addr.encode(&mut buf).is_err() {
                continue;
            }
            checked += 1;
            let declared = match buf[0] {
                0x03 => mqp_hdr_len(0x03, buf[1]).expect("domain length is valid"),
                atyp => mqp_hdr_len(atyp, 0).expect("atyp is valid"),
            };
            assert_eq!(
                declared,
                buf.len(),
                "declared header length must equal the encoding ({addr:?})"
            );
            let (decoded, consumed) = TargetAddr::decode(&buf).expect("decodes");
            assert_eq!(
                consumed,
                buf.len(),
                "decoder must consume the header exactly"
            );
            assert_eq!(decoded, addr, "round trip");
        }
        assert!(checked > 10_000, "most random addresses must be encodable");
    }

    #[test]
    fn mqp_header_roundtrip_v4_v6_and_domain() {
        for (hdr_bytes, want) in [
            (
                hdr(0x01, &[8, 8, 8, 8, 0, 53]),
                TargetAddr::Ip("8.8.8.8:53".parse().unwrap()),
            ),
            (
                hdr(0x04, &{
                    let mut b = [0u8; 18];
                    b[..16].copy_from_slice(
                        &"2001:4860:4860::8888"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    b[16..].copy_from_slice(&443u16.to_be_bytes());
                    b
                }),
                TargetAddr::Ip("[2001:4860:4860::8888]:443".parse().unwrap()),
            ),
            (
                hdr(0x03, &{
                    let d = b"example.com";
                    let mut b = vec![d.len() as u8];
                    b.extend_from_slice(d);
                    b.extend_from_slice(&8443u16.to_be_bytes());
                    b
                }),
                TargetAddr::Domain("example.com".into(), 8443),
            ),
        ] {
            let len = mqp_hdr_len(hdr_bytes[0], *hdr_bytes.get(1).unwrap_or(&0)).unwrap();
            assert_eq!(len, hdr_bytes.len(), "declared length must match the frame");
            let (got, used) = TargetAddr::decode(&hdr_bytes).unwrap();
            assert_eq!(used, hdr_bytes.len());
            assert_eq!(got, want);
        }
    }

    /// A domain header longer than the 255-byte wire limit must be refused by
    /// the length helper, never sliced into the fixed stack buffer.
    #[test]
    fn domain_wire_limit_is_enforced() {
        assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
        assert!(mqp_hdr_len(0x03, 0).is_err());
    }

    fn memo_sock() -> Arc<tokio::net::UdpSocket> {
        let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        s.set_nonblocking(true).unwrap();
        Arc::new(tokio::net::UdpSocket::from_std(s).unwrap())
    }

    /// A session destined for `addr`, inserted the way `get_or_create_sess`
    /// would insert it, so the destination memo can be exercised without a live
    /// QUIC connection.
    fn sess_with_dest(addr: Option<SocketAddr>) -> (SessTable, Arc<tokio::net::UdpSocket>) {
        let ss = Arc::new(ShardedSessTable::new());
        let sock = memo_sock();
        let last = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
        let h = tokio::spawn(std::future::pending::<()>());
        let permit = session_limiter().clone().try_acquire_owned().unwrap();
        ss.shard(7).write().unwrap().insert(
            7,
            SessEntry {
                sock: sock.clone(),
                reader: h,
                last,
                _permit: permit,
                dest: addr.map_or(DestMemo::NONE, |a| DestMemo {
                    key: PortKey::new("", 0).unwrap(),
                    addr: a,
                    expires: mono_millis() + DEST_PIN_TTL_MS,
                }),
                recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
                recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
        );
        (ss, sock)
    }

    /// The per-datagram path, before this change, re-resolved a domain target
    /// for *every* datagram: a hash, a key build and a full key compare per
    /// packet, forever. The session's own memo is what removes that, so the
    /// properties that keep it safe are asserted here.
    #[tokio::test]
    async fn session_dest_memo_round_trips_and_expires() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);

        // A fresh session has pinned nothing: the datagram path must resolve.
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);

        sess_dest_store(&ss, 7, "a.test", 443, dst, DNS_CACHE_TTL_MS);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443),
            Some(dst),
            "a stored destination must be reused"
        );

        // Past the pin's TTL the answer must go back through the resolver, or a
        // name that moves would keep the session pointed at a dead address for
        // the session's whole idle lifetime.
        let past = mono_millis() + DEST_PIN_TTL_MS + 1;
        assert_eq!(sess_dest_lookup(&ss, past, 7, "a.test", 443), None);

        // A different session number must never see another session's pin.
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 8, "a.test", 443), None);
    }

    /// The datagram path stores this memo for every domain-target packet, so the
    /// store must cost a read lock — not a write — whenever the answer has not
    /// changed. A redundant write per packet was measurable (35 ns of exclusive
    /// shard lock plus a dirty line in the shared table) and a redundant
    /// *refresh* is what the refresh window exists to avoid.
    #[tokio::test]
    async fn session_dest_store_writes_only_when_the_memo_needs_it() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let moved: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);
        let expires = || ss.shard(7).read().unwrap().get(&7).unwrap().dest.expires;

        sess_dest_store(&ss, 7, "alpha.test", 443, dst, DNS_CACHE_TTL_MS);
        let first = expires();
        assert!(first > mono_millis(), "a store must leave a live memo");
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(dst)
        );

        // Same name, same address, TTL still fresh: nothing to write.
        sess_dest_store(&ss, 7, "alpha.test", 443, dst, DNS_CACHE_TTL_MS);
        assert_eq!(
            expires(),
            first,
            "a redundant store must not rewrite (and so must not take the write lock)"
        );

        // Same name, new address: the memo must follow it.
        sess_dest_store(&ss, 7, "alpha.test", 443, moved, DNS_CACHE_TTL_MS);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(moved)
        );

        // Inside the refresh window the value is unchanged but the life is not:
        // that one must rewrite, or the entry would expire and the next packet
        // would pay a full resolve.
        ss.shard(7)
            .write()
            .unwrap()
            .get_mut(&7)
            .unwrap()
            .dest
            .expires = mono_millis() + 1;
        sess_dest_store(&ss, 7, "alpha.test", 443, moved, DNS_CACHE_TTL_MS);
        assert!(
            expires() > mono_millis() + DEST_PIN_REFRESH_MS,
            "a memo inside the refresh window must be refreshed"
        );
    }

    /// The bug this memo was rewritten for: a session is not bound to one
    /// target, so a memo keyed on the session alone answered a datagram naming
    /// B with the address resolved for A and relayed it to the wrong host.
    /// Verified end to end with `hotpath_bench udpdomainswitch`, which caught
    /// exactly this (1000 of 2000 datagrams misrouted) before the name became
    /// part of the key.
    #[tokio::test]
    async fn session_dest_memo_is_keyed_on_the_target_name() {
        let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);
        sess_dest_store(&ss, 7, "alpha.test", 443, a, DNS_CACHE_TTL_MS);

        // Same session, different name: must not answer with alpha's address.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "beta.test", 443),
            None
        );
        // Same session, same name, different port: likewise.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 80),
            None
        );
        // The name it was stored for still hits.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(a)
        );

        // A name sharing a prefix must not match a shorter stored name.
        sess_dest_store(&ss, 7, "alpha.test", 443, b, DNS_CACHE_TTL_MS);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test.", 443),
            None
        );
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.tes", 443),
            None
        );
    }

    /// An IP target has no name to re-check, and must not be confused with a
    /// domain whose name happens to be empty or to share the port.
    #[tokio::test]
    async fn session_dest_memo_distinguishes_ip_and_domain_targets() {
        let ip_target: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let domain_target: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);

        // An IP target stores the empty host.
        sess_dest_store(&ss, 7, "", 9999, ip_target, DNS_CACHE_TTL_MS);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "", 9999),
            Some(ip_target)
        );
        // A domain target on the same session replaces it, and the IP-form
        // query must then miss rather than get the domain's address.
        sess_dest_store(&ss, 7, "gamma.test", 9999, domain_target, DNS_CACHE_TTL_MS);
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "", 9999), None);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "gamma.test", 9999),
            Some(domain_target)
        );
    }

    /// A name too long for the inline key must not be memoized at all: storing
    /// it truncated would let a different name sharing the prefix match it.
    #[tokio::test]
    async fn session_dest_memo_refuses_names_it_cannot_key() {
        let (ss, _sock) = sess_with_dest(None);
        let long = "x".repeat(DEST_KEY_BYTES + 1);
        sess_dest_store(
            &ss,
            7,
            &long,
            443,
            "10.0.0.1:443".parse().unwrap(),
            DNS_CACHE_TTL_MS,
        );
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &long, 443), None);
        // A name sharing that prefix must miss too.
        let prefix = "x".repeat(DEST_KEY_BYTES);
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &prefix, 443), None);
    }

    /// Storing into a session that no longer exists is a no-op, not a panic or a
    /// phantom entry: the datagram path races session teardown by design.
    #[tokio::test]
    async fn session_dest_store_tolerates_a_vanished_session() {
        let ss = Arc::new(ShardedSessTable::new());
        sess_dest_store(
            &ss,
            7,
            "a.test",
            443,
            "10.0.0.1:1".parse().unwrap(),
            DNS_CACHE_TTL_MS,
        );
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);
    }

    /// The connection-level pin is a hint *with a deadline*. Without one, a
    /// steady flow to a domain target kept using the address resolved when the
    /// flow started for the whole connection lifetime: the session memo, the
    /// DNS cache and `DEST_PIN_TTL_MS` were all bypassed for the one flow that
    /// never missed, so a name that moved was never re-resolved.
    #[tokio::test]
    async fn conn_pin_stops_answering_when_its_ttl_expires() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stale: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);
        sess_dest_store(&ss, 7, "pin-expiry.invalid", 443, dst, DNS_CACHE_TTL_MS);

        // A live pin answers for exactly the (session, name, port) it was
        // stored for...
        let mut pin: Option<ConnPin> = None;
        pin_arm(
            &mut pin,
            7,
            "pin-expiry.invalid",
            443,
            stale,
            DNS_CACHE_TTL_MS,
        );
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 443, true),
            Some(stale)
        );
        // ...and for nothing else.
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, "other-pin.invalid", 443, true),
            None
        );
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 80, true),
            None
        );

        // Past its deadline it must not answer at all; the session's own memo
        // is consulted instead and the pin is re-armed from it, freshly.
        pin.as_mut().unwrap().expires = mono_millis().saturating_sub(1);
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 443, true),
            Some(dst),
            "an expired pin must not answer"
        );
        let rearmed = pin.as_ref().expect("the memo must re-arm the pin");
        assert_eq!(rearmed.addr, dst);
        assert!(rearmed.expires > mono_millis(), "re-armed pin must be live");
    }

    /// The DNS-cache branch must arm the connection pin. Without that
    /// write-back a fast-path success never called `sess_dest_store`, so pin
    /// and session memo expired together at T+30 s while the 60 s DNS cache
    /// was still live — every later packet paid `sess_dest_lookup` again for
    /// the rest of the DNS TTL.
    #[tokio::test]
    async fn dns_hit_arms_the_pin_when_pin_and_memo_miss() {
        let dst: SocketAddr = "93.184.216.34:8443".parse().unwrap();
        let host = "dns-pin-arm.test";
        let port = 18443u16;
        dns_cache_seed(host, port, dst);

        let (ss, _sock) = sess_with_dest(None);

        // Cold start: no pin, no session memo — only the DNS cache answers.
        let mut pin: Option<ConnPin> = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
            Some(dst),
            "the DNS cache must answer when pin and memo both miss"
        );
        let armed = pin.as_ref().expect("a DNS hit must arm the pin");
        assert_eq!(armed.addr, dst);
        assert!(
            pin_is_for(armed, host, port),
            "the pin must name the target"
        );
        assert_eq!(armed.port, port);
        assert_eq!(armed.sess, 7);
        assert!(
            armed.expires > coarse_millis(),
            "the newly armed pin must be live"
        );

        // The P1 shape: pin expired, session memo still empty, DNS still live.
        // The DNS hit must re-arm the pin, or the flow degrades to a
        // `sess_dest_lookup` read lock on every packet for the rest of the TTL.
        pin.as_mut().unwrap().expires = coarse_millis().saturating_sub(1);
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
            Some(dst),
            "an expired pin must still fall through to the DNS cache"
        );
        let rearmed = pin.as_ref().expect("the DNS hit must re-arm the pin");
        assert_eq!(rearmed.addr, dst);
        assert!(
            rearmed.expires > coarse_millis(),
            "the re-armed pin must be live"
        );
    }

    #[tokio::test]
    async fn resolve_pin_withholds_a_filtered_cached_address() {
        let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let host = "filtered-first.test";
        let port = 18444u16;
        dns_cache_seed(host, port, private);
        let (ss, _sock) = sess_with_dest(None);
        let mut pin: Option<ConnPin> = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, false),
            None,
            "a filtered first address must not be served or pinned"
        );
        assert!(
            pin.is_none(),
            "a filtered address must not arm the pin either"
        );
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
            Some(private),
            "allow_private must still serve it"
        );
    }

    #[tokio::test]
    async fn resolve_pin_falls_back_when_first_record_filtered() {
        let private: SocketAddr = "10.9.9.9:443".parse().unwrap();
        let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let host = "filtered-first-multi.test";
        let port = 18446u16;
        dns_cache_seed_set(host, port, &[private, public]);
        let (ss, _sock) = sess_with_dest(None);
        let mut pin: Option<ConnPin> = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, false),
            Some(public),
            "a filtered first record must fall back to the full set, like the slow path"
        );
        let armed = pin.as_ref().expect("the fallback hit must arm the pin");
        assert_eq!(armed.addr, public);
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, false),
            Some(public),
            "the armed pin must answer the next datagram with no table read"
        );
    }

    /// A memo slot must never be the last owner of a session socket. With a
    /// strong `Arc` there, a dead session's fd and kernel buffers outlived the
    /// connection: the slot is only rewritten by a later session hashing to the
    /// same index on the same thread, and connection ids never repeat, so
    /// nothing ever released it.
    #[tokio::test]
    async fn session_memo_does_not_own_the_socket() {
        use std::sync::atomic::AtomicU64;

        let last = Arc::new(AtomicU64::new(1));
        let weak = {
            let sock = memo_sock();
            let weak = Arc::downgrade(&sock);
            // The strong reference is handed over and dropped here, exactly as
            // the table entry and the aborted reader are when a session dies.
            sess_memo_put(
                11,
                5,
                sock,
                last.clone(),
                live_reader(),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            );
            weak
        };
        assert!(
            weak.upgrade().is_none(),
            "the memo must not keep the session socket alive"
        );
        assert!(matches!(sess_memo_lookup(11, 5), SessHit::Stale));

        // While something else (the table, a reader) owns the socket, the memo
        // still serves it -- the weak reference must not over-stale a live
        // session.
        let sock = memo_sock();
        sess_memo_put(
            12,
            5,
            sock.clone(),
            last,
            live_reader(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        match sess_memo_lookup(12, 5) {
            SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &sock)),
            _ => panic!("a live session must still be served from the memo"),
        }
    }

    /// The 60 s sweeper snapshots idle keys under a *read* lock and removes
    /// them under the write lock. A key that was touched (or recreated) while
    /// the sweeper waited for that write lock is a live session, and removing
    /// it aborted a reader the client was actively using. `take_idle` re-tests
    /// every snapshotted key against the snapshot's `now`.
    #[tokio::test]
    async fn sweep_recheck_keeps_a_session_touched_after_the_snapshot() {
        let (ss, _sock) = sess_with_dest(None);
        let last = ss.shard(7).read().unwrap().get(&7).unwrap().last.clone();
        // A sweep that starts well past the session's idle deadline.
        let now = last.load(std::sync::atomic::Ordering::Relaxed) + SESS_IDLE_MS + 10_000;

        // Phase 1: the read-locked snapshot.
        let keys: Vec<u32> = ss
            .shard(7)
            .read()
            .unwrap()
            .iter()
            .filter(|(_, e)| {
                now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed))
                    >= SESS_IDLE_MS
            })
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(keys, vec![7], "the idle session must be in the snapshot");

        // The client's next datagram lands in the window before phase 2. A
        // touch always stamps a time at or after the sweeper's snapshot, so the
        // worst case this must survive is a stamp equal to `now`.
        last.store(now, std::sync::atomic::Ordering::Relaxed);

        // Phase 2: the write-locked removal must skip it.
        let evicted = {
            let mut w = ss.shard(7).write().unwrap();
            take_idle(&mut w, &keys, now)
        };
        assert!(
            evicted.is_empty(),
            "a session touched after the snapshot must survive"
        );
        assert!(ss.shard(7).read().unwrap().contains_key(&7));
    }

    /// A reader that stays alive (`SessHit::Fresh` requires a running task).
    fn live_reader() -> tokio::task::AbortHandle {
        let h = tokio::spawn(std::future::pending::<()>());
        let abort = h.abort_handle();
        drop(h);
        abort
    }

    /// One over-cap session in a scratch shard, stamped `idle_ms` ago.
    fn capped_session(idle_ms: u64) -> SessEntry {
        SessEntry {
            sock: memo_sock(),
            reader: tokio::spawn(std::future::pending::<()>()),
            last: Arc::new(std::sync::atomic::AtomicU64::new(
                mono_millis().saturating_sub(idle_ms),
            )),
            _permit: session_limiter().clone().try_acquire_owned().unwrap(),
            dest: DestMemo::NONE,
            recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
            recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Whether `s`'s reply allowlist currently admits `dst`.
    fn allowlist_contains(ss: &SessTable, s: u32, dst: SocketAddr) -> bool {
        let sh = lock_read(ss.shard(s));
        let Some(e) = sh.get(&s) else {
            return false;
        };
        e.recent.load().contains(&dst)
    }

    /// The reader's task-local mirror of the reply allowlist must be validated
    /// against the session's allowlist epoch, because one writer of that
    /// allowlist is not the reader: the DNS resolver task `forward_server_dgram`
    /// spawns pushes its resolved address from its own task, and
    /// `RECENT_DST_CAP` such pushes evict a destination the mirror still claims
    /// is present. The mirror then suppressed the re-record, so the target's
    /// replies were dropped as forged — a silent one-way flow for as long as the
    /// pin and the DNS entry lived.
    #[tokio::test]
    async fn the_allowlist_mirror_re_records_after_a_foreign_push() {
        use std::sync::atomic::Ordering;

        let (ss, _sock) = sess_with_dest(None);
        let epoch = ss
            .shard(7)
            .read()
            .unwrap()
            .get(&7)
            .unwrap()
            .recent_epoch
            .clone();
        let a: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let mut mirror: Option<(u32, SocketAddr, u64)> = None;
        mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
        assert_eq!(epoch.load(Ordering::Relaxed), 1, "the first record pushes");
        assert_eq!(mirror, Some((7, a, 1)));

        // Steady state: the mirror suppresses the repeat push, which is the
        // reason it exists at all.
        mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
        assert_eq!(
            epoch.load(Ordering::Relaxed),
            1,
            "a repeat record must not push again"
        );

        // A foreign push — the resolver task's, on another thread — moves the
        // epoch without touching the mirror, and enough of them evict `a`.
        for i in 0..RECENT_DST_CAP {
            let d: SocketAddr = format!("9.9.9.{i}:53").parse().unwrap();
            remember_dst(&ss, 7, d);
        }
        assert!(epoch.load(Ordering::Relaxed) > 1);
        assert!(
            !allowlist_contains(&ss, 7, a),
            "the ring evicted the mirrored destination"
        );

        // The next datagram must notice and re-record, or every reply from `a`
        // stays refused.
        mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
        assert!(
            allowlist_contains(&ss, 7, a),
            "a foreign push must force the mirror to re-record"
        );
    }

    #[test]
    fn reply_allowlist_matches_the_host_not_the_queried_port() {
        let mut r = RecentAddrs::default();
        assert!(r.is_empty());
        let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
        r.push(a);
        assert!(!r.is_empty());
        assert!(r.contains(&a), "the queried destination itself is allowed");
        // The whole point of the IP-only key: a server that answers from a
        // different port (TFTP's ephemeral reply port, redirected game/voice
        // flows) must not be filtered.
        assert!(
            r.contains(&"93.184.216.34:53".parse().unwrap()),
            "a reply from another port on a queried host is legitimate"
        );
        assert!(
            !r.contains(&b),
            "a host this session never sent to must stay refused"
        );
        r.push(a);
        assert_eq!(
            r.slots.iter().flatten().count(),
            1,
            "re-pushing the same host must not consume another slot"
        );
        r.push(b);
        assert!(r.contains(&a) && r.contains(&b));
        for i in 0..RECENT_DST_CAP {
            let d: SocketAddr = format!("9.9.9.{}:53", i).parse().unwrap();
            r.push(d);
        }
        assert!(
            r.slots.iter().flatten().count() <= RECENT_DST_CAP,
            "the allowlist must stay bounded"
        );
    }

    /// The allowlist is a clone-on-write snapshot: the reply task loads it for
    /// every inbound datagram while the outbound path pushes into it from a
    /// different task, so two concurrent pushes must **both** land (a
    /// load-clone-store would drop one, and a dropped entry silently refuses
    /// that target's replies) and the ring must still evict the oldest entry
    /// past [`RECENT_DST_CAP`].
    #[tokio::test]
    async fn allowlist_pushes_are_lock_free_and_both_land() {
        let (ss, _sock) = sess_with_dest(None);
        let s = 7u32;
        let a: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:53".parse().unwrap();

        let (t1, t2) = {
            let (x, y) = (ss.clone(), ss.clone());
            (
                std::thread::spawn(move || remember_dst(&x, s, a)),
                std::thread::spawn(move || remember_dst(&y, s, b)),
            )
        };
        t1.join().unwrap();
        t2.join().unwrap();
        assert!(allowlist_contains(&ss, s, a), "concurrent push A landed");
        assert!(allowlist_contains(&ss, s, b), "concurrent push B landed");

        // Past the cap the oldest entries are evicted, newest survive.
        for i in 0..RECENT_DST_CAP as u8 {
            remember_dst(&ss, s, SocketAddr::from(([10, 1, 0, i], 9)));
        }
        assert!(
            !allowlist_contains(&ss, s, a) && !allowlist_contains(&ss, s, b),
            "the ring evicted the two oldest destinations"
        );
        assert!(
            allowlist_contains(
                &ss,
                s,
                SocketAddr::from(([10, 1, 0, RECENT_DST_CAP as u8 - 1], 9))
            ),
            "the newest destination is admitted"
        );
    }

    /// The fair share divides the global session budget among connections that
    /// actually **hold sessions**, and a table joins/leaves that denominator as
    /// its emptiness changes.
    ///
    /// Counting every live QUIC connection was the pass-29 defect: a client's
    /// four idle TCP slots diluted its own UDP connection by 5x, so a lone
    /// default client capped at `8192 / 5 = 1638` associations while the client
    /// (and the README) admitted `MAX_UDP_ASSOCS = 4032` — and the excess was
    /// silently black-holed server-side. All three properties are asserted in
    /// one test so they cannot race each other over the process-global counter.
    #[tokio::test]
    async fn fair_share_counts_session_holders_not_live_connections() {
        use std::sync::atomic::Ordering;
        let _holder_guard = HOLDER_TEST_LOCK.lock().unwrap();
        let prev = session_holders().load(Ordering::Relaxed);
        // The client cap and the server's static per-connection target are one
        // number, shared through `lib.rs`.
        assert_eq!(LOCAL_SESS_TARGET, MAX_UDP_ASSOCS);

        // Pure arithmetic of the share.
        session_holders().store(1, Ordering::Relaxed);
        assert_eq!(fair_sess_cap(), LOCAL_SESS_MAX);
        assert!(
            fair_sess_cap() >= MAX_UDP_ASSOCS,
            "a lone session holder keeps its whole client cap"
        );
        session_holders().store(2, Ordering::Relaxed);
        assert_eq!(fair_sess_cap(), MAX_SESSIONS_GLOBAL / 2);
        // The floor is what a cheap dilution attack runs into: past 8 holders
        // every connection keeps MIN_SESSION_SHARE and the global semaphore
        // becomes the binding constraint.
        session_holders().store(8, Ordering::Relaxed);
        assert_eq!(fair_sess_cap(), MIN_SESSION_SHARE);
        session_holders().store(64, Ordering::Relaxed);
        assert_eq!(fair_sess_cap(), MIN_SESSION_SHARE);
        assert!(
            fair_sess_cap() >= 1024,
            "the old 256 floor let 32 single-session connections starve everyone"
        );

        // A table is counted only while non-empty.
        session_holders().store(prev, Ordering::Relaxed);
        let before = session_holders().load(Ordering::Relaxed);
        let empty = ShardedSessTable::new();
        empty.note_empty_state();
        assert_eq!(
            session_holders().load(Ordering::Relaxed),
            before,
            "an empty table is not a holder"
        );
        let (holding, _sock) = sess_with_dest(None);
        holding.note_empty_state();
        assert_eq!(
            session_holders().load(Ordering::Relaxed),
            before + 1,
            "a table holding a session joins the denominator"
        );
        let drained = holding.drain_all();
        assert!(!drained.is_empty());
        drop(drained);
        assert_eq!(
            session_holders().load(Ordering::Relaxed),
            before,
            "draining the last session leaves the denominator"
        );
        session_holders().store(prev, Ordering::Relaxed);
    }

    /// The fair-share gate must not compare a count frozen when its window
    /// opened.
    ///
    /// `len_cached` refreshed at most once a second and an insert never touched
    /// it, so inside one window every forged new-session datagram still read the
    /// pre-burst count and passed the gate — one connection could take every
    /// `MAX_SESSIONS_GLOBAL` permit, and hold them indefinitely by touching each
    /// session every <180 s (`sweep_all` reaps only idle sessions). The bound
    /// adds every insert since the sample and re-measures exactly once it
    /// reaches the cap, so the same burst is refused from the first packet past
    /// the share.
    #[tokio::test]
    async fn the_fair_share_gate_counts_inserts_since_the_sample() {
        let ss = ShardedSessTable::new();
        let now = mono_millis();
        // The first call measures and caches: nothing is held yet.
        assert_eq!(ss.len_upper_bound(now, LOCAL_SESS_MAX), 0);

        // One connection's burst of new sessions, all inside the sample window.
        for s in 0..8u32 {
            ss.shard(s).write().unwrap().insert(s, capped_session(0));
            ss.note_insert();
        }
        assert!(
            ss.len_upper_bound(now, LOCAL_SESS_MAX) >= 8,
            "the gate must count inserts since the sample, not the frozen one"
        );
        // At the cap the value is re-measured exactly, so the gate can never be
        // wrong in the admitting direction.
        assert_eq!(ss.len_upper_bound(now, 4), 8);
        // A fresh table with sessions inserted without `note_insert` (i.e. one
        // whose counter was reset by a sweep resync) is still measured exactly
        // once the window expires.
        assert_eq!(ss.len_upper_bound(now + 2_000, LOCAL_SESS_MAX), 8);
    }

    #[tokio::test]
    async fn stillborn_insert_leaves_the_fair_share_bound_unchanged() {
        let ss = ShardedSessTable::new();
        let now = mono_millis();
        assert_eq!(ss.len_upper_bound(now, LOCAL_SESS_MAX), 0);
        ss.shard(7).write().unwrap().insert(7, capped_session(0));
        ss.shard(7).write().unwrap().remove(&7);
        assert_eq!(
            ss.len_upper_bound(now, LOCAL_SESS_MAX),
            0,
            "a rolled-back insert must not inflate the fair-share bound"
        );
        ss.shard(7).write().unwrap().insert(7, capped_session(0));
        ss.note_insert();
        assert_eq!(ss.len_upper_bound(now, LOCAL_SESS_MAX), 1);
        ss.shard(7).write().unwrap().remove(&7);
    }

    /// Expired entries go through `take_idle` unbounded: 70 idle sessions are
    /// all reaped in one call, because aborting idle readers is not a storm.
    /// The old truncation reaped only the first 64 and left provably-dead
    /// entries behind. Stamps and `now` are synthetic (see above).
    #[tokio::test]
    async fn sweep_local_reaps_all_expired_in_one_call() {
        use std::sync::atomic::Ordering;

        let now: u64 = 3_000_000;
        let mut m: HashMap<u32, SessEntry> = HashMap::new();
        for k in 0..70u32 {
            m.insert(k, capped_session(1));
            m.get(&k).unwrap().last.store(0, Ordering::Relaxed);
        }
        // The scan as `sweep_local` performs it: every session reads idle.
        let keys: Vec<u32> = m
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.last.load(Ordering::Relaxed)) >= SESS_IDLE_MS)
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(keys.len(), 70);
        // The exact removal `sweep_local` runs on its expired set: no bound.
        let evicted = take_idle(&mut m, &keys, now);
        assert_eq!(evicted.len(), 70);
        assert!(m.is_empty());
    }

    /// `sweep_local` must re-test each expired key with the same `now` before
    /// removing it, exactly like `sweep_all` does through `take_idle`. The old
    /// body removed the scanned keys unconditionally, so a session touched
    /// after the scan — a touch lands lock-free, without the write guard —
    /// was evicted and its freshly started reader aborted.
    ///
    /// Stamps are synthetic: `mono_millis` is process uptime, so a fast test
    /// process can never be 180 s old and no wall-clock stamp reads expired.
    /// `take_idle` is the exact removal `sweep_local` delegates its expired
    /// path to, with the same `now` the scan used.
    #[tokio::test]
    async fn sweep_local_rechecks_idle_before_removing() {
        use std::sync::atomic::Ordering;

        let mut m: HashMap<u32, SessEntry> = HashMap::new();
        m.insert(1, capped_session(1));
        let last = m.get(&1).unwrap().last.clone();
        // A sweep that starts well past the session's idle deadline.
        let now: u64 = 1_000_000;
        last.store(0, Ordering::Relaxed);
        // The scan as `sweep_local` performs it: the session reads idle.
        let keys: Vec<u32> = m
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.last.load(Ordering::Relaxed)) >= SESS_IDLE_MS)
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(keys, vec![1]);
        // The client's next datagram lands before the removal.
        last.store(now, Ordering::Relaxed);
        // Unconditional removal would evict it here; the re-test keeps it.
        assert!(take_idle(&mut m, &keys, now).is_empty());
        assert!(m.contains_key(&1));
        // End to end: a just-touched session is never expired by `sweep_local`
        // (its stamp is at/after the sweeper's instant, as a real touch is).
        last.store(mono_millis(), Ordering::Relaxed);
        assert!(sweep_local(&mut m).is_empty());
        assert!(m.contains_key(&1));
    }

    /// `touch_session_throttled` must store the mono epoch into `last`, not
    /// the 1 s-quantized coarse sample it uses as its throttle gate: every
    /// sweep reader subtracts `last` from a mono `now`, so a coarse stamp
    /// reads up to one tick older than the true touch and reaps a live
    /// session up to ~1 s before its 180 s budget runs out.
    ///
    /// The test waits until the coarse cursor visibly lags mono (>= 300 ms —
    /// the 1 s ticker guarantees this within one tick), then touches with a
    /// key no other test can hold so the store is unconditional. Against the
    /// old store the stamp would lag by that same >= 300 ms; a mono store
    /// reads fresh within microseconds.
    #[tokio::test]
    async fn touch_stores_mono_millis_not_the_coarse_gate() {
        use std::sync::atomic::{AtomicU64, Ordering};

        // Arm the epoch, then wait for a measurable lag between the two clocks.
        let _ = coarse_millis();
        let mut waited = 0;
        while mono_millis().saturating_sub(coarse_millis()) < 300 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 1;
            assert!(waited < 200, "the 1 s ticker must advance the cursor");
        }
        let lag = mono_millis().saturating_sub(coarse_millis());
        assert!(lag >= 300, "need a visible coarse lag to test against");

        // A key no other test uses: memo miss means the touch is due and the
        // store is unconditional.
        let last = Arc::new(AtomicU64::new(0));
        touch_session_throttled(usize::MAX - 7, u32::MAX - 7, &last);
        let stored = last.load(Ordering::Relaxed);
        let mono_after = mono_millis();
        assert!(stored != 0, "a memo-miss touch must store");
        assert!(
            stored <= mono_after,
            "the stamp cannot run ahead of the clock"
        );
        assert!(
            mono_after.saturating_sub(stored) < 300,
            "the touch stamp must be a fresh mono sample, not the coarse gate \
             lagging {lag} ms behind (stored={stored} mono={mono_after})"
        );

        // Sweep math is exact to the ms on a touched stamp: a session idle
        // just under the budget survives, one exactly at it does not.
        // Synthetic stamps: mono is process uptime, so a fast test process
        // can never be 180 s old and no wall-clock stamp reads expired.
        let now: u64 = 1_000_000;
        let mut m: HashMap<u32, SessEntry> = HashMap::new();
        m.insert(1, capped_session(1));
        m.get(&1)
            .unwrap()
            .last
            .store(now.saturating_sub(SESS_IDLE_MS - 500), Ordering::Relaxed);
        assert!(
            take_idle(&mut m, &[1], now).is_empty(),
            "500 ms under budget must survive the sweep"
        );
        m.get(&1)
            .unwrap()
            .last
            .store(now.saturating_sub(SESS_IDLE_MS), Ordering::Relaxed);
        assert_eq!(
            take_idle(&mut m, &[1], now).len(),
            1,
            "exactly at budget must reap"
        );
    }

    /// The pin stores its name **inline**: arming must round-trip the longest
    /// name the wire can carry without allocating, and must refuse (never
    /// truncate) a name it cannot hold — a truncated key could match a different
    /// name and mis-route the flow.
    #[tokio::test]
    async fn the_pin_holds_the_wire_max_name_inline() {
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let longest = "a".repeat(PIN_HOST_BYTES);
        let mut pin = None;
        pin_arm(&mut pin, 7, &longest, 443, addr, DNS_CACHE_TTL_MS);
        let armed = pin.as_ref().expect("the wire-max name must pin");
        assert!(pin_is_for(armed, &longest, 443));
        assert_eq!(armed.host_len as usize, PIN_HOST_BYTES);
        // Every neighbouring key must not match: a prefix, another port.
        assert!(!pin_is_for(armed, &longest[..PIN_HOST_BYTES - 1], 443));
        assert!(!pin_is_for(armed, &longest, 80));
        assert!(!pin_is_for(armed, "different.test", 443));

        // Longer than the wire limit: refused, not truncated.
        let mut too_long = None;
        pin_arm(
            &mut too_long,
            7,
            &"b".repeat(PIN_HOST_BYTES + 1),
            443,
            addr,
            DNS_CACHE_TTL_MS,
        );
        assert!(
            too_long.is_none(),
            "a name that cannot be stored whole must not be pinned"
        );

        // An IP target pins under the empty name `target_name` gives it.
        pin_arm(&mut too_long, 7, "", 443, addr, DNS_CACHE_TTL_MS);
        assert!(too_long.as_ref().is_some_and(|p| pin_is_for(p, "", 443)));
    }

    /// A pin adopted from a cache hit must not outlive the entry it came from.
    ///
    /// `DEST_PIN_TTL_MS` is documented as "deliberately shorter than the DNS
    /// cache TTL (60 s) ... this bounds how long a session can keep sending to
    /// an address the name no longer resolves to". Measured *from adoption* that
    /// was false: a pin armed at 59.5 s into a 60 s entry lived its own full 30 s
    /// and the address was served 90 s after resolution. Every arming site now
    /// clamps to the source's remaining life, so the documented bound holds.
    #[tokio::test]
    async fn a_pin_never_outlives_the_cache_entry_it_was_armed_from() {
        let addr: SocketAddr = "93.184.216.34:19101".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);

        let (host, port) = ("pin-life-aged.test", 19101u16);
        dns_cache_seed_aged(host, port, addr, Duration::from_millis(59_500));
        let mut pin = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
            Some(addr)
        );
        let life = pin
            .as_ref()
            .unwrap()
            .expires
            .saturating_sub(coarse_millis());
        assert!(
            life > 0 && life <= 1_500,
            "the pin must follow the entry's remainder, got {life} ms"
        );

        // A freshly resolved name still gets the pin's own (shorter) TTL.
        let (fresh, fresh_port) = ("pin-life-fresh.test", 19102u16);
        dns_cache_seed(fresh, fresh_port, addr);
        let mut pin2 = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin2, 7, 7, fresh, fresh_port, true),
            Some(addr)
        );
        let life2 = pin2
            .as_ref()
            .unwrap()
            .expires
            .saturating_sub(coarse_millis());
        assert!(
            life2 > DEST_PIN_TTL_MS - 2_000 && life2 <= DEST_PIN_TTL_MS,
            "a fresh entry keeps the pin TTL, got {life2} ms"
        );
    }

    /// The per-session destination memo has the same contract: `resolve_pin`
    /// reads it back and adopts it as the connection pin, so an unclamped store
    /// would re-arm a fresh `DEST_PIN_TTL_MS` from an address whose DNS entry is
    /// about to expire.
    #[tokio::test]
    async fn the_session_memo_follows_its_sources_remaining_life() {
        let (ss, _sock) = sess_with_dest(None);
        let (host, port) = ("memo-life.test", 19103u16);
        let addr: SocketAddr = "93.184.216.34:19103".parse().unwrap();

        sess_dest_store(&ss, 7, host, port, addr, 1_000);
        let (got, life) = sess_dest_lookup_ttl(&ss, coarse_millis(), 7, host, port).unwrap();
        assert_eq!(got, addr);
        assert!(
            life <= 1_100,
            "the memo must not exceed its source: {life} ms"
        );

        // A pin adopted from that memo inherits the bound, never a fresh TTL.
        let mut pin = None;
        assert_eq!(
            resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
            Some(addr)
        );
        let pin_life = pin
            .as_ref()
            .unwrap()
            .expires
            .saturating_sub(coarse_millis());
        assert!(
            pin_life <= 1_100,
            "pin life {pin_life} ms must follow the memo"
        );

        // Stored with the full source life, the memo keeps DEST_PIN_TTL_MS.
        sess_dest_store(&ss, 7, host, port, addr, DNS_CACHE_TTL_MS);
        let (_, life2) = sess_dest_lookup_ttl(&ss, coarse_millis(), 7, host, port).unwrap();
        assert!(
            life2 > DEST_PIN_TTL_MS - 2_000 && life2 <= DEST_PIN_TTL_MS,
            "a full-life source keeps the memo TTL, got {life2} ms"
        );
    }

    /// Below the static per-shard ceiling the sweep must already fire once the
    /// shard reaches its fair share: with 32 session holders the fair cap is
    /// 256 (32 per shard), so a shard at 400 sweeps instead of waiting for 512.
    #[test]
    fn fair_shard_trigger_fires_below_the_static_shard_cap() {
        assert!(shard_over_share(400, 256), "32 per shard: 400 is over");
        assert!(shard_over_share(32, 256), "exactly the share fires");
        assert!(!shard_over_share(31, 256));
        // A lone holder: one eighth of its whole cap.
        assert!(shard_over_share(
            LOCAL_SESS_MAX / SESS_SHARDS,
            LOCAL_SESS_MAX
        ));
        assert!(!shard_over_share(
            LOCAL_SESS_MAX / SESS_SHARDS - 1,
            LOCAL_SESS_MAX
        ));
        // Defense in depth: the floor lives inside the helper, so a tiny
        // `fair_cap` can never produce a zero share (and a trigger on it).
        assert!(!shard_over_share(0, 0));
        assert!(shard_over_share(1, 0));
        assert!(shard_over_share(1, 7));
        assert!(!shard_over_share(0, 7));
    }

    /// The admission cap must be a real memory bound: raising the transport
    /// windows has to admit fewer connections, a budget too small for one
    /// connection still admits one (so the endpoint is diagnosable), and no
    /// configuration may exceed the hard connection cap.
    #[test]
    fn admission_cap_bounds_connections_by_memory() {
        let per_conn = per_connection_memory_bytes(&TransportTuning::default());
        assert_eq!(
            per_conn,
            8 * 1024 * 1024,
            "2/4/2 MB windows + 2 x 1 MB packets"
        );

        // No budget: the count cap stands, clamped to the hard cap.
        assert_eq!(
            admission_cap(MAX_CONNECTIONS, None, per_conn),
            MAX_CONNECTIONS
        );
        assert_eq!(admission_cap(1, None, per_conn), 1);

        // A 512 MiB budget / 8 MiB per connection = 64 connections.
        assert_eq!(admission_cap(MAX_CONNECTIONS, Some(512), per_conn), 64);
        // Raising the windows must lower the admitted count for the same budget.
        let wide = TransportTuning {
            receive_window: 16 * 1024 * 1024,
            send_window: 8 * 1024 * 1024,
            stream_receive_window: 8 * 1024 * 1024,
            ..TransportTuning::default()
        };
        let per_conn_wide = per_connection_memory_bytes(&wide);
        assert!(per_conn_wide > per_conn);
        assert!(
            admission_cap(MAX_CONNECTIONS, Some(512), per_conn_wide)
                < admission_cap(MAX_CONNECTIONS, Some(512), per_conn),
            "the same budget must admit fewer wide-window connections"
        );
        // Count cap still wins when it is the smaller of the two.
        assert_eq!(admission_cap(8, Some(512), per_conn), 8);
        // A budget too small for even one connection admits exactly one.
        assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), per_conn), 1);
        // No division by zero for a degenerate per-connection figure: the
        // divisor floors at one byte, so the count cap still binds.
        assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), 0), MAX_CONNECTIONS);
    }

    /// One connection's stream-task share must be bounded by the pool, floored
    /// so a crowd of peers cannot cut a real client down to a handful of flows,
    /// and never above what a connection can even open.
    #[test]
    fn one_connection_cannot_hold_the_whole_stream_pool() {
        // A lone connection is capped by the transport credit, not the pool:
        // 8192 streams is what it can open, and the pool is larger.
        assert_eq!(stream_share(1), MAX_BIDI_STREAMS_PER_CONN as usize);
        // Two connections each asking for the whole pool: half each.
        assert_eq!(stream_share(2), MAX_STREAM_TASKS / 2);
        // Four: a quarter each, so the pool cannot be consumed by four peers.
        assert_eq!(stream_share(4), MAX_STREAM_TASKS / 4);
        assert!(stream_share(4) * 4 <= MAX_STREAM_TASKS + MIN_STREAM_SHARE);
        // Beyond 16 admitted connections the floor takes over, so a crowd of
        // mostly-idle peers cannot starve a real client.
        assert_eq!(stream_share(16), MIN_STREAM_SHARE);
        assert_eq!(stream_share(64), MIN_STREAM_SHARE);
        assert_eq!(stream_share(MAX_CONNECTIONS), MIN_STREAM_SHARE);
        // A zero divisor (no admission accounting yet) must not divide by zero.
        assert_eq!(stream_share(0), MAX_BIDI_STREAMS_PER_CONN as usize);
        // The floor is never above the per-connection maximum.
        assert!(MIN_STREAM_SHARE <= MAX_BIDI_STREAMS_PER_CONN as usize);
    }

    /// Live loopback QUIC pair driving the production transport config, so the
    /// stream-admission tests below run `handle_tcp_stream` against real
    /// streams instead of a mock.
    async fn stream_test_pair() -> (quinn::Connection, quinn::Connection) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        scfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(scfg).unwrap();
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        server_cfg.transport_config(build_transport("bbr", 5));
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();

        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates({
                let mut r = rustls::RootCertStore::empty();
                r.add(cert.der().clone()).unwrap();
                r
            })
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(ccfg).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport("bbr", 5));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);

        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.await.unwrap()
        });
        let client_conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let server_conn = accept.await.unwrap();
        (client_conn, server_conn)
    }

    async fn read_reset_code(recv: &mut quinn::RecvStream) -> u64 {
        match recv.read_chunk(64 * 1024, true).await {
            Err(quinn::ReadError::Reset(code)) => code.into_inner(),
            Err(e) => panic!("expected a stream reset, got {e:?}"),
            Ok(_) => panic!("expected a stream reset, got bytes"),
        }
    }

    /// H7 pin: a stream that never sends its header must wait out the 5 s
    /// header budget holding NO stream-task permit. With every permit drained,
    /// the old order (permit before header) reset `0x05` immediately without
    /// reading; the new order reads first and resets `0x01` on the header
    /// timeout. Either the code or the elapsed time falsifies a regression.
    #[tokio::test]
    async fn header_wait_holds_no_stream_task_permit() {
        // Drain the process-wide pool. No other test in this binary touches
        // `stream_task_limiter`, so this cannot starve parallel tests.
        let _drained = stream_task_limiter()
            .clone()
            .acquire_many_owned(MAX_STREAM_TASKS as u32)
            .await
            .unwrap();
        assert_eq!(stream_task_limiter().available_permits(), 0);

        let (client_conn, server_conn) = stream_test_pair().await;
        let (mut _cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
        let (srv_send, srv_recv) = server_conn.accept_bi().await.unwrap();

        let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t0 = std::time::Instant::now();
        // No header bytes are ever sent: the 5 s budget must elapse first.
        handle_tcp_stream(
            srv_send,
            srv_recv,
            streams_held.clone(),
            MAX_STREAM_TASKS,
            1,
            true,
            server_conn.clone(),
        )
        .await;
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(4500),
            "the header budget must elapse before admission is even attempted, waited {waited:?}"
        );
        assert_eq!(
            read_reset_code(&mut cli_recv).await,
            0x01,
            "a header timeout resets 0x01 even with zero permits (old order reset 0x05 immediately)"
        );
        assert_eq!(
            streams_held.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a header-less stream must never take a share slot"
        );
        client_conn.close(0u32.into(), b"done");
        server_conn.close(0u32.into(), b"done");
    }

    /// The other half of the H7 pin: with the header already in, an exhausted
    /// pool must still refuse fail-fast with `0x05` — no dial attempted, no
    /// wait, no share slot taken. The target is loopback so even a leaked
    /// permit could not dial anywhere surprising.
    #[tokio::test]
    async fn admission_after_header_still_fails_fast() {
        let _drained = stream_task_limiter()
            .clone()
            .acquire_many_owned(MAX_STREAM_TASKS as u32)
            .await
            .unwrap();

        let (client_conn, server_conn) = stream_test_pair().await;
        let (mut cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
        // Valid IP-literal header for 127.0.0.1:9 (discard): decoding must
        // succeed so the stream reaches admission, where the drained pool
        // refuses it before any dial.
        cli_send
            .write_all(&[0x01, 127, 0, 0, 1, 0, 9])
            .await
            .unwrap();
        let (srv_send, srv_recv) = server_conn.accept_bi().await.unwrap();

        let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t0 = std::time::Instant::now();
        handle_tcp_stream(
            srv_send,
            srv_recv,
            streams_held.clone(),
            MAX_STREAM_TASKS,
            1,
            true,
            server_conn.clone(),
        )
        .await;
        let took = t0.elapsed();
        assert!(
            took < Duration::from_secs(4),
            "admission with the header in must fail fast, took {took:?}"
        );
        assert_eq!(
            read_reset_code(&mut cli_recv).await,
            0x05,
            "an exhausted pool after a good header resets 0x05"
        );
        assert_eq!(
            streams_held.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a refused stream must never take a share slot"
        );
        client_conn.close(0u32.into(), b"done");
        server_conn.close(0u32.into(), b"done");
    }

    /// The shard sweep never kills a *live* session, however far over the fair
    /// share the shard is: 512 sessions touched milliseconds ago all survive one
    /// sweep, because the only set it removes is the expired one (and the reap
    /// of a genuinely expired session is `take_idle`'s job, pinned with
    /// synthetic stamps by `sweep_local_rechecks_idle_before_removing`). The
    /// over-share's resource bound is the connection-level fair-share gate, not
    /// an eviction here.
    #[tokio::test]
    async fn a_live_over_share_shard_loses_nothing_to_the_sweep() {
        let mut m: HashMap<u32, SessEntry> = HashMap::new();
        for k in 0..512u32 {
            m.insert(k, capped_session(5));
        }
        assert!(
            shard_over_share(512, 256),
            "premise: the shard is over share"
        );
        let evicted = sweep_local(&mut m);
        assert!(
            evicted.is_empty(),
            "a live over-share must not be aborted: {} evicted",
            evicted.len()
        );
        assert_eq!(m.len(), 512);
    }

    /// A reader that exits after its session was recreated must not clear the
    /// new generation's memo. The old `forget` matched on `(conn, sess)` alone,
    /// so the exiting old reader wiped the recreated session's entry and its
    /// datagrams fell through to a table miss.
    #[tokio::test]
    async fn sess_memo_forget_never_wipes_a_recreated_memo() {
        use std::sync::atomic::AtomicU64;

        let old_sock = memo_sock();
        let new_sock = memo_sock();
        let epoch = Arc::new(AtomicU64::new(0));
        sess_memo_put(
            9,
            3,
            old_sock.clone(),
            Arc::new(AtomicU64::new(1)),
            live_reader(),
            epoch.clone(),
        );
        // Same (conn, sess), new socket and reader: the recreated session.
        sess_memo_put(
            9,
            3,
            new_sock.clone(),
            Arc::new(AtomicU64::new(2)),
            live_reader(),
            epoch,
        );
        // The old reader exits after the recreate.
        sess_memo_forget(9, 3, &old_sock);
        match sess_memo_lookup(9, 3) {
            SessHit::Fresh(s, _, _, _) => assert!(
                Arc::ptr_eq(&s, &new_sock),
                "the recreated memo must survive the old reader's forget"
            ),
            _ => panic!("the recreated memo must survive the old reader's forget"),
        }
        // The new generation's own forget still clears.
        sess_memo_forget(9, 3, &new_sock);
        assert!(matches!(sess_memo_lookup(9, 3), SessHit::Miss));
    }

    /// Session ids are allocated per client and every client hub counts from 1,
    /// so two connections whose DATAGRAM readers share one worker thread
    /// routinely carry the same sess id. The memo is a single thread-local
    /// slot, so matching on `sess` alone served one connection's socket to the
    /// other — its datagrams then went out on the wrong session and the replies
    /// came back on the wrong QUIC connection.
    #[tokio::test]
    async fn session_memo_never_crosses_connections() {
        use std::sync::atomic::AtomicU64;

        let a = memo_sock();
        let b = memo_sock();
        let last = Arc::new(AtomicU64::new(1));

        sess_memo_put(
            1,
            7,
            a.clone(),
            last.clone(),
            live_reader(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        assert!(matches!(sess_memo_lookup(2, 7), SessHit::Miss));
        match sess_memo_lookup(1, 7) {
            SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &a)),
            _ => panic!("the owning connection must still hit"),
        }
        assert!(matches!(sess_memo_lookup(1, 8), SessHit::Miss));

        sess_memo_forget(2, 7, &a);
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Fresh(..)));
        sess_memo_forget(1, 7, &a);
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));

        sess_memo_put(
            2,
            7,
            b.clone(),
            last,
            live_reader(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));
        match sess_memo_lookup(2, 7) {
            SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &b)),
            _ => panic!("connection 2 must see its own socket"),
        }
    }

    /// The sweeper and a connection close abort a session's reader, which then
    /// never reaches the cleanup after its loop — so the memo must learn that
    /// the reader is gone from the task handle itself, or it keeps handing out
    /// a socket nobody reads.
    #[tokio::test]
    async fn session_memo_ignores_finished_readers() {
        use std::sync::atomic::AtomicU64;

        let last = Arc::new(AtomicU64::new(1));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let h = tokio::spawn(async move {
            let _ = rx.await;
        });
        let finished = h.abort_handle();
        drop(tx);
        h.await.unwrap();
        assert!(finished.is_finished());
        sess_memo_put(
            3,
            1,
            memo_sock(),
            last.clone(),
            finished,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        assert!(matches!(sess_memo_lookup(3, 1), SessHit::Stale));

        let h = tokio::spawn(std::future::pending::<()>());
        let aborted = h.abort_handle();
        h.abort();
        while !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
        sess_memo_put(
            4,
            1,
            memo_sock(),
            last,
            aborted,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        assert!(matches!(sess_memo_lookup(4, 1), SessHit::Stale));
    }

    /// Security regression: after every cache slot has been written (and
    /// evicted at least once), the memo must still agree with `is_global_ip`
    /// for the whole filter table. A wrong `true` would let a peer dial
    /// private/loopback/link-local/CGNAT space.
    #[test]
    fn ip_cache_matches_predicate_after_full_fill() {
        for i in 0..200u8 {
            let _ = is_global_ip_cached(IpAddr::V4(Ipv4Addr::new(8, 8, 8, i)));
        }
        for i in 0..200u16 {
            let ip: IpAddr = format!("2001:4860::{i:x}").parse().unwrap();
            let _ = is_global_ip_cached(ip);
        }

        let cases = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "::1",
            "169.254.1.1",
            "fe80::1",
            "100.64.0.1",
            "64:ff9b::a00:1",
            "192.0.2.1",
            "2001:db8::1",
            "198.18.0.1",
            "224.0.0.1",
            "ff02::1",
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
        ];
        for s in cases {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(
                is_global_ip_cached(ip),
                is_global_ip(ip),
                "memo verdict diverged from is_global_ip for {s}"
            );
        }
    }

    /// A collision must evict, never mis-serve: two addresses sharing one slot
    /// but carrying opposite verdicts must each return the predicate's answer,
    /// in both probe orders.
    #[test]
    fn ip_cache_collision_evicts_and_never_mis_serves() {
        use std::collections::HashMap;

        // Non-global `0.0.0.0/8` candidates against global `8.8.0.0/16`
        // candidates; 1024 of each over 64 slots guarantees a cross-verdict
        // same-index pair.
        let non_global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::from(i)));
        let global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::new(8, 8, (i >> 8) as u8, i as u8)));

        let mut seen: HashMap<usize, IpAddr> = HashMap::new();
        let mut pair = None;
        for ip in non_global.chain(global) {
            let idx = ip_cache_idx(ip);
            match seen.get(&idx) {
                Some(&other) if is_global_ip(other) != is_global_ip(ip) => {
                    pair = Some((other, ip));
                    break;
                }
                Some(_) => {}
                None => {
                    seen.insert(idx, ip);
                }
            }
        }
        let (a, b) = pair.expect("two verdict classes over 64 slots must collide");
        assert_eq!(ip_cache_idx(a), ip_cache_idx(b));
        assert_ne!(is_global_ip(a), is_global_ip(b));

        assert_eq!(is_global_ip_cached(a), is_global_ip(a));
        assert_eq!(is_global_ip_cached(b), is_global_ip(b));
        assert_eq!(is_global_ip_cached(a), is_global_ip(a));
    }

    /// Churn holds the caps: creating and tearing down 1024 sessions leaves
    /// the table empty, every global permit released, the holder count
    /// restored, and no live session swept.
    ///
    /// The holder assertions are exact because this test and
    /// `fair_share_counts_session_holders_not_live_connections` serialize on
    /// `HOLDER_TEST_LOCK`: both mutate the process-global holder count, and
    /// exact reads would otherwise race each other.
    #[tokio::test]
    async fn session_churn_holds_caps_without_leaking() {
        use std::sync::atomic::Ordering;

        let _holder_guard = HOLDER_TEST_LOCK.lock().unwrap();
        const N: usize = 1024;
        let holders_before = session_holders().load(Ordering::Relaxed);
        let permits_before = session_limiter().available_permits();
        let ss = Arc::new(ShardedSessTable::new());
        for s in 1..=N as u32 {
            ss.shard(s).write().unwrap().insert(s, capped_session(0));
            ss.note_insert();
        }
        ss.note_empty_state();
        assert_eq!(ss.len(), N, "every churned session must be in the table");
        assert_eq!(
            session_holders().load(Ordering::Relaxed),
            holders_before + 1,
            "one non-empty table joins the fair-share denominator exactly once"
        );
        // Outstanding permits can only exceed this test's N (other tests hold
        // permits concurrently), never fall short of it — so the race-proof
        // form counts outstanding, not remaining.
        assert!(
            MAX_SESSIONS_GLOBAL - session_limiter().available_permits() >= N,
            "each session pins one global permit"
        );

        // A sweep over a churned-but-live table reaps nothing: the only set it
        // may remove is the expired one.
        let swept = ss.sweep_all(mono_millis());
        assert!(
            swept.is_empty(),
            "a sweep must not reap live sessions: {} evicted",
            swept.len()
        );
        assert_eq!(ss.len(), N);

        // Teardown mirrors `conn.closed()`: drain plus abort every reader, so
        // no task, socket or permit outlives the connection.
        let drained = ss.drain_all();
        assert_eq!(drained.len(), N);
        abort_evicted(drained);
        assert_eq!(ss.len(), 0);
        assert_eq!(
            session_holders().load(Ordering::Relaxed),
            holders_before,
            "draining the last session leaves the denominator"
        );
        // The exact holder reads above are done: release the serialization
        // guard before the quiescent permit wait below, which awaits.
        drop(_holder_guard);
        // Other tests hold permits concurrently, so balance is asserted
        // quiescently: every test releases what it took, and this test's N
        // are among them.
        for _ in 0..200 {
            if session_limiter().available_permits() >= permits_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            session_limiter().available_permits() >= permits_before,
            "all churned permits must be released"
        );
    }

    /// The recv-buf pool is bounded and exactly sized: whatever churn pushes
    /// in, at most `SESS_BUF_POOL_DEPTH` buffers idle per thread, each one a
    /// valid reader buffer.
    #[test]
    fn sess_recv_buf_pool_is_bounded_and_exactly_sized() {
        let mut bufs = Vec::new();
        for _ in 0..SESS_BUF_POOL_DEPTH + 4 {
            bufs.push(sess_recv_buf());
        }
        for b in &bufs {
            assert_eq!(b.len(), SESS_RECV_BUF_LEN);
        }
        for b in bufs {
            sess_recycle_buf(b);
        }
        assert!(
            sess_buf_pool_len() <= SESS_BUF_POOL_DEPTH,
            "the pool must drop past its depth, not grow with churn"
        );
        // Wrong-sized buffers are dropped, never pooled.
        sess_recycle_buf(vec![0u8; 16]);
        assert!(sess_buf_pool_len() <= SESS_BUF_POOL_DEPTH);
        // A recycled buffer comes back at the exact reader length, so the
        // `n == buf.len()` truncation check holds for reused buffers too.
        let b = sess_recv_buf();
        assert_eq!(b.len(), SESS_RECV_BUF_LEN);
        sess_recycle_buf(b);
    }

    /// The over-cap reap runs at most once per second process-wide, however
    /// many workers contend for it — otherwise every forged new-session
    /// datagram buys an O(sessions) table walk.
    #[test]
    fn fair_sweep_window_admits_one_sweep_per_second() {
        use std::sync::atomic::Ordering;

        // Synthetic stamps, not `mono_millis`: that clock is process uptime,
        // and a young test binary is not yet a second old, so a relative
        // window off it would never read expired. Nothing else in the test
        // build touches this static, and the window is restored below.
        let now = 10_000_000u64;
        FAIR_SWEEP_LAST_MS.store(now - 2000, Ordering::Relaxed);
        assert!(claim_fair_sweep(now), "an expired window must be claimable");
        assert!(
            !claim_fair_sweep(now),
            "the same instant must not claim twice"
        );
        assert!(!claim_fair_sweep(now + 999));
        assert!(claim_fair_sweep(now + 1000));
        FAIR_SWEEP_LAST_MS.store(0, Ordering::Relaxed);
    }
}
