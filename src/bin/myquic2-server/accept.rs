//! Admission limits: connection/dial/stream caps and the per-connection handler.
use super::*;
use futures_util::future::FutureExt as _;
use myquic2::mqp::ctl_stream::{self, CtlRate, CtlReceiver, CtlSender, StreamClass};
use myquic2::mqp::r2::{self, Caps, Ctl};
use myquic2::mqp::r2_flow::{
    CtlState, FlowBinding, FlowIds, FlowRegistry, FlowState, R2_MAX_RESOLVED_ADDRS, RegistryError,
    SessionFlows,
};
use myquic2::mqp::r3::CtlMessage;
use myquic2::mqp::wire::{self, FrameKind, Wire};
use myquic2::udp::{R2Reassembler, R2Stager};

/// Hard process-wide bounds: new QUIC connections are refused past this count
/// and new UDP sessions borrow from a shared permit pool, so a single peer
/// cannot exhaust fds/kernel memory (the server is unauthenticated by default).
pub(crate) const MAX_CONNECTIONS: usize = 4096;
/// Concurrent connections that have not completed token authentication.
/// Bounds the receive-window memory an unauthenticated peer can pin while the
/// process-wide cap still allows 4096 *authenticated* connections. With an
/// empty `auth_token` every peer is implicitly authenticated, so this cap is a
/// no-op and the operator must rely on the firewall + the lowered transport
/// windows.
pub(crate) const MAX_UNAUTH_CONNECTIONS: usize = 256;
/// Process-wide cap on concurrent TCP dials. Per-connection caps alone cannot
/// bound fd usage when an unauthenticated peer can open many connections.
pub(crate) const MAX_DIALS_GLOBAL: usize = 4096;
pub(crate) fn dial_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_DIALS_GLOBAL)))
}

/// TCP dial refusal counters, kept separate so a dial-permit exhaustion flood
/// is distinguishable from a dial-connect failure in debug logs (same split
/// the stream_task_limiter fail-fast path reports via its own reset code).
pub(crate) static DIAL_PERMIT_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(crate) static DIAL_CONNECT_FAILED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Process-wide cap on concurrently handled QUIC bidi streams. The transport's
/// per-connection stream credit ([`MAX_BIDI_STREAMS_PER_CONN`], now 8192 so one
/// admitted client can never stall in `open_bi`) times the connection cap is far
/// more live stream tasks than any host wants; this bounds the worst case to a
/// fixed number of tasks, and excess streams are reset by the accept loop. The
/// permit covers the dial/auth work only — the 5 s header read runs before it
/// is acquired, so trickle headers cannot exhaust the pool.
pub(crate) const MAX_STREAM_TASKS: usize = 16_384;

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
pub(crate) const MIN_STREAM_SHARE: usize = 1024;

/// Stream-task permits refused by the *per-connection* share rather than by the
/// process-wide pool. Split out because the two mean different things: the global
/// pool being empty is "the host is at capacity", this is "one peer took its
/// share and then some".
pub(crate) static STREAM_SHARE_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// One stream's admission reservation: decrements its connection's held-stream
/// count on every exit path, including the `reset` early returns and unwinding.
pub(crate) struct StreamShareGuard(pub(crate) Arc<std::sync::atomic::AtomicUsize>);

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
pub(crate) fn stream_share(admitted: usize) -> usize {
    (MAX_STREAM_TASKS / admitted.max(1)).clamp(MIN_STREAM_SHARE, MAX_BIDI_STREAMS_PER_CONN as usize)
}
pub(crate) fn stream_task_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_STREAM_TASKS)))
}

/// Process-wide credit for streams that are **only** reading their MQP-2
/// header.
///
/// The transport lets one connection open [`MAX_BIDI_STREAMS_PER_CONN`] (8192)
/// concurrent bidi streams, and the accept loop has to spawn a task for each
/// one *before* the header arrives (the 5 s header budget runs inside the
/// task). With the tokenless default 256 connections that was up to 2.1M
/// parked tasks — several GiB of task futures and quinn stream state — because
/// neither the per-connection share nor [`MAX_STREAM_TASKS`] can be charged
/// before the header is read: both must cover the dial/relay work, and a
/// trickling header must not be able to exhaust them (see [`handle_tcp_stream`]).
/// This credit bounds the *header stage* on its own. Concurrent header reads
/// are first-RTT and short-lived, so 4096 is far more than any real client
/// population produces; a stream that cannot get a credit is reset fail-fast
/// (`0x05`) exactly like an exhausted [`stream_task_limiter`].
///
/// **Two-stage bound.** A task must hold a header credit to run the 5 s header
/// read, then hands it back and takes a share slot + [`MAX_STREAM_TASKS`]
/// permit that cover the dial and the whole relay, so a long-lived flow can
/// never occupy header credit and a parked header task can never occupy the
/// stream pool.
pub(crate) const HEADER_TASK_CREDIT: usize = 4_096;

/// Header-stage refusals (see [`HEADER_TASK_CREDIT`]). Split out so an
/// exhausted header credit is distinguishable from a stream-share or
/// stream-pool refusal in the logs and in tests.
pub(crate) static HEADER_TASK_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn header_task_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(HEADER_TASK_CREDIT)))
}

/// Per-connection cap on concurrently parked TCP header reads.
///
/// [`HEADER_TASK_CREDIT`] is a **process-wide** bound: it says how many
/// 5 s header reads this host will park in total, not how many one peer may
/// take. Without a per-connection limit a single admitted peer opens its
/// transport allowance of bidi streams (`MAX_BIDI_STREAMS_PER_CONN` = 8192),
/// parks every header task the process can afford, and every other client's
/// CONNECT is reset `0x05` until the trickle finishes. Each parked stream can
/// also pin quinn-proto's reassembly gap chunks (`MAX_CHUNKS` = 1024), so the
/// bytes behind one header credit are per-stream rather than per-permit — the
/// global credit alone therefore bounds *tasks*, not one connection's share of
/// them. The process-wide bound (and its admission charge in `main.rs`) stays
/// [`HEADER_TASK_CREDIT`]; this constant is only the fair slice one connection
/// may hold. It is deliberately a large slice: real clients keep only a
/// handful of first-RTT header reads in flight, so this only bites a flood.
pub(crate) const HEADER_CREDIT_PER_CONN: usize = 256;

/// Per-connection parked-header refusals (the [`HEADER_CREDIT_PER_CONN`]
/// share). Split from [`HEADER_TASK_REFUSED`] so "one peer took more than its
/// slice" is distinguishable from "the host is out of header credit" in the
/// logs: the first is a peer-behaviour signal, the second a capacity signal.
pub(crate) static HEADER_SHARE_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Rate-limited (one line per second, with a suppressed count) warning for an
/// exhausted [`HEADER_TASK_CREDIT`].
///
/// `total` is the caller's refusal counter *after* its increment. The line is
/// formatted only by the window's winner: a header-credit flood is one wakeup
/// and one formatted line per second here, not one per refused stream (the
/// same argument as [`warn_stream_share_refused`]).
pub(crate) fn warn_header_credit_refused(total: u64) {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(u64::MAX);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    match myquic2::claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()) {
        None => {}
        Some(n) => {
            warn!(
                "{HEADER_TASK_CREDIT} concurrent header reads busy; resetting new TCP stream \
                 ({total} refused so far{})",
                if n > 0 {
                    format!(", {n} suppressed in the last second")
                } else {
                    String::new()
                }
            );
        }
    }
}

/// Connection cap actually admitted, i.e. `conn_cap` bounded by the optional
/// peer-memory budget.
///
/// `per_conn_bytes` is [`per_connection_memory_bytes`] for this server's
/// effective transport tuning (windows, DATAGRAM buffers, reassembly), so
/// raising the windows admits proportionally fewer connections instead of
/// silently multiplying the memory ceiling.
///
/// `fixed_bytes` is the **process-wide fixed term**: every cost that does not
/// scale with the admitted-connection count and is therefore charged once,
/// before the remainder is divided into connections —
/// - the UDP session pool ([`session_pool_memory_bytes`]: session sockets'
///   kernel caps plus each reply reader's userspace buffer; the session
///   semaphore is shared by every peer),
/// - every QUIC ingress endpoint's resident receive buffer and socket caps
///   ([`endpoint_memory_bytes`]),
/// - the relay pump buffers of the whole process-wide stream-task pool: two
///   16 KiB userspace buffers per flow **plus** the relay sockets' kernel
///   `SO_SNDBUF`/`SO_RCVBUF` caps ([`stream_pump_memory_bytes`]),
/// - the UDP retry pools ([`retry_pool_memory_bytes`]), the DNS slow-path
///   waiter set ([`dns_inflight_memory_bytes`]), per-worker thread-locals
///   ([`worker_scratch_bytes`]) and quinn's parked-stream reassembly metadata
///   ([`stream_assembler_memory_bytes`]).
///
/// Charging all of it here is what makes the printed worst case match what the
/// process can actually pin; charging only the session pool left the endpoint,
/// relay-pump and assembler terms invisible to `max_peer_memory_mb`. A budget
/// too small for even one connection clamps to one rather than zero: an
/// endpoint that admits nothing cannot be diagnosed from the outside.
///
/// Pure so the arithmetic is testable without a live endpoint.
pub(crate) fn admission_cap(
    conn_cap: usize,
    budget_mb: Option<u64>,
    per_conn_bytes: u64,
    fixed_bytes: u64,
) -> usize {
    let by_count = conn_cap.max(1);
    match budget_mb {
        None => by_count,
        Some(mb) => {
            let budget = mb.clamp(1, 1 << 20).saturating_mul(1024 * 1024);
            let for_connections = budget.saturating_sub(fixed_bytes);
            let by_memory = (for_connections / per_conn_bytes.max(1)).max(1);
            by_count.min(usize::try_from(by_memory).unwrap_or(usize::MAX))
        }
    }
}
/// One deferred target send of a drain burst: the session socket, the
/// destination (already normalized by `map_for_dual`), and the owned payload.
pub(crate) struct StagedSend {
    pub(crate) sock: Arc<tokio::net::UdpSocket>,
    pub(crate) dst: SocketAddr,
    pub(crate) payload: Bytes,
}

/// Flush staged target sends grouped by consecutive `(sock, dst)` runs.
///
/// One `sendmmsg` per run on Linux (one `try_send_to` per frame on the
/// portable fallback); runs flush in encounter order, so a flow's datagrams
/// keep their staging order on the wire. Staging is bounded by
/// [`LAST_HOP_DRAIN`] and cleared per burst, so the queue can never grow
/// unbounded. Each frame keeps exactly-once accounting through
/// [`udp_try_send_grouped`].
///
/// A run of length 1 takes the per-frame path directly: one connection
/// multiplexes every UDP association of its egress class, so the normal
/// multi-session drain burst stages a *single* frame per `(sock, dst)` run.
/// Filling the 32-entry refs array for it and re-entering the grouped-send
/// machinery (which, for a single frame, is the per-frame path anyway) was
/// pure setup on the common shape.
pub(crate) fn flush_staged_sends(staged: &mut Vec<StagedSend>) {
    let mut i = 0;
    while i < staged.len() {
        let mut j = i + 1;
        while j < staged.len()
            && Arc::ptr_eq(&staged[j].sock, &staged[i].sock)
            && staged[j].dst == staged[i].dst
        {
            j += 1;
        }
        // No header: an MQP-2 target send is the raw payload, so every frame is
        // a single borrowed iovec and nothing is copied here.
        if j - i == 1 {
            let one: [SendFrame<'_>; 1] = [(&[], &staged[i].payload[..])];
            udp_try_send_grouped(&staged[i].sock, staged[i].dst, &one);
            i = j;
            continue;
        }
        // Zero-alloc steady state: stack refs sized to the staging bound
        // (mirrors the client's `flush_staged`). Staging is bounded by
        // LAST_HOP_DRAIN, but the chunk loop keeps a defensive split so a
        // future caller with a longer run cannot silently drop frames.
        let mut refs: [SendFrame<'_>; LAST_HOP_DRAIN] = [(&[], &[]); LAST_HOP_DRAIN];
        let mut k = i;
        while k < j {
            let n = (j - k).min(LAST_HOP_DRAIN);
            for (r, s) in refs[..n].iter_mut().zip(&staged[k..k + n]) {
                *r = (&[], &s.payload[..]);
            }
            udp_try_send_grouped(&staged[i].sock, staged[i].dst, &refs[..n]);
            k += n;
        }
        i = j;
    }
    staged.clear();
}

/// Per-connection fast-path slots.
///
/// See the note at the declaration site in [`handle_conn`] for why this is a
/// table and not the single `(session, dst)` pair it used to be; the sizing
/// argument is there too. 128 covers the steady working set of a connection
/// that fronts a client pooling its associations onto a handful of QUIC
/// connections (the shipped client packs up to ~2000 live sessions per
/// connection), and is charged to admission by `R2_INGRESS_FIXED_BYTES`.
///
/// It is deliberately *not* sized to `LOCAL_SESS_MAX`: at ~440 B a slot that
/// would be ~1.7 MiB per connection, so the table is the working set and a
/// miss still resolves through the shard map. A full table evicts on every
/// arm, which is affordable only because an arm now costs a scan of the tag
/// and stamp arrays instead of the payload array — see [`FastTable`].
pub(crate) const FAST_SESS_SLOTS: usize = 128;

/// One session's steady-state entry in a connection's fast table.
///
/// Every field is exactly what the single-slot version kept, minus the ambiguity
/// of "which session is this about": the slot names its session, so a datagram
/// for any other session simply does not match and falls through.
pub(crate) struct FastSess {
    /// The session this slot describes; the probe compares it exactly.
    pub(crate) sess: u32,
    /// **Weak**, exactly like [`SessMemo::sock`]: a strong handle here is a
    /// second owner of the session's socket, and it outlives the session. The
    /// 180 s sweeper removes the table entry and aborts the reply reader, which
    /// drops both of *their* handles — but a strong slot would keep the socket
    /// (and its kernel send/receive buffer caps, `2 x sess_socket_buf()` per
    /// direction) alive outside the `MAX_SESSIONS_GLOBAL` budget until the next
    /// datagram happened to evict
    /// this slot, or until the connection closed. `abort.is_finished()` already
    /// stops the fast path from *using* such a socket, so retaining it bought
    /// nothing. An `upgrade` that fails is also the sharpest possible liveness
    /// signal: the session is gone, and the datagram falls through to the slow
    /// path, which recreates it.
    sock: std::sync::Weak<tokio::net::UdpSocket>,
    /// The session table's liveness stamp, so a hit refreshes it with no lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// The reply reader's abort handle: liveness at one atomic load.
    abort: tokio::task::AbortHandle,
    /// The session's allowlist epoch, so a re-record happens whenever a push
    /// this reader did not make (a spawned resolver task's) moved the allowlist.
    epoch: Arc<std::sync::atomic::AtomicU64>,
    /// The address this session's domain target resolves to, so a domain
    /// datagram skips the DNS lookup entirely instead of paying a hash, a key
    /// build and a key compare on every packet. Only ever consulted for the
    /// session it was armed for (see [`resolve_fast`]); it expires on its own —
    /// see [`ConnPin`].
    pin: Option<ConnPin>,
    /// Last destination recorded into this session's reply allowlist here. The
    /// allowlist update takes the table read lock, so it runs only when the
    /// destination actually changed (steady single-target flows pay nothing
    /// after the first datagram). Keeps the session id inside the tuple so
    /// [`mirror_record`] is used unchanged.
    last_dst: Option<(u32, SocketAddr, u64)>,
    /// SSRF verdict for the last fast-path destination of this session (see
    /// `fast_allow_cached`): steady single-target flows skip the re-derivation
    /// after the first datagram. Validated by the same epoch mechanism.
    allow: Option<(u32, SocketAddr, bool)>,
}

impl FastSess {
    /// Whether this slot describes exactly `s` and its reader is still live.
    ///
    /// The socket's liveness is checked separately by [`try_stage`], because a
    /// failed `Weak::upgrade` has to be treated as a *miss* (the slow path
    /// rebuilds the slot) rather than as a dead session.
    #[inline]
    fn is_live_for(&self, s: u32) -> bool {
        self.sess == s && !self.abort.is_finished()
    }
}

// The per-connection admission charge for the table is derived from this size
// (see `R2_INGRESS_FIXED_BYTES` in `config::tuning`): a field that grows an
// entry by a few bytes grows every connection's reservation by kilobytes, so
// this is pinned at the measured size rather than rounded up to a comfortable
// ceiling.
const _: () = assert!(std::mem::size_of::<FastSess>() <= 432);

/// The connection's fast-path table: session id to steady-state entry.
///
/// Three parallel arrays rather than one array of payload structs. Finding a
/// session and choosing a victim only ever needed the ids and the liveness
/// stamps; with the payloads inline, a scan had to touch up to 128 scattered
/// ~440-byte structs (`ConnPin` alone carries a 255-byte name), which is ~384
/// cache lines — measured at ~1.3 µs per arm in exactly the shape the shipped
/// client produces (1000+ live sessions per connection against 128 slots, so
/// ~88 % of datagrams take the slow path and arm). Split out, the same scan
/// reads 512 B of tags and 1 KiB of stamps and dereferences nothing.
pub(crate) struct FastTable {
    /// Session id per slot, or [`EMPTY_TAG`] while the slot is free.
    ///
    /// One 512-byte array — the entire probe is eight cache lines. Session ids
    /// come from a monotonic, never-reused counter (`hub.rs::alloc_sess`) and
    /// `get_or_create_sess` refuses id 0, so 0 is a free sentinel.
    tags: [u32; FAST_SESS_SLOTS],
    /// Liveness stamp per slot: the session's `last` when it was armed,
    /// advanced on a hit. The eviction order once the table is full. A reaped
    /// session stops advancing, so its entry ages out on its own instead of
    /// needing a liveness probe of its own.
    ages: [u64; FAST_SESS_SLOTS],
    /// The entries. Only ever reached through `tags`, by index.
    slots: [Option<FastSess>; FAST_SESS_SLOTS],
}

/// The tag of a free slot. Session 0 is never allocated.
const EMPTY_TAG: u32 = 0;

impl FastTable {
    pub(crate) const fn new() -> Self {
        Self {
            tags: [EMPTY_TAG; FAST_SESS_SLOTS],
            ages: [0; FAST_SESS_SLOTS],
            slots: [const { None }; FAST_SESS_SLOTS],
        }
    }

    /// The slot describing `s`, or `None`.
    ///
    /// A full scan of the tag array with **no chains**. The previous
    /// linear-probing version stopped at the first hole, which made an entry
    /// unreachable after an eviction — a miss, so safe — but also *unevictable*:
    /// its stamp is shared with the live session and keeps advancing, so it
    /// never looked like the quietest entry; and an arm that landed in a hole
    /// could install a second entry for a session that already had one.
    /// Scanning 128 tags is a handful of nanoseconds and removes both.
    #[inline]
    pub(crate) fn probe(&self, s: u32) -> Option<usize> {
        if s == EMPTY_TAG {
            return None;
        }
        self.tags.iter().position(|&tag| tag == s)
    }

    /// Where to publish `s`: its own slot, else the first free slot, else the
    /// quietest one.
    ///
    /// The table is a working set, not a router, so once it overflows the least
    /// recently active session loses its slot and simply takes the slow path
    /// on its next datagram.
    pub(crate) fn arm_index(&self, s: u32) -> usize {
        if let Some(idx) = self.probe(s) {
            return idx;
        }
        if let Some(idx) = self.tags.iter().position(|&tag| tag == EMPTY_TAG) {
            return idx;
        }
        let mut victim = 0;
        let mut oldest = self.ages[0];
        for (idx, &age) in self.ages.iter().enumerate().skip(1) {
            if age < oldest {
                oldest = age;
                victim = idx;
            }
        }
        victim
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut FastSess> {
        self.slots[idx].as_mut()
    }

    /// Publish `entry` at `idx`, stamped with the session's current liveness
    /// value, dropping whatever used to be there.
    ///
    /// Dropping the previous entry is load-bearing: it is what releases a
    /// reaped session's flow-table handle (see [`FastSess::flows`]).
    pub(crate) fn insert(&mut self, idx: usize, entry: FastSess) {
        self.ages[idx] = entry.last.load(std::sync::atomic::Ordering::Relaxed);
        self.tags[idx] = entry.sess;
        self.slots[idx] = Some(entry);
    }

    /// Drop `s`'s entry. Returns whether there was one.
    pub(crate) fn clear(&mut self, s: u32) -> bool {
        match self.probe(s) {
            Some(idx) => {
                self.tags[idx] = EMPTY_TAG;
                self.ages[idx] = 0;
                self.slots[idx] = None;
                true
            }
            None => false,
        }
    }

    /// Number of occupied slots. The datagram loop never needs it; the table's
    /// own tests use it to pin "a re-arm updates in place, and a full table
    /// evicts instead of growing".
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.tags.iter().filter(|&&tag| tag != EMPTY_TAG).count()
    }

    /// Advance `idx`'s liveness stamp to `stamp` when it moved.
    ///
    /// The stamp advances about once a second (see `touch_session_throttled`),
    /// so this store — and the dirty cache line it costs — happens on roughly
    /// one datagram in a thousand.
    #[inline]
    pub(crate) fn touch(&mut self, idx: usize, stamp: u64) {
        if stamp > self.ages[idx] {
            self.ages[idx] = stamp;
        }
    }
}

/// Resolve one datagram's target: the session's own pin first (free), then the
/// session's destination memo, then the DNS cache.
///
/// Only this session's own slot is ever consulted — the pin is keyed on
/// `(session, name, port)` and answering another session's datagram from it
/// would be a silent mis-route. A miss resolves with a scratch slot, so the
/// memo/DNS answer is still used for this datagram; the slow path then installs
/// the slot (and its own pin) for the session that asked.
pub(crate) fn resolve_fast(
    fast: &mut FastTable,
    ss: &SessTable,
    s: u32,
    a: TargetAddrRef<'_>,
    allow_private: bool,
) -> Option<SocketAddr> {
    let (h, p) = match a {
        TargetAddrRef::Ip(dst) => return Some(dst),
        TargetAddrRef::Domain(h, p) => (h, p),
    };
    // Scratch is only reached when this session has no slot of its own; nothing
    // is ever armed into it.
    let mut scratch: Option<ConnPin> = None;
    let pin = match fast.probe(s).and_then(|idx| fast.get_mut(idx)) {
        Some(slot) => &mut slot.pin,
        None => &mut scratch,
    };
    // `pinned_sess` is `s` in both arms: `resolve_pin` only trusts a pin whose
    // own `sess` matches, so a scratch (always `None`) can never arm anything.
    resolve_pin(ss, pin, s, s, h, p, allow_private)
}

/// Try the fast path for one datagram: validate the slot, mirror the allowlist
/// and stage the payload for the grouped flush.
///
/// Returns the payload back to the caller on a miss (`Err`), so the slow path
/// can hand it over without a clone: this is the hot path, and a `Bytes` clone
/// per datagram is a refcount round-trip for a value that only ever goes one
/// way.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_stage(
    fast: &mut FastTable,
    ss: &SessTable,
    conn_id: usize,
    s: u32,
    dst: SocketAddr,
    payload: Bytes,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
) -> Result<(), Bytes> {
    let Some(idx) = fast.probe(s) else {
        return Err(payload);
    };
    // `probe` only returns populated slots; keep the fallback a miss rather
    // than a panic (release builds are panic=abort).
    let Some(slot) = fast.get_mut(idx) else {
        return Err(payload);
    };
    if !slot.is_live_for(s) || !fast_allow_cached(&mut slot.allow, allow_private, s, dst) {
        return Err(payload);
    }
    // A failed upgrade means the session exited since the liveness check: treat
    // it as a miss so the slow path rebuilds the slot. This is the *only*
    // signal that releases the socket — see `FastSess::sock`.
    let Some(sock) = slot.sock.upgrade() else {
        return Err(payload);
    };
    touch_session_throttled(conn_id, s, &slot.last);
    // Record *before* the send: the reply reader validates the source against
    // this allowlist, and a failable fast path (a local echo target, a LAN DNS
    // resolver) can answer inside the window between the two calls.
    // `forward_server_dgram` has always ordered it this way.
    //
    // No clearing of this mirror on the slow path any more (the single-slot
    // version cleared a *shared* mirror there): `mirror_record` compares the
    // session's allowlist epoch, every mutation of that allowlist bumps it —
    // including one made by a spawned resolver task this reader cannot see — so
    // a stale mirror can never suppress a record it should have made.
    mirror_record(ss, &mut slot.last_dst, s, dst, Some(&slot.epoch));
    // The slot was just used, so it must not look like the quietest entry:
    // refresh its eviction stamp. `touch` writes only when the stamp moved (it
    // is shared with the session table and advances about once a second).
    let stamp = slot.last.load(std::sync::atomic::Ordering::Relaxed);
    staged.push(StagedSend {
        sock,
        dst: map_for_dual(dst),
        payload,
    });
    fast.touch(idx, stamp);
    Ok(())
}

/// Publish `(session, dst)` into this connection's fast table after the slow
/// path created or found the session, so the next datagram for it is a hit.
///
/// The slot is chosen by [`FastTable::arm_index`] (the session's own slot, else
/// the first free one, else the quietest), so a probe always finds it. A
/// `Stale`/`Miss` memo probe clears the session's slot instead: the session is
/// gone or invisible, and leaving the old entry in place would keep sending
/// into it.
///
/// Re-arming a session that already holds its slot only refreshes the pin and
/// the liveness stamp: this runs on the *slow* path of every datagram while the
/// table is too small for the live set, and rewriting the 432-byte entry (an
/// `Arc::downgrade` refcount round-trip plus the name copy) bought nothing
/// there — the socket, abort and epoch are the same values by construction.
///
/// Deliberately lock-free: it reads only the connection's thread-local session
/// memo, so a miss costs the slow path no session-table acquisition of its own
/// (the two it already takes are in `get_or_create_sess` and `remember_dst`).
pub(crate) fn arm_fast(
    fast: &mut FastTable,
    conn_id: usize,
    s: u32,
    a: TargetAddrRef<'_>,
    dst: SocketAddr,
    life: u64,
) {
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, abort, epoch) => {
            let (ph, pp) = target_name(a);
            let idx = fast.arm_index(s);
            // Already armed and still live: the pin is the only field that can
            // have changed (a new DNS generation), so update it in place. A
            // finished abort falls through: that entry describes a session this
            // arm just replaced, and its handles must be rewritten.
            let stamp = match fast.get_mut(idx) {
                Some(slot) if slot.sess == s && !slot.abort.is_finished() => {
                    pin_arm(&mut slot.pin, s, ph, pp, dst, life);
                    slot.last.load(std::sync::atomic::Ordering::Relaxed)
                }
                _ => {
                    let mut pin = None;
                    pin_arm(&mut pin, s, ph, pp, dst, life);
                    fast.insert(
                        idx,
                        FastSess {
                            sess: s,
                            sock: Arc::downgrade(&sock),
                            last,
                            abort,
                            epoch,
                            pin,
                            last_dst: None,
                            allow: None,
                        },
                    );
                    // `insert` stamped the slot from the entry's own `last`.
                    return;
                }
            };
            fast.touch(idx, stamp);
        }
        SessHit::Stale | SessHit::Miss => {
            fast.clear(s);
        }
    }
}

/// Owned form used to unify an inline address borrowed from the DATAGRAM with a
/// flow address borrowed from the session's clone-on-write table.
enum V3Addr<'a> {
    Inline(TargetAddrRef<'a>),
    Flow(Arc<TargetAddr>),
}

impl V3Addr<'_> {
    fn as_ref(&self) -> TargetAddrRef<'_> {
        match self {
            Self::Inline(a) => *a,
            Self::Flow(a) => (**a).as_ref(),
        }
    }
}

/// Resolve, stage or forward one MQP-3 item. Returns whether the target accepted
/// the payload (fast-stage or slow-path forward), which is the condition for
/// installing a new flow mapping.
#[allow(clippy::too_many_arguments)]
async fn forward_v3_item(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    sess: u32,
    a: TargetAddrRef<'_>,
    payload: Bytes,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    r2: Option<&Arc<R2ConnState>>,
) -> bool {
    let want = resolve_fast(fast, ss, sess, a, allow_private);
    let payload = match want {
        Some(dst) => {
            match try_stage(fast, ss, conn_id, sess, dst, payload, allow_private, staged) {
                Ok(()) => return true,
                Err(payload) => payload,
            }
        }
        None => payload,
    };
    // Keep the per-flow wire order: staged fast-path sends go out before the
    // slow path's immediate send.
    flush_staged_sends(staged);
    let used = forward_server_dgram(ss, cd, conn_id, sess, a, payload, allow_private, r2).await;
    if let Some((dst, life)) = used {
        arm_fast(fast, conn_id, sess, a, dst, life);
        true
    } else {
        false
    }
}

/// Decode and route one MQP-3 SINGLE/TRAIN.
///
/// The first frame for a flow carries its address and installs `(sess, flow)`
/// in the session's table after the target accepts it; a later frame can then
/// be compressed. A TRAIN is processed in wire order, so an inline open and a
/// compressed successor for the same flow in the same frame also work. A
/// compressed item with no mapping is dropped and counted, never guessed.
#[allow(clippy::too_many_arguments)]
async fn handle_v3_ingress(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    r2: Option<&Arc<R2ConnState>>,
    d: Bytes,
) {
    let Some(sess) = v3_sess(&d) else {
        dgram_drops::bump(&dgram_drops::REFUSED);
        return;
    };
    // One shard read lock per v3 train, not per datagram: a train carries up to
    // `MQP3_MAX_TRAIN_ITEMS` items, and the disarm below keeps the handle for
    // all of them. Caching this `Arc` in the fast slot was measured against
    // paying the probe here and lost: it cost every *rev2* miss a shard read
    // lock to fill a field only a rev3 connection ever reads.
    let mut flows = session_flows(ss, sess);
    let mut table = flows.as_ref().map(|f| f.load_full());
    let kind = d[0] & MQP3_KIND_MASK;
    match kind {
        MQP3_SINGLE => {
            let Ok(s) = decode_single(&d) else {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return;
            };
            if s.sess != sess {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return;
            }
            let addr = match s.inline {
                Some(a) => Some(V3Addr::Inline(a)),
                None => table
                    .as_ref()
                    .and_then(|t| t.get_arc(s.flow))
                    .map(V3Addr::Flow),
            };
            let Some(addr) = addr else {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::debug!(
                        "v3 SINGLE compressed flow missing: sess={sess} flow={} table={}",
                        s.flow,
                        table.as_ref().map_or(0, |t| t.len())
                    );
                }
                dgram_drops::bump(&dgram_drops::REFUSED);
                return;
            };
            udp_stats::payload(s.payload.len());
            let accepted = forward_v3_item(
                fast,
                ss,
                cd,
                conn_id,
                sess,
                addr.as_ref(),
                d.slice_ref(s.payload),
                allow_private,
                staged,
                r2,
            )
            .await;
            if accepted
                && let Some(inline) = s.inline
                && s.flow != MQP3_NO_FLOW
            {
                install_v3_flow(ss, &mut flows, &mut table, sess, s.flow, inline);
            }
        }
        MQP3_TRAIN => {
            let Ok(t) = decode_train(&d) else {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return;
            };
            if t.sess != sess {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return;
            }
            for item in t.items() {
                let addr = match item.inline {
                    Some(a) => Some(V3Addr::Inline(a)),
                    None => table
                        .as_ref()
                        .and_then(|t| t.get_arc(item.flow))
                        .map(V3Addr::Flow),
                };
                let Some(addr) = addr else {
                    static WARNED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        tracing::debug!(
                            "v3 TRAIN compressed flow missing: sess={sess} flow={} table={}",
                            item.flow,
                            table.as_ref().map_or(0, |t| t.len())
                        );
                    }
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    continue;
                };
                udp_stats::payload(item.payload.len());
                let accepted = forward_v3_item(
                    fast,
                    ss,
                    cd,
                    conn_id,
                    sess,
                    addr.as_ref(),
                    d.slice_ref(item.payload),
                    allow_private,
                    staged,
                    r2,
                )
                .await;
                if accepted
                    && let Some(inline) = item.inline
                    && item.flow != MQP3_NO_FLOW
                {
                    install_v3_flow(ss, &mut flows, &mut table, sess, item.flow, inline);
                }
            }
        }
        MQP3_FRAG => {
            // The compact fragment codec exists, but the reassembler still
            // keys MQP-2 fragments; large payloads keep using that form.
            dgram_drops::bump(&dgram_drops::REFUSED);
        }
        _ => {}
    }
}

/// Install an inline open into the session's flow table and refresh the local
/// snapshot so a later item in the same TRAIN can use the compressed form.
fn install_v3_flow(
    ss: &SessTable,
    flows: &mut Option<Arc<arc_swap::ArcSwap<FlowTable>>>,
    table: &mut Option<Arc<FlowTable>>,
    sess: u32,
    flow: u8,
    inline: TargetAddrRef<'_>,
) {
    if flows.is_none() {
        *flows = session_flows(ss, sess);
    }
    let Some(handle) = flows.as_ref() else {
        return;
    };
    let target = inline.into_owned();
    handle.rcu(|old| {
        let mut next = (**old).clone();
        if !next.insert_at_owned(flow, target.clone()) {
            // A reused id with a different address is not a legitimate reopen.
            // Drop the old binding so a later compressed frame cannot be
            // forwarded to the old (still authorized, but wrong) target.
            next.remove(flow);
        }
        Arc::new(next)
    });
    *table = Some(handle.load_full());
}

/// Test-only count of BATCH-ingress slow-path results published into a
/// connection's fast table.
///
/// The table itself lives on `handle_conn`'s datagram-reader task and is
/// invisible from outside, so this is what lets the regression test prove the
/// two BATCH arms reach [`arm_fast`] instead of discarding the
/// `Some((dst, life))` that [`forward_server_dgram`] returns — the P1 defect:
/// a bursty small-packet flow (the exact shape MQP-2 BATCH exists for) never
/// armed the table, so it paid the whole slow path per datagram forever.
#[cfg(test)]
pub(crate) static BATCH_FAST_ARMS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// MQP-3 rev2: per-connection state, ingress dispatch and flow installation
// ---------------------------------------------------------------------------

/// Minimum gap between two `CAPS` replies to `HELLO`s on one connection
/// (spec §3.4: `HELLO`/`CAPS` are idempotent and loss-tolerant, so the reply is
/// throttled rather than queued).
pub(crate) const R2_CAPS_MIN_INTERVAL_MS: u64 = 100;

/// Whether a `CAPS` reply is due at `now_ms` given the last one (`0` = never).
pub(crate) fn r2_caps_due(last_ms: u64, now_ms: u64) -> bool {
    last_ms == 0 || now_ms.saturating_sub(last_ms) >= R2_CAPS_MIN_INTERVAL_MS
}

/// Rev2 counters that are not part of the shared `dgram_drops`/`udp_stats`
/// surface (shared with the client, so not extended here). Relaxed atomics for
/// everything except the two hot families, which are thread-locally batched on
/// the same shape as `udp_stats::payload` (flush at 256 records or once per
/// second, whichever comes first; same-thread readers flush the caller's cell
/// first):
///
/// - `TRAIN_ITEMS` is per *item* (a TRAIN datagram can carry up to 64);
/// - `STEADY_SENT` / `OPEN_SRC_SENT` are per **sent reply frame**, i.e. the
///   downlink hot path: a direct process-wide `fetch_add` there put one shared
///   cache-line RMW on every relayed reply (the same contention the `udp_stats`
///   counters avoid at 1/256).
///
/// The bounded visibility of a batched counter is the one every `udp_stats`
/// counter already has: a pending count becomes visible at the next 256-mark or
/// 1 s check, and the 60 s report's accuracy is unaffected. The rest are read
/// directly by tests, so those stay one shared RMW per frame (a per-frame cost
/// next to a QUIC DATAGRAM send reads as noise).
///
/// [`snapshot`] is what the 60 s reporter reads (W9); it flushes the caller
/// thread's batched cells first, exactly like `udp_stats::snapshot`.
pub(crate) mod r2_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// `DATA OPEN` bindings installed (accepted + `FLOW_ACK`).
    pub(crate) static OPENS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static ACKS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static REJECTS: AtomicU64 = AtomicU64::new(0);
    /// Compressed steady/TRAIN item naming an id with no live binding.
    pub(crate) static UNKNOWN_ID: AtomicU64 = AtomicU64::new(0);
    pub(crate) static INLINE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static TRAIN_ITEMS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FRAGS: AtomicU64 = AtomicU64::new(0);
    /// Rev2 `FRAG` frames accepted into the reassembler (not dropped).
    pub(crate) static FRAG_FRAMES: AtomicU64 = AtomicU64::new(0);
    /// Reassembled rev2 payloads routed to a target.
    pub(crate) static FRAG_COMPLETE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static CAPS_SENT: AtomicU64 = AtomicU64::new(0);
    /// Valid `CTL HELLO` frames for this wire version (the `CAPS` trigger).
    ///
    /// `HELLO` is no longer a gate in front of the data plane — frames are
    /// dispatched as they arrive — so this count is pure observability: it says
    /// whether the client's handshake announcement arrived, independent of the
    /// data it may or may not have preceded.
    pub(crate) static HELLOS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static BAD_HELLO: AtomicU64 = AtomicU64::new(0);
    pub(crate) static SESS_CLOSES: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FLOW_CLOSES: AtomicU64 = AtomicU64::new(0);
    /// A repeated `FLOW_CLOSE`/`SESS_CLOSE` for an already-closed target. The
    /// sender repeats these (3x) because they are loss-tolerant: a duplicate is
    /// idempotent, never a refusal.
    pub(crate) static STALE_CLOSES: AtomicU64 = AtomicU64::new(0);
    /// Bindings dropped because their session ended (expiry/SESS_CLOSE/teardown).
    pub(crate) static SESSION_END_BINDINGS: AtomicU64 = AtomicU64::new(0);
    /// Downlink frames sent (steady `DATA`, same-flow `TRAIN`, `OPEN|SRC`).
    /// Thread-locally batched: see [`bump_steady_sent`].
    pub(crate) static STEADY_SENT: AtomicU64 = AtomicU64::new(0);
    /// See [`bump_open_src_sent`].
    pub(crate) static OPEN_SRC_SENT: AtomicU64 = AtomicU64::new(0);
    /// Peer `FLOW_ACK` frames processed: the peer confirmed it decoded an
    /// `OPEN|SRC` binding frame, which is what lets the server compress
    /// (`SourceMatch::Exact`) instead of re-sending the idempotent binding
    /// frame forever. Not batched: it only moves per rebind (rare), and the
    /// tests synchronize on it.
    pub(crate) static FLOW_ACKS_RECV: AtomicU64 = AtomicU64::new(0);
    /// `DATA OPEN`s dropped while another lookup for the same
    /// `(session, id)` was in flight, or because the per-connection
    /// pending-open cap was reached. Duplicates are expected under
    /// retransmission; the counter makes a name-resolution stall visible.
    pub(crate) static DNS_OPEN_DROPS: AtomicU64 = AtomicU64::new(0);
    /// Domain `DATA OPEN`s served by the **synchronous warm-cache fast path**
    /// (W5): the name was answered by this thread's DNS memo / the session's
    /// destination memo, so the payload was forwarded, the binding installed
    /// and `FLOW_ACK` sent inline in the datagram loop — no spawned lookup.
    pub(crate) static DNS_SYNC_OPENS: AtomicU64 = AtomicU64::new(0);
    /// A domain `DATA OPEN` whose lookup failed or timed out (including the
    /// negative-cache verdict). The triggering payload has **no address to be
    /// sent to**: it is inherently undeliverable and is dropped (UDP
    /// semantics), never re-routed, and never retried (a failed
    /// `resolve_all_cached` is negatively cached host-wide for 10 s before it
    /// returns, so an in-budget retry can only re-read that verdict).
    /// Split from [`DNS_OPEN_POLICY_DROP`]/[`DNS_OPEN_SESS_REFUSED`] so the
    /// loss class is observable rather than folded into one `REFUSED` count.
    pub(crate) static DNS_OPEN_DNS_FAIL: AtomicU64 = AtomicU64::new(0);
    /// A domain `DATA OPEN` whose every resolved record the SSRF policy
    /// rejected (or whose install found a conflicting `(session, target)`).
    /// The payload is undeliverable **by policy**; the delivery path stays
    /// fail-closed rather than re-routing around it.
    pub(crate) static DNS_OPEN_POLICY_DROP: AtomicU64 = AtomicU64::new(0);
    /// A domain `DATA OPEN` that resolved to a usable address but could not get
    /// a session to carry it (fair share, global pool, no DATAGRAM support, or a
    /// `SESS_CLOSE` cancelling the creation). The destination is valid but there
    /// is no live per-association delivery path, and the payload is dropped:
    /// inventing a different session path would violate the association's
    /// socket/reader ownership and SSRF authorization.
    pub(crate) static DNS_OPEN_SESS_REFUSED: AtomicU64 = AtomicU64::new(0);
    /// Staged small replies dropped because the connection stager was full
    /// (bounded queue) or could not be re-queued after a drain.
    pub(crate) static STAGE_FULL_DROPS: AtomicU64 = AtomicU64::new(0);
    /// Server-owned flows created for full-cone / unsolicited downlink sources
    /// (`DATA OPEN|SRC` with an id from the server's half).
    pub(crate) static FULL_CONE_FLOWS: AtomicU64 = AtomicU64::new(0);

    // ---- rev3 reliable control stream (`mqp::ctl_stream`) ----

    /// rev3 control streams accepted on this endpoint.
    pub(crate) static CTL_STREAMS: AtomicU64 = AtomicU64::new(0);
    /// rev3 streams refused because they were the *second* marker stream
    /// (exactly one control stream per connection).
    pub(crate) static CTL_STREAM_SECOND: AtomicU64 = AtomicU64::new(0);
    /// rev3 streams reset because their first byte was neither the control
    /// marker nor an MQP address type.
    pub(crate) static CTL_STREAM_BAD_FIRST: AtomicU64 = AtomicU64::new(0);
    /// rev3 control messages accepted from the peer (inside the rate budget).
    pub(crate) static CTL_MSGS_RECV: AtomicU64 = AtomicU64::new(0);
    /// rev3 control messages dropped: over the receiver rate budget, or queued
    /// for a server→client send that has no live control stream / full queue.
    pub(crate) static CTL_MSGS_DROPPED: AtomicU64 = AtomicU64::new(0);
    /// rev3 control-stream read/write errors (the stream is torn down; the
    /// datagram plane keeps running on its own loss-recovery).
    pub(crate) static CTL_STREAM_ERRORS: AtomicU64 = AtomicU64::new(0);
    /// Server→client `NEED_CONTEXT` frames queued because a compressed frame
    /// named an unknown id on a rev3 connection (the no-ACK repair path).
    pub(crate) static NEED_CONTEXT_SENT: AtomicU64 = AtomicU64::new(0);
    /// Client→server `NEED_CONTEXT` frames accepted (downlink context re-arm).
    pub(crate) static NEED_CONTEXT_RECV: AtomicU64 = AtomicU64::new(0);
    /// NEED_CONTEXT repairs dropped: unknown/unrepresentable flow id, or the
    /// repair rate budget/queue refused them. No state is ever allocated for a
    /// repair hint.
    pub(crate) static NEED_CONTEXT_DROPPED: AtomicU64 = AtomicU64::new(0);

    /// Snapshot of every rev2 counter, for the 60 s report (W9) and tests.
    ///
    /// Field order follows the report line; `since`/`is_idle` mirror
    /// `udp_stats::UdpSnapshot` so the reporter can print deltas and stay quiet
    /// when nothing moved.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Snapshot {
        pub(crate) opens: u64,
        pub(crate) acks: u64,
        pub(crate) rejects: u64,
        pub(crate) inline: u64,
        pub(crate) train_items: u64,
        pub(crate) steady_sent: u64,
        pub(crate) open_src_sent: u64,
        pub(crate) flow_acks_recv: u64,
        pub(crate) unknown_id: u64,
        pub(crate) dns_sync_opens: u64,
        pub(crate) dns_open_dns_fail: u64,
        pub(crate) dns_open_policy_drop: u64,
        pub(crate) dns_open_sess_refused: u64,
        pub(crate) dns_open_drops: u64,
        pub(crate) ctl_hellos: u64,
        pub(crate) ctl_caps_sent: u64,
        pub(crate) ctl_bad_hello: u64,
        pub(crate) sess_closes: u64,
        pub(crate) flow_closes: u64,
        pub(crate) stale_closes: u64,
        pub(crate) frag_refused: u64,
        pub(crate) frag_frames: u64,
        pub(crate) frag_complete: u64,
        pub(crate) stage_full_drops: u64,
        pub(crate) session_end_bindings: u64,
        pub(crate) full_cone_flows: u64,
        pub(crate) ctl_streams: u64,
        pub(crate) ctl_stream_second: u64,
        pub(crate) ctl_stream_bad_first: u64,
        pub(crate) ctl_msgs_recv: u64,
        pub(crate) ctl_msgs_dropped: u64,
        pub(crate) ctl_stream_errors: u64,
        pub(crate) need_context_sent: u64,
        pub(crate) need_context_recv: u64,
        pub(crate) need_context_dropped: u64,
    }

    impl Snapshot {
        /// Counters accumulated since `prev`.
        #[must_use]
        pub(crate) fn since(&self, prev: &Self) -> Self {
            fn d(now: u64, prev: u64) -> u64 {
                now.saturating_sub(prev)
            }
            Self {
                opens: d(self.opens, prev.opens),
                acks: d(self.acks, prev.acks),
                rejects: d(self.rejects, prev.rejects),
                inline: d(self.inline, prev.inline),
                train_items: d(self.train_items, prev.train_items),
                steady_sent: d(self.steady_sent, prev.steady_sent),
                open_src_sent: d(self.open_src_sent, prev.open_src_sent),
                flow_acks_recv: d(self.flow_acks_recv, prev.flow_acks_recv),
                unknown_id: d(self.unknown_id, prev.unknown_id),
                dns_sync_opens: d(self.dns_sync_opens, prev.dns_sync_opens),
                dns_open_dns_fail: d(self.dns_open_dns_fail, prev.dns_open_dns_fail),
                dns_open_policy_drop: d(self.dns_open_policy_drop, prev.dns_open_policy_drop),
                dns_open_sess_refused: d(self.dns_open_sess_refused, prev.dns_open_sess_refused),
                dns_open_drops: d(self.dns_open_drops, prev.dns_open_drops),
                ctl_hellos: d(self.ctl_hellos, prev.ctl_hellos),
                ctl_caps_sent: d(self.ctl_caps_sent, prev.ctl_caps_sent),
                ctl_bad_hello: d(self.ctl_bad_hello, prev.ctl_bad_hello),
                sess_closes: d(self.sess_closes, prev.sess_closes),
                flow_closes: d(self.flow_closes, prev.flow_closes),
                stale_closes: d(self.stale_closes, prev.stale_closes),
                frag_refused: d(self.frag_refused, prev.frag_refused),
                frag_frames: d(self.frag_frames, prev.frag_frames),
                frag_complete: d(self.frag_complete, prev.frag_complete),
                stage_full_drops: d(self.stage_full_drops, prev.stage_full_drops),
                session_end_bindings: d(self.session_end_bindings, prev.session_end_bindings),
                full_cone_flows: d(self.full_cone_flows, prev.full_cone_flows),
                ctl_streams: d(self.ctl_streams, prev.ctl_streams),
                ctl_stream_second: d(self.ctl_stream_second, prev.ctl_stream_second),
                ctl_stream_bad_first: d(self.ctl_stream_bad_first, prev.ctl_stream_bad_first),
                ctl_msgs_recv: d(self.ctl_msgs_recv, prev.ctl_msgs_recv),
                ctl_msgs_dropped: d(self.ctl_msgs_dropped, prev.ctl_msgs_dropped),
                ctl_stream_errors: d(self.ctl_stream_errors, prev.ctl_stream_errors),
                need_context_sent: d(self.need_context_sent, prev.need_context_sent),
                need_context_recv: d(self.need_context_recv, prev.need_context_recv),
                need_context_dropped: d(self.need_context_dropped, prev.need_context_dropped),
            }
        }

        /// Nothing happened in this interval; the reporter stays quiet.
        #[must_use]
        pub(crate) fn is_idle(&self) -> bool {
            *self == Self::default()
        }
    }

    impl std::fmt::Display for Snapshot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "opens={} acks={} rejects={} inline={} train_items={} steady_sent={} \
                 open_src_sent={} flow_acks={} unknown_id={}; \
                 dns: sync_open={} dns_fail={} policy_drop={} sess_refused={} open_drops={}; \
                 ctl: hellos={} caps={} bad_hello={} sess_close={} flow_close={} stale_close={}; \
                 frag: refused={} accepted={} complete={}; \
                 stage_full={} session_end={} full_cone={}; \
                 ctl-stream: streams={} second={} bad_first={} msgs={} dropped={} errors={} need_ctx(sent/recv/dropped)={}/{}/{}",
                self.opens,
                self.acks,
                self.rejects,
                self.inline,
                self.train_items,
                self.steady_sent,
                self.open_src_sent,
                self.flow_acks_recv,
                self.unknown_id,
                self.dns_sync_opens,
                self.dns_open_dns_fail,
                self.dns_open_policy_drop,
                self.dns_open_sess_refused,
                self.dns_open_drops,
                self.ctl_hellos,
                self.ctl_caps_sent,
                self.ctl_bad_hello,
                self.sess_closes,
                self.flow_closes,
                self.stale_closes,
                self.frag_refused,
                self.frag_frames,
                self.frag_complete,
                self.stage_full_drops,
                self.session_end_bindings,
                self.full_cone_flows,
                self.ctl_streams,
                self.ctl_stream_second,
                self.ctl_stream_bad_first,
                self.ctl_msgs_recv,
                self.ctl_msgs_dropped,
                self.ctl_stream_errors,
                self.need_context_sent,
                self.need_context_recv,
                self.need_context_dropped,
            )
        }
    }

    /// Totals since process start, after flushing this thread's batched cells.
    ///
    /// The bounded-visibility model is `udp_stats::snapshot`'s: a count pending
    /// on another worker becomes visible at that worker's next flush (256
    /// records or 1 s), which is far inside the reporter's 60 s cadence.
    pub(crate) fn snapshot() -> Snapshot {
        flush_thread();
        Snapshot {
            opens: OPENS.load(Ordering::Relaxed),
            acks: ACKS.load(Ordering::Relaxed),
            rejects: REJECTS.load(Ordering::Relaxed),
            inline: INLINE.load(Ordering::Relaxed),
            train_items: TRAIN_ITEMS.load(Ordering::Relaxed),
            steady_sent: STEADY_SENT.load(Ordering::Relaxed),
            open_src_sent: OPEN_SRC_SENT.load(Ordering::Relaxed),
            flow_acks_recv: FLOW_ACKS_RECV.load(Ordering::Relaxed),
            unknown_id: UNKNOWN_ID.load(Ordering::Relaxed),
            dns_sync_opens: DNS_SYNC_OPENS.load(Ordering::Relaxed),
            dns_open_dns_fail: DNS_OPEN_DNS_FAIL.load(Ordering::Relaxed),
            dns_open_policy_drop: DNS_OPEN_POLICY_DROP.load(Ordering::Relaxed),
            dns_open_sess_refused: DNS_OPEN_SESS_REFUSED.load(Ordering::Relaxed),
            dns_open_drops: DNS_OPEN_DROPS.load(Ordering::Relaxed),
            ctl_hellos: HELLOS.load(Ordering::Relaxed),
            ctl_caps_sent: CAPS_SENT.load(Ordering::Relaxed),
            ctl_bad_hello: BAD_HELLO.load(Ordering::Relaxed),
            sess_closes: SESS_CLOSES.load(Ordering::Relaxed),
            flow_closes: FLOW_CLOSES.load(Ordering::Relaxed),
            stale_closes: STALE_CLOSES.load(Ordering::Relaxed),
            frag_refused: FRAGS.load(Ordering::Relaxed),
            frag_frames: FRAG_FRAMES.load(Ordering::Relaxed),
            frag_complete: FRAG_COMPLETE.load(Ordering::Relaxed),
            stage_full_drops: STAGE_FULL_DROPS.load(Ordering::Relaxed),
            session_end_bindings: SESSION_END_BINDINGS.load(Ordering::Relaxed),
            full_cone_flows: FULL_CONE_FLOWS.load(Ordering::Relaxed),
            ctl_streams: CTL_STREAMS.load(Ordering::Relaxed),
            ctl_stream_second: CTL_STREAM_SECOND.load(Ordering::Relaxed),
            ctl_stream_bad_first: CTL_STREAM_BAD_FIRST.load(Ordering::Relaxed),
            ctl_msgs_recv: CTL_MSGS_RECV.load(Ordering::Relaxed),
            ctl_msgs_dropped: CTL_MSGS_DROPPED.load(Ordering::Relaxed),
            ctl_stream_errors: CTL_STREAM_ERRORS.load(Ordering::Relaxed),
            need_context_sent: NEED_CONTEXT_SENT.load(Ordering::Relaxed),
            need_context_recv: NEED_CONTEXT_RECV.load(Ordering::Relaxed),
            need_context_dropped: NEED_CONTEXT_DROPPED.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    thread_local! {
        static L_TRAIN_ITEMS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_STEADY_SENT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_OPEN_SRC_SENT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_REPLY_LAST_FLUSH_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// Records per thread before a reply-frame counter is flushed (the
    /// `udp_stats` threshold: one shared RMW per 256 records keeps a flood off
    /// the cache line while staying honest down to a few records per second).
    const FLUSH_PER_FRAME: u64 = 256;
    /// Wall bound for the flush: a low-rate worker flushes on its next reply
    /// once a second has passed, so a 60 s report can never miss a worker that
    /// counted fewer than 256 replies. `coarse_millis` (not the precise clock):
    /// this sits on the reply path and only whole seconds are at stake.
    const FLUSH_PER_FRAME_MS: u64 = 1_000;

    /// Flush this thread's pending batched counts into the shared statics.
    fn flush_locals() {
        L_TRAIN_ITEMS.with(|c| {
            let v = c.get();
            if v != 0 {
                TRAIN_ITEMS.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        L_STEADY_SENT.with(|c| {
            let v = c.get();
            if v != 0 {
                STEADY_SENT.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        L_OPEN_SRC_SENT.with(|c| {
            let v = c.get();
            if v != 0 {
                OPEN_SRC_SENT.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
    }

    /// Batched `+= 1` for a per-thread reply-frame counter: count flush at
    /// [`FLUSH_PER_FRAME`], time flush at [`FLUSH_PER_FRAME_MS`].
    ///
    /// `now_ms` is the **frame's** coarse clock sample, passed by the reply
    /// handler that already took one for its own interval gates. Reading the
    /// clock here instead would be a second `coarse_millis()` per downlink
    /// reply frame (W8b: one clock sample per frame).
    #[inline]
    fn bump_reply(
        local: &'static std::thread::LocalKey<std::cell::Cell<u64>>,
        global: &'static AtomicU64,
        now_ms: u64,
    ) {
        local.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            if v >= FLUSH_PER_FRAME {
                global.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        let due = L_REPLY_LAST_FLUSH_MS.with(|c| {
            let last = c.get();
            if now_ms.saturating_sub(last) >= FLUSH_PER_FRAME_MS {
                c.set(now_ms);
                true
            } else {
                false
            }
        });
        if due {
            flush_locals();
        }
    }

    /// One downlink steady frame (or same-flow TRAIN) handed to quinn.
    /// `now_ms` is the reply handler's per-frame coarse clock sample.
    #[inline]
    pub(crate) fn bump_steady_sent(now_ms: u64) {
        bump_reply(&L_STEADY_SENT, &STEADY_SENT, now_ms);
    }

    /// One downlink `OPEN|SRC` binding frame handed to quinn.
    /// `now_ms` is the reply handler's per-frame coarse clock sample.
    #[inline]
    pub(crate) fn bump_open_src_sent(now_ms: u64) {
        bump_reply(&L_OPEN_SRC_SENT, &OPEN_SRC_SENT, now_ms);
    }

    /// Flush this thread's pending batched counts into the shared statics.
    ///
    /// [`snapshot`] calls this before loading the shared counters, and the unit
    /// tests call it directly so a count made on the reading thread is visible
    /// exactly (the same rule `udp_stats::snapshot` documents). A pending count
    /// on another thread becomes visible at that thread's next flush threshold.
    pub(crate) fn flush_thread() {
        flush_locals();
    }

    /// One TRAIN item accepted for the data plane.
    ///
    /// Per item (not per frame): up to 64 per datagram, making this the one
    /// r2_stats line that sits on the packet path. Batched like
    /// `udp_stats::payload` with a 256-cell flush; the 60 s report reads it
    /// (`snapshot`/`flush_locals` publish a pending cell), so the same
    /// bounded-visibility model as the reply-frame counters applies.
    #[inline]
    pub(crate) fn bump_train_item() {
        L_TRAIN_ITEMS.with(|c| {
            let v = c.get().wrapping_add(1);
            if v >= 256 {
                TRAIN_ITEMS.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            } else {
                c.set(v);
            }
        });
    }
}

/// Per-QUIC-connection state for the MQP-3 rev2 data plane.
///
/// One instance is created by [`handle_conn`] and shared (via `Arc`) with the
/// datagram reader, the session sweeper and every session's reply reader, so
/// all of them resolve the same `wire_id -> binding` table:
/// - [`FlowRegistry`] is the connection-wide forward table a compressed frame
///   resolves through;
/// - [`FlowIds`] is the server owner's monotonic allocator (Phase 1b
///   server-initiated/full-cone flows; Phase 1a never allocates from it);
/// - [`CtlState`] carries the `CAPS` reply throttle and the `CTL` rate budget.
///
/// There is deliberately **no HELLO gate** here: rev2 frames are
/// self-identifying by first byte, so the ingress dispatcher routes them the
/// moment they arrive. `CTL HELLO` remains only the trigger that makes the
/// server answer with `CTL CAPS` (and bump the hello/caps counters) — a lost
/// HELLO can therefore no longer stall or drop data.
///
/// # Wire revisions
///
/// The same state model serves both wire revisions; [`Self::new`] is the
/// shipped rev2 default and [`Self::new_with_wire`] selects the connection's
/// revision (chosen from config + ALPN by the caller). rev3 differences are
/// confined to the control plane and the no-ACK context policy:
/// - no `CTL` DATAGRAMs and no `FLOW_ACK` (install is idempotent; bounded
///   context redundancy K=2 replaces the ACK);
/// - server→client `FLOW_REJECT`/`SESS_CLOSE`/`NEED_CONTEXT` are queued on the
///   one reliable client-opened control stream ([`Self::queue_ctl`]);
/// - an unknown compressed id is repaired with `NEED_CONTEXT` instead of only
///   being counted ([`Self::send_need_context`]);
/// - inbound `ASSOC_CLOSE`/`FLOW_CLOSE`/`NEED_CONTEXT` messages arrive on that
///   stream (see `handle_control_message`).
pub(crate) struct R2ConnState {
    /// Wire revision of this connection. Rev2 is the default and keeps the
    /// shipped byte-for-byte behaviour.
    wire: Wire,
    pub(crate) registry: Arc<FlowRegistry>,
    /// Server-owned id allocator. Reserved for Phase 1b (server-initiated and
    /// full-cone downlink flows); keeping it on the connection state means that
    /// phase does not have to rethread it.
    #[allow(dead_code)]
    pub(crate) ids: FlowIds,
    pub(crate) ctl: Arc<CtlState>,
    /// Phase-2 connection-scoped downlink stager. Every session reply reader
    /// pushes ready-to-send small payloads here and drains it at its drain-burst
    /// boundary, so replies from different sessions aggregate into one
    /// cross-session `TRAIN dict` with round-robin fairness. The mutex is the
    /// ownership shim the shared `R2Stager` API needs (`push`/`drain` take
    /// `&mut self`); its critical sections are pure encode/try-send work, never
    /// an await.
    pub(crate) stage: Arc<parking_lot::Mutex<R2Stager>>,
    /// Last `CAPS` reply stamp (`coarse_millis` epoch; `0` = never).
    last_caps_ms: std::sync::atomic::AtomicU64,
    /// Domain `DATA OPEN`s whose DNS lookup / first send is running on a
    /// spawned task, keyed by `(session, wire_id)`. Repeated OPENs for the same
    /// id are coalesced onto the in-flight lookup instead of spawning a second
    /// resolver; see [`R2ConnState::begin_pending_open`]. Payloads that arrive
    /// on such a duplicate are queued (bounded) and forwarded once the lookup
    /// resolves, because they are distinct data, not retransmissions of the
    /// first payload.
    ///
    /// The entry owns the cancellation flag and the duplicate payload queue. A
    /// `CTL SESS_CLOSE` for the session sets the flag
    /// (`cancel_pending_opens_for_session`), and the lookup task checks it when
    /// it is about to create the session, so a DNS answer that lands after the
    /// client closed the association cannot resurrect a session (and a wire
    /// binding) the close already reaped. The map stays bounded by
    /// [`MAX_PENDING_DNS_OPENS`]; an entry's lifetime is owned by the task's
    /// RAII guard, exactly like the coalescing key.
    pending_dns_opens:
        parking_lot::Mutex<std::collections::HashMap<(u32, u32), Arc<PendingDnsLookup>>>,
    /// Bytes currently queued across every [`PendingDnsLookup`] on this
    /// connection (see [`MAX_PENDING_DNS_BYTES`]). Reserved before a duplicate
    /// payload is pushed and released when it is drained or discarded, so a
    /// malicious duplicate stream cannot grow the queues past a fixed bound.
    pending_dns_bytes: std::sync::atomic::AtomicUsize,
    /// Domain datagrams resolved by the **generic slow path**
    /// ([`forward_server_dgram`]'s `Unresolved` arm), keyed by session.
    ///
    /// That path has no per-flow coalescing key (`pending_dns_opens` only
    /// exists for rev2 `DATA OPEN`), so a `CTL SESS_CLOSE` used to have no way
    /// to cancel a lookup that was already in flight: the spawned waiter would
    /// finish the DNS await and call the unguarded `get_or_create_sess`,
    /// recreating the just-closed association (socket + reader task + global
    /// session permit leaked until the 180 s idle sweep — the generic-path half
    /// of the SESS_CLOSE × DNS defect). Each waiter registers its cancellation
    /// flag here for the session it is resolving for; the close flags every
    /// matching entry (`cancel_dns_waiters_for_session`) and the waiter checks
    /// the flag before creating/delivering, with the creation itself routed
    /// through the guarded variant.
    ///
    /// Bounded by the process-wide [`dns_slow_path_limiter`](myquic2::dns_slow_path_limiter)
    /// permits: every waiter holds one for its whole lifetime, and it is
    /// dropped (with this entry) when the task ends, so one connection cannot
    /// grow the map past the 1024 concurrent lookups the process admits.
    dns_waiters:
        parking_lot::Mutex<std::collections::HashMap<u32, Vec<Arc<std::sync::atomic::AtomicBool>>>>,
    /// rev3 only: outbound queue into the connection's control-stream writer
    /// task. `None` until the client's control stream is accepted (and after it
    /// dies). Bounded: a peer that never opens the stream or stops reading must
    /// not make the server buffer control messages without limit, so a full or
    /// absent queue is a counted drop, never a datagram fallback (rev3 has no
    /// control DATAGRAMs).
    ctl_out: parking_lot::Mutex<Option<tokio::sync::mpsc::Sender<CtlMessage>>>,
    /// Receive half of [`Self::ctl_out`], moved into the control-stream writer
    /// task once the stream is accepted. Kept here (not threaded through the
    /// accept loop) so the accept path only needs the connection state.
    ctl_out_rx: parking_lot::Mutex<Option<tokio::sync::mpsc::Receiver<CtlMessage>>>,
    /// rev3 only: whether the single control stream has been claimed. A second
    /// marker stream is a protocol violation and is reset.
    ctl_stream_taken: std::sync::atomic::AtomicBool,
    /// rev3 only: receiver-side rate budget for inbound control messages
    /// (idempotent, reliable, but a hostile peer can still stream duplicates).
    ctl_rate: parking_lot::Mutex<CtlRate>,
    /// rev3 only: sender-side budget for `NEED_CONTEXT` repairs, so a flood of
    /// unknown compressed ids cannot turn into an unbounded control-stream
    /// write amplifier.
    need_ctx_rate: parking_lot::Mutex<CtlRate>,
    /// rev3 only: client→server `NEED_CONTEXT` mailbox.
    ///
    /// Reply readers are per session/task, so the repair hint travels through
    /// this connection-scoped slot: a bump of `ctx_need_epoch` tells every
    /// reply reader to pick up the (bounded) id list before its next reply.
    /// `None`/empty means no repair outstanding. Never allocates flow state —
    /// an unknown id is a hint, not a binding.
    ctx_need: parking_lot::Mutex<Vec<u32>>,
    ctx_need_epoch: std::sync::atomic::AtomicU64,
}

/// Upper bound on concurrent `NEED_CONTEXT` repairs a connection's mailbox
/// carries between two reply-reader syncs. Exceeding it clears the set (the
/// peer repeats a repair on its own retransmission/timeout); the point is only
/// that a hint flood cannot grow memory.
pub(crate) const CTX_NEED_CAP: usize = 64;

/// Concurrent domain lookups one connection may have in flight. The global
/// `dns_slow_path_limiter` bounds the actual resolver work; this is the
/// per-connection share that keeps one peer from queueing an unbounded set of
/// tasks (each waits on the limiter while holding its socket/target copies).
pub(crate) const MAX_PENDING_DNS_OPENS: usize = 16;

/// Bounds for duplicate payloads queued behind an in-flight domain OPEN.
///
/// A duplicate OPEN is the client's normal "no ACK yet" behaviour and its
/// payload is new data, so dropping it unconditionally loses application
/// datagrams for the whole DNS window. The queue keeps those payloads until the
/// first lookup resolves; the byte budget is per connection (shared across all
/// [`MAX_PENDING_DNS_OPENS`] lookups) and the item cap is per lookup, so a
/// zero-length-payload flood cannot grow a single deque without bound either.
pub(crate) const MAX_PENDING_DNS_PAYLOADS: usize = 64;
pub(crate) const MAX_PENDING_DNS_BYTES: usize = 256 * 1024;

/// One in-flight domain OPEN: its target, cancellation flag and the duplicate
/// payloads waiting for the lookup to resolve.
///
/// The target is what makes a queued duplicate safe: an id names one
/// `(session, target)` for the connection's life, so a duplicate that names a
/// different target must never be forwarded to the in-flight lookup's
/// destination (that would deliver the payload to the wrong host).
///
/// The queue mutex is only taken while the state's pending map is held (push) or
/// by the owning task/drop (drain), so there is no lock-order inversion with
/// `cancel_pending_opens_for_session` (which never touches the queue).
struct PendingDnsLookup {
    target: TargetAddr,
    cancelled: std::sync::atomic::AtomicBool,
    queued: parking_lot::Mutex<std::collections::VecDeque<Bytes>>,
}

/// Result of offering a duplicate OPEN payload to its in-flight lookup.
pub(crate) enum PendingPayload {
    /// Buffered; the lookup task will forward it after resolution.
    Queued,
    /// The item/byte bound was reached: the payload is dropped (counted at the
    /// caller), never a flow reject — the first lookup is still healthy.
    Full,
    /// The session was closed while the lookup was in flight.
    Cancelled,
    /// The duplicate names a different target than the in-flight lookup. That
    /// is the same protocol violation the installed-registry conflict check
    /// refuses, so the caller rejects the id instead of misrouting the payload.
    Conflict,
    /// The lookup finished between the duplicate check and the queue push; the
    /// caller should forward the payload through the normal inline path.
    NotPending,
}

/// RAII entry for one in-flight domain OPEN: removes the `(session, id)`
/// coalescing key when the lookup task exits, on every path (success, refusal,
/// timeout, cancellation).
///
/// The entry also owns the task's cancellation flag: a `CTL SESS_CLOSE` for
/// the session sets it while the lookup is in flight, and the task checks it
/// before publishing the session. The key is removed only here, so a duplicate
/// OPEN that races the cancel still coalesces (it must not spawn a second
/// resolver while the first is draining).
pub(crate) struct PendingDnsOpen {
    state: Arc<R2ConnState>,
    key: (u32, u32),
    entry: Arc<PendingDnsLookup>,
}

impl PendingDnsOpen {
    /// Whether the session this OPEN belongs to was closed while the lookup
    /// was in flight. Relaxed is sound for the same reason it is on the
    /// reader-side close flag: the flag only selects "abandon now" vs "the
    /// normal path", and the normal path's session-table write lock provides
    /// the ordering against `take_session` (see
    /// [`R2ConnState::cancel_pending_opens_for_session`]).
    pub(crate) fn is_cancelled(&self) -> bool {
        self.entry
            .cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The flag as a borrow, for the guarded session creation
    /// ([`get_or_create_sess_guarded`]).
    pub(crate) fn cancelled_flag(&self) -> &std::sync::atomic::AtomicBool {
        &self.entry.cancelled
    }

    /// Take the duplicate payloads queued behind this lookup. The global byte
    /// budget is released here; the task forwards the returned payloads to the
    /// already-resolved destination.
    pub(crate) fn take_queued(&self) -> Vec<Bytes> {
        self.state.take_pending_payloads(&self.entry)
    }
}

impl Drop for PendingDnsOpen {
    fn drop(&mut self) {
        self.state.pending_dns_opens.lock().remove(&self.key);
        // The key is gone, so no new duplicate can be queued. Whatever is left
        // belongs to a lookup that failed/was refused/was cancelled: release
        // its byte budget and account each payload as a DNS-window drop.
        for _ in self.state.take_pending_payloads(&self.entry) {
            r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
        }
    }
}

/// Result of trying to start a domain OPEN.
pub(crate) enum PendingOpen {
    Started(PendingDnsOpen),
    /// The same `(session, id)` already has a lookup in flight: drop the
    /// duplicate payload; the client repeats OPEN until the first ACK.
    Duplicate,
    /// This connection is already at [`MAX_PENDING_DNS_OPENS`].
    Full,
}

impl R2ConnState {
    /// Shipped-revision (rev2) connection state. Byte-for-byte the behaviour
    /// every existing call site had; the wiring task swaps the server's call
    /// site to [`Self::new_with_wire`] with the configured revision.
    ///
    /// Production goes through [`Self::new_with_wire`] (the handler always
    /// knows the connection's revision), so this is the fixture/test default —
    /// kept as the documented rev2 constructor the contract requires.
    #[allow(dead_code)]
    pub(crate) fn new() -> Arc<Self> {
        Self::new_with_wire(Wire::Rev2)
    }

    /// Connection state for `wire` (the revision selected by config + ALPN).
    pub(crate) fn new_with_wire(wire: Wire) -> Arc<Self> {
        Arc::new(Self {
            wire,
            registry: Arc::new(FlowRegistry::new(
                myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_CONN,
            )),
            ids: FlowIds::new(true),
            ctl: Arc::new(CtlState::new()),
            // The stager encodes with the connection's revision (rev2 default
            // keeps the shipped byte stream).
            stage: Arc::new(parking_lot::Mutex::new(R2Stager::new_with_wire(wire))),
            last_caps_ms: std::sync::atomic::AtomicU64::new(0),
            pending_dns_opens: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_dns_bytes: std::sync::atomic::AtomicUsize::new(0),
            dns_waiters: parking_lot::Mutex::new(std::collections::HashMap::new()),
            ctl_out: parking_lot::Mutex::new(None),
            ctl_out_rx: parking_lot::Mutex::new(None),
            ctl_stream_taken: std::sync::atomic::AtomicBool::new(false),
            ctl_rate: parking_lot::Mutex::new(CtlRate::default_budget()),
            need_ctx_rate: parking_lot::Mutex::new(CtlRate::new(256)),
            ctx_need: parking_lot::Mutex::new(Vec::new()),
            ctx_need_epoch: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Wire revision of this connection.
    #[must_use]
    pub(crate) fn wire(&self) -> Wire {
        self.wire
    }

    /// Attach the outbound control-stream queue (rev3, once the client's
    /// control stream has been accepted).
    fn install_ctl_out(&self, tx: tokio::sync::mpsc::Sender<CtlMessage>) {
        *self.ctl_out.lock() = Some(tx);
    }

    /// Attach the receive half of the outbound queue (called once by
    /// [`handle_conn_inner`]); the control-stream task takes it when it starts.
    fn install_ctl_out_rx(&self, rx: tokio::sync::mpsc::Receiver<CtlMessage>) {
        *self.ctl_out_rx.lock() = Some(rx);
    }

    /// Take the writer queue for the control-stream task (single consumer).
    fn take_ctl_out_rx(&self) -> Option<tokio::sync::mpsc::Receiver<CtlMessage>> {
        self.ctl_out_rx.lock().take()
    }

    /// Detach the outbound queue when the control stream dies, so later
    /// messages are counted as dropped instead of buffered forever.
    fn clear_ctl_out(&self) {
        *self.ctl_out.lock() = None;
    }

    /// Claim the connection's single rev3 control stream. `false` means one was
    /// already claimed: a second marker stream is a protocol violation.
    fn claim_ctl_stream(&self) -> bool {
        self.ctl_stream_taken
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Consume one slot of the inbound control-message rate budget.
    fn allow_ctl_message(&self, now_ms: u64) -> bool {
        self.ctl_rate.lock().allow(now_ms)
    }

    /// Queue one server→client control-stream message.
    ///
    /// `false` means the control stream is absent (not opened yet / torn down)
    /// or its bounded queue is full: the caller counts the drop. Never falls
    /// back to a DATAGRAM — rev3 has no control DATAGRAMs.
    fn queue_ctl(&self, msg: CtlMessage) -> bool {
        match self.ctl_out.lock().as_ref() {
            Some(tx) => tx.try_send(msg).is_ok(),
            None => false,
        }
    }

    /// Ask the reply readers to re-send downlink context for `wire_id`
    /// (client→server `NEED_CONTEXT`). Bounded mailbox + epoch bump; never
    /// allocates flow state.
    fn note_need_context(&self, wire_id: u32) {
        {
            let mut ids = self.ctx_need.lock();
            if ids.len() >= CTX_NEED_CAP {
                // Bounded hint set: drop the stale repairs instead of growing.
                // A peer that still misses context repeats its hint (the control
                // stream is reliable, so this is not a repair-loss path).
                r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
                ids.clear();
            }
            if !ids.contains(&wire_id) {
                ids.push(wire_id);
            }
        }
        self.ctx_need_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// The client's pending context repairs, when the epoch moved since `seen`.
    ///
    /// Called by every reply reader (per session) before classifying a reply;
    /// the id list is small and bounded, and the common case is one relaxed
    /// load returning `None`.
    pub(crate) fn take_need_context(&self, seen: &mut u64) -> Option<Vec<u32>> {
        let epoch = self
            .ctx_need_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        if epoch == *seen {
            return None;
        }
        *seen = epoch;
        Some(self.ctx_need.lock().clone())
    }

    /// Queue a `NEED_CONTEXT{fid}` repair for an unknown compressed id
    /// (server→client, rev3). Rate-limited; `false` when the id cannot be
    /// represented as a rev3 fid or the budget/queue refused the hint.
    fn send_need_context(&self, wire_id: u32) -> bool {
        let Some(fid) = wire::fid_for(wire_id) else {
            r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
            return false;
        };
        if !self.need_ctx_rate.lock().allow(coarse_millis()) {
            r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
            return false;
        }
        if self.queue_ctl(CtlMessage::NeedContext { fid }) {
            r2_stats::bump(&r2_stats::NEED_CONTEXT_SENT);
            true
        } else {
            r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
            false
        }
    }

    /// Queue a `REJECT{fid}` for a refused install/OPEN (rev3).
    fn send_reject(&self, wire_id: u32, reason: u8) -> bool {
        let Some(fid) = wire::fid_for(wire_id) else {
            r2_stats::bump(&r2_stats::CTL_MSGS_DROPPED);
            return false;
        };
        if self.queue_ctl(CtlMessage::Reject { fid, reason }) {
            true
        } else {
            r2_stats::bump(&r2_stats::CTL_MSGS_DROPPED);
            false
        }
    }

    /// Queue a `SESS_CLOSE` for a reaped association (rev3). The reliable
    /// stream replaces the rev2 three-DATAGRAM repeat; one message is enough.
    fn send_sess_close(&self, sess: u32) -> bool {
        if self.queue_ctl(CtlMessage::SessClose { sess, reason: 0 }) {
            true
        } else {
            r2_stats::bump(&r2_stats::CTL_MSGS_DROPPED);
            false
        }
    }

    /// Register one generic-slow-path DNS waiter for `sess`, returning the RAII
    /// guard that owns its cancellation flag (see the [`dns_waiters`] field).
    ///
    /// The waiter is registered **before** it is spawned (the only slow-path
    /// datagram's spawn is synchronous), and the datagram reader processes
    /// datagrams in order, so a `SESS_CLOSE` for the session always runs after
    /// the registration and finds the flag; the waiter's guarded creation then
    /// refuses to publish a session for the closed association.
    pub(crate) fn begin_dns_waiter(self: &Arc<Self>, sess: u32) -> DnsWaiter {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.dns_waiters
            .lock()
            .entry(sess)
            .or_default()
            .push(Arc::clone(&flag));
        DnsWaiter {
            state: Arc::clone(self),
            session: sess,
            flag,
        }
    }

    /// Flag every in-flight generic-slow-path waiter of `sess` (`CTL
    /// SESS_CLOSE`). Like [`Self::cancel_pending_opens_for_session`], the
    /// entries are flagged, not removed: the task's RAII guard owns the entry's
    /// lifetime and clears it on exit.
    ///
    /// Ordering proof is the same: this runs before `r2_close_session`'s
    /// `take_session` (the shard write lock), and the waiter's guarded creation
    /// re-reads the flag inside that same lock, immediately before publishing.
    pub(crate) fn cancel_dns_waiters_for_session(&self, sess: u32) {
        let set = self.dns_waiters.lock();
        for flag in set.get(&sess).into_iter().flatten() {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Test-only count of registered generic-slow-path waiters for `sess`.
    #[cfg(test)]
    pub(crate) fn dns_waiter_count(&self, sess: u32) -> usize {
        self.dns_waiters
            .lock()
            .get(&sess)
            .map_or(0, std::vec::Vec::len)
    }

    /// Begin (or coalesce) one domain OPEN. The returned guard owns the
    /// pending-entry lifetime; a duplicate or cap refusal leaves the set
    /// unchanged.
    ///
    /// `target` is stored only when a lookup actually starts (the duplicate
    /// path returns before allocating), so the steady retransmission pays no
    /// target clone.
    pub(crate) fn begin_pending_open(
        self: &Arc<Self>,
        sess: u32,
        id: u32,
        target: &TargetAddr,
    ) -> PendingOpen {
        let key = (sess, id);
        let mut set = self.pending_dns_opens.lock();
        if set.contains_key(&key) {
            return PendingOpen::Duplicate;
        }
        if set.len() >= MAX_PENDING_DNS_OPENS {
            return PendingOpen::Full;
        }
        let entry = Arc::new(PendingDnsLookup {
            target: target.clone(),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            queued: parking_lot::Mutex::new(std::collections::VecDeque::new()),
        });
        set.insert(key, Arc::clone(&entry));
        PendingOpen::Started(PendingDnsOpen {
            state: Arc::clone(self),
            key,
            entry,
        })
    }

    /// Queue one duplicate OPEN payload behind its in-flight lookup.
    ///
    /// The pending-map lock is held across the queue push, so the RAII guard's
    /// map removal cannot race a push into an entry that is already being
    /// dropped: either the push is visible to the guard's final drain, or the
    /// caller sees [`PendingPayload::NotPending`] and forwards the payload on
    /// the ordinary path.
    ///
    /// A duplicate naming a different target is refused as
    /// [`PendingPayload::Conflict`]: an id is bound to one `(session, target)`
    /// for the connection's life, so queueing it here would forward it to the
    /// in-flight lookup's destination instead of the one the frame named.
    pub(crate) fn queue_pending_open_payload(
        &self,
        sess: u32,
        id: u32,
        target: &TargetAddrRef<'_>,
        payload: &Bytes,
    ) -> PendingPayload {
        let set = self.pending_dns_opens.lock();
        let Some(entry) = set.get(&(sess, id)) else {
            return PendingPayload::NotPending;
        };
        if entry.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return PendingPayload::Cancelled;
        }
        if entry.target.as_ref() != *target {
            return PendingPayload::Conflict;
        }
        let mut queued = entry.queued.lock();
        if queued.len() >= MAX_PENDING_DNS_PAYLOADS || !self.reserve_pending_bytes(payload.len()) {
            return PendingPayload::Full;
        }
        queued.push_back(payload.clone());
        PendingPayload::Queued
    }

    /// Reserve `bytes` in the connection's duplicate-payload budget. A zero
    /// length payload reserves nothing but still needs the item cap.
    fn reserve_pending_bytes(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        self.pending_dns_bytes
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |current| {
                    let next = current.checked_add(bytes)?;
                    (next <= MAX_PENDING_DNS_BYTES).then_some(next)
                },
            )
            .is_ok()
    }

    /// Drain an entry's queued duplicate payloads and release their budget.
    fn take_pending_payloads(&self, entry: &PendingDnsLookup) -> Vec<Bytes> {
        let drained: Vec<Bytes> = {
            let mut queued = entry.queued.lock();
            queued.drain(..).collect()
        };
        let bytes: usize = drained.iter().map(Bytes::len).sum();
        if bytes != 0 {
            self.pending_dns_bytes
                .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
        }
        drained
    }

    /// Bytes currently queued for duplicate domain-OPEN payloads (test probe
    /// and the bound the queue must never exceed).
    #[cfg(test)]
    pub(crate) fn pending_dns_bytes(&self) -> usize {
        self.pending_dns_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cancel every in-flight domain OPEN belonging to `sess` (`CTL
    /// SESS_CLOSE`). The entries are **flagged, not removed**: the key stays
    /// owned by the lookup task's RAII guard, so an OPEN retransmitted in the
    /// same window still coalesces instead of spawning a second resolver.
    ///
    /// Ordering proof (the whole reason a flag is enough): this runs *before*
    /// `r2_close_session`'s `take_session`, which removes the entry under the
    /// session's shard write lock. The lookup task checks the flag **inside**
    /// the same `sh.write()` critical section, immediately before publishing
    /// the session, so the two interleavings are:
    /// - the flag store happens first → the task's check sees it and rolls the
    ///   insert back (aborts its reader, returns the global permit), so no
    ///   session is published;
    /// - the task's check runs first (flag still false) → it holds the shard
    ///   write lock across the insert, so `take_session` is serialized after it
    ///   and removes the just-published entry.
    ///
    /// Either way no session (and no binding/ACK for a closed association)
    /// outlives the close. The flag is only ever set false→true, and a session
    /// id is never reused by a conforming client, so a stale flag cannot
    /// cancel an unrelated future OPEN.
    pub(crate) fn cancel_pending_opens_for_session(&self, sess: u32) {
        let set = self.pending_dns_opens.lock();
        for ((s, _), entry) in set.iter() {
            if *s == sess {
                entry
                    .cancelled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        // The guards remove their keys on task exit; this loop deliberately
        // does not, so a retransmitted OPEN still coalesces onto the task that
        // is about to notice the flag and stop.
    }

    /// Whether this HELLO may be answered with CAPS now (100 ms throttle).
    ///
    /// Uses the precise [`mono_millis`] clock, not the 1 s-quantized
    /// [`coarse_millis`]: the throttle window is 100 ms, and a coarse sample
    /// would suppress every retransmitted HELLO inside the same second. Control
    /// frames are rare, so one vDSO read here is free.
    fn caps_due(&self, now_ms: u64) -> bool {
        use std::sync::atomic::Ordering;
        let last = self.last_caps_ms.load(Ordering::Relaxed);
        if !r2_caps_due(last, now_ms) {
            return false;
        }
        // `0` means "never replied", so the first real stamp is never 0.
        self.last_caps_ms.store(now_ms.max(1), Ordering::Relaxed);
        true
    }
}

/// RAII registration of one generic-slow-path DNS waiter (see
/// [`R2ConnState::begin_dns_waiter`]).
///
/// Owns the waiter's cancellation flag until the lookup task exits on every
/// path (delivered, refused, timed out, cancelled), at which point the entry is
/// removed from the waiter registry so a long-lived connection cannot
/// accumulate flags for sessions the peer has churned through.
pub(crate) struct DnsWaiter {
    state: Arc<R2ConnState>,
    session: u32,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl DnsWaiter {
    /// Whether `CTL SESS_CLOSE` closed the session while the lookup was in
    /// flight. Relaxed is sound for the same reason as
    /// [`PendingDnsOpen::is_cancelled`].
    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The flag as a borrow, for [`get_or_create_sess_guarded`].
    pub(crate) fn cancelled_flag(&self) -> &std::sync::atomic::AtomicBool {
        &self.flag
    }
}

impl Drop for DnsWaiter {
    fn drop(&mut self) {
        let mut map = self.state.dns_waiters.lock();
        let empty = match map.get_mut(&self.session) {
            Some(flags) => {
                flags.retain(|f| !Arc::ptr_eq(f, &self.flag));
                flags.is_empty()
            }
            None => false,
        };
        if empty {
            map.remove(&self.session);
        }
    }
}

/// Best-effort control-frame send (control frames are loss-tolerant).
fn r2_send_ctl(cd: &quinn::Connection, ctl: &Ctl) {
    let _ = try_send_datagram(cd, r2::encode_ctl(ctl));
}

/// Tell the client that session `sess` is gone (`CTL SESS_CLOSE`), cloned and
/// sent up to three times best-effort — the same shape the client's association
/// exit uses, because a CTL frame may be lost or reordered and the close is
/// idempotent on the receiver.
///
/// Every **server-side reap path** calls this after it removed the session
/// (idle sweep, fair-share / session-pool sweeps, the reply reader's own exit):
/// without it the client keeps sending steady frames for a session the server
/// no longer has — each one fails lookup and is silently dropped — until its
/// own idle path notices. A terminal/blocked verdict stops the repeats: a dead
/// or backed-up DATAGRAM path cannot carry them and the receiver's idle sweep is
/// the correctness backstop.
pub(crate) fn r2_send_sess_close(
    cd: &quinn::Connection,
    state: Option<&Arc<R2ConnState>>,
    sess: u32,
) {
    match state.map(|s| s.wire()).unwrap_or(Wire::Rev2) {
        Wire::Rev2 => {
            let frame = r2::encode_ctl(&Ctl::SessClose { sess, reason: 0 });
            for _ in 0..3 {
                if try_send_datagram(cd, frame.clone()) != DatagramSend::Sent {
                    return;
                }
            }
        }
        Wire::Rev3 => {
            // The reliable stream replaces the rev2 three-DATAGRAM repeat: one
            // ordered, retransmitted message is enough, and a lost close cannot
            // blackhole the association anymore.
            match state {
                Some(state) => {
                    let _ = state.send_sess_close(sess);
                }
                // No connection state (a unit fixture): count the undeliverable
                // notification instead of falling back to a rev2 DATAGRAM a
                // rev3 peer cannot read.
                None => r2_stats::bump(&r2_stats::CTL_MSGS_DROPPED),
            }
        }
    }
}

/// Send the reap-time `SESS_CLOSE` notifications **off the reaping task**.
///
/// A connection may hold up to the per-connection session cap; a 60 s idle
/// sweep or a pool/fair-share reap can evict thousands of sessions at once, and
/// three best-effort control datagrams each was ~12k non-blocking sends plus
/// the registry purges on the datagram-reader/shard runtime that also drives
/// every connection's QUIC. The reap therefore hands the session ids to this
/// detached task: bounded work per wake (one chunk of ids), then `yield_now`
/// so the runtime can service the shard between chunks.
///
/// Best-effort by construction: the frames are loss-tolerant and the peer's
/// own idle sweep is the correctness backstop, so a closed/backed-up connection
/// just stops early (`close_reason` check per chunk). The batch is bounded by
/// the reap itself (the per-connection session cap); the `Vec<u32>` costs 16
/// KiB only in the pathological full-reap case.
pub(crate) fn spawn_sess_close_notifications(
    cd: quinn::Connection,
    state: Option<Arc<R2ConnState>>,
    sessions: Vec<u32>,
) {
    if sessions.is_empty() {
        return;
    }
    tokio::spawn(async move {
        // ~64 sessions (192 datagrams) per wakeup: long enough that the detach
        // still removes thousands of sends from the reap path, short enough
        // that a saturated connection does not hold a worker for long.
        const CHUNK: usize = 64;
        for chunk in sessions.chunks(CHUNK) {
            if cd.close_reason().is_some() {
                return;
            }
            for &sess in chunk {
                r2_send_sess_close(&cd, state.as_ref(), sess);
            }
            tokio::task::yield_now().await;
        }
    });
}

/// Count one rev2 policy/gate refusal (shared `REFUSED` plus the rev2 counter).
fn r2_refuse(counter: Option<&std::sync::atomic::AtomicU64>) {
    dgram_drops::bump(&dgram_drops::REFUSED);
    if let Some(c) = counter {
        r2_stats::bump(c);
    }
}

/// Refuse one client flow: the rev2 `FLOW_REJECT` DATAGRAM, or the equivalent
/// rev3 reliable-stream `REJECT{fid}` message. The flow id cannot be represented
/// as a rev3 fid only past the 14-bit exhaustion point, where the control
/// message is counted as dropped (the peer's id space is the same bound).
fn r2_reject(state: &Arc<R2ConnState>, cd: &quinn::Connection, id: u32, reason: u8) {
    r2_stats::bump(&r2_stats::REJECTS);
    match state.wire() {
        Wire::Rev2 => r2_send_ctl(cd, &Ctl::FlowReject { id, reason }),
        Wire::Rev3 => {
            let _ = state.send_reject(id, reason);
        }
    }
}

/// Acknowledge an accepted `DATA OPEN`.
///
/// rev2 sends the post-hoc `FLOW_ACK` that unlocks the client's compression.
/// rev3 has **no ACK at all**: the install is idempotent and bounded context
/// redundancy (K=2) is what makes the binding usable, so this is a no-op there
/// (the `ACKS` counter then only tracks rev2 ACK datagrams).
fn r2_ack_open(state: &Arc<R2ConnState>, cd: &quinn::Connection, id: u32) {
    if state.wire() == Wire::Rev2 {
        r2_send_ctl(
            cd,
            &Ctl::FlowAck {
                id,
                status: r2::R2_ACK_OPEN,
            },
        );
        r2_stats::bump(&r2_stats::ACKS);
    }
}

/// Install an accepted `DATA OPEN` in both tables: the connection-wide forward
/// registry and the session's reverse table.
///
/// The target has already accepted the payload when this runs; an install
/// failure therefore only means "no compression", never "payload lost".
///
/// Both tables must be published or neither: a binding that lives only in the
/// forward registry would accept compressed uplink frames for a flow the reply
/// side cannot classify (replies then degrade to `INLINE` at best), and it
/// would keep a registry slot until the connection ends — the session's
/// reverse table is the only thing `r2_remove_flow`/the reap purge
/// can find it through. The reverse-table insert can fail only when a
/// concurrent install filled one of the 64 per-session slots between the
/// `is_full` check above and this `rcu`; the registry entry is rolled back then
/// and the caller reports `TABLE_FULL` instead of ACKing a half-installed flow.
pub(crate) fn r2_install(
    state: &Arc<R2ConnState>,
    ss: &SessTable,
    sess: u32,
    wire_id: u32,
    target: TargetAddr,
    resolved: Vec<SocketAddr>,
) -> Result<Arc<FlowBinding>, RegistryError> {
    // The "session still live" check and both table publications are one
    // critical section under the session's shard **read** lock. That is what
    // closes the residual install-vs-close race: `SESS_CLOSE` removes the entry
    // *and* purges its bindings under the same shard's write lock (see
    // `r2_close_session`) and the idle sweep does the same via
    // `sweep_all_with`, so a concurrent close either
    // - runs before this guard is acquired: the liveness check below sees no
    //   entry and the install aborts (nothing is forwarded into a dead
    //   session), or
    // - is serialized after this guard is dropped: its batched purge (or the
    //   removed entry's own reverse-table snapshot) removes exactly the binding
    //   published here, so no orphaned `Open` binding outlives the session.
    // Without the guard the check and the insert were two separate critical
    // sections; a close landing between them left an `Open` binding in the
    // registry whose session no longer existed (its steady frames later
    // re-created the session through the unguarded datagram path).
    let sh = ss.shard(sess);
    let guard = sh.read();
    let Some(entry) = guard.get(&sess).filter(|e| !e.reader.is_finished()) else {
        // The session vanished between the forward and the install; the payload
        // was delivered, but there is nothing left to bind.
        return Err(RegistryError::Full);
    };
    let flows = entry.r2_flows.clone();
    {
        let snap = flows.load();
        if snap.is_full() && snap.find_id(wire_id).is_none() {
            return Err(RegistryError::Full);
        }
    }
    let binding = FlowBinding::new_shared(wire_id, sess, target);
    if !resolved.is_empty() {
        binding.set_resolved(resolved);
    }
    // The server has installed the binding and is about to send FLOW_ACK.
    binding.mark_open();
    let inserted = state.registry.insert(binding)?;
    // `rcu` may retry its closure; the last attempt's verdict is what the
    // published snapshot reflects (a published attempt is never superseded by a
    // later failing one, because once `insert` returned true the id is present
    // forever after).
    let mut published = false;
    flows.rcu(|old| {
        let mut next = (**old).clone();
        published = next.insert(inserted.clone());
        Arc::new(next)
    });
    if !published {
        // The reverse table filled concurrently: undo the registry entry so the
        // two tables stay consistent, and report the same refusal a full
        // session table reports. `mark_closed` makes any Arc still held by an
        // in-flight reader snapshot fail the `Closed` check.
        if let Some(removed) = state.registry.remove(wire_id) {
            removed.mark_closed();
        }
        return Err(RegistryError::Full);
    }
    drop(guard);
    Ok(inserted)
}

/// Drop one binding from both tables (`FLOW_CLOSE`, or a peer-rejected
/// server-owned flow). Idempotent: an already-removed id is a no-op.
pub(crate) fn r2_remove_flow(
    ss: &SessTable,
    state: &R2ConnState,
    wire_id: u32,
) -> Option<Arc<FlowBinding>> {
    let binding = state.registry.remove(wire_id)?;
    binding.mark_closed();
    if let Some(flows) = session_r2_flows(ss, binding.session) {
        flows.rcu(|old| {
            let mut next = (**old).clone();
            let _ = next.remove(wire_id);
            Arc::new(next)
        });
    }
    Some(binding)
}

/// Mark every rev2 binding in a reaped entry's own reverse-table snapshot
/// `Closed` and empty the snapshot. **No registry access** (the registry purge
/// for the same entries is batched separately, under the session-shard write
/// lock that removed them — see [`ShardedSessTable::sweep_all_with`]).
///
/// Marking the snapshot is what stops a reply reader that is still draining
/// (it is aborted right after) from matching a torn-down binding. It is also
/// cheap: one `ArcSwap` load per entry and a relaxed store per binding, no
/// locks.
pub(crate) fn r2_mark_reaped_entry_closed(entry: &SessEntry) {
    let flows = entry.r2_flows.load();
    if flows.is_empty() {
        return;
    }
    for binding in flows.iter() {
        binding.mark_closed();
    }
    // Publish an empty reverse table too: a reply reader that still holds this
    // session's handle must not match a torn-down binding from its snapshot.
    entry.r2_flows.store(Arc::new(SessionFlows::new()));
}

/// Account + mark a batch of reaped sessions: adds `purged` bindings to the
/// `SESSION_END_BINDINGS` counter (already removed from the registry by the
/// caller's batched purge) and marks each entry's snapshot closed.
pub(crate) fn r2_finish_reaped_entries(entries: &[SessEntry], purged: usize) {
    if purged > 0 {
        r2_stats::SESSION_END_BINDINGS
            .fetch_add(purged as u64, std::sync::atomic::Ordering::Relaxed);
    }
    for entry in entries {
        r2_mark_reaped_entry_closed(entry);
    }
}

/// `CTL SESS_CLOSE`: reap the session (socket, reader task, permit) and every
/// binding it owns from the connection registry, immediately.
///
/// Cost is O(1) for an unknown session: [`FlowRegistry::remove_session`] looks
/// the id up in its per-session index (one hash probe) and touches nothing else
/// when the entry is absent, so the retransmission/forged-id storm the spec's
/// 3x `SESS_CLOSE` repeat produces cannot walk the 4096-entry forward table.
/// The by-id purge stays unconditional (even when the table held no entry)
/// because a reply reader that exited first may have left receive-only bindings
/// whose session is already gone from the table.
pub(crate) fn r2_close_session(ss: &SessTable, state: &R2ConnState, sess: u32) -> bool {
    // Remove the table entry and purge the registry bindings in **one** shard
    // write critical section: `get_or_create_sess` recreates a session id and
    // `r2_install` installs a binding both under this shard's write/read lock,
    // so a datagram for a *recreated* association can only make progress after
    // the guard drops — this close therefore cannot purge a recreated session's
    // fresh binding (the residual close-vs-install race). The purge stays
    // authoritative even when the table entry was already gone (a reply reader
    // that exited first, or a retransmitted close): a receive-only binding must
    // never outlive its association, and an unknown session costs one index
    // probe (the singular purge exits before taking the forward-table lock).
    let purged;
    let entry = {
        let sh = ss.shard(sess);
        let mut w = sh.write();
        let entry = w.remove(&sess);
        if entry.is_some() {
            ss.note_live_remove(1);
        }
        // The singular call is the cheap path for an unknown session: it
        // returns after one index probe without taking the forward table's
        // write lock (the batch variant always locks the map, which is the
        // right trade for a multi-session reap and the wrong one for a 7-byte
        // forged close).
        purged = state.registry.remove_session(sess);
        drop(w);
        entry
    };
    ss.note_empty_state();
    if purged > 0 {
        r2_stats::SESSION_END_BINDINGS
            .fetch_add(purged as u64, std::sync::atomic::Ordering::Relaxed);
    }
    let Some(entry) = entry else {
        return false;
    };
    // Mark the bindings in the session's reverse table closed before it is
    // dropped, so a reply reader still holding the snapshot cannot use them.
    let flows = entry.r2_flows.load();
    for binding in flows.iter() {
        binding.mark_closed();
    }
    if !flows.is_empty() {
        entry.r2_flows.store(Arc::new(SessionFlows::new()));
    }
    entry.reader.abort();
    true
}

/// Handle one rev2 `CTL` DATAGRAM.
///
/// `pub(crate)` so the unit tests can drive individual opcodes (notably
/// `FLOW_ACK`, whose only observable effect is the shared binding's
/// confirmation flag) against a fixture state instead of through a live QUIC
/// connection.
pub(crate) fn r2_handle_ctl(
    ss: &SessTable,
    cd: &quinn::Connection,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    d: &[u8],
) {
    let Ok(ctl) = r2::decode_ctl(d) else {
        r2_refuse(None);
        return;
    };
    // Spec §3.4 ("control frames have rate/total caps"): the three
    // idempotent-but-costly opcodes below all touch per-session shard/stager/
    // reassembler state. They are trivially cheap now (O(flows of the session),
    // or O(1) for an unknown id), but a peer can still drive them at line rate
    // — the cap bounds the per-connection CTL CPU share without ever touching
    // any legitimate control rate (it is far above one close per association
    // exit x3 plus one ACK per downlink rebind). Refused frames are dropped and
    // counted like any other refusal. `HELLO`/`FLOW_ACK` are one registry/shared
    // flag access and stay outside the budget (they are also the startup path).
    if matches!(
        ctl,
        Ctl::FlowReject { .. } | Ctl::FlowClose { .. } | Ctl::SessClose { .. }
    ) && !state.ctl.ctl_allowed(mono_millis())
    {
        r2_refuse(None);
        return;
    }
    match ctl {
        Ctl::Hello { wire_ver, .. } => {
            // HELLO is a capability announcement, never a gate: the data plane
            // runs whether or not it arrived. It is what makes the server
            // answer with CAPS (throttled) and what bumps the hello/caps
            // counters, so a lost HELLO now costs one control frame, not a
            // stalled or dropped data path.
            if wire_ver == r2::R2_WIRE_VER {
                state.ctl.mark_hello();
                r2_stats::bump(&r2_stats::HELLOS);
            } else {
                // Version mismatch: answer with our own version so the peer can
                // fail fast; the data plane is unaffected because a rev2 frame
                // is self-identifying and can only come from a rev2 peer.
                r2_stats::bump(&r2_stats::BAD_HELLO);
            }
            if state.caps_due(mono_millis()) {
                let caps = Caps::default();
                state.ctl.set_caps(caps);
                r2_stats::bump(&r2_stats::CAPS_SENT);
                r2_send_ctl(cd, &Ctl::Caps(caps));
            }
        }
        // The peer confirms an installed flow. Besides marking the binding
        // open (the Phase-1b server-owned case), this is what confirms a
        // learned downlink `reply_src`: the server sets the source when the
        // binding frame is only *queued* to quinn, so until the peer ACKs it
        // `SessionFlows::match_source` keeps returning `Rebind` and re-sends
        // the idempotent `OPEN|SRC` every time (a lost DATAGRAM cannot leave
        // the flow permanently unaddressable). The client ACKs every
        // `OPEN|SRC` it decodes, so one ACK makes the source steady.
        Ctl::FlowAck { id, .. } => {
            if let Some(binding) = state.registry.get(id) {
                binding.mark_open();
                binding.mark_reply_src_acked();
                r2_stats::bump(&r2_stats::FLOW_ACKS_RECV);
            }
        }
        Ctl::FlowReject { id, .. } => {
            // The peer refused a server-opened flow (Phase 1b). Client-owned ids
            // are not the peer's to reject.
            if r2::wire_id_server_owned(id) {
                let _ = r2_remove_flow(ss, state, id);
            } else {
                r2_refuse(None);
            }
        }
        Ctl::FlowClose { id } => {
            // Remove the binding first: a close for an id this side never
            // installed (or already reaped with its session) is the common
            // retransmission case and must cost one registry lookup, not a
            // whole-stager scan. Only a binding that actually existed can own
            // queued downstream payloads or in-flight fragments, and its
            // session scopes the stager purge to that association's queue.
            match r2_remove_flow(ss, state, id) {
                Some(binding) => {
                    let dropped = r2_reasm.drop_flow(id);
                    let _ = state.stage.lock().drop_flow_scoped(binding.session, id);
                    if dropped > 0 {
                        r2_stats::SESSION_END_BINDINGS
                            .fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    r2_stats::bump(&r2_stats::FLOW_CLOSES);
                }
                // Idempotent: an already-reaped id is a counted no-op, never a
                // policy refusal, and it never pays the queue scans above.
                None => r2_stats::bump(&r2_stats::STALE_CLOSES),
            }
        }
        Ctl::SessClose { sess, .. } => {
            // Cancel in-flight domain lookups for this session *before* the
            // session is removed: the flags must be visible to the lookup
            // tasks' guarded inserts, or a late DNS answer would recreate the
            // session (and a wire binding) the close is about to reap. Two
            // registries: the rev2 `DATA OPEN` coalescer (`pending_dns_opens`)
            // and the generic datagram slow path (`dns_waiters`, which has no
            // per-flow key and would otherwise resurrect the session after its
            // DNS await). See the ordering proofs on both cancel methods.
            state.cancel_pending_opens_for_session(sess);
            state.cancel_dns_waiters_for_session(sess);
            let dropped = r2_reasm.drop_session(sess);
            let _ = state.stage.lock().drop_session(sess);
            if dropped > 0 {
                r2_stats::SESSION_END_BINDINGS
                    .fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
            }
            if r2_close_session(ss, state, sess) {
                r2_stats::bump(&r2_stats::SESS_CLOSES);
            } else {
                r2_stats::bump(&r2_stats::STALE_CLOSES);
            }
        }
        // A server never receives CAPS from a client.
        Ctl::Caps(_) => r2_refuse(None),
    }
}

/// Handle one rev3 control-stream message on the connection's datagram-reader
/// task (which owns the reassembler and the session table the message acts on).
///
/// The message classes mirror the rev2 `CTL` opcodes, minus the ACK/HELLO
/// machinery rev3 deletes:
/// - `ASSOC_CLOSE`: the reliable replacement for `SESS_CLOSE` ×3. Cancels the
///   in-flight DNS paths *before* removing the session (same ordering proof as
///   the rev2 arm: the lookup tasks' guarded creation re-reads the flag inside
///   the shard write lock), drops this connection's reassembly/stager state for
///   the association, then reaps it.
/// - `FLOW_CLOSE`: removes one binding from both tables and drops its queued
///   downlink payloads / in-flight fragments.
/// - `NEED_CONTEXT`: the peer missed the downlink binding context of a flow it
///   still has on the wire — record a bounded repair hint that every reply
///   reader of the connection re-reads before its next reply (see
///   [`R2ConnState::take_need_context`]). Never allocates flow state.
/// - `REJECT`/`SESS_CLOSE`/`GOAWAY` are server→client messages; a client
///   sending them is a protocol violation and is counted, never acted on.
pub(crate) fn handle_control_message(
    ss: &SessTable,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    msg: CtlMessage,
) {
    match msg {
        CtlMessage::AssocClose { sess, .. } => {
            state.cancel_pending_opens_for_session(sess);
            state.cancel_dns_waiters_for_session(sess);
            let dropped = r2_reasm.drop_session(sess);
            let _ = state.stage.lock().drop_session(sess);
            if dropped > 0 {
                r2_stats::SESSION_END_BINDINGS
                    .fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
            }
            // Same accounting as the rev2 `CTL SESS_CLOSE` arm: a closed
            // session and a repeated close are different classes.
            if r2_close_session(ss, state, sess) {
                r2_stats::bump(&r2_stats::SESS_CLOSES);
            } else {
                r2_stats::bump(&r2_stats::STALE_CLOSES);
            }
        }
        CtlMessage::FlowClose { fid, .. } => {
            let Some(wire_id) = wire::wire_id_for_fid(fid) else {
                r2_refuse(None);
                return;
            };
            match r2_remove_flow(ss, state, wire_id) {
                Some(binding) => {
                    let dropped = r2_reasm.drop_flow(wire_id);
                    let _ = state
                        .stage
                        .lock()
                        .drop_flow_scoped(binding.session, wire_id);
                    if dropped > 0 {
                        r2_stats::SESSION_END_BINDINGS
                            .fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    r2_stats::bump(&r2_stats::FLOW_CLOSES);
                }
                None => r2_stats::bump(&r2_stats::STALE_CLOSES),
            }
        }
        CtlMessage::NeedContext { fid } => {
            let Some(wire_id) = wire::wire_id_for_fid(fid) else {
                r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
                return;
            };
            // A repair hint is only meaningful for a flow this side actually
            // has; an unknown id stays a counted no-op (never allocate state).
            if state.registry.get(wire_id).is_none() {
                r2_stats::bump(&r2_stats::NEED_CONTEXT_DROPPED);
                return;
            }
            r2_stats::bump(&r2_stats::NEED_CONTEXT_RECV);
            state.note_need_context(wire_id);
        }
        // Server→client message classes: never valid from a client.
        CtlMessage::Reject { .. } | CtlMessage::SessClose { .. } => r2_refuse(None),
        // The peer announces it will stop using the connection. There is
        // nothing the server must repair (the datagram plane is loss-tolerant by
        // contract and the peer closes the QUIC connection itself); the message
        // is already counted by the control-stream task.
        CtlMessage::Goaway => {}
    }
}

/// Forward one payload for an already-installed rev2 flow.
///
/// The target is the binding's IP address, or (domain flow) the first address
/// the install validated — a steady compressed frame never resolves DNS again
/// and never reaches an address the install did not authorize. Payload delivery
/// goes through the same fast/slow machinery as every other ingress frame.
///
/// This is the per-frame entry point (single `DATA` frames and FRAG
/// completions): it resolves the id itself. The TRAIN ingress uses
/// [`r2_forward_flow_resolved`] directly with bindings obtained under one
/// registry lock for the whole frame.
#[allow(clippy::too_many_arguments)]
async fn r2_forward_flow_item(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    wire_id: u32,
    payload: Bytes,
) -> bool {
    let binding = state.registry.get(wire_id);
    r2_forward_flow_resolved(
        fast,
        ss,
        cd,
        conn_id,
        allow_private,
        staged,
        state,
        wire_id,
        binding.as_ref(),
        payload,
    )
    .await
}

/// Forward one payload whose binding is already resolved.
///
/// A server-owned id names a *downlink-created* flow (full-cone / unsolicited
/// source). A steady/TRAIN item on it is the client app's reply to that source,
/// and is legitimate exactly when this connection has a live binding for the
/// id: the binding carries the session and the remote source
/// (`target = Ip(src)`), so it is forwarded like any other flow item. Unknown
/// and closed ids still fail lookup (drop + count, never guess), and a client
/// `DATA OPEN` on a server-owned id is still rejected by the owner-half rule.
/// `binding` is `None` for an id with no live registry entry (or a resolved
/// binding that was already `Closed`).
#[allow(clippy::too_many_arguments)]
async fn r2_forward_flow_resolved(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    wire_id: u32,
    binding: Option<&Arc<FlowBinding>>,
    payload: Bytes,
) -> bool {
    // rev3 no-ACK repair is only useful for an id this endpoint **never**
    // installed: the peer missed the binding context (its steady output is the
    // symptom). A closed id is never reused (so a repair could not help a late
    // frame) and is the normal post-close retransmission shape. Ask for
    // `NEED_CONTEXT{fid}` on the reliable control stream instead of only
    // counting — rate-limited and never allocating state (a hint, not a binding).
    let repair_unknown = state.wire() == Wire::Rev3 && binding.is_none();
    let Some(binding) = binding.filter(|b| b.state() != FlowState::Closed) else {
        // The id was closed (FLOW_CLOSE / session teardown) or never lived: a
        // late frame must fail lookup, never be re-routed.
        r2_refuse(Some(&r2_stats::UNKNOWN_ID));
        if repair_unknown {
            let _ = state.send_need_context(wire_id);
        }
        return false;
    };
    let Some(dst) = binding.target_ip().or_else(|| binding.resolved_first()) else {
        r2_refuse(None);
        return false;
    };
    let sess = binding.session;
    let aref = r2::ip_ref(dst);
    match try_stage(fast, ss, conn_id, sess, dst, payload, allow_private, staged) {
        Ok(()) => true,
        Err(payload) => {
            flush_staged_sends(staged);
            let used = forward_server_dgram(
                ss,
                cd,
                conn_id,
                sess,
                aref,
                payload,
                allow_private,
                Some(state),
            )
            .await;
            if let Some((used_dst, life)) = used {
                arm_fast(fast, conn_id, sess, aref, used_dst, life);
            }
            used.is_some()
        }
    }
}

/// Filter a resolved address list through the SSRF policy and bound it to
/// [`R2_MAX_RESOLVED_ADDRS`].
///
/// The cap is what keeps the per-flow admission charge real: 4096 domain flows
/// cannot each retain a DNS response's full record set, and `match_source`
/// scans each retained address on the reply path. The first accepted address
/// is the one the OPEN is forwarded to; later ones only authorize compressed
/// replies.
pub(crate) fn policy_resolved(addrs: &[SocketAddr], allow_private: bool) -> Vec<SocketAddr> {
    let mut usable = Vec::with_capacity(addrs.len().min(R2_MAX_RESOLVED_ADDRS));
    for a in addrs.iter().copied() {
        if !(allow_private || is_global_ip(a.ip())) {
            continue;
        }
        usable.push(a);
        if usable.len() == R2_MAX_RESOLVED_ADDRS {
            break;
        }
    }
    usable
}

/// Resolve and forward a domain-target `DATA OPEN` **off the datagram loop**.
///
/// This is the **cold-cache slow path**: the caller already consulted the
/// synchronous thread memo / session destination memo (W5) and fell through
/// because the name is not cached on this thread. DNS is the only potentially
/// seconds-long await on the ingress path (up to `DNS_LOOKUP_TIMEOUT`), so the
/// reader spawns this task with owned data and keeps routing other datagrams.
/// The task owns everything it touches: resolution + SSRF filtering, session
/// creation (which may await a session permit), the target send, and the
/// idempotent install + `FLOW_ACK`.
///
/// `pending` removes the `(session, id)` coalescing entry on every exit path
/// and carries the session's cancellation flag: if a `CTL SESS_CLOSE` for
/// `sess` lands while the lookup is in flight, that flag is set *before* the
/// session is removed, and the guarded creation below refuses to publish a
/// session for a closed association. Without it, a DNS answer slower than the
/// close resurrected the session (socket, global permit and wire binding) after
/// `SESS_CLOSE` had already reaped it.
///
/// Repeated OPENs for the same id while this task is in flight coalesce onto it
/// ([`R2ConnState::begin_pending_open`]); their payloads are queued (bounded and
/// target-checked) and forwarded here after the lookup resolves, so a client
/// that opens a flow per payload does not lose the DNS window's datagrams.
#[allow(clippy::too_many_arguments)]
async fn r2_forward_domain_open_bg(
    ss: SessTable,
    cd: quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    state: Arc<R2ConnState>,
    id: u32,
    sess: u32,
    host: String,
    port: u16,
    payload: Bytes,
    pending: PendingDnsOpen,
) {
    if cd.close_reason().is_some() {
        return;
    }
    let _dns_permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Process-wide resolver budget refused: counted by the shared
            // `DNS_BUDGET` class (the 60 s report's DNS line), not as a name
            // failure — the name was never looked up.
            dgram_drops::bump(&dgram_drops::DNS_BUDGET);
            r2_reject(&state, &cd, id, r2::R2_REJECT_DNS);
            return;
        }
    };
    let addrs = match resolve_all_cached(&host, port).await {
        Ok(v) => v,
        Err(_) => {
            // W4: a resolver error/timeout is **inherently undeliverable** —
            // there is no address to send this payload to, and inventing one
            // would be exactly the SSRF hole the policy exists to close.
            //
            // No in-budget retry is possible: `resolve_all_cached` records the
            // failure as a host-keyed negative cache entry (`DNS_NEG_TTL`,
            // 10 s) *before* returning it, so a retry inside this 5 s budget can
            // only re-read that verdict. It would add an await and a second
            // wakeup on the ingress path and never succeed; the payload stays an
            // ordinary UDP drop (the client's own retransmission is the retry).
            // The distinct counter is what makes the loss observable instead of
            // folded into the shared `REFUSED`.
            r2_stats::bump(&r2_stats::DNS_OPEN_DNS_FAIL);
            r2_refuse(None);
            r2_reject(&state, &cd, id, r2::R2_REJECT_DNS);
            return;
        }
    };
    let usable = policy_resolved(&addrs, allow_private);
    if usable.is_empty() {
        // Every record was rejected by the SSRF policy: undeliverable by
        // policy, never re-routed around the filter (`DNS_OPEN_POLICY_DROP`).
        r2_stats::bump(&r2_stats::DNS_OPEN_POLICY_DROP);
        r2_refuse(None);
        r2_reject(&state, &cd, id, r2::R2_REJECT_POLICY);
        return;
    }
    if cd.close_reason().is_some() {
        return;
    }
    // Cheap post-DNS check: the client may have closed the association while
    // the lookup was in flight. The guarded creation below closes the remaining
    // window; this exit just avoids creating a socket that would be thrown away.
    if pending.is_cancelled() {
        return;
    }
    let dst = usable[0];
    // Pass the DNS entry's *remaining* life, not the fresh-resolution constant:
    // `resolve_all_cached` may have served a host-keyed cache hit (other ports
    // share the entry) that is already close to expiry, and the session
    // destination memo must not outlive the resolution behind it
    // (`pin_life_ms` clamping). A miss — the memo being overwritten by another
    // worker — falls back to the fresh bound.
    let remaining_ms = {
        let (_, life) = lookup_cached_fast_with_ttl(&host, port);
        if life == 0 { DNS_CACHE_TTL_MS } else { life }
    };
    let sock = match get_or_create_sess_guarded(
        &ss,
        &cd,
        conn_id,
        sess,
        Some((host.as_str(), port, dst, remaining_ms)),
        Some(&state),
        Some(pending.cancelled_flag()),
    )
    .await
    {
        Some(s) => s,
        None => {
            // Session/share/permit refusal (or the cancelled-creation rollback):
            // no flow can be installed around it. A cancelled OPEN must not ACK
            // or bind a closed session either — the client already dropped the
            // association. W4: the destination is valid but there is no live
            // per-association delivery path, and *deliberately* no alternative
            // one is invented — a session owns its socket, its reader task and
            // its SSRF authorization, so routing around a refusal would bypass
            // the admission policy. `DNS_OPEN_SESS_REFUSED` makes that distinct
            // from a name failure (`DNS_OPEN_DNS_FAIL`) and a policy drop
            // (`DNS_OPEN_POLICY_DROP`). The specific resource class
            // (`FAIR_SHARE`/`SESSION_FULL`/`SESS_CREATE_FAILED`) is already
            // counted by `get_or_create_sess_guarded`.
            r2_stats::bump(&r2_stats::DNS_OPEN_SESS_REFUSED);
            r2_reject(&state, &cd, id, r2::R2_REJECT_TABLE_FULL);
            return;
        }
    };
    // A cancel that raced the guarded insert's check has already had the session
    // removed by the close's `take_session` (same shard write lock): do not send
    // or install around a session that no longer exists. `r2_install` also
    // re-checks `session_r2_flows`, so this is the cheap half of the same
    // guard.
    if pending.is_cancelled() {
        return;
    }
    remember_dst(&ss, sess, dst);
    // No `arm_fast` here: the fast table is owned by the datagram loop. The
    // next datagram for this session takes the slow path once, finds the dest
    // memo written above, and arms it there — one slow-path hit, never a
    // reason to keep the DNS wait on the reader.
    udp_try_send(&sock, map_for_dual(dst), payload);
    // Duplicate OPENs that arrived while the lookup was in flight carried new
    // payloads (the client repeats OPEN per payload, it does not retransmit the
    // same one). Forward them now, in arrival order, before the install/ACK.
    for queued in pending.take_queued() {
        if pending.is_cancelled() {
            r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
            continue;
        }
        udp_try_send(&sock, map_for_dual(dst), queued);
    }
    match r2_install(
        &state,
        &ss,
        sess,
        id,
        TargetAddr::Domain(host, port),
        usable,
    ) {
        Ok(_) => {
            r2_stats::bump(&r2_stats::OPENS);
            r2_ack_open(&state, &cd, id);
        }
        Err(RegistryError::Full) => r2_reject(&state, &cd, id, r2::R2_REJECT_TABLE_FULL),
        Err(RegistryError::Conflict) => {
            r2_refuse(None);
            r2_reject(&state, &cd, id, r2::R2_REJECT_POLICY);
        }
    }
}

/// Handle one `DATA OPEN` (client-initiated flow: the address is the target).
///
/// Order is invariant: the target send happens **before** the install, so an
/// install/table refusal can only mean "no compression", never "payload lost"
/// (P2-7). IP targets forward inline through `forward_server_dgram`; domain
/// targets first take the synchronous warm-cache fast path (W5), and only a
/// name that is not cached on this thread is handed to the spawned resolver
/// task.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn r2_ingress_open(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    id: u32,
    sess: u32,
    target: TargetAddr,
    payload: Bytes,
) {
    // Half-owner rule (spec §2.1): the low bit names which endpoint allocated
    // the id. A client may only open ids from its own half; a server-owned id
    // arrives in Phase 1b as the *server's* OPEN|SRC, never as a client OPEN.
    if sess == 0 || r2::wire_id_server_owned(id) {
        r2_refuse(None);
        r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
        return;
    }
    // An id is bound to one `(session, target)` for the connection's life: a
    // reopen with a different target is a protocol violation, never a reroute.
    //
    // A *full* registry is deliberately not checked here: the payload still has
    // to be delivered before the install is refused (P2-7). `r2_install` runs
    // after the forward and reports `TABLE_FULL`, which sends the reject then.
    // Rejecting before the forward silently dropped the triggering datagram
    // even though `INLINE` would have carried it.
    if let Some(existing) = state.registry.get(id)
        && (existing.session != sess || existing.target != target)
    {
        r2_refuse(None);
        r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
        return;
    }
    // Deliver first (or resolve+deliver): a flow is installed only after the
    // target actually accepted a payload. A duplicate OPEN still forwards this
    // frame's distinct payload, then re-installs idempotently and re-ACKs.
    let resolved: Option<Vec<SocketAddr>> = match target.as_ref() {
        TargetAddrRef::Ip(dst) => {
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                r2_refuse(None);
                r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
                return;
            }
            flush_staged_sends(staged);
            let used = forward_server_dgram(
                ss,
                cd,
                conn_id,
                sess,
                r2::ip_ref(dst),
                payload,
                allow_private,
                Some(state),
            )
            .await;
            match used {
                Some((used_dst, life)) => {
                    arm_fast(fast, conn_id, sess, r2::ip_ref(dst), used_dst, life);
                    Some(Vec::new())
                }
                None => {
                    r2_reject(state, cd, id, r2::R2_REJECT_TABLE_FULL);
                    return;
                }
            }
        }
        TargetAddrRef::Domain(host, port) => {
            let host = host.to_owned();
            // Duplicate-OPEN pre-check (W5): if a lookup for this `(session,
            // id)` is already in flight, this frame is the client's normal "no
            // ACK yet" duplicate. Queue its payload behind that lookup — never
            // forward it early, because the in-flight target is the authority
            // for where it may go, and a duplicate naming a different target
            // must still be refused as the protocol violation it is.
            // `NotPending` means there is no in-flight lookup, so this OPEN can
            // take the synchronous warm-cache path below.
            match state.queue_pending_open_payload(sess, id, &target.as_ref(), &payload) {
                PendingPayload::Queued => return,
                PendingPayload::Full | PendingPayload::Cancelled => {
                    r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
                    return;
                }
                PendingPayload::Conflict => {
                    r2_refuse(None);
                    r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
                    return;
                }
                PendingPayload::NotPending => {}
            }
            // W5 — synchronous warm-cache fast path. Mirror
            // `forward_server_dgram`'s resolution order (this thread's DNS memo,
            // then the session's destination memo) *before* paying a task spawn:
            // on a hit the payload is forwarded, the binding installed and
            // `FLOW_ACK` sent inline in the datagram loop, so a warm domain flow
            // starts compressing one task round trip earlier and never leaves
            // the reader. The resolution runs exactly once per frame: its answer
            // is reused for the forward and the install instead of resolving a
            // second time inside `forward_server_dgram` (W8b: one resolution and
            // one coarse clock sample per frame).
            //
            // The SSRF/`allow_private` decision is the *same* one the slow path
            // makes: `resolve_forward_target` only returns `Addr` for an address
            // that passes the policy, so a warm name that resolves to a filtered
            // address stays on the cold path (which scans the whole record set
            // for a usable one) and never skips the check.
            if let ForwardResolution::Addr(dst, life) =
                resolve_forward_target(ss, sess, &host, port, allow_private)
            {
                flush_staged_sends(staged);
                let sock = match get_or_create_sess(
                    ss,
                    cd,
                    conn_id,
                    sess,
                    Some((host.as_str(), port, dst, life)),
                    Some(state),
                )
                .await
                {
                    Some(s) => s,
                    None => {
                        // Same class as the slow path's refusal: the destination
                        // is valid but no per-association delivery path exists
                        // (and none is invented — see `DNS_OPEN_SESS_REFUSED`).
                        r2_stats::bump(&r2_stats::DNS_OPEN_SESS_REFUSED);
                        r2_reject(state, cd, id, r2::R2_REJECT_TABLE_FULL);
                        return;
                    }
                };
                remember_dst(ss, sess, dst);
                udp_try_send(&sock, map_for_dual(dst), payload);
                // Arm the connection fast table from the answer just used, so
                // this session's later steady frames hit the fast path. (The
                // spawned slow path deliberately leaves arming to the datagram
                // loop; here we *are* the datagram loop.)
                arm_fast(fast, conn_id, sess, target.as_ref(), dst, life);
                r2_stats::bump(&r2_stats::DNS_SYNC_OPENS);
                // The one address the synchronous probe knows (the memo's first
                // record) is the flow's validated reply-source set here: it is
                // the address this payload was sent to, so its replies are
                // authorized without a second lookup. A reply from a *different*
                // record of the same name is the cold path's case (its full
                // resolved set is installed there).
                Some(vec![dst])
            } else {
                match state.begin_pending_open(sess, id, &target) {
                    PendingOpen::Duplicate => {
                        // The first OPEN for this id is already resolving. This
                        // frame's payload is distinct application data, so buffer
                        // it behind the lookup (bounded) instead of losing it;
                        // the task forwards the queued payloads in order after
                        // the resolution. A full/closed queue drops it as the
                        // old path always did, and `NotPending` means the lookup
                        // just finished: forward on the ordinary path. A
                        // duplicate that names a different target is the
                        // registry's conflict case moved into the DNS window:
                        // refuse it, never queue it for the in-flight target's
                        // destination.
                        match state.queue_pending_open_payload(sess, id, &target.as_ref(), &payload)
                        {
                            PendingPayload::Queued => {}
                            PendingPayload::Full | PendingPayload::Cancelled => {
                                r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
                            }
                            PendingPayload::Conflict => {
                                r2_refuse(None);
                                r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
                            }
                            PendingPayload::NotPending => {
                                let accepted = forward_v3_item(
                                    fast,
                                    ss,
                                    cd,
                                    conn_id,
                                    sess,
                                    target.as_ref(),
                                    payload,
                                    allow_private,
                                    staged,
                                    Some(state),
                                )
                                .await;
                                if !accepted {
                                    r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
                                }
                            }
                        }
                        return;
                    }
                    PendingOpen::Full => {
                        // This is a *per-connection* resource refusal (16
                        // in-flight OPENs), never DNS-budget exhaustion: charging
                        // it to `DNS_BUDGET` made the 60 s report claim the
                        // process-wide resolver budget was drained while the
                        // share cap was the actual gate. REFUSED is the correct
                        // policy-drop class, plus the per-connection
                        // pending-open counter.
                        r2_refuse(Some(&r2_stats::DNS_OPEN_DROPS));
                        r2_reject(state, cd, id, r2::R2_REJECT_DNS);
                        return;
                    }
                    PendingOpen::Started(pending) => {
                        // Owned task: the datagram loop must not await DNS. The
                        // task performs the same forward-then-install sequence
                        // and sends its own ACK/reject.
                        tokio::spawn(r2_forward_domain_open_bg(
                            ss.clone(),
                            cd.clone(),
                            conn_id,
                            allow_private,
                            Arc::clone(state),
                            id,
                            sess,
                            host,
                            port,
                            payload,
                            pending,
                        ));
                        return;
                    }
                }
            }
        }
    };
    let Some(resolved) = resolved else {
        return;
    };
    match r2_install(state, ss, sess, id, target, resolved) {
        Ok(_) => {
            r2_stats::bump(&r2_stats::OPENS);
            r2_ack_open(state, cd, id);
        }
        Err(RegistryError::Full) => r2_reject(state, cd, id, r2::R2_REJECT_TABLE_FULL),
        Err(RegistryError::Conflict) => {
            r2_refuse(None);
            r2_reject(state, cd, id, r2::R2_REJECT_POLICY);
        }
    }
}

/// Route one decoded `DATA` frame (steady / open / inline) for `wire`.
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_data(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    wire: Wire,
    d: Bytes,
) {
    // The adapter maps rev3 `fid`s back to the internal `wire_id` the whole
    // state model uses, so everything below is revision-agnostic.
    let Ok(data) = wire::decode_data(wire, &d) else {
        r2_refuse(None);
        return;
    };
    // Uplink frames never carry the `SRC` flag: a client-initiated OPEN names
    // its destination, a steady frame names nothing, and INLINE is a one-shot
    // destination. `OPEN|SRC` is the downlink rebind form.
    if data.src {
        r2_refuse(None);
        return;
    }
    let target = data.addr.map(TargetAddrRef::into_owned);
    let payload = d.slice_ref(data.payload);
    udp_stats::payload(data.payload.len());
    match (data.wire_id, data.sess, target) {
        (Some(id), Some(sess), Some(target)) => {
            r2_ingress_open(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                id,
                sess,
                target,
                payload,
            )
            .await;
        }
        (None, Some(sess), Some(target)) => {
            // INLINE: one-shot forwarding, never installed (the fail-safe for a
            // full table / a target the client does not want to bind).
            let accepted = forward_v3_item(
                fast,
                ss,
                cd,
                conn_id,
                sess,
                target.as_ref(),
                payload,
                allow_private,
                staged,
                Some(state),
            )
            .await;
            if accepted {
                r2_stats::bump(&r2_stats::INLINE);
            }
        }
        (Some(id), None, None) => {
            let _ = r2_forward_flow_item(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                id,
                payload,
            )
            .await;
        }
        // OPEN/INLINE forms that also carry an id (or none) are contradictory;
        // a truncated header was already rejected by the decoder.
        _ => r2_refuse(None),
    }
}

/// Route one `TRAIN`: every item resolves through the connection registry and
/// is forwarded on its own; an item naming an unknown id is dropped/counted
/// (and, on rev3, repaired with `NEED_CONTEXT`), never guessed, and the rest of
/// the frame continues.
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_train(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    wire: Wire,
    d: Bytes,
) {
    // The adapter's iterator yields `(internal wire_id, payload)` in wire order
    // for both revisions (rev2 same/dict; rev3 same/same-equal/dict).
    let Ok(train) = wire::decode_train(wire, &d) else {
        r2_refuse(None);
        return;
    };
    // Frame-batched id resolution. One TRAIN can carry up to 64 items; the
    // per-item `registry.get` paid one RwLock acquire/release per item (and a
    // fresh `Arc` clone for every hit) *inside the datagram loop*. Instead the
    // frame does two bounded passes:
    //
    //   pass 1 — collect each item's id, deduplicating into at most one slot per
    //            distinct id (repeated item indices are legal in the dict form
    //            and name the same flow; every item then sees the binding the
    //            map holds when the frame started);
    //   batch  — one `get_batch` under a single read-lock hold fills every slot;
    //   pass 2 — dispatch per item against its slot's binding.
    //
    // Both lists are fixed-size stack arrays (the codec bounds the count at
    // 64), and the dedupe is a tiny open-addressing table instead of a
    // quadratic scan: no allocation, and one probe per item in the common
    // all-distinct case.
    const TRAIN_MAX: usize = r2::R2_MAX_TRAIN_ITEMS;
    const TRAIN_HASH_CAP: usize = 128; // power of two, >= 2 * TRAIN_MAX
    let mut slots: [(u32, Option<Arc<FlowBinding>>); TRAIN_MAX] =
        std::array::from_fn(|_| (0, None));
    let mut slot_of: [u16; TRAIN_HASH_CAP] = [u16::MAX; TRAIN_HASH_CAP];
    let mut item_slot: [u16; TRAIN_MAX] = [0; TRAIN_MAX];
    let mut n_slots = 0usize;
    for (i, (wire_id, _)) in train.items().enumerate() {
        debug_assert!(i < TRAIN_MAX, "the codec bounds the train item count");
        let mut h = (wire_id.wrapping_mul(0x9E37_79B1) as usize) & (TRAIN_HASH_CAP - 1);
        let slot = loop {
            let s = slot_of[h];
            if s == u16::MAX {
                let s = n_slots as u16;
                n_slots += 1;
                slot_of[h] = s;
                slots[usize::from(s)] = (wire_id, None);
                break s;
            }
            if slots[usize::from(s)].0 == wire_id {
                break s;
            }
            h = (h + 1) & (TRAIN_HASH_CAP - 1);
        };
        item_slot[i] = slot;
    }
    state.registry.get_batch(&mut slots[..n_slots]);
    for (slot_index, (wire_id, item)) in train.items().enumerate() {
        r2_stats::bump_train_item();
        udp_stats::payload(item.len());
        let payload = d.slice_ref(item);
        let binding = slots[usize::from(item_slot[slot_index])].1.as_ref();
        let _ = r2_forward_flow_resolved(
            fast,
            ss,
            cd,
            conn_id,
            allow_private,
            staged,
            state,
            wire_id,
            binding,
            payload,
        )
        .await;
    }
}

/// Route one rev2 `FRAG` frame through the connection's rev2 reassembler.
///
/// Completion is routed exactly like the equivalent single-frame payload:
/// - an `OPEN` context (`wire_id + sess + addr`) takes the same policy/install/
///   `FLOW_ACK` path as a single `DATA OPEN`;
/// - an `INLINE` context (no id) takes the one-shot forward path and is never
///   installed;
/// - a steady context (id only) resolves the connection registry *at completion*
///   (never caches a session in the partial) and forwards the whole payload.
///
/// Partials are bounded by the shared module (8 KiB, 2 s, 256 partials,
/// 256 KiB/connection); a refused/expired fragment is a drop, never a
/// connection fault and never a guess.
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_frag(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    wire: Wire,
    d: Bytes,
) {
    // Decode through the wire adapter; the decoded view carries the internal
    // `wire_id` for both revisions, and the reassembler keeps the same keys,
    // bounds and expiry.
    let Ok(frag) = wire::decode_frag(wire, &d) else {
        r2_stats::bump(&r2_stats::FRAGS);
        r2_refuse(None);
        return;
    };
    r2_stats::bump(&r2_stats::FRAG_FRAMES);
    let Some(done) = r2_reasm.push_view(&d, &frag, coarse_millis()) else {
        // Partial, duplicate, expired or refused fragment: the module already
        // bounds and validates everything; UDP semantics say drop.
        return;
    };
    // One payload for the 60 s report, exactly like the single-frame paths count
    // a delivered datagram's payload (booked once per reassembled payload, not
    // per fragment).
    udp_stats::payload(done.payload.len());
    // Uplink frames never carry `SRC`: an `OPEN`/`INLINE` fragment names its
    // destination; a steady fragment set names nothing.
    if done.src {
        r2_stats::bump(&r2_stats::FRAGS);
        r2_refuse(None);
        return;
    }
    match (done.wire_id, done.sess, done.addr) {
        (Some(id), Some(sess), Some(target)) => {
            // Fragmented OPEN: the whole payload is the flow's first data, so it
            // takes the same session/policy/install/ACK path as a single-frame
            // OPEN (including duplicate-OPEN and conflict handling).
            r2_ingress_open(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                id,
                sess,
                target,
                done.payload,
            )
            .await;
            r2_stats::bump(&r2_stats::FRAG_COMPLETE);
        }
        (None, Some(sess), Some(target)) => {
            // Fragmented INLINE: one-shot forwarding, never installed.
            let accepted = forward_v3_item(
                fast,
                ss,
                cd,
                conn_id,
                sess,
                target.as_ref(),
                done.payload,
                allow_private,
                staged,
                Some(state),
            )
            .await;
            if accepted {
                r2_stats::bump(&r2_stats::INLINE);
                r2_stats::bump(&r2_stats::FRAG_COMPLETE);
            }
        }
        (Some(id), None, None) => {
            // Steady fragments: the registry is consulted here, at completion;
            // the partial never cached a session.
            if r2_forward_flow_item(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                id,
                done.payload,
            )
            .await
            {
                r2_stats::bump(&r2_stats::FRAG_COMPLETE);
            }
        }
        // Contradictory/malformed completion (e.g. `sess` without `addr`): the
        // decoder plus the reassembler make this unreachable for a conforming
        // peer, but a hostile one must only cost this payload.
        _ => {
            r2_stats::bump(&r2_stats::FRAGS);
            r2_refuse(None);
        }
    }
}

/// Dispatch one MQP-3 DATAGRAM body for the connection's `wire` revision.
///
/// Optimistic-first-packet contract: the client does not wait for `CAPS` before
/// sending its first UDP payload, and (on rev2) the server does not wait for
/// `HELLO` before dispatching data. The caller classified `kind` from the first
/// byte through [`wire::kind`] — the only revision-specific dispatch decision —
/// so this function only has to route by frame family and hand the decoder the
/// same `wire`.
///
/// rev2: `CTL` frames are the lossy datagram control plane (HELLO/CAPS/ACK/
/// REJECT/CLOSE) and are handled here; the data classes keep the shipped bytes
/// and behaviour.
/// rev3: there is no control DATAGRAM class at all (`wire::kind(Rev3, ..)`
/// never returns [`FrameKind::Ctl`]); the reliable control stream is handled by
/// the stream accept path.
#[allow(clippy::too_many_arguments)]
async fn handle_ingress_frame(
    fast: &mut FastTable,
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    wire: Wire,
    kind: FrameKind,
    d: Bytes,
) {
    match kind {
        FrameKind::Data => {
            r2_ingress_data(fast, ss, cd, conn_id, allow_private, staged, state, wire, d).await;
        }
        FrameKind::Train => {
            r2_ingress_train(fast, ss, cd, conn_id, allow_private, staged, state, wire, d).await;
        }
        FrameKind::Frag => {
            r2_ingress_frag(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                r2_reasm,
                wire,
                d,
            )
            .await;
        }
        FrameKind::Ctl => {
            // Only rev2 can produce this family; rev3's control plane is the
            // reliable stream (see the control-stream accept path).
            debug_assert_eq!(wire, Wire::Rev2);
            r2_handle_ctl(ss, cd, state, r2_reasm, &d);
        }
    }
}

/// Capacity of the control-stream → datagram-loop handoff queue
/// ([`r3_control_stream_task`]). Same order as the server→client writer queue
/// in [`R2ConnState::queue_ctl`]: the datagram loop drains this between packets,
/// so a full queue means the peer outpaced its own receive path, not that
/// messages are being lost.
const CTL_IN_QUEUE: usize = 64;

/// The connection's rev3 control-stream task: one reliable, ordered bidi stream
/// carries every rare control message in both directions (see
/// `mqp::ctl_stream`). It owns the stream halves and bridges them to the rest of
/// the server:
/// - inbound messages are rate-limited here and forwarded to the datagram-reader
///   task ([`handle_control_message`]), which owns the reassembler/session table
///   they act on;
/// - outbound messages are written straight from the bounded queue in
///   [`R2ConnState::queue_ctl`] (REJECT / SESS_CLOSE / NEED_CONTEXT).
///
/// The inbound handoff is **bounded** ([`CTL_IN_QUEUE`]) and applies
/// backpressure: a peer that outruns the datagram loop makes this task wait,
/// which its reliable stream turns into QUIC flow control on the peer, instead
/// of growing a per-connection queue. Dropping the message instead would break
/// the reliable-plane contract (`OPEN`/`CLOSE` are not idempotent), and waiting
/// cannot deadlock: the datagram loop only ever touches this side through
/// `queue_ctl`'s `try_send`.
///
/// The task ends when the stream or the connection goes away; the datagram
/// plane keeps running (its loss recovery never depends on a control message).
async fn r3_control_stream_task(
    conn: quinn::Connection,
    state: Arc<R2ConnState>,
    mut tx: CtlSender,
    mut rx: CtlReceiver,
    mut out_rx: tokio::sync::mpsc::Receiver<CtlMessage>,
    ctl_in: tokio::sync::mpsc::Sender<CtlMessage>,
) {
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(Some(msg)) => {
                    if !state.allow_ctl_message(coarse_millis()) {
                        // Idempotent message classes are cheap but not free;
                        // the reliable sender never repeats, so only a hostile
                        // peer can hit this.
                        r2_stats::bump(&r2_stats::CTL_MSGS_DROPPED);
                        continue;
                    }
                    r2_stats::bump(&r2_stats::CTL_MSGS_RECV);
                    // Bounded handoff: waiting here applies the peer's own QUIC
                    // stream flow control, which is the only correct answer to
                    // "the datagram loop is a queue behind" — see the fn doc.
                    if ctl_in.send(msg).await.is_err() {
                        // The datagram reader is gone: nothing can act on the
                        // message anymore.
                        r2_stats::bump(&r2_stats::CTL_STREAM_ERRORS);
                        break;
                    }
                }
                // Clean FIN from the peer: it will not send more control
                // messages. Tear the whole control plane down (the writer half
                // only exists to answer those messages); the datagram plane is
                // unaffected.
                Ok(None) => break,
                Err(_) => {
                    r2_stats::bump(&r2_stats::CTL_STREAM_ERRORS);
                    break;
                }
            },
            out = out_rx.recv() => match out {
                Some(msg) => {
                    if tx.send(msg).await.is_err() {
                        r2_stats::bump(&r2_stats::CTL_STREAM_ERRORS);
                        break;
                    }
                }
                // The connection state is being dropped: the handler is exiting.
                None => break,
            },
            _ = conn.closed() => break,
        }
    }
    // Later server→client messages are counted drops, never a DATAGRAM fallback
    // (rev3 has no control DATAGRAMs).
    state.clear_ctl_out();
}

/// Dispatch one client-opened bidi stream on a rev3 connection.
///
/// rev3 multiplexes the TCP relay and the reliable control plane on the same
/// bidi-stream space, so the **first byte** decides (see
/// [`ctl_stream::classify_first_byte`]): `0xFF` is the control marker,
/// `0x01|0x03|0x04` are the MQP address `atyp` of a TCP relay stream, anything
/// else is a protocol violation. The byte is consumed here and handed to the
/// chosen path, so it is never read twice.
///
/// The 5 s header budget starts here (one deadline for the byte plus the rest of
/// the TCP header), and the caller's header-stage credits are held across it
/// exactly like the rev2 handler's header read; the control stream returns them
/// immediately (it is not a parked header).
#[allow(clippy::too_many_arguments)]
async fn dispatch_rev3_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    header_credit: tokio::sync::OwnedSemaphorePermit,
    header_share: tokio::sync::OwnedSemaphorePermit,
    streams_held: Arc<std::sync::atomic::AtomicUsize>,
    share: usize,
    admitted: usize,
    allow_private: bool,
    conn: quinn::Connection,
    state: Arc<R2ConnState>,
    ctl_in: tokio::sync::mpsc::Sender<CtlMessage>,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut first = [0u8; 1];
    match tokio::time::timeout_at(deadline, recv.read_exact(&mut first)).await {
        Ok(Ok(())) => {}
        // A stream whose first byte never arrives is a parked header task; the
        // credits bound it and the budget releases it.
        _ => {
            send.reset(0x01u32.into()).ok();
            return;
        }
    }
    match ctl_stream::classify_first_byte(first[0]) {
        Some(StreamClass::Control) => {
            // Not a header-stage task: return the credits now.
            drop(header_credit);
            drop(header_share);
            if !state.claim_ctl_stream() {
                // Exactly one control stream per connection; a second marker
                // stream is a protocol violation.
                r2_stats::bump(&r2_stats::CTL_STREAM_SECOND);
                send.reset(0x05u32.into()).ok();
                return;
            }
            r2_stats::bump(&r2_stats::CTL_STREAMS);
            let Some((tx, rx)) = ctl_stream::accept_server_stream(send, recv, first[0]) else {
                // Unreachable: the marker was just classified as control.
                r2_stats::bump(&r2_stats::CTL_STREAM_ERRORS);
                return;
            };
            let Some(out_rx) = state.take_ctl_out_rx() else {
                // The state was not built with a writer queue (a fixture / a
                // non-rev3 connection): without it server→client control is
                // impossible, so tear the stream down instead of half-using it.
                r2_stats::bump(&r2_stats::CTL_STREAM_ERRORS);
                let mut send = tx.into_inner();
                send.reset(0x05u32.into()).ok();
                return;
            };
            r3_control_stream_task(conn, state, tx, rx, out_rx, ctl_in).await;
        }
        Some(StreamClass::Tcp { atyp }) => {
            // Hand the already-consumed atyp into the shipped TCP handler; it
            // reads only the rest of the MQP header inside the same deadline,
            // so the 5 s header budget is not doubled.
            handle_tcp_stream(
                send,
                recv,
                header_credit,
                header_share,
                streams_held,
                share,
                admitted,
                allow_private,
                conn,
                Some(atyp),
                deadline,
            )
            .await;
        }
        None => {
            // Neither a control marker nor an MQP address type: reset + count,
            // never guess a route.
            r2_stats::bump(&r2_stats::CTL_STREAM_BAD_FIRST);
            drop(header_credit);
            drop(header_share);
            send.reset(0x01u32.into()).ok();
        }
    }
}

/// Entry point kept for call sites that do not (yet) know the connection's
/// wire revision: the shipped rev2 behaviour.
///
/// The revision is a property of the connection (config + ALPN, validated at
/// the TLS boundary), so the wiring task swaps the accept loop's call to
/// [`handle_conn_with_wire`] with the configured [`Wire`]; this default wrapper
/// keeps the existing signature as the documented rev2 default/rollback entry
/// point (used by fixtures and tests).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn handle_conn(
    conn: quinn::Connection,
    allow_private: bool,
    reply_filter: ReplyFilter,
    conn_limit: Arc<tokio::sync::Semaphore>,
    conn_cap: usize,
) -> Result<()> {
    handle_conn_with_wire(
        conn,
        allow_private,
        reply_filter,
        conn_limit,
        conn_cap,
        Wire::Rev2,
    )
    .await
}

/// Connection entry point for an explicit wire revision.
///
/// The one line the later wiring task changes in `main.rs`:
/// `handle_conn(...)` → `handle_conn_with_wire(..., wire)`.
pub(crate) async fn handle_conn_with_wire(
    conn: quinn::Connection,
    allow_private: bool,
    reply_filter: ReplyFilter,
    conn_limit: Arc<tokio::sync::Semaphore>,
    conn_cap: usize,
    wire: Wire,
) -> Result<()> {
    handle_conn_inner(
        conn,
        allow_private,
        reply_filter,
        conn_limit,
        conn_cap,
        wire,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_conn_inner(
    conn: quinn::Connection,
    allow_private: bool,
    reply_filter: ReplyFilter,
    conn_limit: Arc<tokio::sync::Semaphore>,
    conn_cap: usize,
    wire: Wire,
) -> Result<()> {
    // Peer-driven rate: a line per admitted connection is the right operational
    // granularity, but a churn/handshake flood makes it one formatted line per
    // event — through tracing's process-wide writer lock, on the thread that
    // owns a whole ingress shard's QUIC driver. One line per second per class is
    // plenty; the window's losers are counted and folded into the winner's line
    // (`reporter::claim_server_log`). Formatting is inside the gate too: only the
    // winner pays for the address/time formatting.
    if let Some(sup) = claim_server_log(ServerLog::NewConn) {
        info!("new QUIC conn from {}{sup}", conn.remote_address());
    }
    let conn_id = next_conn_id();
    // One UDP socket per sess_id: replies are inherently demuxed, concurrent
    // ASSOCIATEs sharing this QUIC connection never cross-talk. The table
    // carries the process's reply-source policy (`udp_full_cone`), snapshotted
    // for this connection's sessions.
    // The connection joins the fair-share denominator only once it actually
    // holds a session (`ShardedSessTable::note_empty_state`); an idle TCP-only
    // connection must not dilute anyone's session budget.
    let sess: SessTable = Arc::new(ShardedSessTable::new(reply_filter));
    // MQP-3 connection state (flow registry + control-plane bookkeeping) for
    // this connection's wire revision. Shared by this handler, the datagram
    // reader, the sweeper and every session reader.
    let r2_state = R2ConnState::new_with_wire(wire);
    // rev3 reliable control plane: one client-opened bidi stream. `ctl_out` is
    // the server→client writer queue (installed when the stream is accepted);
    // `ctl_in` carries the peer's messages to the datagram loop, which owns the
    // reassembler/session table they act on. Both are **bounded** (this one at
    // `CTL_IN_QUEUE`, and it applies backpressure — see
    // `r3_control_stream_task`) and both are unused on rev2 (controls ride
    // DATAGRAMs there).
    let (ctl_out_tx, ctl_out_rx) = tokio::sync::mpsc::channel::<CtlMessage>(64);
    let (ctl_in_tx, mut ctl_in_rx) = tokio::sync::mpsc::channel::<CtlMessage>(CTL_IN_QUEUE);
    r2_state.install_ctl_out(ctl_out_tx);
    r2_state.install_ctl_out_rx(ctl_out_rx);
    let mut ctl_in_open = true;
    {
        let sess = sess.clone();
        let conn = conn.clone();
        let r2_sweep = r2_state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        // Shard-by-shard sweep, abort after all locks drop. Each
                        // shard's rev2 bindings are purged in **one** registry
                        // call while that shard's write lock is still held
                        // (`sweep_all_with`): the purge-by-session is collision
                        // safe there, and a full-connection reap costs one
                        // registry write lock per shard instead of one per
                        // binding.
                        let mut purged = 0usize;
                        let evicted = sess.sweep_all_with(now, |ids| {
                            purged += r2_sweep.registry.remove_sessions(ids);
                        });
                        r2_finish_reaped_entries(&evicted, purged);
                        // The client's associations are gone on this side: tell
                        // it (`SESS_CLOSE`, idempotent, three best-effort frames
                        // each) so it stops sending steady frames that could only
                        // fail lookup here. Detached and chunked with a yield
                        // between chunks: a full reap is thousands of sends, and
                        // they must not block the shard runtime that also drives
                        // every connection's QUIC.
                        let ids: Vec<u32> = evicted.iter().map(|e| e.sess).collect();
                        spawn_sess_close_notifications(conn.clone(), Some(r2_sweep.clone()), ids);
                        abort_evicted(evicted);
                    }
                    _ = conn.closed() => {
                        let drained = sess.drain_all();
                        // Connection teardown: one registry purge for the whole
                        // drain (the connection is closed, so no notification is
                        // sent), then abort the readers.
                        let ids: Vec<u32> = drained.iter().map(|e| e.sess).collect();
                        let purged = r2_sweep.registry.remove_sessions(&ids);
                        r2_finish_reaped_entries(&drained, purged);
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
    let r2 = r2_state.clone();
    // Captured for the dispatch/decoders: the revision never changes for a live
    // connection (it is fixed by config + ALPN at the handshake).
    let wire = r2_state.wire();
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
        // MQP-3 rev2 uplink `FRAG` reassembly, one per connection: the rev2
        // keys are connection-scoped (`wire_id`) or self-describing (`INLINE`),
        // so it sits next to the legacy MQP-2 reassembler rather than inside a
        // session. It shares the same expiry tick.
        // The reassembler is created for the connection's revision (the wire
        // only affects which decoded view it accepts; keys/bounds/expiry are
        // shared and `push_view` takes the adapter's view).
        let mut r2_reasm = R2Reassembler::new_with_wire(wire);
        // The reassembler can only expire state it is asked about, and `push` is
        // reached only when a fragment arrives — so a peer that sends fragments
        // and then goes quiet (its connection stays alive on keepalives) would pin
        // its partials for the connection's lifetime. This tick is what makes
        // `FRAG_TIMEOUT_MS` a real deadline.
        //
        // The select branch is guarded on `held_bytes() > 0` (partials *and*
        // tombstones, so 0 means "nothing to expire"): every connection pays for
        // this timer, including TCP-only ones, and an unguarded 500 ms tick
        // wakes an otherwise idle datagram reader twice a second forever — on a
        // 4096-connection server that is ~8k wakeups/s of pure timer churn.
        // With the guard the tick is only polled while a fragment's state is
        // actually alive; the interval's first poll after the state appears
        // fires immediately (missed-tick `Delay` behavior), so expiry latency is
        // unchanged.
        let mut reasm_tick = tokio::time::interval(Duration::from_millis(FRAG_SWEEP_INTERVAL_MS));
        reasm_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Per-connection fast table, linearly probed on the session id.
        //
        // N=1 NOTE: a fast-path hit takes zero quinn locks before the send —
        // no `close_reason`, no `max_datagram_size`. Liveness is the reader
        // task's `AbortHandle` (one atomic load) plus the socket `Weak`
        // upgrade, and the budget is the reader's cached `limit`. The send
        // itself then pays the single irreducible `SendDatagram::poll` take.
        // The slow path (`forward_server_dgram` → `get_or_create_sess`) takes
        // at most one `max_datagram_size` per new session (creation only, off
        // the memo), never per packet — and only *after* the cheap fair-share
        // gates, so a forged session id over the connection's share never
        // reaches that lock at all (reader.rs).
        //
        // **Every ingress frame kind arms it.** The fragment branch and the
        // single-datagram branch always did; both BATCH (0x06) arms used to
        // discard `forward_server_dgram`'s `Some((dst, life))` with `let _ =`,
        // so the one path built for bursty small-packet flows — each BATCH
        // frame carries up to 16 target sends — never installed the fast slot
        // and re-ran the entire slow path (session memo probe, shard read
        // lock, unbatched send) for every payload of every frame, forever.
        // Arm from the first answer the slow path returns.
        //
        // **Why a table and not one slot.** A single `(session, dst)` pair was
        // the largest defect on this path. The client multiplexes every UDP
        // association of an egress class onto one connection — `SharedEgress::
        // egress_order` picks that class's own dedicated UDP slot first and a
        // fail-closed pool stops there — so one connection routinely carries
        // hundreds of sessions. With one slot, every datagram for any *second*
        // session missed, and a miss is not just a lookup: it is the whole slow
        // path (`remember_dst`'s shard read lock, an unbatched target send that
        // bypasses `flush_staged_sends`'s `sendmmsg`, and two memo probes with a
        // `Weak` upgrade plus three `Arc` clones each) and a lost batch group.
        // Measured on loopback, volume-matched (20 000 datagrams, one session vs
        // two): 70.2 us of server CPU per delivered datagram against 76.3 us,
        // +8.8% — and that is with the portable fallback, i.e. before the Linux
        // syscall amplification of one `sendto` per datagram against one
        // `sendmmsg` per 32.
        //
        // Sizing: 128 slots (a 440 B payload entry, pinned by the
        // `size_of::<FastSess>()` assert above, next to a 4 B tag and an 8 B
        // stamp in the probe arrays). The multi-association shape this comment
        // documents ("hundreds of sessions") is beyond one heap array, but 64
        // covered only the DNS + game + handful-of-flows case, and the shipped
        // client packs up to ~2000 live sessions onto one connection, i.e. once
        // a table is full *every* arm evicts. 128 doubles the working set for
        // ~56.5 KiB per connection and admission still charges it through
        // `R2_INGRESS_FIXED_BYTES`. The remaining gap to `LOCAL_SESS_MAX` is
        // structural: covering it with slots would cost ~1.8 MiB per
        // connection, so a miss must stay cheap (an arm now scans only the tag
        // and stamp arrays) rather than be made impossible by table size.
        //
        // **Probed, not direct-mapped.** Session ids come from the client's
        // monotonic counter and are never reused, so the live ids on a
        // long-lived connection are a *sparse* subset of the id space rather
        // than a dense interval: a raw `s & (N-1)` maps two live sessions to the
        // same slot at random, and an earlier revision's "N <= 16 live ids land
        // on N distinct slots" was only true for consecutive ids. After churn
        // the chance all A live homes are distinct falls off as `∏(N-i)/N`; at
        // N=16 it was already ~50 % at A=5 and ~12 % at A=8, so collisions were
        // the *common* multi-association case, and a colliding pair evicted each
        // other on every arm and paid the whole slow path (an unbatched
        // `udp_try_send` per datagram, a `remember_dst` shard read lock, an
        // epoch bump) forever. With linear probing any set of ≤ N live sessions
        // finds a slot; only a genuinely over-N-live table evicts the quietest,
        // and a probe miss is never a mis-route: every slot re-validates the
        // exact session id, the reader's liveness and the socket's liveness
        // before it stages anything, and a miss only means "run the slow path,
        // which re-arms".
        //
        // The slot count stays a compromise rather than as large as possible:
        // every slot carries a 255-byte pin buffer for the domain-target
        // shortcut, and this table lives per *connection* (4096 admitted
        // connections would be ~105 MiB at this size — the reason the admission
        // charge was raised alongside the slot count, see
        // `R2_INGRESS_FIXED_BYTES` in `config::tuning`).
        let mut fast = FastTable::new();
        // Target sends staged for the current drain burst, flushed grouped per
        // `(sock, dst)` run by `flush_staged_sends` (one `sendmmsg` per 32 on
        // Linux, one `try_send_to` per frame elsewhere). Bounded by
        // `LAST_HOP_DRAIN`, cleared per burst.
        let mut staged: Vec<StagedSend> = Vec::with_capacity(LAST_HOP_DRAIN);
        loop {
            let head: Bytes = tokio::select! {
                r = reader.as_mut() => match r {
                    Ok(d) => d,
                    Err(_) => break,
                },
                // rev3 reliable control plane: the control-stream task forwards
                // the peer's rare messages here, because this task owns the
                // reassembler and session table they act on. Disabled on rev2
                // (its control plane is the CTL DATAGRAM, handled per frame).
                msg = ctl_in_rx.recv(), if wire == Wire::Rev3 && ctl_in_open => match msg {
                    Some(msg) => {
                        handle_control_message(&ss, &r2, &mut r2_reasm, msg);
                        continue;
                    }
                    None => {
                        // Every control-stream task is gone (connection teardown).
                        ctl_in_open = false;
                        continue;
                    }
                },
                _ = reasm_tick.tick(),
                    if reasm.held_bytes() > 0 || r2_reasm.held_bytes() > 0 =>
                {
                    // Coarse epoch: every consumer here compares against
                    // `FRAG_TIMEOUT_MS` (2 s) or the 500 ms sweep throttle, so a
                    // 1 s-quantized sample of the same epoch is sufficient — and
                    // `mono_millis()` was a vDSO `clock_gettime` per *fragment*
                    // on the receive path. (`DgramFragmenter`'s 32-bit id-reuse
                    // guard keeps its precise clock: that one is a splice-safety
                    // bound, and it runs per fragmented payload, not per packet.
                    // It is a backstop now — a 32-bit space cannot wrap inside
                    // the window at any sustained rate.)
                    let now = coarse_millis();
                    reasm.expire(now);
                    r2_reasm.expire(now);
                    continue;
                }
            };
            // Bounded drain (mirrors the client dispatcher): the awaited head
            // plus up to `LAST_HOP_DRAIN - 1` already-buffered datagrams via
            // `now_or_never` (`read_datagram` is cancel-safe: a buffered datagram
            // returns before its first await point, and a Pending probe parks
            // nothing). One wakeup moves up to 32 datagrams; the fast path
            // stages its target send and the burst flushes grouped per
            // `(sock, dst)` run. A drained connection error flushes what was
            // staged and then exits.
            let mut drained = 1usize;
            let mut closed = false;
            let mut pending: Option<Bytes> = Some(head);
            'burst: loop {
                let d = match pending.take() {
                    Some(d) => d,
                    None => {
                        if drained >= LAST_HOP_DRAIN {
                            break 'burst;
                        }
                        match reader.as_mut().now_or_never() {
                            Some(Ok(d)) => {
                                drained += 1;
                                d
                            }
                            Some(Err(_)) => {
                                closed = true;
                                break 'burst;
                            }
                            None => break 'burst,
                        }
                    }
                };
                // `d` is already owned (from `read_datagram`), so payload slices borrow
                // it directly: one refcount bump per slice, no extra clone per packet.
                // (`decode_*_ref` borrows are shared, coexisting with `slice`.)
                //
                // rev3 connections dispatch **only** rev3 frames: the revision is
                // fixed at the TLS/ALPN boundary, so a legacy MQP-2/3 frame here
                // is a protocol violation, not a fallback. The first byte is
                // classified exactly once and handed to the dispatcher.
                if wire == Wire::Rev3 {
                    match wire::kind(Wire::Rev3, &d) {
                        Some(kind) => {
                            handle_ingress_frame(
                                &mut fast,
                                &ss,
                                &cd,
                                conn_id,
                                allow_private,
                                &mut staged,
                                &r2,
                                &mut r2_reasm,
                                Wire::Rev3,
                                kind,
                                d,
                            )
                            .await;
                        }
                        // Not an r3 frame class: counted refusal, never guessed.
                        None => {
                            dgram_drops::bump(&dgram_drops::REFUSED);
                        }
                    }
                    continue;
                }
                if is_v3(&d) {
                    handle_v3_ingress(
                        &mut fast,
                        &ss,
                        &cd,
                        conn_id,
                        allow_private,
                        &mut staged,
                        Some(&r2),
                        d,
                    )
                    .await;
                    continue;
                }
                // rev2 frames are dispatched before the MQP-2 kinds: their first
                // byte is `0x0X`, which no legacy decoder accepts (see
                // `r2::is_r2`), so the two dispatch orders can never claim the
                // same DATAGRAM. `wire::kind` is the single classification; the
                // legacy v2/v3 fallbacks above/below are rev2-connection-only and
                // keep the shipped mixed-version behaviour byte-identical.
                if let Some(kind) = wire::kind(Wire::Rev2, &d) {
                    handle_ingress_frame(
                        &mut fast,
                        &ss,
                        &cd,
                        conn_id,
                        allow_private,
                        &mut staged,
                        &r2,
                        &mut r2_reasm,
                        Wire::Rev2,
                        kind,
                        d,
                    )
                    .await;
                    continue;
                }
                if d.first() == Some(&MQP_DGRAM_FRAG) {
                    let Ok(f) = decode_fragment(&d) else {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        continue;
                    };
                    let Some((s, a, whole)) = reasm.push(&f, coarse_millis()) else {
                        continue;
                    };
                    udp_stats::payload(whole.len());
                    // One resolution for this datagram: the session's own pin, else
                    // the DNS cache. A domain target whose session is already pinned
                    // never reaches `forward_server_dgram` at all.
                    let want = resolve_fast(&mut fast, &ss, s, a.as_ref(), allow_private);
                    // Stage on the fast path; only the slow path keeps the payload,
                    // and `try_stage` hands it back on a miss so the steady path
                    // pays no `Bytes` clone.
                    let whole = match want {
                        Some(dst) => match try_stage(
                            &mut fast,
                            &ss,
                            conn_id,
                            s,
                            dst,
                            whole,
                            allow_private,
                            &mut staged,
                        ) {
                            Ok(()) => continue,
                            Err(whole) => whole,
                        },
                        None => whole,
                    };
                    // Flush staged fast-path sends before the slow path's own
                    // (immediate) send, so a flow's datagrams keep their staging
                    // order on the wire.
                    flush_staged_sends(&mut staged);
                    let used = forward_server_dgram(
                        &ss,
                        &cd,
                        conn_id,
                        s,
                        a.as_ref(),
                        whole,
                        allow_private,
                        Some(&r2),
                    )
                    .await;
                    if let Some((dst, life)) = used {
                        arm_fast(&mut fast, conn_id, s, a.as_ref(), dst, life);
                    }
                } else {
                    if is_batch(&d) {
                        let Ok(b) = decode_batch(&d) else {
                            dgram_drops::bump(&dgram_drops::REFUSED);
                            continue;
                        };
                        let s = b.sess;
                        let want = resolve_fast(&mut fast, &ss, s, b.addr, allow_private);
                        match want {
                            Some(dst) => {
                                for p in b.payloads() {
                                    let off = p.as_ptr() as usize - d.as_ptr() as usize;
                                    let payload = d.slice(off..off + p.len());
                                    udp_stats::payload(p.len());
                                    if let Err(payload) = try_stage(
                                        &mut fast,
                                        &ss,
                                        conn_id,
                                        s,
                                        dst,
                                        payload,
                                        allow_private,
                                        &mut staged,
                                    ) {
                                        // See the single-datagram branch: flush
                                        // staged sends before the slow path's
                                        // immediate send so a flow's datagrams
                                        // keep their staging order on the wire.
                                        flush_staged_sends(&mut staged);
                                        let used = forward_server_dgram(
                                            &ss,
                                            &cd,
                                            conn_id,
                                            s,
                                            b.addr,
                                            payload,
                                            allow_private,
                                            Some(&r2),
                                        )
                                        .await;
                                        // Arm from the slow path's answer, so the
                                        // *next* frame for this session hits the
                                        // fast table (see the table comment).
                                        if let Some((dst2, life)) = used {
                                            arm_fast(&mut fast, conn_id, s, b.addr, dst2, life);
                                            #[cfg(test)]
                                            BATCH_FAST_ARMS
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        }
                                    }
                                }
                                continue;
                            }
                            None => {
                                flush_staged_sends(&mut staged);
                                for p in b.payloads() {
                                    let off = p.as_ptr() as usize - d.as_ptr() as usize;
                                    let payload = d.slice(off..off + p.len());
                                    udp_stats::payload(p.len());
                                    let used = forward_server_dgram(
                                        &ss,
                                        &cd,
                                        conn_id,
                                        s,
                                        b.addr,
                                        payload,
                                        allow_private,
                                        Some(&r2),
                                    )
                                    .await;
                                    // Same arm as the `Some(dst)` arm above: an
                                    // unarmed table is exactly why `want` was
                                    // `None`, and the slow path's answer is what
                                    // installs the slot for the rest of the
                                    // burst. Discarding it (the old `let _ =`)
                                    // kept every payload of every BATCH frame on
                                    // the slow path.
                                    if let Some((dst2, life)) = used {
                                        arm_fast(&mut fast, conn_id, s, b.addr, dst2, life);
                                        #[cfg(test)]
                                        BATCH_FAST_ARMS
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    let Ok((s, a, p)) = decode_datagram_ref(&d) else {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        continue;
                    };
                    let want = resolve_fast(&mut fast, &ss, s, a, allow_private);
                    // `d` is already owned (from `read_datagram`), so the slice
                    // borrows it directly: one refcount bump, no payload copy.
                    let off = d.len() - p.len();
                    let payload_len = p.len();
                    let payload = d.slice(off..);
                    // Charged once, before the fast/slow split, exactly like the
                    // fragment branch: the counter must not depend on which path
                    // the datagram took.
                    udp_stats::payload(payload_len);
                    let payload = match want {
                        Some(dst) => match try_stage(
                            &mut fast,
                            &ss,
                            conn_id,
                            s,
                            dst,
                            payload,
                            allow_private,
                            &mut staged,
                        ) {
                            Ok(()) => continue,
                            Err(payload) => payload,
                        },
                        None => payload,
                    };
                    // See the fragment branch: flush staged sends before the slow
                    // path's immediate send to keep per-flow order.
                    flush_staged_sends(&mut staged);
                    let used = forward_server_dgram(
                        &ss,
                        &cd,
                        conn_id,
                        s,
                        a,
                        payload,
                        allow_private,
                        Some(&r2),
                    )
                    .await;
                    if let Some((dst, life)) = used {
                        arm_fast(&mut fast, conn_id, s, a, dst, life);
                    }
                }
            }
            flush_staged_sends(&mut staged);
            record_drain_batch(drained);
            // Saturation yields: the extra datagrams of a burst are served by
            // `now_or_never` with a noop waker, and quinn returns an
            // already-buffered datagram before its first await point, so a
            // *full* burst leaves this branch ready again at once and the task
            // would hold its worker indefinitely. A full burst is exactly the
            // saturated case; a partial one already drained the peer, so the
            // next `select!` parks as before.
            if drained >= LAST_HOP_DRAIN {
                tokio::task::yield_now().await;
            }
            if closed {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // TCP: one QUIC bidi stream per connection. First bytes = MQP addr header.
    // Concurrent streams are already capped by the transport; dials are bounded
    // process-wide (not per connection) so many connections cannot exhaust fds
    // together.
    //
    // Admission is **two-stage**, and each stage has its own pool:
    // 1. a [`HEADER_TASK_CREDIT`] is taken before the spawn and released once
    //    the 5 s header read has returned (success or failure) — this is what
    //    bounds parked header tasks, which the transport's per-connection
    //    stream credit (8192 x admitted connections) does not;
    // 2. the share slot and [`MAX_STREAM_TASKS`] permit are taken *after* the
    //    header, inside `handle_tcp_stream`, and cover the dial plus the whole
    //    relay — so a trickling header cannot exhaust the stream pool and a
    //    long-lived flow cannot sit on header credit.
    // On top of the two-stage flow, the header stage also has a per-connection
    // share ([`HEADER_CREDIT_PER_CONN`]): [`HEADER_TASK_CREDIT`] is a
    // process-wide bound, and one admitted peer can open its whole transport
    // stream allowance, so without the share the first peer to arrive parks
    // every header task the host can afford (each stream may also pin up to
    // quinn-proto's 1024 reassembly gap chunks) and every other client is reset
    // `0x05` until the trickle finishes. The share permit is passed into the
    // handler and dropped together with the global credit when the header read
    // resolves, so a live relay flow occupies neither.
    // The stream-task pool is process-wide, and one connection may open
    // `MAX_BIDI_STREAMS_PER_CONN` (8192) streams — more than the whole pool — so
    // each connection also has to stay inside its own share of it. Without this,
    // the first two peers to arrive hold every permit while their flows sit idle
    // and every other client's CONNECT is reset after its SOCKS success
    // reply — with nothing logged server-side.
    let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let header_share = Arc::new(tokio::sync::Semaphore::new(HEADER_CREDIT_PER_CONN));
    loop {
        let (mut send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => break,
        };
        // Header-stage credit, taken *before* the spawn: the task that reads
        // the header is the memory a peer floods for (8192 x connections
        // parked tasks), so it is charged here and returned as soon as the
        // read resolves. Fail-fast 0x05: a stream the host cannot afford to
        // park is reset immediately, exactly like an exhausted stream pool.
        let header_credit = match header_task_limiter().clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let n = HEADER_TASK_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                warn_header_credit_refused(n);
                send.reset(0x05u32.into()).ok();
                continue;
            }
        };
        // This connection's own slice of the parked-header budget. Taken after
        // the global credit (so the process-wide pool is never held by a
        // connection that is refused its own share) and fail-fast like it: a
        // peer that already parked its slice is flooding this host, not asking
        // for a flow, so a reset is the honest answer.
        let header_share_permit = match header_share.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let n = HEADER_SHARE_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if warn_once_per_sec() {
                    warn!(
                        "per-connection parked-stream limit {HEADER_CREDIT_PER_CONN} reached \
                         ({n} refused so far); resetting the stream"
                    );
                }
                drop(header_credit);
                send.reset(0x05u32.into()).ok();
                continue;
            }
        };
        // Admitted connections (the accept loop holds one permit each). The
        // denominator is this endpoint's actual cap, which the admission budget
        // may have lowered, not `MAX_CONNECTIONS`.
        let admitted = conn_cap
            .saturating_sub(conn_limit.available_permits())
            .max(1);
        let share = stream_share(admitted);
        let stat_conn = conn.clone();
        // One task per accepted stream, bounded by [`HEADER_TASK_CREDIT`] for
        // the header stage. Inside, the task trades the credit for the share
        // slot + process-wide stream permit before dialing (see
        // `handle_tcp_stream`).
        if wire == Wire::Rev3 {
            // rev3 multiplexes the reliable control stream and the TCP relay on
            // the same bidi-stream space: the first byte decides. rev2 never
            // sniffs it (its control plane is CTL DATAGRAMs), which keeps the
            // shipped header read — and its bytes — unchanged.
            tokio::spawn(dispatch_rev3_stream(
                send,
                recv,
                header_credit,
                header_share_permit,
                streams_held.clone(),
                share,
                admitted,
                allow_private,
                stat_conn,
                r2_state.clone(),
                ctl_in_tx.clone(),
            ));
        } else {
            tokio::spawn(handle_tcp_stream(
                send,
                recv,
                header_credit,
                header_share_permit,
                streams_held.clone(),
                share,
                admitted,
                allow_private,
                stat_conn,
                None,
                tokio::time::Instant::now() + Duration::from_secs(5),
            ));
        }
    }
    Ok(())
}
