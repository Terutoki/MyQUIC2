//! Admission limits: connection/dial/stream caps and the per-connection handler.
use super::*;
use futures_util::future::FutureExt as _;
use myquic2::mqp::r2::{self, Caps, Ctl, R2Kind};
use myquic2::mqp::r2_flow::{
    CtlState, FlowBinding, FlowIds, FlowRegistry, FlowState, RegistryError, SessionFlows,
};
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
/// - the TCP relay pump buffers of the whole process-wide stream-task pool
///   ([`stream_pump_memory_bytes`]).
///
/// Charging all three here is what makes the printed worst case match what the
/// process can actually pin; charging only the session pool left the endpoint
/// and relay-buffer terms invisible to `max_peer_memory_mb`. A budget too small
/// for even one connection clamps to one rather than zero: an endpoint that
/// admits nothing cannot be diagnosed from the outside.
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

/// Per-connection fast-path slots, linearly probed on the session id.
///
/// See the note at the declaration site in [`handle_conn`] for why this is a
/// table and not the single `(session, dst)` pair it used to be; the sizing
/// argument is there too.
pub(crate) const FAST_SESS_SLOTS: usize = 16;
// `fast_slot` masks instead of taking a modulo, and every probe step is a mask.
const _: () = assert!(FAST_SESS_SLOTS.is_power_of_two());

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
    /// (and its 2 x 32 KiB kernel buffers) alive outside the
    /// `MAX_SESSIONS_GLOBAL` budget until the next datagram happened to evict
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
    /// The session's MQP-3 flow table snapshot handle. Cached here so a steady
    /// v3 frame resolves a compressed flow id without taking the session-table
    /// shard lock; the snapshot itself is clone-on-write, so this handle stays
    /// valid across flow opens.
    flows: Arc<arc_swap::ArcSwap<FlowTable>>,
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

/// Home probe position for `s` — the first slot its entry may occupy.
///
/// The table is a small linearly probed map whose hash is the session id's low
/// bits. Session ids are allocated from a **monotonic, never-reused** client
/// counter (`hub.rs::alloc_sess`), so on a long-lived connection the live ids
/// are a *sparse* subset of the 32-bit space, not a dense `1..=N` interval: two
/// live sessions land on the same home slot at random (with A live ids the
/// chance all homes are distinct is `∏(16-i)/16`, i.e. ~50 % already at A=5).
/// Probing past the home slot is what keeps every such collision from parking
/// both sessions on the slow path forever — see [`fast_probe`].
pub(crate) fn fast_slot(s: u32) -> usize {
    (s as usize) & (FAST_SESS_SLOTS - 1)
}

/// The slot describing `s`, found by linear probing from its home position.
///
/// Probing stops at the first empty slot: [`arm_fast`] always installs an entry
/// at the first empty position from the session's home, so an entry is reachable
/// while the chain from home up to it has no hole. A hole (left by an eviction
/// or a stale-slot clear) can therefore only turn a hit into a **miss** — which
/// is safe, because a miss means "run the slow path", which re-arms the slot —
/// and can never mis-route a datagram onto another session's socket.
pub(crate) fn fast_probe(fast: &[Option<FastSess>; FAST_SESS_SLOTS], s: u32) -> Option<usize> {
    let home = fast_slot(s);
    for step in 0..FAST_SESS_SLOTS {
        let idx = (home + step) & (FAST_SESS_SLOTS - 1);
        match &fast[idx] {
            None => return None,
            Some(slot) if slot.sess == s => return Some(idx),
            Some(_) => {}
        }
    }
    None
}

/// Where [`arm_fast`] publishes a session: its existing slot, else the first
/// empty slot from home, else the least-recently-active slot when all 16 are
/// taken.
///
/// The eviction order is the session's own liveness stamp (`last`, refreshed at
/// most once a second per session), so a table that is genuinely over
/// `FAST_SESS_SLOTS` live sessions keeps the recently active ones and lets the
/// quiet ones fall back to the slow path — the same disposition the old
/// direct-mapped table gave a colliding pair, but only once the table is full,
/// not on a random low-bit collision below it.
fn fast_arm_index(fast: &[Option<FastSess>; FAST_SESS_SLOTS], s: u32) -> usize {
    let home = fast_slot(s);
    let mut oldest: Option<(u64, usize)> = None;
    for step in 0..FAST_SESS_SLOTS {
        let idx = (home + step) & (FAST_SESS_SLOTS - 1);
        match &fast[idx] {
            None => return idx,
            Some(slot) if slot.sess == s => return idx,
            Some(slot) => {
                let last = slot.last.load(std::sync::atomic::Ordering::Relaxed);
                if oldest.is_none_or(|(oldest_last, _)| last < oldest_last) {
                    oldest = Some((last, idx));
                }
            }
        }
    }
    // Every slot is live and none is this session: evict the quietest.
    oldest.map_or(home, |(_, idx)| idx)
}

/// Empty slot value for `[Option<FastSess>; _]` initialization.
pub(crate) const NO_FAST_SESS: Option<FastSess> = None;

/// Resolve one datagram's target: the session's own pin first (free), then the
/// session's destination memo, then the DNS cache.
///
/// Only this session's own slot is ever consulted — the pin is keyed on
/// `(session, name, port)` and answering another session's datagram from it
/// would be a silent mis-route. A miss resolves with a scratch slot, so the
/// memo/DNS answer is still used for this datagram; the slow path then installs
/// the slot (and its own pin) for the session that asked.
pub(crate) fn resolve_fast(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    s: u32,
    a: TargetAddrRef<'_>,
    allow_private: bool,
) -> Option<SocketAddr> {
    let (h, p) = match a {
        TargetAddrRef::Ip(dst) => return Some(dst),
        TargetAddrRef::Domain(h, p) => (h, p),
    };
    // Scratch is only reached when this session has no reachable slot; nothing
    // is ever armed into it.
    let mut scratch: Option<ConnPin> = None;
    let pin = match fast_probe(fast, s) {
        Some(idx) => match fast[idx].as_mut() {
            Some(slot) => &mut slot.pin,
            // Unreachable: `fast_probe` only returns populated slots.
            None => &mut scratch,
        },
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
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    conn_id: usize,
    s: u32,
    dst: SocketAddr,
    payload: Bytes,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
) -> Result<(), Bytes> {
    let Some(idx) = fast_probe(fast, s) else {
        return Err(payload);
    };
    // `fast_probe` only returns populated slots; keep the fallback a miss rather
    // than a panic (release builds are panic=abort).
    let Some(slot) = fast[idx].as_mut() else {
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
    staged.push(StagedSend {
        sock,
        dst: map_for_dual(dst),
        payload,
    });
    Ok(())
}

/// Publish `(session, dst)` into this connection's fast table after the slow
/// path created or found the session, so the next datagram for it is a hit.
///
/// The slot is chosen by [`fast_arm_index`] (existing slot, else first empty
/// from the session's home, else the quietest), so probing lookups always find
/// it. A `Stale`/`Miss` memo probe clears the session's slot instead: the
/// session is gone or invisible, and leaving the old entry in place would keep
/// sending into it.
pub(crate) fn arm_fast(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    conn_id: usize,
    s: u32,
    a: TargetAddrRef<'_>,
    dst: SocketAddr,
    life: u64,
) {
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, abort, epoch) => {
            let Some(flows) = session_flows(ss, s) else {
                if let Some(idx) = fast_probe(fast, s) {
                    fast[idx] = None;
                }
                return;
            };
            let mut pin = None;
            let (ph, pp) = target_name(a);
            pin_arm(&mut pin, s, ph, pp, dst, life);
            let idx = fast_arm_index(fast, s);
            fast[idx] = Some(FastSess {
                sess: s,
                sock: Arc::downgrade(&sock),
                last,
                abort,
                epoch,
                pin,
                last_dst: None,
                allow: None,
                flows,
            });
        }
        SessHit::Stale | SessHit::Miss => {
            if let Some(idx) = fast_probe(fast, s) {
                fast[idx] = None;
            }
        }
    }
}

/// The session's flow table from its fast slot, without taking the session-table
/// lock. A stale/dead slot falls through to the caller's `session_flows` probe.
fn fast_flows(
    fast: &[Option<FastSess>; FAST_SESS_SLOTS],
    s: u32,
) -> Option<Arc<arc_swap::ArcSwap<FlowTable>>> {
    let idx = fast_probe(fast, s)?;
    let slot = fast[idx].as_ref()?;
    slot.is_live_for(s).then(|| slot.flows.clone())
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
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
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
        arm_fast(fast, ss, conn_id, sess, a, dst, life);
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
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
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
    let mut flows = fast_flows(fast, sess).or_else(|| session_flows(ss, sess));
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
/// surface (shared with the client, so not extended here). Relaxed atomics: at
/// most one increment per frame next to a QUIC DATAGRAM send, so the cost is
/// noise; tests read them to prove a drop happened on the path under test
/// instead of inferring it from a timeout.
pub(crate) mod r2_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Rev2 frame dropped because no valid `HELLO` had been seen.
    pub(crate) static GATED: AtomicU64 = AtomicU64::new(0);
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
    pub(crate) static STEADY_SENT: AtomicU64 = AtomicU64::new(0);
    pub(crate) static OPEN_SRC_SENT: AtomicU64 = AtomicU64::new(0);
    /// Staged small replies dropped because the connection stager was full
    /// (bounded queue) or could not be re-queued after a drain.
    pub(crate) static STAGE_FULL_DROPS: AtomicU64 = AtomicU64::new(0);
    /// Server-owned flows created for full-cone / unsolicited downlink sources
    /// (`DATA OPEN|SRC` with an id from the server's half).
    pub(crate) static FULL_CONE_FLOWS: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
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
/// - [`CtlState`] carries the `HELLO`/`CAPS` gate: rev2 data frames are dropped
///   (and counted) until a valid HELLO for this wire version has been seen.
pub(crate) struct R2ConnState {
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
}

impl R2ConnState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(FlowRegistry::new(
                myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_CONN,
            )),
            ids: FlowIds::new(true),
            ctl: Arc::new(CtlState::new()),
            stage: Arc::new(parking_lot::Mutex::new(R2Stager::new())),
            last_caps_ms: std::sync::atomic::AtomicU64::new(0),
        })
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

/// Best-effort control-frame send (control frames are loss-tolerant).
fn r2_send_ctl(cd: &quinn::Connection, ctl: &Ctl) {
    let _ = try_send_datagram(cd, r2::encode_ctl(ctl));
}

/// Count one rev2 policy/gate refusal (shared `REFUSED` plus the rev2 counter).
fn r2_refuse(counter: Option<&std::sync::atomic::AtomicU64>) {
    dgram_drops::bump(&dgram_drops::REFUSED);
    if let Some(c) = counter {
        r2_stats::bump(c);
    }
}

fn r2_reject(cd: &quinn::Connection, id: u32, reason: u8) {
    r2_stats::bump(&r2_stats::REJECTS);
    r2_send_ctl(cd, &Ctl::FlowReject { id, reason });
}

/// Install an accepted `DATA OPEN` in both tables: the connection-wide forward
/// registry and the session's reverse table.
///
/// The target has already accepted the payload when this runs; an install
/// failure therefore only means "no compression", never "payload lost".
fn r2_install(
    state: &Arc<R2ConnState>,
    ss: &SessTable,
    sess: u32,
    wire_id: u32,
    target: TargetAddr,
    resolved: Vec<SocketAddr>,
) -> Result<Arc<FlowBinding>, RegistryError> {
    let Some(flows) = session_r2_flows(ss, sess) else {
        // The session vanished between the forward and the install; the payload
        // was delivered, but there is nothing left to bind.
        return Err(RegistryError::Full);
    };
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
    flows.rcu(|old| {
        let mut next = (**old).clone();
        let _ = next.insert(inserted.clone());
        Arc::new(next)
    });
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

/// Drop every rev2 binding of a session entry (session removal paths: the 180 s
/// sweeper, `SESS_CLOSE`, connection teardown). Returns how many were dropped.
pub(crate) fn r2_close_entry_bindings(state: &R2ConnState, entry: &SessEntry) -> usize {
    let flows = entry.r2_flows.load();
    let mut n = 0usize;
    for binding in flows.iter() {
        if state.registry.remove(binding.wire_id).is_some() {
            binding.mark_closed();
            n += 1;
        }
    }
    // Publish an empty reverse table too: a reply reader that still holds this
    // session's handle (it is being aborted) must not match a torn-down binding
    // from its snapshot.
    if n > 0 {
        entry.r2_flows.store(Arc::new(SessionFlows::new()));
    }
    n
}

/// `CTL SESS_CLOSE`: reap the session (socket, reader task, permit) and every
/// binding it owns from the connection registry, immediately.
pub(crate) fn r2_close_session(ss: &SessTable, state: &R2ConnState, sess: u32) -> bool {
    let entry = ss.take_session(sess);
    // Purge by session id, which is authoritative even if the table entry was
    // already gone (a reply reader that exited first, or a retransmitted close):
    // a receive-only binding must never outlive its association.
    let purged = state.registry.remove_session(sess);
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
fn r2_handle_ctl(
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
    match ctl {
        Ctl::Hello { wire_ver, .. } => {
            if wire_ver == r2::R2_WIRE_VER {
                state.ctl.mark_hello();
            } else {
                // Version mismatch: answer with our own version so the peer can
                // fail fast, but never open the gate for it.
                r2_stats::bump(&r2_stats::BAD_HELLO);
            }
            if state.caps_due(mono_millis()) {
                let caps = Caps::default();
                state.ctl.set_caps(caps);
                r2_stats::bump(&r2_stats::CAPS_SENT);
                r2_send_ctl(cd, &Ctl::Caps(caps));
            }
        }
        // Server-owned flows are Phase 1b; a client ACK can only confirm one.
        Ctl::FlowAck { id, .. } => {
            if let Some(binding) = state.registry.get(id) {
                binding.mark_open();
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
            // Idempotent: a close retransmission (or a close for an id this
            // side already reaped) is a no-op, not a policy refusal. Release any
            // in-flight rev2 partial for the flow as well.
            let dropped = r2_reasm.drop_flow(id);
            let _ = state.stage.lock().drop_flow(id);
            if dropped > 0 {
                r2_stats::SESSION_END_BINDINGS
                    .fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
            }
            if r2_remove_flow(ss, state, id).is_some() {
                r2_stats::bump(&r2_stats::FLOW_CLOSES);
            } else {
                r2_stats::bump(&r2_stats::STALE_CLOSES);
            }
        }
        Ctl::SessClose { sess, .. } => {
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

/// Forward one payload for an already-installed rev2 flow.
///
/// The target is the binding's IP address, or (domain flow) the first address
/// the install validated — a steady compressed frame never resolves DNS again
/// and never reaches an address the install did not authorize. Payload delivery
/// goes through the same fast/slow machinery as every other ingress frame.
#[allow(clippy::too_many_arguments)]
async fn r2_forward_flow_item(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    wire_id: u32,
    payload: Bytes,
) -> bool {
    // A server-owned id names a *downlink-created* flow (full-cone / unsolicited
    // source). A steady/TRAIN item on it is the client app's reply to that
    // source, and is legitimate exactly when this connection has a live binding
    // for the id: the binding carries the session and the remote source
    // (`target = Ip(src)`), so it is forwarded like any other flow item. Unknown
    // and closed ids still fail lookup (drop + count, never guess), and a client
    // `DATA OPEN` on a server-owned id is still rejected by the owner-half rule.
    let Some(binding) = state.registry.get(wire_id) else {
        r2_refuse(Some(&r2_stats::UNKNOWN_ID));
        return false;
    };
    if binding.state() == FlowState::Closed {
        // The id was closed (FLOW_CLOSE / session teardown); a late frame must
        // fail lookup, never be re-routed.
        r2_refuse(Some(&r2_stats::UNKNOWN_ID));
        return false;
    }
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
                arm_fast(fast, ss, conn_id, sess, aref, used_dst, life);
            }
            used.is_some()
        }
    }
}

/// Resolve and forward the payload of a domain-target `DATA OPEN`.
///
/// Returns the validated address set to install in the binding (the set is what
/// authorizes domain reply sources on the downlink), or `None` after sending the
/// matching `FLOW_REJECT`.
#[allow(clippy::too_many_arguments)]
async fn r2_forward_domain_open(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    state: &Arc<R2ConnState>,
    id: u32,
    sess: u32,
    host: &str,
    port: u16,
    payload: Bytes,
) -> Option<Vec<SocketAddr>> {
    // Resolve synchronously: the OPEN is the only frame that carries the name,
    // so the validated address set must be known before the binding is
    // installed. The DNS layer's own negative cache makes a repeated OPEN cheap,
    // and the shared slow-path budget bounds a flood of distinct names (a peer
    // pays a registry slot and a new flow id per OPEN, so this is only a
    // second line of defence).
    let _dns_permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            dgram_drops::bump(&dgram_drops::DNS_BUDGET);
            r2_reject(cd, id, r2::R2_REJECT_DNS);
            return None;
        }
    };
    let addrs = match resolve_all_cached(host, port).await {
        Ok(v) => v,
        Err(_) => {
            r2_refuse(None);
            r2_reject(cd, id, r2::R2_REJECT_DNS);
            return None;
        }
    };
    let usable: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| allow_private || is_global_ip(a.ip()))
        .collect();
    if usable.is_empty() {
        // Every record was rejected by the SSRF policy.
        r2_refuse(None);
        r2_reject(cd, id, r2::R2_REJECT_POLICY);
        return None;
    }
    let dst = usable[0];
    let sock = match get_or_create_sess(
        ss,
        cd,
        conn_id,
        sess,
        Some((host, port, dst, DNS_CACHE_TTL_MS)),
        Some(state),
    )
    .await
    {
        Some(s) => s,
        None => {
            // Session/share/permit refusal: no flow can be installed around it.
            r2_reject(cd, id, r2::R2_REJECT_TABLE_FULL);
            return None;
        }
    };
    remember_dst(ss, sess, dst);
    arm_fast(
        fast,
        ss,
        conn_id,
        sess,
        TargetAddrRef::Domain(host, port),
        dst,
        DNS_CACHE_TTL_MS,
    );
    udp_try_send(&sock, map_for_dual(dst), payload);
    Some(usable)
}

/// Handle one `DATA OPEN` (client-initiated flow: the address is the target).
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_open(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
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
        r2_reject(cd, id, r2::R2_REJECT_POLICY);
        return;
    }
    // An id is bound to one `(session, target)` for the connection's life: a
    // reopen with a different target is a protocol violation, never a reroute.
    if let Some(existing) = state.registry.get(id) {
        if existing.session != sess || existing.target != target {
            r2_refuse(None);
            r2_reject(cd, id, r2::R2_REJECT_POLICY);
            return;
        }
    } else if state.registry.len() >= state.registry.cap() {
        r2_reject(cd, id, r2::R2_REJECT_TABLE_FULL);
        return;
    }
    // Deliver first (or resolve+deliver): a flow is installed only after the
    // target actually accepted a payload. A duplicate OPEN still forwards this
    // frame's distinct payload, then re-installs idempotently and re-ACKs.
    let resolved: Option<Vec<SocketAddr>> = match target.as_ref() {
        TargetAddrRef::Ip(dst) => {
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                r2_refuse(None);
                r2_reject(cd, id, r2::R2_REJECT_POLICY);
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
                    arm_fast(fast, ss, conn_id, sess, r2::ip_ref(dst), used_dst, life);
                    Some(Vec::new())
                }
                None => {
                    r2_reject(cd, id, r2::R2_REJECT_TABLE_FULL);
                    return;
                }
            }
        }
        TargetAddrRef::Domain(host, port) => {
            match r2_forward_domain_open(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                state,
                id,
                sess,
                host,
                port,
                payload,
            )
            .await
            {
                Some(v) => Some(v),
                None => return,
            }
        }
    };
    let Some(resolved) = resolved else {
        return;
    };
    match r2_install(state, ss, sess, id, target, resolved) {
        Ok(_) => {
            r2_stats::bump(&r2_stats::OPENS);
            r2_send_ctl(
                cd,
                &Ctl::FlowAck {
                    id,
                    status: r2::R2_ACK_OPEN,
                },
            );
            r2_stats::bump(&r2_stats::ACKS);
        }
        Err(RegistryError::Full) => r2_reject(cd, id, r2::R2_REJECT_TABLE_FULL),
        Err(RegistryError::Conflict) => {
            r2_refuse(None);
            r2_reject(cd, id, r2::R2_REJECT_POLICY);
        }
    }
}

/// Route one decoded rev2 `DATA` frame (steady / open / inline).
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_data(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    d: Bytes,
) {
    let Ok(data) = r2::decode_data(&d) else {
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
    match (data.id, data.sess, target) {
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

/// Route one rev2 `TRAIN`: every item resolves through the connection registry
/// and is forwarded on its own; an item naming an unknown id is dropped and
/// counted, never guessed, and the rest of the frame continues.
#[allow(clippy::too_many_arguments)]
async fn r2_ingress_train(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    d: Bytes,
) {
    let Ok(train) = r2::decode_train(&d) else {
        r2_refuse(None);
        return;
    };
    for (wire_id, item) in train.items() {
        r2_stats::bump(&r2_stats::TRAIN_ITEMS);
        udp_stats::payload(item.len());
        let payload = d.slice_ref(item);
        let _ = r2_forward_flow_item(
            fast,
            ss,
            cd,
            conn_id,
            allow_private,
            staged,
            state,
            wire_id,
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
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    d: Bytes,
) {
    let Ok(frag) = r2::decode_frag(&d) else {
        r2_stats::bump(&r2_stats::FRAGS);
        r2_refuse(None);
        return;
    };
    r2_stats::bump(&r2_stats::FRAG_FRAMES);
    let Some(done) = r2_reasm.push(&frag, coarse_millis()) else {
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

/// Dispatch one rev2 DATAGRAM body.
///
/// The `HELLO` gate is applied here, before any frame can reach a target:
/// without a valid HELLO for this wire version a rev2 data frame is dropped and
/// counted ([`r2_stats::GATED`]), which is what keeps a "new server + old
/// client" deployment from exposing any unexpected path. Legacy v2/v3 frames
/// keep their own dispatch and are unaffected.
#[allow(clippy::too_many_arguments)]
async fn handle_r2_ingress(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    r2_reasm: &mut R2Reassembler,
    d: Bytes,
) {
    let Some(kind) = r2::kind(&d) else {
        return;
    };
    if kind == R2Kind::Ctl {
        // HELLO is the only control frame allowed before the gate opens.
        let is_hello = d.get(1).copied() == Some(r2::R2_CTL_HELLO);
        if !is_hello && !state.ctl.hello_seen() {
            r2_refuse(Some(&r2_stats::GATED));
            return;
        }
        r2_handle_ctl(ss, cd, state, r2_reasm, &d);
        return;
    }
    if !state.ctl.hello_seen() {
        r2_refuse(Some(&r2_stats::GATED));
        return;
    }
    match kind {
        R2Kind::Data => {
            r2_ingress_data(fast, ss, cd, conn_id, allow_private, staged, state, d).await;
        }
        R2Kind::Train => {
            r2_ingress_train(fast, ss, cd, conn_id, allow_private, staged, state, d).await;
        }
        R2Kind::Frag => {
            r2_ingress_frag(
                fast,
                ss,
                cd,
                conn_id,
                allow_private,
                staged,
                state,
                r2_reasm,
                d,
            )
            .await;
        }
        R2Kind::Ctl => unreachable!(),
    }
}

pub(crate) async fn handle_conn(
    conn: quinn::Connection,
    allow_private: bool,
    reply_filter: ReplyFilter,
    conn_limit: Arc<tokio::sync::Semaphore>,
    conn_cap: usize,
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
    // MQP-3 rev2 connection state (flow registry + HELLO/CAPS gate). Shared by
    // this handler, the datagram reader, the sweeper and every session reader.
    let r2_state = R2ConnState::new();
    {
        let sess = sess.clone();
        let conn = conn.clone();
        let r2_sweep = r2_state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        // Shard-by-shard sweep, abort after all locks drop. The
                        // rev2 bindings of every reaped session go with it, so a
                        // stale `wire_id` can only fail lookup afterwards.
                        let evicted = sess.sweep_all(now);
                        for entry in &evicted {
                            r2_close_entry_bindings(&r2_sweep, entry);
                        }
                        abort_evicted(evicted);
                    }
                    _ = conn.closed() => {
                        let drained = sess.drain_all();
                        for entry in &drained {
                            r2_close_entry_bindings(&r2_sweep, entry);
                        }
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
        let mut r2_reasm = R2Reassembler::new();
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
        // Sizing: 16 slots (~420 B each, on this task's heap future — the pin
        // buffer dominates) covers the shape a multi-association client actually
        // presents (DNS + a game + a handful of flows) and matches the
        // `RECENT_DST_CAP` the reply side already uses.
        //
        // **Probed, not direct-mapped.** Session ids come from the client's
        // monotonic counter and are never reused, so the live ids on a
        // long-lived connection are a *sparse* subset of the id space rather
        // than a dense interval: a raw `s & 15` maps two live sessions to the
        // same slot at random, and an earlier revision's "N <= 16 live ids land
        // on N distinct slots" was only true for consecutive ids. After churn
        // the chance all A live homes are distinct is `∏(16-i)/16` — ~50 % at
        // A=5, ~12 % at A=8 — so collisions were the *common* multi-association
        // case, and a colliding pair evicted each other on every arm and paid
        // the whole slow path (an unbatched `udp_try_send` per datagram, a
        // `remember_dst` shard read lock, an epoch bump) forever. With linear
        // probing any set of ≤ 16 live sessions finds a slot; only a genuinely
        // over-16-live table evicts the quietest, and a probe miss is never a
        // mis-route: every slot re-validates the exact session id, the reader's
        // liveness and the socket's liveness before it stages anything, and a
        // miss only means "run the slow path, which re-arms".
        //
        // The slot count stays a compromise rather than as large as possible:
        // every slot carries a 255-byte pin buffer for the domain-target
        // shortcut, and this table lives per *connection* (4096 admitted
        // connections would be ~27 MiB at this size).
        let mut fast: [Option<FastSess>; FAST_SESS_SLOTS] = [NO_FAST_SESS; FAST_SESS_SLOTS];
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
                // MQP-3 rev2 frames are dispatched before the MQP-2 kinds: their
                // first byte is `0x0X`, which no legacy decoder accepts (see
                // `r2::is_r2`), so the two dispatch orders can never claim the
                // same DATAGRAM. The gate inside drops rev2 data until HELLO.
                if r2::is_r2(&d) {
                    handle_r2_ingress(
                        &mut fast,
                        &ss,
                        &cd,
                        conn_id,
                        allow_private,
                        &mut staged,
                        &r2,
                        &mut r2_reasm,
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
                        arm_fast(&mut fast, &ss, conn_id, s, a.as_ref(), dst, life);
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
                                            arm_fast(
                                                &mut fast, &ss, conn_id, s, b.addr, dst2, life,
                                            );
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
                                        arm_fast(&mut fast, &ss, conn_id, s, b.addr, dst2, life);
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
                        arm_fast(&mut fast, &ss, conn_id, s, a, dst, life);
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
    // Admission is **two-stage**, and each stage has its own process-wide pool:
    // 1. a [`HEADER_TASK_CREDIT`] is taken before the spawn and released once
    //    the 5 s header read has returned (success or failure) — this is what
    //    bounds parked header tasks, which the transport's per-connection
    //    stream credit (8192 x admitted connections) does not;
    // 2. the share slot and [`MAX_STREAM_TASKS`] permit are taken *after* the
    //    header, inside `handle_tcp_stream`, and cover the dial plus the whole
    //    relay — so a trickling header cannot exhaust the stream pool and a
    //    long-lived flow cannot sit on header credit.
    // The stream-task pool is process-wide, and one connection may open
    // `MAX_BIDI_STREAMS_PER_CONN` (8192) streams — more than the whole pool — so
    // each connection also has to stay inside its own share of it. Without this,
    // the first two peers to arrive hold every permit while their flows sit idle
    // and every other client's CONNECT is reset after its SOCKS success
    // reply — with nothing logged server-side.
    let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
        tokio::spawn(handle_tcp_stream(
            send,
            recv,
            header_credit,
            streams_held.clone(),
            share,
            admitted,
            allow_private,
            stat_conn,
        ));
    }
    Ok(())
}
