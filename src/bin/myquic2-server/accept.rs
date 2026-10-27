//! Admission limits: connection/dial/stream caps and the per-connection handler.
use super::*;
use futures_util::future::FutureExt as _;
use myquic2::mqp::r2::{self, Caps, Ctl, R2Kind};
use myquic2::mqp::r2_flow::{
    CtlState, FlowBinding, FlowIds, FlowRegistry, FlowState, R2_MAX_RESOLVED_ADDRS, RegistryError,
    SessionFlows,
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

/// Per-connection fast-path slots, linearly probed on the session id.
///
/// See the note at the declaration site in [`handle_conn`] for why this is a
/// table and not the single `(session, dst)` pair it used to be; the sizing
/// argument is there too. 64 is the documented "hundreds of associations per
/// connection" shape rounded to the probing table's power of two, and is
/// charged to admission by `R2_INGRESS_FIXED_BYTES`.
pub(crate) const FAST_SESS_SLOTS: usize = 64;
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
/// chance all homes are distinct is `∏(N-i)/N`; at N=64 it stays above 60 %
/// through A=8 (16 slots were already down to ~12 % there), which is why the
/// table was widened.
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
/// empty slot from home, else the least-recently-active slot when all
/// [`FAST_SESS_SLOTS`] are taken.
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
pub(crate) mod r2_stats {
    use crate::coarse_millis;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Rev2 data/control frames accepted into the pre-HELLO buffer.
    pub(crate) static PRE_HELLO_BUFFERED: AtomicU64 = AtomicU64::new(0);
    /// Pre-HELLO frames dropped because the bounded buffer was full.
    pub(crate) static PRE_HELLO_DROPPED: AtomicU64 = AtomicU64::new(0);
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

    /// Flush this thread's pending batched reply-frame counts into the shared
    /// statics.
    fn flush_locals() {
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
    #[inline]
    fn bump_reply(
        local: &'static std::thread::LocalKey<std::cell::Cell<u64>>,
        global: &'static AtomicU64,
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
            let now = coarse_millis();
            let last = c.get();
            if now.saturating_sub(last) >= FLUSH_PER_FRAME_MS {
                c.set(now);
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
    #[inline]
    pub(crate) fn bump_steady_sent() {
        bump_reply(&L_STEADY_SENT, &STEADY_SENT);
    }

    /// One downlink `OPEN|SRC` binding frame handed to quinn.
    #[inline]
    pub(crate) fn bump_open_src_sent() {
        bump_reply(&L_OPEN_SRC_SENT, &OPEN_SRC_SENT);
    }

    /// Flush this thread's pending reply-frame counts into the shared statics.
    ///
    /// The batched counters are documented with the same bounded-visibility
    /// model as `udp_stats`: a reporter or a test that reads them on the
    /// counting thread calls this first to see its own records exactly. (A
    /// pending count on another thread becomes visible at its next flush
    /// threshold.)
    pub(crate) fn flush_thread() {
        flush_locals();
    }

    /// One TRAIN item accepted for the data plane.
    ///
    /// Per item (not per frame): up to 64 per datagram, making this the one
    /// r2_stats line that sits on the packet path. Batched like
    /// `udp_stats::payload` with a 256-cell flush; `TRAIN_ITEMS` has no
    /// cross-thread reader (the 60 s report reads only the frames-sent family),
    /// so the bounded visibility is invisible in practice.
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
/// - [`CtlState`] carries the `HELLO`/`CAPS` version gate: rev2 data frames
///   that beat the HELLO are buffered (bounded) and flushed once a valid HELLO
///   for this wire version opens the gate; overflow is counted and dropped.
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
    /// Rev2 frames that arrived before a valid `HELLO` (data **and** control,
    /// e.g. `SESS_CLOSE`). The client may send its first UDP payload
    /// optimistically (no `CAPS` wait), so the server buffers those frames
    /// until the version gate opens, then dispatches them in arrival order.
    /// Bounded to keep a connection flood from pinning memory; overflow is
    /// counted and dropped.
    pre_hello: parking_lot::Mutex<(Vec<Bytes>, usize)>,
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
}

/// Bounds for [`R2ConnState::pre_hello`]: only the first optimistic frames
/// need to survive the HELLO round trip. A larger burst is dropped and counted
/// rather than buffered (the handshake completes in one RTT on any live path).
pub(crate) const PRE_HELLO_MAX_FRAMES: usize = 8;
pub(crate) const PRE_HELLO_MAX_BYTES: usize = 16 * 1024;

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
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(FlowRegistry::new(
                myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_CONN,
            )),
            ids: FlowIds::new(true),
            ctl: Arc::new(CtlState::new()),
            stage: Arc::new(parking_lot::Mutex::new(R2Stager::new())),
            last_caps_ms: std::sync::atomic::AtomicU64::new(0),
            pre_hello: parking_lot::Mutex::new((Vec::new(), 0)),
            pending_dns_opens: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_dns_bytes: std::sync::atomic::AtomicUsize::new(0),
            dns_waiters: parking_lot::Mutex::new(std::collections::HashMap::new()),
        })
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

    /// Buffer one pre-HELLO frame; `false` means the buffer is full and the
    /// caller must count/drop it.
    fn buffer_pre_hello(&self, d: Bytes) -> bool {
        let mut q = self.pre_hello.lock();
        let (frames, bytes) = &mut *q;
        if frames.len() >= PRE_HELLO_MAX_FRAMES
            || bytes.saturating_add(d.len()) > PRE_HELLO_MAX_BYTES
        {
            return false;
        }
        *bytes += d.len();
        frames.push(d);
        r2_stats::bump(&r2_stats::PRE_HELLO_BUFFERED);
        true
    }

    /// Take the buffered pre-HELLO frames after a valid HELLO opened the gate.
    fn take_pre_hello(&self) -> Vec<Bytes> {
        let mut q = self.pre_hello.lock();
        let frames = std::mem::take(&mut q.0);
        q.1 = 0;
        frames
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
pub(crate) fn r2_send_sess_close(cd: &quinn::Connection, sess: u32) {
    let frame = r2::encode_ctl(&Ctl::SessClose { sess, reason: 0 });
    for _ in 0..3 {
        if try_send_datagram(cd, frame.clone()) != DatagramSend::Sent {
            return;
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
pub(crate) fn spawn_sess_close_notifications(cd: quinn::Connection, sessions: Vec<u32>) {
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
                r2_send_sess_close(&cd, sess);
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

fn r2_reject(cd: &quinn::Connection, id: u32, reason: u8) {
    r2_stats::bump(&r2_stats::REJECTS);
    r2_send_ctl(cd, &Ctl::FlowReject { id, reason });
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
    let binding = state.registry.get(wire_id);
    r2_forward_flow_resolved(
        fast,
        ss,
        cd,
        conn_id,
        allow_private,
        staged,
        state,
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
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    allow_private: bool,
    staged: &mut Vec<StagedSend>,
    state: &Arc<R2ConnState>,
    binding: Option<&Arc<FlowBinding>>,
    payload: Bytes,
) -> bool {
    let Some(binding) = binding.filter(|b| b.state() != FlowState::Closed) else {
        // The id was closed (FLOW_CLOSE / session teardown) or never lived: a
        // late frame must fail lookup, never be re-routed.
        r2_refuse(Some(&r2_stats::UNKNOWN_ID));
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
                arm_fast(fast, ss, conn_id, sess, aref, used_dst, life);
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
/// DNS is the only potentially seconds-long await on the ingress path (up to
/// `DNS_LOOKUP_TIMEOUT`), so the reader spawns this task with owned data and
/// keeps routing other datagrams. The task owns everything it touches:
/// resolution + SSRF filtering, session creation (which may await a session
/// permit), the target send, and the idempotent install + `FLOW_ACK`.
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
            dgram_drops::bump(&dgram_drops::DNS_BUDGET);
            r2_reject(&cd, id, r2::R2_REJECT_DNS);
            return;
        }
    };
    let addrs = match resolve_all_cached(&host, port).await {
        Ok(v) => v,
        Err(_) => {
            r2_refuse(None);
            r2_reject(&cd, id, r2::R2_REJECT_DNS);
            return;
        }
    };
    let usable = policy_resolved(&addrs, allow_private);
    if usable.is_empty() {
        // Every record was rejected by the SSRF policy.
        r2_refuse(None);
        r2_reject(&cd, id, r2::R2_REJECT_POLICY);
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
            // association.
            r2_reject(&cd, id, r2::R2_REJECT_TABLE_FULL);
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
            r2_send_ctl(
                &cd,
                &Ctl::FlowAck {
                    id,
                    status: r2::R2_ACK_OPEN,
                },
            );
            r2_stats::bump(&r2_stats::ACKS);
        }
        Err(RegistryError::Full) => r2_reject(&cd, id, r2::R2_REJECT_TABLE_FULL),
        Err(RegistryError::Conflict) => {
            r2_refuse(None);
            r2_reject(&cd, id, r2::R2_REJECT_POLICY);
        }
    }
}

/// Handle one `DATA OPEN` (client-initiated flow: the address is the target).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn r2_ingress_open(
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
        r2_reject(cd, id, r2::R2_REJECT_POLICY);
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
            let host = host.to_owned();
            match state.begin_pending_open(sess, id, &target) {
                PendingOpen::Duplicate => {
                    // The first OPEN for this id is already resolving. This
                    // frame's payload is distinct application data, so buffer
                    // it behind the lookup (bounded) instead of losing it; the
                    // task forwards the queued payloads in order after the
                    // resolution. A full/closed queue drops it as the old path
                    // always did, and `NotPending` means the lookup just
                    // finished: forward on the ordinary path. A duplicate that
                    // names a different target is the registry's conflict case
                    // moved into the DNS window: refuse it, never queue it for
                    // the in-flight target's destination.
                    match state.queue_pending_open_payload(sess, id, &target.as_ref(), &payload) {
                        PendingPayload::Queued => {}
                        PendingPayload::Full | PendingPayload::Cancelled => {
                            r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
                        }
                        PendingPayload::Conflict => {
                            r2_refuse(None);
                            r2_reject(cd, id, r2::R2_REJECT_POLICY);
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
                    // This is a *per-connection* resource refusal (16 in-flight
                    // OPENs), never DNS-budget exhaustion: charging it to
                    // `DNS_BUDGET` made the 60 s report claim the process-wide
                    // resolver budget was drained while the share cap was the
                    // actual gate. REFUSED is the correct policy-drop class,
                    // plus the per-connection pending-open counter.
                    r2_refuse(Some(&r2_stats::DNS_OPEN_DROPS));
                    r2_reject(cd, id, r2::R2_REJECT_DNS);
                    return;
                }
                PendingOpen::Started(pending) => {
                    // Owned task: the datagram loop must not await DNS. The
                    // task performs the same forward-then-install sequence and
                    // sends its own ACK/reject.
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
    for (slot_index, (_wire_id, item)) in train.items().enumerate() {
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
    let Some(done) = r2_reasm.push(&d, &frag, coarse_millis()) else {
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
/// Optimistic-first-packet contract: the client no longer waits for `CAPS`
/// before sending its first UDP payload. The version gate remains authoritative
/// — every rev2 frame except `HELLO` that arrives before a valid `HELLO` is
/// stashed in a bounded per-connection buffer and dispatched only once
/// `HELLO(wire_ver=2)` opens the gate; overflow is counted and dropped. This
/// keeps order for optimistic data plus an early `SESS_CLOSE`. A wrong-version
/// HELLO never opens the gate and therefore never releases the buffer. Legacy
/// v2/v3 frames keep their own dispatch and are unaffected.
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
        // HELLO is processed immediately; every other frame (data or control)
        // waits for it in the bounded buffer so optimistic sends keep their
        // order, including a fast SESS_CLOSE.
        let is_hello = d.get(1).copied() == Some(r2::R2_CTL_HELLO);
        if !is_hello && !state.ctl.hello_seen() {
            if state.buffer_pre_hello(d) {
                return;
            }
            r2_refuse(Some(&r2_stats::PRE_HELLO_DROPPED));
            return;
        }
        r2_handle_ctl(ss, cd, state, r2_reasm, &d);
        if state.ctl.hello_seen() {
            for frame in state.take_pre_hello() {
                r2_dispatch_frame(
                    fast,
                    ss,
                    cd,
                    conn_id,
                    allow_private,
                    staged,
                    state,
                    r2_reasm,
                    frame,
                )
                .await;
            }
        }
        return;
    }
    if !state.ctl.hello_seen() {
        if state.buffer_pre_hello(d) {
            return;
        }
        r2_refuse(Some(&r2_stats::PRE_HELLO_DROPPED));
        return;
    }
    r2_dispatch_frame(
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

/// Dispatch one already-version-gated rev2 data frame.
#[allow(clippy::too_many_arguments)]
async fn r2_dispatch_frame(
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
    match r2::kind(&d) {
        Some(R2Kind::Data) => {
            r2_ingress_data(fast, ss, cd, conn_id, allow_private, staged, state, d).await;
        }
        Some(R2Kind::Train) => {
            r2_ingress_train(fast, ss, cd, conn_id, allow_private, staged, state, d).await;
        }
        Some(R2Kind::Frag) => {
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
        Some(R2Kind::Ctl) => r2_handle_ctl(ss, cd, state, r2_reasm, &d),
        None => r2_refuse(None),
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
                        spawn_sess_close_notifications(conn.clone(), ids);
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
        // Sizing: 64 slots (~420 B each, on this task's heap future — the pin
        // buffer dominates). The multi-association shape this comment documents
        // ("hundreds of sessions") is beyond one heap array, but 64 covers the
        // DNS + game + handful-of-flows case with headroom and, unlike the old
        // 16, keeps a realistic number of simultaneous associations on the fast
        // path. Admission charges the array through `R2_INGRESS_FIXED_BYTES`;
        // the delivered figure is `FAST_SESS_SLOTS * 420 B ~= 26.25 KiB` per
        // connection.
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
                // same DATAGRAM. The gate inside buffers non-HELLO frames until HELLO.
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
        ));
    }
    Ok(())
}
