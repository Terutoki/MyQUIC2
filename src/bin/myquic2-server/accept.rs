//! Admission limits: connection/dial/stream caps and the per-connection handler.
use super::*;
use futures_util::future::FutureExt as _;

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

/// Per-connection fast-path slots, direct-mapped on the session id.
///
/// See the note at the declaration site in [`handle_conn`] for why this is a
/// table and not the single `(session, dst)` pair it used to be; the sizing
/// argument is there too.
pub(crate) const FAST_SESS_SLOTS: usize = 16;
// `fast_slot` masks instead of taking a modulo.
const _: () = assert!(FAST_SESS_SLOTS.is_power_of_two());

/// One session's steady-state entry in a connection's fast table.
///
/// Every field is exactly what the single-slot version kept, minus the ambiguity
/// of "which session is this about": the slot names its session, so a datagram
/// for any other session simply does not match and falls through.
pub(crate) struct FastSess {
    sess: u32,
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

pub(crate) fn fast_slot(s: u32) -> usize {
    (s as usize) & (FAST_SESS_SLOTS - 1)
}

/// Empty slot value for `[Option<FastSess>; _]` initialization.
pub(crate) const NO_FAST_SESS: Option<FastSess> = None;

/// Resolve one datagram's target: the session's own pin first (free), then the
/// session's destination memo, then the DNS cache.
///
/// A slot owned by a *different* session is never consulted — the pin is keyed
/// on `(session, name, port)` and answering another session's datagram from it
/// would be a silent mis-route. A slot miss resolves with a scratch slot, so
/// the memo/DNS answer is still used for this datagram; the slow path then
/// installs the slot (and its own pin) for the session that asked.
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
    // Scratch is only reached when this slot belongs to someone else; nothing
    // is ever armed into it.
    let mut scratch: Option<ConnPin> = None;
    let pin = match fast[fast_slot(s)].as_mut() {
        Some(slot) if slot.sess == s => &mut slot.pin,
        _ => &mut scratch,
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
    let Some(slot) = fast[fast_slot(s)].as_mut() else {
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
/// A `Stale`/`Miss` memo probe clears the slot instead: the session is gone or
/// invisible, and leaving the old entry in place would keep sending into it.
pub(crate) fn arm_fast(
    fast: &mut [Option<FastSess>; FAST_SESS_SLOTS],
    conn_id: usize,
    s: u32,
    a: TargetAddrRef<'_>,
    dst: SocketAddr,
    life: u64,
) {
    let idx = fast_slot(s);
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, abort, epoch) => {
            let mut pin = None;
            let (ph, pp) = target_name(a);
            pin_arm(&mut pin, s, ph, pp, dst, life);
            fast[idx] = Some(FastSess {
                sess: s,
                sock: Arc::downgrade(&sock),
                last,
                abort,
                epoch,
                pin,
                last_dst: None,
                allow: None,
            });
        }
        SessHit::Stale | SessHit::Miss => fast[idx] = None,
    }
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
        // Per-connection fast table, direct-mapped on the session id.
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
        // `RECENT_DST_CAP` the reply side already uses. Session ids come from the
        // client's monotonic counter, so N <= 16 live ids land on N distinct
        // slots; beyond that, pigeonhole says some pairs share a slot, and two
        // *hot* sessions that collide evict each other and therefore both fall
        // back to the slow path per datagram — the old shape, but only for the
        // colliding pair instead of for every pair. That residual is why the slot
        // count is a compromise rather than as large as possible: every slot
        // carries a 255-byte pin buffer for the domain-target shortcut, and this
        // table lives per *connection* (4096 admitted connections would be
        // ~27 MiB at this size). A collision is never a mis-route: every slot
        // re-validates the exact session id, the reader's liveness and the
        // socket's liveness before it stages anything.
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
                _ = reasm_tick.tick() => {
                    // Coarse epoch: every consumer here compares against
                    // `FRAG_TIMEOUT_MS` (2 s) or the 500 ms sweep throttle, so a
                    // 1 s-quantized sample of the same epoch is sufficient — and
                    // `mono_millis()` was a vDSO `clock_gettime` per *fragment*
                    // on the receive path. (`DgramFragmenter`'s 32-bit id-reuse
                    // guard keeps its precise clock: that one is a splice-safety
                    // bound, and it runs per fragmented payload, not per packet.
                    // It is a backstop now — a 32-bit space cannot wrap inside
                    // the window at any sustained rate.)
                    reasm.expire(coarse_millis());
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
                    let used =
                        forward_server_dgram(&ss, &cd, conn_id, s, a, payload, allow_private).await;
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
