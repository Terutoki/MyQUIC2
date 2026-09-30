//! Admission limits: connection/dial/stream caps and the per-connection handler.
use super::*;

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
pub(crate) fn admission_cap(conn_cap: usize, budget_mb: Option<u64>, per_conn_bytes: u64) -> usize {
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
        let refs: Vec<&[u8]> = staged[i..j].iter().map(|s| &s.payload[..]).collect();
        udp_try_send_grouped(&staged[i].sock, staged[i].dst, &refs);
        i = j;
    }
    staged.clear();
}

pub(crate) async fn handle_conn(
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
        //
        // N=1 NOTE: a fast-path hit takes zero quinn locks before the send —
        // no `close_reason`, no `max_datagram_size`. Liveness is the reader
        // task's `AbortHandle` (one atomic load) plus the socket `Weak`
        // upgrade, and the budget is the reader's cached `limit`. The send
        // itself then pays the single irreducible `SendDatagram::poll` take.
        // The slow path (`forward_server_dgram` → `get_or_create_sess`) takes
        // at most one `max_datagram_size` per new session (creation only, off
        // the memo), never per packet.
        let mut fast_sess: u32 = u32::MAX;
        // **Weak**, exactly like [`SessMemo::sock`], and for the same reason: a
        // strong handle here is a second owner of the session's socket, and it
        // outlives the session. The 180 s sweeper removes the table entry and
        // aborts the reply reader, which drops both of *their* handles — but a
        // strong `fast_sock` would keep the socket (and its 2 x 32 KiB kernel
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
        // SSRF verdict for the last fast-path destination (see
        // `fast_allow_cached`): steady single-target flows skip the
        // re-derivation after the first datagram, exactly like the allowlist
        // record above. Cleared wherever that mirror is.
        let mut fast_allow: Option<(u32, SocketAddr, bool)> = None;
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
                    reasm.expire(mono_millis());
                    continue;
                }
            };
            // Bounded drain (mirrors the client dispatcher): the awaited head
            // plus up to `LAST_HOP_DRAIN - 1` already-buffered datagrams via
            // `poll_once` (`read_datagram` is cancel-safe: a buffered datagram
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
                        match poll_once(reader.as_mut()) {
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
                                if !ab.is_finished()
                                    && fast_allow_cached(&mut fast_allow, allow_private, s, dst)
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
                                        staged.push(StagedSend {
                                            sock,
                                            dst: map_for_dual(dst),
                                            payload: whole.clone(),
                                        });
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
                    fast_allow = None;
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
                                fast_allow = None;
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
                                if !ab.is_finished()
                                    && fast_allow_cached(&mut fast_allow, allow_private, s, dst)
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
                                        staged.push(StagedSend {
                                            sock,
                                            dst: map_for_dual(dst),
                                            payload: d.slice(off..),
                                        });
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
                    fast_allow = None;
                    // See the fragment branch: flush staged sends before the slow
                    // path's immediate send to keep per-flow order.
                    flush_staged_sends(&mut staged);
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
                                fast_allow = None;
                            }
                        }
                    }
                }
            }
            flush_staged_sends(&mut staged);
            record_drain_batch(drained);
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
