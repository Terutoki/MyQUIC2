//! Per-session UDP reader and session creation.
use super::*;

/// Userspace receive buffer per session reader: one full-protocol-cap datagram
/// plus the truncation-detection slack byte (`n == buf.len()` means the kernel
/// truncated, so the length is load-bearing).
pub(crate) const SESS_RECV_BUF_LEN: usize = UDP_RECV_MAX + UDP_RECV_SLACK;

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
pub(crate) const SESS_BUF_POOL_DEPTH: usize = 8;

thread_local! {
    static SESS_BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Take a session-reader buffer, recycled when one is idle.
pub(crate) fn sess_recv_buf() -> Vec<u8> {
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
pub(crate) fn sess_recycle_buf(buf: Vec<u8>) {
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

/// Minimum gap between live DATAGRAM-budget re-reads after a `TooLarge` send
/// verdict on this reader task. Mirrors the client's
/// `BUDGET_PROBE_INTERVAL_MS` (100 ms): without it a PMTU shrink costs one
/// quinn connection-state lock per oversized reply for the whole window, i.e.
/// a re-probe storm on exactly the mutex the steady path takes once per frame.
/// Inside the window the reader keeps the last known budget and the datagram
/// is dropped with size accounting (UDP semantics).
pub(crate) const READER_BUDGET_PROBE_INTERVAL_MS: u64 = 100;

/// Whether a `TooLarge` verdict may re-read the live budget now. Pure so the
/// throttle is testable without a live connection; `now_ms` is the
/// [`mono_millis`] epoch. Zero means never probed: the mono epoch counts from
/// process start, so a small `now` must not read as "probed 0 ms ago".
pub(crate) fn too_large_probe_due(last_probe_ms: u64, now_ms: u64) -> bool {
    last_probe_ms == 0 || now_ms.saturating_sub(last_probe_ms) >= READER_BUDGET_PROBE_INTERVAL_MS
}

#[cfg(test)]
pub(crate) fn sess_buf_pool_len() -> usize {
    SESS_BUF_POOL.with(|p| p.borrow().len())
}

pub(crate) async fn sess_reader_task(
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
    // Last live-budget re-read caused by a `TooLarge` verdict (mono epoch, 0 =
    // never). Gates the re-probe so a PMTU shrink cannot cost one quinn lock
    // per oversized reply; see `READER_BUDGET_PROBE_INTERVAL_MS`.
    let mut last_too_large_probe_ms = 0u64;
    'session: loop {
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
        // Bounded reply drain (mirrors the client relay loops): the awaited
        // head plus up to `LAST_HOP_DRAIN - 1` more, so one wakeup moves up
        // to 32 replies instead of one reply per wakeup. On Linux the extras
        // come from one `recvmmsg` burst per refill; a kernel without it keeps
        // the per-frame `try_recv_from` arm. Tokio keeps recv readiness set
        // until a `WouldBlock`, so the remainder is picked up on the next
        // poll; nothing queues in userspace. Every drained datagram runs the
        // same body as the head (truncation check, allowlist, fragmenter
        // send). A drained error ends the burst, not the session: the head
        // already proved the socket live this poll.
        let mut drained = 1usize;
        let mut pending: Option<(usize, SocketAddr)> = Some((n, src));
        // recvmmsg burst state (Linux): `burst_i < burst_n` consumes staged
        // datagrams; otherwise one refill syscall covers the remaining
        // per-wakeup budget. Both counters stay 0 on the portable path, where
        // the `try_recv_from` arm below runs.
        let mut burst_n = 0usize;
        let mut burst_i = 0usize;
        loop {
            let (n, src) = match pending.take() {
                Some(x) => x,
                None if burst_i < burst_n => {
                    let i = burst_i;
                    burst_i += 1;
                    match burst_msg_copy(i, &mut buf) {
                        Some(x) => {
                            drained += 1;
                            x
                        }
                        None => break,
                    }
                }
                None => {
                    if drained >= LAST_HOP_DRAIN {
                        break;
                    }
                    match recv_burst(&rs, LAST_HOP_DRAIN - drained) {
                        Some(0) => break,
                        Some(k) => {
                            burst_n = k;
                            burst_i = 1;
                            match burst_msg_copy(0, &mut buf) {
                                Some(x) => {
                                    drained += 1;
                                    x
                                }
                                None => break,
                            }
                        }
                        None => match rs.try_recv_from(&mut buf) {
                            Ok(x) => {
                                drained += 1;
                                x
                            }
                            Err(_) => break,
                        },
                    }
                }
            };
            // N=1 CONTRACT (server reply path): a datagram sent through the cached
            // `limit` pays exactly one quinn take per frame — the
            // `SendDatagram::poll` lock inside `try_send_datagram`. Auxiliary takes
            // are all throttled off this path: the 60 s idle tick re-reads the
            // budget at most once per tick, active sessions refresh PMTU at most
            // once per 10 s, `TooLarge` re-probes at most once per
            // `READER_BUDGET_PROBE_INTERVAL_MS`, and `Unsupported`/`ConnectionLost`
            // break the reader instead of re-acquiring (DATAGRAM support is
            // negotiated at the handshake, so a re-check could never find a better
            // budget — only spend another take per datagram).
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
                    None => break 'session,
                }
            }
            if n == buf.len() {
                // Rate-limited, exactly like every other drop on this path: the
                // rate is chosen by the *target* (any reply above the protocol
                // cap), and an unthrottled `warn!` here put a formatted line
                // through tracing's process-wide writer lock once per packet.
                let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                dgram_drops::warn_oversize_recv(
                    dgram_drops::OversizeRecv::TargetReply,
                    dropped,
                    || format!("; session {s}"),
                );
                continue;
            }
            if limit == 0 {
                break 'session;
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
                    // Size verdict, never a connection fault: keep the reader and
                    // the cached budget, re-reading the live budget at most once
                    // per probe interval. Unthrottled, every oversized reply in a
                    // PMTU-shrink window took quinn's connection-state lock on top
                    // of the one per-frame take the send itself already paid.
                    // `.max(1)`: the zero stamp means "never probed" (see
                    // `too_large_probe_due`), and the mono epoch counts from
                    // process start, so a verdict inside the first millisecond
                    // must still arm the throttle.
                    let now_probe = mono_millis().max(1);
                    if too_large_probe_due(last_too_large_probe_ms, now_probe) {
                        last_too_large_probe_ms = now_probe;
                        limit = c2.max_datagram_size().unwrap_or(0);
                    }
                }
                DatagramSend::Unsupported | DatagramSend::ConnectionLost => break 'session,
            }
        }
        record_drain_batch(drained);
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

pub(crate) async fn get_or_create_sess(
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
    if ss.len_upper_bound(now) >= fair_cap {
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
