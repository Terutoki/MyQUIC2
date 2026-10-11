//! UDP ASSOCIATE relay.
use super::*;

// ---- UDP ASSOCIATE: app <-> local relay <-> QUIC DATAGRAM ----
pub(crate) async fn handle_udp_associate(
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

/// Bind the UDP relay socket to the address BND will advertise, so every reply
/// is sent *from* the address the app was told to expect. A wildcard bind lets
/// the kernel pick the source by route to the app, which on a multi-homed host
/// (a second LAN, a VPN interface) can differ from the address the app
/// connected to; a source-validating app then drops every reply. The v4 form
/// goes in as its v4-mapped equivalent so the socket stays dual-stack for the
/// `map_for_dual` reply path; a bind failure (the peer-address fallback is not
/// a local address) degrades to the wildcard rather than failing the
/// association.
pub(crate) fn bind_relay(relay_ip: std::net::IpAddr) -> Result<tokio::net::UdpSocket> {
    let bind = map_for_dual(SocketAddr::new(relay_ip, 0)).to_string();
    let raw = match udp_socket_dual_small(&bind) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("udp relay bind {bind} failed ({e:#}); falling back to the wildcard");
            udp_socket_dual_small("[::]:0")?
        }
    };
    Ok(tokio::net::UdpSocket::from_std(raw)?)
}

/// Userspace receive buffer per association: one full-protocol-cap datagram
/// plus the worst-case SOCKS5 header in front of it and the
/// truncation-detection slack byte.
pub(crate) const ASSOC_RECV_BUF_LEN: usize = UDP_RECV_MAX + SOCKS_UDP_HDR_MAX + UDP_RECV_SLACK;

/// Compile-time userspace bound: one relay buffer per association, so the
/// live set can never exceed the assoc cap times it (~34 MiB worst case).
const _: () = assert!(ASSOC_RECV_BUF_LEN == UDP_RECV_MAX + SOCKS_UDP_HDR_MAX + UDP_RECV_SLACK);
const _: () = assert!(
    MAX_UDP_ASSOCS * ASSOC_RECV_BUF_LEN <= 40 * 1024 * 1024,
    "4032 x ~8.5 KiB must stay a bounded worst case"
);

/// Idle association buffers retained per worker thread. Same contract as the
/// server's `SESS_BUF_POOL`: the live set is bounded by `MAX_UDP_ASSOCS`, only
/// moved-not-shared byte buffers are pooled (never sockets, hub slots or
/// tasks), and past this depth buffers drop as before.
pub(crate) const ASSOC_BUF_POOL_DEPTH: usize = 8;

thread_local! {
    static ASSOC_BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

pub(crate) fn assoc_recv_buf() -> Vec<u8> {
    ASSOC_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        while let Some(buf) = p.pop() {
            if buf.len() == ASSOC_RECV_BUF_LEN {
                return buf;
            }
        }
        vec![0u8; ASSOC_RECV_BUF_LEN]
    })
}

pub(crate) fn assoc_recycle_buf(buf: Vec<u8>) {
    if buf.len() != ASSOC_RECV_BUF_LEN {
        return;
    }
    ASSOC_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < ASSOC_BUF_POOL_DEPTH {
            p.push(buf);
        }
    })
}

#[cfg(test)]
pub(crate) fn assoc_buf_pool_len() -> usize {
    ASSOC_BUF_POOL.with(|p| p.borrow().len())
}

pub(crate) async fn udp_associate_inner(
    mut tcp: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
    sess: u32,
) -> Result<()> {
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
    let relay = bind_relay(relay_ip)?;
    let relay_port = relay.local_addr()?.port();
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
    // Pooled (see `assoc_recv_buf`): same length, so that check is unchanged.
    let mut buf = assoc_recv_buf();
    // One id counter per association: `(sess, id)` is the receiver's key.
    let mut frag = DgramFragmenter::new();
    // Fixed-schedule interval (not a re-armed sleep): TCP control chatter must
    // not reset the idle timer and keep an otherwise dead association alive.
    //
    // The jitter phase is baked into the interval's **first deadline**, never
    // slept off before this loop. The sleep used to run after the SOCKS reply
    // had already told the app the relay was ready, so the app's first
    // datagram — a DNS query, a STUN binding, a game handshake: the most
    // latency-sensitive one — sat unread in the relay socket while the
    // association was not even polling. `jitter_ms()` is bounded to 0..=199,
    // so that was up to ~200 ms of pure added latency per association
    // (1.4x a 140 ms RTT). `interval_at` keeps the same desynchronized tick
    // schedule and starts serving the relay socket immediately.
    let phase_ms = jitter_ms(); // 0..=199; desynchronizes the 30 s tick phase
    let mut idle_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_millis(phase_ms),
        Duration::from_secs(ASSOC_IDLE_TICK_SECS),
    );
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Local copy of the last published app address: the value almost never
    // changes (one UDP socket per association), so only publish on change
    // instead of storing per packet.
    let mut published_app: Option<SocketAddr> = None;
    // Egress class, fixed by the first datagram that reaches the send path and
    // kept for the association's life (see [`EgressClass`]); until then every
    // datagram would classify from itself, which cannot happen because the
    // first send classifies before it goes out.
    let mut class: Option<EgressClass> = None;
    // Opportunistic 2-pack buffer: one owned small payload held across drain
    // iterations so two consecutive same-destination small datagrams go out as
    // a single BATCH frame (one quinn lock + one AEAD instead of two). Never
    // waits: flushed at burst end or when the next datagram does not match,
    // so no added latency, only saved work.
    let mut batch_pending: Option<(EgressClass, TargetAddr, Vec<u8>)> = None;
    'assoc: loop {
        tokio::select! {
            r = relay.recv_from(&mut buf) => {
                // Bounded ingress drain: the awaited head plus up to
                // `LAST_HOP_DRAIN - 1` more, so one readiness event moves up
                // to 32 app datagrams instead of one wakeup per datagram. On
                // Linux the extras come from one `recvmmsg` burst per refill;
                // a kernel without it keeps the per-frame `try_recv_from` arm.
                // Tokio keeps readiness set until a `WouldBlock`, so the
                // remainder is picked up on the next poll; nothing queues in
                // userspace (no HOL). `continue` below advances the drain —
                // the same packet-skip as before; only the head error ends
                // the association.
                let mut pending = match r {
                    Ok(x) => Some(x),
                    // A transient socket error must end this association only;
                    // the wrapper still removes the hub subscription.
                    Err(_) => break 'assoc,
                };
                let mut drained = 0usize;
                // recvmmsg burst state (Linux): `burst_i < burst_n` consumes
                // staged datagrams; otherwise one refill syscall covers the
                // remaining per-wakeup budget. Both counters stay 0 on the
                // portable path, where the `try_recv_from` arm below runs.
                let mut burst_n = 0usize;
                let mut burst_i = 0usize;
                for _ in 0..LAST_HOP_DRAIN {
                    let (n, app) = match pending.take() {
                        Some(x) => x,
                        None if burst_i < burst_n => {
                            let i = burst_i;
                            burst_i += 1;
                            match burst_msg_copy(i, &mut buf) {
                                Some(x) => x,
                                None => break,
                            }
                        }
                        None => match recv_burst(&relay, LAST_HOP_DRAIN - drained) {
                            Some(0) => break,
                            Some(k) => {
                                burst_n = k;
                                burst_i = 1;
                                match burst_msg_copy(0, &mut buf) {
                                    Some(x) => x,
                                    None => break,
                                }
                            }
                            None => match relay.try_recv_from(&mut buf) {
                                Ok(x) => x,
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                // A drained-packet error ends the burst, not the
                                // association: the head already proved the socket
                                // live this poll.
                                Err(_) => break,
                            },
                        },
                    };
                    drained += 1;
                if n == buf.len() {
                    // The kernel truncates a datagram larger than the buffer and
                    // reports only the buffer length, so the excess is already
                    // gone. Counted as oversized (the payload is past the
                    // protocol cap by construction) as well as warned — and the
                    // warning is rate-limited like every other drop: the app
                    // chooses this rate, and an unthrottled `warn!` here put a
                    // formatted line through tracing's process-wide writer lock
                    // once per datagram.
                    let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                    dgram_drops::warn_oversize_recv(
                        dgram_drops::OversizeRecv::AppDatagram,
                        dropped,
                        || format!("; association {sess}, {} B buffer", buf.len()),
                    );
                    continue;
                }
                // Pin the source IP: any host that can reach the relay port
                // could otherwise become "the app" and steal all replies.
                if let Some(expected) = expected_app_ip
                    && unmap(app.ip()) != expected {
                        tracing::debug!("udp assoc {sess}: datagram from unauthorized app {app} ignored");
                        continue;
                    }
                // The coarse epoch: this value feeds the 1 s liveness throttle
                // and the egress memo's 1 s freshness window, and both are whole
                // seconds. `mono_millis()` here was a vDSO `clock_gettime` on
                // every app datagram — the same cost the reply path already had
                // removed for the same reason (see `AssocEntry::replied`).
                let now = coarse_millis();
                // Validate the SOCKS5 UDP framing *before* letting this packet
                // claim the association. The relay port is reachable by any
                // process on the control connection's IP, so locking on the first
                // packet from any source let one unsolicited or malformed
                // datagram — a single stray byte suffices — pin `entry.app` to
                // the sender permanently: replies then went to that sender, the
                // legitimate app's datagrams were dropped as a "changed source",
                // and because dropped packets deliberately do not touch the
                // liveness stamp the association also starved to death at 180 s.
                // Only a well-formed RSV/FRAG + address frame may lock.
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
                if published_app != Some(app) {
                    // Lock to the first app address: IP-only pinning would let a
                    // different socket on the same host (same IP, another port)
                    // take over the association and steal its replies. A
                    // legitimate client uses one UDP socket per association, so
                    // its source never changes; a changed source is a hijack
                    // attempt, not a rebinding, and is ignored instead of
                    // published — before the liveness stamp below, so dropped
                    // packets cannot keep a dead association alive.
                    if let Some(first) = published_app {
                        tracing::debug!(
                            "udp assoc {sess}: datagram from {app} ignored (locked to {first})"
                        );
                        continue;
                    }
                    entry.app.store(Some(Arc::new(app)));
                    published_app = Some(app);
                }
                if now.saturating_sub(activity_stamp) >= ASSOC_TOUCH_INTERVAL_MS {
                    activity_stamp = now;
                    entry.touch(now);
                }
                // Shared egress: the common case is a thread-local memo hit
                // (one generation load, zero Arc RMWs and zero quinn locks);
                // the lock path runs only on a generation change or once the
                // memo's stamp expires, and the single-flight winner still
                // pays close_reason/max_datagram_size at most once per refresh
                // window. Stale handles are reused optimistically behind one
                // cheap `close_reason` gate: a dead one is invalidated and
                // counted as NO_EGRESS instead of being sent.
                //
                // `limit` is the connection's live `max_datagram_size()`: the
                // real DATAGRAM budget for the discovered path MTU, with the
                // QUIC overhead already subtracted. It is deliberately NOT
                // clamped — a hard cap here is really a *payload* cap, and the
                // old `min(1350)` made every UDP payload above 1338 B vanish on
                // a 1472 B path (see `dgram_payload_cap`). Payloads past a single
                // frame are split by the fragmenter rather than dropped.
                // A first datagram may not be classified yet (an earlier one may
                // have failed framing validation); the send path pins it.
                let class = *class.get_or_insert_with(|| {
                    let c = pool.udp_class(&addr, payload.len());
                    tracing::debug!(
                        "udp assoc {sess}: egress class {} (first payload {} B)",
                        c.name(),
                        payload.len()
                    );
                    c
                });
                let sent = match egress_shared.with_fresh(class, now, |c, limit| {
                    {
                        if payload.len() <= BATCH_SMALL_MAX {
                            if let Some((pc, pa, pp)) = batch_pending.take() {
                                if pc == class && pa.as_ref() == addr {
                                    let pair: [&[u8]; 2] = [&pp, payload];
                                    match send_udp_batch(c, sess, &addr, &pair, limit) {
                                        DatagramSend::Sent => {
                                            return PayloadSend {
                                                frames: 1,
                                                failed: None,
                                            };
                                        }
                                        DatagramSend::TooLarge | DatagramSend::Blocked => {
                                            let s1 =
                                                frag.send(c, sess, &pa.as_ref(), &pp, limit);
                                            if s1.failed.is_some() {
                                                let s2 =
                                                    frag.send(c, sess, &addr, payload, limit);
                                                return prefer_severe(s1, s2);
                                            }
                                            return frag.send(c, sess, &addr, payload, limit);
                                        }
                                        other => {
                                            return PayloadSend {
                                                frames: 0,
                                                failed: Some(other),
                                            };
                                        }
                                    }
                                }
                                let pa_ref = pa.as_ref();
                                let s1 = frag.send(c, sess, &pa_ref, &pp, limit);
                                if s1.failed.is_some() {
                                    let s2 = frag.send(c, sess, &addr, payload, limit);
                                    return prefer_severe(s1, s2);
                                }
                            }
                            if payload.len() <= BATCH_SMALL_MAX {
                                batch_pending = Some((class, addr.into_owned(), payload.to_vec()));
                                return PayloadSend {
                                    frames: 1,
                                    failed: None,
                                };
                            }
                        } else if let Some((_, pa, pp)) = batch_pending.take() {
                            let pa_ref = pa.as_ref();
                            let s1 = frag.send(c, sess, &pa_ref, &pp, limit);
                            if s1.failed.is_some() {
                                let s2 = frag.send(c, sess, &addr, payload, limit);
                                return prefer_severe(s1, s2);
                            }
                        }
                    }
                    frag.send(c, sess, &addr, payload, limit)
                }) {
                    Some(s) => s,
                    None => {
                        // Load the generation *before* the cached read: any
                        // mutation concurrent with `acquire` then bumps past
                        // this tag, so the memo below is never served for a
                        // value the mutation replaced.
                        let generation = egress_shared.generation[class.index()]
                            .load(std::sync::atomic::Ordering::Acquire);
                        match egress_shared.acquire(&pool, class, now) {
                            Some((conn, limit, stamp)) => {
                                egress_shared.memo_store(class, generation, &conn, limit, stamp);
                                frag.send(&conn, sess, &addr, payload, limit)
                            }
                            None => {
                                // No isolated egress connection right now: this
                                // class's dedicated UDP slot has not come up, is
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
                                            "; class={} udp_fail_closed={} udp_slot_live={} refresh_in_flight={}",
                                            class.name(),
                                            pool.udp_fail_closed(),
                                            pool.slot(pool.udp_slot(class)).is_live(),
                                            egress_shared.refreshing[class.index()]
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
                        egress_shared.refresh_budget(class);
                    }
                    DatagramSend::ConnectionLost => {
                        tracing::debug!("client egress stale, invalidating shared cache");
                        let n = dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
                        dgram_drops::warn_egress_drop(
                            dgram_drops::EgressDrop::ConnectionLost,
                            n,
                            || format!("; class={}, send outcome {outcome:?}, cached handle invalidated", class.name()),
                        );
                        egress_shared.invalidate(class);
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
                if let Some((pc, pa, pp)) = batch_pending.take() {
                    let now_flush = coarse_millis();
                    let flushed = egress_shared.with_fresh(pc, now_flush, |c, limit| {
                        frag.send(c, sess, &pa.as_ref(), &pp, limit)
                    });
                    if flushed.is_none() {
                        batch_pending = Some((pc, pa, pp));
                    }
                }
                record_drain_batch(drained);
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
                    break 'assoc;
                }
            }
            _ = idle_tick.tick() => {
                // Both directions count, but only one of them reads a clock: the
                // relay loop stamps `last` for app-side traffic, and this tick
                // folds the dispatcher's `replied` flag in for the reply side, so
                // a receive-only flow is not reaped out from under the app and
                // the per-reply path stays clock-free.
                if entry.idle_since_tick(mono_millis(), ASSOC_IDLE_MS) {
                    break 'assoc;
                }
            }
        }
    }
    // Every exit above breaks to here, so the buffer is recycled exactly once
    // per association lifetime, however it ended (idle reap, control close,
    // socket error). A held 2-pack payload never reached the wire: count it so
    // the exit cannot create invisible loss (one datagram, worst case).
    if batch_pending.is_some() {
        dgram_drops::bump(&dgram_drops::NO_EGRESS);
    }
    assoc_recycle_buf(buf);
    Ok(())
}

/// Pick the outcome the caller must react to when two single sends were both
/// attempted (batch fallback, pending flush): a dead connection outranks a
/// size/backpressure verdict, so the egress cache is invalidated rather than
/// merely refreshed. Both sends already did their own drop accounting; this
/// only decides which verdict drives the shared recovery.
fn prefer_severe(first: PayloadSend, second: PayloadSend) -> PayloadSend {
    fn rank(failed: Option<DatagramSend>) -> u8 {
        match failed {
            None | Some(DatagramSend::Sent) => 0,
            Some(DatagramSend::Blocked) | Some(DatagramSend::TooLarge) => 1,
            Some(DatagramSend::Unsupported) => 2,
            Some(DatagramSend::ConnectionLost) => 3,
        }
    }
    if rank(second.failed) > rank(first.failed) {
        second
    } else {
        first
    }
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
pub(crate) fn send_reply(
    entry: &AssocEntry,
    dst: SocketAddr,
    payload: &Bytes,
    pkt: &mut bytes::BytesMut,
) {
    let Some(app) = entry.app() else {
        udp_write::no_app();
        return;
    };
    send_reply_addr(entry, app, dst, payload, pkt);
}

pub(crate) fn send_reply_addr(
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
    encode_reply(pkt, dst, payload);
    udp_try_send_slice(&entry.relay, map_for_dual(app), &pkt[..]);
}

/// Encode one SOCKS5 UDP reply frame (RSV/FRAG + source address + payload).
///
/// Split out of [`send_reply_addr`] so the dispatcher's grouped flush shares
/// the single encoder: one wire format, no drift between the immediate and
/// the batched path. Generic over `BufMut` so both the `BytesMut` scratch
/// and the flush arena use it.
pub(crate) fn encode_reply<B: bytes::BufMut>(pkt: &mut B, dst: SocketAddr, payload: &[u8]) {
    encode_reply_header(pkt, dst);
    pkt.put_slice(payload);
}

/// The SOCKS5 UDP reply header alone: `RSV | FRAG | ATYP | ADDR | PORT`.
///
/// Split out of [`encode_reply`] so the grouped flush can stage **just the
/// header** (≤ 22 B) and hand the payload to `sendmmsg` as a second iovec,
/// instead of concatenating both into a staging arena — which copied every
/// reply payload end to end on the download path.
pub(crate) fn encode_reply_header<B: bytes::BufMut>(pkt: &mut B, dst: SocketAddr) {
    pkt.put_slice(&[0, 0, 0]);
    // The destination of a reply is always the source address the server
    // reported, which is IP-form; encode it straight into the caller's buffer.
    match dst {
        SocketAddr::V4(a) => {
            pkt.put_slice(&[0x01]);
            pkt.put_slice(&a.ip().octets());
            pkt.put_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            pkt.put_slice(&[0x04]);
            pkt.put_slice(&a.ip().octets());
            pkt.put_slice(&a.port().to_be_bytes());
        }
    }
}
