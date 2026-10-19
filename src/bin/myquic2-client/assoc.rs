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
    // P3-6: bind from the address directly. The old shape formatted it to a
    // `String` and parsed it back inside the constructor — two allocations plus
    // the round trip on every association, for a value already in hand.
    let bind = map_for_dual(SocketAddr::new(relay_ip, 0));
    let raw = match udp_socket_dual_small_addr(bind) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("udp relay bind {bind} failed ({e:#}); falling back to the wildcard");
            // The dual-stack wildcard `"[::]:0"`, in address form.
            udp_socket_dual_small_addr(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                0,
            ))?
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
/// The recvmmsg scratch slot and the association buffer must stay the same
/// size: that is what makes the borrowed burst arm's truncation predicate
/// (`msg.len() >= ASSOC_RECV_BUF_LEN`) identical to the awaited head's
/// (`n == buf.len()`) and to the copy-out fallback's, so moving a datagram
/// between the two arms can never change whether it counts as oversized.
const _: () = assert!(BURST_SLOT == ASSOC_RECV_BUF_LEN);

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

/// Control action one processed app datagram asks the association's drain loop
/// to take.
///
/// The per-datagram body moved into [`AppDgramCtx::process`] so the recvmmsg
/// burst arm can run it while the payload is still in the borrowed scratch
/// buffer ([`with_burst_msg`]); an inline body could `continue`/`break 'assoc`
/// directly, but a call cannot, so it reports the action instead.
enum AppDgram {
    /// Drop this datagram (or it was forwarded) and keep draining.
    Continue,
    /// End the association's relay loop. No framing or liveness arm ends the
    /// whole association today — the awaited head's socket error, the only
    /// `break 'assoc`, stays outside the body — so this variant has no producer
    /// yet; it exists so a future fatal arm has an explicit action instead of
    /// silently swallowing it.
    #[allow(dead_code)]
    BreakAssoc,
}

/// Mutable association state the per-datagram body reads and writes, bundled so
/// the awaited head (`recv_from` into `buf`) and the zero-copy burst arm
/// ([`with_burst_msg`]) share exactly one body.
///
/// Borrowed for one drain burst only. [`AppDgramCtx::process`] takes the
/// message as a slice: the head's payload lives in `buf`, the burst's in the
/// thread-local `recvmmsg` scratch, and neither needs an owned copy before it
/// is encoded.
struct AppDgramCtx<'a> {
    sess: u32,
    pool: &'a ConnPool,
    egress_shared: &'a SharedEgress,
    entry: &'a AssocEntry,
    /// Pinned app source IP, from the SOCKS control connection's peer.
    expected_app_ip: Option<IpAddr>,
    published_app: &'a mut Option<SocketAddr>,
    activity_stamp: &'a mut u64,
    bind: &'a mut Option<UdpBind>,
    pending_buf: &'a mut Vec<u8>,
    pending_pack: &'a mut Option<PendingPack>,
    pending_addr: &'a mut TargetAddr,
    frag: &'a mut DgramFragmenter,
}

impl AppDgramCtx<'_> {
    /// Validate and forward one SOCKS5-framed app datagram.
    ///
    /// `msg` is the datagram exactly as received from the relay socket:
    /// `RSV | FRAG | ATYP | ADDR | PORT | payload`. Fully synchronous (no
    /// `.await` anywhere in here), so the caller may hold the burst-scratch
    /// borrow across the call.
    fn process(&mut self, msg: &[u8], app: SocketAddr) -> AppDgram {
        // Split the context into disjoint borrows once: the `with_fresh`
        // closure below mutates the staging state while `egress_shared` is
        // borrowed immutably, which this proves to the borrow checker. After
        // inlining it costs nothing.
        let pool = self.pool;
        let egress_shared = self.egress_shared;
        let entry = self.entry;
        let expected_app_ip = self.expected_app_ip;
        let sess = self.sess;
        let published_app = &mut *self.published_app;
        let activity_stamp = &mut *self.activity_stamp;
        let bind = &mut *self.bind;
        let pending_buf = &mut *self.pending_buf;
        let pending_pack = &mut *self.pending_pack;
        let pending_addr = &mut *self.pending_addr;
        let frag = &mut *self.frag;

        // The kernel truncates a datagram larger than the receive buffer and
        // reports only the buffer length, so the excess is already gone. Both
        // drain arms receive at most one full buffer, and the recvmmsg scratch
        // slot is the same size as the association buffer (the const assert
        // above), so `>= ASSOC_RECV_BUF_LEN` is exactly the old
        // `n == buf.len()` predicate. Counted as oversized (the payload is past
        // the protocol cap by construction) as well as warned — and the warning
        // is rate-limited like every other drop: the app chooses this rate, and
        // an unthrottled `warn!` here put a formatted line through tracing's
        // process-wide writer lock once per datagram.
        if msg.len() >= ASSOC_RECV_BUF_LEN {
            let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            dgram_drops::warn_oversize_recv(
                dgram_drops::OversizeRecv::AppDatagram,
                dropped,
                || format!("; association {sess}, {} B buffer", msg.len()),
            );
            return AppDgram::Continue;
        }
        // Pin the source IP: any host that can reach the relay port could
        // otherwise become "the app" and steal all replies.
        if let Some(expected) = expected_app_ip
            && unmap(app.ip()) != expected
        {
            tracing::debug!("udp assoc {sess}: datagram from unauthorized app {app} ignored");
            return AppDgram::Continue;
        }
        // The coarse epoch: this value feeds the 1 s liveness throttle and the
        // egress memo's 1 s freshness window, and both are whole seconds.
        // `mono_millis()` here was a vDSO `clock_gettime` on every app datagram
        // — the same cost the reply path already had removed for the same
        // reason (see `AssocEntry::replied`).
        let now = coarse_millis();
        // Validate the SOCKS5 UDP framing *before* letting this packet claim
        // the association. The relay port is reachable by any process on the
        // control connection's IP, so locking on the first packet from any
        // source let one unsolicited or malformed datagram — a single stray
        // byte suffices — pin `entry.app` to the sender permanently: replies
        // then went to that sender, the legitimate app's datagrams were dropped
        // as a "changed source", and because dropped packets deliberately do
        // not touch the liveness stamp the association also starved to death at
        // 180 s. Only a well-formed RSV/FRAG + address frame may lock.
        if msg.len() < 4 || msg[0] != 0 || msg[1] != 0 || msg[2] != 0x00 {
            return AppDgram::Continue;
        }
        // Single decode: reuse header length for the payload offset.
        let (addr, hdr_len) = match TargetAddrRef::decode(&msg[3..]) {
            Ok((a, n)) => (a, n),
            Err(_) => return AppDgram::Continue,
        };
        let payload_off = 3 + hdr_len;
        if payload_off > msg.len() {
            return AppDgram::Continue;
        }
        let payload = &msg[payload_off..];
        if *published_app != Some(app) {
            // Lock to the first app address: IP-only pinning would let a
            // different socket on the same host (same IP, another port) take
            // over the association and steal its replies. A legitimate client
            // uses one UDP socket per association, so its source never changes;
            // a changed source is a hijack attempt, not a rebinding, and is
            // ignored instead of published — before the liveness stamp below,
            // so dropped packets cannot keep a dead association alive.
            if let Some(first) = *published_app {
                tracing::debug!(
                    "udp assoc {sess}: datagram from {app} ignored (locked to {first})"
                );
                return AppDgram::Continue;
            }
            entry.app.store(Some(Arc::new(app)));
            *published_app = Some(app);
        }
        if now.saturating_sub(*activity_stamp) >= ASSOC_TOUCH_INTERVAL_MS {
            *activity_stamp = now;
            entry.touch(now);
        }
        // Shared egress: the common case is a thread-local memo hit (one
        // generation load, zero Arc RMWs and zero quinn locks); the lock path
        // runs only on a generation change or once the memo's stamp expires,
        // and the single-flight winner still pays close_reason/
        // max_datagram_size at most once per refresh window. Stale handles are
        // reused optimistically behind one cheap `close_reason` gate: a dead
        // one is invalidated and counted as NO_EGRESS instead of being sent.
        //
        // `limit` is the connection's live `max_datagram_size()`: the real
        // DATAGRAM budget for the discovered path MTU, with the QUIC overhead
        // already subtracted. It is deliberately NOT clamped — a hard cap here
        // is really a *payload* cap, and the old `min(1350)` made every UDP
        // payload above 1338 B vanish on a 1472 B path (see
        // `dgram_payload_cap`). Payloads past a single frame are split by the
        // fragmenter rather than dropped. A first datagram may not be bound yet
        // (an earlier one may have failed framing validation); the send path
        // pins it.
        let bind = *bind.get_or_insert_with(|| {
            let c = pool.udp_class(&addr, payload.len());
            let b = pool.udp_bind(c);
            tracing::debug!(
                "udp assoc {sess}: egress class {} shard {} (first payload {} B)",
                c.name(),
                b.index,
                payload.len()
            );
            b
        });
        let sent = match egress_shared.with_fresh(bind, now, |c, limit| {
            {
                if payload.len() <= BATCH_SMALL_MAX {
                    if let Some(p) = pending_pack.take() {
                        if p.bind == bind && pending_addr.as_ref() == addr {
                            let pair: [&[u8]; 2] = [&pending_buf[..p.len], payload];
                            match send_udp_batch(c, sess, &addr, &pair, limit) {
                                DatagramSend::Sent => {
                                    return PayloadSend {
                                        frames: 1,
                                        failed: None,
                                    };
                                }
                                DatagramSend::TooLarge | DatagramSend::Blocked => {
                                    let pa = pending_addr.as_ref();
                                    let s1 = frag.send(c, sess, &pa, &pending_buf[..p.len], limit);
                                    if s1.failed.is_some() {
                                        let s2 = frag.send(c, sess, &addr, payload, limit);
                                        return prefer_severe(s1, s2);
                                    }
                                    return frag.send(c, sess, &addr, payload, limit);
                                }
                                other => {
                                    // One BATCH verdict for both staged
                                    // payloads: `frames: 0` says neither went
                                    // out, and the outer caller's
                                    // `recover_send_outcome` counts the event
                                    // once (`EGRESS_DEAD` is per dead
                                    // connection, not per lost datagram) —
                                    // deliberately, so a 2-pack loss cannot
                                    // double-count or double-invalidate.
                                    return PayloadSend {
                                        frames: 0,
                                        failed: Some(other),
                                    };
                                }
                            }
                        }
                        // Different destination or binding: hand the staged
                        // payload to the single-datagram path first, then stage
                        // this one below.
                        let pa = pending_addr.as_ref();
                        let s1 = frag.send(c, sess, &pa, &pending_buf[..p.len], limit);
                        if s1.failed.is_some() {
                            let s2 = frag.send(c, sess, &addr, payload, limit);
                            return prefer_severe(s1, s2);
                        }
                    }
                    pending_retarget(pending_addr, &addr);
                    pending_buf.clear();
                    pending_buf.extend_from_slice(payload);
                    *pending_pack = Some(PendingPack {
                        bind,
                        len: payload.len(),
                    });
                    return PayloadSend {
                        frames: 1,
                        failed: None,
                    };
                } else if let Some(p) = pending_pack.take() {
                    let pa = pending_addr.as_ref();
                    let s1 = frag.send(c, sess, &pa, &pending_buf[..p.len], limit);
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
                // Load the generation *before* the cached read: any mutation
                // concurrent with `acquire` then bumps past this tag, so the
                // memo below is never served for a value the mutation replaced.
                let generation =
                    egress_shared.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
                match egress_shared.acquire(pool, bind, now) {
                    Some((conn, limit, stamp)) => {
                        egress_shared.memo_store(bind, generation, &conn, limit, stamp);
                        frag.send(&conn, sess, &addr, payload, limit)
                    }
                    None => {
                        // No isolated egress connection right now: this
                        // binding's dedicated UDP slot(s) have not come up, are
                        // reconnecting, or another thread owns the refresh gate.
                        // Counted *exactly* (this counter is not batched) and
                        // warned once per `DROP_WARN_INTERVAL_MS`, because "is
                        // `udp_fail_closed` costing me anything" is only
                        // answerable if a short outage is visible at all. The
                        // detail separates the three causes, which is the
                        // difference between "the WAN is flapping" and "another
                        // thread won the refresh race".
                        let n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
                        dgram_drops::warn_egress_drop(
                            dgram_drops::EgressDrop::NoConnection,
                            n,
                            || {
                                format!(
                                    "; class={} bind={} udp_fail_closed={} udp_slot_live={} refresh_in_flight={}",
                                    bind.class.name(),
                                    bind.index,
                                    pool.udp_fail_closed(),
                                    pool.slot(pool.udp_global_slot(bind.index)).is_live(),
                                    egress_shared.refreshing[bind.index]
                                        .load(std::sync::atomic::Ordering::Relaxed),
                                )
                            },
                        );
                        return AppDgram::Continue;
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
        // Exactly one place for a send verdict's recovery, shared with the
        // deferred 2-pack flush below. `Blocked`/`TooLarge` are already counted
        // where they are decided; `ConnectionLost`/`Unsupported` are the states
        // the memo hit path deliberately defers to the send's verdict.
        recover_send_outcome(egress_shared, bind, sent);
        AppDgram::Continue
    }
}

/// Portable fallback for one recvmmsg-staged message: copy it out of the
/// thread-local burst scratch into the association's `buf`, then run the shared
/// body on it.
///
/// [`with_burst_msg`] only yields a borrow on Linux; every other build gets
/// `None` and takes this path, which is byte-for-byte the pre-F6 behaviour (one
/// copy out, then the same body). `None` means no message is staged, which ends
/// the burst exactly like the old `burst_msg_copy` returning `None`.
fn process_staged_copy(
    ctx: &mut AppDgramCtx<'_>,
    i: usize,
    buf: &mut [u8],
    drained: &mut usize,
) -> Option<AppDgram> {
    let (n, app) = burst_msg_copy(i, buf)?;
    *drained += 1;
    Some(ctx.process(&buf[..n], app))
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
    // Egress binding (class + shard), fixed by the first datagram that reaches
    // the send path and kept for the association's life (see [`UdpBind`]);
    // until then every datagram would bind from itself, which cannot happen
    // because the first send binds before it goes out.
    let mut bind: Option<UdpBind> = None;
    // Opportunistic 2-pack staging: one small payload held across drain
    // iterations so two consecutive same-destination small datagrams go out as
    // a single BATCH frame (one quinn lock + one AEAD instead of two). Never
    // waits: flushed at burst end or when the next datagram does not match, so
    // no added latency, only saved work.
    //
    // The bytes live in a **reused** buffer and the address is re-materialized
    // only when the destination actually changes, so a steady destination pays
    // one `memcpy` and no allocation. The previous shape stored
    // `payload.to_vec()` (plus a `String` for a domain target) on *every* small
    // datagram, pairing or not — a per-datagram allocation on the interactive
    // class, whose whole point is latency.
    let mut pending_buf: Vec<u8> = Vec::with_capacity(BATCH_SMALL_MAX);
    let mut pending_pack: Option<PendingPack> = None;
    // The staged payload's destination, kept *outside* the `Option` so the
    // domain key's `String` survives a take/flush cycle and is rewritten in
    // place instead of reallocated on every stage.
    let mut pending_addr = TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0)));
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
                // userspace (no HOL). `AppDgram::Continue` below advances the
                // drain — the same packet-skip as before; only the head error
                // ends the association.
                //
                // F6: staged (recvmmsg) datagrams are processed **in place**
                // through `with_burst_msg`, so they never pay the extra
                // burst-scratch -> `buf` copy. The awaited head has no burst
                // staging and keeps using `buf`.
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
                // F6: the per-datagram body lives in `AppDgramCtx::process`, so
                // the recvmmsg-staged arm can run it while the payload is still
                // in the thread-local burst scratch (`with_burst_msg`) instead
                // of copying it out to `buf` first. The context borrows the
                // association state mutably; it is scoped to this drain burst
                // and released before the deferred 2-pack flush below.
                let mut ctx = AppDgramCtx {
                    sess,
                    pool: &pool,
                    egress_shared: &egress_shared,
                    entry: &entry,
                    expected_app_ip,
                    published_app: &mut published_app,
                    activity_stamp: &mut activity_stamp,
                    bind: &mut bind,
                    pending_buf: &mut pending_buf,
                    pending_pack: &mut pending_pack,
                    pending_addr: &mut pending_addr,
                    frag: &mut frag,
                };
                for _ in 0..LAST_HOP_DRAIN {
                    // Resolve the next datagram and run the shared body while
                    // it is still in place: `pending` is the awaited head
                    // (first iteration only), the extras come from the burst
                    // scratch without a copy, or from `try_recv_from` on
                    // kernels without `recvmmsg`.
                    let action = if let Some((n, app)) = pending.take() {
                        drained += 1;
                        ctx.process(&buf[..n], app)
                    } else if burst_i < burst_n {
                        let i = burst_i;
                        burst_i += 1;
                        match with_burst_msg(i, |msg, app| {
                            drained += 1;
                            ctx.process(msg, app)
                        }) {
                            Some(action) => action,
                            // No burst scratch on this thread (every non-Linux
                            // build, where `recvmmsg` is unavailable): keep the
                            // portable copy-out path.
                            None => {
                                match process_staged_copy(&mut ctx, i, &mut buf, &mut drained) {
                                    Some(action) => action,
                                    None => break,
                                }
                            }
                        }
                    } else {
                        match recv_burst(&relay, LAST_HOP_DRAIN - drained) {
                            Some(0) => break,
                            Some(k) => {
                                burst_n = k;
                                burst_i = 1;
                                match with_burst_msg(0, |msg, app| {
                                    drained += 1;
                                    ctx.process(msg, app)
                                }) {
                                    Some(action) => action,
                                    None => {
                                        match process_staged_copy(
                                            &mut ctx,
                                            0,
                                            &mut buf,
                                            &mut drained,
                                        ) {
                                            Some(action) => action,
                                            None => break,
                                        }
                                    }
                                }
                            }
                            None => match relay.try_recv_from(&mut buf) {
                                Ok((n, app)) => {
                                    drained += 1;
                                    ctx.process(&buf[..n], app)
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                // A drained-packet error ends the burst, not the
                                // association: the head already proved the socket
                                // live this poll.
                                Err(_) => break,
                            },
                        }
                    };
                    match action {
                        AppDgram::Continue => {}
                        // No current body arm ends the association; the variant
                        // keeps the drain's two control actions explicit so a
                        // future fatal arm cannot silently swallow it.
                        AppDgram::BreakAssoc => break 'assoc,
                    }
                }
                if let Some(p) = pending_pack.take() {
                    flush_deferred_pair(
                        &egress_shared,
                        &pool,
                        &mut frag,
                        sess,
                        p.bind,
                        &pending_addr.as_ref(),
                        &pending_buf[..p.len],
                    );
                }
                record_drain_batch(drained);
            }
            // Fresh future per iteration, on purpose: `readable()` is an
            // `async fn`, and polling its state machine after it has returned
            // `Ready` panics ("async fn resumed after completion") — a pinned
            // future crashed every association whose control connection fired
            // readability once without closing. The per-iteration registration
            // it saves is one slab churn per drained burst, not per packet.
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
    // Backstop only: the flush at the end of the recv branch above always
    // drains `pending_pack` now (it sends, or drops it with accounting), so no exit
    // path can leave one behind. Kept so a future staging site added outside
    // that branch fails loudly in the counters instead of losing a datagram
    // silently.
    if pending_pack.is_some() {
        dgram_drops::bump(&dgram_drops::NO_EGRESS);
    }
    assoc_recycle_buf(buf);
    Ok(())
}

/// One staged small payload of the association's opportunistic 2-pack.
///
/// Metadata only: the bytes live in the association's reused `pending_buf`
/// (`len` bytes) and the destination in its `pending_addr` slot, so nothing
/// here allocates.
pub(crate) struct PendingPack {
    pub(crate) bind: UdpBind,
    pub(crate) len: usize,
}

/// Point the association's staged destination at `addr`, reusing the key
/// buffer it already owns.
///
/// A domain target keeps its `String` allocation across destination switches
/// (`clear` + `push_str`), which is what makes the alternating-destination case
/// allocation-free as well as the steady one. The caller must invoke this
/// *before* publishing a pack, so `pending_addr` always describes the staged
/// payload.
pub(crate) fn pending_retarget(slot: &mut TargetAddr, addr: &TargetAddrRef<'_>) {
    match (&mut *slot, addr) {
        (TargetAddr::Domain(name, port), TargetAddrRef::Domain(h, p)) => {
            if name.as_str() != *h || *port != *p {
                name.clear();
                name.push_str(h);
                *port = *p;
            }
        }
        (TargetAddr::Ip(slot), TargetAddrRef::Ip(a)) => *slot = *a,
        (slot, other) => *slot = other.into_owned(),
    }
}

/// Shared recovery for one send verdict on `bind`: the per-datagram path and
/// the deferred 2-pack flush both route through here, so the two cannot drift.
///
/// `Blocked`/`TooLarge` are counted where they are decided —
/// `DgramFragmenter::send` for the protocol's own size caps, `send_encoded` for
/// quinn's path-budget verdict — each with its own rate-limited size warning,
/// and must not be counted again. `TooLarge` re-reads the live DATAGRAM budget
/// so the next datagram is encoded against it; it is a **size** verdict, never a
/// connection fault, so it emphatically does not invalidate (folding it into
/// `ConnectionLost` used to flush the process-wide egress cache, bump the
/// connection-lost counter and log about a healthy connection).
///
/// `ConnectionLost`/`Unsupported` are the two states the memo hit path
/// deliberately leaves to the send's verdict (see `SharedEgress::with_fresh`):
/// both are counted in `EGRESS_DEAD`, **one bump per event** — a single verdict
/// can lose several staged payloads (a failed BATCH carries two), and the outage
/// is one fault, not one per payload. A lost connection invalidates the shared
/// cache so the next datagram re-acquires; `Unsupported` is static for the
/// connection's life, so re-acquiring cannot find a better slot and would only
/// add two quinn state-mutex acquisitions per datagram — it deliberately does
/// not invalidate.
pub(crate) fn recover_send_outcome(egress_shared: &SharedEgress, bind: UdpBind, sent: PayloadSend) {
    let outcome = sent.outcome();
    match outcome {
        DatagramSend::Sent => {}
        DatagramSend::Blocked => {
            tracing::debug!("client datagram dropped: send buffer full");
        }
        DatagramSend::TooLarge => {
            tracing::debug!("client datagram dropped: past the path's DATAGRAM budget");
            egress_shared.refresh_budget(bind);
        }
        DatagramSend::ConnectionLost => {
            tracing::debug!("client egress stale, invalidating shared cache");
            let n = dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
            dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::ConnectionLost, n, || {
                format!(
                    "; class={}, send outcome {outcome:?}, cached handle invalidated",
                    bind.class.name()
                )
            });
            egress_shared.invalidate(bind);
        }
        DatagramSend::Unsupported => {
            tracing::debug!("client datagram dropped: peer does not support DATAGRAM");
            let n = dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
            dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::Unsupported, n, String::new);
        }
    }
}

/// Send the deferred 2-pack payload once, or drop it with accounting.
///
/// The payload is never returned: parking it back for a later iteration is
/// what the pre-fix code did, and a parked payload waits for the next app
/// datagram — unbounded when the app pauses, since the idle and control
/// branches never look at it. A memo that has gone stale between staging and
/// this flush (a coarse-tick boundary, or a concurrent generation bump from
/// a reconnect or budget probe) therefore falls back to the same acquire a
/// datagram takes on a memo miss, exactly once; a genuine no-egress outcome
/// drops the payload and counts it. Either way the deferred queue empties.
///
/// The send **verdict** is not thrown away: this used to end in
/// `with_fresh(..).is_some()`, so a cached handle that died between staging and
/// the flush produced a `ConnectionLost` that was neither counted in
/// `EGRESS_DEAD` nor invalidated the cache — the loss stayed invisible and the
/// dead handle kept being served for the rest of the memo window (every later
/// datagram paying one failed send, and every flush silently dropping its
/// payload). Both the memo-hit and the re-acquire send now go through
/// `recover_send_outcome`, exactly like the per-datagram path.
pub(crate) fn flush_deferred_pair(
    egress_shared: &SharedEgress,
    pool: &ConnPool,
    frag: &mut DgramFragmenter,
    sess: u32,
    bind: UdpBind,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
) {
    let now_flush = coarse_millis();
    if let Some(sent) = egress_shared.with_fresh(bind, now_flush, |c, limit| {
        frag.send(c, sess, addr, payload, limit)
    }) {
        recover_send_outcome(egress_shared, bind, sent);
        return;
    }
    // Generation read before the cached read, the same contract the
    // per-datagram miss path in `udp_associate_inner` documents.
    let generation =
        egress_shared.generation[bind.index].load(std::sync::atomic::Ordering::Acquire);
    match egress_shared.acquire(pool, bind, now_flush) {
        Some((conn, limit, stamp)) => {
            egress_shared.memo_store(bind, generation, &conn, limit, stamp);
            recover_send_outcome(
                egress_shared,
                bind,
                frag.send(&conn, sess, addr, payload, limit),
            );
        }
        None => {
            let n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
            dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, n, || {
                format!("; class={} (deferred 2-pack flush)", bind.class.name())
            });
        }
    }
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
