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
    pending_train: &'a mut Option<PendingTrain>,
    /// Session-scoped outbound flow table. The association task is its only
    /// writer; a clone-on-write snapshot is published to `entry.flows` so the
    /// dispatcher can decode downlink flow ids without a lock.
    flows: &'a mut FlowTable,
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
        let pending_train = &mut *self.pending_train;
        let flows = &mut *self.flows;
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
            // A payload that cannot join a TRAIN still has to drain the current
            // run first: keeping it would reorder the association's wire.
            if payload.len() > BATCH_SMALL_MAX {
                if let Some(p) = pending_train.take() {
                    let s1 = flush_pending_train(c, sess, frag, flows, &p, pending_buf, limit);
                    if !s1.complete() {
                        let s2 = frag.send(c, sess, &addr, payload, limit);
                        return prefer_severe(s1, s2);
                    }
                }
                return frag.send(c, sess, &addr, payload, limit);
            }
            // A refused header takes the same single/fragment path (and the
            // same accounting) it would take without a train.
            let Ok(header) = addr.header() else {
                if let Some(p) = pending_train.take() {
                    let s1 = flush_pending_train(c, sess, frag, flows, &p, pending_buf, limit);
                    if !s1.complete() {
                        let s2 = frag.send(c, sess, &addr, payload, limit);
                        return prefer_severe(s1, s2);
                    }
                }
                return frag.send(c, sess, &addr, payload, limit);
            };
            // Conservative worst case for one item: extra flow byte + inline
            // address. Deciding the preliminary flush against it makes the
            // exact append below memory-safe against a full run without a
            // second budget branch: `wire_len` is an upper bound, so an item
            // that fits this estimate fits the encoder.
            let worst_item = 1usize
                .saturating_add(1)
                .saturating_add(varint_len(payload.len()))
                .saturating_add(header.len())
                .saturating_add(payload.len());
            if pending_train.as_ref().is_some_and(|p| {
                p.bind != bind
                    || p.n >= MQP3_MAX_TRAIN_ITEMS
                    || p.wire_len.saturating_add(worst_item) > limit
            }) {
                let p = pending_train.take().expect("checked by is_some_and");
                let s1 = flush_pending_train(c, sess, frag, flows, &p, pending_buf, limit);
                if !s1.complete() {
                    let s2 = frag.send(c, sess, &addr, payload, limit);
                    return prefer_severe(s1, s2);
                }
            }
            // Flow allocation and the inline decision. A new IP flow is opened
            // inline; an established flow keeps its address inline until a
            // downlink frame for that flow was successfully staged on the
            // client (see `AssocEntry::confirmed`). That downlink is proof the
            // server installed the mapping, so compressing the next frame is
            // safe even if the open frames were lost. A pure-uplink flow never
            // gets that proof and stays inline; that costs the flow byte plus
            // the address, but cannot black-hole. Flow ids are never reused; a
            // full table falls back to the reserved no-flow inline id.
            //
            // Domain targets deliberately stay inline (`NO_FLOW`) on every
            // frame. The first unresolved domain is delivered by a spawned
            // resolver task, so the session (and its flow table) may not exist
            // when the accept loop sees the open; compressing later frames
            // would then need a growth-proof race. The reply direction already
            // cannot compress a domain flow, because the client has no resolved
            // IP to put in the SOCKS header. Inline avoids both problems and
            // does not consume a flow slot; TRAIN still shares the session
            // header across a domain fanout.
            let (flow, want_open) = if matches!(addr, TargetAddrRef::Domain(..)) {
                (MQP3_NO_FLOW, true)
            } else {
                match flows.flow_for(&addr) {
                    Some(f) => (f, !entry.flow_confirmed(f)),
                    None => match flows.insert(addr.into_owned()) {
                        Some((f, owned)) => {
                            publish_flow(entry, f, owned);
                            (f, true)
                        }
                        None => (MQP3_NO_FLOW, true),
                    },
                }
            };
            let already_open = pending_train
                .as_ref()
                .is_some_and(|p| flow < MQP3_MAX_FLOWS as u8 && p.open_mask & (1u64 << flow) != 0);
            let open = want_open && !already_open;
            let addr_len = if open { header.len() } else { 0 };
            let item_len = train_item_len(flow, addr_len, payload.len());
            let train = pending_train.get_or_insert_with(|| PendingTrain::new(bind));
            let off = pending_buf.len();
            pending_buf.extend_from_slice(payload);
            train.push(
                PendingItem {
                    flow,
                    open,
                    off,
                    len: payload.len(),
                    open_addr: (flow == MQP3_NO_FLOW).then(|| addr.into_owned()),
                },
                item_len,
            );
            PayloadSend {
                frames: 1,
                failed: None,
            }
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
        // deferred TRAIN flush below. `Blocked`/`TooLarge` are already counted
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
    // Opportunistic MQP-3 TRAIN staging: small payloads for any mix of
    // destinations are held across drain iterations and flushed as one QUIC
    // DATAGRAM (one quinn lock + one AEAD instead of one per payload). The run
    // is capped by the current DATAGRAM budget, not just by
    // `MQP3_MAX_TRAIN_ITEMS`, and never waits: it is flushed at burst end,
    // when the next item would not fit, and before a non-trainable payload, so
    // packing adds no latency.
    //
    // Destination state is the session's flow table. A new destination gets a
    // flow id and is published to the dispatcher immediately; the first few
    // frames repeat the address inline so a reordered/lost open cannot
    // black-hole the flow. After that the address is gone from the wire.
    let mut pending_buf: Vec<u8> = Vec::with_capacity(BATCH_SMALL_MAX * 2);
    let mut pending_train: Option<PendingTrain> = None;
    let mut flows = FlowTable::default();
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
                // and released before the deferred TRAIN flush below.
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
                    pending_train: &mut pending_train,
                    flows: &mut flows,
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
                if let Some(p) = pending_train.take() {
                    flush_deferred_train(
                        &egress_shared,
                        &pool,
                        &mut frag,
                        sess,
                        &p,
                        &flows,
                        &mut pending_buf,
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
    // drains `pending_train` now (it sends, or drops it with accounting), so no
    // exit path can leave one behind. Kept so a future staging site added
    // outside that branch fails loudly in the counters instead of losing a
    // datagram silently.
    if let Some(p) = pending_train {
        for _ in 0..p.n {
            dgram_drops::bump(&dgram_drops::NO_EGRESS);
        }
    }
    assoc_recycle_buf(buf);
    Ok(())
}

#[derive(Default)]
pub(crate) struct PendingItem {
    pub(crate) flow: u8,
    pub(crate) open: bool,
    pub(crate) off: usize,
    pub(crate) len: usize,
    /// Only for [`MQP3_NO_FLOW`]: the inline address of a destination that did
    /// not fit the fixed flow table. Established flows resolve through the
    /// table at flush time.
    pub(crate) open_addr: Option<TargetAddr>,
}

/// One in-progress MQP-3 TRAIN.
///
/// Metadata only: payload bytes live back-to-back in the association's reused
/// `pending_buf`, and flow addresses live in the session's `FlowTable`. A
/// `PendingTrain` is never larger than `MQP3_MAX_TRAIN_ITEMS`; `wire_len` is a
/// conservative upper bound used while staging and the encoder recomputes the
/// exact size (the same-flow form is slightly smaller).
pub(crate) struct PendingTrain {
    pub(crate) bind: UdpBind,
    pub(crate) items: [PendingItem; MQP3_MAX_TRAIN_ITEMS],
    pub(crate) n: usize,
    pub(crate) wire_len: usize,
    /// Bit `f` is set when flow `f` has already appeared with an inline address
    /// in this run, so a second item for it is compressed even during the
    /// open window.
    pub(crate) open_mask: u64,
}

impl PendingTrain {
    pub(crate) fn new(bind: UdpBind) -> Self {
        Self {
            bind,
            items: std::array::from_fn(|_| PendingItem::default()),
            n: 0,
            wire_len: MQP3_TRAIN_HEADER_LEN,
            open_mask: 0,
        }
    }

    pub(crate) fn push(&mut self, item: PendingItem, item_len: usize) {
        debug_assert!(self.n < MQP3_MAX_TRAIN_ITEMS);
        debug_assert!(item.len <= BATCH_SMALL_MAX);
        if item.open && item.flow < MQP3_MAX_FLOWS as u8 {
            self.open_mask |= 1u64 << item.flow;
        }
        self.items[self.n] = item;
        self.n += 1;
        self.wire_len = self.wire_len.saturating_add(item_len);
    }
}

/// Publish a newly allocated flow to the dispatcher's read-only snapshot.
///
/// Allocation happens once per destination, so the clone-on-write copy is not a
/// per-packet cost. A concurrent dispatcher either sees the old snapshot
/// (inline/known flows still resolve) or the new one; it can never see a
/// half-written table.
fn publish_flow(entry: &AssocEntry, flow: u8, addr: Arc<TargetAddr>) {
    entry.flows.rcu(|old| {
        let mut next = (**old).clone();
        let ok = next.insert_at(flow, addr.clone());
        debug_assert!(ok, "freshly allocated flow must install");
        Arc::new(next)
    });
}

fn pending_item_addr<'a>(item: &'a PendingItem, flows: &'a FlowTable) -> Option<TargetAddrRef<'a>> {
    if item.flow == MQP3_NO_FLOW {
        item.open_addr.as_ref().map(TargetAddr::as_ref)
    } else {
        flows.get(item.flow).map(TargetAddr::as_ref)
    }
}

/// Send one staged item as a `SINGLE`, falling back to the MQP-2 fragment
/// sender if the v3 header does not fit or the DATAGRAM queue is full.
fn flush_train_single(
    c: &quinn::Connection,
    sess: u32,
    frag: &mut DgramFragmenter,
    item: &PendingItem,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> PayloadSend {
    let inline = item.open.then_some(*addr);
    let sent = match encode_single(sess, item.flow, inline.as_ref(), false, payload, limit) {
        Some(body) => try_send_datagram(c, body),
        None => DatagramSend::TooLarge,
    };
    match sent {
        DatagramSend::Sent => {
            udp_stats::payload(payload.len());
            PayloadSend {
                frames: 1,
                failed: None,
            }
        }
        DatagramSend::Blocked | DatagramSend::TooLarge => frag.send(c, sess, addr, payload, limit),
        // A dead/unsupported connection is one event for the whole flush;
        // `recover_send_outcome` counts it once and invalidates the shared
        // cache.
        other => PayloadSend {
            frames: 0,
            failed: Some(other),
        },
    }
}

fn fallback_train(
    c: &quinn::Connection,
    sess: u32,
    frag: &mut DgramFragmenter,
    p: &PendingTrain,
    flows: &FlowTable,
    arena: &[u8],
    limit: usize,
) -> PayloadSend {
    let mut worst = PayloadSend {
        frames: 0,
        failed: None,
    };
    for item in &p.items[..p.n] {
        let Some(addr) = pending_item_addr(item, flows) else {
            // A compressed item whose flow vanished cannot be addressed. This
            // is a receiver-side bookkeeping failure, not a path verdict; count
            // it as a refusal rather than inventing an address.
            dgram_drops::bump(&dgram_drops::REFUSED);
            continue;
        };
        let payload = &arena[item.off..item.off + item.len];
        worst = prefer_severe(
            worst,
            flush_train_single(c, sess, frag, item, &addr, payload, limit),
        );
    }
    worst
}

/// Send one staged MQP-3 run, or fall back to per-payload sends.
///
/// A run of one is a plain `SINGLE` rather than a one-item TRAIN: the train
/// header and item flags would cost more than the 5/6-byte single header. For a
/// real run, `encode_train` does the exact budget check; if quinn refuses the
/// frame (full queue or a shrunken path budget), every payload is retried as a
/// `SINGLE`/fragment, each with its own accounting.
pub(crate) fn flush_pending_train(
    c: &quinn::Connection,
    sess: u32,
    frag: &mut DgramFragmenter,
    flows: &FlowTable,
    p: &PendingTrain,
    arena: &mut Vec<u8>,
    limit: usize,
) -> PayloadSend {
    let sent = flush_pending_train_inner(c, sess, frag, flows, p, arena, limit);
    arena.clear();
    sent
}

fn flush_pending_train_inner(
    c: &quinn::Connection,
    sess: u32,
    frag: &mut DgramFragmenter,
    flows: &FlowTable,
    p: &PendingTrain,
    arena: &[u8],
    limit: usize,
) -> PayloadSend {
    if p.n == 0 {
        return PayloadSend {
            frames: 0,
            failed: None,
        };
    }
    if p.n == 1 {
        let item = &p.items[0];
        debug_assert_eq!(item.off, 0, "a one-item run must start at arena offset 0");
        let Some(addr) = pending_item_addr(item, flows) else {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return PayloadSend {
                frames: 0,
                failed: None,
            };
        };
        let payload = &arena[item.off..item.off + item.len];
        return flush_train_single(c, sess, frag, item, &addr, payload, limit);
    }
    let mut refs: [TrainItem<'_>; MQP3_MAX_TRAIN_ITEMS] = [TrainItem {
        flow: 0,
        inline: None,
        src_override: false,
        payload: &[],
    }; MQP3_MAX_TRAIN_ITEMS];
    for (i, item) in p.items[..p.n].iter().enumerate() {
        let addr = if item.open {
            match pending_item_addr(item, flows) {
                Some(a) => Some(a),
                None => {
                    return fallback_train(c, sess, frag, p, flows, arena, limit);
                }
            }
        } else {
            None
        };
        refs[i] = TrainItem {
            flow: item.flow,
            inline: addr,
            src_override: false,
            payload: &arena[item.off..item.off + item.len],
        };
    }
    let Some(body) = encode_train(sess, &refs[..p.n], limit) else {
        return fallback_train(c, sess, frag, p, flows, arena, limit);
    };
    match try_send_datagram(c, body) {
        DatagramSend::Sent => {
            for item in &p.items[..p.n] {
                udp_stats::payload(item.len);
            }
            PayloadSend {
                frames: 1,
                failed: None,
            }
        }
        DatagramSend::Blocked | DatagramSend::TooLarge => {
            fallback_train(c, sess, frag, p, flows, arena, limit)
        }
        other => PayloadSend {
            frames: 0,
            failed: Some(other),
        },
    }
}

/// Send the deferred MQP-3 run once, or drop it with accounting.
///
/// The run is never parked for a later iteration: that would wait for the next
/// app datagram, unbounded when the app pauses. A stale memo falls back to the
/// same acquire a datagram takes on a miss, exactly once; a genuine no-egress
/// outcome drops every payload in the run and counts each one. The send verdict
/// still drives `recover_send_outcome`, so a handle that died between staging
/// and the flush is counted and invalidated instead of silently disappearing.
pub(crate) fn flush_deferred_train(
    egress_shared: &SharedEgress,
    pool: &ConnPool,
    frag: &mut DgramFragmenter,
    sess: u32,
    p: &PendingTrain,
    flows: &FlowTable,
    arena: &mut Vec<u8>,
) {
    let bind = p.bind;
    let now_flush = coarse_millis();
    if let Some(sent) = egress_shared.with_fresh(bind, now_flush, |c, limit| {
        flush_pending_train(c, sess, frag, flows, p, arena, limit)
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
                flush_pending_train(&conn, sess, frag, flows, p, arena, limit),
            );
        }
        None => {
            let mut n = 0;
            for _ in 0..p.n {
                n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
            }
            dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, n, || {
                format!(
                    "; class={} ({} staged datagrams, deferred TRAIN flush)",
                    bind.class.name(),
                    p.n
                )
            });
            // The run is gone; the next datagram must not append to its arena
            // (a one-item flush would otherwise read the old bytes at offset 0).
            arena.clear();
        }
    }
}

/// One in-progress BATCH run of the association's opportunistic N-pack.
///
/// Metadata only: the bytes live back-to-back in the association's reused
/// `pending_buf` and the destination in its `pending_addr` slot, so appending
/// an item after the first allocates nothing. `lens` is in wire order and its
/// sum is exactly `pending_buf.len()` while the run is staged.
#[cfg(test)]
pub(crate) struct PendingBatch {
    pub(crate) bind: UdpBind,
    pub(crate) lens: [u16; MAX_BATCH_ITEMS],
    pub(crate) n: usize,
}

#[cfg(test)]
impl PendingBatch {
    /// Start a run with `len` payload bytes already in `pending_buf`.
    pub(crate) fn new(bind: UdpBind, len: usize) -> Self {
        debug_assert!(len <= BATCH_SMALL_MAX);
        debug_assert!(len <= u16::MAX as usize);
        let mut lens = [0u16; MAX_BATCH_ITEMS];
        lens[0] = len as u16;
        Self { bind, lens, n: 1 }
    }
}

/// Shared recovery for one send verdict on `bind`: the per-datagram path and
/// the deferred TRAIN flush both route through here, so the two cannot drift.
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
/// can lose a whole staged run, and the outage is one fault, not one per
/// payload. A lost connection invalidates the shared
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

/// Send one staged BATCH run through `c`, falling back to per-payload sends if
/// the frame is refused by the path budget or a full DATAGRAM buffer.
///
/// A run of one is deliberately sent as a plain `0x02` datagram: the BATCH
/// wrapper would add a count byte and a length prefix for no sharing, and the
/// single-datagram path is the one every unbatched payload already uses. For a
/// real run (`n >= 2`), `send_udp_batch` books every payload on success; on a
/// refused frame it books nothing, so the fallback re-sends each payload
/// through `DgramFragmenter::send`, which does its own exactly-once
/// accounting.
///
/// This function is the client-side twin of the server's `flush_reply_batch`.
/// It is called with the staging arena exactly as it was left by
/// [`PendingBatch`], so it borrows rather than copies each payload.
#[cfg(test)]
pub(crate) fn flush_pending_batch(
    c: &quinn::Connection,
    sess: u32,
    frag: &mut DgramFragmenter,
    addr: &TargetAddrRef<'_>,
    p: &PendingBatch,
    arena: &[u8],
    limit: usize,
) -> PayloadSend {
    if p.n == 0 {
        return PayloadSend {
            frames: 0,
            failed: None,
        };
    }
    let total: usize = p.lens[..p.n].iter().map(|&n| n as usize).sum();
    debug_assert_eq!(total, arena.len(), "staged lengths must cover the arena");
    if p.n == 1 {
        return frag.send(c, sess, addr, &arena[..total], limit);
    }
    let mut refs: [&[u8]; MAX_BATCH_ITEMS] = [&[][..]; MAX_BATCH_ITEMS];
    let mut off = 0usize;
    for (r, &len) in refs.iter_mut().zip(&p.lens[..p.n]) {
        let len = len as usize;
        *r = &arena[off..off + len];
        off += len;
    }
    match send_udp_batch(c, sess, addr, &refs[..p.n], limit) {
        DatagramSend::Sent => PayloadSend {
            frames: 1,
            failed: None,
        },
        DatagramSend::TooLarge | DatagramSend::Blocked => {
            let mut worst = PayloadSend {
                frames: 0,
                failed: None,
            };
            for r in &refs[..p.n] {
                worst = prefer_severe(worst, frag.send(c, sess, addr, r, limit));
            }
            worst
        }
        // A dead/unsupported connection is one event for the whole run, not one
        // per payload: `recover_send_outcome` counts `EGRESS_DEAD` once and
        // invalidates the shared cache once.
        other => PayloadSend {
            frames: 0,
            failed: Some(other),
        },
    }
}

/// Send the deferred N-pack run once, or drop it with accounting.
///
/// The run is never returned: parking it back for a later iteration is what
/// the pre-fix 2-pack code did, and a parked payload waits for the next app
/// datagram — unbounded when the app pauses, since the idle and control
/// branches never look at it. A memo that has gone stale between staging and
/// this flush (a coarse-tick boundary, or a concurrent generation bump from
/// a reconnect or budget probe) therefore falls back to the same acquire a
/// datagram takes on a memo miss, exactly once; a genuine no-egress outcome
/// drops every payload in the run and counts each one. Either way the deferred
/// queue empties.
///
/// The send **verdict** is not thrown away: this used to end in
/// `with_fresh(..).is_some()`, so a cached handle that died between staging and
/// the flush produced a `ConnectionLost` that was neither counted in
/// `EGRESS_DEAD` nor invalidated the cache — the loss stayed invisible and the
/// dead handle kept being served for the rest of the memo window (every later
/// datagram paying one failed send, and every flush silently dropping its
/// payload). Both the memo-hit and the re-acquire send now go through
/// `recover_send_outcome`, exactly like the per-datagram path.
#[cfg(test)]
pub(crate) fn flush_deferred_batch(
    egress_shared: &SharedEgress,
    pool: &ConnPool,
    frag: &mut DgramFragmenter,
    sess: u32,
    p: &PendingBatch,
    addr: &TargetAddrRef<'_>,
    arena: &[u8],
) {
    let bind = p.bind;
    let now_flush = coarse_millis();
    if let Some(sent) = egress_shared.with_fresh(bind, now_flush, |c, limit| {
        flush_pending_batch(c, sess, frag, addr, p, arena, limit)
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
                flush_pending_batch(&conn, sess, frag, addr, p, arena, limit),
            );
        }
        None => {
            let mut n = 0;
            for _ in 0..p.n {
                n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
            }
            dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, n, || {
                format!(
                    "; class={} ({} staged datagrams, deferred N-pack flush)",
                    bind.class.name(),
                    p.n
                )
            });
        }
    }
}

/// Pick the outcome the caller must react to when two single sends were both
/// attempted (packed-frame fallback, pending flush): a dead connection outranks a
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
