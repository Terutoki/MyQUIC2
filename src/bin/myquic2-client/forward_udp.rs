//! Config-driven UDP forward listeners: raw datagrams in, MQP-3 rev2 out.
//!
//! One listener socket serves many peers. Each distinct client source address
//! (`IP:port`) gets its own client session: a `sess` reserved from the shared
//! [`UdpHub`], an [`AssocEntry`] whose relay socket **is** the listener (so
//! replies leave from the port the peer sent to) and whose app address is the
//! peer itself, plus the rev2 [`UplinkFlows`] state.
//!
//! Why per-peer sessions rather than one shared one: a server session has a
//! single upstream socket, so every reply from the target arrives with the same
//! source tuple and cannot be demultiplexed back to the right peer. The client
//! `sess` is the demux key, exactly as it is for SOCKS5 `UDP ASSOCIATE`.
//!
//! The dispatcher reply path is shared with SOCKS; [`AssocEntry::raw_reply`]
//! tells it to write the bare payload instead of a SOCKS5 UDP header (see
//! `dispatcher.rs`).
use super::*;
use myquic2::udp::R2Fragmenter;

/// Spawn a UDP forward listener on `spec.listen`, relaying each peer's
/// datagrams to `spec.target`.
///
/// The bind completes before the task is spawned, so an occupied port fails
/// client startup instead of silently dropping the listener.
pub(crate) fn spawn_udp_forward(
    spec: UdpForwardSpec,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listen = spec.listen;
    let raw = udp_socket_dual(&listen.to_string())
        .with_context(|| format!("forward UDP listener {listen}"))?;
    let listener = Arc::new(tokio::net::UdpSocket::from_std(raw)?);
    if !listen.ip().is_loopback() {
        warn!(
            "udp_forward listen {listen} is not loopback: any host that can reach it can use \
             the tunnel to {}; bind 127.0.0.1 or firewall the port",
            display_target(&spec.target)
        );
    }
    let fwd = UdpForwarder {
        listener,
        target: spec.target,
        max_sessions: spec.max_sessions,
        pool,
        hub,
        egress,
        peers: HashMap::default(),
    };
    Ok(tokio::spawn(async move { fwd.run(shutdown).await }))
}

/// One live per-peer UDP session.
///
/// The `hub` reference exists so the [`Drop`] impl can give the process-wide
/// session slot back on *every* exit path, including a panicking listener task
/// (dev/test unwinds): `UdpHub::alloc_sess` reserves exactly one slot, and its
/// documented invariant is one `release` per successful allocation.
pub(crate) struct PeerSession {
    pub(crate) sess: u32,
    hub: Arc<UdpHub>,
    pub(crate) entry: Arc<AssocEntry>,
    pub(crate) uplink: UplinkFlows,
    pub(crate) frag: R2Fragmenter,
    /// Egress class + shard, fixed by the first datagram (see `UdpBind`).
    pub(crate) bind: Option<UdpBind>,
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        self.entry
            .alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.hub.release(self.sess);
    }
}

/// The listener task's whole state: socket, fixed target, peer table.
pub(crate) struct UdpForwarder {
    listener: Arc<tokio::net::UdpSocket>,
    target: TargetAddr,
    max_sessions: usize,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    peers: HashMap<SocketAddr, PeerSession, foldhash::fast::RandomState>,
}

impl UdpForwarder {
    /// Test-only constructor: production builds this in [`spawn_udp_forward`]
    /// from a bound listener, so tests can drive [`Self::handle_datagram`] and
    /// the sweep against a real socket and a published egress handle.
    #[cfg(test)]
    pub(crate) fn for_test(
        listener: Arc<tokio::net::UdpSocket>,
        target: TargetAddr,
        max_sessions: usize,
        pool: ConnPool,
        hub: Arc<UdpHub>,
        egress: Arc<SharedEgress>,
    ) -> Self {
        Self {
            listener,
            target,
            max_sessions,
            pool,
            hub,
            egress,
            peers: HashMap::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    pub(crate) fn peer_sess(&self, src: SocketAddr) -> Option<u32> {
        self.peers.get(&src).map(|p| p.sess)
    }

    /// Route one datagram from `src` to `payload`'s session, creating the
    /// session on the first datagram from that source.
    ///
    /// Returns the egress binding the payload was sent on (if any) so the
    /// caller can drain the connection-scoped stager once per burst. Synchronous
    /// so it can run while the payload still lives in the recvmmsg scratch
    /// buffer.
    pub(crate) fn handle_datagram(
        &mut self,
        src: SocketAddr,
        payload: &[u8],
        now: u64,
    ) -> Option<UdpBind> {
        if !self.peers.contains_key(&src) && !self.create_peer(src) {
            return None;
        }
        let target = self.target.as_ref();
        let peer = self.peers.get_mut(&src)?;
        // Same 1 Hz-throttled liveness stamp as a SOCKS association: the idle
        // sweep reaps on bidirectional silence only.
        peer.entry.touch(now);
        send_payload_uplink(
            &self.pool,
            &self.egress,
            peer.sess,
            &target,
            payload,
            &mut peer.bind,
            &mut peer.uplink,
            &mut peer.frag,
            now,
            SessionKind::Forward,
        );
        peer.bind
    }

    /// Share the SOCKS phase: the send block moved into `send_payload_uplink`
    /// lives in `assoc.rs` (see `SessionKind`).
    fn create_peer(&mut self, src: SocketAddr) -> bool {
        if self.peers.len() >= self.max_sessions {
            // Per-listener policy limit, not the process-wide budget: counted
            // as REFUSED so an operator can tell the two apart in the 60 s line.
            let n = dgram_drops::bump(&dgram_drops::REFUSED);
            if let Some(sup) = claim_forward_udp_refused_log() {
                warn!(
                    "udp_forward {} peer cap {} reached; dropping datagram from {src} ({n} so far){sup}",
                    display_target(&self.target),
                    self.max_sessions
                );
            }
            return false;
        }
        let Some(sess) = self.hub.alloc_sess() else {
            // Process-wide UDP-association budget (shared with SOCKS).
            let n = dgram_drops::bump(&dgram_drops::SESSION_FULL);
            if let Some(sup) = claim_forward_udp_refused_log() {
                warn!(
                    "udp_forward {} sessions exhausted (max_udp_assocs); dropping datagram from {src} ({n} so far){sup}",
                    display_target(&self.target)
                );
            }
            return false;
        };
        udp_stats::session();
        // `new_raw`: the dispatcher must write replies as bare payloads.
        let entry = Arc::new(AssocEntry::new_raw(self.listener.clone()));
        // The app address is fixed at creation (unlike a SOCKS association,
        // which locks it on the first datagram): every datagram of this peer
        // maps to this session, and a reply must go back to exactly this source.
        entry.app.store(Some(Arc::new(src)));
        // Publish before the first send: a reply can only follow a datagram
        // that was just sent, but the dispatcher resolves the session through
        // the hub, so publishing first removes the window entirely.
        self.hub.publish(sess, entry.clone());
        self.peers.insert(
            src,
            PeerSession {
                sess,
                hub: self.hub.clone(),
                entry,
                uplink: UplinkFlows::new(),
                frag: R2Fragmenter::new(),
                bind: None,
            },
        );
        tracing::debug!(
            "udp_forward {} peer {src}: session {sess} opened",
            display_target(&self.target)
        );
        true
    }

    /// Reap peers idle in both directions for the association idle window.
    ///
    /// `send_sess_close` tells the server to drop the session immediately; a
    /// lost close is harmless (the server's own 180 s sweep is the backstop, and
    /// the next datagram from this peer simply opens a fresh session). Removing
    /// the map entry releases the hub slot through [`PeerSession::drop`].
    pub(crate) fn sweep_idle(&mut self, now: u64) {
        let mut reap: Vec<SocketAddr> = Vec::new();
        for (src, peer) in &self.peers {
            if peer.entry.idle_since_tick(now, ASSOC_IDLE_MS) {
                reap.push(*src);
            }
        }
        for src in reap {
            if let Some(peer) = self.peers.remove(&src) {
                send_sess_close(
                    &self.egress,
                    &self.pool,
                    peer.bind,
                    peer.sess,
                    peer.uplink.epoch,
                );
                tracing::debug!(
                    "udp_forward {} peer {src}: session {} idle reaped",
                    display_target(&self.target),
                    peer.sess
                );
            }
        }
    }

    /// Close every session (process shutdown): best-effort `SESS_CLOSE`, then
    /// release the hub slots by dropping the map.
    pub(crate) fn shutdown_all(&mut self) {
        for (src, peer) in std::mem::take(&mut self.peers) {
            send_sess_close(
                &self.egress,
                &self.pool,
                peer.bind,
                peer.sess,
                peer.uplink.epoch,
            );
            tracing::debug!(
                "udp_forward {} peer {src}: session {} closed on shutdown",
                display_target(&self.target),
                peer.sess
            );
        }
    }

    /// The listener loop: bounded recvmmsg bursts, an idle tick and shutdown.
    async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        // Local Arc so the receive future never borrows `self` (the handler
        // needs `&mut self` after a datagram resolves).
        let listener = self.listener.clone();
        let mut buf = assoc_recv_buf();
        // Desynchronized fixed tick, same phase contract as the SOCKS
        // association: the first deadline is jittered rather than slept off
        // after binding, so the listener serves datagrams immediately.
        let phase_ms = jitter_ms();
        let mut idle_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(phase_ms),
            Duration::from_secs(ASSOC_IDLE_TICK_SECS),
        );
        idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Egress bindings touched by the current burst; the connection stager is
        // drained once per distinct binding at the burst end so small payloads
        // from several peers still share one TRAIN.
        let mut touched: Vec<UdpBind> = Vec::with_capacity(MAX_UDP_SLOTS);
        loop {
            tokio::select! {
                r = listener.recv_from(&mut buf) => {
                    let (n, src) = match r {
                        Ok(x) => x,
                        Err(e) if forward_recv_error_is_transient(e.kind()) => {
                            // Peer churn delivers ICMP errors to the listener
                            // socket (see `forward_recv_error_is_transient`):
                            // warn once per window and keep serving everyone.
                            if let Some(sup) = claim_forward_udp_recv_failed_log() {
                                warn!(
                                    "udp_forward {} receive transient error: {e:#}; \
                                     listener continues{sup}",
                                    display_target(&self.target)
                                );
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            continue;
                        }
                        Err(e) => {
                            // Not a recoverable asynchronous error: the socket
                            // itself is unusable, and every other listener /
                            // SOCKS keeps its own socket.
                            if let Some(sup) = claim_forward_udp_recv_failed_log() {
                                warn!(
                                    "udp_forward {} receive failed: {e:#}; listener stopped{sup}",
                                    display_target(&self.target)
                                );
                            }
                            break;
                        }
                    };
                    let now = coarse_millis();
                    let mut drained = 0usize;
                    self.record_touched(src, &buf[..n], now, &mut touched);
                    drained += 1;
                    // Linux: one recvmmsg refill covers up to LAST_HOP_DRAIN
                    // datagrams. The portable `try_recv_from` arm keeps the
                    // per-frame wakeup shape when recvmmsg is unavailable.
                    let mut burst_n = 0usize;
                    let mut burst_i = 0usize;
                    while drained < LAST_HOP_DRAIN {
                        if burst_i < burst_n {
                            let i = burst_i;
                            burst_i += 1;
                            with_burst_msg(i, |msg, src| {
                                self.record_touched(src, msg, now, &mut touched);
                            });
                            drained += 1;
                            continue;
                        }
                        match recv_burst(&listener, LAST_HOP_DRAIN - drained) {
                            Some(0) => break,
                            Some(k) => {
                                burst_n = k;
                                burst_i = 1;
                                with_burst_msg(0, |msg, src| {
                                    self.record_touched(src, msg, now, &mut touched);
                                });
                                drained += 1;
                            }
                            None => match listener.try_recv_from(&mut buf) {
                                Ok((n, src)) => {
                                    self.record_touched(src, &buf[..n], now, &mut touched);
                                    drained += 1;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => break,
                            },
                        }
                    }
                    // Connection-scoped dashboard: all sessions' small payloads
                    // staged on these bindings go out together.
                    for b in touched.drain(..) {
                        drain_assoc_stage(&self.egress, &self.pool, b);
                    }
                    record_drain_batch(drained);
                }
                _ = idle_tick.tick() => {
                    self.sweep_idle(mono_millis());
                }
                _ = shutdown.changed() => break,
            }
        }
        self.shutdown_all();
        assoc_recycle_buf(buf);
    }

    /// Validate one inbound datagram's length, then count it as a touch of the
    /// binding its session used. Split out so the burst arms share exactly one
    /// length predicate ([`ASSOC_RECV_BUF_LEN`], the SOCKS association buffer,
    /// which is > the protocol payload cap).
    fn record_touched(
        &mut self,
        src: SocketAddr,
        payload: &[u8],
        now: u64,
        touched: &mut Vec<UdpBind>,
    ) {
        if payload.len() >= ASSOC_RECV_BUF_LEN {
            let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            dgram_drops::warn_oversize_recv(
                dgram_drops::OversizeRecv::AppDatagram,
                dropped,
                || {
                    format!(
                        "; udp_forward {}, peer {src}, {} B buffer",
                        display_target(&self.target),
                        payload.len()
                    )
                },
            );
            return;
        }
        if let Some(b) = self.handle_datagram(src, payload, now)
            && !touched.contains(&b)
        {
            touched.push(b);
        }
    }
}

/// Whether a `recv_from` error on a UDP forward listener is a **transient
/// asynchronous error** that must not end the listener.
///
/// Linux `udp(7)`: "All fatal errors will be passed to the user as an error
/// return even when the socket is not connected." A forward listener writes
/// replies to peers that may close at any moment; the resulting ICMP
/// port-unreachable surfaces on the *listener* socket as `ECONNREFUSED` on a
/// later `recv_from`. Ending the task there would stop forwarding for every
/// other peer until process restart, while SOCKS (a different socket) kept
/// serving — a silent, configuration-shaped outage. Only a genuinely broken
/// socket ends the listener.
pub(crate) fn forward_recv_error_is_transient(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
    )
}

/// One-per-window accounting for "cannot open/keep a forward peer session" and
/// for the listener's own recv failure. One slot per listener task is not
/// needed: a process with several UDP forward listeners is a handful of lines
/// per window at worst.
fn claim_forward_udp_refused_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

fn claim_forward_udp_recv_failed_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}
