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
///
/// `forward_budget` is the process-wide cap on concurrent sessions across
/// **all** UDP forward listeners (one semaphore survives for the client's
/// lifetime, see `main`). Admission is three-level, each permit held for the
/// peer session's lifetime:
///
/// 1. `spec.max_sessions`, this listener's own policy cap;
/// 2. `forward_budget`, the feature-wide cap, so the forwarding feature cannot
///    consume the process session budget SOCKS5 `UDP ASSOCIATE` also uses
///    (default: 3/4 of `max_udp_assocs`, leaving a SOCKS reserve);
/// 3. the shared [`UdpHub`] slot, which is SOCKS's own budget too. Only the
///    residual (at most 1/4 by default) can ever be taken from SOCKS.
///
/// When a level refuses a *new source*, the listener first tries to evict its
/// own oldest peer that has been idle for [`EVICT_MIN_IDLE_MS`] — a churn
/// workload (DNS-style ephemeral source ports) could otherwise hold the session
/// cap until the 180 s idle reap and refuse every new peer in the meantime.
pub(crate) fn spawn_udp_forward(
    spec: UdpForwardSpec,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    forward_budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listen = spec.listen;
    let raw = udp_socket_dual(&listen.to_string())
        .with_context(|| format!("forward UDP listener {listen}"))?;
    let listener = Arc::new(tokio::net::UdpSocket::from_std(raw)?);
    if !listen_is_loopback(listen) {
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
        forward_budget,
        last_evict_scan_ms: 0,
        peers: HashMap::default(),
    };
    Ok(tokio::spawn(async move { fwd.run(shutdown).await }))
}

/// One live per-peer UDP session.
///
/// The `hub` reference and the `_fwd_permit` exist so this struct's [`Drop`]
/// gives **both** process-wide slots back on *every* exit path (idle sweep,
/// admission eviction, shutdown, a panicking listener task in dev/test
/// unwinds): `UdpHub::alloc_sess` reserves exactly one hub slot (one `release`
/// per successful allocation) and `forward_budget.try_acquire_owned` reserves
/// one feature-wide session permit. Field drop order releases the semaphore
/// permit automatically after `drop()` runs.
pub(crate) struct PeerSession {
    pub(crate) sess: u32,
    hub: Arc<UdpHub>,
    /// Process-wide forward-session budget permit (see [`spawn_udp_forward`]),
    /// held for exactly as long as this peer session exists.
    _fwd_permit: tokio::sync::OwnedSemaphorePermit,
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
    /// Process-wide forward-session budget shared by every UDP forward listener
    /// (not one semaphore per listener: the cap is a feature-wide, process-wide
    /// resource — see [`spawn_udp_forward`]).
    forward_budget: Arc<tokio::sync::Semaphore>,
    /// Monotonic ms (`now` epoch, supplied by [`Self::handle_datagram`]) of the
    /// last admission-eviction scan. A refused datagram may trigger an
    /// O(peers) scan only once per [`EVICT_SCAN_INTERVAL_MS`], so a
    /// spoofed-source flood against a full table of fresh (non-evictable) peers
    /// cannot turn every O(1) refusal into a whole-table walk. `0` lets the
    /// first refusal scan (the mono epoch starts near zero).
    last_evict_scan_ms: u64,
    peers: HashMap<SocketAddr, PeerSession, foldhash::fast::RandomState>,
}

impl UdpForwarder {
    /// Test-only constructor: production builds this in [`spawn_udp_forward`]
    /// from a bound listener, so tests can drive [`Self::handle_datagram`] and
    /// the sweep against a real socket and a published egress handle.
    ///
    /// Uses the full process-wide budget (`MAX_UDP_ASSOCS` permits), i.e. the
    /// pre-forward-budget behaviour, so the existing lifecycle/cap tests keep
    /// exercising the hub limit rather than the aggregate budget. Use
    /// [`Self::for_test_with_budget`] to exercise the budget itself.
    #[cfg(test)]
    pub(crate) fn for_test(
        listener: Arc<tokio::net::UdpSocket>,
        target: TargetAddr,
        max_sessions: usize,
        pool: ConnPool,
        hub: Arc<UdpHub>,
        egress: Arc<SharedEgress>,
    ) -> Self {
        Self::for_test_with_budget(
            listener,
            target,
            max_sessions,
            pool,
            hub,
            egress,
            Arc::new(tokio::sync::Semaphore::new(MAX_UDP_ASSOCS)),
        )
    }

    /// [`Self::for_test`] with an explicit process-wide forward-session budget.
    #[cfg(test)]
    pub(crate) fn for_test_with_budget(
        listener: Arc<tokio::net::UdpSocket>,
        target: TargetAddr,
        max_sessions: usize,
        pool: ConnPool,
        hub: Arc<UdpHub>,
        egress: Arc<SharedEgress>,
        forward_budget: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            listener,
            target,
            max_sessions,
            pool,
            hub,
            egress,
            forward_budget,
            last_evict_scan_ms: 0,
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
    /// Steady state pays **one** peer-table hash probe: the `get_mut` hit is the
    /// fast path; only a miss allocates (`create_peer`) and re-probes. (The
    /// pre-fix shape did `contains_key` *then* `get_mut`, i.e. two probes on
    /// every datagram, contradicting plan §11.)
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
        // Fast path: the peer exists. Borrow the disjoint fields directly so a
        // hit never re-borrows `self` after the lookup.
        if let Some(peer) = self.peers.get_mut(&src) {
            return send_peer_payload(
                &self.pool,
                &self.egress,
                &self.target.as_ref(),
                payload,
                now,
                peer,
            );
        }
        if let Err(refusal) = self.create_peer(src, now) {
            // Accounting lives here, not in `create_peer`, so the admission
            // mechanics (including eviction) are testable without touching the
            // process-wide drop counters other tests assert exact deltas on.
            self.note_peer_refusal(src, refusal);
            return None;
        }
        let peer = self.peers.get_mut(&src)?;
        send_peer_payload(
            &self.pool,
            &self.egress,
            &self.target.as_ref(),
            payload,
            now,
            peer,
        )
    }

    /// Admit a new peer source, with one eviction attempt when a limit refuses
    /// it.
    ///
    /// Order matters: a listener-cap or forward-budget refusal must spend no
    /// shared permit, and the hub probe comes last. A refusal is retried once
    /// after displacing this listener's oldest peer that has been idle for at
    /// least [`EVICT_MIN_IDLE_MS`] — that is what keeps an ephemeral-source
    /// workload from dead-ending on the session cap until the 180 s idle reap.
    /// The eviction scan itself is throttled to one per
    /// [`EVICT_SCAN_INTERVAL_MS`] ([`Self::evict_one_idle`]): a throttled scan
    /// is simply a refusal, so the retry runs only after a real eviction. The
    /// *retry's* verdict is reported when eviction ran, because after freeing
    /// one peer a different level may be the binding constraint.
    fn create_peer(&mut self, src: SocketAddr, now: u64) -> Result<(), PeerRefusal> {
        match self.try_admit_peer(src) {
            Ok(()) => Ok(()),
            Err(refusal) => {
                if !self.evict_one_idle(now) {
                    return Err(refusal);
                }
                self.try_admit_peer(src)
            }
        }
    }

    /// The three admission levels, in order. Returns an un-counted refusal
    /// reason; the caller ([`Self::handle_datagram`]) owns drop accounting.
    fn try_admit_peer(&mut self, src: SocketAddr) -> Result<(), PeerRefusal> {
        // (a) This listener's own policy cap: no shared permit is spent on a
        // refusal the configured `max_sessions` already dictates.
        if self.peers.len() >= self.max_sessions {
            return Err(PeerRefusal::ListenerCap);
        }
        // (b) The process-wide feature budget shared by every UDP forward
        // listener. A refusal here leaves the SOCKS reserve untouched.
        let fwd_permit = match self.forward_budget.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return Err(PeerRefusal::ForwardBudget),
        };
        // (c) The shared association hub, whose budget SOCKS also uses. Drop the
        // forwarding permit first: an eviction frees both slots, and the retry
        // re-acquires them; holding the permit across the failed attempt would
        // put it back only after the retry had already decided.
        let sess = match self.hub.alloc_sess() {
            Some(s) => s,
            None => {
                drop(fwd_permit);
                return Err(PeerRefusal::HubFull);
            }
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
                _fwd_permit: fwd_permit,
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
        Ok(())
    }

    /// Displace this listener's single oldest peer, if it has been silent in
    /// both directions for at least [`EVICT_MIN_IDLE_MS`].
    ///
    /// Eviction is the cap-pressure valve: without it a listener whose table is
    /// full (churn, spoofed sources) refuses every new source until the 180 s
    /// idle sweep runs, even though most held sessions are long dead.
    ///
    /// The scan folds pending reply activity exactly like the idle sweep's tick
    /// ([`AssocEntry::idle_since_tick`]): a set [`AssocEntry::replied`] flag is
    /// reply activity the 30 s idle tick has not folded into `last` yet, so it
    /// is consumed and `last` is stamped with `now`, which keeps a receive-only
    /// flow from being evicted while it is still receiving. Folding (rather
    /// than merely skipping flagged peers) is what makes the valve responsive:
    /// a peer whose last reply arrived just before the 30 s tick would
    /// otherwise stay unevictable for up to a full tick after the 5 s floor had
    /// already passed. Removing the entry runs [`PeerSession::drop`], which
    /// returns the hub slot and the budget permit; `send_sess_close` tells the
    /// server to drop the session now (best effort, exactly like the idle
    /// sweep).
    ///
    /// Returns `true` when a peer was removed. The scan itself is throttled:
    /// a call inside [`EVICT_SCAN_INTERVAL_MS`] of the previous scan returns
    /// `false` without touching the table, which the caller treats as an
    /// ordinary refusal (no retry).
    fn evict_one_idle(&mut self, now: u64) -> bool {
        // Throttle *before* any per-peer work: this is the difference between a
        // cheap refusal and the eviction feature becoming its own DoS vector
        // (see [`EVICT_SCAN_INTERVAL_MS`]).
        if now.saturating_sub(self.last_evict_scan_ms) < EVICT_SCAN_INTERVAL_MS {
            return false;
        }
        self.last_evict_scan_ms = now;
        let mut victim: Option<(SocketAddr, u64)> = None;
        for (src, peer) in &self.peers {
            // Same fold the idle sweep uses: consume a pending `replied` flag
            // (that is activity the 30 s tick has not folded into `last` yet,
            // because the reply path deliberately takes no clock), stamping
            // `last` with `now` so a receive-only flow is never treated as idle
            // on activity the tick has not seen. Folding here matters for
            // latency: a flagged peer that is merely skipped stays unevictable
            // until the next idle tick even when it has been reply-idle for far
            // longer than the floor.
            if !peer.entry.idle_since_tick(now, EVICT_MIN_IDLE_MS) {
                continue;
            }
            let idle = peer.entry.idle_ms(now);
            if victim.is_none_or(|(_, oldest)| idle > oldest) {
                victim = Some((*src, idle));
            }
        }
        let Some((src, idle)) = victim else {
            return false;
        };
        let Some(peer) = self.peers.remove(&src) else {
            return false;
        };
        send_sess_close(
            &self.egress,
            &self.pool,
            peer.bind,
            peer.sess,
            peer.uplink.epoch,
        );
        tracing::debug!(
            "udp_forward {} peer {src}: session {} evicted after {idle} ms idle to admit a new source",
            display_target(&self.target),
            peer.sess
        );
        true
    }

    /// Count and rate-limit-log one refused new peer, naming the limit that
    /// refused it. One log window per limit kind, so a listener-cap flood
    /// cannot hide a feature-budget or hub exhaustion line (the operator's
    /// action differs per kind).
    fn note_peer_refusal(&self, src: SocketAddr, refusal: PeerRefusal) {
        let target = display_target(&self.target);
        match refusal {
            PeerRefusal::ListenerCap => {
                let n = dgram_drops::bump(&dgram_drops::REFUSED);
                if let Some(sup) = claim_forward_udp_listener_cap_log() {
                    warn!(
                        "udp_forward {target} listener session limit {} reached; \
                         dropping datagram from {src} ({n} so far){sup}",
                        self.max_sessions
                    );
                }
            }
            PeerRefusal::ForwardBudget => {
                let n = dgram_drops::bump(&dgram_drops::REFUSED);
                if let Some(sup) = claim_forward_udp_forward_budget_log() {
                    warn!(
                        "udp_forward {target} process-wide forward session budget exhausted; \
                         dropping datagram from {src} ({n} so far){sup}"
                    );
                }
            }
            PeerRefusal::HubFull => {
                let n = dgram_drops::bump(&dgram_drops::SESSION_FULL);
                if let Some(sup) = claim_forward_udp_hub_log() {
                    warn!(
                        "udp_forward {target} sessions exhausted (max_udp_assocs); \
                         dropping datagram from {src} ({n} so far){sup}"
                    );
                }
            }
        }
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
        // Consecutive transient receive errors since the last good datagram.
        // An ICMP error is consumed by the syscall that reports it, so the
        // socket is live on the next call: the listener must retry immediately
        // instead of sleeping (the old unconditional 20 ms sleep stalled every
        // peer once per error, and a churn workload could hold the whole
        // listener down). Only a *persistent* error may need a real yield, and
        // only once per 32 attempts, so a broken-but-not-fatal socket cannot
        // spin a worker with no timeslice for other tasks.
        let mut consecutive_recv_errors: u32 = 0;
        loop {
            tokio::select! {
                r = listener.recv_from(&mut buf) => {
                    let (n, src) = match r {
                        Ok(x) => {
                            consecutive_recv_errors = 0;
                            x
                        }
                        Err(e) if recv_error_is_transient(&e) => {
                            // Peer churn delivers ICMP errors to the listener
                            // socket (see `recv_error_is_transient`), and a
                            // RAM-tight kernel can report ENOBUFS: warn once per
                            // window (its own slot; see the fatal arm) and keep
                            // serving everyone.
                            consecutive_recv_errors = consecutive_recv_errors.wrapping_add(1);
                            if let Some(sup) = claim_forward_udp_recv_transient_log() {
                                warn!(
                                    "udp_forward {} receive transient error ({} consecutive): \
                                     {e:#}; listener continues{sup}",
                                    display_target(&self.target),
                                    consecutive_recv_errors
                                );
                            }
                            if (consecutive_recv_errors & 31) == 0 {
                                tokio::task::yield_now().await;
                            }
                            continue;
                        }
                        Err(e) => {
                            // Not a recoverable asynchronous error: the socket
                            // itself is unusable, and every other listener /
                            // SOCKS keeps its own socket. Own log slot: this
                            // line must never be suppressed by a transient warn.
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

/// Send one datagram through an existing peer session, returning the egress
/// binding it was sent on (for the caller's once-per-burst stager drain).
///
/// Free function taking the disjoint field refs: `handle_datagram` must hold
/// the peer-table `get_mut` borrow while borrowing the immutable listener
/// fields, and re-borrowing `self` there would force the steady path back to
/// two hash probes.
fn send_peer_payload(
    pool: &ConnPool,
    egress: &SharedEgress,
    target: &TargetAddrRef<'_>,
    payload: &[u8],
    now: u64,
    peer: &mut PeerSession,
) -> Option<UdpBind> {
    // Same 1 Hz-throttled liveness stamp as a SOCKS association: the idle
    // sweep (and the admission eviction) reaps on bidirectional silence only.
    peer.entry.touch(now);
    send_payload_uplink(
        pool,
        egress,
        peer.sess,
        target,
        payload,
        &mut peer.bind,
        &mut peer.uplink,
        &mut peer.frag,
        now,
        SessionKind::Forward,
    );
    peer.bind
}

/// Which admission level refused a new peer source (see
/// [`UdpForwarder::try_admit_peer`]). The caller maps it to a drop counter and a
/// rate-limited warn line that names the limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerRefusal {
    /// This listener's `max_sessions` (config policy).
    ListenerCap,
    /// The process-wide budget shared by all UDP forward listeners.
    ForwardBudget,
    /// The shared [`UdpHub`] budget (the same one SOCKS `UDP ASSOCIATE` uses).
    HubFull,
}

/// Minimum bidirectional silence before a new source may displace this
/// listener's oldest peer when an admission limit refuses it.
///
/// Long enough that an active session (or one whose replies are still arriving;
/// `idle_ms` folds the dispatcher's `replied` flag into `last`) is never
/// evicted for a newcomer, short enough that an ephemeral-source workload
/// (DNS/TFTP/one-shot clients: one new `IP:port` per exchange) is not
/// dead-ended at the cap until the 180 s idle reap. 5 s is a conservative
/// "nothing has used this session recently" floor; the reap window itself
/// (`ASSOC_IDLE_MS`) is unchanged.
pub(crate) const EVICT_MIN_IDLE_MS: u64 = 5_000;

/// Minimum spacing between admission-eviction scans, measured on the caller's
/// `now` epoch.
///
/// The scan is O(peers), so it must not run per refused datagram: a
/// spoofed-source flood that keeps the table full of **fresh** (< 5 s idle,
/// therefore non-evictable) peers would otherwise walk every entry on each
/// refusal and saturate the listener task, stalling all its other peers — a DoS
/// regression the eviction feature itself would introduce over the previous
/// O(1) refusal. 100 ms bounds the extra work to at most 10 scans/s per
/// listener (≈30 k `idle_ms` loads/s at the default 3024-peer cap). In
/// production `now` is the coarse clock (`coarse_millis`, refreshed on a 1 s
/// tick), so the practical rate is at most one scan per tick; precise/time-
/// injected callers get the stated 100 ms floor. A legitimate new peer that
/// meets a table of genuinely idle peers is still admitted by the first scan
/// after the interval: throttling only *delays* a scan, and a peer cannot
/// become evictable before [`EVICT_MIN_IDLE_MS`] anyway (50× this interval).
pub(crate) const EVICT_SCAN_INTERVAL_MS: u64 = 100;

/// Whether a `recv_from` error on a UDP forward listener is a **transient
/// asynchronous error** that must not end the listener.
///
/// Linux `udp(7)`: "All fatal errors will be passed to the user as an error
/// return even when the socket is not connected. This includes asynchronous
/// errors received from the network. You may get an error for an earlier packet
/// that was sent on the same socket." A forward listener writes replies to peers
/// that may close at any moment; the resulting ICMP port-unreachable surfaces on
/// the *listener* socket as `ECONNREFUSED` on a later `recv_from`. Ending the
/// task there would stop forwarding for every other peer until process restart,
/// while SOCKS (a different socket) kept serving — a silent,
/// configuration-shaped outage.
///
/// `OutOfMemory` is here because `ENOMEM` maps to it in std (the kernel could
/// not allocate the skb / socket memory for this datagram): a resource
/// condition is retried like ICMP rather than treated as a broken socket. See
/// [`recv_error_is_transient`] for the raw codes std does not map.
pub(crate) fn forward_recv_error_is_transient(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::OutOfMemory
    )
}

/// [`forward_recv_error_is_transient`] for a full `std::io::Error`, adding the
/// raw OS codes std leaves uncategorized.
///
/// `ENOBUFS` (no kernel buffers available for this receive) has no
/// `ErrorKind` mapping in std, so classifying on `kind()` alone treated a
/// transient memory-pressure condition as a permanently broken socket and
/// stopped the whole listener. It is retried here like ICMP: the next
/// `recv_from` is the retry. `ENOMEM` is checked raw as well as through
/// `ErrorKind::OutOfMemory` so a platform whose std does not map it still
/// classifies correctly. Other targets classify by kind only.
pub(crate) fn recv_error_is_transient(e: &std::io::Error) -> bool {
    if forward_recv_error_is_transient(e.kind()) {
        return true;
    }
    #[cfg(unix)]
    {
        use rustix::io::Errno;
        if let Some(raw) = e.raw_os_error()
            && (raw == Errno::NOBUFS.raw_os_error() || raw == Errno::NOMEM.raw_os_error())
        {
            return true;
        }
    }
    false
}

/// One rate-limited log window per *fault kind*.
///
/// Each kind gets its own pair of statics: a listener-cap flood must not hide a
/// feature-budget line, and — most importantly — a **transient** recv warn must
/// never suppress the **fatal** "listener stopped" line within the same 1 s
/// window. (They used to share one slot, so the only line saying the listener
/// had died could be swallowed by a retry that happened a millisecond earlier.)
/// One slot per process is enough: several UDP listeners are a handful of lines
/// per window at worst.
macro_rules! forward_log_window {
    ($fn_name:ident, $why:literal) => {
        #[doc = $why]
        fn $fn_name() -> Option<Suppressed> {
            static LAST: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
            static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
        }
    };
}

forward_log_window!(
    claim_forward_udp_listener_cap_log,
    "Per-listener session-cap refusals (raise this listener's `max_sessions`)."
);
forward_log_window!(
    claim_forward_udp_forward_budget_log,
    "Process-wide forward-session budget refusals (raise `max_forward_sessions`)."
);
forward_log_window!(
    claim_forward_udp_hub_log,
    "Shared `UdpHub` exhaustion refusals (the SOCKS `UDP ASSOCIATE` budget)."
);
forward_log_window!(
    claim_forward_udp_recv_transient_log,
    "Transient receive errors that were retried (a separate slot from the fatal one)."
);
forward_log_window!(
    claim_forward_udp_recv_failed_log,
    "The fatal receive error that stopped the listener."
);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_listener() -> Arc<tokio::net::UdpSocket> {
        Arc::new(
            tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap())
                .expect("register test listener"),
        )
    }

    fn test_forwarder(budget: usize, max_sessions: usize) -> UdpForwarder {
        UdpForwarder::for_test_with_budget(
            test_listener(),
            TargetAddr::Ip("198.51.100.9:53".parse().unwrap()),
            max_sessions,
            ConnPool::new(2, Vec::new(), true, true, 1),
            Arc::new(UdpHub::new()),
            Arc::new(SharedEgress::default()),
            Arc::new(tokio::sync::Semaphore::new(budget)),
        )
    }

    fn peer_src(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// The feature-wide budget is a lifetime permit: it refuses the
    /// (budget+1)-th *live* peer, and dropping any one peer returns the permit
    /// so the next source is admitted. The listener cap is deliberately larger
    /// here, so the budget (not `max_sessions`) is the binding limit.
    ///
    /// Drives `create_peer` directly: it is the complete admission path
    /// (listener cap → budget → hub, plus one eviction retry), and this way the
    /// test bumps **no** global drop counters — the per-datagram send path would
    /// book `NO_EGRESS` and race tests.rs's exact-delta counter assertions.
    #[tokio::test]
    async fn forward_budget_refuses_extra_peers_and_releases_on_drop() {
        const BUDGET: usize = 2;
        let mut fwd = test_forwarder(BUDGET, MAX_UDP_ASSOCS);
        let now = mono_millis();
        let (a, b, c) = (peer_src(30_001), peer_src(30_002), peer_src(30_003));

        assert_eq!(fwd.create_peer(a, now), Ok(()));
        assert_eq!(fwd.create_peer(b, now), Ok(()));
        assert_eq!(fwd.forward_budget.available_permits(), 0);
        assert_eq!(fwd.peer_count(), 2);

        // Budget exhausted, nobody idle long enough to evict.
        assert_eq!(
            fwd.create_peer(c, now),
            Err(PeerRefusal::ForwardBudget),
            "the (budget+1)-th live peer must be refused"
        );
        assert_eq!(fwd.peer_count(), 2, "a refusal must not install a session");
        assert!(fwd.peer_sess(c).is_none());

        // Dropping one peer is dropping its permit (PeerSession::drop), so the
        // next source can be admitted again.
        assert!(fwd.peers.remove(&a).is_some());
        assert_eq!(fwd.forward_budget.available_permits(), 1);
        assert_eq!(fwd.create_peer(c, now), Ok(()));
        assert!(fwd.peer_sess(c).is_some());
        assert_eq!(fwd.forward_budget.available_permits(), 0);
        assert_eq!(fwd.hub.len.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// A full listener does not dead-end on churn: a source that is refused by
    /// the per-listener cap may displace this listener's oldest peer once that
    /// peer has been idle for `EVICT_MIN_IDLE_MS` — and a *fresh* peer is never
    /// evicted for a newcomer.
    #[tokio::test]
    async fn listener_cap_evicts_only_a_peer_idle_past_the_floor() {
        let mut fwd = test_forwarder(MAX_UDP_ASSOCS, 1);
        let t0 = mono_millis();
        let (a, b) = (peer_src(30_011), peer_src(30_012));
        assert_eq!(fwd.create_peer(a, t0), Ok(()));

        // Fresh session: refused, and the live peer is untouched. `now` for the
        // synthetic clock may be below the scan interval (process uptime), so
        // open the throttle window explicitly.
        fwd.last_evict_scan_ms = t0.saturating_sub(EVICT_SCAN_INTERVAL_MS);
        assert_eq!(
            fwd.create_peer(b, t0),
            Err(PeerRefusal::ListenerCap),
            "a fresh peer must not be displaced"
        );
        assert!(fwd.peer_sess(a).is_some());
        assert!(fwd.peer_sess(b).is_none());
        assert_eq!(fwd.peer_count(), 1);

        // Same source, later: the victim is now past the floor, but a pending
        // (not yet folded) reply flag is live activity. The scan folds it into
        // `last = later` and must keep the peer — the receive-only-flow guard.
        let later = t0 + EVICT_MIN_IDLE_MS + 1_000;
        fwd.last_evict_scan_ms = later.saturating_sub(EVICT_SCAN_INTERVAL_MS);
        fwd.peers
            .get(&a)
            .unwrap()
            .entry
            .replied
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            fwd.create_peer(b, later),
            Err(PeerRefusal::ListenerCap),
            "reply activity the idle tick has not folded yet must keep the peer"
        );
        assert!(fwd.peer_sess(a).is_some());

        // The scan folded that activity into the stamp, so the peer is not
        // evictable until another floor interval has passed. Then the next
        // attempt evicts the now-idle victim and admits the new source (one
        // eviction + one retry). Re-open the throttle window: the guard attempt
        // above already spent it at `later`.
        let after = later + EVICT_MIN_IDLE_MS + 1;
        fwd.last_evict_scan_ms = after.saturating_sub(EVICT_SCAN_INTERVAL_MS);
        assert_eq!(fwd.create_peer(b, after), Ok(()));
        assert!(
            fwd.peer_sess(a).is_none(),
            "the idle peer must be evicted to admit a waiting source"
        );
        assert!(fwd.peer_sess(b).is_some());
        assert_eq!(
            fwd.peer_count(),
            1,
            "eviction keeps the listener at its cap"
        );
        // The evicted session's shared slots were returned, not leaked.
        assert_eq!(fwd.hub.len.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(fwd.forward_budget.available_permits(), MAX_UDP_ASSOCS - 1);
    }

    /// The admission-eviction scan is throttled: a spoofed-source flood that
    /// keeps the table full of peers that are not evictable yet must not make
    /// every refused datagram walk the whole peer table (the eviction feature's
    /// own DoS regression). Two refusals inside one interval do no scan and no
    /// eviction; after the interval the next refusal scans, evicts the idle
    /// victim and runs the usual one retry.
    #[tokio::test]
    async fn eviction_scan_is_throttled_against_a_refusal_flood() {
        let mut fwd = test_forwarder(MAX_UDP_ASSOCS, 1);
        let t0 = mono_millis();
        let (full, b) = (peer_src(30_021), peer_src(30_022));
        assert_eq!(fwd.create_peer(full, t0), Ok(()));

        // The victim is already past the eviction floor, so an *un-throttled*
        // scan would evict it; pretending a scan just ran models the flood
        // steady state, where every refusal arrives inside some interval.
        let later = t0 + EVICT_MIN_IDLE_MS + 1_000;
        fwd.last_evict_scan_ms = later;
        assert_eq!(fwd.create_peer(b, later), Err(PeerRefusal::ListenerCap));
        assert_eq!(
            fwd.last_evict_scan_ms, later,
            "a throttled scan must not move the stamp (it did no work)"
        );
        let inside = later + EVICT_SCAN_INTERVAL_MS / 2;
        assert_eq!(
            fwd.create_peer(b, inside),
            Err(PeerRefusal::ListenerCap),
            "the second refusal inside the interval must be refused cheaply"
        );
        assert!(
            fwd.peer_sess(full).is_some(),
            "no eviction while the scan is throttled"
        );
        assert!(fwd.peer_sess(b).is_none());

        // The interval has passed: the scan runs, the idle victim is evicted and
        // the waiting source is admitted (admission + retry semantics intact).
        let after = later + EVICT_SCAN_INTERVAL_MS + 1;
        assert_eq!(fwd.create_peer(b, after), Ok(()));
        assert!(fwd.peer_sess(full).is_none());
        assert!(fwd.peer_sess(b).is_some());
        assert_eq!(fwd.last_evict_scan_ms, after);
        assert_eq!(fwd.hub.len.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// The widened transient taxonomy: ICMP/resource errors keep the listener
    /// alive (including `ENOBUFS`/`ENOMEM`, which std does not map to a distinct
    /// `ErrorKind`), while genuinely broken-socket kinds stay fatal.
    #[test]
    fn recv_error_classification_covers_resource_errors_but_not_broken_sockets() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::Interrupted,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::TimedOut,
            ErrorKind::OutOfMemory,
        ] {
            assert!(
                forward_recv_error_is_transient(kind),
                "{kind:?} must be retried, not treated as fatal"
            );
            assert!(
                recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?} must be retried through the full-error classifier too"
            );
        }
        #[cfg(unix)]
        {
            use rustix::io::Errno;
            for errno in [Errno::NOBUFS, Errno::NOMEM] {
                let e = std::io::Error::from_raw_os_error(errno.raw_os_error());
                assert!(
                    recv_error_is_transient(&e),
                    "raw {errno:?} must be transient, not fatal"
                );
            }
        }
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::NotConnected,
            ErrorKind::AddrNotAvailable,
            ErrorKind::PermissionDenied,
        ] {
            assert!(
                !forward_recv_error_is_transient(kind),
                "{kind:?} means the socket itself is unusable"
            );
            assert!(
                !recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?} means the socket itself is unusable"
            );
        }
    }
}
