//! Config-driven TCP forward listeners: raw TCP in, QUIC bidi stream out.
//!
//! This is the SOCKS5 `CONNECT` path with the negotiation and the SOCKS replies
//! removed: every accepted stream opens one QUIC bidirectional stream, writes
//! the target `AddrHeader`, and relays bytes with the existing
//! [`copy_tcp_quic_acked`] pump. The server needs no change — it already reads
//! a header, resolves/policy-checks the target, dials it and writes the MQP
//! dial ACK.
//!
//! The UDP half lives in `forward_udp.rs`; startup/validation lives in
//! `main.rs` (see `ClientConf::tcp_forwards` / `ClientConf::udp_forwards`).
use super::*;

/// Idle deadline of one forwarded TCP stream. Matches the SOCKS relay's 300 s
/// so a forwarded connection never outlives its SOCKS equivalent for the same
/// application protocol.
const FORWARD_TCP_IDLE: Duration = Duration::from_secs(300);

/// Budget for one step of establishing a forwarded stream (slot wait, stream
/// open, header write), mirroring the SOCKS path's 5 s stream-open timeout.
const FORWARD_TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a TCP forward listener on `spec.listen`, relaying every accepted
/// stream to `spec.target`.
///
/// The bind completes before the task is spawned: a listener that cannot bind
/// fails client startup instead of silently serving one fewer port (the whole
/// feature would otherwise look healthy while doing nothing for that entry).
///
/// Admission is three-level, each permit held for the flow's lifetime:
/// 1. `spec.max_conns`, this listener's own cap;
/// 2. `forward_budget`, the process-wide budget shared by every
///    `[[tcp_forward]]` listener (default 3/4 of the relay cap), so forwarding
///    as a feature cannot take the whole TCP relay pool from SOCKS;
/// 3. the shared SOCKS relay semaphore ([`socks_conn_limiter`]), the same
///    process-wide 8192 flow ceiling the SOCKS accept loop uses.
///
/// Acquiring in that order means a listener-local or feature-wide refusal
/// spends no shared permit, and the shared semaphore's own refusal can only
/// happen when SOCKS/other forward traffic already owns the rest.
pub(crate) fn spawn_tcp_forward(
    spec: TcpForwardSpec,
    pool: ConnPool,
    egress: Arc<SharedEgress>,
    timeout: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    forward_budget: Arc<tokio::sync::Semaphore>,
    relay_limiter: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listen = spec.listen;
    let target = spec.target;
    let max_conns = spec.max_conns;
    // Context on the *bind*: with several configured forwards, a bare
    // EADDRINUSE must still name which listener failed.
    let raw = tcp_listener_dual(&listen.to_string())
        .with_context(|| format!("bind forward TCP listener {listen}"))?;
    let li = tokio::net::TcpListener::from_std(raw)
        .with_context(|| format!("register forward TCP listener {listen}"))?;
    if !listen_is_loopback(listen) {
        warn!(
            "tcp_forward listen {listen} is not loopback: any host that can reach it can use \
             the tunnel to {}; bind 127.0.0.1 or firewall the port",
            display_target(&target)
        );
    }
    // Per-listener cap. A separate semaphore (not a counter) so the permit
    // lifetime is the connection's lifetime: `try_acquire_owned` in the accept
    // loop, one permit moved into the relay task and dropped when it ends.
    let admission = TcpAdmission {
        listener: Arc::new(tokio::sync::Semaphore::new(max_conns)),
        forward_budget,
        relay: relay_limiter,
    };
    Ok(tokio::spawn(async move {
        loop {
            let (sock, peer) = tokio::select! {
                accepted = li.accept() => match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        // Transient errors (EMFILE/ECONNABORTED) must kill this
                        // listener only, never the proxy. The 50 ms pause keeps
                        // an fd-exhausted accept loop from spinning, exactly
                        // like the SOCKS listener in `main.rs`.
                        if let Some(sup) = claim_forward_accept_failed_log() {
                            warn!("tcp_forward {listen} accept failed: {e:#}; continuing{sup}");
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                _ = shutdown.changed() => break,
            };
            // Admission before the relay-TCP tuning: a connection that will be
            // refused must not pay `setsockopt` work it never uses.
            let permits = match admission.try_admit() {
                Ok(p) => p,
                Err(refusal) => {
                    warn_forward_refusal(refusal, listen, peer, max_conns);
                    // A forward listener has no SOCKS reply channel to carry
                    // the failure: close with RST so the app sees an explicit
                    // failure, not a clean empty response (the pump's rule).
                    abort_tcp(&sock);
                    continue;
                }
            };
            // Same relay-TCP posture as the SOCKS socket: nodelay plus (on
            // Linux) TCP_NOTSENT_LOWAT, so the kernel send buffer cannot stack
            // unsent bytes ahead of the QUIC stream that already paces this
            // flow.
            linux::tune_relay_tcp(&sock);
            let pool = pool.clone();
            let egress = egress.clone();
            let target = target.clone();
            tokio::spawn(async move {
                // All three permits live exactly as long as the relay task.
                let _permits = permits;
                if let Err(e) = relay_tcp_forward(sock, target, pool, egress, timeout).await {
                    warn_forward_end(peer, listen, &e);
                }
            });
        }
    }))
}

/// The three semaphores one forward listener admits against, in acquisition
/// order (per-listener -> process-wide forward budget -> shared relay cap).
///
/// Split out of [`spawn_tcp_forward`] so the permit lifecycle — the whole point
/// of the T-01 fix — is unit-testable with small semaphores instead of the
/// 8192-permit process singletons.
struct TcpAdmission {
    listener: Arc<tokio::sync::Semaphore>,
    forward_budget: Arc<tokio::sync::Semaphore>,
    relay: Arc<tokio::sync::Semaphore>,
}

/// All three permits for one forwarded connection, held in this order.
type TcpPermits = (
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
);

/// Which admission level refused a forwarded connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpRefusal {
    /// This listener's own `max_conns` cap.
    Listener,
    /// The process-wide `[[tcp_forward]]` budget.
    ForwardBudget,
    /// The shared SOCKS/forward relay semaphore is fully held.
    SharedRelay,
}

impl TcpAdmission {
    /// Acquire one permit from each level, in order.
    ///
    /// Every `Err` returns after the already-acquired permits have been dropped
    /// with this stack frame (`OwnedSemaphorePermit` releases on drop), so a
    /// refusal at level 2 or 3 can never leak a level-1/2 permit, and the
    /// caller never has to unwind manually.
    fn try_admit(&self) -> Result<TcpPermits, TcpRefusal> {
        let listener = self
            .listener
            .clone()
            .try_acquire_owned()
            .map_err(|_| TcpRefusal::Listener)?;
        let forward = self
            .forward_budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| TcpRefusal::ForwardBudget)?;
        let relay = self
            .relay
            .clone()
            .try_acquire_owned()
            .map_err(|_| TcpRefusal::SharedRelay)?;
        Ok((listener, forward, relay))
    }
}

/// One rate-limited line per refusal level, each naming the limit and its knob.
///
/// A single shared window would let the most frequent refusal (usually the
/// listener cap) hide the other two, and an operator's action differs per level:
/// raise `max_conns`, raise `max_forward_conns`, or free SOCKS capacity.
fn warn_forward_refusal(
    refusal: TcpRefusal,
    listen: SocketAddr,
    peer: SocketAddr,
    max_conns: usize,
) {
    match refusal {
        TcpRefusal::Listener => {
            if let Some(sup) = claim_forward_listener_limit_log() {
                warn!(
                    "tcp_forward {listen} listener connection limit {max_conns} reached; \
                     dropping {peer}{sup}"
                );
            }
        }
        TcpRefusal::ForwardBudget => {
            if let Some(sup) = claim_forward_budget_log() {
                warn!(
                    "tcp_forward {listen} process-wide forward connection budget exhausted; \
                     dropping {peer} (raise max_forward_conns or lower max_conns){sup}"
                );
            }
        }
        TcpRefusal::SharedRelay => {
            if let Some(sup) = claim_forward_limit_log() {
                warn!(
                    "tcp relay connection limit {MAX_SOCKS_CONNS} reached; dropping {peer} \
                     from {listen}{sup}"
                );
            }
        }
    }
}

/// Relay one accepted TCP stream to `target` through the QUIC pool.
///
/// Contract: `Ok` means both halves reached clean EOF (the pump's contract);
/// any error leaves the app socket closed — RST when the failure happened
/// before the pump took ownership, so the app sees an explicit failure instead
/// of a clean-but-empty response (there is no SOCKS reply that could carry the
/// reason).
pub(crate) async fn relay_tcp_forward(
    sock: tokio::net::TcpStream,
    target: TargetAddr,
    pool: ConnPool,
    egress: Arc<SharedEgress>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let (send, recv) = match open_forward_stream(&target, &pool, &egress, timeout).await {
        Ok(v) => v,
        Err(e) => {
            abort_tcp(&sock);
            return Err(e);
        }
    };
    match copy_tcp_quic_acked(sock, send, recv, FORWARD_TCP_IDLE, TCP_DIAL_ACK_TIMEOUT).await {
        Ok((up, down)) => {
            tracing::debug!("tcp_forward {target:?} clean fin: {up}B up/{down}B down");
            Ok(())
        }
        Err(e) => {
            // Sampled with this listener family's own window: the SOCKS abort
            // gate (`tcp_abort_log_due`) is shared by every SOCKS pump and its
            // winning `warn!` also carries the connection stats an operator
            // needs, so spending that window on a forward `debug!` line (which
            // the default `info` filter drops anyway) could silence a SOCKS
            // abort report. Kept at `debug!` because a forward failure is
            // already reported by `warn_forward_end` once per flow window.
            if let Some(sup) = claim_forward_abort_log() {
                tracing::debug!("tcp_forward {target:?} aborted: {e:#}{sup}");
            }
            Err(e)
        }
    }
}

/// Open one QUIC bidi stream and write the MQP target header on it.
///
/// Mirrors the CONNECT half of `socks::handle_socks`, including the dead-slot
/// self-heal: an `open_bi` failure on a connection with a `close_reason` is the
/// one path that can notice a death before the reconnect loop's watchdog, so
/// it must retire the slot's generation exactly like the SOCKS path does.
async fn open_forward_stream(
    target: &TargetAddr,
    pool: &ConnPool,
    egress: &SharedEgress,
    timeout: Duration,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
    let slot_idx = pool.pick_tcp_index(target);
    let slot = pool.slot(slot_idx);
    let zero_rtt = slot.zero_rtt_state();
    let mut gen_rx = slot.gen_rx.clone();
    let conn = slot.wait_conn(&mut gen_rx, timeout).await?;
    // The header is written as its own first stream write, flushed before any
    // app byte is read: a target that waits for its first reply (game login,
    // banner protocols) must see the request within ~100 ms without the app
    // having sent anything yet. On a resumed connection the open lands on a
    // 0-RTT stream (first flight); `open_bi_and_write_header` retries on a
    // 1-RTT stream when the peer rejects the early data, and consumes no app
    // bytes before it returns Ok.
    let mut hdr = [0u8; AddrHeader::MAX_LEN];
    let hdr_len = target.as_ref().header()?.encode_into(&mut hdr);
    let prio = if pool.is_interactive(target) { 10 } else { 0 };
    match open_bi_and_write_header(
        &conn,
        &zero_rtt,
        &hdr[..hdr_len],
        prio,
        FORWARD_TCP_OPEN_TIMEOUT,
    )
    .await
    {
        Ok(pair) => Ok(pair),
        Err(e) => {
            // The dead-slot self-heal: an open failure on a connection with a
            // `close_reason` is the one path that can notice a death before the
            // reconnect loop's watchdog, so it must retire the slot's
            // generation exactly like the SOCKS path does.
            if conn.close_reason().is_some() {
                retire_dead_slot(&slot, slot_idx, egress, &conn);
            }
            Err(e)
        }
    }
}

/// Arm a reset on the still-owned app socket.
///
/// A forward listener has no SOCKS reply channel, so the only unambiguous
/// failure signal is an RST: a plain drop would FIN, which every peer reads as
/// "the server closed a successful request" and some apps treat as an empty
/// response. The pump already uses RST for every abnormal end.
fn abort_tcp(sock: &tokio::net::TcpStream) {
    // `socket2::SockRef` rather than `tokio::net::TcpStream::set_linger`: the
    // tokio method is deprecated precisely because SO_LINGER can block the
    // calling thread on drop, and a relay task must never do that. The socket
    // is already nonblocking and about to be dropped; the option only decides
    // whether the peer sees RST instead of FIN.
    let _ = socket2::SockRef::from(sock).set_linger(Some(Duration::ZERO));
}

/// Human-readable target for startup/error lines. Kept out of the MQP types so
/// the shared wire module does not grow a display-only `Display` impl.
pub(crate) fn display_target(t: &TargetAddr) -> String {
    match t {
        TargetAddr::Ip(a) => a.to_string(),
        TargetAddr::Domain(h, p) => format!("{h}:{p}"),
    }
}

/// One-per-window accounting for the accept-error line.
fn claim_forward_accept_failed_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// One-per-window accounting for the shared TCP relay admission cap. Separate
/// from the accept-error slot: the two are different faults and a flood of one
/// must not silence the other.
fn claim_forward_limit_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// Per-listener admission-cap window. Its own slot so the per-listener cap, the
/// process-wide forward budget and the shared relay limit can each be seen
/// while one of them floods (three different operator actions: raise
/// `max_conns`, raise `max_forward_conns`, or free SOCKS capacity).
fn claim_forward_listener_limit_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// Process-wide forward-connection budget window (see
/// `claim_forward_listener_limit_log` for why it is a separate slot).
fn claim_forward_budget_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// Forward-only abort-line window. Deliberately **not** the SOCKS
/// `tcp_abort_log_due` gate: sharing it let a burst of forwarded-flow aborts
/// consume the window and suppress the SOCKS abort `warn!` that carries the
/// path stats.
fn claim_forward_abort_log() -> Option<Suppressed> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// One-per-window failure line for a forwarded TCP relay.
///
/// `relay_tcp_forward` returns once per failed flow, so during a pool outage
/// this would be one formatted line per accepted connection on the same runtime
/// as the TCP pumps. The suppressed path costs two relaxed atomics.
fn warn_forward_end(peer: SocketAddr, listen: SocketAddr, err: &anyhow::Error) {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if let Some(n) = claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()) {
        warn!("tcp_forward {listen} {peer} end: {err:#}{}", Suppressed(n));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission(listener: usize, forward: usize, relay: usize) -> TcpAdmission {
        TcpAdmission {
            listener: Arc::new(tokio::sync::Semaphore::new(listener)),
            forward_budget: Arc::new(tokio::sync::Semaphore::new(forward)),
            relay: Arc::new(tokio::sync::Semaphore::new(relay)),
        }
    }

    fn held(adm: &TcpAdmission) -> (usize, usize, usize) {
        (
            adm.listener.available_permits(),
            adm.forward_budget.available_permits(),
            adm.relay.available_permits(),
        )
    }

    /// The central property of the T-01 fix: a forwarded flow holds exactly one
    /// permit from every admission level for its whole life, and releasing it
    /// returns all three exactly once.
    #[test]
    fn admission_holds_one_permit_from_each_level_until_released() {
        let adm = admission(2, 2, 2);
        let permits = adm.try_admit().expect("a fresh admission succeeds");
        assert_eq!(
            held(&adm),
            (1, 1, 1),
            "one permit from each level is held by the flow"
        );
        drop(permits);
        assert_eq!(
            held(&adm),
            (2, 2, 2),
            "releasing the flow returns every permit exactly once"
        );
    }

    /// A refusal at any level must unwind the already-acquired outer levels:
    /// otherwise one refused connection would permanently shrink the listener's
    /// own cap or the process-wide forward budget.
    #[test]
    fn admission_refusals_release_every_earlier_level() {
        // Level 1 (listener cap): nothing was acquired, nothing may be spent.
        let adm = admission(1, 2, 2);
        let first = adm.try_admit().unwrap();
        assert_eq!(adm.try_admit().unwrap_err(), TcpRefusal::Listener);
        assert_eq!(held(&adm), (0, 1, 1), "a level-1 refusal spends nothing");
        drop(first);

        // Level 2 (forward budget): the level-1 permit must come back.
        let adm = admission(3, 1, 2);
        let first = adm.try_admit().unwrap();
        assert_eq!(adm.try_admit().unwrap_err(), TcpRefusal::ForwardBudget);
        assert_eq!(
            held(&adm),
            (2, 0, 1),
            "level-1 permit returned after the level-2 refusal"
        );
        drop(first);

        // Level 3 (shared relay): levels 1 and 2 must come back.
        let adm = admission(3, 3, 1);
        let first = adm.try_admit().unwrap();
        assert_eq!(adm.try_admit().unwrap_err(), TcpRefusal::SharedRelay);
        assert_eq!(
            held(&adm),
            (2, 2, 0),
            "level-1/2 permits returned after the level-3 refusal"
        );
        drop(first);
    }

    /// The refusal must name the outermost exhausted level, so the log line
    /// points at the knob the operator should change.
    #[test]
    fn admission_refuses_at_the_outermost_exhausted_level() {
        let adm = admission(1, 1, 1);
        let first = adm.try_admit().unwrap();
        assert_eq!(adm.try_admit().unwrap_err(), TcpRefusal::Listener);
        drop(first);

        let adm = admission(2, 1, 1);
        let first = adm.try_admit().unwrap();
        assert_eq!(adm.try_admit().unwrap_err(), TcpRefusal::ForwardBudget);
        drop(first);
    }
}
