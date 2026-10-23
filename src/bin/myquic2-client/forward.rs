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
pub(crate) fn spawn_tcp_forward(
    spec: TcpForwardSpec,
    pool: ConnPool,
    egress: Arc<SharedEgress>,
    timeout: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listen = spec.listen;
    let target = spec.target;
    // Context on the *bind*: with several configured forwards, a bare
    // EADDRINUSE must still name which listener failed.
    let raw = tcp_listener_dual(&listen.to_string())
        .with_context(|| format!("bind forward TCP listener {listen}"))?;
    let li = tokio::net::TcpListener::from_std(raw)
        .with_context(|| format!("register forward TCP listener {listen}"))?;
    if !listen.ip().is_loopback() {
        warn!(
            "tcp_forward listen {listen} is not loopback: any host that can reach it can use \
             the tunnel to {}; bind 127.0.0.1 or firewall the port",
            display_target(&target)
        );
    }
    let limiter = socks_conn_limiter().clone();
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
            // Same relay-TCP posture as the SOCKS socket: nodelay plus (on
            // Linux) TCP_NOTSENT_LOWAT, so the kernel send buffer cannot stack
            // unsent bytes ahead of the QUIC stream that already paces this
            // flow.
            linux::tune_relay_tcp(&sock);
            // One process-wide TCP relay budget shared with SOCKS: a second
            // per-listener allowance would multiply the fd/task ceiling by the
            // configured listener count.
            let permit = match limiter.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    if let Some(sup) = claim_forward_limit_log() {
                        warn!(
                            "tcp relay connection limit {MAX_SOCKS_CONNS} reached; \
                             dropping {peer} from {listen}{sup}"
                        );
                    }
                    // A forward listener has no SOCKS reply channel to carry
                    // the failure: close with RST so the app sees an explicit
                    // failure, not a clean empty response (the pump's rule).
                    abort_tcp(&sock);
                    continue;
                }
            };
            let pool = pool.clone();
            let egress = egress.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = relay_tcp_forward(sock, target, pool, egress, timeout).await {
                    warn_forward_end(peer, listen, &e);
                }
            });
        }
    }))
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
            // Sampled like the SOCKS abort line: `tcp_abort_log_due` gates the
            // formatting and the tracing write, not just the emission.
            if tcp_abort_log_due() {
                tracing::debug!("tcp_forward {target:?} aborted: {e:#}");
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
    let mut gen_rx = slot.gen_rx.clone();
    let conn = slot.wait_conn(&mut gen_rx, timeout).await?;
    let (mut send, mut recv) =
        match tokio::time::timeout(FORWARD_TCP_OPEN_TIMEOUT, conn.open_bi()).await {
            Ok(Ok((s, r))) => (s, r),
            _ => {
                if conn.close_reason().is_some() {
                    retire_dead_slot(&slot, slot_idx, egress, &conn);
                }
                anyhow::bail!("quic stream open failed (connection down or stream limit)");
            }
        };
    let prio = if pool.is_interactive(target) { 10 } else { 0 };
    let _ = send.set_priority(prio);
    // The header is deliberately its own write, flushed before any app byte is
    // read: a target that waits for its first reply (game login, banner
    // protocols) must see the request within ~100 ms without the app having
    // sent anything yet. Same contract as the SOCKS path's header write.
    let mut hdr = [0u8; AddrHeader::MAX_LEN];
    let hdr_len = target.as_ref().header()?.encode_into(&mut hdr);
    let sent = tokio::time::timeout(FORWARD_TCP_OPEN_TIMEOUT, send.write_all(&hdr[..hdr_len]))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !sent {
        send.reset(0x04u32.into()).ok();
        recv.stop(0x04u32.into()).ok();
        anyhow::bail!("quic stream header write failed or timed out");
    }
    Ok((send, recv))
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
