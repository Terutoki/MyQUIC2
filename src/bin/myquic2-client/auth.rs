//! Dial, auth and reconnect loop.
use super::*;

pub(crate) fn spawn_conn_loop(
    ep: quinn::Endpoint,
    server_str: String,
    sname: String,
    auth: String,
    slot: ConnSlot,
    watchdog_silence: Duration,
) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(200);
        loop {
            let server: SocketAddr = match resolve_server_addr(&server_str).await {
                Ok(a) => a,
                Err(e) => {
                    warn!("resolve {server_str} failed: {e:#}; retry in {backoff:?}");
                    tokio::time::sleep(backoff + Duration::from_millis(jitter_ms())).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            match dial_once(&ep, server, &sname, &auth).await {
                Ok(conn) => {
                    info!("QUIC connected to {server}");
                    slot.publish(&conn);
                    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
                    bump_gen(&slot.gen_tx);
                    let connected_at = std::time::Instant::now();
                    let watchdog = async {
                        let mut last_rx = conn.stats().udp_rx.datagrams;
                        let mut quiet_since = std::time::Instant::now();
                        info!("watchdog armed rx={last_rx} silence_limit={watchdog_silence:?}");
                        loop {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            if conn.close_reason().is_some() {
                                break;
                            }
                            let rx = conn.stats().udp_rx.datagrams;
                            if rx != last_rx {
                                last_rx = rx;
                                quiet_since = std::time::Instant::now();
                            } else if quiet_since.elapsed() >= watchdog_silence {
                                warn!(
                                    "QUIC path silent {watchdog_silence:?}, force-closing {server}"
                                );
                                conn.close(0u32.into(), b"watchdog");
                                break;
                            }
                        }
                    };
                    tokio::select! {
                        _ = conn.closed() => {}
                        _ = watchdog => {}
                    }
                    warn!("QUIC connection lost, reconnecting...");
                    if let Some(reason) = conn.close_reason() {
                        warn!("QUIC close reason: {reason}");
                    }
                    // The clear and the `live = false` must commit together in
                    // `clear_if_and_mark_dead`: the `open_bi` failure path is a
                    // second writer on this slot, and this loop's own reconnect
                    // may publish a fresh connection between this death and its
                    // clear, so an unconditional `live.store(false)` first
                    // would leave (fresh C, false) with no generation bump and
                    // `wait_conn` would treat C as dead until C itself died.
                    // Three states: holding D commits to None + live false
                    // (the bump wakes waiters off the dead handle); holding a
                    // fresh C clears nothing and leaves live true (no bump —
                    // nothing changed); holding None means the `open_bi` path
                    // already cleared and bumped, so there is nothing to do.
                    if slot.clear_if_and_mark_dead(&conn) {
                        bump_gen(&slot.gen_tx);
                    }
                    if connected_at.elapsed() >= Duration::from_secs(5) {
                        backoff = Duration::from_millis(200);
                    }
                    let wait = backoff + Duration::from_millis(jitter_ms());
                    tokio::time::sleep(wait).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
                Err(e) => {
                    warn!("dial {server} failed: {e:#}; retry in {backoff:?}");
                    tokio::time::sleep(backoff + Duration::from_millis(jitter_ms())).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    });
}
/// Cap on a single dial attempt.
///
/// Without an explicit bound a dead path costs ~15 s per attempt: QUIC keeps
/// retransmitting the Initial until the handshake PTO budget runs out, and the
/// reconnect loop only regains control after that. The loop already retries with
/// backoff, so a shorter attempt is strictly better: it shrinks the window in
/// which `shared` still holds the previous, dead connection, and it lets the
/// first attempt that lands after a server restart succeed instead of waiting
/// out the previous attempt's timeout.
pub(crate) const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Confirm that a freshly dialed connection is actually alive before it is
/// published to the shared slot.
///
/// quinn-0.11's `Connecting` resolved `Ok` even when the underlying connection
/// terminated instead of completing its handshake, which let the reconnect loop
/// publish a connection that was already closed, log "QUIC connected", and hand
/// every new SOCKS flow a dead handle until quinn's idle timeout expired ~15 s
/// later. quinn 0.12 reports the terminal error from `Connecting` itself, so
/// this is now a cheap belt-and-braces guard rather than the only defence:
/// yielding once lets the connection driver deliver any terminal event, after
/// which `close_reason()` is populated and the dial is reported as the failure
/// it is.
pub(crate) async fn ensure_dialed_alive(conn: &quinn::Connection) -> bool {
    if conn.close_reason().is_some() {
        return false;
    }
    tokio::task::yield_now().await;
    conn.close_reason().is_none()
}

pub(crate) async fn dial_once(
    ep: &quinn::Endpoint,
    server: SocketAddr,
    name: &str,
    auth_token: &str,
) -> Result<quinn::Connection> {
    let t0 = tokio::time::Instant::now();
    // One deadline for the whole attempt, the auth stages included. The stages
    // used to carry independent 5 s budgets, so a handshake that consumed its
    // own 5 s and then stalled in `send_auth` (5 s open + 5 s write) held the
    // slot for up to 15 s — contradicting this constant's documented promise
    // and widening the window in which the pool still advertises the previous,
    // dead connection. Every stage below now shares this instant.
    let deadline = t0 + DIAL_ATTEMPT_TIMEOUT;
    let connecting = ep.connect(server, name)?;
    // 0-RTT: the token is deliberately NOT sent in early data. A bearer
    // secret in replayable early data lets anyone who observes one handshake
    // open new authenticated connections by replaying it inside the ticket
    // window (rustls single-use tickets narrow the window but cannot close
    // it: a replay that arrives first wins). Application flows still benefit
    // from resumption (one handshake instead of a full one); only the token
    // waits for the 1-RTT keys, which are never replayable. This costs the
    // resumed handshake one RTT before the server admits flows, in exchange
    // for the token never appearing in replayable bytes.
    //
    // 0.11 API: `into_0rtt()` yields `(Connection, ZeroRttAccepted)`; the
    // future resolves when the handshake completes with true = early data
    // kept, false = rejected OR the connection died first. The timeout plus
    // the `ensure_dialed_alive` gate below keep a dead dial from ever being
    // published (0.11's `Connecting` resolves `Ok` even for dead dials).
    let conn = match connecting.into_0rtt() {
        Ok((conn, accepted_fut)) => {
            let token = auth_token.to_owned();
            let accepted = match tokio::time::timeout_at(deadline, accepted_fut).await {
                Ok(a) => a,
                Err(_) => anyhow::bail!("0-RTT offered but the handshake did not complete"),
            };
            tracing::debug!("QUIC resumption: 0-RTT accepted={accepted}");
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection lost during handshake");
            }
            // 1-RTT only: the established connection's keys are fresh per
            // handshake, so a captured token can never be replayed into a new
            // connection the way captured early data could.
            if !token.is_empty() {
                send_auth(&conn, &token, deadline).await?;
            }
            conn
        }
        Err(connecting) => {
            let conn = match tokio::time::timeout_at(deadline, connecting).await {
                Ok(r) => r?,
                Err(_) => anyhow::bail!("handshake timed out after {DIAL_ATTEMPT_TIMEOUT:?}"),
            };
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection closed immediately after the handshake");
            }
            info!("QUIC full handshake in {:?}", t0.elapsed());
            if !auth_token.is_empty() {
                send_auth(&conn, auth_token, deadline).await?;
            }
            conn
        }
    };
    if !ensure_dialed_alive(&conn).await {
        anyhow::bail!("connection not usable after dial");
    }
    Ok(conn)
}

/// Open a uni stream and write the auth token into it (1-RTT only).
///
/// Rejection is learned via the `ZeroRttAccepted` future, not from this handle.
/// `deadline` is the dial attempt's shared deadline: both stages time out
/// against it, so auth can never extend an attempt beyond
/// [`DIAL_ATTEMPT_TIMEOUT`].
pub(crate) async fn send_auth_stream(
    conn: &quinn::Connection,
    token: &str,
    deadline: tokio::time::Instant,
) -> Result<quinn::SendStream> {
    let mut uni = tokio::time::timeout_at(deadline, conn.open_uni())
        .await
        .context("auth stream open timed out")??;
    // Bounded by the same attempt deadline: without one a stalled connection
    // parks the dial attempt here until the QUIC idle timeout. On timeout the
    // error propagates out of `dial_once`, so the attempt fails and nothing is
    // published. The token is ≤ 256 B (one small write); `finish()` stays
    // best-effort. A failed write must `reset` instead of merely dropping
    // `uni`: dropping sends a graceful FIN bearing whatever prefix of the
    // token got out, which the server reads as a credential mismatch, while
    // `reset` aborts the stream so no partial token is ever framed as final.
    match tokio::time::timeout_at(deadline, uni.write_all(token.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            uni.reset(0u32.into()).ok();
            return Err(e).context("auth write failed");
        }
        Err(e) => {
            uni.reset(0u32.into()).ok();
            return Err(e).context("auth write timed out");
        }
    }
    uni.finish().ok();
    Ok(uni)
}

pub(crate) async fn send_auth(
    conn: &quinn::Connection,
    token: &str,
    deadline: tokio::time::Instant,
) -> Result<()> {
    send_auth_stream(conn, token, deadline).await.map(|_| ())
}
