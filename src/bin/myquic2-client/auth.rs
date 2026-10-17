//! Dial, auth and reconnect loop.
use super::*;
use backon::{BackoffBuilder, ExponentialBuilder};

/// Reconnect backoff: 200 ms base, x2, capped at 5 s. Additive jitter is the
/// caller's (`jitter_ms()`), not backon's.
///
/// Replaces the hand-rolled `backoff = (backoff * 2).min(5s)` with the
/// audited `backon` iterator: same shape (200 ms → 5 s cap), same
/// per-thread seeded jitter, but the doubling/cap live in one builder
/// instead of three copy-pasted sites. Infinite (`without_max_times`)
/// because the reconnect loop never gives up; reset by rebuilding after a
/// long-lived connection.
///
/// Why not `ExponentialBuilder::with_jitter()`: backon applies jitter
/// *after* the cap (`delay + delay * U(0,1)`, exponential.rs), so the
/// capped 5 s step would emit waits of up to ~10 s — doubling the
/// documented redial bound for every pool slot during an outage. The
/// call sites add the original bounded `0..200 ms` instead, keeping the
/// steady-state redial at `[5 s, 5.2 s]`.
fn reconnect_backoff() -> impl Iterator<Item = Duration> {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(200))
        .with_max_delay(Duration::from_secs(5))
        .with_factor(2.0)
        .without_max_times()
        .build()
}

/// How often the silence watchdog re-reads `ConnectionStats`.
///
/// Detection granularity is this tick on top of the silence window, so the old
/// hard-coded 5 s poll made a 10 s watchdog fire at ~15 s — i.e. at the QUIC
/// idle timeout it is supposed to beat, quietly turning it back into the dead
/// code the old `4x/20 s` window made it. One second keeps a 10 s window a
/// ~11 s detector; the tick costs one `ConnectionStats` snapshot per second per
/// connection (the same quinn state-lock acquisition the 5 s tick paid, just
/// more often — still nowhere near the per-packet path).
const WATCHDOG_POLL: Duration = Duration::from_secs(1);

pub(crate) fn spawn_conn_loop(
    ep: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    server_str: String,
    sname: String,
    auth: String,
    slot: ConnSlot,
    watchdog_silence: Duration,
) {
    tokio::spawn(async move {
        let mut backoff = reconnect_backoff();
        loop {
            let server: SocketAddr = match resolve_server_addr(&server_str).await {
                Ok(a) => a,
                Err(e) => {
                    let wait = backoff.next().unwrap_or(Duration::from_secs(5))
                        + Duration::from_millis(jitter_ms());
                    warn!("resolve {server_str} failed: {e:#}; retry in {wait:?}");
                    tokio::time::sleep(wait).await;
                    continue;
                }
            };
            match dial_once(&ep, &cfg, server, &sname, &auth).await {
                Ok(conn) => {
                    info!("QUIC connected to {server}");
                    slot.publish(&conn);
                    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
                    bump_gen(&slot.gen_tx);
                    let connected_at = std::time::Instant::now();
                    // Silence watchdog, two independent detectors sharing one
                    // poll loop. `tx` progress is deliberately NEVER treated
                    // as health: keepalives and retransmits keep `udp_tx`
                    // advancing into a dead path, so an `rx || tx` reset
                    // blinds the detector exactly when the downlink dies.
                    //
                    // `watchdog_silence` is derived from the same clamped
                    // keepalive as the transport's idle timeout and is
                    // `max(2x keepalive, 8 s)`, provably strictly below
                    // `max(3x keepalive, 15 s)` (see its unit test). So these
                    // detectors really fire first and force the reconnect,
                    // instead of the old `4x/20 s` window that the idle timer
                    // always beat — which made them dead code and pinned path
                    // death at ~15 s. `WATCHDOG_POLL` bounds the overshoot.
                    let watchdog = async {
                        let s0 = conn.stats();
                        // (a) Downlink / full blackhole: inbound datagrams
                        // stall for >= silence, no matter what tx does.
                        let mut last_rx = s0.udp_rx.datagrams;
                        let mut quiet_since = std::time::Instant::now();
                        // (b) Uplink blackhole: our packets go out but no
                        // ACK comes back, while the peer's keepalives still
                        // feed `rx` so (a) stays blind. Progress signals
                        // from `ConnectionStats` (quinn 0.11):
                        // `frame_rx.acks` advances only when the peer's ACKs
                        // reach us; `path.sent_packets` proves we sent
                        // ack-eliciting traffic. `path.lost_packets` is
                        // sampled for the log line only, never gated on:
                        // quinn declares loss only inside the largest_acked
                        // range and PTO bumps pto_count without bumping
                        // lost, so a fully blackholed uplink may never
                        // declare loss at all. `path.rtt` is NOT used: its
                        // value may legitimately plateau on a stable link,
                        // while these counters are monotonic progress signals.
                        // Baselines are snapshotted whenever ACKs advance;
                        // a stall fires as soon as we kept sending while ACKs
                        // stalled, without waiting for a loss declaration, so
                        // transient loss with recovering ACKs resets the
                        // baseline and can never trip it.
                        // Backstop only: a path where (b)'s gates never line
                        // up (no ack-eliciting traffic sent) still falls to
                        // the *idle* timeout, which is strictly above this
                        // window and can therefore no longer mask it.
                        let mut last_ack = s0.frame_rx.acks;
                        let mut ack_since = std::time::Instant::now();
                        let mut ack_window_sent = s0.path.sent_packets;
                        info!("watchdog armed rx={last_rx} silence_limit={watchdog_silence:?}");
                        loop {
                            tokio::time::sleep(WATCHDOG_POLL).await;
                            if conn.close_reason().is_some() {
                                break;
                            }
                            let st = conn.stats();
                            let rx = st.udp_rx.datagrams;
                            if rx != last_rx {
                                last_rx = rx;
                                quiet_since = std::time::Instant::now();
                            } else if quiet_since.elapsed() >= watchdog_silence {
                                warn!(
                                    "QUIC path silent (downlink) rx={rx} tx={} {watchdog_silence:?}, force-closing {server}",
                                    st.udp_tx.datagrams,
                                );
                                conn.close(0u32.into(), b"watchdog");
                                break;
                            }
                            let acks = st.frame_rx.acks;
                            let sent = st.path.sent_packets;
                            let lost = st.path.lost_packets;
                            if acks != last_ack {
                                last_ack = acks;
                                ack_since = std::time::Instant::now();
                                ack_window_sent = sent;
                            } else if ack_since.elapsed() >= watchdog_silence
                                && sent != ack_window_sent
                            {
                                warn!(
                                    "QUIC path silent (uplink) acks={acks} sent={sent} lost={lost} {watchdog_silence:?}, force-closing {server}"
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
                        backoff = reconnect_backoff();
                    }
                    let wait = backoff.next().unwrap_or(Duration::from_secs(5))
                        + Duration::from_millis(jitter_ms());
                    tokio::time::sleep(wait).await;
                }
                Err(e) => {
                    let wait = backoff.next().unwrap_or(Duration::from_secs(5))
                        + Duration::from_millis(jitter_ms());
                    warn!("dial {server} failed: {e:#}; retry in {wait:?}");
                    tokio::time::sleep(wait).await;
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

/// Dial one connection with the slot's own transport preset.
///
/// `cfg` is per-slot, not the endpoint default: the two UDP egress classes
/// need different ACK presets on the same endpoint (the bulk class trades
/// feedback precision for reverse-path CPU; the interactive class must keep
/// the tuned low-latency one), which `Endpoint::connect` cannot express.
pub(crate) async fn dial_once(
    ep: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
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
    let connecting = ep.connect_with(cfg.clone(), server, name)?;
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
