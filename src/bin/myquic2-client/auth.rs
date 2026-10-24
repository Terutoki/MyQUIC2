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
/// Detection granularity is this tick on top of the silence window: one second
/// keeps the shipped 40 s window a ~41 s detector, while the tick costs one
/// `ConnectionStats` snapshot per second per connection (the same quinn
/// state-lock acquisition the old 5 s tick paid, just more often — still
/// nowhere near the per-packet path).
///
/// `pub(crate)` because the pool's selection-time path-health threshold
/// ([`data_stale_threshold_ms`]) is derived from the worst-case age of an
/// inbound-progress stamp: one keepalive interval plus this sampling tick.
pub(crate) const WATCHDOG_POLL: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_conn_loop(
    ep: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    server_str: String,
    sname: String,
    auth: String,
    slot: ConnSlot,
    watchdog_silence: Duration,
    idx: usize,
    egress: std::sync::Arc<super::egress::SharedEgress>,
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
                    // MQP-3 rev2 state is created per dial and published
                    // *before* the connection: the dispatcher and the egress
                    // cache resolve the state of the generation they are
                    // handed, never a neighbouring generation's.
                    let rev2 = ConnRev2::new();
                    slot.set_rev2(rev2.clone());
                    slot.publish(&conn);
                    // Establishment is inbound progress: seed the routing
                    // stamp before publishing the live hint, so the first
                    // selections of the new generation never read the previous
                    // one's (or the initial 0) age. `0` is treated as
                    // "unknown, not stale" as a belt-and-braces, but seeding
                    // here is what makes the gate meaningful from the start.
                    slot.note_rx_progress();
                    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
                    bump_gen(&slot.gen_tx);
                    let connected_at = std::time::Instant::now();
                    // MQP-3 rev2 negotiation: `CTL HELLO` immediately, retried
                    // until `CAPS` or the ~2 s cap. The dispatcher task that
                    // receives `CAPS` was started by the generation bump above
                    // and stores it on this very `ConnRev2`; the egress cache
                    // refuses to publish a connection until then, so no UDP
                    // frame can leave before the peer acknowledged rev2.
                    //
                    // No `CAPS`/wrong wire version is fatal for this dial: the
                    // connection is closed here and the redial loop retries.
                    // There is deliberately no fallback to the old wire.
                    if !rev2::handshake(&conn, &rev2).await {
                        warn!(
                            "MQP-3 rev2 handshake failed (no CAPS/wrong wire version) on {server}; closing and redialing"
                        );
                        conn.close(0u32.into(), b"rev2 handshake");
                    }
                    // Silence watchdog, two independent detectors sharing one
                    // poll loop. `tx` progress is deliberately NEVER treated
                    // as health: keepalives and retransmits keep `udp_tx`
                    // advancing into a dead path, so an `rx || tx` reset
                    // blinds the detector exactly when the downlink dies.
                    //
                    // `watchdog_silence` is `2/3` of the transport's resolved
                    // idle timeout (40 s at the shipped defaults) and is
                    // provably strictly below it (see its unit test). So these
                    // detectors really fire first and force the reconnect,
                    // instead of being masked by quinn's idle timer.
                    // `WATCHDOG_POLL` bounds the overshoot.
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
                                // Publish the downlink-progress stamp the
                                // routing path's health gate reads (see
                                // `ConnSlot::is_data_stale`). Only an actual
                                // advance refreshes it — that is exactly the
                                // signal that freezes on a blackholed path
                                // while `live` still reads true; the watchdog
                                // below remains the authority that closes and
                                // redials the connection.
                                slot.note_rx_progress();
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
                    //
                    // `retire_dead_slot` is that one death commit, shared with
                    // the SOCKS `open_bi` failure path: besides the clear it
                    // releases the dead generation's egress handles (strong
                    // `quinn::Connection` clones that would otherwise outlive
                    // the redial) and its rev2 registry/staged payloads, then
                    // bumps the generation. Whoever wins the `rcu` clear owns
                    // the whole cleanup, so it can never run twice.
                    retire_dead_slot(&slot, idx, &egress, &conn);
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
/// Commit one dead connection generation and release everything it owned.
///
/// This is the single death commit both writers on a pool slot use: the
/// reconnect loop after its connection/watchdog future ends, and the SOCKS
/// `open_bi` failure path when it is the first to notice that the handle it was
/// handed has died. Committing through [`ConnSlot::clear_if_and_mark_dead`]
/// means exactly one caller wins the clear (the `rcu` decision, the
/// `live = false` store and the progress-stamp reset land together), so the
/// cleanup can never run twice for one generation and a connection published
/// concurrently is neither marked dead nor cleaned.
///
/// On a won commit, in order:
///
/// 1. drop this pool slot's egress-cache handles — they hold strong
///    `quinn::Connection` clones, and a dead generation is otherwise reclaimed
///    only by a later verdict on that binding, i.e. never if it goes idle
///    ([`SharedEgress::forget_slot`]);
/// 2. retire the slot's rev2 state (compare-and-clear on generation identity,
///    [`ConnSlot::clear_rev2_if`]) and drop the dead generation's connection-
///    scoped flow registry and staged payloads, so a dispatcher that waits for
///    the next generation cannot resolve ids from the dead one and an
///    association's epoch check sees the change before it sends
///    ([`ConnRev2::clear_flows`], [`ConnRev2::clear_stage`], which books every
///    dropped payload as an egress death);
/// 3. bump the generation, waking `wait_conn` waiters and dispatchers.
///
/// The rev2 state is captured *before* the clear commits: the publisher
/// installs `set_rev2` before `publish`, so while `shared` still holds this
/// connection `slot.rev2()` is this connection's state, whereas a read taken
/// after the clear could observe the next generation's state if a redial
/// slipped in behind the commit. The slot's rev2 entry is then retired with a
/// compare-and-clear, never unconditionally: the SOCKS path is not the
/// publisher, so a reconnect loop that published a fresh generation while this
/// call was running must keep it — a blind clear would leave the fresh
/// connection without rev2 state and force its UDP traffic to drop until the
/// next redial.
///
/// Returns `true` when this call committed the death (and performed the
/// cleanup), `false` when the slot already held another generation or nothing
/// — another writer won the same commit, and there is nothing left to do.
pub(crate) fn retire_dead_slot(
    slot: &ConnSlot,
    idx: usize,
    egress: &SharedEgress,
    conn: &quinn::Connection,
) -> bool {
    let rev2 = slot.rev2();
    if !slot.clear_if_and_mark_dead(conn) {
        return false;
    }
    egress.forget_slot(idx);
    // Retire the slot only while it still holds this generation's state (see
    // the doc above). The dead generation's own tables are independent of the
    // slot's current state, so they are always released: a fresh generation
    // published in the meantime keeps its state and its flows.
    if let Some(dead) = &rev2 {
        let _ = slot.clear_rev2_if(dead);
        dead.clear_flows();
        dead.clear_stage();
    }
    bump_gen(&slot.gen_tx);
    true
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
