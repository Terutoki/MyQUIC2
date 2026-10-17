//! TCP ingress: stream task, MQP header, happy-eyeballs dial.
use super::*;

/// One accepted TCP bidi stream: header first, admission second, dial last.
///
/// The 5 s header read runs *before* the per-connection share check and the
/// process-wide stream-task permit, and holds neither: a stream that trickles
/// one byte per 4.9 s parks only its own task for the budget instead of a
/// `MAX_STREAM_TASKS` permit plus a share slot, so a slowloris treadmill can
/// no longer exhaust the pool. Spawning is still bounded — one task per
/// accepted stream, capped by the transport's per-connection stream credit —
/// and the share/permit are taken fail-fast (`try_acquire`, `0x05` reset) once
/// the header is in, so they bound only the dial/auth work.
pub(crate) async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    streams_held: Arc<std::sync::atomic::AtomicUsize>,
    share: usize,
    admitted: usize,
    allow_private: bool,
    stat_conn: quinn::Connection,
) {
    let target: TargetAddr =
        match tokio::time::timeout(Duration::from_secs(5), read_mqp_target(&mut recv)).await {
            Ok(Ok(t)) => t,
            _ => {
                send.reset(0x01u32.into()).ok();
                return;
            }
        };
    // Reserve a share slot atomically. `fetch_add` returns the *pre-increment*
    // value, so the reservation is exact under concurrency: the previous
    // `load() >= share` check followed by a later `fetch_add(1)` was a TOCTOU
    // race — every stream is its own `tokio::spawn`ed task on a multi-thread
    // runtime, so N tasks accepted at the same instant all read `share - 1`,
    // all passed, and all incremented, overshooting the share by up to the
    // number of concurrent accepts (bounded only by `MAX_BIDI_STREAMS_PER_CONN`
    // rather than by `share`). A loser's `fetch_sub` puts the slot straight
    // back, so the count is never left inflated.
    let held = streams_held.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if held >= share {
        streams_held.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        let n = STREAM_SHARE_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if warn_stream_share_refused() {
            warn!(
                "tcp stream share reached ({share} of {MAX_STREAM_TASKS} across \
                 {admitted} connection(s), {n} refused so far); resetting the stream"
            );
        }
        send.reset(0x05u32.into()).ok();
        return;
    }
    // Armed before the permit attempt so the refusal below gives the slot back.
    let _stream_share_guard = StreamShareGuard(streams_held);
    let _stream_permit = match stream_task_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Fail the stream immediately instead of queueing unbounded work.
            send.reset(0x05u32.into()).ok();
            return;
        }
    };
    // Candidate addresses for the dial. Both branches produce a plain
    // `&[SocketAddr]`: the IP-literal path (the dominant case) borrows
    // the decoded target and allocates nothing, while the domain path
    // resolves into a local buffer whose scope covers the dial.
    let ip_cand;
    let mut dns_cand = [SocketAddr::from(([0, 0, 0, 0], 0)); 8];
    let dns_n;
    let cands: &[SocketAddr] = match &target {
        TargetAddr::Ip(s) => {
            ip_cand = *s;
            std::slice::from_ref(&ip_cand)
        }
        TargetAddr::Domain(h, p) => {
            // Fail fast when the global slow-path budget is exhausted
            // instead of parking this stream task (and its
            // stream-task permit) in a 3s queue: a unique-domain
            // flood would otherwise hold up to MAX_STREAM_TASKS
            // permits while IP-literal flows starve behind them.
            // Matches the UDP path's try_acquire; the client retries.
            let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            dns_n = match resolve_all_cached(h, *p).await {
                Ok(v) => {
                    // `resolve_all_cached` sorts by the configured family
                    // preference, so a flat prefix cut would starve the
                    // non-preferred family whenever upstream returns more
                    // than 8 preferred-family records. Alternate families
                    // instead, keeping the preference while guaranteeing the
                    // other family gets tried.
                    let mut n = 0;
                    let mut v4 = v.iter().filter(|a| a.is_ipv4());
                    let mut v6 = v.iter().filter(|a| !a.is_ipv4());
                    // Start on the preferred family and alternate so the
                    // other family is never starved, but keep filling from
                    // whichever family still has records until the 8-slot
                    // buffer is full (a single-family answer must still
                    // yield up to 8).
                    let mut want_v4 = ip_preference() == IpPreference::Ipv4;
                    while n < dns_cand.len() {
                        let next = if want_v4 {
                            v4.next().or_else(|| v6.next())
                        } else {
                            v6.next().or_else(|| v4.next())
                        };
                        match next {
                            Some(a) => {
                                dns_cand[n] = *a;
                                n += 1;
                            }
                            None => break,
                        }
                        want_v4 = !want_v4;
                    }
                    n
                }
                // Negative-cached name, policy refusal, resolution failure or
                // timeout: an empty candidate list fails the dial below.
                Err(_) => 0,
            };
            drop(permit);
            &dns_cand[..dns_n]
        }
    };
    // Hold the global dial permit only for the connect phase; the copy
    // phase is bounded by the transport's stream limit instead.
    // Fail fast instead of parking this stream task (and its
    // stream-task permit) in a DIAL_PERMIT_WAIT queue: a dial flood
    // would otherwise hold up to MAX_STREAM_TASKS permits while
    // later flows starve behind them. Matches the stream_task_limiter
    // and dns_slow_path_limiter try_acquire paths; the client retries.
    let _dial_permit = match dial_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let n = DIAL_PERMIT_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::debug!("tcp dial permit refused ({n} so far)");
            send.reset(0x04u32.into()).ok();
            return;
        }
    };
    let tcp = match dial_happy_eyeballs(cands, allow_private).await {
        Some(t) => t,
        None => {
            let n = DIAL_CONNECT_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tracing::debug!("tcp dial failed ({n} so far)");
            send.reset(0x04u32.into()).ok();
            return;
        }
    };
    drop(_dial_permit);
    // Relay-TCP posture: nodelay always, plus Linux TCP_NOTSENT_LOWAT so the
    // kernel send buffer cannot stack megabytes of unsent bytes ahead of the
    // QUIC stream that already paces this flow (see `linux::tune_relay_tcp`).
    // This is the single owner of that tuning: `dial_happy_eyeballs` used to
    // apply it inside the dial as well, duplicating the `setsockopt`s on every
    // TCP flow.
    myquic2::linux::tune_relay_tcp(&tcp);
    // MQP-2: report the bound address of the dialed socket so the
    // client can answer SOCKS with the real BND.ADDR/PORT (RFC 1928)
    // instead of a placeholder.
    let bnd = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    // Fixed-size stack buffer: the ACK is at most magic + status + the
    // v6 bnd form (`MAX_TCP_ACK_LEN`), so the per-stream `Vec` this
    // used to allocate bought nothing.
    let mut ack = [0u8; MAX_TCP_ACK_LEN];
    let n = encode_tcp_ack_into(bnd, &mut ack);
    // Bounded: a stalled stream must not pin this task and its
    // stream-task permit until connection death; the client tears the
    // flow down on a missing ACK, so a slow write here buys nothing.
    // Reset symmetrically with the dial-failure paths above so the
    // client fails fast instead of waiting out its 25s ACK timeout.
    let ack_sent = tokio::time::timeout(Duration::from_secs(5), send.write_all(&ack[..n]))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !ack_sent {
        send.reset(0x04u32.into()).ok();
        return;
    }
    match copy_tcp_quic_idle(tcp, send, recv, Duration::from_secs(300)).await {
        Ok((up, down)) => {
            tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
        }
        Err(e) => {
            if tcp_abort_log_due() {
                let st = stat_conn.stats();
                tracing::warn!(
                    "tcp {target:?} aborted: {e:#} (rtt={:?} cwnd={} lost={}/{} pkts)",
                    st.path.rtt,
                    st.path.cwnd,
                    st.path.lost_packets,
                    st.path.sent_packets,
                );
            }
        }
    }
}

/// Byte length of the complete MQP-2 TCP header for a given `atyp`: how much
/// the header reader must collect before it can decode. The domain form needs
/// its length byte first, which is why this is two-staged. Pure so the lengths
/// are unit-testable without a live QUIC stream.
pub(crate) fn mqp_hdr_len(atyp: u8, domain_len: u8) -> Result<usize> {
    Ok(match atyp {
        0x01 => 1 + 6,
        0x04 => 1 + 18,
        0x03 => {
            if domain_len == 0 {
                anyhow::bail!("empty domain");
            }
            1 + 1 + domain_len as usize + 2
        }
        a => anyhow::bail!("bad atyp {a}"),
    })
}

pub(crate) async fn read_mqp_target(recv: &mut quinn::RecvStream) -> Result<TargetAddr> {
    // No per-read timeout here: the caller wraps the whole header read in a
    // single 5s budget, and an inner timeout just registered extra timers.
    //
    // The header is decoded from one stack buffer instead of assembling a
    // temporary `Vec` per field and then decoding that: a domain target used to
    // cost four heap allocations (three `Vec`s plus the owned `String`) before
    // the dial even started. Now only the final `TargetAddr` allocates.
    pub(crate) const HDR_MAX: usize = 1 + 1 + 255 + 2;
    let mut buf = [0u8; HDR_MAX];
    recv.read_exact(&mut buf[..1]).await.context("hdr read")?;
    let (len, rest_at) = match buf[0] {
        0x03 => {
            recv.read_exact(&mut buf[1..2])
                .await
                .context("hdr domain len")?;
            (mqp_hdr_len(0x03, buf[1])?, 2)
        }
        atyp => (mqp_hdr_len(atyp, 0)?, 1),
    };
    recv.read_exact(&mut buf[rest_at..len])
        .await
        .context("hdr read")?;
    Ok(TargetAddr::decode(&buf[..len])?.0)
}

/// Connect to the first candidate that succeeds.
///
/// `cands` is borrowed so the IP-literal path allocates nothing. Filtering
/// (`allow_private`) and the 8-candidate cap stay here; the staggered
/// alternating-family racing itself is `happy-eyeballs` (RFC 8305, 250 ms
/// stagger internally) instead of the hand-rolled `JoinSet` + `watch`
/// cancellation. Total budget 4 s is kept via `timeout` so the client-side ACK
/// wait still covers it.
///
/// Single-candidate fast path: IP-literal targets (the dominant case, and the
/// reason the old hand-rolled version special-cased them) get one direct
/// connect — no `lookup_host` clone, no partition/merge `Vec`s, no `JoinSet`,
/// no attempt/delay task spawns. The crate is only consulted when there is
/// actually a race to run; delegating the single case to it re-introduced
/// several allocations and two task spawns per TCP flow for nothing.
///
/// Socket options are the **caller's**: `handle_tcp_stream` calls
/// [`myquic2::linux::tune_relay_tcp`] once on the returned socket. This function
/// used to call it on both arms as well, so every dial paid the `setsockopt`s
/// twice — and the single-candidate arm (every IP-literal flow) tuned a socket
/// before it had even been returned. One owner, one tuning.
///
/// Note: `happy-eyeballs` re-interleaves v6/v4 (v6-first per RFC 8305) after
/// `lookup_host`, so a `dns_ip_preference = "ipv4"` deployment still resolves
/// v4-first but races v6-first. That matches the RFC default; strict v4-first
/// racing would need input-order racing instead of this crate.
pub(crate) async fn dial_happy_eyeballs(
    cands: &[SocketAddr],
    allow_private: bool,
) -> Option<tokio::net::TcpStream> {
    pub(crate) const DIAL_CAND_MAX: usize = 8;
    let mut accept = [SocketAddr::from(([0, 0, 0, 0], 0)); DIAL_CAND_MAX];
    let mut n = 0;
    for a in cands
        .iter()
        .filter(|a| allow_private || is_global_ip(a.ip()))
    {
        accept[n] = *a;
        n += 1;
        if n == DIAL_CAND_MAX {
            break;
        }
    }
    if n == 0 {
        return None;
    }
    if let [only] = &accept[..n] {
        return match tokio::time::timeout(
            Duration::from_secs(4),
            tokio::net::TcpStream::connect(*only),
        )
        .await
        {
            Ok(Ok(s)) => Some(s),
            _ => None,
        };
    }
    // Total budget 4s; the client-side ACK wait is sized to cover it.
    let res = tokio::time::timeout(
        Duration::from_secs(4),
        happy_eyeballs::tokio::connect(&accept[..n]),
    )
    .await;
    match res {
        Ok(Ok(s)) => Some(s),
        _ => None,
    }
}
