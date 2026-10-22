//! SOCKS5 ingress (CONNECT / UDP ASSOCIATE).
use super::*;

/// Must cover the server's worst-case dial path:
/// 5s header read + 3s DNS permit + 5s DNS lookup + 2s dial permit +
/// 4s TCP connect + scheduling jitter, with margin for a loaded host.
pub(crate) const TCP_DIAL_ACK_TIMEOUT: Duration = Duration::from_secs(25);
/// Process-wide caps on client-side resources. Without these a local or LAN
/// peer can spawn unbounded tasks / relay sockets (each with ~64 KiB kernel
/// buffers) and exhaust fds and memory on the proxy host.
pub(crate) const MAX_SOCKS_CONNS: usize = 8192;
/// The admission cap above is only useful if the QUIC pool can actually carry
/// that many concurrent TCP flows without parking them in `open_bi()`; the
/// transport advertises `MAX_BIDI_STREAMS_PER_CONN` per connection, and pinned
/// flows can all land on one connection. Fail the build if either constant is
/// changed without the other.
const _: () = assert!(MAX_SOCKS_CONNS as u32 <= MAX_BIDI_STREAMS_PER_CONN);
// `MAX_UDP_ASSOCS` (the concurrent UDP-association cap) now lives in `lib.rs`
// next to the server's per-connection session target, so the two can never drift
// apart again: it is imported by `use myquic2::*`. It is a *budget* constant,
// not a guarantee — see its docstring for the server-side fair share
// (`clamp(MAX_SESSIONS_GLOBAL / session-holding connections, 1024, 4096)`) that
// this client cannot observe.
pub(crate) fn socks_conn_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_SOCKS_CONNS)))
}
/// One deadline for a whole SOCKS negotiation (greeting + request + target).
/// The app is local, so this only has to bound a stuck or hostile peer; the
/// previous shape re-armed a fresh 10 s timeout per field, making the worst
/// case a multiple of it and registering several timers per connection at the
/// connection rate.
pub(crate) const SOCKS_NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the client asked for, once its whole negotiation has been read.
pub(crate) enum SocksRequest {
    Connect(TargetAddr),
    Associate,
}

/// Reads the greeting (only the no-auth method is offered) and the request.
/// Framing only; the caller owns the deadline (see [`SOCKS_NEGOTIATE_TIMEOUT`]).
///
/// Frame constants come from `fast-socks5` (MIT): version/cmd/atyp/reply codes
/// are the crate's `consts`, not hand-written magic numbers. The ASSOCIATE
/// outer-address leniency and the optimistic CONNECT timing below stay
/// hand-rolled: the outer addr is a hint only (often 0.0.0.0:0) and the
/// success reply is sent before the server dial ACK.
pub(crate) async fn negotiate(s: &mut tokio::net::TcpStream) -> Result<SocksRequest> {
    use fast_socks5::consts::*;
    // handshake: VER NMETHODS METHODS; we only support 0x00
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.context("socks greeting")?;
    if h[0] != SOCKS5_VERSION {
        anyhow::bail!("bad ver");
    }
    if h[1] == 0 {
        anyhow::bail!("no methods offered");
    }
    let mut m = [0u8; u8::MAX as usize];
    s.read_exact(&mut m[..h[1] as usize])
        .await
        .context("socks methods")?;
    if !m[..h[1] as usize].contains(&SOCKS5_AUTH_METHOD_NONE) {
        write_socks(s, &[SOCKS5_VERSION, SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    write_socks(s, &[SOCKS5_VERSION, SOCKS5_AUTH_METHOD_NONE]).await?;

    let mut r = [0u8; 3];
    s.read_exact(&mut r).await.context("socks request")?;
    if r[0] != SOCKS5_VERSION {
        anyhow::bail!("bad req ver");
    }
    if r[2] != 0x00 {
        anyhow::bail!("bad req rsv {:#x}", r[2]);
    }
    match r[1] {
        SOCKS5_CMD_TCP_CONNECT => match read_socks_addr(s).await {
            Ok(t) => Ok(SocksRequest::Connect(t)),
            Err(_) => {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED, b)
                        .await
                        .ok();
                }
                anyhow::bail!("bad connect target");
            }
        },
        SOCKS5_CMD_UDP_ASSOCIATE => {
            // UDP ASSOCIATE: outer addr is a hint only (often 0.0.0.0:0) and
            // is always ignored, so read it leniently without TargetAddr
            // validation. Real packet targets inside DATAGRAMs stay strict.
            if read_socks_addr_lenient(s).await.is_err() {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED, b)
                        .await
                        .ok();
                }
                anyhow::bail!("bad associate target");
            }
            Ok(SocksRequest::Associate)
        }
        _ => {
            write_socks(
                s,
                &[
                    SOCKS5_VERSION,
                    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
                    0,
                    SOCKS5_ADDR_TYPE_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
            .await?;
            anyhow::bail!("unsupported cmd");
        }
    }
}

pub(crate) async fn handle_socks(
    mut s: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
    timeout: Duration,
) -> Result<()> {
    let request = match tokio::time::timeout(SOCKS_NEGOTIATE_TIMEOUT, negotiate(&mut s)).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("socks negotiation timed out"),
    };
    let target = match request {
        SocksRequest::Connect(t) => t,
        SocksRequest::Associate => return handle_udp_associate(s, pool, hub, egress_shared).await,
    };
    let bnd: SocketAddr = bnd_for(&s).unwrap_or_else(|_| {
        s.peer_addr()
            .map(|p| SocketAddr::new(unmap(p.ip()), 0))
            .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0))
    });

    let slot_idx = pool.pick_tcp_index(&target);
    let slot = pool.slot(slot_idx);
    let mut gen_rx = slot.gen_rx.clone();
    let conn = match slot.wait_conn(&mut gen_rx, timeout).await {
        Ok(c) => c,
        Err(e) => {
            // Answer the SOCKS client instead of just dropping the TCP
            // connection (a reset looks like a proxy crash to the app).
            write_socks_reply(
                &mut s,
                fast_socks5::consts::SOCKS5_REPLY_HOST_UNREACHABLE,
                bnd,
            )
            .await
            .ok();
            return Err(e);
        }
    };
    let (mut send, mut recv) =
        match tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await {
            Ok(Ok((s, r))) => {
                let prio = if pool.is_interactive(&target) { 10 } else { 0 };
                let _ = s.set_priority(prio);
                (s, r)
            }
            _ => {
                if conn.close_reason().is_some() {
                    // Atomic read-then-clear with re-check: a reconnect may install
                    // a fresh connection between a read and a later clear, and
                    // clearing unconditionally would blackhole the new connection
                    // until it dies. `clear_if_and_mark_dead` matches on
                    // `stable_id` and folds the `live = false` into the same `rcu`
                    // closure, so the decision, the store and the liveness bit
                    // cannot be split by a concurrent publish.
                    //
                    // The SOCKS failure is a second writer on this slot, and it
                    // shares the reconnect loop's one death commit: on top of the
                    // clear, `retire_dead_slot` releases the dead generation's
                    // egress-cache handles and its rev2 registry/staged payloads
                    // and bumps the generation, exactly as the loop does when its
                    // own future ends. Without it a connection death first noticed
                    // here would leave the previous generation's state behind
                    // until the loop's watchdog noticed, and a dead egress handle
                    // could outlive the redial. Whichever writer wins the clear
                    // owns the whole cleanup, so nothing is released twice.
                    retire_dead_slot(&slot, slot_idx, &egress_shared, &conn);
                    write_socks_reply(
                        &mut s,
                        fast_socks5::consts::SOCKS5_REPLY_HOST_UNREACHABLE,
                        bnd,
                    )
                    .await
                    .ok();
                    anyhow::bail!("quic connection dead, retry");
                }
                write_socks_reply(
                    &mut s,
                    fast_socks5::consts::SOCKS5_REPLY_GENERAL_FAILURE,
                    bnd,
                )
                .await
                .ok();
                anyhow::bail!("quic stream open failed (limit?), retry without killing conn");
            }
        };
    // The open header is deliberately its own write, flushed before any
    // application byte is read: a peer that waits for its first reply
    // (game login, banner protocols) must see the header within ~100ms
    // without the client ever sending payload. Never batch it behind the
    // first app chunk; `tcp_open_header_arrives_without_app_data` pins this.
    // Stack buffer: the header is at most 259 B, so the per-flow `Vec` this
    // used to allocate was one heap round trip for bytes that live one write.
    let mut hdr = [0u8; AddrHeader::MAX_LEN];
    let hdr_len = target.as_ref().header()?.encode_into(&mut hdr);
    // Bounded: without a deadline a stalled connection parks this write until
    // the QUIC idle timeout, pinning the app socket with no SOCKS answer and
    // no idle watchdog (the watchdog lives inside the pump, which has not
    // started yet). SOCKS success has not been sent at this point, so the
    // failure still surfaces as a SOCKS error rather than a close.
    let hdr_sent = tokio::time::timeout(Duration::from_secs(5), send.write_all(&hdr[..hdr_len]))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !hdr_sent {
        send.reset(0x04u32.into()).ok();
        recv.stop(0x04u32.into()).ok();
        write_socks_reply(
            &mut s,
            fast_socks5::consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            bnd,
        )
        .await
        .ok();
        anyhow::bail!("quic stream header write failed or timed out");
    }
    // Optimistic SOCKS success: the application's first bytes must not be
    // serialized behind the server-side dial. Waiting for the MQP-2 ACK here
    // costs one full client<->server RTT on every connection (Hysteria/
    // juicity-class clients answer immediately for exactly this reason).
    // BND.ADDR is unknown at this point, so report 0.0.0.0:0 (the conventional
    // "not available" value); the ACK is consumed by the reply direction and a
    // failed dial tears the TCP flow down instead of returning a SOCKS error.
    // A failed reply write means the app is gone: reset/stop the stream so the
    // peer reads an abort, not the clean FIN a dropped `SendStream` sends
    // (quinn's `Drop` calls `finish()`), which would advertise a truncated
    // flow as complete.
    let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    if let Err(e) =
        write_socks_reply(&mut s, fast_socks5::consts::SOCKS5_REPLY_SUCCEEDED, unknown).await
    {
        send.reset(0x04u32.into()).ok();
        recv.stop(0x04u32.into()).ok();
        return Err(e);
    }
    match copy_tcp_quic_acked(
        s,
        send,
        recv,
        Duration::from_secs(300),
        TCP_DIAL_ACK_TIMEOUT,
    )
    .await
    {
        Ok((up, down)) => {
            tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
        }
        Err(e) => {
            // Abnormal ends already RST the TCP flow inside the pump; log the
            // path snapshot so loss-driven kills are diagnosable in one line.
            // Sampled: `stats()` takes the quinn lock, so an abort storm must
            // not pay it per flow.
            //
            // Selection-time path health: `pick_tcp_index` now re-picks a slot
            // away when the reconnect loop's published inbound-progress stamp
            // is older than `data_stale_threshold_ms` (~7 s with the shipped
            // 5 s keepalive, strictly below the `max(2x keepalive, 8 s)` ~10 s
            // silence watchdog). A connection that blackholes *before* this
            // flow's `pick_tcp` therefore stops receiving new flows at the
            // first selection after its stamp goes stale, instead of swallowing
            // every CONNECT for the whole ~10 s watchdog window. The selection
            // gate changes routing only: the watchdog remains the authority
            // that force-closes the dead connection and redials it.
            //
            // The residual limitation is the in-flight flow: once the
            // optimistic SOCKS success reply above has been sent, a flow that
            // was assigned to the slot before it blackholed cannot be retried
            // on a sibling — the only truthful signal left is to tear the flow
            // down (the pump RSTs), because the application already believes
            // the CONNECT succeeded. Retrying before the reply would mortgage
            // every connection's latency for a rare outage; recovering at
            // selection time is what keeps a blackhole from claiming flows at
            // all.
            if tcp_abort_log_due() {
                let st = conn.stats();
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
    Ok(())
}

/// NOTE: the `read_exact`-per-field read shape is kept on purpose.
/// An earlier stack-buffer rewrite (one buffer + a `read`-loop tail) was
/// implemented and reverted: on macOS it reproducibly lost the final port byte
/// of a domain target (`bad connect target` on every domain CONNECT), while the
/// `read_exact`-per-field shape passes 30/30. This version changes only *where*
/// the bytes land (one stack buffer instead of assembled `Vec`s); every read
/// keeps the proven size and order. No per-field deadline here: `negotiate`'s
/// caller bounds the whole negotiation with one timeout.
pub(crate) async fn read_socks_addr(s: &mut tokio::net::TcpStream) -> Result<TargetAddr> {
    use fast_socks5::consts::*;
    let mut buf = [0u8; AddrHeader::MAX_LEN];
    s.read_exact(&mut buf[..1]).await.context("socks atyp")?;
    let len = match buf[0] {
        SOCKS5_ADDR_TYPE_IPV4 => {
            s.read_exact(&mut buf[1..7]).await.context("socks v4")?;
            7
        }
        SOCKS5_ADDR_TYPE_IPV6 => {
            s.read_exact(&mut buf[1..19]).await.context("socks v6")?;
            19
        }
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            s.read_exact(&mut buf[1..2])
                .await
                .context("socks domain len")?;
            let n = buf[1] as usize;
            if n == 0 {
                anyhow::bail!("empty domain");
            }
            s.read_exact(&mut buf[2..4 + n])
                .await
                .context("socks domain")?;
            4 + n
        }
        x => anyhow::bail!("bad atyp {x}"),
    };
    Ok(TargetAddr::decode(&buf[..len])?.0)
}

pub(crate) async fn read_socks_addr_lenient(s: &mut tokio::net::TcpStream) -> Result<()> {
    use fast_socks5::consts::*;
    let mut t = [0u8; 1];
    s.read_exact(&mut t).await.context("socks atyp")?;
    match t[0] {
        SOCKS5_ADDR_TYPE_IPV4 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.context("socks v4")?;
            Ok(())
        }
        SOCKS5_ADDR_TYPE_IPV6 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await.context("socks v6")?;
            Ok(())
        }
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await.context("socks domain len")?;
            if n[0] == 0 {
                anyhow::bail!("empty domain");
            }
            let mut b = vec![0u8; n[0] as usize + 2];
            s.read_exact(&mut b).await.context("socks domain")?;
            Ok(())
        }
        x => anyhow::bail!("bad atyp {x}"),
    }
}

/// SOCKS control writes are tiny; a stalled local reader must not pin this
/// task (and its connection permit) indefinitely.
pub(crate) async fn write_socks(s: &mut tokio::net::TcpStream, buf: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), s.write_all(buf))
        .await
        .context("socks write timed out")??;
    Ok(())
}

pub(crate) fn bnd_for(s: &tokio::net::TcpStream) -> Result<SocketAddr> {
    let local = s.local_addr()?;
    let ip = unmap(local.ip());
    // An accepted socket's local address is concrete in practice; the
    // unspecified branch only fires for an unbound/odd socket. Falling back
    // to the peer (client) address there misreports BND as the client itself,
    // so report an unavailable address instead (the error REP is what the app
    // acts on; BND is informational on failures).
    let ip = if ip.is_unspecified() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        ip
    };
    Ok(SocketAddr::new(ip, local.port()))
}

pub(crate) async fn write_socks_reply(
    s: &mut tokio::net::TcpStream,
    rep: u8,
    bnd: SocketAddr,
) -> Result<()> {
    use fast_socks5::consts::SOCKS5_VERSION;
    let mut v = [0u8; 3 + MAX_BND_LEN];
    v[0] = SOCKS5_VERSION;
    v[1] = rep;
    v[2] = 0x00;
    let n = 3 + encode_bnd_addr_into(bnd, &mut v[3..]);
    write_socks(s, &v[..n]).await
}
