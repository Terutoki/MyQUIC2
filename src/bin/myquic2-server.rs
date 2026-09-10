//! myquic2-server: QUIC ingress -> TCP/UDP dial-out. BBR+GSO defaults, self-signed TLS13.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-server.toml")]
    config: String,
}

type SessEntry = (
    Arc<tokio::net::UdpSocket>,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicU64>,
);
type SessTable = Arc<tokio::sync::RwLock<HashMap<u32, SessEntry>>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let a = Args::parse();
    let c: ServerConf = load_toml(&a.config)?;
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let listen: SocketAddr = c.listen.parse().context("bad listen")?;

    // Self-signed cert: auto-generate on first run (fast path, no external CA RTT).
    if !Path::new(&c.cert_file).exists() || !Path::new(&c.key_file).exists() {
        info!("generating self-signed cert for {}", c.server_name);
        gen_self_signed_files(&c.server_name, &c.cert_file, &c.key_file)?;
    }
    let cert = load_cert_der(&c.cert_file)?;
    let key = load_key_der(&c.key_file)?;
    let tls = server_tls_config(cert, key)?;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    scfg.transport_config(build_transport(&c.congestion, c.keep_alive_secs));
    // Dual-stack QUIC socket: explicit V6ONLY=0 so [::] also serves IPv4-mapped clients.
    let rt = Arc::new(quinn::TokioRuntime);
    let std_sock = udp_socket_dual(&c.listen)?;
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(scfg),
        rt.wrap_udp_socket(std_sock)?,
        rt,
    )?;
    info!(
        "server listening on {listen} congestion={} gso_auto={} (quinn-udp probes UDP_SEGMENT/GRO)",
        c.congestion, c.gso
    );
    if !c.gso {
        warn!("gso=false requested: quinn still uses GRO/GSO if kernel supports; set only affects logging");
    }

    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => continue,
        };
        // 0.5-RTT accept: streams usable before handshake completes on resumption.
        let conn = match incoming.accept() {
            Ok(connecting) => match connecting.into_0rtt() {
                Ok((c, _)) => c,
                Err(connecting) => match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("accept err: {e:#}");
                        continue;
                    }
                },
            },
            Err(e) => {
                warn!("accept err: {e:#}");
                continue;
            }
        };
        let allow_private = c.allow_private;
        tokio::spawn(async move {
            if let Err(e) = handle_conn(conn, allow_private).await {
                warn!("conn end: {e:#}");
            }
        });
    }
}

async fn handle_conn(conn: quinn::Connection, allow_private: bool) -> Result<()> {
    info!("new QUIC conn from {}", conn.remote_address());
    // One UDP socket per sess_id: replies are inherently demuxed, concurrent
    // ASSOCIATEs sharing this QUIC connection never cross-talk.
    let sess: SessTable = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    {
        let sess = sess.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        let mut m = sess.write().await;
                        let expired: Vec<u32> = m
                            .iter()
                            .filter(|(_, (_, _, t))| {
                                now.saturating_sub(t.load(std::sync::atomic::Ordering::Relaxed)) >= 180_000
                            })
                            .map(|(k, _)| *k)
                            .collect();
                        for k in expired {
                            if let Some((_, h, _)) = m.remove(&k) {
                                h.abort();
                            }
                        }
                    }
                    _ = conn.closed() => {
                        let mut m = sess.write().await;
                        for (_, (_, h, _)) in m.drain() {
                            h.abort();
                        }
                        break;
                    }
                }
            }
        });
    }
    // QUIC DATAGRAMs -> per-sess UDP sockets
    let cd = conn.clone();
    let ss = sess.clone();
    tokio::spawn(async move {
        loop {
            let d: Bytes = match cd.read_datagram().await {
                Ok(d) => d,
                Err(_) => break,
            };
            let (s, addr, payload) = match decode_datagram(&d) {
                Ok(x) => x,
                Err(_) => continue,
            };
            match addr {
                TargetAddr::Ip(dst) => {
                    if !allow_private && !is_global_ip(dst.ip()) {
                        continue;
                    }
                    let sock = match get_or_create_sess(&ss, &cd, s).await {
                        Some(v) => v,
                        None => continue,
                    };
                    let _ = sock.send_to(payload, map_for_dual(dst)).await;
                }
                TargetAddr::Domain(h, p) => {
                    // Fast path: cached DNS avoids per-packet spawn (P1).
                    if let Some(v) = lookup_cached_sync(&h, p) {
                        let dst = match v.into_iter().next() {
                            Some(v) => v,
                            None => continue,
                        };
                        if !allow_private && !is_global_ip(dst.ip()) {
                            continue;
                        }
                        let sock = match get_or_create_sess(&ss, &cd, s).await {
                            Some(v) => v,
                            None => continue,
                        };
                        let _ = sock.send_to(payload, map_for_dual(dst)).await;
                    } else {
                        let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let ss = ss.clone();
                        let cd = cd.clone();
                        let payload = Bytes::copy_from_slice(payload);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let dst = match resolve_all_cached(&h, p).await {
                                Ok(v) => match v.into_iter().next() {
                                    Some(v) => v,
                                    None => return,
                                },
                                Err(_) => return,
                            };
                            if !allow_private && !is_global_ip(dst.ip()) {
                                return;
                            }
                            let sock = match get_or_create_sess(&ss, &cd, s).await {
                                Some(v) => v,
                                None => return,
                            };
                            let _ = sock.send_to(&payload, map_for_dual(dst)).await;
                        });
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // TCP: one QUIC bidi stream per connection. First bytes = MQP addr header.
    // Bound concurrent dials so fast open/close cannot exhaust FDs/DNS.
    let dial_sem = Arc::new(tokio::sync::Semaphore::new(1024));
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => break,
        };
        let permit = match dial_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                send.reset(0x04u32.into()).ok();
                continue;
            }
        };
        tokio::spawn(async move {
            let _permit = permit;
            let target: TargetAddr = match tokio::time::timeout(
                Duration::from_secs(10),
                read_mqp_target(&mut recv),
            )
            .await
            {
                Ok(Ok(t)) => t,
                _ => {
                    send.reset(0x01u32.into()).ok();
                    return;
                }
            };
            let cands = match &target {
                TargetAddr::Ip(s) => vec![*s],
                TargetAddr::Domain(h, p) => resolve_all_cached(h, *p).await.unwrap_or_default(),
            };
            let tcp = match dial_happy_eyeballs(cands, allow_private).await {
                Some(t) => t,
                None => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            let _ = tcp.set_nodelay(true);
            if send.write_all(&[MQP_TCP_ACK]).await.is_err() {
                return;
            }
            let _ = copy_tcp_quic_idle(tcp, send, recv, Duration::from_secs(300)).await;
        });
    }
    Ok(())
}

async fn read_mqp_target(recv: &mut quinn::RecvStream) -> Result<TargetAddr> {
    async fn rd(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(buf))
            .await
            .context("hdr timeout")??;
        Ok(())
    }
    let mut atyp = [0u8; 1];
    rd(recv, &mut atyp).await?;
    let full: Vec<u8> = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 6];
            rd(recv, &mut b).await?;
            let mut full = Vec::with_capacity(7);
            full.push(0x01);
            full.extend_from_slice(&b);
            full
        }
        0x04 => {
            let mut b = [0u8; 18];
            rd(recv, &mut b).await?;
            let mut full = Vec::with_capacity(19);
            full.push(0x04);
            full.extend_from_slice(&b);
            full
        }
        0x03 => {
            let mut n = [0u8; 1];
            rd(recv, &mut n).await?;
            if n[0] == 0 {
                anyhow::bail!("empty domain");
            }
            let mut rest = vec![0u8; n[0] as usize + 2];
            rd(recv, &mut rest).await?;
            let mut full = Vec::with_capacity(2 + n[0] as usize + 2);
            full.push(0x03);
            full.push(n[0]);
            full.extend_from_slice(&rest);
            full
        }
        a => anyhow::bail!("bad atyp {a}"),
    };
    Ok(TargetAddr::decode(&full)?.0)
}

async fn dial_happy_eyeballs(
    cands: Vec<SocketAddr>,
    allow_private: bool,
) -> Option<tokio::net::TcpStream> {
    let cands: Vec<SocketAddr> = cands
        .into_iter()
        .filter(|a| allow_private || is_global_ip(a.ip()))
        .take(8)
        .collect();
    if cands.is_empty() {
        return None;
    }
    // Total budget 4s so the client-side 7s ACK wait always covers us.
    let budget = tokio::time::sleep(Duration::from_secs(4));
    tokio::pin!(budget);
    if cands.len() == 1 {
        tokio::select! {
            r = tokio::net::TcpStream::connect(cands[0]) => {
                let s = r.ok()?;
                let _ = s.set_nodelay(true);
                return Some(s);
            }
            _ = &mut budget => return None,
        }
    }
    let won = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(1);
    for (i, a) in cands.into_iter().enumerate() {
        let tx = tx.clone();
        let won = won.clone();
        tokio::spawn(async move {
            if i > 0 {
                let mut waited = 0u64;
                let delay = 250 * i.min(4) as u64;
                while waited < delay {
                    if won.load(std::sync::atomic::Ordering::Relaxed) || tx.is_closed() {
                        return;
                    }
                    let step = 50.min(delay - waited);
                    tokio::time::sleep(Duration::from_millis(step)).await;
                    waited += step;
                }
            }
            if won.load(std::sync::atomic::Ordering::Relaxed) || tx.is_closed() {
                return;
            }
            tokio::select! {
                r = tokio::net::TcpStream::connect(a) => {
                    if let Ok(s) = r {
                        let _ = s.set_nodelay(true);
                        if won.compare_exchange(
                            false, true,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Relaxed,
                        ).is_ok() {
                            let _ = tx.try_send(s);
                        }
                    }
                }
                _ = async {
                    while !won.load(std::sync::atomic::Ordering::Relaxed) && !tx.is_closed() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                } => {}
            }
        });
    }
    drop(tx);
    let res = tokio::select! {
        r = rx.recv() => r,
        _ = &mut budget => None,
    };
    won.store(true, std::sync::atomic::Ordering::Relaxed);
    res
}

async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    s: u32,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Fast path: single read lock + lock-free timestamp bump. No write lock
    // per packet, so concurrent sessions never serialize on a global lock.
    {
        let r = ss.read().await;
        if let Some((sock, _, t)) = r.get(&s) {
            let sock = sock.clone();
            t.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
            return Some(sock);
        }
    }
    // Slow path holds the write lock across check+insert so concurrent
    // packets for the same sess cannot create duplicate sockets (B8).
    let mut w = ss.write().await;
    if let Some((sock2, _, t)) = w.get(&s) {
        t.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
        return Some(sock2.clone());
    }
    if w.len() >= 4096 + 64 {
        let mut oldest: Vec<(u64, u32)> = Vec::with_capacity(w.len());
        for (k, (_, _, t)) in w.iter() {
            if *k == s {
                continue;
            }
            oldest.push((t.load(std::sync::atomic::Ordering::Relaxed), *k));
        }
        oldest.sort_unstable_by_key(|(t, _)| *t);
        let excess = w.len().saturating_sub(4096);
        for (_, k) in oldest.into_iter().take(excess.max(1)) {
            if let Some((_, hh, _)) = w.remove(&k) {
                hh.abort();
            }
        }
    }
    let raw = udp_socket_dual_small("[::]:0").ok()?;
    let sock = Arc::new(tokio::net::UdpSocket::from_std(raw).ok()?);
    let c2 = cd.clone();
    let rs = sock.clone();
    let ss2 = ss.clone();
    let h = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = match tokio::time::timeout(
                Duration::from_secs(180),
                rs.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(x)) => x,
                _ => break,
            };
            if n == buf.len() {
                continue;
            }
            let src = SocketAddr::new(unmap(src.ip()), src.port());
            // Cap by the connection's live max datagram size when known.
            let limit = c2.max_datagram_size().unwrap_or(1350);
            let d = match encode_datagram_with_limit(s, &TargetAddr::Ip(src), &buf[..n], limit.min(1350)) {
                Some(d) => d,
                None => continue,
            };
            if c2.send_datagram(d).is_err() {
                if c2.close_reason().is_some() {
                    break;
                }
                continue;
            }
        }
        // Self-reap: task exit removes the zombie entry instead of waiting 180s.
        let mut w = ss2.write().await;
        if let Some((cur, _, _)) = w.get(&s) {
            if Arc::ptr_eq(cur, &rs) {
                if let Some((_, hh, _)) = w.remove(&s) {
                    hh.abort();
                }
            }
        }
    });
    w.insert(
        s,
        (
            sock.clone(),
            h,
            Arc::new(std::sync::atomic::AtomicU64::new(mono_millis())),
        ),
    );
    Some(sock)
}
