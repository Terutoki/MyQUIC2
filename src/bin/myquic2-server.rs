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

type SessEntry = (Arc<tokio::net::UdpSocket>, std::time::Instant);
type SessTable = Arc<tokio::sync::Mutex<HashMap<u32, SessEntry>>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let a = Args::parse();
    let c: ServerConf = load_toml(&a.config)?;
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
    let sess: SessTable = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    // Idle sweep tied to the connection lifetime so closed connections
    // release their tasks instead of leaking one sweeper each.
    {
        let sess = sess.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let mut m = sess.lock().await;
                        m.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(180));
                    }
                    _ = conn.closed() => break,
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
            let dst = match addr {
                TargetAddr::Ip(s) => s,
                TargetAddr::Domain(h, p) => match resolve_all_cached(&h, p).await {
                    Ok(v) => match v.into_iter().next() {
                        Some(s) => s,
                        None => continue,
                    },
                    Err(_) => continue,
                },
            };
            if !allow_private && !is_global_ip(dst.ip()) {
                continue;
            }
            let sock = {
                // Fast path: short critical section for lookup/touch only.
                let cached = {
                    let mut m = ss.lock().await;
                    if let Some((s, t)) = m.get_mut(&s) {
                        *t = std::time::Instant::now();
                        Some(s.clone())
                    } else {
                        None
                    }
                };
                if let Some(sock) = cached {
                    sock
                } else {
                    let raw = match udp_socket_dual("[::]:0") {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let sock = match tokio::net::UdpSocket::from_std(raw) {
                        Ok(r) => Arc::new(r),
                        Err(_) => continue,
                    };
                    // Reply loop tags this sess so the client can route it back.
                    let c2 = cd.clone();
                    let rs = sock.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 2048];
                        loop {
                            let (n, src) = match rs.recv_from(&mut buf).await {
                                Ok(x) => x,
                                Err(_) => break,
                            };
                            let src = SocketAddr::new(unmap(src.ip()), src.port());
                            let d = match encode_datagram(s, &TargetAddr::Ip(src), &buf[..n]) {
                                Some(d) => d,
                                None => continue,
                            };
                            if c2.send_datagram(d).is_err() {
                                break;
                            }
                        }
                    });
                    {
                        let mut m = ss.lock().await;
                        // Re-check under lock: another packet may have created it.
                        if let Some((s2, t)) = m.get_mut(&s) {
                            *t = std::time::Instant::now();
                            s2.clone()
                        } else {
                            m.insert(s, (sock.clone(), std::time::Instant::now()));
                            // Bound sessions per connection; evict oldest on overflow.
                            if m.len() > 4096 {
                                let oldest = m.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k);
                                if let Some(k) = oldest {
                                    if k != s {
                                        m.remove(&k);
                                    }
                                }
                            }
                            sock
                        }
                    }
                }
            };
            let _ = sock.send_to(payload, map_for_dual(dst)).await;
        }
        Ok::<(), anyhow::Error>(())
    });

    // TCP: one QUIC bidi stream per connection. First bytes = MQP addr header.
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => break,
        };
        tokio::spawn(async move {
            async fn read_hdr(recv: &mut quinn::RecvStream, n: usize) -> Option<Vec<u8>> {
                let mut b = vec![0u8; n];
                match tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut b)).await {
                    Ok(Ok(())) => Some(b),
                    _ => None,
                }
            }
            let head = match read_hdr(&mut recv, 1).await {
                Some(h) => h,
                None => {
                    send.reset(0x01u32.into()).ok();
                    return;
                }
            };
            let full: Vec<u8> = match head[0] {
                0x01 => {
                    let b = match read_hdr(&mut recv, 6).await {
                        Some(b) => b,
                        None => {
                            send.reset(0x01u32.into()).ok();
                            return;
                        }
                    };
                    let mut full = Vec::with_capacity(7);
                    full.push(0x01);
                    full.extend_from_slice(&b);
                    full
                }
                0x04 => {
                    let b = match read_hdr(&mut recv, 18).await {
                        Some(b) => b,
                        None => {
                            send.reset(0x01u32.into()).ok();
                            return;
                        }
                    };
                    let mut full = Vec::with_capacity(19);
                    full.push(0x04);
                    full.extend_from_slice(&b);
                    full
                }
                0x03 => {
                    let n = match read_hdr(&mut recv, 1).await {
                        Some(b) => b[0] as usize,
                        None => {
                            send.reset(0x01u32.into()).ok();
                            return;
                        }
                    };
                    let rest = match read_hdr(&mut recv, n + 2).await {
                        Some(b) => b,
                        None => {
                            send.reset(0x01u32.into()).ok();
                            return;
                        }
                    };
                    let mut full = Vec::with_capacity(2 + n + 2);
                    full.push(0x03);
                    full.push(n as u8);
                    full.extend_from_slice(&rest);
                    full
                }
                _ => {
                    send.reset(0x01u32.into()).ok();
                    return;
                }
            };
            let target: TargetAddr = match TargetAddr::decode(&full) {
                Ok((t, _)) => t,
                Err(_) => {
                    send.reset(0x01u32.into()).ok();
                    return;
                }
            };
            // Dual-stack dial: try every resolved address until one connects.
            let cands = match &target {
                TargetAddr::Ip(s) => vec![*s],
                TargetAddr::Domain(h, p) => resolve_all_cached(h, *p).await.unwrap_or_default(),
            };
            let mut tcp_ok = None;
            for a in cands.into_iter().take(8) {
                if !allow_private && !is_global_ip(a.ip()) {
                    continue;
                }
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(a),
                )
                .await
                {
                    Ok(Ok(t)) => {
                        tcp_ok = Some(t);
                        break;
                    }
                    _ => continue,
                }
            }
            let tcp = match tcp_ok {
                Some(t) => t,
                None => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            let _ = copy_tcp_quic(tcp, send, recv).await;
        });
    }
    Ok(())
}
