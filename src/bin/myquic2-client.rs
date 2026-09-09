//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::RwLock};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-client.toml")]
    config: String,
}

type SharedConn = Arc<RwLock<Option<quinn::Connection>>>;

/// Routes inbound QUIC DATAGRAMs to their UDP ASSOCIATE by sess_id.
/// One dispatcher serves the whole process across reconnects; subscriptions
/// die with their association, so no immortal task can steal another's packets.
struct UdpHub {
    subs: std::sync::Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>>,
    next: std::sync::atomic::AtomicU32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let a = Args::parse();
    let c: ClientConf = load_toml(&a.config)?;
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?)?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_client));
    ccfg.transport_config(build_transport(&c.congestion, c.keep_alive_secs));
    let ccfg = Arc::new(ccfg);
    let server: SocketAddr = c.server_addr.parse().context("bad server_addr")?;

    // Single Endpoint for the process lifetime: one UDP socket, shared session-ticket
    // cache (0-RTT resumption) and CID routing for every dial. Never recreate per dial.
    // Bound dual-stack so servers reachable over IPv4-mapped or native IPv6 both work.
    let mut ep = quinn::Endpoint::client("[::]:0".parse()?)?;
    ep.set_default_client_config((*ccfg).clone());

    let shared: SharedConn = Arc::new(RwLock::new(None));
    let hub: Arc<UdpHub> = Arc::new(UdpHub {
        subs: std::sync::Mutex::new(HashMap::new()),
        next: std::sync::atomic::AtomicU32::new(1),
    });
    // Sole DATAGRAM reader for the process: routes by sess_id to the live association.
    {
        let shared = shared.clone();
        let hub = hub.clone();
        tokio::spawn(async move {
            loop {
                let conn = match wait_conn(&shared, Duration::from_secs(10)).await {
                    Ok(c) => c, Err(_) => continue,
                };
                loop {
                    let d: Bytes = match conn.read_datagram().await {
                        Ok(d) => d, Err(_) => break,
                    };
                    let sess = match decode_datagram(&d) {
                        Ok((s, _, _)) => s, Err(_) => continue,
                    };
                    let tx = hub.subs.lock().unwrap().get(&sess).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(d);
                    }
                }
            }
        });
    }
    // Reconnect loop: survives server restart. Backoff 200ms..5s + jitter.
    {
        let shared = shared.clone();
        let sname = c.server_name.clone();
        let ep = ep.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(200);
            loop {
                match dial_once(&ep, server, &sname).await {
                    Ok(conn) => {
                        info!("QUIC connected to {server}");
                        *shared.write().await = Some(conn);
                        backoff = Duration::from_millis(200);
                        // wait until connection dies
                        loop {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            let dead = shared.read().await.as_ref().map(|c| c.close_reason().is_some()).unwrap_or(true);
                            if dead { break; }
                        }
                        warn!("QUIC connection lost, reconnecting...");
                        *shared.write().await = None;
                    }
                    Err(e) => {
                        warn!("dial {server} failed: {e:#}; retry in {backoff:?}");
                        tokio::time::sleep(backoff + Duration::from_millis(fastrand_jitter())).await;
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                    }
                }
            }
        });
    }

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!("socks5 listening on {listen} -> QUIC {server} (dns=server-side, auth=none, tls13-pinned, 0rtt)");
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    loop {
        let (sock, peer) = li.accept().await?;
        let shared = shared.clone();
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks(sock, shared, hub, timeout).await {
                warn!("socks {peer} end: {e:#}");
            }
        });
    }
}

fn fastrand_jitter() -> u64 {
    // tiny xorshift jitter, no extra dep
    use std::cell::Cell;
    thread_local! { static S: Cell<u64> = Cell::new(0x9e3779b97f4a7c15); }
    S.with(|s| {
        let mut x = s.get();
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) % 200
    })
}

async fn dial_once(ep: &quinn::Endpoint, server: SocketAddr, name: &str) -> Result<quinn::Connection> {
    let t0 = tokio::time::Instant::now();
    let connecting = ep.connect(server, name)?;
    // 0-RTT fast path: on resumption the connection is usable immediately, saving 1 RTT.
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            tokio::spawn(async move {
                info!("QUIC resumption: 0-RTT keys accepted={}", accepted.await);
            });
            Ok(conn)
        }
        Err(connecting) => {
            let conn = connecting.await?;
            info!("QUIC full handshake in {:?}", t0.elapsed());
            Ok(conn)
        }
    }
}

async fn wait_conn(shared: &SharedConn, timeout: Duration) -> Result<quinn::Connection> {
    let t0 = tokio::time::Instant::now();
    loop {
        if let Some(c) = shared.read().await.clone() {
            if c.close_reason().is_none() { return Ok(c); }
        }
        if t0.elapsed() > timeout { anyhow::bail!("quic unavailable (server restarting?)"); }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---- SOCKS5 (RFC1928, no-auth only) ----
async fn handle_socks(mut s: tokio::net::TcpStream, shared: SharedConn, hub: Arc<UdpHub>, timeout: Duration) -> Result<()> {
    // handshake: VER NMETHODS METHODS; we only support 0x00
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 0x05 { anyhow::bail!("bad ver"); }
    let mut m = vec![0u8; h[1] as usize];
    s.read_exact(&mut m).await?;
    if !m.contains(&0x00) {
        s.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    s.write_all(&[0x05, 0x00]).await?;

    let mut r = [0u8; 3];
    s.read_exact(&mut r).await?;
    if r[0] != 0x05 { anyhow::bail!("bad req ver"); }
    let target = match r[1] {
        0x01 => read_socks_addr(&mut s).await?,   // CONNECT
        0x03 => { // UDP ASSOCIATE
            let _ = read_socks_addr(&mut s).await?;
            return handle_udp_associate(s, shared, hub).await;
        }
        _ => {
            s.write_all(&[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("unsupported cmd");
        }
    };
    // Server-side DNS: domain is forwarded as-is for the server to resolve.
    // Min-RTT: reply success BEFORE remote dial completes. BND must be dialable:
    // unmap v4-mapped addrs, and never report wildcard (substitute the peer's IP).
    let bnd: SocketAddr = {
        let local = s.local_addr()?;
        let ip = unmap(local.ip());
        let ip = if ip.is_unspecified() { unmap(s.peer_addr()?.ip()) } else { ip };
        SocketAddr::new(ip, local.port())
    };
    write_socks_reply(&mut s, 0x00, bnd).await?;

    let conn = wait_conn(&shared, timeout).await?;
    let (send, recv) = match tokio::time::timeout(Duration::from_secs(3), conn.open_bi()).await {
        Ok(Ok(x)) => x,
        _ => {
            *shared.write().await = None;
            anyhow::bail!("quic stream open failed (server restarting?), retry");
        }
    };
    let mut hdr = Vec::with_capacity(20);
    target.encode(&mut hdr);
    let mut send = send;
    send.write_all(&hdr).await?;
    let _ = copy_tcp_quic(s, send, recv).await;
    Ok(())
}

async fn read_socks_addr(s: &mut tokio::net::TcpStream) -> Result<TargetAddr> {
    let mut t = [0u8; 1];
    s.read_exact(&mut t).await?;
    match t[0] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            let mut v = vec![0x01];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let mut v = vec![0x04];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        0x03 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            let mut b = vec![0u8; n[0] as usize + 2];
            s.read_exact(&mut b).await?;
            let mut v = vec![0x03, n[0]];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        x => anyhow::bail!("bad atyp {x}"),
    }
}

async fn write_socks_reply(s: &mut tokio::net::TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    let mut v = vec![0x05, rep, 0x00];
    match bnd {
        SocketAddr::V4(a) => {
            v.push(0x01);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            v.push(0x04);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    s.write_all(&v).await?;
    Ok(())
}

// ---- UDP ASSOCIATE: app <-> local relay <-> QUIC DATAGRAM ----
async fn handle_udp_associate(
    tcp: tokio::net::TcpStream,
    shared: SharedConn,
    hub: Arc<UdpHub>,
) -> Result<()> {
    let sess = hub.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(1024);
    hub.subs.lock().unwrap().insert(sess, tx);
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0")?)?;
    let relay_port = relay.local_addr()?.port();
    let relay_reply = SocketAddr::new(unmap(tcp.peer_addr()?.ip()), relay_port);
    let mut tcp = tcp;
    write_socks_reply(&mut tcp, 0x00, relay_reply).await?;
    let relay = Arc::new(relay);
    // hub -> app: ends when this association is torn down (sender removed).
    {
        let r2 = relay.clone();
        let last_app: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));
        let last_app_w = last_app.clone();
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                let (_, addr, payload) = match decode_datagram(&d) {
                    Ok(x) => x, Err(_) => continue,
                };
                let dst = match addr {
                    TargetAddr::Ip(s) => s,
                    TargetAddr::Domain(h, p) => match resolve_server_side(&h, p).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                };
                if let Some(app) = *last_app.read().await {
                    let mut pkt = vec![0, 0, 0];
                    let mut ah = Vec::new();
                    TargetAddr::Ip(dst).encode(&mut ah);
                    pkt.extend_from_slice(&ah);
                    pkt.extend_from_slice(payload);
                    let _ = r2.send_to(&pkt, map_for_dual(app)).await;
                }
            }
        });
        // app -> QUIC with this association's sess.
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                r = relay.recv_from(&mut buf) => {
                    let (n, app) = r?;
                    *last_app_w.write().await = Some(app);
                    if n < 4 || buf[2] != 0x00 { continue; }
                    let addr = match TargetAddr::decode(&buf[3..n]) {
                        Ok((a, _)) => a,
                        Err(_) => continue,
                    };
                    let payload_off = 3 + TargetAddr::decode(&buf[3..n])?.1;
                    let payload = &buf[payload_off..n];
                    let d = match encode_datagram(sess, &addr, payload) {
                        Some(d) => d, None => continue,
                    };
                    if let Ok(conn) = wait_conn(&shared, Duration::from_millis(500)).await {
                        let _ = conn.send_datagram(d);
                    }
                }
                _ = tcp.readable() => {
                    let mut b = [0u8; 1];
                    match tcp.try_read(&mut b) {
                        Ok(0) => break,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        _ => break,
                    }
                }
            }
        }
    }
    hub.subs.lock().unwrap().remove(&sess);
    Ok(())
}
