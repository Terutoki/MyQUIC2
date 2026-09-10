//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{watch, RwLock},
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-client.toml")]
    config: String,
}

type SharedConn = Arc<RwLock<Option<quinn::Connection>>>;

/// Bump the connection-generation counter. Split across two statements on
/// purpose: the borrow's read guard must drop before `send_replace` takes
/// the write lock, otherwise this self-deadlocks inside one statement.
fn bump_gen(tx: &watch::Sender<u64>) {
    let next = tx.borrow().wrapping_add(1);
    tx.send_replace(next);
}

/// Routes inbound QUIC DATAGRAMs to their UDP ASSOCIATE by sess_id.
/// One dispatcher serves the whole process across reconnects; subscriptions
/// die with their association, so no immortal task can steal another's packets.
struct UdpHub {
    subs: tokio::sync::RwLock<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>>,
    next: std::sync::atomic::AtomicU32,
}

impl UdpHub {
    async fn alloc_sess(
        &self,
    ) -> (
        u32,
        tokio::sync::mpsc::Sender<Bytes>,
        tokio::sync::mpsc::Receiver<Bytes>,
    ) {
        loop {
            let s = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // 0 is reserved; skip it and avoid reusing a live id after wraparound.
            if s == 0 || s == u32::MAX {
                continue;
            }
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1024);
            {
                let mut m = self.subs.write().await;
                if m.contains_key(&s) {
                    continue;
                }
                m.insert(s, tx.clone());
                return (s, tx, rx);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let a = Args::parse();
    let c: ClientConf = load_toml(&a.config)?;
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?)?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_client));
    ccfg.transport_config(build_transport(&c.congestion, c.keep_alive_secs));
    let ccfg = Arc::new(ccfg);
    let server_str = c.server_addr.clone();
    let server_str_log = server_str.clone();

    // Single Endpoint for the process lifetime: one UDP socket, shared session-ticket
    // cache (0-RTT resumption) and CID routing for every dial. Never recreate per dial.
    // Tuned socket buffers so bursts do not drop before quinn sees them.
    let rt = Arc::new(quinn::TokioRuntime);
    let std_sock = udp_socket_dual("[::]:0")?;
    let mut ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        rt.wrap_udp_socket(std_sock)?,
        rt,
    )?;
    ep.set_default_client_config((*ccfg).clone());

    let shared: SharedConn = Arc::new(RwLock::new(None));
    // Generation counter: bumped on every `shared` swap so waiters sleep
    // without polling and the datagram dispatcher drops a stale connection
    // without a per-packet timer.
    let (gen_tx, gen_rx) = watch::channel(0u64);
    let hub: Arc<UdpHub> = Arc::new(UdpHub {
        subs: tokio::sync::RwLock::new(HashMap::new()),
        next: std::sync::atomic::AtomicU32::new(1),
    });
    // Sole DATAGRAM reader for the process: routes by sess_id to the live association.
    {
        let shared = shared.clone();
        let hub = hub.clone();
        let mut gen = gen_rx.clone();
        tokio::spawn(async move {
            loop {
                let conn = match wait_conn(&shared, &mut gen, Duration::from_secs(10)).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                loop {
                    tokio::select! {
                        d = conn.read_datagram() => {
                            let d: Bytes = match d {
                                Ok(d) => d, Err(_) => break,
                            };
                            // Lightweight sess extraction: no full TargetAddr decode
                            // here, the association task decodes once.
                            if d.len() < 6 || d[0] != 0x02 {
                                continue;
                            }
                            let sess = u32::from_le_bytes([d[1], d[2], d[3], d[4]]);
                            let tx = hub.subs.read().await.get(&sess).cloned();
                            if let Some(tx) = tx {
                                let _ = tx.try_send(d);
                            }
                        }
                        // Every `shared` swap bumps the generation, so any
                        // notification means this connection is stale.
                        _ = gen.changed() => break,
                    }
                }
            }
        });
    }
    // Reconnect loop: survives server restart. Backoff 200ms..5s + jitter.
    // server_addr is re-resolved every dial so DDNS/IP changes are picked up (B3).
    // Watchdog silence limit derives from keepalive so custom keep_alive_secs
    // never causes spurious reconnects.
    let watchdog_silence = Duration::from_secs((c.keep_alive_secs.max(1) * 4).max(20));
    {
        let shared = shared.clone();
        let sname = c.server_name.clone();
        let ep = ep.clone();
        let gen_tx = gen_tx.clone();
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
                match dial_once(&ep, server, &sname).await {
                    Ok(conn) => {
                        info!("QUIC connected to {server}");
                        *shared.write().await = Some(conn.clone());
                        bump_gen(&gen_tx);
                        backoff = Duration::from_millis(200);
                        // Watchdog backs up `closed()`: a blackholed path may
                        // never deliver anything, so a healthy connection must
                        // keep showing inbound traffic (keepalive ACKs every
                        // few seconds). Silence beyond 4x keepalive (min 20s)
                        // means dead.
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
                                    warn!("QUIC path silent {watchdog_silence:?}, force-closing {server}");
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
                        // Only clear if nobody already installed a newer connection.
                        {
                            let mut w = shared.write().await;
                            if let Some(cur) = w.as_ref() {
                                if cur.stable_id() == conn.stable_id() {
                                    *w = None;
                                    bump_gen(&gen_tx);
                                }
                            }
                        }
                        // Small pause avoids tight redial spin on flapping links.
                        tokio::time::sleep(Duration::from_millis(200)).await;
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

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!("socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, auth=none, tls13-pinned, 0rtt)");
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    loop {
        let (sock, peer) = li.accept().await?;
        let _ = sock.set_nodelay(true);
        let shared = shared.clone();
        let hub = hub.clone();
        let gen_rx = gen_rx.clone();
        let gen_tx = gen_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks(sock, shared, hub, gen_rx, gen_tx, timeout).await {
                warn!("socks {peer} end: {e:#}");
            }
        });
    }
}

fn jitter_ms() -> u64 {
    use std::cell::Cell;
    thread_local! { static S: Cell<u64> = const { Cell::new(0) }; }
    S.with(|s| {
        let mut x = s.get();
        if x == 0 {
            // Seed per-thread from time + thread id so concurrent clients
            // do not share one backoff sequence and thundering-herd.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e3779b97f4a7c15);
            let tid = format!("{:?}", std::thread::current().id());
            let mut h = t.wrapping_add(0x9e3779b97f4a7c15);
            for b in tid.bytes() {
                h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
            }
            x = h | 1;
        }
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) % 200
    })
}

async fn dial_once(
    ep: &quinn::Endpoint,
    server: SocketAddr,
    name: &str,
) -> Result<quinn::Connection> {
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

async fn wait_conn(
    shared: &SharedConn,
    gen_rx: &mut watch::Receiver<u64>,
    timeout: Duration,
) -> Result<quinn::Connection> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(c) = shared.read().await.clone() {
            if c.close_reason().is_none() {
                return Ok(c);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("quic unavailable (server restarting?)");
        }
        tokio::select! {
            _ = gen_rx.changed() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

// ---- SOCKS5 (RFC1928, no-auth only) ----
async fn handle_socks(
    mut s: tokio::net::TcpStream,
    shared: SharedConn,
    hub: Arc<UdpHub>,
    mut gen_rx: watch::Receiver<u64>,
    gen_tx: watch::Sender<u64>,
    timeout: Duration,
) -> Result<()> {
    async fn read_exact_timeout(s: &mut tokio::net::TcpStream, buf: &mut [u8]) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(buf))
            .await
            .context("socks read timed out")??;
        Ok(())
    }
    // handshake: VER NMETHODS METHODS; we only support 0x00
    let mut h = [0u8; 2];
    read_exact_timeout(&mut s, &mut h).await?;
    if h[0] != 0x05 {
        anyhow::bail!("bad ver");
    }
    if h[1] == 0 {
        anyhow::bail!("no methods offered");
    }
    let mut m = vec![0u8; h[1] as usize];
    read_exact_timeout(&mut s, &mut m).await?;
    if !m.contains(&0x00) {
        s.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    s.write_all(&[0x05, 0x00]).await?;

    let mut r = [0u8; 3];
    read_exact_timeout(&mut s, &mut r).await?;
    if r[0] != 0x05 {
        anyhow::bail!("bad req ver");
    }
    let target = match r[1] {
        0x01 => match read_socks_addr(&mut s).await {
            Ok(t) => t,
            Err(_) => {
                if let Ok(b) = bnd_for(&s) {
                    write_socks_reply(&mut s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad connect target");
            }
        },
        0x03 => {
            // UDP ASSOCIATE: outer addr is a hint only (often 0.0.0.0:0) and
            // is always ignored, so read it leniently without TargetAddr
            // validation. Real packet targets inside DATAGRAMs stay strict.
            if read_socks_addr_lenient(&mut s).await.is_err() {
                if let Ok(b) = bnd_for(&s) {
                    write_socks_reply(&mut s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad associate target");
            }
            return handle_udp_associate(s, shared, hub).await;
        }
        _ => {
            s.write_all(&[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            anyhow::bail!("unsupported cmd");
        }
    };
    let bnd: SocketAddr = bnd_for(&s).unwrap_or_else(|_| {
        s.peer_addr()
            .map(|p| SocketAddr::new(unmap(p.ip()), 0))
            .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0))
    });

    let conn = wait_conn(&shared, &mut gen_rx, timeout).await?;
    let (mut send, mut recv) =
        match tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await {
            Ok(Ok(x)) => x,
            _ => {
                if conn.close_reason().is_some() {
                    let stale = shared
                        .read()
                        .await
                        .as_ref()
                        .map(|cur| cur.stable_id() == conn.stable_id())
                        .unwrap_or(false);
                    if stale {
                        *shared.write().await = None;
                        bump_gen(&gen_tx);
                    }
                    write_socks_reply(&mut s, 0x04, bnd).await.ok();
                    anyhow::bail!("quic connection dead, retry");
                }
                write_socks_reply(&mut s, 0x01, bnd).await.ok();
                anyhow::bail!("quic stream open failed (limit?), retry without killing conn");
            }
        };
    let mut hdr = Vec::with_capacity(273);
    target.encode(&mut hdr)?;
    send.write_all(&hdr).await?;
    // Strict MQP-1 ACK: server must reply exactly MQP_TCP_ACK. No silent
    // fallback — an old peer's first app byte must never be eaten as an ACK,
    // and our ACK must never leak into an old peer's app stream (B1).
    // 7s covers the server-side 4s dial budget plus handshake jitter.
    {
        let mut ack = [0u8; 1];
        let got = tokio::time::timeout(Duration::from_secs(7), recv.read(&mut ack)).await;
        let ok = match got {
            Ok(Ok(Some(1))) => ack[0] == MQP_TCP_ACK,
            _ => false,
        };
        if !ok {
            write_socks_reply(&mut s, 0x04, bnd).await.ok();
            send.reset(0x04u32.into()).ok();
            anyhow::bail!("remote dial refused/timeout/version mismatch");
        }
    }
    write_socks_reply(&mut s, 0x00, bnd).await?;
    let _ = copy_tcp_quic_idle(s, send, recv, Duration::from_secs(300)).await;
    Ok(())
}

async fn read_socks_addr(s: &mut tokio::net::TcpStream) -> Result<TargetAddr> {
    async fn rd(s: &mut tokio::net::TcpStream, buf: &mut [u8]) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(buf))
            .await
            .context("socks addr read timed out")??;
        Ok(())
    }
    let mut t = [0u8; 1];
    rd(s, &mut t).await?;
    match t[0] {
        0x01 => {
            let mut b = [0u8; 6];
            rd(s, &mut b).await?;
            let mut v = vec![0x01];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        0x04 => {
            let mut b = [0u8; 18];
            rd(s, &mut b).await?;
            let mut v = vec![0x04];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        0x03 => {
            let mut n = [0u8; 1];
            rd(s, &mut n).await?;
            let mut b = vec![0u8; n[0] as usize + 2];
            rd(s, &mut b).await?;
            let mut v = vec![0x03, n[0]];
            v.extend_from_slice(&b);
            Ok(TargetAddr::decode(&v)?.0)
        }
        x => anyhow::bail!("bad atyp {x}"),
    }
}

async fn read_socks_addr_lenient(s: &mut tokio::net::TcpStream) -> Result<()> {
    async fn rd(s: &mut tokio::net::TcpStream, buf: &mut [u8]) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(buf))
            .await
            .context("socks addr read timed out")??;
        Ok(())
    }
    let mut t = [0u8; 1];
    rd(s, &mut t).await?;
    match t[0] {
        0x01 => {
            let mut b = [0u8; 6];
            rd(s, &mut b).await?;
            Ok(())
        }
        0x04 => {
            let mut b = [0u8; 18];
            rd(s, &mut b).await?;
            Ok(())
        }
        0x03 => {
            let mut n = [0u8; 1];
            rd(s, &mut n).await?;
            if n[0] == 0 {
                anyhow::bail!("empty domain");
            }
            let mut b = vec![0u8; n[0] as usize + 2];
            rd(s, &mut b).await?;
            Ok(())
        }
        x => anyhow::bail!("bad atyp {x}"),
    }
}

fn bnd_for(s: &tokio::net::TcpStream) -> Result<SocketAddr> {
    let local = s.local_addr()?;
    let ip = unmap(local.ip());
    let ip = if ip.is_unspecified() {
        unmap(s.peer_addr()?.ip())
    } else {
        ip
    };
    Ok(SocketAddr::new(ip, local.port()))
}

async fn write_socks_reply(s: &mut tokio::net::TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {    let mut v = vec![0x05, rep, 0x00];
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
    let (sess, _tx, mut rx) = hub.alloc_sess().await;
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0")?)?;
    let relay_port = relay.local_addr()?.port();
    let relay_reply = SocketAddr::new(unmap(tcp.peer_addr()?.ip()), relay_port);
    let mut tcp = tcp;
    write_socks_reply(&mut tcp, 0x00, relay_reply).await?;
    let relay = Arc::new(relay);
    {
        let r2 = relay.clone();
        let last_app: Arc<std::sync::RwLock<Option<SocketAddr>>> =
            Arc::new(std::sync::RwLock::new(None));
        let last_app_w = last_app.clone();
        let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
        let last_activity_rx = last_activity.clone();
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                last_activity_rx.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
                let (_, addr, payload) = match decode_datagram(&d) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let dst = match addr {
                    TargetAddr::Ip(s) => s,
                    TargetAddr::Domain(h, p) => {
                        if let Some(v) = lookup_cached_sync(&h, p) {
                            match v.into_iter().next() {
                                Some(s) => s,
                                None => continue,
                            }
                        } else {
                            match resolve_all_cached(&h, p).await {
                                Ok(v) => match v.into_iter().next() {
                                    Some(s) => s,
                                    None => continue,
                                },
                                Err(_) => continue,
                            }
                        }
                    }
                };
                let app = last_app.read().ok().and_then(|g| *g);
                if let Some(app) = app {
                    let mut pkt = Vec::with_capacity(3 + 19 + payload.len());
                    pkt.extend_from_slice(&[0, 0, 0]);
                    let mut ah = Vec::with_capacity(19);
                    if TargetAddr::Ip(dst).encode(&mut ah).is_err() {
                        continue;
                    }
                    pkt.extend_from_slice(&ah);
                    pkt.extend_from_slice(payload);
                    let _ = r2.send_to(&pkt, map_for_dual(app)).await;
                }
            }
        });
        // app -> QUIC with this association's sess. Idle assoc (no packets
        // either way for 180s) is reaped so leaked TCP controls cannot hold
        // relay sockets forever (B6).
        let mut buf = vec![0u8; 2048];
        let idle_limit_ms = 180_000u64;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut buf) => {
                    let (n, app) = r?;
                    if n == buf.len() {
                        continue;
                    }
                    last_activity.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
                    if let Ok(mut g) = last_app_w.write() {
                        *g = Some(app);
                    }
                    if n < 4 || buf[2] != 0x00 { continue; }
                    // Single decode: reuse header length for the payload offset.
                    let (addr, hdr_len) = match TargetAddr::decode(&buf[3..n]) {
                        Ok((a, n)) => (a, n),
                        Err(_) => continue,
                    };
                    let payload_off = 3 + hdr_len;
                    if payload_off > n { continue; }
                    let payload = &buf[payload_off..n];
                    let d = match encode_datagram(sess, &addr, payload) {
                        Some(d) => d, None => continue,
                    };
                    // Fast path: never stall the relay loop behind a reconnect
                    // wait; drop this packet if no live connection exists.
                    // Small grace: one 20ms wait covers reconnect races.
                    let conn = {
                        let g = shared.read().await;
                        g.clone().filter(|c| c.close_reason().is_none())
                    };
                    let conn = if conn.is_none() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        shared.read().await.clone().filter(|c| c.close_reason().is_none())
                    } else {
                        conn
                    };
                    if let Some(conn) = conn {
                        let _ = conn.send_datagram(d);
                    }
                }
                _ = tcp.readable() => {
                    let mut closed = false;
                    loop {
                        let mut b = [0u8; 512];
                        match tcp.try_read(&mut b) {
                            Ok(0) => { closed = true; break; }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Ok(_) => continue,
                            Err(_) => { closed = true; break; }
                        }
                    }
                    if closed {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    if mono_millis().saturating_sub(last_activity.load(std::sync::atomic::Ordering::Relaxed)) >= idle_limit_ms {
                        break;
                    }
                }
            }
        }
    }
    hub.subs.write().await.remove(&sess);
    Ok(())
}
