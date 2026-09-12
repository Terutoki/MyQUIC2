//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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

/// Must cover the server's worst-case dial path:
/// 5s header read + 3s DNS permit + 5s DNS lookup + 2s dial permit +
/// 4s TCP connect + scheduling jitter.
const TCP_DIAL_ACK_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the UDP relay may reuse a cached `(connection, PMTU limit)` pair
/// before re-reading it. Both `close_reason()` and `max_datagram_size()` take
/// quinn's connection-state mutex, so they must not run per datagram.
const EGRESS_REFRESH: Duration = Duration::from_secs(1);

/// Process-wide caps on client-side resources. Without these a local or LAN
/// peer can spawn unbounded tasks / relay sockets (each with 512 KB kernel
/// buffers) and exhaust fds and memory on the proxy host.
const MAX_SOCKS_CONNS: usize = 8192;
const MAX_UDP_ASSOCS: usize = 4096;

fn socks_conn_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_SOCKS_CONNS)))
}

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
/// The table is sharded because the dispatcher reads it for every inbound
/// DATAGRAM: a single RwLock there is a cross-core cache-line bottleneck.
const HUB_SHARDS: usize = 32;

struct UdpHub {
    subs: Vec<std::sync::RwLock<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>>>,
    next: std::sync::atomic::AtomicU32,
    /// Exact process-wide association count across all shards.
    len: std::sync::atomic::AtomicUsize,
}

impl UdpHub {
    fn new() -> Self {
        Self {
            subs: (0..HUB_SHARDS)
                .map(|_| std::sync::RwLock::new(HashMap::new()))
                .collect(),
            next: std::sync::atomic::AtomicU32::new(1),
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn shard(&self, s: u32) -> &std::sync::RwLock<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>> {
        &self.subs[(s as usize) % HUB_SHARDS]
    }

    /// Allocates a session id + reply channel. `None` when the process-wide
    /// association cap is reached (caller replies SOCKS5 REP=0x01).
    fn alloc_sess(
        &self,
    ) -> Option<(
        u32,
        tokio::sync::mpsc::Sender<Bytes>,
        tokio::sync::mpsc::Receiver<Bytes>,
    )> {
        use std::sync::atomic::Ordering;
        // Reserve a global slot first so the cap stays exact across shards.
        loop {
            let cur = self.len.load(Ordering::Relaxed);
            if cur >= MAX_UDP_ASSOCS {
                return None;
            }
            if self
                .len
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        loop {
            let s = self.next.fetch_add(1, Ordering::Relaxed);
            // 0 is reserved; skip it and avoid reusing a live id after wraparound.
            if s == 0 || s == u32::MAX {
                continue;
            }
            let shard = self.shard(s);
            let mut m = myquic2::lock_write(shard);
            if m.contains_key(&s) {
                continue;
            }
            // 256 queued datagrams (~350KB worst case) per association: the
            // reply task never blocks (udp_try_send), so a deeper queue only
            // multiplies the worst-case memory across MAX_UDP_ASSOCS.
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(256);
            m.insert(s, tx.clone());
            return Some((s, tx, rx));
        }
    }

    fn remove(&self, s: u32) {
        let shard = self.shard(s);
        if myquic2::lock_write(shard).remove(&s).is_some() {
            self.len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    fn sender(&self, s: u32) -> Option<tokio::sync::mpsc::Sender<Bytes>> {
        myquic2::lock_read(self.shard(s)).get(&s).cloned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let a = Args::parse();
    let c: ClientConf = load_toml(&a.config)?;
    if is_placeholder_token(&c.auth_token) {
        warn!("auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)");
    }
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
    let hub: Arc<UdpHub> = Arc::new(UdpHub::new());
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
                // Construct the receive future ONCE per connection instead of
                // once per datagram: `read_datagram` is cancel-safe (a buffered
                // datagram is returned before its first await point, so dropping
                // and recreating it inside `select!` cannot lose one) and its
                // `Notify` registration is inline, so rebuilding it per packet
                // was pure per-packet overhead. The connection-state mutex that
                // quinn takes per datagram still applies — that cost is inside
                // quinn and cannot be removed from here.
                let reader = conn.read_datagram();
                tokio::pin!(reader);
                // Session id of the last dispatched datagram: a burst addressed
                // to one association then skips both the shard read lock and the
                // `Sender` refcount bump.
                let mut last_sess = 0u32;
                let mut last_tx: Option<tokio::sync::mpsc::Sender<Bytes>> = None;
                loop {
                    tokio::select! {
                        d = &mut reader => {
                            let d: Bytes = match d {
                                Ok(d) => d, Err(_) => break,
                            };
                            // Lightweight sess extraction: no full TargetAddr decode
                            // here, the association task decodes once.
                            if d.len() < 6 || d[0] != 0x02 {
                                continue;
                            }
                            let sess = u32::from_le_bytes([d[1], d[2], d[3], d[4]]);
                            if sess != last_sess || last_tx.is_none() {
                                last_sess = sess;
                                last_tx = hub.sender(sess);
                            }
                            match last_tx.as_ref() {
                                Some(tx) => {
                                    if tx.try_send(d).is_err() {
                                        static DROPS: std::sync::atomic::AtomicU64 =
                                            std::sync::atomic::AtomicU64::new(0);
                                        let n = DROPS
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        if n.is_multiple_of(1000) {
                                            tracing::warn!(
                                                "udphub sess={sess} dispatcher drops={n}"
                                            );
                                        }
                                    }
                                }
                                // Dead association: stop re-probing the hub for
                                // every packet still queued behind it.
                                None => last_sess = 0,
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
    // Mirror build_transport's clamp before multiplying: using the raw config
    // value could overflow u64 (release: tiny watchdog -> endless reconnect
    // loop; debug: panic).
    let keep_alive_secs = c.keep_alive_secs.clamp(1, 3600);
    let watchdog_silence = Duration::from_secs(keep_alive_secs.saturating_mul(4).max(20));
    {
        let shared = shared.clone();
        let sname = c.server_name.clone();
        let auth = c.auth_token.clone();
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
                match dial_once(&ep, server, &sname, &auth).await {
                    Ok(conn) => {
                        info!("QUIC connected to {server}");
                        *shared.write().await = Some(conn.clone());
                        bump_gen(&gen_tx);
                        let connected_at = std::time::Instant::now();
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
                        if let Some(reason) = conn.close_reason() {
                            warn!("QUIC close reason: {reason}");
                        }
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
                        // A stable connection decays the backoff; a peer that
                        // closes immediately (wrong token, flapping) keeps it
                        // growing so it cannot cause a redial storm.
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

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!("socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, token={}, tls13-pinned, 0rtt)",
        if c.auth_token.is_empty() { "off" } else { "on" });
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    loop {
        let (sock, peer) = match li.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (EMFILE/ECONNABORTED) must not kill
                // the proxy for every other client.
                warn!("accept failed: {e:#}; continuing");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let permit = match socks_conn_limiter().clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("socks connection limit {MAX_SOCKS_CONNS} reached; dropping {peer}");
                continue; // socket closes on drop
            }
        };
        let shared = shared.clone();
        let hub = hub.clone();
        let gen_rx = gen_rx.clone();
        let gen_tx = gen_tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
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

/// Cap on a single dial attempt.
///
/// Without an explicit bound a dead path costs ~15 s per attempt: QUIC keeps
/// retransmitting the Initial until the handshake PTO budget runs out, and the
/// reconnect loop only regains control after that. The loop already retries with
/// backoff, so a shorter attempt is strictly better: it shrinks the window in
/// which `shared` still holds the previous, dead connection, and it lets the
/// first attempt that lands after a server restart succeed instead of waiting
/// out the previous attempt's timeout.
const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Confirm that a freshly dialed connection is actually alive before it is
/// published to the shared slot.
///
/// quinn's `Connecting` resolves `Ok` even when the underlying connection
/// terminated instead of completing its handshake: the `on_connected` oneshot
/// carries the 0-RTT accept flag, but `Connecting::poll` discards it and always
/// yields `Ok(Connection)`, while `ConnectionInner::terminate` fires that same
/// oneshot (with `false`) for *every* connection that ends — including one that
/// never established. Without this check the reconnect loop can publish a
/// connection that is already closed, log "QUIC connected", and hand every new
/// SOCKS flow a dead handle until quinn's idle timeout expires ~15 s later.
/// Yielding once lets the connection driver deliver the terminal event, after
/// which `close_reason()` is populated and the dial is reported as the failure
/// it is.
async fn ensure_dialed_alive(conn: &quinn::Connection) -> bool {
    if conn.close_reason().is_some() {
        return false;
    }
    tokio::task::yield_now().await;
    conn.close_reason().is_none()
}

async fn dial_once(
    ep: &quinn::Endpoint,
    server: SocketAddr,
    name: &str,
    auth_token: &str,
) -> Result<quinn::Connection> {
    let t0 = tokio::time::Instant::now();
    let connecting = ep.connect(server, name)?;
    // 0-RTT: send the auth token in early data, then WAIT for the server's
    // accept/reject decision before handing the connection to application
    // flows. quinn discards every stream and DATAGRAM sent in rejected early
    // data (and resets stream ids), so using the connection before `accepted`
    // resolves would silently lose SOCKS requests and could make a stale
    // stream handle alias a newly opened stream. The token still rides early
    // data, which is the part that actually saves a round trip on resumption.
    let conn = match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            let token = auth_token.to_owned();
            let needs_auth = !token.is_empty();
            // A failed early-data write must not fail the whole dial: the
            // handshake may still complete at 1-RTT.
            let early_send_failed = if needs_auth {
                send_auth(&conn, &token).await.is_err()
            } else {
                false
            };
            let accepted_ok = matches!(
                tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, accepted).await,
                Ok(true)
            );
            tracing::debug!("QUIC resumption: 0-RTT keys accepted={accepted_ok}");
            if !accepted_ok {
                // `accepted` reports `true` only once the handshake actually
                // finished, so a `false` here means there is no 1-RTT connection
                // to hand out (the server is gone, or it refused early data and
                // the handshake then failed). Reporting this as a failed dial is
                // what keeps a dead handle out of `shared`.
                anyhow::bail!("0-RTT offered but the handshake did not complete");
            }
            if needs_auth && early_send_failed {
                // Rejected early data discarded the auth stream; re-send it on
                // the now-established connection so the server does not sit
                // out its auth timeout and close us.
                send_auth(&conn, &token).await?;
            }
            conn
        }
        Err(connecting) => {
            let conn = match tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, connecting).await {
                Ok(r) => r?,
                Err(_) => anyhow::bail!("handshake timed out after {DIAL_ATTEMPT_TIMEOUT:?}"),
            };
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection closed immediately after the handshake");
            }
            info!("QUIC full handshake in {:?}", t0.elapsed());
            if !auth_token.is_empty() {
                send_auth(&conn, auth_token).await?;
            }
            conn
        }
    };
    if !ensure_dialed_alive(&conn).await {
        anyhow::bail!("connection not usable after dial");
    }
    Ok(conn)
}

async fn send_auth(conn: &quinn::Connection, token: &str) -> Result<()> {
    let mut uni = tokio::time::timeout(Duration::from_secs(5), conn.open_uni())
        .await
        .context("auth stream open timed out")??;
    uni.write_all(token.as_bytes())
        .await
        .context("auth write failed")?;
    uni.finish().ok();
    Ok(())
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
        write_socks(&mut s, &[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    write_socks(&mut s, &[0x05, 0x00]).await?;

    let mut r = [0u8; 3];
    read_exact_timeout(&mut s, &mut r).await?;
    if r[0] != 0x05 {
        anyhow::bail!("bad req ver");
    }
    if r[2] != 0x00 {
        anyhow::bail!("bad req rsv {:#x}", r[2]);
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
            write_socks(&mut s, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("unsupported cmd");
        }
    };
    let bnd: SocketAddr = bnd_for(&s).unwrap_or_else(|_| {
        s.peer_addr()
            .map(|p| SocketAddr::new(unmap(p.ip()), 0))
            .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0))
    });

    let conn = match wait_conn(&shared, &mut gen_rx, timeout).await {
        Ok(c) => c,
        Err(e) => {
            // Answer the SOCKS client instead of just dropping the TCP
            // connection (a reset looks like a proxy crash to the app).
            write_socks_reply(&mut s, 0x04, bnd).await.ok();
            return Err(e);
        }
    };
    let (mut send, recv) = match tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await
    {
        Ok(Ok(x)) => x,
        _ => {
            if conn.close_reason().is_some() {
                // Single write lock with re-check (no read-then-write split):
                // a reconnect may install a fresh connection between a read
                // and a later write, and clearing unconditionally would
                // blackhole the new connection until it dies. Matches the
                // reconnect loop's own clear path.
                {
                    let mut w = shared.write().await;
                    if let Some(cur) = w.as_ref() {
                        if cur.stable_id() == conn.stable_id() {
                            *w = None;
                            bump_gen(&gen_tx);
                        }
                    }
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
    // Optimistic SOCKS success: the application's first bytes must not be
    // serialized behind the server-side dial. Waiting for the MQP-2 ACK here
    // costs one full client<->server RTT on every connection (Hysteria/
    // juicity-class clients answer immediately for exactly this reason).
    // BND.ADDR is unknown at this point, so report 0.0.0.0:0 (the conventional
    // "not available" value); the ACK is consumed by the reply direction and a
    // failed dial tears the TCP flow down instead of returning a SOCKS error.
    let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    write_socks_reply(&mut s, 0x00, unknown).await?;
    let (pump, diag) = copy_tcp_quic_acked(
        s,
        send,
        recv,
        Duration::from_secs(300),
        TCP_DIAL_ACK_TIMEOUT,
    )
    .await;
    // Stall evidence is reported in both outcomes: the whole point is to see
    // whether the receiver stopped draining *before* quinn killed the flow
    // with "too many gaps in stream buffer". A long s2c read gap means the
    // local consumer (browser/disk), not the WAN, stalled the assembler.
    if diag.is_significant() {
        tracing::warn!("tcp {target:?} {}", diag.summary());
    }
    match pump {
        Ok((up, down)) => {
            tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
        }
        Err(e) => {
            // Abnormal ends already RST the TCP flow inside the pump; log the
            // path snapshot so loss-driven kills are diagnosable in one line.
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
    Ok(())
}

/// NOTE: this reader keeps the original two-`read_exact` shape on purpose.
/// A stack-buffer rewrite (one buffer + a `read`-loop tail) was implemented and
/// reverted: on macOS it reproducibly lost the final port byte of a domain
/// target (`bad connect target` on every domain CONNECT), while this shape
/// passes 30/30, and the same rewrite from a QUIC stream is fine. The per-flow
/// `Vec`s it would save never showed up in a profile, so correctness wins.
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

/// SOCKS control writes are tiny; a stalled local reader must not pin this
/// task (and its connection permit) indefinitely.
async fn write_socks(s: &mut tokio::net::TcpStream, buf: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), s.write_all(buf))
        .await
        .context("socks write timed out")??;
    Ok(())
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
    write_socks(s, &v).await?;
    Ok(())
}

// ---- UDP ASSOCIATE: app <-> local relay <-> QUIC DATAGRAM ----
async fn handle_udp_associate(
    mut tcp: tokio::net::TcpStream,
    shared: SharedConn,
    hub: Arc<UdpHub>,
) -> Result<()> {
    let (sess, _tx, rx) = match hub.alloc_sess() {
        Some(x) => x,
        None => {
            let bnd = bnd_for(&tcp)
                .unwrap_or_else(|_| SocketAddr::new(unmap("127.0.0.1".parse().unwrap()), 0));
            write_socks_reply(&mut tcp, 0x01, bnd).await.ok();
            anyhow::bail!("udp association limit {MAX_UDP_ASSOCS} reached");
        }
    };
    // Wrapper guarantees the subscription is torn down on every exit path,
    // including early setup errors that used to leak the hub entry forever.
    let res = udp_associate_inner(tcp, shared, sess, rx).await;
    hub.remove(sess);
    res
}

async fn udp_associate_inner(
    mut tcp: tokio::net::TcpStream,
    shared: SharedConn,
    sess: u32,
    mut rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> Result<()> {
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0")?)?;
    let relay_port = relay.local_addr()?.port();
    // BND.ADDR must be THIS proxy's address (the IP the app connected to), not
    // the app's own address: a LAN client sending datagrams to its own
    // IP:port would never reach the relay, breaking UDP off-host entirely.
    // `bnd_for` mirrors the CONNECT path's unspecified-address handling.
    let relay_ip = bnd_for(&tcp)
        .map(|b| b.ip())
        .or_else(|_| tcp.local_addr().map(|l| unmap(l.ip())))
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let relay_reply = SocketAddr::new(relay_ip, relay_port);
    write_socks_reply(&mut tcp, 0x00, relay_reply).await?;
    let relay = Arc::new(relay);
    // Pin the app's source IP to the SOCKS control connection's peer. The
    // relay binds [::]:0 (all interfaces), so without this the last datagram
    // sender (any host that can reach the ephemeral port) would hijack replies.
    // Ports are intentionally not pinned: RFC 1928 clients commonly send UDP
    // from a different socket/port than the TCP control connection.
    let expected_app_ip = tcp.peer_addr().ok().map(|p| unmap(p.ip()));
    // Sync lock: the critical section is a single `Option<SocketAddr>` copy
    // and is never held across an await.
    let last_app: Arc<std::sync::RwLock<Option<SocketAddr>>> =
        Arc::new(std::sync::RwLock::new(None));
    let last_app_w = last_app.clone();
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let last_activity_rx = last_activity.clone();
    {
        let r2 = relay.clone();
        let last_app = last_app.clone();
        tokio::spawn(async move {
            // One scratch buffer for the whole lifetime of the association: the
            // reply is always "RSV/FRAG | addr | payload", so the header is
            // written straight into it and the payload appended without any
            // intermediate copy. `freeze()` then hands the filled buffer to the
            // socket as a zero-copy `Bytes`; `send_reply` takes a fresh scratch
            // buffer, because `bytes` cannot tell us whether the socket task
            // kept the allocation.
            let mut pkt = bytes::BytesMut::with_capacity(256);
            while let Some(d) = rx.recv().await {
                // ~1s resolution is plenty for the idle reaper.
                let now = mono_millis();
                let prev = last_activity_rx.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(prev) >= 1000 {
                    last_activity_rx.store(now, std::sync::atomic::Ordering::Relaxed);
                }
                let (_, addr, payload) = match decode_datagram_ref(&d) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                // Zero-copy view of the received datagram: `Bytes::slice` only
                // bumps a refcount, so the reply path never copies the payload
                // to hand it to the socket task.
                let off = d.len() - payload.len();
                let payload = d.slice(off..);
                match addr {
                    TargetAddrRef::Ip(dst) => send_reply(&r2, &last_app, dst, &payload, &mut pkt),
                    TargetAddrRef::Domain(h, p) => {
                        // The server always echoes replies with an IP-form source
                        // address, so this branch is defensive; the negative
                        // cache is still consulted synchronously so a known-bad
                        // name never spawns a resolver task.
                        match lookup_cached_fast(h, p) {
                            CachedLookup::Negative => continue,
                            CachedLookup::Addr(dst) => {
                                send_reply(&r2, &last_app, dst, &payload, &mut pkt)
                            }
                            CachedLookup::Unknown => {
                                let permit =
                                    match dns_slow_path_limiter().clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => continue,
                                    };
                                let r2 = r2.clone();
                                let last_app = last_app.clone();
                                let host = h.to_string();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let dst = match resolve_all_cached(&host, p).await {
                                        Ok(v) => match v.first().copied() {
                                            Some(s) => s,
                                            None => return,
                                        },
                                        Err(_) => return,
                                    };
                                    let mut pkt = bytes::BytesMut::with_capacity(256);
                                    send_reply(&r2, &last_app, dst, &payload, &mut pkt);
                                });
                            }
                        }
                    }
                }
            }
        });
    }
    // app -> QUIC with this association's sess. Idle assoc (no packets
    // either way for 180s) is reaped so leaked TCP controls cannot hold
    // relay sockets forever (B6).
    let mut buf = vec![0u8; 2048];
    let idle_limit_ms = 180_000u64;
    // Cached egress connection + PMTU limit. Re-read from `shared` at most
    // once per EGRESS_REFRESH (or after a failed send), so the per-packet path
    // never touches quinn's connection-state mutex for close_reason()/
    // max_datagram_size().
    let mut egress: Option<(quinn::Connection, usize, tokio::time::Instant)> = None;
    let mut warned_no_datagram = false;
    // Fixed-schedule interval (not a re-armed sleep): TCP control chatter must
    // not reset the idle timer and keep an otherwise dead association alive.
    let mut idle_tick = tokio::time::interval(Duration::from_secs(10));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Local copy of the last liveness stamp: the relay loop bumps at most once
    // per second, but it must not pay a clock read *and* an atomic reload on
    // every datagram to decide that.
    let mut activity_stamp = mono_millis();
    loop {
        tokio::select! {
            r = relay.recv_from(&mut buf) => {
                let (n, app) = match r {
                    Ok(x) => x,
                    // A transient socket error must end this association only;
                    // the wrapper still removes the hub subscription.
                    Err(_) => break,
                };
                if n == buf.len() {
                    continue;
                }
                // Pin the source IP: any host that can reach the relay port
                // could otherwise become "the app" and steal all replies.
                if let Some(expected) = expected_app_ip {
                    if unmap(app.ip()) != expected {
                        tracing::debug!("udp assoc {sess}: datagram from unauthorized app {app} ignored");
                        continue;
                    }
                }
                let now = mono_millis();
                if now.saturating_sub(activity_stamp) >= 1000 {
                    activity_stamp = now;
                    last_activity.store(now, std::sync::atomic::Ordering::Relaxed);
                }
                if let Ok(mut w) = last_app_w.write() {                    *w = Some(app);
                }
                if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0x00 {
                    continue;
                }
                // Single decode: reuse header length for the payload offset.
                let (addr, hdr_len) = match TargetAddrRef::decode(&buf[3..n]) {
                    Ok((a, n)) => (a, n),
                    Err(_) => continue,
                };
                let payload_off = 3 + hdr_len;
                if payload_off > n { continue; }
                let payload = &buf[payload_off..n];
                // Fast path: never stall the relay loop behind a reconnect
                // wait; drop this packet if no live egress exists. Both
                // `close_reason()` and `max_datagram_size()` lock the same
                // connection state as the protocol driver, so they are
                // refreshed at most once per second (or on send failure).
                let now_c = tokio::time::Instant::now();
                let stale = egress
                    .as_ref()
                    .map(|(_, _, t)| now_c.duration_since(*t) >= EGRESS_REFRESH)
                    .unwrap_or(true);
                if stale {
                    let g = match shared.try_read() {
                        Ok(g) => g,
                        Err(_) => shared.read().await,
                    };
                    egress = match g.as_ref() {
                        Some(c) if c.close_reason().is_none() => match c.max_datagram_size() {
                            Some(m) => Some((c.clone(), m.min(1350), now_c)),
                            None => {
                                if !warned_no_datagram {
                                    warned_no_datagram = true;
                                    warn!("peer does not support QUIC DATAGRAM; dropping outbound UDP");
                                }
                                None
                            }
                        },
                        _ => None,
                    };
                }
                let Some((conn, limit, _)) = egress.as_ref() else {
                    continue;
                };
                // Respect live PMTU: quinn starts at a 1200-byte MTU, so the
                // old fixed 1350 limit silently dropped datagrams that were
                // still too large for the current path.
                let d = match encode_datagram_ref_with_limit(sess, &addr, payload, *limit) {
                    Some(d) => d,
                    None => continue,
                };
                match try_send_datagram(conn, d) {
                    DatagramSend::Sent => {}
                    DatagramSend::Blocked => {
                        // Full send buffer: dropped, per UDP semantics. The
                        // shared egress handle stays valid.
                        tracing::debug!("client datagram dropped: send buffer full");
                    }
                    DatagramSend::TooLarge => {
                        // Force a refresh on the next packet: TooLarge means the
                        // PMTU estimate shrank under our cached limit.
                        tracing::debug!("client datagram too large for the current PMTU");
                        egress = None;
                    }
                    DatagramSend::Unsupported => {
                        tracing::debug!("client datagram dropped: peer does not support DATAGRAM");
                    }
                    DatagramSend::ConnectionLost => {
                        // ConnectionLost means the handle is dead until the
                        // reconnect loop installs a new one.
                        tracing::debug!("client datagram send failed: connection lost");
                        egress = None;
                    }
                }
            }
            _ = tcp.readable() => {
                let mut closed = false;
                let mut got = false;
                // Bounded drain (8 KiB per readiness event): an unbounded loop
                // inside one select branch lets a flooding local app starve the
                // relay and idle branches. Tokio keeps readiness set until a
                // `WouldBlock`, so the remainder is picked up on the next poll.
                for _ in 0..16 {
                    let mut b = [0u8; 512];
                    match tcp.try_read(&mut b) {
                        Ok(0) => { closed = true; break; }
                        Ok(_) => { got = true; }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => { closed = true; break; }
                    }
                }
                if got {
                    // An open control connection that is actively used counts
                    // as activity; only truly abandoned associations idle out.
                    last_activity.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
                }
                if closed {
                    break;
                }
            }
            _ = idle_tick.tick() => {
                if mono_millis().saturating_sub(last_activity.load(std::sync::atomic::Ordering::Relaxed)) >= idle_limit_ms {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Build a SOCKS5 UDP reply (RSV/FRAG + source address + payload) for the app
/// and try to send it.
///
/// The address encoder writes directly into the caller's scratch buffer, and
/// the payload is appended without an intermediate copy when the caller already
/// holds it as `Bytes` (the received datagram). A full app socket buffer drops
/// the datagram instead of stalling this association's reply task.
///
/// The freed prefix is taken back only when the datagram was never handed to
/// the socket task: `split_to` gives the socket an owned `Bytes`, and the buffer
/// is refillable only while nothing else shares it. Once it is shared, a fresh
/// buffer is allocated — otherwise the next reply would overwrite bytes another
/// task is still holding (or, worse, be silently truncated).
fn send_reply(
    relay: &Arc<tokio::net::UdpSocket>,
    last_app: &std::sync::RwLock<Option<SocketAddr>>,
    dst: SocketAddr,
    payload: &Bytes,
    pkt: &mut bytes::BytesMut,
) {
    let Some(app) = last_app.read().ok().and_then(|g| *g) else {
        return;
    };
    pkt.truncate(0);
    pkt.extend_from_slice(&[0, 0, 0]);
    // The destination of a reply is always the source address the server
    // reported, which is IP-form; encode it straight into the scratch buffer.
    match dst {
        SocketAddr::V4(a) => {
            pkt.extend_from_slice(&[0x01]);
            pkt.extend_from_slice(&a.ip().octets());
            pkt.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            pkt.extend_from_slice(&[0x04]);
            pkt.extend_from_slice(&a.ip().octets());
            pkt.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    pkt.extend_from_slice(payload);
    // Hand the filled buffer over as an owned `Bytes` and start a fresh scratch
    // buffer for the next reply. The single allocation here (exactly the
    // datagram's size, so building it never reallocates) replaced two — the old
    // shape allocated a `Vec` for the packet *and* copied the payload again on
    // every slow-path send.
    let out = std::mem::take(pkt).freeze();
    let sent_len = out.len();
    udp_try_send(relay, map_for_dual(app), out);
    *pkt = bytes::BytesMut::with_capacity(sent_len.max(256));
}

#[cfg(test)]
mod tests {
    //! Guards for the SOCKS5 address reader. `read_socks_addr` keeps its
    //! original two-`read_exact` shape (see the note above it), so these tests
    //! exist to catch a framing regression in any future rewrite.
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Serve `bytes` on a loopback socket and run the real reader against it,
    /// exactly as `handle_socks` drives it.
    async fn feed(bytes: &[u8], lenient: bool) -> Result<TargetAddr> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let payload = bytes.to_vec();
        let server = tokio::spawn(async move {
            let (mut t, _) = l.accept().await.unwrap();
            t.write_all(&payload).await.unwrap();
            // Wait for a byte from the client before closing: a plain
            // `shutdown()`/drop right after `write_all` races the loopback
            // stack on macOS and the last byte can be lost, which would make
            // this reader test fail for reasons that have nothing to do with
            // the reader.
            let mut ack = [0u8; 1];
            t.read_exact(&mut ack).await.ok();
        });
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = if lenient {
            read_socks_addr_lenient(&mut c)
                .await
                .map(|()| TargetAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))))
        } else {
            read_socks_addr(&mut c).await
        };
        // Unblock the server (see above) once the reader is done, then let it
        // exit cleanly.
        let _ = c.write_all(b"\n").await;
        let _ = server.await;
        r
    }

    #[tokio::test]
    async fn socks_reader_decodes_v4_v6_and_domain() {
        assert_eq!(
            feed(&[0x01, 127, 0, 0, 1, 0x46, 0xA1], false)
                .await
                .unwrap(),
            TargetAddr::Ip("127.0.0.1:18081".parse().unwrap())
        );

        let mut v6 = vec![0x04];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            feed(&v6, false).await.unwrap(),
            TargetAddr::Ip("[::1]:443".parse().unwrap())
        );

        let d = b"localhost";
        let mut dm = vec![0x03, d.len() as u8];
        dm.extend_from_slice(d);
        dm.extend_from_slice(&18081u16.to_be_bytes());
        assert_eq!(
            feed(&dm, false).await.unwrap(),
            TargetAddr::Domain("localhost".into(), 18081)
        );
    }

    #[tokio::test]
    async fn socks_reader_rejects_bad_atyp_and_empty_domain() {
        assert!(feed(&[0x02, 0, 0, 0, 0, 0, 0], false).await.is_err());
        assert!(feed(&[0x03, 0x00, 0x00, 0x00], false).await.is_err());
    }

    #[tokio::test]
    async fn socks_lenient_reader_accepts_the_same_framing() {
        let d = b"example.com";
        let mut dm = vec![0x03, d.len() as u8];
        dm.extend_from_slice(d);
        dm.extend_from_slice(&8443u16.to_be_bytes());
        assert!(feed(&dm, true).await.is_ok());
        assert!(feed(&[0x01, 0, 0, 0, 0, 0, 0], true).await.is_ok());
    }
}
