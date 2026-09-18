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
/// 4s TCP connect + scheduling jitter, with margin for a loaded host.
const TCP_DIAL_ACK_TIMEOUT: Duration = Duration::from_secs(25);

/// Egress freshness window in ms, mirroring the old 1 s `EGRESS_REFRESH`.
/// Stored as `mono_millis()` so the relay loop reuses its single per-packet
/// clock read instead of taking a second `Instant::now()` per datagram.
const EGRESS_REFRESH_MS: u64 = 1000;

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

/// One QUIC connection slot: the shared handle plus its generation channel.
/// Bumped on every swap so waiters sleep without polling and dispatchers drop
/// a stale connection without a per-packet timer.
#[derive(Clone, Debug)]
struct ConnSlot {
    shared: SharedConn,
    gen_tx: watch::Sender<u64>,
    gen_rx: watch::Receiver<u64>,
    /// Routing hint, maintained by the connection loop: `shared` holds a
    /// connection with no close reason. One atomic load where `close_reason()`
    /// takes quinn's connection-state mutex and clones the error, which
    /// `pick_tcp` would otherwise pay twice per TCP flow. `wait_conn` remains
    /// the authority that fails a flow fast.
    live: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnSlot {
    fn fresh() -> Self {
        let (gen_tx, gen_rx) = watch::channel(0u64);
        Self {
            shared: Arc::new(RwLock::new(None)),
            gen_tx,
            gen_rx,
            live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn is_live(&self) -> bool {
        self.live.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Pure routing decision for tests: true = use `a`.
/// A dead preferred slot fails over to the live one; both dead keeps the
/// preferred slot so `wait_conn` still bounds the stall and fails fast.
fn select_slot(pinned: bool, rr: usize, a_live: bool, b_live: Option<bool>) -> bool {
    let Some(b_live) = b_live else {
        return true;
    };
    if pinned || rr.is_multiple_of(2) {
        a_live || !b_live
    } else {
        a_live && !b_live
    }
}

/// Dual-connection pool for loaded-latency isolation.
/// `a` is the interactive connection (all UDP + pinned ports, and the sole
/// connection when `quic_conns == 1`). `b` exists only in dual mode and
/// absorbs half the bulk TCP streams so each cwnd holds ~half the queue.
/// quinn 0.11 has no per-stream priority, so separate congestion windows are
/// the isolation mechanism.
#[derive(Clone, Debug)]
struct ConnPool {
    a: ConnSlot,
    b: Option<ConnSlot>,
    rr: Arc<std::sync::atomic::AtomicUsize>,
    interactive_ports: Arc<std::collections::HashSet<u16>>,
}

impl ConnPool {
    fn target_port(t: &TargetAddr) -> u16 {
        match t {
            TargetAddr::Ip(s) => s.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Pick the slot for a new TCP flow. Pinned ports prefer `a` and bulk
    /// spreads round-robin in dual mode; a dead preferred slot fails over to
    /// the live one (returning flows stick to their slot for life, so nothing
    /// oscillates). Both dead keeps the preference and `wait_conn` fails fast.
    fn pick_tcp(&self, t: &TargetAddr) -> ConnSlot {
        match &self.b {
            None => self.a.clone(),
            Some(b) => {
                let pinned = self.interactive_ports.contains(&Self::target_port(t));
                let n = if pinned {
                    0
                } else {
                    self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                };
                if select_slot(pinned, n, self.a.is_live(), Some(b.is_live())) {
                    self.a.clone()
                } else {
                    b.clone()
                }
            }
        }
    }

    /// Bulk-slot fallback for UDP while the interactive slot is down
    /// (see `refresh_udp_egress`). `None` in single-connection mode.
    fn udp_fallback(&self) -> Option<ConnSlot> {
        self.b.clone()
    }

    fn is_interactive(&self, t: &TargetAddr) -> bool {
        self.interactive_ports.contains(&Self::target_port(t))
    }
}

#[derive(Debug, Default)]
struct SharedEgress {
    cached: std::sync::RwLock<Option<(quinn::Connection, usize, u64)>>,
    warned: std::sync::atomic::AtomicBool,
    /// Single-flight refresh gate: only one association task pays the two
    /// quinn locks (`close_reason` + `max_datagram_size`) per refresh window.
    /// The rest fail fast (UDP drop semantics) instead of herding on the same
    /// mutexes the moment the 1 s window expires on 4096 associations at once.
    refreshing: std::sync::atomic::AtomicBool,
}

impl SharedEgress {
    fn get_fresh(&self, now_ms: u64) -> Option<(quinn::Connection, usize)> {
        let g = self.cached.try_read().ok()?;
        let (c, limit, t) = g.as_ref()?;
        if now_ms.saturating_sub(*t) >= EGRESS_REFRESH_MS {
            return None;
        }
        Some((c.clone(), *limit))
    }

    fn get_stale(&self) -> Option<(quinn::Connection, usize)> {
        let g = self.cached.try_read().ok()?;
        let (c, limit, _) = g.as_ref()?;
        Some((c.clone(), *limit))
    }

    fn refresh_global(&self, pool: &ConnPool, now_ms: u64) -> Option<(quinn::Connection, usize)> {
        // Single-flight: a loser drops fast (UDP semantics) instead of paying
        // the quinn locks while a winner is already refreshing.
        if self
            .refreshing
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        struct RefreshGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for RefreshGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _guard = RefreshGuard(&self.refreshing);
        for slot in [&pool.a].into_iter().chain(pool.udp_fallback().as_ref()) {
            let Ok(g) = slot.shared.try_read() else {
                continue;
            };
            match g.as_ref() {
                Some(c) if c.close_reason().is_none() => match c.max_datagram_size() {
                    Some(m) => {
                        let out = (c.clone(), m);
                        // Publish the timestamp without ever blocking the
                        // executor: readers hold `try_read` only for an Arc
                        // bump, but a blocking write would still park this
                        // worker thread whenever one is inside. If the
                        // `try_write` loses, this packet still uses the fresh
                        // handle; the stamp stays expired so the next packet
                        // retries (single-flight keeps it to one contender).
                        if let Ok(mut w) = self.cached.try_write() {
                            *w = Some((c.clone(), m, now_ms));
                        }
                        return Some(out);
                    }
                    None => {
                        if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            warn!("peer does not support QUIC DATAGRAM; dropping outbound UDP");
                        }
                        return None;
                    }
                },
                _ => continue,
            }
        }
        None
    }

    fn invalidate(&self) {
        if let Ok(mut w) = self.cached.try_write() {
            *w = None;
        }
    }
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
        myquic2::try_lock_read(self.shard(s))?.get(&s).cloned()
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
    if c.auth_token.len() > AUTH_TOKEN_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_TOKEN_MAX_BYTES} B wire cap (server only reads the first {AUTH_TOKEN_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
        );
    }
    if is_placeholder_token(&c.auth_token) {
        warn!("auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)");
    }
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?, &c.alpn_bytes())?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_client));
    ccfg.transport_config(build_transport_tuned(
        &c.congestion,
        c.keep_alive_secs,
        c.tuning(),
    ));
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

    let dual = c.conn_count() >= 2;
    let pool = ConnPool {
        a: ConnSlot::fresh(),
        b: if dual { Some(ConnSlot::fresh()) } else { None },
        rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        interactive_ports: Arc::new(c.interactive_port_list().into_iter().collect()),
    };
    info!(
        "quic pool: {} connection(s){}",
        if dual { 2 } else { 1 },
        if dual {
            " (bulk round-robin + interactive pin)"
        } else {
            ""
        }
    );
    let hub: Arc<UdpHub> = Arc::new(UdpHub::new());
    let egress_shared: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    spawn_dispatcher(pool.a.clone(), hub.clone());
    if let Some(b) = pool.b.clone() {
        spawn_dispatcher(b, hub.clone());
    }
    // One reconnect loop per pool slot, sharing the same Endpoint (one UDP
    // socket, one ticket cache). Dual mode doubles idle keepalives; each
    // connection carries ~half the streams, so each cwnd holds ~half the queue.
    let keep_alive_secs = c.keep_alive_secs.clamp(1, 3600);
    let watchdog_silence = Duration::from_secs(keep_alive_secs.saturating_mul(4).max(20));
    spawn_conn_loop(
        ep.clone(),
        server_str.clone(),
        c.server_name.clone(),
        c.auth_token.clone(),
        pool.a.clone(),
        watchdog_silence,
    );
    if let Some(b) = pool.b.clone() {
        spawn_conn_loop(
            ep.clone(),
            server_str.clone(),
            c.server_name.clone(),
            c.auth_token.clone(),
            b,
            watchdog_silence,
        );
    }

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!("socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, token={}, tls13-pinned, 0rtt)",
        if c.auth_token.is_empty() { "off" } else { "on" });
    spawn_udp_reporter();
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
        let pool = pool.clone();
        let hub = hub.clone();
        let egress_shared = egress_shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks(sock, pool, hub, egress_shared, timeout).await {
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

fn count_dispatch_drop(sess: u32) {
    static DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n.is_multiple_of(1000) {
        tracing::warn!("udphub sess={sess} dispatcher drops={n}");
    }
}

fn tcp_abort_log_due() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if LAST
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let n = SUPPRESSED.swap(0, Ordering::Relaxed);
        if n > 0 {
            tracing::warn!("tcp aborts suppressed in the last window: {n}");
        }
        true
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

fn spawn_dispatcher(slot: ConnSlot, hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        let mut gen = slot.gen_rx.clone();
        loop {
            let conn = match wait_conn(&slot.shared, &mut gen, Duration::from_secs(10)).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let reader = conn.read_datagram();
            tokio::pin!(reader);
            const DISPATCH_CACHE: usize = 32;
            let mut cache: [(u32, Option<tokio::sync::mpsc::Sender<Bytes>>); DISPATCH_CACHE] =
                std::array::from_fn(|_| (u32::MAX, None));
            let mut rr: usize = 0;
            loop {
                tokio::select! {
                    d = &mut reader => {
                        let d: Bytes = match d {
                            Ok(d) => d, Err(_) => break,
                        };
                        let Some(sess) = dgram_sess(&d) else {
                            continue;
                        };
                        let mut cur: Option<tokio::sync::mpsc::Sender<Bytes>> = None;
                        for (s, tx) in cache.iter() {
                            if *s == sess {
                                cur = tx.clone();
                                break;
                            }
                        }
                        if cur.is_none() {
                            // Distinguish "never cached" from "cached as absent":
                            // only a live sender avoids the shard lock; an
                            // absent entry is re-probed via the hub below.
                            let tx = hub.sender(sess);
                            let mut placed = false;
                            for e in cache.iter_mut() {
                                if e.0 == sess || e.1.is_none() {
                                    *e = (sess, tx.clone());
                                    placed = true;
                                    break;
                                }
                            }
                            if !placed {
                                let i = rr % DISPATCH_CACHE;
                                rr = rr.wrapping_add(1);
                                cache[i] = (sess, tx.clone());
                            }
                            cur = tx;
                        }
                        match cur.as_ref() {
                            Some(tx) => {
                                match tx.try_send(d) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(
                                        payload,
                                    )) => {
                                        let fresh = hub.sender(sess);
                                        for e in cache.iter_mut() {
                                            if e.0 == sess {
                                                e.1 = fresh.clone();
                                                break;
                                            }
                                        }
                                        match fresh.as_ref() {
                                            Some(fresh) => {
                                                if fresh.try_send(payload).is_err() {
                                                    count_dispatch_drop(sess);
                                                }
                                            }
                                            None => {
                                                count_dispatch_drop(sess);
                                            }
                                        }
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        count_dispatch_drop(sess);
                                    }
                                }
                            }
                            None => {
                                for e in cache.iter_mut() {
                                    if e.0 == sess {
                                        e.1 = None;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    _ = gen.changed() => break,
                }
            }
        }
    });
}

fn spawn_conn_loop(
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
                    *slot.shared.write().await = Some(conn.clone());
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
                    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
                    {
                        let mut w = slot.shared.write().await;
                        if let Some(cur) = w.as_ref() {
                            if cur.stable_id() == conn.stable_id() {
                                *w = None;
                                bump_gen(&slot.gen_tx);
                            }
                        }
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
const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

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
    // 0-RTT: send the auth token in early data, then WAIT for the handshake to
    // complete before handing the connection to application flows. quinn
    // discards every stream and DATAGRAM sent in rejected early data (and
    // resets stream ids), so using the connection before the handshake is known
    // to have completed would silently lose SOCKS requests and could make a
    // stale stream handle alias a newly opened stream. The token still rides
    // early data, which is the part that actually saves a round trip on
    // resumption.
    //
    // 0.11 API: `into_0rtt()` yields `(Connection, ZeroRttAccepted)`; the
    // future resolves when the handshake completes with true = early data
    // kept, false = rejected OR the connection died first. The timeout plus
    // the `ensure_dialed_alive` gate below keep a dead dial from ever being
    // published (0.11's `Connecting` resolves `Ok` even for dead dials).
    let conn = match connecting.into_0rtt() {
        Ok((conn, accepted_fut)) => {
            let token = auth_token.to_owned();
            let needs_auth = !token.is_empty();
            // A failed early-data write must not fail the whole dial: the
            // handshake may still complete at 1-RTT, in which case the token is
            // re-sent below.
            let early_ok = if needs_auth {
                match send_auth_stream(&conn, &token).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::debug!("0-RTT auth write failed ({e:#}); will re-send at 1-RTT");
                        false
                    }
                }
            } else {
                true
            };
            let accepted = match tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, accepted_fut).await {
                Ok(a) => a,
                Err(_) => anyhow::bail!("0-RTT offered but the handshake did not complete"),
            };
            tracing::debug!("QUIC resumption: 0-RTT accepted={accepted}");
            if !ensure_dialed_alive(&conn).await {
                anyhow::bail!("connection lost during handshake");
            }
            // Rejected early data discarded the auth stream; re-send it on the
            // now-established connection so the server does not sit out its auth
            // timeout and close us. A failed early write needs the same recovery
            // even when the server kept 0-RTT.
            if needs_auth && (!accepted || !early_ok) {
                tracing::debug!("QUIC 0-RTT rejected: re-sending auth at 1-RTT");
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

/// Open a uni stream and write the auth token into it (early data on 0-RTT).
///
/// Rejection is learned via the `ZeroRttAccepted` future, not from this handle.
async fn send_auth_stream(conn: &quinn::Connection, token: &str) -> Result<quinn::SendStream> {
    let mut uni = tokio::time::timeout(Duration::from_secs(5), conn.open_uni())
        .await
        .context("auth stream open timed out")??;
    uni.write_all(token.as_bytes())
        .await
        .context("auth write failed")?;
    uni.finish().ok();
    Ok(uni)
}

async fn send_auth(conn: &quinn::Connection, token: &str) -> Result<()> {
    send_auth_stream(conn, token).await.map(|_| ())
}

async fn wait_conn(
    shared: &SharedConn,
    gen_rx: &mut watch::Receiver<u64>,
    timeout: Duration,
) -> Result<quinn::Connection> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(g) = shared.try_read() {
            if let Some(c) = g.clone() {
                drop(g);
                if c.close_reason().is_none() {
                    return Ok(c);
                }
            }
        } else if let Some(c) = shared.read().await.clone() {
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

/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
fn spawn_udp_reporter() {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately; skip it
        let mut prev = udp_stats::snapshot();
        let mut prev_w = udp_write::snapshot();
        let mut prev_r = udp_stats::reassembly_drops();
        loop {
            tick.tick().await;
            let now = udp_stats::snapshot();
            let now_w = udp_write::snapshot();
            let d = now.since(&prev);
            let dw = now_w.since(&prev_w);
            if !d.is_idle() {
                info!(
                    "udp relay (60s): {d}; high-water payload {} B",
                    now.max_payload
                );
            }
            // The last-hop write outcomes, always logged: a silent drop here is
            // what a flat relay counter cannot show.
            if !(dw.sent == 0 && dw.retried == 0) || !dw.clean() {
                info!("udp write (60s): {dw}");
            }
            let now_r = udp_stats::reassembly_drops();
            if now_r != prev_r {
                info!(
                    "udp reassembly (60s): {} expired (missing fragment), {} evicted (memory cap)",
                    now_r.0.saturating_sub(prev_r.0),
                    now_r.1.saturating_sub(prev_r.1)
                );
                prev_r = now_r;
            }
            prev = now;
            prev_w = now_w;
        }
    });
}

// ---- SOCKS5 (RFC1928, no-auth only) ----

/// One deadline for a whole SOCKS negotiation (greeting + request + target).
/// The app is local, so this only has to bound a stuck or hostile peer; the
/// previous shape re-armed a fresh 10 s timeout per field, making the worst
/// case a multiple of it and registering several timers per connection at the
/// connection rate.
const SOCKS_NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the client asked for, once its whole negotiation has been read.
enum SocksRequest {
    Connect(TargetAddr),
    Associate,
}

/// Reads the greeting (only the no-auth method is offered) and the request.
/// Framing only; the caller owns the deadline (see [`SOCKS_NEGOTIATE_TIMEOUT`]).
async fn negotiate(s: &mut tokio::net::TcpStream) -> Result<SocksRequest> {
    // handshake: VER NMETHODS METHODS; we only support 0x00
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.context("socks greeting")?;
    if h[0] != 0x05 {
        anyhow::bail!("bad ver");
    }
    if h[1] == 0 {
        anyhow::bail!("no methods offered");
    }
    let mut m = [0u8; u8::MAX as usize];
    s.read_exact(&mut m[..h[1] as usize])
        .await
        .context("socks methods")?;
    if !m[..h[1] as usize].contains(&0x00) {
        write_socks(s, &[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth (client must offer 0x00)");
    }
    write_socks(s, &[0x05, 0x00]).await?;

    let mut r = [0u8; 3];
    s.read_exact(&mut r).await.context("socks request")?;
    if r[0] != 0x05 {
        anyhow::bail!("bad req ver");
    }
    if r[2] != 0x00 {
        anyhow::bail!("bad req rsv {:#x}", r[2]);
    }
    match r[1] {
        0x01 => match read_socks_addr(s).await {
            Ok(t) => Ok(SocksRequest::Connect(t)),
            Err(_) => {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad connect target");
            }
        },
        0x03 => {
            // UDP ASSOCIATE: outer addr is a hint only (often 0.0.0.0:0) and
            // is always ignored, so read it leniently without TargetAddr
            // validation. Real packet targets inside DATAGRAMs stay strict.
            if read_socks_addr_lenient(s).await.is_err() {
                if let Ok(b) = bnd_for(s) {
                    write_socks_reply(s, 0x08, b).await.ok();
                }
                anyhow::bail!("bad associate target");
            }
            Ok(SocksRequest::Associate)
        }
        _ => {
            write_socks(s, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("unsupported cmd");
        }
    }
}

async fn handle_socks(
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

    let slot = pool.pick_tcp(&target);
    let shared = slot.shared.clone();
    let live = slot.live.clone();
    let mut gen_rx = slot.gen_rx.clone();
    let gen_tx = slot.gen_tx.clone();
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
        Ok(Ok((s, r))) => {
            let prio = if pool.is_interactive(&target) { 10 } else { 0 };
            let _ = s.set_priority(prio);
            (s, r)
        }
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
                            live.store(false, std::sync::atomic::Ordering::Relaxed);
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
    // The open header is deliberately its own write, flushed before any
    // application byte is read: a peer that waits for its first reply
    // (game login, banner protocols) must see the header within ~100ms
    // without the client ever sending payload. Never batch it behind the
    // first app chunk; `tcp_open_header_arrives_without_app_data` pins this.
    // Stack buffer: the header is at most 259 B, so the per-flow `Vec` this
    // used to allocate was one heap round trip for bytes that live one write.
    let mut hdr = [0u8; AddrHeader::MAX_LEN];
    let hdr_len = target.as_ref().header()?.encode_into(&mut hdr);
    send.write_all(&hdr[..hdr_len]).await?;
    // Optimistic SOCKS success: the application's first bytes must not be
    // serialized behind the server-side dial. Waiting for the MQP-2 ACK here
    // costs one full client<->server RTT on every connection (Hysteria/
    // juicity-class clients answer immediately for exactly this reason).
    // BND.ADDR is unknown at this point, so report 0.0.0.0:0 (the conventional
    // "not available" value); the ACK is consumed by the reply direction and a
    // failed dial tears the TCP flow down instead of returning a SOCKS error.
    let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    write_socks_reply(&mut s, 0x00, unknown).await?;
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
async fn read_socks_addr(s: &mut tokio::net::TcpStream) -> Result<TargetAddr> {
    let mut buf = [0u8; AddrHeader::MAX_LEN];
    s.read_exact(&mut buf[..1]).await.context("socks atyp")?;
    let len = match buf[0] {
        0x01 => {
            s.read_exact(&mut buf[1..7]).await.context("socks v4")?;
            7
        }
        0x04 => {
            s.read_exact(&mut buf[1..19]).await.context("socks v6")?;
            19
        }
        0x03 => {
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

async fn read_socks_addr_lenient(s: &mut tokio::net::TcpStream) -> Result<()> {
    let mut t = [0u8; 1];
    s.read_exact(&mut t).await.context("socks atyp")?;
    match t[0] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.context("socks v4")?;
            Ok(())
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await.context("socks v6")?;
            Ok(())
        }
        0x03 => {
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
async fn write_socks(s: &mut tokio::net::TcpStream, buf: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), s.write_all(buf))
        .await
        .context("socks write timed out")??;
    Ok(())
}

fn bnd_for(s: &tokio::net::TcpStream) -> Result<SocketAddr> {
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

async fn write_socks_reply(s: &mut tokio::net::TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    let mut v = [0u8; 3 + MAX_BND_LEN];
    v[0] = 0x05;
    v[1] = rep;
    v[2] = 0x00;
    let n = 3 + encode_bnd_addr_into(bnd, &mut v[3..]);
    write_socks(s, &v[..n]).await
}

// ---- UDP ASSOCIATE: app <-> local relay <-> QUIC DATAGRAM ----
async fn handle_udp_associate(
    mut tcp: tokio::net::TcpStream,
    pool: ConnPool,
    hub: Arc<UdpHub>,
    egress_shared: Arc<SharedEgress>,
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
    udp_stats::session();
    // Wrapper guarantees the subscription is torn down on every exit path,
    // including early setup errors that used to leak the hub entry forever.
    let res = udp_associate_inner(tcp, pool, egress_shared, sess, rx).await;
    hub.remove(sess);
    res
}

async fn udp_associate_inner(
    mut tcp: tokio::net::TcpStream,
    pool: ConnPool,
    egress_shared: Arc<SharedEgress>,
    sess: u32,
    mut rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> Result<()> {
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0")?)?;
    let relay_port = relay.local_addr()?.port();
    // BND.ADDR must be THIS proxy's address (the IP the app connected to), not
    // the app's own address: a LAN client sending datagrams to its own
    // IP:port would never reach the relay, breaking UDP off-host entirely.
    // Computed directly (not via `bnd_for`, whose unknown fallback is
    // 0.0.0.0): prefer the concrete local interface, else the peer address
    // (correct for same-host testing), else localhost.
    let relay_ip = match tcp.local_addr().map(|l| unmap(l.ip())) {
        Ok(ip) if !ip.is_unspecified() => ip,
        _ => tcp
            .peer_addr()
            .map(|p| unmap(p.ip()))
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    };
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
    let reply_handle = {
        let r2 = relay.clone();
        let last_app = last_app.clone();
        tokio::spawn(async move {
            let mut pkt = bytes::BytesMut::with_capacity(256);
            let mut reasm = DgramReassembler::new();
            let mut cached_app: Option<SocketAddr> = None;
            let mut cached_at: u64 = 0;
            let mut refresh_app = |now: u64| -> Option<SocketAddr> {
                if let Some(a) = cached_app {
                    if now.saturating_sub(cached_at) < 200 {
                        return Some(a);
                    }
                }
                match last_app.try_read().ok().and_then(|g| *g) {
                    Some(a) => {
                        cached_app = Some(a);
                        cached_at = now;
                        Some(a)
                    }
                    None => {
                        if cached_app.is_some() && now.saturating_sub(cached_at) < 1000 {
                            cached_app
                        } else {
                            cached_app = None;
                            udp_write::no_app();
                            None
                        }
                    }
                }
            };
            while let Some(d) = rx.recv().await {
                // ~1s resolution is plenty for the idle reaper.
                let now = mono_millis();
                let prev = last_activity_rx.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(prev) >= 1000 {
                    last_activity_rx.store(now, std::sync::atomic::Ordering::Relaxed);
                }
                let Some(app) = refresh_app(now) else {
                    continue;
                };
                if d.first() == Some(&MQP_DGRAM_FRAG) {
                    let Ok(f) = decode_fragment(&d) else { continue };
                    let Some((_, a, whole)) = reasm.push(&f, now) else {
                        continue;
                    };
                    udp_stats::payload(whole.len());
                    match a.as_ref() {
                        TargetAddrRef::Ip(dst) => send_reply_addr(&r2, app, dst, &whole, &mut pkt),
                        TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                            CachedLookup::Addr(dst) => {
                                send_reply_addr(&r2, app, dst, &whole, &mut pkt)
                            }
                            CachedLookup::Negative | CachedLookup::Unknown => {}
                        },
                    }
                    continue;
                }
                let Ok((_, a, p)) = decode_datagram_ref(&d) else {
                    continue;
                };
                let off = d.len() - p.len();
                let payload = d.slice(off..);
                udp_stats::payload(payload.len());
                match a {
                    TargetAddrRef::Ip(dst) => send_reply_addr(&r2, app, dst, &payload, &mut pkt),
                    TargetAddrRef::Domain(h, p) => {
                        // The server always echoes replies with an IP-form source
                        // address, so this branch is defensive; the negative
                        // cache is still consulted synchronously so a known-bad
                        // name never spawns a resolver task.
                        match lookup_cached_fast(h, p) {
                            CachedLookup::Negative => continue,
                            CachedLookup::Addr(dst) => {
                                send_reply_addr(&r2, app, dst, &payload, &mut pkt)
                            }
                            CachedLookup::Unknown => {
                                if dns_is_inflight(h, p) {
                                    continue;
                                }
                                if dns_slow_path_limiter().available_permits() == 0 {
                                    continue;
                                }
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
        })
    };
    // app -> QUIC with this association's sess. Idle assoc (no packets
    // either way for 180s) is reaped so leaked TCP controls cannot hold
    // relay sockets forever (B6).
    //
    // `UDP_RECV_MAX`, not 2048: the socket must be able to hold any datagram
    // the protocol can carry, or the kernel truncates it before the fragmenter
    // ever sees it. The SOCKS5 header sits in front of the payload, so the
    // buffer covers both (`n == buf.len()` below reports a truncation).
    let mut buf = vec![0u8; UDP_RECV_MAX + SOCKS_UDP_HDR_MAX + UDP_RECV_SLACK];
    // One id counter per association: `(sess, id)` is the receiver's key.
    let mut frag = DgramFragmenter::new();
    let idle_limit_ms = 180_000u64;
    // Fixed-schedule interval (not a re-armed sleep): TCP control chatter must
    // not reset the idle timer and keep an otherwise dead association alive.
    let mut idle_tick = tokio::time::interval(Duration::from_secs(10));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Local copy of the last liveness stamp: the relay loop bumps at most once
    // per second, but it must not pay a clock read *and* an atomic reload on
    // every datagram to decide that.
    let mut activity_stamp = mono_millis();
    // Local copy of the last published app address: the value almost never
    // changes (one UDP socket per association), so only `try_write` on change
    // instead of CAS-ing the shared lock per packet where a loaded reply task
    // would starve the write.
    let mut published_app: Option<SocketAddr> = None;
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
                    // The kernel truncates a datagram larger than the buffer and
                    // reports only the buffer length, so the excess is already
                    // gone. Say so instead of dropping it without a trace.
                    warn!(
                        "udp assoc {sess}: app datagram of >= {} B truncated; raise \
                         MQP_FRAG_MAX_PAYLOAD to carry it",
                        buf.len()
                    );
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
                if published_app != Some(app) {
                    if let Ok(mut w) = last_app_w.try_write() {
                        *w = Some(app);
                        published_app = Some(app);
                    }
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
                // Shared egress: per-packet path is a try_read + timestamp
                // check, no quinn lock. Only the single-flight winner (once
                // per second) pays close_reason/max_datagram_size. Stale
                // handles are reused optimistically with no liveness check:
                // a dead one surfaces as ConnectionLost on send and
                // invalidates the cache there, so the expired window costs
                // zero quinn locks instead of one close_reason per assoc.
                let (conn, limit) = match egress_shared.get_fresh(now) {
                    Some(v) => v,
                    None => match egress_shared.refresh_global(&pool, now) {
                        Some(v) => v,
                        None => match egress_shared.get_stale() {
                            Some(v) => v,
                            None => continue,
                        },
                    },
                };
                // `limit` is the connection's live `max_datagram_size()`: the
                // real DATAGRAM budget for the discovered path MTU, with the
                // QUIC overhead already subtracted. It is deliberately NOT
                // clamped — a hard cap here is really a *payload* cap, and the
                // old `min(1350)` made every UDP payload above 1338 B vanish on
                // a 1472 B path (see `dgram_payload_cap`). Payloads past a single
                // frame are split by the fragmenter rather than dropped.
                let sent = frag.send(&conn, sess, &addr, payload, limit);
                if sent.fragmented() {
                    tracing::debug!(
                        "udp assoc {sess}: {} B sent as {} fragments",
                        payload.len(),
                        sent.frames
                    );
                }
                match sent.outcome() {
                    DatagramSend::Sent => {}
                    DatagramSend::Blocked => {
                        tracing::debug!("client datagram dropped: send buffer full");
                    }
                    DatagramSend::TooLarge | DatagramSend::ConnectionLost => {
                        tracing::debug!("client egress stale, invalidating shared cache");
                        egress_shared.invalidate();
                    }
                    DatagramSend::Unsupported => {
                        tracing::debug!("client datagram dropped: peer does not support DATAGRAM");
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
    reply_handle.abort();
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
/// The scratch buffer is reused across replies: the fast path borrows it for
/// the syscall and only WouldBlock copies into the retry queue, so there is
/// no per-reply allocation and no aliasing with another task.
fn send_reply(
    relay: &Arc<tokio::net::UdpSocket>,
    last_app: &std::sync::RwLock<Option<SocketAddr>>,
    dst: SocketAddr,
    payload: &Bytes,
    pkt: &mut bytes::BytesMut,
) {
    let Some(app) = last_app.try_read().ok().and_then(|g| *g) else {
        udp_write::no_app();
        return;
    };
    send_reply_addr(relay, app, dst, payload, pkt);
}

fn send_reply_addr(
    relay: &Arc<tokio::net::UdpSocket>,
    app: SocketAddr,
    dst: SocketAddr,
    payload: &Bytes,
    pkt: &mut bytes::BytesMut,
) {
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
    udp_try_send_slice(relay, map_for_dual(app), &pkt[..]);
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

    /// The whole negotiation is a linear read of greeting + request; the tests
    /// pin the two request forms and a version mismatch, so the single-deadline
    /// refactor cannot change which bytes are consumed.
    #[tokio::test]
    async fn negotiate_reads_connect_and_associate() {
        async fn feed(bytes: &[u8]) -> Result<SocksRequest> {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let payload = bytes.to_vec();
            let server = tokio::spawn(async move {
                let (mut t, _) = l.accept().await.unwrap();
                t.write_all(&payload).await.unwrap();
                // Drain until the client closes: half-closing early races the
                // client's remaining reads on macOS loopback.
                let mut sink = [0u8; 64];
                while let Ok(n) = t.read(&mut sink).await {
                    if n == 0 {
                        break;
                    }
                }
            });
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let r = negotiate(&mut c).await;
            drop(c);
            let _ = server.await;
            r
        }

        let mut connect = vec![0x05, 0x01, 0x00];
        connect.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0xA1]);
        match feed(&connect).await.unwrap() {
            SocksRequest::Connect(t) => {
                assert_eq!(t, TargetAddr::Ip("127.0.0.1:18081".parse().unwrap()));
            }
            SocksRequest::Associate => panic!("expected CONNECT"),
        }

        let mut assoc = vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00];
        assoc.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            feed(&assoc).await.unwrap(),
            SocksRequest::Associate
        ));

        assert!(feed(&[0x04, 0x01, 0x00]).await.is_err(), "bad ver");
    }

    /// Routing must read the maintained atomic: the old shape took the
    /// `shared` lock and `close_reason()` (quinn's connection-state mutex) per
    /// slot per flow, and a slot whose `shared` is empty still has to report
    /// whatever the connection loop last published.
    #[test]
    fn slot_liveness_is_the_maintained_atomic() {
        let slot = ConnSlot::fresh();
        assert!(!slot.is_live(), "no connection yet");
        slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(slot.is_live(), "the hint is what routing reads");
        slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!slot.is_live());
    }

    #[test]
    fn slot_routing_fails_over_to_the_live_connection() {
        // Single mode always keeps `a`.
        assert!(select_slot(false, 0, false, None));
        assert!(select_slot(true, 1, false, None));
        // Dual, all live: pinned -> a, bulk round-robins.
        assert!(select_slot(true, 0, true, Some(true)));
        assert!(select_slot(false, 0, true, Some(true)));
        assert!(!select_slot(false, 1, true, Some(true)));
        // Dual, `a` down: everything fails over to `b`.
        assert!(!select_slot(true, 0, false, Some(true)));
        assert!(!select_slot(false, 0, false, Some(true)));
        assert!(!select_slot(false, 1, false, Some(true)));
        // Dual, `b` down: bulk falls back to `a`, pinned stays.
        assert!(select_slot(true, 0, true, Some(false)));
        assert!(select_slot(false, 0, true, Some(false)));
        assert!(select_slot(false, 1, true, Some(false)));
        // Dual, both down: keep the preference for a bounded fail-fast.
        assert!(select_slot(true, 0, false, Some(false)));
        assert!(select_slot(false, 0, false, Some(false)));
        assert!(!select_slot(false, 1, false, Some(false)));
    }
}
