//! myquic2-server: QUIC ingress -> TCP/UDP dial-out. BBR+GSO defaults, self-signed TLS13.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-server.toml")]
    config: String,
}

/// One live UDP session: the socket replies are read from, plus the bookkeeping
/// the connection needs to reap it.
///
/// A named struct rather than the 4-tuple this used to be, because the
/// destination memo below is the fifth field and `(Arc<..>, JoinHandle, Arc<..>,
/// OwnedPermit, DestMemo)` destructured at nine call sites is no longer
/// readable — and a mis-ordered tuple here would silently pair a socket with
/// the wrong field.
struct SessEntry {
    sock: Arc<tokio::net::UdpSocket>,
    /// The reply reader. `is_finished` is the liveness signal everywhere.
    reader: tokio::task::JoinHandle<()>,
    /// The session's idle stamp, shared with the memo so a memo hit can refresh
    /// liveness without the table lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// Held for the session's lifetime; dropping it returns the global slot.
    _permit: tokio::sync::OwnedSemaphorePermit,
    /// Per-session destination memo — see [`DestMemo`].
    dest: DestMemo,
}

/// Where a session's target address came from, so a domain target is not
/// re-resolved on every datagram.
///
/// The UDP path is per-datagram: without this, a sustained flow to a domain
/// name went through `lookup_cached_fast` (hash + key build + full-key compare)
/// for *every* datagram, whose cost is real — measured at ~6 ns on a memo hit
/// but 15-26 ns/op once the memo's working set exceeds its associativity, which
/// is exactly the many-domains-per-worker case a busy proxy hits. The stream
/// head already pins one destination per quic stream; a session is the same
/// idea one layer down, so the resolution is stored here and every later
/// datagram for the session is a lock-free compare.
///
/// It is keyed on the target *name*, not on the session alone. A session is not
/// bound to one target — a client may send the same session id to a different
/// destination on the next datagram — so a memo that matched on the session
/// alone would answer a datagram naming B with the address resolved for A, and
/// the datagram would be relayed to the wrong target. That failure is silent
/// (replies come back from the wrong host), which is why the name is part of
/// the memo and is compared byte-for-byte, exactly like the DNS memo.
///
/// It is a *hint*, never a substitute for a lookup: it holds no negative state
/// and is ignored when expired, so a name that starts failing or rotates still
/// goes back through the resolver, and a target that moves is picked up within
/// `DEST_PIN_TTL` rather than for the lifetime of the session.
#[derive(Clone, Copy)]
struct DestMemo {
    /// The port and (for a domain target) the name this address was resolved
    /// for. An IP target stores an empty host: it has no name to re-check.
    key: PortKey,
    addr: SocketAddr,
    /// Monotonic deadline ([`mono_millis`] epoch). Read on the datagram path
    /// without a lock; the writer holds the table write lock already.
    expires: u64,
}

/// Domain names up to this length are stored inline in a [`DestMemo`]. Longer
/// names are simply never memoized and take the DNS path every time — a miss,
/// never a mis-route. 64 bytes covers all but a vanishing fraction of real
/// names, and a name longer than the 255-byte wire limit cannot occur here.
const DEST_KEY_BYTES: usize = 64;

/// What a memoized destination is valid *for*: the port always, and the
/// normalized target name when the target was a domain.
#[derive(Clone, Copy)]
struct PortKey {
    host_len: u8,
    host: [u8; DEST_KEY_BYTES],
    port: u16,
}

impl PortKey {
    const EMPTY: Self = Self {
        host_len: 0,
        host: [0; DEST_KEY_BYTES],
        port: 0,
    };

    /// `None` when the name is too long to store inline.
    fn new(host: &str, port: u16) -> Option<Self> {
        if host.len() > DEST_KEY_BYTES {
            return None;
        }
        let mut k = Self::EMPTY;
        k.host_len = host.len() as u8;
        k.host[..host.len()].copy_from_slice(host.as_bytes());
        k.port = port;
        Some(k)
    }

    #[inline]
    fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port
            && self.host_len as usize == host.len()
            && &self.host[..self.host_len as usize] == host.as_bytes()
    }
}

impl DestMemo {
    /// A fresh session has pinned nothing; `expires == 0` can never be `> now`,
    /// so the entry reads as absent without a separate flag.
    const NONE: Self = Self {
        key: PortKey::EMPTY,
        addr: SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        expires: 0,
    };

    /// The memoized address, but only for the target it was resolved for and
    /// only while it is live.
    #[inline]
    fn get(&self, now: u64, host: &str, port: u16) -> Option<SocketAddr> {
        (self.expires > now && self.key.matches(host, port)).then_some(self.addr)
    }

    /// True when this memo already names exactly `addr` for `(host, port)`,
    /// whatever its remaining life. The caller decides whether that life is
    /// short enough to be worth a refresh.
    #[inline]
    fn is_for(&self, host: &str, port: u16, addr: SocketAddr) -> bool {
        self.addr == addr && self.key.matches(host, port)
    }
}

/// How long a resolved destination is reused before it is re-resolved.
///
/// Deliberately shorter than the DNS cache TTL (60 s): DNS answers can change
/// while the cache entry is still live, so this bounds how long a session can
/// keep sending to an address the name no longer resolves to.
const DEST_PIN_TTL_MS: u64 = 30_000;

/// How close to expiry a memo must be before a datagram refreshes it.
///
/// A steady flow stores the same `(key, addr)` on every datagram, so refreshing
/// on each one turned the datagram path into a shard *write* lock per packet
/// (35 ns of lock plus a dirty line in the shared table, measured) for a value
/// that had not changed. Refreshing only in the last quarter of the TTL keeps
/// the entry continuously live with one write per ~7.5 s per session instead.
const DEST_PIN_REFRESH_MS: u64 = DEST_PIN_TTL_MS / 4;
type SessTable = Arc<ShardedSessTable>;

const SESS_SHARDS: usize = 8;

struct ShardedSessTable {
    shards: Vec<std::sync::RwLock<HashMap<u32, SessEntry>>>,
}

impl ShardedSessTable {
    fn new() -> Self {
        Self {
            shards: (0..SESS_SHARDS)
                .map(|_| std::sync::RwLock::new(HashMap::new()))
                .collect(),
        }
    }

    fn shard(&self, s: u32) -> &std::sync::RwLock<HashMap<u32, SessEntry>> {
        &self.shards[(s as usize) % SESS_SHARDS]
    }

    fn drain_all(&self) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            out.extend(lock_write(sh).drain().map(|(_, v)| v));
        }
        out
    }

    fn sweep_all(&self, now: u64) -> Vec<SessEntry> {
        let mut out = Vec::new();
        for sh in &self.shards {
            let expired: Vec<u32> = {
                let m = lock_read(sh);
                m.iter()
                    .filter(|(_, e)| {
                        now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed))
                            >= SESS_IDLE_MS
                    })
                    .map(|(k, _)| *k)
                    .collect()
            };
            if expired.is_empty() {
                continue;
            }
            let mut m = lock_write(sh);
            for k in expired {
                if let Some(e) = m.remove(&k) {
                    out.push(e);
                }
            }
        }
        out
    }
}

/// Hard process-wide bounds: new QUIC connections are refused past this count
/// and new UDP sessions borrow from a shared permit pool, so a single peer
/// cannot exhaust fds/kernel memory (the server is unauthenticated by default).
const MAX_CONNECTIONS: usize = 4096;
/// Concurrent connections that have not completed token authentication.
/// Bounds the receive-window memory an unauthenticated peer can pin while the
/// process-wide cap still allows 4096 *authenticated* connections. With an
/// empty `auth_token` every peer is implicitly authenticated, so this cap is a
/// no-op and the operator must rely on the firewall + the lowered transport
/// windows.
const MAX_UNAUTH_CONNECTIONS: usize = 256;
/// Process-wide UDP session cap. Each session owns a kernel socket with a
/// 512KB send + 512KB receive buffer (see `udp_socket_dual_small`), so 8192
/// sessions bound the kernel side to ~8GB worst case instead of ~32GB.
const MAX_SESSIONS_GLOBAL: usize = 8192;
const LOCAL_SESS_MAX: usize = 4096;
const LOCAL_SESS_TARGET: usize = LOCAL_SESS_MAX - 64;
/// Per-shard sweep target: `sweep_local` runs on one shard, so comparing the
/// shard length against the connection-global `LOCAL_SESS_TARGET` never fires
/// (512 < 4032) and the per-connection cap silently stops working. Keep the
/// global target for documentation, enforce the sharded one here.
const LOCAL_SESS_TARGET_SHARD: usize = LOCAL_SESS_TARGET / SESS_SHARDS;
const SESS_IDLE_MS: u64 = 180_000;
/// Process-wide cap on concurrent TCP dials. Per-connection caps alone cannot
/// bound fd usage when an unauthenticated peer can open many connections.
const MAX_DIALS_GLOBAL: usize = 4096;
/// How long a dial may wait for a global dial permit before giving up.
const DIAL_PERMIT_WAIT: Duration = Duration::from_secs(2);
/// Wall-clock budget for the post-handshake token exchange (accept the uni
/// stream and read the token). `Incoming::accept()` is synchronous, so the
/// handshake itself is bounded separately by [`HANDSHAKE_TIMEOUT`]; together
/// they cap how long an unauthenticated peer can hold a connection permit.
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for completing the QUIC handshake after `Incoming::accept()` before
/// the connection permit is reclaimed (0-RTT connections skip this wait).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn session_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS_GLOBAL)))
}

fn dial_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_DIALS_GLOBAL)))
}

/// Process-wide cap on concurrently handled QUIC bidi streams. The transport's
/// per-connection stream limit alone allows 1024 x 4096 = ~4M live stream tasks,
/// each holding a 5s header timer while queued on the DNS/dial limiters; this
/// bounds the worst case to a fixed number of tasks.
const MAX_STREAM_TASKS: usize = 16_384;

fn stream_task_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_STREAM_TASKS)))
}

/// One-way token authentication: the client opens a uni stream and writes the
/// configured shared secret before any other traffic. Empty = disabled.
const AUTH_MAX_BYTES: usize = 256;

async fn authenticate(conn: &quinn::Connection, expected: &[u8]) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let got = tokio::time::timeout(AUTH_TIMEOUT, async {
        let mut uni = conn.accept_uni().await?;
        uni.read_to_end(AUTH_MAX_BYTES)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .context("auth timeout")??;
    if !ct_eq(&got, expected) {
        anyhow::bail!("auth token mismatch");
    }
    Ok(())
}

/// Constant-time token compare that never short-circuits on the first
/// mismatching byte: mismatched lengths contribute a single flag and the loop
/// runs over `max(len)` bytes with zero padding.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Length inequality is folded in as a 0/1 flag: casting `(len_a ^ len_b)`
    // to u8 could wrap to 0 for lengths 256 apart (e.g. 256 vs 0) and compare
    // equal if every common byte matched. Only *whether* the lengths differ
    // is revealed, never the token bytes.
    let mut diff = if a.len() == b.len() { 0u8 } else { 1u8 };
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Rate limit for "refusing new connection" logs under a flood.
fn warn_once_per_sec() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        return false;
    }
    LAST.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Rate limit for per-flow abort lines: the `conn.stats()` snapshot takes the
/// quinn connection-state mutex, so an abort storm must not pay it per flow.
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let a = Args::parse();
    let c: ServerConf = load_toml(&a.config)?;
    if c.auth_token.len() > AUTH_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_MAX_BYTES} B wire cap (server only reads the first {AUTH_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
        );
    }
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    let listen: SocketAddr = c.listen.parse().context("bad listen")?;

    if is_placeholder_token(&c.auth_token) {
        warn!("auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)");
    }
    // Self-signed cert: auto-generate on first run (fast path, no external CA RTT).
    // Regenerate only when BOTH files are absent: silently recreating one over
    // an existing counterpart would invalidate every client's pinned cert.
    let cert_exists = Path::new(&c.cert_file).exists();
    let key_exists = Path::new(&c.key_file).exists();
    match (cert_exists, key_exists) {
        (true, true) => {}
        (false, false) => {
            info!("generating self-signed cert for {}", c.server_name);
            gen_self_signed_files(&c.server_name, &c.cert_file, &c.key_file)?;
        }
        _ => anyhow::bail!(
            "cert/key pair incomplete: cert_file {} and key_file {}; refusing to overwrite \
             the surviving file (restore the missing one, or delete both to regenerate)",
            if cert_exists { "exists" } else { "is missing" },
            if key_exists { "exists" } else { "is missing" }
        ),
    }
    let cert = load_cert_der(&c.cert_file)?;
    let key = load_key_der(&c.key_file)?;
    let tls = server_tls_config(cert, key, &c.alpn_bytes())?;
    if c.alpn.as_deref().is_some_and(|s| !s.is_empty()) {
        info!("custom ALPN in use (masquerade: skew guard weakened, upgrade both sides together)");
    }
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    scfg.transport_config(build_transport_tuned(
        &c.congestion,
        c.keep_alive_secs,
        c.tuning(),
    ));
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
    if !c.auth_token.is_empty() {
        info!("client token authentication enabled");
    } else {
        warn!("auth_token is empty: the QUIC endpoint accepts any peer (rely on firewall/network isolation)");
    }
    let auth_token = Arc::new(c.auth_token.clone().into_bytes());
    let auth_enabled = !auth_token.is_empty();
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let pending_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UNAUTH_CONNECTIONS));
    spawn_udp_reporter();
    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => {
                error!("QUIC endpoint driver stopped (socket failure?); exiting");
                break;
            }
        };
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if warn_once_per_sec() {
                    warn!("connection limit {MAX_CONNECTIONS} reached; refusing new connection");
                }
                drop(incoming); // implicit refuse
                continue;
            }
        };
        // Bound pre-auth receive-window memory: a peer that never sends a
        // token must not pin the whole MAX_CONNECTIONS budget. Released as
        // soon as `authenticate` returns.
        let pending = if auth_enabled {
            match pending_limit.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    if warn_once_per_sec() {
                        warn!(
                            "pre-auth connection limit {MAX_UNAUTH_CONNECTIONS} reached; refusing"
                        );
                    }
                    drop(incoming);
                    continue;
                }
            }
        } else {
            None
        };
        let allow_private = c.allow_private;
        let auth_token = auth_token.clone();
        // Accept + handshake per connection: never await a handshake inline, or
        // one slow/malicious client stalls every other new connection.
        tokio::spawn(async move {
            let _permit = permit;
            // 0.5-RTT accept: streams usable before handshake completes on resumption.
            let conn = match incoming.accept() {
                Ok(connecting) => match connecting.into_0rtt() {
                    Ok((c, accepted_fut)) => {
                        // Incoming conversion always succeeds and `accepted`
                        // always resolves true, but an unfinished handshake
                        // must not hold the connection permit: awaiting it
                        // (bounded) gates the permit on handshake completion.
                        // A dead client resolves false via the channel close,
                        // and the timeout backstops a stall; either way the
                        // close_reason check keeps a dead handle out.
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepted_fut).await {
                            Ok(_) if c.close_reason().is_none() => c,
                            Ok(_) => {
                                warn!("client handshake failed: {:?}", c.close_reason());
                                return;
                            }
                            Err(_) => {
                                warn!("handshake timed out after {HANDSHAKE_TIMEOUT:?}");
                                return;
                            }
                        }
                    }
                    Err(connecting) => {
                        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
                        match tokio::time::timeout_at(deadline, connecting).await {
                            Ok(Ok(c)) => c,
                            Ok(Err(e)) => {
                                warn!("accept err: {e:#}");
                                return;
                            }
                            Err(_) => {
                                warn!("handshake timed out after {HANDSHAKE_TIMEOUT:?}");
                                return;
                            }
                        }
                    }
                },
                Err(e) => {
                    warn!("accept err: {e:#}");
                    return;
                }
            };
            if let Err(e) = authenticate(&conn, &auth_token).await {
                warn!("auth failed from {}: {e:#}", conn.remote_address());
                conn.close(0x01u32.into(), b"unauthorized");
                return;
            }
            // Authentication done: free the pre-auth slot so other new peers
            // can handshake while this connection lives on.
            drop(pending);
            if let Err(e) = handle_conn(conn, allow_private).await {
                warn!("conn end: {e:#}");
            }
        });
    }
    Ok(())
}

/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
fn spawn_udp_reporter() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if ONCE.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately; skip it
        let mut prev = udp_stats::snapshot();
        let mut prev_w = udp_write::snapshot();
        let mut prev_r = udp_stats::reassembly_drops();
        let mut prev_d = dgram_drops::snapshot3();
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
            let now_d = dgram_drops::snapshot3();
            let d_full = now_d.2.saturating_sub(prev_d.2);
            if d_full > 0 {
                info!(
                    "udp budget (60s): {d_full} dropped (session/DNS cap); totals too_large={} buffer_full={} session_full={}",
                    now_d.0, now_d.1, now_d.2
                );
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
        }
    });
}

async fn handle_conn(conn: quinn::Connection, allow_private: bool) -> Result<()> {
    info!("new QUIC conn from {}", conn.remote_address());
    let conn_id = next_conn_id();
    // One UDP socket per sess_id: replies are inherently demuxed, concurrent
    // ASSOCIATEs sharing this QUIC connection never cross-talk.
    let sess: SessTable = Arc::new(ShardedSessTable::new());
    {
        let sess = sess.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        // Shard-by-shard sweep, abort after all locks drop.
                        let evicted = sess.sweep_all(now);
                        abort_evicted(evicted);
                    }
                    _ = conn.closed() => {
                        let drained = sess.drain_all();
                        abort_evicted(drained);
                        break;
                    }
                }
            }
        });
    }
    // Uni streams carry only the auth token, which `authenticate` already
    // consumed. Without a reader quinn would buffer up to the whole connection
    // receive window for extra uni streams, so drain and refuse them explicitly.
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut uni) = conn.accept_uni().await {
                let _ = uni.stop(0u32.into());
            }
        });
    }
    // QUIC DATAGRAMs -> per-sess UDP sockets
    let cd = conn.clone();
    let ss = sess.clone();
    tokio::spawn(async move {
        // One receive future per connection instead of one per datagram:
        // `read_datagram` is cancel-safe (a buffered datagram is returned before
        // its first await point), and its `Notify` is inline, so rebuilding it
        // per packet was pure overhead. The connection-state mutex that quinn
        // takes per datagram still applies — that part is inside quinn.
        let reader = cd.read_datagram();
        tokio::pin!(reader);
        // Large app datagrams arrive as MQP-2 fragments; reassemble before they
        // reach a target socket, so the target sees the datagram the app sent.
        let mut reasm = DgramReassembler::new();
        // Per-connection fast path: the thread-local memo is shared by every
        // connection on this worker, so a burst to one session still pays two
        // RefCell scans per packet. This slot lives in the reader task itself.
        let mut fast_sess: u32 = u32::MAX;
        let mut fast_sock: Option<Arc<tokio::net::UdpSocket>> = None;
        let mut fast_last: Option<Arc<std::sync::atomic::AtomicU64>> = None;
        let mut fast_abort: Option<tokio::task::AbortHandle> = None;
        // The address the pinned session resolves to, so a domain target's
        // datagrams skip the DNS lookup entirely instead of paying a hash, a
        // key build and a key compare on every packet. Only meaningful while
        // `fast_sess` names the session it was resolved for; it is cleared
        // whenever the pin is.
        /// The target a datagram names, as `(host, port)`. An IP target reports
        /// an empty host: it has no name that could rotate to another address,
        /// so there is nothing for a pin to re-check.
        fn target_name(a: TargetAddrRef<'_>) -> (&str, u16) {
            match a {
                TargetAddrRef::Ip(dst) => ("", dst.port()),
                TargetAddrRef::Domain(h, p) => (h, p),
            }
        }
        let mut fast_pin: Option<(u32, String, u16, SocketAddr)> = None;
        // Resolve this datagram's target once, for both the fragment and the
        // plain branch. Order matters: the connection's pin first (free, and
        // only trusted while it still names the pinned session), then the
        // session's own memo, then the DNS cache. `None` means "not known yet"
        // -- `forward_server_dgram` spawns the resolver, so it is not an error.
        //
        // A free function rather than a closure: it both reads and writes the
        // pin, and a closure capturing it mutably would conflict with the pin
        // assignments below.
        fn resolve_pin(
            ss: &SessTable,
            pin: &mut Option<(u32, String, u16, SocketAddr)>,
            pinned_sess: u32,
            s: u32,
            h: &str,
            p: u16,
        ) -> Option<SocketAddr> {
            // The connection-level pin is only trusted for the exact
            // (session, name, port) it was stored for. Matching on the session
            // alone would send a datagram naming a *different* target to the
            // address resolved for the previous one -- a silent mis-route.
            if s == pinned_sess {
                if let Some((ps, ph, pp, dst)) = pin {
                    if *ps == s && *pp == p && ph == h {
                        return Some(*dst);
                    }
                }
            }
            if let Some(dst) = sess_dest_lookup(ss, mono_millis(), s, h, p) {
                // Adopt the session's memo so the next datagram is a pure
                // compare with no table read at all.
                *pin = Some((s, h.to_string(), p, dst));
                return Some(dst);
            }
            match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => Some(dst),
                CachedLookup::Negative | CachedLookup::Unknown => None,
            }
        }
        loop {
            let d: Bytes = match reader.as_mut().await {
                Ok(d) => d,
                Err(_) => break,
            };
            // Keep an owned handle so the payload can be handed to the send
            // path as a zero-copy `Bytes::slice` (instead of a per-packet
            // copy) even after `decode_datagram_ref` borrowed `d`.
            let owned = d.clone();
            if d.first() == Some(&MQP_DGRAM_FRAG) {
                let Ok(f) = decode_fragment(&d) else {
                    continue;
                };
                let Some((s, a, whole)) = reasm.push(&f, mono_millis()) else {
                    continue;
                };
                udp_stats::payload(whole.len());
                // One resolution for this datagram: the session's own pin, else
                // the DNS cache. A domain target whose session is already pinned
                // never reaches `forward_server_dgram` at all.
                let want = match a.as_ref() {
                    TargetAddrRef::Ip(dst) => Some(dst),
                    TargetAddrRef::Domain(h, p) => {
                        resolve_pin(&ss, &mut fast_pin, fast_sess, s, h, p)
                    }
                };
                if let Some(dst) = want {
                    let mut fast_hit = false;
                    if s == fast_sess {
                        if let (Some(sock), Some(last), Some(ab)) =
                            (fast_sock.as_ref(), fast_last.as_ref(), fast_abort.as_ref())
                        {
                            if !ab.is_finished() && (allow_private || is_global_ip_cached(dst.ip()))
                            {
                                touch_session_throttled(conn_id, s, last);
                                udp_try_send(sock, map_for_dual(dst), whole.clone());
                                fast_hit = true;
                            }
                        }
                    }
                    if fast_hit {
                        continue;
                    }
                }
                let used =
                    forward_server_dgram(&ss, &cd, conn_id, s, a.as_ref(), whole, allow_private)
                        .await;
                if let Some(dst) = used {
                    match sess_memo_lookup(conn_id, s) {
                        SessHit::Fresh(sock, last, ab) => {
                            fast_sess = s;
                            fast_sock = Some(sock);
                            fast_last = Some(last);
                            fast_abort = Some(ab);
                            let (ph, pp) = target_name(a.as_ref());
                            fast_pin = Some((s, ph.to_string(), pp, dst));
                        }
                        SessHit::Stale | SessHit::Miss => {
                            fast_sess = u32::MAX;
                            fast_sock = None;
                            fast_last = None;
                            fast_abort = None;
                            fast_pin = None;
                        }
                    }
                }
            } else {
                let Ok((s, a, p)) = decode_datagram_ref(&d) else {
                    continue;
                };
                let want = match a {
                    TargetAddrRef::Ip(dst) => Some(dst),
                    TargetAddrRef::Domain(h, p) => {
                        resolve_pin(&ss, &mut fast_pin, fast_sess, s, h, p)
                    }
                };
                if let Some(dst) = want {
                    let mut fast_hit = false;
                    if s == fast_sess {
                        if let (Some(sock), Some(last), Some(ab)) =
                            (fast_sock.as_ref(), fast_last.as_ref(), fast_abort.as_ref())
                        {
                            if !ab.is_finished() && (allow_private || is_global_ip_cached(dst.ip()))
                            {
                                let off = owned.len() - p.len();
                                udp_stats::payload(p.len());
                                touch_session_throttled(conn_id, s, last);
                                udp_try_send(sock, map_for_dual(dst), owned.slice(off..));
                                fast_hit = true;
                            }
                        }
                    }
                    if fast_hit {
                        continue;
                    }
                }
                let off = owned.len() - p.len();
                let payload = owned.slice(off..);
                udp_stats::payload(payload.len());
                let used =
                    forward_server_dgram(&ss, &cd, conn_id, s, a, payload, allow_private).await;
                if let Some(dst) = used {
                    match sess_memo_lookup(conn_id, s) {
                        SessHit::Fresh(sock, last, ab) => {
                            fast_sess = s;
                            fast_sock = Some(sock);
                            fast_last = Some(last);
                            fast_abort = Some(ab);
                            let (ph, pp) = target_name(a);
                            fast_pin = Some((s, ph.to_string(), pp, dst));
                        }
                        SessHit::Stale | SessHit::Miss => {
                            fast_sess = u32::MAX;
                            fast_sock = None;
                            fast_last = None;
                            fast_abort = None;
                            fast_pin = None;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // TCP: one QUIC bidi stream per connection. First bytes = MQP addr header.
    // Concurrent streams are already capped by the transport; dials are bounded
    // process-wide (not per connection) so many connections cannot exhaust fds
    // together.
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => break,
        };
        let stream_permit = match stream_task_limiter().clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // Fail the stream immediately instead of queueing unbounded work.
                send.reset(0x05u32.into()).ok();
                continue;
            }
        };
        let stat_conn = conn.clone();
        tokio::spawn(async move {
            let _stream_permit = stream_permit;
            let target: TargetAddr = match tokio::time::timeout(
                Duration::from_secs(5),
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
                            // `resolve_all_cached` sorts IPv4 first, so a flat
                            // prefix cut would starve IPv6 whenever upstream
                            // returns more than 8 v4 records. Alternate
                            // families instead, keeping v4 preference while
                            // guaranteeing v6 gets tried.
                            let mut n = 0;
                            let mut v4 = v.iter().filter(|a| a.is_ipv4());
                            let mut v6 = v.iter().filter(|a| !a.is_ipv4());
                            // Alternate families so v6 is never starved, but
                            // keep filling from whichever family still has
                            // records until the 8-slot buffer is full (a
                            // v4-only answer must still yield up to 8).
                            let mut want_v4 = true;
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
                        Err(_) => 0,
                    };
                    drop(permit);
                    &dns_cand[..dns_n]
                }
            };
            // Hold the global dial permit only for the connect phase; the copy
            // phase is bounded by the transport's stream limit instead.
            let _dial_permit = match tokio::time::timeout(
                DIAL_PERMIT_WAIT,
                dial_limiter().clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(p)) => p,
                _ => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            let tcp = match dial_happy_eyeballs(cands, allow_private).await {
                Some(t) => t,
                None => {
                    send.reset(0x04u32.into()).ok();
                    return;
                }
            };
            drop(_dial_permit);
            let _ = tcp.set_nodelay(true);
            // MQP-2: report the bound address of the dialed socket so the
            // client can answer SOCKS with the real BND.ADDR/PORT (RFC 1928)
            // instead of a placeholder.
            let bnd = tcp
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            // Fixed-size stack buffer: the ACK is at most 1 + 1 + 16 + 2 bytes
            // (v6 form), so the per-stream `Vec` this used to allocate bought
            // nothing.
            let mut ack = [0u8; 20];
            ack[0] = MQP_TCP_ACK;
            let n = 1 + encode_bnd_addr_into(bnd, &mut ack[1..]);
            if send.write_all(&ack[..n]).await.is_err() {
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
        });
    }
    Ok(())
}

/// Byte length of the complete MQP-2 TCP header for a given `atyp`: how much
/// the header reader must collect before it can decode. The domain form needs
/// its length byte first, which is why this is two-staged. Pure so the lengths
/// are unit-testable without a live QUIC stream.
fn mqp_hdr_len(atyp: u8, domain_len: u8) -> Result<usize> {
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

async fn read_mqp_target(recv: &mut quinn::RecvStream) -> Result<TargetAddr> {
    // No per-read timeout here: the caller wraps the whole header read in a
    // single 5s budget, and an inner timeout just registered extra timers.
    //
    // The header is decoded from one stack buffer instead of assembling a
    // temporary `Vec` per field and then decoding that: a domain target used to
    // cost four heap allocations (three `Vec`s plus the owned `String`) before
    // the dial even started. Now only the final `TargetAddr` allocates.
    const HDR_MAX: usize = 1 + 1 + 255 + 2;
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
/// `cands` is borrowed so the IP-literal path allocates nothing. The filtered
/// candidate list and the task set live in fixed arrays: the old `Vec::collect`
/// plus `JoinSet` allocated two or three times per flow just to set up a dial
/// that, in the single-candidate case, needs one `connect`.
async fn dial_happy_eyeballs(
    cands: &[SocketAddr],
    allow_private: bool,
) -> Option<tokio::net::TcpStream> {
    const DIAL_CAND_MAX: usize = 8;
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
    let cands = &accept[..n];
    if cands.is_empty() {
        return None;
    }
    // Total budget 4s; the client-side ACK wait is sized to cover it.
    let budget = tokio::time::sleep(Duration::from_secs(4));
    tokio::pin!(budget);
    if let [only] = cands {
        tokio::select! {
            r = tokio::net::TcpStream::connect(*only) => {
                let s = r.ok()?;
                let _ = s.set_nodelay(true);
                return Some(s);
            }
            _ = &mut budget => return None,
        }
    }
    // Event-driven cancellation: losers are woken by a watch value instead of
    // polling a flag every 50ms (which cost extra wakeups on hot dial paths).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(1);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::with_capacity(cands.len());
    for (i, a) in cands.iter().enumerate() {
        let tx = tx.clone();
        let mut cancel = cancel_rx.clone();
        let a = *a;
        tasks.push(tokio::spawn(async move {
            if i > 0 {
                let delay = Duration::from_millis(250 * i.min(4) as u64);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.wait_for(|v| *v) => return,
                }
            }
            if *cancel.borrow() || tx.is_closed() {
                return;
            }
            let connected = tokio::select! {
                r = tokio::net::TcpStream::connect(a) => r.ok(),
                _ = cancel.wait_for(|v| *v) => None,
            };
            if let Some(s) = connected {
                let _ = s.set_nodelay(true);
                // Capacity 1: the first winner wins, the rest drop their socket.
                let _ = tx.try_send(s);
            }
        }));
    }
    drop(tx);
    let res = tokio::select! {
        r = rx.recv() => r,
        _ = &mut budget => None,
    };
    let _ = cancel_tx.send(true);
    for t in tasks {
        t.abort();
    }
    res
}

const SLOTS: usize = 64;

/// Mix an IP into `0..SLOTS` with a manual multiply-add fold (no
/// SipHash on the packet path). A collision only shares a slot — the probe
/// compares the full key — so it can evict an entry but never mis-serve one.
fn ip_cache_idx(ip: IpAddr) -> usize {
    let mut h: u64 = 0;
    match ip {
        IpAddr::V4(v4) => {
            for o in v4.octets() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(o as u64);
            }
        }
        IpAddr::V6(v6) => {
            for s in v6.segments() {
                h = h.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(s as u64);
            }
        }
    }
    (h % SLOTS as u64) as usize
}

/// Direct-mapped per-thread memo of `is_global_ip` verdicts.
///
/// Fixed-destination flows pay `is_global_ip` per inbound datagram, and the
/// predicate is pure over the IP, so the verdict is remembered thread-locally.
/// One hashed slot per address with a full-key compare makes a probe O(1)
/// instead of the O(SLOTS) linear scan the first revision used; a collision
/// only evicts the slot, so the security outcome is the same as calling the
/// predicate directly — only an exact key match is ever returned, never
/// another address's verdict.
fn is_global_ip_cached(ip: IpAddr) -> bool {
    thread_local! {
        static CACHE: std::cell::RefCell<[(Option<IpAddr>, bool); SLOTS]> =
            const { std::cell::RefCell::new([(None, false); SLOTS]) };
    }
    let idx = ip_cache_idx(ip);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c[idx].0 == Some(ip) {
            return c[idx].1;
        }
        let v = is_global_ip(ip);
        c[idx] = (Some(ip), v);
        v
    })
}

/// Relay one datagram to its target. `Some(dst)` is the address actually used,
/// which the caller pins onto the session so the next datagram for the same
/// session skips this whole function; `None` means the datagram was dropped
/// (SSRF filter, negative cache, DNS overload, or no session slot).
async fn forward_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    addr: TargetAddrRef<'_>,
    payload: Bytes,
    allow_private: bool,
) -> Option<SocketAddr> {
    match addr {
        TargetAddrRef::Ip(dst) => {
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                return None;
            }
            // No destination memo for an IP target: `resolve_pin` — the memo's
            // only reader on the datagram path — consults it for domain targets
            // exclusively (an IP target's address is already in the datagram),
            // and `PortKey::matches` would need an empty host *and* port 0 to
            // ever match this entry, which the wire decoder rejects. Storing it
            // was a shard write lock plus a 72-byte memo write per datagram that
            // nothing could read back.
            let sock = get_or_create_sess(ss, cd, conn_id, s, None).await?;
            udp_try_send(&sock, map_for_dual(dst), payload);
            Some(dst)
        }
        TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
            CachedLookup::Negative => None,
            CachedLookup::Addr(dst) => {
                if !allow_private && !is_global_ip_cached(dst.ip()) {
                    return None;
                }
                let sock = get_or_create_sess(ss, cd, conn_id, s, Some((h, p, dst))).await?;
                udp_try_send(&sock, map_for_dual(dst), payload);
                Some(dst)
            }
            CachedLookup::Unknown => {
                if dns_is_inflight(h, p) {
                    return None;
                }
                if dns_slow_path_limiter().available_permits() == 0 {
                    dgram_drops::bump(&dgram_drops::SESSION_FULL);
                    return None;
                }
                let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        dgram_drops::bump(&dgram_drops::SESSION_FULL);
                        return None;
                    }
                };
                let ss = ss.clone();
                let cd = cd.clone();
                let host = h.to_owned();
                tokio::spawn(async move {
                    let _permit = permit;
                    let dst = match resolve_all_cached(&host, p).await {
                        Ok(v) => match v
                            .iter()
                            .copied()
                            .find(|a| allow_private || is_global_ip(a.ip()))
                        {
                            Some(v) => v,
                            None => return,
                        },
                        Err(_) => return,
                    };
                    let sock = match get_or_create_sess(&ss, &cd, conn_id, s, Some((&host, p, dst)))
                        .await
                    {
                        Some(v) => v,
                        None => return,
                    };
                    udp_try_send(&sock, map_for_dual(dst), payload);
                });
                // The resolution happens in the spawned task above (it awaits),
                // so this datagram is delivered there and there is no pin for
                // the caller to record yet. The next datagram for this session
                // finds the answer in the DNS cache -- or, once one datagram has
                // completed this path, in the session's own destination memo.
                None
            }
        },
    }
}
/// Evict sessions that are past their idle deadline, then arbitrary ones if the
/// table is still over its target, and hand the removed entries back so the
/// caller can abort their readers *after* releasing the table lock.
///
/// Expired entries must be aborted, not merely dropped: a dropped `JoinHandle`
/// leaves the reply reader (and its socket fd / kernel buffer) alive until its
/// own 180s timeout, which transiently doubles the session/fd budget.
///
/// Returning a `Vec` instead of aborting inline keeps `abort()` — which touches
/// the task's vtable and may wake a worker thread — off the write-lock hold,
/// and removes the key-collection allocations from that critical section.
fn sweep_local(w: &mut HashMap<u32, SessEntry>) -> Vec<SessEntry> {
    let now = mono_millis();
    let mut expired: Vec<u32> = Vec::new();
    for (k, e) in w.iter() {
        if now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS {
            expired.push(*k);
        }
    }
    let mut evicted: Vec<SessEntry> = Vec::with_capacity(expired.len());
    for k in expired {
        if let Some(e) = w.remove(&k) {
            evicted.push(e);
        }
    }
    let over = w.len().saturating_sub(LOCAL_SESS_TARGET_SHARD);
    if over > 0 {
        let victims: Vec<u32> = w.keys().take(over).copied().collect();
        for k in victims {
            if let Some(e) = w.remove(&k) {
                evicted.push(e);
            }
        }
    }
    evicted
}

fn abort_evicted(evicted: Vec<SessEntry>) {
    for e in evicted {
        e.reader.abort();
    }
}

/// The session's pinned destination, if it still has one.
///
/// Lock-free on the common path: the fast path only needs the shard read guard
/// (the same one `get_or_create_sess` takes) and the memo is a `Copy` field, so
/// there is no atomic traffic and no allocation. A memo miss costs the same as
/// any other session-table probe and simply means "resolve and store again".
fn sess_dest_lookup(ss: &SessTable, now: u64, s: u32, host: &str, port: u16) -> Option<SocketAddr> {
    let sh = ss.shard(s);
    if let Some(e) = lock_read(sh).get(&s) {
        return e.dest.get(now, host, port);
    }
    None
}

/// Record (or refresh) the session's pinned destination. Best effort: a session
/// that vanished between the send and this call is simply not memoized, and the
/// next datagram re-resolves and tries again.
///
/// Read first, write only when the memo actually needs it. The datagram path
/// calls this for every domain-target packet, and the answer for a steady flow
/// is the same `(key, addr)` every time — so an unconditional write lock made
/// every packet of that flow take the shard exclusively. Now a packet whose
/// memo already names the right address and still has more than
/// [`DEST_PIN_REFRESH_MS`] of life left takes only the read lock it would take
/// anyway, and the write happens once per refresh window instead of per packet.
fn sess_dest_store(ss: &SessTable, s: u32, host: &str, port: u16, addr: SocketAddr) {
    // A name too long for the inline key is not memoized. Storing it under a
    // truncated key would be worse than not storing it: a later datagram for a
    // different name sharing that prefix would match.
    let Some(key) = PortKey::new(host, port) else {
        return;
    };
    let now = mono_millis();
    {
        let r = lock_read(ss.shard(s));
        if let Some(e) = r.get(&s) {
            if e.dest.is_for(host, port, addr)
                && e.dest.expires.saturating_sub(now) > DEST_PIN_REFRESH_MS
            {
                return;
            }
        }
    }
    let mut w = lock_write(ss.shard(s));
    if let Some(e) = w.get_mut(&s) {
        e.dest = DestMemo {
            key,
            addr,
            expires: now + DEST_PIN_TTL_MS,
        };
    }
}

/// Monotonic connection ids for the session memos.
///
/// Session ids are allocated per client — every client hub counts from 1 — so
/// `(conn, sess)` is the identity of a session and the connection half must
/// never repeat. `Connection::stable_id` is a heap address, and the allocator
/// hands the same address to the next connection after a reconnect, so a memo
/// entry left behind by a dead connection could match a different one. A
/// process-wide counter cannot alias.
fn next_conn_id() -> usize {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Per-thread memo of the most recently used session socket.
///
/// A datagram-heavy flow sends a long run of packets to the *same* session, so
/// the connection-level `RwLock` read plus hash lookup in `get_or_create_sess`
/// is pure per-packet overhead for all but the first packet of the run. The
/// memo is a single slot on purpose: a miss simply falls through to the table.
/// The key is `(conn, sess)`, never `sess` alone: session ids are allocated per
/// client, so two connections sharing this thread would otherwise serve each
/// other's sockets and route replies onto the wrong QUIC connection.
struct SessMemo {
    /// Owning connection id ([`next_conn_id`]): the slot is shared by every
    /// connection whose DATAGRAM reader runs on this worker thread.
    conn: usize,
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    /// The session table's liveness stamp, kept so a memo hit can refresh it
    /// without re-taking the table lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// The reply reader's abort handle. `is_finished` is the liveness signal,
    /// the same one the table path uses: a flag the reader cleared on its way
    /// out would stay set when the sweeper or a connection close aborts the
    /// reader mid-await, and that path runs no cleanup at all.
    abort: tokio::task::AbortHandle,
}

const SESS_MEMO_SLOTS: usize = 32;

thread_local! {
    static SESS_MEMO: std::cell::RefCell<[Option<SessMemo>; SESS_MEMO_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

fn sess_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % SESS_MEMO_SLOTS
}

fn sess_memo_put(
    conn: usize,
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    last: Arc<std::sync::atomic::AtomicU64>,
    abort: tokio::task::AbortHandle,
) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        m[idx] = Some(SessMemo {
            conn,
            sess,
            sock,
            last,
            abort,
        });
    });
}

/// Drop the memo when it still points at `(conn, sess)`. Called by a reply
/// reader as it exits, so the next inbound packet for that session recreates it
/// instead of sending into a socket nobody reads.
fn sess_memo_forget(conn: usize, sess: u32) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        if m[idx]
            .as_ref()
            .is_some_and(|x| x.conn == conn && x.sess == sess)
        {
            m[idx] = None;
        }
    });
}

/// Outcome of a session-memo probe.
enum SessHit {
    Miss,
    /// A live session socket, its liveness stamp and its reader abort handle
    /// (the abort handle lets per-connection fast paths validate liveness
    /// without re-probing the thread-local memo).
    Fresh(
        Arc<tokio::net::UdpSocket>,
        Arc<std::sync::atomic::AtomicU64>,
        tokio::task::AbortHandle,
    ),
    /// The memo's reader has exited: the table (not the memo) must decide,
    /// so this falls through and lets the table path recreate the session.
    Stale,
}

/// Probe the thread-local session memo for `(conn, sess)`.
///
/// The connection is part of the key because a session id is only unique
/// within one connection (every client hub allocates ids from 1), and this slot
/// is shared by every connection whose DATAGRAM reader runs on this worker
/// thread. Matching on `sess` alone served one connection's socket to another,
/// so that connection's datagrams went out on the wrong session.
fn sess_memo_lookup(conn: usize, sess: u32) -> SessHit {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        match m[idx].as_ref() {
            Some(x) if x.conn == conn && x.sess == sess => {
                if !x.abort.is_finished() {
                    SessHit::Fresh(x.sock.clone(), x.last.clone(), x.abort.clone())
                } else {
                    m[idx] = None;
                    SessHit::Stale
                }
            }
            _ => SessHit::Miss,
        }
    })
}

/// Per-thread view of the last liveness refresh, so the throttling decision
/// costs no table lock. A `(connection, session, ms)` triple: session ids are
/// only unique within a connection, so `(session, ms)` alone let two
/// connections share — and thereby defeat — one throttle window.
///
/// NOTE: an earlier revision sampled the clock 1/64 by packet count. That
/// starved trickle flows: a burst past 64 packets froze `tick` large without
/// a store, and every later trickle packet kept skipping the clock read, so
/// `last` froze until the 180s reap. The clock read (~20ns vdso) is an order
/// of magnitude cheaper than the hash lookup + table lock it replaces, so the
/// throttle is purely time-based now: at most one shared store per second per
/// session, every packet pays one clock read.
struct TouchMemo {
    conn: usize,
    sess: u32,
    ms: u64,
}

const TOUCH_SLOTS: usize = 32;

thread_local! {
    static TOUCH_MEMO: std::cell::RefCell<[Option<TouchMemo>; TOUCH_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

fn touch_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % TOUCH_SLOTS
}

/// Refresh `last` at most once per [`TOUCH_INTERVAL_MS`], using a thread-local
/// copy of the last refresh time.
fn touch_session_throttled(conn: usize, sess: u32, last: &std::sync::atomic::AtomicU64) {
    const TOUCH_INTERVAL_MS: u64 = 1000;
    let now = mono_millis();
    let due = TOUCH_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        let idx = touch_memo_idx(conn, sess);
        match c[idx].as_mut() {
            Some(e) if e.conn == conn && e.sess == sess => {
                if now.saturating_sub(e.ms) >= TOUCH_INTERVAL_MS {
                    e.ms = now;
                    true
                } else {
                    false
                }
            }
            _ => {
                c[idx] = Some(TouchMemo {
                    conn,
                    sess,
                    ms: now,
                });
                true
            }
        }
    });
    if due {
        last.store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn sess_reader_task(
    conn_id: usize,
    s: u32,
    rs: Arc<tokio::net::UdpSocket>,
    ss2: SessTable,
    c2: quinn::Connection,
    last2: Arc<std::sync::atomic::AtomicU64>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buf = vec![0u8; UDP_RECV_MAX + UDP_RECV_SLACK];
    let mut frag = DgramFragmenter::new();
    let mut limit = c2.max_datagram_size().unwrap_or(0);
    let mut last_touch = 0u64;
    let mut last_limit_refresh = mono_millis();
    loop {
        let (n, src) = tokio::select! {
            r = rs.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = tick.tick() => {
                if c2.close_reason().is_some()
                    || mono_millis()
                        .saturating_sub(last2.load(std::sync::atomic::Ordering::Relaxed))
                        >= SESS_IDLE_MS
                {
                    break;
                }
                limit = match c2.max_datagram_size() {
                    Some(m) => m,
                    // DATAGRAM support is negotiated at the handshake; a mid-life
                    // disable leaves this reader with nothing to deliver, so exit
                    // and let the entry self-reap instead of holding a socket.
                    None => break,
                };
                continue;
            }
        };
        let now = mono_millis();
        if now.saturating_sub(last_touch) >= 1000 {
            last_touch = now;
            last2.store(now, std::sync::atomic::Ordering::Relaxed);
        }
        // Active sessions track PMTU growth without waiting for the 60 s idle
        // tick: at most one quinn lock per session per 10 s, and only while the
        // session is actually receiving replies.
        if now.saturating_sub(last_limit_refresh) >= 10_000 {
            last_limit_refresh = now;
            match c2.max_datagram_size() {
                Some(m) => limit = m,
                None => break,
            }
        }
        if n == buf.len() {
            warn!(
                "udp session {s}: target reply above {MQP_FRAG_MAX_PAYLOAD} B truncated; \
                 raise MQP_FRAG_MAX_PAYLOAD to carry it"
            );
            continue;
        }
        if limit == 0 {
            break;
        }
        let src = SocketAddr::new(unmap(src.ip()), src.port());
        let ta = TargetAddr::Ip(src);
        let sent = frag.send(&c2, s, &ta.as_ref(), &buf[..n], limit);
        if sent.fragmented() {
            tracing::debug!("udp session {s}: {} B sent as {} fragments", n, sent.frames);
        }
        match sent.outcome() {
            DatagramSend::Sent => {}
            DatagramSend::Blocked => {}
            DatagramSend::TooLarge => {
                limit = c2.max_datagram_size().unwrap_or(0);
            }
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => break,
        }
    }
    sess_memo_forget(conn_id, s);
    {
        let sh = ss2.shard(s);
        let mut w = lock_write(sh);
        if let Some(cur) = w.get(&s) {
            if Arc::ptr_eq(&cur.sock, &rs) {
                w.remove(&s);
            }
        }
    }
}

async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    // `(host, port, resolved address)` when the caller already knows a *named*
    // destination, so the session can memoize it. An IP target passes `None`:
    // its address is already in every datagram it sends, and the memo is only
    // ever read back for domain targets (`sess_dest_store`).
    dest: Option<(&str, u16, SocketAddr)>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Session 0 is reserved (never allocated by any client hub): a wire
    // datagram carrying it is malformed or hostile, not a new session.
    // Refusing here keeps it from pinning a global permit until the sweep.
    if s == 0 {
        dgram_drops::bump(&dgram_drops::SESSION_FULL);
        return None;
    }
    // Zero-lock fast path: the common case (a burst of packets for one session)
    // allocates nothing and never touches the table. The memo's liveness check
    // is the same signal the table path uses (`JoinHandle::is_finished`) — one
    // atomic load — so a session whose reader has exited, aborted included,
    // still falls through and is recreated.
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, _) => {
            // Refresh liveness without the table lock; a session captured here is
            // scheduled by its reader and may be exiting, in which case one reply
            // is dropped and the next packet recreates it.
            touch_session_throttled(conn_id, s, &last);
            if let Some((h, p, d)) = dest {
                sess_dest_store(ss, s, h, p, d);
            }
            return Some(sock);
        }
        SessHit::Stale | SessHit::Miss => {}
    }
    // Fast path: single shard read + lock-free timestamp bump. A session whose
    // reply reader has already exited is treated as absent so its next packet
    // recreates it instead of black-holing.
    //
    // The read *blocks* rather than failing fast. Pass 21 made this a
    // `try_lock_read` that dropped the datagram on failure and counted it in
    // `SESSION_FULL`, reasoning that a packet path must never park a worker.
    // Pass 23 revisited that: the table is per-connection, so the only
    // cross-task writers are a session reader exiting (a `get` plus maybe a
    // `remove`), the 60 s sweeper's removal loop, and a DNS-spawned
    // `get_or_create_sess` -- all short, allocation-free critical sections. The
    // datagram reader is by far the commonest writer itself, so it cannot
    // contend with itself. Against that, the old behaviour silently dropped a
    // datagram every time any of those brief writers won the race, and charged
    // the drop to a counter documented as "budget exhausted", hiding relay loss
    // inside a resource-limit metric. `std::sync::RwLock::read` already tries
    // before it parks, so the uncontended cost is unchanged; only the drop is
    // gone.
    {
        let sh = ss.shard(s);
        let r = lock_read(sh);
        if let Some(e) = r.get(&s) {
            if !e.reader.is_finished() {
                let sock = e.sock.clone();
                touch_session_throttled(conn_id, s, &e.last);
                drop(r);
                if let Some((h, p, d)) = dest {
                    sess_dest_store(ss, s, h, p, d);
                }
                return Some(sock);
            }
        }
    }
    // No DATAGRAM support on this path: refuse before pinning a global permit,
    // a kernel socket and a reader task for a session whose replies would all
    // be dropped (`limit == 0` in the reader). Negotiated at the handshake, so
    // it never flaps mid-connection — and since a hit above can only be a
    // session that passed this check already, it stays off the per-packet path
    // instead of taking the connection-state lock for every datagram.
    cd.max_datagram_size()?;
    // Check the global pool BEFORE creating the socket: once every session slot
    // is held there is no point paying socket()+setsockopt()+bind() per packet.
    let permit = match session_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Throttled reap: per-worker 1/sec throttle (thread-local, no
            // cross-core CAS herd) instead of one global atomic.
            thread_local! {
                static LAST_SWEEP_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
            }
            let now = mono_millis();
            let due = LAST_SWEEP_MS.with(|c| {
                let last = c.get();
                if now.saturating_sub(last) < 1000 {
                    false
                } else {
                    c.set(now);
                    true
                }
            });
            if !due {
                dgram_drops::bump(&dgram_drops::SESSION_FULL);
                return None;
            }
            let evicted = ss.sweep_all(mono_millis());
            abort_evicted(evicted);
            match session_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    dgram_drops::bump(&dgram_drops::SESSION_FULL);
                    return None;
                }
            }
        }
    };
    // Create the socket outside the write lock: socket()/setsockopt()/bind()
    // are syscalls and must not stall the datagram reader for every session.
    let raw = udp_socket_dual_small("[::]:0").ok()?;
    let sock = Arc::new(tokio::net::UdpSocket::from_std(raw).ok()?);
    let c2_pre = cd.clone();
    let rs_pre = sock.clone();
    let ss_pre = ss.clone();
    let last_pre = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let h_pre = tokio::spawn(sess_reader_task(
        conn_id,
        s,
        rs_pre,
        ss_pre,
        c2_pre,
        last_pre.clone(),
    ));
    let reader_abort = h_pre.abort_handle();
    let mut stale_dead: Vec<SessEntry> = Vec::new();
    let mut swept: Vec<SessEntry> = Vec::new();
    let (inserted, memo_data) = {
        let sh = ss.shard(s);
        // Blocks for the same reason the read path does: a losing `try_lock_write`
        // used to abort the freshly spawned reader, release the global permit and
        // drop the datagram, which is strictly worse than waiting out a short
        // `HashMap` mutation. The socket syscalls above deliberately stay outside
        // this critical section.
        let mut w = lock_write(sh);
        if let Some(e) = w.get(&s) {
            if !e.reader.is_finished() {
                touch_session_throttled(conn_id, s, &e.last);
                let sock2 = e.sock.clone();
                drop(w);
                h_pre.abort();
                drop(permit);
                if let Some((h, p, d)) = dest {
                    sess_dest_store(ss, s, h, p, d);
                }
                return Some(sock2);
            }
            if let Some(e) = w.remove(&s) {
                stale_dead.push(e);
            }
        }
        // Per-connection cap is enforced on the owning shard; shards share the
        // cap evenly so no single shard lock ever scans the whole table.
        if w.len() >= LOCAL_SESS_MAX / SESS_SHARDS {
            swept = sweep_local(&mut w);
        }
        let dead = h_pre.is_finished();
        w.insert(
            s,
            SessEntry {
                sock: sock.clone(),
                reader: h_pre,
                last: last_pre.clone(),
                _permit: permit,
                dest: dest
                    .and_then(|(h, p, a)| Some((PortKey::new(h, p)?, a)))
                    .map_or(DestMemo::NONE, |(key, addr)| DestMemo {
                        key,
                        addr,
                        expires: mono_millis() + DEST_PIN_TTL_MS,
                    }),
            },
        );
        udp_stats::session();
        if dead || w.get(&s).map(|e| e.reader.is_finished()).unwrap_or(false) {
            if let Some(e) = w.remove(&s) {
                e.reader.abort();
            }
            (false, None)
        } else {
            (
                true,
                Some((sock.clone(), last_pre.clone(), reader_abort.clone())),
            )
        }
    };
    if let Some((msock, mlast, mabort)) = memo_data {
        sess_memo_put(conn_id, s, msock, mlast, mabort);
    }
    abort_evicted(stale_dead);
    abort_evicted(swept);
    if inserted {
        Some(sock)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(atyp: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![atyp];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn mqp_hdr_len_matches_each_wire_form() {
        assert_eq!(mqp_hdr_len(0x01, 0).unwrap(), 7);
        assert_eq!(mqp_hdr_len(0x04, 0).unwrap(), 19);
        assert_eq!(mqp_hdr_len(0x03, 1).unwrap(), 5);
        assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
        assert!(
            mqp_hdr_len(0x03, 0).is_err(),
            "empty domain must be refused"
        );
        assert!(
            mqp_hdr_len(0x02, 0).is_err(),
            "unknown atyp must be refused"
        );
    }

    /// The stack-buffer reader must consume exactly the bytes the framed header
    /// names, so the caller's stream position equals the pre-refactor one.
    #[test]
    fn mqp_header_roundtrip_v4_v6_and_domain() {
        for (hdr_bytes, want) in [
            (
                hdr(0x01, &[8, 8, 8, 8, 0, 53]),
                TargetAddr::Ip("8.8.8.8:53".parse().unwrap()),
            ),
            (
                hdr(0x04, &{
                    let mut b = [0u8; 18];
                    b[..16].copy_from_slice(
                        &"2001:4860:4860::8888"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    b[16..].copy_from_slice(&443u16.to_be_bytes());
                    b
                }),
                TargetAddr::Ip("[2001:4860:4860::8888]:443".parse().unwrap()),
            ),
            (
                hdr(0x03, &{
                    let d = b"example.com";
                    let mut b = vec![d.len() as u8];
                    b.extend_from_slice(d);
                    b.extend_from_slice(&8443u16.to_be_bytes());
                    b
                }),
                TargetAddr::Domain("example.com".into(), 8443),
            ),
        ] {
            let len = mqp_hdr_len(hdr_bytes[0], *hdr_bytes.get(1).unwrap_or(&0)).unwrap();
            assert_eq!(len, hdr_bytes.len(), "declared length must match the frame");
            let (got, used) = TargetAddr::decode(&hdr_bytes).unwrap();
            assert_eq!(used, hdr_bytes.len());
            assert_eq!(got, want);
        }
    }

    /// A domain header longer than the 255-byte wire limit must be refused by
    /// the length helper, never sliced into the fixed stack buffer.
    #[test]
    fn domain_wire_limit_is_enforced() {
        assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
        assert!(mqp_hdr_len(0x03, 0).is_err());
    }

    fn memo_sock() -> Arc<tokio::net::UdpSocket> {
        let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        s.set_nonblocking(true).unwrap();
        Arc::new(tokio::net::UdpSocket::from_std(s).unwrap())
    }

    /// A session destined for `addr`, inserted the way `get_or_create_sess`
    /// would insert it, so the destination memo can be exercised without a live
    /// QUIC connection.
    fn sess_with_dest(addr: Option<SocketAddr>) -> (SessTable, Arc<tokio::net::UdpSocket>) {
        let ss = Arc::new(ShardedSessTable::new());
        let sock = memo_sock();
        let last = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
        let h = tokio::spawn(std::future::pending::<()>());
        let permit = session_limiter().clone().try_acquire_owned().unwrap();
        ss.shard(7).write().unwrap().insert(
            7,
            SessEntry {
                sock: sock.clone(),
                reader: h,
                last,
                _permit: permit,
                dest: addr.map_or(DestMemo::NONE, |a| DestMemo {
                    key: PortKey::new("", 0).unwrap(),
                    addr: a,
                    expires: mono_millis() + DEST_PIN_TTL_MS,
                }),
            },
        );
        (ss, sock)
    }

    /// The per-datagram path, before this change, re-resolved a domain target
    /// for *every* datagram: a hash, a key build and a full key compare per
    /// packet, forever. The session's own memo is what removes that, so the
    /// properties that keep it safe are asserted here.
    #[tokio::test]
    async fn session_dest_memo_round_trips_and_expires() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);

        // A fresh session has pinned nothing: the datagram path must resolve.
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);

        sess_dest_store(&ss, 7, "a.test", 443, dst);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443),
            Some(dst),
            "a stored destination must be reused"
        );

        // Past the pin's TTL the answer must go back through the resolver, or a
        // name that moves would keep the session pointed at a dead address for
        // the session's whole idle lifetime.
        let past = mono_millis() + DEST_PIN_TTL_MS + 1;
        assert_eq!(sess_dest_lookup(&ss, past, 7, "a.test", 443), None);

        // A different session number must never see another session's pin.
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 8, "a.test", 443), None);
    }

    /// The datagram path stores this memo for every domain-target packet, so the
    /// store must cost a read lock — not a write — whenever the answer has not
    /// changed. A redundant write per packet was measurable (35 ns of exclusive
    /// shard lock plus a dirty line in the shared table) and a redundant
    /// *refresh* is what the refresh window exists to avoid.
    #[tokio::test]
    async fn session_dest_store_writes_only_when_the_memo_needs_it() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let moved: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);
        let expires = || ss.shard(7).read().unwrap().get(&7).unwrap().dest.expires;

        sess_dest_store(&ss, 7, "alpha.test", 443, dst);
        let first = expires();
        assert!(first > mono_millis(), "a store must leave a live memo");
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(dst)
        );

        // Same name, same address, TTL still fresh: nothing to write.
        sess_dest_store(&ss, 7, "alpha.test", 443, dst);
        assert_eq!(
            expires(),
            first,
            "a redundant store must not rewrite (and so must not take the write lock)"
        );

        // Same name, new address: the memo must follow it.
        sess_dest_store(&ss, 7, "alpha.test", 443, moved);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(moved)
        );

        // Inside the refresh window the value is unchanged but the life is not:
        // that one must rewrite, or the entry would expire and the next packet
        // would pay a full resolve.
        ss.shard(7)
            .write()
            .unwrap()
            .get_mut(&7)
            .unwrap()
            .dest
            .expires = mono_millis() + 1;
        sess_dest_store(&ss, 7, "alpha.test", 443, moved);
        assert!(
            expires() > mono_millis() + DEST_PIN_REFRESH_MS,
            "a memo inside the refresh window must be refreshed"
        );
    }

    /// The bug this memo was rewritten for: a session is not bound to one
    /// target, so a memo keyed on the session alone answered a datagram naming
    /// B with the address resolved for A and relayed it to the wrong host.
    /// Verified end to end with `hotpath_bench udpdomainswitch`, which caught
    /// exactly this (1000 of 2000 datagrams misrouted) before the name became
    /// part of the key.
    #[tokio::test]
    async fn session_dest_memo_is_keyed_on_the_target_name() {
        let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);
        sess_dest_store(&ss, 7, "alpha.test", 443, a);

        // Same session, different name: must not answer with alpha's address.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "beta.test", 443),
            None
        );
        // Same session, same name, different port: likewise.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 80),
            None
        );
        // The name it was stored for still hits.
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
            Some(a)
        );

        // A name sharing a prefix must not match a shorter stored name.
        sess_dest_store(&ss, 7, "alpha.test", 443, b);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test.", 443),
            None
        );
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "alpha.tes", 443),
            None
        );
    }

    /// An IP target has no name to re-check, and must not be confused with a
    /// domain whose name happens to be empty or to share the port.
    #[tokio::test]
    async fn session_dest_memo_distinguishes_ip_and_domain_targets() {
        let ip_target: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let domain_target: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        let (ss, _sock) = sess_with_dest(None);

        // An IP target stores the empty host.
        sess_dest_store(&ss, 7, "", 9999, ip_target);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "", 9999),
            Some(ip_target)
        );
        // A domain target on the same session replaces it, and the IP-form
        // query must then miss rather than get the domain's address.
        sess_dest_store(&ss, 7, "gamma.test", 9999, domain_target);
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "", 9999), None);
        assert_eq!(
            sess_dest_lookup(&ss, mono_millis(), 7, "gamma.test", 9999),
            Some(domain_target)
        );
    }

    /// A name too long for the inline key must not be memoized at all: storing
    /// it truncated would let a different name sharing the prefix match it.
    #[tokio::test]
    async fn session_dest_memo_refuses_names_it_cannot_key() {
        let (ss, _sock) = sess_with_dest(None);
        let long = "x".repeat(DEST_KEY_BYTES + 1);
        sess_dest_store(&ss, 7, &long, 443, "10.0.0.1:443".parse().unwrap());
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &long, 443), None);
        // A name sharing that prefix must miss too.
        let prefix = "x".repeat(DEST_KEY_BYTES);
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &prefix, 443), None);
    }

    /// Storing into a session that no longer exists is a no-op, not a panic or a
    /// phantom entry: the datagram path races session teardown by design.
    #[tokio::test]
    async fn session_dest_store_tolerates_a_vanished_session() {
        let ss = Arc::new(ShardedSessTable::new());
        sess_dest_store(&ss, 7, "a.test", 443, "10.0.0.1:1".parse().unwrap());
        assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);
    }

    /// A reader that stays alive (`SessHit::Fresh` requires a running task).
    fn live_reader() -> tokio::task::AbortHandle {
        let h = tokio::spawn(std::future::pending::<()>());
        let abort = h.abort_handle();
        drop(h);
        abort
    }

    /// Session ids are allocated per client and every client hub counts from 1,
    /// so two connections whose DATAGRAM readers share one worker thread
    /// routinely carry the same sess id. The memo is a single thread-local
    /// slot, so matching on `sess` alone served one connection's socket to the
    /// other — its datagrams then went out on the wrong session and the replies
    /// came back on the wrong QUIC connection.
    #[tokio::test]
    async fn session_memo_never_crosses_connections() {
        use std::sync::atomic::AtomicU64;

        let a = memo_sock();
        let b = memo_sock();
        let last = Arc::new(AtomicU64::new(1));

        sess_memo_put(1, 7, a.clone(), last.clone(), live_reader());
        assert!(matches!(sess_memo_lookup(2, 7), SessHit::Miss));
        match sess_memo_lookup(1, 7) {
            SessHit::Fresh(s, _, _) => assert!(Arc::ptr_eq(&s, &a)),
            _ => panic!("the owning connection must still hit"),
        }
        assert!(matches!(sess_memo_lookup(1, 8), SessHit::Miss));

        sess_memo_forget(2, 7);
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Fresh(..)));
        sess_memo_forget(1, 7);
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));

        sess_memo_put(2, 7, b.clone(), last, live_reader());
        assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));
        match sess_memo_lookup(2, 7) {
            SessHit::Fresh(s, _, _) => assert!(Arc::ptr_eq(&s, &b)),
            _ => panic!("connection 2 must see its own socket"),
        }
    }

    /// The sweeper and a connection close abort a session's reader, which then
    /// never reaches the cleanup after its loop — so the memo must learn that
    /// the reader is gone from the task handle itself, or it keeps handing out
    /// a socket nobody reads.
    #[tokio::test]
    async fn session_memo_ignores_finished_readers() {
        use std::sync::atomic::AtomicU64;

        let last = Arc::new(AtomicU64::new(1));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let h = tokio::spawn(async move {
            let _ = rx.await;
        });
        let finished = h.abort_handle();
        drop(tx);
        h.await.unwrap();
        assert!(finished.is_finished());
        sess_memo_put(3, 1, memo_sock(), last.clone(), finished);
        assert!(matches!(sess_memo_lookup(3, 1), SessHit::Stale));

        let h = tokio::spawn(std::future::pending::<()>());
        let aborted = h.abort_handle();
        h.abort();
        while !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
        sess_memo_put(4, 1, memo_sock(), last, aborted);
        assert!(matches!(sess_memo_lookup(4, 1), SessHit::Stale));
    }

    /// Security regression: after every cache slot has been written (and
    /// evicted at least once), the memo must still agree with `is_global_ip`
    /// for the whole filter table. A wrong `true` would let a peer dial
    /// private/loopback/link-local/CGNAT space.
    #[test]
    fn ip_cache_matches_predicate_after_full_fill() {
        for i in 0..200u8 {
            let _ = is_global_ip_cached(IpAddr::V4(Ipv4Addr::new(8, 8, 8, i)));
        }
        for i in 0..200u16 {
            let ip: IpAddr = format!("2001:4860::{i:x}").parse().unwrap();
            let _ = is_global_ip_cached(ip);
        }

        let cases = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "::1",
            "169.254.1.1",
            "fe80::1",
            "100.64.0.1",
            "64:ff9b::a00:1",
            "192.0.2.1",
            "2001:db8::1",
            "198.18.0.1",
            "224.0.0.1",
            "ff02::1",
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
        ];
        for s in cases {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(
                is_global_ip_cached(ip),
                is_global_ip(ip),
                "memo verdict diverged from is_global_ip for {s}"
            );
        }
    }

    /// A collision must evict, never mis-serve: two addresses sharing one slot
    /// but carrying opposite verdicts must each return the predicate's answer,
    /// in both probe orders.
    #[test]
    fn ip_cache_collision_evicts_and_never_mis_serves() {
        use std::collections::HashMap;

        // Non-global `0.0.0.0/8` candidates against global `8.8.0.0/16`
        // candidates; 1024 of each over 64 slots guarantees a cross-verdict
        // same-index pair.
        let non_global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::from(i)));
        let global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::new(8, 8, (i >> 8) as u8, i as u8)));

        let mut seen: HashMap<usize, IpAddr> = HashMap::new();
        let mut pair = None;
        for ip in non_global.chain(global) {
            let idx = ip_cache_idx(ip);
            match seen.get(&idx) {
                Some(&other) if is_global_ip(other) != is_global_ip(ip) => {
                    pair = Some((other, ip));
                    break;
                }
                Some(_) => {}
                None => {
                    seen.insert(idx, ip);
                }
            }
        }
        let (a, b) = pair.expect("two verdict classes over 64 slots must collide");
        assert_eq!(ip_cache_idx(a), ip_cache_idx(b));
        assert_ne!(is_global_ip(a), is_global_ip(b));

        assert_eq!(is_global_ip_cached(a), is_global_ip(a));
        assert_eq!(is_global_ip_cached(b), is_global_ip(b));
        assert_eq!(is_global_ip_cached(a), is_global_ip(a));
    }
}
