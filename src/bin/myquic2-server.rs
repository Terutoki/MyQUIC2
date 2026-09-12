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

type SessEntry = (
    Arc<tokio::net::UdpSocket>,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicU64>,
    tokio::sync::OwnedSemaphorePermit,
);
type SessTable = Arc<std::sync::RwLock<HashMap<u32, SessEntry>>>;

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
    if !c.auth_token.is_empty() {
        info!("client token authentication enabled");
    } else {
        warn!("auth_token is empty: the QUIC endpoint accepts any peer (rely on firewall/network isolation)");
    }
    let auth_token = Arc::new(c.auth_token.clone().into_bytes());
    let auth_enabled = !auth_token.is_empty();
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let pending_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UNAUTH_CONNECTIONS));
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
                    Ok((c, accepted)) => {
                        // A server-side `into_0rtt` always succeeds (0.5-RTT), but
                        // an unfinished handshake must not hold the connection
                        // permit; wait (bounded) for the handshake before
                        // consuming the token. The client already waits for the
                        // 0-RTT decision, so this costs it no latency.
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepted).await {
                            Ok(_) => c,
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

async fn handle_conn(conn: quinn::Connection, allow_private: bool) -> Result<()> {
    info!("new QUIC conn from {}", conn.remote_address());
    // One UDP socket per sess_id: replies are inherently demuxed, concurrent
    // ASSOCIATEs sharing this QUIC connection never cross-talk.
    let sess: SessTable = Arc::new(std::sync::RwLock::new(HashMap::new()));
    {
        let sess = sess.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = mono_millis();
                        let mut m = lock_write(&sess);
                        let expired: Vec<u32> = m
                            .iter()
                            .filter(|(_, (_, _, t, _))| {
                                now.saturating_sub(t.load(std::sync::atomic::Ordering::Relaxed))
                                    >= SESS_IDLE_MS
                            })
                            .map(|(k, _)| *k)
                            .collect();
                        for k in expired {
                            if let Some((_, h, _, _)) = m.remove(&k) {
                                h.abort();
                            }
                        }
                    }
                    _ = conn.closed() => {
                        let mut m = lock_write(&sess);
                        for (_, (_, h, _, _)) in m.drain() {
                            h.abort();
                        }
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
        loop {
            let d: Bytes = match reader.as_mut().await {
                Ok(d) => d,
                Err(_) => break,
            };
            // Keep an owned handle so the payload can be handed to the send
            // path as a zero-copy `Bytes::slice` (instead of a per-packet
            // copy) even after `decode_datagram_ref` borrowed `d`.
            let owned = d.clone();
            let (s, addr, payload) = match decode_datagram_ref(&d) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let payload_off = owned.len() - payload.len();
            match addr {
                TargetAddrRef::Ip(dst) => {
                    if !allow_private && !is_global_ip(dst.ip()) {
                        continue;
                    }
                    let sock = match get_or_create_sess(&ss, &cd, s).await {
                        Some(v) => v,
                        None => continue,
                    };
                    // Non-blocking send with bounded detached fallback: a full
                    // target buffer must never stall the single per-connection
                    // datagram reader (UDP loss is acceptable).
                    udp_try_send(&sock, map_for_dual(dst), owned.slice(payload_off..));
                }
                TargetAddrRef::Domain(h, p) => {
                    // Fast path: cached DNS avoids a per-packet spawn; a fresh
                    // negative entry avoids even that (the old fast path only
                    // consulted the positive cache, so every packet for a bad
                    // domain spawned a resolver task just to fail).
                    match lookup_cached_fast(h, p) {
                        CachedLookup::Negative => continue,
                        CachedLookup::Addr(dst) => {
                            if !allow_private && !is_global_ip(dst.ip()) {
                                continue;
                            }
                            let sock = match get_or_create_sess(&ss, &cd, s).await {
                                Some(v) => v,
                                None => continue,
                            };
                            udp_try_send(&sock, map_for_dual(dst), owned.slice(payload_off..));
                        }
                        CachedLookup::Unknown => {
                            let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            let ss = ss.clone();
                            let cd = cd.clone();
                            let payload = owned.slice(payload_off..);
                            let host = h.to_string();
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
                                let sock = match get_or_create_sess(&ss, &cd, s).await {
                                    Some(v) => v,
                                    None => return,
                                };
                                udp_try_send(&sock, map_for_dual(dst), payload);
                            });
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
                            let k = v.len().min(dns_cand.len());
                            dns_cand[..k].copy_from_slice(&v[..k]);
                            k
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
            let (pump, diag) = copy_tcp_quic_idle(tcp, send, recv, Duration::from_secs(300)).await;
            // Reported on both outcomes: a long s2c read gap (the app not
            // draining the stream) is what lets quinn's reassembly spans pile
            // up towards the MAX_CHUNKS cap that kills the connection.
            if diag.is_significant() {
                tracing::warn!("tcp {target:?} {}", diag.summary());
            }
            match pump {
                Ok((up, down)) => {
                    tracing::debug!("tcp {target:?} clean fin: {up}B up/{down}B down");
                }
                Err(e) => {
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

/// Throttled liveness bump: readers only need ~1s resolution for the sweeper,
/// so avoid a store per packet (stores bounce cache lines between cores).
fn touch_session(t: &std::sync::atomic::AtomicU64) {
    let now = mono_millis();
    let prev = t.load(std::sync::atomic::Ordering::Relaxed);
    if now.saturating_sub(prev) >= 1000 {
        t.store(now, std::sync::atomic::Ordering::Relaxed);
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
    for (k, (_, _, t, _)) in w.iter() {
        if now.saturating_sub(t.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS {
            expired.push(*k);
        }
    }
    let mut evicted: Vec<SessEntry> = Vec::with_capacity(expired.len());
    for k in expired {
        if let Some(e) = w.remove(&k) {
            evicted.push(e);
        }
    }
    let over = w.len().saturating_sub(LOCAL_SESS_TARGET);
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
    for (_, h, _, _) in evicted {
        h.abort();
    }
}

/// Per-connection memo of the most recently used session socket.
///
/// A datagram-heavy flow sends a long run of packets to the *same* session, so
/// the connection-level `RwLock` read plus hash lookup in `get_or_create_sess`
/// is pure per-packet overhead for all but the first packet of the run. The
/// memo is a single slot on purpose: a miss simply falls through to the table,
/// and a stale hit can only ever send one reply to a socket whose reader has
/// already exited (never to the wrong target), because entries are keyed by
/// session id and the reader holds its own `Arc` to keep the fd alive.
struct SessMemo {
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    /// The session table's liveness stamp, kept so a memo hit can refresh it
    /// without re-taking the table lock.
    last: Arc<std::sync::atomic::AtomicU64>,
    /// Cleared by the reply reader as it exits, which turns this slot back into
    /// a miss for the next packet addressed to `sess`.
    alive: Arc<std::sync::atomic::AtomicBool>,
}

thread_local! {
    static SESS_MEMO: std::cell::RefCell<Option<SessMemo>> =
        const { std::cell::RefCell::new(None) };
}

/// Remember `sock` as the memoized session, unless a newer session already is.
fn sess_memo_put(
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    last: Arc<std::sync::atomic::AtomicU64>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    SESS_MEMO.with(|c| {
        *c.borrow_mut() = Some(SessMemo {
            sess,
            sock,
            last,
            alive,
        })
    });
}

/// Drop the memo when it still points at `sess`. Called by a reply reader as it
/// exits, so the next inbound packet for that session recreates it instead of
/// sending into a socket nobody reads.
fn sess_memo_forget(sess: u32) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        if m.as_ref().is_some_and(|e| e.sess == sess) {
            *m = None;
        }
    });
}

/// Per-thread view of the last liveness refresh, so the throttling decision
/// costs no clock read. A `(session, ms)` pair is enough: it is only ever
/// compared against the session it belongs to.
struct TouchMemo {
    sess: u32,
    ms: u64,
}

thread_local! {
    static TOUCH_MEMO: std::cell::RefCell<Option<TouchMemo>> =
        const { std::cell::RefCell::new(None) };
}

/// Refresh `last` at most once per [`TOUCH_INTERVAL_MS`], using a thread-local
/// copy of the last refresh time and session id.
///
/// The memo hit path used to keep a session alive implicitly (it re-took the
/// table lock and called `touch_session` on every packet). Skipping the table
/// must not change that: an outbound-only flow would be reaped by the sweeper at
/// its idle deadline and immediately recreated, churning a socket per flow every
/// 180 s. The clock read stays on the hot path only in the sense that it decides
/// whether to store — a `clock_gettime` is an order of magnitude cheaper than the
/// hash lookup and hash-map read lock this replaced.
fn touch_session_throttled(sess: u32, last: &std::sync::atomic::AtomicU64) {
    const TOUCH_INTERVAL_MS: u64 = 1000;
    let now = mono_millis();
    let due = TOUCH_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        match c.as_ref() {
            Some(m) if m.sess == sess => {
                if now.saturating_sub(m.ms) >= TOUCH_INTERVAL_MS {
                    *c = Some(TouchMemo { sess, ms: now });
                    true
                } else {
                    false
                }
            }
            _ => {
                *c = Some(TouchMemo { sess, ms: now });
                true
            }
        }
    });
    if due {
        last.store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    s: u32,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Zero-lock fast path: the common case (a burst of packets for one session)
    // allocates nothing and never touches the table. `alive` is the same signal
    // the old table lookup used (`JoinHandle::is_finished`) — an atomic load —
    // so a session whose reader has exited still falls through and is recreated.
    use std::sync::atomic::Ordering;
    enum Hit {
        Miss,
        Fresh(Arc<tokio::net::UdpSocket>),
        /// The memo's reader has exited: the table (not the memo) must decide,
        /// so this falls through and lets the table path recreate the session.
        Stale,
    }
    let hit = SESS_MEMO.with(|c| {
        let m = c.borrow();
        match m.as_ref().filter(|e| e.sess == s) {
            Some(e) if e.alive.load(Ordering::Relaxed) => Hit::Fresh(e.sock.clone()),
            Some(_) => Hit::Stale,
            None => Hit::Miss,
        }
    });
    match hit {
        Hit::Fresh(sock) => {
            // Refresh liveness without the table lock; a session captured here is
            // scheduled by its reader and may be exiting, in which case one reply
            // is dropped and the next packet recreates it.
            SESS_MEMO.with(|c| {
                if let Some(e) = c.borrow().as_ref().filter(|e| e.sess == s) {
                    touch_session_throttled(s, &e.last);
                }
            });
            return Some(sock);
        }
        Hit::Stale | Hit::Miss => {}
    }
    // Fast path: single read lock + lock-free timestamp bump. No write lock
    // per packet, so concurrent sessions never serialize on a global lock.
    // A session whose reply reader has already exited is treated as absent so
    // its next packet recreates it instead of black-holing replies. This path
    // deliberately does not populate the memo: the memo's liveness flag belongs
    // to the reader that this path did not create, and a second flag set by
    // nobody would pin a dead session forever.
    {
        let r = lock_read(ss);
        if let Some((sock, h, t, _)) = r.get(&s) {
            if !h.is_finished() {
                let sock = sock.clone();
                touch_session(t);
                return Some(sock);
            }
        }
    }
    // Check the global pool BEFORE creating the socket: once every session slot
    // is held there is no point paying socket()+setsockopt()+bind() per packet.
    let permit = match session_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Reap expired/over-cap sessions, then retry once. Aborts happen
            // after the lock is dropped (the guard is a temporary in this
            // statement, and `abort_evicted` runs once it is gone).
            let evicted = sweep_local(&mut lock_write(ss));
            abort_evicted(evicted);
            match session_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => return None,
            }
        }
    };
    // Create the socket outside the write lock: socket()/setsockopt()/bind()
    // are syscalls and must not stall the datagram reader for every session.
    let raw = udp_socket_dual_small("[::]:0").ok()?;
    let sock = Arc::new(tokio::net::UdpSocket::from_std(raw).ok()?);
    // Shared with the memo so a reader exit invalidates it without touching the
    // table.
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let alive_reader = alive.clone();
    let evicted;
    // Slow path holds the write lock across check+insert so concurrent
    // packets for the same sess cannot create duplicate sockets (B8).
    {
        let mut w = lock_write(ss);
        if let Some((sock2, h2, t, _)) = w.get(&s) {
            if !h2.is_finished() {
                touch_session(t);
                let sock2 = sock2.clone();
                drop(w);
                return Some(sock2);
            }
            // Dead reader: replace it (dropping the stale entry releases its
            // permit).
            if let Some((_, hh, _, _)) = w.remove(&s) {
                hh.abort();
            }
        }
        if w.len() >= LOCAL_SESS_MAX {
            evicted = sweep_local(&mut w);
        } else {
            evicted = Vec::new();
        }
        let c2 = cd.clone();
        let rs = sock.clone();
        let ss2 = ss.clone();
        let last = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
        let last2 = last.clone();
        let h = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut buf = vec![0u8; 2048];
            // quinn's `max_datagram_size()` takes the connection-state mutex that
            // the protocol driver also uses; never call it per datagram. 0 means
            // the peer does not support QUIC DATAGRAM (replies are then dropped).
            let mut limit = c2.max_datagram_size().map(|m| m.min(1350)).unwrap_or(0);
            // Monotonic ms of the last liveness bump. The atomic is the cross-task
            // view; this copy is what the per-packet comparison uses, so the fast
            // path below never reads a clock.
            let mut last_touch = 0u64;
            loop {
                let (n, src) = tokio::select! {
                    r = rs.recv_from(&mut buf) => match r {
                        Ok(x) => x,
                        // Socket error: exit; the entry is reaped below and the
                        // next packet for this session recreates it.
                        Err(_) => break,
                    },
                    // One fixed 60s tick instead of a fresh 60s timeout per
                    // recv_from (which re-registered a timer for every inbound
                    // packet). The reap decision uses the shared last-activity
                    // stamp, so coarse granularity is sufficient.
                    _ = tick.tick() => {
                        if c2.close_reason().is_some()
                            || mono_millis()
                                .saturating_sub(last2.load(std::sync::atomic::Ordering::Relaxed))
                                >= SESS_IDLE_MS
                        {
                            break;
                        }
                        limit = c2.max_datagram_size().map(|m| m.min(1350)).unwrap_or(0);
                        continue;
                    }
                };
                // Inbound replies are liveness too: a long one-way download must
                // not be reaped while it is actively streaming. The sweeper only
                // needs ~1s resolution, so the clock is read at most once per
                // second instead of once per reply.
                let now = mono_millis();
                if now.saturating_sub(last_touch) >= 1000 {
                    last_touch = now;
                    last2.store(now, std::sync::atomic::Ordering::Relaxed);
                }
                if n == buf.len() || limit == 0 {
                    continue;
                }
                let src = SocketAddr::new(unmap(src.ip()), src.port());
                let d = match encode_datagram_with_limit(s, &TargetAddr::Ip(src), &buf[..n], limit)
                {
                    Some(d) => d,
                    None => continue,
                };
                // `try_send_datagram` (never quinn's `send_datagram`): a full send
                // buffer drops the datagram instead of triggering quinn-proto's
                // broken drop-oldest path, which underflows its byte accounting and
                // aborts the process (see the helper's docs).
                match try_send_datagram(&c2, d) {
                    DatagramSend::Sent => {}
                    DatagramSend::Blocked => {
                        // Buffer full: UDP semantics, drop this reply.
                    }
                    DatagramSend::TooLarge => {
                        // Path MTU shrank: refresh once, drop this packet.
                        limit = c2.max_datagram_size().map(|m| m.min(1350)).unwrap_or(0);
                    }
                    DatagramSend::Unsupported | DatagramSend::ConnectionLost => break,
                }
            }
            // Reader is gone: invalidate the memo slot so the next packet for
            // this session takes the table path and recreates it, rather than
            // sending a reply into a socket nobody is reading.
            alive_reader.store(false, std::sync::atomic::Ordering::Relaxed);
            sess_memo_forget(s);
            // Self-reap: task exit removes the zombie entry (and releases its
            // permit) instead of waiting for the 60s sweeper. Do NOT abort our own
            // JoinHandle: this task is already exiting and abort() has no effect
            // until an await point that no longer exists.
            let mut w = lock_write(&ss2);
            if let Some((cur, _, _, _)) = w.get(&s) {
                if Arc::ptr_eq(cur, &rs) {
                    w.remove(&s);
                }
            }
        });
        let dead = !alive.load(std::sync::atomic::Ordering::Relaxed);
        w.insert(s, (sock.clone(), h, last.clone(), permit));
        // The reader may have exited before the insert (e.g. immediate socket
        // error); its self-reap ran too early, so remove the dead entry here
        // instead of leaving it to hold a permit until the 180s sweep.
        if dead
            || w.get(&s)
                .map(|(_, hh, _, _)| hh.is_finished())
                .unwrap_or(false)
        {
            w.remove(&s);
        } else {
            // Memoize only a session that is actually alive; a memo hit then
            // costs one atomic load instead of a table lock per packet.
            sess_memo_put(s, sock.clone(), last.clone(), alive);
        }
    }
    abort_evicted(evicted);
    Some(sock)
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
}
