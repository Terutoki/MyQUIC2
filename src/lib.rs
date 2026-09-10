//! MyQUIC2 common: MQP-1 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

// ---------------- Address codec (MQP-1) ----------------
// wire: atyp u8 | addr | port u16 BE ; atyp: 0x01 v4, 0x04 v6, 0x03 domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            TargetAddr::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v4");
                }
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v6");
                }
                if a.scope_id() != 0 {
                    anyhow::bail!("v6 scope_id dropped on wire, refuse scoped addr");
                }
                out.push(0x04);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddr::Domain(d, p) => {
                let bytes = d.as_bytes();
                if bytes.is_empty() {
                    anyhow::bail!("empty domain");
                }
                if bytes.len() > 255 {
                    anyhow::bail!("domain too long");
                }
                let n = bytes.len();
                out.push(0x03);
                out.push(n as u8);
                out.extend_from_slice(&bytes[..n]);
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        if b.is_empty() {
            anyhow::bail!("empty addr");
        }
        let atyp = b[0];
        match atyp {
            0x01 => {
                if b.len() < 7 {
                    anyhow::bail!("short v4");
                }
                let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
                if ip.is_unspecified() {
                    anyhow::bail!("refuse unspecified v4 target");
                }
                let port = u16::from_be_bytes([b[5], b[6]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip, port)), 7))
            }
            0x04 => {
                if b.len() < 19 {
                    anyhow::bail!("short v6");
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[1..17]);
                let ip = IpAddr::from(o);
                if ip.is_unspecified() {
                    anyhow::bail!("refuse unspecified v6 target");
                }
                let port = u16::from_be_bytes([b[17], b[18]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip, port)), 19))
            }
            0x03 => {
                if b.len() < 2 {
                    anyhow::bail!("short domain");
                }
                let n = b[1] as usize;
                if n == 0 {
                    anyhow::bail!("bad domain len");
                }
                if b.len() < 2 + n + 2 {
                    anyhow::bail!("short domain body");
                }
                let d = std::str::from_utf8(&b[2..2 + n])
                    .context("bad domain utf8")?
                    .to_owned();
                let port = u16::from_be_bytes([b[2 + n], b[3 + n]]);
                Ok((TargetAddr::Domain(d, port), 4 + n))
            }
            _ => anyhow::bail!("bad atyp {atyp}"),
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            TargetAddr::Ip(s) => Some(*s),
            _ => None,
        }
    }
}

/// MQP-1 TCP open acknowledgement (server -> client, 1 byte).
/// Both sides must run the same version: the client MUST wait for exactly
/// this byte and fail the flow otherwise. There is intentionally NO silent
/// fallback for old peers — falling back would let the first application
/// byte be mistaken for (or polluted by) the ACK (see B1).
pub const MQP_TCP_ACK: u8 = 0x00;

/// Build a UDP DATAGRAM body: type + sess + addr header + payload.
/// sess scopes the packet to one UDP ASSOCIATE so concurrent associations sharing
/// a QUIC connection never steal each other's replies. Returns None if exceeds limit.
pub fn encode_datagram(sess: u32, addr: &TargetAddr, payload: &[u8]) -> Option<Bytes> {
    encode_datagram_with_limit(sess, addr, payload, 1350)
}

pub fn encode_datagram_with_limit(
    sess: u32,
    addr: &TargetAddr,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let mut v = Vec::with_capacity(40 + payload.len());
    v.push(0x02);
    v.extend_from_slice(&sess.to_le_bytes());
    if addr.encode(&mut v).is_err() {
        return None;
    }
    if v.len() + payload.len() > limit {
        return None;
    }
    v.extend_from_slice(payload);
    Some(Bytes::from(v))
}

pub fn decode_datagram(b: &[u8]) -> Result<(u32, TargetAddr, &[u8])> {
    if b.len() < 6 || b[0] != 0x02 {
        anyhow::bail!("bad dgram");
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (a, n) = TargetAddr::decode(&b[5..])?;
    Ok((sess, a, &b[5 + n..]))
}

// ---------------- Config files ----------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConf {
    pub listen: String,      // e.g. 0.0.0.0:8443
    pub cert_file: String,   // server cert PEM (self-signed)
    pub key_file: String,    // server key PEM
    pub server_name: String, // e.g. myquic2, used for self-sign SAN + SNI
    #[serde(default = "d_bbr")]
    pub congestion: String, // bbr | cubic
    #[serde(default = "d_true")]
    pub gso: bool, // informational: quinn-udp auto-enables; false = log warn only
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_false")]
    pub allow_private: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConf {
    pub socks_listen: String,     // e.g. 127.0.0.1:1080
    pub server_addr: String,      // e.g. 127.0.0.1:8443
    pub server_name: String,      // SNI, must match cert SAN
    pub server_cert_file: String, // pinned self-signed cert PEM
    #[serde(default = "d_bbr")]
    pub congestion: String,
    #[serde(default = "d_true")]
    pub gso: bool,
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_5")]
    pub reconnect_timeout_secs: u64,
}
fn d_bbr() -> String {
    "bbr".into()
}
fn d_true() -> bool {
    true
}
fn d_false() -> bool {
    false
}
fn d_keepalive() -> u64 {
    5
}
fn d_5() -> u64 {
    5
}

pub fn load_toml<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    Ok(toml::from_str(&s)?)
}

// ---------------- Self-signed cert (TLS1.3 + AES-128-GCM fastest) ----------------
/// Generate self-signed cert for `san`, save PEM files, return (cert_pem, key_pem).
/// Algorithm: Ed25519 (fastest sign/verify, smallest cert). Validity: 500 years,
/// backdated 7 days so devices without a battery clock (NTP not yet synced at
/// first boot) never fail with "certificate not valid yet".
pub fn gen_self_signed_files(san: &str, cert_path: &str, key_path: &str) -> Result<()> {
    let mut params = rcgen::CertificateParams::new(vec![san.to_string()])?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(7);
    params.not_after = now + time::Duration::days(500 * 365);
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = params.self_signed(&key_pair)?;
    std::fs::write(cert_path, cert.pem()).context("write cert")?;
    std::fs::write(key_path, key_pair.serialize_pem()).context("write key")?;
    Ok(())
}

pub fn load_cert_der(pem_path: &str) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(pem_path)?);
    let v: Vec<_> = rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?;
    v.into_iter().next().context("no cert in file")
}

pub fn load_key_der(pem_path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(pem_path)?);
    rustls_pemfile::private_key(&mut r)?.context("no key in file")
}

/// Server TLS: TLS1.3 only (QUIC mandates it; single version = min handshake RTT).
/// Cipher: ring default negotiates AES-128-GCM first on AES-NI => fastest path.
pub fn server_tls_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![b"myquic2/1".to_vec()];
    // KEEP rustls' default ticketer (NeverProducesTickets): that selects STATEFUL
    // resumption via the in-memory session store, which is the only mode where
    // rustls accepts 0-RTT early data (RFC8446 8.1 anti-replay rule).
    // Accept QUIC 0-RTT early data on resumption. quinn requires exactly 0 or u32::MAX here.
    // Replay caveat: tickets are single-use and short-lived; worst case is a duplicated
    // outbound dial, no amplification.
    // quinn-0.11 hard-requires 0 or u32::MAX here (panics otherwise), so the
    // bound cannot be lowered at this layer; replay exposure is limited by
    // single-use short-lived tickets instead.
    cfg.max_early_data_size = u32::MAX;
    Ok(Arc::new(cfg))
}

/// Client TLS: pin exact self-signed cert, no WebPKI roots (skip chain building => min RTT/CPU).
pub fn client_tls_config(
    pinned: rustls::pki_types::CertificateDer<'static>,
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pinned)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"myquic2/1".to_vec()];
    cfg.enable_early_data = true; // allow QUIC 0-RTT on resumption
    Ok(Arc::new(cfg))
}

// ---------------- QUIC transport: BBR + DATAGRAM + keepalive ----------------
pub fn parse_congestion(name: &str) -> bool {
    name.eq_ignore_ascii_case("cubic") || name.eq_ignore_ascii_case("bbr")
}

pub fn build_transport(congestion: &str, keep_alive_secs: u64) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // BBR default; cubic only as escape hatch. Unknown values warn (B9) and use BBR.
    if congestion.eq_ignore_ascii_case("cubic") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    } else {
        if !congestion.eq_ignore_ascii_case("bbr") {
            tracing::warn!(
                "unknown congestion={congestion:?}, using bbr (want bbr|cubic)"
            );
        }
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    // GSO/GRO: no flag in quinn API — quinn-udp auto-probes UDP_SEGMENT/UDP_GRO.
    // Bounded buffers: 4MB datagram buffers cover high-RTT BDP (~3.5MB) while
    // halving per-connection memory vs 8MB (100 server-side conns ≈ 800MB→400MB).
    t.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    t.datagram_send_buffer_size(4 * 1024 * 1024);
    // 1024 concurrent streams cover high-concurrency tests with margin while bounding
    // worst-case flow-control memory (4MB window each).
    t.max_concurrent_bidi_streams(1024u32.into());
    t.max_concurrent_uni_streams(100u32.into());
    // 140ms trans-Pacific at 200Mb/s needs ~3.5MB BDP; 4MB per-stream window
    // covers it, and the 8MB connection window still allows two fast streams
    // in parallel without pinning tens of MB per connection.
    t.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
    t.send_window(8 * 1024 * 1024);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs.max(1))));
    // Idle timeout derives from keepalive so custom keep_alive_secs can never
    // self-kill a healthy connection: idle must stay well above the keepalive
    // interval (QUIC requires inbound traffic before idle fires). 15s floor
    // preserves the old silent-blackhole bound; larger keepalives scale up.
    let idle_secs = (keep_alive_secs.max(1).saturating_mul(3)).max(15);
    t.max_idle_timeout(Some(
        Duration::from_secs(idle_secs).try_into().unwrap(),
    ));
    // NOTE: quinn-udp auto-probes GSO/GRO (UDP_SEGMENT) + PMTU discovery;
    // no explicit max_udp_payload flag in 0.11 API — 1350B datagram cap enforced in encode_datagram.
    Arc::new(t)
}

/// Server-side DNS with IPv4 preference (many targets are v4-only).
/// Uses a short-lived cache so per-packet domain lookups cannot stall the
/// datagram fast path or amplify upstream DNS.
pub async fn resolve_server_side(host: &str, port: u16) -> Result<SocketAddr> {
    resolve_all_cached(host, port)
        .await?
        .into_iter()
        .next()
        .context("dns empty")
}

/// All resolved addresses, IPv4 first. Caller tries each until one dials (dual-stack fallback).
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    resolve_all_timeout(host, port, Duration::from_secs(5)).await
}

async fn resolve_all_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::time::timeout(timeout, async {
        let mut v: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        v.sort_by_key(|s| if s.is_ipv4() { 0 } else { 1 });
        Ok::<Vec<SocketAddr>, anyhow::Error>(v)
    })
    .await
    .context("dns lookup timed out")??;
    Ok(addrs)
}

type DnsCacheKey = (String, u16);
type DnsCacheVal = (Instant, Vec<SocketAddr>);
fn dns_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>> {
    static CACHE: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_NEG_TTL: Duration = Duration::from_secs(10);

fn dns_neg_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, Instant>> {
    static NEG: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, Instant>>> =
        std::sync::OnceLock::new();
    NEG.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

struct DnsInflightEntry {
    cell: tokio::sync::OnceCell<Result<Vec<SocketAddr>, String>>,
    notify: tokio::sync::Notify,
}

fn dns_inflight() -> &'static tokio::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>> {
    static INF: std::sync::OnceLock<
        tokio::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>>,
    > = std::sync::OnceLock::new();
    INF.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

pub fn dns_slow_path_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1024)))
}

pub fn mono_millis() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

fn dns_key_hash(host: &str, port: u16) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    host.hash(&mut h);
    port.hash(&mut h);
    h.finish()
}

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
/// Sync fast path for the UDP hot loop: returns a clone only on cache hit,
/// never performs I/O. Lets callers avoid `tokio::spawn` per packet (P1).
/// Allocation-free hit path: thread-local single-entry cache keyed by hash
/// avoids the per-packet `String` allocation when the same domain repeats.
pub fn lookup_cached_sync(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    use std::cell::RefCell;
    thread_local! {
        static LAST: RefCell<(u64, Vec<SocketAddr>, Instant)> =
            RefCell::new((0, Vec::new(), Instant::now() - DNS_CACHE_TTL - Duration::from_secs(1)));
    }
    let h = dns_key_hash(host, port);
    let hit = LAST.with(|c| {
        let c = c.borrow();
        c.0 == h && c.2.elapsed() < DNS_CACHE_TTL && !c.1.is_empty()
    });
    if hit {
        return LAST.with(|c| Some(c.borrow().1.clone()));
    }
    let key: DnsCacheKey = (host.to_string(), port);
    if let Ok(m) = dns_cache().read() {
        if let Some((t, v)) = m.get(&key) {
            if t.elapsed() < DNS_CACHE_TTL {
                let v = v.clone();
                LAST.with(|c| {
                    *c.borrow_mut() = (h, v.clone(), Instant::now());
                });
                return Some(v);
            }
        }
    }
    None
}

fn evict_if_needed(m: &mut HashMap<DnsCacheKey, DnsCacheVal>) {
    if m.len() <= 4096 + 256 {
        return;
    }
    m.retain(|_, (t, _)| t.elapsed() < DNS_CACHE_TTL);
    if m.len() <= 4096 {
        return;
    }
    let excess = m.len() - 4096;
    let mut oldest: Vec<(Instant, DnsCacheKey)> = Vec::with_capacity(m.len());
    for (k, (t, _)) in m.iter() {
        oldest.push((*t, k.clone()));
    }
    oldest.sort_by_key(|(t, _)| *t);
    for (_, k) in oldest.into_iter().take(excess) {
        m.remove(&k);
    }
}

pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let key: DnsCacheKey = (host.to_string(), port);
    {
        if let Ok(m) = dns_cache().read() {
            if let Some((t, v)) = m.get(&key) {
                if t.elapsed() < DNS_CACHE_TTL {
                    return Ok(v.clone());
                }
            }
        }
        if let Ok(n) = dns_neg_cache().read() {
            if let Some(t) = n.get(&key) {
                if t.elapsed() < DNS_NEG_TTL {
                    anyhow::bail!("dns negative cached");
                }
            }
        }
    }
    // Singleflight: concurrent lookups for the same key share one upstream query.
    let entry = {
        let mut inf = dns_inflight().lock().await;
        if let Some(c) = inf.get(&key) {
            c.clone()
        } else {
            let c = Arc::new(DnsInflightEntry {
                cell: tokio::sync::OnceCell::new(),
                notify: tokio::sync::Notify::new(),
            });
            inf.insert(key.clone(), c.clone());
            c
        }
    };
    let is_owner = !entry.cell.initialized();
    let res: Result<Vec<SocketAddr>, String> = if is_owner {
        match resolve_all_timeout(host, port, Duration::from_secs(5)).await {
            Ok(v) => {
                let _ = entry.cell.set(Ok(v.clone()));
                entry.notify.notify_waiters();
                Ok(v)
            }
            Err(e) => {
                let _ = entry.cell.set(Err(format!("{e:#}")));
                entry.notify.notify_waiters();
                Err(format!("{e:#}"))
            }
        }
    } else {
        loop {
            if let Some(v) = entry.cell.get() {
                break v.clone();
            }
            entry.notify.notified().await;
        }
    };
    if is_owner {
        let mut inf = dns_inflight().lock().await;
        inf.remove(&key);
    }
    match res {
        Ok(v) => {
            if let Ok(mut m) = dns_cache().write() {
                m.insert(key.clone(), (Instant::now(), v.clone()));
                evict_if_needed(&mut m);
            }
            if let Ok(mut n) = dns_neg_cache().write() {
                n.remove(&key);
            }
            Ok(v)
        }
        Err(msg) => {
            if let Ok(mut n) = dns_neg_cache().write() {
                n.insert(key, Instant::now());
                if n.len() > 1024 + 256 {
                    n.retain(|_, t| t.elapsed() < DNS_NEG_TTL);
                }
            }
            anyhow::bail!("{msg}")
        }
    }
}

/// Accept `IP:port` or `hostname:port` for the QUIC server address.
pub async fn resolve_server_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = s
        .rsplit_once(':')
        .context("bad server_addr, want host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad server port")?;
    let v = resolve_all_timeout(host, port, Duration::from_secs(5)).await?;
    v.into_iter().next().context("dns empty")
}

/// True for globally routable targets; used to enforce `allow_private=false`.
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
                || v.is_unspecified()
                // CGNAT 100.64/10, TEST-NETs, 0/8, 192.0.0.0/24
                || v.octets()[0] == 0
                || (v.octets()[0] == 100 && (v.octets()[1] & 0b1100_0000) == 64)
                || (v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 0)
                || (v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 2)
                // 198.18.0.0/15 benchmarking (198.18.x + 198.19.x), TEST-NET-2 198.51.100.0/24
                || (v.octets()[0] == 198 && (v.octets()[1] & 0xFE) == 18)
                || (v.octets()[0] == 198
                    && v.octets()[1] == 51
                    && v.octets()[2] == 100)
                || (v.octets()[0] == 203 && v.octets()[1] == 0 && v.octets()[2] == 113)
                // 192.88.99.0/24 6to4 relay (deprecated, never a dial target)
                || (v.octets()[0] == 192 && v.octets()[1] == 88 && v.octets()[2] == 99)
                // 240.0.0.0/4 reserved (240-255)
                || (v.octets()[0] >= 240))
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            let s = v.segments();
            !(v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || ((s[0] & 0xfe00) == 0xfc00)
                || ((s[0] & 0xffc0) == 0xfe80)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0064 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || (s[0] == 0x2001 && s[1] == 0x0000)
                || s[0] == 0x0100
                // 2001:10::/28 ORCHIDv2 (RFC7343, non-routable)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010)
                || ((s[0] & 0xffc0) == 0xfec0))
        }
    }
}

/// Strip ::ffff:0:0/96 mapping so SOCKS replies carry a dialable address.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// Map IPv4 to ::ffff:0:0/96 for sending via a dual-stack IPv6 socket.
/// Linux maps in-kernel; macOS/BSD return EINVAL without it. Harmless everywhere.
pub fn map_for_dual(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        v6 => v6,
    }
}

/// Dual-stack UDP socket (V6ONLY=0 when bound to ::). Buffer enlarged for GSO bursts.
/// `sess` sockets (per UDP association) should use the small variant to avoid
/// OOM on routers: 4MB x N sessions of kernel memory adds up fast (P3).
pub fn udp_socket_dual(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, 4 * 1024 * 1024)
}

/// Per-session / relay sockets: 1MB is plenty for a single association's
/// DATAGRAM flow and keeps 100 sessions near ~200MB instead of ~800MB.
pub fn udp_socket_dual_small(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, 1024 * 1024)
}

pub fn udp_socket_dual_with_size(bind: &str, buf: usize) -> Result<std::net::UdpSocket> {
    let addr: SocketAddr = bind.parse()?;
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    if s.set_send_buffer_size(buf).is_err() {
        tracing::warn!("udp send buffer {} unavailable (raise net.core.wmem_max)", buf);
    }
    if s.set_recv_buffer_size(buf).is_err() {
        tracing::warn!("udp recv buffer {} unavailable (raise net.core.rmem_max)", buf);
    }
    s.bind(&addr.into())?;
    Ok(s.into())
}

/// Dual-stack TCP listener (V6ONLY=0 when bound to ::).
pub fn tcp_listener_dual(bind: &str) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = bind.parse()?;
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let s = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    Ok(s.into())
}

/// Zero-copy bidirectional copy between TCP and QUIC stream halves.
/// Propagates half-close in both directions so neither side hangs waiting
/// for EOF after the peer already finished.
pub async fn copy_tcp_quic(
    tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(u64, u64)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut tr, mut tw) = tcp.into_split();
    async fn pump64<R, W>(r: &mut R, w: &mut W) -> Result<u64>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        Ok(total)
    }
    let c2s = async {
        let r = pump64(&mut tr, &mut send).await;
        match &r {
            Ok(_) => send.finish().ok(),
            Err(_) => send.reset(0x04u32.into()).ok(),
        };
        r
    };
    let s2c = async {
        let r = pump64(&mut recv, &mut tw).await;
        if r.is_ok() {
            tw.shutdown().await.ok();
        }
        r
    };
    let (a, b) = tokio::join!(c2s, s2c);
    match (&a, &b) {
        (Err(_), Ok(_)) => {
            tw.shutdown().await.ok();
        }
        (Ok(_), Err(_)) => {
            send.reset(0x04u32.into()).ok();
        }
        (Err(_), Err(_)) => {
            send.reset(0x04u32.into()).ok();
        }
        _ => {}
    }
    Ok((a?, b?))
}

/// Same as [`copy_tcp_quic`] but bounds idle keep-alive streams: if no bytes
/// flow in either direction for `idle`, both halves are shut down and an
/// error is returned so the per-connection task can exit (B7).
/// Uses monotonic `Instant` (never wall-clock) and resets the QUIC stream
/// on any directional failure so the peer never hangs.
pub async fn copy_tcp_quic_idle(
    tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    idle: Duration,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Monotonic base: all timestamps are ms since here, immune to NTP/wall jumps.
    let base = tokio::time::Instant::now();
    let last_ms = Arc::new(AtomicU64::new(0));
    // Throttled touch: at most one atomic store per 100ms per direction.
    // High-throughput (400Mb/s ≈ 1500 chunks/s) must not pay a clock+store per chunk.
    let touch = |last: &AtomicU64, base: &tokio::time::Instant| {
        let now = base.elapsed().as_millis() as u64;
        let prev = last.load(Ordering::Relaxed);
        if now.saturating_sub(prev) >= 100 {
            last.store(now, Ordering::Relaxed);
        }
    };
    let (mut tr, mut tw) = tcp.into_split();
    let l1 = last_ms.clone();
    let l2 = last_ms.clone();
    let b1 = base;
    let b2 = base;
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f1 = failed.clone();
    let f2 = failed.clone();
    let c2s = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        let mut chunks = 0u64;
        loop {
            if f1.load(Ordering::Relaxed) {
                send.reset(0x04u32.into()).ok();
                anyhow::bail!("peer direction failed");
            }
            let n = match tr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    f1.store(true, Ordering::Relaxed);
                    send.reset(0x04u32.into()).ok();
                    return Err::<u64, anyhow::Error>(e.into());
                }
            };
            if let Err(e) = send.write_all(&buf[..n]).await {
                f1.store(true, Ordering::Relaxed);
                send.reset(0x04u32.into()).ok();
                return Err::<u64, anyhow::Error>(e.into());
            }
            total += n as u64;
            chunks += 1;
            if chunks % 8 == 0 {
                touch(&l1, &b1);
            } else {
                let now = b1.elapsed().as_millis() as u64;
                if now.saturating_sub(l1.load(Ordering::Relaxed)) >= 500 {
                    l1.store(now, Ordering::Relaxed);
                }
            }
        }
        send.finish().ok();
        Ok::<u64, anyhow::Error>(total)
    };
    let s2c = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        let mut chunks = 0u64;
        loop {
            if f2.load(Ordering::Relaxed) {
                tw.shutdown().await.ok();
                anyhow::bail!("peer direction failed");
            }
            let n = match recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => n,
                Err(e) => {
                    f2.store(true, Ordering::Relaxed);
                    tw.shutdown().await.ok();
                    return Err::<u64, anyhow::Error>(e.into());
                }
            };
            if n == 0 {
                break;
            }
            if let Err(e) = tw.write_all(&buf[..n]).await {
                f2.store(true, Ordering::Relaxed);
                tw.shutdown().await.ok();
                return Err::<u64, anyhow::Error>(e.into());
            }
            total += n as u64;
            chunks += 1;
            if chunks % 8 == 0 {
                touch(&l2, &b2);
            } else {
                let now = b2.elapsed().as_millis() as u64;
                if now.saturating_sub(l2.load(Ordering::Relaxed)) >= 500 {
                    l2.store(now, Ordering::Relaxed);
                }
            }
        }
        tw.shutdown().await.ok();
        Ok::<u64, anyhow::Error>(total)
    };
    let copy_fut = async move {
        let (a, b) = tokio::join!(c2s, s2c);
        Ok::<(u64, u64), anyhow::Error>((a?, b?))
    };
    tokio::pin!(copy_fut);
    loop {
        let step = Duration::from_secs(5).min(idle);
        tokio::select! {
            r = &mut copy_fut => return r,
            _ = tokio::time::sleep(step) => {
                let elapsed_ms = base.elapsed().as_millis() as u64;
                let last = last_ms.load(Ordering::Relaxed);
                if elapsed_ms.saturating_sub(last) >= idle.as_millis() as u64 {
                    anyhow::bail!("tcp stream idle>{idle:?}");
                }
            }
        }
    }
}

#[allow(dead_code)]
pub fn put_bytes(dst: &mut BytesMut, b: &[u8]) {
    dst.put_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addr_roundtrip() {
        for a in [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 80),
        ] {
            let mut v = Vec::new();
            a.encode(&mut v).unwrap();
            let (b, n) = TargetAddr::decode(&v).unwrap();
            assert_eq!(n, v.len());
            assert_eq!(a, b);
        }
    }
    #[test]
    fn dgram_roundtrip() {
        let a = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let d = encode_datagram(7, &a, b"hello").unwrap();
        let (s, a2, p) = decode_datagram(&d).unwrap();
        assert_eq!(s, 7);
        assert_eq!(a, a2);
        assert_eq!(p, b"hello");
    }
}
