//! MyQUIC2 common: MQP-1 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
use bytes::Bytes;
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

/// Borrowed form of [`TargetAddr`], used on per-datagram hot paths so a
/// domain-typed packet never allocates a `String` just to hit the DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAddrRef<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl TargetAddr {
    pub fn as_ref(&self) -> TargetAddrRef<'_> {
        match self {
            TargetAddr::Ip(s) => TargetAddrRef::Ip(*s),
            TargetAddr::Domain(d, p) => TargetAddrRef::Domain(d, *p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.as_ref().encode(out)
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        let (a, n) = TargetAddrRef::decode(b)?;
        Ok((a.into_owned(), n))
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            TargetAddr::Ip(s) => Some(*s),
            _ => None,
        }
    }
}

impl<'a> TargetAddrRef<'a> {
    pub fn into_owned(self) -> TargetAddr {
        match self {
            TargetAddrRef::Ip(s) => TargetAddr::Ip(s),
            TargetAddrRef::Domain(d, p) => TargetAddr::Domain(d.to_owned(), p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match *self {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    anyhow::bail!("refuse unspecified v4");
                }
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
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
            TargetAddrRef::Domain(d, p) => {
                let bytes = d.as_bytes();
                if bytes.is_empty() {
                    anyhow::bail!("empty domain");
                }
                if bytes.len() > 255 {
                    anyhow::bail!("domain too long");
                }
                out.push(0x03);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn decode(b: &'a [u8]) -> Result<(Self, usize)> {
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
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 7))
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
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 19))
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
                let d = std::str::from_utf8(&b[2..2 + n]).context("bad domain utf8")?;
                let port = u16::from_be_bytes([b[2 + n], b[3 + n]]);
                Ok((TargetAddrRef::Domain(d, port), 4 + n))
            }
            _ => anyhow::bail!("bad atyp {atyp}"),
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
    encode_datagram_ref_with_limit(sess, &addr.as_ref(), payload, limit)
}

/// Same as [`encode_datagram_with_limit`] but takes the borrowed address form,
/// keeping the per-packet path free of domain `String` allocations.
pub fn encode_datagram_ref_with_limit(
    sess: u32,
    addr: &TargetAddrRef<'_>,
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
    let (sess, a, p) = decode_datagram_ref(b)?;
    Ok((sess, a.into_owned(), p))
}

/// Allocation-free variant of [`decode_datagram`] for the UDP fast paths.
pub fn decode_datagram_ref(b: &[u8]) -> Result<(u32, TargetAddrRef<'_>, &[u8])> {
    if b.len() < 6 || b[0] != 0x02 {
        anyhow::bail!("bad dgram");
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (a, n) = TargetAddrRef::decode(&b[5..])?;
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
    /// Optional shared secret. When non-empty, every client must present it on
    /// connection setup; empty disables authentication (rely on network
    /// isolation / firewall).
    #[serde(default)]
    pub auth_token: String,
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
    /// Must match the server's `auth_token` (both empty = no authentication).
    #[serde(default)]
    pub auth_token: String,
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
    // BBR default; cubic only as escape hatch. Callers validate + log the
    // configured value via `parse_congestion`; unknown values fall back to BBR.
    if congestion.eq_ignore_ascii_case("cubic") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    } else {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    // GSO/GRO: no flag in quinn API — quinn-udp auto-probes UDP_SEGMENT/UDP_GRO.
    // Bounded buffers: 4MB datagram buffers cover high-RTT BDP (~3.5MB) while
    // halving per-connection memory vs 8MB (100 server-side conns ≈ 800MB→400MB).
    t.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    t.datagram_send_buffer_size(4 * 1024 * 1024);
    // 1024 concurrent streams cover high-concurrency tests with margin.
    t.max_concurrent_bidi_streams(1024u32.into());
    t.max_concurrent_uni_streams(100u32.into());
    // 140ms trans-Pacific at 200Mb/s needs ~3.5MB BDP; 4MB per-stream window
    // covers it. The aggregate connection window MUST be set explicitly:
    // quinn's default is VarInt::MAX, which would otherwise allow up to
    // 1024 streams * 4MB ≈ 4GB of receive buffering per connection (unauthenticated
    // peers can exploit this). 32MB still covers many parallel fast streams.
    t.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
    t.receive_window(quinn::VarInt::from_u32(32 * 1024 * 1024));
    t.send_window(8 * 1024 * 1024);
    // Clamp so absurd config values cannot overflow the QUIC VarInt timeout.
    let keep_alive_secs = keep_alive_secs.clamp(1, 3600);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs)));
    // Idle timeout derives from keepalive so custom keep_alive_secs can never
    // self-kill a healthy connection: idle must stay well above the keepalive
    // interval (QUIC requires inbound traffic before idle fires). 15s floor
    // preserves the old silent-blackhole bound; larger keepalives scale up.
    let idle_secs = (keep_alive_secs.saturating_mul(3)).max(15);
    t.max_idle_timeout(Some(
        Duration::from_secs(idle_secs)
            .try_into()
            .expect("idle timeout must fit in a QUIC VarInt"),
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
    resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await
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

/// Cache key encoding: `host` bytes + NUL separator + decimal port. This is
/// injective (the decimal port never contains NUL, so splitting at the last
/// NUL recovers the exact host/port), so it is safe to build on the stack and
/// look up with the borrowed `&str` form of `HashMap<String, _>` — no `String`
/// allocation on the per-datagram hot path.
type DnsCacheKey = String;
type DnsCacheVal = (Instant, Vec<SocketAddr>);
const DNS_KEY_BUF: usize = 255 + 1 + 5;

/// Normalize a DNS name for cache keys: DNS is case-insensitive and an
/// absolute (trailing-dot) name is equivalent to its relative form.
fn dns_name_bytes(host: &str) -> &[u8] {
    let mut hb = host.as_bytes();
    while hb.len() > 1 && hb.last() == Some(&b'.') {
        hb = &hb[..hb.len() - 1];
    }
    hb
}

/// Owned fallback for hosts above the wire-format limit; MUST normalize the
/// same way as [`dns_key`] so both forms address the same cache entry.
fn dns_key_owned(host: &str, port: u16) -> String {
    let hb = dns_name_bytes(host);
    let mut bytes = Vec::with_capacity(hb.len() + 6);
    bytes.extend(hb.iter().map(|b| b.to_ascii_lowercase()));
    bytes.push(0);
    bytes.extend_from_slice(port.to_string().as_bytes());
    String::from_utf8(bytes).expect("ascii lowercasing preserves UTF-8")
}

/// Build the cache key into `buf`, returning a borrowed `&str`.
/// Returns `None` only when `host` is longer than the wire-format limit.
fn dns_key<'a>(host: &str, port: u16, buf: &'a mut [u8; DNS_KEY_BUF]) -> Option<&'a str> {
    let hb = dns_name_bytes(host);
    if hb.len() + 1 + 5 > DNS_KEY_BUF {
        return None;
    }
    for (dst, b) in buf.iter_mut().zip(hb) {
        *dst = b.to_ascii_lowercase();
    }
    let mut pos = hb.len();
    buf[pos] = 0;
    pos += 1;
    let mut digits = [0u8; 5];
    let mut p = port;
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (p % 10) as u8;
        p /= 10;
        if p == 0 {
            break;
        }
    }
    buf[pos..pos + (5 - i)].copy_from_slice(&digits[i..]);
    pos += 5 - i;
    std::str::from_utf8(&buf[..pos]).ok()
}

fn dns_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>> {
    static CACHE: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, DnsCacheVal>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_NEG_TTL: Duration = Duration::from_secs(10);
/// Soft cap for the negative cache; past this the table is reaped instead of
/// growing without bound under a failing-domain flood.
const DNS_NEG_MAX: usize = 4096;
/// Wall-clock budget for a single upstream DNS lookup. Client-side dial
/// timeouts are sized to cover this plus the TCP connect budget.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn dns_neg_cache() -> &'static std::sync::RwLock<HashMap<DnsCacheKey, Instant>> {
    static NEG: std::sync::OnceLock<std::sync::RwLock<HashMap<DnsCacheKey, Instant>>> =
        std::sync::OnceLock::new();
    NEG.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Poison-safe lock helpers. The previous `if let Ok(..)` handling silently
/// disabled all DNS caching forever after any panic while a lock was held;
/// recovering the guard keeps the cache functional (a HashMap cannot be left
/// in a half-formed state by such a panic).
fn warn_poisoned() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| tracing::warn!("a cache lock was poisoned; recovering"));
}

pub fn lock_read<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_write<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_mutex<T>(l: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    l.lock().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

struct DnsInflightEntry {
    /// Own copy of the key so the cleanup guard can remove the entry even when
    /// the owner is a takeover task that did not insert it.
    key: DnsCacheKey,
    cell: tokio::sync::OnceCell<Result<Vec<SocketAddr>, String>>,
    notify: tokio::sync::Notify,
    owner: std::sync::atomic::AtomicBool,
}

/// Releases singleflight ownership when the resolving task exits for any
/// reason (completion, cancellation, panic), so waiters can take over instead
/// of sleeping forever.
struct OwnerReset<'a> {
    entry: &'a DnsInflightEntry,
}

impl Drop for OwnerReset<'_> {
    fn drop(&mut self) {
        self.entry
            .owner
            .store(false, std::sync::atomic::Ordering::Release);
        self.entry.notify.notify_waiters();
    }
}

/// Removes the inflight entry when the owner's future is dropped for any
/// reason. Without this, cancellation between `cell.set()` and the explicit
/// removal left a permanently stale entry behind: every later lookup returned
/// the old result without ever re-resolving the name.
struct InflightCleanup<'a> {
    entry: &'a Arc<DnsInflightEntry>,
}

impl Drop for InflightCleanup<'_> {
    fn drop(&mut self) {
        let mut inf = lock_mutex(dns_inflight());
        if let Some(cur) = inf.get(&self.entry.key) {
            if Arc::ptr_eq(cur, self.entry) {
                inf.remove(&self.entry.key);
            }
        }
    }
}

fn dns_inflight() -> &'static std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>> {
    static INF: std::sync::OnceLock<
        std::sync::Mutex<HashMap<DnsCacheKey, Arc<DnsInflightEntry>>>,
    > = std::sync::OnceLock::new();
    INF.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
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

/// Thread-local memo of the most recent lookup, keyed by the *full* normalized
/// key. A 64-bit hash here would let two different `(host, port)` pairs collide
/// and serve each other's address for the whole TTL, so the key is compared
/// byte-for-byte. Storing it inline keeps fast-path hits allocation-free.
struct DnsMemo {
    key: [u8; DNS_KEY_BUF],
    len: usize,
    /// `None` = negatively cached (NXDOMAIN / lookup failure).
    addr: Option<SocketAddr>,
    expires: Instant,
}

thread_local! {
    static DNS_MEMO: std::cell::RefCell<Option<DnsMemo>> = const { std::cell::RefCell::new(None) };
}

fn memo_get(key: &str) -> Option<CachedLookup> {
    let now = Instant::now();
    DNS_MEMO.with(|c| {
        let c = c.borrow();
        match c.as_ref() {
            Some(m) if now < m.expires && &m.key[..m.len] == key.as_bytes() => Some(match m.addr {
                Some(a) => CachedLookup::Addr(a),
                None => CachedLookup::Negative,
            }),
            _ => None,
        }
    })
}

fn memo_put(key: &str, addr: Option<SocketAddr>, expires: Instant) {
    let kb = key.as_bytes();
    if kb.len() > DNS_KEY_BUF {
        return; // only reachable through the owned fallback for >255-byte names
    }
    DNS_MEMO.with(|c| {
        let mut m = DnsMemo {
            key: [0u8; DNS_KEY_BUF],
            len: kb.len(),
            addr,
            expires,
        };
        m.key[..kb.len()].copy_from_slice(kb);
        *c.borrow_mut() = Some(m);
    });
}

/// Result of a synchronous cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedLookup {
    /// A fresh address is cached.
    Addr(SocketAddr),
    /// A fresh negative entry says the name will not resolve; do not spawn a
    /// resolver task for this packet.
    Negative,
    /// Not cached; the caller must use the async resolver.
    Unknown,
}

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
/// Consults the thread-local memo, then the positive cache, then the negative
/// cache, so a known-bad name never costs a task spawn. A hit performs no heap
/// allocation (stack-built key + full-key compare against the memo).
pub fn lookup_cached_fast(host: &str, port: u16) -> CachedLookup {
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    if let Some(hit) = memo_get(key) {
        return hit;
    }
    let now = Instant::now();
    {
        let m = lock_read(dns_cache());
        if let Some((t, v)) = m.get(key) {
            // Expiry is anchored to the global entry's insertion time, so the
            // memo can never outlive the cache TTL.
            let expires = *t + DNS_CACHE_TTL;
            if now < expires {
                if let Some(a) = v.first().copied() {
                    memo_put(key, Some(a), expires);
                    return CachedLookup::Addr(a);
                }
            }
        }
    }
    {
        let n = lock_read(dns_neg_cache());
        if let Some(t) = n.get(key) {
            let expires = *t + DNS_NEG_TTL;
            if now < expires {
                memo_put(key, None, expires);
                return CachedLookup::Negative;
            }
        }
    }
    CachedLookup::Unknown
}

/// Back-compat helper returning only the positive form.
pub fn lookup_cached_sync(host: &str, port: u16) -> Option<SocketAddr> {
    match lookup_cached_fast(host, port) {
        CachedLookup::Addr(a) => Some(a),
        _ => None,
    }
}

const DNS_CACHE_MAX: usize = 4096;

fn evict_if_needed(m: &mut HashMap<DnsCacheKey, DnsCacheVal>) {
    // Soft cap with a slack window so the O(n) sweep is amortized. Eviction is
    // arbitrary (DNS caching needs no LRU ordering); this keeps the global
    // write-lock hold time bounded instead of cloning+sorting the whole map on
    // every insert, which used to stall the packet fast path.
    const SLACK: usize = 512;
    if m.len() <= DNS_CACHE_MAX + SLACK {
        return;
    }
    m.retain(|_, (t, _)| t.elapsed() < DNS_CACHE_TTL);
    let over = m.len().saturating_sub(DNS_CACHE_MAX);
    if over == 0 {
        return;
    }
    // Evict oldest-first so a burst of inserts can never immediately throw away
    // the entries that were just refreshed (the previous arbitrary `take` could).
    // The common case (over == 1) stays a single O(n) scan with one clone.
    let victims: Vec<DnsCacheKey> = if over == 1 {
        m.iter()
            .min_by_key(|(_, (t, _))| *t)
            .map(|(k, _)| k.clone())
            .into_iter()
            .collect()
    } else {
        let mut entries: Vec<(&DnsCacheKey, Instant)> =
            m.iter().map(|(k, (t, _))| (k, *t)).collect();
        entries.sort_unstable_by_key(|(_, t)| *t);
        entries
            .into_iter()
            .take(over)
            .map(|(k, _)| k.clone())
            .collect()
    };
    for k in victims {
        m.remove(&k);
    }
}

pub async fn resolve_all_cached(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    // Stack-built key: no allocation on the positive-cache fast path. The
    // fallback only triggers for hosts longer than the 255-byte wire limit.
    let mut kbuf = [0u8; DNS_KEY_BUF];
    let owned;
    let key: &str = match dns_key(host, port, &mut kbuf) {
        Some(k) => k,
        None => {
            owned = dns_key_owned(host, port);
            &owned
        }
    };
    // 1. Positive cache.
    {
        let m = lock_read(dns_cache());
        if let Some((t, v)) = m.get(key) {
            if t.elapsed() < DNS_CACHE_TTL {
                return Ok(v.clone());
            }
        }
    }
    // 2. Negative cache.
    {
        let n = lock_read(dns_neg_cache());
        if let Some(t) = n.get(key) {
            if t.elapsed() < DNS_NEG_TTL {
                anyhow::bail!("dns negative cached");
            }
        }
    }
    // 3. Singleflight: exactly one owner resolves; everyone else waits on the
    //    cell. Ownership is claimed atomically. If the owner is cancelled or
    //    panics, `OwnerReset` clears the claim and wakes the waiters; the next
    //    waiter re-claims it, so no waiter can sleep forever on a cell that
    //    nobody will ever fill.
    let entry = {
        let mut inf = lock_mutex(dns_inflight());
        match inf.get(key) {
            Some(c) => c.clone(),
            None => {
                let c = Arc::new(DnsInflightEntry {
                    key: key.to_owned(),
                    cell: tokio::sync::OnceCell::new(),
                    notify: tokio::sync::Notify::new(),
                    owner: std::sync::atomic::AtomicBool::new(false),
                });
                inf.insert(c.key.clone(), c.clone());
                c
            }
        }
    };
    loop {
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.swap(true, std::sync::atomic::Ordering::AcqRel) {
            break; // this caller is the owner
        }
        // Waiter: register before re-checking the cell (`notify_waiters` stores
        // no permit, so an unregistered waiter could otherwise miss completion).
        let notified = entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(v) = entry.cell.get() {
            return match v {
                Ok(v) => Ok(v.clone()),
                Err(msg) => anyhow::bail!("{msg}"),
            };
        }
        if !entry.owner.load(std::sync::atomic::Ordering::Acquire) {
            // The owner died without publishing; re-enter and try to take over.
            continue;
        }
        notified.await;
    }

    // Owner path. Both guards live across the await: `_reset` releases the
    // claim and wakes waiters on any exit path, `cleanup` removes the inflight
    // entry once the caches are warm.
    let _reset = OwnerReset { entry: &entry };
    let cleanup = InflightCleanup { entry: &entry };

    // A racing caller may have completed and removed the inflight entry between
    // the initial cache checks and the registration above; re-check before
    // issuing a duplicate upstream lookup.
    {
        let m = lock_read(dns_cache());
        if let Some((t, v)) = m.get(key) {
            if t.elapsed() < DNS_CACHE_TTL {
                return Ok(v.clone());
            }
        }
    }

    let r: Result<Vec<SocketAddr>, String> =
        match resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await {
            Ok(v) => Ok(v),
            Err(e) => Err(format!("{e:#}")),
        };
    let now = Instant::now();
    // Warm the caches and the thread memo BEFORE publishing the result, so a
    // caller that observes the cell also observes a cache hit, and only the
    // owner ever pays for the insert + eviction sweep (previously every waiter
    // re-inserted and re-swept the whole map).
    match &r {
        Ok(v) => {
            {
                let mut m = lock_write(dns_cache());
                m.insert(key.to_owned(), (now, v.clone()));
                evict_if_needed(&mut m);
            }
            lock_write(dns_neg_cache()).remove(key);
            if let Some(a) = v.first().copied() {
                memo_put(key, Some(a), now + DNS_CACHE_TTL);
            }
        }
        Err(_) => {
            {
                let mut n = lock_write(dns_neg_cache());
                if n.len() >= DNS_NEG_MAX {
                    n.retain(|_, t| t.elapsed() < DNS_NEG_TTL);
                }
                if n.len() < DNS_NEG_MAX {
                    n.insert(key.to_owned(), now);
                }
            }
            memo_put(key, None, now + DNS_NEG_TTL);
        }
    }
    let _ = entry.cell.set(r.clone());
    entry.notify.notify_waiters();
    drop(cleanup);
    match r {
        Ok(v) => Ok(v),
        Err(msg) => anyhow::bail!("{msg}"),
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
    let v = resolve_all_timeout(host, port, DNS_LOOKUP_TIMEOUT).await?;
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
                // 192.175.48.0/24 AS112 direct-delegation anycast
                || (v.octets()[0] == 192 && v.octets()[1] == 175 && v.octets()[2] == 48)
                // 192.31.196.0/24 AS112-v4 and 192.52.193.0/24 AMT (RFC 7450)
                || (v.octets()[0] == 192 && v.octets()[1] == 31 && v.octets()[2] == 196)
                || (v.octets()[0] == 192 && v.octets()[1] == 52 && v.octets()[2] == 193)
                // 240.0.0.0/4 reserved (240-255)
                || (v.octets()[0] >= 240))
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            let s = v.segments();
            // RFC 2765 IPv4-translated (SIIT) `::ffff:0:a.b.c.d` is a distinct
            // prefix from IPv4-mapped; on stacks that translate it, the
            // embedded IPv4 decides reachability, so validate it recursively.
            if s[0..4].iter().all(|x| *x == 0) && s[4] == 0xffff && s[5] == 0 {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
            // 64:ff9b::/96 (well-known NAT64 prefix): validate the embedded
            // IPv4 so private/loopback targets cannot slip through via NAT64.
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
            // Deprecated IPv4-compatible ::a.b.c.d: validate embedded IPv4 too,
            // closing a platform-dependent allow_private bypass.
            if s[0..6].iter().all(|x| *x == 0) {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_global_ip(IpAddr::V4(v4));
            }
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
                // 2001:2::/48 benchmarking (RFC 5180)
                || (s[0] == 0x2001 && s[1] == 0x0002)
                // 3fff::/20 documentation (RFC 9637)
                || ((s[0] & 0xfff0) == 0x3ff0)
                // 2001:10::/28 ORCHIDv1 and 2001:20::/28 ORCHIDv2 (RFC 7343)
                || (s[0] == 0x2001
                    && (((s[1] & 0xfff0) == 0x0010) || ((s[1] & 0xfff0) == 0x0020)))
                // 2001:1::1/128 PCP Anycast, ::2/128 TURN Anycast, ::3/128 DNS-SD SRP
                || (s[0] == 0x2001
                    && s[1] == 0x0001
                    && s[2..7].iter().all(|x| *x == 0)
                    && s[7] <= 3)
                // 2001:3::/32 AMT (RFC 7450)
                || (s[0] == 0x2001 && s[1] == 0x0003)
                // 2001:4:112::/48 AS112-v6
                || (s[0] == 0x2001 && s[1] == 0x0004 && s[2] == 0x0112)
                // 2001:30::/28 Drone Remote ID (RFC 9374)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0030)
                // 5f00::/16 SRv6 SIDs (RFC 9602)
                || s[0] == 0x5f00
                // 2620:4f:8000::/48 Direct Delegation AS112
                || (s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
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

fn udp_send_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4096)))
}

/// Best-effort non-blocking UDP send for shared loops (one datagram reader per
/// connection, one relay per association).
///
/// `try_send_to` alone is not enough: tokio returns `WouldBlock` without even
/// attempting the syscall while a freshly registered socket has no cached
/// writable readiness, which would silently drop the first packet of every new
/// session. A genuinely full socket buffer is real backpressure too. In both
/// cases the packet is handed to a bounded detached task so the caller never
/// stalls on one destination; past the permit limit it is dropped (UDP
/// semantics). The payload is only copied on the slow path.
pub fn udp_try_send(sock: &Arc<tokio::net::UdpSocket>, dst: SocketAddr, payload: &[u8]) {
    match sock.try_send_to(payload, dst) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            if let Ok(permit) = udp_send_limiter().clone().try_acquire_owned() {
                let sock = sock.clone();
                let payload = payload.to_vec();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = sock.send_to(&payload, dst).await;
                });
            }
        }
        Err(e) => tracing::debug!("udp send to {dst} failed: {e}"),
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
    // No SO_REUSEADDR here: the QUIC socket is a singleton and reuse would let
    // a second instance bind the same port and silently steal packets.
    s.set_nonblocking(true)?;
    if s.set_send_buffer_size(buf).is_err() {
        tracing::debug!("udp send buffer {buf} unavailable (raise net.core.wmem_max)");
    }
    if s.set_recv_buffer_size(buf).is_err() {
        tracing::debug!("udp recv buffer {buf} unavailable (raise net.core.rmem_max)");
    }
    // Linux/macOS silently clamp to net.core.{w,r}mem_max; surface the real
    // value once per process — these calls run for every UDP session socket,
    // so warning per socket would flood the log on routers with default
    // (small) rmem_max/wmem_max.
    if let Ok(actual) = s.send_buffer_size() {
        if actual < buf {
            warn_buf_clamped("send", actual, buf);
        }
    }
    if let Ok(actual) = s.recv_buffer_size() {
        if actual < buf {
            warn_buf_clamped("recv", actual, buf);
        }
    }
    s.bind(&addr.into())?;
    Ok(s.into())
}

fn warn_buf_clamped(which: &str, actual: usize, want: usize) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let sysctl = if which == "send" { "wmem_max" } else { "rmem_max" };
        tracing::warn!(
            "udp {which} buffer clamped to {actual} (< {want}); raise net.core.{sysctl}; further buffer warnings suppressed"
        );
    }
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

/// Bidirectional copy between TCP and QUIC stream halves.
/// Half-closes propagate in both directions so neither side hangs waiting
/// for EOF after the peer already finished.
///
/// Delegates to [`copy_tcp_quic_idle`] with an effectively unbounded idle
/// window; the direct `join!` implementation this used to have could hang
/// forever when one direction failed while the other stayed blocked.
pub async fn copy_tcp_quic(
    tcp: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<(u64, u64)> {
    copy_tcp_quic_idle(tcp, send, recv, Duration::from_secs(u32::MAX as u64)).await
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
    let c2s = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        let mut chunks = 0u64;
        loop {
            let n = match tr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    send.reset(0x04u32.into()).ok();
                    return Err::<u64, anyhow::Error>(e.into());
                }
            };
            if let Err(e) = send.write_all(&buf[..n]).await {
                send.reset(0x04u32.into()).ok();
                return Err::<u64, anyhow::Error>(e.into());
            }
            total += n as u64;
            chunks += 1;
            if chunks.is_multiple_of(8) {
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
            let n = match recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => n,
                Err(e) => {
                    tw.shutdown().await.ok();
                    return Err::<u64, anyhow::Error>(e.into());
                }
            };
            if n == 0 {
                break;
            }
            if let Err(e) = tw.write_all(&buf[..n]).await {
                tw.shutdown().await.ok();
                return Err::<u64, anyhow::Error>(e.into());
            }
            total += n as u64;
            chunks += 1;
            if chunks.is_multiple_of(8) {
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
    // Drive both directions manually instead of `join!`: when one direction
    // fails, returning from this function drops the other future immediately,
    // which closes its TCP half and resets/stops its QUIC stream. `join!` left
    // the other side blocked in `read()` until the 300 s idle deadline, so a
    // dead QUIC connection could pin the target fd and buffers for minutes.
    tokio::pin!(c2s);
    tokio::pin!(s2c);
    let mut c2s_total: Option<u64> = None;
    let mut s2c_total: Option<u64> = None;
    loop {
        let step = Duration::from_secs(5).min(idle);
        tokio::select! {
            r = &mut c2s, if c2s_total.is_none() => match r {
                Ok(v) => c2s_total = Some(v),
                Err(e) => return Err(e),
            },
            r = &mut s2c, if s2c_total.is_none() => match r {
                Ok(v) => s2c_total = Some(v),
                Err(e) => return Err(e),
            },
            _ = tokio::time::sleep(step) => {
                let elapsed_ms = base.elapsed().as_millis() as u64;
                let last = last_ms.load(Ordering::Relaxed);
                if elapsed_ms.saturating_sub(last) >= idle.as_millis() as u64 {
                    anyhow::bail!("tcp stream idle>{idle:?}");
                }
            }
        }
        if let (Some(a), Some(b)) = (c2s_total, s2c_total) {
            return Ok((a, b));
        }
    }
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
    fn global_ip_filter_extended() {
        // RFC 2765 IPv4-translated addresses are judged by their embedded IPv4.
        assert!(!is_global_ip("::ffff:0:127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:10.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("::ffff:0:8.8.8.8".parse().unwrap()));
        // IPv4-mapped must not be affected by the translated-prefix check.
        assert!(is_global_ip("::ffff:8.8.8.8".parse().unwrap()));
        // Newly added IANA "not globally reachable" ranges.
        assert!(!is_global_ip("192.31.196.1".parse().unwrap()));
        assert!(!is_global_ip("192.52.193.1".parse().unwrap()));
        assert!(!is_global_ip("2001:1::1".parse().unwrap()));
        assert!(!is_global_ip("2001:3::1".parse().unwrap()));
        assert!(!is_global_ip("2001:4:112::1".parse().unwrap()));
        assert!(!is_global_ip("2001:30::1".parse().unwrap()));
        assert!(!is_global_ip("5f00::1".parse().unwrap()));
        assert!(!is_global_ip("2620:4f:8000::1".parse().unwrap()));
        // Still globally routable.
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn dns_key_normalizes_case_and_trailing_dot() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        assert_eq!(
            dns_key("Example.COM.", 443, &mut a).unwrap(),
            dns_key("example.com", 443, &mut b).unwrap()
        );
        assert_eq!(
            dns_key("example.com", 80, &mut a).unwrap(),
            "example.com\u{0}80"
        );
        // The owned fallback must normalize identically to the stack form.
        assert_eq!(
            dns_key_owned("Example.COM.", 443),
            dns_key("example.com", 443, &mut b).unwrap()
        );
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
    #[test]
    fn dgram_ref_roundtrip() {
        let a = TargetAddr::Domain("example.com".into(), 443);
        let d = encode_datagram(9, &a, b"x").unwrap();
        let (s, aref, p) = decode_datagram_ref(&d).unwrap();
        assert_eq!(s, 9);
        assert_eq!(aref, TargetAddrRef::Domain("example.com", 443));
        assert_eq!(aref.into_owned(), a);
        assert_eq!(p, b"x");
    }
    #[test]
    fn global_ip_filter() {
        // NAT64 well-known prefix: the embedded IPv4 decides.
        assert!(!is_global_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("64:ff9b::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        // Deprecated IPv4-compatible form is validated via its embedded IPv4.
        assert!(!is_global_ip("::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("::8.8.8.8".parse().unwrap()));
        // IPv4-mapped unchanged.
        assert!(!is_global_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("8.8.8.8".parse().unwrap()));
        // Newly covered documentation/benchmark prefixes.
        assert!(!is_global_ip("2001:2::1".parse().unwrap()));
        assert!(!is_global_ip("3fff::1".parse().unwrap()));
        // ORCHIDv1/v2 + AS112.
        assert!(!is_global_ip("2001:10::1".parse().unwrap()));
        assert!(!is_global_ip("2001:20::1".parse().unwrap()));
        assert!(!is_global_ip("192.175.48.1".parse().unwrap()));
        assert!(is_global_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn dns_key_is_injective() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        let k1 = dns_key("example.com", 443, &mut a).unwrap();
        let k2 = dns_key("example.com", 80, &mut b).unwrap();
        assert_ne!(k1, k2);
        // A host containing the separator is still unambiguous: the split is
        // always at the last NUL, which the decimal port can never contain.
        let mut c = [0u8; DNS_KEY_BUF];
        let k3 = dns_key("a\0b", 1, &mut c).unwrap();
        assert_eq!(k3, "a\u{0}b\u{0}1");
        assert_eq!(dns_key("same", 1, &mut a).unwrap(), "same\u{0}1");
    }
}
