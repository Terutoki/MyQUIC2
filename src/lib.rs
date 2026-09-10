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
                let port = u16::from_be_bytes([b[17], b[18]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip, port)), 19))
            }
            0x03 => {
                if b.len() < 2 {
                    anyhow::bail!("short domain");
                }
                let n = b[1] as usize;
                if n == 0 || n > 255 {
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

/// Build a UDP DATAGRAM body: type + sess + addr header + payload.
/// sess scopes the packet to one UDP ASSOCIATE so concurrent associations sharing
/// a QUIC connection never steal each other's replies. Returns None if exceeds limit.
pub fn encode_datagram(sess: u32, addr: &TargetAddr, payload: &[u8]) -> Option<Bytes> {
    let mut v = Vec::with_capacity(40 + payload.len());
    v.push(0x02);
    v.extend_from_slice(&sess.to_le_bytes());
    if addr.encode(&mut v).is_err() {
        return None;
    }
    if v.len() + payload.len() > 1350 {
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
pub fn build_transport(congestion: &str, keep_alive_secs: u64) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // BBR default; cubic only as escape hatch
    if congestion.eq_ignore_ascii_case("cubic") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    } else {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    // GSO/GRO: no flag in quinn API — quinn-udp auto-probes UDP_SEGMENT/UDP_GRO.
    // Bounded buffers: large per-connection buffers risk OOM on small routers,
    // so use 8MB datagram buffers which still cover high-RTT BDP with headroom.
    t.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    t.datagram_send_buffer_size(8 * 1024 * 1024);
    // 512 concurrent streams cover the 500-flow test with margin while bounding
    // worst-case flow-control memory (4MB window each).
    t.max_concurrent_bidi_streams(512u32.into());
    t.max_concurrent_uni_streams(100u32.into());
    // 140ms trans-Pacific at 200Mb/s needs ~3.5MB BDP; 4MB per-stream window
    // covers it, and the 8MB connection window still allows two fast streams
    // in parallel without pinning tens of MB per connection.
    t.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
    t.send_window(8 * 1024 * 1024);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs.max(1))));
    // 15s idle timeout bounds silent-blackhole detection: with 5s keepalives a
    // healthy connection always shows inbound traffic, so 15s of nothing means
    // the path is dead. Short enough to redial promptly, long enough to ride
    // out transient stalls on high-RTT links.
    t.max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()));
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

/// Cached variant used on hot paths (UDP per-packet, TCP per-connection).
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
    }
    let v = resolve_all_timeout(host, port, Duration::from_secs(5)).await?;
    {
        if let Ok(mut m) = dns_cache().write() {
            m.insert(key, (Instant::now(), v.clone()));
            if m.len() > 4096 {
                m.retain(|_, (t, _)| t.elapsed() < DNS_CACHE_TTL);
                if m.len() > 4096 {
                    if let Some(k) = m.keys().next().cloned() {
                        m.remove(&k);
                    }
                }
            }
        }
    }
    Ok(v)
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
                // 240.0.0.0/4 reserved (240-255)
                || (v.octets()[0] >= 240))
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            !(v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || ((v.segments()[0] & 0xfe00) == 0xfc00)
                || ((v.segments()[0] & 0xffc0) == 0xfe80)
                || (v.segments()[0] == 0x2001 && v.segments()[1] == 0x0db8))
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
pub fn udp_socket_dual(bind: &str) -> Result<std::net::UdpSocket> {
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
    if s.set_send_buffer_size(4 * 1024 * 1024).is_err() {
        tracing::warn!("udp send buffer 4MB unavailable (raise net.core.wmem_max)");
    }
    if s.set_recv_buffer_size(4 * 1024 * 1024).is_err() {
        tracing::warn!("udp recv buffer 4MB unavailable (raise net.core.rmem_max)");
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
        let mut buf = vec![0u8; 64 * 1024];
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
