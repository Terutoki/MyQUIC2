//! MyQUIC2 common: MQP-1 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};

// ---------------- Address codec (MQP-1) ----------------
// wire: atyp u8 | addr | port u16 BE ; atyp: 0x01 v4, 0x04 v6, 0x03 domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TargetAddr::Ip(SocketAddr::V4(a)) => {
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(a)) => {
                out.push(0x04);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddr::Domain(d, p) => {
                out.push(0x03);
                out.push(d.len() as u8);
                out.extend_from_slice(d.as_bytes());
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize)> {
        if b.is_empty() { anyhow::bail!("empty addr"); }
        let atyp = b[0];
        match atyp {
            0x01 => {
                if b.len() < 7 { anyhow::bail!("short v4"); }
                let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
                let port = u16::from_be_bytes([b[5], b[6]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip, port)), 7))
            }
            0x04 => {
                if b.len() < 19 { anyhow::bail!("short v6"); }
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[1..17]);
                let ip = IpAddr::from(o);
                let port = u16::from_be_bytes([b[17], b[18]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip, port)), 19))
            }
            0x03 => {
                if b.len() < 2 { anyhow::bail!("short domain"); }
                let n = b[1] as usize;
                if b.len() < 2 + n + 2 { anyhow::bail!("short domain body"); }
                let d = String::from_utf8(b[2..2 + n].to_vec()).context("bad domain utf8")?;
                let port = u16::from_be_bytes([b[2 + n], b[3 + n]]);
                Ok((TargetAddr::Domain(d, port), 4 + n))
            }
            _ => anyhow::bail!("bad atyp {atyp}"),
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self { TargetAddr::Ip(s) => Some(*s), _ => None }
    }
}

/// Build a UDP DATAGRAM body: type + sess + addr header + payload.
/// sess scopes the packet to one UDP ASSOCIATE so concurrent associations sharing
/// a QUIC connection never steal each other's replies. Returns None if exceeds limit.
pub fn encode_datagram(sess: u32, addr: &TargetAddr, payload: &[u8]) -> Option<Bytes> {
    let mut v = Vec::with_capacity(40 + payload.len());
    v.push(0x02);
    v.extend_from_slice(&sess.to_le_bytes());
    addr.encode(&mut v);
    if v.len() + payload.len() > 1350 { return None; }
    v.extend_from_slice(payload);
    Some(Bytes::from(v))
}

pub fn decode_datagram(b: &[u8]) -> Result<(u32, TargetAddr, &[u8])> {
    if b.len() < 6 || b[0] != 0x02 { anyhow::bail!("bad dgram"); }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let (a, n) = TargetAddr::decode(&b[5..])?;
    Ok((sess, a, &b[5 + n..]))
}

// ---------------- Config files ----------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConf {
    pub listen: String,          // e.g. 0.0.0.0:8443
    pub cert_file: String,       // server cert PEM (self-signed)
    pub key_file: String,        // server key PEM
    pub server_name: String,     // e.g. myquic2, used for self-sign SAN + SNI
    #[serde(default = "d_bbr")]
    pub congestion: String,      // bbr | cubic
    #[serde(default = "d_true")]
    pub gso: bool,               // informational: quinn-udp auto-enables; false = log warn only
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_true")]
    pub allow_private: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConf {
    pub socks_listen: String,    // e.g. 127.0.0.1:1080
    pub server_addr: String,     // e.g. 127.0.0.1:8443
    pub server_name: String,     // SNI, must match cert SAN
    pub server_cert_file: String,// pinned self-signed cert PEM
    #[serde(default = "d_bbr")]
    pub congestion: String,
    #[serde(default = "d_true")]
    pub gso: bool,
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_5")]
    pub reconnect_timeout_secs: u64,
}
fn d_bbr() -> String { "bbr".into() }
fn d_true() -> bool { true }
fn d_keepalive() -> u64 { 5 }
fn d_5() -> u64 { 5 }

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
    // Large buffers let batching actually happen; required for 10Gbps-class throughput.
    t.datagram_receive_buffer_size(Some(32 * 1024 * 1024));
    t.datagram_send_buffer_size(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(10_000u32.into());
    t.max_concurrent_uni_streams(1_000u32.into());
    // High-RTT tuning (e.g. 140ms trans-Pacific): BDP at 200Mb/s is 3.5MB.
    // Default per-stream window (1.25MB) would cap a single stream at ~71Mb/s,
    // so raise to 8MB (~457Mb/s per stream) and 32MB connection send window.
    // Harmless on low-RTT links: windows only consume memory when actually used.
    t.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));
    t.send_window(32 * 1024 * 1024);
    t.keep_alive_interval(Some(Duration::from_secs(keep_alive_secs.max(1))));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // NOTE: quinn-udp auto-probes GSO/GRO (UDP_SEGMENT) + PMTU discovery;
    // no explicit max_udp_payload flag in 0.11 API — 1452B datagram cap enforced in encode_datagram.
    Arc::new(t)
}

/// Server-side DNS with IPv4 preference (many targets are v4-only).
pub async fn resolve_server_side(host: &str, port: u16) -> Result<SocketAddr> {
    Ok(resolve_all(host, port).await?.into_iter().next().context("dns empty")?)
}

/// All resolved addresses, IPv4 first. Caller tries each until one dials (dual-stack fallback).
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let mut v: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    v.sort_by_key(|s| if s.is_ipv4() { 0 } else { 1 });
    Ok(v)
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
    let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.set_send_buffer_size(4 * 1024 * 1024).ok();
    s.set_recv_buffer_size(4 * 1024 * 1024).ok();
    s.bind(&addr.into())?;
    Ok(s.into())
}

/// Dual-stack TCP listener (V6ONLY=0 when bound to ::).
pub fn tcp_listener_dual(bind: &str) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = bind.parse()?;
    let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
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
pub async fn copy_tcp_quic(
    tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(u64, u64)> {
    let (mut tr, mut tw) = tcp.into_split();
    let c2s = async {
        let n = tokio::io::copy(&mut tr, &mut send).await?;
        send.finish().ok();
        Ok::<u64, anyhow::Error>(n)
    };
    let s2c = async {
        let n = tokio::io::copy(&mut recv, &mut tw).await?;
        Ok::<u64, anyhow::Error>(n)
    };
    let (a, b) = tokio::join!(c2s, s2c);
    Ok((a?, b?))
}

#[allow(dead_code)]
pub fn put_bytes(dst: &mut BytesMut, b: &[u8]) { dst.put_slice(b); }

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
            a.encode(&mut v);
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
