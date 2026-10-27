use anyhow::Result;
use std::sync::Arc;

/// Client TLS: pin exact self-signed cert, no WebPKI roots (skip chain building => min RTT/CPU).
///
/// ## 0-RTT posture
///
/// Early data is explicitly enabled: with a resumption ticket from the previous
/// connection, quinn's `Connecting::into_0rtt()` then succeeds and the caller
/// sends the auth token, `HELLO` and application payloads in the first flight.
///
/// The resumption store is sized well above rustls' default of 256 server names
/// because a ticket is **single-use** (rustls takes it out of the client store
/// when it is offered, RFC 8446 anti-replay): every pool slot's dial burns one
/// ticket and the next one only exists after that handshake's
/// `NewSessionTicket`s land. A larger store keeps tickets for every pool slot
/// (the client dials `MAX_POOL_CONNS` TCP + `MAX_UDP_EGRESS_CONNS` + 1 UDP
/// connections, each to the same server name, but a ticket can be re-fetched
/// only by a completed handshake) and for a rotated/standing set of
/// pool configurations (e.g. an operator changing `quic_conns`), instead of
/// thrashing the fixed-size default and silently degrading to full handshakes.
pub fn client_tls_config(
    pinned: rustls::pki_types::CertificateDer<'static>,
    alpn: &[u8],
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pinned)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.enable_early_data = true; // allow QUIC 0-RTT on resumption
    const TLS_RESUMPTION_SESSIONS: usize = 1024;
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(TLS_RESUMPTION_SESSIONS);
    Ok(Arc::new(cfg))
}

// ---------------- QUIC transport: BBR + DATAGRAM + keepalive ----------------
pub fn parse_congestion(name: &str) -> bool {
    name.parse::<crate::transport::Congestion>().is_ok()
}

/// Placeholder secrets shipped in the sample configs. Deploying one is
/// equivalent to an open proxy with a false sense of security, so both
/// binaries warn when they see it.
pub fn is_placeholder_token(token: &str) -> bool {
    matches!(token, "change-me" | "change-me-6b1f0c2d47a9")
}
