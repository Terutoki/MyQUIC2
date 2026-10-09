use anyhow::Result;
use std::sync::Arc;

/// Server TLS: TLS1.3 only (QUIC mandates it; single version = min handshake RTT).
/// Cipher: the aws-lc-rs provider negotiates the same ordering as ring did
/// (AES-128-GCM first on AES-NI => fastest path); the provider switch moves
/// the per-packet QUIC AEAD and the handshake crypto onto it.
pub fn server_tls_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![alpn.to_vec()];
    // rustls' default stateful store holds only 256 sessions; with the 4096
    // connection cap and 2 tickets per handshake that thrashes, so 0-RTT and
    // (1-RTT) resumption would silently degrade to full handshakes. Size the
    // store for the connection cap instead.
    const TLS_SESSION_CACHE: usize = 8192;
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(TLS_SESSION_CACHE);
    // KEEP rustls' default ticketer (NeverProducesTickets): that selects STATEFUL
    // resumption via the in-memory session store, which is the only mode where
    // rustls accepts 0-RTT early data (RFC8446 8.1 anti-replay rule).
    // Accept QUIC 0-RTT early data on resumption. quinn requires exactly 0 or u32::MAX here.
    // Replay caveat: tickets are single-use and short-lived; worst case is a duplicated
    // outbound dial, no amplification.
    // quinn (and QUIC itself) only permits 0 or u32::MAX here — anything else is
    // a protocol violation, so the bound cannot be lowered at this layer; replay
    // exposure is limited by single-use short-lived tickets instead.
    cfg.max_early_data_size = u32::MAX;
    Ok(Arc::new(cfg))
}
