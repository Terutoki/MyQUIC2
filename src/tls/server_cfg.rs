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
    //
    // Tickets are single-use: each handshake mints `send_tls13_tickets` new
    // ones, and every one of the client pool's connections needs its own to
    // resume with 0-RTT (a ticket offered as early data is consumed once). 2 is
    // rustls' default and forces the client to come back for more after every
    // single resumption; 4 keeps a spare after one reconnect burst so a lost
    // resumption (e.g. a ticket consumed by a dial that then lost its path)
    // does not immediately cost every pool slot a full handshake.
    cfg.send_tls13_tickets = 4;
    // Accept QUIC 0-RTT early data on resumption. quinn requires exactly 0 or u32::MAX here.
    // Replay caveat: tickets are single-use and short-lived; worst case is a duplicated
    // outbound dial, no amplification.
    // quinn (and QUIC itself) only permits 0 or u32::MAX here — anything else is
    // a protocol violation, so the bound cannot be lowered at this layer; replay
    // exposure is limited by single-use short-lived tickets instead.
    //
    // This is what lets the server read the auth token (and any first-flight
    // payloads) and start forwarding *before the handshake completes*: the
    // accept path feeds the 0.5-RTT `Connection` to `authenticate()` instead of
    // awaiting `ZeroRttAccepted` first.
    cfg.max_early_data_size = u32::MAX;
    Ok(Arc::new(cfg))
}
