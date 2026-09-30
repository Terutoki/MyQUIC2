//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
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
    sync::watch,
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config-client.toml")]
    config: String,
}

mod assoc;
mod auth;
mod dispatcher;
mod egress;
mod hub;
mod pool;
mod reporter;
mod socks;
#[cfg(test)]
mod tests;
mod util;

use crate::{
    assoc::*, auth::*, dispatcher::*, egress::*, hub::*, pool::*, reporter::*, socks::*, util::*,
};

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
    info!(
        "udp batch backend: {} (sendmmsg={}, recvmmsg={}); GSO/GRO are auto-probed by quinn-udp",
        batch_backend(),
        sendmmsg_available(),
        recvmmsg_available()
    );
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

    let conns = c.conn_count();
    let udp_fail_closed = c.udp_fail_closed();
    let udp_split = c.udp_split();
    let pool = ConnPool::new(conns, c.interactive_port_list(), udp_fail_closed, udp_split);
    // One extra connection per UDP egress class, so `quic_conns` keeps meaning
    // "TCP pool size" and the dedicated UDP connections never take a congestion
    // window away from the bulk TCP class.
    info!(
        "quic pool: {conns} TCP connection(s){} + {} dedicated UDP connection(s) ({}){}",
        if conns > 1 {
            " (bulk round-robin + interactive pin)"
        } else {
            " (single connection: interactive and bulk share slot 0)"
        },
        if udp_split { 2 } else { 1 },
        if udp_split {
            format!(
                "interactive slot {}, bulk slot {}",
                pool.udp_slot(EgressClass::Interactive),
                pool.udp_slot(EgressClass::Bulk)
            )
        } else {
            format!("shared slot {}", pool.udp_slot(EgressClass::Interactive))
        },
        if udp_fail_closed {
            ", UDP is fail-closed: dropped rather than shared while it reconnects"
        } else {
            ", UDP may fall back to a TCP connection while it reconnects"
        }
    );
    let hub: Arc<UdpHub> = Arc::new(UdpHub::new());
    let egress_shared: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // One DATAGRAM dispatcher and one reconnect loop per pool slot, all sharing
    // the same Endpoint (one UDP socket, one ticket cache, one CID router).
    // Every slot keeps its own reassembler, which is correct because a
    // payload's fragments all travel on the connection that carried them.
    // Each connection carries its own class: the interactive ports and the UDP
    // associations have connections no bulk flow can queue on.
    let keep_alive_secs = c.keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    let watchdog_silence = Duration::from_secs(keep_alive_secs.saturating_mul(4).max(20));
    for i in 0..pool.slots_total() {
        spawn_dispatcher(pool.slot(i), hub.clone());
    }
    for i in 0..pool.slots_total() {
        spawn_conn_loop(
            ep.clone(),
            server_str.clone(),
            c.server_name.clone(),
            c.auth_token.clone(),
            pool.slot(i),
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
