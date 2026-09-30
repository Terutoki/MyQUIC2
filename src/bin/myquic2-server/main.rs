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

mod accept;
mod auth;
mod forward;
mod memo;
mod pin;
mod reader;
mod reporter;
mod table;
mod tcp;
#[cfg(test)]
mod tests;

use crate::{
    accept::*, auth::*, forward::*, memo::*, pin::*, reader::*, reporter::*, table::*, tcp::*,
};

// The shipped static / OpenWrt binaries link musl, whose allocator measured
// well behind glibc on the UDP soak; mimalloc closes part of that gap.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    info!(
        "udp batch backend: {} (sendmmsg={}, recvmmsg={}); GSO/GRO are auto-probed by quinn-udp",
        batch_backend(),
        sendmmsg_available(),
        recvmmsg_available()
    );
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
    let tuning = c.tuning();
    scfg.transport_config(build_transport_tuned(
        &c.congestion,
        c.keep_alive_secs,
        tuning,
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
    let auth_token = Arc::new(c.auth_token.clone().into_bytes());
    let auth_enabled = !auth_token.is_empty();
    // Admission: a connection *count* cap plus — when configured — a
    // peer-pinnable *memory* cap. Both are needed and neither is redundant: a
    // count alone cannot bound memory (each admitted connection may hold its
    // receive window, its send budget and both DATAGRAM buffers, all of which a
    // peer controls), while a memory bound alone cannot bound fds/tasks.
    let conn_cap = c
        .max_connections
        .unwrap_or(if auth_enabled {
            MAX_CONNECTIONS
        } else {
            // With no token every peer is unauthenticated, so the pre-auth budget
            // *is* the connection budget: the shipped default must not admit
            // `MAX_CONNECTIONS` x windows of pinnable memory just because the
            // pre-auth slot is only held during the handshake.
            MAX_UNAUTH_CONNECTIONS
        })
        .clamp(1, MAX_CONNECTIONS);
    let per_conn_bytes = per_connection_memory_bytes(&tuning);
    let cap = admission_cap(conn_cap, c.max_peer_memory_mb, per_conn_bytes);
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(cap));
    let pending_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UNAUTH_CONNECTIONS.min(cap)));
    let worst_mib = (per_conn_bytes as u128 * cap as u128) / (1024 * 1024);
    info!(
        "admission: up to {cap} connection(s); worst case {worst_mib} MiB pinned \
         ({per_conn_bytes} B/connection, auth={}, configured cap={conn_cap}{})",
        if auth_enabled { "on" } else { "off" },
        match c.max_peer_memory_mb {
            Some(mb) => format!(", memory budget {mb} MiB"),
            None => String::new(),
        }
    );
    if worst_mib > 1024 {
        warn!(
            "admission: worst case {worst_mib} MiB of peer-pinnable memory at {cap} \
             connection(s); set max_peer_memory_mb (e.g. 128) on a host with less RAM than that"
        );
    }
    if !auth_enabled
        && c.max_connections
            .is_some_and(|n| n > MAX_UNAUTH_CONNECTIONS)
    {
        warn!(
            "max_connections={conn_cap} on a tokenless endpoint: every admitted peer is \
             unauthenticated, and each one may pin {per_conn_bytes} B of this host's memory"
        );
    }
    if let Some(mb) = c.max_peer_memory_mb {
        if cap < conn_cap {
            info!(
                "memory budget {mb} MiB binds the connection cap: {cap} of {conn_cap} \
                 admitted (raise max_peer_memory_mb or lower the windows to admit more)"
            );
        }
    }
    if !auth_enabled {
        warn!("auth_token is empty: the QUIC endpoint accepts any peer (rely on firewall/network isolation)");
        // Spell out the shipped-default combination, because each half looks
        // benign alone: with no token `allow_private` lets any peer make this
        // host dial its own loopback/LAN (the router's admin UI included), and
        // the admission budget is the tokenless one above.
        if c.allow_private && !listen.ip().is_loopback() {
            warn!(
                "open-proxy posture: auth_token is empty AND allow_private = true AND \
                 listen = {listen} (not loopback) — any host that can reach this port gets \
                 an unauthenticated proxy into loopback/LAN targets; set auth_token, bind \
                 loopback, or firewall the port"
            );
        }
    } else {
        info!("client token authentication enabled");
    }
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
                    warn!("connection limit {cap} reached; refusing new connection");
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
        // Read by `handle_conn` to size this connection's share of the
        // process-wide stream-task pool (a clone per accepted connection).
        let conn_limit_for_conn = conn_limit.clone();
        // One deadline for the handshake while a slot is held (see
        // `PRE_AUTH_TIMEOUT`); without a token there is no slot to free and the
        // more generous handshake budget applies. The token exchange below gets
        // a fresh `AUTH_TIMEOUT` deadline re-armed after the handshake, so a
        // slow handshake cannot starve it.
        let handshake_budget = if pending.is_some() {
            PRE_AUTH_TIMEOUT
        } else {
            HANDSHAKE_TIMEOUT
        };
        let deadline = tokio::time::Instant::now() + handshake_budget;
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
                        match tokio::time::timeout_at(deadline, accepted_fut).await {
                            Ok(_) if c.close_reason().is_none() => c,
                            Ok(_) => {
                                warn!("client handshake failed: {:?}", c.close_reason());
                                return;
                            }
                            Err(_) => {
                                warn!("handshake timed out after {handshake_budget:?}");
                                return;
                            }
                        }
                    }
                    Err(connecting) => match tokio::time::timeout_at(deadline, connecting).await {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            warn!("accept err: {e:#}");
                            return;
                        }
                        Err(_) => {
                            warn!("handshake timed out after {handshake_budget:?}");
                            return;
                        }
                    },
                },
                Err(e) => {
                    warn!("accept err: {e:#}");
                    return;
                }
            };
            if let Err(e) = authenticate(
                &conn,
                &auth_token,
                tokio::time::Instant::now() + AUTH_TIMEOUT,
            )
            .await
            {
                warn!("auth failed from {}: {e:#}", conn.remote_address());
                conn.close(0x01u32.into(), b"unauthorized");
                return;
            }
            // Authentication done: free the pre-auth slot so other new peers
            // can handshake while this connection lives on.
            drop(pending);
            if let Err(e) = handle_conn(conn, allow_private, conn_limit_for_conn, cap).await {
                warn!("conn end: {e:#}");
            }
        });
    }
    Ok(())
}
