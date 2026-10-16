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

// mimalloc on every target (see Cargo.toml): the shipped static / OpenWrt
// binaries link musl, whose allocator measured well behind glibc on the UDP
// soak; on glibc it measured neutral, and one allocator keeps the hot-path
// allocation profile identical between the dev machine and the router.
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
    // Warm the quanta clock (one-time lazy calibration, worst case ~200 ms)
    // and start its upkeep thread before the first packet can pay for either.
    let _ = coarse_millis();
    let a = Args::parse();
    let c: ClientConf = load_toml(&a.config)?;
    if c.auth_token.len() > AUTH_TOKEN_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_TOKEN_MAX_BYTES} B wire cap (server only reads the first {AUTH_TOKEN_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
        );
    }
    if is_placeholder_token(&c.auth_token) {
        warn!(
            "auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)"
        );
    }
    if !parse_congestion(&c.congestion) {
        warn!(
            "unknown congestion={:?}, falling back to bbr (want bbr|cubic)",
            c.congestion
        );
    }
    set_ip_preference(c.dns_ip_preference);
    info!("dns address preference: {:?}", c.dns_ip_preference);
    info!(
        "udp batch backend: {} (sendmmsg={}, recvmmsg={}); GSO/GRO are auto-probed by quinn-udp",
        batch_backend(),
        sendmmsg_available(),
        recvmmsg_available()
    );
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?, &c.alpn_bytes())?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let quic_client = Arc::new(quic_client);
    let mut ccfg_interactive = quinn::ClientConfig::new(quic_client.clone());
    let congestion = Congestion::from_config(&c.congestion);
    ccfg_interactive.transport_config(build_transport_tuned_class(
        congestion,
        c.keep_alive_secs,
        c.tuning(),
        false,
    ));
    let mut ccfg_bulk = quinn::ClientConfig::new(quic_client);
    ccfg_bulk.transport_config(build_transport_tuned_class(
        congestion,
        c.keep_alive_secs,
        c.tuning(),
        true,
    ));
    let server_str = c.server_addr.clone();
    let server_str_log = server_str.clone();

    let conns = c.conn_count();
    let udp_fail_closed = c.udp_fail_closed();
    let udp_split = c.udp_split();
    let udp_egress = c.udp_egress_cnt();
    let pool = ConnPool::new(
        conns,
        c.interactive_port_list(),
        udp_fail_closed,
        udp_split,
        udp_egress,
    );
    // One QUIC endpoint per pool slot — one UDP socket, CID table and driver
    // task each — so no slot's receive syscalls, CID lookups and task wakeups
    // queue behind another slot's. The old shape had the whole TCP pool plus
    // the interactive UDP class on one shared endpoint and the bulk shards on
    // a second; now every connection's ingress is its own. Client endpoints
    // dial with an explicit config (`connect_with` in `dial_once`), so they
    // need no default client config.
    //
    // `quic_conns` extra connections: one per UDP egress class, plus the bulk
    // shards, so the TCP pool keeps its documented meaning and the dedicated
    // UDP connections never take a congestion window away from the bulk TCP
    // class.
    info!(
        "quic pool: {conns} TCP connection(s){} + {} dedicated UDP connection(s) ({}){} (endpoints: one UDP socket per slot)",
        if conns > 1 {
            " (bulk round-robin + interactive pin)"
        } else {
            " (single connection: interactive and bulk share slot 0)"
        },
        if udp_split { 1 + udp_egress } else { 1 },
        if udp_split {
            let first_shard = pool.udp_global_slot(1);
            format!(
                "interactive slot {}, bulk shards {}..{}",
                pool.udp_global_slot(0),
                first_shard,
                first_shard + udp_egress - 1
            )
        } else {
            format!("shared slot {}", pool.udp_global_slot(0))
        },
        if udp_fail_closed {
            ", UDP is fail-closed: dropped rather than shared while it reconnects"
        } else {
            ", UDP may fall back to a TCP connection while it reconnects"
        }
    );
    let hub: Arc<UdpHub> = Arc::new(UdpHub::new());
    let egress_shared: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // One DATAGRAM dispatcher and one reconnect loop per pool slot.
    // Every slot keeps its own reassembler, which is correct because a
    // payload's fragments all travel on the connection that carried them.
    // Each connection carries its own class: the interactive ports and the UDP
    // associations have connections no bulk flow can queue on.
    let keep_alive_secs = c.keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    let watchdog_silence = Duration::from_secs(keep_alive_secs.saturating_mul(4).max(20));
    // Orderly-shutdown flag for the sharded topology: each slot shard parks on
    // it and then drains its own endpoint (see `spawn_slot_shard`); the
    // shared-runtime topology ignores it and is closed from here.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Runtime topology. Sharded (the default; `MYQUIC2_SHARD_RUNTIME=0`
    // disables): every pool slot runs inside its own pinned current-thread
    // runtime, so its endpoint driver, DATAGRAM dispatcher and reconnect loop
    // — and all of their thread-local state (the dispatch cache and
    // reassembler, the per-slot watch generation, the receive buffers) — stay
    // on one core instead of migrating between work-stealing workers. Shared
    // (the pre-sharding topology): every slot runs on the multi-thread
    // runtime and work-stealing may migrate those tasks.
    let (eps, shard_joins) = if shard_runtime_enabled() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let mut joins = Vec::with_capacity(pool.slots_total());
        for i in 0..pool.slots_total() {
            let sock = udp_socket_dual("[::]:0")?;
            // Per-slot transport preset (see `slot_uses_bulk_preset`): only
            // the dedicated bulk UDP class connection gets the coarse bulk
            // preset; the TCP pool and the interactive UDP class keep the
            // tuned 2/5 ms one.
            let cfg = if slot_uses_bulk_preset(&pool, i) {
                ccfg_bulk.clone()
            } else {
                ccfg_interactive.clone()
            };
            joins.push(spawn_slot_shard(
                i,
                sock,
                cfg,
                server_str.clone(),
                c.server_name.clone(),
                c.auth_token.clone(),
                pool.slot(i),
                hub.clone(),
                watchdog_silence,
                shutdown_rx.clone(),
                ready_tx.clone(),
            )?);
        }
        // A shard always reports once (Ok after its endpoint exists and its
        // tasks are spawned, or Err when it cannot start); a disconnect
        // instead of a report means the thread died before that, and both are
        // fatal at startup.
        drop(ready_tx);
        for i in 0..pool.slots_total() {
            match ready_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => anyhow::bail!("client slot {i} failed to start: {e}"),
                Err(e) => anyhow::bail!("client slot {i} did not report ready: {e}"),
            }
        }
        info!(
            "client runtime: {} sharded current-thread runtime(s), one pool slot each \
             (Linux: pinned up to the core count; MYQUIC2_SHARD_RUNTIME=0 restores the shared runtime)",
            pool.slots_total()
        );
        (Vec::new(), joins)
    } else {
        let rt = Arc::new(quinn::TokioRuntime);
        let mut eps: Vec<quinn::Endpoint> = Vec::with_capacity(pool.slots_total());
        for _ in 0..pool.slots_total() {
            let sock = udp_socket_dual("[::]:0")?;
            eps.push(quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                rt.wrap_udp_socket(sock)?,
                rt.clone(),
            )?);
        }
        for i in 0..pool.slots_total() {
            spawn_dispatcher(pool.slot(i), hub.clone());
        }
        for (i, ep) in eps.iter().enumerate() {
            let cfg = if slot_uses_bulk_preset(&pool, i) {
                ccfg_bulk.clone()
            } else {
                ccfg_interactive.clone()
            };
            spawn_conn_loop(
                ep.clone(),
                cfg,
                server_str.clone(),
                c.server_name.clone(),
                c.auth_token.clone(),
                pool.slot(i),
                watchdog_silence,
            );
        }
        (eps, Vec::new())
    };

    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;
    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!(
        "socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, token={}, tls13-pinned, 0rtt)",
        if c.auth_token.is_empty() { "off" } else { "on" }
    );
    spawn_udp_reporter();
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    // SIGTERM/SIGINT: close every slot's endpoint so all pooled connections
    // drop and in-flight SOCKS flows end with a reset instead of being
    // silently killed with the process. There is no drain window; the
    // reconnect loops would redial if the process stayed alive, and process
    // exit follows immediately.
    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        let (sock, peer) = tokio::select! {
            accepted = li.accept() => match accepted {
                Ok(x) => x,
                Err(e) => {
                    // Transient accept errors (EMFILE/ECONNABORTED) must not kill
                    // the proxy for every other client.
                    warn!("accept failed: {e:#}; continuing");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = &mut shutdown => {
                info!("shutdown signal received: closing endpoints so conns drop and peers can reconnect");
                // Sharded slots own their endpoints: the flag wakes each
                // shard, which closes its endpoint and drains it under its own
                // bounded deadline (see `spawn_slot_shard`).
                let _ = shutdown_tx.send(true);
                for e in &eps {
                    e.close(0u32.into(), b"shutdown");
                }
                if shard_joins.is_empty() {
                    // Shared-runtime pool: one deadline for the whole group,
                    // so a wide pool must not multiply the shutdown delay.
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                    for e in &eps {
                        let _ = tokio::time::timeout_at(deadline, e.wait_idle()).await;
                    }
                } else {
                    // Sharded pool: each shard drains under its own deadline,
                    // so joining cannot multiply the delay either.
                    for j in shard_joins {
                        let _ = j.join();
                    }
                }
                break;
            }
        };
        // Relay-TCP posture on the accepted SOCKS socket: nodelay plus (on
        // Linux) TCP_NOTSENT_LOWAT, so the kernel send buffer cannot stack
        // unsent bytes ahead of the QUIC stream that already paces this flow
        // (see `linux::tune_relay_tcp`).
        linux::tune_relay_tcp(&sock);
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
    Ok(())
}

/// How long a slot shard keeps its endpoint's driver alive after closing it,
/// so quinn can flush `CONNECTION_CLOSE` frames to the server. Same budget the
/// shared-runtime path spends in one `wait_idle` timeout.
const SLOT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// One client pool slot: a dedicated OS thread that owns its QUIC endpoint end
/// to end — its own current-thread tokio runtime (pinned to one core on
/// Linux), UDP socket, CID table, driver task, DATAGRAM dispatcher and
/// reconnect loop. All of the per-packet thread-local state those tasks keep
/// then lives on the core that serves it, instead of migrating between
/// work-stealing workers and going cold at each hop — the same locality the
/// server's ingress shards get.
///
/// The endpoint is created on this thread because quinn spawns its driver
/// onto the *ambient* runtime: built on the shared runtime, the driver (and
/// every receive syscall and CID lookup it performs) would stay there. This
/// thread's future parks on the shutdown flag for the process lifetime, which
/// is what holds the runtime — and with it the driver — until main asks the
/// pool to drain. `ready` reports startup success or failure; there is no
/// per-slot failure channel, unlike the server's shards: a client endpoint
/// driver that dies only fails that slot's dials, and the reconnect loop
/// already owns retrying them, so there is nothing to fail the process over.
#[allow(clippy::too_many_arguments)]
fn spawn_slot_shard(
    idx: usize,
    sock: std::net::UdpSocket,
    cfg: quinn::ClientConfig,
    server: String,
    server_name: String,
    auth: String,
    slot: ConnSlot,
    hub: Arc<UdpHub>,
    watchdog_silence: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("myquic2-slot-{idx}"))
        .spawn(move || {
            // Pin the first `cores` slots; a pool wider than the machine
            // leaves its extra slots unpinned so the scheduler can balance
            // them (pinning two threads to one core would force sharing).
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            if idx < cores {
                myquic2::linux::pin_to_core(idx);
            }
            let rt_thread = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = ready.send(Err(format!("current-thread runtime: {e}")));
                    return;
                }
            };
            rt_thread.block_on(async move {
                let qrt = Arc::new(quinn::TokioRuntime);
                let ep = match qrt.wrap_udp_socket(sock) {
                    Ok(sock) => match quinn::Endpoint::new_with_abstract_socket(
                        quinn::EndpointConfig::default(),
                        None,
                        sock,
                        qrt.clone(),
                    ) {
                        Ok(ep) => ep,
                        Err(e) => {
                            let _ = ready.send(Err(format!("endpoint: {e}")));
                            return;
                        }
                    },
                    Err(e) => {
                        let _ = ready.send(Err(format!("socket: {e}")));
                        return;
                    }
                };
                spawn_dispatcher(slot.clone(), hub);
                spawn_conn_loop(
                    ep.clone(),
                    cfg,
                    server,
                    server_name,
                    auth,
                    slot,
                    watchdog_silence,
                );
                let _ = ready.send(Ok(()));
                let _ = shutdown.wait_for(|v| *v).await;
                ep.close(0u32.into(), b"shutdown");
                let _ = tokio::time::timeout(SLOT_DRAIN_TIMEOUT, ep.wait_idle()).await;
            });
        })
        .context("spawn client slot shard")
}
