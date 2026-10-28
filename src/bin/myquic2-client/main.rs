//! myquic2-client: SOCKS5 ingress (no auth) -> QUIC egress. Client-side DNS, auto-reconnect.
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use clap::Parser;
use myquic2::mqp::wire::Wire;
use myquic2::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicU64},
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
mod forward;
mod forward_udp;
mod hub;
mod pool;
mod reporter;
mod rev2;
mod socks;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_0rtt;
mod util;

use crate::{
    assoc::*, auth::*, dispatcher::*, egress::*, forward::*, hub::*, pool::*, reporter::*, rev2::*,
    socks::*, util::*,
};

// mimalloc on every target (see Cargo.toml): the shipped static / OpenWrt
// binaries link musl, whose allocator measured well behind glibc on the UDP
// soak; on glibc it measured neutral, and one allocator keeps the hot-path
// allocation profile identical between the dev machine and the router.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Slack above the derived fd figure: the config file, stdio, the DNS
/// resolver's request sockets, the tokio drivers' epoll/eventfd/pipes and the
/// log writer.
const FD_GUARD: usize = 256;

/// Fds the documented caps can need at once: one accepted socket per SOCKS
/// relay ([`MAX_SOCKS_CONNS`], shared with `[[tcp_forward]]`), one socket per
/// UDP association ([`MAX_UDP_ASSOCS`], shared with `[[udp_forward]]` peers) and
/// one QUIC endpoint per pool slot ([`MAX_POOL_CONNS`]).
fn designed_fds() -> u64 {
    (MAX_SOCKS_CONNS + MAX_UDP_ASSOCS + MAX_POOL_CONNS + FD_GUARD) as u64
}

/// Raise the soft `RLIMIT_NOFILE` toward [`designed_fds`] and report what is in
/// force. See `myquic2::fdlimit` for why this is a startup step rather than a
/// per-accept error path.
fn report_fd_budget() {
    let want = designed_fds();
    match myquic2::fdlimit::raise_nofile_limit(want) {
        Ok(lim) if lim.shortfall(want) == 0 => info!("{}", lim.describe(want)),
        Ok(lim) => warn!("{}", lim.describe(want)),
        Err(e) => warn!(
            "nofile limit unavailable ({e}); relays and associations past the process default \
             fail with EMFILE"
        ),
    }
}

fn main() -> Result<()> {
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
    // File-descriptor budget before the first socket: the SOCKS relay and UDP
    // association caps are one fd each, far above a stock unix soft limit, and
    // the accept loop treats `EMFILE` as transient — so without this line the
    // client silently serves a fraction of its documented capacity.
    report_fd_budget();
    let main_workers = main_runtime_workers(&c);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(main_workers)
        .enable_all()
        .build()
        .context("build client main runtime")?;
    rt.block_on(client_main(c, main_workers))
}

/// Worker count for the process's multi-threaded main runtime.
///
/// The sharded topology (`MYQUIC2_SHARD_RUNTIME`, on by default) runs one
/// current-thread runtime — and therefore one OS thread — per pool slot: 8 at
/// the shipped defaults (4 TCP + 2 interactive UDP + 2 bulk shards). The main
/// runtime is where every SOCKS accept, TCP relay pump and UDP association
/// task runs.
///
/// Only **pinned** slot threads own a core (`linux::pin_to_core` is implemented
/// only on Linux), so only there may the app-side pool give anything up. But
/// "one core per slot" is not a reservation the app-side pool can afford to
/// honour in full: it is the pool that moves user payload (accepts, relay
/// pumps, every association), while a slot thread mostly parks on its endpoint
/// and wakes for QUIC crypto. At the shipped 8 slots an 8-core host kept 8
/// cores for those parked threads and ran every SOCKS/TCP/UDP task on a single
/// worker; a 4-core host did the same while pinning more slots than it has
/// cores — the worst shape exactly where capacity is scarce.
///
/// The reservation is therefore capped at **half the machine**:
/// `workers >= ceil(cores / 2)` everywhere, and a wide machine keeps the old
/// one-core-per-slot shape (16 cores: 7 slots pinned, 9 workers). The floor of
/// one worker is kept because the runtime must exist. [`priority_pin_cores`]
/// pins only the cores this rule leaves unpinned, so the split is real rather
/// than arithmetic: a pinned slot never shares a core with the app-side pool.
///
/// Off Linux `pin_to_core` is a no-op, so the slot threads are ordinary threads
/// the scheduler timeshares with everything else and the full default width is
/// kept — at the shipped 7 slots an 8-core macOS host ran every SOCKS/TCP/UDP
/// task on a single worker when the subtraction was applied there
/// (LOGIC/PERF-3 regression). `main_runtime_workers_for` is the pure rule so
/// both platform behaviours stay testable on one host.
fn main_runtime_workers(c: &ClientConf) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    main_runtime_workers_for(
        cores,
        shard_runtime_enabled(),
        planned_slot_count(
            c.conn_count(),
            c.udp_split(),
            c.udp_interactive_cnt(),
            c.udp_egress_cnt(),
        ),
        cfg!(target_os = "linux"),
    )
}

/// Pure sizing rule behind [`main_runtime_workers`].
///
/// `pins_slots` is whether `linux::pin_to_core` really places each sharded slot
/// thread on its own core (true only on Linux). Parameters instead of `cfg!`
/// inside the body so a unit test can pin both platform behaviours without a
/// second target.
fn main_runtime_workers_for(cores: usize, sharded: bool, slots: usize, pins_slots: bool) -> usize {
    let cores = cores.max(1);
    if !sharded || !pins_slots {
        return cores;
    }
    // A pinned slot may claim a core, but never more than half the machine:
    // the app-side workers are the side that moves payload, so they keep at
    // least `ceil(cores / 2)` of it (see the doc above).
    cores.saturating_sub(slots.min(cores / 2)).max(1)
}

async fn client_main(c: ClientConf, main_workers: usize) -> Result<()> {
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
    // Wire revision: validate the `wire_rev`/ALPN pair before any socket or TLS
    // work. A bad revision (or a rev2 ALPN label pinned together with rev3)
    // must fail startup loudly instead of silently selecting a wire the peer
    // cannot speak; the revision is carried by ALPN and never negotiated.
    c.validate_wire_rev()?;
    // Forward listeners: validate the whole table before any socket, TLS config
    // or QUIC endpoint is created. A bad entry must fail startup loudly — a
    // silently skipped listener is indistinguishable from a working tunnel until
    // the application starts timing out.
    let tcp_forwards = c.tcp_forwards()?;
    let udp_forwards = c.udp_forwards()?;
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
    let alpn = c.alpn_bytes();
    info!(
        "application wire: rev{} (ALPN {})",
        c.wire().rev(),
        String::from_utf8_lossy(&alpn)
    );
    let tls = client_tls_config(load_cert_der(&c.server_cert_file)?, &alpn)?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let quic_client = Arc::new(quic_client);
    let mut ccfg_interactive = quinn::ClientConfig::new(quic_client.clone());
    let congestion = Congestion::from_config(&c.congestion);
    // Resolve the transport tuning once: the idle timeout it carries is the
    // same value the silence watchdog and the pool's stale gate derive from,
    // so the three can never disagree about the liveness window.
    let tuning = c.tuning();
    // Client-side builders: same tuning, but they advertise zero incoming
    // stream credit (the server never opens a stream to us; see
    // `build_client_transport_tuned` for the peer-pinnable-memory reason).
    ccfg_interactive.transport_config(build_client_transport_tuned_class(
        congestion,
        c.keep_alive_secs,
        tuning,
        false,
    ));
    let mut ccfg_bulk = quinn::ClientConfig::new(quic_client);
    ccfg_bulk.transport_config(build_client_transport_tuned_class(
        congestion,
        c.keep_alive_secs,
        tuning,
        true,
    ));
    let server_str = c.server_addr.clone();
    let server_str_log = server_str.clone();

    // The keepalive is only the NAT/firewall refresh cadence; the liveness
    // window is `tuning.idle_timeout_secs`, decoupled from it. The silence
    // watchdog is 2/3 of that idle timeout (40 s at the shipped defaults) and
    // is unit-proven strictly below it, so its two detectors (downlink silence
    // and ACK stall) fire before quinn's idle timer instead of being masked by
    // it.
    let keep_alive_secs = c.keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    let idle_secs = tuning.idle_timeout_secs;
    let watchdog_secs = myquic2::watchdog_silence_secs(idle_secs);
    let watchdog_silence = Duration::from_secs(watchdog_secs);
    // Selection-time path health: how long a live slot's inbound progress may
    // be frozen before `pick_tcp_index` re-picks a new flow away from it. It is
    // strictly above a healthy idle connection's worst-case stamp age
    // (keepalive + one watchdog poll tick) and strictly below the silence
    // watchdog, so a blackholed slot stops receiving *new* flows well before
    // the watchdog force-closes it (22 s vs 40 s at the shipped defaults; see
    // `data_stale_threshold_ms`).
    let data_stale_ms = data_stale_threshold_ms(keep_alive_secs, watchdog_secs);
    info!(
        "liveness: keepalive={keep_alive_secs}s idle={idle_secs}s \
         watchdog={watchdog_secs}s stale={data_stale_ms}ms"
    );

    let conns = c.conn_count();
    let udp_fail_closed = c.udp_fail_closed();
    let udp_split = c.udp_split();
    let udp_interactive = c.udp_interactive_cnt();
    let udp_egress = c.udp_egress_cnt();
    let pool = ConnPool::new_with_bulk_ports(
        conns,
        c.interactive_port_list(),
        c.udp_bulk_port_list(),
        udp_fail_closed,
        udp_split,
        udp_interactive,
        udp_egress,
        data_stale_ms,
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
            " (bulk round-robin + interactive round-robin)"
        } else {
            " (single connection: interactive and bulk share slot 0)"
        },
        if udp_split {
            udp_interactive + udp_egress
        } else {
            1
        },
        if udp_split {
            let first_bulk = pool.udp_global_slot(pool.interactive_shards());
            format!(
                "interactive shards {}..{}, bulk shards {}..{}",
                pool.udp_global_slot(0),
                pool.udp_global_slot(0) + pool.interactive_shards() - 1,
                first_bulk,
                first_bulk + udp_egress - 1
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
    // Concurrent UDP-association cap: process-wide, default `MAX_UDP_ASSOCS`
    // (4032). Each association owns its own relay socket whose kernel
    // send/receive buffer caps dominate its cost (~256 KiB on Linux after the
    // kernel's SO_*BUF doubling) plus an ~8.3 KiB userspace reader buffer, so a
    // RAM-tight router lowers `max_udp_assocs` instead of paying for the full
    // set. Past the cap a UDP ASSOCIATE is refused with SOCKS REP=0x01 (one
    // rate-limited warn line per window, like the SOCKS admission cap).
    let udp_assocs = c.udp_assoc_count();
    let hub: Arc<UdpHub> = Arc::new(UdpHub::with_capacity(udp_assocs));
    info!("udp associations: max {udp_assocs} concurrent (max_udp_assocs)");
    let egress_shared: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // One DATAGRAM dispatcher and one reconnect loop per pool slot.
    // Every slot keeps its own reassembler, which is correct because a
    // payload's fragments all travel on the connection that carried them.
    // Each connection carries its own class: the interactive ports and the UDP
    // associations have connections no bulk flow can queue on.
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
        // Core assignment by priority, not by slot index: see
        // `priority_pin_cores`. Computed before spawning so the interactive
        // pair claims the low cores even on a host with fewer cores than pool
        // slots, and so only the cores `main_workers` did not claim are
        // pinned.
        let pin_cores = priority_pin_cores(&pool, main_workers);
        for (i, &pin_core) in pin_cores.iter().enumerate() {
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
                pin_core,
                sock,
                cfg,
                server_str.clone(),
                c.server_name.clone(),
                c.auth_token.clone(),
                c.wire(),
                pool.slot(i),
                hub.clone(),
                egress_shared.clone(),
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
            "client runtime: {} sharded current-thread runtime(s), one pool slot each, plus \
             {main_workers} main-runtime worker(s) for SOCKS/TCP/UDP tasks \
             (Linux: slots pinned in priority order — interactive TCP, interactive UDP, then the \
             rest — up to the core count, and the worker count is sized to the cores they leave \
             over; MYQUIC2_SHARD_RUNTIME=0 restores the shared runtime)",
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
                c.wire(),
                pool.slot(i),
                watchdog_silence,
                i,
                egress_shared.clone(),
            );
        }
        (eps, Vec::new())
    };

    // Parse the SOCKS listen address before any forward listener binds: a typo
    // must not leave forward ports bound while startup rejects the config (and
    // the forward overlap validation uses this address too).
    let listen: SocketAddr = c.socks_listen.parse().context("bad socks_listen")?;

    // Process-wide forwarding budgets, one semaphore per protocol, shared by
    // every listener of that protocol. They exist so forwarding cannot consume
    // the whole relay/session pool and deny the SOCKS endpoint: the default
    // leaves 1/4 of each pool to SOCKS (see `ClientConf::forward_conn_budget` /
    // `forward_session_budget`). They are lifetime permits: a forwarded TCP flow
    // holds one until it closes, a UDP peer session holds one until it is
    // reaped/closed.
    let forward_conn_budget = Arc::new(tokio::sync::Semaphore::new(c.forward_conn_budget()));
    let forward_session_budget = Arc::new(tokio::sync::Semaphore::new(c.forward_session_budget()));
    // The shared process-wide TCP relay semaphore is passed explicitly (instead
    // of each listener fetching the global) so the admission helper is testable
    // with a small semaphore and the startup log can name the same number.
    let relay_limiter = socks_conn_limiter().clone();

    // Config-driven forward listeners: bound and spawned before the SOCKS
    // accept loop so a bind failure aborts startup, and so their first
    // datagram/connection never waits behind SOCKS negotiation.
    let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));
    for spec in tcp_forwards {
        // Spawn first (it binds): a log line must never claim a listener that
        // the following `?` then fails to create.
        let max_conns = spec.max_conns;
        let line = format!(
            "tcp_forward {} -> {} via QUIC (max_conns={max_conns}, \
             forward_conn_budget={}, shared_relay_limit={MAX_SOCKS_CONNS}, bound)",
            spec.listen,
            display_target(&spec.target),
            c.forward_conn_budget()
        );
        forward::spawn_tcp_forward(
            spec,
            pool.clone(),
            egress_shared.clone(),
            timeout,
            shutdown_rx.clone(),
            forward_conn_budget.clone(),
            relay_limiter.clone(),
        )?;
        info!("{line}");
    }
    for spec in udp_forwards {
        let listen = spec.listen;
        let max_sessions = spec.max_sessions;
        let target = display_target(&spec.target);
        forward_udp::spawn_udp_forward(
            spec,
            pool.clone(),
            hub.clone(),
            egress_shared.clone(),
            shutdown_rx.clone(),
            forward_session_budget.clone(),
        )?;
        info!(
            "udp_forward {listen} -> {target} (max_sessions={max_sessions}, \
             forward_session_budget={}, per-peer sessions, 180s idle reap)",
            c.forward_session_budget()
        );
    }

    let li = tokio::net::TcpListener::from_std(tcp_listener_dual(&c.socks_listen)?)?;
    info!(
        "socks5 listening on {listen} -> QUIC {server_str_log} (dns=server-side, token={}, tls13-pinned, 0rtt)",
        if c.auth_token.is_empty() { "off" } else { "on" }
    );
    spawn_udp_reporter();
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
                    // the proxy for every other client. Rate-limited: this loop
                    // fires up to 20x/s while fds are exhausted, and formatting
                    // one line per failure would pay tracing's process-wide
                    // writer lock plus a blocking stdout write on the same
                    // runtime as the TCP pumps.
                    if let Some(sup) = claim_accept_failed_log() {
                        warn!("accept failed: {e:#}; continuing{sup}");
                    }
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
                // Admission cap: peer-driven, one drop per accepted connection
                // while the cap is held. Rate-limited like the server's
                // "refusing new connection" line so a local flood cannot make
                // the logging the bottleneck it is reporting on.
                if let Some(sup) = claim_socks_limit_log() {
                    warn!("socks connection limit {MAX_SOCKS_CONNS} reached; dropping {peer}{sup}");
                }
                continue; // socket closes on drop
            }
        };
        let pool = pool.clone();
        let hub = hub.clone();
        let egress_shared = egress_shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks(sock, pool, hub, egress_shared, timeout).await {
                // Rate-limited: `handle_socks` returns an error once per failed
                // TCP flow, and during a pool outage that is once per accepted
                // connection. The line (and the `{e:#}` chain formatting behind
                // it) is built only by the window's winner.
                warn_socks_end(peer, &e);
            }
        });
    }
    Ok(())
}

/// Never-claimed sentinel for the per-window log slots below.
///
/// The lib's `NEVER_WARNED` is crate-private and a bin cannot name it; a
/// `0`-initialised slot instead swallows the process's first window, because
/// the mono epoch starts at process start and `now - 0 < LOG_WINDOW_MS` holds
/// for the first second — which is exactly the startup/reconnect burst these
/// peer-driven lines exist for. The helper's contract (`u64::MAX` means never
/// claimed) is locked from here by `never_logged_sentinel_claims_immediately`
/// in the client tests, the same way the server bin locks its copy.
const NEVER_LOGGED: u64 = u64::MAX;

/// Display form for a rate-limited line's suppressed count, mirroring the
/// server's `reporter::Suppressed`: empty in the common window with no losers,
/// so a caller can append it unconditionally and the normal case reads exactly
/// as before.
struct Suppressed(u64);

impl std::fmt::Display for Suppressed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            return Ok(());
        }
        write!(f, " ({} similar suppressed in the last second)", self.0)
    }
}

/// Claim the one-per-window slot for the `accept`-error line.
///
/// Split from the message so the error chain is formatted only when the line
/// will actually be emitted: an fd-exhaustion loop otherwise pays a blocking
/// stdout write (under tracing's process-wide writer lock) up to 20x/s on the
/// runtime serving the TCP pumps. `None` means this call was counted and must
/// stay silent.
fn claim_accept_failed_log() -> Option<Suppressed> {
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// Claim the one-per-window slot for the SOCKS admission-cap drop line. A
/// separate slot from [`claim_accept_failed_log`]: the two are different
/// faults, and a flood of one must not silence the other.
fn claim_socks_limit_log() -> Option<Suppressed> {
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()).map(Suppressed)
}

/// Rate-limited per-connection SOCKS failure line: one line per window, with
/// the number of failures the previous window swallowed folded into it.
///
/// `handle_socks` returns an error once per failed flow, so during a pool
/// outage this is one formatted line per accepted connection — and the
/// formatting plus the blocking stdout write run on the same runtime as the TCP
/// pumps, the exact cost this line is trying to report. The only work a
/// suppressed call does is two relaxed atomic ops.
fn warn_socks_end(peer: SocketAddr, err: &anyhow::Error) {
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    if let Some(n) = claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()) {
        warn!("socks {peer} end: {err:#}{}", Suppressed(n));
    }
}

/// How long a slot shard keeps its endpoint's driver alive after closing it,
/// so quinn can flush `CONNECTION_CLOSE` frames to the server. Same budget the
/// shared-runtime path spends in one `wait_idle` timeout.
const SLOT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Core assignment for the sharded topology: rank every pool slot by how much
/// its latency matters, then pin rank `r < usable` to core `r`, where
/// `usable = cores - app_workers` is what [`main_runtime_workers`] left over.
///
/// The old shape pinned by slot index (`idx < cores`), so on a host with fewer
/// cores than `tcp_slots` plus the UDP range the interactive **UDP** slots
/// (which carry every small-datagram and interactive-port association) were
/// left unpinned and floated between cores while a bulk TCP slot kept a core.
/// Priority order: TCP slot 0 (interactive) first, then every interactive UDP
/// shard, then the remaining TCP slots, then the remaining UDP (bulk) shards.
///
/// `app_workers` is the main runtime's worker count, so the cores that pool was
/// sized for are never handed to a pinned slot: the split that
/// [`main_runtime_workers_for`] promises is only real if a pinned slot thread
/// and a work-stealing worker do not share a core. Slots past `usable` get
/// `None` and float, so a pool wider than the machine is still balanced by the
/// scheduler. On hosts where workers == cores nothing is pinned (`usable`
/// floors at one), which matches the no-op `pin_to_core` there.
fn priority_pin_cores(pool: &ConnPool, app_workers: usize) -> Vec<Option<usize>> {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let usable = cores.saturating_sub(app_workers).max(1);
    let mut order: Vec<usize> = Vec::with_capacity(pool.slots_total());
    order.push(0);
    if pool.udp_split {
        order.extend(
            pool.udp_class_slots(EgressClass::Interactive)
                .map(|i| pool.udp_global_slot(i)),
        );
        order.extend(1..pool.tcp_slots());
        order.extend(
            pool.udp_class_slots(EgressClass::Bulk)
                .map(|i| pool.udp_global_slot(i)),
        );
    } else {
        order.extend(1..pool.tcp_slots());
        order.push(pool.udp_global_slot(0));
    }
    debug_assert_eq!(order.len(), pool.slots_total());
    let mut pin_cores = vec![None; pool.slots_total()];
    for (rank, &slot) in order.iter().enumerate() {
        if rank < usable {
            pin_cores[slot] = Some(rank);
        }
    }
    pin_cores
}

/// One client pool slot: a dedicated OS thread that owns its QUIC endpoint end
/// to end — its own current-thread tokio runtime (pinned to `pin_core` on
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
    pin_core: Option<usize>,
    sock: std::net::UdpSocket,
    cfg: quinn::ClientConfig,
    server: String,
    server_name: String,
    auth: String,
    wire: Wire,
    slot: ConnSlot,
    hub: Arc<UdpHub>,
    egress: Arc<SharedEgress>,
    watchdog_silence: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("myquic2-slot-{idx}"))
        .spawn(move || {
            // Pinned before the runtime is built, so the runtime thread itself,
            // its endpoint driver and every task it spawns stay on the core.
            // `None` means this slot is past the machine's core count (see
            // `priority_pin_cores`) and is left to the scheduler.
            if let Some(core) = pin_core {
                myquic2::linux::pin_to_core(core);
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
                    wire,
                    slot,
                    watchdog_silence,
                    idx,
                    egress,
                );
                let _ = ready.send(Ok(()));
                let _ = shutdown.wait_for(|v| *v).await;
                ep.close(0u32.into(), b"shutdown");
                let _ = tokio::time::timeout(SLOT_DRAIN_TIMEOUT, ep.wait_idle()).await;
            });
        })
        .context("spawn client slot shard")
}
