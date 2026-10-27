//! myquic2-server: QUIC ingress -> TCP/UDP dial-out. BBR+GSO defaults, self-signed TLS13.
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use myquic2::mqp::wire::Wire;
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
#[cfg(test)]
mod tests_0rtt;

use crate::{
    accept::*, auth::*, forward::*, memo::*, pin::*, reader::*, reporter::*, table::*, tcp::*,
};

// mimalloc on every target (see Cargo.toml): the shipped static / OpenWrt
// binaries link musl, whose allocator measured well behind glibc on the UDP
// soak; on glibc it measured neutral, and one allocator keeps the hot-path
// allocation profile identical between the dev machine and the router.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Map the server config's `udp_full_cone` opt-in onto the session reply policy.
///
/// Pure so the config → policy edge (`udp_full_cone = true` ⇒
/// [`ReplyFilter::FullCone`]) is pinned by a unit test below `main`, instead of
/// being observable only through a live accept loop.
fn reply_filter(c: &ServerConf) -> ReplyFilter {
    if c.udp_full_cone {
        ReplyFilter::FullCone
    } else {
        ReplyFilter::Restricted
    }
}

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
    let c: ServerConf = load_toml(&a.config)?;
    // Wire revision: validate the `wire_rev`/ALPN pair before any socket or
    // TLS work. The revision is carried by ALPN and never negotiated, so a bad
    // value (or a rev2 ALPN label pinned together with rev3) must fail startup
    // instead of silently selecting a wire the peer cannot speak.
    c.validate_wire_rev()?;
    if c.auth_token.len() > AUTH_TOKEN_MAX_BYTES {
        anyhow::bail!(
            "auth_token is {} B, over the {AUTH_TOKEN_MAX_BYTES} B wire cap (server only reads the first {AUTH_TOKEN_MAX_BYTES} B, so a longer token can never authenticate)",
            c.auth_token.len()
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
    let listen: SocketAddr = c.listen.parse().context("bad listen")?;

    if is_placeholder_token(&c.auth_token) {
        warn!(
            "auth_token is a placeholder from the sample config; set a private shared secret (or an empty token with firewall isolation)"
        );
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
    let alpn = c.alpn_bytes();
    info!(
        "application wire: rev{} (ALPN {})",
        c.wire().rev(),
        String::from_utf8_lossy(&alpn)
    );
    let tls = server_tls_config(cert, key, &alpn)?;
    if c.alpn.as_deref().is_some_and(|s| !s.is_empty()) {
        info!(
            "custom ALPN in use (both sides must match; ALPN does not encode the wire \
             revision by default, so pin distinct labels across revisions for a \
             handshake-level skew gate)"
        );
    }
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let tuning = c.tuning();
    let congestion = Congestion::from_config(&c.congestion);
    let keep_alive_secs = c.keep_alive_secs.clamp(1, KEEP_ALIVE_MAX_SECS);
    scfg.transport_config(build_transport_tuned(congestion, keep_alive_secs, tuning));
    // QUIC ingress: `quic_endpoints` endpoints, each bound to `listen` with
    // its own receive loop — on Linux they share the port as a `SO_REUSEPORT`
    // group and the kernel spreads connections across it (the default there;
    // see `default_quic_endpoints` for the platform rule). The first
    // per-packet cost on the server was single-threaded — one endpoint driver
    // did every receive syscall, version check and CID lookup for the whole
    // process — and the group is what moves it off one core; the kernel pins
    // each connection to one member by its 4-tuple (see
    // `udp_socket_dual_reuseport` for the NAT-rebind and same-host-group
    // caveats). A single-endpoint deployment keeps the strict singleton
    // socket, no REUSEPORT at all.
    let rt = Arc::new(quinn::TokioRuntime);
    let want_endpoints = c.endpoint_count();
    if want_endpoints > 1 && !reuse_port_ingress_supported() {
        warn!(
            "quic_endpoints={want_endpoints} requested but this platform has no SO_REUSEPORT; \
             using a single ingress endpoint"
        );
    }
    let ep_count = if reuse_port_ingress_supported() {
        want_endpoints
    } else {
        1
    };
    if ep_count > 1 && !cfg!(target_os = "linux") {
        // Explicit request on a platform whose kernel does not spread a
        // REUSEPORT group (measured on macOS: the whole group's traffic goes
        // to the most recently bound member; the default there is already 1,
        // so this only fires for an explicit setting).
        warn!(
            "quic_endpoints={ep_count} on a platform that delivers a REUSEPORT group to a \
             single member: the extra endpoints add sockets and idle driver tasks, not \
             ingress parallelism"
        );
    }
    info!(
        "server listening on {listen} congestion={} gso_auto={} endpoints={ep_count} \
         keepalive={keep_alive_secs}s idle={}s (quinn-udp probes UDP_SEGMENT/GRO)",
        Congestion::from_config(&c.congestion),
        c.gso,
        tuning.idle_timeout_secs
    );
    if !c.gso {
        warn!(
            "gso=false requested: quinn still uses GRO/GSO if kernel supports; set only affects logging"
        );
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
    // Process-wide *fixed* terms, charged once against the memory budget
    // before the remainder is divided into connections — none of them scales
    // with the admitted-connection count, so charging them per connection (or
    // not at all, as the endpoint and relay-pump terms previously were) would
    // understate what the process can actually pin:
    // - the UDP session pool: every session owns a kernel socket (two
    //   directions, doubled by the Linux kernel) plus its reply reader's
    //   userspace buffer, and `MAX_SESSIONS_GLOBAL` permits are shared by every
    //   peer;
    // - every QUIC ingress endpoint's resident userspace receive buffer plus
    //   its kernel socket caps;
    // - the TCP relay pump buffers of the whole process-wide stream-task pool
    //   (two 16 KiB userspace buffers per active relay flow) plus the relay
    //   sockets' kernel `SO_SNDBUF`/`SO_RCVBUF` caps, which the userspace
    //   figures alone did not count (MEM-3);
    // - the UDP retry pool (16 shards x (256 queued + 16 in flight) x 8 KiB
    //   payloads): peer-driven, because a black-holed target / full sndbuf makes
    //   `WouldBlock` the steady state;
    // - the DNS slow-path waiter set (1,024 permits x payload + host + task):
    //   every unique unresolvable domain spawns one waiter until it times out;
    // - per-worker thread-locals (recvmmsg burst scratch + session buffer pool)
    //   on the threads that run the ingress/dispatcher paths;
    // - quinn's stream-reassembly gap-span metadata for the streams parked in
    //   the header-read stage (`HEADER_TASK_CREDIT`): each accepted stream can
    //   hold up to 1024 spans, and flow control counts payload bytes, not that
    //   metadata. This was the largest uncharged term (a peer could park
    //   ~400 MiB with one 8 MiB receive window before it was charged).
    // This is also what the "worst case" line below now prints, so the printed
    // figure matches the bound the admission cap was computed from.
    let per_session_bytes = per_session_memory_bytes();
    let session_pool_bytes = session_pool_memory_bytes(MAX_SESSIONS_GLOBAL);
    let endpoint_bytes = endpoint_memory_bytes(ep_count);
    let pump_bytes = stream_pump_memory_bytes(MAX_STREAM_TASKS);
    let retry_pool_bytes = retry_pool_memory_bytes();
    let dns_inflight_bytes = dns_inflight_memory_bytes();
    // Scratch lives on the threads that run datagram readers: one per ingress
    // shard with the sharded topology, or the shared runtime's worker count when
    // that topology is disabled.
    let scratch_threads = if shard_runtime_enabled() {
        ep_count
    } else {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    };
    let worker_scratch = worker_scratch_bytes(scratch_threads);
    let assembler_bytes = stream_assembler_memory_bytes(HEADER_TASK_CREDIT);
    let fixed_bytes = session_pool_bytes
        .saturating_add(endpoint_bytes)
        .saturating_add(pump_bytes)
        .saturating_add(retry_pool_bytes)
        .saturating_add(dns_inflight_bytes)
        .saturating_add(worker_scratch)
        .saturating_add(assembler_bytes);
    let cap = admission_cap(conn_cap, c.max_peer_memory_mb, per_conn_bytes, fixed_bytes);
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(cap));
    let pending_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UNAUTH_CONNECTIONS.min(cap)));
    let transport_mib = (per_conn_bytes as u128 * cap as u128) / (1024 * 1024);
    let session_mib = session_pool_bytes / (1024 * 1024);
    let endpoint_mib = endpoint_bytes / (1024 * 1024);
    let pump_mib = pump_bytes / (1024 * 1024);
    let retry_mib = retry_pool_bytes / (1024 * 1024);
    let dns_mib = dns_inflight_bytes / (1024 * 1024);
    let scratch_mib = worker_scratch / (1024 * 1024);
    let assembler_mib = assembler_bytes / (1024 * 1024);
    let worst_mib = transport_mib
        + (session_mib
            + endpoint_mib
            + pump_mib
            + retry_mib
            + dns_mib
            + scratch_mib
            + assembler_mib) as u128;
    info!(
        "admission: up to {cap} connection(s); worst case {worst_mib} MiB pinned \
         ({transport_mib} MiB transport at {per_conn_bytes} B/connection + {session_mib} MiB \
         UDP session pool for {MAX_SESSIONS_GLOBAL} sessions at {per_session_bytes} B each + \
         {endpoint_mib} MiB for {ep_count} QUIC ingress endpoint(s) + {pump_mib} MiB TCP relay \
         pump buffers for {MAX_STREAM_TASKS} flows + {retry_mib} MiB UDP retry pool + {dns_mib} MiB \
         DNS waiters + {scratch_mib} MiB worker scratch on {scratch_threads} thread(s) + \
         {assembler_mib} MiB quinn stream-assembly metadata for {HEADER_TASK_CREDIT} parked \
         stream(s); auth={}, configured cap={conn_cap}{})",
        if auth_enabled { "on" } else { "off" },
        match c.max_peer_memory_mb {
            Some(mb) => format!(", memory budget {mb} MiB"),
            None => String::new(),
        }
    );
    if worst_mib > 1024 {
        warn!(
            "admission: worst case {worst_mib} MiB of peer-pinnable memory at {cap} \
             connection(s); set max_peer_memory_mb (e.g. 128) on a host with less RAM than \
             that, or lower the windows, MYQUIC2_SESS_SOCKET_BUF, or quic_endpoints"
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
        let budget = mb.clamp(1, 1 << 20).saturating_mul(1024 * 1024);
        if cap < conn_cap {
            info!(
                "memory budget {mb} MiB binds the connection cap: {cap} of {conn_cap} \
                 admitted (raise max_peer_memory_mb, lower the windows, lower \
                 MYQUIC2_SESS_SOCKET_BUF, or lower quic_endpoints to admit more)"
            );
        }
        if fixed_bytes >= budget {
            let fixed_mib = fixed_bytes / (1024 * 1024);
            warn!(
                "memory budget {mb} MiB is at or below the {fixed_mib} MiB process-wide fixed \
                 term (UDP session pool {session_mib} MiB + {endpoint_mib} MiB ingress sockets + \
                 {pump_mib} MiB TCP relay pump buffers), so only one connection is admitted: \
                 raise max_peer_memory_mb above the fixed term, or lower \
                 MYQUIC2_SESS_SOCKET_BUF / quic_endpoints on a RAM-tight host"
            );
        }
    }
    if !auth_enabled {
        warn!(
            "auth_token is empty: the QUIC endpoint accepts any peer (rely on firewall/network isolation)"
        );
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
    if c.udp_full_cone {
        warn!(
            "udp_full_cone = true: every UDP association's relay socket forwards replies from \
             ANY source (full-cone NAT semantics), so client apps' UDP endpoints accept \
             unsolicited internet traffic: it is not covered by auth_token, there is no \
             per-session inbound rate limit, and inbound traffic keeps the association alive; \
             this only becomes externally reachable if the server's ephemeral relay UDP ports \
             survive this host's firewall/NAT"
        );
        // Each half looks benign alone: full-cone admits any source, and
        // allow_private lets a relay dial private/loopback destinations. Together
        // they let an unsolicited or source-spoofed sender steer replies into
        // local networks — the reflection shape a public exit node must not have.
        if c.allow_private {
            warn!(
                "udp_full_cone + allow_private = true: an unsolicited or source-spoofed \
                 datagram can make a client app reply toward private/loopback targets, so this \
                 server can be steered to send UDP into local networks; keep allow_private = \
                 false unless proxying those targets is the point"
            );
        }
    }
    spawn_udp_reporter();
    // One accept loop per endpoint, all sharing the admission budgets — the
    // connection cap is process-wide, not per-endpoint. The loops are
    // independent from here on: each pulls from its own endpoint's incoming
    // queue, so a peer stuck mid-handshake (or a full accept queue) on one
    // endpoint cannot stall another endpoint's accepts.
    let st = Arc::new(AcceptState {
        conn_limit: conn_limit.clone(),
        pending_limit: pending_limit.clone(),
        pending_by_ip: PendingAddrSlots::new(),
        auth_token,
        auth_enabled,
        allow_private: c.allow_private,
        reply_filter: reply_filter(&c),
        wire: c.wire(),
        cap,
    });
    // Orderly-shutdown flag shared with every accept loop: closing an endpoint
    // makes `accept` resolve `None`, which without this flag is
    // indistinguishable from a dead driver (see `accept_loop`).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Ingress topology. Sharded (the default; `MYQUIC2_SHARD_RUNTIME=0`
    // disables): every endpoint is created *inside* its own pinned
    // current-thread runtime, so its driver, accept loop, connection tasks and
    // all of their thread-local state (DNS/session memos, the burst buffer)
    // stay on one core — which is what the REUSEPORT group is for. Shared
    // (the pre-sharding topology): every endpoint runs on the multi-thread
    // runtime and work-stealing may migrate tasks between workers.
    let (eps, mut shard_joins, mut accepts, mut fail_rx) = if shard_runtime_enabled() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<quinn::Endpoint, String>>();
        let (fail_tx, fail_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let mut joins = Vec::with_capacity(ep_count);
        for idx in 0..ep_count {
            let sock = udp_socket_dual_for_ingress(&c.listen, ep_count > 1)?;
            joins.push(spawn_ingress_shard(
                idx,
                sock,
                scfg.clone(),
                rt.clone(),
                st.clone(),
                shutdown_rx.clone(),
                ready_tx.clone(),
                fail_tx.clone(),
            )?);
        }
        // A shard always reports once (Ok with its endpoint, or Err when it
        // cannot start); a disconnect instead of a report means the thread
        // died before that, and both are fatal at startup.
        drop(ready_tx);
        let mut eps = Vec::with_capacity(ep_count);
        for idx in 0..ep_count {
            match ready_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(ep)) => eps.push(ep),
                Ok(Err(e)) => anyhow::bail!("ingress shard {idx} failed to start: {e}"),
                Err(e) => anyhow::bail!("ingress shard {idx} did not report ready: {e}"),
            }
        }
        info!(
            "ingress runtime: {ep_count} sharded current-thread runtime(s), one endpoint each \
             (Linux: pinned one per core; MYQUIC2_SHARD_RUNTIME=0 restores the shared runtime)"
        );
        (eps, joins, tokio::task::JoinSet::new(), Some(fail_rx))
    } else {
        let mut eps = Vec::with_capacity(ep_count);
        for _ in 0..ep_count {
            let sock = udp_socket_dual_for_ingress(&c.listen, ep_count > 1)?;
            eps.push(quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(scfg.clone()),
                rt.wrap_udp_socket(sock)?,
                rt.clone(),
            )?);
        }
        let mut accepts = tokio::task::JoinSet::new();
        for ep in &eps {
            accepts.spawn(accept_loop(ep.clone(), st.clone(), shutdown_rx.clone()));
        }
        (eps, Vec::new(), accepts, None)
    };
    // SIGTERM/SIGINT: stop accepting and close every endpoint so all peers get
    // an immediate CONNECTION_CLOSE and redial, instead of a silent blackhole
    // until their watchdogs fire. No drain window — in-flight flows restart
    // via the client's reconnect loops; the bounded wait is only for quinn to
    // flush the close frames, shared as one deadline across all endpoints so a
    // wide ingress cannot multiply the shutdown delay.
    let mut shutdown = std::pin::pin!(shutdown_signal());
    let driver_lost = if let Some(fail_rx) = fail_rx.as_mut() {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received: closing endpoints so peers redial immediately");
                false
            }
            ended = fail_rx.recv() => {
                // A shard's accept loop ended before any shutdown was
                // requested: its endpoint driver stopped (socket failure) or
                // the loop panicked. That share of the ingress is permanently
                // dark, so fail fast: exiting non-zero lets a supervisor
                // restart the process instead of silently serving from a
                // fraction of the socket group.
                error!("QUIC ingress shard {ended:?} stopped (driver failure?); exiting");
                true
            }
        }
    } else {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received: closing endpoints so peers redial immediately");
                false
            }
            ended = accepts.join_next() => {
                // An endpoint's driver stopped (socket failure) or its loop
                // panicked. That share of the ingress is permanently dark, so fail
                // fast: exiting non-zero lets a supervisor restart the process
                // instead of silently serving from a fraction of the socket group.
                error!("QUIC endpoint accept loop ended ({ended:?}); exiting");
                true
            }
        }
    };
    // Set the flag before anything can make `accept` resolve `None`: each loop
    // can then tell "endpoint closed for shutdown" from "driver died".
    let _ = shutdown_tx.send(true);
    // Stop the accept loops *before* closing the endpoints: a closed endpoint
    // makes `accept` resolve `None`, the same shape as a dead socket, and the
    // loops would report this orderly shutdown as a driver failure.
    accepts.shutdown().await;
    for ep in &eps {
        ep.close(0u32.into(), b"shutdown");
    }
    if shard_joins.is_empty() {
        // Shared-runtime ingress: one deadline for every endpoint's close
        // flush, as before.
        let deadline = tokio::time::Instant::now() + SHARD_DRAIN_TIMEOUT;
        for ep in &eps {
            let _ = tokio::time::timeout_at(deadline, ep.wait_idle()).await;
        }
    } else {
        // Sharded ingress: each shard owns its endpoint's drain (it keeps its
        // runtime — and with it the driver that flushes the close frames —
        // alive until `wait_idle` resolves or the same budget expires), so
        // joining is bounded by that budget, not by a multiplied one.
        for j in shard_joins.drain(..) {
            let _ = j.join();
        }
    }
    if driver_lost {
        anyhow::bail!("QUIC ingress endpoint driver stopped; exiting for a supervisor restart");
    }
    Ok(())
}

/// How long a shard keeps its endpoint's driver alive after the endpoint is
/// closed, so quinn can flush CONNECTION_CLOSE frames to every peer. Same
/// budget the shared-runtime path spends in one `wait_idle` timeout.
const SHARD_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// One ingress shard: a dedicated OS thread that owns a QUIC endpoint end to
/// end — its own current-thread tokio runtime (pinned to one core on Linux),
/// UDP socket, CID table, driver task, accept loop and connection tasks. All
/// of the per-packet thread-local state the connection handlers keep then
/// lives on the core that serves it, instead of migrating between
/// work-stealing workers and going cold at each hop.
///
/// The endpoint is created on this thread because quinn spawns its driver
/// onto the *ambient* runtime: building it on the shared runtime would pin
/// the driver there and leave the shard serving nothing. The handle is sent
/// back over `ready` for main to close at shutdown; `fail` reports a
/// pre-shutdown exit of `accept_loop` (a dead driver), which main treats as
/// fatal — the same contract the shared-runtime path has via its `JoinSet`.
#[allow(clippy::too_many_arguments)]
fn spawn_ingress_shard(
    idx: usize,
    sock: std::net::UdpSocket,
    scfg: quinn::ServerConfig,
    rt: Arc<quinn::TokioRuntime>,
    st: Arc<AcceptState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    ready: std::sync::mpsc::Sender<Result<quinn::Endpoint, String>>,
    fail: tokio::sync::mpsc::UnboundedSender<usize>,
) -> Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("myquic2-ingress-{idx}"))
        .spawn(move || {
            myquic2::linux::pin_to_core(idx);
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
                let ep = match rt.wrap_udp_socket(sock) {
                    Ok(sock) => match quinn::Endpoint::new_with_abstract_socket(
                        quinn::EndpointConfig::default(),
                        Some(scfg),
                        sock,
                        rt.clone(),
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
                let _ = ready.send(Ok(ep.clone()));
                if accept_loop(ep.clone(), st, shutdown).await {
                    // Driver failure: report promptly so main can fail fast;
                    // the drain below still bounds this thread's exit.
                    let _ = fail.send(idx);
                }
                // Keep this runtime — and with it the driver that flushes
                // CONNECTION_CLOSE frames — alive until the endpoint is idle
                // or the drain budget expires; the runtime and any straggler
                // task are then dropped with the thread.
                let _ = tokio::time::timeout(SHARD_DRAIN_TIMEOUT, ep.wait_idle()).await;
            });
        })
        .context("spawn ingress shard")
}

/// Everything an endpoint's accept loop needs. The admission semaphores and
/// the credential are shared across endpoints on purpose: the documented
/// connection cap is what the *process* admits, however many ingress
/// endpoints run.
/// Maximum connections one source IP may hold in the pending
/// (handshake + pre-auth) window at a time.
///
/// The process-wide pre-auth budget is a *count* ([`MAX_UNAUTH_CONNECTIONS`],
/// or `conn_limit` when the token is empty), and a peer only has to stall a
/// handshake for `PRE_AUTH_TIMEOUT`/`HANDSHAKE_TIMEOUT` (5-10 s) to keep one
/// slot: ~26-51 stalled handshakes per second from a single host denied every
/// new connection, legitimate token holders included. A per-source share makes
/// that denial cost several source IPs instead of one host for the whole
/// budget.
///
/// The value is sized for legitimate bursts, not just for attackers: one client
/// opens all of its pool connections concurrently (seven at the shipped
/// defaults) and a NAT/CGNAT IP can aggregate several clients, so a small
/// number would refuse real dials and force client retries. 16 is above any
/// single client's burst and still means filling the 256-slot tokenless budget
/// needs 16 distinct source IPs. A refusal here is counted and the client
/// retries, so the failure mode is a transient dial delay rather than a drop.
pub(crate) const MAX_PENDING_PER_IP: usize = 16;

/// Connections refused by the per-source pending share (distinct from the
/// process-wide `pending_limit` refusals).
pub(crate) static PENDING_PER_IP_REFUSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Per-source-IP accounting for the pending window.
///
/// Bounded by construction: an entry exists only while that IP holds at least
/// one pending connection, and the process-wide pending budget bounds the live
/// total, so a spoofed-source flood cannot grow the map past the number of
/// admitted pending slots.
#[derive(Debug, Default)]
pub(crate) struct PendingAddrSlots {
    by_ip: parking_lot::Mutex<HashMap<IpAddr, u16>>,
}

impl PendingAddrSlots {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            by_ip: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    /// Reserve one pending slot for `ip`; `None` when the IP already holds its
    /// share.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PendingAddrGuard> {
        let mut map = self.by_ip.lock();
        let n = map.entry(ip).or_insert(0);
        if usize::from(*n) >= MAX_PENDING_PER_IP {
            return None;
        }
        *n += 1;
        Some(PendingAddrGuard {
            slots: Arc::clone(self),
            ip,
        })
    }
}

/// One source IP's pending reservation; releases on every exit path (handshake
/// failure, timeout, auth failure, or handover to the live connection).
#[derive(Debug)]
pub(crate) struct PendingAddrGuard {
    slots: Arc<PendingAddrSlots>,
    ip: IpAddr,
}

impl Drop for PendingAddrGuard {
    fn drop(&mut self) {
        let mut map = self.slots.by_ip.lock();
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// One ingress endpoint's accept state plus the admission budgets it shares
/// with every other endpoint of this process.
#[derive(Debug)]
struct AcceptState {
    /// Process-wide admitted-connection budget.
    conn_limit: Arc<tokio::sync::Semaphore>,
    /// Pre-auth (handshake-in-flight) budget: bounds receive-window memory a
    /// peer that never sends a token can pin; see the loop.
    pending_limit: Arc<tokio::sync::Semaphore>,
    /// Per-source share of the same pending window (see
    /// [`MAX_PENDING_PER_IP`]): one host cannot stall the whole budget.
    pending_by_ip: Arc<PendingAddrSlots>,
    auth_token: Arc<Vec<u8>>,
    auth_enabled: bool,
    allow_private: bool,
    /// Reply-source policy for every session of every connection this process
    /// admits (`udp_full_cone`): snapshot per connection at accept time.
    reply_filter: ReplyFilter,
    /// Application-layer wire revision every admitted connection speaks
    /// (`wire_rev`, fixed for the process; ALPN defaults to the shared `h3`
    /// label for both revisions and is not a wire gate). Threaded into
    /// `handle_conn_with_wire`, which builds the matching connection state,
    /// stager and reassembler — the revision is never sniffed per frame.
    wire: Wire,
    /// Effective admission cap, for logs and `handle_conn`'s stream-pool share.
    cap: usize,
}

/// Accept loop for one ingress endpoint: admit a connection (or refuse it)
/// and hand it to its own task, so one slow/malicious handshake never stalls
/// the accept path — of this endpoint or any other.
///
/// Returns `true` when the endpoint ended *without* a shutdown being
/// requested — a dead driver (socket failure) worth a supervisor restart.
/// `shutdown` is only ever read on that exit path, so it costs the loop
/// nothing per accept.
async fn accept_loop(
    ep: quinn::Endpoint,
    st: Arc<AcceptState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> bool {
    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => {
                // A closed endpoint and a dead driver both resolve `None`.
                if *shutdown.borrow() {
                    return false;
                }
                error!("QUIC endpoint driver stopped (socket failure?)");
                return true;
            }
        };
        let permit = match st.conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if warn_once_per_sec() {
                    warn!(
                        "connection limit {} reached; refusing new connection",
                        st.cap
                    );
                }
                drop(incoming); // implicit refuse
                continue;
            }
        };
        // Per-source share of the pending window, taken before the process-wide
        // pre-auth slot: a stalled-handshake flood from one host must not be
        // able to hold every slot and deny new connections process-wide. The
        // guard is released when this connection leaves the pending window
        // (handshake completes in tokenless mode, authentication completes
        // otherwise) or when its task exits on any failure path.
        let remote_ip = incoming.remote_address().ip();
        let ip_guard = match st.pending_by_ip.try_acquire(remote_ip) {
            Some(g) => Some(g),
            None => {
                let n =
                    PENDING_PER_IP_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if warn_once_per_sec() {
                    warn!(
                        "pre-auth per-IP limit {MAX_PENDING_PER_IP} reached from {remote_ip}; \
                         refusing new connection ({n} refused so far)"
                    );
                }
                drop(incoming);
                continue;
            }
        };
        // Bound pre-auth receive-window memory: a peer that never sends a
        // token must not pin the whole MAX_CONNECTIONS budget. Released as
        // soon as `authenticate` returns.
        let pending = if st.auth_enabled {
            match st.pending_limit.clone().try_acquire_owned() {
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
        let allow_private = st.allow_private;
        let reply_filter = st.reply_filter;
        let wire = st.wire;
        let auth_token = st.auth_token.clone();
        // Read by `handle_conn` to size this connection's share of the
        // process-wide stream-task pool (a clone per accepted connection).
        let conn_limit_for_conn = st.conn_limit.clone();
        let cap = st.cap;
        let auth_enabled = st.auth_enabled;
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
            // This task owns the source IP's pending reservation for every exit
            // path; it is released below once the connection leaves the pending
            // window (or dropped with the task on any failure/timeout return).
            let mut ip_guard = Some(ip_guard);
            // 0.5-RTT accept: `incoming.accept()` + `into_0rtt()` yields a
            // usable Connection *before* the handshake completes. On a resumed
            // connection the client's 0-RTT early data (auth token, HELLO, the
            // first UDP datagrams / TCP stream bytes) is readable on it right
            // away, so authentication starts here instead of after
            // `ZeroRttAccepted`: the token is read and verified while the
            // handshake is still in flight, and `handle_conn` then forwards the
            // first-flight payloads. Waiting for the handshake first would put
            // a full round trip back in front of every resumed connection,
            // which is exactly what the 0-RTT work removes.
            //
            // The accepted future is not dropped: a detached monitor owns it so
            // a handshake that stalls past `deadline` or dies is still
            // logged/closed, and (tokenless mode) the per-IP pre-auth guard is
            // released when the handshake settles.
            let (conn, handshake_awaited) = match incoming.accept() {
                Ok(connecting) => match connecting.into_0rtt() {
                    Ok((c, accepted_fut)) => {
                        // Tokenless mode has no token exchange to hold the
                        // pre-auth window, so the monitor ends it at handshake
                        // completion (same point the old await did). With a
                        // token the slot is held until `authenticate` returns.
                        let guard = if auth_enabled { None } else { ip_guard.take() };
                        let monitor_conn = c.clone();
                        tokio::spawn(async move {
                            let _guard = guard;
                            match tokio::time::timeout_at(deadline, accepted_fut).await {
                                Ok(_accepted) => {
                                    // The payload is meaningless on the server
                                    // (quinn only tracks 0-RTT acceptance on the
                                    // client); settling is the signal, and a
                                    // handshake that died shows up as a close
                                    // reason.
                                    #[cfg(test)]
                                    tests_0rtt::probe::handshake_settled();
                                    if let Some(reason) = monitor_conn.close_reason()
                                        && let Some(sup) =
                                            claim_server_log(ServerLog::HandshakeFailed)
                                    {
                                        warn!("client handshake failed: {reason:?}{sup}");
                                    }
                                }
                                Err(_) => {
                                    // The auth deadline backstops this for a
                                    // token connection; the close is the same
                                    // terminal outcome the old await produced.
                                    if let Some(sup) = claim_server_log(ServerLog::HandshakeTimeout)
                                    {
                                        warn!(
                                            "handshake timed out after {handshake_budget:?}{sup}"
                                        );
                                    }
                                    monitor_conn.close(0x01u32.into(), b"handshake timeout");
                                }
                            }
                        });
                        (c, false)
                    }
                    Err(connecting) => match tokio::time::timeout_at(deadline, connecting).await {
                        Ok(Ok(c)) => (c, true),
                        Ok(Err(e)) => {
                            if let Some(sup) = claim_server_log(ServerLog::AcceptError) {
                                warn!("accept err: {e:#}{sup}");
                            }
                            return;
                        }
                        Err(_) => {
                            if let Some(sup) = claim_server_log(ServerLog::HandshakeTimeout) {
                                warn!("handshake timed out after {handshake_budget:?}{sup}");
                            }
                            return;
                        }
                    },
                },
                Err(e) => {
                    if let Some(sup) = claim_server_log(ServerLog::AcceptError) {
                        warn!("accept err: {e:#}{sup}");
                    }
                    return;
                }
            };
            // In tokenless mode the pre-auth window ended with the handshake:
            // immediately for a fully awaited handshake, at settle time via the
            // monitor for the 0.5-RTT path.
            if handshake_awaited && !auth_enabled {
                drop(ip_guard.take());
            }
            // Authentication starts NOW, possibly before the handshake
            // completes: the token may arrive as 0-RTT early data. The deadline
            // is a fresh `AUTH_TIMEOUT` (the handshake is not consuming it any
            // more) and the pre-auth permit/IP guard stay held until it returns.
            // `authenticate` tolerates 0-RTT-rejected/reset/extra uni streams so
            // the client's 1-RTT re-send after a rejection still authenticates.
            if let Err(e) = authenticate(
                &conn,
                &auth_token,
                tokio::time::Instant::now() + AUTH_TIMEOUT,
            )
            .await
            {
                if let Some(sup) = claim_server_log(ServerLog::AuthFailure) {
                    warn!("auth failed from {}: {e:#}{sup}", conn.remote_address());
                }
                conn.close(0x01u32.into(), b"unauthorized");
                return;
            }
            #[cfg(test)]
            tests_0rtt::probe::authenticated();
            // Authentication done: free the pre-auth slot so other new peers
            // can handshake while this connection lives on.
            drop(pending);
            drop(ip_guard.take());
            // Raise the handshake's pre-auth bidi credit to the full
            // client-facing credit now that the peer has proven it holds the
            // token. MAX_STREAMS is increase-only, so this sequence is
            // protocol-legal; it is what keeps an unauthenticated peer from
            // parking a quinn receive assembler per advertised stream (see
            // `SERVER_PRE_AUTH_BIDI_CREDIT`). The pre-auth credit is 64 rather
            // than 4 because a resumed client opens 0-RTT TCP streams against
            // the credit it remembers from its ticket; 64 covers a reconnect
            // burst while the full 8192 stays post-auth only. Uni stays at the
            // pre-auth credit: the client's auth token (early + 1-RTT re-send)
            // needs at most two, and the server never opens one.
            conn.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(MAX_BIDI_STREAMS_PER_CONN));
            #[cfg(test)]
            tests_0rtt::probe::handle_conn_start();
            // The wire-aware entry point: one revision per process, its
            // connection state/stager/reassembler and bidi-accept dispatch are
            // built for that revision (rev2 CONTROL DATAGRAMs vs rev3 reliable
            // control stream marker 0xFF vs TCP atyp).
            if let Err(e) = handle_conn_with_wire(
                conn,
                allow_private,
                reply_filter,
                conn_limit_for_conn,
                cap,
                wire,
            )
            .await
            {
                warn!("conn end: {e:#}");
            }
        });
    }
}
