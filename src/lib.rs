//! MyQUIC2 common: MQP-2 codec + config + TLS13-fast cert + QUIC transport (BBR/GSO).
use anyhow::{Context, Result};
// `Bytes`/`BytesMut` are used by the unit tests below through `use super::*`.
#[allow(unused_imports)]
use bytes::{Bytes, BytesMut};
// `Instant` is used by the unit tests below through `use super::*`.
#[allow(unused_imports)]
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

/// Relay counters (`udp_stats`/`udp_write`) use thread-local batching: one
/// shared atomic update per 256 records instead of one per packet, so the hot
/// path stays off shared cache lines.
macro_rules! stats_only {
    ($($t:tt)*) => {
        {
            $($t)*
        }
    };
}

pub mod config;
pub mod dns;
pub mod mqp;
pub mod stats;
pub mod sync;
pub mod tcp;
pub mod time;
pub mod tls;
pub mod transport;
pub mod udp;

pub use config::{
    client_conf::ClientConf,
    server_conf::ServerConf,
    tuning::{
        load_toml, per_connection_memory_bytes, TransportTuning, DEFAULT_INITIAL_RTT_MS,
        DEFAULT_QUIC_CONNS, INITIAL_RTT_MS_MAX, INITIAL_RTT_MS_MIN, MAX_BIDI_STREAMS_PER_CONN,
        MAX_POOL_CONNS, MAX_UDP_ASSOCS,
    },
};
pub use sync::guards::{
    lock_mutex, lock_read, lock_write, try_lock_mutex, try_lock_read, try_lock_write,
};
pub use time::{coarse::coarse_millis, mono::mono_millis};

pub use mqp::ack::{
    decode_bnd_addr, encode_bnd_addr, encode_bnd_addr_into, encode_tcp_ack_into, normalize_alpn,
    AUTH_TOKEN_MAX_BYTES, MAX_BND_LEN, MAX_TCP_ACK_LEN, MQP_ALPN, MQP_TCP_ACK, MQP_TCP_ACK_MAGIC,
};
pub use mqp::addr::{AddrHeader, TargetAddr, TargetAddrRef};
pub use mqp::batch::{
    batch_sess, decode_batch_ref, encode_batch, is_batch, BatchRef, BATCH_ITEM_OVERHEAD,
    BATCH_PREFIX_LEN, BATCH_SMALL_MAX, MAX_BATCH_ITEMS, MQP_DGRAM_BATCH,
};
pub use mqp::datagram::{
    decode_datagram, decode_datagram_ref, dgram_payload_cap, encode_datagram,
    encode_datagram_ref_with_limit, encode_datagram_with_limit, DGRAM_DEFAULT_LIMIT,
    DGRAM_PREFIX_LEN, MQP_DGRAM_TYPE,
};
pub use mqp::fragment::{
    decode_fragment, dgram_sess, encode_fragment, fragment_chunk_len, FragmentRef,
    FRAG_ID_SAFE_WINDOW_MS, FRAG_MAX_HELD_BYTES, FRAG_MAX_PARTIALS, FRAG_PREFIX_LEN,
    FRAG_SWEEP_INTERVAL_MS, FRAG_TIMEOUT_MS, MIN_PATH_DGRAM_BUDGET, MQP_DGRAM_FRAG,
    MQP_FRAG_MAX_PAYLOAD, MQP_FRAG_MAX_TOTAL, SOCKS_UDP_HDR_MAX, UDP_PAYLOAD_MAX, UDP_RECV_MAX,
    UDP_RECV_SLACK,
};
pub use tls::{
    client_tls_config, gen_self_signed_files, is_placeholder_token, load_cert_der, load_key_der,
    parse_congestion, server_tls_config,
};
pub use transport::{
    build_transport, build_transport_tuned, build_transport_tuned_class, DGRAM_MAX_WIRE,
    KEEP_ALIVE_MAX_SECS, RECEIVE_WINDOW, SEND_WINDOW, STREAM_RECEIVE_WINDOW, TARGET_BDP_BYTES,
    TARGET_LINK_BYTES_PER_SEC, TARGET_LINK_RTT,
};
// `MQP_DGRAM_MAX` / `clamp_keep_alive` are exercised by the unit tests below
// through `use super::*` (`DATAGRAM_BUFFER` is also read by `config::tuning`).
/// Test-only compatibility surface: the unit tests below address the moved
/// DNS internals through the crate root (`use super::*`).
#[allow(unused_imports)]
pub(crate) use dns::{
    dns_cache_for, dns_inflight_for, dns_key, dns_key_owned, dns_memo_hash, dns_memo_set,
    dns_neg_cache_for, dns_shard, memo_peek_both, memo_put, positive_entry_state, record_negative,
    DnsMemoSlot, PositiveState, DNS_CACHE_MAX, DNS_CACHE_MAX_SHARD, DNS_KEY_BUF, DNS_MEMO,
    DNS_NEG_MAX, DNS_NEG_MAX_SHARD, DNS_SHARDS, MEMO_KEY_BYTES, MEMO_SETS, MEMO_WAYS,
};
pub use dns::{
    dns_cache_seed, dns_cache_seed_aged, dns_cache_seed_set, dns_coalesce_drop, dns_coalesce_take,
    dns_coalesce_take_now, dns_coalesce_try_push, dns_coalesce_try_push_to, dns_inflight_seed,
    dns_inflight_status, dns_inflight_unseed, dns_is_inflight, dns_neg_cache_seed,
    dns_slow_path_limiter, is_dns_contended, is_global_ip, lookup_cached_all_fast,
    lookup_cached_all_fast_with_ttl, lookup_cached_fast, lookup_cached_fast_with_ttl,
    lookup_cached_sync, map_for_dual, resolve_all, resolve_all_cached,
    resolve_all_cached_with_contention_retry, resolve_server_addr, resolve_server_side, unmap,
    CachedLookup, CoalesceOutcome, DnsCoalesceGuard, DnsCoalesceQueue, DnsCoalesced, DnsContended,
    DnsInflight, DNS_CACHE_TTL_MS, DNS_COALESCE_CAP, DNS_LOOKUP_TIMEOUT,
};
pub use stats::drops::dgram_drops;
pub use stats::udp_stats::{self, UdpSnapshot};
pub use stats::udp_write::{self, UdpWriteSnapshot};
pub use tcp::{copy_tcp_quic, copy_tcp_quic_acked, copy_tcp_quic_idle};
#[allow(unused_imports)]
pub(crate) use transport::{clamp_keep_alive, DATAGRAM_BUFFER, MQP_DGRAM_MAX};
pub use udp::send_udp_batch;
pub use udp::{
    batch_backend, batch_report, burst_msg_copy, poll_once, record_drain_batch,
    record_extra_syscalls, record_send_group, recv_burst, recvmmsg_available, send_udp_datagram,
    sendmmsg_available, try_send_datagram, udp_try_send, udp_try_send_grouped, udp_try_send_slice,
    DatagramSend, DgramFragmenter, DgramReassembler, PayloadSend, SendFrame, UdpWriteDrop,
    BURST_SLOT, LAST_HOP_DRAIN,
};
// `pub(crate)` re-exports for the unit tests below (`use super::*`); unused in
// the non-test build.
#[allow(unused_imports)]
pub(crate) use stats::{claim_drop_warning, drop_warn_due, NEVER_WARNED};
#[allow(unused_imports)]
pub(crate) use tcp::{reserve_copy_chunk, COPY_CHUNK};
#[allow(unused_imports)]
pub(crate) use udp::{
    frag_id_reuse_blocked, retry_shards, spawn_retry_worker, udp_retry_submit,
    under_retry_deadline, Partial, UdpRetry, UDP_RETRY_DEPTH, UDP_RETRY_INFLIGHT,
    UDP_RETRY_TIMEOUT,
};

/// Dual-stack UDP socket (V6ONLY=0 when bound to ::). Buffer enlarged for GSO bursts.
/// `sess` sockets (per UDP association) should use the small variant to avoid
/// OOM on routers: 4MB x N sessions of kernel memory adds up fast (P3).
pub fn udp_socket_dual(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, 4 * 1024 * 1024)
}

/// Per-session / relay socket buffer, per direction (the default; see
/// [`sess_socket_buf`] for the effective value).
///
/// These are *caps*, not reservations: the kernel only accounts for what is
/// actually queued, but the cap is what a burst can pin. One association moves
/// a single DATAGRAM flow that is already rate-limited by the QUIC congestion
/// window and drained in ≤32-datagram bursts. The kernel charges ~2 KiB of
/// skb overhead per small datagram, so the cap trades burst absorption for a
/// smaller worst case. The aarch64 burst test measured a fixed ~8 dropped
/// packets per association at 64 KiB and ~50 at 16 KiB (128 KiB was zero):
/// 64 KiB is the measured floor and the shipped default, while the kernel side
/// of a full house (8192 server sessions x 128 KiB across both directions) is
/// ~1 GiB. On a RAM-tight router set `MYQUIC2_SESS_SOCKET_BUF=32768` (or
/// `=131072` for zero measured loss on a server); a full-buffer clamp warning
/// names the sysctl to raise otherwise.
pub const SESS_SOCKET_BUF: usize = 64 * 1024;

/// Lower clamp for [`sess_socket_buf`] overrides: below the 16 KiB the burst
/// test measured ~50 drops/association, an override asks for a loss rate the
/// proxy cannot paper over.
pub const SESS_SOCKET_BUF_MIN: usize = 16 * 1024;

/// Upper clamp for [`sess_socket_buf`] overrides: 4 MiB matches the QUIC
/// endpoint's own socket, and past it the per-session kernel cost stops
/// scaling with any real burst.
pub const SESS_SOCKET_BUF_MAX: usize = 4 * 1024 * 1024;

/// Effective per-session / relay socket buffer: [`SESS_SOCKET_BUF`] unless
/// `MYQUIC2_SESS_SOCKET_BUF` (bytes) overrides it, clamped to
/// [`SESS_SOCKET_BUF_MIN`]..=[`SESS_SOCKET_BUF_MAX`].
///
/// Read once per process: the value feeds every session socket and an operator
/// tuning memory/throughput should not be able to change it mid-run per socket.
/// The override exists because the same binary ships to a 1 GiB server and a
/// 128 MiB router; an invalid value falls back to the default (never panics at
/// socket-creation time on a typo).
pub fn sess_socket_buf() -> usize {
    static OVERRIDE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        std::env::var("MYQUIC2_SESS_SOCKET_BUF")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(clamp_sess_socket_buf)
            .unwrap_or(SESS_SOCKET_BUF)
    })
}

/// Clamp an operator-supplied `MYQUIC2_SESS_SOCKET_BUF` value into the
/// supported range. Split out from the env read so the clamp itself is
/// testable without mutating process-global state.
fn clamp_sess_socket_buf(v: usize) -> usize {
    v.clamp(SESS_SOCKET_BUF_MIN, SESS_SOCKET_BUF_MAX)
}

/// Per-session / relay sockets: see [`SESS_SOCKET_BUF`] / [`sess_socket_buf`].
pub fn udp_socket_dual_small(bind: &str) -> Result<std::net::UdpSocket> {
    udp_socket_dual_with_size(bind, sess_socket_buf())
}

pub fn udp_socket_dual_with_size(bind: &str, buf: usize) -> Result<std::net::UdpSocket> {
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
    // No SO_REUSEADDR here: the QUIC socket is a singleton and reuse would let
    // a second instance bind the same port and silently steal packets.
    s.set_nonblocking(true)?;
    if s.set_send_buffer_size(buf).is_err() {
        tracing::debug!("udp send buffer {buf} unavailable (raise net.core.wmem_max)");
    }
    if s.set_recv_buffer_size(buf).is_err() {
        tracing::debug!("udp recv buffer {buf} unavailable (raise net.core.rmem_max)");
    }
    // Linux caps a plain SO_*BUF request at net.core.{r,w}mem_max (OpenWrt
    // ships ~208 KiB). When that happened and the process holds
    // CAP_NET_ADMIN — the norm for an OpenWrt service running as root — retry
    // through SO_*BUFFFORCE, which ignores the sysctl. Best-effort: without
    // the capability the retry fails EPERM and the clamp warning below still
    // names the sysctl to raise.
    #[cfg(target_os = "linux")]
    {
        let short = |actual: Option<usize>| actual.is_some_and(|a| a < buf);
        if short(s.send_buffer_size().ok()) || short(s.recv_buffer_size().ok()) {
            force_udp_buffers(&s, buf);
        }
    }
    // Linux/macOS silently clamp to net.core.{w,r}mem_max; surface the real
    // value once per process — these calls run for every UDP session socket,
    // so warning per socket would flood the log on routers with default
    // (small) rmem_max/wmem_max.
    if let Ok(actual) = s.send_buffer_size() {
        if actual < buf {
            warn_buf_clamped("send", actual, buf);
        }
    }
    if let Ok(actual) = s.recv_buffer_size() {
        if actual < buf {
            warn_buf_clamped("recv", actual, buf);
        }
    }
    s.bind(&addr.into())?;
    Ok(s.into())
}

fn warn_buf_clamped(which: &str, actual: usize, want: usize) {
    // One flag per direction: a shared flag let whichever direction was probed
    // first permanently silence the other, so a host with a small `wmem_max`
    // but a large `rmem_max` never reported the send-side clamp at all.
    static WARNED_SEND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static WARNED_RECV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let (flag, sysctl) = if which == "send" {
        (&WARNED_SEND, "wmem_max")
    } else {
        (&WARNED_RECV, "rmem_max")
    };
    if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "udp {which} buffer clamped to {actual} (< {want}); raise net.core.{sysctl} or grant CAP_NET_ADMIN (SO_*BUFFFORCE); further buffer warnings suppressed"
        );
    }
}

/// Best-effort `SO_SNDBUFFORCE`/`SO_RCVBUFFORCE`: like the plain buffer
/// options, but not clamped by `net.core.{w,r}mem_max`. Requires
/// `CAP_NET_ADMIN`; an EPERM is ignored and the caller's clamp warning still
/// fires.
#[cfg(target_os = "linux")]
fn force_udp_buffers(s: &socket2::Socket, bytes: usize) {
    use std::os::unix::io::AsRawFd;
    let v: libc::c_int = bytes.min(libc::c_int::MAX as usize) as libc::c_int;
    let len = std::mem::size_of_val(&v) as libc::socklen_t;
    // SAFETY: `s` owns a live UDP socket fd, and `&v` points at a valid c_int
    // for the duration of each call.
    unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            &v as *const _ as *const libc::c_void,
            len,
        );
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &v as *const _ as *const libc::c_void,
            len,
        );
    }
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

/// Resolve when the process receives a shutdown request: `SIGTERM` or `SIGINT`
/// on Unix, Ctrl-C elsewhere.
///
/// Both binaries hold this in their accept loops and, on resolution, close the
/// QUIC endpoint so connected peers receive a `CONNECTION_CLOSE` and redial
/// instead of blackholing until their silence watchdog fires. There is no drain
/// window: in-flight flows are interrupted by design (UDP has no
/// retransmission, and the client's reconnect loops re-establish TCP/UDP).
///
/// Signal handlers are registered on first poll, so pin this future once
/// outside the loop rather than rebuilding it per iteration. It performs no
/// work on the accept path until the signal actually arrives.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::warn!("cannot install SIGTERM handler ({e}); listening for ctrl_c only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Consume the MQP-2 TCP-open ACK (`magic | 0x00 | atyp | addr | port`). The
/// magic is checked first: raw application bytes from a pre-magic peer fail
/// here (never parsed as the ACK), as do a non-zero status, a malformed
/// address, or a stream reset (dial refused/timeout). Used by the optimistic
/// client reply path, which has already answered SOCKS before this runs.
pub(crate) async fn read_mqp_ack(recv: &mut quinn::RecvStream) -> Result<()> {
    let mut head = [0u8; 3];
    recv.read_exact(&mut head).await.context("ack head read")?;
    if head[0..2] != MQP_TCP_ACK_MAGIC {
        anyhow::bail!("bad mqp ack magic {:02x}{:02x}", head[0], head[1]);
    }
    if head[2] != MQP_TCP_ACK {
        anyhow::bail!("bad mqp ack {:#x}", head[2]);
    }
    let mut buf = [0u8; 19];
    recv.read_exact(&mut buf[..1]).await.context("bnd atyp")?;
    let n = match buf[0] {
        0x01 => 7,
        0x04 => 19,
        a => anyhow::bail!("bad bnd atyp {a}"),
    };
    recv.read_exact(&mut buf[1..n]).await.context("bnd addr")?;
    let (addr, consumed) = decode_bnd_addr(&buf[..n])?;
    // Minimal consistency with `encode_bnd_addr_into`: the decoder accepts any
    // well-formed atyp, but the dial ACK must carry the server's real bound
    // socket — never the unknown `0.0.0.0:0` the optimistic SOCKS reply uses,
    // and never a length the encoder could not have produced.
    if consumed != n {
        anyhow::bail!("bnd length mismatch");
    }
    if addr.ip().is_unspecified() && addr.port() == 0 {
        anyhow::bail!("refused bnd {addr}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session-socket override clamps instead of trusting the operator (or
    /// a typo) verbatim: 1 B and `usize::MAX` must land on the measured range,
    /// and the shipped default is the 64 KiB floor, not the 32 KiB value the
    /// burst test measured as lossy.
    #[test]
    fn sess_socket_buf_override_clamps_to_supported_range() {
        assert_eq!(clamp_sess_socket_buf(1), SESS_SOCKET_BUF_MIN);
        assert_eq!(clamp_sess_socket_buf(usize::MAX), SESS_SOCKET_BUF_MAX);
        assert_eq!(clamp_sess_socket_buf(96 * 1024), 96 * 1024);
        assert_eq!(SESS_SOCKET_BUF, 64 * 1024);
    }

    /// The retry pool outlives the runtime that first needed it.
    ///
    /// Every shard's worker is a task, and a task dies with its runtime. The
    /// pool used to keep the `Sender` in a `OnceLock` forever, so once the first
    /// runtime ended, every later `WouldBlock` retry went into a queue nobody
    /// was draining: `try_send` returned `Closed`, the datagram was dropped, and
    /// the drop was charged to a "budget exhausted" counter that had not been
    /// touched. That is not hypothetical — it is why the client's loopback
    /// dispatcher tests failed *every* time they ran serially (one runtime per
    /// `#[tokio::test]`) and intermittently when they ran in parallel. A shard
    /// whose worker is gone has to be re-armed on the runtime that needs it.
    #[test]
    fn retry_shard_is_rearmed_after_its_runtime_ends() {
        // Runtime 1 initializes the pool, exactly as the first test that hits a
        // `WouldBlock` send does.
        let rt1 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt1.block_on(async {
            let _ = retry_shards();
        });
        drop(rt1);

        // Runtime 2 queues a retry through the same process-wide shard; the
        // datagram still has to come out.
        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let delivered = rt2.block_on(async {
            let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            listener
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let dst = listener.local_addr().unwrap();
            let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            assert!(
                udp_retry_submit(
                    &dst,
                    UdpRetry {
                        sock,
                        dst,
                        payload: Bytes::from_static(b"rearmed"),
                    },
                ),
                "a retry queued after the pool's runtime ended must still be accepted"
            );
            tokio::time::sleep(Duration::from_millis(600)).await;
            let mut b = [0u8; 64];
            listener.recv_from(&mut b).is_ok()
        });
        assert!(
            delivered,
            "the re-armed shard must actually send the datagram it accepted"
        );
    }

    /// A burst larger than the in-flight bound must still be delivered: the
    /// extra items exercise the worker's reap-and-wait path (a sequential drain
    /// could pass this too, but nothing may be dropped or abandoned before its
    /// send completes now that sends overlap).
    ///
    /// Drives its own worker (`spawn_retry_worker`) rather than the process-wide
    /// shard: the shard is shared with the other retry tests, whose
    /// current-thread runtimes come and go, and a worker on a runtime that is
    /// dropped mid-queue legitimately loses its queue (the next submit re-arms
    /// the shard — `retry_shard_is_rearmed_after_its_runtime_ends`). Sharing it
    /// here would make this test flaky for a reason that is not under test.
    #[tokio::test]
    async fn retry_pool_delivers_a_burst_past_the_inflight_bound() {
        // Both sockets are async and the wait is awaited: the worker runs on
        // this test's current-thread runtime, so a blocking `recv` here would
        // starve it and fail the test for its own harness's sake.
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tx = spawn_retry_worker();
        let n = UDP_RETRY_INFLIGHT * 3;
        for i in 0..n {
            assert!(
                tx.try_send(UdpRetry {
                    sock: sock.clone(),
                    dst,
                    payload: Bytes::copy_from_slice(&[0xAB, i as u8]),
                })
                .is_ok(),
                "retry {i} of {n} must be accepted (depth is {UDP_RETRY_DEPTH})"
            );
        }
        let mut got = vec![false; n];
        let mut seen = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b = [0u8; 16];
        while seen < n {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, listener.recv_from(&mut b)).await {
                Ok(Ok((2, _))) if b[0] == 0xAB => {
                    let i = b[1] as usize;
                    if i < n && !got[i] {
                        got[i] = true;
                        seen += 1;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(seen, n, "every queued retry must come out: {seen}/{n}");
    }

    /// The retry deadline is what bounds the socket's retention.
    ///
    /// A queued retry is the *last* strong owner of its `Arc<UdpSocket>` once the
    /// association (client relay) or session (server session socket) has dropped
    /// its own handle, and the worker used to await `send_to` with no deadline:
    /// a socket that never became writable pinned the fd — and on the server its
    /// 2 x 32 KiB kernel buffers — for the process lifetime, and parked the
    /// whole shard with it, so no later datagram hashing to that shard was ever
    /// retried. `pending()` stands in for that socket: the point is that the
    /// deadline, not the kernel, ends the wait. Real time (no `test-util`
    /// dependency), so the assertion is a generous upper bound around the
    /// deadline rather than an exact instant.
    #[tokio::test]
    async fn retry_deadline_bounds_a_never_writable_socket() {
        let start = tokio::time::Instant::now();
        assert!(
            under_retry_deadline(std::future::pending::<()>())
                .await
                .is_err(),
            "a send that never completes must be abandoned by the deadline"
        );
        let waited = start.elapsed();
        assert!(
            waited >= UDP_RETRY_TIMEOUT && waited < UDP_RETRY_TIMEOUT * 20,
            "the wait must be the deadline ({UDP_RETRY_TIMEOUT:?}), not open-ended: {waited:?}"
        );
        assert!(
            UDP_RETRY_TIMEOUT <= Duration::from_millis(500),
            "the retry deadline is a retention bound, not a retry policy"
        );
    }

    /// Clear this thread's memo so a test starts from a known state. The memo is
    /// thread-local, so tests running in parallel cannot disturb each other.
    fn memo_reset() {
        DNS_MEMO.with(|c| *c.borrow_mut() = [[DnsMemoSlot::EMPTY; MEMO_WAYS]; MEMO_SETS]);
    }

    #[test]
    fn dns_memo_set_is_stable_and_in_range() {
        for h in [0u64, 1, 0x9e37_79b9_7f4a_7c15, u64::MAX] {
            let set = dns_memo_set(h);
            assert!(set < MEMO_SETS, "set index {set} out of range");
            assert_eq!(set, dns_memo_set(h), "set index must be deterministic");
        }
    }

    /// A same-set collision must not resurrect the evicted key, and — the part
    /// that actually matters for correctness — must never serve the wrong
    /// address. The old direct-mapped version could not mis-serve either, so
    /// this locks in the property the associativity was allowed to change.
    #[test]
    fn dns_memo_two_ways_hold_two_keys_and_never_mis_serve() {
        memo_reset();
        // Find two keys in the same set, so both ways get used.
        let mut by_set: Vec<Vec<String>> = vec![Vec::new(); MEMO_SETS];
        for i in 0..4096 {
            let k = format!("host-{i}.example.com\0443");
            by_set[dns_memo_set(dns_memo_hash(&k))].push(k);
            if by_set.iter().any(|v| v.len() >= 3) {
                break;
            }
        }
        let trio = by_set
            .iter()
            .find(|v| v.len() >= 3)
            .expect("a set with three keys");
        let (a, b, c) = (&trio[0], &trio[1], &trio[2]);
        assert_eq!(
            dns_memo_set(dns_memo_hash(a)),
            dns_memo_set(dns_memo_hash(b)),
            "test premise: a and b share a set"
        );

        let addr_a: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(60);

        // Two keys, two ways: both must be resident at once.
        memo_put(a, Some(addr_a), far);
        memo_put(b, Some(addr_b), far);
        let (pa, na) = memo_peek_both(a);
        let (pb, nb) = memo_peek_both(b);
        assert_eq!(pa.expect("a resident").addr, Some(addr_a));
        assert_eq!(pb.expect("b resident").addr, Some(addr_b));
        assert!(na.is_none() && nb.is_none());

        // A third key in the same set evicts the least recently used, and the
        // surviving entry still answers with its own address.
        memo_put(c, Some("10.0.0.3:443".parse().unwrap()), far);
        let (pb2, _) = memo_peek_both(b);
        let (pa2, _) = memo_peek_both(a);
        assert_eq!(pb2.expect("b promoted, still resident").addr, Some(addr_b));
        assert!(
            pa2.is_none(),
            "a was the LRU victim and must not answer for b's set"
        );
        // The critical invariant: b never answers with a's address.
        assert_ne!(memo_peek_both(b).0.unwrap().addr, Some(addr_a));
    }

    /// Re-putting a resident key must update it in place rather than let one key
    /// occupy both ways of its set.
    #[test]
    fn dns_memo_reput_of_way_one_does_not_duplicate() {
        memo_reset();
        let mut by_set: Vec<Vec<String>> = vec![Vec::new(); MEMO_SETS];
        let mut trio = None;
        for i in 0..8192 {
            let k = format!("h{i}.example.net\0443");
            let set = dns_memo_set(dns_memo_hash(&k));
            by_set[set].push(k);
            if let Some(v) = by_set.iter().find(|v| v.len() >= 2) {
                if trio.is_none() {
                    trio = Some((v[0].clone(), v[1].clone()));
                }
            }
            if trio.is_some() {
                break;
            }
        }
        let (a, b) = trio.expect("a set with two keys");
        let far = Instant::now() + Duration::from_secs(60);

        memo_put(&a, Some("10.1.1.1:1".parse().unwrap()), far);
        memo_put(&b, Some("10.1.1.2:1".parse().unwrap()), far); // a demoted to way 1
                                                                // Re-put a (now in way 1) with a new address: it must promote, and b
                                                                // must survive in way 1.
        memo_put(&a, Some("10.1.1.9:1".parse().unwrap()), far);
        assert_eq!(
            memo_peek_both(&a).0.expect("a resident").addr,
            Some("10.1.1.9:1".parse().unwrap())
        );
        assert_eq!(
            memo_peek_both(&b).0.expect("b survived the promotion").addr,
            Some("10.1.1.2:1".parse().unwrap())
        );
    }

    /// A key too long for the inline slot must be a plain miss, never a match.
    #[test]
    fn dns_memo_ignores_keys_it_cannot_store() {
        memo_reset();
        let long = format!("{}\0443", "a".repeat(MEMO_KEY_BYTES));
        assert!(long.len() > MEMO_KEY_BYTES);
        memo_put(
            &long,
            Some("10.2.2.2:2".parse().unwrap()),
            Instant::now() + Duration::from_secs(60),
        );
        let (pos, neg) = memo_peek_both(&long);
        assert!(
            pos.is_none() && neg.is_none(),
            "long key must not be memoized"
        );
    }

    /// A negative entry must be distinguishable from a positive one and from a
    /// miss, because the caller uses that to skip spawning a resolver.
    #[test]
    fn dns_memo_negative_entries_are_separate_from_positive() {
        memo_reset();
        let k = "bad.example.com\080".to_string();
        memo_put(&k, None, Instant::now() + Duration::from_secs(10));
        let (pos, neg) = memo_peek_both(&k);
        assert!(pos.is_none(), "negative entry must not look positive");
        assert!(neg.expect("negative hit").addr.is_none());

        // Replacing it with a positive answer must flip the classification.
        memo_put(
            &k,
            Some("10.3.3.3:80".parse().unwrap()),
            Instant::now() + Duration::from_secs(60),
        );
        let (pos2, neg2) = memo_peek_both(&k);
        assert_eq!(
            pos2.expect("now positive").addr,
            Some("10.3.3.3:80".parse().unwrap())
        );
        assert!(neg2.is_none());
    }

    /// A negative *memo* entry must not outlive the global negative entry it was
    /// derived from.
    ///
    /// The memo is thread-private, and `resolve_all_cached`'s success path can
    /// only clear the global entry plus the resolving thread's own memo — so a
    /// name that failed on one worker and then resolved on another stayed
    /// refused on the failing worker for the rest of `DNS_NEG_TTL`: every
    /// datagram for it dropped as `REFUSED`, every TCP flow failing with
    /// "dns negative cached", while the cache held a valid address. Two real
    /// threads drive the hole (it is cross-thread by construction), and the
    /// negative memo is produced by [`dns_neg_cache_seed`] rather than a live
    /// resolver failure so the test needs no network.
    #[test]
    fn a_resolution_invalidates_another_threads_negative_memo() {
        let (host, port) = ("neg-memo-coherence.test", 19056u16);
        let addr: SocketAddr = "93.184.216.34:19056".parse().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();

        let w = std::thread::spawn(move || {
            // Premise: nothing is known about this name on this thread.
            assert_eq!(lookup_cached_fast(host, port), CachedLookup::Unknown);
            dns_neg_cache_seed(host, port);
            assert_eq!(
                lookup_cached_fast(host, port),
                CachedLookup::Negative,
                "the recording worker must see its own negative memo"
            );
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            lookup_cached_fast(host, port)
        });

        ready_rx.recv().unwrap();
        // Another worker resolves the same name successfully.
        dns_cache_seed(host, port, addr);
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "a fresh positive entry answers on a thread with no stale memo"
        );
        go_tx.send(()).unwrap();
        assert_eq!(
            w.join().unwrap(),
            CachedLookup::Addr(addr),
            "a successful resolution must invalidate another thread's negative memo"
        );
    }

    /// A transient resolver failure must not downgrade a still-valid positive
    /// answer into a negative one.
    ///
    /// The positive probes on the resolution path are `try_lock_read`, so a
    /// contended-but-valid entry reaches the upstream lookup; if that lookup
    /// fails, the old code wrote a negative cache entry *and* a negative
    /// thread-local memo entry unconditionally. `lookup_cached_fast` consults
    /// the memo first and one memo set holds one slot per key, so every datagram
    /// for that name was then refused for `DNS_NEG_TTL` (10 s) and every TCP
    /// flow failed with "dns negative cached" — while the cached address was
    /// still good. `record_negative` is the gate; this pins both directions.
    #[test]
    fn transient_resolution_failure_does_not_poison_a_fresh_positive_entry() {
        memo_reset();
        let addr: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (host, port) = ("poison-guard.test", 19053u16);
        dns_cache_seed(host, port, addr);
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let key = dns_key(host, port, &mut kbuf).unwrap().to_owned();
        assert!(
            matches!(positive_entry_state(&key), PositiveState::Fresh),
            "test premise: positive is fresh"
        );

        // The failure the owner observed is recorded, but must not shadow the
        // live positive answer.
        record_negative(&key, Instant::now());
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "a fresh positive entry must survive a transient resolver failure"
        );
        assert!(
            lock_read(dns_neg_cache_for(&key)).get(&key).is_none(),
            "no negative entry may be written over a live positive one"
        );
        assert!(
            memo_peek_both(&key).1.is_none(),
            "no negative memo entry may shadow a live positive one"
        );

        // Positive control: with no fresh positive answer, the failure *is*
        // recorded and the packet path refuses the name without a lookup.
        let (miss_host, miss_port) = ("poison-guard-miss.test", 19054u16);
        let mut kbuf2 = [0u8; DNS_KEY_BUF];
        let miss_key = dns_key(miss_host, miss_port, &mut kbuf2)
            .unwrap()
            .to_owned();
        assert!(matches!(
            positive_entry_state(&miss_key),
            PositiveState::Absent
        ));
        record_negative(&miss_key, Instant::now());
        assert_eq!(
            lookup_cached_fast(miss_host, miss_port),
            CachedLookup::Negative,
            "an uncached failure must still be negatively cached"
        );
    }

    #[test]
    fn contended_positive_probe_skips_negative_caching() {
        memo_reset();
        let addr: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (host, port) = ("contention-guard.test", 19055u16);
        dns_cache_seed(host, port, addr);
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let key = dns_key(host, port, &mut kbuf).unwrap().to_owned();
        // Hold the positive shard: std RwLock is not reentrant, so the probe
        // sees contention (not absence) while the guard lives.
        let _guard = lock_write(dns_cache_for(&key));
        assert!(matches!(positive_entry_state(&key), PositiveState::Unknown));
        record_negative(&key, Instant::now());
        drop(_guard);
        assert!(
            lock_read(dns_neg_cache_for(&key)).get(&key).is_none(),
            "contention must not produce a negative entry"
        );
        assert!(
            memo_peek_both(&key).1.is_none(),
            "contention must not produce a negative memo entry"
        );
        assert_eq!(
            lookup_cached_fast(host, port),
            CachedLookup::Addr(addr),
            "the live positive answer must stay servable"
        );
    }

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
    fn global_ip_filter_extended() {
        // RFC 2765 IPv4-translated addresses are judged by their embedded IPv4.
        assert!(!is_global_ip("::ffff:0:127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:10.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::ffff:0:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("::ffff:0:8.8.8.8".parse().unwrap()));
        // IPv4-mapped must not be affected by the translated-prefix check.
        assert!(is_global_ip("::ffff:8.8.8.8".parse().unwrap()));
        // Newly added IANA "not globally reachable" ranges.
        assert!(!is_global_ip("192.31.196.1".parse().unwrap()));
        assert!(!is_global_ip("192.52.193.1".parse().unwrap()));
        assert!(!is_global_ip("2001:1::1".parse().unwrap()));
        assert!(!is_global_ip("2001:3::1".parse().unwrap()));
        assert!(!is_global_ip("2001:4:112::1".parse().unwrap()));
        assert!(!is_global_ip("2001:30::1".parse().unwrap()));
        assert!(!is_global_ip("5f00::1".parse().unwrap()));
        assert!(!is_global_ip("2620:4f:8000::1".parse().unwrap()));
        // Still globally routable.
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    /// Two IPv6 ranges that a per-RFC denylist kept missing.
    ///
    /// `fe00::/9` is IANA "Reserved by IETF" and sits exactly between the
    /// `fc00::/7` and `fe80::/10` rules, so a denylist naming only those two
    /// returned `true` for `fe00::1`. `2001::/23` is the IETF Protocol
    /// Assignments block, not global unicast — the old code denied only the
    /// sub-blocks someone had already written an RFC citation for, so
    /// `2001:5::/32` (the LISP EID block) and the reserved remainder passed.
    #[test]
    fn global_ip_filter_rejects_fe00_and_the_2001_ietf_block() {
        for ip in ["fe00::1", "fe01::1", "fe7f:ffff::1"] {
            assert!(
                !is_global_ip(ip.parse().unwrap()),
                "{ip} is Reserved by IETF, not global"
            );
        }
        for ip in ["2001:0::1", "2001:5::1", "2001:1ff::1"] {
            assert!(
                !is_global_ip(ip.parse().unwrap()),
                "{ip} is inside the IETF Protocol Assignments block"
            );
        }
        // The block boundary is exact: 2001:0200::/23 is the first RIR
        // allocation and must stay dialable, while the last address of the
        // IETF block must not.
        assert!(!is_global_ip("2001:1ff:ffff::1".parse().unwrap()));
        assert!(is_global_ip("2001:200::1".parse().unwrap()));
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    /// `3fff::/20` (RFC 9637) must be exactly that block — no wider.
    ///
    /// The mask used to be `(s[0] & 0xfff0) == 0x3ff0`, i.e. `3ff0::/12`: every
    /// address from `3ff0::` to `3ffe:ffff:...` was refused, 256x the space the
    /// RFC defines. Harmless while `3000::/4` stays IANA-reserved, but it is the
    /// third over-broad denylist mask in this predicate (`fe00::/9` and
    /// `2001::/23` were the first two), so the boundary is pinned here the same
    /// way `2001::/23`'s is.
    #[test]
    fn global_ip_filter_rejects_exactly_3fff_20() {
        // Sweep the whole s[1] nibble boundary: 0x0000..=0x0fff is 3fff::/20 and
        // must be denied, 0x1000 upward must be dialable. Checking sampled
        // addresses is not enough here — the bug was a wrong *mask width* on
        // s[1], which only some addresses expose.
        for hi in 0u32..=0xf {
            for lo in (0u32..0x1000).step_by(0x40) {
                let s1 = (hi << 12) | lo;
                let ip = std::net::Ipv6Addr::new(0x3fff, s1 as u16, 0, 0, 0, 0, 0, 1);
                if s1 <= 0x0fff {
                    assert!(
                        !is_global_ip(ip.into()),
                        "3fff:{s1:x}::1 is inside 3fff::/20"
                    );
                } else {
                    assert!(
                        is_global_ip(ip.into()),
                        "3fff:{s1:x}::1 is outside 3fff::/20"
                    );
                }
            }
        }
        // The neighbouring /16s the old /12 mask swallowed.
        for ip in [
            "3ff0::1",
            "3ff8::1",
            "3ffe:ffff::1",
            "3fff:1000::1",
            "3fff:ffff::1",
        ] {
            assert!(
                is_global_ip(ip.parse().unwrap()),
                "{ip} is outside 3fff::/20"
            );
        }
        // And the block is still denied at both ends of the /20.
        for ip in ["3fff::", "3fff:0fff:ffff::1"] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip} is in 3fff::/20");
        }
    }

    /// The TTL-exposing lookups must report the *remaining* life, not the full
    /// TTL: that remainder is what an adopting caller (the server's connection
    /// pin and session destination memo) has to clamp against.
    #[test]
    fn lookup_ttl_reports_the_entries_remaining_life() {
        memo_reset();
        let addr: SocketAddr = "93.184.216.34:19057".parse().unwrap();
        let (host, port) = ("ttl-report.test", 19057u16);
        dns_cache_seed(host, port, addr);
        let (hit, ttl) = lookup_cached_fast_with_ttl(host, port);
        assert_eq!(hit, CachedLookup::Addr(addr));
        assert!(
            ttl > DNS_CACHE_TTL_MS - 2_000 && ttl <= DNS_CACHE_TTL_MS,
            "a fresh entry reports its full life, got {ttl} ms"
        );

        // 59.5 s into a 60 s TTL: half a second of life is all an adopting
        // caller may use.
        let (aged, aged_port) = ("ttl-report-aged.test", 19058u16);
        dns_cache_seed_aged(aged, aged_port, addr, Duration::from_millis(59_500));
        let (hit2, ttl2) = lookup_cached_fast_with_ttl(aged, aged_port);
        assert_eq!(hit2, CachedLookup::Addr(addr));
        assert!(
            ttl2 <= 1_500,
            "an aged entry must report only its remainder, got {ttl2} ms"
        );

        // The full-set form carries it too, and a miss reports none.
        let set = lookup_cached_all_fast_with_ttl(aged, aged_port).expect("cached set");
        assert!(set.1 <= 1_500, "set life {} ms", set.1);
        assert_eq!(
            lookup_cached_fast_with_ttl("ttl-report-miss.test", 19059).1,
            0
        );
    }

    #[test]
    fn dns_key_normalizes_case_and_trailing_dot() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        assert_eq!(
            dns_key("Example.COM.", 443, &mut a).unwrap(),
            dns_key("example.com", 443, &mut b).unwrap()
        );
        assert_eq!(
            dns_key("example.com", 80, &mut a).unwrap(),
            "example.com\u{0}80"
        );
        // The owned fallback must normalize identically to the stack form.
        assert_eq!(
            dns_key_owned("Example.COM.", 443),
            dns_key("example.com", 443, &mut b).unwrap()
        );
    }

    #[test]
    fn dgram_send_buffer_always_fits_one_wire_datagram() {
        // `try_send_datagram` (and any use of `send_datagram_wait`) can only work
        // if the configured send buffer holds at least one maximum-size MQP-2
        // datagram; a smaller buffer would report Blocked forever. Checked at
        // compile time so editing the DATAGRAM budget fails the build loudly
        // instead of under load; `build_transport` asserts the same bound.
        const { assert!(MQP_DGRAM_MAX == 264, "MQP-2 datagram bound changed") };
        // The header bound has to fit QUIC's minimum path MTU (1200 B) so a
        // maximum-length domain header still leaves room for a payload.
        const { assert!(MQP_DGRAM_MAX < 1200, "MQP-2 header must fit a 1200 B path") };
        // The buffer bound is the largest body we can hand quinn, not the
        // header bound: the relays no longer clamp `max_datagram_size()`.
        const { assert!(DATAGRAM_BUFFER >= DGRAM_MAX_WIRE) };
        const { assert!(DGRAM_DEFAULT_LIMIT <= DGRAM_MAX_WIRE) };
    }

    /// Regression for the silent large-datagram loss: clamping the DATAGRAM
    /// budget is clamping the *payload* budget. With `max_datagram_size()`
    /// clamped to 1350 the usable UDP payload was 1338 B (v4) / 1326 B (v6)
    /// regardless of how much the path could carry, so a 1400 B DTLS record —
    /// which a direct UDP path delivers fine — vanished with no log line.
    #[test]
    fn dgram_payload_cap_tracks_the_live_limit_not_a_hard_cap() {
        let v4 = TargetAddrRef::Ip("1.2.3.4:443".parse().unwrap());
        let v6 = TargetAddrRef::Ip("[2001:db8::1]:443".parse().unwrap());
        let dom = TargetAddrRef::Domain("example.com", 443); // header = 4 + 11

        // Overheads: 5 B MQP prefix, then 7 B (v4) / 19 B (v6) address header.
        assert_eq!(dgram_payload_cap(1350, &v4), 1338); // the old ceiling
        assert_eq!(dgram_payload_cap(1448, &v4), 1436); // a 1472 B path now
        assert_eq!(dgram_payload_cap(1448, &v6), 1424);
        assert_eq!(dgram_payload_cap(1448, &dom), 1428);
        assert!(dgram_payload_cap(1448, &v4) > 1338, "the hard cap is gone");
        // QUIC's minimum path MTU is 1200 B, where `max_datagram_size()` is
        // ~1162: that must still leave room for a typical 1100 B UDP payload.
        assert!(dgram_payload_cap(1162, &v4) >= 1100);
        // Saturates instead of underflowing when even the header cannot fit.
        assert_eq!(dgram_payload_cap(4, &v4), 0);
        assert_eq!(dgram_payload_cap(0, &v6), 0);
    }

    /// The cap must agree with the encoder byte for byte, in both directions:
    /// a payload of exactly `cap` encodes, one byte more is rejected.
    #[test]
    fn dgram_payload_cap_matches_the_encoder() {
        let addrs = [
            (
                TargetAddrRef::Ip("1.2.3.4:443".parse().unwrap()),
                1350usize,
                1338usize,
            ),
            (
                TargetAddrRef::Ip("[2001:db8::1]:443".parse().unwrap()),
                1350,
                1326,
            ),
            (TargetAddrRef::Domain("example.com", 443), 1350, 1330), // header = 4 + 11
        ];
        for (addr, limit, expected) in addrs {
            let cap = dgram_payload_cap(limit, &addr);
            assert_eq!(cap, expected, "cap for {addr:?}");
            assert!(
                encode_datagram_ref_with_limit(1, &addr, &vec![0u8; cap], limit).is_some(),
                "payload of exactly cap must encode for {addr:?}"
            );
            assert!(
                encode_datagram_ref_with_limit(1, &addr, &vec![0u8; cap + 1], limit).is_none(),
                "one byte over cap must be rejected for {addr:?}"
            );
        }
    }

    /// Drops are counted, and `bump` is what moves the counters, so a relay
    /// cannot drop a datagram without it showing up in `snapshot()`.
    #[test]
    fn dgram_drop_counters_are_monotonic() {
        use std::sync::atomic::AtomicU64;
        let c = AtomicU64::new(0);
        assert_eq!(dgram_drops::bump(&c), 1);
        assert_eq!(dgram_drops::bump(&c), 2);

        // The process-wide snapshot must observe a bump on the real counter.
        // Other tests may bump concurrently, so assert a lower bound only.
        let before = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::TOO_LARGE);
        let after = dgram_drops::snapshot();
        assert!(
            after.too_large > before.too_large,
            "snapshot must observe the bump"
        );
    }

    /// Every drop counter must reach its own named field in the snapshot: the
    /// ten-field struct exists so the 60 s report cannot silently omit one, and
    /// the batching table (`bump` + `flush_locals`) is keyed on identity, so a
    /// counter missing one of the two arms would sit in a thread-local cell
    /// forever. One bump per counter, one field asserted per counter.
    #[test]
    fn every_drop_counter_has_its_own_snapshot_field() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let before = dgram_drops::snapshot();
        for c in [
            &dgram_drops::TOO_LARGE,
            &dgram_drops::BUFFER_FULL,
            &dgram_drops::SESSION_FULL,
            &dgram_drops::DNS_BUDGET,
            &dgram_drops::FAIR_SHARE,
            &dgram_drops::DNS_INFLIGHT,
            &dgram_drops::DNS_CONTENTION,
            &dgram_drops::NO_EGRESS,
            &dgram_drops::EGRESS_DEAD,
            &dgram_drops::REFUSED,
            &dgram_drops::SESS_CREATE_FAILED,
        ] {
            dgram_drops::bump(c);
        }
        let after = dgram_drops::snapshot();
        assert!(after.too_large > before.too_large, "too_large");
        assert!(after.buffer_full > before.buffer_full, "buffer_full");
        assert!(after.session_full > before.session_full, "session_full");
        assert!(after.dns_budget > before.dns_budget, "dns_budget");
        assert!(after.fair_share > before.fair_share, "fair_share");
        assert!(after.dns_inflight > before.dns_inflight, "dns_inflight");
        assert!(
            after.dns_contention > before.dns_contention,
            "dns_contention"
        );
        assert!(after.no_egress > before.no_egress, "no_egress");
        assert!(after.egress_dead > before.egress_dead, "egress_dead");
        assert!(after.refused > before.refused, "refused");
        assert!(
            after.sess_create_failed > before.sess_create_failed,
            "sess_create_failed"
        );
        let d = after.since(&before);
        assert!(d.lost() >= 11, "every drop counts as loss: {d:?}");
    }

    /// Hold one single-flight shard mutex from another thread, the way a miss
    /// storm does. Probing that name must read as unknown — never as inflight.
    ///
    /// The old probe returned `true` on `WouldBlock`, so a contended shard
    /// dropped datagrams charged to `DNS_INFLIGHT` for what was only lock
    /// contention; the `!dns_is_inflight` assertion below fails against it.
    #[test]
    fn contended_dns_mutex_is_unknown_not_inflight() {
        let host = "status-contended-probe.invalid";
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let mut kbuf = [0u8; DNS_KEY_BUF];
            let owned;
            let key: &str = match dns_key(host, 53, &mut kbuf) {
                Some(k) => k,
                None => {
                    owned = dns_key_owned(host, 53);
                    &owned
                }
            };
            let _guard = lock_mutex(dns_inflight_for(key));
            locked_tx.send(()).expect("holder signals the lock");
            release_rx.recv().expect("holder waits for release");
        });
        locked_rx.recv().expect("shard mutex is now held elsewhere");
        assert_eq!(
            dns_inflight_status(host, 53),
            DnsInflight::Contended,
            "a busy shard is unknown, not inflight"
        );
        assert!(
            !dns_is_inflight(host, 53),
            "contention must never read as inflight"
        );
        release_tx.send(()).expect("release the holder");
        holder.join().expect("holder thread exits");
        assert_eq!(
            dns_inflight_status(host, 53),
            DnsInflight::Absent,
            "an unregistered name is absent once the shard is free"
        );
    }

    /// Registration must fail fast with `DnsContended` when its shard mutex is
    /// busy — never park the task on it. Against the old blocking register
    /// this test times out instead of returning (the holder only releases
    /// after the awaited call completes).
    #[tokio::test]
    async fn contended_register_fails_fast_as_contention() {
        let host = "register-contended-probe.invalid";
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let mut kbuf = [0u8; DNS_KEY_BUF];
            let owned;
            let key: &str = match dns_key(host, 53, &mut kbuf) {
                Some(k) => k,
                None => {
                    owned = dns_key_owned(host, 53);
                    &owned
                }
            };
            let _guard = lock_mutex(dns_inflight_for(key));
            locked_tx.send(()).expect("holder signals the lock");
            release_rx.recv().expect("holder waits for release");
        });
        locked_rx.recv().expect("shard mutex is now held elsewhere");
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            resolve_all_cached(host, 53),
        )
        .await;
        release_tx.send(()).expect("release the holder");
        holder.join().expect("holder thread exits");
        let err = r
            .expect("register must fail fast, not park on the shard mutex")
            .unwrap_err();
        assert!(
            is_dns_contended(&err),
            "register contention must be Contended, got {err:#}"
        );
    }

    /// The contention retry still fails fast when the shard stays busy: both
    /// attempts hit `DnsContended` and the flow fails instead of parking. The
    /// timeout proves neither attempt blocks; the error proves the retry does
    /// not loop. A single contention event is counted even though nothing was
    /// dropped — the mutex was genuinely busy, and the count is what makes a
    /// miss storm visible.
    #[tokio::test]
    // Test-only serializing mutex, held across a fail-fast future that never
    // parks on it (the holder releases as soon as the contended call returns).
    #[allow(clippy::await_holding_lock)]
    async fn contention_retry_fails_fast_when_shard_stays_busy() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let host = "retry-still-contended-probe.invalid";
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let mut kbuf = [0u8; DNS_KEY_BUF];
            let owned;
            let key: &str = match dns_key(host, 53, &mut kbuf) {
                Some(k) => k,
                None => {
                    owned = dns_key_owned(host, 53);
                    &owned
                }
            };
            let _guard = lock_mutex(dns_inflight_for(key));
            locked_tx.send(()).expect("holder signals the lock");
            release_rx.recv().expect("holder waits for release");
        });
        locked_rx.recv().expect("shard mutex is now held elsewhere");
        let before = dgram_drops::snapshot();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            resolve_all_cached_with_contention_retry(host, 53),
        )
        .await;
        release_tx.send(()).expect("release the holder");
        holder.join().expect("holder thread exits");
        let err = r
            .expect("retry must fail fast, not park on the shard mutex")
            .unwrap_err();
        assert!(
            is_dns_contended(&err),
            "sustained contention must stay Contended, got {err:#}"
        );
        let after = dgram_drops::snapshot();
        assert!(
            after.dns_contention > before.dns_contention,
            "the first contention is counted even though the flow fails"
        );
    }

    /// The retry wrapper is transparent off contention: a seeded name resolves
    /// without ever touching the single-flight mutex.
    #[tokio::test]
    async fn contention_retry_preserves_the_uncontended_path() {
        let host = "retry-uncontended-probe.invalid";
        let addr: SocketAddr = "93.184.216.34:443".parse().expect("probe addr parses");
        dns_cache_seed(host, 443, addr);
        let v = resolve_all_cached_with_contention_retry(host, 443)
            .await
            .expect("a seeded name must resolve");
        assert!(
            v.contains(&addr),
            "the seeded address must come back through the retry wrapper"
        );
    }

    /// `DNS_CONTENTION` is exact like the egress counters: a short episode on
    /// a thread that never reports must be in the very next snapshot. With the
    /// old batching wiring the spawned thread's cell dies with it and the
    /// delta below is zero, deterministically.
    #[test]
    fn contention_drops_are_exact_across_threads() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let before = dgram_drops::snapshot();
        std::thread::spawn(|| {
            for _ in 0..20 {
                dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
            }
        })
        .join()
        .expect("the drop thread must not panic");
        let after = dgram_drops::snapshot();
        assert!(
            after.dns_contention >= before.dns_contention + 20,
            "a 20-event contention episode must be in the next snapshot: {} -> {}",
            before.dns_contention,
            after.dns_contention
        );
    }

    /// A unique-domain flood must fail fast on the slow-path limiter: with the
    /// budget exhausted `try_acquire_owned` returns `Err` synchronously (it can
    /// never park the caller), the excess is counted as `SESSION_FULL` — the
    /// same counter both relay paths bump on that arm — and the contention
    /// counter stays a distinct field. No other lib test holds this limiter
    /// (only the binaries take it, in their own test processes), and nothing
    /// is awaited while the permits are held, so the drain lasts microseconds.
    #[test]
    fn dns_limiter_exhaustion_fails_fast_and_counts_session_full() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let lim = dns_slow_path_limiter();
        let mut held = Vec::new();
        while lim.available_permits() > 0 {
            match lim.clone().try_acquire_owned() {
                Ok(p) => held.push(p),
                Err(_) => break,
            }
        }
        assert_eq!(
            lim.available_permits(),
            0,
            "the flood budget must be exhaustible"
        );
        assert!(
            lim.clone().try_acquire_owned().is_err(),
            "excess misses must fail fast, never park"
        );
        let before = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::SESSION_FULL);
        dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
        let after = dgram_drops::snapshot();
        assert!(
            after.session_full > before.session_full,
            "exhaustion must be counted as SESSION_FULL"
        );
        assert!(
            after.dns_contention > before.dns_contention,
            "contention must stay a distinct counted field"
        );
        drop(held);
        assert!(
            lim.available_permits() > 0,
            "the budget must recover when permits release"
        );
    }

    /// Serializes the tests that assert exact slow-path counter deltas. The
    /// drop counters are process-wide and `bump` is exact (no batching), so
    /// two such tests racing would move each other's deltas; every test that
    /// bumps `REFUSED` / `DNS_INFLIGHT` / `DNS_CONTENTION` / `SESSION_FULL`
    /// holds this while it measures.
    static SLOW_PATH_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// P1-4 slow-path budget lock: each drop arm owns exactly one counter and
    /// every arm counts as loss in the 60 s budget line.
    ///
    /// One bump per arm must move exactly one snapshot field by exactly one:
    /// a doubled bump (or two arms sharing a counter) would double-count one
    /// burst datagram in the budget the reporter prints. The dispatch-level
    /// tests pin that each relay path bumps once per refused datagram; this
    /// pins the counters themselves.
    #[test]
    fn slow_path_budget_arms_fire_exactly_once() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let before = dgram_drops::snapshot();
        dgram_drops::bump(&dgram_drops::REFUSED);
        dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
        dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
        dgram_drops::bump(&dgram_drops::SESSION_FULL);
        let d = dgram_drops::snapshot().since(&before);
        assert_eq!(d.refused, 1, "REFUSED (negative cache / policy) fires once");
        assert_eq!(d.dns_inflight, 1, "DNS_INFLIGHT (single-flight) fires once");
        assert_eq!(
            d.dns_contention, 1,
            "DNS_CONTENTION (shard contention) fires once"
        );
        assert_eq!(
            d.session_full, 1,
            "SESSION_FULL (slow-path budget) fires once"
        );
        assert_eq!(d.lost(), 4, "every slow-path drop is budget loss: {d:?}");
    }

    /// P1-4 slow-path budget lock: the tri-state probe maps to exactly one
    /// counter, and contention is never charged as inflight.
    ///
    /// `forward_server_dgram` (server) and `dispatch_one` (client) share one
    /// contract over `dns_inflight_status`: `Inflight` counts `DNS_INFLIGHT`
    /// and returns, `Contended` counts `DNS_CONTENTION` and falls through to
    /// the limiter-bounded spawn, `Absent` spawns with no count. This drives
    /// the same probe through both contended states and asserts the counting
    /// half of that contract exactly once per arm.
    #[test]
    fn dns_slow_path_probe_counts_contention_apart_from_inflight_exactly_once() {
        let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().unwrap();
        let host = "p14-probe-distinction.invalid";
        // Baseline: unregistered and uncontended is Absent (no counter arm).
        assert_eq!(dns_inflight_status(host, 53), DnsInflight::Absent);
        assert!(!dns_is_inflight(host, 53));
        // Register a fake owner the way `resolve_all_cached` does, so the
        // probe reads Inflight while a resolution owns the name.
        let mut kbuf = [0u8; DNS_KEY_BUF];
        let key_owned = dns_key(host, 53, &mut kbuf).unwrap().to_owned();
        let entry = std::sync::Arc::new(crate::dns::inflight::DnsInflightEntry {
            key: key_owned.clone(),
            cell: tokio::sync::OnceCell::new(),
            notify: tokio::sync::Notify::new(),
            owner: std::sync::atomic::AtomicBool::new(true),
        });
        {
            let mut inf = lock_mutex(dns_inflight_for(&key_owned));
            inf.insert(key_owned.clone(), entry);
        }
        assert_eq!(dns_inflight_status(host, 53), DnsInflight::Inflight);
        assert!(dns_is_inflight(host, 53));
        // The Inflight arm, verbatim: one datagram, one DNS_INFLIGHT.
        let before = dgram_drops::snapshot();
        match dns_inflight_status(host, 53) {
            DnsInflight::Inflight => {
                dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
            }
            DnsInflight::Contended => {
                dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
            }
            DnsInflight::Absent => {}
        }
        let d = dgram_drops::snapshot().since(&before);
        assert_eq!(d.dns_inflight, 1, "one inflight drop counts exactly once");
        assert_eq!(
            d.dns_contention, 0,
            "inflight must never touch the contention counter"
        );
        // Release the name, then hold the shard the way a miss storm does:
        // the same probe must read Contended (unknown), never Inflight.
        {
            let mut inf = lock_mutex(dns_inflight_for(&key_owned));
            inf.remove(&key_owned);
        }
        let _held = lock_mutex(dns_inflight_for(&key_owned));
        assert_eq!(
            dns_inflight_status(host, 53),
            DnsInflight::Contended,
            "a busy shard is unknown, not inflight"
        );
        assert!(
            !dns_is_inflight(host, 53),
            "contention must never read as inflight"
        );
        // The Contended arm, verbatim: one datagram, one DNS_CONTENTION.
        let before = dgram_drops::snapshot();
        match dns_inflight_status(host, 53) {
            DnsInflight::Inflight => {
                dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
            }
            DnsInflight::Contended => {
                dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
            }
            DnsInflight::Absent => {}
        }
        let d = dgram_drops::snapshot().since(&before);
        assert_eq!(
            d.dns_contention, 1,
            "one contended drop counts exactly once"
        );
        assert_eq!(
            d.dns_inflight, 0,
            "contention must never touch the inflight counter"
        );
    }

    /// The two egress counters must be visible **immediately and from another
    /// thread**, which is the whole reason they do not batch.
    ///
    /// Batching (six of the nine counters) keeps the count in the bumping
    /// thread's cell until it reaches 64, and `snapshot` only flushes the thread
    /// it runs on — so a worker thread's short outage stays invisible until that
    /// thread drops 63 more, and a thread that exits takes its pending count with
    /// it. This test spawns exactly such a thread: with the egress counters
    /// batched, the spawned thread's cell dies with it and the delta below is
    /// zero, deterministically. Other tests only ever *add* to these counters, so
    /// the assertions are lower bounds and cannot flake.
    #[test]
    fn egress_drops_are_exact_across_threads() {
        let before = dgram_drops::snapshot();
        std::thread::spawn(|| {
            // One outage's worth of drops, on a thread that never reports and
            // never reaches the batching threshold.
            for _ in 0..20 {
                dgram_drops::bump(&dgram_drops::NO_EGRESS);
            }
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        })
        .join()
        .expect("the drop thread must not panic");

        let after = dgram_drops::snapshot();
        assert!(
            after.no_egress >= before.no_egress + 20,
            "a 20-datagram fail-closed outage must be in the next snapshot: {} -> {}",
            before.no_egress,
            after.no_egress
        );
        assert!(
            after.egress_dead > before.egress_dead,
            "a dead-egress drop must be in the next snapshot: {} -> {}",
            before.egress_dead,
            after.egress_dead
        );
        assert!(
            after.since(&before).lost() >= 21,
            "both egress states count as loss"
        );
    }

    /// The warn helper picks its rate-limit slot from the enum, so two different
    /// egress faults cannot share one 10 s window and silently swallow each
    /// other's first line.
    #[test]
    fn egress_drop_warnings_use_independent_slots() {
        // Both kinds emit on a fresh process (the first call always warns), and
        // calling them repeatedly is safe: the second call inside the interval is
        // suppressed rather than panicking or blocking.
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, 1, String::new);
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::ConnectionLost, 1, String::new);
        dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, 2, String::new);
    }

    /// The first drop must warn, and only then does the interval apply. A rate
    /// limiter that swallows the first event is useless precisely when a fresh
    /// deployment first shows the symptom.
    #[test]
    fn drop_warning_fires_once_then_rate_limits() {
        assert!(drop_warn_due(NEVER_WARNED, 0), "first drop always warns");
        assert!(
            !drop_warn_due(1_000, 1_000),
            "immediately after: suppressed"
        );
        assert!(!drop_warn_due(1_000, 10_999), "just inside the window");
        assert!(
            drop_warn_due(1_000, 11_000),
            "exactly at the interval: warns"
        );
        assert!(drop_warn_due(1_000, 99_999), "well past the interval");
        assert!(!drop_warn_due(5_000, 4_999), "clock regression: suppressed");
    }

    /// The slot is claimed exactly once per interval: the message (and its
    /// detail string) must be built by the winner only, or a drop flood makes
    /// logging itself the per-drop cost.
    #[test]
    fn warning_slot_is_claimed_once_per_interval() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let slot = AtomicU64::new(NEVER_WARNED);
        assert!(claim_drop_warning(&slot), "a never-warned slot claims");
        assert!(slot.load(Ordering::Relaxed) != NEVER_WARNED);
        assert!(
            !claim_drop_warning(&slot),
            "a second claim inside the window is refused"
        );
    }

    /// Encode `payload` the way [`DgramFragmenter`] does, for reassembler tests
    /// that need no connection. The limit is generous so only `chunk` splits.
    fn frag_frames(
        id: u16,
        sess: u32,
        addr: &TargetAddrRef<'_>,
        payload: &[u8],
        chunk: usize,
    ) -> Vec<Bytes> {
        let total = payload.len().div_ceil(chunk) as u8;
        payload
            .chunks(chunk)
            .enumerate()
            .map(|(i, part)| {
                encode_fragment(sess, id, i as u8, total, addr, part, 64 * 1024).unwrap()
            })
            .collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The per-partial byte cap is enforced, not merely documented.
    ///
    /// `f.total` is bounded by `MQP_FRAG_MAX_TOTAL`, but nothing bounds a
    /// *chunk*: at the QUIC path MTU a hostile or buggy peer fits ~1.4 KiB in
    /// each of 64 fragments, which assembles to ~91 KiB — a datagram the
    /// fragmenter on the *sending* side would have refused outright, handed to
    /// `udp_try_send` and then to the kernel to IP-fragment. The aggregate
    /// `FRAG_MAX_HELD_BYTES` bound does not catch it (one such partial is well
    /// under 256 KiB), so the cap has to be checked per partial.
    #[test]
    fn a_partial_past_the_payload_cap_is_discarded_whole() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 8 x 1400 B = 11200 B, past MQP_FRAG_MAX_PAYLOAD (8192) but far inside
        // both the fragment-count cap and the aggregate byte cap.
        let over = frag_frames(1, 1, &addr.as_ref(), &pattern(11_200), 1400);
        assert_eq!(over.len(), 8);
        let mut r = DgramReassembler::new();
        for (i, fr) in over.iter().enumerate() {
            let got = r.push(&decode_fragment(fr).unwrap(), 1_000);
            assert!(
                got.is_none(),
                "fragment {i} completed a partial past the payload cap"
            );
        }
        assert!(
            r.held_bytes() <= MQP_FRAG_MAX_PAYLOAD,
            "the over-cap partial must be released, not retained: {} B held",
            r.held_bytes()
        );

        // Positive control: the same shape one fragment shorter *does* complete,
        // so the test cannot pass by rejecting everything.
        let under = frag_frames(2, 1, &addr.as_ref(), &pattern(7_000), 1400);
        assert_eq!(under.len(), 5);
        let mut r = DgramReassembler::new();
        let mut done = None;
        for fr in &under {
            done = r.push(&decode_fragment(fr).unwrap(), 1_000);
        }
        assert_eq!(
            done.expect("a 7000 B payload is inside the cap").2.len(),
            7_000
        );

        // A *duplicate* fragment adds no bytes, so a replay of an already-filled
        // index must not be what pushes a legal partial over the cap.
        let mut r = DgramReassembler::new();
        let exact = frag_frames(3, 1, &addr.as_ref(), &pattern(8_192), 1_024);
        assert_eq!(exact.len(), 8);
        for fr in &exact[..7] {
            assert!(r.push(&decode_fragment(fr).unwrap(), 1_000).is_none());
        }
        // Replaying index 0 must be ignored, and the last fragment must still
        // complete the datagram.
        assert!(r
            .push(&decode_fragment(&exact[0]).unwrap(), 1_000)
            .is_none());
        let done = r.push(&decode_fragment(&exact[7]).unwrap(), 1_000);
        assert_eq!(
            done.expect("a payload exactly at the cap must complete")
                .2
                .len(),
            8_192
        );
    }

    /// The coarse epoch advances with wall time, on its own.
    ///
    /// This is the property that makes it a safe replacement for a per-packet
    /// `mono_millis()` in the throttles: a *packet-count* sampler freezes when
    /// packets stop arriving (see `TouchMemo`), so a trickle flow's stamp stops
    /// moving and the 180 s reaper kills a live session. An epoch driven by
    /// wall time (quanta's upkeep thread) cannot do that — and this test fails
    /// if the implementation is ever swapped for a counter.
    #[tokio::test]
    async fn coarse_millis_advances_without_traffic() {
        // The value must be a real sample of the shared clock, not an
        // uninitialized sentinel. A consumer stores the first value it sees as
        // its baseline and compares later samples against it, so a 0 read *long
        // after* process start would mean "idle since the epoch began" and its
        // very first deadline check would fire — which is why `coarse_millis`
        // falls back to the live clock until the upkeep thread has published
        // its first sample, and shares `mono_millis`'s START. (A literal 0 is
        // still legitimate during the process's first millisecond, when
        // `mono_millis` is 0 as well, so the assertion is about the *gap*
        // between the two clocks.)
        let first = coarse_millis();
        let fine = mono_millis();
        assert!(
            first <= fine,
            "the cursor is a sample of mono_millis and cannot run ahead of it"
        );
        assert!(
            fine.saturating_sub(first) < 1_000,
            "first sample {first} is more than one tick behind the fine clock {fine}: \
             the cursor was left at a sentinel instead of seeded"
        );

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let later = coarse_millis();
        assert!(
            later > first,
            "the epoch must advance with wall time ({first} -> {later}), with no \
             packets in flight: a count-based sampler would freeze here, which is \
             the liveness bug `TouchMemo` records"
        );
    }

    /// The coarse epoch keeps advancing across a runtime hand-off.
    ///
    /// This is the failure mode the whole design has to rule out: a frozen
    /// clock does not corrupt anything, it silently stops every idle watchdog
    /// and every reaper in the process — the exact liveness bug the epoch was
    /// chosen over a packet counter to avoid, arriving by a different route.
    /// The old ticker was a Tokio task, so a runtime hand-off (one runtime per
    /// `#[tokio::test]`; an embedder may run several) could freeze it;
    /// quanta's upkeep thread is runtime-independent, and this test still pins
    /// the property end to end rather than trusting that.
    ///
    /// The assertion is "the epoch advanced while a second runtime was live",
    /// which holds however the epoch is being driven — so it is a genuine test
    /// of the property rather than of one implementation's bookkeeping.
    #[test]
    fn the_coarse_epoch_is_rearmed_after_its_runtime_ends() {
        let rt1 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Both runtimes must live long enough for the epoch to read non-zero
        // (it counts from the process's first clock read). A test that dropped
        // the first runtime inside the process's first millisecond would read
        // 0 and could not tell a live clock from a frozen one.
        rt1.block_on(async {
            let _ = coarse_millis();
            tokio::time::sleep(Duration::from_millis(1_200)).await;
        });
        drop(rt1);

        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (first, later) = rt2.block_on(async {
            let first = coarse_millis();
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            (first, coarse_millis())
        });
        assert!(
            first > 0,
            "a zero epoch means this test cannot tell a live clock from a frozen one"
        );
        assert!(
            later > first,
            "the epoch froze across a runtime hand-off ({first} -> {later}): nothing \
             runtime-bound is keeping it alive"
        );
    }

    /// The `u8` fragment count must reach the UDP maximum even at QUIC's
    /// minimum path MTU, so raising `MQP_FRAG_MAX_PAYLOAD` later is a one-line
    /// change and never a wire-format change. (The same bound is asserted at
    /// compile time next to `MQP_FRAG_MAX_TOTAL`.)
    #[test]
    fn the_fragment_count_reaches_the_udp_maximum_at_the_minimum_mtu() {
        let min_chunk = MIN_PATH_DGRAM_BUDGET - FRAG_PREFIX_LEN - (1 + 16 + 2);
        assert_eq!(min_chunk, 1134, "1200 B path, IPv6 target");
        assert_eq!(UDP_PAYLOAD_MAX.div_ceil(min_chunk), 58);
        assert!(UDP_PAYLOAD_MAX.div_ceil(min_chunk) <= MQP_FRAG_MAX_TOTAL as usize);

        // A full Ethernet path needs fewer, but the worst case is what bounds it.
        let eth_chunk = 1434 - FRAG_PREFIX_LEN - (1 + 4 + 2);
        assert_eq!(eth_chunk, 1418);
        assert_eq!(UDP_PAYLOAD_MAX.div_ceil(eth_chunk), 47);
    }

    /// Why `MQP_FRAG_MAX_PAYLOAD` is 8 KiB and not the 65507 B UDP maximum:
    /// reassembly is all-or-nothing, so a payload's survival is `(1-p)^F` while
    /// its cost stays `F` fragments. Pinning the numbers here forces any future
    /// change to argue with them rather than re-derive them wrongly.
    #[test]
    fn fragment_count_documents_the_loss_amplification_tradeoff() {
        let chunk = 1434 - FRAG_PREFIX_LEN - (1 + 4 + 2); // IPv4 target, 1472 B path
        let frags = |payload: usize| payload.div_ceil(chunk);
        let survives = |f: usize, p: f64| (1.0 - p).powi(f as i32);

        assert_eq!(frags(1472), 2, "a full Ethernet payload");
        assert_eq!(frags(MQP_FRAG_MAX_PAYLOAD), 6, "the protocol cap");
        assert_eq!(frags(UDP_PAYLOAD_MAX), 47, "the UDP maximum");

        // At 1 % loss everything up to the cap still lands ~95 %+ of the time...
        assert!(survives(frags(MQP_FRAG_MAX_PAYLOAD), 0.01) > 0.94);
        // ...while a 64 KiB payload is a coin flip that costs 47x the bytes.
        assert!(survives(frags(UDP_PAYLOAD_MAX), 0.01) < 0.63);
        // At 5 % loss the UDP maximum is effectively undeliverable.
        assert!(survives(frags(UDP_PAYLOAD_MAX), 0.05) < 0.10);
    }

    #[test]
    fn udp_snapshot_differences_counters_but_not_the_high_water_mark() {
        let a = UdpSnapshot {
            datagrams: 100,
            bytes: 9_000,
            fragmented: 4,
            max_payload: 1_400,
            sessions: 2,
        };
        let b = UdpSnapshot {
            datagrams: 130,
            bytes: 12_000,
            fragmented: 6,
            max_payload: 1_900,
            sessions: 3,
        };
        let d = b.since(&a);
        assert_eq!(
            (d.datagrams, d.bytes, d.fragmented, d.sessions),
            (30, 3_000, 2, 1)
        );
        assert_eq!(d.max_payload, 1_900, "a maximum cannot be differenced");
        assert!(!d.is_idle());
        assert!(b.since(&b).is_idle(), "an empty interval stays quiet");
        // Saturating, so a snapshot taken out of order cannot wrap into an
        // absurd delta.
        assert_eq!(a.since(&b).datagrams, 0);
    }

    /// The dispatcher's rule, in one place. A frame type the router does not
    /// recognise must be skipped, but *both* relay frames carry `sess` at the
    /// same offset — switching on the type is what silently dropped every
    /// fragmented reply before the reassembler could see it.
    #[test]
    fn dgram_sess_routes_both_frame_types() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let plain = encode_datagram(7, &addr, b"x").unwrap();
        let frag = encode_fragment(9, 1, 0, 2, &addr.as_ref(), b"y", 4096).unwrap();
        assert_eq!(dgram_sess(&plain), Some(7));
        assert_eq!(dgram_sess(&frag), Some(9));
        assert_eq!(dgram_sess(&frag), dgram_sess(&plain).map(|_| 9));

        // Not relay frames: an address atyp, an unknown type, a runt.
        assert_eq!(dgram_sess(&[0x01, 0, 0, 0, 0, 0]), None);
        assert_eq!(dgram_sess(&[0x7f, 0, 0, 0, 0, 0]), None);
        assert_eq!(dgram_sess(&[MQP_DGRAM_FRAG, 0, 0]), None);
        assert_eq!(dgram_sess(&[]), None);
    }

    /// The counters must actually move, and `max_payload` must be a high-water
    /// mark rather than the most recent value — that is what makes it the
    /// empirical answer to "is the 8 KiB cap big enough here?".
    #[test]
    fn udp_stats_records_payloads_and_sessions() {
        // Other tests drive `DgramFragmenter::send` concurrently, so assert
        // lower bounds rather than exact deltas.
        let before = udp_stats::snapshot();
        udp_stats::payload(1_472);
        udp_stats::fragmented(3);
        udp_stats::fragmented(1); // unfragmented: must not count
        udp_stats::session();
        let after = udp_stats::snapshot();
        let d = after.since(&before);
        assert!(d.datagrams >= 1 && d.bytes >= 1_472);
        assert!(d.fragmented >= 1);
        assert!(d.sessions >= 1);
        assert!(after.max_payload >= 1_472);

        // A later *smaller* payload must not lower the mark.
        udp_stats::payload(64);
        assert!(udp_stats::snapshot().max_payload >= 1_472);
    }

    /// Reassembly losses must stay observable: they are drop-path counters, and
    /// the reassembly line is the only signal for a fragment lost in transit.
    #[test]
    fn reassembly_counters_are_live() {
        let (expired, evicted) = udp_stats::reassembly_drops();
        udp_stats::reassembly_expired();
        udp_stats::reassembly_evicted();
        let (expired2, evicted2) = udp_stats::reassembly_drops();
        assert!(expired2 > expired, "an expiry must reach the snapshot");
        assert!(evicted2 > evicted, "an eviction must reach the snapshot");
    }

    /// The fragment path must feed the same counters as the single-frame path.
    /// It used to call only `fragmented()`, so fragmented payloads — the exact
    /// size class the 8 KiB cap question is about — were invisible in
    /// `datagrams`/`bytes` and in the `high-water payload` line.
    ///
    /// Deliberately wired through a real connection and the real
    /// `DgramFragmenter::send`: the direct `udp_stats::payload()` test above
    /// cannot catch a caller that never calls it.
    #[tokio::test]
    async fn fragmented_send_counts_the_payload_and_the_high_water() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();
        let limit = conn.max_datagram_size().unwrap();
        let payload = vec![0xABu8; 2_000];
        assert!(payload.len() <= MQP_FRAG_MAX_PAYLOAD);
        let addr = TargetAddr::Ip("93.184.216.34:53".parse().unwrap());

        let before = udp_stats::snapshot();
        let mut frag = DgramFragmenter::new();
        let sent = frag.send(&conn, 7, &addr.as_ref(), &payload, limit);
        assert!(
            sent.complete(),
            "a 2000 B payload must fragment cleanly: {sent:?}"
        );
        assert!(sent.fragmented(), "2000 B cannot fit one loopback frame");
        // Lower bounds only: sibling tests drive the same counters on other
        // threads (the same caveat `udp_stats_records_payloads_and_sessions`
        // documents), but `bytes` can only have moved from a counted send.
        let after = udp_stats::snapshot();
        let d = after.since(&before);
        assert!(
            d.datagrams >= 1 && d.bytes >= payload.len() as u64,
            "a fragmented payload must be counted: {d:?}"
        );
        assert!(
            after.max_payload >= payload.len() as u64,
            "the high-water mark must see fragmented payloads"
        );
    }

    /// `held_bytes` must be the *exact* memory a partial retains, and the
    /// aggregate cap must bound it.
    ///
    /// Retention used to be the received datagram's `Bytes` slice charged at the
    /// frame's length. That is not a bound at all: the frame is a slice of
    /// quinn's per-`recvmsg` receive batch (up to ~92 KiB with GRO), so a chunk
    /// could pin ~92 KiB while `held_bytes()` read 20 B. Chunks are owned copies
    /// now, so the retained figure is checkable exactly — chunk bytes plus the
    /// slot table — and the cap really bounds what a flood can pin.
    #[test]
    fn retained_bytes_are_exact_and_bounded() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let mut r = DgramReassembler::new();
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        assert_eq!(frames.len(), 2, "6000 B over 4000 B chunks");
        let f0 = decode_fragment(&frames[0]).unwrap();
        assert!(r.push(&f0, 0).is_none());
        assert_eq!(
            r.held_bytes(),
            f0.chunk.len() + Partial::slot_table_bytes(f0.total),
            "retained must be exactly the owned chunk plus its slot table"
        );
        // Completion files the delivered generation as the key's tombstone,
        // so `held` keeps exactly the payload plus its slot table — still
        // bounded, still accounted — and the tick releases it with the window.
        assert!(r.push(&decode_fragment(&frames[1]).unwrap(), 0).is_some());
        assert_eq!(r.inflight(), 0);
        let f1 = decode_fragment(&frames[1]).unwrap();
        assert_eq!(
            r.held_bytes(),
            f0.chunk.len() + f1.chunk.len() + Partial::slot_table_bytes(f1.total),
        );
        r.expire(FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0, "the tombstone ages out with the window");

        // A flood of never-completing full-width partials is still bounded, and
        // the bound still evicts rather than merely reporting a number. With
        // exact accounting each such partial costs its 63 stored fragments plus
        // a 64-slot table (2 KiB), so 200 of them (~500 KiB) must be trimmed to
        // the 256 KiB cap — and the count cap (256) is not what does it.
        let addr = TargetAddr::Domain("a".repeat(255), 53);
        let chunk = [0u8; 8];
        let total = 64u8;
        let fed = 200u16;
        let mut r = DgramReassembler::new();
        let mut completed = 0;
        for id in 0..fed {
            for idx in 0..(total - 1) {
                let body =
                    encode_fragment(1, id, idx, total, &addr.as_ref(), &chunk, 4096).unwrap();
                let f = decode_fragment(&body).unwrap();
                if r.push(&f, 0).is_some() {
                    completed += 1;
                }
            }
        }
        assert_eq!(completed, 0, "each partial is one fragment short");
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "retained bytes must stay inside the aggregate cap: {} B",
            r.held_bytes()
        );
        assert!(
            r.inflight() < fed as usize,
            "the byte bound must evict full-width partials: {} of {fed} in flight",
            r.inflight()
        );
        assert!(r.inflight() > 0, "the newest partials stay");
    }

    /// A partial must expire on a clock tick, with no fragment arriving.
    ///
    /// `push` is the only other path that expires state, so without a tick a
    /// peer that sends fragments and then goes quiet (keeping its connection
    /// alive on keepalives) pins its partials — and every byte they retain —
    /// for the connection's lifetime.
    #[test]
    fn expire_drops_partials_without_a_following_fragment() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        let mut r = DgramReassembler::new();
        assert!(r
            .push(&decode_fragment(&frames[0]).unwrap(), 1_000)
            .is_none());
        assert_eq!(r.inflight(), 1);
        assert!(r.held_bytes() > 0);

        // Still inside the window: nothing may be dropped.
        r.expire(1_000 + FRAG_TIMEOUT_MS - 1);
        assert_eq!(r.inflight(), 1, "a live partial survives the tick");

        r.expire(1_000 + FRAG_TIMEOUT_MS);
        assert_eq!(r.inflight(), 0, "the tick expires it with no push at all");
        assert_eq!(r.held_bytes(), 0, "and gives its bytes back");
    }

    /// The sender must refuse to reuse a fragment id while the receiver can
    /// still hold a partial for it, because reuse is what lets two datagrams
    /// splice (see `same_shape_id_reuse_restarts_instead_of_splicing` for the
    /// case the receiver *can* detect, and `push_with_chunk` for the case it
    /// cannot).
    #[test]
    fn fragment_id_reuse_is_blocked_inside_the_reassembly_window() {
        // Never wrapped (0): every id so far is a first use, nothing to guard.
        assert!(!frag_id_reuse_blocked(0, 1_000_000));
        // Wrapped just now: the ids of the new cycle were all in use a moment
        // ago, so reusing one could splice.
        assert!(frag_id_reuse_blocked(10_000, 10_000));
        assert!(frag_id_reuse_blocked(
            10_000,
            10_000 + FRAG_ID_SAFE_WINDOW_MS - 1
        ));
        // The receiver has had its whole window plus a sweep by now.
        assert!(!frag_id_reuse_blocked(
            10_000,
            10_000 + FRAG_ID_SAFE_WINDOW_MS
        ));
        // The window must outlast the partial lifetime it protects; that
        // invariant is asserted at the constant itself.
    }

    /// The invariant the id guard actually exists to protect: whenever an id is
    /// reissued, at least [`FRAG_ID_SAFE_WINDOW_MS`] has passed since it was
    /// last used. Asserting the *loss profile* instead is not enough — a looser
    /// reference (the previous cycle's start, or an interpolated per-id estimate)
    /// drives refusals to zero while quietly letting ids be reused inside the
    /// window, which is a datagram splice. This test therefore tracks every id's
    /// true last-use time independently and checks the gap.
    ///
    /// Pure, so it runs without a live connection; it calls
    /// `try_claim_id` — the production gate — once per payload.
    #[test]
    fn id_reuse_never_lands_inside_the_reassembly_window() {
        // `per_ms` payloads issued within one millisecond. The dangerous regime
        // is a *high* value: the id space then retires in less than
        // `FRAG_ID_SAFE_WINDOW_MS`, so a gate that references anything older than
        // the current cycle's start starts reissuing ids inside the window.
        // Production logic, not a copy — an earlier revision re-implemented the
        // gate inline and therefore passed with the unsafe variant in place.
        let mut refused_when_impossible = 0usize;
        for per_ms in [1usize, 4, 16, 64, 256, 1024] {
            let mut f = DgramFragmenter::new();
            let mut last_use = vec![0u64; u16::MAX as usize + 1];
            let mut now = 1_000_000u64;
            let mut refused = 0usize;
            for n in 0..3 * (u16::MAX as u64 + 1) {
                match f.try_claim_id(now) {
                    None => refused += 1,
                    Some(id) => {
                        let prev = last_use[id as usize];
                        assert!(
                            prev == 0 || now.saturating_sub(prev) >= FRAG_ID_SAFE_WINDOW_MS,
                            "id {id} reissued after {}ms (< {FRAG_ID_SAFE_WINDOW_MS}) at \
                             {per_ms} payloads/ms — that is a splice",
                            now.saturating_sub(prev)
                        );
                        last_use[id as usize] = now;
                    }
                }
                if (n as usize + 1).is_multiple_of(per_ms) {
                    now += 1;
                }
            }
            if per_ms >= 64 {
                refused_when_impossible += refused;
            }
        }
        assert!(
            refused_when_impossible > 0,
            "a cycle shorter than the window must be refused, so the guard is not vacuous"
        );
    }

    /// The guard is wired into `send`, not merely available as a predicate: a
    /// context whose id space just wrapped must refuse the oversized payload
    /// (counted as a size drop) and resume once the window has passed.
    #[tokio::test]
    async fn fragmenter_refuses_a_reused_id_inside_the_window() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _sconn = accept.await.unwrap();

        let addr = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        // Use the live DATAGRAM budget: a hard-coded limit above it would be
        // refused by the encoder for the wrong reason.
        let limit = conn.max_datagram_size().expect("DATAGRAM negotiated");
        let payload = pattern(limit + 200);
        let mut frag = DgramFragmenter::new();

        let before = dgram_drops::snapshot();
        // The id space just wrapped: the ids of the new cycle were all in use a
        // moment ago, so reusing one could splice. `next_id` is mid-cycle so the
        // stamp this arm sets is not immediately overwritten by the next wrap.
        frag.last_wrap_ms = mono_millis();
        frag.next_id = 7;
        let refused = frag.send(&conn, 1, &addr.as_ref(), &payload, limit);
        assert_eq!(refused.frames, 0);
        assert_eq!(refused.failed, Some(DatagramSend::TooLarge));
        assert!(
            dgram_drops::snapshot().too_large > before.too_large,
            "a refusal that loses an oversized payload must be counted"
        );

        frag.last_wrap_ms = mono_millis().saturating_sub(FRAG_ID_SAFE_WINDOW_MS);
        let sent = frag.send(&conn, 1, &addr.as_ref(), &payload, limit);
        assert!(
            sent.complete() && sent.frames > 1,
            "fragmenting resumes once the receiver cannot still hold the id: {sent:?}"
        );
    }

    #[test]
    fn fragment_reassembly_is_order_independent() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let payload = pattern(5000);
        let frames = frag_frames(7, 3, &addr.as_ref(), &payload, 1400);
        assert_eq!(frames.len(), 4, "5000 B over 1400 B chunks");

        for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]] {
            let mut r = DgramReassembler::new();
            let mut done = None;
            for i in order {
                if let Some(x) = r.push(&decode_fragment(&frames[i]).unwrap(), 1_000) {
                    done = Some(x);
                }
            }
            let (sess, got_addr, whole) = done.expect("every fragment arrived");
            assert_eq!(sess, 3);
            assert_eq!(got_addr, addr);
            assert_eq!(&whole[..], &payload[..], "order {order:?} must reassemble");
            assert_eq!(r.inflight(), 0, "the partial is released on completion");
            assert_eq!(
                r.held_bytes(),
                payload.len() + Partial::slot_table_bytes(4),
                "completion files the delivered generation against the budget"
            );
        }
    }

    #[test]
    fn a_lost_fragment_never_yields_a_short_payload() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let payload = pattern(3000);
        let frames = frag_frames(1, 1, &addr.as_ref(), &payload, 1400);
        assert_eq!(frames.len(), 3);

        // UDP semantics: an incomplete datagram is discarded, never delivered
        // short — a short read is exactly what the old 1338 B cap looked like
        // to the application.
        for missing in 0..frames.len() {
            let mut r = DgramReassembler::new();
            let mut completed = 0;
            for (i, fr) in frames.iter().enumerate() {
                if i == missing {
                    continue;
                }
                if r.push(&decode_fragment(fr).unwrap(), 0).is_some() {
                    completed += 1;
                }
            }
            assert_eq!(completed, 0, "missing fragment {missing} must not complete");
        }

        // Duplicates within a partial are idempotent: a replayed fragment must
        // not advance the count, or three distinct fragments plus one replay
        // would "complete" a four-fragment datagram.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        assert!(
            r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none(),
            "a replayed fragment must not advance the count"
        );
        assert!(r.push(&decode_fragment(&frames[1]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&frames[2]).unwrap(), 0);
        let (_, _, w) = done.expect("completes once all three distinct fragments arrive");
        assert_eq!(w.len(), payload.len());
    }

    #[test]
    fn malformed_fragments_are_rejected_without_allocating_state() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(3000), 1400);
        let mut r = DgramReassembler::new();

        let mut f = decode_fragment(&frames[0]).unwrap();
        f.total = 1; // that is the single-frame form, not a fragment
        assert!(r.push(&f, 0).is_none());
        let mut f = decode_fragment(&frames[0]).unwrap();
        f.idx = 9; // index outside the declared count
        assert!(r.push(&f, 0).is_none());
        let mut f = decode_fragment(&frames[0]).unwrap();
        f.total = MQP_FRAG_MAX_TOTAL + 1;
        assert!(r.push(&f, 0).is_none());
        assert_eq!(
            r.inflight(),
            0,
            "a malformed fragment must not allocate state"
        );

        // A wrapped id reused with a different shape restarts rather than
        // splicing two unrelated datagrams together: 3000 B is 3 fragments,
        // 6000 B is 5, and the first two of the new shape must not complete
        // against the old count.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        let other = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 1400);
        assert_eq!(other.len(), 5);
        for fr in &other[1..4] {
            assert!(r.push(&decode_fragment(fr).unwrap(), 0).is_none());
        }
        assert!(r.push(&decode_fragment(&other[4]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&other[0]).unwrap(), 0);
        assert!(done.is_some(), "the restarted partial completes");
        assert_eq!(done.unwrap().2.len(), 6000);
    }

    #[test]
    fn partials_expire_and_reassembly_memory_is_bounded() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 6000 B over 4000 B chunks is exactly two fragments; a payload equal to
        // its chunk would be a one-fragment "fragment", which is malformed.
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 4000);
        assert_eq!(frames.len(), 2);

        // A fragment arriving after the partial expired starts a new partial
        // instead of completing the stale one.
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        assert_eq!(r.inflight(), 1);
        assert!(r
            .push(
                &decode_fragment(&frames[1]).unwrap(),
                FRAG_TIMEOUT_MS + 1_500
            )
            .is_none());
        assert_eq!(
            r.inflight(),
            1,
            "the stale partial was swept, a new one began"
        );

        // A flood of never-completing datagrams cannot grow memory without
        // bound: past FRAG_MAX_HELD_BYTES the oldest partial is evicted.
        let mut r = DgramReassembler::new();
        let (_, ev0) = udp_stats::reassembly_drops();
        // 7000 B over 4000 B chunks: two fragments, so the first push allocates
        // a partial (a payload equal to its chunk would be a one-fragment
        // "fragment", which the reassembler rightly refuses).
        let big_frames = frag_frames(1, 1, &addr.as_ref(), &pattern(7000), 4000);
        assert_eq!(big_frames.len(), 2);
        for id in 0..200u16 {
            let mut f = decode_fragment(&big_frames[0]).unwrap();
            f.id = id;
            assert!(r.push(&f, 0).is_none());
        }
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "held {} B exceeds the {FRAG_MAX_HELD_BYTES} B cap",
            r.held_bytes()
        );
        assert!(
            r.inflight() > 0 && r.inflight() < 200,
            "old partials were evicted"
        );
        assert!(
            udp_stats::reassembly_drops().1 > ev0,
            "an evicted partial must be counted"
        );
    }

    #[test]
    fn slot_tables_are_charged_to_the_aggregate_byte_budget() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // Empty chunks pin nearly nothing themselves, which is exactly why the
        // slot table has to be charged: before this, `held` stayed tiny while
        // FRAG_MAX_PARTIALS x 64 x 32 B of table sat outside every byte bound.
        let one = encode_fragment(1, 0, 0, 64, &addr.as_ref(), &[], 1200).unwrap();
        let fr = decode_fragment(&one).unwrap();
        assert!(fr.chunk.is_empty());
        let mut r = DgramReassembler::new();
        assert!(r.push(&fr, 0).is_none());
        assert_eq!(
            r.held_bytes(),
            Partial::slot_table_bytes(64),
            "a partial whose chunk is empty still costs its slot table"
        );
        assert_eq!(r.inflight(), 1);

        // A flood of full-width, never-completing partials must therefore be
        // evicted by the *byte* bound, not merely parked under the count cap.
        let mut r = DgramReassembler::new();
        for id in 0..(FRAG_MAX_PARTIALS as u16 + 50) {
            let body = encode_fragment(1, id, 0, 64, &addr.as_ref(), &[], 1200).unwrap();
            let f = decode_fragment(&body).unwrap();
            assert!(r.push(&f, 0).is_none());
        }
        assert!(
            r.held_bytes() <= FRAG_MAX_HELD_BYTES,
            "held {} B exceeds the {FRAG_MAX_HELD_BYTES} B cap",
            r.held_bytes()
        );
        assert!(
            r.inflight() < FRAG_MAX_PARTIALS,
            "the byte bound must bind before the count cap: {} partials",
            r.inflight()
        );
    }

    /// A byte-cap overflow must reclaim tombstones before live partials.
    ///
    /// Every completed datagram leaves an id-reuse tombstone charged to the
    /// same [`FRAG_MAX_HELD_BYTES`] budget as the live partials, so a burst of
    /// large fragmented payloads used to fill the cap with tombstones from the
    /// payloads that had just completed and then evict the partials still
    /// mid-assembly — reported as `0 expired, 96 evicted`, losing about half of
    /// an 8 KiB sweep at a 16-deep send window. Tombstones are replay guards,
    /// not deliverable bytes; they go first.
    #[test]
    fn byte_cap_reclaims_tombstones_before_live_partials() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        // 7800 B over 1300 B chunks: six fragments, just under the 8 KiB cap.
        let whole = pattern(7800);

        // Fill the budget with tombstones from completed payloads.
        let mut r = DgramReassembler::new();
        for id in 0..64u32 {
            let frames = frag_frames(7, id, &addr.as_ref(), &whole, 1300);
            assert_eq!(frames.len(), 6);
            let mut done = false;
            for f in &frames {
                done = r.push(&decode_fragment(f).unwrap(), 0).is_some();
            }
            assert!(done, "every fragment must reassemble");
        }
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
        assert_eq!(r.inflight(), 0, "every payload completed");

        // Start live partials and leave them incomplete.
        let live_ids: Vec<u32> = (1000..1020).collect();
        for id in &live_ids {
            for f in frag_frames(7, *id, &addr.as_ref(), &whole, 1300)
                .iter()
                .take(3)
            {
                assert!(r.push(&decode_fragment(f).unwrap(), 0).is_none());
            }
        }
        // One more incomplete fragment tips `held` over the cap.
        let tipping = frag_frames(7, 2000, &addr.as_ref(), &whole, 1300);
        assert!(r.push(&decode_fragment(&tipping[0]).unwrap(), 0).is_none());

        assert_eq!(
            r.inflight(),
            live_ids.len() + 1,
            "the cap must reclaim tombstones, not live partials"
        );
        assert!(r.held_bytes() <= FRAG_MAX_HELD_BYTES);
    }

    /// A live partial restarted by an id reuse files the old generation, so
    /// a stale replay of it cannot occupy the new partial's empty slots.
    ///
    /// The generations below differ in *every* chunk: after the restart on
    /// index 0, the replay of A's index 1 matches the filed generation and
    /// is refused, and B completes with only its own fragments. (A form that
    /// differs in one chunk alone never reaches the tombstone — the
    /// occupied-slot check restarts on the differing index and the shared
    /// chunks are byte-identical either way, so mixing them is harmless.)
    #[test]
    fn same_shape_id_reuse_restarts_instead_of_splicing() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let first = pattern(3000);
        let mut second = pattern(3000);
        for b in second.iter_mut() {
            *b ^= 0xFF;
        }
        assert_ne!(second, first);
        let frames_a = frag_frames(9, 1, &addr.as_ref(), &first, 1400);
        let frames_b = frag_frames(9, 1, &addr.as_ref(), &second, 1400);
        assert_eq!((frames_a.len(), frames_b.len()), (3, 3));

        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames_a[0]).unwrap(), 0).is_none());
        assert!(r.push(&decode_fragment(&frames_a[1]).unwrap(), 0).is_none());
        // Same (sess, id, total, idx) with different bytes: a fast reuse, not
        // a replay. The old partial is discarded and filed as the key's
        // tombstone, so the stale prefix of generation A no longer completes
        // anything.
        assert!(r.push(&decode_fragment(&frames_b[0]).unwrap(), 0).is_none());
        assert_eq!(r.inflight(), 1);
        // A stale replay of A's index 1 lands on an empty slot of B's live
        // partial — the exact shape the occupied-slot check cannot see. It
        // matches the filed generation and is refused: nothing completes,
        // nothing restarts, nothing is retained.
        let held_before = r.held_bytes();
        assert!(r.push(&decode_fragment(&frames_a[1]).unwrap(), 0).is_none());
        assert_eq!(
            r.inflight(),
            1,
            "the replay must leave the live partial alone"
        );
        assert_eq!(
            r.held_bytes(),
            held_before,
            "a refused replay retains nothing"
        );
        assert!(r.push(&decode_fragment(&frames_b[1]).unwrap(), 0).is_none());
        let done = r.push(&decode_fragment(&frames_b[2]).unwrap(), 0);
        let (_, _, whole) = done.expect("generation B completes with its own fragments");
        assert_eq!(&whole[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);
    }

    /// H1: a stale generation's suffix on the *empty* slots of the next
    /// generation's live partial must not splice — same total, same address,
    /// no occupied-slot overlap for the restart heuristic to see.
    ///
    /// Generation A completes whole (filed as the key's tombstone), then B
    /// reuses `(sess, id)` with a different payload. Without the tombstone,
    /// the stale replay of A's last chunk fills B's last empty slot and the
    /// reassembler delivers `[B0, B1, A2]` to A's target; with it, the replay
    /// is refused and B completes with only its own fragments. The second
    /// half covers the same shape through the restart path instead of a
    /// completion.
    #[test]
    fn fragment_empty_slot_reuse_does_not_splice() {
        fn flipped(payload: &[u8]) -> Vec<u8> {
            payload.iter().map(|b| b ^ 0xFF).collect()
        }
        let addr = TargetAddr::Ip("10.9.8.7:53".parse().unwrap());
        let first = pattern(3000);
        let second = flipped(&first);
        let frames_a = frag_frames(11, 5, &addr.as_ref(), &first, 1400);
        let frames_b = frag_frames(11, 5, &addr.as_ref(), &second, 1400);
        assert_eq!((frames_a.len(), frames_b.len()), (3, 3));

        let mut r = DgramReassembler::new();
        // Generation A completes whole and is delivered verbatim.
        let mut done = None;
        for fr in &frames_a {
            done = r.push(&decode_fragment(fr).unwrap(), 1_000);
        }
        let (_, _, whole) = done.expect("generation A completes");
        assert_eq!(&whole[..], &first[..]);
        assert_eq!(r.inflight(), 0);

        // Generation B starts on the reused id: its prefix goes live.
        assert!(r
            .push(&decode_fragment(&frames_b[0]).unwrap(), 1_000)
            .is_none());
        assert!(r
            .push(&decode_fragment(&frames_b[1]).unwrap(), 1_000)
            .is_none());
        assert_eq!(r.inflight(), 1);
        let held_before = r.held_bytes();

        // A stale replay of A's suffix lands on B's last empty slot. This is
        // the splice: stored, it would complete `[B0, B1, A2]`.
        assert!(r
            .push(&decode_fragment(&frames_a[2]).unwrap(), 1_000)
            .is_none());
        assert_eq!(
            r.inflight(),
            1,
            "the replay must neither complete nor restart the live partial"
        );
        assert_eq!(
            r.held_bytes(),
            held_before,
            "a refused replay retains nothing"
        );

        // B's own suffix completes a pure generation-B datagram.
        let done = r.push(&decode_fragment(&frames_b[2]).unwrap(), 1_000);
        let (_, _, whole) = done.expect("generation B completes with its own fragments");
        assert_eq!(&whole[..], &second[..], "must not splice A and B together");
        assert_eq!(r.inflight(), 0);

        // Completion files the delivered generation against the aggregate
        // budget — exactly the payload plus its slot table...
        assert_eq!(r.held_bytes(), second.len() + Partial::slot_table_bytes(3));
        // ...and the tick releases it with the window.
        r.expire(1_000 + FRAG_TIMEOUT_MS);
        assert_eq!(r.held_bytes(), 0);

        // Restart path: C's prefix goes live, D restarts it, and a stale
        // replay of C's prefix on D's empty slot is refused the same way.
        let third = pattern(3000);
        let fourth = flipped(&third);
        let frames_c = frag_frames(12, 5, &addr.as_ref(), &third, 1400);
        let frames_d = frag_frames(12, 5, &addr.as_ref(), &fourth, 1400);
        assert!(r
            .push(&decode_fragment(&frames_c[0]).unwrap(), 1_000)
            .is_none());
        assert!(r
            .push(&decode_fragment(&frames_c[1]).unwrap(), 1_000)
            .is_none());
        assert!(r
            .push(&decode_fragment(&frames_d[0]).unwrap(), 1_000)
            .is_none());
        let held_before = r.held_bytes();
        assert!(r
            .push(&decode_fragment(&frames_c[1]).unwrap(), 1_000)
            .is_none());
        assert_eq!(r.inflight(), 1);
        assert_eq!(r.held_bytes(), held_before);
        assert!(r
            .push(&decode_fragment(&frames_d[1]).unwrap(), 1_000)
            .is_none());
        let done = r.push(&decode_fragment(&frames_d[2]).unwrap(), 1_000);
        let (_, _, whole) = done.expect("generation D completes with its own fragments");
        assert_eq!(&whole[..], &fourth[..], "must not splice C and D together");
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn restart_releases_the_old_bytes_from_held() {
        let addr = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let frames = frag_frames(1, 1, &addr.as_ref(), &pattern(3000), 1400);
        let other = frag_frames(1, 1, &addr.as_ref(), &pattern(6000), 1400);
        let mut r = DgramReassembler::new();
        assert!(r.push(&decode_fragment(&frames[0]).unwrap(), 0).is_none());
        let held_before = r.held_bytes();
        assert!(held_before > 0);
        // Different shape forces a restart: held must drop the old bytes from
        // the live partial and file them as the key's tombstone, counting the
        // new fragment (payload + its slot table) plus the filed generation —
        // never accumulating either twice.
        assert!(r.push(&decode_fragment(&other[0]).unwrap(), 0).is_none());
        let f0 = decode_fragment(&other[0]).unwrap();
        let table = Partial::slot_table_bytes(f0.total);
        assert!(table > 0, "the slot table is charged, not free");
        let old = decode_fragment(&frames[0]).unwrap();
        let tomb = old.chunk.len() + Partial::slot_table_bytes(old.total);
        assert_eq!(r.held_bytes(), f0.chunk.len() + table + tomb);
    }

    /// Half-close propagation between two pumps: when the app shuts down its
    /// write side, the FIN must travel app -> QUIC -> peer TCP and back,
    /// instead of each pump waiting for a FIN only the final disposition
    /// would send. Pre-fix this test hung on every await: both pumps lingered
    /// until the 300 s idle reap, pinning tasks, sockets and stream-task
    /// permits per cleanly-closed flow — so the idle budget here is
    /// deliberately 300 s and every await above it is bounded by a 10 s
    /// timeout. (A single pump against a far end that unconditionally
    /// finishes cannot catch this: the deadlock needs a symmetric peer whose
    /// own TCP never closes first, exactly like a real echo target.)
    #[tokio::test]
    async fn half_close_propagates_and_the_pump_finishes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let a = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (b, _) = listener.accept().await.unwrap();
            (a, b)
        }

        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        // The far accept only resolves after the first STREAM frame arrives
        // (quinn requires a write before accept_bi fires), so pump1 must be
        // running and the app must send before awaiting the far end.
        let far_conn = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (s, r) = conn.accept_bi().await.unwrap();
            (conn, s, r)
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();

        // App <-> pump1 <-> QUIC <-> pump2 <-> echo socket E1; the test holds
        // E2 (peer's TCP read side) open until the FIN arrives, mimicking an
        // echo target that only closes on EOF.
        let (mut app, pump_tcp) = tcp_pair().await;
        let (echo_ours, mut echo_theirs) = tcp_pair().await;
        let pump1 = tokio::spawn(copy_tcp_quic_idle(
            pump_tcp,
            send,
            recv,
            Duration::from_secs(300),
        ));
        app.write_all(b"hello-half-close").await.unwrap();
        let (_far, far_send, far_recv) = tokio::time::timeout(Duration::from_secs(10), far_conn)
            .await
            .expect("far accept fires once the first STREAM frame arrives")
            .unwrap();
        let pump2 = tokio::spawn(copy_tcp_quic_idle(
            echo_ours,
            far_send,
            far_recv,
            Duration::from_secs(300),
        ));
        app.shutdown().await.unwrap();
        // The full 16 B must still arrive before any FIN: shutdown propagation
        // must not truncate in-flight data.
        let mut got = vec![0u8; 16];
        tokio::time::timeout(Duration::from_secs(10), echo_theirs.read_exact(&mut got))
            .await
            .expect("echo side must receive the payload")
            .unwrap();
        assert_eq!(got, b"hello-half-close");
        // Far pump's s2c saw QUIC EOF and must have half-closed E1: without
        // propagation this EOF never arrives.
        let mut one = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(10), echo_theirs.read(&mut one))
            .await
            .expect("echo side must observe EOF promptly");
        assert_eq!(n.unwrap(), 0, "echo side must observe EOF");
        drop(echo_theirs);
        // E2's close EOFs pump2's c2s, which finishes its QUIC send; pump1's
        // s2c then EOFs and half-closes the app socket.
        let n = tokio::time::timeout(Duration::from_secs(10), app.read(&mut one))
            .await
            .expect("app must observe EOF promptly");
        assert_eq!(n.unwrap(), 0, "app must observe EOF, not data or reset");
        // Both pumps must finish on their own rather than at the idle reap.
        let (up, down) = tokio::time::timeout(Duration::from_secs(10), pump1)
            .await
            .expect("pump1 must finish without the idle reap")
            .unwrap()
            .expect("pump1 must end clean");
        assert_eq!((up, down), (16, 0));
        let (up, down) = tokio::time::timeout(Duration::from_secs(10), pump2)
            .await
            .expect("pump2 must finish without the idle reap")
            .unwrap()
            .expect("pump2 must end clean");
        assert_eq!((up, down), (0, 16));
    }

    /// An abnormal pump end must be **told to the peer as a reset**, not dropped
    /// into a clean FIN.
    ///
    /// `Drop for quinn::SendStream` calls `finish()`, so before this was fixed a
    /// pump that gave up — because the other direction failed, or because the
    /// idle watchdog fired — left its send half to be dropped, and the peer's
    /// `read_chunks` returned a clean `Ok(None)`. The peer's own `abort_tcp`
    /// then never ran, so the application on that side saw EOF and accepted a
    /// truncated transfer as a whole one: precisely the silent corruption
    /// `abort_tcp` exists to prevent, one hop further out. The pump now resets
    /// the abandoned half explicitly.
    ///
    /// The test drives it from the *far* side: it resets its send stream (a
    /// download failure, the common case), which fails the near pump's `s2c`,
    /// and then asserts that the near pump's abandoned upload half arrives as a
    /// reset rather than as EOF. Falsified against the old code, which reported
    /// `Ok(0)` here.
    #[tokio::test]
    async fn abnormal_pump_end_resets_the_peer_stream_instead_of_finishing() {
        use tokio::io::AsyncWriteExt;

        async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let a = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (b, _) = listener.accept().await.unwrap();
            (a, b)
        }

        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let far = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            conn.accept_bi().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();

        let (mut app, pump_tcp) = tcp_pair().await;
        let pump = tokio::spawn(copy_tcp_quic_idle(
            pump_tcp,
            send,
            recv,
            Duration::from_secs(30),
        ));
        // The far accept only resolves once a STREAM frame arrives, so the app
        // must write first. It then stays open and silent: `c2s` has to be *in
        // flight* when `s2c` fails, or there would be nothing to abandon and the
        // completion gate would rightly decline to reset a finished half.
        app.write_all(b"up").await.unwrap();
        let (mut far_send, mut far_recv) = tokio::time::timeout(Duration::from_secs(10), far)
            .await
            .expect("far accept fires once the first STREAM frame arrives")
            .unwrap();
        // Kill the download half.
        far_send.write_all(b"x").await.unwrap();
        far_send.reset(7u32.into()).unwrap();

        let out = tokio::time::timeout(Duration::from_secs(10), pump)
            .await
            .expect("the pump must fail fast, not linger to the idle reap")
            .unwrap();
        assert!(
            out.is_err(),
            "a reset download half is not a clean end: {out:?}"
        );

        // The assertion that matters: the far side must observe a *reset*, which
        // is what makes it fail instead of believing the upload completed. Drain
        // whatever is legitimately queued first — the terminal event is what is
        // being judged.
        let mut buf = [0u8; 64];
        let mut drains = 0;
        let terminal = loop {
            match tokio::time::timeout(Duration::from_secs(10), far_recv.read(&mut buf)).await {
                Ok(Ok(Some(n))) if n > 0 && drains < 16 => {
                    drains += 1;
                    continue;
                }
                Ok(other) => break other,
                Err(_) => {
                    panic!("no terminal event within 10s: the stream neither reset nor finished")
                }
            }
        };
        match terminal {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(code.into_inner(), 0x04, "the pump's own reset code");
            }
            Ok(None) => panic!(
                "the peer saw a clean FIN on an abandoned stream: a truncated transfer \
                 would be accepted as a complete one"
            ),
            other => panic!("expected a reset, got {other:?}"),
        }
    }

    /// End to end over a real connection: every size up to the protocol cap
    /// arrives whole, and the frame counts prove the split actually happened.
    #[tokio::test]
    async fn fragmentation_round_trips_large_udp_payloads() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let target = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        let sizes = [1usize, 1400, 3000, MQP_FRAG_MAX_PAYLOAD];
        let expected: Vec<Vec<u8>> = sizes.iter().map(|n| pattern(*n)).collect();

        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let mut reasm = DgramReassembler::new();
            let mut out: Vec<(u32, TargetAddr, Bytes)> = Vec::new();
            while let Ok(d) = conn.read_datagram().await {
                if d.first() == Some(&MQP_DGRAM_FRAG) {
                    let Ok(f) = decode_fragment(&d) else { continue };
                    if let Some(x) = reasm.push(&f, mono_millis()) {
                        out.push(x);
                    }
                } else {
                    let Ok((s, a, p)) = decode_datagram_ref(&d) else {
                        continue;
                    };
                    out.push((s, a.into_owned(), Bytes::copy_from_slice(p)));
                }
            }
            out
        });

        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let limit = conn.max_datagram_size().unwrap();
        let cap = dgram_payload_cap(limit, &target.as_ref());
        assert!(cap > 0);
        let mut frag = DgramFragmenter::new();
        let mut frames = 0u8;
        for (i, payload) in expected.iter().enumerate() {
            let r = frag.send(&conn, i as u32, &target.as_ref(), payload, limit);
            assert!(
                r.complete(),
                "{} B send failed: {:?}",
                payload.len(),
                r.failed
            );
            assert_eq!(r.fragmented(), payload.len() > cap);
            frames = frames.saturating_add(r.frames);
        }
        assert!(
            frames > expected.len() as u8,
            "at least one payload must have been split"
        );

        // Above the protocol cap the payload is refused outright rather than
        // silently truncated by the reassembler.
        let too_big = pattern(MQP_FRAG_MAX_PAYLOAD + 1);
        let r = frag.send(&conn, 99, &target.as_ref(), &too_big, limit);
        assert_eq!(r.failed, Some(DatagramSend::TooLarge));
        assert_eq!(r.frames, 0);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        conn.close(0u32.into(), b"done");
        let got = accept.await.unwrap();
        assert_eq!(
            got.len(),
            expected.len(),
            "every payload arrives exactly once"
        );
        for (i, (sess, addr, payload)) in got.iter().enumerate() {
            assert_eq!(*sess, i as u32);
            assert_eq!(*addr, target);
            assert_eq!(&payload[..], &expected[i][..], "payload {i} mismatch");
        }
    }

    #[test]
    fn dgram_encoder_never_exceeds_the_wire_bound() {
        // The longest encodable datagram: a 255-byte domain, vs the constant
        // used for the send-buffer invariant.
        let longest = TargetAddr::Domain("a".repeat(255), u16::MAX);
        let d = encode_datagram_with_limit(0, &longest, &[0u8; 1350], 4096).unwrap();
        assert_eq!(d.len(), MQP_DGRAM_MAX + 1350);
    }

    /// The single-allocation encoder must produce byte-identical output to the
    /// straightforward `header()` + `encode()` pair for every address form, and
    /// must reject exactly the same addresses.
    #[test]
    fn dgram_encoder_matches_the_reference_encoding() {
        let addrs = [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:4860:4860::8888]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 8443),
            TargetAddr::Domain("a".repeat(255), 1),
        ];
        for a in &addrs {
            let got = encode_datagram_ref_with_limit(7, &a.as_ref(), b"payload", 4096).unwrap();
            // Reference: build the same body by hand from `header()`.
            let mut want = Vec::new();
            want.push(MQP_DGRAM_TYPE);
            want.extend_from_slice(&7u32.to_le_bytes());
            let h = a.as_ref().header().unwrap();
            h.encode(&mut want).unwrap();
            assert_eq!(h.len(), want.len() - DGRAM_PREFIX_LEN);
            want.extend_from_slice(b"payload");
            assert_eq!(&got[..], &want[..], "wire form changed for {a:?}");
        }
        // Rejections must match too: a scoped v6 address (scope_id != 0) is
        // refused by the header validation exactly as `encode` refuses it.
        let scoped = TargetAddrRef::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1,
            0,
            3, // scope_id
        )));
        assert!(scoped.header().is_err());
        assert!(scoped.encode(&mut Vec::new()).is_err());
        assert!(encode_datagram_ref_with_limit(0, &scoped, b"x", 4096).is_none());
    }

    /// The ACK's bound-address encoder must agree with the `Vec` form it
    /// replaces, for both address families.
    #[test]
    fn bnd_addr_into_matches_the_vec_encoder() {
        for a in [
            "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            "192.0.2.7:65535".parse().unwrap(),
            "[::]:0".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let mut v = Vec::new();
            encode_bnd_addr(a, &mut v);
            let mut buf = [0u8; MAX_BND_LEN];
            let n = encode_bnd_addr_into(a, &mut buf);
            assert_eq!(n, v.len(), "length mismatch for {a}");
            assert_eq!(&buf[..n], &v[..], "encoding mismatch for {a}");
        }
    }

    /// L1 version-skew pin: the dial ACK opens with a magic no legacy
    /// `0x00`-led app prefix can carry, so a peer that sends raw application
    /// bytes first (a pre-magic server) fails the ACK gate instead of having
    /// 8/20 B silently stripped with a clean FIN. A valid ACK still parses.
    #[tokio::test]
    async fn tcp_dial_ack_rejects_a_zero_led_app_prefix() {
        async fn ack_result_for(wire: Vec<u8>) -> bool {
            let (client, server) = endpoint_pair().await;
            let server_addr = server.local_addr().unwrap();
            let accept = tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                // Ping first: a locally-opened stream is invisible to the peer
                // until its first STREAM frame arrives, so `accept_bi` above
                // only fires after the client's write below.
                let mut ping = [0u8; 4];
                recv.read_exact(&mut ping).await.unwrap();
                send.write_all(&wire).await.unwrap();
                send.finish().ok();
                // Hold the connection open until the client confirms its read:
                // exiting here drops the endpoint, whose close can otherwise
                // overtake the queued ACK on loopback.
                let mut done = [0u8; 2];
                recv.read_exact(&mut done).await.unwrap();
            });
            let conn = client
                .connect(server_addr, "test.com")
                .unwrap()
                .await
                .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            // Production always writes the MQP target header before reading
            // the ACK; the ping here plays that role for the test stream.
            send.write_all(b"ping").await.unwrap();
            let result = read_mqp_ack(&mut recv).await;
            send.write_all(b"ok").await.unwrap();
            accept.await.unwrap();
            result.is_ok()
        }

        // Same-version writer and reader agree, both families.
        for bnd in [
            "192.0.2.7:1234".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        ] {
            let mut ack = [0u8; MAX_TCP_ACK_LEN];
            let n = encode_tcp_ack_into(bnd, &mut ack);
            assert!(
                ack_result_for(ack[..n].to_vec()).await,
                "valid ACK for {bnd} must be accepted"
            );
        }
        // Legacy-shaped app prefixes: the old 8 B (v4) and 20 B (v6) forms a
        // pre-magic peer's first bytes could take. Both must fail the gate —
        // accepting either would strip app bytes and finish clean.
        let mut legacy_v4 = vec![0x00u8, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
        assert!(
            !ack_result_for(legacy_v4.clone()).await,
            "leading-0x00 app bytes must not parse as ACK"
        );
        let mut legacy_v6 = vec![0x00u8, 0x04];
        legacy_v6.extend_from_slice(&[0u8; 16]);
        legacy_v6.extend_from_slice(&[0x01, 0xbb]);
        assert!(
            !ack_result_for(legacy_v6).await,
            "leading-0x00 v6 app bytes must not parse as ACK"
        );
        // Right magic, wrong status: a refused dial is still an error, never
        // an ACK.
        legacy_v4[0] = MQP_TCP_ACK_MAGIC[0];
        legacy_v4[1] = MQP_TCP_ACK_MAGIC[1];
        legacy_v4[2] = 0x01;
        assert!(
            !ack_result_for(legacy_v4).await,
            "non-zero ACK status must be rejected"
        );
    }

    /// The fixed-buffer header encoder must be byte-identical to the `Vec` one
    /// for every address form: the client writes the TCP-open header from a
    /// stack buffer on the hot path, so a divergence here would misparse every
    /// target.
    #[test]
    fn addr_header_into_matches_the_vec_encoder() {
        for a in [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 8443),
            TargetAddr::Domain("a".repeat(255), 65535),
        ] {
            let mut v = Vec::new();
            a.encode(&mut v).unwrap();
            let header = a.as_ref().header().unwrap();
            assert_eq!(header.len(), v.len(), "measured length for {a:?}");
            let mut buf = [0u8; AddrHeader::MAX_LEN];
            let n = header.encode_into(&mut buf);
            assert_eq!(n, v.len(), "encoded length for {a:?}");
            assert_eq!(&buf[..n], &v[..], "encoding mismatch for {a:?}");
        }
    }

    /// The pump's read path depends on this invariant: a `read_buf` into a full
    /// `BytesMut` would only ever read 64 B, so the reserve helper must always
    /// leave a whole chunk of headroom, including after a zero-copy split that
    /// hands the buffer's front to quinn.
    #[test]
    fn reserve_copy_chunk_always_leaves_a_full_chunk_of_room() {
        let mut buf = BytesMut::with_capacity(COPY_CHUNK);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);

        buf.extend_from_slice(&[0u8; COPY_CHUNK]);
        reserve_copy_chunk(&mut buf);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);

        // A zero-copy handover leaves the tail sharing the allocation; the
        // helper must still find (or make) a whole chunk of room.
        let taken = buf.split_to(buf.len()).freeze();
        assert_eq!(taken.len(), COPY_CHUNK);
        reserve_copy_chunk(&mut buf);
        assert!(buf.capacity() - buf.len() >= COPY_CHUNK);
        assert_eq!(buf.len(), 0);

        // And a small whole buffer must grow rather than settle for 64 B.
        let mut tiny = BytesMut::with_capacity(8);
        tiny.extend_from_slice(b"12345678");
        reserve_copy_chunk(&mut tiny);
        assert!(tiny.capacity() - tiny.len() >= COPY_CHUNK);
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
    #[test]
    fn dgram_ref_roundtrip() {
        let a = TargetAddr::Domain("example.com".into(), 443);
        let d = encode_datagram(9, &a, b"x").unwrap();
        let (s, aref, p) = decode_datagram_ref(&d).unwrap();
        assert_eq!(s, 9);
        assert_eq!(aref, TargetAddrRef::Domain("example.com", 443));
        assert_eq!(aref.into_owned(), a);
        assert_eq!(p, b"x");
    }
    #[test]
    fn global_ip_filter() {
        // NAT64 well-known prefix: the embedded IPv4 decides.
        assert!(!is_global_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("64:ff9b::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        // Deprecated IPv4-compatible form is validated via its embedded IPv4.
        assert!(!is_global_ip("::127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("::10.0.0.1".parse().unwrap()));
        assert!(is_global_ip("::8.8.8.8".parse().unwrap()));
        // IPv4-mapped unchanged.
        assert!(!is_global_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_global_ip("8.8.8.8".parse().unwrap()));
        // Newly covered documentation/benchmark prefixes.
        assert!(!is_global_ip("2001:2::1".parse().unwrap()));
        assert!(!is_global_ip("3fff::1".parse().unwrap()));
        // ORCHIDv1/v2 + AS112.
        assert!(!is_global_ip("2001:10::1".parse().unwrap()));
        assert!(!is_global_ip("2001:20::1".parse().unwrap()));
        assert!(!is_global_ip("192.175.48.1".parse().unwrap()));
        assert!(is_global_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn dns_key_is_injective() {
        let mut a = [0u8; DNS_KEY_BUF];
        let mut b = [0u8; DNS_KEY_BUF];
        let k1 = dns_key("example.com", 443, &mut a).unwrap();
        let k2 = dns_key("example.com", 80, &mut b).unwrap();
        assert_ne!(k1, k2);
        // A host containing the separator is still unambiguous: the split is
        // always at the last NUL, which the decimal port can never contain.
        let mut c = [0u8; DNS_KEY_BUF];
        let k3 = dns_key("a\0b", 1, &mut c).unwrap();
        assert_eq!(k3, "a\u{0}b\u{0}1");
        assert_eq!(dns_key("same", 1, &mut a).unwrap(), "same\u{0}1");
    }

    #[test]
    fn dns_shards_split_keys_and_preserve_total_caps() {
        assert_eq!(DNS_SHARDS, 16);
        assert_eq!(DNS_CACHE_MAX_SHARD * DNS_SHARDS, DNS_CACHE_MAX);
        assert_eq!(DNS_NEG_MAX_SHARD * DNS_SHARDS, DNS_NEG_MAX);
        // Deterministic: the same key always lands on the same shard, or
        // single-flight/warming would address a different lock than the lookup.
        let mut a = [0u8; DNS_KEY_BUF];
        let k = dns_key("example.com", 443, &mut a).unwrap().to_owned();
        assert_eq!(dns_shard(&k), dns_shard(&k));
        assert_eq!(dns_cache_for(&k) as *const _, dns_cache_for(&k) as *const _);
        // Spreading: distinct names must cover multiple shards, or the
        // sharding pays code without removing the single-lock contention.
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let h = format!("host{i}.example.com");
            let mut b = [0u8; DNS_KEY_BUF];
            let kk = dns_key(&h, 80, &mut b).unwrap().to_owned();
            seen.insert(dns_shard(&kk));
        }
        assert!(seen.len() > 1, "sharding must spread keys, got {seen:?}");
    }

    /// Live regression test for the quinn-proto datagram accounting.
    ///
    /// Saturation runs the send path that used to reach quinn's broken
    /// `datagrams.outgoing.payload_bytes` bookkeeping. With `try_send_datagram`
    /// a full buffer must surface as `Blocked` (the datagram is dropped) and
    /// must never panic; on quinn-proto 0.11.17 this test aborted the whole
    /// process with `datagrams.outgoing.payload_bytes desynchronized`. The
    /// underflow is fixed upstream, so the test now guards against a regression
    /// in that accounting.
    /// Loopback QUIC endpoint pair sharing the production transport config.
    /// Lives at module scope so both the send-buffer and fragmentation
    /// tests drive a real connection instead of a mock.
    async fn endpoint_pair() -> (quinn::Endpoint, quinn::Endpoint) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        scfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(scfg).unwrap();
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        server_cfg.transport_config(build_transport("bbr", 5));
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();

        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates({
                let mut r = rustls::RootCertStore::empty();
                r.add(cert.der().clone()).unwrap();
                r
            })
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(ccfg).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport("bbr", 5));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);
        (client, server)
    }

    #[tokio::test]
    async fn try_send_datagram_saturates_without_panicking() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        // The peer must complete the handshake; its datagram queue is never read,
        // which is what eventually fills our send buffer.
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();
        assert!(
            conn.max_datagram_size().unwrap() >= 1024,
            "loopback must allow ~1 KiB datagrams"
        );

        let payload: Bytes = Bytes::from(vec![0u8; 1024]);
        let mut sent = 0usize;
        let mut blocked = 0usize;
        // Far more than the 1 MiB send buffer can hold.
        for _ in 0..64 * 1024 {
            match try_send_datagram(&conn, payload.clone()) {
                DatagramSend::Sent => sent += 1,
                DatagramSend::Blocked => blocked += 1,
                other => panic!("unexpected datagram send result: {other:?}"),
            }
        }
        assert!(sent > 0, "at least some datagrams must be queued");
        assert!(
            blocked > 0,
            "the send buffer must saturate within 64k x 1 KiB sends"
        );
    }

    /// P1 residue pin: hammering the `Blocked` path (each hit polls
    /// `send_datagram_wait` once and drops the future) must leave the
    /// endpoint/connection fully usable. A leaked waiter would wedge the
    /// `datagrams_unblocked` notify queue and a leaked byte count would corrupt
    /// the send-buffer accounting, either of which shows up here as a wedged
    /// or unusable fresh connection on the same endpoint.
    #[tokio::test]
    async fn cancelled_datagram_waits_leave_no_residue() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let mut v = Vec::new();
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                v.push(incoming.accept().unwrap().await.unwrap());
            }
            v
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let payload: Bytes = Bytes::from(vec![0u8; 1024]);
        let mut blocked = 0usize;
        for _ in 0..16 * 1024 {
            match try_send_datagram(&conn, payload.clone()) {
                DatagramSend::Sent => {}
                DatagramSend::Blocked => blocked += 1,
                other => panic!("unexpected datagram send result: {other:?}"),
            }
        }
        assert!(
            blocked > 0,
            "must hit Blocked to exercise future cancellation"
        );
        assert!(conn.close_reason().is_none());
        assert!(conn.max_datagram_size().is_some());
        // Same endpoint, fresh connection: unaffected by the abandoned waiters.
        let conn2 = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _server_conns = accept.await.unwrap();
        let mut sent = 0usize;
        for _ in 0..16 {
            match try_send_datagram(&conn2, payload.clone()) {
                DatagramSend::Sent => sent += 1,
                DatagramSend::Blocked => break,
                other => panic!("fresh connection unexpected: {other:?}"),
            }
        }
        assert!(sent > 0, "fresh connection must still send");
    }

    #[tokio::test]
    async fn tcp_open_header_arrives_without_app_data() {
        let (client, server) = endpoint_pair().await;
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut recv = conn.accept_bi().await.unwrap().1;
            let mut hdr = [0u8; 7];
            recv.read_exact(&mut hdr).await.unwrap();
            TargetAddr::decode(&hdr).unwrap().0
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let target = TargetAddr::Ip("93.184.216.34:80".parse().unwrap());
        let mut hdr = Vec::new();
        target.encode(&mut hdr).unwrap();
        send.write_all(&hdr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .expect("open header must arrive even when the app never sends")
            .unwrap();
        assert_eq!(got, target);
    }

    #[test]
    fn alpn_override_parses_and_defaults() {
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(base).unwrap();
        assert_eq!(c.alpn_bytes(), b"h3");
        let c2: ClientConf = toml::from_str(&format!("{base}alpn = 'myquic2/2'\n")).unwrap();
        assert_eq!(c2.alpn_bytes(), MQP_ALPN);
        assert_eq!(normalize_alpn(Some("")), b"h3");
        assert_eq!(normalize_alpn(None), b"h3");
        assert_eq!(normalize_alpn(Some("h3")), b"h3");
    }

    /// A misspelled key must fail the parse instead of silently falling back.
    /// `auth_tokn` used to deserialize as an empty `auth_token` and disable
    /// client authentication with no diagnostic at all.
    #[test]
    fn unknown_config_keys_are_rejected() {
        let client = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let err = toml::from_str::<ClientConf>(&format!("{client}auth_tokn = 'secret'\n"))
            .expect_err("a typo must not silently disable auth");
        assert!(err.to_string().contains("auth_tokn"), "{err}");
        let ok: ClientConf = toml::from_str(&format!("{client}auth_token = 'secret'\n")).unwrap();
        assert_eq!(ok.auth_token, "secret");

        let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
        let err = toml::from_str::<ServerConf>(&format!("{server}allow_priv = true\n"))
            .expect_err("a typo must not silently flip the SSRF policy");
        assert!(err.to_string().contains("allow_priv"), "{err}");
    }

    /// The keepalive clamp bounds the derived detection window: idle is `3x`
    /// and the client watchdog `4x`, so the old 3600 clamp put silent-path
    /// detection hours out. A sane value must pass through untouched.
    #[test]
    fn keepalive_clamp_bounds_the_detection_window() {
        assert_eq!(clamp_keep_alive(3600), KEEP_ALIVE_MAX_SECS);
        assert_eq!(
            clamp_keep_alive(KEEP_ALIVE_MAX_SECS + 1),
            KEEP_ALIVE_MAX_SECS
        );
        assert_eq!(clamp_keep_alive(17), 17);
        assert_eq!(clamp_keep_alive(0), 1, "a zero keepalive cannot disable it");
        assert!(
            KEEP_ALIVE_MAX_SECS.saturating_mul(4) <= 1200,
            "the watchdog must stay inside 20 minutes"
        );
    }

    /// The admission bound multiplies this figure by the admitted connection
    /// count, so it has to track the configured windows rather than restate a
    /// constant: a deployment that raises the windows must see the per-connection
    /// ceiling rise with them.
    #[test]
    fn per_connection_memory_tracks_the_windows() {
        let d = per_connection_memory_bytes(&TransportTuning::default());
        // 4 MB receive + 2 MB send + 2 x 1 MB DATAGRAM buffers.
        assert_eq!(
            d,
            4 * 1024 * 1024 + 2 * 1024 * 1024 + 2 * DATAGRAM_BUFFER as u64
        );
        let wide = TransportTuning {
            receive_window: 16 * 1024 * 1024,
            send_window: 8 * 1024 * 1024,
            ..TransportTuning::default()
        };
        assert_eq!(per_connection_memory_bytes(&wide) - d, 18 * 1024 * 1024);
        // The per-stream window is bounded by the connection window and must not
        // be charged twice.
        let narrow_streams = TransportTuning {
            stream_receive_window: 1024 * 1024,
            ..TransportTuning::default()
        };
        assert_eq!(per_connection_memory_bytes(&narrow_streams), d);
        // A full house of the shipped defaults is the number the README's limits
        // table has to agree with.
        assert_eq!(
            d * 4096 / (1024 * 1024 * 1024),
            32,
            "4096 x 8 MB is the 32 GiB worst case documented for the default windows"
        );
    }

    #[test]
    fn tuning_defaults_are_low_latency() {
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(base).unwrap();
        let t = c.tuning();
        assert_eq!(t.stream_receive_window, 2 * 1024 * 1024);
        assert_eq!(t.receive_window, 4 * 1024 * 1024);
        assert_eq!(t.send_window, 2 * 1024 * 1024);
        assert_eq!(t.ack_threshold, 2);
        assert_eq!(t.max_ack_delay, Duration::from_millis(5));
        assert_eq!(t.initial_rtt, Duration::from_millis(DEFAULT_INITIAL_RTT_MS));
        assert_eq!(c.conn_count(), 4, "pool default is four connections");
        assert_eq!(DEFAULT_QUIC_CONNS, 4);
        let conf =
            |extra: &str| -> ClientConf { toml::from_str(&format!("{base}{extra}")).unwrap() };
        assert_eq!(
            conf("initial_rtt_ms = 140\n").tuning().initial_rtt,
            Duration::from_millis(140),
            "the documented 140 ms seed must reach the transport builder"
        );
        assert_eq!(
            conf("initial_rtt_ms = 0\n").tuning().initial_rtt,
            Duration::from_millis(INITIAL_RTT_MS_MIN),
            "a zero seed must clamp up, not zero the estimator"
        );
        assert_eq!(
            conf("initial_rtt_ms = 999_999\n").tuning().initial_rtt,
            Duration::from_millis(INITIAL_RTT_MS_MAX),
            "a typo must not postpone first-flight loss recovery absurdly"
        );
        assert_eq!(conf("quic_conns = 1\n").conn_count(), 1);
        assert_eq!(conf("quic_conns = 3\n").conn_count(), 3);
        assert_eq!(conf("quic_conns = 0\n").conn_count(), 1, "clamped up");
        assert_eq!(
            conf("quic_conns = 999\n").conn_count(),
            MAX_POOL_CONNS,
            "a config typo cannot spawn an unbounded dial loop"
        );
    }

    /// Window sizing invariant: the documented **opt-in** 300Mb/s configuration
    /// must actually produce flow-control windows that clear the BDP, or they —
    /// not BBR's congestion window — become the single-stream throughput ceiling.
    ///
    /// This is a config-path check rather than a live measurement on purpose:
    /// quinn exposes no window getters, and a loopback connection cannot detect
    /// the regression it guards against (with a 2MB window the cushion is still
    /// 1MB, worth ~40Gb/s at a ~0.2ms loopback RTT).
    ///
    /// **It used to assert only on the constants**, which `build_transport_tuned`
    /// never reads — it consumes `TransportTuning`, whose default is the 2/4/2
    /// low-latency preset. So the guard passed while proving nothing about any
    /// window that could reach the wire. It now drives `ClientConf::tuning()`
    /// with the exact values the sample configs document and checks both that
    /// they reproduce the constants and that they clear the BDP.
    #[test]
    fn tcp_windows_cover_the_300mb_s_bdp() {
        // Relations between constants are asserted at compile time, so a future
        // edit that re-tightens a window fails the build rather than only a WAN
        // measurement. Panic messages cannot be formatted in const context, so
        // each relation gets its own const block and the comments carry intent.
        //
        // `STREAM_RECEIVE_WINDOW` is the receiver-side advertisement, so it caps
        // a *download*; `SEND_WINDOW` caps the write side of an *upload*.
        const _: () = assert!(TARGET_LINK_RTT.as_millis() == 140);
        const _: () = assert!(TARGET_BDP_BYTES == 5_250_000);
        const _: () = assert!(STREAM_RECEIVE_WINDOW >= TARGET_BDP_BYTES);
        const _: () = assert!(SEND_WINDOW >= TARGET_BDP_BYTES);
        // The stream window is only useful if it still clears the BDP after the
        // cushion quinn withholds (`window / 8`) before announcing an update.
        const _: () = assert!(STREAM_RECEIVE_WINDOW - STREAM_RECEIVE_WINDOW / 8 > TARGET_BDP_BYTES);
        // The aggregate window must cover more than one stream's BDP, or a
        // single stream would exhaust the connection-level budget.
        const _: () = assert!(RECEIVE_WINDOW >= 2 * TARGET_BDP_BYTES);
        // Regression guards: these two are what capped single-stream at ~120Mb/s
        // (receive) and ~240Mb/s (send) at 140ms before the 2026-09 re-tuning.
        const _: () = assert!(STREAM_RECEIVE_WINDOW > 2 * 1024 * 1024);
        const _: () = assert!(SEND_WINDOW > 4 * 1024 * 1024);
        // Implied single-stream ceiling for the target RTT, in Mb/s.
        const _: () = assert!(STREAM_RECEIVE_WINDOW * 8 / 140 * 1000 / 1_000_000 >= 300);

        // ...and the same invariant through the only path that reaches quinn:
        // the config, as the sample configs document it on both sides.
        let base = "socks_listen = '[::]:1080'\nserver_addr = '127.0.0.1:8443'\n\
            server_name = 'test.com'\nserver_cert_file = 'x'\n";
        let c: ClientConf = toml::from_str(&format!(
            "{base}stream_receive_window_mb = 8\nreceive_window_mb = 16\n\
             send_window_mb = 8\nack_threshold = 8\nmax_ack_delay_ms = 10\n"
        ))
        .unwrap();
        let t = c.tuning();
        assert_eq!(
            t.stream_receive_window, STREAM_RECEIVE_WINDOW,
            "the documented 300Mb/s config must reproduce the stream window"
        );
        assert_eq!(t.receive_window, RECEIVE_WINDOW);
        assert_eq!(t.send_window, SEND_WINDOW);
        // The guarded invariant, on the values that actually go to
        // `build_transport_tuned`.
        assert!(
            t.stream_receive_window - t.stream_receive_window / 8 > TARGET_BDP_BYTES,
            "the advertised stream window must clear the BDP after quinn's cushion"
        );
        assert!(t.send_window >= TARGET_BDP_BYTES);
        assert!(t.receive_window >= 2 * TARGET_BDP_BYTES);
        // And the shipped default must stay the *low-latency* preset the README
        // and the sample configs document, not silently drift into the opt-in.
        let default_conf: ClientConf = toml::from_str(base).unwrap();
        let d = default_conf.tuning();
        assert_eq!(d.stream_receive_window, 2 * 1024 * 1024);
        assert_eq!(d.receive_window, 4 * 1024 * 1024);
        assert_eq!(d.send_window, 2 * 1024 * 1024);
    }
}
