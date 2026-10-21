//! Benchmark harness for the proxy hot paths. Not part of the shipped product:
//! it exists so the optimizations in this repository can be measured instead of
//! argued about.
//!
//! Modes:
//!   `echo <port>`                 UDP echo server (fast target for `udp`).
//!   `echomulti <base_port> <count>`
//!                                 UDP echo target on `count` consecutive
//!                                 loopback ports starting at `base_port`
//!                                 (127.0.0.1 only): one socket per port, every
//!                                 datagram echoed back to its source. This is
//!                                 the fan-out target for `udpfanout`.
//!   `techo <port>`                TCP echo server that returns the request
//!                                 verbatim, so a client can verify payload
//!                                 integrity byte-for-byte.
//!   `tcp <socks> <host:port> <n> [conc]`
//!                                 open N SOCKS5 CONNECTs, read one reply each.
//!   `server <port> <bytes> <count>`  TCP server that writes N chunks of
//!                                 `bytes` to every connection (fast target).
//!   `bulk <socks> <host:port> <mb> [conc]`
//!                                 download `mb` MiB through the proxy in
//!                                 parallel and report aggregate MB/s.
//!   `udp <socks> <host:port> <n> [batch]`
//!                                 send N datagrams over one UDP ASSOCIATE and
//!                                 wait for the same number of replies.
//!   `udpdomain <socks> <host:port> <n> [batch]`
//!                                 the same, but the request carries the target
//!                                 as a SOCKS5 *domain* (ATYP 0x03), so the
//!                                 proxy resolves per datagram instead of
//!                                 receiving an address. This is the only mode
//!                                 that exercises the DNS path on the relay.
//!   `udpmulti <socks> <host:port> <assocs> <n> [batch]`
//!                                 the same, but with `assocs` concurrent
//!                                 associations on `assocs` OS threads, each
//!                                 with its own relay socket. A single
//!                                 association runs on one core and cannot
//!                                 resolve lock/cache-line contention: every
//!                                 shared-state cost this repository has been
//!                                 removing only shows up once several
//!                                 associations run in parallel (see the
//!                                 hardening passes' "run-to-run noise" notes).
//!   `udpfanout <socks> <host:port> <flows> <n> [batch]`
//!                                 one UDP ASSOCIATE, `n` datagrams sent
//!                                 round-robin over `flows` consecutive
//!                                 destination ports (`host:(port+i)`), waiting
//!                                 for `n` replies. This is the mixed-destination
//!                                 shape behind TRAIN: `udp`/`udpmulti` hit one
//!                                 destination, so they never show the per-item
//!                                 flow/addressing cost, and `udpdomain` varies
//!                                 only the encoding. `host` may be an IPv4
//!                                 literal (ATYP 0x01) or a name (ATYP 0x03, the
//!                                 domain fan-out wire; the proxy resolves it,
//!                                 so use a name that resolves to the echo
//!                                 target). The payload is fixed at 60 B so
//!                                 frames stay on the v3/TRAIN path (payloads
//!                                 >512 B never batch); pair it with the
//!                                 `echomulti` target.
//!   `udpps <socks> <host:port> <secs> [payload]`
//!                                 N=1 soak: one UDP ASSOCIATE, one relay
//!                                 socket, fixed `payload`-byte payload
//!                                 (64-200 B, default 128) blasted for `secs`
//!                                 seconds (default 60). Reports
//!                                 sent_pps/recv_pps/loss%. This is the
//!                                 single-association ceiling the 100k pps N=1
//!                                 small-packet target is measured against.
//!
//!   `udppaced <socks> <host:port> <secs> [payload] [pps]`
//!                                 paced small-packet soak: the same socket
//!                                 shape as `udpps`, but the sender paces at
//!                                 exactly `pps` packets/s (default 20000) on
//!                                 an absolute timeline instead of blasting.
//!                                 `udpps` collapses both ends in buffers/BBR
//!                                 (loss 70%+, so per-frame savings are
//!                                 invisible) while `udp`/`udpmulti` use fixed
//!                                 1000 B payloads that never batch — a paced
//!                                 rate just under the collapse knee keeps
//!                                 every loss in the tunnel, which is what
//!                                 `loss%` then measures. Sweep `pps` across
//!                                 runs to find the knee (highest rate at ~0%
//!                                 loss); the N-pack staging exists to move
//!                                 exactly this ceiling.
//!
//!   `udpbidir <socks> <host:port> <secs> [payload] [pps]`
//!                                 full-duplex small-packet soak: one sender
//!                                 thread paces datagrams on an absolute timeline
//!                                 exactly like `udppaced`, while the reply drain
//!                                 runs concurrently for the whole send window.
//!                                 The `echo` target returns exactly one reply per
//!                                 datagram, so both directions carry the same
//!                                 offered rate and interference between them
//!                                 shows up as receive loss instead of a slower
//!                                 send. Reports sent/recv, loss%, send pps,
//!                                 recv pps and wall time (the D6 acceptance
//!                                 shape for the full-duplex work).
//!
//!   `udpmultipaced <socks> <host:port> <assocs> <secs> [payload] [pps]`
//!                                 `assocs` independent UDP ASSOCIATEs, each on
//!                                 its own thread with its own relay socket
//!                                 (the `udpmulti` shape), each paced at `pps`
//!                                 datagrams/s of `payload` bytes for `secs` on
//!                                 an absolute timeline and draining replies
//!                                 concurrently (the `udppaced` discipline).
//!                                 Reports assocs, payload, per-assoc and
//!                                 aggregate target pps, total sent/recv,
//!                                 send_errs, loss%, wall, aggregate sent/recv
//!                                 pps, and per-assoc min/max recv. With a
//!                                 payload <=512 B on a neutral port every
//!                                 association classifies as interactive, so
//!                                 they share the client's one interactive UDP
//!                                 connection — the shape a connection-level
//!                                 cross-session stager has to move.
//!
//!   `lat <socks> <host:port> <n> [payload]`
//!                                 serial UDP round trip: one UDP ASSOCIATE,
//!                                 then `n` request datagrams one at a time,
//!                                 each timed from send to the matching reply
//!                                 of the `echo` target. The request payload
//!                                 carries the iteration index and each reply
//!                                 is checked against it, so a late reply from
//!                                 a timed-out iteration is never booked as the
//!                                 current RTT. Reports samples/lost plus
//!                                 p50/p90/p99/p999/max/mean in µs.
//!                                 `<host:port>` must be an IPv4 literal (like
//!                                 `udp`); domain-encoded targets are covered by
//!                                 `udpdomain`.
//!
//!   `lattcp <socks> <host:port> <n> [bytes]`
//!                                 per-iteration stream setup plus first byte:
//!                                 one fresh SOCKS5 CONNECT per iteration,
//!                                 timed up to the success reply, then a
//!                                 `bytes`-byte payload written and echoed back
//!                                 by the `techo` target and timed as a second,
//!                                 independent round trip. Reports
//!                                 p50/p90/p99/p999/max/mean for CONNECT and for
//!                                 the first echo.
//!
//! The throughput/pps/loss modes cannot see transport latency at all: a
//! loopback path has ~0 RTT, so congestion control, buffers, ACK delay and the
//! initial-MTU choice move no number there. Shape the path before trusting a
//! `lat`/`lattcp` sample, e.g. on Linux:
//!   tc qdisc add dev lo root netem delay 70ms loss 0.5%
//!   cargo run --release --example hotpath_bench -- \
//!       lat 127.0.0.1:1080 127.0.0.1:9000 500
//!   cargo run --release --example hotpath_bench -- \
//!       lattcp 127.0.0.1:1080 127.0.0.1:9000 200
//!   tc qdisc del dev lo root
//!
//! Fan-out, full-duplex and multi-association runs use the `echomulti` target
//! (one echo port per destination flow; its first port also serves modes that
//! send everything to one destination) with the proxy in front of it:
//!   cargo run --release --example hotpath_bench -- echomulti 9000 8
//!   cargo run --release --example hotpath_bench -- \
//!       udpfanout 127.0.0.1:1080 127.0.0.1:9000 8 100000
//!   cargo run --release --example hotpath_bench -- \
//!       udpbidir 127.0.0.1:1080 127.0.0.1:9000 10 128 20000
//!   cargo run --release --example hotpath_bench -- \
//!       udpmultipaced 127.0.0.1:1080 127.0.0.1:9000 4 10 128 2000
//!
//!   `chan <n> [depth]`
//!                                 per-datagram cost of the client's inbound
//!                                 hand-off (`tokio::sync::mpsc` bounded
//!                                 `try_send` + `recv`) between the single
//!                                 DATAGRAM dispatcher task and the
//!                                 per-association reply task, measured in
//!                                 isolation. This is the hop a "dispatcher
//!                                 writes the socket directly" rewrite would
//!                                 delete; the number says whether that hop is
//!                                 worth deleting at all.
//!
//! Run with `--release`; the numbers are only comparable to each other.
//! End-to-end check bench (byte-for-byte peer verify + socket I/O, no DCE); std::hint::black_box/criterion N/A.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("echo") => echo(args[2].parse().unwrap()),
        Some("echomulti") => echomulti(args[2].parse().unwrap(), args[3].parse().unwrap()),
        Some("techo") => techo(args[2].parse().unwrap()),
        Some("utag") => utag(args[2].parse().unwrap(), args[3].as_bytes()[0]),
        Some("tcp") => tcp(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(16),
        ),
        Some("udp") => udp(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("udpdomain") => udpdomain(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("udpdomainswitch") => udpdomainswitch(
            &args[2],
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
        ),
        Some("udpdomainmulti") => udpdomainmulti(
            &args[2],
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args[6].parse().unwrap(),
        ),
        Some("udpmulti") => udpmulti(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("udpfanout") => udpfanout(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("udpraw") => udpraw(
            &args[2],
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("udpps") => udpps(
            &args[2],
            &args[3],
            args.get(4).and_then(|s| s.parse().ok()).unwrap_or(60),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(128),
        ),
        Some("udppaced") => udppaced(
            &args[2],
            &args[3],
            args.get(4).and_then(|s| s.parse().ok()).unwrap_or(10),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(128),
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(20_000),
        ),
        Some("udpbidir") => udpbidir(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(128),
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(20_000),
        ),
        Some("udpmultipaced") => udpmultipaced(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(128),
            args.get(7).and_then(|s| s.parse().ok()).unwrap_or(2000),
        ),
        Some("lat") => lat(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("lattcp") => lattcp(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(64),
        ),
        Some("chan") => chan(
            args[2].parse().unwrap(),
            args.get(3).and_then(|s| s.parse().ok()).unwrap_or(256),
        ),
        Some("udpsweep") => udpsweep(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            &args[5],
            args.get(6).and_then(|s| s.parse().ok()).unwrap_or(16),
        ),
        Some("tcpecho") => tcpecho(&args[2], &args[3], args[4].parse().unwrap()),
        Some("server") => server(
            args[2].parse().unwrap(),
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
        ),
        Some("reply") => reply_server(args[2].parse().unwrap()),
        Some("bulk") => bulk(
            &args[2],
            &args[3],
            args[4].parse().unwrap(),
            args.get(5).and_then(|s| s.parse().ok()).unwrap_or(4),
        ),
        _ => {
            eprintln!(
                "usage: hotpath_bench <echo|echomulti|techo|tcp|udp|udpmulti|udpfanout|udpraw|udpps|udppaced|udpbidir|udpmultipaced|lat|lattcp|udpsweep|tcpecho|chan|server|reply|bulk> ..."
            );
            std::process::exit(2);
        }
    }
}

/// UDP echo target.
///
/// One thread is not enough to be a useful target: a blocking `recv_from` costs
/// one kernel thread wake per datagram (~100 µs on macOS), which caps a
/// single-threaded echo at a few thousand packets per second and makes the
/// *target* — not the tunnel — the bottleneck of every UDP number measured
/// through it. The target therefore binds `ECHO_THREADS` sockets to the same
/// port with `SO_REUSEPORT`, and the kernel spreads datagrams across them by
/// 4-tuple hash, so the ceiling scales with the thread count.
fn echo(port: u16) {
    const ECHO_THREADS: usize = 8;
    let mut handles = Vec::with_capacity(ECHO_THREADS);
    for _ in 0..ECHO_THREADS {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        sock.set_reuse_port(true).unwrap();
        sock.bind(&socket2::SockAddr::from(
            format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
        let s: UdpSocket = sock.into();
        handles.push(std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, a)) = s.recv_from(&mut buf) {
                let _ = s.send_to(&buf[..n], a);
            }
        }));
    }
    println!("echo listening on 127.0.0.1:{port} ({ECHO_THREADS} reuseport threads)");
    for h in handles {
        let _ = h.join();
    }
}

/// Multi-port UDP echo target: `count` consecutive loopback ports starting at
/// `base_port`, one socket per port, every datagram echoed back to its source.
///
/// This is the target for `udpfanout`, which addresses `host:(port+i)` for
/// `i in 0..flows` and therefore needs one listener per destination flow. One
/// blocking `recv_from` loop per socket is enough here — unlike `echo`, which
/// needs `SO_REUSEPORT` threads because every association hammers the *same*
/// port: fan-out spreads across distinct sockets, so no single socket becomes
/// the target bottleneck.
fn echomulti(base_port: u16, count: u16) {
    if count == 0 {
        eprintln!("echomulti: count must be > 0");
        std::process::exit(2);
    }
    let Some(last_port) = base_port.checked_add(count - 1) else {
        eprintln!("echomulti: ports {base_port}..+{count} overflow u16");
        std::process::exit(2);
    };
    let mut handles = Vec::with_capacity(usize::from(count));
    for i in 0..count {
        // `i < count`, so `base_port + i <= last_port <= u16::MAX`.
        let port = base_port + i;
        let sock = UdpSocket::bind(("127.0.0.1", port))
            .unwrap_or_else(|e| panic!("echomulti: bind 127.0.0.1:{port}: {e}"));
        handles.push(std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, a)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], a);
            }
        }));
    }
    println!(
        "echomulti listening on 127.0.0.1:{base_port}..={last_port} ({count} ports, udp echo)"
    );
    for h in handles {
        let _ = h.join();
    }
}

/// SOCKS5 handshake helper: greeting + CONNECT, returns the socket positioned
/// right after the success reply.
fn socks_connect(socks: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let trace = std::env::var_os("BENCH_TRACE").is_some();
    macro_rules! t {
        ($($a:tt)*) => { if trace { eprintln!($($a)*); } };
    }
    t!("connecting {socks}");
    let mut s = TcpStream::connect(socks)?;
    t!("connected, sending greeting");
    s.set_nodelay(true)?;
    // Never let a broken flow wedge the whole benchmark.
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut g = [0u8; 2];
    match s.read_exact(&mut g) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    t!("greeting ok, sending request");
    let h = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, h.len() as u8];
    req.extend_from_slice(h);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    t!("reply ok rep={:02x?}", rep);
    if rep[1] != 0 {
        return Err(std::io::Error::other(format!("socks rep {:#x}", rep[1])));
    }
    Ok(s)
}

fn tcp(socks: &str, target: &str, n: usize, conc: usize) {
    let (host, port) = split_host(target);
    let done = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    // Flows that actually got a reply. The client answers SOCKS *optimistically*
    // (before the server-side dial result), so `done` alone counts a flow whose
    // target was unreachable and whose stream was reset — a proxy that is
    // completely broken still prints a high `flows/s`. `ok` is the number that
    // means what the metric claims, and an empty `ok` fails the run.
    let ok = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut workers = Vec::new();
    let per = n.div_ceil(conc);
    for _ in 0..conc {
        let socks = socks.to_string();
        let host = host.clone();
        let done = done.clone();
        let bytes = bytes.clone();
        let ok = ok.clone();
        workers.push(std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..per {
                if let Ok(mut s) = socks_connect(&socks, &host, port) {
                    let mut replied = false;
                    if s.write_all(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").is_ok()
                        && let Ok(k) = s.read(&mut buf)
                    {
                        bytes.fetch_add(k as u64, Ordering::Relaxed);
                        replied = k > 0;
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                    if replied {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let d = done.load(Ordering::Relaxed);
    let b = bytes.load(Ordering::Relaxed);
    let o = ok.load(Ordering::Relaxed);
    println!(
        "tcp flows={d} ok={o} conc={conc} wall={:.3}s flows/s={:.0} reply_bytes={b}{}",
        dt.as_secs_f64(),
        d as f64 / dt.as_secs_f64(),
        if d > 0 && o == 0 {
            "  FAIL: no flow got a reply (proxy down, target unreachable, or every dial refused)"
        } else {
            ""
        }
    );
    if d > 0 && o == 0 {
        std::process::exit(1);
    }
}

fn split_host(target: &str) -> (String, u16) {
    let (h, p) = target.rsplit_once(':').expect("host:port");
    (
        h.trim_start_matches('[').trim_end_matches(']').to_string(),
        p.parse().unwrap(),
    )
}

/// One SOCKS5 UDP ASSOCIATE. The returned `TcpStream` is the control
/// connection: the association lives exactly as long as it does, so the caller
/// owns it (dropping it mid-run tears the relay socket down).
fn socks_associate(socks: &str) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut s = TcpStream::connect(socks)?;
    s.set_nodelay(true)?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut g = [0u8; 2];
    s.read_exact(&mut g)?;
    // `0.0.0.0:0` asks the proxy for a relay endpoint on any interface.
    s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let mut rep = [0u8; 32];
    let k = s.read(&mut rep)?;
    if rep[1] != 0 {
        return Err(std::io::Error::other(format!(
            "associate refused rep={:#x}",
            rep[1]
        )));
    }
    // Reply lengths are 10 (v4) / 22 (v6); a short read would silently yield a
    // zero port, which would make the bench look like a total packet loss.
    let want = if rep[3] == 1 { 10 } else { 22 };
    if k < want {
        return Err(std::io::Error::other(format!(
            "short associate reply: {k} < {want}"
        )));
    }
    let relay = if rep[3] == 1 {
        let ip = std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
        let mut ip = std::net::IpAddr::V4(ip);
        // The proxy binds `[::]:0` and reports the unspecified address when the
        // control connection is loopback; dial it on loopback instead.
        if ip.is_unspecified() {
            ip = "127.0.0.1".parse().unwrap();
        }
        SocketAddr::new(ip, u16::from_be_bytes([rep[8], rep[9]]))
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&rep[4..20]);
        let ip = std::net::Ipv6Addr::from(o);
        let ip = if ip.is_unspecified() {
            std::net::Ipv6Addr::LOCALHOST
        } else {
            ip
        };
        SocketAddr::new(
            std::net::IpAddr::V6(ip),
            u16::from_be_bytes([rep[20], rep[21]]),
        )
    };
    Ok((s, relay))
}

/// Build the SOCKS5 UDP request prefix for `host:port` once; only the payload
/// varies per datagram, so the loop never re-encodes the header.
fn udp_request(host: &str, port: u16, payload: usize) -> Vec<u8> {
    let ip: std::net::Ipv4Addr = host.parse().unwrap();
    let mut pkt = vec![0, 0, 0, 0x01];
    pkt.extend_from_slice(&ip.octets());
    pkt.extend_from_slice(&port.to_be_bytes());
    let hdr = pkt.len();
    pkt.resize(hdr + payload, 0x5A);
    pkt
}

/// The same request prefix in SOCKS5 *domain* form (ATYP 0x03). The proxy's
/// per-datagram DNS path only runs for this encoding: with ATYP 0x01 the target
/// is already an address and no resolver is involved, so an IP-literal
/// benchmark cannot see that path at all.
fn udp_request_domain(host: &str, port: u16, payload: usize) -> Vec<u8> {
    let hb = host.as_bytes();
    let mut pkt = vec![0, 0, 0, 0x03, hb.len() as u8];
    pkt.extend_from_slice(hb);
    pkt.extend_from_slice(&port.to_be_bytes());
    let hdr = pkt.len();
    pkt.resize(hdr + payload, 0x5A);
    pkt
}

/// `udp` against a *domain* target, which is the case the server-side
/// destination memo exists for: every datagram of the association carries the
/// name, so the proxy must resolve (or reuse a resolution) per packet.
fn udpdomain(socks: &str, target: &str, n: usize, batch: usize) {
    let (host, port) = split_host(target);
    let (_control, relay) = socks_associate(socks).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request_domain(&host, port, 1000);
    let t0 = Instant::now();
    let (sent, recv) = udp_pump(&u, &pkt, relay, n, batch);
    let dt = t0.elapsed();
    println!(
        "udpdomain sent={sent} recv={recv} batch={batch} wall={:.3}s recv_pps={:.0}",
        dt.as_secs_f64(),
        recv as f64 / dt.as_secs_f64()
    );
}

/// Send `n` datagrams and wait for `n` replies on one association.
/// Returns `(sent, recv)`.
fn udp_pump(
    u: &UdpSocket,
    pkt: &[u8],
    relay: SocketAddr,
    n: usize,
    batch: usize,
) -> (usize, usize) {
    let mut sent = 0usize;
    let mut recv = 0usize;
    let mut stalled = 0usize;
    let mut buf = vec![0u8; 2048];
    while recv < n {
        while sent < n && sent - recv < batch {
            if u.send_to(pkt, relay).is_err() {
                break;
            }
            sent += 1;
        }
        match u.recv_from(&mut buf) {
            Ok(_) => {
                recv += 1;
                stalled = 0;
            }
            Err(_) => {
                // UDP may genuinely lose packets: stop after a few consecutive
                // silent windows rather than hanging on a fixed target count.
                stalled += 1;
                if stalled >= 10 {
                    break;
                }
            }
        }
    }
    (sent, recv)
}

/// Per-datagram cost of the client's inbound hand-off, with no network in the
/// path: the dispatcher's `try_send` into a per-association bounded
/// `tokio::sync::mpsc`, and the reply task's `recv`.
///
/// This is the hop a "dispatcher writes the relay socket directly" rewrite
/// would delete. Measuring it in isolation is the only way to judge that
/// rewrite, because the same rewrite also *serializes* every inbound datagram
/// onto the one dispatcher task — a cost the hop itself does not have. Two
/// controls are printed alongside: an empty loop of the same length (the
/// harness floor) and the same-rate `send_to` cost measured by `udpraw`.
fn chan(n: usize, depth: usize) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_time()
        .build()
        .unwrap();

    // Control: the same loop with no queue at all.
    let sink = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    {
        let sink = sink.clone();
        rt.block_on(async move {
            for _ in 0..n {
                sink.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    let loop_dt = t0.elapsed();

    let (dt, sent, full, got) = rt.block_on(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<usize>(depth);
        let consumer = tokio::spawn(async move {
            let mut got = 0usize;
            while rx.recv().await.is_some() {
                got += 1;
            }
            got
        });
        // Let the consumer park so the producer exercises the wake path rather
        // than finding an already-running receiver.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t0 = Instant::now();
        let mut sent = 0usize;
        let mut full = 0usize;
        while sent < n {
            match tx.try_send(1000usize) {
                Ok(()) => sent += 1,
                Err(_) => {
                    full += 1;
                    tokio::task::yield_now().await;
                }
            }
        }
        drop(tx);
        let got = consumer.await.unwrap();
        (t0.elapsed(), sent, full, got)
    });

    let per = dt.as_secs_f64() / (sent.max(1) as f64) * 1e9;
    let loop_per = loop_dt.as_secs_f64() / (n.max(1) as f64) * 1e9;
    println!(
        "chan n={n} depth={depth} sent={sent} recv={got} full_retries={full} \
         wall={:.3}s per_msg={per:.0}ns loop_only={loop_per:.0}ns \
         queue_cost={:.0}ns",
        dt.as_secs_f64(),
        (per - loop_per).max(0.0)
    );
}

/// Payload-integrity sweep. For each size, relay `n` datagrams of exactly that
/// payload size through a fresh association and verify the echoed payload byte
/// for byte.
///
/// This is the correctness counterpart to `udpmulti`: it pins that the relay
/// carries *what was sent* at each size, including sizes above the path's
/// single-frame budget (which take the MQP-2 fragmentation + reassembly path)
/// and sizes around the common 1420/1430 B MTU boundary. A payload mismatch is
/// reported separately from a lost datagram, because the two have completely
/// different causes.
fn udpsweep(socks: &str, target: &str, n: usize, sizes: &str, batch: usize) {
    let (host, port) = split_host(target);
    let mut all_ok = true;
    for size in sizes.split(',').map(|s| s.trim().parse::<usize>().unwrap()) {
        let Ok((_control, relay)) = socks_associate(socks) else {
            println!("udpsweep size={size} FAILED: associate refused");
            all_ok = false;
            continue;
        };
        let Ok(u) = UdpSocket::bind("127.0.0.1:0") else {
            continue;
        };
        u.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        // Header-only build, then append the payload so the two are never
        // accidentally mixed by a resize.
        let prefix = udp_request(&host, port, 0);
        let mut pkt = prefix.clone();
        pkt.resize(prefix.len() + size, 0);
        for (i, b) in pkt[prefix.len()..].iter_mut().enumerate() {
            // Position-dependent, so a shifted or truncated reply cannot match.
            *b = (i % 251) as u8;
        }
        let want = &pkt[prefix.len()..];

        let mut sent = 0usize;
        let mut ok = 0usize;
        let mut bad = 0usize;
        let mut lost = 0usize;
        let mut stale = 0usize;
        let mut buf = vec![0u8; 65535];
        while ok + bad + lost < n {
            while sent < n && sent - (ok + bad + lost) < batch {
                if u.send_to(&pkt, relay).is_err() {
                    break;
                }
                sent += 1;
            }
            match u.recv_from(&mut buf) {
                Ok((k, _)) => {
                    // Reply framing: 3 reserved bytes, ATYP, address, port,
                    // then the payload the target echoed.
                    let hlen = match buf.get(3) {
                        Some(1) => 10,
                        Some(4) => 22,
                        _ => {
                            bad += 1;
                            continue;
                        }
                    };
                    if k < hlen || &buf[hlen..k] != want {
                        bad += 1;
                    } else {
                        ok += 1;
                    }
                }
                Err(_) => {
                    stale += 1;
                    if stale >= 10 {
                        lost += n - ok - bad - lost;
                        break;
                    }
                }
            }
        }
        let good = bad == 0 && ok == n;
        all_ok &= good;
        println!(
            "udpsweep size={size} sent={sent} verified={ok} mismatched={bad} lost={lost} {}",
            if good { "OK" } else { "FAIL" }
        );
    }
    println!("udpsweep {}", if all_ok { "ALL OK" } else { "FAILURES" });
    if !all_ok {
        std::process::exit(1);
    }
}

/// Push `bytes` of a position-dependent pattern through one SOCKS5 CONNECT to
/// the TCP echo target and verify the echo byte for byte.
///
/// A writer thread is required, not a courtesy: echoing `bytes` while the same
/// thread is still writing deadlocks once the two socket buffers fill (the
/// target stops reading because it is blocked writing to us, and we stop
/// writing because our send buffer is full).
fn tcpecho(socks: &str, target: &str, bytes: usize) {
    let (host, port) = split_host(target);
    let mut s = match socks_connect(socks, &host, port) {
        Ok(s) => s,
        Err(e) => {
            println!("tcpecho FAILED: connect {e}");
            std::process::exit(1);
        }
    };
    let payload: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let mut w = s.try_clone().unwrap();
    let out = payload.clone();
    let writer = std::thread::spawn(move || {
        let r = w.write_all(&out);
        let _ = w.shutdown(std::net::Shutdown::Write);
        r.is_ok()
    });

    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0usize;
    let mut mismatch = 0usize;
    let t0 = Instant::now();
    while got < bytes {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                // A pump that *duplicates* data makes a single read return more
                // than the stream was asked for, which is exactly the case this
                // check exists to report — indexing `payload[got + j]` would
                // panic on it instead (and exit 101 before any size/mode runs).
                // Compare what was expected and count the excess as mismatches.
                let expected = (bytes - got).min(k);
                for (j, b) in buf[..expected].iter().enumerate() {
                    if *b != payload[got + j] {
                        mismatch += 1;
                    }
                }
                if k > expected {
                    mismatch += k - expected;
                }
                got += k;
            }
        }
    }
    let dt = t0.elapsed();
    let wrote = writer.join().unwrap_or(false);
    let good = mismatch == 0 && got == bytes && wrote;
    println!(
        "tcpecho bytes={bytes} echoed={got} mismatched={mismatch} wall={:.3}s {:.1} MB/s {}",
        dt.as_secs_f64(),
        got as f64 / dt.as_secs_f64() / 1e6,
        if good { "OK" } else { "FAIL" }
    );
    if !good {
        std::process::exit(1);
    }
}

/// Raw loopback UDP echo through the *same* pump loop and the same target the
/// tunnel benchmarks use, with no proxy in the path.
///
/// This is the control for [`udpmulti`]: it bounds how much of a measured rate
/// belongs to the harness and the kernel's loopback path rather than the
/// tunnel. A tunnel number above this one is impossible, and a tunnel number
/// far below it is the tunnel's own cost — not the benchmark's.
fn udpraw(target: &str, assocs: usize, n: usize, batch: usize) {
    let (host, port) = split_host(target);
    let echo: SocketAddr = format!("{host}:{port}").parse().unwrap();
    let sent = Arc::new(AtomicU64::new(0));
    let recv = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut ws = Vec::with_capacity(assocs);
    for _ in 0..assocs {
        let sent = sent.clone();
        let recv = recv.clone();
        ws.push(std::thread::spawn(move || {
            let Ok(u) = UdpSocket::bind("127.0.0.1:0") else {
                return;
            };
            u.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let pkt = vec![0x5Au8; 1000];
            let (s, r) = udp_pump(&u, &pkt, echo, n, batch);
            sent.fetch_add(s as u64, Ordering::Relaxed);
            recv.fetch_add(r as u64, Ordering::Relaxed);
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let s = sent.load(Ordering::Relaxed);
    let r = recv.load(Ordering::Relaxed);
    println!(
        "udpraw assocs={assocs} sent={s} recv={r} batch={batch} wall={:.3}s recv_pps={:.0} \
         loss={:.3}%",
        dt.as_secs_f64(),
        r as f64 / dt.as_secs_f64(),
        if s == 0 {
            0.0
        } else {
            100.0 * (s - r) as f64 / s as f64
        }
    );
}

/// One UDP ASSOCIATE, then `n` datagrams to the target, waiting for `n` replies.
fn udp(socks: &str, target: &str, n: usize, batch: usize) {
    let (host, port) = split_host(target);
    let (_control, relay) = socks_associate(socks).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request(&host, port, 1000);
    let t0 = Instant::now();
    let (sent, recv) = udp_pump(&u, &pkt, relay, n, batch);
    let dt = t0.elapsed();
    println!(
        "udp sent={sent} recv={recv} batch={batch} wall={:.3}s recv_pps={:.0}",
        dt.as_secs_f64(),
        recv as f64 / dt.as_secs_f64()
    );
}

/// Nearest-rank percentile of an ascending-sorted sample set, shared by both
/// latency modes so a percentile means the same thing on both lines.
///
/// Nearest rank, not interpolation: the question a latency benchmark answers is
/// "how bad was the worst 1 request in 100", and that is an *observed* request.
/// An interpolated value between two samples would smooth over exactly the tail
/// the benchmark exists to expose (netem loss + retransmission spikes).
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (sorted.len() as f64 * p).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// One latency distribution as a `p50=...`-style fragment in µs.
///
/// Sorts `samples` in place once and then indexes it through [`percentile`], so
/// both latency modes pay one sort per distribution and print the same set of
/// statistics. An empty set is reported explicitly instead of as zeros: an
/// all-lost run must not look like a fast one.
fn latency_summary(samples: &mut [f64]) -> String {
    if samples.is_empty() {
        return "no samples".to_string();
    }
    samples.sort_unstable_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    format!(
        "p50={:.0} p90={:.0} p99={:.0} p999={:.0} max={:.0} mean={:.0} µs",
        percentile(samples, 0.50),
        percentile(samples, 0.90),
        percentile(samples, 0.99),
        percentile(samples, 0.999),
        percentile(samples, 1.00),
        mean
    )
}

/// Serial UDP request/response latency: one SOCKS5 UDP ASSOCIATE, then `n`
/// request datagrams to the `echo` target one at a time, each timed from
/// `send_to` to the matching reply. This is the shape transport tuning shows up
/// in — the throughput modes (`udp`, `udpps`) cannot see it, and loopback has
/// ~0 RTT, so run it on a netem-shaped path (see the module docs).
///
/// One outstanding datagram is not the same as in-order replies: a datagram
/// whose wait timed out may still be retransmitted on the QUIC path and land
/// during a later iteration, so the payload carries the iteration index and a
/// reply is only accepted when it matches. Otherwise a late reply would be
/// booked as the *current* RTT and the whole distribution would drift low.
/// A full-payload compare additionally rejects corruption, counted separately
/// because a mismatch and a loss have completely different causes.
fn lat(socks: &str, target: &str, n: usize, payload: usize) {
    /// Iteration marker at the front of the payload, big-endian u64.
    const MARKER: usize = 8;
    /// A request lost on the QUIC path still has a retransmission to lose before
    /// it is a loss; this bounds how long the harness waits for that. It only
    /// costs wall time on a genuinely lost sample.
    const TIMEOUT: Duration = Duration::from_secs(2);
    let (host, port) = split_host(target);
    // The marker is the minimum payload that can carry the iteration index.
    let payload = payload.max(MARKER);
    let (_control, relay) = socks_associate(socks).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut pkt = udp_request(&host, port, payload);
    // Payload starts here; the header is constant, so later iterations rewrite
    // only the marker and the loop measures the tunnel, not header encoding.
    let data = pkt.len() - payload;
    let mut buf = vec![0u8; 65535];
    let mut samples = Vec::with_capacity(n);
    let (mut lost, mut stale, mut bad) = (0usize, 0usize, 0usize);
    let t0 = Instant::now();
    for i in 0..n {
        pkt[data..data + MARKER].copy_from_slice(&(i as u64).to_be_bytes());
        let started = Instant::now();
        if u.send_to(&pkt, relay).is_err() {
            lost += 1;
            continue;
        }
        loop {
            let (k, _) = match u.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => {
                    // No reply inside the window: count it lost and move on. A
                    // late answer is rejected by the marker check below rather
                    // than being attributed to a later iteration.
                    lost += 1;
                    break;
                }
            };
            // Reply framing: 3 reserved bytes, ATYP, address, port, payload.
            let hlen = match buf.get(3) {
                Some(1) => 10,
                Some(4) => 22,
                _ => {
                    bad += 1;
                    continue;
                }
            };
            if k < hlen || k - hlen != payload {
                bad += 1;
                continue;
            }
            if buf[hlen..hlen + MARKER] != pkt[data..data + MARKER] {
                // A reply from an earlier timed-out iteration: not this RTT.
                stale += 1;
                continue;
            }
            if buf[hlen..k] != pkt[data..] {
                // Right marker, wrong bytes: corruption, not latency.
                bad += 1;
                continue;
            }
            samples.push(started.elapsed().as_secs_f64() * 1e6);
            break;
        }
    }
    let wall = t0.elapsed();
    println!(
        "lat n={n} payload={payload} samples={} lost={lost} stale={stale} bad={bad} \
         wall={:.3}s {}",
        samples.len(),
        wall.as_secs_f64(),
        latency_summary(&mut samples)
    );
    if samples.is_empty() {
        eprintln!(
            "lat FAIL: no reply verified (proxy down, or the target is not the `echo` server)"
        );
        std::process::exit(1);
    }
}

/// Per-iteration SOCKS5 CONNECT plus first-byte latency, one fresh stream per
/// iteration. The CONNECT sample is dial + SOCKS handshake up to the success
/// reply; the echo sample is a small payload written and echoed back by the
/// `techo` target, timed separately. The two measure different paths: stream
/// setup is dominated by the client's optimistic CONNECT answer and the proxy
/// dial, while the first echo carries the server-side dial result plus the first
/// QUIC stream round trip.
///
/// A fresh connection per iteration is deliberate. Reusing one stream would
/// only measure the tunnel's per-datagram cost and hide every per-flow setup
/// change (pool hit rate, handshake cost, stream open), which is the half of the
/// latency budget CONNECT is here to report.
fn lattcp(socks: &str, target: &str, n: usize, bytes: usize) {
    let (host, port) = split_host(target);
    let bytes = bytes.max(1);
    // Position-dependent payload: a shifted, truncated or duplicated echo cannot
    // match, so a wrong reply is reported instead of silently timing it.
    let payload: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let mut connect = Vec::with_capacity(n);
    let mut echo = Vec::with_capacity(n);
    let (mut connect_lost, mut echo_lost, mut bad) = (0usize, 0usize, 0usize);
    let mut buf = vec![0u8; 64 * 1024];
    let t0 = Instant::now();
    for _ in 0..n {
        let started = Instant::now();
        let Ok(mut s) = socks_connect(socks, &host, port) else {
            connect_lost += 1;
            continue;
        };
        connect.push(started.elapsed().as_secs_f64() * 1e6);
        // Time from the first byte written to the last byte echoed: the round
        // trip the tunnel adds to a stream that is already open.
        let started = Instant::now();
        let mut got = 0usize;
        let mut corrupt = false;
        if s.write_all(&payload).is_ok() {
            while got < payload.len() {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => {
                        if k > payload.len() - got || buf[..k] != payload[got..got + k] {
                            corrupt = true;
                            break;
                        }
                        got += k;
                    }
                }
            }
        }
        drop(s);
        if got == payload.len() {
            echo.push(started.elapsed().as_secs_f64() * 1e6);
        } else {
            echo_lost += 1;
            if corrupt {
                bad += 1;
            }
        }
    }
    let wall = t0.elapsed();
    println!(
        "lattcp n={n} bytes={bytes} connect_ok={} connect_lost={connect_lost} \
         echo_ok={} echo_lost={echo_lost} bad={bad} wall={:.3}s | connect {} | echo {}",
        connect.len(),
        echo.len(),
        wall.as_secs_f64(),
        latency_summary(&mut connect),
        latency_summary(&mut echo)
    );
    if connect.is_empty() {
        eprintln!("lattcp FAIL: no SOCKS5 CONNECT completed (proxy down or target unreachable)");
        std::process::exit(1);
    }
}

/// One UDP ASSOCIATE whose datagrams alternate between two *different* domain
/// targets that resolve to two different addresses, each running a server that
/// stamps its own response. Every reply is checked against the server that owns
/// the address the datagram was addressed to.
///
/// This is the correctness question a per-session destination pin raises: if a
/// session's remembered address were used for a datagram naming a different
/// name, replies would arrive from — and be sent to — the wrong target.
fn udpdomainswitch(socks: &str, port_a: u16, port_b: u16, n: usize) {
    let (a_host, a_port) = ("alpha.localhost", port_a);
    let (b_host, b_port) = ("beta.localhost", port_b);
    let (_control, relay) = socks_associate(socks).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(2000)))
        .unwrap();
    // The payload carries the intended target's initial, and each echo server
    // replies with its own initial, so a mis-route is visible in the payload.
    let pkt_a = udp_request_domain(a_host, a_port, 0);
    let pkt_b = udp_request_domain(b_host, b_port, 0);
    let mut buf = vec![0u8; 2048];
    let (mut ok_a, mut ok_b, mut bad) = (0usize, 0usize, 0usize);
    for i in 0..n {
        let (pkt, want) = if i % 2 == 0 {
            (&pkt_a, b'A')
        } else {
            (&pkt_b, b'B')
        };
        if u.send_to(pkt, relay).is_err() {
            break;
        }
        match u.recv_from(&mut buf) {
            Ok((len, _)) => {
                // SOCKS5 UDP reply header: 2 rsv + 1 frag + atyp + addr + port.
                let hdr = match buf.get(3) {
                    Some(0x01) => 4 + 4 + 2,
                    Some(0x04) => 4 + 16 + 2,
                    _ => {
                        bad += 1;
                        continue;
                    }
                };
                if len < hdr {
                    bad += 1;
                    continue;
                }
                let body = &buf[hdr..len];
                if body.first() == Some(&want) {
                    if want == b'A' {
                        ok_a += 1;
                    } else {
                        ok_b += 1;
                    }
                } else {
                    bad += 1;
                }
            }
            Err(_) => break,
        }
    }
    println!("udpdomainswitch n={n} ok_alpha={ok_a} ok_beta={ok_b} misrouted={bad}");

    // The same check across encodings: alternate a *domain* target with an
    // *IP* target in one session. The IP target memoizes an empty host, so a
    // memo that matched on the session alone would answer the domain's
    // datagrams with the IP target's address (or vice versa).
    let ip_pkt = udp_request("127.0.0.1", port_b, 0);
    let (mut ok_ip, mut ok_dom, mut bad2) = (0usize, 0usize, 0usize);
    let mut buf = vec![0u8; 2048];
    for i in 0..n {
        let (pkt, want) = if i % 2 == 0 {
            (&ip_pkt, b'B')
        } else {
            (&pkt_a, b'A')
        };
        if u.send_to(pkt, relay).is_err() {
            break;
        }
        match u.recv_from(&mut buf) {
            Ok((len, _)) => {
                let hdr = match buf.get(3) {
                    Some(0x01) => 4 + 4 + 2,
                    Some(0x04) => 4 + 16 + 2,
                    _ => {
                        bad2 += 1;
                        continue;
                    }
                };
                if len < hdr {
                    bad2 += 1;
                    continue;
                }
                match (buf[hdr], want) {
                    (b'B', b'B') => ok_ip += 1,
                    (b'A', b'A') => ok_dom += 1,
                    _ => bad2 += 1,
                }
            }
            Err(_) => break,
        }
    }
    println!("udpipswitch n={n} ok_ip_target={ok_ip} ok_domain_target={ok_dom} misrouted={bad2}");
}

/// `assocs` concurrent associations, each cycling through a pool of `domains`
/// distinct *domain* targets, so the per-datagram DNS work is on the hot path
/// and the thread-local memo is under pressure from more names than it can
/// hold at once.
///
/// This is the shape the DNS memo's associativity exists for: one name per
/// association is absorbed by a single memo slot, but N names per worker thread
/// is what turns a memo hit into a shared-cache lookup.
fn udpdomainmulti(socks: &str, port: u16, domains: usize, assocs: usize, n: usize) {
    // Distinct names, all resolving to loopback through a wildcard resolver: to
    // the memo and the DNS cache `sub0.localhost` and `sub1.localhost` are
    // different names even though they land on the same address, which is what
    // puts the memo under pressure without needing /etc/hosts entries.
    let recv = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut ws = Vec::with_capacity(assocs);
    for _a in 0..assocs {
        let socks = socks.to_string();
        let recv = recv.clone();
        let sent = sent.clone();
        let pkts: Vec<Vec<u8>> = (0..domains)
            .map(|i| udp_request_domain(&format!("sub{i}.localhost"), port, 1000))
            .collect();
        ws.push(std::thread::spawn(move || {
            let Ok((_control, relay)) = socks_associate(&socks) else {
                return;
            };
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            u.set_read_timeout(Some(Duration::from_millis(2000)))
                .unwrap();
            let mut buf = vec![0u8; 2048];
            let mut got = 0usize;
            let mut snt = 0usize;
            for i in 0..n {
                let pkt = &pkts[i % pkts.len()];
                if u.send_to(pkt, relay).is_err() {
                    break;
                }
                snt += 1;
                if u.recv_from(&mut buf).is_ok() {
                    got += 1;
                }
            }
            recv.fetch_add(got as u64, Ordering::Relaxed);
            sent.fetch_add(snt as u64, Ordering::Relaxed);
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let r = recv.load(Ordering::Relaxed);
    println!(
        "udpdomainmulti sent={} recv={r} domains={domains} assocs={assocs} wall={:.3}s recv_pps={:.0}",
        sent.load(Ordering::Relaxed),
        dt.as_secs_f64(),
        r as f64 / dt.as_secs_f64()
    );
}

/// `assocs` concurrent associations, each on its own OS thread and relay
/// socket, all hammering the same target.
///
/// This is the configuration in which per-packet *shared* state actually
/// contends — quinn's per-connection state mutex, the client's shared egress
/// cache, the UDP hub's subscription table, the dispatcher's inbound path. A
/// single association runs on one core and never touches any of them from two
/// threads at once, which is why the hardening passes' single-flow loopback
/// numbers could not resolve those changes ("all inside run-to-run noise").
fn udpmulti(socks: &str, target: &str, assocs: usize, n: usize, batch: usize) {
    let (host, port) = split_host(target);
    let sent = Arc::new(AtomicU64::new(0));
    let recv = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let complete = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut ws = Vec::with_capacity(assocs);
    for _ in 0..assocs {
        let socks = socks.to_string();
        let host = host.clone();
        let sent = sent.clone();
        let recv = recv.clone();
        let failed = failed.clone();
        let complete = complete.clone();
        ws.push(std::thread::spawn(move || {
            // `_control` must outlive the pump: it *is* the association.
            let Ok((_control, relay)) = socks_associate(&socks) else {
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let Ok(u) = UdpSocket::bind("127.0.0.1:0") else {
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            };
            u.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let pkt = udp_request(&host, port, 1000);
            let (s, r) = udp_pump(&u, &pkt, relay, n, batch);
            sent.fetch_add(s as u64, Ordering::Relaxed);
            recv.fetch_add(r as u64, Ordering::Relaxed);
            if r >= n {
                complete.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let s = sent.load(Ordering::Relaxed);
    let r = recv.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);
    let c = complete.load(Ordering::Relaxed);
    println!(
        "udpmulti assocs={assocs} complete={c} failed_assocs={f} sent={s} recv={r} \
         batch={batch} wall={:.3}s recv_pps={:.0} loss={:.3}%",
        dt.as_secs_f64(),
        r as f64 / dt.as_secs_f64(),
        if s == 0 {
            0.0
        } else {
            100.0 * (s - r) as f64 / s as f64
        }
    );
}

/// One UDP ASSOCIATE, `n` datagrams sent round-robin over `flows` consecutive
/// destination ports of one host, waiting for `n` replies.
///
/// This is the mixed-destination shape behind TRAIN: `udp` and `udpmulti` hit a
/// single destination, so every frame can reuse one flow and the benchmark never
/// sees per-item flow/addressing cost, while `udpdomain` varies the encoding but
/// not the destination. Here each datagram names a different port (therefore a
/// different flow), so a TRAIN that packs several datagrams cannot assume one
/// destination. `host` may be an IPv4 literal (ATYP 0x01) or a name (ATYP 0x03,
/// the domain fan-out wire; the proxy resolves it server-side, so use a name
/// that resolves to the echo target). Pair with the `echomulti` target, which
/// listens on exactly these consecutive ports.
///
/// The payload is deliberately small (60 B): MQP-3's v3/TRAIN path only carries
/// payloads up to 512 B, and the 1000 B payload the other UDP modes use never
/// batches, so the shape this mode exists to measure would not be on the wire at
/// all at that size.
fn udpfanout(socks: &str, target: &str, flows: u16, n: usize, batch: usize) {
    /// Small enough to stay in the v3 batching range (1-512 B).
    const PAYLOAD: usize = 60;
    if flows == 0 {
        eprintln!("udpfanout: flows must be > 0");
        std::process::exit(2);
    }
    let (host, port) = split_host(target);
    let Some(last_port) = port.checked_add(flows - 1) else {
        eprintln!("udpfanout: destination ports {port}..+{flows} overflow u16");
        std::process::exit(2);
    };
    let domain = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        false
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        eprintln!("udpfanout: IPv6 target {host} is not supported (IPv4 literal or a name)");
        std::process::exit(2);
    } else {
        true
    };
    let (_control, relay) = socks_associate(socks).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    // One complete request per destination, encoded up front: only the
    // destination varies per datagram, so the send loop never re-encodes.
    let pkts: Vec<Vec<u8>> = (0..flows)
        .map(|i| {
            let p = port + i;
            if domain {
                udp_request_domain(&host, p, PAYLOAD)
            } else {
                udp_request(&host, p, PAYLOAD)
            }
        })
        .collect();
    let t0 = Instant::now();
    // The `udp_pump` window/pump shape, with destination `sent % flows` rotating
    // on every send so a burst is a mixed-destination run, not a single flow.
    let mut sent = 0usize;
    let mut recv = 0usize;
    let mut stalled = 0usize;
    let mut buf = vec![0u8; 2048];
    while recv < n {
        while sent < n && sent - recv < batch {
            if u.send_to(&pkts[sent % pkts.len()], relay).is_err() {
                break;
            }
            sent += 1;
        }
        match u.recv_from(&mut buf) {
            Ok(_) => {
                recv += 1;
                stalled = 0;
            }
            Err(_) => {
                // Same reasoning as `udp_pump`: a silent window on a UDP path is
                // a real loss, not a reason to hang waiting for a fixed target.
                stalled += 1;
                if stalled >= 10 {
                    break;
                }
            }
        }
    }
    let dt = t0.elapsed();
    println!(
        "udpfanout socks={socks} target={target} atyp={} flows={flows} \
         ports={port}..={last_port} payload={PAYLOAD} sent={sent} recv={recv} \
         batch={batch} wall={:.3}s recv_pps={:.0} loss={:.3}%",
        if domain { "domain" } else { "ip" },
        dt.as_secs_f64(),
        recv as f64 / dt.as_secs_f64(),
        if sent == 0 {
            0.0
        } else {
            100.0 * (sent - recv) as f64 / sent as f64
        }
    );
}

/// N=1 soak: one UDP ASSOCIATE, one relay socket, fixed small payload blasted
/// for `secs` wall seconds. Sender and receiver run on two threads sharing the
/// one socket (cloned fd) so the send rate is not gated by the reply RTT; both
/// sides count through the same AtomicU64 style as `udp`/`udpmulti`.
/// Baseline 2026-09-30, macOS loopback, release, 4TCP+2UDP, 8-thread echo:
///   udpraw control (no proxy, 1000 B): 20000/20000 in 0.273s = 73129 pps, 0% loss
///   udp windowed via proxy (batch=64): 20000/20000 in 0.745s = 26847 pps, 0% loss
///   udpps 5s/128 B via proxy:  offered 96485 pps, goodput 2586 pps, loss 96.9%
///   udpps 60s/128 B via proxy: offered 105350 pps, goodput 370 pps, loss 99.6%
/// Reading: the sender sustains >100k pps offered, the paced single-assoc
/// ceiling is ~27k pps, and unthrottled blast collapses (buffers/BBR give up
/// long before 100k). The N=1 100k target needs paced send + deeper
/// buffers/windows, not a faster blast.
fn udpps(socks: &str, target: &str, secs: u64, payload: usize) {
    if secs == 0 {
        eprintln!("udpps: secs must be > 0");
        std::process::exit(2);
    }
    if !(64..=200).contains(&payload) {
        eprintln!("udpps: payload must be 64-200 (got {payload})");
        std::process::exit(2);
    }
    let (host, port) = split_host(target);
    let (_control, relay) = match socks_associate(socks) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("udpps: associate {e}");
            std::process::exit(1);
        }
    };
    let u = match UdpSocket::bind("127.0.0.1:0") {
        Ok(u) => u,
        Err(e) => {
            eprintln!("udpps: bind {e}");
            std::process::exit(1);
        }
    };
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request(&host, port, payload);
    let secs_d = Duration::from_secs(secs);
    let deadline = Instant::now() + secs_d;
    let sent = Arc::new(AtomicU64::new(0));
    let send_errs = Arc::new(AtomicU64::new(0));
    let sender = {
        let tx = u.try_clone().expect("udpps: clone relay socket");
        let sent = sent.clone();
        let send_errs = send_errs.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            let mut e = 0u64;
            while Instant::now() < deadline {
                match tx.send_to(&pkt, relay) {
                    Ok(_) => n += 1,
                    Err(_) => e += 1,
                }
            }
            sent.fetch_add(n, Ordering::Relaxed);
            send_errs.fetch_add(e, Ordering::Relaxed);
        })
    };
    // Receiver runs here until the send deadline plus a drain grace so
    // in-flight replies are counted rather than truncated by the stop time.
    let t0 = Instant::now();
    let mut recv = 0u64;
    let mut buf = vec![0u8; 2048];
    let drain_end = deadline + Duration::from_secs(2);
    while Instant::now() < drain_end {
        match u.recv_from(&mut buf) {
            Ok(_) => recv += 1,
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        if Instant::now() >= drain_end {
            break;
        }
    }
    let _ = sender.join();
    // Final short drain on the now-idle socket: the sender is done, so any
    // datagram still in the kernel queue belongs to this run.
    u.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while u.recv_from(&mut buf).is_ok() {
        recv += 1;
    }
    let dt = t0.elapsed();
    let s = sent.load(Ordering::Relaxed);
    let se = send_errs.load(Ordering::Relaxed);
    let wall = dt.as_secs_f64();
    // `sent` was produced during exactly the `secs` send window (the sender
    // stops at the deadline while the wall also covers the drain grace), so
    // sent_pps is over `secs` and recv_pps over the wall that carried replies.
    let sent_pps = s as f64 / secs as f64;
    let recv_pps = recv as f64 / wall;
    let loss = if s == 0 {
        0.0
    } else {
        100.0 * s.saturating_sub(recv) as f64 / s as f64
    };
    println!(
        "udpps socks={socks} target={target} payload={payload} secs={secs} \
         sent={s} recv={recv} send_errs={se} wall={wall:.3}s \
         sent_pps={sent_pps:.0} recv_pps={recv_pps:.0} loss={loss:.3}%"
    );
    if s == 0 {
        eprintln!("udpps FAIL: nothing sent (associate down or send path broken)");
        std::process::exit(1);
    }
    if recv > s {
        eprintln!("udpps FAIL: accounting mismatch recv={recv} > sent={s}");
        std::process::exit(1);
    }
}

/// Paced small-packet soak: one UDP ASSOCIATE, one relay socket, fixed small
/// `payload`-byte payload (1-512 B, the batchable range) sent at exactly
/// `pps` packets/s for `secs` wall seconds. Sender and receiver run on two
/// threads sharing the one socket (cloned fd), as in `udpps`.
///
/// Pacing runs on an absolute timeline (`start + k * interval`): a stall
/// sends catch-up packets only within a 1 s lag window, past it the schedule
/// re-syncs instead of emitting a burst that would measure the burst
/// collapse rather than the paced ceiling. `sent_pps` must read back at
/// `target_pps` — if it does not, the sender (or the loopback path itself)
/// is the bottleneck, not the tunnel.
fn udppaced(socks: &str, target: &str, secs: u64, payload: usize, pps: u64) {
    if secs == 0 {
        eprintln!("udppaced: secs must be > 0");
        std::process::exit(2);
    }
    if !(1..=512).contains(&payload) {
        eprintln!("udppaced: payload must be 1-512 (batchable range), got {payload}");
        std::process::exit(2);
    }
    if pps == 0 {
        eprintln!("udppaced: pps must be > 0");
        std::process::exit(2);
    }
    let (host, port) = split_host(target);
    let (_control, relay) = match socks_associate(socks) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("udppaced: associate {e}");
            std::process::exit(1);
        }
    };
    let u = match UdpSocket::bind("127.0.0.1:0") {
        Ok(u) => u,
        Err(e) => {
            eprintln!("udppaced: bind {e}");
            std::process::exit(1);
        }
    };
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request(&host, port, payload);
    let secs_d = Duration::from_secs(secs);
    let deadline = Instant::now() + secs_d;
    let interval = Duration::from_nanos(1_000_000_000 / pps);
    let sent = Arc::new(AtomicU64::new(0));
    let send_errs = Arc::new(AtomicU64::new(0));
    let sender = {
        let tx = u.try_clone().expect("udppaced: clone relay socket");
        let sent = sent.clone();
        let send_errs = send_errs.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut next = start;
            let mut n = 0u64;
            let mut e = 0u64;
            // Past this lag the schedule re-syncs: emitting the backlog as
            // one burst would collapse buffers and measure that collapse.
            let max_lag = Duration::from_secs(1);
            while Instant::now() < deadline {
                let now = Instant::now();
                if next > now {
                    let left = next - now;
                    if left > Duration::from_micros(50) {
                        std::thread::sleep(left - Duration::from_micros(20));
                    } else {
                        std::hint::spin_loop();
                    }
                    continue;
                }
                if now.duration_since(next) > max_lag {
                    next = now;
                }
                match tx.send_to(&pkt, relay) {
                    Ok(_) => n += 1,
                    Err(_) => e += 1,
                }
                next += interval;
            }
            sent.fetch_add(n, Ordering::Relaxed);
            send_errs.fetch_add(e, Ordering::Relaxed);
        })
    };
    // Receiver runs here until the send deadline plus a drain grace so
    // in-flight replies are counted rather than truncated by the stop time.
    let t0 = Instant::now();
    let mut recv = 0u64;
    let mut buf = vec![0u8; 2048];
    let drain_end = deadline + Duration::from_secs(2);
    while Instant::now() < drain_end {
        match u.recv_from(&mut buf) {
            Ok(_) => recv += 1,
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        if Instant::now() >= drain_end {
            break;
        }
    }
    let _ = sender.join();
    // Final short drain on the now-idle socket: the sender is done, so any
    // datagram still in the kernel queue belongs to this run.
    u.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while u.recv_from(&mut buf).is_ok() {
        recv += 1;
    }
    let dt = t0.elapsed();
    let s = sent.load(Ordering::Relaxed);
    let se = send_errs.load(Ordering::Relaxed);
    let wall = dt.as_secs_f64();
    // `sent` was produced during exactly the `secs` send window (the sender
    // stops at the deadline while the wall also covers the drain grace), so
    // sent_pps is over `secs` and recv_pps over the wall that carried replies.
    let sent_pps = s as f64 / secs as f64;
    let recv_pps = recv as f64 / wall;
    let loss = if s == 0 {
        0.0
    } else {
        100.0 * s.saturating_sub(recv) as f64 / s as f64
    };
    println!(
        "udppaced socks={socks} target={target} payload={payload} secs={secs} \
         target_pps={pps} sent={s} recv={recv} send_errs={se} wall={wall:.3}s \
         sent_pps={sent_pps:.0} recv_pps={recv_pps:.0} loss={loss:.3}%"
    );
    if s == 0 {
        eprintln!("udppaced FAIL: nothing sent (associate down or send path broken)");
        std::process::exit(1);
    }
    if (sent_pps - pps as f64).abs() > 0.05 * pps as f64 {
        eprintln!(
            "udppaced WARN: sender did not hold the pace (sent_pps={sent_pps:.0} vs target {pps}); \
             the bottleneck is the harness, not the tunnel"
        );
    }
    if recv > s {
        eprintln!("udppaced FAIL: accounting mismatch recv={recv} > sent={s}");
        std::process::exit(1);
    }
}

/// Full-duplex paced small-packet soak: one UDP ASSOCIATE, one relay socket, a
/// sender thread pacing `payload`-byte datagrams on an absolute timeline (the
/// exact `udppaced` schedule) and a reply drain running concurrently for the
/// whole send window.
///
/// The `echo` target returns exactly one reply per datagram, so both directions
/// carry the same offered rate and the receive loss/pps is a measurement of
/// whether the tunnel sustains both directions at once — the D6 acceptance shape
/// for the full-duplex work. Send and receive rates are reported separately and
/// never summed: a run that loses half the replies must not look like equal slow
/// progress in both directions. As in `udppaced`, the send pps is over the paced
/// window and the receive pps over the wall that actually carried replies.
fn udpbidir(socks: &str, target: &str, secs: u64, payload: usize, pps: u64) {
    if secs == 0 {
        eprintln!("udpbidir: secs must be > 0");
        std::process::exit(2);
    }
    if !(1..=512).contains(&payload) {
        eprintln!("udpbidir: payload must be 1-512 (batchable range), got {payload}");
        std::process::exit(2);
    }
    if pps == 0 {
        eprintln!("udpbidir: pps must be > 0");
        std::process::exit(2);
    }
    let (host, port) = split_host(target);
    let (_control, relay) = match socks_associate(socks) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("udpbidir: associate {e}");
            std::process::exit(1);
        }
    };
    let u = match UdpSocket::bind("127.0.0.1:0") {
        Ok(u) => u,
        Err(e) => {
            eprintln!("udpbidir: bind {e}");
            std::process::exit(1);
        }
    };
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request(&host, port, payload);
    let secs_d = Duration::from_secs(secs);
    let deadline = Instant::now() + secs_d;
    let interval = Duration::from_nanos(1_000_000_000 / pps);
    let sent = Arc::new(AtomicU64::new(0));
    let send_errs = Arc::new(AtomicU64::new(0));
    // Uplink half of the full duplex: the `udppaced` absolute-timeline sender on
    // its own thread, so pacing is never delayed by reply processing.
    let sender = {
        let tx = u.try_clone().expect("udpbidir: clone relay socket");
        let sent = sent.clone();
        let send_errs = send_errs.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut next = start;
            let mut n = 0u64;
            let mut e = 0u64;
            // Past this lag the schedule re-syncs: emitting the backlog as one
            // burst would collapse buffers and measure that collapse.
            let max_lag = Duration::from_secs(1);
            while Instant::now() < deadline {
                let now = Instant::now();
                if next > now {
                    let left = next - now;
                    if left > Duration::from_micros(50) {
                        std::thread::sleep(left - Duration::from_micros(20));
                    } else {
                        std::hint::spin_loop();
                    }
                    continue;
                }
                if now.duration_since(next) > max_lag {
                    next = now;
                }
                match tx.send_to(&pkt, relay) {
                    Ok(_) => n += 1,
                    Err(_) => e += 1,
                }
                next += interval;
            }
            sent.fetch_add(n, Ordering::Relaxed);
            send_errs.fetch_add(e, Ordering::Relaxed);
        })
    };
    // Downlink half: runs concurrently on the calling thread, draining replies
    // for the whole send window rather than only after the sender has finished.
    let t0 = Instant::now();
    let mut recv = 0u64;
    let mut buf = vec![0u8; 2048];
    let drain_end = deadline + Duration::from_secs(2);
    while Instant::now() < drain_end {
        match u.recv_from(&mut buf) {
            Ok(_) => recv += 1,
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        if Instant::now() >= drain_end {
            break;
        }
    }
    let _ = sender.join();
    // Final short drain on the now-idle socket: the sender is done, so anything
    // still in the kernel queue belongs to this run.
    u.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while u.recv_from(&mut buf).is_ok() {
        recv += 1;
    }
    let dt = t0.elapsed();
    let s = sent.load(Ordering::Relaxed);
    let se = send_errs.load(Ordering::Relaxed);
    let wall = dt.as_secs_f64();
    let sent_pps = s as f64 / secs as f64;
    let recv_pps = recv as f64 / wall;
    let loss = if s == 0 {
        0.0
    } else {
        100.0 * s.saturating_sub(recv) as f64 / s as f64
    };
    println!(
        "udpbidir socks={socks} target={target} payload={payload} secs={secs} \
         target_pps={pps} sent={s} recv={recv} send_errs={se} wall={wall:.3}s \
         sent_pps={sent_pps:.0} recv_pps={recv_pps:.0} loss={loss:.3}%"
    );
    if s == 0 {
        eprintln!("udpbidir FAIL: nothing sent (associate down or send path broken)");
        std::process::exit(1);
    }
    if (sent_pps - pps as f64).abs() > 0.05 * pps as f64 {
        eprintln!(
            "udpbidir WARN: sender did not hold the pace (sent_pps={sent_pps:.0} vs target {pps}); \
             the bottleneck is the harness, not the tunnel"
        );
    }
    if recv > s {
        eprintln!("udpbidir FAIL: accounting mismatch recv={recv} > sent={s}");
        std::process::exit(1);
    }
}

/// One association of [`udpmultipaced`]: handshake, bind its own relay socket,
/// run a paced sender on a second thread, and drain replies concurrently on this
/// thread for the whole shared `deadline`. Returns `(sent, recv, send_errs)`, or
/// `None` when the association itself could not be set up — the caller counts
/// that as a failed association instead of aborting the whole run.
fn udpmultipaced_assoc(
    socks: &str,
    host: &str,
    port: u16,
    payload: usize,
    pps: u64,
    deadline: Instant,
) -> Option<(u64, u64, u64)> {
    // `_control` must outlive the pump: it *is* the association.
    let Ok((_control, relay)) = socks_associate(socks) else {
        return None;
    };
    let u = UdpSocket::bind("127.0.0.1:0").ok()?;
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let pkt = udp_request(host, port, payload);
    let interval = Duration::from_nanos(1_000_000_000 / pps);
    let sent = Arc::new(AtomicU64::new(0));
    let send_errs = Arc::new(AtomicU64::new(0));
    // Same absolute-timeline sender as `udppaced`/`udpbidir`: a stall sends
    // catch-up packets only inside the 1 s lag window, past it re-syncs.
    let sender = {
        let tx = u.try_clone().expect("udpmultipaced: clone relay socket");
        let sent = sent.clone();
        let send_errs = send_errs.clone();
        std::thread::spawn(move || {
            let mut next = Instant::now();
            let mut n = 0u64;
            let mut e = 0u64;
            let max_lag = Duration::from_secs(1);
            while Instant::now() < deadline {
                let now = Instant::now();
                if next > now {
                    let left = next - now;
                    if left > Duration::from_micros(50) {
                        std::thread::sleep(left - Duration::from_micros(20));
                    } else {
                        std::hint::spin_loop();
                    }
                    continue;
                }
                if now.duration_since(next) > max_lag {
                    next = now;
                }
                match tx.send_to(&pkt, relay) {
                    Ok(_) => n += 1,
                    Err(_) => e += 1,
                }
                next += interval;
            }
            sent.fetch_add(n, Ordering::Relaxed);
            send_errs.fetch_add(e, Ordering::Relaxed);
        })
    };
    // Reply drain runs concurrently with the sender, exactly as in `udpbidir`;
    // `drain_end` bounds the post-deadline wait for in-flight replies.
    let mut recv = 0u64;
    let mut buf = vec![0u8; 2048];
    let drain_end = deadline + Duration::from_secs(2);
    while Instant::now() < drain_end {
        match u.recv_from(&mut buf) {
            Ok(_) => recv += 1,
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        if Instant::now() >= drain_end {
            break;
        }
    }
    let _ = sender.join();
    // Final short drain on the now-idle socket: the sender is done, so anything
    // still in the kernel queue belongs to this association's run.
    u.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while u.recv_from(&mut buf).is_ok() {
        recv += 1;
    }
    Some((
        sent.load(Ordering::Relaxed),
        recv,
        send_errs.load(Ordering::Relaxed),
    ))
}

/// `assocs` concurrent associations, one OS thread and one relay socket each
/// (the `udpmulti` shape), each paced at `pps` datagrams/s of `payload` bytes
/// for `secs` on an absolute timeline and draining its replies concurrently
/// (the `udppaced`/`udpbidir` discipline).
///
/// This is the many-associations-on-one-connection shape the Phase-2
/// connection-level cross-session stager is measured against. With a payload
/// <=512 B and a target port outside `interactive_ports`/`udp_bulk_ports`, the
/// client classifies every association as interactive, so they all share its
/// single interactive UDP connection and the run puts several sessions' TRAIN
/// stagers on that one connection at once. The harness cannot observe which
/// egress class the client actually picks; use a neutral destination port (e.g.
/// 9000) and keep `payload` <=512 B to stay on this path.
///
/// Aggregate send pps is over `secs` (every association shares one deadline, so
/// the aggregate is the sum of the per-association paces; association setup is
/// not part of the paced window) and aggregate receive pps is over `wall` (which
/// includes the drain grace). Per-association receive counts are reported as
/// min/max so one starved association cannot hide behind a healthy aggregate.
fn udpmultipaced(socks: &str, target: &str, assocs: usize, secs: u64, payload: usize, pps: u64) {
    if assocs == 0 {
        eprintln!("udpmultipaced: assocs must be > 0");
        std::process::exit(2);
    }
    if secs == 0 {
        eprintln!("udpmultipaced: secs must be > 0");
        std::process::exit(2);
    }
    if !(1..=512).contains(&payload) {
        eprintln!("udpmultipaced: payload must be 1-512 (batchable range), got {payload}");
        std::process::exit(2);
    }
    if pps == 0 {
        eprintln!("udpmultipaced: pps must be > 0");
        std::process::exit(2);
    }
    let (host, port) = split_host(target);
    // One deadline shared by all associations: they pace over the same `secs`
    // window, so the aggregate pps is not skewed by staggered starts.
    let deadline = Instant::now() + Duration::from_secs(secs);
    let t0 = Instant::now();
    let mut workers = Vec::with_capacity(assocs);
    for _ in 0..assocs {
        let socks = socks.to_string();
        let host = host.clone();
        workers.push(std::thread::spawn(move || {
            udpmultipaced_assoc(&socks, &host, port, payload, pps, deadline)
        }));
    }
    let (mut total_sent, mut total_recv, mut total_errs, mut failed) = (0u64, 0u64, 0u64, 0usize);
    let mut per_assoc_recv = Vec::with_capacity(assocs);
    for w in workers {
        match w.join() {
            Ok(Some((s, r, e))) => {
                total_sent += s;
                total_recv += r;
                total_errs += e;
                per_assoc_recv.push(r);
            }
            // A failed setup and a panicked worker both mean this association
            // contributed nothing; count it rather than losing the whole run.
            _ => failed += 1,
        }
    }
    let wall = t0.elapsed();
    let wall_s = wall.as_secs_f64();
    let target_agg = pps.saturating_mul(assocs as u64);
    let sent_pps = total_sent as f64 / secs as f64;
    let recv_pps = total_recv as f64 / wall_s;
    let loss = if total_sent == 0 {
        0.0
    } else {
        100.0 * total_sent.saturating_sub(total_recv) as f64 / total_sent as f64
    };
    let (recv_min, recv_max) = match (per_assoc_recv.iter().min(), per_assoc_recv.iter().max()) {
        (Some(lo), Some(hi)) => (*lo, *hi),
        _ => (0, 0),
    };
    println!(
        "udpmultipaced socks={socks} target={target} assocs={assocs} failed_assocs={failed} \
         payload={payload} secs={secs} target_pps_per_assoc={pps} target_pps_agg={target_agg} \
         sent={total_sent} recv={total_recv} send_errs={total_errs} wall={wall_s:.3}s \
         sent_pps={sent_pps:.0} recv_pps={recv_pps:.0} loss={loss:.3}% \
         per_assoc_recv_min={recv_min} per_assoc_recv_max={recv_max}"
    );
    if total_sent == 0 {
        eprintln!(
            "udpmultipaced FAIL: nothing sent (all associations failed or the send path is broken)"
        );
        std::process::exit(1);
    }
    if (sent_pps - target_agg as f64).abs() > 0.05 * target_agg as f64 {
        eprintln!(
            "udpmultipaced WARN: aggregate sender did not hold the pace (sent_pps={sent_pps:.0} \
             vs target {target_agg}); the bottleneck is the harness (threads/pacing), not the tunnel"
        );
    }
    if total_recv > total_sent {
        eprintln!("udpmultipaced FAIL: accounting mismatch recv={total_recv} > sent={total_sent}");
        std::process::exit(1);
    }
}

/// TCP echo target: echoes every byte it reads back verbatim. Unlike the reply
/// server it never closes on its own, so a client can keep one connection open
/// across several exchanges and verify each payload exactly.
/// UDP echo that replies with `tag` followed by the request, so a client can
/// tell *which* target answered — the check `udpdomainswitch` needs to prove a
/// multi-target session is not served by the wrong address.
fn utag(port: u16, tag: u8) {
    let s = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    println!("tagged udp echo on 127.0.0.1:{port} tag={}", tag as char);
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = s.recv_from(&mut buf) else {
            continue;
        };
        let mut out = Vec::with_capacity(n + 1);
        out.push(tag);
        out.extend_from_slice(&buf[..n]);
        let _ = s.send_to(&out, from);
    }
}

fn techo(port: u16) {
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    println!("tcp echo on 127.0.0.1:{port}");
    for c in l.incoming() {
        let Ok(mut s) = c else { continue };
        let _ = s.set_nodelay(true);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match std::io::Read::read(&mut s, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// Tiny HTTP-ish target: reads a request line and replies with a fixed body.
/// Used by the `tcp` flow benchmark so a flow is request/response, not a bare
/// read (which legitimately blocks until the peer sends something).
fn reply_server(port: u16) {
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    println!("reply server on 127.0.0.1:{port}");
    for c in l.incoming() {
        let Ok(mut s) = c else { continue };
        let _ = s.set_nodelay(true);
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let _ = std::io::Read::read(&mut s, &mut buf);
            let body = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = s.write_all(body);
            let _ = s.shutdown(std::net::Shutdown::Both);
        });
    }
}

/// Fast bulk-download target: writes `bytes` of payload per connection, `count`
/// times over, so the proxy's QUIC->TCP direction is the only bottleneck.
fn server(port: u16, bytes: usize, count: usize) {
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    println!("bulk server on 127.0.0.1:{port} ({bytes} B x {count})");
    let chunk = vec![0x41u8; bytes];
    for c in l.incoming() {
        let Ok(mut s) = c else { continue };
        let _ = s.set_nodelay(true);
        let chunk = chunk.clone();
        std::thread::spawn(move || {
            // Push immediately and ignore the request: the server never reads,
            // so the client must not be expected to send anything first.
            for _ in 0..count {
                if s.write_all(&chunk).is_err() {
                    break;
                }
            }
            let _ = s.shutdown(std::net::Shutdown::Both);
        });
    }
}

/// Download `mb` MiB per connection through the proxy and report aggregate
/// throughput: this exercises the stream copy path (buffers, stream writes)
/// rather than the per-flow setup costs.
fn bulk(socks: &str, target: &str, mb: usize, conc: usize) {
    let (host, port) = split_host(target);
    let want = mb * 1024 * 1024;
    let total = Arc::new(AtomicU64::new(0));
    // Threads that read their whole `want`. Without this the mode happily
    // reports a throughput for a *truncated* transfer (a reset flow, a target
    // that stopped early), so the number cannot be compared across revisions.
    let complete = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut ws = Vec::new();
    for _ in 0..conc {
        let socks = socks.to_string();
        let host = host.clone();
        let total = total.clone();
        let complete = complete.clone();
        ws.push(std::thread::spawn(move || {
            let mut s = match socks_connect(&socks, &host, port) {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = s.write_all(b"GET /bulk\r\n");
            let mut buf = vec![0u8; 256 * 1024];
            let mut got = 0usize;
            while got < want {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        total.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }
            // `got >= want`, not `==`: the loop stops after the read that
            // crosses `want`, so a healthy transfer overshoots by up to one
            // read's worth of already-buffered bytes.
            if got >= want {
                complete.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let b = total.load(Ordering::Relaxed);
    let c = complete.load(Ordering::Relaxed);
    let want_total = want as u64 * conc as u64;
    println!(
        "bulk conc={conc} bytes={b}/{want_total} complete={c}/{conc} wall={:.3}s throughput={:.0} MB/s{}",
        dt.as_secs_f64(),
        b as f64 / dt.as_secs_f64() / 1e6,
        if b < want_total {
            "  SHORT: the transfer was truncated, so this throughput is not comparable"
        } else {
            ""
        }
    );
    if b == 0 {
        // Nothing was carried at all: the path is broken, not slow.
        std::process::exit(1);
    }
}
