//! Benchmark harness for the proxy hot paths. Not part of the shipped product:
//! it exists so the optimizations in this repository can be measured instead of
//! argued about.
//!
//! Modes:
//!   `echo <port>`                 UDP echo server (fast target for `udp`).
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
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("echo") => echo(args[2].parse().unwrap()),
        Some("techo") => techo(args[2].parse().unwrap()),
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
        Some("udpmulti") => udpmulti(
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
                "usage: hotpath_bench <echo|techo|tcp|udp|udpmulti|udpraw|udpsweep|tcpecho|chan|server|reply|bulk> ..."
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
    let t0 = Instant::now();
    let mut workers = Vec::new();
    let per = n.div_ceil(conc);
    for _ in 0..conc {
        let socks = socks.to_string();
        let host = host.clone();
        let done = done.clone();
        let bytes = bytes.clone();
        workers.push(std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..per {
                if let Ok(mut s) = socks_connect(&socks, &host, port) {
                    if s.write_all(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").is_ok() {
                        if let Ok(k) = s.read(&mut buf) {
                            bytes.fetch_add(k as u64, Ordering::Relaxed);
                        }
                    }
                    done.fetch_add(1, Ordering::Relaxed);
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
    println!(
        "tcp flows={d} conc={conc} wall={:.3}s flows/s={:.0} reply_bytes={b}",
        dt.as_secs_f64(),
        d as f64 / dt.as_secs_f64()
    );
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
                for (j, b) in buf[..k].iter().enumerate() {
                    if *b != payload[got + j] {
                        mismatch += 1;
                    }
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

/// TCP echo target: echoes every byte it reads back verbatim. Unlike the reply
/// server it never closes on its own, so a client can keep one connection open
/// across several exchanges and verify each payload exactly.
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
    let t0 = Instant::now();
    let mut ws = Vec::new();
    for _ in 0..conc {
        let socks = socks.to_string();
        let host = host.clone();
        let total = total.clone();
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
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    let dt = t0.elapsed();
    let b = total.load(Ordering::Relaxed);
    println!(
        "bulk conc={conc} bytes={b} wall={:.3}s throughput={:.0} MB/s",
        dt.as_secs_f64(),
        b as f64 / dt.as_secs_f64() / 1e6
    );
}
