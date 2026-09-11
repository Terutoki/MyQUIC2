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
            eprintln!("usage: hotpath_bench <echo|tcp|udp> ...");
            std::process::exit(2);
        }
    }
}

/// UDP echo target. Counts replies so the client-side harness can stop at a
/// fixed number instead of guessing how long to run.
fn echo(port: u16) {
    let s = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    println!("echo listening on 127.0.0.1:{port}");
    let mut buf = vec![0u8; 65535];
    while let Ok((n, a)) = s.recv_from(&mut buf) {
        let _ = s.send_to(&buf[..n], a);
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

/// One UDP ASSOCIATE, then `n` datagrams to the target, waiting for `n` replies.
fn udp(socks: &str, target: &str, n: usize, batch: usize) {
    let (host, port) = split_host(target);
    // TCP control connection + ASSOCIATE.
    let mut s = TcpStream::connect(socks).unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut g = [0u8; 2];
    s.read_exact(&mut g).unwrap();
    s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let mut rep = [0u8; 32];
    let k = s.read(&mut rep).unwrap();
    assert_eq!(rep[1], 0, "associate refused");
    let relay: SocketAddr = if rep[3] == 1 {
        let ip = std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
        let mut ip = std::net::IpAddr::V4(ip);
        if ip.is_unspecified() {
            ip = "127.0.0.1".parse().unwrap();
        }
        SocketAddr::new(ip, u16::from_be_bytes([rep[8], rep[9]]))
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&rep[4..20]);
        std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
            u16::from_be_bytes([rep[20], rep[21]]),
        )
    };
    let _ = k;
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    // Pre-build the SOCKS5 UDP request header once; only the payload varies.
    let ip: std::net::Ipv4Addr = host.parse().unwrap();
    let mut pkt = vec![0, 0, 0, 0x01];
    pkt.extend_from_slice(&ip.octets());
    pkt.extend_from_slice(&port.to_be_bytes());
    let hdr = pkt.len();
    pkt.resize(hdr + 1000, 0x5A);

    let mut sent = 0usize;
    let mut recv = 0usize;
    let mut stalled = 0usize;
    let mut buf = vec![0u8; 2048];
    let t0 = Instant::now();
    while recv < n {
        while sent < n && sent - recv < batch {
            if u.send_to(&pkt, relay).is_err() {
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
    let dt = t0.elapsed();
    println!(
        "udp sent={sent} recv={recv} batch={batch} wall={:.3}s recv_pps={:.0}",
        dt.as_secs_f64(),
        recv as f64 / dt.as_secs_f64()
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
