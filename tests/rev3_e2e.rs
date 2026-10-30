//! Process-level end-to-end tests for the configurable MQP-3 wire revision.
//!
//! Each test spawns the real `myquic2-server` and `myquic2-client` binaries with
//! temp configs pinned to a `wire_rev` (3 = rev3 default, 2 = rev2 rollback) and
//! drives traffic through the actual tunnel:
//!
//! - rev3 SOCKS5 `UDP ASSOCIATE` round-trips (OPEN + steady frames), a payload
//!   above the live DATAGRAM budget (`FRAG`), and a domain target
//!   (OPEN(domain) → server-side DNS → reply-source SRC context → steady);
//! - rev3 SOCKS5 `CONNECT` and the config-driven TCP/UDP forward listeners;
//! - rev3 0-RTT resumption after a forced path break;
//! - rev2 rollback: the same key round-trips with `wire_rev = 2`;
//! - distinct ALPN labels across revisions (the opt-in fail-fast pair) must fail
//!   at the TLS gate and never forward a byte. Both revisions default to the
//!   shared `h3` label, so a same-label mixed pair is *unsupported* rather than
//!   detected: it completes the handshake and then fails at the data plane.
//!   Matched binaries are required unless distinct labels are pinned.
//!
//! The in-bin `tests_0rtt.rs` files cover the in-process, pre-handshake
//! assertions against the production accept path and dial; this file covers
//! config parsing, revision selection, ALPN and the real wire end to end. The
//! harness duplicates the small pieces of `tests/forward_e2e.rs` it needs
//! because every integration test file is its own crate.
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const AUTH: &str = "rev3-e2e-secret";
const START_TIMEOUT: Duration = Duration::from_secs(25);

/// `wire_rev` values the binaries accept.
const REV2: u8 = 2;
const REV3: u8 = 3;

// ---------------------------------------------------------------- ports -----

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a free TCP port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind a free UDP port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Bind-drop port discovery is TOCTOU; a port already baked into a forward
/// listener must not be handed to the SOCKS/server listeners (the client's own
/// overlap validator would correctly refuse to start).
fn free_tcp_port_excluding(exclude: &[u16]) -> u16 {
    for _ in 0..128 {
        let p = free_tcp_port();
        if !exclude.contains(&p) {
            return p;
        }
    }
    panic!("no free TCP port outside {exclude:?}");
}

fn free_udp_port_excluding(exclude: &[u16]) -> u16 {
    for _ in 0..128 {
        let p = free_udp_port();
        if !exclude.contains(&p) {
            return p;
        }
    }
    panic!("no free UDP port outside {exclude:?}");
}

fn listener_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

// ------------------------------------------------------------- harness ------

/// One server + client pair with both configs written to a temp dir.
struct Harness {
    dir: tempfile::TempDir,
    server: Child,
    client: Child,
    client_cfg: PathBuf,
}

/// Spawn a binary with stdout/stderr redirected to `log`.
fn spawn_bin(bin: &str, cfg: &Path, log: &Path, log_filter: Option<&str>) -> Child {
    let open = |p: &Path| {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(p)
            .unwrap_or_else(|e| panic!("open {}: {e}", p.display()))
    };
    let stdout = open(log);
    let stderr = open(&log.with_extension("err"));
    let mut cmd = Command::new(bin);
    cmd.arg("--config")
        .arg(cfg)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    match log_filter {
        Some(filter) => {
            cmd.env("RUST_LOG", filter);
        }
        None => {
            // The binaries default to `info` only when RUST_LOG is unset; clear
            // an inherited value so the harness behaves the same in a developer
            // shell and in CI.
            cmd.env_remove("RUST_LOG");
        }
    }
    cmd.spawn().unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

/// A self-signed certificate pair in a temp dir, usable by both binaries.
fn write_cert_pair(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("server-cert.pem");
    let key = dir.join("server-key.pem");
    myquic2::gen_self_signed_files(
        "test.com",
        cert.to_str().expect("utf-8 cert path"),
        key.to_str().expect("utf-8 key path"),
    )
    .expect("generate the pinned self-signed certificate");
    (cert, key)
}

/// Write a matched server/client config pair pinned to `wire_rev`.
#[allow(clippy::too_many_arguments)]
fn write_configs(
    server_cfg: &Path,
    client_cfg: &Path,
    cert: &Path,
    key: &Path,
    server_port: u16,
    socks_port: u16,
    wire_rev: u8,
    allow_private: bool,
    extra_server: &str,
    extra_client: &str,
) {
    fs::write(
        server_cfg,
        format!(
            "listen = \"127.0.0.1:{server_port}\"\n\
             cert_file = {:?}\n\
             key_file = {:?}\n\
             server_name = \"test.com\"\n\
             allow_private = {allow_private}\n\
             auth_token = {AUTH:?}\n\
             wire_rev = {wire_rev}\n\
             {extra_server}",
            cert.display().to_string(),
            key.display().to_string(),
        ),
    )
    .expect("write server config");
    fs::write(
        client_cfg,
        format!(
            "socks_listen = \"127.0.0.1:{socks_port}\"\n\
             server_addr = \"127.0.0.1:{server_port}\"\n\
             server_name = \"test.com\"\n\
             server_cert_file = {:?}\n\
             auth_token = {AUTH:?}\n\
             wire_rev = {wire_rev}\n\
             {extra_client}\n",
            cert.display().to_string(),
        ),
    )
    .expect("write client config");
}

/// Collect the `listen` ports embedded in a `[[udp_forward]]` /
/// `[[tcp_forward]]` fragment so the dynamic SOCKS/server ports never collide
/// with them.
fn listener_ports(extra: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for line in extra.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("listen") else {
            continue;
        };
        let Some(addr) = rest.split('"').nth(1) else {
            continue;
        };
        if let Some(port) = addr.rsplit(':').next().and_then(|p| p.parse().ok()) {
            out.push(port);
        }
    }
    out
}

impl Harness {
    /// Start a matched server/client pair pinned to `wire_rev`.
    ///
    /// `extra_server` / `extra_client` are appended verbatim to the respective
    /// configs (forward listeners, liveness overrides, …); `log_filter` sets
    /// `RUST_LOG` for both children.
    fn start(
        wire_rev: u8,
        allow_private: bool,
        extra_server: &str,
        extra_client: &str,
        log_filter: Option<&str>,
    ) -> Harness {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (cert, key) = write_cert_pair(dir.path());
        let server_cfg = dir.path().join("config-server.toml");
        let client_cfg = dir.path().join("config-client.toml");
        let client_log = dir.path().join("client.log");
        let server_log = dir.path().join("server.log");
        let mut last_error = String::new();
        for _ in 0..8 {
            // Both extras may add listeners: forward listeners live in the
            // client config, so reserve every explicit port from both sides.
            let mut reserved = listener_ports(extra_server);
            reserved.extend(listener_ports(extra_client));
            let server_port = free_udp_port_excluding(&reserved);
            let socks_port = free_tcp_port_excluding(&[reserved, vec![server_port]].concat());
            write_configs(
                &server_cfg,
                &client_cfg,
                &cert,
                &key,
                server_port,
                socks_port,
                wire_rev,
                allow_private,
                extra_server,
                extra_client,
            );
            let mut server = spawn_bin(
                env!("CARGO_BIN_EXE_myquic2-server"),
                &server_cfg,
                &server_log,
                log_filter,
            );
            let mut client = spawn_bin(
                env!("CARGO_BIN_EXE_myquic2-client"),
                &client_cfg,
                &client_log,
                log_filter,
            );
            match wait_started_short(
                &mut client,
                &mut server,
                &client_log,
                Duration::from_secs(10),
            ) {
                Ok(()) => {
                    return Harness {
                        dir,
                        server,
                        client,
                        client_cfg,
                    };
                }
                Err(e) => {
                    let mut logs = e;
                    for (name, err) in [
                        ("server.log", false),
                        ("server.log", true),
                        ("client.log", false),
                        ("client.log", true),
                    ] {
                        let mut p = dir.path().join(name);
                        if err {
                            p = p.with_extension("err");
                        }
                        logs.push_str(&format!(
                            "\n--- {}\n{}",
                            p.display(),
                            fs::read_to_string(&p).unwrap_or_default()
                        ));
                    }
                    last_error = logs;
                    let _ = client.kill();
                    let _ = client.wait();
                    let _ = server.kill();
                    let _ = server.wait();
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        panic!("rev3 E2E harness could not start after 8 attempts: {last_error}");
    }

    fn log_path(&self, name: &str, err: bool) -> PathBuf {
        let mut p = self.dir.path().join(name);
        if err {
            p = p.with_extension("err");
        }
        p
    }

    fn logs(&self) -> String {
        let mut all = String::new();
        for (name, err) in [
            ("server.log", false),
            ("server.log", true),
            ("client.log", false),
            ("client.log", true),
        ] {
            let p = self.log_path(name, err);
            all.push_str(&format!("--- {}\n", p.display()));
            all.push_str(&fs::read_to_string(&p).unwrap_or_default());
        }
        all
    }

    fn log_text(&self, name: &str) -> String {
        fs::read_to_string(self.log_path(name, false)).unwrap_or_default()
    }

    /// Byte length of the client log, used as the "from" anchor of
    /// [`Self::wait_client_log`] after a forced reconnection.
    fn client_log_len(&self) -> usize {
        fs::metadata(self.log_path("client.log", false))
            .map(|m| usize::try_from(m.len()).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Wait for `needle` to appear in the client log after byte offset `from`.
    /// Fails early if the client exits.
    fn wait_client_log(
        &mut self,
        needle: &str,
        from: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let path = self.log_path("client.log", false);
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.client.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "client exited with {status} while waiting for {needle:?}"
                ));
            }
            let text = fs::read_to_string(&path).unwrap_or_default();
            if text.get(from..).unwrap_or("").contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{needle:?} did not appear in {} within {timeout:?}",
                    path.display()
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stop the **server** process (`SIGSTOP`). The client keeps sending but
    /// receives nothing, so its downlink-silence watchdog fires (~10 s with the
    /// test's liveness override), force-closes and redials; the server resumes
    /// with its resumption session store intact, so those redials are 0-RTT.
    #[cfg(unix)]
    fn stop_server(&self) {
        signal(&self.server, "-STOP");
    }

    #[cfg(unix)]
    fn resume_server(&self) {
        signal(&self.server, "-CONT");
    }

    /// The SOCKS listen address (chosen dynamically by the harness).
    fn socks_addr(&self) -> SocketAddr {
        let text = fs::read_to_string(&self.client_cfg).expect("read client config");
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("socks_listen")
                && let Some(addr) = rest.split('"').nth(1)
            {
                return addr.parse().expect("socks_listen is an IP:port literal");
            }
        }
        panic!("no socks_listen in {}", self.client_cfg.display());
    }
}

/// Accumulated CPU time of a process, in seconds (`ps -o time=`: `M:SS.ss` or
/// `H:MM:SS`). The delta across a wall-clock sleep is the process's core usage.
#[cfg(unix)]
fn cpu_seconds(pid: u32) -> f64 {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .expect("spawn ps");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut secs = 0.0f64;
    for part in text.trim().split(':') {
        secs = secs * 60.0 + part.trim().parse::<f64>().unwrap_or(0.0);
    }
    secs
}

#[cfg(unix)]
fn signal(child: &Child, signal: &str) {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .arg(signal)
        .arg(&pid)
        .status()
        .expect("spawn kill");
    assert!(status.success(), "kill {signal} {pid} failed");
}

impl Drop for Harness {
    fn drop(&mut self) {
        for child in [&mut self.client, &mut self.server] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Wait until the client has bound its listeners and entered the SOCKS accept
/// loop (every listener is bound before that info line).
fn wait_started_short(
    client: &mut Child,
    server: &mut Child,
    client_log: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = client.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("client exited during startup: {status}"));
        }
        if let Some(status) = server.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("server exited during startup: {status}"));
        }
        if fs::read_to_string(client_log)
            .unwrap_or_default()
            .contains("socks5 listening on")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "client did not complete startup within {timeout:?}"
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// --------------------------------------------------------------- socks ------

/// Dial the SOCKS5 listener and complete the no-auth greeting.
fn socks_greeting(s: &mut TcpStream) -> Result<(), String> {
    s.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| e.to_string())?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).map_err(|e| e.to_string())?;
    if reply != [0x05, 0x00] {
        return Err(format!("unexpected SOCKS greeting answer {reply:?}"));
    }
    Ok(())
}

/// Total byte length of a SOCKS5 address field whose `ATYP` is at `atyp_at`,
/// including `ATYP | addr | port`.
fn socks_addr_len(buf: &[u8], atyp_at: usize) -> Option<usize> {
    let atyp = *buf.get(atyp_at)?;
    let body_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => usize::from(*buf.get(atyp_at + 1)?),
        _ => return None,
    };
    Some(atyp_at + 1 + body_len + 2)
}

/// A SOCKS5 destination: raw IP or domain name.
#[derive(Clone, Copy)]
enum SocksTarget<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl SocksTarget<'_> {
    /// SOCKS5 address bytes (`ATYP | addr | port`).
    fn bytes(&self) -> Vec<u8> {
        match self {
            SocksTarget::Ip(SocketAddr::V4(v4)) => {
                let mut v = vec![0x01];
                v.extend_from_slice(&v4.ip().octets());
                v.extend_from_slice(&v4.port().to_be_bytes());
                v
            }
            SocksTarget::Ip(SocketAddr::V6(v6)) => {
                let mut v = vec![0x04];
                v.extend_from_slice(&v6.ip().octets());
                v.extend_from_slice(&v6.port().to_be_bytes());
                v
            }
            SocksTarget::Domain(host, port) => {
                let mut v = vec![0x03, u8::try_from(host.len()).expect("domain fits")];
                v.extend_from_slice(host.as_bytes());
                v.extend_from_slice(&port.to_be_bytes());
                v
            }
        }
    }
}

/// One SOCKS5 `CONNECT` attempt; `None` means "not yet, retry" (the tunnel may
/// still be dialing).
fn socks_connect_once(
    proxy: SocketAddr,
    target: SocksTarget<'_>,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&proxy, Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_write_timeout(Some(Duration::from_secs(5))).ok();
    socks_greeting(&mut s).ok()?;
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&target.bytes());
    s.write_all(&req).ok()?;
    let mut reply = [0u8; 24];
    s.read_exact(&mut reply[..4]).ok()?;
    if reply[1] != 0x00 {
        // REP != succeeded: the tunnel is not up yet.
        return None;
    }
    let len = socks_addr_len(&reply, 3)?;
    if len > 4 {
        s.read_exact(&mut reply[4..len]).ok()?;
    }
    s.write_all(payload).ok()?;
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).ok()?;
    let _ = s.shutdown(Shutdown::Both);
    Some(got)
}

/// SOCKS5 `CONNECT` + one payload round-trip, retried until `deadline`.
fn socks_tcp_roundtrip(
    proxy: SocketAddr,
    target: SocksTarget<'_>,
    payload: &[u8],
    deadline: Instant,
) -> Option<Vec<u8>> {
    while Instant::now() < deadline {
        if let Some(got) = socks_connect_once(proxy, target, payload) {
            return Some(got);
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

/// SOCKS5 `UDP ASSOCIATE`; returns the control connection (kept alive) and the
/// relay address UDP datagrams are sent to.
fn socks_udp_associate(proxy: SocketAddr, deadline: Instant) -> Option<(TcpStream, SocketAddr)> {
    while Instant::now() < deadline {
        let Some(mut s) = TcpStream::connect_timeout(&proxy, Duration::from_millis(500)).ok()
        else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        if socks_greeting(&mut s).is_err() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        // CMD=UDP ASSOCIATE, ATYP=IPv4 0.0.0.0:0 (the conventional hint).
        let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        if s.write_all(&req).is_err() {
            continue;
        }
        let mut reply = [0u8; 24];
        if s.read_exact(&mut reply[..4]).is_err() {
            continue;
        }
        if reply[0] != 0x05 || reply[1] != 0x00 {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let Some(len) = socks_addr_len(&reply, 3) else {
            continue;
        };
        if len > 4 && s.read_exact(&mut reply[4..len]).is_err() {
            continue;
        }
        let mut ip = match reply[3] {
            0x01 => std::net::IpAddr::from([reply[4], reply[5], reply[6], reply[7]]),
            0x04 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&reply[4..20]);
                std::net::IpAddr::from(octets)
            }
            _ => proxy.ip(),
        };
        let port_at = len - 2;
        let port = u16::from_be_bytes([reply[port_at], reply[port_at + 1]]);
        if ip.is_unspecified() {
            ip = proxy.ip();
        }
        return Some((s, SocketAddr::new(ip, port)));
    }
    None
}

/// Send one SOCKS5 UDP datagram through `relay` and return the reply payload,
/// retried until `deadline`.
fn socks_udp_roundtrip(
    sock: &UdpSocket,
    relay: SocketAddr,
    target: SocksTarget<'_>,
    payload: &[u8],
    deadline: Instant,
) -> Option<Vec<u8>> {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let mut datagram = vec![0x00, 0x00, 0x00];
    datagram.extend_from_slice(&target.bytes());
    datagram.extend_from_slice(payload);
    let mut buf = vec![0u8; 66 * 1024];
    while Instant::now() < deadline {
        if sock.send_to(&datagram, relay).is_ok()
            && let Ok((n, _)) = sock.recv_from(&mut buf)
            && let Some(addr_len) = socks_addr_len(&buf[..n], 3)
            && n > addr_len
        {
            return Some(buf[addr_len..n].to_vec());
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Raw UDP datagram round trip through a `[[udp_forward]]` listener.
fn raw_udp_roundtrip(listener: SocketAddr, payload: &[u8], deadline: Instant) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let mut buf = vec![0u8; 66 * 1024];
    while Instant::now() < deadline {
        if sock.send_to(payload, listener).is_ok()
            && let Ok((n, _)) = sock.recv_from(&mut buf)
        {
            return Some(buf[..n].to_vec());
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

// ------------------------------------------------------------- targets ------

/// Loopback TCP echo server.
fn spawn_tcp_echo() -> SocketAddr {
    let li = TcpListener::bind("127.0.0.1:0").expect("bind TCP echo");
    let addr = li.local_addr().expect("echo addr");
    thread::spawn(move || {
        for conn in li.incoming() {
            let Ok(mut conn) = conn else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// Loopback UDP echo server.
fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo");
    let addr = sock.local_addr().expect("echo addr");
    thread::spawn(move || {
        let mut buf = vec![0u8; 66 * 1024];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], from);
        }
    });
    addr
}

// --------------------------------------------------------------- serial -----

/// Serializes the process-level tests in this binary.
///
/// Every test spawns a real `myquic2-server` + `myquic2-client` pair and picks
/// ephemeral ports before spawning; running several pairs in parallel makes
/// startup races (port reuse, CPU contention on the 12 s 0-RTT scenario) show
/// up as flaky harness failures rather than product regressions. The tests are
/// independent, so serializing them costs wall-clock time only.
static E2E_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn e2e_guard() -> std::sync::MutexGuard<'static, ()> {
    // A panicking test poisons the mutex; recover the guard so the remaining
    // tests still run and report their own verdict.
    E2E_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------- tests -----

/// The revision the binaries resolved from config is observable in their own
/// startup line; this is the wiring proof the behavioural cases build on.
///
/// The harness returns as soon as the *client* logs its SOCKS listener line, so
/// the server may still be inside its own startup (the two children are
/// scheduled independently, and a debug log filter widens the window). Poll
/// both startup lines for a bounded time instead of racing the server's first
/// log write.
fn assert_wire_selected(h: &Harness, rev: u8) {
    let needle = format!("application wire: rev{rev}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let client_ok = h.log_text("client.log").contains(&needle);
        let server_ok = h.log_text("server.log").contains(&needle);
        if client_ok && server_ok {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "wire-selection line missing (client_ok={client_ok} server_ok={server_ok}) \
                 for {needle}\n{}",
                h.logs()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// rev3: SOCKS5 `UDP ASSOCIATE` OPEN + steady datagrams round-trip through the
/// real rev3 data plane.
#[test]
fn rev3_socks_udp_roundtrip_open_and_steady() {
    let _serial = e2e_guard();
    let echo = spawn_udp_echo();
    let h = Harness::start(REV3, true, "", "", None);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    for (i, payload) in [b"dns-like".as_slice(), b"steady-2".as_slice(), b"steady-3"]
        .into_iter()
        .enumerate()
    {
        let got = socks_udp_roundtrip(
            &sock,
            relay,
            SocksTarget::Ip(echo),
            payload,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap_or_else(|| panic!("rev3 UDP payload {i} never echoed\n{}", h.logs()));
        assert_eq!(got, payload, "rev3 UDP payload {i} must round-trip intact");
    }
    assert_wire_selected(&h, REV3);
}

/// rev3: a payload above the live DATAGRAM budget goes through the rev3 `FRAG`
/// path and reassembles byte-for-byte in both directions.
#[test]
fn rev3_frag_above_datagram_budget_roundtrip() {
    let _serial = e2e_guard();
    let echo = spawn_udp_echo();
    let h = Harness::start(REV3, true, "", "", None);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    // 4 KiB is above any live DATAGRAM budget (≤1434 B): both directions
    // fragment and reassemble.
    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(echo),
        &payload,
        Instant::now() + Duration::from_secs(15),
    )
    .unwrap_or_else(|| panic!("rev3 fragmented payload never echoed\n{}", h.logs()));
    assert_eq!(
        got, payload,
        "a >DATAGRAM-budget payload must reassemble intact"
    );
    assert_wire_selected(&h, REV3);
}

/// rev3: a **domain** target exercises OPEN(domain) → server-side DNS → the
/// reply-source SRC context → steady downlink.
#[test]
fn rev3_domain_target_roundtrip() {
    let _serial = e2e_guard();
    let echo = spawn_udp_echo();
    // `localhost` has both families and the default resolution order is
    // IPv6-first, while the echo target binds IPv4 only: pin the exit's
    // family preference so the domain OPEN resolves to the reachable address.
    let h = Harness::start(REV3, true, "dns_ip_preference = \"ipv4\"\n", "", None);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    // `localhost` resolves through the resolver's hosts-file path, so this test
    // is hermetic (no upstream DNS).
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Domain("localhost", echo.port()),
        b"domain-payload",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("rev3 domain target never echoed\n{}", h.logs()));
    assert_eq!(
        got, b"domain-payload",
        "the domain OPEN must reach the target"
    );
    assert_wire_selected(&h, REV3);
}

/// rev3: SOCKS5 `CONNECT` (TCP stream path) keeps working with rev3 selected.
#[test]
fn rev3_socks_tcp_connect_roundtrip() {
    let _serial = e2e_guard();
    let echo = spawn_tcp_echo();
    let h = Harness::start(REV3, true, "", "", None);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let got = socks_tcp_roundtrip(socks, SocksTarget::Ip(echo), b"rev3-tcp-connect", deadline)
        .unwrap_or_else(|| panic!("rev3 SOCKS CONNECT never echoed\n{}", h.logs()));
    assert_eq!(got, b"rev3-tcp-connect");
    // Multi-chunk transfer proves the stream pump as well.
    let big: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
    let got = socks_tcp_roundtrip(
        socks,
        SocksTarget::Ip(echo),
        &big,
        Instant::now() + Duration::from_secs(20),
    )
    .unwrap_or_else(|| panic!("rev3 large TCP payload never echoed\n{}", h.logs()));
    assert_eq!(got, big);
    assert_wire_selected(&h, REV3);
}

/// rev3: the config-driven forward listeners work on rev3 (TCP forward stream
/// header + UDP forward session).
#[test]
fn rev3_forward_listeners_roundtrip() {
    let _serial = e2e_guard();
    let tcp_echo = spawn_tcp_echo();
    let udp_echo = spawn_udp_echo();
    let tcp_fwd_port = free_tcp_port();
    let udp_fwd_port = free_udp_port();
    let extras = format!(
        "[[tcp_forward]]\nlisten = \"127.0.0.1:{tcp_fwd_port}\"\ntarget = \"{tcp_echo}\"\n\n\
         [[udp_forward]]\nlisten = \"127.0.0.1:{udp_fwd_port}\"\ntarget = \"{udp_echo}\"\n"
    );
    let h = Harness::start(REV3, true, "", &extras, None);
    let deadline = Instant::now() + START_TIMEOUT;
    // TCP forward: raw TCP -> one QUIC stream -> target.
    let got = loop {
        if let Ok(mut s) =
            TcpStream::connect_timeout(&listener_addr(tcp_fwd_port), Duration::from_millis(500))
        {
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            s.write_all(b"fwd-tcp").ok();
            let mut buf = [0u8; 7];
            if s.read_exact(&mut buf).is_ok() {
                break buf.to_vec();
            }
        }
        assert!(
            Instant::now() < deadline,
            "rev3 TCP forward never echoed\n{}",
            h.logs()
        );
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(got, b"fwd-tcp");
    // UDP forward: raw datagram -> rev3 session -> target.
    let payload = b"fwd-udp";
    let got = raw_udp_roundtrip(
        listener_addr(udp_fwd_port),
        payload,
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("rev3 UDP forward never echoed\n{}", h.logs()));
    assert_eq!(got, payload);
    assert_wire_selected(&h, REV3);
}

/// rev2 rollback: the key UDP and TCP round-trips still work when both binaries
/// are pinned to `wire_rev = 2`.
#[test]
fn rev2_rollback_udp_and_tcp_roundtrip() {
    let _serial = e2e_guard();
    let tcp_echo = spawn_tcp_echo();
    let udp_echo = spawn_udp_echo();
    let h = Harness::start(REV2, true, "", "", None);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("rev2 UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(udp_echo),
        b"rev2-udp",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("rev2 UDP payload never echoed\n{}", h.logs()));
    assert_eq!(got, b"rev2-udp");
    let got = socks_tcp_roundtrip(
        socks,
        SocksTarget::Ip(tcp_echo),
        b"rev2-tcp",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("rev2 SOCKS CONNECT never echoed\n{}", h.logs()));
    assert_eq!(got, b"rev2-tcp");
    assert_wire_selected(&h, REV2);
}

/// Distinct ALPN labels across revisions fail at the TLS gate in both
/// directions.
///
/// Both wire revisions default to the shared `h3` masquerade, so the ALPN label
/// is not a revision gate by default: a mismatched pair with the same label
/// handles the TLS handshake and then silently fails at the data plane (no
/// payload is misrouted, but nothing is forwarded). Operators who want a
/// handshake-level skew gate pin distinct labels instead; this test proves that
/// opt-in pair never completes a connection.
#[test]
fn distinct_alpn_labels_fail_at_the_tls_gate() {
    let _serial = e2e_guard();
    for (server_rev, server_alpn, client_rev, client_alpn) in [
        (REV2, "h3", REV3, "myquic2/r3"),
        (REV3, "myquic2/r3", REV2, "h3"),
    ] {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (cert, key) = write_cert_pair(dir.path());
        let server_cfg = dir.path().join("config-server.toml");
        let client_cfg = dir.path().join("config-client.toml");
        let server_port = free_udp_port();
        let socks_port = free_tcp_port_excluding(&[server_port]);
        // Deliberately mismatched labels across revisions: each binary is
        // written with its own label, so the TLS gate can fire.
        fs::write(
            &server_cfg,
            format!(
                "listen = \"127.0.0.1:{server_port}\"\n\
                 cert_file = {:?}\n\
                 key_file = {:?}\n\
                 server_name = \"test.com\"\n\
                 allow_private = true\n\
                 auth_token = {AUTH:?}\n\
                 wire_rev = {server_rev}\n\
                 alpn = {server_alpn:?}\n",
                cert.display().to_string(),
                key.display().to_string(),
            ),
        )
        .expect("write server config");
        fs::write(
            &client_cfg,
            format!(
                "socks_listen = \"127.0.0.1:{socks_port}\"\n\
                 server_addr = \"127.0.0.1:{server_port}\"\n\
                 server_name = \"test.com\"\n\
                 server_cert_file = {:?}\n\
                 auth_token = {AUTH:?}\n\
                 wire_rev = {client_rev}\n\
                 alpn = {client_alpn:?}\n",
                cert.display().to_string(),
            ),
        )
        .expect("write client config");
        let client_log = dir.path().join("client.log");
        let server_log = dir.path().join("server.log");
        let mut server = spawn_bin(
            env!("CARGO_BIN_EXE_myquic2-server"),
            &server_cfg,
            &server_log,
            None,
        );
        let mut client = spawn_bin(
            env!("CARGO_BIN_EXE_myquic2-client"),
            &client_cfg,
            &client_log,
            None,
        );
        let start = wait_started_short(&mut client, &mut server, &client_log, START_TIMEOUT);
        assert!(
            start.is_ok(),
            "a distinct-label pair must still start (server rev{server_rev} alpn \
             {server_alpn}, client rev{client_rev} alpn {client_alpn}): {start:?}"
        );
        // Give the reconnect loop a few attempts to hit the TLS gate.
        thread::sleep(Duration::from_secs(2));
        let client_text = fs::read_to_string(&client_log).unwrap_or_default();
        assert!(
            client_text.contains("dial") || client_text.contains("handshake"),
            "the client must log a failed handshake for server rev{server_rev} alpn \
             {server_alpn} / client rev{client_rev} alpn {client_alpn}:\n{client_text}"
        );
        assert!(
            !client_text.contains("QUIC connected to"),
            "a distinct-label pair must never complete a QUIC connection:\n{client_text}"
        );
        let server_text = fs::read_to_string(&server_log).unwrap_or_default();
        assert!(
            !server_text.contains("new QUIC conn"),
            "the server must never admit a peer rejected at the TLS gate:\n{server_text}"
        );
        let _ = client.kill();
        let _ = client.wait();
        let _ = server.kill();
        let _ = server.wait();
    }
}

/// rev3 + 0-RTT resumption: after a forced path break the client redials with
/// its resumption ticket, the 0-RTT dial is accepted, and the tunnel keeps
/// forwarding. The process-level companion to the in-bin pre-handshake tests.
#[cfg(unix)]
#[test]
fn rev3_0rtt_resumption_after_forced_path_break() {
    let _serial = e2e_guard();
    let echo = spawn_udp_echo();
    // Debug logs expose the 0-RTT acceptance lines. The liveness override makes
    // the silence watchdog fire after 10 s (idle floor 15 s → 2/3).
    // `reconnect_timeout_secs` is client-only (the server config rejects unknown
    // fields), so the two sides get separate blocks.
    let server_liveness = "keep_alive_secs = 1\nidle_timeout_secs = 15\n";
    let client_liveness =
        "keep_alive_secs = 1\nidle_timeout_secs = 15\nreconnect_timeout_secs = 5\n";
    let mut h = Harness::start(REV3, true, server_liveness, client_liveness, Some("debug"));
    assert_wire_selected(&h, REV3);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(echo),
        b"before-break",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("pre-break payload never echoed\n{}", h.logs()));
    assert_eq!(got, b"before-break");
    // Let the client receive its NewSessionTicket(s): in this quinn build they
    // trail the handshake by about one loss-detection timeout.
    thread::sleep(Duration::from_millis(1500));

    // Force a path break that the client can actually observe: stop the
    // *server* past the client's 10 s silence watchdog. The client keeps
    // sending but receives nothing, so it force-closes and redials while the
    // server is paused; the server resumes with its resumption session store
    // intact, so those redials complete as 0-RTT resumptions.
    let anchor = h.client_log_len();
    h.stop_server();
    thread::sleep(Duration::from_secs(12));
    h.resume_server();
    h.wait_client_log("0-RTT accepted", anchor, Duration::from_secs(25))
        .unwrap_or_else(|e| panic!("{e}\n{}", h.logs()));
    h.wait_client_log("QUIC connected to", anchor, Duration::from_secs(15))
        .unwrap_or_else(|e| panic!("{e}\n{}", h.logs()));

    // The tunnel keeps forwarding after the resumption repair.
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(echo),
        b"after-break",
        Instant::now() + Duration::from_secs(15),
    )
    .unwrap_or_else(|| panic!("post-resumption payload never echoed\n{}", h.logs()));
    assert_eq!(got, b"after-break");
    let client_text = h.log_text("client.log");
    assert!(
        client_text.contains("0-RTT auth token written in the first flight")
            || client_text.contains("0-RTT rejected"),
        "the redial must be a 0-RTT dial (accepted or repaired):\n{client_text}"
    );
    let server_text = h.log_text("server.log");
    assert!(
        !server_text.contains("auth failed from"),
        "the server must accept the 0-RTT/re-sent token:\n{server_text}"
    );
}

/// A *hard* server restart (the old process is gone, a new one starts with fresh
/// session-ticket keys) must not leave the client burning cores.
///
/// This is the reported symptom: server restarts, the client reconnects, and a
/// minute later one or two cores are pegged at 100%. The mechanism: the client's
/// resumption ticket was issued by the *previous* server process, so the new one
/// cannot decrypt the early data and rejects 0-RTT. The rev3 control stream used
/// to be the only client stream opened before the handshake settled, so it was
/// the stream that died. Its task then dropped the dispatcher's inbound queue,
/// and the dispatcher's `select!` kept polling that closed queue as a
/// permanently-ready branch: a closed, empty `mpsc::Receiver::recv()` resolves
/// `None` immediately, forever. The fix opens the control stream only after the
/// handshake verdict (so the rejection cannot reset it) and retires the
/// generation if the control stream dies anyway instead of spinning on it.
///
/// The CPU check is the assertion; the payload round-trip after it makes sure the
/// fix does not trade a spin for a stalled tunnel.
#[cfg(unix)]
#[test]
fn rev3_hard_server_restart_reconnect_does_not_burn_cores() {
    let _serial = e2e_guard();
    let echo = spawn_udp_echo();
    // The same liveness override as the resumption test: the silence watchdog
    // fires after ~10 s, so the client notices the stopped server quickly.
    let server_liveness = "keep_alive_secs = 1\nidle_timeout_secs = 15\n";
    let client_liveness =
        "keep_alive_secs = 1\nidle_timeout_secs = 15\nreconnect_timeout_secs = 5\n";
    let mut h = Harness::start(REV3, true, server_liveness, client_liveness, Some("debug"));
    assert_wire_selected(&h, REV3);
    let socks = h.socks_addr();
    let deadline = Instant::now() + START_TIMEOUT;
    let (_ctrl, relay) = socks_udp_associate(socks, deadline)
        .unwrap_or_else(|| panic!("UDP ASSOCIATE never succeeded\n{}", h.logs()));
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind app UDP");
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(echo),
        b"before-restart",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap_or_else(|| panic!("pre-restart payload never echoed\n{}", h.logs()));
    assert_eq!(got, b"before-restart");
    // Let the client receive its NewSessionTicket(s) from the old process.
    thread::sleep(Duration::from_millis(1500));

    // 1. Make the client notice the break and force-close its connection: the
    //    server is paused past the client's silence watchdog, so the redials
    //    that follow time out against a silent peer.
    let anchor = h.client_log_len();
    h.stop_server();
    thread::sleep(Duration::from_secs(12));

    // 2. Hard restart: SIGKILL the paused process and start a new one from the
    //    same config (same certificate, fresh ticket keys).
    let server_cfg = h.dir.path().join("config-server.toml");
    let server_log = h.log_path("server.log", false);
    let _ = fs::copy(&server_log, h.dir.path().join("server-before-restart.log"));
    let _ = h.server.kill();
    let _ = h.server.wait();
    // Everything the still-paused server made the client tear down is in the log
    // by now (the watchdog fired ~2 s ago). Anchor past it: from here on, any
    // control-stream teardown belongs to the *new* server and is a regression.
    let restart_anchor = h.client_log_len();
    h.server = spawn_bin(
        env!("CARGO_BIN_EXE_myquic2-server"),
        &server_cfg,
        &server_log,
        Some("debug"),
    );

    // 3. The client redials: its first successful dial offers the stale ticket
    //    and the new server rejects the early data.
    h.wait_client_log("QUIC connected to", anchor, Duration::from_secs(40))
        .unwrap_or_else(|e| panic!("{e}\n{}", h.logs()));
    // Let the rejection, the auth re-send and the control-stream teardown land.
    thread::sleep(Duration::from_secs(2));

    // 4. Measure the client's CPU time over a fixed wall window. A healthy idle
    //    client is far below one core; a busy-looped dispatcher shard is a whole
    //    core, one per affected connection.
    let pid = h.client.id();
    let before = cpu_seconds(pid);
    let wall = Duration::from_secs(4);
    thread::sleep(wall);
    let cores = (cpu_seconds(pid) - before) / wall.as_secs_f64();
    let client_text = h.log_text("client.log");
    let after_restart = client_text.get(restart_anchor..).unwrap_or("");
    println!(
        "client CPU after the restart: {cores:.2} cores \
         (0-RTT rejections after the restart: {}, control-stream teardowns: {})",
        after_restart.matches("0-RTT rejected").count(),
        after_restart.matches("control stream closed").count(),
    );
    // The test is only meaningful if the new server actually refused the stale
    // ticket. If this fails, resumption stopped being offered and the repro has
    // to be rebuilt around a different path break.
    assert!(
        after_restart.contains("0-RTT rejected"),
        "the client never offered 0-RTT after the restart, so the repro exercised \
         nothing:\n{}",
        h.logs()
    );
    assert!(
        cores < 0.5,
        "client burns {cores:.2} cores after reconnecting to the restarted server \
         (0-RTT rejected: {}):\n{}",
        client_text.contains("0-RTT rejected"),
        h.logs()
    );
    // The rejected early data must not take the generation's control plane down:
    // the control stream is opened only once the handshake verdict is known, so
    // the rejection cannot reset it. Any post-restart teardown would mean a
    // control stream died on a live connection and the dispatcher had to retire
    // that generation (the safety net): a needless reconnect and a lost data path.
    assert_eq!(
        after_restart.matches("control stream closed").count(),
        0,
        "0-RTT rejection killed a rev3 control stream on a live connection:\n{}",
        h.logs()
    );

    // 5. The tunnel still forwards after the reconnect.
    let got = socks_udp_roundtrip(
        &sock,
        relay,
        SocksTarget::Ip(echo),
        b"after-restart",
        Instant::now() + Duration::from_secs(15),
    )
    .unwrap_or_else(|| panic!("post-restart payload never echoed\n{}", h.logs()));
    assert_eq!(got, b"after-restart");
}
