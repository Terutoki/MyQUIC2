//! Process-level end-to-end tests for the client's config-driven forward
//! listeners (`[[tcp_forward]]` / `[[udp_forward]]`).
//!
//! These spawn the real `myquic2-server` and `myquic2-client` binaries with
//! real config files. That is the layer the client bin's unit tests cannot
//! cover: config validation at startup, listener binding/wiring, the full
//! QUIC tunnel, and the server's destination policy.
//!
//! Each test owns a temp dir (cert/key pair, both configs, the children's
//! logs) and its own ephemeral ports, so the cases may run in parallel.
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const AUTH: &str = "forward-e2e-secret";
const START_TIMEOUT: Duration = Duration::from_secs(20);

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

/// Bind-drop port discovery is TOCTOU; the caller's reserved forward ports must
/// not be handed to the SOCKS/server listener, or the client's own overlap
/// validator (correctly) refuses to start.
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

fn spawn_bin(bin: &str, cfg: &Path, log: &Path) -> Child {
    spawn_bin_logged(bin, cfg, log, false)
}

/// Restart variant: append to the log so the pre-restart server output (and
/// the offset a caller took before respawning) stays readable.
fn spawn_bin_append(bin: &str, cfg: &Path, log: &Path) -> Child {
    spawn_bin_logged(bin, cfg, log, true)
}

fn spawn_bin_logged(bin: &str, cfg: &Path, log: &Path, append: bool) -> Child {
    let open = |p: &Path| {
        let mut opts = fs::OpenOptions::new();
        opts.create(true);
        if append {
            opts.append(true);
        } else {
            opts.write(true).truncate(true);
        }
        opts.open(p)
            .unwrap_or_else(|e| panic!("open {}: {e}", p.display()))
    };
    let stdout = open(log);
    let stderr = open(&log.with_extension("err"));
    Command::new(bin)
        .arg("--config")
        .arg(cfg)
        // `wait_started` keys on the info-level "socks5 listening on" line, and
        // the binaries default to `info` only when RUST_LOG is unset. Clear an
        // inherited RUST_LOG=warn so the harness behaves the same in a
        // developer shell and in CI.
        .env_remove("RUST_LOG")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

/// Liveness overrides for tests that must observe a dead path quickly.
///
/// `idle_timeout_secs` is floored at 15 by the transport, so the client's
/// silence watchdog (2/3 of idle) can fire no earlier than ~10 s. A shorter
/// value here would be silently clamped and only make the intent unclear.
#[derive(Clone, Copy)]
struct Liveness {
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
    reconnect_timeout_secs: u64,
}

/// One server + client pair with the tunnel's config written to a temp dir.
struct Harness {
    dir: tempfile::TempDir,
    server: Child,
    client: Child,
    server_cfg: PathBuf,
}

impl Harness {
    /// Start a server + client pair.
    ///
    /// `reserved` lists ports the caller already baked into `forwards` (the
    /// forward listeners are not chosen here); they are excluded from the
    /// SOCKS/server picks. The whole attempt is retried if a child exits during
    /// startup: bind-drop port discovery is TOCTOU, and a collision now either
    /// trips the client's duplicate-listener validator or makes the forward
    /// bind fail.
    fn start(allow_private: bool, forwards: &str, reserved: &[u16]) -> Harness {
        Self::start_opts(allow_private, forwards, reserved, None)
    }

    /// [`Self::start`] with explicit keepalive/idle/reconnect values, for the
    /// restart test that has to watch the liveness watchdog fire.
    fn start_opts(
        allow_private: bool,
        forwards: &str,
        reserved: &[u16],
        liveness: Option<Liveness>,
    ) -> Harness {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cert = dir.path().join("server-cert.pem");
        let key = dir.path().join("server-key.pem");
        myquic2::gen_self_signed_files(
            "test.com",
            cert.to_str().expect("utf-8 cert path"),
            key.to_str().expect("utf-8 key path"),
        )
        .expect("generate the pinned self-signed certificate");
        let server_cfg = dir.path().join("config-server.toml");
        let client_cfg = dir.path().join("config-client.toml");
        let client_log = dir.path().join("client.log");
        let server_log = dir.path().join("server.log");
        let mut last_error = String::new();
        for _ in 0..8 {
            let server_port = free_udp_port_excluding(reserved);
            let socks_port = free_tcp_port_excluding(&[reserved, &[server_port]].concat());
            write_configs(
                &server_cfg,
                &client_cfg,
                &cert,
                &key,
                server_port,
                socks_port,
                allow_private,
                forwards,
                liveness,
            );
            let mut server = spawn_bin(
                env!("CARGO_BIN_EXE_myquic2-server"),
                &server_cfg,
                &server_log,
            );
            let mut client = spawn_bin(
                env!("CARGO_BIN_EXE_myquic2-client"),
                &client_cfg,
                &client_log,
            );
            match wait_started_short(
                &mut client,
                &mut server,
                &client_log,
                Duration::from_secs(8),
            ) {
                Ok(()) => {
                    return Harness {
                        dir,
                        server,
                        client,
                        server_cfg: server_cfg.clone(),
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
        panic!("forward E2E harness could not start after 8 attempts: {last_error}");
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

    /// Re-check that startup completed (start already waited for it). Kept as an
    /// explicit assertion point: the forward listeners are bound and spawned
    /// before the "socks5 listening on" line.
    fn wait_started(&mut self) {
        let client_log = self.log_path("client.log", false);
        if let Err(e) = wait_started_short(
            &mut self.client,
            &mut self.server,
            &client_log,
            START_TIMEOUT,
        ) {
            panic!("harness did not start: {e}\n{}", self.logs());
        }
    }

    /// SIGKILL the server. No CONNECTION_CLOSE reaches the client, so this is
    /// the "silent path death" case the watchdog exists for.
    fn kill_server(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }

    /// Start the server again from the same config (same listen port, cert and
    /// forwards), appending to its log, and wait for the listener line.
    fn restart_server(&mut self) {
        let log = self.log_path("server.log", false);
        let offset = fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
        self.server =
            spawn_bin_append(env!("CARGO_BIN_EXE_myquic2-server"), &self.server_cfg, &log);
        if let Err(e) = wait_log_after(
            &mut self.server,
            &log,
            offset,
            "server listening on",
            Duration::from_secs(15),
        ) {
            panic!("server did not restart: {e}\n{}", self.logs());
        }
    }
}

/// Write both config files for one startup attempt.
#[allow(clippy::too_many_arguments)]
fn write_configs(
    server_cfg: &Path,
    client_cfg: &Path,
    cert: &Path,
    key: &Path,
    server_port: u16,
    socks_port: u16,
    allow_private: bool,
    forwards: &str,
    liveness: Option<Liveness>,
) {
    let (server_liveness, client_liveness) = match liveness {
        None => (String::new(), String::new()),
        Some(l) => (
            format!(
                "keep_alive_secs = {}\nidle_timeout_secs = {}\n",
                l.keep_alive_secs, l.idle_timeout_secs
            ),
            format!(
                "keep_alive_secs = {}\nidle_timeout_secs = {}\n\
                 reconnect_timeout_secs = {}\n",
                l.keep_alive_secs, l.idle_timeout_secs, l.reconnect_timeout_secs
            ),
        ),
    };
    fs::write(
        server_cfg,
        format!(
            "listen = \"127.0.0.1:{server_port}\"\n\
             cert_file = {:?}\n\
             key_file = {:?}\n\
             server_name = \"test.com\"\n\
             allow_private = {allow_private}\n\
             auth_token = {AUTH:?}\n\
             {server_liveness}",
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
             {client_liveness}\
             {forwards}\n",
            cert.display().to_string(),
        ),
    )
    .expect("write client config");
}

/// Wait until the client has bound every listener and entered its SOCKS accept
/// loop, returning a readable failure (including both children's logs are the
/// caller's job) when a child exits early or the deadline passes.
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

/// Wait for `needle` to appear in `log` after byte `offset` (the file's length
/// when the wait began). Fails early if the child exits.
fn wait_log_after(
    child: &mut Child,
    log: &Path,
    offset: u64,
    needle: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!(
                "child exited with {status} while waiting for {needle:?}"
            ));
        }
        let bytes = fs::read(log).unwrap_or_default();
        let start = usize::try_from(offset).unwrap_or(0).min(bytes.len());
        if String::from_utf8_lossy(&bytes[start..]).contains(needle) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{needle:?} did not appear in {} within {timeout:?}",
                log.display()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for child in [&mut self.client, &mut self.server] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Loopback TCP echo server (echoes each chunk, then shutdowns its write side).
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

/// Loopback UDP echo server (returns each datagram verbatim to its sender).
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

fn connect_retry(addr: SocketAddr, deadline: Instant) -> Option<TcpStream> {
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(3))).ok();
                s.set_write_timeout(Some(Duration::from_secs(3))).ok();
                return Some(s);
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    None
}

/// One TCP round trip through a forward listener, retried until the tunnel is
/// live. Returns the echoed bytes on success.
fn tcp_roundtrip(addr: SocketAddr, payload: &[u8], deadline: Instant) -> Option<Vec<u8>> {
    while Instant::now() < deadline {
        let Some(mut s) = connect_retry(
            addr,
            (Instant::now() + Duration::from_secs(1)).min(deadline),
        ) else {
            continue;
        };
        if s.write_all(payload).is_err() {
            continue;
        }
        let mut got = vec![0u8; payload.len()];
        if s.read_exact(&mut got).is_err() {
            continue;
        }
        if got == payload {
            return Some(got);
        }
    }
    None
}

/// Full TCP E2E: echo, half-close, and 32 parallel streams.
#[test]
fn tcp_forward_e2e_roundtrip_half_close_and_parallel() {
    let echo = spawn_tcp_echo();
    let fwd_port = free_tcp_port();
    let forwards =
        format!("[[tcp_forward]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo}\"\n");
    let mut h = Harness::start(true, &forwards, &[fwd_port]);
    h.wait_started();
    let addr: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();

    let deadline = Instant::now() + START_TIMEOUT;
    let got = tcp_roundtrip(addr, b"ping", deadline)
        .unwrap_or_else(|| panic!("TCP forward never echoed\n{}", h.logs()));
    assert_eq!(got, b"ping");

    // Half-close: the app's FIN must reach the target, and the target's FIN
    // must give the app a clean EOF after the echoed bytes.
    let mut s = connect_retry(addr, Instant::now() + Duration::from_secs(10))
        .unwrap_or_else(|| panic!("TCP forward listener went away\n{}", h.logs()));
    s.write_all(b"half-close").expect("write");
    s.shutdown(Shutdown::Write).expect("shutdown write");
    let mut got = Vec::new();
    s.read_to_end(&mut got).expect("read to end");
    assert_eq!(got, b"half-close", "half-close must preserve the stream");

    // Large payload: the pump's 16 KiB copy chunks and the QUIC stream must
    // preserve a multi-chunk transfer end to end (Review Focus #5).
    let big: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let echoed = tcp_roundtrip(addr, &big, Instant::now() + Duration::from_secs(20))
        .unwrap_or_else(|| panic!("64 KiB TCP payload was not relayed intact\n{}", h.logs()));
    assert_eq!(
        echoed, big,
        "a large TCP payload must round-trip byte-for-byte"
    );

    // Parallel streams: the pool multiplexes them, each echo must be its own.
    let mut joins = Vec::new();
    for i in 0..32u32 {
        let payload = format!("parallel-{i}").into_bytes();
        joins.push(thread::spawn(move || {
            tcp_roundtrip(addr, &payload, Instant::now() + Duration::from_secs(20))
                .map(|got| got == payload)
                .unwrap_or(false)
        }));
    }
    let results: Vec<bool> = joins
        .into_iter()
        .map(|j| j.join().expect("thread"))
        .collect();
    assert!(
        results.iter().all(|ok| *ok),
        "every parallel stream must echo its own payload; failures: {:?}\n{}",
        results
            .iter()
            .enumerate()
            .filter(|(_, ok)| !**ok)
            .map(|(i, _)| i)
            .collect::<Vec<_>>(),
        h.logs()
    );
}

/// UDP E2E: two peers on one listener get their own replies (per-peer session
/// demux), byte-for-byte.
#[test]
fn udp_forward_e2e_two_peers_get_their_own_replies() {
    let echo = spawn_udp_echo();
    let fwd_port = free_udp_port();
    let forwards =
        format!("[[udp_forward]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo}\"\n");
    let mut h = Harness::start(true, &forwards, &[fwd_port]);
    h.wait_started();
    let fwd: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let a = thread::spawn(move || udp_roundtrip(fwd, b"peer-a", deadline));
    let b = thread::spawn(move || udp_roundtrip(fwd, b"peer-b", deadline));
    assert!(
        a.join().expect("peer a thread"),
        "peer a never got its reply\n{}",
        h.logs()
    );
    assert!(
        b.join().expect("peer b thread"),
        "peer b never got its reply\n{}",
        h.logs()
    );
}

/// UDP E2E at the protocol's payload ceiling: an 8 KiB datagram must survive
/// the FRAG path in both directions and come back byte-for-byte.
#[test]
fn udp_forward_e2e_roundtrips_an_8k_payload() {
    let echo = spawn_udp_echo();
    let fwd_port = free_udp_port();
    let forwards =
        format!("[[udp_forward]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo}\"\n");
    let mut h = Harness::start(true, &forwards, &[fwd_port]);
    h.wait_started();
    let fwd: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    assert!(
        udp_roundtrip(fwd, &payload, Instant::now() + Duration::from_secs(20)),
        "an 8 KiB datagram must survive the forward path\n{}",
        h.logs()
    );
}

/// Send `payload` to `fwd` until the echo comes back (first datagrams can be
/// dropped while the QUIC pool is still dialing).
fn udp_roundtrip(fwd: SocketAddr, payload: &[u8], deadline: Instant) -> bool {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("read timeout");
    udp_roundtrip_on(&sock, fwd, payload, deadline)
}

/// [`udp_roundtrip`] on an existing peer socket, so a caller can prove the
/// *same* source address keeps working across a reconnect (the forward
/// listener's peer table and the QUIC session are independent lifetimes).
fn udp_roundtrip_on(sock: &UdpSocket, fwd: SocketAddr, payload: &[u8], deadline: Instant) -> bool {
    let mut buf = vec![0u8; payload.len().max(1024) + 64];
    while Instant::now() < deadline {
        if sock.send_to(payload, fwd).is_err() {
            return false;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if n == payload.len() && buf[..n] == *payload => {
                // Replies must come from the configured listen address (the
                // listener socket is the relay's write half), not from a
                // server/session port: that port is what the app talks to and
                // what its own firewall/NAPT rules expect.
                if from == fwd {
                    return true;
                }
                return false;
            }
            _ => {}
        }
    }
    false
}

/// Server policy: a private target is refused before any dial, and the app
/// must see that refusal quickly (a reset/EOF, not a parked connection).
///
/// The 3 s bound separates the policy refusal (server resets the stream
/// immediately, so the client pump errors within an RTT) from "the QUIC pool
/// was not up yet" (the relay then waits out its 5 s connection timeout). A
/// slow close is retried rather than counted as the expected failure.
#[test]
fn private_target_fails_fast_without_allow_private() {
    let echo = spawn_tcp_echo();
    let fwd_port = free_tcp_port();
    let forwards =
        format!("[[tcp_forward]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo}\"\n");
    let mut h = Harness::start(false, &forwards, &[fwd_port]);
    h.wait_started();
    let addr: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        assert!(
            Instant::now() < deadline,
            "a refused private target never failed fast\n{}",
            h.logs()
        );
        let Some(mut s) = connect_retry(
            addr,
            (Instant::now() + Duration::from_secs(1)).min(deadline),
        ) else {
            continue;
        };
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let started = Instant::now();
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) | Err(_) => {
                if started.elapsed() < Duration::from_secs(3) {
                    return; // fast refusal: the expected outcome
                }
            }
            Ok(n) => panic!(
                "server forwarded {n} bytes to a private target with allow_private=false\n{}",
                h.logs()
            ),
        }
    }
}

/// A malformed forward entry must fail client startup with a message naming
/// the entry and field — never start without that listener.
#[test]
fn invalid_forward_config_fails_client_startup() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let cfg = dir.path().join("config-client.toml");
    // Validation runs before any certificate/TLS work, so the server-related
    // paths may be dummies: the process must exit naming the forward entry.
    fs::write(
        &cfg,
        "socks_listen = \"127.0.0.1:1080\"\n\
         server_addr = \"127.0.0.1:8443\"\n\
         server_name = \"test.com\"\n\
         server_cert_file = \"missing.pem\"\n\
         auth_token = \"\"\n\
         [[tcp_forward]]\n\
         listen = \"127.0.0.1\"\n\
         target = \"example.com:80\"\n",
    )
    .expect("write client config");
    let log = dir.path().join("client.log");
    let mut child = spawn_bin(env!("CARGO_BIN_EXE_myquic2-client"), &cfg, &log);
    let status = wait_child(&mut child, Duration::from_secs(15))
        .expect("client must exit on an invalid forward config");
    assert!(!status.success(), "exit status must be non-zero: {status}");
    let stderr = fs::read_to_string(log.with_extension("err")).unwrap_or_default();
    assert!(
        stderr.contains("tcp_forward[0].listen"),
        "the error must name the entry and field; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("missing :port"),
        "the error must name the problem; stderr was:\n{stderr}"
    );
}

fn wait_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("probe child") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Peer churn must not kill the UDP forward listener.
///
/// On Linux an ICMP port-unreachable produced by a reply to a peer that already
/// closed its socket surfaces as `ECONNREFUSED` on the listener's next
/// `recv_from`. Ending the listener there silently stopped forwarding for every
/// other peer until process restart, so this test creates 40 one-shot peers and
/// then requires the listener to still serve a normal peer. (macOS may not
/// surface the asynchronous ICMP error; on Linux CI this pins the retry path.)
#[test]
fn udp_forward_listener_survives_peer_churn() {
    let echo = spawn_udp_echo();
    let fwd_port = free_udp_port();
    let forwards =
        format!("[[udp_forward]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo}\"\n");
    let mut h = Harness::start(true, &forwards, &[fwd_port]);
    h.wait_started();
    let fwd: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();
    // Warm the tunnel so the churn replies are actually attempted.
    assert!(
        udp_roundtrip(fwd, b"warmup", Instant::now() + Duration::from_secs(10)),
        "the UDP forward never came up\n{}",
        h.logs()
    );
    // One-shot peers: send once, close immediately. The echo replies are then
    // written to a closed port.
    for _ in 0..40 {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("churn peer");
        let _ = peer.send_to(b"churn", fwd);
        drop(peer);
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        udp_roundtrip(
            fwd,
            b"after-churn",
            Instant::now() + Duration::from_secs(10)
        ),
        "peer churn stopped the UDP forward listener\n{}",
        h.logs()
    );
}

/// Server restart: the client must notice the tunnel is gone on its own, keep
/// both forward listeners alive while the server is down, redial the same
/// address, and carry TCP and UDP echo again — including on the UDP peer
/// socket that existed before the restart.
///
/// The server is SIGKILLed, so no CONNECTION_CLOSE is sent: detection depends
/// on the client's silence watchdog (`2/3` of the idle timeout). With the
/// transport's 15 s idle floor that is ~10 s, so this is intentionally the
/// slowest e2e case; the assertions, not a shorter timeout, are what pin the
/// reconnect path.
#[test]
fn forwards_detect_server_loss_and_recover_after_restart() {
    let tcp_echo = spawn_tcp_echo();
    let udp_echo = spawn_udp_echo();
    let tcp_fwd_port = free_tcp_port();
    let udp_fwd_port = free_udp_port();
    let forwards = format!(
        "[[tcp_forward]]\nlisten = \"127.0.0.1:{tcp_fwd_port}\"\ntarget = \"{tcp_echo}\"\n\
         [[udp_forward]]\nlisten = \"127.0.0.1:{udp_fwd_port}\"\ntarget = \"{udp_echo}\"\n"
    );
    let mut h = Harness::start_opts(
        true,
        &forwards,
        &[tcp_fwd_port, udp_fwd_port],
        Some(Liveness {
            keep_alive_secs: 1,
            idle_timeout_secs: 15,
            reconnect_timeout_secs: 2,
        }),
    );
    h.wait_started();
    let tcp_fwd: SocketAddr = format!("127.0.0.1:{tcp_fwd_port}").parse().unwrap();
    let udp_fwd: SocketAddr = format!("127.0.0.1:{udp_fwd_port}").parse().unwrap();

    // Both forward paths are live before the restart.
    let got = tcp_roundtrip(
        tcp_fwd,
        b"before-restart",
        Instant::now() + Duration::from_secs(20),
    )
    .unwrap_or_else(|| panic!("TCP forward never came up\n{}", h.logs()));
    assert_eq!(got, b"before-restart");
    let udp_peer = UdpSocket::bind("127.0.0.1:0").expect("bind persistent UDP peer");
    udp_peer
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("read timeout");
    assert!(
        udp_roundtrip_on(
            &udp_peer,
            udp_fwd,
            b"before-restart",
            Instant::now() + Duration::from_secs(20)
        ),
        "UDP forward never came up\n{}",
        h.logs()
    );

    let client_log = h.log_path("client.log", false);
    let killed_at = fs::metadata(&client_log).map(|m| m.len()).unwrap_or(0);
    h.kill_server();

    // SIGKILL leaves the QUIC connection half-open: only the client's own
    // liveness detection can turn this into a redial.
    if let Err(e) = wait_log_after(
        &mut h.client,
        &client_log,
        killed_at,
        "QUIC connection lost, reconnecting",
        Duration::from_secs(30),
    ) {
        panic!("client did not detect the server loss: {e}\n{}", h.logs());
    }

    // While the server is down, neither listener may deliver a stale echo.
    assert!(
        !udp_roundtrip_on(
            &udp_peer,
            udp_fwd,
            b"while-down",
            Instant::now() + Duration::from_millis(1200)
        ),
        "UDP forward echoed while the server was down\n{}",
        h.logs()
    );
    let mut down = connect_retry(tcp_fwd, Instant::now() + Duration::from_secs(2))
        .unwrap_or_else(|| panic!("TCP forward listener died with the server\n{}", h.logs()));
    down.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ = down.write_all(b"while-down");
    let mut buf = [0u8; 32];
    match down.read(&mut buf) {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!(
            "TCP forward echoed {n} bytes while the server was down\n{}",
            h.logs()
        ),
    }
    // Release the relay permit before the restart; this stream belongs to the
    // dead generation and can never carry the post-restart echo.
    drop(down);

    // Restart the very same server config (port, cert, forwards). The client
    // was not restarted or reconfigured: recovery proves the redial path.
    let restarted_at = fs::metadata(&client_log).map(|m| m.len()).unwrap_or(0);
    h.restart_server();
    let got = tcp_roundtrip(
        tcp_fwd,
        b"after-restart",
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap_or_else(|| panic!("TCP forward did not recover after restart\n{}", h.logs()));
    assert_eq!(got, b"after-restart");
    assert!(
        udp_roundtrip_on(
            &udp_peer,
            udp_fwd,
            b"after-restart",
            Instant::now() + Duration::from_secs(30)
        ),
        "the pre-restart UDP peer did not recover its forward\n{}",
        h.logs()
    );
    // Echo recovery already implies a redial; the log pins that it was the
    // same client process that reconnected to the restarted server.
    if let Err(e) = wait_log_after(
        &mut h.client,
        &client_log,
        restarted_at,
        "QUIC connected to",
        Duration::from_secs(10),
    ) {
        panic!(
            "client never logged a post-restart connect: {e}\n{}",
            h.logs()
        );
    }
}
