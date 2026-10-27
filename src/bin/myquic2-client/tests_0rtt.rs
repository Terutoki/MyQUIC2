//! 0-RTT early-data end-to-end tests on real loopback quinn endpoints.
//!
//! These pin the user-facing promise of the 0-RTT work: a **resumed** dial
//! hands back a published connection before the handshake completes, and the
//! auth token, a rev2 `HELLO` datagram and an application UDP payload all ride
//! the first flight — the server receives them while it is still handshaking.
//! A rejected resumption must re-send the token on a 1-RTT uni stream and the
//! connection must remain usable.
//!
//! Determinism: the "before the handshake completes" property cannot be
//! asserted on a bare loopback pair, where the server→client flight completes
//! the handshake within tens of microseconds of the first flight. The harness
//! therefore relays UDP through [`spawn_delay_proxy`], which delays **only the
//! server→client direction**. The client's first flight reaches the server
//! immediately; the server's handshake flight (and every later server→client
//! packet) arrives 250 ms later, so every observation the server makes on the
//! first flight provably happens before it can have completed the handshake.
//!
//! The harness duplicates the small pieces of the production server config the
//! client can reach (`server_tls_config` + the production transport presets);
//! it does not import `tests.rs` (owned separately) and does not need the
//! server binary.
use super::*;
use myquic2::mqp::r2;
use myquic2::mqp::wire::Wire;

/// Shared secret the fake server token-reader expects.
const TOKEN: &str = "0rtt-loopback-token";
/// Server→client delay used to make first-flight observations deterministic
/// (see the module docs). 250 ms is far above any scheduler jitter on a
/// loopback pair and far below the tests' multi-second waits.
const PROXY_DELAY: Duration = Duration::from_millis(250);
/// How long a connection is kept alive after a handshake so its
/// `NewSessionTicket` arrives (this build delivers the post-handshake 1-RTT
/// CRYPTO about one loss-detection timeout after the handshake, not in the
/// handshake flight). Only ticket-minting helper connections pay it.
const TICKET_ARRIVAL_WAIT: Duration = Duration::from_millis(600);

/// Serializes the 0-RTT tests: they share the process-wide
/// [`zero_rtt_counters`] and bind real sockets, and the counter deltas they
/// assert are only meaningful without a sibling test dialing concurrently.
static ZERO_RTT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn zero_rtt_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    ZERO_RTT_TEST_LOCK.lock().await
}

/// A full read of one accepted connection as observed by the fake server.
#[derive(Default)]
struct EarlyObs {
    /// Bytes of the first complete uni stream (the auth token), if any.
    token: std::sync::Mutex<Option<Vec<u8>>>,
    token_reads: std::sync::atomic::AtomicU64,
    /// Complete uni streams read while the server still considered the
    /// handshake in flight.
    token_before_handshake: std::sync::atomic::AtomicU64,
    /// rev2 `HELLO` datagrams received before the handshake settled.
    hello_before_handshake: std::sync::atomic::AtomicU64,
    /// TCP headers received on bidi streams before the handshake settled, and
    /// every bidi payload in arrival order.
    bi_before_handshake: std::sync::atomic::AtomicU64,
    bi_payloads: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Non-`HELLO` (application) datagrams received before the handshake
    /// settled, plus every application datagram in arrival order.
    payload_before_handshake: std::sync::atomic::AtomicU64,
    payloads: std::sync::Mutex<Vec<Vec<u8>>>,
    /// The server's `ZeroRttAccepted` future resolved (handshake settled).
    ///
    /// The *value* is meaningless on the server (quinn docs): `accepted_0rtt`
    /// is only tracked on the client side. The proof that the server kept the
    /// early data is the early token/datagram observations themselves —
    /// discarded early data is never delivered to the application.
    handshake_done: std::sync::atomic::AtomicBool,
}

impl EarlyObs {
    fn token(&self) -> Option<Vec<u8>> {
        self.token.lock().unwrap().clone()
    }

    fn early_hello(&self) -> u64 {
        self.hello_before_handshake
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn early_payloads(&self) -> u64 {
        self.payload_before_handshake
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn early_bi(&self) -> u64 {
        self.bi_before_handshake
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn saw_bi(&self, want: &[u8]) -> bool {
        self.bi_payloads
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.as_slice() == want)
    }

    fn early_tokens(&self) -> u64 {
        self.token_before_handshake
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn handshake_done(&self) -> bool {
        self.handshake_done
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn saw_payload(&self, want: &[u8]) -> bool {
        self.payloads
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.as_slice() == want)
    }
}

/// Waits until the server's token reader records `want`.
async fn wait_for_token(obs: &EarlyObs, want: &[u8], timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if obs.token().as_deref() == Some(want) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    obs.token().as_deref() == Some(want)
}

/// Dial `addr` until the client actually holds a resumption ticket, returning
/// the 0-RTT dial's connection and phase state.
///
/// A dial without a ticket takes the full-handshake path (`ZeroRttState::NONE`);
/// that handshake mints fresh tickets, which the same server config accepts on
/// the retry. The connection is kept alive for [`TICKET_ARRIVAL_WAIT`] before
/// being discarded: closing earlier would discard the still-in-flight
/// post-handshake ticket CRYPTO unread.
async fn dial_until_resumed(
    client_ep: &quinn::Endpoint,
    ccfg: &quinn::ClientConfig,
    addr: SocketAddr,
    attempts: usize,
) -> (quinn::Connection, Arc<ZeroRttState>) {
    for _ in 0..attempts {
        let state = ZeroRttState::new();
        let conn = dial_once(client_ep, ccfg, addr, "test.com", TOKEN, &state)
            .await
            .expect("dial must succeed");
        if state.phase() == ZeroRttState::PENDING {
            return (conn, state);
        }
        tokio::time::sleep(TICKET_ARRIVAL_WAIT).await;
        conn.close(0u32.into(), b"no ticket yet");
    }
    panic!("no resumption ticket within {attempts} dials");
}

/// Waits until `want` appears among the observed application datagrams.
async fn wait_for_payload(obs: &EarlyObs, want: &[u8], timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if obs.saw_payload(want) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    obs.saw_payload(want)
}

/// A loopback UDP relay that delays **only** server→client datagrams.
///
/// CLIENT→SERVER is forwarded immediately, so the client's 0-RTT first flight
/// reaches the real server while its handshake still cannot complete; the reply
/// direction is held for `delay`.
async fn spawn_delay_proxy(
    server: SocketAddr,
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = sock.local_addr().unwrap();
    // The test drives one client endpoint; remember the one peer the QUIC
    // client dials from so the reply direction knows where to send.
    let client_addr: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));
    let handle = {
        let sock = sock.clone();
        let client_addr = client_addr.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                if from == server {
                    let Some(to) = *client_addr.lock().unwrap() else {
                        continue;
                    };
                    let payload = buf[..n].to_vec();
                    let out = sock.clone();
                    // One task per delayed datagram: a serialized sleep would
                    // stack the delay per packet, and QUIC tolerates the
                    // arbitrary reordering a handful of tasks can produce.
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = out.send_to(&payload, to).await;
                    });
                } else {
                    *client_addr.lock().unwrap() = Some(from);
                    let _ = sock.send_to(&buf[..n], server).await;
                }
            }
        })
    };
    (proxy_addr, handle)
}

/// A fake server endpoint with production TLS/transport settings, plus the two
/// per-connection observation tasks.
fn spawn_server(
    server_cfg: quinn::ServerConfig,
    obs: Arc<EarlyObs>,
) -> (quinn::Endpoint, tokio::task::JoinHandle<()>) {
    let ep = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let accept_ep = ep.clone();
    let join = tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let obs = obs.clone();
            tokio::spawn(async move {
                let connecting = match incoming.accept() {
                    Ok(c) => c,
                    Err(_) => return,
                };
                // Incoming conversion always succeeds (quinn docs); the fallback
                // keeps the harness honest if that ever changes.
                let (conn, accepted_fut) = match connecting.into_0rtt() {
                    Ok((c, fut)) => (c, Some(fut)),
                    Err(connecting) => match connecting.await {
                        Ok(c) => (c, None),
                        Err(_) => return,
                    },
                };
                match accepted_fut {
                    Some(accepted_fut) => {
                        let obs = obs.clone();
                        tokio::spawn(async move {
                            let _accepted = accepted_fut.await;
                            obs.handshake_done
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                        });
                    }
                    None => {
                        obs.handshake_done
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let token_conn = conn.clone();
                let token_obs = obs.clone();
                tokio::spawn(async move {
                    // Tolerate reset/discarded early streams exactly like the
                    // production server's authenticate loop.
                    loop {
                        let mut uni = match tokio::time::timeout(
                            Duration::from_secs(5),
                            token_conn.accept_uni(),
                        )
                        .await
                        {
                            Ok(Ok(u)) => u,
                            _ => return,
                        };
                        let read = tokio::time::timeout(
                            Duration::from_secs(5),
                            uni.read_to_end(AUTH_TOKEN_MAX_BYTES),
                        )
                        .await;
                        let Ok(Ok(bytes)) = read else { continue };
                        token_obs
                            .token_reads
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if !token_obs.handshake_done() {
                            token_obs
                                .token_before_handshake
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        *token_obs.token.lock().unwrap() = Some(bytes.to_vec());
                        return;
                    }
                });
                let bi_conn = conn.clone();
                let bi_obs = obs.clone();
                tokio::spawn(async move {
                    // One bidi stream per proxied TCP flow: the first bytes are
                    // the MQP target header. Record whether it arrived in the
                    // first flight.
                    while let Ok((mut send, mut recv)) = bi_conn.accept_bi().await {
                        let early = !bi_obs.handshake_done();
                        let mut buf = [0u8; 64];
                        if let Ok(Some(n)) = recv.read(&mut buf).await {
                            if early {
                                bi_obs
                                    .bi_before_handshake
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            bi_obs.bi_payloads.lock().unwrap().push(buf[..n].to_vec());
                        }
                        let _ = send.finish();
                        send.stopped().await.ok();
                    }
                });
                let datagram_conn = conn.clone();
                let datagram_obs = obs;
                tokio::spawn(async move {
                    let hello = r2::encode_ctl(&r2::Ctl::Hello {
                        wire_ver: r2::R2_WIRE_VER,
                        flags: 0,
                    });
                    loop {
                        let d = match tokio::time::timeout(
                            Duration::from_secs(5),
                            datagram_conn.read_datagram(),
                        )
                        .await
                        {
                            Ok(Ok(d)) => d,
                            _ => return,
                        };
                        let early = !datagram_obs.handshake_done();
                        if d.as_ref() == hello.as_ref() {
                            if early {
                                datagram_obs
                                    .hello_before_handshake
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        } else {
                            if early {
                                datagram_obs
                                    .payload_before_handshake
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            datagram_obs.payloads.lock().unwrap().push(d.to_vec());
                        }
                    }
                });
                // Keep the connection (and its reader tasks) alive until the
                // client closes: hold it in this task.
                conn.closed().await;
            });
        }
    });
    (ep, join)
}

/// A self-signed cert usable for several independent server configs (each with
/// its own TLS session store) and the matching client config.
fn test_cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap()
}

/// Production-shaped server QUIC config for `cert` and an explicit ALPN label.
///
/// The default label is the shared `h3` masquerade for both wire revisions, so
/// the label alone is not a revision gate; a test that wants a TLS-level gate
/// must pin distinct labels on the two endpoints.
fn server_quinn_cfg_with_alpn(
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
    alpn: &[u8],
) -> quinn::ServerConfig {
    let tls = server_tls_config(
        cert.cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        alpn,
    )
    .unwrap();
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    // The server-side preset: advertises the pre-auth stream credit a resumed
    // client needs to open 0-RTT TCP streams.
    scfg.transport_config(build_transport(Congestion::Bbr, 5));
    scfg
}

/// Server config using the revision's default ALPN label (the shared `h3`
/// masquerade for both revisions).
fn server_quinn_cfg(cert: &rcgen::CertifiedKey<rcgen::KeyPair>, wire: Wire) -> quinn::ServerConfig {
    server_quinn_cfg_with_alpn(cert, wire.alpn())
}

/// Production-shaped client QUIC config pinned to `cert` and an explicit ALPN.
fn client_quinn_cfg_with_alpn(
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
    alpn: &[u8],
) -> quinn::ClientConfig {
    let tls = client_tls_config(cert.cert.der().clone(), alpn).unwrap();
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
    ccfg.transport_config(build_client_transport_tuned(
        Congestion::Bbr,
        5,
        TransportTuning::default(),
    ));
    ccfg
}

/// Client config using the revision's default ALPN label.
fn client_quinn_cfg(cert: &rcgen::CertifiedKey<rcgen::KeyPair>, wire: Wire) -> quinn::ClientConfig {
    client_quinn_cfg_with_alpn(cert, wire.alpn())
}

/// Waits until the dial's handshake phase is known (accepted or rejected).
async fn wait_settled(state: &ZeroRttState, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while state.is_pending() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// The core 0-RTT promise: a resumed dial returns a *published* connection
/// before the handshake completes, and the token + `HELLO` + the first UDP
/// payload are all received by the server while it is still handshaking.
#[tokio::test]
async fn resumed_dial_sends_token_hello_and_udp_in_first_flight() {
    let _guard = zero_rtt_test_guard().await;
    let counted_before = zero_rtt_counters();
    let cert = test_cert();
    // One server TLS config, so the tickets minted by the first endpoint's
    // handshake are resumable on the second (the ticket state lives in the
    // shared rustls session store).
    let scfg = server_quinn_cfg(&cert, Wire::Rev2);
    let ccfg = client_quinn_cfg(&cert, Wire::Rev2);

    let obs_first = Arc::new(EarlyObs::default());
    let (ep_first, join_first) = spawn_server(scfg.clone(), obs_first.clone());
    let obs_resumed = Arc::new(EarlyObs::default());
    let (ep_resumed, join_resumed) = spawn_server(scfg, obs_resumed.clone());

    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(ccfg.clone());

    // Dial 1: no ticket yet, so this is the awaited full handshake and its
    // 1-RTT token. It mints the resumption tickets dial 2 uses.
    let state_first = ZeroRttState::new();
    let conn_first = dial_once(
        &client_ep,
        &ccfg,
        ep_first.local_addr().unwrap(),
        "test.com",
        TOKEN,
        &state_first,
    )
    .await
    .expect("the first (full-handshake) dial must succeed");
    assert_eq!(
        state_first.phase(),
        ZeroRttState::NONE,
        "a first dial has no ticket, so it must take the awaited full-handshake path"
    );
    assert!(
        wait_for_token(&obs_first, TOKEN.as_bytes(), Duration::from_secs(3)).await,
        "the 1-RTT token must reach the server"
    );
    // Dial 2: resumed. `dial_once` must hand the connection back before the
    // handshake completes (the server's flight is delayed by PROXY_DELAY, so
    // completion is impossible within the dial). Retried until the ticket from
    // dial 1 has actually landed in the client's store.
    let (proxy_addr, proxy) =
        spawn_delay_proxy(ep_resumed.local_addr().unwrap(), PROXY_DELAY).await;
    let (conn_resumed, state_resumed) = dial_until_resumed(&client_ep, &ccfg, proxy_addr, 8).await;
    assert!(
        state_resumed.token_early(),
        "the auth token must be written in the early-data window"
    );

    // First flight, on the just-published connection: the rev2 HELLO (the
    // exact frame the connection loop sends) and one application UDP payload.
    conn_resumed
        .send_datagram(r2::encode_ctl(&r2::Ctl::Hello {
            wire_ver: r2::R2_WIRE_VER,
            flags: 0,
        }))
        .expect("HELLO datagram on the 0.5-RTT connection");
    conn_resumed
        .send_datagram(Bytes::from_static(b"first-flight-udp"))
        .expect("application UDP payload on the 0.5-RTT connection");
    // …and the SOCKS/forward TCP open path: a bidi stream plus the target
    // header, still before the handshake settles.
    let (mut early_send, early_recv) = open_bi_and_write_header(
        &conn_resumed,
        &state_resumed,
        b"\x04first-flight-tcp-header",
        0,
        Duration::from_secs(5),
    )
    .await
    .expect("a first-flight TCP header open must succeed on the published connection");
    assert!(
        early_recv.is_0rtt(),
        "the TCP header stream must be a 0-RTT stream (first flight)"
    );
    let _ = early_send.finish();

    assert!(
        wait_settled(&state_resumed, Duration::from_secs(5)).await,
        "the handshake must settle"
    );
    assert!(
        state_resumed.is_accepted(),
        "the peer must keep the early data (same server session store)"
    );
    // The server's own handshake completion settles a network round trip behind
    // the client's; the early observations below were made before it either way
    // (the reply direction is delayed by PROXY_DELAY), so wait for it to prove
    // the connection is fully established, not just published.
    let server_settle = tokio::time::Instant::now() + Duration::from_secs(3);
    while !obs_resumed.handshake_done() && tokio::time::Instant::now() < server_settle {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        obs_resumed.handshake_done(),
        "the fake server's handshake must complete after the first flight"
    );

    // Everything the server saw on the first flight, before its handshake
    // settled (the 250 ms reply delay makes this deterministic).
    assert_eq!(
        obs_resumed.early_tokens(),
        1,
        "exactly one complete auth token must arrive before the handshake settles \
         (a re-send would mean the early token was not delivered)"
    );
    assert_eq!(
        obs_resumed.token().as_deref(),
        Some(TOKEN.as_bytes()),
        "the token must arrive on the early uni stream"
    );
    assert!(
        obs_resumed.early_hello() >= 1,
        "the rev2 HELLO datagram must be in the first flight"
    );
    assert!(
        obs_resumed.early_payloads() >= 1,
        "the application UDP payload must be in the first flight"
    );
    assert!(
        obs_resumed.early_bi() >= 1,
        "the TCP header stream must arrive before the handshake settles"
    );
    assert!(
        obs_resumed.saw_bi(b"\x04first-flight-tcp-header"),
        "the TCP target header bytes must be received by the server"
    );
    assert_eq!(
        obs_resumed
            .token_reads
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an accepted early token must not be re-sent"
    );
    let counted_after = zero_rtt_counters();
    assert!(
        counted_after.0 > counted_before.0,
        "the acceptance must be counted: {counted_before:?} -> {counted_after:?}"
    );

    conn_first.close(0u32.into(), b"done");
    conn_resumed.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");
    proxy.abort();
    join_first.abort();
    join_resumed.abort();
}

/// A resumption the peer rejects must be repaired without losing the
/// connection: the monitor re-sends the token on a 1-RTT uni stream, the
/// connection stays usable, and post-handshake TCP stream opens land on 1-RTT
/// streams (no silently discarded header).
#[tokio::test]
async fn rejected_early_data_resends_the_token_1rtt() {
    let _guard = zero_rtt_test_guard().await;
    let counted_before = zero_rtt_counters();
    let cert = test_cert();
    // Two *independent* server TLS configs (separate session stores) sharing
    // one cert: the ticket minted by the first endpoint is unknown to the
    // second, so the second rejects the client's resumption (a server restart
    // in miniature) while still accepting the connection.
    let scfg_accepting = server_quinn_cfg(&cert, Wire::Rev2);
    let scfg_rejecting = server_quinn_cfg(&cert, Wire::Rev2);
    let ccfg = client_quinn_cfg(&cert, Wire::Rev2);

    let obs_first = Arc::new(EarlyObs::default());
    let (ep_first, join_first) = spawn_server(scfg_accepting, obs_first);
    let obs_rejecting = Arc::new(EarlyObs::default());
    let (ep_rejecting, join_rejecting) = spawn_server(scfg_rejecting, obs_rejecting.clone());

    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(ccfg.clone());

    // Mint a ticket on the accepting endpoint.
    let mint_state = ZeroRttState::new();
    let conn_mint = dial_once(
        &client_ep,
        &ccfg,
        ep_first.local_addr().unwrap(),
        "test.com",
        TOKEN,
        &mint_state,
    )
    .await
    .expect("the ticket-minting dial must succeed");
    assert_eq!(
        mint_state.phase(),
        ZeroRttState::NONE,
        "the very first dial has no ticket and must take the awaited path"
    );

    // Prove a ticket for the *accepting* endpoint is in the client store before
    // touching the rejecting one: a full handshake against the rejecting
    // endpoint would make it know a ticket (its session store is otherwise
    // empty), which is exactly the state the rejection below needs. A resumed
    // dial is the proof, and its handshake mints fresh accepting-endpoint
    // tickets; keep it alive until those have arrived.
    let (conn_probe, state_probe) =
        dial_until_resumed(&client_ep, &ccfg, ep_first.local_addr().unwrap(), 8).await;
    assert!(
        !state_probe.is_rejected(),
        "a dial to the ticket's own endpoint must not be rejected"
    );
    tokio::time::sleep(TICKET_ARRIVAL_WAIT).await;
    conn_probe.close(0u32.into(), b"probe done");

    // Resume against the rejecting endpoint through the reply-delay proxy: the
    // dial must come back while the handshake is pending, so the early token is
    // written into data the peer will discard.
    let (proxy_addr, proxy) =
        spawn_delay_proxy(ep_rejecting.local_addr().unwrap(), PROXY_DELAY).await;
    let state = ZeroRttState::new();
    let conn = dial_once(&client_ep, &ccfg, proxy_addr, "test.com", TOKEN, &state)
        .await
        .expect("a rejected 0-RTT resumption must still complete the connection");
    assert_eq!(
        state.phase(),
        ZeroRttState::PENDING,
        "the dial must not wait for the handshake"
    );
    assert!(
        state.token_early(),
        "the token must have been written in the early-data window"
    );

    // Same open path the SOCKS/forward code uses, on the still-pending
    // connection: the header rides a 0-RTT stream.
    let (mut early_send, early_recv) = open_bi_and_write_header(
        &conn,
        &state,
        b"\x04first-flight-header",
        0,
        Duration::from_secs(5),
    )
    .await
    .expect("a first-flight TCP header open must succeed");
    assert!(
        early_recv.is_0rtt(),
        "the header stream must be a 0-RTT stream (first flight) on a resumed dial"
    );
    let _ = early_send.finish();

    assert!(
        wait_settled(&state, Duration::from_secs(5)).await,
        "the handshake must settle"
    );
    assert_eq!(
        state.phase(),
        ZeroRttState::REJECTED,
        "a different session store must reject the ticket's early data"
    );

    // The monitor's 1-RTT re-send is what keeps the connection authenticated.
    let counted_after = zero_rtt_counters();
    assert!(
        counted_after.1 > counted_before.1,
        "the rejection must be counted: {counted_before:?} -> {counted_after:?}"
    );
    assert!(
        counted_after.2 > counted_before.2,
        "the monitor must re-send the token on a 1-RTT stream: \
         {counted_before:?} -> {counted_after:?}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while obs_rejecting.token().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        obs_rejecting.token().as_deref(),
        Some(TOKEN.as_bytes()),
        "the re-sent token must reach the server after the handshake"
    );
    assert_eq!(
        obs_rejecting.early_tokens(),
        0,
        "the early token itself must have been discarded by the rejecting peer"
    );

    // And a post-settlement TCP open lands on a 1-RTT stream, so the header can
    // no longer be discarded under the application's feet.
    let (mut send_1rtt, recv_1rtt) = open_bi_and_write_header(
        &conn,
        &state,
        b"\x04post-reject-header",
        0,
        Duration::from_secs(5),
    )
    .await
    .expect("a post-rejection TCP header open must succeed");
    assert!(!recv_1rtt.is_0rtt(), "post-settlement streams are 1-RTT");
    let _ = send_1rtt.finish();

    // The connection still carries application datagrams.
    conn.send_datagram(Bytes::from_static(b"post-reject-udp"))
        .expect("post-rejection datagram");
    assert!(
        wait_for_payload(&obs_rejecting, b"post-reject-udp", Duration::from_secs(3)).await,
        "the connection must still forward payloads after the rejection repair"
    );

    conn_mint.close(0u32.into(), b"done");
    conn.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");
    proxy.abort();
    join_first.abort();
    join_rejecting.abort();
}

/// Distinct ALPN labels still give a TLS-level fail-fast gate.
///
/// Both wire revisions default to the shared `h3` masquerade, so the label is
/// not a revision gate by construction. An operator who wants handshake-level
/// skew detection pins distinct labels across revisions (for example
/// `myquic2/r3` for rev3 and `h3` for rev2); this test proves that mechanism,
/// in both label directions, and that no auth token is ever read from the
/// rejected peer.
#[tokio::test]
async fn distinct_alpn_labels_fail_at_the_tls_gate() {
    let cert = test_cert();
    for (server_alpn, client_alpn) in [
        (b"h3".as_slice(), b"myquic2/r3".as_slice()),
        (b"myquic2/r3".as_slice(), b"h3".as_slice()),
    ] {
        let obs = Arc::new(EarlyObs::default());
        let (server_ep, join) =
            spawn_server(server_quinn_cfg_with_alpn(&cert, server_alpn), obs.clone());
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let ccfg = client_quinn_cfg_with_alpn(&cert, client_alpn);
        client_ep.set_default_client_config(ccfg.clone());
        let err = client_ep
            .connect_with(ccfg, server_ep.local_addr().unwrap(), "test.com")
            .unwrap()
            .await
            .expect_err("a TLS handshake across distinct ALPN labels must fail");
        // rustls answers the mismatched ClientHello with the TLS
        // no_application_protocol alert ("peer doesn't support any known
        // protocol"), i.e. the label gate fired at the handshake and no MQP
        // frame could ever be exchanged.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("known protocol") || msg.contains("no_application_protocol"),
            "expected the ALPN label gate to reject {server_alpn:?}/{client_alpn:?}, got {msg}"
        );
        // The fake server never sees an auth token on a rejected peer: the TLS
        // layer refused it before any application data.
        assert_eq!(
            obs.token_reads.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no auth token may be read from a peer rejected at the TLS gate"
        );
        client_ep.close(0u32.into(), b"alpn mismatch");
        join.abort();
    }
}
