//! 0-RTT early-data tests for the server accept path, on real loopback quinn
//! endpoints.
//!
//! What is pinned here:
//!
//! 1. the **production accept loop** (`accept_loop`) authenticates a resumed
//!    client's 0-RTT token and starts `handle_conn` *before the handshake
//!    completes* — the ordering the accept path deliberately stopped serializing
//!    behind `ZeroRttAccepted`;
//! 2. `authenticate` tolerates the early-data failure shapes (reset/incomplete
//!    uni streams, extra streams) and authenticates the first complete matching
//!    token, while still failing closed on a complete wrong token.
//!
//! Determinism: the "before the handshake completes" ordering is made
//! deterministic by relaying the mock client's UDP through
//! [`spawn_delay_proxy`], which delays only the server→client direction. The
//! client's first flight (0-RTT token + HELLO) reaches the server immediately;
//! the server's handshake flight — and thus the client's Finished that settles
//! `ZeroRttAccepted` on the server — is held back by 250 ms, so every server-side
//! observation of the first flight provably precedes the handshake settling.
use super::*;
use myquic2::mqp::r2;
use myquic2::mqp::wire::Wire;

const TOKEN: &str = "0rtt-server-token";
const PROXY_DELAY: Duration = Duration::from_millis(250);
/// How long a connection is kept alive after a handshake so the server's
/// post-handshake `NewSessionTicket` CRYPTO frame arrives (this build delivers
/// it about one loss-detection timeout after the handshake rather than in the
/// handshake flight itself). Only the ticket-minting fallbacks pay it.
const TICKET_ARRIVAL_WAIT: Duration = Duration::from_millis(600);

/// Ordered observations recorded by the production accept path (see the
/// `#[cfg(test)]` probe calls in `main.rs`). Only these tests drive
/// `accept_loop`, and they serialize on [`ZERO_RTT_TEST_LOCK`], so the counters
/// describe one test's connections.
pub(crate) mod probe {
    use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

    pub(crate) static HANDSHAKE_SETTLED: AtomicU64 = AtomicU64::new(0);
    pub(crate) static AUTH_OK: AtomicU64 = AtomicU64::new(0);
    /// `authenticate` returned Ok while the handshake had not settled yet: the
    /// 0-RTT token was accepted pre-handshake.
    pub(crate) static AUTH_BEFORE_HANDSHAKE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static HANDLE_CONN_STARTED: AtomicU64 = AtomicU64::new(0);
    /// `handle_conn` started while the handshake had not settled yet: the server
    /// began forwarding before the handshake completed.
    pub(crate) static HANDLE_CONN_BEFORE_HANDSHAKE: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn reset() {
        HANDSHAKE_SETTLED.store(0, SeqCst);
        AUTH_OK.store(0, SeqCst);
        AUTH_BEFORE_HANDSHAKE.store(0, SeqCst);
        HANDLE_CONN_STARTED.store(0, SeqCst);
        HANDLE_CONN_BEFORE_HANDSHAKE.store(0, SeqCst);
    }

    pub(crate) fn handshake_settled() {
        HANDSHAKE_SETTLED.fetch_add(1, SeqCst);
    }

    pub(crate) fn authenticated() {
        AUTH_OK.fetch_add(1, SeqCst);
        if HANDSHAKE_SETTLED.load(SeqCst) == 0 {
            AUTH_BEFORE_HANDSHAKE.fetch_add(1, SeqCst);
        }
    }

    pub(crate) fn handle_conn_start() {
        HANDLE_CONN_STARTED.fetch_add(1, SeqCst);
        if HANDSHAKE_SETTLED.load(SeqCst) == 0 {
            HANDLE_CONN_BEFORE_HANDSHAKE.fetch_add(1, SeqCst);
        }
    }

    pub(crate) fn load(counter: &AtomicU64) -> u64 {
        counter.load(SeqCst)
    }
}

/// Serializes these tests: they drive the process-global accept probe counters
/// and assert on their exact values.
static ZERO_RTT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn zero_rtt_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    ZERO_RTT_TEST_LOCK.lock().await
}

/// A loopback UDP relay delaying **only** server→client datagrams (see the
/// module docs).
async fn spawn_delay_proxy(
    server: SocketAddr,
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = sock.local_addr().unwrap();
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

/// The production accept state for one test endpoint: a token-protected server
/// with the shipped admission shape and the restricted reply policy.
fn accept_state(token: &str) -> Arc<AcceptState> {
    Arc::new(AcceptState {
        conn_limit: Arc::new(tokio::sync::Semaphore::new(8)),
        pending_limit: Arc::new(tokio::sync::Semaphore::new(4)),
        pending_by_ip: PendingAddrSlots::new(),
        auth_token: Arc::new(token.as_bytes().to_vec()),
        auth_enabled: true,
        allow_private: false,
        reply_filter: ReplyFilter::Restricted,
        // These in-bin tests pin the rev2 codec; the rev3 data-plane matrix is
        // driven end to end by tests/rev3_e2e.rs.
        wire: Wire::Rev2,
        cap: 8,
    })
}

/// Production client config (resumption store + early data) pinned to `cert`
/// and an explicit ALPN label.
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

/// Client config using the revision's default ALPN label (the shared `h3`
/// masquerade for both revisions).
fn client_quinn_cfg(cert: &rcgen::CertifiedKey<rcgen::KeyPair>, wire: Wire) -> quinn::ClientConfig {
    client_quinn_cfg_with_alpn(cert, wire.alpn())
}

/// Production server QUIC config for `cert` and an explicit ALPN label.
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
    scfg.transport_config(build_transport(Congestion::Bbr, 5));
    scfg
}

/// Server config using the revision's default ALPN label.
fn server_quinn_cfg(cert: &rcgen::CertifiedKey<rcgen::KeyPair>, wire: Wire) -> quinn::ServerConfig {
    server_quinn_cfg_with_alpn(cert, wire.alpn())
}

/// Wait (bounded) for `want` to be reached by the probe counter `counter`.
async fn wait_probe(counter: &std::sync::atomic::AtomicU64, want: u64, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if probe::load(counter) >= want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    probe::load(counter) >= want
}

/// The server authenticates a resumed client's 0-RTT token and starts
/// `handle_conn` while the handshake is still in flight.
#[tokio::test]
async fn accept_loop_authenticates_and_starts_conn_before_handshake() {
    let _guard = zero_rtt_test_guard().await;
    probe::reset();
    let cert = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
    let scfg = server_quinn_cfg(&cert, Wire::Rev2);
    let ccfg = client_quinn_cfg(&cert, Wire::Rev2);

    let server_ep = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let accept_join = tokio::spawn(accept_loop(
        server_ep.clone(),
        accept_state(TOKEN),
        shutdown_rx,
    ));

    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(ccfg.clone());
    // Reply-delay proxy: the client's first flight reaches the server
    // immediately, the server's handshake flight (and the client Finished that
    // settles the server's `ZeroRttAccepted`) is held back by PROXY_DELAY.
    let (proxy_addr, proxy) = spawn_delay_proxy(server_addr, PROXY_DELAY).await;

    // A resumption ticket may trail the first full handshake by a loss-recovery
    // tick (the NewSessionTicket CRYPTO is emitted only after the server has
    // processed the client's Finished), so retry: a dial without a ticket is a
    // full handshake, which itself mints fresh tickets. Once a 0-RTT dial is
    // returned, reset the probes from the minting attempts and drive its first
    // flight — the assertions below then describe exactly this connection.
    let mut resumed = None;
    for _attempt in 0..8 {
        let connecting = client_ep
            .connect_with(ccfg.clone(), proxy_addr, "test.com")
            .unwrap();
        match connecting.into_0rtt() {
            Ok(pair) => {
                resumed = Some(pair);
                break;
            }
            Err(connecting) => {
                if let Ok(conn) = connecting.await {
                    // Authenticate this full handshake too: it is what mints
                    // the tickets the retry uses (and proves the 1-RTT token
                    // path on the production accept loop). Keep the connection
                    // alive for a loss-recovery tick: the NewSessionTicket is a
                    // post-handshake 1-RTT CRYPTO frame and this build delivers
                    // it ~1 PTO after the handshake, not in the same flight, so
                    // closing earlier would discard it unread.
                    let mut uni = conn.open_uni().await.expect("1-RTT token uni stream");
                    uni.write_all(TOKEN.as_bytes())
                        .await
                        .expect("1-RTT token write");
                    uni.finish().ok();
                    tokio::time::sleep(TICKET_ARRIVAL_WAIT).await;
                    conn.close(0u32.into(), b"no ticket yet");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let (conn, accepted_fut) =
        resumed.expect("a resumption ticket must be available within the retry budget");

    // The resumed connection's handshake cannot settle for PROXY_DELAY; wait for
    // the minting attempts' monitor events to drain, then observe this one from
    // a clean slate. This happens before the token is sent, so it cannot hide a
    // pre-handshake auth event of this connection.
    tokio::time::sleep(Duration::from_millis(20)).await;
    probe::reset();

    // First flight: the auth token on a 0-RTT uni stream plus the rev2 HELLO
    // datagram, exactly what the real client sends before it awaits anything.
    let mut uni = conn.open_uni().await.expect("0-RTT token uni stream");
    uni.write_all(TOKEN.as_bytes())
        .await
        .expect("0-RTT token write");
    uni.finish().ok();
    conn.send_datagram(r2::encode_ctl(&r2::Ctl::Hello {
        wire_ver: r2::R2_WIRE_VER,
        flags: 0,
    }))
    .expect("0-RTT HELLO datagram");

    assert!(
        wait_probe(&probe::AUTH_BEFORE_HANDSHAKE, 1, Duration::from_secs(3)).await,
        "the server must authenticate the 0-RTT token before the handshake settles"
    );
    assert!(
        wait_probe(
            &probe::HANDLE_CONN_BEFORE_HANDSHAKE,
            1,
            Duration::from_secs(3)
        )
        .await,
        "handle_conn must start before the handshake settles"
    );
    assert!(
        probe::load(&probe::HANDSHAKE_SETTLED) == 0,
        "no handshake of this connection may have settled before the pre-handshake \
         observations"
    );
    // The same connection still settles normally afterwards (the handshake is
    // not skipped, just no longer on the critical path).
    assert!(
        accepted_fut.await,
        "the resumed handshake must complete with the early data accepted"
    );

    conn.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");
    proxy.abort();
    accept_join.abort();
    server_ep.close(0u32.into(), b"done");
}

/// `authenticate` skips a reset (failed / discarded early) uni stream and
/// authenticates the complete token on the next one, i.e. the client's 1-RTT
/// re-send after a 0-RTT rejection.
#[tokio::test]
async fn authenticate_skips_reset_streams_and_accepts_the_resend() {
    let _guard = zero_rtt_test_guard().await;
    let cert = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
    let scfg = server_quinn_cfg(&cert, Wire::Rev2);
    let ccfg = client_quinn_cfg(&cert, Wire::Rev2);

    let server_ep = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        incoming.await.unwrap()
    });
    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let client_conn = client_ep
        .connect_with(ccfg, server_addr, "test.com")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    // Stream 1: a complete stream of garbage that the client then resets, the
    // shape of a discarded/reset early token write.
    let mut bad = client_conn.open_uni().await.unwrap();
    bad.write_all(b"not-the-token").await.unwrap();
    bad.reset(0u32.into()).ok();
    // Stream 2: the real token (the client's 1-RTT re-send).
    let mut good = client_conn.open_uni().await.unwrap();
    good.write_all(TOKEN.as_bytes()).await.unwrap();
    good.finish().ok();

    authenticate(
        &server_conn,
        TOKEN.as_bytes(),
        tokio::time::Instant::now() + AUTH_TIMEOUT,
    )
    .await
    .expect("a reset stream must not fail authentication when the token follows");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");
}

/// A complete wrong token still fails closed (and quickly): tolerating resets
/// must not turn a credential mismatch into a waiting game.
#[tokio::test]
async fn authenticate_rejects_a_complete_wrong_token() {
    let _guard = zero_rtt_test_guard().await;
    let cert = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
    let scfg = server_quinn_cfg(&cert, Wire::Rev2);
    let ccfg = client_quinn_cfg(&cert, Wire::Rev2);

    let server_ep = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        incoming.await.unwrap()
    });
    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let client_conn = client_ep
        .connect_with(ccfg, server_addr, "test.com")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    let mut wrong = client_conn.open_uni().await.unwrap();
    wrong.write_all(b"wrong-token").await.unwrap();
    wrong.finish().ok();

    let started = tokio::time::Instant::now();
    let err = authenticate(
        &server_conn,
        TOKEN.as_bytes(),
        tokio::time::Instant::now() + AUTH_TIMEOUT,
    )
    .await
    .expect_err("a complete wrong token must be rejected");
    assert!(
        err.to_string().contains("mismatch"),
        "the verdict must be a credential mismatch, got: {err:#}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a mismatch must fail fast, not wait out the auth deadline"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");
}

/// Distinct ALPN labels are rejected at the TLS gate before authentication.
///
/// Both wire revisions default to the shared `h3` masquerade, so the label is
/// not a revision gate unless the operator pins distinct labels. This proves
/// that optional mechanism (both label directions) and that the server never
/// verifies a token or starts `handle_conn` for a peer rejected at the TLS gate.
#[tokio::test]
async fn distinct_alpn_labels_are_rejected_before_auth() {
    let _guard = zero_rtt_test_guard().await;
    for (server_alpn, client_alpn) in [
        (b"h3".as_slice(), b"myquic2/r3".as_slice()),
        (b"myquic2/r3".as_slice(), b"h3".as_slice()),
    ] {
        probe::reset();
        let cert = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
        let server_ep = quinn::Endpoint::server(
            server_quinn_cfg_with_alpn(&cert, server_alpn),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let accept_join = tokio::spawn(accept_loop(
            server_ep.clone(),
            accept_state(TOKEN),
            shutdown_rx,
        ));
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let ccfg = client_quinn_cfg_with_alpn(&cert, client_alpn);
        client_ep.set_default_client_config(ccfg.clone());
        let err = client_ep
            .connect_with(ccfg, server_addr, "test.com")
            .unwrap()
            .await
            .expect_err("a TLS handshake across distinct ALPN labels must fail");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("known protocol") || msg.contains("no_application_protocol"),
            "expected the ALPN label gate to reject {server_alpn:?}/{client_alpn:?}, got {msg}"
        );
        // Give the server-side task time to run its accept/auth path (the peer
        // is already gone, so `authenticate` fails out immediately). Nothing on
        // this connection may reach the data plane: no token verified, no
        // `handle_conn`, therefore no frame parsed.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            probe::load(&probe::AUTH_OK),
            0,
            "a peer rejected at the TLS gate must never authenticate"
        );
        assert_eq!(
            probe::load(&probe::HANDLE_CONN_STARTED),
            0,
            "handle_conn must never see a peer rejected at the TLS gate"
        );
        client_ep.close(0u32.into(), b"alpn mismatch");
        accept_join.abort();
        server_ep.close(0u32.into(), b"alpn mismatch");
    }
}
