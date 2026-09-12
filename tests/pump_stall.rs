//! Live (in-process) verification of the pump stall instrumentation added for
//! the "Chrome download truncated / too many gaps in stream buffer" hunt.
//!
//! Nothing here is simulated: a real quinn endpoint pair runs over loopback,
//! the real [`copy_tcp_quic_idle`] pump is driven against a real TCP socket
//! with a deliberately tiny kernel buffer, and the assertions are on the
//! telemetry that pump reports.
//!
//! What these tests establish:
//!   1. A local consumer that stops reading parks the pump in `write_all`, so
//!      the pump stops draining the QUIC stream. That is exactly the condition
//!      under which quinn's reassembly spans accumulate monotonically towards
//!      `MAX_CHUNKS` (1024) and eventually kill the whole connection with
//!      "too many gaps in stream buffer". `s2c_read_gap_ms` is the field
//!      evidence for it, and this test proves it is actually recorded.
//!   2. A healthy consumer never reports a significant stall, so the new WARN
//!      cannot become a false positive on ordinary transfers.
//!   3. Byte accounting and payload integrity are unaffected by the change.
//!
//! Every await is wrapped in a timeout, so a regression fails the test instead
//! of hanging CI.

use std::sync::Arc;
use std::time::Duration;

use myquic2::{build_transport, client_tls_config, copy_tcp_quic_idle, server_tls_config};
use tokio::io::AsyncReadExt;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the parked consumer stays parked. Must exceed the pump's
/// STALL_REPORT_MS (250 ms) with margin on a loaded machine.
const PARK_MS: u64 = 600;
/// Must exceed the local kernel socket buffering (a few hundred KiB on
/// macOS/Linux) so that a parked consumer actually parks the pump in
/// `write_all`. At 512 KiB the buffers absorb the whole response and no stall
/// is observable at all; at 4 MiB the stall is unmistakable.
const PAYLOAD: usize = 4 * 1024 * 1024;
/// Each test runs a 4 MiB transfer through a parked consumer; the pump's own
/// idle deadline is 20 s, so the transfer must finish well inside that.
const PUMP_IDLE: Duration = Duration::from_secs(20);

/// Deterministic payload so integrity can be checked byte-by-byte.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

struct Harness {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
    server_addr: std::net::SocketAddr,
    /// Kept alive so the endpoints stay valid for the whole test.
    _rt: Arc<quinn::TokioRuntime>,
}

fn harness() -> Harness {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key).expect("self-signed");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key der");

    let tls_server = server_tls_config(cert_der.clone(), key_der).expect("server tls");
    let tls_client = client_tls_config(cert_der).expect("client tls");

    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_server).expect("quic server tls"),
    ));
    scfg.transport_config(build_transport("bbr", 15));

    let mut ccfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).expect("quic client tls"),
    ));
    ccfg.transport_config(build_transport("bbr", 15));

    let rt = Arc::new(quinn::TokioRuntime);
    // `Endpoint::new` takes a plain std socket and performs the runtime wrap
    // itself (the binaries use `new_with_abstract_socket` only because they
    // need the dual-stack V6ONLY=0 socket).
    let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("server udp bind");
    let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("client udp bind");
    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(scfg),
        server_sock,
        rt.clone(),
    )
    .expect("server endpoint");
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        client_sock,
        rt.clone(),
    )
    .expect("client endpoint");
    client.set_default_client_config(ccfg);

    let server_addr = server.local_addr().expect("server addr");
    Harness {
        server,
        client,
        server_addr,
        _rt: rt,
    }
}

/// A plain local TCP pair. The pump writes into kernel buffers; a consumer
/// that parks for `PARK_MS` lets those buffers fill up, which is what parks the
/// pump in `write_all` and stops it draining QUIC.
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let consumer = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (producer, _) = listener.accept().await.expect("accept");
    (producer, consumer)
}

/// Server side: accept one connection, push `payload` down its first stream,
/// then hold the connection until the peer goes away.
fn serve_one_stream(h: &Harness, payload: Vec<u8>) -> tokio::task::JoinHandle<()> {
    let server = h.server.clone();
    tokio::spawn(async move {
        let Some(incoming) = server.accept().await else {
            return;
        };
        let Ok(conn) = incoming.await else { return };
        let Ok((mut send, recv)) = conn.accept_bi().await else {
            return;
        };
        if send.write_all(&payload).await.is_err() {
            return;
        }
        let _ = send.finish();
        // Read the request side to EOF, then drop it: the client's upstream
        // half only completes when the server closes its receive side, and a
        // dropped `RecvStream` (rather than a read-to-EOF) would STOP_SENDING
        // the upstream direction instead of ending it cleanly.
        let mut drain = recv;
        let _ = drain.read_to_end(1024).await;
        drop(drain);
        let _ = conn.closed().await;
    })
}

/// Client side: connect, open the stream, run the real pump over `tcp`.
///
/// `tcp` is **moved in and dropped** when the pump returns, which closes the
/// application socket; without that the upstream half never sees EOF and the
/// pump sits until its idle deadline. A real client closes its socket after the
/// response, so this mirrors production.
async fn pump_once(
    h: &Harness,
    tcp: tokio::net::TcpStream,
) -> (u64, u64, myquic2::CopyDiagnostics, Result<(), String>) {
    let conn = tokio::time::timeout(
        TEST_TIMEOUT,
        h.client
            .connect(h.server_addr, "localhost")
            .expect("connect"),
    )
    .await
    .expect("connect timeout")
    .expect("connected");
    let (mut send, recv) = tokio::time::timeout(TEST_TIMEOUT, conn.open_bi())
        .await
        .expect("open_bi timeout")
        .expect("open_bi");
    // The server only calls `accept_bi` once it sees the stream, so send one
    // byte (and FIN) to flush it open — a real client always sends its request.
    let kick = send.write_all(b"k").await;
    let _ = send.finish();
    assert!(kick.is_ok(), "stream kick failed: {kick:?}");
    let (pump, diag) = copy_tcp_quic_idle(tcp, send, recv, PUMP_IDLE).await;
    // Drop the connection so the server's `conn.closed()` resolves.
    conn.close(0u32.into(), b"done");
    match pump {
        Ok((up, down)) => (up, down, diag, Ok(())),
        Err(e) => (0, 0, diag, Err(format!("{e:#}"))),
    }
}

/// Drain the consumer side the way a browser does: optionally park (slow disk,
/// paused download), then read exactly the response body and close the socket.
///
/// Closing matters: the application's FIN is what lets the pump's upstream
/// direction finish, exactly as in production. A reset is not asserted here
/// because the pump deliberately RSTs on abnormal ends, which is the behaviour
/// under test.
async fn drain_consumer(
    mut consumer: tokio::net::TcpStream,
    park: Option<Duration>,
    expect: usize,
) -> Vec<u8> {
    if let Some(d) = park {
        tokio::time::sleep(d).await;
    }
    let mut got = Vec::with_capacity(expect);
    let mut buf = vec![0u8; 64 * 1024];
    while got.len() < expect {
        match consumer.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    // Dropping `consumer` closes the application socket (FIN upstream).
    got
}

/// The headline case: while the local consumer is parked, the pump stops
/// draining the QUIC stream. That is the mechanism behind the gaps-death.
#[tokio::test]
async fn parked_consumer_shows_up_as_an_s2c_read_gap() {
    let h = harness();
    let payload = pattern(PAYLOAD);
    let srv = serve_one_stream(&h, payload.clone());

    let (producer, consumer) = tcp_pair().await;
    let drain = tokio::spawn(drain_consumer(
        consumer,
        Some(Duration::from_millis(PARK_MS)),
        PAYLOAD,
    ));

    let (up, down, diag, res) = tokio::time::timeout(TEST_TIMEOUT, pump_once(&h, producer))
        .await
        .expect("pump timeout");
    let got = tokio::time::timeout(TEST_TIMEOUT, drain)
        .await
        .expect("drain timeout")
        .expect("drain join");
    srv.abort();

    assert!(
        res.is_ok(),
        "pump failed: {res:?} diag={diag:?} up={up} down={down} consumer_got={}",
        got.len()
    );
    // `up` only ever carries the stream kick; the consumer's FIN can reach the
    // pump before that write completes, so it is not asserted exactly.
    assert!(up <= 1, "unexpected upstream traffic: {up}B");
    assert_eq!(down, PAYLOAD as u64, "byte accounting lost data: {diag:?}");
    assert_eq!(got.len(), PAYLOAD, "consumer got a short read: {diag:?}");
    assert_eq!(got, payload, "payload corrupted in transit");

    // The parked consumer still stalls the TCP writer — that is the local
    // socket's backpressure and it is expected.
    assert!(
        diag.s2c_write_stall_ms >= PARK_MS - 150,
        "expected a write stall of at least ~{PARK_MS}ms, got {diag:?}"
    );
    // ...but the pump must have kept draining QUIC anyway. This is the whole
    // point of the decoupled reader: the local consumer can only stall the flow
    // as far as the spool budget, never far enough to let quinn's reassembly
    // spans pile up towards the 1024 cap that kills the connection.
    assert!(
        diag.s2c_spool_peak > 0,
        "the reader never ran ahead of TCP; decoupling is not in effect: {diag:?}"
    );
    assert!(
        diag.s2c_read_gap_ms < 250,
        "the QUIC stream went undrained while a consumer was merely slow: {diag:?}"
    );
    assert!(
        diag.s2c_credit_wait_ms >= PARK_MS - 150 && diag.s2c_credit_waits > 0,
        "the stall should have been absorbed as spool backpressure: {diag:?}"
    );
    // The stall belongs to the download direction, not to the upstream one,
    // which is what makes the field evidence unambiguous.
    assert!(
        diag.c2s_read_gap_ms < 250 && diag.c2s_write_stall_ms < 250,
        "upstream direction should not have stalled: {diag:?}"
    );
    assert!(
        diag.is_significant(),
        "the slow consumer must still be visible to the operator: {diag:?}"
    );
}

/// Control: a healthy consumer produces no significant stall, so the new WARN
/// cannot fire on ordinary transfers.
#[tokio::test]
async fn healthy_consumer_reports_no_significant_stall() {
    let h = harness();
    let payload = pattern(PAYLOAD);
    let srv = serve_one_stream(&h, payload.clone());

    let (producer, consumer) = tcp_pair().await;
    let drain = tokio::spawn(drain_consumer(consumer, None, PAYLOAD));

    let (up, down, diag, res) = tokio::time::timeout(TEST_TIMEOUT, pump_once(&h, producer))
        .await
        .expect("pump timeout");
    let got = tokio::time::timeout(TEST_TIMEOUT, drain)
        .await
        .expect("drain timeout")
        .expect("drain join");
    srv.abort();

    assert!(res.is_ok(), "pump failed: {res:?} diag={diag:?}");
    assert!(up <= 1, "unexpected upstream traffic: {up}B");
    assert_eq!(down, PAYLOAD as u64, "byte accounting lost data: {diag:?}");
    assert_eq!(got, payload, "payload corrupted in transit");
    assert!(
        !diag.is_significant(),
        "healthy transfer must not be reported as a stall: {diag:?}"
    );
}
