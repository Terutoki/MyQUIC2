//! Standalone reproduction of the "stalled local consumer" mechanism behind the
//! gaps-death, with the pump's stall telemetry printed for each mode.
//!
//! Run with: `cargo run --release --example pump_probe [parked|healthy|both]`
//!
//! Why this exists next to `tests/pump_stall.rs`: a test binary swallows
//! anything a spawned task prints, so when the hypothesis needs to be checked
//! against a real transfer this is the harness to reach for. It drives the real
//! [`copy_tcp_quic_idle`] pump over a real quinn connection to a real local
//! socket, exactly like the shipped client does.
//!
//! `parked`  — the local consumer does not read for 600 ms, which is what a
//!             browser writing to disk (or a paused download) does. The pump
//!             parks in `write_all`, stops draining QUIC, and the reported
//!             `s2c_read_gap_ms` shows it.
//! `healthy` — the consumer drains promptly. No significant stall is reported,
//!             which is what keeps the new WARN free of false positives.
//!
//! Expected: `parked` reports a read gap close to the park duration while
//! `healthy` reports a few milliseconds, and both deliver every byte intact.

use std::sync::Arc;
use std::time::Duration;

use myquic2::{build_transport, client_tls_config, copy_tcp_quic_idle, server_tls_config};
use tokio::io::AsyncReadExt;

/// Must exceed local kernel socket buffering for a parked consumer to block the
/// pump; at 512 KiB the buffers absorb the whole response and no stall shows.
const PAYLOAD: usize = 4 * 1024 * 1024;
const PARK: Duration = Duration::from_millis(600);

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

struct Endpoints {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
    addr: std::net::SocketAddr,
    _rt: Arc<quinn::TokioRuntime>,
}

fn endpoints() -> Endpoints {
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
    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(scfg),
        std::net::UdpSocket::bind("127.0.0.1:0").expect("server udp"),
        rt.clone(),
    )
    .expect("server endpoint");
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std::net::UdpSocket::bind("127.0.0.1:0").expect("client udp"),
        rt.clone(),
    )
    .expect("client endpoint");
    client.set_default_client_config(ccfg);
    let addr = server.local_addr().expect("addr");
    Endpoints {
        server,
        client,
        addr,
        _rt: rt,
    }
}

/// One full transfer. `park` is how long the local consumer waits before it
/// starts reading, i.e. how long the pump is blocked by it.
async fn run(mode: &str, park: Option<Duration>) -> bool {
    let h = endpoints();
    let payload = pattern(PAYLOAD);
    let srv_payload = payload.clone();
    let srv = {
        let server = h.server.clone();
        tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.await.expect("handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            send.write_all(&srv_payload).await.expect("server write");
            let _ = send.finish();
            // Consume the request side so the client's upstream direction ends
            // cleanly rather than being stop-sent.
            let _ = recv.read_to_end(1024).await;
            drop(recv);
            let _ = conn.closed().await;
        })
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let local = listener.local_addr().expect("local addr");
    let mut consumer = tokio::net::TcpStream::connect(local)
        .await
        .expect("connect");
    let (producer, _) = listener.accept().await.expect("accept");

    let consumer_task = tokio::spawn(async move {
        if let Some(d) = park {
            tokio::time::sleep(d).await;
        }
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < PAYLOAD {
            match consumer.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        got
    });

    let conn = h
        .client
        .connect(h.addr, "localhost")
        .expect("connect")
        .await
        .expect("connected");
    let (mut send, recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"k").await.expect("kick");
    let _ = send.finish();

    let (res, diag) = copy_tcp_quic_idle(producer, send, recv, Duration::from_secs(20)).await;
    conn.close(0u32.into(), b"done");
    let got = consumer_task.await.expect("consumer join");
    srv.abort();

    let ok = match res {
        Ok((up, down)) => {
            println!("[{mode}] ok: {up}B up / {down}B down, consumer got {got}B");
            down == PAYLOAD as u64 && got == PAYLOAD
        }
        Err(e) => {
            println!("[{mode}] pump error: {e:#} (consumer got {got}B)");
            false
        }
    };
    println!(
        "[{mode}] stalls: s2c read {}ms@{}ms s2c write {}ms@{}ms spool {}B credit {}ms x{} | c2s read {}ms@{}ms c2s write {}ms@{}ms",
        diag.s2c_read_gap_ms,
        diag.s2c_read_gap_at_ms,
        diag.s2c_write_stall_ms,
        diag.s2c_write_stall_at_ms,
        diag.s2c_spool_peak,
        diag.s2c_credit_wait_ms,
        diag.s2c_credit_waits,
        diag.c2s_read_gap_ms,
        diag.c2s_read_gap_at_ms,
        diag.c2s_write_stall_ms,
        diag.c2s_write_stall_at_ms,
    );
    println!(
        "[{mode}] significant={} (threshold 250ms) — would log: {}",
        diag.is_significant(),
        diag.summary()
    );
    ok
}

#[tokio::main]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "both".into());
    let mut all_ok = true;
    if mode == "parked" || mode == "both" {
        println!("--- parked consumer (browser stalled on disk) ---");
        all_ok &= run("parked", Some(PARK)).await;
    }
    if mode == "healthy" || mode == "both" {
        println!("--- healthy consumer ---");
        all_ok &= run("healthy", None).await;
    }
    if !all_ok {
        eprintln!("FAILED: a transfer did not complete intact");
        std::process::exit(1);
    }
    println!("all transfers completed intact");
}
