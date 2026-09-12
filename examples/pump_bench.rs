//! Loopback throughput of the real QUIC→TCP pump, used to measure the cost of
//! the reader/writer split in `copy_tcp_quic_inner`.
//!
//! Run with: `cargo run --release --example pump_bench [mib] [reps]`
//!
//! The consumer always drains as fast as it can, so this measures the pump's
//! own hot path (QUIC read → spool → TCP write) rather than a stalled one. The
//! number to compare across revisions is the median MB/s.
//!
//! Measured on this machine (aarch64 macOS, loopback, 256 MiB x 4 reps, six
//! alternating rounds against the pre-split revision): baseline median
//! 249-259 MB/s, decoupled median 248-256 MB/s — i.e. the reader/writer split
//! and its 32 KiB spool memcpy are below the run-to-run noise of this harness.
//! The spool also stays shallow when the consumer keeps up (a few tens of KiB
//! peak), so the copy is not on the steady-state critical path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use myquic2::{build_transport, client_tls_config, copy_tcp_quic_idle, server_tls_config};
use tokio::io::AsyncReadExt;

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint, std::net::SocketAddr) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let tls_server = server_tls_config(cert_der.clone(), key_der).unwrap();
    let tls_client = client_tls_config(cert_der).unwrap();
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_server).unwrap(),
    ));
    scfg.transport_config(build_transport("bbr", 15));
    let mut ccfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap(),
    ));
    ccfg.transport_config(build_transport("bbr", 15));
    let rt = Arc::new(quinn::TokioRuntime);
    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(scfg),
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        rt.clone(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        rt.clone(),
    )
    .unwrap();
    client.set_default_client_config(ccfg);
    let addr = server.local_addr().unwrap();
    (server, client, addr)
}

/// One transfer of `mib` MiB; returns (seconds, delivered_bytes).
async fn once(
    server: &quinn::Endpoint,
    client: &quinn::Endpoint,
    addr: std::net::SocketAddr,
    mib: usize,
) -> f64 {
    let total = mib * 1024 * 1024;
    let payload = vec![0xA5u8; 1024 * 1024]; // reused per MiB, no giant allocation

    let srv = {
        let server = server.clone();
        tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            for _ in 0..mib {
                send.write_all(&payload).await.unwrap();
            }
            let _ = send.finish();
            let _ = recv.read_to_end(1024).await;
            drop(recv);
            let _ = conn.closed().await;
        })
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let mut consumer = tokio::net::TcpStream::connect(local).await.unwrap();
    let (producer, _) = listener.accept().await.unwrap();
    let consumer_task = tokio::spawn(async move {
        let mut got = 0usize;
        let mut buf = vec![0u8; 256 * 1024];
        while got < total {
            match consumer.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        got
    });

    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, recv) = conn.open_bi().await.unwrap();
    send.write_all(b"k").await.unwrap();
    let _ = send.finish();

    let t0 = Instant::now();
    let (res, diag) = copy_tcp_quic_idle(producer, send, recv, Duration::from_secs(60)).await;
    let secs = t0.elapsed().as_secs_f64();
    let got = consumer_task.await.unwrap();
    conn.close(0u32.into(), b"done");
    srv.abort();

    let (up, down) = res.unwrap_or_else(|e| panic!("pump failed: {e:#} diag={diag:?}"));
    assert!(up <= 1, "up={up}");
    assert_eq!(
        down, total as u64,
        "short transfer: {down} != {total} diag={diag:?}"
    );
    assert_eq!(got, total, "consumer short read");
    secs
}

#[tokio::main]
async fn main() {
    let mib: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    let reps: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let (server, client, addr) = endpoints();
    let mut rates = Vec::new();
    for i in 0..reps {
        let secs = once(&server, &client, addr, mib).await;
        let mbps = mib as f64 / secs;
        rates.push(mbps);
        println!(
            "rep {}: {:.1} MB/s ({:.3}s for {} MiB)",
            i + 1,
            mbps,
            secs,
            mib
        );
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = rates[rates.len() / 2];
    println!(
        "MEDIAN {:.1} MB/s  (min {:.1}, max {:.1})",
        median,
        rates[0],
        rates[rates.len() - 1]
    );
}
