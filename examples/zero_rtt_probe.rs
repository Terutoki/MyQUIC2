//! 0-RTT end-to-end probe: connect twice to the SAME server process.
//! First connection fetches resumption tickets; second must offer 0-RTT early data.
use myquic2::*;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("rustls=debug,quinn_proto=debug")
        .with_writer(std::io::stderr)
        .init();
    let cert = load_cert_der("server-cert.pem")?;
    let tls = client_tls_config(cert)?;
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ccfg = quinn::ClientConfig::new(std::sync::Arc::new(quic_client));
    ccfg.transport_config(build_transport("bbr", 5));
    let mut ep = quinn::Endpoint::client("[::]:0".parse()?)?;
    ep.set_default_client_config(ccfg);
    let server: SocketAddr = "127.0.0.1:8443".parse()?;

    let c1 = ep.connect(server, "myquic2")?.await?;
    println!("conn1: full handshake ok");
    // Keep conn1 OPEN while conn2 is attempted: mirrors quinn's own zero_rtt test,
    // which exchanges 1-RTT data first so NewSessionTickets are guaranteed delivered.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let connecting = ep.connect(server, "myquic2")?;
    match connecting.into_0rtt() {
        Ok((c2, accepted)) => {
            println!("conn2: client HAD resumption tickets, 0-RTT offered");
            // Send application data immediately, before handshake completes.
            let (mut send, mut recv) = c2.open_bi().await?;
            let mut hdr = Vec::new();
            TargetAddr::Ip("127.0.0.1:18081".parse()?).encode(&mut hdr);
            send.write_all(&hdr).await?;
            send.write_all(b"zero-rtt-echo").await?;
            let mut buf = vec![0u8; 13];
            recv.read_exact(&mut buf).await?;
            println!("conn2: 0-RTT echo ok: {:?}", String::from_utf8_lossy(&buf));
            println!(
                "conn2: server accepted 0-RTT early data = {}",
                accepted.await
            );
            c2.close(0u32.into(), b"probe-done");
            c1.close(0u32.into(), b"probe-done");
        }
        Err(_) => println!("conn2: NO resumption tickets (0-RTT unavailable)"),
    }
    Ok(())
}
