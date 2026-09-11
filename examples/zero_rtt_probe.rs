//! 0-RTT end-to-end probe: connect twice to the SAME server process.
//! First connection fetches resumption tickets; second must offer 0-RTT early data.
//! Usage: zero_rtt_probe [server_addr] [sni] [auth_token]
//! (auth_token also read from MYQUIC2_AUTH_TOKEN; must match the server config)
use myquic2::*;
use std::net::SocketAddr;

async fn authenticate(conn: &quinn::Connection, token: &str) -> anyhow::Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    // `write_all` is inherent on quinn's SendStream (no AsyncWriteExt needed).
    let mut uni = conn.open_uni().await?;
    uni.write_all(token.as_bytes()).await?;
    uni.finish().ok();
    Ok(())
}

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
    let server: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".into())
        .parse()?;
    let sni: String = std::env::args().nth(2).unwrap_or_else(|| "test.com".into());
    let token: String = std::env::args()
        .nth(3)
        .or_else(|| std::env::var("MYQUIC2_AUTH_TOKEN").ok())
        .unwrap_or_default();

    let c1 = ep.connect(server, &sni)?.await?;
    authenticate(&c1, &token).await?;
    println!("conn1: full handshake ok");
    // Keep conn1 OPEN while conn2 is attempted: mirrors quinn's own zero_rtt test,
    // which exchanges 1-RTT data first so NewSessionTickets are guaranteed delivered.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let connecting = ep.connect(server, &sni)?;
    match connecting.into_0rtt() {
        Ok((c2, accepted)) => {
            authenticate(&c2, &token).await?;
            println!("conn2: client HAD resumption tickets, 0-RTT offered");
            // Send application data immediately, before handshake completes.
            let (mut send, mut recv) = c2.open_bi().await?;
            let mut hdr = Vec::new();
            TargetAddr::Ip("127.0.0.1:18081".parse()?).encode(&mut hdr)?;
            send.write_all(&hdr).await?;
            send.write_all(b"zero-rtt-echo").await?;
            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack).await?;
            assert_eq!(ack[0], 0x00, "server dial refused");
            // MQP-2: the ACK carries the server's bound address for this dial.
            let mut atyp = [0u8; 1];
            recv.read_exact(&mut atyp).await?;
            let n = match atyp[0] {
                0x01 => 6,
                0x04 => 18,
                a => panic!("bad bnd atyp {a}"),
            };
            let mut bnd = Vec::with_capacity(19);
            bnd.push(atyp[0]);
            let mut rest = vec![0u8; n];
            recv.read_exact(&mut rest).await?;
            bnd.extend_from_slice(&rest);
            let (bnd, _) = decode_bnd_addr(&bnd)?;
            println!("conn2: server bound address {bnd}");
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
