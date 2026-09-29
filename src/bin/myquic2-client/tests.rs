//! Client unit tests (moved verbatim from the single-file bin).
//!
//! Guards for the SOCKS5 address reader. `read_socks_addr` keeps its
//! original two-`read_exact` shape (see the note above it), so these tests
//! exist to catch a framing regression in any future rewrite.
use super::*;

use tokio::io::AsyncWriteExt;

/// Serve `bytes` on a loopback socket and run the real reader against it,
/// exactly as `handle_socks` drives it.
async fn feed(bytes: &[u8], lenient: bool) -> Result<TargetAddr> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let payload = bytes.to_vec();
    let server = tokio::spawn(async move {
        let (mut t, _) = l.accept().await.unwrap();
        t.write_all(&payload).await.unwrap();
        // Wait for a byte from the client before closing: a plain
        // `shutdown()`/drop right after `write_all` races the loopback
        // stack on macOS and the last byte can be lost, which would make
        // this reader test fail for reasons that have nothing to do with
        // the reader.
        let mut ack = [0u8; 1];
        t.read_exact(&mut ack).await.ok();
    });
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = if lenient {
        read_socks_addr_lenient(&mut c)
            .await
            .map(|()| TargetAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))))
    } else {
        read_socks_addr(&mut c).await
    };
    // Unblock the server (see above) once the reader is done, then let it
    // exit cleanly.
    let _ = c.write_all(b"\n").await;
    let _ = server.await;
    r
}

/// Like [`feed`], but closes the write half once the bytes are out, so a
/// frame that asks for more than it supplies reaches the reader as EOF
/// instead of parking it (the real caller bounds the whole negotiation with
/// one deadline; this proves the reader cannot outlive a closed peer at all).
async fn feed_truncated(bytes: &[u8], lenient: bool) -> Result<TargetAddr> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let payload = bytes.to_vec();
    let server = tokio::spawn(async move {
        let (mut t, _) = l.accept().await.unwrap();
        let _ = t.write_all(&payload).await;
        // FIN: a frame that wants more than it was given must surface as EOF
        // rather than parking the reader. (Nothing is read back — this path
        // never replies — so the task ends here and drops the socket.)
        let _ = t.shutdown().await;
    });
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = if lenient {
        read_socks_addr_lenient(&mut c)
            .await
            .map(|()| TargetAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))))
    } else {
        read_socks_addr(&mut c).await
    };
    assert!(server.await.is_ok(), "the writer task must not panic");
    r
}

/// Randomized ingress fuzz for the SOCKS5 address readers.
///
/// This is the one parser a hostile (or buggy) local peer drives with
/// arbitrary bytes, and the reader runs inside the accepted connection's
/// task: a panic there kills the flow, and a read that parks on a short frame
/// holds the task and its permit until the negotiation deadline. Every
/// mutated stream — including every truncation of every form — must either
/// complete with an encodable address or fail, within the timeout.
#[tokio::test]
async fn socks_reader_survives_random_and_truncated_ingress() {
    for case in 0..1_500u64 {
        let mut x = case.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let n = (case as usize * 7919) % 48;
        let mut b = Vec::with_capacity(n);
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b.push(x as u8);
        }
        if !b.is_empty() {
            // Bias the atyp so every branch of both readers is reached.
            b[0] = [0x01u8, 0x02, 0x03, 0x04, 0x00][(case % 5) as usize];
        }
        if b.len() >= 2 && b[0] == 0x03 {
            // Declare exactly what follows (sometimes short, sometimes long):
            // the reader must consume only what it was given.
            b[1] = (b.len() - 2).min(255) as u8;
        }
        let lenient = case % 2 == 0;
        let out =
            match tokio::time::timeout(Duration::from_secs(2), feed_truncated(&b, lenient)).await {
                Ok(r) => r,
                Err(_) => panic!(
                    "SOCKS reader parked on a {} B frame (case {case}, lenient={lenient})",
                    b.len()
                ),
            };
        // The strict reader decodes a target the caller will put on the wire,
        // so an accepted one must be encodable. (The lenient form returns the
        // placeholder below on purpose: it parses the ignored ASSOCIATE outer
        // address, which is never encoded.)
        if let Ok(addr) = out {
            if !lenient {
                assert!(
                    addr.as_ref().header().is_ok(),
                    "an accepted address must be encodable (case {case}): {addr:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn socks_reader_decodes_v4_v6_and_domain() {
    assert_eq!(
        feed(&[0x01, 127, 0, 0, 1, 0x46, 0xA1], false)
            .await
            .unwrap(),
        TargetAddr::Ip("127.0.0.1:18081".parse().unwrap())
    );

    let mut v6 = vec![0x04];
    v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    v6.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(
        feed(&v6, false).await.unwrap(),
        TargetAddr::Ip("[::1]:443".parse().unwrap())
    );

    let d = b"localhost";
    let mut dm = vec![0x03, d.len() as u8];
    dm.extend_from_slice(d);
    dm.extend_from_slice(&18081u16.to_be_bytes());
    assert_eq!(
        feed(&dm, false).await.unwrap(),
        TargetAddr::Domain("localhost".into(), 18081)
    );
}

#[tokio::test]
async fn socks_reader_rejects_bad_atyp_and_empty_domain() {
    assert!(feed(&[0x02, 0, 0, 0, 0, 0, 0], false).await.is_err());
    assert!(feed(&[0x03, 0x00, 0x00, 0x00], false).await.is_err());
}

#[tokio::test]
async fn socks_lenient_reader_accepts_the_same_framing() {
    let d = b"example.com";
    let mut dm = vec![0x03, d.len() as u8];
    dm.extend_from_slice(d);
    dm.extend_from_slice(&8443u16.to_be_bytes());
    assert!(feed(&dm, true).await.is_ok());
    assert!(feed(&[0x01, 0, 0, 0, 0, 0, 0], true).await.is_ok());
}

/// Serve `bytes`, drain whatever the negotiation writes back, and hand the
/// client half a FIN once they are out — so a truncated request surfaces as
/// EOF rather than parking the reader.
async fn negotiate_feed(bytes: &[u8]) -> Result<SocksRequest> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let payload = bytes.to_vec();
    let server = tokio::spawn(async move {
        let (mut t, _) = l.accept().await.unwrap();
        let _ = t.write_all(&payload).await;
        let _ = t.shutdown().await;
        // Drain the method-selection / error replies so the client's writes
        // never block, and exit when the client closes its half.
        let mut sink = [0u8; 256];
        while let Ok(n) = t.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    });
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = negotiate(&mut c).await;
    drop(c);
    assert!(server.await.is_ok(), "the serving task must not panic");
    r
}

/// Randomized fuzz for the **whole** negotiation: an accepted greeting is
/// followed by a randomized request, so the CMD dispatch, the reserved-byte
/// check and both address readers are all reached with hostile bytes — and
/// every frame is also tried truncated, which must fail rather than park the
/// connection task until its deadline.
#[tokio::test]
async fn negotiate_survives_random_and_truncated_requests() {
    for case in 0..800u64 {
        let mut x = case.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1;
        // A greeting the reader accepts, so the request path is what runs.
        let mut b = vec![0x05u8, 0x01, 0x00];
        let cmd = [0x01u8, 0x03, 0x02, 0x00][(case % 4) as usize];
        let rsv = if case % 7 == 0 { 0x01 } else { 0x00 };
        b.extend_from_slice(&[0x05, cmd, rsv]);
        let n = (case as usize * 104_729) % 24;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b.push(x as u8);
        }
        if case % 3 == 0 {
            if let Some(a) = b.get_mut(6) {
                *a = [0x01u8, 0x03, 0x04, 0x05][(case % 4) as usize];
            }
            if b.get(6) == Some(&0x03) {
                let declared = b.len().saturating_sub(8).min(255) as u8;
                if let Some(l) = b.get_mut(7) {
                    *l = declared;
                }
            }
        }
        match tokio::time::timeout(Duration::from_secs(2), negotiate_feed(&b)).await {
            Ok(_) => {}
            Err(_) => panic!("negotiate parked on a {} B request (case {case})", b.len()),
        }
    }
}

/// The whole negotiation is a linear read of greeting + request; the tests
/// pin the two request forms and a version mismatch, so the single-deadline
/// refactor cannot change which bytes are consumed.    /// The whole negotiation is a linear read of greeting + request; the tests
/// pin the two request forms and a version mismatch, so the single-deadline
/// refactor cannot change which bytes are consumed.
#[tokio::test]
async fn negotiate_reads_connect_and_associate() {
    async fn feed(bytes: &[u8]) -> Result<SocksRequest> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let payload = bytes.to_vec();
        let server = tokio::spawn(async move {
            let (mut t, _) = l.accept().await.unwrap();
            t.write_all(&payload).await.unwrap();
            // Drain until the client closes: half-closing early races the
            // client's remaining reads on macOS loopback.
            let mut sink = [0u8; 64];
            while let Ok(n) = t.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = negotiate(&mut c).await;
        drop(c);
        let _ = server.await;
        r
    }

    let mut connect = vec![0x05, 0x01, 0x00];
    connect.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0xA1]);
    match feed(&connect).await.unwrap() {
        SocksRequest::Connect(t) => {
            assert_eq!(t, TargetAddr::Ip("127.0.0.1:18081".parse().unwrap()));
        }
        SocksRequest::Associate => panic!("expected CONNECT"),
    }

    let mut assoc = vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00];
    assoc.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(
        feed(&assoc).await.unwrap(),
        SocksRequest::Associate
    ));

    assert!(feed(&[0x04, 0x01, 0x00]).await.is_err(), "bad ver");
}

/// Routing must read the maintained atomic: the old shape took the
/// `shared` lock and `close_reason()` (quinn's connection-state mutex) per
/// slot per flow, and a slot whose `shared` is empty still has to report
/// whatever the connection loop last published.
#[test]
fn slot_liveness_is_the_maintained_atomic() {
    let slot = ConnSlot::fresh();
    assert!(!slot.is_live(), "no connection yet");
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(slot.is_live(), "the hint is what routing reads");
    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!slot.is_live());
}

/// The routing table, row by row; the first three blocks are the *old*
/// dual-pool assertions restated for the generalized selector, so a
/// two-slot pool still behaves exactly as it did (including "keep the
/// preference and fail fast" when both are down).
#[test]
fn slot_routing_table() {
    // Single slot: always slot 0, whatever the liveness says.
    assert_eq!(select_slot(false, 0, &[false]), 0);
    assert_eq!(select_slot(true, 1, &[true]), 0);
    assert_eq!(select_slot(false, 7, &[false]), 0);
    // Dual, all live: pinned -> a (0), bulk -> b (1) only.
    assert_eq!(select_slot(true, 0, &[true, true]), 0);
    assert_eq!(select_slot(false, 0, &[true, true]), 1);
    assert_eq!(select_slot(false, 1, &[true, true]), 1);
    // Dual, `a` down: everything fails over to `b` (1).
    assert_eq!(select_slot(true, 0, &[false, true]), 1);
    assert_eq!(select_slot(false, 0, &[false, true]), 1);
    assert_eq!(select_slot(false, 1, &[false, true]), 1);
    // Dual, `b` down: bulk falls back to `a`, pinned stays.
    assert_eq!(select_slot(true, 0, &[true, false]), 0);
    assert_eq!(select_slot(false, 0, &[true, false]), 0);
    assert_eq!(select_slot(false, 1, &[true, false]), 0);
    // Dual, both down: keep the preference for a bounded fail-fast.
    assert_eq!(select_slot(true, 0, &[false, false]), 0);
    assert_eq!(select_slot(false, 0, &[false, false]), 1);
    assert_eq!(select_slot(false, 1, &[false, false]), 1);
    // Four slots live: bulk cycles the three *non-interactive* slots and
    // never takes slot 0, while pinned never leaves it. This is the
    // isolation the pool exists for.
    for rr in 0..8 {
        assert_eq!(select_slot(false, rr, &[true; 4]), 1 + rr % 3);
        assert_eq!(select_slot(true, rr, &[true; 4]), 0);
    }
    // Four slots, 0 down: pinned and bulk both fail over to the first live.
    assert_eq!(select_slot(true, 0, &[false, true, true, true]), 1);
    assert_eq!(select_slot(false, 0, &[false, true, true, true]), 1);
    // ...but a live preference is never abandoned just because a lower slot
    // is dead: rr = 2 prefers slot 3 and keeps it.
    assert_eq!(select_slot(false, 2, &[false, true, true, true]), 3);
    assert_eq!(select_slot(true, 0, &[false, false, true, false]), 2);
    // Every slot down: the round-robin preference is kept, so each flow
    // waits on a real slot and fails fast rather than picking a random one.
    assert_eq!(select_slot(false, 0, &[false; 4]), 1);
    assert_eq!(select_slot(false, 2, &[false; 4]), 3);
    assert_eq!(select_slot(true, 2, &[false; 4]), 0);
}

/// The pool holds N distinct TCP slots plus one dedicated UDP slot per
/// egress class, bulk flows cycling through every *non-interactive* TCP
/// slot, the interactive port pinned to slot 0, and failover driven by the
/// maintained liveness bits.
#[test]
fn pool_round_robins_bulk_over_every_non_interactive_slot() {
    let pool = ConnPool::new(4, vec![53], true, true);
    assert_eq!(pool.tcp_slots(), 4, "every TCP slot is registered");
    assert_eq!(
        pool.udp_slot(EgressClass::Interactive),
        4,
        "the interactive UDP class is one past the TCP range"
    );
    assert_eq!(
        pool.udp_slot(EgressClass::Bulk),
        5,
        "the bulk UDP class gets its own slot"
    );
    assert_eq!(pool.slots_total(), 6);
    assert_eq!(pool.slots.len(), 6, "all six slots are installed");
    assert!(
        !Arc::ptr_eq(&pool.slot(0).live, &pool.slot(1).live),
        "each index is its own slot, not one shared handle"
    );
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    // All slots still down: bulk keeps its round-robin preference (bounded
    // stall), the pinned port keeps slot 0.
    assert_eq!(pool.pick_tcp_index(&bulk), 1);
    assert_eq!(pool.pick_tcp_index(&bulk), 2);
    assert_eq!(pool.pick_tcp_index(&interactive), 0);
    for i in 0..4 {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    let seq: Vec<usize> = (0..8).map(|_| pool.pick_tcp_index(&bulk)).collect();
    assert_eq!(
        seq,
        vec![1, 2, 3, 1, 2, 3, 1, 2],
        "bulk spreads over the three non-interactive slots and never takes slot 0"
    );
    for _ in 0..4 {
        assert_eq!(pool.pick_tcp_index(&interactive), 0, "pinned to slot 0");
    }
    // Slot 0 down: both pinned and bulk fail over to the first live slot,
    // and `pick_tcp` hands back that slot's handle rather than slot 0's.
    pool.slot(0)
        .live
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pool.pick_tcp_index(&interactive), 1);
    // rr has advanced to 8 by now, so the bulk preference is slot 3 — still
    // live, so it is kept rather than collapsed onto slot 1.
    assert_eq!(pool.pick_tcp_index(&bulk), 3);
    assert!(Arc::ptr_eq(
        &pool.pick_tcp(&interactive).live,
        &pool.slot(1).live
    ));
}

/// The regression the class-preserving failover exists for: with one bulk
/// slot reconnecting, a bulk flow whose round-robin preference lands on that
/// dead slot must take *another bulk slot*, never the interactive slot. The
/// pre-fix selector scanned `0..n` and returned 0 here — one flow in three
/// sharing the connection every interactive port rides, precisely while a
/// connection was degraded.
#[test]
fn bulk_failover_never_takes_the_interactive_slot() {
    // Slots 0 (interactive), 1 (bulk), 3 (bulk) live; slot 2 (bulk) down.
    let live = [true, true, false, true];
    // rr = 1 prefers slot 2, which is down: fail over inside the bulk class.
    assert_eq!(select_slot(false, 1, &live), 1);
    assert_eq!(select_slot(false, 4, &live), 1);
    // A live preference is still kept.
    assert_eq!(select_slot(false, 0, &live), 1);
    assert_eq!(select_slot(false, 2, &live), 3);
    // Only when *no* bulk slot is live does slot 0 become the fallback.
    assert_eq!(select_slot(false, 1, &[true, false, false, false]), 0);
    assert_eq!(select_slot(false, 1, &[false, false, false, false]), 2);
    // ...and a pinned flow still prefers slot 0 or the first live slot.
    assert_eq!(select_slot(true, 0, &live), 0);
    assert_eq!(select_slot(true, 0, &[false, true, false, true]), 1);
    // The pool-level form of the same case.
    let pool = ConnPool::new(4, vec![], true, true);
    for i in [0usize, 1, 3] {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    let rr0 = pool.rr.load(std::sync::atomic::Ordering::Relaxed);
    // Walk enough flows to hit the dead slot's round-robin turn.
    let mut hits = [0usize; 4];
    for _ in 0..30 {
        hits[pool.pick_tcp_index(&bulk)] += 1;
    }
    assert_eq!(hits[0], 0, "bulk never lands on the interactive slot");
    assert_eq!(hits[2], 0, "the dead bulk slot is never selected");
    assert!(hits[1] > 0 && hits[3] > 0, "both live bulk slots are used");
    assert!(rr0 < pool.rr.load(std::sync::atomic::Ordering::Relaxed));
}

/// L2 stale-live regression: a bulk preference whose QUIC connection died
/// in the window before the conn loop clears the `live` bit (stale-true)
/// must re-pick to a live bulk sibling instead of stalling the reconnect
/// timeout on the dead slot. Without the `close_reason()` confirm in
/// `pick_tcp_index`, the stale-true preference is kept and `wait_conn`
/// sits on its generation until the deadline.
#[tokio::test]
async fn stale_true_preference_repicks_to_a_live_bulk_sibling() {
    let pool = ConnPool::new(4, vec![], true, true);
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    // One live connection per bulk slot; slot 1's is closed but its bit
    // stays true, i.e. the flap window between QUIC death and the clear.
    // Built inline (not via `real_connection`): that helper drops the
    // server-side handle, whose close then races the assertions. Every
    // handle here is retained so only the deliberately closed slot probes
    // dead.
    let mut conns = Vec::new();
    let mut _held = Vec::new();
    for i in 1..4usize {
        let certified = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
        let alpn = normalize_alpn(None);
        let server_tls = server_tls_config(
            certified.cert.der().clone(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
            &alpn,
        )
        .unwrap();
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        scfg.transport_config(build_transport("bbr", 5));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_tls = client_tls_config(certified.cert.der().clone(), &alpn).unwrap();
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport("bbr", 5));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);
        let accept = async {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        };
        let (c, s) = tokio::join!(client.connect(server_addr, "test.com").unwrap(), accept);
        let (c, s): (quinn::Connection, quinn::Connection) = (c.unwrap(), s);
        pool.slot(i).publish(&c);
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
        conns.push(c);
        _held.push((s, client, server));
    }
    conns[0].close(0u32.into(), b"test");
    assert!(
        pool.slot(1).holds_dead_handle(),
        "the closed slot must probe dead"
    );
    assert!(
        !pool.slot(2).holds_dead_handle() && !pool.slot(3).holds_dead_handle(),
        "the siblings must probe live"
    );
    // Force the round-robin preference onto the stale-true slot 1.
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    let idx = pool.pick_tcp_index(&bulk);
    assert_ne!(idx, 1, "a stale-true dead preference must not be kept");
    assert!(
        idx == 2 || idx == 3,
        "failover stays in the bulk class, got slot {idx}"
    );
    assert_ne!(idx, 0, "bulk never falls back to the interactive slot");
    // A fresh flow must be servable without waiting out a timeout: the
    // re-picked slot hands out its live connection immediately.
    let slot = pool.slot(idx);
    let mut gen_rx = slot.gen_rx.clone();
    let got = tokio::time::timeout(
        Duration::from_millis(200),
        slot.wait_conn(&mut gen_rx, Duration::from_millis(200)),
    )
    .await
    .expect("re-picked slot must not stall")
    .expect("re-picked slot holds a live connection");
    assert!(
        got.close_reason().is_none(),
        "the re-picked handle must be live"
    );
}

/// A one-slot pool is the legacy single-TCP-connection mode: every flow,
/// pinned or bulk, resolves to slot 0 no matter what the liveness bit says.
/// UDP still gets its own connection(s) past the TCP range, so even the
/// legacy mode keeps the classes off one congestion window.
#[test]
fn pool_of_one_slot_always_routes_to_slot_zero() {
    let pool = ConnPool::new(1, vec![], true, true);
    assert_eq!(pool.tcp_slots(), 1);
    assert_eq!(pool.udp_slot(EgressClass::Interactive), 1);
    assert_eq!(pool.udp_slot(EgressClass::Bulk), 2);
    assert_eq!(pool.slots_total(), 3);
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    assert_eq!(pool.pick_tcp_index(&bulk), 0);
    assert_eq!(pool.pick_tcp_index(&bulk), 0);
    pool.slot(0)
        .live
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pool.pick_tcp_index(&bulk), 0);
    // The constructor clamps, so a wider pool can never be built than the
    // routing path's stack liveness array can describe.
    assert_eq!(
        ConnPool::new(999, vec![], true, true).tcp_slots(),
        MAX_POOL_CONNS
    );
    assert_eq!(ConnPool::new(0, vec![], true, true).tcp_slots(), 1);
    // Clamping holds for the physical registry too: `tcp + classes` slots
    // with the split on, `tcp + 1` with it off.
    assert_eq!(
        ConnPool::new(999, vec![], true, true).slots_total(),
        MAX_POOL_CONNS + EgressClass::COUNT
    );
    assert_eq!(
        ConnPool::new(999, vec![], true, false).slots_total(),
        MAX_POOL_CONNS + 1
    );
}

/// The dedicated UDP slots are outside every TCP range, and the fail-closed
/// policy keeps each class on its own slot: a datagram is never handed a TCP
/// slot's connection, whatever the rest of the pool is doing.
#[test]
fn udp_egress_is_confined_to_the_dedicated_slot() {
    let pool = ConnPool::new(4, vec![], true, true);
    assert_eq!(pool.udp_slot(EgressClass::Interactive), 4);
    assert_eq!(pool.udp_slot(EgressClass::Bulk), 5);
    assert!(pool.udp_slot(EgressClass::Interactive) >= pool.tcp_slots());
    // Bulk rotation can never reach the UDP slots, live or dead.
    for rr in 0..16 {
        let i = select_slot(false, rr, &[true; 4]);
        assert!(i < pool.tcp_slots(), "rr={rr} picked {i}");
    }
    // Fail-closed: exactly one candidate, and it is the caller's class slot.
    let egress = SharedEgress::default();
    let (order, k) = egress.egress_order(&pool, EgressClass::Interactive);
    assert_eq!((order[0], k), (4, 1), "interactive is confined to slot 4");
    let (order, k) = egress.egress_order(&pool, EgressClass::Bulk);
    assert_eq!((order[0], k), (5, 1), "bulk is confined to slot 5");
    // Fallback allowed: own class, other class, then interactive TCP, then
    // bulk TCP — and each UDP slot appears exactly once.
    let pool = ConnPool::new(4, vec![], false, true);
    let (order, k) = egress.egress_order(&pool, EgressClass::Interactive);
    assert_eq!(k, pool.slots_total());
    assert_eq!(&order[..6], &[4, 5, 0, 1, 2, 3]);
    assert_eq!(
        order[..k]
            .iter()
            .filter(|&&i| i == pool.udp_slot(EgressClass::Interactive))
            .count(),
        1
    );
    let (order, _) = egress.egress_order(&pool, EgressClass::Bulk);
    assert_eq!(&order[..6], &[5, 4, 0, 1, 2, 3]);
    // The split off: both classes share the single slot, TCP after it.
    let pool = ConnPool::new(4, vec![], false, false);
    let (order, k) = egress.egress_order(&pool, EgressClass::Bulk);
    assert_eq!(k, pool.slots_total());
    assert_eq!(&order[..5], &[4, 0, 1, 2, 3]);
    // The one-slot legacy pool still separates the classes.
    let pool = ConnPool::new(1, vec![], true, true);
    let (order, k) = egress.egress_order(&pool, EgressClass::Bulk);
    assert_eq!((order[0], k), (2, 1));
}

/// The class split decision: a known interactive port is interactive
/// whatever the payload size, and an unknown port is interactive only when
/// the first datagram is small enough to be STUN/DTLS/RTP-sized media.
#[test]
fn udp_class_splits_by_port_and_first_payload() {
    let pool = ConnPool::new(1, vec![53, 3478], true, true);
    let ip = |port| TargetAddrRef::Ip(SocketAddr::from(([203, 0, 113, 7], port)));
    // A known interactive port is interactive whatever the payload size.
    assert_eq!(pool.udp_class(&ip(53), 1400), EgressClass::Interactive);
    assert_eq!(pool.udp_class(&ip(3478), 1400), EgressClass::Interactive);
    // An unknown port with a small first payload (STUN/DTLS/RTP-sized) is
    // interactive; the same port with a full-size first payload is bulk.
    assert_eq!(pool.udp_class(&ip(443), 100), EgressClass::Interactive);
    assert_eq!(
        pool.udp_class(&ip(443), UDP_INTERACTIVE_MAX),
        EgressClass::Interactive
    );
    assert_eq!(
        pool.udp_class(&ip(443), UDP_INTERACTIVE_MAX + 1),
        EgressClass::Bulk
    );
    assert_eq!(pool.udp_class(&ip(443), 1200), EgressClass::Bulk);
    // A domain target classifies by its port the same way.
    assert_eq!(
        pool.udp_class(&TargetAddrRef::Domain("example.com", 3478), 1200),
        EgressClass::Interactive
    );
}

/// The two classes never share a cached handle: a handle published for the
/// interactive class must not serve a fail-closed bulk association, or the
/// split would collapse back to one congestion window.
#[tokio::test]
async fn egress_classes_do_not_share_cached_handles() {
    let (conn, _c, _s) = real_connection().await;
    let pool = ConnPool::new(2, Vec::new(), true, true);
    let e = SharedEgress::default();
    let now = mono_millis();
    let (ic, bc) = (EgressClass::Interactive, EgressClass::Bulk);
    e.cached[ic.index()].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: pool.udp_slot(ic),
    })));
    // The interactive class serves its live handle ...
    let got = e.acquire(&pool, ic, now).expect("interactive handle");
    assert_eq!(got.0.stable_id(), conn.stable_id());
    // ... while the bulk class, whose own slot has no connection, gets
    // nothing — never the interactive handle.
    assert!(
        e.acquire(&pool, bc, now).is_none(),
        "a fail-closed bulk class must not borrow the interactive handle"
    );
    assert!(e.cached[bc.index()].load().is_none());
}

/// The loser path of `acquire` gates an expired handle on one cheap
/// `close_reason` check: a live handle is still reused (zero-window
/// blackhole fix must not cost a drop), while a dead one is invalidated
/// so the caller counts NO_EGRESS instead of sending into a dead
/// connection for the whole refresh window (the kill-9 restart case).
/// The refresh gate is held so both probes take the loser path.
#[tokio::test]
async fn expired_dead_handle_is_invalidated_not_served() {
    let (conn, _c, _s) = real_connection().await;
    let pool = ConnPool::new(2, Vec::new(), true, true);
    let e = SharedEgress::default();
    let class = EgressClass::Interactive;
    let now = mono_millis();
    // Probe past the refresh window: a stamp of `now` read at
    // `now + EGRESS_REFRESH_MS` is exactly expired. (Computing the stamp
    // as `now - EGRESS_REFRESH_MS` saturates to 0 on a fast test clock
    // and reads back as fresh.)
    let expired_now = now + EGRESS_REFRESH_MS;
    e.cached[class.index()].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: pool.udp_slot(class),
    })));
    e.generation[class.index()].fetch_add(1, std::sync::atomic::Ordering::Release);
    // Hold the single-flight gate: `refresh_global` returns None, so
    // `acquire` must decide on the loser path alone.
    e.refreshing[class.index()].store(true, std::sync::atomic::Ordering::Release);

    // Live expired handle: reused, cache kept.
    let got = e
        .acquire(&pool, class, expired_now)
        .expect("a live expired handle must still be served");
    assert_eq!(got.0.stable_id(), conn.stable_id());
    assert!(e.cached[class.index()].load().is_some());

    // Dead expired handle: dropped, cache invalidated (generation bumped
    // so every thread's memo misses), never handed out for a doomed send.
    conn.close(0u32.into(), b"test");
    assert!(
        conn.close_reason().is_some(),
        "the test's closed handle must probe dead"
    );
    let gen_before = e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
    assert!(
        e.acquire(&pool, class, expired_now).is_none(),
        "a dead expired handle must not be served"
    );
    assert!(
        e.cached[class.index()].load().is_none(),
        "the dead handle must be invalidated"
    );
    assert_eq!(
        e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire),
        gen_before + 1,
        "invalidation must bump the generation so memos miss"
    );
    e.refreshing[class.index()].store(false, std::sync::atomic::Ordering::Release);
}

/// Loopback QUIC endpoint pair through the same public TLS/transport
/// helpers `main` uses, for tests that need a real `quinn::Connection`.
/// The endpoints are returned alongside the client connection because
/// dropping them closes it.
async fn real_connection() -> (quinn::Connection, quinn::Endpoint, quinn::Endpoint) {
    let certified = rcgen::generate_simple_self_signed(vec!["test.com".to_string()]).unwrap();
    let alpn = normalize_alpn(None);
    let server_tls = server_tls_config(
        certified.cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        &alpn,
    )
    .unwrap();
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    scfg.transport_config(build_transport("bbr", 5));
    let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client_tls = client_tls_config(certified.cert.der().clone(), &alpn).unwrap();
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
    let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
    ccfg.transport_config(build_transport("bbr", 5));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(ccfg);

    let accept = async {
        let incoming = server.accept().await.unwrap();
        incoming.accept().unwrap().await.unwrap()
    };
    let (conn, _server_conn) =
        tokio::join!(client.connect(server_addr, "test.com").unwrap(), accept);
    (conn.unwrap(), client, server)
}

/// The memo is served only while it is both current (generation matches)
/// and fresh (stamp inside the window); `invalidate` bumps the generation
/// so every thread's memo misses without a scan. The two classes are
/// independent: a bulk memo never serves an interactive lookup.
#[tokio::test]
async fn egress_memo_honours_generation_and_freshness() {
    let (conn, _client, _server) = real_connection().await;
    let e = SharedEgress::default();
    let class = EgressClass::Interactive;
    let now = mono_millis();
    e.cached[class.index()].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: 0,
    })));
    e.generation[class.index()].fetch_add(1, std::sync::atomic::Ordering::Release);
    let gen = e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
    e.memo_store(class, gen, &conn, 1200, now);
    assert_eq!(e.with_fresh(class, now, |_, limit| limit), Some(1200));
    assert!(
        e.with_fresh(EgressClass::Bulk, now, |_, _| ()).is_none(),
        "a memo stored for one class must not serve the other"
    );
    assert!(
        e.with_fresh(class, now + EGRESS_REFRESH_MS, |_, _| ())
            .is_none(),
        "a stamp past the refresh window must miss"
    );
    e.invalidate(class);
    assert!(
        e.with_fresh(class, now, |_, _| ()).is_none(),
        "a successful invalidate bumps the generation and drops the memo"
    );
    // A memo tagged before a later bump is not served even while its stamp
    // is still inside the window.
    let old_gen = e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
    e.memo_store(class, old_gen, &conn, 1200, now);
    assert!(e.with_fresh(class, now, |_, _| ()).is_some());
    e.generation[class.index()].fetch_add(1, std::sync::atomic::Ordering::Release);
    assert!(e.with_fresh(class, now, |_, _| ()).is_none());
}

/// A `TooLarge` send refreshes the cached DATAGRAM budget instead of
/// throwing the handle away.
///
/// The two reactions are not interchangeable. `invalidate` drops the
/// process-wide cache, so the next datagram on *every* thread re-acquires
/// through `refresh_global` — two quinn state-mutex acquisitions — and the
/// connection-lost counter and warning both lie about a healthy connection.
/// `refresh_budget` keeps the handle and only re-reads the one number that
/// moved.
#[tokio::test]
async fn too_large_refreshes_the_budget_without_discarding_the_handle() {
    let (conn, _client, _server) = real_connection().await;
    let live = conn
        .max_datagram_size()
        .expect("both ends negotiate DATAGRAM");
    let e = SharedEgress::default();
    let class = EgressClass::Interactive;
    // A deliberately stale, too-small budget, as if the path MTU had shrunk
    // under a memoized handle.
    e.cached[class.index()].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: live.saturating_sub(64).max(1),
        stamp_ms: mono_millis(),
        slot: 0,
    })));
    let gen_before = e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
    let cached_before = e.cached[class.index()]
        .load_full()
        .expect("published above");

    e.refresh_budget(class);

    let after = e.cached[class.index()]
        .load_full()
        .expect("the handle must survive");
    assert_eq!(
        after.conn.stable_id(),
        cached_before.conn.stable_id(),
        "refresh_budget must keep the same connection, not re-pick one"
    );
    assert_eq!(
        after.limit, live,
        "the stale budget must be replaced by the live one"
    );
    assert_eq!(after.slot, cached_before.slot);
    assert_eq!(
        e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire),
        gen_before + 1,
        "every thread's memo must be invalidated so the new budget is used"
    );

    // And it is a no-op once the budget already matches — the case for a
    // payload past MQP_FRAG_MAX_PAYLOAD, where the fragmenter rejects the
    // datagram before quinn ever sees it and nothing moved.
    let gen_now = e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire);
    e.refresh_budget(class);
    assert_eq!(
        e.generation[class.index()].load(std::sync::atomic::Ordering::Acquire),
        gen_now,
        "an unchanged budget must not churn the generation"
    );

    // With no cached handle at all it must not resurrect one.
    e.invalidate(class);
    e.refresh_budget(class);
    assert!(
        e.cached[class.index()].load().is_none(),
        "refresh_budget never re-picks a connection; that is acquire's job"
    );
}

/// Serializes the slow-path counter tests below. The drop counters are
/// process-wide and `bump` is exact, so two such tests racing would move
/// each other's deltas. No other client test bumps these counters: every
/// existing dispatch test uses IP targets, which never reach the DNS arms.
static DNS_SLOW_PATH_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A well-formed MQP-2 datagram for `sess` naming a domain target. Production
/// replies are always IP-form, so this is the defensive slow path
/// (`dispatch_one`'s `Domain` arm): negative cache, tri-state probe,
/// limiter-bounded spawn.
fn dgram_domain(sess: u32, host: &str, port: u16, payload: &[u8]) -> Bytes {
    encode_datagram(sess, &TargetAddr::Domain(host.into(), port), payload).unwrap()
}

/// P1-4 slow-path budget lock, REFUSED arm: a negatively-cached name is
/// refused synchronously — no resolver spawn, no reply — and counted exactly
/// once, on `REFUSED` only.
#[tokio::test]
async fn dispatch_negative_cached_domain_counts_refused_exactly_once() {
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let (host, port) = ("p14-dispatch-refused.invalid", 19531u16);
    dns_neg_cache_seed(host, port);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Negative,
        "premise: the name is negatively cached"
    );
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let before = dgram_drops::snapshot();
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram_domain(sess, host, port, b"q"),
        &mut reasm,
        &mut pkt,
    );
    assert!(
        no_reply(&a.app).await,
        "a negatively-cached name must be refused, never relayed"
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(d.refused, 1, "one refused datagram counts exactly once");
    assert_eq!(d.dns_inflight, 0, "no resolution was in flight");
    assert_eq!(d.dns_contention, 0, "no shard was contended");
    assert_eq!(d.session_full, 0, "no budget was spent");
    hub.release(sess);
}

/// P1-4 slow-path budget lock, SESSION_FULL arm: a 40-burst at one uncached
/// name with the 1024-permit budget exhausted counts every datagram exactly
/// once on `SESSION_FULL` — the countable loss budget. The dispatcher's
/// double guard (`available_permits` probe plus `try_acquire_owned`) still
/// charges one count per datagram: the probe returns early, so the acquire
/// never double-bumps the race it just observed.
#[tokio::test]
async fn dispatch_limiter_exhaustion_counts_session_full_exactly_once_per_drop() {
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let (host, port) = ("p14-dispatch-budget.invalid", 19532u16);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the name is uncached"
    );
    // Drain the slow-path budget the way a miss storm does. No other client
    // test holds this limiter, and nothing is awaited while drained.
    let lim = dns_slow_path_limiter();
    let mut held = Vec::new();
    while lim.available_permits() > 0 {
        match lim.clone().try_acquire_owned() {
            Ok(p) => held.push(p),
            Err(_) => break,
        }
    }
    assert_eq!(lim.available_permits(), 0, "the budget must be exhaustible");
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let before = dgram_drops::snapshot();
    for _ in 0..40 {
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram_domain(sess, host, port, b"q"),
            &mut reasm,
            &mut pkt,
        );
    }
    assert!(
        no_reply(&a.app).await,
        "budget-exhausted datagrams must be dropped, never relayed"
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.session_full, 40,
        "a 40-burst over budget counts every datagram exactly once"
    );
    assert_eq!(d.dns_inflight, 0, "nothing was registered inflight");
    assert_eq!(d.dns_contention, 0, "contention stays a distinct counter");
    assert_eq!(d.refused, 0, "budget loss is not policy refusal");
    drop(held);
    assert!(
        lim.available_permits() > 0,
        "the budget must recover when permits release"
    );
    hub.release(sess);
}

/// P1-4 slow-path budget lock, spawn arm: an uncached name with budget
/// available leaves the synchronous scope uncounted — the caller owns
/// nothing, records no pin, delivers nothing — and the spawned task owns the
/// resolution to completion. This is the "no reader awaits DNS" half: the
/// only `resolve_all_cached` in `dispatch_one` runs inside `tokio::spawn`.
#[tokio::test]
async fn dispatch_uncached_domain_spawns_without_a_sync_bump() {
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let (host, port) = ("p14-dispatch-spawn.invalid", 19533u16);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the name is uncached"
    );
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let before = dgram_drops::snapshot();
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram_domain(sess, host, port, b"q"),
        &mut reasm,
        &mut pkt,
    );
    assert!(
        no_reply(&a.app).await,
        "the caller delivers nothing; the spawned task owns this datagram"
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(d.refused, 0, "uncached is not refusal");
    assert_eq!(
        d.dns_inflight, 0,
        "the first miss spawns, it is not inflight"
    );
    assert_eq!(d.dns_contention, 0, "no shard was contended");
    assert_eq!(d.session_full, 0, "budget was available");
    // The spawn owned the resolution: an unresolvable name settles as a
    // negative cache entry (the client spawn bumps nothing on a plain
    // failure), so the next datagram refuses without spawning again.
    let mut settled = CachedLookup::Unknown;
    for _ in 0..100 {
        settled = lookup_cached_fast(host, port);
        if settled == CachedLookup::Negative {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        settled,
        CachedLookup::Negative,
        "the spawned task must drive the resolution to a cached verdict"
    );
    hub.release(sess);
}

fn empty_dispatch_cache() -> [DispatchSlot; DISPATCH_CACHE] {
    std::array::from_fn(|_| DispatchSlot {
        sess: u32::MAX,
        entry: None,
    })
}

/// The dispatcher cache must never be the last owner of an association's
/// relay socket.
///
/// A cached binding outlives the association: the hub drops its entry and the
/// association task exits, but the cache entry is only re-validated when
/// another datagram for the *same session id* arrives. With a strong `Arc`
/// there, every retired association stayed cached — up to `DISPATCH_CACHE`
/// dead relay sockets, each an fd plus 2 x 256 KiB of kernel buffers, per
/// dispatcher — until a colliding session id happened to arrive or the
/// connection was redialed. Measured before the fix: 1200 short-lived
/// associations left 1024 UDP fds open in the client.
#[tokio::test]
async fn dispatch_cache_does_not_own_the_relay_socket() {
    let hub = Arc::new(UdpHub::new());
    let a = test_assoc().await;
    hub.subscribe(7, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    dispatch_one(
        &mut cache,
        &hub,
        7,
        dgram(7, b"hello"),
        &mut reasm,
        &mut pkt,
    );
    assert!(
        cache[7 & (DISPATCH_CACHE - 1)].entry.is_some(),
        "the dispatcher must have cached the binding"
    );

    let weak = Arc::downgrade(&a.entry);
    let weak_relay = Arc::downgrade(&a.entry.relay);
    hub.release(7); // the association exits: hub entry and slot released
    drop(a); // ... and its own Arc goes with the task
             // The relay socket can still be in the global `WouldBlock` retry pool for
             // a moment — the first send on a fresh socket is answered with
             // `WouldBlock` on this platform — so poll briefly instead of demanding
             // instant release.
    let mut released = false;
    for _ in 0..100 {
        if weak.upgrade().is_none() && weak_relay.upgrade().is_none() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        released,
        "the dispatcher cache must not keep a retired association's relay socket alive"
    );
}

/// UDP egress must stay on the connection it first used while that
/// connection is alive.
///
/// Re-running the slot scan on every refresh moved every association back
/// onto the interactive slot the moment that slot recovered: a second
/// target-side source-port change (the server builds a new session on the new
/// connection) for a flow that had already failed over, which is the
/// flap-back the docs promise not to do. The pool here has *no* live slot,
/// which is the sharpest form of the check: a scan-based refresh gives up
/// (`None`, so the datagram is dropped), while the sticky path still serves
/// the live cached handle.
#[tokio::test]
async fn egress_stays_on_its_connection_while_it_lives() {
    let (conn, _c, _s) = real_connection().await;
    let pool = ConnPool::new(2, Vec::new(), true, true);
    let e = SharedEgress::default();
    let class = EgressClass::Interactive;
    let now = mono_millis();
    // Cached, but past the freshness window, so a refresh is required. Slot
    // 2 is this pool's interactive UDP slot, which is what a fail-closed
    // pool can legitimately hold.
    e.cached[class.index()].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now.saturating_sub(EGRESS_REFRESH_MS),
        slot: pool.udp_slot(class),
    })));
    let (got, limit, stamp) = e
        .refresh_global(&pool, class, now)
        .expect("a live cached connection must be reused, not re-picked");
    assert_eq!(
        got.stable_id(),
        conn.stable_id(),
        "the cached connection must survive the refresh"
    );
    assert_eq!(stamp, now, "the refresh re-stamps the cached handle");
    assert!(
        limit > 0,
        "the DATAGRAM budget is re-read from the live path"
    );
    assert_eq!(
        e.cached[class.index()]
            .load()
            .as_ref()
            .map(|c| c.conn.stable_id()),
        Some(conn.stable_id()),
        "the published handle must still be that same connection"
    );

    // Once it is really gone the refresh falls back to the pool scan — and
    // with nothing live there is nothing to select, so the caller drops the
    // datagram instead of writing into a dead connection.
    conn.close(0u32.into(), b"test");
    for _ in 0..1000 {
        if conn.close_reason().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(conn.close_reason().is_some(), "close must be observable");
    assert!(
        e.refresh_global(&pool, class, now).is_none(),
        "a dead cached handle with no live slot must not be re-served"
    );
}

/// The relay must be bound to the address BND advertises, so every reply is
/// sent from the source the app was told to expect. A wildcard bind (the
/// previous shape) lets the kernel pick the source by route to the app,
/// which a multi-homed host can resolve to a different local address; a
/// source-validating app then drops every reply.
#[tokio::test]
async fn relay_bind_pins_the_announced_address() {
    let v4 = bind_relay(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
    assert_eq!(
        unmap(v4.local_addr().unwrap().ip()),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "a v4 relay must be bound to its advertised address, not the wildcard"
    );
    let v6 = bind_relay(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)).unwrap();
    assert_eq!(
        v6.local_addr().unwrap().ip(),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        "a v6 relay must be bound to its advertised address, not the wildcard"
    );
}

/// A fake association: a dual-stack relay socket (the production shape —
/// `map_for_dual` maps the reply destination to a v4-mapped address, so a
/// v4-only relay could not send), an "app" socket that receives replies, and
/// the entry the hub would hold, with the app address already published.
struct TestAssoc {
    entry: Arc<AssocEntry>,
    app: tokio::net::UdpSocket,
}

async fn test_assoc() -> TestAssoc {
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap();
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app.local_addr().unwrap();
    let entry = Arc::new(AssocEntry::new(Arc::new(relay)));
    entry.app.store(Some(Arc::new(app_addr)));
    TestAssoc { entry, app }
}

/// How long a *positive* delivery assertion waits.
///
/// 2 s, not the 300 ms this used to be: the reply is a loopback datagram
/// sent by `dispatch_one` from *this* process, so it cannot be lost on the
/// wire — but the suite runs several real-QUIC loopback tests concurrently,
/// and while those saturate the loopback path a 300 ms window misses the
/// datagram often enough that the client bin went red in roughly half of
/// back-to-back `cargo test --all-targets` runs. Nothing here is sensitive
/// to how long a *successful* wait takes.
const REPLY_WAIT: Duration = Duration::from_secs(2);

/// How long a *negative* probe waits before concluding "nothing arrived".
///
/// Deliberately short, and it must stay well under `FRAG_TIMEOUT_MS`
/// (2 s): `dispatch_reassembles_fragments_for_two_interleaved_sessions`
/// probes *between* the fragments of one payload, so a 2 s probe would let
/// the partial expire and the completed datagram could never be delivered —
/// the assertion would fail for a reason that has nothing to do with the
/// dispatcher. A reply sent synchronously by `dispatch_one` lands in
/// microseconds, so 300 ms is a generous margin for a wrong-reply check.
const REPLY_PROBE: Duration = Duration::from_millis(300);

async fn recv_reply_in(app: &tokio::net::UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut b = vec![0u8; 2048];
    match tokio::time::timeout(wait, app.recv_from(&mut b)).await {
        Ok(Ok((n, _))) => Some(b[..n].to_vec()),
        _ => None,
    }
}

/// Drain one reply from the fake app, or `None` if nothing arrives within
/// [`REPLY_WAIT`] — the timeout is what lets a "must be dropped" assertion
/// terminate.
async fn recv_reply(app: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
    recv_reply_in(app, REPLY_WAIT).await
}

/// True when no reply arrives within [`REPLY_PROBE`].
async fn no_reply(app: &tokio::net::UdpSocket) -> bool {
    recv_reply_in(app, REPLY_PROBE).await.is_none()
}

/// A well-formed MQP-2 datagram carrying `payload` for `sess`.
fn dgram(sess: u32, payload: &[u8]) -> Bytes {
    encode_datagram(
        sess,
        &TargetAddr::Ip("203.0.113.7:53".parse().unwrap()),
        payload,
    )
    .unwrap()
}

/// The SOCKS5 reply header is RSV(3) + ATYP(1) + v4(4) + port(2).
const REPLY_HDR_V4: usize = 10;

#[tokio::test]
async fn dispatch_first_packet_probes_hub_and_delivers() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"hello"),
        &mut reasm,
        &mut pkt,
    );
    let got = recv_reply(&a.app).await.expect("reply must be delivered");
    assert_eq!(got[0..3], [0, 0, 0]);
    assert_eq!(got[3], 0x01, "ATYP must be IPv4");
    assert_eq!(&got[REPLY_HDR_V4..], b"hello");
    assert_eq!(cache[(sess as usize) & (DISPATCH_CACHE - 1)].sess, sess);
}

/// The dispatcher writes the relay socket itself, so a cached live entry must
/// keep delivering even after the hub has forgotten the session. This is the
/// replacement for the old "receiver still alive after `hub.remove`" case.
#[tokio::test]
async fn dispatch_cache_hit_does_not_reprobe_the_hub() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"a"),
        &mut reasm,
        &mut pkt,
    );
    assert_eq!(
        &recv_reply(&a.app).await.expect("first reply")[REPLY_HDR_V4..],
        b"a"
    );
    // Unpublish but leave the entry alive: the cache must still serve it.
    hub.release(sess);
    assert!(a.entry.is_alive());
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"b"),
        &mut reasm,
        &mut pkt,
    );
    assert_eq!(
        &recv_reply(&a.app).await.expect("cached reply")[REPLY_HDR_V4..],
        b"b"
    );
}

/// `alive` replaces the `Closed` signal the dropped `mpsc::Receiver` used to
/// give: once the association clears it, the dispatcher must re-probe, find
/// nothing, and drop — not keep writing into a socket nobody reads.
#[tokio::test]
async fn dispatch_dead_entry_reprobes_and_drops() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"a"),
        &mut reasm,
        &mut pkt,
    );
    assert!(recv_reply(&a.app).await.is_some());

    a.entry
        .alive
        .store(false, std::sync::atomic::Ordering::Relaxed);
    hub.release(sess);
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"b"),
        &mut reasm,
        &mut pkt,
    );
    assert!(
        no_reply(&a.app).await,
        "a torn-down association must not receive further replies"
    );
    assert!(
        cache[(sess as usize) & (DISPATCH_CACHE - 1)]
            .entry
            .is_none(),
        "the dead slot must have been re-probed away"
    );
}

/// The hub-probe path must filter liveness, not just publication.
///
/// `dispatch_dead_entry_reprobes_and_drops` above releases the hub entry, so
/// the map is already empty and `hub.entry` returns `None`. The window that
/// test does not cover is the real one: `AliveGuard` clears the bit when the
/// association exits, and the entry leaves the shard only later (in
/// `UdpHub::release`, or never if that release is unwound past). A reply in
/// that window was written into a socket nobody reads — the exact thing the
/// cache-hit path filters with `is_alive`.
#[tokio::test]
async fn dispatch_published_but_dead_entry_is_dropped() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"a"),
        &mut reasm,
        &mut pkt,
    );
    assert!(recv_reply(&a.app).await.is_some());

    // The association has exited, but its entry is still published: this is
    // the `AliveGuard`-before-`release` window.
    a.entry
        .alive
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(hub.entry(sess).is_some(), "the entry is still published");
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"b"),
        &mut reasm,
        &mut pkt,
    );
    assert!(
        no_reply(&a.app).await,
        "a published-but-dead association must not receive replies"
    );
    assert!(
        cache[(sess as usize) & (DISPATCH_CACHE - 1)]
            .entry
            .is_none(),
        "the dead entry must not be cached"
    );
}

/// A reply is activity: it sets the association's activity bit, and the
/// association's next idle tick folds that bit into the stamp, so a flow that
/// is receive-only after its first request is not reaped at 180 s while the
/// server-side session is still live.
///
/// Both halves are driven with explicit clocks (the send path no longer reads
/// one at all), so this asserts the semantics rather than the test process's
/// uptime: a test binary is younger than one idle tick, so no real-clock run
/// could observe both "the flag was consumed" and "the deadline passed".
#[tokio::test]
async fn replies_mark_the_association_active_until_the_next_tick() {
    let a = test_assoc().await;
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let dst: SocketAddr = "203.0.113.7:53".parse().unwrap();
    let payload = Bytes::from_static(b"reply");
    let app = a.entry.app().expect("the app address is published");

    // The association was last active at t=0 and its deadline has just passed.
    a.entry.last.store(0, std::sync::atomic::Ordering::Relaxed);
    let now = ASSOC_IDLE_MS + ASSOC_IDLE_TICK_SECS * 1000;
    assert!(
        a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
        "without activity the deadline must be reported"
    );

    // One reply, then the tick that follows it: the flag is folded into the
    // stamp and the association stays alive, however stale the old stamp was.
    send_reply_addr(&a.entry, app, dst, &payload, &mut pkt);
    assert!(
        a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
        "a written reply must set the activity bit"
    );
    assert_eq!(
        a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the reply path itself must not touch the stamp (no clock read)"
    );
    assert!(
        !a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
        "a reply inside the window must keep the association alive"
    );
    assert_eq!(
        a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
        now,
        "the tick folds the bit into the stamp"
    );
    assert!(
        recv_reply(&a.app).await.is_some(),
        "the reply still goes out"
    );

    // The bit is consumed exactly once: the next tick with no further replies
    // reports idle at the deadline, and no earlier.
    assert!(
        !a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
        "the tick must consume the bit"
    );
    assert!(!a.entry.idle_since_tick(now + 1000, ASSOC_IDLE_MS));
    assert!(
        !a.entry
            .idle_since_tick(now + ASSOC_IDLE_MS - 1, ASSOC_IDLE_MS),
        "one millisecond short of the deadline is not idle"
    );
    assert!(
        a.entry.idle_since_tick(now + ASSOC_IDLE_MS, ASSOC_IDLE_MS),
        "the deadline itself is idle"
    );
}

/// A receive-only association is never reaped while replies flow, even when
/// its stamp is older than the deadline on every single tick: this is the
/// property the per-reply stamp existed for, restated for the bit.
#[tokio::test]
async fn flowing_replies_never_let_the_deadline_fire() {
    let a = test_assoc().await;
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let dst: SocketAddr = "203.0.113.7:53".parse().unwrap();
    let payload = Bytes::from_static(b"stream");
    let app = a.entry.app().expect("the app address is published");
    a.entry.last.store(0, std::sync::atomic::Ordering::Relaxed);

    // 60 ticks, one reply in each: the app never sends anything.
    let mut now = ASSOC_IDLE_TICK_SECS * 1000;
    for _ in 0..60 {
        send_reply_addr(&a.entry, app, dst, &payload, &mut pkt);
        assert!(
            !a.entry.idle_since_tick(now, ASSOC_IDLE_MS),
            "replies are still arriving at t={now}ms"
        );
        now += ASSOC_IDLE_TICK_SECS * 1000;
    }
    assert_eq!(
        a.entry.last.load(std::sync::atomic::Ordering::Relaxed),
        now - ASSOC_IDLE_TICK_SECS * 1000,
        "the stamp tracks the last tick that saw activity"
    );
}

/// The dispatcher path (not just `send_reply_addr`) is what production uses,
/// so pin that `dispatch_one` sets the same activity bit. No clock is read on
/// either side of this assertion any more, which is why the test needs no
/// sleep: it used to have to wait out a full touch interval.
#[tokio::test]
async fn dispatch_marks_the_association_active() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    assert!(!a.entry.replied.load(std::sync::atomic::Ordering::Relaxed));
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"reply"),
        &mut reasm,
        &mut pkt,
    );
    assert!(recv_reply(&a.app).await.is_some());
    assert!(
        a.entry.replied.load(std::sync::atomic::Ordering::Relaxed),
        "the dispatcher must mark the association active"
    );
    hub.release(sess);
}

/// The hub reservation is released by a `Drop` guard, so a panic in the
/// association body cannot leak the process-wide slot or the shard's strong
/// `Arc<AssocEntry>` (the relay socket's last owner). The reservation is the
/// one release in this file that used to be a plain statement after an
/// `.await`, which unwinding skips.
#[tokio::test]
async fn association_reservation_survives_a_panicking_body() {
    let hub = Arc::new(UdpHub::new());
    let sess = hub.alloc_sess().unwrap();
    let before = hub.len.load(std::sync::atomic::Ordering::Acquire);
    assert_eq!(before, 1, "one association reserved");

    let h = hub.clone();
    let joined = tokio::spawn(async move {
        let _res = SessReservation { hub: &h, sess };
        // A body that panics for any reason: a `?`-less failure, an
        // unexpected `None`, a poisoned helper.
        panic!("association body panicked");
    })
    .await;
    assert!(joined.is_err(), "the task must have unwound");

    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Acquire),
        0,
        "the reserved slot must come back on unwinding"
    );
    assert!(
        hub.entry(sess).is_none(),
        "the released id must not stay published"
    );
    // The budget is reusable: a later association still gets an id. Ids are
    // not recycled by a monotonic counter (`alloc_sess`'s reuse-distance
    // note), so this asserts availability, not identity.
    let next = hub.alloc_sess().expect("the budget must be reusable");
    assert_ne!(next, 0);
    hub.release(next);
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Acquire), 0);
}

#[tokio::test]
async fn dispatch_absent_slot_reprobes_the_hub() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = 7777u32;
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    // Not published yet: the packet is dropped and the slot caches absent.
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"x"),
        &mut reasm,
        &mut pkt,
    );
    assert!(no_reply(&a.app).await);
    hub.publish(sess, a.entry.clone());
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"y"),
        &mut reasm,
        &mut pkt,
    );
    assert_eq!(
        &recv_reply(&a.app).await.expect("reply after publish")[REPLY_HDR_V4..],
        b"y"
    );
}

#[tokio::test]
async fn dispatch_collision_reprobes_and_delivers_both() {
    let hub = UdpHub::new();
    let s1 = 100u32;
    let s2 = s1 + DISPATCH_CACHE as u32;
    assert_eq!(
        (s1 as usize) & (DISPATCH_CACHE - 1),
        (s2 as usize) & (DISPATCH_CACHE - 1)
    );
    let a1 = test_assoc().await;
    let a2 = test_assoc().await;
    hub.publish(s1, a1.entry.clone());
    hub.publish(s2, a2.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    for (s, want) in [(s1, &b"1"[..]), (s2, &b"2"[..]), (s1, &b"3"[..])] {
        dispatch_one(&mut cache, &hub, s, dgram(s, want), &mut reasm, &mut pkt);
    }
    let f = |v: Vec<u8>| v[REPLY_HDR_V4..].to_vec();
    // Delivery, not order, is the property under test — and the collision
    // re-probe is what it is about: both replies for `s1` must reach `a1`,
    // and `s2`'s must reach `a2`.
    //
    // Order is deliberately NOT asserted between the two replies to one
    // association. The first write on a fresh tokio UDP socket reports
    // `WouldBlock` (no cached writable readiness — see `udp_try_send`), so
    // these datagrams go through the detached retry pool, whose shard keeps
    // up to `UDP_RETRY_INFLIGHT` sends in flight at once; two datagrams to
    // the same destination can therefore complete in either order. UDP
    // permits reordering and that hop is best-effort by contract, so an
    // order assertion here left the client bin red under
    // `--no-default-features` (where the per-packet stats calls are compiled
    // out and the timing shifts) for a reason that has nothing to do with
    // the dispatcher — a red suite that hides real regressions.
    let mut replies = [
        f(recv_reply(&a1.app).await.unwrap()),
        f(recv_reply(&a1.app).await.unwrap()),
    ];
    replies.sort();
    assert_eq!(replies, [b"1".to_vec(), b"3".to_vec()]);
    assert_eq!(f(recv_reply(&a2.app).await.unwrap()), b"2");
}

/// Phase 3 moved fragment reassembly out of the per-association reply task
/// and into the dispatcher, relying on `DgramReassembler` being keyed by
/// `(sess, id)` — i.e. connection-wide, exactly as the server has always used
/// it. This pins that a payload split across fragments still arrives whole,
/// and that two sessions reassembling *concurrently* on the one dispatcher
/// reassembler do not cross-contaminate.
#[tokio::test]
async fn dispatch_reassembles_fragments_for_two_interleaved_sessions() {
    let hub = UdpHub::new();
    let s1 = 11u32;
    let s2 = 12u32;
    let a1 = test_assoc().await;
    let a2 = test_assoc().await;
    hub.publish(s1, a1.entry.clone());
    hub.publish(s2, a2.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let addr = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    let limit = 1400usize;
    let send = |reasm: &mut DgramReassembler,
                cache: &mut [DispatchSlot; DISPATCH_CACHE],
                pkt: &mut bytes::BytesMut,
                sess: u32,
                id: u16,
                total: u8,
                idx: u8,
                chunk: &[u8]| {
        let f = encode_fragment(sess, id, idx, total, &addr.as_ref(), chunk, limit).unwrap();
        dispatch_one(cache, &hub, sess, f, reasm, pkt);
    };
    // Interleave the two sessions' fragments deliberately.
    send(&mut reasm, &mut cache, &mut pkt, s1, 5, 2, 0, b"AAAA");
    send(&mut reasm, &mut cache, &mut pkt, s2, 9, 2, 0, b"BBBB");
    assert!(
        no_reply(&a1.app).await,
        "a half-reassembled payload must not be delivered"
    );
    send(&mut reasm, &mut cache, &mut pkt, s1, 5, 2, 1, b"aaaa");
    send(&mut reasm, &mut cache, &mut pkt, s2, 9, 2, 1, b"bbbb");
    assert_eq!(
        &recv_reply(&a1.app).await.expect("s1 reassembled")[REPLY_HDR_V4..],
        b"AAAAaaaa"
    );
    assert_eq!(
        &recv_reply(&a2.app).await.expect("s2 reassembled")[REPLY_HDR_V4..],
        b"BBBBbbbb"
    );
}

/// The dispatcher's lookup is *total*: `sender` reports `None` only for a
/// session that genuinely has no subscription, never because a lock was
/// busy. This is the property the old `try_lock_read` violated — a losing
/// `try_read` returned `None` and the inbound datagram was silently dropped.
///
/// Hammered from several threads, a subscribed id must be observable on
/// every single probe until it is removed, and `remove` must be the only
/// thing that makes it disappear.
#[tokio::test]
async fn hub_sender_never_fails_because_of_concurrency() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let hub = Arc::new(UdpHub::new());
    const PROBES: u32 = 4096;
    // Subscribe everything *before* any reader runs, so from this point on
    // every id in 1..=PROBES is continuously subscribed and a `None` can
    // only mean a lost lookup.
    // One socket shared by every stub entry: these tests only exercise the
    // hub's lookup, never a dispatch, so 4096 real sockets would only risk
    // the fd limit.
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    for s in 1..=PROBES {
        hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let hub = hub.clone();
        let stop = stop.clone();
        readers.push(std::thread::spawn(move || {
            let mut seen = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for s in 1..=PROBES {
                    assert!(
                        hub.entry(s).is_some(),
                        "subscribed session {s} probed as absent"
                    );
                    seen += 1;
                }
            }
            seen
        }));
    }
    let mut churn = Vec::new();
    for t in 0..2u32 {
        let hub = hub.clone();
        let sock = sock.clone();
        churn.push(std::thread::spawn(move || {
            // A disjoint id range, hashed across the same 32 shards, so the
            // writers keep re-publishing maps the readers are loading.
            for i in 0..256u32 {
                let s = 1_000_000 + t * 1000 + i;
                hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
                hub.unpublish(s);
            }
        }));
    }
    for c in churn {
        let _ = c.join();
    }
    stop.store(true, Ordering::Relaxed);
    let total: u64 = readers.into_iter().map(|r| r.join().unwrap()).sum();
    assert!(total > 0, "readers never ran");
    // Everything subscribed must still be present, and nothing else.
    for s in 1..=PROBES {
        assert!(hub.entry(s).is_some(), "session {s} lost after churn");
    }
    assert!(hub.entry(PROBES + 1).is_none());
}

/// `rcu` re-runs against the latest published map, so two associations
/// subscribing to the same shard concurrently cannot lose each other's
/// insert (which a load-clone-store would).
#[tokio::test]
async fn hub_concurrent_subscribes_on_one_shard_all_land() {
    let hub = Arc::new(UdpHub::new());
    // HUB_SHARDS == 32, so ids 0..32 spread over every shard exactly once
    // per round; each thread therefore contends on all shards.
    const PER_THREAD: u32 = 512;
    let mut threads = Vec::new();
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    for t in 0..8u32 {
        let hub = hub.clone();
        let sock = sock.clone();
        threads.push(std::thread::spawn(move || {
            for i in 0..PER_THREAD {
                let s = 1 + t * PER_THREAD + i;
                hub.subscribe(s, Arc::new(AssocEntry::new(sock.clone())));
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
    for s in 1..=(8 * PER_THREAD) {
        assert!(
            hub.entry(s).is_some(),
            "concurrent subscribe lost session {s}"
        );
    }
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "subscribe must not move the global association counter"
    );
}

/// `wait_conn` confirms a `live`-true handle via `close_reason()` and
/// still fails fast once the bit is false, with `close_reason()` as the
/// authority. A locally closed connection with a stale-true bit waits to
/// the deadline instead of handing back a dead handle (the race window
/// before the conn loop clears `live` + bumps the generation); the TCP
/// `open_bi` failure path stays the self-heal for handles that die after
/// this check.
#[tokio::test]
async fn wait_conn_trusts_the_live_bit_and_bounds_the_dead_case() {
    let (conn, _client, _server) = real_connection().await;
    let slot = ConnSlot::fresh();
    slot.publish(&conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    let (_gen_tx, mut gen_rx) = watch::channel(0u64);

    // Stale-true bit with a closed connection: must wait, not hand back
    // the dead handle that used to let the dispatcher busy-spin.
    conn.close(0u32.into(), b"test");
    assert!(
        slot.wait_conn(&mut gen_rx, Duration::from_millis(50))
            .await
            .is_err(),
        "a closed connection must not be handed out even while live is stale-true"
    );

    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        slot.wait_conn(&mut gen_rx, Duration::from_millis(50))
            .await
            .is_err(),
        "a dead slot must fail at the deadline, not hand out a dead handle"
    );
}

/// BUG-2: the `open_bi` failure path must never mark a freshly published
/// connection dead. The old two-step (`clear_if`, then a trailing
/// `live.store(false)`) let a concurrent `publish(C)` land between the
/// decision and the store, leaving `(shared == C, live == false)` until C
/// died. `clear_if_and_mark_dead` folds the store into the `rcu` closure,
/// so the interleaving has nowhere to land.
#[tokio::test]
async fn open_bi_failure_path_never_kills_a_fresh_connection() {
    let (d, _e1, _s1) = real_connection().await;
    let (c, _e2, _s2) = real_connection().await;
    assert_ne!(
        d.stable_id(),
        c.stable_id(),
        "the test needs two distinct connections"
    );

    // The old pattern, with the racing publish injected exactly between
    // the decision and the trailing store: ends with the fresh connection
    // marked dead. Pinned here so the regression stays visible.
    let slot = ConnSlot::fresh();
    slot.publish(&d);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(slot.clear_if(&d), "decision made while D was installed");
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|x| x.stable_id() == c.stable_id()),
        "the racing publish won the slot"
    );
    assert!(
        !slot.is_live(),
        "old two-step marks the fresh connection dead"
    );

    // The atomic helper under the same race, both orders: the slot is
    // never left holding C with live == false.
    // Order 1: the clear commits before C is published.
    let slot = ConnSlot::fresh();
    slot.publish(&d);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(slot.clear_if_and_mark_dead(&d));
    assert!(!slot.is_live());
    assert!(slot.shared.load().as_ref().is_none());
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        slot.is_live(),
        "a connection published after the clear stays live"
    );
    assert!(slot
        .shared
        .load()
        .as_ref()
        .is_some_and(|x| x.stable_id() == c.stable_id()));

    // Order 2: C is already installed when the stale failure for D runs.
    let slot = ConnSlot::fresh();
    slot.publish(&d);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        !slot.clear_if_and_mark_dead(&d),
        "stable_id mismatch clears nothing"
    );
    assert!(slot.is_live(), "the fresh connection is untouched");
    assert!(slot
        .shared
        .load()
        .as_ref()
        .is_some_and(|x| x.stable_id() == c.stable_id()));

    // Teardown interleaving: the slot holds fresh C (live) while the
    // teardown for dead D runs. The old unconditional store + `clear_if`
    // ends at (C, false) with no generation bump, so `wait_conn` treats
    // C as dead; the helper must never end at (C, false).
    let slot = ConnSlot::fresh();
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!slot.clear_if(&d), "D's teardown sees C and clears nothing");
    assert!(slot
        .shared
        .load()
        .as_ref()
        .is_some_and(|x| x.stable_id() == c.stable_id()));
    assert!(
        !slot.is_live(),
        "old teardown leaves (C, false) with no wake"
    );

    let slot = ConnSlot::fresh();
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        !slot.clear_if_and_mark_dead(&d),
        "D's teardown sees C and clears nothing"
    );
    assert!(slot
        .shared
        .load()
        .as_ref()
        .is_some_and(|x| x.stable_id() == c.stable_id()));
    assert!(
        slot.is_live(),
        "a stale teardown must never mark the fresh connection dead"
    );
}

/// BUG-6: the auth token write is bounded by the same 5 s deadline as the
/// stream open, so every dial attempt honours DIAL_ATTEMPT_TIMEOUT instead
/// of parking on a stalled connection until the QUIC idle timeout.
#[tokio::test]
async fn auth_write_fails_fast_on_a_stalled_stream() {
    // A writer that never becomes writable, standing in for a stalled
    // connection: the production wrapper shape
    // `timeout(deadline, write_all)` must resolve as a timeout, not park.
    struct Pending;
    impl tokio::io::AsyncWrite for Pending {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    let mut w = Pending;
    let start = tokio::time::Instant::now();
    let r = tokio::time::timeout(
        Duration::from_millis(50),
        tokio::io::AsyncWriteExt::write_all(&mut w, b"token"),
    )
    .await;
    assert!(r.is_err(), "a stalled auth write must time out");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the bound fails fast instead of parking for the idle timeout"
    );
    assert_eq!(
        DIAL_ATTEMPT_TIMEOUT,
        Duration::from_secs(5),
        "the dial attempt budget is unchanged"
    );

    // The small-write happy path still works through the real code, with
    // the deadline the dial passes in.
    let (conn, _client, _server) = real_connection().await;
    send_auth_stream(
        &conn,
        "t",
        tokio::time::Instant::now() + DIAL_ATTEMPT_TIMEOUT,
    )
    .await
    .expect("a small token write succeeds");
}

/// A clear that lost its CAS race must restore `live` **and** wake readers.
///
/// `wait_conn` wakes only on a generation bump or its deadline, and the
/// reader that consumed the publish's own bump can go on to observe the
/// transient `false` the losing clear run stored. Restoring the bit without
/// bumping therefore leaves a live, published connection unusable until that
/// reader's whole timeout (10 s for a dispatcher — every inbound datagram on
/// that egress connection stalls — or a spurious `REP=0x04` for a TCP flow).
#[tokio::test]
async fn restoring_live_after_a_lost_race_wakes_readers() {
    let (c, _e1, _s1) = real_connection().await;
    let slot = ConnSlot::fresh();
    slot.publish(&c);
    let mut gen_rx = slot.gen_rx.clone();

    // Not replaced: nothing to restore, and nothing may be woken.
    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!slot.restore_live_if_replaced(c.stable_id()));
    assert!(!slot.is_live());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), gen_rx.changed())
            .await
            .is_err(),
        "an unchanged slot must not bump the generation"
    );

    // Replaced by a different connection (the lost-race outcome): restore
    // the bit and wake the waiters that already consumed the publish bump.
    assert!(slot.restore_live_if_replaced(usize::MAX));
    assert!(slot.is_live());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), gen_rx.changed())
            .await
            .is_ok(),
        "the restore must wake a reader, or it sleeps out its deadline \
             with a live connection published"
    );
}

/// Association churn holds the cap without leaking slots: alloc/publish/
/// release cycles (the `SessReservation` pairing in production) return the
/// hub to empty, filling to the cap admits exactly `MAX_UDP_ASSOCS`, and
/// one more allocation is refused.
#[tokio::test]
async fn hub_churn_holds_the_assoc_cap_without_leaking_slots() {
    use std::sync::atomic::Ordering;

    const N: usize = 512;
    let hub = UdpHub::new();
    let relay = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let entry = Arc::new(AssocEntry::new(relay));
    for _ in 0..N {
        let s = hub.alloc_sess().expect("churn must not exhaust the cap");
        hub.publish(s, entry.clone());
        assert!(hub.entry(s).is_some());
        hub.release(s);
        assert!(hub.entry(s).is_none());
    }
    assert_eq!(hub.len.load(Ordering::Relaxed), 0);

    let mut ids = Vec::new();
    while let Some(s) = hub.alloc_sess() {
        hub.publish(s, entry.clone());
        ids.push(s);
    }
    assert_eq!(ids.len(), MAX_UDP_ASSOCS, "the cap must be exact");
    assert!(hub.alloc_sess().is_none(), "past the cap is refused");
    for s in ids {
        hub.release(s);
    }
    assert_eq!(hub.len.load(Ordering::Relaxed), 0);
}

/// Teardown is RAII-paired: dropping the guards clears the liveness bit
/// (so dispatchers stop writing into the socket) and releases the hub
/// slot (so the cap cannot leak one association at a time).
#[tokio::test]
async fn teardown_guards_pair_alive_bit_with_slot_release() {
    use std::sync::atomic::Ordering;

    let hub = UdpHub::new();
    let s = hub.alloc_sess().unwrap();
    let relay = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let entry = Arc::new(AssocEntry::new(relay));
    hub.publish(s, entry.clone());
    {
        let _alive = AliveGuard(entry.clone());
        let _reservation = SessReservation { hub: &hub, sess: s };
        assert!(entry.is_alive());
    }
    assert!(
        !entry.is_alive(),
        "AliveGuard must clear on every exit path"
    );
    assert!(hub.entry(s).is_none(), "release must unpublish");
    assert_eq!(
        hub.len.load(Ordering::Relaxed),
        0,
        "release must free the slot"
    );
}

/// The assoc recv-buf pool is bounded and exactly sized: whatever churn
/// pushes in, at most `ASSOC_BUF_POOL_DEPTH` buffers idle per thread, each
/// one a valid association buffer.
#[test]
fn assoc_recv_buf_pool_is_bounded_and_exactly_sized() {
    let mut bufs = Vec::new();
    for _ in 0..ASSOC_BUF_POOL_DEPTH + 4 {
        bufs.push(assoc_recv_buf());
    }
    for b in &bufs {
        assert_eq!(b.len(), ASSOC_RECV_BUF_LEN);
    }
    for b in bufs {
        assoc_recycle_buf(b);
    }
    assert!(
        assoc_buf_pool_len() <= ASSOC_BUF_POOL_DEPTH,
        "the pool must drop past its depth, not grow with churn"
    );
    assoc_recycle_buf(vec![0u8; 16]);
    assert!(assoc_buf_pool_len() <= ASSOC_BUF_POOL_DEPTH);
    let b = assoc_recv_buf();
    assert_eq!(b.len(), ASSOC_RECV_BUF_LEN);
    assoc_recycle_buf(b);
}
