//! Client unit tests (moved verbatim from the single-file bin).
//!
//! Guards for the SOCKS5 address reader. `read_socks_addr` keeps its
//! original two-`read_exact` shape (see the note above it), so these tests
//! exist to catch a framing regression in any future rewrite.
use super::*;

use myquic2::mqp::ctl_stream;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{FlowBinding, FlowState, R2_MAX_FLOWS_PER_CONN, R3_CONTEXT_REPEATS};
use myquic2::mqp::r3::CtlMessage;
use myquic2::mqp::wire::{self, Wire};
use myquic2::udp::{R2Assembled, R2Fragmenter, R2Reassembler, R2StageItem, R2StageKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serve `bytes` on a loopback socket and run the real reader against it,
/// exactly as `handle_socks` drives it.
/// Ready-to-use MQP-3 rev2 connection state for the wire tests: `CAPS`
/// negotiated (`wire_ver=2`), empty flow registry, client-owned id allocator.
fn rev2_state() -> Arc<ConnRev2> {
    let r = ConnRev2::new();
    r.on_caps(r2::Caps::default());
    r
}

/// Ready-to-use rev3 connection state: statically ready (no HELLO/CAPS), empty
/// flow registry, client-owned ids, rev3 stager/reassembler.
fn rev3_state() -> Arc<ConnRev2> {
    ConnRev2::new_with_wire(Wire::Rev3)
}

/// Fresh rev3 reassembler matching [`rev3_state`].
fn rev3_reasm() -> R2Reassembler {
    R2Reassembler::new_with_wire(Wire::Rev3)
}

/// Phase 2: small payloads queue in the connection-scoped stager and a drain
/// (the association's burst end) writes them. Tests that call `send_uplink`
/// directly drive that drain explicitly.
fn drain_now(rev2: &ConnRev2, conn: &quinn::Connection, limit: usize) {
    let _ = rev2.drain_stage(conn, limit);
}

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
        if let Ok(addr) = out
            && !lenient
        {
            assert!(
                addr.as_ref().header().is_ok(),
                "an accepted address must be encodable (case {case}): {addr:?}"
            );
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
    // Four slots, 0 down: the pinned class no longer has its home, so it
    // spreads over the bulk set with the same rotation cursor instead of
    // collapsing onto the first live slot: rr 0 -> 1, 1 -> 2, 2 -> 3, 3 -> 1.
    assert_eq!(select_slot(true, 0, &[false, true, true, true]), 1);
    assert_eq!(select_slot(true, 1, &[false, true, true, true]), 2);
    assert_eq!(select_slot(true, 2, &[false, true, true, true]), 3);
    assert_eq!(select_slot(true, 3, &[false, true, true, true]), 1);
    // ...while bulk keeps its own live preference.
    assert_eq!(select_slot(false, 0, &[false, true, true, true]), 1);
    // A live preference is never abandoned just because a lower slot is
    // dead: rr = 2 prefers slot 3 and keeps it.
    assert_eq!(select_slot(false, 2, &[false, true, true, true]), 3);
    // A dead bulk preference continues the rotation to the *next* live bulk
    // slot (3), not to the lowest live sibling (1).
    assert_eq!(select_slot(false, 1, &[true, true, false, true]), 3);
    // Only one bulk slot is left: both classes converge on it when their
    // rotation reaches it.
    assert_eq!(select_slot(true, 0, &[false, false, true, false]), 2);
    assert_eq!(select_slot(true, 1, &[false, false, true, false]), 2);
    // Every slot down: the round-robin preference is kept, so each flow
    // waits on a real slot and fails fast rather than picking a random one.
    assert_eq!(select_slot(false, 0, &[false; 4]), 1);
    assert_eq!(select_slot(false, 2, &[false; 4]), 3);
    assert_eq!(select_slot(true, 2, &[false; 4]), 0);
}

/// The pool holds N distinct TCP slots plus the dedicated UDP egress range —
/// the interactive slot followed by the bulk shard(s) — bulk flows cycling
/// through every *non-interactive* TCP slot, the interactive port pinned to
/// slot 0, and failover driven by the maintained liveness bits.
#[test]
fn pool_round_robins_bulk_over_every_non_interactive_slot() {
    let pool = ConnPool::new(4, vec![53], true, true, 1);
    assert_eq!(pool.tcp_slots(), 4, "every TCP slot is registered");
    assert_eq!(
        pool.udp_global_slot(0),
        4,
        "the interactive UDP class is one past the TCP range"
    );
    assert_eq!(
        pool.udp_global_slot(1),
        5,
        "the first bulk shard follows the interactive slot"
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
    // Slot 0 down: the pinned class falls back over the bulk set with the
    // same rotation cursor `pick_tcp_index` advances on every flow — pinned
    // ones included — so successes/failures spread instead of piling every
    // interactive flow onto slot 1 (the pre-fix `(0..n).find` behaviour).
    pool.slot(0)
        .live
        .store(false, std::sync::atomic::Ordering::Relaxed);
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pool.pick_tcp_index(&interactive), 1);
    assert_eq!(pool.pick_tcp_index(&interactive), 2);
    assert_eq!(pool.pick_tcp_index(&interactive), 3);
    assert_eq!(pool.pick_tcp_index(&interactive), 1, "the rotation wraps");
    // A live bulk preference is still kept: the cursor is at 4, so the bulk
    // preference is `1 + 4 % 3` = slot 2.
    assert_eq!(pool.pick_tcp_index(&bulk), 2);
    // `pick_tcp` hands back the *selected* slot's handle, not slot 0's. The
    // cursor is at 5 now, so the pinned fallback starts at 1 + 5 % 3 = slot 3.
    assert!(Arc::ptr_eq(
        &pool.pick_tcp(&interactive).live,
        &pool.slot(3).live
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
    // rr = 1 prefers slot 2, which is down: fail over *forward* inside the
    // bulk class — to slot 3, the dead slot's rotation successor — not back
    // to the lowest live sibling (slot 1), which is what `(1..n).find` did.
    assert_eq!(select_slot(false, 1, &live), 3);
    assert_eq!(select_slot(false, 4, &live), 3);
    // A live preference is still kept.
    assert_eq!(select_slot(false, 0, &live), 1);
    assert_eq!(select_slot(false, 2, &live), 3);
    // Only when *no* bulk slot is live does slot 0 become the fallback.
    assert_eq!(select_slot(false, 1, &[true, false, false, false]), 0);
    assert_eq!(select_slot(false, 1, &[false, false, false, false]), 2);
    // ...and a pinned flow still prefers slot 0, and when slot 0 is down it
    // rotates over the live bulk set instead of collapsing onto slot 1.
    assert_eq!(select_slot(true, 0, &live), 0);
    assert_eq!(select_slot(true, 0, &[false, true, false, true]), 1);
    assert_eq!(select_slot(true, 1, &[false, true, false, true]), 3);
    // The pool-level form of the same case.
    let pool = ConnPool::new(4, vec![], true, true, 1);
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

/// The rotated failover must not dump a dead bulk slot's round-robin share
/// onto the lowest live sibling: the pre-fix `(1..n).find` sent every flow
/// whose preference was dead to slot 1, so one reconnect could double that
/// slot's load while the rest of the bulk class idled. The rotation continues
/// from the dead preference to the next live slot, and `pick_tcp_index`
/// advances the cursor for pinned flows too, so their fallback (slot 0 down)
/// spreads over the whole live set as well.
#[test]
fn dead_bulk_slots_share_rotates_across_live_siblings() {
    // 0 interactive, 1..=4 bulk; slot 3 reconnecting.
    let pool = ConnPool::new(5, vec![], true, true, 1);
    for i in [0usize, 1, 2, 4] {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    // Divisible by the four bulk slots, so each `rr % 4` position appears
    // exactly FLOWS / 4 times.
    const FLOWS: usize = 400;
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut hits = [0usize; 5];
    for _ in 0..FLOWS {
        let i = pool.pick_tcp_index(&bulk);
        assert_ne!(i, 0, "bulk never falls back to the interactive slot");
        assert_ne!(i, 3, "the dead bulk slot is never selected");
        hits[i] += 1;
    }
    // Each live bulk slot keeps its own share; the dead slot's share is
    // redirected to its rotation successor (slot 4), never to the lowest
    // sibling. Pre-fix slot 1 got its own share *plus* every dead preference.
    assert_eq!(hits[1], FLOWS / 4, "slot 1 keeps only its own share");
    assert_eq!(hits[2], FLOWS / 4);
    assert_eq!(
        hits[4],
        FLOWS / 2,
        "the dead slot's RR share lands on its successor"
    );
    // Slot 0 down: the pinned class uses the same rotation (and the pinned
    // flow's fetch_add), so every live bulk sibling is used instead of every
    // interactive flow landing on slot 1.
    pool.slot(0)
        .live
        .store(false, std::sync::atomic::Ordering::Relaxed);
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut pinned_hits = [0usize; 5];
    for _ in 0..FLOWS {
        pinned_hits[pool.pick_tcp_index(&interactive)] += 1;
    }
    assert_eq!(pinned_hits[0], 0);
    assert_eq!(pinned_hits[3], 0);
    assert_eq!(
        pinned_hits[1],
        FLOWS / 4,
        "no collapse of the pinned fallback onto slot 1"
    );
    assert_eq!(pinned_hits[2], FLOWS / 4);
    assert_eq!(pinned_hits[4], FLOWS / 2);
}

/// L2 stale-live regression: a bulk preference whose QUIC connection died
/// in the window before the conn loop clears the `live` bit (stale-true)
/// must re-pick to a live bulk sibling instead of stalling the reconnect
/// timeout on the dead slot. Without the `close_reason()` confirm in
/// `pick_tcp_index`, the stale-true preference is kept and `wait_conn`
/// sits on its generation until the deadline.
#[tokio::test]
async fn stale_true_preference_repicks_to_a_live_bulk_sibling() {
    let pool = ConnPool::new(4, vec![], true, true, 1);
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
        scfg.transport_config(build_transport(Congestion::Bbr, 5));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_tls = client_tls_config(certified.cert.der().clone(), &alpn).unwrap();
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
        ccfg.transport_config(build_transport(Congestion::Bbr, 5));
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

/// Path-health gate, healthy case: a live slot whose inbound-progress stamp is
/// fresh is the *normal* state of an idle healthy connection (keepalives keep
/// `udp_rx.datagrams` moving at least every keepalive interval, and the
/// reconnect loop republishes the stamp on every advance), so routing must be
/// byte-identical to the pre-gate table for both classes.
#[test]
fn stale_gate_keeps_healthy_idle_slot() {
    let mut pool = ConnPool::new(4, vec![53], true, true, 1);
    assert_eq!(
        pool.data_stale_ms,
        data_stale_threshold_ms(5, 40),
        "the test constructor derives the threshold from the shipped 5 s keepalive / 60 s idle"
    );
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
        pool.slot(i).note_rx_progress();
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    // The gate must not perturb the rotation or the interactive pin.
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    let seq: Vec<usize> = (0..4).map(|_| pool.pick_tcp_index(&bulk)).collect();
    assert_eq!(seq, vec![1, 2, 3, 1], "healthy pool keeps the RR rotation");
    assert_eq!(
        pool.pick_tcp_index(&interactive),
        0,
        "pinned stays on slot 0"
    );
    pool.data_stale_ms = 60_000;
    // A healthy idle slot is never rejected even with a wide threshold.
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pool.pick_tcp_index(&bulk), 1);
}

/// Path-health gate, bulk class: the rr preference is a live slot whose inbound
/// progress froze past the threshold — the blackholed-NAT shape, where
/// `close_reason()` is still empty and `live` still reads true. Selection must
/// re-pick once over the live-and-fresh bulk set (continuing the rotation, like
/// the L2 dead-handle failover) instead of handing the new flow a dead path.
#[test]
fn stale_gate_re_picks_bulk_away_from_a_blackholed_preference() {
    let pool = ConnPool::new(4, vec![53], true, true, 1);
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let now = 1_000_000;
    let stale = now - pool.data_stale_ms - 1;
    // rr = 0 prefers bulk slot 1; freeze only that slot's progress.
    pool.slot(1)
        .last_rx_ms
        .store(stale, std::sync::atomic::Ordering::Relaxed);
    for i in [0usize, 2, 3] {
        pool.slot(i)
            .last_rx_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    // The rotation continues inside the bulk class from the stale preference:
    // 1 + (0 + 1) % 3 = slot 2.
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        2,
        "a stale bulk preference must fail over to a fresh bulk sibling"
    );
    assert!(
        pool.slot(1).is_live(),
        "the gate changes selection only: a blackholed slot stays live for the watchdog to own"
    );
    // Cursor 1: preference slot 2 is fresh, so the rotation is untouched.
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        2,
        "a fresh live preference is kept"
    );
}

/// Path-health gate, interactive/pinned class: slot 0 is the only home of an
/// `interactive_ports` flow, so a stale slot 0 must fall into the live-and-fresh
/// bulk set with the shared rotation — the fallback the class already uses when
/// slot 0 is dead — rather than pin the flow to a blackholed path.
#[test]
fn stale_gate_re_picks_pinned_away_from_a_blackholed_slot_zero() {
    let pool = ConnPool::new(4, vec![53], true, true, 1);
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let now = 1_000_000;
    let stale = now - pool.data_stale_ms - 1;
    pool.slot(0)
        .last_rx_ms
        .store(stale, std::sync::atomic::Ordering::Relaxed);
    for i in [1usize, 2, 3] {
        pool.slot(i)
            .last_rx_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
    let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&interactive, now),
        1,
        "a stale pin must rotate into the fresh bulk set, not stall the flow"
    );
    // The shared cursor moves the next fallback on to the next fresh bulk slot,
    // exactly as it does when slot 0 is merely dead.
    assert_eq!(
        pool.pick_tcp_index_at(&interactive, now),
        2,
        "pinned fallbacks keep spreading over the fresh set"
    );
}

/// Path-health gate, bounded-stall rule: when every live slot is stale (a
/// pool-wide outage, or a stalled coarse clock) there is no better sibling to
/// re-pick, so the preference is kept — `wait_conn` bounds the wait, and a
/// random stale sibling would only move the same failure elsewhere.
#[test]
fn stale_gate_keeps_the_preference_when_every_slot_is_stale() {
    let pool = ConnPool::new(4, vec![53], true, true, 1);
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let now = 1_000_000;
    let stale = now - pool.data_stale_ms - 1;
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .last_rx_ms
            .store(stale, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    let interactive = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        1,
        "all-stale keeps the bulk preference for the bounded stall"
    );
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&interactive, now),
        0,
        "all-stale keeps the pinned slot 0"
    );
}

/// The gate is an overlay on the liveness table, not a replacement: liveness
/// failover still wins first, and unseeded stamps (`0` = "no progress observed
/// yet", the shape of every slot built by the test constructor and of a slot
/// whose clear just committed) read as fresh, so the pre-gate routing table is
/// unchanged.
#[test]
fn stale_gate_overlays_liveness_without_changing_it() {
    let pool = ConnPool::new(4, vec![], true, true, 1);
    // Slots 0, 1 and 3 live; slot 2 down. No stamps at all.
    for i in [0usize, 1, 3] {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    // rr = 1 prefers dead slot 2: the liveness rotation picks slot 3.
    pool.rr.store(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pool.pick_tcp_index(&bulk), 3, "liveness failover unchanged");
    // The same shape with fresh stamps: still slot 3.
    let now = 1_000_000;
    for i in [0usize, 1, 3] {
        pool.slot(i)
            .last_rx_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
    pool.rr.store(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        3,
        "fresh stamps leave the liveness rotation alone"
    );
}

/// The gate reads the threshold the pool was built with, not a hard-coded
/// window: the same 30 s-old stamp is stale under the shipped 22 s threshold
/// and fresh under a 60 s one.
#[test]
fn stale_gate_uses_the_configured_threshold() {
    let mut pool = ConnPool::new(3, vec![], true, true, 1);
    for i in 0..pool.tcp_slots() {
        pool.slot(i)
            .live
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let now = 1_000_000;
    pool.slot(1)
        .last_rx_ms
        .store(now - 30_000, std::sync::atomic::Ordering::Relaxed);
    for i in [0usize, 2] {
        pool.slot(i)
            .last_rx_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
    let bulk = TargetAddr::Ip("203.0.113.7:443".parse().unwrap());
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        2,
        "30 s old is stale at the shipped 22 s threshold"
    );
    pool.data_stale_ms = 60_000;
    pool.rr.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        pool.pick_tcp_index_at(&bulk, now),
        1,
        "30 s old is fresh at a 60 s threshold, so the preference is kept"
    );
}

/// `ConnSlot::is_data_stale` semantics the routing gate depends on: boundary
/// inclusive, a `0` stamp is "unknown, never stale", and a clock that goes
/// backwards can never manufacture staleness.
#[test]
fn slot_data_staleness_semantics() {
    use std::sync::atomic::Ordering;
    let slot = ConnSlot::fresh();
    assert!(
        !slot.is_data_stale(1_000_000, 7_000),
        "no progress ever observed: unknown, not stale"
    );
    slot.last_rx_ms.store(993_000, Ordering::Relaxed);
    assert!(
        !slot.is_data_stale(999_999, 7_000),
        "6.999 s old is still inside the window"
    );
    assert!(
        slot.is_data_stale(1_000_000, 7_000),
        "exactly at the threshold is stale"
    );
    assert!(
        !slot.is_data_stale(900_000, 7_000),
        "a backwards clock reading is not staleness"
    );
    slot.reset_rx_progress();
    assert_eq!(
        slot.last_rx_ms.load(Ordering::Relaxed),
        0,
        "the death path clears the generation's stamp"
    );
    assert!(!slot.is_data_stale(u64::MAX, 7_000));
    slot.note_rx_progress();
    assert!(
        !slot.is_data_stale(coarse_millis(), 7_000),
        "a freshly published stamp is never stale"
    );
}

/// The selection threshold must sit strictly between "a healthy idle
/// connection is never rejected" and "the gate can win before the watchdog
/// closes the slot" for every legal keepalive — the invariant the whole gate
/// rests on.
#[test]
fn data_stale_threshold_sits_between_healthy_idle_and_watchdog() {
    // The shipped shape: 5 s keepalive / 60 s idle -> 40 s watchdog -> 22 s gate.
    assert_eq!(data_stale_threshold_ms(5, 40), 22_000);
    for keepalive in 1..=KEEP_ALIVE_MAX_SECS {
        let idle = resolve_idle_timeout_secs(keepalive, None);
        let watchdog = watchdog_silence_secs(idle);
        let threshold = data_stale_threshold_ms(keepalive, watchdog);
        // Lower bound: a healthy idle connection's stamp ages by at most one
        // keepalive interval plus one watchdog poll tick before the next
        // sample; the gate must never fire inside that.
        let healthy_idle_worst_ms = (keepalive + WATCHDOG_POLL.as_secs()) * 1_000;
        assert!(
            threshold > healthy_idle_worst_ms,
            "keepalive={keepalive}: threshold {threshold} <= healthy-idle age {healthy_idle_worst_ms}"
        );
        // Upper bound: strictly below the silence watchdog, so a blackholed
        // slot is rejected while it is still live and selectable.
        let watchdog_ms = watchdog * 1_000;
        assert!(
            threshold < watchdog_ms,
            "keepalive={keepalive}: threshold {threshold} >= watchdog {watchdog_ms}"
        );
    }
    // Out-of-range inputs use the same clamp as the transport, without warning.
    let watchdog_one = watchdog_silence_secs(resolve_idle_timeout_secs(1, None));
    let watchdog_max = watchdog_silence_secs(resolve_idle_timeout_secs(KEEP_ALIVE_MAX_SECS, None));
    assert_eq!(
        data_stale_threshold_ms(0, watchdog_one),
        data_stale_threshold_ms(1, watchdog_one)
    );
    assert_eq!(
        data_stale_threshold_ms(u64::MAX, watchdog_max),
        data_stale_threshold_ms(KEEP_ALIVE_MAX_SECS, watchdog_max)
    );
}

/// `claim_log_window_counted` must treat the bin's `NEVER_LOGGED` sentinel as
/// "never claimed": a `0`-initialised slot would swallow the first window, and
/// the client's per-connection failure lines exist for exactly the
/// startup/reconnect burst. The same contract the server bin locks from
/// `reporter::NEVER_LOGGED`.
#[test]
fn never_logged_sentinel_claims_immediately() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let last = AtomicU64::new(NEVER_LOGGED);
    let suppressed = AtomicU64::new(0);
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 0),
        Some(0),
        "the first event must always log"
    );
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 999),
        None,
        "the rest of the window is suppressed"
    );
    assert_eq!(suppressed.load(Ordering::Relaxed), 1);
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 1_000),
        Some(1),
        "the next window reports the suppressed count"
    );
}

/// The suppressed suffix is empty for a clean window, so callers append it
/// unconditionally and the common line reads exactly as before.
#[test]
fn suppressed_suffix_is_empty_for_a_clean_window() {
    assert_eq!(Suppressed(0).to_string(), "");
    assert_eq!(
        Suppressed(3).to_string(),
        " (3 similar suppressed in the last second)"
    );
}

/// A one-slot pool is the legacy single-TCP-connection mode: every flow,
/// pinned or bulk, resolves to slot 0 no matter what the liveness bit says.
/// UDP still gets its own connection(s) past the TCP range, so even the
/// legacy mode keeps the classes off one congestion window.
#[test]
fn pool_of_one_slot_always_routes_to_slot_zero() {
    let pool = ConnPool::new(1, vec![], true, true, 1);
    assert_eq!(pool.tcp_slots(), 1);
    assert_eq!(pool.udp_global_slot(0), 1);
    assert_eq!(pool.udp_global_slot(1), 2);
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
        ConnPool::new(999, vec![], true, true, 1).tcp_slots(),
        MAX_POOL_CONNS
    );
    assert_eq!(ConnPool::new(0, vec![], true, true, 1).tcp_slots(), 1);
    // Clamping holds for the physical registry too — `tcp + 1 + shards` slots
    // with the split on (the shard count itself clamps at
    // MAX_UDP_EGRESS_CONNS), `tcp + 1` with it off.
    assert_eq!(
        ConnPool::new(999, vec![], true, true, 1).slots_total(),
        MAX_POOL_CONNS + 2
    );
    assert_eq!(
        ConnPool::new(999, vec![], true, true, 999).slots_total(),
        MAX_POOL_CONNS + 1 + MAX_UDP_EGRESS_CONNS
    );
    assert_eq!(
        ConnPool::new(999, vec![], true, false, 999).slots_total(),
        MAX_POOL_CONNS + 1
    );
    // A zero shard count clamps up to the single bulk connection, so the
    // bulk class always has a dedicated connection with the split on.
    assert_eq!(ConnPool::new(2, vec![], true, true, 0).slots_total(), 4);
}

/// The dedicated UDP slots are outside every TCP range, and the fail-closed
/// policy keeps each binding inside its class's dedicated slots: a datagram
/// is never handed a TCP slot's connection, whatever the rest of the pool is
/// doing.
#[test]
fn udp_egress_is_confined_to_the_dedicated_slots() {
    let pool = ConnPool::new(4, vec![], true, true, 1);
    let ib = pool.udp_bind_shard(EgressClass::Interactive, 0);
    let bb = pool.udp_bind_shard(EgressClass::Bulk, 0);
    assert_eq!((ib.index, bb.index), (0, 1));
    assert_eq!(pool.udp_global_slot(ib.index), 4);
    assert_eq!(pool.udp_global_slot(bb.index), 5);
    assert!(pool.udp_global_slot(0) >= pool.tcp_slots());
    // Bulk rotation can never reach the UDP slots, live or dead.
    for rr in 0..16 {
        let i = select_slot(false, rr, &[true; 4]);
        assert!(i < pool.tcp_slots(), "rr={rr} picked {i}");
    }
    // Fail-closed: exactly one candidate, and it is the binding's own slot.
    let egress = SharedEgress::default();
    let (order, k) = egress.egress_order(&pool, ib);
    assert_eq!((order[0], k), (4, 1), "interactive is confined to slot 4");
    let (order, k) = egress.egress_order(&pool, bb);
    assert_eq!((order[0], k), (5, 1), "bulk is confined to slot 5");

    // Fail-closed with shards: the failover set is the *class's* slots. A
    // sibling bulk shard is still a UDP-only connection, so a dead shard may
    // fail over to one — the isolation contract is UDP-vs-TCP — but the
    // binding never crosses into the interactive class or a TCP slot.
    let sharded = ConnPool::new(4, vec![], true, true, 3);
    let b1 = sharded.udp_bind_shard(EgressClass::Bulk, 1);
    let (order, k) = egress.egress_order(&sharded, b1);
    assert_eq!(k, 3, "own shard plus the two siblings, nothing else");
    assert_eq!(&order[..k], &[6, 5, 7]);
    for &slot in &order[..k] {
        assert!(
            slot >= sharded.tcp_slots(),
            "fail-closed egress picked TCP slot {slot}"
        );
        assert_ne!(
            slot,
            sharded.udp_global_slot(0),
            "fail-closed egress crossed into the interactive class"
        );
    }
    // One interactive shard in this pool: with fail-closed on the class has
    // no sibling to fail over to and stays on its own slot.
    let (order, k) = egress.egress_order(
        &sharded,
        sharded.udp_bind_shard(EgressClass::Interactive, 0),
    );
    assert_eq!((order[0], k), (4, 1));

    // Fallback allowed: own class first (own shard, then siblings), other
    // class, then interactive TCP, then bulk TCP — each slot exactly once.
    let pool = ConnPool::new(4, vec![], false, true, 1);
    let (order, k) = egress.egress_order(&pool, pool.udp_bind_shard(EgressClass::Interactive, 0));
    assert_eq!(k, pool.slots_total());
    assert_eq!(&order[..6], &[4, 5, 0, 1, 2, 3]);
    assert_eq!(
        order[..k]
            .iter()
            .filter(|&&i| i == pool.udp_global_slot(0))
            .count(),
        1
    );
    let (order, _) = egress.egress_order(&pool, pool.udp_bind_shard(EgressClass::Bulk, 0));
    assert_eq!(&order[..6], &[5, 4, 0, 1, 2, 3]);
    // With shards the same walk visits every shard once before the other
    // class's slot: shard 2 is UDP index 3 (the last shard), so its scan is
    // its own slot, then the two earlier shards, then the interactive slot.
    let sharded = ConnPool::new(4, vec![], false, true, 3);
    let (order, k) = egress.egress_order(&sharded, sharded.udp_bind_shard(EgressClass::Bulk, 2));
    assert_eq!(k, sharded.slots_total());
    assert_eq!(&order[..8], &[7, 5, 6, 4, 0, 1, 2, 3]);

    // The split off: both classes share the single slot, TCP after it.
    let pool = ConnPool::new(4, vec![], false, false, 9);
    let (order, k) = egress.egress_order(&pool, pool.udp_bind_shard(EgressClass::Bulk, 0));
    assert_eq!(k, pool.slots_total());
    assert_eq!(&order[..5], &[4, 0, 1, 2, 3]);

    // The one-slot legacy pool still separates the classes.
    let pool = ConnPool::new(1, vec![], true, true, 1);
    let (order, k) = egress.egress_order(&pool, pool.udp_bind_shard(EgressClass::Bulk, 0));
    assert_eq!((order[0], k), (2, 1));
}

/// The class split decision: a known interactive port is interactive
/// whatever the payload size, and an unknown port is interactive only when
/// the first datagram is small enough to be STUN/DTLS/RTP-sized media.
#[test]
fn udp_class_splits_by_port_and_first_payload() {
    let pool = ConnPool::new(1, vec![53, 3478], true, true, 1);
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

/// `udp_bulk_ports` forces the bulk class regardless of the first payload
/// size: a VPN tunnel's handshake is small (WireGuard's first packet is 148 B),
/// so the size heuristic alone would keep the whole tunnel on the single
/// interactive connection next to DNS/STUN/games, where it can never use the
/// bulk shards. `interactive_ports` keeps precedence, and an empty bulk list
/// restores the pure size heuristic.
#[test]
fn udp_bulk_ports_force_bulk_regardless_of_first_payload() {
    let ip = |port| TargetAddrRef::Ip(SocketAddr::from(([203, 0, 113, 7], port)));
    let pool = ConnPool::new_with_bulk_ports(
        1,
        vec![53, 3478],
        vec![51820, 1194],
        true,
        true,
        1,
        1,
        data_stale_threshold_ms(5, 40),
    );
    // WireGuard's 148 B handshake must not be mistaken for interactive.
    assert_eq!(pool.udp_class(&ip(51820), 148), EgressClass::Bulk);
    // ...OpenVPN's data port too, and a full-size payload stays bulk anyway.
    assert_eq!(pool.udp_class(&ip(1194), 148), EgressClass::Bulk);
    assert_eq!(pool.udp_class(&ip(1194), 1200), EgressClass::Bulk);
    // The same small payload on an unknown port keeps the size heuristic.
    assert_eq!(pool.udp_class(&ip(51999), 148), EgressClass::Interactive);
    // Interactive precedence: a port listed in both classes stays interactive
    // (the operator's explicit latency-sensitive intent wins).
    let both = ConnPool::new_with_bulk_ports(
        1,
        vec![443],
        vec![443],
        true,
        true,
        1,
        1,
        data_stale_threshold_ms(5, 40),
    );
    assert_eq!(both.udp_class(&ip(443), 1200), EgressClass::Interactive);
    // A domain target classifies by its port the same way.
    assert_eq!(
        pool.udp_class(&TargetAddrRef::Domain("vpn.example.com", 51820), 148),
        EgressClass::Bulk
    );
    // `ConnPool::new` passes an empty bulk list: the override is off and the
    // same WireGuard-sized payload keeps the pre-existing size classification.
    let plain = ConnPool::new(1, vec![53], true, true, 1);
    assert_eq!(plain.udp_class(&ip(51820), 148), EgressClass::Interactive);
    assert_eq!(plain.udp_class(&ip(1194), 148), EgressClass::Interactive);
    assert_eq!(plain.udp_class(&ip(51820), 1200), EgressClass::Bulk);
}

/// Bulk associations rotate over the shard set and never onto another
/// class's slot; a zero shard count clamps up (the bulk class always owns at
/// least one dedicated connection with the split on). This pool has one
/// interactive shard, so the interactive cursor stays on index 0 — the
/// multi-shard case is `interactive_associations_rotate_over_their_own_shards`.
#[test]
fn bulk_associations_rotate_over_the_shard_set() {
    let pool = ConnPool::new(3, vec![], true, true, 3);
    assert_eq!(pool.udp_slot_count(), 4);
    let idx: Vec<usize> = (0..7)
        .map(|_| pool.udp_bind(EgressClass::Bulk).index)
        .collect();
    assert_eq!(idx, vec![1, 2, 3, 1, 2, 3, 1], "rotation, not hashing");
    // A single interactive shard: the cursor does not matter.
    for _ in 0..4 {
        assert_eq!(pool.udp_bind(EgressClass::Interactive).index, 0);
    }
    // Every shard binding resolves to its own slot inside the UDP range.
    for shard in 0..3 {
        let b = pool.udp_bind_shard(EgressClass::Bulk, shard);
        assert_eq!(b.index, 1 + shard);
        assert_eq!(pool.udp_global_slot(b.index), pool.tcp_slots() + 1 + shard);
    }
    // Explicit shard keys reduce modulo the count.
    assert_eq!(pool.udp_bind_shard(EgressClass::Bulk, 7).index, 1 + 7 % 3);

    // A zero count clamps up to one shard; a huge count clamps down to the
    // scratch-array cap.
    let clamped = ConnPool::new(3, vec![], true, true, 0);
    assert_eq!(clamped.udp_bind_shard(EgressClass::Bulk, 0).index, 1);
    assert!(clamped.udp_bind(EgressClass::Bulk).index <= MAX_UDP_EGRESS_CONNS);
    let capped = ConnPool::new(3, vec![], true, true, usize::MAX);
    assert_eq!(capped.slots_total(), 3 + 1 + MAX_UDP_EGRESS_CONNS);

    // `udp_split` off ignores the shard count: one shared slot for both.
    let shared = ConnPool::new(3, vec![], true, false, 8);
    assert_eq!(shared.udp_slot_count(), 1);
    assert_eq!(shared.udp_bind(EgressClass::Bulk).index, 0);
    assert_eq!(shared.udp_bind(EgressClass::Interactive).index, 0);
    assert_eq!(shared.udp_bind_shard(EgressClass::Bulk, 3).index, 0);
}

/// The interactive class is sharded too: every interactive slot is a separate
/// QUIC connection with its own 1 MiB DATAGRAM buffer, 256 KiB stager and
/// congestion window, so N small-packet associations spread over min(N, k)
/// connections instead of queueing behind one another on a single one.
#[test]
fn interactive_associations_rotate_over_their_own_shards() {
    // 3 TCP + 2 interactive + 2 bulk.
    let pool = ConnPool::new_with_bulk_ports(
        3,
        vec![],
        vec![],
        true,
        true,
        2,
        2,
        data_stale_threshold_ms(5, 40),
    );
    assert_eq!(pool.udp_slot_count(), 4);
    assert_eq!(pool.interactive_shards(), 2);
    assert_eq!(pool.slots_total(), 7);

    // Interactive: indices 0..2, rotating on its own cursor.
    let interactive: Vec<usize> = (0..5)
        .map(|_| pool.udp_bind(EgressClass::Interactive).index)
        .collect();
    assert_eq!(interactive, vec![0, 1, 0, 1, 0]);
    // Bulk: indices 2..4. Its cursor is independent, so the bulk burst above
    // cannot shift an interactive binding.
    let bulk: Vec<usize> = (0..5)
        .map(|_| pool.udp_bind(EgressClass::Bulk).index)
        .collect();
    assert_eq!(bulk, vec![2, 3, 2, 3, 2]);
    assert_eq!(pool.udp_bind(EgressClass::Interactive).index, 1);

    // The class ranges are the fail-closed boundary.
    assert_eq!(pool.udp_class_slots(EgressClass::Interactive), 0..2);
    assert_eq!(pool.udp_class_slots(EgressClass::Bulk), 2..4);
    // Explicit shard keys reduce modulo the class's own count.
    assert_eq!(pool.udp_bind_shard(EgressClass::Interactive, 5).index, 1);
    assert_eq!(pool.udp_bind_shard(EgressClass::Bulk, 5).index, 3);

    // Every interactive slot is its own pool slot past the TCP range.
    for i in 0..2 {
        assert_eq!(pool.udp_global_slot(i), 3 + i);
    }

    // One interactive shard restores the legacy single stable connection, and
    // the class then rotates on index 0 only.
    let single = ConnPool::new_with_bulk_ports(
        3,
        vec![],
        vec![],
        true,
        true,
        1,
        2,
        data_stale_threshold_ms(5, 40),
    );
    assert_eq!(single.udp_slot_count(), 3);
    for _ in 0..4 {
        assert_eq!(single.udp_bind(EgressClass::Interactive).index, 0);
    }

    // `udp_split = false` collapses both classes onto the shared slot.
    let shared = ConnPool::new_with_bulk_ports(
        3,
        vec![],
        vec![],
        true,
        false,
        4,
        4,
        data_stale_threshold_ms(5, 40),
    );
    assert_eq!(shared.udp_slot_count(), 1);
    assert_eq!(shared.udp_bind(EgressClass::Interactive).index, 0);
    assert_eq!(shared.udp_class_slots(EgressClass::Bulk), 0..1);
}

/// Two egress bindings never share a cached handle: a handle published for
/// the interactive class must not serve a fail-closed bulk association, nor a
/// sibling bulk shard whatever its class, or the sharding would collapse back
/// onto one connection.
#[tokio::test]
async fn egress_bindings_do_not_share_cached_handles() {
    let (conn, _c, _s) = real_connection().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 2);
    let e = SharedEgress::default();
    let now = mono_millis();
    // Three bindings, three independent caches: the interactive slot and the
    // two bulk shards.
    let ib = pool.udp_bind_shard(EgressClass::Interactive, 0);
    let b0 = pool.udp_bind_shard(EgressClass::Bulk, 0);
    let b1 = pool.udp_bind_shard(EgressClass::Bulk, 1);
    assert_eq!((ib.index, b0.index, b1.index), (0, 1, 2));
    e.cached[ib.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: pool.udp_global_slot(ib.index),
        rev2: rev2_state(),
    })));
    // The interactive binding serves its live handle ...
    let got = e.acquire(&pool, ib, now).expect("interactive handle");
    assert_eq!(got.conn.stable_id(), conn.stable_id());
    // ... while a fail-closed bulk binding, whose own slot has no connection,
    // gets nothing — never the interactive handle, and never a sibling
    // shard's cache either.
    for bulk in [b0, b1] {
        assert!(
            e.acquire(&pool, bulk, now).is_none(),
            "a fail-closed bulk binding must not borrow another binding's handle"
        );
        assert!(e.cached[bulk.index].load().is_none());
    }
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
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let e = SharedEgress::default();
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let now = mono_millis();
    // Probe past the refresh window: a stamp of `now` read at
    // `now + EGRESS_REFRESH_MS` is exactly expired. (Computing the stamp
    // as `now - EGRESS_REFRESH_MS` saturates to 0 on a fast test clock
    // and reads back as fresh.)
    let expired_now = now + EGRESS_REFRESH_MS;
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: pool.udp_global_slot(class.index),
        rev2: rev2_state(),
    })));
    e.generation[class.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    // Hold the single-flight gate: `refresh_global` returns None, so
    // `acquire` must decide on the loser path alone.
    e.refreshing[class.index].store(true, std::sync::atomic::Ordering::Release);

    // Live expired handle: reused, cache kept.
    let got = e
        .acquire(&pool, class, expired_now)
        .expect("a live expired handle must still be served");
    assert_eq!(got.conn.stable_id(), conn.stable_id());
    assert!(e.cached[class.index].load().is_some());

    // Dead expired handle: dropped, cache invalidated (generation bumped
    // so every thread's memo misses), never handed out for a doomed send.
    conn.close(0u32.into(), b"test");
    assert!(
        conn.close_reason().is_some(),
        "the test's closed handle must probe dead"
    );
    let gen_before = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    assert!(
        e.acquire(&pool, class, expired_now).is_none(),
        "a dead expired handle must not be served"
    );
    assert!(
        e.cached[class.index].load().is_none(),
        "the dead handle must be invalidated"
    );
    assert_eq!(
        e.generation[class.index].load(std::sync::atomic::Ordering::Acquire),
        gen_before + 1,
        "invalidation must bump the generation so memos miss"
    );
    e.refreshing[class.index].store(false, std::sync::atomic::Ordering::Release);
}

/// Loopback QUIC endpoint pair through the same public TLS/transport
/// helpers `main` uses, for tests that need a real `quinn::Connection`.
/// The endpoints are returned alongside the client connection because
/// dropping them closes it.
async fn real_connection() -> (quinn::Connection, quinn::Endpoint, quinn::Endpoint) {
    let (conn, _server_conn, client, server) = real_connection_with_server().await;
    (conn, client, server)
}

/// [`real_connection`] plus the accepted server-side handle, so a datagram
/// test can read exactly what the client queued.
async fn real_connection_with_server() -> (
    quinn::Connection,
    quinn::Connection,
    quinn::Endpoint,
    quinn::Endpoint,
) {
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
    scfg.transport_config(build_transport(Congestion::Bbr, 5));
    let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client_tls = client_tls_config(certified.cert.der().clone(), &alpn).unwrap();
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
    let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
    ccfg.transport_config(build_transport(Congestion::Bbr, 5));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(ccfg);

    let accept = async {
        let incoming = server.accept().await.unwrap();
        incoming.accept().unwrap().await.unwrap()
    };
    let (conn, server_conn) =
        tokio::join!(client.connect(server_addr, "test.com").unwrap(), accept);
    (conn.unwrap(), server_conn, client, server)
}

/// A single staged client payload must flush as a plain `0x02` datagram, not
/// a BATCH wrapper: a run of one is the steady shape of DNS/STUN request and
/// response traffic, and the wrapper would add a count byte plus a length
/// prefix for no sharing.
#[tokio::test]
async fn client_single_staged_payload_flushes_as_plain_datagram() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let body = &b"single-query"[..];
    let p = PendingBatch::new(bind, body.len());
    let limit = client_conn.max_datagram_size().unwrap();
    let mut frag = DgramFragmenter::new();
    let sent = flush_pending_batch(&client_conn, 7, &mut frag, &addr.as_ref(), &p, body, limit);
    assert!(sent.complete(), "a small staged payload must be accepted");

    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the single payload must arrive")
        .unwrap();
    assert!(
        !is_batch(&d),
        "a run of one must stay a plain 0x02 datagram"
    );
    let (sess, decoded_addr, payload) =
        decode_datagram_ref(&d).expect("the single frame must decode");
    assert_eq!(sess, 7);
    assert_eq!(payload, body, "the payload must be sent verbatim");
    match decoded_addr {
        TargetAddrRef::Ip(a) => assert_eq!(a, addr.socket_addr().unwrap()),
        other => panic!("an IP destination must stay IP-form: {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server_conn.read_datagram())
            .await
            .is_err(),
        "one staged payload must produce exactly one frame"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The client-side N-pack flush: one BATCH frame carries every staged payload
/// in order, under the association's session id and shared destination.
#[tokio::test]
async fn client_n_pack_flushes_one_ordered_batch_frame() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let bodies: Vec<Vec<u8>> = (0..MAX_BATCH_ITEMS)
        .map(|i| format!("item-{i:02}").into_bytes())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let mut arena = Vec::new();
    let mut p = PendingBatch::new(bind, refs[0].len());
    arena.extend_from_slice(refs[0]);
    for (i, body) in refs.iter().enumerate().skip(1) {
        p.lens[i] = body.len() as u16;
        p.n += 1;
        arena.extend_from_slice(body);
    }
    assert_eq!(p.n, MAX_BATCH_ITEMS, "the test stages a full run");

    let limit = client_conn.max_datagram_size().unwrap();
    let mut frag = DgramFragmenter::new();
    let sent = flush_pending_batch(
        &client_conn,
        7,
        &mut frag,
        &addr.as_ref(),
        &p,
        &arena,
        limit,
    );
    assert!(sent.complete(), "a full small run must fit one frame");

    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the batch frame must arrive")
        .unwrap();
    assert!(is_batch(&d), "the staged run must ride one BATCH frame");
    let b = decode_batch_ref(&d).expect("the frame must decode as a batch");
    assert_eq!(b.sess, 7);
    assert_eq!(
        b.payloads, refs,
        "a batch must preserve staging order exactly"
    );
    match b.addr {
        TargetAddrRef::Ip(a) => assert_eq!(a, addr.socket_addr().unwrap()),
        other => panic!("an IP destination must stay IP-form: {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server_conn.read_datagram())
            .await
            .is_err(),
        "a staged run must produce exactly one frame, not one per payload"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// MQP-3 rev2 uplink state machine over a real QUIC connection: an unknown
/// target's first payload is `DATA OPEN` (session + address), every payload
/// before the ack repeats the OPEN (idempotent server-side), and after the ack
/// a payload is a 2-byte-header steady `DATA` while several queued payloads of
/// the open flow become one `TRAIN` on the connection-scoped stager.
#[tokio::test]
async fn client_rev2_open_until_ack_then_steady_and_train() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    let send = |body: &[u8], up: &mut UplinkFlows, frag: &mut R2Fragmenter| {
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            body,
            bind,
            &rev2,
            up,
            frag,
        )
    };

    // (1) First payload: standalone OPEN with session + address. The stager
    // only queues it; the drain (the association's burst end in production)
    // writes it.
    assert!(send(b"one", &mut up, &mut frag).complete());
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the open frame must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the first frame must be rev2 DATA");
    let id = f.id.expect("an unbound target opens a flow");
    assert!(!r2::wire_id_server_owned(id), "the client owns the id");
    assert_eq!(f.sess, Some(7));
    assert_eq!(f.addr, Some(addr.as_ref()));
    assert_eq!(f.payload, b"one");
    assert!(!f.src, "an uplink OPEN names the destination, not a source");
    let binding = rev2.registry.get(id).expect("the flow is in the registry");
    assert_eq!(binding.state(), FlowState::Opening);

    // (2) Still Opening: the next payload repeats OPEN (a lost open/ack must
    // only delay compression, never delivery).
    assert!(send(b"two", &mut up, &mut frag).complete());
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the repeated open must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the repeat must be rev2 DATA");
    assert_eq!(f.id, Some(id));
    assert_eq!(f.sess, Some(7));
    assert_eq!(f.addr, Some(addr.as_ref()));
    assert_eq!(f.payload, b"two");

    // (3) ACK observed (`FLOW_ACK` or any compressed downlink): steady DATA
    // with only the wire id, a 2-byte header for ids below 64.
    binding.mark_open();
    assert!(send(b"three", &mut up, &mut frag).complete());
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the steady frame must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the committed frame must be rev2 DATA");
    assert_eq!(f.id, Some(id));
    assert_eq!(f.sess, None, "steady frames carry no session");
    assert_eq!(f.addr, None, "steady frames carry no address");
    assert_eq!(f.payload, b"three");
    assert_eq!(
        d.len(),
        1 + r2::varint_len(id) + b"three".len(),
        "a confirmed flow costs only the id"
    );

    // (4) Two queued payloads of the same open flow are packed into one TRAIN
    // by the connection stager (dict form: a cross-session train may carry
    // several wire ids).
    assert!(send(b"aaaa", &mut up, &mut frag).complete());
    assert!(send(b"bb", &mut up, &mut frag).complete());
    assert_eq!(rev2.stage_len(), 2, "both payloads wait for the drain");
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the train frame must arrive")
        .unwrap();
    let t = r2::decode_train(&d).expect("the frame must be a rev2 TRAIN");
    assert_eq!(t.form, r2::R2_TRAIN_FORM_DICT);
    assert_eq!(t.count, 2);
    let items: Vec<(u32, &[u8])> = t.items().collect();
    assert_eq!(items, vec![(id, &b"aaaa"[..]), (id, &b"bb"[..])]);
    assert_eq!(rev2.stage_len(), 0, "a drain empties the queue");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A domain target uses the same rev2 small-packet path: `DATA OPEN` carries
/// `TargetAddr::Domain`, the server resolves and ACKs, and the next frame is a
/// compressed steady `DATA` (the SOCKS5 reply source is learned from the
/// downlink `OPEN|SRC`, see the dispatcher tests).
#[tokio::test]
async fn client_rev2_domain_flow_opens_with_domain_addr() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Domain("example.com".to_string(), 53);
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            11,
            &addr.as_ref(),
            b"query",
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the domain open must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the frame must be rev2 DATA");
    let id = f.id.expect("a domain target opens a flow");
    assert_eq!(f.sess, Some(11));
    assert_eq!(f.addr, Some(TargetAddrRef::Domain("example.com", 53)));

    rev2.registry.get(id).unwrap().mark_open();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            11,
            &addr.as_ref(),
            b"query2",
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the compressed domain frame must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the steady frame must be rev2 DATA");
    assert_eq!(f.id, Some(id));
    assert_eq!(
        f.addr, None,
        "a resolved domain flow compresses like an IP one"
    );
    assert_eq!(f.payload, b"query2");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Registry full ⇒ `DATA INLINE` (session + address), the fail-safe that never
/// blocks the association; nothing half-bound is left in the session table.
#[tokio::test]
async fn client_rev2_inline_fallback_when_registry_full() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let filler = TargetAddr::Ip("192.0.2.1:1".parse().unwrap());
    for i in 1..=R2_MAX_FLOWS_PER_CONN as u32 {
        let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 1, filler.clone());
        assert!(rev2.registry.insert(b).is_ok());
    }
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            b"inline",
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    assert!(
        up.flows.is_empty(),
        "the fallback must not half-bind a flow"
    );
    assert_eq!(
        rev2.ids.allocated(),
        0,
        "the INLINE fail-safe must not consume a never-reused wire id"
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the inline frame must arrive")
        .unwrap();
    let f = r2::decode_data(&d).expect("the fallback frame must be rev2 DATA");
    assert_eq!(f.id, None, "INLINE carries no wire id");
    assert_eq!(f.sess, Some(7));
    assert_eq!(f.addr, Some(addr.as_ref()));
    assert_eq!(f.payload, b"inline");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// `CTL HELLO` immediately after the connection, retried until the server's
/// `CAPS`; only then does the connection become usable for rev2 udp.
#[tokio::test]
async fn rev2_handshake_negotiates_caps() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = Arc::new(ConnRev2::new());
    assert!(!state.is_ready());
    // The production dispatcher is what receives `CAPS`; drive the same
    // `handle_r2_ctl` path from a reader task here.
    let client_for_reader = client_conn.clone();
    let reader_state = state.clone();
    let reader_hub = UdpHub::new();
    let reader = tokio::spawn(async move {
        while !reader_state.is_ready() {
            let Ok(d) = client_for_reader.read_datagram().await else {
                return;
            };
            if r2::kind(&d) == Some(r2::R2Kind::Ctl) {
                handle_r2_ctl(
                    &reader_state,
                    &reader_hub,
                    &mut myquic2::udp::R2Reassembler::new(),
                    &d,
                );
            }
        }
    });
    let server = tokio::spawn(async move {
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("the client must send HELLO")
            .unwrap();
        match r2::decode_ctl(&d).expect("HELLO must decode") {
            r2::Ctl::Hello { wire_ver, .. } => {
                assert_eq!(wire_ver, r2::R2_WIRE_VER, "HELLO advertises wire_ver=2");
            }
            other => panic!("first CTL must be HELLO, got {other:?}"),
        }
        server_conn
            .send_datagram(r2::encode_ctl(&r2::Ctl::Caps(r2::Caps::default())))
            .expect("CAPS must be sendable");
        server_conn
    });
    assert!(rev2::handshake(&client_conn, &state).await);
    assert!(state.is_ready());
    assert_eq!(
        state.ctl.caps().map(|c| c.max_frame_bytes),
        Some(r2::R2_DEFAULT_MAX_FRAME_BYTES),
        "CAPS limits are stored on the connection state"
    );
    reader.abort();
    let server_conn = server.await.unwrap();
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A `CAPS` with another wire version is a definitive mismatch: fail fast
/// instead of waiting out the window. There is no silent old-wire fallback.
#[tokio::test]
async fn rev2_handshake_fails_fast_on_wire_version_mismatch() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = ConnRev2::new();
    // The production dispatcher is what receives `CAPS`; drive the same
    // `handle_r2_ctl` path from a reader task here (without it the answer never
    // reaches the connection state and the test would be exercising the window
    // instead of the version mismatch).
    let client_for_reader = client_conn.clone();
    let reader_state = state.clone();
    let hub = UdpHub::new();
    let reader = tokio::spawn(async move {
        while !reader_state.is_ready() {
            let Ok(d) = client_for_reader.read_datagram().await else {
                return;
            };
            if r2::kind(&d) == Some(r2::R2Kind::Ctl) {
                handle_r2_ctl(
                    &reader_state,
                    &hub,
                    &mut myquic2::udp::R2Reassembler::new(),
                    &d,
                );
            }
        }
    });
    let server = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("the client must send HELLO")
            .unwrap();
        server_conn
            .send_datagram(r2::encode_ctl(&r2::Ctl::Caps(r2::Caps {
                wire_ver: 9,
                ..r2::Caps::default()
            })))
            .expect("CAPS must be sendable");
        server_conn
    });
    assert!(
        !rev2::handshake(&client_conn, &state).await,
        "a version mismatch must fail the handshake"
    );
    assert!(!state.is_ready());
    reader.abort();
    let server_conn = server.await.unwrap();
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Read the next downlink datagram that is not a rev2 `CTL` frame.
///
/// The W2 tests run a background `HELLO` retry, so HELLOs interleave with the
/// DATA frames these tests assert on.
async fn read_next_data(conn: &quinn::Connection) -> Bytes {
    loop {
        let d = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("a frame must arrive")
            .unwrap();
        if r2::kind(&d) != Some(r2::R2Kind::Ctl) {
            return d;
        }
    }
}

/// W2: no `CAPS` at all must **never** fail a live connection.
///
/// The fast window is only a negotiation-retry bound: the handshake reports the
/// connection usable, keeps advertising `HELLO` in the background at the slow
/// cadence, and the data path keeps working on the boot limits
/// (`frame_limit` falls back to the connection's DATAGRAM budget, the stager
/// keeps the codec's train bound), so pre-`CAPS`/0-RTT datagrams are unaffected.
#[tokio::test]
async fn rev2_handshake_without_caps_keeps_the_connection_usable() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = ConnRev2::new();
    let before = counters::snapshot();
    assert!(
        rev2::handshake_with(
            &client_conn,
            &state,
            Duration::from_millis(40),
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await,
        "a missing CAPS must not tear the connection down"
    );
    assert!(!state.is_ready(), "no CAPS has arrived");
    assert!(
        counters::since(&before).handshake_slow >= 1,
        "the slow background retry is the non-fatal outcome"
    );
    // The background retry keeps the negotiation alive: the foreground loop is
    // gone (we are past its return), so any further HELLO can only come from
    // the spawned retry. `hello_tx` is a process-wide counter, hence `> 0`.
    let before_hello = counters::snapshot();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        counters::since(&before_hello).hello_tx > 0,
        "a lost CAPS must be recovered by another HELLO, not a redial"
    );
    // ... and the connection carries rev2 DATA with no negotiated caps at all.
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            b"no-caps-payload",
            bind,
            &state,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    drain_now(&state, &client_conn, limit);
    let d = read_next_data(&server_conn).await;
    let f = r2::decode_data(&d).expect("the payload must be rev2 DATA");
    assert_eq!(f.payload, b"no-caps-payload");
    assert!(
        client_conn.close_reason().is_none(),
        "the producer side must still consider the connection live"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// W2: a **late** `CAPS` (after the fast window) still completes the
/// negotiation on the same connection — the background retry is what recovers
/// it, with no redial and no flow loss.
#[tokio::test]
async fn late_caps_completes_the_negotiation_without_a_redial() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = ConnRev2::new();
    let hub = UdpHub::new();
    let client_for_reader = client_conn.clone();
    let reader_state = state.clone();
    let reader = tokio::spawn(async move {
        while !reader_state.is_ready() {
            let Ok(d) = client_for_reader.read_datagram().await else {
                return;
            };
            if r2::kind(&d) == Some(r2::R2Kind::Ctl) {
                handle_r2_ctl(
                    &reader_state,
                    &hub,
                    &mut myquic2::udp::R2Reassembler::new(),
                    &d,
                );
            }
        }
    });
    let before = counters::snapshot();
    assert!(
        rev2::handshake_with(
            &client_conn,
            &state,
            Duration::from_millis(40),
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
    );
    assert!(!state.is_ready());
    // The server's answer arrives after the fast window: this is exactly the
    // lost-negotiation-packet case W2 exists for.
    server_conn
        .send_datagram(r2::encode_ctl(&r2::Ctl::Caps(r2::Caps {
            max_train_items: 8,
            ..r2::Caps::default()
        })))
        .unwrap();
    for _ in 0..5_000 {
        if state.is_ready() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(state.is_ready(), "a late CAPS must still be applied");
    assert_eq!(
        state.ctl.caps().map(|c| c.max_train_items),
        Some(8),
        "the late CAPS tunes the same limits as an early one"
    );
    // The background retry notices `ready` at its next tick (the slow cadence
    // in this test is 20 ms), so poll for its success booking.
    let mut booked = false;
    for _ in 0..100 {
        if counters::since(&before).handshake_ok >= 1 {
            booked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        booked,
        "the background retry books the late completion as a success"
    );
    assert!(
        client_conn.close_reason().is_none(),
        "the connection is never closed for a late CAPS"
    );
    // The retry stops once ready: after the in-flight HELLO(s), no more arrive.
    for _ in 0..8 {
        let _ = tokio::time::timeout(Duration::from_millis(20), server_conn.read_datagram()).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server_conn.read_datagram())
            .await
            .is_err(),
        "the background HELLO retry must stop once CAPS arrived"
    );
    reader.abort();
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// W2: the fail-fast for an explicit wrong wire version is preserved even when
/// the answer arrives after the fast window — the background retry closes the
/// connection itself, exactly the verdict the foreground loop would produce.
#[tokio::test]
async fn wrong_version_caps_after_the_fast_window_still_fails_fast() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = ConnRev2::new();
    let hub = UdpHub::new();
    let client_for_reader = client_conn.clone();
    let reader_state = state.clone();
    let reader = tokio::spawn(async move {
        while client_for_reader.close_reason().is_none() {
            let Ok(d) = client_for_reader.read_datagram().await else {
                return;
            };
            if r2::kind(&d) == Some(r2::R2Kind::Ctl) {
                handle_r2_ctl(
                    &reader_state,
                    &hub,
                    &mut myquic2::udp::R2Reassembler::new(),
                    &d,
                );
            }
        }
    });
    let before = counters::snapshot();
    assert!(
        rev2::handshake_with(
            &client_conn,
            &state,
            Duration::from_millis(40),
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await,
        "the window expiry itself is not a failure"
    );
    server_conn
        .send_datagram(r2::encode_ctl(&r2::Ctl::Caps(r2::Caps {
            wire_ver: r2::R2_WIRE_VER + 7,
            ..r2::Caps::default()
        })))
        .unwrap();
    let mut closed = false;
    for _ in 0..500 {
        if client_conn.close_reason().is_some() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        closed,
        "an explicit wrong-version CAPS must still close the connection"
    );
    assert!(
        counters::since(&before).handshake_fail >= 1,
        "a wrong-version answer is still a handshake failure"
    );
    reader.abort();
    server_conn.close(0u32.into(), b"done");
}

/// byte-identical to what `encode_reply` produces in one buffer.
///
/// This is the path the two-iovec change rewrote (the payload used to be
/// concatenated into a full-size arena per reply), and it is the one the wire
/// bytes actually depend on: the header lives in a reused `hdrs` buffer, the
/// payload is borrowed from the receive path, and only the pairing built from
/// `offs`/`refs` ties them together. Two associations with *different* relay
/// sockets is the shape that matters — it makes each run length 1, exactly what
/// a multi-association client produces.
#[tokio::test]
async fn flush_staged_sends_header_and_payload_as_one_datagram() {
    // Relay sockets are dual-stack in production (`udp_socket_dual_small`), and
    // the flush maps the app address the same way; binding plain IPv4 sockets
    // here would test a send the production path never performs.
    let mk_relay = || {
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap())
    };
    let apps = [
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let dsts: [SocketAddr; 2] = [
        "198.51.100.1:53".parse().unwrap(),
        "203.0.113.9:3478".parse().unwrap(),
    ];
    let bodies: [&[u8]; 2] = [b"one", b"two-reply"];
    let mut staged = Vec::new();
    for i in 0..2 {
        staged.push(StagedReply {
            sock: Some(mk_relay()),
            app: apps[i].local_addr().unwrap(),
            dst: dsts[i],
            payload: bytes::Bytes::copy_from_slice(bodies[i]),
            raw: false,
            reply_v6: true,
        });
    }
    let mut hdrs: Vec<u8> = Vec::new();
    let mut offs: Vec<(usize, usize)> = Vec::new();
    flush_staged(&mut staged, &mut hdrs, &mut offs);
    assert!(staged.is_empty(), "a flush must clear the staging queue");

    // Each app receives exactly its own reply, byte-for-byte as `encode_reply`
    // would have built it (header first, payload appended).
    let mut buf = [0u8; 128];
    for (i, app) in apps.iter().enumerate() {
        let mut want = Vec::new();
        encode_reply(&mut want, dsts[i], bodies[i]);
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), app.recv_from(&mut buf))
            .await
            .expect("the staged reply must arrive")
            .unwrap();
        assert_eq!(&buf[..n], &want[..], "app {i} reply bytes");
    }
    // Nothing was sent twice: no second datagram is waiting on either socket.
    for (i, app) in apps.iter().enumerate() {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), app.recv_from(&mut buf))
                .await
                .is_err(),
            "app {i} must receive exactly one datagram per staged reply"
        );
    }
}

/// Items of one staged BATCH frame share their run: the head carries the
/// relay `Arc` and the rest inherit it (`None`), and the flush must deliver
/// every item to the one app as its own datagram — one refcount round-trip
/// for the frame, not one per item.
#[tokio::test]
async fn flush_staged_batch_items_share_one_run() {
    let relay = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app.local_addr().unwrap();
    let dsts: [SocketAddr; 3] = [
        "198.51.100.1:53".parse().unwrap(),
        "198.51.100.2:53".parse().unwrap(),
        "198.51.100.3:53".parse().unwrap(),
    ];
    let bodies: [&[u8]; 3] = [b"a", b"bb", b"ccc"];
    let mut staged = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        staged.push(StagedReply {
            sock: if i == 0 { Some(relay.clone()) } else { None },
            app: app_addr,
            dst: dsts[i],
            payload: bytes::Bytes::copy_from_slice(body),
            raw: false,
            reply_v6: true,
        });
    }
    // One extra single for the same app but a *different* relay: it must end
    // the inherited run rather than join it.
    let other = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    staged.push(StagedReply {
        sock: Some(other.clone()),
        app: app_addr,
        dst: dsts[0],
        payload: bytes::Bytes::copy_from_slice(bodies[0]),
        raw: false,
        reply_v6: true,
    });
    // Prime writable readiness on both relays: a freshly registered socket
    // may report `WouldBlock` before its first readiness edge (no syscall
    // ever runs), which would detour the first frame through the detached
    // retry worker and reorder it behind the later frames. The contract
    // tests prime the same way; the primes are drained, never asserted.
    for r in [&relay, &other] {
        r.send_to(b"prime", map_for_dual(app_addr)).await.unwrap();
    }
    let mut prime = [0u8; 8];
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(2), app.recv_from(&mut prime))
            .await
            .expect("priming datagram must arrive")
            .unwrap();
    }
    let mut hdrs: Vec<u8> = Vec::new();
    let mut offs: Vec<(usize, usize)> = Vec::new();
    flush_staged(&mut staged, &mut hdrs, &mut offs);
    assert!(staged.is_empty(), "a flush must clear the staging queue");

    let mut buf = [0u8; 128];
    for want_body in [
        b"a".as_slice(),
        b"bb".as_slice(),
        b"ccc".as_slice(),
        b"a".as_slice(),
    ] {
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), app.recv_from(&mut buf))
            .await
            .expect("every staged item must arrive")
            .unwrap();
        // Header pins the source; body pins the payload: order and pairing
        // must survive the shared run.
        let hlen = match buf.get(3) {
            Some(1) => 10,
            Some(4) => 22,
            _ => panic!("reply must carry an IP-form source"),
        };
        assert_eq!(&buf[hlen..n], want_body, "reply body");
    }
}

/// The memo is served only while it is both current (generation matches)
/// and fresh (stamp inside the window); `invalidate` bumps the generation
/// so every thread's memo misses without a scan. The bindings are
/// independent: a bulk shard's memo never serves the interactive lookup,
/// and never a sibling shard's.
#[tokio::test]
async fn egress_memo_honours_generation_and_freshness() {
    let (conn, _client, _server) = real_connection().await;
    let e = SharedEgress::default();
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let bulk = UdpBind {
        class: EgressClass::Bulk,
        index: 1,
    };
    let sibling = UdpBind {
        class: EgressClass::Bulk,
        index: 2,
    };
    let now = mono_millis();
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    e.generation[class.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    let generation = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    e.memo_store(class, generation, &conn, 1200, now, &rev2_state());
    assert_eq!(e.with_fresh(class, now, |_, limit, _| limit), Some(1200));
    assert!(
        e.with_fresh(bulk, now, |_, _, _| ()).is_none(),
        "a memo stored for one class must not serve the other"
    );
    assert!(
        e.with_fresh(sibling, now, |_, _, _| ()).is_none(),
        "a memo stored for one bulk shard must not serve a sibling shard"
    );
    assert!(
        e.with_fresh(class, now + EGRESS_REFRESH_MS, |_, _, _| ())
            .is_none(),
        "a stamp past the refresh window must miss"
    );
    e.invalidate(class);
    assert!(
        e.with_fresh(class, now, |_, _, _| ()).is_none(),
        "a successful invalidate bumps the generation and drops the memo"
    );
    // A memo tagged before a later bump is not served even while its stamp
    // is still inside the window.
    let old_gen = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    e.memo_store(class, old_gen, &conn, 1200, now, &rev2_state());
    assert!(e.with_fresh(class, now, |_, _, _| ()).is_some());
    e.generation[class.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    assert!(e.with_fresh(class, now, |_, _, _| ()).is_none());
}

/// A memo hit serves the handle whatever the connection's state: liveness is
/// the **send's** verdict, not a per-frame `close_reason` gate.
///
/// The gate this replaces took quinn's connection-state mutex once per uplink
/// frame — the one per-frame cost that cannot parallelize, because the
/// connection driver holds that same mutex while processing every received
/// packet. It bought nothing: a dead handle's next `send_datagram` returns
/// `ConnectionLost`, and `assoc.rs` already invalidates the cache and counts
/// `EGRESS_DEAD` on that arm, exactly as it does for `Unsupported` (which the
/// code deliberately does *not* gate for the same reason). What must not
/// regress is that the hit is still classified: the memo serves, the send
/// fails, and the generation moves so every thread's memo misses next time.
#[tokio::test]
async fn memo_hit_serves_a_dead_handle_and_the_send_reports_it() {
    let (conn, _client, _server) = real_connection().await;
    let e = SharedEgress::default();
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let now = mono_millis();
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    e.generation[class.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    let generation = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    e.memo_store(class, generation, &conn, 1200, now, &rev2_state());
    assert_eq!(
        e.with_fresh(class, now, |_, limit, _| limit),
        Some(1200),
        "a fresh memo hit must be served without a quinn lock"
    );

    // Kill the connection: the memo is still current and fresh, so it still
    // serves — and the send is what reports the death.
    conn.close(0u32.into(), b"test");
    assert!(
        conn.close_reason().is_some(),
        "the test's closed handle must probe dead"
    );
    assert!(
        e.with_fresh(class, now, |_, limit, _| limit).is_some(),
        "liveness is the send's verdict: the memo must not take a per-frame \
         quinn lock to re-check it"
    );
    assert_eq!(
        try_send_datagram(&conn, bytes::Bytes::from_static(b"x")),
        DatagramSend::ConnectionLost,
        "the send must report the death the memo no longer gates on"
    );
    // ... and the caller's `ConnectionLost` arm invalidates, so the next
    // datagram on every thread re-acquires instead of reusing the handle.
    e.invalidate(class);
    assert!(e.with_fresh(class, now, |_, _, _| ()).is_none());
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
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    // A deliberately stale, too-small budget, as if the path MTU had shrunk
    // under a memoized handle.
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: live.saturating_sub(64).max(1),
        stamp_ms: mono_millis(),
        slot: 0,
        rev2: rev2_state(),
    })));
    let gen_before = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    let cached_before = e.cached[class.index].load_full().expect("published above");

    e.refresh_budget(class);

    let after = e.cached[class.index]
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
        e.generation[class.index].load(std::sync::atomic::Ordering::Acquire),
        gen_before + 1,
        "every thread's memo must be invalidated so the new budget is used"
    );

    // And it is a no-op once the budget already matches — the case for a
    // payload past MQP_FRAG_MAX_PAYLOAD, where the fragmenter rejects the
    // datagram before quinn ever sees it and nothing moved.
    let gen_now = e.generation[class.index].load(std::sync::atomic::Ordering::Acquire);
    e.refresh_budget(class);
    assert_eq!(
        e.generation[class.index].load(std::sync::atomic::Ordering::Acquire),
        gen_now,
        "an unchanged budget must not churn the generation"
    );

    // With no cached handle at all it must not resurrect one.
    e.invalidate(class);
    e.refresh_budget(class);
    assert!(
        e.cached[class.index].load().is_none(),
        "refresh_budget never re-picks a connection; that is acquire's job"
    );
}

/// N=1 CONTRACT: steady state pays zero auxiliary quinn takes per frame.
///
/// The per-frame `SendDatagram::poll` lock is irreducible (it lives inside
/// quinn); this test pins everything around it: (a) a memo hit serves without
/// touching the process-wide cache or the single-flight gate, so no `acquire`
/// and no `close_reason`/`max_datagram_size`; (b) a `TooLarge` storm re-reads
/// the live budget at most once per 100 ms window and keeps the handle; (c)
/// `Unsupported` invalidates nothing — the production arm deliberately keeps
/// the memoized handle — so a peer without DATAGRAM support costs one send
/// attempt per datagram and zero re-acquire takes.
#[tokio::test]
async fn steady_n1_pays_zero_auxiliary_quinn_takes() {
    use std::sync::atomic::Ordering;
    let (conn, _client, _server) = real_connection().await;
    let live = conn
        .max_datagram_size()
        .expect("both ends negotiate DATAGRAM");
    let e = SharedEgress::default();
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let now = mono_millis();

    // (a) Memo hit path: publish, tag the memo, and serve repeatedly. A hit
    // must neither bump the generation nor arm the single-flight gate — both
    // would mean an auxiliary quinn take is hiding on the steady path.
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: live,
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    e.generation[class.index].fetch_add(1, Ordering::Release);
    let generation = e.generation[class.index].load(Ordering::Acquire);
    e.memo_store(class, generation, &conn, live, now, &rev2_state());
    for _ in 0..16 {
        assert_eq!(e.with_fresh(class, now, |_, limit, _| limit), Some(live));
    }
    assert_eq!(
        e.generation[class.index].load(Ordering::Acquire),
        generation,
        "memo hits must not mutate shared state"
    );
    assert!(
        !e.refreshing[class.index].load(Ordering::Relaxed),
        "memo hits must never arm the single-flight gate"
    );

    // (b) `TooLarge` storm: a PMTU shrink under a memoized handle. The first
    // verdict re-reads the live budget (one take, one generation bump so every
    // thread picks the new budget up); the rest of the storm inside the
    // 100 ms probe window must change nothing — stale budget kept, no takes.
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: live.saturating_sub(64).max(1),
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    e.generation[class.index].fetch_add(1, Ordering::Release);
    let gen_before = e.generation[class.index].load(Ordering::Acquire);
    e.refresh_budget(class);
    assert_eq!(
        e.cached[class.index]
            .load_full()
            .expect("handle kept")
            .limit,
        live,
        "the first TooLarge of the storm refreshes the budget"
    );
    assert_eq!(
        e.generation[class.index].load(Ordering::Acquire),
        gen_before + 1,
        "exactly one memo invalidation per storm"
    );
    let probed = e.budget_probed_ms[class.index].load(Ordering::Relaxed);
    assert_ne!(probed, 0, "the storm's first probe must stamp the throttle");
    // The storm continues against a budget that shrank again — without the
    // throttle every one of these would take quinn's state lock.
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: live.saturating_sub(64).max(1),
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    let gen_storm = e.generation[class.index].load(Ordering::Acquire);
    for _ in 0..64 {
        e.refresh_budget(class);
    }
    assert_eq!(
        e.budget_probed_ms[class.index].load(Ordering::Relaxed),
        probed,
        "the 100 ms probe window must admit exactly one re-read per storm"
    );
    assert_eq!(
        e.generation[class.index].load(Ordering::Acquire),
        gen_storm,
        "throttled storm verdicts must not churn the generation"
    );
    assert!(
        e.cached[class.index]
            .load_full()
            .expect("handle kept")
            .limit
            != live,
        "a throttled verdict keeps the last known budget, not a fresh take"
    );

    // (c) `Unsupported`: the production arm counts the drop and keeps the
    // handle — no invalidate, no re-acquire. Model that arm (doing nothing)
    // and assert the steady path is undisturbed.
    let gen_unsupported = e.generation[class.index].load(Ordering::Acquire);
    e.memo_store(class, gen_unsupported, &conn, live, now, &rev2_state());
    // ... production `Unsupported` arm runs here: bump EGRESS_DEAD only ...
    assert_eq!(
        e.generation[class.index].load(Ordering::Acquire),
        gen_unsupported,
        "Unsupported must not invalidate: a re-acquire could only add two \
         takes per datagram without finding a better slot"
    );
    assert!(
        e.with_fresh(class, now, |_, _, _| ()).is_some(),
        "the memo stays servable across Unsupported verdicts"
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
    dns_neg_cache_seed(host, port).await;
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
    assert_eq!(d.dns_budget, 0, "no budget was spent");
    assert_eq!(d.session_full, 0, "no budget was spent");
    hub.release(sess);
}

/// P1-4 slow-path budget lock, `DNS_BUDGET` arm: a 40-burst at one uncached
/// name with the 1024-permit budget exhausted counts every datagram exactly
/// once on `DNS_BUDGET` — the countable loss budget for the *resolver's* pool,
/// which is shared with the server's TCP dial path and must not be reported as
/// session-capacity exhaustion. The dispatcher's single guard
/// (`try_acquire_owned` only, no `available_permits` probe) charges one count
/// per datagram: a freed-between-probe-and-acquire permit stays usable and
/// exhaustion is counted once.
#[tokio::test]
async fn dispatch_limiter_exhaustion_counts_dns_budget_exactly_once_per_drop() {
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
        d.dns_budget, 40,
        "a 40-burst over budget counts every datagram exactly once"
    );
    assert_eq!(
        d.session_full, 0,
        "a resolver-budget refusal is not session-capacity exhaustion: charging \
         it to `session_full` reported a slow upstream as a full host"
    );
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
    // Synchronous scope only: snapshotted before any await, so the spawned
    // task cannot have run yet — the caller owns nothing, records no pin,
    // delivers nothing, counts nothing.
    let sync = dgram_drops::snapshot().since(&before);
    assert_eq!(sync.refused, 0, "uncached is not refusal");
    assert_eq!(sync.dns_budget, 0, "budget was available");
    assert_eq!(sync.session_full, 0, "budget was available");
    assert!(
        no_reply(&a.app).await,
        "the caller delivers nothing; the spawned task owns this datagram"
    );
    // The spawn owned the resolution: an unresolvable name settles as a
    // negative cache entry, and the failed owner counts its own datagram
    // exactly once on `REFUSED` (no queued followers here to drop), so the
    // next datagram refuses without spawning again.
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
    // Counter-driven settle: the owner's bump runs in the spawned task right
    // after the failed resolution, a breath after the negative verdict above.
    let mut counted = false;
    for _ in 0..100 {
        if dgram_drops::snapshot().since(&before).refused >= 1 {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(counted, "the failed owner must count its datagram");
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(d.refused, 1, "one failed waiter counts exactly once");
    assert_eq!(d.dns_budget, 0, "budget was available");
    assert_eq!(d.session_full, 0, "budget was available");
    hub.release(sess);
}

/// A burst at an unresolvable name must count every datagram exactly once.
///
/// Every datagram spawns its own waiter; the waiters coalesce into one
/// upstream query that fails, and each waiter counts its payload on `REFUSED`
/// exactly once — there is no queue left for a follower to strand in, and no
/// follower is counted twice.
///
/// Holds `DNS_SLOW_PATH_COUNTER_LOCK` like every other slow-path counter
/// test; `.invalid` never resolves (RFC 2606), so the waiters
/// deterministically take the failure path on both the `None` and the `Err`
/// arms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_failed_name_counts_every_waiter_exactly_once() {
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let (host, port) = ("dispatch-fail-followers.invalid", 19534u16);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the name is uncached"
    );
    assert!(
        dns_slow_path_limiter().available_permits() > 0,
        "premise: the slow-path budget is available"
    );
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let before = dgram_drops::snapshot();
    const BURST: usize = 8;
    for _ in 0..BURST {
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram_domain(sess, host, port, b"fail"),
            &mut reasm,
            &mut pkt,
        );
    }
    assert!(no_reply(&a.app).await, "a failed name relays nothing");
    // Counter-driven settle: each waiter's counted drop runs right after the
    // shared resolution fails, so `refused == BURST` proves every waiter ran.
    let mut settled = false;
    for _ in 0..150 {
        if dgram_drops::snapshot().since(&before).refused >= BURST as u64 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(settled, "every spawned waiter must count its own datagram");
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.refused, BURST as u64,
        "each waiter counts exactly once on REFUSED"
    );
    assert_eq!(d.dns_budget, 0, "budget was available");
    assert_eq!(d.session_full, 0, "budget was available");
    hub.release(sess);
}

/// L2 DNS single-flight burst delivery (dispatch path).
///
/// Cold 40-datagram same-host burst through `dispatch_one`, mirroring the
/// server's `l2_dns_singleflight_burst_delivers_server`: the first miss
/// spawns a waiter, every follower spawns its own, moka coalesces all of
/// them into one upstream query, and every waiter delivers its own reply —
/// all 40 replies reach the app socket with zero budget/policy counters
/// moving.
///
/// Holds `DNS_SLOW_PATH_COUNTER_LOCK` like every other slow-path counter
/// test; `localhost` + an unused port keeps the `(host, port)` key cold
/// without network. The limiter premise is asserted, never drained: each
/// waiter holds one permit while it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_dns_singleflight_burst_delivers_dispatch() {
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let host = "localhost";
    assert!(
        dns_slow_path_limiter().available_permits() > 0,
        "premise: the slow-path budget is available"
    );
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, a.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let port = 19641u16;
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the (host, port) key is cold"
    );
    let before = dgram_drops::snapshot();
    for _ in 0..40 {
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram_domain(sess, host, port, b"l2"),
            &mut reasm,
            &mut pkt,
        );
    }
    // Every spawned waiter delivers once the (single) resolution completes;
    // count them all.
    let mut delivered = 0u32;
    while delivered < 40 {
        if recv_reply(&a.app).await.is_some() {
            delivered += 1;
        } else {
            break;
        }
    }
    let d = dgram_drops::snapshot().since(&before);
    hub.release(sess);
    assert_eq!(
        delivered, 40,
        "L2 burst delivery (dispatch path): delivered={delivered}/40 \
         dns_budget_delta={} session_full_delta={} refused_delta={} (want 40/0/0/0)",
        d.dns_budget, d.session_full, d.refused,
    );
    assert_eq!(d.dns_budget, 0, "budget was available");
    assert_eq!(d.session_full, 0, "budget was available");
    assert_eq!(d.refused, 0, "localhost is not a policy refusal");
}

fn empty_dispatch_cache() -> [DispatchSlot; DISPATCH_CACHE] {
    std::array::from_fn(|_| DispatchSlot {
        sess: u32::MAX,
        entry: None,
        // Test helper tracks the sibling dispatcher's `app` pin field; an
        // empty slot has no address yet, same as production's miss fill.
        app: None,
    })
}

/// The dispatcher cache must never be the last owner of an association's
/// relay socket.
///
/// A cached binding outlives the association: the hub drops its entry and the
/// association task exits, but the cache entry is only re-validated when
/// another datagram for the *same session id* arrives. With a strong `Arc`
/// there, every retired association stayed cached — up to `DISPATCH_CACHE`
/// dead relay sockets, each an fd plus 2 x 32 KiB of kernel buffers, per
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

/// Churn-scale form of the ownership test above: 1200 short-lived
/// associations — the exact population that once left 1024 UDP fds open —
/// each dispatched once (so every one fills a cache slot), then released.
/// Afterwards no entry may survive: every weak must be dead and the hub
/// empty, proving the cache (including its pinned app addresses, which are
/// `Copy` values, not owners) extends no lifetime.
///
/// One relay socket and one app socket are shared by all 1200: per-association
/// sockets would only measure the test host's fd limit, not the cache's
/// ownership, and the leak was owned `Arc`s, not sockets.
#[tokio::test]
async fn dispatch_cache_reclaims_1200_short_assocs() {
    let hub = UdpHub::new();
    let relay = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let app_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app_sock.local_addr().unwrap();
    prime_relay(&relay, &app_sock, app_addr).await;
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let mut weaks = Vec::with_capacity(1200);
    for _ in 0..1200 {
        let sess = hub.alloc_sess().expect("churn must not exhaust the cap");
        let entry = Arc::new(AssocEntry::new(relay.clone()));
        entry.app.store(Some(Arc::new(app_addr)));
        hub.publish(sess, entry.clone());
        weaks.push((sess, Arc::downgrade(&entry)));
        dispatch_one(
            &mut cache,
            &hub,
            sess,
            dgram(sess, b"x"),
            &mut reasm,
            &mut pkt,
        );
        hub.release(sess);
        drop(entry);
    }
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "all 1200 reservations must come back"
    );
    for (sess, w) in &weaks {
        assert!(
            w.upgrade().is_none(),
            "assoc {sess} must be reclaimed, not cached"
        );
    }
    for (i, slot) in cache.iter().enumerate() {
        assert!(
            slot.entry.as_ref().is_none_or(|w| w.upgrade().is_none()),
            "cache slot {i} must hold no live entry"
        );
    }
}

/// The pinned app address backfills: a slot filled before the app sent
/// anything caches `None`, drops that datagram as no-app, and serves the
/// next one from a single re-read — every datagram after that is a pure
/// cache hit that never touches `AssocEntry::app` again.
#[tokio::test]
async fn dispatch_cache_backfills_app_after_publish() {
    let hub = UdpHub::new();
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap();
    let entry = Arc::new(AssocEntry::new(Arc::new(relay)));
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    // No app address yet: dropped, slot pinned to None.
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"early"),
        &mut reasm,
        &mut pkt,
    );
    let idx = (sess as usize) & (DISPATCH_CACHE - 1);
    assert!(cache[idx].entry.is_some());
    assert_eq!(cache[idx].app, None);
    // The app sends: the relay loop would publish this address.
    let app_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app_sock.local_addr().unwrap();
    prime_relay(&entry.relay, &app_sock, app_addr).await;
    entry.app.store(Some(Arc::new(app_addr)));
    dispatch_one(
        &mut cache,
        &hub,
        sess,
        dgram(sess, b"late"),
        &mut reasm,
        &mut pkt,
    );
    assert_eq!(cache[idx].app, Some(app_addr));
    let got = recv_reply(&app_sock)
        .await
        .expect("reply must be delivered");
    assert_eq!(&got[REPLY_HDR_V4..], b"late");
    hub.release(sess);
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
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let e = SharedEgress::default();
    let class = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let now = mono_millis();
    // Cached, but past the freshness window, so a refresh is required. Slot
    // 2 is this pool's interactive UDP slot, which is what a fail-closed
    // pool can legitimately hold.
    e.cached[class.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now.saturating_sub(EGRESS_REFRESH_MS),
        slot: pool.udp_global_slot(class.index),
        rev2: rev2_state(),
    })));
    let got = e
        .refresh_global(&pool, class, now)
        .expect("a live cached connection must be reused, not re-picked");
    let (limit, stamp) = (got.limit, got.stamp_ms);
    assert_eq!(
        got.conn.stable_id(),
        conn.stable_id(),
        "the cached connection must survive the refresh"
    );
    assert_eq!(stamp, now, "the refresh re-stamps the cached handle");
    assert!(
        limit > 0,
        "the DATAGRAM budget is re-read from the live path"
    );
    assert_eq!(
        e.cached[class.index]
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
    prime_relay(&relay, &app, app_addr).await;
    let entry = Arc::new(AssocEntry::new(Arc::new(relay)));
    entry.app.store(Some(Arc::new(app_addr)));
    TestAssoc { entry, app }
}

/// MQP-3 downlink: a TRAIN resolves compressed items through the association's
/// outbound flow table, and an inline no-flow item supplies its own source. The
/// staged replies must carry the source address of each item.
#[tokio::test]
async fn dispatch_v3_train_resolves_flows_and_inline_source() {
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let b: SocketAddr = "203.0.113.9:5353".parse().unwrap();
    let c: SocketAddr = "192.0.2.77:443".parse().unwrap();
    let assoc = test_assoc().await;
    assoc.entry.flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Ip(a)));
        assert!(t.insert_at_owned(1, TargetAddr::Ip(b)));
        Arc::new(t)
    });
    let items = [
        TrainItem {
            flow: 0,
            inline: None,
            src_override: false,
            payload: b"from-flow-0",
        },
        TrainItem {
            flow: 1,
            inline: None,
            src_override: false,
            payload: b"from-flow-1",
        },
        TrainItem {
            flow: MQP3_NO_FLOW,
            inline: Some(TargetAddrRef::Ip(c)),
            src_override: false,
            payload: b"inline-source",
        },
    ];
    let frame = encode_train(7, &items, 1400).expect("encode the downlink train");
    let hub = UdpHub::new();
    hub.publish(7, assoc.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    assert_eq!(
        dispatch_stage_multi(&mut cache, &hub, 7, frame, &mut reasm, &mut out),
        3
    );
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].dst, a);
    assert_eq!(out[1].dst, b);
    assert_eq!(out[2].dst, c);
    assert_eq!(out[0].payload, &b"from-flow-0"[..]);
    assert_eq!(out[1].payload, &b"from-flow-1"[..]);
    assert_eq!(out[2].payload, &b"inline-source"[..]);
    assert!(out[0].sock.is_some(), "the head item owns the relay Arc");
    assert!(out[1].sock.is_none() && out[2].sock.is_none());
}

/// Prime a fresh relay socket's writable readiness, and drain the priming
/// datagram from the app socket.
///
/// A fresh tokio UDP socket can report `WouldBlock` before its first
/// readiness edge (see `retry.rs`), which routes the first reply through the
/// process-global retry pool — whose workers live on whichever test runtime
/// spawned them and can die with it. That cross-runtime churn is what made
/// the positive-delivery assertions in this file flaky under full test
/// parallelism; priming (the same pattern the retry contract tests use)
/// keeps the first measured reply on the direct `try_send_to` arm, so these
/// tests exercise the dispatcher, not the pool's runtime lifecycle.
async fn prime_relay(
    relay: &tokio::net::UdpSocket,
    app: &tokio::net::UdpSocket,
    app_addr: SocketAddr,
) {
    let _ = relay.send_to(b"prime", map_for_dual(app_addr)).await;
    let mut b = [0u8; 8];
    let _ = app.recv_from(&mut b).await;
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

/// Serializes the tests that assert exact `dgram_drops::UNKNOWN_SESS` deltas:
/// the counter is process-wide, and the absent-session dispatch here is the one
/// other test that bumps it.
static UNKNOWN_SESS_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn dispatch_absent_slot_reprobes_the_hub() {
    let _counter_guard = UNKNOWN_SESS_COUNTER_LOCK.lock().await;
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

/// The batch path must not conflate "no such association" with "association
/// has no app address yet": `lookup_entry` used to return `Option` and
/// `dispatch_stage_multi` bumped `udp_write::no_app` for both, so a late reply
/// for a session this process had already torn down (an ordinary race, already
/// counted in `UNKNOWN_SESS` by the hub probe) was also reported as a missing
/// app address. Only the live-but-address-less association is a `no_app` drop.
#[tokio::test]
async fn batch_lookup_separates_unknown_sess_from_no_app() {
    let _counter_guard = UNKNOWN_SESS_COUNTER_LOCK.lock().await;
    let hub = UdpHub::new();
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let addr = TargetAddr::Ip("203.0.113.7:53".parse().unwrap());
    let unknown = 0x0BAD_F00Du32;

    // (a) No association at all: UNKNOWN_SESS, never NO_APP.
    let frame = encode_batch(unknown, &addr.as_ref(), &[b"x"], 1400).unwrap();
    let before_d = dgram_drops::snapshot();
    let before_w = udp_write::snapshot();
    assert_eq!(
        dispatch_stage_multi(&mut cache, &hub, unknown, frame, &mut reasm, &mut out,),
        0
    );
    assert!(out.is_empty());
    assert!(
        dgram_drops::snapshot().since(&before_d).unknown_sess >= 1,
        "the absent session is counted where the hub probe decides it"
    );
    assert_eq!(
        udp_write::snapshot().no_app,
        before_w.no_app,
        "an unknown session is not an association without an app address"
    );

    // (b) A live association whose app has not sent yet is the real no-app
    // case: counted there, not as an unknown session.
    let relay = tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap();
    let appless = Arc::new(AssocEntry::new(Arc::new(relay)));
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, appless);
    let frame = encode_batch(sess, &addr.as_ref(), &[b"y"], 1400).unwrap();
    let before_d = dgram_drops::snapshot();
    let before_w = udp_write::snapshot();
    assert_eq!(
        dispatch_stage_multi(&mut cache, &hub, sess, frame, &mut reasm, &mut out),
        0
    );
    assert!(out.is_empty());
    assert_eq!(
        udp_write::snapshot().no_app,
        before_w.no_app + 1,
        "the live association with no app address is the no_app drop"
    );
    assert_eq!(
        dgram_drops::snapshot().since(&before_d).unknown_sess,
        0,
        "a known session must not be charged to UNKNOWN_SESS"
    );
    hub.release(sess);
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
    // order assertion here left the client bin red for a reason that has
    // nothing to do with the dispatcher — a red suite that hides real
    // regressions.
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
                id: u32,
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
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|x| x.stable_id() == c.stable_id())
    );

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
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|x| x.stable_id() == c.stable_id())
    );

    // Teardown interleaving: the slot holds fresh C (live) while the
    // teardown for dead D runs. The old unconditional store + `clear_if`
    // ends at (C, false) with no generation bump, so `wait_conn` treats
    // C as dead; the helper must never end at (C, false).
    let slot = ConnSlot::fresh();
    slot.publish(&c);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    slot.live.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!slot.clear_if(&d), "D's teardown sees C and clears nothing");
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|x| x.stable_id() == c.stable_id())
    );
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
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|x| x.stable_id() == c.stable_id())
    );
    assert!(
        slot.is_live(),
        "a stale teardown must never mark the fresh connection dead"
    );
}

/// The `open_bi` failure path and the reconnect loop must share one death
/// commit: besides clearing the slot it releases the dead generation's cached
/// egress handles, its rev2 flow registry and its staged payloads, then bumps
/// the generation. A connection death first noticed by a SOCKS flow used to
/// leave all of that behind until the loop's watchdog fired.
#[tokio::test]
async fn retire_dead_slot_clears_egress_rev2_and_stage_once() {
    let (conn, _client, _server) = real_connection().await;
    let egress = SharedEgress::default();
    let slot = ConnSlot::fresh();
    let idx = 0usize;
    let rev2 = ConnRev2::with_stager_capacity(4, 4096);
    slot.set_rev2(rev2.clone());
    slot.publish(&conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);

    // The dead generation's state that must be released with it: one flow, one
    // queued payload and this slot's cached egress handle.
    let wire_id = r2::make_wire_id(1, false).unwrap();
    let binding = FlowBinding::new_shared(
        wire_id,
        7,
        TargetAddr::Ip("198.51.100.9:4242".parse().unwrap()),
    );
    assert!(rev2.registry.insert(binding).is_ok());
    assert!(
        rev2.push_stage(R2StageItem {
            session: 7,
            kind: R2StageKind::Steady { wire_id },
            payload: bytes::Bytes::from_static(b"queued"),
        })
        .is_ok()
    );
    egress.cached[0].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: mono_millis(),
        slot: idx,
        rev2: rev2.clone(),
    })));
    let gen_before = *slot.gen_rx.borrow();

    conn.close(0u32.into(), b"open_bi failed");
    assert!(
        retire_dead_slot(&slot, idx, &egress, &conn),
        "the death commit is won by the first writer"
    );
    assert!(
        slot.shared.load().as_ref().is_none(),
        "the dead connection is retracted"
    );
    assert!(!slot.is_live());
    assert!(
        slot.rev2().is_none(),
        "the generation's rev2 state is cleared"
    );
    assert!(
        rev2.registry.is_empty(),
        "its connection-scoped flow registry is dropped"
    );
    assert_eq!(rev2.stage_len(), 0, "its staged payloads are cleared");
    assert!(
        egress.cached[0].load().is_none(),
        "its cached egress handles are released"
    );
    assert_eq!(
        *slot.gen_rx.borrow(),
        gen_before.wrapping_add(1),
        "waiters and dispatchers are woken exactly once"
    );

    // A losing writer (the reconnect loop racing the same death) must not
    // release anything twice or bump the generation again.
    assert!(!retire_dead_slot(&slot, idx, &egress, &conn));
    assert_eq!(*slot.gen_rx.borrow(), gen_before.wrapping_add(1));
}

/// A stale death report — an `open_bi` failure on a handle the pool has since
/// replaced — must never clean the fresh generation's rev2/egress state.
#[tokio::test]
async fn retire_dead_slot_leaves_a_fresh_generation_untouched() {
    let (dead, _c1, _s1) = real_connection().await;
    let (fresh, _c2, _s2) = real_connection().await;
    assert_ne!(dead.stable_id(), fresh.stable_id());
    let egress = SharedEgress::default();
    let slot = ConnSlot::fresh();
    let dead_state = ConnRev2::new();
    let fresh_state = ConnRev2::new();
    slot.set_rev2(dead_state);
    slot.publish(&dead);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    // A redial already published the next generation while the old SOCKS flow
    // was still failing its `open_bi`.
    slot.set_rev2(fresh_state.clone());
    slot.publish(&fresh);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    egress.cached[0].store(Some(Arc::new(EgressCache {
        conn: fresh.clone(),
        limit: 1200,
        stamp_ms: mono_millis(),
        slot: 0,
        rev2: fresh_state.clone(),
    })));
    let gen_before = *slot.gen_rx.borrow();

    assert!(
        !retire_dead_slot(&slot, 0, &egress, &dead),
        "the stale death loses the clear to the published generation"
    );
    assert!(
        slot.shared
            .load()
            .as_ref()
            .is_some_and(|c| c.stable_id() == fresh.stable_id())
    );
    assert!(slot.is_live(), "the fresh connection stays usable");
    assert!(
        slot.rev2().is_some_and(|s| s.epoch == fresh_state.epoch),
        "the fresh generation's rev2 state is untouched"
    );
    assert!(
        egress.cached[0].load().is_some(),
        "the fresh generation's egress handles are untouched"
    );
    assert_eq!(
        *slot.gen_rx.borrow(),
        gen_before,
        "no wake-up for a death that changed nothing"
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

/// Regression for the association startup stall: after the SOCKS reply the
/// relay loop must be serving the app's first datagram immediately.
///
/// The old code slept `jitter_ms()` (0..=199 ms) *after* answering SOCKS and
/// *before* entering the relay loop, so the app's first datagram — typically
/// the latency-critical one (DNS query, STUN binding, game handshake) — sat
/// unread in the relay socket while the app believed the proxy was ready.
///
/// The paused clock plus a spinner task make the property deterministic: the
/// spinner keeps the scheduler non-idle, so every park is a zero-timeout
/// `park_yield` (which still polls the IO driver) and tokio's test-util
/// auto-advance never fires. A pre-loop sleep therefore parks the association
/// on an unfireable timer and the datagram stays queued — exactly what the
/// final probe detects.
#[tokio::test(start_paused = true)]
async fn udp_associate_serves_its_first_datagram_without_a_startup_sleep() {
    // No egress is published in this harness: since W3 the first datagram is
    // *held* (and its flush/expiry may bump the process-wide NO_EGRESS
    // counter), so serialize with the tests that assert exact deltas on it.
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let spinner = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = l.local_addr().unwrap();
    let mut control = tokio::net::TcpStream::connect(control_addr).await.unwrap();
    let (control_server, _) = l.accept().await.unwrap();

    // No QUIC connection is ever published in this harness, so the datagram
    // takes the synchronous no-egress path once it is read (W3: held for the
    // bounded grace, which is still consumed by the relay loop).
    let pool = ConnPool::new(1, vec![], true, true, 1);
    let hub = Arc::new(UdpHub::new());
    let egress: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    let task = tokio::spawn(handle_udp_associate(
        control_server,
        pool,
        hub.clone(),
        egress,
    ));

    // SOCKS5 reply: VER REP RSV ATYP=IPv4 addr port.
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
        u16::from_be_bytes([reply[8], reply[9]]),
    );

    // The entry is published before the reply; capture the relay socket so the
    // test can prove the datagram was consumed.
    let entry = hub
        .subs
        .iter()
        .find_map(|shard| shard.load().values().next().cloned())
        .expect("the association must publish its entry before the SOCKS reply");

    // One well-formed SOCKS5 UDP frame: RSV/FRAG + IPv4 target + payload.
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut frame = vec![0, 0, 0, 0x01, 127, 0, 0, 1, 0, 53];
    frame.extend_from_slice(b"q");
    app.send_to(&frame, relay).await.unwrap();

    // Spin yields: the scheduler polls the IO driver every `event_interval`
    // task polls (`park_yield`), so readiness is delivered without parking
    // and — under paused time — without any clock advance.
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }

    // Consumed => the relay queue is empty. A pre-loop sleep leaves it queued:
    // the paused clock never reaches the sleep deadline.
    let mut b = [0u8; 64];
    assert!(
        entry.relay.try_recv_from(&mut b).is_err(),
        "the association must consume the first datagram, not sleep before the relay loop"
    );
    task.abort();
    spinner.abort();
}

/// The per-slot transport preset split: only the dedicated bulk UDP shards
/// may dial with the coarse bulk preset. TCP slots and the interactive UDP
/// class keep the tuned low-latency preset — the old wiring gave *both* UDP
/// classes the bulk preset through the UDP endpoint default, silently
/// degrading the class whose whole point is latency-sensitive flows.
#[test]
fn only_the_dedicated_bulk_udp_shards_use_the_bulk_preset() {
    let split = ConnPool::new(4, vec![], true, true, MAX_UDP_EGRESS_CONNS);
    assert_eq!(
        split.slots_total(),
        split.tcp_slots() + 1 + MAX_UDP_EGRESS_CONNS
    );
    for i in 0..split.slots_total() {
        // Every slot past the interactive UDP slot — i.e. every bulk shard —
        // dials bulk; everything before it (TCP and interactive) is tuned.
        assert_eq!(
            slot_uses_bulk_preset(&split, i),
            i > split.udp_global_slot(0),
            "slot {i} preset wrong with udp_split on"
        );
    }
    assert!(
        !slot_uses_bulk_preset(&split, split.udp_global_slot(0)),
        "the interactive UDP class must keep the tuned 2/5 ms preset"
    );
    for i in 0..MAX_UDP_EGRESS_CONNS {
        assert!(
            slot_uses_bulk_preset(&split, split.udp_global_slot(1 + i)),
            "bulk shard {i} must dial with the bulk preset"
        );
    }

    // `udp_split` off: the classes share one slot, which keeps the preset it
    // had before the per-class split, and no TCP slot ever goes bulk.
    let shared = ConnPool::new(4, vec![], true, false, 1);
    assert_eq!(shared.tcp_slots + 1, shared.slots_total());
    assert!(slot_uses_bulk_preset(&shared, shared.udp_global_slot(0)));
    for i in 0..shared.tcp_slots() {
        assert!(
            !slot_uses_bulk_preset(&shared, i),
            "a TCP slot must never dial with the bulk preset"
        );
    }
}

/// P0-2 regression: the deferred N-pack flush must never park its payloads
/// back for a later loop iteration. The pre-fix code re-stored them on a stale
/// memo, so they waited for the next app datagram — unbounded when the app
/// pauses, since the idle and control branches never look at the deferred
/// queue — and were finally mis-counted at association exit. With no
/// publishable egress every payload is dropped and counted exactly once.
#[tokio::test]
async fn deferred_batch_flush_drops_each_payload_once_instead_of_parking() {
    use std::sync::atomic::Ordering;
    // NO_EGRESS is process-wide and this test asserts an exact delta, so it
    // must not overlap any other test that can bump it (the same lock the
    // other egress-verdict counter tests hold).
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(1, vec![], true, true, 1);
    let egress = SharedEgress::default();
    let mut frag = DgramFragmenter::new();
    let addr = TargetAddr::Ip("127.0.0.1:53".parse().unwrap());
    let bind = pool.udp_bind_shard(EgressClass::Interactive, 0);
    let payload = b"deferred-query";
    let p = PendingBatch::new(bind, payload.len());

    let before = dgram_drops::snapshot();
    flush_deferred_batch(&egress, &pool, &mut frag, 7, &p, &addr.as_ref(), payload);
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.no_egress, 1,
        "an undeliverable deferred payload is dropped and counted exactly once"
    );
    assert_eq!(
        dgram_drops::NO_EGRESS.load(Ordering::Relaxed),
        before.no_egress + 1,
        "exactly one bookkeeping event for one lost payload"
    );

    // A real run loses every staged datagram, not one event for the frame.
    let mut arena = payload.to_vec();
    arena.extend_from_slice(b"abc");
    let mut p2 = PendingBatch::new(bind, payload.len());
    p2.lens[1] = 3;
    p2.n = 2;
    let before = dgram_drops::snapshot();
    flush_deferred_batch(&egress, &pool, &mut frag, 7, &p2, &addr.as_ref(), &arena);
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.no_egress, 2,
        "every payload in an undeliverable run is counted"
    );
}

/// Serializes the tests that assert exact deltas on the process-wide egress
/// drop counters: `EGRESS_DEAD`, `NO_EGRESS` and `udp_write::no_app`. The
/// tests that bump them on purpose take this lock too, so a parallel test
/// cannot inflate the delta another test is asserting
/// (`deferred_batch_flush_drops_each_payload_once_instead_of_parking` and the
/// UDP-associate startup test were the two missing holders; the rest of the
/// file uses live loopback connections).
static EGRESS_VERDICT_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The send-verdict recovery is one shared handler for the per-datagram path
/// and the deferred N-pack flush, and it must count exactly once per event:
/// `ConnectionLost` invalidates the shared cache and bumps `EGRESS_DEAD`;
/// `Unsupported` only counts; `Blocked`/`TooLarge` are already counted where
/// they are decided (inside `send_encoded`) and must not be counted again.
#[tokio::test]
async fn send_verdict_recovery_is_counted_once_and_shared() {
    use std::sync::atomic::Ordering;
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let (conn, _client, _server) = real_connection().await;
    let egress = SharedEgress::default();
    let bind = UdpBind {
        class: EgressClass::Bulk,
        index: 1,
    };
    let cached = || EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: coarse_millis(),
        slot: 0,
        rev2: rev2_state(),
    };

    // A success changes nothing.
    egress.cached[bind.index].store(Some(Arc::new(cached())));
    recover_send_outcome(
        &egress,
        bind,
        PayloadSend {
            frames: 1,
            failed: None,
        },
    );
    assert!(egress.cached[bind.index].load().is_some());

    // `Blocked` / `TooLarge`: counted inside `send_encoded`, not here, and
    // never a reason to drop the cached handle. (`TooLarge` re-reads the
    // budget, which keeps the handle.)
    let before = dgram_drops::snapshot();
    recover_send_outcome(
        &egress,
        bind,
        PayloadSend {
            frames: 0,
            failed: Some(DatagramSend::Blocked),
        },
    );
    recover_send_outcome(
        &egress,
        bind,
        PayloadSend {
            frames: 0,
            failed: Some(DatagramSend::TooLarge),
        },
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        (d.egress_dead, d.buffer_full, d.too_large),
        (0, 0, 0),
        "size/backpressure verdicts are counted where they are decided, not here"
    );
    assert!(
        egress.cached[bind.index].load().is_some(),
        "a size/backpressure verdict must not invalidate the handle"
    );

    // `ConnectionLost`: one `EGRESS_DEAD` for the event — even when a single
    // BATCH verdict lost two staged payloads (`frames` is not consulted) —
    // and the cached handle goes, so the next datagram re-acquires.
    egress.cached[bind.index].store(Some(Arc::new(cached())));
    let gen_before = egress.generation[bind.index].load(Ordering::Acquire);
    let before = dgram_drops::snapshot();
    recover_send_outcome(
        &egress,
        bind,
        PayloadSend {
            frames: 0,
            failed: Some(DatagramSend::ConnectionLost),
        },
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.egress_dead, 1,
        "one EGRESS_DEAD per event, not per lost datagram"
    );
    assert!(
        egress.cached[bind.index].load().is_none(),
        "a lost connection must invalidate the shared cache"
    );
    assert!(
        egress.generation[bind.index].load(Ordering::Acquire) > gen_before,
        "the invalidation must bump the generation so every thread's memo misses"
    );

    // `Unsupported`: counted, but deliberately not invalidated — the condition
    // is static for the connection's life, so a re-acquire cannot find a
    // better slot and would only add two quinn locks per datagram.
    egress.cached[bind.index].store(Some(Arc::new(cached())));
    let gen_before = egress.generation[bind.index].load(Ordering::Acquire);
    let before = dgram_drops::snapshot();
    recover_send_outcome(
        &egress,
        bind,
        PayloadSend {
            frames: 0,
            failed: Some(DatagramSend::Unsupported),
        },
    );
    assert_eq!(
        dgram_drops::snapshot().since(&before).egress_dead,
        1,
        "Unsupported is a counted egress drop"
    );
    assert!(
        egress.cached[bind.index].load().is_some(),
        "Unsupported must not invalidate the handle"
    );
    assert_eq!(
        egress.generation[bind.index].load(Ordering::Acquire),
        gen_before,
        "Unsupported must not churn the generation"
    );
}

/// Regression for the deferred N-pack flush dropping its send verdict: a memo
/// hit whose cached handle died between staging and the flush must run the same
/// recovery as the per-datagram path — one `EGRESS_DEAD`, cache invalidated —
/// instead of silently losing the payload with `.is_some()`.
#[tokio::test]
async fn deferred_batch_flush_recovers_a_dead_egress_verdict() {
    use std::sync::atomic::Ordering;
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(1, vec![], true, true, 1);
    let egress = SharedEgress::default();
    let mut frag = DgramFragmenter::new();
    let addr = TargetAddr::Ip("127.0.0.1:53".parse().unwrap());
    let bind = pool.udp_bind_shard(EgressClass::Interactive, 0);
    let payload = b"deferred-query";
    let p = PendingBatch::new(bind, payload.len());

    // A live memo pointing at a connection that is closed by the time of the
    // flush: exactly the stale-handle window the memo deliberately serves.
    let (conn, _client, _server) = real_connection().await;
    conn.close(0u32.into(), b"test");
    assert!(
        conn.close_reason().is_some(),
        "premise: the cached handle is dead"
    );
    let now = coarse_millis();
    let generation = egress.generation[bind.index].load(Ordering::Acquire);
    egress.memo_store(bind, generation, &conn, 1200, now, &rev2_state());
    egress.cached[bind.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: now,
        slot: 0,
        rev2: rev2_state(),
    })));
    assert!(
        egress.with_fresh(bind, now, |_, _, _| ()).is_some(),
        "premise: the memo is fresh, so the flush takes the hit path"
    );

    let before = dgram_drops::snapshot();
    let gen_before = egress.generation[bind.index].load(Ordering::Acquire);
    flush_deferred_batch(&egress, &pool, &mut frag, 7, &p, &addr.as_ref(), payload);
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.egress_dead, 1,
        "a dead handle on the deferred flush is counted, not swallowed"
    );
    assert_eq!(
        d.no_egress, 0,
        "the send reached the connection: this is not a no-egress drop"
    );
    assert!(
        egress.cached[bind.index].load().is_none(),
        "the dead cached handle must be invalidated for the next datagram"
    );
    assert!(
        egress.generation[bind.index].load(Ordering::Acquire) > gen_before,
        "the invalidation must wake every thread's memo"
    );
}

/// The sharded topology pins cores by *priority*, not by slot index: TCP slot
/// 0 (interactive) gets the lowest core, then the dedicated interactive UDP
/// slot, then the remaining TCP slots, then the bulk shards. The old
/// `idx < cores` shape left the interactive UDP slot unpinned on hosts with
/// fewer cores than TCP slots + 1 — exactly the slot every small-datagram
/// association rides.
#[test]
fn slot_pinning_prioritizes_the_interactive_pair() {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let pool = ConnPool::new(4, vec![], true, true, 2);
    // The shipped split: the main runtime keeps half the machine, so the pinned
    // slots may claim `usable = ceil(cores / 2)` cores at most.
    let app_workers = cores / 2;
    let usable = cores.saturating_sub(app_workers).max(1);
    let pin_cores = priority_pin_cores(&pool, app_workers);
    assert_eq!(pin_cores.len(), pool.slots_total());
    // Rank 0 is always pinned (there is at least one core).
    assert_eq!(
        pin_cores[0],
        Some(0),
        "the interactive TCP slot is the top priority"
    );
    if usable >= 2 {
        assert_eq!(
            pin_cores[pool.udp_global_slot(0)],
            Some(1),
            "the interactive UDP slot is the second priority"
        );
    }
    if usable >= 3 {
        assert_eq!(
            pin_cores[1],
            Some(2),
            "the remaining TCP slots follow the interactive pair"
        );
    }
    // Every pinned rank is a real core, and past the usable count slots float.
    let mut ranks: Vec<usize> = pin_cores.iter().flatten().copied().collect();
    ranks.sort_unstable();
    assert_eq!(
        ranks,
        (0..usable.min(pool.slots_total())).collect::<Vec<_>>(),
        "pins are a bijection onto the first `min(usable, slots)` ranks"
    );
    // A pool wider than the usable cores leaves the lowest-priority tail
    // floating: the number of pinned slots is exactly the usable core count.
    assert_eq!(
        pin_cores.iter().flatten().count(),
        usable.min(pool.slots_total()),
        "exactly `min(usable, slots)` slots are pinned"
    );
    // And pinning never eats a core the app-side pool was sized for.
    assert!(
        cores.saturating_sub(pin_cores.iter().flatten().count()) >= app_workers,
        "pinned slots must leave the {app_workers} app-side workers their cores"
    );

    // Every interactive shard outranks every bulk slot: the class carries the
    // latency-sensitive population, so widening it must not push its later
    // shards behind bulk TCP/UDP slots.
    let wide = ConnPool::new_with_bulk_ports(
        4,
        vec![],
        vec![],
        true,
        true,
        2,
        2,
        data_stale_threshold_ms(5, 40),
    );
    let wide_pins = priority_pin_cores(&wide, app_workers);
    assert_eq!(wide_pins.len(), wide.slots_total());
    assert_eq!(wide_pins[0], Some(0), "interactive TCP slot first");
    if usable >= 2 {
        assert_eq!(
            wide_pins[wide.udp_global_slot(0)],
            Some(1),
            "first interactive UDP shard is rank 1"
        );
    }
    if usable >= 3 {
        assert_eq!(
            wide_pins[wide.udp_global_slot(1)],
            Some(2),
            "second interactive UDP shard outranks every bulk slot"
        );
    }
    if usable >= 4 {
        assert_eq!(
            wide_pins[1],
            Some(3),
            "the remaining TCP slots follow the whole interactive class"
        );
    }
}

// ---- Memory-retention fixes: egress dead-handle release, UDP-assoc cap ----

/// `UdpHub::with_capacity` is the client's UDP-association memory knob: it must
/// refuse the `max + 1`-th reservation, hand a slot back on `release`, and
/// clamp (0 -> 1 so UDP can never be silently switched off; a usize::MAX typo
/// -> the default cap so the protocol budget is never exceeded).
#[test]
fn hub_with_capacity_bounds_alloc_and_release_reopens() {
    let hub = UdpHub::with_capacity(2);
    let a = hub.alloc_sess().expect("first association");
    let b = hub.alloc_sess().expect("second association");
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "both reservations must be counted"
    );
    assert!(
        hub.alloc_sess().is_none(),
        "a capacity-2 hub must refuse the third association"
    );
    hub.release(a);
    let c = hub
        .alloc_sess()
        .expect("release must free the reservation for reuse");
    assert_ne!(b, c, "the freed slot must hand out the next live id");
    hub.release(b);
    hub.release(c);
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "every reservation must come back"
    );

    let floor = UdpHub::with_capacity(0);
    assert_eq!(floor.max, 1, "0 clamps to 1, never disables UDP");
    assert!(floor.alloc_sess().is_some());
    assert!(floor.alloc_sess().is_none());

    let ceiling = UdpHub::with_capacity(usize::MAX);
    assert_eq!(
        ceiling.max, MAX_UDP_ASSOCS,
        "an oversize value clamps to the default cap"
    );
}

/// Minimal client config with only the four required fields, for the
/// `max_udp_assocs` parsing/clamping test.
fn client_conf_with(extra: &str) -> ClientConf {
    let base = concat!(
        "socks_listen = \"[::]:1080\"\n",
        "server_addr = \"127.0.0.1:8443\"\n",
        "server_name = \"test.com\"\n",
        "server_cert_file = \"server-cert.pem\"\n",
    );
    toml::from_str(&format!("{base}{extra}")).expect("minimal client config parses")
}

/// `max_udp_assocs`: unset = default (4032), explicit honored, 0/oversize
/// clamped. This is the config surface behind the hub cap above.
#[test]
fn client_udp_assoc_cap_defaults_and_clamps() {
    assert_eq!(MAX_UDP_ASSOCS, 4032, "the documented default");
    let unset = client_conf_with("");
    assert!(
        unset.max_udp_assocs.is_none(),
        "unset must stay None so the default is decided in one place"
    );
    assert_eq!(unset.udp_assoc_count(), MAX_UDP_ASSOCS);

    let explicit = client_conf_with("max_udp_assocs = 128\n");
    assert_eq!(explicit.max_udp_assocs, Some(128));
    assert_eq!(explicit.udp_assoc_count(), 128);

    assert_eq!(
        client_conf_with("max_udp_assocs = 0\n").udp_assoc_count(),
        1,
        "0 clamps to 1, never disables UDP associations"
    );
    assert_eq!(
        client_conf_with("max_udp_assocs = 999999\n").udp_assoc_count(),
        MAX_UDP_ASSOCS,
        "an oversize value clamps to the default cap"
    );
}

/// A redial must release the dead generation's `quinn::Connection` clones held
/// by the egress caches, or a binding that goes idle pins the whole quinn-proto
/// connection state for the process lifetime. `forget_slot` must be scoped to
/// the dead pool slot: a healthy slot's cached handle stays.
#[tokio::test]
async fn forget_slot_releases_only_that_slots_handles() {
    let (conn, _client, _server) = real_connection().await;
    let e = SharedEgress::default();
    let now = mono_millis();
    for (i, slot) in [(0usize, 3usize), (1, 4)] {
        e.cached[i].store(Some(Arc::new(EgressCache {
            conn: conn.clone(),
            limit: 1200,
            stamp_ms: now,
            slot,
            rev2: rev2_state(),
        })));
    }
    let other_gen = e.generation[1].load(std::sync::atomic::Ordering::Acquire);

    e.forget_slot(3);

    assert!(
        e.cached[0].load().is_none(),
        "the dead slot's cached handle must be released"
    );
    assert_eq!(
        e.generation[0].load(std::sync::atomic::Ordering::Acquire),
        1,
        "the clear must bump the generation so every thread's memo misses"
    );
    assert!(
        e.cached[1].load().is_some(),
        "a healthy slot's cached handle must be untouched"
    );
    assert_eq!(
        e.generation[1].load(std::sync::atomic::Ordering::Acquire),
        other_gen,
        "a healthy slot's generation must be untouched"
    );
}

/// A stale thread-local memo entry (generation mismatch, i.e. redial or
/// invalidation) must release its cloned `Connection` on the miss path; the
/// fresh-hit path is unchanged and must not drop the entry.
#[tokio::test]
async fn stale_egress_memo_releases_the_connection() {
    let (conn, _client, _server) = real_connection().await;
    let e = SharedEgress::default();
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let now = mono_millis();
    e.memo_store(bind, 0, &conn, 1200, now, &rev2_state());
    assert!(!memo_is_empty(bind), "premise: the memo holds a handle");

    // Fresh hit: served, and the hit path must not clear the memo.
    assert!(
        e.with_fresh(bind, now, |c, limit, _| (c.stable_id(), limit))
            .is_some(),
        "a fresh memo entry must be served"
    );
    assert!(
        !memo_is_empty(bind),
        "a fresh hit must not release the thread-local memo"
    );

    // Generation bump (invalidate/forget_slot): the stale entry must be freed.
    e.generation[bind.index].fetch_add(1, std::sync::atomic::Ordering::Release);
    assert!(
        e.with_fresh(bind, now, |_, _, _| ()).is_none(),
        "a stale memo entry must not be served"
    );
    assert!(
        memo_is_empty(bind),
        "a stale memo entry must release its cloned Connection"
    );
}

// ---------------- MQP-3 wire rev2 downlink ----------------

/// A compressed steady `DATA` resolves its wire id through the connection
/// registry, delivers to the binding's session, and is itself the implicit ACK
/// that moves the uplink binding `Opening -> Open`.
#[tokio::test]
async fn dispatch_rev2_steady_resolves_binding_and_marks_it_open() {
    let assoc = test_assoc().await;
    let sess = 7u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let target: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let binding = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        sess,
        TargetAddr::Ip(target),
    );
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let frame = r2::encode_data_steady(binding.wire_id, b"reply-1", 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        1
    );
    assert_eq!(
        out[0].dst, target,
        "no learned source yet: the IP target is used"
    );
    assert_eq!(out[0].payload, &b"reply-1"[..]);
    assert!(
        binding.is_open(),
        "a compressed downlink is the implicit ACK"
    );
    assert!(
        assoc
            .entry
            .replied
            .load(std::sync::atomic::Ordering::Relaxed),
        "delivering a reply marks the association active for the idle tick"
    );
}

/// Domain flow downlink: a steady frame cannot name a reply source, so it is
/// dropped (counted); the server's `DATA OPEN|SRC` teaches the actual source,
/// after which the same flow compresses into SOCKS5 replies.
#[tokio::test]
async fn dispatch_rev2_domain_open_src_binds_reply_source() {
    // The steady-frame drop below bumps the process-wide REFUSED counter; the
    // DNS slow-path tests assert exact REFUSED deltas, so share their lock.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let assoc = test_assoc().await;
    let sess = 9u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let binding = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        sess,
        TargetAddr::Domain("example.com".to_string(), 53),
    );
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    // A compressed frame for a domain flow with no learned source has nowhere
    // to deliver: the requested name is not a valid SOCKS5 reply address.
    let frame = r2::encode_data_steady(binding.wire_id, b"lost", 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        0
    );
    assert!(
        binding.reply_src().is_none(),
        "a steady frame must not invent a source address"
    );

    // The binding frame carries the real source of the reply.
    let src: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let frame = r2::encode_data_open(
        binding.wire_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        b"first",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        1
    );
    assert_eq!(out[0].dst, src);
    assert_eq!(out[0].payload, &b"first"[..]);
    assert_eq!(binding.reply_src(), Some(src));
    assert!(binding.is_open());

    // Subsequent steady frames resolve through the learned reply source.
    let frame = r2::encode_data_steady(binding.wire_id, b"second", 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        1
    );
    assert_eq!(out[1].dst, src);
    assert_eq!(out[1].payload, &b"second"[..]);
}

/// A same-flow `TRAIN` delivers every item through the flow's binding, in wire
/// order.
#[tokio::test]
async fn dispatch_rev2_train_resolves_same_flow() {
    let assoc = test_assoc().await;
    let sess = 3u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let target: SocketAddr = "192.0.2.7:5353".parse().unwrap();
    let binding = FlowBinding::new_shared(
        r2::make_wire_id(2, false).unwrap(),
        sess,
        TargetAddr::Ip(target),
    );
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let frame = r2::encode_train_same(binding.wire_id, &[b"x", b"yy"], 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        2
    );
    assert_eq!(out[0].dst, target);
    assert_eq!(out[1].dst, target);
    assert_eq!(out[0].payload, &b"x"[..]);
    assert_eq!(out[1].payload, &b"yy"[..]);
    assert!(binding.is_open());
}

/// `DATA INLINE` (the server's fail-safe) is self-describing: session + source
/// address, no registry lookup.
#[tokio::test]
async fn dispatch_rev2_inline_downlink_delivers() {
    let assoc = test_assoc().await;
    let sess = 5u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let src: SocketAddr = "198.51.100.44:443".parse().unwrap();
    let frame =
        r2::encode_data_inline(sess, &TargetAddrRef::Ip(src), false, b"inline", 1400).unwrap();
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        1
    );
    assert_eq!(out[0].dst, src);
    assert_eq!(out[0].payload, &b"inline"[..]);
}

/// Unknown wire ids are dropped and counted, never mapped to a guessed
/// session.
#[tokio::test]
async fn dispatch_rev2_unknown_id_is_dropped() {
    let assoc = test_assoc().await;
    let hub = UdpHub::new();
    hub.publish(7, assoc.entry.clone());
    let rev2 = rev2_state();
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let before = counters::snapshot();
    let frame = r2::encode_data_steady(999, b"stale", 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut r2_reasm,
            None,
            frame,
            &mut out
        ),
        0
    );
    assert!(out.is_empty());
    let delta = counters::since(&before);
    assert!(delta.rx_unknown_id >= 1, "the stale id must be counted");
}

/// `CTL` handling: `CAPS` stores the limits, `FLOW_ACK` confirms an uplink
/// binding, `FLOW_REJECT`/`FLOW_CLOSE` close and forget one, and `SESS_CLOSE`
/// reaches the association through its per-association close signal.
#[tokio::test]
async fn dispatch_rev2_ctl_caps_ack_reject_close_sess_close() {
    let rev2 = ConnRev2::new();
    let hub = UdpHub::new();
    // SESS_CLOSE is only recorded for a session with a live association (the
    // only thing that can consume it); publish one for 42 below.
    let assoc = test_assoc().await;
    hub.publish(42, assoc.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let mut send = |rev2: &ConnRev2, ctl: r2::Ctl, cache: &mut [DispatchSlot; DISPATCH_CACHE]| {
        let frame = r2::encode_ctl(&ctl);
        dispatch_r2(rev2, cache, &hub, &mut r2_reasm, None, frame, &mut out)
    };

    // CAPS: negotiated limits become the connection state.
    let caps = r2::Caps {
        max_train_items: 8,
        ..r2::Caps::default()
    };
    assert_eq!(send(&rev2, r2::Ctl::Caps(caps), &mut cache), 0);
    assert!(rev2.is_ready());
    assert_eq!(rev2.ctl.caps(), Some(caps));

    // FLOW_ACK: Opening -> Open.
    let a = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        7,
        TargetAddr::Ip("198.51.100.1:53".parse().unwrap()),
    );
    assert!(rev2.registry.insert(a.clone()).is_ok());
    assert_eq!(
        send(
            &rev2,
            r2::Ctl::FlowAck {
                id: a.wire_id,
                status: r2::R2_ACK_OPEN
            },
            &mut cache
        ),
        0
    );
    assert!(a.is_open());

    // FLOW_REJECT: closed and forgotten.
    let b = FlowBinding::new_shared(
        r2::make_wire_id(2, false).unwrap(),
        7,
        TargetAddr::Ip("198.51.100.2:53".parse().unwrap()),
    );
    assert!(rev2.registry.insert(b.clone()).is_ok());
    assert_eq!(
        send(
            &rev2,
            r2::Ctl::FlowReject {
                id: b.wire_id,
                reason: r2::R2_REJECT_TABLE_FULL
            },
            &mut cache
        ),
        0
    );
    assert_eq!(b.state(), FlowState::Closed);
    assert!(rev2.registry.get(b.wire_id).is_none());
    assert!(
        rev2.is_rejected(&b.target_ref(), coarse_millis()),
        "a rejected target is sent INLINE until the TTL expires"
    );

    // FLOW_CLOSE: closed and forgotten.
    let c = FlowBinding::new_shared(
        r2::make_wire_id(3, false).unwrap(),
        7,
        TargetAddr::Ip("198.51.100.3:53".parse().unwrap()),
    );
    assert!(rev2.registry.insert(c.clone()).is_ok());
    assert_eq!(
        send(&rev2, r2::Ctl::FlowClose { id: c.wire_id }, &mut cache),
        0
    );
    assert_eq!(c.state(), FlowState::Closed);
    assert!(rev2.registry.get(c.wire_id).is_none());

    // SESS_CLOSE: raised on the association's own hub entry, exactly once.
    assert!(!assoc.entry.closed.take());
    assert_eq!(
        send(
            &rev2,
            r2::Ctl::SessClose {
                sess: 42,
                reason: 0
            },
            &mut cache
        ),
        0
    );
    assert!(assoc.entry.closed.take());
    assert!(!assoc.entry.closed.take(), "a consumed close is not sticky");
    // A close for a session this process has no association for has nobody to
    // signal: the dispatcher checks the hub first, so no state is touched.
    assert_eq!(
        send(
            &rev2,
            r2::Ctl::SessClose {
                sess: 43,
                reason: 0
            },
            &mut cache
        ),
        0
    );
}

/// A `SESS_CLOSE` makes the association forget its bindings so the next uplink
/// payload re-opens the flow instead of sending steady frames for ids the
/// server no longer holds.
#[test]
fn rev2_session_close_makes_the_uplink_reopen() {
    let rev2 = rev2_state();
    let sig = Arc::new(CloseSignal::new());
    let mut up = UplinkFlows::new(sig.clone());
    up.sync(&rev2);
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let binding = {
        let b = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr.clone());
        assert!(rev2.registry.insert(b.clone()).is_ok());
        assert!(up.flows.insert(b.clone()));
        b
    };
    binding.mark_open();
    sig.raise();
    up.sync(&rev2);
    assert!(up.flows.is_empty(), "the session's bindings are forgotten");
    assert!(
        rev2.registry.get(binding.wire_id).is_none(),
        "and dropped from the connection registry"
    );
    // The flag was consumed: a fresh binding opened after the reset must
    // survive the next sync (a sticky flag would reset it again and reopen on
    // every datagram).
    let fresh = FlowBinding::new_shared(r2::make_wire_id(2, false).unwrap(), 7, addr);
    assert!(rev2.registry.insert(fresh.clone()).is_ok());
    assert!(up.flows.insert(fresh.clone()));
    up.sync(&rev2);
    assert_eq!(up.flows.len(), 1, "the close was consumed exactly once");
    assert!(rev2.registry.get(fresh.wire_id).is_some());
}

/// The egress cache publishes a rev2 generation as soon as its state exists,
/// even before `CAPS`, so the first UDP payload can be sent optimistically.
/// `CAPS` only upgrades the boot limits; Phase 0 removed the pre-HELLO buffer,
/// so the server dispatches rev2 frames as they arrive.
#[tokio::test]
async fn egress_publishes_before_caps_for_optimistic_first_packet() {
    let (conn, _client, _server) = real_connection().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let e = SharedEgress::default();
    let bind = pool.udp_bind_shard(EgressClass::Bulk, 0);
    let slot = pool.slot(pool.udp_global_slot(bind.index));
    slot.publish(&conn);
    let now = mono_millis();
    assert!(
        e.refresh_global(&pool, bind, now).is_none(),
        "a connection without rev2 state must not carry UDP"
    );
    let state = ConnRev2::new();
    slot.set_rev2(state.clone());
    let h = e
        .refresh_global(&pool, bind, now)
        .expect("rev2 state is publishable before CAPS");
    assert_eq!(h.conn.stable_id(), conn.stable_id());
    assert_eq!(h.rev2.epoch, state.epoch);
    assert!(
        !h.rev2.is_ready(),
        "the optimistic send happens before CAPS"
    );
    state.on_caps(r2::Caps::default());
    let h = e
        .refresh_global(&pool, bind, now)
        .expect("a negotiated connection is publishable");
    assert!(h.rev2.is_ready());
}

/// W3: payloads produced while no egress connection exists are held, not
/// dropped, and the hold is flushed **in order** through the normal uplink path
/// once a fresh generation is published — the same path a live datagram takes
/// (`DATA OPEN` for the first payload of the target, repeated while `Opening`).
#[tokio::test]
async fn queued_datagrams_flush_in_order_on_a_new_generation() {
    // The no-egress assertions below hold exact deltas on process-wide
    // counters, so serialize with the other egress-verdict tests.
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress = SharedEgress::default();
    let mut bind: Option<UdpBind> = None;
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());

    // No egress published yet: the payloads are held, not dropped.
    let before = dgram_drops::snapshot();
    let before_counters = counters::snapshot();
    for payload in [&b"one"[..], b"two", b"three"] {
        send_payload_uplink(
            &pool,
            &egress,
            7,
            &target.as_ref(),
            payload,
            &mut bind,
            &mut up,
            &mut frag,
            coarse_millis(),
            SessionKind::Socks,
        );
    }
    assert_eq!(
        dgram_drops::snapshot().since(&before).no_egress,
        0,
        "a payload with no egress must be held, not dropped (W3)"
    );
    assert_eq!(up.pending_len(), 3);
    assert!(
        counters::since(&before_counters).egress_queued >= 3,
        "each held payload is counted"
    );

    // A fresh generation is published (the redial the hold is waiting for).
    let slot = pool.slot(pool.udp_global_slot(bind.unwrap().index));
    let state = rev2_state();
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);

    // The next send attempt flushes the hold first (FIFO), then sends itself.
    send_payload_uplink(
        &pool,
        &egress,
        7,
        &target.as_ref(),
        b"four",
        &mut bind,
        &mut up,
        &mut frag,
        coarse_millis(),
        SessionKind::Socks,
    );
    assert_eq!(up.pending_len(), 0, "the hold is empty after the flush");
    assert_eq!(
        up.epoch, state.epoch,
        "flushed payloads ride the new generation's flow tables"
    );
    assert!(
        counters::since(&before_counters).egress_flushed >= 3,
        "each held payload handed back to the send path is counted"
    );
    drain_assoc_stage(&egress, &pool, bind.unwrap());

    // Wire order is exactly the hold order followed by the new payload, and
    // the frames are ordinary rev2 DATA: the flush reuses the normal encoder.
    let mut ids = Vec::new();
    for expected in [&b"one"[..], b"two", b"three", b"four"] {
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("the flushed payloads must reach the server")
            .unwrap();
        let f = r2::decode_data(&d).expect("a flushed payload is normal rev2 DATA");
        assert_eq!(f.payload, expected, "the hold must preserve FIFO order");
        assert_eq!(f.sess, Some(7));
        assert_eq!(f.addr, Some(target.as_ref()));
        ids.push(f.id.expect("the first payload of a new target opens a flow"));
    }
    assert!(
        ids.windows(2).all(|w| w[0] == w[1]),
        "the held payloads belong to one flow, opened by the first"
    );
    assert!(
        state.registry.get(ids[0]).is_some(),
        "the flow was installed on the new generation"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server_conn.read_datagram())
            .await
            .is_err(),
        "four held payloads must produce four frames, not more"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// W3: the hold is bounded by items and by bytes and drops the **newest**
/// payload past the bound, booking it exactly like the pre-W3 loss (one
/// `NO_EGRESS` per payload) plus the reason counter.
#[tokio::test]
async fn queue_until_publish_is_bounded_and_books_the_newest_drop() {
    // Process-wide no-egress counter: serialize with the other egress tests.
    let _guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress = SharedEgress::default();
    let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());

    // Item bound: hold exactly PENDING_MAX_ITEMS one-byte payloads, then the
    // next one is dropped (the oldest stay).
    let mut bind: Option<UdpBind> = None;
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    for _ in 0..PENDING_MAX_ITEMS {
        send_payload_uplink(
            &pool,
            &egress,
            7,
            &target.as_ref(),
            b"x",
            &mut bind,
            &mut up,
            &mut frag,
            coarse_millis(),
            SessionKind::Socks,
        );
    }
    assert_eq!(up.pending_len(), PENDING_MAX_ITEMS);
    let before = dgram_drops::snapshot();
    let before_counters = counters::snapshot();
    send_payload_uplink(
        &pool,
        &egress,
        7,
        &target.as_ref(),
        b"newest",
        &mut bind,
        &mut up,
        &mut frag,
        coarse_millis(),
        SessionKind::Socks,
    );
    assert_eq!(
        up.pending_len(),
        PENDING_MAX_ITEMS,
        "drop-newest never evicts a held payload"
    );
    assert_eq!(
        dgram_drops::snapshot().since(&before).no_egress,
        1,
        "exactly the refused payload is booked"
    );
    assert!(
        counters::since(&before_counters).egress_hold_full >= 1,
        "the full-bound drop has its own reason counter"
    );

    // Byte bound: 8 KiB payloads fill PENDING_MAX_BYTES with fewer items, and
    // the ninth is refused although the item bound is far from reached.
    let mut bind2: Option<UdpBind> = None;
    let mut up2 = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag2 = R2Fragmenter::new();
    let big = vec![0u8; PENDING_MAX_BYTES / 8];
    for _ in 0..8 {
        send_payload_uplink(
            &pool,
            &egress,
            7,
            &target.as_ref(),
            &big,
            &mut bind2,
            &mut up2,
            &mut frag2,
            coarse_millis(),
            SessionKind::Socks,
        );
    }
    assert_eq!(up2.pending_len(), 8, "the byte bound, not the item bound");
    let before = dgram_drops::snapshot();
    send_payload_uplink(
        &pool,
        &egress,
        7,
        &target.as_ref(),
        &big,
        &mut bind2,
        &mut up2,
        &mut frag2,
        coarse_millis(),
        SessionKind::Socks,
    );
    assert_eq!(up2.pending_len(), 8);
    assert_eq!(dgram_drops::snapshot().since(&before).no_egress, 1);
}

/// W3: a payload held past `PENDING_TTL_MS` is dropped and accounted, never
/// delivered late: the bounded grace preserves UDP semantics (a stale datagram
/// is worse than a lost one).
#[test]
fn expired_held_datagrams_are_dropped_and_accounted() {
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let now = mono_millis();
    assert!(up.hold_pending_at(&target.as_ref(), b"old", now));
    assert!(up.hold_pending_at(&target.as_ref(), b"older", now));
    assert_eq!(up.pending_len(), 2);
    // Inside the window nothing is dropped (not even a millisecond short).
    assert_eq!(up.expire_pending_at(now + PENDING_TTL_MS - 1), 0);
    assert_eq!(up.pending_len(), 2);
    let before = dgram_drops::snapshot();
    let before_counters = counters::snapshot();
    assert_eq!(up.expire_pending_at(now + PENDING_TTL_MS), 2);
    assert!(
        !up.has_pending(),
        "the expired hold is empty, never delivered"
    );
    assert!(
        dgram_drops::snapshot().since(&before).no_egress >= 2,
        "each expired payload is a counted loss"
    );
    assert!(
        counters::since(&before_counters).egress_hold_stale >= 2,
        "the stale-hold reason counter is bumped"
    );
    // A payload enqueued at the same instant as the expiry is not stale.
    assert!(up.hold_pending_at(&target.as_ref(), b"fresh", now + PENDING_TTL_MS));
    assert_eq!(up.expire_pending_at(now + PENDING_TTL_MS), 0);
    assert_eq!(up.pending_len(), 1);
    assert_eq!(up.expire_pending_at(now + 2 * PENDING_TTL_MS), 1);
    assert!(!up.has_pending());
}

/// W8a: `mark_open` is called per downlink frame (steady DATA, first occurrence
/// of every TRAIN id, every completed FRAG payload). It must be a relaxed-load
/// fast path in the steady state while keeping the exact transition semantics:
/// `Opening -> Open` once, idempotent for `Open`, and `Closed` is terminal.
#[test]
fn mark_open_is_idempotent_for_downlink_frames() {
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let binding = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr);
    assert_eq!(binding.state(), FlowState::Opening);
    for _ in 0..64 {
        binding.mark_open();
        assert!(binding.is_open(), "an OPEN confirmation is idempotent");
    }
    binding.mark_closed();
    for _ in 0..64 {
        binding.mark_open();
        assert_eq!(
            binding.state(),
            FlowState::Closed,
            "a compressed frame must never reopen a closed flow"
        );
    }
}

/// W8a: the dispatcher classifies the first byte **once** per inbound
/// datagram and passes the drain burst's single coarse-clock read down; the
/// legacy fallback (`MQP-3`/`MQP-2`/BATCH bytes) must still be routed to the
/// old path after that refactor.
#[tokio::test]
async fn dispatch_inbound_classifies_the_first_byte_once() {
    // The unroutable legacy frame below bumps the process-wide REFUSED counter,
    // so serialize with the tests that assert exact deltas on it (the DNS
    // slow-path suite) even though this test only checks a lower bound.
    let _guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let rev2 = ConnRev2::new();
    let hub = UdpHub::new();
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut r2_reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    // A rev2 CTL CAPS goes through the rev2 branch (the classification result
    // is consumed there, not re-derived) and reaches the connection state.
    let frame = r2::encode_ctl(&r2::Ctl::Caps(r2::Caps::default()));
    assert_eq!(r2::kind(&frame), Some(r2::R2Kind::Ctl));
    dispatch_inbound(
        &mut cache,
        &hub,
        &rev2,
        None,
        frame,
        &mut reasm,
        &mut r2_reasm,
        &mut out,
        coarse_millis(),
    );
    assert!(rev2.is_ready(), "the rev2 CTL branch still handles CAPS");
    assert_eq!(out.len(), 0, "a CTL contributes no staged reply");
    // A non-rev2 first byte still falls through to the legacy path, which
    // books REFUSED for an unroutable frame — the single classification must
    // not swallow the fallback.
    let before = dgram_drops::snapshot();
    dispatch_inbound(
        &mut cache,
        &hub,
        &rev2,
        None,
        Bytes::from_static(&[0x70]),
        &mut reasm,
        &mut r2_reasm,
        &mut out,
        coarse_millis(),
    );
    assert!(
        dgram_drops::snapshot().since(&before).refused >= 1,
        "an unroutable legacy frame is still refused on the old path"
    );
}

/// Full-slice round trip: a real association task on a real QUIC connection
/// plus the slot's DATAGRAM dispatcher and the shared egress cache.
///
/// The uplink's first payload must arrive as `DATA OPEN` (with session and
/// address), the server's `FLOW_ACK` must turn the binding `Open`, the next
/// payload must ride a compressed frame, and a server reply must come back
/// through the dispatcher to the app's UDP socket. Association exit then emits
/// best-effort `CTL SESS_CLOSE`.
#[tokio::test]
async fn rev2_full_duplex_round_trip_through_assoc_and_dispatcher() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let hub = Arc::new(UdpHub::new());
    let egress: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // Publish the connection and its negotiated rev2 state as the reconnect
    // loop would, then start the slot's dispatcher on that generation.
    let slot = pool.slot(pool.udp_global_slot(0));
    let state = rev2_state();
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    spawn_dispatcher(slot.clone(), hub.clone());

    // SOCKS5 control connection + UDP ASSOCIATE.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = l.local_addr().unwrap();
    let mut control = tokio::net::TcpStream::connect(control_addr).await.unwrap();
    let (control_server, _) = l.accept().await.unwrap();
    let assoc = tokio::spawn(handle_udp_associate(
        control_server,
        pool.clone(),
        hub.clone(),
        egress.clone(),
    ));
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let target: SocketAddr = "127.0.0.1:5300".parse().unwrap();
    let mut frame = vec![0u8, 0, 0, 0x01];
    frame.extend_from_slice(
        &target
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.extend_from_slice(b"ping");
    app.send_to(&frame, relay).await.unwrap();

    // Uplink: the first payload of a new target is DATA OPEN.
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the assoc must send the first payload")
        .unwrap();
    let open = r2::decode_data(&d).expect("the first uplink frame must be rev2 DATA");
    let id = open.id.expect("a new target opens a flow");
    assert_eq!(open.addr, Some(TargetAddrRef::Ip(target)));
    assert_eq!(open.payload, b"ping");
    assert!(open.sess.is_some(), "OPEN carries the session");

    // The server installs the flow and acks it.
    server_conn
        .send_datagram(r2::encode_ctl(&r2::Ctl::FlowAck {
            id,
            status: r2::R2_ACK_OPEN,
        }))
        .unwrap();
    let binding = state.registry.get(id).expect("the flow is in the registry");
    for _ in 0..10_000 {
        if binding.is_open() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(binding.is_open(), "FLOW_ACK must confirm the uplink flow");

    // Downlink: a compressed reply for that flow reaches the app socket.
    server_conn
        .send_datagram(r2::encode_data_steady(id, b"pong", 1400).unwrap())
        .unwrap();
    let mut b = [0u8; 64];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), app.recv_from(&mut b))
        .await
        .expect("the reply must reach the app")
        .unwrap();
    // SOCKS5 UDP reply header: RSV/FRAG + ATYP 0x01 + IPv4 + port, then the
    // payload verbatim.
    assert_eq!(&b[..4], &[0, 0, 0, 0x01]);
    assert_eq!(&b[4..8], &[127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([b[8], b[9]]), target.port());
    assert_eq!(&b[10..n], b"pong", "payload must arrive verbatim");

    // Uplink after the ack: compressed (no session, no address, 2-byte header).
    app.send_to(&frame, relay).await.unwrap();
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the confirmed flow must send a compressed frame")
        .unwrap();
    match r2::kind(&d) {
        Some(r2::R2Kind::Data) => {
            let f = r2::decode_data(&d).unwrap();
            assert_eq!(f.id, Some(id));
            assert_eq!(f.sess, None);
            assert_eq!(f.addr, None);
            assert_eq!(f.payload, b"ping");
        }
        Some(r2::R2Kind::Train) => {
            let t = r2::decode_train(&d).unwrap();
            let items: Vec<(u32, &[u8])> = t.items().collect();
            assert_eq!(items, vec![(id, &b"ping"[..])]);
        }
        other => panic!("expected a compressed frame, got {other:?}"),
    }

    // Association exit: best-effort SESS_CLOSE on the same connection.
    drop(control);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("association exit must send a control frame")
        .unwrap();
    match r2::decode_ctl(&d).expect("exit control frame must decode") {
        r2::Ctl::SessClose { sess, .. } => {
            assert_ne!(sess, 0);
        }
        other => panic!("expected SESS_CLOSE, got {other:?}"),
    }

    assoc.abort();
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// ---------------- MQP-3 wire rev2 fragmentation (Phase 1b) ----------------

/// Reassemble the next payload from `server_conn`'s rev2 `FRAG` frames. Returns
/// the payload and how many frames it took; every received datagram must be a
/// rev2 frame (the client no longer emits MQP-2 for any payload size).
async fn recv_rev2_fragments(
    server_conn: &quinn::Connection,
    reasm: &mut R2Reassembler,
) -> (R2Assembled, usize) {
    let mut frames = 0usize;
    loop {
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("a rev2 fragment must arrive")
            .unwrap();
        assert!(
            r2::is_r2(&d),
            "the client must never emit a legacy MQP-2 frame (first byte {:?})",
            d.first()
        );
        let f = r2::decode_frag(&d).expect("the frame must be rev2 FRAG");
        frames += 1;
        if let Some(done) = reasm.push(&d, &f, coarse_millis()) {
            return (done, frames);
        }
    }
}

/// A payload above one frame is fragmented with `OPEN` addressing while the
/// flow is still opening (first fragment carries session + address), then with
/// steady addressing once the ack confirmed it. Every frame is rev2.
#[tokio::test]
async fn client_rev2_large_payload_fragments_open_then_steady() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let big: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    // A limit below the payload forces the fragment path even though the
    // loopback connection could carry more.
    let limit = 400usize;

    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let mut reasm = R2Reassembler::new();
    let (open, frames) = recv_rev2_fragments(&server_conn, &mut reasm).await;
    assert!(frames >= 2, "the payload must span several frames");
    let id = open
        .wire_id
        .expect("flow-addressed fragments name the wire id");
    assert_eq!(open.sess, Some(7), "the OPEN fragment carries the session");
    assert_eq!(open.addr, Some(addr.clone()));
    assert_eq!(open.payload, big);

    // Ack it, then the same payload fragments with steady frames only.
    let binding = rev2.registry.get(id).expect("the flow is in the registry");
    binding.mark_open();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let mut reasm = R2Reassembler::new();
    let (steady, frames) = recv_rev2_fragments(&server_conn, &mut reasm).await;
    assert!(frames >= 2);
    assert_eq!(steady.wire_id, Some(id));
    assert_eq!(steady.sess, None, "steady fragments carry no session");
    assert_eq!(steady.addr, None, "steady fragments carry no address");
    assert_eq!(steady.payload, big);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A payload above [`BATCH_SMALL_MAX`] that *does* fit one frame stays one
/// standalone `DATA`/`OPEN` frame — fragmentation is for overflow, not for
/// every large payload (fate sharing: one frame lost, one payload lost).
#[tokio::test]
async fn client_rev2_large_payload_fits_one_data_frame() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let limit = client_conn.max_datagram_size().unwrap();

    // Opening: one DATA OPEN frame (session + address).
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the single open frame must arrive")
        .unwrap();
    assert!(r2::is_r2(&d));
    let f = r2::decode_data(&d).expect("a fitting payload is one DATA frame, not FRAG");
    let id = f.id.expect("the flow was opened");
    assert_eq!(f.sess, Some(7));
    assert_eq!(f.addr, Some(addr.as_ref()));
    assert_eq!(f.payload, big);

    // Confirmed: one compressed steady frame.
    rev2.registry.get(id).unwrap().mark_open();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the single steady frame must arrive")
        .unwrap();
    assert!(r2::is_r2(&d));
    let f = r2::decode_data(&d).expect("a fitting payload is one DATA frame, not FRAG");
    assert_eq!(f.id, Some(id));
    assert_eq!(f.sess, None);
    assert_eq!(f.payload, big);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Registry full ⇒ a large payload is fragmented in the self-describing
/// `INLINE` form (session + address on every frame), the fail-safe that still
/// delivers when no wire id can be bound.
#[tokio::test]
async fn client_rev2_large_inline_fragments() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    // Fill the connection registry so `ensure_binding` must fail.
    let filler = TargetAddr::Ip("203.0.113.7:9".parse().unwrap());
    for i in 1..=R2_MAX_FLOWS_PER_CONN as u32 {
        let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 2, filler.clone());
        assert!(rev2.registry.insert(b).is_ok());
    }
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let big: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    assert!(
        send_uplink(
            &client_conn,
            400,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let mut reasm = R2Reassembler::new();
    let (done, frames) = recv_rev2_fragments(&server_conn, &mut reasm).await;
    assert!(frames >= 2);
    assert_eq!(done.wire_id, None, "INLINE fragments carry no wire id");
    assert_eq!(done.sess, Some(7));
    assert_eq!(done.addr, Some(addr.clone()));
    assert_eq!(done.payload, big);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The negotiated `CAPS.max_frame_bytes` is the live per-frame cap: a payload
/// that would fit the raw QUIC budget is fragmented when the peer negotiated a
/// smaller frame.
#[tokio::test]
async fn client_rev2_caps_frame_cap_forces_fragments() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = ConnRev2::new();
    rev2.on_caps(r2::Caps {
        max_frame_bytes: 400,
        ..r2::Caps::default()
    });
    assert!(rev2.is_ready());
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    // Pre-built confirmed binding: the payload itself (> 1000 B) must fragment
    // even though it is smaller than the raw connection budget.
    let binding = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr.clone());
    binding.mark_open();
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    up.sync(&rev2);
    assert!(up.flows.insert(binding));
    let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let conn_limit = client_conn.max_datagram_size().unwrap();
    assert!(
        conn_limit > 1000,
        "premise: the raw budget would fit the payload"
    );
    assert!(
        send_uplink(
            &client_conn,
            conn_limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    let mut reasm = R2Reassembler::new();
    let (done, frames) = recv_rev2_fragments(&server_conn, &mut reasm).await;
    assert!(
        frames >= 2,
        "CAPS.max_frame_bytes must bound the single frame"
    );
    assert_eq!(done.payload, big);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Wire order between the connection stager's queued small payloads and a
/// following standalone large payload: the queue is drained first, so the peer
/// never sees the large payload overtake the small one queued before it.
#[tokio::test]
async fn client_rev2_large_after_queued_small_keeps_order() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let binding = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr.clone());
    binding.mark_open();
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    up.sync(&rev2);
    assert!(up.flows.insert(binding.clone()));
    let limit = 400usize;

    // Small payload of the open flow: queued on the connection stager, nothing
    // on the wire yet.
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            b"small",
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    // Large payload: must drain the queue first, then go out directly.
    let big: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            &big,
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );

    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the drained queue must arrive first")
        .unwrap();
    assert!(r2::is_r2(&d));
    let first = r2::decode_data(&d).expect("a one-item drain sends a steady DATA frame");
    assert_eq!(first.id, Some(binding.wire_id));
    assert_eq!(first.payload, b"small");

    let mut reasm = R2Reassembler::new();
    let (done, frames) = recv_rev2_fragments(&server_conn, &mut reasm).await;
    assert!(frames >= 2);
    assert_eq!(done.payload, big);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// An address the SOCKS5 form cannot encode is a `TooLarge` drop with the same
/// accounting the legacy fragmenter used — never a legacy send.
#[tokio::test]
async fn client_rev2_unencodable_addr_is_too_large() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let long = "a".repeat(300);
    let addr = TargetAddrRef::Domain(&long, 53);
    assert!(
        addr.header().is_err(),
        "premise: the address is unencodable"
    );
    let before = dgram_drops::snapshot();
    let sent = send_uplink(
        &client_conn,
        1200,
        7,
        &addr,
        b"payload",
        bind,
        &rev2,
        &mut up,
        &mut frag,
    );
    assert_eq!(sent.failed, Some(DatagramSend::TooLarge));
    assert_eq!(sent.frames, 0);
    let delta = dgram_drops::snapshot().since(&before);
    assert!(
        delta.too_large >= 1,
        "the unencodable target must book a TOO_LARGE drop"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server_conn.read_datagram())
            .await
            .is_err(),
        "nothing may be sent for an unencodable target"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Downlink rev2 FRAG: out-of-order `OPEN|SRC` fragments reassemble, learn the
/// reply source and deliver through the association's staged-reply path.
#[tokio::test]
async fn dispatch_rev2_frag_open_src_out_of_order() {
    let assoc = test_assoc().await;
    let sess = 7u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let binding = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        sess,
        TargetAddr::Domain("example.com".to_string(), 53),
    );
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    let src: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    // Deliver the steady tail first: the reassembler keeps the context from
    // whichever fragment carries it.
    let tail = r2::encode_frag_steady(binding.wire_id, 99, 1, 2, b"world", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, tail, &mut out),
        0,
        "a partial payload delivers nothing"
    );
    let head = r2::encode_frag_open(
        binding.wire_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        99,
        0,
        2,
        b"hello ",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, head, &mut out),
        1
    );
    assert_eq!(out[0].dst, src, "OPEN|SRC fragments learn the reply source");
    assert_eq!(out[0].payload, &b"hello world"[..]);
    assert_eq!(binding.reply_src(), Some(src));
    assert!(binding.is_open(), "a downlink payload is the implicit ACK");
    assert_eq!(reasm.inflight(), 0);
}

/// Downlink inline fragments: session + address self-describe the route, and a
/// steady frame set for an uninstalled wire id is dropped and counted.
#[tokio::test]
async fn dispatch_rev2_frag_inline_and_unknown_id() {
    let assoc = test_assoc().await;
    let sess = 5u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let src: SocketAddr = "198.51.100.44:443".parse().unwrap();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let head =
        r2::encode_frag_inline(sess, &TargetAddrRef::Ip(src), false, 3, 0, 2, b"ab", 1400).unwrap();
    let tail =
        r2::encode_frag_inline(sess, &TargetAddrRef::Ip(src), false, 3, 1, 2, b"cd", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, head, &mut out),
        0
    );
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, tail, &mut out),
        1
    );
    assert_eq!(out[0].dst, src);
    assert_eq!(out[0].payload, &b"abcd"[..]);

    // Unknown wire id: reassembly succeeds, the registry lookup does not.
    let unknown = r2::make_wire_id(9999, false).unwrap();
    let before = counters::snapshot();
    for idx in 0..2u8 {
        let d = if idx == 0 {
            r2::encode_frag_steady(unknown, 77, 0, 2, b"xx", 1400).unwrap()
        } else {
            r2::encode_frag_steady(unknown, 77, 1, 2, b"yy", 1400).unwrap()
        };
        assert_eq!(
            dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, d, &mut out),
            0
        );
    }
    assert!(
        counters::since(&before).rx_unknown_id >= 1,
        "an uninstalled id is counted, not guessed"
    );
}

/// A partial rev2 payload expires on the connection's reassembly tick, so a
/// peer that sends one fragment and stops cannot pin memory.
#[tokio::test]
async fn dispatch_rev2_frag_partial_expires() {
    let assoc = test_assoc().await;
    let sess = 6u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let binding = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        sess,
        TargetAddr::Ip("198.51.100.1:53".parse().unwrap()),
    );
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let half = r2::encode_frag_steady(binding.wire_id, 42, 0, 2, b"half", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, half, &mut out),
        0
    );
    assert_eq!(reasm.inflight(), 1);
    // `expire` takes an absolute clock reading, not a duration. Reading the
    // clock after the push makes this deterministic on any runner (the old
    // `expire(FRAG_TIMEOUT_MS)` depended on the process-uptime clock still
    // being near zero, which is not true on slower/real CI machines).
    reasm.expire(coarse_millis() + FRAG_TIMEOUT_MS + 1);
    assert_eq!(reasm.inflight(), 0, "the partial must expire");
    // The missing fragment arriving after expiry cannot complete the payload.
    let tail = r2::encode_frag_steady(binding.wire_id, 42, 1, 2, b"tail", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, tail, &mut out),
        0
    );
    assert!(out.is_empty());
    assert_eq!(reasm.inflight(), 1, "the late tail starts a new partial");
}

// ---------------- Phase 2: connection-level cross-session stager ----------------

/// Two associations (four payload flows, sessions 1 and 2) share one
/// connection: their queued steady payloads are packed into **one** `TRAIN
/// dict` carrying both wire ids, instead of one frame per association.
#[tokio::test]
async fn rev2_stager_packs_two_associations_into_one_dict_train() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut frag = R2Fragmenter::new();
    let limit = client_conn.max_datagram_size().unwrap();
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let a = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let b = TargetAddr::Ip("203.0.113.7:5353".parse().unwrap());
    let mut up_a = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut up_b = UplinkFlows::new(Arc::new(CloseSignal::new()));

    // Open both flows (one standalone OPEN each) and ack them, exactly like two
    // associations whose first datagrams opened a flow.
    assert!(
        send_uplink(
            &client_conn,
            limit,
            1,
            &a.as_ref(),
            b"a0",
            bind,
            &rev2,
            &mut up_a,
            &mut frag
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("session 1 open")
        .unwrap();
    let id_a = r2::decode_data(&d).unwrap().id.unwrap();
    rev2.registry.get(id_a).unwrap().mark_open();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            2,
            &b.as_ref(),
            b"b0",
            bind,
            &rev2,
            &mut up_b,
            &mut frag
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("session 2 open")
        .unwrap();
    let id_b = r2::decode_data(&d).unwrap().id.unwrap();
    rev2.registry.get(id_b).unwrap().mark_open();

    // Both associations queue one steady payload before the next drain.
    assert!(
        send_uplink(
            &client_conn,
            limit,
            1,
            &a.as_ref(),
            b"a1",
            bind,
            &rev2,
            &mut up_a,
            &mut frag
        )
        .complete()
    );
    assert!(
        send_uplink(
            &client_conn,
            limit,
            2,
            &b.as_ref(),
            b"b1",
            bind,
            &rev2,
            &mut up_b,
            &mut frag
        )
        .complete()
    );
    assert_eq!(rev2.stage_len(), 2, "both payloads wait for one drain");
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the cross-session train must arrive")
        .unwrap();
    let t = r2::decode_train(&d).expect("two steady items become a dict train");
    assert_eq!(t.form, r2::R2_TRAIN_FORM_DICT);
    assert_eq!(t.nfl, 2, "one flow id per session");
    let items: Vec<(u32, &[u8])> = t.items().collect();
    assert_eq!(items, vec![(id_a, &b"a1"[..]), (id_b, &b"b1"[..])]);
    assert_eq!(rev2.stage_len(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server_conn.read_datagram())
            .await
            .is_err(),
        "two payloads from two sessions must be one frame, not two"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Per-session FIFO order survives the round-robin packing, and a later drain
/// continues after the earlier payloads of the same session.
#[tokio::test]
async fn rev2_stager_preserves_per_session_order_across_drains() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut frag = R2Fragmenter::new();
    let limit = client_conn.max_datagram_size().unwrap();
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let a = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let b = TargetAddr::Ip("203.0.113.7:5353".parse().unwrap());
    let mut up_a = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut up_b = UplinkFlows::new(Arc::new(CloseSignal::new()));
    // Open and ack both flows deterministically.
    for (sess, target, up) in [(1u32, &a, &mut up_a), (2u32, &b, &mut up_b)] {
        assert!(
            send_uplink(
                &client_conn,
                limit,
                sess,
                &target.as_ref(),
                b"x",
                bind,
                &rev2,
                up,
                &mut frag
            )
            .complete()
        );
        drain_now(&rev2, &client_conn, limit);
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("open")
            .unwrap();
        let id = r2::decode_data(&d).unwrap().id.unwrap();
        rev2.registry.get(id).unwrap().mark_open();
    }

    // Three payloads on session 1, two on session 2, queued before one drain.
    for body in [&b"a1"[..], &b"a2"[..], &b"a3"[..]] {
        assert!(
            send_uplink(
                &client_conn,
                limit,
                1,
                &a.as_ref(),
                body,
                bind,
                &rev2,
                &mut up_a,
                &mut frag
            )
            .complete()
        );
    }
    for body in [&b"b1"[..], &b"b2"[..]] {
        assert!(
            send_uplink(
                &client_conn,
                limit,
                2,
                &b.as_ref(),
                body,
                bind,
                &rev2,
                &mut up_b,
                &mut frag
            )
            .complete()
        );
    }
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("train")
        .unwrap();
    let t = r2::decode_train(&d).expect("train frame");
    let order: Vec<&[u8]> = t.items().map(|(_, p)| p).collect();
    // The stager interleaves sessions (round robin) but must not reorder one
    // session's payloads relative to each other.
    let s1: Vec<&[u8]> = order.iter().copied().filter(|p| p[0] == b'a').collect();
    let s2: Vec<&[u8]> = order.iter().copied().filter(|p| p[0] == b'b').collect();
    assert_eq!(s1, vec![&b"a1"[..], &b"a2"[..], &b"a3"[..]]);
    assert_eq!(s2, vec![&b"b1"[..], &b"b2"[..]]);

    // A later drain continues the session order without replaying retired ones.
    assert!(
        send_uplink(
            &client_conn,
            limit,
            1,
            &a.as_ref(),
            b"a4",
            bind,
            &rev2,
            &mut up_a,
            &mut frag
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("later payload")
        .unwrap();
    assert_eq!(r2::decode_data(&d).unwrap().payload, b"a4");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// `Open` and `Inline` items are self-describing standalone frames; they never
/// join a train and they keep their own session/address headers.
#[tokio::test]
async fn rev2_stager_open_and_inline_items_are_standalone() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let limit = client_conn.max_datagram_size().unwrap();
    let a = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let b = TargetAddr::Ip("203.0.113.7:5353".parse().unwrap());
    let id = r2::make_wire_id(1, false).unwrap();
    assert!(
        rev2.registry
            .insert(FlowBinding::new_shared(id, 1, a.clone()))
            .is_ok()
    );
    // A steady item from session 3, an Open item from session 1 and an Inline
    // item from session 2: the two self-describing frames are standalone.
    for item in [
        R2StageItem {
            session: 3,
            kind: R2StageKind::Steady {
                wire_id: r2::make_wire_id(2, false).unwrap(),
            },
            payload: Bytes::from_static(b"steady"),
        },
        R2StageItem {
            session: 1,
            kind: R2StageKind::Open {
                wire_id: id,
                sess: 1,
                addr: a.clone(),
                src: false,
            },
            payload: Bytes::from_static(b"open"),
        },
        R2StageItem {
            session: 2,
            kind: R2StageKind::Inline {
                sess: 2,
                addr: b.clone(),
                src: false,
            },
            payload: Bytes::from_static(b"inline"),
        },
    ] {
        assert!(rev2.push_stage(item).is_ok());
    }
    drain_now(&rev2, &client_conn, limit);
    let mut frames = Vec::new();
    for _ in 0..3 {
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("each item is one frame")
            .unwrap();
        frames.push(d);
    }
    let mut saw_open = false;
    let mut saw_inline = false;
    let mut saw_steady = false;
    for d in &frames {
        match r2::kind(d) {
            Some(r2::R2Kind::Data) => {
                let f = r2::decode_data(d).unwrap();
                if f.id.is_none() {
                    assert_eq!(f.sess, Some(2));
                    assert_eq!(f.addr, Some(b.as_ref()));
                    assert_eq!(f.payload, b"inline");
                    saw_inline = true;
                } else if f.sess.is_some() {
                    assert_eq!(f.id, Some(id));
                    assert_eq!(f.addr, Some(a.as_ref()));
                    assert_eq!(f.payload, b"open");
                    saw_open = true;
                } else {
                    assert_eq!(f.payload, b"steady");
                    saw_steady = true;
                }
            }
            other => panic!("standalone items must be DATA frames, got {other:?}"),
        }
    }
    assert!(saw_open && saw_inline && saw_steady);
    assert_eq!(rev2.stage_len(), 0);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A full stager queue that a drain cannot empty books the payload as a full
/// send buffer instead of losing it silently.
#[tokio::test]
async fn rev2_stage_queue_full_accounts_buffer_full() {
    let (client_conn, _server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    // One byte of capacity: no payload can ever be queued.
    let rev2 = ConnRev2::with_stager_capacity(8, 1);
    rev2.on_caps(r2::Caps::default());
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    let before = dgram_drops::snapshot();
    let sent = send_uplink(
        &client_conn,
        limit,
        7,
        &addr.as_ref(),
        b"payload",
        bind,
        &rev2,
        &mut up,
        &mut frag,
    );
    assert_eq!(sent.failed, Some(DatagramSend::Blocked));
    assert_eq!(sent.frames, 0);
    assert_eq!(rev2.stage_len(), 0, "a refused payload is not queued");
    assert!(
        dgram_drops::snapshot().since(&before).buffer_full >= 1,
        "the full-queue drop must book BUFFER_FULL"
    );

    client_conn.close(0u32.into(), b"done");
}

/// A drain verdict of `ConnectionLost` propagates through `PayloadSend.failed`
/// so the existing recovery invalidates the egress cache instead of leaving a
/// dead handle cached.
#[tokio::test]
async fn rev2_stage_drain_propagates_connection_lost() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let rev2 = rev2_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let limit = client_conn.max_datagram_size().unwrap();
    let addr = TargetAddr::Ip("198.51.100.9:4242".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    // Pre-open/ack a flow and queue one steady payload behind the association.
    let binding = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr.clone());
    binding.mark_open();
    assert!(rev2.registry.insert(binding.clone()).is_ok());
    up.sync(&rev2);
    assert!(up.flows.insert(binding.clone()));
    assert!(
        rev2.push_stage(R2StageItem {
            session: 7,
            kind: R2StageKind::Steady {
                wire_id: binding.wire_id
            },
            payload: Bytes::from_static(b"queued"),
        })
        .is_ok()
    );
    // Kill the connection, then send a large payload: it drains first (and
    // meets the dead connection) before going out itself.
    client_conn.close(0u32.into(), b"done");
    for _ in 0..10_000 {
        if client_conn.close_reason().is_some() && server_conn.close_reason().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let sent = send_uplink(
        &client_conn,
        limit,
        7,
        &addr.as_ref(),
        &big,
        bind,
        &rev2,
        &mut up,
        &mut frag,
    );
    assert_eq!(
        sent.failed,
        Some(DatagramSend::ConnectionLost),
        "a dead connection must surface its verdict to the egress recovery"
    );
    assert_eq!(rev2.stage_len(), 0, "the failed drain accounts its items");
}

/// A redial (new connection state) never inherits the previous generation's
/// queued payloads: the old stager is torn down with them and the new one
/// starts empty (the teardown accounting itself is unit-tested in `rev2`).
#[tokio::test]
async fn rev2_stager_resets_with_the_connection_generation() {
    let old = rev2_state();
    let new = ConnRev2::new();
    assert_ne!(old.epoch, new.epoch);
    let id = old.ids.alloc().unwrap();
    assert!(
        old.push_stage(R2StageItem {
            session: 1,
            kind: R2StageKind::Steady { wire_id: id },
            payload: Bytes::from_static(b"old"),
        })
        .is_ok()
    );
    assert_eq!(old.stage_len(), 1);
    // A fresh generation's stager is empty, and an association's flow table is
    // reset by the epoch check, so the old item can never be sent with new ids.
    assert_eq!(new.stage_len(), 0);
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    up.sync(&new);
    assert!(up.flows.is_empty());
}

// ---------------- Final symmetry: server-owned flows (full-cone) ----------------

/// A server-owned, never-seen `DATA OPEN|SRC` installs a local binding (the
/// reply is staged immediately), a following compressed frame on that id
/// resolves, and the app's reply reuses the same server-owned wire id instead
/// of burning a client-owned one.
#[tokio::test]
async fn rev2_server_owned_open_installs_and_reuses_on_uplink() {
    let assoc = test_assoc().await;
    let sess = 7u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let src: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let server_id = r2::make_wire_id(1, true).unwrap();
    assert!(
        r2::wire_id_server_owned(server_id),
        "premise: server-owned id"
    );
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let before = counters::snapshot();

    // The server's unsolicited OPEN|SRC: unknown id, self-describing context.
    let frame = r2::encode_data_open(
        server_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        b"unsolicited",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        1
    );
    assert_eq!(out[0].dst, src);
    assert_eq!(out[0].payload, &b"unsolicited"[..]);
    let binding = rev2
        .registry
        .get(server_id)
        .expect("the server-owned flow must be installed");
    assert_eq!(binding.session, sess);
    assert_eq!(binding.target, TargetAddr::Ip(src));
    assert_eq!(binding.reply_src(), Some(src));
    assert!(binding.is_open(), "the announcing OPEN is the flow's ack");
    assert!(
        counters::since(&before).server_flow_accept >= 1,
        "the accepted flow is counted"
    );

    // A later compressed frame on that id resolves through the new binding.
    let frame = r2::encode_data_steady(server_id, b"more", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        1
    );
    assert_eq!(out[1].dst, src);
    assert_eq!(out[1].payload, &b"more"[..]);

    // Unknown *client-owned* ids are still dropped and never installed.
    let client_unknown = r2::make_wire_id(9999, false).unwrap();
    let frame = r2::encode_data_steady(client_unknown, b"stale", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        0
    );
    assert!(rev2.registry.get(client_unknown).is_none());
    // ... and a TRAIN item never installs a flow (no address to name it).
    let server_unknown = r2::make_wire_id(4242, true).unwrap();
    let frame = r2::encode_train_same(server_unknown, &[b"y"], 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        0
    );
    assert!(rev2.registry.get(server_unknown).is_none());

    // Uplink: the app replies to that source on a real connection; the frame
    // must carry the server-owned id (owner bit 1), not a fresh client id.
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            sess,
            &TargetAddr::Ip(src).as_ref(),
            b"app-reply",
            bind,
            &rev2,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    drain_now(&rev2, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the app reply must reach the server")
        .unwrap();
    let f = r2::decode_data(&d).expect("steady DATA");
    assert_eq!(f.id, Some(server_id));
    assert!(
        r2::wire_id_server_owned(f.id.unwrap()),
        "the reply must ride the server-owned flow"
    );
    assert_eq!(f.sess, None);
    assert_eq!(f.payload, b"app-reply");
    assert_eq!(rev2.ids.allocated(), 0, "no client-owned id was burned");
    assert!(up.flows.find_id(server_id).is_some());

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A fragmented server-owned `OPEN|SRC` installs the same way (the first
/// fragment carries the self-describing context), so a large unsolicited reply
/// also becomes a reusable flow.
#[tokio::test]
async fn rev2_server_owned_fragmented_open_installs() {
    let assoc = test_assoc().await;
    let sess = 3u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let src: SocketAddr = "198.51.100.44:443".parse().unwrap();
    let server_id = r2::make_wire_id(2, true).unwrap();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let head = r2::encode_frag_open(
        server_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        11,
        0,
        2,
        b"big-",
        1400,
    )
    .unwrap();
    let tail = r2::encode_frag_steady(server_id, 11, 1, 2, b"reply", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, head, &mut out),
        0
    );
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, tail, &mut out),
        1
    );
    assert_eq!(out[0].dst, src);
    assert_eq!(out[0].payload, &b"big-reply"[..]);
    let binding = rev2
        .registry
        .get(server_id)
        .expect("fragmented server-owned flow installed");
    assert_eq!(binding.reply_src(), Some(src));
    assert!(binding.is_open());
}

/// `SESS_CLOSE` purges every registry entry of that session — client-owned and
/// accepted server-owned — while other sessions keep their flows.
#[tokio::test]
async fn rev2_sess_close_purges_registry_entries() {
    let rev2 = rev2_state();
    let client_owned = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        7,
        TargetAddr::Ip("198.51.100.1:53".parse().unwrap()),
    );
    let server_owned = FlowBinding::new_shared(
        r2::make_wire_id(1, true).unwrap(),
        7,
        TargetAddr::Ip("203.0.113.9:53".parse().unwrap()),
    );
    let other_session = FlowBinding::new_shared(
        r2::make_wire_id(2, false).unwrap(),
        8,
        TargetAddr::Ip("192.0.2.7:53".parse().unwrap()),
    );
    for b in [&client_owned, &server_owned, &other_session] {
        assert!(rev2.registry.insert(b.clone()).is_ok());
    }
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    // The close notification is only recorded for a live association.
    let hub = UdpHub::new();
    let assoc = test_assoc().await;
    hub.publish(7, assoc.entry.clone());
    let frame = r2::encode_ctl(&r2::Ctl::SessClose { sess: 7, reason: 0 });
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        0
    );
    assert!(rev2.registry.get(client_owned.wire_id).is_none());
    assert!(rev2.registry.get(server_owned.wire_id).is_none());
    assert!(
        rev2.registry.get(other_session.wire_id).is_some(),
        "another session's flows are untouched"
    );
    assert!(assoc.entry.closed.take());
    // `remove_session` detaches the bindings from the registry; the
    // association's own `sync` marks the ones it still holds closed when it
    // consumes the `SESS_CLOSE` flag, so no tombstone is needed here.
    assert_eq!(client_owned.session, 7);
}

// ---------------- Client severe-issue hardening (LOGIC-2/3/8/11, PERF-3) ----------------

/// LOGIC-8: association-exit cleanup must run even when the generation is still
/// in its handshake window (rev2 not ready) and even when no *fresh* egress
/// handle can be acquired. Only the `SESS_CLOSE` datagram is conditional; the
/// bindings and staged payloads must not leak for the connection's life.
#[tokio::test]
async fn sess_close_cleanup_runs_in_the_handshake_window() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    let bind = pool.udp_bind_shard(EgressClass::Bulk, 0);
    let slot = pool.slot(pool.udp_global_slot(bind.index));
    // A connection published before CAPS, exactly the 0-RTT→CAPS window: the
    // egress cache publishes it optimistically (first packet before the
    // handshake finishes), so a refresh succeeds while `is_ready()` is false.
    let state = ConnRev2::new();
    assert!(
        !state.is_ready(),
        "premise: the handshake has not completed"
    );
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    let now = mono_millis();
    let h = egress
        .refresh_global(&pool, bind, now)
        .expect("a pre-CAPS rev2 generation is still publishable for UDP");
    egress.memo_store(
        bind,
        egress.generation[bind.index].load(std::sync::atomic::Ordering::Relaxed),
        &h.conn,
        h.limit,
        h.stamp_ms,
        &h.rev2,
    );

    let wire_id = r2::make_wire_id(1, false).unwrap();
    let binding = FlowBinding::new_shared(
        wire_id,
        7,
        TargetAddr::Ip("198.51.100.9:4242".parse().unwrap()),
    );
    assert!(state.registry.insert(binding).is_ok());
    assert!(
        state
            .push_stage(R2StageItem {
                session: 7,
                kind: R2StageKind::Steady { wire_id },
                payload: bytes::Bytes::from_static(b"queued"),
            })
            .is_ok()
    );

    send_sess_close(&egress, &pool, Some(bind), 7, state.epoch);

    assert!(
        state.registry.is_empty(),
        "the exit must release the session's bindings even before CAPS"
    );
    assert_eq!(
        state.stage_len(),
        0,
        "and its staged payloads, so a later drain cannot send them"
    );
    // Only the control frame is skipped: nothing may be put on the wire for a
    // generation that has not negotiated rev2.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server_conn.read_datagram())
            .await
            .is_err(),
        "a handshake-window exit must not send SESS_CLOSE"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// LOGIC-8: a lost egress refresh (no published handle at all) must not block
/// the exit cleanup — the binding's own pool slot still names the generation.
#[tokio::test]
async fn sess_close_cleanup_reaches_the_slot_without_a_published_handle() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    let bind = pool.udp_bind_shard(EgressClass::Bulk, 0);
    let slot = pool.slot(pool.udp_global_slot(bind.index));
    let state = rev2_state();
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    // Deliberately no `refresh_global`/`memo_store`: this is the association
    // whose only refresh lost the single-flight race.
    assert!(
        egress.cached_handle(bind).is_none(),
        "premise: no published egress handle"
    );
    let wire_id = r2::make_wire_id(1, false).unwrap();
    let binding = FlowBinding::new_shared(
        wire_id,
        7,
        TargetAddr::Ip("198.51.100.9:4242".parse().unwrap()),
    );
    assert!(state.registry.insert(binding).is_ok());
    assert!(
        state
            .push_stage(R2StageItem {
                session: 7,
                kind: R2StageKind::Steady { wire_id },
                payload: bytes::Bytes::from_static(b"lost"),
            })
            .is_ok()
    );

    send_sess_close(&egress, &pool, Some(bind), 7, state.epoch);

    assert!(
        state.registry.is_empty(),
        "the slot-direct fallback must still release the bindings"
    );
    assert_eq!(state.stage_len(), 0);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// LOGIC-8: the exit cleanup is generation-gated: a newer generation's fresh
/// tables must never be touched by the old association's exit.
#[test]
fn sess_close_cleanup_never_touches_a_newer_generation() {
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress = SharedEgress::default();
    let bind = pool.udp_bind_shard(EgressClass::Bulk, 0);
    let slot = pool.slot(pool.udp_global_slot(bind.index));
    let old = ConnRev2::new();
    let new = ConnRev2::with_stager_capacity(4, 4096);
    assert_ne!(old.epoch, new.epoch);
    slot.set_rev2(new.clone());
    // The new generation's own state (a different session) must survive.
    let keep = FlowBinding::new_shared(
        r2::make_wire_id(1, false).unwrap(),
        9,
        TargetAddr::Ip("203.0.113.9:53".parse().unwrap()),
    );
    assert!(new.registry.insert(keep.clone()).is_ok());
    assert!(
        new.push_stage(R2StageItem {
            session: 9,
            kind: R2StageKind::Steady {
                wire_id: keep.wire_id
            },
            payload: bytes::Bytes::from_static(b"new-gen"),
        })
        .is_ok()
    );
    // The old association exits: its epoch no longer matches the slot's.
    send_sess_close(&egress, &pool, Some(bind), 7, old.epoch);

    assert!(
        new.registry.get(keep.wire_id).is_some(),
        "a newer generation's bindings are never touched"
    );
    assert_eq!(
        new.stage_len(),
        1,
        "nor its staged payloads (they belong to other sessions)"
    );
}

/// LOGIC-3: an `OPEN|SRC` binding frame (server-owned install or a rebind of a
/// client-owned flow) is confirmed with `CTL FLOW_ACK {id, status: 0}`, and a
/// duplicate binding frame is re-acked idempotently (a lost ACK is recovered by
/// the peer's rebind, so the receiver must keep answering).
#[tokio::test]
async fn dispatch_rev2_open_src_sends_flow_ack_idempotently() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let assoc = test_assoc().await;
    let sess = 7u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let src: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let server_id = r2::make_wire_id(1, true).unwrap();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let before = counters::snapshot();

    let frame = r2::encode_data_open(
        server_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        b"unsolicited",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            Some(&client_conn),
            frame.clone(),
            &mut out
        ),
        1
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the OPEN|SRC must be confirmed")
        .unwrap();
    match r2::decode_ctl(&d).expect("the confirmation must be a CTL frame") {
        r2::Ctl::FlowAck { id, status } => {
            assert_eq!(id, server_id);
            assert_eq!(status, r2::R2_ACK_OPEN);
        }
        other => panic!("expected FLOW_ACK, got {other:?}"),
    }
    assert!(counters::since(&before).flow_ack_tx >= 1);

    // The same idempotent binding frame again (the peer missed the first ACK):
    // it resolves through the registry and must be re-acked.
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            Some(&client_conn),
            frame,
            &mut out
        ),
        1
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("a duplicate binding frame is re-acked")
        .unwrap();
    assert!(matches!(
        r2::decode_ctl(&d).expect("second confirmation"),
        r2::Ctl::FlowAck { id, status } if id == server_id && status == r2::R2_ACK_OPEN
    ));
    assert_eq!(
        rev2.registry.len(),
        1,
        "the duplicate install did not create a second binding"
    );

    // Client-owned rebind: the server teaches the actual source of a flow this
    // side opened; the client must confirm that too.
    let client_id = r2::make_wire_id(2, false).unwrap();
    let client_binding = FlowBinding::new_shared(
        client_id,
        sess,
        TargetAddr::Ip("198.51.100.7:443".parse().unwrap()),
    );
    assert!(rev2.registry.insert(client_binding).is_ok());
    let rebind = r2::encode_data_open(
        client_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        b"rebound",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            Some(&client_conn),
            rebind,
            &mut out
        ),
        1
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("a client-owned rebind is confirmed")
        .unwrap();
    assert!(matches!(
        r2::decode_ctl(&d).expect("rebind confirmation"),
        r2::Ctl::FlowAck { id, status } if id == client_id && status == r2::R2_ACK_OPEN
    ));

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// LOGIC-3: a binding frame this side cannot install is answered with
/// `FLOW_REJECT` — `TABLE_FULL` when the per-connection registry is at its cap,
/// `POLICY` otherwise — so the peer can stop re-sending it and fall back to
/// `INLINE`.
#[tokio::test]
async fn dispatch_rev2_install_failure_sends_flow_reject() {
    // The TABLE_FULL arm books a REFUSED drop, like every other counter test
    // that can bump the process-wide counter.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let assoc = test_assoc().await;
    let sess = 7u32;
    let hub = UdpHub::new();
    hub.publish(sess, assoc.entry.clone());
    let rev2 = rev2_state();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();

    // Fill the registry so a server-owned install cannot fit.
    let filler = TargetAddr::Ip("203.0.113.7:9".parse().unwrap());
    for i in 1..=R2_MAX_FLOWS_PER_CONN as u32 {
        let b = FlowBinding::new_shared(r2::make_wire_id(i, false).unwrap(), 2, filler.clone());
        assert!(rev2.registry.insert(b).is_ok());
    }
    assert!(!rev2.registry.has_capacity(), "premise: the table is full");
    let server_id = r2::make_wire_id(1, true).unwrap();
    let src: SocketAddr = "198.51.100.44:443".parse().unwrap();
    let frame = r2::encode_data_open(
        server_id,
        sess,
        &TargetAddrRef::Ip(src),
        true,
        b"cannot-install",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            Some(&client_conn),
            frame,
            &mut out
        ),
        0
    );
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("a full registry must be reported to the peer")
        .unwrap();
    assert!(matches!(
        r2::decode_ctl(&d).expect("reject control frame"),
        r2::Ctl::FlowReject { id, reason }
            if id == server_id && reason == r2::R2_REJECT_TABLE_FULL
    ));

    // An unknown id that is not server-owned (a frame the peer still thinks is
    // bound) gets POLICY: this side cannot install it for any reason.
    let client_unknown = r2::make_wire_id(4242, false).unwrap();
    let steady = r2::encode_data_steady(client_unknown, b"stale", 1400).unwrap();
    assert_eq!(
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            Some(&client_conn),
            steady,
            &mut out
        ),
        0
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("an uninstallable id is rejected")
            .map(|d| r2::decode_ctl(&d).expect("reject control frame")),
        Ok(r2::Ctl::FlowReject {
            id: client_unknown,
            reason: r2::R2_REJECT_POLICY
        })
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The dispatcher raises a `SESS_CLOSE` on a live association only; a close for
/// an exiting or unknown association reaches no consumer.
#[tokio::test]
async fn dispatch_rev2_sess_close_for_a_dead_association_is_not_signalled() {
    let assoc = test_assoc().await;
    let hub = UdpHub::new();
    hub.publish(7, assoc.entry.clone());
    let rev2 = rev2_state();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let mut send = |rev2: &ConnRev2, cache: &mut [DispatchSlot; DISPATCH_CACHE], sess: u32| {
        let frame = r2::encode_ctl(&r2::Ctl::SessClose { sess, reason: 0 });
        dispatch_r2(rev2, cache, &hub, &mut reasm, None, frame, &mut out)
    };
    // Live association: raised, consumed once.
    assert_eq!(send(&rev2, &mut cache, 7), 0);
    assert!(assoc.entry.closed.take());
    assert!(!assoc.entry.closed.take());
    // Exiting association (hub entry still served but no longer alive): not
    // raised, so a peer cannot arm a signal nobody will consume.
    assoc
        .entry
        .alive
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(send(&rev2, &mut cache, 7), 0);
    assert!(!assoc.entry.closed.take());
    // Unknown session: same verdict (no entry, no signal).
    assert_eq!(send(&rev2, &mut cache, 99), 0);
    assert!(!assoc.entry.closed.take());
}

/// LOGIC-11: every SOCKS5 UDP framing reject books a drop (notably `FRAG != 0`,
/// which used to be dropped in total silence).
#[tokio::test]
async fn socks_udp_framing_rejects_are_counted() {
    // REFUSED is process-wide and several dispatch tests assert exact deltas.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let before = dgram_drops::snapshot();
    let valid = [0u8, 0, 0, 0x01, 127, 0, 0, 1, 0, 53, b'x'];
    let (addr, off) = socks_udp_frame(1, &valid).expect("a well-formed frame is accepted");
    assert_eq!(addr, TargetAddrRef::Ip("127.0.0.1:53".parse().unwrap()));
    assert_eq!(&valid[off..], b"x");
    // FRAG != 0: legal SOCKS5 the proxy does not implement.
    let mut frag = valid;
    frag[2] = 1;
    assert!(socks_udp_frame(1, &frag).is_none());
    // Short header and an undecodable target address are refused the same way.
    assert!(socks_udp_frame(1, &[0, 0]).is_none());
    assert!(socks_udp_frame(1, &[0, 0, 0, 0x07]).is_none());
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.refused, 3,
        "every framing reject is counted exactly once, including FRAG != 0"
    );
}

/// LOGIC-11: the app-IP pin tolerates the v4/v6 family difference for loopback
/// and unspecified addresses (a dual-stack app must not be locked out of its
/// own association) while still rejecting a real address mismatch.
#[test]
fn app_ip_pin_is_family_tolerant() {
    let l4: IpAddr = "127.0.0.1".parse().unwrap();
    let l6: IpAddr = "::1".parse().unwrap();
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(
        app_ip_matches(l4, l6),
        "loopback is the same host in both families"
    );
    assert!(app_ip_matches(l6, l4));
    assert!(
        app_ip_matches(l4, mapped),
        "v4-mapped forms are unmapped first"
    );
    let u4: IpAddr = "0.0.0.0".parse().unwrap();
    let u6: IpAddr = "::".parse().unwrap();
    assert!(app_ip_matches(u4, u6));
    assert!(
        !app_ip_matches(l4, u4),
        "a loopback pin is not the wildcard"
    );
    let pub4: IpAddr = "198.51.100.7".parse().unwrap();
    let pub6: IpAddr = "2001:db8::7".parse().unwrap();
    assert!(
        !app_ip_matches(pub4, pub6),
        "only loopback/unspecified are family-equivalent"
    );
    assert!(!app_ip_matches(l4, pub4));
}

/// PERF-3: the main runtime only loses workers to the sharded slot runtimes
/// where those slots are really pinned (Linux), and even there it never drops
/// below half the machine — the shipped 8 slots on an 8-core host must not leave
/// every SOCKS/TCP/UDP task on one worker.
#[test]
fn main_runtime_worker_count_only_subtracts_real_pinning() {
    // Linux: 8 pinned slots on 8 cores may claim at most half the machine, so
    // the app-side pool keeps the other half (the old rule left exactly one).
    assert_eq!(main_runtime_workers_for(8, true, 8, true), 4);
    // A wide machine keeps the one-core-per-slot shape: 16 - 8 = 8.
    assert_eq!(main_runtime_workers_for(16, true, 8, true), 8);
    // 4 cores: 8 slots may only claim 2, leaving 2 workers.
    assert_eq!(main_runtime_workers_for(4, true, 8, true), 2);
    // Degenerate core counts still yield a usable runtime.
    assert_eq!(main_runtime_workers_for(1, true, 8, true), 1);
    assert_eq!(main_runtime_workers_for(2, true, 8, true), 1);
    assert_eq!(main_runtime_workers_for(0, true, 8, true), 1);
    // Off Linux pinning is a no-op: the slot threads reserve no core, so the
    // full default width is kept (this was the one-worker regression).
    assert_eq!(main_runtime_workers_for(8, true, 8, false), 8);
    assert_eq!(main_runtime_workers_for(4, true, 8, false), 4);
    // Shared-runtime topology: no pinned slot threads at all.
    assert_eq!(main_runtime_workers_for(8, false, 8, true), 8);
    assert_eq!(main_runtime_workers_for(0, false, 8, false), 1);
    // Invariant over the whole matrix: pinned slots never take more than half
    // the machine, so the pool that moves payload keeps at least the other
    // half (rounded up) whatever the pool width is.
    for cores in 1..=64usize {
        for slots in [1, 4, 8, 9, 16] {
            let workers = main_runtime_workers_for(cores, true, slots, true);
            assert!(workers >= 1, "cores={cores} slots={slots}");
            assert_eq!(
                workers,
                cores.saturating_sub(slots.min(cores / 2)).max(1),
                "cores={cores} slots={slots}"
            );
            assert!(
                workers >= cores.div_ceil(2),
                "cores={cores} slots={slots} left only {workers} workers"
            );
        }
    }
}

/// The startup fd raise must be sized off the pools that actually spend fds:
/// one accepted socket per SOCKS/`tcp_forward` relay, one socket per UDP
/// association/forward peer, one QUIC endpoint per pool slot. A cap change that
/// leaves this derivation behind makes the raise (and the log line that reports
/// it) understate what the process needs.
#[test]
fn fd_budget_covers_the_relay_and_association_pools() {
    let floor = (MAX_SOCKS_CONNS + MAX_UDP_ASSOCS) as u64;
    assert!(
        designed_fds() >= floor,
        "designed_fds() {} < relay+association floor {floor}",
        designed_fds()
    );
    assert_eq!(
        designed_fds(),
        (MAX_SOCKS_CONNS + MAX_UDP_ASSOCS + MAX_POOL_CONNS + FD_GUARD) as u64,
        "the endpoint term and guard band stay part of the derivation"
    );
}

/// PERF-9: a `TRAIN dict` resolves every distinct id through one `get_batch`
/// hold, stages items in wire order, and keeps per-item unknown-id accounting.
#[tokio::test]
async fn dispatch_rev2_train_dict_batches_ids() {
    let hub = UdpHub::new();
    let a = test_assoc().await;
    let b = test_assoc().await;
    let sess_a = 3u32;
    let sess_b = 4u32;
    hub.publish(sess_a, a.entry.clone());
    hub.publish(sess_b, b.entry.clone());
    let rev2 = rev2_state();
    let dst_a: SocketAddr = "192.0.2.7:5353".parse().unwrap();
    let dst_b: SocketAddr = "198.51.100.8:443".parse().unwrap();
    let id_a = r2::make_wire_id(1, false).unwrap();
    let id_b = r2::make_wire_id(2, false).unwrap();
    for (id, sess, dst) in [(id_a, sess_a, dst_a), (id_b, sess_b, dst_b)] {
        let binding = FlowBinding::new_shared(id, sess, TargetAddr::Ip(dst));
        assert!(rev2.registry.insert(binding).is_ok());
    }
    let flows = [id_a, id_b];
    let items: [(u8, &[u8]); 3] = [(0, b"a1"), (1, b"b1"), (0, b"a2")];
    let frame = r2::encode_train_dict(&flows, &items, 1400).expect("dict train encodes");
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        3
    );
    assert_eq!(out[0].dst, dst_a);
    assert_eq!(out[0].payload, &b"a1"[..]);
    assert_eq!(out[1].dst, dst_b);
    assert_eq!(out[1].payload, &b"b1"[..]);
    assert_eq!(out[2].dst, dst_a, "a repeated id reuses its slot");
    assert_eq!(out[2].payload, &b"a2"[..]);
    out.clear();

    // An unknown id is still counted per item and never installs a flow.
    let unknown = r2::make_wire_id(4242, false).unwrap();
    let flows = [id_a, unknown];
    let items: [(u8, &[u8]); 2] = [(0, b"ok"), (1, b"lost")];
    let frame = r2::encode_train_dict(&flows, &items, 1400).expect("dict train encodes");
    let before = counters::snapshot();
    assert_eq!(
        dispatch_r2(&rev2, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        1
    );
    assert_eq!(out[0].payload, &b"ok"[..]);
    assert!(rev2.registry.get(unknown).is_none());
    assert!(counters::since(&before).rx_unknown_id >= 1);
}

/// C10: the connection handle and the rev2 id tables are paired structurally —
/// a handle from the previous generation is never paired with the next
/// generation's state (wire ids restart at 1 on every dial, so such a pair could
/// resolve a buffered frame against an unrelated live binding).
#[tokio::test]
async fn conn_rev2_pairing_rejects_a_replaced_generation() {
    let (c1, _e1, _s1) = real_connection().await;
    let (c2, _e2, _s2) = real_connection().await;
    let slot = ConnSlot::fresh();
    let r1 = ConnRev2::new();
    slot.set_rev2(r1.clone());
    slot.publish(&c1);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    assert_eq!(
        slot.rev2_for(&c1).map(|r| r.epoch),
        Some(r1.epoch),
        "the paired state is the published generation's"
    );

    // Death + redial publishes a fresh generation: the old handle must not pair
    // with the new state (and no pair may be reported during the transition).
    assert!(slot.clear_if_and_mark_dead(&c1));
    let r2_state = ConnRev2::new();
    slot.set_rev2(r2_state.clone());
    slot.publish(&c2);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    assert!(
        slot.rev2_for(&c1).is_none(),
        "an old connection must not pair with the next generation's id tables"
    );
    assert_eq!(
        slot.rev2_for(&c2).map(|r| r.epoch),
        Some(r2_state.epoch),
        "the fresh pair is returned"
    );
    c1.close(0u32.into(), b"done");
    c2.close(0u32.into(), b"done");
}

/// LOGIC-2/PERF-1 client half: peer-controlled `SESS_CLOSE`/`FLOW_CLOSE`/
/// `FLOW_REJECT` frames are rate-limited per connection; the excess is dropped
/// and counted instead of doing purge work at line rate.
#[test]
fn peer_ctl_frames_are_rate_limited() {
    let rev2 = rev2_state();
    let hub = UdpHub::new();
    let mut cache = empty_dispatch_cache();
    let mut reasm = R2Reassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    let before = counters::snapshot();
    let frame = r2::encode_ctl(&r2::Ctl::FlowClose { id: 999 });
    // Two windows' worth + a margin: even if the coarse clock advances across
    // the loop (resetting the budget once), the tail still exceeds the cap and
    // must be dropped.
    let n = myquic2::mqp::r2_flow::CTL_MAX_PER_SEC * 2 + 8;
    for _ in 0..n {
        assert_eq!(
            dispatch_r2(
                &rev2,
                &mut cache,
                &hub,
                &mut reasm,
                None,
                frame.clone(),
                &mut out
            ),
            0
        );
    }
    assert!(
        counters::since(&before).ctl_rate_limited >= 1,
        "the CTL rate budget must drop the excess frames"
    );
    // FLOW_ACK is exempt: it is needed for the confirmation contract and is one
    // cheap map probe, so a legitimate ack is never refused by the budget.
    let ack = r2::encode_ctl(&r2::Ctl::FlowAck {
        id: 999,
        status: r2::R2_ACK_OPEN,
    });
    let before_ack = counters::since(&before).ctl_rate_limited;
    for _ in 0..16 {
        dispatch_r2(
            &rev2,
            &mut cache,
            &hub,
            &mut reasm,
            None,
            ack.clone(),
            &mut out,
        );
    }
    assert_eq!(
        counters::since(&before).ctl_rate_limited,
        before_ack,
        "FLOW_ACK is deliberately outside the rate budget"
    );
}

/// P2-8: the hub's "published but already dead" arm is an unknown-session drop
/// too, so it must bump the counter its own documentation names (it used to
/// return silently, leaving the dead-entry race uncounted).
#[tokio::test]
async fn dispatch_dead_hub_entry_counts_unknown_session() {
    let assoc = test_assoc().await;
    let hub = UdpHub::new();
    hub.publish(7, assoc.entry.clone());
    // An exiting association: the hub still serves the entry between
    // `AliveGuard` clearing the bit and `UdpHub::release` unpublishing it.
    assoc
        .entry
        .alive
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let mut cache = empty_dispatch_cache();
    let mut reasm = DgramReassembler::new();
    let mut pkt = bytes::BytesMut::with_capacity(256);
    let before = dgram_drops::snapshot();
    dispatch_one(&mut cache, &hub, 7, dgram(7, b"late"), &mut reasm, &mut pkt);
    assert!(
        dgram_drops::snapshot().since(&before).unknown_sess >= 1,
        "a dead hub entry must be counted as an unknown session"
    );
}

// ---------------- TCP/UDP forward listeners ----------------

/// A forwarded UDP peer is an ordinary UDP application: raw mode must write the
/// payload alone. A stray SOCKS5 `RSV|FRAG|ATYP|ADDR|PORT` prefix would be
/// delivered as payload bytes and silently corrupt every forwarded datagram.
#[tokio::test]
async fn raw_reply_frames_payload_without_a_socks5_header() {
    let listener = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    prime_relay(&listener, &peer, peer_addr).await;
    let entry = Arc::new(AssocEntry::new_raw(listener));
    entry.app.store(Some(Arc::new(peer_addr)));
    let payload = Bytes::from_static(b"raw-reply");
    let staged = stage_reply(
        &entry,
        peer_addr,
        "198.51.100.9:53".parse().unwrap(),
        payload.clone(),
    );
    assert!(staged.raw, "a forward association must stage raw replies");
    let mut hdrs = Vec::new();
    let mut offs = Vec::new();
    flush_staged(&mut vec![staged], &mut hdrs, &mut offs);
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(REPLY_WAIT, peer.recv_from(&mut buf))
        .await
        .expect("the raw reply must arrive")
        .unwrap();
    assert_eq!(
        &buf[..n],
        &payload[..],
        "raw mode must deliver exactly the payload"
    );
    assert!(hdrs.is_empty(), "raw mode must not encode a SOCKS5 header");
}

/// The SOCKS5 path keeps its framing: the same staging/flush pair must still
/// prefix the reply with `RSV|FRAG|ATYP|ADDR|PORT`. This is the behaviour the
/// raw-mode branch above must not change.
#[tokio::test]
async fn socks_reply_still_carries_the_socks5_udp_header() {
    let listener = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    prime_relay(&listener, &peer, peer_addr).await;
    let entry = Arc::new(AssocEntry::new(listener));
    entry.app.store(Some(Arc::new(peer_addr)));
    let dst: SocketAddr = "198.51.100.9:53".parse().unwrap();
    let payload = Bytes::from_static(b"framed");
    let staged = stage_reply(&entry, peer_addr, dst, payload.clone());
    assert!(!staged.raw, "a SOCKS association must stay framed");
    let mut hdrs = Vec::new();
    let mut offs = Vec::new();
    flush_staged(&mut vec![staged], &mut hdrs, &mut offs);
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(REPLY_WAIT, peer.recv_from(&mut buf))
        .await
        .expect("the framed reply must arrive")
        .unwrap();
    assert_eq!(&buf[..2], &[0, 0], "RSV must be zero");
    assert_eq!(buf[2], 0, "FRAG must be zero");
    let (addr, consumed) = TargetAddrRef::decode(&buf[3..n]).expect("SOCKS5 address");
    assert_eq!(addr, TargetAddrRef::Ip(dst));
    assert_eq!(&buf[3 + consumed..n], &payload[..]);
}

/// A forwarded TCP stream must (a) write the configured target as the MQP
/// header, (b) write nothing else before the app's bytes, and (c) relay both
/// directions with half-close propagation.
#[tokio::test]
async fn tcp_forward_relays_bytes_and_header_to_the_fixed_target() {
    let (client_conn, server_conn, _ce, _se) = real_connection_with_server().await;
    // One TCP slot: `pick_tcp_index` round-robins the bulk slots, and only
    // slot 0 has a published connection in this test.
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    {
        let slot = pool.slot(0);
        slot.shared.store(Some(Arc::new(client_conn.clone())));
        slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let egress = Arc::new(SharedEgress::default());
    let target: TargetAddr = TargetAddr::Ip("203.0.113.7:8080".parse().unwrap());
    let expected = target.clone();
    // Keep the server-side handle alive until the relay has observed the
    // stream's FIN: the last `Connection` handle dropping closes it, which
    // would surface in the pump as "connection lost" before the clean EOF.
    let server_keepalive = server_conn.clone();
    let server = tokio::spawn(async move {
        let (mut send, mut recv) = server_conn.accept_bi().await.unwrap();
        let mut hdr = [0u8; 7];
        recv.read_exact(&mut hdr).await.unwrap();
        let (got, consumed) = TargetAddr::decode(&hdr).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(got, expected, "the forward target must be the MQP header");
        let bnd: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut ack = [0u8; MAX_TCP_ACK_LEN];
        let n = encode_tcp_ack_into(bnd, &mut ack);
        send.write_all(&ack[..n]).await.unwrap();
        let mut body = [0u8; 16];
        let n = recv.read(&mut body).await.unwrap().unwrap();
        send.write_all(&body[..n]).await.unwrap();
        // Drain the client's FIN before finishing. Dropping a `RecvStream`
        // with unread data sends STOP_SENDING, which the pump treats as an
        // abort; the real server pump reads until EOF, and the test must too.
        while let Ok(Some(_)) = recv.read(&mut body).await {}
        send.finish().unwrap();
    });
    let li = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = li.local_addr().unwrap();
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), li.accept());
    let mut client = client.unwrap();
    let (app_sock, _) = accepted.unwrap();
    let relay = tokio::spawn(relay_tcp_forward(
        app_sock,
        target,
        pool,
        egress,
        Duration::from_secs(5),
    ));
    client.write_all(b"ping").await.unwrap();
    client.shutdown().await.unwrap();
    let relay_result = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("the relay must finish")
        .unwrap();
    assert!(relay_result.is_ok(), "relay failed: {relay_result:?}");
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"ping");
    server.await.unwrap();
    drop(server_keepalive);
}

/// No usable QUIC generation: the forward must fail fast (and reset the app
/// socket), never park the accepted connection until the app gives up.
#[tokio::test]
async fn tcp_forward_fails_fast_without_a_quic_connection() {
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let li = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = li.local_addr().unwrap();
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), li.accept());
    let mut client = client.unwrap();
    let (app_sock, _) = accepted.unwrap();
    let target: TargetAddr = TargetAddr::Ip("203.0.113.7:8080".parse().unwrap());
    let err = relay_tcp_forward(app_sock, target, pool, egress, Duration::from_millis(200))
        .await
        .expect_err("there is no live connection to open a stream on");
    assert!(!err.to_string().is_empty());
    let mut probe = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut probe)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("app socket must close (FIN or RST) fast, got {other:?}"),
    }
}

/// Publish a ready egress handle on `bind` for tests that need a real
/// `send_uplink` path without the 1 s refresh machinery.
fn publish_test_egress(
    egress: &SharedEgress,
    pool: &ConnPool,
    bind: UdpBind,
    conn: &quinn::Connection,
    rev2: Arc<ConnRev2>,
) {
    egress.cached[bind.index].store(Some(Arc::new(EgressCache {
        conn: conn.clone(),
        limit: 1200,
        stamp_ms: mono_millis(),
        slot: pool.udp_global_slot(bind.index),
        rev2,
    })));
}

/// Two peers on one forward listener get two independent sessions; the server
/// sees the configured target on each `OPEN`, and an inbound reply for one
/// session reaches only that peer, as a bare payload.
#[tokio::test]
async fn udp_forward_demuxes_peers_and_delivers_raw_replies() {
    let (client_conn, server_conn, _ce, _se) = real_connection_with_server().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let rev2 = rev2_state();
    let bind = pool.udp_bind_shard(EgressClass::Interactive, 0);
    publish_test_egress(&egress, &pool, bind, &client_conn, rev2.clone());

    let hub = Arc::new(UdpHub::new());
    let listener =
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap());
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let target_sock = target.socket_addr().unwrap();
    let mut fwd = crate::forward_udp::UdpForwarder::for_test(
        listener.clone(),
        target.clone(),
        MAX_UDP_ASSOCS,
        pool.clone(),
        hub.clone(),
        egress.clone(),
    );
    let peer_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = peer_a.local_addr().unwrap();
    let b = peer_b.local_addr().unwrap();
    let now = mono_millis();
    let ba = fwd
        .handle_datagram(a, b"a", now)
        .expect("first payload sends");
    let bb = fwd
        .handle_datagram(b, b"b", now)
        .expect("first payload sends");
    assert_eq!(fwd.peer_count(), 2, "one session per peer");
    let sess_a = fwd.peer_sess(a).expect("peer a session");
    let sess_b = fwd.peer_sess(b).expect("peer b session");
    assert_ne!(sess_a, sess_b, "peers must not share a session");
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 2);
    drain_assoc_stage(&egress, &pool, ba);
    drain_assoc_stage(&egress, &pool, bb);

    // Each session opened with the configured target; payloads are verbatim.
    let mut opens = std::collections::HashMap::new();
    for _ in 0..2 {
        let d = tokio::time::timeout(Duration::from_secs(2), server_conn.read_datagram())
            .await
            .expect("an OPEN frame must arrive")
            .unwrap();
        let f = r2::decode_data(&d).expect("decode DATA");
        let sess = f.sess.expect("OPEN carries its session");
        assert_eq!(f.addr, Some(TargetAddrRef::Ip(target_sock)));
        opens.insert(sess, f.payload.to_vec());
    }
    assert_eq!(opens.get(&sess_a).map(Vec::as_slice), Some(&b"a"[..]));
    assert_eq!(opens.get(&sess_b).map(Vec::as_slice), Some(&b"b"[..]));

    // Downlink: one INLINE reply per session. The dispatcher must write each
    // bare payload to exactly its own peer.
    let reply_src: SocketAddr = "198.51.100.9:53".parse().unwrap();
    let mut cache = empty_dispatch_cache();
    let mut r2_reasm = R2Reassembler::new();
    let mut staged: Vec<StagedReply> = Vec::new();
    for (sess, body) in [(sess_a, &b"reply-a"[..]), (sess_b, &b"reply-b"[..])] {
        let frame = r2::encode_data_inline(sess, &TargetAddrRef::Ip(reply_src), true, body, 1200)
            .expect("encode inline reply");
        assert_eq!(
            dispatch_r2(
                &rev2,
                &mut cache,
                &hub,
                &mut r2_reasm,
                Some(&client_conn),
                frame,
                &mut staged,
            ),
            1
        );
    }
    // Prime the listener's writable readiness with one drained datagram per
    // peer: a freshly registered socket can report `WouldBlock` before its
    // first readiness edge, which would detour the first reply through the
    // detached retry worker (the cross-runtime flake the flush tests document).
    for peer in [&peer_a, &peer_b] {
        prime_relay(&listener, peer, peer.local_addr().unwrap()).await;
    }
    let mut hdrs = Vec::new();
    let mut offs = Vec::new();
    flush_staged(&mut staged, &mut hdrs, &mut offs);
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(REPLY_WAIT, peer_a.recv_from(&mut buf))
        .await
        .expect("peer a reply")
        .unwrap();
    assert_eq!(&buf[..n], b"reply-a", "peer a must get its own raw reply");
    let (n, _) = tokio::time::timeout(REPLY_WAIT, peer_b.recv_from(&mut buf))
        .await
        .expect("peer b reply")
        .unwrap();
    assert_eq!(&buf[..n], b"reply-b", "peer b must get its own raw reply");
}

/// The per-listener peer cap admits the first sessions and drops beyond it
/// without disturbing the admitted ones; the global `UdpHub` budget is a
/// separate refusal reason.
#[tokio::test]
async fn udp_forward_peer_cap_refuses_only_new_peers() {
    // These tests bump process-wide drop counters (REFUSED / SESSION_FULL /
    // NO_EGRESS), and the DNS/egress suites assert exact deltas on them under
    // their own locks. Take both locks so our bumps cannot land inside their
    // snapshot windows.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let _egress_guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let hub = Arc::new(UdpHub::new());
    let listener =
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap());
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let mut fwd = crate::forward_udp::UdpForwarder::for_test(
        listener,
        target,
        1,
        pool.clone(),
        hub.clone(),
        egress.clone(),
    );
    let a: SocketAddr = "127.0.0.1:1111".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:2222".parse().unwrap();
    let now = mono_millis();
    fwd.handle_datagram(a, b"first", now);
    fwd.handle_datagram(b, b"over-cap", now);
    assert_eq!(fwd.peer_count(), 1, "max_sessions=1 admits one peer");
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(fwd.peer_sess(a).is_some());
    assert!(fwd.peer_sess(b).is_none());

    // The process-wide hub budget is exhausted independently of the listener
    // cap: a second listener with room must still be refused by alloc_sess.
    let tiny = Arc::new(UdpHub::with_capacity(1));
    tiny.alloc_sess().expect("occupy the only hub slot");
    let mut fwd2 = crate::forward_udp::UdpForwarder::for_test(
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap()),
        TargetAddr::Ip("198.51.100.9:53".parse().unwrap()),
        MAX_UDP_ASSOCS,
        pool,
        tiny.clone(),
        egress,
    );
    fwd2.handle_datagram(a, b"no-budget", now);
    assert_eq!(fwd2.peer_count(), 0, "hub exhaustion refuses the peer");
}

/// The idle sweep closes the server session and releases the hub slot exactly
/// once, so a long-running listener cannot leak its 4032-session budget.
#[tokio::test]
async fn udp_forward_idle_sweep_releases_the_hub_slot() {
    // These tests bump process-wide drop counters (REFUSED / SESSION_FULL /
    // NO_EGRESS), and the DNS/egress suites assert exact deltas on them under
    // their own locks. Take both locks so our bumps cannot land inside their
    // snapshot windows.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let _egress_guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let hub = Arc::new(UdpHub::new());
    let listener =
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap());
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let mut fwd = crate::forward_udp::UdpForwarder::for_test(
        listener,
        target,
        MAX_UDP_ASSOCS,
        pool,
        hub.clone(),
        egress,
    );
    let src: SocketAddr = "127.0.0.1:3333".parse().unwrap();
    let t0 = mono_millis();
    fwd.handle_datagram(src, b"x", t0);
    let sess = fwd.peer_sess(src).expect("session");
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 1);
    // One tick past the association idle window: both directions have been
    // silent since `t0`.
    fwd.sweep_idle(t0 + ASSOC_IDLE_MS + 1_000);
    assert_eq!(fwd.peer_count(), 0, "the peer must be reaped");
    assert!(
        hub.entry(sess).is_none(),
        "the hub entry must be unpublished"
    );
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the session slot must be returned"
    );
    // A second sweep must not double-release (it would underflow the count).
    fwd.sweep_idle(t0 + ASSOC_IDLE_MS + 2_000);
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// `udp(7)` delivers ICMP port-unreachable to an unconnected listener as
/// `ConnectionRefused`; treating that as fatal silently stops the whole UDP
/// forward listener under normal peer churn. Only genuinely broken-socket
/// errors may end it.
#[test]
fn udp_forward_recv_error_classification_matches_linux_icmp_semantics() {
    use std::io::ErrorKind;
    for kind in [
        ErrorKind::WouldBlock,
        ErrorKind::Interrupted,
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::TimedOut,
    ] {
        assert!(
            crate::forward_udp::forward_recv_error_is_transient(kind),
            "{kind:?} must be retried, not treated as fatal"
        );
    }
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::NotConnected,
        ErrorKind::AddrNotAvailable,
        ErrorKind::PermissionDenied,
    ] {
        assert!(
            !crate::forward_udp::forward_recv_error_is_transient(kind),
            "{kind:?} means the socket itself is unusable"
        );
    }
}

/// A port that is already bound must fail startup, naming the listener family
/// and address (plan Task 6). This is the fail-fast half of the startup
/// contract; the E2E config test covers the validation half.
#[tokio::test]
async fn forward_listener_bind_conflicts_fail_startup() {
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());

    // TCP: a live listener holds the port.
    let hold = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = hold.local_addr().unwrap();
    let err = spawn_tcp_forward(
        TcpForwardSpec {
            listen,
            target: target.clone(),
            max_conns: 16,
        },
        ConnPool::new(2, Vec::new(), true, true, 1),
        Arc::new(SharedEgress::default()),
        Duration::from_secs(1),
        rx.clone(),
        Arc::new(tokio::sync::Semaphore::new(16)),
        Arc::new(tokio::sync::Semaphore::new(16)),
    )
    .expect_err("an occupied TCP port must fail startup");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("bind forward TCP listener") && msg.contains(&listen.to_string()),
        "the bind error must name the listener: {msg}"
    );

    // UDP: same contract.
    let hold = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listen = hold.local_addr().unwrap();
    let err = crate::forward_udp::spawn_udp_forward(
        UdpForwardSpec {
            listen,
            target,
            max_sessions: 1,
        },
        ConnPool::new(2, Vec::new(), true, true, 1),
        Arc::new(UdpHub::new()),
        Arc::new(SharedEgress::default()),
        rx,
        Arc::new(tokio::sync::Semaphore::new(16)),
    )
    .expect_err("an occupied UDP port must fail startup");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("forward UDP listener") && msg.contains(&listen.to_string()),
        "the bind error must name the listener: {msg}"
    );
}

/// Every reserved hub slot is returned on both orderly teardown paths:
/// `shutdown_all` (listener sees the process shutdown) and `Drop` (the task
/// dies without a sweep). Both are `PeerSession::Drop`'s contract.
#[tokio::test]
async fn udp_forward_shutdown_and_drop_release_hub_slots() {
    // `handle_datagram` without an egress connection books NO_EGRESS; keep the
    // global-drop-counter suites from seeing our bumps in their windows.
    let _counter_guard = DNS_SLOW_PATH_COUNTER_LOCK.lock().await;
    let _egress_guard = EGRESS_VERDICT_COUNTER_LOCK.lock().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let hub = Arc::new(UdpHub::new());
    let listener =
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap());
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let mut fwd = crate::forward_udp::UdpForwarder::for_test(
        listener,
        target,
        MAX_UDP_ASSOCS,
        pool,
        hub.clone(),
        egress,
    );
    let now = mono_millis();
    for port in [4444u16, 5555] {
        fwd.handle_datagram(format!("127.0.0.1:{port}").parse().unwrap(), b"x", now);
    }
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 2);
    fwd.shutdown_all();
    assert_eq!(fwd.peer_count(), 0, "shutdown must drop every peer");
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "shutdown must release every reserved hub slot"
    );

    // Drop path: a listener task that ends without a final sweep (panic/task
    // abort in dev, runtime teardown) must still return its slots.
    fwd.handle_datagram("127.0.0.1:6666".parse().unwrap(), b"z", now);
    assert_eq!(hub.len.load(std::sync::atomic::Ordering::Relaxed), 1);
    drop(fwd);
    assert_eq!(
        hub.len.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "PeerSession::Drop must release the reserved hub slot"
    );
}

/// The idle sweep tells the server to drop the session immediately (the
/// `SESS_CLOSE` datagram), not only the 180 s server-side backstop.
#[tokio::test]
async fn udp_forward_idle_sweep_sends_sess_close() {
    let (client_conn, server_conn, _ce, _se) = real_connection_with_server().await;
    let pool = ConnPool::new(2, Vec::new(), true, true, 1);
    let egress = Arc::new(SharedEgress::default());
    let rev2 = rev2_state();
    let bind = pool.udp_bind_shard(EgressClass::Interactive, 0);
    publish_test_egress(&egress, &pool, bind, &client_conn, rev2);
    let hub = Arc::new(UdpHub::new());
    let listener =
        Arc::new(tokio::net::UdpSocket::from_std(udp_socket_dual("[::]:0").unwrap()).unwrap());
    let target: TargetAddr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let mut fwd = crate::forward_udp::UdpForwarder::for_test(
        listener,
        target,
        MAX_UDP_ASSOCS,
        pool.clone(),
        hub.clone(),
        egress.clone(),
    );
    let peer: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let t0 = mono_millis();
    let bind_used = fwd.handle_datagram(peer, b"q", t0).expect("a binding");
    let sess = fwd.peer_sess(peer).expect("the peer session");
    // Flush the OPEN first so the next datagram is unambiguous.
    drain_assoc_stage(&egress, &pool, bind_used);
    let _open = tokio::time::timeout(Duration::from_secs(2), server_conn.read_datagram())
        .await
        .expect("the DATA OPEN must arrive")
        .unwrap();
    fwd.sweep_idle(t0 + ASSOC_IDLE_MS + 1_000);
    let close = tokio::time::timeout(Duration::from_secs(2), server_conn.read_datagram())
        .await
        .expect("SESS_CLOSE must be sent")
        .unwrap();
    assert_eq!(
        r2::kind(&close),
        Some(r2::R2Kind::Ctl),
        "the sweep must send a CTL SESS_CLOSE, not rely on the server sweep"
    );
    assert!(hub.entry(sess).is_none(), "the hub entry must be gone");
}

/// The legacy DNS slow-path reply helper (used for a domain-form reply source)
/// must honour raw mode too: a forwarded peer never expects a SOCKS5 header,
/// and an IPv4 listener socket cannot send to a v4-mapped peer address.
#[tokio::test]
async fn raw_forward_slow_path_reply_sends_bare_payload() {
    let listener = Arc::new(
        tokio::net::UdpSocket::from_std(udp_socket_dual_small("[::]:0").unwrap()).unwrap(),
    );
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    prime_relay(&listener, &peer, peer_addr).await;
    let entry = Arc::new(AssocEntry::new_raw(listener));
    entry.app.store(Some(Arc::new(peer_addr)));
    let payload = Bytes::from_static(b"slow-path-raw");
    let mut pkt = bytes::BytesMut::with_capacity(256);
    send_reply_addr(
        &entry,
        peer_addr,
        "198.51.100.9:53".parse().unwrap(),
        &payload,
        &mut pkt,
    );
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(REPLY_WAIT, peer.recv_from(&mut buf))
        .await
        .expect("the slow-path reply must arrive")
        .unwrap();
    assert_eq!(&buf[..n], &payload[..], "raw mode must not frame the reply");
    assert!(
        pkt.is_empty(),
        "raw mode must not encode into the SOCKS5 scratch packet"
    );
}

// ================= MQP-3 rev3 client data plane =================
//
// The rev3 integration keeps the whole flow/stager/reassembly state model and
// swaps only the codec, the sender confirmation policy (no per-flow ACK, K=2
// binding context) and the control plane (one reliable client-opened bidi
// stream instead of `CTL` DATAGRAMs). These tests construct
// `ConnRev2::new_with_wire(Wire::Rev3)` and drive the same entry points the
// production path uses.

/// rev3 has no `HELLO`/`CAPS`: the state is ready from construction with the
/// static caps, and `handshake()` is a no-op that sends **no** datagram bytes.
#[tokio::test]
async fn rev3_handshake_is_a_noop_and_never_sends_hello() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = rev3_state();
    // Static contract: ready before any negotiation, default frame limit.
    assert!(state.is_ready(), "rev3 caps are static: ready at publish");
    assert_eq!(state.wire(), Wire::Rev3);
    assert_eq!(
        state.frame_limit(1400),
        1400,
        "the connection DATAGRAM budget is the live limit (static caps)"
    );
    assert!(state.ctl.caps().is_none(), "no CAPS frame was consumed");
    // Both entry points report success and write nothing.
    assert!(rev2::handshake(&client_conn, &state).await);
    assert!(
        rev2::handshake_with(
            &client_conn,
            &state,
            Duration::from_millis(10),
            Duration::from_millis(5),
            Duration::from_millis(5)
        )
        .await
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), server_conn.read_datagram())
            .await
            .is_err(),
        "rev3 must not send HELLO/CAPS DATAGRAMs"
    );
    assert!(state.is_ready());
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 no-ACK policy: the first [`R3_CONTEXT_REPEATS`] payloads of a fresh flow
/// carry the binding form (`DATA_EXT OPEN` with session + address), the last of
/// them marks the binding open **locally**, and the third payload is a 2-byte
/// steady header — with no `FLOW_ACK` (or any other downlink) ever needed.
#[tokio::test]
async fn rev3_context_frames_then_steady_without_any_ack() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = rev3_state();
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new_with_wire(Wire::Rev3);
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    let send = |body: &[u8], up: &mut UplinkFlows, frag: &mut R2Fragmenter| {
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            body,
            bind,
            &state,
            up,
            frag,
        )
    };
    let mut id = None;
    for payload in [&b"one"[..], b"two"] {
        assert!(send(payload, &mut up, &mut frag).complete());
        drain_now(&state, &client_conn, limit);
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .expect("a context frame must arrive")
            .unwrap();
        let f = wire::decode_data(Wire::Rev3, &d).expect("rev3 DATA decodes");
        let seen = f
            .wire_id
            .expect("a binding-context payload carries the flow id");
        assert_eq!(f.sess, Some(7), "context frames carry session + address");
        assert_eq!(f.addr, Some(addr.as_ref()));
        assert!(!f.src, "an uplink context frame names the destination");
        assert_eq!(f.payload, payload);
        // Not steady: a steady rev3 frame is exactly 2 header bytes + payload.
        assert!(
            d.len() > 2 + payload.len(),
            "payload {} must repeat the binding context",
            String::from_utf8_lossy(payload)
        );
        id = Some(seen);
    }
    let id = id.expect("an id was allocated");
    assert!(state.ids.allocated() >= 1);
    assert!(
        state.registry.get(id).unwrap().is_open(),
        "the K-th context payload marks the binding open locally (no ACK)"
    );
    // Third payload: a steady frame with only the packed 2-byte header.
    assert!(send(b"three", &mut up, &mut frag).complete());
    drain_now(&state, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the steady frame must arrive")
        .unwrap();
    assert_eq!(
        d.len(),
        2 + b"three".len(),
        "a confirmed rev3 flow costs only the 2-byte packed header"
    );
    let f = wire::decode_data(Wire::Rev3, &d).expect("rev3 steady DATA decodes");
    assert_eq!(f.wire_id, Some(id));
    assert_eq!(f.sess, None);
    assert_eq!(f.addr, None);
    assert_eq!(f.payload, b"three");
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A `NEED_CONTEXT` repair hint re-arms the sender's K=2 window: the binding
/// moves back to `Opening`, the counter resets, and the next payload carries the
/// binding form again.
#[test]
fn rev3_need_context_message_rearms_the_sender_window() {
    let state = rev3_state();
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let wire_id = r2::make_wire_id(1, false).unwrap();
    let binding = FlowBinding::new_shared(wire_id, 7, addr);
    assert!(state.registry.insert(binding.clone()).is_ok());
    // Simulate the sender having spent the window (K context frames, self-open).
    for _ in 0..R3_CONTEXT_REPEATS {
        assert!(binding.take_context_slot());
    }
    assert!(binding.is_open());
    let hub = UdpHub::new();
    let mut reasm = rev3_reasm();
    let before = counters::snapshot();
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::NeedContext {
            fid: wire::fid_for(wire_id).unwrap(),
        },
    );
    assert_eq!(binding.state(), FlowState::Opening, "window re-armed");
    assert_eq!(binding.context_left(), R3_CONTEXT_REPEATS);
    assert!(
        binding.take_context_slot(),
        "the next payload carries the binding context again"
    );
    assert!(counters::since(&before).need_context_rx >= 1);
    // An unknown fid is a no-op (counted), not a panic.
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::NeedContext {
            fid: wire::fid_for(r2::make_wire_id(2000, false).unwrap()).unwrap(),
        },
    );
}

/// rev3 id exhaustion: once the 14-bit `fid` space is spent, a new target is
/// never installed — the payload falls back to the stateless `INLINE` form and
/// the allocator burns **no** further ids (the documented rev3 fail-safe).
#[tokio::test]
async fn rev3_id_exhaustion_falls_back_to_inline_without_burning_ids() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = rev3_state();
    // Spend the rev3 id space (the codec's 14-bit per-owner limit: 8192 ids).
    for _ in 0..wire::MAX_R3_LOCAL_ID {
        assert!(state.ids.alloc().is_some());
    }
    let allocated = state.ids.allocated();
    assert_eq!(allocated, wire::MAX_R3_LOCAL_ID);
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new_with_wire(Wire::Rev3);
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            b"inline",
            bind,
            &state,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    assert!(
        state.registry.is_empty(),
        "no unencodable binding installed"
    );
    assert_eq!(
        state.ids.allocated(),
        allocated,
        "exhaustion must not burn ids"
    );
    drain_now(&state, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the INLINE payload must arrive")
        .unwrap();
    let f = wire::decode_data(Wire::Rev3, &d).expect("rev3 INLINE decodes");
    assert_eq!(f.wire_id, None, "INLINE carries no flow id");
    assert_eq!(f.sess, Some(7));
    assert_eq!(f.addr, Some(addr.as_ref()));
    assert_eq!(f.payload, b"inline");
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 reuses an installed **server-owned** flow with a steady frame from the
/// first payload (the server already owns/knows the id, so no client context is
/// needed), while a fresh client-owned flow carries context — the OPEN/SRC vs
/// steady split the adapter performs per owner bit.
#[tokio::test]
async fn rev3_server_owned_flow_reuses_steady_without_context() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let state = rev3_state();
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    // The dispatcher installs a server-owned reply flow (`OPEN|SRC` on the
    // downlink); the app then sends to the same reply source.
    let server_wid = r2::make_wire_id(1, true).unwrap();
    let binding = FlowBinding::new_shared(server_wid, 7, addr.clone());
    binding.set_reply_src(addr.socket_addr().unwrap());
    binding.mark_open();
    assert!(state.registry.insert(binding.clone()).is_ok());
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new_with_wire(Wire::Rev3);
    let bind = UdpBind {
        class: EgressClass::Interactive,
        index: 0,
    };
    let limit = client_conn.max_datagram_size().unwrap();
    assert!(
        send_uplink(
            &client_conn,
            limit,
            7,
            &addr.as_ref(),
            b"echo",
            bind,
            &state,
            &mut up,
            &mut frag,
        )
        .complete()
    );
    drain_now(&state, &client_conn, limit);
    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the steady reuse frame must arrive")
        .unwrap();
    let f = wire::decode_data(Wire::Rev3, &d).expect("rev3 DATA decodes");
    assert_eq!(f.wire_id, Some(server_wid));
    assert_eq!(f.sess, None, "reused server-owned flow rides steady");
    assert_eq!(f.addr, None);
    assert_eq!(f.payload, b"echo");
    assert!(state.ids.allocated() == 0, "no client id was allocated");
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 downlink: DATA/TRAIN/FRAG are decoded through the `wire` adapter and
/// resolve the same flow registry / connection-scoped ids as rev2.
#[tokio::test]
async fn rev3_downlink_data_train_and_inline_decode_through_the_adapter() {
    let state = rev3_state();
    let hub = UdpHub::new();
    let assoc = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, assoc.entry.clone());
    let mut cache = empty_dispatch_cache();
    let mut reasm = rev3_reasm();
    let mut out: Vec<StagedReply> = Vec::new();
    let dst: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let wire_id = r2::make_wire_id(1, false).unwrap();
    let binding = FlowBinding::new_shared(wire_id, sess, TargetAddr::Ip(dst));
    binding.mark_open();
    assert!(state.registry.insert(binding).is_ok());

    // Steady DATA.
    let frame = wire::encode_data_steady(Wire::Rev3, wire_id, b"one", 1400).unwrap();
    assert_eq!(
        dispatch_r2(&state, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        1
    );
    assert_eq!(out[0].dst, dst);
    assert_eq!(out[0].payload, &b"one"[..]);
    out.clear();

    // TRAIN dict over the same flow (two items).
    let items: [(u8, &[u8]); 2] = [(0, b"a"), (0, b"bb")];
    let frame = wire::encode_train_dict(Wire::Rev3, &[wire_id], &items, 1400).unwrap();
    assert_eq!(
        dispatch_r2(&state, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        2
    );
    assert_eq!(out[0].payload, &b"a"[..]);
    assert_eq!(out[1].payload, &b"bb"[..]);
    out.clear();

    // INLINE (no flow id) is self-describing: session + source address.
    let frame = wire::encode_data_inline(
        Wire::Rev3,
        sess,
        &TargetAddrRef::Ip(dst),
        false,
        b"inline",
        1400,
    )
    .unwrap();
    assert_eq!(
        dispatch_r2(&state, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        1
    );
    assert_eq!(out[0].dst, dst);
    assert_eq!(out[0].payload, &b"inline"[..]);
}

/// rev3 unknown steady flow: the receiver cannot install a run/DATA frame with
/// no address, so it asks the peer for the binding context (`NEED_CONTEXT`)
/// instead of only counting the drop — the no-ACK repair path.
#[tokio::test]
async fn rev3_unknown_steady_flow_requests_context() {
    let state = rev3_state();
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::channel(rev2::CTL_QUEUE);
    state.install_ctl_writer(ctl_tx);
    let hub = UdpHub::new();
    let mut cache = empty_dispatch_cache();
    let mut reasm = rev3_reasm();
    let mut out: Vec<StagedReply> = Vec::new();
    let server_wid = r2::make_wire_id(1, true).unwrap();
    let frame = wire::encode_data_steady(Wire::Rev3, server_wid, b"reply", 1400).unwrap();
    let before = counters::snapshot();
    assert_eq!(
        dispatch_r2(&state, &mut cache, &hub, &mut reasm, None, frame, &mut out),
        0
    );
    assert!(counters::since(&before).rx_unknown_id >= 1);
    assert!(counters::since(&before).need_context_tx >= 1);
    match ctl_rx.try_recv() {
        Ok(CtlMessage::NeedContext { fid }) => {
            assert_eq!(fid, wire::fid_for(server_wid).unwrap())
        }
        other => panic!("expected NEED_CONTEXT on the control stream, got {other:?}"),
    }
}

/// rev3 control-stream messages reproduce the rev2 `CTL` effects
/// (`REJECT`/`SESS_CLOSE`/`FLOW_CLOSE`), with no DATAGRAM involved.
#[tokio::test]
async fn rev3_control_messages_match_the_rev2_actions() {
    let state = rev3_state();
    let hub = UdpHub::new();
    let assoc = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, assoc.entry.clone());
    let mut reasm = rev3_reasm();

    // REJECT: remove + close + arm the INLINE window for the target.
    let target_a = TargetAddr::Ip("198.51.100.1:53".parse().unwrap());
    let id_a = r2::make_wire_id(1, false).unwrap();
    let a = FlowBinding::new_shared(id_a, sess, target_a.clone());
    a.mark_open();
    assert!(state.registry.insert(a.clone()).is_ok());
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::Reject {
            fid: wire::fid_for(id_a).unwrap(),
            reason: r2::R2_REJECT_TABLE_FULL,
        },
    );
    assert!(state.registry.get(id_a).is_none());
    assert_eq!(a.state(), FlowState::Closed);
    assert!(state.is_rejected(&target_a.as_ref(), coarse_millis()));
    assert!(counters::snapshot().flow_reject_rx >= 1);

    // SESS_CLOSE: purge the session's bindings and notify the live association.
    let id_b = r2::make_wire_id(2, false).unwrap();
    let b = FlowBinding::new_shared(id_b, sess, TargetAddr::Ip(target_a.socket_addr().unwrap()));
    b.mark_open();
    assert!(state.registry.insert(b.clone()).is_ok());
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::SessClose { sess, reason: 0 },
    );
    assert!(state.registry.get(id_b).is_none());
    assert_eq!(b.state(), FlowState::Closed);
    assert!(assoc.entry.closed.take());

    // FLOW_CLOSE: remove one flow.
    let id_c = r2::make_wire_id(3, false).unwrap();
    let c = FlowBinding::new_shared(
        id_c,
        sess,
        TargetAddr::Ip("203.0.113.9:3478".parse().unwrap()),
    );
    c.mark_open();
    assert!(state.registry.insert(c.clone()).is_ok());
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::FlowClose {
            fid: wire::fid_for(id_c).unwrap(),
            reason: 0,
        },
    );
    assert!(state.registry.get(id_c).is_none());
    assert_eq!(c.state(), FlowState::Closed);

    // Unknown fids are counted, never guessed.
    let before = counters::snapshot();
    handle_r3_ctl(
        &state,
        &hub,
        &mut reasm,
        CtlMessage::FlowClose {
            fid: 0x3FFF,
            reason: 0,
        },
    );
    assert!(counters::since(&before).rx_unknown_id >= 1);
}

/// rev3 association exit sends **one** `ASSOC_CLOSE` on the reliable control
/// stream and no `SESS_CLOSE` DATAGRAM (rev2's x3 repeat is gone).
#[tokio::test]
async fn rev3_assoc_close_replaces_sess_close_datagrams() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let egress = SharedEgress::default();
    let bind = pool.udp_bind_shard(EgressClass::Interactive, 0);
    let state = rev3_state();
    // Published generation, as the reconnect loop would.
    let slot = pool.slot(pool.udp_global_slot(bind.index));
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);
    egress.cached[bind.index].store(Some(Arc::new(EgressCache {
        conn: client_conn.clone(),
        limit: 1200,
        stamp_ms: coarse_millis(),
        slot: pool.udp_global_slot(bind.index),
        rev2: state.clone(),
    })));
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::channel(rev2::CTL_QUEUE);
    state.install_ctl_writer(ctl_tx);
    let before = counters::snapshot();
    send_sess_close(&egress, &pool, Some(bind), 7, state.epoch);
    match ctl_rx.try_recv() {
        Ok(CtlMessage::AssocClose { sess, .. }) => assert_eq!(sess, 7),
        other => panic!("expected ASSOC_CLOSE on the control stream, got {other:?}"),
    }
    assert!(counters::since(&before).assoc_close_tx >= 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), server_conn.read_datagram())
            .await
            .is_err(),
        "rev3 never sends SESS_CLOSE DATAGRAMs"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 never acts on `CTL` DATAGRAMs (its control plane is the stream), and an
/// unclassifiable byte never reaches the legacy MQP-2/MQP-3 fallbacks.
#[test]
fn rev3_never_acts_on_ctl_datagrams_or_legacy_fallbacks() {
    let state = rev3_state();
    let hub = UdpHub::new();
    let mut cache = empty_dispatch_cache();
    let mut reasm = rev3_reasm();
    let mut dgram_reasm = DgramReassembler::new();
    let mut out: Vec<StagedReply> = Vec::new();
    // A rev2 CAPS/HELLO-shaped DATAGRAM must not touch rev3 state.
    let ctl = r2::encode_ctl(&r2::Ctl::Caps(r2::Caps::default()));
    let caps_before = state.ctl.caps();
    dispatch_inbound(
        &mut cache,
        &hub,
        &state,
        None,
        ctl,
        &mut dgram_reasm,
        &mut reasm,
        &mut out,
        coarse_millis(),
    );
    assert_eq!(state.ctl.caps(), caps_before, "CTL datagrams are inert");
    assert!(state.is_ready());
    // An unclassifiable rev3 byte is a malformed frame (rx_drop), never the
    // legacy MQP-2/MQP-3 dispatch paths.
    let before = counters::snapshot();
    dispatch_inbound(
        &mut cache,
        &hub,
        &state,
        None,
        Bytes::from_static(&[0x70]),
        &mut dgram_reasm,
        &mut reasm,
        &mut out,
        coarse_millis(),
    );
    assert!(counters::since(&before).rx_drop >= 1);
    assert_eq!(state.registry.len(), 0);
}

/// rev3 control sender plumbing is pure queueing (the stream task owns the
/// I/O): no writer ⇒ `false`, installed writer ⇒ the message is queued, and a
/// `NEED_CONTEXT` repair respects the per-connection rate budget.
#[test]
fn rev3_control_sender_queues_messages_and_rate_limits_repairs() {
    let state = rev3_state();
    assert!(
        !state.send_ctl(CtlMessage::Goaway),
        "no control-stream writer installed yet"
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(rev2::CTL_QUEUE);
    state.install_ctl_writer(tx);
    assert!(state.send_ctl(CtlMessage::AssocClose { sess: 9, reason: 0 }));
    assert_eq!(
        rx.try_recv().expect("queued"),
        CtlMessage::AssocClose { sess: 9, reason: 0 }
    );
    let wire_id = r2::make_wire_id(1, false).unwrap();
    assert!(state.send_need_context(wire_id));
    assert_eq!(
        rx.try_recv().expect("repair queued"),
        CtlMessage::NeedContext {
            fid: wire::fid_for(wire_id).unwrap()
        }
    );
    // Budget exhausted: a flood of idempotent hints is bounded per second, so
    // most of a 5000-call burst is refused instead of reaching the stream.
    let mut sent = 0usize;
    for _ in 0..5000 {
        if state.send_need_context(wire_id) {
            sent += 1;
        }
    }
    assert!(
        sent < 5000,
        "the NEED_CONTEXT budget must refuse part of an unknown-id frame storm"
    );
    assert_eq!(ctl_stream::MARKER, 0xFF, "control stream marker is stable");
}

/// A peer that floods frames this side refuses must not grow the outbound
/// control queue without bound: past `CTL_QUEUE` the message is dropped and
/// counted, and the queue drains normally once the writer makes progress.
#[test]
fn rev3_control_queue_drops_instead_of_growing() {
    let state = rev3_state();
    // Capacity 1, so the bound is reached deterministically.
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    state.install_ctl_writer(tx);
    let before = counters::snapshot();
    assert!(state.send_ctl(CtlMessage::Goaway), "first message fits");
    assert!(
        !state.send_ctl(CtlMessage::AssocClose { sess: 1, reason: 0 }),
        "a full queue refuses the message instead of buffering it"
    );
    assert_eq!(counters::since(&before).ctl_queue_full, 1);
    // The same refusal at the real depth, shaped like a peer-driven reject
    // storm: exactly the overflow is dropped, the queue keeps its first
    // `CTL_QUEUE` messages.
    let (tx2, mut rx2) = tokio::sync::mpsc::channel(rev2::CTL_QUEUE);
    state.install_ctl_writer(tx2);
    let before = counters::snapshot();
    let mut refused = 0usize;
    for fid in 0..(rev2::CTL_QUEUE as u16 + 8) {
        if !state.send_ctl(CtlMessage::Reject {
            fid,
            reason: r2::R2_REJECT_POLICY,
        }) {
            refused += 1;
        }
    }
    assert_eq!(refused, 8, "only the ring overflow is dropped");
    assert_eq!(counters::since(&before).ctl_queue_full, 8);
    // Draining one slot lets the next message through: dropping is pressure
    // relief, not a latched failure.
    assert!(rx2.try_recv().is_ok());
    assert!(state.send_ctl(CtlMessage::Reject {
        fid: 0,
        reason: r2::R2_REJECT_POLICY,
    }));
    assert_eq!(
        rx.try_recv()
            .expect("the capacity-1 queue kept its message"),
        CtlMessage::Goaway
    );
}

/// rev3 full-slice round trip on a real connection: a published rev3
/// generation (dispatcher + control-stream task started), first payload sent as
/// `DATA_EXT OPEN` through the shared egress, and a server steady reply decoded
/// through the rev3 adapter and delivered to the app's UDP socket.
#[tokio::test]
async fn rev3_full_duplex_round_trip_through_egress_and_dispatcher() {
    let (client_conn, server_conn, _client_ep, _server_ep) = real_connection_with_server().await;
    let pool = ConnPool::new(1, Vec::new(), true, true, 1);
    let hub = Arc::new(UdpHub::new());
    let egress: Arc<SharedEgress> = Arc::new(SharedEgress::default());
    // A live association, so the dispatcher has a destination for the reply.
    let assoc = test_assoc().await;
    let sess = hub.alloc_sess().unwrap();
    hub.publish(sess, assoc.entry.clone());
    // Publish the rev3 generation exactly as the reconnect loop + wiring will.
    let slot = pool.slot(pool.udp_global_slot(0));
    let state = rev3_state();
    slot.set_rev2(state.clone());
    slot.publish(&client_conn);
    slot.live.store(true, std::sync::atomic::Ordering::Relaxed);
    bump_gen(&slot.gen_tx);
    spawn_dispatcher(slot.clone(), hub.clone());

    // Uplink through the real egress path (single-flight acquire + memo store).
    let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let mut bind: Option<UdpBind> = None;
    let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
    let mut frag = R2Fragmenter::new();
    send_payload_uplink(
        &pool,
        &egress,
        sess,
        &target.as_ref(),
        b"ping",
        &mut bind,
        &mut up,
        &mut frag,
        coarse_millis(),
        SessionKind::Socks,
    );
    let bind = bind.expect("the first payload binds the egress class");
    drain_assoc_stage(&egress, &pool, bind);

    let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("the rev3 context frame must arrive")
        .unwrap();
    let f = wire::decode_data(Wire::Rev3, &d).expect("rev3 DATA decodes");
    let id = f.wire_id.expect("the first payload opens a flow");
    assert_eq!(f.sess, Some(sess));
    assert_eq!(f.addr, Some(target.as_ref()));
    assert_eq!(f.payload, b"ping");

    // Downlink: a steady rev3 frame for that flow reaches the app socket via
    // the dispatcher's rev3 decode path.
    server_conn
        .send_datagram(wire::encode_data_steady(Wire::Rev3, id, b"pong", 1400).unwrap())
        .unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), assoc.app.recv_from(&mut buf))
        .await
        .expect("the dispatcher must deliver the reply")
        .unwrap()
        .0;
    // SOCKS5 UDP reply header (RSV/FRAG + IPv4 source + port) then the payload.
    assert_eq!(&buf[..3], &[0, 0, 0]);
    assert_eq!(buf[3], 0x01, "an IP-form reply source is encoded as IPv4");
    assert_eq!(&buf[10..n], b"pong");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Regression (task-12): rev3 **early-data payloads must never spend the
/// binding's no-ACK context window**.
///
/// A DATAGRAM sent before the connection's handshake completes is 0-RTT early
/// data; if the server rejects the resumption (e.g. it restarted), QUIC
/// discards those DATAGRAMs wholesale and never retransmits them. If the sender
/// had self-confirmed the binding on such a frame, every payload after the
/// handshake would be a steady frame for an id the server never installed — the
/// "held datagram across a server restart leaves a persistent forward peer
/// blackholed" bug. Early data therefore always carries the binding form and
/// leaves the K=2 window for the first post-handshake payloads.
#[test]
fn rev3_early_data_never_spends_the_binding_context_window() {
    let state = rev3_state();
    let addr = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
    let binding = FlowBinding::new_shared(r2::make_wire_id(1, false).unwrap(), 7, addr);
    // Pre-handshake (0-RTT) sends: binding form every time, budget untouched.
    for _ in 0..8 {
        assert!(
            uses_binding_context(&state, &binding, false),
            "an early-data payload must carry the binding context"
        );
    }
    assert_eq!(
        binding.state(),
        FlowState::Opening,
        "early data must not confirm the binding locally"
    );
    assert_eq!(
        binding.context_left(),
        R3_CONTEXT_REPEATS,
        "a discarded 0-RTT frame must not consume the repair window"
    );
    // Established connection: the ordinary K=2 window, then steady frames.
    assert!(uses_binding_context(&state, &binding, true));
    assert!(uses_binding_context(&state, &binding, true));
    assert!(
        binding.is_open(),
        "the last context payload self-confirms the binding"
    );
    assert!(!uses_binding_context(&state, &binding, true));

    // rev2 is untouched: the ACK-gated rule ignores the handshake verdict.
    let rev2 = rev2_state();
    let b2 = FlowBinding::new_shared(
        r2::make_wire_id(2, false).unwrap(),
        7,
        TargetAddr::Ip("198.51.100.10:53".parse().unwrap()),
    );
    assert!(uses_binding_context(&rev2, &b2, false));
    assert!(uses_binding_context(&rev2, &b2, true));
    b2.mark_open();
    assert!(!uses_binding_context(&rev2, &b2, true));
}

/// Regression (task-12): a held payload that expires during an egress outage
/// must leave the session on the ordinary `with_fresh`/`acquire` path, so the
/// next payload of the SAME session (the persistent forward peer) is delivered
/// on the fresh generation. Runs on both wire revisions: the hold/flush code is
/// revision-independent.
#[tokio::test]
async fn held_datagram_expiry_then_fresh_generation_delivers_the_next_payload() {
    for wire in [Wire::Rev2, Wire::Rev3] {
        let (client_conn, server_conn, _client_ep, _server_ep) =
            real_connection_with_server().await;
        let pool = ConnPool::new(1, Vec::new(), true, true, 1);
        let egress = SharedEgress::default();
        let state = match wire {
            Wire::Rev2 => rev2_state(),
            Wire::Rev3 => rev3_state(),
        };
        let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
        let sess = 7u32;
        // One persistent "peer": its uplink state and binding survive the
        // generation change, exactly like a udp_forward peer session.
        let mut bind: Option<UdpBind> = None;
        let mut up = UplinkFlows::new(Arc::new(CloseSignal::new()));
        let mut frag = R2Fragmenter::new_with_wire(wire);

        // No egress published: the payload is held, not dropped.
        send_payload_uplink(
            &pool,
            &egress,
            sess,
            &target.as_ref(),
            b"during-outage",
            &mut bind,
            &mut up,
            &mut frag,
            coarse_millis(),
            SessionKind::Socks,
        );
        assert_eq!(up.pending_len(), 1, "{wire:?}: payload held");
        // The outage outlives the bounded window: the held payload expires and
        // the hold empties (no stale state left behind).
        assert_eq!(
            up.expire_pending_at(mono_millis() + PENDING_TTL_MS),
            1,
            "{wire:?}: held payload expires"
        );
        assert!(up.pending_len() == 0, "{wire:?}: hold empty after expiry");

        // A fresh generation is published (the restarted server's redial).
        let bind = bind.expect("the first payload fixed the egress binding");
        let slot = pool.slot(pool.udp_global_slot(bind.index));
        slot.set_rev2(state.clone());
        slot.publish(&client_conn);

        // The same session's next payload takes the normal path and arrives.
        send_payload_uplink(
            &pool,
            &egress,
            sess,
            &target.as_ref(),
            b"after-outage",
            &mut Some(bind),
            &mut up,
            &mut frag,
            coarse_millis(),
            SessionKind::Socks,
        );
        assert_eq!(
            up.pending_len(),
            0,
            "{wire:?}: fresh generation sends, no hold"
        );
        drain_assoc_stage(&egress, &pool, bind);
        let d = tokio::time::timeout(Duration::from_secs(5), server_conn.read_datagram())
            .await
            .unwrap_or_else(|_| panic!("{wire:?}: post-outage payload was not sent"))
            .unwrap();
        let f = wire::decode_data(wire, &d).expect("a DATA frame decodes");
        assert_eq!(f.payload, b"after-outage", "{wire:?}");
        assert_eq!(
            f.sess,
            Some(sess),
            "{wire:?}: binding context on the new flow"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), server_conn.read_datagram())
                .await
                .is_err(),
            "{wire:?}: the expired held payload must not be delivered late"
        );
        client_conn.close(0u32.into(), b"done");
        server_conn.close(0u32.into(), b"done");
    }
}
