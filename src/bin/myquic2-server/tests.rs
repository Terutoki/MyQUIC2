//! Server unit tests (moved verbatim from the single-file bin).
use super::*;

/// Serializes the tests that mutate the process-global session-holder
/// count, so their exact reads cannot race each other.
static HOLDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn hdr(atyp: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![atyp];
    v.extend_from_slice(body);
    v
}

#[test]
fn mqp_hdr_len_matches_each_wire_form() {
    assert_eq!(mqp_hdr_len(0x01, 0).unwrap(), 7);
    assert_eq!(mqp_hdr_len(0x04, 0).unwrap(), 19);
    assert_eq!(mqp_hdr_len(0x03, 1).unwrap(), 5);
    assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
    assert!(
        mqp_hdr_len(0x03, 0).is_err(),
        "empty domain must be refused"
    );
    assert!(
        mqp_hdr_len(0x02, 0).is_err(),
        "unknown atyp must be refused"
    );
}

/// The stack-buffer reader must consume exactly the bytes the framed header
/// names, so the caller's stream position equals the pre-refactor one.
/// The length the stream-header reader collects and the length the decoder
/// consumes must agree for **every** form, or the server splits the stream at
/// the wrong offset and misparses every following byte of that flow. The
/// fixed cases above pin the four wire forms; this drives the same invariant
/// differentially over randomized addresses (including every port and the
/// whole domain-length range) against the encoder itself.
#[test]
fn mqp_hdr_len_agrees_with_the_encoder_for_random_addresses() {
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let mut checked = 0;
    for _ in 0..20_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let pick = x % 3;
        let addr = match pick {
            0 => TargetAddr::Ip(SocketAddr::from((
                std::net::Ipv4Addr::from((x >> 16) as u32),
                x as u16,
            ))),
            1 => {
                let mut o = [0u8; 16];
                o[..8].copy_from_slice(&x.to_be_bytes());
                o[8..].copy_from_slice(&x.rotate_left(29).to_be_bytes());
                TargetAddr::Ip(SocketAddr::from((std::net::Ipv6Addr::from(o), x as u16)))
            }
            _ => {
                let n = (x % 256) as usize;
                if n == 0 {
                    continue;
                }
                TargetAddr::Domain("d".repeat(n), x as u16)
            }
        };
        // Random draws include unspecified addresses and scoped v6 forms the
        // encoder legitimately refuses; only encodable ones can reach a peer.
        let mut buf = Vec::new();
        if addr.encode(&mut buf).is_err() {
            continue;
        }
        checked += 1;
        let declared = match buf[0] {
            0x03 => mqp_hdr_len(0x03, buf[1]).expect("domain length is valid"),
            atyp => mqp_hdr_len(atyp, 0).expect("atyp is valid"),
        };
        assert_eq!(
            declared,
            buf.len(),
            "declared header length must equal the encoding ({addr:?})"
        );
        let (decoded, consumed) = TargetAddr::decode(&buf).expect("decodes");
        assert_eq!(
            consumed,
            buf.len(),
            "decoder must consume the header exactly"
        );
        assert_eq!(decoded, addr, "round trip");
    }
    assert!(checked > 10_000, "most random addresses must be encodable");
}

#[test]
fn mqp_header_roundtrip_v4_v6_and_domain() {
    for (hdr_bytes, want) in [
        (
            hdr(0x01, &[8, 8, 8, 8, 0, 53]),
            TargetAddr::Ip("8.8.8.8:53".parse().unwrap()),
        ),
        (
            hdr(0x04, &{
                let mut b = [0u8; 18];
                b[..16].copy_from_slice(
                    &"2001:4860:4860::8888"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                b[16..].copy_from_slice(&443u16.to_be_bytes());
                b
            }),
            TargetAddr::Ip("[2001:4860:4860::8888]:443".parse().unwrap()),
        ),
        (
            hdr(0x03, &{
                let d = b"example.com";
                let mut b = vec![d.len() as u8];
                b.extend_from_slice(d);
                b.extend_from_slice(&8443u16.to_be_bytes());
                b
            }),
            TargetAddr::Domain("example.com".into(), 8443),
        ),
    ] {
        let len = mqp_hdr_len(hdr_bytes[0], *hdr_bytes.get(1).unwrap_or(&0)).unwrap();
        assert_eq!(len, hdr_bytes.len(), "declared length must match the frame");
        let (got, used) = TargetAddr::decode(&hdr_bytes).unwrap();
        assert_eq!(used, hdr_bytes.len());
        assert_eq!(got, want);
    }
}

/// A domain header longer than the 255-byte wire limit must be refused by
/// the length helper, never sliced into the fixed stack buffer.
#[test]
fn domain_wire_limit_is_enforced() {
    assert_eq!(mqp_hdr_len(0x03, 255).unwrap(), 259);
    assert!(mqp_hdr_len(0x03, 0).is_err());
}

fn memo_sock() -> Arc<tokio::net::UdpSocket> {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    s.set_nonblocking(true).unwrap();
    Arc::new(tokio::net::UdpSocket::from_std(s).unwrap())
}

/// A session destined for `addr`, inserted the way `get_or_create_sess`
/// would insert it, so the destination memo can be exercised without a live
/// QUIC connection.
fn sess_with_dest(addr: Option<SocketAddr>) -> (SessTable, Arc<tokio::net::UdpSocket>) {
    let ss = Arc::new(ShardedSessTable::new());
    let sock = memo_sock();
    let last = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let h = tokio::spawn(std::future::pending::<()>());
    let permit = session_limiter().clone().try_acquire_owned().unwrap();
    lock_write(ss.shard(7)).insert(
        7,
        SessEntry {
            sock: sock.clone(),
            reader: h,
            last,
            _permit: permit,
            dest: addr.map_or(DestMemo::NONE, |a| DestMemo {
                key: PortKey::new("", 0).unwrap(),
                addr: a,
                expires: mono_millis() + DEST_PIN_TTL_MS,
            }),
            recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
            recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        },
    );
    (ss, sock)
}

/// The per-datagram path, before this change, re-resolved a domain target
/// for *every* datagram: a hash, a key build and a full key compare per
/// packet, forever. The session's own memo is what removes that, so the
/// properties that keep it safe are asserted here.
#[tokio::test]
async fn session_dest_memo_round_trips_and_expires() {
    let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);

    // A fresh session has pinned nothing: the datagram path must resolve.
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);

    sess_dest_store(&ss, 7, "a.test", 443, dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443),
        Some(dst),
        "a stored destination must be reused"
    );

    // Past the pin's TTL the answer must go back through the resolver, or a
    // name that moves would keep the session pointed at a dead address for
    // the session's whole idle lifetime.
    let past = mono_millis() + DEST_PIN_TTL_MS + 1;
    assert_eq!(sess_dest_lookup(&ss, past, 7, "a.test", 443), None);

    // A different session number must never see another session's pin.
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 8, "a.test", 443), None);
}

/// The datagram path stores this memo for every domain-target packet, so the
/// store must cost a read lock — not a write — whenever the answer has not
/// changed. A redundant write per packet was measurable (35 ns of exclusive
/// shard lock plus a dirty line in the shared table) and a redundant
/// *refresh* is what the refresh window exists to avoid.
#[tokio::test]
async fn session_dest_store_writes_only_when_the_memo_needs_it() {
    let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let moved: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);
    let expires = || lock_read(ss.shard(7)).get(&7).unwrap().dest.expires;

    sess_dest_store(&ss, 7, "alpha.test", 443, dst, DNS_CACHE_TTL_MS);
    let first = expires();
    assert!(first > mono_millis(), "a store must leave a live memo");
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
        Some(dst)
    );

    // Same name, same address, TTL still fresh: nothing to write.
    sess_dest_store(&ss, 7, "alpha.test", 443, dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        expires(),
        first,
        "a redundant store must not rewrite (and so must not take the write lock)"
    );

    // Same name, new address: the memo must follow it.
    sess_dest_store(&ss, 7, "alpha.test", 443, moved, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
        Some(moved)
    );

    // Inside the refresh window the value is unchanged but the life is not:
    // that one must rewrite, or the entry would expire and the next packet
    // would pay a full resolve.
    lock_write(ss.shard(7)).get_mut(&7).unwrap().dest.expires = mono_millis() + 1;
    sess_dest_store(&ss, 7, "alpha.test", 443, moved, DNS_CACHE_TTL_MS);
    assert!(
        expires() > mono_millis() + DEST_PIN_REFRESH_MS,
        "a memo inside the refresh window must be refreshed"
    );
}

/// The bug this memo was rewritten for: a session is not bound to one
/// target, so a memo keyed on the session alone answered a datagram naming
/// B with the address resolved for A and relayed it to the wrong host.
/// Verified end to end with `hotpath_bench udpdomainswitch`, which caught
/// exactly this (1000 of 2000 datagrams misrouted) before the name became
/// part of the key.
#[tokio::test]
async fn session_dest_memo_is_keyed_on_the_target_name() {
    let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);
    sess_dest_store(&ss, 7, "alpha.test", 443, a, DNS_CACHE_TTL_MS);

    // Same session, different name: must not answer with alpha's address.
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "beta.test", 443),
        None
    );
    // Same session, same name, different port: likewise.
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 80),
        None
    );
    // The name it was stored for still hits.
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test", 443),
        Some(a)
    );

    // A name sharing a prefix must not match a shorter stored name.
    sess_dest_store(&ss, 7, "alpha.test", 443, b, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.test.", 443),
        None
    );
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "alpha.tes", 443),
        None
    );
}

/// An IP target has no name to re-check, and must not be confused with a
/// domain whose name happens to be empty or to share the port.
#[tokio::test]
async fn session_dest_memo_distinguishes_ip_and_domain_targets() {
    let ip_target: SocketAddr = "10.0.0.1:9999".parse().unwrap();
    let domain_target: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);

    // An IP target stores the empty host.
    sess_dest_store(&ss, 7, "", 9999, ip_target, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "", 9999),
        Some(ip_target)
    );
    // A domain target on the same session replaces it, and the IP-form
    // query must then miss rather than get the domain's address.
    sess_dest_store(&ss, 7, "gamma.test", 9999, domain_target, DNS_CACHE_TTL_MS);
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "", 9999), None);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, "gamma.test", 9999),
        Some(domain_target)
    );
}

/// A name too long for the inline key must not be memoized at all: storing
/// it truncated would let a different name sharing the prefix match it.
#[tokio::test]
async fn session_dest_memo_refuses_names_it_cannot_key() {
    let (ss, _sock) = sess_with_dest(None);
    let long = "x".repeat(DEST_KEY_BYTES + 1);
    sess_dest_store(
        &ss,
        7,
        &long,
        443,
        "10.0.0.1:443".parse().unwrap(),
        DNS_CACHE_TTL_MS,
    );
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &long, 443), None);
    // A name sharing that prefix must miss too.
    let prefix = "x".repeat(DEST_KEY_BYTES);
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &prefix, 443), None);
}

/// Storing into a session that no longer exists is a no-op, not a panic or a
/// phantom entry: the datagram path races session teardown by design.
#[tokio::test]
async fn session_dest_store_tolerates_a_vanished_session() {
    let ss = Arc::new(ShardedSessTable::new());
    sess_dest_store(
        &ss,
        7,
        "a.test",
        443,
        "10.0.0.1:1".parse().unwrap(),
        DNS_CACHE_TTL_MS,
    );
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, "a.test", 443), None);
}

/// The connection-level pin is a hint *with a deadline*. Without one, a
/// steady flow to a domain target kept using the address resolved when the
/// flow started for the whole connection lifetime: the session memo, the
/// DNS cache and `DEST_PIN_TTL_MS` were all bypassed for the one flow that
/// never missed, so a name that moved was never re-resolved.
#[tokio::test]
async fn conn_pin_stops_answering_when_its_ttl_expires() {
    let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let stale: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);
    sess_dest_store(&ss, 7, "pin-expiry.invalid", 443, dst, DNS_CACHE_TTL_MS);

    // A live pin answers for exactly the (session, name, port) it was
    // stored for...
    let mut pin: Option<ConnPin> = None;
    pin_arm(
        &mut pin,
        7,
        "pin-expiry.invalid",
        443,
        stale,
        DNS_CACHE_TTL_MS,
    );
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 443, true),
        Some(stale)
    );
    // ...and for nothing else.
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, "other-pin.invalid", 443, true),
        None
    );
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 80, true),
        None
    );

    // Past its deadline it must not answer at all; the session's own memo
    // is consulted instead and the pin is re-armed from it, freshly.
    pin.as_mut().unwrap().expires = coarse_millis().saturating_sub(1);
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, "pin-expiry.invalid", 443, true),
        Some(dst),
        "an expired pin must not answer"
    );
    let rearmed = pin.as_ref().expect("the memo must re-arm the pin");
    assert_eq!(rearmed.addr, dst);
    assert!(rearmed.expires > mono_millis(), "re-armed pin must be live");
}

/// The DNS-cache branch must arm the connection pin. Without that
/// write-back a fast-path success never called `sess_dest_store`, so pin
/// and session memo expired together at T+30 s while the DNS entry
/// was still live — every later packet paid `sess_dest_lookup` again for
/// the rest of the DNS TTL.
#[tokio::test]
async fn dns_hit_arms_the_pin_when_pin_and_memo_miss() {
    let dst: SocketAddr = "93.184.216.34:8443".parse().unwrap();
    let host = "dns-pin-arm.test";
    let port = 18443u16;
    dns_cache_seed(host, port, dst).await;

    let (ss, _sock) = sess_with_dest(None);

    // Cold start: no pin, no session memo — only the DNS cache answers.
    let mut pin: Option<ConnPin> = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(dst),
        "the DNS cache must answer when pin and memo both miss"
    );
    let armed = pin.as_ref().expect("a DNS hit must arm the pin");
    assert_eq!(armed.addr, dst);
    assert!(
        pin_is_for(armed, host, port),
        "the pin must name the target"
    );
    assert_eq!(armed.port, port);
    assert_eq!(armed.sess, 7);
    assert!(
        armed.expires > coarse_millis(),
        "the newly armed pin must be live"
    );

    // The P1 shape: pin expired, session memo still empty, DNS still live.
    // The DNS hit must re-arm the pin, or the flow degrades to a
    // `sess_dest_lookup` read lock on every packet for the rest of the TTL.
    pin.as_mut().unwrap().expires = coarse_millis().saturating_sub(1);
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(dst),
        "an expired pin must still fall through to the DNS cache"
    );
    let rearmed = pin.as_ref().expect("the DNS hit must re-arm the pin");
    assert_eq!(rearmed.addr, dst);
    assert!(
        rearmed.expires > coarse_millis(),
        "the re-armed pin must be live"
    );
}

#[tokio::test]
async fn resolve_pin_withholds_a_filtered_cached_address() {
    let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let host = "filtered-first.test";
    let port = 18444u16;
    dns_cache_seed(host, port, private).await;
    let (ss, _sock) = sess_with_dest(None);
    let mut pin: Option<ConnPin> = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, false),
        None,
        "a filtered first address must not be served or pinned"
    );
    assert!(
        pin.is_none(),
        "a filtered address must not arm the pin either"
    );
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(private),
        "allow_private must still serve it"
    );
}

/// A filtered first record: the synchronous pin probe withholds it, and the
/// async slow path is the layer that can still reach the rest of the set —
/// `resolve_all_cached` serves the full multi-record answer, from which
/// `forward_server_dgram`'s spawned waiter picks the first allowed address and
/// stores it into the session memo (which arms the pin on the next datagram).
#[tokio::test]
async fn resolve_pin_defers_filtered_first_record_to_the_slow_path() {
    let private: SocketAddr = "10.9.9.9:443".parse().unwrap();
    let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let host = "filtered-first-multi.test";
    let port = 18446u16;
    dns_cache_seed_set(host, port, &[private, public]).await;
    let (ss, _sock) = sess_with_dest(None);
    let mut pin: Option<ConnPin> = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, false),
        None,
        "the sync probe is the memo (first record only): a filtered first record \
         must be left to the slow path, never served or pinned"
    );
    assert!(
        pin.is_none(),
        "a deferred first record must not arm the pin either"
    );
    // The slow path's data source: the full set, with a usable record.
    let full = resolve_all_cached(host, port).await.expect("cached set");
    assert_eq!(&full[..], &[private, public]);
    assert!(
        full.iter().any(|a| is_global_ip(a.ip())),
        "the set the slow path picks from must contain an allowed address"
    );
    // allow_private callers still get the first record straight from the memo.
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(private),
        "allow_private must still serve the first record"
    );
}

/// A memo slot must never be the last owner of a session socket. With a
/// strong `Arc` there, a dead session's fd and kernel buffers outlived the
/// connection: the slot is only rewritten by a later session hashing to the
/// same index on the same thread, and connection ids never repeat, so
/// nothing ever released it.
#[tokio::test]
async fn session_memo_does_not_own_the_socket() {
    use std::sync::atomic::AtomicU64;

    let last = Arc::new(AtomicU64::new(1));
    let weak = {
        let sock = memo_sock();
        let weak = Arc::downgrade(&sock);
        // The strong reference is handed over and dropped here, exactly as
        // the table entry and the aborted reader are when a session dies.
        sess_memo_put(
            11,
            5,
            sock,
            last.clone(),
            live_reader(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        weak
    };
    assert!(
        weak.upgrade().is_none(),
        "the memo must not keep the session socket alive"
    );
    assert!(matches!(sess_memo_lookup(11, 5), SessHit::Stale));

    // While something else (the table, a reader) owns the socket, the memo
    // still serves it -- the weak reference must not over-stale a live
    // session.
    let sock = memo_sock();
    sess_memo_put(
        12,
        5,
        sock.clone(),
        last,
        live_reader(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    match sess_memo_lookup(12, 5) {
        SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &sock)),
        _ => panic!("a live session must still be served from the memo"),
    }
}

/// The 60 s sweeper snapshots idle keys under a *read* lock and removes
/// them under the write lock. A key that was touched (or recreated) while
/// the sweeper waited for that write lock is a live session, and removing
/// it aborted a reader the client was actively using. `take_idle` re-tests
/// every snapshotted key against the snapshot's `now`.
#[tokio::test]
async fn sweep_recheck_keeps_a_session_touched_after_the_snapshot() {
    let (ss, _sock) = sess_with_dest(None);
    let last = lock_read(ss.shard(7)).get(&7).unwrap().last.clone();
    // A sweep that starts well past the session's idle deadline.
    let now = last.load(std::sync::atomic::Ordering::Relaxed) + SESS_IDLE_MS + 10_000;

    // Phase 1: the read-locked snapshot.
    let keys: Vec<u32> = lock_read(ss.shard(7))
        .iter()
        .filter(|(_, e)| {
            now.saturating_sub(e.last.load(std::sync::atomic::Ordering::Relaxed)) >= SESS_IDLE_MS
        })
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(keys, vec![7], "the idle session must be in the snapshot");

    // The client's next datagram lands in the window before phase 2. A
    // touch always stamps a time at or after the sweeper's snapshot, so the
    // worst case this must survive is a stamp equal to `now`.
    last.store(now, std::sync::atomic::Ordering::Relaxed);

    // Phase 2: the write-locked removal must skip it.
    let evicted = {
        let mut w = lock_write(ss.shard(7));
        take_idle(&mut w, &keys, now)
    };
    assert!(
        evicted.is_empty(),
        "a session touched after the snapshot must survive"
    );
    assert!(lock_read(ss.shard(7)).contains_key(&7));
}

/// A reader that stays alive (`SessHit::Fresh` requires a running task).
fn live_reader() -> tokio::task::AbortHandle {
    let h = tokio::spawn(std::future::pending::<()>());
    let abort = h.abort_handle();
    drop(h);
    abort
}

/// One over-cap session in a scratch shard, stamped `idle_ms` ago.
fn capped_session(idle_ms: u64) -> SessEntry {
    SessEntry {
        sock: memo_sock(),
        reader: tokio::spawn(std::future::pending::<()>()),
        last: Arc::new(std::sync::atomic::AtomicU64::new(
            mono_millis().saturating_sub(idle_ms),
        )),
        _permit: session_limiter().clone().try_acquire_owned().unwrap(),
        dest: DestMemo::NONE,
        recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
        recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    }
}

/// Whether `s`'s reply allowlist currently admits `dst`.
fn allowlist_contains(ss: &SessTable, s: u32, dst: SocketAddr) -> bool {
    let sh = lock_read(ss.shard(s));
    let Some(e) = sh.get(&s) else {
        return false;
    };
    e.recent.load().contains(&dst)
}

/// Two interleaved sessions on one connection must **both** hit the
/// per-connection fast table.
///
/// The table replaced a single `(session, dst)` slot, which was the largest
/// defect on this path: the client multiplexes every UDP association of an
/// egress class onto one QUIC connection (`SharedEgress::egress_order` picks
/// that class's dedicated UDP slot first and a fail-closed pool stops there),
/// so with one slot every datagram for any second session took the full slow
/// path — a shard read lock, an unbatched target send that bypasses
/// `flush_staged_sends`'s `sendmmsg`, and two extra memo probes with a `Weak`
/// upgrade plus three `Arc` clones each.
///
/// Pinned at the level the defect lived: arm two sessions that map to different
/// slots, then require a hit (and the allowlist record the fast path owes) from
/// each, and a miss for a session that was never armed — the table is a cache,
/// never a router.
#[tokio::test]
async fn two_sessions_on_one_connection_both_hit_the_fast_table() {
    let ss: SessTable = Arc::new(ShardedSessTable::new());
    let conn_id = next_conn_id();
    let mut fast: [Option<FastSess>; FAST_SESS_SLOTS] = [NO_FAST_SESS; FAST_SESS_SLOTS];
    let mut staged: Vec<StagedSend> = Vec::with_capacity(LAST_HOP_DRAIN);
    let dst: SocketAddr = "198.51.100.7:53".parse().unwrap();

    let (s1, s2) = (1u32, 2u32);
    assert_ne!(
        fast_slot(s1),
        fast_slot(s2),
        "the fixture must exercise two distinct slots"
    );
    // Held for the test's life: the fast path's socket liveness is a `Weak`
    // upgrade, so the table entry must be the socket's live owner.
    let mut socks = Vec::new();
    for s in [s1, s2] {
        let entry = capped_session(0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        lock_write(ss.shard(s)).insert(s, entry);
        sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
        socks.push(sock);
    }

    // Arm both slots through the production slow-path arm.
    for s in [s1, s2] {
        arm_fast(
            &mut fast,
            conn_id,
            s,
            TargetAddrRef::Ip(dst),
            dst,
            DNS_CACHE_TTL_MS,
        );
        assert!(fast[fast_slot(s)].is_some(), "arm must publish session {s}");
    }

    // Both sessions must stage. The single-slot version could only ever serve
    // the most recently armed one.
    for s in [s1, s2] {
        let payload = Bytes::from_static(b"fast");
        assert!(
            try_stage(&mut fast, &ss, conn_id, s, dst, payload, true, &mut staged).is_ok(),
            "session {s} must hit its own slot"
        );
        assert_eq!(staged.len(), 1, "exactly one datagram staged for {s}");
        assert_eq!(staged[0].dst, map_for_dual(dst));
        staged.clear();
        // The fast path owes the reply allowlist the destination *before* the
        // send, or the reader drops the target's answer as forged.
        assert!(
            allowlist_contains(&ss, s, dst),
            "session {s}'s allowlist must record the fast-path destination"
        );
    }

    // Never armed, and mapped to a slot that is EMPTY: must miss (this is the
    // cheap case, and on its own it would still pass if `is_live_for` stopped
    // checking the session id).
    let empty_slot = 99u32;
    assert!(
        fast[fast_slot(empty_slot)].is_none(),
        "premise: slot is empty"
    );
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            empty_slot,
            dst,
            Bytes::from_static(b"x"),
            true,
            &mut staged
        )
        .is_err(),
        "an unarmed session must fall through to the slow path"
    );

    // The case that actually pins "a cache, never a router": a session whose id
    // collides with an armed slot (same index, different session), with a live
    // reader and an upgradable socket of its own. Dropping `slot.sess == s`
    // would stage this datagram onto *session 1's* socket, and only this shape
    // can catch that.
    let colliding = s1 + FAST_SESS_SLOTS as u32;
    assert_eq!(
        fast_slot(colliding),
        fast_slot(s1),
        "the fixture must collide"
    );
    {
        let entry = capped_session(0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        lock_write(ss.shard(colliding)).insert(colliding, entry);
        sess_memo_put(conn_id, colliding, sock.clone(), last, abort, epoch);
        socks.push(sock);
    }
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            colliding,
            dst,
            Bytes::from_static(b"x"),
            true,
            &mut staged
        )
        .is_err(),
        "a colliding session must miss its way to the slow path, never borrow \
         the slot owner's socket"
    );
    assert!(staged.is_empty(), "a miss must not stage anything");
}

/// The reader's task-local mirror of the reply allowlist must be validated
/// against the session's allowlist epoch, because one writer of that
/// allowlist is not the reader: the DNS resolver task `forward_server_dgram`
/// spawns pushes its resolved address from its own task, and
/// `RECENT_DST_CAP` such pushes evict a destination the mirror still claims
/// is present. The mirror then suppressed the re-record, so the target's
/// replies were dropped as forged — a silent one-way flow for as long as the
/// pin and the DNS entry lived.
#[tokio::test]
async fn the_allowlist_mirror_re_records_after_a_foreign_push() {
    use std::sync::atomic::Ordering;

    let (ss, _sock) = sess_with_dest(None);
    let epoch = lock_read(ss.shard(7)).get(&7).unwrap().recent_epoch.clone();
    let a: SocketAddr = "93.184.216.34:443".parse().unwrap();

    let mut mirror: Option<(u32, SocketAddr, u64)> = None;
    mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
    assert_eq!(epoch.load(Ordering::Relaxed), 1, "the first record pushes");
    assert_eq!(mirror, Some((7, a, 1)));

    // Steady state: the mirror suppresses the repeat push, which is the
    // reason it exists at all.
    mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
    assert_eq!(
        epoch.load(Ordering::Relaxed),
        1,
        "a repeat record must not push again"
    );

    // A foreign push — the resolver task's, on another thread — moves the
    // epoch without touching the mirror, and enough of them evict `a`.
    for i in 0..RECENT_DST_CAP {
        let d: SocketAddr = format!("9.9.9.{i}:53").parse().unwrap();
        remember_dst(&ss, 7, d);
    }
    assert!(epoch.load(Ordering::Relaxed) > 1);
    assert!(
        !allowlist_contains(&ss, 7, a),
        "the ring evicted the mirrored destination"
    );

    // The next datagram must notice and re-record, or every reply from `a`
    // stays refused.
    mirror_record(&ss, &mut mirror, 7, a, Some(&epoch));
    assert!(
        allowlist_contains(&ss, 7, a),
        "a foreign push must force the mirror to re-record"
    );
}

#[test]
fn reply_allowlist_matches_the_host_not_the_queried_port() {
    let mut r = RecentAddrs::default();
    assert!(r.is_empty());
    let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
    r.push(a);
    assert!(!r.is_empty());
    assert!(r.contains(&a), "the queried destination itself is allowed");
    // The whole point of the IP-only key: a server that answers from a
    // different port (TFTP's ephemeral reply port, redirected game/voice
    // flows) must not be filtered.
    assert!(
        r.contains(&"93.184.216.34:53".parse().unwrap()),
        "a reply from another port on a queried host is legitimate"
    );
    assert!(
        !r.contains(&b),
        "a host this session never sent to must stay refused"
    );
    r.push(a);
    assert_eq!(
        r.slots.iter().flatten().count(),
        1,
        "re-pushing the same host must not consume another slot"
    );
    r.push(b);
    assert!(r.contains(&a) && r.contains(&b));
    for i in 0..RECENT_DST_CAP {
        let d: SocketAddr = format!("9.9.9.{}:53", i).parse().unwrap();
        r.push(d);
    }
    assert!(
        r.slots.iter().flatten().count() <= RECENT_DST_CAP,
        "the allowlist must stay bounded"
    );
}

/// The allowlist is a clone-on-write snapshot: the reply task loads it for
/// every inbound datagram while the outbound path pushes into it from a
/// different task, so two concurrent pushes must **both** land (a
/// load-clone-store would drop one, and a dropped entry silently refuses
/// that target's replies) and the ring must still evict the oldest entry
/// past [`RECENT_DST_CAP`].
#[tokio::test]
async fn allowlist_pushes_are_lock_free_and_both_land() {
    let (ss, _sock) = sess_with_dest(None);
    let s = 7u32;
    let a: SocketAddr = "10.0.0.1:53".parse().unwrap();
    let b: SocketAddr = "10.0.0.2:53".parse().unwrap();

    let (t1, t2) = {
        let (x, y) = (ss.clone(), ss.clone());
        (
            std::thread::spawn(move || remember_dst(&x, s, a)),
            std::thread::spawn(move || remember_dst(&y, s, b)),
        )
    };
    t1.join().unwrap();
    t2.join().unwrap();
    assert!(allowlist_contains(&ss, s, a), "concurrent push A landed");
    assert!(allowlist_contains(&ss, s, b), "concurrent push B landed");

    // Past the cap the oldest entries are evicted, newest survive.
    for i in 0..RECENT_DST_CAP as u8 {
        remember_dst(&ss, s, SocketAddr::from(([10, 1, 0, i], 9)));
    }
    assert!(
        !allowlist_contains(&ss, s, a) && !allowlist_contains(&ss, s, b),
        "the ring evicted the two oldest destinations"
    );
    assert!(
        allowlist_contains(
            &ss,
            s,
            SocketAddr::from(([10, 1, 0, RECENT_DST_CAP as u8 - 1], 9))
        ),
        "the newest destination is admitted"
    );
}

/// The fair share divides the global session budget among connections that
/// actually **hold sessions**, and a table joins/leaves that denominator as
/// its emptiness changes.
///
/// Counting every live QUIC connection was the pass-29 defect: a client's
/// four idle TCP slots diluted its own UDP connection by 5x, so a lone
/// default client capped at `8192 / 5 = 1638` associations while the client
/// (and the README) admitted `MAX_UDP_ASSOCS = 4032` — and the excess was
/// silently black-holed server-side. All three properties are asserted in
/// one test so they cannot race each other over the process-global counter.
#[tokio::test]
async fn fair_share_counts_session_holders_not_live_connections() {
    use std::sync::atomic::Ordering;
    let _holder_guard = HOLDER_TEST_LOCK.lock().unwrap();
    let prev = session_holders().load(Ordering::Relaxed);
    // The client cap and the server's static per-connection target are one
    // number, shared through `lib.rs`.
    assert_eq!(LOCAL_SESS_TARGET, MAX_UDP_ASSOCS);

    // Pure arithmetic of the share.
    session_holders().store(1, Ordering::Relaxed);
    assert_eq!(fair_sess_cap(), LOCAL_SESS_MAX);
    assert!(
        fair_sess_cap() >= MAX_UDP_ASSOCS,
        "a lone session holder keeps its whole client cap"
    );
    session_holders().store(2, Ordering::Relaxed);
    assert_eq!(fair_sess_cap(), MAX_SESSIONS_GLOBAL / 2);
    // The floor is what a cheap dilution attack runs into: past 8 holders
    // every connection keeps MIN_SESSION_SHARE and the global semaphore
    // becomes the binding constraint.
    session_holders().store(8, Ordering::Relaxed);
    assert_eq!(fair_sess_cap(), MIN_SESSION_SHARE);
    session_holders().store(64, Ordering::Relaxed);
    assert_eq!(fair_sess_cap(), MIN_SESSION_SHARE);
    assert!(
        fair_sess_cap() >= 1024,
        "the old 256 floor let 32 single-session connections starve everyone"
    );

    // A table is counted only while non-empty.
    session_holders().store(prev, Ordering::Relaxed);
    let before = session_holders().load(Ordering::Relaxed);
    let empty = ShardedSessTable::new();
    empty.note_empty_state();
    assert_eq!(
        session_holders().load(Ordering::Relaxed),
        before,
        "an empty table is not a holder"
    );
    let (holding, _sock) = sess_with_dest(None);
    holding.note_empty_state();
    assert_eq!(
        session_holders().load(Ordering::Relaxed),
        before + 1,
        "a table holding a session joins the denominator"
    );
    let drained = holding.drain_all();
    assert!(!drained.is_empty());
    drop(drained);
    assert_eq!(
        session_holders().load(Ordering::Relaxed),
        before,
        "draining the last session leaves the denominator"
    );
    session_holders().store(prev, Ordering::Relaxed);
}

/// The fair-share gate must not compare a count frozen when its window
/// opened.
///
/// `len_cached` refreshed at most once a second and an insert never touched
/// it, so inside one window every forged new-session datagram still read the
/// pre-burst count and passed the gate — one connection could take every
/// `MAX_SESSIONS_GLOBAL` permit, and hold them indefinitely by touching each
/// session every <180 s (`sweep_all` reaps only idle sessions). The bound
/// adds every insert since the sample, so the same burst is refused from the
/// first packet past the share — and it is returned *as a bound*: only a stale
/// sample re-measures, because `cached_len` stays at or above the share until a
/// sweep republishes it, so re-measuring on every over-cap datagram charged the
/// 8-shard `len()` exactly where the peer is already over its share.
#[tokio::test]
async fn the_fair_share_gate_counts_inserts_since_the_sample() {
    let ss = ShardedSessTable::new();
    let now = mono_millis();
    // The first call measures and caches: nothing is held yet.
    assert_eq!(ss.len_upper_bound(now), 0);

    // One connection's burst of new sessions, all inside the sample window.
    for s in 0..8u32 {
        lock_write(ss.shard(s)).insert(s, capped_session(0));
        ss.note_insert();
    }
    assert!(
        ss.len_upper_bound(now) >= 8,
        "the gate must count inserts since the sample, not the frozen one"
    );
    // Past the share the value is the conservative bound, never an
    // under-count, so the gate can never be wrong in the admitting direction.
    assert_eq!(ss.len_upper_bound(now), 8);
    // A fresh table with sessions inserted without `note_insert` (i.e. one
    // whose counter was reset by a sweep resync) is still measured exactly
    // once the window expires.
    assert_eq!(ss.len_upper_bound(now + 2_000), 8);
}

#[tokio::test]
async fn stillborn_insert_leaves_the_fair_share_bound_unchanged() {
    let ss = ShardedSessTable::new();
    let now = mono_millis();
    assert_eq!(ss.len_upper_bound(now), 0);
    lock_write(ss.shard(7)).insert(7, capped_session(0));
    lock_write(ss.shard(7)).remove(&7);
    assert_eq!(
        ss.len_upper_bound(now),
        0,
        "a rolled-back insert must not inflate the fair-share bound"
    );
    lock_write(ss.shard(7)).insert(7, capped_session(0));
    ss.note_insert();
    assert_eq!(ss.len_upper_bound(now), 1);
    lock_write(ss.shard(7)).remove(&7);
}

/// Expired entries go through `take_idle` unbounded: 70 idle sessions are
/// all reaped in one call, because aborting idle readers is not a storm.
/// The old truncation reaped only the first 64 and left provably-dead
/// entries behind. Stamps and `now` are synthetic (see above).
#[tokio::test]
async fn sweep_local_reaps_all_expired_in_one_call() {
    use std::sync::atomic::Ordering;

    let now: u64 = 3_000_000;
    let mut m: SessMap = SessMap::default();
    for k in 0..70u32 {
        m.insert(k, capped_session(1));
        m.get(&k).unwrap().last.store(0, Ordering::Relaxed);
    }
    // The scan as `sweep_local` performs it: every session reads idle.
    let keys: Vec<u32> = m
        .iter()
        .filter(|(_, e)| now.saturating_sub(e.last.load(Ordering::Relaxed)) >= SESS_IDLE_MS)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(keys.len(), 70);
    // The exact removal `sweep_local` runs on its expired set: no bound.
    let evicted = take_idle(&mut m, &keys, now);
    assert_eq!(evicted.len(), 70);
    assert!(m.is_empty());
}

/// `sweep_local` must re-test each expired key with the same `now` before
/// removing it, exactly like `sweep_all` does through `take_idle`. The old
/// body removed the scanned keys unconditionally, so a session touched
/// after the scan — a touch lands lock-free, without the write guard —
/// was evicted and its freshly started reader aborted.
///
/// Stamps are synthetic: `mono_millis` is process uptime, so a fast test
/// process can never be 180 s old and no wall-clock stamp reads expired.
/// `take_idle` is the exact removal `sweep_local` delegates its expired
/// path to, with the same `now` the scan used.
#[tokio::test]
async fn sweep_local_rechecks_idle_before_removing() {
    use std::sync::atomic::Ordering;

    let mut m: SessMap = SessMap::default();
    m.insert(1, capped_session(1));
    let last = m.get(&1).unwrap().last.clone();
    // A sweep that starts well past the session's idle deadline.
    let now: u64 = 1_000_000;
    last.store(0, Ordering::Relaxed);
    // The scan as `sweep_local` performs it: the session reads idle.
    let keys: Vec<u32> = m
        .iter()
        .filter(|(_, e)| now.saturating_sub(e.last.load(Ordering::Relaxed)) >= SESS_IDLE_MS)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(keys, vec![1]);
    // The client's next datagram lands before the removal.
    last.store(now, Ordering::Relaxed);
    // Unconditional removal would evict it here; the re-test keeps it.
    assert!(take_idle(&mut m, &keys, now).is_empty());
    assert!(m.contains_key(&1));
    // End to end: a just-touched session is never expired by `sweep_local`
    // (its stamp is at/after the sweeper's instant, as a real touch is).
    last.store(mono_millis(), Ordering::Relaxed);
    assert!(sweep_local(&mut m).is_empty());
    assert!(m.contains_key(&1));
}

/// `touch_session_throttled` must store the mono epoch into `last`, not
/// the 1 s-quantized coarse sample it uses as its throttle gate: every
/// sweep reader subtracts `last` from a mono `now`, so a coarse stamp
/// reads up to one tick older than the true touch and reaps a live
/// session up to ~1 s before its 180 s budget runs out.
///
/// The test waits until the coarse sample visibly lags mono (>= 300 ms —
/// the 1 s upkeep interval guarantees this within one interval), then
/// touches with a key no other test can hold so the store is
/// unconditional. Against the old store the stamp would lag by that same
/// >= 300 ms; a mono store reads fresh within microseconds.
#[tokio::test]
async fn touch_stores_mono_millis_not_the_coarse_gate() {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Arm the epoch, then wait for a measurable lag between the two clocks.
    let _ = coarse_millis();
    let mut waited = 0;
    while mono_millis().saturating_sub(coarse_millis()) < 300 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += 1;
        assert!(
            waited < 200,
            "the upkeep thread must advance the cached sample"
        );
    }
    let lag = mono_millis().saturating_sub(coarse_millis());
    assert!(lag >= 300, "need a visible coarse lag to test against");

    // A key no other test uses: memo miss means the touch is due and the
    // store is unconditional.
    let last = Arc::new(AtomicU64::new(0));
    touch_session_throttled(usize::MAX - 7, u32::MAX - 7, &last);
    let stored = last.load(Ordering::Relaxed);
    let mono_after = mono_millis();
    assert!(stored != 0, "a memo-miss touch must store");
    assert!(
        stored <= mono_after,
        "the stamp cannot run ahead of the clock"
    );
    assert!(
        mono_after.saturating_sub(stored) < 300,
        "the touch stamp must be a fresh mono sample, not the coarse gate \
             lagging {lag} ms behind (stored={stored} mono={mono_after})"
    );

    // Sweep math is exact to the ms on a touched stamp: a session idle
    // just under the budget survives, one exactly at it does not.
    // Synthetic stamps: mono is process uptime, so a fast test process
    // can never be 180 s old and no wall-clock stamp reads expired.
    let now: u64 = 1_000_000;
    let mut m: SessMap = SessMap::default();
    m.insert(1, capped_session(1));
    m.get(&1)
        .unwrap()
        .last
        .store(now.saturating_sub(SESS_IDLE_MS - 500), Ordering::Relaxed);
    assert!(
        take_idle(&mut m, &[1], now).is_empty(),
        "500 ms under budget must survive the sweep"
    );
    m.get(&1)
        .unwrap()
        .last
        .store(now.saturating_sub(SESS_IDLE_MS), Ordering::Relaxed);
    assert_eq!(
        take_idle(&mut m, &[1], now).len(),
        1,
        "exactly at budget must reap"
    );
}

/// The pin stores its name **inline**: arming must round-trip the longest
/// name the wire can carry without allocating, and must refuse (never
/// truncate) a name it cannot hold — a truncated key could match a different
/// name and mis-route the flow.
#[tokio::test]
async fn the_pin_holds_the_wire_max_name_inline() {
    let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let longest = "a".repeat(PIN_HOST_BYTES);
    let mut pin = None;
    pin_arm(&mut pin, 7, &longest, 443, addr, DNS_CACHE_TTL_MS);
    let armed = pin.as_ref().expect("the wire-max name must pin");
    assert!(pin_is_for(armed, &longest, 443));
    assert_eq!(armed.host_len as usize, PIN_HOST_BYTES);
    // Every neighbouring key must not match: a prefix, another port.
    assert!(!pin_is_for(armed, &longest[..PIN_HOST_BYTES - 1], 443));
    assert!(!pin_is_for(armed, &longest, 80));
    assert!(!pin_is_for(armed, "different.test", 443));

    // Longer than the wire limit: refused, not truncated.
    let mut too_long = None;
    pin_arm(
        &mut too_long,
        7,
        &"b".repeat(PIN_HOST_BYTES + 1),
        443,
        addr,
        DNS_CACHE_TTL_MS,
    );
    assert!(
        too_long.is_none(),
        "a name that cannot be stored whole must not be pinned"
    );

    // An IP target pins under the empty name `target_name` gives it.
    pin_arm(&mut too_long, 7, "", 443, addr, DNS_CACHE_TTL_MS);
    assert!(too_long.as_ref().is_some_and(|p| pin_is_for(p, "", 443)));
}

/// A pin adopted from a cache hit must not outlive the entry it came from.
///
/// `DEST_PIN_TTL_MS` is documented as "deliberately shorter than the DNS
/// cache TTL (120 s) ... this bounds how long a session can keep sending to
/// an address the name no longer resolves to". Measured *from adoption* that
/// was false: a pin armed 0.5 s before its source entry expired still lived
/// its own full 30 s, so the address was served well past the entry's life.
/// Every arming site now clamps to the source's remaining life, so the
/// documented bound holds.
#[tokio::test]
async fn a_pin_never_outlives_the_cache_entry_it_was_armed_from() {
    let addr: SocketAddr = "93.184.216.34:19101".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);

    let (host, port) = ("pin-life-aged.test", 19101u16);
    dns_cache_seed_aged(
        host,
        port,
        addr,
        Duration::from_millis(DNS_CACHE_TTL_MS - 500),
    )
    .await;
    let mut pin = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(addr)
    );
    let life = pin
        .as_ref()
        .unwrap()
        .expires
        .saturating_sub(coarse_millis());
    assert!(
        life > 0 && life <= 1_500,
        "the pin must follow the entry's remainder, got {life} ms"
    );

    // A freshly resolved name still gets the pin's own (shorter) TTL.
    let (fresh, fresh_port) = ("pin-life-fresh.test", 19102u16);
    dns_cache_seed(fresh, fresh_port, addr).await;
    let mut pin2 = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin2, 7, 7, fresh, fresh_port, true),
        Some(addr)
    );
    let life2 = pin2
        .as_ref()
        .unwrap()
        .expires
        .saturating_sub(coarse_millis());
    assert!(
        life2 > DEST_PIN_TTL_MS - 2_000 && life2 <= DEST_PIN_TTL_MS,
        "a fresh entry keeps the pin TTL, got {life2} ms"
    );
}

/// The per-session destination memo has the same contract: `resolve_pin`
/// reads it back and adopts it as the connection pin, so an unclamped store
/// would re-arm a fresh `DEST_PIN_TTL_MS` from an address whose DNS entry is
/// about to expire.
#[tokio::test]
async fn the_session_memo_follows_its_sources_remaining_life() {
    let (ss, _sock) = sess_with_dest(None);
    let (host, port) = ("memo-life.test", 19103u16);
    let addr: SocketAddr = "93.184.216.34:19103".parse().unwrap();

    sess_dest_store(&ss, 7, host, port, addr, 1_000);
    let (got, life) = sess_dest_lookup_ttl(&ss, coarse_millis(), 7, host, port).unwrap();
    assert_eq!(got, addr);
    assert!(
        life <= 1_100,
        "the memo must not exceed its source: {life} ms"
    );

    // A pin adopted from that memo inherits the bound, never a fresh TTL.
    let mut pin = None;
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(addr)
    );
    let pin_life = pin
        .as_ref()
        .unwrap()
        .expires
        .saturating_sub(coarse_millis());
    assert!(
        pin_life <= 1_100,
        "pin life {pin_life} ms must follow the memo"
    );

    // Stored with the full source life, the memo keeps DEST_PIN_TTL_MS.
    sess_dest_store(&ss, 7, host, port, addr, DNS_CACHE_TTL_MS);
    let (_, life2) = sess_dest_lookup_ttl(&ss, coarse_millis(), 7, host, port).unwrap();
    assert!(
        life2 > DEST_PIN_TTL_MS - 2_000 && life2 <= DEST_PIN_TTL_MS,
        "a full-life source keeps the memo TTL, got {life2} ms"
    );
}

/// Below the static per-shard ceiling the sweep must already fire once the
/// shard reaches its fair share: with 32 session holders the fair cap is
/// 256 (32 per shard), so a shard at 400 sweeps instead of waiting for 512.
#[test]
fn fair_shard_trigger_fires_below_the_static_shard_cap() {
    assert!(shard_over_share(400, 256), "32 per shard: 400 is over");
    assert!(shard_over_share(32, 256), "exactly the share fires");
    assert!(!shard_over_share(31, 256));
    // A lone holder: one eighth of its whole cap.
    assert!(shard_over_share(
        LOCAL_SESS_MAX / SESS_SHARDS,
        LOCAL_SESS_MAX
    ));
    assert!(!shard_over_share(
        LOCAL_SESS_MAX / SESS_SHARDS - 1,
        LOCAL_SESS_MAX
    ));
    // Defense in depth: the floor lives inside the helper, so a tiny
    // `fair_cap` can never produce a zero share (and a trigger on it).
    assert!(!shard_over_share(0, 0));
    assert!(shard_over_share(1, 0));
    assert!(shard_over_share(1, 7));
    assert!(!shard_over_share(0, 7));
}

/// The admission cap must be a real memory bound: raising the transport
/// windows has to admit fewer connections, a budget too small for one
/// connection still admits one (so the endpoint is diagnosable), and no
/// configuration may exceed the hard connection cap.
#[test]
fn admission_cap_bounds_connections_by_memory() {
    let per_conn = per_connection_memory_bytes(&TransportTuning::default());
    assert_eq!(
        per_conn,
        8 * 1024 * 1024,
        "2/4/2 MB windows + 2 x 1 MB packets"
    );

    // No budget: the count cap stands, clamped to the hard cap.
    assert_eq!(
        admission_cap(MAX_CONNECTIONS, None, per_conn),
        MAX_CONNECTIONS
    );
    assert_eq!(admission_cap(1, None, per_conn), 1);

    // A 512 MiB budget / 8 MiB per connection = 64 connections.
    assert_eq!(admission_cap(MAX_CONNECTIONS, Some(512), per_conn), 64);
    // Raising the windows must lower the admitted count for the same budget.
    let wide = TransportTuning {
        receive_window: 16 * 1024 * 1024,
        send_window: 8 * 1024 * 1024,
        stream_receive_window: 8 * 1024 * 1024,
        ..TransportTuning::default()
    };
    let per_conn_wide = per_connection_memory_bytes(&wide);
    assert!(per_conn_wide > per_conn);
    assert!(
        admission_cap(MAX_CONNECTIONS, Some(512), per_conn_wide)
            < admission_cap(MAX_CONNECTIONS, Some(512), per_conn),
        "the same budget must admit fewer wide-window connections"
    );
    // Count cap still wins when it is the smaller of the two.
    assert_eq!(admission_cap(8, Some(512), per_conn), 8);
    // A budget too small for even one connection admits exactly one.
    assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), per_conn), 1);
    // No division by zero for a degenerate per-connection figure: the
    // divisor floors at one byte, so the count cap still binds.
    assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), 0), MAX_CONNECTIONS);
}

/// One connection's stream-task share must be bounded by the pool, floored
/// so a crowd of peers cannot cut a real client down to a handful of flows,
/// and never above what a connection can even open.
#[test]
fn one_connection_cannot_hold_the_whole_stream_pool() {
    // A lone connection is capped by the transport credit, not the pool:
    // 8192 streams is what it can open, and the pool is larger.
    assert_eq!(stream_share(1), MAX_BIDI_STREAMS_PER_CONN as usize);
    // Two connections each asking for the whole pool: half each.
    assert_eq!(stream_share(2), MAX_STREAM_TASKS / 2);
    // Four: a quarter each, so the pool cannot be consumed by four peers.
    assert_eq!(stream_share(4), MAX_STREAM_TASKS / 4);
    assert!(stream_share(4) * 4 <= MAX_STREAM_TASKS + MIN_STREAM_SHARE);
    // Beyond 16 admitted connections the floor takes over, so a crowd of
    // mostly-idle peers cannot starve a real client.
    assert_eq!(stream_share(16), MIN_STREAM_SHARE);
    assert_eq!(stream_share(64), MIN_STREAM_SHARE);
    assert_eq!(stream_share(MAX_CONNECTIONS), MIN_STREAM_SHARE);
    // A zero divisor (no admission accounting yet) must not divide by zero.
    assert_eq!(stream_share(0), MAX_BIDI_STREAMS_PER_CONN as usize);
    // The floor is never above the per-connection maximum.
    assert!(MIN_STREAM_SHARE <= MAX_BIDI_STREAMS_PER_CONN as usize);
}

/// Live loopback QUIC pair driving the production transport config, so the
/// stream-admission tests below run `handle_tcp_stream` against real
/// streams instead of a mock.
async fn stream_test_pair() -> (quinn::Connection, quinn::Connection) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec!["test.com".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    scfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(scfg).unwrap();
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    server_cfg.transport_config(build_transport("bbr", 5));
    let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();

    let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates({
            let mut r = rustls::RootCertStore::empty();
            r.add(cert.der().clone()).unwrap();
            r
        })
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![MQP_ALPN.to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(ccfg).unwrap();
    let mut ccfg = quinn::ClientConfig::new(Arc::new(qcc));
    ccfg.transport_config(build_transport("bbr", 5));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(ccfg);

    let server_addr = server.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        incoming.await.unwrap()
    });
    let client_conn = client
        .connect(server_addr, "test.com")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();
    (client_conn, server_conn)
}

async fn read_reset_code(recv: &mut quinn::RecvStream) -> u64 {
    match recv.read_chunk(64 * 1024, true).await {
        Err(quinn::ReadError::Reset(code)) => code.into_inner(),
        Err(e) => panic!("expected a stream reset, got {e:?}"),
        Ok(_) => panic!("expected a stream reset, got bytes"),
    }
}

/// H7 pin: a stream that never *finishes* its header must wait out the 5 s
/// header budget holding NO stream-task permit. With every permit drained,
/// the old order (permit before header) reset `0x05` immediately without
/// reading; the new order reads first and resets `0x01` on the header
/// timeout. Either the code or the elapsed time falsifies a regression.
///
/// One header byte is sent deliberately: a QUIC stream only becomes visible
/// to the peer once a frame carries its id, so a stream that sends nothing
/// at all would leave `accept_bi` — and this test — hanging forever.
#[tokio::test]
async fn header_wait_holds_no_stream_task_permit() {
    // Drain the process-wide pool. No other test in this binary touches
    // `stream_task_limiter`, so this cannot starve parallel tests.
    let _drained = stream_task_limiter()
        .clone()
        .acquire_many_owned(MAX_STREAM_TASKS as u32)
        .await
        .unwrap();
    assert_eq!(stream_task_limiter().available_permits(), 0);

    let (client_conn, server_conn) = stream_test_pair().await;
    let (mut cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
    // The atyp byte only: this opens the stream on the wire (the peer can
    // then accept it) while leaving the header incomplete, so the server's
    // `read_mqp_target` must wait out the rest of the 5 s budget.
    cli_send.write_all(&[0x01]).await.unwrap();
    let (srv_send, srv_recv) = server_conn.accept_bi().await.unwrap();

    let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let t0 = std::time::Instant::now();
    // The header never completes: the 5 s budget must elapse first.
    handle_tcp_stream(
        srv_send,
        srv_recv,
        streams_held.clone(),
        MAX_STREAM_TASKS,
        1,
        true,
        server_conn.clone(),
    )
    .await;
    let waited = t0.elapsed();
    assert!(
        waited >= Duration::from_millis(4500),
        "the header budget must elapse before admission is even attempted, waited {waited:?}"
    );
    assert_eq!(
        read_reset_code(&mut cli_recv).await,
        0x01,
        "a header timeout resets 0x01 even with zero permits (old order reset 0x05 immediately)"
    );
    assert_eq!(
        streams_held.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a header-less stream must never take a share slot"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The other half of the H7 pin: with the header already in, an exhausted
/// pool must still refuse fail-fast with `0x05` — no dial attempted, no
/// wait, no share slot taken. The target is loopback so even a leaked
/// permit could not dial anywhere surprising.
#[tokio::test]
async fn admission_after_header_still_fails_fast() {
    let _drained = stream_task_limiter()
        .clone()
        .acquire_many_owned(MAX_STREAM_TASKS as u32)
        .await
        .unwrap();

    let (client_conn, server_conn) = stream_test_pair().await;
    let (mut cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
    // Valid IP-literal header for 127.0.0.1:9 (discard): decoding must
    // succeed so the stream reaches admission, where the drained pool
    // refuses it before any dial.
    cli_send
        .write_all(&[0x01, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();
    let (srv_send, srv_recv) = server_conn.accept_bi().await.unwrap();

    let streams_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let t0 = std::time::Instant::now();
    handle_tcp_stream(
        srv_send,
        srv_recv,
        streams_held.clone(),
        MAX_STREAM_TASKS,
        1,
        true,
        server_conn.clone(),
    )
    .await;
    let took = t0.elapsed();
    assert!(
        took < Duration::from_secs(4),
        "admission with the header in must fail fast, took {took:?}"
    );
    assert_eq!(
        read_reset_code(&mut cli_recv).await,
        0x05,
        "an exhausted pool after a good header resets 0x05"
    );
    assert_eq!(
        streams_held.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a refused stream must never take a share slot"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The shard sweep never kills a *live* session, however far over the fair
/// share the shard is: 512 sessions touched milliseconds ago all survive one
/// sweep, because the only set it removes is the expired one (and the reap
/// of a genuinely expired session is `take_idle`'s job, pinned with
/// synthetic stamps by `sweep_local_rechecks_idle_before_removing`). The
/// over-share's resource bound is the connection-level fair-share gate, not
/// an eviction here.
#[tokio::test]
async fn a_live_over_share_shard_loses_nothing_to_the_sweep() {
    let mut m: SessMap = SessMap::default();
    for k in 0..512u32 {
        m.insert(k, capped_session(5));
    }
    assert!(
        shard_over_share(512, 256),
        "premise: the shard is over share"
    );
    let evicted = sweep_local(&mut m);
    assert!(
        evicted.is_empty(),
        "a live over-share must not be aborted: {} evicted",
        evicted.len()
    );
    assert_eq!(m.len(), 512);
}

/// A reader that exits after its session was recreated must not clear the
/// new generation's memo. The old `forget` matched on `(conn, sess)` alone,
/// so the exiting old reader wiped the recreated session's entry and its
/// datagrams fell through to a table miss.
#[tokio::test]
async fn sess_memo_forget_never_wipes_a_recreated_memo() {
    use std::sync::atomic::AtomicU64;

    let old_sock = memo_sock();
    let new_sock = memo_sock();
    let epoch = Arc::new(AtomicU64::new(0));
    sess_memo_put(
        9,
        3,
        old_sock.clone(),
        Arc::new(AtomicU64::new(1)),
        live_reader(),
        epoch.clone(),
    );
    // Same (conn, sess), new socket and reader: the recreated session.
    sess_memo_put(
        9,
        3,
        new_sock.clone(),
        Arc::new(AtomicU64::new(2)),
        live_reader(),
        epoch,
    );
    // The old reader exits after the recreate.
    sess_memo_forget(9, 3, &old_sock);
    match sess_memo_lookup(9, 3) {
        SessHit::Fresh(s, _, _, _) => assert!(
            Arc::ptr_eq(&s, &new_sock),
            "the recreated memo must survive the old reader's forget"
        ),
        _ => panic!("the recreated memo must survive the old reader's forget"),
    }
    // The new generation's own forget still clears.
    sess_memo_forget(9, 3, &new_sock);
    assert!(matches!(sess_memo_lookup(9, 3), SessHit::Miss));
}

/// Session ids are allocated per client and every client hub counts from 1,
/// so two connections whose DATAGRAM readers share one worker thread
/// routinely carry the same sess id. The memo is a single thread-local
/// slot, so matching on `sess` alone served one connection's socket to the
/// other — its datagrams then went out on the wrong session and the replies
/// came back on the wrong QUIC connection.
#[tokio::test]
async fn session_memo_never_crosses_connections() {
    use std::sync::atomic::AtomicU64;

    let a = memo_sock();
    let b = memo_sock();
    let last = Arc::new(AtomicU64::new(1));

    sess_memo_put(
        1,
        7,
        a.clone(),
        last.clone(),
        live_reader(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    assert!(matches!(sess_memo_lookup(2, 7), SessHit::Miss));
    match sess_memo_lookup(1, 7) {
        SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &a)),
        _ => panic!("the owning connection must still hit"),
    }
    assert!(matches!(sess_memo_lookup(1, 8), SessHit::Miss));

    sess_memo_forget(2, 7, &a);
    assert!(matches!(sess_memo_lookup(1, 7), SessHit::Fresh(..)));
    sess_memo_forget(1, 7, &a);
    assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));

    sess_memo_put(
        2,
        7,
        b.clone(),
        last,
        live_reader(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    assert!(matches!(sess_memo_lookup(1, 7), SessHit::Miss));
    match sess_memo_lookup(2, 7) {
        SessHit::Fresh(s, _, _, _) => assert!(Arc::ptr_eq(&s, &b)),
        _ => panic!("connection 2 must see its own socket"),
    }
}

/// The sweeper and a connection close abort a session's reader, which then
/// never reaches the cleanup after its loop — so the memo must learn that
/// the reader is gone from the task handle itself, or it keeps handing out
/// a socket nobody reads.
#[tokio::test]
async fn session_memo_ignores_finished_readers() {
    use std::sync::atomic::AtomicU64;

    let last = Arc::new(AtomicU64::new(1));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let h = tokio::spawn(async move {
        let _ = rx.await;
    });
    let finished = h.abort_handle();
    drop(tx);
    h.await.unwrap();
    assert!(finished.is_finished());
    sess_memo_put(
        3,
        1,
        memo_sock(),
        last.clone(),
        finished,
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    assert!(matches!(sess_memo_lookup(3, 1), SessHit::Stale));

    let h = tokio::spawn(std::future::pending::<()>());
    let aborted = h.abort_handle();
    h.abort();
    while !aborted.is_finished() {
        tokio::task::yield_now().await;
    }
    sess_memo_put(
        4,
        1,
        memo_sock(),
        last,
        aborted,
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    assert!(matches!(sess_memo_lookup(4, 1), SessHit::Stale));
}

/// Security regression: after every cache slot has been written (and
/// evicted at least once), the memo must still agree with `is_global_ip`
/// for the whole filter table. A wrong `true` would let a peer dial
/// private/loopback/link-local/CGNAT space.
#[test]
fn ip_cache_matches_predicate_after_full_fill() {
    for i in 0..200u8 {
        let _ = is_global_ip_cached(IpAddr::V4(Ipv4Addr::new(8, 8, 8, i)));
    }
    for i in 0..200u16 {
        let ip: IpAddr = format!("2001:4860::{i:x}").parse().unwrap();
        let _ = is_global_ip_cached(ip);
    }

    let cases = [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "fe80::1",
        "100.64.0.1",
        "64:ff9b::a00:1",
        "192.0.2.1",
        "2001:db8::1",
        "198.18.0.1",
        "224.0.0.1",
        "ff02::1",
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
    ];
    for s in cases {
        let ip: IpAddr = s.parse().unwrap();
        assert_eq!(
            is_global_ip_cached(ip),
            is_global_ip(ip),
            "memo verdict diverged from is_global_ip for {s}"
        );
    }
}

/// A collision must evict, never mis-serve: two addresses sharing one slot
/// but carrying opposite verdicts must each return the predicate's answer,
/// in both probe orders.
#[test]
fn ip_cache_collision_evicts_and_never_mis_serves() {
    use std::collections::HashMap;

    // Non-global `0.0.0.0/8` candidates against global `8.8.0.0/16`
    // candidates; 1024 of each over 64 slots guarantees a cross-verdict
    // same-index pair.
    let non_global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::from(i)));
    let global = (0..1024u32).map(|i| IpAddr::V4(Ipv4Addr::new(8, 8, (i >> 8) as u8, i as u8)));

    let mut seen: HashMap<usize, IpAddr> = HashMap::new();
    let mut pair = None;
    for ip in non_global.chain(global) {
        let idx = ip_cache_idx(ip);
        match seen.get(&idx) {
            Some(&other) if is_global_ip(other) != is_global_ip(ip) => {
                pair = Some((other, ip));
                break;
            }
            Some(_) => {}
            None => {
                seen.insert(idx, ip);
            }
        }
    }
    let (a, b) = pair.expect("two verdict classes over 64 slots must collide");
    assert_eq!(ip_cache_idx(a), ip_cache_idx(b));
    assert_ne!(is_global_ip(a), is_global_ip(b));

    assert_eq!(is_global_ip_cached(a), is_global_ip(a));
    assert_eq!(is_global_ip_cached(b), is_global_ip(b));
    assert_eq!(is_global_ip_cached(a), is_global_ip(a));
}

/// Churn holds the caps: creating and tearing down 1024 sessions leaves
/// the table empty, every global permit released, the holder count
/// restored, and no live session swept.
///
/// The holder assertions are exact because this test and
/// `fair_share_counts_session_holders_not_live_connections` serialize on
/// `HOLDER_TEST_LOCK`: both mutate the process-global holder count, and
/// exact reads would otherwise race each other.
#[tokio::test]
async fn session_churn_holds_caps_without_leaking() {
    use std::sync::atomic::Ordering;

    let _holder_guard = HOLDER_TEST_LOCK.lock().unwrap();
    const N: usize = 1024;
    let holders_before = session_holders().load(Ordering::Relaxed);
    let permits_before = session_limiter().available_permits();
    let ss = Arc::new(ShardedSessTable::new());
    for s in 1..=N as u32 {
        lock_write(ss.shard(s)).insert(s, capped_session(0));
        ss.note_insert();
    }
    ss.note_empty_state();
    assert_eq!(ss.len(), N, "every churned session must be in the table");
    assert_eq!(
        session_holders().load(Ordering::Relaxed),
        holders_before + 1,
        "one non-empty table joins the fair-share denominator exactly once"
    );
    // Outstanding permits can only exceed this test's N (other tests hold
    // permits concurrently), never fall short of it — so the race-proof
    // form counts outstanding, not remaining.
    assert!(
        MAX_SESSIONS_GLOBAL - session_limiter().available_permits() >= N,
        "each session pins one global permit"
    );

    // A sweep over a churned-but-live table reaps nothing: the only set it
    // may remove is the expired one.
    let swept = ss.sweep_all(mono_millis());
    assert!(
        swept.is_empty(),
        "a sweep must not reap live sessions: {} evicted",
        swept.len()
    );
    assert_eq!(ss.len(), N);

    // Teardown mirrors `conn.closed()`: drain plus abort every reader, so
    // no task, socket or permit outlives the connection.
    let drained = ss.drain_all();
    assert_eq!(drained.len(), N);
    abort_evicted(drained);
    assert_eq!(ss.len(), 0);
    assert_eq!(
        session_holders().load(Ordering::Relaxed),
        holders_before,
        "draining the last session leaves the denominator"
    );
    // The exact holder reads above are done: release the serialization
    // guard before the quiescent permit wait below, which awaits.
    drop(_holder_guard);
    // Other tests hold permits concurrently, so balance is asserted
    // quiescently: every test releases what it took, and this test's N
    // are among them.
    for _ in 0..200 {
        if session_limiter().available_permits() >= permits_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        session_limiter().available_permits() >= permits_before,
        "all churned permits must be released"
    );
}

/// The recv-buf pool is bounded and exactly sized: whatever churn pushes
/// in, at most `SESS_BUF_POOL_DEPTH` buffers idle per thread, each one a
/// valid reader buffer.
#[test]
fn sess_recv_buf_pool_is_bounded_and_exactly_sized() {
    let mut bufs = Vec::new();
    for _ in 0..SESS_BUF_POOL_DEPTH + 4 {
        bufs.push(sess_recv_buf());
    }
    for b in &bufs {
        assert_eq!(b.len(), SESS_RECV_BUF_LEN);
    }
    for b in bufs {
        sess_recycle_buf(b);
    }
    assert!(
        sess_buf_pool_len() <= SESS_BUF_POOL_DEPTH,
        "the pool must drop past its depth, not grow with churn"
    );
    // Wrong-sized buffers are dropped, never pooled.
    sess_recycle_buf(vec![0u8; 16]);
    assert!(sess_buf_pool_len() <= SESS_BUF_POOL_DEPTH);
    // A recycled buffer comes back at the exact reader length, so the
    // `n == buf.len()` truncation check holds for reused buffers too.
    let b = sess_recv_buf();
    assert_eq!(b.len(), SESS_RECV_BUF_LEN);
    sess_recycle_buf(b);
}

/// The over-cap reap runs at most once per second process-wide, however
/// many workers contend for it — otherwise every forged new-session
/// datagram buys an O(sessions) table walk.
#[test]
fn fair_sweep_window_admits_one_sweep_per_second() {
    use std::sync::atomic::Ordering;

    // Synthetic stamps, not `mono_millis`: that clock is process uptime,
    // and a young test binary is not yet a second old, so a relative
    // window off it would never read expired. Nothing else in the test
    // build touches this static, and the window is restored below.
    let now = 10_000_000u64;
    FAIR_SWEEP_LAST_MS.store(now - 2000, Ordering::Relaxed);
    assert!(claim_fair_sweep(now), "an expired window must be claimable");
    assert!(
        !claim_fair_sweep(now),
        "the same instant must not claim twice"
    );
    assert!(!claim_fair_sweep(now + 999));
    assert!(claim_fair_sweep(now + 1000));
    FAIR_SWEEP_LAST_MS.store(0, Ordering::Relaxed);
}

/// The `TooLarge` re-probe throttle: one live-budget re-read per probe window
/// per reader, so a PMTU shrink cannot cost one quinn state-lock per oversized
/// reply on top of the per-frame send take. Zero means never probed (mono
/// epoch counts from process start). Pure and Thundering-free by construction:
/// the reader task owns the stamp, so no atomics and no cross-task traffic.
#[test]
fn too_large_probe_throttle_admits_one_reread_per_window() {
    assert!(too_large_probe_due(0, 0));
    assert!(too_large_probe_due(0, 5));
    assert!(!too_large_probe_due(
        1_000,
        1_000 + READER_BUDGET_PROBE_INTERVAL_MS - 1
    ));
    assert!(too_large_probe_due(
        1_000,
        1_000 + READER_BUDGET_PROBE_INTERVAL_MS
    ));
    assert!(too_large_probe_due(
        1_000,
        1_000 + READER_BUDGET_PROBE_INTERVAL_MS + 1
    ));
}

/// Serializes the slow-path counter tests in this binary: the drop counters
/// are process-wide and exact, so two such tests racing would move each
/// other's deltas — and the limiter test drains the shared budget another
/// test's burst needs. Every test below that asserts a counter delta holds
/// this while it measures. (Mirrors the client's `DNS_SLOW_PATH_COUNTER_LOCK`
/// and the lib's `SLOW_PATH_COUNTER_LOCK`.)
static SLOW_PATH_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Drain loopback datagrams until `quiet` of silence after the first arrival
/// (or `deadline`): returns how many arrived. Shared by the burst phases
/// below so both count deliveries the same way — one delivery, then quiet,
/// proves nothing else is coming.
async fn recv_loopback_burst(
    socks: [&tokio::net::UdpSocket; 2],
    deadline: Duration,
    quiet: Duration,
) -> u32 {
    let mut delivered = 0u32;
    let mut buf = [0u8; 2048];
    let mut last_at: Option<tokio::time::Instant> = None;
    let deadline = tokio::time::Instant::now() + deadline;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        if let Some(t) = last_at
            && delivered > 0
            && now - t >= quiet
        {
            break;
        }
        let mut got = false;
        for s in socks {
            if s.try_recv(&mut buf).is_ok() {
                delivered += 1;
                got = true;
            }
        }
        if got {
            last_at = Some(tokio::time::Instant::now());
        } else {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    delivered
}

/// L2 DNS single-flight burst delivery (server egress).
///
/// A same-host cold burst must deliver every datagram. The first miss spawns
/// a waiter, every follower spawns its own waiter, and moka coalesces all of
/// them into one upstream query; each waiter delivers its own payload once
/// the resolution completes. No queue, no in-flight probe, no drop between
/// the two. Phase 1 drives a 33-burst at a cold name (the spawning miss plus
/// 32 followers); phase 2 re-sends 40 at the now-warm name. Both phases must
/// land 100% of their datagrams on the loopback sockets with zero
/// budget/policy counters moving.
///
/// `localhost` resolves via the hosts file (no network), and the ephemeral
/// port keeps the `(host, port)` cache key cold: no other test can have
/// seeded or resolved it. The limiter premise is asserted, never drained:
/// each waiter holds one permit while it waits, so the burst needs budget
/// available. Follower *disposition* (inline from a warm memo vs.
/// spawn-delivered) is deliberately not pinned: the resolution runs on
/// another task's thread, so a follower whose thread happens to carry the
/// memo hit is served inline, and both shapes deliver exactly once — the
/// socket count below is the contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_dns_singleflight_burst_delivers_server() {
    let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().await;
    let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("loopback binds");
    let port = v4.local_addr().expect("loopback has a port").port();
    // `lookup_host("localhost")` may answer ::1 first and the spawned task
    // delivers to the first usable address, so both families listen on the
    // same port (distinct addresses, distinct families: no bind conflict).
    let v6 = tokio::net::UdpSocket::bind(format!("[::1]:{port}"))
        .await
        .expect("v6 loopback binds");
    let host = "localhost";
    assert_eq!(
        lookup_cached_fast_with_ttl(host, port).0,
        CachedLookup::Unknown,
        "premise: the (host, port) key is cold"
    );
    assert!(
        dns_slow_path_limiter().available_permits() > 0,
        "premise: the slow-path budget is available"
    );

    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new());
    let target = TargetAddr::Domain(host.to_owned(), port);
    let addr = target.as_ref();
    let payload = Bytes::from_static(b"l2-burst");

    let before = dgram_drops::snapshot();
    // Datagrams 1..33: the first miss spawns the resolving waiter, every
    // follower spawns its own; all return None inline (the spawned tasks own
    // delivery).
    for _ in 0..33 {
        let r = forward_server_dgram(&ss, &server_conn, 0, 11, addr, payload.clone(), true).await;
        assert!(
            r.is_none(),
            "a spawned-miss datagram delivers inline nothing; its task owns it"
        );
    }
    // Every waiter delivers once the (single) resolution completes; the quiet
    // period proves nothing else arrives.
    let delivered = recv_loopback_burst(
        [&v4, &v6],
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .await;
    let d = dgram_drops::snapshot().since(&before);
    assert!(
        delivered == 33,
        "L2 burst delivery (server slow path): delivered={delivered}/33 \
         dns_budget_delta={} session_full_delta={} refused_delta={} (want 33/0/0/0)",
        d.dns_budget,
        d.session_full,
        d.refused,
    );
    assert_eq!(d.session_full, 0, "budget was available throughout");
    assert_eq!(d.dns_budget, 0, "budget was available throughout");
    assert_eq!(d.refused, 0, "localhost is not a policy refusal");
    // The cold burst warmed the shared cache; a 40-burst at the warm name
    // delivers 40/40 with zero slow-path counts (spawn or inline, whichever
    // the checker thread observes).
    let before2 = dgram_drops::snapshot();
    for _ in 0..40 {
        let _ = forward_server_dgram(&ss, &server_conn, 0, 12, addr, payload.clone(), true).await;
    }
    let delivered2 = recv_loopback_burst(
        [&v4, &v6],
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .await;
    let d2 = dgram_drops::snapshot().since(&before2);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
    assert!(
        delivered2 == 40 && d2.dns_budget == 0 && d2.session_full == 0 && d2.refused == 0,
        "warm 40-burst: delivered={delivered2}/40 dns_budget_delta={} \
         session_full_delta={} refused_delta={} (want 40/0/0/0)",
        d2.dns_budget,
        d2.session_full,
        d2.refused,
    );
}

/// Slow-path budget lock, server `DNS_BUDGET` arm: an uncached name with
/// the 1024-permit budget exhausted counts the refused datagram exactly once
/// on `DNS_BUDGET` — no spawn, no resolution, no other counter moves, and
/// `session_full` stays at zero (the resolver's pool is not the session
/// budget).
#[tokio::test]
async fn forward_limiter_exhaustion_counts_dns_budget_exactly_once() {
    let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().await;
    let (host, port) = ("dnsbudget.invalid", 19713u16);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the name is uncached"
    );
    // Drain the slow-path budget the way a miss storm does. No other server
    // test holds this limiter while this lock is held, and nothing is awaited
    // while drained.
    let lim = dns_slow_path_limiter();
    let mut held = Vec::new();
    while lim.available_permits() > 0 {
        match lim.clone().try_acquire_owned() {
            Ok(p) => held.push(p),
            Err(_) => break,
        }
    }
    assert_eq!(lim.available_permits(), 0, "the budget must be exhaustible");
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new());
    let target = TargetAddr::Domain(host.to_owned(), port);
    let addr = target.as_ref();
    let before = dgram_drops::snapshot();
    let r = forward_server_dgram(
        &ss,
        &server_conn,
        0,
        63,
        addr,
        Bytes::from_static(b"q"),
        true,
    )
    .await;
    assert!(
        r.is_none(),
        "a budget-exhausted datagram delivers nothing, never relays"
    );
    let d = dgram_drops::snapshot().since(&before);
    drop(held);
    assert!(
        lim.available_permits() > 0,
        "the budget must recover when permits release"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
    assert_eq!(
        d.dns_budget, 1,
        "one exhausted datagram counts exactly once"
    );
    assert_eq!(
        d.session_full, 0,
        "the resolver's permit pool is not the session budget: charging its \
         exhaustion to `session_full` reported a slow upstream as a full host"
    );
    assert_eq!(d.refused, 0, "budget loss is not policy refusal");
}

/// Reply-path batching: one BATCH frame carries every staged small reply,
/// in staging order, with the session id and the shared source address.
///
/// This is the reply-path twin of the client association's 2-pack, driven
/// directly against a live loopback pair so the wire format is what is
/// asserted — one `0x06` frame the client dispatcher already decodes into
/// per-association replies, not N `0x02` frames.
#[tokio::test]
async fn reply_batch_frame_carries_every_staged_reply_in_order() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let mut staged = vec![
        Bytes::from_static(b"first"),
        Bytes::from_static(b"second-reply"),
        Bytes::from_static(b"third"),
    ];
    let mut staged_src = Some("198.51.100.9:4242".parse::<SocketAddr>().unwrap());
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;

    flush_reply_batch(
        &server_conn,
        7,
        &mut frag,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );
    assert!(
        staged.is_empty() && staged_src.is_none(),
        "a flush must drain the queue and its source, never park them"
    );

    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the batch frame must arrive")
        .unwrap();
    assert!(
        is_batch(&d),
        "staged small replies must ride one BATCH frame"
    );
    let b = decode_batch_ref(&d).expect("the frame must decode as a batch");
    assert_eq!(b.sess, 7, "the session id must survive the batch frame");
    let payloads: Vec<&[u8]> = b.payloads;
    assert_eq!(
        payloads,
        vec![
            b"first".as_slice(),
            b"second-reply".as_slice(),
            b"third".as_slice()
        ],
        "a batch must preserve reply order exactly"
    );
    match b.addr {
        TargetAddrRef::Ip(a) => assert_eq!(a.port(), 4242, "the shared reply source address"),
        other => panic!("an IP target reply must stay IP-form: {other:?}"),
    }
    // Exactly one frame for three replies: a duplicate single 0x02 frame per
    // reply (a half-wired staging loop) leaves this probe firing, which the
    // payload assertions above cannot see.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), client_conn.read_datagram())
            .await
            .is_err(),
        "three staged replies must produce exactly one frame, not one plus extras"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A batch frame that does not fit the path must not take its replies down
/// with it: every reply goes out as its own `0x02` frame, in order, and each
/// keeps its own accounting. Without the fallback a shrunken DATAGRAM budget
/// would lose N replies that would each have fit.
#[tokio::test]
async fn reply_batch_falls_back_to_per_reply_frames_when_it_cannot_fit() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let replies: Vec<Bytes> = vec![
        Bytes::from(vec![0xA1; 100]),
        Bytes::from(vec![0xB2; 100]),
        Bytes::from(vec![0xC3; 100]),
    ];
    let mut staged = replies.clone();
    let mut staged_src = Some("198.51.100.9:4242".parse::<SocketAddr>().unwrap());
    // Each single frame is 5 + 7 + 100 = 112 B; the batch needs
    // 5 + 7 + 1 + 3 x (2 + 100) = 321 B, so this budget admits the replies
    // and refuses the frame — the exact shape the fallback exists for.
    let mut limit = 300usize;
    let mut last_probe = 0u64;

    flush_reply_batch(
        &server_conn,
        9,
        &mut frag,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );
    assert!(staged.is_empty(), "the fallback must still drain the queue");

    for (i, want) in replies.iter().enumerate() {
        let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
            .await
            .unwrap_or_else(|_| panic!("reply {i} must arrive"))
            .unwrap();
        assert_eq!(
            d.first(),
            Some(&MQP_DGRAM_TYPE),
            "a fallback reply must be a single 0x02 frame, got {d:02x?}"
        );
        let (_, _, p) = decode_datagram_ref(&d).expect("a fallback frame must decode");
        assert_eq!(
            p,
            want.as_ref(),
            "fallback reply {i} must be byte-identical"
        );
    }
    // Three replies and no more: a fourth frame would mean the fallback
    // double-sent (or a batch frame tagged along), which the per-frame
    // assertions above cannot see.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), client_conn.read_datagram())
            .await
            .is_err(),
        "the fallback must send exactly one frame per reply, never a duplicate"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Distinct target sources must not share one batch frame, and a run's flush
/// must complete before the next run's replies are sent: two flushes produce
/// two frames in source order, each carrying only its own replies. A
/// half-wired source check merges them into one frame whose address belongs
/// to neither (or both) sources — a silent mis-route of the reply's source
/// address, which the payload bytes alone would not reveal.
#[tokio::test]
async fn distinct_source_runs_flush_in_order_as_separate_frames() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let src_a: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let src_b: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;

    let mut staged = vec![Bytes::from_static(b"a-1"), Bytes::from_static(b"a-2")];
    let mut staged_src = Some(src_a);
    flush_reply_batch(
        &server_conn,
        11,
        &mut frag,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );

    let mut staged = vec![Bytes::from_static(b"b-1"), Bytes::from_static(b"b-2")];
    let mut staged_src = Some(src_b);
    flush_reply_batch(
        &server_conn,
        11,
        &mut frag,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );

    let d1 = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the first run's frame must arrive first")
        .unwrap();
    let b1 = decode_batch_ref(&d1).expect("the first frame must decode");
    assert_eq!(b1.payloads, vec![b"a-1".as_slice(), b"a-2".as_slice()]);
    match b1.addr {
        TargetAddrRef::Ip(a) => assert_eq!(a, src_a, "the first frame must name source A"),
        other => panic!("an IP target reply must stay IP-form: {other:?}"),
    }

    let d2 = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the second run's frame must arrive")
        .unwrap();
    let b2 = decode_batch_ref(&d2).expect("the second frame must decode");
    assert_eq!(b2.payloads, vec![b"b-1".as_slice(), b"b-2".as_slice()]);
    match b2.addr {
        TargetAddrRef::Ip(a) => assert_eq!(a, src_b, "the second frame must name source B"),
        other => panic!("an IP target reply must stay IP-form: {other:?}"),
    }
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}
