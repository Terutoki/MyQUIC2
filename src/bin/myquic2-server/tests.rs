//! Server unit tests (moved verbatim from the single-file bin).
use super::*;
use myquic2::mqp::ctl_stream;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{
    CTL_MAX_PER_SEC, FlowBinding, FlowState, R2_MAX_RESOLVED_ADDRS, RegistryError, SessionFlows,
    SourceMatch,
};
use myquic2::mqp::r3::CtlMessage;
use myquic2::mqp::wire::{self, Wire};
use myquic2::udp::{R2Fragmenter, R2Reassembler, R2StageItem, R2StageKind, R2Stager};

/// Serializes the tests that mutate the process-global session-holder
/// count, so their exact reads cannot race each other.
///
/// Four tests touch the counter: the two exact-delta holder tests
/// (`fair_share_counts_session_holders_not_live_connections`,
/// `session_churn_holds_caps_without_leaking`),
/// `l2_dns_burst_coalesces_to_one_waiter_per_session`, whose burst runs
/// `forward_server_dgram` through the real `get_or_create_sess` creation
/// path, and the full-cone e2e helper above `full_cone_forwards_unsolicited_reply_source`
/// (it runs a real connection through `handle_conn`, which creates and reaps a
/// session-holder table) — each registers its own table as a holder and
/// releases it only when the connection closes, so without this lock a
/// concurrent run could observe two holders for a one-table delta. The count is
/// process-global, so every test that can make a table non-empty must serialize
/// here.
static HOLDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire [`HOLDER_TEST_LOCK`], recovering from poisoning. The lock guards
/// only this serialization, not any data under it, so one holder's panic
/// must not turn every later holder's exact read into a spurious
/// `PoisonError` failure of its own — the panicking test has already failed
/// the suite on its own.
fn holder_test_guard() -> std::sync::MutexGuard<'static, ()> {
    HOLDER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Serializes the tests that drain or assert on the process-global
/// [`header_task_limiter`]. One test holds all [`HEADER_TASK_CREDIT`] permits
/// to drive the exhausted-credit path; a parallel test's
/// `try_acquire_owned().unwrap()` would panic if the drain were concurrent.
static HEADER_CREDIT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Acquire [`HEADER_CREDIT_TEST_LOCK`] for the header-stage credit tests.
async fn header_credit_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    HEADER_CREDIT_TEST_LOCK.lock().await
}

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
    let sock = memo_sock();
    (sess_with_sock(addr, sock.clone()), sock)
}

/// [`sess_with_dest`] with a caller-chosen session socket.
///
/// Session 7's entry is inserted directly (no `note_empty_state`, no holder
/// transition), so tests using it never disturb the process-global holder count
/// that `HOLDER_TEST_LOCK` keeps exact for the tests that assert on it. The
/// socket is a parameter because the relay sends to `map_for_dual(dst)`:
/// reaching a v4 target needs the dual-stack socket production sessions use,
/// while the DNS memo tests only need any bound socket.
fn sess_with_sock(addr: Option<SocketAddr>, sock: Arc<tokio::net::UdpSocket>) -> SessTable {
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let last = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let h = tokio::spawn(std::future::pending::<()>());
    let permit = session_limiter().clone().try_acquire_owned().unwrap();
    ss.shard(7).write().insert(
        7,
        SessEntry {
            sess: 7,
            sock,
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
            flows: Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default())),
            r2_flows: Arc::new(arc_swap::ArcSwap::from_pointee(SessionFlows::new())),
        },
    );
    // Direct insert (not `get_or_create_sess`): keep the table's live count in
    // step so `note_empty_state`/`drain_all` see this session in tests that
    // assert on the fair-share holder denominator.
    ss.note_live_insert();
    ss
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
    let expires = || ss.shard(7).read().get(&7).unwrap().dest.expires;

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
    ss.shard(7).write().get_mut(&7).unwrap().dest.expires = mono_millis() + 1;
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

/// Every name the wire can carry must be memoizable; only a name longer than
/// the `u8` length prefix can (255 bytes) may be refused, and it must be
/// refused rather than truncated — storing a prefix would let a different name
/// sharing it match.
///
/// The key used to be 64 bytes, so every name in 65..=255 was silently never
/// memoized: `forward_server_dgram` could not return `Some`, the connection
/// fast table never armed, and each datagram of such a flow re-entered the
/// spawned-resolver path forever. The 65..255 range is real (long service
/// names, DNS-SD-ish labels), not a corner case.
#[tokio::test]
async fn session_dest_memo_stores_every_wire_legal_name() {
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let (ss, _sock) = sess_with_dest(None);

    // The bound is the wire maximum, not a compromise: `host_len` is a `u8`
    // length prefix, so 255 must fit exactly.
    assert_eq!(
        DEST_KEY_BYTES, 255,
        "the inline key must cover the MQP-2 wire maximum (u8 length prefix)"
    );
    let longest = "x".repeat(DEST_KEY_BYTES);
    assert!(
        PortKey::new(&longest, 443).is_some(),
        "a 255-byte name is the wire maximum and must key"
    );
    sess_dest_store(&ss, 7, &longest, 443, dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, &longest, 443),
        Some(dst),
        "the wire-max name must be memoized and matched"
    );

    // A 100-byte name — deep inside the range the old 64-byte key refused —
    // stores and matches, and a prefix of it does not (the key is exact).
    let mid = "m".repeat(100);
    let mid_dst: SocketAddr = "10.0.0.2:443".parse().unwrap();
    sess_dest_store(&ss, 7, &mid, 443, mid_dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, &mid, 443),
        Some(mid_dst)
    );
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, &mid[..mid.len() - 1], 443),
        None,
        "a name sharing the stored prefix must not match"
    );

    // One byte past the wire maximum: `PortKey::new` refuses it (never
    // truncates), so the store is a no-op and the lookup misses.
    let over = "x".repeat(DEST_KEY_BYTES + 1);
    assert!(
        PortKey::new(&over, 443).is_none(),
        "a name longer than the wire maximum must not key"
    );
    let over_dst: SocketAddr = "10.0.0.3:443".parse().unwrap();
    sess_dest_store(&ss, 7, &over, 443, over_dst, DNS_CACHE_TTL_MS);
    assert_eq!(sess_dest_lookup(&ss, mono_millis(), 7, &over, 443), None);
    // ...and the stored 255-byte prefix is untouched by that refused store.
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, &longest, 443),
        None,
        "the previous store (mid) still owns the memo; over-length must not write"
    );
    sess_dest_store(&ss, 7, &longest, 443, dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        sess_dest_lookup(&ss, mono_millis(), 7, &longest, 443),
        Some(dst),
        "the wire-max name still round-trips"
    );
}

/// Storing into a session that no longer exists is a no-op, not a panic or a
/// phantom entry: the datagram path races session teardown by design.
#[tokio::test]
async fn session_dest_store_tolerates_a_vanished_session() {
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
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
    // allow_private callers still get the first record straight from the memo.
    // Checked *before* the slow-path probe below, which warms this thread's
    // per-(host, port) memo with the port-attached set it returns and would
    // overwrite the seeded verbatim address.
    assert_eq!(
        resolve_pin(&ss, &mut pin, 7, 7, host, port, true),
        Some(private),
        "allow_private must still serve the first record"
    );
    // The slow path's data source: the full set, with a usable record. The
    // shared positive cache is keyed by the normalized **host** and stores
    // port-free IPs (a port change of one name must hit the same entry, and a
    // cached A/AAAA record carries no port), so the caller's port is attached
    // when the set is returned — the seeded `:443` records come back on the
    // queried port. The set's IPs and order are what the slow path picks from.
    let full = resolve_all_cached(host, port).await.expect("cached set");
    let want = [
        SocketAddr::new(private.ip(), port),
        SocketAddr::new(public.ip(), port),
    ];
    assert_eq!(&full[..], &want);
    assert!(
        full.iter().any(|a| is_global_ip(a.ip())),
        "the set the slow path picks from must contain an allowed address"
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
    let last = ss.shard(7).read().get(&7).unwrap().last.clone();
    // A sweep that starts well past the session's idle deadline.
    let now = last.load(std::sync::atomic::Ordering::Relaxed) + SESS_IDLE_MS + 10_000;

    // Phase 1: the read-locked snapshot.
    let keys: Vec<u32> = ss
        .shard(7)
        .read()
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
        let mut w = ss.shard(7).write();
        take_idle(&mut w, &keys, now)
    };
    assert!(
        evicted.is_empty(),
        "a session touched after the snapshot must survive"
    );
    assert!(ss.shard(7).read().contains_key(&7));
}

/// A reader that stays alive (`SessHit::Fresh` requires a running task).
fn live_reader() -> tokio::task::AbortHandle {
    let h = tokio::spawn(std::future::pending::<()>());
    let abort = h.abort_handle();
    drop(h);
    abort
}

/// One over-cap session in a scratch shard, stamped `idle_ms` ago and filed
/// under `sess` (the entry now carries its own id for the reap-path
/// `SESS_CLOSE` notification; the fixtures only read it back through the
/// table, so callers pass the key they insert under).
fn capped_session(sess: u32, idle_ms: u64) -> SessEntry {
    SessEntry {
        sess,
        sock: memo_sock(),
        reader: tokio::spawn(std::future::pending::<()>()),
        last: Arc::new(std::sync::atomic::AtomicU64::new(
            mono_millis().saturating_sub(idle_ms),
        )),
        _permit: session_limiter().clone().try_acquire_owned().unwrap(),
        dest: DestMemo::NONE,
        recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
        recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        flows: Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default())),
        r2_flows: Arc::new(arc_swap::ArcSwap::from_pointee(SessionFlows::new())),
    }
}

/// Whether `s`'s reply allowlist currently admits `dst`.
fn allowlist_contains(ss: &SessTable, s: u32, dst: SocketAddr) -> bool {
    let sh = ss.shard(s).read();
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
/// Pinned at the level the defect lived: arm two sessions, then require a hit
/// (and the allowlist record the fast path owes) from each, and a miss for a
/// session that was never armed — the table is a cache, never a router.
#[tokio::test]
async fn two_sessions_on_one_connection_both_hit_the_fast_table() {
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let conn_id = next_conn_id();
    let mut fast = FastTable::new();
    let mut staged: Vec<StagedSend> = Vec::with_capacity(LAST_HOP_DRAIN);
    let dst: SocketAddr = "198.51.100.7:53".parse().unwrap();

    let (s1, s2) = (1u32, 2u32);
    // Held for the test's life: the fast path's socket liveness is a `Weak`
    // upgrade, so the table entry must be the socket's live owner.
    let mut socks = Vec::new();
    for s in [s1, s2] {
        let entry = capped_session(s, 0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(s).write().insert(s, entry);
        ss.note_live_insert();
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
        assert!(fast.probe(s).is_some(), "arm must publish session {s}");
    }
    assert_eq!(fast.len(), 2, "two sessions, two entries");

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

    // Never armed: must miss.
    let never = 99u32;
    assert!(fast.probe(never).is_none(), "premise: not armed");
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            never,
            dst,
            Bytes::from_static(b"x"),
            true,
            &mut staged
        )
        .is_err(),
        "an unarmed session must fall through to the slow path"
    );

    // The case that actually pins "a cache, never a router": a live session
    // with a published session-table entry and an upgradable socket of its own,
    // whose datagram arrives before anything armed it. Staging it could only
    // come from another session's slot, and that would send this session's
    // payload to the wrong target.
    let live = s1 + FAST_SESS_SLOTS as u32;
    {
        let entry = capped_session(live, 0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(live).write().insert(live, entry);
        ss.note_live_insert();
        sess_memo_put(conn_id, live, sock.clone(), last, abort, epoch);
        socks.push(sock);
    }
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            live,
            dst,
            Bytes::from_static(b"x"),
            true,
            &mut staged
        )
        .is_err(),
        "an unarmed live session must miss its way to the slow path, never \
         borrow another session's slot"
    );
    assert!(staged.is_empty(), "a miss must not stage anything");
}

/// A full table must evict the **quietest** session: never grow, never
/// mis-route.
///
/// Session ids are monotonic and never reused, so nothing else reclaims a slot:
/// without an eviction order the table would simply stop admitting new
/// sessions once full. The order is the session's own liveness stamp, advanced
/// on a hit — a reaped or idle session stops advancing it and ages out, which
/// is also why the arm scan no longer has to look for dead entries (two
/// atomics per slot) and now only reads the tag and stamp arrays.
#[tokio::test]
async fn a_full_table_evicts_the_quietest_session() {
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let conn_id = next_conn_id();
    let mut fast = FastTable::new();
    let mut staged: Vec<StagedSend> = Vec::with_capacity(LAST_HOP_DRAIN);
    let dst: SocketAddr = "198.51.100.11:53".parse().unwrap();

    let mut socks = Vec::new();
    // The quiet session is stamped a minute ago; every other session is fresh.
    let quiet = 5u32;
    let fresh: Vec<u32> = (0..FAST_SESS_SLOTS as u32 - 1).map(|i| 1_000 + i).collect();
    for (s, idle) in std::iter::once((quiet, 60_000u64)).chain(fresh.iter().map(|&s| (s, 0u64))) {
        let entry = capped_session(s, idle);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(s).write().insert(s, entry);
        ss.note_live_insert();
        sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
        socks.push(sock);
        arm_fast(
            &mut fast,
            conn_id,
            s,
            TargetAddrRef::Ip(dst),
            dst,
            DNS_CACHE_TTL_MS,
        );
    }
    assert_eq!(fast.len(), FAST_SESS_SLOTS, "premise: the table is full");
    assert!(
        fast.probe(quiet).is_some(),
        "premise: the quiet session is armed"
    );

    // One more session: the table has no free slot, so this arm can only evict.
    let newcomer = 9_000u32;
    {
        let entry = capped_session(newcomer, 0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(newcomer).write().insert(newcomer, entry);
        ss.note_live_insert();
        sess_memo_put(conn_id, newcomer, sock.clone(), last, abort, epoch);
        socks.push(sock);
    }
    arm_fast(
        &mut fast,
        conn_id,
        newcomer,
        TargetAddrRef::Ip(dst),
        dst,
        DNS_CACHE_TTL_MS,
    );

    assert_eq!(fast.len(), FAST_SESS_SLOTS, "a full table never grows");
    assert!(
        fast.probe(quiet).is_none(),
        "the quietest session must lose its slot"
    );
    assert!(
        fast.probe(newcomer).is_some(),
        "the session that just armed must be present"
    );
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            newcomer,
            dst,
            Bytes::from_static(b"fast"),
            true,
            &mut staged
        )
        .is_ok(),
        "the newly armed session must hit"
    );
    staged.clear();
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            quiet,
            dst,
            Bytes::from_static(b"fast"),
            true,
            &mut staged
        )
        .is_err(),
        "the evicted session must take the slow path, not a stale slot"
    );
}

/// Sparse session ids must all hit, and a table over capacity must evict rather
/// than grow.
///
/// The client allocates session ids from a monotonic counter and never reuses
/// them, so on a long-lived connection the live ids are a *sparse* subset of the
/// id space rather than a dense `1..=N` interval. A sparse-id fixture is also
/// the only shape that catches a probe keyed on anything but the exact id.
#[tokio::test]
async fn sparse_session_ids_both_hit_and_a_full_table_never_grows() {
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let conn_id = next_conn_id();
    let mut fast = FastTable::new();
    let mut staged: Vec<StagedSend> = Vec::with_capacity(LAST_HOP_DRAIN);
    let dst: SocketAddr = "198.51.100.7:53".parse().unwrap();

    // Ids from a counter that has run for a while, a full table apart.
    let base = 1_001u32;
    let step = FAST_SESS_SLOTS as u32;
    let (s1, s2, s3) = (base + 1, base + step, base + 2 * step);

    let mut socks = Vec::new();
    for s in [s1, s2, s3] {
        let entry = capped_session(s, 0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(s).write().insert(s, entry);
        ss.note_live_insert();
        sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
        socks.push(sock);
    }
    for s in [s1, s2, s3] {
        arm_fast(
            &mut fast,
            conn_id,
            s,
            TargetAddrRef::Ip(dst),
            dst,
            DNS_CACHE_TTL_MS,
        );
    }
    // Re-arming an already armed session must update its own slot in place,
    // never append a second copy.
    let i3 = fast.probe(s3).expect("s3 must be armed");
    arm_fast(
        &mut fast,
        conn_id,
        s3,
        TargetAddrRef::Ip(dst),
        dst,
        DNS_CACHE_TTL_MS,
    );
    assert_eq!(
        fast.probe(s3),
        Some(i3),
        "a re-arm must keep the session's own slot"
    );
    assert_eq!(fast.len(), 3, "a re-arm must not duplicate the entry");
    for s in [s1, s2, s3] {
        assert!(
            try_stage(
                &mut fast,
                &ss,
                conn_id,
                s,
                dst,
                Bytes::from_static(b"fast"),
                true,
                &mut staged
            )
            .is_ok(),
            "sparse session {s} must hit its slot"
        );
        staged.clear();
    }

    // Over capacity: `FAST_SESS_SLOTS + 1` new live sessions. The table is a
    // fixed array, so the last arm must evict rather than grow; the session it
    // just armed is still present (nothing runs after it) and hits.
    let mut overflow = Vec::new();
    for i in 0..(FAST_SESS_SLOTS as u32 + 1) {
        let s = 5000 + i;
        let entry = capped_session(s, 0);
        let sock = entry.sock.clone();
        let last = entry.last.clone();
        let epoch = entry.recent_epoch.clone();
        let abort = entry.reader.abort_handle();
        ss.shard(s).write().insert(s, entry);
        ss.note_live_insert();
        sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
        overflow.push((s, sock));
    }
    for (s, _) in &overflow {
        arm_fast(
            &mut fast,
            conn_id,
            *s,
            TargetAddrRef::Ip(dst),
            dst,
            DNS_CACHE_TTL_MS,
        );
    }
    assert_eq!(fast.len(), FAST_SESS_SLOTS, "the table is fixed-size");
    let (last_s, _) = overflow.last().expect("overflow fixture is non-empty");
    assert!(
        try_stage(
            &mut fast,
            &ss,
            conn_id,
            *last_s,
            dst,
            Bytes::from_static(b"fast"),
            true,
            &mut staged
        )
        .is_ok(),
        "the most recently armed session must still hit after the eviction"
    );
    socks.extend(overflow.into_iter().map(|(_, sock)| sock));
}

/// A BATCH (0x06) ingress frame must arm the connection fast table.
///
/// Both BATCH arms used to `let _ = forward_server_dgram(...)`, discarding the
/// `Some((dst, life))` that [`arm_fast`] needs. The one ingress shape built for
/// bursty small-packet flows therefore never installed the fast slot, so every
/// payload of every BATCH frame re-ran the whole slow path (session memo probe,
/// shard read lock, unbatched target send) forever — the `+8.8%` server CPU per
/// datagram the fast table exists to remove.
///
/// The payloads are delivered with or without the fix, so only the test-only
/// `BATCH_FAST_ARMS` counter can tell the fixed path from the buggy one. One
/// frame with two payloads is enough: the first payload takes the slow path and
/// arms the slot, the second then hits the fast path — so the expected delta is
/// exactly 1, and a second increment would mean the slot was not armed.
///
/// The session this creates makes the table a process-wide holder, so the test
/// serializes on [`HOLDER_TEST_LOCK`] and waits for the connection-close sweeper
/// to drain it before releasing, leaving the exact holder count untouched.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn batch_ingress_arms_the_connection_fast_table() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client_conn, server_conn) = stream_test_pair().await;
    // Loopback target: `allow_private = true` passes the SSRF gate, and a v4 IP
    // target needs no DNS, so the slow path's first answer is inline.
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let limit = client_conn
        .max_datagram_size()
        .expect("DATAGRAM is negotiated by the test transport");
    let addr = TargetAddr::Ip(dst);
    let payloads: [&[u8]; 2] = [b"batch-1", b"batch-2"];
    let frame = encode_batch(1, &addr.as_ref(), &payloads, limit).expect("encode one BATCH frame");

    let server_task = tokio::spawn(handle_conn(
        server_conn,
        true,
        ReplyFilter::Restricted,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));
    let arms_before = BATCH_FAST_ARMS.load(Ordering::Relaxed);
    client_conn.send_datagram(frame).unwrap();

    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    for _ in &payloads {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("every payload of the BATCH frame must be relayed")
            .unwrap();
        got.push(buf[..n].to_vec());
    }
    // Delivery, not wire order: the session socket is fresh, and tokio may
    // report `WouldBlock` on its first send without issuing the syscall
    // (`udp_try_send`'s retry-pool note), so either payload can be delivered by
    // a detached retry task and the two can invert. The BATCH frame's *staging*
    // order is pinned on the reply side by
    // `reply_batch_frame_carries_every_staged_reply_in_order`.
    got.sort();
    assert_eq!(
        got,
        vec![b"batch-1".to_vec(), b"batch-2".to_vec()],
        "every payload of the BATCH frame must be relayed"
    );

    // The arm happens after the slow path's send, so poll rather than race the
    // target's receive: the assertion is about "the batch arm reached
    // `arm_fast`", not about the instant it did.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let arms = loop {
        let now = BATCH_FAST_ARMS.load(Ordering::Relaxed) - arms_before;
        if now >= 1 || tokio::time::Instant::now() >= deadline {
            break now;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(
        arms, 1,
        "the BATCH arm must arm the fast table exactly once: the first payload \
         takes the slow path, the second must then hit the newly armed slot"
    );

    client_conn.close(0u32.into(), b"done");
    server_task.abort();
    // The connection-close sweeper drains the session; wait for the holder
    // count to come back so this test leaves the process-global counter exactly
    // where it found it (the [`HOLDER_TEST_LOCK`] contract).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_holders().load(Ordering::Relaxed) != holders_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session holder count must return after the connection closes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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
    let epoch = ss.shard(7).read().get(&7).unwrap().recent_epoch.clone();
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

/// The allowlist epoch must move only when a push actually publishes a new
/// snapshot.
///
/// `sess_reader_task` gates its `ArcSwap` reload on this epoch: a bump it can
/// see costs the reply reader a `load_full` (hazard pointer + refcount RMW) on
/// its next reply. The datagram path calls `remember_dst` for every slow-path
/// packet, and for a steady single-target flow that call finds the destination
/// already in the ring and publishes nothing — so an unconditional bump was
/// pure cross-task cache-line traffic per packet, on exactly the flows the
/// mirror is meant to make cheap.
#[tokio::test]
async fn remember_dst_bumps_the_epoch_only_on_a_real_push() {
    use std::sync::atomic::Ordering;

    let (ss, _sock) = sess_with_dest(None);
    let epoch = ss.shard(7).read().get(&7).unwrap().recent_epoch.clone();
    let a: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let a_other_port: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
    assert_eq!(epoch.load(Ordering::Relaxed), 0);

    remember_dst(&ss, 7, a);
    assert_eq!(
        epoch.load(Ordering::Relaxed),
        1,
        "a real push publishes a snapshot and must move the epoch"
    );

    // Steady flow: the destination is already in the ring, so the fast exit
    // publishes nothing and must not move the epoch.
    for _ in 0..8 {
        remember_dst(&ss, 7, a);
    }
    assert_eq!(
        epoch.load(Ordering::Relaxed),
        1,
        "a repeat destination must not bump: that forced the reply reader to \
         reload its snapshot for every reply"
    );
    // The ring is IP-keyed, so a different port on a known host publishes
    // nothing either.
    remember_dst(&ss, 7, a_other_port);
    assert_eq!(epoch.load(Ordering::Relaxed), 1);

    // A new destination is a real change and must invalidate the mirror.
    remember_dst(&ss, 7, b);
    assert_eq!(
        epoch.load(Ordering::Relaxed),
        2,
        "a new destination must bump the epoch"
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
    let _holder_guard = holder_test_guard();
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
    let empty = ShardedSessTable::new(ReplyFilter::Restricted);
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
    let ss = ShardedSessTable::new(ReplyFilter::Restricted);
    let now = mono_millis();
    // The first call measures and caches: nothing is held yet.
    assert_eq!(ss.len_upper_bound(now), 0);

    // One connection's burst of new sessions, all inside the sample window.
    for s in 0..8u32 {
        ss.shard(s).write().insert(s, capped_session(s, 0));
        ss.note_insert();
        ss.note_live_insert();
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
    let ss = ShardedSessTable::new(ReplyFilter::Restricted);
    let now = mono_millis();
    assert_eq!(ss.len_upper_bound(now), 0);
    ss.shard(7).write().insert(7, capped_session(7, 0));
    ss.note_live_insert();
    ss.shard(7).write().remove(&7);
    ss.note_live_remove(1);
    assert_eq!(
        ss.len_upper_bound(now),
        0,
        "a rolled-back insert must not inflate the fair-share bound"
    );
    ss.shard(7).write().insert(7, capped_session(7, 0));
    ss.note_insert();
    ss.note_live_insert();
    assert_eq!(ss.len_upper_bound(now), 1);
    ss.shard(7).write().remove(&7);
    ss.note_live_remove(1);
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
        m.insert(k, capped_session(k, 1));
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
    m.insert(1, capped_session(1, 1));
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
    m.insert(1, capped_session(1, 1));
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
/// windows has to admit fewer connections, the process-wide fixed terms (UDP
/// session pool + ingress endpoint buffers + relay pump buffers + retry pool +
/// DNS waiters + worker scratch + quinn stream-reassembly metadata) have to be
/// charged against the budget exactly once (none of it is per connection), a
/// budget too small for one connection still admits one (so the endpoint is
/// diagnosable), and no configuration may exceed the hard connection cap.
#[test]
fn admission_cap_bounds_connections_by_memory() {
    let per_conn = per_connection_memory_bytes(&TransportTuning::default());
    let stager = myquic2::udp::r2_stage::R2_STAGE_MAX_BYTES as u64
        + (myquic2::udp::r2_stage::R2_STAGE_MAX_ITEMS
            * std::mem::size_of::<myquic2::udp::r2_stage::R2StageItem>()
            * myquic2::config::tuning::R2_STAGER_SLOT_FACTOR) as u64;
    let registry = myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_CONN as u64
        * (std::mem::size_of::<myquic2::mqp::r2_flow::FlowBinding>() as u64
            + myquic2::config::tuning::R2_FLOW_HEAP_SLACK_BYTES);
    assert_eq!(
        per_conn,
        14 * 1024 * 1024
            + 2 * FRAG_MAX_HELD_BYTES as u64
            + stager
            + myquic2::config::tuning::R2_INGRESS_FIXED_BYTES
            + registry
            + myquic2::pre_auth_stream_memory_bytes(),
        "4/8/4 MB windows + 2 x 1 MB packets + both reassembly budgets + rev2 stager/ingress/flow registry + the pre-auth stream-assembler credit"
    );
    let per_session = per_session_memory_bytes();
    // Linux stores and reports SO_RCVBUF/SO_SNDBUF at 2x the requested value,
    // so a session's socket cap there is 4 x `sess_socket_buf()` (both
    // directions doubled); other platforms charge the requested caps. The
    // admission formula must charge what the kernel actually pins, not what was
    // asked for — otherwise `max_peer_memory_mb` under-counts the pool by ~2x.
    let socket_terms = if cfg!(target_os = "linux") {
        2 * (2 * sess_socket_buf())
    } else {
        2 * sess_socket_buf()
    };
    assert_eq!(
        per_session,
        (socket_terms + UDP_RECV_MAX + UDP_RECV_SLACK + MQP3_FLOW_TABLE_MAX_BYTES) as u64
            + myquic2::R2_SESSION_TABLES_BYTES,
        "a session's kernel caps (doubled on Linux), its reader buffer, its MQP-3 flow table \
         (domain-target worst case) and its rev2 copy-on-write table snapshots"
    );
    let pool = session_pool_memory_bytes(MAX_SESSIONS_GLOBAL);
    assert_eq!(pool, MAX_SESSIONS_GLOBAL as u64 * per_session);
    assert!(
        pool > 512 * 1024 * 1024,
        "the session pool alone must be a term worth charging (got {pool} B)"
    );
    // The fixed term (charged once, before connections are divided out) is not
    // just the session pool any more: every QUIC ingress endpoint pins a
    // resident userspace receive buffer plus its socket caps, the whole
    // process-wide stream-task pool can hold two 16 KiB relay-pump buffers per
    // flow, the UDP retry pool and DNS waiters are peer-driven process-wide
    // pools, worker threads hold burst/session scratch, and quinn's per-stream
    // reassembly can hold up to MAX_CHUNKS gap spans for every header-parked
    // stream. None of it scales with the admitted-connection count, so all of
    // it belongs here — without the last terms `max_peer_memory_mb` understated
    // the pinnable memory by hundreds of MiB.
    let endpoint = endpoint_memory_bytes(1);
    let pump = stream_pump_memory_bytes(MAX_STREAM_TASKS);
    let retry = retry_pool_memory_bytes();
    let dns = dns_inflight_memory_bytes();
    let scratch = worker_scratch_bytes(1);
    let assembler = stream_assembler_memory_bytes(HEADER_TASK_CREDIT);
    assert!(
        endpoint >= 8 * 1024 * 1024,
        "one endpoint must charge its resident receive buffer + socket caps (got {endpoint} B)"
    );
    assert_eq!(
        pump,
        MAX_STREAM_TASKS as u64
            * (2 * 16 * 1024 + myquic2::linux::relay_tcp_kernel_bytes_per_flow()),
        "two COPY_CHUNK (16 KiB) userspace pump buffers plus the relay socket \
         kernel caps per concurrent relay flow (MEM-3)"
    );
    assert!(pump > 256 * 1024 * 1024, "pump term must be a real bound");
    assert!(retry > 32 * 1024 * 1024, "retry pool must be a real term");
    assert!(dns > 8 * 1024 * 1024, "DNS waiter term must be a real term");
    assert_eq!(assembler, HEADER_TASK_CREDIT as u64 * 1024 * 96);
    assert!(
        assembler > 256 * 1024 * 1024,
        "parked stream-assembly metadata is the largest process-wide fixed term"
    );
    let fixed = pool + endpoint + pump + retry + dns + scratch + assembler;
    assert!(fixed > pool, "endpoint + pump terms are charged on top");

    // No budget: the count cap stands, clamped to the hard cap.
    assert_eq!(
        admission_cap(MAX_CONNECTIONS, None, per_conn, fixed),
        MAX_CONNECTIONS
    );
    assert_eq!(admission_cap(1, None, per_conn, fixed), 1);

    // The budget is derived from the formula's own terms: the process-wide
    // fixed term (now ~5.6 GiB at Linux defaults: session pool + endpoint +
    // relay pump with kernel caps + assembler + retry + DNS + scratch) plus
    // room for 64 connections. A fixed literal budget (the old 4 GiB) can fall
    // below the fixed term as more real charges are discovered, which used to
    // make these division assertions vacuous.
    let budget_bytes = fixed + 64 * per_conn;
    let budget_mib = budget_bytes.div_ceil(1 << 20);
    let budget_bytes = budget_mib << 20;
    let expected = ((budget_bytes - fixed) / per_conn) as usize;
    assert_eq!(
        admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, fixed),
        expected
    );
    assert!(
        expected >= 64,
        "the derived budget must still admit a useful pool (got {expected})"
    );
    // Charging the fixed term is the whole point: without it the same budget
    // would admit `budget / per_conn` connections and pin that much *plus* the
    // session pool, endpoint buffers and relay pump buffers.
    assert!(
        admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, 0)
            > admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, fixed),
        "the fixed term must reduce the admitted count"
    );
    // The endpoint + pump terms are additional to the session pool and must
    // tighten the cap further; a formula that only charged the pool would let
    // the same budget admit more.
    assert!(
        admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, pool)
            > admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, fixed),
        "endpoint + relay-pump terms must reduce the admitted count"
    );
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
        admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn_wide, fixed)
            < admission_cap(MAX_CONNECTIONS, Some(budget_mib), per_conn, fixed),
        "the same budget must admit fewer wide-window connections"
    );
    // Count cap still wins when it is the smaller of the two.
    assert_eq!(admission_cap(8, Some(budget_mib), per_conn, fixed), 8);
    // A budget too small for even one connection admits exactly one, and a
    // budget at or below the fixed term is the same case rather than zero.
    assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), per_conn, fixed), 1);
    assert_eq!(admission_cap(MAX_CONNECTIONS, Some(1), per_conn, 0), 1);
    let fixed_mib = fixed / (1024 * 1024);
    assert_eq!(
        admission_cap(MAX_CONNECTIONS, Some(fixed_mib), per_conn, fixed),
        1,
        "a budget equal to the fixed term leaves nothing for connections"
    );
    // No division by zero for a degenerate per-connection figure: the
    // divisor floors at one byte, so the count cap still binds.
    assert_eq!(
        admission_cap(MAX_CONNECTIONS, Some(4096), 0, 0),
        MAX_CONNECTIONS
    );
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

/// Server and client QUIC configs for a loopback pair, sharing one generated
/// self-signed cert and the production transport tuning. Split out of
/// `stream_test_pair` so ingress-shape tests can build their own endpoints
/// around the same configuration.
fn loopback_tls() -> (quinn::ServerConfig, quinn::ClientConfig) {
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
    server_cfg.transport_config(build_transport(Congestion::Bbr, 5));

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
    ccfg.transport_config(build_transport(Congestion::Bbr, 5));
    (server_cfg, ccfg)
}

/// Live loopback QUIC pair driving the production transport config, so the
/// stream-admission tests below run `handle_tcp_stream` against real
/// streams instead of a mock.
async fn stream_test_pair() -> (quinn::Connection, quinn::Connection) {
    let (server_cfg, ccfg) = loopback_tls();
    let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
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

/// The `quic_endpoints` ingress shape end to end: two QUIC endpoints sharing
/// one `SO_REUSEPORT` socket group accept, handshake and carry a stream
/// exactly like a single endpoint does. Which member receives the client's
/// flow is the kernel's choice — on macOS always the most recently bound
/// member, on Linux a per-4-tuple hash; the spread behavior itself is pinned
/// in the lib tests. What this test adds is that quinn over a grouped socket
/// is a working server ingress on every member, and that a single client
/// flow lands on exactly one member (never split across two CID tables).
#[cfg(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
))]
#[tokio::test]
async fn reuseport_group_endpoints_serve_a_stream() {
    let (server_cfg, client_cfg) = loopback_tls();
    let a = udp_socket_dual_reuseport("127.0.0.1:0").expect("first group member");
    let addr = a.local_addr().expect("bound address");
    let b = udp_socket_dual_reuseport(&addr.to_string()).expect("second group member");
    let rt = Arc::new(quinn::TokioRuntime);
    let ep_a = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg.clone()),
        rt.wrap_udp_socket(a).unwrap(),
        rt.clone(),
    )
    .unwrap();
    let ep_b = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        rt.wrap_udp_socket(b).unwrap(),
        rt.clone(),
    )
    .unwrap();
    // Each member's accept path must *accept* what it receives and hold it,
    // not just observe it: quinn only starts a server handshake once the
    // application accepts the `Incoming`, and dropping the `Incoming` or the
    // `Connection` refuses/closes it — either way the client hangs or dies.
    // The member that receives the client's flow echoes its payload back, so
    // the round trip below proves it carried real stream data.
    let mut acc_a = tokio::spawn(serve_one_group_member(ep_a));
    let mut acc_b = tokio::spawn(serve_one_group_member(ep_b));

    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_cfg);
    let conn = client.connect(addr, "test.com").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"grouped ingress").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"grouped ingress");
    conn.close(0u32.into(), b"done");

    // Exactly one member accepted the connection (true = handshake completed
    // and the stream round-tripped through it) while the other keeps waiting
    // because the whole flow went to its sibling.
    let a = tokio::time::timeout(Duration::from_millis(500), &mut acc_a).await;
    let b = tokio::time::timeout(Duration::from_millis(500), &mut acc_b).await;
    let served = |r: Result<
        Result<(bool, quinn::Endpoint), tokio::task::JoinError>,
        tokio::time::error::Elapsed,
    >| { matches!(r, Ok(Ok((true, _)))) };
    assert_eq!(
        served(a) as usize + served(b) as usize,
        1,
        "one client flow must land on exactly one group member, handshake and stream there"
    );
    acc_a.abort();
    acc_b.abort();
}

/// One group member's whole accept path: accept whichever client flow the
/// kernel hands this member, echo the client's first bidi stream back (so a
/// completed round trip proves real stream data crossed this member, not just
/// the handshake) and hold the connection until the client closes. `true`
/// means this member served a flow; `false` means its driver stopped or the
/// handshake failed.
async fn serve_one_group_member(ep: quinn::Endpoint) -> (bool, quinn::Endpoint) {
    let incoming = match ep.accept().await {
        Some(incoming) => incoming,
        None => return (false, ep), // driver stopped
    };
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(_) => return (false, ep), // handshake failed
    };
    if let Ok((mut send, mut recv)) = conn.accept_bi().await
        && let Ok(data) = recv.read_to_end(64).await
    {
        let _ = send.write_all(&data).await;
        let _ = send.finish();
    }
    // Keep the connection alive until the client closes it: dropping the last
    // handle would close it (code 0) possibly before the echo is acknowledged.
    conn.closed().await;
    (true, ep)
}

async fn read_reset_code(recv: &mut quinn::RecvStream) -> u64 {
    match recv.read_chunk(64 * 1024, true).await {
        Err(quinn::ReadError::Reset(code)) => code.into_inner(),
        Err(e) => panic!("expected a stream reset, got {e:?}"),
        Ok(_) => panic!("expected a stream reset, got bytes"),
    }
}

/// H7 pin: a stream that never *finishes* its header must wait out the 5 s
/// header budget holding NO stream-task permit and NO share slot. With every
/// permit drained, the old order (permit before header) reset `0x05`
/// immediately without reading; the new order reads first and resets `0x01` on
/// the header timeout. Either the code or the elapsed time falsifies a
/// regression. The caller still holds the header-stage credit (that is the
/// whole point of the header stage — it is returned when the read resolves),
/// so this also pins that the credit is dropped on the timeout path.
///
/// One header byte is sent deliberately: a QUIC stream only becomes visible
/// to the peer once a frame carries its id, so a stream that sends nothing
/// at all would leave `accept_bi` — and this test — hanging forever.
#[tokio::test]
async fn header_wait_holds_no_stream_task_permit() {
    let _header_credit_guard = header_credit_test_guard().await;
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
    let header_credit = header_task_limiter()
        .clone()
        .try_acquire_owned()
        .expect("header credit");
    let header_share = Arc::new(tokio::sync::Semaphore::new(HEADER_CREDIT_PER_CONN))
        .try_acquire_owned()
        .expect("per-connection header share");
    let t0 = std::time::Instant::now();
    // The header never completes: the 5 s budget must elapse first.
    handle_tcp_stream(
        srv_send,
        srv_recv,
        header_credit,
        header_share,
        streams_held.clone(),
        MAX_STREAM_TASKS,
        1,
        true,
        server_conn.clone(),
        // rev2 path: the handler reads the atyp itself (no accept-side sniff).
        None,
        tokio::time::Instant::now() + Duration::from_secs(5),
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
    let _header_credit_guard = header_credit_test_guard().await;
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
    let header_credit = header_task_limiter()
        .clone()
        .try_acquire_owned()
        .expect("header credit");
    let header_share = Arc::new(tokio::sync::Semaphore::new(HEADER_CREDIT_PER_CONN))
        .try_acquire_owned()
        .expect("per-connection header share");
    let t0 = std::time::Instant::now();
    handle_tcp_stream(
        srv_send,
        srv_recv,
        header_credit,
        header_share,
        streams_held.clone(),
        MAX_STREAM_TASKS,
        1,
        true,
        server_conn.clone(),
        // rev2 path: the handler reads the atyp itself (no accept-side sniff).
        None,
        tokio::time::Instant::now() + Duration::from_secs(5),
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

/// The two-stage stream bound, end to end through the real accept loop:
///
/// 1. a stream that carries a complete header gives its [`HEADER_TASK_CREDIT`]
///    back before it starts relaying — with a live relay flow holding the
///    stream-task permit and a TCP target connection, the whole header credit
///    is available again (nothing long-lived sits on it);
/// 2. with the header credit fully drained, the next stream is reset `0x05`
///    *before* any task is spawned (no header read, no 5 s wait) and the
///    refusal counter moves;
/// 3. once the drain is released, another stream is admitted again — the
///    limiter returns credits rather than leaking them.
#[tokio::test]
async fn header_credit_bounds_header_tasks_and_is_returned() {
    use std::sync::atomic::Ordering;

    let _header_credit_guard = header_credit_test_guard().await;
    assert_eq!(
        header_task_limiter().available_permits(),
        HEADER_TASK_CREDIT,
        "the header credit must start and end full"
    );
    let (client_conn, server_conn) = stream_test_pair().await;
    let server_task = tokio::spawn(handle_conn(
        server_conn,
        true,
        ReplyFilter::Restricted,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));

    // A local target that holds the relayed connection open, so the flow
    // survives past its header and would keep a header credit if the handler
    // failed to return it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move { listener.accept().await });

    // Stream 1: complete header. The dial must happen (proves the handler got
    // past the header stage), and the relay must then hold no header credit.
    let (mut cli_send, _cli_recv) = client_conn.open_bi().await.unwrap();
    let mut hdr = vec![0x01, 127, 0, 0, 1];
    hdr.extend_from_slice(&target_addr.port().to_be_bytes());
    cli_send.write_all(&hdr).await.unwrap();
    let (_target_stream, _) = tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .expect("the header must reach the dial")
        .unwrap()
        .expect("the target must accept the relayed connection");
    // Poll: the credit is dropped right after the header read, marginally
    // before the dial completes, so a full set is expected shortly.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while header_task_limiter().available_permits() != HEADER_TASK_CREDIT {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a live relay flow must not hold header credit (available {})",
            header_task_limiter().available_permits()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Stream 2: exhaust the header credit, then open another stream. The accept
    // loop must refuse it after `accept_bi` (a reset is observable) and before
    // the handler's header read: `0x05` is only sent by the credit refusal.
    let drained = header_task_limiter()
        .clone()
        .acquire_many_owned(HEADER_TASK_CREDIT as u32)
        .await
        .unwrap();
    assert_eq!(header_task_limiter().available_permits(), 0);
    let refused_before = HEADER_TASK_REFUSED.load(Ordering::Relaxed);
    let (mut cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
    cli_send.write_all(&hdr).await.unwrap();
    let took = std::time::Instant::now();
    let code = tokio::time::timeout(Duration::from_secs(2), read_reset_code(&mut cli_recv))
        .await
        .expect("an exhausted header credit must refuse without the 5 s header wait");
    assert_eq!(code, 0x05, "header-credit refusal resets 0x05");
    assert!(
        took.elapsed() < Duration::from_secs(2),
        "the refusal must be fail-fast, took {:?}",
        took.elapsed()
    );
    assert!(
        HEADER_TASK_REFUSED.load(Ordering::Relaxed) > refused_before,
        "the header-credit refusal must be counted"
    );
    assert_eq!(header_task_limiter().available_permits(), 0);

    // Release the drain: the credit is returned rather than leaked, and a
    // fresh stream gets through the header stage again (invalid atyp, so the
    // handler resets 0x01 immediately and returns the credit).
    drop(drained);
    let (mut cli_send, mut cli_recv) = client_conn.open_bi().await.unwrap();
    cli_send.write_all(&[0x09]).await.unwrap();
    let code = tokio::time::timeout(Duration::from_secs(2), read_reset_code(&mut cli_recv))
        .await
        .expect("a re-admitted stream must run its header read");
    assert_eq!(code, 0x01, "an invalid header resets 0x01");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while header_task_limiter().available_permits() != HEADER_TASK_CREDIT {
        assert!(
            tokio::time::Instant::now() < deadline,
            "header credit must be returned when the handler ends (available {})",
            header_task_limiter().available_permits()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    client_conn.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
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
        m.insert(k, capped_session(k, 5));
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
/// The holder assertions are exact because every test that can register a
/// non-empty table — this one,
/// `fair_share_counts_session_holders_not_live_connections`, the
/// `l2_dns_burst_coalesces_to_one_waiter_per_session` burst (which reaches
/// `get_or_create_sess`'s creation arm), and the full-cone e2e helper
/// (`unsolicited_reply_through_filter`, which runs a real connection through
/// `handle_conn`) — serializes on `HOLDER_TEST_LOCK`; exact reads would
/// otherwise race each other.
#[tokio::test]
async fn session_churn_holds_caps_without_leaking() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    const N: usize = 1024;
    let holders_before = session_holders().load(Ordering::Relaxed);
    let permits_before = session_limiter().available_permits();
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    for s in 1..=N as u32 {
        ss.shard(s).write().insert(s, capped_session(s, 0));
        ss.note_insert();
        ss.note_live_insert();
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

/// L2 DNS burst coalescing (server egress).
///
/// A same-host cold burst must **not** spawn one resolver waiter per datagram.
/// The per-connection [`DnsGate`] admits one waiter per `(session, name, port)`;
/// datagrams arriving while that resolution is in flight are dropped (ordinary
/// UDP loss, counted as `REFUSED`), and any datagram arriving after the session
/// destination memo was stored resolves inline. `DNS_WAITER_SPAWNS` is the
/// contract the observable counters cannot express: delivery and `REFUSED` look
/// the same whichever way a follower is disposed of, but the whole point of the
/// gate is that the spawn count stays at one.
///
/// Phase 1 drives a 33-burst at a cold name from a fresh session; phase 2 drives
/// 40 at the now-warm name from a second fresh session (a new session has no
/// destination memo yet, so it still goes through the gate even though the
/// shared DNS cache is warm). Every datagram must be accounted for as
/// delivered-or-refused with zero budget/session counters moving.
///
/// `localhost` resolves via the hosts file (no network), `allow_private` keeps
/// the loopback answer deliverable, and the ephemeral port keeps the
/// `(host, port)` memo key cold. The holder guard: the burst lands on
/// `get_or_create_sess`'s *creation* path (sessions 11/12 are absent from the
/// fresh table), which registers this table in the process-global holder count
/// and only releases it when this test's runtime drops. Holding std guards
/// across awaits is deliberate and safe here: each test owns its own runtime.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_dns_burst_coalesces_to_one_waiter_per_session() {
    use std::sync::atomic::Ordering;

    let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().await;
    let _holder_guard = holder_test_guard();
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
        "premise: the (host, port) key is cold on this thread"
    );
    assert!(
        dns_slow_path_limiter().available_permits() > 0,
        "premise: the slow-path budget is available"
    );

    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let target = TargetAddr::Domain(host.to_owned(), port);
    let addr = target.as_ref();
    let payload = Bytes::from_static(b"l2-burst");

    // Phase 1: cold name, fresh session 11.
    let before = dgram_drops::snapshot();
    let spawns_before = DNS_WAITER_SPAWNS.load(Ordering::Relaxed);
    // The process-wide `dgram_drops` counters are shared with every
    // concurrently running test, so exact accounting for this burst uses the
    // gate's own counter (local to this SessTable); the global deltas are only
    // printed for context.
    let gate_before = ss.dns_gate.refusals();
    let mut inline = 0usize;
    for _ in 0..33 {
        if forward_server_dgram(&ss, &server_conn, 0, 11, addr, payload.clone(), true, None)
            .await
            .is_some()
        {
            inline += 1;
        }
    }
    let delivered = recv_loopback_burst(
        [&v4, &v6],
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .await;
    let d = dgram_drops::snapshot().since(&before);
    let spawns = DNS_WAITER_SPAWNS.load(Ordering::Relaxed) - spawns_before;
    assert_eq!(
        spawns, 1,
        "a cold burst must spawn exactly one waiter, not one per datagram"
    );
    assert!(
        delivered >= 1,
        "the one waiter's payload must reach the target"
    );
    assert_eq!(
        delivered as usize,
        inline + 1,
        "every datagram is delivered by the single waiter or inline; a \u{22}dropped\u{22} \
         payload here means the gate lost one"
    );
    let gate_refs = ss.dns_gate.refusals() - gate_before;
    assert_eq!(
        delivered as u64 + gate_refs,
        33,
        "every burst datagram must be delivered or coalesced away by this gate: \
         gate_refusals={gate_refs} global_refused_delta={} dns_budget_delta={} \
         session_full_delta={}",
        d.refused,
        d.dns_budget,
        d.session_full,
    );
    assert_eq!(d.session_full, 0, "budget was available throughout");
    assert_eq!(d.dns_budget, 0, "budget was available throughout");

    // Phase 2: warm shared cache, fresh session 12 (no destination memo yet).
    // Exactly one waiter again — unless this thread's DNS memo was warmed by a
    // spawned waiter while this test awaited, in which case the whole burst is
    // served inline (zero spawns) and every datagram is delivered.
    let before2 = dgram_drops::snapshot();
    let spawns_before2 = DNS_WAITER_SPAWNS.load(Ordering::Relaxed);
    let gate_before2 = ss.dns_gate.refusals();
    let mut inline2 = 0usize;
    for _ in 0..40 {
        if forward_server_dgram(&ss, &server_conn, 0, 12, addr, payload.clone(), true, None)
            .await
            .is_some()
        {
            inline2 += 1;
        }
    }
    let delivered2 = recv_loopback_burst(
        [&v4, &v6],
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .await;
    let d2 = dgram_drops::snapshot().since(&before2);
    let spawns2 = DNS_WAITER_SPAWNS.load(Ordering::Relaxed) - spawns_before2;
    let gate_refs2 = ss.dns_gate.refusals() - gate_before2;
    assert!(
        spawns2 <= 1,
        "a warm-name burst must coalesce to at most one waiter, spawned {spawns2}"
    );
    assert_eq!(
        delivered2 as usize,
        inline2 + spawns2 as usize,
        "every datagram is delivered by the single waiter or inline"
    );
    assert_eq!(
        delivered2 as u64 + gate_refs2,
        40,
        "every warm-burst datagram must be delivered or coalesced away by this \
         gate: gate_refusals={gate_refs2} global_refused_delta={} \
         dns_budget_delta={} session_full_delta={}",
        d2.refused,
        d2.dns_budget,
        d2.session_full,
    );
    assert_eq!(d2.session_full, 0);
    assert_eq!(d2.dns_budget, 0);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A domain whose records the SSRF filter rejects must be refused **inline**
/// after one waiter, not re-spawned per datagram — the F1 defect.
///
/// `localhost` resolves via the hosts file to loopback addresses, which
/// `allow_private = false` filters: every resolution yields "no usable address".
/// Before the gate, the thread memo kept that (filtered) first address warm, so
/// every datagram re-entered the spawn arm — one task, one `String`, two `Arc`
/// clones, one limiter permit and two moka lookups per packet, drivable by any
/// peer with a public name that resolves to a private address.
///
/// The assertions are the mechanism: the burst spawns exactly one waiter, the
/// waiter publishes an `Unusable` verdict in the gate, and the second burst
/// spawns **zero** waiters while still counting every datagram as `REFUSED`.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filtered_domain_burst_is_refused_inline_after_one_waiter() {
    use std::sync::atomic::Ordering;

    let _counter_guard = SLOW_PATH_COUNTER_LOCK.lock().await;
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let host = "localhost";
    let port = 19755u16;
    assert_eq!(
        lookup_cached_fast_with_ttl(host, port).0,
        CachedLookup::Unknown,
        "premise: this (host, port) memo key is cold on this thread"
    );
    let target = TargetAddr::Domain(host.to_owned(), port);
    let addr = target.as_ref();
    let payload = Bytes::from_static(b"filtered-burst");

    // Cold burst at a filtered name.
    let before = dgram_drops::snapshot();
    let spawns_before = DNS_WAITER_SPAWNS.load(Ordering::Relaxed);
    for _ in 0..33 {
        assert!(
            forward_server_dgram(&ss, &server_conn, 0, 21, addr, payload.clone(), false, None)
                .await
                .is_none(),
            "a filtered target never relays a datagram"
        );
    }
    // The one waiter resolves, finds every record filtered and publishes the
    // unusable verdict for the gate (recorded before it completes the claim).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if ss.dns_gate.probe_for_test(21, host, port, coarse_millis()) == Some(true) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the waiter must publish an unusable verdict"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let d = dgram_drops::snapshot().since(&before);
    let spawns = DNS_WAITER_SPAWNS.load(Ordering::Relaxed) - spawns_before;
    assert_eq!(
        spawns, 1,
        "a filtered-name burst must spawn exactly one waiter"
    );
    assert!(
        d.refused >= 33,
        "every filtered datagram must count as refused (waiter plus coalesced \
         followers), got {}",
        d.refused
    );
    assert_eq!(d.dns_budget, 0, "no slow-path permit was ever exhausted");
    assert_eq!(d.session_full, 0, "no session was ever created");

    // Second burst, same verdict window: refused inline, zero new waiters.
    let before2 = dgram_drops::snapshot();
    let spawns_before2 = DNS_WAITER_SPAWNS.load(Ordering::Relaxed);
    for _ in 0..40 {
        assert!(
            forward_server_dgram(&ss, &server_conn, 0, 21, addr, payload.clone(), false, None)
                .await
                .is_none(),
            "a cached unusable verdict never relays"
        );
    }
    let d2 = dgram_drops::snapshot().since(&before2);
    let spawns2 = DNS_WAITER_SPAWNS.load(Ordering::Relaxed) - spawns_before2;
    assert_eq!(
        spawns2, 0,
        "the cached unusable verdict must not spawn a waiter per datagram"
    );
    assert!(
        d2.refused >= 40,
        "every datagram in the cached verdict window must be refused inline, \
         got {}",
        d2.refused
    );
    assert_eq!(d2.dns_budget, 0);
    assert_eq!(d2.session_full, 0);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The gate's state machine, off the network: one claim per key, a completed
/// claim publishes a short-lived unusable verdict, and a name is normalized the
/// way DNS treats it so two spellings share one claim.
#[test]
fn dns_gate_coalesces_and_caches_unusable_verdicts() {
    let gate = DnsGate::new();
    let (s, host, port) = (7u32, "filtered.test", 443u16);
    let t0 = 1_000u64;
    let token = match gate.claim(s, host, port, t0) {
        GateClaim::Proceed(token) => token,
        _ => panic!("a cold key must be admitted"),
    };
    assert!(matches!(
        gate.claim(s, host, port, t0 + 1),
        GateClaim::InFlight
    ));
    // Different session / name / port are independent claims.
    assert!(matches!(
        gate.claim(8, host, port, t0 + 1),
        GateClaim::Proceed(_)
    ));
    assert!(matches!(
        gate.claim(s, "other.test", port, t0 + 1),
        GateClaim::Proceed(_)
    ));
    assert!(matches!(
        gate.claim(s, host, port + 1, t0 + 1),
        GateClaim::Proceed(_)
    ));
    // DNS names are case-insensitive and a trailing dot is absolute: both
    // spellings must find the same in-flight claim.
    assert!(matches!(
        gate.claim(s, "FILTERED.test.", port, t0 + 1),
        GateClaim::InFlight
    ));
    // A completed unusable verdict is remembered, and expires on its own.
    gate.finish(s, host, port, token, true, t0 + 2);
    assert_eq!(gate.probe_for_test(s, host, port, t0 + 2), Some(true));
    assert!(matches!(
        gate.claim(s, host, port, t0 + 3),
        GateClaim::Unusable
    ));
    assert!(matches!(
        gate.claim(s, host, port, t0 + 2 + DNS_GATE_UNUSABLE_TTL_MS + 1),
        GateClaim::Proceed(_)
    ));
}

/// The abandoned-waiter backstop, and why `finish` is generation-tagged: a
/// waiter that outlived its claim (its runtime was torn down, or it panicked
/// before finishing) must not clear a claim a *newer* waiter now owns for the
/// same key.
#[test]
fn dns_gate_backstop_expires_and_a_stale_finish_is_ignored() {
    let gate = DnsGate::new();
    let (s, host, port) = (9u32, "slow.test", 53u16);
    let t0 = 5_000u64;
    let stale = match gate.claim(s, host, port, t0) {
        GateClaim::Proceed(token) => token,
        _ => panic!("a cold key must be admitted"),
    };
    // The backstop expires the claim, and a fresh datagram claims again.
    let fresh = match gate.claim(s, host, port, t0 + DNS_GATE_INFLIGHT_TTL_MS + 1) {
        GateClaim::Proceed(token) => token,
        _ => panic!("an expired claim must be admitted again"),
    };
    assert_ne!(stale, fresh);
    // The abandoned waiter's late finish must not touch the fresh claim.
    gate.finish(
        s,
        host,
        port,
        stale,
        false,
        t0 + DNS_GATE_INFLIGHT_TTL_MS + 2,
    );
    assert_eq!(
        gate.probe_for_test(s, host, port, t0 + DNS_GATE_INFLIGHT_TTL_MS + 2),
        Some(false),
        "a stale finish must leave the newer in-flight claim alone"
    );
    // The current claim completes and clears its entry.
    gate.finish(
        s,
        host,
        port,
        fresh,
        false,
        t0 + DNS_GATE_INFLIGHT_TTL_MS + 3,
    );
    assert_eq!(
        gate.probe_for_test(s, host, port, t0 + DNS_GATE_INFLIGHT_TTL_MS + 3),
        None
    );
}

/// The one-slot fast hint is only ever a *hint* of the authoritative verdict:
/// a delivered (cleared) finish must invalidate it — an `InFlight` hint that
/// outlived its entry would keep dropping datagrams the gate lets spawn for
/// the whole 15 s backstop — and an expired hint must fall through instead of
/// answering from its deadline-blind state.
#[test]
fn dns_gate_fast_hint_is_invalidated_by_a_delivered_finish_and_expires() {
    let gate = DnsGate::new();
    let (s, host, port) = (11u32, "hint.test", 53u16);
    let t0 = 2_000u64;
    let token = match gate.claim(s, host, port, t0) {
        GateClaim::Proceed(token) => token,
        _ => panic!("a cold key must be admitted"),
    };
    // The same claim served twice: the second one comes from the hint.
    assert!(matches!(
        gate.claim(s, host, port, t0 + 1),
        GateClaim::InFlight
    ));
    // Delivered → the inner entry *and* the hint are gone; a fresh datagram
    // must be admitted (spawned) again, never refused by a stale InFlight.
    gate.finish(s, host, port, token, false, t0 + 2);
    assert!(
        matches!(gate.claim(s, host, port, t0 + 3), GateClaim::Proceed(_)),
        "the hint must not outlive a delivered finish"
    );
    // Backstop expiry: a hint carrying an expired deadline must fall through
    // to the lock path instead of returning its dead state.
    let fresh = match gate.claim(s, host, port, t0 + DNS_GATE_INFLIGHT_TTL_MS + 10) {
        GateClaim::Proceed(token) => token,
        other => panic!("an expired hint must fall through, got {other:?}"),
    };
    let _ = fresh;
}

/// Slot overflow must only cost a lost claim (the evicted waiter still delivers
/// its payload), never a stuck or wrong verdict: the newest claim is still
/// enforced and the evicted key is admissible again.
#[test]
fn dns_gate_overflow_evicts_claims_without_sticking() {
    let gate = DnsGate::new();
    let t0 = 1_000u64;
    let hosts: Vec<String> = (0..=DNS_GATE_SLOTS).map(|i| format!("n{i}.test")).collect();
    for (i, host) in hosts.iter().enumerate() {
        assert!(
            matches!(
                gate.claim(1, host, 1000, t0 + i as u64),
                GateClaim::Proceed(_)
            ),
            "claim {i} must be admitted"
        );
    }
    let newest = hosts.last().expect("overflow fixture is non-empty");
    assert!(matches!(
        gate.claim(1, newest, 1000, t0 + 100),
        GateClaim::InFlight
    ));
    assert!(
        matches!(
            gate.claim(1, &hosts[0], 1000, t0 + 101),
            GateClaim::Proceed(_)
        ),
        "the evicted claim's key must be admissible again, not stuck"
    );
}

/// The F1 ordering fix, off the network: when this thread's DNS memo holds a
/// **filtered** first record, the session's destination memo (which only ever
/// stores filtered-passing addresses) must be consulted before deciding to take
/// the spawned-resolver path.
///
/// Before this, the filtered branch fell straight through to the spawn arm, so
/// a name whose first record was filtered spawned a resolver task per datagram
/// forever even after one resolver pass had stored the usable address in the
/// session memo — and because the slow path therefore never returned `Some`, the
/// connection fast table could never arm either.
#[tokio::test]
async fn filtered_thread_memo_falls_back_to_the_session_dest_memo() {
    let host = "filtered-fallback.test";
    let port = 19801u16;
    let private: SocketAddr = "10.9.9.9:19801".parse().unwrap();
    let public: SocketAddr = "93.184.216.34:19801".parse().unwrap();
    dns_cache_seed(host, port, private).await;
    assert!(
        matches!(
            lookup_cached_fast_with_ttl(host, port).0,
            CachedLookup::Addr(a) if a == private
        ),
        "premise: this thread's DNS memo holds the filtered first record"
    );

    let (ss, _sock) = sess_with_dest(None);
    // Nothing memoized for the session yet: the slow path is the right answer.
    assert_eq!(
        resolve_forward_target(&ss, 7, host, port, false),
        ForwardResolution::Unresolved
    );
    // A resolver pass stored the usable address in the session memo.
    sess_dest_store(&ss, 7, host, port, public, DNS_CACHE_TTL_MS);
    assert!(
        matches!(
            resolve_forward_target(&ss, 7, host, port, false),
            ForwardResolution::Addr(a, life) if a == public && life > 0
        ),
        "the filtered thread memo must fall through to the session memo instead \
         of re-entering the spawn arm"
    );
    // `allow_private` semantics are unchanged: it still trusts the filtered
    // first record from the thread memo.
    assert!(
        matches!(
            resolve_forward_target(&ss, 7, host, port, true),
            ForwardResolution::Addr(a, _) if a == private
        ),
        "allow_private must still serve the memo's first record unchanged"
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
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
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
        None,
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

/// Target the pending-domain-OPEN tests use for their coalesced lookups.
fn pending_target() -> TargetAddr {
    TargetAddr::Ip("203.0.113.7:53".parse().unwrap())
}

/// [`R2ConnState::begin_pending_open`] with the shared test target.
fn begin_test_pending_open(state: &Arc<R2ConnState>, sess: u32, id: u32) -> PendingOpen {
    state.begin_pending_open(sess, id, &pending_target())
}

/// [`R2ConnState::queue_pending_open_payload`] with the shared test target.
fn queue_test_pending(state: &R2ConnState, sess: u32, id: u32, payload: &Bytes) -> PendingPayload {
    let target = pending_target();
    state.queue_pending_open_payload(sess, id, &target.as_ref(), payload)
}

/// The per-connection domain-OPEN coalescer: one in-flight lookup per
/// `(session, id)`, a hard cap of `MAX_PENDING_DNS_OPENS`, and RAII release on
/// every task exit path (ACK, reject, timeout, cancellation).
#[test]
fn pending_domain_opens_coalesce_cap_and_release() {
    let state = R2ConnState::new();
    let first = match begin_test_pending_open(&state, 7, 9) {
        PendingOpen::Started(g) => g,
        _ => panic!("the first OPEN must start a lookup"),
    };
    assert!(
        matches!(
            begin_test_pending_open(&state, 7, 9),
            PendingOpen::Duplicate
        ),
        "a retransmitted OPEN coalesces onto the in-flight lookup"
    );
    // A different session (or a different id) is a different flow.
    assert!(matches!(
        begin_test_pending_open(&state, 8, 9),
        PendingOpen::Started(_)
    ));
    assert!(matches!(
        begin_test_pending_open(&state, 7, 10),
        PendingOpen::Started(_)
    ));
    drop(first);
    assert!(
        matches!(
            begin_test_pending_open(&state, 7, 9),
            PendingOpen::Started(_)
        ),
        "dropping the guard must release the coalescing key"
    );

    // Fill the per-connection cap with held guards.
    let mut held = Vec::new();
    for id in 100..(100 + MAX_PENDING_DNS_OPENS as u32) {
        match begin_test_pending_open(&state, 1, id) {
            PendingOpen::Started(g) => held.push(g),
            _ => panic!("the cap must admit exactly MAX_PENDING_DNS_OPENS"),
        }
    }
    assert!(
        matches!(begin_test_pending_open(&state, 1, 9999), PendingOpen::Full),
        "past the cap the OPEN is refused instead of spawning another task"
    );
    drop(held);
    assert!(
        matches!(
            begin_test_pending_open(&state, 1, 9999),
            PendingOpen::Started(_)
        ),
        "releasing the in-flight guards must make room again"
    );
}

/// P2-2: duplicate domain-OPEN payloads are distinct data, not retransmissions
/// of the first frame. They are queued behind the in-flight lookup within a
/// per-lookup item cap and a per-connection byte budget, and the task's
/// `take_queued`/RAII drop releases the budget on every exit path.
#[test]
fn duplicate_domain_open_payloads_are_bounded_and_released() {
    let state = R2ConnState::new();
    let pending = match begin_test_pending_open(&state, 7, 9) {
        PendingOpen::Started(g) => g,
        _ => panic!("the first OPEN must start a lookup"),
    };
    let first = Bytes::from_static(b"first-duplicate");
    assert!(matches!(
        queue_test_pending(&state, 7, 9, &first),
        PendingPayload::Queued
    ));
    assert_eq!(state.pending_dns_bytes(), first.len());
    assert!(
        matches!(
            queue_test_pending(&state, 8, 9, &first),
            PendingPayload::NotPending
        ),
        "a payload for a different lookup is not queued here"
    );
    // An id names one target for the connection's life. A duplicate naming a
    // different target must be refused, never queued for the in-flight
    // lookup's destination (that would deliver it to the wrong host).
    let other_target = TargetAddr::Ip("203.0.113.8:53".parse().unwrap());
    assert!(matches!(
        state.queue_pending_open_payload(7, 9, &other_target.as_ref(), &first),
        PendingPayload::Conflict
    ));
    assert_eq!(
        state.pending_dns_bytes(),
        first.len(),
        "a refused conflict reserves nothing"
    );

    // Per-lookup item cap: the first payload plus the fill reaches the cap and
    // the next one is refused, not queued without bound.
    let one = Bytes::from_static(b"x");
    for _ in 1..MAX_PENDING_DNS_PAYLOADS {
        assert!(matches!(
            queue_test_pending(&state, 7, 9, &one),
            PendingPayload::Queued
        ));
    }
    assert!(matches!(
        queue_test_pending(&state, 7, 9, &one),
        PendingPayload::Full
    ));

    // A close flags the entry: a later duplicate is not buffered for a session
    // that is going away.
    state.cancel_pending_opens_for_session(7);
    assert!(matches!(
        queue_test_pending(&state, 7, 9, &one),
        PendingPayload::Cancelled
    ));
    let drained = pending.take_queued();
    assert_eq!(drained.len(), MAX_PENDING_DNS_PAYLOADS);
    assert_eq!(
        state.pending_dns_bytes(),
        0,
        "the drained budget is released"
    );

    // Byte budget: one maximal payload fills the connection budget and the next
    // byte is refused; dropping the guard releases it even without a drain.
    let big = match begin_test_pending_open(&state, 7, 10) {
        PendingOpen::Started(g) => g,
        _ => panic!("a fresh key must start a lookup"),
    };
    let max = Bytes::from(vec![0u8; MAX_PENDING_DNS_BYTES]);
    assert!(matches!(
        queue_test_pending(&state, 7, 10, &max),
        PendingPayload::Queued
    ));
    assert_eq!(state.pending_dns_bytes(), MAX_PENDING_DNS_BYTES);
    assert!(matches!(
        queue_test_pending(&state, 7, 10, &one),
        PendingPayload::Full
    ));
    drop(big);
    assert_eq!(
        state.pending_dns_bytes(),
        0,
        "the RAII drop releases every queued payload's budget"
    );
}

/// `SESS_CLOSE` cancels exactly the in-flight domain OPENs of its own session,
/// and it *flags* them rather than removing the coalescing key: a retransmitted
/// OPEN in the same window must coalesce onto the task that is about to notice
/// the flag and stop, never spawn a second resolver.
#[test]
fn sess_close_cancels_only_its_sessions_in_flight_opens() {
    let state = R2ConnState::new();
    let ours = match begin_test_pending_open(&state, 7, 9) {
        PendingOpen::Started(g) => g,
        _ => panic!("the first OPEN must start a lookup"),
    };
    let other = match begin_test_pending_open(&state, 8, 9) {
        PendingOpen::Started(g) => g,
        _ => panic!("a different session is a different lookup"),
    };
    assert!(!ours.is_cancelled());
    assert!(!other.is_cancelled());

    state.cancel_pending_opens_for_session(7);
    assert!(
        ours.is_cancelled(),
        "the closed session's in-flight OPEN must be cancelled"
    );
    assert!(
        !other.is_cancelled(),
        "another session's in-flight OPEN must be left alone"
    );
    assert!(
        matches!(
            begin_test_pending_open(&state, 7, 9),
            PendingOpen::Duplicate
        ),
        "a flagged entry still coalesces (it is removed by its RAII guard)"
    );

    drop(ours);
    assert!(
        matches!(
            begin_test_pending_open(&state, 7, 9),
            PendingOpen::Started(_)
        ),
        "the guard's drop releases the key again"
    );
    drop(other);
}

/// A cancelled in-flight domain OPEN must not publish a session.
///
/// This is the write-critical-section half of the D1 fix: the creation path
/// re-reads the flag immediately before inserting the entry, aborts the reader
/// it just spawned and returns the global session permit with the abandoned
/// insert. The caller (`r2_forward_domain_open_bg`) then gets `None` and rejects
/// instead of ACKing/binding a closed association, whose `take_session` may
/// have completed before the DNS answer arrived.
#[tokio::test]
async fn cancelled_in_flight_domain_open_does_not_publish_a_session() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let conn_id = next_conn_id();
    let permits_before = session_limiter().available_permits();
    assert!(permits_before > 0, "premise: the session pool has a slot");

    let cancelled = std::sync::atomic::AtomicBool::new(true);
    let sock =
        get_or_create_sess_guarded(&ss, &server_conn, conn_id, 42, None, None, Some(&cancelled))
            .await;
    assert!(
        sock.is_none(),
        "a cancelled creation must not hand out a socket"
    );
    assert_eq!(ss.len(), 0, "no session may be published");
    assert!(
        ss.shard(42).read().get(&42).is_none(),
        "the cancelled session id must not appear in its shard"
    );
    // The global permit must be back: the abandoned insert returns it, so a peer
    // cannot pin the session pool with domain OPENs that were closed mid-DNS.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_limiter().available_permits() < permits_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the aborted creation must return its session permit"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// `r2_install` publishes into **both** tables, is idempotent for a duplicate
/// OPEN of the same `(session, target)`, and refuses a new id once the session's
/// 64-entry reverse table is full without leaving a forward-registry entry
/// behind (the D2 invariant: the reverse-table publish is what makes a binding
/// reachable from every cleanup path, so it must never be half-installed; the
/// concurrent `rcu`-full half of that rollback is not deterministically
/// reachable from a unit test, the pre-check half is asserted here).
#[tokio::test]
async fn r2_install_publishes_both_tables_and_refuses_a_full_reverse_table() {
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    insert_test_session(&ss, 7);
    let state = R2ConnState::new();
    let target = TargetAddr::Ip("93.184.216.34:53".parse().unwrap());
    let first_id = r2::make_wire_id(1, false).unwrap();

    let binding = r2_install(&state, &ss, 7, first_id, target.clone(), Vec::new())
        .expect("the first install must publish");
    assert!(
        state.registry.get(first_id).is_some(),
        "the forward registry must hold the binding"
    );
    let reverse = session_r2_flows(&ss, 7).expect("the fixture session is live");
    assert!(
        reverse.load().find_id(first_id).is_some(),
        "the session's reverse table must hold the binding"
    );

    // A duplicate OPEN for the same `(session, target)` re-installs idempotently
    // and hands back the same binding (the caller re-ACKs it).
    let again = r2_install(&state, &ss, 7, first_id, target.clone(), Vec::new())
        .expect("a duplicate OPEN is idempotent");
    assert!(Arc::ptr_eq(&binding, &again));

    // The same id bound to a *different* target is the protocol-violation path.
    assert!(matches!(
        r2_install(
            &state,
            &ss,
            7,
            first_id,
            TargetAddr::Ip("1.1.1.1:53".parse().unwrap()),
            Vec::new()
        ),
        Err(RegistryError::Conflict)
    ));

    // Fill the session's reverse table to its cap (64 ids total).
    for local in 2..=(myquic2::mqp::r2_flow::R2_MAX_FLOWS_PER_SESSION as u32) {
        let id = r2::make_wire_id(local, false).expect("wire id");
        r2_install(&state, &ss, 7, id, target.clone(), Vec::new()).expect("fill install");
    }
    assert!(
        reverse.load().is_full(),
        "premise: the reverse table reached its 64-entry cap"
    );
    // A new id is refused *before* the registry insert (no leaked forward entry).
    let new_id = r2::make_wire_id(9999, false).expect("wire id");
    assert!(matches!(
        r2_install(&state, &ss, 7, new_id, target.clone(), Vec::new()),
        Err(RegistryError::Full)
    ));
    assert!(
        state.registry.get(new_id).is_none(),
        "a full reverse table must not leak a forward-registry entry"
    );
    // An existing id still reinstalls (the pre-check exempts it), so a duplicate
    // OPEN after the table filled is not wrongly rejected.
    assert!(
        r2_install(&state, &ss, 7, first_id, target, Vec::new()).is_ok(),
        "a duplicate OPEN is exempt from the full-table refusal"
    );
}

/// The server's reap notification is a `SESS_CLOSE` sent three times
/// best-effort (the client's own association exit uses the same repeat), so one
/// lost CTL datagram does not leave the client sending into a session the
/// server has already reaped.
#[tokio::test]
async fn r2_send_sess_close_sends_three_idempotent_frames() {
    let (client_conn, server_conn) = stream_test_pair().await;
    // No connection state: the default/rev2 path (three idempotent DATAGRAMs).
    r2_send_sess_close(&server_conn, None, 42);
    for i in 0..3 {
        let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
            .await
            .unwrap_or_else(|_| panic!("SESS_CLOSE repeat {i} must arrive"))
            .expect("datagram read");
        assert_eq!(
            r2::decode_ctl(&d).expect("SESS_CLOSE must decode"),
            r2::Ctl::SessClose {
                sess: 42,
                reason: 0
            }
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), client_conn.read_datagram())
            .await
            .is_err(),
        "exactly three repeats, not an unbounded stream"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The domain-flow address set is SSRF-filtered first and then capped: a
/// peer-controlled name cannot pin an unbounded resolved set (or make every
/// reply scan thousands of addresses).
#[test]
fn resolved_set_is_ssrf_filtered_before_it_is_capped() {
    let private = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443));
    let first_public = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 1), 443));
    let mut addrs = vec![private];
    for i in 0..(R2_MAX_RESOLVED_ADDRS + 8) {
        addrs.push(SocketAddr::from((
            Ipv4Addr::new(93, 184, 216, 1 + i as u8),
            443,
        )));
    }
    let kept = policy_resolved(&addrs, false);
    assert_eq!(kept.len(), R2_MAX_RESOLVED_ADDRS);
    assert!(kept.iter().all(|a| a.ip() != private.ip()));
    assert_eq!(kept[0], first_public);
    // `allow_private` keeps the first (private) record but still caps.
    let kept = policy_resolved(&addrs, true);
    assert_eq!(kept.len(), R2_MAX_RESOLVED_ADDRS);
    assert_eq!(kept[0], private);
}

/// A domain target whose answer is only in the **session destination memo**
/// (the shared DNS cache and this thread's memo are both cold) must resolve
/// inline.
///
/// This is the production shape the spawn arm used to catch on *every* packet:
/// `lookup_cached_fast*` reads a thread-local memo that only the cache-*miss*
/// init writes, so a moka hit — or, as here, a memo written by the first
/// datagram's spawned resolver on another worker — left it cold,
/// `forward_server_dgram` spawned a resolver task per datagram, and the reader
/// never saw the `Some((dst, life))` that `arm_fast` needs to install the
/// connection fast table. The whole N=1 fast path (pin + staged `sendmmsg`) was
/// bypassed for domain targets. The memo is now consulted here, so the slow
/// path runs once per session rather than once per packet.
///
/// The session fixture inserts its entry directly (never through
/// `get_or_create_sess`), so the process-global holder count — which
/// `HOLDER_TEST_LOCK` keeps exact for the tests that assert on it — is
/// untouched (this fixture's session 7 hit also keeps the memo path here
/// from ever reaching the creation arm).
#[tokio::test]
async fn a_session_dest_memo_answers_a_domain_target_inline() {
    let (host, port) = ("inline-resolve.test", 19741u16);
    // The target is a loopback socket the test owns, so the relayed datagram is
    // observable and nothing leaves the host (`allow_private = true`).
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    // A dual-stack session socket, built the way `get_or_create_sess` builds
    // one: the relay sends to `map_for_dual(dst)`, so a v4-only fixture socket
    // could not deliver to the v4 target above.
    let raw = udp_socket_dual_small("[::]:0").expect("dual-stack session socket");
    let ss = sess_with_sock(
        None,
        Arc::new(tokio::net::UdpSocket::from_std(raw).unwrap()),
    );
    // The memo a previous datagram's spawned resolver would have stored; the
    // premise below is what makes this the shape under test.
    sess_dest_store(&ss, 7, host, port, dst, DNS_CACHE_TTL_MS);
    assert_eq!(
        lookup_cached_fast(host, port),
        CachedLookup::Unknown,
        "premise: the session memo is the only source that can answer this name"
    );

    let (client_conn, server_conn) = stream_test_pair().await;
    let conn_id = next_conn_id();
    let mut buf = [0u8; 64];
    let used = forward_server_dgram(
        &ss,
        &server_conn,
        conn_id,
        7,
        TargetAddrRef::Domain(host, port),
        Bytes::from_static(b"first"),
        true,
        None,
    )
    .await;
    let (resolved, life) = used.expect(
        "the session memo must resolve inline: `None` here is the per-datagram \
         spawn path, and the reader needs `Some` to arm the connection fast table",
    );
    assert_eq!(
        resolved, dst,
        "the memoized answer must be relayed verbatim"
    );
    assert!(life > 0, "the returned life must be usable as a pin TTL");
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the inline send must deliver")
        .unwrap();
    assert_eq!(&buf[..n], b"first");
    assert!(
        from.ip().is_loopback(),
        "relay came from the session socket: {from}"
    );

    // ...and it keeps resolving inline (this path refreshes the memo).
    let again = forward_server_dgram(
        &ss,
        &server_conn,
        conn_id,
        7,
        TargetAddrRef::Domain(host, port),
        Bytes::from_static(b"second"),
        true,
        None,
    )
    .await;
    assert_eq!(
        again.map(|(a, _)| a),
        Some(dst),
        "the memo must keep serving"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A run of one reply must flush as a plain `0x02` DATAGRAM, not a BATCH frame.
///
/// Low-rate sessions (DNS-style request/response, keepalives) deliver exactly
/// one reply per wakeup, so a run of one is their steady shape. Wrapping it in
/// `0x06` buys a count byte, a per-item length prefix and one extra client-side
/// decode for no grouping; the single-frame path is also the encoder the
/// per-reply fallback already uses, so the answer is identical to an unbatched
/// reply (and the batch debug line now only fires for real groups).
#[tokio::test]
async fn a_single_staged_reply_flushes_as_one_plain_datagram() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let body = &b"single-reply"[..];
    assert!(
        reply_stage(&mut arena, &mut staged, &mut staged_src, src, body, limit),
        "a small reply must stage under a full path budget"
    );

    flush_reply_batch(
        &server_conn,
        7,
        &mut frag,
        &mut arena,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );
    assert!(
        staged.is_empty() && staged_src.is_none(),
        "a flush must drain the queue and its source"
    );

    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the single reply must arrive")
        .unwrap();
    assert!(
        !is_batch(&d),
        "a run of one must not be wrapped in a BATCH frame"
    );
    let (sess, addr, payload) =
        decode_datagram_ref(&d).expect("a plain reply must be a valid MQP-2 datagram");
    assert_eq!(sess, 7);
    assert_eq!(payload, body, "the reply payload must be sent verbatim");
    match addr {
        TargetAddrRef::Ip(a) => assert_eq!(a, src, "the reply must name its source"),
        other => panic!("an IP target reply must stay IP-form: {other:?}"),
    }
    // Exactly one frame: a duplicate single-`0x02` send (a half-wired flush that
    // also falls through to the BATCH path) would leave this probe firing.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), client_conn.read_datagram())
            .await
            .is_err(),
        "one staged reply must produce exactly one frame"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// MQP-3 reply path: a source that matches an inbound IP flow is compressed to
/// a 5-byte SINGLE (the client already has the flow id from its outbound
/// table).
#[tokio::test]
async fn reply_v3_known_ip_flow_is_compressed() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let flows = Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Ip(src)));
        Arc::new(t)
    });
    let mut arena = Vec::new();
    let mut staged = Vec::new();
    let mut staged_wire = 0usize;
    let mut last_flow = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;
    let body = &b"known-flow"[..];
    assert!(reply_stage_v3(
        &mut arena,
        &mut staged,
        &mut staged_wire,
        flows.as_ref(),
        &mut last_flow,
        src,
        body,
        limit,
    ));
    flush_reply_train(
        &server_conn,
        7,
        &mut DgramFragmenter::new(),
        &mut arena,
        &mut staged,
        &mut staged_wire,
        &mut limit,
        &mut last_probe,
    );
    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the reply must arrive")
        .unwrap();
    let s = decode_single(&d).expect("known flow must use v3 SINGLE");
    assert_eq!(s.sess, 7);
    assert_eq!(s.flow, 0);
    assert_eq!(s.inline, None, "the client already has the flow address");
    assert_eq!(s.payload, body);
    assert_eq!(d.len(), 5 + body.len());
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// One reply TRAIN can carry sources for two different flows; this is the
/// server-side counterpart of the client's mixed-flow train.
#[tokio::test]
async fn reply_v3_train_mixes_sources() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let a: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let b: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let flows = Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Ip(a)));
        assert!(t.insert_at_owned(1, TargetAddr::Ip(b)));
        Arc::new(t)
    });
    let mut arena = Vec::new();
    let mut staged = Vec::new();
    let mut staged_wire = 0usize;
    let mut last_flow = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    for (src, body) in [(a, &b"first"[..]), (b, b"second"), (a, b"third")] {
        assert!(reply_stage_v3(
            &mut arena,
            &mut staged,
            &mut staged_wire,
            flows.as_ref(),
            &mut last_flow,
            src,
            body,
            limit,
        ));
    }
    flush_reply_train(
        &server_conn,
        7,
        &mut DgramFragmenter::new(),
        &mut arena,
        &mut staged,
        &mut staged_wire,
        &mut limit,
        &mut 0u64,
    );
    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the train must arrive")
        .unwrap();
    let t = decode_train(&d).expect("known flows must use a v3 TRAIN");
    let items: Vec<_> = t.items().collect();
    assert_eq!(items.len(), 3);
    assert_eq!(
        items.iter().map(|i| i.flow).collect::<Vec<_>>(),
        vec![0, 1, 0]
    );
    assert_eq!(items[0].payload, b"first");
    assert_eq!(items[1].payload, b"second");
    assert_eq!(items[2].payload, b"third");
    assert!(items.iter().all(|i| i.inline.is_none()));
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A domain flow has no resolved IP in the client's flow table, so compressing
/// a reply would make the SOCKS header claim the *domain* as the source. The
/// server deliberately sends those sources inline (no-flow) instead.
#[tokio::test]
async fn reply_v3_domain_flow_stays_inline() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "203.0.113.7:53".parse().unwrap();
    let flows = Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Domain("example.test".into(), 53)));
        Arc::new(t)
    });
    let mut arena = Vec::new();
    let mut staged = Vec::new();
    let mut staged_wire = 0usize;
    let mut last_flow = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    let body = &b"domain-reply"[..];
    assert!(reply_stage_v3(
        &mut arena,
        &mut staged,
        &mut staged_wire,
        flows.as_ref(),
        &mut last_flow,
        src,
        body,
        limit,
    ));
    flush_reply_train(
        &server_conn,
        7,
        &mut DgramFragmenter::new(),
        &mut arena,
        &mut staged,
        &mut staged_wire,
        &mut limit,
        &mut 0u64,
    );
    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the inline reply must arrive")
        .unwrap();
    let s = decode_single(&d).expect("the reply must be a v3 SINGLE");
    assert_eq!(s.flow, MQP3_NO_FLOW);
    assert_eq!(s.inline, Some(TargetAddrRef::Ip(src)));
    assert_eq!(s.payload, body);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// MQP-3 ingress: a TRAIN may open a flow inline and carry compressed payloads
/// for that same flow later in the frame. The server must install the mapping
/// after the first accepted item, then resolve the later item from it.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn v3_train_open_then_compressed_reaches_the_target() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client_conn, server_conn) = stream_test_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let limit = client_conn
        .max_datagram_size()
        .expect("DATAGRAM is negotiated by the test transport");
    let addr = TargetAddr::Ip(dst);
    let items = [
        TrainItem {
            flow: 0,
            inline: Some(addr.as_ref()),
            src_override: false,
            payload: b"v3-open",
        },
        TrainItem {
            flow: 0,
            inline: None,
            src_override: false,
            payload: b"v3-compressed",
        },
    ];
    let frame = encode_train(1, &items, limit).expect("encode a mixed open/compressed train");

    let server_task = tokio::spawn(handle_conn(
        server_conn,
        true,
        ReplyFilter::Restricted,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));
    client_conn.send_datagram(frame).unwrap();

    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    for _ in 0..2 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("both items must be relayed")
            .unwrap();
        got.push(buf[..n].to_vec());
    }
    got.sort();
    assert_eq!(
        got,
        vec![b"v3-compressed".to_vec(), b"v3-open".to_vec()],
        "the compressed item must resolve through the flow opened in the same train"
    );

    client_conn.close(0u32.into(), b"done");
    server_task.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_holders().load(Ordering::Relaxed) != holders_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session holder count must return after the connection closes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A target that answers from a different port is not the flow's bound source.
/// The server must send the actual `(ip, port)` inline rather than let the
/// client reconstruct the wrong SOCKS5 response source from the flow id.
#[tokio::test]
async fn reply_v3_changed_source_port_stays_inline() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let bound: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let actual: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let flows = Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Ip(bound)));
        Arc::new(t)
    });
    let mut arena = Vec::new();
    let mut staged = Vec::new();
    let mut staged_wire = 0usize;
    let mut last_flow = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    let body = &b"port-changed"[..];
    assert!(reply_stage_v3(
        &mut arena,
        &mut staged,
        &mut staged_wire,
        flows.as_ref(),
        &mut last_flow,
        actual,
        body,
        limit,
    ));
    flush_reply_train(
        &server_conn,
        7,
        &mut DgramFragmenter::new(),
        &mut arena,
        &mut staged,
        &mut staged_wire,
        &mut limit,
        &mut 0u64,
    );
    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the inline reply must arrive")
        .unwrap();
    let s = decode_single(&d).expect("the reply must be a v3 SINGLE");
    assert_eq!(s.flow, MQP3_NO_FLOW);
    assert_eq!(s.inline, Some(TargetAddrRef::Ip(actual)));
    assert_eq!(s.payload, body);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A destination evicted from the 16-entry recent-IP ring must still be able to
/// answer if its exact flow is live. This is the 32-resolver fanout shape: the
/// ring cannot hold every source, but the session's flow table can.
#[tokio::test]
async fn reply_v3_flow_admits_an_evicted_allowlist_host() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let (ss, _sock) = sess_with_dest(None);
    let (last2, recent, recent_epoch, flows) = {
        let r = ss.shard(7).read();
        let e = r.get(&7).expect("session 7");
        (
            e.last.clone(),
            e.recent.clone(),
            e.recent_epoch.clone(),
            e.flows.clone(),
        )
    };
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let other: SocketAddr = "203.0.113.7:53".parse().unwrap();
    // The ring knows a different host only; `src` is not on the allowlist.
    remember_dst(&ss, 7, other);
    flows.rcu(|old| {
        let mut t = (**old).clone();
        assert!(t.insert_at_owned(0, TargetAddr::Ip(src)));
        Arc::new(t)
    });

    let r2_flows = {
        let r = ss.shard(7).read();
        r.get(&7).expect("session 7").r2_flows.clone()
    };
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut frag2 = R2Fragmenter::new();
    let mut r2 = R2ReplyState::new(r2_flows, None);
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut probe = 0u64;
    let mut last_touch = 0u64;
    let mut last_refresh = coarse_millis();
    let mut allow_snap = None;
    let mut allow_epoch = u64::MAX;
    let body = &b"evicted-source"[..];
    let disposition = handle_session_reply(
        &server_conn,
        7,
        body,
        src,
        ReplyFilter::Restricted,
        &mut r2,
        &stage,
        &mut frag2,
        flows.as_ref(),
        &mut limit,
        &mut probe,
        &mut last_touch,
        &mut last_refresh,
        last2.as_ref(),
        recent.as_ref(),
        recent_epoch.as_ref(),
        &mut allow_snap,
        &mut allow_epoch,
    );
    assert_eq!(disposition, ReplyDisposition::Continue);
    assert_eq!(
        drain_stage(&server_conn, &stage, &mut limit, &mut probe),
        StageDrain::Ok
    );
    // The reply is authorized by the live v3 flow mapping, but no rev2 binding
    // exists for the source, so it stages as the self-describing INLINE shape.
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("the authorized reply must be rev2 DATA");
    assert_eq!(data.id, None, "no rev2 binding: an INLINE frame");
    assert_eq!(data.sess, Some(7));
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(src)));
    assert!(data.src);
    assert_eq!(data.payload, body);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// Reply-path batching: one BATCH frame carries every staged small reply,
/// in staging order, with the session id and the shared source address.
///
/// This is the reply-path twin of the client association's N-pack, driven
/// directly against a live loopback pair so the wire format is what is
/// asserted — one `0x06` frame the client dispatcher already decodes into
/// per-association replies, not N `0x02` frames.
#[tokio::test]
async fn reply_batch_frame_carries_every_staged_reply_in_order() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    for body in [&b"first"[..], b"second-reply", b"third"] {
        assert!(
            reply_stage(&mut arena, &mut staged, &mut staged_src, src, body, limit),
            "a small reply must stage under a full path budget"
        );
    }

    flush_reply_batch(
        &server_conn,
        7,
        &mut frag,
        &mut arena,
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

/// Staging must charge **every** reply's 2-byte length prefix, so an accepted
/// run always encodes: the old check added a single `BATCH_ITEM_OVERHEAD` and
/// compared the bodies-only arena against the budget, under-counting an N-item
/// run by `2 * N` bytes.
///
/// The boundary is exact and matches `encode_batch`'s arithmetic: an IPv4
/// source costs a 7-byte header, so a BATCH frame spends
/// `5 + 7 + 1 + Σ(2 + len)`. Sixteen 88-byte replies need
/// `13 + 16 x 90 = 1453 B`:
///
/// - at 1452 B the 16th reply does not fit (`90 x 16 = 1440 > 1452 - 13 = 1439`)
///   and must be refused **during staging** — the old accounting admitted it, the
///   flush then found the frame unencodable and degraded to per-reply sends after
///   the staging copy had already been paid for. That is precisely the waste the
///   budget exists to prevent;
/// - at 1453 B all sixteen fit, and both the 15-item and the 16-item accepted
///   runs must encode (asserted against `encode_batch` itself, not against a
///   copied formula).
#[test]
fn reply_stage_prefix_charge_makes_every_accepted_run_encodable() {
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let body = [0xA5u8; 88];
    let addr = TargetAddr::Ip(src);
    let aref = addr.as_ref();

    // 1452 B: the 16th 88-byte reply is over budget and is refused at staging.
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    let mut staged_n = 0usize;
    while reply_stage(&mut arena, &mut staged, &mut staged_src, src, &body, 1452) {
        staged_n += 1;
        assert!(
            staged_n <= MAX_BATCH_ITEMS,
            "the run must stay item-bounded"
        );
    }
    assert_eq!(
        staged_n, 15,
        "16 x 88 B replies need 1453 B, so the 1452 B budget must refuse the 16th"
    );
    assert_eq!(staged.len(), 15);
    assert_eq!(arena.len(), 15 * 88, "the arena holds bodies only");
    let refs: Vec<&[u8]> = staged.iter().map(|(o, l)| &arena[*o..*o + *l]).collect();
    let frame = encode_batch(7, &aref, &refs, 1452)
        .expect("every staged run must encode — this is the invariant the under-count broke");
    assert_eq!(
        frame.len(),
        13 + 15 * 90,
        "frame = prefix + addr header + count byte + Σ(2 + len)"
    );

    // 1453 B: the wire size of the 16-item frame, so all sixteen fit and encode.
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    let mut staged_n = 0usize;
    while staged_n < MAX_BATCH_ITEMS
        && reply_stage(&mut arena, &mut staged, &mut staged_src, src, &body, 1453)
    {
        staged_n += 1;
    }
    assert_eq!(staged_n, MAX_BATCH_ITEMS, "the full run fits 1453 B");
    let refs: Vec<&[u8]> = staged.iter().map(|(o, l)| &arena[*o..*o + *l]).collect();
    let frame = encode_batch(7, &aref, &refs, 1453).expect("the full 16-item run must encode");
    assert_eq!(frame.len(), 1453);
}

/// The end-to-end shape of the accounting fix: a full run that staging accepts
/// flushes as exactly **one** 0x06 frame.
///
/// Sizes are derived from the live path budget instead of the 1452/1453 literal
/// boundary above, because the frame is actually sent through quinn here (a
/// frame larger than `max_datagram_size` would be `TooLarge` and legitimately
/// take the per-reply fallback — a different test). The point is that the
/// budget-aware staging fills a run to the last byte and the flush still emits
/// one grouped frame: before the fix the last item's prefixes were unaccounted
/// and the frame overflowed.
#[tokio::test]
async fn a_staging_full_reply_run_flushes_as_one_batch_frame() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let limit = server_conn.max_datagram_size().unwrap();
    // IPv4 source: the fixed part is BATCH_PREFIX_LEN + 7 + 1.
    let fixed = BATCH_PREFIX_LEN + 7 + 1;
    let per_item = (limit - fixed) / MAX_BATCH_ITEMS;
    assert!(
        per_item > BATCH_ITEM_OVERHEAD,
        "the test transport must carry a batch frame: limit {limit} B"
    );
    let body_len = per_item - BATCH_ITEM_OVERHEAD;
    let bodies: Vec<Vec<u8>> = (0..MAX_BATCH_ITEMS)
        .map(|i| vec![i as u8; body_len])
        .collect();

    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    for body in &bodies {
        assert!(
            reply_stage(&mut arena, &mut staged, &mut staged_src, src, body, limit),
            "a run sized to the budget must stage in full"
        );
    }
    assert_eq!(staged.len(), MAX_BATCH_ITEMS);
    // The staged run is at most one frame by construction; this is the property
    // the old under-count violated.
    assert!(
        fixed + staged.len() * per_item <= limit,
        "an accepted run must never exceed the path budget"
    );

    let mut limit_slot = limit;
    let mut last_probe = 0u64;
    flush_reply_batch(
        &server_conn,
        7,
        &mut frag,
        &mut arena,
        &mut staged,
        &mut staged_src,
        &mut limit_slot,
        &mut last_probe,
    );
    assert!(
        staged.is_empty() && staged_src.is_none(),
        "the flush must drain the run"
    );

    let d = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the batch frame must arrive")
        .unwrap();
    assert!(is_batch(&d), "a staged-full run must ride one BATCH frame");
    let b = decode_batch_ref(&d).expect("the frame must decode as a batch");
    assert_eq!(b.sess, 7);
    assert_eq!(b.payloads.len(), MAX_BATCH_ITEMS);
    for (got, want) in b.payloads.iter().zip(&bodies) {
        assert_eq!(*got, want.as_slice(), "payloads must survive in order");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), client_conn.read_datagram())
            .await
            .is_err(),
        "a staged-full run must produce exactly one frame, never a degraded tail"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A batch frame that does not fit the path must not take its replies down
/// with it: every reply goes out as its own `0x02` frame, in order, and each
/// keeps its own accounting.
///
/// Reached only when the path budget **shrinks after staging**: `reply_stage`
/// now charges every item's 2-byte length prefix (see
/// `reply_stage_prefix_charge_makes_every_accepted_run_encodable`), so a run
/// that staging accepted always encodes and a shrink is exactly the case this
/// fallback exists for — a PMTU reduction between the staging and the flush
/// must not lose N replies that each still fit alone. Before the accounting
/// fix this fallback also masked the staging gate's own over-admission (an
/// under-counted run was flushed into a frame it could not fit), at the cost of
/// the whole staged copy.
#[tokio::test]
async fn reply_batch_falls_back_to_per_reply_frames_when_it_cannot_fit() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut frag = DgramFragmenter::new();
    let replies: Vec<Bytes> = vec![
        Bytes::from(vec![0xA1; 100]),
        Bytes::from(vec![0xB2; 100]),
        Bytes::from(vec![0xC3; 100]),
    ];
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let mut limit = server_conn.max_datagram_size().unwrap();
    let mut last_probe = 0u64;
    for want in &replies {
        assert!(
            reply_stage(&mut arena, &mut staged, &mut staged_src, src, want, limit),
            "three 100 B replies must stage under a full path budget"
        );
    }
    // Each single frame is 5 + 7 + 100 = 112 B; the batch needs
    // 5 + 7 + 1 + 3 x (2 + 100) = 321 B, so this budget admits the replies
    // and refuses the frame — the exact shape the fallback exists for.
    limit = 300usize;

    flush_reply_batch(
        &server_conn,
        9,
        &mut frag,
        &mut arena,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );
    assert!(staged.is_empty(), "the fallback must still drain the queue");
    assert!(arena.is_empty(), "the fallback must release the arena");

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

/// Drive one outbound datagram through a live server connection, then answer it
/// from a source the session never contacted, and return the reply as the
/// client sees it (or `None` when the server dropped it).
///
/// The target is IPv4 loopback (`allow_private = true` passes the SSRF gate and
/// an IP target needs no DNS, so the session is created inline), which records
/// `127.0.0.1` as the session's only allowlisted destination. The stranger
/// binds `[::1]`: a source the session never sent to. Using a different address
/// family keeps the two sources distinct without binding a second loopback
/// address (macOS cannot bind `127.0.0.2`), and the relay socket is dual-stack,
/// so the same bound port answers on `[::1]`.
///
/// The reply is > `BATCH_SMALL_MAX`, so it takes the single `0x02` frame path
/// and one `read_datagram` is exactly one reply.
// The `HOLDER_TEST_LOCK` guard must span the awaits: this helper asserts the
// process-global holder count returns after the connection closes, which is
// the exact-delta contract that lock exists for (same shape as
// `batch_ingress_arms_the_connection_fast_table`).
/// Observed outcome of one unsolicited-source run (assertions happen after the
/// connection is closed, so a failure cannot leave the global holder count up).
struct UnsolicitedProbe {
    payload: Vec<u8>,
    src: SocketAddr,
    /// Full-cone only: the server-owned wire id the first reply opened.
    server_id: Option<u32>,
    /// Full-cone only: the client app's steady reply on that id reached the
    /// remote source (the server forwarded it to `binding.target_ip()`).
    app_reply_ok: bool,
    /// Full-cone only: a second reply from the same source compressed to a
    /// steady DATA frame (no second OPEN).
    second_compressed: bool,
    /// Full-cone only: a steady frame on an uninstalled server-owned id was
    /// dropped and not forwarded.
    unknown_server_id_dropped: bool,
}

#[allow(clippy::await_holding_lock)] // the HOLDER_TEST_LOCK guard must span the awaits (see above)
async fn unsolicited_reply_through_filter(reply_filter: ReplyFilter) -> Option<UnsolicitedProbe> {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client_conn, server_conn) = stream_test_pair().await;
    // Loopback target: `allow_private = true` passes the SSRF gate, and a v4 IP
    // target needs no DNS, so the slow path's first answer is inline.
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let limit = client_conn
        .max_datagram_size()
        .expect("DATAGRAM is negotiated by the test transport");
    let addr = TargetAddr::Ip(dst);
    let frame = encode_datagram_ref_with_limit(1, &addr.as_ref(), b"ping", limit)
        .expect("the outbound datagram must encode");
    let server_task = tokio::spawn(handle_conn(
        server_conn,
        true,
        reply_filter,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));
    // This raw test client speaks the legacy MQP-2 wire for its *outbound*
    // datagrams, but the server-owned-flow path needs the rev2 HELLO gate open
    // before a rev2 steady frame from the app can be accepted.
    client_conn
        .send_datagram(r2::encode_ctl(&r2::Ctl::Hello {
            wire_ver: r2::R2_WIRE_VER,
            flags: 0,
        }))
        .unwrap();
    let caps = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("CAPS must arrive after HELLO")
        .unwrap();
    assert!(
        matches!(r2::decode_ctl(&caps), Ok(r2::Ctl::Caps(_))),
        "HELLO must be answered with CAPS"
    );
    client_conn.send_datagram(frame).unwrap();

    // Capture results instead of asserting inside the live section: a panic
    // while the session is live would leave the process-global holder count
    // elevated and cascade into the other holder tests. Every check below runs
    // after the connection is closed and the count restored.
    let mut buf = [0u8; 2048];
    let outbound = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok());
    let mut outbound_payload_ok = false;
    let mut probe: Option<UnsolicitedProbe> = None;
    let mut classified = false;
    if let Some((n, relay)) = outbound {
        outbound_payload_ok = &buf[..n] == b"ping";
        let stranger = tokio::net::UdpSocket::bind("[::1]:0")
            .await
            .expect("this test needs an IPv6 loopback (::1) source");
        let stranger_addr = stranger.local_addr().unwrap();
        let relay_v6: SocketAddr = format!("[::1]:{}", relay.port()).parse().unwrap();
        // Snapshot the classification counters before the stranger speaks, so
        // the check below proves the reader *processed* the datagram instead of
        // relying on a timeout to mean "dropped".
        let refused_before = dgram_drops::snapshot().refused;
        let unsolicited_before = udp_stats::snapshot().unsolicited;
        // > BATCH_SMALL_MAX: Phase 1b+ carries it as a rev2 frame. Full-cone
        // opens a server-owned flow (`DATA OPEN|SRC`), the restricted filter
        // drops it entirely.
        let reply = [0x5A; 1000];
        stranger.send_to(&reply, relay_v6).await.unwrap();

        let wait = if reply_filter == ReplyFilter::FullCone {
            Duration::from_secs(5)
        } else {
            // Long enough for a wrongly admitted reply to cross loopback, short
            // enough not to slow the suite down.
            Duration::from_millis(500)
        };
        let first = tokio::time::timeout(wait, client_conn.read_datagram())
            .await
            .ok()
            .and_then(|d| d.ok());

        // Deterministic path check: the reader runs on another task, so poll
        // the classification counter (unsolicited accepted under full-cone,
        // refused under the default) instead of letting a receive timeout be
        // the only evidence. A late-forwarding regression cannot pass both this
        // and the receive assertion below.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let seen = match reply_filter {
                ReplyFilter::FullCone => udp_stats::snapshot().unsolicited > unsolicited_before,
                ReplyFilter::Restricted => dgram_drops::snapshot().refused > refused_before,
            };
            if seen {
                classified = true;
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if let Some(frame) = first {
            let data = r2::decode_data(&frame).expect("the reply must be a rev2 DATA frame");
            let mut app_reply_ok = false;
            let mut second_compressed = false;
            let mut unknown_server_id_dropped = true;
            let server_id = data.id;
            if reply_filter == ReplyFilter::FullCone {
                // The first unsolicited reply must OPEN a server-owned flow.
                let id = data
                    .id
                    .expect("full-cone must open a server-owned flow, not INLINE");
                assert!(
                    r2::wire_id_server_owned(id),
                    "the server must allocate from its own wire-id half"
                );
                assert!(data.src, "the binding frame marks the source");
                assert_eq!(data.addr, Some(TargetAddrRef::Ip(stranger_addr)));
                // The client app can now answer on the same id: the server
                // forwards the steady frame to the remote source.
                client_conn
                    .send_datagram(r2::encode_data_steady(id, b"app-reply", limit).unwrap())
                    .unwrap();
                let mut sbuf = [0u8; 64];
                app_reply_ok =
                    tokio::time::timeout(Duration::from_secs(5), stranger.recv_from(&mut sbuf))
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .is_some_and(|(k, _)| &sbuf[..k] == b"app-reply");
                // A steady frame for an unknown server-owned id must be dropped,
                // never forwarded to a guessed destination.
                let unknown = r2::make_wire_id(9_000, true).unwrap();
                client_conn
                    .send_datagram(r2::encode_data_steady(unknown, b"unknown-id", limit).unwrap())
                    .unwrap();
                unknown_server_id_dropped =
                    tokio::time::timeout(Duration::from_millis(300), stranger.recv_from(&mut sbuf))
                        .await
                        .is_err();
                // A second reply from the same source now matches the binding's
                // `reply_src` and compresses to a steady frame (no OPEN).
                stranger.send_to(b"again", relay_v6).await.unwrap();
                let second =
                    tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
                        .await
                        .ok()
                        .and_then(|d| d.ok());
                if let Some(second) = second {
                    let sdata =
                        r2::decode_data(&second).expect("the compressed reply must be rev2 DATA");
                    second_compressed = sdata.id == Some(id)
                        && sdata.sess.is_none()
                        && sdata.addr.is_none()
                        && sdata.payload == b"again";
                }
            }
            probe = Some(UnsolicitedProbe {
                payload: data.payload.to_vec(),
                src: match data.addr {
                    Some(TargetAddrRef::Ip(a)) => a,
                    other => panic!("a reply source must stay IP-form: {other:?}"),
                },
                server_id,
                app_reply_ok,
                second_compressed,
                unknown_server_id_dropped,
            });
        }
    }

    client_conn.close(0u32.into(), b"done");
    server_task.abort();
    // The connection-close sweeper drains the session; wait for the
    // process-global holder count to come back so this helper leaves it exactly
    // where it found it (the [`HOLDER_TEST_LOCK`] contract).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_holders().load(Ordering::Relaxed) != holders_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session holder count must return after the connection closes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        outbound_payload_ok,
        "the target must see the app payload (the outbound datagram must be relayed)"
    );
    assert!(
        classified,
        "the stranger datagram must reach the session reader and be classified"
    );
    probe
}

/// `udp_full_cone = true` gives the relay endpoint-independent filtering: a
/// peer the app has never sent to can still reach it, and the app sees that
/// peer's real source address (the property P2P games/WebRTC need).
#[tokio::test]
async fn full_cone_forwards_unsolicited_reply_source() {
    let probe = unsolicited_reply_through_filter(ReplyFilter::FullCone)
        .await
        .expect("full-cone mode must forward a reply from a never-contacted host");
    assert_eq!(
        probe.payload,
        vec![0x5A; 1000],
        "the unsolicited reply payload must survive intact"
    );
    assert!(
        probe.src.is_ipv6() && probe.src.ip().is_loopback(),
        "the app must see the stranger's source address, got {}",
        probe.src
    );
    let id = probe
        .server_id
        .expect("full-cone must open a server-owned flow (DATA OPEN|SRC)");
    assert!(
        r2::wire_id_server_owned(id),
        "the allocated wire id must come from the server's half"
    );
    assert!(
        probe.app_reply_ok,
        "a client steady frame on the server-owned id must be forwarded to the source"
    );
    assert!(
        probe.second_compressed,
        "a second reply from the same source must compress to steady DATA"
    );
    assert!(
        probe.unknown_server_id_dropped,
        "an unknown server-owned id must be dropped, never guessed"
    );
}

/// The shipped default keeps the anti-spoofing property: a reply from a source
/// the session never sent to is still dropped. This is exactly what
/// `udp_full_cone` opts out of, so it must not regress.
#[tokio::test]
async fn restricted_filter_drops_unsolicited_reply_source() {
    assert!(
        unsolicited_reply_through_filter(ReplyFilter::Restricted)
            .await
            .is_none(),
        "restricted mode must not forward a reply from a never-contacted host"
    );
}

/// The config → policy edge must not be inverted: an unset (or false)
/// `udp_full_cone` selects the restricted filter, and only an explicit `true`
/// selects full-cone. Every other full-cone test enters through `handle_conn`,
/// *below* this mapping, so this is what pins the part of the path the e2e
/// tests cannot see.
#[test]
fn udp_full_cone_config_selects_the_reply_filter() {
    let server = "listen = '[::]:8443'\ncert_file = 'c'\nkey_file = 'k'\nserver_name = 's'\n";
    let conf = |extra: &str| -> ServerConf { toml::from_str(&format!("{server}{extra}")).unwrap() };
    assert_eq!(reply_filter(&conf("")), ReplyFilter::Restricted);
    assert_eq!(
        reply_filter(&conf("udp_full_cone = false\n")),
        ReplyFilter::Restricted
    );
    assert_eq!(
        reply_filter(&conf("udp_full_cone = true\n")),
        ReplyFilter::FullCone,
        "an explicit true must reach the accept path"
    );
}

/// The startup fd raise must be sized off the pools that actually spend fds:
/// one UDP socket per session, one TCP socket per relayed flow. A cap change
/// that leaves this derivation behind makes the raise (and the log line that
/// reports it) understate what the process needs.
#[test]
fn fd_budget_covers_the_session_and_relay_pools() {
    let floor = (MAX_SESSIONS_GLOBAL + MAX_STREAM_TASKS) as u64;
    assert!(
        designed_fds() >= floor,
        "designed_fds() {} < session+relay floor {floor}",
        designed_fds()
    );
    assert_eq!(
        designed_fds(),
        (MAX_SESSIONS_GLOBAL + MAX_STREAM_TASKS + MAX_QUIC_ENDPOINTS + FD_GUARD) as u64,
        "the guard band and endpoint term stay part of the derivation"
    );
}

/// Full-cone relaxes the inbound reply filter only: the outbound SSRF policy
/// still refuses a loopback target when `allow_private = false`. This pins the
/// property the two policies are easy to conflate — the mode admits any reply
/// *source*, not any dial destination.
#[tokio::test]
async fn full_cone_does_not_relax_the_outbound_ssrf_filter() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let limit = client_conn
        .max_datagram_size()
        .expect("DATAGRAM is negotiated by the test transport");
    let addr = TargetAddr::Ip(dst);
    let frame = encode_datagram_ref_with_limit(1, &addr.as_ref(), b"must-not-leave", limit)
        .expect("the outbound datagram must encode");
    let server_task = tokio::spawn(handle_conn(
        server_conn,
        false, // allow_private = false: loopback is filtered on the outbound path
        ReplyFilter::FullCone,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));
    client_conn.send_datagram(frame).unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), target.recv_from(&mut buf))
            .await
            .is_err(),
        "full-cone must not relax the outbound SSRF filter: a loopback target \
         stays refused when allow_private = false"
    );
    client_conn.close(0u32.into(), b"done");
    server_task.abort();
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

    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<(usize, usize)> = Vec::new();
    let mut staged_src: Option<SocketAddr> = None;
    for body in [&b"a-1"[..], b"a-2"] {
        assert!(reply_stage(
            &mut arena,
            &mut staged,
            &mut staged_src,
            src_a,
            body,
            limit
        ));
    }
    flush_reply_batch(
        &server_conn,
        11,
        &mut frag,
        &mut arena,
        &mut staged,
        &mut staged_src,
        &mut limit,
        &mut last_probe,
    );

    for body in [&b"b-1"[..], b"b-2"] {
        assert!(reply_stage(
            &mut arena,
            &mut staged,
            &mut staged_src,
            src_b,
            body,
            limit
        ));
    }
    flush_reply_batch(
        &server_conn,
        11,
        &mut frag,
        &mut arena,
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

// The `MYQUIC2_SHARD_RUNTIME` parser now lives with the flag itself
// (`myquic2::shard_runtime_enabled`, pinned by the lib's
// `shard_runtime_off_spellings_parse` test) because both binaries read it.

/// The peer-driven server lines must log their first event immediately and then
/// go quiet inside the one-second window; the window's losers are counted and
/// folded into the next winner's line.
///
/// A `0`-initialised slot would swallow the first event instead (the mono epoch
/// starts at process start, so `now - 0 < 1000 ms` for the first second) —
/// exactly the startup/handshake burst these lines exist for. The bin mirrors
/// the crate-private lib sentinel with [`NEVER_LOGGED`] = `u64::MAX`; the
/// cross-crate half of that contract is pinned by
/// `never_logged_sentinel_claims_immediately` below.
///
/// Only this test claims these four classes (the fifth, [`ServerLog::NewConn`],
/// is exercised by `batch_ingress_arms_the_connection_fast_table` through
/// `handle_conn`), so their statics are deterministic here.
#[test]
fn peer_driven_server_logs_never_swallow_the_first_line() {
    let classes = [
        ServerLog::HandshakeFailed,
        ServerLog::HandshakeTimeout,
        ServerLog::AcceptError,
        ServerLog::AuthFailure,
    ];
    for class in classes {
        let first = claim_server_log(class)
            .unwrap_or_else(|| panic!("{class:?} must log its first event immediately"));
        assert!(
            first.to_string().is_empty(),
            "nothing has been suppressed before the first window: {class:?}"
        );
        assert!(
            claim_server_log(class).is_none(),
            "{class:?} must stay silent inside its one-second window"
        );
    }
    // Distinct slots: every class above claimed on its very first call, even
    // though the others had already opened their windows. (A shared slot would
    // let a handshake-failure flood silence the auth-failure line.)
    for class in classes {
        assert!(
            claim_server_log(class).is_none(),
            "{class:?} must still be inside its own window"
        );
    }
    // The folded suffix the winner's line carries.
    assert!(
        Suppressed(0).to_string().is_empty(),
        "a clean window must leave the line byte-identical to the old one"
    );
    assert_eq!(
        Suppressed(7).to_string(),
        " (7 similar suppressed in the last second)"
    );
}

/// Cross-crate lock on the `NEVER_LOGGED` sentinel: the lib's
/// `claim_log_window_counted` must treat `u64::MAX` as "never claimed" and hand
/// the first caller the window even at the process's first millisecond, then
/// report the suppressed count once the next window opens.
#[test]
fn never_logged_sentinel_claims_immediately() {
    use std::sync::atomic::{AtomicU64, Ordering};
    // `NEVER_LOGGED` mirrors `myquic2::stats::warn::NEVER_WARNED` (crate-private
    // to the lib); this fails the moment the lib changes the sentinel value.
    let last = AtomicU64::new(NEVER_LOGGED);
    let suppressed = AtomicU64::new(0);
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 0),
        Some(0),
        "an unclaimed slot must claim immediately, even at mono t=0"
    );
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 0),
        None,
        "a second event in the same millisecond is suppressed and counted"
    );
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 999),
        None,
        "the window is 1000 ms wide"
    );
    assert_eq!(
        claim_log_window_counted(&last, &suppressed, 1_000),
        Some(2),
        "the next window's winner must report the two events it swallowed"
    );
    assert_eq!(
        last.load(Ordering::Relaxed),
        1_000,
        "the claim stores the real timestamp it was given"
    );
    assert_eq!(
        suppressed.load(Ordering::Relaxed),
        0,
        "claiming must reset the suppressed count"
    );
}

/// W9: the rev2 counters are surfaced in the 60 s report as **deltas**, the
/// line stays quiet when nothing moved, and it names the counters an operator
/// needs (opens/acks/rejects/compression mix/DNS loss classes/control).
#[test]
fn rev2_report_line_is_delta_based_and_quiet_when_idle() {
    let zero = r2_stats::Snapshot::default();
    assert!(zero.is_idle(), "a fresh interval is idle");
    assert_eq!(
        r2_report_line(&zero),
        None,
        "an idle interval must stay silent like the other report lines"
    );

    // A non-idle interval prints one compact, prefixed line with every family.
    let now = r2_stats::Snapshot {
        opens: 3,
        acks: 3,
        rejects: 1,
        inline: 2,
        train_items: 9,
        steady_sent: 7,
        open_src_sent: 1,
        flow_acks_recv: 1,
        unknown_id: 4,
        dns_sync_opens: 2,
        dns_open_dns_fail: 1,
        dns_open_policy_drop: 1,
        dns_open_sess_refused: 1,
        dns_open_drops: 5,
        ctl_hellos: 1,
        ctl_caps_sent: 1,
        ctl_bad_hello: 0,
        sess_closes: 1,
        flow_closes: 1,
        stale_closes: 2,
        frag_refused: 1,
        frag_frames: 6,
        frag_complete: 5,
        stage_full_drops: 0,
        session_end_bindings: 1,
        full_cone_flows: 1,
        ctl_streams: 1,
        ctl_stream_second: 0,
        ctl_stream_bad_first: 0,
        ctl_msgs_recv: 2,
        ctl_msgs_dropped: 0,
        ctl_stream_errors: 0,
        need_context_sent: 1,
        need_context_recv: 1,
        need_context_dropped: 0,
    };
    let delta = now.since(&zero);
    assert_eq!(delta, now, "the first interval is the totals");
    let line = r2_report_line(&delta).expect("a non-idle interval must log");
    assert!(line.starts_with("mqp3 rev2 (60s):"), "line = {line}");
    for needle in [
        "opens=3",
        "acks=3",
        "rejects=1",
        "inline=2",
        "train_items=9",
        "steady_sent=7",
        "open_src_sent=1",
        "flow_acks=1",
        "unknown_id=4",
        "sync_open=2",
        "dns_fail=1",
        "policy_drop=1",
        "sess_refused=1",
        "open_drops=5",
        "hellos=1",
        "caps=1",
        "sess_close=1",
        "flow_close=1",
        "stale_close=2",
        "refused=1",
        "accepted=6",
        "complete=5",
        "session_end=1",
        "full_cone=1",
        "streams=1",
        "msgs=2",
        "need_ctx(sent/recv/dropped)=1/1/0",
    ] {
        assert!(line.contains(needle), "missing {needle:?} in {line}");
    }

    // A subsequent interval differences correctly, and saturates instead of
    // underflowing (a counter snapshot can never go backwards, but wrapping
    // arithmetic in the delta would print an absurd number if it ever did).
    let next = r2_stats::Snapshot { opens: 5, ..now };
    let d2 = next.since(&now);
    assert_eq!(d2.opens, 2);
    assert_eq!(d2.acks, 0);
    assert!(!d2.is_idle());
    let back = r2_stats::Snapshot::default().since(&next);
    assert_eq!(back.opens, 0, "a delta must saturate at zero, never wrap");
    assert!(back.is_idle());
}

// ---------------------------------------------------------------------------
// MQP-3 rev2 data plane (Phase 1a small-packet path)
// ---------------------------------------------------------------------------

/// A rev2 `CTL HELLO` for this wire version.
fn r2_hello_frame() -> Bytes {
    r2::encode_ctl(&r2::Ctl::Hello {
        wire_ver: r2::R2_WIRE_VER,
        flags: 0,
    })
}

/// A client-initiated `DATA OPEN` (the address is the destination).
fn r2_open_frame(id: u32, sess: u32, target: &TargetAddr, payload: &[u8]) -> Bytes {
    r2::encode_data_open(id, sess, &target.as_ref(), false, payload, 1472)
        .expect("rev2 OPEN must encode")
}

/// A compressed `DATA` steady frame.
fn r2_steady_frame(id: u32, payload: &[u8]) -> Bytes {
    r2::encode_data_steady(id, payload, 1472).expect("rev2 steady frame must encode")
}

/// A no-flow `DATA INLINE` frame (session + destination in the header).
fn r2_inline_frame(sess: u32, target: &TargetAddr, payload: &[u8]) -> Bytes {
    r2::encode_data_inline(sess, &target.as_ref(), false, payload, 1472)
        .expect("rev2 INLINE frame must encode")
}

fn r2_count(counter: &std::sync::atomic::AtomicU64) -> u64 {
    // The per-reply-frame counters (`STEADY_SENT`/`OPEN_SRC_SENT`) are
    // thread-locally batched (OBS-2). Flush this thread's pending cell first so
    // a test running on the counting thread sees its own records exactly — the
    // same rule `udp_stats::snapshot` documents for its batched counters.
    r2_stats::flush_thread();
    counter.load(std::sync::atomic::Ordering::Relaxed)
}

/// Live connection driving the production `handle_conn` datagram path.
async fn rev2_pair() -> (
    quinn::Connection,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    rev2_pair_with(true).await
}

/// [`rev2_pair`] with an explicit SSRF policy, so the policy-refusal path can be
/// driven without a live private target (`allow_private = false`).
async fn rev2_pair_with(
    allow_private: bool,
) -> (
    quinn::Connection,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (client_conn, server_conn) = stream_test_pair().await;
    let task = tokio::spawn(handle_conn(
        server_conn,
        allow_private,
        ReplyFilter::Restricted,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
    ));
    (client_conn, task)
}

/// Send `HELLO` and require one CAPS advertising this wire version.
async fn rev2_handshake(client: &quinn::Connection) {
    client.send_datagram(r2_hello_frame()).unwrap();
    let d = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("CAPS must arrive after HELLO")
        .unwrap();
    match r2::decode_ctl(&d).expect("CAPS must decode") {
        r2::Ctl::Caps(caps) => {
            assert_eq!(caps.wire_ver, r2::R2_WIRE_VER);
            assert_eq!(caps, r2::Caps::default());
        }
        other => panic!("expected CAPS, got {other:?}"),
    }
}

/// Require one `FLOW_ACK` for `want_id`.
async fn rev2_expect_ack(client: &quinn::Connection, want_id: u32) {
    let d = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("FLOW_ACK must arrive")
        .unwrap();
    match r2::decode_ctl(&d).expect("FLOW_ACK must decode") {
        r2::Ctl::FlowAck { id, status } => {
            assert_eq!(id, want_id, "ACK must name the opened wire id");
            assert_eq!(status, r2::R2_ACK_OPEN);
        }
        other => panic!("expected FLOW_ACK, got {other:?}"),
    }
}

/// Await one payload at `target`; `None` on timeout (used for negative checks).
async fn rev2_recv_timeout(
    target: &tokio::net::UdpSocket,
    buf: &mut [u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    match tokio::time::timeout(wait, target.recv_from(buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        Err(_) | Ok(Err(_)) => None,
    }
}

/// Close the client and wait until the connection's sessions are reaped, so the
/// process-global holder count returns exactly to `holders_before`.
async fn rev2_teardown(
    client: quinn::Connection,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    holders_before: usize,
) {
    client.close(0u32.into(), b"done");
    server_task.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_holders().load(std::sync::atomic::Ordering::Relaxed) != holders_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session holder count must return after the connection closes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Insert one live session entry into `ss` (test fixture). The reader is a
/// pending task, so the entry counts as "fresh" for `session_r2_flows`, exactly
/// like a session the accept loop just created. Direct insert + `note_live_insert`
/// mirrors [`sess_with_sock`], so the process-global holder denominator is left
/// untouched (these fixtures never call `note_empty_state` on insert).
fn insert_test_session(ss: &SessTable, sess: u32) {
    let h = tokio::spawn(std::future::pending::<()>());
    let permit = session_limiter().clone().try_acquire_owned().unwrap();
    ss.shard(sess).write().insert(
        sess,
        SessEntry {
            sess,
            sock: memo_sock(),
            reader: h,
            last: Arc::new(std::sync::atomic::AtomicU64::new(mono_millis())),
            _permit: permit,
            dest: DestMemo::NONE,
            recent: Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default())),
            recent_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            flows: Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default())),
            r2_flows: Arc::new(arc_swap::ArcSwap::from_pointee(SessionFlows::new())),
        },
    );
    ss.note_live_insert();
}

/// Attach a live rev2 binding to session `sess`'s reverse table, the way the
/// accept loop leaves it after an accepted `DATA OPEN`.
fn insert_r2_binding(
    ss: &SessTable,
    sess: u32,
    local_id: u32,
    target: TargetAddr,
    resolved: Vec<SocketAddr>,
) -> (Arc<arc_swap::ArcSwap<SessionFlows>>, Arc<FlowBinding>) {
    let wire_id = r2::make_wire_id(local_id, false).unwrap();
    let binding = FlowBinding::new_shared(wire_id, sess, target);
    if !resolved.is_empty() {
        binding.set_resolved(resolved);
    }
    binding.mark_open();
    let r2_flows = {
        let r = ss.shard(sess).read();
        r.get(&sess).expect("fixture session").r2_flows.clone()
    };
    r2_flows.rcu(|old| {
        let mut next = (**old).clone();
        assert!(next.insert(binding.clone()));
        Arc::new(next)
    });
    (r2_flows, binding)
}

/// Session-7 fixture with one live rev2 binding in its reverse table, the way
/// the accept loop leaves it after an accepted `DATA OPEN`.
fn rev2_reply_fixture(
    target: TargetAddr,
    resolved: Vec<SocketAddr>,
) -> (
    SessTable,
    Arc<arc_swap::ArcSwap<SessionFlows>>,
    Arc<FlowBinding>,
) {
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    insert_test_session(&ss, 7);
    let (r2_flows, binding) = insert_r2_binding(&ss, 7, 1, target, resolved);
    (ss, r2_flows, binding)
}

/// W1: the rev2 data plane runs **without** HELLO. A frame that arrives before
/// any `HELLO` is dispatched immediately (no bounded pre-HELLO buffer, no
/// version gate), `CTL HELLO` is only the CAPS trigger, and a wrong-version
/// HELLO is still answered with our CAPS while never blocking data.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_frames_dispatch_without_hello_and_hello_only_triggers_caps() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];
    let id = r2::make_wire_id(1, false).unwrap();

    // 1. Data before any HELLO is dispatched immediately: forwarded, installed
    //    and ACKed in the datagram loop.
    let hellos_before = r2_count(&r2_stats::HELLOS);
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"early"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("pre-HELLO data must be forwarded, not buffered")
        .unwrap();
    assert_eq!(&buf[..n], b"early");
    rev2_expect_ack(&client, id).await;
    assert_eq!(
        r2_count(&r2_stats::HELLOS),
        hellos_before,
        "no HELLO was sent yet: the data path must not have needed one"
    );

    // 2. A control frame before HELLO is processed immediately too (a fast
    //    association can exit and send SESS_CLOSE before the handshake
    //    announcement). Unknown session 9 is a counted stale close.
    let closes_before = r2_count(&r2_stats::SESS_CLOSES) + r2_count(&r2_stats::STALE_CLOSES);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::SessClose { sess: 9, reason: 0 }))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r2_count(&r2_stats::SESS_CLOSES) + r2_count(&r2_stats::STALE_CLOSES) == closes_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a pre-HELLO control frame must be processed, not buffered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // 3. A wrong-version HELLO is answered with our CAPS (fail-fast) and is
    //    counted, but cannot block the data plane.
    let bad_before = r2_count(&r2_stats::BAD_HELLO);
    let caps_before = r2_count(&r2_stats::CAPS_SENT);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::Hello {
            wire_ver: r2::R2_WIRE_VER + 1,
            flags: 0,
        }))
        .unwrap();
    let d = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a mismatched HELLO must still be answered with CAPS")
        .unwrap();
    match r2::decode_ctl(&d).expect("CAPS must decode") {
        r2::Ctl::Caps(caps) => assert_eq!(caps.wire_ver, r2::R2_WIRE_VER),
        other => panic!("expected CAPS, got {other:?}"),
    }
    assert_eq!(r2_count(&r2_stats::BAD_HELLO) - bad_before, 1);
    assert_eq!(r2_count(&r2_stats::CAPS_SENT) - caps_before, 1);
    client
        .send_datagram(r2_steady_frame(id, b"after-bad-hello"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("data must still be dispatched after a mismatched HELLO")
        .unwrap();
    assert_eq!(&buf[..n], b"after-bad-hello");

    // 4. The valid HELLO is the CAPS trigger (throttled to one reply per
    //    100 ms), and bumps the hello counter. Wait out the throttle the
    //    mismatched HELLO just consumed.
    tokio::time::sleep(Duration::from_millis(R2_CAPS_MIN_INTERVAL_MS + 20)).await;
    let hellos_before = r2_count(&r2_stats::HELLOS);
    let caps_before = r2_count(&r2_stats::CAPS_SENT);
    rev2_handshake(&client).await;
    assert_eq!(r2_count(&r2_stats::HELLOS) - hellos_before, 1);
    assert_eq!(r2_count(&r2_stats::CAPS_SENT) - caps_before, 1);

    // 5. Steady data keeps flowing after the handshake.
    client
        .send_datagram(r2_steady_frame(id, b"steady"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("steady data after HELLO must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"steady");

    rev2_teardown(client, task, holders_before).await;
}

/// W1 regression: a first burst larger than the deleted pre-HELLO buffer
/// (8 frames / 16 KiB) is **not** stalled or dropped when no HELLO ever
/// arrives. Every payload is dispatched immediately; the old gate delivered
/// nothing before HELLO and silently dropped frames 9..N.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_hello_loss_cannot_stall_or_drop_a_burst() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];
    // 12 distinct flows > the old 8-frame pre-HELLO cap, all opened with no
    // HELLO on the wire at all.
    for local in 1..=12u32 {
        let id = r2::make_wire_id(local, false).unwrap();
        client
            .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"x"))
            .unwrap();
    }
    let mut delivered = 0usize;
    for _ in 0..12 {
        if rev2_recv_timeout(&target, &mut buf, Duration::from_secs(5))
            .await
            .is_some()
        {
            delivered += 1;
        }
    }
    assert_eq!(
        delivered, 12,
        "every payload of a HELLO-less burst must be dispatched (no gate, no overflow drop)"
    );
    rev2_teardown(client, task, holders_before).await;
}

/// The Phase 1a ingress contract end to end: OPEN installs + ACKs, a steady
/// frame resolves through the registry, duplicate OPEN still forwards its
/// payload, INLINE forwards without installing, and unknown ids / rev2 FRAG are
/// dropped and counted.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_open_ack_steady_inline_and_drops() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"open"))
        .unwrap();
    let (n, relay) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the OPEN payload must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], b"open");
    rev2_expect_ack(&client, id).await;

    // Steady: two bytes of header, resolved by the connection registry.
    client
        .send_datagram(r2_steady_frame(id, b"steady"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("a steady frame must resolve through the installed flow")
        .unwrap();
    assert_eq!(&buf[..n], b"steady");

    // Downlink of a small reply compresses to a rev2 steady frame.
    target.send_to(b"reply", relay).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a small reply from the bound target must be compressed")
        .unwrap();
    let data = r2::decode_data(&frame).expect("downlink must be a rev2 DATA frame");
    assert_eq!(data.id, Some(id));
    assert_eq!(data.sess, None, "steady downlink carries no session");
    assert_eq!(data.addr, None, "steady downlink carries no address");
    assert_eq!(data.payload, b"reply");
    assert_eq!(
        frame.len(),
        1 + r2::varint_len(id) + b"reply".len(),
        "steady header is one kind byte plus the wire-id varint"
    );

    // Duplicate OPEN: idempotent install, but this frame's payload is delivered
    // and the ACK is re-sent (the client may have missed the first one).
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"again"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("a duplicate OPEN still carries new data")
        .unwrap();
    assert_eq!(&buf[..n], b"again");
    rev2_expect_ack(&client, id).await;

    // INLINE: forwarded once, never installed, never ACKed.
    let inline_before = r2_count(&r2_stats::INLINE);
    client
        .send_datagram(r2_inline_frame(1, &TargetAddr::Ip(dst), b"inline"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("INLINE must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"inline");
    assert!(r2_count(&r2_stats::INLINE) > inline_before);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), client.read_datagram())
            .await
            .is_err(),
        "INLINE must not install a flow or send an ACK"
    );

    // A steady frame for an id that was never installed fails lookup: drop, count,
    // never guess (the destination exists, the id does not).
    let inline_id = r2::make_wire_id(2, false).unwrap();
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client
        .send_datagram(r2_steady_frame(inline_id, b"guess"))
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "an unknown wire id must never be forwarded"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    // Phase 1b: a one-fragment rev2 FRAG for an installed flow reassembles and
    // forwards the whole payload like the equivalent steady DATA frame.
    client
        .send_datagram(
            r2::encode_frag_steady(id, 2, 0, 1, b"frag", 1472).expect("frag must encode"),
        )
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("a rev2 FRAG for an installed flow must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"frag");

    // ...while a fragmented payload for an unknown id is dropped and counted at
    // completion (the registry is resolved then, never guessed).
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client
        .send_datagram(
            r2::encode_frag_steady(inline_id, 3, 0, 1, b"guess-frag", 1472)
                .expect("frag must encode"),
        )
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a fragmented payload for an unknown id must never be forwarded"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    // Half-owner rule: a client may not open an id from the server's half — it
    // is rejected and nothing is forwarded (Phase 1b sends those as OPEN|SRC
    // from the server side).
    let server_owned = r2::make_wire_id(1, true).unwrap();
    client
        .send_datagram(r2_open_frame(
            server_owned,
            1,
            &TargetAddr::Ip(dst),
            b"spoofed",
        ))
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a client OPEN must not claim a server-owned wire id"
    );
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("the rejected OPEN must be answered with FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject { id, reason } => {
            assert_eq!(id, server_owned);
            assert_eq!(reason, r2::R2_REJECT_POLICY);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }

    rev2_teardown(client, task, holders_before).await;
}

/// P2-7: a full connection registry refuses the *install*, never the payload.
/// The triggering OPEN's datagram must reach the target, then `FLOW_REJECT`
/// tells the client to fall back to `INLINE` for later payloads.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_open_on_full_registry_forwards_payload_then_rejects() {
    let _holder_guard = holder_test_guard();
    let (client_conn, server_conn) = stream_test_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let state = R2ConnState::new();
    // Pre-fill the connection registry to its cap as unrelated installed flows.
    for local in 1..=state.registry.cap() as u32 {
        let filler = FlowBinding::new_shared(
            r2::make_wire_id(local, false).unwrap(),
            999,
            TargetAddr::Ip(SocketAddr::from(([203, 0, 113, 9], local as u16))),
        );
        assert!(state.registry.insert(filler).is_ok());
    }
    assert!(
        !state.registry.has_capacity(),
        "premise: the registry is full"
    );
    let id = r2::make_wire_id(state.registry.cap() as u32 + 1, false).unwrap();
    let mut fast = FastTable::new();
    let mut staged = Vec::new();
    r2_ingress_open(
        &mut fast,
        &ss,
        &server_conn,
        next_conn_id(),
        true,
        &mut staged,
        &state,
        id,
        1,
        TargetAddr::Ip(dst),
        Bytes::from_static(b"must-arrive"),
    )
    .await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("a full registry must still deliver the triggering payload")
        .unwrap();
    assert_eq!(&buf[..n], b"must-arrive");

    let frame = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect("the refused install must answer FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject {
            id: rejected,
            reason,
        } => {
            assert_eq!(rejected, id);
            assert_eq!(reason, r2::R2_REJECT_TABLE_FULL);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }
    assert!(
        state.registry.get(id).is_none(),
        "a refused install must not leave a binding behind"
    );
    assert_eq!(state.registry.len(), state.registry.cap());

    assert!(r2_close_session(&ss, &state, 1));
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// SSRF policy failure on an OPEN answers `FLOW_REJECT(policy)` and installs
/// nothing: the payload is never forwarded and a later steady frame for the id
/// fails lookup instead of reaching a private target.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_open_policy_refusal_rejects_without_install() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    // The server's SSRF policy is the shipped `allow_private = false`: every
    // loopback target must be refused before a session is created.
    let (client, task) = rev2_pair_with(false).await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"private"))
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "an SSRF-filtered OPEN must not reach the target"
    );
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a refused OPEN must be answered with FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject {
            id: rejected,
            reason,
        } => {
            assert_eq!(rejected, id);
            assert_eq!(reason, r2::R2_REJECT_POLICY);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }

    // No binding was installed: a compressed successor fails lookup.
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client
        .send_datagram(r2_steady_frame(id, b"after-reject"))
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a rejected OPEN must not leave a binding behind"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    rev2_teardown(client, task, holders_before).await;
}

/// A same-flow `TRAIN` delivers every payload in wire order; a dict-form item
/// naming an unknown id is dropped alone while the rest of the frame continues.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_train_delivers_known_flows_and_drops_unknown_items() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let a = r2::make_wire_id(1, false).unwrap();
    let b = r2::make_wire_id(2, false).unwrap();
    let unknown = r2::make_wire_id(9, false).unwrap();
    client
        .send_datagram(r2_open_frame(a, 1, &TargetAddr::Ip(dst), b"open-a"))
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("open payload");
    rev2_expect_ack(&client, a).await;

    // Same-flow form: one header, two labelled payloads.
    let train = r2::encode_train_same(a, &[&b"first"[..], &b"second"[..]], 1472)
        .expect("same-flow train must encode");
    client.send_datagram(train).unwrap();
    let (n1, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("first train item")
        .unwrap();
    let first = buf[..n1].to_vec();
    let (n2, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("second train item")
        .unwrap();
    let second = buf[..n2].to_vec();
    assert_eq!(
        (first, second),
        (b"first".to_vec(), b"second".to_vec()),
        "train items must keep wire order"
    );

    // Dict form with one unknown id: only the known item is forwarded.
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    let train = r2::encode_train_dict(
        &[a, unknown],
        &[(0, &b"known"[..]), (1, &b"unknown"[..])],
        1472,
    )
    .expect("dict train must encode");
    client.send_datagram(train).unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the known item must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"known");
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "the item for the unknown id must be dropped, never guessed"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    // Two known flows in one dict train both arrive.
    client
        .send_datagram(r2_open_frame(b, 1, &TargetAddr::Ip(dst), b"open-b"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("open-b payload")
        .unwrap();
    assert_eq!(&buf[..n], b"open-b");
    rev2_expect_ack(&client, b).await;
    let train = r2::encode_train_dict(&[a, b], &[(0, &b"via-a"[..]), (1, &b"via-b"[..])], 1472)
        .expect("dict train must encode");
    client.send_datagram(train).unwrap();
    let mut got = Vec::new();
    for _ in 0..2 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("both dict items must be forwarded")
            .unwrap();
        got.push(buf[..n].to_vec());
    }
    assert_eq!(got, vec![b"via-a".to_vec(), b"via-b".to_vec()]);

    // Repeated flow indices in one dict train (multiple payloads of the same
    // flow) must resolve to one registry slot and dispatch every item: the
    // client stager legitimately batches a flow this way.
    let train = r2::encode_train_dict(&[a], &[(0, &b"dup-1"[..]), (0, &b"dup-2"[..])], 1472)
        .expect("repeated-index dict train must encode");
    client.send_datagram(train).unwrap();
    let mut dup = Vec::new();
    for _ in 0..2 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("both duplicate-id items must be forwarded")
            .unwrap();
        dup.push(buf[..n].to_vec());
    }
    assert_eq!(dup, vec![b"dup-1".to_vec(), b"dup-2".to_vec()]);

    rev2_teardown(client, task, holders_before).await;
}

/// `CTL SESS_CLOSE` reaps the session and its bindings immediately: a late
/// steady frame fails lookup, and the same wire id can be opened again (the
/// registry entry is gone, so this is a fresh install, not a reroute).
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_sess_close_reaps_bindings_on_the_live_path() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"open"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("open payload")
        .unwrap();
    assert_eq!(&buf[..n], b"open");
    rev2_expect_ack(&client, id).await;

    // SESS_CLOSE is processed on the connection's datagram task: wait for it to
    // be applied instead of racing a sleep.
    let closes_before = r2_count(&r2_stats::SESS_CLOSES);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::SessClose { sess: 1, reason: 0 }))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r2_count(&r2_stats::SESS_CLOSES) == closes_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "SESS_CLOSE must be processed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The binding is gone with the session: a late compressed frame is dropped.
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client.send_datagram(r2_steady_frame(id, b"stale")).unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a binding closed by SESS_CLOSE must never route again"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    // The id is not tombstoned: a fresh OPEN reinstalls it on the recreated
    // session (the wire id is never reused by a conforming client, but the
    // server's behaviour must be a new install, not a stale reroute).
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"reopen"))
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("a reopen after SESS_CLOSE must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"reopen");
    rev2_expect_ack(&client, id).await;

    rev2_teardown(client, task, holders_before).await;
}

/// `FLOW_CLOSE` removes the binding, and a repeated close for the same id is a
/// counted stale no-op that must not pay the stager/reassembler purge (the D3
/// change removes the binding first and only then runs the scoped cleanup).
/// Observable contract pinned here: the first close is counted as
/// `FLOW_CLOSES`, later ones as `STALE_CLOSES`, and a steady frame for the
/// closed id fails lookup either way.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_flow_close_removes_once_and_repeats_are_stale_noops() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"open"))
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("open payload")
        .unwrap();
    rev2_expect_ack(&client, id).await;

    let closes_before = r2_count(&r2_stats::FLOW_CLOSES);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::FlowClose { id }))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r2_count(&r2_stats::FLOW_CLOSES) == closes_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "FLOW_CLOSE must be processed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The binding is gone: a steady frame for it must fail lookup and never
    // reach the target again.
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client.send_datagram(r2_steady_frame(id, b"late")).unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a closed flow must never route again"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    // A retransmitted close is idempotent: `STALE_CLOSES` moves, `FLOW_CLOSES`
    // does not (the scoped purge is skipped because no binding was removed).
    let stale_before = r2_count(&r2_stats::STALE_CLOSES);
    let flow_closes_after_first = r2_count(&r2_stats::FLOW_CLOSES);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::FlowClose { id }))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r2_count(&r2_stats::STALE_CLOSES) == stale_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a repeated FLOW_CLOSE must be counted stale"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        r2_count(&r2_stats::FLOW_CLOSES),
        flow_closes_after_first,
        "a repeated close must not be counted as another removal"
    );

    rev2_teardown(client, task, holders_before).await;
}

/// Domain target end to end: the OPEN resolves synchronously and installs the
/// resolved address set, the first downlink reply from a resolved IP rebinds
/// with one `OPEN|SRC` (payload riding the binding frame), and the next reply
/// compresses to a two-byte steady frame.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_domain_open_and_downlink_rebind() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    // The seeded cache is host-keyed and carries no port: the queried port is
    // attached on return, so it must be the target's real listen port.
    let host = "rev2-domain.test";
    let port = dst.port();
    dns_cache_seed(host, port, dst).await;
    let (client, task) = rev2_pair().await;
    let mut buf = [0u8; 64];

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(
            id,
            1,
            &TargetAddr::Domain(host.into(), port),
            b"domain-open",
        ))
        .unwrap();
    let (n, relay) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the resolved domain OPEN must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], b"domain-open");
    rev2_expect_ack(&client, id).await;

    // First reply from the resolved address: rebind (domain bindings have no
    // reply source yet, so the server sends the actual source inline once).
    target.send_to(b"domain-first", relay).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("the first domain reply must arrive")
        .unwrap();
    let data = r2::decode_data(&frame).expect("rebind must be a rev2 DATA frame");
    assert_eq!(data.id, Some(id));
    assert_eq!(data.sess, Some(1), "the binding frame names its session");
    assert!(data.src, "the binding frame marks the address as a source");
    assert_eq!(
        data.addr,
        Some(TargetAddrRef::Ip(dst)),
        "the client must learn the target's actual reply source"
    );
    assert_eq!(data.payload, b"domain-first");

    // LOGIC-3: the client confirms every `OPEN|SRC` it decodes with
    // `CTL FLOW_ACK`; only then does the server classify the learned source as
    // steady. Wait for the server to process the ACK before relying on it.
    let acks_before = r2_count(&r2_stats::FLOW_ACKS_RECV);
    client
        .send_datagram(r2::encode_ctl(&r2::Ctl::FlowAck {
            id,
            status: r2::R2_ACK_OPEN,
        }))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r2_count(&r2_stats::FLOW_ACKS_RECV) == acks_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client FLOW_ACK must be processed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Second reply is compressed: the client confirmed the source.
    target.send_to(b"domain-steady", relay).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("the second domain reply must arrive")
        .unwrap();
    let data = r2::decode_data(&frame).expect("compressed downlink must be rev2 DATA");
    assert_eq!(data.id, Some(id));
    assert_eq!(data.sess, None);
    assert_eq!(data.addr, None);
    assert_eq!(data.payload, b"domain-steady");

    rev2_teardown(client, task, holders_before).await;
}

/// W5: a domain-open whose name is **warm in this thread's DNS memo** is served
/// synchronously in the datagram loop — forwarded, installed and ACKed with no
/// spawned resolver task — and `DNS_SYNC_OPENS` is the observable proof (it did
/// not exist before the fast path).
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_domain_open_warm_cache_takes_the_sync_fast_path() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let host = "rev2-sync.test";
    let port = dst.port();
    // Warm this thread's memo. `#[tokio::test]` is a current_thread runtime, so
    // the server's datagram task runs on this same thread and sees the memo.
    dns_cache_seed(host, port, dst).await;
    let sync_before = r2_count(&r2_stats::DNS_SYNC_OPENS);
    let (client, task) = rev2_pair().await;
    let mut buf = [0u8; 64];
    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(
            id,
            1,
            &TargetAddr::Domain(host.into(), port),
            b"warm",
        ))
        .unwrap();
    let (n, relay) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the warm-cache OPEN must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], b"warm");
    rev2_expect_ack(&client, id).await;
    assert!(
        r2_count(&r2_stats::DNS_SYNC_OPENS) > sync_before,
        "the synchronous fast path must serve the warm-cache domain OPEN"
    );
    // The binding is installed with the address the payload was sent to, so the
    // first reply is classified against it (a rebind frame, not a drop).
    target.send_to(b"warm-reply", relay).await.unwrap();
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the first reply must be a rev2 DATA frame");
    assert_eq!(data.id, Some(id));
    assert_eq!(data.sess, Some(1));
    assert!(data.src);
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(dst)));
    assert_eq!(data.payload, b"warm-reply");

    rev2_teardown(client, task, holders_before).await;
}

/// W4: a domain OPEN whose name is negatively cached (resolver failure/timeout)
/// stays on the cold path, is refused with `R2_REJECT_DNS`, and the loss is
/// booked as `DNS_OPEN_DNS_FAIL` — distinct from a policy drop and a session
/// refusal, so the payload loss is observable in the 60 s report.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_domain_open_resolution_failure_is_distinctly_counted() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    // A host-keyed negative verdict: the cold path's `resolve_all_cached` fails
    // without any upstream query, exactly like a resolver error/timeout would
    // (offline-deterministic).
    let host = "rev2-neg.test";
    dns_neg_cache_seed(host, port).await;
    let fails_before = r2_count(&r2_stats::DNS_OPEN_DNS_FAIL);
    let (client, task) = rev2_pair().await;
    let mut buf = [0u8; 64];
    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(
            id,
            1,
            &TargetAddr::Domain(host.into(), port),
            b"lost",
        ))
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a failed resolution must answer FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject {
            id: rejected,
            reason,
        } => {
            assert_eq!(rejected, id);
            assert_eq!(reason, r2::R2_REJECT_DNS);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }
    assert!(
        r2_count(&r2_stats::DNS_OPEN_DNS_FAIL) > fails_before,
        "the dropped payload must be booked as a DNS failure"
    );
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a name with no usable address delivers nothing (UDP loss, never a guess)"
    );
    rev2_teardown(client, task, holders_before).await;
}

/// W4: a domain OPEN whose every recorded address fails the SSRF policy is
/// refused and booked as `DNS_OPEN_POLICY_DROP` — the payload is undeliverable
/// **by policy**, never re-routed around the filter.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_domain_open_policy_drop_is_distinctly_counted() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let host = "rev2-policy.test";
    let port = dst.port();
    // The name resolves to loopback (as far as the cache is concerned) and the
    // connection runs the shipped `allow_private = false` policy. The warm memo
    // hit is filtered, so `resolve_forward_target` cannot answer and the cold
    // path scans the whole record set and rejects all of it.
    dns_cache_seed(host, port, dst).await;
    let policy_before = r2_count(&r2_stats::DNS_OPEN_POLICY_DROP);
    let (client, task) = rev2_pair_with(false).await;
    let mut buf = [0u8; 64];
    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(
            id,
            1,
            &TargetAddr::Domain(host.into(), port),
            b"private",
        ))
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a policy-filtered domain must answer FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject {
            id: rejected,
            reason,
        } => {
            assert_eq!(rejected, id);
            assert_eq!(reason, r2::R2_REJECT_POLICY);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }
    assert!(
        r2_count(&r2_stats::DNS_OPEN_POLICY_DROP) > policy_before,
        "the policy-refused payload must be booked distinctly"
    );
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "the SSRF policy must never be weakened to deliver the payload"
    );
    rev2_teardown(client, task, holders_before).await;
}

/// Await one downlink DATAGRAM (5 s budget).
async fn r2_read_frame(client: &quinn::Connection) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("a downlink frame must arrive")
        .unwrap()
}

/// Await one downlink DATAGRAM with a short budget; `None` means nothing was
/// emitted (used for ordering/negative assertions).
async fn r2_read_frame_timeout(client: &quinn::Connection, wait: Duration) -> Option<Bytes> {
    tokio::time::timeout(wait, client.read_datagram())
        .await
        .ok()
        .and_then(|r| r.ok())
}

/// Downlink staging against a live pair: a run of one is a steady frame, a run
/// of several is one dict `TRAIN` (same flow), a changed source port rebinds
/// with `OPEN|SRC` (the learned source compresses afterwards), and a reply over
/// the staging threshold drains the queue first (order) before going direct.
#[tokio::test]
async fn rev2_downlink_steady_train_and_port_rebind() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let other_port: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    // Mirror the ingest path: the accept loop records every destination it
    // sends to, which is the reply reader's other authorization source.
    remember_dst(&ss, 7, src);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, None);

    // A run of one is a steady frame (2 B header + id varint).
    assert!(matches!(h.reply(b"one", src), ReplyDisposition::Continue));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("a run of one must be steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.sess, None);
    assert_eq!(data.payload, b"one");

    // A run of two same-flow replies is one dict `TRAIN`.
    for payload in [&b"two"[..], b"three"] {
        assert!(matches!(h.reply(payload, src), ReplyDisposition::Continue));
    }
    assert_eq!(h.r2.flows.load().len(), 1);
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let train = r2::decode_train(&frame).expect("a run of two must be a dict TRAIN");
    let items: Vec<_> = train.items().collect();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|(id, _)| *id == binding.wire_id));
    assert_eq!(items[0].1, b"two");
    assert_eq!(items[1].1, b"three");

    // Same IP, new port: one OPEN|SRC binds the actual source, payload riding it.
    // The rebind item is drained immediately so the reply source is learned only
    // once the binding frame was actually queued.
    assert!(matches!(
        h.reply(b"port", other_port),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("a source rebind must be rev2 DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.sess, Some(7));
    assert!(data.src);
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(other_port)));
    assert_eq!(data.payload, b"port");
    assert_eq!(binding.reply_src(), Some(other_port));
    // LOGIC-3: teaching the peer the source only queued the binding frame, so
    // the shared table keeps classifying the learned source as `Rebind` until
    // the peer confirms it (`CLT FLOW_ACK`). A lost binding frame can therefore
    // never strand the flow on steady frames the peer cannot route.
    assert!(!binding.reply_src_acked());
    assert!(matches!(
        h.r2.flows.load().match_source(other_port),
        Some(SourceMatch::Rebind(_))
    ));
    // The peer decodes the `OPEN|SRC` and ACKs it (`mark_reply_src_acked` is
    // what the server's `FlowAck` handler calls; see the handler-level test).
    binding.mark_reply_src_acked();
    assert!(matches!(
        h.r2.flows.load().match_source(other_port),
        Some(SourceMatch::Exact(_))
    ));

    // ...and the learned port compresses from now on.
    assert!(matches!(
        h.reply(b"after", other_port),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("post-rebind downlink must be steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.sess, None);
    assert_eq!(data.payload, b"after");

    // Ordering across the staging boundary: a queued small reply goes out
    // before a subsequent reply too large to stage, and that large reply is
    // rev2 DATA (one frame at this payload), never the legacy v2 form.
    let big = vec![0x5Au8; BATCH_SMALL_MAX + 1];
    assert!(matches!(
        h.reply(b"small-first", other_port),
        ReplyDisposition::Continue
    ));
    assert!(matches!(
        h.reply(&big, other_port),
        ReplyDisposition::Continue
    ));
    let first = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&first).expect("the queued small reply must be steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.payload, b"small-first");
    let second = r2_read_frame(&client_conn).await;
    assert!(
        r2::is_r2(&second),
        "a >512 B reply must stay on the rev2 wire"
    );
    let data =
        r2::decode_data(&second).expect("a fitting oversized reply must be rev2 steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.sess, None);
    assert_eq!(data.addr, None);
    assert_eq!(data.payload, &big[..]);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// A domain binding has no exact source until one is learned: a reply from any
/// address in the binding's validated `resolved` set triggers one `OPEN|SRC`
/// rebind (this is the domain downlink-compression path).
#[tokio::test]
async fn rev2_downlink_domain_resolved_ip_rebinds() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let resolved: SocketAddr = "203.0.113.7:53".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(
        TargetAddr::Domain("rev2.example".into(), 53),
        vec![resolved],
    );
    remember_dst(&ss, 7, resolved);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, None);
    assert!(matches!(
        h.reply(b"domain-rebind", resolved),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("domain rebind must be rev2 DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.sess, Some(7));
    assert!(data.src);
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(resolved)));
    assert_eq!(data.payload, b"domain-rebind");
    assert_eq!(binding.reply_src(), Some(resolved));

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// PERF/W8: the one-entry reply-source memo in front of `match_source` makes a
/// steady request/response flow pay **one** reverse-table scan, not one per
/// reply. (`match_scans` is the reader-local scan counter the memo exists to
/// keep at one.)
#[tokio::test]
async fn reply_source_memo_skips_repeated_scans() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, None);
    assert_eq!(h.r2.match_scans, 0);

    // First reply scans once and caches `Exact` (the binding's target is the
    // source, so no binding frame is needed).
    assert!(matches!(h.reply(b"one", src), ReplyDisposition::Continue));
    assert_eq!(h.r2.match_scans, 1, "the first reply must run the scan");
    for payload in [&b"two"[..], b"three", b"four"] {
        assert!(matches!(h.reply(payload, src), ReplyDisposition::Continue));
    }
    assert_eq!(
        h.r2.match_scans, 1,
        "repeated replies from the memoized source must not rescan"
    );
    // The four steady replies drain as one compressed run (DATA or a same-flow
    // TRAIN); the memo's contract is the scan count above.
    assert_eq!(h.drain(), StageDrain::Ok);
    assert_eq!(binding.state(), FlowState::Open);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The memo must **not** override a rebind or the peer's `FLOW_ACK`: learning
/// the source invalidates it (the next reply rescans and re-sends the binding
/// frame, as the no-memo path always did), and the ACK invalidates it again so
/// the flow compresses on the next reply instead of re-sending forever.
#[tokio::test]
async fn reply_source_memo_invalidates_on_rebind_and_flow_ack() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let target: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let learned: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(target), Vec::new());
    remember_dst(&ss, 7, target);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, None);

    // Same IP, new port: one OPEN|SRC rebind, source learned on `Sent`.
    assert!(matches!(
        h.reply(b"first", learned),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.r2.match_scans, 1);
    assert_eq!(binding.reply_src(), Some(learned));
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("a rebind must be rev2 DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert!(data.src);
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(learned)));

    // The memo recorded `reply_src = None`; `set_reply_src` just changed it, so
    // the next reply must rescan (and still rebind: not ACKed yet).
    assert!(matches!(
        h.reply(b"second", learned),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.r2.match_scans, 2, "a learned source invalidates the memo");
    assert!(!binding.reply_src_acked());
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("the un-ACKed source must rebind again");
    assert_eq!(data.id, Some(binding.wire_id));
    assert!(data.src);

    // The peer's FLOW_ACK (the CTL handler's `mark_reply_src_acked`) changes the
    // other observed field: the next reply rescans and now compresses.
    binding.mark_reply_src_acked();
    assert!(matches!(
        h.reply(b"third", learned),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.r2.match_scans, 3, "a FLOW_ACK invalidates the memo");
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = r2::decode_data(&frame).expect("the ACKed source must compress to steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert!(data.sess.is_none() && data.addr.is_none());
    assert_eq!(data.payload, b"third");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// The memo must not survive a reverse-table change or serve a closed binding:
/// an install (new snapshot) and a `Closed` mark both invalidate it, so the
/// verdict always comes from the current table.
#[tokio::test]
async fn reply_source_memo_invalidates_on_table_change_and_close() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let other: SocketAddr = "203.0.113.77:53".parse().unwrap();
    let (ss, r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, None);

    assert!(matches!(h.reply(b"a", src), ReplyDisposition::Continue));
    assert!(matches!(h.reply(b"b", src), ReplyDisposition::Continue));
    assert_eq!(h.r2.match_scans, 1, "the second reply is a memo hit");

    // A new binding is published into the session's reverse table: the
    // snapshot pointer changes, so the memo is invalid and a reply from the
    // new source is classified by the scan.
    let other_binding = FlowBinding::new_shared(
        r2::make_wire_id(2, false).unwrap(),
        7,
        TargetAddr::Ip(other),
    );
    other_binding.mark_open();
    r2_flows.rcu(|old| {
        let mut next = (**old).clone();
        assert!(next.insert(other_binding.clone()));
        Arc::new(next)
    });
    assert!(matches!(h.reply(b"c", other), ReplyDisposition::Continue));
    assert_eq!(
        h.r2.match_scans, 2,
        "a reverse-table change must invalidate the memo"
    );

    // A closed binding must never be served from the memo even though the
    // snapshot is unchanged (close paths mark first, then republish). With no
    // live match the restricted policy refuses the reply — the shared refusal
    // counter moving is the observable proof it was dropped, not compressed.
    other_binding.mark_closed();
    let refused_before = dgram_drops::snapshot().refused;
    assert!(matches!(h.reply(b"d", other), ReplyDisposition::Continue));
    assert_eq!(
        h.r2.match_scans, 3,
        "a closed binding must invalidate the memo"
    );
    assert!(
        dgram_drops::snapshot().refused > refused_before,
        "a reply from a closed binding must be refused, never compressed"
    );
    assert_eq!(binding.state(), FlowState::Open);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// `SESS_CLOSE` / `FLOW_CLOSE` teardown at the state level: the session entry,
/// its socket/task/permit and every registry binding go together, and a
/// per-flow close removes exactly one binding from both tables.
#[tokio::test]
async fn rev2_close_paths_remove_bindings_from_both_tables() {
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    let state = R2ConnState::new();
    assert!(state.registry.insert(binding.clone()).is_ok());
    assert_eq!(ss.shard(7).read().len(), 1);

    // FLOW_CLOSE: one binding, both tables.
    assert!(r2_remove_flow(&ss, &state, binding.wire_id).is_some());
    assert!(state.registry.get(binding.wire_id).is_none());
    assert_eq!(binding.state(), FlowState::Closed);
    assert!(r2_flows.load().is_empty());
    assert!(
        r2_remove_flow(&ss, &state, binding.wire_id).is_none(),
        "a second FLOW_CLOSE is a no-op"
    );

    // SESS_CLOSE: entry removed immediately, bindings gone with it.
    let (ss2, r2_flows2, binding2) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    let state2 = R2ConnState::new();
    assert!(state2.registry.insert(binding2.clone()).is_ok());
    assert!(r2_close_session(&ss2, &state2, 7));
    assert!(
        ss2.shard(7).read().get(&7).is_none(),
        "the session entry must be removed immediately"
    );
    assert!(
        state2.registry.get(binding2.wire_id).is_none(),
        "its bindings must be removed from the connection registry"
    );
    assert_eq!(binding2.state(), FlowState::Closed);
    assert!(r2_flows2.load().is_empty());
    assert!(
        !r2_close_session(&ss2, &state2, 7),
        "second close is a no-op"
    );
}

/// The CAPS reply throttle is the spec's ~100 ms, and "never replied" is always
/// due (the `0` stamp cannot mean "replied at process start").
#[test]
fn rev2_caps_reply_throttle_is_100ms() {
    assert!(r2_caps_due(0, 1));
    assert!(r2_caps_due(0, 999_999));
    assert!(!r2_caps_due(100, 150));
    assert!(!r2_caps_due(100, 199));
    assert!(r2_caps_due(100, 200));
    assert!(r2_caps_due(100, 100 + R2_CAPS_MIN_INTERVAL_MS + 1));
}

// ---------------------------------------------------------------------------
// MQP-3 rev2 FRAG (Phase 1b: all UDP payloads up to 8 KiB use rev2)
// ---------------------------------------------------------------------------

/// Split `payload` into rev2 `FRAG` frames the way the uplink sender does:
/// `Some(id)+Some(addr)` = first fragment carries `OPEN`; `Some(id)` alone =
/// steady fragments; `None+Some(addr)` = every fragment carries `INLINE`.
///
/// Scripted here (rather than via `R2Fragmenter`) so the test can send the
/// frames in any order and assert on out-of-order reassembly.
fn r2_frag_frames(
    id: Option<u32>,
    sess: Option<u32>,
    addr: Option<&TargetAddr>,
    payload: &[u8],
    limit: usize,
) -> Vec<Bytes> {
    let header_len = |r: &TargetAddrRef<'_>| r.header().expect("test address must encode").len();
    let (first_hdr, rest_hdr) = match (id, addr) {
        (Some(wid), Some(a)) => (
            r2::frag_open_len(wid, header_len(&a.as_ref()), 0),
            r2::frag_steady_len(wid, 0),
        ),
        (Some(wid), None) => {
            let h = r2::frag_steady_len(wid, 0);
            (h, h)
        }
        (None, Some(a)) => {
            let h = r2::frag_inline_len(header_len(&a.as_ref()), 0);
            (h, h)
        }
        (None, None) => panic!("an inline fragment needs an address"),
    };
    let first_chunk = limit - first_hdr;
    let rest_chunk = limit - rest_hdr;
    assert!(first_chunk > 0 && rest_chunk > 0);
    let total = if payload.len() <= first_chunk {
        1usize
    } else {
        1 + (payload.len() - first_chunk).div_ceil(rest_chunk)
    };
    assert!(total <= usize::from(r2::R2_MAX_FRAG_TOTAL));
    let mut frames = Vec::with_capacity(total);
    let mut offset = 0usize;
    for idx in 0..total {
        let remaining = payload.len() - offset;
        let chunk_len = if idx == 0 {
            first_chunk.min(remaining)
        } else {
            rest_chunk.min(remaining)
        };
        let chunk = &payload[offset..offset + chunk_len];
        let body = match (id, addr) {
            (Some(wid), Some(a)) if idx == 0 => r2::encode_frag_open(
                wid,
                sess.expect("open needs a session"),
                &a.as_ref(),
                false,
                7,
                idx as u8,
                total as u8,
                chunk,
                limit,
            ),
            (Some(wid), _) => r2::encode_frag_steady(wid, 7, idx as u8, total as u8, chunk, limit),
            (None, Some(a)) => r2::encode_frag_inline(
                sess.expect("inline needs a session"),
                &a.as_ref(),
                false,
                7,
                idx as u8,
                total as u8,
                chunk,
                limit,
            ),
            (None, None) => unreachable!(),
        }
        .expect("fragment frame must encode");
        frames.push(body);
        offset += chunk_len;
    }
    frames
}

/// Read downlink frames until the rev2 reassembler completes a payload.
async fn r2_collect_reassembled(
    client: &quinn::Connection,
    reasm: &mut R2Reassembler,
    max_frames: usize,
) -> Option<myquic2::udp::R2Assembled> {
    for _ in 0..max_frames {
        let d = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
            .await
            .expect("a downlink frame must arrive")
            .unwrap();
        assert!(
            r2::is_r2(&d),
            "Phase 1b must carry every downlink frame on the rev2 wire"
        );
        let f = r2::decode_frag(&d).expect("a fragmented downlink must be rev2 FRAG");
        if let Some(done) = reasm.push(&d, &f, coarse_millis()) {
            return Some(done);
        }
    }
    None
}

/// Downlink unit-test harness: the locals `handle_session_reply` needs, plus a
/// connection-scoped stager, so a test can drive several replies/ sessions
/// through the production reply body and drain once.
struct R2ReplyHarness {
    session: u32,
    server: quinn::Connection,
    r2: R2ReplyState,
    frag2: R2Fragmenter,
    flows: Arc<arc_swap::ArcSwap<FlowTable>>,
    stage: Arc<parking_lot::Mutex<R2Stager>>,
    limit: usize,
    last_probe: u64,
    last_touch: u64,
    last_refresh: u64,
    last2: Arc<std::sync::atomic::AtomicU64>,
    recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
    allow_snap: Option<Arc<RecentAddrs>>,
    allow_epoch: u64,
    reply_filter: ReplyFilter,
}

impl R2ReplyHarness {
    fn new(
        session: u32,
        ss: &SessTable,
        server: quinn::Connection,
        stage: Arc<parking_lot::Mutex<R2Stager>>,
        conn: Option<Arc<R2ConnState>>,
    ) -> Self {
        let (last2, recent, recent_epoch, flows, r2_flows) = {
            let r = ss.shard(session).read();
            let e = r.get(&session).expect("fixture session");
            (
                e.last.clone(),
                e.recent.clone(),
                e.recent_epoch.clone(),
                e.flows.clone(),
                e.r2_flows.clone(),
            )
        };
        let limit = server.max_datagram_size().unwrap_or(0);
        Self {
            session,
            server,
            r2: R2ReplyState::new(r2_flows, conn.clone()),
            // The reply sender follows the connection's revision; a fixture
            // without a connection is the shipped rev2 default.
            frag2: R2Fragmenter::new_with_wire(conn.as_ref().map_or(Wire::Rev2, |c| c.wire())),
            flows,
            stage,
            limit,
            last_probe: 0,
            last_touch: 0,
            last_refresh: coarse_millis(),
            last2,
            recent,
            recent_epoch,
            allow_snap: None,
            allow_epoch: u64::MAX,
            reply_filter: ReplyFilter::Restricted,
        }
    }

    /// Run this harness with another reply-source policy (full-cone tests).
    fn with_filter(mut self, filter: ReplyFilter) -> Self {
        self.reply_filter = filter;
        self
    }

    fn reply(&mut self, payload: &[u8], src: SocketAddr) -> ReplyDisposition {
        handle_session_reply(
            &self.server,
            self.session,
            payload,
            src,
            self.reply_filter,
            &mut self.r2,
            &self.stage,
            &mut self.frag2,
            self.flows.as_ref(),
            &mut self.limit,
            &mut self.last_probe,
            &mut self.last_touch,
            &mut self.last_refresh,
            self.last2.as_ref(),
            self.recent.as_ref(),
            self.recent_epoch.as_ref(),
            &mut self.allow_snap,
            &mut self.allow_epoch,
        )
    }

    /// Drain the connection stager once (the session reader's burst boundary).
    fn drain(&mut self) -> StageDrain {
        drain_stage(
            &self.server,
            &self.stage,
            &mut self.limit,
            &mut self.last_probe,
        )
    }
}

/// Large uplink: fragmented `OPEN` (sent out of order) installs the flow,
/// delivers the whole payload and is ACKed; fragmented steady frames then
/// resolve through the registry at completion.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_frag_large_uplink_open_and_steady_roundtrip() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 8192];
    let limit = client
        .max_datagram_size()
        .expect("DATAGRAM is negotiated by the test transport");

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    let big_open = vec![0xA1u8; 2500];
    let frames = r2_frag_frames(
        Some(id),
        Some(1),
        Some(&TargetAddr::Ip(dst)),
        &big_open,
        limit,
    );
    assert!(frames.len() > 1, "fixture must exceed one rev2 frame");
    // Out of order: every steady fragment first, the OPEN-carrying fragment
    // last. The reassembler keeps the context from whichever fragment has it
    // and routes the whole payload once the set completes.
    for frame in frames.iter().skip(1).rev() {
        client.send_datagram(frame.clone()).unwrap();
    }
    client.send_datagram(frames[0].clone()).unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), target.recv_from(&mut buf))
        .await
        .expect("the reassembled OPEN payload must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], &big_open[..]);
    rev2_expect_ack(&client, id).await;

    // Fragmented steady frame set for the now-installed flow.
    let big_steady = vec![0xB2u8; 4000];
    let frames = r2_frag_frames(Some(id), None, None, &big_steady, limit);
    assert!(frames.len() > 1);
    for frame in &frames {
        client.send_datagram(frame.clone()).unwrap();
    }
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), target.recv_from(&mut buf))
        .await
        .expect("the reassembled steady payload must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], &big_steady[..]);

    rev2_teardown(client, task, holders_before).await;
}

/// A fragmented `OPEN` runs the same SSRF policy as a single-frame one: the
/// whole reassembled payload is refused before any session/forward, with
/// `FLOW_REJECT(policy)` and no binding installed.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_frag_open_policy_refusal_rejects() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair_with(false).await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 8192];
    let limit = client.max_datagram_size().unwrap();

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    let payload = vec![0xCCu8; 2200];
    for frame in r2_frag_frames(
        Some(id),
        Some(1),
        Some(&TargetAddr::Ip(dst)),
        &payload,
        limit,
    ) {
        client.send_datagram(frame).unwrap();
    }
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a fragmented OPEN to a filtered target must be refused before forwarding"
    );
    let frame = tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
        .await
        .expect("the refused fragmented OPEN must be answered with FLOW_REJECT")
        .unwrap();
    match r2::decode_ctl(&frame).expect("FLOW_REJECT must decode") {
        r2::Ctl::FlowReject {
            id: rejected,
            reason,
        } => {
            assert_eq!(rejected, id);
            assert_eq!(reason, r2::R2_REJECT_POLICY);
        }
        other => panic!("expected FLOW_REJECT, got {other:?}"),
    }
    // Nothing was installed: a compressed successor fails lookup.
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    client
        .send_datagram(r2_steady_frame(id, b"after-reject"))
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    rev2_teardown(client, task, holders_before).await;
}

/// A fragmented steady payload for an id the connection never installed is
/// dropped at completion (the registry is consulted only once the whole
/// payload is back), never guessed from the fragments.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_frag_unknown_steady_id_is_dropped() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 8192];
    let limit = client.max_datagram_size().unwrap();

    rev2_handshake(&client).await;
    let unknown = r2::make_wire_id(9, false).unwrap();
    let unknown_before = r2_count(&r2_stats::UNKNOWN_ID);
    let payload = vec![0x11u8; 2200];
    for frame in r2_frag_frames(Some(unknown), None, None, &payload, limit) {
        client.send_datagram(frame).unwrap();
    }
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a fragmented unknown id must never be forwarded"
    );
    assert!(r2_count(&r2_stats::UNKNOWN_ID) > unknown_before);

    rev2_teardown(client, task, holders_before).await;
}

/// A partial that never completes is reaped by the shared reassembly timeout:
/// fragments arriving after the expiry cannot complete a payload, so nothing is
/// forwarded and nothing is delivered to a target.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev2_frag_partial_expires() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev2_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 8192];
    let limit = client.max_datagram_size().unwrap();

    rev2_handshake(&client).await;
    let id = r2::make_wire_id(1, false).unwrap();
    client
        .send_datagram(r2_open_frame(id, 1, &TargetAddr::Ip(dst), b"open"))
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("small OPEN must be forwarded");
    rev2_expect_ack(&client, id).await;

    let payload = vec![0xDDu8; 2500];
    let frames = r2_frag_frames(Some(id), None, None, &payload, limit);
    assert!(frames.len() > 1);
    client.send_datagram(frames[0].clone()).unwrap();
    // Past the 2 s reassembly window plus a sweep tick.
    tokio::time::sleep(Duration::from_millis(FRAG_TIMEOUT_MS + 900)).await;
    for frame in &frames[1..] {
        client.send_datagram(frame.clone()).unwrap();
    }
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(500)).await,
        None,
        "fragments after the partial expired must not complete a payload"
    );

    rev2_teardown(client, task, holders_before).await;
}

/// Large downlink: all three rev2 addressing modes — steady (known flow),
/// `OPEN|SRC` rebind (learned source), and INLINE (no flow) — are carried as
/// rev2 FRAG when the reply exceeds one frame, and reassemble to the exact
/// payload/context on the peer.
#[tokio::test]
async fn rev2_frag_large_downlink_modes() {
    let (client, server) = stream_test_pair().await;
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let big = vec![0x5Au8; 3000];
    let limit = server.max_datagram_size().unwrap();
    assert!(
        r2::data_steady_len(r2::make_wire_id(1, false).unwrap(), big.len()) > limit,
        "fixture must exceed one rev2 DATA frame"
    );

    // Exact -> steady fragments (id only; no session/address context).
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _f, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), None);
    assert!(matches!(h.reply(&big, src), ReplyDisposition::Continue));
    let mut reasm = R2Reassembler::new();
    let done = r2_collect_reassembled(&client, &mut reasm, 16)
        .await
        .expect("the steady fragment set must complete");
    assert_eq!(done.wire_id, Some(binding.wire_id));
    assert_eq!(done.sess, None);
    assert_eq!(done.addr, None);
    assert_eq!(done.payload, Bytes::from(big.clone()));
    assert!(
        r2_count(&r2_stats::STEADY_SENT) > 0,
        "the steady fragment send must be counted"
    );

    // Rebind -> the first fragment carries OPEN|SRC, later ones are steady.
    let bound: SocketAddr = "203.0.113.9:4242".parse().unwrap();
    let rebind_src: SocketAddr = "203.0.113.9:5000".parse().unwrap();
    let (ss, _f, binding) = rev2_reply_fixture(TargetAddr::Ip(bound), Vec::new());
    remember_dst(&ss, 7, rebind_src);
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), None);
    assert!(matches!(
        h.reply(&big, rebind_src),
        ReplyDisposition::Continue
    ));
    let mut reasm = R2Reassembler::new();
    let done = r2_collect_reassembled(&client, &mut reasm, 16)
        .await
        .expect("the rebind fragment set must complete");
    assert_eq!(done.wire_id, Some(binding.wire_id));
    assert_eq!(done.sess, Some(7));
    assert_eq!(done.addr, Some(TargetAddr::Ip(rebind_src)));
    assert!(done.src, "the binding frame marks the address as a source");
    assert_eq!(done.payload, Bytes::from(big.clone()));
    assert_eq!(binding.reply_src(), Some(rebind_src));

    // Inline -> no flow matches (the binding names another IP); the reply is
    // self-describing and still authorized by the session's destination list.
    let inline_src: SocketAddr = "198.51.100.77:7777".parse().unwrap();
    let other = TargetAddr::Ip("203.0.113.9:4242".parse().unwrap());
    let (ss, _f, _binding) = rev2_reply_fixture(other, Vec::new());
    remember_dst(&ss, 7, inline_src);
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), None);
    assert!(matches!(
        h.reply(&big, inline_src),
        ReplyDisposition::Continue
    ));
    let mut reasm = R2Reassembler::new();
    let done = r2_collect_reassembled(&client, &mut reasm, 16)
        .await
        .expect("the inline fragment set must complete");
    assert_eq!(done.wire_id, None);
    assert_eq!(done.sess, Some(7));
    assert_eq!(done.addr, Some(TargetAddr::Ip(inline_src)));
    assert!(done.src);
    assert_eq!(done.payload, Bytes::from(big));

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

// ---------------------------------------------------------------------------
// MQP-3 rev2 Phase 2: connection-level cross-session stager
// ---------------------------------------------------------------------------

/// Two associations on one connection: their small replies stage into the same
/// connection queue and go out as ONE cross-session dict `TRAIN` (one frame,
/// both wire ids and payloads).
#[tokio::test]
async fn rev2_stage_cross_session_dict_train() {
    let (client, server) = stream_test_pair().await;
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    insert_test_session(&ss, 7);
    insert_test_session(&ss, 8);
    let src_a: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let src_b: SocketAddr = "198.51.100.10:5353".parse().unwrap();
    let (_, binding_a) = insert_r2_binding(&ss, 7, 1, TargetAddr::Ip(src_a), Vec::new());
    let (_, binding_b) = insert_r2_binding(&ss, 8, 2, TargetAddr::Ip(src_b), Vec::new());
    remember_dst(&ss, 7, src_a);
    remember_dst(&ss, 8, src_b);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut ha = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), None);
    let mut hb = R2ReplyHarness::new(8, &ss, server.clone(), stage.clone(), None);

    // Both replies are staged before either drain: the shared queue holds a
    // Steady item from each session, which the round-robin drain packs together.
    assert!(matches!(
        ha.reply(b"from-a", src_a),
        ReplyDisposition::Continue
    ));
    assert!(matches!(
        hb.reply(b"from-b", src_b),
        ReplyDisposition::Continue
    ));
    assert_eq!(ha.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let train = r2::decode_train(&frame).expect("two sessions must share one dict TRAIN");
    let items: Vec<(u32, &[u8])> = train.items().collect();
    assert_eq!(items.len(), 2, "one frame carries both sessions' payloads");
    assert_eq!(items[0], (binding_a.wire_id, &b"from-a"[..]));
    assert_eq!(items[1], (binding_b.wire_id, &b"from-b"[..]));

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

/// Per-session FIFO survives the shared queue: replies pushed in order are
/// sent in order, across a train and the next single-frame drain.
#[tokio::test]
async fn rev2_stage_preserves_per_session_order_across_drains() {
    let (client, server) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage, None);

    for payload in [&b"a1"[..], b"a2", b"a3"] {
        assert!(matches!(h.reply(payload, src), ReplyDisposition::Continue));
    }
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let train = r2::decode_train(&frame).expect("three steady items must be one TRAIN");
    let got: Vec<&[u8]> = train.items().map(|(_, p)| p).collect();
    assert_eq!(got, vec![&b"a1"[..], b"a2", b"a3"]);
    assert!(train.items().all(|(id, _)| id == binding.wire_id));

    assert!(matches!(h.reply(b"a4", src), ReplyDisposition::Continue));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("a single queued reply must be steady DATA");
    assert_eq!(data.id, Some(binding.wire_id));
    assert_eq!(data.payload, b"a4");

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

/// A full staging queue drops the payload with `BUFFER_FULL` accounting and
/// never books it as sent or emits a frame.
#[tokio::test]
async fn rev2_stage_queue_full_drops_and_counts() {
    use std::sync::atomic::Ordering;

    let (client, server) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _r2_flows, _binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    // Capacity zero: every push is refused, even after the drain retry.
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::with_capacity(0, 0)));
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage, None);

    let full_before = dgram_drops::snapshot().buffer_full;
    let stage_before = r2_stats::STAGE_FULL_DROPS.load(Ordering::Relaxed);
    assert!(matches!(
        h.reply(b"dropped", src),
        ReplyDisposition::Continue
    ));
    assert!(
        dgram_drops::snapshot().buffer_full > full_before,
        "a full staging queue is a BUFFER_FULL drop"
    );
    assert!(
        r2_stats::STAGE_FULL_DROPS.load(Ordering::Relaxed) > stage_before,
        "the rev2 staging drop counter must move"
    );
    assert!(
        r2_read_frame_timeout(&client, Duration::from_millis(200))
            .await
            .is_none(),
        "a dropped staged payload must not be emitted"
    );

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

/// Connection teardown with queued items: the stager's `Drop` accounts every
/// queued payload as `EGRESS_DEAD` (nothing is lost silently).
#[tokio::test]
async fn rev2_stage_drop_accounts_queued_items() {
    use std::sync::atomic::Ordering;

    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    for i in 0..3u32 {
        stage
            .lock()
            .push(R2StageItem {
                session: 7,
                kind: R2StageKind::Steady {
                    wire_id: r2::make_wire_id(i + 1, false).unwrap(),
                },
                payload: Bytes::from_static(b"q"),
            })
            .expect("a fresh stager has room");
    }
    let dead_before = dgram_drops::snapshot().egress_dead;
    drop(stage);
    assert_eq!(
        dgram_drops::snapshot().egress_dead - dead_before,
        3,
        "every queued payload must be accounted on drop"
    );
    let _ = Ordering::Relaxed;
}

/// A dead connection surfaces as `StageDrain::Terminal`, which is what makes
/// the session readers take their existing flush-and-exit path.
#[tokio::test]
async fn rev2_stage_drain_reports_terminal_on_connection_lost() {
    let (client, server) = stream_test_pair().await;
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut limit = server.max_datagram_size().unwrap_or(0);
    let mut probe = 0u64;
    server.close(0u32.into(), b"bye");
    let mut verdict = StageDrain::Ok;
    for i in 0..100u32 {
        let _ = stage.lock().push(R2StageItem {
            session: 7,
            kind: R2StageKind::Steady {
                wire_id: r2::make_wire_id(i + 1, false).unwrap(),
            },
            payload: Bytes::from_static(b"dead"),
        });
        verdict = drain_stage(&server, &stage, &mut limit, &mut probe);
        if verdict == StageDrain::Terminal {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        verdict,
        StageDrain::Terminal,
        "a closed connection must surface as Terminal"
    );
    client.close(0u32.into(), b"done");
}

/// The drain-verdict mapping is the only place the stager's `DatagramSend`
/// surface turns into reader dispositions; pin every arm.
#[test]
fn rev2_stage_verdict_mapping() {
    assert_eq!(stage_verdict(None), StageDrain::Ok);
    assert_eq!(
        stage_verdict(Some(DatagramSend::Blocked)),
        StageDrain::Ok,
        "backpressure keeps the reader alive; the stager retained the rest"
    );
    assert_eq!(
        stage_verdict(Some(DatagramSend::TooLarge)),
        StageDrain::TooLarge
    );
    assert_eq!(
        stage_verdict(Some(DatagramSend::Unsupported)),
        StageDrain::Terminal
    );
    assert_eq!(
        stage_verdict(Some(DatagramSend::ConnectionLost)),
        StageDrain::Terminal
    );
    assert_eq!(
        stage_verdict(Some(DatagramSend::Sent)),
        StageDrain::Ok,
        "defensive: drain never reports a successful verdict"
    );
}

/// Fairness: a quiet session's reply is not starved by a busy session's queue.
/// The stager's round-robin cursor must pull the quiet session's head into the
/// very first frame, even when the busy session has dozens of items queued.
#[tokio::test]
async fn rev2_stage_fairness_quiet_session_shares_first_frame() {
    let (client, server) = stream_test_pair().await;
    let ss = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    insert_test_session(&ss, 7);
    insert_test_session(&ss, 8);
    let busy_src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let quiet_src: SocketAddr = "198.51.100.10:5353".parse().unwrap();
    let (_, busy_binding) = insert_r2_binding(&ss, 7, 1, TargetAddr::Ip(busy_src), Vec::new());
    let (_, quiet_binding) = insert_r2_binding(&ss, 8, 2, TargetAddr::Ip(quiet_src), Vec::new());
    remember_dst(&ss, 7, busy_src);
    remember_dst(&ss, 8, quiet_src);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut busy = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), None);
    let mut quiet = R2ReplyHarness::new(8, &ss, server.clone(), stage.clone(), None);

    for i in 0..40u8 {
        assert!(matches!(
            busy.reply(&[b'b', i], busy_src),
            ReplyDisposition::Continue
        ));
    }
    assert!(matches!(
        quiet.reply(b"quiet", quiet_src),
        ReplyDisposition::Continue
    ));
    assert_eq!(busy.drain(), StageDrain::Ok);
    // The first frame is a dict train that already carries the quiet session's
    // payload: the round-robin cursor interleaves it with the busy session.
    let frame = r2_read_frame(&client).await;
    let train = r2::decode_train(&frame).expect("a cross-session run must be a dict TRAIN");
    let ids: Vec<u32> = train.items().map(|(id, _)| id).collect();
    assert!(
        ids.contains(&quiet_binding.wire_id),
        "the quiet session must share the first frame, got ids {ids:?} (busy {})",
        busy_binding.wire_id
    );
    assert!(
        ids.contains(&busy_binding.wire_id),
        "the busy session's items must be in the same run"
    );

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

// ---------------------------------------------------------------------------
// MQP-3 rev2 final: server-owned full-cone flows + client replies
// ---------------------------------------------------------------------------

/// Full-cone: an unsolicited source with no matching flow opens one
/// server-owned flow — one `DATA OPEN|SRC` with an id from the server's half,
/// installed in both tables — and later replies from the same source compress.
#[tokio::test]
async fn rev2_full_cone_opens_server_owned_flow_and_compresses() {
    use std::sync::atomic::Ordering;

    let (client, server) = stream_test_pair().await;
    let peer: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    // The fixture's only binding names a different target, so the peer source
    // matches no flow and full-cone has to create one.
    let (ss, _flows, _other) = rev2_reply_fixture(
        TargetAddr::Ip("203.0.113.99:9".parse().unwrap()),
        Vec::new(),
    );
    let conn = R2ConnState::new();
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), Some(conn.clone()))
        .with_filter(ReplyFilter::FullCone);

    let flows_before = r2_stats::FULL_CONE_FLOWS.load(Ordering::Relaxed);
    assert!(matches!(
        h.reply(b"hello-peer", peer),
        ReplyDisposition::Continue
    ));
    assert!(
        r2_stats::FULL_CONE_FLOWS.load(Ordering::Relaxed) > flows_before,
        "the full-cone flow must be counted"
    );
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the first unsolicited reply must be rev2 DATA");
    let id = data
        .id
        .expect("full-cone must open a server-owned flow, not INLINE");
    assert!(
        r2::wire_id_server_owned(id),
        "the id must come from the server's half"
    );
    assert_eq!(data.sess, Some(7));
    assert!(data.src);
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(peer)));
    assert_eq!(data.payload, b"hello-peer");

    // The binding is installed in both tables, carries the remote source as its
    // target, learned the reply source, and is Open.
    let binding = conn
        .registry
        .get(id)
        .expect("the server-owned binding must be in the connection registry");
    assert_eq!(binding.session, 7);
    assert_eq!(binding.state(), FlowState::Open);
    assert_eq!(binding.reply_src(), Some(peer));
    assert_eq!(binding.target_ip(), Some(peer));
    assert!(matches!(
        h.r2.flows.load().match_source(peer),
        Some(SourceMatch::Exact(_))
    ));

    // Second reply from the same source: the reverse table hits `reply_src` and
    // the payload compresses to steady DATA (no second OPEN).
    assert!(matches!(
        h.reply(b"compressed", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the second reply must be steady DATA");
    assert_eq!(data.id, Some(id));
    assert_eq!(data.sess, None);
    assert_eq!(data.addr, None);
    assert_eq!(data.payload, b"compressed");

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

/// Non-full-cone mode is byte-identical to before: an unmatched (but
/// allowlisted) source keeps the self-describing INLINE fail-safe and opens no
/// flow.
#[tokio::test]
async fn rev2_non_full_cone_unmatched_reply_stays_inline() {
    let (client, server) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _flows, _other) = rev2_reply_fixture(
        TargetAddr::Ip("198.51.100.99:9".parse().unwrap()),
        Vec::new(),
    );
    remember_dst(&ss, 7, src);
    let conn = R2ConnState::new();
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage, Some(conn.clone()));

    assert!(matches!(
        h.reply(b"inline", src),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the unmatched reply must be rev2 DATA");
    assert_eq!(data.id, None, "restricted mode must not open a flow");
    assert_eq!(data.sess, Some(7));
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(src)));
    assert!(data.src);
    assert_eq!(data.payload, b"inline");
    assert!(
        conn.registry.is_empty(),
        "non-full-cone must not install a server-owned binding"
    );

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

/// Full-cone falls back to the INLINE fail-safe at either table bound (session
/// reverse table full, connection registry full), never panicking and never
/// leaving a half-installed binding.
#[tokio::test]
async fn rev2_full_cone_falls_back_to_inline_when_bounds_reached() {
    // (a) Per-session reverse table full: 63 extra bindings fill the 64-slot
    // session table, so the server-owned flow cannot be published.
    let (client, server) = stream_test_pair().await;
    let peer: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let (ss, _flows, _other) = rev2_reply_fixture(
        TargetAddr::Ip("203.0.113.99:9".parse().unwrap()),
        Vec::new(),
    );
    for local in 2..=64u32 {
        let target = TargetAddr::Ip(SocketAddr::from((
            std::net::Ipv4Addr::new(198, 51, 100, 7),
            local as u16,
        )));
        let _ = insert_r2_binding(&ss, 7, local, target, Vec::new());
    }
    let conn = R2ConnState::new();
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h = R2ReplyHarness::new(7, &ss, server.clone(), stage.clone(), Some(conn.clone()))
        .with_filter(ReplyFilter::FullCone);
    assert!(matches!(
        h.reply(b"table-full", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the fallback must be rev2 DATA");
    assert_eq!(data.id, None, "a full session table falls back to INLINE");
    assert_eq!(data.sess, Some(7));
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(peer)));
    assert!(data.payload == b"table-full");
    assert!(
        conn.registry.is_empty(),
        "the failed install must not leave a registry entry"
    );

    // (b) Connection registry full: pre-fill the per-connection flow cap.
    let conn2 = R2ConnState::new();
    for local in 0..conn2.registry.cap() {
        let target = TargetAddr::Ip(SocketAddr::from((
            std::net::Ipv4Addr::new(203, 0, 113, 9),
            local as u16,
        )));
        let binding = FlowBinding::new_shared(
            r2::make_wire_id(local as u32 + 1, false).unwrap(),
            999,
            target,
        );
        assert!(
            conn2.registry.insert(binding).is_ok(),
            "pre-fill insert {local} must fit the cap"
        );
    }
    assert_eq!(conn2.registry.len(), conn2.registry.cap());
    let (ss2, _f2, _b2) = rev2_reply_fixture(
        TargetAddr::Ip("203.0.113.99:9".parse().unwrap()),
        Vec::new(),
    );
    let stage2 = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    let mut h2 = R2ReplyHarness::new(7, &ss2, server.clone(), stage2, Some(conn2.clone()))
        .with_filter(ReplyFilter::FullCone);
    assert!(matches!(
        h2.reply(b"reg-full", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h2.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client).await;
    let data = r2::decode_data(&frame).expect("the fallback must be rev2 DATA");
    assert_eq!(data.id, None, "a full registry falls back to INLINE");
    assert_eq!(data.sess, Some(7));
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(peer)));
    assert!(data.payload == b"reg-full");

    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
}

// ---------------------------------------------------------------------------
// Severe-issue regression tests (2026-10-22 batch)
// ---------------------------------------------------------------------------

/// LOGIC-1 (server half): the generic datagram slow path registers a cancellable
/// waiter per session, and `SESS_CLOSE` flags exactly that session's waiters.
/// The entries are RAII-owned by the lookup task: a finished waiter removes its
/// own registration, so a long-lived connection cannot accumulate flags for the
/// sessions the peer churned through.
#[test]
fn generic_dns_waiters_are_registered_and_cancelled_per_session() {
    let state = R2ConnState::new();
    let ours = state.begin_dns_waiter(7);
    let other = state.begin_dns_waiter(8);
    assert_eq!(state.dns_waiter_count(7), 1);
    assert_eq!(state.dns_waiter_count(8), 1);
    assert!(!ours.is_cancelled() && !other.is_cancelled());

    state.cancel_dns_waiters_for_session(7);
    assert!(
        ours.is_cancelled(),
        "the closed session's generic DNS waiter must be flagged"
    );
    assert!(
        !other.is_cancelled(),
        "another session's waiter must be left alone"
    );
    // The entry survives the cancel: the lookup task owns its lifetime, so a
    // duplicate datagram in the same window still finds the flag.
    assert_eq!(state.dns_waiter_count(7), 1);
    drop(ours);
    assert_eq!(
        state.dns_waiter_count(7),
        0,
        "a finished waiter removes its own registration"
    );
    drop(other);
    assert_eq!(state.dns_waiter_count(8), 0);
}

/// LOGIC-1: a generic slow-path waiter that a `CTL SESS_CLOSE` cancelled while
/// its DNS lookup was in flight must not recreate the session (socket, reader
/// task and global permit) after the close reaped it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_generic_dns_waiter_does_not_create_a_session() {
    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(std::sync::atomic::Ordering::Relaxed);
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let state = R2ConnState::new();
    let waiter = state.begin_dns_waiter(41);
    // A `SESS_CLOSE` for session 41 landed while the lookup was in flight.
    state.cancel_dns_waiters_for_session(41);

    let delivered = deliver_resolved_server_dgram(
        &ss,
        &server_conn,
        0,
        41,
        "localhost",
        19811,
        Bytes::from_static(b"late"),
        true,
        Some(&state),
        Some(&waiter),
    )
    .await;
    assert!(
        !delivered,
        "a cancelled waiter reports no DNS verdict (nothing to cache)"
    );
    assert_eq!(
        ss.len(),
        0,
        "a late DNS answer must not publish a session for a closed association"
    );
    assert_eq!(
        session_holders().load(std::sync::atomic::Ordering::Relaxed),
        holders_before,
        "no session table may be registered as a holder"
    );
    drop(waiter);
    assert_eq!(state.dns_waiter_count(41), 0);
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// LOGIC-6: the generic slow path passes the DNS entry's *remaining* life into
/// the session destination memo, not the fresh-resolution `DNS_CACHE_TTL_MS`;
/// the `pin_life_ms` clamp is then real instead of being subverted by a hot
/// (already near-expiry) cache entry.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_dns_slow_path_clamps_the_session_memo_to_the_entry_life() {
    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(std::sync::atomic::Ordering::Relaxed);
    let (client_conn, server_conn) = stream_test_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let host = "slowpath-ttl.test";
    let port = dst.port();
    // Entry is 100 s old: only ~20 s of its 120 s TTL is left.
    dns_cache_seed_aged(
        host,
        port,
        dst,
        Duration::from_millis(DNS_CACHE_TTL_MS - 20_000),
    )
    .await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let state = R2ConnState::new();

    let delivered = deliver_resolved_server_dgram(
        &ss,
        &server_conn,
        0,
        42,
        host,
        port,
        Bytes::from_static(b"clamped"),
        true,
        Some(&state),
        None,
    )
    .await;
    assert!(!delivered, "a delivered datagram is not a DNS verdict");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the slow-path datagram must be delivered")
        .unwrap();
    assert_eq!(&buf[..n], b"clamped");
    let now = coarse_millis();
    let (_, life) = sess_dest_lookup_ttl(&ss, now, 42, host, port)
        .expect("the resolved destination must be memoized on the session");
    assert!(
        life <= 20_500,
        "the session memo must not outlive the DNS entry it came from (got {life} ms)"
    );
    assert!(life > 0, "the memo must still be live");

    // Return the session (and its global permit) before leaving the holder lock.
    if let Some(entry) = ss.take_session(42) {
        entry.reader.abort();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while session_holders().load(std::sync::atomic::Ordering::Relaxed) != holders_before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session holder count must return after the session is taken"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// LOGIC-3 (server half): the `FLOW_ACK` handler is what confirms a learned
/// downlink reply source. Until it runs, `SessionFlows::match_source` keeps
/// classifying the source as `Rebind` (re-send the idempotent `OPEN|SRC`, so a
/// lost binding frame cannot strand the flow); after it, the source is steady.
#[tokio::test]
async fn flow_ack_confirms_a_learned_reply_source() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    insert_test_session(&ss, 7);
    let state = R2ConnState::new();
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let learned: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let (r2_flows, binding) = insert_r2_binding(&ss, 7, 1, TargetAddr::Ip(src), Vec::new());
    assert!(state.registry.insert(binding.clone()).is_ok());

    // The reply side learned a source but has not yet been confirmed: the
    // binding frame may have been lost, so the shared table must keep rebinding.
    binding.set_reply_src(learned);
    assert!(!binding.reply_src_acked());
    assert!(matches!(
        r2_flows.load().match_source(learned),
        Some(SourceMatch::Rebind(_))
    ));

    let acks_before = r2_count(&r2_stats::FLOW_ACKS_RECV);
    let ack = r2::encode_ctl(&r2::Ctl::FlowAck {
        id: binding.wire_id,
        status: r2::R2_ACK_OPEN,
    });
    r2_handle_ctl(&ss, &server_conn, &state, &mut R2Reassembler::new(), &ack);
    assert!(
        binding.reply_src_acked(),
        "FLOW_ACK must confirm the learned reply source"
    );
    assert_eq!(r2_count(&r2_stats::FLOW_ACKS_RECV), acks_before + 1);
    assert!(matches!(
        r2_flows.load().match_source(learned),
        Some(SourceMatch::Exact(_))
    ));

    // An ACK for an id this side never installed is a cheap no-op.
    let stray = r2::make_wire_id(99, false).unwrap();
    let ack = r2::encode_ctl(&r2::Ctl::FlowAck {
        id: stray,
        status: r2::R2_ACK_OPEN,
    });
    r2_handle_ctl(&ss, &server_conn, &state, &mut R2Reassembler::new(), &ack);
    assert_eq!(
        r2_count(&r2_stats::FLOW_ACKS_RECV),
        acks_before + 1,
        "an ACK for an unknown id confirms nothing"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// PERF-1: the per-connection CTL rate budget refuses excess
/// `SESS_CLOSE`/`FLOW_CLOSE`/`FLOW_REJECT` frames as counted refusals without
/// touching any session/flow state.
#[tokio::test]
async fn ctl_rate_budget_drops_excess_close_frames() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let ss: SessTable = Arc::new(ShardedSessTable::new(ReplyFilter::Restricted));
    let state = R2ConnState::new();
    // Spend this connection's one-second CTL budget directly: the handler uses
    // the same `CtlState::ctl_allowed` gate.
    let now = mono_millis();
    for _ in 0..CTL_MAX_PER_SEC {
        assert!(state.ctl.ctl_allowed(now));
    }
    let closes_before = r2_count(&r2_stats::SESS_CLOSES) + r2_count(&r2_stats::STALE_CLOSES);
    let refused_before = dgram_drops::snapshot().refused;
    let frame = r2::encode_ctl(&r2::Ctl::SessClose { sess: 5, reason: 0 });
    r2_handle_ctl(&ss, &server_conn, &state, &mut R2Reassembler::new(), &frame);
    assert_eq!(
        dgram_drops::snapshot().refused,
        refused_before + 1,
        "an over-budget CTL is a counted refusal"
    );
    assert_eq!(
        r2_count(&r2_stats::SESS_CLOSES) + r2_count(&r2_stats::STALE_CLOSES),
        closes_before,
        "a refused frame must not touch session state"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// PERF-1: a `SESS_CLOSE` naming a session this connection never had (the common
/// duplicate/forged case) is O(1) in the registry's session index and must not
/// purge a live session's bindings.
#[tokio::test]
async fn unknown_sess_close_does_not_touch_a_live_sessions_bindings() {
    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(std::sync::atomic::Ordering::Relaxed);
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    let state = R2ConnState::new();
    assert!(state.registry.insert(binding.clone()).is_ok());

    assert!(
        !r2_close_session(&ss, &state, 99),
        "there was no session 99 to reap"
    );
    assert!(
        state.registry.get(binding.wire_id).is_some(),
        "a close for an unknown session must not purge another session's bindings"
    );
    assert_ne!(
        binding.state(),
        FlowState::Closed,
        "the live binding must not be marked closed"
    );
    assert!(
        ss.shard(7).read().get(&7).is_some(),
        "the untouched session entry must still be live"
    );
    assert_eq!(
        session_holders().load(std::sync::atomic::Ordering::Relaxed),
        holders_before + 1,
        "premise: the close's `take_session` registered the fixture table as a holder"
    );
    // Drain the fixture session so the table leaves the global holder count
    // exactly as this test found it (`take_session` pairs its own removal with a
    // `note_empty_state`, the same way `conn.closed`/`SESS_CLOSE` teardown do).
    if let Some(entry) = ss.take_session(7) {
        entry.reader.abort();
    }
    assert_eq!(
        session_holders().load(std::sync::atomic::Ordering::Relaxed),
        holders_before,
        "the test must leave the process-global holder count untouched"
    );
}

/// LOGIC-5: the stager retry trigger is "frames are still queued after a
/// drain". The probe is false for an empty stager, true while frames are
/// queued, and false again once a drain empties it — so the session reader's
/// retry timer exists only while a quiet tail is actually stranded.
#[tokio::test]
async fn stage_backlog_probe_arms_only_while_frames_are_queued() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new()));
    assert!(!stage_has_backlog(&stage), "an empty stager arms nothing");
    for i in 0..2u32 {
        stage
            .lock()
            .push(R2StageItem {
                session: 7,
                kind: R2StageKind::Steady {
                    wire_id: r2::make_wire_id(i + 1, false).unwrap(),
                },
                payload: Bytes::from_static(b"tail"),
            })
            .expect("a fresh stager has room");
    }
    assert!(
        stage_has_backlog(&stage),
        "queued frames are what arms the retry timer"
    );
    let mut limit = server_conn.max_datagram_size().unwrap_or(0);
    let mut probe = 0u64;
    assert_eq!(
        drain_stage(&server_conn, &stage, &mut limit, &mut probe),
        StageDrain::Ok
    );
    assert!(
        !stage_has_backlog(&stage),
        "an emptied stager disarms the retry timer"
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// OBS-1 (server half): a large reply's drop is booked exactly once, in the
/// class that actually lost it. Single-frame `Blocked`/`TooLarge` verdicts are
/// booked here (nothing else sees them); a fragmented drop is *not* re-booked
/// (the shared fragmenter accounts its own per-payload drop); `Terminal` ends
/// the reader.
#[tokio::test]
async fn large_reply_verdict_books_its_drop_once() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let mut limit = server_conn.max_datagram_size().unwrap_or(0);
    let mut probe = 0u64;

    let before = dgram_drops::snapshot();
    assert_eq!(
        large_reply_disposition(R2LargeReply::Sent, &server_conn, &mut limit, &mut probe),
        ReplyDisposition::Continue
    );
    assert_eq!(
        large_reply_disposition(R2LargeReply::Blocked, &server_conn, &mut limit, &mut probe),
        ReplyDisposition::Continue
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.buffer_full, 1,
        "a single-frame Blocked large reply is a BUFFER_FULL drop"
    );

    let before = dgram_drops::snapshot();
    assert_eq!(
        large_reply_disposition(R2LargeReply::TooLarge, &server_conn, &mut limit, &mut probe),
        ReplyDisposition::Continue
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(
        d.too_large, 1,
        "a single-frame TooLarge large reply is a TOO_LARGE drop"
    );

    // The fragmenter books its own drop: the reader must not double-book it.
    let before = dgram_drops::snapshot();
    assert_eq!(
        large_reply_disposition(
            R2LargeReply::FragDropped { reprobe: true },
            &server_conn,
            &mut limit,
            &mut probe
        ),
        ReplyDisposition::Continue
    );
    let d = dgram_drops::snapshot().since(&before);
    assert_eq!(d.buffer_full, 0, "fragmented drops are not re-booked");
    assert_eq!(d.too_large, 0, "fragmented drops are not re-booked");

    assert_eq!(
        large_reply_disposition(R2LargeReply::Terminal, &server_conn, &mut limit, &mut probe),
        ReplyDisposition::BreakSession
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// P2-12: the binary-private `RecentAddrs` layout must match the derivation the
/// lib's admission charge (`config::tuning::RECENT_ADDRS_BYTES`) uses — a
/// 16-slot `[Option<IpAddr>; 16]` ring plus an 8-byte cursor = 280 B on a
/// 64-bit host. `RECENT_ADDRS_BYTES` is private to the lib, so this asserts the
/// same expression and the concrete 280.
#[test]
fn recent_addrs_layout_matches_the_admission_derivation() {
    assert_eq!(RECENT_DST_CAP, 16);
    let derived = 16 * std::mem::size_of::<Option<IpAddr>>() + std::mem::size_of::<usize>();
    assert_eq!(
        std::mem::size_of::<RecentAddrs>(),
        derived,
        "the type layout must stay exactly the 16-slot ring plus its cursor"
    );
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(derived, 280, "16 x 16 B slots + 8 B cursor");
    }
}

/// PERF-2 regression: the per-source share of the pre-auth window must cap one
/// host at `MAX_PENDING_PER_IP` stalled handshakes, leave other source IPs
/// unaffected, and release reservations on every drop path (so a normal
/// connect/reconnect flow never stays refused).
#[test]
fn pending_window_has_a_per_ip_share_that_releases() {
    let slots = PendingAddrSlots::new();
    let ip: IpAddr = "192.0.2.9".parse().unwrap();
    let other: IpAddr = "192.0.2.10".parse().unwrap();
    let mut guards: Vec<_> = (0..MAX_PENDING_PER_IP)
        .map(|_| slots.try_acquire(ip).expect("under the per-IP share"))
        .collect();
    assert!(
        slots.try_acquire(ip).is_none(),
        "the whole process-wide pending budget must not be holdable by one IP"
    );
    // Another source has its own share (this is what turns a one-host denial
    // into a many-IP one).
    let other_guard = slots.try_acquire(other).expect("independent per-IP share");
    drop(other_guard);
    // Releasing any reservation makes room for the same IP again.
    guards.pop();
    drop(slots.try_acquire(ip).expect("one slot was released"));
    // Dropping the task's reservations (the failure/timeout paths) returns the
    // share completely: a stream of normal connects must never leave the IP
    // throttled.
    drop(guards);
    for _ in 0..MAX_PENDING_PER_IP {
        drop(slots.try_acquire(ip).expect("share released"));
    }
}

// ---------------------------------------------------------------------------
// MQP-3 rev3 server data plane (wire adapter, no-ACK context, control stream)
// ---------------------------------------------------------------------------

/// Live rev3 connection through the production ``handle_conn_with_wire`` path.
///
/// `handle_conn` (the unchanged wrapper) stays Rev2-default; this is the entry
/// point the wiring task will use with the configured revision.
async fn rev3_pair() -> (
    quinn::Connection,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (client_conn, server_conn) = stream_test_pair().await;
    let task = tokio::spawn(handle_conn_with_wire(
        server_conn,
        true,
        ReplyFilter::Restricted,
        Arc::new(tokio::sync::Semaphore::new(1)),
        MAX_CONNECTIONS,
        Wire::Rev3,
    ));
    (client_conn, task)
}

/// Internal flow id for a client/server-owned local counter, mirroring
/// `mqp::wire`'s mapping (`wire_id = local << 1 | owner`).
fn r3_wire_id(local: u32, server_owned: bool) -> u32 {
    (local << 1) | u32::from(server_owned)
}

/// rev3 end to end: `DATA OPEN`, steady `DATA`, `TRAIN` and `FRAG` all decode
/// through the wire adapter, route to the target, and **no `FLOW_ACK`** is ever
/// emitted (rev3 replaces the ACK with bounded context redundancy).
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev3_open_steady_train_and_frag_roundtrip_without_ack() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev3_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 8192];
    // Client-owned local 1 => fid 0 => internal wire_id 2.
    let wid = r3_wire_id(1, false);
    assert_eq!(wire::fid_for(wid), Some(0));

    // OPEN: forwarded + installed, with no ACK (or any datagram) back.
    let open = wire::encode_data_open(
        Wire::Rev3,
        wid,
        1,
        &TargetAddr::Ip(dst).as_ref(),
        false,
        b"rev3-open",
        1472,
    )
    .expect("rev3 OPEN encodes");
    client.send_datagram(open).unwrap();
    let (n, _relay) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the rev3 OPEN payload must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], b"rev3-open");
    assert_eq!(
        r2_read_frame_timeout(&client, Duration::from_millis(250)).await,
        None,
        "rev3 must not send FLOW_ACK (or any control DATAGRAM)"
    );

    // Steady frame resolves through the connection registry.
    client
        .send_datagram(wire::encode_data_steady(Wire::Rev3, wid, b"rev3-steady", 1472).unwrap())
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("steady rev3 frame must be forwarded")
        .unwrap();
    assert_eq!(&buf[..n], b"rev3-steady");

    // TRAIN: two payloads for one flow (rev3 SAME form).
    let train = wire::encode_train_same(Wire::Rev3, wid, &[&b"t1"[..], b"t2"], 1472).unwrap();
    client.send_datagram(train).unwrap();
    let mut got = Vec::new();
    while got.len() < 4 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("both TRAIN items must reach the target")
            .unwrap();
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"t1t2");

    // FRAG: one payload split over three rev3 fragments; the server's
    // reassembler decodes them through the wire adapter.
    let whole: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for idx in 0..3u8 {
        let chunk = &whole[usize::from(idx) * 1000..usize::from(idx + 1) * 1000];
        let frag = wire::encode_frag_steady(Wire::Rev3, wid, 7, idx, 3, chunk, 1472)
            .expect("rev3 fragment encodes");
        client.send_datagram(frag).unwrap();
    }
    let mut merged = Vec::new();
    while merged.len() < whole.len() {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
            .await
            .expect("the reassembled payload must reach the target")
            .unwrap();
        merged.extend_from_slice(&buf[..n]);
    }
    assert_eq!(merged, whole, "rev3 FRAG reassembly must be byte-exact");

    rev2_teardown(client, task, holders_before).await;
}

/// rev3: a compressed frame naming an unknown id is repaired with
/// `NEED_CONTEXT{fid}` on the reliable control stream (the no-ACK recovery
/// path), instead of only being counted.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev3_unknown_steady_id_sends_need_context_on_control_stream() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev3_pair().await;
    let (_ctl_tx, mut ctl_rx) = ctl_stream::open_client_stream(&client)
        .await
        .expect("rev3 control stream opens");
    let unknown = r3_wire_id(7, false);
    let fid = wire::fid_for(unknown).expect("client fid");

    // The control stream is accepted asynchronously by the accept loop; retry
    // the unknown-id frame until the repair arrives (the request is rate-limited
    // and simply counted if the stream is not up yet).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut repair = None;
    while tokio::time::Instant::now() < deadline {
        client
            .send_datagram(wire::encode_data_steady(Wire::Rev3, unknown, b"orphan", 1472).unwrap())
            .unwrap();
        match tokio::time::timeout(Duration::from_millis(100), ctl_rx.recv()).await {
            Ok(Ok(Some(CtlMessage::NeedContext { fid: got }))) => {
                repair = Some(got);
                break;
            }
            Ok(Ok(Some(other))) => panic!("unexpected server control message {other:?}"),
            Ok(Ok(None)) => panic!("the server closed the control stream"),
            Ok(Err(e)) => panic!("control stream error: {e:#}"),
            Err(_) => {} // not yet
        }
    }
    assert_eq!(
        repair,
        Some(fid),
        "the server must ask for the missing context of the unknown id"
    );
    assert!(
        r2_read_frame_timeout(&client, Duration::from_millis(200))
            .await
            .is_none(),
        "rev3 must never emit a FLOW_ACK/FLOW_REJECT DATAGRAM"
    );

    rev2_teardown(client, task, holders_before).await;
}

/// rev3 reliable control plane end to end: `ASSOC_CLOSE` on the control stream
/// reaps the association (its bindings stop resolving; later steady frames are
/// unknown and trigger the NEED_CONTEXT repair).
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev3_assoc_close_control_message_reaps_the_session() {
    use std::sync::atomic::Ordering;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev3_pair().await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let mut buf = [0u8; 64];
    let (mut ctl_tx, mut ctl_rx) = ctl_stream::open_client_stream(&client)
        .await
        .expect("rev3 control stream opens");
    // Create session 5 with an installed flow.
    let wid = r3_wire_id(1, false);
    client
        .send_datagram(
            wire::encode_data_open(
                Wire::Rev3,
                wid,
                5,
                &TargetAddr::Ip(dst).as_ref(),
                false,
                b"before-close",
                1472,
            )
            .unwrap(),
        )
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .expect("the OPEN payload must reach the target")
        .unwrap();
    assert_eq!(&buf[..n], b"before-close");

    // Close the association over the reliable stream.
    ctl_tx
        .send(CtlMessage::AssocClose { sess: 5, reason: 0 })
        .await
        .expect("ASSOC_CLOSE writes");

    // The close is processed asynchronously; keep sending the steady frame
    // until the binding is gone (observable as a NEED_CONTEXT repair).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut repaired = false;
    while tokio::time::Instant::now() < deadline {
        client
            .send_datagram(wire::encode_data_steady(Wire::Rev3, wid, b"after-close", 1472).unwrap())
            .unwrap();
        match tokio::time::timeout(Duration::from_millis(100), ctl_rx.recv()).await {
            Ok(Ok(Some(CtlMessage::NeedContext { .. }))) => {
                repaired = true;
                break;
            }
            Ok(Ok(Some(other))) => panic!("unexpected server control message {other:?}"),
            Ok(Ok(None)) => panic!("the server closed the control stream"),
            Ok(Err(e)) => panic!("control stream error: {e:#}"),
            Err(_) => {}
        }
    }
    assert!(
        repaired,
        "the closed association's binding must stop resolving (NEED_CONTEXT repair)"
    );
    // Drain anything delivered before the close was processed, then prove the
    // session is really gone.
    while rev2_recv_timeout(&target, &mut buf, Duration::from_millis(100))
        .await
        .is_some()
    {}
    client
        .send_datagram(wire::encode_data_steady(Wire::Rev3, wid, b"really-gone", 1472).unwrap())
        .unwrap();
    assert_eq!(
        rev2_recv_timeout(&target, &mut buf, Duration::from_millis(300)).await,
        None,
        "a steady frame for the closed session's flow must not be forwarded"
    );

    rev2_teardown(client, task, holders_before).await;
}

/// rev3 dispatch on the first bidi-stream byte: an MQP address `atyp` starts the
/// shipped TCP relay path (the consumed byte is fed to the header decoder), a
/// non-address byte is reset, and a second control stream is refused.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rev3_stream_first_byte_dispatch_and_second_control_stream() {
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt as _;

    let _holder_guard = holder_test_guard();
    let holders_before = session_holders().load(Ordering::Relaxed);
    let (client, task) = rev3_pair().await;

    // TCP-derived stream: atyp 0x01 + v4 + big-endian port, then app bytes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = listener.local_addr().unwrap();
    let mut hdr = vec![0x01u8];
    let SocketAddr::V4(v4) = tcp_addr else {
        panic!("loopback listener must be v4")
    };
    hdr.extend_from_slice(&v4.ip().octets());
    hdr.extend_from_slice(&v4.port().to_be_bytes());
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(&hdr).await.unwrap();
    send.write_all(b"rev3-tcp").await.unwrap();
    let (mut tcp, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the rev3 atyp stream must reach the TCP dial path")
        .unwrap();
    let mut tcp_buf = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut tcp_buf))
        .await
        .expect("relayed bytes must reach the target")
        .unwrap();
    assert_eq!(&tcp_buf, b"rev3-tcp");

    // A stream whose first byte is neither control marker nor atyp is reset.
    let bad_before = r2_count(&r2_stats::CTL_STREAM_BAD_FIRST);
    let (mut bad_send, mut bad_recv) = client.open_bi().await.unwrap();
    bad_send.write_all(&[0x00]).await.unwrap();
    assert_eq!(
        read_reset_code(&mut bad_recv).await,
        0x01,
        "an unclassifiable first byte resets 0x01"
    );
    assert!(
        r2_count(&r2_stats::CTL_STREAM_BAD_FIRST) > bad_before,
        "the unclassifiable stream must be counted"
    );

    // Exactly one control stream: the second marker stream is reset 0x05.
    let (_ctl_tx, mut ctl_rx) = ctl_stream::open_client_stream(&client)
        .await
        .expect("first control stream");
    // Wait until the server has claimed the stream: a NEED_CONTEXT repair for an
    // unknown id is the observable acceptance (there is no stream ack).
    let unknown = r3_wire_id(9, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut claimed = false;
    while tokio::time::Instant::now() < deadline {
        client
            .send_datagram(wire::encode_data_steady(Wire::Rev3, unknown, b"x", 1472).unwrap())
            .unwrap();
        if let Ok(Ok(Some(CtlMessage::NeedContext { .. }))) =
            tokio::time::timeout(Duration::from_millis(100), ctl_rx.recv()).await
        {
            claimed = true;
            break;
        }
    }
    assert!(claimed, "the first control stream must be accepted");
    let second_before = r2_count(&r2_stats::CTL_STREAM_SECOND);
    let (mut second_send, mut second_recv) = client.open_bi().await.unwrap();
    second_send.write_all(&[ctl_stream::MARKER]).await.unwrap();
    assert_eq!(
        read_reset_code(&mut second_recv).await,
        0x05,
        "a second control stream is a protocol violation"
    );
    assert!(
        r2_count(&r2_stats::CTL_STREAM_SECOND) > second_before,
        "the refused second control stream must be counted"
    );

    rev2_teardown(client, task, holders_before).await;
}

/// rev3 downlink no-ACK policy, client-owned flow: the first **K=2** replies of
/// a learned reply source carry the `SRC` context form (session-less, no ACK
/// gating), after which the flow compresses to steady frames.
#[tokio::test]
async fn rev3_downlink_k2_src_context_then_steady() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let target: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let learned: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(target), Vec::new());
    remember_dst(&ss, 7, target);
    let conn = R2ConnState::new_with_wire(Wire::Rev3);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new_with_wire(Wire::Rev3)));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, Some(conn));

    // Reply 1: same IP, new port -> one rev3 SRC context frame (session-less).
    assert!(matches!(
        h.reply(b"one", learned),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("rev3 SRC frame");
    assert_eq!(data.wire_id, Some(binding.wire_id));
    assert!(data.src, "the context form marks the address as a source");
    assert_eq!(data.sess, None, "rev3 SRC is session-less");
    assert_eq!(data.payload, b"one");
    assert_eq!(binding.reply_src(), Some(learned));
    assert!(
        !binding.reply_src_acked(),
        "rev3 does not wait for a client ACK; it counts K sends locally"
    );

    // Reply 2: second (and last) context frame.
    assert!(matches!(
        h.reply(b"two", learned),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("rev3 SRC frame");
    assert_eq!(data.wire_id, Some(binding.wire_id));
    assert!(data.src);
    assert_eq!(data.payload, b"two");
    assert!(
        binding.reply_src_acked(),
        "after K=2 context frames the source is confirmed locally"
    );

    // Reply 3: steady (the no-ACK policy replaces the FLOW_ACK round trip).
    assert!(matches!(
        h.reply(b"three", learned),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("compressed rev3 DATA");
    assert_eq!(data.wire_id, Some(binding.wire_id));
    assert!(!data.src);
    assert_eq!(data.sess, None);
    assert_eq!(data.addr, None);
    assert_eq!(data.payload, b"three");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 downlink, server-owned flow: full-cone install allocates a server-half
/// fid (14-bit mapping), the first two replies carry `OPEN_SRC` (session + addr),
/// then the flow compresses.
#[tokio::test]
async fn rev3_downlink_server_owned_open_src_then_steady() {
    use myquic2::mqp::r3;

    let (client_conn, server_conn) = stream_test_pair().await;
    let peer: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let (ss, _flows, _other) = rev2_reply_fixture(
        TargetAddr::Ip("203.0.113.99:9".parse().unwrap()),
        Vec::new(),
    );
    let conn = R2ConnState::new_with_wire(Wire::Rev3);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new_with_wire(Wire::Rev3)));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, Some(conn.clone()))
        .with_filter(ReplyFilter::FullCone);

    assert!(matches!(
        h.reply(b"hello-peer", peer),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("rev3 OPEN_SRC frame");
    let wid = data
        .wire_id
        .expect("full-cone must open a server-owned flow");
    assert!(r3::is_server_fid(
        wire::fid_for(wid).expect("server id maps to a fid")
    ));
    assert!(data.src, "the first reply teaches the actual source");
    assert_eq!(data.sess, Some(7), "OPEN_SRC keeps the session context");
    assert_eq!(data.addr, Some(TargetAddrRef::Ip(peer)));
    assert_eq!(data.payload, b"hello-peer");

    // K=2: the second reply repeats the context form even though the binding's
    // target already names the source (target_names_src would say Exact).
    assert!(matches!(
        h.reply(b"second", peer),
        ReplyDisposition::Continue
    ));
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("second OPEN_SRC frame");
    assert_eq!(data.wire_id, Some(wid));
    assert!(data.src);
    assert_eq!(data.payload, b"second");

    // Third reply compresses.
    assert!(matches!(
        h.reply(b"third", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("steady rev3 DATA");
    assert_eq!(data.wire_id, Some(wid));
    assert!(!data.src);
    assert_eq!(data.payload, b"third");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 downlink large replies: a reply above the small-staging threshold goes
/// out as one rev3 `DATA` frame, and a reply above the live path budget is
/// fragmented with rev3 `FRAG` frames (the client-side view of the same wire).
#[tokio::test]
async fn rev3_downlink_large_and_fragmented_replies() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    remember_dst(&ss, 7, src);
    let conn = R2ConnState::new_with_wire(Wire::Rev3);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new_with_wire(Wire::Rev3)));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, Some(conn));

    // One frame above the small-staging threshold: rev3 steady DATA.
    let big = vec![0x5Au8; BATCH_SMALL_MAX + 1];
    assert!(matches!(h.reply(&big, src), ReplyDisposition::Continue));
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("rev3 steady DATA");
    assert_eq!(data.wire_id, Some(binding.wire_id));
    assert!(data.sess.is_none() && data.addr.is_none() && !data.src);
    assert_eq!(data.payload, &big[..]);

    // Above the live DATAGRAM budget: rev3 FRAG, reassembled with the same
    // `R2Reassembler` the client runs.
    let huge = vec![0xA5u8; 5000];
    assert!(matches!(h.reply(&huge, src), ReplyDisposition::Continue));
    let mut reasm = R2Reassembler::new_with_wire(Wire::Rev3);
    let done = loop {
        let frame = r2_read_frame(&client_conn).await;
        let view = wire::decode_frag(Wire::Rev3, &frame).expect("rev3 FRAG frame");
        assert_eq!(view.wire_id, Some(binding.wire_id));
        if let Some(done) = reasm.push_view(&frame, &view, coarse_millis()) {
            break done;
        }
    };
    assert_eq!(done.wire_id, Some(binding.wire_id));
    assert_eq!(
        done.payload, huge,
        "rev3 downlink fragmentation must be byte-exact"
    );

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 client→server `NEED_CONTEXT` re-arms the downlink context window: the
/// repair message bumps the connection's epoch and the reply reader re-sends K=2
/// context frames for the flow before compressing again.
#[tokio::test]
async fn rev3_need_context_rearms_the_downlink_window() {
    let (client_conn, server_conn) = stream_test_pair().await;
    let peer: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let (ss, _flows, _other) = rev2_reply_fixture(
        TargetAddr::Ip("203.0.113.99:9".parse().unwrap()),
        Vec::new(),
    );
    let conn = R2ConnState::new_with_wire(Wire::Rev3);
    let stage = Arc::new(parking_lot::Mutex::new(R2Stager::new_with_wire(Wire::Rev3)));
    let mut h = R2ReplyHarness::new(7, &ss, server_conn.clone(), stage, Some(conn.clone()))
        .with_filter(ReplyFilter::FullCone);

    // Open the flow and run out its initial K=2 window (first two replies are
    // standalone OPEN_SRC frames; the third compresses after a drain).
    assert!(matches!(h.reply(b"a", peer), ReplyDisposition::Continue));
    let frame = r2_read_frame(&client_conn).await;
    let _ = wire::decode_data(Wire::Rev3, &frame).expect("rev3 OPEN_SRC");
    assert!(matches!(h.reply(b"b", peer), ReplyDisposition::Continue));
    let frame = r2_read_frame(&client_conn).await;
    let _ = wire::decode_data(Wire::Rev3, &frame).expect("rev3 OPEN_SRC");
    assert!(matches!(
        h.reply(b"steady", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("steady rev3 DATA");
    assert!(!data.src);
    let wid = data.wire_id.unwrap();

    // The peer says it missed the context for that flow.
    let fid = wire::fid_for(wid).expect("server fid");
    let mut reasm = R2Reassembler::new_with_wire(Wire::Rev3);
    handle_control_message(&ss, &conn, &mut reasm, CtlMessage::NeedContext { fid });
    let mut seen = 0u64;
    assert!(
        conn.take_need_context(&mut seen).is_some(),
        "the repair hint must be queued for the reply readers"
    );

    // The repaired reader sends context K=2 again before compressing.
    for payload in [&b"repair-one"[..], b"repair-two"] {
        assert!(matches!(h.reply(payload, peer), ReplyDisposition::Continue));
        let frame = r2_read_frame(&client_conn).await;
        let data = wire::decode_data(Wire::Rev3, &frame).expect("rev3 OPEN_SRC frame");
        assert_eq!(data.wire_id, Some(wid));
        assert!(data.src, "a repaired flow must re-send its binding context");
        assert_eq!(data.payload, payload);
    }
    assert!(matches!(
        h.reply(b"after", peer),
        ReplyDisposition::Continue
    ));
    assert_eq!(h.drain(), StageDrain::Ok);
    let frame = r2_read_frame(&client_conn).await;
    let data = wire::decode_data(Wire::Rev3, &frame).expect("steady rev3 DATA");
    assert!(!data.src, "the repaired window closes after K sends");
    assert_eq!(data.payload, b"after");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

/// rev3 control-message handling at the state level: `FLOW_CLOSE` removes one
/// binding from both tables (idempotent repeats are counted stale no-ops),
/// `NEED_CONTEXT` never allocates state, and `ASSOC_CLOSE` reaps the session.
#[tokio::test]
async fn rev3_control_messages_reap_session_flow_and_rearm_context() {
    let (_client_conn, _server_conn) = stream_test_pair().await;
    let src: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let (ss, _r2_flows, binding) = rev2_reply_fixture(TargetAddr::Ip(src), Vec::new());
    let conn = R2ConnState::new_with_wire(Wire::Rev3);
    assert!(
        conn.registry.insert(binding.clone()).is_ok(),
        "fixture binding enters the connection registry"
    );
    let mut reasm = R2Reassembler::new_with_wire(Wire::Rev3);

    // FLOW_CLOSE removes exactly that binding from both tables.
    let fid = wire::fid_for(binding.wire_id).expect("client fid");
    let before = r2_count(&r2_stats::FLOW_CLOSES);
    handle_control_message(
        &ss,
        &conn,
        &mut reasm,
        CtlMessage::FlowClose { fid, reason: 0 },
    );
    assert!(conn.registry.get(binding.wire_id).is_none());
    assert!(r2_count(&r2_stats::FLOW_CLOSES) > before);
    // A repeated close is a counted stale no-op, never a fault.
    let stale_before = r2_count(&r2_stats::STALE_CLOSES);
    handle_control_message(
        &ss,
        &conn,
        &mut reasm,
        CtlMessage::FlowClose { fid, reason: 0 },
    );
    assert!(r2_count(&r2_stats::STALE_CLOSES) > stale_before);

    // NEED_CONTEXT for an unknown flow never allocates state (counted no-op);
    // for a live flow it bumps the repair epoch the reply readers poll.
    let dropped_before = r2_count(&r2_stats::NEED_CONTEXT_DROPPED);
    handle_control_message(
        &ss,
        &conn,
        &mut reasm,
        CtlMessage::NeedContext { fid: 0x1FFF },
    );
    assert!(r2_count(&r2_stats::NEED_CONTEXT_DROPPED) > dropped_before);
    let mut seen = 0u64;
    assert!(conn.take_need_context(&mut seen).is_none());
    let (flows, live) = insert_r2_binding(&ss, 7, 2, TargetAddr::Ip(src), Vec::new());
    assert!(conn.registry.insert(live.clone()).is_ok());
    let live_fid = wire::fid_for(live.wire_id).expect("live fid");
    handle_control_message(
        &ss,
        &conn,
        &mut reasm,
        CtlMessage::NeedContext { fid: live_fid },
    );
    assert!(
        conn.take_need_context(&mut seen).is_some(),
        "a live flow's repair must reach the reply readers"
    );
    // The extra binding is in the session's reverse table only after install;
    // keep the variable used.
    assert!(!flows.load().is_empty());

    // ASSOC_CLOSE reaps the session (the fixture's only association).
    assert_eq!(ss.len(), 1);
    handle_control_message(
        &ss,
        &conn,
        &mut reasm,
        CtlMessage::AssocClose { sess: 7, reason: 0 },
    );
    assert_eq!(ss.len(), 0, "ASSOC_CLOSE must remove the session entry");
}

/// rev3 connection state is wire-tagged and its stager/allocator follow it,
/// while `new()` stays the shipped rev2 default.
#[test]
fn rev3_state_is_wire_tagged_with_rev2_default() {
    let rev2 = R2ConnState::new();
    assert_eq!(rev2.wire(), Wire::Rev2);
    assert_eq!(rev2.stage.lock().wire(), Wire::Rev2);
    let rev3 = R2ConnState::new_with_wire(Wire::Rev3);
    assert_eq!(rev3.wire(), Wire::Rev3);
    assert_eq!(rev3.stage.lock().wire(), Wire::Rev3);
    // The reassembler follows the same revision.
    assert_eq!(R2Reassembler::new().wire(), Wire::Rev2);
    assert_eq!(R2Reassembler::new_with_wire(Wire::Rev3).wire(), Wire::Rev3);
    // 14-bit fid mapping: client half 0x0000.., server half 0x2000...
    assert_eq!(wire::fid_for(r3_wire_id(1, false)), Some(0x0000));
    assert_eq!(wire::fid_for(r3_wire_id(1, true)), Some(0x2000));
    assert_eq!(wire::wire_id_for_fid(0x0000), Some(r3_wire_id(1, false)));
    assert_eq!(wire::wire_id_for_fid(0x2000), Some(r3_wire_id(1, true)));
}
