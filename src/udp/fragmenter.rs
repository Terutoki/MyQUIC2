//! MQP-2 UDP 分片发送器：逐行搬运自 `src/lib.rs`（零改动抽取，`lib.rs` 未碰）。
//!
//! 搬运区间（以符号为准）：
//! - `DgramFragmenter`：lib.rs:1059-1070（含 1059-1063 文档与 1064 derive）
//! - `frag_id_reuse_blocked`：lib.rs:1072-1079
//! - `impl DgramFragmenter`（含 `send` 全套）：lib.rs:1081-1238
//!
//! 接线：`mqp`（`TargetAddrRef`/`FRAG_PREFIX_LEN`/`FRAG_ID_SAFE_WINDOW_MS`/
//! `MQP_FRAG_MAX_PAYLOAD`/`MQP_FRAG_MAX_TOTAL`/`DGRAM_PREFIX_LEN`/
//! `encode_fragment_with_header`）、`time`（`mono_millis`）、
//! `stats`（`dgram_drops::*`、`udp_stats::*`、`warn_datagram_drop`、
//! `DatagramDropKind`）、同目录 `send`（`DatagramSend`、`send_udp_datagram_with_header`、
//! `send_encoded`）均经 `crate::` / `super::` 路径引用。

use super::send::{
    DatagramSend, PayloadSend, note_send_buffer_full, send_encoded, send_udp_datagram_with_prefix,
};
use crate::mono_millis;
use crate::mqp::addr::TargetAddrRef;
use crate::mqp::datagram::{DGRAM_PREFIX_LEN, DgramPrefixCache};
use crate::mqp::fragment::{
    FRAG_ID_SAFE_WINDOW_MS, FRAG_PREFIX_LEN, MQP_FRAG_MAX_PAYLOAD, MQP_FRAG_MAX_TOTAL,
    encode_fragment_with_header,
};
use crate::stats::{DatagramDropKind, warn_datagram_drop};
use crate::{dgram_drops, udp_stats};

/// Per-frame bookkeeping slack for the aggregate send-space gate in
/// [`DgramFragmenter::send`].
///
/// quinn charges every queued DATAGRAM `size_of::<Datagram>()` on top of its
/// body (quinn-proto `connection/datagrams.rs`), and that type is private, so
/// this is a conservative stand-in for the control-block charge (32 bytes on
/// 64-bit; the extra 16 B covers alignment/upstream drift). Over-estimating can
/// only make a backpressured payload drop slightly earlier in the same
/// saturated regime; under-estimating is what would let an unreassemblable
/// prefix through.
const FRAG_FRAME_BOOKKEEPING: usize = 48;

/// Test-only count of fragmented payloads the aggregate-space gate dropped
/// whole. Production behaviour is unobservable from outside (a gated drop and a
/// first-frame `Blocked` share the same `PayloadSend` verdict), so the live
/// test asserts on this counter that the *gate* decided.
#[cfg(test)]
static GATE_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Splits oversized UDP payloads across [`MQP_DGRAM_FRAG`] frames.
///
/// One instance per sending context (a SOCKS association on the client, a UDP
/// session on the server), so `id` is unique within the `(sess, id)` key the
/// receiver reassembles on.
#[derive(Debug, Default)]
pub struct DgramFragmenter {
    pub(crate) next_id: u32,
    /// [`mono_millis`] when `next_id` last wrapped (0 = it never has). See
    /// [`FRAG_ID_SAFE_WINDOW_MS`].
    pub(crate) last_wrap_ms: u64,
    /// Pre-encoded `type | sess | addr` prefix for the steady destination, so
    /// the N=1 fast path below skips the `header()` validation + re-encode on
    /// every packet. Keyed by `(sess, dst)` and invalidated on any change; the
    /// fragment path underneath keeps its own validation untouched.
    prefix_cache: DgramPrefixCache,
    /// Whether the last *fragmented* send stopped on [`DatagramSend::Blocked`]
    /// (quinn's outgoing DATAGRAM buffer full). Drives the aggregate-space gate
    /// in [`Self::send`]: while set, a multi-frame payload is only started when
    /// the buffer can hold **every** frame, so backpressure cannot queue a
    /// prefix that the peer can never reassemble. Cleared as soon as a send
    /// succeeds or the gate admits a whole payload; the healthy path only pays
    /// one `false` branch.
    last_blocked: bool,
}

/// Whether handing out a fresh fragment id would risk colliding with a partial
/// the receiver may still hold — see [`FRAG_ID_SAFE_WINDOW_MS`].
///
/// `last_wrap_ms` must be an **upper bound on the previous use of every id in
/// the cycle now starting**; the ids of a cycle are all issued before the
/// current cycle's first id, so the cycle's own start is the only such bound
/// available without a per-id timestamp ring. That is why this is deliberately
/// the *conservative* choice: a looser reference (e.g. the previous cycle's
/// start, or an interpolated per-id estimate) over-estimates how long ago each
/// id was last used and therefore lets an id be reused inside the window — a
/// datagram splice.
///
/// The cycle is 2^32 ids wide (see [`FRAG_PREFIX_LEN`]), so the 3 s pause after
/// each wrap documented on [`FRAG_ID_SAFE_WINDOW_MS`] is unreachable at any
/// rate a single sending context sustains; it remains as the correctness
/// backstop rather than a periodic cost.
///
/// Split out of [`DgramFragmenter::send`] so the window logic is testable
/// without a live connection; `now_ms` is the [`mono_millis`] epoch.
pub(crate) fn frag_id_reuse_blocked(last_wrap_ms: u64, now_ms: u64) -> bool {
    last_wrap_ms != 0 && now_ms.saturating_sub(last_wrap_ms) < FRAG_ID_SAFE_WINDOW_MS
}

/// Bytes a `total`-frame payload occupies in quinn's outgoing DATAGRAM buffer:
/// the encoded wire bytes of every frame plus the per-datagram control-block
/// charge for all but the first (quinn's `send_buffer_space` already subtracts
/// one). `frame_overhead` is `FRAG_PREFIX_LEN + address header length`.
///
/// Pure so the backpressure gate's arithmetic is unit-tested without a live
/// connection (see [`DgramFragmenter::send`]).
pub(crate) fn fragmented_send_footprint(
    payload_len: usize,
    total: usize,
    frame_overhead: usize,
) -> usize {
    payload_len
        .saturating_add(total.saturating_mul(frame_overhead))
        .saturating_add(
            total
                .saturating_sub(1)
                .saturating_mul(FRAG_FRAME_BOOKKEEPING),
        )
}

impl DgramFragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim the next fragment id, or `None` when the 32-bit id space cannot be
    /// cycled yet without risking a splice (see [`FRAG_ID_SAFE_WINDOW_MS`]).
    ///
    /// The gate, the advance and the wrap stamp live here rather than inline in
    /// [`Self::send`] so the invariant test drives the *production* logic: a
    /// test that re-implements the three lines cannot catch a change to them.
    /// That matters because a looser reference passes a refusals-only test while
    /// quietly reissuing ids inside the window — gating on the *previous* cycle's
    /// start instead of this one does exactly that, driving refusals to zero and
    /// splicing datagrams. `id_reuse_never_lands_inside_the_reassembly_window`
    /// exists to catch that shape.
    pub(crate) fn try_claim_id(&mut self, now_ms: u64) -> Option<u32> {
        if frag_id_reuse_blocked(self.last_wrap_ms, now_ms) {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            // 0 is the "never wrapped" sentinel, and `mono_millis` legitimately
            // reads 0 during the process's first millisecond — stamping that
            // raw would silently disable the guard it is meant to arm.
            self.last_wrap_ms = now_ms.max(1);
        }
        Some(id)
    }

    /// Production id claim: [`try_claim_id`](Self::try_claim_id) with a
    /// **lazily read** precise clock.
    ///
    /// The reuse guard can only refuse *after* the 32-bit id space has wrapped,
    /// and the wrap stamp is only taken on the wrap itself, so before the first
    /// wrap every claim is clock-free — the fragment path no longer pays a
    /// TSC/`clock_gettime` read per fragmented payload. `try_claim_id(now_ms)`
    /// stays the single gate and is what the guard tests drive with a
    /// fabricated clock.
    fn claim_id(&mut self) -> Option<u32> {
        if self.last_wrap_ms == 0 && self.next_id != u32::MAX {
            // Guard provably open and no wrap stamp to take: two integer
            // operations, no clock read.
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            return Some(id);
        }
        self.try_claim_id(mono_millis())
    }

    /// Encode and send `payload`, fragmenting only when it does not fit one
    /// DATAGRAM. The unfragmented path is byte-identical to the pre-fragmentation
    /// wire format, so small packets pay nothing for this.
    ///
    /// Fragmented sends are **all-or-nothing under backpressure**: after a
    /// `Blocked` verdict the aggregate outgoing DATAGRAM space is checked
    /// before the first frame, and a payload that does not fit whole is dropped
    /// whole (see [`PayloadSend::failed`]) rather than queued as a prefix that
    /// the peer can never reassemble. The gate costs one bool check on the
    /// healthy path.
    pub fn send(
        &mut self,
        conn: &quinn::Connection,
        sess: u32,
        address: &TargetAddrRef<'_>,
        payload: &[u8],
        limit: usize,
    ) -> PayloadSend {
        // N=1 fast path: serve the steady destination from the pre-encoded
        // prefix (no `header()` validation, no re-encode). A refused address
        // reports exactly like the old `header().is_err()` branch below.
        //
        // The cache slice is used **directly**: it only needs to live through
        // `send_udp_datagram_with_prefix`, and the fast path returns before
        // anything needs `&mut self`. The earlier shape copied it into a
        // 264-byte stack array on every datagram, which LLVM lowers to a
        // full-width memset even though at most 19 bytes are ever read (a
        // per-packet store no length check can elide).
        let cap = match self.prefix_cache.prefix_for(sess, address) {
            Some(p) => {
                let cap = limit.saturating_sub(p.len());
                if payload.len() <= cap {
                    let failed = match send_udp_datagram_with_prefix(conn, p, payload, limit) {
                        DatagramSend::Sent => {
                            // Counted only on an accepted send: counting before
                            // the size refusals inflated
                            // `datagrams`/`bytes`/`max_payload` with payloads
                            // that were never queued, and `max_payload` is
                            // documented as the empirical check on the 8 KiB
                            // cap, so a refused oversized datagram could move
                            // the very number that is supposed to describe
                            // delivered traffic.
                            udp_stats::payload(payload.len());
                            None
                        }
                        other => Some(other),
                    };
                    return PayloadSend {
                        frames: u8::from(failed.is_none()),
                        failed,
                    };
                }
                cap
            }
            None => {
                let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                warn_datagram_drop(
                    DatagramDropKind::Large,
                    "bad address header",
                    n,
                    String::new,
                );
                return PayloadSend {
                    frames: 0,
                    failed: Some(DatagramSend::TooLarge),
                };
            }
        };

        // Fragment path below: `payload.len() > cap` was proven above, and the
        // cached prefix length agrees with a fresh validation by construction,
        // so this re-validation only serves the fragment encoder's `header`.
        // (Unreachable when the address is refused: the fast path already
        // returned `TooLarge` for it with identical accounting.)
        let Ok(header) = address.header() else {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop(
                DatagramDropKind::Large,
                "bad address header",
                n,
                String::new,
            );
            return PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            };
        };
        debug_assert_eq!(cap, limit.saturating_sub(DGRAM_PREFIX_LEN + header.len()));

        let chunk = limit.saturating_sub(FRAG_PREFIX_LEN + header.len());
        // One fragment must carry something, and the reassembled result must
        // stay inside both the protocol's payload cap and the u8 fragment count.
        let total_usize = if chunk == 0 {
            usize::MAX
        } else {
            payload.len().div_ceil(chunk)
        };
        if total_usize > MQP_FRAG_MAX_TOTAL as usize || payload.len() > MQP_FRAG_MAX_PAYLOAD {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop(
                DatagramDropKind::Large,
                "payload above the MQP-2 fragmentation limit",
                n,
                || {
                    format!(
                        "; {} B exceeds the {MQP_FRAG_MAX_PAYLOAD} B reassembly cap",
                        payload.len()
                    )
                },
            );
            return PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            };
        }
        // Backpressure gate (all-or-nothing fragmented send). Once a fragmented
        // send has been stopped by a full DATAGRAM buffer, the next fragmented
        // payload first asks quinn how much space is actually free and only
        // starts if the buffer can hold **every** frame. Without the gate the
        // loop below queues a *prefix* of the frames and drops the rest; the
        // queued frames still go out on the wire, but the peer can never
        // reassemble them (it times the partial out), so they are pure wire
        // waste — and under sustained backpressure the freed space keeps being
        // taken by such prefixes instead of by payloads that could complete.
        // A healthy fragmenter only pays the `false` check; the quinn state
        // lock is taken on the backpressure path only.
        if self.last_blocked {
            let footprint = fragmented_send_footprint(
                payload.len(),
                total_usize,
                FRAG_PREFIX_LEN + header.len(),
            );
            if conn.datagram_send_buffer_space() < footprint {
                #[cfg(test)]
                GATE_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                note_send_buffer_full();
                return PayloadSend {
                    frames: 0,
                    failed: Some(DatagramSend::Blocked),
                };
            }
            // The whole payload fits now: the cached verdict is stale. If a
            // concurrent sender on the same connection takes the space between
            // this probe and the frames below, the loop re-arms the flag.
            self.last_blocked = false;
        }
        // The 32-bit id must not be reused while the receiver can still hold a
        // partial for it: an id that comes around again feeds a second payload's
        // fragments into the first payload's partial, and a fragment landing on
        // an *empty* slot completes a spliced datagram that is delivered to the
        // older generation's target (see the note on the restart heuristic in
        // `DgramReassembler::push_with_chunk`). Refusing to fragment while the
        // whole id space has been consumed faster than the receiver forgets is
        // the only wire-compatible way to rule that out. The space is 2^32 ids
        // wide, so with the shipped reassembly window this gate cannot trip
        // below ~1.4M fragmented payloads/s per sending context.
        let Some(id) = self.claim_id() else {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop(
                DatagramDropKind::Large,
                "fragment id would be reused inside the reassembly window",
                n,
                || {
                    format!(
                        "; all 4294967296 fragment ids were retired within \
                         {FRAG_ID_SAFE_WINDOW_MS} ms, so the receiver may still hold a partial \
                         for the id this payload needs — dropped rather than spliced. This is \
                         the 32-bit id space's correctness backstop; it needs >1.4M fragmented \
                         payloads/s from this one sending context to trip, so a deployment that \
                         reaches it is far outside the protocol's operating envelope"
                    )
                },
            );
            return PayloadSend {
                frames: 0,
                failed: Some(DatagramSend::TooLarge),
            };
        };
        let total = total_usize as u8;

        let mut frames = 0u8;
        for (i, part) in payload.chunks(chunk).enumerate() {
            let Some(body) =
                encode_fragment_with_header(sess, id, i as u8, total, &header, part, limit)
            else {
                // Only reachable if `chunk` and the encoder disagree; report it
                // rather than send a payload that can never reassemble.
                let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
                warn_datagram_drop(
                    DatagramDropKind::Large,
                    "fragment does not fit the path budget",
                    n,
                    String::new,
                );
                return PayloadSend {
                    frames,
                    failed: Some(DatagramSend::TooLarge),
                };
            };
            match send_encoded(conn, body) {
                DatagramSend::Sent => frames += 1,
                other => {
                    // Remember DATAGRAM-buffer backpressure: the next fragmented
                    // payload pre-checks the aggregate space instead of queueing
                    // an unreassemblable prefix (see the gate above).
                    self.last_blocked = other == DatagramSend::Blocked;
                    return PayloadSend {
                        frames,
                        failed: Some(other),
                    };
                }
            }
        }
        self.last_blocked = false;
        // Both counters fire only for a payload whose every frame was queued —
        // a partial send is not a delivered datagram, and the peer's reassembler
        // times it out either way. `payload` used to be missing here entirely,
        // so fragmented payloads were invisible in `datagrams`/`bytes` and,
        // worse, in `max_payload`, which is exactly the size class the 8 KiB
        // cap question is about. `fragmented` itself ignores `frames <= 1`.
        udp_stats::payload(payload.len());
        udp_stats::fragmented(frames);
        PayloadSend {
            frames,
            failed: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::ack::MQP_ALPN;
    use crate::mqp::addr::TargetAddr;
    use crate::transport::{Congestion, build_transport};
    use bytes::Bytes;
    use std::sync::Arc;

    /// The test-only gate counter, read relaxed (single-threaded tests).
    fn gate_drops() -> u64 {
        GATE_DROPS.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The aggregate-space gate must charge every frame's encoded wire bytes
    /// plus quinn's per-datagram control-block charge for all but the first
    /// (quinn's `send_buffer_space` already subtracts one). Saturating, so an
    /// absurd input can only over-state the requirement, never wrap under it.
    #[test]
    fn fragmented_send_footprint_charges_wire_bytes_and_bookkeeping() {
        let overhead = FRAG_PREFIX_LEN + 7; // IPv4 target header
        assert_eq!(
            fragmented_send_footprint(1400, 2, overhead),
            1400 + 2 * overhead + FRAG_FRAME_BOOKKEEPING,
        );
        assert_eq!(fragmented_send_footprint(100, 1, overhead), 100 + overhead);
        assert_eq!(
            fragmented_send_footprint(usize::MAX, 64, 19),
            usize::MAX,
            "overflow must saturate towards 'not enough space', never wrap"
        );
    }

    /// A fresh fragmenter must not probe the send buffer: the one-lock gate
    /// only runs after a fragmented send was actually stopped by a full
    /// DATAGRAM buffer (the live test below covers that transition).
    #[test]
    fn fresh_fragmenter_does_not_probe_the_send_buffer() {
        let f = DgramFragmenter::new();
        assert!(!f.last_blocked, "a healthy fragmenter must not probe");
    }

    /// Production id claims are clock-free until the 32-bit space wraps: the
    /// reuse guard can only refuse after a wrap, and the wrap stamp is taken
    /// only on the wrap itself (which `.max(1)` keeps out of the 0 sentinel).
    #[test]
    fn id_claim_is_clock_free_until_the_space_wraps() {
        let mut f = DgramFragmenter::new();
        assert_eq!(f.claim_id(), Some(0));
        assert_eq!(f.claim_id(), Some(1));
        assert_eq!(f.next_id, 2);
        assert_eq!(
            f.last_wrap_ms, 0,
            "no wrap stamp before the 32-bit space wraps"
        );

        f.next_id = u32::MAX;
        assert_eq!(
            f.claim_id(),
            Some(u32::MAX),
            "the last id of the cycle is claimable"
        );
        assert_eq!(f.next_id, 0);
        assert_ne!(
            f.last_wrap_ms, 0,
            "the wrap must stamp a non-zero window reference"
        );
        assert_eq!(
            f.claim_id(),
            None,
            "ids of the new cycle are refused inside the reassembly window"
        );
    }

    /// Endpoint pair for the live send-path test. The client's DATAGRAM send
    /// buffer is deliberately two-max-datagrams sized: it can be filled to
    /// `Blocked` with a couple of synchronous sends, so the gate's drop path is
    /// deterministic without depending on driver pacing.
    fn datagram_endpoint_pair() -> (quinn::Endpoint, quinn::Endpoint) {
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
        let mut tc = quinn::TransportConfig::default();
        tc.datagram_send_buffer_size(2_600);
        tc.datagram_receive_buffer_size(Some(2_600));
        ccfg.transport_config(Arc::new(tc));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);
        (client, server)
    }

    /// F9 end-to-end: once a fragmented send has seen a full DATAGRAM buffer,
    /// the next fragmented payload is dropped **whole** when the buffer cannot
    /// hold every frame — never queued as a prefix the peer can never
    /// reassemble.
    ///
    /// Deterministic by construction: the fill loop and the measured send run
    /// synchronously inside one current-thread-runtime poll, so the connection
    /// driver cannot drain the buffer in between, and the buffer holds only
    /// two max-size datagrams.
    #[tokio::test]
    async fn fragmented_payload_is_dropped_whole_when_the_datagram_buffer_is_full() {
        let (client, server) = datagram_endpoint_pair();
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.accept().unwrap().await.unwrap()
        });
        let conn = client
            .connect(server_addr, "test.com")
            .unwrap()
            .await
            .unwrap();
        let _sconn = accept.await.unwrap();
        let limit = conn.max_datagram_size().expect("DATAGRAM negotiated");

        // Fill the outgoing DATAGRAM buffer (single non-blocking poll per send;
        // no await, so nothing drains meanwhile).
        let filler = Bytes::from(vec![0u8; limit]);
        let mut filled = 0usize;
        loop {
            match crate::udp::try_send_datagram(&conn, filler.clone()) {
                DatagramSend::Sent => {
                    filled += 1;
                    assert!(filled < 64, "the DATAGRAM send buffer could not be filled");
                }
                DatagramSend::Blocked => break,
                other => panic!("unexpected send outcome while filling: {other:?}"),
            }
        }

        let addr = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        let payload = vec![0x5Au8; limit + 200];

        // First fragmented send: the buffer cannot even hold one more frame, so
        // the per-frame loop takes the real `Blocked` verdict on frame 0 and
        // arms the sticky gate without queueing an orphan.
        let mut frag = DgramFragmenter::new();
        let first = frag.send(&conn, 1, &addr.as_ref(), &payload, limit);
        assert_eq!(
            first.frames, 0,
            "a blocked fragmented payload must not queue a prefix frame: {first:?}"
        );
        assert_eq!(
            first.failed,
            Some(DatagramSend::Blocked),
            "the whole payload must be reported as blocked: {first:?}"
        );
        assert!(frag.last_blocked, "the Blocked verdict must arm the gate");

        // Second fragmented send: the sticky gate decides on the aggregate
        // space, drops the payload whole, and the test-only counter proves the
        // gate (not the per-frame loop) made that call.
        let before = gate_drops();
        let second = frag.send(&conn, 2, &addr.as_ref(), &payload, limit);
        assert_eq!(
            second.frames, 0,
            "the aggregate-space gate must not queue a prefix frame: {second:?}"
        );
        assert_eq!(second.failed, Some(DatagramSend::Blocked));
        assert_eq!(
            gate_drops(),
            before + 1,
            "the aggregate-space gate, not a first-frame verdict, must drop it"
        );
    }
}
