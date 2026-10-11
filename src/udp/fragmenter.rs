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

use super::send::{DatagramSend, PayloadSend, send_encoded, send_udp_datagram_with_prefix};
use crate::mono_millis;
use crate::mqp::addr::TargetAddrRef;
use crate::mqp::datagram::{DGRAM_PREFIX_LEN, DgramPrefixCache};
use crate::mqp::fragment::{
    FRAG_ID_SAFE_WINDOW_MS, FRAG_PREFIX_LEN, MQP_FRAG_MAX_PAYLOAD, MQP_FRAG_MAX_TOTAL,
    encode_fragment_with_header,
};
use crate::stats::{DatagramDropKind, warn_datagram_drop};
use crate::{dgram_drops, udp_stats};

/// Splits oversized UDP payloads across [`MQP_DGRAM_FRAG`] frames.
///
/// One instance per sending context (a SOCKS association on the client, a UDP
/// session on the server), so `id` is unique within the `(sess, id)` key the
/// receiver reassembles on.
#[derive(Debug, Default)]
pub struct DgramFragmenter {
    pub(crate) next_id: u16,
    /// [`mono_millis`] when `next_id` last wrapped (0 = it never has). See
    /// [`FRAG_ID_SAFE_WINDOW_MS`].
    pub(crate) last_wrap_ms: u64,
    /// Pre-encoded `type | sess | addr` prefix for the steady destination, so
    /// the N=1 fast path below skips the `header()` validation + re-encode on
    /// every packet. Keyed by `(sess, dst)` and invalidated on any change; the
    /// fragment path underneath keeps its own validation untouched.
    prefix_cache: DgramPrefixCache,
}

/// Whether handing out a fresh fragment id would risk colliding with a partial
/// the receiver may still hold — see [`FRAG_ID_SAFE_WINDOW_MS`].
///
/// `last_wrap_ms` must be an **upper bound on the previous use of every id in
/// the cycle now starting**; the ids of a cycle are all issued before the
/// current cycle's first id, so the cycle's own start is the only such bound
/// available without a per-id timestamp ring (65536 entries per sending
/// context). That is why this is deliberately the *conservative* choice: a
/// looser reference (e.g. the previous cycle's start, or an interpolated
/// per-id estimate) over-estimates how long ago each id was last used and
/// therefore lets an id be reused inside the window — a datagram splice. The
/// cost is the 3 s pause after each wrap documented on
/// [`FRAG_ID_SAFE_WINDOW_MS`], which is inherent to a 16-bit id with no wire
/// generation marker, not an artefact of this reference.
///
/// Split out of [`DgramFragmenter::send`] so the window logic is testable
/// without a live connection; `now_ms` is the [`mono_millis`] epoch.
pub(crate) fn frag_id_reuse_blocked(last_wrap_ms: u64, now_ms: u64) -> bool {
    last_wrap_ms != 0 && now_ms.saturating_sub(last_wrap_ms) < FRAG_ID_SAFE_WINDOW_MS
}

impl DgramFragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim the next fragment id, or `None` when the 16-bit id space cannot be
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
    pub(crate) fn try_claim_id(&mut self, now_ms: u64) -> Option<u16> {
        if frag_id_reuse_blocked(self.last_wrap_ms, now_ms) {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.last_wrap_ms = now_ms;
        }
        Some(id)
    }

    /// Encode and send `payload`, fragmenting only when it does not fit one
    /// DATAGRAM. The unfragmented path is byte-identical to the pre-fragmentation
    /// wire format, so small packets pay nothing for this.
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
        // The small prefix is copied to the stack (12 B steady-state IPv4) so
        // the cache borrow ends before the send.
        let mut prefix_buf = [0u8; DgramPrefixCache::PREFIX_MAX];
        let prefix_len = match self.prefix_cache.prefix_for(sess, address) {
            Some(p) => {
                let n = p.len();
                prefix_buf[..n].copy_from_slice(p);
                n
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
        let cap = limit.saturating_sub(prefix_len);
        if payload.len() <= cap {
            let failed = match send_udp_datagram_with_prefix(
                conn,
                &prefix_buf[..prefix_len],
                payload,
                limit,
            ) {
                DatagramSend::Sent => {
                    // Counted only on an accepted send: counting before the
                    // size refusals inflated `datagrams`/`bytes`/`max_payload`
                    // with payloads that were never queued, and `max_payload` is
                    // documented as the empirical check on the 8 KiB cap, so a
                    // refused oversized datagram could move the very number that
                    // is supposed to describe delivered traffic.
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
        // The 16-bit id must not be reused while the receiver can still hold a
        // partial for it: an id that comes around again feeds a second payload's
        // fragments into the first payload's partial, and a fragment landing on
        // an *empty* slot completes a spliced datagram that is delivered to the
        // older generation's target (see the note on the restart heuristic in
        // `DgramReassembler::push_with_chunk`). Refusing to fragment while the
        // whole id space has been consumed faster than the receiver forgets is
        // the only wire-compatible way to rule that out.
        let Some(id) = self.try_claim_id(mono_millis()) else {
            let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            warn_datagram_drop(
                DatagramDropKind::Large,
                "fragment id would be reused inside the reassembly window",
                n,
                || {
                    format!(
                        "; all 65536 fragment ids were retired within {FRAG_ID_SAFE_WINDOW_MS} ms, \
                         so the receiver may still hold a partial for the id this payload needs — \
                         dropped rather than spliced. Expected cost is \
                         {FRAG_ID_SAFE_WINDOW_MS} / (cycle + {FRAG_ID_SAFE_WINDOW_MS}) of \
                         oversized payloads: ~4% at 1000/s, ~8% at 2000/s, 50% at 21845/s. This is \
                         inherent to a 16-bit id with no wire generation marker, not a tuning knob"
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
                    return PayloadSend {
                        frames,
                        failed: Some(other),
                    };
                }
            }
        }
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
