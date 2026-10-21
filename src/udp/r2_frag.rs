//! MQP-3 rev2 fragmenter: split a UDP payload that does not fit one DATAGRAM
//! into rev2 `FRAG` frames.
//!
//! The wire codec lives in [`crate::mqp::r2`]; this module owns the sender-side
//! split/backpressure policy, mirroring the shipped MQP-2 [`DgramFragmenter`]
//! (see [`crate::udp::fragmenter`]) with the rev2 addressing rules:
//!
//! * `Steady { wire_id }` — a confirmed flow: every fragment carries the 8 B
//!   steady header (kind + id varint + frag id u32 + idx/total);
//! * `Opening { wire_id, sess, addr, src }` — a flow whose binding is not yet
//!   confirmed: the **first** fragment carries `OPEN` + `sess u32 + addr` so a
//!   receiver that has not installed the flow can still name the session and
//!   route the payload; the remaining fragments are steady (the reassembler
//!   keeps the context from the first one);
//! * `Inline { sess, addr, src }` — no flow id available (table full / id
//!   space exhausted): every fragment carries `INLINE` + `sess u32 + addr`, the
//!   self-describing fail-safe.
//!
//! rev2 wire ids are monotonic and never reused, so the rev2 reassembler cannot
//! splice two generations onto one id; the per-frame `frag_id` is still a
//! monotonic u32 per sending context. It would take >1.4M fragmented payloads/s
//! from one context to wrap it inside the 2 s reassembly window — far outside
//! the protocol's operating envelope — so no id-reuse gate is needed (the MQP-2
//! fragmenter keeps one because its key is reused `(sess, id)`).
//!
//! Backpressure follows the MQP-2 fragmenter: a fragmented payload is
//! **all-or-nothing** once the DATAGRAM buffer has refused a frame; the
//! aggregate outgoing-DATAGRAM space is probed before the first frame and a
//! payload that does not fit whole is dropped whole instead of queueing a
//! prefix the peer can never reassemble.

use quinn::Connection;

use super::send::{DatagramSend, PayloadSend, try_send_datagram};
use crate::mqp::addr::TargetAddrRef;
use crate::mqp::fragment::{MQP_FRAG_MAX_PAYLOAD, MQP_FRAG_MAX_TOTAL};
use crate::mqp::r2;
use crate::stats::{DatagramDropKind, warn_datagram_drop};
use crate::{dgram_drops, udp_stats};

/// Largest payload the rev2 wire carries/reassembles (unchanged: 8 KiB, the
/// loss-amplification cap documented on `MQP_FRAG_MAX_PAYLOAD`).
pub const R2_FRAG_MAX_PAYLOAD: usize = MQP_FRAG_MAX_PAYLOAD;

/// Quinn's per-datagram control-block charge, used only by the aggregate
/// backpressure footprint (same constant as the MQP-2 fragmenter).
const FRAME_BOOKKEEPING: usize = 48;

/// Addressing mode of one rev2 fragmented payload.
#[derive(Debug, Clone, Copy)]
pub enum R2FragFlow<'a> {
    /// Confirmed flow; steady fragments only.
    Steady { wire_id: u32 },
    /// Flow binding still opening; the first fragment carries `OPEN`.
    Opening {
        wire_id: u32,
        sess: u32,
        addr: TargetAddrRef<'a>,
        src: bool,
    },
    /// No flow id; every fragment carries `INLINE` (self-describing).
    Inline {
        sess: u32,
        addr: TargetAddrRef<'a>,
        src: bool,
    },
}

/// Pure split plan: frame count + per-fragment chunk sizes/headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FragPlan {
    pub(crate) total: u8,
    pub(crate) first_hdr: usize,
    pub(crate) rest_hdr: usize,
    pub(crate) first_chunk: usize,
    pub(crate) rest_chunk: usize,
}

impl FragPlan {
    /// Split `payload_len` into at most [`MQP_FRAG_MAX_TOTAL`] fragments.
    /// `first_hdr`/`rest_hdr` are the encoded header lengths of the first and
    /// following fragments; `limit` is the live DATAGRAM body budget.
    pub(crate) fn new(
        limit: usize,
        first_hdr: usize,
        rest_hdr: usize,
        payload_len: usize,
    ) -> Option<Self> {
        if payload_len == 0 || payload_len > R2_FRAG_MAX_PAYLOAD {
            return None;
        }
        let first_chunk = limit.checked_sub(first_hdr)?;
        let rest_chunk = limit.checked_sub(rest_hdr)?;
        if first_chunk == 0 || rest_chunk == 0 {
            return None;
        }
        let total = if payload_len <= first_chunk {
            1usize
        } else {
            1 + (payload_len - first_chunk).div_ceil(rest_chunk)
        };
        if total > MQP_FRAG_MAX_TOTAL as usize {
            return None;
        }
        Some(Self {
            total: total as u8,
            first_hdr,
            rest_hdr,
            first_chunk,
            rest_chunk,
        })
    }

    /// Bytes this payload will occupy in quinn's outgoing DATAGRAM buffer,
    /// including the per-datagram bookkeeping for all but the first frame.
    pub(crate) fn footprint(&self, payload_len: usize) -> usize {
        payload_len
            .saturating_add(self.first_hdr)
            .saturating_add((usize::from(self.total) - 1).saturating_mul(self.rest_hdr))
            .saturating_add((usize::from(self.total) - 1).saturating_mul(FRAME_BOOKKEEPING))
    }
}

/// Splits oversized UDP payloads across rev2 `FRAG` frames.
///
/// One instance per sending context (a SOCKS association on the client, a UDP
/// session on the server). `next_id` is a monotonic per-payload fragment id.
#[derive(Debug, Default)]
pub struct R2Fragmenter {
    next_id: u32,
    /// Whether the last fragmented send stopped on `DatagramSend::Blocked`.
    /// Drives the aggregate-space gate in [`Self::send`]; a healthy fragmenter
    /// only pays one `false` branch.
    last_blocked: bool,
}

impl R2Fragmenter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Send `payload` as rev2 `FRAG` frames. The caller has already established
    /// that the payload does not fit one `DATA`/`OPEN` frame (this function
    /// still handles a one-fragment plan for safety).
    pub fn send(
        &mut self,
        conn: &Connection,
        limit: usize,
        flow: &R2FragFlow<'_>,
        payload: &[u8],
    ) -> PayloadSend {
        let (wire_id, first_hdr, rest_hdr, sess_ctx) = match *flow {
            R2FragFlow::Steady { wire_id } => {
                if wire_id == 0 {
                    return self.too_large("rev2 fragment for id 0");
                }
                let hdr = r2::frag_steady_len(wire_id, 0);
                (Some(wire_id), hdr, hdr, None)
            }
            R2FragFlow::Opening {
                wire_id,
                sess,
                addr,
                src,
            } => {
                if wire_id == 0 {
                    return self.too_large("rev2 fragment open for id 0");
                }
                let Ok(header) = addr.header() else {
                    return self.too_large("bad address header");
                };
                let first = r2::frag_open_len(wire_id, header.len(), 0);
                (
                    Some(wire_id),
                    first,
                    r2::frag_steady_len(wire_id, 0),
                    Some((sess, addr, src)),
                )
            }
            R2FragFlow::Inline { sess, addr, src } => {
                let Ok(header) = addr.header() else {
                    return self.too_large("bad address header");
                };
                let hdr = r2::frag_inline_len(header.len(), 0);
                (None, hdr, hdr, Some((sess, addr, src)))
            }
        };
        let Some(plan) = FragPlan::new(limit, first_hdr, rest_hdr, payload.len()) else {
            return self.too_large("payload above the rev2 fragmentation limit");
        };
        let total = plan.total;

        // Aggregate backpressure gate: after a Blocked verdict, only start a
        // fragmented payload when the buffer can hold every frame. Otherwise a
        // prefix would be queued and never reassembled.
        if self.last_blocked {
            if conn.datagram_send_buffer_space() < plan.footprint(payload.len()) {
                return PayloadSend {
                    frames: 0,
                    failed: Some(DatagramSend::Blocked),
                };
            }
            self.last_blocked = false;
        }

        let frag_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let mut frames = 0u8;
        let mut offset = 0usize;
        for idx in 0..usize::from(total) {
            let remaining = &payload[offset..];
            let chunk_len = if idx == 0 {
                plan.first_chunk.min(remaining.len())
            } else {
                plan.rest_chunk.min(remaining.len())
            };
            let chunk = &remaining[..chunk_len];
            let encoded = match (idx, wire_id, sess_ctx) {
                (0, Some(id), Some((sess, addr, src))) => r2::encode_frag_open(
                    id, sess, &addr, src, frag_id, idx as u8, total, chunk, limit,
                ),
                (_, Some(id), _) => {
                    r2::encode_frag_steady(id, frag_id, idx as u8, total, chunk, limit)
                }
                (_, None, Some((sess, addr, src))) => r2::encode_frag_inline(
                    sess, &addr, src, frag_id, idx as u8, total, chunk, limit,
                ),
                _ => None,
            };
            let Some(body) = encoded else {
                // Only reachable if the plan and the encoder disagree; report
                // it rather than send a payload that can never reassemble.
                return PayloadSend {
                    frames,
                    failed: Some(DatagramSend::TooLarge),
                };
            };
            match try_send_datagram(conn, body) {
                DatagramSend::Sent => frames += 1,
                other => {
                    self.last_blocked = other == DatagramSend::Blocked;
                    return PayloadSend {
                        frames,
                        failed: Some(other),
                    };
                }
            }
            offset += chunk_len;
        }
        self.last_blocked = false;
        // Counters fire only for a payload whose every frame was queued (same
        // contract as the MQP-2 fragmenter: a partial payload is not delivered).
        udp_stats::payload(payload.len());
        udp_stats::fragmented(frames);
        PayloadSend {
            frames,
            failed: None,
        }
    }

    fn too_large(&self, why: &'static str) -> PayloadSend {
        let n = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        warn_datagram_drop(DatagramDropKind::Large, why, n, String::new);
        PayloadSend {
            frames: 0,
            failed: Some(DatagramSend::TooLarge),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_steady_fragments() {
        // Budget 1162, steady v4 header 8 B (id < 128) -> 1154 B per chunk.
        let p = FragPlan::new(1162, 8, 8, 1200).unwrap();
        assert_eq!(p.total, 2);
        assert_eq!(p.first_chunk, 1154);
        assert_eq!(p.rest_chunk, 1154);
        // 1200 = 1154 + 46.
        let p = FragPlan::new(1162, 8, 8, 8192).unwrap();
        assert_eq!(p.total, 8);
    }

    #[test]
    fn plan_open_first_header_is_larger() {
        // open IPv4: 1 kind + 1 flags + 1 id + 4 frag + 1 idx + 1 total + 4 sess + 7 addr = 20
        let p = FragPlan::new(1162, 20, 8, 1200).unwrap();
        assert_eq!(p.total, 2);
        assert_eq!(p.first_chunk, 1142);
    }

    #[test]
    fn plan_inline_headers_are_larger() {
        // inline IPv4: 1 + 1 + 4 + 1 + 1 + 4 + 7 = 19
        let p = FragPlan::new(1162, 19, 19, 1200).unwrap();
        assert_eq!(p.total, 2);
        assert_eq!(p.first_chunk, 1143);
    }

    #[test]
    fn plan_rejects_impossible_shapes() {
        assert!(FragPlan::new(10, 12, 12, 100).is_none()); // no room for a chunk
        assert!(FragPlan::new(1162, 8, 8, 0).is_none());
        assert!(FragPlan::new(1162, 8, 8, R2_FRAG_MAX_PAYLOAD + 1).is_none());
        // 8 KiB at 130 B/frame needs >64 fragments.
        assert!(FragPlan::new(120, 8, 8, 8192).is_none());
    }

    #[test]
    fn plan_one_fragment_for_small_payload() {
        let p = FragPlan::new(1162, 8, 8, 100).unwrap();
        assert_eq!(p.total, 1);
        assert_eq!(p.first_chunk, 1154);
    }

    #[test]
    fn footprint_counts_every_frame_and_bookkeeping() {
        let p = FragPlan::new(1162, 8, 8, 1200).unwrap();
        // payload + 2 headers + 1 bookkeeping block.
        assert_eq!(p.footprint(1200), 1200 + 16 + FRAME_BOOKKEEPING);
    }

    #[test]
    fn fragmenter_default_is_at_zero() {
        let f = R2Fragmenter::new();
        assert_eq!(f.next_id, 0);
        assert!(!f.last_blocked);
    }
}
