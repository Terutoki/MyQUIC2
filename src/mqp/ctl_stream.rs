//! rev3 reliable control plane: one QUIC bidi stream per connection.
//!
//! rev2 carries control in `CTL` DATAGRAMs: `HELLO`/`CAPS` negotiation, one
//! `FLOW_ACK` per accepted flow, `FLOW_REJECT`, `FLOW_CLOSE` and three
//! best-effort `SESS_CLOSE` repeats per association exit. Those frames are
//! idempotent but *lossy*, so the design compensates with repeats, ACK-gated
//! compression and an idle sweep as the correctness backstop.
//!
//! rev3 removes that machinery. The only control messages are rare and
//! correctness-relevant, so they ride a single reliable, ordered, client-opened
//! bidi stream (QUIC retransmits them; there is no app-level repeat logic and no
//! rate budget on the sender side):
//!
//! ```text
//! client opens a bidi stream and writes the marker byte 0xFF, then messages:
//!   type:u8 | len:u16le | body      (len <= MAX_CTL_MESSAGE, see r3::MAX_CTL_BODY)
//! ```
//!
//! | type | message | direction | replaces |
//! |---|---|---|---|
//! | `0x01` | `ASSOC_CLOSE { sess, reason }` | C→S | `SESS_CLOSE x3` on association exit |
//! | `0x02` | `FLOW_CLOSE { fid, reason }` | both | rev2 dead-code `FLOW_CLOSE` |
//! | `0x81` | `REJECT { fid, reason }` | S→C | `FLOW_REJECT` DATAGRAM |
//! | `0x82` | `NEED_CONTEXT { fid }` | both | (new) repair hint for the no-ACK flow policy |
//! | `0x83` | `SESS_CLOSE { sess, reason }` | S→C | `SESS_CLOSE x3` on server reap |
//! | `0x84` | `GOAWAY { }` | S→C | (new) connection health / id-space hint |
//!
//! # Stream classification
//!
//! The server accepts two kinds of client-opened bidi streams: TCP relay flows
//! (first byte is an MQP address `atyp`: `0x01`/`0x03`/`0x04`) and this control
//! stream (first byte [`MARKER`] = `0xFF`). [`classify_first_byte`] is the only
//! place that decision is made, and it refuses the reserved/unused values so a
//! stream is never silently misrouted. The marker byte is written by
//! [`open_client_stream`] and *consumed* by [`accept_server_stream`], so callers
//! only ever see complete messages.
//!
//! # Bounds
//!
//! * one control stream per connection; a second marker stream is reset by the
//!   caller (the server counts it as a protocol violation);
//! * `MAX_CTL_MESSAGE` (64 B) per message body, validated before allocation;
//! * [`CtlRate`] is a *receiver-side* cap: a peer that floods idempotent
//!   messages must not turn into a CPU amplifier. The sender never repeats.
//! * all messages are idempotent: duplicate `ASSOC_CLOSE`/`FLOW_CLOSE`/
//!   `REJECT` cost one lookup, duplicate `NEED_CONTEXT` re-arms context
//!   (harmless).

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};

use super::error::MqpError;
use super::r3::{self, CtlMessage};

/// First byte that marks a bidi stream as the rev3 control stream.
///
/// Chosen far away from the MQP address `atyp` values (`0x01` v4, `0x03`
/// domain, `0x04` v6) that start a TCP relay stream.
pub const MARKER: u8 = r3::CTL_STREAM_MARKER;

/// Largest accepted control-message body.
pub const MAX_CTL_MESSAGE: usize = r3::MAX_CTL_BODY;

/// Largest accepted framing overhead (`type` + `len`).
pub const MAX_CTL_FRAME_OVERHEAD: usize = 3;

/// What a client-opened bidi stream is, decided by its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamClass {
    /// The rev3 control stream (first byte was [`MARKER`] and has been consumed).
    Control,
    /// A TCP relay stream; the first byte is the address `atyp` and has been
    /// consumed but must be fed to the address decoder.
    Tcp {
        /// The consumed address-type byte.
        atyp: u8,
    },
}

/// Classify the first byte of a client-opened bidi stream.
///
/// Returns `None` for a byte that is neither an MQP address type nor the control
/// marker. Callers reset the stream and count the violation; they must never
/// guess a route.
#[must_use]
pub fn classify_first_byte(first: u8) -> Option<StreamClass> {
    match first {
        MARKER => Some(StreamClass::Control),
        // MQP address codec: v4, domain, v6 (the only forms any wire emits).
        0x01 | 0x03 | 0x04 => Some(StreamClass::Tcp { atyp: first }),
        _ => None,
    }
}

/// Encode one control message for the stream, including its `type|len` framing.
///
/// Returns `None` only for an unrepresentable flow id (14-bit overflow); every
/// other field is full-domain.
#[must_use]
pub fn encode_message(msg: CtlMessage) -> Option<Bytes> {
    r3::encode_ctl_message(msg)
}

/// Decode one control message from the front of `buf`.
///
/// Returns the message and the number of bytes consumed, or `None` when `buf`
/// does not yet hold a complete message. A malformed frame is an error and the
/// caller must close the control stream (there is no resynchronisation: QUIC
/// guarantees order, so a bad frame is a peer bug or a corrupted implementation,
/// never loss).
pub fn decode_message(buf: &[u8]) -> Result<Option<(CtlMessage, usize)>, MqpError> {
    if buf.len() < MAX_CTL_FRAME_OVERHEAD {
        return Ok(None);
    }
    let body_len = usize::from(u16::from_le_bytes([buf[1], buf[2]]));
    if body_len > MAX_CTL_MESSAGE {
        return Err(MqpError::Malformed("r3 ctl message body too long"));
    }
    let total = MAX_CTL_FRAME_OVERHEAD + body_len;
    if buf.len() < total {
        return Ok(None);
    }
    let (msg, consumed) = r3::decode_ctl_message(&buf[..total])?;
    if consumed != total {
        return Err(MqpError::Malformed("r3 ctl message length mismatch"));
    }
    Ok(Some((msg, total)))
}

/// Send half of one control stream plus its framing state.
#[derive(Debug)]
pub struct CtlSender {
    send: SendStream,
}

impl CtlSender {
    /// Write one message. QUIC handles reliability; a write error means the
    /// stream/connection is gone and the caller should drop the sender.
    pub async fn send(&mut self, msg: CtlMessage) -> anyhow::Result<()> {
        let body = encode_message(msg)
            .ok_or_else(|| anyhow::anyhow!("r3 control message unrepresentable"))?;
        self.send.write_all(&body).await?;
        Ok(())
    }

    /// Underlying stream, for shutdown (`finish`/`reset`).
    pub fn into_inner(self) -> SendStream {
        self.send
    }
}

/// Client side: open the control stream and write its marker byte.
///
/// Called once per connection right after it is usable (for 0-RTT connections:
/// in the first early-data flight). The returned [`CtlReceiver`] is driven by a
/// connection-scoped task; both halves survive for the connection's life.
pub async fn open_client_stream(conn: &Connection) -> anyhow::Result<(CtlSender, CtlReceiver)> {
    let (mut send, recv) = conn.open_bi().await?;
    send.write_all(&[MARKER]).await?;
    Ok((CtlSender { send }, CtlReceiver::new(recv)))
}

/// Server side: consume the marker byte from an accepted stream and split it
/// into the control halves.
///
/// `first` must be the byte the accept loop already read; returns `None` when it
/// is not [`MARKER`] (the caller routes it as a TCP stream instead).
#[must_use]
pub fn accept_server_stream(
    send: SendStream,
    recv: RecvStream,
    first: u8,
) -> Option<(CtlSender, CtlReceiver)> {
    match classify_first_byte(first)? {
        StreamClass::Control => Some((CtlSender { send }, CtlReceiver::new(recv))),
        StreamClass::Tcp { .. } => None,
    }
}

/// Receive half of one control stream with incremental framing.
#[derive(Debug)]
pub struct CtlReceiver {
    recv: RecvStream,
    /// Read scratch: max one frame plus slack, reused across messages.
    buf: Vec<u8>,
}

impl CtlReceiver {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buf: Vec::with_capacity(MAX_CTL_FRAME_OVERHEAD + MAX_CTL_MESSAGE),
        }
    }

    /// Read the next complete control message; `Ok(None)` means the peer closed
    /// the stream cleanly (no more messages).
    pub async fn recv(&mut self) -> anyhow::Result<Option<CtlMessage>> {
        // Read the framing header, then the body. Two exact reads are fine on a
        // path that carries a handful of bytes for the connection's life.
        let mut head = [0u8; MAX_CTL_FRAME_OVERHEAD];
        match self.recv.read_exact(&mut head).await {
            Ok(()) => {}
            // A clean EOF before any byte is the normal "peer closed" case.
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let body_len = usize::from(u16::from_le_bytes([head[1], head[2]]));
        if body_len > MAX_CTL_MESSAGE {
            anyhow::bail!("r3 ctl message body {body_len} > {MAX_CTL_MESSAGE}");
        }
        self.buf.clear();
        self.buf.extend_from_slice(&head);
        self.buf.resize(MAX_CTL_FRAME_OVERHEAD + body_len, 0);
        if body_len > 0 {
            self.recv
                .read_exact(&mut self.buf[MAX_CTL_FRAME_OVERHEAD..])
                .await?;
        }
        let (msg, consumed) = r3::decode_ctl_message(&self.buf)?;
        if consumed != self.buf.len() {
            anyhow::bail!("r3 ctl message length mismatch");
        }
        Ok(Some(msg))
    }

    /// Underlying stream, for restart/stop.
    pub fn into_inner(self) -> RecvStream {
        self.recv
    }
}

/// Receiver-side rate budget for idempotent-but-costly control messages.
///
/// The wire is reliable, so the sender never repeats; this only bounds a
/// hostile (or buggy) peer that streams duplicates. The budget is far above any
/// legitimate rate: one close per association exit plus one NEED_CONTEXT per lost
/// context window.
#[derive(Debug)]
pub struct CtlRate {
    window_ms: u64,
    max_per_sec: u32,
    count: u32,
}

impl CtlRate {
    /// New budget of `max_per_sec` messages per one-second window.
    #[must_use]
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            window_ms: 0,
            max_per_sec,
            count: max_per_sec,
        }
    }

    /// Default budget: `4096` messages per second per connection.
    #[must_use]
    pub fn default_budget() -> Self {
        Self::new(4096)
    }

    /// Consume one message slot; `false` means the caller must drop the message
    /// (and count it) without acting on it.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.window_ms) >= 1_000 {
            self.window_ms = now_ms;
            self.count = self.max_per_sec;
        }
        if self.count == 0 {
            return false;
        }
        self.count -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_messages() -> Vec<CtlMessage> {
        vec![
            CtlMessage::AssocClose {
                sess: 42,
                reason: 0,
            },
            CtlMessage::FlowClose {
                fid: 0x0002,
                reason: 7,
            },
            CtlMessage::Reject {
                fid: 0x2003,
                reason: 2,
            },
            CtlMessage::NeedContext { fid: 0x0001 },
            CtlMessage::SessClose { sess: 7, reason: 1 },
            CtlMessage::Goaway,
        ]
    }

    #[test]
    fn every_message_roundtrips_through_the_frame() {
        for msg in all_messages() {
            let framed = encode_message(msg).expect("encodable");
            let (got, consumed) = decode_message(&framed)
                .expect("valid frame")
                .expect("complete");
            assert_eq!(got, msg);
            assert_eq!(consumed, framed.len());
        }
    }

    #[test]
    fn partial_frames_wait_for_more_bytes() {
        let msg = CtlMessage::NeedContext { fid: 0x0123 };
        let framed = encode_message(msg).unwrap();
        for cut in 0..framed.len() {
            assert_eq!(
                decode_message(&framed[..cut]).expect("no error before complete"),
                None,
                "prefix {cut} must be incomplete"
            );
        }
        assert!(decode_message(&framed).unwrap().is_some());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        // Body length over the cap.
        let mut huge = Vec::new();
        huge.push(r3::CTL_NEED_CONTEXT);
        huge.extend_from_slice(&(MAX_CTL_MESSAGE as u16 + 1).to_le_bytes());
        huge.resize(MAX_CTL_FRAME_OVERHEAD + MAX_CTL_MESSAGE + 1, 0);
        assert!(decode_message(&huge).is_err());
        // Body length too small for the type.
        let bad = [r3::CTL_ASSOC_CLOSE, 0, 0];
        assert!(decode_message(&bad).is_err());
        // Unknown message type with an empty body is rejected by the codec.
        let unknown = [0x7F, 0, 0];
        assert!(decode_message(&unknown).is_err());
    }

    #[test]
    fn first_byte_classification_is_disjoint_and_total() {
        assert_eq!(classify_first_byte(MARKER), Some(StreamClass::Control));
        for atyp in [0x01u8, 0x03, 0x04] {
            assert_eq!(
                classify_first_byte(atyp),
                Some(StreamClass::Tcp { atyp }),
                "atyp {atyp:#x}"
            );
        }
        for bad in [0x00u8, 0x02, 0x05, 0x06, 0x7F, 0xFE] {
            assert_eq!(classify_first_byte(bad), None, "byte {bad:#x}");
        }
    }

    #[test]
    fn rate_budget_refills_each_second_and_never_underflows() {
        let mut r = CtlRate::new(2);
        // The constructor arms for the first window.
        assert!(r.allow(0));
        assert!(r.allow(1));
        assert!(!r.allow(2));
        assert!(r.allow(1_000));
        assert!(r.allow(1_001));
        assert!(!r.allow(1_002));
        assert!(r.allow(2_000));
    }
}
