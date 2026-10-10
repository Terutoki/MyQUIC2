//! Zero-allocation error type for the MQP-2 codec.
//!
//! Every decode on the relay path runs on peer-controlled bytes at line rate:
//! both datagram readers (the server's per-connection loop in `accept.rs`, the
//! client dispatcher) call [`decode_datagram_ref`](super::datagram::decode_datagram_ref)
//! / [`decode_fragment`](super::fragment::decode_fragment) /
//! [`decode_batch_ref`](super::batch::decode_batch_ref) for every inbound frame,
//! with [`TargetAddrRef::decode`](super::addr::TargetAddrRef::decode) underneath
//! all three. A malformed frame is ordinary traffic — the call sites count it
//! (`dgram_drops::REFUSED`) precisely because a hostile or buggy peer can
//! produce them by the burst — so the error *value* sits on a peer-drivable
//! path, not a cold one.
//!
//! `anyhow` is the wrong type there: every construction boxes an `ErrorImpl`
//! and materializes its message (one allocation plus one format per bad
//! frame), so a malformed-frame flood turns into allocator traffic charged to
//! exactly the flood the counters exist to bound. `MqpError` is `Copy` and
//! holds at most a `&'static str`/`u8`, so constructing one is free; only
//! *formatting* it (a cold log line) can allocate, and [`Display`](std::fmt::Display)
//! reproduces the `anyhow::bail!` texts this replaces byte for byte.
//!
//! Cold boundaries keep their shape: `MqpError` implements
//! `std::error::Error + Send + Sync`, so a `?` inside an `anyhow::Result`
//! function (the TCP head read, `read_mqp_ack`) still converts — and pays the
//! anyhow allocation only when an error actually occurs there.

/// A decode/validation failure of the MQP-2 codec, constructible without a
/// heap allocation (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqpError {
    /// Shape/framing failure: truncated field, wrong frame type, trailing
    /// bytes. The static text names the failed check and matches the
    /// `anyhow::bail!` message it replaced.
    Malformed(&'static str),
    /// A structurally readable field refused by policy: an unspecified or
    /// scoped address, an empty or over-long domain name. Distinct from
    /// [`MqpError::Malformed`] because the two mean different things to an
    /// operator (a hostile/buggy peer versus a target this tunnel will not
    /// dial), mirroring the `Refused`-vs-budget split the drop counters
    /// already make.
    Refused(&'static str),
    /// Unknown address-type byte (`atyp`) in an MQP-2 address header.
    BadAtyp(u8),
    /// Unknown bound-address `atyp` in the TCP-open ACK.
    BadBndAtyp(u8),
    /// Domain bytes are not valid UTF-8.
    BadDomainUtf8,
    /// A BATCH frame named an item count outside `1..=MAX_BATCH_ITEMS`.
    BadBatchCount(u8),
}

impl std::fmt::Display for MqpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MqpError::Malformed(m) | MqpError::Refused(m) => f.write_str(m),
            MqpError::BadAtyp(a) => write!(f, "bad atyp {a}"),
            MqpError::BadBndAtyp(a) => write!(f, "bad bnd atyp {a}"),
            MqpError::BadDomainUtf8 => f.write_str("bad domain utf8"),
            MqpError::BadBatchCount(c) => write!(f, "bad batch count {c}"),
        }
    }
}

impl std::error::Error for MqpError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Display texts are the `anyhow::bail!` messages this type replaced —
    /// a cold boundary that logs `{e}` must not change wording.
    #[test]
    fn display_matches_the_replaced_bail_texts() {
        assert_eq!(MqpError::Malformed("short v4").to_string(), "short v4");
        assert_eq!(
            MqpError::Refused("empty domain").to_string(),
            "empty domain"
        );
        assert_eq!(MqpError::BadAtyp(0x07).to_string(), "bad atyp 7");
        assert_eq!(MqpError::BadBndAtyp(0x02).to_string(), "bad bnd atyp 2");
        assert_eq!(MqpError::BadDomainUtf8.to_string(), "bad domain utf8");
        assert_eq!(
            MqpError::BadBatchCount(200).to_string(),
            "bad batch count 200"
        );
    }

    /// The conversion cold callers rely on: `?` inside an `anyhow::Result`
    /// function still works, and the message survives.
    #[test]
    fn converts_into_anyhow_at_cold_boundaries() {
        fn inner() -> Result<(), MqpError> {
            Err(MqpError::Malformed("bad dgram"))
        }
        fn outer() -> anyhow::Result<()> {
            inner()?;
            Ok(())
        }
        assert_eq!(outer().unwrap_err().to_string(), "bad dgram");
    }
}
