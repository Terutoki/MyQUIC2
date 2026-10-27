//! Wire-version adapter shared by the client and server data planes.
//!
//! The relay supports two application-layer wire revisions behind one internal
//! state model ([`super::r2_flow`], [`crate::udp::r2_stage`], [`crate::udp::r2_reasm`]):
//!
//! * [`Wire::Rev2`] — the shipped MQP-3 rev2 codec ([`super::r2`]): LEB128 flow
//!   ids, `DATA`/`TRAIN`/`FRAG` classes distinguished by the first byte, a
//!   `CTL` DATAGRAM control plane and a per-flow `FLOW_ACK`.
//! * [`Wire::Rev3`] — the clean-slate codec ([`super::r3`]): a fixed 2-byte
//!   packed header, 14-bit owner-split flow ids, no varints, `TRAIN`
//!   `SAME_EQUAL` support, and (at the integration layer) no `HELLO`/`CAPS` and
//!   no per-flow ACK: rare control messages move to one reliable stream.
//!
//! The revision is a property of the **connection** (selected by config plus
//! ALPN, see [`Wire::alpn`]), never sniffed from a frame: a peer of a different
//! revision fails the TLS handshake instead of being misparsed.
//!
//! # Internal id mapping
//!
//! Internally every flow is keyed by the rev2-style connection-scoped `u32`
//! `wire_id = (local << 1) | owner` produced by
//! [`super::r2_flow::FlowIds`]; the rev3 codec speaks 14-bit `fid`s. The
//! [`fid_for`]/[`wire_id_for_fid`] pair maps between them so the flow registry,
//! stager and reassembler stay revision-agnostic:
//!
//! ```text
//! client-owned: wire_id = local << 1        fid = local - 1            (0x0000..=0x1FFF)
//! server-owned: wire_id = (local << 1) | 1  fid = 0x2000 + (local - 1) (0x2000..=0x3FFF)
//! local = 1..=0x2000
//! ```
//!
//! `local > 0x2000` (i.e. more than 8192 flow ids ever handed out by one
//! endpoint on one connection) is the documented rev3 exhaustion point: the
//! mapping returns `None`, the encoders refuse, and the caller falls back to
//! `INLINE` exactly like a full flow table does on rev2.
//!
//! # What this module does not do
//!
//! It does not implement the rev3 control plane (the reliable control stream)
//! or the rev3 no-ACK sender policy; those live at the integration sites
//! (`src/bin/myquic2-client/rev2.rs`, `src/bin/myquic2-server/{accept,reader}.rs`)
//! because they are state-machine changes, not byte-layout changes.

use bytes::Bytes;

use super::addr::TargetAddrRef;
use super::error::MqpError;
use super::r2::{self, Caps};
use super::r2_flow::FlowIds;
use super::r3;

/// Build-time default application-layer wire revision.
///
/// Used when a configuration file does not pin `wire_rev`: **3 (rev3)**, the
/// clean-slate wire (2-byte packed header, no varints, no per-flow ACK, one
/// reliable control stream). Keeping the default in a single constant is what
/// guarantees the client and server defaults can never drift apart.
///
/// There is no runtime mixed-revision tolerance: the revision is selected
/// purely by configuration, and **both revisions default to the historical
/// `h3` ALPN masquerade**. The ALPN label therefore does NOT encode the wire
/// revision by default: a rev2 peer and a rev3 peer configured with the same
/// label complete the TLS handshake and then fail silently at the data plane
/// (frames are dropped; no payload is misrouted, but nothing is forwarded).
/// Deploy matched pairs.
///
/// Operators who want handshake-level skew detection can still pin a
/// distinguishing `alpn` on both sides (for example `alpn = "myquic2/r3"` for
/// rev3 and `h3` for rev2); a mismatch then fails the TLS handshake. See
/// [`Wire::versioned_alpn`] for the conventional labels.
///
/// **Rollback:** rev2 is retained config-selectable for one release. Set
/// `wire_rev = 2` on **both** binaries (upgrade/redeploy them together) to run
/// the rev2 codec, or redeploy the previous binaries. Do not expect a rev3 peer
/// to talk to a rev2 one.
pub const DEFAULT_REV: u8 = 3;

/// Application-layer wire revision of one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// MQP-3 rev2 (shipped wire).
    Rev2,
    /// MQP-3 rev3 (clean-slate wire).
    Rev3,
}

impl Default for Wire {
    /// The rollback-safe default: rev2. Containers that derive `Default` (for
    /// example the fragmenter) therefore start on the shipped wire until the
    /// connection setup explicitly selects a revision.
    fn default() -> Self {
        Wire::Rev2
    }
}

impl Wire {
    /// Numeric revision carried in configuration and logs.
    #[must_use]
    pub const fn rev(self) -> u8 {
        match self {
            Wire::Rev2 => 2,
            Wire::Rev3 => 3,
        }
    }

    /// Map a configured revision number; only 2 and 3 are valid.
    #[must_use]
    pub const fn from_rev(rev: u8) -> Option<Self> {
        match rev {
            2 => Some(Wire::Rev2),
            3 => Some(Wire::Rev3),
            _ => None,
        }
    }

    /// Default ALPN protocol identifier: the `h3` masquerade, used by **both**
    /// revisions unless the operator configures a custom label.
    ///
    /// ALPN is no longer the revision gate by default: `h3` hides only the
    /// label (certificate and MQP framing stay fingerprintable) and a rev2 and
    /// a rev3 peer with the same label will handshake successfully and then
    /// fail at the data plane. That is why deployments must run matched
    /// binaries, and why a skew-strict deployment should pin
    /// [`Wire::versioned_alpn`] labels instead.
    #[must_use]
    pub const fn alpn(self) -> &'static [u8] {
        let _ = self;
        b"h3"
    }

    /// Conventional fail-fast ALPN label for this revision.
    ///
    /// Not used by default (the default is the `h3` masquerade for both
    /// revisions). Setting these labels on both sides restores a TLS-level
    /// revision gate: rev2 `myquic2/3`, rev3 `myquic2/r3`.
    #[must_use]
    pub const fn versioned_alpn(self) -> &'static [u8] {
        match self {
            Wire::Rev2 => super::ack::MQP_ALPN,
            Wire::Rev3 => b"myquic2/r3",
        }
    }

    /// Internal capability set for this revision.
    ///
    /// rev2 negotiates [`Caps`] over `CTL HELLO`/`CAPS`; rev3 has a static
    /// contract (the revision comes from configuration and ALPN is only a
    /// deployment label), so the same protocol bounds are returned as
    /// constants. Both revisions therefore feed identical values to
    /// `frame_limit`/stager code.
    #[must_use]
    pub fn caps(self) -> Caps {
        Caps {
            wire_ver: u16::from(self.rev()),
            ..Caps::default()
        }
    }
}

/// Validate a configured wire revision.
///
/// Shared by [`crate::config::client_conf::ClientConf`] and
/// [`crate::config::server_conf::ServerConf`] so the two binaries cannot drift:
/// only revisions 2 and 3 exist. The ALPN label is deliberately not validated
/// against the revision: both revisions default to `h3`, and a custom label is
/// a deployment choice (a distinguishing pair restores a TLS-level skew gate,
/// but it is not required for a matched deployment).
pub fn validate_config(rev: Option<u8>, _alpn: Option<&str>) -> anyhow::Result<()> {
    let rev = rev.unwrap_or(DEFAULT_REV);
    if Wire::from_rev(rev).is_none() {
        anyhow::bail!("wire_rev {rev}: only 2 (rev2) and 3 (rev3) are supported");
    }
    Ok(())
}

// ---------------- internal id <-> wire fid ----------------

/// Highest one-based internal local id a rev3 `fid` can represent.
pub const MAX_R3_LOCAL_ID: u32 = r3::FIDS_PER_OWNER as u32;

/// Map an internal `wire_id` to the rev3 `fid` that names the same flow.
///
/// Returns `None` for `wire_id == 0` and for ids whose local part exceeds the
/// 14-bit fid space (more than [`MAX_R3_LOCAL_ID`] ids ever allocated by that
/// endpoint), which is the caller's cue to fall back to `INLINE`.
#[must_use]
pub fn fid_for(wire_id: u32) -> Option<u16> {
    if wire_id == 0 {
        return None;
    }
    let local = wire_id >> 1;
    if local == 0 || local > MAX_R3_LOCAL_ID {
        return None;
    }
    let base = if wire_id & 1 == 0 {
        0u16
    } else {
        r3::SERVER_FID_BASE
    };
    Some(base + (local as u16 - 1))
}

/// Inverse of [`fid_for`]: the internal `wire_id` for a rev3 `fid`.
#[must_use]
pub fn wire_id_for_fid(fid: u16) -> Option<u32> {
    let (owner, local) = if fid <= r3::CLIENT_FID_MAX {
        (0u32, u32::from(fid) + 1)
    } else if (r3::SERVER_FID_BASE..=r3::FID_MAX).contains(&fid) {
        (1u32, u32::from(fid - r3::SERVER_FID_BASE) + 1)
    } else {
        return None;
    };
    Some((local << 1) | owner)
}

/// Whether `wire_id` was allocated by the server half of the id space.
#[inline]
fn wire_id_server_owned(wire_id: u32) -> bool {
    wire_id & 1 != 0
}

// ---------------- frame classification ----------------

/// Logical frame family, revision-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// `DATA` steady or binding-carrying (`OPEN`/`SRC`/`INLINE`).
    Data,
    /// Multi-payload `TRAIN`.
    Train,
    /// Fragmented payload.
    Frag,
    /// Control frame (rev2 DATAGRAM `CTL`; rev3 never classifies frames as
    /// control because its control plane is a reliable stream).
    Ctl,
}

/// Classify the first byte of a DATAGRAM body for the connection's `wire`.
#[must_use]
pub fn kind(wire: Wire, b: &[u8]) -> Option<FrameKind> {
    match wire {
        Wire::Rev2 => match r2::kind(b)? {
            r2::R2Kind::Data => Some(FrameKind::Data),
            r2::R2Kind::Train => Some(FrameKind::Train),
            r2::R2Kind::Frag => Some(FrameKind::Frag),
            r2::R2Kind::Ctl => Some(FrameKind::Ctl),
        },
        Wire::Rev3 => match r3::kind(b)? {
            r3::R3Kind::Data | r3::R3Kind::DataExt => Some(FrameKind::Data),
            r3::R3Kind::Train => Some(FrameKind::Train),
            r3::R3Kind::Frag => Some(FrameKind::Frag),
        },
    }
}

// ---------------- encode wrappers ----------------

/// Encode a steady `DATA` frame.
#[must_use]
pub fn encode_data_steady(wire: Wire, wire_id: u32, payload: &[u8], limit: usize) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_data_steady(wire_id, payload, limit),
        Wire::Rev3 => r3::encode_data_steady(fid_for(wire_id)?, payload, limit),
    }
}

/// Encode a binding-carrying `DATA` frame (`OPEN`, `OPEN|SRC`, or `INLINE`).
///
/// `wire_id == None` selects the stateless `INLINE` form. For rev3 the
/// rebinding case (`src == true` on a client-owned flow) is the dedicated `SRC`
/// form (no session), while a server-owned new flow is `OPEN_SRC`; rev2 has a
/// single `OPEN|SRC` form, so the adapter splits them.
#[must_use]
pub fn encode_data_open(
    wire: Wire,
    wire_id: u32,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_data_open(wire_id, sess, addr, src, payload, limit),
        Wire::Rev3 => {
            let fid = fid_for(wire_id)?;
            if src && !wire_id_server_owned(wire_id) {
                r3::encode_data_src(fid, addr, payload, limit)
            } else {
                r3::encode_data_open(fid, sess, addr, src, payload, limit)
            }
        }
    }
}

/// Encode the stateless `INLINE` form (no flow id).
#[must_use]
pub fn encode_data_inline(
    wire: Wire,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_data_inline(sess, addr, src, payload, limit),
        Wire::Rev3 => {
            let _ = src;
            r3::encode_data_inline(sess, addr, payload, limit)
        }
    }
}

/// Encode a single-flow `TRAIN`.
#[must_use]
pub fn encode_train_same(
    wire: Wire,
    wire_id: u32,
    payloads: &[&[u8]],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_train_same(wire_id, payloads, limit),
        Wire::Rev3 => r3::encode_train_same(fid_for(wire_id)?, payloads, limit),
    }
}

/// Encode a constant-item-length single-flow `TRAIN`.
///
/// rev2 has no equal-length form, so the adapter falls back to the regular
/// `SAME` form there; rev3 uses `SAME_EQUAL` and saves the per-item length byte.
#[must_use]
pub fn encode_train_same_equal(
    wire: Wire,
    wire_id: u32,
    payloads: &[&[u8]],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_train_same(wire_id, payloads, limit),
        Wire::Rev3 => r3::encode_train_same_equal(fid_for(wire_id)?, payloads, limit),
    }
}

/// Encode a dictionary `TRAIN`; `flows` are internal wire ids indexed by the
/// per-item index.
#[must_use]
pub fn encode_train_dict(
    wire: Wire,
    flows: &[u32],
    items: &[(u8, &[u8])],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_train_dict(flows, items, limit),
        Wire::Rev3 => {
            // The dict form has no owner half of its own: each fid carries its
            // own half, so map every id and bail out to the caller's fail-safe
            // (a standalone frame / INLINE) when one cannot be represented.
            let mut fids = [0u16; r3::MAX_TRAIN_ITEMS];
            if flows.len() > fids.len() {
                return None;
            }
            for (slot, id) in fids.iter_mut().zip(flows) {
                *slot = fid_for(*id)?;
            }
            r3::encode_train_dict(fids.get(..flows.len())?, items, limit)
        }
    }
}

/// Encode a steady `FRAG` frame.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_frag_steady(
    wire: Wire,
    wire_id: u32,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_frag_steady(wire_id, frag_id, idx, total, chunk, limit),
        Wire::Rev3 => r3::encode_frag_steady(fid_for(wire_id)?, frag_id, idx, total, chunk, limit),
    }
}

/// Encode a binding-carrying `FRAG` frame.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_frag_open(
    wire: Wire,
    wire_id: u32,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => {
            r2::encode_frag_open(wire_id, sess, addr, src, frag_id, idx, total, chunk, limit)
        }
        Wire::Rev3 => {
            let fid = fid_for(wire_id)?;
            if src && !wire_id_server_owned(wire_id) {
                r3::encode_frag_src(fid, addr, frag_id, idx, total, chunk, limit)
            } else {
                r3::encode_frag_open(fid, sess, addr, src, frag_id, idx, total, chunk, limit)
            }
        }
    }
}

/// Encode the stateless `INLINE` fragment form.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_frag_inline(
    wire: Wire,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => r2::encode_frag_inline(sess, addr, src, frag_id, idx, total, chunk, limit),
        Wire::Rev3 => {
            let _ = src;
            r3::encode_frag_inline(sess, addr, frag_id, idx, total, chunk, limit)
        }
    }
}

/// Encode a rev2 control frame for the DATAGRAM plane.
///
/// rev3 has no control DATAGRAMs: its control plane is the reliable stream
/// (`r3::encode_ctl_message`), so this returns `None` for [`Wire::Rev3`] and
/// the integration site must send on the control stream instead.
#[must_use]
pub fn encode_ctl_datagram(wire: Wire, ctl: &r2::Ctl) -> Option<Bytes> {
    match wire {
        Wire::Rev2 => Some(r2::encode_ctl(ctl)),
        Wire::Rev3 => None,
    }
}

// ---------------- decode adapters ----------------

/// Borrowed, revision-independent view of a decoded `DATA` frame.
#[derive(Debug, Clone, Copy)]
pub struct DataView<'a> {
    /// Internal wire id; `None` for the stateless `INLINE` form.
    pub wire_id: Option<u32>,
    /// Session id carried by a binding form.
    pub sess: Option<u32>,
    /// Inline address (target or source).
    pub addr: Option<TargetAddrRef<'a>>,
    /// `addr` names the actual source, not the bound target.
    pub src: bool,
    /// Payload bytes (rest of the frame).
    pub payload: &'a [u8],
}

impl<'a> DataView<'a> {
    fn from_rev2(d: r2::DataRef<'a>) -> Self {
        Self {
            wire_id: d.id,
            sess: d.sess,
            addr: d.addr,
            src: d.src,
            payload: d.payload,
        }
    }

    fn try_from_rev3(d: r3::DataRef<'a>) -> Result<Self, MqpError> {
        let wire_id = match d.fid {
            Some(fid) => {
                Some(wire_id_for_fid(fid).ok_or(MqpError::Malformed("r3 data fid out of range"))?)
            }
            None => None,
        };
        Ok(Self {
            wire_id,
            sess: d.sess,
            addr: d.addr,
            src: d.src,
            payload: d.payload,
        })
    }
}

/// Decode a `DATA` frame for the connection's wire revision.
pub fn decode_data(wire: Wire, b: &[u8]) -> Result<DataView<'_>, MqpError> {
    match wire {
        Wire::Rev2 => Ok(DataView::from_rev2(r2::decode_data(b)?)),
        Wire::Rev3 => DataView::try_from_rev3(r3::decode_data(b)?),
    }
}

/// Decoded `TRAIN` frame, revision-independent.
#[derive(Debug, Clone)]
pub enum TrainView<'a> {
    /// rev2 codec view.
    Rev2(r2::TrainFrame<'a>),
    /// rev3 codec view.
    Rev3(r3::TrainFrame<'a>),
}

impl<'a> TrainView<'a> {
    /// Iterate `(internal wire_id, payload)` in wire order.
    #[must_use]
    pub fn items(&self) -> TrainItemIter<'a> {
        match self {
            TrainView::Rev2(t) => TrainItemIter::Rev2(t.items()),
            TrainView::Rev3(t) => TrainItemIter::Rev3(t.items()),
        }
    }

    /// Wire form number (rev2 same/dict, rev3 same/same-equal/dict).
    #[must_use]
    pub fn form(&self) -> u8 {
        match self {
            TrainView::Rev2(t) => t.form,
            TrainView::Rev3(t) => t.form,
        }
    }

    /// Number of items in the frame.
    #[must_use]
    pub fn count(&self) -> u8 {
        match self {
            TrainView::Rev2(t) => t.count,
            TrainView::Rev3(t) => t.count,
        }
    }
}

/// Iterator over a decoded `TRAIN`'s `(wire_id, payload)` items.
pub enum TrainItemIter<'a> {
    /// rev2 iterator.
    Rev2(r2::TrainItems<'a>),
    /// rev3 iterator.
    Rev3(r3::TrainItems<'a>),
}

impl<'a> Iterator for TrainItemIter<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TrainItemIter::Rev2(it) => it.next(),
            TrainItemIter::Rev3(it) => {
                let (fid, payload) = it.next()?;
                Some((wire_id_for_fid(fid)?, payload))
            }
        }
    }
}

/// Decode a `TRAIN` frame for the connection's wire revision.
pub fn decode_train(wire: Wire, b: &[u8]) -> Result<TrainView<'_>, MqpError> {
    match wire {
        Wire::Rev2 => Ok(TrainView::Rev2(r2::decode_train(b)?)),
        Wire::Rev3 => Ok(TrainView::Rev3(r3::decode_train(b)?)),
    }
}

/// Borrowed, revision-independent view of a decoded `FRAG` frame.
#[derive(Debug, Clone, Copy)]
pub struct FragView<'a> {
    /// Internal wire id; `None` for the stateless `INLINE` form.
    pub wire_id: Option<u32>,
    /// Session id carried by a binding form.
    pub sess: Option<u32>,
    /// Inline address (target or source).
    pub addr: Option<TargetAddrRef<'a>>,
    /// `addr` names the actual source.
    pub src: bool,
    /// Fragment identity and ordering.
    pub frag_id: u32,
    /// Fragment index and total.
    pub idx: u8,
    /// Fragment total.
    pub total: u8,
    /// Offset of the chunk inside the buffer handed to the decoder.
    pub chunk_off: usize,
    /// Fragment payload bytes.
    pub chunk: &'a [u8],
}

impl<'a> FragView<'a> {
    fn from_rev2(f: r2::FragRef<'a>) -> Self {
        Self {
            wire_id: f.id,
            sess: f.sess,
            addr: f.addr,
            src: f.src,
            frag_id: f.frag_id,
            idx: f.idx,
            total: f.total,
            chunk_off: f.chunk_off,
            chunk: f.chunk,
        }
    }

    fn try_from_rev3(f: r3::FragRef<'a>) -> Result<Self, MqpError> {
        let wire_id = match f.fid {
            Some(fid) => {
                Some(wire_id_for_fid(fid).ok_or(MqpError::Malformed("r3 frag fid out of range"))?)
            }
            None => None,
        };
        Ok(Self {
            wire_id,
            sess: f.sess,
            addr: f.addr,
            src: f.src,
            frag_id: f.frag_id,
            idx: f.idx,
            total: f.total,
            chunk_off: f.chunk_off,
            chunk: f.chunk,
        })
    }
}

/// Decode a `FRAG` frame for the connection's wire revision.
pub fn decode_frag(wire: Wire, b: &[u8]) -> Result<FragView<'_>, MqpError> {
    match wire {
        Wire::Rev2 => Ok(FragView::from_rev2(r2::decode_frag(b)?)),
        Wire::Rev3 => FragView::try_from_rev3(r3::decode_frag(b)?),
    }
}

/// Allocate the next rev3-capable internal wire id.
///
/// Convenience for integration sites that already hold a [`FlowIds`] allocator
/// and a [`Wire`]: on rev3 an id that cannot be represented as a 14-bit fid is
/// refused *before* it is inserted into the flow registry, so the caller can
/// take the `INLINE` fail-safe instead of installing an unusable binding.
/// rev2 accepts every id the allocator returns.
#[must_use]
pub fn alloc_wire_id(ids: &FlowIds, wire: Wire) -> Option<u32> {
    let id = ids.alloc()?;
    match wire {
        Wire::Rev2 => Some(id),
        Wire::Rev3 => fid_for(id).map(|_| id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn v4(port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        ))
    }

    fn v6(port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
    }

    fn dom(name: &'static str, port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Domain(name, port)
    }

    #[test]
    fn rev_and_alpn_roundtrip() {
        assert_eq!(Wire::Rev2.rev(), 2);
        assert_eq!(Wire::Rev3.rev(), 3);
        // Both revisions default to the same h3 masquerade label; the
        // versioned labels are opt-in fail-fast identifiers.
        assert_eq!(Wire::Rev2.alpn(), b"h3");
        assert_eq!(Wire::Rev3.alpn(), b"h3");
        assert_eq!(Wire::Rev2.versioned_alpn(), b"myquic2/3");
        assert_eq!(Wire::Rev3.versioned_alpn(), b"myquic2/r3");
        assert_eq!(Wire::from_rev(2), Some(Wire::Rev2));
        assert_eq!(Wire::from_rev(3), Some(Wire::Rev3));
        assert_eq!(Wire::from_rev(0), None);
        assert_eq!(Wire::from_rev(4), None);
    }

    #[test]
    fn caps_are_static_and_revision_tagged() {
        let c2 = Wire::Rev2.caps();
        let c3 = Wire::Rev3.caps();
        assert_eq!(c2.wire_ver, 2);
        assert_eq!(c3.wire_ver, 3);
        // Every protocol limit is identical: only the version marker differs.
        let mut c2 = c2;
        let mut c3 = c3;
        c2.wire_ver = 0;
        c3.wire_ver = 0;
        assert_eq!(c2, c3);
        assert_eq!(c3.max_frame_bytes, r2::R2_DEFAULT_MAX_FRAME_BYTES);
        assert_eq!(usize::from(c3.max_train_items), r3::MAX_TRAIN_ITEMS);
    }

    #[test]
    fn config_validation_cases() {
        // Unset -> build default is accepted.
        assert!(validate_config(None, None).is_ok());
        assert!(validate_config(Some(2), None).is_ok());
        assert!(validate_config(Some(2), Some("myquic2/2")).is_ok());
        // rev3 accepts any ALPN label: both revisions default to h3, and a
        // label is a deployment choice, not a revision switch.
        assert!(validate_config(Some(3), None).is_ok());
        assert!(validate_config(Some(3), Some("h3")).is_ok());
        assert!(validate_config(Some(3), Some("myquic2/r3")).is_ok());
        assert!(validate_config(Some(3), Some("custom-label")).is_ok());
        // Revisions outside 2/3 are refused.
        assert!(validate_config(Some(0), None).is_err());
        assert!(validate_config(Some(1), None).is_err());
        assert!(validate_config(Some(4), None).is_err());
    }

    #[test]
    fn id_mapping_boundaries_roundtrip() {
        // Client-owned ids: local 1..=0x2000 => wire 2,4,..,0x4000.
        for local in [1u32, 2, 127, 128, 0x1FFF, 0x2000] {
            let wire_id = local << 1;
            let fid = fid_for(wire_id).expect("client id maps");
            assert_eq!(u32::from(fid), local - 1);
            assert_eq!(wire_id_for_fid(fid), Some(wire_id));
        }
        // Server-owned ids: local 1..=0x2000 => wire 3,5,..,0x4001.
        for local in [1u32, 2, 127, 128, 0x1FFF, 0x2000] {
            let wire_id = (local << 1) | 1;
            let fid = fid_for(wire_id).expect("server id maps");
            assert_eq!(u32::from(fid), u32::from(0x2000 + (local as u16 - 1)));
            assert_eq!(wire_id_for_fid(fid), Some(wire_id));
        }
        // Exhaustion: the next local id cannot be represented.
        assert_eq!(fid_for(0x2001 << 1), None);
        assert_eq!(fid_for((0x2001 << 1) | 1), None);
        assert_eq!(fid_for(0), None);
        // Rev3 id space edges.
        assert_eq!(wire_id_for_fid(0), Some(2));
        assert_eq!(wire_id_for_fid(r3::CLIENT_FID_MAX), Some(0x4000));
        assert_eq!(wire_id_for_fid(r3::SERVER_FID_BASE), Some(3));
        assert_eq!(wire_id_for_fid(r3::FID_MAX), Some(0x4001));
        assert_eq!(wire_id_for_fid(r3::FID_MAX + 1), None);
    }

    #[test]
    fn alloc_respects_rev3_exhaustion() {
        let ids = FlowIds::new(false);
        for _ in 0..(r3::FIDS_PER_OWNER as u32) {
            assert!(alloc_wire_id(&ids, Wire::Rev3).is_some());
        }
        assert_eq!(alloc_wire_id(&ids, Wire::Rev3), None);
        // rev2 keeps allocating past the fid space.
        assert!(alloc_wire_id(&ids, Wire::Rev2).is_some());
    }

    #[test]
    fn rev2_encoding_is_byte_identical_through_the_adapter() {
        let id = 0x1234u32; // typical rev2 id: 2-byte varint
        assert_eq!(
            encode_data_steady(Wire::Rev2, id, b"abc", 1500).unwrap(),
            r2::encode_data_steady(id, b"abc", 1500).unwrap()
        );
        assert_eq!(
            encode_data_open(Wire::Rev2, id, 7, &v4(53), false, b"abc", 1500).unwrap(),
            r2::encode_data_open(id, 7, &v4(53), false, b"abc", 1500).unwrap()
        );
        assert_eq!(
            encode_data_open(Wire::Rev2, id, 7, &v4(53), true, b"abc", 1500).unwrap(),
            r2::encode_data_open(id, 7, &v4(53), true, b"abc", 1500).unwrap()
        );
        assert_eq!(
            encode_data_inline(Wire::Rev2, 7, &dom("example.com", 53), false, b"z", 1500).unwrap(),
            r2::encode_data_inline(7, &dom("example.com", 53), false, b"z", 1500).unwrap()
        );
        let payloads: [&[u8]; 2] = [b"abc", b"de"];
        assert_eq!(
            encode_train_same(Wire::Rev2, id, &payloads, 1500).unwrap(),
            r2::encode_train_same(id, &payloads, 1500).unwrap()
        );
        let items: [(u8, &[u8]); 2] = [(0, b"abc"), (1, b"de")];
        assert_eq!(
            encode_train_dict(Wire::Rev2, &[id, id + 2], &items, 1500).unwrap(),
            r2::encode_train_dict(&[id, id + 2], &items, 1500).unwrap()
        );
        assert_eq!(
            encode_frag_steady(Wire::Rev2, id, 9, 0, 2, b"qq", 1500).unwrap(),
            r2::encode_frag_steady(id, 9, 0, 2, b"qq", 1500).unwrap()
        );
        assert_eq!(
            encode_frag_open(Wire::Rev2, id, 7, &v6(443), false, 9, 0, 2, b"qq", 1500).unwrap(),
            r2::encode_frag_open(id, 7, &v6(443), false, 9, 0, 2, b"qq", 1500).unwrap()
        );
        assert_eq!(
            encode_frag_inline(Wire::Rev2, 7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap(),
            r2::encode_frag_inline(7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap()
        );
    }

    #[test]
    fn rev3_data_roundtrip_and_mapping() {
        // Hot steady id: one byte of fid high bits must stay in b0[5:0].
        for local in [1u32, 2, 0x40, 0x1FFF, 0x2000] {
            let wire_id = local << 1;
            let d = encode_data_steady(Wire::Rev3, wire_id, b"abc", 1500).unwrap();
            assert_eq!(d.len(), 2 + 3);
            let view = decode_data(Wire::Rev3, &d).unwrap();
            assert_eq!(view.wire_id, Some(wire_id));
            assert_eq!(view.payload, b"abc");
        }
        for local in [1u32, 0x2000] {
            let wire_id = (local << 1) | 1;
            let d = encode_data_steady(Wire::Rev3, wire_id, b"abc", 1500).unwrap();
            let view = decode_data(Wire::Rev3, &d).unwrap();
            assert_eq!(view.wire_id, Some(wire_id));
        }
        // Exhausted internal id cannot be encoded on rev3.
        assert!(encode_data_steady(Wire::Rev3, 0x2001 << 1, b"x", 1500).is_none());
    }

    #[test]
    fn rev3_open_src_inline_roundtrip() {
        let wid = 2u32; // client-owned, local 1
        let d = encode_data_open(Wire::Rev3, wid, 7, &v4(53), false, b"abc", 1500).unwrap();
        let v = decode_data(Wire::Rev3, &d).unwrap();
        assert_eq!(v.wire_id, Some(wid));
        assert_eq!(v.sess, Some(7));
        assert!(!v.src);
        assert_eq!(v.addr, Some(v4(53)));
        assert_eq!(v.payload, b"abc");
        // Client-owned rebind uses the session-less SRC form.
        let d = encode_data_open(Wire::Rev3, wid, 7, &v4(53), true, b"abc", 1500).unwrap();
        let v = decode_data(Wire::Rev3, &d).unwrap();
        assert_eq!(v.wire_id, Some(wid));
        assert_eq!(v.sess, None);
        assert!(v.src);
        // Server-owned new flow keeps OPEN_SRC's session context.
        let swid = 3u32; // server-owned, local 1
        let d = encode_data_open(Wire::Rev3, swid, 7, &v4(53), true, b"abc", 1500).unwrap();
        let v = decode_data(Wire::Rev3, &d).unwrap();
        assert_eq!(v.wire_id, Some(swid));
        assert_eq!(v.sess, Some(7));
        assert!(v.src);
        // Stateless INLINE.
        let d =
            encode_data_inline(Wire::Rev3, 7, &dom("example.com", 53), false, b"z", 1500).unwrap();
        let v = decode_data(Wire::Rev3, &d).unwrap();
        assert_eq!(v.wire_id, None);
        assert_eq!(v.sess, Some(7));
        assert_eq!(v.addr, Some(dom("example.com", 53)));
    }

    #[test]
    fn rev3_train_roundtrip_maps_ids() {
        let local_a = 3u32; // client local => wire 6
        let local_b = 4u32; // client local => wire 8
        let wa = local_a << 1;
        let wb = local_b << 1;
        let payloads: [&[u8]; 2] = [b"abc", b"def"];
        let d = encode_train_same(Wire::Rev3, wa, &payloads, 1500).unwrap();
        let t = decode_train(Wire::Rev3, &d).unwrap();
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(got, vec![(wa, &b"abc"[..]), (wa, &b"def"[..])]);
        assert_eq!(t.count(), 2);

        let items: [(u8, &[u8]); 3] = [(0, b"a"), (1, b"bb"), (0, b"ccc")];
        let d = encode_train_dict(Wire::Rev3, &[wa, wb], &items, 1500).unwrap();
        let t = decode_train(Wire::Rev3, &d).unwrap();
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![(wa, &b"a"[..]), (wb, &b"bb"[..]), (wa, &b"ccc"[..])]
        );
        // A train mixing halves maps each id to its own owner.
        let server_wid = (1u32 << 1) | 1; // server local 1
        let items: [(u8, &[u8]); 2] = [(0, b"x"), (1, b"y")];
        let d = encode_train_dict(Wire::Rev3, &[wa, server_wid], &items, 1500).unwrap();
        let got: Vec<(u32, &[u8])> = decode_train(Wire::Rev3, &d).unwrap().items().collect();
        assert_eq!(got, vec![(wa, &b"x"[..]), (server_wid, &b"y"[..])]);
        // Unrepresentable id refuses to encode rather than emitting a bad frame.
        assert!(encode_train_dict(Wire::Rev3, &[0x2001 << 1], &items[..1], 1500).is_none());
    }

    #[test]
    fn rev3_frag_roundtrip() {
        let wid = 2u32;
        let d = encode_frag_steady(Wire::Rev3, wid, 9, 1, 3, b"abc", 1500).unwrap();
        let f = decode_frag(Wire::Rev3, &d).unwrap();
        assert_eq!(f.wire_id, Some(wid));
        assert_eq!(f.frag_id, 9);
        assert_eq!((f.idx, f.total), (1, 3));
        assert_eq!(f.chunk, b"abc");
        let d = encode_frag_open(Wire::Rev3, wid, 7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap();
        let f = decode_frag(Wire::Rev3, &d).unwrap();
        assert_eq!(f.sess, Some(7));
        assert_eq!(f.addr, Some(v4(53)));
        let d = encode_frag_inline(Wire::Rev3, 7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap();
        let f = decode_frag(Wire::Rev3, &d).unwrap();
        assert_eq!(f.wire_id, None);
        assert_eq!(f.sess, Some(7));
    }

    #[test]
    fn kind_is_revision_specific() {
        // rev2 steady DATA.
        let d = r2::encode_data_steady(2, b"x", 1500).unwrap();
        assert_eq!(kind(Wire::Rev2, &d), Some(FrameKind::Data));
        assert_eq!(kind(Wire::Rev3, &d), Some(FrameKind::Data)); // rev3 also class 00
        // rev2 CTL is rev3 INLINE-ish; classification is only used per revision.
        let c = r2::encode_ctl(&r2::Ctl::FlowClose { id: 2 });
        assert_eq!(kind(Wire::Rev2, &c), Some(FrameKind::Ctl));
        // rev3 train/frag classes.
        let payloads: [&[u8]; 1] = [b"x"];
        let t = encode_train_same(Wire::Rev3, 2, &payloads, 1500).unwrap();
        assert_eq!(kind(Wire::Rev3, &t), Some(FrameKind::Train));
        let f = encode_frag_steady(Wire::Rev3, 2, 1, 0, 1, b"x", 1500).unwrap();
        assert_eq!(kind(Wire::Rev3, &f), Some(FrameKind::Frag));
        // Empty input is not a frame in either revision.
        assert_eq!(kind(Wire::Rev2, &[]), None);
        assert_eq!(kind(Wire::Rev3, &[]), None);
    }

    #[test]
    fn ctl_datagram_is_rev2_only() {
        let ctl = r2::Ctl::FlowAck {
            id: 2,
            status: r2::R2_ACK_OPEN,
        };
        assert!(encode_ctl_datagram(Wire::Rev2, &ctl).is_some());
        assert!(encode_ctl_datagram(Wire::Rev3, &ctl).is_none());
    }
}
