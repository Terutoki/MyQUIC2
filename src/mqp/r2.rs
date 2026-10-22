//! MQP-3 wire **rev2** codec: connection-scoped flow ids, no per-frame session,
//! compact TRAIN/FRAG, and a DATAGRAM-carried CTL plane.
//!
//! This is deliberately **wire-incompatible** with the v0.2.0 MQP-3 codec in
//! [`super::v3`] and with MQP-2; the two only share the SOCKS5 address encoding
//! ([`super::addr`]). The protocol is still called *MQP-3*: the wire version
//! lives in [`R2_WIRE_VER`] inside `CTL HELLO`/`CAPS`, never in a new name.
//!
//! # First-byte safety
//!
//! Every rev2 frame starts with a byte whose high nibble is `0` and which is
//! not one of the MQP-2 type bytes (`0x02`, `0x05`, `0x06`). Both the shipped
//! v2 decoder and the v3 decoder treat such a first byte as an unknown frame
//! and drop it, so a mixed-version deployment can never be misparsed into a
//! wrong route:
//!
//! ```text
//! 0x00 DATA steady      0x01 DATA extended
//! 0x04 TRAIN            0x08 FRAG steady
//! 0x09 FRAG extended    0x0C CTL
//! ```
//!
//! # Identity
//!
//! A flow is named by a connection-scoped `u32` wire id:
//! `wire_id = (local_id << 1) | owner`, where the low bit says which endpoint
//! allocated it (client `0`, server `1`). `local_id` is monotonic per
//! connection and never reused while the connection lives, so a delayed frame
//! for a closed flow can only hit a closed table entry — never a fresh target.
//! `wire_id == 0` is reserved; flows without an id use the `INLINE` form, which
//! carries `session u32 + addr` and is the fail-safe for a full flow table.
//!
//! # Design constraints
//!
//! * one QUIC DATAGRAM body carries exactly one rev2 frame; `DATA`/`FRAG`
//!   payloads are the rest of the datagram (no length field);
//! * every decoder validates length/range before slicing and returns
//!   [`MqpError`] instead of panicking on peer-controlled input;
//! * `TRAIN` items reference already-open flows only; a flow's first frame is a
//!   standalone `DATA OPEN` (or `FRAG` first fragment with `OPEN`), so no
//!   per-item inline address is needed;
//! * control frames are idempotent and loss-tolerant: losing an ack only delays
//!   compression, never correctness.

use std::net::SocketAddr;

use bytes::Bytes;

use super::addr::{AddrHeader, TargetAddr, TargetAddrRef};
use super::error::MqpError;

/// Wire version advertised by `CTL HELLO`/`CAPS`. The protocol name stays
/// MQP-3; this is only the internal revision of the wire format.
pub const R2_WIRE_VER: u16 = 2;

/// Magic carried by `HELLO`/`CAPS` bodies.
pub const R2_MAGIC: [u8; 2] = *b"M3";

// ---------------- first-byte kinds ----------------

pub const R2_DATA: u8 = 0x00;
pub const R2_DATA_EXT: u8 = 0x01;
pub const R2_TRAIN: u8 = 0x04;
pub const R2_FRAG: u8 = 0x08;
pub const R2_FRAG_EXT: u8 = 0x09;
pub const R2_CTL: u8 = 0x0C;

/// High nibble of a safe rev2 first byte (all kinds have `0` here).
pub const R2_FIRST_MASK: u8 = 0xF0;

/// `DATA`/`FRAG` extended-header flags.
pub const R2_FLAG_OPEN: u8 = 0x01;
pub const R2_FLAG_INLINE: u8 = 0x02;
pub const R2_FLAG_SRC: u8 = 0x04;

const R2_EXT_FLAGS_MASK: u8 = R2_FLAG_OPEN | R2_FLAG_INLINE | R2_FLAG_SRC;

/// `TRAIN` forms.
pub const R2_TRAIN_FORM_SAME: u8 = 0;
pub const R2_TRAIN_FORM_DICT: u8 = 1;

/// `CTL` opcodes.
pub const R2_CTL_HELLO: u8 = 0x01;
pub const R2_CTL_CAPS: u8 = 0x02;
pub const R2_CTL_FLOW_ACK: u8 = 0x10;
pub const R2_CTL_FLOW_REJECT: u8 = 0x11;
pub const R2_CTL_FLOW_CLOSE: u8 = 0x12;
pub const R2_CTL_SESS_CLOSE: u8 = 0x20;

/// `FLOW_ACK`/`FLOW_REJECT` status/reason values.
pub const R2_ACK_OPEN: u8 = 0;
pub const R2_REJECT_POLICY: u8 = 1;
pub const R2_REJECT_TABLE_FULL: u8 = 2;
pub const R2_REJECT_DNS: u8 = 3;

/// Bounds shared by the encoder and decoder. The defaults are the values the
/// existing code already uses (64 flows/session, 8 KiB reassembly, 1472 B max
/// UDP payload); `CAPS` only makes them negotiable.
pub const R2_MAX_TRAIN_ITEMS: usize = 64;
pub const R2_MAX_FRAG_TOTAL: u8 = 64;
pub const R2_DEFAULT_MAX_CONN_FLOWS: u16 = 4096;
pub const R2_DEFAULT_MAX_FLOWS_SESS: u16 = 64;
pub const R2_DEFAULT_MAX_TRAIN_ITEMS: u8 = R2_MAX_TRAIN_ITEMS as u8;
pub const R2_DEFAULT_MAX_FRAME_BYTES: u16 = 1472;
pub const R2_DEFAULT_MAX_REASSEMBLY: u16 = 8192;

const _: () = {
    assert!(R2_DEFAULT_MAX_TRAIN_ITEMS as usize <= R2_MAX_TRAIN_ITEMS);
};

/// Framing kind of a rev2 frame, or `None` when `b` is not a rev2 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R2Kind {
    Data,
    Train,
    Frag,
    Ctl,
}

/// Whether `b` starts with a rev2 first byte (safe for old peers to drop).
#[must_use]
pub fn is_r2(b: &[u8]) -> bool {
    kind(b).is_some()
}

/// Classify the first byte of `b`; `None` for any non-rev2 byte.
#[must_use]
pub fn kind(b: &[u8]) -> Option<R2Kind> {
    match *b.first()? {
        R2_DATA | R2_DATA_EXT => Some(R2Kind::Data),
        R2_TRAIN => Some(R2Kind::Train),
        R2_FRAG | R2_FRAG_EXT => Some(R2Kind::Frag),
        R2_CTL => Some(R2Kind::Ctl),
        _ => None,
    }
}

// ---------------- flow ids ----------------

/// Build a wire id from a sender-local monotonic id plus the owner bit.
/// `local_id == 0` and ids that would overflow the shifted space are rejected.
#[must_use]
pub fn make_wire_id(local_id: u32, server_owned: bool) -> Option<u32> {
    if local_id == 0 || local_id > (u32::MAX >> 1) {
        return None;
    }
    Some((local_id << 1) | u32::from(server_owned))
}

/// Sender-local part of a wire id (without the owner bit).
#[must_use]
pub fn wire_id_local(id: u32) -> u32 {
    id >> 1
}

/// Whether a wire id was allocated by the server endpoint.
#[must_use]
pub fn wire_id_server_owned(id: u32) -> bool {
    id & 1 != 0
}

/// Valid data-frame flow id: any non-zero wire id.
#[inline]
fn valid_wire_id(id: u32) -> bool {
    id != 0
}

// ---------------- varints ----------------

/// LEB128 length of `n`.
#[must_use]
pub fn varint_len(mut n: u32) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

fn put_varint(out: &mut Vec<u8>, mut n: u32) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn get_varint(b: &[u8], off: &mut usize) -> Result<u32, MqpError> {
    let mut value = 0u32;
    for i in 0..5 {
        let byte = *b
            .get(*off)
            .ok_or(MqpError::Malformed("truncated r2 varint"))?;
        *off += 1;
        if i == 4 {
            // Only the low 4 bits fit in a u32 at shift 28; a continuation bit
            // or any higher payload bit means the value overflowed.
            if byte & 0xF0 != 0 {
                return Err(MqpError::Malformed("r2 varint overflow"));
            }
            value |= u32::from(byte) << 28;
            return Ok(value);
        }
        value |= u32::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(MqpError::Malformed("r2 varint too long"))
}

/// Allocation-free varint parse for the `TRAIN` item iterator. The frame was
/// validated by [`decode_train`], so `None` here only means "stop iterating"
/// and is never reachable on a frame this module produced.
fn varint_at(b: &[u8], off: &mut usize) -> Option<u32> {
    let mut value = 0u32;
    for i in 0..5 {
        let byte = *b.get(*off)?;
        *off += 1;
        if i == 4 {
            if byte & 0xF0 != 0 {
                return None;
            }
            return Some(value | (u32::from(byte) << 28));
        }
        value |= u32::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn get_u32(b: &[u8], off: &mut usize) -> Result<u32, MqpError> {
    let end = off
        .checked_add(4)
        .ok_or(MqpError::Malformed("r2 u32 offset overflow"))?;
    let s = b
        .get(*off..end)
        .ok_or(MqpError::Malformed("truncated r2 u32"))?;
    *off = end;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn push_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_addr(out: &mut Vec<u8>, addr: &AddrHeader<'_>) {
    let start = out.len();
    out.resize(start + addr.len(), 0);
    let n = addr.encode_into(&mut out[start..]);
    debug_assert_eq!(n, addr.len());
}

// ---------------- DATA ----------------

/// Borrowed view of a decoded `DATA` frame.
#[derive(Debug, Clone, Copy)]
pub struct DataRef<'a> {
    /// `None` for the `INLINE` form (no flow bound).
    pub id: Option<u32>,
    /// Present when the frame carries an `INLINE`/`OPEN` extended header.
    pub sess: Option<u32>,
    /// The inline address (open/bind address, or source when [`Self::src`]).
    pub addr: Option<TargetAddrRef<'a>>,
    /// `addr` is the actual source (downlink rebind / full-cone) not the target.
    pub src: bool,
    pub payload: &'a [u8],
}

/// Wire length of a steady `DATA` frame.
#[must_use]
pub fn data_steady_len(id: u32, payload_len: usize) -> usize {
    1 + varint_len(id) + payload_len
}

/// Wire length of an `OPEN` `DATA` frame (id + `sess` + address + payload).
#[must_use]
pub fn data_open_len(id: u32, addr_len: usize, payload_len: usize) -> usize {
    2 + varint_len(id) + 4 + addr_len + payload_len
}

/// Wire length of an `INLINE` `DATA` frame (no id).
#[must_use]
pub fn data_inline_len(addr_len: usize, payload_len: usize) -> usize {
    2 + 4 + addr_len + payload_len
}

pub fn encode_data_steady(id: u32, payload: &[u8], limit: usize) -> Option<Bytes> {
    if !valid_wire_id(id) {
        return None;
    }
    let total = data_steady_len(id, payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(R2_DATA);
    put_varint(&mut v, id);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

pub fn encode_data_open(
    id: u32,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_wire_id(id) {
        return None;
    }
    let header = addr.header().ok()?;
    let total = data_open_len(id, header.len(), payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(R2_DATA_EXT);
    v.push(R2_FLAG_OPEN | if src { R2_FLAG_SRC } else { 0 });
    put_varint(&mut v, id);
    push_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

pub fn encode_data_inline(
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let header = addr.header().ok()?;
    let total = data_inline_len(header.len(), payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(R2_DATA_EXT);
    v.push(R2_FLAG_INLINE | if src { R2_FLAG_SRC } else { 0 });
    push_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

pub fn decode_data(b: &[u8]) -> Result<DataRef<'_>, MqpError> {
    match *b.first().ok_or(MqpError::Malformed("empty r2 frame"))? {
        R2_DATA => {
            let mut off = 1usize;
            let id = get_varint(b, &mut off)?;
            if !valid_wire_id(id) {
                return Err(MqpError::Malformed("r2 data id 0"));
            }
            Ok(DataRef {
                id: Some(id),
                sess: None,
                addr: None,
                src: false,
                payload: &b[off..],
            })
        }
        R2_DATA_EXT => {
            let flags = *b
                .get(1)
                .ok_or(MqpError::Malformed("truncated r2 data flags"))?;
            if flags & !R2_EXT_FLAGS_MASK != 0 {
                return Err(MqpError::Malformed("bad r2 data flags"));
            }
            let inline = flags & R2_FLAG_INLINE != 0;
            let open = flags & R2_FLAG_OPEN != 0;
            if inline && open {
                return Err(MqpError::Malformed("r2 data open+inline"));
            }
            if !inline && !open {
                return Err(MqpError::Malformed("r2 data ext without open/inline"));
            }
            let src = flags & R2_FLAG_SRC != 0;
            let mut off = 2usize;
            if inline {
                let sess = get_u32(b, &mut off)?;
                let (addr, n) = TargetAddrRef::decode(&b[off..])?;
                off += n;
                Ok(DataRef {
                    id: None,
                    sess: Some(sess),
                    addr: Some(addr),
                    src,
                    payload: &b[off..],
                })
            } else {
                let id = get_varint(b, &mut off)?;
                if !valid_wire_id(id) {
                    return Err(MqpError::Malformed("r2 data id 0"));
                }
                let (sess, addr) = if open {
                    let sess = get_u32(b, &mut off)?;
                    let (addr, n) = TargetAddrRef::decode(&b[off..])?;
                    off += n;
                    (Some(sess), Some(addr))
                } else {
                    (None, None)
                };
                Ok(DataRef {
                    id: Some(id),
                    sess,
                    addr,
                    src,
                    payload: &b[off..],
                })
            }
        }
        _ => Err(MqpError::Malformed("bad r2 data kind")),
    }
}

// ---------------- TRAIN ----------------

/// Wire length of a same-flow `TRAIN`.
#[must_use]
pub fn train_same_len(id: u32, payloads: &[&[u8]]) -> Option<usize> {
    valid_train_count(payloads.len())?;
    if !valid_wire_id(id) {
        return None;
    }
    let mut total = 3 + varint_len(id);
    for p in payloads {
        total = total.checked_add(varint_len(p.len() as u32) + p.len())?;
    }
    Some(total)
}

/// Wire length of a dict-form `TRAIN`.
#[must_use]
pub fn train_dict_len(flows: &[u32], items: &[(u8, &[u8])]) -> Option<usize> {
    valid_train_count(items.len())?;
    valid_train_flows(flows, items)?;
    let mut total = 4usize; // kind + form + count + nfl
    for f in flows {
        total = total.checked_add(varint_len(*f))?;
    }
    for (_, p) in items {
        // idx byte + length varint + payload
        total = total.checked_add(1 + varint_len(p.len() as u32) + p.len())?;
    }
    Some(total)
}

fn valid_train_count(n: usize) -> Option<()> {
    if n == 0 || n > R2_MAX_TRAIN_ITEMS {
        None
    } else {
        Some(())
    }
}

fn valid_train_flows(flows: &[u32], items: &[(u8, &[u8])]) -> Option<()> {
    if flows.is_empty() || flows.len() > u8::MAX as usize || flows.len() > R2_MAX_TRAIN_ITEMS {
        return None;
    }
    // Encoder symmetry: `decode_train` rejects `nfl > count` (there cannot be
    // more flows than items). Refuse to emit that shape instead of producing a
    // frame the peer would reject wholesale.
    if flows.len() > items.len() {
        return None;
    }
    for (i, f) in flows.iter().enumerate() {
        if !valid_wire_id(*f) || flows[..i].contains(f) {
            return None;
        }
    }
    for (idx, _) in items {
        if usize::from(*idx) >= flows.len() {
            return None;
        }
    }
    Some(())
}

pub fn encode_train_same(id: u32, payloads: &[&[u8]], limit: usize) -> Option<Bytes> {
    let total = train_same_len(id, payloads)?;
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(R2_TRAIN);
    v.push(R2_TRAIN_FORM_SAME);
    v.push(payloads.len() as u8);
    put_varint(&mut v, id);
    for p in payloads {
        put_varint(&mut v, p.len() as u32);
        v.extend_from_slice(p);
    }
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

pub fn encode_train_dict(flows: &[u32], items: &[(u8, &[u8])], limit: usize) -> Option<Bytes> {
    let total = train_dict_len(flows, items)?;
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(R2_TRAIN);
    v.push(R2_TRAIN_FORM_DICT);
    v.push(items.len() as u8);
    v.push(flows.len() as u8);
    for f in flows {
        put_varint(&mut v, *f);
    }
    for (idx, p) in items {
        v.push(*idx);
        put_varint(&mut v, p.len() as u32);
        v.extend_from_slice(p);
    }
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Decoded `TRAIN` header plus its item bytes. The decoder validated the whole
/// frame eagerly, so [`Self::items`] only walks already-bounded slices.
#[derive(Debug, Clone)]
pub struct TrainFrame<'a> {
    pub form: u8,
    pub count: u8,
    pub nfl: u8,
    flows: [u32; R2_MAX_TRAIN_ITEMS],
    items: &'a [u8],
}

impl<'a> TrainFrame<'a> {
    /// Iterate `(wire_id, payload)` pairs in wire order.
    #[must_use]
    pub fn items(&self) -> TrainItems<'a> {
        TrainItems {
            form: self.form,
            nfl: usize::from(self.nfl),
            flows: self.flows,
            items: self.items,
        }
    }
}

pub struct TrainItems<'a> {
    form: u8,
    nfl: usize,
    flows: [u32; R2_MAX_TRAIN_ITEMS],
    items: &'a [u8],
}

impl<'a> Iterator for TrainItems<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.items.is_empty() {
            return None;
        }
        let (flow, mut off) = if self.form == R2_TRAIN_FORM_DICT {
            let idx = usize::from(*self.items.first()?);
            if idx >= self.nfl {
                return None;
            }
            (self.flows[idx], 1usize)
        } else if self.form == R2_TRAIN_FORM_SAME {
            (self.flows[0], 0usize)
        } else {
            return None;
        };
        let len = varint_at(self.items, &mut off)? as usize;
        let end = off.checked_add(len)?;
        let payload = self.items.get(off..end)?;
        self.items = &self.items[end..];
        Some((flow, payload))
    }
}

pub fn decode_train(b: &[u8]) -> Result<TrainFrame<'_>, MqpError> {
    if b.first().copied() != Some(R2_TRAIN) {
        return Err(MqpError::Malformed("bad r2 train kind"));
    }
    let form = *b.get(1).ok_or(MqpError::Malformed("short r2 train"))?;
    let count = *b
        .get(2)
        .ok_or(MqpError::Malformed("short r2 train count"))?;
    valid_train_count(usize::from(count)).ok_or(MqpError::Malformed("bad r2 train count"))?;
    let mut off = 3usize;
    let mut flows = [0u32; R2_MAX_TRAIN_ITEMS];
    let nfl = match form {
        R2_TRAIN_FORM_SAME => {
            let id = get_varint(b, &mut off)?;
            if !valid_wire_id(id) {
                return Err(MqpError::Malformed("r2 train id 0"));
            }
            flows[0] = id;
            1usize
        }
        R2_TRAIN_FORM_DICT => {
            let nfl = usize::from(
                *b.get(off)
                    .ok_or(MqpError::Malformed("short r2 train dict"))?,
            );
            off += 1;
            if nfl == 0 || nfl > usize::from(count) || nfl > R2_MAX_TRAIN_ITEMS {
                return Err(MqpError::Malformed("bad r2 train dict"));
            }
            for i in 0..nfl {
                let id = get_varint(b, &mut off)?;
                if !valid_wire_id(id) || flows[..i].contains(&id) {
                    return Err(MqpError::Malformed("bad r2 train flow id"));
                }
                flows[i] = id;
            }
            nfl
        }
        _ => return Err(MqpError::Malformed("bad r2 train form")),
    };
    // Validate items eagerly: every length must fit inside the frame.
    //
    // A zero-length item is legal: the common rules allow an empty `DATA`
    // payload, the encoders emit one for an empty UDP datagram, and the
    // connection stager packs such a payload into a `TRAIN`. Rejecting it here
    // made a single empty payload poison the whole frame (up to 64 payloads,
    // possibly from many sessions), so only the end bound is enforced.
    let mut p = off;
    for _ in 0..count {
        if form == R2_TRAIN_FORM_DICT {
            let idx = usize::from(*b.get(p).ok_or(MqpError::Malformed("short r2 train item"))?);
            p += 1;
            if idx >= nfl {
                return Err(MqpError::Malformed("bad r2 train item flow"));
            }
        }
        let len = get_varint(b, &mut p)? as usize;
        let end = p
            .checked_add(len)
            .ok_or(MqpError::Malformed("r2 train item overflow"))?;
        if end > b.len() {
            return Err(MqpError::Malformed("bad r2 train item length"));
        }
        p = end;
    }
    if p != b.len() {
        return Err(MqpError::Malformed("r2 train trailing bytes"));
    }
    Ok(TrainFrame {
        form,
        count,
        nfl: nfl as u8,
        flows,
        items: &b[off..],
    })
}

// ---------------- FRAG ----------------

/// Borrowed view of a decoded `FRAG` frame.
///
/// `chunk_off` is where [`Self::chunk`] sits inside the buffer handed to
/// [`decode_frag`]; an owner of that buffer uses the pair to address the chunk
/// without copying it (the rev2 reassembler keeps out-of-order chunks as
/// offset views of the frame instead of owned copies).
#[derive(Debug, Clone, Copy)]
pub struct FragRef<'a> {
    pub id: Option<u32>,
    pub sess: Option<u32>,
    pub addr: Option<TargetAddrRef<'a>>,
    pub src: bool,
    pub frag_id: u32,
    pub idx: u8,
    pub total: u8,
    pub chunk_off: usize,
    pub chunk: &'a [u8],
}

/// Steady `FRAG` header: kind + id varint + frag id u32 + idx + total.
#[must_use]
pub fn frag_steady_len(id: u32, chunk_len: usize) -> usize {
    1 + varint_len(id) + 4 + 1 + 1 + chunk_len
}

/// Extended `FRAG` header with `sess` + address.
#[must_use]
pub fn frag_open_len(id: u32, addr_len: usize, chunk_len: usize) -> usize {
    2 + varint_len(id) + 4 + 1 + 1 + 4 + addr_len + chunk_len
}

/// Extended `FRAG` header with `sess` + address and no id (`INLINE`).
#[must_use]
pub fn frag_inline_len(addr_len: usize, chunk_len: usize) -> usize {
    2 + 4 + 1 + 1 + 4 + addr_len + chunk_len
}

fn frag_meta_ok(idx: u8, total: u8, chunk: &[u8]) -> bool {
    (1..=R2_MAX_FRAG_TOTAL).contains(&total) && idx < total && !chunk.is_empty()
}

pub fn encode_frag_steady(
    id: u32,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_wire_id(id) || !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let total_len = frag_steady_len(id, chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(R2_FRAG);
    put_varint(&mut v, id);
    push_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_frag_open(
    id: u32,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_wire_id(id) || !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let header = addr.header().ok()?;
    let total_len = frag_open_len(id, header.len(), chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(R2_FRAG_EXT);
    v.push(R2_FLAG_OPEN | if src { R2_FLAG_SRC } else { 0 });
    put_varint(&mut v, id);
    push_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    push_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_frag_inline(
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let header = addr.header().ok()?;
    let total_len = frag_inline_len(header.len(), chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(R2_FRAG_EXT);
    v.push(R2_FLAG_INLINE | if src { R2_FLAG_SRC } else { 0 });
    push_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    push_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

pub fn decode_frag(b: &[u8]) -> Result<FragRef<'_>, MqpError> {
    let first = *b.first().ok_or(MqpError::Malformed("empty r2 frame"))?;
    let (mut off, inline, src, open) = match first {
        R2_FRAG => (1usize, false, false, false),
        R2_FRAG_EXT => {
            let flags = *b
                .get(1)
                .ok_or(MqpError::Malformed("truncated r2 frag flags"))?;
            if flags & !R2_EXT_FLAGS_MASK != 0 {
                return Err(MqpError::Malformed("bad r2 frag flags"));
            }
            let inline = flags & R2_FLAG_INLINE != 0;
            let open = flags & R2_FLAG_OPEN != 0;
            if inline && open {
                return Err(MqpError::Malformed("r2 frag open+inline"));
            }
            if !inline && !open {
                return Err(MqpError::Malformed("r2 frag ext without open/inline"));
            }
            (2usize, inline, flags & R2_FLAG_SRC != 0, open)
        }
        _ => return Err(MqpError::Malformed("bad r2 frag kind")),
    };
    let id = if inline {
        None
    } else {
        let id = get_varint(b, &mut off)?;
        if !valid_wire_id(id) {
            return Err(MqpError::Malformed("r2 frag id 0"));
        }
        Some(id)
    };
    let frag_id = get_u32(b, &mut off)?;
    let idx = *b.get(off).ok_or(MqpError::Malformed("short r2 frag idx"))?;
    let total = *b
        .get(off + 1)
        .ok_or(MqpError::Malformed("short r2 frag total"))?;
    off += 2;
    let mut sess = None;
    let mut addr = None;
    if inline || open {
        let s = get_u32(b, &mut off)?;
        let (a, n) = TargetAddrRef::decode(&b[off..])?;
        off += n;
        sess = Some(s);
        addr = Some(a);
    }
    let chunk = &b[off..];
    if !frag_meta_ok(idx, total, chunk) {
        return Err(MqpError::Malformed("bad r2 frag meta"));
    }
    Ok(FragRef {
        id,
        sess,
        addr,
        src,
        frag_id,
        idx,
        total,
        chunk_off: off,
        chunk,
    })
}

// ---------------- CTL ----------------

/// Negotiated limits carried by `CAPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub wire_ver: u16,
    pub flags: u16,
    pub max_conn_flows: u16,
    pub max_flows_sess: u16,
    pub max_train_items: u8,
    pub max_frame_bytes: u16,
    pub max_reassembly: u16,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            wire_ver: R2_WIRE_VER,
            flags: 0,
            max_conn_flows: R2_DEFAULT_MAX_CONN_FLOWS,
            max_flows_sess: R2_DEFAULT_MAX_FLOWS_SESS,
            max_train_items: R2_DEFAULT_MAX_TRAIN_ITEMS,
            max_frame_bytes: R2_DEFAULT_MAX_FRAME_BYTES,
            max_reassembly: R2_DEFAULT_MAX_REASSEMBLY,
        }
    }
}

/// A decoded control frame. Every variant is idempotent and small; the control
/// plane is carried in DATAGRAMs because losing one only delays an optimisation
/// (compression or resource release), never correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctl {
    Hello { wire_ver: u16, flags: u16 },
    Caps(Caps),
    FlowAck { id: u32, status: u8 },
    FlowReject { id: u32, reason: u8 },
    FlowClose { id: u32 },
    SessClose { sess: u32, reason: u8 },
}

impl Ctl {
    /// Wire length of the encoded control frame.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Ctl::Hello { .. } => 8,
            Ctl::Caps(_) => 17,
            Ctl::FlowAck { id, .. } | Ctl::FlowReject { id, .. } => 3 + varint_len(*id),
            Ctl::FlowClose { id } => 2 + varint_len(*id),
            Ctl::SessClose { .. } => 7,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

pub fn encode_ctl(ctl: &Ctl) -> Bytes {
    let total = ctl.len();
    let mut v = Vec::with_capacity(total);
    v.push(R2_CTL);
    match *ctl {
        Ctl::Hello { wire_ver, flags } => {
            v.push(R2_CTL_HELLO);
            v.extend_from_slice(&R2_MAGIC);
            v.extend_from_slice(&wire_ver.to_le_bytes());
            v.extend_from_slice(&flags.to_le_bytes());
        }
        Ctl::Caps(c) => {
            v.push(R2_CTL_CAPS);
            v.extend_from_slice(&R2_MAGIC);
            v.extend_from_slice(&c.wire_ver.to_le_bytes());
            v.extend_from_slice(&c.flags.to_le_bytes());
            v.extend_from_slice(&c.max_conn_flows.to_le_bytes());
            v.extend_from_slice(&c.max_flows_sess.to_le_bytes());
            v.push(c.max_train_items);
            v.extend_from_slice(&c.max_frame_bytes.to_le_bytes());
            v.extend_from_slice(&c.max_reassembly.to_le_bytes());
        }
        Ctl::FlowAck { id, status } => {
            v.push(R2_CTL_FLOW_ACK);
            put_varint(&mut v, id);
            v.push(status);
        }
        Ctl::FlowReject { id, reason } => {
            v.push(R2_CTL_FLOW_REJECT);
            put_varint(&mut v, id);
            v.push(reason);
        }
        Ctl::FlowClose { id } => {
            v.push(R2_CTL_FLOW_CLOSE);
            put_varint(&mut v, id);
        }
        Ctl::SessClose { sess, reason } => {
            v.push(R2_CTL_SESS_CLOSE);
            push_u32(&mut v, sess);
            v.push(reason);
        }
    }
    debug_assert_eq!(v.len(), total);
    Bytes::from(v)
}

pub fn decode_ctl(b: &[u8]) -> Result<Ctl, MqpError> {
    if b.first().copied() != Some(R2_CTL) {
        return Err(MqpError::Malformed("bad r2 ctl kind"));
    }
    let opcode = *b.get(1).ok_or(MqpError::Malformed("short r2 ctl"))?;
    match opcode {
        R2_CTL_HELLO => {
            if b.len() != 8 || b[2..4] != R2_MAGIC {
                return Err(MqpError::Malformed("bad r2 hello"));
            }
            Ok(Ctl::Hello {
                wire_ver: u16::from_le_bytes([b[4], b[5]]),
                flags: u16::from_le_bytes([b[6], b[7]]),
            })
        }
        R2_CTL_CAPS => {
            if b.len() != 17 || b[2..4] != R2_MAGIC {
                return Err(MqpError::Malformed("bad r2 caps"));
            }
            Ok(Ctl::Caps(Caps {
                wire_ver: u16::from_le_bytes([b[4], b[5]]),
                flags: u16::from_le_bytes([b[6], b[7]]),
                max_conn_flows: u16::from_le_bytes([b[8], b[9]]),
                max_flows_sess: u16::from_le_bytes([b[10], b[11]]),
                max_train_items: b[12],
                max_frame_bytes: u16::from_le_bytes([b[13], b[14]]),
                max_reassembly: u16::from_le_bytes([b[15], b[16]]),
            }))
        }
        R2_CTL_FLOW_ACK => {
            let mut off = 2usize;
            let id = get_varint(b, &mut off)?;
            if !valid_wire_id(id) {
                return Err(MqpError::Malformed("r2 ack id 0"));
            }
            let status = *b.get(off).ok_or(MqpError::Malformed("short r2 ack"))?;
            if off + 1 != b.len() {
                return Err(MqpError::Malformed("r2 ack trailing bytes"));
            }
            Ok(Ctl::FlowAck { id, status })
        }
        R2_CTL_FLOW_REJECT => {
            let mut off = 2usize;
            let id = get_varint(b, &mut off)?;
            if !valid_wire_id(id) {
                return Err(MqpError::Malformed("r2 reject id 0"));
            }
            let reason = *b.get(off).ok_or(MqpError::Malformed("short r2 reject"))?;
            if off + 1 != b.len() {
                return Err(MqpError::Malformed("r2 reject trailing bytes"));
            }
            Ok(Ctl::FlowReject { id, reason })
        }
        R2_CTL_FLOW_CLOSE => {
            let mut off = 2usize;
            let id = get_varint(b, &mut off)?;
            if !valid_wire_id(id) {
                return Err(MqpError::Malformed("r2 close id 0"));
            }
            if off != b.len() {
                return Err(MqpError::Malformed("r2 close trailing bytes"));
            }
            Ok(Ctl::FlowClose { id })
        }
        R2_CTL_SESS_CLOSE => {
            if b.len() != 7 {
                return Err(MqpError::Malformed("bad r2 sess close"));
            }
            Ok(Ctl::SessClose {
                sess: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
                reason: b[6],
            })
        }
        _ => Err(MqpError::Malformed("bad r2 ctl opcode")),
    }
}

// ---------------- address helpers ----------------

/// Borrowed target address helper used by call sites that already hold a
/// [`TargetAddr`] and need a [`TargetAddrRef`] without allocating.
#[must_use]
pub fn addr_ref(addr: &TargetAddr) -> TargetAddrRef<'_> {
    addr.as_ref()
}

/// Convenience for tests/callers that hold an IP socket address.
#[must_use]
pub fn ip_ref(addr: SocketAddr) -> TargetAddrRef<'static> {
    TargetAddrRef::Ip(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqp::v3;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    /// Every rev2 first byte must be safely droppable by the old decoders.
    #[test]
    fn first_bytes_are_safe_for_old_parsers() {
        let flows = [5u32, 9];
        let payloads: [&[u8]; 1] = [b"x"];
        let items: [(u8, &[u8]); 2] = [(0, b"x"), (1, b"y")];
        let frames: Vec<Bytes> = vec![
            encode_data_steady(5, b"x", 1500).unwrap(),
            encode_data_open(5, 7, &v4(53), false, b"x", 1500).unwrap(),
            encode_data_inline(7, &v4(53), false, b"x", 1500).unwrap(),
            encode_train_same(5, &payloads, 1500).unwrap(),
            encode_train_dict(&flows, &items, 1500).unwrap(),
            encode_frag_steady(5, 1, 0, 1, b"x", 1500).unwrap(),
            encode_frag_open(5, 7, &v4(53), false, 1, 0, 1, b"x", 1500).unwrap(),
            encode_frag_inline(7, &v4(53), false, 1, 0, 1, b"x", 1500).unwrap(),
            encode_ctl(&Ctl::Hello {
                wire_ver: R2_WIRE_VER,
                flags: 0,
            }),
        ];
        for f in frames {
            let first = f[0];
            assert_eq!(first & R2_FIRST_MASK, 0, "high nibble must be zero");
            assert!(
                !matches!(first, 0x02 | 0x05 | 0x06),
                "must not collide with an MQP-2 type"
            );
            assert!(!v3::is_v3(&f), "old v3 must reject rev2 first byte");
        }
    }

    #[test]
    fn data_steady_golden() {
        let d = encode_data_steady(5, b"abc", 1500).unwrap();
        assert_eq!(&d[..], &[0x00, 0x05, b'a', b'b', b'c']);
        // Two-byte LEB128 for id 128.
        let d = encode_data_steady(128, b"", 1500).unwrap();
        assert_eq!(&d[..], &[0x00, 0x80, 0x01]);
    }

    #[test]
    fn data_open_and_inline_golden_and_roundtrip() {
        let d = encode_data_open(5, 7, &v4(53), false, b"abc", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x01, 0x01, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x35,
                b'a', b'b', b'c'
            ]
        );
        let r = decode_data(&d).unwrap();
        assert_eq!(r.id, Some(5));
        assert_eq!(r.sess, Some(7));
        assert!(!r.src);
        assert_eq!(r.addr.unwrap(), v4(53));
        assert_eq!(r.payload, b"abc");

        let d = encode_data_inline(7, &dom("example.com", 53), true, b"z", 1500).unwrap();
        let r = decode_data(&d).unwrap();
        assert_eq!(r.id, None);
        assert_eq!(r.sess, Some(7));
        assert!(r.src);
        assert_eq!(r.addr.unwrap(), dom("example.com", 53));
        assert_eq!(r.payload, b"z");

        let d = encode_data_open(6, 7, &v6(443), false, b"", 1500).unwrap();
        let r = decode_data(&d).unwrap();
        assert_eq!(r.addr.unwrap(), v6(443));
        assert!(r.payload.is_empty());
    }

    #[test]
    fn train_golden_and_roundtrip() {
        let payloads: [&[u8]; 2] = [b"abc", b"de"];
        let d = encode_train_same(5, &payloads, 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x04, 0x00, 0x02, 0x05, 0x03, b'a', b'b', b'c', 0x02, b'd', b'e'
            ]
        );
        let t = decode_train(&d).unwrap();
        assert_eq!(t.form, R2_TRAIN_FORM_SAME);
        assert_eq!(t.count, 2);
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(got, vec![(5, &b"abc"[..]), (5, &b"de"[..])]);

        let flows = [5u32, 9];
        let items: [(u8, &[u8]); 2] = [(0, b"abc"), (1, b"de")];
        let d = encode_train_dict(&flows, &items, 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x04, 0x01, 0x02, 0x02, 0x05, 0x09, 0x00, 0x03, b'a', b'b', b'c', 0x01, 0x02, b'd',
                b'e'
            ]
        );
        let t = decode_train(&d).unwrap();
        assert_eq!(t.form, R2_TRAIN_FORM_DICT);
        assert_eq!(t.nfl, 2);
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(got, vec![(5, &b"abc"[..]), (9, &b"de"[..])]);
    }

    #[test]
    fn train_accepts_64_items_and_rejects_bad_shapes() {
        let payloads: Vec<&[u8]> = (0..R2_MAX_TRAIN_ITEMS).map(|_| &b"x"[..]).collect();
        let d = encode_train_same(1, &payloads, 1500).unwrap();
        assert_eq!(decode_train(&d).unwrap().items().count(), 64);
        assert!(encode_train_same(1, &payloads[..0], 1500).is_none());
        assert!(encode_train_same(0, &payloads[..1], 1500).is_none());
        // Duplicate flows are refused.
        let flows = [5u32, 5];
        let items: [(u8, &[u8]); 1] = [(0, b"x")];
        assert!(encode_train_dict(&flows, &items, 1500).is_none());
        // Index out of range is refused.
        let flows = [5u32];
        let items: [(u8, &[u8]); 1] = [(1, b"x")];
        assert!(encode_train_dict(&flows, &items, 1500).is_none());
        // More flows than items can never decode (`nfl > count`), so the
        // encoder must refuse the shape instead of emitting a frame the peer
        // drops wholesale.
        let flows = [5u32, 9];
        let items: [(u8, &[u8]); 1] = [(0, b"x")];
        assert!(encode_train_dict(&flows, &items, 1500).is_none());
    }

    /// An empty UDP payload is legal and the stager packs it into a TRAIN as a
    /// `len == 0` item. Both the same-flow and dict encoders must round-trip it
    /// and the decoder must accept it — otherwise one empty payload made the
    /// receiver drop the whole frame (and every other session's items in it).
    #[test]
    fn train_roundtrips_zero_length_items() {
        let payloads: [&[u8]; 2] = [b"", b"x"];
        let d = encode_train_same(5, &payloads, 1500).unwrap();
        assert_eq!(&d[..], &[0x04, 0x00, 0x02, 0x05, 0x00, 0x01, b'x']);
        let t = decode_train(&d).unwrap();
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(5, &b""[..]), (5, &b"x"[..])]
        );

        let flows = [5u32, 9];
        let items: [(u8, &[u8]); 3] = [(0, b""), (1, b"x"), (0, b"")];
        let d = encode_train_dict(&flows, &items, 1500).unwrap();
        let t = decode_train(&d).unwrap();
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(5, &b""[..]), (9, &b"x"[..]), (5, &b""[..])]
        );
        // A hostile frame whose only item is empty still parses to exactly one
        // empty payload, and a trailing byte after it is still rejected.
        assert!(decode_train(&[0x04, 0x00, 0x01, 0x05, 0x00]).is_ok());
        assert!(decode_train(&[0x04, 0x00, 0x01, 0x05, 0x00, 0x00]).is_err());
    }

    #[test]
    fn frag_golden_and_roundtrip() {
        let d = encode_frag_steady(5, 0x1234_5678, 1, 3, b"abc", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x08, 0x05, 0x78, 0x56, 0x34, 0x12, 0x01, 0x03, b'a', b'b', b'c'
            ]
        );
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.id, Some(5));
        assert_eq!(r.frag_id, 0x1234_5678);
        assert_eq!((r.idx, r.total), (1, 3));
        assert_eq!(r.chunk, b"abc");
        assert_eq!(r.sess, None);

        let d = encode_frag_open(5, 7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap();
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.sess, Some(7));
        assert_eq!(r.addr.unwrap(), v4(53));
        assert_eq!(r.chunk, b"qq");

        assert!(encode_frag_steady(5, 1, 1, 1, b"x", 1500).is_none());
        assert!(encode_frag_steady(5, 1, 0, 0, b"x", 1500).is_none());
        assert!(encode_frag_steady(5, 1, 0, 65, b"x", 1500).is_none());
        assert!(encode_frag_steady(5, 1, 0, 1, b"", 1500).is_none());
    }

    #[test]
    fn ctl_golden_and_roundtrip() {
        let hello = encode_ctl(&Ctl::Hello {
            wire_ver: R2_WIRE_VER,
            flags: 0,
        });
        assert_eq!(
            &hello[..],
            &[0x0C, 0x01, b'M', b'3', 0x02, 0x00, 0x00, 0x00]
        );

        let caps = Caps::default();
        let d = encode_ctl(&Ctl::Caps(caps));
        assert_eq!(d.len(), 17);
        assert_eq!(decode_ctl(&d).unwrap(), Ctl::Caps(caps));

        let ack = encode_ctl(&Ctl::FlowAck {
            id: 5,
            status: R2_ACK_OPEN,
        });
        assert_eq!(&ack[..], &[0x0C, 0x10, 0x05, 0x00]);
        assert_eq!(
            decode_ctl(&ack).unwrap(),
            Ctl::FlowAck {
                id: 5,
                status: R2_ACK_OPEN
            }
        );

        let rej = encode_ctl(&Ctl::FlowReject {
            id: 200,
            reason: R2_REJECT_TABLE_FULL,
        });
        assert_eq!(
            decode_ctl(&rej).unwrap(),
            Ctl::FlowReject {
                id: 200,
                reason: R2_REJECT_TABLE_FULL
            }
        );

        let close = encode_ctl(&Ctl::FlowClose { id: 5 });
        assert_eq!(&close[..], &[0x0C, 0x12, 0x05]);
        let sess = encode_ctl(&Ctl::SessClose { sess: 7, reason: 0 });
        assert_eq!(&sess[..], &[0x0C, 0x20, 0x07, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_ctl(&sess).unwrap(),
            Ctl::SessClose { sess: 7, reason: 0 }
        );
    }

    #[test]
    fn ctl_rejects_malformed() {
        assert!(decode_ctl(&[]).is_err());
        assert!(decode_ctl(&[0x0C]).is_err());
        assert!(decode_ctl(&[0x0C, 0x99]).is_err());
        // Bad magic.
        assert!(decode_ctl(&[0x0C, 0x01, b'X', b'3', 0x02, 0x00, 0x00, 0x00]).is_err());
        // Wrong version is *decoded* (the caller negotiates); only shape is checked.
        assert!(matches!(
            decode_ctl(&[0x0C, 0x01, b'M', b'3', 0x09, 0x00, 0x00, 0x00]).unwrap(),
            Ctl::Hello { wire_ver: 9, .. }
        ));
        // Id zero is invalid.
        assert!(decode_ctl(&[0x0C, 0x12, 0x00]).is_err());
        // Trailing bytes are refused.
        assert!(decode_ctl(&[0x0C, 0x12, 0x05, 0x00]).is_err());
    }

    #[test]
    fn malformed_data_does_not_panic() {
        assert!(decode_data(&[]).is_err());
        assert!(decode_data(&[0x00]).is_err());
        assert!(decode_data(&[0x00, 0x00]).is_err()); // id 0
        assert!(decode_data(&[0x01]).is_err());
        assert!(decode_data(&[0x01, 0x00]).is_err()); // no id
        assert!(decode_data(&[0x01, 0x08, 0x05]).is_err()); // bad flag
        assert!(decode_data(&[0x01, 0x03, 0x05]).is_err()); // open+inline
        assert!(decode_data(&[0x02, 0x05]).is_err()); // not DATA
        // Truncated address.
        assert!(decode_data(&[0x01, R2_FLAG_OPEN, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn malformed_train_does_not_panic() {
        assert!(decode_train(&[]).is_err());
        assert!(decode_train(&[0x04]).is_err());
        assert!(decode_train(&[0x04, 0x00, 0x00]).is_err()); // count 0
        assert!(decode_train(&[0x04, 0x00, 0x01]).is_err()); // missing id
        assert!(decode_train(&[0x04, 0x02, 0x01, 0x05]).is_err()); // bad form
        assert!(decode_train(&[0x04, 0x01, 0x01, 0x00, 0x05]).is_err()); // nfl 0
        // Item length overruns the frame.
        assert!(decode_train(&[0x04, 0x00, 0x01, 0x05, 0x05, b'x']).is_err());
        // Trailing bytes are refused.
        assert!(decode_train(&[0x04, 0x00, 0x01, 0x05, 0x01, b'x', b'y']).is_err());
    }

    #[test]
    fn malformed_frag_does_not_panic() {
        assert!(decode_frag(&[]).is_err());
        assert!(decode_frag(&[0x08]).is_err());
        assert!(decode_frag(&[0x08, 0x05]).is_err());
        assert!(decode_frag(&[0x09, 0x08, 0x05]).is_err()); // bad flags
        // idx >= total
        assert!(decode_frag(&[0x08, 0x05, 0, 0, 0, 0, 1, 1, b'x']).is_err());
        // empty chunk
        assert!(decode_frag(&[0x08, 0x05, 0, 0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn varint_boundaries() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 3);
        assert_eq!(varint_len(u32::MAX), 5);
        for n in [0, 1, 127, 128, 16_383, 16_384, 0x7FFF_FFFF, u32::MAX] {
            let mut v = Vec::new();
            put_varint(&mut v, n);
            let mut off = 0;
            assert_eq!(get_varint(&v, &mut off).unwrap(), n);
            assert_eq!(off, v.len());
        }
        // Overflow: fifth byte with high bits set.
        let mut off = 0;
        assert!(get_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0x10], &mut off).is_err());
        // Unterminated.
        let mut off = 0;
        assert!(get_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], &mut off).is_err());
    }

    #[test]
    fn wire_ids_roundtrip_and_reject_zero() {
        assert_eq!(make_wire_id(1, false), Some(2));
        assert_eq!(make_wire_id(1, true), Some(3));
        assert_eq!(make_wire_id(0, false), None);
        let id = make_wire_id(1234, true).unwrap();
        assert_eq!(wire_id_local(id), 1234);
        assert!(wire_id_server_owned(id));
        assert!(!wire_id_server_owned(make_wire_id(1234, false).unwrap()));
    }

    #[test]
    fn limit_is_enforced() {
        let payload = [0u8; 32];
        let need = data_steady_len(5, payload.len());
        assert!(encode_data_steady(5, &payload, need).is_some());
        assert!(encode_data_steady(5, &payload, need - 1).is_none());
    }

    #[test]
    fn kind_and_is_r2() {
        assert_eq!(kind(&[0x00]), Some(R2Kind::Data));
        assert_eq!(kind(&[0x01]), Some(R2Kind::Data));
        assert_eq!(kind(&[0x04]), Some(R2Kind::Train));
        assert_eq!(kind(&[0x08]), Some(R2Kind::Frag));
        assert_eq!(kind(&[0x09]), Some(R2Kind::Frag));
        assert_eq!(kind(&[0x0C]), Some(R2Kind::Ctl));
        assert_eq!(kind(&[0x02]), None);
        assert_eq!(kind(&[0x05]), None);
        assert_eq!(kind(&[0x06]), None);
        assert_eq!(kind(&[0x10]), None);
        assert!(!is_r2(&[]));
        assert!(is_r2(&[0x00]));
    }
}
