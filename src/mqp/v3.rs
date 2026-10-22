//! MQP-3 data frames: session + flow addressing, mixed-flow TRAIN, compact FRAG.
//!
//! MQP-3 keeps the MQP-2 `sess u32` and replaces the per-payload address with a
//! per-session `flow u8`. Flow 0 is implicit on the wire; every other flow costs
//! one byte. A flow is opened by the first frame that carries its address
//! (`I`) and is then referenced by id. The receiver only ever uses an id it
//! already has a mapping for, so a compressed frame never invents a route.
//!
//! This module is deliberately codec-only. It does not know about QUIC, DNS,
//! SSRF or the relay sockets; those live in the client/server data paths.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use super::addr::{AddrHeader, TargetAddr, TargetAddrRef};
use super::error::MqpError;
use super::fragment::MQP_FRAG_MAX_PAYLOAD;

/// High nibble of the first byte: frame kind. The low nibble is flags.
pub const MQP3_SINGLE: u8 = 0x10;
pub const MQP3_TRAIN: u8 = 0x20;
pub const MQP3_FRAG: u8 = 0x30;
pub const MQP3_CTL: u8 = 0x40;
pub const MQP3_KIND_MASK: u8 = 0xF0;

/// `SINGLE`/`FRAG` flags.
pub const MQP3_FLAG_INLINE: u8 = 0x1;
pub const MQP3_FLAG_FLOW: u8 = 0x2;
/// The inline address is the actual source for this payload, not the address
/// bound to the flow. Used by the reply path when a target answers from a
/// different port than it was sent to.
pub const MQP3_FLAG_SRC: u8 = 0x4;

/// `TRAIN` item flags.
pub const MQP3_ITEM_FLOW: u8 = 0x1;
pub const MQP3_ITEM_INLINE: u8 = 0x2;
pub const MQP3_ITEM_SRC: u8 = 0x4;

/// `TRAIN` frame flag: every item has the same flow, carried once in the header.
pub const MQP3_TRAIN_SAME_FLOW: u8 = 0x1;

/// Reserved flow id meaning "no table entry; the address is inline". A frame
/// using this id must carry `I`; the receiver does not install it.
pub const MQP3_NO_FLOW: u8 = 0xFF;

/// Conservative per-session charge for the flow table, used by admission
/// accounting.
///
/// The inline table is 64 `Option<Arc<TargetAddr>>` slots plus the monotonic
/// cursor (520 B on a 64-bit host), and each live flow additionally owns the
/// pointee behind its `Arc`. The peer-fillable worst case is a table full of
/// **domain** targets: every flow costs an `Arc` header (16 B: strong + weak)
/// plus a `TargetAddr` (40 B — the `SocketAddr` payload plus the enum tag), and
/// the domain variant also owns a `String` at the 255-byte wire limit, which an
/// allocator rounds up by at least 32 B of size-class overhead. That is
/// `64 x (16 + 40 + 255 + 32) = 21,952 B`, plus the 520-byte inline table =
/// **22,472 B**; `22 * 1024` covers it with 56 B to spare.
///
/// The previous 4,096 B was the *IP-only* derivation (64 x (slot 8 + `Arc` 16 +
/// `SocketAddr` 32 + 8 slack) = 4,096), which under-counted a domain-filled
/// table by ~5x — exactly the kind of under-count an admission bound must not
/// have, because the peer controls whether its targets are domains.
pub const MQP3_FLOW_TABLE_MAX_BYTES: usize = 22 * 1024;

const _: () = {
    // Admission must bound the domain-target worst case: per flow = Arc header
    // + TargetAddr + a 255-byte name rounded up by allocator size-class
    // overhead (32 B is the documented round-up), plus the inline table and its
    // cursor. Spelled out from real `size_of` values rather than hard-coded so
    // a layout change fails here instead of silently under-counting.
    let per_domain = 2 * std::mem::size_of::<usize>() // Arc strong + weak counts
        + std::mem::size_of::<TargetAddr>()
        + (255 + 32);
    let inline = MQP3_MAX_FLOWS * std::mem::size_of::<Option<Arc<TargetAddr>>>()
        + std::mem::size_of::<usize>(); // monotonic cursor
    assert!(MQP3_FLOW_TABLE_MAX_BYTES >= MQP3_MAX_FLOWS * per_domain + inline);
};

/// Flows 0..=63 fit in the fixed per-session table. The wire supports the full
/// u8 range, but the table is deliberately small (the analysis budgets 64
/// entries/session); past it the sender falls back to inline.
pub const MQP3_MAX_FLOWS: usize = 64;

/// Defensive bound on a TRAIN's item count. The encoder fills by path budget,
/// not by this number; the decoder rejects anything larger before iterating.
pub const MQP3_MAX_TRAIN_ITEMS: usize = 64;

/// Fixed TRAIN header: kind/flags + sess + count.
pub const MQP3_TRAIN_HEADER_LEN: usize = 1 + 4 + 1;

/// Fixed FRAG header: kind/flags + sess + id + idx + total.
pub const MQP3_FRAG_PREFIX_LEN: usize = 1 + 4 + 4 + 1 + 1;

/// Whether `b` starts with an MQP-3 frame kind.
#[must_use]
pub fn is_v3(b: &[u8]) -> bool {
    matches!(
        b.first().map(|b| b & MQP3_KIND_MASK),
        Some(MQP3_SINGLE | MQP3_TRAIN | MQP3_FRAG | MQP3_CTL)
    )
}

#[must_use]
pub fn v3_sess(b: &[u8]) -> Option<u32> {
    if b.len() < 5 || !is_v3(b) {
        return None;
    }
    Some(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))
}

/// Validate a flow id used by a data frame. `None` is for values the wire
/// cannot represent (0x40..=0xFE).
#[inline]
fn valid_flow(flow: u8) -> bool {
    flow < MQP3_MAX_FLOWS as u8 || flow == MQP3_NO_FLOW
}

/// LEB128 length used by TRAIN items. A small payload (the common case) costs
/// one byte; 128..=16383 costs two.
#[must_use]
pub fn varint_len(mut n: usize) -> usize {
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

fn get_varint(b: &[u8], off: &mut usize) -> Result<usize, MqpError> {
    let mut value = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let byte = *b
            .get(*off)
            .ok_or(MqpError::Malformed("truncated train varint"))?;
        *off += 1;
        value |= u32::from(byte & 0x7F).wrapping_shl(shift);
        if byte & 0x80 == 0 {
            return Ok(value as usize);
        }
        shift += 7;
    }
    Err(MqpError::Malformed("train varint too long"))
}

// ---------------- SINGLE ----------------

#[derive(Debug, Clone, Copy)]
pub struct SingleRef<'a> {
    pub sess: u32,
    pub flow: u8,
    /// Present when the frame carries `I`.
    pub inline: Option<TargetAddrRef<'a>>,
    /// The inline address is a source override, not the flow's bound address.
    pub src_override: bool,
    pub payload: &'a [u8],
}

#[must_use]
pub fn single_frame_len(flow: u8, addr_len: usize, payload_len: usize) -> usize {
    1usize
        .saturating_add(4)
        .saturating_add(usize::from(flow != 0))
        .saturating_add(addr_len)
        .saturating_add(payload_len)
}

pub fn encode_single(
    sess: u32,
    flow: u8,
    addr: Option<&TargetAddrRef<'_>>,
    src_override: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_flow(flow) || (flow == MQP3_NO_FLOW && addr.is_none()) {
        return None;
    }
    if src_override && addr.is_none() {
        return None;
    }
    let header = match addr {
        Some(a) => Some(a.header().ok()?),
        None => None,
    };
    let addr_len = header.as_ref().map_or(0, AddrHeader::len);
    let total = single_frame_len(flow, addr_len, payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    let mut flags = 0u8;
    if header.is_some() {
        flags |= MQP3_FLAG_INLINE;
    }
    if flow != 0 {
        flags |= MQP3_FLAG_FLOW;
    }
    if src_override {
        flags |= MQP3_FLAG_SRC;
    }
    v.push(MQP3_SINGLE | flags);
    v.extend_from_slice(&sess.to_le_bytes());
    if flow != 0 {
        v.push(flow);
    }
    if let Some(h) = header {
        let start = v.len();
        v.resize(start + h.len(), 0);
        let n = h.encode_into(&mut v[start..]);
        debug_assert_eq!(n, h.len());
    }
    v.extend_from_slice(payload);
    Some(Bytes::from(v))
}

pub fn decode_single(b: &[u8]) -> Result<SingleRef<'_>, MqpError> {
    if b.len() < 5 || b.first().copied().map(|x| x & MQP3_KIND_MASK) != Some(MQP3_SINGLE) {
        return Err(MqpError::Malformed("bad single"));
    }
    let flags = b[0] & 0x0F;
    if flags & !(MQP3_FLAG_INLINE | MQP3_FLAG_FLOW | MQP3_FLAG_SRC) != 0 {
        return Err(MqpError::Malformed("bad single flags"));
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let mut off = 5usize;
    let flow = if flags & MQP3_FLAG_FLOW != 0 {
        let f = *b
            .get(off)
            .ok_or(MqpError::Malformed("truncated single flow"))?;
        off += 1;
        f
    } else {
        0
    };
    if !valid_flow(flow) {
        return Err(MqpError::Malformed("bad single flow"));
    }
    let inline = if flags & MQP3_FLAG_INLINE != 0 {
        let (a, n) = TargetAddrRef::decode(&b[off..])?;
        off += n;
        Some(a)
    } else {
        None
    };
    let src_override = flags & MQP3_FLAG_SRC != 0;
    if src_override && inline.is_none() {
        return Err(MqpError::Malformed(
            "source override without inline address",
        ));
    }
    if flow == MQP3_NO_FLOW && inline.is_none() {
        return Err(MqpError::Malformed("no-flow single without address"));
    }
    Ok(SingleRef {
        sess,
        flow,
        inline,
        src_override,
        payload: &b[off..],
    })
}

// ---------------- TRAIN ----------------

#[derive(Debug, Clone, Copy)]
pub struct TrainItem<'a> {
    pub flow: u8,
    pub inline: Option<TargetAddrRef<'a>>,
    pub src_override: bool,
    pub payload: &'a [u8],
}

/// Wire length of one mixed-format TRAIN item. For an extra flow this is the
/// conservative 3 B overhead; [`encode_train`] may drop the per-item flow byte
/// when every item shares it.
#[must_use]
pub fn train_item_len(flow: u8, addr_len: usize, payload_len: usize) -> usize {
    1usize
        .saturating_add(usize::from(flow != 0))
        .saturating_add(varint_len(payload_len))
        .saturating_add(addr_len)
        .saturating_add(payload_len)
}

fn validate_item(item: &TrainItem<'_>) -> Option<usize> {
    if !valid_flow(item.flow) {
        return None;
    }
    if item.flow == MQP3_NO_FLOW && item.inline.is_none() {
        return None;
    }
    if item.src_override && item.inline.is_none() {
        return None;
    }
    match item.inline {
        Some(a) => Some(a.header().ok()?.len()),
        None => Some(0),
    }
}

pub fn encode_train(sess: u32, items: &[TrainItem<'_>], limit: usize) -> Option<Bytes> {
    if items.is_empty() || items.len() > MQP3_MAX_TRAIN_ITEMS || items.len() > u8::MAX as usize {
        return None;
    }
    let mut addr_lens = [0usize; MQP3_MAX_TRAIN_ITEMS];
    let mut total = MQP3_TRAIN_HEADER_LEN;
    for (i, item) in items.iter().enumerate() {
        let n = validate_item(item)?;
        addr_lens[i] = n;
        total = total.saturating_add(train_item_len(item.flow, n, item.payload.len()));
    }
    // The same-flow encoding saves one flow byte per item and adds one flow
    // byte to the header. Compute the exact total before writing.
    // The same-flow header carries the flow byte only for a non-zero flow.
    // Flow 0 is implicit, so setting the flag for it would make the decoder
    // read the first item's flags byte as a flow id. Keep flow 0 in the mixed
    // form; it is byte-identical apart from the (clear) flag bit.
    let same_flow = items[0].flow != 0
        && items[0].flow != MQP3_NO_FLOW
        && items
            .iter()
            .all(|i| i.flow == items[0].flow && i.inline.is_none() && !i.src_override);
    if same_flow {
        total = total.saturating_sub(items.len()).saturating_add(1);
    }
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(MQP3_TRAIN | u8::from(same_flow));
    v.extend_from_slice(&sess.to_le_bytes());
    v.push(items.len() as u8);
    if same_flow && items[0].flow != 0 {
        v.push(items[0].flow);
    }
    for (i, item) in items.iter().enumerate() {
        let mut flags = 0u8;
        if item.flow != 0 && !same_flow {
            flags |= MQP3_ITEM_FLOW;
        }
        if item.inline.is_some() {
            flags |= MQP3_ITEM_INLINE;
        }
        if item.src_override {
            flags |= MQP3_ITEM_SRC;
        }
        v.push(flags);
        if flags & MQP3_ITEM_FLOW != 0 {
            v.push(item.flow);
        }
        put_varint(&mut v, item.payload.len() as u32);
        if let Some(a) = item.inline {
            let h = a.header().ok()?;
            let start = v.len();
            v.resize(start + h.len(), 0);
            let n = h.encode_into(&mut v[start..]);
            debug_assert_eq!(n, addr_lens[i]);
        }
        v.extend_from_slice(item.payload);
    }
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

#[derive(Debug, Clone, Copy)]
pub struct TrainItemRef<'a> {
    pub flow: u8,
    pub inline: Option<TargetAddrRef<'a>>,
    pub src_override: bool,
    pub payload: &'a [u8],
}

pub struct TrainFrame<'a> {
    pub sess: u32,
    same_flow: Option<u8>,
    items: &'a [u8],
    count: u8,
}

impl<'a> TrainFrame<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.count as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn items(&self) -> TrainItems<'a> {
        TrainItems {
            rest: self.items,
            left: self.count,
            same_flow: self.same_flow,
        }
    }
}

pub struct TrainItems<'a> {
    rest: &'a [u8],
    left: u8,
    same_flow: Option<u8>,
}

impl<'a> Iterator for TrainItems<'a> {
    type Item = TrainItemRef<'a>;

    fn next(&mut self) -> Option<TrainItemRef<'a>> {
        if self.left == 0 {
            return None;
        }
        // Validation in `decode_train` walked exactly this parse, so every
        // index below is in bounds.
        let flags = self.rest[0];
        let mut off = 1usize;
        let flow = if flags & MQP3_ITEM_FLOW != 0 {
            let f = self.rest[off];
            off += 1;
            f
        } else {
            self.same_flow.unwrap_or(0)
        };
        let mut cursor = off;
        let len = get_varint(self.rest, &mut cursor).expect("validated train length");
        off = cursor;
        let inline = if flags & MQP3_ITEM_INLINE != 0 {
            let (a, n) = TargetAddrRef::decode(&self.rest[off..]).expect("validated train address");
            off += n;
            Some(a)
        } else {
            None
        };
        let payload = &self.rest[off..off + len];
        self.rest = &self.rest[off + len..];
        self.left -= 1;
        Some(TrainItemRef {
            flow,
            inline,
            src_override: flags & MQP3_ITEM_SRC != 0,
            payload,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}

impl ExactSizeIterator for TrainItems<'_> {}

pub fn decode_train(b: &[u8]) -> Result<TrainFrame<'_>, MqpError> {
    if b.len() < MQP3_TRAIN_HEADER_LEN
        || b.first().copied().map(|x| x & MQP3_KIND_MASK) != Some(MQP3_TRAIN)
    {
        return Err(MqpError::Malformed("bad train"));
    }
    if b[0] & 0x0F & !MQP3_TRAIN_SAME_FLOW != 0 {
        return Err(MqpError::Malformed("bad train flags"));
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let mut off = MQP3_TRAIN_HEADER_LEN;
    let count = b[5] as usize;
    if count == 0 || count > MQP3_MAX_TRAIN_ITEMS {
        return Err(MqpError::BadBatchCount(count as u8));
    }
    let same_flow = if b[0] & MQP3_TRAIN_SAME_FLOW != 0 {
        let f = *b
            .get(off)
            .ok_or(MqpError::Malformed("truncated train same flow"))?;
        off += 1;
        if f >= MQP3_MAX_FLOWS as u8 {
            return Err(MqpError::Malformed("bad train same flow"));
        }
        Some(f)
    } else {
        None
    };
    // Full validation before the iterator hands out any slice: a hostile
    // frame must not be able to panic the item parser.
    let mut cursor = off;
    for _ in 0..count {
        let flags = *b
            .get(cursor)
            .ok_or(MqpError::Malformed("truncated train item"))?;
        cursor += 1;
        if flags & !(MQP3_ITEM_FLOW | MQP3_ITEM_INLINE | MQP3_ITEM_SRC) != 0 {
            return Err(MqpError::Malformed("bad train item flags"));
        }
        let flow = if flags & MQP3_ITEM_FLOW != 0 {
            let f = *b
                .get(cursor)
                .ok_or(MqpError::Malformed("truncated train item flow"))?;
            cursor += 1;
            f
        } else {
            same_flow.unwrap_or(0)
        };
        if !valid_flow(flow) {
            return Err(MqpError::Malformed("bad train item flow"));
        }
        if same_flow.is_some() && flags & MQP3_ITEM_FLOW != 0 {
            return Err(MqpError::Malformed("train item flow with same-flow flag"));
        }
        if flags & MQP3_ITEM_SRC != 0 && flags & MQP3_ITEM_INLINE == 0 {
            return Err(MqpError::Malformed("train source override without inline"));
        }
        if flow == MQP3_NO_FLOW && flags & MQP3_ITEM_INLINE == 0 {
            return Err(MqpError::Malformed("train no-flow without inline"));
        }
        let len = get_varint(b, &mut cursor)?;
        if flags & MQP3_ITEM_INLINE != 0 {
            let (_, n) = TargetAddrRef::decode(&b[cursor..])?;
            cursor += n;
        }
        if len > MQP_FRAG_MAX_PAYLOAD || cursor + len > b.len() {
            return Err(MqpError::Malformed("bad train item body"));
        }
        cursor += len;
    }
    if cursor != b.len() {
        return Err(MqpError::Malformed("train trailing bytes"));
    }
    Ok(TrainFrame {
        sess,
        same_flow,
        items: &b[off..],
        count: count as u8,
    })
}

#[must_use]
pub fn train_sess(b: &[u8]) -> Option<u32> {
    if b.len() < MQP3_TRAIN_HEADER_LEN
        || b.first().copied().map(|x| x & MQP3_KIND_MASK) != Some(MQP3_TRAIN)
    {
        return None;
    }
    Some(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))
}

// ---------------- FRAG ----------------

#[derive(Debug, Clone, Copy)]
pub struct FragmentV3Ref<'a> {
    pub sess: u32,
    pub flow: u8,
    pub inline: Option<TargetAddrRef<'a>>,
    pub src_override: bool,
    pub id: u32,
    pub idx: u8,
    pub total: u8,
    pub chunk: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
pub fn encode_fragment_v3(
    sess: u32,
    flow: u8,
    addr: Option<&TargetAddrRef<'_>>,
    src_override: bool,
    id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_flow(flow) || total == 0 || idx >= total || chunk.is_empty() {
        return None;
    }
    if (flow == MQP3_NO_FLOW || src_override) && addr.is_none() {
        return None;
    }
    let header = match addr {
        Some(a) => Some(a.header().ok()?),
        None => None,
    };
    let addr_len = header.as_ref().map_or(0, AddrHeader::len);
    let total_len = MQP3_FRAG_PREFIX_LEN
        .saturating_add(usize::from(flow != 0))
        .saturating_add(addr_len)
        .saturating_add(chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    let mut flags = 0u8;
    if header.is_some() {
        flags |= MQP3_FLAG_INLINE;
    }
    if flow != 0 {
        flags |= MQP3_FLAG_FLOW;
    }
    if src_override {
        flags |= MQP3_FLAG_SRC;
    }
    v.push(MQP3_FRAG | flags);
    v.extend_from_slice(&sess.to_le_bytes());
    if flow != 0 {
        v.push(flow);
    }
    v.extend_from_slice(&id.to_le_bytes());
    v.push(idx);
    v.push(total);
    if let Some(h) = header {
        let start = v.len();
        v.resize(start + h.len(), 0);
        let n = h.encode_into(&mut v[start..]);
        debug_assert_eq!(n, h.len());
    }
    v.extend_from_slice(chunk);
    Some(Bytes::from(v))
}

pub fn decode_fragment_v3(b: &[u8]) -> Result<FragmentV3Ref<'_>, MqpError> {
    if b.len() < MQP3_FRAG_PREFIX_LEN
        || b.first().copied().map(|x| x & MQP3_KIND_MASK) != Some(MQP3_FRAG)
    {
        return Err(MqpError::Malformed("bad v3 frag"));
    }
    let flags = b[0] & 0x0F;
    if flags & !(MQP3_FLAG_INLINE | MQP3_FLAG_FLOW | MQP3_FLAG_SRC) != 0 {
        return Err(MqpError::Malformed("bad v3 frag flags"));
    }
    let sess = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    let mut off = 5usize;
    let flow = if flags & MQP3_FLAG_FLOW != 0 {
        let f = *b
            .get(off)
            .ok_or(MqpError::Malformed("truncated v3 frag flow"))?;
        off += 1;
        f
    } else {
        0
    };
    if !valid_flow(flow) {
        return Err(MqpError::Malformed("bad v3 frag flow"));
    }
    let id = u32::from_le_bytes(
        b.get(off..off + 4)
            .ok_or(MqpError::Malformed("truncated v3 frag id"))?
            .try_into()
            .expect("fixed slice"),
    );
    off += 4;
    let idx = *b
        .get(off)
        .ok_or(MqpError::Malformed("truncated v3 frag idx"))?;
    off += 1;
    let total = *b
        .get(off)
        .ok_or(MqpError::Malformed("truncated v3 frag total"))?;
    off += 1;
    if total == 0 || idx >= total {
        return Err(MqpError::Malformed("bad v3 frag index"));
    }
    let inline = if flags & MQP3_FLAG_INLINE != 0 {
        let (a, n) = TargetAddrRef::decode(&b[off..])?;
        off += n;
        Some(a)
    } else {
        None
    };
    let src_override = flags & MQP3_FLAG_SRC != 0;
    if src_override && inline.is_none() {
        return Err(MqpError::Malformed(
            "v3 frag source override without inline",
        ));
    }
    if flow == MQP3_NO_FLOW && inline.is_none() {
        return Err(MqpError::Malformed("v3 no-flow frag without inline"));
    }
    if off >= b.len() {
        return Err(MqpError::Malformed("empty v3 frag chunk"));
    }
    Ok(FragmentV3Ref {
        sess,
        flow,
        inline,
        src_override,
        id,
        idx,
        total,
        chunk: &b[off..],
    })
}

// ---------------- flow table ----------------

/// Fixed per-session `flow -> target` table.
///
/// Entries are `Arc<TargetAddr>` so a clone-on-write snapshot (the data paths
/// publish this behind an `ArcSwap`) does not allocate for an IP flow and does
/// not deep-copy a domain name. Flow ids are never reused while a session is
/// alive: when the table is full the sender falls back to [`MQP3_NO_FLOW`]
/// inline frames, which avoids both id-reuse splice hazards and receiver
/// eviction.
#[derive(Clone)]
pub struct FlowTable {
    entries: [Option<Arc<TargetAddr>>; MQP3_MAX_FLOWS],
    /// First id [`Self::insert`] may consider. Monotonic: a removed id is never
    /// handed out again while the session lives, so a delayed compressed frame
    /// cannot be spliced onto a new destination.
    next: usize,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            next: 0,
        }
    }
}

impl FlowTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, flow: u8) -> Option<&TargetAddr> {
        self.entries.get(flow as usize).and_then(Option::as_deref)
    }

    #[must_use]
    pub fn get_arc(&self, flow: u8) -> Option<Arc<TargetAddr>> {
        self.entries.get(flow as usize).and_then(Clone::clone)
    }

    /// Find the flow bound to `addr`. A linear 64-entry scan is the right trade
    /// here: a steady association hits its one flow in the first few slots, and
    /// a fanout of 32 pays a short predictable scan instead of a per-packet
    /// hash of a domain string.
    #[must_use]
    pub fn flow_for(&self, addr: &TargetAddrRef<'_>) -> Option<u8> {
        self.entries.iter().enumerate().find_map(|(i, e)| {
            e.as_ref()
                .filter(|a| a.as_ref().as_ref() == *addr)
                .map(|_| i as u8)
        })
    }

    #[must_use]
    pub fn flow_for_ip(&self, addr: SocketAddr) -> Option<u8> {
        self.flow_for(&TargetAddrRef::Ip(addr))
    }

    /// Allocate the next flow id. Returns the id and the shared address handle
    /// so the caller can publish it into a snapshot without another allocation.
    pub fn insert(&mut self, addr: TargetAddr) -> Option<(u8, Arc<TargetAddr>)> {
        let idx = self.next;
        if idx >= MQP3_MAX_FLOWS || self.entries[idx].is_some() {
            return None;
        }
        let a = Arc::new(addr);
        self.entries[idx] = Some(a.clone());
        self.next = idx + 1;
        Some((idx as u8, a))
    }

    /// Install `addr` at a caller-chosen flow (the receiver side of an inline
    /// open). Repeating the same mapping is idempotent; a different address at
    /// an occupied id is rejected, because flow ids are never reused.
    pub fn insert_at(&mut self, flow: u8, addr: Arc<TargetAddr>) -> bool {
        if flow as usize >= MQP3_MAX_FLOWS {
            return false;
        }
        match &self.entries[flow as usize] {
            None => {
                self.entries[flow as usize] = Some(addr);
                self.next = self.next.max(flow as usize + 1);
                true
            }
            Some(old) => old.as_ref() == addr.as_ref(),
        }
    }

    pub fn insert_at_owned(&mut self, flow: u8, addr: TargetAddr) -> bool {
        self.insert_at(flow, Arc::new(addr))
    }

    /// Drop a mapping. Used only when an inline open contradicts an existing
    /// binding for the same id: keeping the old target would forward later
    /// compressed frames to a destination the client no longer means, so the
    /// safe answer is to make those frames unresolvable (and therefore dropped)
    /// until a fresh open re-establishes the id.
    pub fn remove(&mut self, flow: u8) -> Option<Arc<TargetAddr>> {
        self.entries.get_mut(flow as usize)?.take()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.next >= MQP3_MAX_FLOWS
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
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
    fn single_golden_headers() {
        let p = [1u8, 2, 3];
        // flow 0 compressed: 0x10 | sess | payload = 8 B.
        let d = encode_single(7, 0, None, false, &p, 1500).unwrap();
        assert_eq!(&d[..], &[0x10, 7, 0, 0, 0, 1, 2, 3]);
        // flow 2 compressed: one extra flow byte.
        let d = encode_single(7, 2, None, false, &p, 1500).unwrap();
        assert_eq!(&d[..], &[0x12, 7, 0, 0, 0, 2, 1, 2, 3]);
        // flow 2 + v4 inline: 1 + 4 + 1 + 7 + payload.
        let a = v4(53);
        let d = encode_single(7, 2, Some(&a), false, &p, 1500).unwrap();
        assert_eq!(d.len(), 1 + 4 + 1 + 7 + 3);
        assert_eq!(d[0], MQP3_SINGLE | MQP3_FLAG_FLOW | MQP3_FLAG_INLINE);
        let s = decode_single(&d).unwrap();
        assert_eq!(s.sess, 7);
        assert_eq!(s.flow, 2);
        assert_eq!(s.inline, Some(a));
        assert_eq!(s.payload, &p);
        // flow 0 inline: no flow byte.
        let d = encode_single(7, 0, Some(&a), false, &p, 1500).unwrap();
        assert_eq!(d.len(), 1 + 4 + 7 + 3);
        assert_eq!(d[0], MQP3_SINGLE | MQP3_FLAG_INLINE);
        // domain and v6 round-trip.
        for a in [dom("example.test", 5353), v6(443)] {
            let d = encode_single(9, 1, Some(&a), false, b"x", 1500).unwrap();
            let s = decode_single(&d).unwrap();
            assert_eq!(s.inline, Some(a));
            assert_eq!(s.payload, b"x");
        }
    }

    #[test]
    fn single_rejects_bad_shapes_and_budget() {
        assert!(encode_single(1, 0, None, false, b"x", 6).is_some());
        assert!(encode_single(1, 0, None, false, b"xx", 6).is_none());
        assert!(encode_single(1, MQP3_NO_FLOW, None, false, b"x", 1500).is_none());
        assert!(encode_single(1, 0, None, true, b"x", 1500).is_none());
        assert!(encode_single(1, 64, Some(&v4(1)), false, b"x", 1500).is_none());
        assert!(decode_single(&[0x10, 1, 0, 0]).is_err());
        assert!(decode_single(&[0x12, 1, 0, 0, 0, 64, b'x']).is_err());
        assert!(decode_single(&[0x11, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn train_roundtrip_mixed_flows() {
        let a = v4(53);
        let b = dom("dns.example", 53);
        let items = [
            TrainItem {
                flow: 0,
                inline: Some(a),
                src_override: false,
                payload: b"aaaa",
            },
            TrainItem {
                flow: 0,
                inline: None,
                src_override: false,
                payload: b"bbbb",
            },
            TrainItem {
                flow: 1,
                inline: Some(b),
                src_override: false,
                payload: &[0u8; 200],
            },
            TrainItem {
                flow: MQP3_NO_FLOW,
                inline: Some(v6(9)),
                src_override: true,
                payload: b"z",
            },
        ];
        let d = encode_train(17, &items, 1600).unwrap();
        let t = decode_train(&d).unwrap();
        assert_eq!(t.sess, 17);
        assert_eq!(t.len(), 4);
        let got: Vec<_> = t.items().collect();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].flow, 0);
        assert_eq!(got[0].inline, Some(a));
        assert_eq!(got[0].payload, b"aaaa");
        assert_eq!(got[1].flow, 0);
        assert_eq!(got[1].inline, None);
        assert_eq!(got[2].flow, 1);
        assert_eq!(got[2].inline, Some(b));
        assert_eq!(got[2].payload.len(), 200);
        assert_eq!(got[3].flow, MQP3_NO_FLOW);
        assert!(got[3].src_override);
        assert_eq!(got[3].inline, Some(v6(9)));
    }

    #[test]
    fn train_same_flow_is_compact_and_roundtrips() {
        let body = [7u8; 50];
        let items: Vec<_> = (0..16)
            .map(|_| TrainItem {
                flow: 3,
                inline: None,
                src_override: false,
                payload: &body,
            })
            .collect();
        let d = encode_train(1, &items, 1600).unwrap();
        assert_eq!(d[0] & MQP3_TRAIN_SAME_FLOW, MQP3_TRAIN_SAME_FLOW);
        // 7 B header + 16 * (1 iflg + 1 len + 50 payload)
        assert_eq!(d.len(), 7 + 16 * 52);
        let t = decode_train(&d).unwrap();
        let got: Vec<_> = t.items().collect();
        assert_eq!(got.len(), 16);
        assert!(got.iter().all(|i| i.flow == 3 && i.payload.len() == 50));
    }

    #[test]
    fn train_same_flow_handles_two_byte_lengths() {
        let body = [7u8; 128];
        let items: Vec<_> = (0..8)
            .map(|_| TrainItem {
                flow: 3,
                inline: None,
                src_override: false,
                payload: &body,
            })
            .collect();
        let d = encode_train(1, &items, 1200).unwrap();
        assert_eq!(d[0] & MQP3_TRAIN_SAME_FLOW, MQP3_TRAIN_SAME_FLOW);
        let t = decode_train(&d).unwrap();
        let got: Vec<_> = t.items().collect();
        assert_eq!(got.len(), 8);
        assert!(got.iter().all(|i| i.flow == 3 && i.payload == &body[..]));
    }

    #[test]
    fn train_flow_zero_stays_in_mixed_form_and_roundtrips() {
        let body = [7u8; 128];
        let items: Vec<_> = (0..8)
            .map(|_| TrainItem {
                flow: 0,
                inline: None,
                src_override: false,
                payload: &body,
            })
            .collect();
        let d = encode_train(1, &items, 1200).unwrap();
        assert_eq!(
            d[0] & MQP3_TRAIN_SAME_FLOW,
            0,
            "flow 0 is implicit; the same-flow flag would shift the item parser"
        );
        let t = decode_train(&d).unwrap();
        let got: Vec<_> = t.items().collect();
        assert_eq!(got.len(), 8);
        assert!(got.iter().all(|i| i.flow == 0 && i.payload == &body[..]));
    }

    #[test]
    fn train_rejects_malformed() {
        assert!(decode_train(&[0x20, 1, 0, 0, 0, 0]).is_err());
        assert!(decode_train(&[0x20, 1, 0, 0, 0, 1]).is_err());
        let bad = [0x20, 1, 0, 0, 0, 1, 0x04, 1, b'x']; // src without inline
        assert!(decode_train(&bad).is_err());
        let bad = [0x20, 1, 0, 0, 0, 1, 0x02, 1]; // inline but no address
        assert!(decode_train(&bad).is_err());
        let mut d = encode_train(
            1,
            &[TrainItem {
                flow: 0,
                inline: None,
                src_override: false,
                payload: b"x",
            }],
            100,
        )
        .unwrap()
        .to_vec();
        d.push(0);
        assert!(decode_train(&d).is_err());
    }

    #[test]
    fn frag_roundtrip_and_header_sizes() {
        let a = v4(53);
        let d =
            encode_fragment_v3(7, 1, Some(&a), false, 0x1234_5678, 1, 3, b"chunk", 1500).unwrap();
        assert_eq!(d.len(), MQP3_FRAG_PREFIX_LEN + 1 + 7 + 5);
        let f = decode_fragment_v3(&d).unwrap();
        assert_eq!(
            (f.sess, f.flow, f.id, f.idx, f.total),
            (7, 1, 0x1234_5678, 1, 3)
        );
        assert_eq!(f.inline, Some(a));
        assert_eq!(f.chunk, b"chunk");
        let d = encode_fragment_v3(7, 0, None, false, 1, 0, 1, b"x", 1500).unwrap();
        assert_eq!(d.len(), MQP3_FRAG_PREFIX_LEN + 1);
        assert!(decode_fragment_v3(&[0x30, 7, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn flow_table_allocates_never_reuses_and_falls_full() {
        let mut t = FlowTable::default();
        let (f0, a0) = t
            .insert(TargetAddr::Ip(SocketAddr::from(([192, 0, 2, 1], 1))))
            .unwrap();
        assert_eq!(f0, 0);
        assert_eq!(t.flow_for(&v4(1)), None);
        assert_eq!(
            t.flow_for_ip(SocketAddr::from(([192, 0, 2, 1], 1))),
            Some(0)
        );
        assert_eq!(t.get(0).unwrap(), &*a0);
        for i in 1..MQP3_MAX_FLOWS {
            let (f, _) = t
                .insert(TargetAddr::Ip(SocketAddr::from((
                    [198, 51, 100, i as u8],
                    9,
                ))))
                .unwrap();
            assert_eq!(f as usize, i);
        }
        assert!(t.is_full());
        assert!(
            t.insert(TargetAddr::Ip(SocketAddr::from(([203, 0, 113, 1], 1))))
                .is_none()
        );
        // Same-id repeated install is idempotent; a different address is not.
        let a = Arc::new(TargetAddr::Ip(SocketAddr::from(([192, 0, 2, 1], 1))));
        assert!(t.insert_at(0, a.clone()));
        assert!(t.insert_at(0, a));
        assert!(!t.insert_at(
            0,
            Arc::new(TargetAddr::Ip(SocketAddr::from(([192, 0, 2, 2], 2))))
        ));
        // A removed id is not handed out again: a late compressed frame for the
        // old flow must not be spliced onto a new destination.
        let mut reuse = FlowTable::default();
        assert_eq!(
            reuse
                .insert(TargetAddr::Ip(SocketAddr::from(([192, 0, 2, 1], 1))))
                .unwrap()
                .0,
            0
        );
        reuse.remove(0);
        let (next, _) = reuse
            .insert(TargetAddr::Ip(SocketAddr::from(([203, 0, 113, 9], 9))))
            .expect("the table has free capacity");
        assert_eq!(next, 1, "the removed id must not be reused");
    }

    /// The admission charge must bound a *domain*-filled table, not only the
    /// IP-target case the old 4 KiB figure priced: a peer chooses whether its
    /// targets are domains, so the worst case is 64 live `Arc<TargetAddr>` with
    /// a wire-limit name each, plus the 520-byte inline table.
    #[test]
    fn flow_table_charge_covers_domain_targets() {
        let per_domain = 16 + 40 + 255 + 32; // Arc header + TargetAddr + name + rounding
        let inline = MQP3_MAX_FLOWS * std::mem::size_of::<Option<Arc<TargetAddr>>>()
            + std::mem::size_of::<usize>();
        assert!(
            MQP3_FLOW_TABLE_MAX_BYTES >= MQP3_MAX_FLOWS * per_domain,
            "{MQP3_FLOW_TABLE_MAX_BYTES} B must cover {MQP3_MAX_FLOWS} domain targets"
        );
        assert!(
            MQP3_FLOW_TABLE_MAX_BYTES >= MQP3_MAX_FLOWS * per_domain + inline,
            "the inline table and cursor must fit too"
        );
        // Pinned to the constant's own documented size, so shrinking it back
        // toward the old IP-only figure fails here.
        assert_eq!(MQP3_FLOW_TABLE_MAX_BYTES, 22 * 1024);
    }

    #[test]
    fn varint_matches_leb128_boundaries() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 3);
    }
}
