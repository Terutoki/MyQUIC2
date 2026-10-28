//! MQP-3 wire **rev3** codec: fixed-width little-endian framing, a 2-byte
//! packed steady header with 14-bit owner-split flow ids, the burst/fragment
//! forms, and the reliable-stream control-message framing.
//!
//! This is the Phase-1 "codec only" module from
//! `analysis/rev3/design-options.md` §4.2 (*Exact wire format*): pure
//! encode/decode with no flow/session state machines and no client/server
//! wiring. It is wire-incompatible with [`super::r2`] and with the MQP-2/v3
//! codecs; the only shared component is the SOCKS5 address codec in
//! [`super::addr`].
//!
//! # Wire rules (all fixed width, little-endian, no varints)
//!
//! * One rev3 frame per QUIC DATAGRAM body. For `DATA`/`DATA_EXT`/`FRAG` the
//!   payload is the rest of the datagram after the header (no length field);
//!   `TRAIN` has an explicit item count and therefore an exact frame size.
//! * The top two bits of byte 0 are the frame class:
//!
//! ```text
//! b0[7:6]  class      rest of byte 0 / frame
//!   00     DATA       b0[5:0] = fid[13:8], b1 = fid[7:0]          (2-byte header)
//!   01     DATA_EXT   b0[5:4] reserved = 0, b0[3:0] flags
//!   10     TRAIN      b0[5:4] form,        b0[3:0] reserved = 0
//!   11     FRAG       b0[5:4] reserved = 0, b0[3:0] flags (0 = steady)
//! ```
//!
//! * The steady `DATA` fid is split **high bits first** across b0/b1
//!   (`fid = (b0 & 0x3F) << 8 | b1`), unlike every multi-byte integer field,
//!   which is little-endian. That packing is what makes the steady header
//!   exactly two bytes with no length varint.
//! * `DATA_EXT` and `FRAG` flags: `0x01 OPEN`, `0x02 SRC`, `0x04 INLINE`.
//!   Exactly four forms exist — `OPEN` (`0x01`), `SRC` (`0x02`),
//!   `OPEN_SRC` (`0x03`) and `INLINE` (`0x04`); every other flag combination,
//!   and any non-zero reserved bit, is malformed. `OPEN` allocates a
//!   client-owned fid, `OPEN_SRC` a server-owned fid (§4.1 decision 4), and
//!   both decoders and encoders enforce that owner assignment.
//! * `TRAIN` forms `SAME` (0), `SAME_EQUAL` (1), `DICT` (2); count `1..=64`,
//!   `nfl <= count`, distinct fids, zero-length items allowed.
//! * `FRAG`: `1 <= total <= 64`, `idx < total`, non-empty chunk capped at
//!   [`MAX_FRAG_BYTES`].
//!
//! # Header sizes (from §4.2, asserted by the unit tests)
//!
//! ```text
//! DATA steady            2 B
//! DATA OPEN/OPEN_SRC     v4 14, v6 26, domain 11+L
//! DATA SRC               v4 10, v6 22, domain  7+L
//! DATA INLINE            v4 12, v6 24, domain  9+L
//! TRAIN SAME             4 B base,  1 B/item (3 B if len > 254)
//! TRAIN SAME_EQUAL       5-7 B base, 0 B/item
//! TRAIN DICT             3 + 2*nfl B base, 2 B/item (4 B if len > 254)
//!                        (b0 owns the form; the analysis table's "4+2*nfl"
//!                        counts a rev2 form byte that rev3 packs into b0)
//! FRAG steady            9 B
//! ```
//!
//! # Flow ids and the allocator
//!
//! A flow is named by a connection-scoped 14-bit `fid`: `0x0000..=0x1FFF`
//! client-allocated, `0x2000..=0x3FFF` server-allocated (8192 ids per owner,
//! 2x the 4096 live-flow cap). Ids are allocated monotonically and **never
//! reused while the connection lives**, so a delayed frame for a closed flow
//! can only miss the table — it can never be delivered to a new flow's target.
//! [`FlowIds`] is that allocator; it returns `None` once its owner's 8192 ids
//! are spent, and the caller then falls back to the fid-less `INLINE` form
//! (correct but larger) and may recycle the connection. `fid == 0` is a
//! perfectly valid client id (unlike rev2, where the LEB128 encoding forced
//! id 0 to be reserved).
//!
//! # Validation and bounds (security invariants)
//!
//! Every decoder runs on peer-controlled bytes, so each one validates
//! class/flag/reserved/length/range fields **before** slicing, returns
//! [`MqpError`] instead of panicking, and never allocates: payloads, frames,
//! control messages and (borrowed) domain addresses are returned as views
//! into the input buffer. Bounds enforced here: [`MAX_TRAIN_ITEMS`] items per
//! train, [`MAX_FRAG_TOTAL`] fragments, [`MAX_FRAG_BYTES`] bytes per fragment
//! chunk, [`MAX_FRAG_BYTES`] chunk cap, and [`MAX_CTL_BODY`] bytes per control
//! message. [`MAX_FRAME_BYTES`] is the encoder's DATAGRAM budget (every
//! `encode_*` takes an explicit `limit`); decoders deliberately do not enforce
//! it, because the transport already bounds a DATAGRAM and the caller bounds
//! the buffer it hands in. [`MAX_REASSEMBLY`] and [`MAX_ADDR_LEN`] are the
//! protocol limits the reassembler and address codec must keep.
//!
//! # Trailing-byte policy (decided here, documented for the integrator)
//!
//! * `DATA`/`DATA_EXT`: the payload is the remainder of the DATAGRAM; every
//!   byte after the header is payload, so there is no trailing-byte concept.
//! * `FRAG`: the chunk is the remainder of the DATAGRAM (capped at
//!   [`MAX_FRAG_BYTES`]); again no trailing-byte concept.
//! * `TRAIN` (all forms): `count` defines the exact frame size, so trailing
//!   bytes are rejected as [`MqpError::Malformed`]. A receiver must never have
//!   to guess where a `TRAIN` ends.
//! * Control messages: `len` defines the exact body size, which must also
//!   equal the size the message type requires. [`decode_ctl_message`] returns
//!   the number of bytes it consumed and leaves the rest to the next message
//!   (the control plane is a byte stream; rejecting trailing bytes here would
//!   make coalesced stream reads impossible).
//! * A non-canonical item-length escape (`0xFF` + a `u16` below `0xFF`) is
//!   accepted on decode: it is unambiguous and cannot make a frame unsafe;
//!   encoders always emit the canonical short form.
//!
//! # First-byte classification and the TCP-stream collision hazard
//!
//! [`kind`] classifies a buffer by `b0 >> 6`. Because the class is the top two
//! bits, **every one of the 256 possible first bytes belongs to a rev3 class**,
//! so [`is_r3`] is true for every non-empty buffer. That is correct for rev3
//! DATAGRAM bodies (the connection's configured revision means every DATAGRAM
//! on an r3 connection is an r3 frame) and deliberately useless anywhere else.
//!
//! It MUST NOT be used to classify bytes on a reliable stream. On the TCP data
//! path the first byte is a SOCKS5 address `atyp` (`0x01` IPv4, `0x03` domain,
//! `0x04` IPv6), and a steady `DATA` frame can easily start with exactly those
//! bytes: a frame for `fid = 0x0100/0x0300/0x0400..` has `b0 ==
//! 0x01/0x03/0x04` while still being a valid `DATA` header. Likewise the
//! control stream's first byte is [`CTL_STREAM_MARKER`] (`0xFF`), which
//! classifies as `FRAG` (no valid `FRAG` header has its reserved bits set, so
//! the encoder never emits one, but the class byte alone does not prove it).
//! Stream classifiers must branch on the control marker / address `atyp`
//! **first**, and only DATAGRAM bodies — never stream bytes — may be passed to
//! this module. The encoder needs no such distinction: it knows which plane it
//! is writing.
//!
//! # Control plane
//!
//! Control messages ride one reliable QUIC bidi stream, not DATAGRAMs. The
//! stream opener writes [`CTL_STREAM_MARKER`] once (so the server can tell it
//! apart from a TCP-flow stream, whose first byte is a valid address `atyp`),
//! then frames messages as `type:u8 | len:u16le | body`, where `len` counts the
//! body only (`len <= MAX_CTL_BODY`; every defined body is `<= 5` B, so a
//! message is at most 8 B, well inside the 64 B message budget). The marker is
//! not part of any message and is not produced or consumed by
//! [`encode_ctl_message`]/[`decode_ctl_message`].

use bytes::Bytes;

use super::addr::{AddrHeader, TargetAddrRef};
use super::error::MqpError;

// ---------------- frame classes and form flags ----------------

/// Mask of the frame-class bits (`b0[7:6]`).
pub const CLASS_MASK: u8 = 0xC0;
/// Class `00`: steady `DATA` frame (`fid` packed into b0/b1).
pub const CLASS_DATA: u8 = 0x00;
/// Class `01`: extended `DATA` frame (`OPEN`/`SRC`/`OPEN_SRC`/`INLINE`).
pub const CLASS_DATA_EXT: u8 = 0x40;
/// Class `10`: `TRAIN` burst frame.
pub const CLASS_TRAIN: u8 = 0x80;
/// Class `11`: `FRAG` fragment frame.
pub const CLASS_FRAG: u8 = 0xC0;

/// `DATA_EXT`/`FRAG` flag: this frame opens/re-binds a flow (carries binding).
pub const FLAG_OPEN: u8 = 0x01;
/// `DATA_EXT`/`FRAG` flag: the carried address is the actual source, not the
/// target (downlink rebind / full-cone reply).
pub const FLAG_SRC: u8 = 0x02;
/// `DATA_EXT`/`FRAG` flag: no flow id; session + address are carried inline.
pub const FLAG_INLINE: u8 = 0x04;

/// The four valid `DATA_EXT`/`FRAG` form bytes (`b0[3:0]`).
///
/// These are *values* to pattern-match on, not bits to OR into an arbitrary
/// flag set: `OPEN_SRC` is the value `0x03`, i.e. the wire encoding of
/// "open + src", and a frame carrying any other combination is malformed.
const FORM_OPEN: u8 = FLAG_OPEN; // 0x01
const FORM_SRC: u8 = FLAG_SRC; // 0x02
const FORM_OPEN_SRC: u8 = FLAG_OPEN | FLAG_SRC; // 0x03
const FORM_INLINE: u8 = FLAG_INLINE; // 0x04

/// Reserved bits `b0[5:4]` of a `DATA_EXT`/`FRAG` first byte; must be zero.
const EXT_RESERVED_MASK: u8 = 0x30;
/// Mask of the form-flag bits `b0[3:0]` of a `DATA_EXT`/`FRAG` first byte.
const EXT_FLAGS_MASK: u8 = 0x0F;

// ---------------- TRAIN forms ----------------

/// `TRAIN` form `SAME`: one flow, every item carries its own length.
pub const TRAIN_FORM_SAME: u8 = 0;
/// `TRAIN` form `SAME_EQUAL`: one flow, every item has the same length, which
/// is carried once in the header.
pub const TRAIN_FORM_SAME_EQUAL: u8 = 1;
/// `TRAIN` form `DICT`: an inline flow dictionary plus indexed items.
pub const TRAIN_FORM_DICT: u8 = 2;

/// Mask of the `TRAIN` form bits `b0[5:4]`.
const TRAIN_FORM_MASK: u8 = 0x30;
/// Shift of the `TRAIN` form bits.
const TRAIN_FORM_SHIFT: u8 = 4;
/// Reserved bits `b0[3:0]` of a `TRAIN` first byte; must be zero.
const TRAIN_RESERVED_MASK: u8 = 0x0F;

// ---------------- flow-id space ----------------
//
// The 14-bit id space is split by owner: the client owns the low half, the
// server the high half, so an id can never be allocated by both endpoints.

/// Highest flow id representable on the wire (14 bits).
pub const FID_MAX: u16 = 0x3FFF;
/// Highest client-allocated flow id (`0x0000..=0x1FFF`).
pub const CLIENT_FID_MAX: u16 = 0x1FFF;
/// Lowest server-allocated flow id (`0x2000..=0x3FFF`).
pub const SERVER_FID_BASE: u16 = 0x2000;
/// Number of flow ids each endpoint may allocate over one connection (8192).
pub const FIDS_PER_OWNER: usize = 8192;

// ---------------- protocol bounds ----------------

/// Maximum number of items in one `TRAIN` frame.
pub const MAX_TRAIN_ITEMS: usize = 64;
/// Live flows per connection (admission cap; the id space is 2x this).
pub const MAX_FLOWS_PER_CONN: u16 = 4096;
/// Live flows per UDP session.
pub const MAX_FLOWS_SESSION: u16 = 64;
/// Maximum `FRAG` fragment count of one datagram (`1..=64`).
pub const MAX_FRAG_TOTAL: u8 = 64;
/// Maximum bytes in one `FRAG` chunk (and thus the per-fragment payload cap).
pub const MAX_FRAG_BYTES: usize = 8192;
/// Maximum reassembled datagram size.
pub const MAX_REASSEMBLY: usize = 8192;
/// DATAGRAM payload budget the encoders are sized against (1472 B MTU class).
pub const MAX_FRAME_BYTES: usize = 1472;
/// Wire length of the largest address form (`atyp | addr | port`).
pub const MAX_ADDR_LEN: usize = AddrHeader::MAX_LEN;
/// Maximum control-message body length (`len` field of the stream framing).
pub const MAX_CTL_BODY: usize = 64;

/// Frame class of a rev3 frame, from the top two bits of its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R3Kind {
    /// Class `00`: steady [`DataRef`] (2-byte header, binding already known).
    Data,
    /// Class `01`: extended data frame carrying a binding
    /// (`OPEN`/`SRC`/`OPEN_SRC`/`INLINE`).
    DataExt,
    /// Class `10`: [`TrainFrame`] burst.
    Train,
    /// Class `11`: [`FragRef`] fragment.
    Frag,
}

// The bounds above are protocol invariants; a bad edit must fail the build,
// not ship a frame the peer rejects.
const _: () = {
    assert!(FIDS_PER_OWNER == CLIENT_FID_MAX as usize + 1);
    assert!(FIDS_PER_OWNER == FID_MAX as usize - SERVER_FID_BASE as usize + 1);
    assert!(MAX_TRAIN_ITEMS <= u8::MAX as usize);
    assert!(MAX_FLOWS_PER_CONN as usize <= FIDS_PER_OWNER);
    assert!(MAX_FLOWS_SESSION <= MAX_FLOWS_PER_CONN);
    assert!(MAX_FRAG_BYTES <= MAX_REASSEMBLY);
    assert!(MAX_FRAME_BYTES <= u16::MAX as usize);
    assert!(MAX_CTL_BODY <= u16::MAX as usize);
    assert!(5 <= MAX_CTL_BODY); // largest defined control body fits the cap
};

// ---------------- first-byte classification ----------------

/// Whether `b` starts with a rev3 class byte.
///
/// Every non-empty buffer does, because the class is the top two bits of byte
/// 0 and all 256 values are covered. See the module docs: this predicate is
/// only meaningful for bytes already known to be a rev3 DATAGRAM body, and
/// must never be used to classify the reliable-stream planes (the TCP-flow
/// address `atyp` and the control-stream marker collide with valid `DATA`
/// first bytes).
#[must_use]
pub fn is_r3(b: &[u8]) -> bool {
    !b.is_empty()
}

/// Classify the first byte of `b`; `None` only for an empty slice.
#[must_use]
pub fn kind(b: &[u8]) -> Option<R3Kind> {
    let b0 = *b.first()?;
    Some(match b0 & CLASS_MASK {
        CLASS_DATA => R3Kind::Data,
        CLASS_DATA_EXT => R3Kind::DataExt,
        CLASS_TRAIN => R3Kind::Train,
        _ => R3Kind::Frag,
    })
}

// ---------------- flow ids ----------------

/// Which endpoint allocated a flow id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidOwner {
    /// Client-allocated ids, `0x0000..=0x1FFF`.
    Client,
    /// Server-allocated ids, `0x2000..=0x3FFF`.
    Server,
}

/// Whether `fid` is in the client-allocated half of the id space.
#[must_use]
#[inline]
pub fn is_client_fid(fid: u16) -> bool {
    fid <= CLIENT_FID_MAX
}

/// Whether `fid` is in the server-allocated half of the id space.
#[must_use]
#[inline]
pub fn is_server_fid(fid: u16) -> bool {
    (SERVER_FID_BASE..=FID_MAX).contains(&fid)
}

/// Whether `fid` is a valid wire flow id (representable in 14 bits).
#[must_use]
#[inline]
pub fn valid_fid(fid: u16) -> bool {
    fid <= FID_MAX
}

/// Owner of a valid wire flow id; `None` for a 14-bit overflow (`>= 0x4000`).
#[must_use]
pub fn fid_owner(fid: u16) -> Option<FidOwner> {
    if is_client_fid(fid) {
        Some(FidOwner::Client)
    } else if is_server_fid(fid) {
        Some(FidOwner::Server)
    } else {
        None
    }
}

/// Validate that `fid` belongs to `owner`'s half of the id space.
///
/// Used by the binding-carrying forms whose owner is fixed by the form
/// (`OPEN` allocates a client id, `OPEN_SRC` a server id — §4.1 decision 4):
/// emitting or accepting the wrong half would let one endpoint allocate in the
/// other's space, so both encoder and decoder reject it.
fn require_fid_owner(fid: u16, owner: FidOwner, bad: &'static str) -> Result<(), MqpError> {
    let ok = match owner {
        FidOwner::Client => is_client_fid(fid),
        FidOwner::Server => is_server_fid(fid),
    };
    if ok {
        Ok(())
    } else {
        Err(MqpError::Malformed(bad))
    }
}

/// Monotonic, never-reused flow-id allocator for one endpoint of one
/// connection.
///
/// `alloc` hands out consecutive ids from the owner's half
/// (`0x0000..=0x1FFF` for [`FidOwner::Client`], `0x2000..=0x3FFF` for
/// [`FidOwner::Server`]) and never reuses one while the allocator lives — that
/// is the delayed-frame safety invariant (§4.1 decision 4). After 8192
/// allocations it returns `None`: the caller must then use the fid-less
/// `INLINE` data form (correct, just larger) and may recycle the connection;
/// ids are *not* recycled by this type.
#[derive(Debug, Clone)]
pub struct FlowIds {
    owner: FidOwner,
    next: u32,
    end: u32,
    base: u32,
}

impl FlowIds {
    /// Create an allocator for one endpoint's half of the id space.
    #[must_use]
    pub fn new(owner: FidOwner) -> Self {
        let (base, end) = match owner {
            FidOwner::Client => (0u32, FIDS_PER_OWNER as u32),
            FidOwner::Server => (
                SERVER_FID_BASE as u32,
                SERVER_FID_BASE as u32 + FIDS_PER_OWNER as u32,
            ),
        };
        Self {
            owner,
            next: base,
            end,
            base,
        }
    }

    /// Allocator for the client half of the id space.
    #[must_use]
    pub fn client() -> Self {
        Self::new(FidOwner::Client)
    }

    /// Allocator for the server half of the id space.
    #[must_use]
    pub fn server() -> Self {
        Self::new(FidOwner::Server)
    }

    /// Which endpoint owns the ids this allocator hands out.
    #[must_use]
    pub fn owner(&self) -> FidOwner {
        self.owner
    }

    /// Allocate the next id, or `None` once the owner's 8192 ids are spent.
    ///
    /// The returned ids are strictly increasing and never repeat; callers fall
    /// back to `DATA INLINE` on `None`.
    pub fn alloc(&mut self) -> Option<u16> {
        if self.next >= self.end {
            return None;
        }
        let fid = self.next as u16;
        self.next += 1;
        Some(fid)
    }

    /// Number of ids still available.
    #[must_use]
    pub fn remaining(&self) -> usize {
        (self.end - self.next) as usize
    }

    /// Number of ids handed out so far.
    #[must_use]
    pub fn allocated(&self) -> usize {
        (self.next - self.base) as usize
    }

    /// Whether every id of this owner's half has been handed out.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.next >= self.end
    }
}

// ---------------- fixed-width helpers ----------------
//
// Every multi-byte integer on the rev3 wire is little-endian and fixed width;
// these helpers are the only place that reads or writes one. Each bounds
// checks the offset before slicing, so a truncated buffer is an error, never a
// panic.

fn get_u16(b: &[u8], off: &mut usize) -> Result<u16, MqpError> {
    let end = off
        .checked_add(2)
        .ok_or(MqpError::Malformed("r3 u16 offset overflow"))?;
    let s = b
        .get(*off..end)
        .ok_or(MqpError::Malformed("truncated r3 u16"))?;
    *off = end;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn get_u32(b: &[u8], off: &mut usize) -> Result<u32, MqpError> {
    let end = off
        .checked_add(4)
        .ok_or(MqpError::Malformed("r3 u32 offset overflow"))?;
    let s = b
        .get(*off..end)
        .ok_or(MqpError::Malformed("truncated r3 u32"))?;
    *off = end;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_addr(out: &mut Vec<u8>, addr: &AddrHeader<'_>) {
    let start = out.len();
    out.resize(start + addr.len(), 0);
    let n = addr.encode_into(&mut out[start..]);
    debug_assert_eq!(n, addr.len());
}

/// Validate the reserved bits of a `DATA_EXT`/`FRAG` first byte and return its
/// (still unvalidated) form-flag bits.
fn ext_flags(b0: u8, bad_reserved: &'static str) -> Result<u8, MqpError> {
    if b0 & EXT_RESERVED_MASK != 0 {
        return Err(MqpError::Malformed(bad_reserved));
    }
    Ok(b0 & EXT_FLAGS_MASK)
}

/// Whether a `TRAIN` item count is inside `1..=MAX_TRAIN_ITEMS`.
fn valid_train_count(n: usize) -> Option<()> {
    if (1..=MAX_TRAIN_ITEMS).contains(&n) {
        Some(())
    } else {
        None
    }
}

/// Encoded length of a `TRAIN` item-length field: one byte below `0xFF`, else
/// the `0xFF` escape plus a `u16` (three bytes). `None` above `u16::MAX`.
fn item_len_len(n: usize) -> Option<usize> {
    if n < 0xFF {
        Some(1)
    } else if n <= u16::MAX as usize {
        Some(3)
    } else {
        None
    }
}

/// Append a `TRAIN` item-length field. Returns `false` only for a length above
/// `u16::MAX`, which every `train_*_len` helper already refused.
fn put_item_len(out: &mut Vec<u8>, n: usize) -> bool {
    if n < 0xFF {
        out.push(n as u8);
        true
    } else if let Ok(n) = u16::try_from(n) {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
        true
    } else {
        false
    }
}

/// Read a `TRAIN` item-length field (see [`put_item_len`]).
fn get_item_len(b: &[u8], off: &mut usize) -> Result<usize, MqpError> {
    let first = *b
        .get(*off)
        .ok_or(MqpError::Malformed("truncated r3 train item len"))?;
    *off += 1;
    if first == 0xFF {
        Ok(usize::from(get_u16(b, off)?))
    } else {
        Ok(usize::from(first))
    }
}

/// Allocation-free item-length read for the [`TrainItems`] iterator. The frame
/// was validated eagerly by [`decode_train`], so `None` here only means "stop
/// iterating" and is unreachable for a frame this module produced.
fn item_len_at(b: &[u8], off: &mut usize) -> Option<usize> {
    let first = *b.get(*off)?;
    *off += 1;
    if first == 0xFF {
        let end = off.checked_add(2)?;
        let s = b.get(*off..end)?;
        *off = end;
        Some(usize::from(u16::from_le_bytes([s[0], s[1]])))
    } else {
        Some(usize::from(first))
    }
}

// ---------------- DATA ----------------

/// Borrowed view of a decoded `DATA` frame (steady or one of the four
/// `DATA_EXT` forms).
#[derive(Debug, Clone, Copy)]
pub struct DataRef<'a> {
    /// Flow id; `None` for the `INLINE` form (no flow is bound by this frame).
    pub fid: Option<u16>,
    /// Session id; present on `OPEN`/`OPEN_SRC`/`INLINE`.
    pub sess: Option<u32>,
    /// Binding address; present on every `DATA_EXT` form. For `OPEN`/`INLINE`
    /// it is the target, for `SRC`/`OPEN_SRC` it is the actual source.
    pub addr: Option<TargetAddrRef<'a>>,
    /// The carried address is a source (`SRC`/`OPEN_SRC`), not a target.
    pub src: bool,
    /// Payload: the rest of the DATAGRAM after the header (may be empty).
    pub payload: &'a [u8],
}

/// Wire length of a steady `DATA` frame (2-byte header + payload).
#[must_use]
pub fn data_steady_len(payload_len: usize) -> usize {
    2 + payload_len
}

/// Wire length of an `OPEN`/`OPEN_SRC` frame header + payload
/// (`v4 14`, `v6 26`, `domain 11+L` with `addr_len = 4+L`).
#[must_use]
pub fn data_open_len(addr_len: usize, payload_len: usize) -> usize {
    7 + addr_len + payload_len
}

/// Wire length of a `SRC` frame header + payload
/// (`v4 10`, `v6 22`, `domain 7+L`).
#[must_use]
pub fn data_src_len(addr_len: usize, payload_len: usize) -> usize {
    3 + addr_len + payload_len
}

/// Wire length of an `INLINE` frame header + payload
/// (`v4 12`, `v6 24`, `domain 9+L`).
#[must_use]
pub fn data_inline_len(addr_len: usize, payload_len: usize) -> usize {
    5 + addr_len + payload_len
}

/// Encode a steady `DATA` frame (binding context already confirmed).
///
/// Returns `None` when `fid` is outside `0..=0x3FFF` or the exact frame size
/// exceeds `limit`.
pub fn encode_data_steady(fid: u16, payload: &[u8], limit: usize) -> Option<Bytes> {
    if !valid_fid(fid) {
        return None;
    }
    let total = data_steady_len(payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    // Class bits 00 in b0[7:6]; the id's high six bits in b0[5:0].
    v.push(((fid >> 8) as u8) & 0x3F);
    v.push(fid as u8);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Encode an `OPEN` (`src == false`, client-owned fid) or `OPEN_SRC`
/// (`src == true`, server-owned fid) frame.
///
/// `sess` + `addr` are the binding context the receiver installs; the payload
/// is the first payload of the flow. Returns `None` on an invalid address
/// (the [`super::addr`] policy refuses unspecified/scoped IPs and empty or
/// over-long domains), on an `fid` in the wrong owner half, or when the frame
/// would exceed `limit`.
pub fn encode_data_open(
    fid: u16,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let owner = if src {
        FidOwner::Server
    } else {
        FidOwner::Client
    };
    require_fid_owner(fid, owner, "r3 data open fid owner").ok()?;
    let header = addr.header().ok()?;
    let total = data_open_len(header.len(), payload.len());
    if total > limit {
        return None;
    }
    let flags = if src { FORM_OPEN_SRC } else { FORM_OPEN };
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_DATA_EXT | flags);
    put_u16(&mut v, fid);
    put_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Encode a `SRC` frame: rebind an existing flow to the actual source address
/// (downlink / full-cone), carrying no session id.
///
/// Returns `None` on an invalid `fid`, on an address the address codec refuses,
/// or when the frame would exceed `limit`.
pub fn encode_data_src(
    fid: u16,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_fid(fid) {
        return None;
    }
    let header = addr.header().ok()?;
    let total = data_src_len(header.len(), payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_DATA_EXT | FORM_SRC);
    put_u16(&mut v, fid);
    put_addr(&mut v, &header);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Encode an `INLINE` frame: session + target address with no flow id, the
/// fallback when the local id space is exhausted (or a rebind must not allocate
/// one).
///
/// Returns `None` on an address the address codec refuses or when the frame
/// would exceed `limit`.
pub fn encode_data_inline(
    sess: u32,
    addr: &TargetAddrRef<'_>,
    payload: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let header = addr.header().ok()?;
    let total = data_inline_len(header.len(), payload.len());
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_DATA_EXT | FORM_INLINE);
    put_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(payload);
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Decode a `DATA` frame (steady or extended).
///
/// Validates class, reserved bits, form/flag combination and fid ownership
/// before returning borrowed views; the payload is the remainder of `b`.
pub fn decode_data(b: &[u8]) -> Result<DataRef<'_>, MqpError> {
    let b0 = *b.first().ok_or(MqpError::Malformed("empty r3 frame"))?;
    match b0 & CLASS_MASK {
        CLASS_DATA => {
            let b1 = *b.get(1).ok_or(MqpError::Malformed("short r3 data"))?;
            // b0[5:0] are fid[13:8] and b1 is fid[7:0]: high bits first.
            let fid = (u16::from(b0 & 0x3F) << 8) | u16::from(b1);
            Ok(DataRef {
                fid: Some(fid),
                sess: None,
                addr: None,
                src: false,
                payload: &b[2..],
            })
        }
        CLASS_DATA_EXT => {
            let flags = ext_flags(b0, "bad r3 data reserved")?;
            let mut off = 1usize;
            match flags {
                FORM_OPEN | FORM_OPEN_SRC => {
                    let src = flags == FORM_OPEN_SRC;
                    let fid = get_u16(b, &mut off)?;
                    let owner = if src {
                        FidOwner::Server
                    } else {
                        FidOwner::Client
                    };
                    require_fid_owner(fid, owner, "r3 data open fid owner")?;
                    let sess = get_u32(b, &mut off)?;
                    let (addr, n) = TargetAddrRef::decode(&b[off..])?;
                    off += n;
                    Ok(DataRef {
                        fid: Some(fid),
                        sess: Some(sess),
                        addr: Some(addr),
                        src,
                        payload: &b[off..],
                    })
                }
                FORM_SRC => {
                    let fid = get_u16(b, &mut off)?;
                    if !valid_fid(fid) {
                        return Err(MqpError::Malformed("bad r3 data fid"));
                    }
                    let (addr, n) = TargetAddrRef::decode(&b[off..])?;
                    off += n;
                    Ok(DataRef {
                        fid: Some(fid),
                        sess: None,
                        addr: Some(addr),
                        src: true,
                        payload: &b[off..],
                    })
                }
                FORM_INLINE => {
                    let sess = get_u32(b, &mut off)?;
                    let (addr, n) = TargetAddrRef::decode(&b[off..])?;
                    off += n;
                    Ok(DataRef {
                        fid: None,
                        sess: Some(sess),
                        addr: Some(addr),
                        src: false,
                        payload: &b[off..],
                    })
                }
                _ => Err(MqpError::Malformed("bad r3 data flags")),
            }
        }
        _ => Err(MqpError::Malformed("bad r3 data kind")),
    }
}

// ---------------- TRAIN ----------------

/// Wire length of a `SAME` train: 4-byte header plus `len + payload` per item.
#[must_use]
pub fn train_same_len(fid: u16, payloads: &[&[u8]]) -> Option<usize> {
    valid_train_count(payloads.len())?;
    if !valid_fid(fid) {
        return None;
    }
    let mut total = 4usize;
    for p in payloads {
        total = total.checked_add(item_len_len(p.len())?)?;
        total = total.checked_add(p.len())?;
    }
    Some(total)
}

/// Wire length of a `SAME_EQUAL` train: 4-byte header, the one shared item
/// length (1 or 3 bytes), then `count * item_len` payload bytes.
///
/// Returns `None` unless every payload has the same length and that length is
/// encodable in a `u16` item-length field.
#[must_use]
pub fn train_same_equal_len(fid: u16, payloads: &[&[u8]]) -> Option<usize> {
    valid_train_count(payloads.len())?;
    if !valid_fid(fid) {
        return None;
    }
    let item_len = payloads.first()?.len();
    if payloads.iter().any(|p| p.len() != item_len) {
        return None;
    }
    let total = 4usize;
    let total = total.checked_add(item_len_len(item_len)?)?;
    let body = item_len.checked_mul(payloads.len())?;
    total.checked_add(body)
}

/// Wire length of a `DICT` train: 3-byte header (`b0 | nfl | count`), two bytes
/// per dictionary fid, then `idx + len + payload` per item.
///
/// The analysis doc's §4.2 prose says "header 4+2*nfl", but the byte layout in
/// the same block is `b0 | nfl:u8 | count:u8 | nfl x fid:u16` — three header
/// bytes, because rev3 packs the form (a separate byte in rev2) into b0. The
/// byte layout is authoritative here.
#[must_use]
pub fn train_dict_len(flows: &[u16], items: &[(u8, &[u8])]) -> Option<usize> {
    valid_train_count(items.len())?;
    valid_train_flows(flows, items)?;
    let mut total = 3usize; // b0 + nfl + count; the form is inside b0
    for _ in flows {
        total = total.checked_add(2)?;
    }
    for (_, p) in items {
        total = total.checked_add(1)?;
        total = total.checked_add(item_len_len(p.len())?)?;
        total = total.checked_add(p.len())?;
    }
    Some(total)
}

/// Validate a `DICT` train's shared shape: at least one distinct fid, no more
/// flows than items (`nfl <= count`), and every item index inside the
/// dictionary. Used by both the encoder (symmetric refusal) and the decoder.
fn valid_train_flows(flows: &[u16], items: &[(u8, &[u8])]) -> Option<()> {
    if flows.is_empty() || flows.len() > MAX_TRAIN_ITEMS || flows.len() > items.len() {
        return None;
    }
    for (i, f) in flows.iter().enumerate() {
        if !valid_fid(*f) || flows[..i].contains(f) {
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

/// Encode a `SAME` train: one flow, one independent length per item.
pub fn encode_train_same(fid: u16, payloads: &[&[u8]], limit: usize) -> Option<Bytes> {
    let total = train_same_len(fid, payloads)?;
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_TRAIN | TRAIN_FORM_SAME);
    put_u16(&mut v, fid);
    v.push(payloads.len() as u8);
    for p in payloads {
        // `put_item_len` writes the length field: it must never sit inside a
        // `debug_assert!`, which compiles the whole expression away in release
        // and would emit a frame every peer rejects.
        let wrote = put_item_len(&mut v, p.len());
        debug_assert!(wrote, "the length was already bounded by train_same_len");
        v.extend_from_slice(p);
    }
    debug_assert_eq!(v.len(), total);
    // The length the encoder budgeted and the bytes it produced must agree in
    // every profile: a mismatch means a header writer was skipped (the bug that
    // shipped a length-less DICT train), and emitting that frame would make
    // every receiver drop it. Refusing the frame keeps the failure countable.
    if v.len() != total {
        return None;
    }
    Some(Bytes::from(v))
}

/// Encode a `SAME_EQUAL` train: one flow, every item the same length, carried
/// once in the header (0 bytes of per-item framing).
pub fn encode_train_same_equal(fid: u16, payloads: &[&[u8]], limit: usize) -> Option<Bytes> {
    let total = train_same_equal_len(fid, payloads)?;
    if total > limit {
        return None;
    }
    let item_len = payloads.first()?.len();
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_TRAIN | (TRAIN_FORM_SAME_EQUAL << TRAIN_FORM_SHIFT));
    put_u16(&mut v, fid);
    v.push(payloads.len() as u8);
    // See `encode_train_same`: the writer must run in every profile.
    let wrote = put_item_len(&mut v, item_len);
    debug_assert!(
        wrote,
        "the item length was already bounded by train_same_equal_len"
    );
    for p in payloads {
        v.extend_from_slice(p);
    }
    debug_assert_eq!(v.len(), total);
    // See `encode_train_same`: never emit a frame whose bytes disagree with its
    // computed length.
    if v.len() != total {
        return None;
    }
    Some(Bytes::from(v))
}

/// Encode a `DICT` train: an inline flow dictionary plus indexed items.
pub fn encode_train_dict(flows: &[u16], items: &[(u8, &[u8])], limit: usize) -> Option<Bytes> {
    let total = train_dict_len(flows, items)?;
    if total > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.push(CLASS_TRAIN | (TRAIN_FORM_DICT << TRAIN_FORM_SHIFT));
    v.push(flows.len() as u8);
    v.push(items.len() as u8);
    for f in flows {
        put_u16(&mut v, *f);
    }
    for (idx, p) in items {
        v.push(*idx);
        // See `encode_train_same`: the writer must run in every profile.
        let wrote = put_item_len(&mut v, p.len());
        debug_assert!(
            wrote,
            "the item length was already bounded by train_dict_len"
        );
        v.extend_from_slice(p);
    }
    debug_assert_eq!(v.len(), total);
    // See `encode_train_same`: never emit a frame whose bytes disagree with its
    // computed length.
    if v.len() != total {
        return None;
    }
    Some(Bytes::from(v))
}

/// Decoded `TRAIN` header plus its item bytes.
///
/// The decoder validated the whole frame eagerly (every item length fits, every
/// `DICT` index is in range, the frame has no trailing bytes), so
/// [`Self::items`] only walks already-bounded slices.
#[derive(Debug, Clone)]
pub struct TrainFrame<'a> {
    /// Wire form: [`TRAIN_FORM_SAME`], [`TRAIN_FORM_SAME_EQUAL`] or
    /// [`TRAIN_FORM_DICT`].
    pub form: u8,
    /// Number of items (`1..=64`).
    pub count: u8,
    /// Number of distinct flows referenced: `1` for the single-flow forms, the
    /// wire `nfl` for `DICT`.
    pub nfl: u8,
    /// Shared item length for `SAME_EQUAL`; `0` for the other forms.
    pub item_len: usize,
    flows: [u16; MAX_TRAIN_ITEMS],
    items: &'a [u8],
}

impl<'a> TrainFrame<'a> {
    /// Iterate `(fid, payload)` pairs in wire order.
    #[must_use]
    pub fn items(&self) -> TrainItems<'a> {
        TrainItems {
            form: self.form,
            remaining: self.count,
            item_len: self.item_len,
            nfl: usize::from(self.nfl),
            flows: self.flows,
            items: self.items,
        }
    }

    /// The referenced flow ids, in wire order (`nfl` entries).
    #[must_use]
    pub fn flows(&self) -> &[u16] {
        &self.flows[..usize::from(self.nfl)]
    }

    /// Number of items in the frame.
    #[must_use]
    pub fn item_count(&self) -> usize {
        usize::from(self.count)
    }
}

/// Iterator over a decoded `TRAIN`'s `(fid, payload)` items.
///
/// The frame was validated by [`decode_train`], so iteration yields exactly
/// `count` items; a `None` from `next` before exhaustion would mean the decoder
/// and iterator disagree, which is a codec bug, not peer input.
pub struct TrainItems<'a> {
    form: u8,
    remaining: u8,
    item_len: usize,
    nfl: usize,
    flows: [u16; MAX_TRAIN_ITEMS],
    items: &'a [u8],
}

impl<'a> Iterator for TrainItems<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        match self.form {
            TRAIN_FORM_SAME => {
                let mut off = 0usize;
                let len = item_len_at(self.items, &mut off)?;
                let end = off.checked_add(len)?;
                let payload = self.items.get(off..end)?;
                self.items = &self.items[end..];
                Some((self.flows[0], payload))
            }
            TRAIN_FORM_SAME_EQUAL => {
                let payload = self.items.get(..self.item_len)?;
                self.items = &self.items[self.item_len..];
                Some((self.flows[0], payload))
            }
            TRAIN_FORM_DICT => {
                let idx = usize::from(*self.items.first()?);
                if idx >= self.nfl {
                    return None;
                }
                let mut off = 1usize;
                let len = item_len_at(self.items, &mut off)?;
                let end = off.checked_add(len)?;
                let payload = self.items.get(off..end)?;
                self.items = &self.items[end..];
                Some((self.flows[idx], payload))
            }
            _ => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize::from(self.remaining);
        (n, Some(n))
    }
}

impl ExactSizeIterator for TrainItems<'_> {}
impl std::iter::FusedIterator for TrainItems<'_> {}

/// Decode a `TRAIN` frame.
///
/// Validates the class, reserved bits, form, count, dictionary shape
/// (`nfl <= count`, distinct fids, in-range item indices), every item length,
/// and requires the frame to end exactly after the last item (no trailing
/// bytes).
pub fn decode_train(b: &[u8]) -> Result<TrainFrame<'_>, MqpError> {
    let b0 = *b.first().ok_or(MqpError::Malformed("empty r3 frame"))?;
    if b0 & CLASS_MASK != CLASS_TRAIN {
        return Err(MqpError::Malformed("bad r3 train kind"));
    }
    if b0 & TRAIN_RESERVED_MASK != 0 {
        return Err(MqpError::Malformed("bad r3 train reserved"));
    }
    let form = (b0 & TRAIN_FORM_MASK) >> TRAIN_FORM_SHIFT;
    let mut flows = [0u16; MAX_TRAIN_ITEMS];
    match form {
        TRAIN_FORM_SAME | TRAIN_FORM_SAME_EQUAL => {
            let mut off = 1usize;
            let fid = get_u16(b, &mut off)?;
            if !valid_fid(fid) {
                return Err(MqpError::Malformed("bad r3 train fid"));
            }
            let count = *b
                .get(off)
                .ok_or(MqpError::Malformed("short r3 train count"))?;
            off += 1;
            valid_train_count(usize::from(count))
                .ok_or(MqpError::Malformed("bad r3 train count"))?;
            flows[0] = fid;
            let item_len = if form == TRAIN_FORM_SAME_EQUAL {
                let n = get_item_len(b, &mut off)?;
                let body = usize::from(count)
                    .checked_mul(n)
                    .ok_or(MqpError::Malformed("r3 train items overflow"))?;
                let end = off
                    .checked_add(body)
                    .ok_or(MqpError::Malformed("r3 train items overflow"))?;
                if end > b.len() {
                    return Err(MqpError::Malformed("bad r3 train item length"));
                }
                if end != b.len() {
                    return Err(MqpError::Malformed("r3 train trailing bytes"));
                }
                n
            } else {
                // SAME: walk the (len, payload) pairs; they must fill the frame
                // exactly, so a truncated or trailing byte is rejected here.
                let mut p = off;
                for _ in 0..count {
                    let len = get_item_len(b, &mut p)?;
                    let end = p
                        .checked_add(len)
                        .ok_or(MqpError::Malformed("r3 train item overflow"))?;
                    if end > b.len() {
                        return Err(MqpError::Malformed("bad r3 train item length"));
                    }
                    p = end;
                }
                if p != b.len() {
                    return Err(MqpError::Malformed("r3 train trailing bytes"));
                }
                0
            };
            Ok(TrainFrame {
                form,
                count,
                nfl: 1,
                item_len,
                flows,
                items: &b[off..],
            })
        }
        TRAIN_FORM_DICT => {
            let mut off = 1usize;
            let nfl = *b
                .get(off)
                .ok_or(MqpError::Malformed("short r3 train nfl"))?;
            off += 1;
            let count = *b
                .get(off)
                .ok_or(MqpError::Malformed("short r3 train count"))?;
            off += 1;
            valid_train_count(usize::from(count))
                .ok_or(MqpError::Malformed("bad r3 train count"))?;
            if nfl == 0 || nfl > count {
                return Err(MqpError::Malformed("bad r3 train nfl"));
            }
            let nfl_usize = usize::from(nfl);
            for i in 0..nfl_usize {
                let fid = get_u16(b, &mut off)?;
                if !valid_fid(fid) || flows[..i].contains(&fid) {
                    return Err(MqpError::Malformed("bad r3 train dict fid"));
                }
                flows[i] = fid;
            }
            let items_start = off;
            let mut p = off;
            for _ in 0..count {
                let idx = *b.get(p).ok_or(MqpError::Malformed("short r3 train item"))?;
                p += 1;
                if usize::from(idx) >= nfl_usize {
                    return Err(MqpError::Malformed("bad r3 train item fid"));
                }
                let len = get_item_len(b, &mut p)?;
                let end = p
                    .checked_add(len)
                    .ok_or(MqpError::Malformed("r3 train item overflow"))?;
                if end > b.len() {
                    return Err(MqpError::Malformed("bad r3 train item length"));
                }
                p = end;
            }
            if p != b.len() {
                return Err(MqpError::Malformed("r3 train trailing bytes"));
            }
            Ok(TrainFrame {
                form,
                count,
                nfl,
                item_len: 0,
                flows,
                items: &b[items_start..],
            })
        }
        _ => Err(MqpError::Malformed("bad r3 train form")),
    }
}

// ---------------- FRAG ----------------

/// Borrowed view of a decoded `FRAG` frame.
///
/// `chunk_off` is where [`Self::chunk`] sits inside the buffer handed to
/// [`decode_frag`]; an owner of that buffer can use the pair to address the
/// chunk without copying it (the reassembler keeps out-of-order chunks as
/// offset views of the frame instead of owned copies).
#[derive(Debug, Clone, Copy)]
pub struct FragRef<'a> {
    /// Flow id; `None` for the `INLINE` form.
    pub fid: Option<u16>,
    /// Session id; present on `OPEN`/`OPEN_SRC`/`INLINE`.
    pub sess: Option<u32>,
    /// Binding address; present on every extended form.
    pub addr: Option<TargetAddrRef<'a>>,
    /// The carried address is a source (`SRC`/`OPEN_SRC`), not a target.
    pub src: bool,
    /// Datagram-instance id shared by all fragments of one payload.
    pub frag_id: u32,
    /// Fragment index, `0 <= idx < total`.
    pub idx: u8,
    /// Fragment count, `1..=MAX_FRAG_TOTAL`.
    pub total: u8,
    /// Offset of [`Self::chunk`] in the decoded buffer.
    pub chunk_off: usize,
    /// Fragment payload bytes (non-empty, `<= MAX_FRAG_BYTES`).
    pub chunk: &'a [u8],
}

/// Wire length of a steady `FRAG` frame (9-byte header + chunk).
#[must_use]
pub fn frag_steady_len(chunk_len: usize) -> usize {
    9 + chunk_len
}

/// Wire length of an `OPEN`/`OPEN_SRC` fragment (`9 + 4 + addr + chunk`).
#[must_use]
pub fn frag_open_len(addr_len: usize, chunk_len: usize) -> usize {
    13 + addr_len + chunk_len
}

/// Wire length of a `SRC` fragment (`9 + addr + chunk`).
#[must_use]
pub fn frag_src_len(addr_len: usize, chunk_len: usize) -> usize {
    9 + addr_len + chunk_len
}

/// Wire length of an `INLINE` fragment (`1 + 4 + 1 + 1 + 4 + addr + chunk`).
#[must_use]
pub fn frag_inline_len(addr_len: usize, chunk_len: usize) -> usize {
    11 + addr_len + chunk_len
}

/// Bounds shared by the `FRAG` encoder and decoder.
fn frag_meta_ok(idx: u8, total: u8, chunk: &[u8]) -> bool {
    (1..=MAX_FRAG_TOTAL).contains(&total)
        && idx < total
        && !chunk.is_empty()
        && chunk.len() <= MAX_FRAG_BYTES
}

/// Encode a steady `FRAG` frame.
pub fn encode_frag_steady(
    fid: u16,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_fid(fid) || !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let total_len = frag_steady_len(chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(CLASS_FRAG);
    put_u16(&mut v, fid);
    put_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

/// Encode an `OPEN` (`src == false`, client-owned fid) or `OPEN_SRC`
/// (`src == true`, server-owned fid) fragment; the first fragment of a flow
/// carries its binding context.
#[allow(clippy::too_many_arguments)]
pub fn encode_frag_open(
    fid: u16,
    sess: u32,
    addr: &TargetAddrRef<'_>,
    src: bool,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    let owner = if src {
        FidOwner::Server
    } else {
        FidOwner::Client
    };
    require_fid_owner(fid, owner, "r3 frag open fid owner").ok()?;
    if !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let header = addr.header().ok()?;
    let total_len = frag_open_len(header.len(), chunk.len());
    if total_len > limit {
        return None;
    }
    let flags = if src { FORM_OPEN_SRC } else { FORM_OPEN };
    let mut v = Vec::with_capacity(total_len);
    v.push(CLASS_FRAG | flags);
    put_u16(&mut v, fid);
    put_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    put_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

/// Encode a `SRC` fragment: rebind an existing flow to the actual source
/// address while fragmenting (no session id).
pub fn encode_frag_src(
    fid: u16,
    addr: &TargetAddrRef<'_>,
    frag_id: u32,
    idx: u8,
    total: u8,
    chunk: &[u8],
    limit: usize,
) -> Option<Bytes> {
    if !valid_fid(fid) || !frag_meta_ok(idx, total, chunk) {
        return None;
    }
    let header = addr.header().ok()?;
    let total_len = frag_src_len(header.len(), chunk.len());
    if total_len > limit {
        return None;
    }
    let mut v = Vec::with_capacity(total_len);
    v.push(CLASS_FRAG | FORM_SRC);
    put_u16(&mut v, fid);
    put_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    put_addr(&mut v, &header);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

/// Encode an `INLINE` fragment: session + target address, no flow id.
pub fn encode_frag_inline(
    sess: u32,
    addr: &TargetAddrRef<'_>,
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
    v.push(CLASS_FRAG | FORM_INLINE);
    put_u32(&mut v, frag_id);
    v.push(idx);
    v.push(total);
    put_u32(&mut v, sess);
    put_addr(&mut v, &header);
    v.extend_from_slice(chunk);
    debug_assert_eq!(v.len(), total_len);
    Some(Bytes::from(v))
}

/// Decode a `FRAG` frame.
///
/// Validates class, reserved bits, form/flag combination, fid ownership,
/// fragment bounds (`1 <= total <= 64`, `idx < total`), and the chunk
/// (non-empty, `<= MAX_FRAG_BYTES`). The chunk is the remainder of `b`.
pub fn decode_frag(b: &[u8]) -> Result<FragRef<'_>, MqpError> {
    let b0 = *b.first().ok_or(MqpError::Malformed("empty r3 frame"))?;
    if b0 & CLASS_MASK != CLASS_FRAG {
        return Err(MqpError::Malformed("bad r3 frag kind"));
    }
    let flags = ext_flags(b0, "bad r3 frag reserved")?;
    let mut off = 1usize;
    let (fid, src) = match flags {
        0 => {
            // Steady form: the binding is already installed.
            let fid = get_u16(b, &mut off)?;
            if !valid_fid(fid) {
                return Err(MqpError::Malformed("bad r3 frag fid"));
            }
            (Some(fid), false)
        }
        FORM_OPEN | FORM_OPEN_SRC => {
            let src = flags == FORM_OPEN_SRC;
            let fid = get_u16(b, &mut off)?;
            let owner = if src {
                FidOwner::Server
            } else {
                FidOwner::Client
            };
            require_fid_owner(fid, owner, "r3 frag open fid owner")?;
            (Some(fid), src)
        }
        FORM_SRC => {
            let fid = get_u16(b, &mut off)?;
            if !valid_fid(fid) {
                return Err(MqpError::Malformed("bad r3 frag fid"));
            }
            (Some(fid), true)
        }
        FORM_INLINE => (None, false),
        _ => return Err(MqpError::Malformed("bad r3 frag flags")),
    };
    let frag_id = get_u32(b, &mut off)?;
    let idx = *b.get(off).ok_or(MqpError::Malformed("short r3 frag idx"))?;
    let total = *b
        .get(off + 1)
        .ok_or(MqpError::Malformed("short r3 frag total"))?;
    off += 2;
    let (sess, addr) = match flags {
        FORM_OPEN | FORM_OPEN_SRC | FORM_INLINE => {
            let sess = get_u32(b, &mut off)?;
            let (addr, n) = TargetAddrRef::decode(&b[off..])?;
            off += n;
            (Some(sess), Some(addr))
        }
        FORM_SRC => {
            let (addr, n) = TargetAddrRef::decode(&b[off..])?;
            off += n;
            (None, Some(addr))
        }
        _ => (None, None),
    };
    let chunk = &b[off..];
    if !frag_meta_ok(idx, total, chunk) {
        return Err(MqpError::Malformed("bad r3 frag meta"));
    }
    Ok(FragRef {
        fid,
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

// ---------------- control messages ----------------

/// First byte the opener of the control stream writes, once, before the first
/// message: it distinguishes the control stream from a TCP-flow stream (whose
/// first byte is a valid address `atyp` of `0x01`/`0x03`/`0x04`). It is not
/// part of any control message.
pub const CTL_STREAM_MARKER: u8 = 0xFF;

/// `ASSOC_CLOSE` (`C->S`): the client closed a UDP association.
pub const CTL_ASSOC_CLOSE: u8 = 0x01;
/// `FLOW_CLOSE` (`both`): eager release of one flow.
pub const CTL_FLOW_CLOSE: u8 = 0x02;
/// `REJECT` (`S->C`): policy/table-full/DNS refusal of a flow.
pub const CTL_REJECT: u8 = 0x81;
/// `NEED_CONTEXT` (`both`): recovery hint; re-arm the binding for a flow.
pub const CTL_NEED_CONTEXT: u8 = 0x82;
/// `SESS_CLOSE` (`S->C`): the server reaped the session.
pub const CTL_SESS_CLOSE: u8 = 0x83;
/// `GOAWAY` (`S->C`): stop opening new flows on this connection.
pub const CTL_GOAWAY: u8 = 0x84;

/// A decoded control message.
///
/// Messages are idempotent and small; they ride the reliable control stream so
/// losing one is not possible, and they never carry payload data. `reason`
/// values are codec-opaque here (the policy layer defines them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtlMessage {
    /// `0x01`: association close for `sess`.
    AssocClose {
        /// UDP session id being closed.
        sess: u32,
        /// Opaque close reason.
        reason: u8,
    },
    /// `0x02`: eager flow release.
    FlowClose {
        /// Flow id being released.
        fid: u16,
        /// Opaque close reason.
        reason: u8,
    },
    /// `0x81`: server refusal of a flow.
    Reject {
        /// Flow id being refused.
        fid: u16,
        /// Opaque refusal reason (policy / table full / DNS).
        reason: u8,
    },
    /// `0x82`: ask the peer to re-send binding context for `fid`.
    NeedContext {
        /// Flow id whose binding must be re-armed.
        fid: u16,
    },
    /// `0x83`: server reaped `sess` (client must re-open lazily).
    SessClose {
        /// UDP session id being closed.
        sess: u32,
        /// Opaque close reason.
        reason: u8,
    },
    /// `0x84`: server asks the client to stop opening new flows here.
    Goaway,
}

impl CtlMessage {
    /// Wire message type byte.
    #[must_use]
    pub fn msg_type(&self) -> u8 {
        match self {
            CtlMessage::AssocClose { .. } => CTL_ASSOC_CLOSE,
            CtlMessage::FlowClose { .. } => CTL_FLOW_CLOSE,
            CtlMessage::Reject { .. } => CTL_REJECT,
            CtlMessage::NeedContext { .. } => CTL_NEED_CONTEXT,
            CtlMessage::SessClose { .. } => CTL_SESS_CLOSE,
            CtlMessage::Goaway => CTL_GOAWAY,
        }
    }

    /// Body length carried in the framing `len` field.
    #[must_use]
    pub fn body_len(&self) -> usize {
        match self {
            CtlMessage::AssocClose { .. } | CtlMessage::SessClose { .. } => 5,
            CtlMessage::FlowClose { .. } | CtlMessage::Reject { .. } => 3,
            CtlMessage::NeedContext { .. } => 2,
            CtlMessage::Goaway => 0,
        }
    }

    /// Total framed length: 3-byte header (`type`, `len`) plus the body.
    #[must_use]
    pub fn len(&self) -> usize {
        3 + self.body_len()
    }

    /// A control message is never zero bytes (the 3-byte header is always
    /// present); present so `len()` satisfies the lint convention.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Encode one control message (`type:u8 | len:u16le | body`).
///
/// Returns `None` only when a flow-id-carrying message names an id outside
/// `0..=FID_MAX` (the encoder must never emit a message its own decoder
/// rejects); all other fields are full-domain.
#[must_use]
pub fn encode_ctl_message(m: CtlMessage) -> Option<Bytes> {
    let fid_in_range = match m {
        CtlMessage::FlowClose { fid, .. }
        | CtlMessage::Reject { fid, .. }
        | CtlMessage::NeedContext { fid } => valid_fid(fid),
        _ => true,
    };
    if !fid_in_range {
        return None;
    }
    let total = m.len();
    let mut v = Vec::with_capacity(total);
    v.push(m.msg_type());
    put_u16(&mut v, m.body_len() as u16);
    match m {
        CtlMessage::AssocClose { sess, reason } | CtlMessage::SessClose { sess, reason } => {
            put_u32(&mut v, sess);
            v.push(reason);
        }
        CtlMessage::FlowClose { fid, reason } | CtlMessage::Reject { fid, reason } => {
            put_u16(&mut v, fid);
            v.push(reason);
        }
        CtlMessage::NeedContext { fid } => put_u16(&mut v, fid),
        CtlMessage::Goaway => {}
    }
    debug_assert_eq!(v.len(), total);
    Some(Bytes::from(v))
}

/// Decode one control message from a stream buffer.
///
/// Returns the message and the number of bytes consumed (`3 + len`). Bytes
/// after it are the next message, not an error: the control plane is a byte
/// stream and a read may coalesce several messages. Validates the length cap
/// ([`MAX_CTL_BODY`]), the exact body size the type requires, the flow-id
/// range, and the message type before slicing.
pub fn decode_ctl_message(b: &[u8]) -> Result<(CtlMessage, usize), MqpError> {
    if b.len() < 3 {
        return Err(MqpError::Malformed("short r3 ctl message"));
    }
    let ty = b[0];
    let len = usize::from(u16::from_le_bytes([b[1], b[2]]));
    if len > MAX_CTL_BODY {
        return Err(MqpError::Malformed("r3 ctl body too long"));
    }
    let end = 3 + len;
    if b.len() < end {
        return Err(MqpError::Malformed("truncated r3 ctl body"));
    }
    let body = &b[3..end];
    let msg = match ty {
        CTL_ASSOC_CLOSE => {
            let (sess, reason) = ctl_sess_reason(body)?;
            CtlMessage::AssocClose { sess, reason }
        }
        CTL_FLOW_CLOSE => {
            let (fid, reason) = ctl_fid_reason(body)?;
            CtlMessage::FlowClose { fid, reason }
        }
        CTL_REJECT => {
            let (fid, reason) = ctl_fid_reason(body)?;
            CtlMessage::Reject { fid, reason }
        }
        CTL_NEED_CONTEXT => {
            if body.len() != 2 {
                return Err(MqpError::Malformed("bad r3 ctl body len"));
            }
            let fid = u16::from_le_bytes([body[0], body[1]]);
            if !valid_fid(fid) {
                return Err(MqpError::Malformed("bad r3 ctl fid"));
            }
            CtlMessage::NeedContext { fid }
        }
        CTL_SESS_CLOSE => {
            let (sess, reason) = ctl_sess_reason(body)?;
            CtlMessage::SessClose { sess, reason }
        }
        CTL_GOAWAY => {
            if !body.is_empty() {
                return Err(MqpError::Malformed("bad r3 ctl body len"));
            }
            CtlMessage::Goaway
        }
        _ => return Err(MqpError::Malformed("bad r3 ctl type")),
    };
    Ok((msg, end))
}

/// Parse an `ASSOC_CLOSE`/`SESS_CLOSE` body: `sess:u32 | reason:u8`.
fn ctl_sess_reason(body: &[u8]) -> Result<(u32, u8), MqpError> {
    if body.len() != 5 {
        return Err(MqpError::Malformed("bad r3 ctl body len"));
    }
    Ok((
        u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
        body[4],
    ))
}

/// Parse a `FLOW_CLOSE`/`REJECT` body: `fid:u16 | reason:u8`.
fn ctl_fid_reason(body: &[u8]) -> Result<(u16, u8), MqpError> {
    if body.len() != 3 {
        return Err(MqpError::Malformed("bad r3 ctl body len"));
    }
    let fid = u16::from_le_bytes([body[0], body[1]]);
    if !valid_fid(fid) {
        return Err(MqpError::Malformed("bad r3 ctl fid"));
    }
    Ok((fid, body[2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    // ---------------- helpers ----------------

    /// `192.0.2.1:port` — 7-byte address header.
    fn v4(port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        ))
    }

    /// `[::1]:port` — 19-byte address header.
    fn v6(port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
    }

    /// Domain target — `4+L`-byte address header.
    fn dom(name: &'static str, port: u16) -> TargetAddrRef<'static> {
        TargetAddrRef::Domain(name, port)
    }

    fn addr_len(addr: &TargetAddrRef<'_>) -> usize {
        addr.header().expect("test address must be encodable").len()
    }

    /// Raw steady `FRAG` bytes with arbitrary fragment metadata.
    fn frag_raw(idx: u8, total: u8, chunk: &[u8]) -> Vec<u8> {
        let mut v = vec![0xC0, 0x05, 0x00, 0, 0, 0, 0, idx, total];
        v.extend_from_slice(chunk);
        v
    }

    /// Deterministic 64-bit LCG: the adversarial loops use no dev-dependency
    /// and replay identically on every run.
    struct Lcg(u64);

    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    /// Every strict header prefix must be rejected; the header alone must
    /// decode with an empty payload. (`DATA`/`FRAG` payloads are the rest of
    /// the datagram, so only the header region is truncation-sensitive.)
    fn assert_data_header_truncations(frame: &[u8], header_len: usize) {
        for n in 0..header_len {
            assert!(
                decode_data(&frame[..n]).is_err(),
                "DATA prefix {n} must be rejected"
            );
        }
        let r = decode_data(&frame[..header_len]).expect("header-only DATA must decode");
        assert!(r.payload.is_empty());
    }

    fn assert_frag_header_truncations(frame: &[u8], header_len: usize) {
        for n in 0..=header_len {
            assert!(
                decode_frag(&frame[..n]).is_err(),
                "FRAG prefix {n} must be rejected"
            );
        }
        let r = decode_frag(&frame[..=header_len]).expect("one chunk byte must decode");
        assert_eq!(r.chunk.len(), 1);
    }

    fn assert_train_prefixes_rejected(frame: &[u8]) {
        for n in 0..frame.len() {
            assert!(
                decode_train(&frame[..n]).is_err(),
                "TRAIN prefix {n} must be rejected"
            );
        }
    }

    fn assert_ctl_prefixes_rejected(frame: &[u8]) {
        for n in 0..frame.len() {
            assert!(
                decode_ctl_message(&frame[..n]).is_err(),
                "CTL prefix {n} must be rejected"
            );
        }
    }

    // ---------------- constants and classification ----------------

    #[test]
    fn constants_match_the_analysis_bounds() {
        assert_eq!(MAX_TRAIN_ITEMS, 64);
        assert_eq!(MAX_FLOWS_PER_CONN, 4096);
        assert_eq!(MAX_FLOWS_SESSION, 64);
        assert_eq!(MAX_FRAG_TOTAL, 64);
        assert_eq!(MAX_FRAG_BYTES, 8192);
        assert_eq!(MAX_REASSEMBLY, 8192);
        assert_eq!(MAX_FRAME_BYTES, 1472);
        assert_eq!(MAX_ADDR_LEN, AddrHeader::MAX_LEN);
        assert_eq!(MAX_ADDR_LEN, 1 + 1 + 255 + 2);
        assert_eq!(MAX_CTL_BODY, 64);
        assert_eq!(FIDS_PER_OWNER, 8192);
        assert_eq!(FID_MAX, 0x3FFF);
        assert_eq!(CLIENT_FID_MAX, 0x1FFF);
        assert_eq!(SERVER_FID_BASE, 0x2000);
        assert_eq!(CTL_STREAM_MARKER, 0xFF);
        // Two 8192-id halves exactly cover the 14-bit space.
        assert_eq!(
            FIDS_PER_OWNER * 2,
            usize::from(FID_MAX) + 1,
            "owner halves must tile the 14-bit id space"
        );
    }

    #[test]
    fn first_byte_classes_cover_every_byte() {
        assert_eq!(kind(&[]), None);
        assert!(!is_r3(&[]));
        for b0 in 0..=u8::MAX {
            let buf = [b0];
            let expect = match b0 & CLASS_MASK {
                CLASS_DATA => R3Kind::Data,
                CLASS_DATA_EXT => R3Kind::DataExt,
                CLASS_TRAIN => R3Kind::Train,
                _ => R3Kind::Frag,
            };
            assert_eq!(kind(&buf), Some(expect), "b0 = {b0:#04x}");
            assert!(is_r3(&buf), "every non-empty buffer classifies");
        }
    }

    /// The documented hazard: a steady `DATA` first byte is indistinguishable
    /// from a TCP-flow address `atyp`, and the control-stream marker (`0xFF`)
    /// lies in the `FRAG` class. `kind`/`is_r3` must therefore never classify
    /// reliable-stream bytes.
    #[test]
    fn tcp_stream_atyp_bytes_collide_with_valid_steady_data_frames() {
        for &(fid, first) in &[(0x0100u16, 0x01u8), (0x0300, 0x03), (0x0400, 0x04)] {
            let f = encode_data_steady(fid, b"x", 1500).unwrap();
            assert_eq!(f[0], first, "valid DATA header starts with an address atyp");
            assert_eq!(kind(&f), Some(R3Kind::Data));
            assert!(is_r3(&f));
            // …and it really is a well-formed r3 frame, not just a class byte.
            assert_eq!(decode_data(&f).unwrap().fid, Some(fid));
        }
        // 0xFF is reserved as the control-stream marker. It classifies as FRAG
        // by its top bits, but no valid FRAG header has reserved bits set.
        assert_eq!(kind(&[CTL_STREAM_MARKER]), Some(R3Kind::Frag));
        assert!(is_r3(&[CTL_STREAM_MARKER]));
        assert!(decode_frag(&[CTL_STREAM_MARKER]).is_err());
    }

    // ---------------- DATA ----------------

    #[test]
    fn data_steady_golden() {
        let d = encode_data_steady(0x0000, b"abc", 1500).unwrap();
        assert_eq!(&d[..], &[0x00, 0x00, b'a', b'b', b'c']);
        let d = encode_data_steady(0x0001, b"", 1500).unwrap();
        assert_eq!(&d[..], &[0x00, 0x01]);
        let d = encode_data_steady(0x1FFF, b"z", 1500).unwrap();
        assert_eq!(&d[..], &[0x1F, 0xFF, b'z']);
        let d = encode_data_steady(0x2000, b"z", 1500).unwrap();
        assert_eq!(&d[..], &[0x20, 0x00, b'z']);
        let d = encode_data_steady(0x3FFF, b"z", 1500).unwrap();
        assert_eq!(&d[..], &[0x3F, 0xFF, b'z']);
        assert_eq!(data_steady_len(0), 2);
        assert_eq!(data_steady_len(17), 19);
    }

    #[test]
    fn data_steady_roundtrips_every_fid() {
        for fid in 0..=FID_MAX {
            let d = encode_data_steady(fid, b"p", 1472).unwrap();
            assert_eq!(d.len(), 3);
            let r = decode_data(&d).unwrap();
            assert_eq!(r.fid, Some(fid));
            assert_eq!(r.sess, None);
            assert_eq!(r.addr, None);
            assert!(!r.src);
            assert_eq!(r.payload, b"p");
        }
        assert!(encode_data_steady(0x4000, b"", 1500).is_none());
        assert!(encode_data_steady(u16::MAX, b"", 1500).is_none());
    }

    #[test]
    fn data_open_golden_v4() {
        let d = encode_data_open(0x0005, 7, &v4(53), false, b"abc", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x41, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x35,
                b'a', b'b', b'c',
            ]
        );
        assert_eq!(d.len(), 17);
        assert_eq!(data_open_len(addr_len(&v4(53)), 3), 17);
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, Some(0x0005));
        assert_eq!(r.sess, Some(7));
        assert_eq!(r.addr, Some(v4(53)));
        assert!(!r.src);
        assert_eq!(r.payload, b"abc");
    }

    #[test]
    fn data_open_src_golden_v6_and_domain() {
        // OPEN_SRC (server-owned flow, source address) with v6 + max session.
        let d = encode_data_open(0x2000, u32::MAX, &v6(443), true, b"z", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x43, 0x00, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xBB, b'z',
            ]
        );
        assert_eq!(d.len(), 26 + 1);
        assert_eq!(data_open_len(addr_len(&v6(443)), 1), 26 + 1);
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, Some(0x2000));
        assert_eq!(r.sess, Some(u32::MAX));
        assert_eq!(r.addr, Some(v6(443)));
        assert!(r.src);
        assert_eq!(r.payload, b"z");

        // Domain + session 0.
        let d = encode_data_open(0x2001, 0, &dom("example.com", 53), true, b"d", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x43, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6D, 0x70,
                0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x35, b'd',
            ]
        );
        assert_eq!(d.len(), 11 + 11 + 1);
        assert_eq!(
            data_open_len(addr_len(&dom("example.com", 53)), 1),
            11 + 11 + 1
        );
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, Some(0x2001));
        assert_eq!(r.sess, Some(0));
        assert_eq!(r.addr, Some(dom("example.com", 53)));
        assert!(r.src);
        assert_eq!(r.payload, b"d");
    }

    #[test]
    fn data_src_golden_and_roundtrip() {
        let d = encode_data_src(0x0123, &v4(9), b"z", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x42, 0x23, 0x01, 0x01, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x09, b'z'
            ]
        );
        assert_eq!(d.len(), 11);
        assert_eq!(data_src_len(7, 1), 11);
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, Some(0x0123));
        assert_eq!(r.sess, None);
        assert_eq!(r.addr, Some(v4(9)));
        assert!(r.src);
        assert_eq!(r.payload, b"z");

        // A `SRC` rebind may name a server-owned flow (full-cone reply).
        let d = encode_data_src(0x2000, &v6(1), b"", 1500).unwrap();
        assert_eq!(data_src_len(19, 0), d.len());
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, Some(0x2000));
        assert!(r.src);
        assert!(r.payload.is_empty());
    }

    #[test]
    fn data_inline_golden_and_roundtrip() {
        let d = encode_data_inline(7, &dom("example.com", 53), b"", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x44, 0x07, 0x00, 0x00, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
                0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x35,
            ]
        );
        assert_eq!(d.len(), 20);
        assert_eq!(data_inline_len(15, 0), 20);
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, None);
        assert_eq!(r.sess, Some(7));
        assert_eq!(r.addr, Some(dom("example.com", 53)));
        assert!(!r.src);
        assert!(r.payload.is_empty());

        let d = encode_data_inline(u32::MAX, &v4(0), b"q", 1500).unwrap();
        assert_eq!(d.len(), 12 + 1);
        let r = decode_data(&d).unwrap();
        assert_eq!(r.fid, None);
        assert_eq!(r.sess, Some(u32::MAX));
        assert_eq!(r.addr, Some(v4(0)));
        assert_eq!(r.payload, b"q");
    }

    #[test]
    fn data_ext_roundtrips_all_address_and_session_variants() {
        let addrs = [v4(53), v4(0), v6(443), v6(0), dom("example.com", 53)];
        for addr in addrs {
            let alen = addr_len(&addr);
            for &sess in &[0u32, 1, u32::MAX] {
                for &fid in &[0u16, 0x1FFF] {
                    let d = encode_data_open(fid, sess, &addr, false, b"p", 1500).unwrap();
                    assert_eq!(d.len(), data_open_len(alen, 1));
                    let r = decode_data(&d).unwrap();
                    assert_eq!(r.fid, Some(fid));
                    assert_eq!(r.sess, Some(sess));
                    assert_eq!(r.addr, Some(addr));
                    assert!(!r.src);
                    assert_eq!(r.payload, b"p");

                    let d = encode_data_inline(sess, &addr, b"", 1500).unwrap();
                    assert_eq!(d.len(), data_inline_len(alen, 0));
                    let r = decode_data(&d).unwrap();
                    assert_eq!(r.fid, None);
                    assert_eq!(r.sess, Some(sess));
                    assert_eq!(r.addr, Some(addr));
                    assert!(r.payload.is_empty());
                }
                for &fid in &[0x2000u16, 0x3FFF] {
                    let d = encode_data_open(fid, sess, &addr, true, b"p", 1500).unwrap();
                    let r = decode_data(&d).unwrap();
                    assert_eq!(r.fid, Some(fid));
                    assert_eq!(r.sess, Some(sess));
                    assert_eq!(r.addr, Some(addr));
                    assert!(r.src);
                    assert_eq!(r.payload, b"p");
                }
            }
            for &fid in &[0u16, 0x1FFF, 0x2000, 0x3FFF] {
                let d = encode_data_src(fid, &addr, b"s", 1500).unwrap();
                assert_eq!(d.len(), data_src_len(alen, 1));
                let r = decode_data(&d).unwrap();
                assert_eq!(r.fid, Some(fid));
                assert_eq!(r.sess, None);
                assert_eq!(r.addr, Some(addr));
                assert!(r.src);
                assert_eq!(r.payload, b"s");
            }
        }
    }

    #[test]
    fn data_ext_owner_contract_is_enforced_both_ways() {
        // OPEN allocates a client id; OPEN_SRC allocates a server id.
        assert!(encode_data_open(0x2000, 1, &v4(53), false, b"", 1500).is_none());
        assert!(encode_data_open(0x0000, 1, &v4(53), true, b"", 1500).is_none());
        assert!(encode_data_open(0x1FFF, 1, &v4(53), false, b"", 1500).is_some());
        assert!(encode_data_open(0x3FFF, 1, &v4(53), true, b"", 1500).is_some());
        assert!(encode_data_open(0xFFFF, 1, &v4(53), false, b"", 1500).is_none());
        assert!(encode_data_open(0xFFFF, 1, &v4(53), true, b"", 1500).is_none());

        // The decoder rejects the same mis-owned ids.
        let open = encode_data_open(0x0005, 1, &v4(53), false, b"", 1500).unwrap();
        let mut bad = open.to_vec();
        bad[1] = 0x00;
        bad[2] = 0x20; // server-half fid in an OPEN
        assert!(decode_data(&bad).is_err());
        let open_src = encode_data_open(0x2005, 1, &v4(53), true, b"", 1500).unwrap();
        let mut bad = open_src.to_vec();
        bad[1] = 0x05;
        bad[2] = 0x00; // client-half fid in an OPEN_SRC
        assert!(decode_data(&bad).is_err());

        // SRC / steady / trains may name a flow of either owner.
        assert!(encode_data_src(0x0000, &v4(53), b"", 1500).is_some());
        assert!(encode_data_src(0x3FFF, &v4(53), b"", 1500).is_some());
    }

    #[test]
    fn data_malformed_matrix_does_not_panic() {
        // Empty / truncated class bytes.
        assert!(decode_data(&[]).is_err());
        assert!(decode_data(&[0x00]).is_err());
        assert!(decode_data(&[0x40]).is_err()); // ext with no flags
        assert!(decode_data(&[0x41]).is_err()); // missing fid
        assert!(decode_data(&[0x41, 0x05]).is_err()); // missing sess
        assert!(decode_data(&[0x41, 0x05, 0x00]).is_err());
        assert!(decode_data(&[0x41, 0x05, 0x00, 0, 0, 0, 0]).is_err()); // missing addr
        assert!(decode_data(&[0x41, 0x05, 0x00, 0, 0, 0, 0, 0x01]).is_err()); // short v4
        assert!(decode_data(&[0x42, 0x05, 0x00]).is_err()); // SRC missing addr
        assert!(decode_data(&[0x44]).is_err()); // INLINE missing sess
        assert!(decode_data(&[0x44, 1, 0, 0, 0]).is_err()); // INLINE missing addr
        // Reserved bits b0[5:4] must be zero.
        for b0 in [0x50u8, 0x60, 0x70] {
            assert!(decode_data(&[b0, 0, 0, 0]).is_err(), "reserved {b0:#04x}");
        }
        // Only the four documented forms are legal flag combinations.
        for b0 in [0x40u8, 0x45, 0x46, 0x47, 0x48, 0x4F] {
            assert!(decode_data(&[b0, 0, 0, 0]).is_err(), "flags {b0:#04x}");
        }
        // Wrong class for the decoder.
        for b0 in [0x80u8, 0x90, 0xC0, 0xC4] {
            assert!(decode_data(&[b0, 0, 0]).is_err(), "kind {b0:#04x}");
        }
        // fid outside the 14-bit space.
        assert!(
            decode_data(&[0x42, 0x00, 0x40, 0x01, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x35]).is_err()
        );
        // Truncated / bad domain address, bad atyp.
        assert!(decode_data(&[0x42, 0x05, 0x00, 0x03, 0x05, b'a']).is_err());
        assert!(decode_data(&[0x42, 0x05, 0x00, 0x07]).is_err());
        // A structurally valid frame carrying the unspecified v4 address is
        // refused by the address codec, not accepted.
        assert!(decode_data(&[0x42, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn data_header_truncations_are_rejected() {
        let cases = [
            (
                encode_data_open(0x0005, 7, &v4(53), false, b"abc", 1500)
                    .unwrap()
                    .to_vec(),
                data_open_len(7, 0),
            ),
            (
                encode_data_open(0x2005, u32::MAX, &v6(443), true, b"abc", 1500)
                    .unwrap()
                    .to_vec(),
                data_open_len(19, 0),
            ),
            (
                encode_data_src(0x0123, &dom("example.com", 53), b"abc", 1500)
                    .unwrap()
                    .to_vec(),
                data_src_len(15, 0),
            ),
            (
                encode_data_inline(7, &v4(53), b"abc", 1500)
                    .unwrap()
                    .to_vec(),
                data_inline_len(7, 0),
            ),
        ];
        for (frame, header_len) in cases {
            assert_data_header_truncations(&frame, header_len);
        }
        // Steady frames are exactly a 2-byte header; 0/1 bytes are rejected.
        assert!(decode_data(&[]).is_err());
        assert!(decode_data(&[0x00]).is_err());
        assert!(decode_data(&[0x00, 0x00]).unwrap().payload.is_empty());
    }

    #[test]
    fn data_payload_is_the_datagram_remainder() {
        // A steady frame's payload is every byte after the header, including
        // arbitrary bytes that might look like other frame classes.
        let r = decode_data(&[0x00, 0x05, 0xFF, 0x00, 0xC4, 0x80]).unwrap();
        assert_eq!(r.payload, &[0xFF, 0x00, 0xC4, 0x80]);
        // Same for the extended forms: appending bytes grows the payload.
        let base = encode_data_inline(1, &v4(53), b"", 1500).unwrap();
        let mut longer = base.to_vec();
        longer.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let r = decode_data(&longer).unwrap();
        assert_eq!(r.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
        // A zero-length UDP payload is legal in every data form.
        let d = encode_data_open(0x0000, 0, &v4(53), false, b"", 1500).unwrap();
        assert!(decode_data(&d).unwrap().payload.is_empty());
        let d = encode_data_src(0x3FFF, &v4(53), b"", 1500).unwrap();
        assert!(decode_data(&d).unwrap().payload.is_empty());
    }

    // ---------------- TRAIN ----------------

    #[test]
    fn train_same_golden() {
        let payloads: [&[u8]; 2] = [b"abc", b"de"];
        let d = encode_train_same(5, &payloads, 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x80, 0x05, 0x00, 0x02, 0x03, b'a', b'b', b'c', 0x02, b'd', b'e'
            ]
        );
        assert_eq!(d.len(), 11);
        assert_eq!(train_same_len(5, &payloads), Some(11));
        let t = decode_train(&d).unwrap();
        assert_eq!(t.form, TRAIN_FORM_SAME);
        assert_eq!(t.count, 2);
        assert_eq!(t.nfl, 1);
        assert_eq!(t.item_len, 0);
        assert_eq!(t.item_count(), 2);
        assert_eq!(t.flows(), &[5u16][..]);
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(5, &b"abc"[..]), (5, &b"de"[..])]
        );
        assert_eq!(t.items().len(), 2);

        // Zero-length items are legal.
        let payloads: [&[u8]; 3] = [b"", b"x", b""];
        let d = encode_train_same(0x2000, &payloads, 1500).unwrap();
        assert_eq!(&d[..], &[0x80, 0x00, 0x20, 0x03, 0x00, 0x01, b'x', 0x00]);
        let t = decode_train(&d).unwrap();
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(0x2000, &b""[..]), (0x2000, &b"x"[..]), (0x2000, &b""[..])]
        );

        // The `0xFF` escape keeps every payload length encodable up to u16.
        let big = vec![7u8; 300];
        let payloads: [&[u8]; 1] = [big.as_slice()];
        let d = encode_train_same(9, &payloads, 1500).unwrap();
        assert_eq!(&d[4..7], &[0xFF, 0x2C, 0x01]); // 300 = 0x012C
        assert_eq!(d.len(), 4 + 3 + 300);
        assert_eq!(train_same_len(9, &payloads), Some(d.len()));
        let t = decode_train(&d).unwrap();
        assert_eq!(t.items().next().unwrap(), (9, big.as_slice()));

        // 255 is the first escaped length; 254 stays one byte.
        let p = vec![0u8; 255];
        let payloads: [&[u8]; 1] = [p.as_slice()];
        let d = encode_train_same(1, &payloads, 1500).unwrap();
        assert_eq!(&d[4..7], &[0xFF, 0xFF, 0x00]);
        let p = vec![0u8; 254];
        let payloads: [&[u8]; 1] = [p.as_slice()];
        let d = encode_train_same(1, &payloads, 1500).unwrap();
        assert_eq!(d[4], 254);
        assert_eq!(d.len(), 4 + 1 + 254);
    }

    #[test]
    fn train_same_equal_golden() {
        let payloads: [&[u8]; 3] = [b"ab", b"ab", b"ab"];
        let d = encode_train_same_equal(9, &payloads, 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0x90, 0x09, 0x00, 0x03, 0x02, b'a', b'b', b'a', b'b', b'a', b'b'
            ]
        );
        assert_eq!(d.len(), 11);
        assert_eq!(train_same_equal_len(9, &payloads), Some(11));
        let t = decode_train(&d).unwrap();
        assert_eq!(t.form, TRAIN_FORM_SAME_EQUAL);
        assert_eq!(t.count, 3);
        assert_eq!(t.nfl, 1);
        assert_eq!(t.item_len, 2);
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(9, &b"ab"[..]), (9, &b"ab"[..]), (9, &b"ab"[..])]
        );

        // Zero-length items: the whole frame is the 5-byte header.
        let payloads: [&[u8]; 4] = [b"", b"", b"", b""];
        let d = encode_train_same_equal(1, &payloads, 1500).unwrap();
        assert_eq!(&d[..], &[0x90, 0x01, 0x00, 0x04, 0x00]);
        let t = decode_train(&d).unwrap();
        assert_eq!(t.item_len, 0);
        assert_eq!(t.items().count(), 4);
        assert!(t.items().all(|(fid, p)| fid == 1 && p.is_empty()));

        // Escaped shared length; the earlier frame is still usable.
        assert_eq!(t.item_count(), 4);
        let big = vec![1u8; 300];
        let payloads: [&[u8]; 2] = [big.as_slice(), big.as_slice()];
        let d = encode_train_same_equal(1, &payloads, 2000).unwrap();
        assert_eq!(&d[0..7], &[0x90, 0x01, 0x00, 0x02, 0xFF, 0x2C, 0x01]);
        assert_eq!(d.len(), 4 + 3 + 600);
        let t = decode_train(&d).unwrap();
        assert_eq!(t.item_len, 300);
        assert_eq!(t.items().count(), 2);

        // Mixed lengths can never be a SAME_EQUAL frame: the encoder refuses.
        let payloads: [&[u8]; 2] = [b"a", b"bb"];
        assert!(encode_train_same_equal(1, &payloads, 1500).is_none());
        assert!(train_same_equal_len(1, &payloads).is_none());
    }

    #[test]
    fn train_dict_golden() {
        let flows = [5u16, 9];
        let items: [(u8, &[u8]); 2] = [(0, b"abc"), (1, b"de")];
        let d = encode_train_dict(&flows, &items, 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0xA0, 0x02, 0x02, 0x05, 0x00, 0x09, 0x00, 0x00, 0x03, b'a', b'b', b'c', 0x01, 0x02,
                b'd', b'e',
            ]
        );
        assert_eq!(d.len(), 16);
        assert_eq!(train_dict_len(&flows, &items), Some(16));
        let t = decode_train(&d).unwrap();
        assert_eq!(t.form, TRAIN_FORM_DICT);
        assert_eq!(t.count, 2);
        assert_eq!(t.nfl, 2);
        assert_eq!(t.item_len, 0);
        assert_eq!(t.flows(), &[5u16, 9][..]);
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(5, &b"abc"[..]), (9, &b"de"[..])]
        );

        // Zero-length items and repeated dictionary flows are legal.
        let flows = [0x2000u16, 0x1FFF];
        let items: [(u8, &[u8]); 3] = [(0, b""), (1, b"x"), (0, b"")];
        let d = encode_train_dict(&flows, &items, 1500).unwrap();
        let t = decode_train(&d).unwrap();
        assert_eq!(
            t.items().collect::<Vec<_>>(),
            vec![(0x2000, &b""[..]), (0x1FFF, &b"x"[..]), (0x2000, &b""[..])]
        );

        // Minimal dictionary: one flow, one empty item.
        assert!(decode_train(&[0xA0, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00]).is_ok());
    }

    /// The length fields are written by a stateful helper, and a version of
    /// this encoder put that call inside `debug_assert!`: every multi-item
    /// `TRAIN` then shipped without its per-item length and the peer rejected
    /// it, silently dropping ~14% of a batched uplink in release builds. These
    /// shapes are the ones that regressed, checked byte-for-byte so the profile
    /// the test runs in cannot hide it.
    #[test]
    fn train_encoders_emit_every_length_field() {
        let big = [0x5Au8; 128];

        // DICT: `[idx][len][payload]` per item, len = 0x80 for 128 bytes.
        let flows = [3u16, 2];
        let items: [(u8, &[u8]); 2] = [(0, &big), (1, &big)];
        let d = encode_train_dict(&flows, &items, 4096).expect("dict train fits");
        assert_eq!(d.len(), train_dict_len(&flows, &items).unwrap());
        assert_eq!(d.len(), 3 + 4 + 2 * (1 + 1 + 128));
        assert_eq!(
            &d[..9],
            &[0xA0, 0x02, 0x02, 0x03, 0x00, 0x02, 0x00, 0x00, 0x80]
        );
        assert_eq!(decode_train(&d).unwrap().items().count(), 2);

        // SAME: one shared flow, one length per item.
        let refs: [&[u8]; 2] = [&big, &big];
        let d = encode_train_same(7, &refs, 4096).expect("same train fits");
        assert_eq!(d.len(), train_same_len(7, &refs).unwrap());
        assert_eq!(
            &d[..10],
            &[0x80, 0x07, 0x00, 0x02, 0x80, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A]
        );
        assert_eq!(decode_train(&d).unwrap().items().count(), 2);

        // SAME_EQUAL: the length lives once in the header.
        let d = encode_train_same_equal(7, &refs, 4096).expect("same-equal train fits");
        assert_eq!(d.len(), train_same_equal_len(7, &refs).unwrap());
        assert_eq!(&d[..6], &[0x90, 0x07, 0x00, 0x02, 0x80, 0x5A]);
        assert_eq!(decode_train(&d).unwrap().items().count(), 2);
    }

    #[test]
    fn train_counts_1_8_and_64_roundtrip() {
        for &count in &[1usize, 8, MAX_TRAIN_ITEMS] {
            // SAME: heterogeneous lengths, including zero.
            let payloads: Vec<&[u8]> = (0..count)
                .map(|i| match i % 3 {
                    0 => &b""[..],
                    1 => &b"x"[..],
                    _ => &b"yy"[..],
                })
                .collect();
            let d = encode_train_same(0x0ABC, &payloads, 20_000).unwrap();
            let t = decode_train(&d).unwrap();
            assert_eq!(usize::from(t.count), count);
            let got: Vec<(u16, &[u8])> = t.items().collect();
            assert_eq!(got.len(), count);
            for (i, (fid, p)) in got.iter().enumerate() {
                assert_eq!(*fid, 0x0ABC);
                assert_eq!(p.len(), payloads[i].len());
            }

            // SAME_EQUAL: all 4-byte payloads.
            let payloads: Vec<&[u8]> = (0..count).map(|_| &b"item"[..]).collect();
            let d = encode_train_same_equal(0x2000, &payloads, 20_000).unwrap();
            let t = decode_train(&d).unwrap();
            assert_eq!(usize::from(t.count), count);
            assert_eq!(t.item_len, 4);
            assert_eq!(t.items().count(), count);

            // DICT: one distinct flow per item.
            let flows: Vec<u16> = (0..count as u16).collect();
            let items: Vec<(u8, &[u8])> = (0..count).map(|i| (i as u8, &b"q"[..])).collect();
            let d = encode_train_dict(&flows, &items, 20_000).unwrap();
            let t = decode_train(&d).unwrap();
            assert_eq!(usize::from(t.count), count);
            assert_eq!(usize::from(t.nfl), count);
            assert_eq!(t.flows().len(), count);
            let got: Vec<(u16, &[u8])> = t.items().collect();
            assert_eq!(got.len(), count);
        }
    }

    #[test]
    fn train_item_length_encoding_escapes_at_255() {
        assert_eq!(item_len_len(0), Some(1));
        assert_eq!(item_len_len(254), Some(1));
        assert_eq!(item_len_len(255), Some(3));
        assert_eq!(item_len_len(u16::MAX as usize), Some(3));
        assert_eq!(item_len_len(u16::MAX as usize + 1), None);

        // An item that cannot be length-prefixed is refused by the encoders.
        let huge = vec![0u8; u16::MAX as usize + 1];
        let payloads: [&[u8]; 1] = [huge.as_slice()];
        assert!(train_same_len(1, &payloads).is_none());
        assert!(encode_train_same(1, &payloads, usize::MAX).is_none());

        // Non-canonical escape of a short length is accepted on decode (the
        // representation is unambiguous); encoders never emit it.
        let t = decode_train(&[0x80, 0x05, 0x00, 0x01, 0xFF, 0x00, 0x00]).unwrap();
        let items: Vec<(u16, &[u8])> = t.items().collect();
        assert_eq!(items, vec![(5, &b""[..])]);
    }

    #[test]
    fn train_encoder_rejects_bad_shapes() {
        // Counts outside 1..=64.
        let empty: [&[u8]; 0] = [];
        assert!(encode_train_same(5, &empty, 1500).is_none());
        assert!(encode_train_same_equal(5, &empty, 1500).is_none());
        let too_many: Vec<&[u8]> = (0..MAX_TRAIN_ITEMS + 1).map(|_| &b"q"[..]).collect();
        assert!(encode_train_same(5, &too_many, 20_000).is_none());
        assert!(encode_train_same_equal(5, &too_many, 20_000).is_none());

        // Out-of-range fids.
        let one: [&[u8]; 1] = [b"x"];
        assert!(encode_train_same(0x4000, &one, 1500).is_none());
        assert!(encode_train_same(u16::MAX, &one, 1500).is_none());
        assert!(encode_train_same_equal(0x4000, &one, 1500).is_none());

        // DICT shape rules: non-empty, nfl <= count, distinct fids, idx<nfl.
        let items: [(u8, &[u8]); 1] = [(0, b"x")];
        assert!(encode_train_dict(&[], &items, 1500).is_none());
        let flows = [5u16, 9];
        assert!(encode_train_dict(&flows, &items, 1500).is_none()); // nfl > count
        let flows = [5u16, 5];
        let items2: [(u8, &[u8]); 2] = [(0, b"x"), (1, b"y")];
        assert!(encode_train_dict(&flows, &items2, 1500).is_none()); // duplicate
        let flows = [5u16];
        let items2: [(u8, &[u8]); 2] = [(0, b"x"), (1, b"y")];
        assert!(encode_train_dict(&flows, &items2, 1500).is_none()); // idx out of range
        let flows = [0x4000u16];
        assert!(encode_train_dict(&flows, &items, 1500).is_none());
    }

    #[test]
    fn train_malformed_matrix_does_not_panic() {
        assert!(decode_train(&[]).is_err());
        assert!(decode_train(&[0x80]).is_err());
        assert!(decode_train(&[0x80, 0x05]).is_err());
        assert!(decode_train(&[0x80, 0x05, 0x00]).is_err()); // missing count
        // Count 0 / 65.
        assert!(decode_train(&[0x80, 0x05, 0x00, 0x00]).is_err());
        assert!(decode_train(&[0x80, 0x05, 0x00, 0x41]).is_err());
        // Form 3 does not exist; reserved nibble must be zero.
        assert!(decode_train(&[0xB0, 0x05, 0x00, 0x01, 0x00]).is_err());
        assert!(decode_train(&[0x81, 0x05, 0x00, 0x01, 0x00]).is_err());
        // Out-of-range fid.
        assert!(decode_train(&[0x80, 0x00, 0x40, 0x01, 0x00]).is_err());
        // SAME item length overrun / trailing bytes / missing length.
        assert!(decode_train(&[0x80, 0x05, 0x00, 0x01, 0x05, b'x']).is_err());
        assert!(decode_train(&[0x80, 0x05, 0x00, 0x01, 0x01, b'x', b'y']).is_err());
        assert!(decode_train(&[0x80, 0x05, 0x00, 0x01]).is_err());
        // SAME_EQUAL: missing shared length, short body, trailing bytes.
        assert!(decode_train(&[0x90, 0x05, 0x00, 0x01]).is_err());
        assert!(decode_train(&[0x90, 0x05, 0x00, 0x01, 0x02, b'a']).is_err());
        assert!(decode_train(&[0x90, 0x05, 0x00, 0x02, 0x02, b'a']).is_err());
        assert!(
            decode_train(&[0x90, 0x05, 0x00, 0x01, 0x01, b'a', b'b']).is_err(),
            "SAME_EQUAL trailing byte"
        );
        // DICT: missing fields, nfl 0 / > count, duplicate fids, idx >= nfl,
        // item overrun, trailing bytes, truncated fid table.
        assert!(decode_train(&[0xA0]).is_err());
        assert!(decode_train(&[0xA0, 0x01]).is_err());
        assert!(decode_train(&[0xA0, 0x01, 0x00]).is_err()); // count 0
        assert!(decode_train(&[0xA0, 0x00, 0x01]).is_err()); // nfl 0
        assert!(decode_train(&[0xA0, 0x02, 0x01, 0x05, 0x00, 0x09, 0x00]).is_err()); // nfl > count
        assert!(
            decode_train(&[
                0xA0, 0x02, 0x02, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00
            ])
            .is_err(),
            "duplicate fids"
        );
        assert!(decode_train(&[0xA0, 0x01, 0x01, 0x05, 0x00, 0x01, 0x00]).is_err()); // idx >= nfl
        assert!(decode_train(&[0xA0, 0x01, 0x01, 0x05, 0x00, 0x00, 0x05, b'x']).is_err());
        assert!(
            decode_train(&[0xA0, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, b'z']).is_err(),
            "DICT trailing byte"
        );
        assert!(decode_train(&[0xA0, 0x01, 0x01, 0x05]).is_err()); // truncated fid table
        // Wrong class.
        assert!(decode_train(&[0x00, 0x00]).is_err());
        assert!(decode_train(&[0xC0, 0x05, 0x00, 0, 0, 0, 0, 0, 1, b'x']).is_err());
    }

    #[test]
    fn train_truncations_are_rejected() {
        // TRAIN has an exact frame size: every strict prefix is malformed.
        let same: [&[u8]; 3] = [b"", b"x", b"yz"];
        assert_train_prefixes_rejected(&encode_train_same(5, &same, 1500).unwrap());
        let equal: [&[u8]; 2] = [b"ab", b"ab"];
        assert_train_prefixes_rejected(&encode_train_same_equal(5, &equal, 1500).unwrap());
        let flows = [5u16, 9];
        let items: [(u8, &[u8]); 2] = [(0, b""), (1, b"x")];
        assert_train_prefixes_rejected(&encode_train_dict(&flows, &items, 1500).unwrap());
    }

    #[test]
    fn train_items_iterator_is_exact_and_count_based() {
        let payloads: [&[u8]; 2] = [b"", b"x"];
        let d = encode_train_same(5, &payloads, 1500).unwrap();
        let t = decode_train(&d).unwrap();
        let mut it = t.items();
        assert_eq!(it.len(), 2);
        assert_eq!(it.size_hint(), (2, Some(2)));
        assert_eq!(it.next(), Some((5, &b""[..])));
        assert_eq!(it.len(), 1);
        assert_eq!(it.next(), Some((5, &b"x"[..])));
        assert_eq!(it.len(), 0);
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None, "iterator is fused");
        // The frame can hand out fresh iterators; a zero-length SAME_EQUAL
        // frame must still yield `count` items (count-based, not byte-based).
        assert_eq!(t.items().count(), 2);
        let payloads: [&[u8]; 4] = [b"", b"", b"", b""];
        let d = encode_train_same_equal(6, &payloads, 1500).unwrap();
        let t = decode_train(&d).unwrap();
        assert_eq!(t.items().count(), 4);
        assert_eq!(t.flows(), &[6u16][..]);
    }

    // ---------------- FRAG ----------------

    #[test]
    fn frag_steady_golden() {
        let d = encode_frag_steady(5, 0x1234_5678, 1, 3, b"abc", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0xC0, 0x05, 0x00, 0x78, 0x56, 0x34, 0x12, 0x01, 0x03, b'a', b'b', b'c'
            ]
        );
        assert_eq!(d.len(), 12);
        assert_eq!(frag_steady_len(3), 12);
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.fid, Some(5));
        assert_eq!(r.sess, None);
        assert_eq!(r.addr, None);
        assert!(!r.src);
        assert_eq!(r.frag_id, 0x1234_5678);
        assert_eq!((r.idx, r.total), (1, 3));
        assert_eq!(r.chunk_off, 9);
        assert_eq!(r.chunk, b"abc");
        assert_eq!(&d[r.chunk_off..], r.chunk);
    }

    #[test]
    fn frag_open_golden_and_roundtrip() {
        let d = encode_frag_open(5, 7, &v4(53), false, 9, 0, 2, b"qq", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0xC1, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x01,
                0xC0, 0x00, 0x02, 0x01, 0x00, 0x35, b'q', b'q',
            ]
        );
        assert_eq!(d.len(), 22);
        assert_eq!(frag_open_len(7, 2), 22);
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.fid, Some(5));
        assert_eq!(r.sess, Some(7));
        assert_eq!(r.addr, Some(v4(53)));
        assert!(!r.src);
        assert_eq!(r.frag_id, 9);
        assert_eq!((r.idx, r.total), (0, 2));
        assert_eq!(r.chunk_off, 20);
        assert_eq!(r.chunk, b"qq");
        assert_eq!(&d[r.chunk_off..], r.chunk);
    }

    #[test]
    fn frag_src_golden_and_roundtrip() {
        let d = encode_frag_src(0x0123, &v4(9), 0xABCD_EF01, 1, 4, b"chunk", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0xC2, 0x23, 0x01, 0x01, 0xEF, 0xCD, 0xAB, 0x01, 0x04, 0x01, 0xC0, 0x00, 0x02, 0x01,
                0x00, 0x09, b'c', b'h', b'u', b'n', b'k',
            ]
        );
        assert_eq!(d.len(), 21);
        assert_eq!(frag_src_len(7, 5), 21);
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.fid, Some(0x0123));
        assert_eq!(r.sess, None);
        assert_eq!(r.addr, Some(v4(9)));
        assert!(r.src);
        assert_eq!(r.frag_id, 0xABCD_EF01);
        assert_eq!((r.idx, r.total), (1, 4));
        assert_eq!(r.chunk_off, 16);
        assert_eq!(r.chunk, b"chunk");
    }

    #[test]
    fn frag_inline_golden_and_roundtrip() {
        let d = encode_frag_inline(7, &v4(53), 1, 0, 1, b"x", 1500).unwrap();
        assert_eq!(
            &d[..],
            &[
                0xC4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x00, 0x00, 0x00, 0x01, 0xC0, 0x00,
                0x02, 0x01, 0x00, 0x35, b'x',
            ]
        );
        assert_eq!(d.len(), 19);
        assert_eq!(frag_inline_len(7, 1), 19);
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.fid, None);
        assert_eq!(r.sess, Some(7));
        assert_eq!(r.addr, Some(v4(53)));
        assert!(!r.src);
        assert_eq!(r.frag_id, 1);
        assert_eq!((r.idx, r.total), (0, 1));
        assert_eq!(r.chunk_off, 18);
        assert_eq!(r.chunk, b"x");
    }

    #[test]
    fn frag_ext_roundtrips_all_address_variants() {
        let addrs = [v4(53), v6(443), dom("example.com", 53)];
        for addr in addrs {
            let alen = addr_len(&addr);
            // OPEN (client-owned).
            let d = encode_frag_open(0x0001, 9, &addr, false, 0x0102_0304, 1, 2, b"frag", 1500)
                .unwrap();
            assert_eq!(d.len(), frag_open_len(alen, 4));
            let r = decode_frag(&d).unwrap();
            assert_eq!(r.fid, Some(0x0001));
            assert_eq!(r.sess, Some(9));
            assert_eq!(r.addr, Some(addr));
            assert!(!r.src);
            assert_eq!(r.frag_id, 0x0102_0304);
            assert_eq!((r.idx, r.total), (1, 2));
            assert_eq!(r.chunk_off, 13 + alen);
            assert_eq!(r.chunk, b"frag");

            // OPEN_SRC (server-owned). A fragment always carries a non-empty
            // chunk, so the payload here is one byte rather than empty.
            let d = encode_frag_open(0x2000, u32::MAX, &addr, true, 0xDEAD_BEEF, 0, 1, b"z", 1500)
                .unwrap();
            assert_eq!(d.len(), frag_open_len(alen, 1));
            let r = decode_frag(&d).unwrap();
            assert_eq!(r.fid, Some(0x2000));
            assert_eq!(r.sess, Some(u32::MAX));
            assert_eq!(r.addr, Some(addr));
            assert!(r.src);
            assert_eq!(r.frag_id, 0xDEAD_BEEF);
            assert_eq!(r.chunk_off, 13 + alen);
            assert_eq!(r.chunk, b"z");

            // SRC rebind (either owner half).
            for &fid in &[0u16, 0x1FFF, 0x2000, 0x3FFF] {
                let d = encode_frag_src(fid, &addr, 1, 3, 4, b"c", 1500).unwrap();
                assert_eq!(d.len(), frag_src_len(alen, 1));
                let r = decode_frag(&d).unwrap();
                assert_eq!(r.fid, Some(fid));
                assert_eq!(r.sess, None);
                assert_eq!(r.addr, Some(addr));
                assert!(r.src);
                assert_eq!(r.chunk_off, 9 + alen);
            }

            // INLINE.
            let d = encode_frag_inline(3, &addr, 4, 0, 1, b"i", 1500).unwrap();
            assert_eq!(d.len(), frag_inline_len(alen, 1));
            let r = decode_frag(&d).unwrap();
            assert_eq!(r.fid, None);
            assert_eq!(r.sess, Some(3));
            assert_eq!(r.addr, Some(addr));
            assert_eq!(r.chunk_off, 11 + alen);
        }
    }

    #[test]
    fn frag_owner_contract_is_enforced_both_ways() {
        assert!(encode_frag_open(0x2000, 1, &v4(53), false, 1, 0, 1, b"x", 1500).is_none());
        assert!(encode_frag_open(0x0000, 1, &v4(53), true, 1, 0, 1, b"x", 1500).is_none());
        assert!(encode_frag_open(0x1FFF, 1, &v4(53), false, 1, 0, 1, b"x", 1500).is_some());
        assert!(encode_frag_open(0x3FFF, 1, &v4(53), true, 1, 0, 1, b"x", 1500).is_some());

        let open = encode_frag_open(5, 7, &v4(53), false, 1, 0, 1, b"x", 1500).unwrap();
        let mut bad = open.to_vec();
        bad[1] = 0x00;
        bad[2] = 0x20; // server fid in OPEN
        assert!(decode_frag(&bad).is_err());
        let open_src = encode_frag_open(0x2005, 7, &v4(53), true, 1, 0, 1, b"x", 1500).unwrap();
        let mut bad = open_src.to_vec();
        bad[1] = 0x05;
        bad[2] = 0x00; // client fid in OPEN_SRC
        assert!(decode_frag(&bad).is_err());
    }

    #[test]
    fn frag_bounds_are_enforced() {
        // Encoder-side fragment bounds.
        assert!(encode_frag_steady(5, 1, 0, 0, b"x", 1500).is_none()); // total 0
        assert!(encode_frag_steady(5, 1, 0, 65, b"x", 1500).is_none()); // total 65
        assert!(encode_frag_steady(5, 1, 1, 1, b"x", 1500).is_none()); // idx >= total
        assert!(encode_frag_steady(5, 1, 0, 1, b"", 1500).is_none()); // empty chunk
        assert!(encode_frag_steady(5, 1, 63, 64, b"x", 1500).is_some());
        assert!(encode_frag_steady(0x4000, 1, 0, 1, b"x", 1500).is_none());

        // Decoder-side fragment bounds.
        assert!(decode_frag(&frag_raw(0, 0, b"x")).is_err());
        assert!(decode_frag(&frag_raw(0, 65, b"x")).is_err());
        assert!(decode_frag(&frag_raw(1, 1, b"x")).is_err());
        assert!(decode_frag(&frag_raw(2, 2, b"x")).is_err());
        assert!(decode_frag(&frag_raw(0, 1, b"")).is_err());
        assert!(decode_frag(&frag_raw(0, 64, b"x")).is_ok());
        assert!(decode_frag(&frag_raw(63, 64, b"x")).is_ok());
        let mut out_of_range = frag_raw(0, 1, b"x");
        out_of_range[1] = 0x00;
        out_of_range[2] = 0x40; // fid 0x4000
        assert!(decode_frag(&out_of_range).is_err());
    }

    #[test]
    fn frag_malformed_matrix_does_not_panic() {
        assert!(decode_frag(&[]).is_err());
        assert!(decode_frag(&[0xC0]).is_err());
        assert!(decode_frag(&[0xC0, 0x05]).is_err());
        assert!(decode_frag(&[0xC0, 0x05, 0x00, 0, 0, 0, 0]).is_err());
        assert!(decode_frag(&[0xC4]).is_err()); // INLINE missing frag_id
        assert!(decode_frag(&[0xC1]).is_err()); // OPEN missing fid
        // Reserved bits must be zero; only the four forms are legal flags.
        for b0 in [0xD0u8, 0xE0, 0xF0] {
            assert!(decode_frag(&[b0, 0, 0]).is_err(), "reserved {b0:#04x}");
        }
        for b0 in [0xC5u8, 0xC6, 0xC7, 0xCF] {
            assert!(decode_frag(&[b0, 0, 0]).is_err(), "flags {b0:#04x}");
        }
        // Wrong class.
        for b0 in [0x00u8, 0x41, 0x80, 0xA0] {
            assert!(decode_frag(&[b0, 0, 0]).is_err(), "kind {b0:#04x}");
        }
    }

    #[test]
    fn frag_header_truncations_are_rejected() {
        let cases = [
            (
                encode_frag_steady(5, 1, 0, 2, b"xy", 1500)
                    .unwrap()
                    .to_vec(),
                frag_steady_len(0),
            ),
            (
                encode_frag_open(5, 7, &v4(53), false, 1, 0, 2, b"xy", 1500)
                    .unwrap()
                    .to_vec(),
                frag_open_len(7, 0),
            ),
            (
                encode_frag_src(5, &v6(9), 1, 0, 2, b"xy", 1500)
                    .unwrap()
                    .to_vec(),
                frag_src_len(19, 0),
            ),
            (
                encode_frag_inline(7, &dom("example.com", 53), 1, 0, 2, b"xy", 1500)
                    .unwrap()
                    .to_vec(),
                frag_inline_len(15, 0),
            ),
        ];
        for (frame, header_len) in cases {
            assert_frag_header_truncations(&frame, header_len);
        }
    }

    #[test]
    fn frag_chunk_cap_is_independent_of_frame_budget() {
        let chunk = vec![0u8; MAX_FRAG_BYTES];
        let need = frag_steady_len(chunk.len());
        let d = encode_frag_steady(1, 1, 0, 1, &chunk, need).unwrap();
        let r = decode_frag(&d).unwrap();
        assert_eq!(r.chunk.len(), MAX_FRAG_BYTES);

        let too_big = vec![0u8; MAX_FRAG_BYTES + 1];
        assert!(encode_frag_steady(1, 1, 0, 1, &too_big, usize::MAX).is_none());
        let mut raw = vec![0xC0, 0x01, 0x00, 0, 0, 0, 0, 0, 1];
        raw.extend_from_slice(&too_big);
        assert!(decode_frag(&raw).is_err());
    }

    // ---------------- control messages ----------------

    #[test]
    fn ctl_golden_and_roundtrip() {
        let cases: [(CtlMessage, &[u8]); 6] = [
            (
                CtlMessage::AssocClose { sess: 7, reason: 1 },
                &[0x01, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01],
            ),
            (
                CtlMessage::FlowClose { fid: 5, reason: 2 },
                &[0x02, 0x03, 0x00, 0x05, 0x00, 0x02],
            ),
            (
                CtlMessage::Reject {
                    fid: 0x2000,
                    reason: 3,
                },
                &[0x81, 0x03, 0x00, 0x00, 0x20, 0x03],
            ),
            (
                CtlMessage::NeedContext { fid: 0x1FFF },
                &[0x82, 0x02, 0x00, 0xFF, 0x1F],
            ),
            (
                CtlMessage::SessClose {
                    sess: 0xDEAD_BEEF,
                    reason: 9,
                },
                &[0x83, 0x05, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x09],
            ),
            (CtlMessage::Goaway, &[0x84, 0x00, 0x00]),
        ];
        for (m, golden) in cases {
            let d = encode_ctl_message(m).expect("valid control message");
            assert_eq!(&d[..], golden, "golden bytes for {m:?}");
            assert_eq!(d.len(), m.len());
            assert_eq!(m.len(), 3 + m.body_len());
            assert!(!m.is_empty());
            assert_eq!(m.msg_type(), d[0]);
            let (got, used) = decode_ctl_message(&d).unwrap();
            assert_eq!(got, m);
            assert_eq!(used, d.len());
        }
    }

    #[test]
    fn ctl_stream_framing_consumes_exactly_one_message() {
        let msgs = [
            CtlMessage::AssocClose { sess: 7, reason: 1 },
            CtlMessage::Goaway,
            CtlMessage::NeedContext { fid: 0x1FFF },
            CtlMessage::SessClose {
                sess: u32::MAX,
                reason: 0,
            },
        ];
        let mut stream = Vec::new();
        for m in msgs {
            stream.extend_from_slice(&encode_ctl_message(m).unwrap());
        }
        let mut off = 0usize;
        for expect in msgs {
            let (got, used) = decode_ctl_message(&stream[off..]).unwrap();
            assert_eq!(got, expect);
            assert!((3..=MAX_CTL_BODY + 3).contains(&used));
            off += used;
        }
        assert_eq!(off, stream.len());
        // The 0xFF stream marker is not part of a message: as a lone byte it is
        // a truncated message, and it must be consumed by the stream classifier.
        assert!(decode_ctl_message(&[CTL_STREAM_MARKER]).is_err());
        // Trailing bytes after one message are the next message, not an error.
        let m = encode_ctl_message(CtlMessage::SessClose { sess: 1, reason: 2 }).unwrap();
        let mut two = m.to_vec();
        two.extend_from_slice(&[0xFF]);
        assert_eq!(decode_ctl_message(&two).unwrap().1, m.len());
    }

    #[test]
    fn ctl_malformed_matrix_does_not_panic() {
        assert!(decode_ctl_message(&[]).is_err());
        assert!(decode_ctl_message(&[0x01]).is_err());
        assert!(decode_ctl_message(&[0x01, 0x05]).is_err());
        assert!(decode_ctl_message(&[0x01, 0x05, 0x00]).is_err()); // truncated body
        assert!(decode_ctl_message(&[0x01, 0x41, 0x00]).is_err()); // len 65 > 64
        assert!(decode_ctl_message(&[0x99, 0x00, 0x00]).is_err()); // unknown type
        // Body length must equal the size the type requires.
        assert!(decode_ctl_message(&[0x01, 0x04, 0x00, 0, 0, 0, 0]).is_err());
        assert!(decode_ctl_message(&[0x01, 0x06, 0x00, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_ctl_message(&[0x84, 0x01, 0x00, 0x00]).is_err()); // GOAWAY body
        assert!(decode_ctl_message(&[0x82, 0x03, 0x00, 0x05, 0x00, 0x00]).is_err());
        // Flow ids outside the 14-bit space are rejected.
        assert!(decode_ctl_message(&[0x02, 0x03, 0x00, 0x00, 0x40, 0x00]).is_err());
        assert!(decode_ctl_message(&[0x81, 0x03, 0x00, 0xFF, 0xFF, 0x00]).is_err());
        assert!(decode_ctl_message(&[0x82, 0x02, 0x00, 0x00, 0x40]).is_err());
        // …and the encoder never emits them.
        assert!(
            encode_ctl_message(CtlMessage::FlowClose {
                fid: 0x4000,
                reason: 0
            })
            .is_none()
        );
        assert!(
            encode_ctl_message(CtlMessage::Reject {
                fid: u16::MAX,
                reason: 0
            })
            .is_none()
        );
        assert!(encode_ctl_message(CtlMessage::NeedContext { fid: 0x4000 }).is_none());
        // Boundary ids are accepted.
        assert!(encode_ctl_message(CtlMessage::FlowClose { fid: 0, reason: 0 }).is_some());
        assert!(
            encode_ctl_message(CtlMessage::FlowClose {
                fid: FID_MAX,
                reason: 0xFF
            })
            .is_some()
        );
    }

    #[test]
    fn ctl_truncations_are_rejected() {
        let msgs = [
            CtlMessage::AssocClose { sess: 7, reason: 1 },
            CtlMessage::FlowClose { fid: 9, reason: 2 },
            CtlMessage::Reject { fid: 9, reason: 2 },
            CtlMessage::NeedContext { fid: 9 },
            CtlMessage::SessClose { sess: 7, reason: 2 },
            CtlMessage::Goaway,
        ];
        for m in msgs {
            assert_ctl_prefixes_rejected(&encode_ctl_message(m).unwrap());
        }
    }

    // ---------------- flow-id allocator ----------------

    #[test]
    fn flow_ids_client_monotonic_and_exhausts() {
        let mut ids = FlowIds::client();
        assert_eq!(ids.owner(), FidOwner::Client);
        assert_eq!(ids.allocated(), 0);
        assert_eq!(ids.remaining(), FIDS_PER_OWNER);
        assert!(!ids.is_exhausted());
        let mut seen = HashSet::new();
        for expected in 0..=CLIENT_FID_MAX {
            let fid = ids.alloc().expect("id available");
            assert_eq!(fid, expected);
            assert!(is_client_fid(fid));
            assert_eq!(fid_owner(fid), Some(FidOwner::Client));
            assert!(seen.insert(fid), "ids must never repeat");
        }
        assert_eq!(seen.len(), FIDS_PER_OWNER);
        assert_eq!(ids.allocated(), FIDS_PER_OWNER);
        assert_eq!(ids.remaining(), 0);
        assert!(ids.is_exhausted());
        // Exhaustion is sticky: no wrap-around, no reuse.
        assert_eq!(ids.alloc(), None);
        assert_eq!(ids.alloc(), None);
        assert_eq!(ids.allocated(), FIDS_PER_OWNER);
    }

    #[test]
    fn flow_ids_server_monotonic_and_exhausts() {
        let mut ids = FlowIds::server();
        assert_eq!(ids.owner(), FidOwner::Server);
        assert_eq!(ids.allocated(), 0);
        let mut seen = HashSet::new();
        for expected in SERVER_FID_BASE..=FID_MAX {
            let fid = ids.alloc().expect("id available");
            assert_eq!(fid, expected);
            assert!(is_server_fid(fid));
            assert_eq!(fid_owner(fid), Some(FidOwner::Server));
            assert!(seen.insert(fid));
        }
        assert_eq!(seen.len(), FIDS_PER_OWNER);
        assert!(ids.is_exhausted());
        assert_eq!(ids.alloc(), None);
        // The two owners never share an id.
        assert_eq!(FlowIds::client().alloc(), Some(0));
        assert_eq!(FlowIds::server().alloc(), Some(SERVER_FID_BASE));
    }

    #[test]
    fn fid_owner_helpers() {
        assert!(valid_fid(0));
        assert!(valid_fid(CLIENT_FID_MAX));
        assert!(valid_fid(SERVER_FID_BASE));
        assert!(valid_fid(FID_MAX));
        assert!(!valid_fid(0x4000));
        assert!(!valid_fid(u16::MAX));
        assert!(is_client_fid(0));
        assert!(is_client_fid(CLIENT_FID_MAX));
        assert!(!is_client_fid(SERVER_FID_BASE));
        assert!(is_server_fid(SERVER_FID_BASE));
        assert!(is_server_fid(FID_MAX));
        assert!(!is_server_fid(CLIENT_FID_MAX));
        assert!(!is_server_fid(0));
        assert_eq!(fid_owner(0), Some(FidOwner::Client));
        assert_eq!(fid_owner(CLIENT_FID_MAX), Some(FidOwner::Client));
        assert_eq!(fid_owner(SERVER_FID_BASE), Some(FidOwner::Server));
        assert_eq!(fid_owner(FID_MAX), Some(FidOwner::Server));
        assert_eq!(fid_owner(0x4000), None);
        assert_eq!(fid_owner(u16::MAX), None);

        // Ids from an allocator round-trip through the steady frame.
        let mut ids = FlowIds::client();
        for _ in 0..16 {
            let fid = ids.alloc().unwrap();
            let f = encode_data_steady(fid, b"p", 1500).unwrap();
            assert_eq!(decode_data(&f).unwrap().fid, Some(fid));
        }
        let mut ids = FlowIds::server();
        for _ in 0..16 {
            let fid = ids.alloc().unwrap();
            let f = encode_data_steady(fid, b"p", 1500).unwrap();
            assert_eq!(decode_data(&f).unwrap().fid, Some(fid));
        }
    }

    // ---------------- header sizes and encoder limits ----------------

    #[test]
    fn header_sizes_match_the_analysis_table() {
        let a4 = addr_len(&v4(53));
        let a6 = addr_len(&v6(443));
        let ad = addr_len(&dom("example.com", 53)); // L = 11
        assert_eq!((a4, a6, ad), (7, 19, 15));

        // §4.2 table, v4 / v6 / domain 11+L.
        assert_eq!(data_steady_len(0), 2);
        assert_eq!(data_open_len(a4, 0), 14);
        assert_eq!(data_open_len(a6, 0), 26);
        assert_eq!(data_open_len(ad, 0), 11 + 11);
        assert_eq!(data_src_len(a4, 0), 10);
        assert_eq!(data_src_len(a6, 0), 22);
        assert_eq!(data_src_len(ad, 0), 7 + 11);
        assert_eq!(data_inline_len(a4, 0), 12);
        assert_eq!(data_inline_len(a6, 0), 24);
        assert_eq!(data_inline_len(ad, 0), 9 + 11);
        // FRAG steady 9; extended forms follow from §4.2's field order.
        assert_eq!(frag_steady_len(0), 9);
        assert_eq!(frag_open_len(a4, 0), 13 + 7);
        assert_eq!(frag_src_len(a4, 0), 9 + 7);
        assert_eq!(frag_inline_len(a4, 0), 11 + 7);

        // TRAIN headers: SAME 4 B; SAME_EQUAL 5-7 B; DICT 3 + 2*nfl B (the
        // byte layout puts b0/nfl/count before the fid table).
        let empty_item: [&[u8]; 1] = [b""];
        assert_eq!(train_same_len(0, &empty_item).unwrap(), 4 + 1);
        assert_eq!(train_same_equal_len(0, &empty_item).unwrap(), 4 + 1);
        let big_buf = [0u8; 255];
        let one_255: [&[u8]; 1] = [&big_buf];
        assert_eq!(train_same_equal_len(0, &one_255).unwrap(), 4 + 3 + 255);
        let flows = [1u16, 2];
        let items: [(u8, &[u8]); 2] = [(0, b""), (1, b"")];
        assert_eq!(
            train_dict_len(&flows, &items).unwrap(),
            3 + 2 * 2 + 2 * (1 + 1)
        );

        // Encoded length always equals the helper's prediction.
        let p: &[u8] = b"payload";
        let d = encode_data_steady(1, p, 1500).unwrap();
        assert_eq!(d.len(), data_steady_len(p.len()));
        let d = encode_data_open(1, 1, &v4(53), false, p, 1500).unwrap();
        assert_eq!(d.len(), data_open_len(a4, p.len()));
        let d = encode_data_open(0x2000, 1, &v6(1), true, p, 1500).unwrap();
        assert_eq!(d.len(), data_open_len(a6, p.len()));
        let d = encode_data_src(1, &dom("example.com", 1), p, 1500).unwrap();
        assert_eq!(d.len(), data_src_len(ad, p.len()));
        let d = encode_data_inline(1, &v4(1), p, 1500).unwrap();
        assert_eq!(d.len(), data_inline_len(a4, p.len()));
        let d = encode_frag_steady(1, 1, 0, 1, p, 1500).unwrap();
        assert_eq!(d.len(), frag_steady_len(p.len()));
        let d = encode_frag_open(1, 1, &v4(1), false, 1, 0, 1, p, 1500).unwrap();
        assert_eq!(d.len(), frag_open_len(a4, p.len()));
        let d = encode_frag_open(0x2000, 1, &v6(1), true, 1, 0, 1, p, 1500).unwrap();
        assert_eq!(d.len(), frag_open_len(a6, p.len()));
        let d = encode_frag_src(1, &v4(1), 1, 0, 1, p, 1500).unwrap();
        assert_eq!(d.len(), frag_src_len(a4, p.len()));
        let d = encode_frag_inline(1, &v4(1), 1, 0, 1, p, 1500).unwrap();
        assert_eq!(d.len(), frag_inline_len(a4, p.len()));
        let payloads: [&[u8]; 2] = [b"ab", b"cd"];
        let d = encode_train_same(1, &payloads, 1500).unwrap();
        assert_eq!(d.len(), train_same_len(1, &payloads).unwrap());
        let d = encode_train_same_equal(1, &payloads, 1500).unwrap();
        assert_eq!(d.len(), train_same_equal_len(1, &payloads).unwrap());
        let flows = [1u16];
        let items: [(u8, &[u8]); 2] = [(0, b"ab"), (0, b"cd")];
        let d = encode_train_dict(&flows, &items, 1500).unwrap();
        assert_eq!(d.len(), train_dict_len(&flows, &items).unwrap());
    }

    #[test]
    fn encode_limit_is_enforced_by_every_encoder() {
        let p: &[u8] = b"abc";
        let check = |need: usize, mk: &dyn Fn(usize) -> Option<Bytes>| {
            assert!(mk(need).is_some(), "exact need = {need}");
            assert!(mk(need - 1).is_none(), "one byte short of {need}");
        };
        check(data_steady_len(p.len()), &|l| encode_data_steady(5, p, l));
        check(data_open_len(7, p.len()), &|l| {
            encode_data_open(5, 1, &v4(53), false, p, l)
        });
        check(data_open_len(7, p.len()), &|l| {
            encode_data_open(0x2000, 1, &v4(53), true, p, l)
        });
        check(data_src_len(7, p.len()), &|l| {
            encode_data_src(5, &v4(53), p, l)
        });
        check(data_inline_len(7, p.len()), &|l| {
            encode_data_inline(1, &v4(53), p, l)
        });
        let payloads: [&[u8]; 2] = [b"ab", b"cd"];
        check(train_same_len(5, &payloads).unwrap(), &|l| {
            encode_train_same(5, &payloads, l)
        });
        check(train_same_equal_len(5, &payloads).unwrap(), &|l| {
            encode_train_same_equal(5, &payloads, l)
        });
        let flows = [5u16, 9];
        let items: [(u8, &[u8]); 2] = [(0, b"ab"), (1, b"cd")];
        check(train_dict_len(&flows, &items).unwrap(), &|l| {
            encode_train_dict(&flows, &items, l)
        });
        check(frag_steady_len(p.len()), &|l| {
            encode_frag_steady(5, 1, 0, 1, p, l)
        });
        check(frag_open_len(7, p.len()), &|l| {
            encode_frag_open(5, 1, &v4(53), false, 1, 0, 1, p, l)
        });
        check(frag_src_len(7, p.len()), &|l| {
            encode_frag_src(5, &v4(53), 1, 0, 1, p, l)
        });
        check(frag_inline_len(7, p.len()), &|l| {
            encode_frag_inline(1, &v4(53), 1, 0, 1, p, l)
        });
        assert!(encode_data_steady(5, p, 0).is_none());
    }

    #[test]
    fn frame_bytes_budget_matches_max_frame_bytes() {
        // A steady frame exactly at the DATAGRAM budget fits; one byte more
        // does not. (The codec does not clamp `limit`, so tests can build
        // larger shapes; MAX_FRAME_BYTES is the intended production value.)
        let payload = vec![0u8; MAX_FRAME_BYTES - 2];
        let d = encode_data_steady(1, &payload, MAX_FRAME_BYTES).unwrap();
        assert_eq!(d.len(), MAX_FRAME_BYTES);
        let payload = vec![0u8; MAX_FRAME_BYTES - 1];
        assert!(encode_data_steady(1, &payload, MAX_FRAME_BYTES).is_none());
    }

    #[test]
    fn address_policy_is_inherited_from_the_addr_codec() {
        // Unspecified IP targets are refused by the address codec (§addr), so
        // the encoders return `None` instead of emitting them.
        let unspecified = TargetAddrRef::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        assert!(encode_data_open(0, 1, &unspecified, false, b"", 1500).is_none());
        assert!(encode_data_open(0x2000, 1, &unspecified, true, b"", 1500).is_none());
        assert!(encode_data_src(0, &unspecified, b"", 1500).is_none());
        assert!(encode_data_inline(1, &unspecified, b"", 1500).is_none());
        assert!(encode_frag_open(0, 1, &unspecified, false, 1, 0, 1, b"x", 1500).is_none());
        assert!(encode_frag_src(0, &unspecified, 1, 0, 1, b"x", 1500).is_none());
        assert!(encode_frag_inline(1, &unspecified, 1, 0, 1, b"x", 1500).is_none());
        // Empty / too-long domains are refused too.
        let empty_domain = TargetAddrRef::Domain("", 53);
        assert!(encode_data_open(0, 1, &empty_domain, false, b"", 1500).is_none());
        let name = "a".repeat(256);
        let long = TargetAddrRef::Domain(&name, 53);
        assert!(encode_data_open(0, 1, &long, false, b"", 1500).is_none());
        // A max-length (255 B) domain is the MAX_ADDR_LEN case and round-trips.
        let name = "d".repeat(255);
        let max = TargetAddrRef::Domain(&name, u16::MAX);
        assert_eq!(addr_len(&max), MAX_ADDR_LEN);
        let d = encode_data_open(0x1FFF, u32::MAX, &max, false, b"", MAX_FRAME_BYTES).unwrap();
        assert_eq!(d.len(), 7 + MAX_ADDR_LEN);
        assert_eq!(d.len(), data_open_len(MAX_ADDR_LEN, 0));
        let r = decode_data(&d).unwrap();
        assert_eq!(r.addr, Some(TargetAddrRef::Domain(name.as_str(), u16::MAX)));
        assert_eq!(r.fid, Some(0x1FFF));
        assert_eq!(r.sess, Some(u32::MAX));
    }

    // ---------------- adversarial loops ----------------

    #[test]
    fn exhaustive_two_byte_prefixes_never_panic() {
        for b0 in 0..=u8::MAX {
            for b1 in 0..=u8::MAX {
                let buf = [b0, b1];
                let _ = decode_data(&buf);
                let _ = decode_train(&buf);
                let _ = decode_frag(&buf);
                let _ = decode_ctl_message(&buf);
                let _ = kind(&buf);
                assert!(is_r3(&buf));
            }
        }
    }

    #[test]
    fn lcg_fuzz_random_short_buffers_never_panic() {
        let mut lcg = Lcg(0x9E37_79B9_7F4A_7C15);
        let mut buf = [0u8; 96];
        for _ in 0..2_000_000 {
            let len = (lcg.next_u64() % (buf.len() as u64 + 1)) as usize;
            let mut i = 0;
            while i < len {
                let word = lcg.next_u64().to_le_bytes();
                let n = (len - i).min(8);
                buf[i..i + n].copy_from_slice(&word[..n]);
                i += n;
            }
            let s = &buf[..len];
            assert_eq!(is_r3(s), !s.is_empty());
            let _ = kind(s);
            let _ = decode_data(s);
            if let Ok(t) = decode_train(s) {
                assert_eq!(t.item_count(), t.items().count());
                assert!(t.flows().len() <= MAX_TRAIN_ITEMS);
                for (fid, payload) in t.items() {
                    assert!(valid_fid(fid));
                    assert!(payload.len() <= s.len());
                }
            }
            if let Ok(r) = decode_frag(s) {
                assert!(!r.chunk.is_empty());
                assert!(r.idx < r.total);
                assert!((1..=MAX_FRAG_TOTAL).contains(&r.total));
                assert!(r.chunk.len() <= MAX_FRAG_BYTES);
                assert_eq!(&s[r.chunk_off..], r.chunk);
                if let Some(fid) = r.fid {
                    assert!(valid_fid(fid));
                }
            }
            if let Ok(d) = decode_data(s) {
                if let Some(fid) = d.fid {
                    assert!(valid_fid(fid));
                }
                assert!(d.payload.len() <= s.len());
            }
            if let Ok((_, used)) = decode_ctl_message(s) {
                assert!((3..=MAX_CTL_BODY + 3).contains(&used));
                assert!(used <= s.len());
            }
        }
    }

    #[test]
    fn mutated_valid_frames_never_panic() {
        let same_payloads: [&[u8]; 2] = [&b"a"[..], &b"bc"[..]];
        let equal_payloads: [&[u8]; 2] = [&b"aa"[..], &b"bb"[..]];
        let dict_items: [(u8, &[u8]); 2] = [(0, &b"a"[..]), (1, &b"bc"[..])];
        let base: Vec<Vec<u8>> = vec![
            encode_data_steady(0x0100, b"pay", 1500).unwrap().to_vec(),
            encode_data_open(5, 7, &v4(53), false, b"pay", 1500)
                .unwrap()
                .to_vec(),
            encode_data_open(0x2000, 7, &v6(53), true, b"", 1500)
                .unwrap()
                .to_vec(),
            encode_data_src(5, &v4(53), b"p", 1500).unwrap().to_vec(),
            encode_data_inline(7, &dom("example.com", 53), b"p", 1500)
                .unwrap()
                .to_vec(),
            encode_train_same(5, &same_payloads, 1500).unwrap().to_vec(),
            encode_train_same_equal(5, &equal_payloads, 1500)
                .unwrap()
                .to_vec(),
            encode_train_dict(&[5, 9], &dict_items, 1500)
                .unwrap()
                .to_vec(),
            encode_frag_steady(5, 1, 0, 2, b"p", 1500).unwrap().to_vec(),
            encode_frag_open(5, 7, &v4(53), false, 1, 0, 2, b"p", 1500)
                .unwrap()
                .to_vec(),
            encode_frag_src(5, &v4(53), 1, 0, 2, b"p", 1500)
                .unwrap()
                .to_vec(),
            encode_frag_inline(7, &v4(53), 1, 0, 2, b"p", 1500)
                .unwrap()
                .to_vec(),
            encode_ctl_message(CtlMessage::AssocClose { sess: 7, reason: 1 })
                .unwrap()
                .to_vec(),
            encode_ctl_message(CtlMessage::FlowClose { fid: 9, reason: 3 })
                .unwrap()
                .to_vec(),
        ];
        let mut lcg = Lcg(0x0123_4567_89AB_CDEF);
        for frame in &base {
            assert!(!frame.is_empty());
            for _ in 0..2_000 {
                let mut m = frame.clone();
                let flips = 1 + (lcg.next_u64() % 3);
                for _ in 0..flips {
                    let pos = (lcg.next_u64() as usize) % m.len();
                    m[pos] ^= 1u8 << (lcg.next_u64() % 8);
                }
                let s = &m[..];
                let _ = decode_data(s);
                let _ = decode_train(s);
                let _ = decode_frag(s);
                let _ = decode_ctl_message(s);
                let _ = kind(s);
                let _ = is_r3(s);
            }
        }
    }
}
