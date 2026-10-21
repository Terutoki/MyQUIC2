//! Per-connection cross-session egress stager for MQP-3 rev2 small payloads.
//!
//! With one QUIC connection carrying many UDP associations (the router/client
//! shape), the Phase-1 paths stage and send per association: one `TRAIN` per
//! session per drain burst. That already amortises the frame header, but a
//! burst of tiny payloads from N associations still becomes N MQP frames (and N
//! `send_datagram` calls). This module is the Phase-2 aggregation point:
//! associations push ready-to-send items into one connection-scoped queue, and
//! whichever task drains it packs **different sessions' flows into one
//! `TRAIN dict`**, round-robin across sessions so one busy association cannot
//! starve the others.
//!
//! # Item shapes
//!
//! * [`R2StageKind::Steady`] — a confirmed flow payload: can join a dict train
//!   with items from any session (rev2 wire ids are connection-scoped, so a
//!   train no longer needs a session header).
//! * [`R2StageKind::Open`] — the first frame of an opening flow: carries
//!   `sess + addr`, must be sent standalone (`DATA OPEN`).
//! * [`R2StageKind::Inline`] — the no-flow fail-safe: standalone `DATA INLINE`.
//!
//! `Open`/`Inline` items break a train run (they are self-describing frames,
//! not train items); ordering inside one session is preserved because each
//! session's queue is FIFO and the round-robin only ever pops from a queue's
//! head.
//!
//! # Ownership and accounting
//!
//! Payloads are owned [`Bytes`]: an item may be queued by one task and drained
//! by another, so a borrowed slice cannot outlive the push. A successful frame
//! books `udp_stats::payload` per item; a refused frame accounts the items it
//! contained through [`crate::dgram_drops`] and leaves the rest queued for the
//! next drain. `clear` returns the number of items the caller must account for
//! when a connection dies.
//!
//! # Bounds
//!
//! The queue is bounded by item count and bytes; `push` returns the item back
//! when full so the caller can apply its own drop policy (e.g. count
//! `NO_EGRESS`/`BUFFER_FULL`). Every drain is itself bounded by the live
//! DATAGRAM budget, so a hostile local application cannot make one drain loop
//! unbounded.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use quinn::Connection;

use crate::dgram_drops;
use crate::mqp::addr::TargetAddr;
use crate::mqp::r2;
use crate::udp::send::{DatagramSend, try_send_datagram};
use crate::udp_stats;

/// Default queue cap: items and bytes. A connection with 64 associations and a
/// full drain burst per association stays well below this; the caps exist to
/// bound a stalled/never-drained connection, not to shape normal traffic.
pub const R2_STAGE_MAX_ITEMS: usize = 1024;
pub const R2_STAGE_MAX_BYTES: usize = 256 * 1024;

/// Addressing shape of one staged item.
#[derive(Debug, Clone)]
pub enum R2StageKind {
    /// Confirmed flow: only the wire id is needed; can join a dict train.
    Steady { wire_id: u32 },
    /// Opening flow: first frame carries session + address (`DATA OPEN`).
    Open {
        wire_id: u32,
        sess: u32,
        addr: TargetAddr,
        src: bool,
    },
    /// No flow id: self-describing `DATA INLINE`, standalone.
    Inline {
        sess: u32,
        addr: TargetAddr,
        src: bool,
    },
}

/// One ready-to-send payload.
#[derive(Debug, Clone)]
pub struct R2StageItem {
    /// Owning UDP session, for the round-robin fairness cursor.
    pub session: u32,
    pub kind: R2StageKind,
    pub payload: Bytes,
}

/// Result of one [`R2Stager::drain`] call.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct R2DrainOutcome {
    /// DATAGRAM frames actually queued to quinn.
    pub frames: u32,
    /// Payloads booked as sent.
    pub items_sent: u32,
    /// Payloads in the failed frame that were dropped (not sent).
    pub items_dropped: u32,
    /// The verdict that stopped the drain, if any. Remaining items stay queued.
    pub failed: Option<DatagramSend>,
}

/// One encoded frame plus the number of items it carries.
struct EncodedFrame {
    body: Bytes,
    items: u32,
}

/// Per-connection stager. One instance lives next to the connection's
/// `FlowRegistry`/`CtlState`; associations and session readers share it.
pub struct R2Stager {
    /// Per-session FIFO queues. A session's items are always sent in push order.
    sessions: HashMap<u32, VecDeque<R2StageItem>, foldhash::fast::RandomState>,
    /// Round-robin cursor over session ids that currently have items.
    order: VecDeque<u32>,
    queued_items: usize,
    queued_bytes: usize,
    max_items: usize,
    max_bytes: usize,
    /// Negotiated `CAPS.max_train_items`, clamped to the codec bound.
    max_train_items: usize,
}

impl Default for R2Stager {
    fn default() -> Self {
        Self::with_capacity(R2_STAGE_MAX_ITEMS, R2_STAGE_MAX_BYTES)
    }
}

impl R2Stager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_capacity(max_items: usize, max_bytes: usize) -> Self {
        Self {
            sessions: HashMap::with_hasher(foldhash::fast::RandomState::default()),
            order: VecDeque::new(),
            queued_items: 0,
            queued_bytes: 0,
            max_items,
            max_bytes,
            max_train_items: r2::R2_MAX_TRAIN_ITEMS,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queued_items
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued_items == 0
    }

    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Apply the negotiated `CAPS.max_train_items` (clamped to the codec bound;
    /// 0 means "peer did not advertise", keep the default 64).
    pub fn set_max_train_items(&mut self, n: u8) {
        if n > 0 {
            self.max_train_items = usize::from(n).min(r2::R2_MAX_TRAIN_ITEMS);
        }
    }

    /// Drop queue entries belonging to a closed session (`SESS_CLOSE`), returning
    /// how many payloads the caller should account for. A closed association's
    /// queued datagrams must not be sent to a session the server already reaped.
    pub fn drop_session(&mut self, session: u32) -> usize {
        let Some(queue) = self.sessions.remove(&session) else {
            return 0;
        };
        let mut removed = 0usize;
        for item in queue {
            self.queued_items = self.queued_items.saturating_sub(1);
            self.queued_bytes = self.queued_bytes.saturating_sub(item.payload.len());
            removed += 1;
        }
        // The order deque keeps a stale slot for `session`; next_session skips
        // sessions whose map entry is gone, so no explicit removal is needed.
        for _ in 0..removed {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        removed
    }

    /// Drop queue entries naming a closed flow (`FLOW_CLOSE`), preserving the
    /// order of the remaining items in each session queue.
    pub fn drop_flow(&mut self, wire_id: u32) -> usize {
        let mut removed = 0usize;
        for queue in self.sessions.values_mut() {
            let before = queue.len();
            queue.retain(|item| match &item.kind {
                R2StageKind::Steady { wire_id: id } | R2StageKind::Open { wire_id: id, .. } => {
                    *id != wire_id
                }
                R2StageKind::Inline { .. } => true,
            });
            let dropped = before - queue.len();
            if dropped > 0 {
                removed += dropped;
            }
        }
        if removed == 0 {
            return 0;
        }
        // Rebuild the accounting exactly (rare close path).
        let items: usize = self.sessions.values().map(VecDeque::len).sum();
        let bytes: usize = self
            .sessions
            .values()
            .flat_map(|q| q.iter())
            .map(|i| i.payload.len())
            .sum();
        self.queued_items = items;
        self.queued_bytes = bytes;
        for _ in 0..removed {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
        removed
    }

    /// Queue one item. On a full queue the item is returned unchanged so the
    /// caller can apply its own drop accounting (never silently lost here).
    pub fn push(&mut self, item: R2StageItem) -> Result<(), R2StageItem> {
        if self.queued_items >= self.max_items
            || self
                .queued_bytes
                .saturating_add(item.payload.len())
                .gt(&self.max_bytes)
        {
            return Err(item);
        }
        let session = item.session;
        let bytes = item.payload.len();
        let queue = self.sessions.entry(session).or_default();
        if queue.is_empty() {
            self.order.push_back(session);
        }
        queue.push_back(item);
        self.queued_items += 1;
        self.queued_bytes += bytes;
        Ok(())
    }

    /// Drop everything, returning how many items the caller must account for
    /// (connection death / teardown).
    pub fn clear(&mut self) -> usize {
        let n = self.queued_items;
        self.sessions.clear();
        self.order.clear();
        self.queued_items = 0;
        self.queued_bytes = 0;
        n
    }

    /// Pop and encode the next DATAGRAM body, using at most `limit` bytes.
    ///
    /// A run of confirmed flows from any sessions becomes one `TRAIN dict`; a
    /// single confirmed item becomes a 2 B steady `DATA`; `Open`/`Inline`
    /// items become standalone self-describing frames. Returns `None` when the
    /// queue is empty.
    fn next_frame(&mut self, limit: usize) -> Option<EncodedFrame> {
        loop {
            let session = self.next_session()?;
            let head_is_standalone = self
                .sessions
                .get(&session)
                .and_then(|q| q.front())
                .is_some_and(|i| !matches!(i.kind, R2StageKind::Steady { .. }));
            if head_is_standalone {
                let item = self.pop_one(session)?;
                match self.encode_standalone(item, limit) {
                    Some(frame) => return Some(frame),
                    None => {
                        // The live budget shrank below a queued standalone
                        // item: drop it (counted) and keep draining.
                        self.drop_too_large(1);
                        continue;
                    }
                }
            }
            let run = self.collect_steady_run(session, limit);
            if run.is_empty() {
                // Every remaining head is either standalone (handled next
                // iteration) or cannot fit the live limit. Drop the latter so
                // the loop always makes progress.
                if self
                    .sessions
                    .get(&session)
                    .and_then(|q| q.front())
                    .is_some_and(|i| matches!(i.kind, R2StageKind::Steady { .. }))
                {
                    let _ = self.pop_one(session);
                    self.drop_too_large(1);
                }
                continue;
            }
            let single = run.len() == 1;
            let encoded = if single {
                let (wire_id, payload) = &run[0];
                r2::encode_data_steady(*wire_id, payload, limit)
            } else {
                self.encode_train(&run, limit)
            };
            match encoded {
                Some(body) => {
                    let items = run.len() as u32;
                    for (_, payload) in &run {
                        udp_stats::payload(payload.len());
                    }
                    return Some(EncodedFrame { body, items });
                }
                None => {
                    // The live budget shrank under queued items: drop this run
                    // (counted) and keep draining the rest.
                    self.drop_too_large(run.len());
                    continue;
                }
            }
        }
    }

    /// Account `n` payloads dropped because the live path budget no longer fits
    /// the encoded frame.
    fn drop_too_large(&self, n: usize) {
        for _ in 0..n {
            let bumped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
            if bumped == 1 {
                crate::stats::warn_datagram_drop(
                    crate::stats::DatagramDropKind::Large,
                    "staged rev2 payload no longer fits the path budget",
                    bumped,
                    String::new,
                );
            }
        }
    }

    /// Encode one standalone `Open`/`Inline` item.
    fn encode_standalone(&self, item: R2StageItem, limit: usize) -> Option<EncodedFrame> {
        let body = match item.kind {
            R2StageKind::Open {
                wire_id,
                sess,
                addr,
                src,
            } => r2::encode_data_open(wire_id, sess, &addr.as_ref(), src, &item.payload, limit),
            R2StageKind::Inline { sess, addr, src } => {
                r2::encode_data_inline(sess, &addr.as_ref(), src, &item.payload, limit)
            }
            R2StageKind::Steady { wire_id } => {
                r2::encode_data_steady(wire_id, &item.payload, limit)
            }
        }?;
        udp_stats::payload(item.payload.len());
        Some(EncodedFrame { body, items: 1 })
    }

    /// Pop heads round-robin while they are `Steady` and fit `limit`.
    ///
    /// `first` is the session already selected by [`Self::next_frame`], so the
    /// run starts with that session's head and only then rotates. Per-session
    /// FIFO order is preserved; sessions interleave for fairness.
    fn collect_steady_run(&mut self, first: u32, limit: usize) -> Vec<(u32, Bytes)> {
        let mut run: Vec<(u32, Bytes)> = Vec::new();
        let mut unique: Vec<u32> = Vec::new();
        let mut cost = 4usize; // kind/form/count/nfl
        if !self.take_steady_head(first, limit, &mut run, &mut unique, &mut cost) {
            return run;
        }
        while let Some(session) = self.next_steady_session() {
            if !self.take_steady_head(session, limit, &mut run, &mut unique, &mut cost) {
                break;
            }
        }
        run
    }

    /// Pop one `Steady` head from `session` if it keeps the train within
    /// `limit`; mirrors the exact wire size [`r2::encode_train_dict`] will use.
    fn take_steady_head(
        &mut self,
        session: u32,
        limit: usize,
        run: &mut Vec<(u32, Bytes)>,
        unique: &mut Vec<u32>,
        cost: &mut usize,
    ) -> bool {
        let Some(front) = self.sessions.get(&session).and_then(|q| q.front()) else {
            return false;
        };
        let R2StageKind::Steady { wire_id } = front.kind else {
            return false;
        };
        if run.len() >= self.max_train_items {
            return false;
        }
        let payload_len = front.payload.len();
        let mut add = 1 + r2::varint_len(payload_len as u32) + payload_len;
        let new_flow = !unique.contains(&wire_id);
        if new_flow {
            if unique.len() >= u8::MAX as usize {
                return false;
            }
            add += r2::varint_len(wire_id);
        }
        if cost.saturating_add(add) > limit {
            return false;
        }
        let item = self.pop_one(session).expect("peeked item exists");
        let wire_id = match item.kind {
            R2StageKind::Steady { wire_id } => wire_id,
            _ => unreachable!("take_steady_head peeked a steady item"),
        };
        if new_flow {
            unique.push(wire_id);
        }
        *cost += add;
        run.push((wire_id, item.payload));
        true
    }

    fn encode_train(&self, run: &[(u32, Bytes)], limit: usize) -> Option<Bytes> {
        let mut flows: Vec<u32> = Vec::new();
        for (wire_id, _) in run {
            if !flows.contains(wire_id) {
                flows.push(*wire_id);
            }
        }
        let mut items: Vec<(u8, &[u8])> = Vec::with_capacity(run.len());
        for (wire_id, payload) in run {
            let idx = flows.iter().position(|f| f == wire_id)?;
            items.push((idx as u8, payload.as_ref()));
        }
        r2::encode_train_dict(&flows, &items, limit)
    }

    /// Pop the next session that has a non-empty queue, rotating the cursor.
    fn next_session(&mut self) -> Option<u32> {
        let len = self.order.len();
        for _ in 0..len {
            let session = self.order.pop_front()?;
            let non_empty = self.sessions.get(&session).is_some_and(|q| !q.is_empty());
            if non_empty {
                self.order.push_back(session);
                return Some(session);
            }
        }
        None
    }

    /// Pop the next session whose head is a `Steady` item, rotating the cursor.
    fn next_steady_session(&mut self) -> Option<u32> {
        let len = self.order.len();
        for _ in 0..len {
            let session = self.order.pop_front()?;
            let steady = self
                .sessions
                .get(&session)
                .and_then(|q| q.front())
                .is_some_and(|i| matches!(i.kind, R2StageKind::Steady { .. }));
            if steady {
                self.order.push_back(session);
                return Some(session);
            }
            self.order.push_back(session);
        }
        None
    }

    fn pop_one(&mut self, session: u32) -> Option<R2StageItem> {
        let queue = self.sessions.get_mut(&session)?;
        let item = queue.pop_front()?;
        if queue.is_empty() {
            self.sessions.remove(&session);
        }
        self.queued_items = self.queued_items.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(item.payload.len());
        Some(item)
    }

    /// Drain frames and send them on `conn`. Stops on the first send verdict
    /// that is not `Sent`; the remaining items stay queued for the next drain
    /// (the failed frame's items are counted as dropped, see
    /// [`R2DrainOutcome`]).
    pub fn drain(&mut self, conn: &Connection, limit: usize) -> R2DrainOutcome {
        let mut out = R2DrainOutcome::default();
        while let Some(frame) = self.next_frame(limit) {
            match try_send_datagram(conn, frame.body) {
                DatagramSend::Sent => {
                    out.frames = out.frames.saturating_add(1);
                    out.items_sent = out.items_sent.saturating_add(frame.items);
                }
                other => {
                    out.items_dropped = out.items_dropped.saturating_add(frame.items);
                    out.failed = Some(other);
                    let counter = if other == DatagramSend::Blocked {
                        &dgram_drops::BUFFER_FULL
                    } else {
                        &dgram_drops::EGRESS_DEAD
                    };
                    for _ in 0..frame.items {
                        dgram_drops::bump(counter);
                    }
                    break;
                }
            }
        }
        out
    }
}

impl Drop for R2Stager {
    fn drop(&mut self) {
        // A connection dying with queued payloads must not lose them silently:
        // account each as an egress death (the stager is connection-scoped, so
        // the connection is the only thing that can have died).
        for _ in 0..self.queued_items {
            dgram_drops::bump(&dgram_drops::EGRESS_DEAD);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    fn id(local: u32) -> u32 {
        r2::make_wire_id(local, false).unwrap()
    }

    fn steady(session: u32, local: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Steady { wire_id: id(local) },
            payload: Bytes::from_static(payload),
        }
    }

    fn open(session: u32, local: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Open {
                wire_id: id(local),
                sess: session,
                addr: TargetAddr::Ip(v4(53)),
                src: false,
            },
            payload: Bytes::from_static(payload),
        }
    }

    fn inline(session: u32, payload: &'static [u8]) -> R2StageItem {
        R2StageItem {
            session,
            kind: R2StageKind::Inline {
                sess: session,
                addr: TargetAddr::Ip(v4(53)),
                src: true,
            },
            payload: Bytes::from_static(payload),
        }
    }

    #[test]
    fn queue_bounds_return_the_item() {
        let mut s = R2Stager::with_capacity(2, 64);
        assert!(s.push(steady(1, 1, b"aa")).is_ok());
        assert!(s.push(steady(1, 2, b"bb")).is_ok());
        assert!(s.push(steady(1, 3, b"cc")).is_err());
        assert_eq!(s.len(), 2);
        let mut s = R2Stager::with_capacity(8, 2);
        assert!(s.push(steady(1, 1, b"aa")).is_ok());
        assert!(s.push(steady(1, 2, b"bb")).is_err());
    }

    #[test]
    fn cross_session_steady_items_become_one_dict_train() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(2, 2, b"bb")).unwrap();
        s.push(steady(3, 3, b"cc")).unwrap();
        let f = s.next_frame(1162).expect("a frame");
        assert_eq!(f.items, 3);
        let t = r2::decode_train(&f.body).expect("dict train");
        let got: Vec<(u32, &[u8])> = t.items().collect();
        assert_eq!(
            got,
            vec![
                (id(1), &b"aa"[..]),
                (id(2), &b"bb"[..]),
                (id(3), &b"cc"[..])
            ]
        );
        assert!(s.is_empty());
    }

    #[test]
    fn per_session_order_is_preserved() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"a1")).unwrap();
        s.push(steady(1, 2, b"a2")).unwrap();
        s.push(steady(2, 3, b"b1")).unwrap();
        s.push(steady(2, 4, b"b2")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let t = r2::decode_train(&f.body).unwrap();
        let got: Vec<u32> = t.items().map(|(id, _)| id).collect();
        // Round-robin: session 1 head, session 2 head, then session 1, session 2.
        assert_eq!(got, vec![id(1), id(3), id(2), id(4)]);
    }

    #[test]
    fn standalone_items_break_the_train() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(open(2, 2, b"bb")).unwrap();
        s.push(steady(3, 3, b"cc")).unwrap();
        // The steady heads of sessions 1 and 3 can share a train; the Open item
        // from session 2 is a standalone frame and is sent next.
        let f1 = s.next_frame(1162).unwrap();
        assert_eq!(f1.items, 2);
        let train: Vec<u32> = r2::decode_train(&f1.body)
            .unwrap()
            .items()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(train, vec![id(1), id(3)]);
        let f2 = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f2.body).unwrap();
        assert_eq!(d.id, Some(id(2)));
        assert!(d.addr.is_some());
    }

    #[test]
    fn inline_item_is_self_describing() {
        let mut s = R2Stager::new();
        s.push(inline(7, b"zz")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let d = r2::decode_data(&f.body).unwrap();
        assert_eq!(d.id, None);
        assert_eq!(d.sess, Some(7));
        assert_eq!(d.payload, b"zz");
    }

    #[test]
    fn budget_splits_a_large_run() {
        let mut s = R2Stager::new();
        for i in 0..32u32 {
            // ~100 B payloads: 32 fit the budget individually, not one frame.
            let payload = vec![0u8; 100];
            s.push(R2StageItem {
                session: i,
                kind: R2StageKind::Steady { wire_id: id(i + 1) },
                payload: Bytes::from(payload),
            })
            .unwrap();
        }
        let mut frames = 0;
        let mut items = 0;
        while let Some(f) = s.next_frame(1162) {
            let t = r2::decode_train(&f.body).unwrap();
            items += t.items().count();
            frames += 1;
        }
        assert!(frames > 1);
        assert_eq!(items, 32);
        assert!(s.is_empty());
    }

    #[test]
    fn one_steady_item_uses_the_short_data_frame() {
        let mut s = R2Stager::new();
        s.push(steady(1, 5, b"abc")).unwrap();
        let f = s.next_frame(1162).unwrap();
        assert!(f.body[0] == r2::R2_DATA);
        assert_eq!(r2::decode_data(&f.body).unwrap().payload, b"abc");
    }

    #[test]
    fn drop_session_and_flow_purge_queued_items() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(1, 2, b"bb")).unwrap();
        s.push(steady(2, 3, b"cc")).unwrap();
        assert_eq!(s.drop_session(1), 2);
        assert_eq!(s.len(), 1);
        // Session 1's items never come back.
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(3)));
        assert!(s.is_empty());
        // Flow purge keeps other flows.
        s.push(steady(1, 10, b"dd")).unwrap();
        s.push(steady(1, 11, b"ee")).unwrap();
        assert_eq!(s.drop_flow(id(10)), 1);
        let f = s.next_frame(1162).unwrap();
        assert_eq!(r2::decode_data(&f.body).unwrap().id, Some(id(11)));
    }

    #[test]
    fn negotiated_train_items_splits_frames() {
        let mut s = R2Stager::new();
        s.set_max_train_items(2);
        for i in 0..5u32 {
            s.push(steady(1, i + 1, b"xx")).unwrap();
        }
        let mut frames = 0;
        let mut items = 0;
        while let Some(f) = s.next_frame(1162) {
            items += f.items as usize;
            frames += 1;
        }
        assert_eq!(items, 5);
        assert_eq!(frames, 3, "5 items at 2 per train => 3 frames");
    }

    #[test]
    fn clear_returns_the_item_count() {
        let mut s = R2Stager::new();
        s.push(steady(1, 1, b"aa")).unwrap();
        s.push(steady(2, 2, b"bb")).unwrap();
        assert_eq!(s.clear(), 2);
        assert!(s.is_empty());
        assert!(s.next_frame(1162).is_none());
    }

    #[test]
    fn fairness_lets_a_quiet_session_share_the_first_frame() {
        let mut s = R2Stager::new();
        for i in 0..100u32 {
            s.push(steady(1, i + 1, b"xx")).unwrap();
        }
        s.push(steady(2, 1000, b"yy")).unwrap();
        let f = s.next_frame(1162).unwrap();
        let t = r2::decode_train(&f.body).unwrap();
        let ids: Vec<u32> = t.items().map(|(id, _)| id).collect();
        assert!(ids.contains(&id(1000)), "quiet session must not be starved");
        assert!(ids.len() > 1);
    }
}
