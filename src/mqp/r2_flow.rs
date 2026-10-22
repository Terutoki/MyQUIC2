//! Shared flow/session bookkeeping for the MQP-3 rev2 data plane.
//!
//! The wire codec lives in [`super::r2`]; this module owns the state that both
//! endpoints keep per QUIC connection and per UDP session:
//!
//! * [`FlowBinding`] — one open flow: its connection-scoped wire id, the
//!   session it belongs to, its destination, confirmation state and (for the
//!   downlink direction) the learned reply source / resolved addresses;
//! * [`SessionFlows`] — the per-session reverse table used by the sender to
//!   find a flow id from a destination (uplink) or a reply source (downlink);
//! * [`FlowRegistry`] — the per-connection forward table `wire_id -> binding`
//!   used by the receiver to resolve compressed frames;
//! * [`FlowIds`] — the monotonic sender-side id allocator (one per endpoint
//!   owner);
//! * [`CtlState`] — the per-connection `HELLO`/`CAPS` handshake state.
//!
//! The tables mirror the design in `MQP3_REV2_SPEC.md`: wire ids are never
//! reused while the connection lives, so a removed binding can only be hit by
//! a stale frame that then fails lookup; there is no tombstone/lease dance.
//! All tables are bounded and the registry is charged to admission by the
//! caller.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use arc_swap::{ArcSwap, ArcSwapOption};
use parking_lot::RwLock;

use super::addr::{TargetAddr, TargetAddrRef};
use super::r2::{self, Caps};

/// Per-session flow cap. Mirrors the v0.2.0 `MQP3_MAX_FLOWS`; a full table
/// falls back to `INLINE` frames and never blocks the association.
pub const R2_MAX_FLOWS_PER_SESSION: usize = 64;

/// Per-connection live-flow cap (admission-charged). The codec's `CAPS` frame
/// makes this negotiable; this is the default both endpoints start from.
pub const R2_MAX_FLOWS_PER_CONN: usize = 4096;

/// Resolved addresses retained per domain flow. The set authorizes downlink
/// reply sources before an exact `reply_src` is learned. A peer-controlled
/// name can answer with more records than any real multi-homed service, and
/// every extra address costs memory per flow plus a comparison per reply.
/// A reply from an address beyond the cap is treated like any other unmatched
/// source (inline under full-cone, refused by the restricted filter); the first
/// address is always kept, so the OPEN still forwards. Sixteen covers real
/// multi-A/AAAA sets with a wide margin.
pub const R2_MAX_RESOLVED_ADDRS: usize = 16;

/// Highest sender-local id that still fits `wire_id = (local << 1) | owner`.
const MAX_LOCAL_FLOW_ID: u32 = u32::MAX >> 1;

/// Confirmation state of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Opened by the sender; compressed frames are safe only once an ack or a
    /// compressed frame in the opposite direction proved installation.
    Opening = 0,
    /// Confirmed by the peer; the sender may use steady/id-only frames.
    Open = 1,
    /// Closed (session teardown or explicit close); late frames fail lookup.
    Closed = 2,
}

impl FlowState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => FlowState::Open,
            2 => FlowState::Closed,
            _ => FlowState::Opening,
        }
    }
}

/// One flow binding shared by the sender table, the receiver registry and the
/// dispatchers. Fields are read on the per-packet path, so the mutable ones are
/// atomics or lock-free snapshot loads (`reply_src`, `resolved`): the
/// REP-format `match_source` scan touches both per candidate binding, and a
/// writer lock (however short) would re-serialize every reply-packet provenance
/// check behind the rare DNS install that replaces the address set.
#[derive(Debug)]
pub struct FlowBinding {
    /// Connection-scoped wire id (`local << 1 | owner`), never zero.
    pub wire_id: u32,
    /// Session this flow belongs to (a UDP ASSOCIATE).
    pub session: u32,
    /// Destination the flow is bound to (domain targets keep their name).
    pub target: TargetAddr,
    state: AtomicU8,
    /// Downlink: address to write into the SOCKS5 UDP reply header. Learned
    /// from the first inline reply / `OPEN|SRC` rebind, so it is the actual
    /// source address (same semantics as today's inline replies).
    reply_src: ArcSwapOption<SocketAddr>,
    /// Whether the peer confirmed the `OPEN|SRC` frame that taught it
    /// `reply_src`.
    ///
    /// `reply_src` is set when the binding frame is handed to quinn, but a
    /// QUIC DATAGRAM is unreliable: if that frame is lost the peer never learns
    /// the source, and a steady (address-less) frame for the same id can never
    /// be delivered. [`SessionFlows::match_source`] therefore only classifies a
    /// learned source as `Exact` once this flag is set; until then it keeps
    /// returning `Rebind`, i.e. every reply re-sends the idempotent `OPEN|SRC`
    /// (which carries its own payload, so this costs header bytes, not a
    /// datagram). The peer confirms with `CTL FLOW_ACK`; a binding whose target
    /// is the exact reply address needs no confirmation because the peer can
    /// deliver from the target it already knows.
    reply_src_acked: AtomicBool,
    /// Server side, domain flows: addresses the name resolved to. Used to
    /// decide whether a reply source belongs to this flow (and may be
    /// compressed) before an exact source binding exists.
    ///
    /// `ArcSwap<Vec<..>>` rather than a writer lock: the read side (one
    /// snapshot load per candidate) never blocks and the whole set is
    /// replaced at once on DNS install/rebind, which is its only write.
    resolved: ArcSwap<Vec<SocketAddr>>,
}

impl FlowBinding {
    /// Create an `Opening` binding. The caller inserts it into the registry.
    #[must_use]
    pub fn new_shared(wire_id: u32, session: u32, target: TargetAddr) -> Arc<Self> {
        Arc::new(Self {
            wire_id,
            session,
            target,
            state: AtomicU8::new(FlowState::Opening as u8),
            reply_src: ArcSwapOption::const_empty(),
            reply_src_acked: AtomicBool::new(false),
            resolved: ArcSwap::from_pointee(Vec::new()),
        })
    }

    #[must_use]
    pub fn state(&self) -> FlowState {
        FlowState::from_u8(self.state.load(Ordering::Relaxed))
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Relaxed) == FlowState::Open as u8
    }

    /// Mark the flow confirmed. Idempotent; never reopens a closed binding.
    pub fn mark_open(&self) {
        let _ = self.state.compare_exchange(
            FlowState::Opening as u8,
            FlowState::Open as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Mark the flow closed. A closed id is never reused, so no transition out
    /// of this state exists.
    pub fn mark_closed(&self) {
        self.state.store(FlowState::Closed as u8, Ordering::Relaxed);
    }

    /// Record the actual reply source of a downlink flow and clear its
    /// confirmation: the binding frame that teaches the peer this source has
    /// only been queued to quinn, not acknowledged. Re-sending the same source
    /// (the idempotent retry path) re-arms the wait, which is harmless: the
    /// next ACK confirms whichever retransmission reached the peer.
    pub fn set_reply_src(&self, src: SocketAddr) {
        self.reply_src.store(Some(Arc::new(src)));
        self.reply_src_acked.store(false, Ordering::Relaxed);
    }

    /// Record that the peer confirmed the `OPEN|SRC` binding frame (it decoded
    /// the source or rejected the flow).
    pub fn mark_reply_src_acked(&self) {
        self.reply_src_acked.store(true, Ordering::Relaxed);
    }

    /// Whether the peer has confirmed the learned reply source.
    #[must_use]
    pub fn reply_src_acked(&self) -> bool {
        self.reply_src_acked.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn reply_src(&self) -> Option<SocketAddr> {
        self.reply_src.load().as_deref().copied()
    }

    /// Borrowed destination address, for encoders/forwarding.
    #[must_use]
    pub fn target_ref(&self) -> TargetAddrRef<'_> {
        self.target.as_ref()
    }

    /// IP destination of an IP flow (server uplink fast path).
    #[must_use]
    pub fn target_ip(&self) -> Option<SocketAddr> {
        self.target.socket_addr()
    }

    /// First resolved address of a domain flow (server uplink compressed
    /// frames forward to the address that was already validated at install).
    #[must_use]
    pub fn resolved_first(&self) -> Option<SocketAddr> {
        self.resolved.load().first().copied()
    }

    /// Install the resolved address set of a domain flow (server side). An
    /// empty set means "DNS failed"; the binding is then rejected. Set swap is
    /// atomic: a reader sees either the old set or the new one, never a mix.
    pub fn set_resolved(&self, addrs: Vec<SocketAddr>) {
        self.resolved.store(Arc::new(addrs));
    }

    #[must_use]
    pub fn resolved_len(&self) -> usize {
        self.resolved.load().len()
    }

    /// Whether `ip` is one of the resolved addresses of a domain flow.
    #[must_use]
    pub fn resolved_contains(&self, ip: IpAddr) -> bool {
        self.resolved.load().iter().any(|a| a.ip() == ip)
    }
}

/// Match of a reply source against a session's outbound flows.
#[derive(Debug)]
pub enum SourceMatch {
    /// Exact `(ip, port)` (or an already-bound reply source): compress now.
    Exact(Arc<FlowBinding>),
    /// Same IP / domain-resolved IP but not an exact source yet: send one
    /// `OPEN|SRC` binding frame, then compress the next one.
    Rebind(Arc<FlowBinding>),
}

/// Per-session reverse table. Small fixed array + linear scan: a session has at
/// most [`R2_MAX_FLOWS_PER_SESSION`] flows, and the steady case hits its one
/// flow in the first slots (the v0.2.0 `FlowTable` uses the same trade-off).
#[derive(Debug, Clone)]
pub struct SessionFlows {
    entries: [Option<Arc<FlowBinding>>; R2_MAX_FLOWS_PER_SESSION],
}

impl Default for SessionFlows {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }
}

impl SessionFlows {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.entries.iter().all(Option::is_some)
    }

    /// Find a binding whose target equals `addr` (uplink send path).
    #[must_use]
    pub fn find(&self, addr: &TargetAddrRef<'_>) -> Option<Arc<FlowBinding>> {
        self.entries
            .iter()
            .flatten()
            .find(|b| b.target.as_ref() == *addr)
            .cloned()
    }

    /// Find a binding by exact wire id (close/bookkeeping paths).
    #[must_use]
    pub fn find_id(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        self.entries
            .iter()
            .flatten()
            .find(|b| b.wire_id == wire_id)
            .cloned()
    }

    /// Classify a reply source for the downlink direction.
    ///
    /// One pass over the table: a learned reply source is the strongest match
    /// and wins wherever it sits, so the first candidate for the weaker classes
    /// is remembered and resolved only after the scan. Older revisions scanned
    /// the table three times (and re-loaded every `reply_src` on the first
    /// pass) for every incoming reply.
    ///
    /// A learned source is only `Exact` once the peer confirmed the binding
    /// frame (`FLOW_ACK`) or when the binding's target *is* that source (the
    /// peer can already deliver from the target it knows: an IP flow whose
    /// reply port never changed). Otherwise the frame must be re-sent as
    /// `OPEN|SRC`: QUIC DATAGRAMs are unreliable and a lost binding frame
    /// would otherwise leave every later steady frame for this flow
    /// undeliverable forever.
    #[must_use]
    pub fn match_source(&self, src: SocketAddr) -> Option<SourceMatch> {
        let mut exact: Option<&Arc<FlowBinding>> = None;
        let mut rebind: Option<&Arc<FlowBinding>> = None;
        for b in self.entries.iter().flatten() {
            // A learned reply source is the strongest match (covers domain
            // targets and port changes after the first rebind).
            if b.reply_src() == Some(src) {
                let target_names_src = matches!(&b.target, TargetAddr::Ip(a) if *a == src);
                if b.reply_src_acked() || target_names_src {
                    return Some(SourceMatch::Exact(b.clone()));
                }
                // Unconfirmed: re-send the idempotent binding frame instead of
                // compressing a frame the peer may be unable to route.
                if rebind.is_none() {
                    rebind = Some(b);
                }
                continue;
            }
            if exact.is_none()
                && let TargetAddr::Ip(a) = &b.target
                && *a == src
            {
                exact = Some(b);
            }
            if rebind.is_none() {
                let hit = match &b.target {
                    TargetAddr::Ip(a) => a.ip() == src.ip(),
                    TargetAddr::Domain(..) => b.resolved_contains(src.ip()),
                };
                if hit {
                    rebind = Some(b);
                }
            }
        }
        if let Some(b) = exact {
            return Some(SourceMatch::Exact(b.clone()));
        }
        // Same-IP different-port, a domain flow whose resolved address matches,
        // or a learned-but-unconfirmed source: needs one binding frame before
        // compression.
        rebind.map(|b| SourceMatch::Rebind(b.clone()))
    }

    /// Insert a binding; returns `false` when the table is full or the id is
    /// already present (duplicate open is handled by the registry).
    pub fn insert(&mut self, binding: Arc<FlowBinding>) -> bool {
        if self.find_id(binding.wire_id).is_some() {
            return true;
        }
        let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) else {
            return false;
        };
        *slot = Some(binding);
        true
    }

    /// Remove a binding by id (close/teardown paths).
    pub fn remove(&mut self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.as_ref().is_some_and(|b| b.wire_id == wire_id))?;
        entry.take()
    }

    /// Iterate live bindings.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<FlowBinding>> {
        self.entries.iter().flatten()
    }
}

/// Why a registry insert was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// The per-connection flow cap is reached.
    Full,
    /// The id is already bound to a different `(session, target)` — a
    /// mis-behaving or hostile peer; the caller drops and counts it.
    Conflict,
}

/// Per-connection forward table `wire_id -> binding`.
///
/// Besides the id map the registry keeps two indexes, both maintained under
/// the same write lock so they can never drift from `map`:
///
/// - `by_session`: `session -> [wire_id]`. `SESS_CLOSE` purging and the server's
///   reap paths need "every binding of this association"; without the index that
///   was a full `HashMap::retain` over every binding — expensive for a 7-byte
///   control frame and repeated three times per association exit. With it the
///   cost is O(flows of that session), and a close for an unknown session
///   touches nothing (the common duplicate/forged case).
/// - `server_flow_count`: lock-free count of server-owned bindings. The client
///   uplink's `find_server_flow` scan only runs when a server-owned flow could
///   exist at all; a normal uplink-only client never scans the 4096-entry map.
///
/// Both indexes are only mutated by insert/remove paths, all of which hold the
/// write lock; the count is mirrored into an atomic for the lock-free probe.
#[derive(Debug)]
pub struct FlowRegistry {
    cap: usize,
    map: RwLock<HashMap<u32, Arc<FlowBinding>, foldhash::fast::RandomState>>,
    by_session: RwLock<HashMap<u32, Vec<u32>, foldhash::fast::RandomState>>,
    server_flow_count: std::sync::atomic::AtomicUsize,
}

impl FlowRegistry {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            map: RwLock::new(HashMap::with_hasher(foldhash::fast::RandomState::default())),
            by_session: RwLock::new(HashMap::with_hasher(foldhash::fast::RandomState::default())),
            server_flow_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Record `binding` in the session index and the server-owned counter.
    /// Callers hold the map write lock; the session index has its own lock so a
    /// purge by session does not serialize against unrelated inserts (both are
    /// short critical sections, and no path takes them in the other order).
    fn index_binding(&self, binding: &Arc<FlowBinding>) {
        self.by_session
            .write()
            .entry(binding.session)
            .or_default()
            .push(binding.wire_id);
        if r2::wire_id_server_owned(binding.wire_id) {
            self.server_flow_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Remove `wire_id` from the session index and update the server-owned
    /// counter from the binding that was removed.
    fn unindex_binding(&self, binding: &FlowBinding) {
        {
            let mut by_session = self.by_session.write();
            if let Some(ids) = by_session.get_mut(&binding.session) {
                if let Some(pos) = ids.iter().position(|id| *id == binding.wire_id) {
                    ids.swap_remove(pos);
                }
                if ids.is_empty() {
                    by_session.remove(&binding.session);
                }
            }
        }
        if r2::wire_id_server_owned(binding.wire_id) {
            self.server_flow_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.read().is_empty()
    }

    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Whether one more binding would fit, measured with one read-lock hold.
    ///
    /// The client uplink probes this before its server-owned-flow scan: a full
    /// registry can only fall back to `INLINE`, so the scan (and the id
    /// allocation behind [`FlowRegistry::insert_new`]) is skipped entirely
    /// while the table is full. Advisory only — capacity can change before the
    /// caller inserts; [`FlowRegistry::insert_new`] re-checks it under the
    /// write lock and remains the authority.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.map.read().len() < self.cap
    }

    /// Insert a binding. Re-inserting the same id for the same
    /// `(session, target)` is the idempotent duplicate-open case and succeeds
    /// with the existing binding returned.
    pub fn insert(&self, binding: Arc<FlowBinding>) -> Result<Arc<FlowBinding>, RegistryError> {
        let mut map = self.map.write();
        if let Some(existing) = map.get(&binding.wire_id) {
            if existing.session == binding.session && existing.target == binding.target {
                return Ok(existing.clone());
            }
            return Err(RegistryError::Conflict);
        }
        if map.len() >= self.cap {
            return Err(RegistryError::Full);
        }
        map.insert(binding.wire_id, binding.clone());
        self.index_binding(&binding);
        Ok(binding)
    }

    /// Allocate the next wire id from `ids` and insert the new flow's binding,
    /// with both steps under the one write-lock hold that checked capacity.
    ///
    /// The cap is tested **before** [`FlowIds::alloc`]: wire ids are never
    /// reused, so an id allocated for an insert the registry then refuses is
    /// leaked from the sender's finite id space — repeated new-target attempts
    /// against a full table would eventually exhaust it and force every payload
    /// to `INLINE` even after the table drains. Checking capacity first makes a
    /// full registry cost no id at all.
    ///
    /// Idempotent-duplicate and conflict semantics match
    /// [`FlowRegistry::insert`]: an existing binding for the allocated id with
    /// the same `(session, target)` is returned as-is (the duplicate-open
    /// case), a different `(session, target)` is [`RegistryError::Conflict`].
    /// In production the monotonic allocator makes a collision impossible; the
    /// check is kept so this stays a drop-in replacement for `insert`.
    ///
    /// # Errors
    /// [`RegistryError::Full`] when the registry is at its cap or `ids` is
    /// exhausted; [`RegistryError::Conflict`] for an id already bound to a
    /// different `(session, target)`.
    pub fn insert_new(
        &self,
        ids: &FlowIds,
        session: u32,
        target: TargetAddr,
    ) -> Result<Arc<FlowBinding>, RegistryError> {
        let mut map = self.map.write();
        // Capacity before allocation: a refused insert must not consume an id
        // (see the doc above).
        if map.len() >= self.cap {
            return Err(RegistryError::Full);
        }
        // No id left is the same INLINE fail-safe as a full table.
        let Some(wire_id) = ids.alloc() else {
            return Err(RegistryError::Full);
        };
        let binding = FlowBinding::new_shared(wire_id, session, target);
        if let Some(existing) = map.get(&binding.wire_id) {
            if existing.session == binding.session && existing.target == binding.target {
                return Ok(existing.clone());
            }
            return Err(RegistryError::Conflict);
        }
        map.insert(binding.wire_id, binding.clone());
        self.index_binding(&binding);
        Ok(binding)
    }

    #[must_use]
    pub fn get(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        self.map.read().get(&wire_id).cloned()
    }

    /// Resolve a batch of wire ids under **one** read-lock hold.
    ///
    /// `ids` is a `(wire_id, slot)` pair list in encounter order; every slot is
    /// filled from the live map (`None` keeps the no-live-binding verdict).
    /// Duplicate ids pay one foldhash probe each instead of one lock handoff
    /// each — the TRAIN ingress uses this to replace one acquire per item (a
    /// 64-item frame was 64 read-lock acquire/release cycles, all on the
    /// packet path) with one acquire per frame. Callers that need per-item
    /// frames see the *same* `Arc` as single lookups would return: the map
    /// never stores two bindings for one id.
    pub fn get_batch(&self, ids: &mut [(u32, Option<Arc<FlowBinding>>)]) {
        let map = self.map.read();
        for (wire_id, slot) in ids.iter_mut() {
            *slot = map.get(wire_id).cloned();
        }
    }

    /// Find a **server-owned** binding for `(session, target)`. This is how the
    /// client's uplink reuses a flow the server opened for a full-cone /
    /// server-initiated reply source: without it the app's reply would open a
    /// second (client-owned) flow to the same address, losing compression.
    ///
    /// The counter probe is lock-free and makes an uplink-only client (the
    /// common case: no server-owned flows at all) skip the O(registry) scan
    /// entirely on every new target.
    #[must_use]
    pub fn find_server_flow(
        &self,
        session: u32,
        addr: &TargetAddrRef<'_>,
    ) -> Option<Arc<FlowBinding>> {
        if self
            .server_flow_count
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            return None;
        }
        self.map
            .read()
            .values()
            .find(|b| {
                r2::wire_id_server_owned(b.wire_id)
                    && b.session == session
                    && b.target.as_ref() == *addr
            })
            .cloned()
    }

    /// Number of live server-owned bindings (lock-free probe).
    #[must_use]
    pub fn server_flow_count(&self) -> usize {
        self.server_flow_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Remove and return a binding (close/teardown).
    pub fn remove(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        let mut map = self.map.write();
        let binding = map.remove(&wire_id)?;
        self.unindex_binding(&binding);
        Some(binding)
    }

    /// Remove every binding that belongs to `session`, returning how many were
    /// dropped. Used by `SESS_CLOSE` teardown so a closed association cannot
    /// leave receive-only bindings behind until the connection dies.
    ///
    /// O(bindings of this session): the per-session index means a duplicate or
    /// forged `SESS_CLOSE` for an unknown session costs one hash probe, not a
    /// walk over the whole per-connection table.
    pub fn remove_session(&self, session: u32) -> usize {
        let ids = match self.by_session.write().remove(&session) {
            Some(ids) => ids,
            None => return 0,
        };
        let mut map = self.map.write();
        let mut removed = 0usize;
        for wire_id in ids {
            if let Some(binding) = map.remove(&wire_id) {
                if r2::wire_id_server_owned(binding.wire_id) {
                    self.server_flow_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                removed += 1;
            }
        }
        removed
    }

    /// Remove every binding of every `session` in `sessions` under **one** map
    /// write-lock hold, returning how many were dropped.
    ///
    /// The server reap paths (idle/fair-share/session-pool sweeps, reader exit)
    /// remove a batch of sessions at once; doing so through
    /// [`Self::remove_session`] per entry paid one write lock and one map walk
    /// per session. This pays one lock for the whole batch.
    pub fn remove_sessions(&self, sessions: &[u32]) -> usize {
        if sessions.is_empty() {
            return 0;
        }
        let indexed: Vec<Vec<u32>> = {
            let mut by_session = self.by_session.write();
            sessions
                .iter()
                .filter_map(|s| by_session.remove(s))
                .collect()
        };
        let mut map = self.map.write();
        let mut removed = 0usize;
        for ids in indexed {
            for wire_id in ids {
                if let Some(binding) = map.remove(&wire_id) {
                    if r2::wire_id_server_owned(binding.wire_id) {
                        self.server_flow_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Close every binding and return how many were dropped. Used when the
    /// connection or a session is torn down.
    pub fn clear(&self) -> usize {
        let mut map = self.map.write();
        self.by_session.write().clear();
        self.server_flow_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let n = map.len();
        map.clear();
        n
    }
}

/// Sender-side monotonic wire-id allocator, one per endpoint owner per
/// connection. Ids are never reused; `None` means the id space is exhausted and
/// the caller must fall back to `INLINE`.
#[derive(Debug)]
pub struct FlowIds {
    next: AtomicU32,
    server_owned: bool,
}

impl FlowIds {
    #[must_use]
    pub fn new(server_owned: bool) -> Self {
        Self {
            next: AtomicU32::new(0),
            server_owned,
        }
    }

    /// Allocate the next wire id.
    pub fn alloc(&self) -> Option<u32> {
        let prev = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n >= MAX_LOCAL_FLOW_ID {
                    None
                } else {
                    Some(n + 1)
                }
            })
            .ok()?;
        r2::make_wire_id(prev + 1, self.server_owned)
    }

    /// Number of ids this allocator has handed out (for observability).
    #[must_use]
    pub fn allocated(&self) -> u32 {
        self.next.load(Ordering::Relaxed)
    }
}

/// Per-connection `HELLO`/`CAPS` handshake state.
#[derive(Debug)]
pub struct CtlState {
    /// Client side: the CAPS the server sent (once per connection).
    caps: RwLock<Option<Caps>>,
    /// Server side: a valid HELLO for this wire version was seen.
    hello_seen: AtomicBool,
    /// Rate budget for idempotent-but-costly CTL frames (`SESS_CLOSE`,
    /// `FLOW_CLOSE`, `FLOW_REJECT`). See [`CTL_MAX_PER_SEC`].
    ctl_rate: parking_lot::Mutex<CtlRate>,
}

/// One fixed one-second CTL-observation window.
#[derive(Debug)]
struct CtlRate {
    window_ms: u64,
    count: u32,
}

/// Maximum CTL frames one connection may have processed in a one-second
/// window before the excess is dropped (counted by the caller with the
/// connection's normal refusal counter).
///
/// The rev2 spec requires "control frames have rate/total caps"; before this,
/// a peer could send `SESS_CLOSE`/`FLOW_CLOSE` at line rate. Those opcodes are
/// idempotent but not free (even with the O(flows-of-session) purge, every
/// frame takes the session shard, the stager queue and the reassembler). The
/// cap is deliberately far above any legitimate control-plane rate (one
/// `SESS_CLOSE` per association exit ×3, plus an ACK per downlink rebind) and
/// only exists to stop a CPU-amplification loop.
pub const CTL_MAX_PER_SEC: u32 = 8_192;

impl Default for CtlState {
    fn default() -> Self {
        Self::new()
    }
}

impl CtlState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            caps: RwLock::new(None),
            hello_seen: AtomicBool::new(false),
            ctl_rate: parking_lot::Mutex::new(CtlRate {
                window_ms: 0,
                count: 0,
            }),
        }
    }

    pub fn set_caps(&self, caps: Caps) {
        *self.caps.write() = Some(caps);
    }

    #[must_use]
    pub fn caps(&self) -> Option<Caps> {
        *self.caps.read()
    }

    /// Record a HELLO with the expected wire version.
    pub fn mark_hello(&self) {
        self.hello_seen.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn hello_seen(&self) -> bool {
        self.hello_seen.load(Ordering::Relaxed)
    }

    /// Consume one unit of the per-connection CTL rate budget.
    ///
    /// Returns `false` when the peer exceeded [`CTL_MAX_PER_SEC`] in the
    /// current one-second window; the caller then drops the frame and counts
    /// it as a refusal. The window advances on the first CTL of a new second;
    /// `now_ms` is the caller's coarse/mono clock and only needs
    /// second-resolution monotonicity.
    pub fn ctl_allowed(&self, now_ms: u64) -> bool {
        let mut rate = self.ctl_rate.lock();
        if now_ms.saturating_sub(rate.window_ms) >= 1_000 {
            rate.window_ms = now_ms;
            rate.count = 0;
        }
        if rate.count >= CTL_MAX_PER_SEC {
            return false;
        }
        rate.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    fn v4_other(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), port)
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    fn binding(id_local: u32, session: u32, target: TargetAddr) -> Arc<FlowBinding> {
        let wire_id = r2::make_wire_id(id_local, false).unwrap();
        FlowBinding::new_shared(wire_id, session, target)
    }

    #[test]
    fn allocator_is_monotonic_and_owner_tagged() {
        let ids = FlowIds::new(false);
        let a = ids.alloc().unwrap();
        let b = ids.alloc().unwrap();
        assert_ne!(a, b);
        assert_eq!(r2::wire_id_local(a), 1);
        assert_eq!(r2::wire_id_local(b), 2);
        assert!(!r2::wire_id_server_owned(a));
        let sids = FlowIds::new(true);
        assert!(r2::wire_id_server_owned(sids.alloc().unwrap()));
        assert_eq!(sids.allocated(), 1);
    }

    #[test]
    fn allocator_exhaustion_returns_none() {
        let ids = FlowIds::new(false);
        ids.next.store(MAX_LOCAL_FLOW_ID, Ordering::Relaxed);
        assert!(ids.alloc().is_none());
    }

    #[test]
    fn binding_state_transitions() {
        let b = binding(1, 7, TargetAddr::Ip(v4(53)));
        assert_eq!(b.state(), FlowState::Opening);
        assert!(!b.is_open());
        b.mark_open();
        assert!(b.is_open());
        // Opening a second time is a no-op, never a transition back.
        b.mark_open();
        assert_eq!(b.state(), FlowState::Open);
        b.set_reply_src(v4(53));
        assert_eq!(b.reply_src(), Some(v4(53)));
        b.mark_closed();
        assert_eq!(b.state(), FlowState::Closed);
        b.mark_open();
        assert_eq!(b.state(), FlowState::Closed);
    }

    #[test]
    fn binding_resolved_set() {
        let b = binding(1, 7, TargetAddr::Domain("example.com".into(), 53));
        b.set_resolved(vec![v4(53), v6(53)]);
        assert_eq!(b.resolved_len(), 2);
        assert!(b.resolved_contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!b.resolved_contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
    }

    #[test]
    fn session_flows_find_insert_remove() {
        let mut flows = SessionFlows::new();
        let b = binding(1, 7, TargetAddr::Ip(v4(53)));
        assert!(flows.insert(b.clone()));
        assert_eq!(flows.len(), 1);
        assert!(flows.find(&TargetAddrRef::Ip(v4(53))).is_some());
        assert!(flows.find(&TargetAddrRef::Ip(v4(54))).is_none());
        assert!(flows.find_id(b.wire_id).is_some());
        assert!(flows.remove(b.wire_id).is_some());
        assert!(flows.is_empty());
        // Duplicate insert is idempotent.
        assert!(flows.insert(b.clone()));
        assert!(flows.insert(b));
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn session_flows_full_falls_back() {
        let mut flows = SessionFlows::new();
        for i in 1..=R2_MAX_FLOWS_PER_SESSION as u32 {
            let b = binding(i, 7, TargetAddr::Ip(v4(1000 + i as u16)));
            assert!(flows.insert(b));
        }
        assert!(flows.is_full());
        let extra = binding(999, 7, TargetAddr::Ip(v4(9999)));
        assert!(!flows.insert(extra));
    }

    #[test]
    fn source_matching_exact_rebind_and_domain() {
        let mut flows = SessionFlows::new();
        let ip = binding(1, 7, TargetAddr::Ip(v4(53)));
        assert!(flows.insert(ip.clone()));
        assert!(matches!(
            flows.match_source(v4(53)),
            Some(SourceMatch::Exact(_))
        ));
        assert!(matches!(
            flows.match_source(v4(54)),
            Some(SourceMatch::Rebind(_))
        ));
        assert!(flows.match_source(v4_other(53)).is_none());

        let dom = binding(2, 7, TargetAddr::Domain("example.com".into(), 53));
        dom.set_resolved(vec![v4_other(53)]);
        assert!(flows.insert(dom));
        assert!(matches!(
            flows.match_source(v4_other(53)),
            Some(SourceMatch::Rebind(_))
        ));

        // A learned reply source only becomes an exact match once the peer
        // confirmed the binding frame; before that the server must keep
        // re-sending the idempotent OPEN|SRC.
        let learned = binding(3, 7, TargetAddr::Ip(v4(88)));
        learned.set_reply_src(v4(89));
        assert!(!learned.reply_src_acked());
        assert!(flows.insert(learned.clone()));
        assert!(matches!(
            flows.match_source(v4(89)),
            Some(SourceMatch::Rebind(_))
        ));
        learned.mark_reply_src_acked();
        assert!(matches!(
            flows.match_source(v4(89)),
            Some(SourceMatch::Exact(_))
        ));

        // An IP flow whose target is the exact reply source needs no
        // confirmation: the peer can deliver from the target it already knows.
        let same = binding(4, 7, TargetAddr::Ip(v4(90)));
        same.set_reply_src(v4(90));
        assert!(flows.insert(same));
        assert!(matches!(
            flows.match_source(v4(90)),
            Some(SourceMatch::Exact(_))
        ));
    }

    #[test]
    fn registry_insert_get_conflict_full() {
        let reg = FlowRegistry::new(2);
        let a = binding(1, 7, TargetAddr::Ip(v4(53)));
        let a2 = FlowBinding::new_shared(a.wire_id, 7, TargetAddr::Ip(v4(53)));
        assert!(reg.insert(a.clone()).is_ok());
        // Same id + same session + same target: idempotent duplicate open.
        let ok = reg.insert(a2).unwrap();
        assert_eq!(ok.wire_id, a.wire_id);
        assert_eq!(reg.len(), 1);
        // Same id, different target: conflict, never overwrite.
        let conflict = FlowBinding::new_shared(a.wire_id, 7, TargetAddr::Ip(v4(54)));
        assert!(matches!(reg.insert(conflict), Err(RegistryError::Conflict)));
        // Different id still fits.
        let b = binding(2, 7, TargetAddr::Ip(v4(54)));
        assert!(reg.insert(b).is_ok());
        assert_eq!(reg.len(), 2);
        // Full.
        let c = binding(3, 8, TargetAddr::Ip(v4(55)));
        assert!(matches!(reg.insert(c), Err(RegistryError::Full)));
        assert!(reg.remove(a.wire_id).is_some());
        assert!(reg.get(a.wire_id).is_none());
        assert_eq!(reg.clear(), 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_insert_new_allocates_an_id_only_when_there_is_room() {
        let ids = FlowIds::new(false);
        let reg = FlowRegistry::new(2);
        assert!(reg.has_capacity());
        let a = reg.insert_new(&ids, 7, TargetAddr::Ip(v4(53))).unwrap();
        let b = reg.insert_new(&ids, 7, TargetAddr::Ip(v4(54))).unwrap();
        // The normal path allocates monotonically, client-owned ids.
        assert_eq!(r2::wire_id_local(a.wire_id), 1);
        assert_eq!(r2::wire_id_local(b.wire_id), 2);
        assert!(!r2::wire_id_server_owned(a.wire_id));
        assert_eq!(ids.allocated(), 2);
        assert_eq!(reg.len(), 2);
        assert!(!reg.has_capacity(), "premise: the registry is full");
        // Full: refused with the fail-safe and *no* id consumed.
        assert_eq!(
            reg.insert_new(&ids, 7, TargetAddr::Ip(v4(55))).unwrap_err(),
            RegistryError::Full
        );
        assert_eq!(ids.allocated(), 2, "a full registry must not consume an id");
        // A second attempt costs nothing either (the old shape leaked one id
        // per attempt against a full table).
        assert!(reg.insert_new(&ids, 7, TargetAddr::Ip(v4(56))).is_err());
        assert_eq!(ids.allocated(), 2);
        // Freeing a slot restores capacity; the next insert takes the next id.
        assert!(reg.remove(b.wire_id).is_some());
        assert!(reg.has_capacity());
        let c = reg.insert_new(&ids, 7, TargetAddr::Ip(v4(55))).unwrap();
        assert_eq!(r2::wire_id_local(c.wire_id), 3);
        assert_eq!(ids.allocated(), 3);
    }

    #[test]
    fn registry_insert_new_keeps_insert_duplicate_and_conflict_semantics() {
        let reg = FlowRegistry::new(8);
        // Seed the map with id 1 for (7, v4(53)) as the receiver `insert` path
        // would, then force the next allocation to hand out that same id.
        let seeded = binding(1, 7, TargetAddr::Ip(v4(53)));
        assert!(reg.insert(seeded.clone()).is_ok());
        let dup_ids = FlowIds::new(false);
        dup_ids.next.store(0, Ordering::Relaxed);
        let dup = reg.insert_new(&dup_ids, 7, TargetAddr::Ip(v4(53))).unwrap();
        assert_eq!(dup.wire_id, seeded.wire_id);
        assert!(
            Arc::ptr_eq(&dup, &seeded),
            "the existing binding is returned"
        );
        assert_eq!(reg.len(), 1, "the duplicate open inserts nothing new");

        // Same forced id, different target: conflict, never overwrite.
        let conflict_ids = FlowIds::new(false);
        conflict_ids.next.store(0, Ordering::Relaxed);
        assert_eq!(
            reg.insert_new(&conflict_ids, 7, TargetAddr::Ip(v4(54)))
                .unwrap_err(),
            RegistryError::Conflict
        );
        assert_eq!(reg.len(), 1);
        assert_eq!(
            reg.get(seeded.wire_id).unwrap().target,
            TargetAddr::Ip(v4(53))
        );
    }

    #[test]
    fn registry_insert_new_reports_full_for_an_exhausted_allocator() {
        let ids = FlowIds::new(false);
        ids.next.store(MAX_LOCAL_FLOW_ID, Ordering::Relaxed);
        let reg = FlowRegistry::new(8);
        assert_eq!(
            reg.insert_new(&ids, 7, TargetAddr::Ip(v4(53))).unwrap_err(),
            RegistryError::Full,
            "an exhausted id space is the same INLINE fail-safe as a full table"
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_finds_server_owned_flows_only() {
        let reg = FlowRegistry::new(8);
        let client_id = r2::make_wire_id(1, false).unwrap();
        let server_id = r2::make_wire_id(1, true).unwrap();
        let client = FlowBinding::new_shared(client_id, 7, TargetAddr::Ip(v4(53)));
        let server = FlowBinding::new_shared(server_id, 7, TargetAddr::Ip(v4(53)));
        reg.insert(client).unwrap();
        assert!(
            reg.find_server_flow(7, &TargetAddrRef::Ip(v4(53)))
                .is_none()
        );
        reg.insert(server.clone()).unwrap();
        let found = reg.find_server_flow(7, &TargetAddrRef::Ip(v4(53))).unwrap();
        assert_eq!(found.wire_id, server_id);
        // Wrong session or target never matches.
        assert!(
            reg.find_server_flow(8, &TargetAddrRef::Ip(v4(53)))
                .is_none()
        );
        assert!(
            reg.find_server_flow(7, &TargetAddrRef::Ip(v4(54)))
                .is_none()
        );
    }

    #[test]
    fn registry_remove_session() {
        let reg = FlowRegistry::new(8);
        let a = binding(1, 7, TargetAddr::Ip(v4(53)));
        let b = binding(2, 7, TargetAddr::Ip(v4(54)));
        let c = binding(3, 8, TargetAddr::Ip(v4(55)));
        assert!(reg.insert(a).is_ok());
        assert!(reg.insert(b).is_ok());
        assert!(reg.insert(c).is_ok());
        assert_eq!(reg.remove_session(7), 2);
        assert_eq!(reg.len(), 1);
        // A duplicate/forged close for an unknown session costs one probe and
        // must not touch the remaining binding.
        assert_eq!(reg.remove_session(7), 0);
        assert_eq!(reg.remove_session(9_999), 0);
        assert_eq!(reg.len(), 1);
        assert!(
            reg.get(reg.map.read().keys().next().copied().unwrap())
                .is_some()
        );
        // The index stays consistent for the survivor: a batch remove sees it.
        assert_eq!(reg.remove_sessions(&[8]), 1);
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.clear(), 0);
    }

    #[test]
    fn registry_remove_sessions_batches_one_lock() {
        let reg = FlowRegistry::new(16);
        for (local, session) in [(1u32, 7u32), (2, 7), (3, 8), (4, 9), (5, 9)] {
            let b = binding(local, session, TargetAddr::Ip(v4(50 + local as u16)));
            assert!(reg.insert(b).is_ok());
        }
        assert_eq!(reg.remove_sessions(&[7, 9, 42]), 4);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.remove_sessions(&[]), 0);
        assert_eq!(reg.remove_sessions(&[8]), 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_server_flow_count_and_fast_skip() {
        let reg = FlowRegistry::new(8);
        assert_eq!(reg.server_flow_count(), 0);
        assert!(
            reg.find_server_flow(7, &TargetAddrRef::Ip(v4(53)))
                .is_none()
        );
        let client = binding(1, 7, TargetAddr::Ip(v4(53)));
        let server = FlowBinding::new_shared(
            r2::make_wire_id(2, true).unwrap(),
            7,
            TargetAddr::Ip(v4(53)),
        );
        assert!(reg.insert(client.clone()).is_ok());
        assert_eq!(
            reg.server_flow_count(),
            0,
            "client-owned flows are not counted"
        );
        assert!(reg.insert(server).is_ok());
        assert_eq!(reg.server_flow_count(), 1);
        assert!(
            reg.find_server_flow(7, &TargetAddrRef::Ip(v4(53)))
                .is_some()
        );
        assert!(reg.remove(client.wire_id).is_some());
        assert_eq!(reg.server_flow_count(), 1);
        assert_eq!(reg.remove_session(7), 1);
        assert_eq!(reg.server_flow_count(), 0);
        assert!(
            reg.find_server_flow(7, &TargetAddrRef::Ip(v4(53)))
                .is_none()
        );
    }

    #[test]
    fn ctl_rate_budget_is_per_second_and_bounded() {
        let s = CtlState::new();
        // A full window of CTLs is allowed; the next one is refused.
        for _ in 0..CTL_MAX_PER_SEC {
            assert!(s.ctl_allowed(1_000));
        }
        assert!(!s.ctl_allowed(1_000));
        // The next second starts a fresh budget.
        assert!(s.ctl_allowed(2_000));
        assert!(s.ctl_allowed(2_001));
    }

    #[test]
    fn ctl_state_handshake() {
        let s = CtlState::new();
        assert!(s.caps().is_none());
        assert!(!s.hello_seen());
        s.mark_hello();
        assert!(s.hello_seen());
        s.set_caps(Caps::default());
        assert_eq!(s.caps(), Some(Caps::default()));
    }
}
