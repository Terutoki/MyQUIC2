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

use arc_swap::ArcSwapOption;
use parking_lot::RwLock;

use super::addr::{TargetAddr, TargetAddrRef};
use super::r2::{self, Caps};

/// Per-session flow cap. Mirrors the v0.2.0 `MQP3_MAX_FLOWS`; a full table
/// falls back to `INLINE` frames and never blocks the association.
pub const R2_MAX_FLOWS_PER_SESSION: usize = 64;

/// Per-connection live-flow cap (admission-charged). The codec's `CAPS` frame
/// makes this negotiable; this is the default both endpoints start from.
pub const R2_MAX_FLOWS_PER_CONN: usize = 4096;

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
/// atomics; only `resolved` takes a lock and only on DNS install/rebind.
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
    /// Server side, domain flows: addresses the name resolved to. Used to
    /// decide whether a reply source belongs to this flow (and may be
    /// compressed) before an exact source binding exists.
    resolved: RwLock<Vec<SocketAddr>>,
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
            resolved: RwLock::new(Vec::new()),
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

    pub fn set_reply_src(&self, src: SocketAddr) {
        self.reply_src.store(Some(Arc::new(src)));
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
        self.resolved.read().first().copied()
    }

    /// Install the resolved address set of a domain flow (server side). An
    /// empty set means "DNS failed"; the binding is then rejected.
    pub fn set_resolved(&self, addrs: Vec<SocketAddr>) {
        *self.resolved.write() = addrs;
    }

    #[must_use]
    pub fn resolved_len(&self) -> usize {
        self.resolved.read().len()
    }

    /// Whether `ip` is one of the resolved addresses of a domain flow.
    #[must_use]
    pub fn resolved_contains(&self, ip: IpAddr) -> bool {
        self.resolved.read().iter().any(|a| a.ip() == ip)
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
    #[must_use]
    pub fn match_source(&self, src: SocketAddr) -> Option<SourceMatch> {
        // A learned reply source is the strongest match (covers domain targets
        // and port changes after the first rebind).
        if let Some(b) = self
            .entries
            .iter()
            .flatten()
            .find(|b| b.reply_src() == Some(src))
        {
            return Some(SourceMatch::Exact(b.clone()));
        }
        // Exact IP flow target.
        if let Some(b) = self.entries.iter().flatten().find(|b| match &b.target {
            TargetAddr::Ip(a) => *a == src,
            TargetAddr::Domain(..) => false,
        }) {
            return Some(SourceMatch::Exact(b.clone()));
        }
        // Same-IP different-port, or a domain flow whose resolved address
        // matches: needs one inline binding frame before compression.
        if let Some(b) = self.entries.iter().flatten().find(|b| match &b.target {
            TargetAddr::Ip(a) => a.ip() == src.ip(),
            TargetAddr::Domain(..) => b.resolved_contains(src.ip()),
        }) {
            return Some(SourceMatch::Rebind(b.clone()));
        }
        None
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
#[derive(Debug)]
pub struct FlowRegistry {
    cap: usize,
    map: RwLock<HashMap<u32, Arc<FlowBinding>, foldhash::fast::RandomState>>,
}

impl FlowRegistry {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            map: RwLock::new(HashMap::with_hasher(foldhash::fast::RandomState::default())),
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
        Ok(binding)
    }

    #[must_use]
    pub fn get(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        self.map.read().get(&wire_id).cloned()
    }

    /// Find a **server-owned** binding for `(session, target)`. This is how the
    /// client's uplink reuses a flow the server opened for a full-cone /
    /// server-initiated reply source: without it the app's reply would open a
    /// second (client-owned) flow to the same address, losing compression.
    /// Scans the live map, so it is only for the new-target path, never the
    /// per-payload path.
    #[must_use]
    pub fn find_server_flow(
        &self,
        session: u32,
        addr: &TargetAddrRef<'_>,
    ) -> Option<Arc<FlowBinding>> {
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

    /// Remove and return a binding (close/teardown).
    pub fn remove(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        self.map.write().remove(&wire_id)
    }

    /// Remove every binding that belongs to `session`, returning how many were
    /// dropped. Used by `SESS_CLOSE` teardown so a closed association cannot
    /// leave receive-only bindings behind until the connection dies.
    pub fn remove_session(&self, session: u32) -> usize {
        let mut map = self.map.write();
        let before = map.len();
        map.retain(|_, b| b.session != session);
        before - map.len()
    }

    /// Close every binding and return how many were dropped. Used when the
    /// connection or a session is torn down.
    pub fn clear(&self) -> usize {
        let mut map = self.map.write();
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
}

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

        // A learned reply source becomes an exact match.
        let learned = binding(3, 7, TargetAddr::Ip(v4(88)));
        learned.set_reply_src(v4(89));
        assert!(flows.insert(learned));
        assert!(matches!(
            flows.match_source(v4(89)),
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
        assert!(
            reg.get(reg.map.read().keys().next().copied().unwrap())
                .is_some()
        );
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
