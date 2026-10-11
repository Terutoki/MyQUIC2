/// Process-wide UDP DATAGRAM drop accounting.
///
/// Every dropped datagram is a packet the peer's own UDP stack would have
/// carried, so these counters are the honest measure of how much the tunnel is
/// degrading UDP. Both drop paths used to be `debug!`-only, which made a
/// silent 100 % loss of large datagrams invisible at the default log level.
pub mod dgram_drops {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Payload did not fit the current path's DATAGRAM budget (oversized).
    pub static TOO_LARGE: AtomicU64 = AtomicU64::new(0);
    /// Send buffer full: dropped per UDP semantics (quinn `Blocked`).
    pub static BUFFER_FULL: AtomicU64 = AtomicU64::new(0);
    /// Session budget exhausted: dropped before a socket was created (UDP
    /// semantics, fail-closed under flood). This is the *global* session pool;
    /// a connection that hit only its own fair share of it is counted in
    /// `FAIR_SHARE` instead, and the resolver's separate permit pool is counted
    /// in `DNS_BUDGET` — so the three readings cannot be confused in the 60 s
    /// line.
    pub static SESSION_FULL: AtomicU64 = AtomicU64::new(0);
    /// The connection's own fair share of the session budget was reached while
    /// the process-wide pool still had room. Split from `SESSION_FULL` because
    /// the two mean different things to an operator: `SESSION_FULL` is "the host
    /// is out of capacity", this is "one busy client hit its cap". A datagram
    /// dropped here is still lost, so it counts in `lost()`.
    pub static FAIR_SHARE: AtomicU64 = AtomicU64::new(0);
    /// The **DNS slow-path limiter** (1024 permits, shared with the server's
    /// TCP dial path) was exhausted, so this datagram was dropped before any
    /// resolution was attempted.
    ///
    /// Split from `SESSION_FULL` because the two mean opposite things to an
    /// operator: `SESSION_FULL` is "the host is out of session capacity",
    /// while this is "the resolver is slow or failing and its permit pool is
    /// full". Charging a resolver outage to the session budget made an
    /// unrelated fault look like capacity exhaustion in the 60 s line — and on
    /// the TCP side the same pool's exhaustion silently reset a CONNECT.
    pub static DNS_BUDGET: AtomicU64 = AtomicU64::new(0);
    /// No usable egress connection at the moment the datagram was ready: its
    /// egress class's dedicated UDP connection had not come up yet, was
    /// reconnecting, or the class's single-flight refresh was already owned by
    /// another thread. The client drops the datagram (UDP semantics) — before
    /// this counter existed that loss was a bare `continue` with no counter and
    /// no log at all.
    ///
    /// On the server there is no egress-connection choice, so a non-zero value
    /// here is client-only.
    pub static NO_EGRESS: AtomicU64 = AtomicU64::new(0);
    /// The egress connection was gone (or the peer stopped offering DATAGRAM
    /// support) at send time. The datagram is lost; the client invalidates its
    /// cached egress handle and the next datagram re-picks a connection.
    pub static EGRESS_DEAD: AtomicU64 = AtomicU64::new(0);
    /// An inbound relay datagram named a session this process has no
    /// association for: the association was reaped (or its control connection
    /// closed) while the server's session was still live and its target kept
    /// answering. Client-only, and *not* a tunnel degradation — the peer is
    /// entitled to send until its own 180 s reap — but it used to be dropped in
    /// total silence while every sibling drop path was counted, which made "the
    /// 60 s budget line is clean" a claim the code could not support.
    pub static UNKNOWN_SESS: AtomicU64 = AtomicU64::new(0);
    /// A datagram refused on policy, not on budget: a negatively-cached name,
    /// an SSRF-filtered target, or the reserved session id 0. Each used to be
    /// dropped with no counter (or, for sess 0, charged to `SESSION_FULL`,
    /// which means "budget exhausted" and misreported malformed input as a
    /// resource event). Batched like the other flood-type counters: an app
    /// retrying a refused target is exactly the flood case batching exists for.
    pub static REFUSED: AtomicU64 = AtomicU64::new(0);
    /// A new UDP session could not be set up: the kernel refused a session
    /// socket (fd or memory exhaustion), or the freshly spawned reply reader
    /// exited before the entry was published and the insert was rolled back.
    /// The datagram is lost. Server-only, and counted apart from the budget
    /// counters because this is a *host-resource* failure, not a cap the peer
    /// hit — before this counter both paths were silent `.ok()?` returns, so
    /// an fd-exhausted server looked idle. Batched like the other flood-type
    /// counters (the flood case is exactly fd exhaustion); the call site also
    /// emits one rate-limited warning.
    pub static SESS_CREATE_FAILED: AtomicU64 = AtomicU64::new(0);

    /// Every drop counter in one read, so the 60 s report cannot silently omit
    /// one. Named fields rather than a tuple: a tuple read at two call sites
    /// is exactly the shape that pairs a socket with the wrong field elsewhere
    /// in this codebase (see the client's `SessEntry` note).
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DropSnapshot {
        pub too_large: u64,
        pub buffer_full: u64,
        pub session_full: u64,
        pub dns_budget: u64,
        pub fair_share: u64,
        pub no_egress: u64,
        pub egress_dead: u64,
        pub unknown_sess: u64,
        pub refused: u64,
        pub sess_create_failed: u64,
    }

    impl DropSnapshot {
        pub fn since(&self, prev: &Self) -> Self {
            let d = |a: u64, b: u64| a.saturating_sub(b);
            Self {
                too_large: d(self.too_large, prev.too_large),
                buffer_full: d(self.buffer_full, prev.buffer_full),
                session_full: d(self.session_full, prev.session_full),
                dns_budget: d(self.dns_budget, prev.dns_budget),
                fair_share: d(self.fair_share, prev.fair_share),
                no_egress: d(self.no_egress, prev.no_egress),
                egress_dead: d(self.egress_dead, prev.egress_dead),
                unknown_sess: d(self.unknown_sess, prev.unknown_sess),
                refused: d(self.refused, prev.refused),
                sess_create_failed: d(self.sess_create_failed, prev.sess_create_failed),
            }
        }

        /// Drops that mean "the tunnel degraded this packet", i.e. everything
        /// except a datagram that was already destined for a dead connection's
        /// peers. Used by the reporter to decide whether the line is worth
        /// printing at all.
        ///
        /// `unknown_sess` is deliberately *not* counted here. It is a late reply
        /// to a session this side already closed, not a packet the tunnel failed
        /// to carry, and folding it in would make every ordinary association
        /// teardown look like loss.
        pub fn lost(&self) -> u64 {
            self.too_large
                .saturating_add(self.buffer_full)
                .saturating_add(self.session_full)
                .saturating_add(self.dns_budget)
                .saturating_add(self.fair_share)
                .saturating_add(self.no_egress)
                .saturating_add(self.egress_dead)
                .saturating_add(self.refused)
                .saturating_add(self.sess_create_failed)
        }
    }

    /// Totals since process start. Every counter is a direct `fetch_add`
    /// (see `bump`), so the next report shows every drop including a
    /// short low-rate episode. One RMW per *dropped* datagram (never per
    /// sent datagram) is the price for numbers that have to be true.
    pub fn snapshot() -> DropSnapshot {
        flush_locals();
        DropSnapshot {
            too_large: TOO_LARGE.load(Ordering::Relaxed),
            buffer_full: BUFFER_FULL.load(Ordering::Relaxed),
            session_full: SESSION_FULL.load(Ordering::Relaxed),
            dns_budget: DNS_BUDGET.load(Ordering::Relaxed),
            fair_share: FAIR_SHARE.load(Ordering::Relaxed),
            no_egress: NO_EGRESS.load(Ordering::Relaxed),
            egress_dead: EGRESS_DEAD.load(Ordering::Relaxed),
            unknown_sess: UNKNOWN_SESS.load(Ordering::Relaxed),
            refused: REFUSED.load(Ordering::Relaxed),
            sess_create_failed: SESS_CREATE_FAILED.load(Ordering::Relaxed),
        }
    }

    fn flush_locals() {
        L_TOO_LARGE.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                TOO_LARGE.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_BUFFER_FULL.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                BUFFER_FULL.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_SESSION_FULL.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                SESSION_FULL.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_FAIR_SHARE.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                FAIR_SHARE.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_UNKNOWN_SESS.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                UNKNOWN_SESS.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_REFUSED.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                REFUSED.fetch_add(v, Ordering::Relaxed);
            }
        });
        L_SESS_CREATE_FAILED.with(|c| {
            let v = c.replace(0);
            if v != 0 {
                SESS_CREATE_FAILED.fetch_add(v, Ordering::Relaxed);
            }
        });
    }

    thread_local! {
        static L_TOO_LARGE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_BUFFER_FULL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_SESSION_FULL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_FAIR_SHARE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_UNKNOWN_SESS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_REFUSED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static L_SESS_CREATE_FAILED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[allow(dead_code)]
    fn batched(
        counter: &AtomicU64,
        local: &'static std::thread::LocalKey<std::cell::Cell<u64>>,
    ) -> u64 {
        let v = local.with(|c| {
            let v = c.get().wrapping_add(1);
            if v >= 64 {
                c.set(0);
                64
            } else {
                c.set(v);
                0
            }
        });
        if v != 0 {
            counter.fetch_add(v, Ordering::Relaxed).saturating_add(v)
        } else {
            counter.load(Ordering::Relaxed).saturating_add(1)
        }
    }

    /// `counter` must be one of this module's statics. All counters use a
    /// direct `fetch_add`: one RMW per *dropped* datagram (never per sent
    /// datagram) is the price for numbers the 60 s report can trust. Batching
    /// hid short outages in a worker thread's cell indefinitely (the reporter's
    /// `snapshot` only flushes its own cells, and a thread exit drops its
    /// pending count), so a low-rate `REFUSED`/`SESSION_FULL` could read 0;
    /// `egress_drops_are_exact_across_threads` pins the exactness.
    pub fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    /// Which egress state a warning is about. An enum rather than a reason
    /// string: the slot is picked from it, and a typo in a substring match would
    /// silently merge two different faults into one rate limit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EgressDrop {
        /// No usable egress connection at all: the datagram's egress class had
        /// no dedicated connection up, or that class's single-flight refresh was
        /// owned by another thread.
        NoConnection,
        /// The connection was gone at send time.
        ConnectionLost,
        /// The peer never negotiated DATAGRAM support, so this connection can
        /// never carry a datagram. Its own slot: the condition is static rather
        /// than transient, the remedy is a configuration change rather than a
        /// reconnect, and sharing `ConnectionLost`'s line made the log read
        /// "egress connection lost … peer does not support DATAGRAM" about a
        /// connection that was up and healthy.
        Unsupported,
    }

    /// Rate-limited, once-per-state warning for a datagram dropped because its
    /// **egress connection** was unusable.
    ///
    /// Split from `warn_datagram_drop`: that helper's text is about the packet
    /// ("a packet this size would have been carried by a direct UDP path") and its
    /// three slots are shared with the size/buffer cases, so folding egress drops
    /// into them would both misdescribe the fault and let one class starve the
    /// other's warning. Each state gets a slot, limited to one line per
    /// `DROP_WARN_INTERVAL_MS`, so the *first* drop of an outage is in the log
    /// immediately — before this existed the whole fail-closed loss mode was
    /// visible only in the 60 s aggregate, and (for a short outage) sometimes not
    /// even there, because of the batching bound.
    ///
    /// Costs one clock read per *dropped* datagram (the rate limiter needs it; it
    /// reads the coarse epoch, so the cost is a relaxed load in the common case)
    /// and builds `detail` only when a line is actually emitted.
    pub fn warn_egress_drop(kind: EgressDrop, total: u64, detail: impl FnOnce() -> String) {
        use crate::stats::{claim_drop_warning, NEVER_WARNED};
        static LAST_NO_CONNECTION: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        static LAST_LOST: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        static LAST_UNSUPPORTED: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        let (slot, reason) = match kind {
            EgressDrop::NoConnection => (&LAST_NO_CONNECTION, "no usable udp egress connection"),
            EgressDrop::ConnectionLost => (&LAST_LOST, "udp egress connection lost at send"),
            EgressDrop::Unsupported => (
                &LAST_UNSUPPORTED,
                "udp egress peer does not support DATAGRAM",
            ),
        };
        if !claim_drop_warning(slot) {
            return;
        }
        let detail = detail();
        tracing::warn!("udp datagram dropped ({reason}): {total} so far{detail}");
    }

    /// Which **oversize-receive** fault a warning is about.
    ///
    /// A datagram the receiving socket could not hold is not a send-side drop:
    /// the kernel already truncated it, so the payload above the protocol cap is
    /// gone and the peer never learns. It is also the one drop class a *remote*
    /// party chooses the rate of — a target that answers with a datagram above
    /// [`UDP_RECV_MAX`](crate::UDP_RECV_MAX), or an app that sends one — which is
    /// why both directions keep their own rate-limited slot. Unthrottled, each
    /// such packet formatted and emitted a line through
    /// `tracing_subscriber`'s process-wide writer lock, i.e. the log itself
    /// became the per-packet cost on a path a peer controls.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OversizeRecv {
        /// A target's reply was larger than the session receive buffer
        /// (server-side session reader).
        TargetReply,
        /// The app sent a datagram larger than the relay receive buffer
        /// (client-side UDP association loop).
        AppDatagram,
    }

    /// Rate-limited (at most one line per [`DROP_WARN_INTERVAL_MS`] per
    /// direction) warning for a truncated oversize receive.
    ///
    /// Costs one coarse-epoch read per *oversized* datagram — never on the
    /// steady path — and builds `detail` only when a line is actually emitted.
    pub fn warn_oversize_recv(kind: OversizeRecv, total: u64, detail: impl FnOnce() -> String) {
        use crate::stats::{claim_drop_warning, NEVER_WARNED};
        static LAST_TARGET_REPLY: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        static LAST_APP_DGRAM: AtomicU64 = AtomicU64::new(NEVER_WARNED);
        let (slot, which) = match kind {
            OversizeRecv::TargetReply => (&LAST_TARGET_REPLY, "target reply"),
            OversizeRecv::AppDatagram => (&LAST_APP_DGRAM, "app datagram"),
        };
        if !claim_drop_warning(slot) {
            return;
        }
        let detail = detail();
        tracing::warn!(
            "{which} above {} B truncated and dropped: {total} so far{detail}; raise \
             MQP_FRAG_MAX_PAYLOAD to carry payloads this size",
            crate::UDP_RECV_MAX,
        );
    }
}
