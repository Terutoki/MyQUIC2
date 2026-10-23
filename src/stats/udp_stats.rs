//! UDP relay activity, so "is my UDP traffic actually going through the tunnel,
//! and how large does it get?" is answerable from the log rather than a packet
//! capture — on a QUIC tunnel a capture can only ever show ciphertext.
//!
//! [`UdpSnapshot::max_payload`] is a **high-water mark, not a limit**: it is the
//! empirical answer to "is `MQP_FRAG_MAX_PAYLOAD` big enough for this
//! deployment", measured on real traffic instead of argued from protocol specs.
//! A deployment whose high-water mark stays under `UDP_RECV_MAX` never needs a
//! larger cap, whatever its workload is.
use std::sync::atomic::{AtomicU64, Ordering};

static DATAGRAMS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static FRAGMENTED: AtomicU64 = AtomicU64::new(0);
static MAX_PAYLOAD: AtomicU64 = AtomicU64::new(0);
static SESSIONS: AtomicU64 = AtomicU64::new(0);
static REASSEMBLY_EXPIRED: AtomicU64 = AtomicU64::new(0);
static REASSEMBLY_EVICTED: AtomicU64 = AtomicU64::new(0);
static UNSOLICITED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static L_DATAGRAMS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static L_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Fragmented payloads counted by [`fragmented`].
    ///
    /// Batched like `L_DATAGRAMS`: the counter used to be a direct
    /// `FRAGMENTED.fetch_add` on the per-payload send path, so a workload that
    /// fragments most of its packets (the shipped 1200 B initial MTU makes
    /// every payload above ~1150 B a two-frame send) paid one process-wide
    /// cache-line RMW per datagram from every relay thread — exactly the
    /// contention the sibling counters avoid at 1/256. It is a *separate*
    /// counter from the datagrams cell because only some payloads fragment.
    static L_FRAGMENTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// `udp_full_cone` inbound datagrams whose source was not on the session's
    /// allowlist, counted by [`unsolicited`]. Batched with the same threshold
    /// for the same reason: a busy full-cone session can take these per packet.
    static L_UNSOLICITED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// This thread's payload high-water mark. It guards the shared
    /// `MAX_PAYLOAD` read on the per-payload path: the global is only
    /// touched when this thread sees a payload larger than any it has
    /// already recorded, so a steady flow costs one Cell compare and no
    /// shared cache-line access at all.
    static L_MAX_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Coarse-epoch stamp of the last time-based publish, per thread.
    ///
    /// The count thresholds below only fire after 256 events, so a low-rate
    /// worker (a keepalive flow, DNS-style request/response) could hold a
    /// pending count for arbitrarily long — the 60 s reporter runs on another
    /// thread and cannot flush these cells. A time gate at
    /// [`PUBLISH_INTERVAL_MS`] bounds that lag to ~2 s (the coarse clock lags
    /// one tick), for one cheap atomic read per event. [`NEVER_PUBLISHED`]
    /// means "no publish yet": the first event on a thread publishes even at
    /// low rates.
    static L_LAST_PUBLISH_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(NEVER_PUBLISHED) };
}

/// Thread-local flush thresholds. One shared atomic RMW per 256 records still
/// keeps a flood off the cache line; the *time*-based publish below covers the
/// low-rate case the count alone cannot: at 17 pps a 256-count threshold bounds
/// the lag to ~15 s, at 1 pps it was 4+ minutes, and a thread that never reached
/// 256 never published at all. [`PUBLISH_INTERVAL_MS`] bounds the lag regardless
/// of rate, and the count thresholds remain as the flood amortiser.
const FLUSH_DATAGRAMS: u64 = 256;
const FLUSH_BYTES: u64 = 256 * 1024;

/// Maximum lag of the time-based publish, in milliseconds.
///
/// The check reads [`coarse_millis`], whose sample lags its upkeep tick by at
/// most one interval, so worst-case visibility is about two seconds — well
/// inside the 60 s report cadence. One relaxed atomic load per event is the
/// cost on the per-packet path (the count checks already cost a cell read).
pub(crate) const PUBLISH_INTERVAL_MS: u64 = 1_000;

/// Sentinel for "this thread has never published".
const NEVER_PUBLISHED: u64 = u64::MAX;

/// Whether a time-based publish is due at `now` for a thread last published at
/// `last` ([`NEVER_PUBLISHED`] = never).
#[inline]
pub(crate) fn publish_due(last: u64, now: u64) -> bool {
    last == NEVER_PUBLISHED || now.saturating_sub(last) >= PUBLISH_INTERVAL_MS
}

/// Publish this thread's pending counters when the time gate is open.
///
/// Called from the per-event counters; a no-op until [`PUBLISH_INTERVAL_MS`]
/// has elapsed since this thread's last publish (or `snapshot` flushed it).
#[inline]
fn maybe_time_publish() {
    L_LAST_PUBLISH_MS.with(|last| {
        let now = crate::coarse_millis();
        if publish_due(last.get(), now) {
            last.set(now);
            flush_locals();
        }
    });
}

fn flush_locals() {
    L_DATAGRAMS.with(|c| {
        let v = c.get();
        if v != 0 {
            DATAGRAMS.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_BYTES.with(|c| {
        let v = c.get();
        if v != 0 {
            BYTES.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_FRAGMENTED.with(|c| {
        let v = c.get();
        if v != 0 {
            FRAGMENTED.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_UNSOLICITED.with(|c| {
        let v = c.get();
        if v != 0 {
            UNSOLICITED.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
}

/// One relayed UDP payload of `len` bytes.
///
/// **Counter semantics:** call sites book this when the payload has been
/// *accepted for relay* (it got a target binding / a send attempt), before the
/// final `try_send_datagram`/send-buffer outcome is known. A payload that is
/// then dropped by backpressure also bumps the matching `dgram_drops` class
/// (`BUFFER_FULL`, `EGRESS_DEAD`, …), so `datagrams - drops` is the delivered
/// estimate rather than `datagrams` alone. Do not move the booking later: the
/// BATCH/FRAG/TRAIN paths hand the payload to shared senders that own their
/// own accounting, and a second booking would double count.
pub fn payload(len: usize) {
    stats_only! {
        L_DATAGRAMS.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            if v >= FLUSH_DATAGRAMS {
                DATAGRAMS.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        L_BYTES.with(|c| {
            let v = c.get().wrapping_add(len as u64);
            c.set(v);
            if v >= FLUSH_BYTES {
                BYTES.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        let l = len as u64;
        L_MAX_SEEN.with(|c| {
            if l > c.get() {
                c.set(l);
                if l > MAX_PAYLOAD.load(Ordering::Relaxed) {
                    MAX_PAYLOAD.fetch_max(l, Ordering::Relaxed);
                }
            }
        });
        // Time-based publish: the count thresholds above can hold a low-rate
        // worker's pending count indefinitely (see `L_LAST_PUBLISH_MS`).
        maybe_time_publish();
    }
    let _ = len;
}

/// One payload that needed `frames` frames to carry.
///
/// Thread-locally batched like [`payload`] (flushed at [`FLUSH_DATAGRAMS`], or
/// by a [`snapshot`] on the *same* thread): the counter used to be one
/// process-wide RMW per fragmented payload, which is exactly what a
/// high-fragmentation workload pays per datagram.
pub fn fragmented(frames: u8) {
    stats_only! {
        if frames > 1 {
            L_FRAGMENTED.with(|c| {
                let v = c.get().wrapping_add(1);
                c.set(v);
                if v >= FLUSH_DATAGRAMS {
                    FRAGMENTED.fetch_add(v, Ordering::Relaxed);
                    c.set(0);
                }
            });
            maybe_time_publish();
        }
    }
    let _ = frames;
}

/// An inbound relay datagram admitted by the server's `udp_full_cone` mode
/// whose source is **not** on the session's recent-destination IP allowlist.
///
/// This is the unsolicited ingress a full-cone NAT forwards by definition. It
/// is counted on the accepted (not dropped) path because the reader still
/// classifies the source against the allowlist — every accepted reply is
/// already in [`UdpSnapshot::datagrams`]; this counter separates the peer that
/// answered from a peer that initiated, so a deployment can tell whether the
/// exposure is actually being used. Always zero in the default
/// (address-restricted) mode.
///
/// Thread-locally batched with the same threshold as [`fragmented`]: a busy
/// full-cone session takes these per inbound datagram, so a direct shared
/// `fetch_add` here would put the process-wide counter line back on the
/// packet path.
pub fn unsolicited() {
    stats_only! {
        L_UNSOLICITED.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            if v >= FLUSH_DATAGRAMS {
                UNSOLICITED.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        maybe_time_publish();
    }
}

/// A new UDP session (server) or SOCKS association (client) was established.
pub fn session() {
    stats_only! {
        SESSIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// A partial datagram was discarded because a fragment never arrived.
///
/// Drop-path only (never per packet): this is the only signal for a fragment
/// lost in transit.
pub fn reassembly_expired() {
    REASSEMBLY_EXPIRED.fetch_add(1, Ordering::Relaxed);
}

/// Drop-path only: a peer sending fragments whose sum exceeds the protocol's
/// payload ceiling or the aggregate reassembly budget.
pub fn reassembly_evicted() {
    REASSEMBLY_EVICTED.fetch_add(1, Ordering::Relaxed);
}

/// `(expired, evicted)` reassembly losses since process start. These are the
/// only drops that happen after the wire, so no send-side counter can see
/// them: a fragment lost in transit shows up here, not in `udp_write`.
pub fn reassembly_drops() -> (u64, u64) {
    (
        REASSEMBLY_EXPIRED.load(Ordering::Relaxed),
        REASSEMBLY_EVICTED.load(Ordering::Relaxed),
    )
}

/// Totals since process start.
///
/// **Batching bound.** `datagrams`, `bytes`, `fragmented` and `unsolicited`
/// accumulate in thread-local cells and are published either when the count
/// thresholds ([`FLUSH_DATAGRAMS`] / [`FLUSH_BYTES`]) are reached or when
/// [`PUBLISH_INTERVAL_MS`] has elapsed on the counting thread — whichever comes
/// first. The time gate is what bounds a low-rate worker's lag: at 17 pps the
/// count threshold alone is ~15 s, but at 1 pps it is ~4 minutes and a thread
/// that never reached it never published; with both gates the worst-case lag is
/// the coarse-clock error plus one interval (~2 s), independent of rate. A
/// thread that exits with an unpublished count still drops it (the shipped
/// worker threads live for the process, so this is a test/embedder and
/// rearmed-runtime case). Every `snapshot` call flushes the *caller's* cells and
/// re-arms its time gate, so tests and a reporter running on the counting
/// thread see their own records exactly.
pub fn snapshot() -> UdpSnapshot {
    flush_locals();
    L_LAST_PUBLISH_MS.with(|last| last.set(crate::coarse_millis()));
    UdpSnapshot {
        datagrams: DATAGRAMS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        fragmented: FRAGMENTED.load(Ordering::Relaxed),
        max_payload: MAX_PAYLOAD.load(Ordering::Relaxed),
        sessions: SESSIONS.load(Ordering::Relaxed),
        unsolicited: UNSOLICITED.load(Ordering::Relaxed),
    }
}

/// See [`udp_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSnapshot {
    pub datagrams: u64,
    pub bytes: u64,
    pub fragmented: u64,
    /// High-water mark over the process lifetime; never differenced, because a
    /// maximum cannot be subtracted.
    pub max_payload: u64,
    pub sessions: u64,
    /// Inbound replies admitted by `udp_full_cone` from sources this session had
    /// never sent to (see [`unsolicited`]). Always zero in restricted mode.
    pub unsolicited: u64,
}

impl UdpSnapshot {
    /// Counters accumulated since `prev`. `max_payload` stays the cumulative
    /// high-water mark for the reason above.
    pub fn since(&self, prev: &Self) -> Self {
        Self {
            datagrams: self.datagrams.saturating_sub(prev.datagrams),
            bytes: self.bytes.saturating_sub(prev.bytes),
            fragmented: self.fragmented.saturating_sub(prev.fragmented),
            max_payload: self.max_payload,
            sessions: self.sessions.saturating_sub(prev.sessions),
            unsolicited: self.unsolicited.saturating_sub(prev.unsolicited),
        }
    }

    /// Nothing happened in this interval; callers use it to stay quiet.
    pub fn is_idle(&self) -> bool {
        self.datagrams == 0 && self.sessions == 0
    }
}

impl std::fmt::Display for UdpSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} session(s), {} datagram(s) / {:.2} MiB, {} fragmented",
            self.sessions,
            self.datagrams,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.fragmented
        )?;
        // Only in the opt-in mode, so the default 60 s relay line stays
        // byte-identical to before the counter existed.
        if self.unsolicited > 0 {
            write!(f, ", {} unsolicited (full-cone)", self.unsolicited)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_gate_is_time_based_and_never_throttles_the_first_event() {
        assert!(
            publish_due(NEVER_PUBLISHED, 0),
            "first event always publishes"
        );
        assert!(publish_due(NEVER_PUBLISHED, 12_345));
        assert!(!publish_due(1_000, 1_000));
        assert!(!publish_due(1_000, 1_999));
        assert!(publish_due(1_000, 2_000));
        // A lagging coarse clock can report the same or an earlier stamp; the
        // saturating subtraction must not panic or publish early.
        assert!(!publish_due(5_000, 4_000));
    }

    /// The hot counters must publish on the time gate even when the count
    /// thresholds are nowhere near: a low-rate worker (a keepalive/DNS trickle)
    /// otherwise holds its pending count for minutes. Simulates a stale gate by
    /// making this thread's last-publish stamp old, then counts one payload.
    #[test]
    fn payload_publishes_on_the_time_gate_without_reaching_the_count_threshold() {
        L_LAST_PUBLISH_MS.with(|last| last.set(NEVER_PUBLISHED)); // due immediately
        let before = DATAGRAMS.load(Ordering::Relaxed);
        payload(7);
        let after = DATAGRAMS.load(Ordering::Relaxed);
        assert!(
            after > before,
            "one payload after a stale time gate must be published, not held in the cell"
        );
        // The cell is empty afterwards, so the next snapshot cannot double count
        // it (the publish reset it). Assert the **thread-local** cell, never the
        // process-wide counter: the lib test binary runs its tests in parallel
        // and other tests publish their own payloads into the same global, so a
        // global equality check here is inherently racy (it failed under the
        // default multi-threaded harness as soon as an unrelated payload test
        // happened to publish in the window). The cell is what the contract is
        // about anyway: `snapshot` flushes *the caller's* cells.
        assert_eq!(
            L_DATAGRAMS.with(|c| c.get()),
            0,
            "a time-gate publish must empty this thread's cell"
        );
        snapshot();
        assert_eq!(
            L_DATAGRAMS.with(|c| c.get()),
            0,
            "a publish empties the cell; snapshot must not re-add it"
        );
    }

    /// `snapshot` re-arms this thread's gate and still flushes its own cells, so
    /// the reporter/test thread sees exactly its own records.
    #[test]
    fn snapshot_flushes_and_rearms_the_caller_gate() {
        L_LAST_PUBLISH_MS.with(|last| last.set(NEVER_PUBLISHED));
        let before = snapshot();
        payload(1);
        let after = snapshot();
        assert!(
            after.datagrams > before.datagrams,
            "snapshot on the counting thread must flush its own cell"
        );
    }
}
