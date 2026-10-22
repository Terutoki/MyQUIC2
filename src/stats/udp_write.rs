//! Terminal outcomes of the last-hop UDP write.
//!
//! These were the only paths in the relay that could lose a packet with no
//! counter behind them — `udp_try_send` dropped on a full retry budget, threw
//! away hard errors at `debug!`, and a reply with no recorded app address
//! returned silently. That is why a rate-dependent loss could be measured from
//! the outside while every existing counter stayed flat.
use std::sync::atomic::{AtomicU64, Ordering};

/// Written to the socket on the first attempt.
pub static SENT: AtomicU64 = AtomicU64::new(0);
/// `WouldBlock`: handed to a detached task that retries (not a loss).
pub static RETRIED: AtomicU64 = AtomicU64::new(0);
/// `WouldBlock` and the detached-retry budget was exhausted: dropped.
pub static DROPPED_NO_PERMIT: AtomicU64 = AtomicU64::new(0);
/// Hard send error. Previously `debug!`-only, i.e. invisible in production.
pub static FAILED: AtomicU64 = AtomicU64::new(0);
/// A reply arrived before any app address was known: nowhere to send it.
pub static NO_APP: AtomicU64 = AtomicU64::new(0);
/// A detached retry finished without writing.
pub static RETRY_FAILED: AtomicU64 = AtomicU64::new(0);

fn bump(c: &AtomicU64) -> u64 {
    c.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}
thread_local! {
    static L_SENT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Coarse-epoch stamp of this thread's last publish; see
    /// [`crate::udp_stats::PUBLISH_INTERVAL_MS`]. The count threshold alone
    /// cannot bound a low-rate session's reporting lag: 256 sends at 1 pps is
    /// ~4 minutes, so the line used to dwell at zero for many reporting
    /// intervals. The time gate publishes at most every interval, for one cheap
    /// atomic read per send.
    static L_LAST_PUBLISH_MS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(NEVER_PUBLISHED) };
}

/// Sentinel for "this thread has never published".
const NEVER_PUBLISHED: u64 = u64::MAX;

fn flush_sent() {
    L_SENT.with(|c| {
        let v = c.get();
        if v != 0 {
            SENT.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
}

/// Publish this thread's pending `sent` count when the time gate is open.
#[inline]
fn maybe_time_publish() {
    L_LAST_PUBLISH_MS.with(|last| {
        let now = crate::coarse_millis();
        if crate::udp_stats::publish_due(last.get(), now) {
            last.set(now);
            flush_sent();
        }
    });
}

/// One successful last-hop write.
///
/// Batching matches [`crate::udp_stats::payload`]: one shared atomic RMW per
/// 256 sends, plus a time-based publish at
/// [`crate::udp_stats::PUBLISH_INTERVAL_MS`] so the 60 s `udp write` line tracks
/// a low-rate session too (the count threshold alone could hold a sub-256 send
/// count for minutes).
pub fn sent() {
    stats_only! {
        L_SENT.with(|c| {
            let v = c.get().wrapping_add(1);
            if v >= 256 {
                SENT.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            } else {
                c.set(v);
            }
        });
        maybe_time_publish();
    }
}
pub fn retried() -> u64 {
    bump(&RETRIED)
}
pub fn dropped_no_permit() -> u64 {
    bump(&DROPPED_NO_PERMIT)
}
pub fn failed() -> u64 {
    bump(&FAILED)
}
pub fn no_app() -> u64 {
    bump(&NO_APP)
}
pub fn retry_failed() -> u64 {
    bump(&RETRY_FAILED)
}

/// Totals since process start. `sent` is thread-local batched (published at
/// 256 or every [`crate::udp_stats::PUBLISH_INTERVAL_MS`] on the counting
/// thread, or by a `snapshot` on the same thread); the other counters are
/// direct `fetch_add` calls from the send paths and are always exact.
pub fn snapshot() -> UdpWriteSnapshot {
    flush_sent();
    L_LAST_PUBLISH_MS.with(|last| last.set(crate::coarse_millis()));
    UdpWriteSnapshot {
        sent: SENT.load(Ordering::Relaxed),
        retried: RETRIED.load(Ordering::Relaxed),
        dropped_no_permit: DROPPED_NO_PERMIT.load(Ordering::Relaxed),
        failed: FAILED.load(Ordering::Relaxed),
        no_app: NO_APP.load(Ordering::Relaxed),
        retry_failed: RETRY_FAILED.load(Ordering::Relaxed),
    }
}

/// See [`udp_write`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpWriteSnapshot {
    pub sent: u64,
    pub retried: u64,
    pub dropped_no_permit: u64,
    pub failed: u64,
    pub no_app: u64,
    pub retry_failed: u64,
}

impl UdpWriteSnapshot {
    pub fn since(&self, prev: &Self) -> Self {
        let d = |a: u64, b: u64| a.saturating_sub(b);
        Self {
            sent: d(self.sent, prev.sent),
            retried: d(self.retried, prev.retried),
            dropped_no_permit: d(self.dropped_no_permit, prev.dropped_no_permit),
            failed: d(self.failed, prev.failed),
            no_app: d(self.no_app, prev.no_app),
            retry_failed: d(self.retry_failed, prev.retry_failed),
        }
    }
    /// Nothing was lost in this interval.
    pub fn clean(&self) -> bool {
        self.dropped_no_permit == 0
            && self.failed == 0
            && self.no_app == 0
            && self.retry_failed == 0
    }
}

impl std::fmt::Display for UdpWriteSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} sent, {} retried, {} dropped(no permit), {} failed, {} no-app, {} retry-failed",
            self.sent,
            self.retried,
            self.dropped_no_permit,
            self.failed,
            self.no_app,
            self.retry_failed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_publishes_on_the_time_gate_below_the_count_threshold() {
        L_LAST_PUBLISH_MS.with(|last| last.set(NEVER_PUBLISHED));
        let before = SENT.load(Ordering::Relaxed);
        sent();
        assert!(
            SENT.load(Ordering::Relaxed) > before,
            "one send after a stale gate must be published, not held in the cell"
        );
    }

    #[test]
    fn snapshot_flushes_and_rearms_the_caller_gate() {
        L_LAST_PUBLISH_MS.with(|last| last.set(NEVER_PUBLISHED));
        let before = snapshot();
        sent();
        let after = snapshot();
        assert!(
            after.sent > before.sent,
            "snapshot on the counting thread must flush its own cell"
        );
    }

    /// The other counters are exact (direct `fetch_add`) and must never be
    /// batched: a drop that a rate-limited report has to show immediately.
    #[test]
    fn loss_counters_are_exact_per_event() {
        let before = snapshot();
        retried();
        dropped_no_permit();
        failed();
        no_app();
        retry_failed();
        let after = snapshot();
        assert_eq!(after.retried, before.retried + 1);
        assert_eq!(after.dropped_no_permit, before.dropped_no_permit + 1);
        assert_eq!(after.failed, before.failed + 1);
        assert_eq!(after.no_app, before.no_app + 1);
        assert_eq!(after.retry_failed, before.retry_failed + 1);
    }
}
