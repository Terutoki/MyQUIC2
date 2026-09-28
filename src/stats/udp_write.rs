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

#[cfg(feature = "stats")]
fn bump(c: &AtomicU64) -> u64 {
    c.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}
thread_local! {
    static L_SENT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(feature = "stats")]
fn flush_sent() {
    L_SENT.with(|c| {
        let v = c.get();
        if v != 0 {
            SENT.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
}
/// One successful last-hop write.
///
/// Batching matches [`crate::udp_stats::payload`]: one shared atomic RMW per
/// 256 sends, so the 60 s `udp write` line cannot dwell at zero for a
/// low-rate session.
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
    }
}
// Without the `stats` feature every total reads zero, as documented: these
// are counts, and a literal 1 made every drop warning claim "1 so far" no
// matter how many had happened.
pub fn retried() -> u64 {
    #[cfg(feature = "stats")]
    return bump(&RETRIED);
    #[cfg(not(feature = "stats"))]
    return 0;
}
pub fn dropped_no_permit() -> u64 {
    #[cfg(feature = "stats")]
    return bump(&DROPPED_NO_PERMIT);
    #[cfg(not(feature = "stats"))]
    return 0;
}
pub fn failed() -> u64 {
    #[cfg(feature = "stats")]
    return bump(&FAILED);
    #[cfg(not(feature = "stats"))]
    return 0;
}
pub fn no_app() -> u64 {
    #[cfg(feature = "stats")]
    return bump(&NO_APP);
    #[cfg(not(feature = "stats"))]
    return 0;
}
pub fn retry_failed() -> u64 {
    #[cfg(feature = "stats")]
    return bump(&RETRY_FAILED);
    #[cfg(not(feature = "stats"))]
    return 0;
}

/// Totals since process start. `sent` is thread-local batched (flushed at
/// 256 or by a `snapshot` on the same thread); the other counters are
/// direct `fetch_add` calls from the send paths.
pub fn snapshot() -> UdpWriteSnapshot {
    #[cfg(feature = "stats")]
    flush_sent();
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
