//! What the DNS layer actually did, in numbers the 60 s line can print.
//!
//! The optimizations in [`crate::dns::resolve`] are all about *which* path a
//! lookup takes — a warm hit never touches the network, a stale hit answers and
//! refreshes beside the caller, a refusal answers from the negative cache. That
//! makes the interesting properties invisible in any single latency number: a
//! p99 of 40 ms can mean "every request resolved" or "one in a thousand did",
//! and the fix for each is different. So the async path counts the classes it
//! serves and times the two things a user waits on:
//!
//! * `lookup` — one upstream resolution on a *foreground* path, from
//!   `resolve_ips` entry to answer (including the `getaddrinfo` fallback). The
//!   number that a cold name pays.
//! * `refresh` — the same, for a background serve-stale refresh. Kept apart
//!   because the two are fixed differently: a slow `lookup` is a cold flow
//!   waiting, a slow `refresh` only delays how long a stale answer keeps being
//!   served.
//! * `waiter` — one gated datagram, from the spawn that owns it to the moment
//!   its payload is handed to the socket. The number a *packet* waits, which is
//!   what a cold flow's first exchange actually costs.
//!
//! Both are log-scale histograms, so the line stays one line and p50/p99 cost
//! nothing to print. `mean` alone would hide exactly the tail these exist for.
//!
//! Sampling is free enough for the packet path: one relaxed `fetch_add` on the
//! path that already pays a resolution. The counters are process-global and the
//! reporter reads them delta-style (see the server's 60 s line).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Bucket count, including the catch-all last bucket.
const BUCKETS: usize = 16;

/// Inclusive upper bound of each bucket in microseconds; the last one is
/// unbounded. The spacing is one doubling per bucket from 250 µs, because the
/// interesting distinction is "sub-millisecond cache work" versus "one, two or
/// four seconds of upstream failure", not the difference between 3 ms and 4 ms.
const UPPER_US: [u64; BUCKETS] = [
    250,
    500,
    1_000,
    2_000,
    4_000,
    8_000,
    16_000,
    32_000,
    64_000,
    128_000,
    256_000,
    512_000,
    1_000_000,
    2_000_000,
    4_000_000,
    u64::MAX,
];

/// One log-scale histogram of durations in microseconds.
struct Histogram {
    buckets: [AtomicU64; BUCKETS],
    sum_us: AtomicU64,
    max_us: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; BUCKETS],
            sum_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration) {
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let idx = UPPER_US
            .iter()
            .position(|b| us <= *b)
            .unwrap_or(BUCKETS - 1);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        // Relaxed max: a concurrent pair can lose one sample's maximum, which is
        // a fine trade for not putting a CAS loop on the packet path.
        self.max_us.fetch_max(us, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistSnapshot {
        let mut counts = [0u64; BUCKETS];
        for (dst, src) in counts.iter_mut().zip(self.buckets.iter()) {
            *dst = src.load(Ordering::Relaxed);
        }
        HistSnapshot {
            counts,
            sum_us: self.sum_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
        }
    }
}

/// The async path's counters.
struct Counters {
    /// Warm positive hit, still inside the answer's own TTL.
    fresh: AtomicU64,
    /// Warm positive hit past its freshness deadline: served, refresh requested.
    stale: AtomicU64,
    /// The negative cache answered without touching the network.
    refused: AtomicU64,
    /// A resolution actually ran (the `try_get_with` init future ran once).
    cold: AtomicU64,
    /// The resolver answered that the name does not exist: a cached verdict.
    verdict: AtomicU64,
    /// No answer was obtained (timeout, saturated fallback, transport): a short
    /// backoff, not a verdict.
    inconclusive: AtomicU64,
    /// Background refreshes that got a permit and started a lookup.
    refresh_started: AtomicU64,
    refresh_ok: AtomicU64,
    refresh_fail: AtomicU64,
    /// Follower datagrams parked behind an in-flight resolution instead of
    /// being dropped, and how many of them the waiter went on to deliver.
    parked: AtomicU64,
    parked_delivered: AtomicU64,
    lookup: Histogram,
    refresh_lookup: Histogram,
    waiter: Histogram,
}

static COUNTERS: Counters = Counters {
    fresh: AtomicU64::new(0),
    stale: AtomicU64::new(0),
    refused: AtomicU64::new(0),
    cold: AtomicU64::new(0),
    verdict: AtomicU64::new(0),
    inconclusive: AtomicU64::new(0),
    refresh_started: AtomicU64::new(0),
    refresh_ok: AtomicU64::new(0),
    refresh_fail: AtomicU64::new(0),
    parked: AtomicU64::new(0),
    parked_delivered: AtomicU64::new(0),
    lookup: Histogram::new(),
    refresh_lookup: Histogram::new(),
    waiter: Histogram::new(),
};

pub(crate) fn fresh_hit() {
    COUNTERS.fresh.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn stale_hit() {
    COUNTERS.stale.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn refused_hit() {
    COUNTERS.refused.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn cold_started() {
    COUNTERS.cold.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn failed(verdict: bool) {
    let c = if verdict {
        &COUNTERS.verdict
    } else {
        &COUNTERS.inconclusive
    };
    c.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn refresh_started() {
    COUNTERS.refresh_started.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn refresh_finished(ok: bool) {
    let c = if ok {
        &COUNTERS.refresh_ok
    } else {
        &COUNTERS.refresh_fail
    };
    c.fetch_add(1, Ordering::Relaxed);
}

/// Time one upstream resolution (see the module docs for what is included).
pub(crate) fn lookup_took(elapsed: Duration) {
    COUNTERS.lookup.record(elapsed);
}

/// Time one background refresh's upstream resolution.
pub(crate) fn refresh_lookup_took(elapsed: Duration) {
    COUNTERS.refresh_lookup.record(elapsed);
}

/// One follower datagram was parked behind an in-flight resolution.
pub fn parked() {
    COUNTERS.parked.fetch_add(1, Ordering::Relaxed);
}

/// One parked follower was delivered by the waiter that resolved its name.
pub fn parked_delivered() {
    COUNTERS.parked_delivered.fetch_add(1, Ordering::Relaxed);
}

/// Time one gated datagram from its spawn to the socket hand-off.
pub fn waiter_took(elapsed: Duration) {
    COUNTERS.waiter.record(elapsed);
}

/// Copy of the histograms' shape, delta-comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HistSnapshot {
    counts: [u64; BUCKETS],
    sum_us: u64,
    max_us: u64,
}

impl HistSnapshot {
    /// Samples in this interval (or in total, for an absolute snapshot).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Mean in microseconds, or 0 with no samples.
    #[must_use]
    pub fn mean_us(&self) -> u64 {
        self.sum_us.checked_div(self.count()).unwrap_or(0)
    }

    /// Largest sample in microseconds.
    #[must_use]
    pub fn max_us(&self) -> u64 {
        self.max_us
    }

    /// Approximate percentile as the *upper bound of the bucket* the sample
    /// falls in, in microseconds; 0 with no samples. Approximate on purpose: the
    /// buckets double, so the answer is "at most this", which is what a decision
    /// about a timeout budget needs.
    #[must_use]
    pub fn percentile_us(&self, p: u32) -> u64 {
        let total = self.count();
        if total == 0 {
            return 0;
        }
        // The rank is `ceil(p% of n)`, at least 1, so p99 of a single sample is
        // that sample.
        let rank = (u64::from(p).saturating_mul(total)).div_ceil(100).max(1);
        let mut seen = 0u64;
        for (i, n) in self.counts.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return UPPER_US[i];
            }
        }
        UPPER_US[BUCKETS - 1]
    }

    /// This interval's samples, given the previous absolute snapshot.
    ///
    /// `max_us` is left as the *process-lifetime* maximum — it is not
    /// subtractable — so an interval's own ceiling is `percentile_us(100)`,
    /// which is a bucket bound rather than an exact sample. The printed line
    /// uses that and says `max<=` to be honest about it; reading `max_us()` off a
    /// delta would report a sample that may have happened hours ago.
    #[must_use]
    pub fn since(&self, prev: &Self) -> Self {
        let mut counts = [0u64; BUCKETS];
        for ((dst, now), was) in counts
            .iter_mut()
            .zip(self.counts.iter())
            .zip(prev.counts.iter())
        {
            *dst = now.saturating_sub(*was);
        }
        Self {
            counts,
            sum_us: self.sum_us.saturating_sub(prev.sum_us),
            max_us: self.max_us,
        }
    }
}

/// Absolute snapshot of the DNS counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub fresh: u64,
    pub stale: u64,
    pub refused: u64,
    pub cold: u64,
    pub verdict: u64,
    pub inconclusive: u64,
    pub refresh_started: u64,
    pub refresh_ok: u64,
    pub refresh_fail: u64,
    pub parked: u64,
    pub parked_delivered: u64,
    pub lookup: HistSnapshot,
    pub refresh_lookup: HistSnapshot,
    pub waiter: HistSnapshot,
}

/// Read every counter. Cheap (relaxed loads), no locking, callable anywhere.
#[must_use]
pub fn dns_stats() -> Snapshot {
    snapshot()
}

/// Read every counter. Cheap (relaxed loads), no locking, callable anywhere.
#[must_use]
pub fn snapshot() -> Snapshot {
    Snapshot {
        fresh: COUNTERS.fresh.load(Ordering::Relaxed),
        stale: COUNTERS.stale.load(Ordering::Relaxed),
        refused: COUNTERS.refused.load(Ordering::Relaxed),
        cold: COUNTERS.cold.load(Ordering::Relaxed),
        verdict: COUNTERS.verdict.load(Ordering::Relaxed),
        inconclusive: COUNTERS.inconclusive.load(Ordering::Relaxed),
        refresh_started: COUNTERS.refresh_started.load(Ordering::Relaxed),
        refresh_ok: COUNTERS.refresh_ok.load(Ordering::Relaxed),
        refresh_fail: COUNTERS.refresh_fail.load(Ordering::Relaxed),
        parked: COUNTERS.parked.load(Ordering::Relaxed),
        parked_delivered: COUNTERS.parked_delivered.load(Ordering::Relaxed),
        lookup: COUNTERS.lookup.snapshot(),
        refresh_lookup: COUNTERS.refresh_lookup.snapshot(),
        waiter: COUNTERS.waiter.snapshot(),
    }
}

impl Snapshot {
    /// This interval's counters, given the previous absolute snapshot.
    #[must_use]
    pub fn since(&self, prev: &Self) -> Self {
        Self {
            fresh: self.fresh.saturating_sub(prev.fresh),
            stale: self.stale.saturating_sub(prev.stale),
            refused: self.refused.saturating_sub(prev.refused),
            cold: self.cold.saturating_sub(prev.cold),
            verdict: self.verdict.saturating_sub(prev.verdict),
            inconclusive: self.inconclusive.saturating_sub(prev.inconclusive),
            refresh_started: self.refresh_started.saturating_sub(prev.refresh_started),
            refresh_ok: self.refresh_ok.saturating_sub(prev.refresh_ok),
            refresh_fail: self.refresh_fail.saturating_sub(prev.refresh_fail),
            parked: self.parked.saturating_sub(prev.parked),
            parked_delivered: self.parked_delivered.saturating_sub(prev.parked_delivered),
            lookup: self.lookup.since(&prev.lookup),
            refresh_lookup: self.refresh_lookup.since(&prev.refresh_lookup),
            waiter: self.waiter.since(&prev.waiter),
        }
    }

    /// Nothing moved: the 60 s line stays silent.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        *self == Self::default()
    }
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} fresh, {} stale, {} refused, {} cold ({} verdict, {} inconclusive), \
             {} refresh ({} ok, {} failed), {} parked ({} delivered)",
            self.fresh,
            self.stale,
            self.refused,
            self.cold,
            self.verdict,
            self.inconclusive,
            self.refresh_started,
            self.refresh_ok,
            self.refresh_fail,
            self.parked,
            self.parked_delivered
        )?;
        for (name, h) in [
            ("lookup", &self.lookup),
            ("refresh", &self.refresh_lookup),
            ("waiter", &self.waiter),
        ] {
            if h.count() > 0 {
                // `max<=` because this is a bucket bound, not the exact sample:
                // the interval delta cannot subtract a maximum, and the
                // process-lifetime one would outlive its own interval.
                write!(
                    f,
                    "; {name} n={} p50<={} p99<={} max<={}",
                    h.count(),
                    duration_us(h.percentile_us(50)),
                    duration_us(h.percentile_us(99)),
                    duration_us(h.percentile_us(100)),
                )?;
            }
        }
        Ok(())
    }
}

/// Render a microsecond count the way the line reads best.
fn duration_us(us: u64) -> String {
    if us == u64::MAX {
        // The catch-all bucket's upper bound: say "more than the last bound"
        // rather than print a 584-billion-year number.
        return ">4s".to_string();
    }
    if us >= 1_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The histogram's contract: a percentile answers with the upper bound of
    /// the bucket its sample falls in, so a decision about a timeout budget can
    /// read "p99 is at most this".
    #[test]
    fn percentiles_report_bucket_upper_bounds() {
        let h = Histogram::new();
        h.record(Duration::from_micros(120));
        let s = h.snapshot();
        assert_eq!(s.count(), 1);
        assert_eq!(s.percentile_us(50), 250, "the 250 us bucket");
        assert_eq!(s.percentile_us(99), 250, "one sample is its own p99");
        assert_eq!(s.max_us(), 120);

        let h = Histogram::new();
        for us in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            h.record(Duration::from_micros(us));
        }
        let s = h.snapshot();
        assert_eq!(s.count(), 10);
        assert_eq!(s.percentile_us(50), 250);
        assert_eq!(s.percentile_us(100), 250);
        assert_eq!(s.mean_us(), 55);
    }

    #[test]
    fn the_catch_all_bucket_holds_everything_slower_than_the_last_bound() {
        let h = Histogram::new();
        h.record(Duration::from_secs(30));
        let s = h.snapshot();
        assert_eq!(s.percentile_us(99), u64::MAX, "unbounded last bucket");
        assert_eq!(s.max_us(), 30_000_000);
    }

    /// Interval deltas subtract cleanly, and an interval with no traffic is
    /// idle (the reporter then prints nothing).
    #[test]
    fn since_subtracts_and_idle_is_empty() {
        let empty = Snapshot::default();
        assert!(empty.since(&empty).is_idle());

        let now = Snapshot {
            fresh: 3,
            cold: 1,
            ..Snapshot::default()
        };
        let d = now.since(&empty);
        assert_eq!(d.fresh, 3);
        assert_eq!(d.cold, 1);
        assert!(!d.is_idle());
        assert_eq!(
            d.lookup.count(),
            0,
            "a counter-only interval has no samples"
        );
    }

    /// A printed maximum must describe *its own* interval. The absolute
    /// snapshot exposes the process-lifetime maximum, and the interval delta
    /// cannot subtract it, so the line prints the interval's ceiling bound
    /// instead — one 4 s timeout must not make every later line claim 4 s.
    #[test]
    fn a_printed_maximum_belongs_to_its_interval() {
        let h = Histogram::new();
        h.record(Duration::from_secs(4));
        let before = h.snapshot();
        h.record(Duration::from_millis(1));
        let interval = h.snapshot().since(&before);
        assert_eq!(
            interval.max_us(),
            4_000_000,
            "the field stays the lifetime maximum"
        );
        let line = Snapshot {
            lookup: interval,
            ..Snapshot::default()
        }
        .to_string();
        assert!(line.contains("max<=1.0ms"), "{line}");
        assert!(!line.contains("4.0s"), "{line}");
    }

    #[test]
    fn the_line_names_every_class_and_skips_empty_histograms() {
        let s = Snapshot {
            fresh: 7,
            stale: 2,
            refused: 1,
            cold: 3,
            verdict: 2,
            inconclusive: 1,
            refresh_started: 2,
            refresh_ok: 1,
            refresh_fail: 1,
            ..Snapshot::default()
        };
        let line = s.to_string();
        assert!(line.contains("7 fresh"), "{line}");
        assert!(line.contains("3 cold"), "{line}");
        assert!(line.contains("2 verdict"), "{line}");
        assert!(line.contains("1 inconclusive"), "{line}");
        assert!(!line.contains("lookup n="), "no samples, no timing: {line}");
        assert!(!line.contains('\n'));

        let h = Histogram::new();
        h.record(Duration::from_millis(3));
        let s = Snapshot {
            lookup: h.snapshot(),
            ..Snapshot::default()
        };
        let line = s.to_string();
        assert!(line.contains("lookup n=1"), "{line}");
        assert!(line.contains("p50<=4.0ms"), "{line}");
    }
}
