//! Process-uptime millisecond clock, quanta-backed.
//!
//! One process-wide epoch ([`START`]) and two readers off the same quanta
//! clock, so the values stay mutually comparable:
//!
//! - [`mono_millis`] reads `quanta::Instant::now()`: on x86_64 a TSC read
//!   scaled to nanoseconds (~12-15 ns), the replacement for the vDSO
//!   `clock_gettime` the std `Instant` used to cost (~22 ns here); on targets
//!   without a usable TSC quanta falls back to the OS monotonic clock, which
//!   is the pre-migration cost.
//! - [`coarse_millis`](super::coarse::coarse_millis) reads
//!   `quanta::Instant::recent()` (~4-5 ns, one atomic load): the upkeep-cached
//!   sample for per-packet gates that only compare whole-second deadlines.
//!   The upkeep thread is a quanta OS thread, not a Tokio task — so the epoch
//!   is no longer bound to any runtime, which deletes the whole
//!   re-arm/Disarm machinery the previous ticker needed across runtime
//!   hand-offs (tests, embedders).
//!
//! Both readers must scale against the same [`START`] instant: quanta's
//! `Instant::now()` and `Instant::recent()` are reference-time scaled, so a
//! `recent()` sample can be subtracted from a `now()` reading (callers mix
//! the two epochs deliberately — see `dns::memo::coarse_deadline`).

use std::sync::OnceLock;

/// Process-wide clock epoch: the first quanta instant this process reads.
static START: OnceLock<quanta::Instant> = OnceLock::new();

/// First quanta instant read in this process; also calibrates the underlying
/// clock on first use (quanta lazily initializes, worst case ~200 ms once).
pub(crate) fn start() -> quanta::Instant {
    *START.get_or_init(quanta::Instant::now)
}

/// Milliseconds from [`START`] to `at`, saturating at zero on a monotonicity
/// hiccup (quanta's own `duration_since` saturates the same way).
fn millis_at(at: quanta::Instant) -> u64 {
    at.saturating_duration_since(start()).as_millis() as u64
}

/// Milliseconds since the first clock read in this process, up to saturation.
/// Precise read: pays a TSC read (or the fallback clock) per call.
pub fn mono_millis() -> u64 {
    millis_at(quanta::Instant::now())
}

/// Cached sample of the same clock, refreshed by quanta's upkeep thread (see
/// [`super::coarse::coarse_millis`], which owns the upkeep registration).
pub(crate) fn recent_millis() -> u64 {
    millis_at(quanta::Instant::recent())
}
