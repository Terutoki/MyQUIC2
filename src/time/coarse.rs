//! Coarse millisecond clock: the upkeep-cached quanta sample.
//!
//! [`coarse_millis`] reads `quanta::Instant::recent()` — one atomic load of a
//! value refreshed by quanta's upkeep thread every [`UPKEEP_INTERVAL_MS`].
//! Same epoch as [`mono_millis`](super::mono::mono_millis) (both scale against
//! the shared `START` in `super::mono`), at most one interval behind — the
//! exact "lagging gate" contract per-packet throttles rely on (DNS memo
//! deadlines, drop-warning windows, liveness stamps, reapers).
//!
//! **Why the upkeep thread replaced the ticker.** The previous coarse clock
//! was a Tokio task publishing a 1 s sample; a task dies with its runtime, so
//! the implementation needed an armed flag, a `Disarm` guard and a re-arm path
//! to keep the epoch from freezing across runtime hand-offs. quanta's upkeep is
//! an OS thread started once and held in [`UPKEEP`] for the process lifetime,
//! so the epoch structurally cannot freeze — the failure mode is gone, not
//! handled.
//!
//! **Fallback.** If the upkeep thread cannot be spawned, `start()` errors and
//! [`UPKEEP`] stores `None`; `recent()` then falls back to the live clock
//! (quanta's documented behaviour), i.e. coarse degrades to precise — slower
//! but never stale or frozen.
//!
//! Callers must not need a Tokio runtime: quanta works without one, and this
//! module is the reason the tests around runtime hand-offs still pass.

use std::sync::OnceLock;
use std::time::Duration;

/// Refresh cadence of the upkeep thread: matches the 1 s tick of the clock
/// this replaces, so every documented staleness bound ("up to one tick
/// behind") stays literally true.
const UPKEEP_INTERVAL_MS: u64 = 1_000;
const UPKEEP_INTERVAL: Duration = Duration::from_millis(UPKEEP_INTERVAL_MS);
const _: () = assert!(UPKEEP_INTERVAL_MS <= 1_000);

/// Keeps the upkeep thread alive for the process lifetime (dropping the handle
/// stops it — see `quanta::Upkeep::start`); `None` when the spawn failed.
static UPKEEP: OnceLock<Option<quanta::Handle>> = OnceLock::new();

/// Start the upkeep thread once. Called on every [`coarse_millis`] call: the
/// first call pays the spawn, later calls a relaxed load of the `OnceLock`.
#[inline]
fn ensure_upkeep() {
    UPKEEP.get_or_init(|| quanta::Upkeep::new(UPKEEP_INTERVAL).start().ok());
}

/// Coarse monotonic milliseconds since the first clock read in this process.
/// One atomic load: up to one upkeep interval behind
/// [`mono_millis`](super::mono::mono_millis), never ahead of it.
pub fn coarse_millis() -> u64 {
    ensure_upkeep();
    super::mono::recent_millis()
}
