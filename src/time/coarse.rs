use std::time::Duration;

use super::mono::mono_millis;

/// Step of the coarse clock below.
const COARSE_TICK: Duration = Duration::from_secs(1);

/// Monotonic milliseconds, advanced in [`COARSE_TICK`] steps by one lazily
/// armed task: the same epoch as [`mono_millis`], sampled once per second.
///
/// **Why.** Every hot-path throttle and deadline in this crate is measured in
/// whole seconds — the 1 s liveness-touch throttle, the 1 s egress-memo
/// refresh, the 10 s PMTU refresh, the 30 s destination pin, the 180 s idle
/// reap, the 300 s TCP idle watchdog and the 10 s drop-warning interval.
/// `mono_millis()` (a vDSO `clock_gettime`, measured at ~22 ns here) was being
/// paid *per packet* to answer "has a second passed?", which is the shape this
/// replaces with one relaxed load.
///
/// **Why not a packet counter.** Sampling the clock every Nth packet was tried
/// and reverted — see `TouchMemo`. A burst advances the local counter past its
/// sample point without storing anything, and every later trickle packet then
/// keeps skipping the clock read, so the stamp freezes until the 180 s reaper
/// kills a session that was live the whole time. A task-driven epoch advances
/// with wall time regardless of how packets arrive: a trickle flow is refreshed
/// on its first packet after each tick, which is exactly the guarantee the
/// throttle is supposed to provide.
///
/// **Frozen-epoch safety.** A stalled epoch would be that same liveness bug, so
/// the ticker is not fire-and-forget: the task clears the armed flag as it goes
/// down (including when its runtime is dropped mid-flight), and any reader that
/// finds the flag clear re-arms it. A reader that *is* running is therefore
/// never more than one call away from a live clock, and the cursor it publishes
/// is monotonic either way — a stale value can only make a deadline look
/// further away, never closer, so the failure mode is a delay, not a false
/// expiry.
///
/// Because the cursor is a sample of the same clock, coarse and fine values are
/// directly comparable and both are used side by side; a coarse value is simply
/// up to one tick behind.
///
/// Callers must be on a Tokio runtime (every call site is inside a task); with
/// no runtime the cursor is left where it is and the next caller arms it.
pub fn coarse_millis() -> u64 {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static CURSOR: AtomicU64 = AtomicU64::new(0);
    static ARMED: AtomicBool = AtomicBool::new(false);

    /// Clears `ARMED` however the ticker task ends — loop exit, panic or the
    /// runtime dropping the task. Without this the flag would stay set across a
    /// runtime hand-off and the epoch would stay frozen forever.
    struct Disarm;
    impl Drop for Disarm {
        fn drop(&mut self) {
            ARMED.store(false, Ordering::Release);
        }
    }

    let mut v = CURSOR.load(Ordering::Relaxed);
    if v == 0 {
        // No sample yet (first call ever, or the ticker has not been polled).
        // Seed it here rather than returning 0: a consumer that stores the value
        // as its baseline would otherwise read "idle since process start", and
        // its very first deadline check would fire — a silent TCP flow would be
        // torn down after one watchdog step instead of after 300 s. Costs one
        // clock read once per process.
        v = mono_millis();
        CURSOR.store(v, Ordering::Relaxed);
    }
    if !ARMED.load(Ordering::Relaxed) && !ARMED.swap(true, Ordering::AcqRel) {
        // The guard is built *here* and moved into the task, not constructed
        // inside it. A runtime that is already shutting down drops the future
        // without ever polling it (`OwnedTasks::bind_inner` calls
        // `task.shutdown()` and schedules nothing), so an inside-the-block guard
        // would never exist and `ARMED` would stay set forever — and a frozen
        // epoch is exactly the liveness bug this clock exists to avoid. As a
        // capture it is dropped whichever way the future ends.
        let disarm = Disarm;
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(async move {
                    let _disarm = disarm;
                    let mut tick = tokio::time::interval(COARSE_TICK);
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        // `interval` completes its first tick immediately, so
                        // the cursor is real from the first packet rather than
                        // after one tick of startup lag.
                        tick.tick().await;
                        CURSOR.store(mono_millis(), Ordering::Relaxed);
                    }
                });
            }
            // No runtime here: let the next caller — always a task — try again
            // rather than leaving the flag set on a ticker that was never
            // spawned. `disarm` drops at the end of this arm and clears it.
            Err(_) => ARMED.store(false, Ordering::Release),
        }
    }
    v
}
