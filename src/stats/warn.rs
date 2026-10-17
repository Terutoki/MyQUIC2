use crate::coarse_millis;

/// Minimum spacing between datagram-drop warnings, per process.
pub(crate) const DROP_WARN_INTERVAL_MS: u64 = 10_000;

/// Sentinel for "no drop warning has been emitted yet".
///
/// Using 0 here swallows the *first* drop: [`mono_millis`] establishes its base
/// on first call, so the elapsed value it returns starts near zero and
/// `now - 0 < INTERVAL` holds. That is exactly the case a fresh deployment
/// hits, so the first drop must warn unconditionally.
pub(crate) const NEVER_WARNED: u64 = u64::MAX;

/// Whether a drop warning is due. Split out from the atomic so the window logic
/// is testable without a clock or a global.
pub(crate) fn drop_warn_due(last: u64, now: u64) -> bool {
    last == NEVER_WARNED || now.saturating_sub(last) >= DROP_WARN_INTERVAL_MS
}

/// Claim this warning slot if one is due (at most one winner per
/// [`DROP_WARN_INTERVAL_MS`] per counter).
///
/// Split from the message so a flood of drops pays for building the detail
/// string only when the line will actually be emitted: formatting it before the
/// gate made the *logging* itself the per-drop cost.
pub(crate) fn claim_drop_warning(last: &std::sync::atomic::AtomicU64) -> bool {
    use std::sync::atomic::Ordering;
    // The coarse epoch, not `mono_millis()`: this runs per *dropped* datagram,
    // and a 10 s window does not need a precise clock (a warning can be up to
    // one tick late). The vDSO `clock_gettime` here was per-drop cost on the
    // very path that is already the exceptional one.
    let now = coarse_millis();
    let prev = last.load(Ordering::Relaxed);
    drop_warn_due(prev, now)
        && last
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// Which datagram-drop class a warning is about.
///
/// An enum rather than a reason substring: the slot used to be picked with
/// `reason.contains("buffer full" | "budget" | "fragment" | "header")`, so a
/// reworded message would silently merge two faults into one rate limit — the
/// same failure mode [`UdpWriteDrop`] documents. Each variant keeps its
/// historical slot (`LAST_LARGE` / `LAST_FULL` / `LAST_OTHER`); the
/// human-readable `reason` stays a separate parameter so the log line keeps
/// its diagnostic specificity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramDropKind {
    /// The payload did not fit the path budget or the fragmentation cap
    /// (including a bad address header, which only affects sizing).
    Large,
    /// quinn's DATAGRAM send buffer was full.
    BufferFull,
    /// Any other drop. No current call site maps here; the slot is kept so a
    /// future class gets its own rate limit instead of sharing one.
    #[allow(dead_code)]
    Other,
}

/// Rate-limited (at most one per [`DROP_WARN_INTERVAL_MS`], process-wide)
/// warning for a dropped datagram. A per-packet `warn!` would itself become the
/// bottleneck under the flood that causes drops.
pub(crate) fn warn_datagram_drop(
    kind: DatagramDropKind,
    reason: &str,
    total: u64,
    detail: impl FnOnce() -> String,
) {
    use std::sync::atomic::AtomicU64;
    static LAST_LARGE: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_FULL: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static LAST_OTHER: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    let slot = match kind {
        DatagramDropKind::Large => &LAST_LARGE,
        DatagramDropKind::BufferFull => &LAST_FULL,
        DatagramDropKind::Other => &LAST_OTHER,
    };
    if !claim_drop_warning(slot) {
        return;
    }
    let detail = detail();
    tracing::warn!(
        "udp datagram dropped ({reason}): {total} so far{detail} — a packet this size would \
         have been carried by a direct UDP path, so the tunnel is degrading UDP here"
    );
}

/// Path-budget context for a drop warning.
pub(crate) fn budget_detail(limit: usize, cap: usize) -> String {
    format!("; path DATAGRAM limit {limit} B, usable UDP payload {cap} B")
}

/// Window of the per-second log limiters ([`claim_log_window`] and
/// [`claim_log_window_counted`]).
pub const LOG_WINDOW_MS: u64 = 1_000;

/// Whether a per-second window is open at `now` for a slot last claimed at
/// `prev`. [`NEVER_WARNED`] means the slot has never been claimed, which is
/// always due: the mono epoch starts near zero, so a 0-initialised slot
/// swallows the process's first window — for the TCP-abort line that is
/// exactly the startup/reconnect burst the diagnostic exists for.
#[inline]
fn log_window_due(prev: u64, now: u64) -> bool {
    prev == NEVER_WARNED || now.saturating_sub(prev) >= LOG_WINDOW_MS
}

/// Claim a one-per-[`LOG_WINDOW_MS`] window on `slot`; the caller supplies the
/// clock reading, so the shared clock choice stays at the call site.
///
/// `true` for the single winner; every other caller inside the window — and
/// every loser of a concurrent race — gets `false` without blocking (relaxed
/// load + relaxed CAS, the same claim protocol as [`claim_drop_warning`]).
pub fn claim_log_window(slot: &std::sync::atomic::AtomicU64, now: u64) -> bool {
    use std::sync::atomic::Ordering;
    let prev = slot.load(Ordering::Relaxed);
    if !log_window_due(prev, now) {
        return false;
    }
    slot.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Counted variant of [`claim_log_window`]: `None` while the window is closed
/// (and this call is counted as suppressed), `Some(n)` for the winner, where
/// `n` is the number of calls suppressed since the previous window opened —
/// reset by the claim so the winner can fold it into its next line.
pub fn claim_log_window_counted(
    slot: &std::sync::atomic::AtomicU64,
    suppressed: &std::sync::atomic::AtomicU64,
    now: u64,
) -> Option<u64> {
    use std::sync::atomic::Ordering;
    let prev = slot.load(Ordering::Relaxed);
    if !log_window_due(prev, now) {
        suppressed.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if slot
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        Some(suppressed.swap(0, Ordering::Relaxed))
    } else {
        suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Rate-limited (one per [`LOG_WINDOW_MS`], process-wide) claim for the
/// per-flow TCP-abort log line, folding the suppressed count into a warning
/// whenever the next window opens.
///
/// The caller's failure line reads `conn.stats()`, which takes quinn's
/// connection-state mutex, so an abort storm must not reach it per flow — a
/// `false` here keeps the storm off the mutex entirely. Both binaries carried
/// byte-identical copies of this state machine before it moved here.
pub fn tcp_abort_log_due() -> bool {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(NEVER_WARNED);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    match claim_log_window_counted(&LAST, &SUPPRESSED, crate::mono_millis()) {
        None => false,
        Some(n) => {
            if n > 0 {
                tracing::warn!("tcp aborts suppressed in the last window: {n}");
            }
            true
        }
    }
}
