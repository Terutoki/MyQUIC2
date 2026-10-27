//! Log rate-limiters and the 60 s UDP reporter.
use super::*;

/// Rate limit for the per-connection stream-share refusal line (1/s, with a
/// suppressed count, like the other per-flow abort logs).
///
/// The slot starts at [`NEVER_LOGGED`], not `0`: the mono epoch starts at
/// process start, so a `0`-initialised slot swallows the first second — exactly
/// the startup/reconnect burst these lines exist for.
pub(crate) fn warn_stream_share_refused() -> bool {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    match claim_log_window_counted(&LAST, &SUPPRESSED, mono_millis()) {
        None => false,
        Some(n) => {
            if n > 0 {
                tracing::warn!("tcp stream-share refusals suppressed in the last window: {n}");
            }
            true
        }
    }
}

/// Rate limit for "refusing new connection" logs under a flood.
pub(crate) fn warn_once_per_sec() -> bool {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    claim_log_window(&LAST, mono_millis())
}

/// Rate limit for session-socket setup failures (fd or memory exhaustion).
/// A separate slot from [`warn_once_per_sec`] on purpose: an fd-exhaustion
/// storm must not silence the connection-limit warning, and vice versa.
pub(crate) fn warn_sess_create_failed() -> bool {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(NEVER_LOGGED);
    claim_log_window(&LAST, mono_millis())
}

/// Never-claimed sentinel for the [`claim_server_log`] windows.
///
/// Mirrors the crate-private `myquic2::stats::warn::NEVER_WARNED` (`u64::MAX`),
/// which a bin crate cannot name. A `0`-initialised slot instead swallows the
/// process's first window: the mono epoch starts at process start, so
/// `now.saturating_sub(0) < LOG_WINDOW_MS` holds for the first second — which
/// is exactly the startup/reconnect burst these peer-driven lines exist for.
/// The lib-side contract (`claim_log_window_counted` treats `u64::MAX` as
/// "never claimed") is locked from here by
/// `never_logged_sentinel_claims_immediately`.
pub(crate) const NEVER_LOGGED: u64 = u64::MAX;

/// The peer-driven server lines that must not be formatted per event.
///
/// Each of these is reachable once per handshake/connection at a rate the peer
/// chooses. On the sharded current-thread ingress a formatted line takes
/// tracing's process-wide writer lock on the same thread that owns a whole
/// ingress shard's QUIC driver, so a handshake/accept flood can stall that
/// shard for however long stderr is slow (the same argument as
/// [`warn_stream_share_refused`], one layer out). One line per second per class
/// is enough to operate with; the window's losers are counted and folded into
/// the winner's line by [`Suppressed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerLog {
    /// One line per admitted QUIC connection (`handle_conn`).
    NewConn,
    /// Handshake failed before admission (peer RST, TLS error, ...).
    HandshakeFailed,
    /// Handshake exceeded its budget.
    HandshakeTimeout,
    /// `Incoming::accept` / handshake driver error.
    AcceptError,
    /// Client token authentication failed.
    AuthFailure,
}

/// One throttled class's state: the last claim stamp and the losers since it.
struct LogWindow {
    last: std::sync::atomic::AtomicU64,
    suppressed: std::sync::atomic::AtomicU64,
}

impl LogWindow {
    /// A window that has never claimed. `const fn` rather than an associated
    /// const: a `const` holding `AtomicU64`s is a named interior-mutable value
    /// (`clippy::declare_interior_mutable_const`), and each class needs its own
    /// distinct slot anyway.
    const fn new() -> Self {
        Self {
            last: std::sync::atomic::AtomicU64::new(NEVER_LOGGED),
            suppressed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// `None` inside the window (this event was just counted); `Some(n)` for the
    /// single winner, where `n` is how many events the previous window swallowed.
    fn claim(&self) -> Option<Suppressed> {
        claim_log_window_counted(&self.last, &self.suppressed, mono_millis()).map(Suppressed)
    }
}

// One slot pair per class: a shared slot would let a handshake-failure flood
// silence the auth-failure line, and the two mean different things (the same
// reason `UdpWriteDrop` and `dgram_drops::EgressDrop` are enums, not substrings).
static NEW_CONN_LOG: LogWindow = LogWindow::new();
static HANDSHAKE_FAILED_LOG: LogWindow = LogWindow::new();
static HANDSHAKE_TIMEOUT_LOG: LogWindow = LogWindow::new();
static ACCEPT_ERROR_LOG: LogWindow = LogWindow::new();
static AUTH_FAILURE_LOG: LogWindow = LogWindow::new();

/// Claim the one-per-second window for a peer-driven server line.
///
/// `Some(n)` means the caller should emit the line and may format it; `None`
/// means it was suppressed and counted. See [`ServerLog`] for why these are
/// throttled at all.
pub(crate) fn claim_server_log(class: ServerLog) -> Option<Suppressed> {
    let w = match class {
        ServerLog::NewConn => &NEW_CONN_LOG,
        ServerLog::HandshakeFailed => &HANDSHAKE_FAILED_LOG,
        ServerLog::HandshakeTimeout => &HANDSHAKE_TIMEOUT_LOG,
        ServerLog::AcceptError => &ACCEPT_ERROR_LOG,
        ServerLog::AuthFailure => &AUTH_FAILURE_LOG,
    };
    w.claim()
}

/// The suppressed count folded into a throttled line: displays as the empty
/// string while nothing has been swallowed, so a steady first line stays
/// byte-identical to the old unthrottled one, and as
/// `" (N similar suppressed in the last second)"` after a burst.
pub(crate) struct Suppressed(pub(crate) u64);

impl std::fmt::Display for Suppressed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            return Ok(());
        }
        write!(f, " ({} similar suppressed in the last second)", self.0)
    }
}
/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
///
/// The same cadence carries the rev2 data-plane counters (`r2_stats::Snapshot`,
/// W9). Before this they were read only by unit tests, so every claim about the
/// rev2 path — how many flows were opened/rejected, whether downlink
/// compression works (`steady_sent` vs `open_src_sent`), how the domain/DNS
/// paths behave, whether anything is being refused — was unobservable in the
/// shipped binary. The line is delta-based (like the relay line) and silent
/// when nothing moved.
pub(crate) fn spawn_udp_reporter() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if ONCE.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately; skip it
        let mut prev = udp_stats::snapshot();
        let mut prev_w = udp_write::snapshot();
        let mut prev_r = udp_stats::reassembly_drops();
        let mut prev_d = dgram_drops::snapshot();
        // `snapshot()` flushes this thread's pending batched rev2 cells first
        // (the same contract as `udp_stats::snapshot`): the reporter task is
        // scheduled on a runtime worker, which may have counted replies for a
        // session reader before the task migrated here, and a pending count
        // would otherwise stay invisible until that thread's next 256-record or
        // 1 s flush.
        let mut prev_r2 = r2_stats::snapshot();
        loop {
            tick.tick().await;
            let now = udp_stats::snapshot();
            let now_w = udp_write::snapshot();
            let d = now.since(&prev);
            let dw = now_w.since(&prev_w);
            if !d.is_idle() {
                info!(
                    "udp relay (60s): {d}; high-water payload {} B",
                    now.max_payload
                );
            }
            // The last-hop write outcomes, always logged: a silent drop here is
            // what a flat relay counter cannot show.
            if !(dw.sent == 0 && dw.retried == 0) || !dw.clean() {
                info!("udp write (60s): {dw}");
            }
            let now_r = udp_stats::reassembly_drops();
            if now_r != prev_r {
                info!(
                    "udp reassembly (60s): {} expired (missing fragment), {} evicted (memory cap)",
                    now_r.0.saturating_sub(prev_r.0),
                    now_r.1.saturating_sub(prev_r.1)
                );
                prev_r = now_r;
            }
            let now_d = dgram_drops::snapshot();
            let dd = now_d.since(&prev_d);
            // The budget paths only: `too_large`/`buffer_full` have their own
            // rate-limited per-packet warning and would double-report here.
            if dd.session_full > 0
                || dd.dns_budget > 0
                || dd.fair_share > 0
                || dd.sess_create_failed > 0
                || dd.refused > 0
            {
                info!(
                    "udp budget (60s): {} dropped (session cap), {} dropped (DNS slow-path budget), {} dropped (connection fair share), {} dropped (session setup failed), {} refused (policy); totals too_large={} buffer_full={} session_full={} dns_budget={} fair_share={} sess_create_failed={} refused={}",
                    dd.session_full,
                    dd.dns_budget,
                    dd.fair_share,
                    dd.sess_create_failed,
                    dd.refused,
                    now_d.too_large,
                    now_d.buffer_full,
                    now_d.session_full,
                    now_d.dns_budget,
                    now_d.fair_share,
                    now_d.sess_create_failed,
                    now_d.refused
                );
            }
            let now_r2 = r2_stats::snapshot();
            let dr2 = now_r2.since(&prev_r2);
            if let Some(line) = r2_report_line(&dr2) {
                info!("{line}");
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
            prev_r2 = now_r2;
        }
    });
}

/// The 60 s MQP-3 rev2 line for one interval, or `None` when nothing moved.
///
/// Pure so the "stay quiet when idle" contract and the line's prefix are
/// unit-testable without a live reporter task (the counters themselves are
/// process-global and other tests move them).
pub(crate) fn r2_report_line(d: &r2_stats::Snapshot) -> Option<String> {
    (!d.is_idle()).then(|| format!("mqp3 rev2 (60s): {d}"))
}
