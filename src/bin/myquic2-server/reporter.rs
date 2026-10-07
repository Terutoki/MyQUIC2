//! Log rate-limiters and the 60 s UDP reporter.
use super::*;

/// Rate limit for the per-connection stream-share refusal line (1/s, with a
/// suppressed count, like the other per-flow abort logs).
pub(crate) fn warn_stream_share_refused() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if LAST
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let n = SUPPRESSED.swap(0, Ordering::Relaxed);
        if n > 0 {
            tracing::warn!("tcp stream-share refusals suppressed in the last window: {n}");
        }
        true
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Rate limit for "refusing new connection" logs under a flood.
pub(crate) fn warn_once_per_sec() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        return false;
    }
    LAST.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Rate limit for session-socket setup failures (fd or memory exhaustion).
/// A separate slot from [`warn_once_per_sec`] on purpose: an fd-exhaustion
/// storm must not silence the connection-limit warning, and vice versa.
pub(crate) fn warn_sess_create_failed() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        return false;
    }
    LAST.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}
/// Rate limit for per-flow abort lines: the `conn.stats()` snapshot takes the
/// quinn connection-state mutex, so an abort storm must not pay it per flow.
pub(crate) fn tcp_abort_log_due() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = mono_millis();
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 1000 {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if LAST
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let n = SUPPRESSED.swap(0, Ordering::Relaxed);
        if n > 0 {
            tracing::warn!("tcp aborts suppressed in the last window: {n}");
        }
        true
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }
}
/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
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
                || dd.dns_inflight > 0
                || dd.dns_contention > 0
                || dd.sess_create_failed > 0
                || dd.refused > 0
            {
                info!(
                    "udp budget (60s): {} dropped (session cap), {} dropped (DNS slow-path budget), {} dropped (connection fair share), {} dropped (resolution in flight), {} dropped (DNS lock contention), {} dropped (session setup failed), {} refused (policy); totals too_large={} buffer_full={} session_full={} dns_budget={} fair_share={} dns_inflight={} dns_contention={} sess_create_failed={} refused={}",
                    dd.session_full,
                    dd.dns_budget,
                    dd.fair_share,
                    dd.dns_inflight,
                    dd.dns_contention,
                    dd.sess_create_failed,
                    dd.refused,
                    now_d.too_large,
                    now_d.buffer_full,
                    now_d.session_full,
                    now_d.dns_budget,
                    now_d.fair_share,
                    now_d.dns_inflight,
                    now_d.dns_contention,
                    now_d.sess_create_failed,
                    now_d.refused
                );
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
        }
    });
}
