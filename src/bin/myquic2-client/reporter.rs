//! 60 s UDP activity reporter.
use super::*;

/// One UDP activity line per minute.
///
/// The only way to answer "is my UDP traffic actually going through the tunnel,
/// and how large does it get?" without a packet capture — which on an encrypted
/// tunnel can only ever show ciphertext. `high-water payload` is the empirical
/// check on `MQP_FRAG_MAX_PAYLOAD`: a deployment that never approaches it needs
/// no larger cap, whatever its workload is.
pub(crate) fn spawn_udp_reporter() {
    // One reporter per process: `main` calls this once today, and a second call
    // would double every 60 s line (the server's reporter has carried this guard
    // since it was written).
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
                    "udp reassembly (60s): {} expired (missing fragment), {} evicted (cap)",
                    now_r.0.saturating_sub(prev_r.0),
                    now_r.1.saturating_sub(prev_r.1)
                );
                prev_r = now_r;
            }
            // Every dropped datagram, including the two client-only egress paths
            // and the DNS ones this side used to drop without a counter. Without
            // this line the counters existed but nothing ever read them: the
            // server's reporter printed the same block, the client's did not.
            let now_d = dgram_drops::snapshot();
            let dd = now_d.since(&prev_d);
            if dd.lost() > 0 {
                info!(
                    "udp budget (60s): {} dropped (no egress connection), {} dropped (egress died), {} dropped (resolution in flight), {} dropped (DNS lock contention), {} dropped (DNS/session cap), {} refused (policy); totals too_large={} buffer_full={} no_egress={} egress_dead={} dns_inflight={} dns_contention={} session_full={} refused={}",
                    dd.no_egress,
                    dd.egress_dead,
                    dd.dns_inflight,
                    dd.dns_contention,
                    dd.session_full,
                    dd.refused,
                    now_d.too_large,
                    now_d.buffer_full,
                    now_d.no_egress,
                    now_d.egress_dead,
                    now_d.dns_inflight,
                    now_d.dns_contention,
                    now_d.session_full,
                    now_d.refused
                );
            }
            // Reported on its own line, and outside `lost()`: a late reply to a
            // session this side already closed is not a packet the tunnel failed
            // to carry, so folding it into the budget line would make every
            // ordinary association teardown look like loss. It is still worth a
            // line of its own — a number that only ever grows means the client is
            // reaping associations the server still considers live.
            if dd.unknown_sess > 0 {
                info!(
                    "udp late replies (60s): {} dropped (no such association); total {}",
                    dd.unknown_sess, now_d.unknown_sess
                );
            }
            prev_d = now_d;
            prev = now;
            prev_w = now_w;
        }
    });
}

// ---- SOCKS5 (RFC1928, no-auth only) ----
