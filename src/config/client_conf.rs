use serde::{Deserialize, Serialize};

use super::tuning::{DEFAULT_QUIC_CONNS, MAX_POOL_CONNS, d_5, d_bbr, d_keepalive, d_true};
use crate::dns::IpPreference;
use crate::mqp::ack::normalize_alpn;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConf {
    pub socks_listen: String,     // e.g. 127.0.0.1:1080
    pub server_addr: String,      // e.g. 127.0.0.1:8443
    pub server_name: String,      // SNI, must match cert SAN
    pub server_cert_file: String, // pinned self-signed cert PEM
    #[serde(default = "d_bbr")]
    pub congestion: String,
    #[serde(default = "d_true")]
    pub gso: bool,
    /// Address-family preference for DNS results: "ipv6" (default) or
    /// "ipv4". On the client this orders the `server_addr` lookup (which
    /// family the tunnel dials first) and the defensive domain-reply paths.
    #[serde(default)]
    pub dns_ip_preference: IpPreference,
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_5")]
    pub reconnect_timeout_secs: u64,
    /// Must match the server's `auth_token` (both empty = no authentication).
    #[serde(default)]
    pub auth_token: String,
    // ---- Transport tuning (mirrors ServerConf) ----
    #[serde(default)]
    pub stream_receive_window_mb: Option<u64>,
    #[serde(default)]
    pub receive_window_mb: Option<u64>,
    #[serde(default)]
    pub send_window_mb: Option<u64>,
    #[serde(default)]
    pub ack_threshold: Option<u32>,
    #[serde(default)]
    pub max_ack_delay_ms: Option<u64>,
    /// RTT seed in ms for loss detection/pacing until the first measured
    /// sample; default 190. Set it to the link's real RTT (e.g. 140 on a
    /// 140 ms link) to shorten the first PTO from ~575 ms to ~435 ms; only
    /// first-flight loss recovery is affected. Clamped 1..=3000.
    #[serde(default)]
    pub initial_rtt_ms: Option<u64>,
    // ---- Connection isolation ----
    // TCP pool size: bulk TCP spreads round-robin across the bulk slots while
    // ports in `interactive_ports` pin to slot 0, so a latency probe never
    // queues behind bulk on the same cwnd. Unset = DEFAULT_QUIC_CONNS (4); 1
    // restores the legacy single shared TCP connection; clamped to
    // 1..=MAX_POOL_CONNS. UDP egress is a separate, additional connection (see
    // `udp_fail_closed`) — it is never one of these slots.
    // quinn 0.11 exposes no per-stream priority API, so separate cwnds are
    // the only reliable isolation.
    #[serde(default)]
    pub quic_conns: Option<usize>,
    #[serde(default)]
    pub interactive_ports: Option<Vec<u16>>,
    /// What UDP egress does when its dedicated connection is down. `true`
    /// (default) drops the datagram — counted in `dgram_drops::NO_EGRESS` —
    /// instead of putting it on a TCP connection's congestion window. `false`
    /// restores the pre-separation behaviour: fall back to the interactive
    /// connection, then to the bulk slots, so UDP keeps flowing while sharing a
    /// cwnd with TCP traffic.
    #[serde(default)]
    pub udp_fail_closed: Option<bool>,
    /// Whether UDP egress is split into one dedicated connection per egress
    /// class (default `true`). Destinations in `interactive_ports`, and
    /// associations whose first datagram is no larger than 512 B
    /// (STUN/DTLS/RTP-sized media, DNS, games), ride the **interactive** UDP
    /// connection; everything else rides the **bulk** one — so a bulk flow's
    /// congestion window and 1 MB DATAGRAM send buffer cannot starve a
    /// latency-sensitive flow. A client with the split dials `quic_conns + 2`
    /// connections; `false` restores the single shared UDP connection
    /// (`quic_conns + 1`).
    #[serde(default)]
    pub udp_split: Option<bool>,
    /// ALPN override (e.g. `myquic2/2` to restore the versioned identifier).
    /// Unset/empty = `h3` masquerade.
    #[serde(default)]
    pub alpn: Option<String>,
}

impl ClientConf {
    /// Pool size: [`DEFAULT_QUIC_CONNS`] (4) when `quic_conns` is unset,
    /// clamped to `1..=`[`MAX_POOL_CONNS`]. 1 restores the legacy single
    /// connection.
    pub fn conn_count(&self) -> usize {
        self.quic_conns
            .unwrap_or(DEFAULT_QUIC_CONNS)
            .clamp(1, MAX_POOL_CONNS)
    }

    pub fn interactive_port_list(&self) -> Vec<u16> {
        self.interactive_ports
            .clone()
            .unwrap_or_else(|| vec![53, 123, 3478, 3479, 3480, 3481])
    }

    /// Whether UDP egress is confined to its dedicated connection. Default
    /// `true`: a datagram that has nowhere isolated to go is dropped and
    /// counted, rather than queued behind TCP traffic on a shared connection.
    pub fn udp_fail_closed(&self) -> bool {
        self.udp_fail_closed.unwrap_or(true)
    }

    /// Whether UDP egress is split by egress class. Default `true`; see the
    /// field's note for the classification and the connection count.
    pub fn udp_split(&self) -> bool {
        self.udp_split.unwrap_or(true)
    }

    pub fn alpn_bytes(&self) -> Vec<u8> {
        normalize_alpn(self.alpn.as_deref())
    }
}
