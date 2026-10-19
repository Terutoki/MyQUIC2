use serde::{Deserialize, Serialize};

use super::tuning::{
    DEFAULT_QUIC_CONNS, DEFAULT_UDP_EGRESS_CONNS, MAX_POOL_CONNS, MAX_UDP_ASSOCS,
    MAX_UDP_EGRESS_CONNS, d_5, d_bbr, d_keepalive, d_true,
};
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
    /// Path MTU every new connection starts from, in bytes (clamped
    /// 1200..=1472; default 1200, the QUIC floor). A configured value below
    /// 1200 is raised to 1200 — QUIC forbids smaller packets. PMTU discovery
    /// is opportunistic, so at the default a busy connection can spend a long
    /// time at 1200: ~18-23% more packets and every UDP payload above 1150 B
    /// split into two MQP-2 fragments. Raise it on a known path: 1360 keeps
    /// the wire size at 1388 B (IPv4) / 1408 B (IPv6) after the IP+UDP
    /// headers, so it is safe on WireGuard-1420 and similar tunnel paths; a
    /// known 1500-byte Ethernet path can use 1400 or 1472 (zero discovery
    /// ramp, and 1420-byte UDP payloads stay a single frame at 1472).
    /// Mind the path when raising it: a too-high value costs a loss burst
    /// until quinn's black-hole detector resets to the 1200-byte floor.
    #[serde(default)]
    pub initial_mtu: Option<u16>,
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
    /// Destination UDP ports that always ride the **bulk** egress class,
    /// whatever their first payload size is (clamped to the interactive
    /// ports' precedence: a port in `interactive_ports` stays interactive).
    ///
    /// The egress class is fixed by the association's first datagram, and a
    /// tunnel's first packet is small (WireGuard handshake initiation is
    /// 148 B, OpenVPN control packets 14-60 B), so the size heuristic alone
    /// would bind a whole VPN tunnel to the single interactive connection —
    /// sharing one congestion window and DATAGRAM buffer with DNS/STUN/games,
    /// exactly the starvation the split exists to prevent. Unset = the
    /// shipped VPN list `[51820, 1194]` (WireGuard, OpenVPN). Set it to `[]`
    /// to restore the pure size heuristic, or add the ports a tunnel runs on.
    #[serde(default)]
    pub udp_bulk_ports: Option<Vec<u16>>,
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
    /// connection; everything else rides one of the **bulk** shards — so a
    /// bulk flow's congestion window and 1 MB DATAGRAM send buffer cannot
    /// starve a latency-sensitive flow. A client with the split dials
    /// `quic_conns + 1 + udp_egress_conns` connections; `false` restores the
    /// single shared UDP connection (`quic_conns + 1`) and disables sharding.
    #[serde(default)]
    pub udp_split: Option<bool>,
    /// Number of dedicated **bulk** UDP egress connections ("shards").
    ///
    /// Every bulk association is assigned one shard from its first datagram
    /// and keeps it for life (see `ConnPool::udp_bind`), so N bulk
    /// associations spread over min(N, k) connections — on both ends: the
    /// client gets k encrypt/ACK/send pipelines and k dispatcher tasks, and
    /// the server k per-connection DATAGRAM readers. On a many-core host
    /// raise it toward half the cores (up to 8); 1 restores the single bulk
    /// connection. Unset = `DEFAULT_UDP_EGRESS_CONNS` (2). The interactive
    /// class is never sharded (it must stay one stable connection), and
    /// `udp_split = false` ignores this value.
    #[serde(default)]
    pub udp_egress_conns: Option<usize>,
    /// Concurrent UDP-association cap for this client process. Unset =
    /// [`MAX_UDP_ASSOCS`] (4032); clamped to `1..=MAX_UDP_ASSOCS`.
    ///
    /// Each association owns its own relay socket — whose kernel send/receive
    /// buffer caps dominate its memory cost (~256 KiB on Linux after the
    /// kernel's `SO_*BUF` doubling) — plus an ~8 KiB userspace reader buffer,
    /// so a RAM-tight router lowers this instead of paying for the full set.
    /// Past the cap a UDP ASSOCIATE is refused with SOCKS5 `REP=0x01` and
    /// logged once per window, like the SOCKS admission cap.
    #[serde(default)]
    pub max_udp_assocs: Option<usize>,
    /// ALPN override (e.g. `myquic2/3` to restore the versioned identifier).
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

    /// Bulk UDP egress shard count: [`DEFAULT_UDP_EGRESS_CONNS`] (2) when
    /// `udp_egress_conns` is unset, clamped to
    /// `1..=`[`MAX_UDP_EGRESS_CONNS`]. The interactive class always keeps its
    /// single dedicated connection; this number multiplies the bulk class
    /// only, and only while `udp_split` is on.
    pub fn udp_egress_cnt(&self) -> usize {
        self.udp_egress_conns
            .unwrap_or(DEFAULT_UDP_EGRESS_CONNS)
            .clamp(1, MAX_UDP_EGRESS_CONNS)
    }

    /// Concurrent UDP-association cap: [`MAX_UDP_ASSOCS`] (4032) when
    /// `max_udp_assocs` is unset, clamped to `1..=MAX_UDP_ASSOCS`. This is the
    /// process-wide budget the hub enforces and the reason it exists is the
    /// per-association relay-socket memory noted on [`Self::max_udp_assocs`].
    pub fn udp_assoc_count(&self) -> usize {
        self.max_udp_assocs
            .unwrap_or(MAX_UDP_ASSOCS)
            .clamp(1, MAX_UDP_ASSOCS)
    }

    pub fn interactive_port_list(&self) -> Vec<u16> {
        self.interactive_ports
            .clone()
            .unwrap_or_else(|| vec![53, 123, 3478, 3479, 3480, 3481])
    }

    /// Destination ports forced to the bulk egress class regardless of first
    /// payload size (see [`ClientConf::udp_bulk_ports`]): the shipped default
    /// is the two common VPN data ports, so a WireGuard/OpenVPN tunnel is
    /// never mistaken for a small-packet interactive flow.
    pub fn udp_bulk_port_list(&self) -> Vec<u16> {
        self.udp_bulk_ports
            .clone()
            .unwrap_or_else(|| vec![51820, 1194])
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
