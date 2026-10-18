use serde::{Deserialize, Serialize};

use super::tuning::{
    MAX_QUIC_ENDPOINTS, d_bbr, d_false, d_keepalive, d_true, default_quic_endpoints,
};
use crate::dns::IpPreference;
use crate::mqp::ack::normalize_alpn;

// ---------------- Config files ----------------
/// Unknown keys are a hard error (both config structs). A misspelled
/// `auth_token` used to deserialize as the empty string via `#[serde(default)]`
/// and silently *disable* client authentication, and a misspelled
/// `allow_private` silently flipped the SSRF policy — with no diagnostic at
/// startup. serde's error names the offending field and lists the accepted
/// ones, so a typo fails the process instead of changing its security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConf {
    pub listen: String,      // e.g. 0.0.0.0:8443
    pub cert_file: String,   // server cert PEM (self-signed)
    pub key_file: String,    // server key PEM
    pub server_name: String, // e.g. myquic2, used for self-sign SAN + SNI
    #[serde(default = "d_bbr")]
    pub congestion: String, // bbr | cubic
    #[serde(default = "d_true")]
    pub gso: bool, // informational: quinn-udp auto-enables; false = log warn only
    /// Address-family preference for resolved targets: "ipv6" (default) or
    /// "ipv4". Orders every resolved address list; the first entry leads UDP
    /// sends and TCP's happy-eyeballs dial. IP-literal targets are unaffected.
    #[serde(default)]
    pub dns_ip_preference: IpPreference,
    #[serde(default = "d_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default = "d_false")]
    pub allow_private: bool,
    /// Optional shared secret. When non-empty, every client must present it on
    /// connection setup; empty disables authentication (rely on network
    /// isolation / firewall).
    #[serde(default)]
    pub auth_token: String,
    /// Maximum concurrent QUIC connections admitted by this process.
    ///
    /// Unset means: `MAX_CONNECTIONS` (4096) when `auth_token` is set, and
    /// `MAX_UNAUTH_CONNECTIONS` (256) when it is not. That asymmetry is the
    /// point — with no token *every* peer is unauthenticated, so the connection
    /// budget is the pre-auth budget and the memory a peer can pin has to be
    /// bounded accordingly (each connection may hold its receive window, its
    /// send budget and both DATAGRAM buffers; see
    /// [`per_connection_memory_bytes`]). Clamped to `1..=MAX_CONNECTIONS`;
    /// raising it on a tokenless endpoint is warned about at startup.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Optional cap, in MiB, on the peer-pinnable memory the admitted
    /// connections may represent: the connection cap is additionally limited to
    /// `budget / per_connection_memory_bytes(tuning())`, so raising the transport
    /// windows automatically admits fewer connections rather than quietly
    /// multiplying the memory ceiling. Unset keeps the connection cap as the only
    /// bound; the worst case is logged at startup either way.
    #[serde(default)]
    pub max_peer_memory_mb: Option<u64>,
    // ---- Transport tuning (all optional; None = shipped default) ----
    // Shipped default windows are 4/8/4 MB, sized for the target ~140 ms link:
    // ~240 Mb/s single-flow. The 2/4/2 MB low-memory preset (~114 Mb/s) halves
    // the per-connection transport term, and 8/16/8 MB reaches ~300 Mb/s peak
    // at ~2x/4x loaded latency. ACK threshold 8 + 10 ms delay saves
    // reverse-path CPU at the cost of coarser RTT/loss feedback.
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
    /// 140 ms link) to shorten the first PTO; steady state is unaffected.
    /// Clamped 1..=3000.
    #[serde(default)]
    pub initial_rtt_ms: Option<u64>,
    /// Path MTU every new connection starts from, in bytes (clamped
    /// 1200..=1472; default 1360). Mirror the client's value: the tunnel's
    /// path is shared, and starting above quinn's 1200-byte floor removes the
    /// 4-probe-RTT ramp every connection pays before it can send 1472-byte
    /// packets. 1360 is 1388/1408 wire bytes after the IPv4/IPv6 + UDP
    /// headers, so it is safe on WireGuard-1420 and similar tunnel paths;
    /// operators on a known 1500-byte Ethernet path can set 1400 or 1472.
    /// See `ClientConf::initial_mtu`.
    #[serde(default)]
    pub initial_mtu: Option<u16>,
    /// ALPN override (e.g. `myquic2/3` to restore the versioned identifier).
    /// Unset/empty = `h3` masquerade.
    #[serde(default)]
    pub alpn: Option<String>,
    /// Number of QUIC ingress endpoints (UDP sockets sharing `listen` through
    /// `SO_REUSEPORT`) to run, and with them the number of accept loops, CID
    /// tables and receive queues serving this address.
    ///
    /// Unset means [`default_quic_endpoints`]: every usable core on Linux,
    /// where the kernel spreads a REUSEPORT group by connection 4-tuple, so
    /// the first per-packet cost — one driver doing every `recv` syscall,
    /// version check and CID lookup for the process before any connection
    /// task runs — scales with the cores. On a platform that delivers the
    /// whole group to a single member (macOS; the default there is 1) extra
    /// endpoints buy nothing, and the server logs that when they are
    /// requested anyway. 1 restores the strict singleton socket (no REUSEPORT
    /// is set at all). Clamped to `1..=MAX_QUIC_ENDPOINTS`; forced to 1 (with
    /// a warning) on platforms without REUSEPORT, where the second bind would
    /// fail.
    ///
    /// The trade-offs are REUSEPORT's, and are worth knowing before raising
    /// this: the kernel pins a connection to one member by its 4-tuple, so a
    /// client that changes its source address/port (NAT rebind) loses the
    /// connection instead of being followed to the endpoint that still knows
    /// its CIDs, and any other process on the host that sets REUSEPORT could
    /// bind the same address and take a share of the datagrams.
    #[serde(default)]
    pub quic_endpoints: Option<usize>,
}

impl ServerConf {
    pub fn alpn_bytes(&self) -> Vec<u8> {
        normalize_alpn(self.alpn.as_deref())
    }

    /// Effective QUIC ingress endpoint count: see [`ServerConf::quic_endpoints`]
    /// for the default rule and the clamps.
    pub fn endpoint_count(&self) -> usize {
        self.quic_endpoints
            .unwrap_or_else(default_quic_endpoints)
            .clamp(1, MAX_QUIC_ENDPOINTS)
    }
}
