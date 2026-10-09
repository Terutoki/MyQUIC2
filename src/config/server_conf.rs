use serde::{Deserialize, Serialize};

use super::tuning::{d_bbr, d_false, d_keepalive, d_true};
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
    // ---- Transport tuning (all optional; None = low-latency default) ----
    // Larger windows trade loaded latency for peak throughput: 4/8/4 MB
    // reaches ~240 Mb/s @140 ms and 8/16/8 MB reaches ~300 Mb/s, against the
    // 2/4/2 MB default (~114 Mb/s). ACK threshold 8 + 10 ms delay saves
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
    /// ALPN override (e.g. `myquic2/2` to restore the versioned identifier).
    /// Unset/empty = `h3` masquerade.
    #[serde(default)]
    pub alpn: Option<String>,
}

impl ServerConf {
    pub fn alpn_bytes(&self) -> Vec<u8> {
        normalize_alpn(self.alpn.as_deref())
    }
}
