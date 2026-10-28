use std::net::SocketAddr;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use super::tuning::{
    DEFAULT_FORWARD_CONNS, DEFAULT_QUIC_CONNS, DEFAULT_UDP_EGRESS_CONNS,
    DEFAULT_UDP_INTERACTIVE_CONNS, MAX_POOL_CONNS, MAX_SOCKS_CONNS, MAX_UDP_ASSOCS,
    MAX_UDP_EGRESS_CONNS, MAX_UDP_INTERACTIVE_CONNS, d_5, d_bbr, d_keepalive, d_true,
};
use crate::dns::IpPreference;
use crate::mqp::ack::normalize_alpn;
use crate::mqp::addr::TargetAddr;
use crate::mqp::wire::{DEFAULT_REV, Wire};

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
    /// QUIC idle timeout in seconds, decoupled from `keep_alive_secs` (which
    /// stays the NAT/firewall refresh cadence).
    ///
    /// Unset means `max(3 x keep_alive_secs, 60)`. The client's silence
    /// watchdog is `2/3 x idle` (40 s at the shipped defaults) and its
    /// selection-time stale gate is the midpoint between keepalive and
    /// watchdog (22 s). An explicit value is clamped to
    /// `max(3 x keep_alive_secs, 15)..=900`; `15` restores the previous
    /// fast-detection behavior with a 5 s keepalive, while values above 60
    /// widen the no-drop window at the cost of slower true-failure detection.
    ///
    /// Both peers advertise an idle timeout and QUIC uses the minimum, so the
    /// same value must be set on both sides for the intended window.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
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
    /// would bind a whole VPN tunnel to the interactive connections —
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
    /// Whether UDP egress is split into dedicated connections per egress
    /// class (default `true`). Destinations in `interactive_ports`, and
    /// associations whose first datagram is no larger than 512 B
    /// (STUN/DTLS/RTP-sized media, DNS, games), ride the **interactive** UDP
    /// connections; everything else rides one of the **bulk** shards — so a
    /// bulk flow's congestion window and 1 MB DATAGRAM send buffer cannot
    /// starve a latency-sensitive flow. A client with the split dials
    /// `quic_conns + udp_interactive_conns + udp_egress_conns` connections;
    /// `false` restores the single shared UDP connection (`quic_conns + 1`) and
    /// disables sharding in both classes.
    #[serde(default)]
    pub udp_split: Option<bool>,
    /// Number of dedicated **interactive** UDP egress connections ("shards").
    ///
    /// Every interactive association is assigned one shard from its first
    /// datagram and keeps it for life (see `ConnPool::udp_bind`), so N such
    /// associations spread over min(N, k) connections instead of queueing on
    /// one shared 1 MiB DATAGRAM buffer, 256 KiB stager and congestion window.
    /// Unset = [`DEFAULT_UDP_INTERACTIVE_CONNS`] (2); 1 restores the single
    /// stable interactive connection, and `udp_split = false` ignores this
    /// value.
    #[serde(default)]
    pub udp_interactive_conns: Option<usize>,
    /// Number of dedicated **bulk** UDP egress connections ("shards").
    ///
    /// Every bulk association is assigned one shard from its first datagram
    /// and keeps it for life (see `ConnPool::udp_bind`), so N bulk
    /// associations spread over min(N, k) connections — on both ends: the
    /// client gets k encrypt/ACK/send pipelines and k dispatcher tasks, and
    /// the server k per-connection DATAGRAM readers. On a many-core host
    /// raise it toward half the cores (up to 8); 1 restores the single bulk
    /// connection. Unset = `DEFAULT_UDP_EGRESS_CONNS` (2). The interactive
    /// class has its own shard count ([`Self::udp_interactive_conns`]), and
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
    /// Process-wide cap on concurrent sessions across **all** `[[udp_forward]]`
    /// listeners. Unset = 3/4 of the effective [`Self::udp_assoc_count`]
    /// (≈3024 at the shipped 4032), so at least 1/4 of the process UDP-session
    /// budget always stays available to SOCKS5 `UDP ASSOCIATE`.
    ///
    /// This is the aggregate budget; one `[[udp_forward]]` entry's own
    /// `max_sessions` bounds that listener inside it. Without the aggregate
    /// budget a single busy forward listener (default `max_sessions` = the whole
    /// process cap) could fill the hub and deny new SOCKS associations for up to
    /// the 180 s idle reap, which is exactly the failure this knob prevents.
    /// Clamped to `1..=MAX_UDP_ASSOCS`.
    #[serde(default)]
    pub max_forward_sessions: Option<usize>,
    /// Process-wide cap on concurrent connections across **all**
    /// `[[tcp_forward]]` listeners. Unset = [`DEFAULT_FORWARD_CONNS`] (3/4 of
    /// the shared relay cap, i.e. 6144), leaving at least 1/4 of the relay
    /// permits for SOCKS5 `CONNECT`. Clamped to `1..=MAX_SOCKS_CONNS`.
    #[serde(default)]
    pub max_forward_conns: Option<usize>,
    /// Application-layer wire revision: `2` = shipped MQP-3 rev2, `3` = the
    /// clean-slate rev3 wire. Unset = the build default ([`DEFAULT_REV`]).
    ///
    /// Both binaries of a deployment must agree. Both revisions default to the
    /// shared `h3` ALPN masquerade, so ALPN is a deployment label rather than a
    /// revision switch: a mixed pair with the same label completes the TLS
    /// handshake and then fails silently at the data plane (nothing is
    /// forwarded or misrouted). Pin distinct `alpn` labels across revisions to
    /// get a TLS-level skew gate. There is no runtime negotiation and no
    /// fallback by design.
    #[serde(default)]
    pub wire_rev: Option<u8>,
    /// ALPN label override. Unset/empty = the historical `h3` masquerade,
    /// which is the default for **both** wire revisions; a custom label is
    /// used verbatim (e.g. `myquic2/r3` for rev3, `myquic2/3` for rev2).
    ///
    /// The label is a deployment choice, not a revision switch: both sides
    /// must run the same value. Distinct labels across revisions give a
    /// TLS-level fail-fast gate, while the default shared `h3` label means a
    /// mismatched pair (rev2 vs rev3) completes the handshake and then fails
    /// silently at the data plane — deploy matched binaries.
    #[serde(default)]
    pub alpn: Option<String>,
    // ---- Forward listeners (client-only; both arrays empty = disabled) ----
    /// TCP forward listeners: bind `listen`, relay every accepted stream
    /// through the QUIC pool to `target`. Validated by
    /// [`ClientConf::tcp_forwards`] at startup.
    #[serde(default)]
    pub tcp_forward: Vec<ForwardEntry>,
    /// UDP forward listeners: bind `listen`, one client session per source
    /// `IP:port`, each datagram relayed through the MQP-3 rev2 DATAGRAM path
    /// to `target`. Validated by [`ClientConf::udp_forwards`] at startup.
    #[serde(default)]
    pub udp_forward: Vec<UdpForwardEntry>,
}

/// One `[[tcp_forward]]` / `[[udp_forward]]` entry exactly as written in TOML.
///
/// The strings are deliberately unparsed here: validation lives in
/// [`ClientConf::tcp_forwards`] / [`ClientConf::udp_forwards`], which run at
/// startup and can name the bad entry index. Making the *serde* layer reject a
/// value would lose that context, and a silently skipped listener is the one
/// failure mode a forward feature must not have.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardEntry {
    /// Local listen address, `IP:port` (an IP literal; no hostname resolution).
    pub listen: String,
    /// Destination after the QUIC hop, `IP:port` or `host:port`. A domain is
    /// resolved and policy-checked by the **server**, like every SOCKS target.
    pub target: String,
    /// Concurrent connections this listener may relay. Unset = the process-wide
    /// `max_forward_conns` budget (no extra per-listener constraint); clamped to
    /// `1..=MAX_SOCKS_CONNS`. Ignored by `[[udp_forward]]` (it has
    /// `max_sessions`).
    #[serde(default)]
    pub max_conns: Option<usize>,
}

/// UDP variant of [`ForwardEntry`] with the optional per-listener session cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForwardEntry {
    pub listen: String,
    pub target: String,
    /// Concurrent per-peer sessions for this listener. Unset = the process-wide
    /// forward-session budget ([`ClientConf::forward_session_budget`]), which is
    /// itself below `max_udp_assocs` so SOCKS keeps a reserved share; clamped to
    /// `1..=MAX_UDP_ASSOCS`.
    #[serde(default)]
    pub max_sessions: Option<usize>,
}

/// A validated TCP forward listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpForwardSpec {
    pub listen: SocketAddr,
    pub target: TargetAddr,
    /// Effective per-listener connection cap (`1..=MAX_SOCKS_CONNS`).
    pub max_conns: usize,
}

/// A validated UDP forward listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpForwardSpec {
    pub listen: SocketAddr,
    pub target: TargetAddr,
    /// Effective per-listener peer cap (`1..=MAX_UDP_ASSOCS`).
    pub max_sessions: usize,
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
    /// `1..=`[`MAX_UDP_EGRESS_CONNS`]. The interactive class has its own count
    /// ([`Self::udp_interactive_cnt`]); this number multiplies the bulk class
    /// only, and only while `udp_split` is on.
    pub fn udp_egress_cnt(&self) -> usize {
        self.udp_egress_conns
            .unwrap_or(DEFAULT_UDP_EGRESS_CONNS)
            .clamp(1, MAX_UDP_EGRESS_CONNS)
    }

    /// Interactive UDP egress shard count:
    /// [`DEFAULT_UDP_INTERACTIVE_CONNS`] (2) when `udp_interactive_conns` is
    /// unset, clamped to `1..=`[`MAX_UDP_INTERACTIVE_CONNS`]. 1 is the legacy
    /// shape — every small-first-datagram association on one connection.
    pub fn udp_interactive_cnt(&self) -> usize {
        self.udp_interactive_conns
            .unwrap_or(DEFAULT_UDP_INTERACTIVE_CONNS)
            .clamp(1, MAX_UDP_INTERACTIVE_CONNS)
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

    /// Process-wide cap on concurrent sessions across all `[[udp_forward]]`
    /// listeners: `max_forward_sessions` when set, else 3/4 of the effective
    /// [`Self::udp_assoc_count`] (never below 1). Clamped to
    /// `1..=MAX_UDP_ASSOCS`.
    ///
    /// The default deliberately leaves a quarter of the process UDP-session
    /// budget reserved for SOCKS5 `UDP ASSOCIATE`: forwarding is a shared
    /// consumer of `UdpHub`, and without the reserve a churn-heavy listener can
    /// fill it and deny SOCKS for up to the 180 s idle reap. An operator who
    /// wants the whole budget for forwarding sets `max_forward_sessions`.
    pub fn forward_session_budget(&self) -> usize {
        let udp_cap = self.udp_assoc_count();
        self.max_forward_sessions
            .unwrap_or_else(|| default_forward_share(udp_cap))
            .clamp(1, MAX_UDP_ASSOCS)
    }

    /// Process-wide cap on concurrent connections across all
    /// `[[tcp_forward]]` listeners: `max_forward_conns` when set, else
    /// [`DEFAULT_FORWARD_CONNS`] (3/4 of [`MAX_SOCKS_CONNS`]). Clamped to
    /// `1..=MAX_SOCKS_CONNS`.
    pub fn forward_conn_budget(&self) -> usize {
        self.max_forward_conns
            .unwrap_or(DEFAULT_FORWARD_CONNS)
            .clamp(1, MAX_SOCKS_CONNS)
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

    /// Application-layer wire revision selected by this configuration.
    ///
    /// An out-of-range `wire_rev` is rejected at startup by
    /// [`Self::validate_wire_rev`]; this accessor falls back to the build
    /// default so a partially-validated config can never change the wire
    /// silently. The revision is not encoded in ALPN by default (both
    /// revisions default to the `h3` masquerade), so only a matched deployment
    /// is supported.
    pub fn wire(&self) -> Wire {
        Wire::from_rev(self.wire_rev.unwrap_or(DEFAULT_REV)).unwrap_or(Wire::Rev2)
    }

    /// Whether the configuration pins a valid wire revision and an ALPN that
    /// matches it. Called at startup by the client binary.
    pub fn validate_wire_rev(&self) -> anyhow::Result<()> {
        crate::mqp::wire::validate_config(self.wire_rev, self.alpn.as_deref())
    }

    pub fn alpn_bytes(&self) -> Vec<u8> {
        // Same resolution for both revisions: the default is the `h3`
        // masquerade; a configured label is used verbatim. ALPN does not
        // encode the wire revision by default.
        normalize_alpn(self.alpn.as_deref())
    }

    /// Validate and lower the `[[tcp_forward]]` tables.
    ///
    /// Every failure names the entry index and the offending field: a forward
    /// listener that "just does not start" is indistinguishable from a typo,
    /// and the operator has no other signal (the process would look healthy).
    pub fn tcp_forwards(&self) -> anyhow::Result<Vec<TcpForwardSpec>> {
        if self.tcp_forward.len() > MAX_FORWARD_LISTENERS {
            bail!(
                "{} [[tcp_forward]] entries configured: more than the {MAX_FORWARD_LISTENERS} \
                 listener cap (each listener owns a socket, a task and a backlog queue)",
                self.tcp_forward.len()
            );
        }
        let socks = self.socks_listen.parse::<SocketAddr>().ok();
        let mut seen: Vec<(usize, SocketAddr)> = Vec::with_capacity(self.tcp_forward.len());
        let mut out = Vec::with_capacity(self.tcp_forward.len());
        for (i, e) in self.tcp_forward.iter().enumerate() {
            let listen = parse_forward_listen("tcp_forward", i, &e.listen)?;
            if let Some(socks) = socks
                && listen_overlaps(listen, socks)
            {
                bail!(
                    "tcp_forward[{i}].listen {:?}: overlaps socks_listen {socks} \
                     (same port, wildcard or identical address)",
                    e.listen
                );
            }
            if let Some((j, other)) = seen
                .iter()
                .find(|(_, other)| listen_overlaps(listen, *other))
            {
                bail!(
                    "tcp_forward[{i}].listen {:?}: overlaps tcp_forward[{j}] listening on {other}",
                    e.listen
                );
            }
            seen.push((i, listen));
            let max_conns = match e.max_conns {
                Some(0) => bail!("tcp_forward[{i}].max_conns 0: must be >= 1"),
                Some(n) => n.clamp(1, MAX_SOCKS_CONNS),
                None => self.forward_conn_budget(),
            };
            out.push(TcpForwardSpec {
                listen,
                max_conns,
                target: parse_forward_target("tcp_forward", i, &e.target)?,
            });
        }
        Ok(out)
    }

    /// Validate and lower the `[[udp_forward]]` tables (see
    /// [`ClientConf::tcp_forwards`] for the error-shape rationale).
    pub fn udp_forwards(&self) -> anyhow::Result<Vec<UdpForwardSpec>> {
        if self.udp_forward.len() > MAX_FORWARD_LISTENERS {
            bail!(
                "{} [[udp_forward]] entries configured: more than the {MAX_FORWARD_LISTENERS} \
                 listener cap (each listener owns a socket, a task and a 30 s timer)",
                self.udp_forward.len()
            );
        }
        let mut seen: Vec<(usize, SocketAddr)> = Vec::with_capacity(self.udp_forward.len());
        let mut out = Vec::with_capacity(self.udp_forward.len());
        for (i, e) in self.udp_forward.iter().enumerate() {
            let listen = parse_forward_listen("udp_forward", i, &e.listen)?;
            if let Some((j, other)) = seen
                .iter()
                .find(|(_, other)| listen_overlaps(listen, *other))
            {
                bail!(
                    "udp_forward[{i}].listen {:?}: overlaps udp_forward[{j}] listening on {other}",
                    e.listen
                );
            }
            seen.push((i, listen));
            let max_sessions = match e.max_sessions {
                Some(0) => bail!("udp_forward[{i}].max_sessions 0: must be >= 1"),
                Some(n) => n.clamp(1, MAX_UDP_ASSOCS),
                None => self.forward_session_budget(),
            };
            out.push(UdpForwardSpec {
                listen,
                target: parse_forward_target("udp_forward", i, &e.target)?,
                max_sessions,
            });
        }
        Ok(out)
    }
}

/// Upper bound on configured forward listeners per protocol (`[[tcp_forward]]`
/// and `[[udp_forward]]` are capped independently).
///
/// Each listener owns a socket, a task and (TCP) a 1024-deep backlog queue;
/// validation is also O(n²) in the listener count. A generated config with
/// thousands of entries would stall startup and pin kernel queues, so the
/// count is capped rather than silently accepted. The ceiling is far above any
/// real port-forward deployment.
pub const MAX_FORWARD_LISTENERS: usize = 256;

/// Share of a process budget that forwarding may take by default: everything
/// but a quarter, so the SOCKS endpoint always keeps a reserve. The quarter is
/// floored at one slot and the result is floored at one, so even the tiniest
/// caps (`max_udp_assocs` 2..=7) keep a genuine SOCKS reserve instead of
/// silently granting forwarding the whole budget.
fn default_forward_share(cap: usize) -> usize {
    cap.saturating_sub((cap / 4).max(1)).max(1)
}

/// Fold an IPv4-mapped IPv6 address back to IPv4, so `[::ffff:127.0.0.1]` and
/// `127.0.0.1` name the same listener.
fn unmap_listen_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Whether two configured listen addresses can accept the same traffic.
///
/// Exact equality is not enough. Both sockets are local, on the same port, and
/// `tcp_listener_dual` / `udp_socket_dual` bind an IPv6 socket dual-stack; an
/// unspecified address covers every address of its family and — for an IPv6
/// wildcard, which is dual-stack — every IPv4 address too. With the shipped
/// `socks_listen = "[::]:1080"`, a `[[tcp_forward]] listen = "127.0.0.1:1080"`
/// must be rejected: the forward listener binds first, SOCKS still binds the
/// dual-stack wildcard on some platforms, and loopback SOCKS clients would
/// silently be relayed to the forward target.
///
/// The cross-family case is deliberately asymmetric: an IPv4 wildcard
/// (`0.0.0.0:P`) does **not** overlap a concrete IPv6 address, because an
/// AF_INET socket cannot receive IPv6 traffic; rejecting that pair would refuse
/// a configuration that binds cleanly. Only the IPv6 wildcard (`[::]:P`) covers
/// the other family, because it is bound with `V6ONLY=0`.
fn listen_overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    use std::net::IpAddr;
    if a.port() != b.port() {
        return false;
    }
    let a_ip = unmap_listen_ip(a.ip());
    let b_ip = unmap_listen_ip(b.ip());
    match (a_ip, b_ip) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V6(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        // A v4-mapped form was unmapped to V4 above, so a cross-family pair here
        // is a genuine v4 address vs a genuine v6 address. Only the v6 wildcard
        // (dual-stack) can receive the v4 traffic.
        (IpAddr::V6(v6), IpAddr::V4(_)) | (IpAddr::V4(_), IpAddr::V6(v6)) => v6.is_unspecified(),
    }
}

/// Parse one forward `listen` value: an `IP:port` literal with a non-zero port.
///
/// Local binding never resolves a hostname (the socket API cannot anyway), so
/// an impossible-but-plausible `"example.com:8080"` is rejected with the field
/// name instead of surfacing later as a bind error from inside the runtime.
fn parse_forward_listen(kind: &str, idx: usize, raw: &str) -> anyhow::Result<SocketAddr> {
    if !raw.contains(':') {
        bail!("{kind}[{idx}].listen {raw:?}: missing :port");
    }
    let addr: SocketAddr = raw
        .parse()
        .with_context(|| format!("{kind}[{idx}].listen {raw:?}: not an IP:port address"))?;
    if addr.port() == 0 {
        bail!("{kind}[{idx}].listen {raw:?}: port 0 is not a valid listen port");
    }
    Ok(addr)
}

/// Parse one forward `target` value: an `IP:port`/`[v6]:port` literal or a
/// `host:port` domain target, both non-zero port.
///
/// The domain form is passed through untouched: DNS, SSRF policy and
/// `allow_private` all live at the server exit, and this client must not
/// resolve (or cache) the name first — that is the property that keeps the
/// exit the single authorization point.
fn parse_forward_target(kind: &str, idx: usize, raw: &str) -> anyhow::Result<TargetAddr> {
    if !raw.contains(':') {
        bail!("{kind}[{idx}].target {raw:?}: missing :port");
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        if addr.port() == 0 {
            bail!("{kind}[{idx}].target {raw:?}: port 0 is not a valid target port");
        }
        // Unmap before the unspecified test: `[::ffff:0.0.0.0]:80` is the
        // IPv4-any address, not a concrete IPv6 address, and `Ipv6Addr::
        // is_unspecified` is false for the mapped form. Without the unmap it
        // slips past both this check and the shared wire encoder's
        // "refuse unspecified" rule and the server may dial its own loopback.
        if unmap_listen_ip(addr.ip()).is_unspecified() {
            bail!("{kind}[{idx}].target {raw:?}: unspecified address is not a valid target");
        }
        return Ok(TargetAddr::Ip(addr));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        // `contains(':')` above makes this unreachable; kept total anyway.
        bail!("{kind}[{idx}].target {raw:?}: missing :port");
    };
    if host.is_empty() {
        bail!("{kind}[{idx}].target {raw:?}: empty host");
    }
    if host.contains(':') {
        bail!("{kind}[{idx}].target {raw:?}: IPv6 literal must be bracketed, e.g. [::1]:443");
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("{kind}[{idx}].target {raw:?}: invalid port (want 1..=65535)"))?;
    if port == 0 {
        bail!("{kind}[{idx}].target {raw:?}: port 0 is not a valid target port");
    }
    if host.len() > 255 {
        bail!("{kind}[{idx}].target {raw:?}: domain longer than the 255-byte wire limit");
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("{kind}[{idx}].target {raw:?}: domain contains whitespace or control characters");
    }
    Ok(TargetAddr::Domain(host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid client config; each test appends the forward tables it
    /// exercises. Keeping the shared prefix in one place stops the tests from
    /// drifting apart as required fields are added.
    const BASE: &str = r#"
socks_listen = "127.0.0.1:1080"
server_addr = "127.0.0.1:8443"
server_name = "test.com"
server_cert_file = "server-cert.pem"
"#;

    fn parse_ok(extra: &str) -> ClientConf {
        let c: ClientConf = toml::from_str(&format!("{BASE}\n{extra}"))
            .expect("the base config plus this table must parse");
        c
    }

    /// Same as [`parse_ok`] but with a caller-chosen `socks_listen`, for the
    /// wildcard-overlap cases (the shipped sample binds `[::]:1080`).
    fn parse_with_socks(socks: &str, extra: &str) -> ClientConf {
        toml::from_str(&format!(
            "socks_listen = {socks:?}\n\
             server_addr = \"127.0.0.1:8443\"\n\
             server_name = \"test.com\"\n\
             server_cert_file = \"server-cert.pem\"\n\
             {extra}"
        ))
        .expect("the config with a custom socks_listen must parse")
    }

    #[test]
    fn wire_rev_is_parsed_validated_and_alpn_defaults_to_h3() {
        use crate::mqp::wire::Wire;

        // Unset follows the build default, which is rev3 after the rollover,
        // and both revisions default to the shared h3 masquerade label.
        let c = parse_ok("");
        assert_eq!(c.wire(), Wire::Rev3);
        assert_eq!(c.alpn_bytes(), b"h3");
        assert!(c.validate_wire_rev().is_ok());

        let c = parse_ok("wire_rev = 3\n");
        assert_eq!(c.wire(), Wire::Rev3);
        assert_eq!(c.alpn_bytes(), b"h3");
        assert!(c.validate_wire_rev().is_ok());

        // Explicit rev2 is the one-release rollback wire; it also defaults to
        // the h3 masquerade.
        let c = parse_ok("wire_rev = 2\n");
        assert_eq!(c.wire(), Wire::Rev2);
        assert_eq!(c.alpn_bytes(), b"h3");
        assert!(c.validate_wire_rev().is_ok());

        // A custom label is a deployment choice, accepted for any revision (it
        // is not a revision switch). Empty stays the h3 default.
        let c = parse_ok("wire_rev = 3\nalpn = \"h3\"\n");
        assert_eq!(c.wire(), Wire::Rev3);
        assert_eq!(c.alpn_bytes(), b"h3");
        assert!(c.validate_wire_rev().is_ok());
        let c = parse_ok("wire_rev = 3\nalpn = \"myquic2/r3\"\n");
        assert_eq!(c.wire(), Wire::Rev3);
        assert_eq!(c.alpn_bytes(), b"myquic2/r3");
        assert!(c.validate_wire_rev().is_ok());
        let c = parse_ok("wire_rev = 2\nalpn = \"myquic2/2\"\n");
        assert_eq!(c.wire(), Wire::Rev2);
        assert_eq!(c.alpn_bytes(), b"myquic2/2");
        assert!(c.validate_wire_rev().is_ok());
        let c = parse_ok("alpn = \"\"\n");
        assert_eq!(c.alpn_bytes(), b"h3");

        // Only the revision number is validated.
        assert!(parse_ok("wire_rev = 4\n").validate_wire_rev().is_err());
        assert!(parse_ok("wire_rev = 0\n").validate_wire_rev().is_err());
    }

    fn validation_err(extra: &str) -> String {
        let c = parse_ok(extra);
        match c
            .tcp_forwards()
            .map(|_| ())
            .and_then(|_| c.udp_forwards().map(|_| ()))
        {
            Ok(()) => panic!("expected a validation error for:\n{extra}"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn forward_tables_parse_and_lower() {
        let c = parse_ok(
            r#"
[[tcp_forward]]
listen = "127.0.0.1:8080"
target = "example.com:80"

[[tcp_forward]]
listen = "127.0.0.1:8081"
target = "10.0.0.5:443"

[[udp_forward]]
listen = "127.0.0.1:5353"
target = "1.1.1.1:53"

[[udp_forward]]
listen = "0.0.0.0:5354"
target = "[2001:db8::1]:53"
max_sessions = 7
"#,
        );
        let tcp = c.tcp_forwards().unwrap();
        assert_eq!(tcp.len(), 2);
        assert_eq!(tcp[0].listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(tcp[0].max_conns, c.forward_conn_budget());
        assert_eq!(
            tcp[0].target,
            TargetAddr::Domain("example.com".to_string(), 80)
        );
        assert_eq!(
            tcp[1].target,
            TargetAddr::Ip("10.0.0.5:443".parse().unwrap())
        );
        let udp = c.udp_forwards().unwrap();
        assert_eq!(udp.len(), 2);
        assert_eq!(udp[0].max_sessions, c.forward_session_budget());
        assert_eq!(udp[1].max_sessions, 7);
        assert_eq!(
            udp[1].target,
            TargetAddr::Ip("[2001:db8::1]:53".parse().unwrap())
        );
    }

    #[test]
    fn forward_tables_are_optional() {
        let c = parse_ok("");
        assert!(c.tcp_forward.is_empty());
        assert!(c.udp_forward.is_empty());
        assert!(c.tcp_forwards().unwrap().is_empty());
        assert!(c.udp_forwards().unwrap().is_empty());
    }

    #[test]
    fn forward_listen_and_target_rules() {
        for (table, needle) in [
            (
                "[[tcp_forward]]\nlisten = \"127.0.0.1\"\ntarget = \"example.com:80\"",
                "missing :port",
            ),
            (
                "[[tcp_forward]]\nlisten = \"127.0.0.1:0\"\ntarget = \"example.com:80\"",
                "port 0",
            ),
            (
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"example.com\"",
                "missing :port",
            ),
            (
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"1.1.1.1:0\"",
                "port 0",
            ),
            (
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"0.0.0.0:53\"",
                "unspecified",
            ),
            (
                // IPv4-mapped ANY is the v4 wildcard in a v6 literal; the
                // unspecified test must unmap before deciding.
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"[::ffff:0.0.0.0]:53\"",
                "unspecified",
            ),
            (
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"[::]:53\"",
                "unspecified",
            ),
            (
                "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"::1:80\"",
                "bracketed",
            ),
            (
                "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"1.1.1.1:53\"\nmax_sessions = 0",
                "max_sessions",
            ),
            (
                "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"example.com:80\"\nmax_conns = 0",
                "max_conns",
            ),
        ] {
            let err = validation_err(table);
            assert!(
                err.contains(needle),
                "expected {needle:?} in error for\n{table}\ngot: {err}"
            );
        }
    }

    #[test]
    fn forward_listeners_must_be_unique_and_not_socks() {
        for table in [
            "[[tcp_forward]]\nlisten = \"127.0.0.1:1080\"\ntarget = \"example.com:80\"",
            "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"b.example:80\"",
            "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"1.1.1.1:53\"\n[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"8.8.8.8:53\"",
        ] {
            let err = validation_err(table);
            assert!(
                err.contains("overlaps"),
                "expected an overlap error for\n{table}\ngot: {err}"
            );
        }
        // Same `IP:port` across TCP and UDP is legal: different protocols.
        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"example.com:80\"\n[[udp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"1.1.1.1:53\"",
        );
        assert!(c.tcp_forwards().is_ok());
        assert!(c.udp_forwards().is_ok());
    }

    #[test]
    fn forward_entry_rejects_unknown_fields() {
        let err = toml::from_str::<ClientConf>(&format!(
            "{BASE}\n[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"1.1.1.1:53\"\nlisen = \"typo\""
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unknown field"),
            "deny_unknown_fields must name the typo: {err}"
        );
    }

    #[test]
    fn udp_forward_max_sessions_clamps_to_the_global_cap() {
        let c = parse_ok(&format!(
            "[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"1.1.1.1:53\"\nmax_sessions = {}",
            MAX_UDP_ASSOCS + 10_000
        ));
        assert_eq!(c.udp_forwards().unwrap()[0].max_sessions, MAX_UDP_ASSOCS);
    }

    /// Overlap validation must catch wildcard-vs-specific on the same port, not
    /// just exact duplicates: the forward listeners bind before the SOCKS listener,
    /// so a missed overlap silently routes SOCKS clients into a forward target.
    #[test]
    fn forward_listener_overlap_rejects_wildcards_and_specifics() {
        // The shipped sample: socks_listen = "[::]:1080" plus a loopback forward on
        // the same port.
        let c = parse_with_socks(
            "[::]:1080",
            "[[tcp_forward]]\nlisten = \"127.0.0.1:1080\"\ntarget = \"example.com:80\"",
        );
        let err = format!(
            "{:#}",
            c.tcp_forwards()
                .expect_err("wildcard/specific overlap must be rejected")
        );
        assert!(err.contains("overlaps socks_listen"), "{err}");

        // v4 wildcard vs specific between two forwards, and the v6 wildcard form.
        for table in [
            "[[tcp_forward]]\nlisten = \"0.0.0.0:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"b.example:80\"",
            "[[tcp_forward]]\nlisten = \"[::]:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"b.example:80\"",
            "[[tcp_forward]]\nlisten = \"0.0.0.0:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"[::]:8080\"\ntarget = \"b.example:80\"",
        ] {
            let c = parse_ok(table);
            let err = format!(
                "{:#}",
                c.tcp_forwards()
                    .expect_err("wildcard overlap must be rejected")
            );
            assert!(err.contains("overlaps tcp_forward[0]"), "{err}");
        }

        // An IPv4-mapped IPv6 literal names the same listener as plain IPv4.
        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"[::ffff:127.0.0.1]:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"b.example:80\"",
        );
        assert!(
            c.tcp_forwards().is_err(),
            "v4-mapped v6 and v4 must be the same listen address"
        );

        // UDP uses the same rule.
        let c = parse_ok(
            "[[udp_forward]]\nlisten = \"[::]:5353\"\ntarget = \"1.1.1.1:53\"\n[[udp_forward]]\nlisten = \"127.0.0.1:5353\"\ntarget = \"8.8.8.8:53\"",
        );
        let err = format!(
            "{:#}",
            c.udp_forwards()
                .expect_err("UDP wildcard overlap must be rejected")
        );
        assert!(err.contains("overlaps udp_forward[0]"), "{err}");

        // Distinct concrete addresses on one port stay legal, and TCP+UDP may share
        // a port (different protocols).
        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"a.example:80\"\n[[tcp_forward]]\nlisten = \"127.0.0.2:8080\"\ntarget = \"b.example:80\"\n[[udp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"1.1.1.1:53\"",
        );
        assert!(
            c.tcp_forwards().is_ok(),
            "distinct concrete addresses overlap nothing"
        );
        assert!(
            c.udp_forwards().is_ok(),
            "TCP and UDP may share a port number"
        );
    }

    /// The aggregate forward budgets are the config half of "forwarding cannot
    /// deny the SOCKS endpoint": 3/4 by default, leaving a quarter reserved.
    #[test]
    fn forward_budgets_reserve_a_socks_share_by_default() {
        let c = parse_ok("");
        assert_eq!(c.forward_conn_budget(), DEFAULT_FORWARD_CONNS);
        assert_eq!(c.forward_session_budget(), 3024);
        assert!(
            c.forward_session_budget() < c.udp_assoc_count(),
            "the forwarding default must leave a SOCKS reserve"
        );
        assert!(c.forward_session_budget() + c.udp_assoc_count() / 4 <= c.udp_assoc_count() + 1);

        // Explicit knobs are honored, and clamped to the process caps.
        let c: ClientConf = toml::from_str(&format!(
            "{BASE}\nmax_forward_conns = 100\nmax_forward_sessions = 7"
        ))
        .unwrap();
        assert_eq!(c.forward_conn_budget(), 100);
        assert_eq!(c.forward_session_budget(), 7);

        let c: ClientConf = toml::from_str(&format!(
            "{BASE}\nmax_forward_conns = 999999\nmax_forward_sessions = 999999"
        ))
        .unwrap();
        assert_eq!(c.forward_conn_budget(), MAX_SOCKS_CONNS);
        assert_eq!(c.forward_session_budget(), MAX_UDP_ASSOCS);

        // A lowered UDP budget shrinks the forwarding default with it, so the
        // reserve follows the operator's `max_udp_assocs` rather than the
        // process constant.
        let c: ClientConf = toml::from_str(&format!("{BASE}\nmax_udp_assocs = 100")).unwrap();
        assert_eq!(c.forward_session_budget(), 75);
        let c: ClientConf = toml::from_str(&format!("{BASE}\nmax_udp_assocs = 1")).unwrap();
        assert_eq!(c.forward_session_budget(), 1);

        // Every cap keeps a nonzero SOCKS reserve; the integer-floor trap used
        // to give forwarding the whole budget at caps 2 and 3.
        for cap in 1usize..=8 {
            let c: ClientConf = toml::from_str(&format!("{BASE}\nmax_udp_assocs = {cap}")).unwrap();
            let forward = c.forward_session_budget();
            assert!(forward <= cap, "forward budget {forward} exceeds cap {cap}");
            if cap >= 2 {
                assert!(
                    forward < cap,
                    "cap {cap} must reserve at least one slot for SOCKS, got forward={forward}"
                );
            }
        }
    }

    #[test]
    fn tcp_forward_max_conns_parses_clamps_and_defaults() {
        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"example.com:80\"\nmax_conns = 9",
        );
        assert_eq!(c.tcp_forwards().unwrap()[0].max_conns, 9);

        let c = parse_ok(&format!(
            "[[tcp_forward]]\nlisten = \"127.0.0.1:8080\"\ntarget = \"example.com:80\"\nmax_conns = {}",
            MAX_SOCKS_CONNS + 10_000
        ));
        assert_eq!(
            c.tcp_forwards().unwrap()[0].max_conns,
            MAX_SOCKS_CONNS,
            "max_conns clamps to the shared relay cap"
        );
    }

    /// The cross-family overlap rule is asymmetric on purpose: an AF_INET
    /// wildcard cannot receive IPv6, so `0.0.0.0:P` + `[::1]:P` is a legal pair
    /// that binds cleanly; the dual-stack `[::]:P` covers both families and
    /// must still be rejected against either.
    #[test]
    fn cross_family_listen_overlap_is_asymmetric() {
        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"0.0.0.0:8080\"\ntarget = \"a.example:80\"\n\
             [[tcp_forward]]\nlisten = \"[::1]:8080\"\ntarget = \"b.example:80\"",
        );
        assert!(
            c.tcp_forwards().is_ok(),
            "v4 wildcard does not cover a concrete v6 address"
        );

        let c = parse_ok(
            "[[tcp_forward]]\nlisten = \"[::]:8080\"\ntarget = \"a.example:80\"\n\
             [[tcp_forward]]\nlisten = \"[::1]:8080\"\ntarget = \"b.example:80\"",
        );
        assert!(
            c.tcp_forwards().is_err(),
            "the dual-stack v6 wildcard covers a concrete v6 address"
        );

        // A concrete-v4 wildcard must also not overlap a v6 socks_listen.
        let c = parse_with_socks(
            "[::1]:1080",
            "[[tcp_forward]]\nlisten = \"0.0.0.0:1080\"\ntarget = \"a.example:80\"",
        );
        assert!(
            c.tcp_forwards().is_ok(),
            "0.0.0.0 does not capture a v6-only SOCKS listener"
        );
    }

    #[test]
    fn forward_listener_count_is_capped() {
        let mut tcp = String::new();
        for i in 0..=MAX_FORWARD_LISTENERS {
            tcp.push_str(&format!(
                "[[tcp_forward]]\nlisten = \"127.0.0.1:{}\"\ntarget = \"example.com:80\"\n",
                20_000 + i
            ));
        }
        let c = parse_ok(&tcp);
        let err = format!("{:#}", c.tcp_forwards().unwrap_err());
        assert!(err.contains("listener cap"), "{err}");

        let mut udp = String::new();
        for i in 0..=MAX_FORWARD_LISTENERS {
            udp.push_str(&format!(
                "[[udp_forward]]\nlisten = \"127.0.0.1:{}\"\ntarget = \"1.1.1.1:53\"\n",
                20_000 + i
            ));
        }
        let c = parse_ok(&udp);
        let err = format!("{:#}", c.udp_forwards().unwrap_err());
        assert!(err.contains("listener cap"), "{err}");
    }
}
