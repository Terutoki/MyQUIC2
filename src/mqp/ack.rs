use super::error::MqpError;
use std::net::{IpAddr, SocketAddr};

/// Versioned ALPN identifier. Bumped to `/2` together with the MQP-2 TCP-open
/// ACK (status byte + bound address); a version-skewed peer now fails the TLS
/// handshake with a clear error instead of misparsing the ACK as app data.
/// The default config ALPN is now `h3` (see `normalize_alpn`); set
/// `alpn = "myquic2/2"` explicitly to restore this identifier and its
/// fail-closed skew guard.
pub const MQP_ALPN: &[u8] = b"myquic2/2";

/// Resolve the configured ALPN: empty/unset keeps the default `h3`
/// masquerade. `h3` hides only the ALPN label — the self-signed cert and the
/// MQP framing stay fingerprintable, so this is obfuscation, not a full
/// HTTP/3 disguise. Explicit `myquic2/2` restores the versioned identifier
/// (and its fail-closed skew guard against real HTTP/3 peers); either way
/// both sides must run the same value.
pub fn normalize_alpn(configured: Option<&str>) -> Vec<u8> {
    match configured {
        Some(s) if !s.is_empty() => s.as_bytes().to_vec(),
        _ => b"h3".to_vec(),
    }
}

/// MQP-2 TCP open acknowledgement (server -> client).
///
/// `magic [0x4D, 0x51] ("MQ") | status u8 (0x00) | atyp u8 | addr | port u16 BE`
/// — the bound address is the server-side socket it dialed the target from, so
/// the client can put the real BND.ADDR/BND.PORT into its SOCKS5 success reply
/// (RFC 1928).
///
/// The magic prefix is the fail-closed version-skew guard (B1): the client MUST
/// wait for exactly these bytes and fail the flow otherwise. A peer that sends
/// raw application bytes first (a pre-magic server) can never have them mistaken
/// for the ACK — even a `0x00`-led app prefix fails the magic check and tears
/// the flow down with RST instead of stripping 8/20 B silently with a clean
/// FIN. There is intentionally NO silent fallback for old peers. The wire form
/// changed, so **both sides must be upgraded together**; same-version pairs are
/// unaffected (the default `h3` ALPN still masquerades the handshake as before).
pub const MQP_TCP_ACK: u8 = 0x00;

/// Two-byte magic opening every MQP-2 TCP-open ACK. ASCII "MQ" (MyQUIC): not a
/// valid legacy-ACK status (`0x00`) in either position, so a legacy `0x00`-led
/// app prefix fails closed here instead of parsing as the ACK.
pub const MQP_TCP_ACK_MAGIC: [u8; 2] = [0x4D, 0x51];

/// Largest wire length of the TCP-open ACK: magic + status + largest bnd form.
pub const MAX_TCP_ACK_LEN: usize = 2 + 1 + MAX_BND_LEN;

/// Wire cap for the connection-auth token: the server reads at most this many
/// bytes, so a longer configured token can never authenticate and must be
/// rejected at startup instead of failing every handshake.
pub const AUTH_TOKEN_MAX_BYTES: usize = 256;

/// Encode a bound address for the ACK (no status byte). Datagram/stream
/// target encoding rejects unspecified addresses; BND may legitimately be
/// `0.0.0.0:0`, so this is a dedicated encoder that is never used to dial.
pub fn encode_bnd_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + MAX_BND_LEN, 0);
    let n = encode_bnd_addr_into(addr, &mut out[start..]);
    out.truncate(start + n);
}

/// Number of bytes [`encode_bnd_addr_into`] can write: `atyp | addr | port`
/// for the largest address form.
pub const MAX_BND_LEN: usize = 1 + 16 + 2;

/// Allocation-free form of [`encode_bnd_addr`] for hot paths that already own a
/// fixed buffer (the MQP-2 ACK is at most [`MAX_BND_LEN`] bytes). `out` must be
/// at least that long. Returns the number of bytes written.
///
/// # Panics
/// Panics if `out` is shorter than [`MAX_BND_LEN`].
pub fn encode_bnd_addr_into(addr: SocketAddr, out: &mut [u8]) -> usize {
    assert!(out.len() >= MAX_BND_LEN, "bnd buffer too small");
    match addr {
        SocketAddr::V4(a) => {
            out[0] = 0x01;
            out[1..5].copy_from_slice(&a.ip().octets());
            out[5..7].copy_from_slice(&a.port().to_be_bytes());
            7
        }
        SocketAddr::V6(a) => {
            out[0] = 0x04;
            out[1..17].copy_from_slice(&a.ip().octets());
            out[17..19].copy_from_slice(&a.port().to_be_bytes());
            19
        }
    }
}

/// Decode the address portion of an ACK (`atyp | addr | port`).
/// Returns the address and the number of bytes consumed.
pub fn decode_bnd_addr(b: &[u8]) -> Result<(SocketAddr, usize), MqpError> {
    if b.is_empty() {
        return Err(MqpError::Malformed("empty bnd"));
    }
    match b[0] {
        0x01 => {
            if b.len() < 7 {
                return Err(MqpError::Malformed("short bnd v4"));
            }
            let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Ok((SocketAddr::new(ip, port), 7))
        }
        0x04 => {
            if b.len() < 19 {
                return Err(MqpError::Malformed("short bnd v6"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Ok((SocketAddr::new(IpAddr::from(o), port), 19))
        }
        a => Err(MqpError::BadBndAtyp(a)),
    }
}

/// Encode a full TCP-open ACK (`magic | status | atyp | addr | port`) into
/// `out`, which must hold [`MAX_TCP_ACK_LEN`] bytes. Returns the bytes
/// written (10 for IPv4, 22 for IPv6). The single constructor the server uses,
/// so the reader below and the writer cannot drift.
///
/// # Panics
/// Panics if `out` is shorter than [`MAX_TCP_ACK_LEN`].
pub fn encode_tcp_ack_into(addr: SocketAddr, out: &mut [u8]) -> usize {
    assert!(out.len() >= MAX_TCP_ACK_LEN, "ack buffer too small");
    out[0..2].copy_from_slice(&MQP_TCP_ACK_MAGIC);
    out[2] = MQP_TCP_ACK;
    3 + encode_bnd_addr_into(addr, &mut out[3..])
}
