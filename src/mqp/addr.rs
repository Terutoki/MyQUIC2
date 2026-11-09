use super::error::MqpError;
use std::net::{IpAddr, SocketAddr};

// ---------------- Address codec (MQP-2) ----------------
// wire: atyp u8 | addr | port u16 BE ; atyp: 0x01 v4, 0x04 v6, 0x03 domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// Borrowed form of [`TargetAddr`], used on per-datagram hot paths so a
/// domain-typed packet never allocates a `String` just to hit the DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAddrRef<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl TargetAddr {
    pub fn as_ref(&self) -> TargetAddrRef<'_> {
        match self {
            TargetAddr::Ip(s) => TargetAddrRef::Ip(*s),
            TargetAddr::Domain(d, p) => TargetAddrRef::Domain(d, *p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), MqpError> {
        self.as_ref().encode(out)
    }

    pub fn decode(b: &[u8]) -> Result<(Self, usize), MqpError> {
        let (a, n) = TargetAddrRef::decode(b)?;
        Ok((a.into_owned(), n))
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            TargetAddr::Ip(s) => Some(*s),
            _ => None,
        }
    }
}

/// A [`TargetAddrRef`] that has already been validated and measured, so the
/// caller can size its output buffer exactly once instead of encoding twice.
///
/// Both operations are pure, so splitting them out of [`TargetAddrRef::encode`]
/// never changes which addresses are accepted — `encode` remains the single
/// definition of the wire format and the validation rules.
#[derive(Debug, Clone, Copy)]
pub struct AddrHeader<'a> {
    addr: TargetAddrRef<'a>,
    len: usize,
}

impl<'a> AddrHeader<'a> {
    /// Wire length of the largest address form (`atyp | addr | port`).
    pub const MAX_LEN: usize = 1 + 1 + 255 + 2;

    /// Wire length of `addr` (`atyp | addr | port`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append the header to `out`, returning the byte count written.
    ///
    /// The allocation-free twin of [`AddrHeader::encode`], for per-connection
    /// paths that own a fixed buffer ([`AddrHeader::MAX_LEN`] bytes covers every
    /// form). Validation already happened in [`TargetAddrRef::header`], so this
    /// only writes bytes; a debug build asserts the two agree on the length.
    ///
    /// # Panics
    /// Panics if `out` is shorter than the encoded header.
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        let n = match self.addr {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                out[0] = 0x01;
                out[1..5].copy_from_slice(&a.ip().octets());
                out[5..7].copy_from_slice(&a.port().to_be_bytes());
                7
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                out[0] = 0x04;
                out[1..17].copy_from_slice(&a.ip().octets());
                out[17..19].copy_from_slice(&a.port().to_be_bytes());
                19
            }
            TargetAddrRef::Domain(d, p) => {
                let b = d.as_bytes();
                out[0] = 0x03;
                out[1] = b.len() as u8;
                out[2..2 + b.len()].copy_from_slice(b);
                out[2 + b.len()..4 + b.len()].copy_from_slice(&p.to_be_bytes());
                4 + b.len()
            }
        };
        debug_assert_eq!(n, self.len, "encoder and header() disagree");
        n
    }

    /// Append the header to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), MqpError> {
        self.addr.encode(out)
    }
}

impl<'a> TargetAddrRef<'a> {
    pub fn into_owned(self) -> TargetAddr {
        match self {
            TargetAddrRef::Ip(s) => TargetAddr::Ip(s),
            TargetAddrRef::Domain(d, p) => TargetAddr::Domain(d.to_owned(), p),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), MqpError> {
        match *self {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v4"));
                }
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                if a.ip().is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v6"));
                }
                if a.scope_id() != 0 {
                    return Err(MqpError::Refused(
                        "v6 scope_id dropped on wire, refuse scoped addr",
                    ));
                }
                out.push(0x04);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            TargetAddrRef::Domain(d, p) => {
                let bytes = d.as_bytes();
                if bytes.is_empty() {
                    return Err(MqpError::Refused("empty domain"));
                }
                if bytes.len() > 255 {
                    return Err(MqpError::Refused("domain too long"));
                }
                out.push(0x03);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Validate and measure this address once, so a hot-path encoder can
    /// `with_capacity` the exact size (no growth reallocation) and skip the
    /// second validation pass that a separate `encode` call would repeat.
    pub fn header(&self) -> Result<AddrHeader<'a>, MqpError> {
        let len = match *self {
            TargetAddrRef::Ip(SocketAddr::V4(a)) => {
                if a.ip().is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v4"));
                }
                1 + 4 + 2
            }
            TargetAddrRef::Ip(SocketAddr::V6(a)) => {
                if a.ip().is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v6"));
                }
                if a.scope_id() != 0 {
                    return Err(MqpError::Refused(
                        "v6 scope_id dropped on wire, refuse scoped addr",
                    ));
                }
                1 + 16 + 2
            }
            TargetAddrRef::Domain(d, _) => {
                let n = d.len();
                if n == 0 {
                    return Err(MqpError::Refused("empty domain"));
                }
                if n > 255 {
                    return Err(MqpError::Refused("domain too long"));
                }
                1 + 1 + n + 2
            }
        };
        Ok(AddrHeader { addr: *self, len })
    }

    pub fn decode(b: &'a [u8]) -> Result<(Self, usize), MqpError> {
        if b.is_empty() {
            return Err(MqpError::Malformed("empty addr"));
        }
        let atyp = b[0];
        match atyp {
            0x01 => {
                if b.len() < 7 {
                    return Err(MqpError::Malformed("short v4"));
                }
                let ip = IpAddr::from([b[1], b[2], b[3], b[4]]);
                if ip.is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v4 target"));
                }
                let port = u16::from_be_bytes([b[5], b[6]]);
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 7))
            }
            0x04 => {
                if b.len() < 19 {
                    return Err(MqpError::Malformed("short v6"));
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[1..17]);
                let ip = IpAddr::from(o);
                if ip.is_unspecified() {
                    return Err(MqpError::Refused("refuse unspecified v6 target"));
                }
                let port = u16::from_be_bytes([b[17], b[18]]);
                Ok((TargetAddrRef::Ip(SocketAddr::new(ip, port)), 19))
            }
            0x03 => {
                if b.len() < 2 {
                    return Err(MqpError::Malformed("short domain"));
                }
                let n = b[1] as usize;
                if n == 0 {
                    return Err(MqpError::Malformed("bad domain len"));
                }
                if b.len() < 2 + n + 2 {
                    return Err(MqpError::Malformed("short domain body"));
                }
                let d = std::str::from_utf8(&b[2..2 + n]).map_err(|_| MqpError::BadDomainUtf8)?;
                let port = u16::from_be_bytes([b[2 + n], b[3 + n]]);
                Ok((TargetAddrRef::Domain(d, port), 4 + n))
            }
            _ => Err(MqpError::BadAtyp(atyp)),
        }
    }
}

// ---------------- IP-only socket-address helpers (control-plane) ----------------
//
// A reply source is always IP-form (the server never echoes a domain), and the
// control plane needs an exact, source-carrying confirmation. These helpers are
// deliberately narrower than [`TargetAddrRef`]: no domain form, no validation
// against unspecified/scoped addresses (a source that reached a socket is
// concrete), and a fixed 7/19-byte encoding.

/// Wire length of [`put_ip_socket_addr`]'s output: `atyp | ip | port`.
#[must_use]
pub fn ip_socket_addr_len(addr: SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 16 + 2,
    }
}

/// Append an IP-form socket address (`atyp | ip | port`, big-endian port).
pub fn put_ip_socket_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

/// Decode one [`put_ip_socket_addr`] value and advance `off`.
///
/// A domain atyp is refused: a reply source on the wire is an address, never a
/// name.
pub fn get_ip_socket_addr(b: &[u8], off: &mut usize) -> Result<SocketAddr, MqpError> {
    let atyp = *b.get(*off).ok_or(MqpError::Malformed("short src addr"))?;
    *off += 1;
    match atyp {
        0x01 => {
            let end = off
                .checked_add(4 + 2)
                .ok_or(MqpError::Malformed("src v4 overflow"))?;
            let s = b
                .get(*off..end)
                .ok_or(MqpError::Malformed("short src v4"))?;
            let ip = std::net::Ipv4Addr::new(s[0], s[1], s[2], s[3]);
            let port = u16::from_be_bytes([s[4], s[5]]);
            *off = end;
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let end = off
                .checked_add(16 + 2)
                .ok_or(MqpError::Malformed("src v6 overflow"))?;
            let s = b
                .get(*off..end)
                .ok_or(MqpError::Malformed("short src v6"))?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&s[..16]);
            let port = u16::from_be_bytes([s[16], s[17]]);
            *off = end;
            Ok(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                port,
            ))
        }
        _ => Err(MqpError::Malformed("bad src atyp")),
    }
}
