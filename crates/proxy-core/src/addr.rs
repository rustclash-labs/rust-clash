use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Magic destination domain used by Sing-box / AnyTLS `udp-over-tcp` v2.
pub const UOT_V2_MAGIC_ADDR: &str = "sp.v2.udp-over-tcp.arpa";

/// Unified target endpoint representation (Domain or IP + Port).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetAddr {
    pub host: HostName,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostName {
    Ip(IpAddr),
    Domain(String),
}

impl HostName {
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(d) => Some(d.as_str()),
            Self::Ip(_) => None,
        }
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Domain(_) => None,
        }
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(d) => write!(f, "{d}"),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            HostName::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            HostName::Ip(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            HostName::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: HostName::Ip(addr.ip()),
            port: addr.port(),
        }
    }
}

impl FromStr for TargetAddr {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(sock) = s.parse::<SocketAddr>() {
            return Ok(sock.into());
        }
        if let Some(rest) = s.strip_prefix('[') {
            let (ip_str, port_str) = rest.split_once("]:").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid bracketed IPv6 target")
            })?;
            let ip: Ipv6Addr = ip_str
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 address"))?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
            return Ok(Self::new_ip(IpAddr::V6(ip), port));
        }
        let (host_str, port_str) = s.rsplit_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing ':port' in target address",
            )
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
        if let Ok(ip) = host_str.parse::<IpAddr>() {
            Ok(Self::new_ip(ip, port))
        } else {
            Self::new_domain(host_str, port)
        }
    }
}

impl TargetAddr {
    pub fn new_ip(ip: IpAddr, port: u16) -> Self {
        Self {
            host: HostName::Ip(ip),
            port,
        }
    }

    pub fn new_domain(domain: impl Into<String>, port: u16) -> io::Result<Self> {
        let domain = domain
            .into()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if domain.is_empty() || domain.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain length must be 1..=255 bytes",
            ));
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(Self::new_ip(ip, port));
        }
        Ok(Self {
            host: HostName::Domain(domain),
            port,
        })
    }

    pub fn to_socket_addr_str(&self) -> String {
        self.to_string()
    }

    /// Encode in RFC 1928 SOCKS5 / Shadowsocks wire format:
    /// - `0x01` + IPv4 (4B) + Port (2B BE)
    /// - `0x03` + Len (1B) + Domain + Port (2B BE)
    /// - `0x04` + IPv6 (16B) + Port (2B BE)
    pub fn encode_socks5(&self, buf: &mut BytesMut) -> io::Result<()> {
        match &self.host {
            HostName::Ip(IpAddr::V4(v4)) => {
                buf.put_u8(0x01);
                buf.put_slice(&v4.octets());
                buf.put_u16(self.port);
            }
            HostName::Domain(domain) => {
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "domain name exceeds 255 bytes",
                    ));
                }
                buf.put_u8(0x03);
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
                buf.put_u16(self.port);
            }
            HostName::Ip(IpAddr::V6(v6)) => {
                buf.put_u8(0x04);
                buf.put_slice(&v6.octets());
                buf.put_u16(self.port);
            }
        }
        Ok(())
    }

    pub fn to_socks5_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(32);
        self.encode_socks5(&mut buf)?;
        Ok(buf.to_vec())
    }

    /// Decode RFC 1928 SOCKS5 / Shadowsocks address from a byte slice, returning `(TargetAddr, consumed_len)`.
    pub fn decode_socks5_slice(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty socks5 address buffer",
            ));
        }
        match data[0] {
            0x01 => {
                if data.len() < 7 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated IPv4 socks5 address",
                    ));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Self::new_ip(IpAddr::V4(ip), port), 7))
            }
            0x03 => {
                if data.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated domain socks5 length",
                    ));
                }
                let len = data[1] as usize;
                if data.len() < 2 + len + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated domain socks5 address",
                    ));
                }
                let domain = std::str::from_utf8(&data[2..2 + len]).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in socks5 domain")
                })?;
                let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
                Ok((Self::new_domain(domain, port)?, 4 + len))
            }
            0x04 => {
                if data.len() < 19 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated IPv6 socks5 address",
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Self::new_ip(IpAddr::V6(ip), port), 19))
            }
            atyp => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 ATYP: 0x{atyp:02x}"),
            )),
        }
    }

    pub async fn read_socks5<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let atyp = reader.read_u8().await?;
        match atyp {
            0x01 => {
                let mut ip_bytes = [0u8; 4];
                reader.read_exact(&mut ip_bytes).await?;
                let port = reader.read_u16().await?;
                Ok(Self::new_ip(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port))
            }
            0x03 => {
                let len = reader.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; len];
                reader.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 domain")
                })?;
                let port = reader.read_u16().await?;
                Self::new_domain(domain, port)
            }
            0x04 => {
                let mut ip_bytes = [0u8; 16];
                reader.read_exact(&mut ip_bytes).await?;
                let port = reader.read_u16().await?;
                Ok(Self::new_ip(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type 0x{other:02x}"),
            )),
        }
    }

    pub async fn write_socks5<W: AsyncWrite + Unpin + ?Sized>(
        &self,
        writer: &mut W,
    ) -> io::Result<()> {
        let bytes = self.to_socks5_bytes()?;
        writer.write_all(&bytes).await
    }

    /// Encode in VLESS wire format:
    /// Port (2B BE) | AddrType (`0x01` IPv4, `0x02` Domain, `0x03` IPv6) | Addr
    pub fn encode_vless(&self, buf: &mut BytesMut) -> io::Result<()> {
        buf.put_u16(self.port);
        match &self.host {
            HostName::Ip(IpAddr::V4(v4)) => {
                buf.put_u8(0x01);
                buf.put_slice(&v4.octets());
            }
            HostName::Domain(domain) => {
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "VLESS domain exceeds 255 bytes",
                    ));
                }
                buf.put_u8(0x02);
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
            }
            HostName::Ip(IpAddr::V6(v6)) => {
                buf.put_u8(0x03);
                buf.put_slice(&v6.octets());
            }
        }
        Ok(())
    }

    pub async fn read_vless<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let port = reader.read_u16().await?;
        let atyp = reader.read_u8().await?;
        match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                Ok(Self::new_ip(IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            0x02 => {
                let len = reader.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in VLESS domain")
                })?;
                Self::new_domain(domain, port)
            }
            0x03 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                Ok(Self::new_ip(IpAddr::V6(Ipv6Addr::from(ip)), port))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VLESS address type 0x{other:02x}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_socks5_and_vless_addresses() {
        let cases = vec![
            TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443),
            TargetAddr::new_domain("Example.COM.", 443).unwrap(),
        ];

        for addr in cases {
            let socks = addr.to_socks5_bytes().unwrap();
            let (decoded, used) = TargetAddr::decode_socks5_slice(&socks).unwrap();
            assert_eq!(used, socks.len());
            assert_eq!(decoded, addr);
        }
    }
}
