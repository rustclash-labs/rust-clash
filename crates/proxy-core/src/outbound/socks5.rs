use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

use crate::{
    addr::{HostName, TargetAddr},
    outbound::{BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession},
    platform::socket_protect::{protected_tcp_connect_host_with_dns, protected_udp_bind},
};

#[derive(Clone)]
pub struct Socks5OutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub udp: bool,
}

struct Socks5Inner {
    cfg: Socks5OutboundConfig,
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct Socks5Outbound {
    inner: Arc<Socks5Inner>,
}

impl Socks5Inner {
    async fn negotiate_auth<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        &self,
        stream: &mut S,
    ) -> io::Result<()> {
        let user = self.cfg.username.as_deref().filter(|u| !u.is_empty());
        let pass = self.cfg.password.as_deref().unwrap_or("");

        if let Some(u) = user {
            if u.len() > 255 || pass.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 username/password must not exceed 255 bytes",
                ));
            }
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        stream.flush().await?;

        let mut greeting_resp = [0u8; 2];
        stream.read_exact(&mut greeting_resp).await?;
        if greeting_resp[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 version 0x{:02x}", greeting_resp[0]),
            ));
        }

        match greeting_resp[1] {
            0x00 => Ok(()),
            0x02 => {
                let u = user.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 server requires username/password authentication",
                    )
                })?;
                let mut auth_req = BytesMut::with_capacity(3 + u.len() + pass.len());
                auth_req.put_u8(0x01);
                auth_req.put_u8(u.len() as u8);
                auth_req.put_slice(u.as_bytes());
                auth_req.put_u8(pass.len() as u8);
                auth_req.put_slice(pass.as_bytes());
                stream.write_all(&auth_req).await?;
                stream.flush().await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 username/password authentication failed",
                    ));
                }
                Ok(())
            }
            0xff => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 server rejected all offered authentication methods",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 auth method 0x{other:02x}"),
            )),
        }
    }

    async fn send_socks5_command<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        &self,
        stream: &mut S,
        cmd: u8,
        target: &TargetAddr,
    ) -> io::Result<TargetAddr> {
        let mut req = BytesMut::with_capacity(32);
        req.put_slice(&[0x05, cmd, 0x00]);
        target.encode_socks5(&mut req)?;
        stream.write_all(&req).await?;
        stream.flush().await?;

        let mut hdr = [0u8; 3];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 reply version 0x{:02x}", hdr[0]),
            ));
        }
        let bnd_addr = TargetAddr::read_socks5(stream).await?;
        if hdr[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "SOCKS5 command 0x{cmd:02x} failed with reply code 0x{:02x}",
                    hdr[1]
                ),
            ));
        }
        Ok(bnd_addr)
    }
}

impl Socks5Outbound {
    pub fn new(cfg: Socks5OutboundConfig) -> io::Result<Self> {
        Self::new_with_dns(cfg, None)
    }

    pub fn new_with_dns(
        cfg: Socks5OutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let tls_connector = if cfg.tls {
            let tls_cfg = crate::crypto::tls::build_tls_client_config(
                cfg.skip_cert_verify,
                &cfg.extra_ca_der,
                &[],
            )?;
            Some(TlsConnector::from(tls_cfg))
        } else {
            None
        };

        Ok(Self {
            inner: Arc::new(Socks5Inner {
                cfg,
                tls_connector,
                dns,
            }),
        })
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn same_socket_peer(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && canonical_ip(a.ip()) == canonical_ip(b.ip())
}

struct Socks5UdpSession {
    ctrl_tcp: tokio::sync::Mutex<TcpStream>,
    udp_sock: UdpSocket,
    relay_addr: SocketAddr,
}

#[async_trait]
impl OutboundUdpSession for Socks5UdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let mut pkt = BytesMut::with_capacity(32 + payload.len());
        pkt.put_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(0)
        target.encode_socks5(&mut pkt)?;
        pkt.put_slice(payload);
        self.udp_sock.send_to(&pkt, self.relay_addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut buf = vec![0u8; 65535];
        let mut ctrl_guard = self.ctrl_tcp.lock().await;
        let mut ctrl_probe = [0u8; 8];
        loop {
            tokio::select! {
                ctrl_res = ctrl_guard.read(&mut ctrl_probe) => {
                    match ctrl_res {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "SOCKS5 UDP associate TCP control connection closed by server",
                            ));
                        }
                        Ok(_) => continue,
                        Err(e) => return Err(e),
                    }
                }
                udp_res = self.udp_sock.recv_from(&mut buf) => {
                    let (n, peer) = udp_res?;
                    if !same_socket_peer(peer, self.relay_addr) {
                        // Drop spoofed UDP packets from unexpected peers (RFC 1928 §7).
                        continue;
                    }
                    if n < 4 {
                        continue;
                    }
                    // RSV(2) must be 0x0000 and FRAG(1) must be 0x00 (unfragmented standalone datagram).
                    if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
                        continue;
                    }
                    let Ok((src_addr, addr_used)) = TargetAddr::decode_socks5_slice(&buf[3..n]) else {
                        continue;
                    };
                    let payload_offset = 3 + addr_used;
                    if payload_offset > n {
                        continue;
                    }
                    return Ok((buf[payload_offset..n].to_vec(), src_addr));
                }
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for Socks5Outbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "SOCKS5"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.inner.cfg.server, self.inner.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        self.inner.cfg.udp && !self.inner.cfg.tls
    }

    async fn preconnect(&self, target_sessions: usize) -> io::Result<()> {
        if target_sessions > 0
            && let Some(dns) = &self.inner.dns
        {
            dns.prewarm_proxy_server_ips(&self.inner.cfg.server)
                .await
                .map_err(|e| e.into_io())?;
        }
        Ok(())
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect_host_with_dns(
            &self.inner.cfg.server,
            self.inner.cfg.port,
            self.inner.dns.as_deref(),
        )
        .await?;

        let mut stream: BoxedStream = if let Some(connector) = &self.inner.tls_connector {
            let sni_str = self
                .inner
                .cfg
                .sni
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(self.inner.cfg.server.as_str());
            let sni = crate::crypto::tls::parse_server_name(sni_str)?;
            Box::new(connector.connect(sni, tcp).await?)
        } else {
            Box::new(tcp)
        };

        self.inner.negotiate_auth(&mut stream).await?;
        self.inner
            .send_socks5_command(&mut stream, 0x01, target)
            .await?;
        Ok(stream)
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.udp_supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP Associate is disabled or unsupported over TLS on this SOCKS5 outbound",
            ));
        }

        let mut ctrl_tcp = protected_tcp_connect_host_with_dns(
            &self.inner.cfg.server,
            self.inner.cfg.port,
            self.inner.dns.as_deref(),
        )
        .await?;
        let peer_ip = ctrl_tcp.peer_addr()?.ip();

        self.inner.negotiate_auth(&mut ctrl_tcp).await?;
        let unspec = if peer_ip.is_ipv4() {
            TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let bnd = self
            .inner
            .send_socks5_command(&mut ctrl_tcp, 0x03, &unspec)
            .await?;

        let relay_ip = match bnd.host {
            HostName::Ip(ip) if !ip.is_unspecified() => ip,
            HostName::Ip(_) => peer_ip,
            HostName::Domain(ref d) => {
                if let Some(dns) = &self.inner.dns {
                    *dns.resolve_direct_ips(d)
                        .await
                        .map_err(|e| e.into_io())?
                        .first()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::HostUnreachable, "empty SOCKS5 relay DNS")
                        })?
                } else {
                    peer_ip
                }
            }
        };
        let relay_addr = SocketAddr::new(relay_ip, bnd.port);
        let local_bind = if relay_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let udp_sock = protected_udp_bind(local_bind, Some(relay_addr))?;

        Ok(Box::new(Socks5UdpSession {
            ctrl_tcp: tokio::sync::Mutex::new(ctrl_tcp),
            udp_sock,
            relay_addr,
        }))
    }
}

/// Loopback SOCKS5 server (supporting optional RFC 1929 auth, TCP `CONNECT`, and `UDP ASSOCIATE`) for E2E tests.
pub struct Socks5ServerConfig {
    pub listen_addr: String,
    pub credentials: Option<(String, String)>,
}

pub async fn spawn_socks5_server(
    cfg: Socks5ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let bound_addr = listener.local_addr()?;
    let creds = cfg.credentials.map(Arc::new);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((tcp, _peer)) = accepted else {
                        continue;
                    };
                    let _ = tcp.set_nodelay(true);
                    let creds_clone = creds.clone();
                    tokio::spawn(async move {
                        let _ = handle_socks5_server_conn(tcp, creds_clone).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, handle))
}

async fn handle_socks5_server_conn(
    mut tcp: TcpStream,
    creds: Option<Arc<(String, String)>>,
) -> io::Result<()> {
    let ver = tcp.read_u8().await?;
    if ver != 0x05 {
        return Ok(());
    }
    let nmethods = tcp.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await?;

    if let Some(expected) = creds {
        if !methods.contains(&0x02) {
            let _ = tcp.write_all(&[0x05, 0xff]).await;
            return Ok(());
        }
        tcp.write_all(&[0x05, 0x02]).await?;
        let auth_ver = tcp.read_u8().await?;
        if auth_ver != 0x01 {
            return Ok(());
        }
        let ulen = tcp.read_u8().await? as usize;
        let mut ubuf = vec![0u8; ulen];
        tcp.read_exact(&mut ubuf).await?;
        let plen = tcp.read_u8().await? as usize;
        let mut pbuf = vec![0u8; plen];
        tcp.read_exact(&mut pbuf).await?;

        if ubuf == expected.0.as_bytes() && pbuf == expected.1.as_bytes() {
            tcp.write_all(&[0x01, 0x00]).await?;
        } else {
            let _ = tcp.write_all(&[0x01, 0x01]).await;
            return Ok(());
        }
    } else {
        tcp.write_all(&[0x05, 0x00]).await?;
    }

    let mut req_hdr = [0u8; 3];
    tcp.read_exact(&mut req_hdr).await?;
    let cmd = req_hdr[1];
    let target = TargetAddr::read_socks5(&mut tcp).await?;

    let direct = DirectOutbound::default();
    match cmd {
        0x01 => {
            let mut outbound = direct.connect_tcp(&target).await?;
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut outbound).await?;
            Ok(())
        }
        0x03 => {
            let local_ip = tcp.local_addr()?.ip();
            let udp_relay = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
            let relay_bound = udp_relay.local_addr()?;

            let mut reply = BytesMut::with_capacity(32);
            reply.put_slice(&[0x05, 0x00, 0x00]);
            TargetAddr::from(relay_bound).encode_socks5(&mut reply)?;
            tcp.write_all(&reply).await?;
            tcp.flush().await?;

            let upstream = direct.open_udp_session().await?;
            let mut client_udp_addr: Option<SocketAddr> = None;
            let mut udp_buf = vec![0u8; 65535];
            let mut tcp_eof = [0u8; 8];

            loop {
                tokio::select! {
                    n = tcp.read(&mut tcp_eof) => {
                        if n.unwrap_or(0) == 0 {
                            break;
                        }
                    }
                    recv = udp_relay.recv_from(&mut udp_buf) => {
                        let Ok((n, peer)) = recv else {
                            break;
                        };
                        if n < 4 || udp_buf[2] != 0x00 {
                            continue;
                        }
                        client_udp_addr = Some(peer);
                        if let Ok((dst, used)) = TargetAddr::decode_socks5_slice(&udp_buf[3..n])
                            && 3 + used <= n
                        {
                            let _ = upstream.send_to(&udp_buf[3 + used..n], &dst).await;
                        }
                    }
                    up_recv = tokio::time::timeout(Duration::from_secs(60), upstream.recv_from()) => {
                        let Ok(Ok((resp, src_addr))) = up_recv else {
                            break;
                        };
                        if let Some(client_peer) = client_udp_addr {
                            let mut pkt = BytesMut::with_capacity(32 + resp.len());
                            pkt.put_slice(&[0x00, 0x00, 0x00]);
                            if src_addr.encode_socks5(&mut pkt).is_ok() {
                                pkt.put_slice(&resp);
                                let _ = udp_relay.send_to(&pkt, client_peer).await;
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        _ => {
            let _ = tcp
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Ok(())
        }
    }
}
