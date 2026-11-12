use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytes::{Buf, BytesMut};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

use crate::{
    addr::TargetAddr,
    outbound::{BoxedStream, DirectOutbound, OutboundHandler},
    platform::socket_protect::protected_tcp_connect_host_with_dns,
};

#[derive(Clone)]
pub struct HttpOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub headers: HashMap<String, String>,
}

struct HttpInner {
    cfg: HttpOutboundConfig,
    basic_auth_header: Option<String>,
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct HttpOutbound {
    inner: Arc<HttpInner>,
}

impl HttpOutbound {
    pub fn new(cfg: HttpOutboundConfig) -> io::Result<Self> {
        Self::new_with_dns(cfg, None)
    }

    pub fn new_with_dns(
        cfg: HttpOutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let basic_auth_header = cfg.username.as_deref().filter(|u| !u.is_empty()).map(|u| {
            let p = cfg.password.as_deref().unwrap_or("");
            let token = BASE64_STANDARD.encode(format!("{u}:{p}"));
            format!("Basic {token}")
        });

        let tls_connector = if cfg.tls {
            let alpn = [b"http/1.1".to_vec()];
            let tls_cfg = crate::crypto::tls::build_tls_client_config(
                cfg.skip_cert_verify,
                &cfg.extra_ca_der,
                &alpn,
            )?;
            Some(TlsConnector::from(tls_cfg))
        } else {
            None
        };

        Ok(Self {
            inner: Arc::new(HttpInner {
                cfg,
                basic_auth_header,
                tls_connector,
                dns,
            }),
        })
    }
}

struct PrefixedStream<S> {
    prefix: BytesMut,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = buf.remaining().min(self.prefix.len());
            buf.put_slice(&self.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[async_trait]
impl OutboundHandler for HttpOutbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "HTTP"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.inner.cfg.server, self.inner.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        false
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

        let authority = target.to_string();
        let mut req = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
        );
        if let Some(auth) = &self.inner.basic_auth_header {
            req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        let mut has_ua = false;
        for (k, v) in &self.inner.cfg.headers {
            let k_clean = k.trim();
            if k_clean.is_empty()
                || k_clean.contains(['\r', '\n'])
                || v.contains(['\r', '\n'])
                || k_clean.eq_ignore_ascii_case("host")
                || k_clean.eq_ignore_ascii_case("proxy-authorization")
            {
                continue;
            }
            if k_clean.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            req.push_str(&format!("{k_clean}: {}\r\n", v.trim()));
        }
        if !has_ua {
            req.push_str(&format!(
                "User-Agent: rust-clash/{}\r\n",
                env!("CARGO_PKG_VERSION")
            ));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut resp_buf = BytesMut::with_capacity(512);
        let mut tmp = [0u8; 512];
        let hdr_end = loop {
            if let Some(end) = find_header_end(&resp_buf) {
                break end;
            }
            if resp_buf.len() >= 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT response header exceeded 16 KiB",
                ));
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF before HTTP CONNECT response completed",
                ));
            }
            resp_buf.extend_from_slice(&tmp[..n]);
        };

        let header_bytes = resp_buf.split_to(hdr_end);
        let status_line = std::str::from_utf8(&header_bytes)
            .ok()
            .and_then(|s| s.lines().next())
            .unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);

        if status_code != 200 {
            let kind = if status_code == 407 {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            };
            return Err(io::Error::new(
                kind,
                format!("HTTP CONNECT rejected with status {status_code}"),
            ));
        }

        if resp_buf.is_empty() {
            Ok(stream)
        } else {
            Ok(Box::new(PrefixedStream {
                prefix: resp_buf,
                inner: stream,
            }))
        }
    }
}

/// Loopback HTTP `CONNECT` proxy server (supporting optional Basic Auth) for E2E testing.
pub struct HttpConnectServerConfig {
    pub listen_addr: String,
    pub credentials: Option<(String, String)>,
}

pub async fn spawn_http_connect_server(
    cfg: HttpConnectServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let bound_addr = listener.local_addr()?;
    let expected_auth = cfg.credentials.map(|(u, p)| {
        Arc::new(format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{u}:{p}"))
        ))
    });

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
                    let auth_clone = expected_auth.clone();
                    tokio::spawn(async move {
                        let _ = handle_http_connect_conn(tcp, auth_clone).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, handle))
}

async fn handle_http_connect_conn(
    mut tcp: TcpStream,
    expected_auth: Option<Arc<String>>,
) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 512];
    let hdr_end = loop {
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() >= 16 * 1024 {
            return Ok(());
        }
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let req_head = buf.split_to(hdr_end);
    let head_str = std::str::from_utf8(&req_head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in HTTP CONNECT"))?;
    let mut lines = head_str.lines();
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = tcp
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return Ok(());
    }

    if let Some(exp) = expected_auth {
        let authed = lines.any(|line| {
            if let Some((k, v)) = line.split_once(':') {
                k.trim().eq_ignore_ascii_case("Proxy-Authorization") && v.trim() == exp.as_str()
            } else {
                false
            }
        });
        if !authed {
            let _ = tcp
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rust-clash\"\r\n\r\n")
                .await;
            return Ok(());
        }
    }

    let target: TargetAddr = authority.parse()?;
    let direct = DirectOutbound::default();
    let mut outbound = direct.connect_tcp(&target).await?;
    tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !buf.is_empty() {
        outbound.write_all(&buf.chunk()[..buf.len()]).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut outbound).await?;
    Ok(())
}
