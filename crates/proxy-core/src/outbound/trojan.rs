use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA224, digest};
use bytes::{Buf, BufMut, BytesMut};
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    addr::TargetAddr,
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        ws_stream::{WsTransportConfig, accept_ws_stream, connect_ws_stream},
    },
    platform::socket_protect::protected_tcp_connect_host_with_dns,
};

pub const TROJAN_CMD_TCP: u8 = 0x01;
pub const TROJAN_CMD_UDP: u8 = 0x03;

/// Compute the 56-byte lowercase hexadecimal SHA-224 digest of a Trojan password.
pub fn trojan_password_hex(password: &str) -> [u8; 56] {
    let hash = digest(&SHA224, password.as_bytes());
    let mut out = [0u8; 56];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in hash.as_ref().iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn constant_time_eq_56(a: &[u8; 56], b: &[u8; 56]) -> bool {
    let mut diff = 0u8;
    for i in 0..56 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Clone)]
pub struct TrojanOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub ws_opts: Option<WsTransportConfig>,
    pub udp: bool,
}

struct TrojanInner {
    cfg: TrojanOutboundConfig,
    password_hex: [u8; 56],
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct TrojanOutbound {
    inner: Arc<TrojanInner>,
}

impl TrojanInner {
    async fn establish_transport(&self) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect_host_with_dns(
            &self.cfg.server,
            self.cfg.port,
            self.dns.as_deref(),
        )
        .await?;

        let sni_host = self
            .cfg
            .sni
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.cfg.ws_opts.as_ref().and_then(|w| w.host_header()))
            .unwrap_or(self.cfg.server.as_str());

        let base_stream: BoxedStream = if let Some(connector) = &self.tls_connector {
            let sni = crate::crypto::tls::parse_server_name(sni_host)?;
            let tls = connector.connect(sni, tcp).await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(ws_cfg) = &self.cfg.ws_opts {
            connect_ws_stream(base_stream, sni_host, self.cfg.port, self.cfg.tls, ws_cfg).await
        } else {
            Ok(base_stream)
        }
    }

    fn build_request_header(&self, cmd: u8, target: &TargetAddr) -> io::Result<BytesMut> {
        let mut hdr = BytesMut::with_capacity(96);
        hdr.put_slice(&self.password_hex);
        hdr.put_slice(b"\r\n");
        hdr.put_u8(cmd);
        target.encode_socks5(&mut hdr)?;
        hdr.put_slice(b"\r\n");
        Ok(hdr)
    }
}

impl TrojanOutbound {
    pub fn new(cfg: TrojanOutboundConfig) -> io::Result<Self> {
        Self::new_with_dns(cfg, None)
    }

    pub fn new_with_dns(
        cfg: TrojanOutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        if cfg.password.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trojan password must not be empty",
            ));
        }
        let password_hex = trojan_password_hex(&cfg.password);
        let tls_connector = if cfg.tls {
            let default_ws_alpn = [b"http/1.1".to_vec()];
            let effective_alpn: &[Vec<u8>] = if cfg.ws_opts.is_some() && cfg.alpn.is_empty() {
                &default_ws_alpn
            } else {
                &cfg.alpn
            };
            let tls_cfg = crate::crypto::tls::build_tls_client_config(
                cfg.skip_cert_verify,
                &cfg.extra_ca_der,
                effective_alpn,
            )?;
            Some(TlsConnector::from(tls_cfg))
        } else {
            None
        };

        Ok(Self {
            inner: Arc::new(TrojanInner {
                cfg,
                password_hex,
                tls_connector,
                dns,
            }),
        })
    }
}

/// Client stream coalescing the Trojan request header with the first outbound payload write
/// (or flushing on first read for server-speaks-first protocols).
pub struct TrojanClientStream<S> {
    inner: S,
    pending_req_hdr: BytesMut,
    pending_user_written: usize,
}

impl<S> TrojanClientStream<S> {
    pub fn new(inner: S, req_hdr: BytesMut) -> Self {
        Self {
            inner,
            pending_req_hdr: req_hdr,
            pending_user_written: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrojanClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.pending_req_hdr.is_empty() {
            while !this.pending_req_hdr.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.pending_req_hdr) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Trojan header write(0) before read",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.pending_req_hdr.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if let Poll::Ready(Err(e)) = Pin::new(&mut this.inner).poll_flush(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrojanClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if !this.pending_req_hdr.is_empty() {
            if this.pending_user_written == 0 {
                let take = buf.len().min(8000);
                this.pending_req_hdr.extend_from_slice(&buf[..take]);
                this.pending_user_written = take;
            }
            while !this.pending_req_hdr.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.pending_req_hdr) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Trojan header write(0)",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.pending_req_hdr.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let done = this.pending_user_written;
            this.pending_user_written = 0;
            return Poll::Ready(Ok(done));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending_req_hdr.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending_req_hdr) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Trojan flush write(0)",
                    )));
                }
                Poll::Ready(Ok(n)) => this.pending_req_hdr.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().inner).poll_shutdown(cx),
            other => other,
        }
    }
}

pub fn encode_trojan_udp_packet(
    target: &TargetAddr,
    payload: &[u8],
    out: &mut BytesMut,
) -> io::Result<()> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Trojan UDP datagram exceeds 65535 bytes",
        ));
    }
    target.encode_socks5(out)?;
    out.put_u16(payload.len() as u16);
    out.put_slice(b"\r\n");
    out.put_slice(payload);
    Ok(())
}

pub async fn read_trojan_udp_packet<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<(Vec<u8>, TargetAddr)> {
    let target = TargetAddr::read_socks5(reader).await?;
    let plen = reader.read_u16().await? as usize;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Trojan UDP CRLF delimiter",
        ));
    }
    let mut payload = vec![0u8; plen];
    reader.read_exact(&mut payload).await?;
    Ok((payload, target))
}

type UdpRecvItem = io::Result<(Vec<u8>, TargetAddr)>;
type UdpSendTx = mpsc::Sender<(Vec<u8>, TargetAddr)>;

struct TrojanUdpSession {
    inner: Arc<TrojanInner>,
    tx: Arc<AsyncMutex<Option<UdpSendTx>>>,
    rx_tx: mpsc::Sender<UdpRecvItem>,
    rx: AsyncMutex<mpsc::Receiver<UdpRecvItem>>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl TrojanUdpSession {
    fn new(inner: Arc<TrojanInner>) -> Self {
        let (rx_tx, rx) = mpsc::channel(128);
        Self {
            inner,
            tx: Arc::new(AsyncMutex::new(None)),
            rx_tx,
            rx: AsyncMutex::new(rx),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl OutboundUdpSession for TrojanUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trojan UDP datagram exceeds 65535 bytes",
            ));
        }

        let mut guard = self.tx.lock().await;
        if let Some(existing) = guard.as_ref() {
            if !existing.is_closed()
                && existing
                    .send((payload.to_vec(), target.clone()))
                    .await
                    .is_ok()
            {
                return Ok(());
            }
            *guard = None;
        }

        let transport = self.inner.establish_transport().await?;
        let req_hdr = self.inner.build_request_header(TROJAN_CMD_UDP, target)?;
        let stream = TrojanClientStream::new(transport, req_hdr);
        let (mut rd, mut wr) = tokio::io::split(stream);

        let my_gen = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.closed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut rx_guard) = self.rx.try_lock() {
            while let Ok(item) = rx_guard.try_recv() {
                if let Ok(ok_item) = item {
                    let _ = self.rx_tx.try_send(Ok(ok_item));
                    break;
                }
            }
        }

        let (pkt_tx, mut pkt_rx) = mpsc::channel::<(Vec<u8>, TargetAddr)>(64);
        pkt_tx
            .send((payload.to_vec(), target.clone()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Trojan UDP queue closed"))?;

        let writer_handle = tokio::spawn(async move {
            while let Some((dgram, dst)) = pkt_rx.recv().await {
                let mut pkt = BytesMut::with_capacity(32 + dgram.len());
                if encode_trojan_udp_packet(&dst, &dgram, &mut pkt).is_err() {
                    continue;
                }
                if wr.write_all(&pkt).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        let writer_abort = writer_handle.abort_handle();

        let rx_tx = self.rx_tx.clone();
        let tx_slot = Arc::clone(&self.tx);
        let gen_ref = Arc::clone(&self.generation);
        let closed_ref = Arc::clone(&self.closed);
        tokio::spawn(async move {
            loop {
                match read_trojan_udp_packet(&mut rd).await {
                    Ok(item) => {
                        if rx_tx.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        writer_abort.abort();
                        if gen_ref.load(std::sync::atomic::Ordering::SeqCst) == my_gen {
                            closed_ref.store(true, std::sync::atomic::Ordering::SeqCst);
                            if let Ok(mut g) = tx_slot.try_lock() {
                                *g = None;
                            }
                            let eof_err = io::Error::new(
                                err.kind(),
                                format!("Trojan UDP remote stream closed: {err}"),
                            );
                            let _ = rx_tx.try_send(Err(eof_err));
                        }
                        break;
                    }
                }
            }
        });

        *guard = Some(pkt_tx);
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut rx = self.rx.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(item) = rx.try_recv() {
                return item;
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Trojan UDP remote stream closed",
            ));
        }
        rx.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Trojan UDP session closed",
            ))
        })
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "Trojan"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.inner.cfg.server, self.inner.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        self.inner.cfg.udp
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
        let transport = self.inner.establish_transport().await?;
        let req_hdr = self.inner.build_request_header(TROJAN_CMD_TCP, target)?;
        Ok(Box::new(TrojanClientStream::new(transport, req_hdr)))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.inner.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this Trojan outbound",
            ));
        }
        Ok(Box::new(TrojanUdpSession::new(Arc::clone(&self.inner))))
    }
}

/// Loopback-compatible Trojan server (supporting TLS, plain TCP, WebSocket, TCP CONNECT, and UDP ASSOCIATE).
pub struct TrojanServerConfig {
    pub listen_addr: String,
    pub password: String,
    pub tls_config: Option<Arc<ServerConfig>>,
    pub ws_path: Option<String>,
}

pub async fn spawn_trojan_server(
    cfg: TrojanServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let bound_addr = listener.local_addr()?;
    let expected_hex = trojan_password_hex(&cfg.password);
    let tls_acceptor = cfg.tls_config.map(TlsAcceptor::from);
    let ws_path = cfg.ws_path;

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
                    let tls_clone = tls_acceptor.clone();
                    let ws_clone = ws_path.clone();
                    tokio::spawn(async move {
                        let _ = handle_trojan_server_conn(tcp, expected_hex, tls_clone, ws_clone).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, handle))
}

async fn handle_trojan_server_conn(
    tcp: TcpStream,
    expected_hex: [u8; 56],
    tls_acceptor: Option<TlsAcceptor>,
    ws_path: Option<String>,
) -> io::Result<()> {
    let base: BoxedStream = if let Some(acceptor) = tls_acceptor {
        Box::new(acceptor.accept(tcp).await?)
    } else {
        Box::new(tcp)
    };

    let mut stream: BoxedStream = if let Some(path) = ws_path {
        accept_ws_stream(base, Some(&path)).await?
    } else {
        base
    };

    let mut client_hex = [0u8; 56];
    stream.read_exact(&mut client_hex).await?;
    client_hex.make_ascii_lowercase();
    if !constant_time_eq_56(&client_hex, &expected_hex) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trojan password hash mismatch",
        ));
    }

    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing CRLF after Trojan password",
        ));
    }

    let cmd = stream.read_u8().await?;
    let initial_target = TargetAddr::read_socks5(&mut stream).await?;
    stream.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing CRLF after Trojan target address",
        ));
    }

    let direct = DirectOutbound::default();
    match cmd {
        TROJAN_CMD_TCP => {
            let mut outbound = direct.connect_tcp(&initial_target).await?;
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut stream,
                &mut outbound,
                64 * 1024,
                64 * 1024,
            )
            .await?;
            Ok(())
        }
        TROJAN_CMD_UDP => {
            let upstream = Arc::new(direct.open_udp_session().await?);
            let upstream_rx = Arc::clone(&upstream);
            let (mut rd, mut wr) = tokio::io::split(stream);

            let client_to_up = async move {
                while let Ok((dgram, dst)) = read_trojan_udp_packet(&mut rd).await {
                    let _ = upstream.send_to(&dgram, &dst).await;
                }
            };

            let up_to_client = async move {
                while let Ok(res) =
                    tokio::time::timeout(Duration::from_secs(60), upstream_rx.recv_from()).await
                {
                    let Ok((resp, src_addr)) = res else {
                        break;
                    };
                    let mut out_pkt = BytesMut::with_capacity(32 + resp.len());
                    if encode_trojan_udp_packet(&src_addr, &resp, &mut out_pkt).is_err() {
                        continue;
                    }
                    if wr.write_all(&out_pkt).await.is_err() || wr.flush().await.is_err() {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = client_to_up => {}
                _ = up_to_client => {}
            }
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported Trojan command 0x{other:02x}"),
        )),
    }
}
