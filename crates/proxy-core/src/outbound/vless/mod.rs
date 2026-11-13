pub mod encryption;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

use crate::{
    addr::TargetAddr,
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        vless::encryption::{ClientEncryption, ServerEncryption},
        ws_stream::{WsTransportConfig, accept_ws_stream, connect_ws_stream},
    },
    platform::socket_protect::protected_tcp_connect_host_with_dns,
};

pub const VLESS_CMD_TCP: u8 = 0x01;
pub const VLESS_CMD_UDP: u8 = 0x02;
pub const VLESS_CMD_MUX: u8 = 0x03;

#[derive(Clone)]
pub struct VlessOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub encryption: String,
    pub tls: bool,
    pub servername: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub udp: bool,
}

struct VlessInner {
    cfg: VlessOutboundConfig,
    ws_opts: Option<WsTransportConfig>,
    pq_encryption: Option<Arc<ClientEncryption>>,
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct VlessOutbound {
    inner: Arc<VlessInner>,
}

impl VlessInner {
    async fn establish_transport(&self) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect_host_with_dns(
            &self.cfg.server,
            self.cfg.port,
            self.dns.as_deref(),
        )
        .await?;

        let sni_str = self
            .cfg
            .servername
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.ws_opts.as_ref().and_then(|w| w.host_header()))
            .unwrap_or(self.cfg.server.as_str());

        let tls_or_tcp: BoxedStream = if let Some(connector) = &self.tls_connector {
            let sni = crate::crypto::tls::parse_server_name(sni_str)?;
            let tls = connector.connect(sni, tcp).await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        let base_stream: BoxedStream = if let Some(ws_cfg) = &self.ws_opts {
            connect_ws_stream(tls_or_tcp, sni_str, self.cfg.port, self.cfg.tls, ws_cfg).await?
        } else {
            tls_or_tcp
        };

        if let Some(enc) = &self.pq_encryption {
            let encrypted = enc.handshake(base_stream).await?;
            Ok(Box::new(encrypted))
        } else {
            Ok(base_stream)
        }
    }

    fn build_vless_request_header(&self, cmd: u8, target: &TargetAddr) -> io::Result<BytesMut> {
        let mut hdr = BytesMut::with_capacity(64);
        hdr.put_u8(0x00); // VLESS v0
        hdr.put_slice(self.cfg.uuid.as_bytes());
        hdr.put_u8(0x00); // Addons length = 0
        hdr.put_u8(cmd);
        target.encode_vless(&mut hdr)?;
        Ok(hdr)
    }
}

impl VlessOutbound {
    pub fn new(cfg: VlessOutboundConfig) -> io::Result<Self> {
        Self::new_with_transport(cfg, None, None)
    }

    pub fn new_with_dns(
        cfg: VlessOutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        Self::new_with_transport(cfg, None, dns)
    }

    pub fn new_with_transport(
        cfg: VlessOutboundConfig,
        ws_opts: Option<WsTransportConfig>,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let pq_encryption =
            if cfg.encryption.trim().is_empty() || cfg.encryption.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(Arc::new(ClientEncryption::new(&cfg.encryption)?))
            };

        let tls_connector = if cfg.tls {
            let default_ws_alpn = [b"http/1.1".to_vec()];
            let effective_alpn: &[Vec<u8>] = if ws_opts.is_some() && cfg.alpn.is_empty() {
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
            inner: Arc::new(VlessInner {
                cfg,
                ws_opts,
                pq_encryption,
                tls_connector,
                dns,
            }),
        })
    }

    pub fn has_valid_0rtt_ticket(&self) -> bool {
        self.inner
            .pq_encryption
            .as_ref()
            .is_some_and(|e| e.has_valid_0rtt_ticket())
    }
}

type UdpRecvItem = io::Result<(Vec<u8>, TargetAddr)>;

/// Persistent multi-packet VLESS UDP session caching open `VLESS_CMD_UDP` streams per target.
/// Avoids repeating TLS / ML-KEM-768 handshakes on every UDP datagram and supports asynchronous
/// multi-datagram server bursts (such as QUIC/HTTP3 handshakes and media streams).
struct VlessUdpSession {
    inner: Arc<VlessInner>,
    streams: Arc<AsyncMutex<HashMap<TargetAddr, mpsc::Sender<Vec<u8>>>>>,
    rx_tx: mpsc::Sender<UdpRecvItem>,
    rx: AsyncMutex<mpsc::Receiver<UdpRecvItem>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl VlessUdpSession {
    fn new(inner: Arc<VlessInner>) -> Self {
        let (rx_tx, rx) = mpsc::channel(128);
        Self {
            inner,
            streams: Arc::new(AsyncMutex::new(HashMap::new())),
            rx_tx,
            rx: AsyncMutex::new(rx),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl OutboundUdpSession for VlessUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP datagram exceeds 65535 bytes",
            ));
        }

        let mut map = self.streams.lock().await;
        map.retain(|_, tx| !tx.is_closed());
        if let Some(tx) = map.get(target) {
            if tx.send(payload.to_vec()).await.is_ok() {
                return Ok(());
            }
            map.remove(target);
        }

        if map.len() >= 16
            && let Some(evict_key) = map.keys().next().cloned()
        {
            map.remove(&evict_key);
        }

        let transport = self.inner.establish_transport().await?;
        let req_hdr = self
            .inner
            .build_vless_request_header(VLESS_CMD_UDP, target)?;
        let stream = VlessClientStream::new(transport, req_hdr);
        let (mut rd, mut wr) = tokio::io::split(stream);

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

        let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(64);
        pkt_tx
            .send(payload.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VLESS UDP queue closed"))?;

        let writer_handle = tokio::spawn(async move {
            while let Some(dgram) = pkt_rx.recv().await {
                let mut pkt = BytesMut::with_capacity(2 + dgram.len());
                pkt.put_u16(dgram.len() as u16);
                pkt.put_slice(&dgram);
                if wr.write_all(&pkt).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        let writer_abort = writer_handle.abort_handle();

        let target_clone = target.clone();
        let rx_tx = self.rx_tx.clone();
        let streams_ref = Arc::clone(&self.streams);
        let closed_ref = Arc::clone(&self.closed);
        let weak_pkt_tx = pkt_tx.downgrade();
        tokio::spawn(async move {
            let mut end_err: Option<io::Error> = None;
            loop {
                match rd.read_u16().await {
                    Ok(resp_len) => {
                        let mut resp = vec![0u8; resp_len as usize];
                        if let Err(e) = rd.read_exact(&mut resp).await {
                            end_err = Some(e);
                            break;
                        }
                        if rx_tx.send(Ok((resp, target_clone.clone()))).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        end_err = Some(e);
                        break;
                    }
                }
            }
            writer_abort.abort();
            let no_live_streams = {
                let mut m = streams_ref.lock().await;
                let ended_tx = weak_pkt_tx.upgrade();
                m.retain(|k, tx| {
                    if k == &target_clone
                        && ended_tx.as_ref().is_some_and(|mine| tx.same_channel(mine))
                    {
                        return false;
                    }
                    !tx.is_closed()
                });
                m.is_empty()
            };
            if no_live_streams && let Some(err) = end_err {
                closed_ref.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = rx_tx.try_send(Err(io::Error::new(
                    err.kind(),
                    format!("VLESS UDP remote stream closed: {err}"),
                )));
            }
        });

        map.insert(target.clone(), pkt_tx);
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
                "VLESS UDP remote stream closed",
            ));
        }
        rx.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VLESS UDP session closed",
            ))
        })
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        if self.inner.pq_encryption.is_some() {
            "VLESS+Encryption"
        } else {
            "VLESS"
        }
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
        let req_hdr = self
            .inner
            .build_vless_request_header(VLESS_CMD_TCP, target)?;
        Ok(Box::new(VlessClientStream::new(transport, req_hdr)))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.inner.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this VLESS outbound",
            ));
        }
        Ok(Box::new(VlessUdpSession::new(Arc::clone(&self.inner))))
    }

    async fn exchange_udp(
        &self,
        target: &TargetAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if !self.inner.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this VLESS outbound",
            ));
        }
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP datagram exceeds 65535 bytes",
            ));
        }

        tokio::time::timeout(timeout, async {
            let transport = self.inner.establish_transport().await?;
            let req_hdr = self
                .inner
                .build_vless_request_header(VLESS_CMD_UDP, target)?;
            let mut stream = VlessClientStream::new(transport, req_hdr);

            let mut pkt = BytesMut::with_capacity(2 + payload.len());
            pkt.put_u16(payload.len() as u16);
            pkt.put_slice(payload);
            stream.write_all(&pkt).await?;
            stream.flush().await?;

            let resp_len = stream.read_u16().await? as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await?;
            Ok(resp)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS UDP timed out"))?
    }
}

/// Client stream wrapper that coalesces the VLESS v0 request header onto the first write
/// (enabling true 0-RTT application data piggybacking!) and strips the `[ver=0, addons_len]`
/// VLESS response header on the first read!
pub struct VlessClientStream<S> {
    inner: S,
    pending_req_hdr: BytesMut,
    pending_user_written: usize,
    resp_hdr_state: RespHdrState,
    hdr_buf: BytesMut,
}

enum RespHdrState {
    NeedVerAndAddonsLen,
    NeedAddons(usize),
    Done,
}

impl<S> VlessClientStream<S> {
    pub fn new(inner: S, req_hdr: BytesMut) -> Self {
        Self {
            inner,
            pending_req_hdr: req_hdr,
            pending_user_written: 0,
            resp_hdr_state: RespHdrState::NeedVerAndAddonsLen,
            hdr_buf: BytesMut::with_capacity(8),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.resp_hdr_state {
                RespHdrState::Done => {
                    if !self.hdr_buf.is_empty() {
                        let n = buf.remaining().min(self.hdr_buf.len());
                        buf.put_slice(&self.hdr_buf.split_to(n));
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
                RespHdrState::NeedVerAndAddonsLen => {
                    if self.hdr_buf.len() >= 2 {
                        let ver = self.hdr_buf[0];
                        let addons_len = self.hdr_buf[1] as usize;
                        self.hdr_buf.advance(2);
                        if ver != 0x00 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid VLESS response version 0x{ver:02x}"),
                            )));
                        }
                        self.resp_hdr_state = if addons_len == 0 {
                            RespHdrState::Done
                        } else {
                            RespHdrState::NeedAddons(addons_len)
                        };
                        continue;
                    }
                }
                RespHdrState::NeedAddons(len) => {
                    if self.hdr_buf.len() >= len {
                        self.hdr_buf.advance(len);
                        self.resp_hdr_state = RespHdrState::Done;
                        continue;
                    }
                }
            }

            let mut tmp = [0u8; 256];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.hdr_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessClientStream<S> {
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
                            "VLESS header write(0)",
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
                        "VLESS flush write(0)",
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

/// Wire-compatible VLESS v0 + `mlkem768x25519plus` Decryption Server (supports plain, TLS, and PQ-Encrypted VLESS!).
pub struct VlessServerConfig {
    pub listen_addr: String,
    pub allowed_uuid: Uuid,
    /// `"none"` or `"mlkem768x25519plus.<mode>.<ttl>..."`
    pub decryption: String,
    pub tls_config: Option<Arc<ServerConfig>>,
}

pub async fn spawn_vless_server(
    cfg: VlessServerConfig,
    shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    spawn_vless_server_inner(cfg, None, shutdown).await
}

pub async fn spawn_vless_ws_server(
    cfg: VlessServerConfig,
    ws_path: String,
    shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    spawn_vless_server_inner(cfg, Some(ws_path), shutdown).await
}

async fn spawn_vless_server_inner(
    cfg: VlessServerConfig,
    ws_path: Option<String>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let bound_addr = listener.local_addr()?;

    let pq_dec = if cfg.decryption.trim().is_empty() || cfg.decryption.eq_ignore_ascii_case("none")
    {
        None
    } else {
        Some(Arc::new(ServerEncryption::new(&cfg.decryption)?))
    };
    let tls_acceptor = cfg.tls_config.map(TlsAcceptor::from);
    let expected_uuid = cfg.allowed_uuid;

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
                    let dec_clone = pq_dec.clone();
                    let tls_clone = tls_acceptor.clone();
                    let ws_clone = ws_path.clone();
                    tokio::spawn(async move {
                        let _ = handle_vless_server_conn(tcp, expected_uuid, tls_clone, ws_clone, dec_clone).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, handle))
}

async fn handle_vless_server_conn(
    tcp: TcpStream,
    expected_uuid: Uuid,
    tls_acceptor: Option<TlsAcceptor>,
    ws_path: Option<String>,
    pq_dec: Option<Arc<ServerEncryption>>,
) -> io::Result<()> {
    let tls_or_tcp: BoxedStream = if let Some(acceptor) = tls_acceptor {
        Box::new(acceptor.accept(tcp).await?)
    } else {
        Box::new(tcp)
    };

    let base: BoxedStream = if let Some(path) = ws_path {
        accept_ws_stream(tls_or_tcp, Some(&path)).await?
    } else {
        tls_or_tcp
    };

    let mut stream: BoxedStream = if let Some(dec) = pq_dec {
        Box::new(dec.accept(base).await?)
    } else {
        base
    };

    let ver = stream.read_u8().await?;
    if ver != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VLESS version 0x{ver:02x}"),
        ));
    }
    let mut uuid_bytes = [0u8; 16];
    stream.read_exact(&mut uuid_bytes).await?;
    if Uuid::from_bytes(uuid_bytes) != expected_uuid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS UUID mismatch",
        ));
    }
    let addons_len = stream.read_u8().await? as usize;
    if addons_len > 0 {
        let mut addons = vec![0u8; addons_len];
        stream.read_exact(&mut addons).await?;
    }
    let cmd = stream.read_u8().await?;
    let direct = DirectOutbound::default();
    match cmd {
        VLESS_CMD_TCP => {
            let target = TargetAddr::read_vless(&mut stream).await?;
            let mut outbound = direct.connect_tcp(&target).await?;
            stream.write_all(&[0x00, 0x00]).await?;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await?;
            Ok(())
        }
        VLESS_CMD_UDP => {
            let target = TargetAddr::read_vless(&mut stream).await?;
            let upstream = Arc::new(direct.open_udp_session().await?);
            let upstream_rx = Arc::clone(&upstream);
            let (mut rd, mut wr) = tokio::io::split(stream);

            let client_to_up = async move {
                while let Ok(plen) = rd.read_u16().await {
                    let mut dgram = vec![0u8; plen as usize];
                    if rd.read_exact(&mut dgram).await.is_err() {
                        break;
                    }
                    let _ = upstream.send_to(&dgram, &target).await;
                }
            };

            let up_to_client = async move {
                let mut hdr_sent = false;
                while let Ok(res) =
                    tokio::time::timeout(Duration::from_secs(60), upstream_rx.recv_from()).await
                {
                    let Ok((resp, _src)) = res else {
                        break;
                    };
                    let mut out_pkt = BytesMut::with_capacity(4 + resp.len());
                    if !hdr_sent {
                        out_pkt.put_slice(&[0x00, 0x00]);
                        hdr_sent = true;
                    }
                    out_pkt.put_u16(resp.len() as u16);
                    out_pkt.put_slice(&resp);
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
        VLESS_CMD_MUX => {
            // Xray XUDP / mux.cool framing (`RequestCommandMux = 0x03`, persistent per-session UDP sockets)
            let (mut rd, mut wr) = tokio::io::split(stream);
            let (resp_tx, mut resp_rx) = mpsc::channel::<(u16, TargetAddr, Vec<u8>)>(128);

            let writer_fut = async move {
                let mut hdr_sent = false;
                while let Some((session_id, src_addr, resp)) = resp_rx.recv().await {
                    let mut resp_meta = BytesMut::with_capacity(32);
                    resp_meta.put_u16(session_id);
                    resp_meta.put_u8(0x02); // SessionStatusKeep
                    resp_meta.put_u8(0x01); // OptionData
                    resp_meta.put_u8(0x02); // Network_UDP
                    if src_addr.encode_vless(&mut resp_meta).is_err() {
                        continue;
                    }

                    let mut out_pkt = BytesMut::with_capacity(6 + resp_meta.len() + resp.len());
                    if !hdr_sent {
                        out_pkt.put_slice(&[0x00, 0x00]);
                        hdr_sent = true;
                    }
                    out_pkt.put_u16(resp_meta.len() as u16);
                    out_pkt.put_slice(&resp_meta);
                    out_pkt.put_u16(resp.len() as u16);
                    out_pkt.put_slice(&resp);
                    if wr.write_all(&out_pkt).await.is_err() || wr.flush().await.is_err() {
                        break;
                    }
                }
            };

            let reader_fut = async move {
                let mut sessions: HashMap<u16, (TargetAddr, Arc<Box<dyn OutboundUdpSession>>)> =
                    HashMap::new();
                while let Ok(meta_len_u16) = rd.read_u16().await {
                    let meta_len = meta_len_u16 as usize;
                    if meta_len < 4 {
                        break;
                    }
                    let mut meta = vec![0u8; meta_len];
                    if rd.read_exact(&mut meta).await.is_err() {
                        break;
                    }
                    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
                    let status = meta[2];
                    let option = meta[3];

                    let mut pkt_target = None;
                    if (status == 0x01 || status == 0x02) && meta.len() > 5 && meta[4] == 0x02 {
                        let mut cursor = io::Cursor::new(&meta[5..]);
                        if let Ok(parsed) = TargetAddr::read_vless(&mut cursor).await {
                            pkt_target = Some(parsed);
                        }
                    }

                    let payload = if (option & 0x01) != 0 {
                        let Ok(dlen) = rd.read_u16().await else {
                            break;
                        };
                        let mut d = vec![0u8; dlen as usize];
                        if rd.read_exact(&mut d).await.is_err() {
                            break;
                        }
                        Some(d)
                    } else {
                        None
                    };

                    if status == 0x03 {
                        sessions.remove(&session_id);
                        continue;
                    }

                    if !sessions.contains_key(&session_id)
                        && let Some(ref initial_t) = pkt_target
                        && sessions.len() < 64
                        && let Ok(up) = direct.open_udp_session().await
                    {
                        let up_arc = Arc::new(up);
                        let up_rx = Arc::clone(&up_arc);
                        let tx_clone = resp_tx.clone();
                        tokio::spawn(async move {
                            while let Ok(res) =
                                tokio::time::timeout(Duration::from_secs(60), up_rx.recv_from())
                                    .await
                            {
                                let Ok((resp, src_addr)) = res else {
                                    break;
                                };
                                if tx_clone.send((session_id, src_addr, resp)).await.is_err() {
                                    break;
                                }
                            }
                        });
                        sessions.insert(session_id, (initial_t.clone(), up_arc));
                    }

                    let resolved_entry = sessions.get(&session_id).cloned();
                    if let (Some((default_t, up_sess)), Some(dgram)) = (resolved_entry, payload) {
                        let dst = pkt_target.unwrap_or(default_t);
                        let _ = up_sess.send_to(&dgram, &dst).await;
                    }
                }
            };

            tokio::select! {
                _ = writer_fut => {}
                _ = reader_fut => {}
            }
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported VLESS command 0x{other:02x}"),
        )),
    }
}
