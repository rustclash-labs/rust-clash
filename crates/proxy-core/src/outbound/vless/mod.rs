pub mod encryption;
pub mod reality;
pub mod vision;

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
        vless::{
            encryption::{ClientEncryption, ServerEncryption},
            reality::{
                RealityClientConfig, Tls13HandshakeMode, Tls13VisionStream,
                accept_reality_tls13_server, connect_tls13_vision_stream,
            },
            vision::{
                VISION_ADDONS_PROTOBUF, VisionStream, VlessVisionFlow, VlessVisionXudpSession,
            },
        },
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
    flow: Option<VlessVisionFlow>,
    reality: Option<RealityClientConfig>,
    pq_encryption: Option<Arc<ClientEncryption>>,
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct VlessOutbound {
    inner: Arc<VlessInner>,
}

impl VlessInner {
    fn effective_sni(&self) -> &str {
        self.cfg
            .servername
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.reality.as_ref().map(|r| r.server_name.as_str()))
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.ws_opts.as_ref().and_then(|w| w.host_header()))
            .unwrap_or(self.cfg.server.as_str())
    }

    async fn establish_vision_tls(&self) -> io::Result<Tls13VisionStream<TcpStream>> {
        let tcp = protected_tcp_connect_host_with_dns(
            &self.cfg.server,
            self.cfg.port,
            self.dns.as_deref(),
        )
        .await?;
        let mode = if let Some(rcfg) = &self.reality {
            Tls13HandshakeMode::Reality(rcfg.clone())
        } else {
            Tls13HandshakeMode::StandardTls {
                server_name: self.effective_sni().to_string(),
                skip_cert_verify: self.cfg.skip_cert_verify,
                extra_ca_der: self.cfg.extra_ca_der.clone(),
                alpn: self.cfg.alpn.clone(),
            }
        };
        crate::outbound::with_handshake_timeout(
            "VLESS Vision TLS/REALITY handshake",
            connect_tls13_vision_stream(tcp, &mode),
        )
        .await
    }

    async fn connect_vision_mux_stream(&self) -> io::Result<VisionStream<TcpStream>> {
        let tls = self.establish_vision_tls().await?;
        let req_hdr = self.build_vless_vision_mux_header();
        Ok(VisionStream::new_client(tls, self.cfg.uuid, req_hdr))
    }

    async fn establish_transport(&self) -> io::Result<BoxedStream> {
        if let Some(rcfg) = &self.reality {
            let tcp = protected_tcp_connect_host_with_dns(
                &self.cfg.server,
                self.cfg.port,
                self.dns.as_deref(),
            )
            .await?;
            let mode = Tls13HandshakeMode::Reality(rcfg.clone());
            let tls = crate::outbound::with_handshake_timeout(
                "VLESS REALITY handshake",
                connect_tls13_vision_stream(tcp, &mode),
            )
            .await?;
            return Ok(Box::new(tls));
        }

        let tcp = protected_tcp_connect_host_with_dns(
            &self.cfg.server,
            self.cfg.port,
            self.dns.as_deref(),
        )
        .await?;

        let sni_str = self.effective_sni();

        let tls_or_tcp: BoxedStream = if let Some(connector) = &self.tls_connector {
            let sni = crate::crypto::tls::parse_server_name(sni_str)?;
            let tls = crate::outbound::with_handshake_timeout(
                "VLESS TLS handshake",
                connector.connect(sni, tcp),
            )
            .await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        let base_stream: BoxedStream = if let Some(ws_cfg) = &self.ws_opts {
            crate::outbound::with_handshake_timeout(
                "VLESS WebSocket handshake",
                connect_ws_stream(tls_or_tcp, sni_str, self.cfg.port, self.cfg.tls, ws_cfg),
            )
            .await?
        } else {
            tls_or_tcp
        };

        if let Some(enc) = &self.pq_encryption {
            let encrypted = crate::outbound::with_handshake_timeout(
                "VLESS PQ encryption handshake",
                enc.handshake(base_stream),
            )
            .await?;
            Ok(Box::new(encrypted))
        } else {
            Ok(base_stream)
        }
    }

    fn build_vless_request_header(&self, cmd: u8, target: &TargetAddr) -> io::Result<BytesMut> {
        let mut hdr = BytesMut::with_capacity(96);
        hdr.put_u8(0x00); // VLESS v0
        hdr.put_slice(self.cfg.uuid.as_bytes());
        if self.flow.is_some() {
            hdr.put_u8(VISION_ADDONS_PROTOBUF.len() as u8);
            hdr.put_slice(VISION_ADDONS_PROTOBUF);
        } else {
            hdr.put_u8(0x00); // Addons length = 0
        }
        hdr.put_u8(cmd);
        target.encode_vless(&mut hdr)?;
        Ok(hdr)
    }

    fn build_vless_vision_mux_header(&self) -> BytesMut {
        let mut hdr = BytesMut::with_capacity(40);
        hdr.put_u8(0x00); // VLESS v0
        hdr.put_slice(self.cfg.uuid.as_bytes());
        hdr.put_u8(VISION_ADDONS_PROTOBUF.len() as u8);
        hdr.put_slice(VISION_ADDONS_PROTOBUF);
        hdr.put_u8(VLESS_CMD_MUX); // RequestCommandMux omits Address/Port in VLESS header
        hdr
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
        Self::new_with_vision_and_reality(cfg, ws_opts, None, None, dns)
    }

    pub fn new_with_vision_and_reality(
        cfg: VlessOutboundConfig,
        ws_opts: Option<WsTransportConfig>,
        flow: Option<VlessVisionFlow>,
        reality: Option<RealityClientConfig>,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let pq_encryption =
            if cfg.encryption.trim().is_empty() || cfg.encryption.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(Arc::new(ClientEncryption::new(&cfg.encryption)?))
            };

        if flow.is_some() {
            if ws_opts.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS xtls-rprx-vision requires raw TCP transport (WebSocket is incompatible)",
                ));
            }
            if pq_encryption.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS xtls-rprx-vision cannot be combined with VLESS PQ encryption",
                ));
            }
            if reality.is_none() && !cfg.tls {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS xtls-rprx-vision requires TLS or REALITY",
                ));
            }
        }

        if reality.is_some() {
            if ws_opts.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS REALITY requires raw TCP transport",
                ));
            }
            if pq_encryption.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS REALITY cannot be combined with VLESS PQ encryption",
                ));
            }
        }

        let tls_connector = if cfg.tls && reality.is_none() && flow.is_none() {
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
                flow,
                reality,
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
type VlessUdpStreamEntry = (mpsc::Sender<Vec<u8>>, tokio::task::AbortHandle);

/// Persistent multi-packet VLESS UDP session caching open `VLESS_CMD_UDP` streams per target.
/// Avoids repeating TLS / ML-KEM-768 handshakes on every UDP datagram and supports asynchronous
/// multi-datagram server bursts (such as QUIC/HTTP3 handshakes and media streams).
struct VlessUdpSession {
    inner: Arc<VlessInner>,
    streams: Arc<AsyncMutex<HashMap<TargetAddr, VlessUdpStreamEntry>>>,
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

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[async_trait]
impl OutboundUdpSession for VlessUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP datagram exceeds 65535 bytes",
            ));
        }

        let maybe_existing = {
            let mut map = self.streams.lock().await;
            map.retain(|_, (tx, _)| !tx.is_closed());
            map.get(target).map(|(tx, _)| tx.clone())
        };
        if let Some(tx) = maybe_existing
            && tx.send(payload.to_vec()).await.is_ok()
        {
            return Ok(());
        }

        let transport = self.inner.establish_transport().await?;
        let req_hdr = self
            .inner
            .build_vless_request_header(VLESS_CMD_UDP, target)?;

        let mut map = self.streams.lock().await;
        map.retain(|_, (tx, _)| !tx.is_closed());
        if let Some((tx, _)) = map.get(target) {
            if tx.send(payload.to_vec()).await.is_ok() {
                return Ok(());
            }
            if let Some((_, reader_abort)) = map.remove(target) {
                reader_abort.abort();
            }
        }

        if map.len() >= 16
            && let Some(evict_key) = map.keys().next().cloned()
            && let Some((_, reader_abort)) = map.remove(&evict_key)
        {
            reader_abort.abort();
        }

        let stream = VlessClientStream::new(transport, req_hdr);
        let (mut rd, mut wr) = tokio::io::split(stream);

        self.closed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut rx_guard) = self.rx.try_lock() {
            let mut valid = Vec::new();
            while let Ok(item) = rx_guard.try_recv() {
                if let Ok(ok_item) = item {
                    valid.push(ok_item);
                }
            }
            for ok_item in valid {
                let _ = self.rx_tx.try_send(Ok(ok_item));
            }
        }

        let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(64);
        pkt_tx
            .send(payload.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VLESS UDP queue closed"))?;

        let started = tokio::time::Instant::now();
        let last_active_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let last_active_wr = Arc::clone(&last_active_ms);

        let writer_handle = tokio::spawn(async move {
            while let Some(dgram) = pkt_rx.recv().await {
                let mut pkt = BytesMut::with_capacity(2 + dgram.len());
                pkt.put_u16(dgram.len() as u16);
                pkt.put_slice(&dgram);
                if wr.write_all(&pkt).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
                last_active_wr.store(
                    started.elapsed().as_millis() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            let _ = wr.shutdown().await;
        });
        let writer_abort = writer_handle.abort_handle();

        let target_clone = target.clone();
        let rx_tx = self.rx_tx.clone();
        let streams_ref = Arc::clone(&self.streams);
        let closed_ref = Arc::clone(&self.closed);
        let weak_pkt_tx = pkt_tx.downgrade();
        let reader_handle = tokio::spawn(async move {
            let mut end_err: Option<io::Error> = None;
            loop {
                let len_res = tokio::select! {
                    biased;
                    _ = rx_tx.closed() => break,
                    res = tokio::time::timeout(UDP_SESSION_IDLE_TIMEOUT, rd.read_u16()) => res,
                };
                match len_res {
                    Ok(Ok(resp_len)) => {
                        let mut resp = vec![0u8; resp_len as usize];
                        let body_res = tokio::select! {
                            biased;
                            _ = rx_tx.closed() => break,
                            res = tokio::time::timeout(
                                UDP_SESSION_IDLE_TIMEOUT,
                                rd.read_exact(&mut resp),
                            ) => res,
                        };
                        match body_res {
                            Ok(Ok(_)) => {
                                last_active_ms.store(
                                    started.elapsed().as_millis() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            Ok(Err(e)) => {
                                end_err = Some(e);
                                break;
                            }
                            Err(_) => {
                                end_err = Some(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "VLESS UDP frame read timed out",
                                ));
                                break;
                            }
                        }
                        if rx_tx.send(Ok((resp, target_clone.clone()))).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        end_err = Some(e);
                        break;
                    }
                    Err(_) => {
                        let now_ms = started.elapsed().as_millis() as u64;
                        let idle_ms = now_ms.saturating_sub(
                            last_active_ms.load(std::sync::atomic::Ordering::Relaxed),
                        );
                        if idle_ms < UDP_SESSION_IDLE_TIMEOUT.as_millis() as u64 {
                            continue;
                        }
                        end_err = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "VLESS UDP session idle timeout",
                        ));
                        break;
                    }
                }
            }
            writer_abort.abort();
            let no_live_streams = {
                let mut m = streams_ref.lock().await;
                let ended_tx = weak_pkt_tx.upgrade();
                m.retain(|k, (tx, _)| {
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

        map.insert(target.clone(), (pkt_tx, reader_handle.abort_handle()));
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
        match (self.inner.flow.is_some(), self.inner.reality.is_some()) {
            (true, true) => "VLESS+REALITY+Vision",
            (false, true) => "VLESS+REALITY",
            (true, false) => "VLESS+Vision",
            (false, false) => {
                if self.inner.pq_encryption.is_some() {
                    "VLESS+Encryption"
                } else {
                    "VLESS"
                }
            }
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
        if self.inner.flow.is_some() {
            let tls = self.inner.establish_vision_tls().await?;
            let req_hdr = self
                .inner
                .build_vless_request_header(VLESS_CMD_TCP, target)?;
            return Ok(Box::new(VisionStream::new_client(
                tls,
                self.inner.cfg.uuid,
                req_hdr,
            )));
        }
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
        if let Some(vision_flow) = self.inner.flow {
            let inner = Arc::clone(&self.inner);
            return Ok(Box::new(VlessVisionXudpSession::new(
                vision_flow,
                move || {
                    let inner = Arc::clone(&inner);
                    async move { inner.connect_vision_mux_stream().await }
                },
            )));
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
        if let Some(vision_flow) = self.inner.flow {
            if !vision_flow.allows_udp_port(target.port) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "XTLS Vision rejected UDP/443 traffic (use xtls-rprx-vision-udp443 to enable)",
                ));
            }
            return tokio::time::timeout(timeout, async {
                let sess = self.open_udp_session().await?;
                sess.send_to(payload, target).await?;
                let (resp, _src) = sess.recv_from().await?;
                Ok(resp)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS Vision XUDP timed out"))?;
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
/// (enabling true 0-RTT application data piggybacking!), flushes the header on first read for
/// server-speaks-first protocols, and strips the `[ver=0, addons_len]` VLESS response header
/// on the first read!
pub struct VlessClientStream<S> {
    inner: S,
    pending_req_hdr: BytesMut,
    hdr_flushed: bool,
    pending_write: Option<(usize, u64)>,
    read_waker: Option<std::task::Waker>,
    write_waker: Option<std::task::Waker>,
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
        let hdr_flushed = req_hdr.is_empty();
        Self {
            inner,
            pending_req_hdr: req_hdr,
            hdr_flushed,
            pending_write: None,
            read_waker: None,
            write_waker: None,
            resp_hdr_state: RespHdrState::NeedVerAndAddonsLen,
            hdr_buf: BytesMut::with_capacity(8),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.hdr_flushed {
            if this.pending_write.is_none() {
                let had_pending = !this.pending_req_hdr.is_empty();
                while !this.pending_req_hdr.is_empty() {
                    match Pin::new(&mut this.inner).poll_write(cx, &this.pending_req_hdr) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "VLESS header write(0) before read",
                            )));
                        }
                        Poll::Ready(Ok(n)) => this.pending_req_hdr.advance(n),
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                            this.pending_req_hdr.clear();
                            this.hdr_flushed = true;
                            break;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
                            return Poll::Pending;
                        }
                    }
                }
                if had_pending && let Some(w) = this.write_waker.take() {
                    w.wake();
                }
                if !this.hdr_flushed {
                    match Pin::new(&mut this.inner).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            this.hdr_flushed = true;
                        }
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                            this.hdr_flushed = true;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
                            return Poll::Pending;
                        }
                    }
                }
            } else {
                crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
            }
        }

        loop {
            match this.resp_hdr_state {
                RespHdrState::Done => {
                    if !this.hdr_buf.is_empty() {
                        let n = buf.remaining().min(this.hdr_buf.len());
                        buf.put_slice(&this.hdr_buf.split_to(n));
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }
                RespHdrState::NeedVerAndAddonsLen => {
                    if this.hdr_buf.len() >= 2 {
                        let ver = this.hdr_buf[0];
                        let addons_len = this.hdr_buf[1] as usize;
                        this.hdr_buf.advance(2);
                        if ver != 0x00 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid VLESS response version 0x{ver:02x}"),
                            )));
                        }
                        this.resp_hdr_state = if addons_len == 0 {
                            RespHdrState::Done
                        } else {
                            RespHdrState::NeedAddons(addons_len)
                        };
                        continue;
                    }
                }
                RespHdrState::NeedAddons(len) => {
                    if this.hdr_buf.len() >= len {
                        this.hdr_buf.advance(len);
                        this.resp_hdr_state = RespHdrState::Done;
                        continue;
                    }
                }
            }

            let mut tmp = [0u8; 256];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS response header truncated before EOF",
                        )));
                    }
                    this.hdr_buf.extend_from_slice(filled);
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
            if this.pending_write.is_none() {
                let take = buf.len().min(8000);
                let sig = crate::outbound::hash_write_prefix(&buf[..take]);
                this.pending_req_hdr.extend_from_slice(&buf[..take]);
                this.pending_write = Some((take, sig));
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
                    Poll::Pending => {
                        crate::outbound::save_waker_slot(&mut this.write_waker, cx.waker());
                        return Poll::Pending;
                    }
                }
            }
            if let Some(w) = this.read_waker.take() {
                w.wake();
            }
        }
        if let Some((done, sig)) = this.pending_write.take()
            && buf.len() >= done
            && crate::outbound::hash_write_prefix(&buf[..done]) == sig
        {
            return Poll::Ready(Ok(done));
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let had_pending = !this.pending_req_hdr.is_empty();
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
        if had_pending && let Some(w) = this.write_waker.take() {
            w.wake();
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.hdr_flushed = true;
                if let Some(w) = this.read_waker.take() {
                    w.wake();
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
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

/// Loopback VLESS + REALITY (+ optional `xtls-rprx-vision` & XUDP) test server configuration.
#[derive(Clone)]
pub struct VlessRealityServerConfig {
    pub listen_addr: String,
    pub allowed_uuid: Uuid,
    pub reality_private_key: [u8; 32],
    pub reality_short_id: [u8; 8],
    pub reality_server_name: String,
}

pub async fn spawn_vless_reality_vision_server(
    cfg: VlessRealityServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let bound_addr = listener.local_addr()?;

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
                    let cfg_clone = cfg.clone();
                    tokio::spawn(async move {
                        let _ = handle_vless_reality_server_conn(tcp, cfg_clone).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, handle))
}

async fn handle_vless_reality_server_conn(
    tcp: TcpStream,
    cfg: VlessRealityServerConfig,
) -> io::Result<()> {
    let mut tls = accept_reality_tls13_server(
        tcp,
        &cfg.reality_private_key,
        &cfg.reality_short_id,
        &cfg.reality_server_name,
    )
    .await?;

    let ver = tls.read_u8().await?;
    if ver != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VLESS version 0x{ver:02x}"),
        ));
    }
    let mut uuid_bytes = [0u8; 16];
    tls.read_exact(&mut uuid_bytes).await?;
    if Uuid::from_bytes(uuid_bytes) != cfg.allowed_uuid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS UUID mismatch",
        ));
    }
    let addons_len = tls.read_u8().await? as usize;
    let mut addons = vec![0u8; addons_len];
    if addons_len > 0 {
        tls.read_exact(&mut addons).await?;
    }
    let is_vision = addons == VISION_ADDONS_PROTOBUF;
    let cmd = tls.read_u8().await?;
    let target = match cmd {
        VLESS_CMD_TCP | VLESS_CMD_UDP => Some(TargetAddr::read_vless(&mut tls).await?),
        _ => None,
    };

    if is_vision {
        let vision_stream: BoxedStream =
            Box::new(VisionStream::new_server(tls, cfg.allowed_uuid, &[]));
        dispatch_vless_server_body(vision_stream, cmd, target, true).await
    } else {
        let plain_tls: BoxedStream = Box::new(tls);
        dispatch_vless_server_body(plain_tls, cmd, target, false).await
    }
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
    let target = match cmd {
        VLESS_CMD_TCP | VLESS_CMD_UDP => Some(TargetAddr::read_vless(&mut stream).await?),
        _ => None,
    };
    dispatch_vless_server_body(stream, cmd, target, false).await
}

async fn dispatch_vless_server_body(
    mut stream: BoxedStream,
    cmd: u8,
    parsed_target: Option<TargetAddr>,
    resp_hdr_coalesced_by_stream: bool,
) -> io::Result<()> {
    let direct = DirectOutbound::default();
    match cmd {
        VLESS_CMD_TCP => {
            let target = parsed_target.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing VLESS TCP target")
            })?;
            let mut outbound = direct.connect_tcp(&target).await?;
            if !resp_hdr_coalesced_by_stream {
                stream.write_all(&[0x00, 0x00]).await?;
            }
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await?;
            Ok(())
        }
        VLESS_CMD_UDP => {
            let target = parsed_target.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing VLESS UDP target")
            })?;
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
                let mut hdr_sent = resp_hdr_coalesced_by_stream;
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
                let mut hdr_sent = resp_hdr_coalesced_by_stream;
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

#[cfg(test)]
mod tests {
    use super::*;

    struct ThrottledStream<S> {
        inner: S,
        max_write: usize,
        yield_next_write: bool,
        yield_next_flush: bool,
    }

    impl<S> ThrottledStream<S> {
        fn new(inner: S, max_write: usize) -> Self {
            Self {
                inner,
                max_write: max_write.max(1),
                yield_next_write: false,
                yield_next_flush: true,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ThrottledStream<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ThrottledStream<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.yield_next_write {
                this.yield_next_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_next_write = true;
            let cap = buf.len().min(this.max_write);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..cap])
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.yield_next_flush {
                this.yield_next_flush = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_next_flush = true;
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    fn sample_vless_header() -> BytesMut {
        let mut hdr = BytesMut::with_capacity(64);
        hdr.put_u8(0x00);
        hdr.put_slice(Uuid::from_u128(0x11223344_5566_7788_99aa_bbccddeeff00).as_bytes());
        hdr.put_u8(0x00);
        hdr.put_u8(VLESS_CMD_TCP);
        TargetAddr::new_domain("imap.example.com", 143)
            .expect("target")
            .encode_vless(&mut hdr)
            .expect("encode_vless");
        hdr
    }

    fn poll_write_once<W: AsyncWrite + Unpin>(
        writer: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        Pin::new(writer).poll_write(&mut cx, data)
    }

    #[tokio::test]
    async fn vless_stream_flushes_header_on_read_for_server_speaks_first() {
        let req_hdr = sample_vless_header();
        let expected_hdr = req_hdr.to_vec();
        let (c_io, mut s_io) = tokio::io::duplex(256);
        let mut client = VlessClientStream::new(ThrottledStream::new(c_io, 3), req_hdr);

        let srv_task = tokio::spawn(async move {
            let mut got_hdr = vec![0u8; expected_hdr.len()];
            s_io.read_exact(&mut got_hdr)
                .await
                .expect("server read vless hdr");
            assert_eq!(got_hdr, expected_hdr);
            // Send VLESS v0 response header `[0x00, 0x00]` + server-first greeting
            s_io.write_all(b"\x00\x00* OK IMAP4rev1 Service Ready\r\n")
                .await
                .expect("server write greeting");
            let mut cmd = [0u8; 16];
            s_io.read_exact(&mut cmd).await.expect("server read cmd");
            assert_eq!(&cmd, b"A001 CAPABILITY\n");
        });

        let mut banner = [0u8; 30];
        client
            .read_exact(&mut banner)
            .await
            .expect("client read banner before any write");
        assert_eq!(&banner, b"* OK IMAP4rev1 Service Ready\r\n");
        client
            .write_all(b"A001 CAPABILITY\n")
            .await
            .expect("client write after greeting");
        client.flush().await.expect("client flush");
        srv_task.await.expect("srv join");
    }

    #[tokio::test]
    async fn vless_stream_no_duplication_on_interleaved_pending_write_read_and_flush() {
        // Part A: `poll_write` returns `Pending`, then `flush()` drains `pending_req_hdr`,
        // then retrying the same `write_all(payload)` must NOT duplicate `payload`.
        let req_hdr = sample_vless_header();
        let expected_hdr = req_hdr.to_vec();
        let payload: Vec<u8> = (0..512).map(|i| (i * 5 + 11) as u8).collect();
        let (c_io, mut s_io) = tokio::io::duplex(4096);
        let mut client = VlessClientStream::new(ThrottledStream::new(c_io, 2), req_hdr);

        assert!(matches!(
            poll_write_once(&mut client, &payload),
            Poll::Pending
        ));
        client.flush().await.expect("interleaved flush");
        client
            .write_all(&payload)
            .await
            .expect("retried write_all after flush");
        client.shutdown().await.expect("shutdown");

        let mut wire = Vec::new();
        s_io.read_to_end(&mut wire).await.expect("read wire");
        let mut expected_wire = expected_hdr.clone();
        expected_wire.extend_from_slice(&payload);
        assert_eq!(wire, expected_wire, "VLESS payload must not be duplicated");

        // Part B: `copy_bidirectional` over 1-byte throttled stream (interleaving `poll_write` + `poll_read`).
        let req_hdr2 = sample_vless_header();
        let expected_hdr2 = req_hdr2.to_vec();
        let expected_hdr2_len = expected_hdr2.len();
        let (c_io2, mut s_io2) = tokio::io::duplex(128);
        let mut vless_client = VlessClientStream::new(ThrottledStream::new(c_io2, 1), req_hdr2);
        let (mut app_side, mut proxy_in) = tokio::io::duplex(256);

        let client_data: Vec<u8> = (0..2048).map(|i| (i ^ 0xA5) as u8).collect();
        let server_data: Vec<u8> = (0..1536).map(|i| (i * 17 + 9) as u8).collect();
        let server_data_expect = server_data.clone();

        let relay_task = tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut proxy_in, &mut vless_client)
                .await
                .expect("copy_bidirectional")
        });

        let srv_task = tokio::spawn(async move {
            let mut hdr_buf = vec![0u8; expected_hdr2_len];
            s_io2.read_exact(&mut hdr_buf).await.expect("srv hdr");
            assert_eq!(hdr_buf, expected_hdr2);
            let (mut srd, mut swr) = tokio::io::split(s_io2);
            let writer = async move {
                swr.write_all(&[0x00, 0x00])
                    .await
                    .expect("srv vless resp hdr");
                swr.write_all(&server_data).await.expect("srv write");
                swr.shutdown().await.expect("srv shutdown");
            };
            let reader = async move {
                let mut got = Vec::new();
                srd.read_to_end(&mut got).await.expect("srv read_to_end");
                got
            };
            let (_, got_client) = tokio::join!(writer, reader);
            got_client
        });

        let client_data_send = client_data.clone();
        let (mut ard, mut awr) = tokio::io::split(&mut app_side);
        let app_writer = async move {
            awr.write_all(&client_data_send).await.expect("app write");
            awr.shutdown().await.expect("app shutdown");
        };
        let app_reader = async move {
            let mut got = Vec::new();
            ard.read_to_end(&mut got).await.expect("app read");
            got
        };
        let (_, got_server) = tokio::join!(app_writer, app_reader);
        let got_client = srv_task.await.expect("srv join");
        let _ = relay_task.await.expect("relay join");

        assert_eq!(got_client, client_data);
        assert_eq!(got_server, server_data_expect);
    }

    #[tokio::test]
    async fn vless_stream_cancelled_large_write_then_small_write_does_not_panic() {
        let req_hdr = sample_vless_header();
        let expected_hdr = req_hdr.to_vec();
        let (c_io, mut s_io) = tokio::io::duplex(8192);
        let mut client = VlessClientStream::new(ThrottledStream::new(c_io, 4), req_hdr);

        let large_buf = vec![0xCCu8; 1024];
        let small_buf = vec![0xDDu8; 9];
        assert!(matches!(
            poll_write_once(&mut client, &large_buf),
            Poll::Pending
        ));

        client
            .write_all(&small_buf)
            .await
            .expect("cancelled large write followed by small write must not panic");
        client.shutdown().await.expect("shutdown");

        let mut wire = Vec::new();
        s_io.read_to_end(&mut wire).await.expect("read wire");
        let mut expected = expected_hdr;
        expected.extend_from_slice(&large_buf);
        expected.extend_from_slice(&small_buf);
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn vless_stream_returns_unexpected_eof_when_response_header_truncated() {
        let req_hdr = sample_vless_header();
        let (c_io, mut s_io) = tokio::io::duplex(256);
        let mut client = VlessClientStream::new(c_io, req_hdr);
        // Server closes immediately after sending only 1 byte of the 2-byte VLESS response header
        s_io.write_all(&[0x00]).await.expect("write 1 byte");
        drop(s_io);

        let mut buf = [0u8; 16];
        let err = client
            .read(&mut buf)
            .await
            .expect_err("truncated VLESS response header must return UnexpectedEof");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
