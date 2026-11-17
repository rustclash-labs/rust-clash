pub mod crypto;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
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
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession, hash_write_prefix,
        vmess::crypto::{
            VMESS_CMD_MUX, VMESS_CMD_TCP, VMESS_CMD_UDP, VMESS_MAX_CHUNK_PLAIN, VmessChunkCodec,
            VmessRequestHeader, VmessSecurity, derive_cmd_key, derive_response_key_and_iv,
            read_vmess_aead_request_header, seal_vmess_aead_request_header,
            seal_vmess_aead_response_header, try_open_vmess_aead_response_header,
        },
        ws_stream::{WsTransportConfig, accept_ws_stream, connect_ws_stream},
    },
    platform::socket_protect::protected_tcp_connect_host_with_dns,
};

#[derive(Clone)]
pub struct VmessOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub security: VmessSecurity,
    pub global_padding: bool,
    pub tls: bool,
    pub servername: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub udp: bool,
}

struct VmessInner {
    cfg: VmessOutboundConfig,
    cmd_key: [u8; 16],
    ws_opts: Option<WsTransportConfig>,
    tls_connector: Option<TlsConnector>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct VmessOutbound {
    inner: Arc<VmessInner>,
}

impl VmessInner {
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
            let tls = crate::outbound::with_handshake_timeout(
                "VMess TLS handshake",
                connector.connect(sni, tcp),
            )
            .await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        if let Some(ws_cfg) = &self.ws_opts {
            crate::outbound::with_handshake_timeout(
                "VMess WebSocket handshake",
                connect_ws_stream(tls_or_tcp, sni_str, self.cfg.port, self.cfg.tls, ws_cfg),
            )
            .await
        } else {
            Ok(tls_or_tcp)
        }
    }

    fn open_client_stream(
        &self,
        transport: BoxedStream,
        command: u8,
        target: TargetAddr,
    ) -> io::Result<VmessClientStream<BoxedStream>> {
        let req_hdr = VmessRequestHeader::new_random(
            self.cfg.security,
            self.cfg.global_padding,
            command,
            target,
        );
        let wire_hdr = seal_vmess_aead_request_header(&self.cmd_key, &req_hdr)?;
        VmessClientStream::new(transport, wire_hdr, &req_hdr)
    }
}

impl VmessOutbound {
    pub fn new(cfg: VmessOutboundConfig) -> io::Result<Self> {
        Self::new_with_transport(cfg, None, None)
    }

    pub fn new_with_transport(
        cfg: VmessOutboundConfig,
        ws_opts: Option<WsTransportConfig>,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let cmd_key = derive_cmd_key(&cfg.uuid);
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
            inner: Arc::new(VmessInner {
                cfg,
                cmd_key,
                ws_opts,
                tls_connector,
                dns,
            }),
        })
    }
}

/// Client TCP stream wrapper implementing 0-RTT request header + first chunk coalescing,
/// streaming response AEAD verification, and chunk encryption/decryption.
pub struct VmessClientStream<S> {
    inner: S,
    write_buf: BytesMut,
    hdr_queued: bool,
    pending_write: Option<(usize, u64)>,
    eof_sent: bool,
    writer_codec: VmessChunkCodec,

    resp_verified: bool,
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    expected_resp_v: u8,
    read_wire_buf: BytesMut,
    read_plain_buf: BytesMut,
    read_eof: bool,
    reader_codec: VmessChunkCodec,
}

impl<S> VmessClientStream<S> {
    pub fn new(
        inner: S,
        sealed_req_hdr: BytesMut,
        req_hdr: &VmessRequestHeader,
    ) -> io::Result<Self> {
        let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
        let writer_codec = VmessChunkCodec::new(
            &req_hdr.req_key,
            &req_hdr.req_iv,
            req_hdr.security,
            req_hdr.option,
        )?;
        let reader_codec =
            VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)?;
        Ok(Self {
            inner,
            write_buf: sealed_req_hdr,
            hdr_queued: true,
            pending_write: None,
            eof_sent: false,
            writer_codec,
            resp_verified: false,
            resp_key,
            resp_iv,
            expected_resp_v: req_hdr.resp_v,
            read_wire_buf: BytesMut::with_capacity(16 * 1024),
            read_plain_buf: BytesMut::with_capacity(16 * 1024),
            read_eof: false,
            reader_codec,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessClientStream<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "VMess transport closed while writing",
                )));
            }
            self.write_buf.advance(n);
        }
        self.hdr_queued = false;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Ensure request header is flushed for server-speaks-first protocols (e.g. SSH, SMTP).
        if self.hdr_queued {
            ready!(self.poll_drain_write_buf(cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }

        loop {
            if !self.read_plain_buf.is_empty() {
                let to_copy = self.read_plain_buf.len().min(buf.remaining());
                let chunk = self.read_plain_buf.split_to(to_copy);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }

            if !self.resp_verified {
                let resp_key = self.resp_key;
                let resp_iv = self.resp_iv;
                let expected_v = self.expected_resp_v;
                if let Some(used) = try_open_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    expected_v,
                    &self.read_wire_buf,
                )? {
                    let _ = self.read_wire_buf.split_to(used);
                    self.resp_verified = true;
                    continue;
                }
            } else {
                let this = &mut *self;
                if let Some(decoded) = this
                    .reader_codec
                    .try_decode_chunk(&mut this.read_wire_buf)?
                {
                    match decoded {
                        Some(plain) => {
                            this.read_plain_buf.extend_from_slice(&plain);
                        }
                        None => {
                            this.read_eof = true;
                        }
                    }
                    continue;
                }
            }

            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled();
            if filled.is_empty() {
                if !self.resp_verified && !self.read_wire_buf.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VMess AEAD response header",
                    )));
                }
                self.read_eof = true;
                return Poll::Ready(Ok(()));
            }
            self.read_wire_buf.extend_from_slice(filled);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some((orig_len, orig_hash)) = self.pending_write {
            let check_len = orig_len.min(data.len());
            if data.len() < orig_len || hash_write_prefix(&data[..check_len]) != orig_hash {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VMess poll_write retried with mismatched buffer",
                )));
            }
            ready!(self.poll_drain_write_buf(cx))?;
            self.pending_write = None;
            return Poll::Ready(Ok(orig_len));
        }

        // Drain any non-header residual ciphertext before queueing a fresh chunk.
        if !self.hdr_queued && !self.write_buf.is_empty() {
            ready!(self.poll_drain_write_buf(cx))?;
        }

        let accept_len = data.len().min(VMESS_MAX_CHUNK_PLAIN);
        let prefix_hash = hash_write_prefix(&data[..accept_len]);
        {
            let this = &mut *self;
            this.writer_codec
                .encode_chunk(&data[..accept_len], &mut this.write_buf)?;
        }
        self.pending_write = Some((accept_len, prefix_hash));

        match self.poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write = None;
                Poll::Ready(Ok(accept_len))
            }
            Poll::Ready(Err(e)) => {
                self.pending_write = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain_write_buf(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.eof_sent {
            let this = &mut *self;
            this.writer_codec.encode_eof_chunk(&mut this.write_buf)?;
            self.eof_sent = true;
        }
        ready!(self.poll_drain_write_buf(cx))?;
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type UdpRecvItem = io::Result<(Vec<u8>, TargetAddr)>;
type VmessUdpEntry = (mpsc::Sender<Vec<u8>>, tokio::task::AbortHandle);

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Stateful VMess UDP session (`VMESS_CMD_UDP = 0x02`), where each VMess chunk carries one UDP datagram.
struct VmessUdpSession {
    inner: Arc<VmessInner>,
    streams: Arc<AsyncMutex<HashMap<TargetAddr, VmessUdpEntry>>>,
    rx_tx: mpsc::Sender<UdpRecvItem>,
    rx: AsyncMutex<mpsc::Receiver<UdpRecvItem>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl VmessUdpSession {
    fn new(inner: Arc<VmessInner>) -> Self {
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

async fn read_one_vmess_udp_datagram<R: AsyncRead + Unpin>(
    reader: &mut R,
    resp_verified: &mut bool,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    expected_resp_v: u8,
    codec: &mut VmessChunkCodec,
    wire_buf: &mut BytesMut,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        if !*resp_verified {
            if let Some(used) =
                try_open_vmess_aead_response_header(resp_key, resp_iv, expected_resp_v, wire_buf)?
            {
                let _ = wire_buf.split_to(used);
                *resp_verified = true;
                continue;
            }
        } else if let Some(decoded) = codec.try_decode_chunk(wire_buf)? {
            return Ok(decoded);
        }

        let mut tmp = [0u8; 16 * 1024];
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        wire_buf.extend_from_slice(&tmp[..n]);
    }
}

#[async_trait]
impl OutboundUdpSession for VmessUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > VMESS_MAX_CHUNK_PLAIN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VMess UDP datagram exceeds {VMESS_MAX_CHUNK_PLAIN} bytes"),
            ));
        }

        let existing = {
            let mut map = self.streams.lock().await;
            map.retain(|_, (tx, _)| !tx.is_closed());
            map.get(target).map(|(tx, _)| tx.clone())
        };
        if let Some(tx) = existing
            && tx.send(payload.to_vec()).await.is_ok()
        {
            return Ok(());
        }

        let transport = self.inner.establish_transport().await?;
        let req_hdr = VmessRequestHeader::new_random(
            self.inner.cfg.security,
            self.inner.cfg.global_padding,
            VMESS_CMD_UDP,
            target.clone(),
        );
        let wire_hdr = seal_vmess_aead_request_header(&self.inner.cmd_key, &req_hdr)?;
        let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
        let mut wr_codec = VmessChunkCodec::new(
            &req_hdr.req_key,
            &req_hdr.req_iv,
            req_hdr.security,
            req_hdr.option,
        )?;
        let mut rd_codec =
            VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)?;
        let expected_resp_v = req_hdr.resp_v;

        let mut map = self.streams.lock().await;
        map.retain(|_, (tx, _)| !tx.is_closed());
        if let Some((tx, _)) = map.get(target) {
            if tx.send(payload.to_vec()).await.is_ok() {
                return Ok(());
            }
            if let Some((_, abort)) = map.remove(target) {
                abort.abort();
            }
        }
        if map.len() >= 16
            && let Some(evict_key) = map.keys().next().cloned()
            && let Some((_, abort)) = map.remove(&evict_key)
        {
            abort.abort();
        }

        let (mut rd, mut wr) = tokio::io::split(transport);
        self.closed
            .store(false, std::sync::atomic::Ordering::SeqCst);

        let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(64);
        pkt_tx
            .send(payload.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VMess UDP queue closed"))?;

        let writer_handle = tokio::spawn(async move {
            let mut first = Some(wire_hdr);
            while let Some(dgram) = pkt_rx.recv().await {
                let mut out = first
                    .take()
                    .unwrap_or_else(|| BytesMut::with_capacity(dgram.len() + 32));
                if wr_codec.encode_chunk(&dgram, &mut out).is_err() {
                    break;
                }
                if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let mut eof = BytesMut::new();
            if wr_codec.encode_eof_chunk(&mut eof).is_ok() && !eof.is_empty() {
                let _ = wr.write_all(&eof).await;
                let _ = wr.flush().await;
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
            let mut resp_verified = false;
            let mut wire_buf = BytesMut::with_capacity(16 * 1024);
            let mut end_err: Option<io::Error> = None;
            loop {
                let res = tokio::select! {
                    biased;
                    _ = rx_tx.closed() => break,
                    r = tokio::time::timeout(
                        UDP_SESSION_IDLE_TIMEOUT,
                        read_one_vmess_udp_datagram(
                            &mut rd,
                            &mut resp_verified,
                            &resp_key,
                            &resp_iv,
                            expected_resp_v,
                            &mut rd_codec,
                            &mut wire_buf,
                        ),
                    ) => r,
                };
                match res {
                    Ok(Ok(Some(dgram))) => {
                        if rx_tx.send(Ok((dgram, target_clone.clone()))).await.is_err() {
                            break;
                        }
                    }
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        end_err = Some(e);
                        break;
                    }
                    Err(_) => {
                        end_err = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "VMess UDP session idle timeout",
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
                let _ = rx_tx.try_send(Err(err));
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
                "VMess UDP stream closed",
            ));
        }
        rx.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VMess UDP session closed",
            ))
        })
    }
}

#[async_trait]
impl OutboundHandler for VmessOutbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "VMess"
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
        let stream = self
            .inner
            .open_client_stream(transport, VMESS_CMD_TCP, target.clone())?;
        Ok(Box::new(stream))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.inner.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this VMess outbound",
            ));
        }
        Ok(Box::new(VmessUdpSession::new(Arc::clone(&self.inner))))
    }
}

pub struct VmessServerHandle {
    pub listen_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl VmessServerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

/// Spawn a pure-Rust VMess AEAD server (for self-contained unit & E2E verification).
pub async fn spawn_vmess_server(
    bind_addr: SocketAddr,
    allowed_uuid: Uuid,
    tls_config: Option<Arc<ServerConfig>>,
    ws_path: Option<String>,
) -> io::Result<VmessServerHandle> {
    let listener = TcpListener::bind(bind_addr).await?;
    let listen_addr = listener.local_addr()?;
    let cmd_key = derive_cmd_key(&allowed_uuid);
    let tls_acceptor = tls_config.map(TlsAcceptor::from);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let _ = tcp.set_nodelay(true);
                    let acceptor = tls_acceptor.clone();
                    let ws_path = ws_path.clone();
                    tokio::spawn(async move {
                        let _ = handle_vmess_server_conn(tcp, cmd_key, acceptor, ws_path.as_deref()).await;
                    });
                }
            }
        }
    });

    Ok(VmessServerHandle {
        listen_addr,
        shutdown_tx,
        join_handle,
    })
}

async fn handle_vmess_server_conn(
    tcp: TcpStream,
    cmd_key: [u8; 16],
    tls_acceptor: Option<TlsAcceptor>,
    ws_path: Option<&str>,
) -> io::Result<()> {
    let base: BoxedStream = if let Some(acceptor) = tls_acceptor {
        Box::new(acceptor.accept(tcp).await?)
    } else {
        Box::new(tcp)
    };
    let mut transport: BoxedStream = if let Some(expected_path) = ws_path {
        accept_ws_stream(base, Some(expected_path)).await?
    } else {
        base
    };

    let req = read_vmess_aead_request_header(&cmd_key, &mut transport).await?;
    let (resp_key, resp_iv) = derive_response_key_and_iv(&req.req_key, &req.req_iv);
    let resp_hdr = seal_vmess_aead_response_header(&resp_key, &resp_iv, req.resp_v, req.option)?;
    let mut rd_codec = VmessChunkCodec::new(&req.req_key, &req.req_iv, req.security, req.option)?;
    let mut wr_codec = VmessChunkCodec::new(&resp_key, &resp_iv, req.security, req.option)?;

    let direct = DirectOutbound::default();
    match req.command {
        VMESS_CMD_TCP => {
            let mut target_stream = direct.connect_tcp(&req.target).await?;
            let (mut c_rd, mut c_wr) = tokio::io::split(transport);
            let (mut t_rd, mut t_wr) = tokio::io::split(&mut target_stream);

            let c2t = async {
                let mut wire_buf = BytesMut::with_capacity(16 * 1024);
                let mut tmp = [0u8; 16 * 1024];
                loop {
                    while let Some(decoded) = rd_codec.try_decode_chunk(&mut wire_buf)? {
                        match decoded {
                            Some(plain) => {
                                t_wr.write_all(&plain).await?;
                            }
                            None => {
                                t_wr.flush().await?;
                                let _ = t_wr.shutdown().await;
                                return Ok::<(), io::Error>(());
                            }
                        }
                    }
                    t_wr.flush().await?;
                    let n = c_rd.read(&mut tmp).await?;
                    if n == 0 {
                        let _ = t_wr.shutdown().await;
                        return Ok(());
                    }
                    wire_buf.extend_from_slice(&tmp[..n]);
                }
            };

            let t2c = async {
                let mut first_resp = Some(resp_hdr);
                let mut tmp = [0u8; VMESS_MAX_CHUNK_PLAIN];
                loop {
                    let n = t_rd.read(&mut tmp).await?;
                    let mut out = first_resp.take().unwrap_or_default();
                    if n == 0 {
                        wr_codec.encode_eof_chunk(&mut out)?;
                        if !out.is_empty() {
                            c_wr.write_all(&out).await?;
                            c_wr.flush().await?;
                        }
                        let _ = c_wr.shutdown().await;
                        return Ok::<(), io::Error>(());
                    }
                    wr_codec.encode_chunk(&tmp[..n], &mut out)?;
                    c_wr.write_all(&out).await?;
                    c_wr.flush().await?;
                }
            };

            let _ = tokio::try_join!(c2t, t2c);
            Ok(())
        }
        VMESS_CMD_UDP => {
            let udp_sess = direct.open_udp_session().await?;
            let target = req.target;
            let (mut c_rd, mut c_wr) = tokio::io::split(transport);

            let c2u = async {
                let mut wire_buf = BytesMut::with_capacity(16 * 1024);
                let mut tmp = [0u8; 16 * 1024];
                loop {
                    while let Some(decoded) = rd_codec.try_decode_chunk(&mut wire_buf)? {
                        match decoded {
                            Some(dgram) => {
                                udp_sess.send_to(&dgram, &target).await?;
                            }
                            None => return Ok::<(), io::Error>(()),
                        }
                    }
                    let n = c_rd.read(&mut tmp).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    wire_buf.extend_from_slice(&tmp[..n]);
                }
            };

            let u2c = async {
                let mut first_resp = Some(resp_hdr);
                loop {
                    let (resp_dgram, _) = udp_sess.recv_from().await?;
                    let mut out = first_resp.take().unwrap_or_default();
                    wr_codec.encode_chunk(&resp_dgram, &mut out)?;
                    c_wr.write_all(&out).await?;
                    c_wr.flush().await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };

            tokio::select! {
                r = c2u => r,
                r = u2c => r,
            }
        }
        VMESS_CMD_MUX => {
            // Xray / sing-box XUDP (`RequestCommandMux = 0x03`) over VMess chunks
            let (mut c_rd, mut c_wr) = tokio::io::split(transport);
            let (resp_tx, mut resp_rx) = mpsc::channel::<(u16, TargetAddr, Vec<u8>)>(128);

            let u2c = async move {
                let mut first_resp = Some(resp_hdr);
                while let Some((session_id, src_addr, resp)) = resp_rx.recv().await {
                    let mut resp_meta = BytesMut::with_capacity(32);
                    resp_meta.put_u16(session_id);
                    resp_meta.put_u8(0x02); // SessionStatusKeep
                    resp_meta.put_u8(0x01); // OptionData
                    resp_meta.put_u8(0x02); // Network_UDP
                    if src_addr.encode_vless(&mut resp_meta).is_err() {
                        continue;
                    }
                    let mut xudp_pkt = BytesMut::with_capacity(4 + resp_meta.len() + resp.len());
                    xudp_pkt.put_u16(resp_meta.len() as u16);
                    xudp_pkt.put_slice(&resp_meta);
                    xudp_pkt.put_u16(resp.len() as u16);
                    xudp_pkt.put_slice(&resp);

                    let mut out = first_resp.take().unwrap_or_default();
                    for slice in xudp_pkt.chunks(VMESS_MAX_CHUNK_PLAIN) {
                        wr_codec.encode_chunk(slice, &mut out)?;
                    }
                    c_wr.write_all(&out).await?;
                    c_wr.flush().await?;
                }
                Ok::<(), io::Error>(())
            };

            let c2u = async move {
                let mut sessions: HashMap<u16, (TargetAddr, Arc<Box<dyn OutboundUdpSession>>)> =
                    HashMap::new();
                let mut wire_buf = BytesMut::with_capacity(16 * 1024);
                let mut plain_buf = BytesMut::with_capacity(16 * 1024);
                let mut tmp = [0u8; 16 * 1024];

                loop {
                    while let Some(decoded) = rd_codec.try_decode_chunk(&mut wire_buf)? {
                        match decoded {
                            Some(chunk) => plain_buf.extend_from_slice(&chunk),
                            None => return Ok::<(), io::Error>(()),
                        }
                    }

                    loop {
                        if plain_buf.len() < 2 {
                            break;
                        }
                        let meta_len = u16::from_be_bytes([plain_buf[0], plain_buf[1]]) as usize;
                        if meta_len < 4 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XUDP metadata header shorter than 4 bytes",
                            ));
                        }
                        if plain_buf.len() < 2 + meta_len {
                            break;
                        }
                        let option = plain_buf[2 + 3];
                        let payload_len = if (option & 0x01) != 0 {
                            if plain_buf.len() < 2 + meta_len + 2 {
                                break;
                            }
                            let dlen = u16::from_be_bytes([
                                plain_buf[2 + meta_len],
                                plain_buf[2 + meta_len + 1],
                            ]) as usize;
                            if plain_buf.len() < 2 + meta_len + 2 + dlen {
                                break;
                            }
                            Some(dlen)
                        } else {
                            None
                        };

                        plain_buf.advance(2);
                        let meta = plain_buf.split_to(meta_len);
                        let payload = payload_len.map(|dlen| {
                            plain_buf.advance(2);
                            plain_buf.split_to(dlen).to_vec()
                        });

                        let session_id = u16::from_be_bytes([meta[0], meta[1]]);
                        let status = meta[2];
                        if status == 0x04 {
                            // SessionStatusKeepAlive
                            continue;
                        }
                        if status == 0x03 {
                            sessions.remove(&session_id);
                            continue;
                        }

                        let mut pkt_target = None;
                        if (status == 0x01 || status == 0x02) && meta.len() > 5 && meta[4] == 0x02 {
                            let mut cursor = io::Cursor::new(&meta[5..]);
                            if let Ok(parsed) = TargetAddr::read_vless(&mut cursor).await {
                                pkt_target = Some(parsed);
                            }
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
                        if let (Some((default_t, up_sess)), Some(dgram)) = (resolved_entry, payload)
                        {
                            let dst = pkt_target.unwrap_or(default_t);
                            let _ = up_sess.send_to(&dgram, &dst).await;
                        }
                    }

                    let n = c_rd.read(&mut tmp).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    wire_buf.extend_from_slice(&tmp[..n]);
                }
            };

            tokio::select! {
                r = c2u => r,
                r = u2c => r,
            }
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported VMess command 0x{other:02x}"),
        )),
    }
}
