pub mod crypto;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
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

/// Waker fanout coordinating split-stream `poll_read` header/opportunistic TX draining with
/// concurrent `poll_write` / `poll_flush` / `poll_shutdown`:
/// - slot `0` (`read_tx`): reader waiting on `self.inner` TX write-readiness (woken by
///   `wake_by_ref` and writer completion).
/// - slot `1` (`write_tx`): writer waiting on `self.inner` TX write-readiness (woken by
///   `wake_by_ref` and reader drain/flush completion).
/// - slot `2` (`parked_read`): reader currently parked in `VmessClientStream::poll_read`
///   (`Poll::Pending`); NOT woken by `wake_by_ref` (avoiding spurious wakeups during streaming
///   uploads), ONLY woken when a writer returns `Poll::Ready` leaving pending TX work or an error,
///   or once when `poll_shutdown` newly queues outbound TX bytes (e.g., the authenticated EOF
///   chunk) and parks `Poll::Pending`.
#[derive(Default)]
struct FanoutWaker {
    wakers: parking_lot::Mutex<(Option<Waker>, Option<Waker>, Option<Waker>)>,
}

impl FanoutWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn set_slot(slot: &mut Option<Waker>, waker: &Waker) {
        match slot {
            Some(existing) if existing.will_wake(waker) => {}
            slot => *slot = Some(waker.clone()),
        }
    }

    fn register_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.0, waker);
    }

    fn register_parked_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.2, waker);
    }

    fn register_write(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.1, waker);
    }

    /// Atomically check if another task (`!w.will_wake(waker)`) holds the write-readiness slot
    /// and, if so, register `waker` in the read TX slot inside the same lock acquisition.
    /// Eliminates both missing-registration deadlocks and multi-thread check-then-register
    /// lost-wakeup races with [`FanoutWaker::wake_by_ref`].
    fn register_read_if_other_writer(&self, waker: &Waker) -> bool {
        let mut guard = self.wakers.lock();
        if guard.1.as_ref().is_some_and(|w| !w.will_wake(waker)) {
            Self::set_slot(&mut guard.0, waker);
            true
        } else {
            false
        }
    }

    fn clear_read_tx(&self) {
        self.wakers.lock().0 = None;
    }

    fn clear_read(&self) {
        let mut guard = self.wakers.lock();
        guard.0 = None;
        guard.2 = None;
    }

    fn clear_write_and_wake_read(&self) {
        let (w_tx, w_parked) = {
            let mut guard = self.wakers.lock();
            guard.1 = None;
            (guard.0.take(), guard.2.take())
        };
        match (w_tx, w_parked) {
            (Some(a), Some(b)) if a.will_wake(&b) => a.wake(),
            (w_tx, w_parked) => {
                if let Some(w) = w_tx {
                    w.wake();
                }
                if let Some(w) = w_parked {
                    w.wake();
                }
            }
        }
    }

    fn clear_write_and_wake_read_tx(&self) {
        let w = {
            let mut guard = self.wakers.lock();
            guard.1 = None;
            guard.0.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    fn wake_read_tx(&self) {
        let w = self.wakers.lock().0.take();
        if let Some(w) = w {
            w.wake();
        }
    }

    fn wake_write(&self) {
        let w = self.wakers.lock().1.take();
        if let Some(w) = w {
            w.wake();
        }
    }

    /// Wake only `parked_read` (`guard.2`) outside the mutex lock while preserving
    /// `read_tx` (`guard.0`) and `write_tx` (`guard.1`). Used as a one-shot wakeup when
    /// `poll_shutdown` newly queues outbound TX bytes and returns `Poll::Pending`, so a
    /// pre-parked split reader wakes once and arms `read_tx` via `register_read_if_other_writer`
    /// (or drains the queued EOF chunk directly if the writer was already cancelled).
    fn wake_parked_read(&self) {
        let w = {
            let mut guard = self.wakers.lock();
            guard.2.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    #[cfg(test)]
    fn has_write_waker(&self) -> bool {
        self.wakers.lock().1.is_some()
    }
}

impl std::task::Wake for FanoutWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (w_rd, w_wr) = {
            let mut guard = self.wakers.lock();
            (guard.0.take(), guard.1.take())
        };
        match (w_rd, w_wr) {
            (Some(r), Some(w)) if r.will_wake(&w) => r.wake(),
            (w_rd, w_wr) => {
                if let Some(w) = w_wr {
                    w.wake();
                }
                if let Some(w) = w_rd {
                    w.wake();
                }
            }
        }
    }
}

/// Client TCP stream wrapper implementing 0-RTT request header + first chunk coalescing,
/// streaming response AEAD verification, and chunk encryption/decryption.
pub struct VmessClientStream<S> {
    inner: S,
    write_buf: BytesMut,
    hdr_remaining: usize,
    hdr_coalesce_pending: bool,
    hdr_flushed: bool,
    inner_needs_flush: bool,
    uplink_broken_after_resp: bool,
    eof_sent: bool,
    tx_fanout: Arc<FanoutWaker>,
    tx_fanout_waker: Waker,
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
        let hdr_remaining = sealed_req_hdr.len();
        let tx_fanout = FanoutWaker::new();
        let tx_fanout_waker = Waker::from(Arc::clone(&tx_fanout));
        Ok(Self {
            inner,
            write_buf: sealed_req_hdr,
            hdr_remaining,
            hdr_coalesce_pending: hdr_remaining > 0,
            hdr_flushed: false,
            inner_needs_flush: false,
            uplink_broken_after_resp: false,
            eof_sent: false,
            tx_fanout,
            tx_fanout_waker,
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
    fn poll_drain_write_buf_with_fanout(&mut self) -> Poll<io::Result<()>> {
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(&mut fanout_cx, &self.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess transport closed while writing",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_buf.advance(n);
                    self.inner_needs_flush = true;
                    self.uplink_broken_after_resp = false;
                    self.hdr_remaining = self.hdr_remaining.saturating_sub(n);
                }
            }
        }
        self.hdr_coalesce_pending = false;
        Poll::Ready(Ok(()))
    }

    fn poll_drain_write_buf_from_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            self.hdr_coalesce_pending = false;
            return Poll::Ready(Ok(()));
        }
        let had_hdr = self.hdr_remaining > 0;
        self.tx_fanout.register_write(cx.waker());
        let res = self.poll_drain_write_buf_with_fanout();
        if res.is_pending() && had_hdr && self.hdr_remaining == 0 {
            self.tx_fanout.wake_read_tx();
        }
        res
    }

    /// Ensure the VMess request header has been written to `self.inner` AND `inner.poll_flush`
    /// has returned `Poll::Ready(Ok(()))`. Routes all `self.inner` TX operations through the
    /// persistent `self.tx_fanout_waker` so any concurrent writer waiting on `self.tx_fanout`
    /// is never overwritten when `VmessClientStream` is split.
    fn poll_ensure_hdr_flushed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.hdr_flushed {
            return Poll::Ready(Ok(()));
        }

        self.tx_fanout.register_read(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);

        let mut made_write_progress = false;
        while self.hdr_remaining > 0 {
            match Pin::new(&mut self.inner).poll_write(&mut fanout_cx, &self.write_buf) {
                Poll::Pending => {
                    if made_write_progress {
                        self.tx_fanout.wake_write();
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(0)) => {
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess transport closed while writing request header",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_buf.advance(n);
                    self.hdr_remaining = self.hdr_remaining.saturating_sub(n);
                    self.inner_needs_flush = true;
                    made_write_progress = true;
                    if self.write_buf.is_empty() {
                        self.hdr_coalesce_pending = false;
                    }
                }
            }
        }

        match Pin::new(&mut self.inner).poll_flush(&mut fanout_cx) {
            Poll::Pending => {
                if made_write_progress {
                    self.tx_fanout.wake_write();
                }
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                self.hdr_flushed = true;
                self.inner_needs_flush = false;
                self.uplink_broken_after_resp = false;
                self.hdr_coalesce_pending = false;
                self.tx_fanout.clear_read_tx();
                self.tx_fanout.wake_write();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.tx_fanout.clear_read_tx();
                self.tx_fanout.wake_write();
                Poll::Ready(Err(e))
            }
        }
    }

    fn poll_opportunistic_drain_from_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx_fanout.register_read(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);

        let mut made_write_progress = false;
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(&mut fanout_cx, &self.write_buf) {
                Poll::Pending => {
                    if made_write_progress {
                        self.tx_fanout.wake_write();
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(0)) => {
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess transport closed while writing",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_buf.advance(n);
                    self.hdr_remaining = self.hdr_remaining.saturating_sub(n);
                    self.inner_needs_flush = true;
                    made_write_progress = true;
                }
            }
        }
        if self.inner_needs_flush {
            match Pin::new(&mut self.inner).poll_flush(&mut fanout_cx) {
                Poll::Pending => {
                    if made_write_progress {
                        self.tx_fanout.wake_write();
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    self.inner_needs_flush = false;
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                }
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_read_tx();
                    self.tx_fanout.wake_write();
                    return Poll::Ready(Err(e));
                }
            }
        } else {
            self.tx_fanout.clear_read_tx();
            self.tx_fanout.wake_write();
        }
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

        // Always drain already-decoded plaintext (or already-reached EOF) FIRST, before any
        // opportunistic uplink drain, so an uplink error can never discard already-decoded bytes.
        if !self.read_plain_buf.is_empty() {
            let to_copy = self.read_plain_buf.len().min(buf.remaining());
            let chunk = self.read_plain_buf.split_to(to_copy);
            buf.put_slice(&chunk);
            self.tx_fanout.clear_read();
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            self.tx_fanout.clear_read();
            return Poll::Ready(Ok(()));
        }

        // Ensure request header is both written AND flushed for server-speaks-first protocols
        // (e.g. SSH, SMTP) over buffered/TLS/WS transports, WITHOUT early-returning `Pending`
        // so full-duplex responses can be read even while an initial upload saturates the uplink.
        let mut flush_err: Option<io::Error> = None;
        if !self.hdr_flushed {
            match self.poll_ensure_hdr_flushed(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    if self.hdr_remaining > 0 {
                        self.tx_fanout.clear_read();
                        return Poll::Ready(Err(e));
                    }
                    flush_err = Some(e);
                }
                Poll::Pending => {}
            }
        }
        if self.hdr_flushed
            && !self.uplink_broken_after_resp
            && (!self.write_buf.is_empty() || self.inner_needs_flush)
        {
            if self.tx_fanout.register_read_if_other_writer(cx.waker()) {
                // Another task (`Task W != Task R`) currently holds the write-readiness slot.
                // Stay registered in `read_tx` (`guard.0`) so `FanoutWaker::wake_by_ref`
                // atomically clears any stale cancelled writer waker and wakes us as soon as
                // `self.inner` becomes writable, without stealing a live writer's I/O error.
            } else {
                match self.poll_opportunistic_drain_from_read(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        if flush_err.is_none() {
                            flush_err = Some(e);
                        }
                    }
                    Poll::Pending => {}
                }
            }
        }
        if flush_err.is_some() && self.resp_verified {
            // Response header was already verified; stop retrying the broken uplink
            // from `poll_read` across subsequent reads of a multi-frame or keep-alive response.
            self.hdr_flushed = true;
            self.inner_needs_flush = false;
            self.uplink_broken_after_resp = true;
        }

        loop {
            if !self.read_plain_buf.is_empty() {
                let to_copy = self.read_plain_buf.len().min(buf.remaining());
                let chunk = self.read_plain_buf.split_to(to_copy);
                buf.put_slice(&chunk);
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }

            if !self.resp_verified {
                let resp_key = self.resp_key;
                let resp_iv = self.resp_iv;
                let expected_v = self.expected_resp_v;
                match try_open_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    expected_v,
                    &self.read_wire_buf,
                ) {
                    Ok(Some(used)) => {
                        let _ = self.read_wire_buf.split_to(used);
                        self.resp_verified = true;
                        if flush_err.is_some() {
                            // Server already decrypted our request header and sent a valid AEAD
                            // response header; stop retrying the failed uplink from `poll_read`.
                            self.hdr_flushed = true;
                            self.inner_needs_flush = false;
                            self.uplink_broken_after_resp = true;
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.tx_fanout.clear_read();
                        return Poll::Ready(Err(e));
                    }
                }
            } else {
                let this = &mut *self;
                match this.reader_codec.try_decode_chunk(&mut this.read_wire_buf) {
                    Ok(Some(decoded)) => {
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
                    Ok(None) => {}
                    Err(e) => {
                        this.tx_fanout.clear_read();
                        return Poll::Ready(Err(e));
                    }
                }
            }

            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            let server_responded = self.resp_verified || !self.read_wire_buf.is_empty();
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    if let Some(e) = flush_err
                        && !server_responded
                    {
                        self.tx_fanout.clear_read();
                        return Poll::Ready(Err(e));
                    }
                    self.tx_fanout.register_parked_read(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_read();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {}
            }
            let filled = rb.filled();
            if filled.is_empty() {
                self.tx_fanout.clear_read();
                if !self.resp_verified {
                    if self.read_wire_buf.is_empty()
                        && let Some(e) = flush_err
                    {
                        return Poll::Ready(Err(e));
                    }
                    let msg = if self.read_wire_buf.is_empty() {
                        "VMess stream closed before response header"
                    } else {
                        "truncated VMess AEAD response header"
                    };
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, msg)));
                }
                if !self.read_wire_buf.is_empty() || self.reader_codec.has_pending_chunk() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VMess chunk before EOF",
                    )));
                }
                self.read_eof = true;
                if flush_err.is_some() {
                    self.hdr_flushed = true;
                    self.inner_needs_flush = false;
                    self.uplink_broken_after_resp = true;
                }
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
            if !self.write_buf.is_empty() || self.inner_needs_flush {
                self.tx_fanout.clear_write_and_wake_read();
            } else {
                self.tx_fanout.clear_write_and_wake_read_tx();
            }
            return Poll::Ready(Ok(0));
        }

        // Drain any non-header residual ciphertext BEFORE consuming bytes from `data`.
        // This preserves 0-RTT header+first-chunk coalescing while keeping `write_buf`
        // bounded to one chunk and guaranteeing cancel-safe retries with any buffer size.
        if !self.hdr_coalesce_pending && !self.write_buf.is_empty() {
            match self.poll_drain_write_buf_from_write(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_write_and_wake_read();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {}
            }
        }

        let accept_len = data.len().min(VMESS_MAX_CHUNK_PLAIN);
        {
            let this = &mut *self;
            if let Err(e) = this
                .writer_codec
                .encode_chunk(&data[..accept_len], &mut this.write_buf)
            {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            this.hdr_coalesce_pending = false;
            this.uplink_broken_after_resp = false;
        }

        // Opportunistically push buffered ciphertext to `self.inner`, then immediately
        // acknowledge `accept_len` (buffered `AsyncWrite` semantics: never returns `Pending`
        // after buffering bytes). Returning `Poll::Ready` leaves buffered TX work in either
        // `write_buf` or `self.inner` (`inner_needs_flush`), so clear the writer slot and wake
        // any parked split reader (`guard.0` / `guard.2`) so bytes can never strand if the writer
        // never calls `flush()`.
        match self.poll_drain_write_buf_with_fanout() {
            Poll::Ready(Err(e)) => {
                self.tx_fanout.clear_write_and_wake_read();
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) | Poll::Pending => {
                self.tx_fanout.clear_write_and_wake_read();
                Poll::Ready(Ok(accept_len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_write_buf_from_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {}
        }
        let this = &mut *self;
        this.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&this.tx_fanout_waker);
        match Pin::new(&mut this.inner).poll_flush(&mut fanout_cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                this.inner_needs_flush = false;
                this.uplink_broken_after_resp = false;
                if this.hdr_remaining == 0 {
                    this.hdr_flushed = true;
                    this.hdr_coalesce_pending = false;
                }
                this.tx_fanout.clear_write_and_wake_read_tx();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.tx_fanout.clear_write_and_wake_read();
                Poll::Ready(Err(e))
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut newly_queued_tx = false;
        if !self.eof_sent {
            let this = &mut *self;
            if let Err(e) = this.writer_codec.encode_eof_chunk(&mut this.write_buf) {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            this.hdr_coalesce_pending = false;
            this.uplink_broken_after_resp = false;
            this.eof_sent = true;
            newly_queued_tx = true;
        }
        match self.poll_drain_write_buf_from_write(cx) {
            Poll::Pending => {
                if newly_queued_tx {
                    self.tx_fanout.wake_parked_read();
                }
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                self.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {}
        }
        let this = &mut *self;
        this.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&this.tx_fanout_waker);
        match Pin::new(&mut this.inner).poll_flush(&mut fanout_cx) {
            Poll::Pending => {
                if newly_queued_tx {
                    this.tx_fanout.wake_parked_read();
                }
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {
                this.inner_needs_flush = false;
                this.uplink_broken_after_resp = false;
                if this.hdr_remaining == 0 {
                    let was_unflushed = !this.hdr_flushed;
                    this.hdr_flushed = true;
                    this.hdr_coalesce_pending = false;
                    if was_unflushed {
                        this.tx_fanout.wake_read_tx();
                    }
                }
            }
        }
        this.tx_fanout.register_write(cx.waker());
        let res = Pin::new(&mut this.inner).poll_shutdown(&mut fanout_cx);
        match &res {
            Poll::Ready(Ok(())) => {
                this.inner_needs_flush = false;
                this.tx_fanout.clear_write_and_wake_read_tx();
            }
            Poll::Ready(Err(_)) => {
                this.tx_fanout.clear_write_and_wake_read();
            }
            Poll::Pending => {
                if newly_queued_tx {
                    this.tx_fanout.wake_parked_read();
                }
            }
        }
        res
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::ready,
    };

    fn make_vmess_pair() -> ([u8; 16], VmessRequestHeader, BytesMut) {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd_key = derive_cmd_key(&uuid);
        let target = TargetAddr::new_domain("example.com", 443).unwrap();
        let req_hdr =
            VmessRequestHeader::new_random(VmessSecurity::Aes128Gcm, true, VMESS_CMD_TCP, target);
        let wire_hdr = seal_vmess_aead_request_header(&cmd_key, &req_hdr).unwrap();
        (cmd_key, req_hdr, wire_hdr)
    }

    struct DeferredFlushStream {
        written: BytesMut,
        pending_flushes_left: usize,
        flush_calls: usize,
        flushed: bool,
        server_reply: BytesMut,
    }

    impl AsyncRead for DeferredFlushStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.flushed {
                // Server only speaks after the client's request header flush actually completes!
                return Poll::Pending;
            }
            if self.server_reply.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = self.server_reply.len().min(buf.remaining());
            let chunk = self.server_reply.split_to(n);
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DeferredFlushStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_calls += 1;
            if self.pending_flushes_left > 0 {
                self.pending_flushes_left -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.flushed = true;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn server_speaks_first_completes_when_poll_flush_returns_pending_first() {
        let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);

        let mut server_reply =
            seal_vmess_aead_response_header(&resp_key, &resp_iv, req_hdr.resp_v, req_hdr.option)
                .unwrap();
        let mut srv_wr =
            VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option).unwrap();
        let banner = b"SSH-2.0-OpenSSH_9.9\r\n";
        srv_wr.encode_chunk(banner, &mut server_reply).unwrap();
        srv_wr.encode_eof_chunk(&mut server_reply).unwrap();

        let mock = DeferredFlushStream {
            written: BytesMut::new(),
            pending_flushes_left: 2,
            flush_calls: 0,
            flushed: false,
            server_reply,
        };
        let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut got))
            .await
            .expect("poll_read must retry poll_flush after Pending instead of deadlocking")
            .expect("read server-speaks-first banner");

        assert_eq!(got, banner);
        assert!(client.hdr_flushed);
        assert!(client.inner.flush_calls >= 3);
    }

    struct CountingWaker(Arc<AtomicUsize>);

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SingleWriteWakerStream {
        allow_bytes: usize,
        stored_write_waker: Option<Waker>,
    }

    impl AsyncRead for SingleWriteWakerStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SingleWriteWakerStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.allow_bytes == 0 {
                self.stored_write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let take = buf.len().min(self.allow_bytes);
            self.allow_bytes -= take;
            Poll::Ready(Ok(take))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.stored_write_waker = Some(cx.waker().clone());
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn split_stream_fanout_waker_and_concurrent_saturated_io_never_deadlock() {
        // Part A: Deterministic FanoutWaker proof — when Task W is Pending on `poll_write`
        // and Task R drives `!hdr_flushed` in `poll_read`, triggering the inner stream's single
        // write waker slot MUST wake BOTH Task W and Task R.
        let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let mock = SingleWriteWakerStream {
            allow_bytes: 16, // lets partial header through, then blocks
            stored_write_waker: None,
        };
        let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

        let w_hits = Arc::new(AtomicUsize::new(0));
        let r_hits = Arc::new(AtomicUsize::new(0));
        let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
        let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
        let mut cx_w = Context::from_waker(&waker_w);
        let mut cx_r = Context::from_waker(&waker_r);

        // First write coalesces chunk 1 behind header, partially drains 16 bytes, returns Ready(Ok).
        let n1 = Pin::new(&mut stream)
            .poll_write(&mut cx_w, b"chunk-one")
            .map(|r| r.unwrap());
        assert_eq!(n1, Poll::Ready(9));

        // Second write must drain residual `write_buf` first -> hits Pending and saves `write_waker`.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx_w, b"chunk-two"),
            Poll::Pending
        ));

        // Concurrent `poll_read` while `!hdr_flushed` drives `inner.poll_write` using FanoutWaker.
        let mut out = [0u8; 16];
        let mut rb = ReadBuf::new(&mut out);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
            Poll::Pending
        ));

        // Fire the SINGLE waker stored in `SingleWriteWakerStream`: BOTH tasks must wake!
        stream
            .inner
            .stored_write_waker
            .take()
            .expect("inner must have registered waker")
            .wake();
        assert_eq!(w_hits.load(Ordering::SeqCst), 1, "Task W must be woken");
        assert_eq!(r_hits.load(Ordering::SeqCst), 1, "Task R must be woken");

        // Part B: End-to-end split-stream stress over a tiny 256-byte duplex buffer with
        // simultaneous 128 KiB bidirectional streaming.
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let client_stream = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
        let (mut cli_rd, mut cli_wr) = tokio::io::split(client_stream);

        let up_payload: Vec<u8> = (0..(128 * 1024)).map(|i| (i % 251) as u8).collect();
        let down_payload: Vec<u8> = (0..(128 * 1024)).map(|i| ((i * 7) % 251) as u8).collect();
        let expected_up = up_payload.clone();
        let server_down = down_payload.clone();

        let srv_task = tokio::spawn(async move {
            let decoded_req = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let (resp_key, resp_iv) =
                derive_response_key_and_iv(&decoded_req.req_key, &decoded_req.req_iv);
            let resp_hdr = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded_req.resp_v,
                decoded_req.option,
            )
            .unwrap();
            let mut srv_rd_codec = VmessChunkCodec::new(
                &decoded_req.req_key,
                &decoded_req.req_iv,
                decoded_req.security,
                decoded_req.option,
            )
            .unwrap();
            let mut srv_wr_codec = VmessChunkCodec::new(
                &resp_key,
                &resp_iv,
                decoded_req.security,
                decoded_req.option,
            )
            .unwrap();

            let (mut s_rd, mut s_wr) = tokio::io::split(server_io);
            let read_up = async move {
                let mut wire_buf = BytesMut::new();
                let mut acc = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    while let Some(decoded) = srv_rd_codec.try_decode_chunk(&mut wire_buf).unwrap()
                    {
                        match decoded {
                            Some(p) => acc.extend_from_slice(&p),
                            None => return acc,
                        }
                    }
                    let n = s_rd.read(&mut tmp).await.unwrap();
                    assert!(n > 0, "unexpected EOF before client VMess EOF chunk");
                    wire_buf.extend_from_slice(&tmp[..n]);
                }
            };
            let write_down = async move {
                s_wr.write_all(&resp_hdr).await.unwrap();
                for slice in server_down.chunks(4096) {
                    let mut out = BytesMut::new();
                    srv_wr_codec.encode_chunk(slice, &mut out).unwrap();
                    s_wr.write_all(&out).await.unwrap();
                }
                let mut eof = BytesMut::new();
                srv_wr_codec.encode_eof_chunk(&mut eof).unwrap();
                s_wr.write_all(&eof).await.unwrap();
                s_wr.flush().await.unwrap();
                let _ = s_wr.shutdown().await;
            };

            let (got_up, ()) = tokio::join!(read_up, write_down);
            assert_eq!(got_up, expected_up);
        });

        let cli_write = async move {
            cli_wr.write_all(&up_payload).await.unwrap();
            cli_wr.flush().await.unwrap();
            cli_wr.shutdown().await.unwrap();
        };
        let cli_read = async move {
            let mut got_down = Vec::new();
            cli_rd.read_to_end(&mut got_down).await.unwrap();
            got_down
        };

        let ((), got_down, srv_res) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(cli_write, cli_read, srv_task)
        })
        .await
        .expect("split VmessClientStream concurrent saturated IO must not deadlock");
        srv_res.unwrap();
        assert_eq!(got_down, down_payload);
    }

    #[tokio::test]
    async fn cancelled_pending_write_retries_smaller_buffer_without_error_or_panic() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        // Tiny 64-byte duplex guarantees writes hit Pending before server starts draining.
        let (client_io, mut server_io) = tokio::io::duplex(64);
        let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();

        let large = vec![0x5Au8; VMESS_MAX_CHUNK_PLAIN * 2 + 100];
        // First `write_all` accepts the first chunk (VMESS_MAX_CHUNK_PLAIN) into `write_buf`,
        // fills the 64-byte duplex, and hits `Pending` on the second chunk -> cancel via timeout!
        let timed_out =
            tokio::time::timeout(Duration::from_millis(20), client.write_all(&large)).await;
        assert!(
            timed_out.is_err(),
            "write_all(large) on stalled 64-byte duplex must park in Pending before cancel"
        );

        // Now start draining on the server side.
        let srv = tokio::spawn(async move {
            let decoded_req = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut dec = VmessChunkCodec::new(
                &decoded_req.req_key,
                &decoded_req.req_iv,
                decoded_req.security,
                decoded_req.option,
            )
            .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut acc = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                while let Some(decoded) = dec.try_decode_chunk(&mut wire_buf).unwrap() {
                    match decoded {
                        Some(p) => acc.extend_from_slice(&p),
                        None => return acc,
                    }
                }
                let n = server_io.read(&mut tmp).await.unwrap();
                if n == 0 {
                    return acc;
                }
                wire_buf.extend_from_slice(&tmp[..n]);
            }
        });

        // Retry with a tiny, completely different buffer — MUST succeed cleanly (no InvalidInput, no panic).
        let small = b"small-retry";
        tokio::time::timeout(Duration::from_secs(2), async {
            client.write_all(small).await.unwrap();
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();
        })
        .await
        .expect("retried small write_all must complete cleanly");

        let received = srv.await.unwrap();
        let mut expected = vec![0x5Au8; VMESS_MAX_CHUNK_PLAIN];
        expected.extend_from_slice(small);
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn transport_eof_before_response_header_or_mid_chunk_returns_unexpected_eof() {
        // Case 1: Server closes connection with 0 bytes (never sends response header).
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (client_io, server_io) = tokio::io::duplex(4096);
            let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            client.flush().await.unwrap();
            drop(server_io);

            let mut buf = [0u8; 32];
            let err = client
                .read(&mut buf)
                .await
                .expect_err("0-byte EOF before VMess response header must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(err.to_string().contains("before response header"));
        }

        // Case 1b: Server sends truncated response header (10 bytes), then closes.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let resp_hdr = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let (client_io, mut server_io) = tokio::io::duplex(4096);
            let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            client.flush().await.unwrap();
            server_io.write_all(&resp_hdr[..10]).await.unwrap();
            drop(server_io);

            let mut buf = [0u8; 32];
            let err = client
                .read(&mut buf)
                .await
                .expect_err("truncated response header EOF must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }

        // Case 2: Server sends valid response header + ONLY the 2-byte chunk length header
        // (leaving `read_wire_buf` empty but `reader_codec.has_pending_chunk() == true`), then closes.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let resp_hdr = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();
            let mut chunk_wire = BytesMut::new();
            srv_wr
                .encode_chunk(b"truncated-after-2-byte-length", &mut chunk_wire)
                .unwrap();

            let (client_io, mut server_io) = tokio::io::duplex(4096);
            let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            client.flush().await.unwrap();

            server_io.write_all(&resp_hdr).await.unwrap();
            server_io.write_all(&chunk_wire[..2]).await.unwrap();
            drop(server_io);

            let mut out = Vec::new();
            let err = client
                .read_to_end(&mut out)
                .await
                .expect_err("EOF after 2-byte chunk length header must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(err.to_string().contains("truncated VMess chunk"));
        }

        // Case 3: Server sends valid response header + partial chunk ciphertext body, then closes.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let resp_hdr = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();
            let mut chunk_wire = BytesMut::new();
            srv_wr
                .encode_chunk(b"truncated-mid-ciphertext-body", &mut chunk_wire)
                .unwrap();

            let (client_io, mut server_io) = tokio::io::duplex(4096);
            let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            client.flush().await.unwrap();

            server_io.write_all(&resp_hdr).await.unwrap();
            server_io
                .write_all(&chunk_wire[..chunk_wire.len() - 5])
                .await
                .unwrap();
            drop(server_io);

            let mut out = Vec::new();
            let err = client
                .read_to_end(&mut out)
                .await
                .expect_err("EOF mid-VMess chunk body must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(err.to_string().contains("truncated VMess chunk"));
        }

        // Case 4: Server sends valid response header + complete chunk + authenticated EOF chunk.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let resp_hdr = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();
            let mut wire = resp_hdr;
            srv_wr.encode_chunk(b"complete-payload", &mut wire).unwrap();
            srv_wr.encode_eof_chunk(&mut wire).unwrap();

            let (client_io, mut server_io) = tokio::io::duplex(4096);
            let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            client.flush().await.unwrap();

            server_io.write_all(&wire).await.unwrap();
            drop(server_io);

            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"complete-payload");
        }
    }

    /// Transparent buffered wrapper (mirrors TLS/WS write buffering semantics where
    /// `poll_flush` returns `Pending` whenever the underlying 256B duplex is saturated).
    struct BufferedFlushTransport<S> {
        inner: S,
        tx_buf: BytesMut,
        cap: usize,
    }

    impl<S> BufferedFlushTransport<S> {
        fn new(inner: S, cap: usize) -> Self {
            Self {
                inner,
                tx_buf: BytesMut::with_capacity(cap),
                cap,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for BufferedFlushTransport<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for BufferedFlushTransport<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            while !this.tx_buf.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "buffered transport closed",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => break,
                }
            }
            let room = this.cap.saturating_sub(this.tx_buf.len());
            if room == 0 {
                return Poll::Pending;
            }
            let take = data.len().min(room);
            this.tx_buf.extend_from_slice(&data[..take]);
            while !this.tx_buf.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "buffered transport closed",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => break,
                }
            }
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while !this.tx_buf.is_empty() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "buffered transport closed on flush",
                    )));
                }
                this.tx_buf.advance(n);
            }
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            ready!(self.as_mut().poll_flush(cx))?;
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Strict buffered transport mirroring `BufWriter` / `TlsStream`: `poll_write` accepts
    /// up to `cap` bytes into `tx_buf` and returns `Ready(Ok(n))` without flushing to `inner`;
    /// bytes only reach `inner` via `poll_flush` / `poll_shutdown`.
    struct StrictBufWriterTransport<S> {
        inner: S,
        tx_buf: BytesMut,
        cap: usize,
    }

    impl<S> StrictBufWriterTransport<S> {
        fn new(inner: S, cap: usize) -> Self {
            Self {
                inner,
                tx_buf: BytesMut::with_capacity(cap),
                cap,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for StrictBufWriterTransport<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StrictBufWriterTransport<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let room = this.cap.saturating_sub(this.tx_buf.len());
            if room == 0 {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "strict buffered transport closed",
                    )));
                }
                this.tx_buf.advance(n);
            }
            let room = this.cap.saturating_sub(this.tx_buf.len());
            let take = data.len().min(room);
            this.tx_buf.extend_from_slice(&data[..take]);
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while !this.tx_buf.is_empty() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "strict buffered transport closed on flush",
                    )));
                }
                this.tx_buf.advance(n);
            }
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            ready!(self.as_mut().poll_flush(cx))?;
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn full_duplex_reply_before_draining_coalesced_upload_no_deadlock() {
        async fn run_case<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
            client_stream: VmessClientStream<S>,
            mut server_io: tokio::io::DuplexStream,
            cmd_key: [u8; 16],
        ) {
            let (mut rd, mut wr) = tokio::io::split(client_stream);
            let upload = vec![0xABu8; 16 * 1024];
            let upload_tx = upload.clone();
            let reply_plain: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
            let reply_tx = reply_plain.clone();

            let writer_task = tokio::spawn(async move {
                wr.write_all(&upload_tx).await.unwrap();
                wr.flush().await.unwrap();
                wr.shutdown().await.unwrap();
            });

            let reader_task = tokio::spawn(async move {
                let mut got = vec![0u8; 512];
                rd.read_exact(&mut got).await.unwrap();
                got
            });

            let server_task = tokio::spawn(async move {
                // 1. Read ONLY the first 256 bytes (contains full VMess AEAD request header +
                //    initial ciphertext) BEFORE sending response.
                let mut first = vec![0u8; 256];
                server_io.read_exact(&mut first).await.unwrap();
                let mut cursor = io::Cursor::new(first.as_slice());
                let decoded_req = read_vmess_aead_request_header(&cmd_key, &mut cursor)
                    .await
                    .unwrap();
                let hdr_len = cursor.position() as usize;

                let (resp_key, resp_iv) =
                    derive_response_key_and_iv(&decoded_req.req_key, &decoded_req.req_iv);
                let mut wire_reply = seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded_req.resp_v,
                    decoded_req.option,
                )
                .unwrap();
                let mut srv_wr = VmessChunkCodec::new(
                    &resp_key,
                    &resp_iv,
                    decoded_req.security,
                    decoded_req.option,
                )
                .unwrap();
                srv_wr.encode_chunk(&reply_tx, &mut wire_reply).unwrap();
                srv_wr.encode_eof_chunk(&mut wire_reply).unwrap();

                // 2. Write > 256B VMess response BEFORE draining client's remaining 16 KiB upload!
                server_io.write_all(&wire_reply).await.unwrap();
                server_io.flush().await.unwrap();

                // 3. Now drain and decrypt the entire 16 KiB upload.
                let mut wire_buf = BytesMut::from(&first[hdr_len..]);
                let mut srv_rd = VmessChunkCodec::new(
                    &decoded_req.req_key,
                    &decoded_req.req_iv,
                    decoded_req.security,
                    decoded_req.option,
                )
                .unwrap();
                let mut acc = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    while let Some(decoded) = srv_rd.try_decode_chunk(&mut wire_buf).unwrap() {
                        match decoded {
                            Some(p) => acc.extend_from_slice(&p),
                            None => {
                                assert_eq!(acc, upload);
                                return;
                            }
                        }
                    }
                    let n = server_io.read(&mut tmp).await.unwrap();
                    assert!(n > 0, "unexpected EOF before client VMess EOF chunk");
                    wire_buf.extend_from_slice(&tmp[..n]);
                }
            });

            let got_reply = tokio::time::timeout(Duration::from_secs(2), async {
                writer_task.await.unwrap();
                server_task.await.unwrap();
                reader_task.await.unwrap()
            })
            .await
            .expect("VmessClientStream::poll_read must not deadlock behind saturated upload flush");
            assert_eq!(got_reply, reply_plain);
        }

        // Case A: Raw tokio::io::duplex(256)
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (client_io, server_io) = tokio::io::duplex(256);
            let stream = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
            run_case(stream, server_io, cmd_key).await;
        }

        // Case B: Buffered pending-flush transport (mirrors TLS/WS over duplex(256))
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (client_io, server_io) = tokio::io::duplex(256);
            let buffered = BufferedFlushTransport::new(client_io, 512);
            let stream = VmessClientStream::new(buffered, wire_hdr, &req_hdr).unwrap();
            run_case(stream, server_io, cmd_key).await;
        }
    }

    #[tokio::test]
    async fn delivers_buffered_response_on_uplink_error_and_surfaces_unsent_header_error() {
        // Case 1: Server received VMess request header + initial bytes, replied with 512B VMess
        // payload + EOF, and closed uplink (BrokenPipe on further writes). Reader must still
        // verify response header and deliver all 512 bytes cleanly!
        {
            struct EarlyUplinkCloseStream {
                allow_write_bytes: usize,
                downlink: BytesMut,
            }

            impl AsyncRead for EarlyUplinkCloseStream {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    if self.downlink.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let take = self.downlink.len().min(buf.remaining()).min(128);
                    buf.put_slice(&self.downlink.split_to(take));
                    Poll::Ready(Ok(()))
                }
            }

            impl AsyncWrite for EarlyUplinkCloseStream {
                fn poll_write(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    data: &[u8],
                ) -> Poll<io::Result<usize>> {
                    if self.allow_write_bytes == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "server closed uplink early",
                        )));
                    }
                    let take = data.len().min(self.allow_write_bytes);
                    self.allow_write_bytes -= take;
                    Poll::Ready(Ok(take))
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "server closed uplink on flush",
                    )))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let mut downlink = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();
            let reply_plain = vec![0x42u8; 512];
            srv_wr.encode_chunk(&reply_plain, &mut downlink).unwrap();
            srv_wr.encode_eof_chunk(&mut downlink).unwrap();

            let mock = EarlyUplinkCloseStream {
                allow_write_bytes: 256,
                downlink,
            };
            let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            // First write delivers header + initial ciphertext, then hits BrokenPipe.
            let err = client.write(&vec![0xABu8; 16 * 1024]).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(client.hdr_remaining, 0);

            // Reader must still receive the complete decrypted VMess response cleanly!
            let mut got = Vec::new();
            client
                .read_to_end(&mut got)
                .await
                .expect("buffered VMess response must be delivered despite uplink BrokenPipe");
            assert_eq!(got, reply_plain);
        }

        // Case 2: Server-speaks-first broken header write / flush must return Err promptly.
        {
            struct BrokenWritePendingReadStream {
                fail_on_write: bool,
            }

            impl AsyncRead for BrokenWritePendingReadStream {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    _buf: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Pending
                }
            }

            impl AsyncWrite for BrokenWritePendingReadStream {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    data: &[u8],
                ) -> Poll<io::Result<usize>> {
                    if self.fail_on_write {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "broken uplink on VMess header write",
                        )))
                    } else {
                        Poll::Ready(Ok(data.len()))
                    }
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "broken uplink on VMess header flush",
                    )))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let mut s_write = VmessClientStream::new(
                BrokenWritePendingReadStream {
                    fail_on_write: true,
                },
                wire_hdr.clone(),
                &req_hdr,
            )
            .unwrap();
            let mut b = [0u8; 16];
            let err_w = tokio::time::timeout(Duration::from_millis(500), s_write.read(&mut b))
                .await
                .expect("unsent VMess header write error must not hang poll_read")
                .expect_err("expected BrokenPipe");
            assert_eq!(err_w.kind(), io::ErrorKind::BrokenPipe);

            let mut s_flush = VmessClientStream::new(
                BrokenWritePendingReadStream {
                    fail_on_write: false,
                },
                wire_hdr,
                &req_hdr,
            )
            .unwrap();
            let err_f = tokio::time::timeout(Duration::from_millis(500), s_flush.read(&mut b))
                .await
                .expect("failed VMess header flush must not hang server-speaks-first poll_read")
                .expect_err("expected BrokenPipe");
            assert_eq!(err_f.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn noop_flush_wakes_parked_writer_without_clobbering_write_waker() {
        struct NoopFlushSingleWriteWakerStream {
            allow_bytes: usize,
            stored_write_waker: Option<Waker>,
        }

        impl AsyncRead for NoopFlushSingleWriteWakerStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for NoopFlushSingleWriteWakerStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.allow_bytes == 0 {
                    self.stored_write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let take = buf.len().min(self.allow_bytes);
                self.allow_bytes -= take;
                Poll::Ready(Ok(take))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let hdr_len = wire_hdr.len();
        let mock = NoopFlushSingleWriteWakerStream {
            // Allow full header + 16 bytes of first chunk, leaving residual ciphertext in write_buf.
            allow_bytes: hdr_len + 16,
            stored_write_waker: None,
        };
        let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

        let w_hits = Arc::new(AtomicUsize::new(0));
        let r_hits = Arc::new(AtomicUsize::new(0));
        let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
        let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
        let mut cx_w = Context::from_waker(&waker_w);
        let mut cx_r = Context::from_waker(&waker_r);

        let chunk1 = vec![0x11u8; 256];
        assert_eq!(
            Pin::new(&mut stream)
                .poll_write(&mut cx_w, &chunk1)
                .map(|r| r.unwrap()),
            Poll::Ready(256)
        );
        assert_eq!(stream.hdr_remaining, 0);
        assert!(!stream.write_buf.is_empty());

        // Second write parks Pending on residual `write_buf`, storing Task W's waker.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx_w, b"chunk2"),
            Poll::Pending
        ));

        // Concurrent `poll_read` runs no-op `inner.poll_flush -> Ready(Ok(()))`:
        // must set `hdr_flushed = true` and wake Task W immediately via `tx_fanout`.
        let mut out = [0u8; 16];
        let mut rb = ReadBuf::new(&mut out);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
            Poll::Pending
        ));
        assert!(stream.hdr_flushed);
        assert_eq!(w_hits.load(Ordering::SeqCst), 1, "Task W must be woken");

        // Task W responds to its wakeup and re-polls `poll_write`, parking again with `tx_fanout`.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx_w, b"chunk2"),
            Poll::Pending
        ));

        // Firing the stored inner write waker (`tx_fanout_waker`) must wake Task W AND fan out
        // to Task R (so neither live Task W nor Task R on a cancelled writer can ever be starved).
        stream
            .inner
            .stored_write_waker
            .take()
            .expect("inner write waker must still be present")
            .wake();
        assert_eq!(
            w_hits.load(Ordering::SeqCst),
            2,
            "inner write waker must still wake Task W"
        );
        assert_eq!(
            r_hits.load(Ordering::SeqCst),
            1,
            "persistent FanoutWaker must fan out to Task R"
        );
    }

    async fn read_vmess_plain_exact<S: AsyncRead + Unpin>(
        server_io: &mut S,
        rd_codec: &mut VmessChunkCodec,
        wire_buf: &mut BytesMut,
        plain_buf: &mut BytesMut,
        want: usize,
    ) -> Vec<u8> {
        let mut tmp = [0u8; 4096];
        while plain_buf.len() < want {
            while let Some(decoded) = rd_codec.try_decode_chunk(wire_buf).unwrap() {
                match decoded {
                    Some(p) => plain_buf.extend_from_slice(&p),
                    None => panic!("unexpected VMess EOF before receiving {want} bytes"),
                }
            }
            if plain_buf.len() >= want {
                break;
            }
            let n = server_io.read(&mut tmp).await.unwrap();
            assert!(
                n > 0,
                "unexpected transport EOF before receiving {want} bytes"
            );
            wire_buf.extend_from_slice(&tmp[..n]);
        }
        plain_buf.split_to(want).to_vec()
    }

    #[tokio::test]
    async fn single_task_write_all_without_flush_then_read_completes_over_buffered_transports() {
        // Case A: Request #1 single-task write_all(2048 B) WITHOUT flush() + read_exact
        // over BufferedFlushTransport(cap=512, duplex(256)) — exact DEFECT-VMESS-IT2-1 repro.
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (client_io, mut server_io) = tokio::io::duplex(256);
            let mut client = VmessClientStream::new(
                BufferedFlushTransport::new(client_io, 512),
                wire_hdr,
                &req_hdr,
            )
            .unwrap();

            let req1 = vec![0x42u8; 2048];
            let expected_req1 = req1.clone();
            let reply1 = b"REPLY-0000-OK";

            let srv = tokio::spawn(async move {
                let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                    .await
                    .unwrap();
                let mut srv_rd = VmessChunkCodec::new(
                    &decoded.req_key,
                    &decoded.req_iv,
                    decoded.security,
                    decoded.option,
                )
                .unwrap();
                let mut wire_buf = BytesMut::new();
                let mut plain_buf = BytesMut::new();
                let got_req = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected_req1.len(),
                )
                .await;
                assert_eq!(got_req, expected_req1);

                let (resp_key, resp_iv) =
                    derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
                let mut out = seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded.resp_v,
                    decoded.option,
                )
                .unwrap();
                let mut srv_wr =
                    VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                        .unwrap();
                srv_wr.encode_chunk(reply1, &mut out).unwrap();
                srv_wr.encode_eof_chunk(&mut out).unwrap();
                server_io.write_all(&out).await.unwrap();
                server_io.flush().await.unwrap();
            });

            tokio::time::timeout(Duration::from_secs(2), async {
                client.write_all(&req1).await.unwrap();
                let mut got = [0u8; 13];
                client.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, reply1);
            })
            .await
            .expect("Req #1 write_all(no flush) + read_exact over BufferedFlushTransport must not deadlock");
            srv.await.unwrap();
        }

        // Helper for keep-alive Req #1 + Req #2 without flush() across buffered transports.
        async fn run_keepalive_case<C, S>(
            client_transport: C,
            mut server_io: S,
            req1: Vec<u8>,
            req2: Vec<u8>,
            label: &'static str,
        ) where
            C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let mut client = VmessClientStream::new(client_transport, wire_hdr, &req_hdr).unwrap();
            let expected_req1 = req1.clone();
            let expected_req2 = req2.clone();
            let reply1 = b"REPLY-KA-0001";
            let reply2 = b"REPLY-KA-0002";

            let srv = tokio::spawn(async move {
                let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                    .await
                    .unwrap();
                let mut srv_rd = VmessChunkCodec::new(
                    &decoded.req_key,
                    &decoded.req_iv,
                    decoded.security,
                    decoded.option,
                )
                .unwrap();
                let (resp_key, resp_iv) =
                    derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
                let mut srv_wr =
                    VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                        .unwrap();

                let mut wire_buf = BytesMut::new();
                let mut plain_buf = BytesMut::new();

                // Request #1
                let got1 = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected_req1.len(),
                )
                .await;
                assert_eq!(got1, expected_req1);
                let mut out1 = seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded.resp_v,
                    decoded.option,
                )
                .unwrap();
                srv_wr.encode_chunk(reply1, &mut out1).unwrap();
                server_io.write_all(&out1).await.unwrap();
                server_io.flush().await.unwrap();

                // Request #2 (keep-alive after hdr_flushed && resp_verified)
                let got2 = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected_req2.len(),
                )
                .await;
                assert_eq!(got2, expected_req2);
                let mut out2 = BytesMut::new();
                srv_wr.encode_chunk(reply2, &mut out2).unwrap();
                srv_wr.encode_eof_chunk(&mut out2).unwrap();
                server_io.write_all(&out2).await.unwrap();
                server_io.flush().await.unwrap();
            });

            tokio::time::timeout(Duration::from_secs(3), async {
                client.write_all(&req1).await.unwrap();
                let mut got1 = [0u8; 13];
                client.read_exact(&mut got1).await.unwrap();
                assert_eq!(&got1, reply1);

                client.write_all(&req2).await.unwrap();
                let mut got2 = [0u8; 13];
                client.read_exact(&mut got2).await.unwrap();
                assert_eq!(&got2, reply2);

                let mut tail = Vec::new();
                client.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty());
            })
            .await
            .unwrap_or_else(|_| {
                panic!("keep-alive write_all(no flush) + read_exact deadlocked ({label})")
            });
            srv.await.unwrap();
        }

        // Case B: Keep-alive Req #1 (2048 B) + Req #2 (2048 B) over BufferedFlushTransport(512, duplex(256))
        {
            let (client_io, server_io) = tokio::io::duplex(256);
            run_keepalive_case(
                BufferedFlushTransport::new(client_io, 512),
                server_io,
                vec![0x31u8; 2048],
                vec![0x52u8; 2048],
                "BufferedFlushTransport",
            )
            .await;
        }

        // Case C: Keep-alive Req #1 + Req #2 (2048 B) over StrictBufWriterTransport(4096, duplex(256))
        {
            let (client_io, server_io) = tokio::io::duplex(256);
            run_keepalive_case(
                StrictBufWriterTransport::new(client_io, 4096),
                server_io,
                b"GET /1 HTTP/1.1\r\n\r\n".to_vec(),
                vec![0x55u8; 2048],
                "StrictBufWriterTransport",
            )
            .await;
        }

        // Case D: Keep-alive Req #1 + Req #2 (2048 B) over real tokio_rustls::client::TlsStream<DuplexStream(256)>
        {
            let (server_tls_cfg, cert_der) =
                crate::crypto::tls::generate_self_signed_server_config(&[], &[]).unwrap();
            let client_tls_cfg =
                crate::crypto::tls::build_tls_client_config(false, &[cert_der], &[]).unwrap();
            let acceptor = TlsAcceptor::from(server_tls_cfg);
            let connector = TlsConnector::from(client_tls_cfg);
            let sni = crate::crypto::tls::parse_server_name("localhost").unwrap();

            let (client_io, server_io) = tokio::io::duplex(256);
            let (cli_tls_res, srv_tls_res) = tokio::join!(
                connector.connect(sni, client_io),
                acceptor.accept(server_io)
            );
            let cli_tls = cli_tls_res.unwrap();
            let srv_tls = srv_tls_res.unwrap();

            run_keepalive_case(
                cli_tls,
                srv_tls,
                b"GET /1 HTTP/1.1\r\n\r\n".to_vec(),
                vec![0x55u8; 2048],
                "tokio_rustls::TlsStream",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn split_stream_heavy_bidir_and_opportunistic_drain_waker_safety_over_buffered_transport()
    {
        // Part A: Heavy 64 KiB / 64 KiB split bidirectional transfer over BufferedFlushTransport(512, duplex(256)).
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (client_io, mut server_io) = tokio::io::duplex(256);
            let buffered = BufferedFlushTransport::new(client_io, 512);
            let client_stream = VmessClientStream::new(buffered, wire_hdr, &req_hdr).unwrap();
            let (mut cli_rd, mut cli_wr) = tokio::io::split(client_stream);

            let up_payload: Vec<u8> = (0..(64 * 1024)).map(|i| ((i * 3) % 251) as u8).collect();
            let down_payload: Vec<u8> = (0..(64 * 1024)).map(|i| ((i * 11) % 251) as u8).collect();
            let expected_up = up_payload.clone();
            let server_down = down_payload.clone();

            let srv_task = tokio::spawn(async move {
                let decoded_req = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                    .await
                    .unwrap();
                let (resp_key, resp_iv) =
                    derive_response_key_and_iv(&decoded_req.req_key, &decoded_req.req_iv);
                let resp_hdr = seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded_req.resp_v,
                    decoded_req.option,
                )
                .unwrap();
                let mut srv_rd_codec = VmessChunkCodec::new(
                    &decoded_req.req_key,
                    &decoded_req.req_iv,
                    decoded_req.security,
                    decoded_req.option,
                )
                .unwrap();
                let mut srv_wr_codec = VmessChunkCodec::new(
                    &resp_key,
                    &resp_iv,
                    decoded_req.security,
                    decoded_req.option,
                )
                .unwrap();

                let (mut s_rd, mut s_wr) = tokio::io::split(server_io);
                let read_up = async move {
                    let mut wire_buf = BytesMut::new();
                    let mut acc = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        while let Some(decoded) =
                            srv_rd_codec.try_decode_chunk(&mut wire_buf).unwrap()
                        {
                            match decoded {
                                Some(p) => acc.extend_from_slice(&p),
                                None => return acc,
                            }
                        }
                        let n = s_rd.read(&mut tmp).await.unwrap();
                        assert!(n > 0, "unexpected EOF before client VMess EOF chunk");
                        wire_buf.extend_from_slice(&tmp[..n]);
                    }
                };
                let write_down = async move {
                    s_wr.write_all(&resp_hdr).await.unwrap();
                    for slice in server_down.chunks(4096) {
                        let mut out = BytesMut::new();
                        srv_wr_codec.encode_chunk(slice, &mut out).unwrap();
                        s_wr.write_all(&out).await.unwrap();
                    }
                    let mut eof = BytesMut::new();
                    srv_wr_codec.encode_eof_chunk(&mut eof).unwrap();
                    s_wr.write_all(&eof).await.unwrap();
                    s_wr.flush().await.unwrap();
                    let _ = s_wr.shutdown().await;
                };

                let (got_up, ()) = tokio::join!(read_up, write_down);
                assert_eq!(got_up, expected_up);
            });

            let cli_write = async move {
                for slice in up_payload.chunks(2048) {
                    cli_wr.write_all(slice).await.unwrap();
                }
                cli_wr.flush().await.unwrap();
                cli_wr.shutdown().await.unwrap();
            };
            let cli_read = async move {
                let mut got_down = Vec::new();
                cli_rd.read_to_end(&mut got_down).await.unwrap();
                got_down
            };

            let ((), got_down, srv_res) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(cli_write, cli_read, srv_task)
            })
            .await
            .expect("64 KiB/64 KiB split bidir over BufferedFlushTransport must not deadlock");
            srv_res.unwrap();
            assert_eq!(got_down, down_payload);
        }

        // Part B: Deterministic single-write-waker proof for post-hdr_flushed opportunistic flush:
        // (1) If Task W is ALREADY parked on poll_flush while hdr_flushed && inner_needs_flush,
        //     Task R's poll_read must NOT clobber inner's write waker.
        // (2) If Task R parks on opportunistic poll_flush (Pending) and THEN Task W arrives and
        //     parks on poll_flush (Pending), firing inner's single write waker must wake BOTH.
        struct FlushControllableSingleWriteWakerStream {
            allow_bytes: usize,
            flush_ready: bool,
            stored_write_waker: Option<Waker>,
        }

        impl AsyncRead for FlushControllableSingleWriteWakerStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for FlushControllableSingleWriteWakerStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.allow_bytes == 0 {
                    self.stored_write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let take = buf.len().min(self.allow_bytes);
                self.allow_bytes -= take;
                Poll::Ready(Ok(take))
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.flush_ready {
                    Poll::Ready(Ok(()))
                } else {
                    self.stored_write_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Subcase B1: Task W parks on poll_flush while hdr_flushed == true -> Task R must not clobber W.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let mock = FlushControllableSingleWriteWakerStream {
                allow_bytes: 1024,
                flush_ready: true,
                stored_write_waker: None,
            };
            let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            let w_hits = Arc::new(AtomicUsize::new(0));
            let r_hits = Arc::new(AtomicUsize::new(0));
            let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
            let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
            let mut cx_w = Context::from_waker(&waker_w);
            let mut cx_r = Context::from_waker(&waker_r);

            // Flush request header cleanly so hdr_flushed == true.
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.hdr_flushed);

            // Next write is accepted into inner (write_buf empty), then poll_flush parks Pending.
            stream.inner.flush_ready = false;
            assert_eq!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx_w, b"req2-payload")
                    .map(|r| r.unwrap()),
                Poll::Ready(12)
            );
            assert!(stream.write_buf.is_empty());
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Pending
            ));

            // Concurrent poll_read must NOT overwrite inner's write waker; instead it registers
            // in persistent `tx_fanout` so firing `stored_write_waker` wakes Task W AND fans out
            // to Task R (preventing deadlock if Task W was cancelled).
            let mut out = [0u8; 16];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
                Poll::Pending
            ));

            stream
                .inner
                .stored_write_waker
                .take()
                .expect("inner write waker must be stored")
                .wake();
            assert_eq!(w_hits.load(Ordering::SeqCst), 1, "Task W must be woken");
            assert_eq!(
                r_hits.load(Ordering::SeqCst),
                1,
                "FanoutWaker must fan out to Task R while clearing stale write slot"
            );
            assert!(!stream.tx_fanout.has_write_waker());
        }

        // Subcase B2: Task R parks on opportunistic poll_flush (Pending), THEN Task W arrives
        // and parks on poll_flush (Pending) -> firing single write waker wakes BOTH W and R!
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let mock = FlushControllableSingleWriteWakerStream {
                allow_bytes: 1024,
                flush_ready: true,
                stored_write_waker: None,
            };
            let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            let w_hits = Arc::new(AtomicUsize::new(0));
            let r_hits = Arc::new(AtomicUsize::new(0));
            let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
            let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
            let mut cx_w = Context::from_waker(&waker_w);
            let mut cx_r = Context::from_waker(&waker_r);

            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.hdr_flushed);

            // Write without flush -> accepted into inner, write_waker is None.
            stream.inner.flush_ready = false;
            assert_eq!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx_w, b"req2-no-flush")
                    .map(|r| r.unwrap()),
                Poll::Ready(13)
            );
            assert!(stream.write_buf.is_empty());

            // Task R runs poll_read -> opportunistic poll_flush hits Pending.
            let mut out = [0u8; 16];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
                Poll::Pending
            ));

            // Task W then arrives and calls poll_flush -> hits Pending with FanoutWaker(W, R).
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Pending
            ));

            stream
                .inner
                .stored_write_waker
                .take()
                .expect("inner write waker must be stored")
                .wake();
            assert_eq!(w_hits.load(Ordering::SeqCst), 1, "Task W must be woken");
            assert_eq!(
                r_hits.load(Ordering::SeqCst),
                1,
                "Task R must also be woken"
            );
        }
    }

    #[tokio::test]
    async fn keepalive_req2_uplink_broken_pipe_delivers_multiframe_response_and_preserves_truncation_error()
     {
        struct StagedDownlinkBrokenFlushStream {
            downlink_stages: std::collections::VecDeque<Option<BytesMut>>,
            fail_flush: bool,
            broken_flush_calls: usize,
        }

        impl AsyncRead for StagedDownlinkBrokenFlushStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                loop {
                    match self.downlink_stages.front_mut() {
                        None => return Poll::Ready(Ok(())),
                        Some(None) => {
                            // Simulate one async Pending gap between response frames.
                            self.downlink_stages.pop_front();
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Some(Some(chunk)) => {
                            if chunk.is_empty() {
                                self.downlink_stages.pop_front();
                                continue;
                            }
                            let take = chunk.len().min(buf.remaining());
                            buf.put_slice(&chunk.split_to(take));
                            if chunk.is_empty() {
                                self.downlink_stages.pop_front();
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }

        impl AsyncWrite for StagedDownlinkBrokenFlushStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.fail_flush {
                    self.broken_flush_calls += 1;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "server closed uplink during Req #2 response",
                    )));
                }
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Part A: Request #2 BrokenPipe + 2-frame response separated by Pending gap + EOF chunk.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();

            let mut stage1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"REQ1-OK", &mut stage1).unwrap();

            let mut stage2_frame1 = BytesMut::new();
            srv_wr
                .encode_chunk(b"REQ2-FRAME-1:", &mut stage2_frame1)
                .unwrap();

            let mut stage2_frame2 = BytesMut::new();
            srv_wr
                .encode_chunk(b"REQ2-FRAME-2", &mut stage2_frame2)
                .unwrap();
            srv_wr.encode_eof_chunk(&mut stage2_frame2).unwrap();

            let mut stages = std::collections::VecDeque::new();
            stages.push_back(Some(stage1));
            stages.push_back(Some(stage2_frame1));
            stages.push_back(None); // Async Pending gap between Req #2 frames
            stages.push_back(Some(stage2_frame2));

            let mock = StagedDownlinkBrokenFlushStream {
                downlink_stages: stages,
                fail_flush: false,
                broken_flush_calls: 0,
            };
            let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            // Request #1 completes cleanly (hdr_flushed == true, resp_verified == true).
            client.write_all(b"req-1").await.unwrap();
            let mut r1 = [0u8; 7];
            client.read_exact(&mut r1).await.unwrap();
            assert_eq!(&r1, b"REQ1-OK");

            // Request #2 written without flush(); uplink now fails with BrokenPipe on poll_flush.
            client.inner.fail_flush = true;
            client.write_all(b"req-2-keepalive").await.unwrap();

            let mut r2 = Vec::new();
            client
                .read_to_end(&mut r2)
                .await
                .expect("multi-frame Req #2 response must be delivered despite uplink BrokenPipe");
            assert_eq!(r2, b"REQ2-FRAME-1:REQ2-FRAME-2");
            assert_eq!(
                client.inner.broken_flush_calls, 1,
                "poll_read must stop retrying broken uplink flush after resp_verified"
            );
        }

        // Part B: Request #2 BrokenPipe + truncated second VMess chunk -> MUST return UnexpectedEof.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();

            let mut stage1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"REQ1-OK", &mut stage1).unwrap();

            let mut stage2_trunc = BytesMut::new();
            srv_wr
                .encode_chunk(b"REQ2-TRUNCATED-BODY", &mut stage2_trunc)
                .unwrap();
            stage2_trunc.truncate(stage2_trunc.len() - 6);

            let mut stages = std::collections::VecDeque::new();
            stages.push_back(Some(stage1));
            stages.push_back(Some(stage2_trunc));

            let mock = StagedDownlinkBrokenFlushStream {
                downlink_stages: stages,
                fail_flush: false,
                broken_flush_calls: 0,
            };
            let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            client.write_all(b"req-1").await.unwrap();
            let mut r1 = [0u8; 7];
            client.read_exact(&mut r1).await.unwrap();
            assert_eq!(&r1, b"REQ1-OK");

            client.inner.fail_flush = true;
            client.write_all(b"req-2-keepalive").await.unwrap();

            let mut r2 = Vec::new();
            let err = client.read_to_end(&mut r2).await.expect_err(
                "truncated Req #2 VMess chunk after BrokenPipe must return UnexpectedEof",
            );
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert!(err.to_string().contains("truncated VMess chunk"));
        }
    }

    async fn make_tls_duplex_pair(
        duplex_cap: usize,
    ) -> (
        tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
    ) {
        let (server_tls_cfg, cert_der) =
            crate::crypto::tls::generate_self_signed_server_config(&[], &[]).unwrap();
        let client_tls_cfg =
            crate::crypto::tls::build_tls_client_config(false, &[cert_der], &[]).unwrap();
        let acceptor = TlsAcceptor::from(server_tls_cfg);
        let connector = TlsConnector::from(client_tls_cfg);
        let sni = crate::crypto::tls::parse_server_name("localhost").unwrap();

        let (client_io, server_io) = tokio::io::duplex(duplex_cap);
        let (cli_tls_res, srv_tls_res) = tokio::join!(
            connector.connect(sni, client_io),
            acceptor.accept(server_io)
        );
        (cli_tls_res.unwrap(), srv_tls_res.unwrap())
    }

    #[tokio::test]
    async fn same_task_select_unsolicited_push_drops_flush_req2_no_deadlock_raw_and_tls() {
        async fn run_case<C, S>(client_transport: C, mut server_io: S, label: &'static str)
        where
            C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let client = VmessClientStream::new(client_transport, wire_hdr, &req_hdr).unwrap();
            let (mut rd, mut wr) = tokio::io::split(client);

            let req1 = b"REQ1".to_vec();
            let req2 = vec![0x66u8; 2048];
            let expected_req1 = req1.clone();
            let expected_req2 = req2.clone();
            let (flush_parked_tx, flush_parked_rx) = tokio::sync::oneshot::channel::<()>();

            let srv = tokio::spawn(async move {
                let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                    .await
                    .unwrap();
                let mut srv_rd = VmessChunkCodec::new(
                    &decoded.req_key,
                    &decoded.req_iv,
                    decoded.security,
                    decoded.option,
                )
                .unwrap();
                let (resp_key, resp_iv) =
                    derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
                let mut srv_wr =
                    VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                        .unwrap();

                let mut wire_buf = BytesMut::new();
                let mut plain_buf = BytesMut::new();

                // Request #1: complete round-trip so hdr_flushed && resp_verified become true.
                let got1 = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected_req1.len(),
                )
                .await;
                assert_eq!(got1, expected_req1);
                let mut out1 = seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded.resp_v,
                    decoded.option,
                )
                .unwrap();
                srv_wr.encode_chunk(b"R1", &mut out1).unwrap();
                server_io.write_all(&out1).await.unwrap();
                server_io.flush().await.unwrap();

                // Wait until client's biased select! has polled wr.flush() -> Pending
                // (leaving stale same-task write_waker), then send unsolicited "PING!".
                flush_parked_rx.await.unwrap();
                let mut ping_out = BytesMut::new();
                srv_wr.encode_chunk(b"PING!", &mut ping_out).unwrap();
                server_io.write_all(&ping_out).await.unwrap();
                server_io.flush().await.unwrap();

                // Now drain Req #2 (2048 B) and reply "R2".
                let got2 = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected_req2.len(),
                )
                .await;
                assert_eq!(got2, expected_req2);
                let mut out2 = BytesMut::new();
                srv_wr.encode_chunk(b"R2", &mut out2).unwrap();
                srv_wr.encode_eof_chunk(&mut out2).unwrap();
                server_io.write_all(&out2).await.unwrap();
                server_io.flush().await.unwrap();
            });

            tokio::time::timeout(Duration::from_secs(2), async {
                // Req #1
                wr.write_all(&req1).await.unwrap();
                wr.flush().await.unwrap();
                let mut r1 = [0u8; 2];
                rd.read_exact(&mut r1).await.unwrap();
                assert_eq!(&r1, b"R1");

                // Req #2 saturates 256B duplex and leaves ciphertext stranded in write_buf / TLS.
                wr.write_all(&req2).await.unwrap();

                // Same-task biased select!: arm 1 (wr.flush) polls Pending first (setting
                // same-task write_waker), then arm 2 triggers server push "PING!", wins select!,
                // and drops wr.flush().
                let mut flush_parked_tx = Some(flush_parked_tx);
                let mut ping = [0u8; 5];
                tokio::select! {
                    biased;
                    res = wr.flush() => {
                        panic!("wr.flush() must park Pending before unsolicited PING! ({label}): {res:?}");
                    }
                    res = async {
                        if let Some(tx) = flush_parked_tx.take() {
                            let _ = tx.send(());
                        }
                        rd.read_exact(&mut ping).await
                    } => {
                        res.unwrap();
                    }
                }
                assert_eq!(&ping, b"PING!");

                // Subsequent read_exact on the same task MUST opportunistically drain Req #2
                // despite stale same-task write_waker instead of deadlocking.
                let mut r2 = [0u8; 2];
                rd.read_exact(&mut r2).await.unwrap();
                assert_eq!(&r2, b"R2");
            })
            .await
            .unwrap_or_else(|_| {
                panic!("same-task select! dropped wr.flush() deadlocked subsequent read ({label})")
            });

            srv.await.unwrap();
        }

        // Case 1 (Exploit #1): RAW tokio::io::duplex(256)
        {
            let (client_io, server_io) = tokio::io::duplex(256);
            run_case(client_io, server_io, "RAW duplex(256)").await;
        }

        // Case 2 (Exploit #3): Real tokio_rustls::client::TlsStream<DuplexStream(256)>
        {
            let (cli_tls, srv_tls) = make_tls_duplex_pair(256).await;
            run_case(cli_tls, srv_tls, "TlsStream<duplex(256)>").await;
        }
    }

    #[tokio::test]
    async fn timeout_cancelled_write_all_after_chunk1_accepted_then_read_completes_raw_duplex() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let mut client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();

        let (start_drain_tx, start_drain_rx) = tokio::sync::oneshot::channel::<()>();
        let expected_chunk1 = vec![0x5Au8; VMESS_MAX_CHUNK_PLAIN];

        let srv = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();

            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1
            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            // Stay paused until client's write_all(30_000) times out after accepting Chunk 1.
            start_drain_rx.await.unwrap();

            let got_chunk1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_chunk1.len(),
            )
            .await;
            assert_eq!(got_chunk1, expected_chunk1);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"OK2!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1 so hdr_flushed && resp_verified are true.
        client.write_all(b"REQ1").await.unwrap();
        client.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        client.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");
        assert!(client.hdr_flushed);
        assert!(client.resp_verified);

        // Cancel write_all(30_000) after Chunk 1 (15,000 B) is accepted into write_buf
        // and Chunk 2 parks Pending (leaving stale same-task write_waker).
        let large = vec![0x5Au8; 30_000];
        let timed_out =
            tokio::time::timeout(Duration::from_millis(20), client.write_all(&large)).await;
        assert!(
            timed_out.is_err(),
            "write_all(30_000) must park Pending on stalled duplex(256) and time out"
        );
        assert!(
            client.tx_fanout.has_write_waker(),
            "cancelled pending write_all leaves stale same-task write_tx waker"
        );
        assert!(
            !client.write_buf.is_empty(),
            "Chunk 1 ciphertext must remain buffered in write_buf"
        );

        // Release server to drain Chunk 1 and reply "OK2!".
        start_drain_tx.send(()).unwrap();

        let mut r2 = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut r2))
            .await
            .expect("read_exact after timeout-cancelled write_all(30K) must not deadlock")
            .unwrap();
        assert_eq!(&r2, b"OK2!");
        assert!(client.write_buf.is_empty());
        assert!(!client.tx_fanout.has_write_waker());

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn timeout_cancelled_flush_keepalive_req2_then_read_completes_over_tls() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (cli_tls, mut srv_tls) = make_tls_duplex_pair(256).await;
        let mut client = VmessClientStream::new(cli_tls, wire_hdr, &req_hdr).unwrap();

        let (start_drain_tx, start_drain_rx) = tokio::sync::oneshot::channel::<()>();
        let req2 = vec![0x77u8; 2048];
        let expected_req2 = req2.clone();

        let srv = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut srv_tls)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();

            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1
            let got1 =
                read_vmess_plain_exact(&mut srv_tls, &mut srv_rd, &mut wire_buf, &mut plain_buf, 4)
                    .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            srv_tls.write_all(&out1).await.unwrap();
            srv_tls.flush().await.unwrap();

            // Wait until client's Req #2 flush() times out.
            start_drain_rx.await.unwrap();

            let got2 = read_vmess_plain_exact(
                &mut srv_tls,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"OK2!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            srv_tls.write_all(&out2).await.unwrap();
            srv_tls.flush().await.unwrap();
        });

        // Complete Req #1 over real TlsStream.
        client.write_all(b"REQ1").await.unwrap();
        client.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        client.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");
        assert!(client.hdr_flushed);
        assert!(client.resp_verified);

        // Write Req #2 (2048 B), then cancel flush() via timeout while server is paused.
        client.write_all(&req2).await.unwrap();
        let timed_out = tokio::time::timeout(Duration::from_millis(20), client.flush()).await;
        assert!(
            timed_out.is_err(),
            "flush() on stalled TlsStream<duplex(256)> must time out"
        );
        assert!(
            client.tx_fanout.has_write_waker(),
            "cancelled pending flush() leaves stale same-task write_tx waker"
        );

        // Unblock server and assert subsequent read_exact completes without deadlock.
        start_drain_tx.send(()).unwrap();
        let mut r2 = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut r2))
            .await
            .expect(
                "read_exact after timeout-cancelled Req #2 flush() on TlsStream must not deadlock",
            )
            .unwrap();
        assert_eq!(&r2, b"OK2!");
        assert!(client.write_buf.is_empty());
        assert!(!client.inner_needs_flush);
        assert!(!client.tx_fanout.has_write_waker());

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn poll_write_and_poll_shutdown_reset_stale_uplink_broken_after_resp_flag() {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum IoMode {
            Ready,
            Pending,
            BrokenPipe,
        }

        struct ControllableCounterTransport {
            write_mode: IoMode,
            flush_mode: IoMode,
            write_calls: usize,
            flush_calls: usize,
            downlink: std::collections::VecDeque<BytesMut>,
        }

        impl AsyncRead for ControllableCounterTransport {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                while let Some(front) = self.downlink.front_mut() {
                    if front.is_empty() {
                        self.downlink.pop_front();
                        continue;
                    }
                    let take = front.len().min(buf.remaining());
                    buf.put_slice(&front.split_to(take));
                    if front.is_empty() {
                        self.downlink.pop_front();
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            }
        }

        impl AsyncWrite for ControllableCounterTransport {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.write_calls += 1;
                match self.write_mode {
                    IoMode::Ready => Poll::Ready(Ok(data.len())),
                    IoMode::Pending => Poll::Pending,
                    IoMode::BrokenPipe => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mock write broken",
                    ))),
                }
            }

            fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flush_calls += 1;
                match self.flush_mode {
                    IoMode::Ready => Poll::Ready(Ok(())),
                    IoMode::Pending => Poll::Pending,
                    IoMode::BrokenPipe => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mock flush broken",
                    ))),
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Helper that establishes hdr_flushed == true, resp_verified == true, and genuinely
        // triggers uplink_broken_after_resp == true via a Req #2 BrokenPipe flush on poll_read.
        async fn setup_with_broken_after_resp() -> VmessClientStream<ControllableCounterTransport> {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();

            let mut f1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"R1", &mut f1).unwrap();
            let mut f2 = BytesMut::new();
            srv_wr.encode_chunk(b"R2", &mut f2).unwrap();

            let mut downlink = std::collections::VecDeque::new();
            downlink.push_back(f1);
            downlink.push_back(f2);

            let mock = ControllableCounterTransport {
                write_mode: IoMode::Ready,
                flush_mode: IoMode::Ready,
                write_calls: 0,
                flush_calls: 0,
                downlink,
            };
            let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            // Req #1 establishes hdr_flushed && resp_verified.
            client.write_all(b"req1").await.unwrap();
            let mut r1 = [0u8; 2];
            client.read_exact(&mut r1).await.unwrap();
            assert_eq!(&r1, b"R1");
            assert!(client.hdr_flushed);
            assert!(client.resp_verified);
            assert!(!client.uplink_broken_after_resp);

            // Req #2 write succeeds into inner, then opportunistic flush hits BrokenPipe -> sets flag.
            client.inner.flush_mode = IoMode::BrokenPipe;
            client.write_all(b"req2").await.unwrap();
            let mut r2 = [0u8; 2];
            client.read_exact(&mut r2).await.unwrap();
            assert_eq!(&r2, b"R2");
            assert!(
                client.uplink_broken_after_resp,
                "Req #2 BrokenPipe after resp_verified must set uplink_broken_after_resp"
            );
            client
        }

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker(Arc::clone(&hits))));
        let mut cx = Context::from_waker(&waker);

        // Subcase A: poll_write whose initial poll_drain_write_buf returns Pending MUST reset
        // uplink_broken_after_resp so a subsequent poll_read drives opportunistic drain + flush.
        {
            let mut client = setup_with_broken_after_resp().await;
            client.inner.write_mode = IoMode::Pending;
            client.inner.flush_mode = IoMode::Pending;

            let n = Pin::new(&mut client)
                .poll_write(&mut cx, b"fresh-req3")
                .map(|r| r.unwrap());
            assert_eq!(n, Poll::Ready(10));
            assert!(!client.write_buf.is_empty());
            assert!(
                !client.uplink_broken_after_resp,
                "poll_write buffering new chunk must clear stale uplink_broken_after_resp"
            );

            client.inner.write_mode = IoMode::Ready;
            client.inner.flush_mode = IoMode::Ready;
            let writes_before = client.inner.write_calls;
            let flushes_before = client.inner.flush_calls;

            let mut out = [0u8; 16];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut client).poll_read(&mut cx, &mut rb),
                Poll::Pending
            ));
            assert!(
                client.inner.write_calls > writes_before,
                "poll_read must opportunistically drain newly buffered write_buf"
            );
            assert!(
                client.inner.flush_calls > flushes_before,
                "poll_read must opportunistically flush after draining write_buf"
            );
            assert!(client.write_buf.is_empty());
            assert!(!client.inner_needs_flush);
        }

        // Subcase B: poll_shutdown encoding EOF chunk while initial drain returns Pending MUST
        // reset uplink_broken_after_resp so a subsequent same-task poll_read drains & flushes EOF.
        {
            let mut client = setup_with_broken_after_resp().await;
            client.inner.write_mode = IoMode::Pending;
            client.inner.flush_mode = IoMode::Pending;

            assert!(matches!(
                Pin::new(&mut client).poll_shutdown(&mut cx),
                Poll::Pending
            ));
            assert!(client.eof_sent);
            assert!(!client.write_buf.is_empty());
            assert!(client.tx_fanout.has_write_waker());
            assert!(
                !client.uplink_broken_after_resp,
                "poll_shutdown buffering EOF chunk must clear stale uplink_broken_after_resp"
            );

            client.inner.write_mode = IoMode::Ready;
            client.inner.flush_mode = IoMode::Ready;
            let writes_before = client.inner.write_calls;
            let flushes_before = client.inner.flush_calls;

            let mut out = [0u8; 16];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut client).poll_read(&mut cx, &mut rb),
                Poll::Pending
            ));
            assert!(
                client.inner.write_calls > writes_before,
                "poll_read must opportunistically drain buffered EOF chunk"
            );
            assert!(
                client.inner.flush_calls > flushes_before,
                "poll_read must opportunistically flush after draining EOF chunk"
            );
            assert!(client.write_buf.is_empty());
            assert!(!client.inner_needs_flush);
            assert!(!client.tx_fanout.has_write_waker());
        }
    }

    #[tokio::test]
    async fn split_task_writer_isolation_preserves_waker_and_error_routing_while_same_task_wakes_on_drain()
     {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum FlushBehavior {
            Ready,
            Pending,
            BrokenPipe,
        }

        struct IsolationTransport {
            flush_behavior: FlushBehavior,
            flush_calls: usize,
            stored_write_waker: Option<Waker>,
            downlink: BytesMut,
        }

        impl AsyncRead for IsolationTransport {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.downlink.is_empty() {
                    return Poll::Pending;
                }
                let take = self.downlink.len().min(buf.remaining());
                buf.put_slice(&self.downlink.split_to(take));
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for IsolationTransport {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flush_calls += 1;
                match self.flush_behavior {
                    FlushBehavior::Ready => Poll::Ready(Ok(())),
                    FlushBehavior::Pending => {
                        self.stored_write_waker = Some(cx.waker().clone());
                        Poll::Pending
                    }
                    FlushBehavior::BrokenPipe => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "writer-owned flush error",
                    ))),
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Part A: Split-stream Task W != Task R isolation — when Task W is parked in poll_flush,
        // Task R's poll_read must NOT invoke inner.poll_flush, must NOT clobber Task W's waker,
        // and must NOT steal Task W's BrokenPipe error.
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
            let mut downlink = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                req_hdr.resp_v,
                req_hdr.option,
            )
            .unwrap();
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option)
                    .unwrap();
            srv_wr.encode_chunk(b"OK", &mut downlink).unwrap();

            let mock = IsolationTransport {
                flush_behavior: FlushBehavior::Ready,
                flush_calls: 0,
                stored_write_waker: None,
                downlink,
            };
            let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            let w_hits = Arc::new(AtomicUsize::new(0));
            let r_hits = Arc::new(AtomicUsize::new(0));
            let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
            let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
            let mut cx_w = Context::from_waker(&waker_w);
            let mut cx_r = Context::from_waker(&waker_r);

            // Establish hdr_flushed && resp_verified.
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Ready(Ok(()))
            ));
            let mut out = [0u8; 2];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(rb.filled(), b"OK");
            assert!(stream.hdr_flushed);
            assert!(stream.resp_verified);

            // Task W writes Req #2 and parks Pending on poll_flush.
            stream.inner.flush_behavior = FlushBehavior::Pending;
            assert_eq!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx_w, b"req2")
                    .map(|r| r.unwrap()),
                Poll::Ready(4)
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_w),
                Poll::Pending
            ));

            // Now arm a BrokenPipe on the next inner.poll_flush.
            stream.inner.flush_behavior = FlushBehavior::BrokenPipe;
            let flushes_before = stream.inner.flush_calls;

            // Concurrent Task R calls poll_read: must NOT touch inner.poll_flush or steal error!
            let mut out2 = [0u8; 16];
            let mut rb2 = ReadBuf::new(&mut out2);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb2),
                Poll::Pending
            ));
            assert_eq!(
                stream.inner.flush_calls, flushes_before,
                "Task R must not poll inner.poll_flush while separate Task W is parked"
            );
            assert!(
                !stream.uplink_broken_after_resp,
                "Task R must not have swallowed Task W's BrokenPipe error"
            );

            // Firing stored inner write waker wakes Task W (zero clobbering) AND fans out to
            // Task R (atomically clearing `write_tx` so a cancelled writer can never deadlock R).
            stream
                .inner
                .stored_write_waker
                .take()
                .expect("Task W's waker must remain stored in inner")
                .wake();
            assert_eq!(w_hits.load(Ordering::SeqCst), 1);
            assert_eq!(r_hits.load(Ordering::SeqCst), 1);
            assert!(!stream.tx_fanout.has_write_waker());

            // Task W re-polls poll_flush and receives BrokenPipe directly.
            let err = match Pin::new(&mut stream).poll_flush(&mut cx_w) {
                Poll::Ready(Err(e)) => e,
                other => panic!("Task W must observe BrokenPipe directly, got {other:?}"),
            };
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }

        // Part B: Same-task poll_read completing opportunistic drain wakes & clears stale
        // same-task write_tx waker exactly once (no spin loop on subsequent polls).
        {
            let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
            let mock = IsolationTransport {
                flush_behavior: FlushBehavior::Ready,
                flush_calls: 0,
                stored_write_waker: None,
                downlink: BytesMut::new(),
            };
            let mut stream = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

            let t_hits = Arc::new(AtomicUsize::new(0));
            let waker_t = Waker::from(Arc::new(CountingWaker(Arc::clone(&t_hits))));
            let mut cx_t = Context::from_waker(&waker_t);

            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_t),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.hdr_flushed);

            stream.inner.flush_behavior = FlushBehavior::Pending;
            assert_eq!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx_t, b"req2")
                    .map(|r| r.unwrap()),
                Poll::Ready(4)
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx_t),
                Poll::Pending
            ));
            assert!(stream.tx_fanout.has_write_waker());

            // Transport becomes ready; same-task poll_read completes opportunistic flush,
            // wakes the stored same-task write_tx waker once, and clears the slot.
            stream.inner.flush_behavior = FlushBehavior::Ready;
            let mut out = [0u8; 16];
            let mut rb = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_t, &mut rb),
                Poll::Pending
            ));
            assert!(!stream.inner_needs_flush);
            assert!(!stream.tx_fanout.has_write_waker());
            assert_eq!(
                t_hits.load(Ordering::SeqCst),
                1,
                "same-task write_tx waker must be woken once on opportunistic drain completion"
            );

            // Subsequent poll_read must not re-wake (zero spin loop).
            let mut rb2 = ReadBuf::new(&mut out);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx_t, &mut rb2),
                Poll::Pending
            ));
            assert_eq!(t_hits.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_bufstream_cancelled_flush_then_reader_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (c_raw, mut server_io) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let client = VmessClientStream::new(c_buf, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        let req2: Vec<u8> = (0..4096).map(|i| ((i * 19 + 5) & 0xff) as u8).collect();
        let expected_req2 = req2.clone();
        let (buffered_tx, buffered_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1 completes cleanly -> establishes hdr_flushed && resp_verified.
            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            // Wait until split Task W cancels flush() on timeout, then drain Req #2.
            start_srv_rx.await.unwrap();
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"BUF-CNCL-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1 so keepalive state (hdr_flushed && resp_verified) is active.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Split Task W buffers 4096 B in BufStream, parks in flush() against full duplex(256),
        // and drops flush() on timeout leaving a dead writer waker in tx_fanout.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req2).await.unwrap();
            let _ = buffered_tx.send(());
            let timed_out = tokio::time::timeout(Duration::from_millis(60), c_wr.flush())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected BufStream flush() on stalled duplex(256) to time out"
            );
        });

        buffered_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Split Task R != Task W starts read_exact while Task W is parked in flush().
        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 12];
            c_rd.read_exact(&mut reply).await.unwrap();
            let mut tail = Vec::new();
            c_rd.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
            reply
        });

        // Wait until Task W's flush() is cancelled and dropped, then let server drain duplex(256).
        wr_task.await.unwrap();
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<BufStream<duplex(256)>> split Task R deadlocked after Task W cancelled flush()",
        );
        assert_eq!(&reply, b"BUF-CNCL-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_raw_duplex_cancelled_flush_unsolicited_push_then_reader_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        let req2: Vec<u8> = (0..4096).map(|i| ((i * 23 + 11) & 0xff) as u8).collect();
        let expected_req2 = req2.clone();
        let (written_tx, written_rx) = tokio::sync::oneshot::channel::<()>();
        let (send_push_tx, send_push_rx) = tokio::sync::oneshot::channel::<()>();
        let (push_received_tx, push_received_rx) = tokio::sync::oneshot::channel::<()>();
        let (drain_req2_tx, drain_req2_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1 establishes hdr_flushed && resp_verified.
            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            // After Task W cancels flush(), send unsolicited "PUSH" BEFORE draining duplex(256).
            send_push_rx.await.unwrap();
            let mut push_out = BytesMut::new();
            srv_wr.encode_chunk(b"PUSH", &mut push_out).unwrap();
            server_io.write_all(&push_out).await.unwrap();
            server_io.flush().await.unwrap();

            // Now wait until Task R has consumed "PUSH" and re-entered read_exact(&mut reply),
            // THEN drain Req #2 from duplex(256) and send the reply.
            drain_req2_rx.await.unwrap();
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"RAW-PUSH-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Split Task W writes 4096 B (256 B enter duplex, ~3858 B remain in write_buf), then
        // timeout-cancels flush() leaving stale dead writer waker in tx_fanout.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req2).await.unwrap();
            let _ = written_tx.send(());
            let timed_out = tokio::time::timeout(Duration::from_millis(60), c_wr.flush())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected raw duplex(256) flush() to time out while server is paused"
            );
        });

        written_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Split Task R reads unsolicited "PUSH" (which clears read_tx/parked_read on Ready(Ok)),
        // then immediately calls read_exact(&mut reply) which must re-register guard.0 and drain
        // Req #2 once server starts draining duplex(256).
        let rd_task = tokio::spawn(async move {
            let mut push = [0u8; 4];
            c_rd.read_exact(&mut push).await.unwrap();
            assert_eq!(&push, b"PUSH");
            let _ = push_received_tx.send(());

            let mut reply = [0u8; 12];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        // Wait for Task W's flush() timeout cancellation, then send unsolicited PUSH.
        wr_task.await.unwrap();
        let _ = send_push_tx.send(());

        // Wait until Task R receives PUSH and parks in read_exact(&mut reply), then drain Req #2.
        push_received_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = drain_req2_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<duplex(256)> split Task R deadlocked after cancelled flush() + unsolicited PUSH",
        );
        assert_eq!(&reply, b"RAW-PUSH-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_bufstream_uncancelled_multi_write_without_flush_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (c_raw, mut server_io) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let client = VmessClientStream::new(c_buf, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        let part_a: Vec<u8> = (0..4096).map(|i| ((i * 7 + 1) & 0xff) as u8).collect();
        let part_b: Vec<u8> = (0..10_000).map(|i| ((i * 13 + 3) & 0xff) as u8).collect();
        let part_c: Vec<u8> = (0..100).map(|i| ((i * 29 + 9) & 0xff) as u8).collect();
        let mut expected_req2 = Vec::with_capacity(part_a.len() + part_b.len() + part_c.len());
        expected_req2.extend_from_slice(&part_a);
        expected_req2.extend_from_slice(&part_b);
        expected_req2.extend_from_slice(&part_c);

        let (w1_done_tx, w1_done_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            start_srv_rx.await.unwrap();
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"BUF-NOFL-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Zero-cancellation multi-write (4096 B + 10_000 B + 100 B) WITHOUT calling flush().
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&part_a).await.unwrap();
            let _ = w1_done_tx.send(());
            c_wr.write_all(&part_b).await.unwrap();
            c_wr.write_all(&part_c).await.unwrap();
        });

        w1_done_rx.await.unwrap();
        // Let Task W fill BufStream + duplex(256) and park Pending on part_c pre-drain.
        tokio::time::sleep(Duration::from_millis(25)).await;

        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 12];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (wr_res, rd_res, srv_res) = tokio::join!(wr_task, rd_task, srv_task);
            wr_res.unwrap();
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<BufStream<duplex(256)>> split Task R deadlocked with zero-cancellation multi-write without flush()",
        );
        assert_eq!(&reply, b"BUF-NOFL-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_raw_duplex_parked_reader_then_write_without_flush_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        let req2: Vec<u8> = (0..4096).map(|i| ((i * 31 + 17) & 0xff) as u8).collect();
        let expected_req2 = req2.clone();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            // Wait until Task W has finished write_all(4096 B) without flush() and exited.
            start_srv_rx.await.unwrap();
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"RAW-PARK-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Pre-park split Task R in read_exact BEFORE Task W writes Req #2.
        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 12];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Split Task W writes 4096 B (256 B into duplex, ~3858 B left in write_buf) WITHOUT
        // flush() and exits -> must wake parked Task R via `parked_read` (`guard.2`).
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req2).await.unwrap();
        });
        wr_task.await.unwrap();

        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<duplex(256)> pre-parked split Task R deadlocked when Task W wrote without flush()",
        );
        assert_eq!(&reply, b"RAW-PARK-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_bufstream_multi_round_chunk_boundary_race_without_flush() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (c_raw, mut server_io) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let client = VmessClientStream::new(c_buf, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        let sizes: [usize; 16] = [
            17,
            255,
            256,
            257,
            4096,
            8191,
            8192,
            8193,
            14_999,
            VMESS_MAX_CHUNK_PLAIN,
            VMESS_MAX_CHUNK_PLAIN + 1,
            16_384,
            100,
            4096 + 8192 + 37,
            2048,
            VMESS_MAX_CHUNK_PLAIN * 2 + 5,
        ];
        let requests: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(round, &sz)| {
                (0..sz)
                    .map(|i| ((i * 37 + round * 13 + 7) & 0xff) as u8)
                    .collect()
            })
            .collect();
        let expected_requests = requests.clone();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();
            let mut first_resp = Some(
                seal_vmess_aead_response_header(
                    &resp_key,
                    &resp_iv,
                    decoded.resp_v,
                    decoded.option,
                )
                .unwrap(),
            );

            for (round, expected) in expected_requests.iter().enumerate() {
                let got = read_vmess_plain_exact(
                    &mut server_io,
                    &mut srv_rd,
                    &mut wire_buf,
                    &mut plain_buf,
                    expected.len(),
                )
                .await;
                assert_eq!(&got, expected, "mismatch on round {round}");

                let mut out = first_resp.take().unwrap_or_default();
                let tag = format!("R{round:02}-OK!");
                srv_wr.encode_chunk(tag.as_bytes(), &mut out).unwrap();
                if round + 1 == expected_requests.len() {
                    srv_wr.encode_eof_chunk(&mut out).unwrap();
                }
                server_io.write_all(&out).await.unwrap();
                server_io.flush().await.unwrap();
            }
        });

        // Drive all 16 rounds from separate split writer/reader tasks WITHOUT ever calling flush(),
        // alternating whether Task W writes first or Task R parks first on odd/even rounds.
        let (wr_go_tx, mut wr_go_rx) = mpsc::channel::<usize>(1);
        let (rd_go_tx, mut rd_go_rx) = mpsc::channel::<usize>(1);
        let (wr_done_tx, mut wr_done_rx) = mpsc::channel::<usize>(1);
        let (rd_done_tx, mut rd_done_rx) = mpsc::channel::<(usize, [u8; 7])>(1);

        let wr_task = tokio::spawn(async move {
            while let Some(round) = wr_go_rx.recv().await {
                // Split multi-part writes on every 3rd round to exercise BufStream boundaries.
                let payload = &requests[round];
                if round % 3 == 0 && payload.len() > 100 {
                    let mid = payload.len() / 2;
                    c_wr.write_all(&payload[..mid]).await.unwrap();
                    c_wr.write_all(&payload[mid..]).await.unwrap();
                } else {
                    c_wr.write_all(payload).await.unwrap();
                }
                wr_done_tx.send(round).await.unwrap();
            }
        });

        let rd_task = tokio::spawn(async move {
            while let Some(round) = rd_go_rx.recv().await {
                let mut tag = [0u8; 7];
                c_rd.read_exact(&mut tag).await.unwrap();
                rd_done_tx.send((round, tag)).await.unwrap();
            }
            let mut tail = Vec::new();
            c_rd.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            for round in 0..sizes.len() {
                if round % 2 == 0 {
                    wr_go_tx.send(round).await.unwrap();
                    rd_go_tx.send(round).await.unwrap();
                } else {
                    rd_go_tx.send(round).await.unwrap();
                    tokio::task::yield_now().await;
                    wr_go_tx.send(round).await.unwrap();
                }
                let wr_r = wr_done_rx.recv().await.unwrap();
                let (rd_r, tag) = rd_done_rx.recv().await.unwrap();
                assert_eq!(wr_r, round);
                assert_eq!(rd_r, round);
                assert_eq!(tag, format!("R{round:02}-OK!").as_bytes());
            }
            drop(wr_go_tx);
            drop(rd_go_tx);
            wr_task.await.unwrap();
            rd_task.await.unwrap();
            srv_task.await.unwrap();
        })
        .await
        .expect("16-round multi-thread BufStream split race without flush() deadlocked");
    }

    #[tokio::test]
    async fn vmess_read_plain_buf_survives_uplink_broken_pipe_before_drain() {
        struct DownlinkThenBrokenUplink {
            downlink: BytesMut,
            break_uplink: bool,
        }

        impl AsyncRead for DownlinkThenBrokenUplink {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.downlink.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let take = self.downlink.len().min(buf.remaining());
                buf.put_slice(&self.downlink.split_to(take));
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for DownlinkThenBrokenUplink {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.break_uplink {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "uplink broken",
                    )))
                } else {
                    Poll::Ready(Ok(data.len()))
                }
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.break_uplink {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "uplink flush broken",
                    )))
                } else {
                    Poll::Ready(Ok(()))
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (_cmd_key, req_hdr, wire_hdr) = make_vmess_pair();
        let (resp_key, resp_iv) = derive_response_key_and_iv(&req_hdr.req_key, &req_hdr.req_iv);
        let mut downlink =
            seal_vmess_aead_response_header(&resp_key, &resp_iv, req_hdr.resp_v, req_hdr.option)
                .unwrap();
        let mut srv_wr =
            VmessChunkCodec::new(&resp_key, &resp_iv, req_hdr.security, req_hdr.option).unwrap();
        let payload: Vec<u8> = (0u8..64u8).collect();
        srv_wr.encode_chunk(&payload, &mut downlink).unwrap();
        srv_wr.encode_eof_chunk(&mut downlink).unwrap();

        let mock = DownlinkThenBrokenUplink {
            downlink,
            break_uplink: false,
        };
        let mut client = VmessClientStream::new(mock, wire_hdr, &req_hdr).unwrap();

        // Read first 8 bytes -> decodes full 64-byte chunk, leaving 56 bytes in `read_plain_buf`.
        let mut head = [0u8; 8];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, &payload[..8]);
        assert_eq!(client.read_plain_buf.len(), 56);

        // Queue a new write and break uplink before reading remaining 56 bytes.
        client.inner.break_uplink = true;
        let write_err = client.write(b"after-partial-read").await.unwrap_err();
        assert_eq!(write_err.kind(), io::ErrorKind::BrokenPipe);

        // Already-decoded plaintext in `read_plain_buf` + EOF MUST survive intact.
        let mut rest = Vec::new();
        client
            .read_to_end(&mut rest)
            .await
            .expect("already-decoded read_plain_buf bytes must survive uplink BrokenPipe");
        assert_eq!(rest, payload[8..]);

        // Writer still observes BrokenPipe directly on flush().
        let flush_err = client.flush().await.unwrap_err();
        assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);
    }

    fn make_vmess_pair_unpadded() -> ([u8; 16], VmessRequestHeader, BytesMut) {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd_key = derive_cmd_key(&uuid);
        let target = TargetAddr::new_domain("example.com", 443).unwrap();
        let req_hdr =
            VmessRequestHeader::new_random(VmessSecurity::Aes128Gcm, false, VMESS_CMD_TCP, target);
        let wire_hdr = seal_vmess_aead_request_header(&cmd_key, &req_hdr).unwrap();
        (cmd_key, req_hdr, wire_hdr)
    }

    async fn read_vmess_eof<S: AsyncRead + Unpin>(
        server_io: &mut S,
        rd_codec: &mut VmessChunkCodec,
        wire_buf: &mut BytesMut,
    ) {
        let mut tmp = [0u8; 256];
        loop {
            if let Some(decoded) = rd_codec.try_decode_chunk(wire_buf).unwrap() {
                match decoded {
                    None => return,
                    Some(extra) => {
                        panic!(
                            "unexpected {} extra plaintext bytes while waiting for VMess EOF chunk",
                            extra.len()
                        )
                    }
                }
            }
            let n = server_io.read(&mut tmp).await.unwrap();
            assert!(
                n > 0,
                "unexpected transport EOF before receiving authenticated VMess EOF chunk"
            );
            wire_buf.extend_from_slice(&tmp[..n]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_raw_duplex_pre_parked_reader_cancelled_shutdown_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair_unpadded();
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let client = VmessClientStream::new(client_io, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        // 238 B plaintext + 18 B VMess AEAD chunk framing (2 B masked len + 16 B GCM tag, no
        // global padding) = exact 256 B wire size, filling duplex(256) 256/256 on flush().
        let req2: Vec<u8> = (0..238).map(|i| ((i * 17 + 3) & 0xff) as u8).collect();
        let expected_req2 = req2.clone();

        let (req2_flushed_tx, req2_flushed_rx) = tokio::sync::oneshot::channel::<()>();
        let (do_shutdown_tx, do_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1 keepalive succeeds -> establishes hdr_flushed && resp_verified.
            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            // Pause until Task W has filled duplex(256), Task R has pre-parked, and Task W's
            // shutdown() has been cancelled via timeout.
            start_srv_rx.await.unwrap();

            // Drain Req #2 and wait for the client's authenticated 18 B VMess EOF chunk before
            // sending the reply (standard half-close RPC pattern).
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);
            read_vmess_eof(&mut server_io, &mut srv_rd, &mut wire_buf).await;

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"RAW-SHUT-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1 keepalive cleanly.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Split Task W fills duplex(256) 256/256 with write_buf.is_empty() && !inner_needs_flush,
        // waits for Task R to pre-park, then runs timeout(30ms, c_wr.shutdown()) (cancelled).
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req2).await.unwrap();
            c_wr.flush().await.unwrap();
            let _ = req2_flushed_tx.send(());

            do_shutdown_rx.await.unwrap();
            let timed_out = tokio::time::timeout(Duration::from_millis(30), c_wr.shutdown())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected raw duplex(256) shutdown() to time out while pipe is 256/256 full"
            );
        });

        req2_flushed_rx.await.unwrap();

        // Pre-park split Task R in read_to_end() BEFORE Task W calls shutdown().
        let rd_task = tokio::spawn(async move {
            let mut reply = Vec::new();
            c_rd.read_to_end(&mut reply).await.unwrap();
            reply
        });
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Trigger Task W's timeout-cancelled shutdown(), wait until Task W exits, then let server
        // drain Req #2 and wait for the authenticated VMess EOF chunk.
        let _ = do_shutdown_tx.send(());
        wr_task.await.unwrap();
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<duplex(256)> pre-parked split Task R deadlocked after timeout-cancelled shutdown()",
        );
        assert_eq!(&reply, b"RAW-SHUT-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vmess_split_bufstream_pre_parked_reader_cancelled_shutdown_completes() {
        let (cmd_key, req_hdr, wire_hdr) = make_vmess_pair_unpadded();
        let (c_raw, mut server_io) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let client = VmessClientStream::new(c_buf, wire_hdr, &req_hdr).unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(client);

        // 238 B plaintext + 18 B VMess AEAD chunk framing = exact 256 B wire size.
        // flush() pushes all 256 B through BufStream into duplex(256), leaving write_buf empty
        // and inner_needs_flush == false while duplex(256) is 256/256 full.
        let req2: Vec<u8> = (0..238).map(|i| ((i * 29 + 7) & 0xff) as u8).collect();
        let expected_req2 = req2.clone();

        let (req2_flushed_tx, req2_flushed_rx) = tokio::sync::oneshot::channel::<()>();
        let (do_shutdown_tx, do_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let decoded = read_vmess_aead_request_header(&cmd_key, &mut server_io)
                .await
                .unwrap();
            let mut srv_rd = VmessChunkCodec::new(
                &decoded.req_key,
                &decoded.req_iv,
                decoded.security,
                decoded.option,
            )
            .unwrap();
            let (resp_key, resp_iv) = derive_response_key_and_iv(&decoded.req_key, &decoded.req_iv);
            let mut srv_wr =
                VmessChunkCodec::new(&resp_key, &resp_iv, decoded.security, decoded.option)
                    .unwrap();
            let mut wire_buf = BytesMut::new();
            let mut plain_buf = BytesMut::new();

            // Req #1 keepalive succeeds -> establishes hdr_flushed && resp_verified.
            let got1 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                4,
            )
            .await;
            assert_eq!(got1, b"REQ1");
            let mut out1 = seal_vmess_aead_response_header(
                &resp_key,
                &resp_iv,
                decoded.resp_v,
                decoded.option,
            )
            .unwrap();
            srv_wr.encode_chunk(b"OK1!", &mut out1).unwrap();
            server_io.write_all(&out1).await.unwrap();
            server_io.flush().await.unwrap();

            start_srv_rx.await.unwrap();

            // Drain Req #2 and wait for the client's authenticated 18 B VMess EOF chunk (which
            // was buffered inside BufStream during Task W's cancelled shutdown()).
            let got2 = read_vmess_plain_exact(
                &mut server_io,
                &mut srv_rd,
                &mut wire_buf,
                &mut plain_buf,
                expected_req2.len(),
            )
            .await;
            assert_eq!(got2, expected_req2);
            read_vmess_eof(&mut server_io, &mut srv_rd, &mut wire_buf).await;

            let mut out2 = BytesMut::new();
            srv_wr.encode_chunk(b"BUF-SHUT-OK!", &mut out2).unwrap();
            srv_wr.encode_eof_chunk(&mut out2).unwrap();
            server_io.write_all(&out2).await.unwrap();
            server_io.flush().await.unwrap();
        });

        // Complete Req #1 keepalive cleanly.
        c_wr.write_all(b"REQ1").await.unwrap();
        c_wr.flush().await.unwrap();
        let mut r1 = [0u8; 4];
        c_rd.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"OK1!");

        // Split Task W fills duplex(256) 256/256 through BufStream, waits for Task R to pre-park,
        // then runs timeout(30ms, c_wr.shutdown()) (copies 18 B EOF into BufStream, parks in
        // inner.poll_flush, and cancels on timeout).
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req2).await.unwrap();
            c_wr.flush().await.unwrap();
            let _ = req2_flushed_tx.send(());

            do_shutdown_rx.await.unwrap();
            let timed_out = tokio::time::timeout(Duration::from_millis(30), c_wr.shutdown())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected BufStream<duplex(256)> shutdown() to time out while pipe is 256/256 full"
            );
        });

        req2_flushed_rx.await.unwrap();

        // Pre-park split Task R in read_to_end() BEFORE Task W calls shutdown().
        let rd_task = tokio::spawn(async move {
            let mut reply = Vec::new();
            c_rd.read_to_end(&mut reply).await.unwrap();
            reply
        });
        tokio::time::sleep(Duration::from_millis(25)).await;

        let _ = do_shutdown_tx.send(());
        wr_task.await.unwrap();
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VmessClientStream<BufStream<duplex(256)>> pre-parked split Task R deadlocked after timeout-cancelled shutdown()",
        );
        assert_eq!(&reply, b"BUF-SHUT-OK!");
    }
}
