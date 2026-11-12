use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::AbortHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{
    addr::TargetAddr,
    outbound::anytls::{
        frame::{Command, Frame},
        padding::PaddingScheme,
    },
};

const MAX_DATA_CHUNK: usize = 32 * 1024;

enum OutgoingReq {
    /// First stream batch on a brand-new session (`cmdSettings + cmdSYN + cmdPSH(SocksAddr)`)
    /// or subsequent stream open (`cmdSYN + cmdPSH(SocksAddr)`).
    RawBatch(BytesMut),
    Frame(Frame),
}

/// Shared pool metadata passed into each `AnyTlsClientSession` so pre-handoff TLS connections
/// can never be returned to the idle pool after `AnyTlsSessionPool::on_network_change()`.
#[derive(Clone)]
pub struct SessionPoolContext {
    idle: Arc<Mutex<Vec<IdleSessionEntry>>>,
    live: Arc<Mutex<Vec<Weak<AnyTlsClientSession>>>>,
    pool_epoch: Arc<AtomicU64>,
    session_epoch: u64,
}

/// A multiplexed AnyTLS v2 client session over a single TLS connection.
pub struct AnyTlsClientSession {
    pub seq: u64,
    session_epoch: u64,
    pool_epoch: Arc<AtomicU64>,
    next_stream_id: AtomicU32,
    active_streams: AtomicU32,
    healthy: AtomicBool,
    negotiated_v2: AtomicBool,
    tx: mpsc::UnboundedSender<OutgoingReq>,
    streams: Arc<DashMap<u32, mpsc::UnboundedSender<io::Result<Bytes>>>>,
    synack_waiters: Arc<DashMap<u32, oneshot::Sender<io::Result<()>>>>,
    pool_return: Arc<Mutex<Vec<IdleSessionEntry>>>,
    io_aborts: Mutex<(Option<AbortHandle>, Option<AbortHandle>)>,
}

pub struct IdleSessionEntry {
    pub session: Arc<AnyTlsClientSession>,
    pub idle_since: Instant,
}

impl AnyTlsClientSession {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        seq: u64,
        server_host: &str,
        server_port: u16,
        sni: &str,
        password: &str,
        tls_connector: &TlsConnector,
        shared_scheme: Arc<RwLock<PaddingScheme>>,
        pool_ctx: SessionPoolContext,
        initial_target: &TargetAddr,
    ) -> io::Result<(Arc<Self>, AnyTlsStream)> {
        Self::connect_with_payload(
            seq,
            server_host,
            server_port,
            sni,
            password,
            tls_connector,
            shared_scheme,
            pool_ctx,
            initial_target,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_payload(
        seq: u64,
        server_host: &str,
        server_port: u16,
        sni: &str,
        password: &str,
        tls_connector: &TlsConnector,
        shared_scheme: Arc<RwLock<PaddingScheme>>,
        pool_ctx: SessionPoolContext,
        initial_target: &TargetAddr,
        initial_payload: &[u8],
    ) -> io::Result<(Arc<Self>, AnyTlsStream)> {
        Self::connect_with_payload_and_dns(
            seq,
            server_host,
            server_port,
            sni,
            password,
            tls_connector,
            shared_scheme,
            pool_ctx,
            initial_target,
            initial_payload,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_payload_and_dns(
        seq: u64,
        server_host: &str,
        server_port: u16,
        sni: &str,
        password: &str,
        tls_connector: &TlsConnector,
        shared_scheme: Arc<RwLock<PaddingScheme>>,
        pool_ctx: SessionPoolContext,
        initial_target: &TargetAddr,
        initial_payload: &[u8],
        dns: Option<&crate::dns::FakeIpDnsEngine>,
    ) -> io::Result<(Arc<Self>, AnyTlsStream)> {
        let tcp = crate::platform::socket_protect::protected_tcp_connect_host_with_dns(
            server_host,
            server_port,
            dns,
        )
        .await?;
        let server_name = crate::crypto::tls::parse_server_name(sni)?;
        let mut tls_stream: TlsStream<TcpStream> = tls_connector.connect(server_name, tcp).await?;

        let scheme_snapshot = shared_scheme.read().clone();

        // Packet 0: Authentication `sha256(password) [32B] | padding0_len [u16 BE] | padding0`
        let pw_hash = digest(&SHA256, password.as_bytes());
        let pad0_len = scheme_snapshot.sample_padding0_len();
        let mut auth_pkt = BytesMut::with_capacity(34 + pad0_len as usize);
        auth_pkt.put_slice(pw_hash.as_ref());
        auth_pkt.put_u16(pad0_len);
        auth_pkt.put_bytes(0, pad0_len as usize);
        tls_stream.write_all(&auth_pkt).await?;
        tls_stream.flush().await?;

        let (mut rd, mut wr) = tokio::io::split(tls_stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<OutgoingReq>();
        let streams: Arc<DashMap<u32, mpsc::UnboundedSender<io::Result<Bytes>>>> =
            Arc::new(DashMap::new());
        let synack_waiters: Arc<DashMap<u32, oneshot::Sender<io::Result<()>>>> =
            Arc::new(DashMap::new());

        let session = Arc::new(Self {
            seq,
            session_epoch: pool_ctx.session_epoch,
            pool_epoch: Arc::clone(&pool_ctx.pool_epoch),
            // Stream 1 is opened immediately in Packet 1 alongside cmdSettings
            next_stream_id: AtomicU32::new(2),
            active_streams: AtomicU32::new(1),
            healthy: AtomicBool::new(true),
            negotiated_v2: AtomicBool::new(false),
            tx: tx.clone(),
            streams: Arc::clone(&streams),
            synack_waiters: Arc::clone(&synack_waiters),
            pool_return: Arc::clone(&pool_ctx.idle),
            io_aborts: Mutex::new((None, None)),
        });

        // Register in pool live tracker so network changes can immediately abort the underlying TLS socket
        {
            let mut live_guard = pool_ctx.live.lock();
            live_guard.retain(|w| w.strong_count() > 0);
            live_guard.push(Arc::downgrade(&session));
        }

        // Register stream 1 before dispatching Packet 1
        let (s1_tx, s1_rx) = mpsc::unbounded_channel();
        streams.insert(1, s1_tx);
        let (synack_tx, synack_rx) = oneshot::channel();
        synack_waiters.insert(1, synack_tx);

        // Writer task: shapes packets 1..stop through `scheme_snapshot`
        let session_wr = Arc::clone(&session);
        let wr_join = tokio::spawn(async move {
            let mut pkt_idx = 1u32;
            while let Some(req) = rx.recv().await {
                let mut batch = BytesMut::new();
                match req {
                    OutgoingReq::RawBatch(b) => batch.extend_from_slice(&b),
                    OutgoingReq::Frame(f) => {
                        if f.encode_into(&mut batch).is_err() {
                            break;
                        }
                    }
                }
                // Coalesce immediately queued frames into the same logical TLS write
                while let Ok(more) = rx.try_recv() {
                    match more {
                        OutgoingReq::RawBatch(b) => batch.extend_from_slice(&b),
                        OutgoingReq::Frame(f) => {
                            let _ = f.encode_into(&mut batch);
                        }
                    }
                    if batch.len() >= 32 * 1024 {
                        break;
                    }
                }
                let chunks = scheme_snapshot.shape_tls_writes(&mut pkt_idx, batch);
                let mut write_failed = false;
                for chunk in chunks {
                    if wr.write_all(&chunk).await.is_err() {
                        write_failed = true;
                        break;
                    }
                }
                if write_failed || wr.flush().await.is_err() {
                    session_wr.mark_unhealthy("TLS write error");
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        // Reader task: demuxes frames, updates `shared_scheme` on `cmdUpdatePaddingScheme`, replies to heartbeats
        let session_rd = Arc::clone(&session);
        let scheme_rd = Arc::clone(&shared_scheme);
        let tx_pong = tx.clone();
        let rd_join = tokio::spawn(async move {
            loop {
                match Frame::read_from(&mut rd).await {
                    Ok(frame) => match frame.cmd {
                        Command::Waste | Command::HeartResponse => {}
                        Command::HeartRequest => {
                            let _ = tx_pong.send(OutgoingReq::Frame(Frame::empty(
                                Command::HeartResponse,
                                frame.stream_id,
                            )));
                        }
                        Command::ServerSettings => {
                            let text = String::from_utf8_lossy(&frame.data);
                            if text.lines().any(|l| l.trim() == "v=2") {
                                session_rd.negotiated_v2.store(true, Ordering::Relaxed);
                            }
                        }
                        Command::UpdatePaddingScheme => {
                            let text = String::from_utf8_lossy(&frame.data);
                            if let Ok(new_scheme) = PaddingScheme::parse(&text) {
                                *scheme_rd.write() = new_scheme;
                            }
                        }
                        Command::Alert => {
                            let msg = String::from_utf8_lossy(&frame.data).into_owned();
                            tracing::warn!("AnyTLS server alert on session #{seq}: {msg}");
                            session_rd.mark_unhealthy(&format!("AnyTLS server alert: {msg}"));
                            break;
                        }
                        Command::SynAck => {
                            if let Some((_, waiter)) =
                                session_rd.synack_waiters.remove(&frame.stream_id)
                            {
                                if frame.data.is_empty() {
                                    let _ = waiter.send(Ok(()));
                                } else {
                                    let err_msg = String::from_utf8_lossy(&frame.data).into_owned();
                                    session_rd.streams.remove(&frame.stream_id);
                                    let _ = waiter.send(Err(io::Error::new(
                                        io::ErrorKind::ConnectionRefused,
                                        format!("AnyTLS SYNACK error: {err_msg}"),
                                    )));
                                }
                            }
                        }
                        Command::Psh => {
                            // If a v1 server sends data directly without SYNACK, implicitly resolve waiter
                            if let Some((_, waiter)) =
                                session_rd.synack_waiters.remove(&frame.stream_id)
                            {
                                let _ = waiter.send(Ok(()));
                            }
                            if !frame.data.is_empty()
                                && let Some(stx) = session_rd.streams.get(&frame.stream_id)
                            {
                                let _ = stx.send(Ok(frame.data));
                            }
                        }
                        Command::Fin => {
                            if let Some((_, waiter)) =
                                session_rd.synack_waiters.remove(&frame.stream_id)
                            {
                                let _ = waiter.send(Ok(()));
                            }
                            // Per AnyTLS spec: on receiving remote cmdFIN, close local stream WITHOUT echoing cmdFIN
                            session_rd.streams.remove(&frame.stream_id);
                        }
                        Command::Syn | Command::Settings => {}
                    },
                    Err(err) => {
                        session_rd.mark_unhealthy(&format!("session read closed: {err}"));
                        break;
                    }
                }
            }
        });
        *session.io_aborts.lock() = (Some(wr_join.abort_handle()), Some(rd_join.abort_handle()));

        // Build Packet 1: `cmdSettings` + `cmdSYN(1)` + `cmdPSH(1, SocksAddr || initial_payload)`
        let settings_payload = format!(
            "v=2\nclient=rust-clash/{}\npadding-md5={}",
            env!("CARGO_PKG_VERSION"),
            shared_scheme.read().md5_hex()
        );
        let mut psh_body = BytesMut::with_capacity(32 + initial_payload.len());
        psh_body.extend_from_slice(&initial_target.to_socks5_bytes()?);
        psh_body.extend_from_slice(initial_payload);

        let mut pkt1 = BytesMut::with_capacity(128 + psh_body.len());
        Frame::new(Command::Settings, 0, Bytes::from(settings_payload)).encode_into(&mut pkt1)?;
        Frame::empty(Command::Syn, 1).encode_into(&mut pkt1)?;
        Frame::new(Command::Psh, 1, psh_body.freeze()).encode_into(&mut pkt1)?;

        tx.send(OutgoingReq::RawBatch(pkt1))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS session closed"))?;

        let stream_handle = AnyTlsStream {
            session: Arc::clone(&session),
            stream_id: 1,
            rx: s1_rx,
            read_buf: Bytes::new(),
        };

        // Wait briefly for v2 SYNACK if the server sends it rapidly, or proceed cleanly for v1 compatibility:
        // Wait: in v2, if server fails outbound connect it returns SYNACK(error); let's await SYNACK if negotiated_v2,
        // or wait up to a short handshake window if data/SYNACK arrives!
        // Actually, AnyTLS v2 servers send `cmdServerSettings` immediately upon `cmdSettings`, and `cmdSYNACK` once target connects!
        // Waiting on `synack_rx` with a reasonable connect timeout (10s) catches remote connection errors before returning `connect_tcp`!
        match tokio::time::timeout(Duration::from_secs(10), synack_rx).await {
            Ok(Ok(Ok(()))) => Ok((session, stream_handle)),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => {
                if !session.is_healthy() {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "AnyTLS session closed during stream handshake",
                    ))
                } else {
                    Ok((session, stream_handle))
                }
            }
            Err(_) => {
                if session.negotiated_v2.load(Ordering::Relaxed) {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "AnyTLS v2 cmdSYNACK timed out",
                    ))
                } else {
                    // v1 server never sends cmdServerSettings or cmdSYNACK
                    Ok((session, stream_handle))
                }
            }
        }
    }

    /// Open a new stream on an existing warm session (`cmdSYN + cmdPSH(SocksAddr)`).
    pub async fn open_stream(self: &Arc<Self>, target: &TargetAddr) -> io::Result<AnyTlsStream> {
        self.open_stream_with_payload(target, &[]).await
    }

    /// Open a new stream on an existing warm session coalescing `initial_payload` into `cmdPSH`.
    pub async fn open_stream_with_payload(
        self: &Arc<Self>,
        target: &TargetAddr,
        initial_payload: &[u8],
    ) -> io::Result<AnyTlsStream> {
        if !self.is_healthy() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS session is no longer healthy",
            ));
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        self.active_streams.fetch_add(1, Ordering::SeqCst);

        let (stx, srx) = mpsc::unbounded_channel();
        self.streams.insert(stream_id, stx);
        let (synack_tx, synack_rx) = oneshot::channel();
        self.synack_waiters.insert(stream_id, synack_tx);

        let mut psh_body = BytesMut::with_capacity(32 + initial_payload.len());
        psh_body.extend_from_slice(&target.to_socks5_bytes()?);
        psh_body.extend_from_slice(initial_payload);

        let mut batch = BytesMut::with_capacity(64 + psh_body.len());
        Frame::empty(Command::Syn, stream_id).encode_into(&mut batch)?;
        Frame::new(Command::Psh, stream_id, psh_body.freeze()).encode_into(&mut batch)?;

        if self.tx.send(OutgoingReq::RawBatch(batch)).is_err() {
            self.streams.remove(&stream_id);
            self.synack_waiters.remove(&stream_id);
            self.active_streams.fetch_sub(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS session writer closed",
            ));
        }

        let stream_handle = AnyTlsStream {
            session: Arc::clone(self),
            stream_id,
            rx: srx,
            read_buf: Bytes::new(),
        };

        if self.negotiated_v2.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_secs(10), synack_rx).await {
                Ok(Ok(Ok(()))) => Ok(stream_handle),
                Ok(Ok(Err(e))) => Err(e),
                Ok(Err(_)) => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "AnyTLS session dropped while opening multiplexed stream",
                )),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "AnyTLS v2 cmdSYNACK timed out on reused session",
                )),
            }
        } else {
            Ok(stream_handle)
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn send_ping(&self) -> bool {
        self.tx
            .send(OutgoingReq::Frame(Frame::empty(Command::HeartRequest, 0)))
            .is_ok()
    }

    fn mark_unhealthy_inner(&self, reason: &str) -> bool {
        if self.healthy.swap(false, Ordering::SeqCst) {
            let err_keys: Vec<u32> = self.synack_waiters.iter().map(|e| *e.key()).collect();
            for k in err_keys {
                if let Some((_, w)) = self.synack_waiters.remove(&k) {
                    let _ = w.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        reason.to_string(),
                    )));
                }
            }
            let stream_keys: Vec<u32> = self.streams.iter().map(|e| *e.key()).collect();
            for k in stream_keys {
                if let Some((_, stx)) = self.streams.remove(&k) {
                    let _ = stx.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        reason.to_string(),
                    )));
                }
            }
            true
        } else {
            false
        }
    }

    fn mark_unhealthy(&self, reason: &str) {
        let _ = self.mark_unhealthy_inner(reason);
    }

    /// Immediately fail all multiplexed streams and abort the underlying TLS reader/writer tasks
    /// so the stale OS socket closes without waiting for kernel TCP retransmission timeouts.
    pub fn abort_for_network_change(&self) -> bool {
        let was_healthy = self.mark_unhealthy_inner("network interface changed");
        let (wr_abort, rd_abort) = {
            let mut guard = self.io_aborts.lock();
            (guard.0.take(), guard.1.take())
        };
        if let Some(a) = wr_abort {
            a.abort();
        }
        if let Some(a) = rd_abort {
            a.abort();
        }
        was_healthy
    }

    fn on_stream_dropped(self: &Arc<Self>, stream_id: u32) {
        self.synack_waiters.remove(&stream_id);
        let was_present = self.streams.remove(&stream_id).is_some();
        if was_present && self.is_healthy() {
            let _ = self
                .tx
                .send(OutgoingReq::Frame(Frame::empty(Command::Fin, stream_id)));
        }
        let prev = self.active_streams.fetch_sub(1, Ordering::SeqCst);
        let same_epoch = self.session_epoch == self.pool_epoch.load(Ordering::SeqCst);
        if prev == 1 && self.is_healthy() && same_epoch {
            let mut idle = self.pool_return.lock();
            if self.session_epoch == self.pool_epoch.load(Ordering::SeqCst) && self.is_healthy() {
                idle.push(IdleSessionEntry {
                    session: Arc::clone(self),
                    idle_since: Instant::now(),
                });
            }
        }
    }
}

pub struct AnyTlsStream {
    session: Arc<AnyTlsClientSession>,
    stream_id: u32,
    rx: mpsc::UnboundedReceiver<io::Result<Bytes>>,
    read_buf: Bytes,
}

impl AnyTlsStream {
    pub fn session_seq(&self) -> u64 {
        self.session.seq
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.on_stream_dropped(self.stream_id);
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(mut chunk))) => {
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk.split_to(n));
                if !chunk.is_empty() {
                    self.read_buf = chunk;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            // Remote FIN removed sender from DashMap -> EOF!
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.session.is_healthy() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS session closed",
            )));
        }
        let n = buf.len().min(MAX_DATA_CHUNK);
        let frame = Frame::new(
            Command::Psh,
            self.stream_id,
            Bytes::copy_from_slice(&buf[..n]),
        );
        self.session
            .tx
            .send(OutgoingReq::Frame(frame))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS writer closed"))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // AnyTLS v2 `cmdFIN` tears down the entire multiplexed stream (not TCP write half-close);
        // keep the stream registered so responses can still be read until EOF or `Drop`.
        let _ = self;
        Poll::Ready(Ok(()))
    }
}

/// LIFO `SessionPool`: always reuses the healthy idle session with the highest `seq`
/// and periodically reaps sessions older than `idle_timeout` (preserving `min_idle_session`).
pub struct AnyTlsSessionPool {
    next_seq: AtomicU64,
    epoch: Arc<AtomicU64>,
    idle: Arc<Mutex<Vec<IdleSessionEntry>>>,
    live: Arc<Mutex<Vec<Weak<AnyTlsClientSession>>>>,
    total_reuses: AtomicU64,
    check_interval: Duration,
    idle_timeout: Duration,
    min_idle_session: usize,
    reaper_spawned: AtomicBool,
}

impl AnyTlsSessionPool {
    pub fn new(
        check_interval: Duration,
        idle_timeout: Duration,
        min_idle_session: usize,
    ) -> Arc<Self> {
        let idle = Arc::new(Mutex::new(Vec::<IdleSessionEntry>::new()));
        let live = Arc::new(Mutex::new(Vec::<Weak<AnyTlsClientSession>>::new()));
        let epoch = Arc::new(AtomicU64::new(1));
        let pool = Arc::new(Self {
            next_seq: AtomicU64::new(1),
            epoch,
            idle,
            live,
            total_reuses: AtomicU64::new(0),
            check_interval,
            idle_timeout,
            min_idle_session,
            reaper_spawned: AtomicBool::new(false),
        });
        pool.ensure_reaper_spawned();
        pool
    }

    fn ensure_reaper_spawned(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.reaper_spawned.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak_idle = Arc::downgrade(&self.idle);
        let epoch = Arc::clone(&self.epoch);
        let check_interval = self.check_interval;
        let idle_timeout = self.idle_timeout;
        let min_idle_session = self.min_idle_session;

        handle.spawn(async move {
            let mut ticker = tokio::time::interval(check_interval.max(Duration::from_secs(5)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(idle_arc) = weak_idle.upgrade() else {
                    break;
                };
                let cur_epoch = epoch.load(Ordering::SeqCst);
                let mut guard = idle_arc.lock();
                guard.retain(|e| e.session.is_healthy() && e.session.session_epoch == cur_epoch);
                // Sort descending by `seq` so index 0..min_idle_session are the newest sessions
                guard.sort_by_key(|a| std::cmp::Reverse(a.session.seq));
                let now = Instant::now();
                let mut idx = 0usize;
                guard.retain(|entry| {
                    let keep = idx < min_idle_session
                        || now.duration_since(entry.idle_since) < idle_timeout;
                    idx += 1;
                    if keep {
                        let _ = entry.session.send_ping();
                    } else {
                        entry.session.mark_unhealthy("idle timeout expired");
                    }
                    keep
                });
            }
        });
    }

    /// Pop the highest-`seq` healthy idle session matching the current network epoch, if any.
    pub fn pop_latest_idle(&self) -> Option<Arc<AnyTlsClientSession>> {
        let mut guard = self.idle.lock();
        let cur_epoch = self.epoch.load(Ordering::SeqCst);
        guard.retain(|e| e.session.is_healthy() && e.session.session_epoch == cur_epoch);
        if guard.is_empty() {
            return None;
        }
        // Pick the entry with the highest `seq`
        let best_idx = guard
            .iter()
            .enumerate()
            .max_by_key(|(_, e)| e.session.seq)
            .map(|(i, _)| i)?;
        let chosen = guard.swap_remove(best_idx);
        self.total_reuses.fetch_add(1, Ordering::Relaxed);
        Some(chosen.session)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn pool_context(&self) -> SessionPoolContext {
        self.ensure_reaper_spawned();
        SessionPoolContext {
            idle: Arc::clone(&self.idle),
            live: Arc::clone(&self.live),
            pool_epoch: Arc::clone(&self.epoch),
            session_epoch: self.epoch.load(Ordering::SeqCst),
        }
    }

    /// Evict and abort all idle and active AnyTLS TLS 1.3 sessions on network handoff
    /// (e.g. Wi-Fi <-> Cellular), preventing stale sockets from lingering or re-entering the pool.
    pub fn on_network_change(&self) -> usize {
        let drained_idle: Vec<IdleSessionEntry> = {
            let mut idle_guard = self.idle.lock();
            self.epoch.fetch_add(1, Ordering::SeqCst);
            std::mem::take(&mut *idle_guard)
        };
        let live_sessions: Vec<Arc<AnyTlsClientSession>> = {
            let mut live_guard = self.live.lock();
            let drained = std::mem::take(&mut *live_guard);
            drained.into_iter().filter_map(|w| w.upgrade()).collect()
        };

        let mut closed_count = 0usize;
        for entry in drained_idle {
            if entry.session.abort_for_network_change() {
                closed_count += 1;
            }
        }
        for sess in live_sessions {
            if sess.abort_for_network_change() {
                closed_count += 1;
            }
        }
        closed_count
    }

    pub fn idle_count(&self) -> usize {
        let mut guard = self.idle.lock();
        let cur_epoch = self.epoch.load(Ordering::SeqCst);
        guard.retain(|e| e.session.is_healthy() && e.session.session_epoch == cur_epoch);
        guard.len()
    }

    pub fn reuse_count(&self) -> u64 {
        self.total_reuses.load(Ordering::Relaxed)
    }

    pub fn active_padding_map_hint(&self) -> HashMap<&'static str, u64> {
        let mut m = HashMap::new();
        m.insert("idle_sessions", self.idle_count() as u64);
        m.insert("reused_streams", self.reuse_count());
        m
    }
}
