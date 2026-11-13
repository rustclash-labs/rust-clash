pub mod frame;
pub mod padding;
pub mod session;
pub mod uot;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA256, digest};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::RwLock;
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    addr::{HostName, TargetAddr},
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        anytls::{
            frame::{Command, Frame},
            padding::PaddingScheme,
            session::{AnyTlsClientSession, AnyTlsSessionPool, AnyTlsStream},
            uot::{
                AnyTlsUdpSession, UOT_V1_MAGIC_DOMAIN, UOT_V2_MAGIC_DOMAIN, encode_uot_v2_request,
                handle_uot_server_stream,
            },
        },
    },
};

#[derive(Clone)]
pub struct AnyTlsOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_session: usize,
    pub udp: bool,
}

/// Pure-Rust AnyTLS v2 Outbound Client with LIFO `SessionPool`, dynamic `PaddingScheme`,
/// and `sing/common/uot` v2 (`sp.v2.udp-over-tcp.arpa`) stateful UDP-over-TCP support.
pub struct AnyTlsOutbound {
    cfg: AnyTlsOutboundConfig,
    tls_connector: TlsConnector,
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    pool: Arc<AnyTlsSessionPool>,
    preconnect_lock: tokio::sync::Mutex<()>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

impl AnyTlsOutbound {
    pub fn new(cfg: AnyTlsOutboundConfig) -> io::Result<Self> {
        let client_cfg = crate::crypto::tls::build_tls_client_config(
            cfg.skip_cert_verify,
            &cfg.extra_ca_der,
            &cfg.alpn,
        )?;
        let pool = AnyTlsSessionPool::new(
            cfg.idle_session_check_interval,
            cfg.idle_session_timeout,
            cfg.min_idle_session,
        );
        Ok(Self {
            cfg,
            tls_connector: TlsConnector::from(client_cfg),
            padding_scheme: Arc::new(RwLock::new(PaddingScheme::default())),
            pool,
            preconnect_lock: tokio::sync::Mutex::new(()),
            dns: None,
        })
    }

    pub fn with_dns(mut self, dns: Option<Arc<crate::dns::FakeIpDnsEngine>>) -> Self {
        self.dns = dns;
        self
    }

    pub fn current_padding_md5(&self) -> String {
        self.padding_scheme.read().md5_hex().to_string()
    }

    pub fn pool(&self) -> &Arc<AnyTlsSessionPool> {
        &self.pool
    }

    pub async fn connect_anytls_stream(&self, target: &TargetAddr) -> io::Result<AnyTlsStream> {
        self.connect_anytls_stream_with_payload(target, &[]).await
    }

    pub async fn connect_anytls_stream_with_payload(
        &self,
        target: &TargetAddr,
        initial_payload: &[u8],
    ) -> io::Result<AnyTlsStream> {
        // 1. Try reusing highest-Seq idle session first (up to 2 retries if stale)
        for _ in 0..2 {
            let Some(idle_sess) = self.pool.pop_latest_idle() else {
                break;
            };
            match idle_sess
                .open_stream_with_payload(target, initial_payload)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(_) => continue,
            }
        }

        // 2. Otherwise establish a new TLS + AnyTLS v2 Session
        let seq = self.pool.next_seq();
        let (_sess, stream) = AnyTlsClientSession::connect_with_payload_and_dns(
            seq,
            &self.cfg.server,
            self.cfg.port,
            &self.cfg.sni,
            &self.cfg.password,
            &self.tls_connector,
            Arc::clone(&self.padding_scheme),
            self.pool.pool_context(),
            target,
            initial_payload,
            self.dns.as_deref(),
        )
        .await?;
        Ok(stream)
    }
}

#[async_trait]
impl OutboundHandler for AnyTlsOutbound {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "AnyTLS-v2"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.cfg.server, self.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        self.cfg.udp
    }

    fn on_network_change(&self) -> usize {
        self.pool.on_network_change()
    }

    fn set_low_power_mode(&self, enabled: bool) {
        self.pool.set_low_power_mode(enabled);
    }

    async fn preconnect(&self, target_sessions: usize) -> io::Result<()> {
        if target_sessions == 0 {
            return Ok(());
        }
        if let Some(dns) = &self.dns {
            dns.prewarm_proxy_server_ips(&self.cfg.server)
                .await
                .map_err(|e| e.into_io())?;
        }
        let goal = target_sessions.min(4);
        if goal > 1 {
            self.pool.set_dynamic_min_idle(goal);
        }
        let _guard = self.preconnect_lock.lock().await;
        while self.pool.idle_count() < goal && self.pool.healthy_session_count() < goal + 4 {
            let seq = self.pool.next_seq();
            AnyTlsClientSession::preconnect_idle(
                seq,
                &self.cfg.server,
                self.cfg.port,
                &self.cfg.sni,
                &self.cfg.password,
                &self.tls_connector,
                Arc::clone(&self.padding_scheme),
                self.pool.pool_context(),
                self.dns.as_deref(),
            )
            .await?;
        }
        Ok(())
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let stream = self.connect_anytls_stream(target).await?;
        Ok(Box::new(stream))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this AnyTLS outbound",
            ));
        }
        let uot_target = TargetAddr::new_domain(UOT_V2_MAGIC_DOMAIN, 0)?;
        let dummy_dest =
            TargetAddr::new_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut hdr = BytesMut::with_capacity(8);
        encode_uot_v2_request(false, &dummy_dest, &mut hdr)?;
        let stream = self
            .connect_anytls_stream_with_payload(&uot_target, &hdr)
            .await?;
        Ok(Box::new(AnyTlsUdpSession::new_pre_initialized(stream)))
    }

    async fn exchange_udp(
        &self,
        target: &TargetAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if !self.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this AnyTLS outbound",
            ));
        }
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS UDP datagram exceeds 65535 bytes",
            ));
        }

        tokio::time::timeout(timeout, async {
            let uot_target = TargetAddr::new_domain(UOT_V2_MAGIC_DOMAIN, 0)?;
            // Coalesce connected (`isConnect = 1`) UoT v2 header + datagram directly into initial cmdPSH
            // so `anytls-server` (Go) reads `uot.ReadRequest` immediately before sending `cmdSYNACK`.
            let mut req = BytesMut::with_capacity(32 + payload.len());
            encode_uot_v2_request(true, target, &mut req)?;
            req.put_u16(payload.len() as u16);
            req.put_slice(payload);
            let mut stream = self
                .connect_anytls_stream_with_payload(&uot_target, &req)
                .await?;

            let resp_len = stream.read_u16().await? as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await?;
            Ok(resp)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS UoT UDP timed out"))?
    }
}

/// Full wire-authentic AnyTLS v2 Server implementation (supports SHA-256 + `padding0` auth,
/// `cmdSettings` enforcement before `cmdSYN`, `cmdServerSettings`, `cmdUpdatePaddingScheme` push,
/// multiplexed streams over TLS, `cmdSYNACK` reporting, `cmdHeartRequest`/`Response`,
/// and `sing/common/uot` v1 & v2 UDP-over-TCP).
pub struct AnyTlsServerConfig {
    pub listen_addr: String,
    pub password: String,
    pub tls_config: Arc<ServerConfig>,
    pub padding_scheme: PaddingScheme,
}

pub async fn spawn_anytls_server(
    cfg: AnyTlsServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let local_addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(cfg.tls_config);
    let expected_hash: [u8; 32] = digest(&SHA256, cfg.password.as_bytes())
        .as_ref()
        .try_into()
        .expect("32-byte SHA-256");
    let scheme = Arc::new(cfg.padding_scheme);

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
                    let acceptor_clone = acceptor.clone();
                    let scheme_clone = Arc::clone(&scheme);
                    tokio::spawn(async move {
                        let _ = handle_anytls_server_conn(tcp, acceptor_clone, expected_hash, scheme_clone).await;
                    });
                }
            }
        }
    });

    Ok((local_addr, handle))
}

async fn handle_anytls_server_conn(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    expected_hash: [u8; 32],
    scheme: Arc<PaddingScheme>,
) -> io::Result<()> {
    let mut tls = acceptor.accept(tcp).await?;

    // 1. Read Packet 0: `[sha256(password) : 32B] [padding0_len : u16 BE] [padding0]`
    let mut auth_hdr = [0u8; 34];
    tls.read_exact(&mut auth_hdr).await?;
    let mut got_hash = [0u8; 32];
    got_hash.copy_from_slice(&auth_hdr[..32]);
    let mut diff = 0u8;
    for (a, b) in got_hash.iter().zip(expected_hash.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "AnyTLS password mismatch",
        ));
    }
    let pad0_len = u16::from_be_bytes([auth_hdr[32], auth_hdr[33]]) as usize;
    if pad0_len > 0 {
        let mut pad0 = vec![0u8; pad0_len];
        tls.read_exact(&mut pad0).await?;
    }

    let (mut rd, mut wr) = tokio::io::split(tls);
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

    let scheme_wr = Arc::clone(&scheme);
    tokio::spawn(async move {
        let mut pkt_idx = 1u32;
        while let Some(first) = rx.recv().await {
            let mut batch = BytesMut::new();
            if first.encode_into(&mut batch).is_err() {
                break;
            }
            while let Ok(more) = rx.try_recv() {
                let _ = more.encode_into(&mut batch);
                if batch.len() >= 32 * 1024 {
                    break;
                }
            }
            let chunks = scheme_wr.shape_tls_writes(&mut pkt_idx, batch);
            let mut err = false;
            for c in chunks {
                if wr.write_all(&c).await.is_err() {
                    err = true;
                    break;
                }
            }
            if err || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut received_settings = false;
    let mut client_v2 = false;
    let stream_writers: Arc<DashMap<u32, mpsc::UnboundedSender<Bytes>>> = Arc::new(DashMap::new());

    loop {
        let frame = match Frame::read_from(&mut rd).await {
            Ok(f) => f,
            Err(_) => break,
        };

        match frame.cmd {
            Command::Waste | Command::HeartResponse => {}
            Command::HeartRequest => {
                let _ = tx.send(Frame::empty(Command::HeartResponse, frame.stream_id));
            }
            Command::Settings => {
                received_settings = true;
                let text = String::from_utf8_lossy(&frame.data);
                let mut client_md5 = "";
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        match k.trim() {
                            "v" => {
                                if v.trim().parse::<u32>().unwrap_or(1) >= 2 {
                                    client_v2 = true;
                                }
                            }
                            "padding-md5" => client_md5 = v.trim(),
                            _ => {}
                        }
                    }
                }
                if client_v2 {
                    let _ = tx.send(Frame::new(
                        Command::ServerSettings,
                        0,
                        Bytes::from_static(b"v=2"),
                    ));
                }
                if !client_md5.eq_ignore_ascii_case(scheme.md5_hex()) {
                    let _ = tx.send(Frame::new(
                        Command::UpdatePaddingScheme,
                        0,
                        Bytes::copy_from_slice(scheme.raw().as_bytes()),
                    ));
                }
            }
            Command::Syn => {
                if !received_settings {
                    let _ = tx.send(Frame::new(
                        Command::Alert,
                        0,
                        Bytes::from_static(b"cmdSettings required before cmdSYN"),
                    ));
                    break;
                }
                let sid = frame.stream_id;
                let (stx, mut srx) = mpsc::unbounded_channel::<Bytes>();
                stream_writers.insert(sid, stx);
                let tx_clone = tx.clone();
                let writers_clone = Arc::clone(&stream_writers);
                let is_v2 = client_v2;

                tokio::spawn(async move {
                    let mut addr_buf = BytesMut::new();
                    let target_and_rest = loop {
                        let Some(chunk) = srx.recv().await else {
                            return;
                        };
                        addr_buf.extend_from_slice(&chunk);
                        match TargetAddr::decode_socks5_slice(&addr_buf) {
                            Ok((target, used)) => {
                                let rest = addr_buf.split_off(used).freeze();
                                break Ok((target, rest));
                            }
                            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => continue,
                            Err(e) => break Err(e),
                        }
                    };

                    let (target, initial_payload) = match target_and_rest {
                        Ok(v) => v,
                        Err(e) => {
                            writers_clone.remove(&sid);
                            if is_v2 {
                                let _ = tx_clone.send(Frame::new(
                                    Command::SynAck,
                                    sid,
                                    Bytes::from(e.to_string()),
                                ));
                            }
                            return;
                        }
                    };

                    // Dispatch SagerNet `sing/common/uot` v2 (`sp.v2.udp-over-tcp.arpa`) and v1 (`udp-over-tcp.arpa`) streams!
                    if let HostName::Domain(ref d) = target.host {
                        if d.eq_ignore_ascii_case(UOT_V2_MAGIC_DOMAIN) {
                            handle_uot_server_stream(
                                true,
                                is_v2,
                                sid,
                                initial_payload,
                                srx,
                                tx_clone,
                                writers_clone,
                            )
                            .await;
                            return;
                        }
                        if d.eq_ignore_ascii_case(UOT_V1_MAGIC_DOMAIN) {
                            handle_uot_server_stream(
                                false,
                                is_v2,
                                sid,
                                initial_payload,
                                srx,
                                tx_clone,
                                writers_clone,
                            )
                            .await;
                            return;
                        }
                    }

                    let direct = DirectOutbound::default();
                    let mut outbound = match direct.connect_tcp(&target).await {
                        Ok(s) => {
                            if is_v2 {
                                let _ = tx_clone.send(Frame::empty(Command::SynAck, sid));
                            }
                            s
                        }
                        Err(e) => {
                            writers_clone.remove(&sid);
                            if is_v2 {
                                let _ = tx_clone.send(Frame::new(
                                    Command::SynAck,
                                    sid,
                                    Bytes::from(e.to_string()),
                                ));
                            } else {
                                let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
                            }
                            return;
                        }
                    };

                    if !initial_payload.is_empty()
                        && outbound.write_all(&initial_payload).await.is_err()
                    {
                        writers_clone.remove(&sid);
                        let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
                        return;
                    }

                    let (mut out_rd, mut out_wr) = tokio::io::split(outbound);
                    let to_remote = tokio::spawn(async move {
                        while let Some(data) = srx.recv().await {
                            if out_wr.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        let _ = out_wr.shutdown().await;
                    });

                    let mut rbuf = vec![0u8; 16 * 1024];
                    loop {
                        match out_rd.read(&mut rbuf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx_clone
                                    .send(Frame::new(
                                        Command::Psh,
                                        sid,
                                        Bytes::copy_from_slice(&rbuf[..n]),
                                    ))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    if writers_clone.remove(&sid).is_some() {
                        let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
                    }
                    let _ = to_remote.await;
                });
            }
            Command::Psh => {
                if let Some(stx) = stream_writers.get(&frame.stream_id) {
                    let _ = stx.send(frame.data);
                }
            }
            Command::Fin => {
                stream_writers.remove(&frame.stream_id);
            }
            _ => {}
        }
    }

    Ok(())
}
