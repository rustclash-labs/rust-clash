pub mod h3_auth;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU32, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::RngCore;
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
};

use crate::{
    addr::TargetAddr,
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        hysteria2::h3_auth::{
            HY2_FRAME_TCP_REQUEST, HY2_STATUS_AUTH_OK, build_h3_control_stream_init,
            build_hy2_auth_response_frame, perform_hy2_client_auth, read_h3_headers_frame,
        },
        quic_common::{
            CachedQuicSlot, PortSpec, QuicBiStream, QuicCongestionControl, QuicSessionLease,
            QuicWorkLease, SalamanderObfs, bind_quinn_server_endpoint, build_quinn_client_config,
            build_quinn_server_config, build_quinn_transport_config, decode_quic_varint_slice,
            dial_protected_quic_connection, encode_quic_varint, read_quic_varint,
        },
    },
};

const HY2_MAX_TCP_MESSAGE_LEN: usize = 2048;
const HY2_MAX_TCP_PADDING_LEN: usize = 4096;
const HY2_MAX_UDP_DATAGRAM_WIRE: usize = 1150;

#[derive(Clone)]
pub struct Hysteria2OutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub ports: Option<String>,
    pub password: String,
    pub obfs_salamander_password: Option<String>,
    pub up_bytes_per_sec: u64,
    pub down_bytes_per_sec: u64,
    pub servername: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub udp: bool,
}

#[derive(Clone, Debug)]
struct Hy2UdpFrame {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: String,
    data: Vec<u8>,
}

impl Hy2UdpFrame {
    fn encode(&self, out: &mut BytesMut) -> io::Result<()> {
        let addr_bytes = self.addr.as_bytes();
        out.reserve(8 + 4 + addr_bytes.len() + self.data.len());
        out.put_u32(self.session_id);
        out.put_u16(self.packet_id);
        out.put_u8(self.frag_id);
        out.put_u8(self.frag_count);
        encode_quic_varint(addr_bytes.len() as u64, out)?;
        out.put_slice(addr_bytes);
        out.put_slice(&self.data);
        Ok(())
    }

    fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < 9 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Hysteria2 UDP datagram shorter than header",
            ));
        }
        let session_id = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let packet_id = u16::from_be_bytes([raw[4], raw[5]]);
        let frag_id = raw[6];
        let frag_count = raw[7];
        let (addr_len_u64, var_used) = decode_quic_varint_slice(&raw[8..])?;
        let addr_len = addr_len_u64 as usize;
        if addr_len == 0 || addr_len > HY2_MAX_TCP_MESSAGE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Hysteria2 UDP address length",
            ));
        }
        let data_start = 8 + var_used + addr_len;
        if raw.len() < data_start {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Hysteria2 UDP datagram address",
            ));
        }
        let addr = std::str::from_utf8(&raw[8 + var_used..data_start])
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid UTF-8 in Hysteria2 UDP address",
                )
            })?
            .to_string();
        Ok(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data: raw[data_start..].to_vec(),
        })
    }
}

fn fragment_hy2_udp_message(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    payload: &[u8],
    max_wire: usize,
) -> io::Result<Vec<Bytes>> {
    let mut addr_var = BytesMut::with_capacity(8);
    encode_quic_varint(addr.len() as u64, &mut addr_var)?;
    let hdr_len = 8 + addr_var.len() + addr.len();
    let max_chunk = max_wire.saturating_sub(hdr_len).max(256);

    if payload.len() <= max_chunk {
        let frame = Hy2UdpFrame {
            session_id,
            packet_id,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_string(),
            data: payload.to_vec(),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf)?;
        return Ok(vec![buf.freeze()]);
    }

    let frag_count = payload.len().div_ceil(max_chunk);
    if frag_count > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 UDP datagram requires more than 255 fragments",
        ));
    }
    let mut out = Vec::with_capacity(frag_count);
    for (idx, chunk) in payload.chunks(max_chunk).enumerate() {
        let frame = Hy2UdpFrame {
            session_id,
            packet_id,
            frag_id: idx as u8,
            frag_count: frag_count as u8,
            addr: addr.to_string(),
            data: chunk.to_vec(),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf)?;
        out.push(buf.freeze());
    }
    Ok(out)
}

#[derive(Default)]
struct Hy2Defragger {
    pkt_id: u16,
    frags: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl Hy2Defragger {
    fn feed(&mut self, frame: Hy2UdpFrame) -> Option<(Vec<u8>, String)> {
        if frame.frag_count <= 1 {
            return Some((frame.data, frame.addr));
        }
        if frame.frag_id >= frame.frag_count {
            return None;
        }
        let total = frame.frag_count as usize;
        if frame.packet_id != self.pkt_id || self.frags.len() != total {
            self.pkt_id = frame.packet_id;
            self.frags = vec![None; total];
            self.received = 0;
        }
        let idx = frame.frag_id as usize;
        if self.frags[idx].is_none() {
            self.frags[idx] = Some(frame.data);
            self.received += 1;
            if self.received == total {
                let mut full = Vec::new();
                for part in self.frags.iter_mut() {
                    if let Some(bytes) = part.take() {
                        full.extend_from_slice(&bytes);
                    }
                }
                self.frags.clear();
                self.received = 0;
                return Some((full, frame.addr));
            }
        }
        None
    }
}

struct Hy2AuthenticatedConn {
    lease: Arc<QuicSessionLease>,
    server_udp_enabled: bool,
    _h3_control_send: AsyncMutex<quinn::SendStream>,
    uni_drain_task: JoinHandle<()>,
    udp_demux_task: JoinHandle<()>,
    udp_sessions: Arc<DashMap<u32, mpsc::Sender<Hy2UdpFrame>>>,
    next_session_id: AtomicU32,
}

impl Drop for Hy2AuthenticatedConn {
    fn drop(&mut self) {
        self.uni_drain_task.abort();
        self.udp_demux_task.abort();
    }
}

impl Hy2AuthenticatedConn {
    fn is_usable(&self) -> bool {
        self.lease.is_usable()
    }

    fn is_idle(&self) -> bool {
        self.lease.active_work_count() == 0 && self.udp_sessions.is_empty()
    }
}

struct Hysteria2Inner {
    cfg: Hysteria2OutboundConfig,
    port_spec: PortSpec,
    salamander: Option<SalamanderObfs>,
    client_cfg: quinn::ClientConfig,
    connect_lock: AsyncMutex<()>,
    cached_conn: CachedQuicSlot<Hy2AuthenticatedConn>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct Hysteria2Outbound {
    inner: Arc<Hysteria2Inner>,
}

impl Hysteria2Inner {
    fn sni_host(&self) -> &str {
        self.cfg
            .servername
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.cfg.server.as_str())
    }

    fn reap_idle_for_low_power(&self) {
        if let Some(evicted) = self
            .cached_conn
            .reap_if_low_power_idle(Hy2AuthenticatedConn::is_idle)
        {
            evicted.lease.close_immediately(b"low power idle");
        }
    }

    async fn checkout_or_dial_session(
        self: &Arc<Self>,
    ) -> io::Result<(Arc<Hy2AuthenticatedConn>, QuicWorkLease)> {
        if let Some(pair) = self
            .cached_conn
            .checkout_if_usable(Hy2AuthenticatedConn::is_usable, |s| s.lease.acquire_work())
        {
            return Ok(pair);
        }
        let _guard = self.connect_lock.lock().await;
        if let Some(pair) = self
            .cached_conn
            .checkout_if_usable(Hy2AuthenticatedConn::is_usable, |s| s.lease.acquire_work())
        {
            return Ok(pair);
        }

        for attempt in 0..2 {
            let dial_gen = self.cached_conn.current_generation();
            let session = self.dial_fresh_session().await?;
            match self.cached_conn.store_if_generation_and_checkout(
                dial_gen,
                Arc::clone(&session),
                Hy2AuthenticatedConn::is_usable,
                |s| s.lease.acquire_work(),
            ) {
                Ok((replaced, work)) => {
                    if let Some(old) = replaced {
                        old.lease.close_immediately(b"replaced");
                    }
                    return Ok((session, work));
                }
                Err(stale) => {
                    stale.lease.close_immediately(b"stale network generation");
                    if attempt == 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "network switched during Hysteria2 QUIC handshake",
                        ));
                    }
                }
            }
        }
        unreachable!()
    }

    async fn preconnect_session(self: &Arc<Self>) -> io::Result<()> {
        if self.cached_conn.is_low_power_mode() {
            return Ok(());
        }
        if self
            .cached_conn
            .get_if(Hy2AuthenticatedConn::is_usable)
            .is_some()
        {
            return Ok(());
        }
        let _guard = self.connect_lock.lock().await;
        if self.cached_conn.is_low_power_mode()
            || self
                .cached_conn
                .get_if(Hy2AuthenticatedConn::is_usable)
                .is_some()
        {
            return Ok(());
        }
        let dial_gen = self.cached_conn.current_generation();
        let session = self.dial_fresh_session().await?;
        if let Err(rejected) = self.cached_conn.store_preconnect_if_generation(
            dial_gen,
            session,
            Hy2AuthenticatedConn::is_usable,
        ) {
            rejected
                .lease
                .close_immediately(b"preconnect superseded or low power");
        }
        Ok(())
    }

    async fn dial_fresh_session(self: &Arc<Self>) -> io::Result<Arc<Hy2AuthenticatedConn>> {
        let port = self.port_spec.pick_port();
        let (endpoint, conn, _, pre_epoch) = dial_protected_quic_connection(
            &self.cfg.server,
            port,
            self.sni_host(),
            &self.client_cfg,
            self.salamander.as_ref(),
            false,
            self.dns.as_deref(),
        )
        .await?;

        let auth_res: io::Result<(quinn::SendStream, bool)> =
            crate::outbound::with_handshake_timeout("Hysteria2 HTTP/3 auth", async {
                let mut h3_ctrl = conn
                    .open_uni()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;
                let ctrl_init = build_h3_control_stream_init();
                h3_ctrl
                    .write_all(&ctrl_init)
                    .await
                    .map_err(io::Error::from)?;

                let (mut auth_send, mut auth_recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;
                let resp = perform_hy2_client_auth(
                    &mut auth_send,
                    &mut auth_recv,
                    &self.cfg.password,
                    self.cfg.down_bytes_per_sec,
                )
                .await?;
                Ok((h3_ctrl, resp.udp_enabled))
            })
            .await;

        let (h3_ctrl, server_udp_enabled) = match auth_res {
            Ok(pair) => pair,
            Err(e) => {
                conn.close(quinn::VarInt::from_u32(0x100), b"auth failed");
                endpoint.close(quinn::VarInt::from_u32(0), b"auth failed");
                return Err(e);
            }
        };

        // Keep server-initiated HTTP/3 control/QPACK uni-streams alive without sending STOP_SENDING.
        let conn_for_uni = conn.clone();
        let uni_drain_task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok(mut recv) = conn_for_uni.accept_uni().await {
                tokio::spawn(async move {
                    let sink = [0u8; 256];
                    while let Ok(Some(_)) = recv.read_chunk(sink.len(), true).await {}
                });
                if held.len() < 8 {
                    held.push(());
                }
            }
        });

        let udp_sessions: Arc<DashMap<u32, mpsc::Sender<Hy2UdpFrame>>> = Arc::new(DashMap::new());
        let udp_map_bg = Arc::clone(&udp_sessions);
        let conn_for_dgram = conn.clone();
        let udp_demux_task = tokio::spawn(async move {
            while let Ok(dgram) = conn_for_dgram.read_datagram().await {
                let Ok(frame) = Hy2UdpFrame::decode(&dgram) else {
                    continue;
                };
                let sid = frame.session_id;
                let tx = udp_map_bg.get(&sid).map(|entry| entry.value().clone());
                if let Some(tx) = tx
                    && tx.try_send(frame).is_err()
                    && tx.is_closed()
                {
                    udp_map_bg.remove_if(&sid, |_, cur| cur.same_channel(&tx));
                }
            }
            // Drop all mpsc::Senders when the QUIC connection closes so awaiting
            // `Hysteria2UdpSession::recv_from()` wakes promptly and releases `QuicWorkLease`.
            udp_map_bg.clear();
        });

        let lease = QuicSessionLease::new_with_epoch(pre_epoch, endpoint, conn);
        let weak_inner = Arc::downgrade(self);
        lease.set_idle_hook(move || {
            if let Some(inner) = weak_inner.upgrade() {
                inner.reap_idle_for_low_power();
            }
        });
        Ok(Arc::new(Hy2AuthenticatedConn {
            lease,
            server_udp_enabled,
            _h3_control_send: AsyncMutex::new(h3_ctrl),
            uni_drain_task,
            udp_demux_task,
            udp_sessions,
            next_session_id: AtomicU32::new(1),
        }))
    }

    async fn open_tcp_on_session(
        &self,
        sess: &Arc<Hy2AuthenticatedConn>,
        work: QuicWorkLease,
        target: &TargetAddr,
    ) -> io::Result<BoxedStream> {
        let (mut send, mut recv) = sess
            .lease
            .conn
            .open_bi()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()))?;

        let addr_str = target.to_string();
        let pad_len = (rand::rng().next_u32() % 64) as usize;
        let mut req = BytesMut::with_capacity(16 + addr_str.len() + pad_len);
        encode_quic_varint(HY2_FRAME_TCP_REQUEST, &mut req)?;
        encode_quic_varint(addr_str.len() as u64, &mut req)?;
        req.put_slice(addr_str.as_bytes());
        encode_quic_varint(pad_len as u64, &mut req)?;
        if pad_len > 0 {
            let mut pad = [0u8; 64];
            rand::rng().fill_bytes(&mut pad[..pad_len]);
            req.put_slice(&pad[..pad_len]);
        }

        crate::outbound::with_handshake_timeout("Hysteria2 TCP stream open", async {
            send.write_all(&req).await.map_err(io::Error::from)?;

            let status = recv.read_u8().await?;
            let msg_len = read_quic_varint(&mut recv).await? as usize;
            if msg_len > HY2_MAX_TCP_MESSAGE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hysteria2 TCP response message exceeds 2048 bytes",
                ));
            }
            let mut msg_bytes = vec![0u8; msg_len];
            if msg_len > 0 {
                recv.read_exact(&mut msg_bytes)
                    .await
                    .map_err(io::Error::other)?;
            }
            let resp_pad_len = read_quic_varint(&mut recv).await? as usize;
            if resp_pad_len > HY2_MAX_TCP_PADDING_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hysteria2 TCP response padding exceeds 4096 bytes",
                ));
            }
            if resp_pad_len > 0 {
                let mut skip = vec![0u8; resp_pad_len];
                recv.read_exact(&mut skip).await.map_err(io::Error::other)?;
            }
            if status != 0x00 {
                let msg = String::from_utf8_lossy(&msg_bytes);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Hysteria2 server rejected TCP connect to {target}: {msg}"),
                ));
            }
            Ok(())
        })
        .await?;

        Ok(Box::new(QuicBiStream::new(
            send,
            recv,
            BytesMut::new(),
            Some(Arc::new(work) as Arc<dyn Send + Sync>),
        )))
    }
}

/// Parse a Hysteria2 / Mihomo bandwidth string (e.g. `"50"`, `"100 Mbps"`, `"1 gbps"`, `"500 kbps"`)
/// into bytes per second (`0` means unlimited BBR). Bare numbers without units follow Mihomo's
/// convention of Megabits per second (`Mbps`).
pub fn parse_hy2_bandwidth_bytes_per_sec(raw: Option<&str>) -> io::Result<u64> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let split_idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let num_str = s[..split_idx].trim();
    let unit_str = s[split_idx..].trim().to_ascii_lowercase();
    if num_str.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Hysteria2 bandwidth '{s}'"),
        ));
    }
    let val: f64 = num_str.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Hysteria2 bandwidth number '{s}'"),
        )
    })?;
    if !val.is_finite() || val < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Hysteria2 bandwidth must be non-negative ('{s}')"),
        ));
    }
    if val == 0.0 {
        return Ok(0);
    }
    let bytes_per_unit: f64 = match unit_str.as_str() {
        "" | "m" | "mb" | "mbps" | "mbit" | "mbits" => 1_000_000.0 / 8.0,
        "k" | "kb" | "kbps" | "kbit" | "kbits" => 1_000.0 / 8.0,
        "g" | "gb" | "gbps" | "gbit" | "gbits" => 1_000_000_000.0 / 8.0,
        "t" | "tb" | "tbps" | "tbit" | "tbits" => 1_000_000_000_000.0 / 8.0,
        "b" | "bps" | "bit" | "bits" => 1.0 / 8.0,
        "b/s" | "byte/s" | "bytes/s" => 1.0,
        "kb/s" | "kib/s" => 1_000.0,
        "mb/s" | "mib/s" => 1_000_000.0,
        "gb/s" | "gib/s" => 1_000_000_000.0,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported Hysteria2 bandwidth unit '{other}'"),
            ));
        }
    };
    let bps = (val * bytes_per_unit).round();
    if bps > (u64::MAX as f64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 bandwidth overflows u64",
        ));
    }
    Ok(bps as u64)
}

impl Hysteria2Outbound {
    pub fn new(cfg: Hysteria2OutboundConfig) -> io::Result<Self> {
        Self::new_with_dns(cfg, None)
    }

    pub fn new_with_dns(
        cfg: Hysteria2OutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let port_spec = match &cfg.ports {
            Some(s) if !s.trim().is_empty() => PortSpec::parse(s, cfg.port)?,
            _ => PortSpec::single(cfg.port),
        };
        let salamander = match &cfg.obfs_salamander_password {
            Some(pw) => Some(SalamanderObfs::new(pw)?),
            None => None,
        };
        let default_alpn = [b"h3".to_vec()];
        let effective_alpn: &[Vec<u8>] = if cfg.alpn.is_empty() {
            &default_alpn
        } else {
            &cfg.alpn
        };
        let transport = build_quinn_transport_config(
            QuicCongestionControl::Bbr,
            Some(Duration::from_secs(15)),
            Duration::from_secs(60),
            true,
        );
        let client_cfg = build_quinn_client_config(
            cfg.skip_cert_verify,
            &cfg.extra_ca_der,
            effective_alpn,
            false,
            transport,
        )?;
        Ok(Self {
            inner: Arc::new(Hysteria2Inner {
                cfg,
                port_spec,
                salamander,
                client_cfg,
                connect_lock: AsyncMutex::new(()),
                cached_conn: CachedQuicSlot::new(),
                dns,
            }),
        })
    }
}

struct Hysteria2UdpSession {
    conn: Arc<Hy2AuthenticatedConn>,
    session_id: u32,
    next_pkt_id: AtomicU16,
    rx: Option<AsyncMutex<mpsc::Receiver<Hy2UdpFrame>>>,
    defragger: Mutex<Hy2Defragger>,
    _work: Option<QuicWorkLease>,
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        let _ = self.rx.take();
        self.conn.udp_sessions.remove(&self.session_id);
        let _ = self._work.take();
    }
}

#[async_trait]
impl OutboundUdpSession for Hysteria2UdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed);
        let addr_str = target.to_string();
        let max_wire = self
            .conn
            .lease
            .conn
            .max_datagram_size()
            .unwrap_or(HY2_MAX_UDP_DATAGRAM_WIRE)
            .min(HY2_MAX_UDP_DATAGRAM_WIRE);
        let frags =
            fragment_hy2_udp_message(self.session_id, pkt_id, &addr_str, payload, max_wire)?;
        for frag in frags {
            self.conn.lease.conn.send_datagram(frag).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("Hysteria2 UDP datagram send failed: {e}"),
                )
            })?;
        }
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let rx_mutex = self.rx.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Hysteria2 QUIC UDP session closed",
            )
        })?;
        let mut rx = rx_mutex.lock().await;
        loop {
            let frame = tokio::select! {
                biased;
                res = rx.recv() => match res {
                    Some(frame) => frame,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Hysteria2 QUIC UDP session closed",
                        ));
                    }
                },
                _ = self.conn.lease.conn.closed() => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "Hysteria2 QUIC connection closed",
                    ));
                }
            };
            let assembled = self.defragger.lock().feed(frame);
            if let Some((data, addr_str)) = assembled {
                let src = TargetAddr::from_str(&addr_str).unwrap_or_else(|_| {
                    TargetAddr::new_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                });
                return Ok((data, src));
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "Hysteria2"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.inner.cfg.server, self.inner.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        self.inner.cfg.udp
    }

    fn on_network_change(&self) -> usize {
        if let Some(evicted) = self.inner.cached_conn.advance_generation_and_take() {
            evicted.lease.close_immediately(b"network change");
            1
        } else {
            0
        }
    }

    fn set_low_power_mode(&self, enabled: bool) {
        if let Some(evicted) = self
            .inner
            .cached_conn
            .set_low_power_and_take_idle(enabled, Hy2AuthenticatedConn::is_idle)
        {
            evicted.lease.close_immediately(b"low power idle");
        }
    }

    async fn preconnect(&self, target_sessions: usize) -> io::Result<()> {
        if target_sessions > 0 {
            if let Some(dns) = &self.inner.dns {
                let _ = dns.prewarm_proxy_server_ips(&self.inner.cfg.server).await;
            }
            self.inner.preconnect_session().await?;
        }
        Ok(())
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let (sess, work) = self.inner.checkout_or_dial_session().await?;
        match self.inner.open_tcp_on_session(&sess, work, target).await {
            Ok(stream) => Ok(stream),
            Err(first_err) if sess.lease.conn.close_reason().is_some() => {
                self.inner.cached_conn.evict_if_same(&sess);
                let (fresh, fresh_work) = self.inner.checkout_or_dial_session().await?;
                self.inner
                    .open_tcp_on_session(&fresh, fresh_work, target)
                    .await
                    .or(Err(first_err))
            }
            Err(e) => Err(e),
        }
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.inner.cfg.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this Hysteria2 outbound",
            ));
        }
        let (sess, work) = self.inner.checkout_or_dial_session().await?;
        if !sess.server_udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria2 server reported Hysteria-UDP=false",
            ));
        }
        let session_id = sess.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(128);
        sess.udp_sessions.insert(session_id, tx);
        if sess.lease.conn.close_reason().is_some() {
            sess.udp_sessions.remove(&session_id);
            self.inner.cached_conn.evict_if_same(&sess);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Hysteria2 QUIC connection closed while opening UDP session",
            ));
        }
        Ok(Box::new(Hysteria2UdpSession {
            conn: sess,
            session_id,
            next_pkt_id: AtomicU16::new(1),
            rx: Some(AsyncMutex::new(rx)),
            defragger: Mutex::new(Hy2Defragger::default()),
            _work: Some(work),
        }))
    }
}

pub struct Hysteria2ServerHandle {
    pub listen_addr: SocketAddr,
    endpoint: quinn::Endpoint,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl Hysteria2ServerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
        let _ = self.join_handle.await;
    }
}

/// Spawn a pure-Rust Hysteria2 server (supporting plain QUIC and Salamander UDP obfuscation).
pub async fn spawn_hysteria2_server(
    bind_addr: SocketAddr,
    expected_password: String,
    tls_config: Arc<ServerConfig>,
    salamander_password: Option<String>,
) -> io::Result<Hysteria2ServerHandle> {
    let salamander = match salamander_password {
        Some(pw) => Some(SalamanderObfs::new(&pw)?),
        None => None,
    };
    let transport = build_quinn_transport_config(
        QuicCongestionControl::Bbr,
        Some(Duration::from_secs(15)),
        Duration::from_secs(60),
        true,
    );
    let server_cfg = build_quinn_server_config(tls_config, transport)?;
    let endpoint = bind_quinn_server_endpoint(bind_addr, server_cfg, salamander)?;
    let listen_addr = endpoint.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ep_bg = endpoint.clone();

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                incoming = ep_bg.accept() => {
                    let Some(inc) = incoming else { break };
                    let pw = expected_password.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = inc.await {
                            let _ = handle_hy2_server_conn(conn, pw).await;
                        }
                    });
                }
            }
        }
    });

    Ok(Hysteria2ServerHandle {
        listen_addr,
        endpoint,
        shutdown_tx,
        join_handle,
    })
}

async fn handle_hy2_server_conn(conn: quinn::Connection, expected_pw: String) -> io::Result<()> {
    let mut h3_ctrl = conn
        .open_uni()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let init = build_h3_control_stream_init();
    h3_ctrl.write_all(&init).await.map_err(io::Error::from)?;

    let conn_uni = conn.clone();
    let _uni_guard = tokio::spawn(async move {
        while let Ok(mut recv) = conn_uni.accept_uni().await {
            tokio::spawn(async move {
                let sink = [0u8; 256];
                while let Ok(Some(_)) = recv.read_chunk(sink.len(), true).await {}
            });
        }
    });

    let authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let auth_udp = Arc::clone(&authenticated);
    let conn_udp = conn.clone();

    let udp_task = tokio::spawn(async move {
        type Hy2ServerUdpEntry = (Arc<Box<dyn OutboundUdpSession>>, Arc<Mutex<Hy2Defragger>>);
        let mut sessions: HashMap<u32, Hy2ServerUdpEntry> = HashMap::new();
        let direct = DirectOutbound::default();
        while let Ok(raw) = conn_udp.read_datagram().await {
            if !auth_udp.load(Ordering::Acquire) {
                continue;
            }
            let Ok(frame) = Hy2UdpFrame::decode(&raw) else {
                continue;
            };
            let sid = frame.session_id;
            let (udp_sess, defrag) = if let Some(existing) = sessions.get(&sid) {
                (Arc::clone(&existing.0), Arc::clone(&existing.1))
            } else {
                let Ok(opened) = direct.open_udp_session().await else {
                    continue;
                };
                let sess_arc = Arc::new(opened);
                let defrag_arc = Arc::new(Mutex::new(Hy2Defragger::default()));
                sessions.insert(sid, (Arc::clone(&sess_arc), Arc::clone(&defrag_arc)));

                let sess_rx = Arc::clone(&sess_arc);
                let conn_tx = conn_udp.clone();
                let pkt_seq = Arc::new(AtomicU16::new(1));
                tokio::spawn(async move {
                    while let Ok((resp_data, src_addr)) = sess_rx.recv_from().await {
                        let pid = pkt_seq.fetch_add(1, Ordering::Relaxed);
                        let addr_s = src_addr.to_string();
                        if let Ok(frags) = fragment_hy2_udp_message(
                            sid,
                            pid,
                            &addr_s,
                            &resp_data,
                            HY2_MAX_UDP_DATAGRAM_WIRE,
                        ) {
                            for f in frags {
                                if conn_tx.send_datagram(f).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
                (sess_arc, defrag_arc)
            };

            let assembled = defrag.lock().feed(frame);
            if let Some((payload, dst_str)) = assembled
                && let Ok(dst) = TargetAddr::from_str(&dst_str)
            {
                let _ = udp_sess.send_to(&payload, &dst).await;
            }
        }
    });

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let auth_flag = Arc::clone(&authenticated);
        let expected_pw = expected_pw.clone();
        tokio::spawn(async move {
            let Ok(first_var) = read_quic_varint(&mut recv).await else {
                return;
            };
            if first_var == HY2_FRAME_TCP_REQUEST {
                if !auth_flag.load(Ordering::Acquire) {
                    return;
                }
                let _ = handle_hy2_server_tcp(send, recv).await;
            } else {
                // HTTP/3 stream: `first_var` is the first frame_type (usually 0x01 HEADERS)
                let Ok(frame_len) = read_quic_varint(&mut recv).await else {
                    return;
                };
                if frame_len > 65536 {
                    return;
                }
                let mut payload = vec![0u8; frame_len as usize];
                if recv.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let headers = if first_var == h3_auth::H3_FRAME_HEADERS {
                    h3_auth::decode_qpack_header_block(&payload).ok()
                } else {
                    read_h3_headers_frame(&mut recv).await.ok()
                };
                let Some(hdrs) = headers else { return };
                let got_pw = hdrs
                    .iter()
                    .find(|(k, _)| k == "hysteria-auth")
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                let ok = got_pw == expected_pw;
                if ok {
                    auth_flag.store(true, Ordering::Release);
                }
                let status = if ok { HY2_STATUS_AUTH_OK } else { 404 };
                if let Ok(resp) = build_hy2_auth_response_frame(status, true, 0, true) {
                    let _ = send.write_all(&resp).await;
                    let _ = send.finish();
                }
            }
        });
    }

    udp_task.abort();
    drop(h3_ctrl);
    Ok(())
}

async fn handle_hy2_server_tcp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> io::Result<()> {
    let addr_len = read_quic_varint(&mut recv).await? as usize;
    if addr_len == 0 || addr_len > HY2_MAX_TCP_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria2 TCP address length",
        ));
    }
    let mut addr_buf = vec![0u8; addr_len];
    recv.read_exact(&mut addr_buf)
        .await
        .map_err(io::Error::other)?;
    let pad_len = read_quic_varint(&mut recv).await? as usize;
    if pad_len > HY2_MAX_TCP_PADDING_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria2 TCP padding length",
        ));
    }
    if pad_len > 0 {
        let mut skip = vec![0u8; pad_len];
        recv.read_exact(&mut skip).await.map_err(io::Error::other)?;
    }
    let addr_str = String::from_utf8(addr_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 address"))?;
    let target = TargetAddr::from_str(&addr_str)?;

    let direct = DirectOutbound::default();
    match direct.connect_tcp(&target).await {
        Ok(mut upstream) => {
            let mut resp = BytesMut::with_capacity(8);
            resp.put_u8(0x00); // status OK
            encode_quic_varint(0, &mut resp)?; // empty message
            encode_quic_varint(0, &mut resp)?; // 0 padding
            send.write_all(&resp).await.map_err(io::Error::from)?;

            let mut client_bi = QuicBiStream::new(send, recv, BytesMut::new(), None);
            let _ = tokio::io::copy_bidirectional(&mut client_bi, &mut upstream).await;
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            let msg_b = msg.as_bytes();
            let mut resp = BytesMut::with_capacity(8 + msg_b.len());
            resp.put_u8(0x01);
            encode_quic_varint(msg_b.len() as u64, &mut resp)?;
            resp.put_slice(msg_b);
            encode_quic_varint(0, &mut resp)?;
            let _ = send.write_all(&resp).await;
            let _ = send.finish();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hysteria2_udp_recv_from_wakes_on_disconnect_and_releases_work_lease() {
        let sni = "hy2.udp.disconnect.test";
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let password = "hy2-disconnect-pw";
        let srv = spawn_hysteria2_server(
            "127.0.0.1:0".parse().unwrap(),
            password.to_string(),
            tls_cfg,
            None,
        )
        .await
        .unwrap();

        let outbound = Hysteria2Outbound::new(Hysteria2OutboundConfig {
            name: "hy2-udp-disconnect".into(),
            server: "127.0.0.1".into(),
            port: srv.listen_addr.port(),
            ports: None,
            password: password.into(),
            obfs_salamander_password: None,
            up_bytes_per_sec: 0,
            down_bytes_per_sec: 0,
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"h3".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        })
        .unwrap();

        // Case 1: Local `on_network_change()` closes QUIC session while `recv_from()` is awaiting.
        let udp_sess = outbound.open_udp_session().await.unwrap();
        let auth_conn = outbound
            .inner
            .cached_conn
            .get_if(|_| true)
            .expect("cached Hysteria2 session must exist");
        assert_eq!(auth_conn.lease.active_work_count(), 1);

        let recv_task = tokio::spawn(async move {
            let res = udp_sess.recv_from().await;
            (res, udp_sess)
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let start = std::time::Instant::now();
        assert_eq!(outbound.on_network_change(), 1);
        let (res, udp_sess) = tokio::time::timeout(Duration::from_millis(500), recv_task)
            .await
            .expect("Hysteria2 UDP recv_from must not hang after on_network_change")
            .unwrap();
        assert!(
            res.is_err(),
            "Hysteria2 UDP recv_from must return Err on QUIC disconnect"
        );
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "recv_from wakeup exceeded 500ms: {:?}",
            start.elapsed()
        );
        drop(udp_sess);
        assert_eq!(
            auth_conn.lease.active_work_count(),
            0,
            "QuicWorkLease must drop to 0 once Hysteria2UdpSession is dropped"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            auth_conn.udp_sessions.is_empty(),
            "udp_demux_task must clear udp_sessions on disconnect"
        );

        // Case 2: Remote server shutdown closes QUIC session while `recv_from()` is awaiting.
        let udp_sess2 = outbound.open_udp_session().await.unwrap();
        let auth_conn2 = outbound
            .inner
            .cached_conn
            .get_if(|_| true)
            .expect("fresh cached Hysteria2 session must exist");
        assert_eq!(auth_conn2.lease.active_work_count(), 1);

        let recv_task2 = tokio::spawn(async move {
            let res = udp_sess2.recv_from().await;
            (res, udp_sess2)
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let start2 = std::time::Instant::now();
        srv.shutdown().await;
        let (res2, udp_sess2) = tokio::time::timeout(Duration::from_millis(500), recv_task2)
            .await
            .expect("Hysteria2 UDP recv_from must not hang after server shutdown")
            .unwrap();
        assert!(
            res2.is_err(),
            "Hysteria2 UDP recv_from must return Err on server shutdown"
        );
        assert!(
            start2.elapsed() < Duration::from_millis(500),
            "recv_from wakeup on server close exceeded 500ms: {:?}",
            start2.elapsed()
        );
        drop(udp_sess2);
        assert_eq!(
            auth_conn2.lease.active_work_count(),
            0,
            "QuicWorkLease must drop to 0 after server-side disconnect and session drop"
        );
    }
}
