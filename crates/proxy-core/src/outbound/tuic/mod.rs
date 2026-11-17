use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::Mutex;
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    addr::{HostName, TargetAddr},
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession, hash_write_prefix,
        quic_common::{
            CachedQuicSlot, QuicBiStream, QuicCongestionControl, QuicSessionLease,
            bind_quinn_server_endpoint, build_quinn_server_config, build_quinn_transport_config,
            dial_protected_quic_connection,
        },
    },
};

pub const TUIC_VERSION: u8 = 0x05;
pub const TUIC_CMD_AUTHENTICATE: u8 = 0x00;
pub const TUIC_CMD_CONNECT: u8 = 0x01;
pub const TUIC_CMD_PACKET: u8 = 0x02;
pub const TUIC_CMD_DISSOCIATE: u8 = 0x03;
pub const TUIC_CMD_HEARTBEAT: u8 = 0x04;

const TUIC_ATYP_NONE: u8 = 0xff;
const TUIC_ATYP_DOMAIN: u8 = 0x00;
const TUIC_ATYP_IPV4: u8 = 0x01;
const TUIC_ATYP_IPV6: u8 = 0x02;

const TUIC_NATIVE_UDP_MAX_WIRE: usize = 1150;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn parse_opt(raw: Option<&str>) -> io::Result<Self> {
        let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(Self::Native);
        };
        if s.eq_ignore_ascii_case("native") {
            Ok(Self::Native)
        } else if s.eq_ignore_ascii_case("quic") {
            Ok(Self::Quic)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported TUIC udp-relay-mode '{s}' (expected native or quic)"),
            ))
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone)]
pub struct TuicOutboundConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: TuicUdpRelayMode,
    pub congestion_control: QuicCongestionControl,
    pub zero_rtt_handshake: bool,
    pub disable_sni: bool,
    pub heartbeat_interval: Duration,
    pub servername: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub extra_ca_der: Vec<CertificateDer<'static>>,
    pub udp: bool,
}

pub fn encode_tuic_addr(addr: Option<&TargetAddr>, out: &mut BytesMut) -> io::Result<()> {
    let Some(target) = addr else {
        out.put_u8(TUIC_ATYP_NONE);
        return Ok(());
    };
    match &target.host {
        HostName::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TUIC domain exceeds 255 bytes",
                ));
            }
            out.put_u8(TUIC_ATYP_DOMAIN);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
            out.put_u16(target.port);
        }
        HostName::Ip(IpAddr::V4(v4)) => {
            out.put_u8(TUIC_ATYP_IPV4);
            out.put_slice(&v4.octets());
            out.put_u16(target.port);
        }
        HostName::Ip(IpAddr::V6(v6)) => {
            out.put_u8(TUIC_ATYP_IPV6);
            out.put_slice(&v6.octets());
            out.put_u16(target.port);
        }
    }
    Ok(())
}

pub fn decode_tuic_addr_slice(data: &[u8]) -> io::Result<(Option<TargetAddr>, usize)> {
    let Some(&atyp) = data.first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty TUIC address slice",
        ));
    };
    match atyp {
        TUIC_ATYP_NONE => Ok((None, 1)),
        TUIC_ATYP_DOMAIN => {
            if data.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated TUIC domain length",
                ));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated TUIC domain address",
                ));
            }
            let domain = std::str::from_utf8(&data[2..2 + len]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in TUIC domain")
            })?;
            let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
            Ok((Some(TargetAddr::new_domain(domain, port)?), 4 + len))
        }
        TUIC_ATYP_IPV4 => {
            if data.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated TUIC IPv4 address",
                ));
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((Some(TargetAddr::new_ip(IpAddr::V4(ip), port)), 7))
        }
        TUIC_ATYP_IPV6 => {
            if data.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated TUIC IPv6 address",
                ));
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                Some(TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::from(oct)), port)),
                19,
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported TUIC address type 0x{other:02x}"),
        )),
    }
}

pub async fn read_tuic_addr<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<Option<TargetAddr>> {
    let atyp = reader.read_u8().await?;
    match atyp {
        TUIC_ATYP_NONE => Ok(None),
        TUIC_ATYP_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            let mut domain_b = vec![0u8; len];
            reader.read_exact(&mut domain_b).await?;
            let port = reader.read_u16().await?;
            let domain = String::from_utf8(domain_b).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in TUIC domain")
            })?;
            Ok(Some(TargetAddr::new_domain(domain, port)?))
        }
        TUIC_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(Some(TargetAddr::new_ip(
                IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            )))
        }
        TUIC_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(Some(TargetAddr::new_ip(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            )))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported TUIC address type 0x{other:02x}"),
        )),
    }
}

#[derive(Clone, Debug)]
struct TuicUdpPacket {
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: Option<TargetAddr>,
    data: Vec<u8>,
}

impl TuicUdpPacket {
    fn encode(&self, out: &mut BytesMut) -> io::Result<()> {
        out.reserve(32 + self.data.len());
        out.put_u8(TUIC_VERSION);
        out.put_u8(TUIC_CMD_PACKET);
        out.put_u16(self.assoc_id);
        out.put_u16(self.pkt_id);
        out.put_u8(self.frag_total);
        out.put_u8(self.frag_id);
        out.put_u16(self.data.len() as u16);
        encode_tuic_addr(self.addr.as_ref(), out)?;
        out.put_slice(&self.data);
        Ok(())
    }

    fn decode_slice(raw: &[u8]) -> io::Result<Option<Self>> {
        if raw.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUIC datagram shorter than 2 bytes",
            ));
        }
        if raw[0] != TUIC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported TUIC version {}", raw[0]),
            ));
        }
        match raw[1] {
            TUIC_CMD_HEARTBEAT => Ok(None),
            TUIC_CMD_PACKET => {
                if raw.len() < 11 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TUIC Packet header",
                    ));
                }
                let assoc_id = u16::from_be_bytes([raw[2], raw[3]]);
                let pkt_id = u16::from_be_bytes([raw[4], raw[5]]);
                let frag_total = raw[6];
                let frag_id = raw[7];
                let size = u16::from_be_bytes([raw[8], raw[9]]) as usize;
                let (addr, addr_used) = decode_tuic_addr_slice(&raw[10..])?;
                let data_start = 10 + addr_used;
                if raw.len() < data_start + size {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TUIC Packet payload",
                    ));
                }
                Ok(Some(Self {
                    assoc_id,
                    pkt_id,
                    frag_total,
                    frag_id,
                    addr,
                    data: raw[data_start..data_start + size].to_vec(),
                }))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected TUIC datagram command 0x{other:02x}"),
            )),
        }
    }

    async fn read_from_uni<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let ver = reader.read_u8().await?;
        if ver != TUIC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported TUIC version {ver}"),
            ));
        }
        let cmd = reader.read_u8().await?;
        if cmd != TUIC_CMD_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected TUIC client incoming uni command 0x{cmd:02x}"),
            ));
        }
        let assoc_id = reader.read_u16().await?;
        let pkt_id = reader.read_u16().await?;
        let frag_total = reader.read_u8().await?;
        let frag_id = reader.read_u8().await?;
        let size = reader.read_u16().await? as usize;
        let addr = read_tuic_addr(reader).await?;
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data).await?;
        Ok(Self {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            addr,
            data,
        })
    }
}

fn fragment_tuic_udp_packet(
    assoc_id: u16,
    pkt_id: u16,
    target: &TargetAddr,
    payload: &[u8],
    max_wire: usize,
) -> io::Result<Vec<Bytes>> {
    let mut addr_buf = BytesMut::with_capacity(32);
    encode_tuic_addr(Some(target), &mut addr_buf)?;
    let first_hdr = 10 + addr_buf.len();
    let max_chunk = max_wire.saturating_sub(first_hdr).max(256);

    if payload.len() <= max_chunk {
        let pkt = TuicUdpPacket {
            assoc_id,
            pkt_id,
            frag_total: 1,
            frag_id: 0,
            addr: Some(target.clone()),
            data: payload.to_vec(),
        };
        let mut out = BytesMut::new();
        pkt.encode(&mut out)?;
        return Ok(vec![out.freeze()]);
    }

    let frag_total = payload.len().div_ceil(max_chunk);
    if frag_total > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC UDP datagram exceeds 255 fragments",
        ));
    }
    let mut out = Vec::with_capacity(frag_total);
    for (idx, chunk) in payload.chunks(max_chunk).enumerate() {
        let pkt = TuicUdpPacket {
            assoc_id,
            pkt_id,
            frag_total: frag_total as u8,
            frag_id: idx as u8,
            addr: if idx == 0 { Some(target.clone()) } else { None },
            data: chunk.to_vec(),
        };
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf)?;
        out.push(buf.freeze());
    }
    Ok(out)
}

#[derive(Default)]
struct TuicDefragger {
    pkt_id: u16,
    first_addr: Option<TargetAddr>,
    frags: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl TuicDefragger {
    fn feed(&mut self, pkt: TuicUdpPacket) -> Option<(Vec<u8>, TargetAddr)> {
        if pkt.frag_total <= 1 {
            let addr = pkt.addr?;
            return Some((pkt.data, addr));
        }
        if pkt.frag_id >= pkt.frag_total {
            return None;
        }
        let total = pkt.frag_total as usize;
        if pkt.pkt_id != self.pkt_id || self.frags.len() != total {
            self.pkt_id = pkt.pkt_id;
            self.first_addr = None;
            self.frags = vec![None; total];
            self.received = 0;
        }
        if pkt.frag_id == 0 && pkt.addr.is_some() {
            self.first_addr = pkt.addr;
        }
        let idx = pkt.frag_id as usize;
        if self.frags[idx].is_none() {
            self.frags[idx] = Some(pkt.data);
            self.received += 1;
            if self.received == total {
                let addr = self.first_addr.take()?;
                let mut full = Vec::new();
                for part in self.frags.iter_mut() {
                    if let Some(bytes) = part.take() {
                        full.extend_from_slice(&bytes);
                    }
                }
                self.frags.clear();
                self.received = 0;
                return Some((full, addr));
            }
        }
        None
    }
}

/// Coalesces TUIC v5 `Connect` header (`[0x05, 0x01, addr]`) onto the first write (or flushes on first read).
pub struct TuicClientStream<S> {
    inner: S,
    pending_hdr: BytesMut,
    hdr_flushed: bool,
    pending_write: Option<(usize, u64)>,
}

impl<S> TuicClientStream<S> {
    pub fn new(inner: S, connect_hdr: BytesMut) -> Self {
        Self {
            inner,
            pending_hdr: connect_hdr,
            hdr_flushed: false,
            pending_write: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TuicClientStream<S> {
    fn poll_drain_hdr(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_hdr.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending_hdr))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUIC stream closed while flushing Connect header",
                )));
            }
            self.pending_hdr.advance(n);
        }
        self.hdr_flushed = true;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TuicClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.hdr_flushed {
            ready!(self.poll_drain_hdr(cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TuicClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some((orig_len, orig_hash)) = self.pending_write {
            let check = orig_len.min(data.len());
            if data.len() < orig_len || hash_write_prefix(&data[..check]) != orig_hash {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TUIC poll_write retried with mismatched buffer",
                )));
            }
            ready!(self.poll_drain_hdr(cx))?;
            self.pending_write = None;
            return Poll::Ready(Ok(orig_len));
        }
        if !self.hdr_flushed {
            let coal_len = data.len().min(16 * 1024);
            let h = hash_write_prefix(&data[..coal_len]);
            self.pending_hdr.extend_from_slice(&data[..coal_len]);
            self.pending_write = Some((coal_len, h));
            match self.poll_drain_hdr(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write = None;
                    return Poll::Ready(Ok(coal_len));
                }
                Poll::Ready(Err(e)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.hdr_flushed {
            ready!(self.poll_drain_hdr(cx))?;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.hdr_flushed {
            ready!(self.poll_drain_hdr(cx))?;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct TuicAuthenticatedConn {
    lease: Arc<QuicSessionLease>,
    udp_sessions: Arc<DashMap<u16, mpsc::Sender<TuicUdpPacket>>>,
    next_assoc_id: AtomicU16,
    dgram_task: JoinHandle<()>,
    uni_task: JoinHandle<()>,
    hb_task: JoinHandle<()>,
}

impl Drop for TuicAuthenticatedConn {
    fn drop(&mut self) {
        self.dgram_task.abort();
        self.uni_task.abort();
        self.hb_task.abort();
    }
}

impl TuicAuthenticatedConn {
    fn is_usable(&self) -> bool {
        self.lease.is_usable()
    }
}

struct TuicInner {
    cfg: TuicOutboundConfig,
    client_cfg: quinn::ClientConfig,
    connect_lock: AsyncMutex<()>,
    cached_conn: CachedQuicSlot<TuicAuthenticatedConn>,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

pub struct TuicOutbound {
    inner: Arc<TuicInner>,
}

impl TuicInner {
    fn sni_host(&self) -> &str {
        if self.cfg.disable_sni {
            "localhost"
        } else {
            self.cfg
                .servername
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(self.cfg.server.as_str())
        }
    }

    async fn get_or_dial_session(&self) -> io::Result<Arc<TuicAuthenticatedConn>> {
        if let Some(existing) = self.cached_conn.get_if(TuicAuthenticatedConn::is_usable) {
            return Ok(existing);
        }
        let _guard = self.connect_lock.lock().await;
        if let Some(existing) = self.cached_conn.get_if(TuicAuthenticatedConn::is_usable) {
            return Ok(existing);
        }
        let session = self.dial_fresh_session().await?;
        self.cached_conn.store(Arc::clone(&session));
        Ok(session)
    }

    async fn dial_fresh_session(&self) -> io::Result<Arc<TuicAuthenticatedConn>> {
        let (endpoint, conn, _) = dial_protected_quic_connection(
            &self.cfg.server,
            self.cfg.port,
            self.sni_host(),
            &self.client_cfg,
            None,
            self.cfg.zero_rtt_handshake,
            self.dns.as_deref(),
        )
        .await?;

        let uuid = self.cfg.uuid;
        let pw_bytes = self.cfg.password.as_bytes().to_vec();
        let conn_auth = conn.clone();

        // Perform TUIC v5 `Authenticate` (`[0x05, 0x00, uuid(16B), token(32B)]`).
        // Note: if 0-RTT was used, `export_keying_material` requires 1-RTT handshake keys;
        // if not yet ready, await handshake completion before sending Authenticate.
        let auth_res: io::Result<()> =
            crate::outbound::with_handshake_timeout("TUIC v5 Authenticate", async move {
                let mut token = [0u8; 32];
                if conn_auth
                    .export_keying_material(&mut token, uuid.as_bytes(), &pw_bytes)
                    .is_err()
                {
                    // Wait until 1-RTT TLS keys are available
                    for _ in 0..50 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        if conn_auth
                            .export_keying_material(&mut token, uuid.as_bytes(), &pw_bytes)
                            .is_ok()
                        {
                            break;
                        }
                    }
                    conn_auth
                        .export_keying_material(&mut token, uuid.as_bytes(), &pw_bytes)
                        .map_err(|_| {
                            io::Error::other("TUIC TLS 1.3 keying material export failed")
                        })?;
                }
                let mut uni = conn_auth
                    .open_uni()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;
                let mut auth_pkt = [0u8; 50];
                auth_pkt[0] = TUIC_VERSION;
                auth_pkt[1] = TUIC_CMD_AUTHENTICATE;
                auth_pkt[2..18].copy_from_slice(uuid.as_bytes());
                auth_pkt[18..50].copy_from_slice(&token);
                uni.write_all(&auth_pkt).await.map_err(io::Error::from)?;
                uni.finish().map_err(io::Error::from)?;
                Ok(())
            })
            .await;

        if let Err(e) = auth_res {
            conn.close(quinn::VarInt::from_u32(1), b"auth failed");
            endpoint.close(quinn::VarInt::from_u32(0), b"auth failed");
            return Err(e);
        }

        let udp_sessions: Arc<DashMap<u16, mpsc::Sender<TuicUdpPacket>>> = Arc::new(DashMap::new());

        let udp_dgram_map = Arc::clone(&udp_sessions);
        let conn_dgram = conn.clone();
        let dgram_task = tokio::spawn(async move {
            while let Ok(raw) = conn_dgram.read_datagram().await {
                let Ok(Some(pkt)) = TuicUdpPacket::decode_slice(&raw) else {
                    continue;
                };
                let aid = pkt.assoc_id;
                let dead = if let Some(tx) = udp_dgram_map.get(&aid) {
                    tx.try_send(pkt).is_err() && tx.is_closed()
                } else {
                    false
                };
                if dead {
                    udp_dgram_map.remove(&aid);
                }
            }
        });

        let udp_uni_map = Arc::clone(&udp_sessions);
        let conn_uni = conn.clone();
        let uni_task = tokio::spawn(async move {
            while let Ok(mut recv) = conn_uni.accept_uni().await {
                let map_ref = Arc::clone(&udp_uni_map);
                tokio::spawn(async move {
                    let Ok(pkt) = TuicUdpPacket::read_from_uni(&mut recv).await else {
                        return;
                    };
                    let aid = pkt.assoc_id;
                    let dead = if let Some(tx) = map_ref.get(&aid) {
                        tx.send(pkt).await.is_err()
                    } else {
                        false
                    };
                    if dead {
                        map_ref.remove(&aid);
                    }
                });
            }
        });

        let hb_interval = self.cfg.heartbeat_interval.max(Duration::from_secs(5));
        let conn_hb = conn.clone();
        let hb_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(hb_interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if conn_hb.close_reason().is_some() {
                    break;
                }
                let _ =
                    conn_hb.send_datagram(Bytes::from_static(&[TUIC_VERSION, TUIC_CMD_HEARTBEAT]));
            }
        });

        let lease = QuicSessionLease::new(endpoint, conn);
        Ok(Arc::new(TuicAuthenticatedConn {
            lease,
            udp_sessions,
            next_assoc_id: AtomicU16::new(1),
            dgram_task,
            uni_task,
            hb_task,
        }))
    }

    async fn open_tcp_on_session(
        &self,
        sess: &Arc<TuicAuthenticatedConn>,
        target: &TargetAddr,
    ) -> io::Result<BoxedStream> {
        let (send, recv) = sess
            .lease
            .conn
            .open_bi()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()))?;
        let mut hdr = BytesMut::with_capacity(32);
        hdr.put_u8(TUIC_VERSION);
        hdr.put_u8(TUIC_CMD_CONNECT);
        encode_tuic_addr(Some(target), &mut hdr)?;

        let quic_bi = QuicBiStream::new(
            send,
            recv,
            BytesMut::new(),
            Some(Arc::clone(&sess.lease) as Arc<dyn Send + Sync>),
        );
        Ok(Box::new(TuicClientStream::new(quic_bi, hdr)))
    }
}

impl TuicOutbound {
    pub fn new(cfg: TuicOutboundConfig) -> io::Result<Self> {
        Self::new_with_dns(cfg, None)
    }

    pub fn new_with_dns(
        cfg: TuicOutboundConfig,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
    ) -> io::Result<Self> {
        let default_alpn = [b"h3".to_vec()];
        let effective_alpn: &[Vec<u8>] = if cfg.alpn.is_empty() {
            &default_alpn
        } else {
            &cfg.alpn
        };
        let transport = build_quinn_transport_config(
            cfg.congestion_control,
            Some(Duration::from_secs(15)),
            Duration::from_secs(60),
            true,
        );
        let mut base_tls = (*crate::crypto::tls::build_tls_client_config(
            cfg.skip_cert_verify,
            &cfg.extra_ca_der,
            effective_alpn,
        )?)
        .clone();
        base_tls.enable_early_data = cfg.zero_rtt_handshake;
        if cfg.disable_sni {
            base_tls.enable_sni = false;
        }
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(base_tls))
            .map_err(|e| io::Error::other(format!("failed building TUIC Quinn config: {e}")))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(transport);

        Ok(Self {
            inner: Arc::new(TuicInner {
                cfg,
                client_cfg,
                connect_lock: AsyncMutex::new(()),
                cached_conn: CachedQuicSlot::new(),
                dns,
            }),
        })
    }
}

struct TuicUdpSession {
    conn: Arc<TuicAuthenticatedConn>,
    assoc_id: u16,
    relay_mode: TuicUdpRelayMode,
    next_pkt_id: AtomicU16,
    rx: AsyncMutex<mpsc::Receiver<TuicUdpPacket>>,
    defragger: Mutex<TuicDefragger>,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.conn.udp_sessions.remove(&self.assoc_id);
        let quic_conn = self.conn.lease.conn.clone();
        let aid = self.assoc_id;
        if quic_conn.close_reason().is_none()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                if let Ok(mut uni) = quic_conn.open_uni().await {
                    let mut pkt = [0u8; 4];
                    pkt[0] = TUIC_VERSION;
                    pkt[1] = TUIC_CMD_DISSOCIATE;
                    pkt[2..4].copy_from_slice(&aid.to_be_bytes());
                    let _ = uni.write_all(&pkt).await;
                    let _ = uni.finish();
                }
            });
        }
    }
}

#[async_trait]
impl OutboundUdpSession for TuicUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC UDP payload exceeds 65535 bytes",
            ));
        }
        let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed);
        match self.relay_mode {
            TuicUdpRelayMode::Native => {
                let max_wire = self
                    .conn
                    .lease
                    .conn
                    .max_datagram_size()
                    .unwrap_or(TUIC_NATIVE_UDP_MAX_WIRE)
                    .min(TUIC_NATIVE_UDP_MAX_WIRE);
                let frags =
                    fragment_tuic_udp_packet(self.assoc_id, pkt_id, target, payload, max_wire)?;
                for frag in frags {
                    self.conn.lease.conn.send_datagram(frag).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            format!("TUIC native UDP datagram send failed: {e}"),
                        )
                    })?;
                }
                Ok(())
            }
            TuicUdpRelayMode::Quic => {
                let pkt = TuicUdpPacket {
                    assoc_id: self.assoc_id,
                    pkt_id,
                    frag_total: 1,
                    frag_id: 0,
                    addr: Some(target.clone()),
                    data: payload.to_vec(),
                };
                let mut buf = BytesMut::new();
                pkt.encode(&mut buf)?;
                let mut uni = self.conn.lease.conn.open_uni().await.map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("TUIC QUIC uni-stream UDP open failed: {e}"),
                    )
                })?;
                uni.write_all(&buf).await.map_err(io::Error::from)?;
                uni.finish().map_err(io::Error::from)?;
                Ok(())
            }
        }
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut rx = self.rx.lock().await;
        loop {
            let Some(pkt) = rx.recv().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUIC UDP session closed",
                ));
            };
            let assembled = self.defragger.lock().feed(pkt);
            if let Some(res) = assembled {
                return Ok(res);
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for TuicOutbound {
    fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    fn protocol(&self) -> &'static str {
        "TUIC"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.inner.cfg.server, self.inner.cfg.port)
    }

    fn udp_supported(&self) -> bool {
        self.inner.cfg.udp
    }

    fn on_network_change(&self) -> usize {
        if let Some(evicted) = self.inner.cached_conn.take() {
            evicted.lease.close_immediately(b"network change");
            1
        } else {
            0
        }
    }

    async fn preconnect(&self, target_sessions: usize) -> io::Result<()> {
        if target_sessions > 0 {
            if let Some(dns) = &self.inner.dns {
                let _ = dns.prewarm_proxy_server_ips(&self.inner.cfg.server).await;
            }
            let _ = self.inner.get_or_dial_session().await?;
        }
        Ok(())
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let sess = self.inner.get_or_dial_session().await?;
        match self.inner.open_tcp_on_session(&sess, target).await {
            Ok(s) => Ok(s),
            Err(first_err) if sess.lease.conn.close_reason().is_some() => {
                let _ = self.inner.cached_conn.take();
                let fresh = self.inner.get_or_dial_session().await?;
                self.inner
                    .open_tcp_on_session(&fresh, target)
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
                "UDP disabled on this TUIC outbound",
            ));
        }
        let sess = self.inner.get_or_dial_session().await?;
        let assoc_id = sess.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(128);
        sess.udp_sessions.insert(assoc_id, tx);
        Ok(Box::new(TuicUdpSession {
            conn: sess,
            assoc_id,
            relay_mode: self.inner.cfg.udp_relay_mode,
            next_pkt_id: AtomicU16::new(1),
            rx: AsyncMutex::new(rx),
            defragger: Mutex::new(TuicDefragger::default()),
        }))
    }
}

pub struct TuicServerHandle {
    pub listen_addr: SocketAddr,
    endpoint: quinn::Endpoint,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl TuicServerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
        let _ = self.join_handle.await;
    }
}

/// Spawn a pure-Rust TUIC v5 server (supporting TCP `Connect` and both `native` & `quic` UDP relay modes).
pub async fn spawn_tuic_server(
    bind_addr: SocketAddr,
    expected_uuid: Uuid,
    expected_password: String,
    tls_config: Arc<ServerConfig>,
) -> io::Result<TuicServerHandle> {
    let transport = build_quinn_transport_config(
        QuicCongestionControl::Bbr,
        Some(Duration::from_secs(15)),
        Duration::from_secs(60),
        true,
    );
    let server_cfg = build_quinn_server_config(tls_config, transport)?;
    let endpoint = bind_quinn_server_endpoint(bind_addr, server_cfg, None)?;
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
                            let _ = handle_tuic_server_conn(conn, expected_uuid, pw).await;
                        }
                    });
                }
            }
        }
    });

    Ok(TuicServerHandle {
        listen_addr,
        endpoint,
        shutdown_tx,
        join_handle,
    })
}

type ServerUdpEntry = (
    Arc<Box<dyn OutboundUdpSession>>,
    Arc<Mutex<TuicDefragger>>,
    tokio::task::AbortHandle,
);

async fn dispatch_server_tuic_udp(
    conn: &quinn::Connection,
    sessions: &Arc<AsyncMutex<HashMap<u16, ServerUdpEntry>>>,
    pkt: TuicUdpPacket,
    via_uni_stream: bool,
) {
    let aid = pkt.assoc_id;
    let (udp_sess, defrag) = {
        let mut map = sessions.lock().await;
        if let Some(existing) = map.get(&aid) {
            (Arc::clone(&existing.0), Arc::clone(&existing.1))
        } else {
            let direct = DirectOutbound::default();
            let Ok(opened) = direct.open_udp_session().await else {
                return;
            };
            let sess_arc = Arc::new(opened);
            let defrag_arc = Arc::new(Mutex::new(TuicDefragger::default()));
            let sess_rx = Arc::clone(&sess_arc);
            let conn_tx = conn.clone();
            let pkt_seq = Arc::new(AtomicU16::new(1));
            let reader = tokio::spawn(async move {
                while let Ok((resp_data, src_addr)) = sess_rx.recv_from().await {
                    let pid = pkt_seq.fetch_add(1, Ordering::Relaxed);
                    if via_uni_stream {
                        let resp_pkt = TuicUdpPacket {
                            assoc_id: aid,
                            pkt_id: pid,
                            frag_total: 1,
                            frag_id: 0,
                            addr: Some(src_addr),
                            data: resp_data,
                        };
                        let mut buf = BytesMut::new();
                        if resp_pkt.encode(&mut buf).is_ok()
                            && let Ok(mut uni) = conn_tx.open_uni().await
                        {
                            let _ = uni.write_all(&buf).await;
                            let _ = uni.finish();
                        }
                    } else if let Ok(frags) = fragment_tuic_udp_packet(
                        aid,
                        pid,
                        &src_addr,
                        &resp_data,
                        TUIC_NATIVE_UDP_MAX_WIRE,
                    ) {
                        for f in frags {
                            if conn_tx.send_datagram(f).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
            map.insert(
                aid,
                (
                    Arc::clone(&sess_arc),
                    Arc::clone(&defrag_arc),
                    reader.abort_handle(),
                ),
            );
            (sess_arc, defrag_arc)
        }
    };

    let assembled = defrag.lock().feed(pkt);
    if let Some((payload, dst)) = assembled {
        let _ = udp_sess.send_to(&payload, &dst).await;
    }
}

async fn handle_tuic_server_conn(
    conn: quinn::Connection,
    expected_uuid: Uuid,
    expected_pw: String,
) -> io::Result<()> {
    let authenticated = Arc::new(AtomicBool::new(false));
    let auth_notify = Arc::new(tokio::sync::Notify::new());
    let udp_sessions: Arc<AsyncMutex<HashMap<u16, ServerUdpEntry>>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    // Unidirectional stream handler (`Authenticate`, `Packet` in `quic` mode, `Dissociate`)
    let conn_uni = conn.clone();
    let auth_uni = Arc::clone(&authenticated);
    let notify_uni = Arc::clone(&auth_notify);
    let sessions_uni = Arc::clone(&udp_sessions);
    let uni_task = tokio::spawn(async move {
        while let Ok(mut recv) = conn_uni.accept_uni().await {
            let conn_c = conn_uni.clone();
            let auth_c = Arc::clone(&auth_uni);
            let notify_c = Arc::clone(&notify_uni);
            let sessions_c = Arc::clone(&sessions_uni);
            let pw_c = expected_pw.clone();
            tokio::spawn(async move {
                let Ok(ver) = recv.read_u8().await else {
                    return;
                };
                if ver != TUIC_VERSION {
                    return;
                }
                let Ok(cmd) = recv.read_u8().await else {
                    return;
                };
                match cmd {
                    TUIC_CMD_AUTHENTICATE => {
                        let mut got_uuid = [0u8; 16];
                        let mut got_token = [0u8; 32];
                        if recv.read_exact(&mut got_uuid).await.is_err()
                            || recv.read_exact(&mut got_token).await.is_err()
                        {
                            return;
                        }
                        let mut expected_token = [0u8; 32];
                        if got_uuid == *expected_uuid.as_bytes()
                            && conn_c
                                .export_keying_material(
                                    &mut expected_token,
                                    expected_uuid.as_bytes(),
                                    pw_c.as_bytes(),
                                )
                                .is_ok()
                            && got_token == expected_token
                        {
                            auth_c.store(true, Ordering::Release);
                            notify_c.notify_waiters();
                        } else {
                            conn_c.close(quinn::VarInt::from_u32(1), b"tuic auth failed");
                        }
                    }
                    TUIC_CMD_PACKET => {
                        if !auth_c.load(Ordering::Acquire) {
                            let notified = notify_c.notified();
                            if tokio::time::timeout(Duration::from_secs(5), notified)
                                .await
                                .is_err()
                                || !auth_c.load(Ordering::Acquire)
                            {
                                return;
                            }
                        }
                        let Ok(assoc_id) = recv.read_u16().await else {
                            return;
                        };
                        let Ok(pkt_id) = recv.read_u16().await else {
                            return;
                        };
                        let Ok(frag_total) = recv.read_u8().await else {
                            return;
                        };
                        let Ok(frag_id) = recv.read_u8().await else {
                            return;
                        };
                        let Ok(size) = recv.read_u16().await else {
                            return;
                        };
                        let Ok(addr) = read_tuic_addr(&mut recv).await else {
                            return;
                        };
                        let mut data = vec![0u8; size as usize];
                        if recv.read_exact(&mut data).await.is_err() {
                            return;
                        }
                        let pkt = TuicUdpPacket {
                            assoc_id,
                            pkt_id,
                            frag_total,
                            frag_id,
                            addr,
                            data,
                        };
                        dispatch_server_tuic_udp(&conn_c, &sessions_c, pkt, true).await;
                    }
                    TUIC_CMD_DISSOCIATE => {
                        if let Ok(aid) = recv.read_u16().await
                            && let Some((_, _, abort)) = sessions_c.lock().await.remove(&aid)
                        {
                            abort.abort();
                        }
                    }
                    _ => {}
                }
            });
        }
    });

    // Datagram handler (`Packet` in `native` mode + `Heartbeat`)
    let conn_dgram = conn.clone();
    let auth_dgram = Arc::clone(&authenticated);
    let notify_dgram = Arc::clone(&auth_notify);
    let sessions_dgram = Arc::clone(&udp_sessions);
    let dgram_task = tokio::spawn(async move {
        while let Ok(raw) = conn_dgram.read_datagram().await {
            let Ok(Some(pkt)) = TuicUdpPacket::decode_slice(&raw) else {
                continue;
            };
            if !auth_dgram.load(Ordering::Acquire) {
                let notified = notify_dgram.notified();
                if tokio::time::timeout(Duration::from_secs(5), notified)
                    .await
                    .is_err()
                    || !auth_dgram.load(Ordering::Acquire)
                {
                    continue;
                }
            }
            dispatch_server_tuic_udp(&conn_dgram, &sessions_dgram, pkt, false).await;
        }
    });

    // Bidirectional stream handler (`Connect`)
    while let Ok((send, mut recv)) = conn.accept_bi().await {
        let auth_bi = Arc::clone(&authenticated);
        let notify_bi = Arc::clone(&auth_notify);
        tokio::spawn(async move {
            let Ok(ver) = recv.read_u8().await else {
                return;
            };
            let Ok(cmd) = recv.read_u8().await else {
                return;
            };
            if ver != TUIC_VERSION || cmd != TUIC_CMD_CONNECT {
                return;
            }
            let Ok(Some(target)) = read_tuic_addr(&mut recv).await else {
                return;
            };
            if !auth_bi.load(Ordering::Acquire) {
                let notified = notify_bi.notified();
                if tokio::time::timeout(Duration::from_secs(5), notified)
                    .await
                    .is_err()
                    || !auth_bi.load(Ordering::Acquire)
                {
                    return;
                }
            }
            let direct = DirectOutbound::default();
            if let Ok(mut upstream) = direct.connect_tcp(&target).await {
                let mut bi = QuicBiStream::new(send, recv, BytesMut::new(), None);
                let _ = tokio::io::copy_bidirectional(&mut bi, &mut upstream).await;
            }
        });
    }

    uni_task.abort();
    dgram_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuic_address_and_fragmentation_roundtrip() {
        for addr in [
            Some(TargetAddr::new_domain("dns.google", 53).unwrap()),
            Some(TargetAddr::new_ip(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                443,
            )),
            Some(TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 853)),
            None,
        ] {
            let mut buf = BytesMut::new();
            encode_tuic_addr(addr.as_ref(), &mut buf).unwrap();
            let (dec, used) = decode_tuic_addr_slice(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(dec, addr);
        }

        let target = TargetAddr::new_domain("media.example.org", 9000).unwrap();
        let big = vec![0x5au8; 3200];
        let frags = fragment_tuic_udp_packet(7, 42, &target, &big, 1000).unwrap();
        assert!(frags.len() >= 4);

        let mut defrag = TuicDefragger::default();
        let mut out = None;
        for (i, raw) in frags.iter().enumerate() {
            let pkt = TuicUdpPacket::decode_slice(raw).unwrap().unwrap();
            if i == 0 {
                assert_eq!(pkt.addr.as_ref(), Some(&target));
            } else {
                assert!(pkt.addr.is_none());
            }
            out = defrag.feed(pkt);
        }
        let (assembled, src) = out.unwrap();
        assert_eq!(assembled, big);
        assert_eq!(src, target);
    }
}
