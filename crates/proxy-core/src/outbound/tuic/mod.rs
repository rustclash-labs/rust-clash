use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll, Wake, Waker, ready},
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
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        quic_common::{
            CachedQuicSlot, QuicBiStream, QuicCongestionControl, QuicSessionLease, QuicWorkLease,
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

/// Fan-out waker waking two independent tasks when `TuicClientStream` is split via
/// `tokio::io::split` and `poll_read` drives `inner`'s write/flush path for server-speaks-first.
struct FanoutWaker {
    primary: Waker,
    secondary: Waker,
}

impl Wake for FanoutWaker {
    fn wake(self: Arc<Self>) {
        self.primary.wake_by_ref();
        self.secondary.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.primary.wake_by_ref();
        self.secondary.wake_by_ref();
    }
}

fn with_fanout_waker<R>(
    primary: &Waker,
    secondary: Option<&Waker>,
    f: impl FnOnce(&mut Context<'_>) -> R,
) -> R {
    if let Some(sec) = secondary
        && !primary.will_wake(sec)
    {
        let combined = Waker::from(Arc::new(FanoutWaker {
            primary: primary.clone(),
            secondary: sec.clone(),
        }));
        let mut cx = Context::from_waker(&combined);
        return f(&mut cx);
    }
    let mut cx = Context::from_waker(primary);
    f(&mut cx)
}

/// Coalesces TUIC v5 `Connect` header (`[0x05, 0x01, addr]`) onto the first write (or flushes on first read).
pub struct TuicClientStream<S> {
    inner: S,
    pending_buf: BytesMut,
    hdr_remaining: usize,
    hdr_flushed: bool,
    first_write_coalesced: bool,
    any_read_bytes: bool,
    write_waker: Option<Waker>,
    read_flush_waker: Option<Waker>,
}

impl<S> TuicClientStream<S> {
    pub fn new(inner: S, connect_hdr: BytesMut) -> Self {
        let hdr_remaining = connect_hdr.len();
        Self {
            inner,
            pending_buf: connect_hdr,
            hdr_remaining,
            hdr_flushed: false,
            first_write_coalesced: false,
            any_read_bytes: false,
            write_waker: None,
            read_flush_waker: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TuicClientStream<S> {
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_buf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUIC stream closed while flushing buffered Connect header",
                )));
            }
            self.pending_buf.advance(n);
            self.hdr_remaining = self.hdr_remaining.saturating_sub(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TuicClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut flush_err: Option<io::Error> = None;
        let mut flush_pending = false;

        if !self.hdr_flushed {
            let saved_write_waker = self.write_waker.clone();
            let was_non_empty = !self.pending_buf.is_empty();
            let drain_res = with_fanout_waker(cx.waker(), saved_write_waker.as_ref(), |ccx| {
                self.poll_drain_pending(ccx)
            });
            match drain_res {
                Poll::Ready(Ok(())) => {
                    let flush_res =
                        with_fanout_waker(cx.waker(), saved_write_waker.as_ref(), |ccx| {
                            Pin::new(&mut self.inner).poll_flush(ccx)
                        });
                    match flush_res {
                        Poll::Ready(Ok(())) => {
                            self.hdr_flushed = true;
                            self.read_flush_waker = None;
                            if let Some(w) = self.write_waker.take() {
                                w.wake();
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_flush_waker = None;
                            if let Some(w) = self.write_waker.take() {
                                w.wake();
                            }
                            flush_err = Some(e);
                        }
                        Poll::Pending => {
                            if was_non_empty
                                && self.pending_buf.is_empty()
                                && let Some(w) = self.write_waker.as_ref()
                            {
                                w.wake_by_ref();
                            }
                            flush_pending = true;
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.read_flush_waker = None;
                    if let Some(w) = self.write_waker.take() {
                        w.wake();
                    }
                    if self.hdr_remaining > 0 {
                        // Connect header itself could not be sent; surface the error promptly
                        // so server-speaks-first reads cannot hang on a dead uplink.
                        return Poll::Ready(Err(e));
                    }
                    flush_err = Some(e);
                }
                Poll::Pending => {
                    // Never early-return `Poll::Pending` when `pending_buf` is saturated:
                    // fall through to `inner.poll_read` so full-duplex responses can be read
                    // even before the server drains our initial coalesced upload.
                    flush_pending = true;
                }
            }
        }

        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let got_bytes = buf.filled().len() > before;
                self.read_flush_waker = None;
                if got_bytes {
                    self.any_read_bytes = true;
                    if flush_err.is_some() {
                        // Server already responded after receiving Connect header; stop
                        // retrying the failed uplink from `poll_read`.
                        self.hdr_flushed = true;
                    }
                    Poll::Ready(Ok(()))
                } else if let Some(e) = flush_err {
                    if self.any_read_bytes {
                        self.hdr_flushed = true;
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(e))
                    }
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(e)) => {
                self.read_flush_waker = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                if let Some(e) = flush_err {
                    if self.any_read_bytes {
                        self.hdr_flushed = true;
                        self.read_flush_waker = None;
                        return Poll::Pending;
                    }
                    return Poll::Ready(Err(e));
                }
                if flush_pending {
                    self.read_flush_waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        }
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

        let saved_read_waker = if self.hdr_flushed {
            None
        } else {
            self.read_flush_waker.clone()
        };

        // First write coalescing path: append up to 16 KiB directly behind the TUIC Connect
        // header, opportunistically drain, and immediately report `coal_len` accepted so
        // cancelling a subsequent `Pending` write never leaves unacknowledged bytes.
        if !self.first_write_coalesced && !self.hdr_flushed {
            self.first_write_coalesced = true;
            let coal_len = data.len().min(16 * 1024);
            self.pending_buf.extend_from_slice(&data[..coal_len]);
            let drain_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
                self.poll_drain_pending(ccx)
            });
            return match drain_res {
                Poll::Ready(Ok(())) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.as_ref() {
                        w.wake_by_ref();
                    }
                    Poll::Ready(Ok(coal_len))
                }
                Poll::Ready(Err(e)) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.take() {
                        w.wake();
                    }
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    // Returning `Ready(Ok(coal_len))` immediately — do not register `cx` as
                    // `write_waker`, while `with_fanout_waker` already preserved `read_flush_waker`.
                    self.write_waker = None;
                    Poll::Ready(Ok(coal_len))
                }
            };
        }

        // Pre-drain any residual buffered bytes BEFORE consuming new bytes from `data`.
        if !self.pending_buf.is_empty() {
            let drain_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
                self.poll_drain_pending(ccx)
            });
            match drain_res {
                Poll::Ready(Ok(())) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.as_ref() {
                        w.wake_by_ref();
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.take() {
                        w.wake();
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }

        let write_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
            Pin::new(&mut self.inner).poll_write(ccx, data)
        });
        match write_res {
            Poll::Pending => {
                self.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                self.write_waker = None;
                if let Some(w) = self.read_flush_waker.take() {
                    w.wake();
                }
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(n)) => {
                self.write_waker = None;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let saved_read_waker = if self.hdr_flushed {
            None
        } else {
            self.read_flush_waker.clone()
        };
        if !self.pending_buf.is_empty() {
            let drain_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
                self.poll_drain_pending(ccx)
            });
            match drain_res {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.take() {
                        w.wake();
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let flush_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
            Pin::new(&mut self.inner).poll_flush(ccx)
        });
        match flush_res {
            Poll::Ready(Ok(())) => {
                self.hdr_flushed = true;
                self.write_waker = None;
                if let Some(w) = self.read_flush_waker.take() {
                    w.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.write_waker = None;
                if let Some(w) = self.read_flush_waker.take() {
                    w.wake();
                }
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                self.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let saved_read_waker = if self.hdr_flushed {
            None
        } else {
            self.read_flush_waker.clone()
        };
        if !self.pending_buf.is_empty() {
            let drain_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
                self.poll_drain_pending(ccx)
            });
            match drain_res {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    self.write_waker = None;
                    if let Some(w) = self.read_flush_waker.take() {
                        w.wake();
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let shut_res = with_fanout_waker(cx.waker(), saved_read_waker.as_ref(), |ccx| {
            Pin::new(&mut self.inner).poll_shutdown(ccx)
        });
        match shut_res {
            Poll::Ready(Ok(())) => {
                self.hdr_flushed = true;
                self.write_waker = None;
                if let Some(w) = self.read_flush_waker.take() {
                    w.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.write_waker = None;
                if let Some(w) = self.read_flush_waker.take() {
                    w.wake();
                }
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                self.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
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

    fn is_idle(&self) -> bool {
        self.lease.active_work_count() == 0 && self.udp_sessions.is_empty()
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
        // Keep returning the real servername/server even when `disable_sni` is true:
        // `tls_cfg.enable_sni = false` suppresses sending SNI on the wire while rustls
        // still verifies the server certificate SAN against this hostname.
        self.cfg
            .servername
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.cfg.server.as_str())
    }

    fn reap_idle_for_low_power(&self) {
        if let Some(evicted) = self
            .cached_conn
            .reap_if_low_power_idle(TuicAuthenticatedConn::is_idle)
        {
            evicted.lease.close_immediately(b"low power idle");
        }
    }

    async fn checkout_or_dial_session(
        self: &Arc<Self>,
    ) -> io::Result<(Arc<TuicAuthenticatedConn>, QuicWorkLease)> {
        if let Some(pair) = self
            .cached_conn
            .checkout_if_usable(TuicAuthenticatedConn::is_usable, |s| s.lease.acquire_work())
        {
            return Ok(pair);
        }
        let _guard = self.connect_lock.lock().await;
        if let Some(pair) = self
            .cached_conn
            .checkout_if_usable(TuicAuthenticatedConn::is_usable, |s| s.lease.acquire_work())
        {
            return Ok(pair);
        }

        for attempt in 0..2 {
            let dial_gen = self.cached_conn.current_generation();
            let session = self.dial_fresh_session().await?;
            match self.cached_conn.store_if_generation_and_checkout(
                dial_gen,
                Arc::clone(&session),
                TuicAuthenticatedConn::is_usable,
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
                            "network switched during TUIC QUIC handshake",
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
            .get_if(TuicAuthenticatedConn::is_usable)
            .is_some()
        {
            return Ok(());
        }
        let _guard = self.connect_lock.lock().await;
        if self.cached_conn.is_low_power_mode()
            || self
                .cached_conn
                .get_if(TuicAuthenticatedConn::is_usable)
                .is_some()
        {
            return Ok(());
        }
        let dial_gen = self.cached_conn.current_generation();
        let session = self.dial_fresh_session().await?;
        if let Err(rejected) = self.cached_conn.store_preconnect_if_generation(
            dial_gen,
            session,
            TuicAuthenticatedConn::is_usable,
        ) {
            rejected
                .lease
                .close_immediately(b"preconnect superseded or low power");
        }
        Ok(())
    }

    async fn dial_fresh_session(self: &Arc<Self>) -> io::Result<Arc<TuicAuthenticatedConn>> {
        let (endpoint, conn, zero_rtt_accepted, pre_epoch) = dial_protected_quic_connection(
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
        // Note: if 0-RTT was entered, `export_keying_material` requires 1-RTT handshake keys;
        // await `ZeroRttAccepted` (bounded by the full handshake timeout) instead of polling.
        let auth_res: io::Result<()> =
            crate::outbound::with_handshake_timeout("TUIC v5 Authenticate", async move {
                let mut token = [0u8; 32];
                if let Err(first_err) =
                    conn_auth.export_keying_material(&mut token, uuid.as_bytes(), &pw_bytes)
                {
                    let Some(zero_rtt) = zero_rtt_accepted else {
                        return Err(io::Error::other(format!(
                            "TUIC TLS 1.3 keying material export failed: {first_err:?}"
                        )));
                    };
                    let _accepted = zero_rtt.await;
                    if let Some(reason) = conn_auth.close_reason() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!(
                                "TUIC QUIC 0-RTT handshake closed before Authenticate: {reason}"
                            ),
                        ));
                    }
                    conn_auth
                        .export_keying_material(&mut token, uuid.as_bytes(), &pw_bytes)
                        .map_err(|e| {
                            io::Error::other(format!(
                                "TUIC TLS 1.3 keying material export failed after 0-RTT handshake: {e:?}"
                            ))
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
                let tx = udp_dgram_map.get(&aid).map(|entry| entry.value().clone());
                if let Some(tx) = tx
                    && tx.try_send(pkt).is_err()
                    && tx.is_closed()
                {
                    udp_dgram_map.remove_if(&aid, |_, cur| cur.same_channel(&tx));
                }
            }
            // Drop all mpsc::Senders when QUIC disconnects so awaiting `recv_from()` wakes.
            udp_dgram_map.clear();
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
                    // Clone `mpsc::Sender` and drop the `DashMap` shard read guard BEFORE `.await`ing
                    // so a full per-session queue can never deadlock `TuicUdpSession::drop` (`remove()`).
                    let tx = map_ref.get(&aid).map(|entry| entry.value().clone());
                    if let Some(tx) = tx
                        && tx.send(pkt).await.is_err()
                    {
                        map_ref.remove_if(&aid, |_, cur| cur.same_channel(&tx));
                    }
                });
            }
            // Drop all mpsc::Senders when QUIC disconnects so awaiting `recv_from()` wakes.
            udp_uni_map.clear();
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

        let lease = QuicSessionLease::new_with_epoch(pre_epoch, endpoint, conn);
        let weak_inner = Arc::downgrade(self);
        lease.set_idle_hook(move || {
            if let Some(inner) = weak_inner.upgrade() {
                inner.reap_idle_for_low_power();
            }
        });
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
        work: QuicWorkLease,
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
            Some(Arc::new(work) as Arc<dyn Send + Sync>),
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
        let tls_cfg = crate::crypto::tls::build_quic_tls_client_config(
            cfg.skip_cert_verify,
            &cfg.extra_ca_der,
            effective_alpn,
            cfg.zero_rtt_handshake,
            cfg.disable_sni,
        )?;
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
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
    rx: Option<AsyncMutex<mpsc::Receiver<TuicUdpPacket>>>,
    defragger: Mutex<TuicDefragger>,
    _work: Option<QuicWorkLease>,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        // Drop the `mpsc::Receiver` FIRST so any in-flight `tx.send(pkt).await` wakes up immediately
        // with `SendError` before we touch `udp_sessions` or drop `_work`.
        let _ = self.rx.take();
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
        let _ = self._work.take();
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
        let rx_mutex = self.rx.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "TUIC UDP session closed")
        })?;
        let mut rx = rx_mutex.lock().await;
        loop {
            let pkt = tokio::select! {
                biased;
                res = rx.recv() => match res {
                    Some(pkt) => pkt,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TUIC UDP session closed",
                        ));
                    }
                },
                _ = self.conn.lease.conn.closed() => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "TUIC QUIC connection closed",
                    ));
                }
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
            .set_low_power_and_take_idle(enabled, TuicAuthenticatedConn::is_idle)
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
            Ok(s) => Ok(s),
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
                "UDP disabled on this TUIC outbound",
            ));
        }
        let (sess, work) = self.inner.checkout_or_dial_session().await?;
        let assoc_id = sess.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(128);
        sess.udp_sessions.insert(assoc_id, tx);
        if sess.lease.conn.close_reason().is_some() {
            sess.udp_sessions.remove(&assoc_id);
            self.inner.cached_conn.evict_if_same(&sess);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "TUIC QUIC connection closed while opening UDP session",
            ));
        }
        Ok(Box::new(TuicUdpSession {
            conn: sess,
            assoc_id,
            relay_mode: self.inner.cfg.udp_relay_mode,
            next_pkt_id: AtomicU16::new(1),
            rx: Some(AsyncMutex::new(rx)),
            defragger: Mutex::new(TuicDefragger::default()),
            _work: Some(work),
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

    #[tokio::test]
    async fn tuic_quic_stream_udp_drop_while_recv_queue_full_does_not_deadlock() {
        let flood_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let flood_addr = flood_sock.local_addr().unwrap();
        let (flood_done_tx, flood_done_rx) = tokio::sync::oneshot::channel();

        let flood_bg = Arc::clone(&flood_sock);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, peer)) = flood_bg.recv_from(&mut buf).await {
                // Send 220 packets (> 128 mpsc channel capacity) without the client reading any,
                // forcing `uni_task` to fill the channel and park on `tx.send(pkt).await`.
                let payload = [0x42u8; 64];
                for _ in 0..220 {
                    let _ = flood_bg.send_to(&payload, peer).await;
                }
                let _ = flood_done_tx.send(());
            }
        });

        let sni = "tuic.deadlock.test";
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let uuid = Uuid::new_v4();
        let password = "tuic-deadlock-test-pw";
        let srv = spawn_tuic_server(
            "127.0.0.1:0".parse().unwrap(),
            uuid,
            password.to_string(),
            tls_cfg,
        )
        .await
        .unwrap();

        let outbound = TuicOutbound::new(TuicOutboundConfig {
            name: "tuic-quic-udp-flood".into(),
            server: "127.0.0.1".into(),
            port: srv.listen_addr.port(),
            uuid,
            password: password.into(),
            udp_relay_mode: TuicUdpRelayMode::Quic,
            congestion_control: QuicCongestionControl::Bbr,
            zero_rtt_handshake: false,
            disable_sni: false,
            heartbeat_interval: Duration::from_secs(30),
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"h3".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        })
        .unwrap();

        let udp_sess = outbound.open_udp_session().await.unwrap();
        let flood_target = TargetAddr::from(flood_addr);
        udp_sess.send_to(b"start", &flood_target).await.unwrap();

        tokio::time::timeout(Duration::from_secs(3), flood_done_rx)
            .await
            .expect("UDP flood server timed out")
            .unwrap();
        // Allow QUIC uni-streams to deliver >128 packets so `uni_task` blocks on full mpsc channel.
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::time::timeout(Duration::from_secs(2), async move {
            drop(udp_sess);
            tokio::task::yield_now().await;
        })
        .await
        .expect("dropping TuicUdpSession with full recv channel must not deadlock");

        // Verify `udp_sessions` DashMap is unlocked and a fresh UDP session works on the same conn!
        let echo_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            if let Ok((n, p)) = echo_sock.recv_from(&mut b).await {
                let _ = echo_sock.send_to(&b[..n], p).await;
            }
        });
        let echoed = outbound
            .exchange_udp(
                &TargetAddr::from(echo_addr),
                b"still-alive",
                Duration::from_secs(2),
            )
            .await
            .expect("multiplexed TUIC session must remain usable after full-queue session drop");
        assert_eq!(echoed, b"still-alive");

        srv.shutdown().await;
    }

    #[tokio::test]
    async fn tuic_udp_recv_from_wakes_on_disconnect_and_releases_work_lease() {
        let sni = "tuic.udp.disconnect.test";
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let uuid = Uuid::new_v4();
        let password = "tuic-disconnect-pw";
        let srv = spawn_tuic_server(
            "127.0.0.1:0".parse().unwrap(),
            uuid,
            password.to_string(),
            tls_cfg,
        )
        .await
        .unwrap();

        let outbound = TuicOutbound::new(TuicOutboundConfig {
            name: "tuic-udp-disconnect".into(),
            server: "127.0.0.1".into(),
            port: srv.listen_addr.port(),
            uuid,
            password: password.into(),
            udp_relay_mode: TuicUdpRelayMode::Native,
            congestion_control: QuicCongestionControl::Bbr,
            zero_rtt_handshake: false,
            disable_sni: false,
            heartbeat_interval: Duration::from_secs(30),
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
            .expect("cached TUIC session must exist");
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
            .expect("TUIC UDP recv_from must not hang after on_network_change")
            .unwrap();
        assert!(
            res.is_err(),
            "TUIC UDP recv_from must return Err on QUIC disconnect"
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
            "QuicWorkLease must drop to 0 once TuicUdpSession is dropped"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            auth_conn.udp_sessions.is_empty(),
            "TUIC dgram/uni tasks must clear udp_sessions on disconnect"
        );

        // Case 2: Remote server shutdown closes QUIC session while `recv_from()` is awaiting.
        let udp_sess2 = outbound.open_udp_session().await.unwrap();
        let auth_conn2 = outbound
            .inner
            .cached_conn
            .get_if(|_| true)
            .expect("fresh cached TUIC session must exist");
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
            .expect("TUIC UDP recv_from must not hang after server shutdown")
            .unwrap();
        assert!(
            res2.is_err(),
            "TUIC UDP recv_from must return Err on server shutdown"
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

    #[tokio::test]
    async fn tuic_zero_rtt_authenticate_succeeds_when_handshake_exceeds_600ms() {
        use std::sync::atomic::AtomicU64;
        use tokio::io::AsyncWriteExt;

        // Local TCP echo target
        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    if let Ok(n) = s.read(&mut buf).await
                        && n > 0
                    {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let sni = "tuic.slow0rtt.test";
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let uuid = Uuid::new_v4();
        let password = "tuic-slow-0rtt-secret";
        let srv = spawn_tuic_server(
            "127.0.0.1:0".parse().unwrap(),
            uuid,
            password.to_string(),
            tls_cfg,
        )
        .await
        .unwrap();
        let srv_addr = srv.listen_addr;

        // Local UDP forwarder that delays server -> client packets by `s2c_delay_ms`
        // while preserving per-client packet ordering.
        let front_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_addr = front_sock.local_addr().unwrap();
        let s2c_delay_ms = Arc::new(AtomicU64::new(0));
        let front_bg = Arc::clone(&front_sock);
        let delay_bg = Arc::clone(&s2c_delay_ms);
        let proxy_task = tokio::spawn(async move {
            let mut client_backends: HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> =
                HashMap::new();
            let mut buf = [0u8; 4096];
            while let Ok((n, client_addr)) = front_bg.recv_from(&mut buf).await {
                let backend = if let Some(b) = client_backends.get(&client_addr) {
                    Arc::clone(b)
                } else {
                    let b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    let b_rx = Arc::clone(&b);
                    let f_tx = Arc::clone(&front_bg);
                    let d_cfg = Arc::clone(&delay_bg);
                    let (delay_tx, mut delay_rx) =
                        mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
                    tokio::spawn(async move {
                        while let Some((release_at, pkt)) = delay_rx.recv().await {
                            tokio::time::sleep_until(release_at).await;
                            let _ = f_tx.send_to(&pkt, client_addr).await;
                        }
                    });
                    tokio::spawn(async move {
                        let mut rbuf = [0u8; 4096];
                        while let Ok((rn, _)) = b_rx.recv_from(&mut rbuf).await {
                            let d = d_cfg.load(Ordering::Acquire);
                            let release_at = tokio::time::Instant::now() + Duration::from_millis(d);
                            if delay_tx.send((release_at, rbuf[..rn].to_vec())).is_err() {
                                break;
                            }
                        }
                    });
                    client_backends.insert(client_addr, Arc::clone(&b));
                    b
                };
                let _ = backend.send_to(&buf[..n], srv_addr).await;
            }
        });

        let outbound = TuicOutbound::new(TuicOutboundConfig {
            name: "tuic-slow-0rtt".into(),
            server: "127.0.0.1".into(),
            port: proxy_addr.port(),
            uuid,
            password: password.into(),
            udp_relay_mode: TuicUdpRelayMode::Native,
            congestion_control: QuicCongestionControl::Bbr,
            zero_rtt_handshake: true,
            disable_sni: false,
            heartbeat_interval: Duration::from_secs(30),
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"h3".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        })
        .unwrap();

        // Step 1: Warm a 0-RTT session ticket with 0ms delay.
        let mut s1 = outbound
            .connect_tcp(&TargetAddr::from(echo_addr))
            .await
            .expect("warm-up TUIC connect must succeed");
        s1.write_all(b"warm-ticket").await.unwrap();
        s1.flush().await.unwrap();
        let mut r1 = [0u8; 11];
        s1.read_exact(&mut r1).await.unwrap();
        assert_eq!(&r1, b"warm-ticket");
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s1);

        // Step 2: Inject 650ms server->client latency (> old 500ms polling limit!) and force
        // a fresh 0-RTT reconnect via `on_network_change()`.
        s2c_delay_ms.store(650, Ordering::Release);
        assert_eq!(outbound.on_network_change(), 1);

        let start = std::time::Instant::now();
        let mut s2 = outbound
            .connect_tcp(&TargetAddr::from(echo_addr))
            .await
            .expect(
                "0-RTT TUIC Authenticate must await ZeroRttAccepted instead of failing at 500ms",
            );
        let auth_elapsed = start.elapsed();
        assert!(
            auth_elapsed >= Duration::from_millis(600),
            "expected >=600ms delayed 0-RTT handshake completion, got {auth_elapsed:?}"
        );
        s2.write_all(b"after-650ms-0rtt").await.unwrap();
        s2.flush().await.unwrap();
        let mut r2 = [0u8; 16];
        s2.read_exact(&mut r2).await.unwrap();
        assert_eq!(&r2, b"after-650ms-0rtt");

        drop(s2);
        proxy_task.abort();
        echo_task.abort();
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn tuic_disable_sni_verifies_real_servername_certificate() {
        use tokio::io::AsyncWriteExt;

        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 128];
                if let Ok(n) = s.read(&mut buf).await
                    && n > 0
                {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        // Self-signed cert ONLY valid for "tuic.example.test" (explicitly NOT "localhost"!).
        let sni = "tuic.example.test";
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let uuid = Uuid::new_v4();
        let password = "tuic-disable-sni-secret";
        let srv = spawn_tuic_server(
            "127.0.0.1:0".parse().unwrap(),
            uuid,
            password.to_string(),
            tls_cfg,
        )
        .await
        .unwrap();

        let outbound = TuicOutbound::new(TuicOutboundConfig {
            name: "tuic-disable-sni-verified".into(),
            server: "127.0.0.1".into(),
            port: srv.listen_addr.port(),
            uuid,
            password: password.into(),
            udp_relay_mode: TuicUdpRelayMode::Native,
            congestion_control: QuicCongestionControl::Bbr,
            zero_rtt_handshake: false,
            disable_sni: true,
            heartbeat_interval: Duration::from_secs(30),
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"h3".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        })
        .unwrap();
        assert_eq!(outbound.inner.sni_host(), sni);

        let mut stream = outbound
            .connect_tcp(&TargetAddr::from(echo_addr))
            .await
            .expect("disable_sni=true with skip_cert_verify=false must verify servername SAN");
        stream.write_all(b"disable-sni-ok").await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = [0u8; 14];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"disable-sni-ok");

        drop(stream);
        echo_task.abort();
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn tuic_client_stream_server_speaks_first_waits_for_pending_flush() {
        struct PendingFlushMockStream {
            written: Vec<u8>,
            flush_calls: usize,
            flushed: bool,
            banner: BytesMut,
            wake_scheduled: bool,
        }

        impl AsyncRead for PendingFlushMockStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if !self.flushed {
                    // Server will not emit its banner until client Connect header is flushed!
                    return Poll::Pending;
                }
                if self.banner.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = self.banner.len().min(buf.remaining());
                buf.put_slice(&self.banner.split_to(n));
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for PendingFlushMockStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.written.extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flush_calls += 1;
                if self.flush_calls == 1 {
                    if !self.wake_scheduled {
                        self.wake_scheduled = true;
                        let waker = cx.waker().clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(15)).await;
                            waker.wake();
                        });
                    }
                    return Poll::Pending;
                }
                self.flushed = true;
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let banner = b"220 SSH-2.0-TUIC-BANNER\r\n";
        let mock = PendingFlushMockStream {
            written: Vec::new(),
            flush_calls: 0,
            flushed: false,
            banner: BytesMut::from(&banner[..]),
            wake_scheduled: false,
        };
        let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x00\x16"[..]);
        let mut stream = TuicClientStream::new(mock, connect_hdr.clone());

        let mut got = vec![0u8; banner.len()];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut got))
            .await
            .expect("poll_read must retry poll_flush after Pending instead of deadlocking")
            .unwrap();
        assert_eq!(&got, banner);
        assert_eq!(stream.inner.flush_calls, 2);
        assert_eq!(stream.inner.written, connect_hdr.as_ref());
        assert!(stream.hdr_flushed);
    }

    #[tokio::test]
    async fn tuic_client_stream_split_concurrent_read_and_saturated_write_no_deadlock() {
        use tokio::io::AsyncWriteExt;

        let (client_io, mut server_io) = tokio::io::duplex(256);
        let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x01\xbb"[..]);
        let stream = TuicClientStream::new(client_io, connect_hdr.clone());
        let (mut rd, mut wr) = tokio::io::split(stream);

        let payload = vec![0xABu8; 256 * 1024];
        let payload_tx = payload.clone();

        // 1. Writer saturates the 256B duplex pipe and parks on `Pending` while `hdr_flushed == false`.
        let writer_task = tokio::spawn(async move {
            wr.write_all(&payload_tx).await.unwrap();
            wr.flush().await.unwrap();
            wr.shutdown().await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 2. Reader polls `poll_read` while `!hdr_flushed` and pipe is still saturated; without
        //    `FanoutWaker`, Reader would overwrite Writer's waker and deadlock permanently.
        let reader_task = tokio::spawn(async move {
            let mut reply = Vec::new();
            rd.read_to_end(&mut reply).await.unwrap();
            reply
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 3. Server drains `connect_hdr + 256 KiB` and then sends its reply.
        let server_task = tokio::spawn(async move {
            let mut expected = Vec::with_capacity(connect_hdr.len() + payload.len());
            expected.extend_from_slice(&connect_hdr);
            expected.extend_from_slice(&payload);
            let mut received = Vec::with_capacity(expected.len());
            server_io.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), expected.len());
            assert_eq!(received, expected);
            server_io.write_all(b"split-ok").await.unwrap();
            server_io.shutdown().await.unwrap();
        });

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            writer_task.await.unwrap();
            server_task.await.unwrap();
            reader_task.await.unwrap()
        })
        .await
        .expect("split TuicClientStream concurrent read + saturated write must not deadlock");
        assert_eq!(reply, b"split-ok");
    }

    #[tokio::test]
    async fn tuic_client_stream_cancelled_pending_write_retries_with_smaller_buffer() {
        use tokio::io::AsyncWriteExt;

        let (client_io, mut server_io) = tokio::io::duplex(64);
        let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x00\x50"[..]);
        let mut stream = TuicClientStream::new(client_io, connect_hdr.clone());

        // First write saturates `duplex(64)` and leaves buffered bytes in `pending_buf`.
        let first_chunk = vec![0x11u8; 4096];
        let n1 = stream.write(&first_chunk).await.unwrap();
        assert_eq!(n1, 4096);

        // Second large write must return `Pending`; cancel it via timeout.
        let cancelled_large = vec![0x22u8; 4096];
        let timed_out =
            tokio::time::timeout(Duration::from_millis(25), stream.write(&cancelled_large)).await;
        assert!(
            timed_out.is_err(),
            "write to saturated duplex while pending_buf is non-empty must park Pending"
        );

        // Start draining server side concurrently, then retry with a SMALLER buffer `b"tiny"`.
        let drain_task = tokio::spawn(async move {
            let mut received = Vec::new();
            server_io.read_to_end(&mut received).await.unwrap();
            received
        });

        stream
            .write_all(b"tiny")
            .await
            .expect("retrying with smaller buffer after cancelled Pending write must succeed");
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), drain_task)
            .await
            .unwrap()
            .unwrap();
        let mut expected = Vec::with_capacity(connect_hdr.len() + first_chunk.len() + 4);
        expected.extend_from_slice(&connect_hdr);
        expected.extend_from_slice(&first_chunk);
        expected.extend_from_slice(b"tiny");
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tuic_client_stream_full_duplex_reply_before_draining_coalesced_upload_no_deadlock() {
        use tokio::io::AsyncWriteExt;

        let (client_io, mut server_io) = tokio::io::duplex(256);
        let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x01\xbb"[..]);
        let stream = TuicClientStream::new(client_io, connect_hdr.clone());
        let (mut rd, mut wr) = tokio::io::split(stream);

        let upload = vec![0xABu8; 16 * 1024];
        let upload_tx = upload.clone();
        let server_reply: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        let server_reply_tx = server_reply.clone();

        // Writer coalesces 16 KiB behind `connect_hdr` into `pending_buf`, saturating the
        // 256-byte duplex while `hdr_flushed` remains `false`, then flushes & shuts down.
        let writer_task = tokio::spawn(async move {
            wr.write_all(&upload_tx).await.unwrap();
            wr.flush().await.unwrap();
            wr.shutdown().await.unwrap();
        });

        // Reader concurrently expects a 512-byte response (> 256B downlink duplex) BEFORE the
        // server drains the remaining ~16 KiB upload.
        let reader_task = tokio::spawn(async move {
            let mut got = vec![0u8; 512];
            rd.read_exact(&mut got).await.unwrap();
            got
        });

        let hdr_expected = connect_hdr.clone();
        let server_task = tokio::spawn(async move {
            // 1. Read only the first 256 bytes (contains Connect header + initial payload).
            let mut first = vec![0u8; 256];
            server_io.read_exact(&mut first).await.unwrap();
            assert_eq!(&first[..hdr_expected.len()], hdr_expected.as_ref());
            assert!(
                first[hdr_expected.len()..].iter().all(|&b| b == 0xAB),
                "initial coalesced payload bytes after Connect header must match"
            );

            // 2. Write 512-byte response (> 256B downlink duplex!) BEFORE reading the rest of upload.
            server_io.write_all(&server_reply_tx).await.unwrap();
            server_io.flush().await.unwrap();

            // 3. Drain remaining upload and verify byte-for-byte integrity.
            let mut rest = Vec::new();
            server_io.read_to_end(&mut rest).await.unwrap();
            let mut full = first;
            full.extend_from_slice(&rest);
            let mut expected = Vec::with_capacity(hdr_expected.len() + upload.len());
            expected.extend_from_slice(&hdr_expected);
            expected.extend_from_slice(&upload);
            assert_eq!(full, expected);
        });

        let got_reply = tokio::time::timeout(Duration::from_secs(2), async {
            writer_task.await.unwrap();
            server_task.await.unwrap();
            reader_task.await.unwrap()
        })
        .await
        .expect(
            "TuicClientStream::poll_read must not deadlock behind saturated coalesced pending_buf",
        );
        assert_eq!(got_reply, server_reply);
    }

    #[tokio::test]
    async fn tuic_client_stream_delivers_buffered_response_on_uplink_error_and_surfaces_unsent_header_error()
     {
        use tokio::io::AsyncWriteExt;

        // Case 1: Server receives Connect header + initial bytes, sends 512-byte HTTP 413
        // response, and closes uplink (BrokenPipe on further writes). Reader must still receive
        // the entire buffered downlink response cleanly!
        {
            struct EarlyUplinkCloseStream {
                allow_write_bytes: usize,
                written: Vec<u8>,
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
                            "server closed uplink after sending HTTP 413",
                        )));
                    }
                    let take = data.len().min(self.allow_write_bytes);
                    self.written.extend_from_slice(&data[..take]);
                    self.allow_write_bytes -= take;
                    Poll::Ready(Ok(take))
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "server closed uplink",
                    )))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x00\x50"[..]);
            let mut resp =
                b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 480\r\n\r\n".to_vec();
            resp.resize(512, b'X');
            let mock = EarlyUplinkCloseStream {
                allow_write_bytes: 256,
                written: Vec::new(),
                downlink: BytesMut::from(resp.as_slice()),
            };
            let mut stream = TuicClientStream::new(mock, connect_hdr.clone());

            // First write pushes 256B (Connect header + 247B payload), then BrokenPipe on next write.
            let err = stream.write(&vec![0xABu8; 16 * 1024]).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(
                &stream.inner.written[..connect_hdr.len()],
                connect_hdr.as_ref()
            );

            // Reading must deliver the full buffered 512-byte response + clean EOF.
            let mut got = Vec::new();
            stream
                .read_to_end(&mut got)
                .await
                .expect("buffered downlink response must be delivered despite uplink BrokenPipe");
            assert_eq!(got, resp);
        }

        // Case 2a: Server-speaks-first where Connect header itself cannot be written (BrokenPipe)
        // while inner.poll_read stays Pending forever -> poll_read MUST return Err immediately.
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
                            "broken uplink during Connect header write",
                        )))
                    } else {
                        Poll::Ready(Ok(data.len()))
                    }
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "broken uplink during Connect header flush",
                    )))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x00\x16"[..]);
            let mut stream_w = TuicClientStream::new(
                BrokenWritePendingReadStream {
                    fail_on_write: true,
                },
                connect_hdr.clone(),
            );
            let mut b = [0u8; 16];
            let err_w = tokio::time::timeout(Duration::from_millis(500), stream_w.read(&mut b))
                .await
                .expect("unsent Connect header write error must not hang poll_read")
                .expect_err("expected BrokenPipe");
            assert_eq!(err_w.kind(), io::ErrorKind::BrokenPipe);

            // Case 2b: Header buffered into inner, but inner.poll_flush fails with BrokenPipe
            // while inner.poll_read stays Pending -> poll_read MUST return Err immediately.
            let mut stream_f = TuicClientStream::new(
                BrokenWritePendingReadStream {
                    fail_on_write: false,
                },
                connect_hdr,
            );
            let err_f = tokio::time::timeout(Duration::from_millis(500), stream_f.read(&mut b))
                .await
                .expect("failed Connect header flush must not hang server-speaks-first poll_read")
                .expect_err("expected BrokenPipe");
            assert_eq!(err_f.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn tuic_client_stream_noop_flush_wakes_writer_and_zero_byte_retry_safe() {
        use std::sync::atomic::AtomicUsize;

        struct CountingWaker(Arc<AtomicUsize>);
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct NoopFlushSingleWriteWakerStream {
            allow_bytes: usize,
            stored_write_waker: Option<Waker>,
            clear_waker_on_flush: bool,
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

            fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.clear_waker_on_flush {
                    self.stored_write_waker = None;
                }
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Case A: First write fits exactly into `allow_bytes`, emptying `pending_buf` while
        // `hdr_flushed == false`. Second write hits `Pending` on `inner.poll_write`. Concurrent
        // `poll_read` runs no-op `inner.poll_flush -> Ready(Ok(()))` and MUST wake parked writer W!
        let connect_hdr = BytesMut::from(&b"\x05\x01\x01\x7f\x00\x00\x01\x01\xbb"[..]);
        let mock = NoopFlushSingleWriteWakerStream {
            allow_bytes: connect_hdr.len() + 8,
            stored_write_waker: None,
            clear_waker_on_flush: true,
        };
        let mut stream = TuicClientStream::new(mock, connect_hdr.clone());

        let w_hits = Arc::new(AtomicUsize::new(0));
        let r_hits = Arc::new(AtomicUsize::new(0));
        let waker_w = Waker::from(Arc::new(CountingWaker(Arc::clone(&w_hits))));
        let waker_r = Waker::from(Arc::new(CountingWaker(Arc::clone(&r_hits))));
        let mut cx_w = Context::from_waker(&waker_w);
        let mut cx_r = Context::from_waker(&waker_r);

        assert_eq!(
            Pin::new(&mut stream)
                .poll_write(&mut cx_w, b"12345678")
                .map(|r| r.unwrap()),
            Poll::Ready(8)
        );
        assert!(stream.pending_buf.is_empty());
        assert!(!stream.hdr_flushed);

        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx_w, b"blocked"),
            Poll::Pending
        ));

        let mut out = [0u8; 16];
        let mut rb = ReadBuf::new(&mut out);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx_r, &mut rb),
            Poll::Pending
        ));
        assert!(stream.hdr_flushed);
        assert_eq!(
            w_hits.load(Ordering::SeqCst),
            1,
            "writer parked on Pending poll_write must be woken when poll_read completes no-op poll_flush"
        );

        // Case B: Retrying cancelled Pending write with a 0-byte buffer must return Ready(Ok(0))
        // with zero panic / InvalidInput.
        assert_eq!(
            Pin::new(&mut stream)
                .poll_write(&mut cx_w, &[])
                .map(|r| r.unwrap()),
            Poll::Ready(0)
        );
    }
}
