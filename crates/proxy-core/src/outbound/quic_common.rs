use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use quinn::{
    AsyncUdpSocket, ClientConfig as QuinnClientConfig, Endpoint, EndpointConfig,
    ServerConfig as QuinnServerConfig, TransportConfig, UdpPoller, VarInt,
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    udp::{RecvMeta, Transmit},
};
use rand::RngCore;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

use crate::platform::socket_protect::{
    current_protector_epoch, global_socket_protector, prioritize_healthy_happy_eyeballs_addrs,
    protected_udp_bind, resolve_protected_host_addrs,
};

/// Hysteria2 Salamander UDP obfuscator (`[8B random salt][payload ^ BLAKE2b-256(psk || salt)]`).
#[derive(Clone)]
pub struct SalamanderObfs {
    psk: Arc<ZeroizedKey>,
}

struct ZeroizedKey(Vec<u8>);

impl Drop for ZeroizedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SalamanderObfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderObfs").finish_non_exhaustive()
    }
}

impl SalamanderObfs {
    pub const SALT_LEN: usize = 8;

    pub fn new(password: &str) -> io::Result<Self> {
        if password.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 Salamander password must be at least 4 bytes",
            ));
        }
        Ok(Self {
            psk: Arc::new(ZeroizedKey(password.as_bytes().to_vec())),
        })
    }

    fn derive_mask(&self, salt: &[u8; Self::SALT_LEN]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b-256 output size");
        hasher.update(&self.psk.0);
        hasher.update(salt);
        let mut mask = [0u8; 32];
        hasher
            .finalize_variable(&mut mask)
            .expect("valid BLAKE2b-256 finalize");
        mask
    }

    pub fn obfuscate_with_salt(
        &self,
        payload: &[u8],
        salt: &[u8; Self::SALT_LEN],
        out: &mut Vec<u8>,
    ) {
        out.clear();
        out.reserve(Self::SALT_LEN + payload.len());
        out.extend_from_slice(salt);
        let mask = self.derive_mask(salt);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i & 31]);
        }
    }

    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut salt = [0u8; Self::SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        self.obfuscate_with_salt(payload, &salt, out);
    }

    /// De-obfuscate an incoming datagram into `dst`, returning plaintext length or `None` if undersized.
    pub fn deobfuscate(&self, packet: &[u8], dst: &mut [u8]) -> Option<usize> {
        if packet.len() <= Self::SALT_LEN {
            return None;
        }
        let plain_len = packet.len() - Self::SALT_LEN;
        if dst.len() < plain_len {
            return None;
        }
        let mut salt = [0u8; Self::SALT_LEN];
        salt.copy_from_slice(&packet[..Self::SALT_LEN]);
        let mask = self.derive_mask(&salt);
        for (i, (&c, p)) in packet[Self::SALT_LEN..]
            .iter()
            .zip(dst[..plain_len].iter_mut())
            .enumerate()
        {
            *p = c ^ mask[i & 31];
        }
        Some(plain_len)
    }
}

struct SalamanderWritablePoller {
    sock: Arc<SalamanderUdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for SalamanderWritablePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderWritablePoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for SalamanderWritablePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            let sock = Arc::clone(&self.sock);
            self.fut = Some(Box::pin(async move { sock.io.writable().await }));
        }
        let res = self
            .fut
            .as_mut()
            .expect("future initialized")
            .as_mut()
            .poll(cx);
        if res.is_ready() {
            self.fut = None;
        }
        res
    }
}

/// Protected `AsyncUdpSocket` applying Hysteria2 Salamander obfuscation/de-obfuscation per UDP packet.
pub struct SalamanderUdpSocket {
    io: tokio::net::UdpSocket,
    obfs: SalamanderObfs,
}

impl fmt::Debug for SalamanderUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderUdpSocket")
            .field("local_addr", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl SalamanderUdpSocket {
    pub fn new(io: tokio::net::UdpSocket, obfs: SalamanderObfs) -> Self {
        Self { io, obfs }
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderWritablePoller {
            sock: self,
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let seg_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if seg_size == 0 {
            return Ok(());
        }
        let mut wire = Vec::with_capacity(SalamanderObfs::SALT_LEN + seg_size);
        for chunk in transmit.contents.chunks(seg_size) {
            self.obfs.obfuscate(chunk, &mut wire);
            let sent = self.io.try_send_to(&wire, transmit.destination)?;
            if sent != wire.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial UDP datagram send on Salamander socket",
                ));
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut wire_buf = [0u8; 4096];
        loop {
            let mut rb = ReadBuf::new(&mut wire_buf);
            let addr = ready!(self.io.poll_recv_from(cx, &mut rb))?;
            let raw = rb.filled();
            let Some(plain_len) = self.obfs.deobfuscate(raw, &mut bufs[0]) else {
                // Per Hysteria2 Salamander spec, silently discard packets <= 8 bytes.
                continue;
            };
            meta[0] = RecvMeta {
                addr,
                len: plain_len,
                stride: plain_len,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Bind a protected client QUIC `Endpoint` (optionally wrapped in Salamander UDP obfuscation).
pub fn bind_protected_quinn_client_endpoint(
    remote_addr: SocketAddr,
    salamander: Option<SalamanderObfs>,
) -> io::Result<Endpoint> {
    let bind_addr = if remote_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let tokio_udp = protected_udp_bind(bind_addr, Some(remote_addr))?;
    let mut ep_cfg = EndpointConfig::default();
    if salamander.is_some() {
        // Reserve headroom for Salamander's 8-byte per-packet salt so outer UDP never fragments.
        let _ = ep_cfg.max_udp_payload_size(1350);
    }
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    match salamander {
        None => {
            let std_udp = tokio_udp.into_std()?;
            Endpoint::new(ep_cfg, None, std_udp, runtime)
        }
        Some(obfs) => {
            let sock = Arc::new(SalamanderUdpSocket::new(tokio_udp, obfs));
            Endpoint::new_with_abstract_socket(ep_cfg, None, sock, runtime)
        }
    }
}

/// Bind a loopback/local QUIC server `Endpoint` (optionally wrapped in Salamander UDP obfuscation).
pub fn bind_quinn_server_endpoint(
    bind_addr: SocketAddr,
    server_cfg: QuinnServerConfig,
    salamander: Option<SalamanderObfs>,
) -> io::Result<Endpoint> {
    let std_sock = std::net::UdpSocket::bind(bind_addr)?;
    std_sock.set_nonblocking(true)?;
    let _ = global_socket_protector();
    let mut ep_cfg = EndpointConfig::default();
    if salamander.is_some() {
        let _ = ep_cfg.max_udp_payload_size(1350);
    }
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    match salamander {
        None => Endpoint::new(ep_cfg, Some(server_cfg), std_sock, runtime),
        Some(obfs) => {
            let tokio_udp = tokio::net::UdpSocket::from_std(std_sock)?;
            let sock = Arc::new(SalamanderUdpSocket::new(tokio_udp, obfs));
            Endpoint::new_with_abstract_socket(ep_cfg, Some(server_cfg), sock, runtime)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicCongestionControl {
    Bbr,
    Cubic,
    NewReno,
}

impl QuicCongestionControl {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
        }
    }

    pub fn parse_opt(raw: Option<&str>) -> io::Result<Self> {
        let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(Self::Bbr);
        };
        if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(Self::NewReno)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported QUIC congestion controller '{s}' (expected bbr, cubic, or new_reno)"
                ),
            ))
        }
    }
}

pub fn build_quinn_transport_config(
    congestion: QuicCongestionControl,
    keep_alive: Option<Duration>,
    idle_timeout: Duration,
    enable_datagrams: bool,
) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(256));
    transport.max_concurrent_uni_streams(VarInt::from_u32(256));
    transport.keep_alive_interval(keep_alive);
    if let Ok(idle) = idle_timeout.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    if enable_datagrams {
        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        transport.datagram_send_buffer_size(2 * 1024 * 1024);
    } else {
        transport.datagram_receive_buffer_size(None);
    }
    match congestion {
        QuicCongestionControl::Bbr => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        QuicCongestionControl::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        QuicCongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
        }
    }
    Arc::new(transport)
}

pub fn build_quinn_client_config(
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    alpn_protocols: &[Vec<u8>],
    enable_early_data: bool,
    transport: Arc<TransportConfig>,
) -> io::Result<QuinnClientConfig> {
    let base_tls = crate::crypto::tls::build_tls_client_config(
        skip_cert_verify,
        extra_ca_der,
        alpn_protocols,
    )?;
    let mut tls_cfg = (*base_tls).clone();
    tls_cfg.enable_early_data = enable_early_data;
    let quic_crypto = QuicClientConfig::try_from(Arc::new(tls_cfg))
        .map_err(|e| io::Error::other(format!("failed building Quinn TLS 1.3 config: {e}")))?;
    let mut client_cfg = QuinnClientConfig::new(Arc::new(quic_crypto));
    client_cfg.transport_config(transport);
    Ok(client_cfg)
}

pub fn build_quinn_server_config(
    tls_server_cfg: Arc<rustls::ServerConfig>,
    transport: Arc<TransportConfig>,
) -> io::Result<QuinnServerConfig> {
    let mut server_tls = (*tls_server_cfg).clone();
    server_tls.max_early_data_size = u32::MAX;
    let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls))
        .map_err(|e| io::Error::other(format!("failed building Quinn server TLS config: {e}")))?;
    let mut server_cfg = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    server_cfg.transport_config(transport);
    Ok(server_cfg)
}

/// Port specification supporting single ports and inclusive `start-end` ranges (Hysteria2 `ports` / `mport`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortSpec {
    ranges: Vec<(u16, u16)>,
}

impl PortSpec {
    pub fn parse(spec: &str, fallback_port: u16) -> io::Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            if fallback_port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "port must be non-zero",
                ));
            }
            return Ok(Self {
                ranges: vec![(fallback_port, fallback_port)],
            });
        }
        let mut ranges = Vec::new();
        for part in trimmed.split([',', '/']) {
            let item = part.trim();
            if item.is_empty() {
                continue;
            }
            if let Some((lo_s, hi_s)) = item.split_once('-') {
                let lo: u16 = lo_s.trim().parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid port range start in '{item}'"),
                    )
                })?;
                let hi: u16 = hi_s.trim().parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid port range end in '{item}'"),
                    )
                })?;
                if lo == 0 || hi == 0 || lo > hi {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid port range '{item}'"),
                    ));
                }
                ranges.push((lo, hi));
            } else {
                let p: u16 = item.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid port '{item}' in ports spec"),
                    )
                })?;
                if p == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "port 0 is invalid in ports spec",
                    ));
                }
                ranges.push((p, p));
            }
        }
        if ranges.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("empty port specification '{spec}'"),
            ));
        }
        Ok(Self { ranges })
    }

    pub fn single(port: u16) -> Self {
        Self {
            ranges: vec![(port, port)],
        }
    }

    pub fn first_port(&self) -> u16 {
        self.ranges[0].0
    }

    pub fn pick_port(&self) -> u16 {
        let total: u64 = self
            .ranges
            .iter()
            .map(|&(lo, hi)| u64::from(hi - lo) + 1)
            .sum();
        if total <= 1 {
            return self.ranges[0].0;
        }
        let mut idx = rand::rng().next_u64() % total;
        for &(lo, hi) in &self.ranges {
            let span = u64::from(hi - lo) + 1;
            if idx < span {
                return lo + (idx as u16);
            }
            idx -= span;
        }
        self.ranges[0].0
    }
}

/// Resolve and connect a protected QUIC `Endpoint` + `quinn::Connection` across candidate addresses.
pub async fn dial_protected_quic_connection(
    server_host: &str,
    port: u16,
    sni_host: &str,
    client_cfg: &QuinnClientConfig,
    salamander: Option<&SalamanderObfs>,
    use_0rtt: bool,
    dns: Option<&crate::dns::FakeIpDnsEngine>,
) -> io::Result<(Endpoint, quinn::Connection, bool)> {
    let addrs = resolve_protected_host_addrs(server_host, port, dns).await?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("DNS lookup returned no addresses for QUIC server '{server_host}'"),
        ));
    }
    let ordered = prioritize_healthy_happy_eyeballs_addrs(&addrs);
    let clean_sni = sni_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let effective_sni = if clean_sni.is_empty() {
        "localhost"
    } else {
        clean_sni
    };

    let mut last_err: Option<io::Error> = None;
    for remote_addr in ordered.into_iter().take(4) {
        let attempt: io::Result<(Endpoint, quinn::Connection, bool)> = async {
            let endpoint = bind_protected_quinn_client_endpoint(remote_addr, salamander.cloned())?;
            let connecting = endpoint
                .connect_with(client_cfg.clone(), remote_addr, effective_sni)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("QUIC connect setup failed: {e}"),
                    )
                })?;
            if use_0rtt {
                match connecting.into_0rtt() {
                    Ok((conn, zero_rtt_accepted)) => {
                        tokio::spawn(async move {
                            let _ = zero_rtt_accepted.await;
                        });
                        return Ok((endpoint, conn, true));
                    }
                    Err(connecting) => {
                        let conn =
                            crate::outbound::with_handshake_timeout("QUIC handshake", async move {
                                connecting.await.map_err(|e| {
                                    io::Error::new(
                                        io::ErrorKind::ConnectionRefused,
                                        format!("QUIC handshake failed: {e}"),
                                    )
                                })
                            })
                            .await?;
                        return Ok((endpoint, conn, false));
                    }
                }
            }
            let conn = crate::outbound::with_handshake_timeout("QUIC handshake", async move {
                connecting.await.map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("QUIC handshake failed: {e}"),
                    )
                })
            })
            .await?;
            Ok((endpoint, conn, false))
        }
        .await;

        match attempt {
            Ok(ok) => return Ok(ok),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::HostUnreachable,
            "unable to connect QUIC endpoint",
        )
    }))
}

/// Shared holder keeping a `quinn::Endpoint` alive for as long as its `quinn::Connection` or child streams live.
pub struct QuicSessionLease {
    pub protector_epoch: u64,
    pub endpoint: Endpoint,
    pub conn: quinn::Connection,
}

impl QuicSessionLease {
    pub fn new(endpoint: Endpoint, conn: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            protector_epoch: current_protector_epoch(),
            endpoint,
            conn,
        })
    }

    pub fn is_usable(&self) -> bool {
        self.protector_epoch == current_protector_epoch() && self.conn.close_reason().is_none()
    }

    pub fn close_immediately(&self, reason: &'static [u8]) {
        self.conn.close(VarInt::from_u32(0), reason);
        self.endpoint.close(VarInt::from_u32(0), reason);
    }
}

/// Evictable single-slot cache helper for multiplexed QUIC sessions.
pub struct CachedQuicSlot<T>(Mutex<Option<Arc<T>>>);

impl<T> Default for CachedQuicSlot<T> {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl<T> CachedQuicSlot<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_if(&self, pred: impl FnOnce(&T) -> bool) -> Option<Arc<T>> {
        let mut guard = self.0.lock();
        if let Some(existing) = guard.as_ref() {
            if pred(existing) {
                return Some(Arc::clone(existing));
            }
            *guard = None;
        }
        None
    }

    pub fn store(&self, val: Arc<T>) {
        *self.0.lock() = Some(val);
    }

    pub fn take(&self) -> Option<Arc<T>> {
        self.0.lock().take()
    }
}

/// Adapts a bidirectional `(quinn::SendStream, quinn::RecvStream)` (with optional `preroll` bytes)
/// into `tokio::io::AsyncRead + tokio::io::AsyncWrite`.
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    preroll: BytesMut,
    _keepalive: Option<Arc<dyn Send + Sync>>,
}

impl QuicBiStream {
    pub fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        preroll: BytesMut,
        keepalive: Option<Arc<dyn Send + Sync>>,
    ) -> Self {
        Self {
            send,
            recv,
            preroll,
            _keepalive: keepalive,
        }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.preroll.is_empty() {
            let to_copy = self.preroll.len().min(buf.remaining());
            let chunk = self.preroll.split_to(to_copy);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::from)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::from)
    }
}

/// Encode an RFC 9000 QUIC variable-length integer (`0..=2^62 - 1`).
pub fn encode_quic_varint(val: u64, buf: &mut BytesMut) -> io::Result<()> {
    if val < (1 << 6) {
        buf.put_u8(val as u8);
    } else if val < (1 << 14) {
        buf.put_u16(0x4000 | (val as u16));
    } else if val < (1 << 30) {
        buf.put_u32(0x8000_0000 | (val as u32));
    } else if val < (1 << 62) {
        buf.put_u64(0xc000_0000_0000_0000 | val);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC varint exceeds 62-bit maximum",
        ));
    }
    Ok(())
}

/// Decode an RFC 9000 QUIC variable-length integer from a slice, returning `(value, consumed_bytes)`.
pub fn decode_quic_varint_slice(data: &[u8]) -> io::Result<(u64, usize)> {
    let Some(&first) = data.first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty QUIC varint slice",
        ));
    };
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QUIC varint",
        ));
    }
    let mut v = u64::from(first & 0x3f);
    for &b in &data[1..len] {
        v = (v << 8) | u64::from(b);
    }
    Ok((v, len))
}

/// Read an RFC 9000 QUIC variable-length integer asynchronously from `reader`.
pub async fn read_quic_varint<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    if len > 1 {
        let mut tail = [0u8; 7];
        reader.read_exact(&mut tail[..len - 1]).await?;
        for &b in &tail[..len - 1] {
            v = (v << 8) | u64::from(b);
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_obfs_roundtrip_and_short_packet_rejection() {
        let obfs = SalamanderObfs::new("super-secret-psk").unwrap();
        let plain = b"hello hysteria2 salamander world over multiple 32-byte blocks!!";
        let mut wire = Vec::new();
        obfs.obfuscate_with_salt(plain, b"12345678", &mut wire);
        assert_eq!(&wire[..8], b"12345678");
        assert_ne!(&wire[8..], plain);

        let mut recovered = vec![0u8; plain.len()];
        let n = obfs.deobfuscate(&wire, &mut recovered).unwrap();
        assert_eq!(n, plain.len());
        assert_eq!(&recovered[..n], plain);

        // <= 8 byte packets must be rejected
        assert!(obfs.deobfuscate(&wire[..8], &mut recovered).is_none());
        assert!(obfs.deobfuscate(&[], &mut recovered).is_none());
    }

    #[test]
    fn quic_varint_roundtrip_across_all_widths() {
        for &v in &[
            0u64,
            63,
            64,
            0x401,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut buf = BytesMut::new();
            encode_quic_varint(v, &mut buf).unwrap();
            let (dec, used) = decode_quic_varint_slice(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(dec, v);
        }
    }

    #[test]
    fn port_spec_parses_single_and_ranges() {
        let spec = PortSpec::parse("443, 20000-20005", 8443).unwrap();
        for _ in 0..32 {
            let p = spec.pick_port();
            assert!(p == 443 || (20000..=20005).contains(&p));
        }
        assert!(PortSpec::parse("30000-20000", 443).is_err());
        assert!(PortSpec::parse("0", 443).is_err());
    }
}
