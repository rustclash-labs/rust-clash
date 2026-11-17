use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
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
    HAPPY_EYEBALLS_DELAY, connect_addrs_happy_eyeballs_with, current_protector_epoch,
    global_socket_protector, network_generation, note_addr_connect_outcome, protected_udp_bind,
    resolve_protected_host_addrs,
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

/// Snapshot of socket-protector and network-reachability epochs captured BEFORE binding a UDP socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicPreDialEpoch {
    pub protector_epoch: u64,
    pub net_generation: u64,
}

impl QuicPreDialEpoch {
    pub fn capture() -> Self {
        Self {
            protector_epoch: current_protector_epoch(),
            net_generation: network_generation(),
        }
    }

    pub fn is_current(self) -> bool {
        self.protector_epoch == current_protector_epoch()
            && self.net_generation == network_generation()
    }
}

/// RAII wrapper ensuring any losing Happy Eyeballs QUIC `Endpoint` closes its UDP driver task on abort/error.
struct ScopedQuinnEndpoint(Option<Endpoint>);

impl ScopedQuinnEndpoint {
    fn new(ep: Endpoint) -> Self {
        Self(Some(ep))
    }

    fn as_ref(&self) -> &Endpoint {
        self.0.as_ref().expect("endpoint still owned")
    }

    fn into_inner(mut self) -> Endpoint {
        self.0.take().expect("endpoint still owned")
    }
}

impl Drop for ScopedQuinnEndpoint {
    fn drop(&mut self) {
        if let Some(ep) = self.0.take() {
            ep.close(VarInt::from_u32(0), b"happy eyeballs cancelled");
        }
    }
}

async fn dial_single_quic_addr(
    remote_addr: SocketAddr,
    effective_sni: String,
    client_cfg: QuinnClientConfig,
    salamander: Option<SalamanderObfs>,
    use_0rtt: bool,
    handshake_timeout: Duration,
) -> io::Result<(Endpoint, quinn::Connection, bool, QuicPreDialEpoch)> {
    let pre_epoch = QuicPreDialEpoch::capture();
    let attempt: io::Result<(Endpoint, quinn::Connection, bool, QuicPreDialEpoch)> = async {
        let scoped_ep = ScopedQuinnEndpoint::new(bind_protected_quinn_client_endpoint(
            remote_addr,
            salamander,
        )?);
        let connecting = scoped_ep
            .as_ref()
            .connect_with(client_cfg, remote_addr, &effective_sni)
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
                    return Ok((scoped_ep.into_inner(), conn, true, pre_epoch));
                }
                Err(connecting) => {
                    let conn = tokio::time::timeout(handshake_timeout, connecting)
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "QUIC handshake timed out after {}ms",
                                    handshake_timeout.as_millis()
                                ),
                            )
                        })?
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("QUIC handshake failed: {e}"),
                            )
                        })?;
                    return Ok((scoped_ep.into_inner(), conn, false, pre_epoch));
                }
            }
        }
        let conn = tokio::time::timeout(handshake_timeout, connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "QUIC handshake timed out after {}ms",
                        handshake_timeout.as_millis()
                    ),
                )
            })?
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("QUIC handshake failed: {e}"),
                )
            })?;
        Ok((scoped_ep.into_inner(), conn, false, pre_epoch))
    }
    .await;

    note_addr_connect_outcome(remote_addr, attempt.as_ref().map(|_| ()));
    attempt
}

/// Race pre-resolved candidate `SocketAddr`s for QUIC using RFC 8305 staggered Happy Eyeballs.
pub async fn dial_protected_quic_addrs_happy_eyeballs(
    addrs: &[SocketAddr],
    sni_host: &str,
    client_cfg: &QuinnClientConfig,
    salamander: Option<&SalamanderObfs>,
    use_0rtt: bool,
    stagger_delay: Duration,
    per_attempt_timeout: Duration,
) -> io::Result<(Endpoint, quinn::Connection, bool, QuicPreDialEpoch)> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            "no candidate addresses for QUIC server",
        ));
    }
    let clean_sni = sni_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let effective_sni = if clean_sni.is_empty() {
        "localhost".to_string()
    } else {
        clean_sni.to_string()
    };
    let cfg_template = client_cfg.clone();
    let salamander_template = salamander.cloned();

    connect_addrs_happy_eyeballs_with(
        addrs,
        stagger_delay,
        per_attempt_timeout,
        move |remote_addr| {
            let sni = effective_sni.clone();
            let cfg = cfg_template.clone();
            let obfs = salamander_template.clone();
            dial_single_quic_addr(remote_addr, sni, cfg, obfs, use_0rtt, per_attempt_timeout)
        },
    )
    .await
}

/// Resolve and connect a protected QUIC `Endpoint` + `quinn::Connection` across candidate addresses
/// using 250ms RFC 8305 Happy Eyeballs staggering.
pub async fn dial_protected_quic_connection(
    server_host: &str,
    port: u16,
    sni_host: &str,
    client_cfg: &QuinnClientConfig,
    salamander: Option<&SalamanderObfs>,
    use_0rtt: bool,
    dns: Option<&crate::dns::FakeIpDnsEngine>,
) -> io::Result<(Endpoint, quinn::Connection, bool, QuicPreDialEpoch)> {
    let addrs = resolve_protected_host_addrs(server_host, port, dns).await?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("DNS lookup returned no addresses for QUIC server '{server_host}'"),
        ));
    }
    dial_protected_quic_addrs_happy_eyeballs(
        &addrs,
        sni_host,
        client_cfg,
        salamander,
        use_0rtt,
        HAPPY_EYEBALLS_DELAY,
        crate::outbound::OUTBOUND_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Shared holder keeping a `quinn::Endpoint` alive for as long as its `quinn::Connection` or child streams live,
/// while tracking active stream/UDP session count for screen-off (`low_power_mode`) idle reaping.
pub struct QuicSessionLease {
    pub pre_epoch: QuicPreDialEpoch,
    pub endpoint: Endpoint,
    pub conn: quinn::Connection,
    active_work: AtomicUsize,
    idle_hook: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl QuicSessionLease {
    pub fn new(endpoint: Endpoint, conn: quinn::Connection) -> Arc<Self> {
        Self::new_with_epoch(QuicPreDialEpoch::capture(), endpoint, conn)
    }

    pub fn new_with_epoch(
        pre_epoch: QuicPreDialEpoch,
        endpoint: Endpoint,
        conn: quinn::Connection,
    ) -> Arc<Self> {
        Arc::new(Self {
            pre_epoch,
            endpoint,
            conn,
            active_work: AtomicUsize::new(0),
            idle_hook: OnceLock::new(),
        })
    }

    pub fn set_idle_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        let _ = self.idle_hook.set(Box::new(hook));
    }

    pub fn active_work_count(&self) -> usize {
        self.active_work.load(Ordering::Acquire)
    }

    pub fn acquire_work(self: &Arc<Self>) -> QuicWorkLease {
        self.active_work.fetch_add(1, Ordering::AcqRel);
        QuicWorkLease {
            lease: Arc::clone(self),
        }
    }

    pub fn is_usable(&self) -> bool {
        self.pre_epoch.is_current() && self.conn.close_reason().is_none()
    }

    pub fn close_immediately(&self, reason: &'static [u8]) {
        self.conn.close(VarInt::from_u32(0), reason);
        self.endpoint.close(VarInt::from_u32(0), reason);
    }
}

/// RAII lease representing one active TCP stream or stateful UDP session multiplexed over a `QuicSessionLease`.
pub struct QuicWorkLease {
    lease: Arc<QuicSessionLease>,
}

impl Drop for QuicWorkLease {
    fn drop(&mut self) {
        if self.lease.active_work.fetch_sub(1, Ordering::AcqRel) == 1
            && let Some(hook) = self.lease.idle_hook.get()
        {
            hook();
        }
    }
}

struct CachedQuicState<T> {
    generation: u64,
    low_power_mode: bool,
    current: Option<Arc<T>>,
}

/// Generation-aware, low-power-aware single-slot cache helper for multiplexed QUIC sessions.
pub struct CachedQuicSlot<T>(Mutex<CachedQuicState<T>>);

impl<T> Default for CachedQuicSlot<T> {
    fn default() -> Self {
        Self(Mutex::new(CachedQuicState {
            generation: 0,
            low_power_mode: false,
            current: None,
        }))
    }
}

impl<T> CachedQuicSlot<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_generation(&self) -> u64 {
        self.0.lock().generation
    }

    pub fn is_low_power_mode(&self) -> bool {
        self.0.lock().low_power_mode
    }

    pub fn get_if(&self, pred: impl FnOnce(&T) -> bool) -> Option<Arc<T>> {
        let mut guard = self.0.lock();
        if let Some(existing) = guard.current.as_ref() {
            if pred(existing) {
                return Some(Arc::clone(existing));
            }
            guard.current = None;
        }
        None
    }

    /// Atomically validate `usable(existing)` and acquire a work lease inside the slot mutex
    /// so `set_low_power_mode(true)` can never race and reap a session being checked out.
    pub fn checkout_if_usable<U, A, W>(&self, usable: U, acquire: A) -> Option<(Arc<T>, W)>
    where
        U: FnOnce(&T) -> bool,
        A: FnOnce(&T) -> W,
    {
        let mut guard = self.0.lock();
        if let Some(existing) = guard.current.as_ref() {
            if usable(existing) {
                let work = acquire(existing);
                return Some((Arc::clone(existing), work));
            }
            guard.current = None;
        }
        None
    }

    /// Store `val` and acquire a work lease ONLY if `dial_gen == self.generation` and `usable(&val)`.
    /// Returns `Err(val)` without modifying the slot if a network switch bumped `generation` while dialing.
    pub fn store_if_generation_and_checkout<U, A, W>(
        &self,
        dial_gen: u64,
        val: Arc<T>,
        usable: U,
        acquire: A,
    ) -> Result<(Option<Arc<T>>, W), Arc<T>>
    where
        U: FnOnce(&T) -> bool,
        A: FnOnce(&T) -> W,
    {
        let mut guard = self.0.lock();
        if guard.generation != dial_gen || !usable(&val) {
            return Err(val);
        }
        let work = acquire(&val);
        let replaced = guard.current.replace(val);
        Ok((replaced, work))
    }

    /// Store a preconnected idle session ONLY if `dial_gen == self.generation`, `!low_power_mode`,
    /// `usable(&val)`, and no usable session is already cached.
    pub fn store_preconnect_if_generation<U>(
        &self,
        dial_gen: u64,
        val: Arc<T>,
        mut usable: U,
    ) -> Result<(), Arc<T>>
    where
        U: FnMut(&T) -> bool,
    {
        let mut guard = self.0.lock();
        if guard.generation != dial_gen || guard.low_power_mode || !usable(&val) {
            return Err(val);
        }
        if guard.current.as_ref().is_some_and(|ex| usable(ex)) {
            return Err(val);
        }
        guard.current = Some(val);
        Ok(())
    }

    /// Evict the cached session ONLY if it is pointer-identical to `failed`, preserving any newer
    /// session concurrently established by another task.
    pub fn evict_if_same(&self, failed: &Arc<T>) -> bool {
        let mut guard = self.0.lock();
        if guard
            .current
            .as_ref()
            .is_some_and(|cur| Arc::ptr_eq(cur, failed))
        {
            guard.current = None;
            return true;
        }
        false
    }

    /// Atomically increment `generation` and take any cached session for `on_network_change()`.
    pub fn advance_generation_and_take(&self) -> Option<Arc<T>> {
        let mut guard = self.0.lock();
        guard.generation = guard.generation.wrapping_add(1);
        guard.current.take()
    }

    /// Update `low_power_mode` and, when enabling low-power mode, evict the cached session if `is_idle`.
    pub fn set_low_power_and_take_idle(
        &self,
        enabled: bool,
        is_idle: impl FnOnce(&T) -> bool,
    ) -> Option<Arc<T>> {
        let mut guard = self.0.lock();
        guard.low_power_mode = enabled;
        if enabled && guard.current.as_deref().is_some_and(is_idle) {
            return guard.current.take();
        }
        None
    }

    /// Evict and return the cached session if `low_power_mode` is active and `is_idle` holds.
    pub fn reap_if_low_power_idle(&self, is_idle: impl FnOnce(&T) -> bool) -> Option<Arc<T>> {
        let mut guard = self.0.lock();
        if guard.low_power_mode && guard.current.as_deref().is_some_and(is_idle) {
            return guard.current.take();
        }
        None
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

    #[test]
    fn cached_quic_slot_generation_isolation_and_evict_if_same() {
        #[derive(Debug)]
        struct DummySession {
            id: usize,
            active: AtomicUsize,
        }
        impl DummySession {
            fn new(id: usize) -> Arc<Self> {
                Arc::new(Self {
                    id,
                    active: AtomicUsize::new(0),
                })
            }
            fn acquire_work(&self) -> usize {
                self.active.fetch_add(1, Ordering::AcqRel) + 1
            }
        }

        let slot: CachedQuicSlot<DummySession> = CachedQuicSlot::new();
        let dial_gen = slot.current_generation();
        assert_eq!(dial_gen, 0);

        // Simulate a network transition (`on_network_change`) occurring while an old QUIC dial is in flight.
        assert!(slot.advance_generation_and_take().is_none());
        assert_eq!(slot.current_generation(), 1);

        let stale = DummySession::new(10);
        assert!(
            slot.store_if_generation_and_checkout(
                dial_gen,
                Arc::clone(&stale),
                |_| true,
                |s| { s.acquire_work() }
            )
            .is_err(),
            "stale generation dial must be rejected and never repopulate the pool"
        );
        assert!(
            slot.store_preconnect_if_generation(dial_gen, stale, |_| true)
                .is_err(),
            "stale generation preconnect must also be rejected"
        );
        assert!(slot.get_if(|_| true).is_none());

        // Store `conn_a` at generation 1, then concurrently replace with `conn_b`.
        let conn_a = DummySession::new(20);
        let conn_b = DummySession::new(21);
        assert!(
            slot.store_if_generation_and_checkout(
                1,
                Arc::clone(&conn_a),
                |_| true,
                |s| { s.acquire_work() }
            )
            .is_ok()
        );
        let (replaced, _work_b) = slot
            .store_if_generation_and_checkout(
                1,
                Arc::clone(&conn_b),
                |_| true,
                |s| s.acquire_work(),
            )
            .unwrap();
        assert_eq!(replaced.unwrap().id, 20);

        // Retry path for `conn_a` must NOT evict `conn_b`!
        assert!(!slot.evict_if_same(&conn_a));
        assert_eq!(slot.get_if(|_| true).unwrap().id, 21);

        // Evicting the actual cached `conn_b` succeeds.
        assert!(slot.evict_if_same(&conn_b));
        assert!(slot.get_if(|_| true).is_none());
    }

    #[tokio::test]
    async fn cached_quic_slot_low_power_reaps_idle_immediately_and_defers_busy_until_idle() {
        struct TestSession(Arc<QuicSessionLease>);

        let sni = "quic.lowpower.test";
        let (srv_tls, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let srv_transport = build_quinn_transport_config(
            QuicCongestionControl::Bbr,
            Some(Duration::from_secs(15)),
            Duration::from_secs(30),
            true,
        );
        let srv_cfg = build_quinn_server_config(srv_tls, srv_transport).unwrap();
        let srv_ep =
            bind_quinn_server_endpoint("127.0.0.1:0".parse().unwrap(), srv_cfg, None).unwrap();
        let srv_addr = srv_ep.local_addr().unwrap();

        let srv_bg = srv_ep.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(inc) = srv_bg.accept().await {
                tokio::spawn(async move {
                    let _ = inc.await;
                });
            }
        });

        let cli_transport = build_quinn_transport_config(
            QuicCongestionControl::Bbr,
            Some(Duration::from_secs(15)),
            Duration::from_secs(30),
            true,
        );
        let cli_cfg = build_quinn_client_config(
            false,
            std::slice::from_ref(&ca_der),
            &[b"h3".to_vec()],
            false,
            cli_transport,
        )
        .unwrap();

        let slot: Arc<CachedQuicSlot<TestSession>> = Arc::new(CachedQuicSlot::new());

        // 1. Purely idle cached QUIC session is reaped immediately on `set_low_power_and_take_idle(true)`.
        let (ep1, conn1, _, pre1) = dial_protected_quic_addrs_happy_eyeballs(
            &[srv_addr],
            sni,
            &cli_cfg,
            None,
            false,
            HAPPY_EYEBALLS_DELAY,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let idle_lease = QuicSessionLease::new_with_epoch(pre1, ep1, conn1);
        assert!(
            slot.store_preconnect_if_generation(
                0,
                Arc::new(TestSession(Arc::clone(&idle_lease))),
                |s| s.0.is_usable(),
            )
            .is_ok()
        );
        let evicted_idle = slot
            .set_low_power_and_take_idle(true, |s| s.0.active_work_count() == 0)
            .expect("idle QUIC session must be evicted immediately on screen-off");
        evicted_idle.0.close_immediately(b"low power idle");
        assert!(idle_lease.conn.close_reason().is_some());
        assert!(slot.get_if(|s| s.0.is_usable()).is_none());

        // Reset low-power mode to false, dial a busy session with two active work leases, then enable low-power mode.
        slot.set_low_power_and_take_idle(false, |_| true);
        let (ep2, conn2, _, pre2) = dial_protected_quic_addrs_happy_eyeballs(
            &[srv_addr],
            sni,
            &cli_cfg,
            None,
            false,
            HAPPY_EYEBALLS_DELAY,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let busy_lease = QuicSessionLease::new_with_epoch(pre2, ep2, conn2);
        let slot_weak = Arc::downgrade(&slot);
        busy_lease.set_idle_hook(move || {
            if let Some(slot_arc) = slot_weak.upgrade()
                && let Some(reaped) =
                    slot_arc.reap_if_low_power_idle(|s| s.0.active_work_count() == 0)
            {
                reaped.0.close_immediately(b"low power idle");
            }
        });
        let Ok((_, work1)) = slot.store_if_generation_and_checkout(
            0,
            Arc::new(TestSession(Arc::clone(&busy_lease))),
            |s| s.0.is_usable(),
            |s| s.0.acquire_work(),
        ) else {
            panic!("storing current-generation busy session must succeed");
        };
        let work2 = busy_lease.acquire_work();
        assert_eq!(busy_lease.active_work_count(), 2);

        // Enabling low-power mode while active streams exist MUST keep the session alive!
        assert!(
            slot.set_low_power_and_take_idle(true, |s| s.0.active_work_count() == 0)
                .is_none()
        );
        assert!(busy_lease.is_usable());

        drop(work1);
        assert_eq!(busy_lease.active_work_count(), 1);
        assert!(
            busy_lease.is_usable(),
            "session must stay alive until the final work lease drops"
        );

        drop(work2);
        assert_eq!(busy_lease.active_work_count(), 0);
        assert!(
            busy_lease.conn.close_reason().is_some(),
            "idle_hook must close and reap the session as soon as active_work hits 0 in low-power mode"
        );
        assert!(slot.get_if(|s| s.0.is_usable()).is_none());

        srv_ep.close(quinn::VarInt::from_u32(0), b"done");
        accept_task.abort();
    }

    #[tokio::test]
    async fn quic_happy_eyeballs_races_staggered_fallback_when_primary_blackholes() {
        use crate::platform::socket_protect::prioritize_healthy_happy_eyeballs_addrs;

        // Primary candidate: bound UDP socket that never replies (simulating silent IPv6/IPv4 blackhole, no ICMP error).
        let blackhole_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let blackhole_addr = blackhole_udp.local_addr().unwrap();

        // Secondary candidate: live local Quinn QUIC server.
        let sni = "quic.happy.eyeballs.test";
        let (srv_tls, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &[sni.to_string(), "127.0.0.1".to_string()],
            &[b"h3".to_vec()],
        )
        .unwrap();
        let srv_transport = build_quinn_transport_config(
            QuicCongestionControl::Bbr,
            Some(Duration::from_secs(15)),
            Duration::from_secs(30),
            true,
        );
        let srv_cfg = build_quinn_server_config(srv_tls, srv_transport).unwrap();
        let srv_ep =
            bind_quinn_server_endpoint("127.0.0.1:0".parse().unwrap(), srv_cfg, None).unwrap();
        let live_addr = srv_ep.local_addr().unwrap();

        let srv_bg = srv_ep.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(inc) = srv_bg.accept().await {
                tokio::spawn(async move {
                    let _ = inc.await;
                });
            }
        });

        let cli_transport = build_quinn_transport_config(
            QuicCongestionControl::Bbr,
            Some(Duration::from_secs(15)),
            Duration::from_secs(30),
            true,
        );
        let cli_cfg = build_quinn_client_config(
            false,
            std::slice::from_ref(&ca_der),
            &[b"h3".to_vec()],
            false,
            cli_transport,
        )
        .unwrap();

        let start = std::time::Instant::now();
        let (ep, conn, _used_0rtt, pre_dial) = dial_protected_quic_addrs_happy_eyeballs(
            &[blackhole_addr, live_addr],
            sni,
            &cli_cfg,
            None,
            false,
            HAPPY_EYEBALLS_DELAY,
            Duration::from_secs(5),
        )
        .await
        .expect("Happy Eyeballs QUIC dial must succeed via secondary candidate");
        let elapsed = start.elapsed();
        let lease = QuicSessionLease::new_with_epoch(pre_dial, ep, conn);

        assert_eq!(lease.conn.remote_address(), live_addr);
        assert!(
            elapsed >= Duration::from_millis(200) && elapsed < Duration::from_millis(2000),
            "expected ~250ms staggered Happy Eyeballs win instead of 12s serial timeout, got {elapsed:?}"
        );

        // Verify stalled primary candidate was recorded in `RECENT_FAILED_ADDRS` so subsequent dials prefer `live_addr` immediately!
        let reordered = prioritize_healthy_happy_eyeballs_addrs(&[blackhole_addr, live_addr]);
        assert_eq!(reordered[0], live_addr);

        lease.close_immediately(b"done");
        drop(blackhole_udp);
        srv_ep.close(quinn::VarInt::from_u32(0), b"done");
        accept_task.abort();
    }
}
