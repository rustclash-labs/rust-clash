pub mod crypto;
pub mod stream;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use rand::Rng;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use zeroize::Zeroizing;

use crate::{
    addr::TargetAddr,
    outbound::{
        BoxedStream, DirectOutbound, OutboundHandler, OutboundUdpSession,
        ss::{
            crypto::{
                SsAeadCipher, SsCipherKind, TAG_LEN, aes_ecb_decrypt_block, aes_ecb_encrypt_block,
                random_bytes, xchacha20_poly1305_open, xchacha20_poly1305_seal,
            },
            stream::{ShadowsocksStream, unix_epoch_secs, validate_ss2022_timestamp},
        },
    },
    platform::socket_protect::{
        protected_tcp_connect_host_with_dns, protected_udp_bind, resolve_protected_host_addrs,
    },
};

pub struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    kind: SsCipherKind,
    master_key: Zeroizing<Vec<u8>>,
    udp: bool,
    dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
}

impl ShadowsocksOutbound {
    pub fn new(
        name: impl Into<String>,
        server: impl Into<String>,
        port: u16,
        cipher_str: &str,
        password: &str,
        udp: bool,
    ) -> io::Result<Self> {
        let kind = SsCipherKind::parse(cipher_str)?;
        let master_key = kind.master_key(password)?;
        Ok(Self {
            name: name.into(),
            server: server.into(),
            port,
            kind,
            master_key,
            udp,
            dns: None,
        })
    }

    pub fn with_dns(mut self, dns: Option<Arc<crate::dns::FakeIpDnsEngine>>) -> Self {
        self.dns = dns;
        self
    }

    async fn resolve_server_addr(&self) -> io::Result<SocketAddr> {
        resolve_protected_host_addrs(&self.server, self.port, self.dns.as_deref())
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SS server DNS empty"))
    }
}

/// 64-packet sliding anti-replay window per SIP022 server session ID.
#[derive(Default)]
struct SlidingReplayWindow {
    server_session_id: Option<u64>,
    max_pkt_id: u64,
    bitmap: u64,
}

impl SlidingReplayWindow {
    fn accept(&mut self, server_sid: u64, pkt_id: u64) -> bool {
        if self.server_session_id != Some(server_sid) {
            self.server_session_id = Some(server_sid);
            self.max_pkt_id = pkt_id;
            self.bitmap = 1;
            return true;
        }
        if pkt_id > self.max_pkt_id {
            let shift = pkt_id - self.max_pkt_id;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.max_pkt_id = pkt_id;
            true
        } else {
            let diff = self.max_pkt_id - pkt_id;
            if diff >= 64 {
                return false;
            }
            let mask = 1u64 << diff;
            if (self.bitmap & mask) != 0 {
                return false;
            }
            self.bitmap |= mask;
            true
        }
    }
}

struct ShadowsocksUdpSession {
    sock: UdpSocket,
    kind: SsCipherKind,
    master_key: Zeroizing<Vec<u8>>,
    client_session_id: u64,
    packet_id: AtomicU64,
    replay_window: Mutex<SlidingReplayWindow>,
}

#[async_trait]
impl OutboundUdpSession for ShadowsocksUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let pkt_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let wire_pkt = encode_ss_udp_client(
            self.kind,
            &self.master_key,
            self.client_session_id,
            pkt_id,
            target,
            payload,
        )?;
        self.sock.send(&wire_pkt).await?;
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self.sock.recv(&mut buf).await?;
            match decode_ss_udp_client_with_meta(
                self.kind,
                &self.master_key,
                self.client_session_id,
                &buf[..n],
            ) {
                Ok((server_meta, src_addr, resp_payload)) => {
                    if let Some((srv_sid, srv_pid)) = server_meta
                        && !self.replay_window.lock().accept(srv_sid, srv_pid)
                    {
                        continue;
                    }
                    return Ok((resp_payload, src_addr));
                }
                Err(_) => continue,
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for ShadowsocksOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        if self.kind.is_ss2022() {
            "Shadowsocks-2022"
        } else {
            "Shadowsocks"
        }
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        format!("{}:{}", self.server, self.port)
    }

    fn udp_supported(&self) -> bool {
        self.udp
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect_host_with_dns(&self.server, self.port, self.dns.as_deref())
            .await?;
        let ss_stream =
            ShadowsocksStream::new_client(tcp, self.kind, self.master_key.clone(), target)?;
        Ok(Box::new(ss_stream))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP disabled on this Shadowsocks outbound",
            ));
        }
        let remote = self.resolve_server_addr().await?;
        let bind_addr = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let sock = protected_udp_bind(bind_addr, Some(remote))?;
        sock.connect(remote).await?;

        Ok(Box::new(ShadowsocksUdpSession {
            sock,
            kind: self.kind,
            master_key: self.master_key.clone(),
            client_session_id: rand::random(),
            packet_id: AtomicU64::new(0),
            replay_window: Mutex::new(SlidingReplayWindow::default()),
        }))
    }
}

/// Encode client->server Shadowsocks UDP datagram (both Legacy AEAD and SIP022).
pub fn encode_ss_udp_client(
    kind: SsCipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    target: &TargetAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let addr_bytes = target.to_socks5_bytes()?;
    if !kind.is_ss2022() {
        let salt = random_bytes(kind.salt_len())?;
        let cipher = SsAeadCipher::new(kind, master_key, &salt)?;
        let mut plain = Vec::with_capacity(addr_bytes.len() + payload.len());
        plain.extend_from_slice(&addr_bytes);
        plain.extend_from_slice(payload);
        let ct = cipher.seal_with_nonce([0u8; 12], &plain)?;
        let mut out = Vec::with_capacity(salt.len() + ct.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        return Ok(out);
    }

    let pad_len: usize = rand::rng().random_range(0..=32);
    if kind == SsCipherKind::Ss2022Blake3ChaCha20Poly1305 {
        let nonce24: [u8; 24] = random_bytes(24)?.try_into().unwrap();
        let mut body =
            BytesMut::with_capacity(8 + 8 + 1 + 8 + 2 + pad_len + addr_bytes.len() + payload.len());
        body.put_u64(session_id);
        body.put_u64(packet_id);
        body.put_u8(0x00);
        body.put_u64(unix_epoch_secs());
        body.put_u16(pad_len as u16);
        body.put_bytes(0, pad_len);
        body.put_slice(&addr_bytes);
        body.put_slice(payload);
        let key32: [u8; 32] = master_key.try_into().unwrap();
        let ct = xchacha20_poly1305_seal(&key32, &nonce24, &body)?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce24);
        out.extend_from_slice(&ct);
        Ok(out)
    } else {
        // SIP022 AES-128/256-GCM separate header construction
        let mut sep_hdr = [0u8; 16];
        sep_hdr[..8].copy_from_slice(&session_id.to_be_bytes());
        sep_hdr[8..16].copy_from_slice(&packet_id.to_be_bytes());
        let enc_hdr = aes_ecb_encrypt_block(master_key, &sep_hdr)?;

        let cipher = SsAeadCipher::new(kind, master_key, &sep_hdr[..8])?;
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&sep_hdr[4..16]);

        let mut body =
            BytesMut::with_capacity(1 + 8 + 2 + pad_len + addr_bytes.len() + payload.len());
        body.put_u8(0x00);
        body.put_u64(unix_epoch_secs());
        body.put_u16(pad_len as u16);
        body.put_bytes(0, pad_len);
        body.put_slice(&addr_bytes);
        body.put_slice(payload);

        let ct = cipher.seal_with_nonce(nonce12, &body)?;
        let mut out = Vec::with_capacity(16 + ct.len());
        out.extend_from_slice(&enc_hdr);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

/// Decode server->client Shadowsocks UDP datagram on the client.
pub fn decode_ss_udp_client(
    kind: SsCipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    wire: &[u8],
) -> io::Result<(TargetAddr, Vec<u8>)> {
    let (_meta, addr, payload) =
        decode_ss_udp_client_with_meta(kind, master_key, expected_client_session_id, wire)?;
    Ok((addr, payload))
}

type DecodedSsClientUdp = (Option<(u64, u64)>, TargetAddr, Vec<u8>);

fn decode_ss_udp_client_with_meta(
    kind: SsCipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    wire: &[u8],
) -> io::Result<DecodedSsClientUdp> {
    if !kind.is_ss2022() {
        let salt_len = kind.salt_len();
        if wire.len() < salt_len + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SS UDP packet",
            ));
        }
        let cipher = SsAeadCipher::new(kind, master_key, &wire[..salt_len])?;
        let plain = cipher.open_with_nonce([0u8; 12], &wire[salt_len..])?;
        let (addr, used) = TargetAddr::decode_socks5_slice(&plain)?;
        return Ok((None, addr, plain[used..].to_vec()));
    }

    let (srv_sid, srv_pid, body) = if kind == SsCipherKind::Ss2022Blake3ChaCha20Poly1305 {
        if wire.len() < 24 + TAG_LEN + 35 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SS-2022 XChaCha UDP",
            ));
        }
        let nonce24: [u8; 24] = wire[..24].try_into().unwrap();
        let key32: [u8; 32] = master_key.try_into().unwrap();
        let plain = xchacha20_poly1305_open(&key32, &nonce24, &wire[24..])?;
        let sid = u64::from_be_bytes(plain[..8].try_into().unwrap());
        let pid = u64::from_be_bytes(plain[8..16].try_into().unwrap());
        (sid, pid, plain[16..].to_vec())
    } else {
        if wire.len() < 16 + TAG_LEN + 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SS-2022 AES UDP",
            ));
        }
        let enc_hdr: [u8; 16] = wire[..16].try_into().unwrap();
        let sep_hdr = aes_ecb_decrypt_block(master_key, &enc_hdr)?;
        let sid = u64::from_be_bytes(sep_hdr[..8].try_into().unwrap());
        let pid = u64::from_be_bytes(sep_hdr[8..16].try_into().unwrap());
        let cipher = SsAeadCipher::new(kind, master_key, &sep_hdr[..8])?;
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&sep_hdr[4..16]);
        let plain = cipher.open_with_nonce(nonce12, &wire[16..])?;
        (sid, pid, plain)
    };

    // Server -> Client body: `type=1 (1B) | ts (8B) | client_session_id (8B) | pad_len (2B) | pad | addr | payload`
    if body.len() < 19 || body[0] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SS-2022 UDP response header",
        ));
    }
    let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
    validate_ss2022_timestamp(ts)?;
    let got_client_sid = u64::from_be_bytes(body[9..17].try_into().unwrap());
    if got_client_sid != expected_client_session_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SS-2022 UDP client_session_id mismatch",
        ));
    }
    let pad_len = u16::from_be_bytes([body[17], body[18]]) as usize;
    if body.len() < 19 + pad_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated SS-2022 UDP pad",
        ));
    }
    let rest = &body[19 + pad_len..];
    let (addr, used) = TargetAddr::decode_socks5_slice(rest)?;
    Ok((Some((srv_sid, srv_pid)), addr, rest[used..].to_vec()))
}

struct ServerUdpSession {
    tx: mpsc::Sender<(TargetAddr, Vec<u8>)>,
    last_active: Instant,
}

/// Spawn a full TCP + stateful UDP Shadowsocks (AEAD & SS-2022) server (with 60s salt replay protection!).
pub async fn spawn_ss_server(
    listen_addr: &str,
    cipher_str: &str,
    password: &str,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let kind = SsCipherKind::parse(cipher_str)?;
    let master_key = kind.master_key(password)?;

    let tcp_listener = TcpListener::bind(listen_addr).await?;
    let bound_addr = tcp_listener.local_addr()?;
    let udp_socket = Arc::new(UdpSocket::bind(bound_addr).await?);

    let replay_cache: Arc<Mutex<HashMap<Vec<u8>, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn matching stateful UDP NAT server loop
    let udp_mk = master_key.clone();
    let mut udp_shutdown = shutdown.clone();
    let udp_sock_clone = Arc::clone(&udp_socket);
    tokio::spawn(async move {
        let mut sessions: HashMap<(SocketAddr, u64), ServerUdpSession> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                changed = udp_shutdown.changed() => {
                    if changed.is_err() || *udp_shutdown.borrow() {
                        break;
                    }
                }
                recv_res = udp_sock_clone.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv_res else {
                        continue;
                    };
                    let Ok((client_sid, dst, payload)) = decode_ss_udp_server(kind, &udp_mk, &buf[..n]) else {
                        continue;
                    };
                    let now = Instant::now();
                    sessions.retain(|_, s| now.duration_since(s.last_active) < Duration::from_secs(60) && !s.tx.is_closed());

                    let key = (peer, client_sid);
                    if let Some(existing) = sessions.get_mut(&key)
                        && existing.tx.try_send((dst.clone(), payload.clone())).is_ok()
                    {
                        existing.last_active = now;
                        continue;
                    }

                    if sessions.len() >= 256 {
                        continue;
                    }
                    let (tx, mut rx) = mpsc::channel::<(TargetAddr, Vec<u8>)>(64);
                    let _ = tx.try_send((dst, payload));
                    sessions.insert(key, ServerUdpSession { tx, last_active: now });

                    let mk_task = udp_mk.clone();
                    let sock_tx = Arc::clone(&udp_sock_clone);
                    tokio::spawn(async move {
                        let direct = DirectOutbound::default();
                        let Ok(upstream) = direct.open_udp_session().await else {
                            return;
                        };
                        let upstream: Arc<Box<dyn OutboundUdpSession>> = Arc::new(upstream);
                        let upstream_rx = Arc::clone(&upstream);
                        let server_sid: u64 = rand::random();
                        let pkt_seq = Arc::new(AtomicU64::new(0));

                        let writer = async move {
                            while let Some((target, data)) = rx.recv().await {
                                let _ = upstream.send_to(&data, &target).await;
                            }
                        };
                        let reader = async move {
                            while let Ok(res) = tokio::time::timeout(Duration::from_secs(60), upstream_rx.recv_from()).await {
                                let Ok((resp, src_addr)) = res else {
                                    break;
                                };
                                let pid = pkt_seq.fetch_add(1, Ordering::Relaxed);
                                if let Ok(wire) = encode_ss_udp_server(kind, &mk_task, server_sid, pid, client_sid, &src_addr, &resp) {
                                    let _ = sock_tx.send_to(&wire, peer).await;
                                }
                            }
                        };
                        tokio::select! {
                            _ = writer => {}
                            _ = reader => {}
                        }
                    });
                }
            }
        }
    });

    let tcp_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = tcp_listener.accept() => {
                    let Ok((tcp, _peer)) = accepted else {
                        continue;
                    };
                    let _ = tcp.set_nodelay(true);
                    let mk = master_key.clone();
                    let cache = Arc::clone(&replay_cache);
                    tokio::spawn(async move {
                        let _ = handle_ss_server_tcp(tcp, kind, mk, cache).await;
                    });
                }
            }
        }
    });

    Ok((bound_addr, tcp_handle))
}

async fn handle_ss_server_tcp(
    mut tcp: TcpStream,
    kind: SsCipherKind,
    master_key: Zeroizing<Vec<u8>>,
    replay_cache: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
) -> io::Result<()> {
    let salt_len = kind.salt_len();

    if kind.is_ss2022() {
        let mut prefix = vec![0u8; salt_len + 27];
        tcp.read_exact(&mut prefix).await?;
        let req_salt = prefix[..salt_len].to_vec();
        let mut dec = SsAeadCipher::new(kind, &master_key, &req_salt)?;
        let fixed_plain = dec.open(&prefix[salt_len..])?;
        if fixed_plain[0] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SS-2022 client request header type",
            ));
        }
        let ts = u64::from_be_bytes(fixed_plain[1..9].try_into().unwrap());
        validate_ss2022_timestamp(ts)?;

        {
            let mut guard = replay_cache.lock();
            let now = Instant::now();
            guard.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
            if guard.contains_key(&req_salt) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SS-2022 salt replay detected",
                ));
            }
            guard.insert(req_salt.clone(), now);
        }

        let var_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;
        let mut var_wire = vec![0u8; var_len + TAG_LEN];
        tcp.read_exact(&mut var_wire).await?;
        let var_plain = dec.open(&var_wire)?;

        let (target, addr_used) = TargetAddr::decode_socks5_slice(&var_plain)?;
        if var_plain.len() < addr_used + 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated SS-2022 variable header",
            ));
        }
        let pad_len = u16::from_be_bytes([var_plain[addr_used], var_plain[addr_used + 1]]) as usize;
        if pad_len > 900 || var_plain.len() < addr_used + 2 + pad_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SS-2022 variable header padding",
            ));
        }
        let init_payload = &var_plain[addr_used + 2 + pad_len..];
        if pad_len == 0 && init_payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SS-2022 forbids empty padding AND empty initial payload",
            ));
        }

        let mut initial_plain = BytesMut::new();
        initial_plain.extend_from_slice(init_payload);

        let mut ss_stream = ShadowsocksStream::from_server_parts(
            tcp,
            kind,
            master_key,
            dec,
            req_salt,
            BytesMut::new(),
            initial_plain,
        );
        let direct = DirectOutbound::default();
        let mut outbound = direct.connect_tcp(&target).await?;
        let _ = tokio::io::copy_bidirectional(&mut ss_stream, &mut outbound).await?;
        Ok(())
    } else {
        let mut hdr = vec![0u8; salt_len + 2 + TAG_LEN];
        tcp.read_exact(&mut hdr).await?;
        let req_salt = hdr[..salt_len].to_vec();
        let mut dec = SsAeadCipher::new(kind, &master_key, &req_salt)?;
        let len_plain = dec.open(&hdr[salt_len..])?;
        let plen = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        if plen == 0 || plen > 0x3FFF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SS AEAD plen",
            ));
        }
        let mut first_wire = vec![0u8; plen + TAG_LEN];
        tcp.read_exact(&mut first_wire).await?;
        let first_plain = dec.open(&first_wire)?;
        let (target, addr_used) = TargetAddr::decode_socks5_slice(&first_plain)?;

        let mut initial_plain = BytesMut::new();
        initial_plain.extend_from_slice(&first_plain[addr_used..]);

        let mut ss_stream = ShadowsocksStream::from_server_parts(
            tcp,
            kind,
            master_key,
            dec,
            req_salt,
            BytesMut::new(),
            initial_plain,
        );
        let direct = DirectOutbound::default();
        let mut outbound = direct.connect_tcp(&target).await?;
        let _ = tokio::io::copy_bidirectional(&mut ss_stream, &mut outbound).await?;
        Ok(())
    }
}

fn decode_ss_udp_server(
    kind: SsCipherKind,
    master_key: &[u8],
    wire: &[u8],
) -> io::Result<(u64, TargetAddr, Vec<u8>)> {
    if !kind.is_ss2022() {
        let salt_len = kind.salt_len();
        if wire.len() < salt_len + TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short SS UDP"));
        }
        let cipher = SsAeadCipher::new(kind, master_key, &wire[..salt_len])?;
        let plain = cipher.open_with_nonce([0u8; 12], &wire[salt_len..])?;
        let (addr, used) = TargetAddr::decode_socks5_slice(&plain)?;
        return Ok((0, addr, plain[used..].to_vec()));
    }

    let (client_sid, body) = if kind == SsCipherKind::Ss2022Blake3ChaCha20Poly1305 {
        if wire.len() < 24 + TAG_LEN + 27 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SS-2022 XChaCha UDP",
            ));
        }
        let nonce24: [u8; 24] = wire[..24].try_into().unwrap();
        let key32: [u8; 32] = master_key.try_into().unwrap();
        let plain = xchacha20_poly1305_open(&key32, &nonce24, &wire[24..])?;
        let sid = u64::from_be_bytes(plain[..8].try_into().unwrap());
        (sid, plain[16..].to_vec())
    } else {
        if wire.len() < 16 + TAG_LEN + 18 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SS-2022 AES UDP",
            ));
        }
        let enc_hdr: [u8; 16] = wire[..16].try_into().unwrap();
        let sep_hdr = aes_ecb_decrypt_block(master_key, &enc_hdr)?;
        let sid = u64::from_be_bytes(sep_hdr[..8].try_into().unwrap());
        let cipher = SsAeadCipher::new(kind, master_key, &sep_hdr[..8])?;
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&sep_hdr[4..16]);
        let plain = cipher.open_with_nonce(nonce12, &wire[16..])?;
        (sid, plain)
    };

    if body.len() < 11 || body[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SS-2022 UDP req type",
        ));
    }
    let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
    validate_ss2022_timestamp(ts)?;
    let pad_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    if body.len() < 11 + pad_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SS-2022 UDP pad",
        ));
    }
    let rest = &body[11 + pad_len..];
    let (addr, used) = TargetAddr::decode_socks5_slice(rest)?;
    Ok((client_sid, addr, rest[used..].to_vec()))
}

fn encode_ss_udp_server(
    kind: SsCipherKind,
    master_key: &[u8],
    server_sid: u64,
    packet_id: u64,
    client_sid: u64,
    src_addr: &TargetAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let addr_bytes = src_addr.to_socks5_bytes()?;
    if !kind.is_ss2022() {
        let salt = random_bytes(kind.salt_len())?;
        let cipher = SsAeadCipher::new(kind, master_key, &salt)?;
        let mut plain = Vec::with_capacity(addr_bytes.len() + payload.len());
        plain.extend_from_slice(&addr_bytes);
        plain.extend_from_slice(payload);
        let ct = cipher.seal_with_nonce([0u8; 12], &plain)?;
        let mut out = Vec::with_capacity(salt.len() + ct.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        return Ok(out);
    }

    if kind == SsCipherKind::Ss2022Blake3ChaCha20Poly1305 {
        let nonce24: [u8; 24] = random_bytes(24)?.try_into().unwrap();
        let mut body = BytesMut::with_capacity(35 + addr_bytes.len() + payload.len());
        body.put_u64(server_sid);
        body.put_u64(packet_id);
        body.put_u8(0x01);
        body.put_u64(unix_epoch_secs());
        body.put_u64(client_sid);
        body.put_u16(0); // pad_len = 0
        body.put_slice(&addr_bytes);
        body.put_slice(payload);
        let key32: [u8; 32] = master_key.try_into().unwrap();
        let ct = xchacha20_poly1305_seal(&key32, &nonce24, &body)?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce24);
        out.extend_from_slice(&ct);
        Ok(out)
    } else {
        let mut sep_hdr = [0u8; 16];
        sep_hdr[..8].copy_from_slice(&server_sid.to_be_bytes());
        sep_hdr[8..16].copy_from_slice(&packet_id.to_be_bytes());
        let enc_hdr = aes_ecb_encrypt_block(master_key, &sep_hdr)?;
        let cipher = SsAeadCipher::new(kind, master_key, &sep_hdr[..8])?;
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&sep_hdr[4..16]);

        let mut body = BytesMut::with_capacity(19 + addr_bytes.len() + payload.len());
        body.put_u8(0x01);
        body.put_u64(unix_epoch_secs());
        body.put_u64(client_sid);
        body.put_u16(0); // pad_len = 0
        body.put_slice(&addr_bytes);
        body.put_slice(payload);
        let ct = cipher.seal_with_nonce(nonce12, &body)?;
        let mut out = Vec::with_capacity(16 + ct.len());
        out.extend_from_slice(&enc_hdr);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}
