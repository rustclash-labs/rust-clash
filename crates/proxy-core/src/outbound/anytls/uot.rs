use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::{Mutex as AsyncMutex, mpsc},
};

use crate::{
    addr::{HostName, TargetAddr},
    outbound::{
        DirectOutbound, OutboundHandler, OutboundUdpSession,
        anytls::{
            frame::{Command, Frame},
            session::AnyTlsStream,
        },
    },
};

/// SagerNet `sing/common/uot` v2 magic domain (`Version = 2`) used by `anytls-go`, `sing-box`, and `mihomo`.
pub const UOT_V2_MAGIC_DOMAIN: &str = "sp.v2.udp-over-tcp.arpa";
/// Legacy `sing/common/uot` v1 magic domain (`LegacyVersion = 1`).
pub const UOT_V1_MAGIC_DOMAIN: &str = "udp-over-tcp.arpa";

const UOT_AF_IPV4: u8 = 0x00;
const UOT_AF_IPV6: u8 = 0x01;
const UOT_AF_FQDN: u8 = 0x02;

/// Encode a `TargetAddr` using `sing/common/uot.AddrParser` wire format:
/// - `0x00` + 4B IPv4 + 2B BE port
/// - `0x01` + 16B IPv6 + 2B BE port
/// - `0x02` + 1B len + FQDN + 2B BE port
pub fn encode_uot_addr(addr: &TargetAddr, out: &mut BytesMut) -> io::Result<()> {
    match &addr.host {
        HostName::Ip(IpAddr::V4(v4)) => {
            out.put_u8(UOT_AF_IPV4);
            out.put_slice(&v4.octets());
            out.put_u16(addr.port);
        }
        HostName::Ip(IpAddr::V6(v6)) => {
            out.put_u8(UOT_AF_IPV6);
            out.put_slice(&v6.octets());
            out.put_u16(addr.port);
        }
        HostName::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UoT domain exceeds 255 bytes",
                ));
            }
            out.put_u8(UOT_AF_FQDN);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
            out.put_u16(addr.port);
        }
    }
    Ok(())
}

/// Read a `TargetAddr` encoded with `sing/common/uot.AddrParser`.
pub async fn read_uot_addr<R: AsyncRead + Unpin>(rd: &mut R) -> io::Result<TargetAddr> {
    let af = rd.read_u8().await?;
    match af {
        UOT_AF_IPV4 => {
            let mut octets = [0u8; 4];
            rd.read_exact(&mut octets).await?;
            let port = rd.read_u16().await?;
            Ok(TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        UOT_AF_IPV6 => {
            let mut octets = [0u8; 16];
            rd.read_exact(&mut octets).await?;
            let port = rd.read_u16().await?;
            Ok(TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        UOT_AF_FQDN => {
            let len = rd.read_u8().await? as usize;
            let mut raw = vec![0u8; len];
            rd.read_exact(&mut raw).await?;
            let port = rd.read_u16().await?;
            let domain = String::from_utf8(raw).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in UoT FQDN")
            })?;
            if let Ok(ip) = domain.parse::<IpAddr>() {
                Ok(TargetAddr::new_ip(ip, port))
            } else {
                TargetAddr::new_domain(domain, port)
            }
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected UoT address family byte 0x{other:02x}"),
        )),
    }
}

/// Encode a `sing/common/uot` v2 stream request header:
/// `isConnect: u8` + `M.SocksaddrSerializer` (`0x01` IPv4 / `0x03` FQDN / `0x04` IPv6 + 2B BE port).
/// Note: `uot/router.go` uses `M.SocksaddrSerializer` for the initial `Request` header, whereas
/// `uot/protocol.go` uses `uot.AddrParser` (`0x00`/`0x01`/`0x02`) for per-packet addresses!
pub fn encode_uot_v2_request(
    is_connect: bool,
    destination: &TargetAddr,
    out: &mut BytesMut,
) -> io::Result<()> {
    out.put_u8(u8::from(is_connect));
    destination.encode_socks5(out)
}

/// Read a `sing/common/uot` v2 stream request header (`isConnect: u8` + `M.SocksaddrSerializer`).
pub async fn read_uot_v2_request<R: AsyncRead + Unpin>(
    rd: &mut R,
) -> io::Result<(bool, TargetAddr)> {
    let is_connect = rd.read_u8().await? != 0;
    let destination = TargetAddr::read_socks5(rd).await?;
    Ok((is_connect, destination))
}

struct UotWriteHalf {
    wr: WriteHalf<AnyTlsStream>,
    header_sent: bool,
}

/// Persistent multi-destination `OutboundUdpSession` multiplexed over AnyTLS v2 using `sing/common/uot` v2 (`isConnect = 0`).
pub struct AnyTlsUdpSession {
    writer: AsyncMutex<UotWriteHalf>,
    reader: AsyncMutex<ReadHalf<AnyTlsStream>>,
}

impl AnyTlsUdpSession {
    pub fn new(stream: AnyTlsStream) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(UotWriteHalf {
                wr,
                header_sent: false,
            }),
            reader: AsyncMutex::new(rd),
        }
    }

    pub fn new_pre_initialized(stream: AnyTlsStream) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(UotWriteHalf {
                wr,
                header_sent: true,
            }),
            reader: AsyncMutex::new(rd),
        }
    }
}

#[async_trait]
impl OutboundUdpSession for AnyTlsUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS UoT UDP datagram exceeds 65535 bytes",
            ));
        }
        let mut guard = self.writer.lock().await;
        let mut frame = BytesMut::with_capacity(32 + payload.len());
        if !guard.header_sent {
            let unspec = TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            encode_uot_v2_request(false, &unspec, &mut frame)?;
            guard.header_sent = true;
        }
        encode_uot_addr(target, &mut frame)?;
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        guard.wr.write_all(&frame).await?;
        guard.wr.flush().await?;
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut rd = self.reader.lock().await;
        let src_addr = read_uot_addr(&mut *rd).await?;
        let len = rd.read_u16().await? as usize;
        let mut data = vec![0u8; len];
        rd.read_exact(&mut data).await?;
        Ok((data, src_addr))
    }
}

/// AsyncRead adapter over an initial `Bytes` buffer followed by `mpsc::UnboundedReceiver<Bytes>`,
/// used by `spawn_anytls_server` to parse UoT v1/v2 frames cleanly across AnyTLS `cmdPSH` boundaries.
struct ServerChannelReader {
    buf: BytesMut,
    rx: mpsc::UnboundedReceiver<Bytes>,
}

impl AsyncRead for ServerChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let take = out.remaining().min(self.buf.len());
                out.put_slice(&self.buf.split_to(take));
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    if !chunk.is_empty() {
                        self.buf.extend_from_slice(&chunk);
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Server-side handler for `sp.v2.udp-over-tcp.arpa` (`uot_v2 = true`) and `udp-over-tcp.arpa` (`uot_v2 = false`) streams.
pub async fn handle_uot_server_stream(
    uot_v2: bool,
    anytls_v2: bool,
    sid: u32,
    initial_payload: Bytes,
    srx: mpsc::UnboundedReceiver<Bytes>,
    tx_clone: mpsc::UnboundedSender<Frame>,
    writers_clone: Arc<DashMap<u32, mpsc::UnboundedSender<Bytes>>>,
) {
    if anytls_v2 {
        let _ = tx_clone.send(Frame::empty(Command::SynAck, sid));
    }

    let mut rd = ServerChannelReader {
        buf: BytesMut::from(initial_payload.as_ref()),
        rx: srx,
    };

    let (is_connect, default_dst) = if uot_v2 {
        match read_uot_v2_request(&mut rd).await {
            Ok(req) => req,
            Err(_) => {
                if writers_clone.remove(&sid).is_some() {
                    let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
                }
                return;
            }
        }
    } else {
        (
            false,
            TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
    };

    let direct = DirectOutbound::default();
    let Ok(upstream) = direct.open_udp_session().await else {
        if writers_clone.remove(&sid).is_some() {
            let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
        }
        return;
    };
    let upstream = Arc::new(upstream);
    let upstream_rx = Arc::clone(&upstream);
    let tx_resp = tx_clone.clone();

    let client_to_up = async move {
        if is_connect {
            while let Ok(plen) = rd.read_u16().await {
                let mut payload = vec![0u8; plen as usize];
                if rd.read_exact(&mut payload).await.is_err() {
                    break;
                }
                let _ = upstream.send_to(&payload, &default_dst).await;
            }
        } else {
            while let Ok(dst) = read_uot_addr(&mut rd).await {
                let Ok(plen) = rd.read_u16().await else {
                    break;
                };
                let mut payload = vec![0u8; plen as usize];
                if rd.read_exact(&mut payload).await.is_err() {
                    break;
                }
                let _ = upstream.send_to(&payload, &dst).await;
            }
        }
    };

    let up_to_client = async move {
        while let Ok(res) =
            tokio::time::timeout(Duration::from_secs(60), upstream_rx.recv_from()).await
        {
            let Ok((resp, src_addr)) = res else {
                break;
            };
            if resp.len() > u16::MAX as usize {
                continue;
            }
            let mut out = BytesMut::with_capacity(28 + resp.len());
            if !is_connect && encode_uot_addr(&src_addr, &mut out).is_err() {
                continue;
            }
            out.put_u16(resp.len() as u16);
            out.put_slice(&resp);
            if tx_resp
                .send(Frame::new(Command::Psh, sid, out.freeze()))
                .is_err()
            {
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_up => {}
        _ = up_to_client => {}
    }

    if writers_clone.remove(&sid).is_some() {
        let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
    }
}
