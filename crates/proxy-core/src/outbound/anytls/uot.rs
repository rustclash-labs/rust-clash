use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
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

/// Parse a single complete `sing/common/uot` packet frame (`uot.AddrParser + u16 len + payload`)
/// from `buf` without consuming ANY bytes until the entire frame is buffered.
///
/// Advances `buf` by `total_len` only once the complete frame is decoded, guaranteeing
/// cancel-safety when driven by an `AsyncReadExt::read_buf` loop.
pub fn try_parse_uot_frame(buf: &mut BytesMut) -> io::Result<Option<(Vec<u8>, TargetAddr)>> {
    let slice = buf.as_ref();
    if slice.is_empty() {
        return Ok(None);
    }

    let (src_addr, addr_len) = match slice[0] {
        UOT_AF_IPV4 => {
            const LEN: usize = 1 + 4 + 2;
            if slice.len() < LEN {
                return Ok(None);
            }
            let octets = [slice[1], slice[2], slice[3], slice[4]];
            let port = u16::from_be_bytes([slice[5], slice[6]]);
            (
                TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::from(octets)), port),
                LEN,
            )
        }
        UOT_AF_IPV6 => {
            const LEN: usize = 1 + 16 + 2;
            if slice.len() < LEN {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&slice[1..17]);
            let port = u16::from_be_bytes([slice[17], slice[18]]);
            (
                TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::from(octets)), port),
                LEN,
            )
        }
        UOT_AF_FQDN => {
            if slice.len() < 2 {
                return Ok(None);
            }
            let domain_len = slice[1] as usize;
            if domain_len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty UoT FQDN length",
                ));
            }
            let addr_len = 2 + domain_len + 2;
            if slice.len() < addr_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&slice[2..2 + domain_len]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in UoT FQDN")
            })?;
            let port = u16::from_be_bytes([slice[2 + domain_len], slice[2 + domain_len + 1]]);
            let addr = if let Ok(ip) = domain.parse::<IpAddr>() {
                TargetAddr::new_ip(ip, port)
            } else {
                TargetAddr::new_domain(domain, port)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            };
            (addr, addr_len)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected UoT address family byte 0x{other:02x}"),
            ));
        }
    };

    if slice.len() < addr_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([slice[addr_len], slice[addr_len + 1]]) as usize;
    let total_len = addr_len + 2 + payload_len;
    if slice.len() < total_len {
        return Ok(None);
    }

    let payload = slice[addr_len + 2..total_len].to_vec();
    buf.advance(total_len);
    Ok(Some((payload, src_addr)))
}

struct UotWriteHalf<S> {
    wr: WriteHalf<S>,
    header_sent: bool,
}

struct UotReadHalf<S> {
    rd: ReadHalf<S>,
    buf: BytesMut,
}

/// Persistent multi-destination `OutboundUdpSession` multiplexed over AnyTLS v2 using `sing/common/uot` v2 (`isConnect = 0`).
pub struct AnyTlsUdpSession<S = AnyTlsStream> {
    writer: AsyncMutex<UotWriteHalf<S>>,
    reader: AsyncMutex<UotReadHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite> AnyTlsUdpSession<S> {
    pub fn new(stream: S) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(UotWriteHalf {
                wr,
                header_sent: false,
            }),
            reader: AsyncMutex::new(UotReadHalf {
                rd,
                buf: BytesMut::with_capacity(4096),
            }),
        }
    }

    pub fn new_pre_initialized(stream: S) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(UotWriteHalf {
                wr,
                header_sent: true,
            }),
            reader: AsyncMutex::new(UotReadHalf {
                rd,
                buf: BytesMut::with_capacity(4096),
            }),
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> OutboundUdpSession
    for AnyTlsUdpSession<S>
{
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
        let mut guard = self.reader.lock().await;
        loop {
            if let Some(pkt) = try_parse_uot_frame(&mut guard.buf)? {
                return Ok(pkt);
            }
            let UotReadHalf { rd, buf } = &mut *guard;
            let n = rd.read_buf(buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "AnyTLS UoT stream closed",
                ));
            }
        }
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
    handle_uot_server_stream_with_upstream(
        uot_v2,
        anytls_v2,
        sid,
        initial_payload,
        srx,
        tx_clone,
        writers_clone,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_uot_server_stream_with_upstream(
    uot_v2: bool,
    anytls_v2: bool,
    sid: u32,
    initial_payload: Bytes,
    srx: mpsc::UnboundedReceiver<Bytes>,
    tx_clone: mpsc::UnboundedSender<Frame>,
    writers_clone: Arc<DashMap<u32, mpsc::UnboundedSender<Bytes>>>,
    custom_upstream: Option<Arc<Box<dyn OutboundUdpSession>>>,
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

    let upstream = if let Some(u) = custom_upstream {
        u
    } else {
        let direct = DirectOutbound::default();
        let Ok(opened) = direct.open_udp_session().await else {
            if writers_clone.remove(&sid).is_some() {
                let _ = tx_clone.send(Frame::empty(Command::Fin, sid));
            }
            return;
        };
        Arc::new(opened)
    };
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
            let mut send_err = false;
            for chunk in out.chunks(u16::MAX as usize) {
                if tx_resp
                    .send(Frame::new(Command::Psh, sid, Bytes::copy_from_slice(chunk)))
                    .is_err()
                {
                    send_err = true;
                    break;
                }
            }
            if send_err {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_uot_frame(addr: &TargetAddr, payload: &[u8]) -> BytesMut {
        let mut frame = BytesMut::with_capacity(32 + payload.len());
        encode_uot_addr(addr, &mut frame).expect("encode_uot_addr");
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        frame
    }

    #[tokio::test]
    async fn recv_from_is_cancel_safe_across_byte_by_byte_drip_and_timeouts() {
        let (client, mut server) = tokio::io::duplex(256);
        let sess = AnyTlsUdpSession::new_pre_initialized(client);

        let cases = [
            (
                TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                b"ipv4-uot-payload-0123456789".to_vec(),
            ),
            (
                TargetAddr::new_ip(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()), 443),
                b"ipv6-uot-payload".to_vec(),
            ),
            (
                TargetAddr::new_domain("dns.google", 853).unwrap(),
                b"fqdn-uot-payload-cancel-safe".to_vec(),
            ),
            (
                TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                Vec::new(),
            ),
        ];

        for (expected_addr, expected_payload) in &cases {
            let wire = build_uot_frame(expected_addr, expected_payload);
            assert!(wire.len() >= 9);

            // Drip every byte except the final one, cancelling `recv_from()` after EACH byte
            // (mid-ATYP, mid-address, mid-port, mid-u16-length, and mid-payload).
            for byte in &wire[..wire.len() - 1] {
                server.write_all(&[*byte]).await.unwrap();
                let res = tokio::time::timeout(Duration::from_millis(1), sess.recv_from()).await;
                assert!(
                    res.is_err(),
                    "incomplete UoT frame must time out and remain buffered without corruption"
                );
            }

            // Deliver the final byte and verify the intact frame is returned.
            server.write_all(&[*wire.last().unwrap()]).await.unwrap();
            let (got_payload, got_addr) =
                tokio::time::timeout(Duration::from_secs(1), sess.recv_from())
                    .await
                    .expect("complete UoT frame should arrive promptly")
                    .expect("complete UoT frame must decode cleanly");
            assert_eq!(got_addr, *expected_addr);
            assert_eq!(got_payload, *expected_payload);
        }

        // Verify two pipelined frames written in a single burst are both returned in order.
        let mut combined = build_uot_frame(&cases[0].0, b"first-burst");
        combined.extend_from_slice(&build_uot_frame(&cases[2].0, b"second-burst"));
        server.write_all(&combined).await.unwrap();

        let (p1, a1) = sess.recv_from().await.unwrap();
        let (p2, a2) = sess.recv_from().await.unwrap();
        assert_eq!((p1, a1), (b"first-burst".to_vec(), cases[0].0.clone()));
        assert_eq!((p2, a2), (b"second-burst".to_vec(), cases[2].0.clone()));

        // Verify truncated frame followed by EOF returns `UnexpectedEof`.
        server.write_all(&[UOT_AF_IPV4, 1, 2]).await.unwrap();
        drop(server);
        let err = sess
            .recv_from()
            .await
            .expect_err("EOF on truncated UoT stream must return UnexpectedEof");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn try_parse_uot_frame_validates_errors_and_preserves_partial_bytes() {
        let addr = TargetAddr::new_domain("example.com", 443).unwrap();
        let full = build_uot_frame(&addr, b"hello");

        // Partial prefixes must return `Ok(None)` without advancing/mutating `buf`.
        for prefix_len in 0..full.len() {
            let mut buf = BytesMut::from(&full[..prefix_len]);
            assert!(try_parse_uot_frame(&mut buf).unwrap().is_none());
            assert_eq!(buf.len(), prefix_len);
        }

        // Complete buffer consumes exact frame length.
        let mut buf = full.clone();
        buf.extend_from_slice(b"trailing");
        let (payload, parsed_addr) = try_parse_uot_frame(&mut buf).unwrap().unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(parsed_addr, addr);
        assert_eq!(&buf[..], b"trailing");

        // Invalid address family byte.
        let mut bad_af = BytesMut::from(&[0x99u8, 1, 2, 3][..]);
        let err = try_parse_uot_frame(&mut bad_af).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Empty FQDN length == 0.
        let mut empty_fqdn = BytesMut::from(&[UOT_AF_FQDN, 0x00, 0x00, 0x35, 0x00, 0x00][..]);
        let err = try_parse_uot_frame(&mut empty_fqdn).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Invalid UTF-8 in FQDN.
        let mut bad_utf8 =
            BytesMut::from(&[UOT_AF_FQDN, 0x02, 0xff, 0xfe, 0x00, 0x35, 0x00, 0x00][..]);
        let err = try_parse_uot_frame(&mut bad_utf8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn server_uot_splits_full_65535_byte_udp_datagram_across_psh_frames_and_roundtrips() {
        struct EchoUdpSession {
            tx: mpsc::UnboundedSender<(Vec<u8>, TargetAddr)>,
            rx: AsyncMutex<mpsc::UnboundedReceiver<(Vec<u8>, TargetAddr)>>,
        }

        #[async_trait]
        impl OutboundUdpSession for EchoUdpSession {
            async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
                self.tx
                    .send((payload.to_vec(), target.clone()))
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "echo closed"))
            }

            async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
                let mut rx = self.rx.lock().await;
                rx.recv()
                    .await
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "echo eof"))
            }
        }

        let (echo_tx, echo_rx) = mpsc::unbounded_channel();
        let upstream: Arc<Box<dyn OutboundUdpSession>> = Arc::new(Box::new(EchoUdpSession {
            tx: echo_tx,
            rx: AsyncMutex::new(echo_rx),
        }));

        let sid = 7u32;
        let (srv_in_tx, srv_in_rx) = mpsc::unbounded_channel::<Bytes>();
        let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();
        let writers = Arc::new(DashMap::new());
        writers.insert(sid, srv_in_tx.clone());
        let writers_c2s = Arc::clone(&writers);

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let (mut srv_rd, mut srv_wr) = tokio::io::split(server_io);

        // Pump client UoT writes from duplex into `srv_in_tx`.
        let pump_c2s = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match srv_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if srv_in_tx.send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                            break;
                        }
                    }
                }
            }
            writers_c2s.remove(&sid);
        });

        // Encode EVERY emitted server `Frame` via real `Frame::encode_into` (which strictly
        // rejects `data.len() > u16::MAX`!) and decode via `Frame::try_decode` before piping
        // `Command::Psh` payload bytes back to the client duplex stream.
        let pump_s2c = tokio::spawn(async move {
            let mut psh_frame_count = 0usize;
            while let Some(frame) = frame_rx.recv().await {
                assert!(
                    frame.data.len() <= u16::MAX as usize,
                    "server emitted AnyTLS frame exceeding u16::MAX: {} bytes",
                    frame.data.len()
                );
                let mut wire = BytesMut::new();
                frame
                    .encode_into(&mut wire)
                    .expect("Frame::encode_into must succeed for every UoT server frame");
                let decoded = Frame::try_decode(&mut wire)
                    .expect("Frame::try_decode must succeed")
                    .expect("complete encoded frame must decode");
                assert!(wire.is_empty());
                if decoded.cmd == Command::Psh {
                    psh_frame_count += 1;
                    if srv_wr.write_all(&decoded.data).await.is_err() {
                        break;
                    }
                    if srv_wr.flush().await.is_err() {
                        break;
                    }
                }
            }
            psh_frame_count
        });

        let srv_task = tokio::spawn(handle_uot_server_stream_with_upstream(
            true,
            true,
            sid,
            Bytes::new(),
            srv_in_rx,
            frame_tx,
            writers,
            Some(upstream),
        ));

        let client_sess = AnyTlsUdpSession::new(client_io);

        // 1. Full 65,535-byte UDP datagram with IPv4 target (wire UoT packet = 7 + 2 + 65535 = 65544 B -> 2 Psh frames).
        let max_payload: Vec<u8> = (0..u16::MAX as usize)
            .map(|i| ((i.wrapping_mul(31).wrapping_add(17)) & 0xff) as u8)
            .collect();
        let targets = [
            TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            TargetAddr::new_ip(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()), 443),
            TargetAddr::new_domain(format!("{}.example.com", "a".repeat(180)), 8443).unwrap(),
        ];

        for target in &targets {
            client_sess.send_to(&max_payload, target).await.unwrap();
            let (got_payload, got_addr) =
                tokio::time::timeout(Duration::from_secs(2), client_sess.recv_from())
                    .await
                    .expect("timed out receiving 65,535-byte UoT roundtrip")
                    .expect("65,535-byte UoT roundtrip must succeed");
            assert_eq!(got_addr, *target);
            assert_eq!(got_payload.len(), u16::MAX as usize);
            assert_eq!(got_payload, max_payload);
        }

        // 2. Follow-up small datagram confirms the stream remains healthy after chunked sends.
        client_sess.send_to(b"tail-ok", &targets[0]).await.unwrap();
        let (tail_payload, tail_addr) =
            tokio::time::timeout(Duration::from_secs(2), client_sess.recv_from())
                .await
                .expect("timed out receiving tail UoT packet")
                .expect("tail UoT packet must succeed");
        assert_eq!(tail_addr, targets[0]);
        assert_eq!(tail_payload, b"tail-ok");

        drop(client_sess);
        tokio::time::timeout(Duration::from_secs(2), srv_task)
            .await
            .expect("server task timed out shutting down")
            .unwrap();
        pump_c2s.await.unwrap();
        let psh_frames = pump_s2c.await.unwrap();
        // 3 full 65,535-byte packets (2 Psh frames each) + 1 small packet (1 Psh frame) = 7 frames.
        assert_eq!(psh_frames, 7);
    }
}
