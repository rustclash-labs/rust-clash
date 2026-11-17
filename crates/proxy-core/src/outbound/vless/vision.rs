use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{Mutex as AsyncMutex, mpsc},
};
use uuid::Uuid;

use crate::{
    addr::TargetAddr,
    outbound::{OutboundUdpSession, vless::reality::Tls13VisionStream},
};

/// Protobuf-encoded `vless.encoding.Addons { string Flow = 1; }` for `Flow = "xtls-rprx-vision"`.
pub const VISION_ADDONS_PROTOBUF: &[u8] = b"\x0a\x10xtls-rprx-vision";

pub const CMD_PADDING_CONTINUE: u8 = 0x00;
pub const CMD_PADDING_END: u8 = 0x01;
pub const CMD_PADDING_DIRECT: u8 = 0x02;

const TLS13_SUPPORTED_VERSIONS_EXT: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];
const MAX_VISION_PLAIN_CHUNK: usize = 7600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VlessVisionFlow {
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

impl VlessVisionFlow {
    pub fn parse(raw: &str) -> io::Result<Option<Self>> {
        let s = raw.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("none") {
            return Ok(None);
        }
        if s.eq_ignore_ascii_case("xtls-rprx-vision") {
            return Ok(Some(Self::XtlsRprxVision));
        }
        if s.eq_ignore_ascii_case("xtls-rprx-vision-udp443") {
            return Ok(Some(Self::XtlsRprxVisionUdp443));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported VLESS flow '{s}' (supported: xtls-rprx-vision, xtls-rprx-vision-udp443)"
            ),
        ))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::XtlsRprxVision => "xtls-rprx-vision",
            Self::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }

    pub fn allows_udp_port(self, port: u16) -> bool {
        match self {
            Self::XtlsRprxVision => port != 443,
            Self::XtlsRprxVisionUdp443 => true,
        }
    }
}

#[derive(Debug)]
struct VisionTrafficState {
    user_uuid: [u8; 16],
    packets_to_filter: i32,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl VisionTrafficState {
    fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            packets_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    fn filter_tls_packet(&mut self, pkt: &[u8]) {
        if self.packets_to_filter <= 0 || pkt.is_empty() {
            return;
        }
        self.packets_to_filter -= 1;

        if pkt.len() >= 6 {
            if pkt[0..3] == [0x16, 0x03, 0x03] && pkt[5] == 0x02 {
                // TLS ServerHello
                let rec_len = u16::from_be_bytes([pkt[3], pkt[4]]) as i32;
                self.remaining_server_hello = rec_len + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if pkt.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid_len = pkt[43] as usize;
                    if 43 + sid_len + 3 <= pkt.len() {
                        self.cipher =
                            u16::from_be_bytes([pkt[43 + sid_len + 1], pkt[43 + sid_len + 2]]);
                    }
                }
            } else if pkt[0..2] == [0x16, 0x03] && pkt[5] == 0x01 {
                // TLS ClientHello
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(pkt.len());
            self.remaining_server_hello -= pkt.len() as i32;
            if contains_subslice(&pkt[..end], TLS13_SUPPORTED_VERSIONS_EXT) {
                // Supported TLS 1.3 cipher suites except TLS_AES_128_CCM_8_SHA256 (0x1305)
                if matches!(self.cipher, 0x1301..=0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                // TLS 1.2 ServerHello finished without TLS 1.3 supported_versions
                self.packets_to_filter = 0;
            }
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Returns true iff `data` consists of one or more complete TLS 1.2/1.3 `ApplicationData`
/// (`0x17 0x03 0x03 <u16 len>`) records with zero trailing partial bytes.
pub fn is_complete_tls_app_data_record(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let mut idx = 0usize;
    while idx < data.len() {
        if data.len() - idx < 5 {
            return false;
        }
        if data[idx] != 0x17 || data[idx + 1] != 0x03 || data[idx + 2] != 0x03 {
            return false;
        }
        let rlen = u16::from_be_bytes([data[idx + 3], data[idx + 4]]) as usize;
        if rlen == 0 || data.len() - (idx + 5) < rlen {
            return false;
        }
        idx += 5 + rlen;
    }
    idx == data.len()
}

fn compute_vision_padding_len(content_len: usize, long_padding: bool) -> usize {
    let mut rng = rand::rng();
    let pad = if content_len < DEFAULT_TESTSEED[0] as usize && long_padding {
        let rand_part = rng.random_range(0..DEFAULT_TESTSEED[1]) as usize;
        (rand_part + DEFAULT_TESTSEED[2] as usize).saturating_sub(content_len)
    } else {
        rng.random_range(0..DEFAULT_TESTSEED[3]) as usize
    };
    let max_pad = (8192usize).saturating_sub(21 + content_len);
    pad.min(max_pad)
}

fn append_vision_padded_block(
    out: &mut BytesMut,
    content: &[u8],
    command: u8,
    write_once_uuid: &mut Option<[u8; 16]>,
    long_padding: bool,
) {
    let pad_len = compute_vision_padding_len(content.len(), long_padding);
    if let Some(uuid) = write_once_uuid.take() {
        out.put_slice(&uuid);
    }
    out.put_u8(command);
    out.put_u16(content.len() as u16);
    out.put_u16(pad_len as u16);
    out.put_slice(content);
    if pad_len > 0 {
        out.put_bytes(0, pad_len);
    }
}

fn split_for_vision_padding(data: &[u8]) -> Vec<&[u8]> {
    if data.len() <= MAX_VISION_PLAIN_CHUNK {
        return vec![data];
    }
    let mut chunks = Vec::new();
    let mut rest = data;
    while rest.len() > MAX_VISION_PLAIN_CHUNK {
        // Prefer splitting at an inner TLS ApplicationData boundary (`0x17 0x03 0x03`) if present
        let window = &rest[..MAX_VISION_PLAIN_CHUNK];
        let mut split_at = MAX_VISION_PLAIN_CHUNK / 2;
        if let Some(pos) = window.windows(3).rposition(|w| w == [0x17, 0x03, 0x03])
            && pos >= 21
        {
            split_at = pos;
        }
        chunks.push(&rest[..split_at]);
        rest = &rest[split_at..];
    }
    if !rest.is_empty() {
        chunks.push(rest);
    }
    chunks
}

#[derive(Debug)]
enum RespHeaderState {
    NeedVerAndLen,
    NeedAddons(usize),
    Done,
}

#[derive(Debug)]
enum UnpadState {
    InitialUuid {
        buf: [u8; 21],
        filled: usize,
    },
    BlockHeader {
        hdr: [u8; 5],
        filled: usize,
    },
    BlockBody {
        cmd: u8,
        rem_content: usize,
        rem_padding: usize,
    },
    FinishedEncrypted,
    FinishedDirect,
}

/// Pure-Rust `xtls-rprx-vision` stream over [`Tls13VisionStream<S>`].
///
/// Handles:
/// - 0-RTT coalescing of VLESS request header + initial Vision padded frame (or empty-content
///   camouflage frame on server-speaks-first reads).
/// - Stripping the VLESS `[0x00, addons_len, addons...]` response header before Vision unpadding.
/// - `XtlsFilterTls` inner TLS 1.3 handshake recognition (`0x1301..=0x1304`).
/// - `CommandPaddingContinue (0)`, `CommandPaddingEnd (1)`, and `CommandPaddingDirect (2)` raw-TCP
///   zero-double-encryption splice transition (`enable_direct_write` / `enable_direct_read`).
pub struct VisionStream<S> {
    tls: Tls13VisionStream<S>,
    traffic: VisionTrafficState,
    pending_wire_prefix: BytesMut,
    header_sent: bool,
    write_once_uuid: Option<[u8; 16]>,
    is_padding_write: bool,
    pending_write_accepted: Option<usize>,
    resp_hdr_state: RespHeaderState,
    resp_hdr_buf: BytesMut,
    unpad_state: UnpadState,
    ready_rx_buf: BytesMut,
}

impl<S> VisionStream<S> {
    /// Wrap an established client [`Tls13VisionStream`] with VLESS + `xtls-rprx-vision` framing.
    pub fn new_client(tls: Tls13VisionStream<S>, user_uuid: Uuid, vless_req_hdr: BytesMut) -> Self {
        let uuid_bytes = *user_uuid.as_bytes();
        Self {
            tls,
            traffic: VisionTrafficState::new(uuid_bytes),
            pending_wire_prefix: vless_req_hdr,
            header_sent: false,
            write_once_uuid: Some(uuid_bytes),
            is_padding_write: true,
            pending_write_accepted: None,
            resp_hdr_state: RespHeaderState::NeedVerAndLen,
            resp_hdr_buf: BytesMut::with_capacity(8),
            unpad_state: UnpadState::InitialUuid {
                buf: [0u8; 21],
                filled: 0,
            },
            ready_rx_buf: BytesMut::with_capacity(16 * 1024),
        }
    }

    /// Wrap an accepted server [`Tls13VisionStream`] after reading the VLESS request header
    /// (coalesces `[0x00, 0x00]` VLESS response header onto first server Vision write).
    pub fn new_server(tls: Tls13VisionStream<S>, user_uuid: Uuid, initial_overread: &[u8]) -> Self {
        let uuid_bytes = *user_uuid.as_bytes();
        let mut s = Self {
            tls,
            traffic: VisionTrafficState::new(uuid_bytes),
            pending_wire_prefix: BytesMut::from(&[0x00u8, 0x00u8][..]),
            header_sent: false,
            write_once_uuid: Some(uuid_bytes),
            is_padding_write: true,
            pending_write_accepted: None,
            resp_hdr_state: RespHeaderState::Done,
            resp_hdr_buf: BytesMut::new(),
            unpad_state: UnpadState::InitialUuid {
                buf: [0u8; 21],
                filled: 0,
            },
            ready_rx_buf: BytesMut::with_capacity(16 * 1024),
        };
        if !initial_overread.is_empty() {
            s.feed_unpad_bytes(initial_overread);
        }
        s
    }

    fn feed_unpad_bytes(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            match &mut self.unpad_state {
                UnpadState::FinishedEncrypted | UnpadState::FinishedDirect => {
                    if self.traffic.packets_to_filter > 0 {
                        self.traffic.filter_tls_packet(input);
                    }
                    self.ready_rx_buf.extend_from_slice(input);
                    break;
                }
                UnpadState::InitialUuid { buf, filled } => {
                    let need = 21 - *filled;
                    let take = need.min(input.len());
                    buf[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    input = &input[take..];
                    if *filled == 21 {
                        if buf[..16] == self.traffic.user_uuid {
                            let cmd = buf[16];
                            let rem_content = u16::from_be_bytes([buf[17], buf[18]]) as usize;
                            let rem_padding = u16::from_be_bytes([buf[19], buf[20]]) as usize;
                            self.unpad_state = UnpadState::BlockBody {
                                cmd,
                                rem_content,
                                rem_padding,
                            };
                            // Handle 0-length content + 0-length padding edge case immediately
                            self.finish_block_if_zero();
                        } else {
                            let literal = *buf;
                            self.traffic.filter_tls_packet(&literal);
                            self.ready_rx_buf.extend_from_slice(&literal);
                            self.unpad_state = UnpadState::FinishedEncrypted;
                        }
                    }
                }
                UnpadState::BlockHeader { hdr, filled } => {
                    let need = 5 - *filled;
                    let take = need.min(input.len());
                    hdr[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    input = &input[take..];
                    if *filled == 5 {
                        let cmd = hdr[0];
                        let rem_content = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
                        let rem_padding = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                        self.unpad_state = UnpadState::BlockBody {
                            cmd,
                            rem_content,
                            rem_padding,
                        };
                        self.finish_block_if_zero();
                    }
                }
                UnpadState::BlockBody {
                    rem_content,
                    rem_padding,
                    ..
                } => {
                    if *rem_content > 0 {
                        let take = (*rem_content).min(input.len());
                        let content_slice = &input[..take];
                        if self.traffic.packets_to_filter > 0 {
                            self.traffic.filter_tls_packet(content_slice);
                        }
                        self.ready_rx_buf.extend_from_slice(content_slice);
                        *rem_content -= take;
                        input = &input[take..];
                    } else if *rem_padding > 0 {
                        let take = (*rem_padding).min(input.len());
                        *rem_padding -= take;
                        input = &input[take..];
                    }
                    self.finish_block_if_zero();
                }
            }
        }
    }

    fn finish_block_if_zero(&mut self) {
        if let UnpadState::BlockBody {
            cmd,
            rem_content: 0,
            rem_padding: 0,
        } = self.unpad_state
        {
            match cmd {
                CMD_PADDING_CONTINUE => {
                    self.unpad_state = UnpadState::BlockHeader {
                        hdr: [0u8; 5],
                        filled: 0,
                    };
                }
                CMD_PADDING_END => {
                    self.unpad_state = UnpadState::FinishedEncrypted;
                }
                CMD_PADDING_DIRECT => {
                    self.unpad_state = UnpadState::FinishedDirect;
                    self.tls.enable_direct_read();
                }
                _ => {
                    self.unpad_state = UnpadState::FinishedEncrypted;
                }
            }
        }
    }

    fn encode_vision_write(&mut self, data: &[u8]) -> io::Result<()> {
        let mut wire = if !self.pending_wire_prefix.is_empty() {
            self.pending_wire_prefix.split()
        } else {
            BytesMut::with_capacity(data.len() + 256)
        };
        self.header_sent = true;

        let is_complete_app_data = is_complete_tls_app_data_record(data);
        let chunks = split_for_vision_padding(data);

        if self.traffic.packets_to_filter > 0 {
            for c in &chunks {
                self.traffic.filter_tls_packet(c);
            }
        }

        let mut switch_direct_after = false;
        let mut unpadded_tail_start: Option<usize> = None;

        for (idx, chunk) in chunks.iter().enumerate() {
            if !self.is_padding_write {
                unpadded_tail_start = Some(idx);
                break;
            }
            let is_last = idx + 1 == chunks.len();
            let long_padding = self.traffic.is_tls;

            if self.traffic.is_tls
                && chunk.len() >= 6
                && chunk.starts_with(&[0x17, 0x03, 0x03])
                && is_complete_app_data
            {
                if self.traffic.enable_xtls {
                    switch_direct_after = true;
                }
                let cmd = if is_last {
                    if self.traffic.enable_xtls {
                        CMD_PADDING_DIRECT
                    } else {
                        CMD_PADDING_END
                    }
                } else {
                    CMD_PADDING_CONTINUE
                };
                append_vision_padded_block(&mut wire, chunk, cmd, &mut self.write_once_uuid, true);
                self.is_padding_write = false;
                continue;
            } else if !self.traffic.is_tls12_or_above && self.traffic.packets_to_filter <= 1 {
                self.is_padding_write = false;
                append_vision_padded_block(
                    &mut wire,
                    chunk,
                    CMD_PADDING_END,
                    &mut self.write_once_uuid,
                    long_padding,
                );
                if !is_last {
                    unpadded_tail_start = Some(idx + 1);
                }
                break;
            }

            let cmd = if is_last && !self.is_padding_write {
                if self.traffic.enable_xtls {
                    CMD_PADDING_DIRECT
                } else {
                    CMD_PADDING_END
                }
            } else {
                CMD_PADDING_CONTINUE
            };
            append_vision_padded_block(
                &mut wire,
                chunk,
                cmd,
                &mut self.write_once_uuid,
                long_padding,
            );
        }

        if let Some(tail_idx) = unpadded_tail_start {
            for tail in &chunks[tail_idx..] {
                wire.put_slice(tail);
            }
        }

        self.tls.queue_encrypted_app_data(&wire)?;
        if switch_direct_after {
            self.tls.enable_direct_write();
        }
        Ok(())
    }

    fn queue_empty_camouflage_header_if_needed(&mut self) -> io::Result<()> {
        if self.header_sent {
            return Ok(());
        }
        self.header_sent = true;
        let mut wire = self.pending_wire_prefix.split();
        if self.is_padding_write {
            append_vision_padded_block(
                &mut wire,
                &[],
                CMD_PADDING_CONTINUE,
                &mut self.write_once_uuid,
                true,
            );
        }
        self.tls.queue_encrypted_app_data(&wire)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Server-speaks-first support: if client calls `poll_read` before writing any bytes,
        // flush the VLESS request header + empty Vision camouflage padding block first.
        if !self.header_sent && matches!(self.resp_hdr_state, RespHeaderState::NeedVerAndLen) {
            self.queue_empty_camouflage_header_if_needed()?;
        }
        if self.tls.has_queued_tx() {
            ready!(self.tls.poll_drain_tx(cx))?;
            let _ = Pin::new(&mut self.tls).poll_flush(cx)?;
        }

        loop {
            if !self.ready_rx_buf.is_empty() {
                let take = self.ready_rx_buf.len().min(buf.remaining());
                let chunk = self.ready_rx_buf.split_to(take);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            // Fast zero-copy path once response header is stripped and Vision unpadding is finished
            if matches!(self.resp_hdr_state, RespHeaderState::Done)
                && matches!(
                    self.unpad_state,
                    UnpadState::FinishedDirect | UnpadState::FinishedEncrypted
                )
                && self.traffic.packets_to_filter <= 0
            {
                return Pin::new(&mut self.tls).poll_read(cx, buf);
            }

            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut rb))?;
            let filled = rb.filled();
            if filled.is_empty() {
                if !matches!(self.resp_hdr_state, RespHeaderState::Done) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS Vision response header truncated before EOF",
                    )));
                }
                return Poll::Ready(Ok(()));
            }

            if !matches!(self.resp_hdr_state, RespHeaderState::Done) {
                self.resp_hdr_buf.extend_from_slice(filled);
                loop {
                    match self.resp_hdr_state {
                        RespHeaderState::NeedVerAndLen => {
                            if self.resp_hdr_buf.len() < 2 {
                                break;
                            }
                            let ver = self.resp_hdr_buf[0];
                            let alen = self.resp_hdr_buf[1] as usize;
                            self.resp_hdr_buf.advance(2);
                            if ver != 0x00 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid VLESS Vision response version 0x{ver:02x}"),
                                )));
                            }
                            self.resp_hdr_state = if alen == 0 {
                                RespHeaderState::Done
                            } else {
                                RespHeaderState::NeedAddons(alen)
                            };
                        }
                        RespHeaderState::NeedAddons(alen) => {
                            if self.resp_hdr_buf.len() < alen {
                                break;
                            }
                            self.resp_hdr_buf.advance(alen);
                            self.resp_hdr_state = RespHeaderState::Done;
                        }
                        RespHeaderState::Done => {
                            let leftover = self.resp_hdr_buf.split();
                            if !leftover.is_empty() {
                                self.feed_unpad_bytes(&leftover);
                            }
                            break;
                        }
                    }
                }
            } else {
                self.feed_unpad_bytes(filled);
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(accepted) = self.pending_write_accepted {
            ready!(self.tls.poll_drain_tx(cx))?;
            self.pending_write_accepted = None;
            return Poll::Ready(Ok(accepted));
        }

        if self.tls.has_queued_tx() {
            ready!(self.tls.poll_drain_tx(cx))?;
        }

        // Fast path once Vision padding has ended and VLESS prefix has been sent
        if !self.is_padding_write && self.header_sent && self.traffic.packets_to_filter <= 0 {
            return Pin::new(&mut self.tls).poll_write(cx, data);
        }

        let accept_len = data.len().min(16 * 1024);
        if self.is_padding_write || !self.header_sent {
            self.encode_vision_write(&data[..accept_len])?;
        } else {
            self.traffic.filter_tls_packet(&data[..accept_len]);
            self.tls.queue_encrypted_app_data(&data[..accept_len])?;
        }

        self.pending_write_accepted = Some(accept_len);
        match self.tls.poll_drain_tx(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write_accepted = None;
                Poll::Ready(Ok(accept_len))
            }
            Poll::Ready(Err(e)) => {
                self.pending_write_accepted = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.tls.poll_drain_tx(cx))?;
        Pin::new(&mut self.tls).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.tls.poll_drain_tx(cx))?;
        Pin::new(&mut self.tls).poll_shutdown(cx)
    }
}

/// Encode a single XUDP (`v1.mux.cool:666`) UDP frame.
pub fn encode_xudp_packet(
    session_id: u16,
    is_new: bool,
    target: &TargetAddr,
    global_id: Option<&[u8; 8]>,
    payload: &[u8],
) -> io::Result<BytesMut> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP payload exceeds 65535 bytes",
        ));
    }
    let mut meta = BytesMut::with_capacity(48);
    meta.put_u16(session_id);
    meta.put_u8(if is_new { 0x01 } else { 0x02 }); // 1 = New, 2 = Keep
    meta.put_u8(0x01); // OptionData
    meta.put_u8(0x02); // Network_UDP
    target.encode_vless(&mut meta)?;
    if is_new && let Some(gid) = global_id {
        meta.put_slice(gid);
    }

    let mut frame = BytesMut::with_capacity(4 + meta.len() + payload.len());
    frame.put_u16(meta.len() as u16);
    frame.put_slice(&meta);
    frame.put_u16(payload.len() as u16);
    frame.put_slice(payload);
    Ok(frame)
}

/// Read the next XUDP (`v1.mux.cool:666`) downlink datagram `(payload, source_addr)` from `reader`,
/// transparently skipping `KeepAlive` (`status == 4`) frames.
pub async fn read_xudp_packet<R>(
    reader: &mut R,
    fallback_addr: &TargetAddr,
) -> io::Result<(Vec<u8>, TargetAddr)>
where
    R: AsyncRead + Unpin,
{
    loop {
        let meta_len = reader.read_u16().await? as usize;
        if meta_len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("XUDP metadata length {meta_len} < 4"),
            ));
        }
        let mut meta = vec![0u8; meta_len];
        reader.read_exact(&mut meta).await?;
        let status = meta[2];
        let option = meta[3];

        let mut parsed_src = None;
        if status == 0x02 && meta_len > 5 && meta[4] == 0x02 {
            let mut cursor = io::Cursor::new(&meta[5..]);
            if let Ok(addr) = TargetAddr::read_vless(&mut cursor).await {
                parsed_src = Some(addr);
            }
        }

        let has_data = (option & 0x01) != 0;
        let payload = if has_data {
            let plen = reader.read_u16().await? as usize;
            let mut body = vec![0u8; plen];
            reader.read_exact(&mut body).await?;
            body
        } else {
            Vec::new()
        };

        match status {
            0x02 => {
                if has_data {
                    return Ok((payload, parsed_src.unwrap_or_else(|| fallback_addr.clone())));
                }
            }
            0x04 => {
                // KeepAlive: discard and keep reading
                continue;
            }
            0x03 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP session closed by remote server",
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected XUDP status 0x{other:02x}"),
                ));
            }
        }
    }
}

type UdpRecvItem = io::Result<(Vec<u8>, TargetAddr)>;

struct ActiveXudpMux {
    tx: mpsc::Sender<(Vec<u8>, TargetAddr)>,
    reader_abort: tokio::task::AbortHandle,
}

/// Persistent full-cone XUDP (`v1.mux.cool:666`) UDP session multiplexed over a VLESS Vision stream.
pub struct VlessVisionXudpSession<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<VisionStream<TcpStream>>> + Send + 'static,
{
    connect_mux: Arc<F>,
    flow: VlessVisionFlow,
    global_id: [u8; 8],
    active: AsyncMutex<Option<ActiveXudpMux>>,
    rx_tx: mpsc::Sender<UdpRecvItem>,
    rx: AsyncMutex<mpsc::Receiver<UdpRecvItem>>,
}

impl<F, Fut> VlessVisionXudpSession<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<VisionStream<TcpStream>>> + Send + 'static,
{
    pub fn new(flow: VlessVisionFlow, connect_mux: F) -> Self {
        let mut gid = [0u8; 8];
        rand::rng().fill(&mut gid);
        let (rx_tx, rx) = mpsc::channel(128);
        Self {
            connect_mux: Arc::new(connect_mux),
            flow,
            global_id: gid,
            active: AsyncMutex::new(None),
            rx_tx,
            rx: AsyncMutex::new(rx),
        }
    }
}

#[async_trait]
impl<F, Fut> OutboundUdpSession for VlessVisionXudpSession<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<VisionStream<TcpStream>>> + Send + 'static,
{
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        if !self.flow.allows_udp_port(target.port) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XTLS Vision rejected UDP/443 traffic (use xtls-rprx-vision-udp443 to enable)",
            ));
        }
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS XUDP datagram exceeds 65535 bytes",
            ));
        }

        {
            let guard = self.active.lock().await;
            if let Some(mux) = guard.as_ref()
                && !mux.tx.is_closed()
                && mux
                    .tx
                    .send((payload.to_vec(), target.clone()))
                    .await
                    .is_ok()
            {
                return Ok(());
            }
        }

        let stream = (self.connect_mux)().await?;
        let mut guard = self.active.lock().await;
        if let Some(old) = guard.take() {
            old.reader_abort.abort();
        }

        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut pkt_rx) = mpsc::channel::<(Vec<u8>, TargetAddr)>(64);
        tx.send((payload.to_vec(), target.clone()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XUDP queue closed"))?;

        let gid = self.global_id;
        let fallback_target = target.clone();
        let writer_task = tokio::spawn(async move {
            let mut is_first = true;
            while let Some((dgram, dst)) = pkt_rx.recv().await {
                let Ok(frame) = encode_xudp_packet(
                    0,
                    is_first,
                    &dst,
                    if is_first { Some(&gid) } else { None },
                    &dgram,
                ) else {
                    break;
                };
                is_first = false;
                if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        let writer_abort = writer_task.abort_handle();

        let rx_tx = self.rx_tx.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    biased;
                    _ = rx_tx.closed() => break,
                    res = tokio::time::timeout(
                        Duration::from_secs(120),
                        read_xudp_packet(&mut rd, &fallback_target),
                    ) => res,
                };
                match next {
                    Ok(Ok(item)) => {
                        if rx_tx.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            writer_abort.abort();
        });

        *guard = Some(ActiveXudpMux {
            tx,
            reader_abort: reader_task.abort_handle(),
        });
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VLESS XUDP session closed",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::vless::reality::{
        RealityClientConfig, Tls13HandshakeMode, accept_reality_tls13_server,
        connect_tls13_vision_stream, decode_reality_short_id,
    };
    use rand::RngCore;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

    #[tokio::test]
    async fn vision_over_reality_switches_to_direct_splice_for_inner_tls13() {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();
        let uuid = Uuid::from_u128(0xdeadbeef_cafe_4bad_8bad_f00d12345678);

        let (c_tcp, s_tcp) = tokio::io::duplex(128 * 1024);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let mut req_hdr = BytesMut::new();
        req_hdr.put_u8(0x00);
        req_hdr.put_slice(uuid.as_bytes());
        req_hdr.put_u8(VISION_ADDONS_PROTOBUF.len() as u8);
        req_hdr.put_slice(VISION_ADDONS_PROTOBUF);
        req_hdr.put_u8(0x01);
        TargetAddr::new_domain("inner.example.com", 443)
            .unwrap()
            .encode_vless(&mut req_hdr)
            .unwrap();
        let expected_hdr_len = req_hdr.len();

        let srv_task = tokio::spawn(async move {
            let mut srv_tls =
                accept_reality_tls13_server(s_tcp, &srv_sk_bytes, &sid, "www.apple.com")
                    .await
                    .unwrap();
            let mut hdr = vec![0u8; expected_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let mut srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);

            // 1. Read simulated inner TLS 1.3 ClientHello
            let mut ch = vec![0u8; 64];
            srv_vision.read_exact(&mut ch).await.unwrap();
            assert_eq!(&ch[0..3], &[0x16, 0x03, 0x01]);

            // 2. Send simulated inner TLS 1.3 ServerHello (with cipher 0x1301 + supported_versions 0304)
            let mut sh = vec![0u8; 96];
            sh[0..3].copy_from_slice(&[0x16, 0x03, 0x03]);
            let sh_rec_len = (96 - 5) as u16;
            sh[3..5].copy_from_slice(&sh_rec_len.to_be_bytes());
            sh[5] = 0x02; // ServerHello
            sh[43] = 32; // 32-byte session_id -> cipher at 43 + 32 + 1 = 76..78
            sh[76..78].copy_from_slice(&0x1301u16.to_be_bytes());
            sh[82..88].copy_from_slice(TLS13_SUPPORTED_VERSIONS_EXT);
            srv_vision.write_all(&sh).await.unwrap();
            srv_vision.flush().await.unwrap();

            // 3. Send simulated inner TLS 1.3 ApplicationData -> triggers CommandPaddingDirect!
            let mut srv_app = vec![0x17, 0x03, 0x03, 0x00, 0x0a];
            srv_app.extend_from_slice(b"srv-secret");
            srv_vision.write_all(&srv_app).await.unwrap();
            srv_vision.flush().await.unwrap();

            // 4. Read client's inner TLS 1.3 ApplicationData + post-direct raw payload!
            let mut cli_data = vec![0u8; 15 + 24];
            srv_vision.read_exact(&mut cli_data).await.unwrap();
            assert_eq!(&cli_data[5..15], b"cli-secret");
            assert_eq!(&cli_data[15..], b"raw-direct-splice-stream");

            // 5. Send raw post-direct server payload!
            srv_vision
                .write_all(b"server-direct-splice-ack")
                .await
                .unwrap();
            srv_vision.flush().await.unwrap();
        });

        let cli_tls = connect_tls13_vision_stream(c_tcp, &mode).await.unwrap();
        let mut cli_vision = VisionStream::new_client(cli_tls, uuid, req_hdr);

        // 1. Write inner TLS ClientHello
        let mut ch = vec![0u8; 64];
        ch[0..3].copy_from_slice(&[0x16, 0x03, 0x01]);
        ch[3..5].copy_from_slice(&59u16.to_be_bytes());
        ch[5] = 0x01;
        cli_vision.write_all(&ch).await.unwrap();
        cli_vision.flush().await.unwrap();

        // 2. Read inner ServerHello + first ApplicationData
        let mut sh_and_app = vec![0u8; 96 + 15];
        cli_vision.read_exact(&mut sh_and_app).await.unwrap();
        assert_eq!(&sh_and_app[96 + 5..], b"srv-secret");

        // 3. Write inner TLS ApplicationData (triggers CommandPaddingDirect on client!) + raw stream
        let mut cli_app = vec![0x17, 0x03, 0x03, 0x00, 0x0a];
        cli_app.extend_from_slice(b"cli-secret");
        cli_vision.write_all(&cli_app).await.unwrap();
        cli_vision
            .write_all(b"raw-direct-splice-stream")
            .await
            .unwrap();
        cli_vision.flush().await.unwrap();

        let mut ack = [0u8; 24];
        cli_vision.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"server-direct-splice-ack");

        srv_task.await.unwrap();
    }
}
