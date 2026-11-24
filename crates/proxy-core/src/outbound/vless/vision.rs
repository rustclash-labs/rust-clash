use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
    header_flush_pending: bool,
    write_once_uuid: Option<[u8; 16]>,
    is_padding_write: bool,
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
            header_flush_pending: false,
            write_once_uuid: Some(uuid_bytes),
            is_padding_write: true,
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
            header_flush_pending: false,
            write_once_uuid: Some(uuid_bytes),
            is_padding_write: true,
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

        // Evaluate once across the entire write: multi-chunk (>7600B) complete TLS ApplicationData
        // records MUST wrap every chunk as Vision blocks (`CMD_PADDING_CONTINUE` for all non-final
        // chunks, `CMD_PADDING_DIRECT` / `CMD_PADDING_END` ONLY on the final chunk) before turning
        // off `is_padding_write`.
        let complete_tls_app_data_write = self.is_padding_write
            && self.traffic.is_tls
            && data.len() >= 6
            && data.starts_with(&[0x17, 0x03, 0x03])
            && is_complete_app_data;

        if complete_tls_app_data_write {
            for (idx, chunk) in chunks.iter().enumerate() {
                let is_last = idx + 1 == chunks.len();
                let cmd = if is_last {
                    if self.traffic.enable_xtls {
                        switch_direct_after = true;
                        CMD_PADDING_DIRECT
                    } else {
                        CMD_PADDING_END
                    }
                } else {
                    CMD_PADDING_CONTINUE
                };
                append_vision_padded_block(&mut wire, chunk, cmd, &mut self.write_once_uuid, true);
            }
            self.is_padding_write = false;
        } else {
            for (idx, chunk) in chunks.iter().enumerate() {
                if !self.is_padding_write {
                    unpadded_tail_start = Some(idx);
                    break;
                }
                let is_last = idx + 1 == chunks.len();
                let long_padding = self.traffic.is_tls;

                if !self.traffic.is_tls12_or_above && self.traffic.packets_to_filter <= 1 {
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

                append_vision_padded_block(
                    &mut wire,
                    chunk,
                    CMD_PADDING_CONTINUE,
                    &mut self.write_once_uuid,
                    long_padding,
                );
            }
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
        self.tls.queue_encrypted_app_data(&wire)?;
        self.header_flush_pending = true;
        Ok(())
    }

    fn sync_header_flush_pending(&mut self) {
        if self.header_flush_pending
            && ((!self.tls.has_queued_tx() && !self.tls.inner_needs_flush())
                || self.tls.is_uplink_drain_failed())
        {
            self.header_flush_pending = false;
        }
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

        // Always drain already-unpadded bytes FIRST, before queueing or driving any uplink flush,
        // so an uplink write error can never discard bytes already buffered in `ready_rx_buf`.
        if !self.ready_rx_buf.is_empty() {
            let take = self.ready_rx_buf.len().min(buf.remaining());
            let chunk = self.ready_rx_buf.split_to(take);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        // Server-speaks-first support: if client calls `poll_read` before writing any bytes,
        // queue the VLESS request header + empty Vision camouflage padding block into `self.tls`.
        // `Tls13VisionStream::poll_read` drives the non-blocking, FanoutWaker-safe drain+flush
        // without blocking downlink reads or discarding buffered server responses on uplink errors.
        if !self.header_sent && matches!(self.resp_hdr_state, RespHeaderState::NeedVerAndLen) {
            self.queue_empty_camouflage_header_if_needed()?;
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
                let res = Pin::new(&mut self.tls).poll_read(cx, buf);
                self.sync_header_flush_pending();
                return res;
            }

            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            let poll_res = Pin::new(&mut self.tls).poll_read(cx, &mut rb);
            self.sync_header_flush_pending();
            ready!(poll_res)?;
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

        // Drain any previously buffered outer TLS records BEFORE accepting new bytes from `data`,
        // maintaining strict 1-record bounded backpressure while remaining 100% cancel-safe.
        if self.tls.has_queued_tx() {
            ready!(self.tls.poll_drain_tx(cx))?;
        }
        // Any previously queued server-speaks-first camouflage header has now left `enc_tx_buf`
        // (and `self.tls` still tracks `inner_needs_flush` if the underlying transport is buffered).
        self.header_flush_pending = false;

        // Fast path once Vision padding has ended and VLESS prefix has been sent
        if !self.is_padding_write
            && self.header_sent
            && (self.traffic.packets_to_filter <= 0 || self.tls.is_direct_write())
        {
            return Pin::new(&mut self.tls).poll_write(cx, data);
        }

        let accept_len = data.len().min(16 * 1024);
        if self.is_padding_write || !self.header_sent {
            self.encode_vision_write(&data[..accept_len])?;
        } else {
            self.traffic.filter_tls_packet(&data[..accept_len]);
            self.tls.queue_encrypted_app_data(&data[..accept_len])?;
        }

        // Opportunistic drain: immediately acknowledge `accept_len` once sealed into `tls`
        // so cancelling a subsequent `Pending` write can never return `Ok(n > data.len())`.
        match self.tls.poll_drain_tx(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(accept_len)),
            Poll::Pending => {
                // Returning `Ready(Ok(accept_len))` immediately — writer is not parked, so clear
                // its waker slot while leaving any concurrent reader waker in `tls` intact.
                self.tls.clear_write_waker();
                Poll::Ready(Ok(accept_len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
        self.header_flush_pending = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.tls).poll_shutdown(cx))?;
        self.header_flush_pending = false;
        Poll::Ready(Ok(()))
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

const XUDP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

struct ActiveXudpMux {
    tx: mpsc::Sender<(Vec<u8>, TargetAddr)>,
    reader_abort: tokio::task::AbortHandle,
    writer_abort: tokio::task::AbortHandle,
    dead: Arc<AtomicBool>,
    replaced: Arc<AtomicBool>,
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
    idle_timeout: Duration,
    active: AsyncMutex<Option<ActiveXudpMux>>,
    rx_tx: mpsc::Sender<UdpRecvItem>,
    rx: AsyncMutex<mpsc::Receiver<UdpRecvItem>>,
}

impl<F, Fut> Drop for VlessVisionXudpSession<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<VisionStream<TcpStream>>> + Send + 'static,
{
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active.try_lock()
            && let Some(mux) = guard.take()
        {
            mux.replaced.store(true, Ordering::Release);
            mux.dead.store(true, Ordering::Release);
            mux.reader_abort.abort();
            mux.writer_abort.abort();
        }
    }
}

impl<F, Fut> VlessVisionXudpSession<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<VisionStream<TcpStream>>> + Send + 'static,
{
    pub fn new(flow: VlessVisionFlow, connect_mux: F) -> Self {
        Self::new_with_idle_timeout(flow, XUDP_STREAM_IDLE_TIMEOUT, connect_mux)
    }

    fn new_with_idle_timeout(
        flow: VlessVisionFlow,
        idle_timeout: Duration,
        connect_mux: F,
    ) -> Self {
        let mut gid = [0u8; 8];
        rand::rng().fill(&mut gid);
        let (rx_tx, rx) = mpsc::channel(128);
        Self {
            connect_mux: Arc::new(connect_mux),
            flow,
            global_id: gid,
            idle_timeout,
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
                && !mux.dead.load(Ordering::Acquire)
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
            old.replaced.store(true, Ordering::Release);
            old.dead.store(true, Ordering::Release);
            old.reader_abort.abort();
            old.writer_abort.abort();
        }

        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut pkt_rx) = mpsc::channel::<(Vec<u8>, TargetAddr)>(64);
        tx.send((payload.to_vec(), target.clone()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XUDP queue closed"))?;

        let dead = Arc::new(AtomicBool::new(false));
        let replaced = Arc::new(AtomicBool::new(false));
        let dead_wr = Arc::clone(&dead);
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
            dead_wr.store(true, Ordering::Release);
            let _ = wr.shutdown().await;
        });
        let writer_abort = writer_task.abort_handle();
        let writer_abort_for_reader = writer_abort.clone();

        let rx_tx = self.rx_tx.clone();
        let idle_timeout = self.idle_timeout;
        let dead_rd = Arc::clone(&dead);
        let replaced_rd = Arc::clone(&replaced);
        let reader_task = tokio::spawn(async move {
            let err_to_send = loop {
                let next = tokio::select! {
                    biased;
                    _ = rx_tx.closed() => break None,
                    res = tokio::time::timeout(
                        idle_timeout,
                        read_xudp_packet(&mut rd, &fallback_target),
                    ) => res,
                };
                match next {
                    Ok(Ok(item)) => {
                        if rx_tx.send(Ok(item)).await.is_err() {
                            break None;
                        }
                    }
                    Ok(Err(e)) => break Some(e),
                    Err(_elapsed) => {
                        break Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "VLESS XUDP stream idle timeout",
                        ));
                    }
                }
            };
            dead_rd.store(true, Ordering::Release);
            writer_abort_for_reader.abort();
            if let Some(err) = err_to_send
                && !replaced_rd.load(Ordering::Acquire)
            {
                tokio::select! {
                    biased;
                    _ = rx_tx.closed() => {}
                    _ = rx_tx.send(Err(err)) => {}
                }
            }
        });

        *guard = Some(ActiveXudpMux {
            tx,
            reader_abort: reader_task.abort_handle(),
            writer_abort,
            dead,
            replaced,
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

    fn build_vless_vision_req_hdr(uuid: Uuid, cmd: u8, target: &TargetAddr) -> BytesMut {
        let mut req_hdr = BytesMut::new();
        req_hdr.put_u8(0x00);
        req_hdr.put_slice(uuid.as_bytes());
        req_hdr.put_u8(VISION_ADDONS_PROTOBUF.len() as u8);
        req_hdr.put_slice(VISION_ADDONS_PROTOBUF);
        req_hdr.put_u8(cmd);
        target.encode_vless(&mut req_hdr).unwrap();
        req_hdr
    }

    async fn establish_vision_duplex_pair(
        duplex_buf: usize,
        uuid: Uuid,
    ) -> (
        VisionStream<tokio::io::DuplexStream>,
        Tls13VisionStream<tokio::io::DuplexStream>,
        usize,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();

        let (c_tcp, s_tcp) = tokio::io::duplex(duplex_buf);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let target = TargetAddr::new_domain("inner.example.com", 443).unwrap();
        let req_hdr = build_vless_vision_req_hdr(uuid, 0x01, &target);
        let req_hdr_len = req_hdr.len();

        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_tcp, &srv_sk_bytes, &sid, "www.apple.com")
                .await
                .unwrap()
        });
        let cli_tls = connect_tls13_vision_stream(c_tcp, &mode).await.unwrap();
        let srv_tls = srv_task.await.unwrap();
        (
            VisionStream::new_client(cli_tls, uuid, req_hdr),
            srv_tls,
            req_hdr_len,
        )
    }

    async fn read_vision_block<R: AsyncRead + Unpin>(
        reader: &mut R,
        expect_uuid: Option<[u8; 16]>,
    ) -> (u8, Vec<u8>) {
        if let Some(expected) = expect_uuid {
            let mut got_uuid = [0u8; 16];
            reader.read_exact(&mut got_uuid).await.unwrap();
            assert_eq!(got_uuid, expected, "Vision block UUID mismatch");
        }
        let mut hdr = [0u8; 5];
        reader.read_exact(&mut hdr).await.unwrap();
        let cmd = hdr[0];
        let content_len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        let pad_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut content = vec![0u8; content_len];
        reader.read_exact(&mut content).await.unwrap();
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            reader.read_exact(&mut pad).await.unwrap();
        }
        (cmd, content)
    }

    #[tokio::test]
    async fn vision_large_complete_tls13_appdata_pads_all_chunks_before_direct_splice() {
        let uuid = Uuid::from_u128(0x11223344_5566_4778_899a_aabbccddeeff);
        let (mut cli_vision, mut srv_tls, req_hdr_len) =
            establish_vision_duplex_pair(128 * 1024, uuid).await;

        // Build a 10,000-byte complete TLS 1.3 ApplicationData record (> MAX_VISION_PLAIN_CHUNK=7600)
        // so `split_for_vision_padding` splits it into >= 2 chunks.
        let mut large_app_record = Vec::with_capacity(10_000);
        large_app_record.extend_from_slice(&[0x17, 0x03, 0x03]);
        large_app_record.extend_from_slice(&(9995u16).to_be_bytes());
        for i in 0..9995usize {
            // Avoid accidental 0x17 0x03 0x03 inner sequence so split produces 2 chunks reliably.
            large_app_record.push(0x40 + (i % 61) as u8);
        }
        assert_eq!(large_app_record.len(), 10_000);
        assert!(is_complete_tls_app_data_record(&large_app_record));
        let expected_large_record = large_app_record.clone();

        let srv_task = tokio::spawn(async move {
            // 1. Read VLESS request header + ClientHello Vision block
            let mut hdr = vec![0u8; req_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let (ch_cmd, ch_content) =
                read_vision_block(&mut srv_tls, Some(*uuid.as_bytes())).await;
            assert_eq!(ch_cmd, CMD_PADDING_CONTINUE);
            assert_eq!(&ch_content[0..3], &[0x16, 0x03, 0x01]);

            // 2. Send VLESS response header + TLS 1.3 ServerHello (cipher 0x1301 + supported_versions 0x0304)
            let mut sh = vec![0u8; 96];
            sh[0..3].copy_from_slice(&[0x16, 0x03, 0x03]);
            sh[3..5].copy_from_slice(&((96 - 5) as u16).to_be_bytes());
            sh[5] = 0x02;
            sh[43] = 32;
            sh[76..78].copy_from_slice(&0x1301u16.to_be_bytes());
            sh[82..88].copy_from_slice(TLS13_SUPPORTED_VERSIONS_EXT);

            let mut resp = BytesMut::from(&[0x00u8, 0x00u8][..]);
            let mut srv_uuid = Some(*uuid.as_bytes());
            append_vision_padded_block(&mut resp, &sh, CMD_PADDING_CONTINUE, &mut srv_uuid, false);
            srv_tls.write_all(&resp).await.unwrap();
            srv_tls.flush().await.unwrap();

            // 3. Decode ALL Vision wire blocks for the 10,000-byte complete TLS 1.3 AppData record
            let mut cmds = Vec::new();
            let mut reconstructed = Vec::new();
            loop {
                let (cmd, content) = read_vision_block(&mut srv_tls, None).await;
                cmds.push(cmd);
                reconstructed.extend_from_slice(&content);
                if cmd != CMD_PADDING_CONTINUE {
                    break;
                }
            }
            assert!(
                cmds.len() >= 2,
                "10,000-byte TLS AppData record must span >= 2 Vision blocks, got {:?}",
                cmds
            );
            assert_eq!(cmds[0], CMD_PADDING_CONTINUE);
            for &mid_cmd in &cmds[..cmds.len() - 1] {
                assert_eq!(mid_cmd, CMD_PADDING_CONTINUE);
            }
            assert_eq!(*cmds.last().unwrap(), CMD_PADDING_DIRECT);
            assert_eq!(reconstructed, expected_large_record);

            // 4. Switch server downlink to raw direct splice and read client's subsequent write
            srv_tls.enable_direct_read();
            let mut direct_tail = [0u8; 29];
            srv_tls.read_exact(&mut direct_tail).await.unwrap();
            assert_eq!(&direct_tail, b"post-large-record-direct-tail");
        });

        // 1. Client writes inner TLS ClientHello
        let mut ch = vec![0u8; 64];
        ch[0..3].copy_from_slice(&[0x16, 0x03, 0x01]);
        ch[3..5].copy_from_slice(&59u16.to_be_bytes());
        ch[5] = 0x01;
        cli_vision.write_all(&ch).await.unwrap();
        cli_vision.flush().await.unwrap();

        // 2. Client reads ServerHello (enabling `enable_xtls = true`)
        let mut sh_buf = vec![0u8; 96];
        cli_vision.read_exact(&mut sh_buf).await.unwrap();
        assert!(cli_vision.traffic.enable_xtls);

        // 3. Client writes 10,000-byte complete TLS 1.3 AppData record + subsequent raw direct write
        cli_vision.write_all(&large_app_record).await.unwrap();
        cli_vision
            .write_all(b"post-large-record-direct-tail")
            .await
            .unwrap();
        cli_vision.flush().await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), srv_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn vision_split_stream_concurrent_upload_backpressure_never_deadlocks() {
        let uuid = Uuid::from_u128(0x22334455_6677_4889_9aab_bbccddeeff00);
        let (cli_vision, mut srv_tls, req_hdr_len) = establish_vision_duplex_pair(256, uuid).await;

        let upload_payload: Vec<u8> = (0..(192 * 1024))
            .map(|i| ((i * 29 + 3) & 0xff) as u8)
            .collect();
        let download_payload: Vec<u8> = (0..(48 * 1024))
            .map(|i| ((i * 41 + 13) & 0xff) as u8)
            .collect();
        let expected_upload = upload_payload.clone();
        let expected_download = download_payload.clone();
        let upload_len = upload_payload.len();
        let download_len = download_payload.len();

        // Server accepts VLESS header, wraps in `VisionStream::new_server`, splits, and drives
        // concurrent backpressured reads + writes over the 256-byte duplex pipe.
        let srv_task = tokio::spawn(async move {
            let mut hdr = vec![0u8; req_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);
            let (mut srv_rd, mut srv_wr) = tokio::io::split(srv_vision);

            let rd_fut = tokio::spawn(async move {
                let mut got = Vec::with_capacity(upload_len);
                let mut tmp = [0u8; 192];
                while got.len() < upload_len {
                    let n = srv_rd.read(&mut tmp).await.unwrap();
                    assert!(n > 0, "unexpected EOF reading Vision upload");
                    got.extend_from_slice(&tmp[..n]);
                    if got.len() % 4096 < 192 {
                        tokio::task::yield_now().await;
                    }
                }
                got
            });
            let wr_fut = tokio::spawn(async move {
                for chunk in download_payload.chunks(512) {
                    srv_wr.write_all(chunk).await.unwrap();
                    tokio::task::yield_now().await;
                }
                srv_wr.flush().await.unwrap();
            });
            let (r, w) = tokio::join!(rd_fut, wr_fut);
            w.unwrap();
            r.unwrap()
        });

        let (mut cli_rd, mut cli_wr) = tokio::io::split(cli_vision);
        let cli_wr_task = tokio::spawn(async move {
            cli_wr.write_all(&upload_payload).await.unwrap();
            cli_wr.flush().await.unwrap();
        });
        let cli_rd_task = tokio::spawn(async move {
            let mut got = vec![0u8; download_len];
            cli_rd.read_exact(&mut got).await.unwrap();
            got
        });

        let (srv_got, (), cli_got) = tokio::time::timeout(Duration::from_secs(2), async {
            let (s, w, r) = tokio::join!(srv_task, cli_wr_task, cli_rd_task);
            (s.unwrap(), w.unwrap(), r.unwrap())
        })
        .await
        .expect("split VisionStream deadlocked under duplex(256) backpressure");

        assert_eq!(srv_got, expected_upload);
        assert_eq!(cli_got, expected_download);
    }

    #[tokio::test]
    async fn vision_cancelled_pending_write_with_smaller_retry_never_panics() {
        let uuid = Uuid::from_u128(0x33445566_7788_499a_abbc_ccddeeff0011);
        let (mut cli_vision, mut srv_tls, req_hdr_len) =
            establish_vision_duplex_pair(256, uuid).await;

        let large_buf = vec![0x6Bu8; 4096];
        let mut acknowledged = Vec::new();
        let mut hit_pending = false;

        for _ in 0..8 {
            let mut polled_once = false;
            let outcome = std::future::poll_fn(|cx| {
                if polled_once {
                    return Poll::Ready(None);
                }
                polled_once = true;
                match Pin::new(&mut cli_vision).poll_write(cx, &large_buf) {
                    Poll::Ready(res) => Poll::Ready(Some(res)),
                    Poll::Pending => Poll::Ready(None),
                }
            })
            .await;

            match outcome {
                Some(Ok(n)) => {
                    assert!(n <= large_buf.len());
                    acknowledged.extend_from_slice(&large_buf[..n]);
                }
                Some(Err(e)) => panic!("unexpected Vision write error before Pending: {e}"),
                None => {
                    hit_pending = true;
                    break;
                }
            }
        }
        assert!(
            hit_pending,
            "expected VisionStream::poll_write(4096) to return Poll::Pending against full duplex(256)"
        );

        let srv_task = tokio::spawn(async move {
            let mut hdr = vec![0u8; req_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let mut srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);
            let mut all = Vec::new();
            srv_vision.read_to_end(&mut all).await.unwrap();
            all
        });

        let tail = [1u8, 2, 3, 4];
        tokio::time::timeout(Duration::from_secs(2), async {
            cli_vision.write_all(&tail).await.unwrap();
            cli_vision.flush().await.unwrap();
            cli_vision.shutdown().await.unwrap();
        })
        .await
        .expect("smaller retry write_all hung on VisionStream after cancelled Pending write");

        let received = tokio::time::timeout(Duration::from_secs(2), srv_task)
            .await
            .unwrap()
            .unwrap();
        let mut expected = acknowledged;
        expected.extend_from_slice(&tail);
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn xudp_session_peer_close_propagates_error_to_recv_from_and_reconnects() {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();
        let uuid = Uuid::from_u128(0x44556677_8899_4aab_bccd_ddeeff001122);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mux_target = TargetAddr::new_domain("v1.mux.cool", 666).unwrap();
        let req_hdr_len = build_vless_vision_req_hdr(uuid, 0x03, &mux_target).len();
        let udp_dst = TargetAddr::new_domain("dns.example.test", 53).unwrap();
        let udp_dst_srv = udp_dst.clone();

        let srv_task = tokio::spawn(async move {
            // Connection 1: accept REALITY + Vision, read first XUDP packet, then close immediately.
            let (tcp1, _) = listener.accept().await.unwrap();
            let mut tls1 = accept_reality_tls13_server(tcp1, &srv_sk_bytes, &sid, "www.apple.com")
                .await
                .unwrap();
            let mut hdr1 = vec![0u8; req_hdr_len];
            tls1.read_exact(&mut hdr1).await.unwrap();
            let mut vision1 = VisionStream::new_server(tls1, uuid, &[]);
            let meta_len1 = vision1.read_u16().await.unwrap() as usize;
            let mut meta1 = vec![0u8; meta_len1];
            vision1.read_exact(&mut meta1).await.unwrap();
            let plen1 = vision1.read_u16().await.unwrap() as usize;
            let mut body1 = vec![0u8; plen1];
            vision1.read_exact(&mut body1).await.unwrap();
            assert_eq!(&body1, b"first-xudp");
            drop(vision1);

            // Connection 2: accept reconnect, read second XUDP packet, send downlink reply.
            let (tcp2, _) = listener.accept().await.unwrap();
            let mut tls2 = accept_reality_tls13_server(tcp2, &srv_sk_bytes, &sid, "www.apple.com")
                .await
                .unwrap();
            let mut hdr2 = vec![0u8; req_hdr_len];
            tls2.read_exact(&mut hdr2).await.unwrap();
            let mut vision2 = VisionStream::new_server(tls2, uuid, &[]);
            let meta_len2 = vision2.read_u16().await.unwrap() as usize;
            let mut meta2 = vec![0u8; meta_len2];
            vision2.read_exact(&mut meta2).await.unwrap();
            let plen2 = vision2.read_u16().await.unwrap() as usize;
            let mut body2 = vec![0u8; plen2];
            vision2.read_exact(&mut body2).await.unwrap();
            assert_eq!(&body2, b"second-xudp");

            let resp = encode_xudp_packet(0, false, &udp_dst_srv, None, b"xudp-pong").unwrap();
            vision2.write_all(&resp).await.unwrap();
            vision2.flush().await.unwrap();
        });

        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let session = VlessVisionXudpSession::new(VlessVisionFlow::XtlsRprxVision, move || {
            let mode = mode.clone();
            let mux_target = mux_target.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                let tls = connect_tls13_vision_stream(tcp, &mode).await?;
                let hdr = build_vless_vision_req_hdr(uuid, 0x03, &mux_target);
                Ok(VisionStream::new_client(tls, uuid, hdr))
            }
        });

        session.send_to(b"first-xudp", &udp_dst).await.unwrap();

        // Peer closes right after reading first packet -> `recv_from` MUST return Err promptly!
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv_from())
            .await
            .expect("VlessVisionXudpSession::recv_from hung after peer closed stream")
            .expect_err("expected recv_from error after peer closed XUDP stream");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ),
            "unexpected error kind on peer close: {err:?}"
        );

        // Next `send_to` must detect the dead mux, reconnect cleanly, and receive the reply.
        session.send_to(b"second-xudp", &udp_dst).await.unwrap();
        let (reply, src) = tokio::time::timeout(Duration::from_secs(2), session.recv_from())
            .await
            .expect("recv_from hung after XUDP reconnect")
            .unwrap();
        assert_eq!(reply, b"xudp-pong");
        assert_eq!(src, udp_dst);

        tokio::time::timeout(Duration::from_secs(2), srv_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn xudp_session_idle_timeout_propagates_timed_out_to_recv_from() {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();
        let uuid = Uuid::from_u128(0x55667788_99aa_4bbc_cdde_eeff00112233);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mux_target = TargetAddr::new_domain("v1.mux.cool", 666).unwrap();
        let req_hdr_len = build_vless_vision_req_hdr(uuid, 0x03, &mux_target).len();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept_reality_tls13_server(tcp, &srv_sk_bytes, &sid, "www.apple.com")
                .await
                .unwrap();
            let mut hdr = vec![0u8; req_hdr_len];
            tls.read_exact(&mut hdr).await.unwrap();
            let mut vision = VisionStream::new_server(tls, uuid, &[]);
            let meta_len = vision.read_u16().await.unwrap() as usize;
            let mut meta = vec![0u8; meta_len];
            vision.read_exact(&mut meta).await.unwrap();
            let plen = vision.read_u16().await.unwrap() as usize;
            let mut body = vec![0u8; plen];
            vision.read_exact(&mut body).await.unwrap();
            // Keep socket open without replying until test signals completion.
            let _ = hold_rx.await;
            drop(vision);
        });

        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let session = VlessVisionXudpSession::new_with_idle_timeout(
            VlessVisionFlow::XtlsRprxVision,
            Duration::from_millis(80),
            move || {
                let mode = mode.clone();
                let mux_target = mux_target.clone();
                async move {
                    let tcp = TcpStream::connect(addr).await?;
                    let tls = connect_tls13_vision_stream(tcp, &mode).await?;
                    let hdr = build_vless_vision_req_hdr(uuid, 0x03, &mux_target);
                    Ok(VisionStream::new_client(tls, uuid, hdr))
                }
            },
        );

        let udp_dst = TargetAddr::new_domain("silent.example.test", 53).unwrap();
        session.send_to(b"hello-silent", &udp_dst).await.unwrap();

        let err = tokio::time::timeout(Duration::from_secs(1), session.recv_from())
            .await
            .expect("VlessVisionXudpSession::recv_from hung on idle timeout")
            .expect_err("expected TimedOut error from recv_from");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let _ = hold_tx.send(());
        let _ = srv_task.await;
    }

    struct VisionAsymmetricDuplex {
        rd: Arc<parking_lot::Mutex<Option<tokio::io::DuplexStream>>>,
        wr: tokio::io::DuplexStream,
    }

    struct VisionHalfDropHandle(Arc<parking_lot::Mutex<Option<tokio::io::DuplexStream>>>);

    impl VisionHalfDropHandle {
        fn drop_reader(&self) {
            let _ = self.0.lock().take();
        }
    }

    impl AsyncRead for VisionAsymmetricDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut guard = self.rd.lock();
            match guard.as_mut() {
                Some(stream) => Pin::new(stream).poll_read(cx, buf),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for VisionAsymmetricDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.wr).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_shutdown(cx)
        }
    }

    async fn establish_vision_asymmetric_pair(
        c2s_buf: usize,
        s2c_buf: usize,
        uuid: Uuid,
    ) -> (
        VisionStream<VisionAsymmetricDuplex>,
        Tls13VisionStream<VisionAsymmetricDuplex>,
        usize,
        VisionHalfDropHandle,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();

        let (c2s_client, c2s_server) = tokio::io::duplex(c2s_buf);
        let (s2c_server, s2c_client) = tokio::io::duplex(s2c_buf);
        let srv_rd = Arc::new(parking_lot::Mutex::new(Some(c2s_server)));
        let drop_srv_rd = VisionHalfDropHandle(Arc::clone(&srv_rd));
        let c_tcp = VisionAsymmetricDuplex {
            rd: Arc::new(parking_lot::Mutex::new(Some(s2c_client))),
            wr: c2s_client,
        };
        let s_tcp = VisionAsymmetricDuplex {
            rd: srv_rd,
            wr: s2c_server,
        };

        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let target = TargetAddr::new_domain("inner.example.com", 443).unwrap();
        let req_hdr = build_vless_vision_req_hdr(uuid, 0x01, &target);
        let req_hdr_len = req_hdr.len();

        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_tcp, &srv_sk_bytes, &sid, "www.apple.com")
                .await
                .unwrap()
        });
        let cli_tls = connect_tls13_vision_stream(c_tcp, &mode).await.unwrap();
        let srv_tls = srv_task.await.unwrap();
        (
            VisionStream::new_client(cli_tls, uuid, req_hdr),
            srv_tls,
            req_hdr_len,
            drop_srv_rd,
        )
    }

    #[tokio::test]
    async fn vision_server_speaks_first_then_write_broken_uplink_drains_multi_frame_response() {
        let uuid = Uuid::from_u128(0x66778899_aabb_4ccd_deef_ff0011223344);
        let (mut cli_vision, mut srv_tls, req_hdr_len, drop_srv_rd) =
            establish_vision_asymmetric_pair(256, 4096, uuid).await;

        // 1. Trigger server-speaks-first `poll_read` once: queues VLESS header + empty Vision
        //    camouflage block (> 256B uplink buffer), setting `header_flush_pending = true`.
        let mut polled_once = false;
        let first_poll = std::future::poll_fn(|cx| {
            if polled_once {
                return Poll::Ready(None);
            }
            polled_once = true;
            let mut tmp = [0u8; 64];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut cli_vision).poll_read(cx, &mut rb) {
                Poll::Ready(res) => Poll::Ready(Some(res)),
                Poll::Pending => Poll::Ready(None),
            }
        })
        .await;
        assert!(first_poll.is_none(), "expected Pending on initial SSF read");
        assert!(cli_vision.header_sent);
        assert!(
            cli_vision.header_flush_pending,
            "header_flush_pending should be true while camouflage header is partially queued"
        );
        assert!(cli_vision.tls.has_queued_tx());

        // 2. Server reads `req_hdr` + empty camouflage block so client `poll_write` can drain it.
        let (hdr_read_tx, hdr_read_rx) = tokio::sync::oneshot::channel::<()>();
        let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();
        let srv_task = tokio::spawn(async move {
            let mut hdr = vec![0u8; req_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let (cmd, content) = read_vision_block(&mut srv_tls, Some(*uuid.as_bytes())).await;
            assert_eq!(cmd, CMD_PADDING_CONTINUE);
            assert!(content.is_empty());
            let _ = hdr_read_tx.send(());

            // Wait until client queues 16 KiB into `enc_tx_buf` before sending early response
            // and dropping the uplink read half.
            proceed_rx.await.unwrap();

            let mut frame1 = BytesMut::from(&[0x00u8, 0x00u8][..]);
            let mut srv_uuid = Some(*uuid.as_bytes());
            append_vision_padded_block(
                &mut frame1,
                b"VISION-413-EARLY-",
                CMD_PADDING_CONTINUE,
                &mut srv_uuid,
                false,
            );
            srv_tls.write_all(&frame1).await.unwrap();
            srv_tls.flush().await.unwrap();

            drop_srv_rd.drop_reader();
            tokio::time::sleep(Duration::from_millis(25)).await;

            let mut frame2 = BytesMut::new();
            append_vision_padded_block(
                &mut frame2,
                b"RESPONSE",
                CMD_PADDING_END,
                &mut srv_uuid,
                false,
            );
            srv_tls.write_all(&frame2).await.unwrap();
            srv_tls.flush().await.unwrap();
            srv_tls.shutdown().await.unwrap();
        });

        // 3. Client write drains the camouflage header (clearing `header_flush_pending`!) and
        //    queues 16 KiB in `tls.enc_tx_buf`.
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            cli_vision.write(&vec![0xCCu8; 16 * 1024]),
        )
        .await
        .expect("client write hung draining camouflage header")
        .unwrap();
        assert_eq!(n, 16 * 1024);
        assert!(
            !cli_vision.header_flush_pending,
            "VisionStream::poll_write must clear header_flush_pending once header drains"
        );
        assert!(cli_vision.tls.has_queued_tx());
        hdr_read_rx.await.unwrap();
        let _ = proceed_tx.send(());

        // 4. Split and drain full multi-frame async-gapped Vision response cleanly after BrokenPipe.
        let (mut c_rd, mut c_wr) = tokio::io::split(cli_vision);
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), c_rd.read_to_end(&mut got))
            .await
            .expect("VisionStream read_to_end hung after uplink BrokenPipe")
            .expect("VisionStream must drain VISION-413-EARLY-RESPONSE across async gap");
        assert_eq!(got, b"VISION-413-EARLY-RESPONSE");
        srv_task.await.unwrap();

        let flush_err = c_wr
            .flush()
            .await
            .expect_err("writer flush must still surface BrokenPipe");
        assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn vision_ready_rx_buf_survives_broken_uplink_and_silent_ssf_fast_fails() {
        // 1. Already-unpadded bytes in `VisionStream::ready_rx_buf` MUST survive uplink BrokenPipe.
        {
            let uuid = Uuid::from_u128(0x778899aa_bbcc_4dde_eff0_011223344556);
            let (mut cli_vision, mut srv_tls, req_hdr_len, drop_srv_rd) =
                establish_vision_asymmetric_pair(256, 4096, uuid).await;

            let payload: Vec<u8> = (0u8..64u8).collect();
            let payload_srv = payload.clone();
            let (sent_tx, sent_rx) = tokio::sync::oneshot::channel::<()>();
            let (break_tx, break_rx) = tokio::sync::oneshot::channel::<()>();

            let srv_task = tokio::spawn(async move {
                let mut hdr = vec![0u8; req_hdr_len];
                srv_tls.read_exact(&mut hdr).await.unwrap();
                let _ = read_vision_block(&mut srv_tls, Some(*uuid.as_bytes())).await;

                let mut resp = BytesMut::from(&[0x00u8, 0x00u8][..]);
                let mut srv_uuid = Some(*uuid.as_bytes());
                append_vision_padded_block(
                    &mut resp,
                    &payload_srv,
                    CMD_PADDING_END,
                    &mut srv_uuid,
                    false,
                );
                srv_tls.write_all(&resp).await.unwrap();
                srv_tls.flush().await.unwrap();
                let _ = sent_tx.send(());

                break_rx.await.unwrap();
                drop_srv_rd.drop_reader();
                srv_tls.shutdown().await.unwrap();
            });

            cli_vision.write_all(b"hi").await.unwrap();
            cli_vision.flush().await.unwrap();
            sent_rx.await.unwrap();

            // Read only 8 bytes, leaving 56 already-unpadded bytes in `VisionStream::ready_rx_buf`.
            let mut head = [0u8; 8];
            cli_vision.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, &payload[..8]);
            assert_eq!(cli_vision.ready_rx_buf.len(), 56);

            // Queue 16 KiB into `tls.enc_tx_buf`, then break uplink and close downlink cleanly.
            let n = cli_vision.write(&vec![0xDDu8; 16 * 1024]).await.unwrap();
            assert_eq!(n, 16 * 1024);
            let _ = break_tx.send(());
            srv_task.await.unwrap();

            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), cli_vision.read_to_end(&mut rest))
                .await
                .expect("read_to_end hung draining VisionStream::ready_rx_buf")
                .expect("already-unpadded ready_rx_buf bytes must survive uplink BrokenPipe");
            assert_eq!(rest, payload[8..]);
        }

        // 2. Server-speaks-first silent broken uplink MUST fast-fail promptly without hanging.
        {
            let uuid = Uuid::from_u128(0x8899aabb_ccdd_4eef_f001_122334455667);
            let (mut cli_vision, _srv_tls, _req_hdr_len, drop_srv_rd) =
                establish_vision_asymmetric_pair(256, 4096, uuid).await;

            drop_srv_rd.drop_reader();
            let mut buf = [0u8; 64];
            let err = tokio::time::timeout(Duration::from_millis(500), cli_vision.read(&mut buf))
                .await
                .expect("server-speaks-first VisionStream hung on silent broken uplink")
                .expect_err("expected BrokenPipe on silent server-speaks-first broken uplink");
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }

        // 3. Server-speaks-first with `header_flush_pending == true` (client never called `write`):
        //    even if the server closes uplink before draining the camouflage header, any early
        //    multi-frame Vision response sent on downlink MUST still drain cleanly through EOF.
        {
            let uuid = Uuid::from_u128(0x899aabb0_ccdd_4eef_f001_122334455668);
            let (mut cli_vision, mut srv_tls, _req_hdr_len, drop_srv_rd) =
                establish_vision_asymmetric_pair(256, 4096, uuid).await;

            let mut polled_once = false;
            let first_poll = std::future::poll_fn(|cx| {
                if polled_once {
                    return Poll::Ready(None);
                }
                polled_once = true;
                let mut tmp = [0u8; 64];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut cli_vision).poll_read(cx, &mut rb) {
                    Poll::Ready(res) => Poll::Ready(Some(res)),
                    Poll::Pending => Poll::Ready(None),
                }
            })
            .await;
            assert!(first_poll.is_none());
            assert!(cli_vision.header_flush_pending);
            assert!(cli_vision.tls.has_queued_tx());

            let srv_task = tokio::spawn(async move {
                let mut frame1 = BytesMut::from(&[0x00u8, 0x00u8][..]);
                let mut srv_uuid = Some(*uuid.as_bytes());
                append_vision_padded_block(
                    &mut frame1,
                    b"SSF-EARLY-",
                    CMD_PADDING_CONTINUE,
                    &mut srv_uuid,
                    false,
                );
                srv_tls.write_all(&frame1).await.unwrap();
                srv_tls.flush().await.unwrap();
                drop_srv_rd.drop_reader();
                tokio::time::sleep(Duration::from_millis(25)).await;

                let mut frame2 = BytesMut::new();
                append_vision_padded_block(
                    &mut frame2,
                    b"RECOVERED",
                    CMD_PADDING_END,
                    &mut srv_uuid,
                    false,
                );
                srv_tls.write_all(&frame2).await.unwrap();
                srv_tls.flush().await.unwrap();
                srv_tls.shutdown().await.unwrap();
            });

            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), cli_vision.read_to_end(&mut got))
                .await
                .expect("SSF VisionStream hung draining early response with header_flush_pending")
                .expect("SSF VisionStream must drain early response despite broken uplink");
            assert_eq!(got, b"SSF-EARLY-RECOVERED");
            assert!(!cli_vision.header_flush_pending);
            srv_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn vision_same_task_select_cancel_write_and_split_dropped_reader_waker_isolation() {
        // 1. Same-task `tokio::select!` cancels a pending `write_all(48 KiB)` after chunk 1 is
        //    accepted into `enc_tx_buf`, then switches to read-only wait for server reply.
        {
            let uuid = Uuid::from_u128(0x99aabbcc_ddee_4ff0_0112_233445566778);
            let (mut cli_vision, mut srv_tls, req_hdr_len) =
                establish_vision_duplex_pair(256, uuid).await;

            let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel::<()>();
            let srv_task = tokio::spawn(async move {
                // Wait until client has cancelled its pending `write_all` before draining.
                cancel_done_rx.await.unwrap();
                let mut hdr = vec![0u8; req_hdr_len];
                srv_tls.read_exact(&mut hdr).await.unwrap();
                let mut srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);
                let mut chunk = vec![0u8; 16 * 1024];
                srv_vision.read_exact(&mut chunk).await.unwrap();
                assert!(chunk.iter().all(|&b| b == 0xAB));
                srv_vision.write_all(b"CANCEL-SAFE-REPLY").await.unwrap();
                srv_vision.flush().await.unwrap();
            });

            let big = vec![0xABu8; 48 * 1024];
            let cancelled = tokio::select! {
                _ = cli_vision.write_all(&big) => false,
                _ = tokio::time::sleep(Duration::from_millis(25)) => true,
            };
            assert!(
                cancelled,
                "expected write_all(48 KiB) to park Pending on full duplex(256) and be cancelled"
            );
            let _ = cancel_done_tx.send(());

            let mut reply = [0u8; 17];
            tokio::time::timeout(Duration::from_secs(2), cli_vision.read_exact(&mut reply))
                .await
                .expect("VisionStream deadlocked on read after same-task select! cancelled write")
                .unwrap();
            assert_eq!(&reply, b"CANCEL-SAFE-REPLY");
            srv_task.await.unwrap();
        }

        // 2. Split-stream `Task W != Task R`: writer parked on saturated `duplex(256)` while
        //    reader reads an early Vision push and drops `c_rd` BEFORE server drains upload.
        {
            let uuid = Uuid::from_u128(0xaabbccdd_eeff_4001_1223_344556677889);
            let (cli_vision, mut srv_tls, req_hdr_len) =
                establish_vision_duplex_pair(256, uuid).await;

            let upload: Vec<u8> = (0..(64 * 1024))
                .map(|i| ((i * 23 + 9) & 0xff) as u8)
                .collect();
            let expected_upload = upload.clone();
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_vision);

            let (rd_done_tx, rd_done_rx) = tokio::sync::oneshot::channel::<()>();
            let wr_task = tokio::spawn(async move {
                c_wr.write_all(&upload).await.unwrap();
                c_wr.flush().await.unwrap();
            });

            // Let writer saturate `duplex(256)` and park in `poll_write`.
            tokio::time::sleep(Duration::from_millis(20)).await;

            let rd_task = tokio::spawn(async move {
                let mut early = [0u8; 12];
                c_rd.read_exact(&mut early).await.unwrap();
                assert_eq!(&early, b"EARLY-VISION");
                drop(c_rd);
                let _ = rd_done_tx.send(());
            });

            // Server sends early Vision response BEFORE draining client's upload, then waits
            // for `c_rd` to exit & drop, and finally drains the full 64 KiB upload.
            let mut early_resp = BytesMut::from(&[0x00u8, 0x00u8][..]);
            let mut srv_uuid = Some(*uuid.as_bytes());
            append_vision_padded_block(
                &mut early_resp,
                b"EARLY-VISION",
                CMD_PADDING_END,
                &mut srv_uuid,
                false,
            );
            srv_tls.write_all(&early_resp).await.unwrap();
            srv_tls.flush().await.unwrap();

            tokio::time::timeout(Duration::from_secs(2), rd_done_rx)
                .await
                .expect("split Vision reader did not finish early push")
                .unwrap();
            rd_task.await.unwrap();

            let mut hdr = vec![0u8; req_hdr_len];
            tokio::time::timeout(Duration::from_secs(2), srv_tls.read_exact(&mut hdr))
                .await
                .expect("server hung reading VLESS header after client reader dropped")
                .unwrap();
            let mut srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);
            let mut got = vec![0u8; expected_upload.len()];
            tokio::time::timeout(Duration::from_secs(2), srv_vision.read_exact(&mut got))
                .await
                .expect("split Vision writer deadlocked after reader exited and dropped c_rd")
                .unwrap();
            assert_eq!(got, expected_upload);
            tokio::time::timeout(Duration::from_secs(2), wr_task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    async fn establish_vision_post_direct_bufstream_pair(
        duplex_buf: usize,
        uuid: Uuid,
    ) -> (
        VisionStream<tokio::io::BufStream<tokio::io::DuplexStream>>,
        VisionStream<tokio::io::DuplexStream>,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let sid = decode_reality_short_id("0102030405060708").unwrap();

        let (c_raw, s_raw) = tokio::io::duplex(duplex_buf);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id: sid,
            server_name: "www.apple.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let target = TargetAddr::new_domain("inner.example.com", 443).unwrap();
        let req_hdr = build_vless_vision_req_hdr(uuid, 0x01, &target);
        let req_hdr_len = req_hdr.len();

        let srv_setup = tokio::spawn(async move {
            let mut srv_tls =
                accept_reality_tls13_server(s_raw, &srv_sk_bytes, &sid, "www.apple.com")
                    .await
                    .unwrap();
            let mut hdr = vec![0u8; req_hdr_len];
            srv_tls.read_exact(&mut hdr).await.unwrap();
            let mut srv_vision = VisionStream::new_server(srv_tls, uuid, &[]);

            let mut ch = vec![0u8; 64];
            srv_vision.read_exact(&mut ch).await.unwrap();
            assert_eq!(&ch[0..3], &[0x16, 0x03, 0x01]);

            let mut sh = vec![0u8; 96];
            sh[0..3].copy_from_slice(&[0x16, 0x03, 0x03]);
            sh[3..5].copy_from_slice(&((96 - 5) as u16).to_be_bytes());
            sh[5] = 0x02;
            sh[43] = 32;
            sh[76..78].copy_from_slice(&0x1301u16.to_be_bytes());
            sh[82..88].copy_from_slice(TLS13_SUPPORTED_VERSIONS_EXT);
            srv_vision.write_all(&sh).await.unwrap();
            srv_vision.flush().await.unwrap();

            let mut srv_app = vec![0x17, 0x03, 0x03, 0x00, 0x0a];
            srv_app.extend_from_slice(b"srv-splice");
            srv_vision.write_all(&srv_app).await.unwrap();
            srv_vision.flush().await.unwrap();

            let mut cli_app = vec![0u8; 15];
            srv_vision.read_exact(&mut cli_app).await.unwrap();
            assert_eq!(&cli_app[5..], b"cli-splice");
            assert!(srv_vision.tls.is_direct_write());
            srv_vision
        });

        let cli_tls = connect_tls13_vision_stream(c_buf, &mode).await.unwrap();
        let mut cli_vision = VisionStream::new_client(cli_tls, uuid, req_hdr);

        let mut ch = vec![0u8; 64];
        ch[0..3].copy_from_slice(&[0x16, 0x03, 0x01]);
        ch[3..5].copy_from_slice(&59u16.to_be_bytes());
        ch[5] = 0x01;
        cli_vision.write_all(&ch).await.unwrap();
        cli_vision.flush().await.unwrap();

        let mut sh_and_app = vec![0u8; 96 + 15];
        cli_vision.read_exact(&mut sh_and_app).await.unwrap();
        assert_eq!(&sh_and_app[96 + 5..], b"srv-splice");

        let mut cli_app = vec![0x17, 0x03, 0x03, 0x00, 0x0a];
        cli_app.extend_from_slice(b"cli-splice");
        cli_vision.write_all(&cli_app).await.unwrap();
        cli_vision.flush().await.unwrap();

        let srv_vision = srv_setup.await.unwrap();
        assert!(
            cli_vision.tls.is_direct_write(),
            "client VisionStream must be in post-CMD_PADDING_DIRECT direct_write mode"
        );
        (cli_vision, srv_vision)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vision_post_direct_splice_bufstream_split_uncancelled_write_never_deadlocks() {
        let uuid = Uuid::from_u128(0xb1b2b3b4_c5c6_4d7d_8e9e_a0a1a2a3a4a5);
        let (cli_vision, mut srv_vision) =
            establish_vision_post_direct_bufstream_pair(256, uuid).await;

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_vision);
        let req1: Vec<u8> = (0..4096).map(|i| ((i * 31 + 11) & 0xff) as u8).collect();
        let req2: Vec<u8> = (0..4097).map(|i| ((i * 43 + 17) & 0xff) as u8).collect();
        let mut expected = Vec::with_capacity(req1.len() + req2.len());
        expected.extend_from_slice(&req1);
        expected.extend_from_slice(&req2);

        let (wr_parked_tx, wr_parked_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            start_srv_rx.await.unwrap();
            let mut got = vec![0u8; expected.len()];
            srv_vision.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            srv_vision.write_all(b"VISION-DIRECT-OK").await.unwrap();
            srv_vision.flush().await.unwrap();
        });

        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req1).await.unwrap();
            let _ = wr_parked_tx.send(());
            c_wr.write_all(&req2).await.unwrap();
        });

        wr_parked_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 16];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (wr_res, rd_res, srv_res) = tokio::join!(wr_task, rd_task, srv_task);
            wr_res.unwrap();
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VisionStream post-CMD_PADDING_DIRECT + BufStream split reader deadlocked with zero-cancellation write without flush",
        );
        assert_eq!(&reply, b"VISION-DIRECT-OK");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vision_post_direct_splice_bufstream_split_cancelled_flush_never_deadlocks() {
        let uuid = Uuid::from_u128(0xc1c2c3c4_d5d6_4e7e_8f9f_b0b1b2b3b4b5);
        let (cli_vision, mut srv_vision) =
            establish_vision_post_direct_bufstream_pair(256, uuid).await;

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_vision);
        let req: Vec<u8> = (0..4096).map(|i| ((i * 37 + 13) & 0xff) as u8).collect();
        let expected = req.clone();

        let (buffered_tx, buffered_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            start_srv_rx.await.unwrap();
            let mut got = vec![0u8; expected.len()];
            srv_vision.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            srv_vision.write_all(b"VISION-CANCEL-OK").await.unwrap();
            srv_vision.flush().await.unwrap();
        });

        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req).await.unwrap();
            let _ = buffered_tx.send(());
            let timed_out = tokio::time::timeout(Duration::from_millis(60), c_wr.flush())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected post-CMD_PADDING_DIRECT BufStream flush() to time out on full duplex(256)"
            );
        });

        buffered_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 16];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        wr_task.await.unwrap();
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "VisionStream post-CMD_PADDING_DIRECT + BufStream split reader deadlocked after timeout-cancelled flush()",
        );
        assert_eq!(&reply, b"VISION-CANCEL-OK");
    }
}
