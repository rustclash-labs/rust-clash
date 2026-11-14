use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::outbound::vless::encryption::keys::{
    AEAD_TAG_LEN, MAX_READ_CIPHERTEXT, MAX_WRITE_PLAINTEXT, RECORD_HEADER_LEN, VlessAead, VlessCtr,
};

const RECORD_MAGIC: [u8; 3] = [0x17, 0x03, 0x03];

pub type ZeroRttInvalidationHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

enum InboundInitState {
    /// 1-RTT Client must first read & authenticate `serverPaddingLen - 18` bytes with `PeerAEAD` (`nonce = 3`).
    Pending1RttPeerPadding {
        len: usize,
    },
    /// 0-RTT Client must lazily read `serverRandom (16B)` on 1st read to derive `PeerAEAD` (+ `PeerCTR` in `random` mode).
    Pending0RttServerRandom {
        use_aes: bool,
        random_mode: bool,
        on_ticket_rejected: ZeroRttInvalidationHook,
    },
    /// 0-RTT Client has read `serverRandom (16B)` and awaits the first 5-byte `RECORD_HEADER_LEN`
    /// (which may arrive in a separate TCP segment / `poll_read` call).
    Pending0RttFirstHeader {
        on_ticket_rejected: ZeroRttInvalidationHook,
    },
    Ready,
}

enum ReadRecordState {
    NeedHeader,
    NeedCiphertext {
        unmasked_hdr: [u8; RECORD_HEADER_LEN],
        cipher_len: usize,
        on_0rtt_rejected: Option<ZeroRttInvalidationHook>,
    },
}

/// Wire-compatible implementation of Xray's `CommonConn` + `XorConn` 5-byte AEAD record stream.
pub struct VlessEncryptedStream<S> {
    inner: S,
    united_key: Zeroizing<[u8; 96]>,

    // Outbound state
    write_aead: VlessAead,
    out_ctr: Option<VlessCtr>,
    pre_write: Vec<u8>,
    write_buf: BytesMut,
    pending_plain_written: usize,

    // Inbound state
    read_aead: Option<VlessAead>,
    in_ctr: Option<VlessCtr>,
    init_state: InboundInitState,
    record_state: ReadRecordState,
    raw_in: BytesMut,
    plain_in: BytesMut,
}

impl<S> VlessEncryptedStream<S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_1rtt_client(
        inner: S,
        united_key: Zeroizing<[u8; 96]>,
        write_aead: VlessAead,
        read_aead: VlessAead,
        out_ctr: Option<VlessCtr>,
        in_ctr: Option<VlessCtr>,
        peer_padding_wire_len: usize,
    ) -> Self {
        Self {
            inner,
            united_key,
            write_aead,
            out_ctr,
            pre_write: Vec::new(),
            write_buf: BytesMut::with_capacity(8192),
            pending_plain_written: 0,
            read_aead: Some(read_aead),
            in_ctr,
            init_state: if peer_padding_wire_len > 0 {
                InboundInitState::Pending1RttPeerPadding {
                    len: peer_padding_wire_len,
                }
            } else {
                InboundInitState::Ready
            },
            record_state: ReadRecordState::NeedHeader,
            raw_in: BytesMut::with_capacity(8192),
            plain_in: BytesMut::with_capacity(8192),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_0rtt_client(
        inner: S,
        united_key: Zeroizing<[u8; 96]>,
        write_aead: VlessAead,
        out_ctr: Option<VlessCtr>,
        pre_write: Vec<u8>,
        use_aes: bool,
        random_mode: bool,
        on_ticket_rejected: ZeroRttInvalidationHook,
    ) -> Self {
        Self {
            inner,
            united_key,
            write_aead,
            out_ctr,
            pre_write,
            write_buf: BytesMut::with_capacity(8192),
            pending_plain_written: 0,
            read_aead: None,
            in_ctr: None,
            init_state: InboundInitState::Pending0RttServerRandom {
                use_aes,
                random_mode,
                on_ticket_rejected,
            },
            record_state: ReadRecordState::NeedHeader,
            raw_in: BytesMut::with_capacity(8192),
            plain_in: BytesMut::with_capacity(8192),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        inner: S,
        united_key: Zeroizing<[u8; 96]>,
        write_aead: VlessAead,
        read_aead: VlessAead,
        out_ctr: Option<VlessCtr>,
        in_ctr: Option<VlessCtr>,
        pre_write: Vec<u8>,
        leftover_raw_in: BytesMut,
    ) -> Self {
        Self {
            inner,
            united_key,
            write_aead,
            out_ctr,
            pre_write,
            write_buf: BytesMut::with_capacity(8192),
            pending_plain_written: 0,
            read_aead: Some(read_aead),
            in_ctr,
            init_state: InboundInitState::Ready,
            record_state: ReadRecordState::NeedHeader,
            raw_in: leftover_raw_in,
            plain_in: BytesMut::with_capacity(8192),
        }
    }

    fn fire_0rtt_rejection_on_eof(&mut self) {
        match &self.init_state {
            InboundInitState::Pending0RttServerRandom {
                on_ticket_rejected, ..
            }
            | InboundInitState::Pending0RttFirstHeader { on_ticket_rejected } => {
                if let Some(cb) = on_ticket_rejected.lock().take() {
                    cb();
                }
            }
            _ => {}
        }
        if let ReadRecordState::NeedCiphertext {
            on_0rtt_rejected: Some(hook),
            ..
        } = &self.record_state
            && let Some(cb) = hook.lock().take()
        {
            cb();
        }
    }

    fn process_inbound_records(&mut self) -> io::Result<()> {
        loop {
            match &mut self.init_state {
                InboundInitState::Pending1RttPeerPadding { len } => {
                    let need = *len;
                    if self.raw_in.len() < need {
                        return Ok(());
                    }
                    let pad_wire = self.raw_in.split_to(need);
                    let aead = self.read_aead.as_mut().expect("1-RTT read_aead present");
                    // Opens `serverPadding` with `nonce = 3` (`aad = b""`)
                    let _ = aead.open(&pad_wire, b"")?;
                    self.init_state = InboundInitState::Ready;
                }
                InboundInitState::Pending0RttServerRandom {
                    use_aes,
                    random_mode,
                    ..
                } => {
                    if self.raw_in.len() < 16 {
                        return Ok(());
                    }
                    let use_aes_val = *use_aes;
                    let random_mode_val = *random_mode;
                    let srv_rand_bytes = self.raw_in.split_to(16);
                    let srv_rand: [u8; 16] = srv_rand_bytes.as_ref().try_into().unwrap();
                    let read_aead =
                        VlessAead::new(&srv_rand, self.united_key.as_ref(), use_aes_val)?;
                    if random_mode_val {
                        self.in_ctr = Some(VlessCtr::new(self.united_key.as_ref(), &srv_rand));
                    }
                    self.read_aead = Some(read_aead);
                    let prev = std::mem::replace(&mut self.init_state, InboundInitState::Ready);
                    if let InboundInitState::Pending0RttServerRandom {
                        on_ticket_rejected, ..
                    } = prev
                    {
                        self.init_state =
                            InboundInitState::Pending0RttFirstHeader { on_ticket_rejected };
                    }
                }
                InboundInitState::Pending0RttFirstHeader { .. } => {
                    if self.raw_in.len() < RECORD_HEADER_LEN {
                        return Ok(());
                    }
                    let mut hdr: [u8; RECORD_HEADER_LEN] = self
                        .raw_in
                        .split_to(RECORD_HEADER_LEN)
                        .as_ref()
                        .try_into()
                        .unwrap();
                    if let Some(ctr) = self.in_ctr.as_mut() {
                        ctr.xor_keystream(&mut hdr)?;
                    }
                    let prev = std::mem::replace(&mut self.init_state, InboundInitState::Ready);
                    let hook = match prev {
                        InboundInitState::Pending0RttFirstHeader { on_ticket_rejected } => {
                            Some(on_ticket_rejected)
                        }
                        _ => None,
                    };
                    match decode_record_header(&hdr) {
                        Ok(cipher_len) => {
                            self.record_state = ReadRecordState::NeedCiphertext {
                                unmasked_hdr: hdr,
                                cipher_len,
                                on_0rtt_rejected: hook,
                            };
                        }
                        Err(_) => {
                            if let Some(h) = hook
                                && let Some(cb) = h.lock().take()
                            {
                                cb();
                            }
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "new handshake needed (0-RTT ticket rejected by server)",
                            ));
                        }
                    }
                }
                InboundInitState::Ready => break,
            }
        }

        loop {
            match &mut self.record_state {
                ReadRecordState::NeedHeader => {
                    if self.raw_in.len() < RECORD_HEADER_LEN {
                        return Ok(());
                    }
                    let mut hdr: [u8; RECORD_HEADER_LEN] = self
                        .raw_in
                        .split_to(RECORD_HEADER_LEN)
                        .as_ref()
                        .try_into()
                        .unwrap();
                    if let Some(ctr) = self.in_ctr.as_mut() {
                        ctr.xor_keystream(&mut hdr)?;
                    }
                    let cipher_len = decode_record_header(&hdr)?;
                    self.record_state = ReadRecordState::NeedCiphertext {
                        unmasked_hdr: hdr,
                        cipher_len,
                        on_0rtt_rejected: None,
                    };
                }
                ReadRecordState::NeedCiphertext {
                    unmasked_hdr,
                    cipher_len,
                    on_0rtt_rejected,
                } => {
                    let need = *cipher_len;
                    if self.raw_in.len() < need {
                        return Ok(());
                    }
                    let hdr_copy = *unmasked_hdr;
                    let hook = on_0rtt_rejected.take();
                    let body = self.raw_in.split_to(need);
                    let aead = self.read_aead.as_mut().expect("read_aead initialized");
                    let ratchet = aead.is_at_max_nonce();
                    let plain = match aead.open(&body, &hdr_copy) {
                        Ok(p) => p,
                        Err(e) => {
                            if let Some(h) = hook
                                && let Some(cb) = h.lock().take()
                            {
                                cb();
                            }
                            return Err(e);
                        }
                    };
                    if ratchet {
                        let mut full_rec = Vec::with_capacity(RECORD_HEADER_LEN + body.len());
                        full_rec.extend_from_slice(&hdr_copy);
                        full_rec.extend_from_slice(&body);
                        *aead = VlessAead::new(&full_rec, self.united_key.as_ref(), aead.use_aes)?;
                    }
                    self.plain_in.extend_from_slice(&plain);
                    self.record_state = ReadRecordState::NeedHeader;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> VlessEncryptedStream<S> {
    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VLESS encrypted stream write(0)",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.write_buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

fn decode_record_header(unmasked: &[u8; RECORD_HEADER_LEN]) -> io::Result<usize> {
    if unmasked[..3] != RECORD_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid VLESS encryption record header: {:02x?}",
                &unmasked[..]
            ),
        ));
    }
    let l = u16::from_be_bytes([unmasked[3], unmasked[4]]) as usize;
    if !(17..=MAX_READ_CIPHERTEXT).contains(&l) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid VLESS encryption record length {l}"),
        ));
    }
    Ok(l)
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessEncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain_in.is_empty() {
                let n = buf.remaining().min(self.plain_in.len());
                buf.put_slice(&self.plain_in.split_to(n));
                return Poll::Ready(Ok(()));
            }

            self.process_inbound_records()?;
            if !self.plain_in.is_empty() {
                continue;
            }

            let mut tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        if !self.raw_in.is_empty()
                            || matches!(
                                self.init_state,
                                InboundInitState::Pending1RttPeerPadding { .. }
                                    | InboundInitState::Pending0RttFirstHeader { .. }
                            )
                            || matches!(self.record_state, ReadRecordState::NeedCiphertext { .. })
                        {
                            self.fire_0rtt_rejection_on_eof();
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated encrypted frame before EOF",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.raw_in.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessEncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !self.write_buf.is_empty() {
            match self.flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {
                    if self.pending_plain_written > 0 {
                        let done = self.pending_plain_written;
                        self.pending_plain_written = 0;
                        return Poll::Ready(Ok(done));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let take = buf.len().min(MAX_WRITE_PLAINTEXT);
        let wire_len = (take + AEAD_TAG_LEN) as u16;
        let unmasked_hdr = [
            RECORD_MAGIC[0],
            RECORD_MAGIC[1],
            RECORD_MAGIC[2],
            (wire_len >> 8) as u8,
            (wire_len & 0xFF) as u8,
        ];

        let ratchet = self.write_aead.is_at_max_nonce();
        let ct_and_tag = self.write_aead.seal(&buf[..take], &unmasked_hdr)?;
        if ratchet {
            let mut full_rec = Vec::with_capacity(RECORD_HEADER_LEN + ct_and_tag.len());
            full_rec.extend_from_slice(&unmasked_hdr);
            full_rec.extend_from_slice(&ct_and_tag);
            self.write_aead =
                VlessAead::new(&full_rec, self.united_key.as_ref(), self.write_aead.use_aes)?;
        }

        let mut wire_hdr = unmasked_hdr;
        if let Some(ctr) = self.out_ctr.as_mut() {
            ctr.xor_keystream(&mut wire_hdr)?;
        }

        if !self.pre_write.is_empty() {
            let pre = std::mem::take(&mut self.pre_write);
            self.write_buf.extend_from_slice(&pre);
        }
        self.write_buf.reserve(RECORD_HEADER_LEN + ct_and_tag.len());
        self.write_buf.put_slice(&wire_hdr);
        self.write_buf.put_slice(&ct_and_tag);

        match self.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.pending_plain_written = take;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn zero_rtt_split_reads_still_fire_on_ticket_rejected() {
        let (client_io, mut server_io) = tokio::io::duplex(256);
        let united_key = Zeroizing::new([0x42u8; 96]);
        let write_aead = VlessAead::new(&[0x11u8; 16], united_key.as_ref(), true).unwrap();

        let rejected_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&rejected_flag);
        let hook: ZeroRttInvalidationHook = Arc::new(Mutex::new(Some(Box::new(move || {
            flag_clone.store(true, Ordering::SeqCst);
        }))));

        let mut stream = VlessEncryptedStream::new_0rtt_client(
            client_io,
            united_key,
            write_aead,
            None,
            Vec::new(),
            true,
            false,
            hook,
        );

        let writer = tokio::spawn(async move {
            // Deliver 16-byte server_random in TCP segment #1
            server_io.write_all(&[0x55u8; 16]).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::task::yield_now().await;
            // Deliver invalid 5-byte record header in TCP segment #2
            server_io
                .write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01])
                .await
                .unwrap();
            server_io.flush().await.unwrap();
        });

        let mut buf = [0u8; 32];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert!(rejected_flag.load(Ordering::SeqCst));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn vless_encrypted_stream_detects_truncated_frame_before_eof() {
        let united_key = Zeroizing::new([0x24u8; 96]);

        // 1. Clean 0-byte EOF when raw_in is empty -> Ok(0)
        let (c_io1, s_io1) = tokio::io::duplex(256);
        drop(s_io1);
        let w_aead1 = VlessAead::new(&[1u8; 16], united_key.as_ref(), true).unwrap();
        let r_aead1 = VlessAead::new(&[2u8; 16], united_key.as_ref(), true).unwrap();
        let mut clean_stream = VlessEncryptedStream::new_1rtt_client(
            c_io1,
            united_key.clone(),
            w_aead1,
            r_aead1,
            None,
            None,
            0,
        );
        let mut out = Vec::new();
        assert_eq!(clean_stream.read_to_end(&mut out).await.unwrap(), 0);

        // 2. Partial AEAD record before EOF -> UnexpectedEof
        let (c_io2, mut s_io2) = tokio::io::duplex(256);
        // Valid 5-byte header claiming 21 bytes of ciphertext, but only 4 bytes follow before EOF
        s_io2
            .write_all(&[0x17, 0x03, 0x03, 0x00, 21, 0xAA, 0xBB, 0xCC, 0xDD])
            .await
            .unwrap();
        drop(s_io2);
        let w_aead2 = VlessAead::new(&[1u8; 16], united_key.as_ref(), true).unwrap();
        let r_aead2 = VlessAead::new(&[2u8; 16], united_key.as_ref(), true).unwrap();
        let mut trunc_stream = VlessEncryptedStream::new_1rtt_client(
            c_io2, united_key, w_aead2, r_aead2, None, None, 0,
        );
        let err = trunc_stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
