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
    hdr_flushed: bool,
    pending_write: Option<(usize, u64)>,
    read_waker: Option<std::task::Waker>,
    write_waker: Option<std::task::Waker>,

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
            hdr_flushed: true,
            pending_write: None,
            read_waker: None,
            write_waker: None,
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
        let hdr_flushed = pre_write.is_empty();
        Self {
            inner,
            united_key,
            write_aead,
            out_ctr,
            pre_write,
            write_buf: BytesMut::with_capacity(8192),
            hdr_flushed,
            pending_write: None,
            read_waker: None,
            write_waker: None,
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
            hdr_flushed: true,
            pending_write: None,
            read_waker: None,
            write_waker: None,
            read_aead: Some(read_aead),
            in_ctr,
            init_state: InboundInitState::Ready,
            record_state: ReadRecordState::NeedHeader,
            raw_in: leftover_raw_in,
            plain_in: BytesMut::with_capacity(8192),
        }
    }

    fn stage_pre_write(&mut self) {
        if !self.pre_write.is_empty() {
            let pre = std::mem::take(&mut self.pre_write);
            if self.write_buf.is_empty() {
                self.write_buf.extend_from_slice(&pre);
            } else {
                let mut combined = BytesMut::with_capacity(pre.len() + self.write_buf.len());
                combined.extend_from_slice(&pre);
                combined.extend_from_slice(&self.write_buf);
                self.write_buf = combined;
            }
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessEncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.hdr_flushed {
            if this.pending_write.is_none() {
                this.stage_pre_write();

                let had_pending = !this.write_buf.is_empty();
                while !this.write_buf.is_empty() {
                    match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "VLESS encrypted stream write(0)",
                            )));
                        }
                        Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                            this.write_buf.clear();
                            this.hdr_flushed = true;
                            break;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
                            return Poll::Pending;
                        }
                    }
                }
                if had_pending && let Some(w) = this.write_waker.take() {
                    w.wake();
                }

                if !this.hdr_flushed {
                    match Pin::new(&mut this.inner).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            this.hdr_flushed = true;
                        }
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                            this.hdr_flushed = true;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
                            return Poll::Pending;
                        }
                    }
                }
            } else {
                crate::outbound::save_waker_slot(&mut this.read_waker, cx.waker());
            }
        }

        loop {
            if !this.plain_in.is_empty() {
                let n = buf.remaining().min(this.plain_in.len());
                buf.put_slice(&this.plain_in.split_to(n));
                return Poll::Ready(Ok(()));
            }

            this.process_inbound_records()?;
            if !this.plain_in.is_empty() {
                continue;
            }

            let mut tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        if !this.raw_in.is_empty()
                            || matches!(
                                this.init_state,
                                InboundInitState::Pending1RttPeerPadding { .. }
                                    | InboundInitState::Pending0RttFirstHeader { .. }
                            )
                            || matches!(this.record_state, ReadRecordState::NeedCiphertext { .. })
                        {
                            this.fire_0rtt_rejection_on_eof();
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated encrypted frame before EOF",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.raw_in.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessEncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            match this.flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {
                    if let Some(w) = this.read_waker.take() {
                        w.wake();
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    crate::outbound::save_waker_slot(&mut this.write_waker, cx.waker());
                    return Poll::Pending;
                }
            }
        }
        if let Some((done, sig)) = this.pending_write.take()
            && buf.len() >= done
            && crate::outbound::hash_write_prefix(&buf[..done]) == sig
        {
            return Poll::Ready(Ok(done));
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

        let ratchet = this.write_aead.is_at_max_nonce();
        let ct_and_tag = this.write_aead.seal(&buf[..take], &unmasked_hdr)?;
        if ratchet {
            let mut full_rec = Vec::with_capacity(RECORD_HEADER_LEN + ct_and_tag.len());
            full_rec.extend_from_slice(&unmasked_hdr);
            full_rec.extend_from_slice(&ct_and_tag);
            this.write_aead =
                VlessAead::new(&full_rec, this.united_key.as_ref(), this.write_aead.use_aes)?;
        }

        let mut wire_hdr = unmasked_hdr;
        if let Some(ctr) = this.out_ctr.as_mut() {
            ctr.xor_keystream(&mut wire_hdr)?;
        }

        if !this.pre_write.is_empty() {
            let pre = std::mem::take(&mut this.pre_write);
            this.write_buf.extend_from_slice(&pre);
        }
        this.write_buf.reserve(RECORD_HEADER_LEN + ct_and_tag.len());
        this.write_buf.put_slice(&wire_hdr);
        this.write_buf.put_slice(&ct_and_tag);

        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                if let Some(w) = this.read_waker.take() {
                    w.wake();
                }
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                let sig = crate::outbound::hash_write_prefix(&buf[..take]);
                this.pending_write = Some((take, sig));
                crate::outbound::save_waker_slot(&mut this.write_waker, cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.stage_pre_write();
        let had_pending = !this.write_buf.is_empty();
        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                if had_pending && let Some(w) = this.write_waker.take() {
                    w.wake();
                }
                match Pin::new(&mut this.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        this.hdr_flushed = true;
                        if let Some(w) = this.read_waker.take() {
                            w.wake();
                        }
                        Poll::Ready(Ok(()))
                    }
                    other => other,
                }
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().inner).poll_shutdown(cx),
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

    struct ThrottledStream<S> {
        inner: S,
        max_write: usize,
        yield_next_write: bool,
        yield_next_flush: bool,
    }

    impl<S> ThrottledStream<S> {
        fn new(inner: S, max_write: usize) -> Self {
            Self {
                inner,
                max_write: max_write.max(1),
                yield_next_write: false,
                yield_next_flush: true,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ThrottledStream<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ThrottledStream<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.yield_next_write {
                this.yield_next_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_next_write = true;
            let cap = buf.len().min(this.max_write);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..cap])
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.yield_next_flush {
                this.yield_next_flush = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_next_flush = true;
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    fn poll_write_once<W: AsyncWrite + Unpin>(
        writer: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        Pin::new(writer).poll_write(&mut cx, data)
    }

    #[tokio::test]
    async fn vless_encrypted_0rtt_flushes_pre_write_on_read_for_server_speaks_first() {
        let united_key = Zeroizing::new([0x7Au8; 96]);
        let enc_ticket = [0x33u8; 32];
        let srv_random = [0x66u8; 16];
        let pre_write = b"0RTT-CLIENT-TICKET-PREFIX-66B".to_vec();
        let expected_pre = pre_write.clone();

        let (c_io, mut s_io) = tokio::io::duplex(512);
        let c_write_aead = VlessAead::new(&enc_ticket, united_key.as_ref(), true).unwrap();
        let hook: ZeroRttInvalidationHook = Arc::new(Mutex::new(None));

        let mut client = VlessEncryptedStream::new_0rtt_client(
            ThrottledStream::new(c_io, 4),
            united_key.clone(),
            c_write_aead,
            None,
            pre_write,
            true,
            false,
            hook,
        );

        let srv_task = tokio::spawn(async move {
            let mut got_pre = vec![0u8; expected_pre.len()];
            s_io.read_exact(&mut got_pre)
                .await
                .expect("srv read 0-RTT pre_write");
            assert_eq!(got_pre, expected_pre);

            let s_write_aead = VlessAead::new(&srv_random, united_key.as_ref(), true).unwrap();
            let s_read_aead = VlessAead::new(&enc_ticket, united_key.as_ref(), true).unwrap();
            let mut srv = VlessEncryptedStream::new_server(
                s_io,
                united_key,
                s_write_aead,
                s_read_aead,
                None,
                None,
                srv_random.to_vec(),
                BytesMut::new(),
            );
            srv.write_all(b"220 pq-vless-ready\r\n")
                .await
                .expect("srv write banner");
            srv.flush().await.expect("srv flush");
            let mut reply = [0u8; 6];
            srv.read_exact(&mut reply).await.expect("srv read reply");
            assert_eq!(&reply, b"HELLO\n");
        });

        let mut banner = [0u8; 20];
        client
            .read_exact(&mut banner)
            .await
            .expect("client read banner before any write");
        assert_eq!(&banner, b"220 pq-vless-ready\r\n");
        client
            .write_all(b"HELLO\n")
            .await
            .expect("client write after banner");
        client.flush().await.expect("client flush");
        srv_task.await.expect("srv join");
    }

    #[tokio::test]
    async fn vless_encrypted_stream_no_duplication_on_interleaved_pending_write_read_and_flush() {
        let united_key = Zeroizing::new([0x91u8; 96]);
        let c_ctx = [0x12u8; 16];
        let s_ctx = [0x34u8; 16];

        // Part A: `poll_write` returns `Pending`, then `flush()` drains `write_buf`,
        // then retrying `write_all(payload)` must NOT encrypt & send `payload` twice.
        let (c_io, s_io) = tokio::io::duplex(8192);
        let mut client = VlessEncryptedStream::new_1rtt_client(
            ThrottledStream::new(c_io, 3),
            united_key.clone(),
            VlessAead::new(&c_ctx, united_key.as_ref(), true).unwrap(),
            VlessAead::new(&s_ctx, united_key.as_ref(), true).unwrap(),
            None,
            None,
            0,
        );
        let mut srv = VlessEncryptedStream::new_server(
            s_io,
            united_key.clone(),
            VlessAead::new(&s_ctx, united_key.as_ref(), true).unwrap(),
            VlessAead::new(&c_ctx, united_key.as_ref(), true).unwrap(),
            None,
            None,
            Vec::new(),
            BytesMut::new(),
        );

        let payload: Vec<u8> = (0..700).map(|i| (i * 13 + 7) as u8).collect();
        let srv_task = tokio::spawn(async move {
            let mut got = Vec::new();
            srv.read_to_end(&mut got).await.unwrap();
            got
        });

        assert!(matches!(
            poll_write_once(&mut client, &payload),
            Poll::Pending
        ));
        client.flush().await.expect("interleaved flush");
        client
            .write_all(&payload)
            .await
            .expect("retried write_all after flush");
        client.shutdown().await.expect("shutdown");

        let got = srv_task.await.unwrap();
        assert_eq!(got, payload, "encrypted payload must not be duplicated");

        // Part B: `copy_bidirectional` over 1-byte throttled stream (interleaving `poll_write` + `poll_read`).
        let (c_io2, s_io2) = tokio::io::duplex(256);
        let mut enc_client = VlessEncryptedStream::new_1rtt_client(
            ThrottledStream::new(c_io2, 1),
            united_key.clone(),
            VlessAead::new(&c_ctx, united_key.as_ref(), true).unwrap(),
            VlessAead::new(&s_ctx, united_key.as_ref(), true).unwrap(),
            Some(VlessCtr::new(united_key.as_ref(), &c_ctx)),
            Some(VlessCtr::new(united_key.as_ref(), &s_ctx)),
            0,
        );
        let enc_srv = VlessEncryptedStream::new_server(
            s_io2,
            united_key.clone(),
            VlessAead::new(&s_ctx, united_key.as_ref(), true).unwrap(),
            VlessAead::new(&c_ctx, united_key.as_ref(), true).unwrap(),
            Some(VlessCtr::new(united_key.as_ref(), &s_ctx)),
            Some(VlessCtr::new(united_key.as_ref(), &c_ctx)),
            Vec::new(),
            BytesMut::new(),
        );
        let (mut app_side, mut proxy_in) = tokio::io::duplex(256);

        let client_data: Vec<u8> = (0..1800).map(|i| (i ^ 0x6D) as u8).collect();
        let server_data: Vec<u8> = (0..1400).map(|i| (i * 23 + 3) as u8).collect();
        let server_data_expect = server_data.clone();

        let relay_task = tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut proxy_in, &mut enc_client)
                .await
                .expect("copy_bidirectional")
        });

        let srv_task2 = tokio::spawn(async move {
            let (mut srd, mut swr) = tokio::io::split(enc_srv);
            let writer = async move {
                swr.write_all(&server_data).await.expect("srv write");
                swr.shutdown().await.expect("srv shutdown");
            };
            let reader = async move {
                let mut got = Vec::new();
                srd.read_to_end(&mut got).await.expect("srv read");
                got
            };
            let (_, got_client) = tokio::join!(writer, reader);
            got_client
        });

        let client_data_send = client_data.clone();
        let (mut ard, mut awr) = tokio::io::split(&mut app_side);
        let app_writer = async move {
            awr.write_all(&client_data_send).await.expect("app write");
            awr.shutdown().await.expect("app shutdown");
        };
        let app_reader = async move {
            let mut got = Vec::new();
            ard.read_to_end(&mut got).await.expect("app read");
            got
        };
        let (_, got_server) = tokio::join!(app_writer, app_reader);
        let got_client = srv_task2.await.unwrap();
        let _ = relay_task.await.unwrap();

        assert_eq!(got_client, client_data);
        assert_eq!(got_server, server_data_expect);
    }

    #[tokio::test]
    async fn vless_encrypted_stream_cancelled_large_write_then_small_write_does_not_panic() {
        let united_key = Zeroizing::new([0xA8u8; 96]);
        let c_ctx = [0x01u8; 16];
        let s_ctx = [0x02u8; 16];

        let (c_io, s_io) = tokio::io::duplex(8192);
        let mut client = VlessEncryptedStream::new_1rtt_client(
            ThrottledStream::new(c_io, 4),
            united_key.clone(),
            VlessAead::new(&c_ctx, united_key.as_ref(), true).unwrap(),
            VlessAead::new(&s_ctx, united_key.as_ref(), true).unwrap(),
            None,
            None,
            0,
        );
        let mut srv = VlessEncryptedStream::new_server(
            s_io,
            united_key,
            VlessAead::new(&s_ctx, &[0xA8u8; 96], true).unwrap(),
            VlessAead::new(&c_ctx, &[0xA8u8; 96], true).unwrap(),
            None,
            None,
            Vec::new(),
            BytesMut::new(),
        );

        let srv_task = tokio::spawn(async move {
            let mut got = Vec::new();
            srv.read_to_end(&mut got).await.unwrap();
            got
        });

        let large_buf = vec![0x77u8; 1024];
        let small_buf = vec![0x88u8; 11];
        assert!(matches!(
            poll_write_once(&mut client, &large_buf),
            Poll::Pending
        ));

        client
            .write_all(&small_buf)
            .await
            .expect("cancelled large write followed by small write must not panic");
        client.shutdown().await.expect("shutdown");

        let got = srv_task.await.unwrap();
        let mut expected = large_buf;
        expected.extend_from_slice(&small_buf);
        assert_eq!(got, expected);
    }
}
