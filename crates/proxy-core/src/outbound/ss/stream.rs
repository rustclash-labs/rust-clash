use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::{
    addr::TargetAddr,
    outbound::ss::crypto::{
        LEGACY_MAX_PAYLOAD, SS2022_MAX_PAYLOAD, SsAeadCipher, SsCipherKind, TAG_LEN, random_bytes,
    },
};

pub fn unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn validate_ss2022_timestamp(peer_ts: u64) -> io::Result<()> {
    let now = unix_epoch_secs();
    if now.abs_diff(peer_ts) > 30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SS-2022 timestamp skew exceeded 30s (now={now}, peer={peer_ts})"),
        ));
    }
    Ok(())
}

enum ReadState {
    NeedSalt,
    /// SS-2022 Client waiting for Server's Fixed-Length Response Header (`1 + 8 + salt_len + 2 + 16B`)
    NeedSs2022RespFixed,
    NeedLenChunk,
    NeedPayloadChunk(usize),
}

enum WritePhase {
    /// Client stream waiting for first write so `salt + target_addr (+ SS-2022 headers) + initial_payload` go out in 1 write!
    ClientInitial {
        target_addr: Vec<u8>,
    },
    /// SS-2022 Server stream waiting for first response payload so `resp_salt + FixedRespHdr + FirstChunk` go out in 1 write!
    ServerSs2022Initial {
        request_salt: Vec<u8>,
    },
    ///Legacy AEAD Server stream waiting to prepend `resp_salt` on first write.
    ServerLegacyInitial,
    Ready,
}

/// Bidirectional `AsyncRead + AsyncWrite` stream implementing both standard Shadowsocks AEAD
/// and Shadowsocks 2022 (SIP022) TCP framing!
pub struct ShadowsocksStream<S> {
    inner: S,
    kind: SsCipherKind,
    master_key: Zeroizing<Vec<u8>>,

    // Write state
    enc: Option<SsAeadCipher>,
    client_sent_salt: Vec<u8>,
    write_phase: WritePhase,
    write_buf: BytesMut,
    hdr_flushed: bool,
    pending_write: Option<(usize, u64)>,
    read_waker: Option<std::task::Waker>,
    write_waker: Option<std::task::Waker>,

    // Read state
    dec: Option<SsAeadCipher>,
    read_state: ReadState,
    raw_in: BytesMut,
    plain_in: BytesMut,
}

impl<S> ShadowsocksStream<S> {
    /// Construct a client-side Shadowsocks TCP stream targeting `target`.
    pub fn new_client(
        inner: S,
        kind: SsCipherKind,
        master_key: Zeroizing<Vec<u8>>,
        target: &TargetAddr,
    ) -> io::Result<Self> {
        let addr_bytes = target.to_socks5_bytes()?;
        let salt = random_bytes(kind.salt_len())?;
        let enc = SsAeadCipher::new(kind, &master_key, &salt)?;
        Ok(Self {
            inner,
            kind,
            master_key,
            enc: Some(enc),
            client_sent_salt: salt,
            write_phase: WritePhase::ClientInitial {
                target_addr: addr_bytes,
            },
            write_buf: BytesMut::with_capacity(4096),
            hdr_flushed: false,
            pending_write: None,
            read_waker: None,
            write_waker: None,
            dec: None,
            read_state: ReadState::NeedSalt,
            raw_in: BytesMut::with_capacity(4096),
            plain_in: BytesMut::with_capacity(4096),
        })
    }

    /// Construct a server-side Shadowsocks TCP stream after reading & authenticating the client request header!
    pub fn from_server_parts(
        inner: S,
        kind: SsCipherKind,
        master_key: Zeroizing<Vec<u8>>,
        dec: SsAeadCipher,
        request_salt: Vec<u8>,
        leftover_raw_in: BytesMut,
        initial_plain_in: BytesMut,
    ) -> Self {
        let write_phase = if kind.is_ss2022() {
            WritePhase::ServerSs2022Initial { request_salt }
        } else {
            WritePhase::ServerLegacyInitial
        };
        Self {
            inner,
            kind,
            master_key,
            enc: None,
            client_sent_salt: Vec::new(),
            write_phase,
            write_buf: BytesMut::with_capacity(4096),
            hdr_flushed: true,
            pending_write: None,
            read_waker: None,
            write_waker: None,
            dec: Some(dec),
            read_state: ReadState::NeedLenChunk,
            raw_in: leftover_raw_in,
            plain_in: initial_plain_in,
        }
    }

    fn max_chunk_size(&self) -> usize {
        if self.kind.is_ss2022() {
            SS2022_MAX_PAYLOAD
        } else {
            LEGACY_MAX_PAYLOAD
        }
    }

    fn encode_standard_chunk(
        enc: &mut SsAeadCipher,
        data: &[u8],
        dst: &mut BytesMut,
    ) -> io::Result<()> {
        let len_hdr = (data.len() as u16).to_be_bytes();
        let enc_len = enc.seal(&len_hdr)?;
        let enc_body = enc.seal(data)?;
        dst.reserve(enc_len.len() + enc_body.len());
        dst.put_slice(&enc_len);
        dst.put_slice(&enc_body);
        Ok(())
    }

    fn encode_client_initial_header_only(&mut self) -> io::Result<()> {
        if !matches!(self.write_phase, WritePhase::ClientInitial { .. }) {
            return Ok(());
        }
        let phase = std::mem::replace(&mut self.write_phase, WritePhase::Ready);
        if let WritePhase::ClientInitial { target_addr } = phase {
            if self.kind.is_ss2022() {
                let pad_len: usize = rand::rng().random_range(32..=128);
                let var_len = target_addr.len() + 2 + pad_len;
                let mut fixed_hdr = [0u8; 11];
                fixed_hdr[0] = 0x00;
                fixed_hdr[1..9].copy_from_slice(&unix_epoch_secs().to_be_bytes());
                fixed_hdr[9..11].copy_from_slice(&(var_len as u16).to_be_bytes());

                let mut var_hdr = BytesMut::with_capacity(var_len);
                var_hdr.put_slice(&target_addr);
                var_hdr.put_u16(pad_len as u16);
                var_hdr.put_bytes(0, pad_len);

                let salt_copy = self.client_sent_salt.clone();
                let enc = self.enc.as_mut().expect("client encoder present");
                let c0 = enc.seal(&fixed_hdr)?;
                let c1 = enc.seal(&var_hdr)?;
                self.write_buf.extend_from_slice(&salt_copy);
                self.write_buf.extend_from_slice(&c0);
                self.write_buf.extend_from_slice(&c1);
            } else {
                let salt_copy = self.client_sent_salt.clone();
                self.write_buf.extend_from_slice(&salt_copy);
                let enc = self.enc.as_mut().expect("client encoder present");
                Self::encode_standard_chunk(enc, &target_addr, &mut self.write_buf)?;
            }
        }
        Ok(())
    }

    fn try_decode_frames(&mut self) -> io::Result<()> {
        loop {
            match self.read_state {
                ReadState::NeedSalt => {
                    let salt_len = self.kind.salt_len();
                    if self.raw_in.len() < salt_len {
                        return Ok(());
                    }
                    let peer_salt = self.raw_in.split_to(salt_len);
                    let dec = SsAeadCipher::new(self.kind, &self.master_key, &peer_salt)?;
                    self.dec = Some(dec);
                    self.read_state = if self.kind.is_ss2022() {
                        ReadState::NeedSs2022RespFixed
                    } else {
                        ReadState::NeedLenChunk
                    };
                }
                ReadState::NeedSs2022RespFixed => {
                    // Fixed response header: type(1) + ts(8) + req_salt(salt_len) + first_len(2) + tag(16)
                    let salt_len = self.kind.salt_len();
                    let fixed_wire_len = 1 + 8 + salt_len + 2 + TAG_LEN;
                    if self.raw_in.len() < fixed_wire_len {
                        return Ok(());
                    }
                    let chunk = self.raw_in.split_to(fixed_wire_len);
                    let dec = self.dec.as_mut().expect("decoder initialized");
                    let plain = dec.open(&chunk)?;
                    if plain[0] != 0x01 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid SS-2022 response header type 0x{:02x}", plain[0]),
                        ));
                    }
                    let peer_ts = u64::from_be_bytes(plain[1..9].try_into().unwrap());
                    validate_ss2022_timestamp(peer_ts)?;
                    if plain[9..9 + salt_len] != self.client_sent_salt[..] {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SS-2022 response request_salt mismatch (MITM / replay)",
                        ));
                    }
                    let first_len =
                        u16::from_be_bytes([plain[9 + salt_len], plain[9 + salt_len + 1]]) as usize;
                    self.read_state = if first_len == 0 {
                        ReadState::NeedLenChunk
                    } else {
                        ReadState::NeedPayloadChunk(first_len)
                    };
                }
                ReadState::NeedLenChunk => {
                    let len_wire = 2 + TAG_LEN;
                    if self.raw_in.len() < len_wire {
                        return Ok(());
                    }
                    let chunk = self.raw_in.split_to(len_wire);
                    let dec = self.dec.as_mut().expect("decoder initialized");
                    let len_plain = dec.open(&chunk)?;
                    let raw_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
                    if !self.kind.is_ss2022() && raw_len > LEGACY_MAX_PAYLOAD {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("legacy SS AEAD chunk length 0x{raw_len:04x} exceeds 0x3FFF"),
                        ));
                    }
                    if raw_len == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "zero-length Shadowsocks data chunk",
                        ));
                    }
                    self.read_state = ReadState::NeedPayloadChunk(raw_len);
                }
                ReadState::NeedPayloadChunk(plen) => {
                    let wire_len = plen + TAG_LEN;
                    if self.raw_in.len() < wire_len {
                        return Ok(());
                    }
                    let chunk = self.raw_in.split_to(wire_len);
                    let dec = self.dec.as_mut().expect("decoder initialized");
                    let data = dec.open(&chunk)?;
                    self.plain_in.extend_from_slice(&data);
                    self.read_state = ReadState::NeedLenChunk;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ShadowsocksStream<S> {
    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks underlying stream returned write(0)",
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.hdr_flushed {
            if this.pending_write.is_none() {
                if matches!(this.write_phase, WritePhase::ClientInitial { .. })
                    && this.write_buf.is_empty()
                {
                    this.encode_client_initial_header_only()?;
                }

                let had_pending = !this.write_buf.is_empty();
                while !this.write_buf.is_empty() {
                    match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "Shadowsocks underlying stream returned write(0)",
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
                let to_copy = buf.remaining().min(this.plain_in.len());
                buf.put_slice(&this.plain_in.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }

            this.try_decode_frames()?;
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
                                this.read_state,
                                ReadState::NeedSs2022RespFixed | ReadState::NeedPayloadChunk(_)
                            )
                        {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated encrypted frame before EOF",
                            )));
                        }
                        return Poll::Ready(Ok(())); // Clean EOF
                    }
                    this.raw_in.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();

        // First flush any previously queued ciphertext chunk completely
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

        let max_chunk = this.max_chunk_size();
        let phase = std::mem::replace(&mut this.write_phase, WritePhase::Ready);

        let consumed_plain = match phase {
            WritePhase::ClientInitial { target_addr } => {
                if this.kind.is_ss2022() {
                    // SIP022 Client Request: `salt || Chunk0(type=0, ts, var_len) || Chunk1(addr, pad_len, pad, init_payload)`
                    let pad_len: usize = if buf.is_empty() {
                        rand::rng().random_range(32..=256)
                    } else {
                        rand::rng().random_range(0..=64)
                    };
                    let overhead = target_addr.len() + 2 + pad_len;
                    let take = buf
                        .len()
                        .min(SS2022_MAX_PAYLOAD.saturating_sub(overhead))
                        .max(1);
                    let var_len = overhead + take;

                    let mut fixed_hdr = [0u8; 11];
                    fixed_hdr[0] = 0x00;
                    fixed_hdr[1..9].copy_from_slice(&unix_epoch_secs().to_be_bytes());
                    fixed_hdr[9..11].copy_from_slice(&(var_len as u16).to_be_bytes());

                    let mut var_hdr = BytesMut::with_capacity(var_len);
                    var_hdr.put_slice(&target_addr);
                    var_hdr.put_u16(pad_len as u16);
                    var_hdr.put_bytes(0, pad_len);
                    var_hdr.put_slice(&buf[..take]);

                    let salt_copy = this.client_sent_salt.clone();
                    let enc = this.enc.as_mut().expect("client encoder present");
                    let c0 = enc.seal(&fixed_hdr)?;
                    let c1 = enc.seal(&var_hdr)?;

                    this.write_buf.extend_from_slice(&salt_copy);
                    this.write_buf.extend_from_slice(&c0);
                    this.write_buf.extend_from_slice(&c1);
                    take
                } else {
                    // Legacy AEAD Client Request: `salt || Chunk0(addr || init_payload)`
                    let take = buf
                        .len()
                        .min(LEGACY_MAX_PAYLOAD.saturating_sub(target_addr.len()))
                        .max(1);
                    let mut first_plain = Vec::with_capacity(target_addr.len() + take);
                    first_plain.extend_from_slice(&target_addr);
                    first_plain.extend_from_slice(&buf[..take]);

                    this.write_buf.extend_from_slice(&this.client_sent_salt);
                    let enc = this.enc.as_mut().expect("client encoder present");
                    Self::encode_standard_chunk(enc, &first_plain, &mut this.write_buf)?;
                    take
                }
            }
            WritePhase::ServerSs2022Initial { request_salt } => {
                let resp_salt = random_bytes(this.kind.salt_len())?;
                let mut enc = SsAeadCipher::new(this.kind, &this.master_key, &resp_salt)?;
                let take = buf.len().min(SS2022_MAX_PAYLOAD);

                let mut fixed_resp = BytesMut::with_capacity(1 + 8 + request_salt.len() + 2);
                fixed_resp.put_u8(0x01);
                fixed_resp.put_u64(unix_epoch_secs());
                fixed_resp.put_slice(&request_salt);
                fixed_resp.put_u16(take as u16);

                let c0 = enc.seal(&fixed_resp)?;
                let c1 = enc.seal(&buf[..take])?;

                this.write_buf.extend_from_slice(&resp_salt);
                this.write_buf.extend_from_slice(&c0);
                this.write_buf.extend_from_slice(&c1);
                this.enc = Some(enc);
                take
            }
            WritePhase::ServerLegacyInitial => {
                let resp_salt = random_bytes(this.kind.salt_len())?;
                let mut enc = SsAeadCipher::new(this.kind, &this.master_key, &resp_salt)?;
                let take = buf.len().min(LEGACY_MAX_PAYLOAD);
                this.write_buf.extend_from_slice(&resp_salt);
                Self::encode_standard_chunk(&mut enc, &buf[..take], &mut this.write_buf)?;
                this.enc = Some(enc);
                take
            }
            WritePhase::Ready => {
                let take = buf.len().min(max_chunk);
                let enc = this.enc.as_mut().expect("encoder initialized");
                Self::encode_standard_chunk(enc, &buf[..take], &mut this.write_buf)?;
                take
            }
        };

        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                if let Some(w) = this.read_waker.take() {
                    w.wake();
                }
                Poll::Ready(Ok(consumed_plain))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                let sig = crate::outbound::hash_write_prefix(&buf[..consumed_plain]);
                this.pending_write = Some((consumed_plain, sig));
                crate::outbound::save_waker_slot(&mut this.write_waker, cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // If a client opened a SS-2022 or Legacy stream and calls flush() before writing user payload
        // (e.g. server-speaks-first protocols), flush the header with mandatory padding!
        if matches!(this.write_phase, WritePhase::ClientInitial { .. }) && this.write_buf.is_empty()
        {
            this.encode_client_initial_header_only()?;
        }

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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    async fn accept_mock_ss_server<S: AsyncRead + AsyncWrite + Unpin>(
        mut io: S,
        kind: SsCipherKind,
        master_key: Zeroizing<Vec<u8>>,
    ) -> io::Result<(TargetAddr, ShadowsocksStream<S>)> {
        let salt_len = kind.salt_len();
        if kind.is_ss2022() {
            let mut prefix = vec![0u8; salt_len + 27];
            io.read_exact(&mut prefix).await?;
            let req_salt = prefix[..salt_len].to_vec();
            let mut dec = SsAeadCipher::new(kind, &master_key, &req_salt)?;
            let fixed_plain = dec.open(&prefix[salt_len..])?;
            assert_eq!(fixed_plain[0], 0x00);
            let ts = u64::from_be_bytes(fixed_plain[1..9].try_into().unwrap());
            validate_ss2022_timestamp(ts)?;
            let var_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;
            let mut var_wire = vec![0u8; var_len + TAG_LEN];
            io.read_exact(&mut var_wire).await?;
            let var_plain = dec.open(&var_wire)?;
            let (target, addr_used) = TargetAddr::decode_socks5_slice(&var_plain)?;
            let pad_len =
                u16::from_be_bytes([var_plain[addr_used], var_plain[addr_used + 1]]) as usize;
            let init_payload = &var_plain[addr_used + 2 + pad_len..];
            if init_payload.is_empty() {
                assert!(
                    pad_len > 0,
                    "SIP022 requires non-empty padding when payload is empty"
                );
            }
            let mut initial_plain = BytesMut::new();
            initial_plain.extend_from_slice(init_payload);
            let srv = ShadowsocksStream::from_server_parts(
                io,
                kind,
                master_key,
                dec,
                req_salt,
                BytesMut::new(),
                initial_plain,
            );
            Ok((target, srv))
        } else {
            let mut hdr = vec![0u8; salt_len + 2 + TAG_LEN];
            io.read_exact(&mut hdr).await?;
            let req_salt = hdr[..salt_len].to_vec();
            let mut dec = SsAeadCipher::new(kind, &master_key, &req_salt)?;
            let len_plain = dec.open(&hdr[salt_len..])?;
            let plen = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            let mut first_wire = vec![0u8; plen + TAG_LEN];
            io.read_exact(&mut first_wire).await?;
            let first_plain = dec.open(&first_wire)?;
            let (target, addr_used) = TargetAddr::decode_socks5_slice(&first_plain)?;
            let mut initial_plain = BytesMut::new();
            initial_plain.extend_from_slice(&first_plain[addr_used..]);
            let srv = ShadowsocksStream::from_server_parts(
                io,
                kind,
                master_key,
                dec,
                req_salt,
                BytesMut::new(),
                initial_plain,
            );
            Ok((target, srv))
        }
    }

    #[tokio::test]
    async fn shadowsocks_stream_detects_truncated_frame_on_eof_and_allows_clean_eof() {
        let kind = SsCipherKind::Aes256Gcm;
        let master_key = kind.master_key("test-pass").unwrap();
        let target = TargetAddr::new_domain("example.com", 443).unwrap();

        // 1. Clean 0-byte EOF before salt -> Ok(0)
        let (c_io, s_io) = tokio::io::duplex(1024);
        drop(s_io);
        let mut client =
            ShadowsocksStream::new_client(c_io, kind, master_key.clone(), &target).unwrap();
        let mut out = Vec::new();
        assert_eq!(client.read_to_end(&mut out).await.unwrap(), 0);
        assert!(out.is_empty());

        // 2. Truncated salt / partial frame before EOF -> UnexpectedEof
        let (c_io2, mut s_io2) = tokio::io::duplex(1024);
        s_io2.write_all(&[0xAA; 10]).await.unwrap();
        drop(s_io2);
        let mut client2 =
            ShadowsocksStream::new_client(c_io2, kind, master_key.clone(), &target).unwrap();
        let err = client2.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // 3. Truncated payload chunk after valid salt + encrypted length chunk -> UnexpectedEof
        let (c_io3, mut s_io3) = tokio::io::duplex(1024);
        let resp_salt = random_bytes(kind.salt_len()).unwrap();
        let mut enc = SsAeadCipher::new(kind, &master_key, &resp_salt).unwrap();
        let enc_len = enc.seal(&5u16.to_be_bytes()).unwrap();
        s_io3.write_all(&resp_salt).await.unwrap();
        s_io3.write_all(&enc_len).await.unwrap();
        drop(s_io3);
        let mut client3 = ShadowsocksStream::new_client(c_io3, kind, master_key, &target).unwrap();
        let err3 = client3.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn shadowsocks_stream_flushes_initial_header_on_read_for_server_speaks_first() {
        for kind in [SsCipherKind::Aes256Gcm, SsCipherKind::Ss2022Blake3Aes256Gcm] {
            let master_key = Zeroizing::new(vec![0x37u8; kind.key_len()]);
            let target = TargetAddr::new_domain("ssh.example.com", 22).unwrap();
            let expected_target = target.clone();
            let mk_srv = master_key.clone();

            let (c_io, s_io) = tokio::io::duplex(512);
            let mut client = ShadowsocksStream::new_client(
                ThrottledStream::new(c_io, 5),
                kind,
                master_key,
                &target,
            )
            .unwrap();

            let srv_task = tokio::spawn(async move {
                let (got_target, mut srv) = accept_mock_ss_server(s_io, kind, mk_srv)
                    .await
                    .expect("accept ss");
                assert_eq!(got_target, expected_target);
                srv.write_all(b"SSH-2.0-OpenSSH_9.9\r\n")
                    .await
                    .expect("srv write banner");
                srv.flush().await.expect("srv flush");
                let mut client_ident = [0u8; 21];
                srv.read_exact(&mut client_ident)
                    .await
                    .expect("srv read client ident");
                assert_eq!(&client_ident, b"SSH-2.0-RustClash_1\r\n");
            });

            let mut banner = [0u8; 21];
            client
                .read_exact(&mut banner)
                .await
                .expect("client read banner before any write");
            assert_eq!(&banner, b"SSH-2.0-OpenSSH_9.9\r\n");
            client
                .write_all(b"SSH-2.0-RustClash_1\r\n")
                .await
                .expect("client write after banner");
            client.flush().await.expect("client flush");
            srv_task.await.expect("srv join");
        }
    }

    #[tokio::test]
    async fn shadowsocks_stream_no_duplication_on_interleaved_pending_write_read_and_flush() {
        let kind = SsCipherKind::Ss2022Blake3Aes256Gcm;
        let master_key = Zeroizing::new(vec![0x5Bu8; kind.key_len()]);
        let target = TargetAddr::new_domain("echo.example.com", 443).unwrap();

        // Part A: `poll_write` returns `Pending`, then `flush()` drains `write_buf`,
        // then retrying `write_all(payload)` must NOT encrypt & transmit `payload` a second time.
        let (c_io, s_io) = tokio::io::duplex(8192);
        let mut client = ShadowsocksStream::new_client(
            ThrottledStream::new(c_io, 3),
            kind,
            master_key.clone(),
            &target,
        )
        .unwrap();
        let mk_srv = master_key.clone();
        let payload: Vec<u8> = (0..600).map(|i| (i * 11 + 5) as u8).collect();

        let srv_task = tokio::spawn(async move {
            let (_t, mut srv) = accept_mock_ss_server(s_io, kind, mk_srv).await.unwrap();
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

        let got_plain = srv_task.await.unwrap();
        assert_eq!(got_plain, payload, "SS-2022 payload must not be duplicated");

        // Part B: `copy_bidirectional` over 1-byte throttled stream (interleaving `poll_write` + `poll_read`).
        let (c_io2, s_io2) = tokio::io::duplex(256);
        let mut ss_client = ShadowsocksStream::new_client(
            ThrottledStream::new(c_io2, 1),
            kind,
            master_key.clone(),
            &target,
        )
        .unwrap();
        let (mut app_side, mut proxy_in) = tokio::io::duplex(256);

        let client_data: Vec<u8> = (0..1500).map(|i| (i ^ 0x3C) as u8).collect();
        let server_data: Vec<u8> = (0..1200).map(|i| (i * 19 + 7) as u8).collect();
        let server_data_expect = server_data.clone();
        let mk_srv2 = master_key;

        let relay_task = tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut proxy_in, &mut ss_client)
                .await
                .expect("copy_bidirectional")
        });

        let srv_task2 = tokio::spawn(async move {
            let (_t, srv) = accept_mock_ss_server(s_io2, kind, mk_srv2).await.unwrap();
            let (mut srd, mut swr) = tokio::io::split(srv);
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
    async fn shadowsocks_stream_cancelled_large_write_then_small_write_does_not_panic() {
        let kind = SsCipherKind::Aes256Gcm;
        let master_key = kind.master_key("cancel-test-pass").unwrap();
        let target = TargetAddr::new_domain("example.com", 80).unwrap();
        let mk_srv = master_key.clone();

        let (c_io, s_io) = tokio::io::duplex(8192);
        let mut client =
            ShadowsocksStream::new_client(ThrottledStream::new(c_io, 4), kind, master_key, &target)
                .unwrap();

        let srv_task = tokio::spawn(async move {
            let (_t, mut srv) = accept_mock_ss_server(s_io, kind, mk_srv).await.unwrap();
            let mut got = Vec::new();
            srv.read_to_end(&mut got).await.unwrap();
            got
        });

        let large_buf = vec![0xE1u8; 1024];
        let small_buf = vec![0xF2u8; 15];
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
