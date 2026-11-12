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
    pending_plain_len: usize,

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
            pending_plain_len: 0,
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
            pending_plain_len: 0,
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

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain_in.is_empty() {
                let to_copy = buf.remaining().min(self.plain_in.len());
                buf.put_slice(&self.plain_in.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }

            self.try_decode_frames()?;
            if !self.plain_in.is_empty() {
                continue;
            }

            let mut tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(())); // Clean EOF
                    }
                    self.raw_in.extend_from_slice(filled);
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
                    if this.pending_plain_len > 0 {
                        let done = this.pending_plain_len;
                        this.pending_plain_len = 0;
                        return Poll::Ready(Ok(done));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
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
            Poll::Ready(Ok(())) => Poll::Ready(Ok(consumed_plain)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.pending_plain_len = consumed_plain;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // If a client opened a SS-2022 or Legacy stream and calls flush() before writing user payload
        // (e.g. server-speaks-first protocols), flush the header with mandatory padding!
        if let WritePhase::ClientInitial { .. } = &self.write_phase {
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
                    let mut out_tmp = BytesMut::new();
                    Self::encode_standard_chunk(enc, &target_addr, &mut out_tmp)?;
                    self.write_buf.extend_from_slice(&out_tmp);
                }
            }
        }

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
