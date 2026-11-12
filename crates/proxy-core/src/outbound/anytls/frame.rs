use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_HEADER_LEN: usize = 7;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl Command {
    pub fn from_u8(val: u8) -> io::Result<Self> {
        match val {
            0 => Ok(Self::Waste),
            1 => Ok(Self::Syn),
            2 => Ok(Self::Psh),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Settings),
            5 => Ok(Self::Alert),
            6 => Ok(Self::UpdatePaddingScheme),
            7 => Ok(Self::SynAck),
            8 => Ok(Self::HeartRequest),
            9 => Ok(Self::HeartResponse),
            10 => Ok(Self::ServerSettings),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown AnyTLS frame command: {other}"),
            )),
        }
    }
}

/// AnyTLS v2 7-byte header multiplexed frame:
/// `command (u8) | stream_id (u32 BE) | data_len (u16 BE) | data`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub cmd: Command,
    pub stream_id: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(cmd: Command, stream_id: u32, data: impl Into<Bytes>) -> Self {
        Self {
            cmd,
            stream_id,
            data: data.into(),
        }
    }

    pub fn empty(cmd: Command, stream_id: u32) -> Self {
        Self {
            cmd,
            stream_id,
            data: Bytes::new(),
        }
    }

    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN + self.data.len()
    }

    pub fn encode_into(&self, dst: &mut BytesMut) -> io::Result<()> {
        if self.data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS frame payload exceeds 65535 bytes",
            ));
        }
        dst.reserve(FRAME_HEADER_LEN + self.data.len());
        dst.put_u8(self.cmd as u8);
        dst.put_u32(self.stream_id);
        dst.put_u16(self.data.len() as u16);
        dst.put_slice(&self.data);
        Ok(())
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(self.encoded_len());
        self.encode_into(&mut buf)?;
        Ok(buf.to_vec())
    }

    pub fn try_decode(src: &mut BytesMut) -> io::Result<Option<Self>> {
        if src.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let cmd = Command::from_u8(src[0])?;
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let data_len = u16::from_be_bytes([src[5], src[6]]) as usize;
        if src.len() < FRAME_HEADER_LEN + data_len {
            return Ok(None);
        }
        src.advance(FRAME_HEADER_LEN);
        let data = src.split_to(data_len).freeze();
        Ok(Some(Self {
            cmd,
            stream_id,
            data,
        }))
    }

    pub async fn read_from<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let mut hdr = [0u8; FRAME_HEADER_LEN];
        reader.read_exact(&mut hdr).await?;
        let cmd = Command::from_u8(hdr[0])?;
        let stream_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut data).await?;
        }
        Ok(Self {
            cmd,
            stream_id,
            data: Bytes::from(data),
        })
    }
}
