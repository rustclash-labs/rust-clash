use std::{collections::HashMap, io};

use bytes::{Buf, BufMut, BytesMut};
use md5::{Digest, Md5};
use rand::Rng;

use crate::outbound::anytls::frame::{Command, FRAME_HEADER_LEN};

pub const DEFAULT_PADDING_SCHEME: &str = "\
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingToken {
    /// Target plaintext length range `[min, max]` for a single TLS write.
    Range { min: u16, max: u16 },
    /// `'c'` checkpoint: if user frame data is already completely drained, stop emitting further chunks.
    CheckStop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaddingScheme {
    raw: String,
    md5_hex: String,
    pub stop: u32,
    rules: HashMap<u32, Vec<PaddingToken>>,
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME).expect("valid default AnyTLS padding scheme")
    }
}

impl PaddingScheme {
    pub fn parse(raw_text: &str) -> io::Result<Self> {
        let normalized = raw_text.trim();
        let mut hasher = Md5::new();
        hasher.update(normalized.as_bytes());
        let md5_hex = hex::encode(hasher.finalize());

        let mut stop = 8u32;
        let mut rules: HashMap<u32, Vec<PaddingToken>> = HashMap::new();

        for line in normalized.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, val) = line.split_once('=').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid paddingScheme line '{line}'"),
                )
            })?;
            let key = key.trim();
            let val = val.trim();
            if key == "stop" {
                stop = val.parse::<u32>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("invalid stop '{val}'"))
                })?;
                continue;
            }
            let pkt_idx = key.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid packet index '{key}'"),
                )
            })?;
            let mut tokens = Vec::new();
            for part in val.split(',') {
                let part = part.trim();
                if part == "c" {
                    tokens.push(PaddingToken::CheckStop);
                } else if let Some((min_s, max_s)) = part.split_once('-') {
                    let min = min_s.trim().parse::<u16>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid min in range")
                    })?;
                    let max = max_s.trim().parse::<u16>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid max in range")
                    })?;
                    if min > max {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("padding range min ({min}) > max ({max})"),
                        ));
                    }
                    tokens.push(PaddingToken::Range { min, max });
                } else {
                    let exact = part.parse::<u16>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid padding token '{part}'"),
                        )
                    })?;
                    tokens.push(PaddingToken::Range {
                        min: exact,
                        max: exact,
                    });
                }
            }
            rules.insert(pkt_idx, tokens);
        }

        Ok(Self {
            raw: normalized.to_string(),
            md5_hex,
            stop,
            rules,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn md5_hex(&self) -> &str {
        &self.md5_hex
    }

    /// Sample `padding0` byte length for the initial SHA-256 auth packet (`0=...`).
    pub fn sample_padding0_len(&self) -> u16 {
        if let Some(tokens) = self.rules.get(&0) {
            for tok in tokens {
                if let PaddingToken::Range { min, max } = *tok {
                    return sample_range(min, max);
                }
            }
        }
        0
    }

    /// Shape an outbound buffer (consisting of complete 7-byte-framed AnyTLS frames)
    /// into one or more TLS write chunks according to packet counter `pkt_idx`.
    /// Updates `pkt_idx` by the number of TLS records produced (or 1 logical step per AnyTLS spec).
    pub fn shape_tls_writes(&self, pkt_idx: &mut u32, mut payload: BytesMut) -> Vec<Vec<u8>> {
        if payload.is_empty() {
            return Vec::new();
        }
        if *pkt_idx >= self.stop {
            *pkt_idx = pkt_idx.saturating_add(1);
            return vec![payload.to_vec()];
        }

        let current_pkt = *pkt_idx;
        *pkt_idx = pkt_idx.saturating_add(1);

        let Some(tokens) = self.rules.get(&current_pkt) else {
            return vec![payload.to_vec()];
        };

        let mut writes: Vec<Vec<u8>> = Vec::new();
        for tok in tokens {
            match *tok {
                PaddingToken::CheckStop => {
                    if payload.is_empty() {
                        break;
                    }
                }
                PaddingToken::Range { min, max } => {
                    let target_len = sample_range(min, max) as usize;
                    if payload.len() >= target_len {
                        let chunk = payload.split_to(target_len);
                        writes.push(chunk.to_vec());
                    } else {
                        // Drain remaining user frames (ending at a valid frame boundary!)
                        // and append a `cmdWaste` frame to reach `target_len` (at least +7B header).
                        let rem = payload.len();
                        let diff = target_len.saturating_sub(rem);
                        let waste_data_len =
                            diff.saturating_sub(FRAME_HEADER_LEN).min(u16::MAX as usize);
                        let mut chunk =
                            BytesMut::with_capacity(rem + FRAME_HEADER_LEN + waste_data_len);
                        if rem > 0 {
                            chunk.put_slice(&payload);
                            payload.advance(rem);
                        }
                        if diff > 0 {
                            chunk.put_u8(Command::Waste as u8);
                            chunk.put_u32(0);
                            chunk.put_u16(waste_data_len as u16);
                            chunk.put_bytes(0, waste_data_len);
                        }
                        if !chunk.is_empty() {
                            writes.push(chunk.to_vec());
                        }
                    }
                }
            }
        }

        // Any remaining user data after all configured split ranges is flushed immediately
        if !payload.is_empty() {
            writes.push(payload.to_vec());
        }

        writes
    }
}

fn sample_range(min: u16, max: u16) -> u16 {
    if min >= max {
        min
    } else {
        rand::rng().random_range(min..=max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::anytls::frame::Frame;

    #[test]
    fn padding_scheme_splits_and_pads_preserving_valid_frame_stream() {
        let scheme = PaddingScheme::default();
        assert_eq!(scheme.sample_padding0_len(), 30);

        // Simulate pkt 1 (100-400) with small 24-byte settings+syn frame buffer
        let mut pkt_idx = 1u32;
        let mut buf = BytesMut::new();
        Frame::new(Command::Settings, 0, &b"v=2"[..])
            .encode_into(&mut buf)
            .unwrap();
        Frame::empty(Command::Syn, 1).encode_into(&mut buf).unwrap();

        let chunks_1 = scheme.shape_tls_writes(&mut pkt_idx, buf);
        assert_eq!(chunks_1.len(), 1);
        assert!(chunks_1[0].len() >= 100 && chunks_1[0].len() <= 400);

        // Simulate pkt 2 (400-500,c,500-1000,c,...) with 650-byte user data frame:
        // Should split into chunk #1 (400..=500), pass 'c' (remaining > 0), chunk #2 (500..=1000 w/ Waste), then hit 'c' (remaining == 0) and stop!
        let mut buf2 = BytesMut::new();
        Frame::new(Command::Psh, 1, vec![0xAB; 650])
            .encode_into(&mut buf2)
            .unwrap();
        let chunks_2 = scheme.shape_tls_writes(&mut pkt_idx, buf2);
        assert_eq!(chunks_2.len(), 2);
        assert!((400..=500).contains(&chunks_2[0].len()));
        assert!((500..=1000).contains(&chunks_2[1].len()));

        // Reassemble all bytes from chunks_2 and verify every frame decodes cleanly!
        let mut reassembled = BytesMut::new();
        for c in chunks_2 {
            reassembled.extend_from_slice(&c);
        }
        let mut decoded = Vec::new();
        while let Some(f) = Frame::try_decode(&mut reassembled).unwrap() {
            decoded.push(f);
        }
        assert!(reassembled.is_empty());
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].cmd, Command::Psh);
        assert_eq!(decoded[0].data.len(), 650);
        assert_eq!(decoded[1].cmd, Command::Waste);
    }
}
