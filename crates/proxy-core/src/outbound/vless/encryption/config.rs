use std::io;

use rand::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XorMode {
    Native = 0,
    XorPub = 1,
    Random = 2,
}

impl XorMode {
    pub fn parse(token: &str) -> io::Result<Self> {
        match token {
            "native" => Ok(Self::Native),
            "xorpub" => Ok(Self::XorPub),
            "random" => Ok(Self::Random),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unknown VLESS encryption mode '{other}' (expected native, xorpub, or random)"
                ),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::XorPub => "xorpub",
            Self::Random => "random",
        }
    }
}

/// Xray-compatible `[prob, min, max]` padding specification (`PaddingLens` & `PaddingGaps`).
#[derive(Clone, Debug)]
pub struct PaddingPolicy {
    pub lens: Vec<[usize; 3]>,
    pub gaps_ms: Vec<[u64; 3]>,
}

impl Default for PaddingPolicy {
    fn default() -> Self {
        Self {
            lens: vec![[100, 111, 1111], [50, 0, 3333]],
            gaps_ms: vec![[75, 0, 111]],
        }
    }
}

impl PaddingPolicy {
    pub fn parse_tokens(tokens: &[&str]) -> io::Result<Self> {
        if tokens.is_empty() {
            return Ok(Self::default());
        }
        let mut lens = Vec::new();
        let mut gaps_ms = Vec::new();
        let mut max_sum = 0usize;

        for (i, tok) in tokens.iter().enumerate() {
            let parts: Vec<&str> = tok.split('-').collect();
            if parts.len() != 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid VLESS padding token '{tok}' (expected prob-min-max)"),
                ));
            }
            let prob: usize = parts[0].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid padding probability")
            })?;
            let min: usize = parts[1]
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid padding min"))?;
            let max: usize = parts[2]
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid padding max"))?;

            if i % 2 == 0 {
                if i == 0 && (prob < 100 || min < 35 || max < 35) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "first VLESS padding length token must satisfy prob>=100, min>=35, max>=35",
                    ));
                }
                max_sum = max_sum.saturating_add(min.max(max));
                lens.push([prob, min, max]);
            } else {
                gaps_ms.push([prob as u64, min as u64, max as u64]);
            }
        }

        if max_sum > 65553 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS max padding length exceeds 65553",
            ));
        }

        Ok(Self { lens, gaps_ms })
    }

    /// Sample concrete `(fragment_lens, gap_millis)` per Xray `CreatPadding`.
    pub fn sample(&self) -> (Vec<usize>, Vec<u64>, usize) {
        let mut sampled_lens = Vec::with_capacity(self.lens.len());
        let mut total_len = 0usize;
        for &[prob, min, max] in &self.lens {
            let r = xray_rand_between_usize(0, 100);
            let l = if prob >= r {
                xray_rand_between_usize(min, max)
            } else {
                0
            };
            sampled_lens.push(l);
            total_len += l;
        }
        if total_len < 35 {
            let boost = 35 - total_len;
            if let Some(first) = sampled_lens.first_mut() {
                *first += boost;
            } else {
                sampled_lens.push(35);
            }
            total_len = 35;
        }

        let mut sampled_gaps = Vec::with_capacity(self.gaps_ms.len());
        for &[prob, min, max] in &self.gaps_ms {
            let r = xray_rand_between_u64(0, 100);
            let g = if prob >= r {
                xray_rand_between_u64(min, max)
            } else {
                0
            };
            sampled_gaps.push(g);
        }

        (sampled_lens, sampled_gaps, total_len)
    }
}

/// Xray `crypto.RandBetween(a, b)`: returns `a` if `b <= a + 1`, else uniform integer in `[a, b)`.
pub fn xray_rand_between_usize(from: usize, to: usize) -> usize {
    if to <= from.saturating_add(1) {
        from
    } else {
        rand::rng().random_range(from..to)
    }
}

pub fn xray_rand_between_u64(from: u64, to: u64) -> u64 {
    if to <= from.saturating_add(1) {
        from
    } else {
        rand::rng().random_range(from..to)
    }
}

#[derive(Clone, Debug)]
pub struct ParsedClientConfig {
    pub mode: XorMode,
    pub enable_0rtt: bool,
    pub padding: PaddingPolicy,
    pub key_tokens: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedServerConfig {
    pub mode: XorMode,
    pub seconds_from: u64,
    pub seconds_to: u64,
    pub padding: PaddingPolicy,
    pub key_tokens: Vec<String>,
}

impl ParsedServerConfig {
    pub fn sample_ticket_seconds(&self) -> u16 {
        if self.seconds_from == 0 && self.seconds_to == 0 {
            return 0;
        }
        let secs = if self.seconds_to == 0 {
            self.seconds_from * xray_rand_between_u64(50, 100) / 100
        } else {
            xray_rand_between_u64(self.seconds_from, self.seconds_to)
        };
        secs.min(u16::MAX as u64) as u16
    }
}

pub fn parse_client_encryption(spec: &str) -> io::Result<ParsedClientConfig> {
    let parts: Vec<&str> = spec.trim().split('.').collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS client encryption must start with 'mlkem768x25519plus.<mode>.<0rtt|1rtt>...'",
        ));
    }
    let mode = XorMode::parse(parts[1])?;
    let enable_0rtt = match parts[2] {
        "0rtt" => true,
        "1rtt" => false,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid VLESS RTT mode '{other}' (expected 0rtt or 1rtt)"),
            ));
        }
    };

    let (pad_tokens, key_tokens) = split_padding_and_keys(&parts[3..])?;
    let padding = PaddingPolicy::parse_tokens(&pad_tokens)?;

    Ok(ParsedClientConfig {
        mode,
        enable_0rtt,
        padding,
        key_tokens,
    })
}

pub fn parse_server_decryption(spec: &str) -> io::Result<ParsedServerConfig> {
    let parts: Vec<&str> = spec.trim().split('.').collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS server decryption must start with 'mlkem768x25519plus.<mode>.<ttl>...'",
        ));
    }
    let mode = XorMode::parse(parts[1])?;
    let ttl_str = parts[2].trim_end_matches('s');
    let (seconds_from, seconds_to) = if let Some((a, b)) = ttl_str.split_once('-') {
        let from: u64 = a.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ticket TTL range start",
            )
        })?;
        let to: u64 = b.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid ticket TTL range end")
        })?;
        (from, to)
    } else {
        let from: u64 = ttl_str
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ticket TTL"))?;
        (from, 0)
    };

    let (pad_tokens, key_tokens) = split_padding_and_keys(&parts[3..])?;
    let padding = PaddingPolicy::parse_tokens(&pad_tokens)?;

    Ok(ParsedServerConfig {
        mode,
        seconds_from,
        seconds_to,
        padding,
        key_tokens,
    })
}

fn split_padding_and_keys<'a>(tail: &[&'a str]) -> io::Result<(Vec<&'a str>, Vec<String>)> {
    let mut first_key_idx = None;
    for (idx, tok) in tail.iter().enumerate() {
        if tok.len() >= 20 {
            first_key_idx = Some(idx);
            break;
        }
    }
    let idx = first_key_idx.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS encryption/decryption string contains no NFS public/private key tokens",
        )
    })?;
    let pad_tokens = tail[..idx].to_vec();
    let mut keys = Vec::with_capacity(tail.len() - idx);
    for tok in &tail[idx..] {
        if tok.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "all VLESS padding tokens (<20 chars) must precede NFS key tokens",
            ));
        }
        keys.push((*tok).to_string());
    }
    Ok((pad_tokens, keys))
}
