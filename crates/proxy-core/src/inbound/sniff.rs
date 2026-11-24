use std::net::IpAddr;

use aws_lc_rs::{
    aead::{self, AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
};

pub const MAX_SNIFF_BYTES: usize = 16 * 1024;
const MAX_HTTP_SNIFF_BYTES: usize = 8 * 1024;
const MAX_QUIC_SNIFF_DATAGRAM_BYTES: usize = 16 * 1024;
const MAX_QUIC_COALESCED_PACKETS: usize = 8;
const MAX_QUIC_CRYPTO_RANGES: usize = 64;
const MAX_QUIC_ACK_RANGES: usize = 64;

pub const QUIC_VERSION_1: u32 = 0x0000_0001;
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// RFC 9001 Section 5.2 QUIC v1 Initial salt.
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 Section 3.3.1 QUIC v2 Initial salt.
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedProtocol {
    Tls,
    Http,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcome {
    Domain(String),
    NeedMoreBytes,
    NoHostname,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcomeWithProto {
    Domain {
        domain: String,
        protocol: SniffedProtocol,
    },
    NeedMoreBytes,
    NoHostname,
}

const HTTP_METHOD_PREFIXES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

/// Validate and normalize an extracted hostname (ASCII lowercase, trailing dot stripped).
/// Rejects empty strings, IP literals, single-label names, malformed DNS labels, and all-numeric TLDs.
pub fn normalize_valid_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 || !trimmed.contains('.') {
        return None;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let mut last_label = "";
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return None;
        }
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
        last_label = label;
    }
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(trimmed)
}

/// Inspect leading TCP payload bytes for a TLS `ClientHello` SNI (`server_name` extension)
/// or an HTTP/1.x `Host` header. Immediately returns `NoHostname` for non-TLS/non-HTTP bytes.
pub fn sniff_client_hello_or_http_host(buf: &[u8]) -> SniffOutcome {
    match sniff_tcp_protocol(buf, true, true) {
        SniffOutcomeWithProto::Domain { domain, .. } => SniffOutcome::Domain(domain),
        SniffOutcomeWithProto::NeedMoreBytes => SniffOutcome::NeedMoreBytes,
        SniffOutcomeWithProto::NoHostname => SniffOutcome::NoHostname,
    }
}

/// Protocol-filtered variant of [`sniff_client_hello_or_http_host`] that also reports whether the
/// hostname came from TLS SNI or HTTP `Host`, immediately returning `NoHostname` if the leading
/// bytes cannot match any enabled protocol.
pub fn sniff_tcp_protocol(buf: &[u8], allow_tls: bool, allow_http: bool) -> SniffOutcomeWithProto {
    if !allow_tls && !allow_http {
        return SniffOutcomeWithProto::NoHostname;
    }
    if buf.is_empty() {
        return SniffOutcomeWithProto::NeedMoreBytes;
    }
    if buf[0] == 0x16 {
        if !allow_tls {
            return SniffOutcomeWithProto::NoHostname;
        }
        return match sniff_tls_client_hello(buf) {
            SniffOutcome::Domain(domain) => SniffOutcomeWithProto::Domain {
                domain,
                protocol: SniffedProtocol::Tls,
            },
            SniffOutcome::NeedMoreBytes => SniffOutcomeWithProto::NeedMoreBytes,
            SniffOutcome::NoHostname => SniffOutcomeWithProto::NoHostname,
        };
    }
    if !allow_http {
        return SniffOutcomeWithProto::NoHostname;
    }
    match sniff_http_host(buf) {
        SniffOutcome::Domain(domain) => SniffOutcomeWithProto::Domain {
            domain,
            protocol: SniffedProtocol::Http,
        },
        SniffOutcome::NeedMoreBytes => SniffOutcomeWithProto::NeedMoreBytes,
        SniffOutcome::NoHostname => SniffOutcomeWithProto::NoHostname,
    }
}

fn sniff_tls_client_hello(buf: &[u8]) -> SniffOutcome {
    if buf.len() >= 2 && buf[1] != 0x03 {
        return SniffOutcome::NoHostname;
    }
    if buf.len() >= 3 && buf[2] > 0x04 {
        return SniffOutcome::NoHostname;
    }
    if buf.len() < 5 {
        return SniffOutcome::NeedMoreBytes;
    }

    let mut hs_payload = Vec::new();
    let mut offset = 0usize;
    let mut expected_hs_len: Option<usize> = None;

    while offset < buf.len() {
        if buf[offset] != 0x16 {
            return SniffOutcome::NoHostname;
        }
        if buf.len() - offset < 5 {
            return if buf.len() < MAX_SNIFF_BYTES {
                SniffOutcome::NeedMoreBytes
            } else {
                SniffOutcome::NoHostname
            };
        }
        if buf[offset + 1] != 0x03 || buf[offset + 2] > 0x04 {
            return SniffOutcome::NoHostname;
        }
        let rec_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        if rec_len == 0 || rec_len > MAX_SNIFF_BYTES {
            return SniffOutcome::NoHostname;
        }

        let payload_start = offset + 5;
        let avail = (buf.len() - payload_start).min(rec_len);
        let remaining_cap = MAX_SNIFF_BYTES.saturating_sub(hs_payload.len());
        let take = avail.min(remaining_cap);
        hs_payload.extend_from_slice(&buf[payload_start..payload_start + take]);

        if hs_payload.len() >= 4 {
            if hs_payload[0] != 0x01 {
                return SniffOutcome::NoHostname;
            }
            let hs_len = ((hs_payload[1] as usize) << 16)
                | ((hs_payload[2] as usize) << 8)
                | (hs_payload[3] as usize);
            if !(34..=MAX_SNIFF_BYTES - 4).contains(&hs_len) {
                return SniffOutcome::NoHostname;
            }
            expected_hs_len = Some(hs_len);
            if hs_payload.len() >= 4 + hs_len {
                return parse_client_hello_body(&hs_payload[4..4 + hs_len]);
            }
        }

        if avail < rec_len {
            return if buf.len() < MAX_SNIFF_BYTES {
                SniffOutcome::NeedMoreBytes
            } else {
                SniffOutcome::NoHostname
            };
        }
        offset = payload_start + rec_len;
    }

    if let Some(hs_len) = expected_hs_len
        && hs_payload.len() >= 4 + hs_len
    {
        return parse_client_hello_body(&hs_payload[4..4 + hs_len]);
    }
    if buf.len() < MAX_SNIFF_BYTES {
        SniffOutcome::NeedMoreBytes
    } else {
        SniffOutcome::NoHostname
    }
}

fn parse_client_hello_body(body: &[u8]) -> SniffOutcome {
    parse_client_hello_body_inner(body, false)
}

fn sniff_tls_handshake_client_hello(
    hs_payload: &[u8],
    allow_truncated_after_sni: bool,
) -> SniffOutcome {
    if hs_payload.len() < 4 || hs_payload[0] != 0x01 {
        return SniffOutcome::NoHostname;
    }
    let hs_len = ((hs_payload[1] as usize) << 16)
        | ((hs_payload[2] as usize) << 8)
        | (hs_payload[3] as usize);
    if !(34..=MAX_SNIFF_BYTES - 4).contains(&hs_len) {
        return SniffOutcome::NoHostname;
    }
    if hs_payload.len() >= 4 + hs_len {
        parse_client_hello_body_inner(&hs_payload[4..4 + hs_len], false)
    } else if allow_truncated_after_sni {
        parse_client_hello_body_inner(&hs_payload[4..], true)
    } else {
        SniffOutcome::NeedMoreBytes
    }
}

fn parse_client_hello_body_inner(body: &[u8], allow_truncated_after_sni: bool) -> SniffOutcome {
    // 2B legacy_version + 32B random + at least 1B session_id_len
    if body.len() < 35 {
        return SniffOutcome::NoHostname;
    }
    let mut pos = 34usize;

    let session_id_len = body[pos] as usize;
    pos += 1;
    let Some(next) = pos.checked_add(session_id_len) else {
        return SniffOutcome::NoHostname;
    };
    if next + 2 > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let Some(next) = pos.checked_add(cipher_suites_len) else {
        return SniffOutcome::NoHostname;
    };
    if next + 1 > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    let comp_methods_len = body[pos] as usize;
    pos += 1;
    let Some(next) = pos.checked_add(comp_methods_len) else {
        return SniffOutcome::NoHostname;
    };
    if next > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    if pos == body.len() {
        return SniffOutcome::NoHostname;
    }
    if pos + 2 > body.len() {
        return SniffOutcome::NoHostname;
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let Some(exts_end) = pos.checked_add(exts_len) else {
        return SniffOutcome::NoHostname;
    };
    let effective_exts_end = if exts_end > body.len() {
        if allow_truncated_after_sni {
            body.len()
        } else {
            return SniffOutcome::NoHostname;
        }
    } else {
        exts_end
    };

    let exts = &body[pos..effective_exts_end];
    let mut ext_pos = 0usize;
    while ext_pos + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[ext_pos], exts[ext_pos + 1]]);
        let ext_len = u16::from_be_bytes([exts[ext_pos + 2], exts[ext_pos + 3]]) as usize;
        ext_pos += 4;
        let Some(ext_end) = ext_pos.checked_add(ext_len) else {
            return SniffOutcome::NoHostname;
        };
        if ext_end > exts.len() {
            return SniffOutcome::NoHostname;
        }
        if ext_type == 0x0000 {
            return parse_sni_extension(&exts[ext_pos..ext_end]);
        }
        ext_pos = ext_end;
    }
    SniffOutcome::NoHostname
}

fn parse_sni_extension(ext_data: &[u8]) -> SniffOutcome {
    if ext_data.len() < 2 {
        return SniffOutcome::NoHostname;
    }
    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    if 2 + list_len > ext_data.len() {
        return SniffOutcome::NoHostname;
    }
    let list = &ext_data[2..2 + list_len];
    let mut pos = 0usize;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;
        let Some(name_end) = pos.checked_add(name_len) else {
            return SniffOutcome::NoHostname;
        };
        if name_end > list.len() {
            return SniffOutcome::NoHostname;
        }
        if name_type == 0x00 {
            let Ok(raw) = std::str::from_utf8(&list[pos..name_end]) else {
                return SniffOutcome::NoHostname;
            };
            return normalize_valid_hostname(raw)
                .map(SniffOutcome::Domain)
                .unwrap_or(SniffOutcome::NoHostname);
        }
        pos = name_end;
    }
    SniffOutcome::NoHostname
}

fn sniff_http_host(buf: &[u8]) -> SniffOutcome {
    let slice = &buf[..buf.len().min(MAX_HTTP_SNIFF_BYTES)];
    let full_method_match = HTTP_METHOD_PREFIXES.iter().any(|p| slice.starts_with(p));
    if !full_method_match {
        let partial_match =
            slice.len() < 8 && HTTP_METHOD_PREFIXES.iter().any(|p| p.starts_with(slice));
        return if partial_match {
            SniffOutcome::NeedMoreBytes
        } else {
            SniffOutcome::NoHostname
        };
    }

    let mut pos = 0usize;
    let mut line_idx = 0usize;
    while pos < slice.len() {
        let Some(rel_nl) = slice[pos..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let line_bytes = &slice[pos..pos + rel_nl];
        let trimmed_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        if line_idx > 0 {
            if trimmed_bytes.is_empty() {
                return SniffOutcome::NoHostname;
            }
            if trimmed_bytes.len() >= 5
                && trimmed_bytes[..5].eq_ignore_ascii_case(b"host:")
                && let Ok(host_val) = std::str::from_utf8(&trimmed_bytes[5..])
            {
                let host_only = strip_optional_port(host_val.trim());
                return host_only
                    .and_then(normalize_valid_hostname)
                    .map(SniffOutcome::Domain)
                    .unwrap_or(SniffOutcome::NoHostname);
            }
        }
        line_idx += 1;
        pos += rel_nl + 1;
    }

    if buf.len() < MAX_HTTP_SNIFF_BYTES {
        SniffOutcome::NeedMoreBytes
    } else {
        SniffOutcome::NoHostname
    }
}

fn strip_optional_port(raw_host: &str) -> Option<&str> {
    if raw_host.starts_with('[') || raw_host.contains(']') {
        return None;
    }
    match raw_host.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || port.contains(':') || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(host)
        }
        None => Some(raw_host),
    }
}

struct QuicHkdfLen(usize);

impl hkdf::KeyType for QuicHkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

struct QuicInitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Option<()> {
    let full_label_len = 6usize.checked_add(label.len())?;
    if full_label_len > 255 || out.len() > u16::MAX as usize {
        return None;
    }
    let len_be = (out.len() as u16).to_be_bytes();
    let label_len = [full_label_len as u8];
    let context_len = [0u8];
    let info: [&[u8]; 5] = [&len_be, &label_len, b"tls13 ", label, &context_len];
    let okm = prk.expand(&info, QuicHkdfLen(out.len())).ok()?;
    okm.fill(out).ok()
}

fn derive_quic_client_initial_keys(version: u32, dcid: &[u8]) -> Option<QuicInitialKeys> {
    let (salt_bytes, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
        QUIC_VERSION_1 => (&QUIC_V1_INITIAL_SALT, b"quic key", b"quic iv", b"quic hp"),
        QUIC_VERSION_2 => (
            &QUIC_V2_INITIAL_SALT,
            b"quicv2 key",
            b"quicv2 iv",
            b"quicv2 hp",
        ),
        _ => return None,
    };

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
    let initial_secret = salt.extract(dcid);

    let mut client_initial_secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, b"client in", &mut client_initial_secret)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_initial_secret);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&client_prk, key_label, &mut key)?;
    hkdf_expand_label(&client_prk, iv_label, &mut iv)?;
    hkdf_expand_label(&client_prk, hp_label, &mut hp)?;

    Some(QuicInitialKeys { key, iv, hp })
}

fn read_quic_varint(buf: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    let end = pos.checked_add(len)?;
    let bytes = buf.get(*pos..end)?;
    *pos = end;
    let mut val = (first & 0x3f) as u64;
    for &b in &bytes[1..] {
        val = (val << 8) | (b as u64);
    }
    usize::try_from(val).ok()
}

#[derive(Default)]
struct CryptoFrameReassembler {
    buf: Vec<u8>,
    /// Sorted, merged, non-overlapping written intervals `[start, end)`.
    ranges: Vec<(usize, usize)>,
}

impl CryptoFrameReassembler {
    fn insert(&mut self, offset: usize, data: &[u8]) {
        if data.is_empty() || offset >= MAX_SNIFF_BYTES {
            return;
        }
        let take = data.len().min(MAX_SNIFF_BYTES - offset);
        let end = offset + take;
        if self.ranges.len() >= MAX_QUIC_CRYPTO_RANGES
            && !self.ranges.iter().any(|&(s, e)| offset <= e && end >= s)
        {
            return;
        }
        if end > self.buf.len() {
            self.buf.resize(end, 0);
        }
        self.buf[offset..end].copy_from_slice(&data[..take]);

        self.ranges.push((offset, end));
        self.ranges.sort_unstable_by_key(|&(s, e)| (s, e));
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for (s, e) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && s <= last.1
            {
                last.1 = last.1.max(e);
                continue;
            }
            merged.push((s, e));
        }
        self.ranges = merged;
    }

    fn contiguous_prefix(&self) -> &[u8] {
        match self.ranges.first() {
            Some(&(0, end)) => &self.buf[..end],
            _ => &[],
        }
    }
}

fn decrypt_quic_initial_packet(
    version: u32,
    dcid: &[u8],
    pkt: &[u8],
    pn_offset: usize,
) -> Option<Vec<u8>> {
    // RFC 9001 Section 5.4.2: header protection sample starts at `pn_offset + 4` and is 16B long.
    let sample_start = pn_offset.checked_add(4)?;
    let sample_end = sample_start.checked_add(16)?;
    let sample = pkt.get(sample_start..sample_end)?;

    let keys = derive_quic_client_initial_keys(version, dcid)?;
    let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.hp).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    let unmasked_first = pkt[0] ^ (mask[0] & 0x0f);
    let pn_len = ((unmasked_first & 0x03) as usize) + 1;
    let payload_start = pn_offset.checked_add(pn_len)?;
    if payload_start.checked_add(16)? > pkt.len() {
        return None;
    }

    let mut header = pkt[..payload_start].to_vec();
    header[0] = unmasked_first;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let b = header[pn_offset + i] ^ mask[1 + i];
        header[pn_offset + i] = b;
        pn = (pn << 8) | (b as u64);
    }

    let mut nonce_bytes = keys.iv;
    let pn_be = pn.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }

    let aead_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).ok()?);
    let mut in_out = pkt[payload_start..].to_vec();
    let plaintext = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(header.as_slice()),
            &mut in_out,
        )
        .ok()?;
    let plaintext_len = plaintext.len();
    in_out.truncate(plaintext_len);
    Some(in_out)
}

fn extract_quic_crypto_frames(plaintext: &[u8], reassembler: &mut CryptoFrameReassembler) {
    let mut pos = 0usize;
    while pos < plaintext.len() {
        let frame_type = plaintext[pos];
        pos += 1;
        match frame_type {
            // PADDING (0x00) & PING (0x01)
            0x00 => {
                while pos < plaintext.len() && plaintext[pos] == 0x00 {
                    pos += 1;
                }
            }
            0x01 => {}
            // ACK (0x02) & ACK_ECN (0x03)
            0x02 | 0x03 => {
                let Some(_) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                }; // largest_acked
                let Some(_) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                }; // ack_delay
                let Some(range_count) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                };
                if range_count > MAX_QUIC_ACK_RANGES {
                    break;
                }
                let Some(_) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                }; // first_ack_range
                let mut ok = true;
                for _ in 0..range_count {
                    if read_quic_varint(plaintext, &mut pos).is_none()
                        || read_quic_varint(plaintext, &mut pos).is_none()
                    {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                if frame_type == 0x03
                    && (read_quic_varint(plaintext, &mut pos).is_none()
                        || read_quic_varint(plaintext, &mut pos).is_none()
                        || read_quic_varint(plaintext, &mut pos).is_none())
                {
                    break;
                }
            }
            // CRYPTO (0x06)
            0x06 => {
                let Some(offset) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                };
                let Some(len) = read_quic_varint(plaintext, &mut pos) else {
                    break;
                };
                let Some(end) = pos.checked_add(len) else {
                    break;
                };
                if end > plaintext.len() {
                    break;
                }
                reassembler.insert(offset, &plaintext[pos..end]);
                pos = end;
            }
            // CONNECTION_CLOSE (0x1c / 0x1d) or any unexpected frame terminates Initial frame scan.
            _ => break,
        }
    }
}

/// Inspect a single UDP datagram for a QUIC v1 (RFC 9001) or QUIC v2 (RFC 9369) Client Initial
/// packet, decrypt its AES-128-GCM Initial payload, reassemble `CRYPTO` frames, and extract the
/// TLS `ClientHello` SNI (`server_name` extension).
///
/// Strictly bounds-checked against malformed/oversized datagrams; non-Initial packets or failed
/// decryptions immediately return [`SniffOutcome::NoHostname`] with zero buffering delay.
pub fn sniff_quic_initial_sni(pkt: &[u8]) -> SniffOutcome {
    if pkt.len() < 29 || pkt.len() > MAX_QUIC_SNIFF_DATAGRAM_BYTES {
        return SniffOutcome::NoHostname;
    }

    let mut reassembler = CryptoFrameReassembler::default();
    let mut cursor = 0usize;

    for _ in 0..MAX_QUIC_COALESCED_PACKETS {
        if cursor >= pkt.len() || pkt.len() - cursor < 6 {
            break;
        }
        let b0 = pkt[cursor];
        // Require Long Header (0x80) and Fixed Bit (0x40).
        if (b0 & 0xc0) != 0xc0 {
            break;
        }
        let version = u32::from_be_bytes([
            pkt[cursor + 1],
            pkt[cursor + 2],
            pkt[cursor + 3],
            pkt[cursor + 4],
        ]);
        let (initial_type, retry_type) = match version {
            QUIC_VERSION_1 => (0b00u8, 0b11u8),
            QUIC_VERSION_2 => (0b01u8, 0b00u8),
            _ => break,
        };
        let pkt_type = (b0 >> 4) & 0x03;

        let mut pos = cursor + 5;
        let Some(&dcid_len_u8) = pkt.get(pos) else {
            break;
        };
        pos += 1;
        let dcid_len = dcid_len_u8 as usize;
        if dcid_len > 20 {
            break;
        }
        let Some(dcid_end) = pos.checked_add(dcid_len) else {
            break;
        };
        let Some(dcid) = pkt.get(pos..dcid_end) else {
            break;
        };
        pos = dcid_end;

        let Some(&scid_len_u8) = pkt.get(pos) else {
            break;
        };
        pos += 1;
        let scid_len = scid_len_u8 as usize;
        if scid_len > 20 {
            break;
        }
        let Some(scid_end) = pos.checked_add(scid_len) else {
            break;
        };
        if scid_end > pkt.len() {
            break;
        }
        pos = scid_end;

        if pkt_type == retry_type {
            break;
        }
        if pkt_type != initial_type {
            // Non-Initial coalesced long-header packet (0-RTT or Handshake): skip via Length varint.
            let Some(other_len) = read_quic_varint(pkt, &mut pos) else {
                break;
            };
            let Some(next_cursor) = pos.checked_add(other_len) else {
                break;
            };
            if next_cursor > pkt.len() {
                break;
            }
            cursor = next_cursor;
            continue;
        }

        let Some(token_len) = read_quic_varint(pkt, &mut pos) else {
            break;
        };
        let Some(after_token) = pos.checked_add(token_len) else {
            break;
        };
        if after_token > pkt.len() {
            break;
        }
        pos = after_token;

        let Some(payload_len) = read_quic_varint(pkt, &mut pos) else {
            break;
        };
        if payload_len < 20 {
            break;
        }
        let Some(pkt_end) = pos.checked_add(payload_len) else {
            break;
        };
        if pkt_end > pkt.len() {
            break;
        }

        let single_pkt = &pkt[cursor..pkt_end];
        let rel_pn_offset = pos - cursor;
        if let Some(plaintext) =
            decrypt_quic_initial_packet(version, dcid, single_pkt, rel_pn_offset)
        {
            extract_quic_crypto_frames(&plaintext, &mut reassembler);
            let prefix = reassembler.contiguous_prefix();
            if let SniffOutcome::Domain(domain) = sniff_tls_handshake_client_hello(prefix, true) {
                return SniffOutcome::Domain(domain);
            }
        } else {
            return SniffOutcome::NoHostname;
        }
        cursor = pkt_end;
    }

    SniffOutcome::NoHostname
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    fn push_quic_varint(out: &mut Vec<u8>, val: usize) {
        if val < (1 << 6) {
            out.push(val as u8);
        } else if val < (1 << 14) {
            let v = (val as u16) | 0x4000;
            out.extend_from_slice(&v.to_be_bytes());
        } else if val < (1 << 30) {
            let v = (val as u32) | 0x8000_0000;
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            let v = (val as u64) | 0xc000_0000_0000_0000;
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut ext_sni = Vec::new();
        let name_bytes = sni.as_bytes();
        let list_len = 1 + 2 + name_bytes.len();
        ext_sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name_bytes);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0x00); // session id len = 0
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // compression len = 1
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    /// Build a realistic Chrome post-quantum (`X25519MLKEM768` / ECH-sized) TLS `ClientHello`
    /// (~2060B total) where a large `key_share` (`0x0033`) extension precedes the `server_name`
    /// (`0x0000`) extension so the SNI sits beyond the first 1460B TCP MSS segment!
    pub fn build_pq_tls_client_hello(sni: &str, key_share_len: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        // Leading `key_share` extension (simulating 1216B+ ML-KEM-768 + X25519 share + padding)
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        exts.resize(exts.len() + key_share_len, 0x5A);

        // Trailing `server_name` (SNI) extension past byte 1460!
        let name_bytes = sni.as_bytes();
        let list_len = 1 + 2 + name_bytes.len();
        let mut ext_sni = Vec::with_capacity(2 + list_len);
        ext_sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name_bytes);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBB; 32]);
        body.push(32); // 32B TLS 1.3 legacy session id
        body.extend_from_slice(&[0xCC; 32]);
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::with_capacity(5 + hs.len());
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    /// Encrypt arbitrary QUIC Initial frames into a valid RFC 9001 (v1) or RFC 9369 (v2)
    /// Client Initial packet padded to at least `min_total_len` bytes (typically 1200B).
    #[allow(clippy::too_many_arguments)]
    pub fn build_quic_initial_packet_from_frames(
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        token: &[u8],
        packet_number: u32,
        pn_len: usize,
        frames: &[u8],
        min_total_len: usize,
    ) -> Vec<u8> {
        assert!((1..=4).contains(&pn_len));
        let keys = derive_quic_client_initial_keys(version, dcid).expect("supported QUIC version");
        let pkt_type_bits: u8 = match version {
            QUIC_VERSION_1 => 0b00,
            QUIC_VERSION_2 => 0b01,
            _ => panic!("unsupported test QUIC version"),
        };
        let first_byte = 0xc0 | (pkt_type_bits << 4) | ((pn_len as u8) - 1);

        let mut header_prefix = Vec::new();
        header_prefix.push(first_byte);
        header_prefix.extend_from_slice(&version.to_be_bytes());
        header_prefix.push(dcid.len() as u8);
        header_prefix.extend_from_slice(dcid);
        header_prefix.push(scid.len() as u8);
        header_prefix.extend_from_slice(scid);
        push_quic_varint(&mut header_prefix, token.len());
        header_prefix.extend_from_slice(token);

        let mut plaintext = frames.to_vec();
        // Ensure sample (at pn_offset + 4, 16 bytes) fits inside ciphertext + 16B tag.
        let min_pt_for_sample = 4usize.saturating_sub(pn_len);
        if plaintext.len() < min_pt_for_sample {
            plaintext.resize(min_pt_for_sample, 0x00);
        }
        // Pad to RFC 9000 >= 1200B client Initial size when requested.
        let estimated_len_field = 2usize;
        let overhead = header_prefix.len() + estimated_len_field + pn_len + 16;
        if overhead + plaintext.len() < min_total_len {
            plaintext.resize(min_total_len - overhead, 0x00);
        }

        let payload_len = pn_len + plaintext.len() + 16;
        let mut header = header_prefix;
        push_quic_varint(&mut header, payload_len);
        let pn_offset = header.len();
        let pn_be_all = packet_number.to_be_bytes();
        header.extend_from_slice(&pn_be_all[4 - pn_len..4]);

        let mut nonce_bytes = keys.iv;
        let pn64 = (packet_number as u64).to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= pn64[i];
        }

        let aead_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).unwrap());
        let mut ciphertext = plaintext;
        aead_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(header.as_slice()),
                &mut ciphertext,
            )
            .unwrap();

        let sample_rel = 4 - pn_len;
        let sample = &ciphertext[sample_rel..sample_rel + 16];
        let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.hp).unwrap();
        let mask = hp_key.new_mask(sample).unwrap();

        header[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[1 + i];
        }

        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Build a standard encrypted QUIC v1/v2 Client Initial packet carrying a TLS `ClientHello` SNI
    /// inside a `CRYPTO` frame (padded to 1200B).
    pub fn build_quic_initial_packet(version: u32, dcid: &[u8], sni: &str) -> Vec<u8> {
        let tls_record = build_tls_client_hello(sni);
        let client_hello_hs = &tls_record[5..];
        let mut frames = Vec::new();
        frames.push(0x06); // CRYPTO
        push_quic_varint(&mut frames, 0); // offset = 0
        push_quic_varint(&mut frames, client_hello_hs.len());
        frames.extend_from_slice(client_hello_hs);
        build_quic_initial_packet_from_frames(
            version,
            dcid,
            b"\x01\x02\x03\x04",
            &[],
            0,
            2,
            &frames,
            1200,
        )
    }

    /// Build a QUIC Initial packet whose TLS `ClientHello` is split across two out-of-order `CRYPTO`
    /// frames separated by `PING` and `PADDING` frames.
    pub fn build_quic_initial_packet_out_of_order_crypto(
        version: u32,
        dcid: &[u8],
        sni: &str,
    ) -> Vec<u8> {
        let tls_record = build_tls_client_hello(sni);
        let hs = &tls_record[5..];
        let split = hs.len() / 2;

        let mut frames = Vec::new();
        frames.push(0x01); // PING
        // Second half first (offset = split)
        frames.push(0x06);
        push_quic_varint(&mut frames, split);
        push_quic_varint(&mut frames, hs.len() - split);
        frames.extend_from_slice(&hs[split..]);
        frames.extend_from_slice(&[0x00, 0x00, 0x00]); // PADDING
        // First half second (offset = 0)
        frames.push(0x06);
        push_quic_varint(&mut frames, 0);
        push_quic_varint(&mut frames, split);
        frames.extend_from_slice(&hs[..split]);

        build_quic_initial_packet_from_frames(version, dcid, &[], b"retry-tok", 7, 4, &frames, 1200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_tls_sni_single_and_split_records() {
        let record = test_helpers::build_tls_client_hello("API.GitHub.COM");
        assert_eq!(
            sniff_client_hello_or_http_host(&record),
            SniffOutcome::Domain("api.github.com".to_string())
        );

        // Partial chunk asks for more bytes, never false-fails
        let split = record.len() / 2;
        assert_eq!(
            sniff_client_hello_or_http_host(&record[..split]),
            SniffOutcome::NeedMoreBytes
        );

        // Split the inner ClientHello handshake bytes across two separate TLS 0x16 records
        let hs = &record[5..];
        let hs_split = hs.len() / 2;
        let mut two_records = Vec::new();
        two_records.push(0x16);
        two_records.extend_from_slice(&[0x03, 0x01]);
        two_records.extend_from_slice(&(hs_split as u16).to_be_bytes());
        two_records.extend_from_slice(&hs[..hs_split]);
        two_records.push(0x16);
        two_records.extend_from_slice(&[0x03, 0x03]);
        two_records.extend_from_slice(&((hs.len() - hs_split) as u16).to_be_bytes());
        two_records.extend_from_slice(&hs[hs_split..]);

        assert_eq!(
            sniff_client_hello_or_http_host(&two_records),
            SniffOutcome::Domain("api.github.com".to_string())
        );

        // Chrome ~2060B PQ ClientHello split across 1460B + remainder TCP segments
        let pq_hello = test_helpers::build_pq_tls_client_hello("linux.do", 1950);
        assert!(pq_hello.len() > 2000 && pq_hello.len() < 2200);
        assert_eq!(
            sniff_tcp_protocol(&pq_hello[..1460], true, false),
            SniffOutcomeWithProto::NeedMoreBytes
        );
        assert_eq!(
            sniff_tcp_protocol(&pq_hello, true, false),
            SniffOutcomeWithProto::Domain {
                domain: "linux.do".to_string(),
                protocol: SniffedProtocol::Tls,
            }
        );
    }

    #[test]
    fn sniffs_http_host_with_optional_port_and_rejects_ip_or_binary() {
        let req = b"GET /v1/ping HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(req),
            SniffOutcome::Domain("example.com".to_string())
        );

        // Partial HTTP prefix waits for more bytes
        assert_eq!(
            sniff_client_hello_or_http_host(b"GET"),
            SniffOutcome::NeedMoreBytes
        );
        assert_eq!(
            sniff_client_hello_or_http_host(b"GET / HTTP/1.1\r\nHost: example"),
            SniffOutcome::NeedMoreBytes
        );

        // IP literal in HTTP Host header is rejected
        let ip_host = b"GET / HTTP/1.1\r\nHost: 198.18.1.252:443\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(ip_host),
            SniffOutcome::NoHostname
        );

        // Arbitrary binary SSH/non-TLS bytes fail immediately on first chunk
        assert_eq!(
            sniff_client_hello_or_http_host(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SniffOutcome::NoHostname
        );
        assert_eq!(
            sniff_client_hello_or_http_host(&[0x00, 0x01, 0x02, 0x03]),
            SniffOutcome::NoHostname
        );
    }

    #[test]
    fn quic_initial_key_derivation_matches_rfc_9001_appendix_a1() {
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let keys = derive_quic_client_initial_keys(QUIC_VERSION_1, &dcid).unwrap();
        assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn sniffs_quic_v1_and_v2_initial_sni_including_out_of_order_and_truncated_pq() {
        let dcid = hex::decode("8394c8f03e515708").unwrap();

        // 1. Standard QUIC v1 Initial packet
        let v1_pkt =
            test_helpers::build_quic_initial_packet(QUIC_VERSION_1, &dcid, "WWW.Google.COM");
        assert!(v1_pkt.len() >= 1200);
        assert_eq!(
            sniff_quic_initial_sni(&v1_pkt),
            SniffOutcome::Domain("www.google.com".to_string())
        );

        // 2. Standard QUIC v2 (RFC 9369) Initial packet
        let v2_pkt =
            test_helpers::build_quic_initial_packet(QUIC_VERSION_2, &dcid, "cloudflare.com");
        assert_eq!(
            sniff_quic_initial_sni(&v2_pkt),
            SniffOutcome::Domain("cloudflare.com".to_string())
        );

        // 3. Out-of-order CRYPTO frames + Retry token + 4-byte packet number + PING/PADDING
        let ooo_pkt = test_helpers::build_quic_initial_packet_out_of_order_crypto(
            QUIC_VERSION_1,
            &dcid,
            "api.openai.com",
        );
        assert_eq!(
            sniff_quic_initial_sni(&ooo_pkt),
            SniffOutcome::Domain("api.openai.com".to_string())
        );

        // 4. First datagram of a multi-packet PQ QUIC ClientHello where SNI precedes a large
        //    truncated `key_share` extension (mimics Chrome ML-KEM-768 HTTP/3 Initial #1).
        let base_sni = test_helpers::build_tls_client_hello("gemini.google.com");
        // Construct a ClientHello with SNI first, followed by a 1500B key_share, then slice at 1100B!
        let mut exts = Vec::new();
        let name = b"gemini.google.com";
        let list_len = (1 + 2 + name.len()) as u16;
        let mut ext_sni = Vec::new();
        ext_sni.extend_from_slice(&list_len.to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&1500u16.to_be_bytes());
        exts.resize(exts.len() + 1500, 0x5A);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);
        assert!(hs.len() > 1500 && !base_sni.is_empty());

        let first_slice = &hs[..1100];
        let mut pq_frames = Vec::new();
        pq_frames.push(0x06);
        pq_frames.push(0x00); // offset = 0
        pq_frames.extend_from_slice(&(((first_slice.len() as u16) | 0x4000).to_be_bytes()));
        pq_frames.extend_from_slice(first_slice);
        let pq_pkt = test_helpers::build_quic_initial_packet_from_frames(
            QUIC_VERSION_1,
            &dcid,
            &[],
            &[],
            0,
            1,
            &pq_frames,
            1200,
        );
        assert_eq!(
            sniff_quic_initial_sni(&pq_pkt),
            SniffOutcome::Domain("gemini.google.com".to_string())
        );
    }

    #[test]
    fn quic_sniffer_rejects_malformed_non_initial_corrupted_and_oversized_packets_without_panic() {
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let valid = test_helpers::build_quic_initial_packet(QUIC_VERSION_1, &dcid, "example.com");

        // 1. Short header (1-RTT) packet
        let mut short_hdr = valid.clone();
        short_hdr[0] &= 0x7f;
        assert_eq!(sniff_quic_initial_sni(&short_hdr), SniffOutcome::NoHostname);

        // 2. Non-Initial long header (Handshake packet type 0b10 in v1)
        let mut hs_pkt = valid.clone();
        hs_pkt[0] = (hs_pkt[0] & 0xcf) | (0b10 << 4);
        assert_eq!(sniff_quic_initial_sni(&hs_pkt), SniffOutcome::NoHostname);

        // 3. Corrupted AEAD tag / tampered ciphertext
        let mut tampered = valid.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(sniff_quic_initial_sni(&tampered), SniffOutcome::NoHostname);

        // 4. Truncated at every prefix boundary -> must NEVER panic
        for cut in 0..valid.len().min(96) {
            assert_eq!(
                sniff_quic_initial_sni(&valid[..cut]),
                SniffOutcome::NoHostname
            );
        }

        // 5. Invalid DCID length (> 20) & huge CRYPTO offset (anti-memory-amplification)
        let mut bad_dcid = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 255];
        bad_dcid.resize(1200, 0x00);
        assert_eq!(sniff_quic_initial_sni(&bad_dcid), SniffOutcome::NoHostname);

        // Valid encrypted Initial carrying a CRYPTO frame with offset = 100_000_000 -> safe NoHostname
        let mut huge_offset_frames = vec![0x06];
        // 4-byte varint for 100_000_000 (0x05f5e100 | 0x80000000)
        huge_offset_frames.extend_from_slice(&(0x85f5_e100u32).to_be_bytes());
        huge_offset_frames.push(0x04); // len = 4
        huge_offset_frames.extend_from_slice(b"test");
        let amp_pkt = test_helpers::build_quic_initial_packet_from_frames(
            QUIC_VERSION_1,
            &dcid,
            &[],
            &[],
            0,
            2,
            &huge_offset_frames,
            1200,
        );
        assert_eq!(sniff_quic_initial_sni(&amp_pkt), SniffOutcome::NoHostname);

        // 6. Oversized UDP payload (> MAX_QUIC_SNIFF_DATAGRAM_BYTES) rejected cleanly
        let oversized = vec![0xc0; MAX_QUIC_SNIFF_DATAGRAM_BYTES + 128];
        assert_eq!(sniff_quic_initial_sni(&oversized), SniffOutcome::NoHostname);

        // 7. Random non-QUIC UDP payloads (DNS / WireGuard / STUN)
        assert_eq!(sniff_quic_initial_sni(&[]), SniffOutcome::NoHostname);
        assert_eq!(
            sniff_quic_initial_sni(b"\x00\x01\x00\x00\x21\x12\xa4\x42stun-pkt"),
            SniffOutcome::NoHostname
        );
    }

    #[test]
    fn http_sniffer_handles_multibyte_utf8_headers_spanning_byte_index_5_without_panic() {
        // "你好: x" has UTF-8 bytes [0..3) = '你', [3..6) = '好', spanning byte index 5.
        let req = "GET / HTTP/1.1\r\n你好: x\r\n你好世界: y\r\nHost: Example.COM:80\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(req.as_bytes()),
            SniffOutcome::Domain("example.com".to_string())
        );

        // Multi-byte UTF-8 header without Host returns NoHostname cleanly instead of panicking.
        let no_host = "GET / HTTP/1.1\r\n你好: x\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(no_host.as_bytes()),
            SniffOutcome::NoHostname
        );

        // Non-ASCII Host value also safely returns NoHostname without panicking.
        let utf8_host = "GET / HTTP/1.1\r\nHost: 你好.example.com\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(utf8_host.as_bytes()),
            SniffOutcome::NoHostname
        );
    }
}
