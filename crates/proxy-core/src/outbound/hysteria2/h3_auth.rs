use std::{io, sync::LazyLock};

use bytes::{BufMut, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::outbound::quic_common::{encode_quic_varint, read_quic_varint};

pub const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_SETTINGS: u64 = 0x04;
pub const HY2_FRAME_TCP_REQUEST: u64 = 0x401;
pub const HY2_STATUS_AUTH_OK: u16 = 233;

const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

const HUFFMAN_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[derive(Clone, Copy)]
struct HuffmanNode {
    children: [i16; 2],
    sym: i16,
}

static HUFFMAN_TRIE: LazyLock<Vec<HuffmanNode>> = LazyLock::new(|| {
    let mut nodes = vec![HuffmanNode {
        children: [-1, -1],
        sym: -1,
    }];
    for sym in 0..256usize {
        let code = HUFFMAN_CODES[sym];
        let len = HUFFMAN_CODE_LEN[sym];
        let mut cur = 0usize;
        for bit_idx in (0..len).rev() {
            let bit = ((code >> bit_idx) & 1) as usize;
            let next = nodes[cur].children[bit];
            if next >= 0 {
                cur = next as usize;
            } else {
                let id = nodes.len();
                nodes.push(HuffmanNode {
                    children: [-1, -1],
                    sym: -1,
                });
                nodes[cur].children[bit] = id as i16;
                cur = id;
            }
        }
        nodes[cur].sym = sym as i16;
    }
    nodes
});

pub fn huffman_decode(src: &[u8]) -> io::Result<Vec<u8>> {
    let trie = &*HUFFMAN_TRIE;
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut cur = 0usize;
    let mut pad_bits = 0u8;
    let mut all_ones_tail = true;

    for &byte in src {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as usize;
            let next = trie[cur].children[bit];
            if next < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid QPACK Huffman bit sequence",
                ));
            }
            cur = next as usize;
            if trie[cur].sym >= 0 {
                out.push(trie[cur].sym as u8);
                cur = 0;
                pad_bits = 0;
                all_ones_tail = true;
            } else {
                pad_bits = pad_bits.saturating_add(1);
                if bit == 0 {
                    all_ones_tail = false;
                }
            }
        }
    }

    if cur != 0 && (pad_bits > 7 || !all_ones_tail) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid QPACK Huffman EOS padding",
        ));
    }
    Ok(out)
}

fn encode_qpack_int(mut val: usize, prefix_bits: u8, first_mask: u8, out: &mut BytesMut) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        out.put_u8(first_mask | (val as u8));
        return;
    }
    out.put_u8(first_mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        out.put_u8(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    out.put_u8(val as u8);
}

fn decode_qpack_int(data: &[u8], prefix_bits: u8) -> io::Result<(usize, usize)> {
    if prefix_bits == 0 || prefix_bits > 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid QPACK integer prefix width",
        ));
    }
    let Some(&first) = data.first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty QPACK integer",
        ));
    };
    let max_prefix = (1u64 << prefix_bits) - 1;
    let mut val = u64::from(first) & max_prefix;
    if val < max_prefix {
        return Ok((val as usize, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    loop {
        let Some(&b) = data.get(idx) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated QPACK integer",
            ));
        };
        idx += 1;
        let chunk = u64::from(b & 0x7f);
        let Some(shifted) = chunk.checked_shl(shift) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QPACK integer overflow",
            ));
        };
        if (shifted >> shift) != chunk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QPACK integer overflow",
            ));
        }
        val = val
            .checked_add(shifted)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "QPACK integer overflow"))?;
        if val > u64::from(u32::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QPACK integer overflow",
            ));
        }
        if (b & 0x80) == 0 {
            let out = usize::try_from(val).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "QPACK integer overflow")
            })?;
            return Ok((out, idx));
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "QPACK integer overflow"))?;
    }
}

fn encode_qpack_raw_str(s: &[u8], prefix_bits: u8, first_mask: u8, out: &mut BytesMut) {
    encode_qpack_int(s.len(), prefix_bits, first_mask, out);
    out.put_slice(s);
}

fn decode_qpack_str(data: &[u8], prefix_bits: u8) -> io::Result<(String, usize)> {
    let Some(&first) = data.first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty QPACK string",
        ));
    };
    let huffman = (first & (1u8 << prefix_bits)) != 0;
    let (str_len, used) = decode_qpack_int(data, prefix_bits)?;
    let Some(end) = used.checked_add(str_len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QPACK string length overflow",
        ));
    };
    if data.len() < end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QPACK string literal",
        ));
    }
    let raw = &data[used..end];
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid UTF-8 in QPACK header string",
        )
    })?;
    Ok((text, end))
}

fn encode_qpack_literal_header(name_lower: &str, value: &str, out: &mut BytesMut) {
    // 001 N(0) H(0) NameLen(3+)
    encode_qpack_raw_str(name_lower.as_bytes(), 3, 0x20, out);
    encode_qpack_raw_str(value.as_bytes(), 7, 0x00, out);
}

fn encode_qpack_static_name_ref(static_idx: usize, value: &str, out: &mut BytesMut) {
    // 01 N(0) T(1=static -> 0x10) Index(4+)
    encode_qpack_int(static_idx, 4, 0x50, out);
    encode_qpack_raw_str(value.as_bytes(), 7, 0x00, out);
}

fn random_ascii_padding(min_len: usize, max_len: usize) -> String {
    let span = (max_len - min_len + 1) as u32;
    let len = min_len + ((rand::rng().next_u32() % span) as usize);
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut raw = vec![0u8; len];
    rand::rng().fill_bytes(&mut raw);
    raw.into_iter()
        .map(|b| ALPHABET[(b as usize) % ALPHABET.len()] as char)
        .collect()
}

pub fn decode_qpack_header_block(block: &[u8]) -> io::Result<Vec<(String, String)>> {
    let (req_insert_cnt, u1) = decode_qpack_int(block, 8)?;
    if req_insert_cnt != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dynamic QPACK table references are not negotiated",
        ));
    }
    let (_, u2) = decode_qpack_int(&block[u1..], 7)?;
    let mut pos = u1 + u2;
    let mut headers = Vec::new();
    while pos < block.len() {
        let b = block[pos];
        if (b & 0x80) != 0 {
            let is_static = (b & 0x40) != 0;
            let (idx, n) = decode_qpack_int(&block[pos..], 6)?;
            pos += n;
            if !is_static || idx >= QPACK_STATIC_TABLE.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid QPACK static table index {idx}"),
                ));
            }
            let (k, v) = QPACK_STATIC_TABLE[idx];
            headers.push((k.to_ascii_lowercase(), v.to_string()));
        } else if (b & 0xc0) == 0x40 {
            let is_static = (b & 0x10) != 0;
            let (idx, n1) = decode_qpack_int(&block[pos..], 4)?;
            pos += n1;
            if !is_static || idx >= QPACK_STATIC_TABLE.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid QPACK static name index {idx}"),
                ));
            }
            let (val, n2) = decode_qpack_str(&block[pos..], 7)?;
            pos += n2;
            let (k, _) = QPACK_STATIC_TABLE[idx];
            headers.push((k.to_ascii_lowercase(), val));
        } else if (b & 0xe0) == 0x20 {
            let (name, n1) = decode_qpack_str(&block[pos..], 3)?;
            pos += n1;
            let (val, n2) = decode_qpack_str(&block[pos..], 7)?;
            pos += n2;
            headers.push((name.to_ascii_lowercase(), val));
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported dynamic QPACK field representation 0x{b:02x}"),
            ));
        }
    }
    Ok(headers)
}

pub fn build_h3_control_stream_init() -> BytesMut {
    let mut buf = BytesMut::with_capacity(8);
    let _ = encode_quic_varint(H3_STREAM_TYPE_CONTROL, &mut buf);
    let _ = encode_quic_varint(H3_FRAME_SETTINGS, &mut buf);
    let _ = encode_quic_varint(0, &mut buf); // empty SETTINGS payload (QPACK dynamic capacity = 0)
    buf
}

pub fn build_hy2_auth_request_frame(password: &str, rx_bytes_per_sec: u64) -> io::Result<BytesMut> {
    let mut qpack = BytesMut::with_capacity(256);
    qpack.put_u8(0x00); // Required Insert Count = 0
    qpack.put_u8(0x00); // Delta Base = 0
    qpack.put_u8(0xd4); // :method = POST (static 20)
    qpack.put_u8(0xd7); // :scheme = https (static 23)
    encode_qpack_static_name_ref(0, "hysteria", &mut qpack);
    encode_qpack_static_name_ref(1, "/auth", &mut qpack);
    encode_qpack_literal_header("hysteria-auth", password, &mut qpack);
    encode_qpack_literal_header("hysteria-cc-rx", &rx_bytes_per_sec.to_string(), &mut qpack);
    let pad = random_ascii_padding(64, 192);
    encode_qpack_literal_header("hysteria-padding", &pad, &mut qpack);

    let mut frame = BytesMut::with_capacity(8 + qpack.len());
    encode_quic_varint(H3_FRAME_HEADERS, &mut frame)?;
    encode_quic_varint(qpack.len() as u64, &mut frame)?;
    frame.extend_from_slice(&qpack);
    Ok(frame)
}

pub fn build_hy2_auth_response_frame(
    status: u16,
    udp_enabled: bool,
    rx_bytes_per_sec: u64,
    rx_auto: bool,
) -> io::Result<BytesMut> {
    let mut qpack = BytesMut::with_capacity(192);
    qpack.put_u8(0x00);
    qpack.put_u8(0x00);
    encode_qpack_static_name_ref(24, &status.to_string(), &mut qpack);
    if status == HY2_STATUS_AUTH_OK {
        encode_qpack_literal_header(
            "hysteria-udp",
            if udp_enabled { "true" } else { "false" },
            &mut qpack,
        );
        let rx_str = if rx_auto {
            "auto".to_string()
        } else {
            rx_bytes_per_sec.to_string()
        };
        encode_qpack_literal_header("hysteria-cc-rx", &rx_str, &mut qpack);
        let pad = random_ascii_padding(64, 192);
        encode_qpack_literal_header("hysteria-padding", &pad, &mut qpack);
    }

    let mut frame = BytesMut::with_capacity(8 + qpack.len());
    encode_quic_varint(H3_FRAME_HEADERS, &mut frame)?;
    encode_quic_varint(qpack.len() as u64, &mut frame)?;
    frame.extend_from_slice(&qpack);
    Ok(frame)
}

#[derive(Clone, Debug)]
pub struct Hy2AuthResponse {
    pub status: u16,
    pub udp_enabled: bool,
    pub server_rx_bps: u64,
    pub rx_auto: bool,
}

pub async fn read_h3_headers_frame<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<Vec<(String, String)>> {
    loop {
        let frame_type = read_quic_varint(reader).await?;
        let frame_len = read_quic_varint(reader).await?;
        if frame_len > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP/3 frame payload too large ({frame_len} bytes)"),
            ));
        }
        let mut payload = vec![0u8; frame_len as usize];
        reader.read_exact(&mut payload).await?;
        if frame_type == H3_FRAME_HEADERS {
            return decode_qpack_header_block(&payload);
        }
    }
}

pub async fn perform_hy2_client_auth<W, R>(
    send: &mut W,
    recv: &mut R,
    password: &str,
    rx_bytes_per_sec: u64,
) -> io::Result<Hy2AuthResponse>
where
    W: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    let req_frame = build_hy2_auth_request_frame(password, rx_bytes_per_sec)?;
    send.write_all(&req_frame).await?;
    send.shutdown().await?;

    let headers = read_h3_headers_frame(recv).await?;
    let mut status: Option<u16> = None;
    let mut udp_enabled = false;
    let mut server_rx_bps = 0u64;
    let mut rx_auto = false;

    for (k, v) in headers {
        match k.as_str() {
            ":status" => {
                status = v.trim().parse::<u16>().ok();
            }
            "hysteria-udp" => {
                udp_enabled = v.trim().eq_ignore_ascii_case("true") || v.trim() == "1";
            }
            "hysteria-cc-rx" => {
                if v.trim().eq_ignore_ascii_case("auto") {
                    rx_auto = true;
                } else if let Ok(n) = v.trim().parse::<u64>() {
                    server_rx_bps = n;
                }
            }
            _ => {}
        }
    }

    let code = status.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 HTTP/3 auth response missing :status pseudo-header",
        )
    })?;
    if code != HY2_STATUS_AUTH_OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Hysteria2 authentication failed with HTTP status {code} (expected 233)"),
        ));
    }

    Ok(Hy2AuthResponse {
        status: code,
        udp_enabled,
        server_rx_bps,
        rx_auto,
    })
}

/// Parse Clash/Mihomo/Hysteria2 bandwidth specification (e.g. `"100 mbps"`, `"50"`, `"20M"`) into bytes/sec.
pub fn parse_bandwidth_bytes_per_sec(raw: Option<&str>) -> io::Result<u64> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let lower = s.to_ascii_lowercase();
    let split_idx = lower
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(lower.len());
    let num_part = lower[..split_idx].trim();
    let unit_part = lower[split_idx..].trim();
    let val: f64 = num_part.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid bandwidth value '{s}'"),
        )
    })?;
    if !val.is_finite() || val < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("negative or non-finite bandwidth value '{s}'"),
        ));
    }
    let multiplier_bytes: f64 = match unit_part {
        // Plain number in Clash/Mihomo YAML (`up: "100"`, `down: "200"`) means Mbps
        "" | "mbps" | "mbit" | "mbits" => 125_000.0,
        "bps" | "bit" | "bits" => 0.125,
        "kbps" | "kbit" | "kbits" => 125.0,
        "gbps" | "gbit" | "gbits" => 125_000_000.0,
        "tbps" | "tbit" | "tbits" => 125_000_000_000.0,
        "b" | "byte" | "bytes" | "b/s" => 1.0,
        "k" | "kb" | "kib" | "kb/s" => 1_024.0,
        "m" | "mb" | "mib" | "mb/s" => 1_048_576.0,
        "g" | "gb" | "gib" | "gb/s" => 1_073_741_824.0,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported bandwidth unit '{other}' in '{s}'"),
            ));
        }
    };
    Ok((val * multiplier_bytes) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn huffman_encode_for_test(input: &[u8]) -> Vec<u8> {
        let mut bits: u64 = 0;
        let mut nbits: u8 = 0;
        let mut out = Vec::new();
        for &b in input {
            let code = u64::from(HUFFMAN_CODES[b as usize]);
            let len = HUFFMAN_CODE_LEN[b as usize];
            bits = (bits << len) | code;
            nbits += len;
            while nbits >= 8 {
                nbits -= 8;
                out.push(((bits >> nbits) & 0xff) as u8);
            }
        }
        if nbits > 0 {
            let pad = 8 - nbits;
            bits = (bits << pad) | ((1u64 << pad) - 1);
            out.push((bits & 0xff) as u8);
        }
        out
    }

    #[test]
    fn huffman_and_qpack_auth_headers_roundtrip() {
        for sample in [
            "233",
            "true",
            "hysteria-udp",
            "hysteria-cc-rx",
            "www.example.com",
            "All printable ASCII 0123456789 !@#$%^&*()",
        ] {
            let enc = huffman_encode_for_test(sample.as_bytes());
            let dec = huffman_decode(&enc).unwrap();
            assert_eq!(dec, sample.as_bytes());
        }

        assert_eq!(QPACK_STATIC_TABLE[48], ("content-type", "image/gif"));

        let req = build_hy2_auth_request_frame("my-secret", 12_500_000).unwrap();
        let resp = build_hy2_auth_response_frame(233, true, 0, true).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut req_cur = io::Cursor::new(req.as_ref());
            let req_hdrs = read_h3_headers_frame(&mut req_cur).await.unwrap();
            assert!(req_hdrs.contains(&(":method".to_string(), "POST".to_string())));
            assert!(req_hdrs.contains(&("hysteria-auth".to_string(), "my-secret".to_string())));

            let mut resp_cur = io::Cursor::new(resp.as_ref());
            let resp_hdrs = read_h3_headers_frame(&mut resp_cur).await.unwrap();
            assert!(resp_hdrs.contains(&(":status".to_string(), "233".to_string())));
            assert!(resp_hdrs.contains(&("hysteria-udp".to_string(), "true".to_string())));
        });
    }

    #[test]
    fn bandwidth_parser_supports_mihomo_and_hysteria_units() {
        assert_eq!(parse_bandwidth_bytes_per_sec(None).unwrap(), 0);
        assert_eq!(
            parse_bandwidth_bytes_per_sec(Some("100")).unwrap(),
            12_500_000
        );
        assert_eq!(
            parse_bandwidth_bytes_per_sec(Some("100 mbps")).unwrap(),
            12_500_000
        );
        assert_eq!(
            parse_bandwidth_bytes_per_sec(Some("1 gbps")).unwrap(),
            125_000_000
        );
    }

    #[test]
    fn qpack_int_and_str_reject_overflow_and_32bit_shift_truncation() {
        // Exact u32::MAX (127 + 0xffff_ff80) decodes cleanly.
        let exact_u32_max = [0x7fu8, 0x80, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(
            decode_qpack_int(&exact_u32_max, 7).unwrap(),
            (u32::MAX as usize, 6)
        );

        // Encodings exceeding u32::MAX — including shift == 28 bit-loss cases that silently
        // truncated or saturated on 32-bit targets — must fail with InvalidData.
        for bad in [
            // 127 + (0x10 << 28) == 2^32 + 127 (previously truncated to 127 on 32-bit!)
            &[0x7fu8, 0x80, 0x80, 0x80, 0x80, 0x10][..],
            // 127 + (127 + 127<<7 + 127<<14 + 127<<21 + 15<<28) == u32::MAX + 127 (previously saturated!)
            &[0x7fu8, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
            // 127 + (0x7f << 28)
            &[0x7fu8, 0x80, 0x80, 0x80, 0x80, 0x7f][..],
            // Overlong continuation chain exceeding 64-bit shift width.
            &[
                0x7fu8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
            ][..],
        ] {
            let err =
                decode_qpack_int(bad, 7).expect_err("overflowing QPACK integer must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // `decode_qpack_str` must reject overflowing integer lengths with InvalidData and
        // reject u32::MAX string lengths cleanly without wrapping `used + str_len`.
        let err_overflow = decode_qpack_str(&[0x7fu8, 0xff, 0xff, 0xff, 0xff, 0x0f], 7)
            .expect_err("overflowing QPACK string length must fail");
        assert_eq!(err_overflow.kind(), io::ErrorKind::InvalidData);

        let err_trunc = decode_qpack_str(&exact_u32_max, 7)
            .expect_err("huge QPACK string length with short buffer must fail cleanly");
        assert!(matches!(
            err_trunc.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
        ));
    }
}
