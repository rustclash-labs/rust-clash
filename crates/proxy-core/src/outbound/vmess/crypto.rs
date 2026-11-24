use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    cipher::{AES_128, DecryptingKey, DecryptionContext, EncryptingKey, UnboundCipherKey},
    digest::{SHA256, digest},
    hmac,
};
use bytes::{BufMut, BytesMut};
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::addr::TargetAddr;

pub const VMESS_VERSION: u8 = 0x01;
pub const VMESS_CMD_TCP: u8 = 0x01;
pub const VMESS_CMD_UDP: u8 = 0x02;
pub const VMESS_CMD_MUX: u8 = 0x03;

pub const VMESS_OPT_CHUNK_STREAM: u8 = 0x01;
pub const VMESS_OPT_CHUNK_MASKING: u8 = 0x04;
pub const VMESS_OPT_GLOBAL_PADDING: u8 = 0x08;

pub const VMESS_SEC_AES_128_GCM: u8 = 0x03;
pub const VMESS_SEC_CHACHA20_POLY1305: u8 = 0x04;
pub const VMESS_SEC_NONE: u8 = 0x05;

pub const VMESS_MAX_CHUNK_PLAIN: usize = 15000;
pub const VMESS_AEAD_TAG_LEN: usize = 16;

const VMESS_CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmessSecurity {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl VmessSecurity {
    pub fn parse(raw: &str) -> io::Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else if trimmed.eq_ignore_ascii_case("aes-128-gcm") {
            Ok(Self::Aes128Gcm)
        } else if trimmed.eq_ignore_ascii_case("chacha20-poly1305") {
            Ok(Self::Chacha20Poly1305)
        } else if trimmed.eq_ignore_ascii_case("none") {
            Ok(Self::None)
        } else if trimmed.eq_ignore_ascii_case("zero") {
            Ok(Self::Zero)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported VMess cipher '{trimmed}' (supported: auto, aes-128-gcm, chacha20-poly1305, none, zero)"
                ),
            ))
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::None => "none",
            Self::Zero => "zero",
        }
    }

    pub fn wire_security_byte(self) -> u8 {
        match self {
            Self::Auto => {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                {
                    VMESS_SEC_AES_128_GCM
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    VMESS_SEC_CHACHA20_POLY1305
                }
            }
            Self::Aes128Gcm => VMESS_SEC_AES_128_GCM,
            Self::Chacha20Poly1305 => VMESS_SEC_CHACHA20_POLY1305,
            Self::None | Self::Zero => VMESS_SEC_NONE,
        }
    }

    pub fn is_unencrypted_payload(self) -> bool {
        matches!(self, Self::None | Self::Zero)
    }
}

/// Derive the 16-byte VMess `CmdKey = MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.
pub fn derive_cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5::Digest::update(&mut md5, uuid.as_bytes());
    md5::Digest::update(&mut md5, VMESS_CMD_KEY_MAGIC);
    md5.finalize().into()
}

/// Derive the 32-byte VMess ChaCha20-Poly1305 key `MD5(key16) || MD5(MD5(key16))`.
pub fn derive_chacha20_key(key16: &[u8; 16]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(key16).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

fn hmac_sha256_base(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Recursive RFC 2104 HMAC tree defined by VMess AEAD KDF:
/// - `H_0(m) = HMAC-SHA256(key = "VMess AEAD KDF", msg = m)`
/// - `H_i(m) = HMAC_{H_{i-1}}(key = path_i, msg = m)` with 64-byte block size.
fn vmess_kdf_eval(paths: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((&last_key, parent_paths)) = paths.split_last() else {
        return hmac_sha256_base(KDF_SALT_VMESS_AEAD_KDF, msg);
    };
    let mut padded_key = [0u8; 64];
    if last_key.len() > 64 {
        let hashed = vmess_kdf_eval(parent_paths, last_key);
        padded_key[..32].copy_from_slice(&hashed);
    } else {
        padded_key[..last_key.len()].copy_from_slice(last_key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }
    let mut inner_buf = Vec::with_capacity(64 + msg.len());
    inner_buf.extend_from_slice(&ipad);
    inner_buf.extend_from_slice(msg);
    let inner_digest = vmess_kdf_eval(parent_paths, &inner_buf);

    let mut outer_buf = [0u8; 96];
    outer_buf[..64].copy_from_slice(&opad);
    outer_buf[64..].copy_from_slice(&inner_digest);
    vmess_kdf_eval(parent_paths, &outer_buf)
}

pub fn vmess_kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    vmess_kdf_eval(paths, key)
}

pub fn vmess_kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = vmess_kdf(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn vmess_kdf12(key: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let full = vmess_kdf(key, paths);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// FNV-1a 32-bit checksum used inside the VMess request instruction header.
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn create_auth_id(cmd_key: &[u8; 16], unix_secs: i64) -> io::Result<[u8; 16]> {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&unix_secs.to_be_bytes());
    rand::rng().fill_bytes(&mut block[8..12]);
    let crc = crc32fast::hash(&block[..12]);
    block[12..16].copy_from_slice(&crc.to_be_bytes());

    let ecb_key_bytes = vmess_kdf16(cmd_key, &[KDF_SALT_AUTH_ID_KEY]);
    let unbound = UnboundCipherKey::new(&AES_128, &ecb_key_bytes)
        .map_err(|_| io::Error::other("AES-128 AuthID key init failed"))?;
    let enc_key = EncryptingKey::ecb(unbound)
        .map_err(|_| io::Error::other("AES-128-ECB AuthID init failed"))?;
    enc_key
        .encrypt(&mut block)
        .map_err(|_| io::Error::other("AES-128-ECB AuthID encrypt failed"))?;
    Ok(block)
}

pub fn decode_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> io::Result<Option<i64>> {
    let mut block = *auth_id;
    let ecb_key_bytes = vmess_kdf16(cmd_key, &[KDF_SALT_AUTH_ID_KEY]);
    let unbound = UnboundCipherKey::new(&AES_128, &ecb_key_bytes)
        .map_err(|_| io::Error::other("AES-128 AuthID key init failed"))?;
    let dec_key = DecryptingKey::ecb(unbound)
        .map_err(|_| io::Error::other("AES-128-ECB AuthID decrypt init failed"))?;
    dec_key
        .decrypt(&mut block, DecryptionContext::None)
        .map_err(|_| io::Error::other("AES-128-ECB AuthID decrypt failed"))?;

    let expected_crc = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let actual_crc = crc32fast::hash(&block[..12]);
    if expected_crc != actual_crc {
        return Ok(None);
    }
    let ts = i64::from_be_bytes([
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
    ]);
    Ok(Some(ts))
}

fn aes128_gcm_seal(
    key16: &[u8; 16],
    nonce12: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> io::Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_128_GCM, key16)
        .map_err(|_| io::Error::other("AES-128-GCM key init failed"))?;
    let key = LessSafeKey::new(unbound);
    let mut buf = Vec::with_capacity(plain.len() + VMESS_AEAD_TAG_LEN);
    buf.extend_from_slice(plain);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce12),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| io::Error::other("AES-128-GCM seal failed"))?;
    Ok(buf)
}

fn aes128_gcm_open(
    key16: &[u8; 16],
    nonce12: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_128_GCM, key16)
        .map_err(|_| io::Error::other("AES-128-GCM key init failed"))?;
    let key = LessSafeKey::new(unbound);
    let mut buf = ciphertext.to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce12),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess AEAD authentication tag mismatch",
            )
        })?;
    let plain_len = plain.len();
    buf.truncate(plain_len);
    Ok(buf)
}

#[derive(Clone, Debug)]
pub struct VmessRequestHeader {
    pub req_iv: [u8; 16],
    pub req_key: [u8; 16],
    pub resp_v: u8,
    pub option: u8,
    pub security: u8,
    pub command: u8,
    pub target: TargetAddr,
}

impl VmessRequestHeader {
    pub fn new_random(
        security_cfg: VmessSecurity,
        global_padding: bool,
        command: u8,
        target: TargetAddr,
    ) -> Self {
        let mut req_iv = [0u8; 16];
        let mut req_key = [0u8; 16];
        let mut resp_b = [0u8; 1];
        rand::rng().fill_bytes(&mut req_iv);
        rand::rng().fill_bytes(&mut req_key);
        rand::rng().fill_bytes(&mut resp_b);

        let security = security_cfg.wire_security_byte();
        let mut option = 0u8;
        if security == VMESS_SEC_NONE {
            if command == VMESS_CMD_UDP {
                option = VMESS_OPT_CHUNK_STREAM;
            }
        } else {
            option = VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING;
            if global_padding {
                option |= VMESS_OPT_GLOBAL_PADDING;
            }
        }

        Self {
            req_iv,
            req_key,
            resp_v: resp_b[0],
            option,
            security,
            command,
            target,
        }
    }

    pub fn encode_instruction(&self) -> io::Result<BytesMut> {
        let pad_len = (rand::rng().next_u32() & 0x0f) as usize;
        let mut hdr = BytesMut::with_capacity(64 + pad_len);
        hdr.put_u8(VMESS_VERSION);
        hdr.put_slice(&self.req_iv);
        hdr.put_slice(&self.req_key);
        hdr.put_u8(self.resp_v);
        hdr.put_u8(self.option);
        hdr.put_u8(((pad_len as u8) << 4) | (self.security & 0x0f));
        hdr.put_u8(0x00); // reserved
        hdr.put_u8(self.command);
        if self.command != VMESS_CMD_MUX {
            self.target.encode_vless(&mut hdr)?;
        }
        if pad_len > 0 {
            let mut pad = [0u8; 15];
            rand::rng().fill_bytes(&mut pad[..pad_len]);
            hdr.put_slice(&pad[..pad_len]);
        }
        let csum = fnv1a32(&hdr);
        hdr.put_u32(csum);
        Ok(hdr)
    }

    pub fn decode_instruction(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < 42 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess instruction header too short",
            ));
        }
        let body = &raw[..raw.len() - 4];
        let expected_fnv = u32::from_be_bytes([
            raw[raw.len() - 4],
            raw[raw.len() - 3],
            raw[raw.len() - 2],
            raw[raw.len() - 1],
        ]);
        if fnv1a32(body) != expected_fnv {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess instruction header FNV1a checksum mismatch",
            ));
        }
        if body[0] != VMESS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VMess version {}", body[0]),
            ));
        }
        let mut req_iv = [0u8; 16];
        let mut req_key = [0u8; 16];
        req_iv.copy_from_slice(&body[1..17]);
        req_key.copy_from_slice(&body[17..33]);
        let resp_v = body[33];
        let option = body[34];
        let p_sec = body[35];
        let pad_len = (p_sec >> 4) as usize;
        let security = p_sec & 0x0f;
        let command = body[37];
        if body.len() < 38 + pad_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess header truncated before padding",
            ));
        }
        let addr_slice = &body[38..body.len() - pad_len];
        let target = if command == VMESS_CMD_MUX && addr_slice.is_empty() {
            TargetAddr::new_domain("v1.mux.cool".to_string(), 666)?
        } else {
            let mut cursor = io::Cursor::new(addr_slice);
            let parsed = decode_vless_addr_sync(&mut cursor)?;
            if cursor.position() as usize != addr_slice.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing bytes in VMess target address",
                ));
            }
            parsed
        };
        Ok(Self {
            req_iv,
            req_key,
            resp_v,
            option,
            security,
            command,
            target,
        })
    }
}

fn decode_vless_addr_sync(cursor: &mut io::Cursor<&[u8]>) -> io::Result<TargetAddr> {
    let mut port_b = [0u8; 2];
    std::io::Read::read_exact(cursor, &mut port_b)?;
    let port = u16::from_be_bytes(port_b);
    let mut atyp = [0u8; 1];
    std::io::Read::read_exact(cursor, &mut atyp)?;
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            std::io::Read::read_exact(cursor, &mut ip)?;
            Ok(TargetAddr::new_ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                port,
            ))
        }
        0x02 => {
            let mut len = [0u8; 1];
            std::io::Read::read_exact(cursor, &mut len)?;
            let mut domain = vec![0u8; len[0] as usize];
            std::io::Read::read_exact(cursor, &mut domain)?;
            let s = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in VMess domain")
            })?;
            TargetAddr::new_domain(s, port)
        }
        0x03 => {
            let mut ip = [0u8; 16];
            std::io::Read::read_exact(cursor, &mut ip)?;
            Ok(TargetAddr::new_ip(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                port,
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VMess ATYP 0x{other:02x}"),
        )),
    }
}

/// Seal a VMess AEAD request header (`[EAuID:16][ALength:18][Nonce:8][AHeader:len+16]`).
pub fn seal_vmess_aead_request_header(
    cmd_key: &[u8; 16],
    header: &VmessRequestHeader,
) -> io::Result<BytesMut> {
    let instruction = header.encode_instruction()?;
    let auth_id = create_auth_id(cmd_key, current_unix_secs())?;
    let mut conn_nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut conn_nonce);

    let len_bytes = (instruction.len() as u16).to_be_bytes();
    let len_key = vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_LEN_KEY, &auth_id, &conn_nonce]);
    let len_iv = vmess_kdf12(cmd_key, &[KDF_SALT_HEADER_LEN_IV, &auth_id, &conn_nonce]);
    let enc_len = aes128_gcm_seal(&len_key, &len_iv, &auth_id, &len_bytes)?;

    let hdr_key = vmess_kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_KEY, &auth_id, &conn_nonce],
    );
    let hdr_iv = vmess_kdf12(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_IV, &auth_id, &conn_nonce],
    );
    let enc_hdr = aes128_gcm_seal(&hdr_key, &hdr_iv, &auth_id, &instruction)?;

    let mut out = BytesMut::with_capacity(16 + 18 + 8 + enc_hdr.len());
    out.put_slice(&auth_id);
    out.put_slice(&enc_len);
    out.put_slice(&conn_nonce);
    out.put_slice(&enc_hdr);
    Ok(out)
}

/// Read and open a VMess AEAD request header from `reader` (used by loopback test server).
pub async fn read_vmess_aead_request_header<R: AsyncRead + Unpin + ?Sized>(
    cmd_key: &[u8; 16],
    reader: &mut R,
) -> io::Result<VmessRequestHeader> {
    let mut auth_id = [0u8; 16];
    reader.read_exact(&mut auth_id).await?;
    let Some(ts) = decode_auth_id(cmd_key, &auth_id)? else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VMess AuthID CRC mismatch",
        ));
    };
    if ts.abs_diff(current_unix_secs()) > 120 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VMess AuthID timestamp skew exceeds 120s",
        ));
    }

    let mut enc_len = [0u8; 18];
    let mut conn_nonce = [0u8; 8];
    reader.read_exact(&mut enc_len).await?;
    reader.read_exact(&mut conn_nonce).await?;

    let len_key = vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_LEN_KEY, &auth_id, &conn_nonce]);
    let len_iv = vmess_kdf12(cmd_key, &[KDF_SALT_HEADER_LEN_IV, &auth_id, &conn_nonce]);
    let dec_len = aes128_gcm_open(&len_key, &len_iv, &auth_id, &enc_len)?;
    let hdr_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;
    if hdr_len > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess AEAD header length exceeds 2048 bytes",
        ));
    }

    let mut enc_hdr = vec![0u8; hdr_len + VMESS_AEAD_TAG_LEN];
    reader.read_exact(&mut enc_hdr).await?;
    let hdr_key = vmess_kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_KEY, &auth_id, &conn_nonce],
    );
    let hdr_iv = vmess_kdf12(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_IV, &auth_id, &conn_nonce],
    );
    let dec_hdr = aes128_gcm_open(&hdr_key, &hdr_iv, &auth_id, &enc_hdr)?;
    VmessRequestHeader::decode_instruction(&dec_hdr)
}

pub fn derive_response_key_and_iv(req_key: &[u8; 16], req_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let rk_full = digest(&SHA256, req_key);
    let riv_full = digest(&SHA256, req_iv);
    let mut resp_key = [0u8; 16];
    let mut resp_iv = [0u8; 16];
    resp_key.copy_from_slice(&rk_full.as_ref()[..16]);
    resp_iv.copy_from_slice(&riv_full.as_ref()[..16]);
    (resp_key, resp_iv)
}

/// Seal a 4-byte VMess AEAD response header (`[resp_v, option, 0, 0]`).
pub fn seal_vmess_aead_response_header(
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    resp_v: u8,
    option: u8,
) -> io::Result<BytesMut> {
    let body = [resp_v, option, 0x00, 0x00];
    let len_bytes = (body.len() as u16).to_be_bytes();

    let len_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_HEADER_LEN_KEY]);
    let len_nonce = vmess_kdf12(resp_iv, &[KDF_SALT_RESP_HEADER_LEN_IV]);
    let enc_len = aes128_gcm_seal(&len_key, &len_nonce, &[], &len_bytes)?;

    let body_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_HEADER_PAYLOAD_KEY]);
    let body_nonce = vmess_kdf12(resp_iv, &[KDF_SALT_RESP_HEADER_PAYLOAD_IV]);
    let enc_body = aes128_gcm_seal(&body_key, &body_nonce, &[], &body)?;

    let mut out = BytesMut::with_capacity(enc_len.len() + enc_body.len());
    out.put_slice(&enc_len);
    out.put_slice(&enc_body);
    Ok(out)
}

/// Incrementally decode the VMess AEAD response header from `src`, returning `Ok(Some(consumed_bytes))`
/// when complete or `Ok(None)` if more bytes are needed.
pub fn try_open_vmess_aead_response_header(
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    expected_resp_v: u8,
    src: &[u8],
) -> io::Result<Option<usize>> {
    if src.len() < 18 {
        return Ok(None);
    }
    let len_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_HEADER_LEN_KEY]);
    let len_nonce = vmess_kdf12(resp_iv, &[KDF_SALT_RESP_HEADER_LEN_IV]);
    let dec_len = aes128_gcm_open(&len_key, &len_nonce, &[], &src[..18])?;
    let body_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;
    if !(4..=2048).contains(&body_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid VMess AEAD response header length {body_len}"),
        ));
    }
    let total = 18 + body_len + VMESS_AEAD_TAG_LEN;
    if src.len() < total {
        return Ok(None);
    }
    let body_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_HEADER_PAYLOAD_KEY]);
    let body_nonce = vmess_kdf12(resp_iv, &[KDF_SALT_RESP_HEADER_PAYLOAD_IV]);
    let dec_body = aes128_gcm_open(&body_key, &body_nonce, &[], &src[18..total])?;
    if dec_body[0] != expected_resp_v {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess response verification byte mismatch",
        ));
    }
    Ok(Some(total))
}

struct ShakeMaskStream {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

impl ShakeMaskStream {
    fn new(iv16: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv16);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.reader.read(&mut b);
        u16::from_be_bytes(b)
    }
}

enum ChunkAeadKind {
    None,
    Aes128Gcm(LessSafeKey),
    Chacha20Poly1305(LessSafeKey),
}

/// Stateful VMess data chunk encoder/decoder supporting `aes-128-gcm`, `chacha20-poly1305`, and `none`/`zero`.
pub struct VmessChunkCodec {
    aead: ChunkAeadKind,
    iv_tail: [u8; 10],
    count: u16,
    mask: Option<ShakeMaskStream>,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    pending_chunk: Option<(usize, usize)>,
}

impl VmessChunkCodec {
    pub fn new(key16: &[u8; 16], iv16: &[u8; 16], security: u8, option: u8) -> io::Result<Self> {
        let aead = match security {
            VMESS_SEC_NONE => ChunkAeadKind::None,
            VMESS_SEC_AES_128_GCM => {
                let unbound = UnboundKey::new(&AES_128_GCM, key16)
                    .map_err(|_| io::Error::other("VMess AES-128-GCM init failed"))?;
                ChunkAeadKind::Aes128Gcm(LessSafeKey::new(unbound))
            }
            VMESS_SEC_CHACHA20_POLY1305 => {
                let key32 = derive_chacha20_key(key16);
                let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key32)
                    .map_err(|_| io::Error::other("VMess ChaCha20-Poly1305 init failed"))?;
                ChunkAeadKind::Chacha20Poly1305(LessSafeKey::new(unbound))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported VMess wire security 0x{other:02x}"),
                ));
            }
        };
        let chunk_stream = (option & VMESS_OPT_CHUNK_STREAM) != 0 || security != VMESS_SEC_NONE;
        let chunk_masking = (option & VMESS_OPT_CHUNK_MASKING) != 0;
        let global_padding = (option & VMESS_OPT_GLOBAL_PADDING) != 0;
        let mask = if chunk_masking || global_padding {
            Some(ShakeMaskStream::new(iv16))
        } else {
            None
        };
        let mut iv_tail = [0u8; 10];
        iv_tail.copy_from_slice(&iv16[2..12]);
        Ok(Self {
            aead,
            iv_tail,
            count: 0,
            mask,
            chunk_stream,
            chunk_masking,
            global_padding,
            pending_chunk: None,
        })
    }

    pub fn is_raw_passthrough(&self) -> bool {
        !self.chunk_stream && matches!(self.aead, ChunkAeadKind::None)
    }

    pub fn has_pending_chunk(&self) -> bool {
        self.pending_chunk.is_some()
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..12].copy_from_slice(&self.iv_tail);
        self.count = self.count.wrapping_add(1);
        Nonce::assume_unique_for_key(n)
    }

    /// Encode a single chunk (or raw slice when `is_raw_passthrough()`).
    pub fn encode_chunk(&mut self, plain: &[u8], out: &mut BytesMut) -> io::Result<()> {
        if self.is_raw_passthrough() {
            out.put_slice(plain);
            return Ok(());
        }
        let pad_len = if self.global_padding {
            (self.mask.as_mut().expect("mask present").next_u16() % 64) as usize
        } else {
            0
        };
        let overhead = match self.aead {
            ChunkAeadKind::None => 0,
            _ => VMESS_AEAD_TAG_LEN,
        };
        let body_len = plain.len() + overhead;
        let wire_len_unmasked = (body_len + pad_len) as u16;
        let wire_len = if self.chunk_masking {
            wire_len_unmasked ^ self.mask.as_mut().expect("mask present").next_u16()
        } else {
            wire_len_unmasked
        };

        out.reserve(2 + body_len + pad_len);
        out.put_u16(wire_len);
        if matches!(self.aead, ChunkAeadKind::None) {
            out.put_slice(plain);
        } else {
            let nonce = self.next_nonce();
            let key = match &self.aead {
                ChunkAeadKind::Aes128Gcm(k) | ChunkAeadKind::Chacha20Poly1305(k) => k,
                ChunkAeadKind::None => unreachable!(),
            };
            let start = out.len();
            out.put_slice(plain);
            let mut body = out.split_off(start);
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
                .map_err(|_| io::Error::other("VMess chunk AEAD seal failed"))?;
            out.unsplit(body);
        }
        if pad_len > 0 {
            let mut pad = [0u8; 64];
            rand::rng().fill_bytes(&mut pad[..pad_len]);
            out.put_slice(&pad[..pad_len]);
        }
        Ok(())
    }

    /// Encode clean VMess stream EOF marker chunk (for graceful half-close).
    pub fn encode_eof_chunk(&mut self, out: &mut BytesMut) -> io::Result<()> {
        if self.is_raw_passthrough() {
            return Ok(());
        }
        self.encode_chunk(&[], out)
    }

    /// Try decoding one chunk from `src`.
    /// Returns:
    /// - `Ok(Some(Some(plaintext)))` on a data chunk
    /// - `Ok(Some(None))` on clean VMess EOF chunk
    /// - `Ok(None)` when `src` needs more bytes
    pub fn try_decode_chunk(&mut self, src: &mut BytesMut) -> io::Result<Option<Option<Vec<u8>>>> {
        if self.is_raw_passthrough() {
            if src.is_empty() {
                return Ok(None);
            }
            return Ok(Some(Some(src.split().to_vec())));
        }

        let (data_len, pad_len) = match self.pending_chunk {
            Some(pair) => pair,
            None => {
                if src.len() < 2 {
                    return Ok(None);
                }
                let raw_len = u16::from_be_bytes([src[0], src[1]]);
                let pad = if self.global_padding {
                    (self.mask.as_mut().expect("mask present").next_u16() % 64) as usize
                } else {
                    0
                };
                let unmasked = if self.chunk_masking {
                    raw_len ^ self.mask.as_mut().expect("mask present").next_u16()
                } else {
                    raw_len
                } as usize;
                if unmasked < pad {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess chunk length smaller than global padding",
                    ));
                }
                let data_len = unmasked - pad;
                if !matches!(self.aead, ChunkAeadKind::None) && data_len < VMESS_AEAD_TAG_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess AEAD chunk shorter than 16-byte tag",
                    ));
                }
                let _ = src.split_to(2);
                self.pending_chunk = Some((data_len, pad));
                (data_len, pad)
            }
        };

        if src.len() < data_len + pad_len {
            return Ok(None);
        }
        self.pending_chunk = None;

        let mut chunk_body = src.split_to(data_len);
        if pad_len > 0 {
            let _ = src.split_to(pad_len);
        }

        if matches!(self.aead, ChunkAeadKind::None) {
            if data_len == 0 {
                return Ok(Some(None));
            }
            Ok(Some(Some(chunk_body.to_vec())))
        } else {
            if chunk_body.len() < VMESS_AEAD_TAG_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess AEAD chunk shorter than 16-byte tag",
                ));
            }
            let nonce = self.next_nonce();
            let key = match &self.aead {
                ChunkAeadKind::Aes128Gcm(k) | ChunkAeadKind::Chacha20Poly1305(k) => k,
                ChunkAeadKind::None => unreachable!(),
            };
            let plain = key
                .open_in_place(nonce, Aad::empty(), &mut chunk_body)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess AEAD chunk authentication failed",
                    )
                })?;
            if plain.is_empty() {
                Ok(Some(None))
            } else {
                Ok(Some(Some(plain.to_vec())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmess_aead_header_and_chunk_codecs_roundtrip() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd_key = derive_cmd_key(&uuid);
        let target = TargetAddr::new_domain("example.com", 443).unwrap();

        for sec in [
            VmessSecurity::Aes128Gcm,
            VmessSecurity::Chacha20Poly1305,
            VmessSecurity::None,
        ] {
            let req = VmessRequestHeader::new_random(sec, true, VMESS_CMD_TCP, target.clone());
            let wire_hdr = seal_vmess_aead_request_header(&cmd_key, &req).unwrap();

            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let decoded_req = rt
                .block_on(async {
                    let mut cursor = io::Cursor::new(wire_hdr.as_ref());
                    read_vmess_aead_request_header(&cmd_key, &mut cursor).await
                })
                .unwrap();
            assert_eq!(decoded_req.req_key, req.req_key);
            assert_eq!(decoded_req.req_iv, req.req_iv);
            assert_eq!(decoded_req.target, target);

            let (resp_key, resp_iv) = derive_response_key_and_iv(&req.req_key, &req.req_iv);
            let wire_resp =
                seal_vmess_aead_response_header(&resp_key, &resp_iv, req.resp_v, req.option)
                    .unwrap();
            let used =
                try_open_vmess_aead_response_header(&resp_key, &resp_iv, req.resp_v, &wire_resp)
                    .unwrap()
                    .unwrap();
            assert_eq!(used, wire_resp.len());

            let mut enc =
                VmessChunkCodec::new(&req.req_key, &req.req_iv, req.security, req.option).unwrap();
            let mut dec =
                VmessChunkCodec::new(&req.req_key, &req.req_iv, req.security, req.option).unwrap();

            let mut wire_chunks = BytesMut::new();
            enc.encode_chunk(b"hello vmess aead", &mut wire_chunks)
                .unwrap();
            enc.encode_chunk(b"second frame", &mut wire_chunks).unwrap();
            enc.encode_eof_chunk(&mut wire_chunks).unwrap();

            if enc.is_raw_passthrough() {
                let all = dec
                    .try_decode_chunk(&mut wire_chunks)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(&all, b"hello vmess aeadsecond frame");
            } else {
                let c1 = dec
                    .try_decode_chunk(&mut wire_chunks)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let c2 = dec
                    .try_decode_chunk(&mut wire_chunks)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let eof = dec.try_decode_chunk(&mut wire_chunks).unwrap().unwrap();
                assert_eq!(c1, b"hello vmess aead");
                assert_eq!(c2, b"second frame");
                assert!(eof.is_none());
            }
        }
    }

    #[test]
    fn aead_rejects_forged_zero_len_while_accepting_authenticated_eof_and_none_zero_eof() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];

        // 1. AEAD modes (both AES-128-GCM and ChaCha20-Poly1305) MUST reject forged data_len == 0
        //    (both unmasked and masked+padded) with InvalidData, and ONLY accept authenticated
        //    16-byte tag EOF chunks from `encode_eof_chunk`.
        for sec in [VMESS_SEC_AES_128_GCM, VMESS_SEC_CHACHA20_POLY1305] {
            for option in [
                VMESS_OPT_CHUNK_STREAM,
                VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING,
                VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING | VMESS_OPT_GLOBAL_PADDING,
            ] {
                // Build a forged `data_len == 0` wire frame matching the decoder's Shake128 stream.
                let mut shake = ShakeMaskStream::new(&iv);
                let pad_len = if (option & VMESS_OPT_GLOBAL_PADDING) != 0 {
                    (shake.next_u16() % 64) as usize
                } else {
                    0
                };
                let unmasked_len = pad_len as u16; // data_len = 0
                let wire_len = if (option & VMESS_OPT_CHUNK_MASKING) != 0 {
                    unmasked_len ^ shake.next_u16()
                } else {
                    unmasked_len
                };

                let mut forged = BytesMut::new();
                forged.put_u16(wire_len);
                forged.put_bytes(0xAA, pad_len);

                let mut dec = VmessChunkCodec::new(&key, &iv, sec, option).unwrap();
                let err = dec
                    .try_decode_chunk(&mut forged)
                    .expect_err("forged data_len == 0 in AEAD mode must be rejected");
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);

                // Genuine `encode_eof_chunk` (16-byte AEAD tag) must decode to clean EOF `Ok(Some(None))`.
                let mut enc = VmessChunkCodec::new(&key, &iv, sec, option).unwrap();
                let mut dec_valid = VmessChunkCodec::new(&key, &iv, sec, option).unwrap();
                let mut eof_wire = BytesMut::new();
                enc.encode_eof_chunk(&mut eof_wire).unwrap();
                assert!(eof_wire.len() >= 2 + VMESS_AEAD_TAG_LEN);
                let decoded = dec_valid.try_decode_chunk(&mut eof_wire).unwrap().unwrap();
                assert!(decoded.is_none());
                assert!(!dec_valid.has_pending_chunk());
            }
        }

        // 2. `ChunkAeadKind::None` chunk stream MUST still accept `data_len == 0` as clean EOF.
        let mut dec_none =
            VmessChunkCodec::new(&key, &iv, VMESS_SEC_NONE, VMESS_OPT_CHUNK_STREAM).unwrap();
        let mut zero_eof = BytesMut::from(&[0x00u8, 0x00u8][..]);
        let decoded = dec_none.try_decode_chunk(&mut zero_eof).unwrap().unwrap();
        assert!(decoded.is_none());

        // 3. `has_pending_chunk()` accurately tracks mid-chunk state even when wire buffer is empty.
        let mut enc = VmessChunkCodec::new(
            &key,
            &iv,
            VMESS_SEC_AES_128_GCM,
            VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING,
        )
        .unwrap();
        let mut dec = VmessChunkCodec::new(
            &key,
            &iv,
            VMESS_SEC_AES_128_GCM,
            VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING,
        )
        .unwrap();
        let mut full = BytesMut::new();
        enc.encode_chunk(b"payload-bytes", &mut full).unwrap();

        assert!(!dec.has_pending_chunk());
        let mut hdr_only = full.split_to(2);
        assert!(dec.try_decode_chunk(&mut hdr_only).unwrap().is_none());
        assert!(hdr_only.is_empty());
        assert!(
            dec.has_pending_chunk(),
            "after consuming 2-byte chunk length header, has_pending_chunk() must be true"
        );

        let decoded = dec.try_decode_chunk(&mut full).unwrap().unwrap().unwrap();
        assert_eq!(decoded, b"payload-bytes");
        assert!(!dec.has_pending_chunk());
    }

    #[tokio::test]
    async fn aead_request_header_rejects_extreme_i64_min_and_max_auth_id_timestamps_without_overflow()
     {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd_key = derive_cmd_key(&uuid);
        let now = current_unix_secs();

        for extreme_ts in [
            i64::MIN,
            i64::MIN + 1,
            -1_000_000,
            now - 121,
            now + 121,
            i64::MAX,
        ] {
            let auth_id = create_auth_id(&cmd_key, extreme_ts).unwrap();
            let mut cursor = io::Cursor::new(auth_id);
            let err = read_vmess_aead_request_header(&cmd_key, &mut cursor)
                .await
                .expect_err("extreme/skewed AuthID timestamp must fail without overflow");
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "expected PermissionDenied for timestamp {extreme_ts}, got {err:?}"
            );
        }
    }
}
