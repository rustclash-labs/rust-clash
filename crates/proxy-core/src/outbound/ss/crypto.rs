use std::io;

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{self, DecryptionContext, EncryptingKey, UnboundCipherKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

pub const TAG_LEN: usize = 16;
pub const LEGACY_MAX_PAYLOAD: usize = 0x3FFF;
pub const SS2022_MAX_PAYLOAD: usize = 0xFFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsCipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Ss2022Blake3Aes128Gcm,
    Ss2022Blake3Aes256Gcm,
    Ss2022Blake3ChaCha20Poly1305,
}

impl SsCipherKind {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "aead_chacha20_poly1305" => {
                Ok(Self::ChaCha20Poly1305)
            }
            "2022-blake3-aes-128-gcm" => Ok(Self::Ss2022Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Ss2022Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Ss2022Blake3ChaCha20Poly1305),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks cipher '{other}'"),
            )),
        }
    }

    pub fn is_ss2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Blake3Aes128Gcm
                | Self::Ss2022Blake3Aes256Gcm
                | Self::Ss2022Blake3ChaCha20Poly1305
        )
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Blake3Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Ss2022Blake3Aes256Gcm
            | Self::Ss2022Blake3ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm | Self::Ss2022Blake3Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm | Self::Ss2022Blake3Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 | Self::Ss2022Blake3ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// Derive or decode the master key (`EVP_BytesToKey` for legacy AEAD; Standard Base64 PSK for SS-2022).
    pub fn master_key(self, password: &str) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.is_ss2022() {
            // Take last user PSK if EIH colon-chain is supplied, or single PSK
            let upsk_b64 = password.rsplit(':').next().unwrap_or(password).trim();
            let raw = STANDARD.decode(upsk_b64).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid SS-2022 base64 PSK: {e}"),
                )
            })?;
            if raw.len() != self.key_len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "SS-2022 cipher {:?} requires {}-byte PSK, got {} bytes",
                        self,
                        self.key_len(),
                        raw.len()
                    ),
                ));
            }
            Ok(Zeroizing::new(raw))
        } else {
            Ok(Zeroizing::new(evp_bytes_to_key(
                password.as_bytes(),
                self.key_len(),
            )))
        }
    }

    /// Derive per-stream or per-session AEAD subkey from `(master_key, salt)`.
    pub fn derive_subkey(self, master_key: &[u8], salt: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let key_len = self.key_len();
        if self.is_ss2022() {
            let mut material = Zeroizing::new(Vec::with_capacity(master_key.len() + salt.len()));
            material.extend_from_slice(master_key);
            material.extend_from_slice(salt);
            let derived = blake3::derive_key("shadowsocks 2022 session subkey", &material);
            Ok(Zeroizing::new(derived[..key_len].to_vec()))
        } else {
            let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
            let prk = hkdf_salt.extract(master_key);
            let info: [&[u8]; 1] = [b"ss-subkey"];
            let okm = prk
                .expand(&info, HkdfLen(key_len))
                .map_err(|_| io::Error::other("HKDF-SHA1 expand failed"))?;
            let mut subkey = Zeroizing::new(vec![0u8; key_len]);
            okm.fill(&mut subkey)
                .map_err(|_| io::Error::other("HKDF-SHA1 fill failed"))?;
            Ok(subkey)
        }
    }
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// OpenSSL-compatible `EVP_BytesToKey` with MD5 for legacy Shadowsocks AEAD passwords.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut md5 = Md5::new();
        if !prev.is_empty() {
            md5.update(&prev);
        }
        md5.update(password);
        let digest = md5.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

pub fn random_bytes(len: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| io::Error::other("CSPRNG failure"))?;
    Ok(out)
}

/// Little-Endian 96-bit nonce AEAD state (post-incremented starting from `[0u8; 12]`).
pub struct SsAeadCipher {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl SsAeadCipher {
    pub fn new(kind: SsCipherKind, master_key: &[u8], salt: &[u8]) -> io::Result<Self> {
        let subkey = kind.derive_subkey(master_key, salt)?;
        Self::from_raw_subkey(kind, &subkey)
    }

    pub fn from_raw_subkey(kind: SsCipherKind, subkey: &[u8]) -> io::Result<Self> {
        let unbound = UnboundKey::new(kind.algorithm(), subkey)
            .map_err(|_| io::Error::other("invalid Shadowsocks AEAD subkey"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce: [0u8; 12],
        })
    }

    fn take_and_increment_le_nonce(&mut self) -> [u8; 12] {
        let current = self.nonce;
        for b in &mut self.nonce {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        current
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.take_and_increment_le_nonce();
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::empty(), &mut out)
            .map_err(|_| io::Error::other("Shadowsocks AEAD seal failed"))?;
        Ok(out)
    }

    pub fn open(&mut self, ciphertext_and_tag: &[u8]) -> io::Result<Vec<u8>> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Shadowsocks AEAD chunk shorter than tag",
            ));
        }
        let n = self.take_and_increment_le_nonce();
        let mut buf = ciphertext_and_tag.to_vec();
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), &mut buf)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks AEAD authentication failed",
                )
            })?;
        let plain_len = plain.len();
        buf.truncate(plain_len);
        Ok(buf)
    }

    pub fn seal_with_nonce(&self, nonce: [u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut out)
            .map_err(|_| io::Error::other("Shadowsocks UDP AEAD seal failed"))?;
        Ok(out)
    }

    pub fn open_with_nonce(
        &self,
        nonce: [u8; 12],
        ciphertext_and_tag: &[u8],
    ) -> io::Result<Vec<u8>> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Shadowsocks UDP datagram shorter than tag",
            ));
        }
        let mut buf = ciphertext_and_tag.to_vec();
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks UDP AEAD authentication failed",
                )
            })?;
        let plain_len = plain.len();
        buf.truncate(plain_len);
        Ok(buf)
    }
}

/// Single-block AES-128/256 ECB encrypt for SS-2022 UDP 16-byte separate header.
pub fn aes_ecb_encrypt_block(key_bytes: &[u8], block: &[u8; 16]) -> io::Result<[u8; 16]> {
    let alg = match key_bytes.len() {
        16 => &cipher::AES_128,
        32 => &cipher::AES_256,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AES-ECB requires 16 or 32 byte key",
            ));
        }
    };
    let unbound = UnboundCipherKey::new(alg, key_bytes)
        .map_err(|_| io::Error::other("AES key init failed"))?;
    let enc_key =
        EncryptingKey::ecb(unbound).map_err(|_| io::Error::other("AES ECB init failed"))?;
    let mut out = *block;
    enc_key
        .encrypt(&mut out)
        .map_err(|_| io::Error::other("AES single-block encrypt failed"))?;
    Ok(out)
}

/// Single-block AES-128/256 ECB decrypt for SS-2022 UDP 16-byte separate header.
pub fn aes_ecb_decrypt_block(key_bytes: &[u8], ct_block: &[u8; 16]) -> io::Result<[u8; 16]> {
    let alg = match key_bytes.len() {
        16 => &cipher::AES_128,
        32 => &cipher::AES_256,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AES-ECB requires 16 or 32 byte key",
            ));
        }
    };
    let unbound = UnboundCipherKey::new(alg, key_bytes)
        .map_err(|_| io::Error::other("AES key init failed"))?;
    let dec_key =
        cipher::DecryptingKey::ecb(unbound).map_err(|_| io::Error::other("AES ECB init failed"))?;
    let mut out = *ct_block;
    dec_key
        .decrypt(&mut out, DecryptionContext::None)
        .map_err(|_| io::Error::other("AES single-block decrypt failed"))?;
    Ok(out)
}

/// RFC 8439 / draft-irtf-cfrg-xchacha HChaCha20 subkey derivation (for `2022-blake3-chacha20-poly1305` UDP XChaCha20-Poly1305).
pub fn xchacha20_poly1305_seal(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = Zeroizing::new(hchacha20(key, &n16));
    let mut n12 = [0u8; 12];
    n12[4..12].copy_from_slice(&nonce24[16..24]);
    let aead = SsAeadCipher::from_raw_subkey(SsCipherKind::ChaCha20Poly1305, subkey.as_ref())?;
    aead.seal_with_nonce(n12, plaintext)
}

pub fn xchacha20_poly1305_open(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = Zeroizing::new(hchacha20(key, &n16));
    let mut n12 = [0u8; 12];
    n12[4..12].copy_from_slice(&nonce24[16..24]);
    let aead = SsAeadCipher::from_raw_subkey(SsCipherKind::ChaCha20Poly1305, subkey.as_ref())?;
    aead.open_with_nonce(n12, ciphertext)
}

fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(nonce16[i * 4..i * 4 + 4].try_into().unwrap());
    }

    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    for (idx, &word_idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&state[word_idx].to_le_bytes());
    }
    out
}

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);

    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ecb_block_roundtrip() {
        for key_len in [16usize, 32usize] {
            let key = random_bytes(key_len).unwrap();
            let plain: [u8; 16] = random_bytes(16).unwrap().try_into().unwrap();
            let ct = aes_ecb_encrypt_block(&key, &plain).unwrap();
            assert_ne!(ct, plain);
            let dec = aes_ecb_decrypt_block(&key, &ct).unwrap();
            assert_eq!(dec, plain);
        }
    }

    #[test]
    fn xchacha20_poly1305_roundtrip() {
        let key: [u8; 32] = random_bytes(32).unwrap().try_into().unwrap();
        let nonce: [u8; 24] = random_bytes(24).unwrap().try_into().unwrap();
        let msg = b"Shadowsocks 2022 XChaCha20-Poly1305 UDP test";
        let ct = xchacha20_poly1305_seal(&key, &nonce, msg).unwrap();
        let opened = xchacha20_poly1305_open(&key, &nonce, &ct).unwrap();
        assert_eq!(opened, msg);
    }
}
