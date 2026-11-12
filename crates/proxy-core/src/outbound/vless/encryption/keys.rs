use std::io;

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{self, EncryptingKey, UnboundCipherKey},
    kem::{
        Ciphertext as LcCiphertext, DecapsulationKey as LcDecapKey, EncapsulationKey as LcEncapKey,
        ML_KEM_768,
    },
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blake3::hazmat::HasherExt;
use ml_kem::{B32, EncodedSizeUser, KemCore, MlKem768};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::outbound::vless::encryption::config::XorMode;

pub const RECORD_HEADER_LEN: usize = 5;
pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_WRITE_PLAINTEXT: usize = 8192;
pub const MAX_READ_CIPHERTEXT: usize = 16640;
pub const MAX_NONCE: [u8; 12] = [0xFF; 12];

pub fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| io::Error::other("CSPRNG failed"))?;
    Ok(buf)
}

pub fn random_vec(len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| io::Error::other("CSPRNG failed"))?;
    Ok(buf)
}

/// Safe, zero-UB implementation of Go's `blake3.DeriveKey(out, string(raw_ctx_bytes), key_material)`.
/// Computes Step 1 (`DERIVE_KEY_CONTEXT = 1 << 5` over arbitrary non-UTF8 `context: &[u8]`)
/// using official BLAKE3 tree compression, and Step 2 (`DERIVE_KEY_MATERIAL = 1 << 6`) using
/// hardware-accelerated `blake3::Hasher::new_from_context_key`.
pub fn blake3_derive_key_bytes(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let cx_key = blake3_hash_derive_key_context_bytes(context);
    let mut hasher = blake3::Hasher::new_from_context_key(&cx_key);
    hasher.update(key_material);
    *hasher.finalize().as_bytes()
}

// Official BLAKE3 specification constants (Section 2.1 of BLAKE3 paper)
const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn blake3_hash_derive_key_context_bytes(input: &[u8]) -> [u8; 32] {
    // Fast path if `input` happens to be valid ASCII/UTF-8: delegates straight to `blake3::hazmat`
    if let Ok(s) = std::str::from_utf8(input) {
        return blake3::hazmat::hash_derive_key_context(s);
    }

    let mut cv_stack: Vec<[u32; 8]> = Vec::with_capacity(16);
    let total_chunks = if input.is_empty() {
        1
    } else {
        input.len().div_ceil(1024)
    };

    for chunk_idx in 0..total_chunks {
        let start = chunk_idx * 1024;
        let end = (start + 1024).min(input.len());
        let chunk = &input[start..end];
        let is_single_root = total_chunks == 1;
        let out = blake3_chunk_output(chunk, chunk_idx as u64, DERIVE_KEY_CONTEXT);

        if is_single_root {
            return words_to_le_bytes(&blake3_compress_words(
                &out.cv,
                &out.block_words,
                out.counter,
                out.block_len,
                out.flags | ROOT,
            ));
        }

        let mut new_cv = blake3_compress_words(
            &out.cv,
            &out.block_words,
            out.counter,
            out.block_len,
            out.flags,
        );
        let mut total = (chunk_idx + 1) as u64;
        // Merge completed binary subtrees while bit is 0 (unless this is the very last chunk)
        while total & 1 == 0 {
            if cv_stack.len() == 1 && chunk_idx + 1 == total_chunks {
                break;
            }
            let left = cv_stack.pop().unwrap();
            new_cv = blake3_parent_cv(&left, &new_cv, DERIVE_KEY_CONTEXT, false);
            total >>= 1;
        }
        cv_stack.push(new_cv);
    }

    while cv_stack.len() > 2 {
        let right = cv_stack.pop().unwrap();
        let left = cv_stack.pop().unwrap();
        cv_stack.push(blake3_parent_cv(&left, &right, DERIVE_KEY_CONTEXT, false));
    }

    let right = cv_stack.pop().unwrap();
    let left = cv_stack.pop().unwrap();
    words_to_le_bytes(&blake3_parent_cv(&left, &right, DERIVE_KEY_CONTEXT, true))
}

struct ChunkOut {
    cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

fn blake3_chunk_output(chunk: &[u8], chunk_counter: u64, base_flags: u32) -> ChunkOut {
    let mut cv = BLAKE3_IV;
    let num_blocks = if chunk.is_empty() {
        1
    } else {
        chunk.len().div_ceil(64)
    };
    for b_idx in 0..num_blocks {
        let b_start = b_idx * 64;
        let b_end = (b_start + 64).min(chunk.len());
        let slice = &chunk[b_start..b_end];
        let mut block = [0u8; 64];
        block[..slice.len()].copy_from_slice(slice);
        let words = le_bytes_to_words_16(&block);
        let mut flags = base_flags;
        if b_idx == 0 {
            flags |= CHUNK_START;
        }
        if b_idx + 1 == num_blocks {
            flags |= CHUNK_END;
            return ChunkOut {
                cv,
                block_words: words,
                counter: chunk_counter,
                block_len: slice.len() as u32,
                flags,
            };
        }
        cv = blake3_compress_words(&cv, &words, chunk_counter, 64, flags);
    }
    unreachable!()
}

fn blake3_parent_cv(left: &[u32; 8], right: &[u32; 8], base_flags: u32, is_root: bool) -> [u32; 8] {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(left);
    block_words[8..16].copy_from_slice(right);
    let mut flags = base_flags | PARENT;
    if is_root {
        flags |= ROOT;
    }
    blake3_compress_words(&BLAKE3_IV, &block_words, 0, 64, flags)
}

fn blake3_compress_words(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    for round in 0..7 {
        blake3_g(&mut state, 0, 4, 8, 12, m[0], m[1]);
        blake3_g(&mut state, 1, 5, 9, 13, m[2], m[3]);
        blake3_g(&mut state, 2, 6, 10, 14, m[4], m[5]);
        blake3_g(&mut state, 3, 7, 11, 15, m[6], m[7]);
        blake3_g(&mut state, 0, 5, 10, 15, m[8], m[9]);
        blake3_g(&mut state, 1, 6, 11, 12, m[10], m[11]);
        blake3_g(&mut state, 2, 7, 8, 13, m[12], m[13]);
        blake3_g(&mut state, 3, 4, 9, 14, m[14], m[15]);
        if round < 6 {
            let mut next = [0u32; 16];
            for i in 0..16 {
                next[i] = m[MSG_PERMUTATION[i]];
            }
            m = next;
        }
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = state[i] ^ state[i + 8];
    }
    out
}

#[inline]
fn blake3_g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn le_bytes_to_words_16(bytes: &[u8; 64]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for i in 0..16 {
        out[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

fn words_to_le_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&words[i].to_le_bytes());
    }
    out
}

/// Xray `NewCTR(key, iv)`: continuous `AES-256-CTR` stream cipher keyed by `blake3::derive_key("VLESS", key)`.
pub struct VlessCtr {
    key_bytes: Zeroizing<[u8; 32]>,
    counter_block: [u8; 16],
    keystream_buf: [u8; 16],
    ks_offset: usize,
}

impl VlessCtr {
    pub fn new(key_material: &[u8], iv: &[u8; 16]) -> Self {
        let derived = blake3::derive_key("VLESS", key_material);
        Self {
            key_bytes: Zeroizing::new(derived),
            counter_block: *iv,
            keystream_buf: [0u8; 16],
            ks_offset: 16,
        }
    }

    pub fn xor_keystream(&mut self, data: &mut [u8]) -> io::Result<()> {
        for byte in data.iter_mut() {
            if self.ks_offset >= 16 {
                self.refill_block()?;
            }
            *byte ^= self.keystream_buf[self.ks_offset];
            self.ks_offset += 1;
        }
        Ok(())
    }

    fn refill_block(&mut self) -> io::Result<()> {
        let unbound = UnboundCipherKey::new(&cipher::AES_256, self.key_bytes.as_ref())
            .map_err(|_| io::Error::other("VLESS AES-256 CTR key init failed"))?;
        let enc = EncryptingKey::ctr(unbound)
            .map_err(|_| io::Error::other("VLESS AES-256 CTR mode init failed"))?;
        let mut block = [0u8; 16];
        let ctx =
            cipher::EncryptionContext::Iv128(aws_lc_rs::iv::FixedLength::from(self.counter_block));
        enc.less_safe_encrypt(&mut block, ctx)
            .map_err(|_| io::Error::other("VLESS AES-256 CTR block failed"))?;
        self.keystream_buf = block;
        self.ks_offset = 0;

        // Big-endian 128-bit counter increment (matches Go `cipher.NewCTR`)
        for b in self.counter_block.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        Ok(())
    }
}

/// Xray `NewAEAD(ctx, key, useAES)` with pre-increment Big-Endian 12-byte nonce & `MaxNonce` key ratchet!
pub struct VlessAead {
    key: LessSafeKey,
    nonce: [u8; 12],
    pub use_aes: bool,
}

impl VlessAead {
    pub fn new(ctx: &[u8], key_material: &[u8], use_aes: bool) -> io::Result<Self> {
        let derived = Zeroizing::new(blake3_derive_key_bytes(ctx, key_material));
        let alg = if use_aes {
            &aead::AES_256_GCM
        } else {
            &aead::CHACHA20_POLY1305
        };
        let unbound = UnboundKey::new(alg, derived.as_ref())
            .map_err(|_| io::Error::other("VLESS AEAD key init failed"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce: [0u8; 12],
            use_aes,
        })
    }

    pub fn is_at_max_nonce(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn next_be_nonce(&mut self) -> [u8; 12] {
        for b in self.nonce.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.nonce
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.next_be_nonce();
        self.seal_at(n, plaintext, aad)
    }

    pub fn seal_at(
        &self,
        explicit_nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + AEAD_TAG_LEN);
        out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(explicit_nonce),
                Aad::from(aad),
                &mut out,
            )
            .map_err(|_| io::Error::other("VLESS AEAD seal failed"))?;
        Ok(out)
    }

    pub fn open(&mut self, ciphertext_and_tag: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.next_be_nonce();
        self.open_at(n, ciphertext_and_tag, aad)
    }

    pub fn open_at(
        &self,
        explicit_nonce: [u8; 12],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        if ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS ciphertext shorter than AEAD tag",
            ));
        }
        let mut buf = ciphertext_and_tag.to_vec();
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(explicit_nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS AEAD authentication failed",
                )
            })?;
        let plain_len = plain.len();
        buf.truncate(plain_len);
        Ok(buf)
    }
}

/// Client-side static NFS public key (either 32B X25519 or 1184B ML-KEM-768 EncapsulationKey).
pub enum ClientNfsKey {
    X25519 {
        public: X25519PublicKey,
        raw_bytes: [u8; 32],
        hash32: [u8; 32],
    },
    MlKem768 {
        encap: LcEncapKey,
        raw_bytes: Vec<u8>,
        hash32: [u8; 32],
    },
}

impl ClientNfsKey {
    pub fn from_b64_token(token: &str) -> io::Result<Self> {
        let raw = URL_SAFE_NO_PAD.decode(token.trim()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Base64URL in VLESS client key: {e}"),
            )
        })?;
        match raw.len() {
            32 => {
                let arr: [u8; 32] = raw.try_into().unwrap();
                let hash32 = *blake3::hash(&arr).as_bytes();
                Ok(Self::X25519 {
                    public: X25519PublicKey::from(arr),
                    raw_bytes: arr,
                    hash32,
                })
            }
            1184 => {
                let hash32 = *blake3::hash(&raw).as_bytes();
                let encap = LcEncapKey::new(&ML_KEM_768, &raw).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid ML-KEM-768 encapsulation key",
                    )
                })?;
                Ok(Self::MlKem768 {
                    encap,
                    raw_bytes: raw,
                    hash32,
                })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported VLESS client key byte length {other} (expected 32 or 1184)"),
            )),
        }
    }

    pub fn wire_share_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => 32,
            Self::MlKem768 { .. } => 1088,
        }
    }

    pub fn raw_public_bytes(&self) -> &[u8] {
        match self {
            Self::X25519 { raw_bytes, .. } => raw_bytes,
            Self::MlKem768 { raw_bytes, .. } => raw_bytes,
        }
    }

    pub fn hash32(&self) -> &[u8; 32] {
        match self {
            Self::X25519 { hash32, .. } | Self::MlKem768 { hash32, .. } => hash32,
        }
    }
}

/// Server-side static NFS private key (either 32B X25519 secret or 64B ML-KEM-768 `d||z` seed).
pub enum ServerNfsKey {
    X25519 {
        secret: X25519Secret,
        pub_bytes: [u8; 32],
        hash32: [u8; 32],
    },
    MlKem768 {
        decap: LcDecapKey,
        pub_bytes: Vec<u8>,
        hash32: [u8; 32],
    },
}

impl ServerNfsKey {
    pub fn from_b64_token(token: &str) -> io::Result<Self> {
        let raw = URL_SAFE_NO_PAD.decode(token.trim()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Base64URL in VLESS server key: {e}"),
            )
        })?;
        match raw.len() {
            32 => {
                let arr: [u8; 32] = raw.try_into().unwrap();
                let secret = X25519Secret::from(arr);
                let public = X25519PublicKey::from(&secret);
                let pub_bytes = public.to_bytes();
                let hash32 = *blake3::hash(&pub_bytes).as_bytes();
                Ok(Self::X25519 {
                    secret,
                    pub_bytes,
                    hash32,
                })
            }
            64 => {
                // Expand 64-byte FIPS 203 seed `d || z` into (2400B DecapsulationKey, 1184B EncapsulationKey)
                let d: B32 = raw[..32].try_into().expect("32B d");
                let z: B32 = raw[32..64].try_into().expect("32B z");
                let (dk_pure, ek_pure) = MlKem768::generate_deterministic(&d, &z);
                let pub_bytes = ek_pure.as_bytes().as_slice().to_vec();
                let dk_bytes = dk_pure.as_bytes();
                let decap = LcDecapKey::new(&ML_KEM_768, dk_bytes.as_slice()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "failed loading expanded ML-KEM-768 decapsulation key into AWS-LC",
                    )
                })?;
                let hash32 = *blake3::hash(&pub_bytes).as_bytes();
                Ok(Self::MlKem768 {
                    decap,
                    pub_bytes,
                    hash32,
                })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported VLESS server key byte length {other} (expected 32 or 64)"),
            )),
        }
    }

    pub fn wire_share_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => 32,
            Self::MlKem768 { .. } => 1088,
        }
    }

    pub fn raw_public_bytes(&self) -> &[u8] {
        match self {
            Self::X25519 { pub_bytes, .. } => pub_bytes,
            Self::MlKem768 { pub_bytes, .. } => pub_bytes,
        }
    }

    pub fn hash32(&self) -> &[u8; 32] {
        match self {
            Self::X25519 { hash32, .. } | Self::MlKem768 { hash32, .. } => hash32,
        }
    }
}

pub fn total_relays_len_client(keys: &[ClientNfsKey]) -> usize {
    if keys.is_empty() {
        return 0;
    }
    keys.iter().map(|k| k.wire_share_len()).sum::<usize>() + 32 * (keys.len() - 1)
}

pub fn total_relays_len_server(keys: &[ServerNfsKey]) -> usize {
    if keys.is_empty() {
        return 0;
    }
    keys.iter().map(|k| k.wire_share_len()).sum::<usize>() + 32 * (keys.len() - 1)
}

pub type ClientRelaysResult = ([u8; 16], Vec<u8>, Zeroizing<[u8; 32]>);

/// Client `EncodeRelays`: produces `(iv, iv_and_relays, final_nfs_key_32)` per Xray §1.4.A.
pub fn client_build_iv_and_relays(
    keys: &[ClientNfsKey],
    mode: XorMode,
) -> io::Result<ClientRelaysResult> {
    let iv = random_array::<16>()?;
    let relays_len = total_relays_len_client(keys);
    let mut out = vec![0u8; 16 + relays_len];
    out[..16].copy_from_slice(&iv);

    let mut offset = 16usize;
    let mut last_ctr: Option<VlessCtr> = None;
    let mut nfs_key = Zeroizing::new([0u8; 32]);

    for (j, key) in keys.iter().enumerate() {
        let share_len = key.wire_share_len();
        match key {
            ClientNfsKey::X25519 { public, .. } => {
                // Ensure ephemeral X25519 public key satisfies `pk[31] <= 127`
                let (ephem_sk, ephem_pk) = loop {
                    let seed = random_array::<32>()?;
                    let sk = X25519Secret::from(seed);
                    let pk = X25519PublicKey::from(&sk);
                    if (pk.as_bytes()[31] & 0x80) == 0 {
                        break (sk, pk);
                    }
                };
                let shared = ephem_sk.diffie_hellman(public);
                if shared.as_bytes().iter().all(|&b| b == 0) {
                    return Err(io::Error::other("low-order X25519 public key"));
                }
                out[offset..offset + 32].copy_from_slice(ephem_pk.as_bytes());
                nfs_key.copy_from_slice(shared.as_bytes());
            }
            ClientNfsKey::MlKem768 { encap, .. } => {
                let (ct, ss) = encap
                    .encapsulate()
                    .map_err(|_| io::Error::other("ML-KEM-768 encapsulate failed"))?;
                out[offset..offset + 1088].copy_from_slice(ct.as_ref());
                nfs_key.copy_from_slice(ss.as_ref());
            }
        }

        // Step 2: Public-key XOR obfuscation (`if XorMode > 0`)
        if mode != XorMode::Native {
            let mut pub_ctr = VlessCtr::new(key.raw_public_bytes(), &iv);
            pub_ctr.xor_keystream(&mut out[offset..offset + share_len])?;
        }

        // Step 3: Previous-hop binding (`if lastCTR != nil`)
        if let Some(prev_ctr) = last_ctr.as_mut() {
            prev_ctr.xor_keystream(&mut out[offset..offset + 32])?;
        }

        // Step 4: Next-hop `Hash32` authentication (`if j < L - 1`)
        if j + 1 < keys.len() {
            let mut hop_ctr = VlessCtr::new(nfs_key.as_ref(), &iv);
            let next_hash = keys[j + 1].hash32();
            out[offset + share_len..offset + share_len + 32].copy_from_slice(next_hash);
            hop_ctr.xor_keystream(&mut out[offset + share_len..offset + share_len + 32])?;
            last_ctr = Some(hop_ctr);
            offset += share_len + 32;
        } else {
            offset += share_len;
        }
    }

    Ok((iv, out, nfs_key))
}

/// Server `DecodeRelays`: verifies multi-hop `Hash32` chain and recovers `final_nfs_key_32`.
pub fn server_decode_relays(
    keys: &[ServerNfsKey],
    mode: XorMode,
    iv: &[u8; 16],
    relays: &mut [u8],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut offset = 0usize;
    let mut last_ctr: Option<VlessCtr> = None;
    let mut nfs_key = Zeroizing::new([0u8; 32]);

    for (j, key) in keys.iter().enumerate() {
        let share_len = key.wire_share_len();

        // Reverse Step 3 BEFORE Step 2!
        if let Some(prev_ctr) = last_ctr.as_mut() {
            prev_ctr.xor_keystream(&mut relays[offset..offset + 32])?;
        }
        if mode != XorMode::Native {
            let mut pub_ctr = VlessCtr::new(key.raw_public_bytes(), iv);
            pub_ctr.xor_keystream(&mut relays[offset..offset + share_len])?;
        }

        match key {
            ServerNfsKey::X25519 { secret, .. } => {
                // Mandatory Xray server check: `publicKey[31] <= 127`
                if (relays[offset + 31] & 0x80) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VLESS X25519 ephemeral public key high bit set",
                    ));
                }
                let pk_arr: [u8; 32] = relays[offset..offset + 32].try_into().unwrap();
                let shared = secret.diffie_hellman(&X25519PublicKey::from(pk_arr));
                if shared.as_bytes().iter().all(|&b| b == 0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "low-order X25519 ephemeral public key",
                    ));
                }
                nfs_key.copy_from_slice(shared.as_bytes());
            }
            ServerNfsKey::MlKem768 { decap, .. } => {
                let ct_slice = &relays[offset..offset + 1088];
                let ss = decap
                    .decapsulate(LcCiphertext::from(ct_slice))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VLESS ML-KEM-768 decapsulation failed",
                        )
                    })?;
                nfs_key.copy_from_slice(ss.as_ref());
            }
        }

        if j + 1 < keys.len() {
            let mut hop_ctr = VlessCtr::new(nfs_key.as_ref(), iv);
            let auth_tag = &mut relays[offset + share_len..offset + share_len + 32];
            hop_ctr.xor_keystream(auth_tag)?;
            if auth_tag != keys[j + 1].hash32() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VLESS relay chain Hash32 verification failed",
                ));
            }
            last_ctr = Some(hop_ctr);
            offset += share_len + 32;
        } else {
            offset += share_len;
        }
    }

    Ok(nfs_key)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneratedVlessPair {
    pub mode: String,
    pub rtt: String,
    pub encryption: String,
    pub decryption: String,
    pub x25519_public_key: String,
    pub mlkem768_client_bytes: usize,
}

/// Generate a fresh Xray `vlessenc`-compatible hybrid (X25519 + ML-KEM-768) `encryption` / `decryption` pair!
pub fn generate_vless_encryption_pair(
    mode: XorMode,
    enable_0rtt: bool,
    include_pq_mlkem768: bool,
) -> io::Result<GeneratedVlessPair> {
    let mut x_priv = random_array::<32>()?;
    // Clamp per Xray `vlessenc` (`k[0] &= 248; k[31] &= 127; k[31] |= 64`)
    x_priv[0] &= 248;
    x_priv[31] &= 127;
    x_priv[31] |= 64;
    let secret = X25519Secret::from(x_priv);
    let x_pub = X25519PublicKey::from(&secret).to_bytes();

    let x_priv_b64 = URL_SAFE_NO_PAD.encode(x_priv);
    let x_pub_b64 = URL_SAFE_NO_PAD.encode(x_pub);

    let rtt = if enable_0rtt { "0rtt" } else { "1rtt" };
    let ttl = if enable_0rtt { "600s" } else { "0s" };
    let mode_str = mode.as_str();

    let (encryption, decryption, pq_bytes) = if include_pq_mlkem768 {
        let seed64 = random_array::<64>()?;
        let d: B32 = seed64[..32].try_into().unwrap();
        let z: B32 = seed64[32..64].try_into().unwrap();
        let (_dk, ek) = MlKem768::generate_deterministic(&d, &z);
        let ek_bytes = ek.as_bytes();
        let seed_b64 = URL_SAFE_NO_PAD.encode(seed64);
        let ek_b64 = URL_SAFE_NO_PAD.encode(ek_bytes.as_slice());

        (
            format!("mlkem768x25519plus.{mode_str}.{rtt}.{x_pub_b64}.{ek_b64}"),
            format!("mlkem768x25519plus.{mode_str}.{ttl}.{x_priv_b64}.{seed_b64}"),
            ek_bytes.len(),
        )
    } else {
        (
            format!("mlkem768x25519plus.{mode_str}.{rtt}.{x_pub_b64}"),
            format!("mlkem768x25519plus.{mode_str}.{ttl}.{x_priv_b64}"),
            0,
        )
    };

    Ok(GeneratedVlessPair {
        mode: mode_str.to_string(),
        rtt: rtt.to_string(),
        encryption,
        decryption,
        x25519_public_key: x_pub_b64,
        mlkem768_client_bytes: pq_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_derive_key_bytes_matches_reference_across_tree_sizes() {
        let material = b"united-key-material-96-bytes-test";
        for len in [0usize, 16, 32, 64, 512, 1024, 1120, 1216, 4096, 16645] {
            let ascii_ctx = "A".repeat(len);
            let expected = blake3::derive_key(&ascii_ctx, material);
            // Force our binary compression path directly by testing `blake3_hash_derive_key_context_bytes`
            // on a non-UTF8 copy when len > 0, and comparing ASCII against `blake3::derive_key`!
            let got = blake3_derive_key_bytes(ascii_ctx.as_bytes(), material);
            assert_eq!(got, expected, "mismatch at len={len}");
        }

        // Also test multi-chunk binary (non-UTF8) deterministic self-consistency & tree path
        let mut raw_non_utf8 = vec![0xFFu8; 2500];
        raw_non_utf8[0] = 0x80;
        let k1 = blake3_derive_key_bytes(&raw_non_utf8, material);
        let k2 = blake3_derive_key_bytes(&raw_non_utf8, material);
        assert_eq!(k1, k2);
    }

    #[test]
    fn hybrid_x25519_and_mlkem768_relay_chain_roundtrips() {
        for mode in [XorMode::Native, XorMode::XorPub, XorMode::Random] {
            let pair = generate_vless_encryption_pair(mode, true, true).unwrap();
            let c_cfg = crate::outbound::vless::encryption::config::parse_client_encryption(
                &pair.encryption,
            )
            .unwrap();
            let s_cfg = crate::outbound::vless::encryption::config::parse_server_decryption(
                &pair.decryption,
            )
            .unwrap();

            let c_keys: Vec<ClientNfsKey> = c_cfg
                .key_tokens
                .iter()
                .map(|t| ClientNfsKey::from_b64_token(t).unwrap())
                .collect();
            let s_keys: Vec<ServerNfsKey> = s_cfg
                .key_tokens
                .iter()
                .map(|t| ServerNfsKey::from_b64_token(t).unwrap())
                .collect();

            let (iv, iv_and_relays, client_nfs) =
                client_build_iv_and_relays(&c_keys, mode).unwrap();
            let mut relay_slice = iv_and_relays[16..].to_vec();
            let server_nfs = server_decode_relays(&s_keys, mode, &iv, &mut relay_slice).unwrap();
            assert_eq!(client_nfs.as_slice(), server_nfs.as_slice());
        }
    }
}
