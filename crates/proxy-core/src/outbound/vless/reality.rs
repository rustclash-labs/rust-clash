use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker, ready},
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    digest::{Context as DigestContext, SHA256, SHA384, digest},
    hmac,
    kem::{
        Ciphertext as LcCiphertext, DecapsulationKey as LcDecapKey, EncapsulationKey as LcEncapKey,
        ML_KEM_768,
    },
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, Ed25519KeyPair, KeyPair,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
        UnparsedPublicKey,
    },
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use bytes::{Buf, BufMut, BytesMut};
use rand::RngCore;
use rustls::{
    client::WebPkiServerVerifier,
    client::danger::ServerCertVerifier,
    crypto::aws_lc_rs::default_provider,
    pki_types::{CertificateDer, UnixTime},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_RECORD_ALERT: u8 = 0x15;
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;

const TLS_HS_CLIENT_HELLO: u8 = 0x01;
const TLS_HS_SERVER_HELLO: u8 = 0x02;
const TLS_HS_NEW_SESSION_TICKET: u8 = 0x04;
const TLS_HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const TLS_HS_CERTIFICATE: u8 = 0x0b;
const TLS_HS_CERTIFICATE_VERIFY: u8 = 0x0f;
const TLS_HS_FINISHED: u8 = 0x14;
const TLS_HS_KEY_UPDATE: u8 = 0x18;

const MAX_POST_HANDSHAKE_BUF: usize = 64 * 1024;

const CIPHER_TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const CIPHER_TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const CIPHER_TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
    pub fingerprint: String,
    pub spider_x: String,
    pub alpn: Vec<Vec<u8>>,
}

pub fn decode_reality_public_key(raw: &str) -> io::Result<[u8; 32]> {
    let s = raw.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid REALITY base64 public-key: {e}"),
            )
        })?;
    if decoded.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "REALITY public-key must decode to 32 bytes (got {})",
                decoded.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn decode_reality_short_id(raw: &str) -> io::Result<[u8; 8]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok([0u8; 8]);
    }
    if trimmed.len() > 16 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("REALITY short-id '{trimmed}' must be 0..=16 hex digits"),
        ));
    }
    let padded = if trimmed.len() % 2 == 1 {
        format!("0{trimmed}")
    } else {
        trimmed.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid REALITY short-id hex: {e}"),
        )
    })?;
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Clone)]
pub enum Tls13HandshakeMode {
    Reality(RealityClientConfig),
    StandardTls {
        server_name: String,
        skip_cert_verify: bool,
        extra_ca_der: Vec<CertificateDer<'static>>,
        alpn: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Copy)]
enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => digest(&SHA256, data).as_ref().to_vec(),
            Self::Sha384 => digest(&SHA384, data).as_ref().to_vec(),
        }
    }

    fn hmac_sign(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let alg = match self {
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
        };
        let k = hmac::Key::new(alg, key);
        hmac::sign(&k, msg).as_ref().to_vec()
    }
}

#[derive(Clone)]
struct TranscriptHash {
    ctx: DigestContext,
}

impl TranscriptHash {
    fn new(alg: HashAlg) -> Self {
        let ctx = match alg {
            HashAlg::Sha256 => DigestContext::new(&SHA256),
            HashAlg::Sha384 => DigestContext::new(&SHA384),
        };
        Self { ctx }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.ctx.update(bytes);
    }

    fn current_hash(&self) -> Vec<u8> {
        self.ctx.clone().finish().as_ref().to_vec()
    }
}

fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zero_salt;
    let eff_salt = if salt.is_empty() {
        zero_salt = vec![0u8; alg.len()];
        zero_salt.as_slice()
    } else {
        salt
    };
    alg.hmac_sign(eff_salt, ikm)
}

fn hkdf_expand(alg: HashAlg, prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hash_len = alg.len();
    let n = out_len.div_ceil(hash_len);
    let mut okm = Vec::with_capacity(n * hash_len);
    let mut prev = Vec::new();
    for counter in 1..=(n as u8) {
        let mut msg = Vec::with_capacity(prev.len() + info.len() + 1);
        msg.extend_from_slice(&prev);
        msg.extend_from_slice(info);
        msg.push(counter);
        prev = alg.hmac_sign(prk, &msg);
        okm.extend_from_slice(&prev);
    }
    okm.truncate(out_len);
    okm
}

fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let full_label_len = 6 + label.len();
    let mut hkdf_label = Vec::with_capacity(4 + full_label_len + context.len());
    hkdf_label.extend_from_slice(&(out_len as u16).to_be_bytes());
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    hkdf_expand(alg, secret, &hkdf_label, out_len)
}

fn derive_secret(alg: HashAlg, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(alg, secret, label, transcript_hash, alg.len())
}

#[derive(Clone, Copy)]
struct SuiteParams {
    id: u16,
    hash: HashAlg,
    key_len: usize,
}

impl SuiteParams {
    fn from_id(id: u16) -> io::Result<Self> {
        match id {
            CIPHER_TLS_AES_128_GCM_SHA256 => Ok(Self {
                id,
                hash: HashAlg::Sha256,
                key_len: 16,
            }),
            CIPHER_TLS_AES_256_GCM_SHA384 => Ok(Self {
                id,
                hash: HashAlg::Sha384,
                key_len: 32,
            }),
            CIPHER_TLS_CHACHA20_POLY1305_SHA256 => Ok(Self {
                id,
                hash: HashAlg::Sha256,
                key_len: 32,
            }),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported TLS 1.3 cipher suite 0x{other:04x}"),
            )),
        }
    }
}

struct RecordTrafficKeys {
    suite: SuiteParams,
    secret: Vec<u8>,
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordTrafficKeys {
    fn from_traffic_secret(suite: SuiteParams, secret: Vec<u8>) -> io::Result<Self> {
        let key_bytes = hkdf_expand_label(suite.hash, &secret, b"key", &[], suite.key_len);
        let iv_vec = hkdf_expand_label(suite.hash, &secret, b"iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);

        let aead_alg = match suite.id {
            CIPHER_TLS_AES_128_GCM_SHA256 => &AES_128_GCM,
            CIPHER_TLS_AES_256_GCM_SHA384 => &AES_256_GCM,
            CIPHER_TLS_CHACHA20_POLY1305_SHA256 => &CHACHA20_POLY1305,
            _ => unreachable!(),
        };
        let unbound = UnboundKey::new(aead_alg, &key_bytes)
            .map_err(|_| io::Error::other("TLS 1.3 record key init failed"))?;
        Ok(Self {
            suite,
            secret,
            key: LessSafeKey::new(unbound),
            iv,
            seq: 0,
        })
    }

    fn roll_key_update(&mut self) -> io::Result<()> {
        let next_secret = hkdf_expand_label(
            self.suite.hash,
            &self.secret,
            b"traffic upd",
            &[],
            self.suite.hash.len(),
        );
        *self = Self::from_traffic_secret(self.suite, next_secret)?;
        Ok(())
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        self.seq = self.seq.wrapping_add(1);
        Nonce::assume_unique_for_key(nonce)
    }

    fn seal_record(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        out: &mut BytesMut,
    ) -> io::Result<()> {
        let cipher_len = plaintext.len() + 1 + 16;
        if cipher_len > 16384 + 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS 1.3 plaintext record exceeds RFC 8446 limit",
            ));
        }
        let header = [
            TLS_RECORD_APPLICATION_DATA,
            0x03,
            0x03,
            (cipher_len >> 8) as u8,
            cipher_len as u8,
        ];
        out.reserve(5 + cipher_len);
        out.put_slice(&header);
        let body_start = out.len();
        out.put_slice(plaintext);
        out.put_u8(content_type);
        let mut body = out.split_off(body_start);
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(&header), &mut body)
            .map_err(|_| io::Error::other("TLS 1.3 record AEAD seal failed"))?;
        out.unsplit(body);
        Ok(())
    }

    fn open_record(&mut self, header: &[u8; 5], ciphertext: &mut [u8]) -> io::Result<(u8, usize)> {
        if ciphertext.len() < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 ciphertext record too short",
            ));
        }
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(header), ciphertext)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS 1.3 record authentication tag mismatch",
                )
            })?;
        // Strip zero padding from TLSInnerPlaintext to find inner content_type byte
        let Some(type_pos) = plain.iter().rposition(|&b| b != 0) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 inner plaintext missing content type byte",
            ));
        };
        let inner_type = plain[type_pos];
        Ok((inner_type, type_pos))
    }
}

fn build_client_hello_handshake(
    sni: &str,
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    mlkem_ek_and_x25519: &[u8],
    x25519_pub: &[u8; 32],
    alpn: &[Vec<u8>],
) -> BytesMut {
    let mut exts = BytesMut::with_capacity(1450);

    // 1. server_name (0x0000) if `sni` is a DNS hostname (not an IP literal)
    let clean_sni = sni.trim().trim_start_matches('[').trim_end_matches(']');
    if !clean_sni.is_empty() && clean_sni.parse::<std::net::IpAddr>().is_err() {
        let host_b = clean_sni.as_bytes();
        let list_len = 3 + host_b.len();
        let ext_len = 2 + list_len;
        exts.put_u16(0x0000);
        exts.put_u16(ext_len as u16);
        exts.put_u16(list_len as u16);
        exts.put_u8(0x00);
        exts.put_u16(host_b.len() as u16);
        exts.put_slice(host_b);
    }

    // 2. extended_master_secret (0x0017)
    exts.put_u16(0x0017);
    exts.put_u16(0x0000);

    // 3. renegotiation_info (0xff01)
    exts.put_u16(0xff01);
    exts.put_u16(0x0001);
    exts.put_u8(0x00);

    // 4. supported_groups (0x000a): X25519MLKEM768 (0x11ec), X25519 (0x001d), P-256 (0x0017), P-384 (0x0018)
    exts.put_u16(0x000a);
    exts.put_u16(10);
    exts.put_u16(8);
    exts.put_u16(GROUP_X25519_MLKEM768);
    exts.put_u16(GROUP_X25519);
    exts.put_u16(0x0017);
    exts.put_u16(0x0018);

    // 5. ec_point_formats (0x000b)
    exts.put_u16(0x000b);
    exts.put_u16(2);
    exts.put_u8(1);
    exts.put_u8(0);

    // 6. ALPN (0x0010)
    let default_alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let mut alpn_list = BytesMut::new();
    if alpn.is_empty() {
        for proto in default_alpn {
            alpn_list.put_u8(proto.len() as u8);
            alpn_list.put_slice(proto);
        }
    } else {
        for proto in alpn {
            if !proto.is_empty() && proto.len() <= 255 {
                alpn_list.put_u8(proto.len() as u8);
                alpn_list.put_slice(proto);
            }
        }
    }
    if !alpn_list.is_empty() {
        exts.put_u16(0x0010);
        exts.put_u16((2 + alpn_list.len()) as u16);
        exts.put_u16(alpn_list.len() as u16);
        exts.put_slice(&alpn_list);
    }

    // 7. status_request (0x0005)
    exts.put_u16(0x0005);
    exts.put_u16(5);
    exts.put_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);

    // 8. signature_algorithms (0x000d)
    let sig_algs: [u16; 9] = [
        0x0403, // ecdsa_secp256r1_sha256
        0x0804, // rsa_pss_rsae_sha256
        0x0401, // rsa_pkcs1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0805, // rsa_pss_rsae_sha384
        0x0501, // rsa_pkcs1_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0601, // rsa_pkcs1_sha512
        0x0807, // ed25519
    ];
    exts.put_u16(0x000d);
    exts.put_u16((2 + sig_algs.len() * 2) as u16);
    exts.put_u16((sig_algs.len() * 2) as u16);
    for alg in sig_algs {
        exts.put_u16(alg);
    }

    // 9. supported_versions (0x002b): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    exts.put_u16(0x002b);
    exts.put_u16(5);
    exts.put_u8(4);
    exts.put_u16(0x0304);
    exts.put_u16(0x0303);

    // 10. psk_key_exchange_modes (0x002d): psk_dhe_ke (0x01)
    exts.put_u16(0x002d);
    exts.put_u16(2);
    exts.put_u8(1);
    exts.put_u8(0x01);

    // 11. key_share (0x0033): X25519MLKEM768 (1216B) FIRST, followed by X25519 (32B),
    // matching Chrome 131+ & Xray-core v26 REALITY server validation rules!
    let ks_entries_len = (4 + mlkem_ek_and_x25519.len()) + (4 + x25519_pub.len());
    exts.put_u16(0x0033);
    exts.put_u16((2 + ks_entries_len) as u16);
    exts.put_u16(ks_entries_len as u16);
    exts.put_u16(GROUP_X25519_MLKEM768);
    exts.put_u16(mlkem_ek_and_x25519.len() as u16);
    exts.put_slice(mlkem_ek_and_x25519);
    exts.put_u16(GROUP_X25519);
    exts.put_u16(x25519_pub.len() as u16);
    exts.put_slice(x25519_pub);

    // Cipher suites (Chrome-compatible list led by TLS 1.3 AEAD suites)
    let suites: [u16; 9] = [
        CIPHER_TLS_AES_128_GCM_SHA256,
        CIPHER_TLS_AES_256_GCM_SHA384,
        CIPHER_TLS_CHACHA20_POLY1305_SHA256,
        0xc02b,
        0xc02f,
        0xc02c,
        0xc030,
        0xcca9,
        0xcca8,
    ];

    let mut body = BytesMut::with_capacity(128 + exts.len());
    body.put_u16(0x0303); // legacy_version = TLS 1.2
    body.put_slice(client_random); // [2..34]
    body.put_u8(32); // legacy_session_id length = 32 -> session_id at body[35..67], msg[39..71]
    body.put_slice(session_id);
    body.put_u16((suites.len() * 2) as u16);
    for s in suites {
        body.put_u16(s);
    }
    body.put_u8(1); // compression_methods len = 1
    body.put_u8(0); // null compression
    body.put_u16(exts.len() as u16);
    body.put_slice(&exts);

    let mut hs = BytesMut::with_capacity(4 + body.len());
    hs.put_u8(TLS_HS_CLIENT_HELLO);
    let len = body.len() as u32;
    hs.put_u8((len >> 16) as u8);
    hs.put_u8((len >> 8) as u8);
    hs.put_u8(len as u8);
    hs.put_slice(&body);
    hs
}

struct ParsedServerHello {
    cipher_suite: u16,
    key_share_group: u16,
    key_share_data: Vec<u8>,
}

fn parse_server_hello(body: &[u8]) -> io::Result<ParsedServerHello> {
    if body.len() < 38 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS ServerHello body too short",
        ));
    }
    let legacy_ver = u16::from_be_bytes([body[0], body[1]]);
    if legacy_ver != 0x0303 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected ServerHello legacy_version 0x{legacy_ver:04x}"),
        ));
    }
    if body[2..34] == HELLO_RETRY_REQUEST_RANDOM {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TLS 1.3 server requested HelloRetryRequest despite X25519MLKEM768+X25519 key shares",
        ));
    }
    let sid_len = body[34] as usize;
    let mut pos = 35 + sid_len;
    if body.len() < pos + 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated TLS ServerHello before cipher_suite",
        ));
    }
    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    let comp = body[pos + 2];
    if comp != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS 1.3 ServerHello compression method",
        ));
    }
    pos += 3;
    if body.len() < pos + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS ServerHello missing TLS 1.3 extensions",
        ));
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + exts_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated TLS ServerHello extensions",
        ));
    }
    let mut ext_end = pos + exts_len;
    let mut negotiated_tls13 = false;
    let mut key_share: Option<(u16, Vec<u8>)> = None;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed ServerHello extension length",
            ));
        }
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;
        match ext_type {
            0x002b => {
                if ext_data.len() == 2 && u16::from_be_bytes([ext_data[0], ext_data[1]]) == 0x0304 {
                    negotiated_tls13 = true;
                }
            }
            0x0033 => {
                if ext_data.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated ServerHello key_share",
                    ));
                }
                let grp = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                let klen = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                if ext_data.len() != 4 + klen {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "mismatched ServerHello key_share length",
                    ));
                }
                key_share = Some((grp, ext_data[4..].to_vec()));
            }
            _ => {}
        }
    }
    let _ = &mut ext_end;

    if !negotiated_tls13 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server downgraded below TLS 1.3 (REALITY/Vision requires TLS 1.3)",
        ));
    }
    let Some((key_share_group, key_share_data)) = key_share else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 ServerHello missing key_share extension",
        ));
    };

    Ok(ParsedServerHello {
        cipher_suite,
        key_share_group,
        key_share_data,
    })
}

fn parse_tls13_certificate_list(body: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    if body.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 Certificate message too short",
        ));
    }
    let ctx_len = body[0] as usize;
    let Some(list_hdr_end) = 1usize.checked_add(ctx_len).and_then(|v| v.checked_add(3)) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 Certificate context length overflow",
        ));
    };
    if body.len() < list_hdr_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated TLS 1.3 Certificate context",
        ));
    }
    let mut pos = 1 + ctx_len;
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    let Some(end) = pos.checked_add(list_len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 Certificate list length overflow",
        ));
    };
    if body.len() < end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated TLS 1.3 Certificate list",
        ));
    }
    let mut certs = Vec::new();
    while pos < end {
        let Some(clen_end) = pos.checked_add(3) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 Certificate entry offset overflow",
            ));
        };
        if clen_end > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TLS 1.3 Certificate entry header",
            ));
        }
        let clen = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos = clen_end;
        let Some(cert_end) = pos.checked_add(clen) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 Certificate entry length overflow",
            ));
        };
        let Some(ext_hdr_end) = cert_end.checked_add(2) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 Certificate extensions offset overflow",
            ));
        };
        if ext_hdr_end > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TLS 1.3 Certificate entry",
            ));
        }
        certs.push(CertificateDer::from(body[pos..cert_end].to_vec()));
        pos = cert_end;
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        let Some(next_pos) = ext_hdr_end.checked_add(ext_len) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 Certificate extensions length overflow",
            ));
        };
        if next_pos > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TLS 1.3 Certificate extensions",
            ));
        }
        pos = next_pos;
    }
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 server sent empty Certificate list",
        ));
    }
    Ok(certs)
}

fn read_der_tlv(input: &[u8]) -> io::Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ASN.1 DER element",
        ));
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (b1 as usize, 2usize)
    } else {
        let num_octets = (b1 & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ASN.1 DER length octets",
            ));
        }
        let mut l = 0u64;
        for &b in &input[2..2 + num_octets] {
            l = (l << 8) | u64::from(b);
        }
        let l = usize::try_from(l).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ASN.1 DER element length exceeds platform limit",
            )
        })?;
        (l, 2 + num_octets)
    };
    let Some(end) = hdr_len.checked_add(len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ASN.1 DER element length overflow",
        ));
    };
    if end > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ASN.1 DER element exceeds buffer",
        ));
    }
    Ok((tag, &input[hdr_len..end], &input[end..]))
}

/// Extract `(ed25519_public_key_32B, certificate_signature_bytes)` from a REALITY X.509 leaf DER cert.
fn extract_ed25519_pub_and_cert_sig(cert_der: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let (tag_outer, cert_seq, _) = read_der_tlv(cert_der).ok()?;
    if tag_outer != 0x30 {
        return None;
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    let (tag_tbs, tbs_seq, rest1) = read_der_tlv(cert_seq).ok()?;
    if tag_tbs != 0x30 {
        return None;
    }
    let (_tag_sig_alg, _sig_alg, rest2) = read_der_tlv(rest1).ok()?;
    let (tag_sig_val, sig_bit_str, _) = read_der_tlv(rest2).ok()?;
    if tag_sig_val != 0x03 || sig_bit_str.is_empty() || sig_bit_str[0] != 0x00 {
        return None;
    }
    let cert_sig = sig_bit_str[1..].to_vec();

    // Locate Ed25519 SubjectPublicKeyInfo (`30 2a 30 05 06 03 2b 65 70 03 21 00 || 32B pub`) inside tbsCertificate
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let pos = tbs_seq
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)?;
    let key_start = pos + ED25519_SPKI_PREFIX.len();
    if tbs_seq.len() < key_start + 32 {
        return None;
    }
    let mut pub_key = [0u8; 32];
    pub_key.copy_from_slice(&tbs_seq[key_start..key_start + 32]);
    Some((pub_key, cert_sig))
}

fn extract_x509_spki_public_key(cert_der: &[u8]) -> io::Result<&[u8]> {
    let (tag_outer, cert_seq, _) = read_der_tlv(cert_der)?;
    if tag_outer != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X.509 certificate outer tag is not SEQUENCE",
        ));
    }
    let (tag_tbs, mut cursor, _) = read_der_tlv(cert_seq)?;
    if tag_tbs != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X.509 TBSCertificate tag is not SEQUENCE",
        ));
    }
    // Optional [0] EXPLICIT version
    let (first_tag, _, after_first) = read_der_tlv(cursor)?;
    if first_tag == 0xa0 {
        cursor = after_first;
        // Skip serialNumber
        let (_, _, rest) = read_der_tlv(cursor)?;
        cursor = rest;
    } else {
        // first element already consumed serialNumber
        cursor = after_first;
    }
    // Skip signature, issuer, validity, subject (4 elements)
    for _ in 0..4 {
        let (_, _, rest) = read_der_tlv(cursor)?;
        cursor = rest;
    }
    // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let (tag_spki, spki_seq, _) = read_der_tlv(cursor)?;
    if tag_spki != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X.509 SubjectPublicKeyInfo is not SEQUENCE",
        ));
    }
    let (_, _alg_id, after_alg) = read_der_tlv(spki_seq)?;
    let (tag_bit_str, bit_str, _) = read_der_tlv(after_alg)?;
    if tag_bit_str != 0x03 || bit_str.is_empty() || bit_str[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X.509 subjectPublicKey is not a byte-aligned BIT STRING",
        ));
    }
    Ok(&bit_str[1..])
}

fn verify_x509_tls13_cert_verify(
    cert_der: &[u8],
    scheme: u16,
    verify_payload: &[u8],
    sig: &[u8],
) -> io::Result<()> {
    let pub_key_bytes = extract_x509_spki_public_key(cert_der)?;
    let alg: &'static dyn aws_lc_rs::signature::VerificationAlgorithm = match scheme {
        0x0403 => &ECDSA_P256_SHA256_ASN1,
        0x0503 => &ECDSA_P384_SHA384_ASN1,
        0x0804 => &RSA_PSS_2048_8192_SHA256,
        0x0805 => &RSA_PSS_2048_8192_SHA384,
        0x0806 => &RSA_PSS_2048_8192_SHA512,
        0x0807 => &ED25519,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsupported TLS 1.3 CertificateVerify signature scheme 0x{other:04x}"),
            ));
        }
    };
    UnparsedPublicKey::new(alg, pub_key_bytes)
        .verify(verify_payload, sig)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TLS 1.3 server CertificateVerify signature invalid",
            )
        })
}

fn build_tls13_cert_verify_message(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let label: &[u8] = if server {
        b"TLS 1.3, server CertificateVerify\x00"
    } else {
        b"TLS 1.3, client CertificateVerify\x00"
    };
    let mut out = Vec::with_capacity(64 + label.len() + transcript_hash.len());
    out.resize(64, 0x20);
    out.extend_from_slice(label);
    out.extend_from_slice(transcript_hash);
    out
}

async fn read_raw_tls_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    raw_buf: &mut BytesMut,
) -> io::Result<(u8, BytesMut)> {
    loop {
        if raw_buf.len() >= 5 {
            let content_type = raw_buf[0];
            let rec_len = u16::from_be_bytes([raw_buf[3], raw_buf[4]]) as usize;
            if rec_len > 16384 + 2048 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS record length {rec_len} exceeds maximum"),
                ));
            }
            if raw_buf.len() >= 5 + rec_len {
                let _ = raw_buf.split_to(5);
                let body = raw_buf.split_to(rec_len);
                return Ok((content_type, body));
            }
        }
        let mut tmp = [0u8; 8192];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while reading TLS handshake record",
            ));
        }
        raw_buf.extend_from_slice(&tmp[..n]);
    }
}

/// Waker fanout coordinating split-stream `poll_read` opportunistic TX flushing with concurrent
/// `poll_write` / `poll_flush` / `poll_shutdown`:
/// - slot `0` (`read_tx`): reader waiting on `self.inner` TX write-readiness (woken by
///   `wake_by_ref` and writer completion).
/// - slot `1` (`write_tx`): writer waiting on `self.inner` TX write-readiness (woken by
///   `wake_by_ref` and reader drain/flush completion).
/// - slot `2` (`parked_read`): reader currently parked in `Tls13VisionStream::poll_read`
///   (`Poll::Pending`); NOT woken by `wake_by_ref` (avoiding spurious wakeups during streaming
///   uploads), ONLY woken when a writer returns `Poll::Ready` leaving pending TX work or when
///   `poll_shutdown` newly queues a TLS 1.3 `close_notify` record and parks `Poll::Pending`.
#[derive(Default)]
struct FanoutWaker {
    wakers: parking_lot::Mutex<(Option<Waker>, Option<Waker>, Option<Waker>)>,
}

impl FanoutWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn set_slot(slot: &mut Option<Waker>, waker: &Waker) {
        match slot {
            Some(existing) if existing.will_wake(waker) => {}
            slot => *slot = Some(waker.clone()),
        }
    }

    fn register_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.0, waker);
    }

    fn register_parked_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.2, waker);
    }

    fn register_write(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        Self::set_slot(&mut guard.1, waker);
    }

    /// Atomically check if another task (`!w.will_wake(waker)`) holds the write-readiness slot
    /// and, if so, register `waker` in the read TX slot inside the same lock acquisition.
    /// Eliminates both missing-registration deadlocks and multi-thread check-then-register
    /// lost-wakeup races with [`FanoutWaker::wake_by_ref`].
    fn register_read_if_other_writer(&self, waker: &Waker) -> bool {
        let mut guard = self.wakers.lock();
        if guard.1.as_ref().is_some_and(|w| !w.will_wake(waker)) {
            Self::set_slot(&mut guard.0, waker);
            true
        } else {
            false
        }
    }

    fn clear_read_tx(&self) {
        self.wakers.lock().0 = None;
    }

    fn clear_read(&self) {
        let mut guard = self.wakers.lock();
        guard.0 = None;
        guard.2 = None;
    }

    fn clear_write_and_wake_read(&self) {
        let (w_tx, w_parked) = {
            let mut guard = self.wakers.lock();
            guard.1 = None;
            (guard.0.take(), guard.2.take())
        };
        match (w_tx, w_parked) {
            (Some(a), Some(b)) if a.will_wake(&b) => a.wake(),
            (w_tx, w_parked) => {
                if let Some(w) = w_tx {
                    w.wake();
                }
                if let Some(w) = w_parked {
                    w.wake();
                }
            }
        }
    }

    fn clear_write_and_wake_read_tx(&self) {
        let w = {
            let mut guard = self.wakers.lock();
            guard.1 = None;
            guard.0.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    fn wake_write(&self) {
        let w = self.wakers.lock().1.take();
        if let Some(w) = w {
            w.wake();
        }
    }

    /// Wake ONLY a reader parked in `poll_read` (`guard.2`), preserving both `read_tx`
    /// (`guard.0`) and `write_tx` (`guard.1`) and always dropping the mutex guard before `.wake()`.
    fn wake_parked_read(&self) {
        let w = {
            let mut guard = self.wakers.lock();
            guard.2.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

impl Wake for FanoutWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (w_rd, w_wr) = {
            let mut guard = self.wakers.lock();
            (guard.0.take(), guard.1.take())
        };
        match (w_rd, w_wr) {
            (Some(r), Some(w)) if r.will_wake(&w) => r.wake(),
            (w_rd, w_wr) => {
                if let Some(w) = w_wr {
                    w.wake();
                }
                if let Some(w) = w_rd {
                    w.wake();
                }
            }
        }
    }
}

/// TLS 1.3 client stream supporting REALITY authentication AND XTLS Vision direct-copy unwrap.
pub struct Tls13VisionStream<S> {
    inner: S,
    read_keys: RecordTrafficKeys,
    write_keys: RecordTrafficKeys,
    raw_rx_buf: BytesMut,
    dec_rx_buf: BytesMut,
    post_hs_buf: BytesMut,
    enc_tx_buf: BytesMut,
    tx_fanout: Arc<FanoutWaker>,
    tx_fanout_waker: Waker,
    direct_read: bool,
    direct_write: bool,
    suppress_close_notify: bool,
    close_notify_sent: bool,
    read_eof: bool,
    any_read_bytes: bool,
    uplink_drain_failed: bool,
    inner_needs_flush: bool,
}

impl<S> Tls13VisionStream<S> {
    fn from_parts(
        inner: S,
        read_keys: RecordTrafficKeys,
        write_keys: RecordTrafficKeys,
        raw_rx_buf: BytesMut,
    ) -> Self {
        let tx_fanout = FanoutWaker::new();
        let tx_fanout_waker = Waker::from(Arc::clone(&tx_fanout));
        Self {
            inner,
            read_keys,
            write_keys,
            raw_rx_buf,
            dec_rx_buf: BytesMut::with_capacity(16 * 1024),
            post_hs_buf: BytesMut::new(),
            enc_tx_buf: BytesMut::with_capacity(16 * 1024),
            tx_fanout,
            tx_fanout_waker,
            direct_read: false,
            direct_write: false,
            suppress_close_notify: false,
            close_notify_sent: false,
            read_eof: false,
            any_read_bytes: false,
            uplink_drain_failed: false,
            inner_needs_flush: false,
        }
    }

    /// Switch downlink to direct raw-TCP reads (used by `xtls-rprx-vision` after receiving `CommandPaddingDirect`).
    /// Preserves any already-decrypted bytes in `dec_rx_buf` followed by any unparsed raw TCP bytes in `raw_rx_buf`.
    pub fn enable_direct_read(&mut self) {
        if !self.direct_read {
            self.direct_read = true;
            self.suppress_close_notify = true;
            if !self.raw_rx_buf.is_empty() {
                let raw_tail = self.raw_rx_buf.split();
                self.dec_rx_buf.unsplit(raw_tail);
            }
        }
    }

    /// Switch uplink to direct raw-TCP writes after flushing any already-encrypted outer TLS records
    /// (used by `xtls-rprx-vision` right after queueing the `CommandPaddingDirect` TLS record).
    pub fn enable_direct_write(&mut self) {
        self.direct_write = true;
        self.suppress_close_notify = true;
    }

    pub(crate) fn is_direct_write(&self) -> bool {
        self.direct_write
    }

    pub fn suppress_close_notify(&mut self) {
        self.suppress_close_notify = true;
    }

    pub fn has_queued_tx(&self) -> bool {
        !self.enc_tx_buf.is_empty()
    }

    pub(crate) fn inner_needs_flush(&self) -> bool {
        self.inner_needs_flush
    }

    pub(crate) fn is_uplink_drain_failed(&self) -> bool {
        self.uplink_drain_failed
    }

    pub(crate) fn clear_write_waker(&self) {
        self.tx_fanout.clear_write_and_wake_read();
    }

    /// Seal `data` into outer TLS 1.3 `ApplicationData` records in `enc_tx_buf` (max 16 KiB per record).
    pub fn queue_encrypted_app_data(&mut self, mut data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        while !data.is_empty() {
            let take = data.len().min(16 * 1024);
            self.write_keys.seal_record(
                TLS_RECORD_APPLICATION_DATA,
                &data[..take],
                &mut self.enc_tx_buf,
            )?;
            data = &data[take..];
        }
        self.uplink_drain_failed = false;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13VisionStream<S> {
    pub fn poll_drain_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.uplink_drain_failed = false;
        self.poll_drain_tx_from_write(cx)
    }

    pub(crate) fn poll_flush_tx_from_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain_tx_from_read(cx))?;
        if !self.inner_needs_flush {
            return Poll::Ready(Ok(()));
        }
        if self.direct_write && self.tx_fanout.register_read_if_other_writer(cx.waker()) {
            return Poll::Pending;
        }
        self.tx_fanout.register_read(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        let res = Pin::new(&mut self.inner).poll_flush(&mut fanout_cx);
        if res.is_ready() {
            if matches!(res, Poll::Ready(Ok(()))) {
                self.inner_needs_flush = false;
            }
            self.tx_fanout.clear_read_tx();
            self.tx_fanout.wake_write();
        }
        res
    }
}

/// Perform a pure-Rust TLS 1.3 client handshake (either REALITY or Standard TLS 1.3) over `io_stream`.
pub async fn connect_tls13_vision_stream<S>(
    mut io_stream: S,
    mode: &Tls13HandshakeMode,
) -> io::Result<Tls13VisionStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_random = [0u8; 32];
    rand::rng().fill_bytes(&mut client_random);

    // Generate hybrid X25519MLKEM768 key share + standalone X25519 key share
    let mlkem_dk = LcDecapKey::generate(&ML_KEM_768)
        .map_err(|_| io::Error::other("ML-KEM-768 key generation failed"))?;
    let mlkem_ek: LcEncapKey = mlkem_dk
        .encapsulation_key()
        .map_err(|_| io::Error::other("ML-KEM-768 encapsulation key failed"))?;
    let mlkem_ek_bytes = mlkem_ek
        .key_bytes()
        .map_err(|_| io::Error::other("ML-KEM-768 key_bytes failed"))?;

    let mut mlkem_x_seed = [0u8; 32];
    let mut x25519_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut mlkem_x_seed);
    rand::rng().fill_bytes(&mut x25519_seed);
    let mlkem_x_priv = X25519Secret::from(mlkem_x_seed);
    let mlkem_x_pub = X25519PublicKey::from(&mlkem_x_priv);
    let x25519_priv = X25519Secret::from(x25519_seed);
    let x25519_pub = X25519PublicKey::from(&x25519_priv);

    let mut hybrid_share = Vec::with_capacity(1184 + 32);
    hybrid_share.extend_from_slice(mlkem_ek_bytes.as_ref());
    hybrid_share.extend_from_slice(mlkem_x_pub.as_bytes());

    let (sni, alpn, mut ch_hs, reality_auth_key) = match mode {
        Tls13HandshakeMode::Reality(rcfg) => {
            let zero_sid = [0u8; 32];
            let mut ch = build_client_hello_handshake(
                &rcfg.server_name,
                &client_random,
                &zero_sid,
                &hybrid_share,
                x25519_pub.as_bytes(),
                &rcfg.alpn,
            );

            // Derive REALITY AuthKey = HKDF-SHA256(ikm = ECDH(x25519_priv, server_pub), salt = random[..20], info = "REALITY")
            let srv_pub = X25519PublicKey::from(rcfg.public_key);
            let shared = x25519_priv.diffie_hellman(&srv_pub);
            if shared.as_bytes().iter().all(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY server public-key produced all-zero X25519 shared secret",
                ));
            }
            let prk = hkdf_extract(HashAlg::Sha256, &client_random[..20], shared.as_bytes());
            let auth_key = hkdf_expand(HashAlg::Sha256, &prk, b"REALITY", 32);

            let mut sid_plain = [0u8; 16];
            sid_plain[0] = 26;
            sid_plain[1] = 10;
            sid_plain[2] = 31;
            sid_plain[3] = 0;
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            sid_plain[4..8].copy_from_slice(&now_secs.to_be_bytes());
            sid_plain[8..16].copy_from_slice(&rcfg.short_id);

            let unbound = UnboundKey::new(&AES_256_GCM, &auth_key)
                .map_err(|_| io::Error::other("REALITY AES-256-GCM init failed"))?;
            let aead = LessSafeKey::new(unbound);
            let mut nonce12 = [0u8; 12];
            nonce12.copy_from_slice(&client_random[20..32]);
            let mut sealed_sid = Vec::with_capacity(32);
            sealed_sid.extend_from_slice(&sid_plain);
            aead.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce12),
                Aad::from(&ch[..]),
                &mut sealed_sid,
            )
            .map_err(|_| io::Error::other("REALITY SessionId AEAD seal failed"))?;
            ch[39..71].copy_from_slice(&sealed_sid);

            (
                rcfg.server_name.as_str(),
                rcfg.alpn.as_slice(),
                ch,
                Some(auth_key),
            )
        }
        Tls13HandshakeMode::StandardTls {
            server_name, alpn, ..
        } => {
            let mut sid = [0u8; 32];
            rand::rng().fill_bytes(&mut sid);
            let ch = build_client_hello_handshake(
                server_name,
                &client_random,
                &sid,
                &hybrid_share,
                x25519_pub.as_bytes(),
                alpn,
            );
            (server_name.as_str(), alpn.as_slice(), ch, None)
        }
    };
    let _ = alpn;

    // Wrap ClientHello in TLS record (`0x16 0x03 0x01 || u16 len`)
    let mut ch_record = BytesMut::with_capacity(5 + ch_hs.len());
    ch_record.put_u8(TLS_RECORD_HANDSHAKE);
    ch_record.put_u16(0x0301);
    ch_record.put_u16(ch_hs.len() as u16);
    ch_record.put_slice(&ch_hs);
    io_stream.write_all(&ch_record).await?;
    io_stream.flush().await?;

    let mut raw_rx_buf = BytesMut::with_capacity(16 * 1024);

    // Read ServerHello record
    let sh_hs = loop {
        let (rtype, body) = read_raw_tls_record(&mut io_stream, &mut raw_rx_buf).await?;
        match rtype {
            TLS_RECORD_CHANGE_CIPHER_SPEC => continue,
            TLS_RECORD_ALERT => {
                let code = body.get(1).copied().unwrap_or(0);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TLS server aborted handshake with alert {code}"),
                ));
            }
            TLS_RECORD_HANDSHAKE => break body,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected TLS record type 0x{other:02x} waiting for ServerHello"),
                ));
            }
        }
    };

    if sh_hs.len() < 4 || sh_hs[0] != TLS_HS_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected TLS ServerHello handshake message",
        ));
    }
    let sh_body_len =
        ((sh_hs[1] as usize) << 16) | ((sh_hs[2] as usize) << 8) | (sh_hs[3] as usize);
    if sh_hs.len() < 4 + sh_body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated TLS ServerHello handshake message",
        ));
    }
    let sh_msg = &sh_hs[..4 + sh_body_len];
    let mut hs_plain_buf = BytesMut::new();
    if sh_hs.len() > 4 + sh_body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected unencrypted bytes trailing ServerHello",
        ));
    }

    let parsed_sh = parse_server_hello(&sh_msg[4..])?;
    let suite = SuiteParams::from_id(parsed_sh.cipher_suite)?;

    // Compute TLS 1.3 ECDHE / X25519MLKEM768 shared secret
    let shared_secret: Vec<u8> = match parsed_sh.key_share_group {
        GROUP_X25519 => {
            if parsed_sh.key_share_data.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid ServerHello X25519 key share length",
                ));
            }
            let mut srv_pk = [0u8; 32];
            srv_pk.copy_from_slice(&parsed_sh.key_share_data);
            let ss = x25519_priv.diffie_hellman(&X25519PublicKey::from(srv_pk));
            if ss.as_bytes().iter().all(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid all-zero ServerHello X25519 shared secret",
                ));
            }
            ss.as_bytes().to_vec()
        }
        GROUP_X25519_MLKEM768 => {
            if parsed_sh.key_share_data.len() != 1088 + 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid ServerHello X25519MLKEM768 key share length",
                ));
            }
            let mlkem_ss = mlkem_dk
                .decapsulate(LcCiphertext::from(&parsed_sh.key_share_data[..1088]))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X25519MLKEM768 decapsulation failed",
                    )
                })?;
            let mut srv_pk = [0u8; 32];
            srv_pk.copy_from_slice(&parsed_sh.key_share_data[1088..1120]);
            let x_ss = mlkem_x_priv.diffie_hellman(&X25519PublicKey::from(srv_pk));
            if x_ss.as_bytes().iter().all(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid all-zero X25519MLKEM768 ECDH shared secret",
                ));
            }
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(mlkem_ss.as_ref());
            combined.extend_from_slice(x_ss.as_bytes());
            combined
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ServerHello key_share group 0x{other:04x}"),
            ));
        }
    };

    let mut transcript = TranscriptHash::new(suite.hash);
    transcript.update(&ch_hs);
    transcript.update(sh_msg);
    let _ = &mut ch_hs;

    let zeros = vec![0u8; suite.hash.len()];
    let empty_hash = suite.hash.hash(&[]);
    let early_secret = hkdf_extract(suite.hash, &zeros, &zeros);
    let derived0 = derive_secret(suite.hash, &early_secret, b"derived", &empty_hash);
    let handshake_secret = hkdf_extract(suite.hash, &derived0, &shared_secret);

    let ch_sh_hash = transcript.current_hash();
    let c_hs_secret = derive_secret(suite.hash, &handshake_secret, b"c hs traffic", &ch_sh_hash);
    let s_hs_secret = derive_secret(suite.hash, &handshake_secret, b"s hs traffic", &ch_sh_hash);

    let mut hs_read_keys = RecordTrafficKeys::from_traffic_secret(suite, s_hs_secret.clone())?;
    let mut hs_write_keys = RecordTrafficKeys::from_traffic_secret(suite, c_hs_secret.clone())?;

    // Helper closure to pull the next decrypted handshake message (`[type:1][len:3][body]`)
    let read_next_hs_msg = async |io: &mut S,
                                  raw_buf: &mut BytesMut,
                                  hs_buf: &mut BytesMut,
                                  rkeys: &mut RecordTrafficKeys|
           -> io::Result<(u8, BytesMut)> {
        loop {
            if hs_buf.len() >= 4 {
                let msg_type = hs_buf[0];
                let mlen = ((hs_buf[1] as usize) << 16)
                    | ((hs_buf[2] as usize) << 8)
                    | (hs_buf[3] as usize);
                if mlen > 256 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS 1.3 handshake message exceeds 256 KiB",
                    ));
                }
                if hs_buf.len() >= 4 + mlen {
                    let full_msg = hs_buf.split_to(4 + mlen);
                    return Ok((msg_type, full_msg));
                }
            }

            let (rtype, mut body) = read_raw_tls_record(io, raw_buf).await?;
            if rtype == TLS_RECORD_CHANGE_CIPHER_SPEC {
                continue;
            }
            if rtype == TLS_RECORD_ALERT {
                let code = body.get(1).copied().unwrap_or(0);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TLS server sent alert {code} during handshake"),
                ));
            }
            if rtype != TLS_RECORD_APPLICATION_DATA {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected encrypted TLS 1.3 record (0x17), got 0x{rtype:02x}"),
                ));
            }
            let header = [
                TLS_RECORD_APPLICATION_DATA,
                0x03,
                0x03,
                (body.len() >> 8) as u8,
                body.len() as u8,
            ];
            let (inner_type, plain_len) = rkeys.open_record(&header, &mut body)?;
            match inner_type {
                TLS_RECORD_HANDSHAKE => {
                    hs_buf.extend_from_slice(&body[..plain_len]);
                }
                TLS_RECORD_ALERT => {
                    let code = body.get(1).copied().unwrap_or(0);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("TLS 1.3 encrypted alert {code} during handshake"),
                    ));
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected inner record type 0x{other:02x} during handshake"),
                    ));
                }
            }
        }
    };

    // 1. EncryptedExtensions (0x08)
    let (ee_type, ee_msg) = read_next_hs_msg(
        &mut io_stream,
        &mut raw_rx_buf,
        &mut hs_plain_buf,
        &mut hs_read_keys,
    )
    .await?;
    if ee_type != TLS_HS_ENCRYPTED_EXTENSIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected EncryptedExtensions (8), got {ee_type}"),
        ));
    }
    transcript.update(&ee_msg);

    // 2. Certificate (0x0b)
    let (cert_type, cert_msg) = read_next_hs_msg(
        &mut io_stream,
        &mut raw_rx_buf,
        &mut hs_plain_buf,
        &mut hs_read_keys,
    )
    .await?;
    if cert_type != TLS_HS_CERTIFICATE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected server Certificate (11), got {cert_type}"),
        ));
    }
    let certs = parse_tls13_certificate_list(&cert_msg[4..])?;
    transcript.update(&cert_msg);
    let hash_at_cert = transcript.current_hash();

    // 3. CertificateVerify (0x0f)
    let (cv_type, cv_msg) = read_next_hs_msg(
        &mut io_stream,
        &mut raw_rx_buf,
        &mut hs_plain_buf,
        &mut hs_read_keys,
    )
    .await?;
    if cv_type != TLS_HS_CERTIFICATE_VERIFY || cv_msg.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed TLS 1.3 CertificateVerify message",
        ));
    }
    let cv_scheme = u16::from_be_bytes([cv_msg[4], cv_msg[5]]);
    let cv_sig_len = u16::from_be_bytes([cv_msg[6], cv_msg[7]]) as usize;
    if cv_msg.len() != 8 + cv_sig_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.3 CertificateVerify signature length mismatch",
        ));
    }
    let cv_sig = &cv_msg[8..];

    // Authenticate server certificate + CertificateVerify according to REALITY vs Standard TLS!
    if let Some(auth_key) = &reality_auth_key {
        let Some((ed25519_pub, cert_sig)) = extract_ed25519_pub_and_cert_sig(certs[0].as_ref())
        else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY server returned real/fallback certificate instead of Ed25519 REALITY certificate (check public-key, short-id, servername, or system clock)",
            ));
        };
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
        if hmac::verify(&hmac_key, &ed25519_pub, cert_sig.as_slice()).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY certificate HMAC-SHA512 authentication failed (untrusted server or fallback)",
            ));
        }
        if cv_scheme != 0x0807 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "REALITY server used non-Ed25519 CertificateVerify scheme 0x{cv_scheme:04x}"
                ),
            ));
        }
        let verify_payload = build_tls13_cert_verify_message(true, &hash_at_cert);
        UnparsedPublicKey::new(&ED25519, ed25519_pub)
            .verify(&verify_payload, cv_sig)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "REALITY Ed25519 CertificateVerify signature invalid",
                )
            })?;
    } else if let Tls13HandshakeMode::StandardTls {
        skip_cert_verify,
        extra_ca_der,
        ..
    } = mode
    {
        let verify_payload = build_tls13_cert_verify_message(true, &hash_at_cert);
        if !*skip_cert_verify {
            let provider = Arc::new(default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for extra in extra_ca_der {
                roots
                    .add(extra.clone())
                    .map_err(|e| io::Error::other(format!("extra CA add failed: {e}")))?;
            }
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                    .build()
                    .map_err(|e| io::Error::other(format!("WebPki verifier failed: {e}")))?;
            let server_name = crate::crypto::tls::parse_server_name(sni)?;
            verifier
                .verify_server_cert(&certs[0], &certs[1..], &server_name, &[], UnixTime::now())
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("TLS 1.3 certificate verification failed: {e}"),
                    )
                })?;
        }
        verify_x509_tls13_cert_verify(certs[0].as_ref(), cv_scheme, &verify_payload, cv_sig)?;
    }

    transcript.update(&cv_msg);
    let hash_at_cv = transcript.current_hash();

    // 4. Server Finished (0x14)
    let (fin_type, fin_msg) = read_next_hs_msg(
        &mut io_stream,
        &mut raw_rx_buf,
        &mut hs_plain_buf,
        &mut hs_read_keys,
    )
    .await?;
    if fin_type != TLS_HS_FINISHED || fin_msg.len() != 4 + suite.hash.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS 1.3 server Finished message",
        ));
    }
    let s_fin_key = hkdf_expand_label(suite.hash, &s_hs_secret, b"finished", &[], suite.hash.len());
    let expected_s_fin = suite.hash.hmac_sign(&s_fin_key, &hash_at_cv);
    if aws_lc_rs::constant_time::verify_slices_are_equal(&fin_msg[4..], &expected_s_fin).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS 1.3 server Finished verify_data mismatch",
        ));
    }
    transcript.update(&fin_msg);
    if !hs_plain_buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected handshake bytes coalesced after server Finished",
        ));
    }

    // Derive Master Secret & Application Traffic Secrets at `ClientHello .. ServerFinished`
    let hash_at_s_fin = transcript.current_hash();
    let derived1 = derive_secret(suite.hash, &handshake_secret, b"derived", &empty_hash);
    let master_secret = hkdf_extract(suite.hash, &derived1, &zeros);
    let c_ap_secret = derive_secret(suite.hash, &master_secret, b"c ap traffic", &hash_at_s_fin);
    let s_ap_secret = derive_secret(suite.hash, &master_secret, b"s ap traffic", &hash_at_s_fin);

    // Send ChangeCipherSpec + encrypted Client Finished under `c_hs_traffic`
    let c_fin_key = hkdf_expand_label(suite.hash, &c_hs_secret, b"finished", &[], suite.hash.len());
    let c_fin_verify = suite.hash.hmac_sign(&c_fin_key, &hash_at_s_fin);
    let mut c_fin_hs = BytesMut::with_capacity(4 + c_fin_verify.len());
    c_fin_hs.put_u8(TLS_HS_FINISHED);
    c_fin_hs.put_u8(0);
    c_fin_hs.put_u8(0);
    c_fin_hs.put_u8(c_fin_verify.len() as u8);
    c_fin_hs.put_slice(&c_fin_verify);

    let mut flight2 = BytesMut::with_capacity(6 + 5 + c_fin_hs.len() + 17);
    flight2.put_slice(&[TLS_RECORD_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    hs_write_keys.seal_record(TLS_RECORD_HANDSHAKE, &c_fin_hs, &mut flight2)?;
    io_stream.write_all(&flight2).await?;
    io_stream.flush().await?;

    let app_read_keys = RecordTrafficKeys::from_traffic_secret(suite, s_ap_secret)?;
    let app_write_keys = RecordTrafficKeys::from_traffic_secret(suite, c_ap_secret)?;

    Ok(Tls13VisionStream::from_parts(
        io_stream,
        app_read_keys,
        app_write_keys,
        raw_rx_buf,
    ))
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13VisionStream<S> {
    fn poll_drain_tx_with_fanout(&mut self) -> Poll<io::Result<()>> {
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        while !self.enc_tx_buf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(&mut fanout_cx, &self.enc_tx_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS 1.3 transport closed while writing record",
                )));
            }
            self.enc_tx_buf.advance(n);
            self.inner_needs_flush = true;
            self.uplink_drain_failed = false;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_drain_tx_from_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.enc_tx_buf.is_empty() {
            self.tx_fanout.clear_write_and_wake_read_tx();
            return Poll::Ready(Ok(()));
        }
        self.tx_fanout.register_write(cx.waker());
        let res = self.poll_drain_tx_with_fanout();
        if res.is_ready() {
            self.tx_fanout.clear_write_and_wake_read();
        }
        res
    }

    fn poll_drain_tx_from_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.enc_tx_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        self.tx_fanout.register_read(cx.waker());
        let res = self.poll_drain_tx_with_fanout();
        if res.is_ready() {
            self.tx_fanout.clear_read_tx();
            self.tx_fanout.wake_write();
        }
        res
    }

    fn handle_post_handshake_messages(&mut self, hs_bytes: &[u8]) -> io::Result<()> {
        if self
            .post_hs_buf
            .len()
            .checked_add(hs_bytes.len())
            .is_none_or(|n| n > MAX_POST_HANDSHAKE_BUF)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.3 post-handshake buffer exceeds 64 KiB limit",
            ));
        }
        self.post_hs_buf.extend_from_slice(hs_bytes);

        while self.post_hs_buf.len() >= 4 {
            let mtype = self.post_hs_buf[0];
            let mlen = ((self.post_hs_buf[1] as usize) << 16)
                | ((self.post_hs_buf[2] as usize) << 8)
                | (self.post_hs_buf[3] as usize);
            let Some(msg_len) = 4usize.checked_add(mlen) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS 1.3 post-handshake message length overflow",
                ));
            };
            if msg_len > MAX_POST_HANDSHAKE_BUF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "TLS 1.3 post-handshake message length {msg_len} exceeds {MAX_POST_HANDSHAKE_BUF} byte limit"
                    ),
                ));
            }
            if self.post_hs_buf.len() < msg_len {
                break;
            }
            match mtype {
                TLS_HS_NEW_SESSION_TICKET => {
                    // Ignore NewSessionTicket (REALITY / Vision opens fresh ephemeral handshakes)
                }
                TLS_HS_KEY_UPDATE => {
                    if mlen != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid TLS 1.3 KeyUpdate length {mlen}"),
                        ));
                    }
                    let req = self.post_hs_buf[4];
                    if req > 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid TLS 1.3 KeyUpdate request_update value {req}"),
                        ));
                    }
                    self.read_keys.roll_key_update()?;
                    if req == 1 {
                        let ku_resp = [TLS_HS_KEY_UPDATE, 0, 0, 1, 0];
                        self.write_keys.seal_record(
                            TLS_RECORD_HANDSHAKE,
                            &ku_resp,
                            &mut self.enc_tx_buf,
                        )?;
                        self.write_keys.roll_key_update()?;
                    }
                }
                _ => {}
            }
            self.post_hs_buf.advance(msg_len);
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Always drain already-decrypted plaintext (or already-reached EOF) FIRST, before any
        // opportunistic uplink drain, so an uplink error can never discard bytes already
        // decrypted in `dec_rx_buf`.
        if !self.dec_rx_buf.is_empty() {
            let to_copy = self.dec_rx_buf.len().min(buf.remaining());
            let chunk = self.dec_rx_buf.split_to(to_copy);
            buf.put_slice(&chunk);
            self.any_read_bytes = true;
            self.tx_fanout.clear_read();
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            self.tx_fanout.clear_read();
            return Poll::Ready(Ok(()));
        }

        // Opportunistically drain/flush any queued outer TLS records (e.g. KeyUpdate responses,
        // server-speaks-first VLESS headers, or un-flushed writes) using FanoutWaker so we never
        // steal a split writer's waker and never block or abort downlink reads behind a congested
        // or half-closed/broken uplink.
        let mut pending_tx_err: Option<io::Error> = None;
        if !self.uplink_drain_failed
            && (!self.enc_tx_buf.is_empty() || self.inner_needs_flush)
            && let Poll::Ready(Err(e)) = self.poll_flush_tx_from_read(cx)
        {
            if self.any_read_bytes {
                self.uplink_drain_failed = true;
            }
            pending_tx_err = Some(e);
        }

        loop {
            if !self.dec_rx_buf.is_empty() {
                let to_copy = self.dec_rx_buf.len().min(buf.remaining());
                let chunk = self.dec_rx_buf.split_to(to_copy);
                buf.put_slice(&chunk);
                self.any_read_bytes = true;
                if pending_tx_err.is_some() {
                    self.uplink_drain_failed = true;
                }
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }
            if self.direct_read {
                let before = buf.filled().len();
                match Pin::new(&mut self.inner).poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        self.tx_fanout.clear_read();
                        if buf.filled().len() > before {
                            self.any_read_bytes = true;
                            if pending_tx_err.is_some() {
                                self.uplink_drain_failed = true;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        self.read_eof = true;
                        if let Some(err) = pending_tx_err {
                            if !self.any_read_bytes {
                                return Poll::Ready(Err(err));
                            }
                            self.uplink_drain_failed = true;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(e)) => {
                        self.tx_fanout.clear_read();
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        if let Some(err) = pending_tx_err {
                            if !self.any_read_bytes {
                                self.tx_fanout.clear_read();
                                return Poll::Ready(Err(err));
                            }
                            self.uplink_drain_failed = true;
                        }
                        self.tx_fanout.register_parked_read(cx.waker());
                        return Poll::Pending;
                    }
                }
            }

            if self.raw_rx_buf.len() >= 5 {
                let rtype = self.raw_rx_buf[0];
                let rlen = u16::from_be_bytes([self.raw_rx_buf[3], self.raw_rx_buf[4]]) as usize;
                if rlen > 16384 + 2048 {
                    self.tx_fanout.clear_read();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("TLS 1.3 record length {rlen} exceeds limit"),
                    )));
                }
                if self.raw_rx_buf.len() >= 5 + rlen {
                    let hdr_bytes = self.raw_rx_buf.split_to(5);
                    let mut body = self.raw_rx_buf.split_to(rlen);
                    if rtype == TLS_RECORD_CHANGE_CIPHER_SPEC {
                        continue;
                    }
                    if rtype != TLS_RECORD_APPLICATION_DATA {
                        self.tx_fanout.clear_read();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected outer TLS record type 0x{rtype:02x}"),
                        )));
                    }
                    let header = [
                        hdr_bytes[0],
                        hdr_bytes[1],
                        hdr_bytes[2],
                        hdr_bytes[3],
                        hdr_bytes[4],
                    ];
                    let (inner_type, plain_len) =
                        match self.read_keys.open_record(&header, &mut body) {
                            Ok(res) => res,
                            Err(e) => {
                                self.tx_fanout.clear_read();
                                return Poll::Ready(Err(e));
                            }
                        };
                    match inner_type {
                        TLS_RECORD_APPLICATION_DATA => {
                            if !self.post_hs_buf.is_empty() {
                                self.tx_fanout.clear_read();
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "TLS 1.3 application data interleaved with incomplete post-handshake message",
                                )));
                            }
                            if plain_len > 0 {
                                self.any_read_bytes = true;
                                if pending_tx_err.is_some() {
                                    self.uplink_drain_failed = true;
                                }
                                self.dec_rx_buf.extend_from_slice(&body[..plain_len]);
                            }
                            continue;
                        }
                        TLS_RECORD_HANDSHAKE => {
                            if let Err(e) = self.handle_post_handshake_messages(&body[..plain_len])
                            {
                                self.tx_fanout.clear_read();
                                return Poll::Ready(Err(e));
                            }
                            if !self.uplink_drain_failed
                                && pending_tx_err.is_none()
                                && (!self.enc_tx_buf.is_empty() || self.inner_needs_flush)
                                && let Poll::Ready(Err(e)) = self.poll_flush_tx_from_read(cx)
                            {
                                if self.any_read_bytes {
                                    self.uplink_drain_failed = true;
                                }
                                pending_tx_err = Some(e);
                            }
                            continue;
                        }
                        TLS_RECORD_ALERT => {
                            let code = body.get(1).copied().unwrap_or(0);
                            self.tx_fanout.clear_read();
                            if code == 0 {
                                // close_notify
                                self.read_eof = true;
                                if let Some(err) = pending_tx_err {
                                    if !self.any_read_bytes {
                                        return Poll::Ready(Err(err));
                                    }
                                    self.uplink_drain_failed = true;
                                }
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("TLS 1.3 peer sent fatal alert {code}"),
                            )));
                        }
                        _ => continue,
                    }
                }
            }

            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    if let Some(err) = pending_tx_err {
                        if !self.any_read_bytes && self.raw_rx_buf.is_empty() {
                            self.tx_fanout.clear_read();
                            return Poll::Ready(Err(err));
                        }
                        if self.any_read_bytes {
                            self.uplink_drain_failed = true;
                        }
                    }
                    self.tx_fanout.register_parked_read(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.tx_fanout.clear_read();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {}
            }
            let filled = rb.filled();
            if filled.is_empty() {
                self.tx_fanout.clear_read();
                if !self.raw_rx_buf.is_empty() || !self.post_hs_buf.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS 1.3 record on EOF",
                    )));
                }
                self.read_eof = true;
                if let Some(err) = pending_tx_err {
                    if !self.any_read_bytes {
                        return Poll::Ready(Err(err));
                    }
                    self.uplink_drain_failed = true;
                }
                return Poll::Ready(Ok(()));
            }
            self.raw_rx_buf.extend_from_slice(filled);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            self.tx_fanout.clear_write_and_wake_read_tx();
            return Poll::Ready(Ok(0));
        }

        self.uplink_drain_failed = false;

        // First drain any previously buffered outer TLS record BEFORE consuming bytes from `data`,
        // keeping backpressure strictly bounded to one record while remaining 100% cancel-safe.
        if !self.enc_tx_buf.is_empty() {
            ready!(self.poll_drain_tx_from_write(cx))?;
        }

        if self.direct_write {
            let this = &mut *self;
            this.tx_fanout.register_write(cx.waker());
            let mut fanout_cx = Context::from_waker(&this.tx_fanout_waker);
            let res = Pin::new(&mut this.inner).poll_write(&mut fanout_cx, data);
            if let Poll::Ready(ref r) = res {
                if matches!(r, Ok(n) if *n > 0) {
                    this.inner_needs_flush = true;
                }
                this.tx_fanout.clear_write_and_wake_read();
            }
            return res;
        }

        let chunk_len = data.len().min(16 * 1024);
        {
            let this = &mut *self;
            if let Err(e) = this.write_keys.seal_record(
                TLS_RECORD_APPLICATION_DATA,
                &data[..chunk_len],
                &mut this.enc_tx_buf,
            ) {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
        }

        // Attempt one opportunistic drain and immediately acknowledge `chunk_len` so cancelling
        // a later `Pending` write can never return `Ok(n > buf.len())` on a smaller retry buffer.
        match self.poll_drain_tx_from_write(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk_len)),
            Poll::Pending => {
                // Returning `Ready(Ok(chunk_len))` immediately — writer is not parked, so clear
                // its slot and wake any parked reader so queued `enc_tx_buf` bytes can drain
                // even if the writer never calls `flush()`.
                self.tx_fanout.clear_write_and_wake_read();
                Poll::Ready(Ok(chunk_len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.uplink_drain_failed = false;
        ready!(self.poll_drain_tx_from_write(cx))?;
        let this = &mut *self;
        this.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&this.tx_fanout_waker);
        let res = Pin::new(&mut this.inner).poll_flush(&mut fanout_cx);
        if res.is_ready() {
            if matches!(res, Poll::Ready(Ok(()))) {
                this.inner_needs_flush = false;
                this.tx_fanout.clear_write_and_wake_read_tx();
            } else {
                this.tx_fanout.clear_write_and_wake_read();
            }
        }
        res
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.uplink_drain_failed = false;
        let mut newly_queued_close_notify = false;
        if !self.suppress_close_notify && !self.direct_write && !self.close_notify_sent {
            let this = &mut *self;
            if let Err(e) =
                this.write_keys
                    .seal_record(TLS_RECORD_ALERT, &[0x01, 0x00], &mut this.enc_tx_buf)
            {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            self.close_notify_sent = true;
            newly_queued_close_notify = true;
        }
        match self.poll_drain_tx_from_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                // One-shot wakeup of any pre-parked split reader (`guard.2`) so cancelling
                // `shutdown()` cannot strand the newly sealed `close_notify` in `enc_tx_buf`.
                if newly_queued_close_notify {
                    self.tx_fanout.wake_parked_read();
                }
                return Poll::Pending;
            }
        }
        let this = &mut *self;
        this.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&this.tx_fanout_waker);
        match Pin::new(&mut this.inner).poll_flush(&mut fanout_cx) {
            Poll::Pending => {
                if newly_queued_close_notify {
                    this.tx_fanout.wake_parked_read();
                }
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                this.tx_fanout.clear_write_and_wake_read();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {
                this.inner_needs_flush = false;
            }
        }
        this.tx_fanout.register_write(cx.waker());
        let res = Pin::new(&mut this.inner).poll_shutdown(&mut fanout_cx);
        if res.is_ready() {
            if matches!(res, Poll::Ready(Ok(()))) {
                this.tx_fanout.clear_write_and_wake_read_tx();
            } else {
                this.tx_fanout.clear_write_and_wake_read();
            }
        }
        res
    }
}

/// Build a minimal REALITY-authenticated Ed25519 self-signed X.509 DER certificate where the trailing
/// 64-byte signature is replaced with `HMAC-SHA512(auth_key, ed25519_pub)` (matching Xray REALITY server!).
fn build_reality_server_cert_der(ed25519_pub: &[u8; 32], auth_key: &[u8]) -> Vec<u8> {
    fn der_seq(content: &[u8]) -> Vec<u8> {
        der_tlv(0x30, content)
    }
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + content.len());
        out.push(tag);
        let len = content.len();
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(content);
        out
    }

    // Minimal valid X.509 v3 TBSCertificate with Ed25519 SPKI
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // version v3
    tbs.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber 1
    tbs.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]); // Ed25519 sigAlg
    tbs.extend_from_slice(&[0x30, 0x00]); // empty issuer RDNSequence
    // validity: 2020-01-01 .. 2049-12-31
    tbs.extend_from_slice(&der_seq(&[
        0x17, 0x0d, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        0x17, 0x0d, b'4', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z',
    ]));
    tbs.extend_from_slice(&[0x30, 0x00]); // empty subject RDNSequence
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(ed25519_pub);
    tbs.extend_from_slice(&spki);

    let tbs_der = der_seq(&tbs);
    let sig_alg = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    let hmac_k = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_sig = hmac::sign(&hmac_k, ed25519_pub);
    let mut bit_str_body = Vec::with_capacity(65);
    bit_str_body.push(0x00);
    bit_str_body.extend_from_slice(hmac_sig.as_ref());
    let sig_val = der_tlv(0x03, &bit_str_body);

    let mut cert_inner = Vec::with_capacity(tbs_der.len() + sig_alg.len() + sig_val.len());
    cert_inner.extend_from_slice(&tbs_der);
    cert_inner.extend_from_slice(&sig_alg);
    cert_inner.extend_from_slice(&sig_val);
    der_seq(&cert_inner)
}

/// Server-side REALITY TLS 1.3 handshake helper (used by loopback E2E tests).
pub async fn accept_reality_tls13_server<S>(
    mut io_stream: S,
    server_reality_private_key: &[u8; 32],
    expected_short_id: &[u8; 8],
    expected_sni: &str,
) -> io::Result<Tls13VisionStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw_rx_buf = BytesMut::with_capacity(8192);
    let (rtype, ch_hs) = read_raw_tls_record(&mut io_stream, &mut raw_rx_buf).await?;
    if rtype != TLS_RECORD_HANDSHAKE || ch_hs.len() < 75 || ch_hs[0] != TLS_HS_CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid REALITY ClientHello record",
        ));
    }
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&ch_hs[6..38]);
    if ch_hs[38] != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY ClientHello session_id length != 32",
        ));
    }
    let mut enc_sid = [0u8; 32];
    enc_sid.copy_from_slice(&ch_hs[39..71]);

    // Parse ClientHello extensions to extract SNI and X25519 / X25519MLKEM768 key shares
    let mut pos = 71;
    let suites_len = u16::from_be_bytes([ch_hs[pos], ch_hs[pos + 1]]) as usize;
    pos += 2 + suites_len;
    let comp_len = ch_hs[pos] as usize;
    pos += 1 + comp_len;
    let exts_len = u16::from_be_bytes([ch_hs[pos], ch_hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + exts_len;

    let mut got_sni = String::new();
    let mut client_x25519_pub: Option<[u8; 32]> = None;
    let mut client_mlkem_share: Option<Vec<u8>> = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([ch_hs[pos], ch_hs[pos + 1]]);
        let elen = u16::from_be_bytes([ch_hs[pos + 2], ch_hs[pos + 3]]) as usize;
        pos += 4;
        let edata = &ch_hs[pos..pos + elen];
        pos += elen;
        match etype {
            0x0000 if edata.len() >= 5 => {
                let nlen = u16::from_be_bytes([edata[3], edata[4]]) as usize;
                if edata.len() >= 5 + nlen
                    && let Ok(s) = std::str::from_utf8(&edata[5..5 + nlen])
                {
                    got_sni = s.to_string();
                }
            }
            0x0033 if edata.len() >= 2 => {
                let mut kpos = 2;
                while kpos + 4 <= edata.len() {
                    let grp = u16::from_be_bytes([edata[kpos], edata[kpos + 1]]);
                    let klen = u16::from_be_bytes([edata[kpos + 2], edata[kpos + 3]]) as usize;
                    kpos += 4;
                    if kpos + klen > edata.len() {
                        break;
                    }
                    let kbytes = &edata[kpos..kpos + klen];
                    kpos += klen;
                    if grp == GROUP_X25519_MLKEM768 && klen == 1216 {
                        client_mlkem_share = Some(kbytes.to_vec());
                    } else if grp == GROUP_X25519 && klen == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(kbytes);
                        client_x25519_pub = Some(arr);
                    }
                }
            }
            _ => {}
        }
    }

    if !expected_sni.is_empty() && !got_sni.eq_ignore_ascii_case(expected_sni) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("REALITY server SNI mismatch: got '{got_sni}', expected '{expected_sni}'"),
        ));
    }

    let peer_auth_x25519 = client_x25519_pub
        .or_else(|| {
            client_mlkem_share.as_ref().map(|s| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s[1184..1216]);
                arr
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing X25519 share in ClientHello",
            )
        })?;

    let srv_static = X25519Secret::from(*server_reality_private_key);
    let auth_ecdh = srv_static.diffie_hellman(&X25519PublicKey::from(peer_auth_x25519));
    let auth_prk = hkdf_extract(HashAlg::Sha256, &client_random[..20], auth_ecdh.as_bytes());
    let auth_key = hkdf_expand(HashAlg::Sha256, &auth_prk, b"REALITY", 32);

    let mut ch_zero_sid = ch_hs.to_vec();
    ch_zero_sid[39..71].fill(0);
    let unbound = UnboundKey::new(&AES_256_GCM, &auth_key)
        .map_err(|_| io::Error::other("AES-256-GCM init failed"))?;
    let aead = LessSafeKey::new(unbound);
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&client_random[20..32]);
    let mut sid_buf = enc_sid.to_vec();
    let sid_plain = aead
        .open_in_place(
            Nonce::assume_unique_for_key(nonce12),
            Aad::from(&ch_zero_sid),
            &mut sid_buf,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY SessionId decryption failed",
            )
        })?;
    if &sid_plain[8..16] != expected_short_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY short_id mismatch",
        ));
    }

    // Negotiate X25519MLKEM768 if offered, otherwise X25519, with TLS_AES_128_GCM_SHA256
    let mut srv_ephem_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut srv_ephem_seed);
    let srv_ephem_sk = X25519Secret::from(srv_ephem_seed);
    let srv_ephem_pk = X25519PublicKey::from(&srv_ephem_sk);

    let (chosen_group, server_share_bytes, tls_shared_secret) =
        if let Some(hybrid) = &client_mlkem_share {
            let ek = LcEncapKey::new(&ML_KEM_768, &hybrid[..1184])
                .map_err(|_| io::Error::other("invalid client ML-KEM-768 ek"))?;
            let (ct, mlkem_ss) = ek
                .encapsulate()
                .map_err(|_| io::Error::other("ML-KEM-768 encapsulate failed"))?;
            let mut cli_x = [0u8; 32];
            cli_x.copy_from_slice(&hybrid[1184..1216]);
            let x_ss = srv_ephem_sk.diffie_hellman(&X25519PublicKey::from(cli_x));
            let mut share = Vec::with_capacity(1120);
            share.extend_from_slice(ct.as_ref());
            share.extend_from_slice(srv_ephem_pk.as_bytes());
            let mut ss = Vec::with_capacity(64);
            ss.extend_from_slice(mlkem_ss.as_ref());
            ss.extend_from_slice(x_ss.as_bytes());
            (GROUP_X25519_MLKEM768, share, ss)
        } else {
            let x_ss = srv_ephem_sk.diffie_hellman(&X25519PublicKey::from(peer_auth_x25519));
            (
                GROUP_X25519,
                srv_ephem_pk.as_bytes().to_vec(),
                x_ss.as_bytes().to_vec(),
            )
        };

    let mut srv_random = [0u8; 32];
    rand::rng().fill_bytes(&mut srv_random);
    let mut sh_exts = BytesMut::new();
    sh_exts.put_u16(0x002b);
    sh_exts.put_u16(2);
    sh_exts.put_u16(0x0304);
    sh_exts.put_u16(0x0033);
    sh_exts.put_u16((4 + server_share_bytes.len()) as u16);
    sh_exts.put_u16(chosen_group);
    sh_exts.put_u16(server_share_bytes.len() as u16);
    sh_exts.put_slice(&server_share_bytes);

    let mut sh_body = BytesMut::new();
    sh_body.put_u16(0x0303);
    sh_body.put_slice(&srv_random);
    sh_body.put_u8(32);
    sh_body.put_slice(&enc_sid);
    sh_body.put_u16(CIPHER_TLS_AES_128_GCM_SHA256);
    sh_body.put_u8(0);
    sh_body.put_u16(sh_exts.len() as u16);
    sh_body.put_slice(&sh_exts);

    let mut sh_hs = BytesMut::with_capacity(4 + sh_body.len());
    sh_hs.put_u8(TLS_HS_SERVER_HELLO);
    let sh_len = sh_body.len() as u32;
    sh_hs.put_u8((sh_len >> 16) as u8);
    sh_hs.put_u8((sh_len >> 8) as u8);
    sh_hs.put_u8(sh_len as u8);
    sh_hs.put_slice(&sh_body);

    let suite = SuiteParams::from_id(CIPHER_TLS_AES_128_GCM_SHA256)?;
    let mut transcript = TranscriptHash::new(suite.hash);
    transcript.update(&ch_hs);
    transcript.update(&sh_hs);

    let zeros = vec![0u8; 32];
    let empty_hash = suite.hash.hash(&[]);
    let early = hkdf_extract(suite.hash, &zeros, &zeros);
    let derived0 = derive_secret(suite.hash, &early, b"derived", &empty_hash);
    let hs_secret = hkdf_extract(suite.hash, &derived0, &tls_shared_secret);
    let ch_sh_hash = transcript.current_hash();
    let c_hs_secret = derive_secret(suite.hash, &hs_secret, b"c hs traffic", &ch_sh_hash);
    let s_hs_secret = derive_secret(suite.hash, &hs_secret, b"s hs traffic", &ch_sh_hash);

    let mut hs_write = RecordTrafficKeys::from_traffic_secret(suite, s_hs_secret.clone())?;
    let mut hs_read = RecordTrafficKeys::from_traffic_secret(suite, c_hs_secret.clone())?;

    // EncryptedExtensions (`[0x08, 0, 0, 2, 0, 0]`)
    let ee_hs = [TLS_HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0];
    transcript.update(&ee_hs);

    // Ephemeral Ed25519 keypair + REALITY HMAC-SHA512 signed certificate
    let ed_kp =
        Ed25519KeyPair::generate().map_err(|_| io::Error::other("Ed25519 keygen failed"))?;
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(ed_kp.public_key().as_ref());
    let cert_der = build_reality_server_cert_der(&ed_pub, &auth_key);

    let mut cert_list = BytesMut::new();
    let clen = cert_der.len() as u32;
    cert_list.put_u8((clen >> 16) as u8);
    cert_list.put_u8((clen >> 8) as u8);
    cert_list.put_u8(clen as u8);
    cert_list.put_slice(&cert_der);
    cert_list.put_u16(0); // extensions

    let mut cert_body = BytesMut::new();
    cert_body.put_u8(0); // context
    let llen = cert_list.len() as u32;
    cert_body.put_u8((llen >> 16) as u8);
    cert_body.put_u8((llen >> 8) as u8);
    cert_body.put_u8(llen as u8);
    cert_body.put_slice(&cert_list);

    let mut cert_hs = BytesMut::new();
    cert_hs.put_u8(TLS_HS_CERTIFICATE);
    let cblen = cert_body.len() as u32;
    cert_hs.put_u8((cblen >> 16) as u8);
    cert_hs.put_u8((cblen >> 8) as u8);
    cert_hs.put_u8(cblen as u8);
    cert_hs.put_slice(&cert_body);
    transcript.update(&cert_hs);

    // CertificateVerify (0x0f)
    let hash_at_cert = transcript.current_hash();
    let cv_msg_to_sign = build_tls13_cert_verify_message(true, &hash_at_cert);
    let cv_sig = ed_kp.sign(&cv_msg_to_sign);
    let mut cv_hs = BytesMut::new();
    cv_hs.put_u8(TLS_HS_CERTIFICATE_VERIFY);
    let cv_body_len = (4 + cv_sig.as_ref().len()) as u32;
    cv_hs.put_u8((cv_body_len >> 16) as u8);
    cv_hs.put_u8((cv_body_len >> 8) as u8);
    cv_hs.put_u8(cv_body_len as u8);
    cv_hs.put_u16(0x0807);
    cv_hs.put_u16(cv_sig.as_ref().len() as u16);
    cv_hs.put_slice(cv_sig.as_ref());
    transcript.update(&cv_hs);

    // Server Finished (0x14)
    let hash_at_cv = transcript.current_hash();
    let s_fin_key = hkdf_expand_label(suite.hash, &s_hs_secret, b"finished", &[], 32);
    let s_fin_verify = suite.hash.hmac_sign(&s_fin_key, &hash_at_cv);
    let mut fin_hs = BytesMut::new();
    fin_hs.put_u8(TLS_HS_FINISHED);
    fin_hs.put_u8(0);
    fin_hs.put_u8(0);
    fin_hs.put_u8(32);
    fin_hs.put_slice(&s_fin_verify);
    transcript.update(&fin_hs);

    let mut out_wire = BytesMut::new();
    out_wire.put_u8(TLS_RECORD_HANDSHAKE);
    out_wire.put_u16(0x0303);
    out_wire.put_u16(sh_hs.len() as u16);
    out_wire.put_slice(&sh_hs);
    out_wire.put_slice(&[TLS_RECORD_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    hs_write.seal_record(TLS_RECORD_HANDSHAKE, &ee_hs, &mut out_wire)?;
    hs_write.seal_record(TLS_RECORD_HANDSHAKE, &cert_hs, &mut out_wire)?;
    hs_write.seal_record(TLS_RECORD_HANDSHAKE, &cv_hs, &mut out_wire)?;
    hs_write.seal_record(TLS_RECORD_HANDSHAKE, &fin_hs, &mut out_wire)?;
    io_stream.write_all(&out_wire).await?;
    io_stream.flush().await?;

    let hash_at_s_fin = transcript.current_hash();
    let derived1 = derive_secret(suite.hash, &hs_secret, b"derived", &empty_hash);
    let master_secret = hkdf_extract(suite.hash, &derived1, &zeros);
    let c_ap_secret = derive_secret(suite.hash, &master_secret, b"c ap traffic", &hash_at_s_fin);
    let s_ap_secret = derive_secret(suite.hash, &master_secret, b"s ap traffic", &hash_at_s_fin);

    // Read Client Finished
    loop {
        let (rt, mut body) = read_raw_tls_record(&mut io_stream, &mut raw_rx_buf).await?;
        if rt == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        let hdr = [rt, 0x03, 0x03, (body.len() >> 8) as u8, body.len() as u8];
        let (inner_t, plen) = hs_read.open_record(&hdr, &mut body)?;
        if inner_t != TLS_RECORD_HANDSHAKE || plen != 36 || body[0] != TLS_HS_FINISHED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Client Finished",
            ));
        }
        let c_fin_key = hkdf_expand_label(suite.hash, &c_hs_secret, b"finished", &[], 32);
        let expected_c_fin = suite.hash.hmac_sign(&c_fin_key, &hash_at_s_fin);
        if body[4..36] != expected_c_fin[..] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Client Finished verify_data mismatch",
            ));
        }
        break;
    }

    Ok(Tls13VisionStream::from_parts(
        io_stream,
        RecordTrafficKeys::from_traffic_secret(suite, c_ap_secret)?,
        RecordTrafficKeys::from_traffic_secret(suite, s_ap_secret)?,
        raw_rx_buf,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn establish_reality_pair(
        duplex_buf: usize,
    ) -> (
        Tls13VisionStream<tokio::io::DuplexStream>,
        Tls13VisionStream<tokio::io::DuplexStream>,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let short_id = decode_reality_short_id("a1b2c3d4").unwrap();

        let (c_io, s_io) = tokio::io::duplex(duplex_buf);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id,
            server_name: "www.microsoft.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_io, &srv_sk_bytes, &short_id, "www.microsoft.com").await
        });
        let cli = connect_tls13_vision_stream(c_io, &mode).await.unwrap();
        let srv = srv_task.await.unwrap().unwrap();
        (cli, srv)
    }

    #[tokio::test]
    async fn reality_tls13_hybrid_pq_handshake_and_direct_unwrap_roundtrip() {
        let (mut cli, mut srv) = establish_reality_pair(64 * 1024).await;

        cli.write_all(b"encrypted reality ping").await.unwrap();
        cli.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = srv.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"encrypted reality ping");

        // Switch both sides to direct raw-TCP splice mode!
        cli.enable_direct_write();
        srv.enable_direct_read();
        cli.write_all(b"raw zero-copy vision payload")
            .await
            .unwrap();
        cli.flush().await.unwrap();
        let n2 = srv.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"raw zero-copy vision payload");
    }

    #[tokio::test]
    async fn tls13_vision_split_stream_backpressure_never_deadlocks() {
        let (cli, srv) = establish_reality_pair(256).await;
        let (mut cli_rd, mut cli_wr) = tokio::io::split(cli);
        let (mut srv_rd, mut srv_wr) = tokio::io::split(srv);

        let upload_payload: Vec<u8> = (0..(256 * 1024))
            .map(|i| ((i * 37 + 11) & 0xff) as u8)
            .collect();
        let download_payload: Vec<u8> = (0..(64 * 1024))
            .map(|i| ((i * 53 + 7) & 0xff) as u8)
            .collect();

        let expected_upload = upload_payload.clone();
        let expected_download = download_payload.clone();
        let upload_len = upload_payload.len();
        let download_len = download_payload.len();

        // Server writes continuously while reading in small backpressured chunks.
        let srv_rd_task = tokio::spawn(async move {
            let mut got = Vec::with_capacity(upload_len);
            let mut tmp = [0u8; 192];
            while got.len() < upload_len {
                let n = srv_rd.read(&mut tmp).await.unwrap();
                assert!(n > 0, "unexpected EOF while reading client upload");
                got.extend_from_slice(&tmp[..n]);
                if got.len() % 4096 < 192 {
                    tokio::task::yield_now().await;
                }
            }
            got
        });

        let srv_wr_task = tokio::spawn(async move {
            for chunk in download_payload.chunks(512) {
                srv_wr.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            srv_wr.flush().await.unwrap();
        });

        let cli_wr_task = tokio::spawn(async move {
            cli_wr.write_all(&upload_payload).await.unwrap();
            cli_wr.flush().await.unwrap();
        });

        let cli_rd_task = tokio::spawn(async move {
            let mut got = vec![0u8; download_len];
            cli_rd.read_exact(&mut got).await.unwrap();
            got
        });

        let (srv_got, (), (), cli_got) = tokio::time::timeout(Duration::from_secs(2), async {
            let (r1, r2, r3, r4) = tokio::join!(srv_rd_task, srv_wr_task, cli_wr_task, cli_rd_task);
            (r1.unwrap(), r2.unwrap(), r3.unwrap(), r4.unwrap())
        })
        .await
        .expect("split Tls13VisionStream deadlocked under duplex(256) backpressure");

        assert_eq!(srv_got, expected_upload);
        assert_eq!(cli_got, expected_download);
    }

    #[tokio::test]
    async fn tls13_vision_cancelled_pending_write_with_smaller_retry_never_panics() {
        let (mut cli, mut srv) = establish_reality_pair(256).await;

        let large_buf = vec![0x5Au8; 4096];
        let mut acknowledged = Vec::new();
        let mut hit_pending = false;

        // Drive `poll_write` with a 4096-byte buffer until it returns `Poll::Pending`,
        // then drop that pending write operation to simulate cancellation (e.g. `select!`).
        for _ in 0..8 {
            let mut single_poll_done = false;
            let outcome = std::future::poll_fn(|cx| {
                if single_poll_done {
                    return Poll::Ready(None);
                }
                single_poll_done = true;
                match Pin::new(&mut cli).poll_write(cx, &large_buf) {
                    Poll::Ready(res) => Poll::Ready(Some(res)),
                    Poll::Pending => Poll::Ready(None),
                }
            })
            .await;

            match outcome {
                Some(Ok(n)) => {
                    assert!(n <= large_buf.len());
                    acknowledged.extend_from_slice(&large_buf[..n]);
                }
                Some(Err(e)) => panic!("unexpected write error before Pending: {e}"),
                None => {
                    hit_pending = true;
                    break;
                }
            }
        }
        assert!(
            hit_pending,
            "expected poll_write(4096) to return Poll::Pending against full duplex(256)"
        );

        // Start draining server side, then retry with a 4-byte `write_all` (smaller than 4096!).
        let srv_task = tokio::spawn(async move {
            let mut all = Vec::new();
            srv.read_to_end(&mut all).await.unwrap();
            all
        });

        let tail = [1u8, 2, 3, 4];
        tokio::time::timeout(Duration::from_secs(2), async {
            cli.write_all(&tail).await.unwrap();
            cli.flush().await.unwrap();
            cli.shutdown().await.unwrap();
        })
        .await
        .expect("smaller retry write_all hung after cancelled Pending write");

        let received = tokio::time::timeout(Duration::from_secs(2), srv_task)
            .await
            .unwrap()
            .unwrap();
        let mut expected = acknowledged;
        expected.extend_from_slice(&tail);
        assert_eq!(received, expected);
    }

    struct AsymmetricDuplex {
        rd: Arc<parking_lot::Mutex<Option<tokio::io::DuplexStream>>>,
        wr: tokio::io::DuplexStream,
    }

    struct HalfDropHandle(Arc<parking_lot::Mutex<Option<tokio::io::DuplexStream>>>);

    impl HalfDropHandle {
        fn drop_reader(&self) {
            let _ = self.0.lock().take();
        }
    }

    impl AsyncRead for AsymmetricDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut guard = self.rd.lock();
            match guard.as_mut() {
                Some(stream) => Pin::new(stream).poll_read(cx, buf),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for AsymmetricDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.wr).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_shutdown(cx)
        }
    }

    fn asymmetric_duplex(
        c2s_buf: usize,
        s2c_buf: usize,
    ) -> (AsymmetricDuplex, AsymmetricDuplex, HalfDropHandle) {
        let (c2s_client, c2s_server) = tokio::io::duplex(c2s_buf);
        let (s2c_server, s2c_client) = tokio::io::duplex(s2c_buf);
        let srv_rd = Arc::new(parking_lot::Mutex::new(Some(c2s_server)));
        let drop_srv_rd = HalfDropHandle(Arc::clone(&srv_rd));
        let client = AsymmetricDuplex {
            rd: Arc::new(parking_lot::Mutex::new(Some(s2c_client))),
            wr: c2s_client,
        };
        let server = AsymmetricDuplex {
            rd: srv_rd,
            wr: s2c_server,
        };
        (client, server, drop_srv_rd)
    }

    async fn establish_reality_asymmetric_pair(
        c2s_buf: usize,
        s2c_buf: usize,
    ) -> (
        Tls13VisionStream<AsymmetricDuplex>,
        Tls13VisionStream<AsymmetricDuplex>,
        HalfDropHandle,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let short_id = decode_reality_short_id("a1b2c3d4").unwrap();

        let (c_io, s_io, drop_srv_rd) = asymmetric_duplex(c2s_buf, s2c_buf);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id,
            server_name: "www.microsoft.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_io, &srv_sk_bytes, &short_id, "www.microsoft.com").await
        });
        let cli = connect_tls13_vision_stream(c_io, &mode).await.unwrap();
        let srv = srv_task.await.unwrap().unwrap();
        (cli, srv, drop_srv_rd)
    }

    #[tokio::test]
    async fn tls13_vision_asymmetric_broken_uplink_drains_buffered_and_async_gapped_response() {
        let (cli, mut srv, drop_srv_rd) = establish_reality_asymmetric_pair(256, 4096).await;
        let (mut c_rd, mut c_wr) = tokio::io::split(cli);

        // Client writes 16 KiB -> sealed in `enc_tx_buf` and acknowledged immediately while
        // ~16 KiB remains queued behind the 256-byte uplink pipe.
        let n = c_wr.write(&vec![0xAAu8; 16 * 1024]).await.unwrap();
        assert_eq!(n, 16 * 1024);

        // Server sends early HTTP 413 headers, closes client uplink (BrokenPipe), waits across
        // an async gap, then sends the body + TLS 1.3 close_notify.
        let srv_task = tokio::spawn(async move {
            srv.write_all(b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                .await
                .unwrap();
            srv.flush().await.unwrap();
            drop_srv_rd.drop_reader();
            tokio::time::sleep(Duration::from_millis(25)).await;
            srv.write_all(b"entity too large after async gap")
                .await
                .unwrap();
            srv.flush().await.unwrap();
            srv.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), c_rd.read_to_end(&mut got))
            .await
            .expect("read_to_end hung draining early TLS 1.3 response after broken uplink")
            .expect("poll_read must drain buffered + async-gapped TLS 1.3 response cleanly");
        assert_eq!(
            got,
            b"HTTP/1.1 413 Payload Too Large\r\n\r\nentity too large after async gap"
        );
        srv_task.await.unwrap();

        // Write path MUST still surface the real BrokenPipe directly to the writer.
        let flush_err = c_wr
            .flush()
            .await
            .expect_err("flush must still surface BrokenPipe");
        assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);
        let write_err = c_wr
            .write(b"after-broken")
            .await
            .expect_err("write must still surface BrokenPipe");
        assert_eq!(write_err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn tls13_vision_dec_rx_buf_already_decrypted_bytes_survive_uplink_broken_pipe() {
        let (cli, mut srv, drop_srv_rd) = establish_reality_asymmetric_pair(256, 4096).await;
        let (mut c_rd, mut c_wr) = tokio::io::split(cli);

        let payload: Vec<u8> = (0u8..64u8).collect();
        srv.write_all(&payload).await.unwrap();
        srv.flush().await.unwrap();

        // Read only 8 bytes, leaving 56 already-decrypted bytes inside `dec_rx_buf`.
        let mut head = [0u8; 8];
        c_rd.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, &payload[..8]);

        // Queue 16 KiB into `enc_tx_buf`, then break uplink and send close_notify.
        let n = c_wr.write(&vec![0xBBu8; 16 * 1024]).await.unwrap();
        assert_eq!(n, 16 * 1024);
        drop_srv_rd.drop_reader();
        srv.shutdown().await.unwrap();

        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), c_rd.read_to_end(&mut rest))
            .await
            .expect("read_to_end hung draining dec_rx_buf")
            .expect("already-decrypted dec_rx_buf bytes must survive uplink BrokenPipe");
        assert_eq!(rest, payload[8..]);

        let flush_err = c_wr
            .flush()
            .await
            .expect_err("flush must still surface BrokenPipe");
        assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn tls13_vision_silent_broken_uplink_fast_fails_and_truncated_record_errors() {
        // 1. Silent broken uplink: server drops uplink read half without sending any TLS data.
        {
            let (cli, _srv, drop_srv_rd) = establish_reality_asymmetric_pair(256, 4096).await;
            let (mut c_rd, mut c_wr) = tokio::io::split(cli);

            let n = c_wr.write(&vec![0xCCu8; 16 * 1024]).await.unwrap();
            assert_eq!(n, 16 * 1024);
            drop_srv_rd.drop_reader();

            let mut buf = [0u8; 64];
            let err = tokio::time::timeout(Duration::from_millis(500), c_rd.read(&mut buf))
                .await
                .expect("silent broken uplink must fast-fail without hanging")
                .expect_err("silent broken uplink must return BrokenPipe");
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }

        // 2. Truncated TLS 1.3 record on EOF with broken uplink must still surface UnexpectedEof.
        {
            let (cli, mut srv, drop_srv_rd) = establish_reality_asymmetric_pair(256, 4096).await;
            let (mut c_rd, mut c_wr) = tokio::io::split(cli);

            let n = c_wr.write(&vec![0xDDu8; 16 * 1024]).await.unwrap();
            assert_eq!(n, 16 * 1024);
            drop_srv_rd.drop_reader();

            // Write an incomplete raw TLS 1.3 record header+partial body directly on server wire
            // and drop the server stream to trigger abrupt mid-record EOF.
            srv.inner
                .write_all(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x40, 1, 2, 3])
                .await
                .unwrap();
            srv.inner.flush().await.unwrap();
            drop(srv);

            let mut buf = [0u8; 64];
            let err = tokio::time::timeout(Duration::from_millis(500), c_rd.read(&mut buf))
                .await
                .expect("truncated record read hung")
                .expect_err("truncated TLS 1.3 record must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn tls13_vision_post_key_update_broken_uplink_delivers_application_data() {
        let (cli, mut srv, drop_srv_rd) = establish_reality_asymmetric_pair(256, 4096).await;
        let (mut c_rd, mut c_wr) = tokio::io::split(cli);

        // Server initiates TLS 1.3 KeyUpdate(update_requested = 1), rolls its write keys,
        // sends application data + close_notify under the new keys, and drops client's uplink
        // so the client's post-KeyUpdate response drain hits BrokenPipe!
        let ku_req = [TLS_HS_KEY_UPDATE, 0, 0, 1, 1];
        srv.write_keys
            .seal_record(TLS_RECORD_HANDSHAKE, &ku_req, &mut srv.enc_tx_buf)
            .unwrap();
        srv.write_keys.roll_key_update().unwrap();
        srv.flush().await.unwrap();
        srv.write_all(b"post-key-update-payload").await.unwrap();
        srv.flush().await.unwrap();
        srv.shutdown().await.unwrap();
        drop_srv_rd.drop_reader();

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), c_rd.read_to_end(&mut got))
            .await
            .expect("read_to_end hung after post-KeyUpdate broken uplink")
            .expect("post-KeyUpdate application data must be delivered despite uplink BrokenPipe");
        assert_eq!(got, b"post-key-update-payload");

        let flush_err = c_wr
            .flush()
            .await
            .expect_err("writer flush must still surface BrokenPipe for queued KeyUpdate ack");
        assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn tls13_vision_buffered_transport_flush_and_split_dropped_reader_waker_isolation() {
        // 1. Buffered underlying transport (`BufStream`): client writes without explicit `flush()`
        //    and immediately calls `read()`; opportunistic `poll_flush_tx_from_read` must flush
        //    through `BufStream` so the server receives the request and replies.
        {
            let mut srv_sk_bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut srv_sk_bytes);
            let srv_sk = X25519Secret::from(srv_sk_bytes);
            let srv_pk = X25519PublicKey::from(&srv_sk);
            let short_id = decode_reality_short_id("a1b2c3d4").unwrap();
            let (c_raw, s_raw) = tokio::io::duplex(64 * 1024);
            let c_buf = tokio::io::BufStream::new(c_raw);
            let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
                public_key: *srv_pk.as_bytes(),
                short_id,
                server_name: "www.microsoft.com".to_string(),
                fingerprint: "chrome".to_string(),
                spider_x: "/".to_string(),
                alpn: Vec::new(),
            });

            let srv_task = tokio::spawn(async move {
                let mut srv = accept_reality_tls13_server(
                    s_raw,
                    &srv_sk_bytes,
                    &short_id,
                    "www.microsoft.com",
                )
                .await
                .unwrap();
                let mut req = [0u8; 16];
                srv.read_exact(&mut req).await.unwrap();
                assert_eq!(&req, b"unflushed-buf-tx");
                srv.write_all(b"buffered-ok").await.unwrap();
                srv.flush().await.unwrap();
            });

            let mut cli = connect_tls13_vision_stream(c_buf, &mode).await.unwrap();
            cli.write_all(b"unflushed-buf-tx").await.unwrap();
            // Intentionally skip `cli.flush()` and go straight to `read_exact`!
            let mut resp = [0u8; 11];
            tokio::time::timeout(Duration::from_secs(2), cli.read_exact(&mut resp))
                .await
                .expect("read over BufStream hung waiting for opportunistic inner.poll_flush")
                .unwrap();
            assert_eq!(&resp, b"buffered-ok");
            srv_task.await.unwrap();
        }

        // 2. Split-stream `Task W != Task R`: writer parked on saturated `duplex(256)` while reader
        //    reads an early server push and exits/drops `c_rd` BEFORE server drains the upload.
        //    `FanoutWaker` must preserve writer wakeup so upload completes without deadlock.
        {
            let (cli, srv) = establish_reality_pair(256).await;
            let (mut c_rd, mut c_wr) = tokio::io::split(cli);
            let (mut s_rd, mut s_wr) = tokio::io::split(srv);

            let upload: Vec<u8> = (0..(64 * 1024))
                .map(|i| ((i * 17 + 5) & 0xff) as u8)
                .collect();
            let expected_upload = upload.clone();

            let (rd_done_tx, rd_done_rx) = tokio::sync::oneshot::channel::<()>();
            let wr_task = tokio::spawn(async move {
                c_wr.write_all(&upload).await.unwrap();
                c_wr.flush().await.unwrap();
            });

            // Let writer saturate `duplex(256)` and park in `poll_write`.
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Reader reads early server push, then exits and drops `c_rd`!
            let rd_task = tokio::spawn(async move {
                let mut early = [0u8; 10];
                c_rd.read_exact(&mut early).await.unwrap();
                assert_eq!(&early, b"early-push");
                drop(c_rd);
                let _ = rd_done_tx.send(());
            });

            s_wr.write_all(b"early-push").await.unwrap();
            s_wr.flush().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), rd_done_rx)
                .await
                .expect("reader did not finish early push")
                .unwrap();
            rd_task.await.unwrap();

            // Now server drains the 64 KiB upload after `c_rd` has already been dropped!
            let mut got = vec![0u8; expected_upload.len()];
            tokio::time::timeout(Duration::from_secs(2), s_rd.read_exact(&mut got))
                .await
                .expect("split writer deadlocked after reader exited and dropped c_rd")
                .unwrap();
            assert_eq!(got, expected_upload);
            tokio::time::timeout(Duration::from_secs(2), wr_task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    async fn establish_reality_bufstream_pair(
        duplex_buf: usize,
    ) -> (
        Tls13VisionStream<tokio::io::BufStream<tokio::io::DuplexStream>>,
        Tls13VisionStream<tokio::io::DuplexStream>,
    ) {
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let short_id = decode_reality_short_id("a1b2c3d4").unwrap();

        let (c_raw, s_raw) = tokio::io::duplex(duplex_buf);
        let c_buf = tokio::io::BufStream::new(c_raw);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id,
            server_name: "www.microsoft.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });

        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_raw, &srv_sk_bytes, &short_id, "www.microsoft.com").await
        });
        let cli = connect_tls13_vision_stream(c_buf, &mode).await.unwrap();
        let srv = srv_task.await.unwrap().unwrap();
        (cli, srv)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls13_vision_direct_write_bufstream_split_uncancelled_write_never_deadlocks() {
        let (mut cli, mut srv) = establish_reality_bufstream_pair(256).await;
        cli.enable_direct_write();
        srv.enable_direct_read();

        let (mut c_rd, mut c_wr) = tokio::io::split(cli);
        let req1: Vec<u8> = (0..4096).map(|i| ((i * 13 + 3) & 0xff) as u8).collect();
        let req2: Vec<u8> = (0..4097).map(|i| ((i * 29 + 7) & 0xff) as u8).collect();
        let mut expected = Vec::with_capacity(req1.len() + req2.len());
        expected.extend_from_slice(&req1);
        expected.extend_from_slice(&req2);

        let (wr_parked_tx, wr_parked_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            start_srv_rx.await.unwrap();
            let mut got = vec![0u8; expected.len()];
            srv.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            srv.write_all(b"TLS13-DIRECT-OK!").await.unwrap();
            srv.flush().await.unwrap();
        });

        // Task W writes 4096 B (buffered in BufStream, inner_needs_flush = true) followed by
        // 4097 B (exceeding 8192 B BufWriter capacity -> flushes 256 B into duplex(256) and parks
        // Pending in direct_write), then exits cleanly WITHOUT calling `flush()`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req1).await.unwrap();
            let _ = wr_parked_tx.send(());
            c_wr.write_all(&req2).await.unwrap();
        });

        wr_parked_rx.await.unwrap();
        // Let Task W enter `poll_write(&req2)` and park on saturated `duplex(256)`.
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Task R polls `read_exact` while Task W owns `tx_fanout` write slot.
        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 16];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        // Let Task R execute `poll_flush_tx_from_read` while Task W is parked in `poll_write`.
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (wr_res, rd_res, srv_res) = tokio::join!(wr_task, rd_task, srv_task);
            wr_res.unwrap();
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "Tls13VisionStream direct_write + BufStream split reader deadlocked with zero-cancellation write without flush",
        );
        assert_eq!(&reply, b"TLS13-DIRECT-OK!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls13_vision_direct_write_bufstream_split_cancelled_flush_never_deadlocks() {
        let (mut cli, mut srv) = establish_reality_bufstream_pair(256).await;
        cli.enable_direct_write();
        cli.enable_direct_read();
        srv.enable_direct_read();
        srv.enable_direct_write();

        let (mut c_rd, mut c_wr) = tokio::io::split(cli);
        let req: Vec<u8> = (0..4096).map(|i| ((i * 19 + 5) & 0xff) as u8).collect();
        let expected = req.clone();

        let (buffered_tx, buffered_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            start_srv_rx.await.unwrap();
            let mut got = vec![0u8; expected.len()];
            srv.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            srv.write_all(b"TLS13-CANCEL-OK!").await.unwrap();
            srv.flush().await.unwrap();
        });

        // Task W buffers 4096 B in BufStream, parks in `flush()` against saturated `duplex(256)`,
        // and cancels `flush()` on timeout, leaving a stale writer waker in `tx_fanout`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&req).await.unwrap();
            let _ = buffered_tx.send(());
            let timed_out = tokio::time::timeout(Duration::from_millis(60), c_wr.flush())
                .await
                .is_err();
            assert!(
                timed_out,
                "expected direct_write BufStream flush() to time out on full duplex(256)"
            );
        });

        buffered_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Task R polls `read_exact` while Task W is parked in `flush()`.
        let rd_task = tokio::spawn(async move {
            let mut reply = [0u8; 16];
            c_rd.read_exact(&mut reply).await.unwrap();
            reply
        });

        // Wait for Task W's timeout cancellation to complete, then let server drain duplex(256).
        wr_task.await.unwrap();
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .expect(
            "Tls13VisionStream direct_write + BufStream split reader deadlocked after timeout-cancelled flush()",
        );
        assert_eq!(&reply, b"TLS13-CANCEL-OK!");
    }

    async fn run_pre_parked_cancelled_shutdown_scenario<S>(
        cli: Tls13VisionStream<S>,
        mut srv: Tls13VisionStream<tokio::io::DuplexStream>,
        expected_reply: &'static [u8],
        label: &'static str,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut c_rd, mut c_wr) = tokio::io::split(cli);

        // 234 B plaintext + 22 B TLS 1.3 outer header/inner type/AEAD tag = exact 256 B wire
        // record -> saturates `duplex(256)` 256/256 while leaving `enc_tx_buf` empty and
        // `inner_needs_flush == false`.
        let req: Vec<u8> = (0..234).map(|i| ((i * 23 + 9) & 0xff) as u8).collect();
        let expected_req = req.clone();
        c_wr.write_all(&req).await.unwrap();
        c_wr.flush().await.unwrap();

        let (rd_started_tx, rd_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            start_srv_rx.await.unwrap();
            // Server reads the 234-byte payload AND waits for client's TLS 1.3 close_notify (EOF)
            // before sending its reply (standard half-close RPC/HTTP pattern).
            let mut got = Vec::new();
            srv.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, expected_req);
            srv.write_all(expected_reply).await.unwrap();
            srv.flush().await.unwrap();
            srv.shutdown().await.unwrap();
        });

        // Pre-park split Task R in `read_to_end()` while `enc_tx_buf` is empty and
        // `!inner_needs_flush` -> `tx_fanout` enters `(read_tx: None, write_tx: None, parked_read: Some(R))`.
        let rd_task = tokio::spawn(async move {
            let _ = rd_started_tx.send(());
            let mut reply = Vec::new();
            c_rd.read_to_end(&mut reply).await.unwrap();
            reply
        });

        rd_started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Split Task W attempts `shutdown()`, sealing TLS 1.3 `close_notify` into TX and parking
        // `Pending` against saturated `duplex(256)`, then cancels on timeout.
        let wr_task = tokio::spawn(async move {
            let timed_out = tokio::time::timeout(Duration::from_millis(30), c_wr.shutdown())
                .await
                .is_err();
            assert!(
                timed_out,
                "{label}: expected shutdown() to time out against saturated duplex(256)"
            );
            c_wr
        });
        let _c_wr = wr_task.await.unwrap();

        // Now let the server drain the saturated pipe; Task R must drain the stranded
        // `close_notify` and receive the complete server reply without deadlocking.
        let _ = start_srv_tx.send(());

        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let (rd_res, srv_res) = tokio::join!(rd_task, srv_task);
            srv_res.unwrap();
            rd_res.unwrap()
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{label}: pre-parked split Task R deadlocked after timeout-cancelled shutdown() (close_notify stranded in TX)"
            )
        });
        assert_eq!(reply, expected_reply);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls13_vision_raw_duplex_pre_parked_reader_cancelled_shutdown_never_deadlocks() {
        let (cli, srv) = establish_reality_pair(256).await;
        run_pre_parked_cancelled_shutdown_scenario(
            cli,
            srv,
            b"TLS13-RAW-SHUTDOWN-OK!",
            "Tls13VisionStream<DuplexStream>",
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls13_vision_bufstream_pre_parked_reader_cancelled_shutdown_never_deadlocks() {
        // 1. Default 8 KiB `BufStream<DuplexStream>` (`close_notify` enters BufStream write buffer
        //    and `inner.poll_flush` returns `Poll::Pending`).
        let (cli, srv) = establish_reality_bufstream_pair(256).await;
        run_pre_parked_cancelled_shutdown_scenario(
            cli,
            srv,
            b"TLS13-BUFSTREAM-SHUTDOWN-OK!",
            "Tls13VisionStream<BufStream<DuplexStream>>",
        )
        .await;

        // 2. Small-buffer `BufStream::with_capacity(16, 16, DuplexStream)` (24 B `close_notify`
        //    exceeds BufWriter capacity, so `poll_drain_tx_from_write` itself hits `Poll::Pending`).
        let mut srv_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut srv_sk_bytes);
        let srv_sk = X25519Secret::from(srv_sk_bytes);
        let srv_pk = X25519PublicKey::from(&srv_sk);
        let short_id = decode_reality_short_id("a1b2c3d4").unwrap();
        let (c_raw, s_raw) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::with_capacity(16, 16, c_raw);
        let mode = Tls13HandshakeMode::Reality(RealityClientConfig {
            public_key: *srv_pk.as_bytes(),
            short_id,
            server_name: "www.microsoft.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: Vec::new(),
        });
        let srv_task = tokio::spawn(async move {
            accept_reality_tls13_server(s_raw, &srv_sk_bytes, &short_id, "www.microsoft.com").await
        });
        let cli_small = connect_tls13_vision_stream(c_buf, &mode).await.unwrap();
        let srv_small = srv_task.await.unwrap().unwrap();
        run_pre_parked_cancelled_shutdown_scenario(
            cli_small,
            srv_small,
            b"TLS13-BUFSTREAM-SMALL-OK!",
            "Tls13VisionStream<BufStream(16)<DuplexStream>>",
        )
        .await;
    }

    #[test]
    fn der_tlv_and_tls13_certificate_list_reject_overflow_and_truncated_lengths() {
        // 1. Valid short-form and multi-octet DER TLV.
        let (tag, val, rest) = read_der_tlv(&[0x30, 0x03, 0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(val, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(rest, &[0xdd]);

        let (tag2, val2, rest2) = read_der_tlv(&[0x04, 0x81, 0x02, 0x11, 0x22]).unwrap();
        assert_eq!(tag2, 0x04);
        assert_eq!(val2, &[0x11, 0x22]);
        assert!(rest2.is_empty());

        // 2. Crafted 4-octet u32::MAX / near-u32::MAX lengths must fail cleanly without overflow
        //    or OOB panic on both 32-bit and 64-bit targets.
        for bad_der in [
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff][..],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xfa][..],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xf9, 0x00][..],
            &[0x30, 0x80][..],
            &[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01][..],
            &[0x30, 0x05, 0x01, 0x02][..],
        ] {
            let err = read_der_tlv(bad_der).expect_err("crafted DER TLV must return InvalidData");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 3. Valid TLS 1.3 Certificate list with 2 entries and extensions.
        let mut valid_body = vec![
            0x00, // request_context len = 0
            0x00, 0x00, 15, // certificate_list len = 15
            // Entry 1: 3B cert + 2B ext = 10B total
            0x00, 0x00, 0x03, 0x30, 0x01, 0x02, 0x00, 0x02, 0xaa, 0xbb,
            // Entry 2: 0B cert + 0B ext = 5B total
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let certs = parse_tls13_certificate_list(&valid_body).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), &[0x30, 0x01, 0x02]);

        // 4. Crafted `ext_len` exceeding the certificate list boundary must be rejected cleanly.
        let bad_ext_body = vec![
            0x00, // request_context len = 0
            0x00, 0x00, 0x07, // certificate_list len = 7
            0x00, 0x00, 0x02, 0x30, 0x00, // 2-byte cert
            0xff, 0xff, // ext_len = 65535 > remaining 0 bytes!
        ];
        let err = parse_tls13_certificate_list(&bad_ext_body)
            .expect_err("oversized CertificateEntry extensions length must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // 5. Trailing truncated entry header (< 3 bytes) inside certificate_list must be rejected.
        valid_body[3] = 17; // list_len = 17
        valid_body.extend_from_slice(&[0x00, 0x01]);
        let err = parse_tls13_certificate_list(&valid_body)
            .expect_err("truncated trailing CertificateEntry header must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tls13_vision_split_post_handshake_key_update_and_interleaving_rules() {
        // 1. KeyUpdate(request_update = 0) split across 2 TLS 1.3 handshake records (2 B + 3 B)
        //    followed by AEAD application data encrypted with the rolled key.
        {
            let (mut cli, mut srv) = establish_reality_pair(16 * 1024).await;
            let ku = [TLS_HS_KEY_UPDATE, 0, 0, 1, 0];
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &ku[..2], &mut srv.enc_tx_buf)
                .unwrap();
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &ku[2..], &mut srv.enc_tx_buf)
                .unwrap();
            srv.write_keys.roll_key_update().unwrap();
            srv.flush().await.unwrap();
            srv.write_all(b"decrypted-after-split-key-update")
                .await
                .unwrap();
            srv.flush().await.unwrap();
            srv.shutdown().await.unwrap();

            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), cli.read_to_end(&mut got))
                .await
                .expect("read_to_end timed out after split KeyUpdate")
                .expect("split KeyUpdate must roll read keys cleanly");
            assert_eq!(got, b"decrypted-after-split-key-update");
        }

        // 2. Coalesced NewSessionTicket + split KeyUpdate(request_update = 1) across 3 records,
        //    verifying BOTH directions roll keys and exchange post-KeyUpdate traffic cleanly.
        {
            let (mut cli, mut srv) = establish_reality_pair(16 * 1024).await;
            let mut nst_and_ku = vec![TLS_HS_NEW_SESSION_TICKET, 0, 0, 4, 1, 2, 3, 4];
            let ku1 = [TLS_HS_KEY_UPDATE, 0, 0, 1, 1];
            nst_and_ku.extend_from_slice(&ku1);

            // Split mid-NST, mid-KU-header, and mid-KU-body.
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &nst_and_ku[..6], &mut srv.enc_tx_buf)
                .unwrap();
            srv.write_keys
                .seal_record(
                    TLS_RECORD_HANDSHAKE,
                    &nst_and_ku[6..10],
                    &mut srv.enc_tx_buf,
                )
                .unwrap();
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &nst_and_ku[10..], &mut srv.enc_tx_buf)
                .unwrap();
            srv.write_keys.roll_key_update().unwrap();
            srv.flush().await.unwrap();
            srv.write_all(b"s2c-rolled").await.unwrap();
            srv.flush().await.unwrap();

            let mut s2c = [0u8; 10];
            tokio::time::timeout(Duration::from_secs(2), cli.read_exact(&mut s2c))
                .await
                .expect("client read after split KeyUpdate(1) timed out")
                .unwrap();
            assert_eq!(&s2c, b"s2c-rolled");

            // Client also rolled its write keys and queued KeyUpdate(0); verify server decrypts
            // both the KeyUpdate(0) ack and subsequent client-to-server application data.
            cli.write_all(b"c2s-rolled").await.unwrap();
            cli.flush().await.unwrap();
            let mut c2s = [0u8; 10];
            tokio::time::timeout(Duration::from_secs(2), srv.read_exact(&mut c2s))
                .await
                .expect("server read after client KeyUpdate ack timed out")
                .unwrap();
            assert_eq!(&c2s, b"c2s-rolled");
        }

        // 3. RFC 8446 §5.1: ApplicationData interleaved while a post-handshake message is
        //    incomplete MUST be rejected with InvalidData.
        {
            let (mut cli, mut srv) = establish_reality_pair(16 * 1024).await;
            let partial_ku = [TLS_HS_KEY_UPDATE, 0];
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &partial_ku, &mut srv.enc_tx_buf)
                .unwrap();
            srv.write_keys
                .seal_record(
                    TLS_RECORD_APPLICATION_DATA,
                    b"illegal-interleave",
                    &mut srv.enc_tx_buf,
                )
                .unwrap();
            srv.flush().await.unwrap();

            let mut buf = [0u8; 32];
            let err = tokio::time::timeout(Duration::from_secs(2), cli.read(&mut buf))
                .await
                .expect("read timed out")
                .expect_err("interleaved ApplicationData mid-handshake message must fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 4. Oversized post-handshake message header (> MAX_POST_HANDSHAKE_BUF) must be rejected
        //    immediately with InvalidData.
        {
            let (mut cli, mut srv) = establish_reality_pair(16 * 1024).await;
            // NewSessionTicket header declaring 64 KiB body -> 4 + 65536 > 65536 cap.
            let oversized_hdr = [TLS_HS_NEW_SESSION_TICKET, 0x01, 0x00, 0x00];
            srv.write_keys
                .seal_record(TLS_RECORD_HANDSHAKE, &oversized_hdr, &mut srv.enc_tx_buf)
                .unwrap();
            srv.flush().await.unwrap();

            let mut buf = [0u8; 32];
            let err = tokio::time::timeout(Duration::from_secs(2), cli.read(&mut buf))
                .await
                .expect("read timed out")
                .expect_err("oversized post-handshake message must fail with InvalidData");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 5. Abrupt EOF with an incomplete buffered post-handshake message must return
        //    UnexpectedEof rather than clean EOF.
        {
            let (mut cli, mut srv) = establish_reality_pair(16 * 1024).await;
            srv.write_keys
                .seal_record(
                    TLS_RECORD_HANDSHAKE,
                    &[TLS_HS_KEY_UPDATE, 0, 0],
                    &mut srv.enc_tx_buf,
                )
                .unwrap();
            srv.flush().await.unwrap();
            drop(srv);

            let mut buf = [0u8; 32];
            let err = tokio::time::timeout(Duration::from_secs(2), cli.read(&mut buf))
                .await
                .expect("read timed out")
                .expect_err("EOF mid-post-handshake message must return UnexpectedEof");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }
    }
}
