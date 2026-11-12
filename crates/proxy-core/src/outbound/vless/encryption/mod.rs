pub mod config;
pub mod keys;
pub mod stream;

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use aws_lc_rs::kem::{
    Ciphertext as LcCiphertext, DecapsulationKey as LcDecapKey, EncapsulationKey as LcEncapKey,
    ML_KEM_768,
};
use bytes::BytesMut;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::outbound::vless::encryption::{
    config::{
        PaddingPolicy, ParsedServerConfig, XorMode, parse_client_encryption,
        parse_server_decryption, xray_rand_between_usize,
    },
    keys::{
        ClientNfsKey, MAX_NONCE, ServerNfsKey, VlessAead, VlessCtr, client_build_iv_and_relays,
        random_array, random_vec, server_decode_relays, total_relays_len_server,
    },
    stream::VlessEncryptedStream,
};

pub use keys::{GeneratedVlessPair, generate_vless_encryption_pair};

#[derive(Clone)]
struct CachedClientTicket {
    expire_at: Instant,
    pfs_key: Zeroizing<[u8; 64]>,
    ticket: [u8; 16],
}

/// Client-side Xray `mlkem768x25519plus` Post-Quantum Hybrid Encryption Engine (1-RTT + 0-RTT).
pub struct ClientEncryption {
    mode: XorMode,
    enable_0rtt: bool,
    padding: PaddingPolicy,
    keys: Vec<ClientNfsKey>,
    use_aes: bool,
    ticket_cache: Arc<Mutex<Option<CachedClientTicket>>>,
}

impl ClientEncryption {
    pub fn new(spec: &str) -> io::Result<Self> {
        let parsed = parse_client_encryption(spec)?;
        let mut keys = Vec::with_capacity(parsed.key_tokens.len());
        for tok in &parsed.key_tokens {
            keys.push(ClientNfsKey::from_b64_token(tok)?);
        }
        Ok(Self {
            mode: parsed.mode,
            enable_0rtt: parsed.enable_0rtt,
            padding: parsed.padding,
            keys,
            use_aes: detect_aes_hardware(),
            ticket_cache: Arc::new(Mutex::new(None)),
        })
    }

    pub fn has_valid_0rtt_ticket(&self) -> bool {
        self.ticket_cache
            .lock()
            .as_ref()
            .is_some_and(|t| Instant::now() < t.expire_at)
    }

    /// Wrap a raw transport stream (`TcpStream`, etc.) in a `mlkem768x25519plus` encrypted session.
    /// Automatically uses 0-RTT ticket resumption when enabled & valid, or full 1-RTT PQ handshake otherwise.
    pub async fn handshake<S>(&self, mut io_stream: S) -> io::Result<VlessEncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.enable_0rtt {
            let cached = {
                let guard = self.ticket_cache.lock();
                guard
                    .as_ref()
                    .filter(|c| Instant::now() < c.expire_at)
                    .cloned()
            };
            if let Some(ticket_entry) = cached {
                return self.build_0rtt_stream(io_stream, ticket_entry);
            }
        }

        // Full 1-RTT Post-Quantum Hybrid Handshake
        let (iv, iv_and_relays, nfs_key) = client_build_iv_and_relays(&self.keys, self.mode)?;
        let mut nfs_aead = VlessAead::new(&iv, nfs_key.as_ref(), self.use_aes)?;

        // Ephemeral ML-KEM-768 (1184B ek) + Ephemeral X25519 (32B pk) = 1216B `clientPfsPublicKey`
        let ephem_decap = LcDecapKey::generate(&ML_KEM_768)
            .map_err(|_| io::Error::other("ML-KEM-768 ephemeral keygen failed"))?;
        let ephem_encap: LcEncapKey = ephem_decap
            .encapsulation_key()
            .map_err(|_| io::Error::other("ML-KEM-768 encapsulation_key failed"))?;
        let ephem_ek_bytes = ephem_encap
            .key_bytes()
            .map_err(|_| io::Error::other("ML-KEM-768 key_bytes failed"))?;

        let ephem_x_seed = random_array::<32>()?;
        let ephem_x_sk = X25519Secret::from(ephem_x_seed);
        let ephem_x_pk = X25519PublicKey::from(&ephem_x_sk);

        let mut client_pfs_pub = Vec::with_capacity(1216);
        client_pfs_pub.extend_from_slice(ephem_ek_bytes.as_ref());
        client_pfs_pub.extend_from_slice(ephem_x_pk.as_bytes());

        let (pad_lens, pad_gaps, total_pad_len) = self.padding.sample();
        let pad_plain_len = total_pad_len - 34; // >= 1 byte

        // Seal 4 blocks under `nfsAEAD` (`nonces 1, 2, 3, 4`)
        let enc_len_pfs = nfs_aead.seal(&1232u16.to_be_bytes(), b"")?; // 18B (nonce 1)
        let enc_pfs_pub = nfs_aead.seal(&client_pfs_pub, b"")?; // 1232B (nonce 2)
        let enc_pad_len = nfs_aead.seal(&((total_pad_len - 18) as u16).to_be_bytes(), b"")?; // 18B (nonce 3)
        let enc_pad_body = nfs_aead.seal(&vec![0u8; pad_plain_len], b"")?; // total_pad_len - 18 B (nonce 4)

        let mut client_hello = Vec::with_capacity(iv_and_relays.len() + 1250 + total_pad_len);
        client_hello.extend_from_slice(&iv_and_relays);
        client_hello.extend_from_slice(&enc_len_pfs);
        client_hello.extend_from_slice(&enc_pfs_pub);
        client_hello.extend_from_slice(&enc_pad_len);
        client_hello.extend_from_slice(&enc_pad_body);

        // Fragmented write per `paddingLens` / `paddingGaps`:
        // Fragment 0 size = `(16 + RelaysLen) + 1250 + pad_lens[0]`
        let prefix_core = iv_and_relays.len() + 1250;
        write_fragmented_hello(
            &mut io_stream,
            &client_hello,
            prefix_core,
            &pad_lens,
            &pad_gaps,
        )
        .await?;

        // Read `serverHello` fixed portion: `1136 (serverPfsPub) + 32 (ticket) + 18 (serverPadLen) = 1186 bytes`
        let mut srv_hello_fixed = vec![0u8; 1186];
        io_stream.read_exact(&mut srv_hello_fixed).await?;

        // Open `serverPfsPublicKey (1120B)` using `nfsAEAD` at explicit `MaxNonce = [0xFF; 12]`
        let server_pfs_pub = nfs_aead.open_at(MAX_NONCE, &srv_hello_fixed[..1136], b"")?;
        if server_pfs_pub.len() != 1120 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid VLESS serverPfsPublicKey length",
            ));
        }

        // Decapsulate ML-KEM-768 ct (1088B) + X25519 ECDH (32B) -> `pfsKey (64B)`
        let mlkem_ss = ephem_decap
            .decapsulate(LcCiphertext::from(&server_pfs_pub[..1088]))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS 1-RTT ML-KEM-768 decapsulation failed",
                )
            })?;
        let srv_x_pk_arr: [u8; 32] = server_pfs_pub[1088..1120].try_into().unwrap();
        let x_ss = ephem_x_sk.diffie_hellman(&X25519PublicKey::from(srv_x_pk_arr));
        if x_ss.as_bytes().iter().all(|&b| b == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "low-order server X25519 public key",
            ));
        }

        let mut pfs_key = Zeroizing::new([0u8; 64]);
        pfs_key[..32].copy_from_slice(mlkem_ss.as_ref());
        pfs_key[32..64].copy_from_slice(x_ss.as_bytes());

        let mut united_key = Zeroizing::new([0u8; 96]);
        united_key[..64].copy_from_slice(pfs_key.as_ref());
        united_key[64..96].copy_from_slice(nfs_key.as_ref());

        let write_aead = VlessAead::new(&client_pfs_pub, united_key.as_ref(), self.use_aes)?;
        let mut read_aead = VlessAead::new(&server_pfs_pub, united_key.as_ref(), self.use_aes)?;

        // Open `ticket (16B)` (nonce 1) and `serverPadWireLen` (nonce 2)
        let ticket_plain = read_aead.open(&srv_hello_fixed[1136..1168], b"")?;
        let ticket_arr: [u8; 16] = ticket_plain.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid VLESS ticket length")
        })?;
        let ticket_secs = u16::from_be_bytes([ticket_arr[0], ticket_arr[1]]);

        let srv_pad_len_plain = read_aead.open(&srv_hello_fixed[1168..1186], b"")?;
        let srv_pad_wire_len =
            u16::from_be_bytes([srv_pad_len_plain[0], srv_pad_len_plain[1]]) as usize;
        if srv_pad_wire_len < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS server padding length < 17",
            ));
        }

        if self.enable_0rtt && ticket_secs > 0 {
            *self.ticket_cache.lock() = Some(CachedClientTicket {
                expire_at: Instant::now() + Duration::from_secs(u64::from(ticket_secs)),
                pfs_key,
                ticket: ticket_arr,
            });
        }

        let (out_ctr, in_ctr) = if self.mode == XorMode::Random {
            (
                Some(VlessCtr::new(united_key.as_ref(), &iv)),
                Some(VlessCtr::new(united_key.as_ref(), &ticket_arr)),
            )
        } else {
            (None, None)
        };

        Ok(VlessEncryptedStream::new_1rtt_client(
            io_stream,
            united_key,
            write_aead,
            read_aead,
            out_ctr,
            in_ctr,
            srv_pad_wire_len,
        ))
    }

    fn build_0rtt_stream<S>(
        &self,
        io_stream: S,
        cached: CachedClientTicket,
    ) -> io::Result<VlessEncryptedStream<S>> {
        let (iv, iv_and_relays, nfs_key) = client_build_iv_and_relays(&self.keys, self.mode)?;
        let mut nfs_aead = VlessAead::new(&iv, nfs_key.as_ref(), self.use_aes)?;

        // `[0x00, 0x20]` (`32`) signals 0-RTT ticket resumption!
        let enc_len_32 = nfs_aead.seal(&32u16.to_be_bytes(), b"")?; // 18B (nonce 1)
        let enc_ticket = nfs_aead.seal(&cached.ticket, b"")?; // 32B (nonce 2)

        let mut pre_write = Vec::with_capacity(iv_and_relays.len() + 50);
        pre_write.extend_from_slice(&iv_and_relays);
        pre_write.extend_from_slice(&enc_len_32);
        pre_write.extend_from_slice(&enc_ticket);

        let mut united_key = Zeroizing::new([0u8; 96]);
        united_key[..64].copy_from_slice(cached.pfs_key.as_ref());
        united_key[64..96].copy_from_slice(nfs_key.as_ref());

        // 0-RTT Client -> Server Data AEAD uses `ctx = enc_ticket` (32B CIPHERTEXT!)
        let write_aead = VlessAead::new(&enc_ticket, united_key.as_ref(), self.use_aes)?;
        let out_ctr = if self.mode == XorMode::Random {
            Some(VlessCtr::new(united_key.as_ref(), &iv))
        } else {
            None
        };

        let cache_ref = Arc::clone(&self.ticket_cache);
        let invalidation_hook = Arc::new(Mutex::new(Some(Box::new(move || {
            *cache_ref.lock() = None;
        }) as Box<dyn FnOnce() + Send>)));

        Ok(VlessEncryptedStream::new_0rtt_client(
            io_stream,
            united_key,
            write_aead,
            out_ctr,
            pre_write,
            self.use_aes,
            self.mode == XorMode::Random,
            invalidation_hook,
        ))
    }
}

struct ServerTicketSession {
    expire_at: Instant,
    pfs_key: Zeroizing<[u8; 64]>,
    seen_nfs_keys: HashSet<[u8; 32]>,
}

/// Server-side Xray `mlkem768x25519plus` Post-Quantum Hybrid Decryption Engine (1-RTT + 0-RTT).
pub struct ServerEncryption {
    cfg: ParsedServerConfig,
    keys: Vec<ServerNfsKey>,
    relays_len: usize,
    sessions: Mutex<HashMap<[u8; 16], ServerTicketSession>>,
}

impl ServerEncryption {
    pub fn new(spec: &str) -> io::Result<Self> {
        let cfg = parse_server_decryption(spec)?;
        let mut keys = Vec::with_capacity(cfg.key_tokens.len());
        for tok in &cfg.key_tokens {
            keys.push(ServerNfsKey::from_b64_token(tok)?);
        }
        let relays_len = total_relays_len_server(&keys);
        Ok(Self {
            cfg,
            keys,
            relays_len,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub async fn accept<S>(&self, mut io_stream: S) -> io::Result<VlessEncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Read `iv (16B) + relays (relays_len) + enc_length (18B)`
        let prefix_len = 16 + self.relays_len + 18;
        let mut prefix = vec![0u8; prefix_len];
        io_stream.read_exact(&mut prefix).await?;

        let iv: [u8; 16] = prefix[..16].try_into().unwrap();
        let nfs_key = server_decode_relays(
            &self.keys,
            self.cfg.mode,
            &iv,
            &mut prefix[16..16 + self.relays_len],
        )?;

        // Auto-negotiate `use_aes`: try `true` first, fallback to `false` (ChaCha20-Poly1305)
        let enc_first_len = &prefix[16 + self.relays_len..];
        let (mut nfs_aead, first_len_plain, use_aes) = {
            let mut try_aes = VlessAead::new(&iv, nfs_key.as_ref(), true)?;
            if let Ok(plain) = try_aes.open(enc_first_len, b"") {
                (try_aes, plain, true)
            } else {
                let mut try_chacha = VlessAead::new(&iv, nfs_key.as_ref(), false)?;
                let plain = try_chacha.open(enc_first_len, b"")?;
                (try_chacha, plain, false)
            }
        };

        let length_val = u16::from_be_bytes([first_len_plain[0], first_len_plain[1]]) as usize;

        // Branch A: 0-RTT Resumption (`length_val == 32`)
        if length_val == 32 {
            if self.cfg.seconds_from == 0 && self.cfg.seconds_to == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VLESS 0-RTT is disabled on server",
                ));
            }
            let mut enc_ticket = [0u8; 32];
            io_stream.read_exact(&mut enc_ticket).await?;
            let ticket_plain = nfs_aead.open(&enc_ticket, b"")?;
            let ticket_id: [u8; 16] = ticket_plain.try_into().unwrap();

            let maybe_pfs = {
                let mut guard = self.sessions.lock();
                let now = Instant::now();
                guard.retain(|_, s| now < s.expire_at);
                if let Some(sess) = guard.get_mut(&ticket_id) {
                    if !sess.seen_nfs_keys.insert(*nfs_key) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "VLESS 0-RTT nfsKey replay detected",
                        ));
                    }
                    Some(sess.pfs_key.clone())
                } else {
                    None
                }
            };

            let Some(pfs_key) = maybe_pfs else {
                // Per Xray `server.go`: emit `RandBetween(1279, 2279)` random noise bytes with invalid header at `[16..21]` and close!
                let noise_len = xray_rand_between_usize(1279, 2279);
                let mut noise = random_vec(noise_len)?;
                if noise[16] == 0x17 && noise[17] == 0x03 && noise[18] == 0x03 {
                    noise[16] ^= 0xFF;
                }
                let _ = io_stream.write_all(&noise).await;
                let _ = io_stream.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "expired or unknown VLESS 0-RTT ticket",
                ));
            };

            let mut united_key = Zeroizing::new([0u8; 96]);
            united_key[..64].copy_from_slice(pfs_key.as_ref());
            united_key[64..96].copy_from_slice(nfs_key.as_ref());

            let server_random = random_array::<16>()?;
            let write_aead = VlessAead::new(&server_random, united_key.as_ref(), use_aes)?;
            let read_aead = VlessAead::new(&enc_ticket, united_key.as_ref(), use_aes)?;

            let (out_ctr, in_ctr) = if self.cfg.mode == XorMode::Random {
                (
                    Some(VlessCtr::new(united_key.as_ref(), &server_random)),
                    Some(VlessCtr::new(united_key.as_ref(), &iv)),
                )
            } else {
                (None, None)
            };

            return Ok(VlessEncryptedStream::new_server(
                io_stream,
                united_key,
                write_aead,
                read_aead,
                out_ctr,
                in_ctr,
                server_random.to_vec(),
                BytesMut::new(),
            ));
        }

        // Branch B: 1-RTT Full PFS Handshake (`length_val >= 1232`)
        if length_val < 1232 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid VLESS client PFS length {length_val}"),
            ));
        }
        let mut enc_client_pfs = vec![0u8; length_val];
        io_stream.read_exact(&mut enc_client_pfs).await?;
        let client_pfs_pub = nfs_aead.open(&enc_client_pfs, b"")?; // nonce 2
        if client_pfs_pub.len() < 1216 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated VLESS clientPfsPublicKey",
            ));
        }

        let client_ek = LcEncapKey::new(&ML_KEM_768, &client_pfs_pub[..1184]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client ephemeral ML-KEM-768 key",
            )
        })?;
        let (mlkem_ct, mlkem_ss) = client_ek
            .encapsulate()
            .map_err(|_| io::Error::other("ML-KEM-768 encapsulate failed"))?;

        let srv_x_seed = random_array::<32>()?;
        let srv_x_sk = X25519Secret::from(srv_x_seed);
        let srv_x_pk = X25519PublicKey::from(&srv_x_sk);
        let cli_x_pk_arr: [u8; 32] = client_pfs_pub[1184..1216].try_into().unwrap();
        let x_ss = srv_x_sk.diffie_hellman(&X25519PublicKey::from(cli_x_pk_arr));
        if x_ss.as_bytes().iter().all(|&b| b == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "low-order client ephemeral X25519 key",
            ));
        }

        let mut server_pfs_pub = Vec::with_capacity(1120);
        server_pfs_pub.extend_from_slice(mlkem_ct.as_ref());
        server_pfs_pub.extend_from_slice(srv_x_pk.as_bytes());

        let mut pfs_key = Zeroizing::new([0u8; 64]);
        pfs_key[..32].copy_from_slice(mlkem_ss.as_ref());
        pfs_key[32..64].copy_from_slice(x_ss.as_bytes());

        let mut united_key = Zeroizing::new([0u8; 96]);
        united_key[..64].copy_from_slice(pfs_key.as_ref());
        united_key[64..96].copy_from_slice(nfs_key.as_ref());

        let mut write_aead = VlessAead::new(&server_pfs_pub, united_key.as_ref(), use_aes)?;
        let read_aead = VlessAead::new(&client_pfs_pub, united_key.as_ref(), use_aes)?;

        // Generate 16B `ticket` = `[u16_be(seconds) || 14B random]`
        let ticket_secs = self.cfg.sample_ticket_seconds();
        let mut ticket = random_array::<16>()?;
        ticket[..2].copy_from_slice(&ticket_secs.to_be_bytes());

        if ticket_secs > 0 {
            let mut seen = HashSet::new();
            seen.insert(*nfs_key);
            let mut guard = self.sessions.lock();
            let now = Instant::now();
            guard.retain(|_, s| now < s.expire_at);
            guard.insert(
                ticket,
                ServerTicketSession {
                    expire_at: now + Duration::from_secs(u64::from(ticket_secs)),
                    pfs_key,
                    seen_nfs_keys: seen,
                },
            );
        }

        let (pad_lens, pad_gaps, srv_total_pad) = self.cfg.padding.sample();
        let srv_pad_plain_len = srv_total_pad - 34;

        // Seal `serverHello` BEFORE reading client's padding!
        let enc_srv_pfs = nfs_aead.seal_at(MAX_NONCE, &server_pfs_pub, b"")?; // 1136B (MaxNonce, does NOT advance nfs_aead!)
        let enc_ticket = write_aead.seal(&ticket, b"")?; // 32B (write_aead nonce 1)
        let enc_srv_pad_len = write_aead.seal(&((srv_total_pad - 18) as u16).to_be_bytes(), b"")?; // 18B (write_aead nonce 2)
        let enc_srv_pad = write_aead.seal(&vec![0u8; srv_pad_plain_len], b"")?; // (write_aead nonce 3)

        let mut server_hello = Vec::with_capacity(1168 + srv_total_pad);
        server_hello.extend_from_slice(&enc_srv_pfs);
        server_hello.extend_from_slice(&enc_ticket);
        server_hello.extend_from_slice(&enc_srv_pad_len);
        server_hello.extend_from_slice(&enc_srv_pad);

        write_fragmented_hello(&mut io_stream, &server_hello, 1168, &pad_lens, &pad_gaps).await?;

        // Now read & verify client's `encryptedPaddingLength` (nfs_aead nonce 3) and `encryptedPadding` (nfs_aead nonce 4)
        let mut cli_pad_len_wire = [0u8; 18];
        io_stream.read_exact(&mut cli_pad_len_wire).await?;
        let cli_pad_len_plain = nfs_aead.open(&cli_pad_len_wire, b"")?;
        let cli_pad_wire_len =
            u16::from_be_bytes([cli_pad_len_plain[0], cli_pad_len_plain[1]]) as usize;
        if cli_pad_wire_len < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS client padding length < 17",
            ));
        }
        let mut cli_pad_wire = vec![0u8; cli_pad_wire_len];
        io_stream.read_exact(&mut cli_pad_wire).await?;
        let _ = nfs_aead.open(&cli_pad_wire, b"")?;

        let (out_ctr, in_ctr) = if self.cfg.mode == XorMode::Random {
            (
                Some(VlessCtr::new(united_key.as_ref(), &ticket)),
                Some(VlessCtr::new(united_key.as_ref(), &iv)),
            )
        } else {
            (None, None)
        };

        Ok(VlessEncryptedStream::new_server(
            io_stream,
            united_key,
            write_aead,
            read_aead,
            out_ctr,
            in_ctr,
            Vec::new(),
            BytesMut::new(),
        ))
    }
}

async fn write_fragmented_hello<S: AsyncWrite + Unpin>(
    io_stream: &mut S,
    hello: &[u8],
    fixed_core_len: usize,
    pad_lens: &[usize],
    pad_gaps_ms: &[u64],
) -> io::Result<()> {
    let mut cursor = 0usize;
    for (idx, &plen) in pad_lens.iter().enumerate() {
        if idx > 0
            && let Some(&gap) = pad_gaps_ms.get(idx - 1)
            && gap > 0
        {
            tokio::time::sleep(Duration::from_millis(gap.min(50))).await;
        }
        let chunk_len = if idx == 0 {
            fixed_core_len + plen
        } else {
            plen
        };
        if chunk_len == 0 {
            continue;
        }
        let end = (cursor + chunk_len).min(hello.len());
        if end > cursor {
            io_stream.write_all(&hello[cursor..end]).await?;
            io_stream.flush().await?;
            cursor = end;
        }
    }
    if cursor < hello.len() {
        io_stream.write_all(&hello[cursor..]).await?;
        io_stream.flush().await?;
    }
    Ok(())
}

fn detect_aes_hardware() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}
