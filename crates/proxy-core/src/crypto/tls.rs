use std::{
    collections::HashMap,
    io,
    sync::{Arc, LazyLock},
};

use parking_lot::Mutex;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, aws_lc_rs::default_provider},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

const MAX_CACHED_ALPN_CONFIGS: usize = 64;

static DEFAULT_CRYPTO_PROVIDER: LazyLock<Arc<CryptoProvider>> =
    LazyLock::new(|| Arc::new(default_provider()));

static WEBPKI_ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(roots)
});

static DEFAULT_VERIFIED_CLIENT_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&DEFAULT_CRYPTO_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("rustls safe default protocol versions")
        .with_root_certificates(Arc::clone(&WEBPKI_ROOT_STORE))
        .with_no_client_auth();
    cfg.resumption = Resumption::in_memory_sessions(256);
    Arc::new(cfg)
});

static DEFAULT_INSECURE_CLIENT_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let provider = Arc::clone(&DEFAULT_CRYPTO_PROVIDER);
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("rustls safe default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureSkipVerifier(provider)))
        .with_no_client_auth();
    cfg.resumption = Resumption::in_memory_sessions(256);
    Arc::new(cfg)
});

type AlpnClientConfigCacheKey = (bool, Vec<Vec<u8>>);
type AlpnClientConfigCache = HashMap<AlpnClientConfigCacheKey, Arc<ClientConfig>>;

static ALPN_CLIENT_CONFIG_CACHE: LazyLock<Mutex<AlpnClientConfigCache>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
struct InsecureSkipVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for InsecureSkipVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_verified_client_config_with_extra_ca(
    extra_ca_der: &[CertificateDer<'static>],
) -> io::Result<ClientConfig> {
    let mut roots = (**WEBPKI_ROOT_STORE).clone();
    for cert in extra_ca_der {
        roots
            .add(cert.clone())
            .map_err(|e| io::Error::other(format!("failed adding extra root cert: {e}")))?;
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::clone(&DEFAULT_CRYPTO_PROVIDER))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(format!("rustls version config failed: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn build_alpn_cached_client_config(
    skip_cert_verify: bool,
    alpn_protocols: &[Vec<u8>],
) -> Arc<ClientConfig> {
    let key = (skip_cert_verify, alpn_protocols.to_vec());
    let mut cache = ALPN_CLIENT_CONFIG_CACHE.lock();
    if let Some(existing) = cache.get(&key) {
        return Arc::clone(existing);
    }
    let mut cfg = if skip_cert_verify {
        (**DEFAULT_INSECURE_CLIENT_CONFIG).clone()
    } else {
        (**DEFAULT_VERIFIED_CLIENT_CONFIG).clone()
    };
    // Isolate the TLS session store per `(skip_cert_verify, alpn_protocols)` so different
    // ALPN protocols (e.g. `h2`, `http/1.1`, empty ALPN) never cross-consume each other's
    // TLS 1.3 tickets.
    cfg.resumption = Resumption::in_memory_sessions(64);
    cfg.alpn_protocols = alpn_protocols.to_vec();
    let arc = Arc::new(cfg);
    if cache.len() < MAX_CACHED_ALPN_CONFIGS {
        cache.insert(key, Arc::clone(&arc));
    }
    arc
}

pub fn build_tls_client_config(
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    alpn_protocols: &[Vec<u8>],
) -> io::Result<Arc<ClientConfig>> {
    if skip_cert_verify {
        if alpn_protocols.is_empty() {
            return Ok(Arc::clone(&DEFAULT_INSECURE_CLIENT_CONFIG));
        }
        return Ok(build_alpn_cached_client_config(true, alpn_protocols));
    }

    if extra_ca_der.is_empty() {
        if alpn_protocols.is_empty() {
            return Ok(Arc::clone(&DEFAULT_VERIFIED_CLIENT_CONFIG));
        }
        return Ok(build_alpn_cached_client_config(false, alpn_protocols));
    }

    let mut cfg = build_verified_client_config_with_extra_ca(extra_ca_der)?;
    cfg.resumption = Resumption::in_memory_sessions(64);
    cfg.alpn_protocols = alpn_protocols.to_vec();
    Ok(Arc::new(cfg))
}

/// Build a dedicated TLS `ClientConfig` for a QUIC outbound (`Hysteria2` / `TUIC`).
///
/// Always allocates a fresh, isolated `Resumption::in_memory_sessions(64)` cache so QUIC
/// (including QUIC 0-RTT) session tickets never collide with TCP TLS or other QUIC outbounds,
/// while reusing the returned config across reconnects within the same outbound preserves
/// 0-RTT resumption.
pub fn build_quic_tls_client_config(
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    alpn_protocols: &[Vec<u8>],
    enable_early_data: bool,
    disable_sni: bool,
) -> io::Result<Arc<ClientConfig>> {
    let mut cfg = if skip_cert_verify {
        (**DEFAULT_INSECURE_CLIENT_CONFIG).clone()
    } else if extra_ca_der.is_empty() {
        (**DEFAULT_VERIFIED_CLIENT_CONFIG).clone()
    } else {
        build_verified_client_config_with_extra_ca(extra_ca_der)?
    };
    cfg.resumption = Resumption::in_memory_sessions(64);
    cfg.alpn_protocols = alpn_protocols.to_vec();
    cfg.enable_early_data = enable_early_data;
    cfg.enable_sni = !disable_sni;
    Ok(Arc::new(cfg))
}

/// Generate an ephemeral self-signed X.509 certificate and matching `ServerConfig`
/// for AnyTLS / VLESS-TLS server listeners and loopback integration tests.
pub fn generate_self_signed_server_config(
    subject_alt_names: &[String],
    alpn_protocols: &[Vec<u8>],
) -> io::Result<(Arc<ServerConfig>, CertificateDer<'static>)> {
    let names = if subject_alt_names.is_empty() {
        vec!["localhost".to_string(), "127.0.0.1".to_string()]
    } else {
        subject_alt_names.to_vec()
    };
    let certified = rcgen::generate_simple_self_signed(names)
        .map_err(|e| io::Error::other(format!("rcgen self-signed cert failed: {e}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

    let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&DEFAULT_CRYPTO_PROVIDER))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls server version config failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(|e| io::Error::other(format!("rustls server cert config failed: {e}")))?;
    server_cfg.alpn_protocols = alpn_protocols.to_vec();

    Ok((Arc::new(server_cfg), cert_der))
}

pub fn parse_server_name(sni: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(sni.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid SNI: {sni}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, HandshakeKind, ServerConnection};

    fn run_in_memory_tls_handshake(
        client_cfg: &Arc<ClientConfig>,
        server_cfg: &Arc<ServerConfig>,
        sni: &str,
    ) -> HandshakeKind {
        let mut client =
            ClientConnection::new(Arc::clone(client_cfg), parse_server_name(sni).unwrap()).unwrap();
        let mut server = ServerConnection::new(Arc::clone(server_cfg)).unwrap();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        // Pump handshake AND post-handshake NewSessionTicket messages from server to client.
        for _ in 0..16 {
            c2s.clear();
            while client.wants_write() {
                client.write_tls(&mut c2s).unwrap();
            }
            if !c2s.is_empty() {
                let mut slice = c2s.as_slice();
                while !slice.is_empty() {
                    server.read_tls(&mut slice).unwrap();
                    server.process_new_packets().unwrap();
                }
            }

            s2c.clear();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            if !s2c.is_empty() {
                let mut slice = s2c.as_slice();
                while !slice.is_empty() {
                    client.read_tls(&mut slice).unwrap();
                    client.process_new_packets().unwrap();
                }
            }

            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        client
            .handshake_kind()
            .expect("completed TLS handshake must report HandshakeKind")
    }

    #[test]
    fn default_tls_client_configs_share_cached_arcs() {
        let a = build_tls_client_config(false, &[], &[]).unwrap();
        let b = build_tls_client_config(false, &[], &[]).unwrap();
        assert!(Arc::ptr_eq(&a, &b));

        let ia = build_tls_client_config(true, &[], &[]).unwrap();
        let ib = build_tls_client_config(true, &[], &[]).unwrap();
        assert!(Arc::ptr_eq(&ia, &ib));
    }

    #[test]
    fn tls_session_cache_is_isolated_across_alpns_and_quic_configs() {
        let sni = "session-isolation.test";
        let (server_cfg, ca_der) = generate_self_signed_server_config(
            &[sni.to_string()],
            &[b"h2".to_vec(), b"http/1.1".to_vec(), b"h3".to_vec()],
        )
        .unwrap();

        // 1. Same non-empty ALPN shares cached Arc (verified & insecure), while distinct ALPNs
        //    and empty ALPN do not share Arcs.
        let v_empty = build_tls_client_config(false, &[], &[]).unwrap();
        let v_h2_a = build_tls_client_config(false, &[], &[b"h2".to_vec()]).unwrap();
        let v_h2_b = build_tls_client_config(false, &[], &[b"h2".to_vec()]).unwrap();
        let v_h3 = build_tls_client_config(false, &[], &[b"h3".to_vec()]).unwrap();
        assert!(Arc::ptr_eq(&v_h2_a, &v_h2_b));
        assert!(!Arc::ptr_eq(&v_empty, &v_h2_a));
        assert!(!Arc::ptr_eq(&v_h2_a, &v_h3));

        // 2. Real TLS 1.3 ticket round-trip proof using insecure configs (which exercise the
        //    cached `DEFAULT_INSECURE_CLIENT_CONFIG` + `ALPN_CLIENT_CONFIG_CACHE` paths):
        let tcp_h2 = build_tls_client_config(true, &[], &[b"h2".to_vec()]).unwrap();
        let tcp_empty = build_tls_client_config(true, &[], &[]).unwrap();
        let tcp_http11 = build_tls_client_config(true, &[], &[b"http/1.1".to_vec()]).unwrap();
        let quic_h2_a =
            build_quic_tls_client_config(true, &[], &[b"h2".to_vec()], true, false).unwrap();
        let quic_h2_b =
            build_quic_tls_client_config(true, &[], &[b"h2".to_vec()], true, true).unwrap();
        assert!(!Arc::ptr_eq(&quic_h2_a, &quic_h2_b));
        assert!(quic_h2_a.enable_early_data && quic_h2_a.enable_sni);
        assert!(quic_h2_b.enable_early_data && !quic_h2_b.enable_sni);

        // Warm a TLS 1.3 ticket into `tcp_h2` and verify `tcp_h2` itself resumes.
        assert_eq!(
            run_in_memory_tls_handshake(&tcp_h2, &server_cfg, sni),
            HandshakeKind::Full
        );
        assert_eq!(
            run_in_memory_tls_handshake(&tcp_h2, &server_cfg, sni),
            HandshakeKind::Resumed
        );

        // Neither empty-ALPN TCP, different-ALPN TCP (`http/1.1`), nor QUIC (`h2`) may consume
        // `tcp_h2`'s cached ticket!
        assert_eq!(
            run_in_memory_tls_handshake(&tcp_empty, &server_cfg, sni),
            HandshakeKind::Full,
            "empty-ALPN TLS config must not share session cache with h2 config"
        );
        assert_eq!(
            run_in_memory_tls_handshake(&tcp_http11, &server_cfg, sni),
            HandshakeKind::Full,
            "http/1.1 TLS config must not share session cache with h2 config"
        );
        assert_eq!(
            run_in_memory_tls_handshake(&quic_h2_a, &server_cfg, sni),
            HandshakeKind::Full,
            "QUIC TLS config must not share session cache with TCP TLS config of same ALPN"
        );

        // `quic_h2_a` MUST resume across reconnects using its own isolated cache, while a
        // separate QUIC outbound config (`quic_h2_b`) must NOT share `quic_h2_a`'s cache.
        assert_eq!(
            run_in_memory_tls_handshake(&quic_h2_a, &server_cfg, sni),
            HandshakeKind::Resumed,
            "same QUIC ClientConfig must preserve resumption across reconnects"
        );
        assert_eq!(
            run_in_memory_tls_handshake(&quic_h2_b, &server_cfg, sni),
            HandshakeKind::Full,
            "distinct QUIC ClientConfigs must not share session caches with each other"
        );

        // 3. Verified path with custom CA: distinct `extra_ca_der` configs and QUIC configs
        //    also remain strictly isolated from each other.
        let verified_tcp =
            build_tls_client_config(false, std::slice::from_ref(&ca_der), &[b"h3".to_vec()])
                .unwrap();
        let verified_quic = build_quic_tls_client_config(
            false,
            std::slice::from_ref(&ca_der),
            &[b"h3".to_vec()],
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            run_in_memory_tls_handshake(&verified_tcp, &server_cfg, sni),
            HandshakeKind::Full
        );
        assert_eq!(
            run_in_memory_tls_handshake(&verified_tcp, &server_cfg, sni),
            HandshakeKind::Resumed
        );
        assert_eq!(
            run_in_memory_tls_handshake(&verified_quic, &server_cfg, sni),
            HandshakeKind::Full,
            "verified QUIC config must not share session cache with verified TCP config"
        );
    }
}
