use std::{
    io,
    sync::{Arc, LazyLock},
};

use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, aws_lc_rs::default_provider},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

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

pub fn build_tls_client_config(
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    alpn_protocols: &[Vec<u8>],
) -> io::Result<Arc<ClientConfig>> {
    if skip_cert_verify {
        if alpn_protocols.is_empty() {
            return Ok(Arc::clone(&DEFAULT_INSECURE_CLIENT_CONFIG));
        }
        let mut cfg = (**DEFAULT_INSECURE_CLIENT_CONFIG).clone();
        cfg.alpn_protocols = alpn_protocols.to_vec();
        return Ok(Arc::new(cfg));
    }

    if extra_ca_der.is_empty() {
        if alpn_protocols.is_empty() {
            return Ok(Arc::clone(&DEFAULT_VERIFIED_CLIENT_CONFIG));
        }
        let mut cfg = (**DEFAULT_VERIFIED_CLIENT_CONFIG).clone();
        cfg.alpn_protocols = alpn_protocols.to_vec();
        return Ok(Arc::new(cfg));
    }

    let mut roots = (**WEBPKI_ROOT_STORE).clone();
    for cert in extra_ca_der {
        roots
            .add(cert.clone())
            .map_err(|e| io::Error::other(format!("failed adding extra root cert: {e}")))?;
    }
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&DEFAULT_CRYPTO_PROVIDER))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls version config failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = Resumption::in_memory_sessions(64);
    cfg.alpn_protocols = alpn_protocols.to_vec();
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

    #[test]
    fn default_tls_client_configs_share_cached_arcs() {
        let a = build_tls_client_config(false, &[], &[]).unwrap();
        let b = build_tls_client_config(false, &[], &[]).unwrap();
        assert!(Arc::ptr_eq(&a, &b));

        let ia = build_tls_client_config(true, &[], &[]).unwrap();
        let ib = build_tls_client_config(true, &[], &[]).unwrap();
        assert!(Arc::ptr_eq(&ia, &ib));
    }
}
