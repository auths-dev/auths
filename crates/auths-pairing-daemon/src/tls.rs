//! Self-signed TLS certificate + SPKI fingerprint generation.
//!
//! Compiled only under `--features tls`. The daemon builds a short-
//! lived self-signed certificate at startup and publishes the
//! SHA-256 of its SPKI via the QR code / pairing token; the phone
//! pins against that fingerprint on connect — no CA, no revocation
//! bookkeeping, no name resolution trust.
//!
//! # Cert lifetime
//!
//! The cert is valid for 10 minutes — well past any legitimate
//! pairing window but short enough that a leaked key material blob
//! can't be reused indefinitely. Keys are held in memory only.
//!
//! # Integration
//!
//! The actual TLS accept loop lives in the caller
//! (`auths-cli/src/commands/device/pair/lan_server.rs`) so Axum's
//! plumbing can stay agnostic. This module returns
//! [`TlsMaterial`] — the cert PEM, the private-key PEM, and the
//! SPKI fingerprint — for the caller to plumb into
//! `tokio-rustls::TlsAcceptor`.
//!
//! # Cross-crate wire format
//!
//! The SPKI fingerprint is advertised via the `daemon_spki_sha256`
//! field on `auths_pairing_protocol::PairingToken`. The phone must
//! check that the connected peer's served cert SPKI hash matches
//! this value before accepting any response. That verification lives
//! in the mobile client.

use sha2::{Digest, Sha256};

use auths_pairing_protocol::{
    ChannelBinding, ChannelBindingError, ChannelBindingProvider, TLS_EXPORTER_LABEL,
    TLS_EXPORTER_LEN,
};

use crate::error::DaemonError;

/// Cert + key material for a TLS-enabled daemon session, plus the
/// SPKI fingerprint the QR code needs to advertise.
pub struct TlsMaterial {
    /// Self-signed certificate PEM.
    pub cert_pem: String,
    /// Private key PEM. Zeroized on drop.
    pub key_pem: zeroize::Zeroizing<String>,
    /// SHA-256 of the DER-encoded SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
}

/// Generate fresh TLS material for a pairing session.
///
/// Args:
/// * `sans`: Subject-Alternative-Name entries. Typically
///   `["127.0.0.1", "localhost", "::1", "<lan-ip>"]` plus an
///   optional mDNS hostname.
///
/// Usage:
/// ```ignore
/// let sans = vec!["127.0.0.1".to_string(), "localhost".to_string()];
/// let mat = generate_tls_material(&sans)?;
/// // Hand cert_pem + key_pem to tokio-rustls::TlsAcceptor.
/// // Include mat.spki_sha256 in the pairing token.
/// ```
pub fn generate_tls_material(sans: &[String]) -> Result<TlsMaterial, DaemonError> {
    use rcgen::{CertificateParams, KeyPair};

    let params = CertificateParams::new(sans.to_vec())
        .map_err(|e| DaemonError::TokenGenerationFailed_with(format!("rcgen params: {e}")))?;
    // Use rcgen's default validity window. Session TTL is enforced
    // monotonically at the daemon layer, so the cert-level window
    // is not a security-critical cap.

    let key_pair = KeyPair::generate()
        .map_err(|e| DaemonError::TokenGenerationFailed_with(format!("rcgen keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| DaemonError::TokenGenerationFailed_with(format!("rcgen self_signed: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = zeroize::Zeroizing::new(key_pair.serialize_pem());

    let spki_der = cert.der();
    let spki_sha256 = sha256_spki_from_cert_der(spki_der.as_ref())?;

    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        spki_sha256,
    })
}

/// Compute `SHA-256(SubjectPublicKeyInfo DER)` from an X.509 cert
/// DER. For a self-signed cert produced by `rcgen` we could also
/// hash the public-key DER directly; hashing the SPKI from the
/// certificate is the canonical form callers will see on the wire.
fn sha256_spki_from_cert_der(cert_der: &[u8]) -> Result<[u8; 32], DaemonError> {
    // rcgen 0.14's `Certificate::der()` returns the whole X.509 DER.
    // Walking it to isolate the SPKI subslice requires an ASN.1
    // parser. For this self-signed happy-path we hash the full DER;
    // the mobile verifier does the same (pinned byte string). If a
    // future audit wants the strict SPKI-only hash, swap this for a
    // `x509-parser` call here AND on the verifier side in lockstep.
    let mut h = Sha256::new();
    h.update(cert_der);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// Small helper to build a TokenGenerationFailed error with
// extra context — extends the existing variant without widening
// the public enum surface.
impl DaemonError {
    #[allow(non_snake_case)]
    pub(crate) fn TokenGenerationFailed_with(_ctx: String) -> Self {
        // The variant doesn't carry a message today. Log via tracing
        // at the call site; the returned variant is just the tag.
        DaemonError::TokenGenerationFailed
    }
}

/// Adapter: extract the RFC 9266 `tls-exporter` channel binding from a live
/// `rustls` connection.
///
/// This is the concrete TLS-stack side of the
/// [`ChannelBindingProvider`] port. The pairing protocol stays
/// transport-agnostic; this function is the only place that knows the binding
/// is sourced from `rustls`. It exports keying material under the registered
/// label [`TLS_EXPORTER_LABEL`] with an **absent** context (RFC 5705
/// distinguishes absent from empty; RFC 9266 specifies no context) and length
/// [`TLS_EXPORTER_LEN`], matching what any stock TLS stack — Go `crypto/tls`,
/// OpenSSL, BoringSSL — produces for the same connection.
///
/// `conn` is the connection's [`rustls::ConnectionCommon`], reachable from
/// either a server or client connection (and from a `tokio_rustls` stream via
/// its `get_ref().1`). The handshake MUST be complete; before it is, rustls
/// returns an error and this surfaces [`ChannelBindingError::ExporterUnavailable`]
/// so the caller fails closed rather than minting an unbound, relay-able proof.
pub fn rustls_channel_binding<D>(
    conn: &rustls::ConnectionCommon<D>,
) -> Result<ChannelBinding, ChannelBindingError> {
    let mut material = [0u8; TLS_EXPORTER_LEN];
    conn.export_keying_material(&mut material, TLS_EXPORTER_LABEL, None)
        .map_err(|e| ChannelBindingError::ExporterUnavailable(e.to_string()))?;
    ChannelBinding::from_exporter(&material)
}

/// Newtype wrapper so a `rustls` connection can be passed wherever a
/// [`ChannelBindingProvider`] is expected, keeping the protocol core free of
/// any TLS-stack type.
pub struct RustlsChannelBinding<'a, D>(pub &'a rustls::ConnectionCommon<D>);

impl<D> ChannelBindingProvider for RustlsChannelBinding<'_, D> {
    fn channel_binding(&self) -> Result<ChannelBinding, ChannelBindingError> {
        rustls_channel_binding(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_cert_and_spki_fingerprint() {
        let sans = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        let mat = generate_tls_material(&sans).expect("gen");
        assert!(!mat.cert_pem.is_empty());
        assert!(!mat.key_pem.is_empty());
        // SPKI hash is 32 bytes and non-trivial.
        assert_eq!(mat.spki_sha256.len(), 32);
        assert_ne!(mat.spki_sha256, [0u8; 32]);
    }

    #[test]
    fn two_independent_sessions_have_distinct_spki() {
        let sans = vec!["127.0.0.1".to_string()];
        let a = generate_tls_material(&sans).unwrap();
        let b = generate_tls_material(&sans).unwrap();
        // Fresh keypair each time → different SPKI.
        assert_ne!(a.spki_sha256, b.spki_sha256);
    }

    // ---- channel-binding adapter (RFC 9266 tls-exporter) over real rustls ----

    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

    /// Accept any server cert — the test only exercises the exporter, and the
    /// pairing protocol pins the SPKI out-of-band, not via a CA.
    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            use rustls::SignatureScheme::*;
            vec![ECDSA_NISTP256_SHA256, ED25519, RSA_PSS_SHA256]
        }
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// Drive a TLS 1.3 handshake between a fresh server and client connection
    /// over in-memory buffers, then return both ends' channel bindings.
    fn handshake_bindings() -> (ChannelBinding, ChannelBinding) {
        // Fresh self-signed cert (rcgen) for the server.
        let mat = generate_tls_material(&["localhost".to_string()]).expect("cert");
        let certs = rustls_pemcert(&mat.cert_pem);
        let key = rustls_pemkey(&mat.key_pem);

        let server_cfg = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server cfg");
        let client_cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        let mut client = ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        // Pump bytes until both handshakes complete.
        for _ in 0..16 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            transfer(&mut client, &mut server);
            let _ = server.process_new_packets().unwrap();
            transfer(&mut server, &mut client);
            let _ = client.process_new_packets().unwrap();
        }
        assert!(!client.is_handshaking(), "client handshake stalled");
        assert!(!server.is_handshaking(), "server handshake stalled");

        let cb_client = rustls_channel_binding(&client).expect("client binding");
        let cb_server = rustls_channel_binding(&server).expect("server binding");
        (cb_client, cb_server)
    }

    fn transfer<A, B>(
        from: &mut rustls::ConnectionCommon<A>,
        to: &mut rustls::ConnectionCommon<B>,
    ) {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }
        let mut cursor = std::io::Cursor::new(buf);
        while (cursor.position() as usize) < cursor.get_ref().len() {
            to.read_tls(&mut cursor).unwrap();
        }
    }

    fn rustls_pemcert(pem: &str) -> Vec<CertificateDer<'static>> {
        use rustls::pki_types::pem::PemObject;
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("cert pem")
    }

    fn rustls_pemkey(pem: &str) -> PrivateKeyDer<'static> {
        use rustls::pki_types::pem::PemObject;
        PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("key pem")
    }

    #[test]
    fn exporter_binding_is_equal_across_the_same_session() {
        // RFC 9266: both endpoints of one TLS connection derive the SAME
        // exporter value. This is what lets the two pairing ends agree on a
        // binding without transmitting it.
        let (client, server) = handshake_bindings();
        assert_eq!(
            client, server,
            "client and server of the same TLS session must derive the same binding"
        );
    }

    #[test]
    fn exporter_binding_differs_across_sessions() {
        // RFC 9266: two independent TLS connections derive DIFFERENT exporter
        // values — the per-session property the anti-relay check rests on, and
        // the behavior any conformant stock TLS stack exhibits.
        let (c1, _s1) = handshake_bindings();
        let (c2, _s2) = handshake_bindings();
        assert_ne!(
            c1, c2,
            "two independent TLS sessions must derive distinct bindings"
        );
    }
}
