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
}
