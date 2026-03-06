//! SPIFFE X.509-SVID verification for the OIDC bridge.
//!
//! Verifies X.509 SVIDs against a trust bundle and extracts the SPIFFE ID
//! from the URI SAN. Follows the SPIFFE X509-SVID specification.

use x509_parser::pem::Pem;
use x509_parser::prelude::*;

use crate::error::BridgeError;

/// Result of verifying a SPIFFE X.509-SVID.
#[derive(Debug, Clone)]
pub struct SpiffeVerificationResult {
    /// The SPIFFE ID extracted from the URI SAN (e.g. `spiffe://example.org/workload`).
    pub spiffe_id: String,
    /// The trust domain (e.g. `example.org`).
    pub trust_domain: String,
}

/// Parsed trust bundle containing CA certificates.
pub struct TrustBundle {
    /// DER-encoded CA certificates.
    ca_certs: Vec<Vec<u8>>,
}

impl TrustBundle {
    /// Parse a PEM-encoded trust bundle file.
    ///
    /// Args:
    /// * `pem_data`: PEM-encoded certificate bundle bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let bundle = TrustBundle::from_pem(&std::fs::read("bundle.pem")?)?;
    /// ```
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, BridgeError> {
        let mut ca_certs = Vec::new();
        for pem in Pem::iter_from_buffer(pem_data) {
            let pem = pem.map_err(|e| {
                BridgeError::SpiffeError(format!("failed to parse PEM in trust bundle: {e}"))
            })?;
            if pem.label == "CERTIFICATE" {
                ca_certs.push(pem.contents);
            }
        }

        if ca_certs.is_empty() {
            return Err(BridgeError::SpiffeError(
                "trust bundle contains no certificates".into(),
            ));
        }

        Ok(Self { ca_certs })
    }

    /// Check whether the SVID was signed by a CA in this bundle.
    fn contains_issuer(&self, svid_issuer: &[u8]) -> bool {
        for ca_der in &self.ca_certs {
            if let Ok((_, ca_cert)) = X509Certificate::from_der(ca_der)
                && ca_cert.subject().as_raw() == svid_issuer
            {
                return true;
            }
        }
        false
    }
}

/// Verify a SPIFFE X.509-SVID and extract the SPIFFE ID.
///
/// Args:
/// * `svid_pem`: PEM-encoded X.509-SVID certificate.
/// * `trust_bundle`: The trust bundle to verify against.
/// * `allowed_trust_domains`: Optional allowlist of trust domains.
/// * `now_epoch`: Current Unix timestamp for expiry checking.
///
/// Usage:
/// ```ignore
/// let result = verify_svid(&svid_bytes, &bundle, Some(&["example.org"]), now)?;
/// ```
pub fn verify_svid(
    svid_pem: &[u8],
    trust_bundle: &TrustBundle,
    allowed_trust_domains: Option<&[String]>,
    now_epoch: i64,
) -> Result<SpiffeVerificationResult, BridgeError> {
    let pem = Pem::iter_from_buffer(svid_pem)
        .next()
        .ok_or_else(|| BridgeError::SpiffeError("no PEM certificate found in SVID".into()))?
        .map_err(|e| BridgeError::SpiffeError(format!("failed to parse SVID PEM: {e}")))?;

    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| BridgeError::SpiffeError(format!("failed to parse X.509 certificate: {e}")))?;

    // Check expiry
    let not_after = cert.validity().not_after.timestamp();
    let not_before = cert.validity().not_before.timestamp();

    if now_epoch < not_before {
        return Err(BridgeError::SpiffeError(format!(
            "SVID not yet valid (notBefore: {not_before})"
        )));
    }
    if now_epoch > not_after {
        return Err(BridgeError::SpiffeError(format!(
            "SVID has expired (notAfter: {not_after})"
        )));
    }

    // Verify issuer is in trust bundle
    if !trust_bundle.contains_issuer(cert.issuer().as_raw()) {
        return Err(BridgeError::SpiffeError(
            "SVID issuer not found in trust bundle".into(),
        ));
    }

    // Extract SPIFFE ID from URI SAN (exactly one required per SPIFFE spec)
    let spiffe_id = extract_spiffe_id(&cert)?;

    // Parse trust domain from SPIFFE ID
    let trust_domain = extract_trust_domain(&spiffe_id)?;

    // Check trust domain allowlist
    if let Some(allowed) = allowed_trust_domains
        && !allowed.iter().any(|d| d == &trust_domain)
    {
        return Err(BridgeError::SpiffeTrustDomainNotAllowed {
            domain: trust_domain,
            allowed: allowed.to_vec(),
        });
    }

    Ok(SpiffeVerificationResult {
        spiffe_id,
        trust_domain,
    })
}

fn extract_spiffe_id(cert: &X509Certificate<'_>) -> Result<String, BridgeError> {
    let san_ext = cert
        .subject_alternative_name()
        .map_err(|e| BridgeError::SpiffeError(format!("failed to parse SAN extension: {e}")))?
        .ok_or_else(|| {
            BridgeError::SpiffeError("SVID has no Subject Alternative Name extension".into())
        })?;

    let uri_sans: Vec<&str> = san_ext
        .value
        .general_names
        .iter()
        .filter_map(|name| {
            if let GeneralName::URI(uri) = name {
                Some(*uri)
            } else {
                None
            }
        })
        .collect();

    // SPIFFE spec: exactly one URI SAN
    match uri_sans.len() {
        0 => Err(BridgeError::SpiffeError(
            "SVID has no URI SAN (SPIFFE ID)".into(),
        )),
        1 => {
            let uri = uri_sans[0];
            if !uri.starts_with("spiffe://") {
                return Err(BridgeError::SpiffeError(format!(
                    "URI SAN is not a SPIFFE ID: {uri}"
                )));
            }
            Ok(uri.to_string())
        }
        n => Err(BridgeError::SpiffeError(format!(
            "SVID has {n} URI SANs, SPIFFE spec requires exactly 1"
        ))),
    }
}

fn extract_trust_domain(spiffe_id: &str) -> Result<String, BridgeError> {
    // spiffe://trust-domain/workload-path
    let without_scheme = spiffe_id.strip_prefix("spiffe://").ok_or_else(|| {
        BridgeError::SpiffeError(format!("invalid SPIFFE ID format: {spiffe_id}"))
    })?;

    let domain = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| {
            BridgeError::SpiffeError(format!("cannot extract trust domain from: {spiffe_id}"))
        })?
        .to_string();

    if domain.is_empty() {
        return Err(BridgeError::SpiffeError(
            "empty trust domain in SPIFFE ID".into(),
        ));
    }

    Ok(domain)
}
