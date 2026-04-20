use crate::attestation::create::{CanonicalRevocationData, canonicalize_revocation_data};
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::core::{Attestation, Ed25519Signature, ResourceId};
use auths_verifier::error::AttestationError;
use auths_verifier::types::{CanonicalDid, DeviceDID};

use chrono::{DateTime, Utc};
use log::{debug, warn};
use serde_json::Value;

/// Revocation version - stays at v1 since revocations don't need org fields
pub const REVOCATION_VERSION: u32 = 1;

/// Creates a signed revocation attestation using the provided SecureSigner.
///
/// This function constructs the canonical revocation data, signs it using the
/// identity key via the signer, and returns the complete revocation attestation.
///
/// # Arguments
/// * `rid` - Resource identifier for the attestation being revoked
/// * `identity_did` - The identity DID (e.g., "did:keri:...") issuing the revocation
/// * `device_did` - The device DID being revoked
/// * `device_public_key` - Raw device public key bytes (32 Ed25519, 33 P-256 compressed)
/// * `device_curve` - Signing curve of `device_public_key`. Carried in-band so the
///   revocation interior never infers curve from byte length.
/// * `note` - Optional note explaining the revocation reason
/// * `payload_arg` - Optional JSON payload (usually None for revocations)
/// * `timestamp_arg` - Timestamp of the revocation
/// * `signer` - SecureSigner implementation for signing operations
/// * `passphrase_provider` - Provider for obtaining passphrases during signing
/// * `identity_alias` - Alias of the identity key in the keychain
#[allow(clippy::too_many_arguments)]
pub fn create_signed_revocation(
    rid: &str,
    identity_did: &IdentityDID,
    device_did: &DeviceDID,
    device_public_key: &[u8],
    device_curve: auths_crypto::CurveType,
    note: Option<String>,
    payload_arg: Option<Value>,
    timestamp_arg: DateTime<Utc>,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    identity_alias: &KeyAlias,
) -> Result<Attestation, AttestationError> {
    warn!("Creating revocation for device {}", device_did);

    // 1. Construct the revocation-specific canonical data
    let revoked_at_value = Some(timestamp_arg);
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: identity_did is an IdentityDID which guarantees valid DID format
    let issuer_canonical = CanonicalDid::new_unchecked(identity_did.as_str());
    let data_to_canonicalize_revocation = CanonicalRevocationData {
        version: REVOCATION_VERSION,
        rid,
        issuer: &issuer_canonical,
        subject: device_did,
        timestamp: &Some(timestamp_arg),
        revoked_at: &revoked_at_value,
        note: &note,
    };

    // 2. Canonicalize the revocation data
    let canonical_bytes = canonicalize_revocation_data(&data_to_canonicalize_revocation)?;
    debug!(
        "Canonical revocation data: {}",
        String::from_utf8_lossy(&canonical_bytes)
    );

    // 3. Sign with the identity key
    debug!(
        "Signing revocation with identity alias '{}'",
        identity_alias
    );
    let identity_sig_bytes = signer
        .sign_with_alias(identity_alias, passphrase_provider, &canonical_bytes)
        .map_err(|e| {
            AttestationError::SigningError(format!(
                "Failed to sign revocation with identity key '{}': {}",
                identity_alias, e
            ))
        })?;
    let identity_signature = Ed25519Signature::try_from_slice(&identity_sig_bytes)
        .map_err(|e| AttestationError::SigningError(e.to_string()))?;
    debug!("Revocation signature obtained successfully");

    // 4. Return the final revocation attestation object
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: identity_did is an IdentityDID which guarantees valid DID format
    let revocation_issuer = CanonicalDid::new_unchecked(identity_did.as_str());
    Ok(Attestation {
        version: REVOCATION_VERSION,
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: device_did is a validated DeviceDID from the caller
        subject: CanonicalDid::new_unchecked(device_did.as_str()),
        issuer: revocation_issuer,
        rid: ResourceId::new(rid),
        payload: payload_arg.clone(),
        timestamp: Some(timestamp_arg),
        expires_at: None,
        revoked_at: Some(timestamp_arg),
        note: note.clone(),
        device_public_key: auths_verifier::DevicePublicKey::try_new(device_curve, device_public_key)
            .map_err(|e| AttestationError::InvalidInput(e.to_string()))?,
        identity_signature,
        device_signature: Ed25519Signature::empty(),
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
        commit_sha: None,
        commit_message: None,
        author: None,
        oidc_binding: None,
    })
}

// =============================================================================
// Pre-signed revocations
//
// At pair time the controller identity pre-signs a revocation bound to a
// specific `(device_did, anchor_sn, not_before, not_after)` tuple and stores
// it locally. On device compromise — even without the controlling device
// being online — the stored cert can be submitted to the transparency log
// and (once witnessed) propagated to verifiers. The trade-off is well-
// known: theft of the cert is a DoS (the device is still revokable by
// normal rotation), not a key-material compromise.
// =============================================================================

use crate::domain_separation::REVOCATION_PRESIGNED_CONTEXT;
use serde::{Deserialize, Serialize};

/// A revocation attestation signed at pair time and held for future
/// use. The signature covers a canonical byte string that includes
/// [`REVOCATION_PRESIGNED_CONTEXT`], which domain-separates this
/// blob from live-signed revocations so a live-ctx signature cannot
/// be replayed as a pre-signed cert (or vice versa).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedRevocation {
    /// The device this revocation targets (`did:key:z…`).
    pub device_did: String,
    /// KEL sequence number at which the cert is anchored. Prevents
    /// replaying an old cert against a post-rotation device state.
    pub anchor_sn: u128,
    /// Earliest time this cert is valid to publish.
    pub not_before: DateTime<Utc>,
    /// Latest time this cert is valid to publish. Set to the time of
    /// the next planned rotation in production — bounded-validity
    /// cert is strictly stronger than the PGP-lifetime model.
    pub not_after: DateTime<Utc>,
    /// The controller identity DID (`did:keri:…`) that signed this
    /// cert.
    pub issuer: String,
    /// Ed25519 signature (64 bytes) over the canonical byte string.
    pub signature: Vec<u8>,
}

/// Errors specific to pre-signed revocation certs.
#[derive(Debug, thiserror::Error)]
pub enum PresignedRevocationError {
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("window validation failed: not_before {nb} >= not_after {na}")]
    InvalidWindow { nb: String, na: String },
    #[error("attestation error: {0}")]
    Attestation(#[from] AttestationError),
}

/// Canonical signing bytes for a pre-signed revocation.
///
/// `<context>\n<issuer>\n<device_did>\n<anchor_sn>\n<not_before>\n<not_after>`
///
/// `<context>` is [`REVOCATION_PRESIGNED_CONTEXT`]. Encoding
/// choices: `anchor_sn` as decimal, timestamps as RFC 3339. The
/// exact bytes are what gets signed — drift from this format breaks
/// every existing cert.
pub fn canonicalize_presigned_revocation(
    issuer: &str,
    device_did: &str,
    anchor_sn: u128,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(REVOCATION_PRESIGNED_CONTEXT);
    out.push(b'\n');
    out.extend_from_slice(issuer.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(device_did.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(anchor_sn.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(not_before.to_rfc3339().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(not_after.to_rfc3339().as_bytes());
    out
}

/// Pre-sign a revocation cert for a device key at pair time.
///
/// Args:
/// * `identity_did`: The controller identity DID (`did:keri:…`).
/// * `device_did`: The device DID (`did:key:z…`) this cert revokes.
/// * `anchor_sn`: The device-keyring KEL sequence number at pair time.
/// * `not_before` / `not_after`: Validity window. `not_before` typically
///   = now at pair time; `not_after` should bound to the next planned
///   rotation. Ten years is a reasonable ceiling for long-lived
///   devices; shorter windows are strictly stronger.
/// * `signer` / `passphrase_provider` / `identity_alias`: Signing key
///   handle, mirroring the live-revocation API shape.
///
/// Usage:
/// ```ignore
/// let cert = create_presigned_revocation(
///     &identity_did, &device_did, anchor_sn, now, now + Duration::days(365),
///     &*signer, &*passphrase_provider, &identity_alias,
/// )?;
/// storage.save_presigned_revocation(&device_did, &cert)?;
/// // On compromise: submit `cert` to the transparency log + propagate.
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_presigned_revocation(
    identity_did: &IdentityDID,
    device_did: &DeviceDID,
    anchor_sn: u128,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    identity_alias: &KeyAlias,
) -> Result<PresignedRevocation, PresignedRevocationError> {
    if not_before >= not_after {
        return Err(PresignedRevocationError::InvalidWindow {
            nb: not_before.to_rfc3339(),
            na: not_after.to_rfc3339(),
        });
    }

    let canonical = canonicalize_presigned_revocation(
        identity_did.as_str(),
        device_did.as_str(),
        anchor_sn,
        not_before,
        not_after,
    );
    let sig_bytes = signer
        .sign_with_alias(identity_alias, passphrase_provider, &canonical)
        .map_err(|e| PresignedRevocationError::Signing(e.to_string()))?;

    Ok(PresignedRevocation {
        device_did: device_did.as_str().to_string(),
        anchor_sn,
        not_before,
        not_after,
        issuer: identity_did.as_str().to_string(),
        signature: sig_bytes,
    })
}

#[cfg(test)]
mod presigned_tests {
    use super::*;

    #[test]
    fn canonical_bytes_include_context_label() {
        let bytes = canonicalize_presigned_revocation(
            "did:keri:ETest",
            "did:key:z6MkTest",
            42,
            Utc::now(),
            Utc::now() + chrono::Duration::days(1),
        );
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.starts_with("auths-revocation-presigned-v1\n"));
        assert!(s.contains("\ndid:keri:ETest\n"));
        assert!(s.contains("\ndid:key:z6MkTest\n"));
        assert!(s.contains("\n42\n"));
    }

    #[test]
    fn canonical_bytes_differ_from_live_revocation_context() {
        // The pre-signed and live-signed contexts must be distinct so
        // cross-context replay is impossible.
        use crate::domain_separation::REVOCATION_LIVE_CONTEXT;
        assert_ne!(REVOCATION_LIVE_CONTEXT, REVOCATION_PRESIGNED_CONTEXT);
    }

    #[test]
    fn canonical_bytes_include_timestamps_in_rfc3339_form() {
        use chrono::TimeZone;
        let nb = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let na = Utc.with_ymd_and_hms(2036, 1, 1, 0, 0, 0).unwrap();
        let bytes =
            canonicalize_presigned_revocation("did:keri:ETest", "did:key:z6MkTest", 7, nb, na);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("2026-01-01T00:00:00+00:00"));
        assert!(s.contains("2036-01-01T00:00:00+00:00"));
    }
}
