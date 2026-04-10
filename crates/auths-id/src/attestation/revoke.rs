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
/// * `device_public_key` - The device's Ed25519 public key bytes (from existing attestation)
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
        // TODO: take DevicePublicKey directly instead of inferring curve from length
        device_public_key: auths_verifier::DevicePublicKey::try_new(
            if device_public_key.len() == 32 {
                auths_crypto::CurveType::Ed25519
            } else {
                auths_crypto::CurveType::P256
            },
            device_public_key,
        )
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
