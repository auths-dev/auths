use crate::storage::git_refs::AttestationMetadata;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::Capability;
use auths_verifier::core::{
    Attestation, Ed25519Signature, ResourceId, Role, SignerType, canonicalize_attestation_data,
};
use auths_verifier::error::AttestationError;
use auths_verifier::types::{CanonicalDid, DeviceDID};

use chrono::{DateTime, Utc};
use log::debug;
use serde::Serialize;
use serde_json::Value;

/// Current attestation version - includes org fields in signed envelope
pub const ATTESTATION_VERSION: u32 = 1;

/// Maximum allowed clock drift at creation time (seconds)
const MAX_CREATION_SKEW_SECS: i64 = 5 * 60;

/// NEW: Data structure specifically for canonicalizing revocation statements.
/// Excludes fields not relevant to the revocation itself (device_pk, payload, expires_at).
#[derive(Serialize, Debug)] // Added Debug
pub struct CanonicalRevocationData<'a> {
    pub version: u32,
    pub rid: &'a str,
    pub issuer: &'a CanonicalDid,
    pub subject: &'a DeviceDID,
    pub timestamp: &'a Option<DateTime<Utc>>,
    pub revoked_at: &'a Option<DateTime<Utc>>, // Should always be Some(...)
    pub note: &'a Option<String>,
}

/// Creates a signed attestation by signing internally using the provided SecureSigner.
///
/// This function constructs the canonical attestation data, signs it using the signer
/// for both identity and device (if device_alias is provided), and returns the complete
/// attestation with embedded signatures.
///
/// # Arguments
/// * `rid` - Resource identifier for this attestation
/// * `identity_did` - The identity DID (e.g., "did:keri:...") issuing the attestation
/// * `device_did` - The device DID being attested
/// * `device_public_key` - The 32-byte Ed25519 public key of the device
/// * `payload` - Optional JSON payload for the attestation
/// * `meta` - Attestation metadata (timestamp, expiry, notes)
/// * `signer` - SecureSigner implementation for signing operations
/// * `passphrase_provider` - Provider for obtaining passphrases during signing
/// * `identity_alias` - Optional alias of the identity key in the keychain (None = device-only signing)
/// * `device_alias` - Optional alias of the device key (None means no device signature)
/// * `capabilities` - Capabilities to grant (included in the signed envelope)
/// * `role` - Optional org role (e.g., "admin", "member") included in the signed envelope
/// * `delegated_by` - Optional DID of the delegator included in the signed envelope
#[allow(clippy::too_many_arguments)]
pub fn create_signed_attestation(
    now: DateTime<Utc>,
    rid: &str,
    identity_did: &IdentityDID,
    device_did: &DeviceDID,
    device_public_key: &[u8],
    payload: Option<Value>,
    meta: &AttestationMetadata,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    identity_alias: Option<&KeyAlias>,
    device_alias: Option<&KeyAlias>,
    capabilities: Vec<Capability>,
    role: Option<Role>,
    delegated_by: Option<IdentityDID>,
    commit_sha: Option<String>,
    signer_type: Option<SignerType>,
) -> Result<Attestation, AttestationError> {
    // Accept both Ed25519 (32 bytes) and P-256 compressed (33 bytes) public keys
    if device_public_key.len() != 32 && device_public_key.len() != 33 {
        return Err(AttestationError::InvalidInput(format!(
            "Device public key length must be 32 (Ed25519) or 33 (P-256), got {}",
            device_public_key.len()
        )));
    }

    // Validate timestamp is not too far from current time (clock drift protection)
    if let Some(ts) = meta.timestamp {
        let drift = (now - ts).num_seconds().abs();
        if drift > MAX_CREATION_SKEW_SECS {
            return Err(AttestationError::InvalidInput(format!(
                "System clock drift {}s exceeds {}s limit",
                drift, MAX_CREATION_SKEW_SECS
            )));
        }
    }

    // Build attestation with empty signatures first (ActionEnvelope pattern)
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: identity_did is an IdentityDID which guarantees valid DID format
    let issuer_canonical = CanonicalDid::new_unchecked(identity_did.as_str());
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: device_did is a validated DeviceDID from the caller
    let subject_canonical = CanonicalDid::new_unchecked(device_did.as_str());
    let delegated_canonical = delegated_by.as_ref().map(|d| CanonicalDid::from(d.clone()));

    let mut attestation = Attestation {
        version: ATTESTATION_VERSION,
        subject: subject_canonical,
        issuer: issuer_canonical,
        rid: ResourceId::new(rid),
        payload: payload.clone(),
        timestamp: meta.timestamp,
        expires_at: meta.expires_at,
        revoked_at: None,
        note: meta.note.clone(),
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
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        role,
        capabilities,
        delegated_by: delegated_canonical,
        signer_type,
        environment_claim: None,
        commit_sha,
        commit_message: None,
        author: None,
        oidc_binding: None,
    };

    // Canonicalize using single source of truth
    let message_to_sign = canonicalize_attestation_data(&attestation.canonical_data())?;

    // Sign with the identity key (if alias provided)
    if let Some(alias) = identity_alias {
        debug!("Signing attestation with identity alias '{}'", alias);
        let sig = signer
            .sign_with_alias(alias, passphrase_provider, &message_to_sign)
            .map_err(|e| {
                AttestationError::SigningError(format!(
                    "Failed to sign with identity key '{}': {}",
                    alias, e
                ))
            })?;
        debug!("Identity signature obtained successfully");
        attestation.identity_signature = Ed25519Signature::try_from_slice(&sig)
            .map_err(|e| AttestationError::SigningError(e.to_string()))?;
    } else {
        debug!("No identity alias provided, skipping identity signature (device-only attestation)");
    }

    // Sign with the device key if alias provided
    if let Some(alias) = device_alias {
        debug!("Signing attestation with device alias '{}'", alias);
        let sig = signer
            .sign_with_alias(alias, passphrase_provider, &message_to_sign)
            .map_err(|e| {
                AttestationError::SigningError(format!(
                    "Failed to sign with device key '{}': {}",
                    alias, e
                ))
            })?;
        debug!("Device signature obtained successfully");
        attestation.device_signature = Ed25519Signature::try_from_slice(&sig)
            .map_err(|e| AttestationError::SigningError(e.to_string()))?;
    } else {
        debug!("No device alias provided, skipping device signature");
    }

    Ok(attestation)
}

/// Generates the canonical byte representation specifically for revocation data.
pub fn canonicalize_revocation_data(
    data: &CanonicalRevocationData,
) -> Result<Vec<u8>, AttestationError> {
    let canonical_json_string = json_canon::to_string(data).map_err(|e| {
        AttestationError::SerializationError(format!(
            "Failed to create canonical JSON for revocation: {}",
            e
        ))
    })?;
    debug!(
        "Generated canonical data (revocation): {}",
        canonical_json_string
    );
    Ok(canonical_json_string.into_bytes())
}
