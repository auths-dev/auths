use crate::storage::git_refs::AttestationMetadata;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::Capability;
use auths_verifier::core::{Attestation, CanonicalAttestationData, canonicalize_attestation_data};
use auths_verifier::error::AttestationError;
use auths_verifier::types::DeviceDID;

use chrono::{DateTime, Utc};
use log::debug;
use ring::signature::ED25519_PUBLIC_KEY_LEN;
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
    pub issuer: &'a IdentityDID,
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
    role: Option<String>,
    delegated_by: Option<IdentityDID>,
) -> Result<Attestation, AttestationError> {
    if device_public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "Device public key length must be {}",
            ED25519_PUBLIC_KEY_LEN
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

    // Construct the canonical data to be signed
    let data_to_canonicalize = CanonicalAttestationData {
        version: ATTESTATION_VERSION,
        rid,
        issuer: identity_did,
        subject: device_did,
        device_public_key,
        payload: &payload,
        timestamp: &meta.timestamp,
        expires_at: &meta.expires_at,
        revoked_at: &None,
        note: &meta.note,
        // Org fields included in signed envelope
        role: role.as_deref(),
        capabilities: if capabilities.is_empty() {
            None
        } else {
            Some(&capabilities)
        },
        delegated_by: delegated_by.as_ref(),
        signer_type: None,
    };

    // Canonicalize the attestation data
    let message_to_sign = canonicalize_attestation_data(&data_to_canonicalize)?;

    // Sign with the identity key (if alias provided)
    let identity_signature = if let Some(alias) = identity_alias {
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
        sig
    } else {
        debug!("No identity alias provided, skipping identity signature (device-only attestation)");
        Vec::new()
    };

    // Sign with the device key if alias provided
    let device_signature = if let Some(alias) = device_alias {
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
        sig
    } else {
        debug!("No device alias provided, skipping device signature");
        Vec::new()
    };

    // Construct final attestation
    Ok(Attestation {
        version: ATTESTATION_VERSION,
        subject: device_did.clone(),
        issuer: identity_did.clone(),
        rid: rid.to_string(),
        payload: payload.clone(),
        timestamp: meta.timestamp,
        expires_at: meta.expires_at,
        revoked_at: None,
        note: meta.note.clone(),
        device_public_key: device_public_key.to_vec(),
        identity_signature,
        device_signature,
        role,
        capabilities,
        delegated_by,
        signer_type: None,
    })
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
