//! Attestation mutation helpers (extend expiration, resign).
//!
//! These functions take an existing attestation and re-sign it using
//! a [`SecureSigner`], following the same pattern as `create_signed_attestation`.

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_verifier::core::{Attestation, CanonicalAttestationData, canonicalize_attestation_data};
use auths_verifier::error::AttestationError;

use chrono::{DateTime, Utc};
use log::debug;

/// Extend the expiration of an existing attestation and re-sign it.
///
/// Creates a new attestation with the updated `expires_at` and a fresh
/// timestamp, then dual-signs it with the identity and device keys.
///
/// # Arguments
/// * `attestation` - The existing attestation to extend
/// * `new_expiration` - The new expiration timestamp
/// * `signer` - SecureSigner for signing operations
/// * `passphrase_provider` - Provider for obtaining passphrases
/// * `identity_alias` - Optional alias of the identity key in the keychain (None = skip identity sig)
/// * `device_alias` - Alias of the device key in the keychain
pub fn extend_expiration(
    now: DateTime<Utc>,
    attestation: &Attestation,
    new_expiration: DateTime<Utc>,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    identity_alias: Option<&KeyAlias>,
    device_alias: &KeyAlias,
) -> Result<Attestation, AttestationError> {
    let mut updated = attestation.clone();
    updated.expires_at = Some(new_expiration);
    updated.timestamp = Some(now);

    resign_attestation(
        &mut updated,
        signer,
        passphrase_provider,
        identity_alias,
        device_alias,
    )?;

    Ok(updated)
}

/// Re-sign an attestation in-place using the provided signer.
///
/// Recomputes the canonical data and produces fresh identity and device
/// signatures. This is useful after modifying any attestation fields.
///
/// # Arguments
/// * `attestation` - The attestation to re-sign (modified in place)
/// * `signer` - SecureSigner for signing operations
/// * `passphrase_provider` - Provider for obtaining passphrases
/// * `identity_alias` - Optional alias of the identity key in the keychain (None = skip identity sig)
/// * `device_alias` - Alias of the device key in the keychain
pub fn resign_attestation(
    attestation: &mut Attestation,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    identity_alias: Option<&KeyAlias>,
    device_alias: &KeyAlias,
) -> Result<(), AttestationError> {
    let data_to_canonicalize = CanonicalAttestationData {
        version: attestation.version,
        rid: &attestation.rid,
        issuer: &attestation.issuer,
        subject: &attestation.subject,
        device_public_key: attestation.device_public_key.as_bytes(),
        payload: &attestation.payload,
        timestamp: &attestation.timestamp,
        expires_at: &attestation.expires_at,
        revoked_at: &attestation.revoked_at,
        note: &attestation.note,
        role: attestation.role.as_ref().map(|r| r.as_str()),
        capabilities: if attestation.capabilities.is_empty() {
            None
        } else {
            Some(&attestation.capabilities)
        },
        delegated_by: attestation.delegated_by.as_ref(),
        signer_type: attestation.signer_type.as_ref(),
    };

    let message_to_sign = canonicalize_attestation_data(&data_to_canonicalize)?;

    // Sign with the identity key (if alias provided)
    if let Some(alias) = identity_alias {
        debug!("Re-signing attestation with identity alias '{}'", alias);
        attestation.identity_signature = signer
            .sign_with_alias(alias, passphrase_provider, &message_to_sign)
            .map_err(|e| {
                AttestationError::SigningError(format!(
                    "Failed to sign with identity key '{}': {}",
                    alias, e
                ))
            })?;
    } else {
        debug!("No identity alias provided, skipping identity signature (device-only)");
        attestation.identity_signature = Vec::new();
    }

    // Sign with the device key
    debug!(
        "Re-signing attestation with device alias '{}'",
        device_alias
    );
    attestation.device_signature = signer
        .sign_with_alias(device_alias, passphrase_provider, &message_to_sign)
        .map_err(|e| {
            AttestationError::SigningError(format!(
                "Failed to sign with device key '{}': {}",
                device_alias, e
            ))
        })?;

    Ok(())
}
