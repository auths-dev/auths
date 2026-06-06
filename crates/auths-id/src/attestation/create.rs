use crate::storage::git_refs::AttestationMetadata;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::core::{
    Attestation, Ed25519Signature, ResourceId, SignerType, canonicalize_attestation_data,
};
use auths_verifier::error::AttestationError;
use auths_verifier::types::CanonicalDid;

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
    pub subject: &'a CanonicalDid,
    pub timestamp: &'a Option<DateTime<Utc>>,
    pub revoked_at: &'a Option<DateTime<Utc>>, // Should always be Some(...)
    pub note: &'a Option<String>,
}

/// Inputs for `create_signed_attestation`.
///
/// Collapses the long positional argument list into a named-field struct so
/// the call sites stay readable as the shape of an attestation evolves.
/// Callers build one of these and hand it in; the function signs over the
/// canonical bytes and returns the complete attestation.
pub struct AttestationInput<'a> {
    /// Resource identifier for this attestation.
    pub rid: &'a str,
    /// The identity DID (e.g., "did:keri:...") issuing the attestation.
    pub identity_did: &'a IdentityDID,
    /// The subject of the attestation — typed as `&CanonicalDid` so
    /// callers can supply either `did:key:` or `did:keri:` shapes. The
    /// wire format (`Attestation.subject`) is also `CanonicalDid`, so
    /// this field type matches the downstream serialized shape
    /// exactly. Field named `subject` to match wire semantics.
    pub subject: &'a CanonicalDid,
    /// Raw device public key bytes (32 Ed25519, 33 P-256 compressed).
    pub device_public_key: &'a [u8],
    /// Signing curve of `device_public_key`. Carried in-band so the
    /// attestation interior never infers curve from byte length.
    pub device_curve: auths_crypto::CurveType,
    /// Optional JSON payload for the attestation.
    pub payload: Option<Value>,
    /// Attestation metadata (timestamp, expiry, notes).
    pub meta: &'a AttestationMetadata,
    /// Identity-key alias in the keychain; `None` = device-only signing.
    pub identity_alias: Option<&'a KeyAlias>,
    /// Device-key alias; `None` = no device signature.
    pub device_alias: Option<&'a KeyAlias>,
    /// Optional delegator DID included in the signed envelope.
    pub delegated_by: Option<IdentityDID>,
    /// Git commit SHA this attestation anchors, if any.
    pub commit_sha: Option<String>,
    /// Signer type (machine, human, etc.).
    pub signer_type: Option<SignerType>,
}

/// Creates a signed attestation by signing internally using the provided SecureSigner.
///
/// Constructs the canonical attestation data, signs it using the signer for
/// both identity and device (if `device_alias` is provided), and returns the
/// complete attestation with embedded signatures.
///
/// Args:
/// * `now`: Creation timestamp, validated against `input.meta.timestamp` for clock drift.
/// * `input`: Attestation payload + metadata (see [`AttestationInput`]).
/// * `signer`: SecureSigner implementation for signing operations.
/// * `passphrase_provider`: Provider for obtaining passphrases during signing.
///
/// Usage:
/// ```ignore
/// let att = create_signed_attestation(now, input, signer, passphrase)?;
/// ```
pub fn create_signed_attestation(
    now: DateTime<Utc>,
    input: AttestationInput<'_>,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<Attestation, AttestationError> {
    let AttestationInput {
        rid,
        identity_did,
        subject,
        device_public_key,
        device_curve,
        payload,
        meta,
        identity_alias,
        device_alias,
        delegated_by,
        commit_sha,
        signer_type,
    } = input;
    // Length must match the declared curve. No length dispatch — the curve
    // came in-band from the caller, so this is pure validation.
    let expected = device_curve.public_key_len();
    if device_public_key.len() != expected {
        return Err(AttestationError::InvalidInput(format!(
            "Device public key length {} does not match {} (expected {} bytes)",
            device_public_key.len(),
            device_curve,
            expected
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
    // INVARIANT: subject is a validated CanonicalDid from the caller
    let subject_canonical = CanonicalDid::new_unchecked(subject.as_str());
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
        device_public_key: auths_verifier::DevicePublicKey::try_new(
            device_curve,
            device_public_key,
        )
        .map_err(|e| AttestationError::InvalidInput(e.to_string()))?,
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
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
