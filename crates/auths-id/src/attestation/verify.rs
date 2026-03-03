use crate::identity::resolve::DidResolver;
use auths_verifier::core::{Attestation, CanonicalAttestationData};
use auths_verifier::error::AttestationError;
use chrono::{DateTime, Duration, Utc};
use log::debug;
use ring::signature::{ED25519, UnparsedPublicKey};

/// Maximum allowed time skew for attestation timestamps.
const MAX_SKEW_SECS: i64 = 5 * 60;

pub fn verify_with_resolver(
    now: DateTime<Utc>,
    resolver: &dyn DidResolver,
    att: &Attestation,
) -> Result<(), AttestationError> {
    // Return specific AttestationError
    // 1. Check revocation and expiration
    if att.is_revoked() {
        return Err(AttestationError::VerificationError(
            "Attestation revoked".to_string(),
        ));
    }
    if let Some(exp) = att.expires_at
        && now > exp
    {
        return Err(AttestationError::VerificationError(format!(
            "Attestation expired on {}",
            exp.to_rfc3339()
        )));
    }
    // Only reject timestamps in the future (clock drift protection)
    // Past timestamps are valid - attestations stored in Git are verified days/months later
    if let Some(ts) = att.timestamp
        && ts > now + Duration::seconds(MAX_SKEW_SECS)
    {
        return Err(AttestationError::VerificationError(format!(
            "Attestation timestamp {} is in the future",
            ts.to_rfc3339()
        )));
    }

    // 2. Resolve issuer's public key
    let resolved = resolver.resolve(&att.issuer).map_err(|e| {
        AttestationError::DidResolutionError(format!("Resolver error for {}: {}", att.issuer, e))
    })?;
    let issuer_pk_bytes = *resolved.public_key();

    // 3. Reconstruct canonical data (MUST match create_with_signatures, includes org fields)
    let data_to_canonicalize = CanonicalAttestationData {
        version: att.version,
        rid: &att.rid,
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_bytes(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: att.role.as_ref().map(|r| r.as_str()),
        capabilities: if att.capabilities.is_empty() {
            None
        } else {
            Some(&att.capabilities)
        },
        delegated_by: att.delegated_by.as_ref(),
        signer_type: att.signer_type.as_ref(),
    };
    let canonical_json_string = json_canon::to_string(&data_to_canonicalize).map_err(|e| {
        AttestationError::SerializationError(format!(
            "Failed to create canonical JSON for verification: {}",
            e
        ))
    })?;
    let data_to_verify = canonical_json_string.as_bytes();
    debug!(
        "(Verify) Canonical data for verification: {}",
        canonical_json_string
    );

    // 4. Verify issuer signature
    let issuer_public_key_ring = UnparsedPublicKey::new(&ED25519, &issuer_pk_bytes);
    issuer_public_key_ring
        .verify(data_to_verify, att.identity_signature.as_bytes())
        .map_err(|e| {
            AttestationError::VerificationError(format!(
                "Issuer signature verification failed: {}",
                e
            ))
        })?;
    debug!(
        "(Verify) Issuer signature verified successfully for {}",
        att.issuer
    );

    // 5. Verify subject (device) signature using stored public key
    let device_public_key_ring = UnparsedPublicKey::new(&ED25519, att.device_public_key.as_bytes());
    device_public_key_ring
        .verify(data_to_verify, att.device_signature.as_bytes())
        .map_err(|e| {
            AttestationError::VerificationError(format!(
                "Device signature verification failed: {}",
                e
            ))
        })?;
    debug!(
        "(Verify) Device signature verified successfully for {}",
        att.subject.as_str()
    );

    // Optional: Schema validation could be a separate function or re-added here if needed
    // if let Some(schema_val) = schema_value { ... }

    Ok(())
}
