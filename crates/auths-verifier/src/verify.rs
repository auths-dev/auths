//! Free-function verification API wrapping [`crate::verifier::Verifier`].

#[cfg(feature = "native")]
use crate::core::Capability;
use crate::core::{
    Attestation, DevicePublicKey, VerifiedAttestation, canonicalize_attestation_data,
};
use crate::error::AttestationError;
use crate::types::{ChainLink, VerificationReport, VerificationStatus};
#[cfg(feature = "native")]
use crate::witness::WitnessVerifyConfig;
use auths_crypto::CryptoProvider;
use auths_keri::{Event, compute_said, find_seal_in_kel};
use chrono::{DateTime, Duration, Utc};
use log::debug;
use serde::Serialize;

/// Maximum allowed clock skew in seconds for timestamp validation.
const MAX_SKEW_SECS: i64 = 5 * 60;

// ---------------------------------------------------------------------------
// Public free functions — backward-compatible, #[cfg(feature = "native")]
// ---------------------------------------------------------------------------

/// Verify an attestation's signatures against the issuer's public key.
///
/// Args:
/// * `att`: The attestation to verify.
/// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
#[cfg(feature = "native")]
pub async fn verify_with_keys(
    att: &Attestation,
    issuer_pk: &DevicePublicKey,
) -> Result<VerifiedAttestation, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_with_keys(att, issuer_pk)
        .await
}

/// Verify an attestation and check that it grants a required capability.
///
/// Args:
/// * `att`: The attestation to verify.
/// * `required`: The capability that must be present.
/// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
#[cfg(feature = "native")]
pub async fn verify_with_capability(
    att: &Attestation,
    required: &Capability,
    issuer_pk: &DevicePublicKey,
) -> Result<VerifiedAttestation, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_with_capability(att, required, issuer_pk)
        .await
}

/// Verify a chain and assert that all attestations share a required capability.
///
/// Args:
/// * `attestations`: Ordered attestation chain (root first).
/// * `required`: The capability that must appear in every link.
/// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
#[cfg(feature = "native")]
pub async fn verify_chain_with_capability(
    attestations: &[Attestation],
    required: &Capability,
    root_pk: &DevicePublicKey,
) -> Result<VerificationReport, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_chain_with_capability(attestations, required, root_pk)
        .await
}

/// Verify an attestation against a specific point in time.
///
/// Args:
/// * `att`: The attestation to verify.
/// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
/// * `at`: The reference timestamp for expiry evaluation.
#[cfg(feature = "native")]
pub async fn verify_at_time(
    att: &Attestation,
    issuer_pk: &DevicePublicKey,
    at: DateTime<Utc>,
) -> Result<VerifiedAttestation, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_at_time(att, issuer_pk, at)
        .await
}

/// Verify a chain and validate witness receipts against a quorum threshold.
///
/// Args:
/// * `attestations`: Ordered attestation chain (root first).
/// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
/// * `witness_config`: Witness receipts and quorum threshold to validate.
#[cfg(feature = "native")]
pub async fn verify_chain_with_witnesses(
    attestations: &[Attestation],
    root_pk: &DevicePublicKey,
    witness_config: &WitnessVerifyConfig<'_>,
) -> Result<VerificationReport, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_chain_with_witnesses(attestations, root_pk, witness_config)
        .await
}

/// Verify an ordered attestation chain starting from a known root public key.
///
/// Args:
/// * `attestations`: Ordered attestation chain (root first).
/// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
#[cfg(feature = "native")]
pub async fn verify_chain(
    attestations: &[Attestation],
    root_pk: &DevicePublicKey,
) -> Result<VerificationReport, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_chain(attestations, root_pk)
        .await
}

/// Verify that a device is authorized under a given identity.
///
/// Args:
/// * `identity_did`: The DID of the authorizing identity.
/// * `device_did`: The device DID to check authorization for.
/// * `attestations`: Pool of attestations to search.
/// * `identity_pk`: Typed identity public key (Ed25519 or P-256).
#[cfg(feature = "native")]
pub async fn verify_device_authorization(
    identity_did: &str,
    device_did: &crate::types::DeviceDID,
    attestations: &[Attestation],
    identity_pk: &DevicePublicKey,
) -> Result<VerificationReport, AttestationError> {
    crate::verifier::Verifier::native()
        .verify_device_authorization(identity_did, device_did, attestations, identity_pk)
        .await
}

use crate::types::DeviceDID;

/// Checks if a device appears in a list of **already-verified** attestations.
pub fn is_device_listed(
    identity_did: &str,
    device_did: &DeviceDID,
    attestations: &[VerifiedAttestation],
    now: DateTime<Utc>,
) -> bool {
    let device_did_str = device_did.to_string();

    attestations.iter().any(|verified| {
        let att = verified.inner();
        if att.issuer != identity_did {
            return false;
        }
        if att.subject.to_string() != device_did_str {
            return false;
        }
        if att.is_revoked() {
            return false;
        }
        if let Some(exp) = att.expires_at
            && now > exp
        {
            return false;
        }
        true
    })
}

// ---------------------------------------------------------------------------
// Device-link verification — stateless, provider-agnostic
// ---------------------------------------------------------------------------

/// Result of verifying a device's link to a KERI identity.
///
/// Verification failures are expressed as `valid: false` with an error message,
/// not as Rust `Err` values. Only infrastructure errors (bad input, serialization)
/// produce `Err`.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceLinkVerification {
    /// Whether the device link verified successfully.
    pub valid: bool,
    /// Human-readable reason if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The KERI key state after KEL replay (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_state: Option<auths_keri::KeyState>,
    /// Sequence number of the IXN event anchoring the attestation seal (if found).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_sequence: Option<u128>,
}

impl DeviceLinkVerification {
    fn success(key_state: auths_keri::KeyState, seal_sequence: Option<u128>) -> Self {
        Self {
            valid: true,
            error: None,
            key_state: Some(key_state),
            seal_sequence,
        }
    }

    fn failure(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            error: Some(reason.into()),
            key_state: None,
            seal_sequence: None,
        }
    }
}

/// Verify that a device (`did:key`) is cryptographically linked to a KERI identity.
///
/// Composes: KEL verification, attestation signature verification, device DID matching,
/// and optional seal anchoring. Provider-agnostic — works with any `CryptoProvider`.
///
/// Args:
/// * `events`: Parsed KEL events (inception first).
/// * `attestation`: The attestation linking identity to device.
/// * `device_did`: The expected device DID (checked against attestation subject).
/// * `now`: Reference time for expiration/revocation checks.
/// * `provider`: Cryptographic provider for Ed25519 verification.
///
/// Usage:
/// ```ignore
/// let result = verify_device_link(&events, &att, "did:key:z6Mk...", now, &provider).await;
/// if result.valid { /* ... */ }
/// ```
pub async fn verify_device_link(
    events: &[Event],
    attestation: &Attestation,
    device_did: &str,
    now: DateTime<Utc>,
    provider: &dyn CryptoProvider,
) -> DeviceLinkVerification {
    let key_state = match auths_keri::validate_kel(events) {
        Ok(ks) => ks,
        Err(e) => return DeviceLinkVerification::failure(format!("KEL verification failed: {e}")),
    };

    if attestation.subject.as_str() != device_did {
        return DeviceLinkVerification::failure(format!(
            "Device DID mismatch: attestation subject is '{}', expected '{device_did}'",
            attestation.subject
        ));
    }

    let current_pk = match key_state.current_keys.first() {
        Some(encoded) => match auths_keri::KeriPublicKey::parse(encoded.as_str()) {
            Ok(keri_pk) => {
                let bytes = keri_pk.into_bytes().to_vec();
                match DevicePublicKey::try_new(auths_crypto::CurveType::Ed25519, &bytes) {
                    Ok(dpk) => dpk,
                    Err(e) => {
                        return DeviceLinkVerification::failure(format!(
                            "Invalid current key: {e}"
                        ));
                    }
                }
            }
            Err(e) => {
                return DeviceLinkVerification::failure(format!("Invalid current key: {e}"));
            }
        },
        None => return DeviceLinkVerification::failure("KEL has no current keys"),
    };

    if let Err(e) = verify_with_keys_at(attestation, &current_pk, now, true, provider).await {
        return DeviceLinkVerification::failure(format!("Attestation verification failed: {e}"));
    }

    let seal_sequence = compute_attestation_seal_digest(attestation)
        .ok()
        .and_then(|digest| find_seal_in_kel(events, digest.as_str()));

    DeviceLinkVerification::success(key_state, seal_sequence)
}

/// Compute the KERI SAID (Blake3 digest) of an attestation's canonical form.
///
/// This is the digest that should appear in a KEL IXN seal when the attestation
/// is anchored. Returns the SAID string (E-prefixed base64url Blake3).
pub fn compute_attestation_seal_digest(
    attestation: &Attestation,
) -> Result<String, AttestationError> {
    let canonical = canonicalize_attestation_data(&attestation.canonical_data())?;
    let value: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|e| AttestationError::SerializationError(e.to_string()))?;
    Ok(compute_said(&value)
        .map_err(|e| AttestationError::SerializationError(e.to_string()))?
        .into_inner())
}

// ---------------------------------------------------------------------------
// Internal async functions — used by Verifier and free function wrappers
// ---------------------------------------------------------------------------

pub(crate) async fn verify_with_keys_at(
    att: &Attestation,
    issuer_pk: &DevicePublicKey,
    at: DateTime<Utc>,
    check_skew: bool,
    provider: &dyn CryptoProvider,
) -> Result<(), AttestationError> {
    let reference_time = at;

    // --- 1. Check revocation (time-aware) ---
    if let Some(revoked_at) = att.revoked_at
        && revoked_at <= reference_time
    {
        return Err(AttestationError::AttestationRevoked);
    }

    // --- 2. Check expiration against reference time ---
    if let Some(exp) = att.expires_at
        && reference_time > exp
    {
        return Err(AttestationError::AttestationExpired {
            at: exp.to_rfc3339(),
        });
    }

    // --- 3. Check timestamp skew against reference time ---
    if check_skew
        && let Some(ts) = att.timestamp
        && ts > reference_time + Duration::seconds(MAX_SKEW_SECS)
    {
        return Err(AttestationError::TimestampInFuture {
            at: ts.to_rfc3339(),
        });
    }

    // --- 4. Reconstruct and canonicalize data ---
    let canonical_json_bytes = canonicalize_attestation_data(&att.canonical_data())?;
    let data_to_verify = canonical_json_bytes.as_slice();
    debug!(
        "(Verify) Canonical data: {}",
        String::from_utf8_lossy(&canonical_json_bytes)
    );

    // --- 5. Verify issuer signature (dispatched on curve) ---
    if !att.identity_signature.is_empty() {
        verify_signature_by_curve(
            issuer_pk,
            data_to_verify,
            att.identity_signature.as_bytes(),
            provider,
            SignatureRole::Issuer,
        )
        .await?;
        debug!("(Verify) Issuer signature verified successfully.");
    } else {
        debug!(
            "(Verify) No identity signature present (device-only attestation), skipping issuer check."
        );
    }

    // --- 6. Verify device signature (dispatched on curve) ---
    verify_signature_by_curve(
        &att.device_public_key,
        data_to_verify,
        att.device_signature.as_bytes(),
        provider,
        SignatureRole::Device,
    )
    .await?;
    debug!("(Verify) Device signature verified successfully.");

    Ok(())
}

/// Which signature slot a curve-dispatch error should be attributed to.
#[derive(Clone, Copy)]
enum SignatureRole {
    Issuer,
    Device,
}

/// Verify a signature via the canonical `DevicePublicKey::verify`, attributing
/// failures to the appropriate role (issuer vs device) at the boundary.
///
/// Thin wrapper preserved so that existing chain-verification code can keep
/// its role-attributed error enum; the dispatch itself now lives in
/// `DevicePublicKey::verify` (fn-114.14).
async fn verify_signature_by_curve(
    pk: &DevicePublicKey,
    message: &[u8],
    signature: &[u8],
    provider: &dyn CryptoProvider,
    role: SignatureRole,
) -> Result<(), AttestationError> {
    let map_err = |e: String| match role {
        SignatureRole::Issuer => AttestationError::IssuerSignatureFailed(e),
        SignatureRole::Device => AttestationError::DeviceSignatureFailed(e),
    };

    pk.verify(message, signature, provider)
        .await
        .map_err(|e| map_err(e.to_string()))
}

pub(crate) async fn verify_chain_inner(
    attestations: &[Attestation],
    root_pk: &DevicePublicKey,
    provider: &dyn CryptoProvider,
    now: DateTime<Utc>,
) -> Result<VerificationReport, AttestationError> {
    if attestations.is_empty() {
        return Ok(VerificationReport::with_status(
            VerificationStatus::BrokenChain {
                missing_link: "empty chain".to_string(),
            },
            vec![],
        ));
    }

    let mut chain_links: Vec<ChainLink> = Vec::with_capacity(attestations.len());

    let first_att = &attestations[0];
    match verify_single_attestation(first_att, root_pk, 0, provider, now).await {
        Ok(link) => chain_links.push(link),
        Err((status, link)) => {
            chain_links.push(link);
            return Ok(VerificationReport::with_status(status, chain_links));
        }
    }

    for (idx, att) in attestations.iter().enumerate().skip(1) {
        let prev_att = &attestations[idx - 1];

        if att.issuer.as_str() != prev_att.subject.as_str() {
            let link = ChainLink::invalid(
                att.issuer.to_string(),
                att.subject.to_string(),
                format!(
                    "Chain broken: expected issuer '{}', got '{}'",
                    prev_att.subject, att.issuer
                ),
            );
            chain_links.push(link);
            return Ok(VerificationReport::with_status(
                VerificationStatus::BrokenChain {
                    missing_link: format!(
                        "Issuer mismatch at step {}: expected '{}', got '{}'",
                        idx, prev_att.subject, att.issuer
                    ),
                },
                chain_links,
            ));
        }

        let issuer_pk = &prev_att.device_public_key;

        match verify_single_attestation(att, issuer_pk, idx, provider, now).await {
            Ok(link) => chain_links.push(link),
            Err((status, link)) => {
                chain_links.push(link);
                return Ok(VerificationReport::with_status(status, chain_links));
            }
        }
    }

    Ok(VerificationReport::valid(chain_links))
}

pub(crate) async fn verify_device_authorization_inner(
    identity_did: &str,
    device_did: &DeviceDID,
    attestations: &[Attestation],
    identity_pk: &DevicePublicKey,
    provider: &dyn CryptoProvider,
    now: DateTime<Utc>,
) -> Result<VerificationReport, AttestationError> {
    let device_did_str = device_did.to_string();

    let matching: Vec<&Attestation> = attestations
        .iter()
        .filter(|a| a.issuer == identity_did && a.subject.to_string() == device_did_str)
        .collect();

    if matching.is_empty() {
        return Ok(VerificationReport::with_status(
            VerificationStatus::BrokenChain {
                missing_link: format!(
                    "No attestation found for device {} under {}",
                    device_did_str, identity_did
                ),
            },
            vec![],
        ));
    }

    match verify_single_attestation(matching[0], identity_pk, 0, provider, now).await {
        Ok(link) => Ok(VerificationReport::valid(vec![link])),
        Err((status, link)) => Ok(VerificationReport::with_status(status, vec![link])),
    }
}

async fn verify_single_attestation(
    att: &Attestation,
    issuer_pk: &DevicePublicKey,
    step: usize,
    provider: &dyn CryptoProvider,
    now: DateTime<Utc>,
) -> Result<ChainLink, (VerificationStatus, ChainLink)> {
    let issuer = att.issuer.to_string();
    let subject = att.subject.to_string();

    if att.is_revoked() {
        return Err((
            VerificationStatus::Revoked { at: att.revoked_at },
            ChainLink::invalid(issuer, subject, "Attestation revoked".to_string()),
        ));
    }

    if let Some(exp) = att.expires_at
        && now > exp
    {
        return Err((
            VerificationStatus::Expired { at: exp },
            ChainLink::invalid(
                issuer,
                subject,
                format!("Attestation expired on {}", exp.to_rfc3339()),
            ),
        ));
    }

    match verify_with_keys_at(att, issuer_pk, now, true, provider).await {
        Ok(()) => Ok(ChainLink::valid(issuer, subject)),
        Err(e) => Err((
            VerificationStatus::InvalidSignature { step },
            ChainLink::invalid(issuer, subject, e.to_string()),
        )),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::clock::ClockProvider;
    use crate::core::{Capability, Ed25519PublicKey, Ed25519Signature, ResourceId, Role};
    use crate::types::{CanonicalDid, DeviceDID};
    use crate::verifier::Verifier;
    use auths_crypto::RingCryptoProvider;
    use auths_crypto::testing::create_test_keypair;
    use auths_keri::Said;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::Arc;

    /// Wrap a raw 32-byte Ed25519 key into a `DevicePublicKey` for tests.
    fn ed(pk: &[u8]) -> DevicePublicKey {
        DevicePublicKey::try_new(auths_crypto::CurveType::Ed25519, pk).unwrap()
    }

    /// Build a `did:key:z...` string from a 32-byte Ed25519 public key (test helper).
    fn ed25519_did(pk: &[u8; 32]) -> String {
        DeviceDID::from_public_key(pk, auths_crypto::CurveType::Ed25519).to_string()
    }

    struct TestClock(DateTime<Utc>);
    impl ClockProvider for TestClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
    }

    fn test_verifier() -> Verifier {
        Verifier::new(
            Arc::new(RingCryptoProvider),
            Arc::new(TestClock(fixed_now())),
        )
    }

    /// Helper to create a signed attestation
    fn create_signed_attestation(
        issuer_kp: &Ed25519KeyPair,
        device_kp: &Ed25519KeyPair,
        issuer_did: &str,
        subject_did: &str,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

        let mut att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: CanonicalDid::new_unchecked(issuer_did),
            subject: CanonicalDid::new_unchecked(subject_did),
            device_public_key: Ed25519PublicKey::from_bytes(device_pk).into(),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at,
            expires_at,
            timestamp: Some(fixed_now()),
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            supersedes_attestation_rid: None,
            signer_type: None,
            environment_claim: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
        };

        let canonical_bytes = canonicalize_attestation_data(&att.canonical_data()).unwrap();

        att.identity_signature =
            Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();
        att.device_signature =
            Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();

        att
    }

    #[tokio::test]
    async fn verify_chain_empty_returns_broken_chain() {
        let result = test_verifier()
            .verify_chain(&[], &ed(&[0u8; 32]))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::BrokenChain { missing_link } => {
                assert_eq!(missing_link, "empty chain");
            }
            _ => panic!("Expected BrokenChain status"),
        }
        assert!(result.chain.is_empty());
    }

    #[tokio::test]
    async fn verify_chain_single_valid_attestation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_chain(&[att], &ed(&root_pk))
            .await
            .unwrap();
        assert!(result.is_valid());
        assert_eq!(result.chain.len(), 1);
        assert!(result.chain[0].valid);
    }

    #[tokio::test]
    async fn verify_chain_revoked_attestation_returns_revoked() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(fixed_now()),
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_chain(&[att], &ed(&root_pk))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::Revoked { .. } => {}
            _ => panic!("Expected Revoked status, got {:?}", result.status),
        }
    }

    #[tokio::test]
    async fn verify_chain_expired_attestation_returns_expired() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() - Duration::days(1)),
        );

        let result = test_verifier()
            .verify_chain(&[att], &ed(&root_pk))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::Expired { .. } => {}
            _ => panic!("Expected Expired status, got {:?}", result.status),
        }
    }

    #[tokio::test]
    async fn verify_chain_invalid_signature_returns_invalid_signature() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let mut tampered = *att.identity_signature.as_bytes();
        tampered[0] ^= 0xFF;
        att.identity_signature = Ed25519Signature::from_bytes(tampered);

        let result = test_verifier()
            .verify_chain(&[att], &ed(&root_pk))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::InvalidSignature { step } => {
                assert_eq!(step, 0);
            }
            _ => panic!("Expected InvalidSignature status, got {:?}", result.status),
        }
    }

    #[tokio::test]
    async fn verify_chain_broken_link_returns_broken_chain() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device1_kp, device1_pk) = create_test_keypair(&[2u8; 32]);
        let device1_did = ed25519_did(&device1_pk);
        let (device2_kp, device2_pk) = create_test_keypair(&[3u8; 32]);
        let device2_did = ed25519_did(&device2_pk);

        let att1 = create_signed_attestation(
            &root_kp,
            &device1_kp,
            &root_did,
            &device1_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let att2 = create_signed_attestation(
            &device1_kp,
            &device2_kp,
            &root_did, // WRONG: should be device1_did
            &device2_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_chain(&[att1, att2], &ed(&root_pk))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::BrokenChain { missing_link } => {
                assert!(missing_link.contains("Issuer mismatch"));
            }
            _ => panic!("Expected BrokenChain status, got {:?}", result.status),
        }
    }

    #[tokio::test]
    async fn verify_chain_valid_three_level_chain() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (identity_kp, identity_pk) = create_test_keypair(&[2u8; 32]);
        let identity_did = ed25519_did(&identity_pk);
        let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att1 = create_signed_attestation(
            &root_kp,
            &identity_kp,
            &root_did,
            &identity_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let att2 = create_signed_attestation(
            &identity_kp,
            &device_kp,
            &identity_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_chain(&[att1, att2], &ed(&root_pk))
            .await
            .unwrap();
        assert!(result.is_valid());
        assert_eq!(result.chain.len(), 2);
        assert!(result.chain[0].valid);
        assert!(result.chain[1].valid);
    }

    #[tokio::test]
    async fn verify_chain_revoked_intermediate_returns_revoked() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (identity_kp, identity_pk) = create_test_keypair(&[2u8; 32]);
        let identity_did = ed25519_did(&identity_pk);
        let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att1 = create_signed_attestation(
            &root_kp,
            &identity_kp,
            &root_did,
            &identity_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let att2 = create_signed_attestation(
            &identity_kp,
            &device_kp,
            &identity_did,
            &device_did,
            Some(fixed_now()),
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_chain(&[att1, att2], &ed(&root_pk))
            .await
            .unwrap();
        assert!(!result.is_valid());
        match result.status {
            VerificationStatus::Revoked { .. } => {}
            _ => panic!("Expected Revoked status, got {:?}", result.status),
        }
        assert_eq!(result.chain.len(), 2);
        assert!(result.chain[0].valid);
        assert!(!result.chain[1].valid);
    }

    #[tokio::test]
    async fn verify_at_time_valid_before_expiration() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, _) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&root_pk);

        let expires = fixed_now() + Duration::days(30);
        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(expires),
        );

        let verification_time = fixed_now() + Duration::days(10);
        let result = test_verifier()
            .verify_at_time(&att, &ed(&root_pk), verification_time)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_at_time_expired_after_expiration() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, _) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&root_pk);

        let expires = fixed_now() + Duration::days(30);
        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(expires),
        );

        let verification_time = fixed_now() + Duration::days(60);
        let result = test_verifier()
            .verify_at_time(&att, &ed(&root_pk), verification_time)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn verify_at_time_signature_always_checked() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, _) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&root_pk);

        let mut att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let mut tampered = *att.identity_signature.as_bytes();
        tampered[0] ^= 0xFF;
        att.identity_signature = Ed25519Signature::from_bytes(tampered);

        let verification_time = fixed_now() - Duration::days(10);
        let result = test_verifier()
            .verify_at_time(&att, &ed(&root_pk), verification_time)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[tokio::test]
    async fn verify_at_time_with_past_time_skips_skew_check() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, _) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&root_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let verification_time = fixed_now() - Duration::days(30);
        let result = test_verifier()
            .verify_at_time(&att, &ed(&root_pk), verification_time)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_with_keys_still_works() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, _) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&root_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(result.is_ok());
    }

    /// Helper to wrap an attestation as verified (for tests where we created it ourselves).
    fn verified(att: Attestation) -> VerifiedAttestation {
        VerifiedAttestation::dangerous_from_unchecked(att)
    }

    #[test]
    fn is_device_listed_returns_true_for_valid_attestation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        assert!(is_device_listed(
            &root_did,
            &device_did,
            &[verified(att)],
            fixed_now()
        ));
    }

    #[test]
    fn is_device_listed_returns_false_for_no_attestations() {
        let (_, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (_, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        assert!(!is_device_listed(&root_did, &device_did, &[], fixed_now()));
    }

    #[test]
    fn is_device_listed_returns_false_for_expired_attestation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() - Duration::days(1)),
        );

        assert!(!is_device_listed(
            &root_did,
            &device_did,
            &[verified(att)],
            fixed_now()
        ));
    }

    #[test]
    fn is_device_listed_returns_false_for_revoked_attestation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            Some(fixed_now()),
            Some(fixed_now() + Duration::days(365)),
        );

        assert!(!is_device_listed(
            &root_did,
            &device_did,
            &[verified(att)],
            fixed_now()
        ));
    }

    #[test]
    fn is_device_listed_returns_true_if_one_valid_among_many() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att_expired = verified(create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() - Duration::days(1)),
        ));
        let att_revoked = verified(create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            Some(fixed_now()),
            Some(fixed_now() + Duration::days(365)),
        ));
        let att_valid = verified(create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        ));

        assert!(is_device_listed(
            &root_did,
            &device_did,
            &[att_expired, att_revoked, att_valid],
            fixed_now()
        ));
    }

    #[test]
    fn is_device_listed_returns_false_for_wrong_identity() {
        let (_, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (other_kp, other_pk) = create_test_keypair(&[3u8; 32]);
        let other_did = ed25519_did(&other_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att = create_signed_attestation(
            &other_kp,
            &device_kp,
            &other_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        assert!(!is_device_listed(
            &root_did,
            &device_did,
            &[verified(att)],
            fixed_now()
        ));
    }

    #[test]
    fn is_device_listed_returns_false_for_wrong_device() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let (_, other_device_pk) = create_test_keypair(&[4u8; 32]);
        let other_device_did_str = ed25519_did(&other_device_pk);
        let other_device_did = DeviceDID::new_unchecked(&other_device_did_str);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        assert!(!is_device_listed(
            &root_did,
            &other_device_did,
            &[verified(att)],
            fixed_now()
        ));
    }

    /// Helper to create a signed attestation with org fields
    fn create_signed_attestation_with_org_fields(
        issuer_kp: &Ed25519KeyPair,
        device_kp: &Ed25519KeyPair,
        issuer_did: &str,
        subject_did: &str,
        role: Option<Role>,
        capabilities: Vec<Capability>,
    ) -> Attestation {
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

        let mut att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: CanonicalDid::new_unchecked(issuer_did),
            subject: CanonicalDid::new_unchecked(subject_did),
            device_public_key: Ed25519PublicKey::from_bytes(device_pk).into(),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(fixed_now() + Duration::days(365)),
            timestamp: Some(fixed_now()),
            note: None,
            payload: None,
            role,
            capabilities: capabilities.clone(),
            delegated_by: None,
            supersedes_attestation_rid: None,
            signer_type: None,
            environment_claim: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
        };

        let canonical_bytes = canonicalize_attestation_data(&att.canonical_data()).unwrap();

        att.identity_signature =
            Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();
        att.device_signature =
            Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();

        att
    }

    fn create_signed_attestation_with_caps(
        issuer_kp: &Ed25519KeyPair,
        device_kp: &Ed25519KeyPair,
        issuer_did: &str,
        subject_did: &str,
        capabilities: Vec<Capability>,
    ) -> Attestation {
        create_signed_attestation_with_org_fields(
            issuer_kp,
            device_kp,
            issuer_did,
            subject_did,
            None,
            capabilities,
        )
    }

    #[tokio::test]
    async fn verify_with_capability_succeeds_when_capability_present() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation_with_caps(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            vec![Capability::sign_commit(), Capability::sign_release()],
        );

        let result = test_verifier()
            .verify_with_capability(&att, &Capability::sign_commit(), &ed(&root_pk))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_with_capability_fails_when_capability_missing() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation_with_caps(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            vec![Capability::sign_commit()],
        );

        let result = test_verifier()
            .verify_with_capability(&att, &Capability::manage_members(), &ed(&root_pk))
            .await;
        assert!(result.is_err());
        match result {
            Err(AttestationError::MissingCapability {
                required,
                available,
            }) => {
                assert_eq!(required, Capability::manage_members());
                assert_eq!(available, vec![Capability::sign_commit()]);
            }
            _ => panic!("Expected MissingCapability error"),
        }
    }

    #[tokio::test]
    async fn verify_with_capability_fails_for_invalid_signature() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = create_signed_attestation_with_caps(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            vec![Capability::sign_commit()],
        );
        let mut tampered = *att.identity_signature.as_bytes();
        tampered[0] ^= 0xFF;
        att.identity_signature = Ed25519Signature::from_bytes(tampered);

        let result = test_verifier()
            .verify_with_capability(&att, &Capability::sign_commit(), &ed(&root_pk))
            .await;
        assert!(result.is_err());
        match result {
            Err(AttestationError::IssuerSignatureFailed(_)) => {}
            _ => panic!("Expected IssuerSignatureFailed, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn verify_chain_with_capability_succeeds_for_single_link() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation_with_caps(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            vec![Capability::sign_commit(), Capability::sign_release()],
        );

        let result = test_verifier()
            .verify_chain_with_capability(&[att], &Capability::sign_commit(), &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_valid());
    }

    #[tokio::test]
    async fn verify_chain_with_capability_uses_intersection() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (identity_kp, identity_pk) = create_test_keypair(&[2u8; 32]);
        let identity_did = ed25519_did(&identity_pk);
        let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att1 = create_signed_attestation_with_org_fields(
            &root_kp,
            &identity_kp,
            &root_did,
            &identity_did,
            None,
            vec![Capability::sign_commit(), Capability::manage_members()],
        );
        let att2 = create_signed_attestation_with_org_fields(
            &identity_kp,
            &device_kp,
            &identity_did,
            &device_did,
            None,
            vec![Capability::sign_commit(), Capability::sign_release()],
        );

        let result = test_verifier()
            .verify_chain_with_capability(
                &[att1.clone(), att2.clone()],
                &Capability::sign_commit(),
                &ed(&root_pk),
            )
            .await;
        assert!(result.is_ok());

        let result = test_verifier()
            .verify_chain_with_capability(
                &[att1, att2],
                &Capability::manage_members(),
                &ed(&root_pk),
            )
            .await;
        assert!(result.is_err());
        match result {
            Err(AttestationError::MissingCapability { required, .. }) => {
                assert_eq!(required, Capability::manage_members());
            }
            _ => panic!("Expected MissingCapability error"),
        }
    }

    #[tokio::test]
    async fn verify_chain_with_capability_returns_report_on_invalid_chain() {
        let result = test_verifier()
            .verify_chain_with_capability(&[], &Capability::sign_commit(), &ed(&[0u8; 32]))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
    }

    #[tokio::test]
    async fn verify_attestation_rejects_tampered_role() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = create_signed_attestation_with_org_fields(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(Role::Member),
            vec![Capability::sign_commit()],
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(result.is_ok(), "Attestation should verify before tampering");

        att.role = Some(Role::Admin);
        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(result.is_err(), "Attestation should reject tampered role");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("signature"),
            "Error should mention signature failure: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn verify_attestation_rejects_tampered_capabilities() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = create_signed_attestation_with_org_fields(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(Role::Member),
            vec![Capability::sign_commit()],
        );
        assert!(
            test_verifier()
                .verify_with_keys(&att, &ed(&root_pk))
                .await
                .is_ok()
        );

        att.capabilities.push(Capability::manage_members());
        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_err(),
            "Attestation should reject tampered capabilities"
        );
    }

    #[tokio::test]
    async fn verify_attestation_rejects_tampered_delegated_by() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = create_signed_attestation_with_org_fields(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(Role::Member),
            vec![Capability::sign_commit()],
        );
        assert!(
            test_verifier()
                .verify_with_keys(&att, &ed(&root_pk))
                .await
                .is_ok()
        );

        att.delegated_by = Some(CanonicalDid::new_unchecked("did:keri:Eattacker"));
        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_err(),
            "Attestation should reject tampered delegated_by"
        );
    }

    #[tokio::test]
    async fn verify_attestation_valid_with_org_fields() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation_with_org_fields(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(Role::Admin),
            vec![Capability::sign_commit(), Capability::manage_members()],
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_ok(),
            "Attestation with org fields should verify: {:?}",
            result.err()
        );
    }

    fn create_signed_attestation_with_timestamp(
        issuer_kp: &Ed25519KeyPair,
        device_kp: &Ed25519KeyPair,
        issuer_did: &str,
        subject_did: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Attestation {
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

        let mut att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: CanonicalDid::new_unchecked(issuer_did),
            subject: CanonicalDid::new_unchecked(subject_did),
            device_public_key: Ed25519PublicKey::from_bytes(device_pk).into(),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(fixed_now() + Duration::days(365)),
            timestamp,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            supersedes_attestation_rid: None,
            signer_type: None,
            environment_claim: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
        };

        let canonical_bytes = canonicalize_attestation_data(&att.canonical_data()).unwrap();

        att.identity_signature =
            Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();
        att.device_signature =
            Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();

        att
    }

    #[tokio::test]
    async fn verify_attestation_created_1_hour_ago_succeeds() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let one_hour_ago = fixed_now() - Duration::hours(1);
        let att = create_signed_attestation_with_timestamp(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(one_hour_ago),
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_ok(),
            "Attestation created 1 hour ago should verify: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn verify_attestation_created_30_days_ago_succeeds() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let thirty_days_ago = fixed_now() - Duration::days(30);
        let att = create_signed_attestation_with_timestamp(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(thirty_days_ago),
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_ok(),
            "Attestation created 30 days ago should verify: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn verify_attestation_with_future_timestamp_fails() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let ten_minutes_future = fixed_now() + Duration::minutes(10);
        let att = create_signed_attestation_with_timestamp(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            Some(ten_minutes_future),
        );

        let result = test_verifier().verify_with_keys(&att, &ed(&root_pk)).await;
        assert!(
            result.is_err(),
            "Attestation with future timestamp should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("in the future"),
            "Error should mention 'in the future': {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn verify_device_authorization_returns_valid_for_signed_attestation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[att], &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.is_valid());
        assert_eq!(report.chain.len(), 1);
        assert!(report.chain[0].valid);
    }

    #[tokio::test]
    async fn verify_device_authorization_returns_broken_chain_for_no_attestations() {
        let (_, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (_, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[], &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::BrokenChain { missing_link } => {
                assert!(missing_link.contains("No attestation found"));
            }
            _ => panic!("Expected BrokenChain status, got {:?}", report.status),
        }
    }

    #[tokio::test]
    async fn verify_device_authorization_fails_for_forged_signature() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let mut att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );
        let mut tampered = *att.identity_signature.as_bytes();
        tampered[0] ^= 0xFF;
        att.identity_signature = Ed25519Signature::from_bytes(tampered);

        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[att], &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::InvalidSignature { step } => assert_eq!(step, 0),
            _ => panic!("Expected InvalidSignature status, got {:?}", report.status),
        }
    }

    #[tokio::test]
    async fn verify_device_authorization_fails_for_wrong_issuer_key() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);
        let (_, wrong_pk) = create_test_keypair(&[99u8; 32]);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[att], &ed(&wrong_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::InvalidSignature { .. } => {}
            _ => panic!("Expected InvalidSignature status, got {:?}", report.status),
        }
    }

    #[tokio::test]
    async fn verify_device_authorization_checks_expiry_and_revocation() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did_str = ed25519_did(&device_pk);
        let device_did = DeviceDID::new_unchecked(&device_did_str);

        let att_expired = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            None,
            Some(fixed_now() - Duration::days(1)),
        );
        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[att_expired], &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::Expired { .. } => {}
            _ => panic!("Expected Expired status, got {:?}", report.status),
        }

        let att_revoked = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did_str,
            Some(fixed_now()),
            Some(fixed_now() + Duration::days(365)),
        );
        let result = test_verifier()
            .verify_device_authorization(&root_did, &device_did, &[att_revoked], &ed(&root_pk))
            .await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::Revoked { .. } => {}
            _ => panic!("Expected Revoked status, got {:?}", report.status),
        }
    }

    fn create_witness_receipt(
        witness_kp: &Ed25519KeyPair,
        witness_did: &str,
        event_said: &str,
        seq: u128,
    ) -> auths_keri::witness::SignedReceipt {
        let receipt = auths_keri::witness::Receipt {
            v: auths_keri::VersionString::placeholder(),
            t: "rct".into(),
            d: Said::new_unchecked(event_said.to_string()),
            i: auths_keri::Prefix::new_unchecked(witness_did.to_string()),
            s: auths_keri::KeriSequence::new(seq),
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        let sig = witness_kp.sign(&payload).as_ref().to_vec();
        auths_keri::witness::SignedReceipt {
            receipt,
            signature: sig,
        }
    }

    #[tokio::test]
    async fn verify_chain_with_witnesses_valid() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let (w1_kp, w1_pk) = create_test_keypair(&[10u8; 32]);
        let (w2_kp, w2_pk) = create_test_keypair(&[20u8; 32]);

        let r1 = create_witness_receipt(&w1_kp, "did:key:w1", "EEvent1", 1);
        let r2 = create_witness_receipt(&w2_kp, "did:key:w2", "EEvent1", 1);

        let witness_keys = vec![
            ("did:key:w1".into(), w1_pk.to_vec()),
            ("did:key:w2".into(), w2_pk.to_vec()),
        ];

        let config = crate::witness::WitnessVerifyConfig {
            receipts: &[r1, r2],
            witness_keys: &witness_keys,
            threshold: 2,
        };

        let report = test_verifier()
            .verify_chain_with_witnesses(&[att], &ed(&root_pk), &config)
            .await
            .unwrap();
        assert!(report.is_valid());
        assert!(report.witness_quorum.is_some());
        let quorum = report.witness_quorum.unwrap();
        assert_eq!(quorum.required, 2);
        assert_eq!(quorum.verified, 2);
    }

    #[tokio::test]
    async fn verify_chain_with_witnesses_chain_fails() {
        let (w1_kp, w1_pk) = create_test_keypair(&[10u8; 32]);
        let r1 = create_witness_receipt(&w1_kp, "did:key:w1", "EEvent1", 1);
        let witness_keys = vec![("did:key:w1".into(), w1_pk.to_vec())];
        let config = crate::witness::WitnessVerifyConfig {
            receipts: &[r1],
            witness_keys: &witness_keys,
            threshold: 1,
        };

        let report = test_verifier()
            .verify_chain_with_witnesses(&[], &ed(&[0u8; 32]), &config)
            .await
            .unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::BrokenChain { .. } => {}
            _ => panic!("Expected BrokenChain, got {:?}", report.status),
        }
        assert!(report.witness_quorum.is_none());
    }

    #[tokio::test]
    async fn verify_chain_with_witnesses_quorum_fails() {
        let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
        let root_did = ed25519_did(&root_pk);
        let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let att = create_signed_attestation(
            &root_kp,
            &device_kp,
            &root_did,
            &device_did,
            None,
            Some(fixed_now() + Duration::days(365)),
        );

        let (w1_kp, w1_pk) = create_test_keypair(&[10u8; 32]);
        let r1 = create_witness_receipt(&w1_kp, "did:key:w1", "EEvent1", 1);
        let witness_keys = vec![("did:key:w1".into(), w1_pk.to_vec())];
        let config = crate::witness::WitnessVerifyConfig {
            receipts: &[r1],
            witness_keys: &witness_keys,
            threshold: 2,
        };

        let report = test_verifier()
            .verify_chain_with_witnesses(&[att], &ed(&root_pk), &config)
            .await
            .unwrap();
        assert!(!report.is_valid());
        match report.status {
            VerificationStatus::InsufficientWitnesses { required, verified } => {
                assert_eq!(required, 2);
                assert_eq!(verified, 1);
            }
            _ => panic!("Expected InsufficientWitnesses, got {:?}", report.status),
        }
        assert!(report.witness_quorum.is_some());
        assert!(!report.warnings.is_empty());
    }

    /// Verify an attestation signed by a P-256 identity using a P-256 `DevicePublicKey`.
    ///
    /// Reproduces the production CI flow where a P-256 identity signs an Ed25519-device
    /// attestation, and ensures the curve-dispatched verifier accepts a 33-byte compressed
    /// P-256 public key.
    #[tokio::test]
    async fn verify_p256_identity_signed_attestation() {
        use auths_crypto::RingCryptoProvider;

        // Generate a P-256 identity keypair (compressed 33-byte pubkey).
        let (p256_seed, p256_pk_bytes) = RingCryptoProvider::p256_generate().unwrap();
        assert_eq!(
            p256_pk_bytes.len(),
            33,
            "P-256 compressed pubkey is 33 bytes"
        );
        let seed_arr: [u8; 32] = *p256_seed.as_bytes();

        // Use a KERI-style DID for the issuer; the DID value is opaque to the verifier
        // (it does not re-derive the issuer key from the DID).
        let issuer_did = "did:keri:Etest-p256-identity";

        // Device remains Ed25519 for this test — matches real-world usage.
        let (device_kp, device_pk) = create_test_keypair(&[42u8; 32]);
        let device_did = ed25519_did(&device_pk);

        let mut att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: CanonicalDid::new_unchecked(issuer_did),
            subject: CanonicalDid::new_unchecked(&device_did),
            device_public_key: Ed25519PublicKey::from_bytes(device_pk).into(),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(fixed_now() + Duration::days(365)),
            timestamp: Some(fixed_now()),
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            supersedes_attestation_rid: None,
            signer_type: None,
            environment_claim: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
        };

        let canonical_bytes = canonicalize_attestation_data(&att.canonical_data()).unwrap();

        // P-256 identity signature over canonical bytes (64 bytes: r||s).
        let p256_sig = RingCryptoProvider::p256_sign(&seed_arr, &canonical_bytes).unwrap();
        // Ed25519Signature holds exactly 64 bytes, matching P-256 r||s.
        assert_eq!(p256_sig.len(), 64);
        att.identity_signature = Ed25519Signature::try_from_slice(&p256_sig).unwrap();

        // Device signature is Ed25519.
        att.device_signature =
            Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();

        let issuer_dpk =
            DevicePublicKey::try_new(auths_crypto::CurveType::P256, &p256_pk_bytes).unwrap();

        let result = test_verifier().verify_with_keys(&att, &issuer_dpk).await;
        assert!(
            result.is_ok(),
            "P-256-signed attestation should verify with a P-256 DevicePublicKey: {:?}",
            result.err()
        );
    }
}
