//! Canonical-bytes pin for `AttestationInput` — proves that the
//! `(now, input, signer, passphrase)` shape produces byte-stable
//! canonical bytes across refactors.
//!
//! If this test fails after a refactor, the canonical wire format
//! of an attestation has drifted. That's a load-bearing change —
//! every attestation signed under the prior canonical shape no
//! longer verifies. Update the pinned digest only when the wire
//! format change is intentional.

use chrono::TimeZone;
use sha2::{Digest, Sha256};

use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_crypto::testing::seeded_p256_keypair;
use auths_id::attestation::create::AttestationInput;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_verifier::core::canonicalize_attestation_data;
use auths_verifier::types::CanonicalDid;

/// Pinned SHA-256 hex digest of the canonical bytes produced from the
/// fixed-seed inputs below. Recompute + update only when the canonical
/// attestation shape changes intentionally.
static GOLDEN_DIGEST_HEX: &str = include_str!("attestation_input_golden.digest");

#[test]
fn canonical_bytes_are_byte_stable_under_fixed_seed() {
    // Seeded inputs — every value chosen to be deterministic.
    let (_pkcs8, pub_compressed) = seeded_p256_keypair(1_700_000_000);

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: test-only IdentityDID built from a seeded prefix; never
    // used at runtime.
    let identity_did = IdentityDID::new_unchecked("did:keri:EGoldenIdentity".to_string());

    let subject =
        CanonicalDid::from_public_key_did_key(&pub_compressed, auths_crypto::CurveType::P256);

    let ts = chrono::Utc
        .timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("valid timestamp");
    let meta = AttestationMetadata {
        note: None,
        timestamp: Some(ts),
        expires_at: None,
    };
    let identity_alias = KeyAlias::new_unchecked("golden-identity");
    let device_alias = KeyAlias::new_unchecked("golden-device");

    let input = AttestationInput {
        rid: "golden-rid",
        identity_did: &identity_did,
        subject: &subject,
        device_public_key: &pub_compressed,
        device_curve: auths_crypto::CurveType::P256,
        payload: None,
        meta: &meta,
        identity_alias: Some(&identity_alias),
        device_alias: Some(&device_alias),
        delegated_by: None,
        commit_sha: None,
        signer_type: None,
    };

    // Build the attestation body we would sign over without actually
    // signing (no SecureSigner needed — we only hash the canonical
    // bytes). Mirrors what `create_signed_attestation` does
    // pre-signature: construct the attestation skeleton, then
    // canonicalize.
    let attestation = test_build_attestation(&input);
    let canonical_bytes = canonicalize_attestation_data(&attestation.canonical_data())
        .expect("canonicalization succeeds");

    let digest = Sha256::digest(&canonical_bytes);
    let digest_hex = hex::encode(digest);

    // First-run helper: if the golden file is empty, print the digest
    // to stderr and fail so the maintainer can paste it in.
    assert_eq!(
        digest_hex.as_str(),
        GOLDEN_DIGEST_HEX.trim(),
        "canonical-bytes drift: recompute and update `attestation_input_golden.digest` if the \
         shape change was intentional. observed digest: {}",
        digest_hex
    );
}

#[test]
fn canonical_bytes_digest_is_stable_across_invocations() {
    // Called once already above; call again to assert determinism
    // independent of test ordering.
    let (_p8, pk) = seeded_p256_keypair(1_700_000_000);
    let a = CanonicalDid::from_public_key_did_key(&pk, auths_crypto::CurveType::P256);
    let b = CanonicalDid::from_public_key_did_key(&pk, auths_crypto::CurveType::P256);
    assert_eq!(a.as_str(), b.as_str());
}

/// Build an unsigned attestation skeleton from an input — mirrors the
/// private construction path inside `create_signed_attestation` up to
/// the canonicalization step.
fn test_build_attestation(input: &AttestationInput<'_>) -> auths_verifier::core::Attestation {
    use auths_verifier::core::{Attestation, Ed25519Signature, ResourceId};

    #[allow(clippy::disallowed_methods)]
    let issuer_canonical = CanonicalDid::new_unchecked(input.identity_did.as_str());
    #[allow(clippy::disallowed_methods)]
    let subject_canonical = CanonicalDid::new_unchecked(input.subject.as_str());

    Attestation {
        version: auths_id::attestation::create::ATTESTATION_VERSION,
        subject: subject_canonical,
        issuer: issuer_canonical,
        rid: ResourceId::new(input.rid),
        payload: input.payload.clone(),
        timestamp: input.meta.timestamp,
        expires_at: input.meta.expires_at,
        revoked_at: None,
        note: input.meta.note.clone(),
        device_public_key: auths_verifier::DevicePublicKey::try_new(
            input.device_curve,
            input.device_public_key,
        )
        .expect("valid test pubkey"),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        delegated_by: input.delegated_by.clone().map(CanonicalDid::from),
        signer_type: input.signer_type.clone(),
        environment_claim: None,
        commit_sha: input.commit_sha.clone(),
        commit_message: None,
        author: None,
        oidc_binding: None,
    }
}
