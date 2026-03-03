//! IXN events for anchoring device attestations in the KEL.
//!
//! Interaction events (IXN) anchor data in the KEL without rotating keys.
//! This creates a cryptographic trust chain linking attestations to the identity.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::signature::Ed25519KeyPair;

use auths_core::crypto::said::compute_said;

use super::event::KeriSequence;
use super::seal::SealType;
use super::types::{Prefix, Said};
use super::{
    Event, GitKel, IxnEvent, KERI_VERSION, KelError, Seal, ValidationError, parse_did_keri,
    validate_kel,
};

/// Error type for anchoring operations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("KEL not found for prefix: {0}")]
    NotFound(String),
}

/// Result of anchor verification.
#[derive(Debug, Clone)]
pub struct AnchorVerification {
    /// Whether the data is anchored in the KEL
    pub anchored: bool,

    /// The SAID of the IXN event containing the anchor (if found)
    pub anchor_said: Option<Said>,

    /// The sequence number of the anchor event (if found)
    pub anchor_sequence: Option<u64>,

    /// The signing key at the time of anchoring (if found)
    pub signing_key: Option<String>,
}

/// Anchor arbitrary data in the KEL via an interaction event.
///
/// This creates an IXN event containing a seal with the data's digest.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `prefix` - The KERI identifier prefix
/// * `data` - The data to anchor (will be serialized to JSON and hashed)
/// * `seal_type` - The type of seal
/// * `current_keypair` - The current signing keypair for this identity
///
/// # Returns
/// * The SAID of the created IXN event
pub fn anchor_data<T: serde::Serialize>(
    repo: &Repository,
    prefix: &Prefix,
    data: &T,
    seal_type: SealType,
    current_keypair: &Ed25519KeyPair,
) -> Result<Said, AnchorError> {
    let kel = GitKel::new(repo, prefix.as_str());
    if !kel.exists() {
        return Err(AnchorError::NotFound(prefix.as_str().to_string()));
    }

    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    // Compute data digest
    let data_json =
        serde_json::to_vec(data).map_err(|e| AnchorError::Serialization(e.to_string()))?;
    let data_digest = compute_said(&data_json);

    // Create seal
    let seal = Seal::new(data_digest, seal_type);

    // Build IXN event
    let new_sequence = state.sequence + 1;
    let mut ixn = IxnEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        a: vec![seal],
        x: String::new(), // Signature added below
    };

    // Compute SAID
    let ixn_json = serde_json::to_vec(&Event::Ixn(ixn.clone()))
        .map_err(|e| AnchorError::Serialization(e.to_string()))?;
    ixn.d = compute_said(&ixn_json);

    // Sign the event with the current key
    let canonical = super::serialize_for_signing(&Event::Ixn(ixn.clone()))?;
    let sig = current_keypair.sign(&canonical);
    ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Append to KEL
    kel.append(&Event::Ixn(ixn.clone()))?;

    Ok(ixn.d)
}

/// Anchor a device attestation in the KEL.
///
/// This is a convenience wrapper for `anchor_data` with the "device-attestation" seal type.
pub fn anchor_attestation<T: serde::Serialize>(
    repo: &Repository,
    prefix: &Prefix,
    attestation: &T,
    current_keypair: &Ed25519KeyPair,
) -> Result<Said, AnchorError> {
    anchor_data(
        repo,
        prefix,
        attestation,
        SealType::DeviceAttestation,
        current_keypair,
    )
}

/// Find the IXN event that anchors a specific data digest.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `prefix` - The KERI identifier prefix
/// * `data_digest` - The SAID of the anchored data
///
/// # Returns
/// * The IXN event if found, None otherwise
pub fn find_anchor_event(
    repo: &Repository,
    prefix: &Prefix,
    data_digest: &str,
) -> Result<Option<IxnEvent>, AnchorError> {
    let kel = GitKel::new(repo, prefix.as_str());
    if !kel.exists() {
        return Err(AnchorError::NotFound(prefix.as_str().to_string()));
    }

    let events = kel.get_events()?;

    for event in events {
        if let Event::Ixn(ixn) = event {
            for seal in &ixn.a {
                if seal.d == data_digest {
                    return Ok(Some(ixn));
                }
            }
        }
    }

    Ok(None)
}

/// Verify that data is properly anchored in a KEL.
///
/// This finds the anchor event and validates the KEL up to that point.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `prefix` - The KERI identifier prefix
/// * `data` - The data to verify anchoring for
///
/// # Returns
/// * `AnchorVerification` with details about the anchor
pub fn verify_anchor<T: serde::Serialize>(
    repo: &Repository,
    prefix: &Prefix,
    data: &T,
) -> Result<AnchorVerification, AnchorError> {
    // Compute data digest
    let data_json =
        serde_json::to_vec(data).map_err(|e| AnchorError::Serialization(e.to_string()))?;
    let data_digest = compute_said(&data_json);

    verify_anchor_by_digest(repo, prefix, data_digest.as_str())
}

/// Verify anchor by digest (when you already have the digest).
pub fn verify_anchor_by_digest(
    repo: &Repository,
    prefix: &Prefix,
    data_digest: &str,
) -> Result<AnchorVerification, AnchorError> {
    let kel = GitKel::new(repo, prefix.as_str());
    if !kel.exists() {
        return Err(AnchorError::NotFound(prefix.as_str().to_string()));
    }

    // Find anchor event
    let anchor = find_anchor_event(repo, prefix, data_digest)?;

    match anchor {
        Some(ixn) => {
            let events = kel.get_events()?;

            let anchor_seq = ixn.s.value();
            let events_subset: Vec<_> = events
                .into_iter()
                .take_while(|e| e.sequence().value() <= anchor_seq)
                .collect();

            let state = validate_kel(&events_subset)?;

            Ok(AnchorVerification {
                anchored: true,
                anchor_said: Some(ixn.d),
                anchor_sequence: Some(anchor_seq),
                signing_key: state.current_key().map(|s| s.to_string()),
            })
        }
        None => Ok(AnchorVerification {
            anchored: false,
            anchor_said: None,
            anchor_sequence: None,
            signing_key: None,
        }),
    }
}

/// Verify that an attestation is properly anchored, extracting the issuer DID.
///
/// This is a convenience function that extracts the issuer from the attestation
/// and verifies the anchor.
pub fn verify_attestation_anchor_by_issuer<T: serde::Serialize>(
    repo: &Repository,
    issuer_did: &str,
    attestation: &T,
) -> Result<AnchorVerification, AnchorError> {
    let prefix: Prefix =
        parse_did_keri(issuer_did).map_err(|e| AnchorError::InvalidDid(e.to_string()))?;
    verify_anchor(repo, &prefix, attestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::{Prefix, create_keri_identity};
    use ring::signature::Ed25519KeyPair as TestKeyPair;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestAttestation {
        issuer: String,
        subject: String,
        capabilities: Vec<String>,
    }

    fn make_test_attestation(issuer: &str, subject: &str) -> TestAttestation {
        TestAttestation {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            capabilities: vec!["sign-commit".to_string()],
        }
    }

    #[test]
    fn anchor_creates_ixn_event() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let attestation = make_test_attestation(&issuer_did, "did:key:device123");
        let anchor_said =
            anchor_attestation(&repo, &init.prefix, &attestation, &current_keypair).unwrap();

        // Verify IXN was created
        let kel = GitKel::new(&repo, init.prefix.as_str());
        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 2); // ICP + IXN

        assert!(events[0].is_inception());
        assert!(events[1].is_interaction());

        if let Event::Ixn(ixn) = &events[1] {
            assert_eq!(ixn.d, anchor_said);
            assert_eq!(ixn.a.len(), 1);
            assert_eq!(ixn.a[0].seal_type, SealType::DeviceAttestation);
        } else {
            panic!("Expected IXN event");
        }
    }

    #[test]
    fn anchor_with_delegation_seal_type() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let data = serde_json::json!({"delegation": "data"});
        let anchor_said = anchor_data(
            &repo,
            &init.prefix,
            &data,
            SealType::Delegation,
            &current_keypair,
        )
        .unwrap();

        let kel = GitKel::new(&repo, init.prefix.as_str());
        let events = kel.get_events().unwrap();

        if let Event::Ixn(ixn) = &events[1] {
            assert_eq!(ixn.d, anchor_said);
            assert_eq!(ixn.a[0].seal_type, SealType::Delegation);
        } else {
            panic!("Expected IXN event");
        }
    }

    #[test]
    fn find_anchor_locates_attestation() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let attestation = make_test_attestation(&issuer_did, "did:key:device123");
        anchor_attestation(&repo, &init.prefix, &attestation, &current_keypair).unwrap();

        // Compute the digest we're looking for
        let att_json = serde_json::to_vec(&attestation).unwrap();
        let att_digest = compute_said(&att_json);

        let found = find_anchor_event(&repo, &init.prefix, att_digest.as_str()).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().a[0].d, att_digest);
    }

    #[test]
    fn verify_anchor_works() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let attestation = make_test_attestation(&issuer_did, "did:key:device123");
        anchor_attestation(&repo, &init.prefix, &attestation, &current_keypair).unwrap();

        let verification = verify_anchor(&repo, &init.prefix, &attestation).unwrap();
        assert!(verification.anchored);
        assert!(verification.anchor_said.is_some());
        assert_eq!(verification.anchor_sequence, Some(1));
        assert!(verification.signing_key.is_some());
    }

    #[test]
    fn unanchored_attestation_not_found() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);

        let attestation = make_test_attestation(&issuer_did, "did:key:device123");
        // Don't anchor it

        let verification = verify_anchor(&repo, &init.prefix, &attestation).unwrap();
        assert!(!verification.anchored);
        assert!(verification.anchor_said.is_none());
    }

    #[test]
    fn multiple_anchors_work() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let att1 = make_test_attestation(&issuer_did, "did:key:device1");
        let att2 = make_test_attestation(&issuer_did, "did:key:device2");

        let said1 = anchor_attestation(&repo, &init.prefix, &att1, &current_keypair).unwrap();
        let said2 = anchor_attestation(&repo, &init.prefix, &att2, &current_keypair).unwrap();

        assert_ne!(said1, said2);

        // Verify both are anchored
        let v1 = verify_anchor(&repo, &init.prefix, &att1).unwrap();
        let v2 = verify_anchor(&repo, &init.prefix, &att2).unwrap();

        assert!(v1.anchored);
        assert!(v2.anchored);
        assert_eq!(v1.anchor_sequence, Some(1));
        assert_eq!(v2.anchor_sequence, Some(2));
    }

    #[test]
    fn verify_by_issuer_did() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let issuer_did = format!("did:keri:{}", init.prefix);
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        let attestation = make_test_attestation(&issuer_did, "did:key:device123");
        anchor_attestation(&repo, &init.prefix, &attestation, &current_keypair).unwrap();

        let verification =
            verify_attestation_anchor_by_issuer(&repo, &issuer_did, &attestation).unwrap();
        assert!(verification.anchored);
    }

    #[test]
    fn anchor_not_found_for_missing_kel() {
        let (_dir, repo) = setup_repo();

        // Create an identity to get a valid keypair (for the signature requirement)
        let init = create_keri_identity(&repo, None).unwrap();
        let current_keypair = TestKeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

        // Try to anchor to a non-existent KEL
        let attestation = make_test_attestation("did:keri:ENotExist", "did:key:device");
        let fake_prefix = Prefix::new_unchecked("ENotExist".to_string());
        let result = anchor_attestation(&repo, &fake_prefix, &attestation, &current_keypair);
        assert!(matches!(result, Err(AnchorError::NotFound(_))));
    }
}
