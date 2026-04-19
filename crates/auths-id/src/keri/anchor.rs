//! IXN-based anchoring for trust-affecting attestations in the KEL.
//!
//! All trust-affecting flows (device-link, device-revoke, org-membership,
//! artifact signing) use [`anchor_and_persist`] or [`anchor_and_persist_via_backend`].
//! There is one anchoring path — no per-operation wrappers.

use git2::Repository;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_keri::compute_said;

use super::event::{KeriSequence, VersionString};
use super::types::{Prefix, Said};
use super::{
    Event, GitKel, IxnEvent, KelError, Seal, ValidationError, parse_did_keri,
    serialize_for_signing, validate_kel,
};

/// Error type for anchoring operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Identity cannot emit interaction events: {0}")]
    IxnForbidden(String),
}

impl auths_core::error::AuthsErrorInfo for AnchorError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Kel(_) => "AUTHS-E4961",
            Self::Validation(_) => "AUTHS-E4962",
            Self::Serialization(_) => "AUTHS-E4963",
            Self::InvalidDid(_) => "AUTHS-E4964",
            Self::NotFound(_) => "AUTHS-E4965",
            Self::Signing(_) => "AUTHS-E4966",
            Self::IxnForbidden(_) => "AUTHS-E4967",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidDid(_) => Some("Use the format 'did:keri:E<prefix>'"),
            Self::NotFound(_) => Some("Initialize the identity first with 'auths init'"),
            Self::Signing(_) => {
                Some("Check that the key alias exists and the passphrase is correct")
            }
            Self::IxnForbidden(_) => Some(
                "Device authorization requires a transferable identity (non-empty n[]) without \
                 establishment-only restriction (no EO in c[]). Create a new identity with auths init.",
            ),
            _ => None,
        }
    }
}

pub use auths_keri::AnchorStatus;

/// Result of anchor verification.
#[derive(Debug, Clone)]
pub struct AnchorVerification {
    /// Whether and how the data is anchored in the KEL.
    pub status: AnchorStatus,

    /// The SAID of the IXN event containing the anchor (if found)
    pub anchor_said: Option<Said>,

    /// The sequence number of the anchor event (if found)
    pub anchor_sequence: Option<u128>,

    /// The signing key at the time of anchoring (if found)
    pub signing_key: Option<String>,
}

fn ixn_forbidden_reason(state: &auths_keri::KeyState) -> String {
    if state.is_non_transferable {
        "non-transferable identity (empty n[] at inception)".to_string()
    } else {
        "establishment-only identity (EO in c[])".to_string()
    }
}

fn build_anchor_ixn(
    attestation_said: &Said,
    controller_prefix: &Prefix,
    state: &auths_keri::KeyState,
) -> Result<IxnEvent, AnchorError> {
    let seal = Seal::digest(attestation_said.as_str());
    let ixn = IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: controller_prefix.clone(),
        s: KeriSequence::new(state.sequence + 1),
        p: state.last_event_said.clone(),
        a: vec![seal],
    };
    auths_keri::finalize_ixn_event(ixn).map_err(AnchorError::from)
}

fn canonicalize_and_said<T: serde::Serialize>(data: &T) -> Result<Said, AnchorError> {
    let canonical =
        json_canon::to_string(data).map_err(|e| AnchorError::Serialization(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(&canonical).map_err(|e| AnchorError::Serialization(e.to_string()))?;
    compute_said(&value).map_err(|e| AnchorError::Serialization(e.to_string()))
}

fn sign_ixn(
    ixn: &IxnEvent,
    signer: &dyn SecureSigner,
    signer_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<Vec<u8>, AnchorError> {
    let canonical_event = serialize_for_signing(&Event::Ixn(ixn.clone()))?;
    signer
        .sign_with_alias(signer_alias, passphrase_provider, &canonical_event)
        .map_err(|e| AnchorError::Signing(e.to_string()))
}

// ── GitKel-based (unit tests, direct git access) ─────────────────────────────

/// Anchor an attestation in the KEL via an ixn seal (GitKel storage).
///
/// # Returns
/// * `(attestation_said, finalized_ixn)` — the attestation SAID and the appended IXN event
#[allow(clippy::too_many_arguments)]
pub fn anchor_and_persist<T: serde::Serialize>(
    kel: &GitKel,
    signer: &dyn SecureSigner,
    signer_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    controller_prefix: &Prefix,
    attestation: &T,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(Said, IxnEvent), AnchorError> {
    if !kel.exists() {
        return Err(AnchorError::NotFound(
            controller_prefix.as_str().to_string(),
        ));
    }

    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    if !state.can_emit_ixn() {
        return Err(AnchorError::IxnForbidden(ixn_forbidden_reason(&state)));
    }

    let attestation_said = canonicalize_and_said(attestation)?;
    let ixn = build_anchor_ixn(&attestation_said, controller_prefix, &state)?;
    let _sig = sign_ixn(&ixn, signer, signer_alias, passphrase_provider)?;

    kel.append(&Event::Ixn(ixn.clone()), now)?;

    Ok((attestation_said, ixn))
}

// ── RegistryBackend-based (SDK orchestration) ────────────────────────────────

/// Stage an ixn anchor seal in the batch WITHOUT committing.
///
/// The caller is responsible for calling `backend.commit_batch(batch)` after
/// this function returns. This separation ensures the caller can always commit
/// the batch (deterministic) regardless of whether the ixn was successfully
/// staged.
#[allow(clippy::too_many_arguments)]
pub fn try_stage_anchor<T: serde::Serialize>(
    backend: &dyn crate::storage::registry::backend::RegistryBackend,
    signer: &dyn SecureSigner,
    signer_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    controller_prefix: &Prefix,
    attestation: &T,
    batch: &mut crate::storage::registry::backend::AtomicWriteBatch,
) -> Result<(Said, IxnEvent), AnchorError> {
    let state = backend
        .get_key_state(controller_prefix)
        .map_err(|e| AnchorError::NotFound(e.to_string()))?;

    if !state.can_emit_ixn() {
        return Err(AnchorError::IxnForbidden(ixn_forbidden_reason(&state)));
    }

    let attestation_said = canonicalize_and_said(attestation)?;
    let ixn = build_anchor_ixn(&attestation_said, controller_prefix, &state)?;
    let _sig = sign_ixn(&ixn, signer, signer_alias, passphrase_provider)?;

    batch.stage_event(controller_prefix.clone(), Event::Ixn(ixn.clone()));

    Ok((attestation_said, ixn))
}

/// Convenience: stage anchor + commit batch atomically.
#[allow(clippy::too_many_arguments)]
pub fn anchor_and_persist_via_backend<T: serde::Serialize>(
    backend: &dyn crate::storage::registry::backend::RegistryBackend,
    signer: &dyn SecureSigner,
    signer_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    controller_prefix: &Prefix,
    attestation: &T,
    batch: &mut crate::storage::registry::backend::AtomicWriteBatch,
) -> Result<(Said, IxnEvent), AnchorError> {
    let result = try_stage_anchor(
        backend,
        signer,
        signer_alias,
        passphrase_provider,
        controller_prefix,
        attestation,
        batch,
    )?;

    backend
        .commit_batch(batch)
        .map_err(|e| AnchorError::Kel(KelError::Serialization(e.to_string())))?;

    Ok(result)
}

// ── KEL walk ─────────────────────────────────────────────────────────────────

/// Collect all digest SAIDs anchored in the KEL up to (and including) `at_seq`.
///
/// Walks the KEL and extracts every digest seal from ixn events. Returns
/// `(sequence, said)` pairs in event order. Callers resolve the SAIDs to
/// attestation blobs to determine which devices are authorized.
pub fn resolve_anchored_saids_via_backend(
    backend: &dyn crate::storage::registry::backend::RegistryBackend,
    controller_prefix: &Prefix,
    at_seq: Option<u128>,
) -> Result<Vec<(u128, Said)>, AnchorError> {
    let mut results = Vec::new();
    backend
        .visit_events(controller_prefix, 0, &mut |event| {
            if let Some(max) = at_seq
                && event.sequence().value() > max
            {
                return std::ops::ControlFlow::Break(());
            }
            if let Event::Ixn(ixn) = event {
                for seal in &ixn.a {
                    if let Some(digest) = seal.digest_value() {
                        results.push((ixn.s.value(), digest.clone()));
                    }
                }
            }
            std::ops::ControlFlow::Continue(())
        })
        .map_err(|e| AnchorError::NotFound(e.to_string()))?;

    Ok(results)
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Find the IXN event that anchors a specific data digest.
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
                if seal.digest_value().map(|d| d.as_str()) == Some(data_digest) {
                    return Ok(Some(ixn));
                }
            }
        }
    }

    Ok(None)
}

/// Verify that data is properly anchored in a KEL.
pub fn verify_anchor<T: serde::Serialize>(
    repo: &Repository,
    prefix: &Prefix,
    data: &T,
) -> Result<AnchorVerification, AnchorError> {
    let data_digest = canonicalize_and_said(data)?;
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
                status: AnchorStatus::Anchored,
                anchor_said: Some(ixn.d),
                anchor_sequence: Some(anchor_seq),
                signing_key: state.current_key().map(|s| s.to_string()),
            })
        }
        None => Ok(AnchorVerification {
            status: AnchorStatus::NotAnchored,
            anchor_said: None,
            anchor_sequence: None,
            signing_key: None,
        }),
    }
}

/// Verify that an attestation is properly anchored, extracting the issuer DID.
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
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{Prefix, create_keri_identity_with_curve};
    use auths_core::crypto::signer::encrypt_keypair;
    use auths_core::signing::StorageSigner;
    use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
    use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    const TEST_PASSPHRASE: &str = "Test-passphrase1!";

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

    struct TestSetup {
        _dir: TempDir,
        repo: Repository,
        prefix: Prefix,
        issuer_did: String,
        signer: StorageSigner<IsolatedKeychainHandle>,
        alias: KeyAlias,
        provider: TestPassphraseProvider,
    }

    fn setup_identity() -> TestSetup {
        let (dir, repo) = setup_repo();
        let keychain = IsolatedKeychainHandle::new();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::default(),
        )
        .unwrap();

        let issuer_did = format!("did:keri:{}", init.prefix);
        let alias = KeyAlias::new_unchecked("test-anchor-key");
        let identity_did = IdentityDID::new_unchecked(&issuer_did);

        let encrypted = encrypt_keypair(init.current_keypair_pkcs8.as_ref(), TEST_PASSPHRASE)
            .expect("encrypt keypair");
        keychain
            .store_key(&alias, &identity_did, KeyRole::Primary, &encrypted)
            .expect("store key");

        let signer = StorageSigner::new(keychain);
        let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

        TestSetup {
            _dir: dir,
            repo,
            prefix: init.prefix,
            issuer_did,
            signer,
            alias,
            provider,
        }
    }

    fn anchor(s: &TestSetup, attestation: &TestAttestation) -> (Said, IxnEvent) {
        let kel = GitKel::new(&s.repo, s.prefix.as_str());
        anchor_and_persist(
            &kel,
            &s.signer,
            &s.alias,
            &s.provider,
            &s.prefix,
            attestation,
            chrono::Utc::now(),
        )
        .unwrap()
    }

    #[test]
    fn creates_ixn_event() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");
        let (att_said, ixn) = anchor(&s, &att);

        let kel = GitKel::new(&s.repo, s.prefix.as_str());
        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].is_inception());
        assert!(events[1].is_interaction());

        assert_eq!(ixn.a.len(), 1);
        assert_eq!(ixn.a[0].digest_value().unwrap(), &att_said);
        assert_ne!(ixn.d, Said::default());
    }

    #[test]
    fn find_anchor_locates_attestation() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");
        let (att_said, _) = anchor(&s, &att);

        let found = find_anchor_event(&s.repo, &s.prefix, att_said.as_str()).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().a[0].digest_value().unwrap(), &att_said);
    }

    #[test]
    fn verify_anchor_works() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");
        anchor(&s, &att);

        let verification = verify_anchor(&s.repo, &s.prefix, &att).unwrap();
        assert_eq!(verification.status, AnchorStatus::Anchored);
        assert!(verification.anchor_said.is_some());
        assert_eq!(verification.anchor_sequence, Some(1));
        assert!(verification.signing_key.is_some());
    }

    #[test]
    fn unanchored_attestation_not_found() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");

        let verification = verify_anchor(&s.repo, &s.prefix, &att).unwrap();
        assert_eq!(verification.status, AnchorStatus::NotAnchored);
        assert!(verification.anchor_said.is_none());
    }

    #[test]
    fn multiple_anchors_work() {
        let s = setup_identity();
        let att1 = make_test_attestation(&s.issuer_did, "did:key:device1");
        let att2 = make_test_attestation(&s.issuer_did, "did:key:device2");

        let (said1, _) = anchor(&s, &att1);
        let (said2, _) = anchor(&s, &att2);
        assert_ne!(said1, said2);

        let v1 = verify_anchor(&s.repo, &s.prefix, &att1).unwrap();
        let v2 = verify_anchor(&s.repo, &s.prefix, &att2).unwrap();
        assert_eq!(v1.status, AnchorStatus::Anchored);
        assert_eq!(v2.status, AnchorStatus::Anchored);
        assert_eq!(v1.anchor_sequence, Some(1));
        assert_eq!(v2.anchor_sequence, Some(2));
    }

    #[test]
    fn verify_by_issuer_did() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");
        anchor(&s, &att);

        let verification =
            verify_attestation_anchor_by_issuer(&s.repo, &s.issuer_did, &att).unwrap();
        assert_eq!(verification.status, AnchorStatus::Anchored);
    }

    #[test]
    fn anchor_not_found_for_missing_kel() {
        let s = setup_identity();
        let att = make_test_attestation("did:keri:ENotExist", "did:key:device");
        let fake_prefix = Prefix::new_unchecked("ENotExist".to_string());
        let kel = GitKel::new(&s.repo, fake_prefix.as_str());
        let result = anchor_and_persist(
            &kel,
            &s.signer,
            &s.alias,
            &s.provider,
            &fake_prefix,
            &att,
            chrono::Utc::now(),
        );
        assert!(matches!(result, Err(AnchorError::NotFound(_))));
    }

    #[test]
    fn canonical_said_is_deterministic() {
        let s = setup_identity();
        let att = make_test_attestation(&s.issuer_did, "did:key:device123");

        let kel = GitKel::new(&s.repo, s.prefix.as_str());
        let (att_said, _) = anchor_and_persist(
            &kel,
            &s.signer,
            &s.alias,
            &s.provider,
            &s.prefix,
            &att,
            chrono::Utc::now(),
        )
        .unwrap();

        let canonical = json_canon::to_string(&att).unwrap();
        let canonical_value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let expected_said = compute_said(&canonical_value).unwrap();
        assert_eq!(att_said, expected_said);
    }
}
