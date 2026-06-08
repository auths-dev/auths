//! Federation-as-attestor: typed OIDC attestations anchored into the subject's own
//! KEL, read by policy as a deny-capable-but-never-grant-capable signal.

use auths_core::storage::keychain::KeyAlias;
use auths_oidc_port::{JwtValidator, OidcError, OidcValidationConfig};
use auths_policy::decision::Outcome;
use auths_sdk::context::AuthsContext;
use auths_sdk::workflows::federation::{
    AttestationContent, FederationError, GroupId, IdpAttestation, IdpId, LifecycleClaim, Nonce,
    OidcAttestationRequest, SamlAssertion, SamlAssertionVerifier, SamlAttestationRequest,
    attest_oidc, attest_saml, evaluate_idp_signals, verify_oidc_attestation,
    verify_saml_attestation,
};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Duration, Utc};

use crate::cases::helpers::setup_signed_artifact_context;

const ISSUER: &str = "https://acme.okta.com";

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc)
}

/// A `JwtValidator` double that returns preset, already-verified claims — the real
/// signature/issuer/audience/expiry checks are the validator's job and are exercised
/// in `auths-oidc-port`; here we exercise the attestation logic above the port.
struct FakeValidator {
    claims: serde_json::Value,
}

#[async_trait::async_trait]
impl JwtValidator for FakeValidator {
    async fn validate(
        &self,
        _token: &str,
        _config: &OidcValidationConfig,
        _now: DateTime<Utc>,
    ) -> Result<serde_json::Value, OidcError> {
        Ok(self.claims.clone())
    }
}

fn config() -> OidcValidationConfig {
    OidcValidationConfig::builder()
        .issuer(ISSUER)
        .audience("auths")
        .build()
        .expect("config")
}

fn claims(nonce: &str, groups: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "okta-user-1",
        "aud": "auths",
        "nonce": nonce,
        "groups": groups,
    })
}

/// A subject identity with a real KEL to anchor into; returns the alias + DID.
fn subject() -> (tempfile::TempDir, KeyAlias, AuthsContext, IdentityDID) {
    let (tmp, alias, ctx) = setup_signed_artifact_context();
    let managed = ctx
        .identity_storage
        .load_identity()
        .expect("subject identity");
    let did = IdentityDID::new_unchecked(managed.controller_did.as_str().to_string());
    (tmp, alias, ctx, did)
}

fn request(subject: &IdentityDID, claim: LifecycleClaim, nonce: &str) -> OidcAttestationRequest {
    OidcAttestationRequest {
        subject: subject.clone(),
        claim,
        expected_nonce: Nonce::new(nonce).expect("nonce"),
        ttl_secs: 3600,
    }
}

#[tokio::test]
async fn federation_oidc_verifies_and_anchors_into_subject_kel() {
    let (_tmp, alias, ctx, did) = subject();
    let validator = FakeValidator {
        claims: claims("challenge-123", &["engineering"]),
    };
    let req = request(&did, LifecycleClaim::Employed, "challenge-123");

    let attestation = attest_oidc(
        &ctx,
        &validator,
        &config(),
        "id-token",
        &req,
        &alias,
        fixed_now(),
    )
    .await
    .expect("attest + anchor");

    assert_eq!(attestation.content.subject, did);
    assert_eq!(attestation.content.idp.as_str(), ISSUER);
    assert_eq!(attestation.content.claim, LifecycleClaim::Employed);
    assert!(
        attestation.anchored_at_seq >= 1,
        "the attestation is anchored past the inception event in the subject's own KEL"
    );
}

#[tokio::test]
async fn idp_attestation_rejects_nonce_replay() {
    let (_tmp, _alias, _ctx, did) = subject();
    let validator = FakeValidator {
        // Token carries a different nonce than the challenge we expect.
        claims: claims("stale-nonce", &[]),
    };
    let req = request(&did, LifecycleClaim::Employed, "fresh-nonce");

    let result =
        verify_oidc_attestation(&validator, &config(), "id-token", &req, fixed_now()).await;
    assert!(matches!(
        result,
        Err(auths_sdk::workflows::federation::FederationError::NonceMismatch)
    ));
}

#[tokio::test]
async fn idp_attestation_group_member_must_be_present_in_token() {
    let (_tmp, _alias, _ctx, did) = subject();
    let validator = FakeValidator {
        claims: claims("n", &["engineering"]),
    };

    // Group not in the token's groups → rejected, never coerced.
    let missing = request(
        &did,
        LifecycleClaim::GroupMember(GroupId::new("admins").unwrap()),
        "n",
    );
    let err = verify_oidc_attestation(&validator, &config(), "t", &missing, fixed_now())
        .await
        .expect_err("group not present must reject");
    assert!(matches!(
        err,
        auths_sdk::workflows::federation::FederationError::ClaimNotInToken(_)
    ));

    // Group present → ok.
    let present = request(
        &did,
        LifecycleClaim::GroupMember(GroupId::new("engineering").unwrap()),
        "n",
    );
    assert!(
        verify_oidc_attestation(&validator, &config(), "t", &present, fixed_now())
            .await
            .is_ok()
    );
}

/// The load-bearing invariant: an attestation is evidence, never authority. The only
/// thing a signal yields is a `Decision`; `Grant` has no public constructor outside
/// `auths-rp` and nothing here produces one. A positive signal must NOT allow.
#[test]
fn idp_attestation_cannot_grant() {
    let subject = IdentityDID::new_unchecked("did:keri:ESubjectIdpAttestation".to_string());
    let fresh = fixed_now() + Duration::hours(1);
    let base = AttestationContent {
        subject: subject.clone(),
        idp: IdpId::new(ISSUER).unwrap(),
        claim: LifecycleClaim::GroupMember(GroupId::new("admins").unwrap()),
        nonce: Nonce::new("n").unwrap(),
        expires_at: fresh,
    };

    // A maximally-positive signal: corroborating evidence, never an authority grant.
    let positive = IdpAttestation {
        content: base.clone(),
        anchored_at_seq: 1,
    };
    let decision = evaluate_idp_signals(&[positive.as_signal(fixed_now())]);
    assert!(
        !decision.is_allowed(),
        "an IdP attestation must never promote to an authority grant"
    );
    assert_eq!(decision.outcome, Outcome::Indeterminate);

    // A negative lifecycle signal CAN deny — the IdP is authoritative over its own
    // employment/suspension status.
    let suspended = IdpAttestation {
        content: AttestationContent {
            claim: LifecycleClaim::Suspended,
            ..base
        },
        anchored_at_seq: 1,
    };
    let deny = evaluate_idp_signals(&[suspended.as_signal(fixed_now())]);
    assert!(deny.is_denied());
}

#[test]
fn idp_attestation_expired_yields_no_signal_not_valid() {
    let subject = IdentityDID::new_unchecked("did:keri:ESubjectExpired".to_string());
    let expired = IdpAttestation {
        content: AttestationContent {
            subject,
            idp: IdpId::new(ISSUER).unwrap(),
            claim: LifecycleClaim::Employed,
            nonce: Nonce::new("n").unwrap(),
            expires_at: fixed_now() - Duration::hours(1),
        },
        anchored_at_seq: 1,
    };
    let signal = expired.as_signal(fixed_now());
    assert!(
        !signal.fresh,
        "an expired attestation is not a fresh signal"
    );

    let decision = evaluate_idp_signals(&[signal]);
    assert_eq!(
        decision.outcome,
        Outcome::Indeterminate,
        "an expired attestation is 'no signal', never still-valid authority"
    );
}

// ── SAML attestor parity ──

/// A SAML verifier double — the XML-DSig check is the production port's job; this
/// returns a preset, already-verified assertion so the attestation logic above the
/// port is exercised.
struct FakeSamlVerifier {
    assertion: SamlAssertion,
}

#[async_trait::async_trait]
impl SamlAssertionVerifier for FakeSamlVerifier {
    async fn verify(
        &self,
        _response_xml: &[u8],
        _now: DateTime<Utc>,
    ) -> Result<SamlAssertion, FederationError> {
        Ok(self.assertion.clone())
    }
}

fn saml_assertion(
    assertion_id: &str,
    audiences: &[&str],
    groups: &[&str],
    not_on_or_after: Option<DateTime<Utc>>,
) -> SamlAssertion {
    let mut attributes = std::collections::BTreeMap::new();
    if !groups.is_empty() {
        attributes.insert(
            "groups".to_string(),
            groups.iter().map(|g| g.to_string()).collect(),
        );
    }
    SamlAssertion {
        issuer: ISSUER.to_string(),
        name_id: "ad-user-1".to_string(),
        audiences: audiences.iter().map(|a| a.to_string()).collect(),
        not_before: None,
        not_on_or_after,
        assertion_id: assertion_id.to_string(),
        attributes,
    }
}

fn saml_request(subject: &IdentityDID, claim: LifecycleClaim) -> SamlAttestationRequest {
    SamlAttestationRequest {
        subject: subject.clone(),
        claim,
        expected_audience: "auths".to_string(),
        ttl_secs: 3600,
    }
}

#[tokio::test]
async fn saml_attest_anchors_into_subject_kel() {
    let (_tmp, alias, ctx, did) = subject();
    let verifier = FakeSamlVerifier {
        assertion: saml_assertion("ASSERT-1", &["auths"], &["engineering"], None),
    };
    let req = saml_request(&did, LifecycleClaim::Employed);

    let attestation = attest_saml(&ctx, &verifier, b"<saml/>", &req, &alias, fixed_now())
        .await
        .expect("attest + anchor");
    assert_eq!(attestation.content.idp.as_str(), ISSUER);
    assert_eq!(attestation.content.nonce.as_str(), "ASSERT-1");
    assert!(attestation.anchored_at_seq >= 1);
}

#[tokio::test]
async fn saml_rejects_expired_assertion() {
    let did = IdentityDID::new_unchecked("did:keri:ESamlExpired".to_string());
    let verifier = FakeSamlVerifier {
        assertion: saml_assertion(
            "A2",
            &["auths"],
            &[],
            Some(fixed_now() - Duration::hours(1)),
        ),
    };
    let req = saml_request(&did, LifecycleClaim::Employed);
    let err = verify_saml_attestation(&verifier, b"<saml/>", &req, fixed_now())
        .await
        .expect_err("expired assertion must reject");
    assert!(matches!(err, FederationError::TokenInvalid(_)));
}

#[tokio::test]
async fn saml_rejects_audience_mismatch() {
    let did = IdentityDID::new_unchecked("did:keri:ESamlAud".to_string());
    let verifier = FakeSamlVerifier {
        assertion: saml_assertion("A3", &["some-other-sp"], &[], None),
    };
    let req = saml_request(&did, LifecycleClaim::Employed);
    let err = verify_saml_attestation(&verifier, b"<saml/>", &req, fixed_now())
        .await
        .expect_err("audience mismatch must reject");
    assert!(matches!(err, FederationError::ClaimNotInToken(_)));
}

#[tokio::test]
async fn saml_group_member_must_be_present_in_attributes() {
    let did = IdentityDID::new_unchecked("did:keri:ESamlGroup".to_string());

    // Group not present → rejected, never coerced.
    let verifier = FakeSamlVerifier {
        assertion: saml_assertion("A4", &["auths"], &["engineering"], None),
    };
    let missing = saml_request(
        &did,
        LifecycleClaim::GroupMember(GroupId::new("admins").unwrap()),
    );
    assert!(matches!(
        verify_saml_attestation(&verifier, b"<saml/>", &missing, fixed_now()).await,
        Err(FederationError::ClaimNotInToken(_))
    ));

    // Group present → ok.
    let verifier = FakeSamlVerifier {
        assertion: saml_assertion("A5", &["auths"], &["admins"], None),
    };
    let present = saml_request(
        &did,
        LifecycleClaim::GroupMember(GroupId::new("admins").unwrap()),
    );
    assert!(
        verify_saml_attestation(&verifier, b"<saml/>", &present, fixed_now())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn saml_and_oidc_yield_structurally_identical_attestation() {
    let did = IdentityDID::new_unchecked("did:keri:EParitySubject".to_string());
    let shared_nonce = "SHARED-CHALLENGE";

    // OIDC: nonce comes from the id_token's `nonce` claim.
    let oidc_validator = FakeValidator {
        claims: claims(shared_nonce, &[]),
    };
    let oidc_req = request(&did, LifecycleClaim::Employed, shared_nonce);
    let oidc_content =
        verify_oidc_attestation(&oidc_validator, &config(), "t", &oidc_req, fixed_now())
            .await
            .unwrap();

    // SAML: the same fact, where the assertion ID is the anti-replay token (nonce).
    let saml_verifier = FakeSamlVerifier {
        assertion: saml_assertion(shared_nonce, &["auths"], &[], None),
    };
    let saml_req = saml_request(&did, LifecycleClaim::Employed);
    let saml_content = verify_saml_attestation(&saml_verifier, b"<saml/>", &saml_req, fixed_now())
        .await
        .unwrap();

    assert_eq!(
        oidc_content, saml_content,
        "OIDC and SAML must produce structurally identical attestation content for an equivalent fact"
    );

    // And the same deny-capable-not-grant-capable policy treatment.
    let attestation = IdpAttestation {
        content: saml_content,
        anchored_at_seq: 1,
    };
    assert!(!evaluate_idp_signals(&[attestation.as_signal(fixed_now())]).is_allowed());
}

#[tokio::test]
async fn idp_attestation_survives_jwks_rotation() {
    let (_tmp, alias, ctx, did) = subject();
    let validator = FakeValidator {
        claims: claims("n", &[]),
    };
    let req = request(&did, LifecycleClaim::Employed, "n");

    let attestation = attest_oidc(&ctx, &validator, &config(), "t", &req, &alias, fixed_now())
        .await
        .expect("attest");

    // Consume-time evaluation depends only on the anchored attestation's expiry,
    // never on re-validating the JWT — so the IdP rotating its JWKS afterwards does
    // not un-verify a valid past attestation.
    let later = fixed_now() + Duration::minutes(30);
    let signal = attestation.as_signal(later);
    assert!(signal.fresh);
    assert!(!evaluate_idp_signals(&[signal]).is_denied());
}
