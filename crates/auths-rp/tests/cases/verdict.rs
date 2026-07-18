use auths_rp::{Denied, VerifiedPrincipal};
use auths_verifier::{
    CanonicalDid, Capability, CredentialVerdict, Freshness, IdentityDID, PresentationVerdict,
};

fn valid_verdict(subject: &str, caps: &[&str]) -> PresentationVerdict {
    PresentationVerdict::Valid {
        issuer: IdentityDID::parse("did:keri:Eissuer").unwrap(),
        subject: CanonicalDid::parse(subject).unwrap(),
        subject_root: CanonicalDid::parse(subject).unwrap(),
        caps: caps.iter().map(|c| Capability::parse(c).unwrap()).collect(),
        role: None,
        expires_at: None,
        freshness: Freshness::Unknown,
        as_of: 0,
    }
}

#[test]
fn valid_verdict_yields_principal_with_subject_and_caps() {
    let principal =
        VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &["acme:read"])).unwrap();
    assert_eq!(principal.subject().as_str(), "did:keri:Eagent");
    assert_eq!(principal.capabilities().len(), 1);
    assert!(
        principal
            .capabilities()
            .contains(&Capability::parse("acme:read").unwrap())
    );
}

#[test]
fn duplicate_caps_in_verdict_collapse_to_one() {
    let principal = VerifiedPrincipal::from_verdict(valid_verdict(
        "did:keri:Eagent",
        &["acme:read", "acme:read"],
    ))
    .unwrap();
    assert_eq!(principal.capabilities().len(), 1);
}

#[test]
fn empty_caps_principal_authenticates_but_authorizes_nothing() {
    let principal = VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &[])).unwrap();
    assert!(principal.capabilities().is_empty());

    let needed = Capability::parse("acme:read").unwrap();
    match principal.authorize(&needed) {
        Err(Denied::MissingCapability { needed: n }) => assert_eq!(n.as_str(), "acme:read"),
        other => panic!("expected MissingCapability, got {other:?}"),
    }
}

#[test]
fn authorize_held_capability_yields_grant_with_subject_and_capability() {
    let principal =
        VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &["acme:read"])).unwrap();
    let grant = principal
        .authorize(&Capability::parse("acme:read").unwrap())
        .unwrap();
    assert_eq!(grant.subject().as_str(), "did:keri:Eagent");
    assert_eq!(grant.exercised().as_str(), "acme:read");
}

#[test]
fn authorize_unheld_capability_is_403() {
    let principal =
        VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &["acme:read"])).unwrap();
    let denied = principal
        .authorize(&Capability::parse("acme:write").unwrap())
        .unwrap_err();
    assert!(matches!(denied, Denied::MissingCapability { .. }));
    assert_eq!(denied.http_status(), 403);
}

#[test]
fn wrong_audience_verdict_maps_to_wrong_audience_denial() {
    assert!(matches!(
        VerifiedPrincipal::from_verdict(PresentationVerdict::WrongAudience),
        Err(Denied::WrongAudience)
    ));
}

#[test]
fn nonce_mismatch_verdict_maps_to_replayed_denial() {
    assert!(matches!(
        VerifiedPrincipal::from_verdict(PresentationVerdict::NonceMismatchOrConsumed),
        Err(Denied::Replayed)
    ));
}

#[test]
fn expired_verdict_maps_to_expired_denial() {
    assert!(matches!(
        VerifiedPrincipal::from_verdict(PresentationVerdict::Expired),
        Err(Denied::Expired)
    ));
}

#[test]
fn holder_not_current_key_verdict_maps_to_not_current_key_denial() {
    assert!(matches!(
        VerifiedPrincipal::from_verdict(PresentationVerdict::HolderNotCurrentKey),
        Err(Denied::NotCurrentKey)
    ));
}

#[test]
fn subject_kel_invalid_verdict_maps_to_subject_kel_invalid_denial() {
    assert!(matches!(
        VerifiedPrincipal::from_verdict(PresentationVerdict::SubjectKelInvalid),
        Err(Denied::SubjectKelInvalid)
    ));
}

#[test]
fn credential_not_valid_verdict_maps_to_credential_invalid_denial() {
    let verdict = PresentationVerdict::CredentialNotValid(CredentialVerdict::SaidMismatch);
    assert!(matches!(
        VerifiedPrincipal::from_verdict(verdict),
        Err(Denied::CredentialInvalid)
    ));
}

#[test]
fn revoked_credential_verdict_also_maps_to_credential_invalid_denial() {
    let verdict = PresentationVerdict::CredentialNotValid(CredentialVerdict::CredentialRevoked {
        revoked_at: 3,
    });
    assert!(matches!(
        VerifiedPrincipal::from_verdict(verdict),
        Err(Denied::CredentialInvalid)
    ));
}

#[test]
fn every_authentication_denial_is_401() {
    let auth_failures = [
        PresentationVerdict::WrongAudience,
        PresentationVerdict::NonceMismatchOrConsumed,
        PresentationVerdict::Expired,
        PresentationVerdict::HolderNotCurrentKey,
        PresentationVerdict::SubjectKelInvalid,
        PresentationVerdict::CredentialNotValid(CredentialVerdict::SaidMismatch),
    ];
    for verdict in auth_failures {
        let denied = VerifiedPrincipal::from_verdict(verdict).unwrap_err();
        assert_eq!(denied.http_status(), 401, "expected 401 for {denied:?}");
    }
}

#[test]
fn missing_capability_is_the_only_403_denial() {
    let denied = Denied::MissingCapability {
        needed: Capability::parse("acme:write").unwrap(),
    };
    assert_eq!(denied.http_status(), 403);
}
