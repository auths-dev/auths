use async_trait::async_trait;
use chrono::{DateTime, Utc};

use auths_idp::binding::{IdpBindingAttestation, bind_identity_to_idp};
use auths_idp::oidc::IdpVerifier;
use auths_idp::{IdpError, IdpProtocol, VerifiedIdpIdentity};

struct MockIdpVerifier {
    identity: VerifiedIdpIdentity,
}

#[async_trait]
impl IdpVerifier for MockIdpVerifier {
    async fn verify(
        &self,
        _credential: &[u8],
        _now: DateTime<Utc>,
    ) -> Result<VerifiedIdpIdentity, IdpError> {
        Ok(self.identity.clone())
    }

    fn provider_name(&self) -> &str {
        "mock"
    }

    fn protocol(&self) -> IdpProtocol {
        self.identity.idp_protocol
    }
}

struct FailingIdpVerifier;

#[async_trait]
impl IdpVerifier for FailingIdpVerifier {
    async fn verify(
        &self,
        _credential: &[u8],
        _now: DateTime<Utc>,
    ) -> Result<VerifiedIdpIdentity, IdpError> {
        Err(IdpError::TokenInvalid("token expired".to_string()))
    }

    fn provider_name(&self) -> &str {
        "failing-mock"
    }

    fn protocol(&self) -> IdpProtocol {
        IdpProtocol::Oidc
    }
}

#[tokio::test]
async fn test_binding_end_to_end_with_mock_verifier() {
    let now = Utc::now();
    let auth_time = now - chrono::Duration::seconds(60);

    let verifier = MockIdpVerifier {
        identity: VerifiedIdpIdentity {
            idp_issuer: "https://company.okta.com".to_string(),
            idp_protocol: IdpProtocol::Oidc,
            subject: "okta-user-123".to_string(),
            subject_email: Some("user@company.com".to_string()),
            auth_time,
            auth_context_class: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string()),
        },
    };

    let result = bind_identity_to_idp(&verifier, b"mock-credential", "did:keri:Eabc123def456", now)
        .await
        .unwrap();

    assert_eq!(result.attestation.version, 1);
    assert_eq!(result.attestation.idp_issuer, "https://company.okta.com");
    assert_eq!(result.attestation.idp_protocol, IdpProtocol::Oidc);
    assert_eq!(result.attestation.subject, "okta-user-123");
    assert_eq!(
        result.attestation.subject_email.as_deref(),
        Some("user@company.com")
    );
    assert_eq!(result.attestation.bound_did, "did:keri:Eabc123def456");
    assert_eq!(result.attestation.timestamp, now);

    assert!(!result.canonical_bytes.is_empty());
}

#[tokio::test]
async fn test_binding_serialization_roundtrip() {
    let now = Utc::now();

    let attestation = IdpBindingAttestation {
        version: 1,
        idp_issuer: "https://login.microsoftonline.com/tenant/v2.0".to_string(),
        idp_protocol: IdpProtocol::Oidc,
        subject: "oid-123@tid-456".to_string(),
        subject_email: Some("user@company.onmicrosoft.com".to_string()),
        auth_time: now,
        auth_context_class: None,
        bound_did: "did:keri:Exyz789".to_string(),
        timestamp: now,
    };

    let json = serde_json::to_string(&attestation).unwrap();
    let deserialized: IdpBindingAttestation = serde_json::from_str(&json).unwrap();

    assert_eq!(attestation, deserialized);
}

#[tokio::test]
async fn test_binding_canonicalization_is_deterministic() {
    let now = Utc::now();

    let attestation = IdpBindingAttestation {
        version: 1,
        idp_issuer: "https://accounts.google.com".to_string(),
        idp_protocol: IdpProtocol::Oidc,
        subject: "123456789".to_string(),
        subject_email: Some("user@company.com".to_string()),
        auth_time: now,
        auth_context_class: Some("urn:mace:incommon:iap:silver".to_string()),
        bound_did: "did:keri:Etest".to_string(),
        timestamp: now,
    };

    let canonical1 = attestation.canonicalize().unwrap();
    let canonical2 = attestation.canonicalize().unwrap();
    assert_eq!(canonical1, canonical2);
}

#[tokio::test]
async fn test_binding_with_expired_credential_is_rejected() {
    let now = Utc::now();
    let verifier = FailingIdpVerifier;

    let result = bind_identity_to_idp(&verifier, b"expired-credential", "did:keri:Eabc", now).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}
