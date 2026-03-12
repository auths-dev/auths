//! OIDC claim types embedded in Auths-issued JWTs.

use serde::{Deserialize, Serialize};

/// RFC 8693 actor claim — identifies the acting party in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// The DID of the acting agent.
    pub sub: String,
    /// Signer type of the actor (auths-specific extension).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<String>,
    /// Nested actor claim for multi-hop delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

/// OIDC claims embedded in Auths-issued JWTs.
///
/// Usage:
/// ```ignore
/// let claims: OidcClaims = serde_json::from_str(&payload)?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Issuer URL.
    pub iss: String,
    /// Subject (KERI DID from the attestation chain root).
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued-at time (Unix timestamp).
    pub iat: u64,
    /// JWT ID (unique per token).
    pub jti: String,
    /// KERI prefix of the root identity.
    pub keri_prefix: String,
    /// Detected target cloud provider (e.g. "aws", "gcp", "azure").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_provider: Option<String>,
    /// Capabilities granted by the attestation chain.
    pub capabilities: Vec<String>,
    /// Witness quorum info (if witnesses were used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_quorum: Option<WitnessQuorumClaim>,
    /// GitHub actor (populated when GitHub OIDC cross-reference succeeds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_actor: Option<String>,
    /// GitHub repository (populated when GitHub OIDC cross-reference succeeds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_repository: Option<String>,
    /// RFC 8693 actor claim — present when attestation chain depth > 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// SPIFFE ID from verified X.509-SVID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// IdP binding data (populated when identity has an enterprise IdP binding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_binding: Option<IdpBindingClaim>,
}

/// IdP binding claim embedded in the JWT when an identity is bound to an enterprise IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpBindingClaim {
    /// IdP issuer URL (e.g. "https://company.okta.com") or SAML entity ID.
    pub idp_issuer: String,
    /// IdP protocol used for the binding.
    pub idp_protocol: String,
    /// IdP-side subject identifier (oid@tid for Entra, sub for others).
    pub subject: String,
    /// Subject email for display/audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_email: Option<String>,
    /// When the IdP authentication occurred (Unix timestamp).
    pub auth_time: u64,
    /// Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_context_class: Option<String>,
}

/// Witness quorum info embedded in the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessQuorumClaim {
    /// Number of witness receipts required.
    pub required: usize,
    /// Number of witness receipts verified.
    pub verified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base_claims() -> OidcClaims {
        OidcClaims {
            iss: "https://auth.example.com".into(),
            sub: "did:keri:ETest".into(),
            aud: "api.example.com".into(),
            exp: 1700000000,
            iat: 1699999000,
            jti: "test-jti".into(),
            keri_prefix: "ETest".into(),
            target_provider: None,
            capabilities: vec!["sign-commit".into()],
            witness_quorum: None,
            github_actor: None,
            github_repository: None,
            act: None,
            spiffe_id: None,
            idp_binding: None,
        }
    }

    #[test]
    fn claims_without_idp_binding_omits_field() {
        let claims = make_base_claims();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("idp_binding"));
    }

    #[test]
    fn claims_without_idp_binding_deserializes_to_none() {
        let json = r#"{
            "iss": "https://auth.example.com",
            "sub": "did:keri:ETest",
            "aud": "api.example.com",
            "exp": 1700000000,
            "iat": 1699999000,
            "jti": "test-jti",
            "keri_prefix": "ETest",
            "capabilities": ["sign-commit"]
        }"#;
        let claims: OidcClaims = serde_json::from_str(json).unwrap();
        assert!(claims.idp_binding.is_none());
    }

    #[test]
    fn claims_with_idp_binding_roundtrips() {
        let mut claims = make_base_claims();
        claims.idp_binding = Some(IdpBindingClaim {
            idp_issuer: "https://company.okta.com".into(),
            idp_protocol: "oidc".into(),
            subject: "alice@company.com".into(),
            subject_email: Some("alice@company.com".into()),
            auth_time: 1699998000,
            auth_context_class: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into(),
            ),
        });

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("idp_binding"));
        assert!(json.contains("company.okta.com"));

        let parsed: OidcClaims = serde_json::from_str(&json).unwrap();
        let binding = parsed.idp_binding.unwrap();
        assert_eq!(binding.idp_issuer, "https://company.okta.com");
        assert_eq!(binding.idp_protocol, "oidc");
        assert_eq!(binding.subject, "alice@company.com");
        assert_eq!(binding.subject_email.as_deref(), Some("alice@company.com"));
        assert_eq!(binding.auth_time, 1699998000);
    }

    #[test]
    fn idp_binding_claim_optional_fields_skipped() {
        let binding = IdpBindingClaim {
            idp_issuer: "https://company.okta.com".into(),
            idp_protocol: "oidc".into(),
            subject: "alice".into(),
            subject_email: None,
            auth_time: 1699998000,
            auth_context_class: None,
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(!json.contains("subject_email"));
        assert!(!json.contains("auth_context_class"));
    }
}
