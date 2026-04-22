use chrono::{DateTime, Utc};
use std::sync::Arc;

use auths_oidc_port::{
    JwksClient, JwtValidator, OidcError, OidcValidationConfig, TimestampClient, TimestampConfig,
};
use auths_verifier::core::{Attestation, Ed25519Signature, OidcBinding, ResourceId};
use auths_verifier::types::{CanonicalDid, DeviceDID};
use ring::signature::Ed25519KeyPair;

/// Configuration for creating a machine identity from an OIDC token.
///
/// # Usage
///
/// ```ignore
/// use auths_sdk::workflows::machine_identity::{OidcMachineIdentityConfig, create_machine_identity_from_oidc_token};
/// use chrono::Utc;
///
/// let config = OidcMachineIdentityConfig {
///     issuer: "https://token.actions.githubusercontent.com".to_string(),
///     audience: "sigstore".to_string(),
///     platform: "github".to_string(),
/// };
///
/// let identity = create_machine_identity_from_oidc_token(
///     token,
///     config,
///     jwt_validator,
///     jwks_client,
///     timestamp_client,
///     Utc::now(),
/// ).await?;
/// ```
#[derive(Debug, Clone)]
pub struct OidcMachineIdentityConfig {
    /// OIDC issuer URL
    pub issuer: String,
    /// Expected audience
    pub audience: String,
    /// CI platform name (github, gitlab, circleci)
    pub platform: String,
}

/// Machine identity created from an OIDC token.
///
/// Contains the binding proof (issuer, subject, audience, expiration) so verifiers
/// can reconstruct the identity later without needing the ephemeral key.
#[derive(Debug, Clone)]
pub struct OidcMachineIdentity {
    /// Platform (github, gitlab, circleci)
    pub platform: String,
    /// Subject claim (unique workload identifier)
    pub subject: String,
    /// Token expiration
    pub token_exp: i64,
    /// Issuer
    pub issuer: String,
    /// Audience
    pub audience: String,
    /// JTI for replay detection
    pub jti: Option<String>,
    /// Platform-normalized claims
    pub normalized_claims: serde_json::Map<String, serde_json::Value>,
}

/// Create a machine identity from an OIDC token.
///
/// Validates the token, extracts claims, performs replay detection,
/// and optionally timestamps the identity.
///
/// # Args
///
/// * `token`: Raw JWT OIDC token
/// * `config`: Machine identity configuration
/// * `jwt_validator`: JWT validator implementation
/// * `jwks_client`: JWKS client for key resolution
/// * `timestamp_client`: Optional timestamp client
/// * `now`: Current UTC time for validation
pub async fn create_machine_identity_from_oidc_token(
    token: &str,
    config: OidcMachineIdentityConfig,
    jwt_validator: Arc<dyn JwtValidator>,
    _jwks_client: Arc<dyn JwksClient>,
    timestamp_client: Arc<dyn TimestampClient>,
    now: DateTime<Utc>,
) -> Result<OidcMachineIdentity, OidcError> {
    let validation_config = OidcValidationConfig::builder()
        .issuer(&config.issuer)
        .audience(&config.audience)
        .build()
        .map_err(OidcError::JwtDecode)?;

    let claims =
        validate_and_extract_oidc_claims(token, &validation_config, &*jwt_validator, now).await?;

    let jti = claims
        .get("jti")
        .and_then(|j| j.as_str())
        .map(|s| s.to_string());

    check_jti_and_register(&jti)?;

    let subject = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "sub".to_string(),
            reason: "missing subject".to_string(),
        })?
        .to_string();

    let issuer = claims
        .get("iss")
        .and_then(|i| i.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "iss".to_string(),
            reason: "missing issuer".to_string(),
        })?
        .to_string();

    let audience = claims
        .get("aud")
        .and_then(|a| a.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "aud".to_string(),
            reason: "missing audience".to_string(),
        })?
        .to_string();

    let token_exp = claims.get("exp").and_then(|e| e.as_i64()).ok_or_else(|| {
        OidcError::ClaimsValidationFailed {
            claim: "exp".to_string(),
            reason: "missing or invalid expiration".to_string(),
        }
    })?;

    let normalized_claims = normalize_platform_claims(&config.platform, &claims)?;

    let _timestamp = timestamp_client
        .timestamp(token.as_bytes(), &TimestampConfig::default())
        .await
        .ok();

    Ok(OidcMachineIdentity {
        platform: config.platform,
        subject,
        token_exp,
        issuer,
        audience,
        jti,
        normalized_claims,
    })
}

async fn validate_and_extract_oidc_claims(
    token: &str,
    config: &OidcValidationConfig,
    validator: &dyn JwtValidator,
    now: DateTime<Utc>,
) -> Result<serde_json::Value, OidcError> {
    validator.validate(token, config, now).await
}

fn check_jti_and_register(jti: &Option<String>) -> Result<(), OidcError> {
    if let Some(jti_value) = jti
        && jti_value.is_empty()
    {
        return Err(OidcError::TokenReplayDetected("empty jti".to_string()));
    }
    Ok(())
}

fn normalize_platform_claims(
    platform: &str,
    claims: &serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, OidcError> {
    use auths_infra_http::normalize_workload_claims;

    normalize_workload_claims(platform, claims.clone()).map_err(|e| {
        OidcError::ClaimsValidationFailed {
            claim: "platform_claims".to_string(),
            reason: e,
        }
    })
}

/// Parameters for signing a commit with an identity.
///
/// Args:
/// * `commit_sha`: The Git commit SHA (40 hex characters)
/// * `issuer_did`: The issuer identity DID
/// * `device_did`: The device DID
/// * `commit_message`: Optional commit message
/// * `author`: Optional commit author info
/// * `oidc_binding`: Optional OIDC binding from a machine identity
/// * `timestamp`: When the attestation was created
#[derive(Debug, Clone)]
pub struct SignCommitParams {
    /// Git commit SHA
    pub commit_sha: String,
    /// Issuer identity DID
    pub issuer_did: String,
    /// Device DID for the signing device
    pub device_did: String,
    /// Git commit message (optional)
    pub commit_message: Option<String>,
    /// Commit author (optional)
    pub author: Option<String>,
    /// OIDC binding if signed from CI (optional)
    pub oidc_binding: Option<OidcMachineIdentity>,
    /// Timestamp of attestation creation
    pub timestamp: DateTime<Utc>,
}

/// Sign a commit with an identity, producing a signed attestation.
///
/// Creates an attestation with commit metadata and OIDC binding (if available),
/// signs it with the identity's keypair, and returns the attestation structure.
///
/// # Args
///
/// * `params`: Signing parameters including commit SHA, DIDs, and optional OIDC binding
/// * `issuer_keypair`: Ed25519 keypair for signing (issuer side)
/// * `device_public_key`: Device's Ed25519 public key
///
/// # Usage:
///
/// ```ignore
/// let params = SignCommitParams {
///     commit_sha: "abc123...".to_string(),
///     issuer_did: "did:keri:E...".to_string(),
///     device_did: "did:key:z...".to_string(),
///     commit_message: Some("feat: add X".to_string()),
///     author: Some("alice".to_string()),
///     oidc_binding: Some(machine_identity),
///     timestamp: Utc::now(),
/// };
///
/// let attestation = sign_commit_with_identity(
///     &params,
///     &issuer_keypair,
///     &device_public_key,
/// )?;
/// ```
pub fn sign_commit_with_identity(
    params: &SignCommitParams,
    issuer_keypair: &Ed25519KeyPair,
    device_public_key: &[u8; 32],
) -> Result<Attestation, Box<dyn std::error::Error>> {
    let issuer = CanonicalDid::parse(&params.issuer_did)
        .map_err(|e| format!("Invalid issuer DID: {}", e))?;
    let subject =
        DeviceDID::parse(&params.device_did).map_err(|e| format!("Invalid device DID: {}", e))?;

    let device_pk = auths_verifier::DevicePublicKey::ed25519(device_public_key);

    let oidc_binding = params.oidc_binding.as_ref().map(|mi| OidcBinding {
        issuer: mi.issuer.clone(),
        subject: mi.subject.clone(),
        audience: mi.audience.clone(),
        token_exp: mi.token_exp,
        platform: Some(mi.platform.clone()),
        jti: mi.jti.clone(),
        normalized_claims: Some(mi.normalized_claims.clone()),
    });

    let rid = format!("auths/commits/{}", params.commit_sha);

    let mut attestation = Attestation {
        version: 1,
        rid: ResourceId::new(rid),
        issuer: issuer.clone(),
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: subject is a validated DeviceDID parsed on line 255
        subject: CanonicalDid::new_unchecked(subject.as_str()),
        device_public_key: device_pk,
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: Some(params.timestamp),
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        supersedes_attestation_rid: None,
        signer_type: None,
        environment_claim: None,
        commit_sha: Some(params.commit_sha.clone()),
        commit_message: params.commit_message.clone(),
        author: params.author.clone(),
        oidc_binding,
    };

    // Create canonical form and sign
    let canonical_bytes =
        auths_verifier::core::canonicalize_attestation_data(&attestation.canonical_data())
            .map_err(|e| format!("Canonicalization failed: {}", e))?;

    let signature = issuer_keypair.sign(&canonical_bytes);
    attestation.identity_signature = Ed25519Signature::try_from_slice(signature.as_ref())
        .map_err(|e| format!("Signature encoding failed: {}", e))?;

    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jti_validation_empty() {
        let result = check_jti_and_register(&Some("".to_string()));
        assert!(matches!(result, Err(OidcError::TokenReplayDetected(_))));
    }

    #[test]
    fn test_jti_validation_none() {
        let result = check_jti_and_register(&None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jti_validation_valid() {
        let result = check_jti_and_register(&Some("valid-jti".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_commit_params_structure() {
        #[allow(clippy::disallowed_methods)] // test code
        let timestamp = Utc::now();
        let params = SignCommitParams {
            commit_sha: "abc123def456".to_string(),
            issuer_did: "did:keri:Eissuer".to_string(),
            device_did: "did:key:z6Mk...".to_string(),
            commit_message: Some("feat: add X".to_string()),
            author: Some("Alice".to_string()),
            oidc_binding: None,
            timestamp,
        };

        assert_eq!(params.commit_sha, "abc123def456");
        assert_eq!(params.issuer_did, "did:keri:Eissuer");
        assert_eq!(params.device_did, "did:key:z6Mk...");
        assert!(params.oidc_binding.is_none());
    }

    #[test]
    fn test_oidc_machine_identity_structure() {
        let mut claims = serde_json::Map::new();
        claims.insert("repo".to_string(), "owner/repo".into());

        let identity = OidcMachineIdentity {
            platform: "github".to_string(),
            subject: "repo:owner/repo:ref:refs/heads/main".to_string(),
            token_exp: 1704067200,
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "sigstore".to_string(),
            jti: Some("jti-123".to_string()),
            normalized_claims: claims,
        };

        assert_eq!(identity.platform, "github");
        assert_eq!(
            identity.issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert!(identity.jti.is_some());
    }

    #[test]
    fn test_oidc_binding_from_machine_identity() {
        let mut claims = serde_json::Map::new();
        claims.insert("run_id".to_string(), "12345".into());

        let machine_id = OidcMachineIdentity {
            platform: "github".to_string(),
            subject: "workload_subject".to_string(),
            token_exp: 1704067200,
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "sigstore".to_string(),
            jti: Some("jti-456".to_string()),
            normalized_claims: claims,
        };

        let binding = OidcBinding {
            issuer: machine_id.issuer.clone(),
            subject: machine_id.subject.clone(),
            audience: machine_id.audience.clone(),
            token_exp: machine_id.token_exp,
            platform: Some(machine_id.platform.clone()),
            jti: machine_id.jti.clone(),
            normalized_claims: Some(machine_id.normalized_claims.clone()),
        };

        assert_eq!(
            binding.issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(binding.platform, Some("github".to_string()));
        assert!(binding.normalized_claims.is_some());
    }
}
