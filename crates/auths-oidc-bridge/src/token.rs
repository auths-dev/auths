//! Token types: claims, exchange request, and response.

use auths_verifier::core::Attestation;
use auths_verifier::witness::WitnessReceipt;
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

/// OIDC claims embedded in the issued JWT.
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
}

/// Witness quorum info embedded in the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessQuorumClaim {
    pub required: usize,
    pub verified: usize,
}

/// Request body for the `/token` endpoint.
#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    /// Ordered attestation chain (root to leaf).
    pub attestation_chain: Vec<Attestation>,
    /// Hex-encoded Ed25519 public key of the root identity.
    pub root_public_key: String,
    /// Override the default audience.
    #[serde(default)]
    pub audience: Option<String>,
    /// Override the default TTL (in seconds).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Request a subset of the chain-granted capabilities (scope-down).
    #[serde(default)]
    pub requested_capabilities: Option<Vec<String>>,
    /// Witness receipts for chain verification.
    #[serde(default)]
    pub witness_receipts: Option<Vec<WitnessReceipt>>,
    /// Witness public keys: list of (DID, hex-encoded public key) pairs.
    #[serde(default)]
    pub witness_keys: Option<Vec<WitnessKeyEntry>>,
    /// Minimum witness threshold.
    #[serde(default)]
    pub witness_threshold: Option<usize>,
    /// OIDC provider issuer URL for trust registry lookup.
    #[cfg(feature = "oidc-trust")]
    #[serde(default)]
    pub provider_issuer: Option<String>,
    /// Repository identifier for trust registry repo matching.
    #[cfg(feature = "oidc-trust")]
    #[serde(default)]
    pub repository: Option<String>,
    /// Optional GitHub Actions OIDC token for cross-referencing.
    #[cfg(feature = "github-oidc")]
    #[serde(default)]
    pub github_oidc_token: Option<String>,
    /// Expected GitHub actor for cross-reference validation.
    #[cfg(feature = "github-oidc")]
    #[serde(default)]
    pub github_actor: Option<String>,
}

/// A witness key entry in the exchange request.
#[derive(Debug, Deserialize)]
pub struct WitnessKeyEntry {
    pub did: String,
    pub public_key_hex: String,
}

/// Response body from the `/token` endpoint.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The issued JWT.
    pub access_token: String,
    /// Always "Bearer".
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// The subject DID.
    pub subject: String,
}

/// RFC 8693 token exchange request (form-encoded).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(default)]
    pub actor_token: Option<String>,
    #[serde(default)]
    pub actor_token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// RFC 8693 token exchange response.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// RFC 6749 error response for the token exchange endpoint.
#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// Extract the KERI prefix from an issuer DID string.
///
/// `did:keri:EAbcdef...` -> `EAbcdef...`
pub fn extract_keri_prefix(issuer_did: &str) -> String {
    issuer_did
        .strip_prefix("did:keri:")
        .unwrap_or(issuer_did)
        .to_string()
}

/// Build an `ActorClaim` from an attestation chain.
///
/// Args:
/// * `chain`: Ordered attestation chain (root to leaf).
///
/// Usage:
/// ```ignore
/// let act = build_act_claim(&chain);
/// ```
pub fn build_act_claim(chain: &[Attestation]) -> Option<ActorClaim> {
    if chain.len() <= 1 {
        return None;
    }

    let leaf = chain.last()?;
    let leaf_did = leaf.subject.to_string();
    let signer_type = leaf.signer_type.as_ref().map(|s| format!("{s:?}"));

    let mut nested: Option<ActorClaim> = None;
    for att in chain[1..chain.len() - 1].iter().rev() {
        nested = Some(ActorClaim {
            sub: att.subject.to_string(),
            signer_type: att.signer_type.as_ref().map(|s| format!("{s:?}")),
            act: nested.map(Box::new),
        });
    }

    Some(ActorClaim {
        sub: leaf_did,
        signer_type,
        act: nested.map(Box::new),
    })
}
