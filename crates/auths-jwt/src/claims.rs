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
}

/// Witness quorum info embedded in the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessQuorumClaim {
    /// Number of witness receipts required.
    pub required: usize,
    /// Number of witness receipts verified.
    pub verified: usize,
}
