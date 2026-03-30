use auths_core::crypto::provider_bridge;
use auths_core::crypto::ssh::SecureSeed;
use auths_core::error::AuthsErrorInfo;
use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use auths_policy::approval::ApprovalAttestation;
use auths_policy::types::{CanonicalCapability, CanonicalDid};

// ── Auth Challenge Signing ────────────────────────────────────────────────────

/// Result of signing an authentication challenge.
///
/// Args:
/// * `signature_hex`: Hex-encoded Ed25519 signature over the canonical payload.
/// * `public_key_hex`: Hex-encoded Ed25519 public key.
/// * `did`: The identity's DID (e.g. `"did:keri:EPREFIX"`).
///
/// Usage:
/// ```ignore
/// let result = sign_auth_challenge("abc123", "auths.dev", &seed, "deadbeef...", "did:keri:E...")?;
/// println!("Signature: {}", result.signature_hex);
/// ```
#[derive(Debug, Clone)]
pub struct SignedAuthChallenge {
    /// Hex-encoded Ed25519 signature over the canonical JSON payload.
    pub signature_hex: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key_hex: String,
    /// The signer's identity DID (e.g. `"did:keri:EPREFIX"`).
    pub did: String,
}

/// Errors from the auth challenge signing workflow.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthChallengeError {
    /// The nonce was empty.
    #[error("nonce must not be empty")]
    EmptyNonce,

    /// The domain was empty.
    #[error("domain must not be empty")]
    EmptyDomain,

    /// Canonical JSON serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(String),

    /// The Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

impl AuthsErrorInfo for AuthChallengeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyNonce => "AUTHS-E6001",
            Self::EmptyDomain => "AUTHS-E6002",
            Self::Canonicalization(_) => "AUTHS-E6003",
            Self::SigningFailed(_) => "AUTHS-E6004",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::EmptyNonce => Some("Provide the nonce from the authentication challenge"),
            Self::EmptyDomain => Some("Provide the domain (e.g. auths.dev)"),
            Self::Canonicalization(_) => {
                Some("This is an internal error; please report it as a bug")
            }
            Self::SigningFailed(_) => {
                Some("Check that your identity key is accessible with `auths key list`")
            }
        }
    }
}

/// Signs an authentication challenge for DID-based login.
///
/// Constructs a canonical JSON payload `{"domain":"...","nonce":"..."}` and signs
/// it with Ed25519. The output matches the auth-server's expected `VerifyRequest` format.
///
/// Args:
/// * `nonce`: The challenge nonce from the authentication server.
/// * `domain`: The domain requesting authentication (e.g. `"auths.dev"`).
/// * `seed`: The Ed25519 signing seed.
/// * `public_key_hex`: Hex-encoded Ed25519 public key of the signer.
/// * `did`: The signer's identity DID.
///
/// Usage:
/// ```ignore
/// let result = sign_auth_challenge("abc123", "auths.dev", &seed, "deadbeef...", "did:keri:E...")?;
/// ```
pub fn sign_auth_challenge(
    nonce: &str,
    domain: &str,
    seed: &SecureSeed,
    public_key_hex: &str,
    did: &str,
) -> Result<SignedAuthChallenge, AuthChallengeError> {
    if nonce.is_empty() {
        return Err(AuthChallengeError::EmptyNonce);
    }
    if domain.is_empty() {
        return Err(AuthChallengeError::EmptyDomain);
    }

    let payload = serde_json::json!({
        "domain": domain,
        "nonce": nonce,
    });
    let canonical = json_canon::to_string(&payload)
        .map_err(|e| AuthChallengeError::Canonicalization(e.to_string()))?;

    let signature_bytes = provider_bridge::sign_ed25519_sync(seed, canonical.as_bytes())
        .map_err(|e| AuthChallengeError::SigningFailed(e.to_string()))?;

    Ok(SignedAuthChallenge {
        signature_hex: hex::encode(&signature_bytes),
        public_key_hex: public_key_hex.to_string(),
        did: did.to_string(),
    })
}

// ── Approval Workflow ─────────────────────────────────────────────────────────

/// Config for granting an approval.
pub struct GrantApprovalConfig {
    /// Hex-encoded hash of the pending request.
    pub request_hash: String,
    /// DID of the approver.
    pub approver_did: String,
    /// Optional note for the approval.
    pub note: Option<String>,
}

/// Config for listing pending approvals.
pub struct ListApprovalsConfig {
    /// Path to the repository.
    pub repo_path: std::path::PathBuf,
}

/// Result of granting an approval.
pub struct GrantApprovalResult {
    /// The request hash that was approved.
    pub request_hash: String,
    /// DID of the approver.
    pub approver_did: String,
    /// The unique JTI for this approval.
    pub jti: String,
    /// When the approval expires.
    pub expires_at: DateTime<Utc>,
    /// Human-readable summary of what was approved.
    pub context_summary: String,
}

/// Errors from approval workflow execution.
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// The request was not found in the registry.
    #[error("request not found: {hash}")]
    RequestNotFound { hash: String },

    /// The request has already expired.
    #[error("request expired at {expires_at}")]
    RequestExpired { expires_at: DateTime<Utc> },
}

/// Build an approval attestation from a pending request (pure function).
///
/// Args:
/// * `request_hash_hex`: Hex-encoded request hash.
/// * `approver_did`: DID of the human approver.
/// * `capabilities`: Capabilities being approved.
/// * `now`: Current time.
/// * `expires_at`: When the approval expires.
///
/// Usage:
/// ```ignore
/// let attestation = build_approval_attestation("abc123", &did, &caps, now, expires)?;
/// ```
pub fn build_approval_attestation(
    request_hash_hex: &str,
    approver_did: CanonicalDid,
    capabilities: Vec<CanonicalCapability>,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<ApprovalAttestation, ApprovalError> {
    if now >= expires_at {
        return Err(ApprovalError::RequestExpired { expires_at });
    }

    let request_hash = hex_to_hash(request_hash_hex)?;
    let jti = uuid_v4(now);

    // Cap the attestation expiry to 5 minutes from now
    let attestation_expires = std::cmp::min(expires_at, now + Duration::minutes(5));

    Ok(ApprovalAttestation {
        jti,
        approver_did,
        request_hash,
        expires_at: attestation_expires,
        approved_capabilities: capabilities,
    })
}

fn hex_to_hash(hex: &str) -> Result<[u8; 32], ApprovalError> {
    let bytes = hex::decode(hex).map_err(|_| ApprovalError::RequestNotFound {
        hash: hex.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(ApprovalError::RequestNotFound {
            hash: hex.to_string(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn uuid_v4(now: DateTime<Utc>) -> String {
    let ts = now.timestamp_nanos_opt().unwrap_or_default() as u64;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ts >> 32) as u32,
        (ts >> 16) & 0xffff,
        ts & 0x0fff,
        0x8000 | ((ts >> 20) & 0x3fff),
        ts & 0xffffffffffff,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::crypto::provider_bridge;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let public_key_hex = hex::encode(pubkey_bytes);
        let did = "did:keri:Etest1234";

        let result = sign_auth_challenge("test-nonce-42", "auths.dev", &seed, &public_key_hex, did)
            .expect("signing should succeed");

        assert_eq!(result.public_key_hex, public_key_hex);
        assert_eq!(result.did, did);
        assert!(!result.signature_hex.is_empty());

        let canonical = json_canon::to_string(&serde_json::json!({
            "domain": "auths.dev",
            "nonce": "test-nonce-42",
        }))
        .expect("canonical JSON");

        let sig_bytes = hex::decode(&result.signature_hex).expect("valid hex");
        let verify_result =
            provider_bridge::verify_ed25519_sync(&pubkey_bytes, canonical.as_bytes(), &sig_bytes);
        assert!(verify_result.is_ok(), "signature should verify");
    }

    #[test]
    fn empty_nonce_rejected() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let result = sign_auth_challenge(
            "",
            "auths.dev",
            &seed,
            &hex::encode(pubkey_bytes),
            "did:keri:E1",
        );
        assert!(matches!(result, Err(AuthChallengeError::EmptyNonce)));
    }

    #[test]
    fn empty_domain_rejected() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let result = sign_auth_challenge(
            "nonce",
            "",
            &seed,
            &hex::encode(pubkey_bytes),
            "did:keri:E1",
        );
        assert!(matches!(result, Err(AuthChallengeError::EmptyDomain)));
    }

    #[test]
    fn canonical_json_sorts_keys_alphabetically() {
        let payload = serde_json::json!({
            "nonce": "abc",
            "domain": "xyz",
        });
        let canonical = json_canon::to_string(&payload).expect("canonical");
        assert_eq!(canonical, r#"{"domain":"xyz","nonce":"abc"}"#);
    }
}
