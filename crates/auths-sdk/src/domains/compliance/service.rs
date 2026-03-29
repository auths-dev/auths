//! Approval workflow functions.
//!
//! Three-phase design:
//! 1. `build_approval_attestation` — pure, deterministic attestation construction.
//! 2. `apply_approval` — side-effecting: consume nonce, remove pending request.
//! 3. `grant_approval` — high-level orchestrator (calls load → build → apply).

use chrono::{DateTime, Duration, Utc};

use auths_policy::approval::ApprovalAttestation;
use auths_policy::types::{CanonicalCapability, CanonicalDid};

use crate::domains::compliance::error::ApprovalError;

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
