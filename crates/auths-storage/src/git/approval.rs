//! Approval request storage using Git refs.
//!
//! Pending requests: `refs/auths/approvals/pending/<request-hash-hex>`
//! Consumed nonces: `refs/auths/approvals/consumed/<jti>`

use chrono::{DateTime, Utc};
use git2::{ErrorCode, Repository};
use serde::{Deserialize, Serialize};

use auths_id::error::StorageError;
use auths_keri::Capability;

/// A pending approval request stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Hex-encoded SHA-256 of the scoped request context.
    pub request_hash: String,
    /// Human-readable description of what's being approved.
    pub context_summary: String,
    /// Capabilities that require approval.
    pub required_capabilities: Vec<Capability>,
    /// DIDs authorized to grant this approval.
    pub allowed_approvers: Vec<String>,
    /// Approval scope used to compute the request hash.
    pub scope: String,
    /// Approval request TTL in seconds.
    pub ttl_seconds: u64,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
}

/// Consumed nonce metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumedNonce {
    expires_at: DateTime<Utc>,
}

/// A lowercase hex SHA-256 — exactly 64 hex characters. Parsing rejects anything else, so a request
/// hash used as a git ref path segment cannot carry a `/` or `..` that would escape the approvals
/// namespace or overwrite an unrelated ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Parse a 64-character lowercase hex string, or reject it.
    pub fn parse(s: &str) -> Result<Sha256Hex, StorageError> {
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Sha256Hex(s.to_string()))
        } else {
            Err(StorageError::InvalidData(format!(
                "approval request hash is not 64-character lowercase hex: {s:?}"
            )))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A consumed-nonce identifier safe to use as a single git ref path segment: non-empty, with no path
/// separator or traversal, so a hostile `jti` cannot forge or overwrite a ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceId(String);

impl NonceId {
    /// Parse a nonce identifier, rejecting anything that is not a safe ref segment.
    pub fn parse(s: &str) -> Result<NonceId, StorageError> {
        if is_safe_ref_segment(s) {
            Ok(NonceId(s.to_string()))
        } else {
            Err(StorageError::InvalidData(format!(
                "nonce id is not a safe ref segment: {s:?}"
            )))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `s` is a single safe git ref path component: non-empty, not `.` or `..`, with no `/` and
/// no control or whitespace character that could escape or corrupt the ref namespace.
fn is_safe_ref_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && s.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

fn pending_ref(request_hash: &Sha256Hex) -> String {
    format!("refs/auths/approvals/pending/{}", request_hash.as_str())
}

fn consumed_ref(jti: &NonceId) -> String {
    format!("refs/auths/approvals/consumed/{}", jti.as_str())
}

fn write_json_blob(repo: &Repository, ref_name: &str, data: &[u8]) -> Result<(), StorageError> {
    let blob_oid = repo.blob(data)?;
    let sig = repo.signature()?;
    repo.reference(ref_name, blob_oid, true, sig.name().unwrap_or("auths"))?;
    Ok(())
}

fn read_json_blob(repo: &Repository, ref_name: &str) -> Result<Option<Vec<u8>>, StorageError> {
    match repo.find_reference(ref_name) {
        Ok(reference) => {
            let oid = reference
                .target()
                .ok_or_else(|| StorageError::NotFound("ref has no target".into()))?;
            let blob = repo.find_blob(oid)?;
            Ok(Some(blob.content().to_vec()))
        }
        Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Store a pending approval request.
///
/// Args:
/// * `repo`: The Git repository.
/// * `request`: The approval request to store.
///
/// Usage:
/// ```ignore
/// store_approval_request(&repo, &request)?;
/// ```
pub fn store_approval_request(
    repo: &Repository,
    request: &ApprovalRequest,
) -> Result<(), StorageError> {
    let json = serde_json::to_vec(request)?;
    let request_hash = Sha256Hex::parse(&request.request_hash)?;
    let ref_name = pending_ref(&request_hash);
    write_json_blob(repo, &ref_name, &json)
}

/// Load a pending approval request by hash.
///
/// Args:
/// * `repo`: The Git repository.
/// * `request_hash`: Hex-encoded request hash.
///
/// Usage:
/// ```ignore
/// let request = load_approval_request(&repo, "abc123")?;
/// ```
pub fn load_approval_request(
    repo: &Repository,
    request_hash: &str,
) -> Result<Option<ApprovalRequest>, StorageError> {
    let ref_name = pending_ref(&Sha256Hex::parse(request_hash)?);
    match read_json_blob(repo, &ref_name)? {
        Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
        None => Ok(None),
    }
}

/// List pending approval requests, pruning expired ones.
///
/// Args:
/// * `repo`: The Git repository.
/// * `now`: Current time for expiry filtering.
///
/// Usage:
/// ```ignore
/// let pending = list_pending_approvals(&repo, Utc::now())?;
/// ```
pub fn list_pending_approvals(
    repo: &Repository,
    now: DateTime<Utc>,
) -> Result<Vec<ApprovalRequest>, StorageError> {
    let mut result = Vec::new();
    let refs = repo.references_glob("refs/auths/approvals/pending/*")?;

    for reference in refs {
        let reference = reference?;
        let ref_name = reference.name().unwrap_or_default().to_string();
        if let Some(oid) = reference.target()
            && let Ok(blob) = repo.find_blob(oid)
            && let Ok(request) = serde_json::from_slice::<ApprovalRequest>(blob.content())
        {
            if request.expires_at > now {
                result.push(request);
            } else {
                let _ = repo.find_reference(&ref_name).and_then(|mut r| r.delete());
            }
        }
    }

    result.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(result)
}

/// Mark a nonce as consumed.
///
/// Args:
/// * `repo`: The Git repository.
/// * `jti`: The unique nonce identifier.
/// * `expires_at`: When the nonce entry can be pruned.
///
/// Usage:
/// ```ignore
/// mark_nonce_consumed(&repo, "uuid-123", expires_at)?;
/// ```
pub fn mark_nonce_consumed(
    repo: &Repository,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), StorageError> {
    let nonce = ConsumedNonce { expires_at };
    let json = serde_json::to_vec(&nonce)?;
    let ref_name = consumed_ref(&NonceId::parse(jti)?);
    write_json_blob(repo, &ref_name, &json)
}

/// Check if a nonce has been consumed.
///
/// Args:
/// * `repo`: The Git repository.
/// * `jti`: The unique nonce identifier.
///
/// Usage:
/// ```ignore
/// if is_nonce_consumed(&repo, "uuid-123")? {
///     return Err(ApprovalError::AlreadyUsed);
/// }
/// ```
pub fn is_nonce_consumed(repo: &Repository, jti: &str) -> Result<bool, StorageError> {
    let ref_name = consumed_ref(&NonceId::parse(jti)?);
    Ok(read_json_blob(repo, &ref_name)?.is_some())
}

/// Remove a pending approval request.
///
/// Args:
/// * `repo`: The Git repository.
/// * `request_hash`: Hex-encoded request hash.
///
/// Usage:
/// ```ignore
/// remove_approval_request(&repo, "abc123")?;
/// ```
pub fn remove_approval_request(repo: &Repository, request_hash: &str) -> Result<(), StorageError> {
    let ref_name = pending_ref(&Sha256Hex::parse(request_hash)?);
    match repo.find_reference(&ref_name) {
        Ok(mut r) => {
            r.delete()?;
            Ok(())
        }
        Err(e) if e.code() == ErrorCode::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Prune expired consumed nonce refs.
///
/// Args:
/// * `repo`: The Git repository.
/// * `now`: Current time for expiry comparison.
///
/// Usage:
/// ```ignore
/// let pruned_count = prune_expired_nonces(&repo, Utc::now())?;
/// ```
pub fn prune_expired_nonces(repo: &Repository, now: DateTime<Utc>) -> Result<usize, StorageError> {
    let mut pruned = 0;
    let refs = repo.references_glob("refs/auths/approvals/consumed/*")?;

    for reference in refs {
        let reference = reference?;
        let ref_name = reference.name().unwrap_or_default().to_string();
        if let Some(oid) = reference.target()
            && let Ok(blob) = repo.find_blob(oid)
            && let Ok(nonce) = serde_json::from_slice::<ConsumedNonce>(blob.content())
            && nonce.expires_at < now
        {
            let _ = repo.find_reference(&ref_name).and_then(|mut r| r.delete());
            pruned += 1;
        }
    }

    Ok(pruned)
}
