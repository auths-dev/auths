use crate::storage::layout;
use anyhow::Result;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};
use git2::Repository;
use std::collections::HashMap;

/// Optional extra fields for the attestation commit metadata.
#[derive(Debug, Clone, Default)]
pub struct AttestationMetadata {
    /// Free-form note or reason for linking devices, e.g. "added second laptop".
    pub note: Option<String>,
    /// Optional custom timestamp; if not set, we'll use `Utc::now()`.
    pub timestamp: Option<DateTime<Utc>>,
    // Add more fields as needed, e.g. device IP, user ID, etc.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Aggregates all refs from refs/namespaces/<nid>/refs/* across known devices.
/// Returns a canonical merged view of refname -> commit hash.
pub fn aggregate_canonical_refs(
    repo: &Repository,
    device_dids: &[DeviceDID],
) -> Result<HashMap<String, String>> {
    let mut canonical = HashMap::new();

    for did in device_dids {
        let prefix = layout::device_namespace_prefix(did.as_str());
        let refs = repo.references_glob(&format!("{}/refs/**", prefix))?;

        for r in refs.flatten() {
            if let Some(name) = r.name()
                && let Some(target) = r.target()
            {
                // Use first seen version of each ref
                canonical
                    .entry(name.to_string())
                    .or_insert_with(|| target.to_string());
            }
        }
    }
    Ok(canonical)
}
