use auths_verifier::types::DeviceDID;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use std::path::PathBuf;

use crate::error::StorageError;

use crate::keri::{Prefix, Said};

// --- General Constants ---

/// Default directory name within the user's home directory for storing repositories.
pub const TOOL_PATH: &str = ".auths";
/// Default filename for storing attestation data within Git commits.
pub const ATTESTATION_JSON: &str = "attestation.json";
/// Default filename for storing identity data within Git commits.
pub const IDENTITY_JSON: &str = "identity.json";

// --- Typed Git ref and blob name newtypes ---

/// A Git reference path (e.g. `refs/auths/identity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitRef(String);

impl GitRef {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Join a path segment to this ref, separated by `/`.
    pub fn join(&self, segment: &str) -> GitRef {
        GitRef(format!("{}/{}", self.0.trim_end_matches('/'), segment))
    }
}

impl fmt::Display for GitRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for GitRef {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for GitRef {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for GitRef {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl From<String> for GitRef {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A blob filename within a Git tree (e.g. `attestation.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobName(String);

impl BlobName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for BlobName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for BlobName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for BlobName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl From<String> for BlobName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// --- KERI Specific Constants & Layout  ---

/// The base Git reference namespace prefix for storing KERI DID information.
pub const KERI_DID_REF_NAMESPACE_PREFIX: &str = "refs/did/keri";

/// Constructs the full Git reference path for a KERI Key Event Log (KEL)
/// based on the DID prefix (AID).
///
/// Example: `refs/did/keri/<did_prefix>/kel`
pub fn keri_kel_ref(did_prefix: &Prefix) -> String {
    format!(
        "{}/{}/kel",
        KERI_DID_REF_NAMESPACE_PREFIX.trim_end_matches('/'),
        did_prefix.as_str()
    )
}

/// Constructs the Git reference path for storing receipts for a specific event.
///
/// Example: `refs/did/keri/<did_prefix>/receipts/<event_said>`
pub fn keri_receipts_ref(did_prefix: &Prefix, event_said: &Said) -> String {
    format!(
        "{}/{}/receipts/{}",
        KERI_DID_REF_NAMESPACE_PREFIX.trim_end_matches('/'),
        did_prefix.as_str(),
        event_said.as_str()
    )
}

/// Returns the base Git reference prefix for all receipts of an identity.
///
/// Example: `refs/did/keri/<did_prefix>/receipts`
pub fn keri_receipts_prefix(did_prefix: &Prefix) -> String {
    format!(
        "{}/{}/receipts",
        KERI_DID_REF_NAMESPACE_PREFIX.trim_end_matches('/'),
        did_prefix.as_str()
    )
}

/// (Optional) Constructs the full Git reference path for a cached KERI DID Document
/// based on the DID prefix (AID).
///
/// Example: `refs/did/keri/<did_prefix>/document`
pub fn keri_document_ref(did_prefix: &Prefix) -> String {
    format!(
        "{}/{}/document",
        KERI_DID_REF_NAMESPACE_PREFIX.trim_end_matches('/'),
        did_prefix.as_str()
    )
}

/// Extracts the KERI prefix (AID) from a full `did:keri:` identifier string.
pub fn did_keri_to_prefix(did: &str) -> Option<Prefix> {
    did.strip_prefix("did:keri:")
        .map(|s| Prefix::new_unchecked(s.to_string()))
}

// --- Configurable Layout (Primarily for did:key Identity & Attestations) ---

/// Configuration defining the Git reference layout for primary identity and device attestation data.
///
/// This struct allows consumers of the `auths-id` library to define custom
/// Git repository layouts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageLayoutConfig {
    /// The Git reference pointing to the commit containing the primary identity document.
    /// Default: `"refs/auths/identity"`
    pub identity_ref: GitRef,

    /// The base Git reference prefix for storing device attestations.
    /// Default: `"refs/auths/keys"`
    pub device_attestation_prefix: GitRef,

    /// Standard filename for the blob containing attestation data.
    /// Default: `"attestation.json"`
    pub attestation_blob_name: BlobName,

    /// Standard filename for the blob containing identity data.
    /// Default: `"identity.json"`
    pub identity_blob_name: BlobName,
}
impl Default for StorageLayoutConfig {
    fn default() -> Self {
        Self {
            identity_ref: GitRef::new("refs/auths/identity"),
            device_attestation_prefix: GitRef::new("refs/auths/keys"),
            attestation_blob_name: BlobName::new(ATTESTATION_JSON),
            identity_blob_name: BlobName::new(IDENTITY_JSON),
        }
    }
}

impl StorageLayoutConfig {
    /// Radicle-compatible layout preset (uses `refs/rad/` namespace).
    pub fn radicle() -> Self {
        Self {
            identity_ref: GitRef::new("refs/rad/id"),
            device_attestation_prefix: GitRef::new("refs/keys"),
            attestation_blob_name: BlobName::new("link-attestation.json"),
            identity_blob_name: BlobName::new("radicle-identity.json"),
        }
    }

    /// Gitoxide-compatible layout preset (uses `refs/auths/` namespace).
    pub fn gitoxide() -> Self {
        Self {
            identity_ref: GitRef::new("refs/auths/id"),
            device_attestation_prefix: GitRef::new("refs/auths/devices"),
            attestation_blob_name: BlobName::new(ATTESTATION_JSON),
            identity_blob_name: BlobName::new(IDENTITY_JSON),
        }
    }

    // --- Organization Reference Helpers ---

    /// Constructs the full Git reference path for storing an organization member's attestation.
    pub fn org_member_ref(&self, org_did: &str, member_did: &DeviceDID) -> String {
        format!(
            "refs/auths/org/{}/members/{}",
            sanitize_did_for_ref(org_did),
            member_did.ref_name()
        )
    }

    /// Returns the base Git reference prefix for listing all members of an organization.
    pub fn org_members_prefix(&self, org_did: &str) -> String {
        format!("refs/auths/org/{}/members", sanitize_did_for_ref(org_did))
    }

    /// Returns the Git reference path for storing organization identity/metadata.
    pub fn org_identity_ref(&self, org_did: &str) -> String {
        format!("refs/auths/org/{}/identity", sanitize_did_for_ref(org_did))
    }
}

/// Sanitizes a DID string for use in Git reference paths.
pub fn sanitize_did_for_ref(did: &str) -> String {
    did.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Determines the actual repository path from an optional `--repo` argument.
pub fn resolve_repo_path(repo_arg: Option<PathBuf>) -> Result<PathBuf, StorageError> {
    match repo_arg {
        Some(pathbuf) if !pathbuf.as_os_str().is_empty() => Ok(pathbuf),
        _ => {
            let home = dirs::home_dir()
                .ok_or_else(|| StorageError::NotFound("Could not find HOME directory".into()))?;
            Ok(home.join(TOOL_PATH))
        }
    }
}

/// Creates a Git namespace prefix string for a given DID.
pub fn device_namespace_prefix(did: &str) -> String {
    format!("refs/namespaces/{}", did_to_nid(did))
}

/// Sanitizes a DID string into a node ID (NID) suitable for use in Git refs.
fn did_to_nid(did: &str) -> String {
    did.replace(':', "-")
}

/// Gets the primary identity Git reference from the configuration.
pub fn identity_ref(config: &StorageLayoutConfig) -> &str {
    &config.identity_ref
}

/// Gets the standard identity blob filename from the configuration.
pub fn identity_blob_name(config: &StorageLayoutConfig) -> &str {
    &config.identity_blob_name
}

/// Gets the standard attestation blob filename from the configuration.
pub fn attestation_blob_name(config: &StorageLayoutConfig) -> &str {
    &config.attestation_blob_name
}

/// Constructs the full Git reference path for storing a specific device's attestations.
pub fn attestation_ref_for_device(config: &StorageLayoutConfig, device_did: &DeviceDID) -> String {
    format!(
        "{}/{}/signatures",
        config
            .device_attestation_prefix
            .as_str()
            .trim_end_matches('/'),
        device_did.ref_name()
    )
}

/// Returns the list of Git reference prefixes to scan when discovering device attestations.
pub fn default_attestation_prefixes(config: &StorageLayoutConfig) -> Vec<String> {
    vec![config.device_attestation_prefix.as_str().to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults_are_agnostic() {
        let config = StorageLayoutConfig::default();
        assert_eq!(config.identity_ref.as_str(), "refs/auths/identity");
        assert_eq!(config.device_attestation_prefix.as_str(), "refs/auths/keys");
        assert_eq!(config.attestation_blob_name.as_str(), "attestation.json");
        assert_eq!(config.identity_blob_name.as_str(), "identity.json");
    }

    #[test]
    fn test_attestation_ref_for_device() {
        let prefix = Prefix::new_unchecked("EABC123".to_string());
        let expected = "refs/did/keri/EABC123/kel";
        assert_eq!(keri_kel_ref(&prefix), expected);
    }

    #[test]
    fn git_ref_join() {
        let base = GitRef::new("refs/auths/keys");
        let joined = base.join("device1");
        assert_eq!(joined.as_str(), "refs/auths/keys/device1");
    }

    #[test]
    fn git_ref_deref() {
        let r = GitRef::new("refs/auths/id");
        let s: &str = &r;
        assert_eq!(s, "refs/auths/id");
    }

    #[test]
    fn blob_name_deref() {
        let b = BlobName::new("attestation.json");
        let s: &str = &b;
        assert_eq!(s, "attestation.json");
    }

    #[test]
    fn layout_roundtrips() {
        let config = StorageLayoutConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: StorageLayoutConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }
}
