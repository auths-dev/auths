use anyhow::{Result, anyhow};
use auths_verifier::types::DeviceDID;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::keri::{Prefix, Said};

// --- General Constants ---

/// Default directory name within the user's home directory for storing repositories.
pub const TOOL_PATH: &str = ".auths";
/// Default filename for storing attestation data within Git commits.
pub const ATTESTATION_JSON: &str = "attestation.json";

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
/// Note: Use depends on whether caching resolved documents in Git is desired.
pub fn keri_document_ref(did_prefix: &Prefix) -> String {
    format!(
        "{}/{}/document",
        KERI_DID_REF_NAMESPACE_PREFIX.trim_end_matches('/'),
        did_prefix.as_str()
    )
}

/// Extracts the KERI prefix (AID) from a full `did:keri:` identifier string.
///
/// Returns `None` if the string does not start with "did:keri:" or is too short.
///
/// Prefer [`auths_core::keri_did::KeriDid`] at API boundaries for type safety.
pub fn did_keri_to_prefix(did: &str) -> Option<Prefix> {
    did.strip_prefix("did:keri:")
        .map(|s| Prefix::new_unchecked(s.to_string()))
}

// --- Configurable Layout (Primarily for did:key Identity & Attestations) ---

/// Configuration defining the Git reference layout for primary identity and device attestation data.
///
/// This struct allows consumers of the `auths-id` library to define custom
/// Git repository layouts, primarily for the `did:key` identity and associated
/// device attestations. This is useful for interoperability (e.g., Radicle's "rad/id"),
/// while also providing a generic default layout.
///
/// *Note:* KERI DID layout (`refs/did/keri/...`) is generally *not* configured here,
/// as it follows a more standardized pattern based on the DID prefix itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageLayoutConfig {
    /// The Git reference pointing to the commit containing the primary identity document.
    /// This typically stores the *controlling* DID (which could be did:key or did:keri)
    /// and associated metadata defined by the application.
    ///
    /// E.g., "rad/id" (Radicle convention) or "refs/auths/identity" (generic default).
    ///
    /// Default: `"refs/auths/identity"`
    pub identity_ref: String,

    /// The base Git reference prefix for storing device attestations.
    ///
    /// The specific device identifier (sanitized) and potentially other segments
    /// (like "/signatures") will be appended to this prefix to form the final
    /// reference path for a device's attestations.
    ///
    /// E.g., "refs/keys" (RIP-X Radicle convention) or
    /// "refs/auths/devices/nodes" (generic default).
    ///
    /// Default: `"refs/auths/devices/nodes"`
    pub device_attestation_prefix: String,

    /// Standard filename for the blob containing attestation data within device
    /// attestation commits.
    ///
    /// Default: `"attestation.json"`
    pub attestation_blob_name: String,

    /// Standard filename for the blob containing identity data within the primary
    /// identity commit (pointed to by `identity_ref`).
    ///
    /// Default: `"identity.json"`
    pub identity_blob_name: String,
}

/// Provides generic default layout settings for `did:key` identity and attestations.
impl Default for StorageLayoutConfig {
    fn default() -> Self {
        Self {
            // Generic default identity ref (stores controller DID + metadata)
            identity_ref: "refs/auths/identity".to_string(),
            // Generic default attestation prefix (for device linking)
            device_attestation_prefix: "refs/auths/devices/nodes".to_string(),
            // Standard blob names (less likely to need configuration)
            attestation_blob_name: ATTESTATION_JSON.to_string(), // Use constant
            identity_blob_name: "identity.json".to_string(),
        }
    }
}

impl StorageLayoutConfig {
    /// Creates a Radicle-compatible storage layout configuration (RIP-X).
    ///
    /// Uses RIP-X conventions for Git reference paths:
    /// - Identity: `refs/rad/id`
    /// - Attestations: `refs/keys` (2-blob format under `<nid>/signatures/`)
    /// - Blob names: `link-attestation.json`, `radicle-identity.json`
    ///
    /// Args:
    /// None — returns a pre-configured layout for Radicle repos.
    ///
    /// Usage:
    /// ```
    /// use auths_id::storage::layout::StorageLayoutConfig;
    ///
    /// let config = StorageLayoutConfig::radicle();
    /// assert_eq!(config.identity_ref, "refs/rad/id");
    /// assert_eq!(config.device_attestation_prefix, "refs/keys");
    /// ```
    pub fn radicle() -> Self {
        Self {
            identity_ref: "refs/rad/id".to_string(),
            device_attestation_prefix: "refs/keys".to_string(),
            attestation_blob_name: "link-attestation.json".to_string(),
            identity_blob_name: "radicle-identity.json".to_string(),
        }
    }

    /// Creates a gitoxide-compatible storage layout configuration.
    ///
    /// Uses standard Git reference conventions compatible with gitoxide:
    /// - Identity: `refs/auths/id`
    /// - Attestations: `refs/auths/devices`
    /// - Blob names: `attestation.json`, `identity.json`
    ///
    /// Gitoxide follows standard Git conventions, so this preset uses
    /// simplified Auths paths that work well with gitoxide tooling.
    ///
    /// # Example
    ///
    /// ```
    /// use auths_id::storage::layout::StorageLayoutConfig;
    ///
    /// let config = StorageLayoutConfig::gitoxide();
    /// assert_eq!(config.identity_ref, "refs/auths/id");
    /// ```
    pub fn gitoxide() -> Self {
        Self {
            identity_ref: "refs/auths/id".to_string(),
            device_attestation_prefix: "refs/auths/devices".to_string(),
            attestation_blob_name: ATTESTATION_JSON.to_string(),
            identity_blob_name: "identity.json".to_string(),
        }
    }

    // --- Organization Reference Helpers ---

    /// Constructs the full Git reference path for storing an organization member's attestation.
    ///
    /// Format: `refs/auths/org/<org-did-sanitized>/members/<member-did-sanitized>`
    ///
    /// # Arguments
    /// * `org_did` - The organization's DID (will be sanitized for use in Git refs)
    /// * `member_did` - The member's DeviceDID
    ///
    /// # Example
    /// ```ignore
    /// let config = StorageLayoutConfig::default();
    /// let member_did = DeviceDID::new("did:key:z6MkMember");
    /// let ref_path = config.org_member_ref("did:keri:EOrg123", &member_did);
    /// // Returns: "refs/auths/org/did_keri_EOrg123/members/did_key_z6MkMember"
    /// ```
    pub fn org_member_ref(&self, org_did: &str, member_did: &DeviceDID) -> String {
        format!(
            "refs/auths/org/{}/members/{}",
            sanitize_did_for_ref(org_did),
            member_did.ref_name()
        )
    }

    /// Returns the base Git reference prefix for listing all members of an organization.
    ///
    /// Format: `refs/auths/org/<org-did-sanitized>/members`
    ///
    /// Use this prefix with `git for-each-ref` or similar to enumerate all members.
    ///
    /// # Arguments
    /// * `org_did` - The organization's DID (will be sanitized for use in Git refs)
    pub fn org_members_prefix(&self, org_did: &str) -> String {
        format!("refs/auths/org/{}/members", sanitize_did_for_ref(org_did))
    }

    /// Returns the Git reference path for storing organization identity/metadata.
    ///
    /// Format: `refs/auths/org/<org-did-sanitized>/identity`
    ///
    /// # Arguments
    /// * `org_did` - The organization's DID (will be sanitized for use in Git refs)
    pub fn org_identity_ref(&self, org_did: &str) -> String {
        format!("refs/auths/org/{}/identity", sanitize_did_for_ref(org_did))
    }
}

/// Sanitizes a DID string for use in Git reference paths.
///
/// Replaces all non-alphanumeric characters with underscores.
/// This ensures the resulting string is safe for use in Git refs.
///
/// # Example
/// ```ignore
/// assert_eq!(sanitize_did_for_ref("did:keri:EOrg123"), "did_keri_EOrg123");
/// assert_eq!(sanitize_did_for_ref("did:key:z6Mk..."), "did_key_z6Mk___");
/// ```
pub fn sanitize_did_for_ref(did: &str) -> String {
    did.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

// --- Utility Functions (Independent of Layout Config or Relying on it) ---

/// Determines the actual repository path from an optional `--repo` argument.
/// If `repo_arg` is Some(<non-empty>), that path is used.
/// Otherwise, it falls back to `$HOME/.auths`.
pub fn resolve_repo_path(repo_arg: Option<PathBuf>) -> Result<PathBuf> {
    match repo_arg {
        Some(pathbuf) if !pathbuf.as_os_str().is_empty() => Ok(pathbuf),
        _ => {
            let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not find HOME directory"))?;
            Ok(home.join(TOOL_PATH)) // Use constant for default dir name
        }
    }
}

/// Creates a Git namespace prefix string for a given DID (used for fork storage).
/// Example: "did:key:abc" -> "refs/namespaces/did-key-abc"
/// Note: This relates to how *forks* are stored (`refs/namespaces/<nid>/...`) and is
/// generally separate from the *canonical* paths defined in `StorageLayoutConfig`.
pub fn device_namespace_prefix(did: &str) -> String {
    format!("refs/namespaces/{}", did_to_nid(did))
}

/// Sanitizes a DID string into a node ID (NID) suitable for use in Git refs.
/// Replaces ':' with '-'. Customize this conversion if needed.
fn did_to_nid(did: &str) -> String {
    // Basic sanitization, might need enhancement for other complex DID methods.
    did.replace(':', "-")
}

// --- Layout Helper Functions (Relying on Config - Primarily for non-KERI DIDs/Attestations) ---

/// Gets the primary identity Git reference from the configuration.
/// Returns a reference to the string within the config.
pub fn identity_ref(config: &StorageLayoutConfig) -> &str {
    // Directly uses the value from the provided config
    &config.identity_ref
}

/// Gets the standard identity blob filename from the configuration.
/// Returns a reference to the string within the config.
pub fn identity_blob_name(config: &StorageLayoutConfig) -> &str {
    // Directly uses the value from the provided config
    &config.identity_blob_name
}

/// Gets the standard attestation blob filename from the configuration.
/// Returns a reference to the string within the config.
pub fn attestation_blob_name(config: &StorageLayoutConfig) -> &str {
    // Directly uses the value from the provided config
    &config.attestation_blob_name
}

/// Constructs the full Git reference path for storing a specific device's attestations,
/// based on the provided configuration and device DID.
///
/// Appends the sanitized device DID and "/signatures" to the configured prefix.
/// Example (default config): `refs/auths/devices/nodes/<sanitized_did>/signatures`
/// Example (Radicle config): `refs/keys/<sanitized_did>/signatures`
pub fn attestation_ref_for_device(config: &StorageLayoutConfig, device_did: &DeviceDID) -> String {
    format!(
        "{}/{}/signatures",
        // Uses the prefix directly from the provided config
        config.device_attestation_prefix.trim_end_matches('/'),
        device_did.ref_name() // Sanitized DID
    )
}

/// Returns the list of Git reference prefixes to scan when discovering or loading
/// all device attestations, based on the provided configuration.
///
/// Currently, this just returns the single prefix defined in `config.device_attestation_prefix`.
/// This could be expanded in the future if the config needs to support searching
/// multiple legacy or alternative prefixes.
pub fn default_attestation_prefixes(config: &StorageLayoutConfig) -> Vec<String> {
    // Directly uses the prefix from the provided config
    vec![config.device_attestation_prefix.clone()]
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::types::DeviceDID;

    // --- Tests for Configurable Layout ---

    #[test]
    fn test_config_defaults() {
        let config = StorageLayoutConfig::default();
        assert_eq!(config.identity_ref, "refs/auths/identity");
        assert_eq!(config.device_attestation_prefix, "refs/auths/devices/nodes");
        assert_eq!(config.attestation_blob_name, "attestation.json");
        assert_eq!(config.identity_blob_name, "identity.json");
    }

    #[test]
    fn test_config_radicle() {
        let config = StorageLayoutConfig::radicle();
        assert_eq!(config.identity_ref, "refs/rad/id");
        assert_eq!(config.device_attestation_prefix, "refs/keys");
        assert_eq!(config.attestation_blob_name, "link-attestation.json");
        assert_eq!(config.identity_blob_name, "radicle-identity.json");
    }

    #[test]
    fn test_config_gitoxide() {
        let config = StorageLayoutConfig::gitoxide();
        assert_eq!(config.identity_ref, "refs/auths/id");
        assert_eq!(config.device_attestation_prefix, "refs/auths/devices");
        assert_eq!(config.attestation_blob_name, "attestation.json");
        assert_eq!(config.identity_blob_name, "identity.json");
    }

    #[test]
    fn test_identity_ref_from_config() {
        let config = StorageLayoutConfig::default();
        assert_eq!(identity_ref(&config), "refs/auths/identity");

        let custom_config = StorageLayoutConfig {
            identity_ref: "rad/id".to_string(),
            ..Default::default()
        };
        assert_eq!(identity_ref(&custom_config), "rad/id");
    }

    #[test]
    fn test_attestation_ref_for_device() {
        let did = DeviceDID::new("did:key:zExampleDeviceDID_With_Special_Chars!");
        let expected_sanitized_suffix = "did_key_zExampleDeviceDID_With_Special_Chars_/signatures";

        let config = StorageLayoutConfig::default();
        let expected_default_ref = format!(
            "{}/{}",
            config.device_attestation_prefix, expected_sanitized_suffix
        );
        assert_eq!(
            attestation_ref_for_device(&config, &did),
            expected_default_ref
        );

        let rad_config = StorageLayoutConfig::radicle();
        let expected_rad_ref = format!(
            "{}/{}",
            rad_config.device_attestation_prefix, expected_sanitized_suffix
        );
        assert_eq!(
            attestation_ref_for_device(&rad_config, &did),
            expected_rad_ref
        );
    }

    #[test]
    fn test_default_attestation_prefixes() {
        let config = StorageLayoutConfig::default();
        assert_eq!(
            default_attestation_prefixes(&config),
            vec!["refs/auths/devices/nodes"]
        );

        let rad_config = StorageLayoutConfig::radicle();
        assert_eq!(
            default_attestation_prefixes(&rad_config),
            vec!["refs/keys"]
        );
    }

    // --- Tests for KERI Layout ---

    #[test]
    fn test_did_keri_to_prefix() {
        let did = "did:keri:EABC123DEF456GHI789JKL";
        assert_eq!(
            did_keri_to_prefix(did),
            Some(Prefix::new_unchecked("EABC123DEF456GHI789JKL".to_string()))
        );

        let invalid_did = "did:key:zabcde";
        assert_eq!(did_keri_to_prefix(invalid_did), None);

        let short_did = "did:keri:";
        assert_eq!(
            did_keri_to_prefix(short_did),
            Some(Prefix::new_unchecked("".to_string()))
        );

        let not_a_did = "hello:world";
        assert_eq!(did_keri_to_prefix(not_a_did), None);
    }

    #[test]
    fn test_keri_kel_ref() {
        let prefix = Prefix::new_unchecked("EABC123DEF456GHI789JKL".to_string());
        let expected = "refs/did/keri/EABC123DEF456GHI789JKL/kel";
        assert_eq!(keri_kel_ref(&prefix), expected);
    }

    #[test]
    fn test_keri_document_ref() {
        let prefix = Prefix::new_unchecked("EABC123DEF456GHI789JKL".to_string());
        let expected = "refs/did/keri/EABC123DEF456GHI789JKL/document";
        assert_eq!(keri_document_ref(&prefix), expected);
    }

    #[test]
    fn test_keri_receipts_ref() {
        let prefix = Prefix::new_unchecked("EABC123".to_string());
        let said = Said::new_unchecked("ESAID456".to_string());
        let expected = "refs/did/keri/EABC123/receipts/ESAID456";
        assert_eq!(keri_receipts_ref(&prefix, &said), expected);
    }

    #[test]
    fn test_keri_receipts_prefix() {
        let prefix = Prefix::new_unchecked("EABC123".to_string());
        let expected = "refs/did/keri/EABC123/receipts";
        assert_eq!(keri_receipts_prefix(&prefix), expected);
    }

    // --- Tests for Organization Layout ---

    #[test]
    fn test_sanitize_did_for_ref() {
        assert_eq!(sanitize_did_for_ref("did:keri:EOrg123"), "did_keri_EOrg123");
        assert_eq!(sanitize_did_for_ref("did:key:z6MkTest"), "did_key_z6MkTest");
        assert_eq!(sanitize_did_for_ref("simple"), "simple");
        assert_eq!(sanitize_did_for_ref("has spaces"), "has_spaces");
        assert_eq!(sanitize_did_for_ref("special!@#$chars"), "special____chars");
    }

    #[test]
    fn test_org_member_ref() {
        let config = StorageLayoutConfig::default();
        let org_did = "did:keri:EOrg123";
        let member_did = DeviceDID::new("did:key:z6MkMember");

        let ref_path = config.org_member_ref(org_did, &member_did);
        assert_eq!(
            ref_path,
            "refs/auths/org/did_keri_EOrg123/members/did_key_z6MkMember"
        );
    }

    #[test]
    fn test_org_member_ref_with_special_chars() {
        let config = StorageLayoutConfig::default();
        let org_did = "did:keri:ESpecial_Org!";
        let member_did = DeviceDID::new("did:key:z6MkMember@Test");

        let ref_path = config.org_member_ref(org_did, &member_did);
        // Both should be sanitized
        assert!(ref_path.starts_with("refs/auths/org/"));
        assert!(ref_path.contains("/members/"));
        // No special chars should remain
        assert!(!ref_path.contains('!'));
        assert!(!ref_path.contains('@'));
    }

    #[test]
    fn test_org_members_prefix() {
        let config = StorageLayoutConfig::default();
        let org_did = "did:keri:EOrg123";

        let prefix = config.org_members_prefix(org_did);
        assert_eq!(prefix, "refs/auths/org/did_keri_EOrg123/members");
    }

    #[test]
    fn test_org_identity_ref() {
        let config = StorageLayoutConfig::default();
        let org_did = "did:keri:EOrg123";

        let ref_path = config.org_identity_ref(org_did);
        assert_eq!(ref_path, "refs/auths/org/did_keri_EOrg123/identity");
    }

    #[test]
    fn test_org_refs_are_consistent() {
        let config = StorageLayoutConfig::default();
        let org_did = "did:keri:EOrg123";
        let member_did = DeviceDID::new("did:key:z6MkMember");

        let member_ref = config.org_member_ref(org_did, &member_did);
        let prefix = config.org_members_prefix(org_did);

        // Member ref should start with the prefix
        assert!(
            member_ref.starts_with(&prefix),
            "Member ref '{}' should start with prefix '{}'",
            member_ref,
            prefix
        );
    }
}
