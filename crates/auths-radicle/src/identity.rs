//! Radicle identity resolver.
//!
//! Resolves Radicle peer identities by reading from `refs/rad/id` and extracting
//! the delegate's Ed25519 public key from the `did:key` format.

use anyhow::{Context, Error, Result, anyhow};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use auths_id::identity::{DidMethod, DidResolver, DidResolverError, ResolvedDid};
use auths_id::storage::layout::StorageLayoutConfig;

/// A Radicle identity document stored at `refs/rad/id`.
///
/// Radicle uses a threshold-based identity model where delegates are
/// identified by their `did:key` identifiers (Ed25519 public keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadicleIdentityDocument {
    /// List of delegate DIDs (typically `did:key:z6Mk...` format)
    pub delegates: Vec<String>,
    /// Threshold for multi-sig operations
    pub threshold: u32,
    /// Optional payload containing project metadata
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Represents a resolved Radicle identity with extracted key material.
#[derive(Debug, Clone)]
pub struct RadicleIdentity {
    /// The original identity document
    pub document: RadicleIdentityDocument,
    /// The primary delegate's Ed25519 public key bytes (32 bytes)
    pub primary_public_key: Vec<u8>,
    /// The primary delegate's DID
    pub primary_did: String,
}

/// Resolver for Radicle peer identities.
///
/// Reads identity documents from `refs/rad/id` in Radicle repositories and
/// extracts the Ed25519 public key from the delegate's `did:key`.
#[derive(Debug, Clone)]
pub struct RadicleIdentityResolver {
    repo_path: PathBuf,
    layout: StorageLayoutConfig,
}

impl RadicleIdentityResolver {
    /// Creates a new resolver for the given repository path.
    ///
    /// Uses the Radicle storage layout preset (`refs/rad/id`).
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
            layout: StorageLayoutConfig::radicle(),
        }
    }

    /// Creates a resolver with a custom storage layout.
    pub fn with_layout(repo_path: impl Into<PathBuf>, layout: StorageLayoutConfig) -> Self {
        Self {
            repo_path: repo_path.into(),
            layout,
        }
    }

    /// Resolves a Radicle peer's identity document.
    ///
    /// Reads from `refs/rad/id` (or the configured identity ref) and parses
    /// the JSON identity document.
    pub fn resolve_identity(&self) -> Result<RadicleIdentity, Error> {
        let repo = Repository::open(&self.repo_path)
            .with_context(|| format!("Failed to open repository at {:?}", self.repo_path))?;

        // Read the identity blob from refs/rad/id
        let identity_ref = &self.layout.identity_ref;
        let reference = repo
            .find_reference(identity_ref)
            .with_context(|| format!("Identity reference '{}' not found", identity_ref))?;

        let commit = reference
            .peel_to_commit()
            .with_context(|| format!("Failed to peel '{}' to commit", identity_ref))?;

        let tree = commit
            .tree()
            .context("Failed to get tree from identity commit")?;

        let blob_name = &self.layout.identity_blob_name;
        let entry = tree
            .get_name(blob_name)
            .ok_or_else(|| anyhow!("Identity blob '{}' not found in tree", blob_name))?;

        let blob = entry
            .to_object(&repo)
            .context("Failed to convert tree entry to object")?
            .peel_to_blob()
            .context("Failed to peel to blob")?;

        let content =
            std::str::from_utf8(blob.content()).context("Identity document is not valid UTF-8")?;

        let document: RadicleIdentityDocument =
            serde_json::from_str(content).context("Failed to parse identity document JSON")?;

        // Extract the primary delegate's public key
        let primary_did = document
            .delegates
            .first()
            .ok_or_else(|| anyhow!("Identity document has no delegates"))?
            .clone();

        let primary_public_key = self.resolve_did_key(&primary_did)?;

        Ok(RadicleIdentity {
            document,
            primary_public_key,
            primary_did,
        })
    }

    /// Resolves a `did:key` to its Ed25519 public key bytes.
    ///
    /// This handles the `did:key:z6Mk...` format used by Radicle, where:
    /// - `z` indicates base58btc encoding
    /// - `6Mk` is the Ed25519 multicodec prefix (0xED01)
    fn resolve_did_key(&self, did: &str) -> Result<Vec<u8>, Error> {
        let prefix = "did:key:z";
        if !did.starts_with(prefix) {
            return Err(anyhow!(DidResolverError::InvalidDidKeyFormat(
                did.to_string()
            )));
        }

        let encoded = &did[prefix.len()..];
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| anyhow!(DidResolverError::DidKeyDecodingFailed(e.to_string())))?;

        // Ed25519 multicodec prefix: 0xED 0x01
        const ED25519_PREFIX: &[u8] = &[0xED, 0x01];
        if decoded.len() != 34 || !decoded.starts_with(ED25519_PREFIX) {
            return Err(anyhow!(DidResolverError::InvalidDidKeyMulticodec));
        }

        Ok(decoded[2..].to_vec())
    }

    /// Returns the repository path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }
}

impl DidResolver for RadicleIdentityResolver {
    /// Resolves a DID to its Ed25519 public key bytes.
    ///
    /// Supports `did:key:z...` format (Radicle's native DID method).
    fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        if did.starts_with("did:key:") {
            let public_key = self
                .resolve_did_key(did)
                .map_err(|e| DidResolverError::InvalidDidKey(e.to_string()))?;
            Ok(ResolvedDid {
                did: did.to_string(),
                public_key,
                method: DidMethod::Key,
            })
        } else {
            Err(DidResolverError::UnsupportedMethod(did.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use tempfile::TempDir;

    fn create_test_repo_with_identity(delegates: Vec<&str>, threshold: u32) -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        let repo = Repository::init(temp_dir.path()).unwrap();

        // Create identity document
        let doc = RadicleIdentityDocument {
            delegates: delegates.iter().map(|s| s.to_string()).collect(),
            threshold,
            payload: serde_json::json!({"name": "test-project"}),
        };
        let content = serde_json::to_string_pretty(&doc).unwrap();

        // Write blob
        let blob_oid = repo.blob(content.as_bytes()).unwrap();

        // Create tree with radicle-identity.json and commit (all scoped to release borrows)
        let commit_oid = {
            let mut tree_builder = repo.treebuilder(None).unwrap();
            tree_builder
                .insert("radicle-identity.json", blob_oid, 0o100644)
                .unwrap();
            let tree_oid = tree_builder.write().unwrap();
            drop(tree_builder);

            let tree = repo.find_tree(tree_oid).unwrap();
            let sig = Signature::now("test", "test@example.com").unwrap();
            repo.commit(None, &sig, &sig, "Initial identity", &tree, &[])
                .unwrap()
        };

        // Create refs/rad/id reference
        repo.reference(
            "refs/rad/id",
            commit_oid,
            true,
            "Create Radicle identity ref",
        )
        .unwrap();

        temp_dir
    }

    #[test]
    fn test_resolve_valid_radicle_identity() {
        // Valid Ed25519 did:key (multicodec 0xED01 + 32 bytes)
        let valid_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";

        let temp_dir = create_test_repo_with_identity(vec![valid_did], 1);

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let identity = resolver.resolve_identity().unwrap();

        assert_eq!(identity.document.delegates.len(), 1);
        assert_eq!(identity.document.threshold, 1);
        assert_eq!(identity.primary_did, valid_did);
        assert_eq!(identity.primary_public_key.len(), 32);
    }

    #[test]
    fn test_resolve_via_trait() {
        let valid_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";

        let temp_dir = create_test_repo_with_identity(vec![valid_did], 1);

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let resolved = resolver.resolve(valid_did).unwrap();

        assert_eq!(resolved.public_key.len(), 32);
    }

    #[test]
    fn test_reject_unsupported_did_method() {
        let temp_dir = create_test_repo_with_identity(
            vec!["did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"],
            1,
        );

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve("did:keri:EExample123");

        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_did_key_format() {
        let temp_dir = create_test_repo_with_identity(
            vec!["did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"],
            1,
        );

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve("did:key:invalid");

        assert!(result.is_err());
    }

    #[test]
    fn test_missing_identity_ref() {
        let temp_dir = TempDir::new().unwrap();
        let _repo = Repository::init(temp_dir.path()).unwrap();

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve_identity();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("refs/rad/id"));
    }

    #[test]
    fn test_empty_delegates() {
        // Helper creates identity with empty delegates
        let temp_dir = create_test_repo_with_identity(vec![], 1);

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve_identity();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no delegates"));
    }
}
