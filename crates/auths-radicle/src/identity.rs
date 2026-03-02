//! Radicle identity resolver.
//!
//! Resolves Radicle peer identities by reading from `refs/rad/id` and extracting
//! the delegate's Ed25519 public key from the `did:key` format. Also resolves
//! `did:keri:` identifiers by replaying the KERI Key Event Log.

use auths_crypto::KeriPublicKey;
use auths_id::identity::{DidMethod, DidResolver, DidResolverError, ResolvedDid};
use auths_id::keri::event::Event;
use auths_id::keri::validate::replay_kel;
use git2::{ErrorCode, Repository};
use radicle_core::Did;
use radicle_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::refs::{self, Layout};

/// Errors from identity resolution.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("repository error at {path}: {detail}")]
    Repository { path: String, detail: String },

    #[error("identity ref '{ref_name}' not found in {path}")]
    RefNotFound { ref_name: String, path: String },

    #[error("invalid identity document: {0}")]
    InvalidDocument(String),

    #[error("no delegates in identity document")]
    NoDelegates,

    #[error("invalid did:key format: {0}")]
    InvalidDidKey(String),

    #[error("KEL not found at {ref_path}")]
    KelNotFound { ref_path: String },

    #[error("KEL validation failed: {0}")]
    KelValidationFailed(String),

    #[error("no current signing keys in key state")]
    NoSigningKeys,

    #[error("invalid DID: {0}")]
    InvalidDid(#[from] radicle_core::identity::DidError),
}

/// A Radicle identity document stored at `refs/rad/id`.
///
/// Radicle uses a threshold-based identity model where delegates are
/// identified by their `did:key` identifiers (Ed25519 public keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadicleIdentityDocument {
    /// List of delegate DIDs (typically `did:key:z6Mk...` format)
    pub delegates: Vec<Did>,
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
    /// The primary delegate's Ed25519 public key
    pub primary_public_key: PublicKey,
    /// The primary delegate's DID
    pub primary_did: Did,
}

/// Resolver for Radicle peer identities.
///
/// Reads identity documents from `refs/rad/id` in Radicle repositories and
/// extracts the Ed25519 public key from the delegate's `did:key`.
#[derive(Debug, Clone)]
pub struct RadicleIdentityResolver {
    repo_path: PathBuf,
    identity_repo_path: Option<PathBuf>,
    layout: Layout,
}

impl RadicleIdentityResolver {
    /// Creates a new resolver for the given repository path.
    ///
    /// Uses the Radicle storage layout preset (`refs/rad/id`).
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
            identity_repo_path: None,
            layout: Layout::radicle(),
        }
    }

    /// Creates a resolver with a custom storage layout.
    pub fn with_layout(repo_path: impl Into<PathBuf>, layout: Layout) -> Self {
        Self {
            repo_path: repo_path.into(),
            identity_repo_path: None,
            layout,
        }
    }

    /// Sets a separate identity repository path for `did:keri` resolution.
    ///
    /// When set, `did:keri:` DIDs are resolved by reading the KEL from this
    /// repository instead of the main project repo.
    pub fn with_identity_repo(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_repo_path = Some(path.into());
        self
    }

    /// Resolves a Radicle peer's identity document.
    ///
    /// Reads from `refs/rad/id` (or the configured identity ref) and parses
    /// the JSON identity document.
    pub fn resolve_identity(&self) -> Result<RadicleIdentity, IdentityError> {
        let repo = Repository::open(&self.repo_path).map_err(|e| IdentityError::Repository {
            path: self.repo_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let identity_ref = &self.layout.rad_id_ref;
        let reference =
            repo.find_reference(identity_ref)
                .map_err(|_| IdentityError::RefNotFound {
                    ref_name: identity_ref.clone(),
                    path: self.repo_path.display().to_string(),
                })?;

        let commit = reference
            .peel_to_commit()
            .map_err(|e| IdentityError::InvalidDocument(format!("peel to commit: {e}")))?;

        let tree = commit
            .tree()
            .map_err(|e| IdentityError::InvalidDocument(format!("get tree: {e}")))?;

        let blob_name = &self.layout.identity_blob;
        let entry = tree.get_name(blob_name).ok_or_else(|| {
            IdentityError::InvalidDocument(format!("blob '{blob_name}' not found"))
        })?;

        let blob = entry
            .to_object(&repo)
            .map_err(|e| IdentityError::InvalidDocument(format!("convert to object: {e}")))?
            .peel_to_blob()
            .map_err(|e| IdentityError::InvalidDocument(format!("peel to blob: {e}")))?;

        let content = std::str::from_utf8(blob.content())
            .map_err(|e| IdentityError::InvalidDocument(format!("not valid UTF-8: {e}")))?;

        let document: RadicleIdentityDocument = serde_json::from_str(content)
            .map_err(|e| IdentityError::InvalidDocument(format!("invalid JSON: {e}")))?;

        let primary_did = document
            .delegates
            .first()
            .ok_or(IdentityError::NoDelegates)?
            .clone();

        let primary_public_key = resolve_did_key(&primary_did)?;

        Ok(RadicleIdentity {
            document,
            primary_public_key,
            primary_did,
        })
    }

    /// Returns the repository path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    fn resolve_keri(&self, did: &str) -> Result<ResolvedDid, IdentityError> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = Repository::open(id_path).map_err(|e| IdentityError::Repository {
            path: id_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let events = read_kel_events(&repo, id_path)?;
        if events.is_empty() {
            return Err(IdentityError::KelNotFound {
                ref_path: refs::KERI_KEL_REF.to_string(),
            });
        }

        let key_state =
            replay_kel(&events).map_err(|e| IdentityError::KelValidationFailed(e.to_string()))?;

        let cesr_key = key_state
            .current_keys
            .first()
            .ok_or(IdentityError::NoSigningKeys)?;

        let keri_pk = KeriPublicKey::parse(cesr_key)
            .map_err(|e| IdentityError::KelValidationFailed(format!("invalid CESR key: {e}")))?;

        let public_key = keri_pk.into_bytes().to_vec();

        Ok(ResolvedDid {
            did: did.to_string(),
            public_key,
            method: DidMethod::Keri {
                sequence: key_state.sequence,
                can_rotate: key_state.can_rotate(),
            },
        })
    }
}

const EVENT_BLOB_NAME: &str = "event.json";

fn read_kel_events(repo: &Repository, path: &Path) -> Result<Vec<Event>, IdentityError> {
    let reference = match repo.find_reference(refs::KERI_KEL_REF) {
        Ok(r) => r,
        Err(e) if e.code() == ErrorCode::NotFound => return Ok(vec![]),
        Err(e) => {
            return Err(IdentityError::Repository {
                path: path.display().to_string(),
                detail: format!("KEL ref error: {e}"),
            });
        }
    };

    let mut commit = reference
        .peel_to_commit()
        .map_err(|e| IdentityError::Repository {
            path: path.display().to_string(),
            detail: format!("KEL ref not a commit: {e}"),
        })?;

    let mut events = Vec::new();
    loop {
        if commit.parent_count() > 1 {
            return Err(IdentityError::KelValidationFailed(
                "merge commit in KEL chain".into(),
            ));
        }

        let tree = commit
            .tree()
            .map_err(|e| IdentityError::KelValidationFailed(format!("missing tree: {e}")))?;
        let entry = tree.get_name(EVENT_BLOB_NAME).ok_or_else(|| {
            IdentityError::KelValidationFailed("missing event.json in KEL commit".into())
        })?;
        let blob = repo
            .find_blob(entry.id())
            .map_err(|e| IdentityError::KelValidationFailed(format!("blob read error: {e}")))?;
        let event: Event = serde_json::from_slice(blob.content())
            .map_err(|e| IdentityError::KelValidationFailed(format!("invalid event JSON: {e}")))?;
        events.push(event);

        if commit.parent_count() == 0 {
            break;
        }
        commit = commit
            .parent(0)
            .map_err(|e| IdentityError::KelValidationFailed(format!("parent walk error: {e}")))?;
    }

    events.reverse();
    Ok(events)
}

/// Resolves a `Did` to its `PublicKey`.
pub fn resolve_did_key(did: &Did) -> Result<PublicKey, IdentityError> {
    did.as_key().copied().ok_or_else(|| {
        IdentityError::InvalidDidKey(format!("{did}: not a did:key (expected Ed25519)"))
    })
}

/// Resolves a `did:key:z...` to its Ed25519 public key bytes.
///
/// Handles the `did:key:z6Mk...` format used by Radicle, where:
/// - `z` indicates base58btc encoding
/// - `6Mk` is the Ed25519 multicodec prefix (0xED01)
pub fn resolve_did_key_bytes(did: &str) -> Result<Vec<u8>, IdentityError> {
    let did: Did = did.parse()?;
    Ok(resolve_did_key(&did)?.to_vec())
}

impl DidResolver for RadicleIdentityResolver {
    fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        if did.starts_with("did:key:") {
            let public_key = resolve_did_key_bytes(did)
                .map_err(|e| DidResolverError::InvalidDidKey(e.to_string()))?;
            Ok(ResolvedDid {
                did: did.to_string(),
                public_key,
                method: DidMethod::Key,
            })
        } else if did.starts_with("did:keri:") {
            self.resolve_keri(did)
                .map_err(|e| DidResolverError::Resolution(e.to_string()))
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

        let doc = RadicleIdentityDocument {
            delegates: delegates.iter().map(|s| s.parse().unwrap()).collect(),
            threshold,
            payload: serde_json::json!({"name": "test-project"}),
        };
        let content = serde_json::to_string_pretty(&doc).unwrap();
        let blob_oid = repo.blob(content.as_bytes()).unwrap();

        let layout = Layout::radicle();
        let commit_oid = {
            let mut tree_builder = repo.treebuilder(None).unwrap();
            tree_builder
                .insert(&layout.identity_blob, blob_oid, 0o100644)
                .unwrap();
            let tree_oid = tree_builder.write().unwrap();
            drop(tree_builder);

            let tree = repo.find_tree(tree_oid).unwrap();
            let sig = Signature::now("test", "test@example.com").unwrap();
            repo.commit(None, &sig, &sig, "Initial identity", &tree, &[])
                .unwrap()
        };

        repo.reference(
            &layout.rad_id_ref,
            commit_oid,
            true,
            "Create Radicle identity ref",
        )
        .unwrap();

        temp_dir
    }

    /// Creates a KERI identity in a Git repo and copies the KEL to `refs/keri/kel`.
    fn create_keri_repo() -> (TempDir, auths_id::keri::InceptionResult) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let result = auths_id::keri::create_keri_identity(&repo, None).unwrap();

        // Copy from refs/did/keri/<prefix>/kel to refs/keri/kel (Radicle layout)
        let src_ref = format!("refs/did/keri/{}/kel", result.prefix.as_str());
        let reference = repo.find_reference(&src_ref).unwrap();
        let oid = reference.target().unwrap();
        repo.reference(refs::KERI_KEL_REF, oid, true, "copy KEL to Radicle layout")
            .unwrap();

        (dir, result)
    }

    #[test]
    fn resolve_valid_radicle_identity() {
        let valid_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
        let temp_dir = create_test_repo_with_identity(vec![valid_did], 1);

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let identity = resolver.resolve_identity().unwrap();

        assert_eq!(identity.document.delegates.len(), 1);
        assert_eq!(identity.document.threshold, 1);
        assert_eq!(identity.primary_did.to_string(), valid_did);
        assert_eq!(identity.primary_public_key.as_ref().len(), 32);
    }

    #[test]
    fn resolve_did_key_via_trait() {
        let valid_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
        let temp_dir = create_test_repo_with_identity(vec![valid_did], 1);

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let resolved = resolver.resolve(valid_did).unwrap();
        assert_eq!(resolved.public_key.len(), 32);
        assert!(matches!(resolved.method, DidMethod::Key));
    }

    #[test]
    fn resolve_did_keri_returns_correct_key() {
        let (dir, inception) = create_keri_repo();
        let did = inception.did();

        let resolver = RadicleIdentityResolver::new(dir.path());
        let resolved = resolver.resolve(&did).unwrap();

        assert_eq!(resolved.did, did);
        assert_eq!(resolved.public_key, inception.current_public_key);
        assert!(matches!(
            resolved.method,
            DidMethod::Keri {
                sequence: 0,
                can_rotate: true
            }
        ));

        // Verify round-trip: resolved key → did:key matches ed25519_to_did_key
        let expected_did_key = auths_id::identity::ed25519_to_did_key(&inception.current_public_key);
        let actual_did_key = auths_id::identity::ed25519_to_did_key(&resolved.public_key);
        assert_eq!(actual_did_key, expected_did_key);
    }

    #[test]
    fn resolve_did_keri_after_rotation_returns_new_key() {
        let (dir, inception) = create_keri_repo();
        let did = inception.did();
        let repo = Repository::open(dir.path()).unwrap();

        let rotation = auths_id::keri::rotate_keys(
            &repo,
            &inception.prefix,
            &inception.next_keypair_pkcs8,
            None,
        )
        .unwrap();

        // Update refs/keri/kel to point at the new tip
        let src_ref = format!("refs/did/keri/{}/kel", inception.prefix.as_str());
        let reference = repo.find_reference(&src_ref).unwrap();
        let oid = reference.target().unwrap();
        repo.reference(refs::KERI_KEL_REF, oid, true, "update KEL after rotation")
            .unwrap();

        let resolver = RadicleIdentityResolver::new(dir.path());
        let resolved = resolver.resolve(&did).unwrap();

        assert_eq!(resolved.public_key, rotation.new_current_public_key);
        assert_ne!(resolved.public_key, inception.current_public_key);
        assert!(matches!(
            resolved.method,
            DidMethod::Keri { sequence: 1, .. }
        ));
    }

    #[test]
    fn resolve_did_keri_no_kel_returns_error() {
        let dir = TempDir::new().unwrap();
        let _repo = Repository::init(dir.path()).unwrap();

        let resolver = RadicleIdentityResolver::new(dir.path());
        let result = resolver.resolve("did:keri:EExample123");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_did_keri_corrupt_kel_returns_error() {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        // Write corrupt event data
        let blob_oid = repo.blob(b"not valid json").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(EVENT_BLOB_NAME, blob_oid, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let sig = git2::Signature::now("test", "test@test.com").unwrap();
        let commit_oid = repo
            .commit(None, &sig, &sig, "bad event", &tree, &[])
            .unwrap();
        repo.reference(refs::KERI_KEL_REF, commit_oid, true, "corrupt")
            .unwrap();

        let resolver = RadicleIdentityResolver::new(dir.path());
        let result = resolver.resolve("did:keri:EBogus");
        assert!(result.is_err());
    }

    #[test]
    fn reject_unsupported_did_method() {
        let temp_dir = create_test_repo_with_identity(
            vec!["did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"],
            1,
        );
        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve("did:web:example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_did_key_format() {
        let temp_dir = create_test_repo_with_identity(
            vec!["did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"],
            1,
        );
        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve("did:key:invalid");
        assert!(result.is_err());
    }

    #[test]
    fn missing_identity_ref() {
        let temp_dir = TempDir::new().unwrap();
        let _repo = Repository::init(temp_dir.path()).unwrap();

        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve_identity();
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::RefNotFound { .. })));
    }

    #[test]
    fn empty_delegates() {
        let temp_dir = create_test_repo_with_identity(vec![], 1);
        let resolver = RadicleIdentityResolver::new(temp_dir.path());
        let result = resolver.resolve_identity();
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::NoDelegates)));
    }

    #[test]
    fn resolve_did_keri_with_separate_identity_repo() {
        let (id_dir, inception) = create_keri_repo();
        let did = inception.did();

        // Project repo is separate from identity repo
        let project_dir = TempDir::new().unwrap();
        let _project_repo = Repository::init(project_dir.path()).unwrap();

        let resolver =
            RadicleIdentityResolver::new(project_dir.path()).with_identity_repo(id_dir.path());
        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.public_key, inception.current_public_key);
    }
}
