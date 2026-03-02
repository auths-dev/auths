//! Radicle identity resolver.
//!
//! Resolves Radicle peer identities by reading from `refs/rad/id` and extracting
//! the delegate's Ed25519 public key from the `did:key` format. Also resolves
//! `did:keri:` identifiers by replaying the KERI Key Event Log.

use auths_id::identity::{DidMethod, DidResolver, DidResolverError, ResolvedDid};
use auths_id::keri::KeyState;
use auths_id::keri::event::Event;
use auths_id::keri::validate::replay_kel;
use git2::{ErrorCode, Repository};
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::refs::Layout;

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

/// A resolved Radicle identity with extracted key material and KERI state.
///
/// This is the single type-safe representation that downstream consumers
/// (radicle-httpd, frontend) depend on for identity display and verification.
///
/// Usage:
/// ```ignore
/// let resolver = RadicleIdentityResolver::new(repo_path);
/// let identity = resolver.resolve("did:keri:EPrefix...")?;
/// assert!(identity.is_keri());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadicleIdentity {
    /// The identity DID (did:key or did:keri)
    pub did: Did,
    /// Current signing keys (as DIDs)
    pub keys: Vec<Did>,
    /// Current sequence number (0 for did:key, KERI sequence for did:keri)
    pub sequence: u64,
    /// Whether the KERI identity has been abandoned (no next-key commitment)
    pub is_abandoned: bool,
    /// Attested device DIDs linked to this identity
    #[serde(default)]
    pub devices: Vec<Did>,
    /// Full KERI key state (if resolved from did:keri)
    pub keri_state: Option<KeyState>,
    /// The original identity document (if resolved from a repository)
    pub document: Option<RadicleIdentityDocument>,
}

impl RadicleIdentity {
    /// Returns `true` if this is a KERI-backed identity.
    pub fn is_keri(&self) -> bool {
        matches!(self.did, Did::Keri(_))
    }
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
    /// Resolves a DID (did:key or did:keri) to a Radicle identity.
    pub fn resolve(&self, did_str: &str) -> Result<RadicleIdentity, IdentityError> {
        let did: Did = did_str.parse()?;

        match did {
            Did::Key(_) => self.resolve_key(&did),
            Did::Keri(_) => self.resolve_keri(&did),
        }
    }

    /// Resolves a `did:key:` to a Radicle identity.
    pub fn resolve_key(&self, did: &Did) -> Result<RadicleIdentity, IdentityError> {
        let _pk = resolve_did_key(did)?;
        Ok(RadicleIdentity {
            did: did.clone(),
            keys: vec![did.clone()],
            sequence: 0,
            is_abandoned: false,
            devices: Vec::new(),
            keri_state: None,
            document: None,
        })
    }

    /// Resolves a `did:keri:` to a Radicle identity by replaying its KEL.
    pub fn resolve_keri(&self, did: &Did) -> Result<RadicleIdentity, IdentityError> {
        let key_state = self.resolve_keri_state(did)?;
        let mut keys = Vec::with_capacity(key_state.current_keys.len());

        for key_str in &key_state.current_keys {
            let keri_pk = auths_crypto::KeriPublicKey::parse(key_str)
                .map_err(|e| IdentityError::KelValidationFailed(format!("invalid CESR key: {e}")))?;
            let public_key = PublicKey::try_from(keri_pk.into_bytes().as_slice())
                .map_err(|_| IdentityError::InvalidDidKey("key conversion failed".to_string()))?;
            keys.push(Did::from(public_key));
        }

        let is_abandoned = key_state.is_abandoned;
        Ok(RadicleIdentity {
            did: did.clone(),
            keys,
            sequence: key_state.sequence,
            is_abandoned,
            devices: Vec::new(),
            keri_state: Some(key_state),
            document: None,
        })
    }

    /// Deprecated: use `resolve` instead.
    pub fn resolve_identity_from_did(&self, did_str: &str) -> Result<RadicleIdentity, IdentityError> {
        self.resolve(did_str)
    }

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

        let mut identity = self.resolve(&primary_did.to_string()).map_err(|e| {
            IdentityError::InvalidDocument(format!("failed to resolve primary delegate: {e}"))
        })?;
        identity.document = Some(document);

        Ok(identity)
    }

    /// Returns the repository path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Finds the identity repository for a given DID by scanning projects.
    pub fn find_identity_repo(&self, did: &Did) -> Result<PathBuf, IdentityError> {
        let prefix = match did {
            Did::Keri(p) => p,
            _ => return Err(IdentityError::InvalidDidKey("Not a KERI DID".into())),
        };

        let repo = Repository::open(&self.repo_path).map_err(|e| IdentityError::Repository {
            path: self.repo_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let namespace_ref = self.layout.identity_rad_id_ref(prefix);
        let reference = repo.find_reference(&namespace_ref).map_err(|_| {
            IdentityError::KelNotFound {
                ref_path: namespace_ref,
            }
        })?;

        let blob = reference
            .peel_to_blob()
            .map_err(|e| IdentityError::InvalidDocument(format!("peel to blob: {e}")))?;

        let rid_str = std::str::from_utf8(blob.content())
            .map_err(|e| IdentityError::InvalidDocument(format!("invalid UTF-8: {e}")))?
            .trim();

        let rid: RepoId = rid_str
            .parse()
            .map_err(|e: radicle_core::repo::IdError| {
                IdentityError::InvalidDocument(format!("invalid RID: {e}"))
            })?;

        // Identity repos are stored under the same storage root
        let mut path = self.repo_path.clone();
        path.push(rid.to_string());
        Ok(path)
    }

    /// Resolves the raw KERI event log for a DID, handling repo discovery.
    ///
    /// Args:
    /// * `did`: The KERI DID whose KEL to retrieve.
    ///
    /// Usage:
    /// ```ignore
    /// let resolver = RadicleIdentityResolver::new(storage_path);
    /// let events = resolver.resolve_kel(&did)?;
    /// ```
    pub fn resolve_kel(&self, did: &Did) -> Result<Vec<Event>, IdentityError> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = Repository::open(id_path).map_err(|e| IdentityError::Repository {
            path: id_path.display().to_string(),
            detail: e.to_string(),
        })?;
        self.resolve_kel_events(&repo)
    }

    pub fn resolve_keri_state(&self, did: &Did) -> Result<KeyState, IdentityError> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = Repository::open(id_path).map_err(|e| IdentityError::Repository {
            path: id_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let events = self.resolve_kel_events(&repo)?;
        if events.is_empty() {
            return Err(IdentityError::KelNotFound {
                ref_path: self.layout.keri_kel_ref.clone(),
            });
        }

        let key_state =
            replay_kel(&events).map_err(|e| IdentityError::KelValidationFailed(e.to_string()))?;

        // Validation: verify prefix matches DID
        if let Some(prefix_str) = did.as_keri_prefix() {
            if key_state.prefix.as_str() != prefix_str {
                return Err(IdentityError::KelValidationFailed(format!(
                    "KEL prefix mismatch: expected {prefix_str}, got {}",
                    key_state.prefix.as_str()
                )));
            }
        }

        Ok(key_state)
    }

    /// Resolves the raw KERI event log from the repository.
    pub fn resolve_kel_events(&self, repo: &Repository) -> Result<Vec<Event>, IdentityError> {
        let path = repo.path();
        let reference = match repo.find_reference(&self.layout.keri_kel_ref) {
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
}

const EVENT_BLOB_NAME: &str = "event.json";

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
        let did_val: Did = did
            .parse()
            .map_err(|e: radicle_core::identity::DidError| {
                DidResolverError::InvalidDidKey(e.to_string())
            })?;

        match did_val {
            Did::Key(pk) => Ok(ResolvedDid {
                did: did.to_string(),
                method: DidMethod::Key,
                public_key: pk.to_vec(),
            }),
            Did::Keri(_) => {
                let key_state = self.resolve_keri_state(&did_val).map_err(|e| {
                    DidResolverError::Resolution(format!("KERI resolution failed: {e}"))
                })?;

                let cesr_key = key_state.current_keys.first().ok_or_else(|| {
                    DidResolverError::Resolution("no signing keys in KEL".into())
                })?;

                let keri_pk = auths_crypto::KeriPublicKey::parse(cesr_key).map_err(|e| {
                    DidResolverError::Resolution(format!("invalid CESR key: {e}"))
                })?;

                Ok(ResolvedDid {
                    did: did.to_string(),
                    method: DidMethod::Keri {
                        sequence: key_state.sequence,
                        can_rotate: key_state.can_rotate(),
                    },
                    public_key: keri_pk.into_bytes().to_vec(),
                })
            }
        }
    }
}
