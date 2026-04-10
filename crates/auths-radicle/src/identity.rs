//! Radicle identity resolver.
//!
//! Resolves Radicle peer identities by reading from `refs/rad/id` and extracting
//! the delegate's Ed25519 public key from the `did:key` format. Also resolves
//! `did:keri:` identifiers by replaying the KERI Key Event Log.

use auths_id::identity::{DidResolver, DidResolverError, ResolvedDid};
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
    /// The controller identity for this device (set when resolving did:key with attestation)
    #[serde(default)]
    pub controller_did: Option<Did>,
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
    ///
    /// Also scans for device attestations to discover the controller identity.
    pub fn resolve_key(&self, did: &Did) -> Result<RadicleIdentity, IdentityError> {
        let _pk = resolve_did_key(did)?;
        let controller_did = self.find_controller_for_device(did);
        Ok(RadicleIdentity {
            did: did.clone(),
            keys: vec![did.clone()],
            sequence: 0,
            is_abandoned: false,
            devices: Vec::new(),
            controller_did,
            keri_state: None,
            document: None,
        })
    }

    /// Resolves a `did:keri:` to a Radicle identity by replaying its KEL.
    ///
    /// Falls back to reading cached key state from the packed registry
    /// when the KEL git ref is not available.
    pub fn resolve_keri(&self, did: &Did) -> Result<RadicleIdentity, IdentityError> {
        let key_state = self
            .resolve_keri_state(did)
            .or_else(|_| self.resolve_keri_state_from_registry(did))?;

        let mut keys = Vec::with_capacity(key_state.current_keys.len());

        for key_str in &key_state.current_keys {
            let keri_pk = auths_keri::KeriPublicKey::parse(key_str.as_str()).map_err(|e| {
                IdentityError::KelValidationFailed(format!("invalid CESR key: {e}"))
            })?;
            let public_key = PublicKey::try_from(keri_pk.into_bytes().as_slice())
                .map_err(|_| IdentityError::InvalidDidKey("key conversion failed".to_string()))?;
            keys.push(Did::from(public_key));
        }

        let is_abandoned = key_state.is_abandoned;
        let devices = self.find_attested_devices();
        Ok(RadicleIdentity {
            did: did.clone(),
            keys,
            sequence: key_state.sequence,
            is_abandoned,
            devices,
            controller_did: Some(did.clone()),
            keri_state: Some(key_state),
            document: None,
        })
    }

    /// Deprecated: use `resolve` instead.
    pub fn resolve_identity_from_did(
        &self,
        did_str: &str,
    ) -> Result<RadicleIdentity, IdentityError> {
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
        let reference =
            repo.find_reference(&namespace_ref)
                .map_err(|_| IdentityError::KelNotFound {
                    ref_path: namespace_ref,
                })?;

        let blob = reference
            .peel_to_blob()
            .map_err(|e| IdentityError::InvalidDocument(format!("peel to blob: {e}")))?;

        let rid_str = std::str::from_utf8(blob.content())
            .map_err(|e| IdentityError::InvalidDocument(format!("invalid UTF-8: {e}")))?
            .trim();

        let rid: RepoId = rid_str.parse().map_err(|e: radicle_core::repo::IdError| {
            IdentityError::InvalidDocument(format!("invalid RID: {e}"))
        })?;

        // Identity repos are stored under the same storage root
        let mut path = self.repo_path.clone();
        path.push(rid.to_string());
        Ok(path)
    }

    /// Finds the controller KERI identity for a device from the packed registry.
    ///
    /// Reads `refs/auths/registry` and looks up the device's attestation
    /// at `v1/devices/{shard}/{sanitized_did}/attestation.json`.
    fn find_controller_for_device(&self, device_did: &Did) -> Option<Did> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        eprintln!(
            "[auths-debug] find_controller_for_device: id_path={}",
            id_path.display()
        );
        let repo = match Repository::open(id_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[auths-debug] Repository::open failed: {e}");
                return None;
            }
        };
        eprintln!("[auths-debug] Repository opened successfully");
        let att = match self.read_device_attestation(&repo, device_did) {
            Some(a) => a,
            None => {
                eprintln!("[auths-debug] read_device_attestation returned None");
                return None;
            }
        };
        eprintln!("[auths-debug] attestation found, issuer={}", att.issuer);
        let result = att.issuer.to_string().parse::<Did>().ok();
        eprintln!(
            "[auths-debug] parsed issuer DID: {:?}",
            result.as_ref().map(|d| d.to_string())
        );
        result
    }

    /// Scans the packed registry for all devices with attestations.
    fn find_attested_devices(&self) -> Vec<Did> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = match Repository::open(id_path) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let registry_tree = match self.registry_tree(&repo) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let devices_entry = match registry_tree.get_path(std::path::Path::new("v1/devices")) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let devices_tree = match repo.find_tree(devices_entry.id()) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();
        self.walk_device_shards(&repo, &devices_tree, &mut result);
        result
    }

    /// Walks the sharded device tree to collect all device DIDs.
    fn walk_device_shards(
        &self,
        repo: &Repository,
        devices_tree: &git2::Tree<'_>,
        out: &mut Vec<Did>,
    ) {
        for s1 in devices_tree.iter() {
            let s1_tree = match s1.to_object(repo).and_then(|o| o.peel_to_tree()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for s2 in s1_tree.iter() {
                let s2_tree = match s2.to_object(repo).and_then(|o| o.peel_to_tree()) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                for device_entry in s2_tree.iter() {
                    if let Some(sanitized_did) = device_entry.name() {
                        let did_str = sanitized_did.replace('_', ":");
                        if let Ok(did) = did_str.parse::<Did>() {
                            out.push(did);
                        }
                    }
                }
            }
        }
    }

    /// Reads a device attestation from the packed registry.
    fn read_device_attestation(
        &self,
        repo: &Repository,
        device_did: &Did,
    ) -> Option<auths_verifier::core::Attestation> {
        let registry_tree = match self.registry_tree(repo) {
            Some(t) => t,
            None => {
                eprintln!("[auths-debug] registry_tree returned None");
                return None;
            }
        };
        let sanitized = device_did.to_string().replace(':', "_");
        let key_part = match sanitized.strip_prefix("did_key_") {
            Some(k) => k,
            None => {
                eprintln!("[auths-debug] strip_prefix(did_key_) failed for: {sanitized}");
                return None;
            }
        };
        if key_part.len() < 4 {
            eprintln!("[auths-debug] key_part too short: {key_part}");
            return None;
        }
        let s1 = &key_part[..2];
        let s2 = &key_part[2..4];
        let att_path = format!("v1/devices/{s1}/{s2}/{sanitized}/attestation.json");
        eprintln!("[auths-debug] looking up att_path: {att_path}");

        let entry = match registry_tree.get_path(std::path::Path::new(&att_path)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[auths-debug] tree.get_path failed: {e}");
                return None;
            }
        };
        let blob = match repo.find_blob(entry.id()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[auths-debug] find_blob failed: {e}");
                return None;
            }
        };
        match serde_json::from_slice(blob.content()) {
            Ok(att) => Some(att),
            Err(e) => {
                eprintln!("[auths-debug] serde_json::from_slice failed: {e}");
                None
            }
        }
    }

    /// Returns the root tree at `refs/auths/registry`.
    fn registry_tree<'r>(&self, repo: &'r Repository) -> Option<git2::Tree<'r>> {
        let reference = match repo.find_reference(REGISTRY_REF) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[auths-debug] find_reference({REGISTRY_REF}) failed: {e}");
                return None;
            }
        };
        let commit = match reference.peel_to_commit() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[auths-debug] peel_to_commit failed: {e}");
                return None;
            }
        };
        match commit.tree() {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("[auths-debug] commit.tree() failed: {e}");
                None
            }
        }
    }

    /// Reads KEL events by walking the commit chain from the given commit.
    fn read_events_from_chain(
        &self,
        repo: &Repository,
        mut commit: git2::Commit<'_>,
    ) -> Result<Vec<Event>, IdentityError> {
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
            let entry = tree
                .get_name(EVENT_BLOB_NAME_CESR)
                .or_else(|| tree.get_name(EVENT_BLOB_NAME_JSON))
                .ok_or_else(|| {
                    IdentityError::KelValidationFailed("missing event blob in KEL commit".into())
                })?;
            let blob = repo
                .find_blob(entry.id())
                .map_err(|e| IdentityError::KelValidationFailed(format!("blob read error: {e}")))?;
            let event: Event = serde_json::from_slice(blob.content()).map_err(|e| {
                IdentityError::KelValidationFailed(format!("invalid event JSON: {e}"))
            })?;
            events.push(event);

            if commit.parent_count() == 0 {
                break;
            }
            commit = commit.parent(0).map_err(|e| {
                IdentityError::KelValidationFailed(format!("parent walk error: {e}"))
            })?;
        }

        events.reverse();
        Ok(events)
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
        let events = self.resolve_kel_events(&repo, did)?;

        if let Some(prefix_str) = did.as_keri_prefix()
            && let Some(Event::Icp(icp)) = events.first()
            && icp.i.as_str() != prefix_str
        {
            return Err(IdentityError::KelValidationFailed(format!(
                "KEL prefix mismatch: expected {prefix_str}, got {}",
                icp.i.as_str()
            )));
        }

        Ok(events)
    }

    pub fn resolve_keri_state(&self, did: &Did) -> Result<KeyState, IdentityError> {
        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = Repository::open(id_path).map_err(|e| IdentityError::Repository {
            path: id_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let events = self.resolve_kel_events(&repo, did)?;
        if events.is_empty() {
            let ref_path = self.kel_ref_for_did(did);
            return Err(IdentityError::KelNotFound { ref_path });
        }

        let key_state =
            replay_kel(&events).map_err(|e| IdentityError::KelValidationFailed(e.to_string()))?;

        if let Some(prefix_str) = did.as_keri_prefix()
            && key_state.prefix.as_str() != prefix_str
        {
            return Err(IdentityError::KelValidationFailed(format!(
                "KEL prefix mismatch: expected {prefix_str}, got {}",
                key_state.prefix.as_str()
            )));
        }

        Ok(key_state)
    }

    /// Reads cached key state from the packed registry.
    ///
    /// Looks up `v1/identities/{s1}/{s2}/{prefix}/state.json` in the
    /// `refs/auths/registry` tree. This is the fallback when the KEL
    /// git ref is not available.
    fn resolve_keri_state_from_registry(&self, did: &Did) -> Result<KeyState, IdentityError> {
        let prefix = did
            .as_keri_prefix()
            .ok_or_else(|| IdentityError::InvalidDidKey("not a KERI DID".into()))?;
        if prefix.len() < 4 {
            return Err(IdentityError::KelNotFound {
                ref_path: format!("registry: prefix too short: {prefix}"),
            });
        }
        let s1 = &prefix[..2];
        let s2 = &prefix[2..4];
        let state_path = format!("v1/identities/{s1}/{s2}/{prefix}/state.json");

        let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
        let repo = Repository::open(id_path).map_err(|e| IdentityError::Repository {
            path: id_path.display().to_string(),
            detail: e.to_string(),
        })?;

        let registry_tree =
            self.registry_tree(&repo)
                .ok_or_else(|| IdentityError::KelNotFound {
                    ref_path: REGISTRY_REF.to_string(),
                })?;

        let entry = registry_tree
            .get_path(std::path::Path::new(&state_path))
            .map_err(|_| IdentityError::KelNotFound {
                ref_path: state_path.clone(),
            })?;

        let blob = repo
            .find_blob(entry.id())
            .map_err(|e| IdentityError::KelValidationFailed(format!("blob read error: {e}")))?;

        #[derive(Deserialize)]
        struct CachedState {
            state: KeyState,
        }

        let cached: CachedState = serde_json::from_slice(blob.content()).map_err(|e| {
            IdentityError::KelValidationFailed(format!("invalid cached state JSON: {e}"))
        })?;

        Ok(cached.state)
    }

    /// Constructs the KEL ref path for a DID.
    ///
    /// Tries the per-prefix format (`refs/did/keri/{PREFIX}/kel`) first,
    /// falling back to the flat layout (`refs/keri/kel`).
    fn kel_ref_for_did(&self, did: &Did) -> String {
        if let Some(prefix) = did.as_keri_prefix() {
            format!("refs/did/keri/{prefix}/kel")
        } else {
            self.layout.keri_kel_ref.clone()
        }
    }

    /// Resolves the raw KERI event log from the repository.
    pub fn resolve_kel_events(
        &self,
        repo: &Repository,
        did: &Did,
    ) -> Result<Vec<Event>, IdentityError> {
        let path = repo.path();

        // Try per-prefix ref first (refs/did/keri/{PREFIX}/kel),
        // then fall back to flat layout (refs/keri/kel).
        let kel_ref = self.kel_ref_for_did(did);
        let reference = match repo.find_reference(&kel_ref) {
            Ok(r) => r,
            Err(_) if kel_ref != self.layout.keri_kel_ref => {
                match repo.find_reference(&self.layout.keri_kel_ref) {
                    Ok(r) => r,
                    Err(e) if e.code() == ErrorCode::NotFound => return Ok(vec![]),
                    Err(e) => {
                        return Err(IdentityError::Repository {
                            path: path.display().to_string(),
                            detail: format!("KEL ref error: {e}"),
                        });
                    }
                }
            }
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(vec![]),
            Err(e) => {
                return Err(IdentityError::Repository {
                    path: path.display().to_string(),
                    detail: format!("KEL ref error: {e}"),
                });
            }
        };

        let commit = reference
            .peel_to_commit()
            .map_err(|e| IdentityError::Repository {
                path: path.display().to_string(),
                detail: format!("KEL ref not a commit: {e}"),
            })?;

        self.read_events_from_chain(repo, commit)
    }
}

const EVENT_BLOB_NAME_CESR: &str = "event.cesr";
const EVENT_BLOB_NAME_JSON: &str = "event.json";
const REGISTRY_REF: &str = "refs/auths/registry";

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
        let did_val: Did = did.parse().map_err(|e: radicle_core::identity::DidError| {
            DidResolverError::InvalidDidKey(e.to_string())
        })?;

        match did_val {
            Did::Key(pk) => Ok(ResolvedDid::Key {
                did: did.to_string(),
                public_key_bytes: pk.as_ref().to_vec(),
            }),
            Did::Keri(_) => {
                let key_state = self.resolve_keri_state(&did_val).map_err(|e| {
                    DidResolverError::Resolution(format!("KERI resolution failed: {e}"))
                })?;

                let cesr_key = key_state
                    .current_keys
                    .first()
                    .ok_or_else(|| DidResolverError::Resolution("no signing keys in KEL".into()))?;

                let keri_pk = auths_keri::KeriPublicKey::parse(cesr_key.as_str())
                    .map_err(|e| DidResolverError::Resolution(format!("invalid CESR key: {e}")))?;

                Ok(ResolvedDid::Keri {
                    did: did.to_string(),
                    public_key_bytes: keri_pk.into_bytes(),
                    sequence: key_state.sequence,
                    can_rotate: key_state.can_rotate(),
                })
            }
        }
    }
}
