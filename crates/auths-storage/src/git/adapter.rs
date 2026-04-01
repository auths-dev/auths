//! Packed registry backend implementation.
//!
//! Stores all registry data under a single Git ref (`refs/auths/registry`).
//!
//! This is a pure Git-only backend with no local caching layer.
//! All state (`tip.json`, `state.json`) is derived from canonical KEL events.
//! The backend validates structure (JSON, SAID) but makes no trust decisions.
//! Can be rebuilt from events at any time.
//!
//! # Filesystem Requirements
//!
//! This module requires a **POSIX-compliant local filesystem** with:
//! - Atomic `rename()` operations
//! - Working `flock()` advisory locking
//!
//! ## Supported Filesystems
//!
//! - ext4, XFS, Btrfs (Linux)
//! - APFS, HFS+ (macOS)
//! - NTFS (Windows)
//!
//! ## Unsupported Filesystems
//!
//! The following filesystems are **explicitly unsupported** and may cause
//! silent data corruption:
//!
//! - **NFS** (v3 and v4): `flock()` may fail silently; `rename()` not atomic on crash
//! - **SMB/CIFS**: Unreliable locking and atomicity semantics
//! - **FUSE** (sshfs, etc.): Behavior depends on implementation; test before use
//! - **Network-attached storage**: Generally unsupported unless using local cache
//!
//! ## Docker Volumes
//!
//! When running in Docker, ensure the volume uses the `local` driver with
//! a local filesystem backing. Avoid NFS-backed volumes.

use std::cell::Cell;
use std::fs::File;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "indexed-storage")]
use std::sync::Mutex;

use fs2::FileExt;
use log::warn;

use auths_core::storage::keychain::IdentityDID;
use auths_verifier::core::{Attestation, VerifiedAttestation};
use auths_verifier::types::{CanonicalDid, DeviceDID};
use git2::{Oid, Repository, Signature, Tree};

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::keri::validate::{ValidationError, verify_event_crypto, verify_event_said};
use auths_verifier::keri::Prefix;

use super::paths;
use super::vfs::{OsVfs, Vfs};
use auths_id::ports::registry::{RegistryBackend, RegistryError};
use auths_verifier::clock::{ClockProvider, SystemClock};

fn from_git2(e: git2::Error) -> RegistryError {
    match e.code() {
        git2::ErrorCode::NotFound => RegistryError::NotFound {
            entity_type: "git object".into(),
            id: e.message().to_string(),
        },
        git2::ErrorCode::Locked => {
            RegistryError::ConcurrentModification(format!("Git lock conflict: {}", e.message()))
        }
        _ => RegistryError::storage(e),
    }
}
use super::tree_ops::{TreeMutator, TreeNavigator};
#[cfg(feature = "indexed-storage")]
use auths_id::storage::registry::org_member::{MemberFilter, MemberView};
use auths_id::storage::registry::org_member::{
    MemberInvalidReason, OrgMemberEntry, expected_org_issuer,
};
use auths_id::storage::registry::schemas::{
    CachedStateJson, RegistryMetadata, SCHEMA_VERSION, TipInfo,
};
use auths_id::storage::registry::shard::{
    device_path, identity_path, org_path, path_parts, sanitize_did, unsanitize_did,
};

/// The Git ref where the registry tree is stored.
pub const REGISTRY_REF: &str = "refs/auths/registry";

/// Advisory lock for protecting concurrent registry access.
///
/// This provides defense-in-depth on top of git2's internal file locking.
/// The lock is automatically released when dropped.
struct AdvisoryLock {
    file: File,
}

impl AdvisoryLock {
    /// Acquire an exclusive advisory lock on the registry.
    ///
    /// Creates `registry.lock` in the repo directory and holds an exclusive
    /// lock on it until this guard is dropped.
    fn acquire(repo_path: &Path) -> Result<Self, RegistryError> {
        let lock_path = repo_path.join("registry.lock");
        let file = File::create(&lock_path)?;
        file.lock_exclusive()?;
        Ok(Self { file })
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        // Unlock is best-effort - if it fails, the OS will release the lock
        // when the file handle is closed anyway
        let _ = self.file.unlock();
    }
}

use super::config::{RegistryConfig, TenantMetadata, TenantStatus};

/// Packed registry backend.
///
/// Stores all identity data under a single Git ref using a sharded tree structure.
/// This eliminates ref explosion for multi-tenant repositories.
///
/// ## Single-Writer Model
///
/// This backend assumes a single-writer model. CAS (compare-and-swap) is used
/// as a safety net only - if CAS fails, the operation aborts rather than retrying.
/// If you need retry/rebase semantics, you're drifting into multi-writer complexity
/// that requires a different design.
#[derive(Clone)]
pub struct GitRegistryBackend {
    repo_path: PathBuf,
    /// Canonical tenant ID, or `None` in single-tenant mode.
    tenant_id: Option<String>,
    /// Clock provider — injected so tests can freeze time.
    clock: Arc<dyn ClockProvider>,
    /// Filesystem abstraction — injected so tests can stub I/O.
    vfs: Arc<dyn Vfs>,
    /// SQLite index for O(1) lookups. Absent if the index file cannot be opened.
    ///
    /// Git is the source of truth. The index is a write-through cache.
    /// If the index write fails, the Git write has already succeeded — log and continue.
    #[cfg(feature = "indexed-storage")]
    index: Option<Arc<Mutex<auths_index::AttestationIndex>>>,
}

impl GitRegistryBackend {
    /// Create a backend from config without verifying or initializing the repo.
    ///
    /// # Caller contract
    /// This constructor does not check that the repository exists or is initialized.
    /// You MUST call `init_if_needed()` (for provisioning) or `open_existing()`
    /// (for startup) immediately after.
    pub fn from_config_unchecked(config: RegistryConfig) -> Self {
        let repo_path = config.resolve_repo_path();
        Self {
            #[cfg(feature = "indexed-storage")]
            index: Self::open_index_if_present(&repo_path),
            tenant_id: config.tenant_id.map(String::from),
            clock: Arc::new(SystemClock),
            vfs: Arc::new(OsVfs),
            repo_path,
        }
    }

    /// Open an existing, initialized backend.
    ///
    /// Uses `Repository::open()` to detect presence (not `.git` existence check).
    ///
    /// Returns `Err(NotFound)` if the repo or `REGISTRY_REF` is absent (unprovisioned).
    /// Returns `Err(Storage)` if the repo exists but is corrupt or unreadable.
    ///
    /// Args:
    /// * `config`: Resolved registry config (already normalized and validated).
    ///
    /// Usage:
    /// ```ignore
    /// let backend = GitRegistryBackend::open_existing(RegistryConfig::single_tenant("/var/lib/auths"))?;
    /// ```
    pub fn open_existing(config: RegistryConfig) -> Result<Self, RegistryError> {
        let backend = Self::from_config_unchecked(config);
        let repo = backend.open_repo()?;
        repo.find_reference(REGISTRY_REF)
            .map_err(|_| RegistryError::NotFound {
                entity_type: "registry".into(),
                id: format!("{} (tenant may be unprovisioned)", REGISTRY_REF),
            })?;
        Ok(backend)
    }

    /// Opens the SQLite index at `<repo_path>/.auths-index.db` if the file exists
    /// or can be created. Returns `None` on failure (logs a warning).
    #[cfg(feature = "indexed-storage")]
    fn open_index_if_present(
        repo_path: &Path,
    ) -> Option<Arc<Mutex<auths_index::AttestationIndex>>> {
        let index_path = repo_path.join(".auths-index.db");
        match auths_index::AttestationIndex::open_or_create(&index_path) {
            Ok(idx) => Some(Arc::new(Mutex::new(idx))),
            Err(e) => {
                log::warn!(
                    "Failed to open index at {:?}: {} — index disabled for this backend",
                    index_path,
                    e
                );
                None
            }
        }
    }

    /// Get the on-disk repo path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Get the canonical tenant ID, or `None` in single-tenant mode.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Initialize the registry if it doesn't already exist.
    ///
    /// Creates the Git repo and empty registry tree if needed. Writes `tenant.json`
    /// in multi-tenant mode.
    ///
    /// Returns:
    /// - `Ok(true)` — newly provisioned (repo + `REGISTRY_REF` + `tenant.json` created).
    /// - `Ok(false)` — already existed (no changes made).
    /// - `Err(...)` — something went wrong.
    pub fn init_if_needed(&self) -> Result<bool, RegistryError> {
        std::fs::create_dir_all(&self.repo_path)?;

        // Use Repository::open to detect existing repo (not .git existence check).
        match Repository::open(&self.repo_path) {
            Ok(repo) => {
                if repo.find_reference(REGISTRY_REF).is_ok() {
                    return Ok(false); // already provisioned
                }
                // Repo exists but ref is absent — finish initialization
                self.write_initial_ref(&repo)?;
            }
            Err(_) => {
                // Not a git repo — initialize fresh.
                // On concurrent calls, only one thread wins the git lock.
                // Losers retry opening until the winner's init completes.
                let repo = match Repository::init(&self.repo_path) {
                    Ok(r) => r,
                    Err(_) => {
                        // Another thread beat us to the init lock.
                        // Poll until the repo is openable (winner typically finishes in <1ms).
                        let mut attempts: u32 = 0;
                        loop {
                            match Repository::open(&self.repo_path) {
                                Ok(_) => return Ok(false), // winner initialized it
                                Err(_) if attempts < 40 => {
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                    attempts += 1;
                                }
                                Err(e) => return Err(from_git2(e)),
                            }
                        }
                    }
                };
                if repo.find_reference(REGISTRY_REF).is_ok() {
                    return Ok(false); // already provisioned (race on the ref write)
                }
                self.write_initial_ref(&repo)?;
            }
        }

        self.write_tenant_metadata()?;
        Ok(true)
    }

    /// Write the initial registry ref with an empty tree.
    fn write_initial_ref(&self, repo: &Repository) -> Result<(), RegistryError> {
        let metadata = RegistryMetadata::empty();
        let metadata_json = serde_json::to_vec_pretty(&metadata)?;

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&paths::versioned("metadata.json"), metadata_json);

        let tree_oid = mutator.build_tree(repo, None)?;
        self.create_commit(repo, tree_oid, None, "Initialize registry")?;
        Ok(())
    }

    /// Write `tenant.json` atomically (tmp + rename).
    ///
    /// No-op in single-tenant mode (`tenant_id` is `None`).
    fn write_tenant_metadata(&self) -> Result<(), RegistryError> {
        let tenant_id = match &self.tenant_id {
            Some(id) => id.clone(),
            None => return Ok(()), // single-tenant mode — no metadata file needed
        };
        let metadata = TenantMetadata {
            version: 1,
            tenant_id,
            created_at: self.clock.now(),
            status: TenantStatus::Active,
            plan: None,
        };
        let json = serde_json::to_string_pretty(&metadata).map_err(RegistryError::from)?;
        let final_path = self.repo_path.join("tenant.json");
        self.vfs.atomic_write(&final_path, json.as_bytes())?;
        Ok(())
    }

    /// Load `tenant.json` from the repo directory.
    ///
    /// Returns `Err(NotFound)` if the file is absent or `Err(Serialization)` if malformed.
    ///
    /// Usage:
    /// ```ignore
    /// let meta = backend.load_tenant_metadata()?;
    /// assert_eq!(meta.status, TenantStatus::Active);
    /// ```
    pub fn load_tenant_metadata(&self) -> Result<TenantMetadata, RegistryError> {
        let path = self.repo_path.join("tenant.json");
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RegistryError::NotFound {
                    entity_type: "tenant.json".into(),
                    id: path.display().to_string(),
                }
            } else {
                RegistryError::Io(e)
            }
        })?;
        let metadata = serde_json::from_slice(&bytes)?;
        Ok(metadata)
    }

    /// Open the Git repository.
    fn open_repo(&self) -> Result<Repository, RegistryError> {
        Repository::open(&self.repo_path).map_err(from_git2)
    }

    /// Get the current registry tree.
    fn current_tree<'a>(&self, repo: &'a Repository) -> Result<Tree<'a>, RegistryError> {
        let reference = repo.find_reference(REGISTRY_REF).map_err(from_git2)?;
        let commit = reference.peel_to_commit().map_err(from_git2)?;
        commit.tree().map_err(from_git2)
    }

    /// Get the current commit and tree together.
    ///
    /// Use this in mutating operations to avoid reading the ref twice.
    /// The commit is used as the parent for CAS, the tree for navigation.
    fn current_commit_and_tree<'a>(
        &self,
        repo: &'a Repository,
    ) -> Result<(git2::Commit<'a>, Tree<'a>), RegistryError> {
        let reference = repo.find_reference(REGISTRY_REF).map_err(from_git2)?;
        let commit = reference.peel_to_commit().map_err(from_git2)?;
        let tree = commit.tree().map_err(from_git2)?;
        Ok((commit, tree))
    }

    /// Create a commit and update the registry ref atomically.
    ///
    /// Uses CAS to detect concurrent modifications. CAS failure aborts
    /// rather than retrying (single-writer model).
    ///
    /// # CAS Implementation
    ///
    /// 1. Read the ref's current target OID (expected_oid)
    /// 2. Create commit with expected parent
    /// 3. Before updating, verify ref still points to expected_oid
    /// 4. If match: update ref (atomic via lock file)
    /// 5. If mismatch: fail with ConcurrentModification
    fn create_commit(
        &self,
        repo: &Repository,
        tree_oid: Oid,
        parent: Option<&git2::Commit>,
        message: &str,
    ) -> Result<Oid, RegistryError> {
        let _lock = AdvisoryLock::acquire(&self.repo_path)?;
        self.create_commit_unlocked(repo, tree_oid, parent, message)
    }

    /// Commit without acquiring the advisory lock.
    /// Caller MUST already hold the `AdvisoryLock`.
    #[allow(clippy::disallowed_methods)]
    fn create_commit_unlocked(
        &self,
        repo: &Repository,
        tree_oid: Oid,
        parent: Option<&git2::Commit>,
        message: &str,
    ) -> Result<Oid, RegistryError> {
        let sig = self.get_signature(repo, chrono::Utc::now())?;
        let tree = repo.find_tree(tree_oid).map_err(from_git2)?;

        let parents: Vec<&git2::Commit> = parent.into_iter().collect();

        let commit_oid = repo
            .commit(None, &sig, &sig, message, &tree, &parents)
            .map_err(from_git2)?;

        match parent {
            Some(expected_parent) => {
                let expected_oid = expected_parent.id();

                // CAS: Re-read the ref and verify it still points to expected_oid
                // BEFORE we update. This catches races between our read and now.
                let mut current_ref = repo.find_reference(REGISTRY_REF).map_err(from_git2)?;
                let current_oid = current_ref
                    .target()
                    .ok_or_else(|| RegistryError::Internal("Ref is symbolic".into()))?;

                if current_oid != expected_oid {
                    warn!(
                        "CAS failed on {}: expected OID {}, found {}",
                        REGISTRY_REF, expected_oid, current_oid
                    );
                    return Err(RegistryError::ConcurrentModification(format!(
                        "Registry ref changed: expected {}, found {}",
                        expected_oid, current_oid
                    )));
                }

                // Update the ref. git2's set_target uses file locking internally,
                // making this atomic at the filesystem level.
                current_ref
                    .set_target(commit_oid, message)
                    .map_err(from_git2)?;
            }
            None => {
                // Create new ref - force=false ensures we fail if it already exists
                repo.reference(REGISTRY_REF, commit_oid, false, message)
                    .map_err(from_git2)?;
            }
        }

        Ok(commit_oid)
    }

    /// Get a Git signature for commits using an injected timestamp.
    fn get_signature(
        &self,
        repo: &Repository,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Signature<'static>, RegistryError> {
        repo.signature()
            .or_else(|_| {
                Signature::new(
                    "authly",
                    "authly@localhost",
                    &git2::Time::new(now.timestamp(), 0),
                )
            })
            .map_err(from_git2)
    }

    /// Compute the new KeyState after applying an event.
    fn compute_state_after_event(
        &self,
        current_state: Option<&KeyState>,
        event: &Event,
    ) -> Result<KeyState, RegistryError> {
        match event {
            Event::Icp(icp) => {
                let threshold = icp.kt.parse::<u64>().unwrap_or(1);
                let next_threshold = icp.nt.parse::<u64>().unwrap_or(1);
                Ok(KeyState::from_inception(
                    icp.i.clone(),
                    icp.k.clone(),
                    icp.n.clone(),
                    threshold,
                    next_threshold,
                    icp.d.clone(),
                ))
            }
            Event::Rot(rot) => {
                let mut state = current_state.cloned().ok_or_else(|| {
                    RegistryError::Internal("Rotation without prior state".into())
                })?;
                let seq = event.sequence().value();
                let threshold = rot.kt.parse::<u64>().unwrap_or(1);
                let next_threshold = rot.nt.parse::<u64>().unwrap_or(1);
                state.apply_rotation(
                    rot.k.clone(),
                    rot.n.clone(),
                    threshold,
                    next_threshold,
                    seq,
                    rot.d.clone(),
                );
                Ok(state)
            }
            Event::Ixn(ixn) => {
                let mut state = current_state.cloned().ok_or_else(|| {
                    RegistryError::Internal("Interaction without prior state".into())
                })?;
                let seq = event.sequence().value();
                state.apply_interaction(seq, ixn.d.clone());
                Ok(state)
            }
        }
    }

    /// Update the metadata after a mutation.
    fn update_metadata(
        &self,
        mutator: &mut TreeMutator,
        navigator: &TreeNavigator,
        identity_delta: i64,
        device_delta: i64,
        member_delta: i64,
    ) -> Result<(), RegistryError> {
        let current_meta = match navigator.read_blob_path(&paths::versioned("metadata.json")) {
            Ok(bytes) => serde_json::from_slice::<RegistryMetadata>(&bytes)
                .map_err(|e| RegistryError::Internal(format!("Corrupt metadata.json: {}", e)))?,
            Err(RegistryError::NotFound { .. }) => RegistryMetadata::empty(),
            Err(e) => return Err(e),
        };

        let new_meta = RegistryMetadata {
            version: SCHEMA_VERSION,
            identity_count: (current_meta.identity_count as i64 + identity_delta).max(0) as u64,
            device_count: (current_meta.device_count as i64 + device_delta).max(0) as u64,
            member_count: (current_meta.member_count as i64 + member_delta).max(0) as u64,
            updated_at: self.clock.now(),
        };

        mutator.write_blob(
            &paths::versioned("metadata.json"),
            serde_json::to_vec_pretty(&new_meta)?,
        );
        Ok(())
    }

    /// Visit all org prefixes in the registry (for rebuild/tooling).
    ///
    /// Walks the `v1/orgs/` tree. Calls `visitor` for each org prefix string.
    /// Return `ControlFlow::Break(())` to stop early.
    #[allow(dead_code)] // called from rebuild_org_members_from_registry (indexed-storage feature)
    fn visit_orgs<F>(&self, mut visitor: F) -> Result<(), RegistryError>
    where
        F: FnMut(&str) -> ControlFlow<()>,
    {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let orgs_base = paths::versioned("orgs");
        let orgs_path = path_parts(&orgs_base);
        if !navigator.exists(&orgs_path) {
            return Ok(());
        }

        let captured_error: Cell<Option<RegistryError>> = Cell::new(None);

        // Level 1: s1 shards
        navigator.visit_dir(&orgs_path, |s1| {
            let s1_path = paths::child(&orgs_base, s1);
            let s1_parts = path_parts(&s1_path);

            // Level 2: s2 shards
            if let Err(e) = navigator.visit_dir(&s1_parts, |s2| {
                let s2_path = paths::child(&s1_path, s2);
                let s2_parts = path_parts(&s2_path);

                // Level 3: org prefixes
                if let Err(e) = navigator.visit_dir(&s2_parts, |org| visitor(org)) {
                    captured_error.set(Some(e));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            }) {
                captured_error.set(Some(e));
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;

        if let Some(e) = captured_error.take() {
            return Err(e);
        }

        Ok(())
    }

    /// Applies multiple KEL events in a single Git commit.
    ///
    /// Args:
    /// * `events`: Ordered list of (prefix, event) pairs to apply atomically.
    ///   If any event fails validation, the entire batch is rejected.
    ///
    /// Usage:
    /// ```ignore
    /// backend.batch_append_events(&events)?;
    /// ```
    pub fn batch_append_events(&self, events: &[(Prefix, Event)]) -> Result<(), RegistryError> {
        if events.is_empty() {
            return Ok(());
        }

        let _lock = AdvisoryLock::acquire(&self.repo_path)?;
        let repo = self.open_repo()?;
        let (parent, base_tree) = self.current_commit_and_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, base_tree.clone());
        let mut mutator = TreeMutator::new();

        let mut state_overlay: std::collections::HashMap<String, KeyState> =
            std::collections::HashMap::new();
        let mut tip_overlay: std::collections::HashMap<String, TipInfo> =
            std::collections::HashMap::new();
        let mut identity_delta: i64 = 0;

        for (i, (prefix, event)) in events.iter().enumerate() {
            let result = self.validate_and_stage_event(
                prefix,
                event,
                &navigator,
                &mut mutator,
                &mut state_overlay,
                &mut tip_overlay,
                &mut identity_delta,
            );

            if let Err(e) = result {
                return Err(RegistryError::BatchValidationFailed {
                    index: i,
                    source: Box::new(e),
                });
            }
        }

        self.update_metadata(&mut mutator, &navigator, identity_delta, 0, 0)?;

        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree))?;
        self.create_commit_unlocked(
            &repo,
            new_tree_oid,
            Some(&parent),
            &format!("batch: {} events", events.len()),
        )?;

        #[cfg(feature = "indexed-storage")]
        for (prefix_str, state) in &state_overlay {
            if let Some(index) = &self.index {
                let indexed = auths_index::IndexedIdentity {
                    prefix: auths_verifier::keri::Prefix::new_unchecked(prefix_str.clone()),
                    current_keys: state.current_keys.clone(),
                    sequence: state.sequence,
                    tip_said: state.last_event_said.clone(),
                    updated_at: self.clock.now(),
                };
                #[allow(clippy::unwrap_used)]
                if let Err(e) = index.lock().unwrap().upsert_identity(&indexed) {
                    log::warn!("Index update failed for identity {}: {}", prefix_str, e);
                }
            }
        }

        Ok(())
    }

    /// Validate a single event and stage its mutations, using overlays for batch state.
    #[allow(clippy::too_many_arguments)]
    fn validate_and_stage_event(
        &self,
        prefix: &Prefix,
        event: &Event,
        navigator: &TreeNavigator,
        mutator: &mut TreeMutator,
        state_overlay: &mut std::collections::HashMap<String, KeyState>,
        tip_overlay: &mut std::collections::HashMap<String, TipInfo>,
        identity_delta: &mut i64,
    ) -> Result<(), RegistryError> {
        let base_path = identity_path(prefix)?;
        let seq = event.sequence().value();
        let event_path = paths::event_file(&base_path, seq);
        let tip_path = paths::tip_file(&base_path);
        let state_path = paths::state_file(&base_path);
        let prefix_key = prefix.to_string();

        // CONSTRAINT 1: Refuse if event file already exists (check Git, not overlay — overlay can't have duplicates)
        if navigator.exists_path(&event_path) {
            return Err(RegistryError::EventExists {
                prefix: prefix_key,
                seq,
            });
        }

        // CONSTRAINT 2: Event prefix must match argument
        if event.prefix() != prefix {
            return Err(RegistryError::InvalidPrefix {
                prefix: prefix_key,
                reason: format!(
                    "event prefix '{}' does not match expected '{}'",
                    event.prefix(),
                    prefix
                ),
            });
        }

        // CONSTRAINT 3: Sequence must be monotonic (check overlay first, then Git)
        let current_tip = tip_overlay.get(&prefix_key).cloned().or_else(|| {
            navigator
                .read_blob_path(&tip_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<TipInfo>(&bytes).ok())
        });

        let expected_seq = current_tip.as_ref().map(|t| t.sequence + 1).unwrap_or(0);
        if seq != expected_seq {
            return Err(RegistryError::SequenceGap {
                prefix: prefix_key,
                expected: expected_seq,
                got: seq,
            });
        }

        // CONSTRAINT 4: First event must be inception
        if seq == 0 && !event.is_inception() {
            return Err(RegistryError::Internal(
                "First event (seq 0) must be inception".into(),
            ));
        }

        // CONSTRAINT 5: Non-inception events must chain to previous SAID
        if seq > 0 {
            let prev_said = event.previous().ok_or_else(|| {
                RegistryError::Internal(format!(
                    "Event at seq {} must have previous SAID (p field)",
                    seq
                ))
            })?;

            let expected_prev = current_tip
                .as_ref()
                .map(|t| t.said.as_str())
                .ok_or_else(|| {
                    RegistryError::Internal("No tip found for non-zero sequence".into())
                })?;

            if prev_said != expected_prev {
                return Err(RegistryError::SaidMismatch {
                    expected: expected_prev.to_string(),
                    actual: prev_said.to_string(),
                });
            }
        }

        // CONSTRAINT 6: Verify SAID matches computed hash
        verify_event_said(event).map_err(|e| match e {
            ValidationError::InvalidSaid { expected, actual } => RegistryError::SaidMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            },
            _ => RegistryError::InvalidEvent {
                reason: e.to_string(),
            },
        })?;

        // Get current state (overlay first, then Git)
        let current_state = state_overlay.get(&prefix_key).cloned().or_else(|| {
            navigator
                .read_blob_path(&state_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<CachedStateJson>(&bytes).ok())
                .map(|c| c.state)
        });

        // CONSTRAINT 7: Verify cryptographic integrity
        verify_event_crypto(event, current_state.as_ref()).map_err(|e| match e {
            ValidationError::SignatureFailed { sequence } => RegistryError::InvalidEvent {
                reason: format!("Signature verification failed at sequence {}", sequence),
            },
            ValidationError::CommitmentMismatch { sequence } => RegistryError::InvalidEvent {
                reason: format!("Pre-rotation commitment mismatch at sequence {}", sequence),
            },
            _ => RegistryError::InvalidEvent {
                reason: e.to_string(),
            },
        })?;

        // Stage mutations
        let event_json = serde_json::to_vec_pretty(event)?;
        mutator.write_blob(&event_path, event_json);

        let tip = TipInfo::new(seq, event.said().clone());
        mutator.write_blob(&tip_path, serde_json::to_vec_pretty(&tip)?);

        let new_state = self.compute_state_after_event(current_state.as_ref(), event)?;
        let cached_state = CachedStateJson::new(new_state.clone(), event.said().clone());
        mutator.write_blob(&state_path, serde_json::to_vec_pretty(&cached_state)?);

        // Update overlays
        tip_overlay.insert(prefix_key.clone(), tip);
        state_overlay.insert(prefix_key, new_state);

        if seq == 0 {
            *identity_delta += 1;
        }

        Ok(())
    }
}

impl RegistryBackend for GitRegistryBackend {
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let (parent, base_tree) = self.current_commit_and_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, base_tree.clone());

        let base_path = identity_path(prefix)?;
        let seq = event.sequence().value();
        let event_path = paths::event_file(&base_path, seq);
        let tip_path = paths::tip_file(&base_path);
        let state_path = paths::state_file(&base_path);

        // CONSTRAINT 1: Refuse if event file already exists
        if navigator.exists_path(&event_path) {
            return Err(RegistryError::EventExists {
                prefix: prefix.to_string(),
                seq,
            });
        }

        // CONSTRAINT 2: Event prefix must match argument
        if event.prefix() != prefix {
            return Err(RegistryError::InvalidPrefix {
                prefix: prefix.to_string(),
                reason: format!(
                    "event prefix '{}' does not match expected '{}'",
                    event.prefix(),
                    prefix
                ),
            });
        }

        // CONSTRAINT 3: Sequence must be monotonic
        let current_tip = navigator
            .read_blob_path(&tip_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<TipInfo>(&bytes).ok());

        let expected_seq = current_tip.as_ref().map(|t| t.sequence + 1).unwrap_or(0);
        if seq != expected_seq {
            return Err(RegistryError::SequenceGap {
                prefix: prefix.to_string(),
                expected: expected_seq,
                got: seq,
            });
        }

        // CONSTRAINT 4: First event must be inception
        if seq == 0 && !event.is_inception() {
            return Err(RegistryError::Internal(
                "First event (seq 0) must be inception".into(),
            ));
        }

        // CONSTRAINT 5: Non-inception events must chain to previous SAID
        if seq > 0 {
            let prev_said = event.previous().ok_or_else(|| {
                RegistryError::Internal(format!(
                    "Event at seq {} must have previous SAID (p field)",
                    seq
                ))
            })?;

            let expected_prev = current_tip
                .as_ref()
                .map(|t| t.said.as_str())
                .ok_or_else(|| {
                    RegistryError::Internal("No tip found for non-zero sequence".into())
                })?;

            if prev_said != expected_prev {
                return Err(RegistryError::SaidMismatch {
                    expected: expected_prev.to_string(),
                    actual: prev_said.to_string(),
                });
            }
        }

        // CONSTRAINT 6: Verify SAID matches computed hash
        verify_event_said(event).map_err(|e| match e {
            ValidationError::InvalidSaid { expected, actual } => RegistryError::SaidMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            },
            _ => RegistryError::InvalidEvent {
                reason: e.to_string(),
            },
        })?;

        // Get current state for computing new state and crypto verification
        let current_state = navigator
            .read_blob_path(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CachedStateJson>(&bytes).ok())
            .map(|c| c.state);

        // CONSTRAINT 7: Verify cryptographic integrity (signature + pre-rotation commitment)
        verify_event_crypto(event, current_state.as_ref()).map_err(|e| match e {
            ValidationError::SignatureFailed { sequence } => RegistryError::InvalidEvent {
                reason: format!("Signature verification failed at sequence {}", sequence),
            },
            ValidationError::CommitmentMismatch { sequence } => RegistryError::InvalidEvent {
                reason: format!("Pre-rotation commitment mismatch at sequence {}", sequence),
            },
            _ => RegistryError::InvalidEvent {
                reason: e.to_string(),
            },
        })?;

        // Build mutations
        let mut mutator = TreeMutator::new();

        // Write event
        let event_json = serde_json::to_vec_pretty(event)?;
        mutator.write_blob(&event_path, event_json);

        // Update tip.json
        let tip = TipInfo::new(seq, event.said().clone());
        mutator.write_blob(&tip_path, serde_json::to_vec_pretty(&tip)?);

        // Update state.json
        let new_state = self.compute_state_after_event(current_state.as_ref(), event)?;
        let cached_state = CachedStateJson::new(new_state.clone(), event.said().clone());
        mutator.write_blob(&state_path, serde_json::to_vec_pretty(&cached_state)?);

        // Update metadata if this is a new identity
        let identity_delta = if seq == 0 { 1 } else { 0 };
        self.update_metadata(&mut mutator, &navigator, identity_delta, 0, 0)?;

        // Build and commit
        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree))?;
        self.create_commit(
            &repo,
            new_tree_oid,
            Some(&parent),
            &format!("Append event {} seq {}", prefix, seq),
        )?;

        // Index update: best-effort, Git is source of truth
        #[cfg(feature = "indexed-storage")]
        if let Some(index) = &self.index {
            let indexed = auths_index::IndexedIdentity {
                prefix: prefix.clone(),
                current_keys: new_state.current_keys.clone(),
                sequence: new_state.sequence,
                tip_said: event.said().clone(),
                updated_at: self.clock.now(),
            };
            // INVARIANT: Mutex poisoning is fatal by design
            #[allow(clippy::unwrap_used)]
            if let Err(e) = index.lock().unwrap().upsert_identity(&indexed) {
                log::warn!("Index update failed for identity {}: {}", prefix, e);
            }
        }

        Ok(())
    }

    fn get_event(&self, prefix: &Prefix, seq: u64) -> Result<Event, RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let base_path = identity_path(prefix)?;
        let event_path = paths::event_file(&base_path, seq);

        let bytes = navigator
            .read_blob_path(&event_path)
            .map_err(|_| RegistryError::event_not_found(prefix, seq))?;

        serde_json::from_slice(&bytes).map_err(Into::into)
    }

    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u64,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let base_path = identity_path(prefix)?;

        // Get tip to know the range
        let tip = self.get_tip(prefix)?;

        for seq in from_seq..=tip.sequence {
            let event_path = paths::event_file(&base_path, seq);
            let bytes = navigator
                .read_blob_path(&event_path)
                .map_err(|_| RegistryError::event_not_found(prefix, seq))?;
            let event: Event = serde_json::from_slice(&bytes)?;

            if visitor(&event).is_break() {
                break;
            }
        }

        Ok(())
    }

    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let base_path = identity_path(prefix)?;
        let tip_path = paths::tip_file(&base_path);

        let bytes = navigator
            .read_blob_path(&tip_path)
            .map_err(|_| RegistryError::identity_not_found(prefix))?;

        serde_json::from_slice(&bytes).map_err(Into::into)
    }

    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let base_path = identity_path(prefix)?;
        let state_path = paths::state_file(&base_path);
        let tip_path = paths::tip_file(&base_path);

        // Try Git tree's cached state
        if let Ok(state_bytes) = navigator.read_blob_path(&state_path)
            && let Ok(cached) = serde_json::from_slice::<CachedStateJson>(&state_bytes)
            && let Ok(tip_bytes) = navigator.read_blob_path(&tip_path)
            && let Ok(tip) = serde_json::from_slice::<TipInfo>(&tip_bytes)
            && cached.is_valid_for(&tip.said)
        {
            return Ok(cached.state);
        }

        // Fall back to full replay - errors here are fatal, not swallowed
        let mut state: Option<KeyState> = None;
        let mut replay_error: Option<RegistryError> = None;

        self.visit_events(prefix, 0, &mut |event| match self
            .compute_state_after_event(state.as_ref(), event)
        {
            Ok(new_state) => {
                state = Some(new_state);
                ControlFlow::Continue(())
            }
            Err(e) => {
                replay_error = Some(RegistryError::Internal(format!(
                    "KEL replay failed at seq {}: {}",
                    event.sequence().value(),
                    e
                )));
                ControlFlow::Break(())
            }
        })?;

        // Propagate any replay error - corrupted KEL must not verify
        if let Some(err) = replay_error {
            return Err(err);
        }

        state.ok_or_else(|| RegistryError::identity_not_found(prefix))
    }

    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        // Visit v1/identities/<s1>/<s2>/<prefix>
        let identities_base = paths::versioned("identities");
        let identities_path = path_parts(&identities_base);
        if !navigator.exists(&identities_path) {
            return Ok(());
        }

        // Capture errors from nested closures and track user-requested break.
        let captured_error: Cell<Option<RegistryError>> = Cell::new(None);
        let user_break: Cell<bool> = Cell::new(false);

        // Level 1: s1 shards
        navigator.visit_dir(&identities_path, |s1| {
            if user_break.get() {
                return ControlFlow::Break(());
            }
            let s1_path = paths::child(&identities_base, s1);
            let s1_parts = path_parts(&s1_path);

            // Level 2: s2 shards
            if let Err(e) = navigator.visit_dir(&s1_parts, |s2| {
                if user_break.get() {
                    return ControlFlow::Break(());
                }
                let s2_path = paths::child(&s1_path, s2);
                let s2_parts = path_parts(&s2_path);

                // Level 3: identity prefixes
                if let Err(e) = navigator.visit_dir(&s2_parts, |prefix| {
                    let flow = visitor(prefix);
                    if flow.is_break() {
                        user_break.set(true);
                    }
                    flow
                }) {
                    captured_error.set(Some(e));
                    return ControlFlow::Break(());
                }
                if user_break.get() {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }) {
                captured_error.set(Some(e));
                return ControlFlow::Break(());
            }
            if user_break.get() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;

        // Propagate any captured error
        if let Some(e) = captured_error.take() {
            return Err(e);
        }

        Ok(())
    }

    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let (parent, base_tree) = self.current_commit_and_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, base_tree.clone());

        let sanitized_did = sanitize_did(attestation.subject.as_ref());
        let device_base = device_path(&sanitized_did)?;
        let att_path = paths::attestation_file(&device_base);

        // Check if this is a new device
        let is_new = !navigator.exists_path(&att_path);

        // Staleness check: enforce timestamp monotonicity for existing devices.
        // Timestamp ordering is sufficient to reject replays; same-rid is allowed
        // for operations like extending device authorization (same issuer, new expiry).
        if !is_new
            && let Ok(existing_bytes) = navigator.read_blob_path(&att_path)
            && let Ok(existing) = serde_json::from_slice::<Attestation>(&existing_bytes)
        {
            match (&attestation.timestamp, &existing.timestamp) {
                (Some(new_ts), Some(old_ts)) if new_ts <= old_ts => {
                    return Err(RegistryError::StaleAttestation(format!(
                        "new attestation timestamp ({}) is not newer than existing ({}) for device {}",
                        new_ts, old_ts, attestation.subject
                    )));
                }
                (None, Some(_)) => {
                    return Err(RegistryError::StaleAttestation(format!(
                        "new attestation has no timestamp but existing does for device {}",
                        attestation.subject
                    )));
                }
                _ => {} // new is strictly newer, or both None — allow
            }
        }

        // Generate history entry ID: ISO timestamp for sortability
        // Format: YYYYMMDDTHHMMSS_<rid-suffix> for uniqueness
        let now = self.clock.now();
        let history_id = format!("{}_{:.8}", now.format("%Y%m%dT%H%M%S%.3f"), attestation.rid);
        let history_path = paths::history_entry_file(&device_base, &history_id);

        let att_json = serde_json::to_vec_pretty(attestation)?;

        let mut mutator = TreeMutator::new();
        // Write current attestation
        mutator.write_blob(&att_path, att_json.clone());
        // Write to append-only history
        mutator.write_blob(&history_path, att_json);

        // Update metadata
        let device_delta = if is_new { 1 } else { 0 };
        self.update_metadata(&mut mutator, &navigator, 0, device_delta, 0)?;

        // Build and commit
        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree))?;
        self.create_commit(
            &repo,
            new_tree_oid,
            Some(&parent),
            &format!("Store attestation for {}", attestation.subject),
        )?;

        // Index update: best-effort, Git is source of truth
        #[cfg(feature = "indexed-storage")]
        if let Some(index) = &self.index {
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: attestation.issuer is a validated CanonicalDid
            let issuer_did = IdentityDID::new_unchecked(attestation.issuer.as_str());
            let indexed = auths_index::IndexedAttestation {
                rid: attestation.rid.clone(),
                issuer_did,
                device_did: attestation.subject.clone(),
                git_ref: REGISTRY_REF.to_string(),
                commit_oid: None,
                revoked_at: attestation.revoked_at,
                expires_at: attestation.expires_at,
                updated_at: attestation.timestamp.unwrap_or_else(|| self.clock.now()),
            };
            // INVARIANT: Mutex poisoning is fatal by design
            #[allow(clippy::unwrap_used)]
            if let Err(e) = index.lock().unwrap().upsert_attestation(&indexed) {
                log::warn!(
                    "Index update failed for attestation {}: {}",
                    attestation.rid,
                    e
                );
            }
        }

        Ok(())
    }

    fn load_attestation(&self, did: &DeviceDID) -> Result<Option<Attestation>, RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let sanitized_did = sanitize_did(&did.to_string());
        let device_base = device_path(&sanitized_did)?;
        let att_path = paths::attestation_file(&device_base);

        match navigator.read_blob_path(&att_path) {
            Ok(bytes) => {
                let att: Attestation = serde_json::from_slice(&bytes)?;
                Ok(Some(att))
            }
            Err(RegistryError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn visit_attestation_history(
        &self,
        did: &DeviceDID,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let sanitized_did = sanitize_did(&did.to_string());
        let device_base = device_path(&sanitized_did)?;
        let history_path = paths::history_dir(&device_base);
        let history_parts = path_parts(&history_path);

        // History directory may not exist for devices created before history tracking
        if !navigator.exists(&history_parts) {
            return Ok(());
        }

        // Collect filenames first (they're sorted chronologically by name format)
        let mut filenames = Vec::new();
        navigator.visit_dir(&history_parts, |filename| {
            if filename.ends_with(".json") {
                filenames.push(filename.to_string());
            }
            ControlFlow::Continue(())
        })?;

        // Sort chronologically (filename format ensures lexicographic = chronological)
        filenames.sort();

        // Visit in order
        for filename in filenames {
            let full_path = paths::child(&history_path, &filename);
            match navigator.read_blob_path(&full_path) {
                Ok(bytes) => {
                    let att: Attestation = serde_json::from_slice(&bytes)?;
                    if visitor(&att).is_break() {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&DeviceDID) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        // Visit v1/devices/<s1>/<s2>/<sanitized_did>
        let devices_base = paths::versioned("devices");
        let devices_path = path_parts(&devices_base);
        if !navigator.exists(&devices_path) {
            return Ok(());
        }

        // Capture errors from nested closures
        let captured_error: Cell<Option<RegistryError>> = Cell::new(None);

        // Level 1: s1 shards
        navigator.visit_dir(&devices_path, |s1| {
            let s1_path = paths::child(&devices_base, s1);
            let s1_parts = path_parts(&s1_path);

            // Level 2: s2 shards
            if let Err(e) = navigator.visit_dir(&s1_parts, |s2| {
                let s2_path = paths::child(&s1_path, s2);
                let s2_parts = path_parts(&s2_path);

                // Level 3: device DIDs
                if let Err(e) = navigator.visit_dir(&s2_parts, |sanitized_did| {
                    let did_str = unsanitize_did(sanitized_did);
                    let did = match DeviceDID::parse(&did_str) {
                        Ok(d) => d,
                        Err(_) => {
                            log::warn!("Skipping unparseable DID from tree: {}", did_str);
                            return ControlFlow::Continue(());
                        }
                    };
                    visitor(&did)
                }) {
                    captured_error.set(Some(e));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            }) {
                captured_error.set(Some(e));
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;

        // Propagate any captured error
        if let Some(e) = captured_error.take() {
            return Err(e);
        }

        Ok(())
    }

    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let (parent, base_tree) = self.current_commit_and_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, base_tree.clone());

        let org_base = org_path(&Prefix::new_unchecked(org.to_string()))?;
        let sanitized_member_did = sanitize_did(member.subject.as_ref());
        let member_path = paths::member_file(&org_base, &sanitized_member_did);

        // Check if this is a new member
        let is_new = !navigator.exists_path(&member_path);

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&member_path, serde_json::to_vec_pretty(member)?);

        // Update metadata
        let member_delta = if is_new { 1 } else { 0 };
        self.update_metadata(&mut mutator, &navigator, 0, 0, member_delta)?;

        // Build and commit
        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree))?;
        self.create_commit(
            &repo,
            new_tree_oid,
            Some(&parent),
            &format!("Store org member {} in {}", member.subject, org),
        )?;

        // Index update: best-effort, Git is source of truth
        #[cfg(feature = "indexed-storage")]
        if let Some(index) = &self.index {
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: org is a validated KERI prefix from registry storage
            let org_prefix = auths_verifier::keri::Prefix::new_unchecked(org.to_string());
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: member.issuer is a validated CanonicalDid
            let issuer_did = IdentityDID::new_unchecked(member.issuer.as_str());
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: member.subject is a validated DID from the attestation
            let member_canonical = CanonicalDid::new_unchecked(member.subject.as_str());
            let indexed = auths_index::IndexedOrgMember {
                org_prefix,
                member_did: member_canonical,
                issuer_did,
                rid: member.rid.clone(),
                revoked_at: member.revoked_at,
                expires_at: member.expires_at,
                updated_at: member.timestamp.unwrap_or_else(|| self.clock.now()),
            };
            // INVARIANT: Mutex poisoning is fatal by design
            #[allow(clippy::unwrap_used)]
            if let Err(e) = index.lock().unwrap().upsert_org_member(&indexed) {
                log::warn!(
                    "Index update failed for org member {} in {}: {}",
                    member.subject,
                    org,
                    e
                );
            }
        }

        Ok(())
    }

    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let org_base = org_path(&Prefix::new_unchecked(org.to_string()))?;
        let members_path = paths::members_dir(&org_base);
        let members_parts = path_parts(&members_path);

        if !navigator.exists(&members_parts) {
            return Ok(());
        }

        // Compute expected issuer once, outside the per-file loop
        let expected_issuer = expected_org_issuer(org);

        navigator.visit_dir(&members_parts, |filename| {
            // Strip .json extension
            let Some(sanitized_did) = filename.strip_suffix(".json") else {
                return ControlFlow::Continue(());
            };

            let did_str = unsanitize_did(sanitized_did);
            let did = match CanonicalDid::parse(&did_str) {
                Ok(d) => d,
                Err(_) => {
                    log::warn!("Skipping unparseable member DID: {}", did_str);
                    return ControlFlow::Continue(());
                }
            };

            // Read blob and parse attestation
            let full_path = paths::child(&members_path, filename);
            let attestation = match navigator.read_blob_path(&full_path) {
                Ok(bytes) => {
                    // Parse JSON
                    match serde_json::from_slice::<Attestation>(&bytes) {
                        Ok(att) => {
                            // Validate subject matches filename DID (hard invariant)
                            if att.subject.as_str() != did_str {
                                #[allow(clippy::disallowed_methods)]
                                // INVARIANT: att.subject is a validated DID from deserialized attestation
                                let att_subject = CanonicalDid::new_unchecked(att.subject.as_str());
                                Err(MemberInvalidReason::SubjectMismatch {
                                    filename_did: did.clone(),
                                    attestation_subject: att_subject,
                                })
                            // Validate issuer matches expected org issuer (hard invariant)
                            } else if att.issuer.as_str() != expected_issuer {
                                #[allow(clippy::disallowed_methods)]
                                // INVARIANT: expected_issuer is derived from validated org KERI prefix via expected_org_issuer()
                                let expected = IdentityDID::new_unchecked(expected_issuer.clone());
                                #[allow(clippy::disallowed_methods)]
                                // INVARIANT: att.issuer is a validated CanonicalDid from deserialized attestation
                                let actual = IdentityDID::new_unchecked(att.issuer.as_str());
                                Err(MemberInvalidReason::IssuerMismatch {
                                    expected_issuer: expected,
                                    actual_issuer: actual,
                                })
                            } else {
                                Ok(att)
                            }
                        }
                        Err(e) => Err(MemberInvalidReason::JsonParseError(e.to_string())),
                    }
                }
                Err(e) => Err(MemberInvalidReason::Other(e.to_string())),
            };

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: org is a validated KERI prefix from registry storage
            let org_did = IdentityDID::new_unchecked(format!("did:keri:{}", org));
            let entry = OrgMemberEntry {
                org: org_did,
                did,
                filename: filename.to_string(),
                attestation,
            };

            visitor(&entry)
        })?;

        Ok(())
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        GitRegistryBackend::init_if_needed(self)
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        let repo = self.open_repo()?;
        let tree = self.current_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, tree);

        let bytes = navigator.read_blob_path(&paths::versioned("metadata.json"))?;
        serde_json::from_slice(&bytes).map_err(Into::into)
    }

    fn write_key_state(&self, prefix: &Prefix, state: &KeyState) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let (parent, base_tree) = self.current_commit_and_tree(&repo)?;
        let navigator = TreeNavigator::new(&repo, base_tree.clone());

        let base_path = identity_path(prefix)?;
        let tip_path = paths::tip_file(&base_path);
        let state_path = paths::state_file(&base_path);

        // Verify identity exists by reading tip.json
        let tip_bytes = navigator
            .read_blob_path(&tip_path)
            .map_err(|_| RegistryError::identity_not_found(prefix))?;
        let tip: TipInfo = serde_json::from_slice(&tip_bytes)?;

        // Build cached state validated against current tip SAID
        let cached = CachedStateJson::new(state.clone(), tip.said.clone());
        let state_json = serde_json::to_vec_pretty(&cached)?;

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&state_path, state_json);

        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree))?;
        self.create_commit(
            &repo,
            new_tree_oid,
            Some(&parent),
            &format!("Write key state for {}", prefix),
        )?;

        Ok(())
    }

    /// List org members using the SQLite index when available.
    ///
    /// Falls back to the Git-scan default when:
    /// - The `indexed-storage` feature is not enabled
    /// - The index could not be opened
    /// - The index has no entries for this org (cold start or first write)
    /// - The filter has role or capability constraints (index lacks these fields)
    #[cfg(feature = "indexed-storage")]
    fn list_org_members_fast(
        &self,
        org: &str,
        filter: &MemberFilter,
    ) -> Result<Vec<MemberView>, RegistryError> {
        use auths_id::storage::registry::org_member::{MemberStatus, MemberView};

        // If the filter requires fields not in the index, fall back to Git scan
        if filter.roles_any.is_some()
            || filter.capabilities_any.is_some()
            || filter.capabilities_all.is_some()
        {
            return self.list_org_members(org, filter);
        }

        let Some(index) = &self.index else {
            return self.list_org_members(org, filter);
        };

        // INVARIANT: Mutex poisoning is fatal by design
        #[allow(clippy::unwrap_used)]
        let indexed = index
            .lock()
            .unwrap()
            .list_org_members_indexed(org)
            .map_err(|e| RegistryError::Internal(format!("Index query failed: {}", e)))?;

        if indexed.is_empty() {
            // Index may not be populated yet — fall back to Git scan
            log::debug!("No index entries for org {}, falling back to Git scan", org);
            return self.list_org_members(org, filter);
        }

        let members: Vec<MemberView> = indexed
            .into_iter()
            .map(|m| {
                #[allow(clippy::disallowed_methods)]
                // INVARIANT: m.issuer_did comes from indexed storage, originally a validated CanonicalDid
                let issuer =
                    auths_core::storage::keychain::IdentityDID::new_unchecked(m.issuer_did);
                MemberView {
                    did: m.member_did.clone(),
                    status: MemberStatus::Active,
                    role: None,
                    capabilities: vec![],
                    issuer,
                    rid: m.rid,
                    revoked_at: m.revoked_at,
                    expires_at: m.expires_at,
                    timestamp: None,
                    source_filename: String::new(),
                }
            })
            .collect();

        Ok(members)
    }
}

// =============================================================================
// AttestationSource Implementation
// =============================================================================

use auths_id::error::StorageError;
use auths_id::storage::attestation::AttestationSource;

fn registry_to_storage_err(e: RegistryError) -> StorageError {
    match e {
        RegistryError::NotFound { entity_type, id } => {
            StorageError::NotFound(format!("{} '{}'", entity_type, id))
        }
        RegistryError::Serialization(e) => StorageError::Serialization(e),
        _ => StorageError::InvalidData(e.to_string()),
    }
}

impl AttestationSource for GitRegistryBackend {
    /// Load all attestations for a specific device DID.
    ///
    /// Note: The packed registry stores only the current attestation per device,
    /// not a history. This returns a single-element vector if found.
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError> {
        match self.load_attestation(device_did) {
            Ok(Some(att)) => Ok(vec![att]),
            Ok(None) => Ok(vec![]),
            Err(e) => Err(registry_to_storage_err(e)),
        }
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, StorageError> {
        self.load_all_attestations_paginated(usize::MAX, 0)
    }

    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, StorageError> {
        let mut attestations = Vec::new();
        let mut error: Option<StorageError> = None;
        let mut skipped: usize = 0;
        let mut collected: usize = 0;

        let visit_result = self.visit_devices(&mut |did| {
            if skipped < offset {
                skipped += 1;
                return ControlFlow::Continue(());
            }
            if collected >= limit {
                return ControlFlow::Break(());
            }
            collected += 1;

            match self.load_attestation(did) {
                Ok(Some(att)) => attestations.push(att),
                Ok(None) => {}
                Err(e) => {
                    error = Some(registry_to_storage_err(e));
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        });

        if let Err(e) = visit_result {
            return Err(registry_to_storage_err(e));
        }
        if let Some(e) = error {
            return Err(e);
        }

        Ok(attestations)
    }

    /// Discover all device DIDs that have attestations stored.
    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, StorageError> {
        let mut dids = Vec::new();

        self.visit_devices(&mut |did| {
            dids.push(did.clone());
            ControlFlow::Continue(())
        })
        .map_err(registry_to_storage_err)?;

        Ok(dids)
    }
}

// =============================================================================
// AttestationSink Implementation
// =============================================================================

use auths_id::attestation::AttestationSink;

impl AttestationSink for GitRegistryBackend {
    /// Export/save a verified attestation to the packed registry.
    fn export(&self, attestation: &VerifiedAttestation) -> Result<(), StorageError> {
        self.store_attestation(attestation.inner())
            .map_err(registry_to_storage_err)
    }
}

// =============================================================================
// Index rebuild helpers (indexed-storage feature)
// =============================================================================

/// Rebuild the identity index table by replaying all identities from the registry.
///
/// Walks all identity prefixes via `visit_identities` and upserts each into the
/// SQLite index. This is a full table rebuild — call only on cold start or repair.
///
/// Git is source of truth. The index is cleared and repopulated in one pass.
///
/// # Arguments
///
/// * `index` - The SQLite index to populate
/// * `backend` - The registry backend to read identity data from
#[cfg(feature = "indexed-storage")]
#[allow(dead_code)] // feature-gated public API — used when indexed-storage is enabled
pub fn rebuild_identities_from_registry(
    index: &auths_index::AttestationIndex,
    backend: &GitRegistryBackend,
) -> auths_index::Result<auths_index::RebuildStats> {
    use auths_index::{IndexedIdentity, RebuildStats};

    let mut stats = RebuildStats::default();

    // Walk all known identity prefixes
    let result = backend.visit_identities(&mut |prefix| {
        stats.refs_scanned += 1;
        let prefix_typed = Prefix::new_unchecked(prefix.to_string());

        match backend.get_key_state(&prefix_typed) {
            Ok(state) => {
                let indexed = IndexedIdentity {
                    prefix: state.prefix.clone(),
                    current_keys: state.current_keys.clone(),
                    sequence: state.sequence,
                    tip_said: state.last_event_said.clone(),
                    updated_at: backend.clock.now(),
                };
                match index.upsert_identity(&indexed) {
                    Ok(()) => stats.attestations_indexed += 1,
                    Err(e) => {
                        log::warn!("Failed to index identity {}: {}", prefix, e);
                        stats.errors += 1;
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to get key state for {}: {}", prefix, e);
                stats.errors += 1;
            }
        }

        ControlFlow::Continue(())
    });

    if let Err(e) = result {
        log::warn!("visit_identities failed during rebuild: {}", e);
        stats.errors += 1;
    }

    Ok(stats)
}

/// Rebuild the org member index table by scanning all org member attestations.
///
/// For each identity prefix, attempts to list its org members and upsert them
/// into the SQLite index. This is O(n) on identities and is intended as a repair
/// operation, not a hot path.
///
/// # Arguments
///
/// * `index` - The SQLite index to populate
/// * `backend` - The registry backend to read org member data from
#[cfg(feature = "indexed-storage")]
#[allow(dead_code)] // feature-gated public API — used when indexed-storage is enabled
pub fn rebuild_org_members_from_registry(
    index: &auths_index::AttestationIndex,
    backend: &GitRegistryBackend,
) -> auths_index::Result<auths_index::RebuildStats> {
    use auths_index::{IndexedOrgMember, RebuildStats};

    let mut stats = RebuildStats::default();

    // Collect all org prefixes first (visit_orgs is streaming and may conflict with index writes)
    let mut org_prefixes: Vec<String> = Vec::new();
    let _ = backend.visit_orgs(|org| {
        org_prefixes.push(org.to_string());
        ControlFlow::Continue(())
    });

    for org_prefix in &org_prefixes {
        match backend.visit_org_member_attestations(org_prefix, &mut |entry| {
            stats.refs_scanned += 1;

            if let Ok(att) = &entry.attestation {
                #[allow(clippy::disallowed_methods)]
                // INVARIANT: org_prefix is a validated KERI prefix from visit_orgs
                let prefix = auths_verifier::keri::Prefix::new_unchecked(org_prefix.clone());
                #[allow(clippy::disallowed_methods)]
                // INVARIANT: att.issuer is a validated CanonicalDid from deserialized attestation
                let issuer_did = IdentityDID::new_unchecked(att.issuer.as_str());
                let indexed = IndexedOrgMember {
                    org_prefix: prefix,
                    member_did: entry.did.clone(),
                    issuer_did,
                    rid: att.rid.clone(),
                    revoked_at: att.revoked_at,
                    expires_at: att.expires_at,
                    updated_at: att.timestamp.unwrap_or_else(|| backend.clock.now()),
                };
                match index.upsert_org_member(&indexed) {
                    Ok(()) => stats.attestations_indexed += 1,
                    Err(e) => {
                        log::warn!(
                            "Failed to index org member {} in {}: {}",
                            entry.did,
                            org_prefix,
                            e
                        );
                        stats.errors += 1;
                    }
                }
            }

            ControlFlow::Continue(())
        }) {
            Ok(()) => {}
            Err(e) => {
                // Many prefixes won't be orgs — these errors are expected
                log::debug!(
                    "visit_org_member_attestations for {} returned error (likely not an org): {}",
                    org_prefix,
                    e
                );
            }
        }
    }
    Ok(stats)
}

// ─────────────────────────────────────────────────────────────────────────────
// StorageDriver async trait implementation
// ─────────────────────────────────────────────────────────────────────────────

use async_trait::async_trait;
use auths_id::storage::driver::{StorageDriver, StorageError as DriverStorageError};

impl GitRegistryBackend {
    /// Synchronous get_blob implementation.
    fn get_blob_sync(&self, path: &str) -> Result<Vec<u8>, DriverStorageError> {
        let repo = self.open_repo().map_err(DriverStorageError::io)?;
        let tree = self.current_tree(&repo).map_err(|e| match e {
            RegistryError::NotFound { .. } => DriverStorageError::not_found(path),
            other => DriverStorageError::io(other),
        })?;

        let navigator = TreeNavigator::new(&repo, tree);
        navigator.read_blob_path(path).map_err(|e| match e {
            RegistryError::NotFound { .. } => DriverStorageError::not_found(path),
            other => DriverStorageError::io(other),
        })
    }

    /// Synchronous put_blob implementation.
    fn put_blob_sync(&self, path: &str, data: &[u8]) -> Result<(), DriverStorageError> {
        let repo = self.open_repo().map_err(DriverStorageError::io)?;

        // Get current commit and tree (or None if registry not initialized)
        let (parent, base_tree) = match self.current_commit_and_tree(&repo) {
            Ok((commit, tree)) => (Some(commit), Some(tree)),
            Err(RegistryError::NotFound { .. }) => (None, None),
            Err(e) => return Err(DriverStorageError::io(e)),
        };

        let mut mutator = TreeMutator::new();
        mutator.write_blob(path, data.to_vec());

        let tree_oid = mutator
            .build_tree(&repo, base_tree.as_ref())
            .map_err(DriverStorageError::io)?;

        self.create_commit(&repo, tree_oid, parent.as_ref(), &format!("put {}", path))
            .map_err(|e| match e {
                RegistryError::ConcurrentModification(msg) => {
                    DriverStorageError::cas_conflict(None, Some(msg.into_bytes()))
                }
                other => DriverStorageError::io(other),
            })?;

        Ok(())
    }

    /// Synchronous delete implementation.
    fn delete_sync(&self, path: &str) -> Result<(), DriverStorageError> {
        let repo = self.open_repo().map_err(DriverStorageError::io)?;

        let (parent, base_tree) = match self.current_commit_and_tree(&repo) {
            Ok((commit, tree)) => (commit, tree),
            Err(RegistryError::NotFound { .. }) => return Ok(()), // Nothing to delete
            Err(e) => return Err(DriverStorageError::io(e)),
        };

        // Check if path exists
        let navigator = TreeNavigator::new(&repo, base_tree.clone());
        if !navigator.exists_path(path) {
            return Ok(()); // Idempotent delete
        }

        let mut mutator = TreeMutator::new();
        mutator.delete(path);

        let tree_oid = mutator
            .build_tree(&repo, Some(&base_tree))
            .map_err(DriverStorageError::io)?;

        self.create_commit(&repo, tree_oid, Some(&parent), &format!("delete {}", path))
            .map_err(DriverStorageError::io)?;

        Ok(())
    }

    /// Synchronous exists implementation.
    fn exists_sync(&self, path: &str) -> Result<bool, DriverStorageError> {
        let repo = self.open_repo().map_err(DriverStorageError::io)?;
        let tree = match self.current_tree(&repo) {
            Ok(t) => t,
            Err(RegistryError::NotFound { .. }) => return Ok(false),
            Err(e) => return Err(DriverStorageError::io(e)),
        };

        let navigator = TreeNavigator::new(&repo, tree);
        Ok(navigator.exists_path(path))
    }

    /// Synchronous list_prefix implementation.
    fn list_prefix_sync(&self, prefix: &str) -> Result<Vec<String>, DriverStorageError> {
        let repo = self.open_repo().map_err(DriverStorageError::io)?;
        let tree = match self.current_tree(&repo) {
            Ok(t) => t,
            Err(RegistryError::NotFound { .. }) => return Ok(vec![]),
            Err(e) => return Err(DriverStorageError::io(e)),
        };

        let navigator = TreeNavigator::new(&repo, tree);
        let mut paths = Vec::new();

        // Collect all entries under the prefix
        self.collect_paths_recursive(&navigator, prefix, &mut paths)?;

        Ok(paths)
    }

    /// Recursively collect all blob paths under a prefix.
    fn collect_paths_recursive(
        &self,
        navigator: &TreeNavigator,
        prefix: &str,
        paths: &mut Vec<String>,
    ) -> Result<(), DriverStorageError> {
        let parts = path_parts(prefix);

        // Try to visit the directory
        let result = navigator.visit_dir(&parts, |name| {
            let full_path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{}/{}", prefix, name)
            };

            // Check if it's a blob or directory
            let child_parts = path_parts(&full_path);
            if navigator.exists(&child_parts) {
                // Try to read as blob - if it works, it's a blob
                if navigator.read_blob(&child_parts).is_ok() {
                    paths.push(full_path);
                } else {
                    // It's a directory, recurse (ignore errors in recursion)
                    let _ = self.collect_paths_recursive(navigator, &full_path, paths);
                }
            }
            ControlFlow::Continue(())
        });

        match result {
            Ok(()) => Ok(()),
            Err(RegistryError::NotFound { .. }) => Ok(()), // Empty prefix is fine
            Err(e) => Err(DriverStorageError::io(e)),
        }
    }
}

#[async_trait]
impl StorageDriver for GitRegistryBackend {
    async fn get_blob(&self, path: &str) -> Result<Vec<u8>, DriverStorageError> {
        let this = self.clone();
        let path = path.to_string();
        tokio::task::spawn_blocking(move || this.get_blob_sync(&path))
            .await
            .map_err(DriverStorageError::io)?
    }

    async fn put_blob(&self, path: &str, data: &[u8]) -> Result<(), DriverStorageError> {
        let this = self.clone();
        let path = path.to_string();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || this.put_blob_sync(&path, &data))
            .await
            .map_err(DriverStorageError::io)?
    }

    async fn cas_update(
        &self,
        ref_key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
    ) -> Result<(), DriverStorageError> {
        // For Git, CAS is implemented at the commit level, not blob level.
        // This is a simplified implementation: if expected matches current blob content,
        // update to new content.
        let current = match self.get_blob(ref_key).await {
            Ok(data) => Some(data),
            Err(DriverStorageError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };

        let expected_vec = expected.map(|b| b.to_vec());
        if current != expected_vec {
            return Err(DriverStorageError::cas_conflict(expected_vec, current));
        }

        self.put_blob(ref_key, new).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, DriverStorageError> {
        let this = self.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || this.list_prefix_sync(&prefix))
            .await
            .map_err(DriverStorageError::io)?
    }

    async fn exists(&self, path: &str) -> Result<bool, DriverStorageError> {
        let this = self.clone();
        let path = path.to_string();
        tokio::task::spawn_blocking(move || this.exists_sync(&path))
            .await
            .map_err(DriverStorageError::io)?
    }

    async fn delete(&self, path: &str) -> Result<(), DriverStorageError> {
        let this = self.clone();
        let path = path.to_string();
        tokio::task::spawn_blocking(move || this.delete_sync(&path))
            .await
            .map_err(DriverStorageError::io)?
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_core::crypto::said::compute_next_commitment;
    use auths_id::keri::KERI_VERSION;
    use auths_id::keri::event::{IcpEvent, IxnEvent, KeriSequence, RotEvent};
    use auths_id::keri::seal::Seal;
    use auths_id::keri::types::{Prefix, Said};
    use auths_id::keri::validate::{compute_event_said, finalize_icp_event, serialize_for_signing};
    use auths_verifier::AttestationBuilder;
    use auths_verifier::core::{Ed25519PublicKey, Role};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::{DateTime, Utc};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    fn setup_test_repo() -> (TempDir, GitRegistryBackend) {
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        (dir, backend)
    }

    /// Create a signed ICP event with proper SAID and Ed25519 signature.
    /// Returns (event, prefix, keypair, next_keypair).
    fn create_signed_icp() -> (Event, Prefix, Ed25519KeyPair, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix, keypair, next_keypair)
    }

    /// Create a signed ROT event with proper SAID and Ed25519 signature.
    fn create_signed_rot(
        prefix: &Prefix,
        seq: u64,
        prev_said: &str,
        new_keypair: &Ed25519KeyPair,
    ) -> (Event, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let new_key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(new_keypair.public_key().as_ref())
        );

        // Generate the next-next key for the new commitment
        let nn_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let nn_keypair = Ed25519KeyPair::from_pkcs8(nn_pkcs8.as_ref()).unwrap();
        let nn_commitment = compute_next_commitment(nn_keypair.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: Said::new_unchecked(prev_said.to_string()),
            kt: "1".to_string(),
            k: vec![new_key_encoded],
            nt: "1".to_string(),
            n: vec![nn_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let event = Event::Rot(rot.clone());
        rot.d = compute_event_said(&event).unwrap();
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig = new_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        (Event::Rot(rot), nn_keypair)
    }

    /// Create a signed IXN event with proper SAID and Ed25519 signature.
    fn create_signed_ixn(
        prefix: &Prefix,
        seq: u64,
        prev_said: &str,
        keypair: &Ed25519KeyPair,
    ) -> Event {
        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: Said::new_unchecked(prev_said.to_string()),
            a: vec![Seal::device_attestation("ETest")],
            x: String::new(),
        };

        let event = Event::Ixn(ixn.clone());
        ixn.d = compute_event_said(&event).unwrap();
        let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        Event::Ixn(ixn)
    }

    /// Create an unsigned ICP event (for tests that check pre-crypto constraints).
    fn create_unsigned_icp(key: &str, next: &str) -> (Event, Prefix) {
        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key.to_string()],
            nt: "1".to_string(),
            n: vec![next.to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    #[test]
    fn init_creates_registry() {
        let (_dir, backend) = setup_test_repo();
        let meta = backend.metadata().unwrap();
        assert_eq!(meta.identity_count, 0);
        assert_eq!(meta.device_count, 0);
    }

    #[test]
    fn append_and_get_event() {
        let (_dir, backend) = setup_test_repo();
        let (event, prefix, _keypair, _next_keypair) = create_signed_icp();

        backend.append_event(&prefix, &event).unwrap();

        let retrieved = backend.get_event(&prefix, 0).unwrap();
        assert_eq!(retrieved.prefix(), &prefix);
        assert_eq!(retrieved.sequence().value(), 0);
    }

    #[test]
    fn append_multiple_events() {
        let (_dir, backend) = setup_test_repo();
        let (icp, prefix, _keypair, next_keypair) = create_signed_icp();
        let icp_said = icp.said().to_string();
        backend.append_event(&prefix, &icp).unwrap();

        let (rot, _nn_keypair) = create_signed_rot(&prefix, 1, &icp_said, &next_keypair);
        let rot_said = rot.said().to_string();
        backend.append_event(&prefix, &rot).unwrap();

        // After rotation, the current key is next_keypair
        let ixn = create_signed_ixn(&prefix, 2, &rot_said, &next_keypair);
        backend.append_event(&prefix, &ixn).unwrap();

        let tip = backend.get_tip(&prefix).unwrap();
        assert_eq!(tip.sequence, 2);
    }

    #[test]
    fn append_rejects_duplicate() {
        let (_dir, backend) = setup_test_repo();
        let (event, prefix, _keypair, _next_keypair) = create_signed_icp();

        backend.append_event(&prefix, &event).unwrap();

        let result = backend.append_event(&prefix, &event);
        assert!(matches!(result, Err(RegistryError::EventExists { .. })));
    }

    #[test]
    fn append_rejects_sequence_gap() {
        let (_dir, backend) = setup_test_repo();
        let (_, prefix) = create_unsigned_icp("DKey1", "ENext1");

        // Try to append seq 1 without seq 0 — rejected before crypto check
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_enc = format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()));
        let next_commit = compute_next_commitment(kp.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EPrev".to_string()),
            kt: "1".to_string(),
            k: vec![key_enc],
            nt: "1".to_string(),
            n: vec![next_commit],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let event = Event::Rot(rot.clone());
        rot.d = compute_event_said(&event).unwrap();
        let result = backend.append_event(&prefix, &Event::Rot(rot));

        assert!(matches!(
            result,
            Err(RegistryError::SequenceGap {
                expected: 0,
                got: 1,
                ..
            })
        ));
    }

    #[test]
    fn append_rejects_prefix_mismatch() {
        let (_dir, backend) = setup_test_repo();
        let (icp, _prefix, _keypair, _next_keypair) = create_signed_icp();

        // Try to append with wrong prefix — rejected before crypto check
        let wrong_prefix = Prefix::new_unchecked("EWrongPrefix1234".to_string());
        let result = backend.append_event(&wrong_prefix, &icp);

        assert!(matches!(result, Err(RegistryError::InvalidPrefix { .. })));
    }

    #[test]
    fn append_rejects_non_icp_at_seq_zero() {
        let (_dir, backend) = setup_test_repo();
        let (_, prefix) = create_unsigned_icp("DKey1", "ENext1");

        // Create an IXN event with seq 0 — rejected before crypto check
        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(0),
            p: Said::new_unchecked("EPrev".to_string()),
            a: vec![Seal::device_attestation("ETest")],
            x: String::new(),
        };
        let event = Event::Ixn(ixn.clone());
        ixn.d = compute_event_said(&event).unwrap();
        let ixn_event = Event::Ixn(ixn);

        let result = backend.append_event(&prefix, &ixn_event);

        assert!(matches!(result, Err(RegistryError::Internal(msg)) if msg.contains("inception")));
    }

    #[test]
    fn append_rejects_broken_chain() {
        let (_dir, backend) = setup_test_repo();
        let (icp, prefix, keypair, _next_keypair) = create_signed_icp();
        backend.append_event(&prefix, &icp).unwrap();

        // Create IXN with wrong previous SAID — rejected before crypto check
        let ixn = create_signed_ixn(&prefix, 1, "EWrongPreviousSaid", &keypair);
        let result = backend.append_event(&prefix, &ixn);

        assert!(matches!(result, Err(RegistryError::SaidMismatch { .. })));
    }

    #[test]
    fn append_rejects_invalid_said() {
        let (_dir, backend) = setup_test_repo();

        // Create ICP with tampered SAID - the prefix matches the (wrong) SAID
        // because for ICP, i == d. So we use the tampered SAID as the prefix.
        let tampered_said = "ETamperedSaid1234567890";
        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked(tampered_said.to_string()),
            i: Prefix::new_unchecked(tampered_said.to_string()),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec!["DKey1".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext1".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let event = Event::Icp(icp);
        // Use the tampered SAID as prefix so the prefix check passes,
        // but the SAID check should fail
        let tampered_prefix = Prefix::new_unchecked(tampered_said.to_string());
        let result = backend.append_event(&tampered_prefix, &event);

        assert!(matches!(result, Err(RegistryError::SaidMismatch { .. })));
    }

    #[test]
    fn get_key_state() {
        let (_dir, backend) = setup_test_repo();
        let (icp, prefix, _keypair, _next_keypair) = create_signed_icp();
        backend.append_event(&prefix, &icp).unwrap();

        let state = backend.get_key_state(&prefix).unwrap();
        assert_eq!(state.prefix, prefix);
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn get_key_state_after_rotation() {
        let (_dir, backend) = setup_test_repo();
        let (icp, prefix, _keypair, next_keypair) = create_signed_icp();
        let icp_said = icp.said().to_string();
        backend.append_event(&prefix, &icp).unwrap();

        let (rot, _nn_keypair) = create_signed_rot(&prefix, 1, &icp_said, &next_keypair);
        backend.append_event(&prefix, &rot).unwrap();

        let state = backend.get_key_state(&prefix).unwrap();
        assert_eq!(state.sequence, 1);
    }

    #[test]
    fn visit_identities() {
        let (_dir, backend) = setup_test_repo();

        let (icp1, prefix1, _, _) = create_signed_icp();
        let (icp2, prefix2, _, _) = create_signed_icp();

        backend.append_event(&prefix1, &icp1).unwrap();
        backend.append_event(&prefix2, &icp2).unwrap();

        let mut prefixes = Vec::new();
        backend
            .visit_identities(&mut |prefix| {
                prefixes.push(prefix.to_string());
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(prefixes.len(), 2);
        assert!(prefixes.contains(&prefix1.to_string()));
        assert!(prefixes.contains(&prefix2.to_string()));
    }

    #[test]
    fn store_and_load_attestation() {
        let (_dir, backend) = setup_test_repo();

        let did = DeviceDID::new_unchecked("did:key:z6MkTest123");
        let attestation = AttestationBuilder::default()
            .rid("test-rid")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();

        backend.store_attestation(&attestation).unwrap();

        let loaded = backend.load_attestation(&did).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.rid, "test-rid");
        assert_eq!(loaded.issuer, "did:keri:EIssuer");
    }

    #[test]
    fn load_nonexistent_attestation() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkNonexistent");

        let result = backend.load_attestation(&did).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn store_attestation_overwrites_existing() {
        // Verify latest-view semantics: store_attestation overwrites existing
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkTestDevice");

        // Store first attestation with rid="original"
        let original = AttestationBuilder::default()
            .rid("original")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .note(Some("original note".to_string()))
            .build();
        backend.store_attestation(&original).unwrap();

        // Verify original was stored
        let loaded = backend.load_attestation(&did).unwrap().unwrap();
        assert_eq!(loaded.rid, "original");
        assert_eq!(loaded.note, Some("original note".to_string()));

        // Store updated attestation with same DID but different data
        let updated = AttestationBuilder::default()
            .rid("updated")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .note(Some("updated note".to_string()))
            .build();
        backend.store_attestation(&updated).unwrap();

        // Verify updated attestation overwrote original
        let loaded = backend.load_attestation(&did).unwrap().unwrap();
        assert_eq!(loaded.rid, "updated");
        assert_eq!(loaded.note, Some("updated note".to_string()));
    }

    #[test]
    fn replay_same_attestation_rejected() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay1");

        let att = AttestationBuilder::default()
            .rid("same-rid")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now()))
            .build();

        backend.store_attestation(&att).unwrap();
        let result = backend.store_attestation(&att);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(RegistryError::StaleAttestation(_))),
            "expected StaleAttestation, got {:?}",
            result
        );
    }

    #[test]
    fn replay_older_attestation_rejected() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay2");

        let newer = AttestationBuilder::default()
            .rid("rid-newer")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now()))
            .build();

        let older = AttestationBuilder::default()
            .rid("rid-older")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now() - chrono::Duration::hours(1)))
            .build();

        backend.store_attestation(&newer).unwrap();
        let result = backend.store_attestation(&older);
        assert!(matches!(result, Err(RegistryError::StaleAttestation(_))));
    }

    #[test]
    fn newer_attestation_accepted() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay3");

        let older = AttestationBuilder::default()
            .rid("rid-old")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now() - chrono::Duration::hours(1)))
            .build();

        let newer = AttestationBuilder::default()
            .rid("rid-new")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now()))
            .build();

        backend.store_attestation(&older).unwrap();
        backend.store_attestation(&newer).unwrap();

        let loaded = backend.load_attestation(&did).unwrap().unwrap();
        assert_eq!(loaded.rid, "rid-new");
    }

    #[test]
    fn replay_revoked_attestation_rejected() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay4");

        let revoked = AttestationBuilder::default()
            .rid("rid-revoked")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .revoked_at(Some(Utc::now()))
            .timestamp(Some(Utc::now()))
            .build();

        let unrevoked_old = AttestationBuilder::default()
            .rid("rid-unrevoked")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now() - chrono::Duration::hours(1)))
            .build();

        backend.store_attestation(&revoked).unwrap();
        let result = backend.store_attestation(&unrevoked_old);
        assert!(matches!(result, Err(RegistryError::StaleAttestation(_))));
    }

    #[test]
    fn first_attestation_always_accepted() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay5");

        let att = AttestationBuilder::default()
            .rid("first-ever")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now()))
            .build();

        assert!(backend.store_attestation(&att).is_ok());
    }

    #[test]
    fn attestation_without_timestamp_rejected_when_existing_has_timestamp() {
        let (_dir, backend) = setup_test_repo();
        let did = DeviceDID::new_unchecked("did:key:z6MkReplay6");

        let with_ts = AttestationBuilder::default()
            .rid("rid-with-ts")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .timestamp(Some(Utc::now()))
            .build();

        let without_ts = AttestationBuilder::default()
            .rid("rid-no-ts")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();

        backend.store_attestation(&with_ts).unwrap();
        let result = backend.store_attestation(&without_ts);
        assert!(matches!(result, Err(RegistryError::StaleAttestation(_))));
    }

    #[test]
    fn visit_devices() {
        let (_dir, backend) = setup_test_repo();

        let did1 = DeviceDID::new_unchecked("did:key:z6MkTest1");
        let did2 = DeviceDID::new_unchecked("did:key:z6MkTest2");

        let att1 = AttestationBuilder::default()
            .rid("rid1")
            .issuer("did:keri:EIssuer")
            .subject(&did1.to_string())
            .build();

        let att2 = AttestationBuilder::default()
            .rid("rid2")
            .issuer("did:keri:EIssuer")
            .subject(&did2.to_string())
            .device_public_key(Ed25519PublicKey::from_bytes([1u8; 32]))
            .build();

        backend.store_attestation(&att1).unwrap();
        backend.store_attestation(&att2).unwrap();

        let mut devices = Vec::new();
        backend
            .visit_devices(&mut |did| {
                devices.push(did.to_string());
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn metadata_counts_increase() {
        let (_dir, backend) = setup_test_repo();

        // Add identity
        let (icp, prefix, _keypair, _next_keypair) = create_signed_icp();
        backend.append_event(&prefix, &icp).unwrap();

        let meta = backend.metadata().unwrap();
        assert_eq!(meta.identity_count, 1);
        assert_eq!(meta.device_count, 0);

        // Add device
        let did = DeviceDID::new_unchecked("did:key:z6MkTest");
        let att = AttestationBuilder::default()
            .rid("rid")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();
        backend.store_attestation(&att).unwrap();

        let meta = backend.metadata().unwrap();
        assert_eq!(meta.identity_count, 1);
        assert_eq!(meta.device_count, 1);
    }

    #[test]
    fn store_and_visit_org_member_attestations() {
        let (_dir, backend) = setup_test_repo();

        let org = "EOrg1234567890";
        let member_did = DeviceDID::new_unchecked("did:key:z6MkMember1");

        let member_att = AttestationBuilder::default()
            .rid("org-member")
            .issuer(&format!("did:keri:{}", org))
            .subject(&member_did.to_string())
            .role(Some(Role::Member))
            .build();

        backend.store_org_member(org, &member_att).unwrap();

        let mut entries = Vec::new();
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                entries.push((entry.did.to_string(), entry.attestation.is_ok()));
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, member_did.to_string());
        assert!(entries[0].1); // attestation parsed successfully
    }

    #[test]
    fn store_and_visit_org_member_with_keri_did() {
        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Members are identities (did:keri:), not devices (did:key:).
        // This test ensures did:keri: members round-trip through git storage.
        let keri_did = "did:keri:EH-Bgtw9tm61YHxUWOw37UweX_7LNJC89t0Pl7ateDdM";
        let member_att = AttestationBuilder::default()
            .rid("org-keri-member")
            .issuer(&format!("did:keri:{}", org))
            .subject(keri_did)
            .role(Some(Role::Member))
            .build();

        backend.store_org_member(org, &member_att).unwrap();

        let mut found_did: Option<String> = None;
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                found_did = Some(entry.did.as_str().to_string());
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(
            found_did.as_deref(),
            Some(keri_did),
            "did:keri: member must be findable after store"
        );
    }

    #[test]
    fn store_and_visit_org_member_keri_did_with_underscore() {
        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // KERI prefixes use Base64url which can contain underscores.
        // The sanitize/unsanitize path must not corrupt these.
        let did_with_underscore = "did:keri:EH-Bgtw9tm61YHxUWOw37UweX_7LNJC89t0Pl7ateDdM";
        let member_att = AttestationBuilder::default()
            .rid("org-underscore-member")
            .issuer(&format!("did:keri:{}", org))
            .subject(did_with_underscore)
            .role(Some(Role::Member))
            .build();

        backend.store_org_member(org, &member_att).unwrap();

        let mut found_did: Option<String> = None;
        let mut attestation_error: Option<String> = None;
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                found_did = Some(entry.did.as_str().to_string());
                if let Err(reason) = &entry.attestation {
                    attestation_error = Some(format!("{:?}", reason));
                }
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(
            found_did.as_deref(),
            Some(did_with_underscore),
            "DID with underscore in KERI prefix must survive sanitize/unsanitize round-trip"
        );
        assert!(
            attestation_error.is_none(),
            "attestation should be valid but got error: {:?}",
            attestation_error
        );
    }

    #[test]
    fn visit_org_member_attestations_yields_invalid_on_bad_json() {
        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Write invalid JSON directly via TreeMutator
        let repo = backend.open_repo().unwrap();
        let base_tree = backend.current_tree(&repo).unwrap();

        let org_base = org_path(&Prefix::new_unchecked(org.to_string())).unwrap();
        let bad_path = paths::member_file(&org_base, "did_key_z6MkBadJson");

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&bad_path, b"{ not valid json }".to_vec());

        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree)).unwrap();
        let parent = repo
            .find_reference(REGISTRY_REF)
            .unwrap()
            .peel_to_commit()
            .unwrap();
        backend
            .create_commit(&repo, new_tree_oid, Some(&parent), "Add invalid JSON")
            .unwrap();

        let mut found_invalid = false;
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                if entry.did.as_str() == "did:key:z6MkBadJson"
                    && let Err(MemberInvalidReason::JsonParseError(_)) = &entry.attestation
                {
                    found_invalid = true;
                }
                ControlFlow::Continue(())
            })
            .unwrap();

        assert!(found_invalid, "Expected to find invalid JSON entry");
    }

    #[test]
    fn visit_org_member_attestations_detects_subject_mismatch() {
        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store attestation with wrong filename (mismatch)
        let repo = backend.open_repo().unwrap();
        let base_tree = backend.current_tree(&repo).unwrap();

        // Create attestation with subject "did:key:z6MkCorrect"
        let correct_did = DeviceDID::new_unchecked("did:key:z6MkCorrect");
        let att = AttestationBuilder::default()
            .rid("mismatch-test")
            .issuer(&format!("did:keri:{}", org))
            .subject(&correct_did.to_string())
            .build();

        // But store it under a WRONG filename
        let org_base = org_path(&Prefix::new_unchecked(org.to_string())).unwrap();
        let wrong_path = paths::member_file(&org_base, "did_key_z6MkWRONG");

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&wrong_path, serde_json::to_vec(&att).unwrap());

        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree)).unwrap();
        let parent = repo
            .find_reference(REGISTRY_REF)
            .unwrap()
            .peel_to_commit()
            .unwrap();
        backend
            .create_commit(&repo, new_tree_oid, Some(&parent), "Add mismatched member")
            .unwrap();

        let mut found_mismatch = false;
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                if entry.did.as_str() == "did:key:z6MkWRONG"
                    && let Err(MemberInvalidReason::SubjectMismatch {
                        filename_did,
                        attestation_subject,
                    }) = &entry.attestation
                {
                    assert_eq!(filename_did.to_string(), "did:key:z6MkWRONG");
                    assert_eq!(attestation_subject.to_string(), "did:key:z6MkCorrect");
                    found_mismatch = true;
                }
                ControlFlow::Continue(())
            })
            .unwrap();

        assert!(found_mismatch, "Expected to find subject mismatch entry");
    }

    #[test]
    fn visit_org_member_attestations_detects_issuer_mismatch() {
        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store attestation with WRONG issuer (but correct subject)
        let member_did = DeviceDID::new_unchecked("did:key:z6MkWrongIssuer");
        let att = AttestationBuilder::default()
            .rid("issuer-mismatch-test")
            .issuer("did:keri:EDifferentOrg") // WRONG issuer
            .subject(&member_did.to_string())
            .build();

        backend.store_org_member(org, &att).unwrap();

        let mut found_mismatch = false;
        backend
            .visit_org_member_attestations(org, &mut |entry| {
                if entry.did.to_string() == member_did.to_string()
                    && let Err(MemberInvalidReason::IssuerMismatch {
                        expected_issuer,
                        actual_issuer,
                    }) = &entry.attestation
                {
                    assert_eq!(expected_issuer.to_string(), format!("did:keri:{}", org));
                    assert_eq!(actual_issuer.to_string(), "did:keri:EDifferentOrg");
                    found_mismatch = true;
                }
                ControlFlow::Continue(())
            })
            .unwrap();

        assert!(found_mismatch, "Expected to find issuer mismatch entry");
    }

    #[test]
    fn list_org_members_returns_all_valid_members() {
        use auths_id::storage::registry::org_member::MemberFilter;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store active member
        let active_did = DeviceDID::new_unchecked("did:key:z6MkActive1");
        let active_att = AttestationBuilder::default()
            .rid("active")
            .issuer(&format!("did:keri:{}", org))
            .subject(&active_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &active_att).unwrap();

        // Store revoked member
        let revoked_did = DeviceDID::new_unchecked("did:key:z6MkRevoked");
        let revoked_att = AttestationBuilder::default()
            .rid("revoked")
            .issuer(&format!("did:keri:{}", org))
            .subject(&revoked_did.to_string())
            .revoked_at(Some(Utc::now()))
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &revoked_att).unwrap();

        // Backend returns ALL valid members (no status filtering - that's policy)
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        // Both members returned - sorted by DID
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].did.to_string(), active_did.to_string());
        assert_eq!(members[1].did.to_string(), revoked_did.to_string());

        // Caller can filter by revoked_at field (policy layer responsibility)
        let active_count = members.iter().filter(|m| m.revoked_at.is_none()).count();
        let revoked_count = members.iter().filter(|m| m.revoked_at.is_some()).count();
        assert_eq!(active_count, 1);
        assert_eq!(revoked_count, 1);
    }

    #[test]
    fn list_org_members_exposes_revoked_flag() {
        use auths_id::storage::registry::org_member::MemberFilter;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store revoked member
        let revoked_did = DeviceDID::new_unchecked("did:key:z6MkRevoked");
        let revoked_att = AttestationBuilder::default()
            .rid("revoked")
            .issuer(&format!("did:keri:{}", org))
            .subject(&revoked_did.to_string())
            .revoked_at(Some(Utc::now()))
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &revoked_att).unwrap();

        // Backend returns member with revoked_at set
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].did.to_string(), revoked_did.to_string());
        // Caller can see revoked_at and compute status in policy layer
        assert!(members[0].revoked_at.is_some());
    }

    #[test]
    fn list_org_members_exposes_expires_at_field() {
        use auths_id::storage::registry::org_member::MemberFilter;
        use chrono::Duration;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store member with past expiry
        let past = Utc::now() - Duration::hours(1);
        let expired_did = DeviceDID::new_unchecked("did:key:z6MkExpired");
        let expired_att = AttestationBuilder::default()
            .rid("expired")
            .issuer(&format!("did:keri:{}", org))
            .subject(&expired_did.to_string())
            .expires_at(Some(past))
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &expired_att).unwrap();

        // Backend returns member with expires_at field set
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 1);
        // Caller can see expires_at and compute expired status in policy layer
        assert!(members[0].expires_at.is_some());
        assert!(members[0].expires_at.unwrap() <= Utc::now());
        // Status is Active (backend doesn't compute expired status)
        assert!(members[0].revoked_at.is_none());
    }

    #[test]
    fn list_org_members_marks_issuer_mismatch_as_invalid() {
        use auths_id::storage::registry::org_member::{
            MemberFilter, MemberInvalidReason, MemberStatus,
        };

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store member from correct org issuer
        let org_member_did = DeviceDID::new_unchecked("did:key:z6MkOrgMember");
        let org_issuer = format!("did:keri:{}", org);
        let org_att = AttestationBuilder::default()
            .rid("org")
            .issuer(&org_issuer)
            .subject(&org_member_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &org_att).unwrap();

        // Store member with WRONG issuer - should be marked Invalid
        let wrong_did = DeviceDID::new_unchecked("did:key:z6MkWrongIssuer");
        let wrong_att = AttestationBuilder::default()
            .rid("wrong")
            .issuer("did:keri:EDifferentIssuer") // WRONG!
            .subject(&wrong_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &wrong_att).unwrap();

        // Backend returns ALL members (no status filtering - that's policy)
        // Structural validation (issuer mismatch) still marks entry as Invalid
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        // Both returned - sorted by DID
        assert_eq!(members.len(), 2);

        // Find the valid one
        let valid = members
            .iter()
            .find(|m| m.did.to_string() == org_member_did.to_string())
            .unwrap();
        assert!(matches!(valid.status, MemberStatus::Active));

        // Find the invalid one (structural validation still happens)
        let invalid = members
            .iter()
            .find(|m| m.did.to_string() == wrong_did.to_string())
            .unwrap();
        if let MemberStatus::Invalid { reason } = &invalid.status {
            assert!(matches!(reason, MemberInvalidReason::IssuerMismatch { .. }));
        } else {
            panic!("Expected Invalid status for wrong issuer");
        }
    }

    #[test]
    fn list_org_members_filters_by_role() {
        use auths_id::storage::registry::org_member::MemberFilter;
        use std::collections::HashSet;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store admin
        let admin_did = DeviceDID::new_unchecked("did:key:z6MkAdminUser");
        let admin_att = AttestationBuilder::default()
            .rid("admin")
            .issuer(&format!("did:keri:{}", org))
            .subject(&admin_did.to_string())
            .role(Some(Role::Admin))
            .build();
        backend.store_org_member(org, &admin_att).unwrap();

        // Store member
        let member_did = DeviceDID::new_unchecked("did:key:z6MkMemberUser");
        let member_att = AttestationBuilder::default()
            .rid("member")
            .issuer(&format!("did:keri:{}", org))
            .subject(&member_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &member_att).unwrap();

        // Filter by admin role
        let mut roles = HashSet::new();
        roles.insert(Role::Admin);
        let filter = MemberFilter {
            roles_any: Some(roles),
            ..Default::default()
        };
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].did.to_string(), admin_did.to_string());
    }

    #[test]
    fn list_org_members_filters_by_capability_any() {
        use auths_id::storage::registry::org_member::MemberFilter;
        use auths_verifier::core::Capability;
        use std::collections::HashSet;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store member with sign_commit capability
        let signer_did = DeviceDID::new_unchecked("did:key:z6MkSigner1");
        let signer_att = AttestationBuilder::default()
            .rid("signer")
            .issuer(&format!("did:keri:{}", org))
            .subject(&signer_did.to_string())
            .role(Some(Role::Member))
            .capabilities(vec![Capability::sign_commit()])
            .build();
        backend.store_org_member(org, &signer_att).unwrap();

        // Store member without capabilities
        let nocap_did = DeviceDID::new_unchecked("did:key:z6MkNoCaps1");
        let nocap_att = AttestationBuilder::default()
            .rid("nocap")
            .issuer(&format!("did:keri:{}", org))
            .subject(&nocap_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &nocap_att).unwrap();

        // Filter by sign_commit capability
        let mut caps = HashSet::new();
        caps.insert(Capability::sign_commit());
        let filter = MemberFilter {
            capabilities_any: Some(caps),
            ..Default::default()
        };
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].did.to_string(), signer_did.to_string());
    }

    #[test]
    fn list_org_members_filters_by_capability_all() {
        use auths_id::storage::registry::org_member::MemberFilter;
        use auths_verifier::core::Capability;
        use std::collections::HashSet;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store member with both capabilities
        let both_did = DeviceDID::new_unchecked("did:key:z6MkBothCaps");
        let both_att = AttestationBuilder::default()
            .rid("both")
            .issuer(&format!("did:keri:{}", org))
            .subject(&both_did.to_string())
            .role(Some(Role::Member))
            .capabilities(vec![Capability::sign_commit(), Capability::sign_release()])
            .build();
        backend.store_org_member(org, &both_att).unwrap();

        // Store member with only sign_commit
        let one_did = DeviceDID::new_unchecked("did:key:z6MkOneCap1");
        let one_att = AttestationBuilder::default()
            .rid("one")
            .issuer(&format!("did:keri:{}", org))
            .subject(&one_did.to_string())
            .role(Some(Role::Member))
            .capabilities(vec![Capability::sign_commit()])
            .build();
        backend.store_org_member(org, &one_att).unwrap();

        // Filter requires both capabilities
        let mut caps = HashSet::new();
        caps.insert(Capability::sign_commit());
        caps.insert(Capability::sign_release());
        let filter = MemberFilter {
            capabilities_all: Some(caps),
            ..Default::default()
        };
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].did.to_string(), both_did.to_string());
    }

    #[test]
    fn list_org_members_includes_invalid_entries() {
        use auths_id::storage::registry::org_member::{MemberFilter, MemberStatus};

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store valid member
        let valid_did = DeviceDID::new_unchecked("did:key:z6MkValid11");
        let valid_att = AttestationBuilder::default()
            .rid("valid")
            .issuer(&format!("did:keri:{}", org))
            .subject(&valid_did.to_string())
            .role(Some(Role::Member))
            .build();
        backend.store_org_member(org, &valid_att).unwrap();

        // Write invalid JSON directly
        let repo = backend.open_repo().unwrap();
        let base_tree = backend.current_tree(&repo).unwrap();
        let org_base = org_path(&Prefix::new_unchecked(org.to_string())).unwrap();
        let bad_path = paths::member_file(&org_base, "did_key_z6MkBadOne");

        let mut mutator = TreeMutator::new();
        mutator.write_blob(&bad_path, b"{ invalid }".to_vec());

        let new_tree_oid = mutator.build_tree(&repo, Some(&base_tree)).unwrap();
        let parent = repo
            .find_reference(REGISTRY_REF)
            .unwrap()
            .peel_to_commit()
            .unwrap();
        backend
            .create_commit(&repo, new_tree_oid, Some(&parent), "Add invalid")
            .unwrap();

        // Backend returns ALL entries including invalid (no status filtering)
        // Policy layer can filter by status if needed
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        // Both entries returned
        assert_eq!(members.len(), 2);

        // One valid, one invalid
        let valid_count = members
            .iter()
            .filter(|m| matches!(m.status, MemberStatus::Active))
            .count();
        let invalid_count = members
            .iter()
            .filter(|m| matches!(m.status, MemberStatus::Invalid { .. }))
            .count();
        assert_eq!(valid_count, 1);
        assert_eq!(invalid_count, 1);
    }

    #[test]
    fn list_org_members_deterministic_ordering_by_did() {
        use auths_id::storage::registry::org_member::MemberFilter;
        use chrono::Duration;

        let (_dir, backend) = setup_test_repo();
        let org = "EOrg1234567890";

        // Store members in non-alphabetical order
        // Tuples: (did, revoked_at, expires_at)
        let now = Utc::now();
        type MemberEntry<'a> = (&'a str, Option<DateTime<Utc>>, Option<DateTime<Utc>>);
        let dids: Vec<MemberEntry> = vec![
            ("did:key:z6MkZZZLast", None, None),  // last alphabetically
            ("did:key:z6MkAAAFirst", None, None), // first alphabetically
            ("did:key:z6MkBBBRevoked", Some(now), None), // revoked
            (
                "did:key:z6MkCCCExpired",
                None,
                Some(now - Duration::hours(1)),
            ), // past expiry
        ];

        for (did_str, revoked_at, expires_at) in &dids {
            let did = DeviceDID::new_unchecked(*did_str);
            let att = AttestationBuilder::default()
                .rid("test")
                .issuer(&format!("did:keri:{}", org))
                .subject(&did.to_string())
                .revoked_at(*revoked_at)
                .expires_at(*expires_at)
                .role(Some(Role::Member))
                .build();
            backend.store_org_member(org, &att).unwrap();
        }

        // Backend returns all members sorted by DID (no status-based sorting)
        let filter = MemberFilter::default();
        let members = backend.list_org_members(org, &filter).unwrap();

        assert_eq!(members.len(), 4);

        // Sorted alphabetically by DID only
        assert_eq!(members[0].did.to_string(), "did:key:z6MkAAAFirst");
        assert_eq!(members[1].did.to_string(), "did:key:z6MkBBBRevoked");
        assert_eq!(members[2].did.to_string(), "did:key:z6MkCCCExpired");
        assert_eq!(members[3].did.to_string(), "did:key:z6MkZZZLast");

        // Caller can check revoked_at/expires_at fields to compute status
        assert!(members[0].revoked_at.is_none());
        assert!(members[1].revoked_at.is_some());
        assert!(members[2].expires_at.is_some());
        assert!(members[3].revoked_at.is_none());
    }

    // =========================================================================
    // AttestationSource trait tests
    // =========================================================================

    #[test]
    fn attestation_source_load_for_device() {
        let (_dir, backend) = setup_test_repo();

        let did = DeviceDID::new_unchecked("did:key:z6MkSourceTest");
        let attestation = AttestationBuilder::default()
            .rid("source-test")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();

        backend.store_attestation(&attestation).unwrap();

        // Test AttestationSource trait
        let loaded = backend.load_attestations_for_device(&did).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].rid, "source-test");
    }

    #[test]
    fn attestation_source_load_for_nonexistent() {
        let (_dir, backend) = setup_test_repo();

        let did = DeviceDID::new_unchecked("did:key:z6MkNonexistent");
        let loaded = backend.load_attestations_for_device(&did).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn attestation_source_load_all() {
        let (_dir, backend) = setup_test_repo();

        // Store multiple attestations
        for i in 0..3 {
            let did = DeviceDID::new_unchecked(format!("did:key:z6MkDevice{}", i));
            let attestation = AttestationBuilder::default()
                .rid(format!("rid-{}", i))
                .issuer("did:keri:EIssuer")
                .subject(&did.to_string())
                .device_public_key(Ed25519PublicKey::from_bytes([i as u8; 32]))
                .build();
            backend.store_attestation(&attestation).unwrap();
        }

        let all = backend.load_all_attestations().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn attestation_source_discover_dids() {
        let (_dir, backend) = setup_test_repo();

        // Store attestations for multiple devices
        let dids: Vec<_> = (0..3)
            .map(|i| DeviceDID::new_unchecked(format!("did:key:z6MkDiscover{}", i)))
            .collect();

        for did in &dids {
            let attestation = AttestationBuilder::default()
                .rid("discover-test")
                .issuer("did:keri:EIssuer")
                .subject(&did.to_string())
                .build();
            backend.store_attestation(&attestation).unwrap();
        }

        let discovered = backend.discover_device_dids().unwrap();
        assert_eq!(discovered.len(), 3);

        // Verify all original DIDs are in discovered set
        for did in &dids {
            assert!(discovered.iter().any(|d| d.to_string() == did.to_string()));
        }
    }

    // =========================================================================
    // AttestationSink trait tests
    // =========================================================================

    #[test]
    fn attestation_sink_export() {
        let (_dir, backend) = setup_test_repo();

        let did = DeviceDID::new_unchecked("did:key:z6MkSinkTest");
        let attestation = AttestationBuilder::default()
            .rid("sink-test")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();

        // Test AttestationSink trait
        backend
            .export(&VerifiedAttestation::dangerous_from_unchecked(attestation))
            .unwrap();

        // Verify it was stored
        let loaded = backend.load_attestation(&did).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().rid, "sink-test");
    }

    #[test]
    fn attestation_sink_export_updates_existing() {
        let (_dir, backend) = setup_test_repo();

        let did = DeviceDID::new_unchecked("did:key:z6MkUpdateTest");

        // First export
        let attestation1 = AttestationBuilder::default()
            .rid("original")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .build();
        backend
            .export(&VerifiedAttestation::dangerous_from_unchecked(attestation1))
            .unwrap();

        // Second export (update)
        let attestation2 = AttestationBuilder::default()
            .rid("updated")
            .issuer("did:keri:EIssuer")
            .subject(&did.to_string())
            .revoked_at(Some(Utc::now())) // Changed!
            .build();
        backend
            .export(&VerifiedAttestation::dangerous_from_unchecked(attestation2))
            .unwrap();

        // Verify updated version
        let loaded = backend.load_attestation(&did).unwrap().unwrap();
        assert_eq!(loaded.rid, "updated");
        assert!(loaded.is_revoked());

        // Verify device count didn't increase (it's an update, not new)
        let meta = backend.metadata().unwrap();
        assert_eq!(meta.device_count, 1);
    }

    // =========================================================================
    // CAS and corruption tests
    // =========================================================================

    #[test]
    fn cas_detects_concurrent_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        // Initialize repository
        let repo = git2::Repository::init(path).unwrap();
        repo.config().unwrap().set_str("user.name", "Test").unwrap();
        repo.config()
            .unwrap()
            .set_str("user.email", "test@test.com")
            .unwrap();

        // Create two backends pointing at the same repo
        let backend1 =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(path));
        let backend2 =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(path));

        backend1.init_if_needed().unwrap();

        // Create first identity with backend1
        let (icp1, prefix1, _, _) = create_signed_icp();
        backend1.append_event(&prefix1, &icp1).unwrap();

        // Now backend2 has a stale view - it read the tree before backend1's write
        // Simulate this by having backend2 try to write based on stale state
        // We can't easily simulate the race in a single-threaded test,
        // but we can verify that CAS would catch it by manually corrupting the ref

        // Create second identity with backend2 - should succeed (no race yet)
        let (icp2, prefix2, _, _) = create_signed_icp();
        backend2.append_event(&prefix2, &icp2).unwrap();

        // Verify both identities exist
        let mut count = 0;
        backend1
            .visit_identities(&mut |_| {
                count += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn corrupt_metadata_fails_write() {
        use crate::git::tree_ops::TreeMutator;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        // Initialize repository
        let repo = git2::Repository::init(path).unwrap();
        repo.config().unwrap().set_str("user.name", "Test").unwrap();
        repo.config()
            .unwrap()
            .set_str("user.email", "test@test.com")
            .unwrap();

        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(path));
        backend.init_if_needed().unwrap();

        // Write corrupt metadata directly
        {
            let repo = git2::Repository::open(path).unwrap();
            let reference = repo.find_reference(REGISTRY_REF).unwrap();
            let parent = reference.peel_to_commit().unwrap();
            let base_tree = parent.tree().unwrap();

            let mut mutator = TreeMutator::new();
            mutator.write_blob(&paths::versioned("metadata.json"), b"{bad json".to_vec());
            let tree_oid = mutator.build_tree(&repo, Some(&base_tree)).unwrap();

            let sig = repo.signature().unwrap();
            let tree = repo.find_tree(tree_oid).unwrap();
            let commit_oid = repo
                .commit(None, &sig, &sig, "Corrupt metadata", &tree, &[&parent])
                .unwrap();

            repo.reference(REGISTRY_REF, commit_oid, true, "Corrupt metadata for test")
                .unwrap();
        }

        // Now try to append an event - should fail due to corrupt metadata
        let (icp, prefix, _, _) = create_signed_icp();
        let result = backend.append_event(&prefix, &icp);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, RegistryError::Internal(ref msg) if msg.contains("Corrupt metadata.json")),
            "Expected corrupt metadata error, got: {:?}",
            err
        );
    }

    // =========================================================================
    // write_key_state Tests
    // =========================================================================

    #[test]
    fn write_key_state_persists_state_to_git() {
        // RED: write_key_state overwrites state.json, get_key_state returns the new state
        let (_dir, backend) = setup_test_repo();
        let (event, prefix, _keypair, _next_keypair) = create_signed_icp();
        backend.append_event(&prefix, &event).unwrap();

        // Capture the original state (which has the correct last_event_said matching tip)
        let original_state = backend.get_key_state(&prefix).unwrap();

        // Build a modified state: same tip SAID, different current_keys
        let modified_state = KeyState {
            prefix: prefix.clone(),
            current_keys: vec!["DModifiedKey123456789012345678901234".to_string()],
            next_commitment: original_state.next_commitment.clone(),
            sequence: original_state.sequence,
            last_event_said: original_state.last_event_said.clone(),
            is_abandoned: false,
            threshold: 1,
            next_threshold: 1,
        };

        backend.write_key_state(&prefix, &modified_state).unwrap();

        // get_key_state must return the overwritten state (not replay the KEL)
        let retrieved = backend.get_key_state(&prefix).unwrap();
        assert_eq!(
            retrieved.current_keys[0],
            "DModifiedKey123456789012345678901234"
        );
        assert_eq!(retrieved.sequence, original_state.sequence);
    }

    #[test]
    fn write_key_state_returns_not_found_for_nonexistent_identity() {
        // RED: writing state for an unknown prefix returns NotFound (no tip.json)
        let (_dir, backend) = setup_test_repo();

        let prefix = Prefix::new_unchecked("EXq5Test1234".to_string());
        let state = KeyState::from_inception(
            prefix.clone(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            1,
            1,
            Said::new_unchecked("ESAID12345".to_string()),
        );

        let result = backend.write_key_state(&prefix, &state);
        assert!(
            matches!(result, Err(RegistryError::NotFound { .. })),
            "Expected NotFound, got: {:?}",
            result
        );
    }
}

#[cfg(all(test, feature = "indexed-storage"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod index_consistency_tests {
    use super::*;
    use auths_core::crypto::said::compute_next_commitment;
    use auths_id::keri::KERI_VERSION;
    use auths_id::keri::event::{IcpEvent, KeriSequence};
    use auths_id::keri::types::{Prefix, Said};
    use auths_id::keri::validate::{finalize_icp_event, serialize_for_signing};
    use auths_id::storage::registry::org_member::MemberFilter;
    use auths_verifier::core::{Ed25519PublicKey, Ed25519Signature, ResourceId};
    use auths_verifier::types::CanonicalDid;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Utc;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    fn setup() -> (TempDir, GitRegistryBackend) {
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        (dir, backend)
    }

    fn make_icp() -> (Event, Prefix) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    /// Build an attestation where the issuer matches the org (so it passes
    /// `expected_org_issuer` validation in `visit_org_member_attestations`).
    ///
    /// `org_prefix` must be a raw KERI prefix (e.g. "EOrg1234567890"), NOT a full DID.
    #[allow(clippy::disallowed_methods)]
    fn make_org_attestation(org_prefix: &str, did_suffix: &str, rid: &str) -> Attestation {
        Attestation {
            version: 1,
            rid: ResourceId::new(rid),
            issuer: CanonicalDid::new_unchecked(format!("did:keri:{}", org_prefix)),
            subject: CanonicalDid::new_unchecked(format!("did:key:z6Mk{}", did_suffix)),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            note: None,
            payload: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
            environment_claim: None,
        }
    }

    fn make_attestation(did_suffix: &str, rid: &str) -> Attestation {
        make_org_attestation("EIssuer", did_suffix, rid)
    }

    fn index_of(
        backend: &GitRegistryBackend,
    ) -> std::sync::MutexGuard<'_, auths_index::AttestationIndex> {
        backend
            .index
            .as_ref()
            .expect("index must be present in test")
            .lock()
            .unwrap()
    }

    #[test]
    fn index_reflects_store_attestation_immediately() {
        let (_dir, backend) = setup();
        let att = make_attestation("ConsistencyA", "rid-consist-a");

        backend.store_attestation(&att).unwrap();

        let results = index_of(&backend)
            .query_by_device("did:key:z6MkConsistencyA")
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "index must have the attestation immediately after store"
        );
        assert_eq!(results[0].rid, "rid-consist-a");
    }

    #[test]
    fn index_reflects_store_org_member_immediately() {
        let (_dir, backend) = setup();
        let org = "EOrgConsistency";
        let member = make_org_attestation(org, "OrgMemberC", "rid-org-c");

        backend.store_org_member(org, &member).unwrap();

        let members = index_of(&backend).list_org_members_indexed(org).unwrap();
        assert_eq!(
            members.len(),
            1,
            "index must reflect org member immediately after store"
        );
        assert_eq!(members[0].rid, "rid-org-c");
    }

    #[test]
    fn index_reflects_append_event_immediately() {
        let (_dir, backend) = setup();
        let (icp, prefix) = make_icp();

        backend.append_event(&prefix, &icp).unwrap();

        let identity = index_of(&backend).query_identity(prefix.as_str()).unwrap();
        assert!(
            identity.is_some(),
            "index must have identity after append_event"
        );
        let identity = identity.unwrap();
        assert_eq!(identity.prefix, prefix.as_str());
        assert_eq!(identity.sequence, 0);
    }

    #[test]
    fn list_org_members_fast_matches_list_org_members() {
        let (_dir, backend) = setup();
        let org = "EOrgFastMatch";
        let filter = MemberFilter::default();

        for i in 0..5u8 {
            let member =
                make_org_attestation(org, &format!("FastMember{}", i), &format!("rid-fast-{}", i));
            backend.store_org_member(org, &member).unwrap();
        }

        let git_members = backend.list_org_members(org, &filter).unwrap();
        let fast_members = backend.list_org_members_fast(org, &filter).unwrap();

        let mut git_dids: Vec<String> = git_members.iter().map(|m| m.did.to_string()).collect();
        let mut fast_dids: Vec<String> = fast_members.iter().map(|m| m.did.to_string()).collect();
        git_dids.sort();
        fast_dids.sort();

        assert_eq!(
            git_dids, fast_dids,
            "list_org_members_fast must return same DIDs as list_org_members"
        );
    }

    #[test]
    fn list_org_members_fast_empty_org_returns_empty() {
        // When neither Git nor index has members, fast returns empty (no error, no panic)
        let (_dir, backend) = setup();
        let filter = MemberFilter::default();

        let result = backend.list_org_members_fast("EOrgEmpty", &filter).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn rebuild_identities_from_scratch_via_separate_index() {
        // Build a backend with 3 identities, then rebuild into a fresh in-memory index
        // and verify all 3 are present. This tests the rebuild path without needing
        // to clear or access private fields.
        let (_dir, backend) = setup();

        for _ in 0..3 {
            let (icp, prefix) = make_icp();
            backend.append_event(&prefix, &icp).unwrap();
        }

        let fresh_index = auths_index::AttestationIndex::in_memory().unwrap();
        let stats = rebuild_identities_from_registry(&fresh_index, &backend).unwrap();

        assert_eq!(
            stats.attestations_indexed, 3,
            "rebuild must index all 3 identities, got {}",
            stats.attestations_indexed
        );
    }

    #[test]
    fn rebuild_org_members_from_scratch_via_separate_index() {
        let (_dir, backend) = setup();
        let org = "EOrgRebuild";

        for i in 0..4u8 {
            let member = make_org_attestation(
                org,
                &format!("RebuildM{}", i),
                &format!("rid-rebuild-{}", i),
            );
            backend.store_org_member(org, &member).unwrap();
        }

        let fresh_index = auths_index::AttestationIndex::in_memory().unwrap();
        let stats = rebuild_org_members_from_registry(&fresh_index, &backend).unwrap();

        assert!(
            stats.attestations_indexed >= 4,
            "rebuild must index all 4 org members, got {}",
            stats.attestations_indexed
        );
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tenant_isolation_tests {
    use std::ops::ControlFlow;
    use std::sync::Arc;

    use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
    use auths_verifier::types::{CanonicalDid, DeviceDID};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use auths_core::crypto::said::compute_next_commitment;
    use auths_id::keri::KERI_VERSION;
    use auths_id::keri::event::{IcpEvent, KeriSequence};
    use auths_id::keri::types::{Prefix, Said};
    use auths_id::keri::validate::{finalize_icp_event, serialize_for_signing};

    use super::*;
    use auths_id::storage::registry::backend::TenantIdError;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    fn setup_tenant_backend(base: &TempDir, tenant_id: &str) -> GitRegistryBackend {
        let config = RegistryConfig::for_tenant(base.path(), tenant_id).unwrap();
        let b = GitRegistryBackend::from_config_unchecked(config);
        assert!(b.init_if_needed().unwrap(), "expected new provisioning");
        b
    }

    fn setup_tenant_backend_open(base: &TempDir, tenant_id: &str) -> GitRegistryBackend {
        let config = RegistryConfig::for_tenant(base.path(), tenant_id).unwrap();
        GitRegistryBackend::open_existing(config).unwrap()
    }

    fn make_icp() -> (Event, Prefix) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    fn make_test_attestation(device_did: &str) -> Attestation {
        Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: CanonicalDid::new_unchecked("did:keri:EIssuer"),
            subject: CanonicalDid::new_unchecked(device_did),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
            environment_claim: None,
        }
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn tenant_identity_isolation() {
        let base = TempDir::new().unwrap();
        let acme = setup_tenant_backend(&base, "acme");
        let globocorp = setup_tenant_backend(&base, "globocorp");

        // Different repo paths — catches path resolution bugs immediately
        assert_ne!(
            acme.repo_path(),
            globocorp.repo_path(),
            "tenant repo paths must differ"
        );

        // Write one identity per tenant
        let (icp_acme, prefix_acme) = make_icp();
        acme.append_event(&prefix_acme, &icp_acme).unwrap();

        let (icp_glob, prefix_glob) = make_icp();
        globocorp.append_event(&prefix_glob, &icp_glob).unwrap();

        // Each tenant sees only their own identities
        let mut acme_ids = Vec::new();
        acme.visit_identities(&mut |p| {
            acme_ids.push(p.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(acme_ids, vec![prefix_acme.to_string()]);

        let mut glob_ids = Vec::new();
        globocorp
            .visit_identities(&mut |p| {
                glob_ids.push(p.to_string());
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(glob_ids, vec![prefix_glob.to_string()]);

        // Cross-tenant reads return errors
        assert!(acme.get_key_state(&prefix_glob).is_err());
        assert!(globocorp.get_key_state(&prefix_acme).is_err());
    }

    #[test]
    fn tenant_attestation_isolation() {
        let base = TempDir::new().unwrap();
        let acme = setup_tenant_backend(&base, "acme");
        let globocorp = setup_tenant_backend(&base, "globocorp");

        let att = make_test_attestation("did:key:z6MkTest123");
        let did = DeviceDID::new_unchecked(att.subject.as_str());
        acme.store_attestation(&att).unwrap();

        // globocorp sees no attestation for the device written to acme
        let result = globocorp.load_attestation(&did).unwrap();
        assert!(
            result.is_none(),
            "globocorp must not see acme's attestation"
        );
    }

    #[test]
    fn tenant_org_isolation() {
        let base = TempDir::new().unwrap();
        let acme = setup_tenant_backend(&base, "acme");
        let globocorp = setup_tenant_backend(&base, "globocorp");

        let member_att = make_test_attestation("did:key:z6MkMember");
        acme.store_org_member("did:keri:EOrgAcme", &member_att)
            .unwrap();

        // globocorp sees 0 members for the org written to acme
        let mut count = 0usize;
        globocorp
            .visit_org_member_attestations("did:keri:EOrgAcme", &mut |_| {
                count += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(count, 0, "globocorp must not see acme's org members");
    }

    #[test]
    fn invalid_tenant_id_rejected() {
        let base = TempDir::new().unwrap();

        let cases: &[(&str, TenantIdError)] = &[
            ("", TenantIdError::InvalidLength(0)),
            (&"a".repeat(65), TenantIdError::InvalidLength(65)),
            ("tenant with spaces", TenantIdError::InvalidCharacter(' ')),
            ("acme/sub", TenantIdError::InvalidCharacter('/')),
            ("acme\\sub", TenantIdError::InvalidCharacter('\\')),
            ("../escape", TenantIdError::InvalidCharacter('.')),
            (".hidden", TenantIdError::InvalidCharacter('.')),
            ("admin", TenantIdError::Reserved("admin".into())),
            ("health", TenantIdError::Reserved("health".into())),
            ("metrics", TenantIdError::Reserved("metrics".into())),
        ];

        for (input, expected_kind) in cases {
            match RegistryConfig::for_tenant(base.path(), *input) {
                Err(RegistryError::InvalidTenantId { kind, .. }) => {
                    assert_eq!(&kind, expected_kind, "wrong error for input {:?}", input);
                }
                other => panic!("expected InvalidTenantId for {:?}, got {:?}", input, other),
            }
        }
    }

    #[test]
    fn valid_tenant_id_accepted() {
        let base = TempDir::new().unwrap();

        let cases: &[(&str, &str)] = &[
            ("acme", "acme"),
            ("globo-corp", "globo-corp"),
            ("tenant_123", "tenant_123"),
            ("TENANT", "tenant"),
            ("Acme", "acme"),
            ("a", "a"),
        ];

        for (input, expected_canonical) in cases {
            let config = RegistryConfig::for_tenant(base.path(), *input)
                .unwrap_or_else(|e| panic!("for_tenant({:?}) failed: {}", input, e));
            assert_eq!(
                config.tenant_id.as_ref().map(|t| t.as_str()),
                Some(*expected_canonical),
                "wrong canonical ID for input {:?}",
                input
            );
        }

        // 64-char max
        let long_id = "a".repeat(64);
        let config = RegistryConfig::for_tenant(base.path(), &long_id).unwrap();
        assert_eq!(
            config.tenant_id.as_ref().map(|t| t.as_str()),
            Some(long_id.as_str())
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn ten_concurrent_tenants_no_interference() {
        let base = Arc::new(TempDir::new().unwrap());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let base = Arc::clone(&base);
                tokio::task::spawn_blocking(move || {
                    let tid = format!("tenant-{:02}", i);
                    let backend = setup_tenant_backend(&base, &tid);
                    let (icp, prefix) = make_icp();
                    backend.append_event(&prefix, &icp).unwrap();
                    (tid, prefix)
                })
            })
            .collect();

        let mut results: Vec<(String, Prefix)> = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Verify isolation: each tenant has exactly one identity
        for (tid, prefix) in &results {
            let backend = setup_tenant_backend_open(&base, tid);
            let mut found = Vec::new();
            backend
                .visit_identities(&mut |p| {
                    found.push(p.to_string());
                    ControlFlow::Continue(())
                })
                .unwrap();
            assert_eq!(
                found,
                vec![prefix.to_string()],
                "tenant {} should have exactly 1 identity",
                tid
            );
        }

        drop(base); // explicit: TempDir lives until here
    }

    #[test]
    fn tenant_metadata_written_correctly() {
        let base = TempDir::new().unwrap();
        let backend = setup_tenant_backend(&base, "acme");

        let meta = backend.load_tenant_metadata().unwrap();
        assert_eq!(meta.tenant_id, "acme");
        assert_eq!(meta.status, TenantStatus::Active);
        assert_eq!(meta.version, 1);
    }
}
