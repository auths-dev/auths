//! Git-backed Key Event Log (KEL) storage.
//!
//! The KEL is stored as a chain of Git commits where:
//! - Each commit contains a single event as `event.json`
//! - The commit chain mirrors the KERI event chain
//! - The ref path follows standard conventions

use chrono::{DateTime, Utc};
use git2::{Commit, ErrorCode, Repository, Signature};

use super::cache;
use super::incremental::{self, IncrementalResult};
use super::types::Prefix;
use super::validate::validate_for_append;
use super::{Event, IcpEvent, KeyState};
use crate::domain::EventHash;
use crate::witness::{event_hash_to_oid, oid_to_event_hash};

/// Errors that can occur during KEL operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KelError {
    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("KEL not found for prefix: {0}")]
    NotFound(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Chain integrity error: {0}")]
    ChainIntegrity(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(#[from] super::ValidationError),
}

impl auths_core::error::AuthsErrorInfo for KelError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Git(_) => "AUTHS-E4601",
            Self::Serialization(_) => "AUTHS-E4602",
            Self::NotFound(_) => "AUTHS-E4603",
            Self::InvalidOperation(_) => "AUTHS-E4604",
            Self::InvalidData(_) => "AUTHS-E4605",
            Self::ChainIntegrity(_) => "AUTHS-E4606",
            Self::ValidationFailed(_) => "AUTHS-E4607",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Git(_) => Some("Check that the Git repository is accessible and not corrupted"),
            Self::Serialization(_) => None,
            Self::NotFound(_) => Some("Initialize the identity first with 'auths init'"),
            Self::InvalidOperation(_) => None,
            Self::InvalidData(_) => Some("The KEL data may be corrupted; try re-syncing"),
            Self::ChainIntegrity(_) => {
                Some("The KEL has non-linear history; this indicates tampering")
            }
            Self::ValidationFailed(_) => None,
        }
    }
}

/// Standard filename for storing KERI events in commits.
const EVENT_BLOB_NAME: &str = "event.json";

/// Construct the Git reference path for a KEL.
fn kel_ref(prefix: &Prefix) -> String {
    format!("refs/did/keri/{}/kel", prefix.as_str())
}

/// Git-backed Key Event Log.
///
/// Provides operations for creating, appending to, and reading KERI event logs
/// stored in a Git repository.
pub struct GitKel<'a> {
    repo: &'a Repository,
    prefix: Prefix,
    ref_path: String,
}

impl<'a> GitKel<'a> {
    /// Create a new GitKel instance for the given prefix using the default ref path.
    pub fn new(repo: &'a Repository, prefix: impl Into<String>) -> Self {
        let prefix = Prefix::new_unchecked(prefix.into());
        let ref_path = kel_ref(&prefix);
        Self {
            repo,
            prefix,
            ref_path,
        }
    }

    /// Create a GitKel instance with a custom ref path.
    ///
    /// This allows reading KELs stored at non-default locations.
    ///
    /// Args:
    /// * `repo`: The Git repository containing the KEL.
    /// * `prefix`: The KERI identifier prefix.
    /// * `ref_path`: The Git ref path to read/write the KEL.
    ///
    /// Usage:
    /// ```ignore
    /// let kel = GitKel::with_ref(&repo, "EPrefix", "refs/keri/kel".into());
    /// ```
    pub fn with_ref(repo: &'a Repository, prefix: impl Into<String>, ref_path: String) -> Self {
        Self {
            repo,
            prefix: Prefix::new_unchecked(prefix.into()),
            ref_path,
        }
    }

    /// Get the prefix for this KEL.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Returns the working directory of the underlying Git repository.
    ///
    /// Used to derive the Auths home directory for cache operations without
    /// reading environment variables. In production the repo workdir equals
    /// `~/.auths`; in tests it equals the temporary directory created by the
    /// test harness.
    pub(crate) fn workdir(&self) -> &std::path::Path {
        self.repo.workdir().unwrap_or_else(|| self.repo.path())
    }

    /// Check if a KEL exists for this prefix.
    pub fn exists(&self) -> bool {
        self.repo.find_reference(&self.ref_path).is_ok()
    }

    /// Create a new KEL with an inception event.
    ///
    /// This creates the initial commit with no parent.
    ///
    /// # Args
    ///
    /// * `event` - The inception event to store as the first commit
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let hash = kel.create(&icp_event)?;
    /// ```
    pub fn create(
        &self,
        event: &IcpEvent,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<EventHash, KelError> {
        if self.exists() {
            return Err(KelError::InvalidOperation(format!(
                "KEL already exists for prefix: {}",
                self.prefix.as_str()
            )));
        }

        let wrapped = Event::Icp(event.clone());
        let json = serde_json::to_vec_pretty(&wrapped)
            .map_err(|e| KelError::Serialization(e.to_string()))?;

        let blob_oid = self.repo.blob(&json)?;
        let mut tree_builder = self.repo.treebuilder(None)?;
        tree_builder.insert(EVENT_BLOB_NAME, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = self.repo.find_tree(tree_oid)?;

        let sig = self.signature(now)?;
        let commit_oid = self.repo.commit(
            Some(&self.ref_path),
            &sig,
            &sig,
            &format!("KERI inception: {}", event.i.as_str()),
            &tree,
            &[],
        )?;

        Ok(oid_to_event_hash(commit_oid))
    }

    /// Append a rotation or interaction event to the KEL.
    ///
    /// The event must have a valid previous SAID that matches the current tip.
    ///
    /// # Args
    ///
    /// * `event` - The rotation or interaction event to append
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let hash = kel.append(&rot_event)?;
    /// ```
    pub fn append(
        &self,
        event: &Event,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<EventHash, KelError> {
        let ref_name = &self.ref_path;

        let reference = self.repo.find_reference(ref_name).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                KelError::NotFound(self.prefix.as_str().to_string())
            } else {
                KelError::Git(e)
            }
        })?;
        let parent_commit = reference.peel_to_commit()?;

        // Validate event cryptographically before persisting
        let state = self.build_current_state()?;
        validate_for_append(event, &state)?;

        let json =
            serde_json::to_vec_pretty(event).map_err(|e| KelError::Serialization(e.to_string()))?;

        let blob_oid = self.repo.blob(&json)?;
        let mut tree_builder = self.repo.treebuilder(None)?;
        tree_builder.insert(EVENT_BLOB_NAME, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = self.repo.find_tree(tree_oid)?;

        let msg = match event {
            Event::Rot(e) => format!("KERI rotation: s={}", e.s),
            Event::Ixn(e) => format!("KERI interaction: s={}", e.s),
            Event::Drt(e) => format!("KERI delegated rotation: s={}", e.s),
            Event::Icp(_) | Event::Dip(_) => unreachable!(),
        };

        let sig = self.signature(now)?;
        let commit_oid =
            self.repo
                .commit(Some(ref_name), &sig, &sig, &msg, &tree, &[&parent_commit])?;

        Ok(oid_to_event_hash(commit_oid))
    }

    /// Read all events from the KEL (oldest to newest).
    pub fn get_events(&self) -> Result<Vec<Event>, KelError> {
        let ref_name = &self.ref_path;
        let reference = self.repo.find_reference(ref_name).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                KelError::NotFound(self.prefix.as_str().to_string())
            } else {
                KelError::Git(e)
            }
        })?;

        let mut events = Vec::new();
        let mut commit = reference.peel_to_commit()?;

        // Walk backwards from tip to inception
        loop {
            let event = self.read_event_from_commit(&commit)?;
            events.push(event);

            if commit.parent_count() == 0 {
                break; // Reached inception
            }
            commit = commit.parent(0)?;
        }

        events.reverse(); // Oldest first
        Ok(events)
    }

    /// Get the current key state with incremental validation.
    ///
    /// This is the primary method for getting key state. It uses a three-tier
    /// approach for optimal performance:
    ///
    /// 1. **Cache hit**: If cached state matches current tip, return immediately (O(1))
    /// 2. **Incremental**: If cache is behind, validate only new events (O(k))
    /// 3. **Full replay**: If cache is missing/invalid, do full replay (O(n))
    ///
    /// All paths write an updated cache on success.
    ///
    /// # Errors
    ///
    /// Returns `KelError` if the KEL is corrupted (e.g., merge commits, broken chain).
    /// Cache problems trigger fallback to full replay, not errors.
    pub fn get_state(&self, now: DateTime<Utc>) -> Result<KeyState, KelError> {
        let did = format!("did:keri:{}", self.prefix.as_str());

        // Try incremental validation
        match incremental::try_incremental_validation(self, &did, now) {
            Ok(IncrementalResult::CacheHit(state)) => {
                return Ok(state);
            }
            Ok(IncrementalResult::IncrementalSuccess {
                state,
                events_validated: _,
            }) => {
                return Ok(state);
            }
            Ok(IncrementalResult::NeedsFullReplay(reason)) => {
                log::debug!("KEL full replay for {}: {:?}", did, reason);
            }
            Err(incremental::IncrementalError::NonLinearHistory {
                commit,
                parent_count,
            }) => {
                // Hard error - don't fall back, the KEL is corrupt
                return Err(KelError::ChainIntegrity(format!(
                    "KEL has non-linear history: commit {} has {} parents",
                    commit, parent_count
                )));
            }
            Err(e) => {
                // Other incremental errors - log and fall back
                log::warn!("Incremental validation failed for {}: {}", did, e);
            }
        }

        // Fall back to full replay
        self.get_state_full_replay(now)
    }

    /// Get the current key state by full O(n) replay of the KEL.
    ///
    /// This bypasses all caching and always replays the entire KEL.
    /// Prefer `get_state()` which uses caching and incremental validation.
    ///
    /// After successful replay, writes the cache for future use.
    pub fn get_state_full_replay(&self, now: DateTime<Utc>) -> Result<KeyState, KelError> {
        let tip_hash = self.tip_commit_hash()?;
        let latest = self.read_event_from_commit_hash(tip_hash)?;
        let tip_said = latest.said();
        let tip_oid_hex = tip_hash.to_hex();
        let did = format!("did:keri:{}", self.prefix.as_str());

        let events = self.get_events()?;

        if events.is_empty() {
            return Err(KelError::NotFound(self.prefix.as_str().to_string()));
        }

        // First event must be inception
        let first = &events[0];
        let Event::Icp(icp) = first else {
            return Err(KelError::InvalidData(
                "First event in KEL must be inception".into(),
            ));
        };

        let mut state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            icp.kt.clone(),
            icp.nt.clone(),
            icp.d.clone(),
            icp.b.clone(),
            icp.bt.clone(),
            icp.c.clone(),
        );

        // Apply remaining events
        for event in events.iter().skip(1) {
            match event {
                Event::Rot(rot) => {
                    let seq = rot.s.value();

                    state.apply_rotation(
                        rot.k.clone(),
                        rot.n.clone(),
                        rot.kt.clone(),
                        rot.nt.clone(),
                        seq,
                        rot.d.clone(),
                        &rot.br,
                        &rot.ba,
                        rot.bt.clone(),
                        rot.c.clone(),
                    );
                }
                Event::Ixn(ixn) => {
                    let seq = ixn.s.value();
                    state.apply_interaction(seq, ixn.d.clone());
                }
                Event::Icp(_) | Event::Dip(_) => {
                    return Err(KelError::InvalidData(
                        "Multiple inception events in KEL".into(),
                    ));
                }
                Event::Drt(_) => {
                    return Err(KelError::InvalidData(
                        "Delegated rotation not yet supported in KEL replay".into(),
                    ));
                }
            }
        }

        // Write cache (ignore errors - cache is optional)
        let _ = cache::write_kel_cache(
            self.workdir(),
            &did,
            &state,
            tip_said.as_str(),
            &tip_oid_hex,
            now,
        );

        Ok(state)
    }

    /// Get the latest event from the KEL.
    pub fn get_latest_event(&self) -> Result<Event, KelError> {
        let ref_name = &self.ref_path;
        let reference = self.repo.find_reference(ref_name).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                KelError::NotFound(self.prefix.as_str().to_string())
            } else {
                KelError::Git(e)
            }
        })?;

        let commit = reference.peel_to_commit()?;
        self.read_event_from_commit(&commit)
    }

    /// Build the current key state from events without caching.
    ///
    /// Used internally by `append()` to validate new events without
    /// requiring a `now` parameter for cache writes.
    fn build_current_state(&self) -> Result<KeyState, KelError> {
        let events = self.get_events()?;
        if events.is_empty() {
            return Err(KelError::NotFound(self.prefix.as_str().to_string()));
        }

        let Event::Icp(icp) = &events[0] else {
            return Err(KelError::InvalidData(
                "First event in KEL must be inception".into(),
            ));
        };

        let mut state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            icp.kt.clone(),
            icp.nt.clone(),
            icp.d.clone(),
            icp.b.clone(),
            icp.bt.clone(),
            icp.c.clone(),
        );

        for event in events.iter().skip(1) {
            match event {
                Event::Rot(rot) => {
                    let seq = rot.s.value();
                    state.apply_rotation(
                        rot.k.clone(),
                        rot.n.clone(),
                        rot.kt.clone(),
                        rot.nt.clone(),
                        seq,
                        rot.d.clone(),
                        &rot.br,
                        &rot.ba,
                        rot.bt.clone(),
                        rot.c.clone(),
                    );
                }
                Event::Ixn(ixn) => {
                    state.apply_interaction(ixn.s.value(), ixn.d.clone());
                }
                Event::Icp(_) | Event::Dip(_) => {
                    return Err(KelError::InvalidData(
                        "Multiple inception events in KEL".into(),
                    ));
                }
                Event::Drt(_) => {
                    return Err(KelError::InvalidData(
                        "Delegated rotation not yet supported in KEL replay".into(),
                    ));
                }
            }
        }

        Ok(state)
    }

    /// Read an event from a commit.
    fn read_event_from_commit(&self, commit: &Commit) -> Result<Event, KelError> {
        let tree = commit.tree()?;
        let entry = tree
            .get_name(EVENT_BLOB_NAME)
            .ok_or_else(|| KelError::InvalidData("Missing event.json in commit".into()))?;
        let blob = self.repo.find_blob(entry.id())?;
        let event: Event = serde_json::from_slice(blob.content())
            .map_err(|e| KelError::Serialization(e.to_string()))?;
        Ok(event)
    }

    /// Create a Git signature for commits using an injected timestamp.
    fn signature(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Signature<'static>, KelError> {
        self.repo
            .signature()
            .or_else(|_| {
                Signature::new("auths", "auths@local", &git2::Time::new(now.timestamp(), 0))
            })
            .map_err(KelError::Git)
    }

    // --- Commit hash helpers for incremental validation ---

    /// Get the hash of the tip commit for this KEL.
    pub fn tip_commit_hash(&self) -> Result<EventHash, KelError> {
        let ref_name = &self.ref_path;
        let reference = self.repo.find_reference(ref_name).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                KelError::NotFound(self.prefix.as_str().to_string())
            } else {
                KelError::Git(e)
            }
        })?;
        let commit = reference.peel_to_commit()?;
        Ok(oid_to_event_hash(commit.id()))
    }

    /// Read an event from a commit by its hash.
    pub fn read_event_from_commit_hash(&self, hash: EventHash) -> Result<Event, KelError> {
        let commit = self.repo.find_commit(event_hash_to_oid(hash))?;
        self.read_event_from_commit(&commit)
    }

    /// Get the parent commit hash, if any.
    ///
    /// Returns `None` for the inception commit (no parent).
    pub fn parent_hash(&self, hash: EventHash) -> Result<Option<EventHash>, KelError> {
        let commit = self.repo.find_commit(event_hash_to_oid(hash))?;
        if commit.parent_count() == 0 {
            Ok(None)
        } else {
            Ok(Some(oid_to_event_hash(commit.parent_id(0)?)))
        }
    }

    /// Get the number of parents for a commit.
    ///
    /// KEL commits must have exactly 1 parent (except inception which has 0).
    /// Any commit with >1 parent indicates a merge, which is invalid for KELs.
    pub fn parent_count(&self, hash: EventHash) -> Result<usize, KelError> {
        let commit = self.repo.find_commit(event_hash_to_oid(hash))?;
        Ok(commit.parent_count())
    }

    /// Check if a commit exists in the repository.
    pub fn commit_exists(&self, hash: EventHash) -> bool {
        self.repo.find_commit(event_hash_to_oid(hash)).is_ok()
    }

    /// Parse a commit hash from a hex string.
    pub fn parse_hash(hex: &str) -> Result<EventHash, KelError> {
        hex.parse::<EventHash>()
            .map_err(|e| KelError::InvalidData(format!("Invalid commit hash: {}", e)))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::inception::{create_keri_identity, create_keri_identity_with_curve};
    use crate::keri::rotation::rotate_keys;
    use crate::keri::{CesrKey, KeriSequence, Prefix, RotEvent, Said, Threshold, VersionString};
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    fn with_temp_auths_home_and_repo<F>(f: F)
    where
        F: FnOnce(&TempDir, &Repository),
    {
        let (dir, repo) = setup_repo();
        f(&dir, &repo);
    }

    fn make_icp_event(prefix: &str) -> IcpEvent {
        IcpEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked(prefix.to_string()),
            i: Prefix::new_unchecked(prefix.to_string()),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey1".to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENext1".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
            x: String::new(),
        }
    }

    #[test]
    fn create_and_read_kel() {
        let (_dir, repo) = setup_repo();
        let kel = GitKel::new(&repo, "ETest123");

        let icp = make_icp_event("ETest123");
        kel.create(&icp, chrono::Utc::now()).unwrap();

        assert!(kel.exists());

        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_inception());
    }

    #[test]
    fn cannot_create_duplicate_kel() {
        let (_dir, repo) = setup_repo();
        let kel = GitKel::new(&repo, "ETest123");

        let icp = make_icp_event("ETest123");
        kel.create(&icp, chrono::Utc::now()).unwrap();

        let result = kel.create(&icp, chrono::Utc::now());
        assert!(result.is_err());
    }

    #[test]
    fn append_rotation_event() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let _rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let kel = GitKel::new(&repo, init.prefix.as_str());
        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].is_inception());
        assert!(events[1].is_rotation());
    }

    #[test]
    fn append_rejects_invalid_signature() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        // Build a fake rotation event with invalid SAID
        let rot = Event::Rot(RotEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked("EFakeSaid".to_string()),
            i: init.prefix.clone(),
            s: KeriSequence::new(1),
            p: Said::new_unchecked(init.prefix.as_str().to_string()),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DFakeKey".to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("EFakeNext".to_string())],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
            x: String::new(),
        });

        let result = kel.append(&rot, chrono::Utc::now());
        assert!(result.is_err());
        assert!(matches!(result, Err(KelError::ValidationFailed(_))));
    }

    #[test]
    fn get_state_after_inception() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.prefix.as_str(), init.prefix.as_str());
        assert_eq!(state.sequence, 0);
        assert!(state.can_rotate());
    }

    #[test]
    fn get_state_after_rotation() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let kel = GitKel::new(&repo, init.prefix.as_str());
        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.sequence, 1);
        assert_eq!(rot.sequence, 1);
    }

    #[test]
    fn get_latest_event() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let latest = kel.get_latest_event().unwrap();
        assert!(latest.is_inception());

        let _rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let latest = kel.get_latest_event().unwrap();
        assert!(latest.is_rotation());
    }

    #[test]
    fn not_found_error_for_missing_kel() {
        let (_dir, repo) = setup_repo();
        let kel = GitKel::new(&repo, "ENotExist");

        let result = kel.get_events();
        assert!(matches!(result, Err(KelError::NotFound(_))));
    }

    #[test]
    fn cannot_append_icp_event() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let icp2 = Event::Icp(make_icp_event("EFake"));
        let result = kel.append(&icp2, chrono::Utc::now());
        assert!(matches!(result, Err(KelError::ValidationFailed(_))));
    }

    // --- Incremental validation tests ---

    fn make_rot_event(prefix: &str, seq: u64, prev_said: &str) -> RotEvent {
        RotEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked(format!("ERot{}", seq)),
            i: Prefix::new_unchecked(prefix.to_string()),
            s: KeriSequence::new(seq),
            p: Said::new_unchecked(prev_said.to_string()),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(format!("DKey{}", seq + 1))],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked(format!("ENext{}", seq + 1))],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
            x: String::new(),
        }
    }

    #[test]
    fn test_cold_cache_full_replay() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.prefix.as_str(), init.prefix.as_str());
        assert_eq!(state.sequence, 0);

        let did = format!("did:keri:{}", init.prefix.as_str());
        let tip_said = kel.get_latest_event().unwrap().said().to_string();
        let cached = cache::try_load_cached_state(_dir.path(), &did, &tip_said);
        assert!(cached.is_some());
    }

    #[test]
    fn test_warm_cache_hit() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let state1 = kel.get_state(chrono::Utc::now()).unwrap();
        let state2 = kel.get_state(chrono::Utc::now()).unwrap();

        assert_eq!(state1, state2);
        assert_eq!(state2.sequence, 0);
    }

    #[test]
    fn test_incremental_validation_after_rotation() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        // Prime cache
        let _ = kel.get_state(chrono::Utc::now()).unwrap();

        // Rotate keys (appends validated event)
        let rot1 = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.sequence, 1);

        // Rotate again
        let _rot2 = rotate_keys(
            &repo,
            &init.prefix,
            &rot1.new_next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.sequence, 2);
    }

    #[test]
    fn test_cache_divergence_fallback() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let _ = kel.get_state(chrono::Utc::now()).unwrap();

        let did = format!("did:keri:{}", init.prefix.as_str());
        let cached_full = cache::try_load_cached_state_full(_dir.path(), &did).unwrap();
        let _ = cache::write_kel_cache(
            _dir.path(),
            &did,
            &cached_full.state,
            cached_full.validated_against_tip_said.as_str(),
            "0000000000000000000000000000000000000000",
            chrono::Utc::now(),
        );

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.prefix.as_str(), init.prefix.as_str());
    }

    #[test]
    fn test_get_state_matches_full_replay() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let rot1 = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        let _rot2 = rotate_keys(
            &repo,
            &init.prefix,
            &rot1.new_next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let kel = GitKel::new(&repo, init.prefix.as_str());

        let state_incremental = kel.get_state(chrono::Utc::now()).unwrap();
        let did = format!("did:keri:{}", init.prefix.as_str());
        let _ = cache::invalidate_cache(_dir.path(), &did);
        let state_full = kel.get_state_full_replay(chrono::Utc::now()).unwrap();

        assert_eq!(state_incremental.prefix, state_full.prefix);
        assert_eq!(state_incremental.sequence, state_full.sequence);
        assert_eq!(state_incremental.current_keys, state_full.current_keys);
        assert_eq!(
            state_incremental.last_event_said,
            state_full.last_event_said
        );
    }

    #[test]
    fn test_cache_said_mismatch_forces_replay() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let _ = kel.get_state(chrono::Utc::now()).unwrap();

        let did = format!("did:keri:{}", init.prefix.as_str());
        let cached_full = cache::try_load_cached_state_full(_dir.path(), &did).unwrap();

        let _ = cache::write_kel_cache(
            _dir.path(),
            &did,
            &cached_full.state,
            "EFakeSaidThatDoesNotMatchCommit",
            cached_full.last_commit_oid.as_str(),
            chrono::Utc::now(),
        );

        let state = kel.get_state(chrono::Utc::now()).unwrap();
        assert_eq!(state.prefix.as_str(), init.prefix.as_str());
        assert_eq!(state.sequence, 0);

        let new_cached = cache::try_load_cached_state_full(_dir.path(), &did).unwrap();
        let tip_said = kel.get_latest_event().unwrap().said().to_string();
        assert_eq!(
            new_cached.validated_against_tip_said.as_str(),
            tip_said.as_str()
        );
    }

    #[test]
    fn test_commit_hash_helpers() {
        let (_dir, repo) = setup_repo();
        let init = create_keri_identity_with_curve(&repo, None, chrono::Utc::now(), auths_crypto::CurveType::Ed25519).unwrap();
        let kel = GitKel::new(&repo, init.prefix.as_str());

        let tip_hash = kel.tip_commit_hash().unwrap();
        assert!(kel.commit_exists(tip_hash));

        let event = kel.read_event_from_commit_hash(tip_hash).unwrap();
        assert!(event.is_inception());

        assert!(kel.parent_hash(tip_hash).unwrap().is_none());

        // Rotate to add another event
        let _rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let new_tip = kel.tip_commit_hash().unwrap();
        assert_ne!(tip_hash, new_tip);

        let parent = kel.parent_hash(new_tip).unwrap();
        assert!(parent.is_some());
        assert_eq!(parent.unwrap(), tip_hash);
    }

    #[test]
    fn test_kel_merge_commit_rejected() {
        with_temp_auths_home_and_repo(|_repo_dir, repo| {
            let prefix = "EMergeReject";
            let kel = GitKel::new(repo, prefix);
            let icp = make_icp_event(prefix);
            kel.create(&icp, chrono::Utc::now()).unwrap();

            let _ = kel.get_state(chrono::Utc::now()).unwrap();

            let inception_hash = kel.tip_commit_hash().unwrap();
            let inception_oid = crate::witness::event_hash_to_oid(inception_hash);

            let rot1 = Event::Rot(make_rot_event(prefix, 1, prefix));
            let rot1_json = serde_json::to_vec_pretty(&rot1).unwrap();
            let blob1_oid = repo.blob(&rot1_json).unwrap();
            let mut tb1 = repo.treebuilder(None).unwrap();
            tb1.insert("event.json", blob1_oid, 0o100644).unwrap();
            let tree1_oid = tb1.write().unwrap();
            let tree1 = repo.find_tree(tree1_oid).unwrap();
            let inception_commit = repo.find_commit(inception_oid).unwrap();
            let sig = repo.signature().unwrap();
            let branch1_oid = repo
                .commit(None, &sig, &sig, "Branch 1", &tree1, &[&inception_commit])
                .unwrap();

            // Create second branch: another rotation at s=1 (divergent)
            let rot2 = Event::Rot(make_rot_event(prefix, 1, prefix));
            let rot2_json = serde_json::to_vec_pretty(&rot2).unwrap();
            let blob2_oid = repo.blob(&rot2_json).unwrap();
            let mut tb2 = repo.treebuilder(None).unwrap();
            tb2.insert("event.json", blob2_oid, 0o100644).unwrap();
            let tree2_oid = tb2.write().unwrap();
            let tree2 = repo.find_tree(tree2_oid).unwrap();
            let branch2_oid = repo
                .commit(None, &sig, &sig, "Branch 2", &tree2, &[&inception_commit])
                .unwrap();

            // Create a merge commit with two parents (INVALID for KEL!)
            let branch1_commit = repo.find_commit(branch1_oid).unwrap();
            let branch2_commit = repo.find_commit(branch2_oid).unwrap();
            let merge_oid = repo
                .commit(
                    None,
                    &sig,
                    &sig,
                    "Merge (invalid)",
                    &tree1,
                    &[&branch1_commit, &branch2_commit],
                )
                .unwrap();

            // Point the KEL ref to the merge commit
            let ref_name = format!("refs/did/keri/{}/kel", prefix);
            repo.reference(&ref_name, merge_oid, true, "Force merge commit")
                .unwrap();

            // Now get_state() should fail with ChainIntegrity error
            let result = kel.get_state(chrono::Utc::now());
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, KelError::ChainIntegrity(_)),
                "Expected ChainIntegrity error, got: {:?}",
                err
            );

            // Verify the error message mentions non-linear
            let msg = err.to_string();
            assert!(
                msg.contains("non-linear"),
                "Error message should mention non-linear: {}",
                msg
            );
        });
    }
}
