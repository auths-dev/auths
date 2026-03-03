//! Provides storage implementation for KERI Key Event Logs (KELs) within a Git repository.
//! e.g., `refs/did/keri/<prefix>/kel`

use crate::error::StorageError;
use crate::identity::events::KeyRotationEvent;
use crate::keri::Prefix;
use crate::storage::layout;
use git2::{Commit, ErrorCode, Oid, Repository, Signature};
use log::{debug, warn};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Standard filename for storing KERI event data within commit blobs in the KEL.
const KERI_EVENT_BLOB_NAME: &str = "event.cesr"; // Or "event.json", "event.cbor" etc.

/// Provides methods for interacting with KERI Key Event Logs stored in a Git repository.
#[derive(Debug, Clone)]
pub struct KeriGitStorage {
    /// Path to the root of the Git repository.
    repo_path: PathBuf,
}

impl KeriGitStorage {
    /// Creates a new `KeriGitStorage` instance for the given repository path.
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        KeriGitStorage {
            repo_path: repo_path.into(),
        }
    }

    fn open_repo(&self) -> Result<Repository, StorageError> {
        Ok(Repository::open(&self.repo_path)?)
    }

    /// Stores a single KERI event as a new commit on the specific KEL Git reference
    /// for the given DID prefix (AID).
    ///
    /// # Arguments
    /// * `did_prefix`: The KERI Autonomous Identifier (AID) prefix.
    /// * `event_bytes`: The serialized KERI event data (e.g., CESR).
    /// * `commit_message`: A descriptive message for the Git commit (e.g., "Inception", "Rotation").
    ///
    /// # Returns
    /// The `Oid` of the newly created Git commit storing the event.
    pub fn store_event(
        &self,
        did_prefix: &Prefix,
        event_bytes: &[u8],
        commit_message: &str,
    ) -> Result<Oid, StorageError> {
        debug!(
            "Storing KERI event for prefix '{}' in repo {:?}. Message: '{}'",
            did_prefix.as_str(),
            self.repo_path,
            commit_message
        );
        let repo = self.open_repo()?;

        // 1. Determine the specific KEL reference path using the layout helper
        let kel_ref_name = layout::keri_kel_ref(did_prefix);
        debug!("Target KEL ref: {}", kel_ref_name);

        // 2. Find the parent commit (the current tip of this specific KEL ref)
        let parent_commit_opt = match repo.find_reference(&kel_ref_name) {
            Ok(reference) => {
                // Ref exists, peel it to a commit
                match reference.peel_to_commit() {
                    Ok(commit) => {
                        debug!(
                            "Found parent commit {} for ref '{}'",
                            commit.id(),
                            kel_ref_name
                        );
                        Some(commit)
                    }
                    Err(e)
                        if e.code() == ErrorCode::Peel
                            || e.code() == ErrorCode::NotFound
                            || e.code() == ErrorCode::InvalidSpec =>
                    {
                        // Ref exists but doesn't point to a valid commit (e.g., symbolic, broken, unborn)
                        warn!(
                            "Ref '{}' exists but doesn't point to a valid commit ({:?}). Creating commit without parent.",
                            kel_ref_name,
                            e.code()
                        );
                        None
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if e.code() == ErrorCode::NotFound => {
                // Ref doesn't exist, this is the initial commit for this KEL (no parent)
                debug!(
                    "KEL reference '{}' not found. Creating initial commit.",
                    kel_ref_name
                );
                None
            }
            Err(e) => return Err(e.into()),
        };
        let parents: Vec<&Commit> = parent_commit_opt.iter().collect();

        // 3. Create the Git blob containing the event data
        let blob_oid = repo.blob(event_bytes)?;
        debug!("Created event blob: {}", blob_oid);

        // 4. Create the Git tree containing the blob
        let mut tree_builder = repo.treebuilder(None)?;
        tree_builder.insert(KERI_EVENT_BLOB_NAME, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;
        debug!("Created tree {} containing event blob", tree_oid);

        // 5. Create the Git signature (use repo default or fallback)
        let sig = repo
            .signature()
            .or_else(|_| Signature::now("auths-keri", "auths-keri@localhost"))?;
        debug!("Using Git signature: {}", sig);

        // 6. Create the Git commit object
        let commit_oid = repo.commit(
            None,
            &sig,
            &sig,
            commit_message,
            &tree,
            &parents,
        )?;
        debug!("Created commit object: {}", commit_oid);

        // 7. Explicitly update the specific KEL Git reference to point to the new commit
        //    Use force=true to overwrite if the reference already exists (it should if parent was found).
        let ref_log_message = format!("commit (keri event): {}", commit_message);
        repo.reference(&kel_ref_name, commit_oid, true, &ref_log_message)?;
        debug!(
            "Updated KEL reference '{}' to point to {}",
            kel_ref_name, commit_oid
        );

        Ok(commit_oid)
    }

    /// Reads the history of KERI events for a specific DID prefix (AID) from its KEL Git reference.
    /// Returns the events as raw bytes, ordered from oldest (inception) to newest.
    ///
    /// # Arguments
    /// * `did_prefix`: The KERI Autonomous Identifier (AID) prefix.
    ///
    /// # Returns
    /// A `Vec` containing the raw bytes (`Vec<u8>`) of each KERI event found in the KEL history,
    /// ordered chronologically (oldest first). Returns an empty `Vec` if the KEL ref is not found.
    pub fn read_kel_history(&self, did_prefix: &Prefix) -> Result<Vec<Vec<u8>>, StorageError> {
        debug!(
            "Reading KEL history for prefix '{}' from repo {:?}",
            did_prefix.as_str(),
            self.repo_path
        );
        let repo = self.open_repo()?;

        // 1. Determine the specific KEL reference path
        let kel_ref_name = layout::keri_kel_ref(did_prefix);
        debug!("Target KEL ref: {}", kel_ref_name);

        // 2. Find the starting commit (tip of the KEL ref)
        let start_commit = match repo.find_reference(&kel_ref_name) {
            Ok(reference) => {
                // Ref exists, peel to commit
                reference.peel_to_commit()?
            }
            Err(e) if e.code() == ErrorCode::NotFound => {
                // Ref doesn't exist, no history for this prefix
                debug!(
                    "KEL reference '{}' not found. Returning empty history.",
                    kel_ref_name
                );
                return Ok(Vec::new()); // Return empty vector, not an error
            }
            Err(e) => return Err(e.into()),
        };
        debug!("Starting history walk from commit {}", start_commit.id());

        // 3. Walk the Git history backwards (first parent) and collect event blobs
        let mut event_history_bytes = Vec::new();
        let mut current_commit = start_commit;

        loop {
            // Get the tree for the current commit
            match current_commit.tree() {
                Ok(tree) => {
                    // Try to find the event blob within the tree
                    match tree.get_name(KERI_EVENT_BLOB_NAME) {
                        Some(entry) => {
                            // Blob entry found, find the blob object
                            match repo.find_blob(entry.id()) {
                                Ok(blob) => {
                                    // Successfully found blob, add its content to history
                                    event_history_bytes.push(blob.content().to_vec());
                                    debug!(
                                        "Read event blob {} from commit {}",
                                        blob.id(),
                                        current_commit.id()
                                    );
                                }
                                Err(e) => {
                                    // Blob OID found in tree, but blob object not found (repo corruption?)
                                    warn!(
                                        "Failed to find blob object {} referenced in commit {}: {}. Skipping event.",
                                        entry.id(),
                                        current_commit.id(),
                                        e
                                    );
                                    // Decide whether to error out or just skip. Skipping makes it more robust.
                                }
                            }
                        }
                        None => {
                            // Commit exists, but doesn't contain the expected event blob
                            warn!(
                                "Commit {} in KEL history for '{}' does not contain the expected blob '{}'. Skipping commit.",
                                current_commit.id(),
                                did_prefix.as_str(),
                                KERI_EVENT_BLOB_NAME
                            );
                            // Skip this commit and continue walking
                        }
                    }
                }
                Err(e) => {
                    // Failed to get tree for the commit (repo issue?)
                    warn!(
                        "Failed to get tree for commit {} in KEL history for '{}': {}. Stopping history walk early.",
                        current_commit.id(),
                        did_prefix.as_str(),
                        e
                    );
                    // Stop walking if tree is inaccessible, history might be incomplete
                    break;
                }
            }

            // Move to the first parent commit
            match current_commit.parent_count() {
                0 => break, // Reached the root of this line of history
                _ => {
                    match current_commit.parent(0) {
                        Ok(parent) => current_commit = parent,
                        Err(e) => {
                            // Failed to get parent commit (repo issue?)
                            warn!(
                                "Failed to get parent commit for {} in KEL history for '{}': {}. Stopping history walk early.",
                                current_commit.id(),
                                did_prefix.as_str(),
                                e
                            );
                            // Stop walking if parent is inaccessible, history might be incomplete
                            break;
                        }
                    }
                }
            }
        } // End loop

        // 4. Reverse the collected bytes so the oldest event (inception) is first
        event_history_bytes.reverse();
        debug!(
            "Finished reading KEL history for '{}'. Found {} events.",
            did_prefix.as_str(),
            event_history_bytes.len()
        );

        Ok(event_history_bytes)
    }

    /// Appends a key rotation event to the KEL, validating chain integrity.
    ///
    /// This method verifies that the `previous_hash` in the event matches the
    /// hash of the current KEL tip commit, ensuring the rotation event is
    /// properly chained.
    ///
    /// # Arguments
    /// * `did_prefix` - The KERI Autonomous Identifier (AID) prefix.
    /// * `event` - The KeyRotationEvent to append.
    ///
    /// # Returns
    /// * `Ok(Oid)` - The Git commit OID of the stored rotation event.
    /// * `Err(...)` - If validation fails or storage fails.
    pub fn append_rotation_event(
        &self,
        did_prefix: &Prefix,
        event: &KeyRotationEvent,
    ) -> Result<Oid, StorageError> {
        debug!(
            "Appending rotation event (seq {}) for prefix '{}' in repo {:?}",
            event.sequence,
            did_prefix.as_str(),
            self.repo_path
        );

        let repo = self.open_repo()?;
        let kel_ref_name = layout::keri_kel_ref(did_prefix);

        // 1. Get the current KEL tip commit hash (if exists)
        let current_tip_hash = match repo.find_reference(&kel_ref_name) {
            Ok(reference) => {
                match reference.peel_to_commit() {
                    Ok(commit) => {
                        // Compute hash of the commit ID for chain verification
                        let commit_id = commit.id().to_string();
                        let mut hasher = Sha256::new();
                        hasher.update(commit_id.as_bytes());
                        let hash = format!("{:x}", hasher.finalize());
                        debug!("Current KEL tip commit: {}, hash: {}", commit.id(), hash);
                        Some(hash)
                    }
                    Err(_) => None,
                }
            }
            Err(e) if e.code() == ErrorCode::NotFound => {
                debug!(
                    "No existing KEL for prefix '{}', this should be the first event",
                    did_prefix.as_str()
                );
                None
            }
            Err(e) => return Err(e.into()),
        };

        // 2. Validate chain integrity
        if event.sequence == 0 {
            if !event.previous_hash.is_empty() && current_tip_hash.is_some() {
                return Err(StorageError::InvalidData(format!(
                    "Sequence 0 event (inception) should have empty previous_hash, got: {}",
                    event.previous_hash
                )));
            }
        } else {
            match &current_tip_hash {
                Some(expected) if &event.previous_hash != expected => {
                    return Err(StorageError::InvalidData(format!(
                        "Chain integrity violation: event.previous_hash ({}) != current KEL tip hash ({})",
                        event.previous_hash,
                        expected
                    )));
                }
                None => {
                    return Err(StorageError::InvalidData(format!(
                        "Cannot append rotation event (seq {}) without existing KEL history",
                        event.sequence
                    )));
                }
                _ => {
                    debug!("Chain integrity validated for sequence {}", event.sequence);
                }
            }
        }

        // 3. Serialize the event as JSON
        let event_json = serde_json::to_vec_pretty(event)?;

        // 4. Store the event using the existing store_event method
        let commit_message = format!("Key rotation: sequence {}", event.sequence);
        self.store_event(did_prefix, &event_json, &commit_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::RepositoryInitOptions;
    use tempfile::tempdir;

    // Helper to initialize a bare Git repo in a temporary directory
    fn init_temp_repo() -> (tempfile::TempDir, PathBuf, Repository) {
        let dir = tempdir().expect("Failed to create temp directory");
        let path = dir.path().to_path_buf();
        let mut opts = RepositoryInitOptions::new();
        opts.bare(true); // Use a bare repo, common for storage like this
        let repo = Repository::init_opts(&path, &opts).expect("Failed to init bare repo");

        // Set git config for CI environments where user.name/email may not be set
        let mut config = repo.config().expect("Failed to get repo config");
        config
            .set_str("user.name", "Test User")
            .expect("Failed to set user.name");
        config
            .set_str("user.email", "test@example.com")
            .expect("Failed to set user.email");

        (dir, path, repo)
    }

    #[test]
    fn test_keri_storage_new() {
        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        assert_eq!(storage.repo_path, path);
    }

    #[test]
    fn test_store_and_read_single_event() -> Result<(), Box<dyn std::error::Error>> {
        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("EABC123".to_string());
        let event1_bytes = b"keri_event_1_data".to_vec();
        let msg1 = "Inception";

        // Store the first event
        let commit1_oid = storage.store_event(&did_prefix, &event1_bytes, msg1)?;
        assert!(!commit1_oid.is_zero());

        // Read the history
        let history = storage.read_kel_history(&did_prefix)?;

        // Verify history
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], event1_bytes);

        Ok(())
    }

    #[test]
    fn test_store_and_read_multiple_events() -> Result<(), Box<dyn std::error::Error>> {
        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("EDEF456".to_string());
        let event1_bytes = b"keri_event_1_data".to_vec();
        let msg1 = "Inception";
        let event2_bytes = b"keri_event_2_rotation".to_vec();
        let msg2 = "Rotation";
        let event3_bytes = b"keri_event_3_interaction".to_vec();
        let msg3 = "Interaction";

        // Store events sequentially
        let _commit1_oid = storage.store_event(&did_prefix, &event1_bytes, msg1)?;
        let _commit2_oid = storage.store_event(&did_prefix, &event2_bytes, msg2)?;
        let _commit3_oid = storage.store_event(&did_prefix, &event3_bytes, msg3)?;

        // Read the history
        let history = storage.read_kel_history(&did_prefix)?;

        // Verify history order and content
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], event1_bytes); // Oldest first
        assert_eq!(history[1], event2_bytes);
        assert_eq!(history[2], event3_bytes); // Newest last

        Ok(())
    }

    #[test]
    fn test_read_kel_history_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("ENotExist".to_string());

        // Read history for a prefix that hasn't had events stored
        let history = storage.read_kel_history(&did_prefix)?;

        // Should return an empty Vec
        assert!(history.is_empty());

        Ok(())
    }

    #[test]
    fn test_store_event_updates_ref() -> Result<(), Box<dyn std::error::Error>> {
        let (_td, path, repo) = init_temp_repo(); // Get repo object
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("EGHI789".to_string());
        let event1_bytes = b"event1".to_vec();
        let msg1 = "Event 1";
        let event2_bytes = b"event2".to_vec();
        let msg2 = "Event 2";

        // Store first event
        let commit1_oid = storage.store_event(&did_prefix, &event1_bytes, msg1)?;
        let kel_ref_name = layout::keri_kel_ref(&did_prefix);
        let ref1 = repo.find_reference(&kel_ref_name)?;
        assert_eq!(ref1.target(), Some(commit1_oid));

        // Store second event
        let commit2_oid = storage.store_event(&did_prefix, &event2_bytes, msg2)?;
        let ref2 = repo.find_reference(&kel_ref_name)?; // Find ref again
        assert_eq!(ref2.target(), Some(commit2_oid)); // Ref should now point to commit2
        assert_ne!(commit1_oid, commit2_oid);

        // Verify parent relationship
        let commit2 = repo.find_commit(commit2_oid)?;
        assert_eq!(commit2.parent_count(), 1);
        assert_eq!(commit2.parent_id(0)?, commit1_oid);

        Ok(())
    }

    #[test]
    fn test_read_kel_history_skips_commit_without_blob() -> Result<(), Box<dyn std::error::Error>> {
        let (_td, path, repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("ESkipBlob".to_string());
        let event1_bytes = b"event1_good".to_vec();
        let msg1 = "Good Event 1";
        let event3_bytes = b"event3_good".to_vec();
        let msg3 = "Good Event 3";

        // Store event 1
        let commit1_oid = storage.store_event(&did_prefix, &event1_bytes, msg1)?;

        // Manually create a commit without the event blob
        let sig = repo.signature()?;
        let tree_oid_empty = repo.treebuilder(None)?.write()?; // Empty tree
        let tree_empty = repo.find_tree(tree_oid_empty)?;
        let commit2_oid_bad = repo.commit(
            None,
            &sig,
            &sig,
            "Bad Commit (No Blob)",
            &tree_empty,
            &[&repo.find_commit(commit1_oid)?],
        )?;
        let kel_ref_name = layout::keri_kel_ref(&did_prefix);
        repo.reference(&kel_ref_name, commit2_oid_bad, true, "ref update bad")?;

        // Store event 3 (parent should be the bad commit now)
        let _commit3_oid = storage.store_event(&did_prefix, &event3_bytes, msg3)?;

        // Read history
        let history = storage.read_kel_history(&did_prefix)?;

        // Verify only good events are present
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], event1_bytes); // Event 1
        assert_eq!(history[1], event3_bytes); // Event 3 (Event 2 was skipped)

        Ok(())
    }

    #[test]
    fn test_append_rotation_event_first() -> Result<(), Box<dyn std::error::Error>> {
        use crate::identity::events::KeyRotationEvent;
        use chrono::Utc;

        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("ERotate1".to_string());

        // Create inception event (sequence 0)
        let event = KeyRotationEvent::new(
            0,
            "".to_string(), // empty for inception
            vec![0u8; 32],  // old key
            vec![1u8; 32],  // new key
            Utc::now(),
            vec![2u8; 64], // signature
        );

        let commit_oid = storage.append_rotation_event(&did_prefix, &event)?;
        assert!(!commit_oid.is_zero());

        // Verify event was stored
        let history = storage.read_kel_history(&did_prefix)?;
        assert_eq!(history.len(), 1);

        Ok(())
    }

    #[test]
    fn test_append_rotation_event_chain_validation() -> Result<(), Box<dyn std::error::Error>> {
        use crate::identity::events::KeyRotationEvent;
        use chrono::Utc;

        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("ERotate2".to_string());

        // Store first event
        let event1 = KeyRotationEvent::new(
            0,
            "".to_string(),
            vec![0u8; 32],
            vec![1u8; 32],
            Utc::now(),
            vec![2u8; 64],
        );
        let commit1_oid = storage.append_rotation_event(&did_prefix, &event1)?;

        // Compute the expected previous_hash
        let commit1_id = commit1_oid.to_string();
        let mut hasher = Sha256::new();
        hasher.update(commit1_id.as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());

        // Store second event with correct previous_hash
        let event2 = KeyRotationEvent::new(
            1,
            expected_hash.clone(),
            vec![1u8; 32],
            vec![2u8; 32],
            Utc::now(),
            vec![3u8; 64],
        );
        let commit2_oid = storage.append_rotation_event(&did_prefix, &event2)?;
        assert!(!commit2_oid.is_zero());

        // Verify both events were stored
        let history = storage.read_kel_history(&did_prefix)?;
        assert_eq!(history.len(), 2);

        Ok(())
    }

    #[test]
    fn test_append_rotation_event_chain_integrity_failure() -> Result<(), Box<dyn std::error::Error>> {
        use crate::identity::events::KeyRotationEvent;
        use chrono::Utc;

        let (_td, path, _repo) = init_temp_repo();
        let storage = KeriGitStorage::new(&path);
        let did_prefix = Prefix::new_unchecked("ERotate3".to_string());

        // Store first event
        let event1 = KeyRotationEvent::new(
            0,
            "".to_string(),
            vec![0u8; 32],
            vec![1u8; 32],
            Utc::now(),
            vec![2u8; 64],
        );
        storage.append_rotation_event(&did_prefix, &event1)?;

        // Try to store second event with WRONG previous_hash
        let event2 = KeyRotationEvent::new(
            1,
            "wrong_hash_value".to_string(),
            vec![1u8; 32],
            vec![2u8; 32],
            Utc::now(),
            vec![3u8; 64],
        );
        let result = storage.append_rotation_event(&did_prefix, &event2);

        // Should fail with chain integrity error
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Chain integrity violation")
        );

        Ok(())
    }
}
