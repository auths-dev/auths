//! Local KEL state cache for performance optimization.
//!
//! This module provides a local, file-based cache for validated KERI key states.
//! The cache eliminates repeated O(n) replays of the Key Event Log by storing
//! the validated `KeyState` keyed by DID and validated against the tip SAID.
//!
//! ## Security Properties
//!
//! - Cache is purely a performance accelerator - never trusted without validation
//! - Always validated against current KEL tip SAID before use
//! - DID stored in cache must match requested DID (prevents file swap attacks)
//! - On any mismatch, cache is treated as a miss and full replay occurs
//! - Cache files are local-only, never committed to Git or replicated

use auths_verifier::CommitOid;
use auths_verifier::types::IdentityDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[allow(clippy::disallowed_types)]
// INVARIANT: file-based cache adapter — fs types are core to this module
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::state::KeyState;
use super::types::Said;

/// Cache format version. Increment when CachedKelState structure changes.
pub const CACHE_VERSION: u32 = 2;

/// Cached key state from a validated KEL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedKelState {
    /// Cache format version for forward compatibility
    pub version: u32,
    /// The DID this cache entry is for (authoritative, verified on load)
    pub did: IdentityDID,
    /// Sequence number of the last event
    pub sequence: u64,
    /// SAID of the tip event when this cache was validated
    pub validated_against_tip_said: Said,
    /// Git commit OID of the tip event (hex-encoded) - enables incremental validation
    pub last_commit_oid: CommitOid,
    /// The validated key state
    pub state: KeyState,
    /// When this cache entry was created
    pub cached_at: DateTime<Utc>,
}

/// Errors that can occur during cache operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl auths_core::error::AuthsErrorInfo for CacheError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "AUTHS-E4981",
            Self::Json(_) => "AUTHS-E4982",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Io(_) => {
                Some("Check cache directory permissions; the cache is optional and can be cleared")
            }
            Self::Json(_) => {
                Some("The cache file may be corrupted; try clearing it with 'auths cache clear'")
            }
        }
    }
}

/// Returns the cache file path for a given DID.
///
/// Uses SHA-256 hash of the DID for the filename to avoid collisions
/// from different DIDs that might sanitize to the same string.
/// The actual DID is stored inside the JSON for verification.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID to compute the cache path for.
pub fn cache_path_for_did(auths_home: &Path, did: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let hash = hasher.finalize();
    let hex = hex::encode(hash);

    auths_home
        .join("cache")
        .join("kel")
        .join(format!("{}.json", hex))
}

/// Write a validated key state to the cache.
///
/// This performs an atomic write using a temp file, fsync, and rename
/// to prevent corrupted cache files from partial writes.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID identifier for this key state.
/// * `state` - The validated KeyState to cache.
/// * `tip_said` - The SAID of the tip event when validation occurred.
/// * `commit_oid` - The Git commit OID of the tip event (hex-encoded).
/// * `now` - The timestamp to record in the cache entry.
///
/// # Errors
/// Returns `CacheError` if the write fails. Callers should generally ignore
/// cache write errors since the cache is optional.
pub fn write_kel_cache(
    auths_home: &Path,
    did: &str,
    state: &KeyState,
    tip_said: &str,
    commit_oid: &str,
    now: DateTime<Utc>,
) -> Result<(), CacheError> {
    let cache = CachedKelState {
        version: CACHE_VERSION,
        did: IdentityDID::new_unchecked(did),
        sequence: state.sequence,
        validated_against_tip_said: Said::new_unchecked(tip_said.to_string()),
        last_commit_oid: CommitOid::new_unchecked(commit_oid),
        state: state.clone(),
        cached_at: now,
    };

    let path = cache_path_for_did(auths_home, did);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Atomic write: temp file -> fsync -> rename
    let temp_path = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        // Set restrictive permissions on Unix (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        let json = serde_json::to_vec_pretty(&cache)?;
        file.write_all(&json)?;
        file.sync_all()?;
    }

    fs::rename(&temp_path, &path)?;

    // Set permissions on final file too (rename can inherit different perms)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Try to load a cached key state for a given DID.
///
/// This performs strict validation of the cache entry:
/// - Version must match current CACHE_VERSION
/// - The stored DID must match the requested DID (prevents file swap attacks)
/// - The `validated_against_tip_said` must match the expected tip SAID
///
/// Returns `None` on any error or mismatch, causing a fallback to full replay.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID to look up.
/// * `expected_tip_said` - The SAID of the current KEL tip event.
///
/// # Returns
/// `Some(KeyState)` if a valid cache entry exists, `None` otherwise.
pub fn try_load_cached_state(
    auths_home: &Path,
    did: &str,
    expected_tip_said: &str,
) -> Option<KeyState> {
    let cache = try_load_cached_state_full(auths_home, did)?;

    // Strict SAID match - any mismatch means cache is stale
    if cache.validated_against_tip_said != expected_tip_said {
        return None;
    }

    Some(cache.state)
}

/// Try to load the full cached state entry for incremental validation.
///
/// This validates version and DID but does NOT check if the cache matches the
/// current tip. Used by the incremental validator to check if the cached
/// position is an ancestor of the current tip.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID to look up.
///
/// # Returns
/// `Some(CachedKelState)` if a parseable, valid-version cache entry exists.
pub fn try_load_cached_state_full(auths_home: &Path, did: &str) -> Option<CachedKelState> {
    let path = cache_path_for_did(auths_home, did);

    // Fail silently on any error - cache miss triggers full replay
    let contents = fs::read_to_string(&path).ok()?;
    let cache: CachedKelState = serde_json::from_str(&contents).ok()?;

    // Version check - cache format may have changed
    if cache.version != CACHE_VERSION {
        return None;
    }

    // DID must match - prevents file swap/collision attacks
    if cache.did.as_str() != did {
        return None;
    }

    Some(cache)
}

/// Invalidate (delete) the cache entry for a given DID.
///
/// This is useful when you know the KEL has changed and want to force
/// a full replay on the next `get_state()` call.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID whose cache entry should be deleted.
///
/// # Errors
/// Returns an error if the file exists but cannot be deleted.
pub fn invalidate_cache(auths_home: &Path, did: &str) -> Result<(), io::Error> {
    let path = cache_path_for_did(auths_home, did);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Information about a cached entry for display purposes.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The DID this cache is for
    pub did: IdentityDID,
    /// Sequence number
    pub sequence: u64,
    /// SAID the cache was validated against
    pub validated_against_tip_said: Said,
    /// Git commit OID of the cached position
    pub last_commit_oid: CommitOid,
    /// When the cache was created
    pub cached_at: DateTime<Utc>,
    /// Path to the cache file
    pub path: PathBuf,
}

/// List all cached entries with their metadata.
///
/// Since filenames are hashes, we need to read each file to get the DID.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
pub fn list_cached_entries(auths_home: &Path) -> Result<Vec<CacheEntry>, io::Error> {
    let cache_dir = auths_home.join("cache").join("kel");

    if !cache_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&cache_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json")
            && let Ok(contents) = fs::read_to_string(&path)
            && let Ok(cache) = serde_json::from_str::<CachedKelState>(&contents)
        {
            entries.push(CacheEntry {
                did: cache.did,
                sequence: cache.sequence,
                validated_against_tip_said: cache.validated_against_tip_said,
                last_commit_oid: cache.last_commit_oid,
                cached_at: cache.cached_at,
                path: path.clone(),
            });
        }
    }

    Ok(entries)
}

/// Clear all KEL cache entries.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
///
/// # Errors
/// Returns an error if the cache directory cannot be read or files cannot be deleted.
pub fn clear_all_caches(auths_home: &Path) -> Result<usize, io::Error> {
    let cache_dir = auths_home.join("cache").join("kel");

    if !cache_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in fs::read_dir(&cache_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            fs::remove_file(&path)?;
            count += 1;
        }
    }

    Ok(count)
}

/// Inspect a specific cache entry by DID.
///
/// Returns the full cached state if it exists and is parseable.
///
/// Args:
/// * `auths_home` - The Auths home directory (e.g. `~/.auths`).
/// * `did` - The DID to inspect.
pub fn inspect_cache(auths_home: &Path, did: &str) -> Result<Option<CachedKelState>, io::Error> {
    let path = cache_path_for_did(auths_home, did);

    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&path)?;
    match serde_json::from_str::<CachedKelState>(&contents) {
        Ok(cache) => Ok(Some(cache)),
        Err(_) => Ok(None), // Treat parse errors as missing
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::Prefix;
    use tempfile::TempDir;

    fn create_test_state() -> KeyState {
        KeyState::from_inception(
            Prefix::new_unchecked("ETestPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            1,
            1,
            Said::new_unchecked("ESaid123".to_string()),
        )
    }

    #[test]
    fn test_cache_path_uses_hash() {
        let dir = TempDir::new().unwrap();
        let path = cache_path_for_did(dir.path(), "did:keri:ETestPrefix");
        let filename = path.file_name().unwrap().to_string_lossy();
        // Should be a 64-char hex hash + .json
        assert!(filename.ends_with(".json"));
        assert_eq!(filename.len(), 64 + 5); // 64 hex chars + ".json"
    }

    #[test]
    fn test_different_dids_get_different_paths() {
        let dir = TempDir::new().unwrap();
        let path1 = cache_path_for_did(dir.path(), "did:keri:ETest1");
        let path2 = cache_path_for_did(dir.path(), "did:keri:ETest2");
        assert_ne!(path1, path2);
    }

    #[test]
    fn test_cache_write_and_read() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:ETest123";
        let state = create_test_state();
        let tip_said = "ELatestSaid";

        // Write cache
        write_kel_cache(
            dir.path(),
            did,
            &state,
            tip_said,
            "abc123def456",
            Utc::now(),
        )
        .unwrap();

        // Read it back
        let loaded = try_load_cached_state(dir.path(), did, tip_said);
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.prefix, state.prefix);
        assert_eq!(loaded.sequence, state.sequence);
    }

    #[test]
    fn test_cache_invalidation_on_said_mismatch() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:EMismatch";
        let state = create_test_state();

        // Write cache with one SAID
        write_kel_cache(dir.path(), did, &state, "EOldSaid", "commit123", Utc::now()).unwrap();

        // Try to load with different SAID - should return None
        let result = try_load_cached_state(dir.path(), did, "ENewSaid");
        assert!(result.is_none());

        // But loading with correct SAID works
        let result = try_load_cached_state(dir.path(), did, "EOldSaid");
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_invalidation_on_did_mismatch() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:EOriginal";
        let state = create_test_state();
        let tip_said = "ESaid";

        // Write cache
        write_kel_cache(
            dir.path(),
            did,
            &state,
            tip_said,
            "abc123def456",
            Utc::now(),
        )
        .unwrap();

        // Manually corrupt the cache by writing wrong DID
        let path = cache_path_for_did(dir.path(), did);
        let mut cache: CachedKelState =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        cache.did = IdentityDID::new_unchecked("did:keri:EWrongDid");
        fs::write(&path, serde_json::to_vec_pretty(&cache).unwrap()).unwrap();

        // Try to load - should return None due to DID mismatch
        let result = try_load_cached_state(dir.path(), did, tip_said);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_handles_missing_file() {
        let dir = TempDir::new().unwrap();
        let result = try_load_cached_state(dir.path(), "did:keri:ENonexistent", "ESomeSaid");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_handles_corrupt_file() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:ECorrupt";
        let path = cache_path_for_did(dir.path(), did);

        // Create parent dir and write corrupt JSON
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{ invalid json }").unwrap();

        // Should return None
        let result = try_load_cached_state(dir.path(), did, "ESomeSaid");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_version_mismatch() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:EVersionTest";
        let state = create_test_state();
        let tip_said = "ESaid";

        // Write cache
        write_kel_cache(
            dir.path(),
            did,
            &state,
            tip_said,
            "abc123def456",
            Utc::now(),
        )
        .unwrap();

        // Manually change version
        let path = cache_path_for_did(dir.path(), did);
        let mut cache: CachedKelState =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        cache.version = CACHE_VERSION + 1;
        fs::write(&path, serde_json::to_vec_pretty(&cache).unwrap()).unwrap();

        // Should return None due to version mismatch
        let result = try_load_cached_state(dir.path(), did, tip_said);
        assert!(result.is_none());
    }

    #[test]
    fn test_invalidate_cache() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:EToInvalidate";
        let state = create_test_state();

        // Write and verify cache exists
        write_kel_cache(dir.path(), did, &state, "ESaid", "commit123", Utc::now()).unwrap();
        assert!(try_load_cached_state(dir.path(), did, "ESaid").is_some());

        // Invalidate
        invalidate_cache(dir.path(), did).unwrap();

        // Should be gone
        assert!(try_load_cached_state(dir.path(), did, "ESaid").is_none());
    }

    #[test]
    fn test_invalidate_nonexistent_cache() {
        let dir = TempDir::new().unwrap();
        // Should succeed even if file doesn't exist
        let result = invalidate_cache(dir.path(), "did:keri:ENeverExisted");
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_cached_entries() {
        let dir = TempDir::new().unwrap();
        let state = create_test_state();

        // Write multiple caches
        write_kel_cache(
            dir.path(),
            "did:keri:ETest1",
            &state,
            "ESaid1",
            "commit1",
            Utc::now(),
        )
        .unwrap();
        write_kel_cache(
            dir.path(),
            "did:keri:ETest2",
            &state,
            "ESaid2",
            "commit2",
            Utc::now(),
        )
        .unwrap();

        let entries = list_cached_entries(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);

        let dids: Vec<_> = entries.iter().map(|e| e.did.as_str()).collect();
        assert!(dids.contains(&"did:keri:ETest1"));
        assert!(dids.contains(&"did:keri:ETest2"));
    }

    #[test]
    fn test_clear_all_caches() {
        let dir = TempDir::new().unwrap();
        let state = create_test_state();

        // Write multiple caches
        write_kel_cache(
            dir.path(),
            "did:keri:EClear1",
            &state,
            "ESaid",
            "commit1",
            Utc::now(),
        )
        .unwrap();
        write_kel_cache(
            dir.path(),
            "did:keri:EClear2",
            &state,
            "ESaid",
            "commit2",
            Utc::now(),
        )
        .unwrap();

        // Clear all
        let count = clear_all_caches(dir.path()).unwrap();
        assert_eq!(count, 2);

        // Verify empty
        let entries = list_cached_entries(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_inspect_cache() {
        let dir = TempDir::new().unwrap();
        let did = "did:keri:EInspect";
        let state = create_test_state();
        let tip_said = "ESaid";

        write_kel_cache(
            dir.path(),
            did,
            &state,
            tip_said,
            "abc123def456",
            Utc::now(),
        )
        .unwrap();

        let inspected = inspect_cache(dir.path(), did).unwrap();
        assert!(inspected.is_some());
        let inspected = inspected.unwrap();
        assert_eq!(inspected.did, did);
        assert_eq!(inspected.validated_against_tip_said, tip_said);
    }
}
