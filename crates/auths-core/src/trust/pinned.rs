//! Pin records for trusted identities.
//!
//! This module defines the data structures for storing pinned identity roots,
//! enabling TOFU (Trust On First Use) and key rotation tracking.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A pinned identity root — what we trusted and when.
///
/// This record stores the state of a trusted identity at the time of pinning,
/// including KEL context for rotation-aware verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedIdentity {
    /// The DID being pinned (e.g., "did:keri:EXq5...")
    pub did: String,

    /// Root public key, raw bytes stored as lowercase hex.
    ///
    /// Always normalized at pin-time via `hex::encode`.
    /// All comparisons happen on decoded bytes, never on strings.
    pub public_key_hex: String,

    /// KEL tip SAID at the time of pinning (enables rotation continuity check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kel_tip_said: Option<String>,

    /// KEL sequence number at time of pinning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kel_sequence: Option<u64>,

    /// When this pin was created.
    pub first_seen: DateTime<Utc>,

    /// Where we learned this identity (repo URL, file path, "manual", etc.)
    pub origin: String,

    /// How this pin was established.
    pub trust_level: TrustLevel,
}

impl PinnedIdentity {
    /// Decode the pinned public key to raw bytes.
    ///
    /// Validates hex at construction; this should never fail on a well-formed pin.
    pub fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        hex::decode(&self.public_key_hex)
            .map_err(|e| anyhow::anyhow!("Corrupt pin for {}: invalid hex: {}", self.did, e))
    }

    /// Check if the pinned key matches the given raw bytes.
    ///
    /// Comparison is always on decoded bytes, never on string representation.
    /// This handles case differences and other encoding variations.
    pub fn key_matches(&self, presented_pk: &[u8]) -> anyhow::Result<bool> {
        Ok(self.public_key_bytes()? == presented_pk)
    }
}

/// How a pin was established.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Accepted on first use (interactive)
    Tofu,

    /// Manually pinned via `auths trust pin` or `--issuer-pk`
    Manual,

    /// Loaded from a roots.json org policy file
    OrgPolicy,
}

/// File-backed store of pinned identities.
///
/// Storage format: a single JSON array file (`~/.auths/known_identities.json`).
/// All mutations are atomic (write to temp + rename).
/// Concurrent access is guarded by an advisory lock file.
///
/// # Example
///
/// ```ignore
/// use auths_core::trust::PinnedIdentityStore;
///
/// let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());
///
/// // Look up a pinned identity
/// if let Some(pin) = store.lookup("did:keri:ETest...")? {
///     println!("Pinned key: {}", pin.public_key_hex);
/// }
/// ```
pub struct PinnedIdentityStore {
    path: PathBuf,
}

impl PinnedIdentityStore {
    /// Create a store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default path: `~/.auths/known_identities.json`
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".auths")
            .join("known_identities.json")
    }

    /// Look up a pinned identity by DID.
    pub fn lookup(&self, did: &str) -> anyhow::Result<Option<PinnedIdentity>> {
        let _lock = self.lock()?;
        Ok(self.read_all()?.into_iter().find(|e| e.did == did))
    }

    /// Pin a new identity.
    ///
    /// The public key hex is validated at pin-time.
    /// Errors if the DID is already pinned (use `update` for rotation).
    pub fn pin(&self, identity: PinnedIdentity) -> anyhow::Result<()> {
        // Validate hex at pin-time, not at verification-time
        let _ = hex::decode(&identity.public_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid public_key_hex: {}", e))?;

        let _lock = self.lock()?;
        let mut entries = self.read_all()?;
        if entries.iter().any(|e| e.did == identity.did) {
            anyhow::bail!(
                "Identity {} already pinned. Use `auths trust remove` first, or rotation \
                 will be handled automatically via continuity checking.",
                identity.did
            );
        }
        entries.push(identity);
        self.write_all(&entries)
    }

    /// Update an existing pin (after verified rotation).
    pub fn update(&self, identity: PinnedIdentity) -> anyhow::Result<()> {
        let _lock = self.lock()?;
        let mut entries = self.read_all()?;
        let pos = entries
            .iter()
            .position(|e| e.did == identity.did)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot update: identity {} not found in pin store.",
                    identity.did
                )
            })?;
        entries[pos] = identity;
        self.write_all(&entries)
    }

    /// Remove a pinned identity by DID.
    ///
    /// Returns `true` if an entry was removed, `false` if not found.
    pub fn remove(&self, did: &str) -> anyhow::Result<bool> {
        let _lock = self.lock()?;
        let mut entries = self.read_all()?;
        let before = entries.len();
        entries.retain(|e| e.did != did);
        if entries.len() < before {
            self.write_all(&entries)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all pinned identities.
    pub fn list(&self) -> anyhow::Result<Vec<PinnedIdentity>> {
        let _lock = self.lock()?;
        self.read_all()
    }

    // --- Internal ---

    fn read_all(&self) -> anyhow::Result<Vec<PinnedIdentity>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let content = fs::read_to_string(&self.path)?;
        let entries: Vec<PinnedIdentity> = serde_json::from_str(&content).map_err(|e| {
            anyhow::anyhow!(
                "Corrupt pin store at {:?}: {}. Consider deleting and re-pinning.",
                self.path,
                e
            )
        })?;
        Ok(entries)
    }

    fn write_all(&self, entries: &[PinnedIdentity]) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut file = fs::File::create(&tmp)?;
            let json = serde_json::to_string_pretty(entries)?;
            file.write_all(json.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn lock(&self) -> anyhow::Result<LockGuard> {
        let lock_path = self.path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        LockGuard::acquire(lock_path)
    }
}

/// Simple advisory file lock. Blocks until acquired. Released on drop.
struct LockGuard {
    path: PathBuf,
    _file: fs::File,
}

impl LockGuard {
    fn acquire(path: PathBuf) -> anyhow::Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;

        // Platform-specific advisory lock
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // SAFETY: flock is safe to call with a valid fd
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                anyhow::bail!("Failed to acquire lock on {:?}", path);
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix, best-effort: existence of lock file is the lock.
            // Acceptable for v1; Windows file locking can be added later.
        }

        Ok(Self { path, _file: file })
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pin() -> PinnedIdentity {
        PinnedIdentity {
            did: "did:keri:ETest123".to_string(),
            public_key_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
            kel_tip_said: Some("ETip".to_string()),
            kel_sequence: Some(0),
            first_seen: Utc::now(),
            origin: "test".to_string(),
            trust_level: TrustLevel::Tofu,
        }
    }

    #[test]
    fn test_public_key_bytes_valid() {
        let pin = make_test_pin();
        let bytes = pin.public_key_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[31], 0x20);
    }

    #[test]
    fn test_public_key_bytes_invalid_hex() {
        let mut pin = make_test_pin();
        pin.public_key_hex = "not-valid-hex".to_string();
        let result = pin.public_key_bytes();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Corrupt pin"));
    }

    #[test]
    fn test_key_matches_true() {
        let pin = make_test_pin();
        let expected: Vec<u8> = (1..=32).collect();
        assert!(pin.key_matches(&expected).unwrap());
    }

    #[test]
    fn test_key_matches_false() {
        let pin = make_test_pin();
        let wrong: Vec<u8> = vec![0; 32];
        assert!(!pin.key_matches(&wrong).unwrap());
    }

    #[test]
    fn test_key_matches_case_insensitive() {
        // Mixed case hex should still match
        let mut pin = make_test_pin();
        pin.public_key_hex =
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20".to_string();
        let expected: Vec<u8> = (1..=32).collect();
        assert!(pin.key_matches(&expected).unwrap());
    }

    #[test]
    fn test_trust_level_serialization() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::Tofu).unwrap(),
            "\"tofu\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::Manual).unwrap(),
            "\"manual\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::OrgPolicy).unwrap(),
            "\"org_policy\""
        );
    }

    #[test]
    fn test_pinned_identity_serialization_roundtrip() {
        let pin = make_test_pin();
        let json = serde_json::to_string(&pin).unwrap();
        let parsed: PinnedIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(pin.did, parsed.did);
        assert_eq!(pin.public_key_hex, parsed.public_key_hex);
        assert_eq!(pin.kel_tip_said, parsed.kel_tip_said);
        assert_eq!(pin.kel_sequence, parsed.kel_sequence);
        assert_eq!(pin.trust_level, parsed.trust_level);
    }

    #[test]
    fn test_optional_fields_skipped() {
        let mut pin = make_test_pin();
        pin.kel_tip_said = None;
        pin.kel_sequence = None;

        let json = serde_json::to_string(&pin).unwrap();
        assert!(!json.contains("kel_tip_said"));
        assert!(!json.contains("kel_sequence"));
    }

    // --- PinnedIdentityStore tests ---

    fn temp_store() -> (tempfile::TempDir, PinnedIdentityStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_identities.json");
        let store = PinnedIdentityStore::new(path);
        (dir, store)
    }

    #[test]
    fn test_store_lookup_empty() {
        let (_dir, store) = temp_store();
        let result = store.lookup("did:keri:ENonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_store_pin_and_lookup() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();

        store.pin(pin.clone()).unwrap();

        let found = store.lookup(&pin.did).unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.did, pin.did);
        assert_eq!(found.public_key_hex, pin.public_key_hex);
    }

    #[test]
    fn test_store_pin_rejects_invalid_hex() {
        let (_dir, store) = temp_store();
        let mut pin = make_test_pin();
        pin.public_key_hex = "not-valid-hex".to_string();

        let result = store.pin(pin);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_store_pin_rejects_duplicate() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();

        store.pin(pin.clone()).unwrap();
        let result = store.pin(pin);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already pinned"));
    }

    #[test]
    fn test_store_update() {
        let (_dir, store) = temp_store();
        let mut pin = make_test_pin();
        store.pin(pin.clone()).unwrap();

        // Update with new key
        pin.public_key_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        pin.kel_sequence = Some(1);
        store.update(pin.clone()).unwrap();

        let found = store.lookup(&pin.did).unwrap().unwrap();
        assert_eq!(found.kel_sequence, Some(1));
        assert!(found.public_key_hex.starts_with("aaaa"));
    }

    #[test]
    fn test_store_update_nonexistent() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();

        let result = store.update(pin);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_store_remove() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();
        store.pin(pin.clone()).unwrap();

        assert!(store.remove(&pin.did).unwrap());
        assert!(store.lookup(&pin.did).unwrap().is_none());
    }

    #[test]
    fn test_store_remove_nonexistent() {
        let (_dir, store) = temp_store();
        assert!(!store.remove("did:keri:ENonexistent").unwrap());
    }

    #[test]
    fn test_store_list() {
        let (_dir, store) = temp_store();

        let mut pin1 = make_test_pin();
        pin1.did = "did:keri:E111".to_string();
        let mut pin2 = make_test_pin();
        pin2.did = "did:keri:E222".to_string();

        store.pin(pin1).unwrap();
        store.pin(pin2).unwrap();

        let all = store.list().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_concurrent_access_no_corruption() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_identities.json");

        // Seed the store file so concurrent threads don't race on first-create
        std::fs::write(&path, "[]").unwrap();

        let store = Arc::new(PinnedIdentityStore::new(path));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let mut pin = make_test_pin();
                    pin.did = format!("did:keri:E{:03}", i);
                    store.pin(pin).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let all = store.list().unwrap();
        assert_eq!(all.len(), 10);

        for i in 0..10 {
            let did = format!("did:keri:E{:03}", i);
            assert!(
                store.lookup(&did).unwrap().is_some(),
                "Missing pin: {}",
                did
            );
        }
    }
}
