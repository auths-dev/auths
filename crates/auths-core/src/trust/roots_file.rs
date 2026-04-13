//! Roots file loader for CI explicit trust.
//!
//! This module provides loading and validation for `.auths/roots.json` files,
//! which allow repositories to define trusted identity roots for CI pipelines.

use auths_verifier::PublicKeyHex;
use serde::Deserialize;
use std::path::Path;

use crate::error::TrustError;

/// A roots.json file containing trusted identity roots.
///
/// This file is checked into repositories at `.auths/roots.json` to define
/// which identities are trusted for verification in CI environments.
///
/// # Format
///
/// ```json
/// {
///   "version": 1,
///   "roots": [
///     {
///       "did": "did:keri:EXq5YqaL...",
///       "public_key_hex": "7a3bc2...",
///       "kel_tip_said": "ERotSaid...",
///       "note": "Primary maintainer"
///     }
///   ]
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct RootsFile {
    /// Version of the roots file format. Currently must be 1.
    pub version: u32,

    /// List of trusted identity roots.
    pub roots: Vec<RootEntry>,
}

/// A single trusted identity root entry.
#[derive(Debug, Deserialize)]
pub struct RootEntry {
    /// The DID of the trusted identity (e.g., "did:keri:EXq5...")
    pub did: String,

    /// The public key in hex format (32 bytes Ed25519 or 33 bytes P-256 compressed).
    pub public_key_hex: PublicKeyHex,

    /// Curve of the root's public key (fn-114.35). Required — pre-launch hard
    /// break, no v1 fallback.
    pub curve: auths_crypto::CurveType,

    /// Optional KEL tip SAID for rotation-aware matching.
    #[serde(default)]
    pub kel_tip_said: Option<String>,

    /// Optional human-readable note about this root.
    #[serde(default)]
    pub note: Option<String>,
}

impl RootsFile {
    /// Parse roots from a JSON string (pure — no I/O).
    ///
    /// Prefer this over `load` when the caller already has the content.
    pub fn parse(content: &str) -> Result<Self, TrustError> {
        let file: Self = serde_json::from_str(content)?;

        if file.version != 2 {
            return Err(TrustError::InvalidData(format!(
                "Unsupported roots.json version: {}. Expected version 2 (fn-114.35 hard break).",
                file.version
            )));
        }

        Ok(file)
    }

    /// Load and validate a roots.json file.
    #[allow(clippy::disallowed_methods)] // INVARIANT: convenience wrapper; prefer parse() for sans-IO callers
    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Find a root entry by DID.
    pub fn find(&self, did: &str) -> Option<&RootEntry> {
        self.roots.iter().find(|r| r.did == did)
    }

    /// Get all DIDs in this roots file.
    pub fn dids(&self) -> Vec<&str> {
        self.roots.iter().map(|r| r.did.as_str()).collect()
    }
}

impl RootEntry {
    /// Decode the public key to raw bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, TrustError> {
        hex::decode(self.public_key_hex.as_str())
            .map_err(|e| TrustError::InvalidData(format!("Invalid public_key_hex: {}", e)))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
#[allow(clippy::disallowed_types)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_roots_file(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roots.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn test_load_valid_roots_file() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:ETest123",
                    "public_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "curve": "ed25519",
                    "kel_tip_said": "ETip",
                    "note": "Test maintainer"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let roots = RootsFile::load(&path).unwrap();

        assert_eq!(roots.version, 2);
        assert_eq!(roots.roots.len(), 1);
        assert_eq!(roots.roots[0].did, "did:keri:ETest123");
        assert_eq!(roots.roots[0].kel_tip_said, Some("ETip".to_string()));
        assert_eq!(roots.roots[0].note, Some("Test maintainer".to_string()));
    }

    #[test]
    fn test_load_minimal_entry() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:ETest",
                    "public_key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "curve": "ed25519"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let roots = RootsFile::load(&path).unwrap();

        assert_eq!(roots.roots[0].kel_tip_said, None);
        assert_eq!(roots.roots[0].note, None);
    }

    #[test]
    fn test_load_rejects_wrong_version() {
        // version 2 is the only supported; v1 or any other must reject.
        let content = r#"{
            "version": 1,
            "roots": []
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let result = RootsFile::load(&path);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_load_rejects_invalid_hex() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:ETest",
                    "public_key_hex": "not-valid-hex",
                    "curve": "ed25519"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let result = RootsFile::load(&path);

        assert!(result.is_err());
    }

    #[test]
    fn test_load_rejects_wrong_key_length() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:ETest",
                    "public_key_hex": "0102030405",
                    "curve": "ed25519"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let result = RootsFile::load(&path);

        assert!(result.is_err());
    }

    #[test]
    fn test_find_by_did() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:E111",
                    "public_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "curve": "ed25519"
                },
                {
                    "did": "did:keri:E222",
                    "public_key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "curve": "ed25519"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let roots = RootsFile::load(&path).unwrap();

        assert!(roots.find("did:keri:E111").is_some());
        assert!(roots.find("did:keri:E222").is_some());
        assert!(roots.find("did:keri:E333").is_none());
    }

    #[test]
    fn test_dids() {
        let content = r#"{
            "version": 2,
            "roots": [
                {
                    "did": "did:keri:E111",
                    "public_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "curve": "ed25519"
                },
                {
                    "did": "did:keri:E222",
                    "public_key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "curve": "ed25519"
                }
            ]
        }"#;

        let (_dir, path) = create_temp_roots_file(content);
        let roots = RootsFile::load(&path).unwrap();
        let dids = roots.dids();

        assert_eq!(dids.len(), 2);
        assert!(dids.contains(&"did:keri:E111"));
        assert!(dids.contains(&"did:keri:E222"));
    }

    #[test]
    fn test_root_entry_public_key_bytes() {
        let entry = RootEntry {
            did: "did:keri:ETest".to_string(),
            public_key_hex: PublicKeyHex::new_unchecked(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            ),
            curve: auths_crypto::CurveType::Ed25519,
            kel_tip_said: None,
            note: None,
        };

        let bytes = entry.public_key_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
    }
}
