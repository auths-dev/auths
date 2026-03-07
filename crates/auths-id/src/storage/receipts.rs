//! Receipt storage for witness receipts.
//!
//! This module provides storage for witness receipts attached to KEL events.
//! Receipts are stored in Git refs under `refs/did/keri/<prefix>/receipts/<said>`.

use crate::error::StorageError;
use auths_core::witness::Receipt;
use git2::{ErrorCode, Repository, Signature};
use log::debug;
use ring::signature::{ED25519, UnparsedPublicKey};
use std::path::PathBuf;

use crate::keri::event::EventReceipts;
use crate::keri::{Prefix, Said};
use crate::storage::layout;

/// Standard filename for storing receipt data within commit blobs.
const RECEIPTS_BLOB_NAME: &str = "receipts.json";

/// Trait for receipt storage operations.
///
/// Implementations can be backed by Git (local) or other storage systems.
pub trait ReceiptStorage: Send + Sync {
    /// Store receipts for an event.
    fn store_receipts(&self, prefix: &Prefix, receipts: &EventReceipts)
    -> Result<(), StorageError>;

    /// Get receipts for an event by SAID.
    fn get_receipts(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<EventReceipts>, StorageError>;

    /// Check if event has sufficient receipts (meets threshold) without exceeding the witness set.
    fn has_quorum(
        &self,
        prefix: &Prefix,
        event_said: &Said,
        threshold: usize,
        witness_count: usize,
    ) -> Result<bool, StorageError>;

    /// List all event SAIDs that have receipts for a prefix.
    fn list_receipts(&self, prefix: &Prefix) -> Result<Vec<String>, StorageError>;
}

/// Git-backed receipt storage.
///
/// Stores receipts as JSON blobs in Git refs under `refs/did/keri/<prefix>/receipts/<said>`.
#[derive(Debug, Clone)]
pub struct GitReceiptStorage {
    repo_path: PathBuf,
}

impl GitReceiptStorage {
    /// Create a new GitReceiptStorage for the given repository path.
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
        }
    }

    fn open_repo(&self) -> Result<Repository, StorageError> {
        Ok(Repository::open(&self.repo_path)?)
    }
}

impl ReceiptStorage for GitReceiptStorage {
    fn store_receipts(
        &self,
        prefix: &Prefix,
        receipts: &EventReceipts,
    ) -> Result<(), StorageError> {
        debug!(
            "Storing {} receipts for event {} (prefix {})",
            receipts.count(),
            receipts.event_said,
            prefix.as_str()
        );

        let repo = self.open_repo()?;
        let event_said = receipts.event_said.clone();
        let ref_path = layout::keri_receipts_ref(prefix, &event_said);

        let json = serde_json::to_vec_pretty(receipts)?;
        let blob_oid = repo.blob(&json)?;

        let mut tree_builder = repo.treebuilder(None)?;
        tree_builder.insert(RECEIPTS_BLOB_NAME, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;

        let sig = repo
            .signature()
            .or_else(|_| Signature::now("auths-witness", "auths-witness@localhost"))?;

        let parent_commit = match repo.find_reference(&ref_path) {
            Ok(reference) => reference.peel_to_commit().ok(),
            Err(_) => None,
        };
        let parents: Vec<&git2::Commit> = parent_commit.iter().collect();

        let commit_message = format!(
            "Store {} receipts for event {}",
            receipts.count(),
            &receipts.event_said
        );
        let commit_oid = repo.commit(None, &sig, &sig, &commit_message, &tree, &parents)?;

        repo.reference(&ref_path, commit_oid, true, "store receipts")?;

        debug!("Stored receipts at {} (commit {})", ref_path, commit_oid);
        Ok(())
    }

    fn get_receipts(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<EventReceipts>, StorageError> {
        debug!(
            "Getting receipts for event {} (prefix {})",
            event_said.as_str(),
            prefix.as_str()
        );

        let repo = self.open_repo()?;
        let ref_path = layout::keri_receipts_ref(prefix, event_said);

        let reference = match repo.find_reference(&ref_path) {
            Ok(r) => r,
            Err(e) if e.code() == ErrorCode::NotFound => {
                debug!("No receipts found at {}", ref_path);
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        let commit = reference.peel_to_commit()?;
        let tree = commit.tree()?;

        let entry = tree
            .get_name(RECEIPTS_BLOB_NAME)
            .ok_or_else(|| StorageError::NotFound("Receipts blob not found in tree".into()))?;

        let blob = repo.find_blob(entry.id())?;
        let receipts: EventReceipts = serde_json::from_slice(blob.content())?;

        Ok(Some(receipts))
    }

    fn has_quorum(
        &self,
        prefix: &Prefix,
        event_said: &Said,
        threshold: usize,
        witness_count: usize,
    ) -> Result<bool, StorageError> {
        match self.get_receipts(prefix, event_said)? {
            Some(receipts) => Ok(receipts.meets_threshold(threshold, witness_count)),
            None => Ok(false),
        }
    }

    fn list_receipts(&self, prefix: &Prefix) -> Result<Vec<String>, StorageError> {
        let repo = self.open_repo()?;
        let prefix_path = layout::keri_receipts_prefix(prefix);

        let mut saids = Vec::new();

        for reference in repo.references()? {
            let reference = reference?;
            if let Some(name) = reference.name()
                && name.starts_with(&prefix_path)
                && let Some(said) = name.strip_prefix(&format!("{}/", prefix_path))
            {
                saids.push(said.to_string());
            }
        }

        Ok(saids)
    }
}

/// Verify a receipt's signature.
///
/// Verifies that the receipt was signed by the claimed witness.
///
/// # Arguments
/// * `receipt` - The receipt to verify
/// * `witness_public_key` - The Ed25519 public key of the witness (32 bytes)
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err` if verification fails due to malformed data
pub fn verify_receipt_signature(
    receipt: &Receipt,
    witness_public_key: &[u8],
) -> Result<bool, StorageError> {
    if witness_public_key.len() != 32 {
        return Err(StorageError::InvalidData(format!(
            "Invalid witness public key length: expected 32, got {}",
            witness_public_key.len()
        )));
    }

    let payload = format!("{}:{}:{}", receipt.i, receipt.s, receipt.a);

    let public_key = UnparsedPublicKey::new(&ED25519, witness_public_key);
    match public_key.verify(payload.as_bytes(), &receipt.sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check receipts for duplicity (conflicting SAIDs for same sequence).
///
/// If any two receipts claim different event SAIDs, duplicity is detected.
///
/// # Returns
/// * `Ok(())` if all receipts are consistent
/// * `Err` with duplicity evidence if conflicting SAIDs found
pub fn check_receipt_consistency(receipts: &[Receipt]) -> Result<(), StorageError> {
    if receipts.is_empty() {
        return Ok(());
    }

    let expected_said = &receipts[0].a;

    for receipt in receipts.iter().skip(1) {
        if &receipt.a != expected_said {
            return Err(StorageError::InvalidData(format!(
                "Duplicity detected: receipts claim different SAIDs ({} vs {})",
                expected_said, receipt.a
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::witness::{KERI_VERSION, RECEIPT_TYPE, Receipt};
    use auths_verifier::keri::Said;
    use git2::RepositoryInitOptions;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::tempdir;

    fn init_test_repo() -> (tempfile::TempDir, PathBuf, Repository) {
        let dir = tempdir().expect("Failed to create temp directory");
        let path = dir.path().to_path_buf();
        let mut opts = RepositoryInitOptions::new();
        opts.bare(true);
        let repo = Repository::init_opts(&path, &opts).expect("Failed to init repo");

        let mut config = repo.config().expect("Failed to get config");
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, path, repo)
    }

    fn make_test_receipt(event_said: &str, witness_did: &str, seq: u64) -> Receipt {
        Receipt {
            v: KERI_VERSION.into(),
            t: RECEIPT_TYPE.into(),
            d: Said::new_unchecked(format!("E{}", &event_said[1..])),
            i: witness_did.to_string(),
            s: seq,
            a: Said::new_unchecked(event_said.to_string()),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn test_store_and_get_receipts() {
        let (_td, path, _repo) = init_test_repo();
        let storage = GitReceiptStorage::new(&path);

        let receipts = EventReceipts::new(
            "ESAID123",
            vec![
                make_test_receipt("ESAID123", "did:key:witness1", 0),
                make_test_receipt("ESAID123", "did:key:witness2", 0),
            ],
        );

        let prefix = Prefix::new_unchecked("EPrefix".to_string());
        storage.store_receipts(&prefix, &receipts).unwrap();

        let said = Said::new_unchecked("ESAID123".to_string());
        let retrieved = storage.get_receipts(&prefix, &said).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.event_said, "ESAID123");
        assert_eq!(retrieved.count(), 2);
    }

    #[test]
    fn test_get_receipts_not_found() {
        let (_td, path, _repo) = init_test_repo();
        let storage = GitReceiptStorage::new(&path);

        let prefix = Prefix::new_unchecked("EPrefix".to_string());
        let said = Said::new_unchecked("NONEXISTENT".to_string());
        let result = storage.get_receipts(&prefix, &said).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_has_quorum() {
        let (_td, path, _repo) = init_test_repo();
        let storage = GitReceiptStorage::new(&path);

        let receipts = EventReceipts::new(
            "ESAID456",
            vec![
                make_test_receipt("ESAID456", "did:key:w1", 0),
                make_test_receipt("ESAID456", "did:key:w2", 0),
            ],
        );

        let prefix = Prefix::new_unchecked("EPrefix".to_string());
        storage.store_receipts(&prefix, &receipts).unwrap();

        let said = Said::new_unchecked("ESAID456".to_string());
        // 2 receipts, threshold 2, witness_count 3 - should meet
        assert!(storage.has_quorum(&prefix, &said, 2, 3).unwrap());

        // 2 receipts, threshold 3, witness_count 3 - should not meet
        assert!(!storage.has_quorum(&prefix, &said, 3, 3).unwrap());
    }

    #[test]
    fn test_list_receipts() {
        let (_td, path, _repo) = init_test_repo();
        let storage = GitReceiptStorage::new(&path);

        let prefix = Prefix::new_unchecked("EPrefix".to_string());
        // Store receipts for multiple events
        storage
            .store_receipts(
                &prefix,
                &EventReceipts::new("ESAID1", vec![make_test_receipt("ESAID1", "did:key:w", 0)]),
            )
            .unwrap();
        storage
            .store_receipts(
                &prefix,
                &EventReceipts::new("ESAID2", vec![make_test_receipt("ESAID2", "did:key:w", 1)]),
            )
            .unwrap();

        let saids = storage.list_receipts(&prefix).unwrap();
        assert_eq!(saids.len(), 2);
        assert!(saids.contains(&"ESAID1".to_string()));
        assert!(saids.contains(&"ESAID2".to_string()));
    }

    #[test]
    fn test_event_receipts_meets_threshold() {
        let receipts = EventReceipts::new(
            "ESAID",
            vec![
                make_test_receipt("ESAID", "did:key:w1", 0),
                make_test_receipt("ESAID", "did:key:w2", 0),
            ],
        );

        assert!(receipts.meets_threshold(1, 3));
        assert!(receipts.meets_threshold(2, 3));
        assert!(!receipts.meets_threshold(3, 3));
    }

    #[test]
    fn test_check_receipt_consistency_ok() {
        let receipts = vec![
            make_test_receipt("ESAID", "did:key:w1", 0),
            make_test_receipt("ESAID", "did:key:w2", 0),
            make_test_receipt("ESAID", "did:key:w3", 0),
        ];

        assert!(check_receipt_consistency(&receipts).is_ok());
    }

    #[test]
    fn test_check_receipt_consistency_duplicity() {
        let receipts = vec![
            make_test_receipt("ESAID_A", "did:key:w1", 0),
            make_test_receipt("ESAID_B", "did:key:w2", 0), // Different SAID!
        ];

        let result = check_receipt_consistency(&receipts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicity"));
    }

    #[test]
    fn test_check_receipt_consistency_empty() {
        let receipts: Vec<Receipt> = vec![];
        assert!(check_receipt_consistency(&receipts).is_ok());
    }

    #[test]
    fn test_verify_receipt_signature_valid() {
        // Generate a real keypair
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = keypair.public_key().as_ref().to_vec();

        // Create and sign a receipt
        let mut receipt = make_test_receipt("ESAID", "did:key:test", 0);
        let payload = format!("{}:{}:{}", receipt.i, receipt.s, receipt.a);
        receipt.sig = keypair.sign(payload.as_bytes()).as_ref().to_vec();

        // Verify
        let result = verify_receipt_signature(&receipt, &public_key).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_receipt_signature_invalid() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = keypair.public_key().as_ref().to_vec();

        // Create receipt with wrong signature
        let receipt = make_test_receipt("ESAID", "did:key:test", 0);
        // sig is all zeros, won't match

        let result = verify_receipt_signature(&receipt, &public_key).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_receipt_signature_bad_key_length() {
        let receipt = make_test_receipt("ESAID", "did:key:test", 0);
        let bad_key = vec![0u8; 16]; // Wrong length

        let result = verify_receipt_signature(&receipt, &bad_key);
        assert!(result.is_err());
    }
}
