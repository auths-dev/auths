use serde::{Deserialize, Serialize};

use crate::types::MerkleHash;

/// Merkle inclusion proof for a single entry in the log.
///
/// Proves that a leaf at `index` is included in the tree of `size` leaves
/// with the given `root`.
///
/// Args:
/// * `index` — Zero-based leaf index.
/// * `size` — Tree size (number of leaves) when the proof was generated.
/// * `root` — Merkle root at tree size `size`.
/// * `hashes` — Sibling hashes from leaf to root.
///
/// Usage:
/// ```ignore
/// let proof = InclusionProof { index: 5, size: 16, root, hashes: vec![...] };
/// proof.verify(&leaf_hash)?;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct InclusionProof {
    pub index: u64,
    pub size: u64,
    pub root: MerkleHash,
    pub hashes: Vec<MerkleHash>,
}

impl InclusionProof {
    /// Verify that `leaf_hash` is included in the tree.
    pub fn verify(&self, leaf_hash: &MerkleHash) -> Result<(), crate::error::TransparencyError> {
        crate::merkle::verify_inclusion(leaf_hash, self.index, self.size, &self.hashes, &self.root)
    }
}

/// Merkle consistency proof between two tree sizes.
///
/// Proves that the tree at `old_size` is a prefix of the tree at `new_size`.
///
/// Args:
/// * `old_size` — Earlier tree size.
/// * `new_size` — Later tree size.
/// * `old_root` — Root at `old_size`.
/// * `new_root` — Root at `new_size`.
/// * `hashes` — Consistency proof hashes.
///
/// Usage:
/// ```ignore
/// let proof = ConsistencyProof { old_size: 8, new_size: 16, .. };
/// proof.verify()?;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub old_root: MerkleHash,
    pub new_root: MerkleHash,
    pub hashes: Vec<MerkleHash>,
}

impl ConsistencyProof {
    /// Verify that the old tree is a prefix of the new tree.
    pub fn verify(&self) -> Result<(), crate::error::TransparencyError> {
        crate::merkle::verify_consistency(
            self.old_size,
            self.new_size,
            &self.hashes,
            &self.old_root,
            &self.new_root,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hash_children, hash_leaf};

    #[test]
    fn inclusion_proof_verify() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let root = hash_children(&a, &b);

        let proof = InclusionProof {
            index: 0,
            size: 2,
            root,
            hashes: vec![b],
        };
        proof.verify(&a).unwrap();
    }

    #[test]
    fn inclusion_proof_json_roundtrip() {
        let proof = InclusionProof {
            index: 3,
            size: 8,
            root: MerkleHash::from_bytes([0xaa; 32]),
            hashes: vec![
                MerkleHash::from_bytes([0xbb; 32]),
                MerkleHash::from_bytes([0xcc; 32]),
            ],
        };
        let json = serde_json::to_string(&proof).unwrap();
        let back: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
    }

    #[test]
    fn consistency_proof_json_roundtrip() {
        let proof = ConsistencyProof {
            old_size: 4,
            new_size: 8,
            old_root: MerkleHash::from_bytes([0x11; 32]),
            new_root: MerkleHash::from_bytes([0x22; 32]),
            hashes: vec![MerkleHash::from_bytes([0x33; 32])],
        };
        let json = serde_json::to_string(&proof).unwrap();
        let back: ConsistencyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
    }
}
