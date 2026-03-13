use sha2::{Digest, Sha256};

use crate::error::TransparencyError;
use crate::types::MerkleHash;

/// RFC 6962 leaf domain separator.
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 interior node domain separator.
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf value with RFC 6962 domain separation: `SHA-256(0x00 || data)`.
///
/// Args:
/// * `data` — Raw leaf bytes (typically canonical JSON of an entry).
///
/// Usage:
/// ```ignore
/// let leaf = hash_leaf(b"entry data");
/// ```
pub fn hash_leaf(data: &[u8]) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    MerkleHash::from_bytes(out)
}

/// Hash two child nodes with RFC 6962 domain separation: `SHA-256(0x01 || left || right)`.
///
/// Args:
/// * `left` — Left child hash.
/// * `right` — Right child hash.
///
/// Usage:
/// ```ignore
/// let parent = hash_children(&left_hash, &right_hash);
/// ```
pub fn hash_children(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    MerkleHash::from_bytes(out)
}

/// Verify a Merkle inclusion proof for a leaf at a given index in a tree of `size` leaves.
///
/// Uses RFC 6962 proof verification: walk from the leaf hash up to the root,
/// combining with proof hashes left or right depending on the index bits.
///
/// Args:
/// * `leaf_hash` — The hash of the leaf being proven.
/// * `index` — Zero-based index of the leaf.
/// * `size` — Total number of leaves in the tree.
/// * `proof` — Ordered list of sibling hashes from leaf to root.
/// * `root` — Expected Merkle root.
///
/// Usage:
/// ```ignore
/// verify_inclusion(&leaf_hash, 5, 16, &proof_hashes, &expected_root)?;
/// ```
pub fn verify_inclusion(
    leaf_hash: &MerkleHash,
    index: u64,
    size: u64,
    proof: &[MerkleHash],
    root: &MerkleHash,
) -> Result<(), TransparencyError> {
    if size == 0 {
        return Err(TransparencyError::InvalidProof("tree size is 0".into()));
    }
    if index >= size {
        return Err(TransparencyError::InvalidProof(format!(
            "index {index} >= size {size}"
        )));
    }

    let (computed, _) = root_from_inclusion_proof(leaf_hash, index, size, proof)?;

    if computed != *root {
        return Err(TransparencyError::RootMismatch {
            expected: root.to_string(),
            actual: computed.to_string(),
        });
    }
    Ok(())
}

/// Compute the root hash from an inclusion proof.
///
/// Returns `(root, proof_elements_consumed)`.
fn root_from_inclusion_proof(
    leaf_hash: &MerkleHash,
    index: u64,
    size: u64,
    proof: &[MerkleHash],
) -> Result<(MerkleHash, usize), TransparencyError> {
    let expected_len = inclusion_proof_length(index, size);
    if proof.len() != expected_len {
        return Err(TransparencyError::InvalidProof(format!(
            "expected {expected_len} proof elements, got {}",
            proof.len()
        )));
    }

    let mut hash = *leaf_hash;
    let mut idx = index;
    let mut level_size = size;
    let mut pos = 0;

    while level_size > 1 {
        if pos >= proof.len() {
            return Err(TransparencyError::InvalidProof("proof too short".into()));
        }
        if idx & 1 == 1 || idx + 1 == level_size {
            if idx & 1 == 1 {
                hash = hash_children(&proof[pos], &hash);
                pos += 1;
            }
        } else {
            hash = hash_children(&hash, &proof[pos]);
            pos += 1;
        }
        idx >>= 1;
        level_size = (level_size + 1) >> 1;
    }

    Ok((hash, pos))
}

/// Compute the expected number of proof elements for an inclusion proof.
fn inclusion_proof_length(index: u64, size: u64) -> usize {
    if size <= 1 {
        return 0;
    }
    let mut length = 0;
    let mut idx = index;
    let mut level_size = size;
    while level_size > 1 {
        if idx & 1 == 1 || idx + 1 < level_size {
            length += 1;
        }
        idx >>= 1;
        level_size = (level_size + 1) >> 1;
    }
    length
}

/// Verify a consistency proof between an old tree of `old_size` and a new tree of `new_size`.
///
/// Ensures the new tree is an append-only extension of the old tree.
///
/// Args:
/// * `old_size` — Number of leaves in the older tree.
/// * `new_size` — Number of leaves in the newer tree.
/// * `proof` — Ordered consistency proof hashes.
/// * `old_root` — Root of the older tree.
/// * `new_root` — Root of the newer tree.
///
/// Usage:
/// ```ignore
/// verify_consistency(8, 16, &proof, &old_root, &new_root)?;
/// ```
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[MerkleHash],
    old_root: &MerkleHash,
    new_root: &MerkleHash,
) -> Result<(), TransparencyError> {
    if old_size == 0 {
        if proof.is_empty() {
            return Ok(());
        }
        return Err(TransparencyError::ConsistencyError(
            "non-empty proof for empty old tree".into(),
        ));
    }
    if old_size > new_size {
        return Err(TransparencyError::ConsistencyError(format!(
            "old size {old_size} > new size {new_size}"
        )));
    }
    if old_size == new_size {
        if !proof.is_empty() {
            return Err(TransparencyError::ConsistencyError(
                "non-empty proof for equal sizes".into(),
            ));
        }
        if old_root != new_root {
            return Err(TransparencyError::RootMismatch {
                expected: old_root.to_string(),
                actual: new_root.to_string(),
            });
        }
        return Ok(());
    }

    // Reconstruct new root from the consistency proof while implicitly verifying old root.
    // For power-of-2 old_size, old_root is used directly as the starting hash.
    // For non-power-of-2, proof elements reconstruct old_root via the bit-walking algorithm.
    let new_computed = new_root_from_consistency_proof(old_size, new_size, proof, old_root)?;

    if new_computed != *new_root {
        return Err(TransparencyError::RootMismatch {
            expected: new_root.to_string(),
            actual: new_computed.to_string(),
        });
    }
    Ok(())
}

/// Reconstruct new root from an RFC 6962 SUBPROOF-format consistency proof.
///
/// The proof is produced by the SUBPROOF(m, D[0:n], b=true) algorithm from
/// RFC 6962 Section 2.1.2. Verification walks the bit pattern of (old_size - 1)
/// to reconstruct both old_root (for validation) and new_root.
///
/// Phase 1 (decomposition): each bit of (old_size - 1) determines whether a
/// proof element is a left sibling (set bit → combines into both roots) or
/// a right sibling (unset bit → combines into new root only).
///
/// Phase 2 (extension): remaining proof elements extend the accumulator to
/// the new root.
fn new_root_from_consistency_proof(
    old_size: u64,
    new_size: u64,
    proof: &[MerkleHash],
    old_root: &MerkleHash,
) -> Result<MerkleHash, TransparencyError> {
    let _ = new_size; // used only in debug assertions via caller

    let (mut fn_hash, mut fr_hash, start) = if old_size.is_power_of_two() {
        // Old tree is a single complete subtree — no decomposition needed
        (*old_root, *old_root, 0)
    } else {
        if proof.is_empty() {
            return Err(TransparencyError::ConsistencyError(
                "proof too short".into(),
            ));
        }
        (proof[0], proof[0], 1)
    };

    let mut pos = start;

    // Phase 1: walk bits of (old_size - 1) to decompose/reconstruct old root
    if !old_size.is_power_of_two() {
        let mut bit = old_size - 1;
        while bit > 0 {
            if pos >= proof.len() {
                return Err(TransparencyError::ConsistencyError(
                    "proof too short during decomposition".into(),
                ));
            }
            if bit & 1 != 0 {
                fn_hash = hash_children(&proof[pos], &fn_hash);
                fr_hash = hash_children(&proof[pos], &fr_hash);
            } else {
                fr_hash = hash_children(&fr_hash, &proof[pos]);
            }
            pos += 1;
            bit >>= 1;
        }

        if fn_hash != *old_root {
            return Err(TransparencyError::RootMismatch {
                expected: old_root.to_string(),
                actual: fn_hash.to_string(),
            });
        }
    }

    // Phase 2: extension elements build up to the new root
    while pos < proof.len() {
        fr_hash = hash_children(&fr_hash, &proof[pos]);
        pos += 1;
    }

    Ok(fr_hash)
}

/// Compute the Merkle root of a list of leaf hashes per RFC 6962 Section 2.1.
///
/// Recursively splits at the largest power of 2 less than `n`:
/// `MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` where `k = 2^(floor(log2(n-1)))`.
///
/// Args:
/// * `leaves` — Slice of leaf hashes. Empty input returns `MerkleHash::EMPTY`.
///
/// Usage:
/// ```ignore
/// let root = compute_root(&leaf_hashes);
/// ```
pub fn compute_root(leaves: &[MerkleHash]) -> MerkleHash {
    match leaves.len() {
        0 => MerkleHash::EMPTY,
        1 => leaves[0],
        n => {
            let k = largest_power_of_2_lt(n as u64) as usize;
            let left = compute_root(&leaves[..k]);
            let right = compute_root(&leaves[k..]);
            hash_children(&left, &right)
        }
    }
}

/// Largest power of 2 strictly less than `n` (for n > 1).
fn largest_power_of_2_lt(n: u64) -> u64 {
    debug_assert!(n > 1);
    if n.is_power_of_two() {
        n / 2
    } else {
        1u64 << (63 - n.leading_zeros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_leaf_domain_separation() {
        let data = b"test data";
        let h = hash_leaf(data);

        // Manually compute SHA-256(0x00 || "test data")
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(data);
        let expected = hasher.finalize();

        assert_eq!(h.as_bytes(), expected.as_slice());
    }

    #[test]
    fn hash_children_domain_separation() {
        let left = MerkleHash::from_bytes([0x11; 32]);
        let right = MerkleHash::from_bytes([0x22; 32]);
        let h = hash_children(&left, &right);

        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update([0x11; 32]);
        hasher.update([0x22; 32]);
        let expected = hasher.finalize();

        assert_eq!(h.as_bytes(), expected.as_slice());
    }

    #[test]
    fn leaf_and_children_produce_different_hashes() {
        let data = [0xab; 64];
        let leaf = hash_leaf(&data);

        let left = MerkleHash::from_bytes(data[..32].try_into().unwrap());
        let right = MerkleHash::from_bytes(data[32..].try_into().unwrap());
        let node = hash_children(&left, &right);

        assert_ne!(leaf, node);
    }

    #[test]
    fn compute_root_single_leaf() {
        let h = MerkleHash::from_bytes([0x42; 32]);
        assert_eq!(compute_root(&[h]), h);
    }

    #[test]
    fn compute_root_empty() {
        assert_eq!(compute_root(&[]), MerkleHash::EMPTY);
    }

    #[test]
    fn compute_root_two_leaves() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let root = compute_root(&[a, b]);
        assert_eq!(root, hash_children(&a, &b));
    }

    #[test]
    fn inclusion_proof_single_leaf() {
        let leaf = hash_leaf(b"only leaf");
        let root = leaf;
        verify_inclusion(&leaf, 0, 1, &[], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_two_leaves() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let root = hash_children(&a, &b);

        // Prove leaf 0 (a) with sibling b
        verify_inclusion(&a, 0, 2, &[b], &root).unwrap();
        // Prove leaf 1 (b) with sibling a
        verify_inclusion(&b, 1, 2, &[a], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_four_leaves() {
        let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
        let root = compute_root(&leaves);

        // Prove leaf 0: needs leaf 1 as sibling, then hash(leaf2, leaf3) as uncle
        let ab = hash_children(&leaves[0], &leaves[1]);
        let cd = hash_children(&leaves[2], &leaves[3]);
        let _ = hash_children(&ab, &cd);

        verify_inclusion(&leaves[0], 0, 4, &[leaves[1], cd], &root).unwrap();
        verify_inclusion(&leaves[1], 1, 4, &[leaves[0], cd], &root).unwrap();
        verify_inclusion(&leaves[2], 2, 4, &[leaves[3], ab], &root).unwrap();
        verify_inclusion(&leaves[3], 3, 4, &[leaves[2], ab], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_rejects_wrong_root() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let _root = hash_children(&a, &b);
        let wrong = MerkleHash::from_bytes([0xff; 32]);

        let err = verify_inclusion(&a, 0, 2, &[b], &wrong);
        assert!(err.is_err());
    }

    #[test]
    fn inclusion_proof_three_leaves() {
        let leaves: Vec<MerkleHash> = (0..3u8).map(|i| hash_leaf(&[i])).collect();
        let root = compute_root(&leaves);

        let ab = hash_children(&leaves[0], &leaves[1]);

        // Leaf 0: sibling = leaf[1], then uncle = leaf[2]
        verify_inclusion(&leaves[0], 0, 3, &[leaves[1], leaves[2]], &root).unwrap();
        // Leaf 1: sibling = leaf[0], then uncle = leaf[2]
        verify_inclusion(&leaves[1], 1, 3, &[leaves[0], leaves[2]], &root).unwrap();
        // Leaf 2: sibling = ab (promoted, no right sibling at level 0)
        verify_inclusion(&leaves[2], 2, 3, &[ab], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_five_leaves() {
        let leaves: Vec<MerkleHash> = (0..5u8).map(|i| hash_leaf(&[i])).collect();
        let root = compute_root(&leaves);

        let h01 = hash_children(&leaves[0], &leaves[1]);
        let h23 = hash_children(&leaves[2], &leaves[3]);
        let h0123 = hash_children(&h01, &h23);

        // Leaf 4: it's the last leaf (unpaired), needs h0123 as sibling
        verify_inclusion(&leaves[4], 4, 5, &[h0123], &root).unwrap();
        // Leaf 0: sibling leaf[1], uncle h23, then uncle leaf[4]
        verify_inclusion(&leaves[0], 0, 5, &[leaves[1], h23, leaves[4]], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_seven_leaves() {
        let leaves: Vec<MerkleHash> = (0..7u8).map(|i| hash_leaf(&[i])).collect();
        let root = compute_root(&leaves);

        let h01 = hash_children(&leaves[0], &leaves[1]);
        let h23 = hash_children(&leaves[2], &leaves[3]);
        let h45 = hash_children(&leaves[4], &leaves[5]);
        let h0123 = hash_children(&h01, &h23);
        let h456 = hash_children(&h45, &leaves[6]);

        // Leaf 6: unpaired at level 0, sibling is h45, then uncle is h0123
        verify_inclusion(&leaves[6], 6, 7, &[h45, h0123], &root).unwrap();
        // Leaf 0: sibling leaf[1], uncle h23, then uncle h456
        verify_inclusion(&leaves[0], 0, 7, &[leaves[1], h23, h456], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_rejects_index_out_of_range() {
        let a = hash_leaf(b"a");
        let root = a;
        let err = verify_inclusion(&a, 1, 1, &[], &root);
        assert!(err.is_err());
    }

    #[test]
    fn consistency_proof_same_size() {
        let root = MerkleHash::from_bytes([0x42; 32]);
        verify_consistency(5, 5, &[], &root, &root).unwrap();
    }

    #[test]
    fn consistency_proof_empty_old() {
        let new_root = MerkleHash::from_bytes([0x42; 32]);
        let old_root = MerkleHash::EMPTY;
        verify_consistency(0, 5, &[], &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_2_to_4() {
        let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..2]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..2], &leaves);
        verify_consistency(2, 4, &proof, &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_3_to_5() {
        let leaves: Vec<MerkleHash> = (0..5u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..3]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..3], &leaves);
        verify_consistency(3, 5, &proof, &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_4_to_8() {
        let leaves: Vec<MerkleHash> = (0..8u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..4], &leaves);
        verify_consistency(4, 8, &proof, &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_7_to_15() {
        let leaves: Vec<MerkleHash> = (0..15u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..7]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..7], &leaves);
        verify_consistency(7, 15, &proof, &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_1_to_4() {
        let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..1]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..1], &leaves);
        verify_consistency(1, 4, &proof, &old_root, &new_root).unwrap();
    }

    #[test]
    fn consistency_proof_rejects_wrong_old_root() {
        let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
        let wrong_old = MerkleHash::from_bytes([0xff; 32]);
        let new_root = compute_root(&leaves);
        let proof = build_consistency_proof(&leaves[..3], &leaves);
        assert!(verify_consistency(3, 4, &proof, &wrong_old, &new_root).is_err());
    }

    #[test]
    fn consistency_proof_rejects_wrong_new_root() {
        let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
        let old_root = compute_root(&leaves[..3]);
        let wrong_new = MerkleHash::from_bytes([0xff; 32]);
        let proof = build_consistency_proof(&leaves[..3], &leaves);
        assert!(verify_consistency(3, 4, &proof, &old_root, &wrong_new).is_err());
    }

    /// Build a consistency proof using RFC 6962 SUBPROOF decomposition. Test-only.
    fn build_consistency_proof(
        old_leaves: &[MerkleHash],
        new_leaves: &[MerkleHash],
    ) -> Vec<MerkleHash> {
        assert!(old_leaves.len() <= new_leaves.len());
        subproof(old_leaves.len() as u64, new_leaves, true)
    }

    /// RFC 6962 Section 2.1.2 SUBPROOF(m, D[0:n], b).
    fn subproof(m: u64, leaves: &[MerkleHash], b: bool) -> Vec<MerkleHash> {
        let n = leaves.len() as u64;
        if m == n {
            if b {
                return vec![];
            }
            return vec![compute_root(leaves)];
        }
        let k = largest_power_of_2_lt(n) as usize;
        if m <= k as u64 {
            let mut proof = subproof(m, &leaves[..k], b);
            proof.push(compute_root(&leaves[k..]));
            proof
        } else {
            let mut proof = subproof(m - k as u64, &leaves[k..], false);
            proof.push(compute_root(&leaves[..k]));
            proof
        }
    }

    #[test]
    fn largest_pow2_lt() {
        assert_eq!(largest_power_of_2_lt(2), 1);
        assert_eq!(largest_power_of_2_lt(3), 2);
        assert_eq!(largest_power_of_2_lt(4), 2);
        assert_eq!(largest_power_of_2_lt(5), 4);
        assert_eq!(largest_power_of_2_lt(8), 4);
        assert_eq!(largest_power_of_2_lt(9), 8);
    }
}
