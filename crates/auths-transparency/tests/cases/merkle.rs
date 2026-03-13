use auths_transparency::merkle::{compute_root, hash_children, hash_leaf, verify_inclusion};
use auths_transparency::types::MerkleHash;
use sha2::{Digest, Sha256};

#[test]
fn hash_leaf_rfc6962_test_vector() {
    // SHA-256(0x00 || "") — empty leaf
    let h = hash_leaf(b"");
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    let expected = hasher.finalize();
    assert_eq!(h.as_bytes(), expected.as_slice());
}

#[test]
fn hash_children_rfc6962_test_vector() {
    let left = MerkleHash::from_bytes([0x00; 32]);
    let right = MerkleHash::from_bytes([0x01; 32]);
    let h = hash_children(&left, &right);

    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update([0x00; 32]);
    hasher.update([0x01; 32]);
    let expected = hasher.finalize();
    assert_eq!(h.as_bytes(), expected.as_slice());
}

#[test]
fn merkle_tree_known_structure_four_leaves() {
    let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
    let root = compute_root(&leaves);

    let left = hash_children(&leaves[0], &leaves[1]);
    let right = hash_children(&leaves[2], &leaves[3]);
    let expected = hash_children(&left, &right);
    assert_eq!(root, expected);
}

#[test]
fn merkle_tree_three_leaves_odd() {
    let leaves: Vec<MerkleHash> = (0..3u8).map(|i| hash_leaf(&[i])).collect();
    let root = compute_root(&leaves);

    let left = hash_children(&leaves[0], &leaves[1]);
    let expected = hash_children(&left, &leaves[2]);
    assert_eq!(root, expected);
}

#[test]
fn inclusion_proof_eight_leaves() {
    let leaves: Vec<MerkleHash> = (0..8u8).map(|i| hash_leaf(&[i])).collect();
    let root = compute_root(&leaves);

    // Manually compute proof for leaf 5
    let h01 = hash_children(&leaves[0], &leaves[1]);
    let h23 = hash_children(&leaves[2], &leaves[3]);
    let h45 = hash_children(&leaves[4], &leaves[5]);
    let h67 = hash_children(&leaves[6], &leaves[7]);
    let h0123 = hash_children(&h01, &h23);
    let _h4567 = hash_children(&h45, &h67);

    // Leaf 5 → sibling leaf[4], uncle h67, great-uncle h0123
    verify_inclusion(&leaves[5], 5, 8, &[leaves[4], h67, h0123], &root).unwrap();
}

#[test]
fn inclusion_proof_rejects_tampered_proof() {
    let leaves: Vec<MerkleHash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
    let root = compute_root(&leaves);

    let cd = hash_children(&leaves[2], &leaves[3]);
    let tampered = MerkleHash::from_bytes([0xff; 32]);
    let result = verify_inclusion(&leaves[0], 0, 4, &[tampered, cd], &root);
    assert!(result.is_err());
}

#[test]
fn inclusion_proof_rejects_wrong_proof_length() {
    let a = hash_leaf(b"a");
    let b = hash_leaf(b"b");
    let root = hash_children(&a, &b);

    let result = verify_inclusion(&a, 0, 2, &[], &root);
    assert!(result.is_err());
}

mod proptest_merkle {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn compute_root_is_deterministic(data in proptest::collection::vec(any::<u8>(), 1..32)) {
            let leaves: Vec<MerkleHash> = data.iter().map(|b| hash_leaf(&[*b])).collect();
            let r1 = compute_root(&leaves);
            let r2 = compute_root(&leaves);
            prop_assert_eq!(r1, r2);
        }

        #[test]
        fn hash_leaf_is_different_from_hash_children(left_byte in any::<u8>(), right_byte in any::<u8>()) {
            let combined = [left_byte, right_byte];
            let leaf = hash_leaf(&combined);

            let left = hash_leaf(&[left_byte]);
            let right = hash_leaf(&[right_byte]);
            let node = hash_children(&left, &right);

            prop_assert_ne!(leaf, node);
        }
    }
}
