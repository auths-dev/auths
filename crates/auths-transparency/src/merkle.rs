//! RFC 6962 Merkle tree hashing and proof verification.
//!
//! The math lives in `auths_verifier::tlog::merkle` — one implementation
//! shared by the log builder here and every offline verifier surface
//! (native, FFI, browser WASM). This module re-exports it.

pub use auths_verifier::tlog::merkle::{
    compute_root, hash_children, hash_leaf, verify_consistency, verify_inclusion,
};
