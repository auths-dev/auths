//! Transparency-log verification primitives — the pure, network-free core any
//! verifier needs to check Merkle proofs against a signed checkpoint.
//!
//! These types are the wire contract between a transparency log
//! (`auths-transparency`, which builds trees, tiles, and proofs server-side)
//! and every verifier surface (native, FFI, browser WASM) that must check
//! that evidence offline. They live here — in the leaf verification crate all
//! surfaces share — so a browser can verify a log proof without linking the
//! log's storage or networking, and so there is exactly one implementation of
//! the RFC 6962 proof math. `auths-transparency` re-exports everything in
//! this module; downstream code keeps importing from either crate without a
//! second copy existing anywhere.

/// Log checkpoints (signed tree heads) and witness cosignatures.
pub mod checkpoint;
/// The transparency-log error contract.
pub mod error;
/// RFC 6962 Merkle tree hashing and proof verification.
pub mod merkle;
/// Inclusion and consistency proofs.
pub mod proof;
/// Identifier and hash newtypes.
pub mod types;

pub use checkpoint::{Checkpoint, SignedCheckpoint, WitnessCosignature};
pub use error::TransparencyError;
pub use merkle::{compute_root, hash_children, hash_leaf, verify_consistency, verify_inclusion};
pub use proof::{ConsistencyProof, InclusionProof};
pub use types::{LogOrigin, MerkleHash};
