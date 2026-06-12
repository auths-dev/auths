//! Merkle inclusion and consistency proofs.
//!
//! The proof types and their verification live in `auths_verifier::tlog`
//! (one RFC 6962 implementation for every surface, including browser WASM);
//! this module re-exports them for the log-construction side.

pub use auths_verifier::tlog::{ConsistencyProof, InclusionProof};
