//! Identifier and hash newtypes for the transparency-log wire contract.
//!
//! The types live in `auths_verifier::tlog` so every verifier surface
//! (native, FFI, browser WASM) shares one implementation; this module
//! re-exports them for the log-construction side.

pub use auths_verifier::tlog::{LogOrigin, MerkleHash};
