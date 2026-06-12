//! The transparency-log error contract.
//!
//! The type itself lives in `auths_verifier::tlog` — the leaf verification
//! crate every surface shares — so offline proof verification (native, FFI,
//! browser WASM) and log construction/storage report through one error type.

pub use auths_verifier::tlog::TransparencyError;

/// Convenience alias for transparency operations.
pub type Result<T> = std::result::Result<T, TransparencyError>;
