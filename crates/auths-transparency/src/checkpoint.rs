//! Log checkpoints (signed tree heads) and witness cosignatures.
//!
//! The types live in `auths_verifier::tlog` so offline verifiers can parse
//! and check checkpoints without linking the log; this module re-exports
//! them for the log-construction side.

pub use auths_verifier::tlog::{Checkpoint, SignedCheckpoint, WitnessCosignature};
