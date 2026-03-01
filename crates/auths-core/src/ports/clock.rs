//! Clock port for injectable time.

// ClockProvider and SystemClock live in auths-verifier (the foundation layer
// used by both auths-core and auths-verifier). Re-exported here so that all
// existing imports of `auths_core::ports::clock::*` continue to compile
// unchanged.
pub use auths_verifier::clock::{ClockProvider, SystemClock};
