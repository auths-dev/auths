//! Port traits for dependency injection.

pub mod clock;
pub mod id;
pub mod network;
/// Pairing relay client port for session-based device pairing.
pub mod pairing;
/// Platform claim port traits for OAuth device flow, proof publishing, and registry submission.
pub mod platform;
pub mod ssh_agent;
pub mod storage;
