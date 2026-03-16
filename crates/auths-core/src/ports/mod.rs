//! Port traits for dependency injection.

pub mod clock;
/// Config file I/O port for reading and writing `config.toml`.
pub mod config_store;
pub mod id;
/// Namespace verification port traits for proof-of-ownership across package ecosystems.
pub mod namespace;
pub mod network;
/// Pairing relay client port for session-based device pairing.
pub mod pairing;
/// Platform claim port traits for OAuth device flow, proof publishing, and registry submission.
pub mod platform;
pub mod ssh_agent;
pub mod storage;
