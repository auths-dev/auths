/// Agent-based signing port for delegating operations to a running agent process.
pub mod agent;
/// Allowed signers file I/O port for reading and writing SSH allowed_signers files.
pub mod allowed_signers;
/// Artifact source port for computing digests and metadata.
pub mod artifact;
/// Diagnostic provider ports for system health checks.
pub mod diagnostics;
/// Git log provider port for audit and compliance workflows.
pub mod git;
/// Git configuration port for setting signing-related git config keys.
pub mod git_config;
/// Pairing relay client port for communicating with a pairing relay server.
pub mod pairing;
/// Platform claim port traits for OAuth device flow, proof publishing, and registry submission.
pub mod platform;
