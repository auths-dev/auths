/// Agent-based signing port for delegating operations to a running agent process.
pub mod agent;
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
