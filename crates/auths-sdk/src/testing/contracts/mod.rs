/// Contract tests for [`ArtifactSource`](crate::ports::artifact::ArtifactSource) implementations.
pub mod artifact;
/// Contract tests for [`GitDiagnosticProvider`](crate::ports::diagnostics::GitDiagnosticProvider)
/// and [`CryptoDiagnosticProvider`](crate::ports::diagnostics::CryptoDiagnosticProvider) implementations.
pub mod diagnostics;
/// Contract tests for [`GitConfigProvider`](crate::ports::git_config::GitConfigProvider) implementations.
pub mod git_config;
/// Contract tests for [`GitLogProvider`](crate::ports::git::GitLogProvider) implementations.
pub mod git_log;
