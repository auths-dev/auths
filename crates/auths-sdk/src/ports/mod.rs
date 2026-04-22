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

// Re-exports from auths-core ports
pub use auths_core::ports::clock::SystemClock;
pub use auths_core::ports::config_store::{ConfigStore, ConfigStoreError};
pub use auths_core::ports::id::{SystemUuidProvider, UuidProvider};
pub use auths_core::ports::namespace::{Ecosystem, NamespaceVerifyError, PackageName};
pub use auths_core::ports::network::RegistryClient;
pub use auths_core::ports::ssh_agent::{SshAgentError, SshAgentPort};
pub use auths_core::ports::storage::StorageError as CoreStorageError;
pub use auths_core::ports::transparency_log::{
    LogError, LogMetadata, LogSubmission, TransparencyLog,
};

// Re-exports from auths-id ports
pub use auths_id::identity::helpers::ManagedIdentity;
pub use auths_id::ports::registry::RegistryBackend;
pub use auths_id::storage::attestation::AttestationSource;
pub use auths_id::storage::git_refs::AttestationMetadata;
pub use auths_id::storage::identity::IdentityStorage;
