mod agent;
mod agent_persistence;
mod allowed_signers_store;
mod artifact;
mod diagnostics;
mod git;
mod git_config;
mod namespace;
mod signer;

pub use agent::FakeAgentProvider;
pub use agent_persistence::FakeAgentPersistence;
pub use allowed_signers_store::FakeAllowedSignersStore;
pub use artifact::FakeArtifactSource;
pub use diagnostics::{FakeCryptoDiagnosticProvider, FakeGitDiagnosticProvider};
pub use git::FakeGitLogProvider;
pub use git_config::{FakeGitConfigProvider, GitConfigSetCall};
pub use namespace::FakeNamespaceVerifier;
pub use signer::FakeSecureSigner;
