//! Re-exports of Git storage backend types from `auths-storage`.
//!
//! Gated behind the `backend-git` feature.

#[cfg(feature = "backend-git")]
pub use auths_id::keri::sync::{MergeOutcome, MergedCredentials, MergedKel};
#[cfg(feature = "backend-git")]
pub use auths_id::storage::GitWitnessReceiptLookup;
#[cfg(feature = "backend-git")]
pub use auths_storage::git::{
    GitAttestationStorage, GitIdentityStorage, GitRegistryBackend, PushOutcome,
    RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage, RegistryPullReport,
    RegistrySyncError, pull_registry, push_registry,
};
