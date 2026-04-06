//! Re-exports of Git storage backend types from `auths-storage`.
//!
//! Gated behind the `backend-git` feature.

#[cfg(feature = "backend-git")]
pub use auths_storage::git::{
    GitAttestationStorage, GitIdentityStorage, GitRegistryBackend, RegistryAttestationStorage,
    RegistryConfig, RegistryIdentityStorage,
};
