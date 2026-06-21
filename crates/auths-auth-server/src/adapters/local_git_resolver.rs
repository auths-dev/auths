//! Identity resolver that reads directly from a local git registry.
//!
//! No HTTP calls — reads KERI key state from `refs/auths/registry`
//! via [`RegistryBackend`].

use std::path::PathBuf;
use std::sync::Arc;

use crate::ports::{IdentityResolver, ResolveError};
use async_trait::async_trait;
use auths_id::ports::registry::{RegistryBackend, RegistryError};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};

/// Resolves identity public keys from a local git registry backend.
///
/// `get_key_state` is synchronous (git2 I/O) — offloaded to a blocking
/// thread via `tokio::task::spawn_blocking` to avoid stalling the runtime.
#[derive(Clone)]
pub struct LocalGitResolver {
    backend: Arc<dyn RegistryBackend + Send + Sync>,
}

impl LocalGitResolver {
    /// Create a resolver from an already-constructed backend.
    ///
    /// The composition root constructs `Arc<GitRegistryBackend>` and passes it
    /// here; the resolver is agnostic to the concrete implementation.
    pub fn new(backend: Arc<dyn RegistryBackend + Send + Sync>) -> Self {
        Self { backend }
    }

    /// Open resolver backed by the git repo at `repo_path`.
    ///
    /// Fails if the path is not a git repo or `refs/auths/registry` is absent.
    /// Call [`GitRegistryBackend::init_if_needed`] first if setting up a fresh
    /// test repo.
    pub fn open(repo_path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let backend = GitRegistryBackend::open_existing(RegistryConfig::single_tenant(repo_path))?;
        Ok(Self::new(Arc::new(backend)))
    }
}

#[async_trait]
impl IdentityResolver for LocalGitResolver {
    async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
        let prefix = did
            .strip_prefix("did:keri:")
            .ok_or_else(|| ResolveError::InvalidKel(format!("not a did:keri DID: {did}")))?
            .to_string();

        // Arc clone is O(1).
        let backend = Arc::clone(&self.backend);

        // git2 is synchronous — must not block the Tokio runtime thread.
        let prefix = auths_verifier::Prefix::new_unchecked(prefix);
        let key_state = tokio::task::spawn_blocking(move || backend.get_key_state(&prefix))
            .await
            .map_err(|e| ResolveError::RegistryUnavailable(format!("blocking task panicked: {e}")))?
            .map_err(|e| match e {
                RegistryError::NotFound { .. } => {
                    ResolveError::NotFound(format!("identity not found: {e}"))
                }
                RegistryError::Serialization(_) | RegistryError::InvalidEvent { .. } => {
                    ResolveError::InvalidKel(format!("KEL data invalid: {e}"))
                }
                other => ResolveError::RegistryUnavailable(format!("storage error: {other}")),
            })?;

        let first_key = key_state
            .current_keys
            .first()
            .ok_or_else(|| ResolveError::InvalidKel("no current keys in key state".to_string()))?;

        // `current_keys` holds CESR-qualified keys; parse to the typed key and take raw bytes.
        let key = first_key
            .parse()
            .map_err(|e| ResolveError::InvalidKel(format!("KERI key decode failed: {e}")))?;

        Ok(key.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_storage::git::RegistryIdentityStorage;
    use tempfile::TempDir;

    /// Bootstrap a temp git repo with one KERI identity.
    ///
    /// Returns `(TempDir, did_string, raw_32_byte_pubkey)`.
    /// `TempDir` must stay alive for the test duration.
    fn make_repo_with_identity() -> (TempDir, String, Vec<u8>) {
        let dir = TempDir::new().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        let storage = RegistryIdentityStorage::new(dir.path());
        let (did, result) = storage.initialize_identity(None, None).unwrap();
        let pub_key = result.current_public_key;
        (dir, did, pub_key)
    }

    #[tokio::test]
    async fn resolves_known_did() {
        let (dir, did, expected_key) = make_repo_with_identity();
        let resolver = LocalGitResolver::open(dir.path()).expect("open");
        let key = resolver.resolve_current_key(&did).await.expect("resolve");
        assert_eq!(key, expected_key);
    }

    #[tokio::test]
    async fn returns_not_found_for_unknown_did() {
        let dir = TempDir::new().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()))
            .init_if_needed()
            .unwrap();
        let resolver = LocalGitResolver::open(dir.path()).expect("open");
        let err = resolver
            .resolve_current_key("did:keri:EUnknown12345")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::NotFound(_)));
    }

    #[tokio::test]
    async fn rejects_non_keri_did() {
        let dir = TempDir::new().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()))
            .init_if_needed()
            .unwrap();
        let resolver = LocalGitResolver::open(dir.path()).expect("open");
        let err = resolver
            .resolve_current_key("did:web:example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::InvalidKel(_)));
    }
}
