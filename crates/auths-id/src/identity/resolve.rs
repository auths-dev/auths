//! DID resolution for did:key and did:keri.

use auths_crypto::KeriPublicKey;
use auths_verifier::core::Ed25519PublicKey;
use git2::Repository;
use std::path::Path;

use std::sync::Arc;

use crate::keri::types::Prefix;
use crate::keri::{DidKeriResolution, resolve_did_keri};
use crate::storage::registry::RegistryBackend;

pub use auths_core::signing::{DidMethod, DidResolver, DidResolverError, ResolvedDid};

/// Default resolver handling did:key and did:keri.
pub struct DefaultDidResolver {
    repo_path: Option<std::path::PathBuf>,
}

impl DefaultDidResolver {
    /// Create a resolver without repository access (did:key only).
    pub fn new() -> Self {
        Self { repo_path: None }
    }

    /// Create a resolver with repository access (did:key and did:keri).
    pub fn with_repo(path: impl AsRef<Path>) -> Self {
        Self {
            repo_path: Some(path.as_ref().to_path_buf()),
        }
    }

    fn resolve_did_key(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        let public_key = did_key_to_ed25519(did)?;
        Ok(ResolvedDid {
            did: did.to_string(),
            public_key,
            method: DidMethod::Key,
        })
    }

    fn resolve_did_keri_internal(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        let repo_path = self.repo_path.as_ref().ok_or_else(|| {
            DidResolverError::Repository("Repository path required for did:keri".into())
        })?;

        let repo =
            Repository::open(repo_path).map_err(|e| DidResolverError::Repository(e.to_string()))?;

        let resolution: DidKeriResolution = resolve_did_keri(&repo, did)
            .map_err(|e| DidResolverError::Resolution(e.to_string()))?;

        let public_key = Ed25519PublicKey::try_from_slice(&resolution.public_key)
            .map_err(|e| DidResolverError::DidKeyDecodingFailed(e.to_string()))?;
        Ok(ResolvedDid {
            did: did.to_string(),
            public_key,
            method: DidMethod::Keri {
                sequence: resolution.sequence,
                can_rotate: resolution.can_rotate,
            },
        })
    }
}

impl Default for DefaultDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DidResolver for DefaultDidResolver {
    fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        if did.starts_with("did:keri:") {
            self.resolve_did_keri_internal(did)
        } else if did.starts_with("did:key:") {
            self.resolve_did_key(did)
        } else {
            let method = did.split(':').nth(1).unwrap_or("unknown");
            Err(DidResolverError::UnsupportedMethod(method.to_string()))
        }
    }
}

/// Resolver for identities stored in the packed registry backend.
///
/// Unlike `DefaultDidResolver`, this resolver reads `did:keri:` DIDs from
/// the packed registry tree (`refs/auths/registry`) rather than standalone
/// `refs/did/keri/<prefix>/kel` refs. Use this whenever the identity was
/// initialized via `RegistryIdentityStorage` from auths-storage.
pub struct RegistryDidResolver {
    backend: Arc<dyn RegistryBackend + Send + Sync>,
}

impl RegistryDidResolver {
    /// Create a resolver backed by the provided registry backend.
    ///
    /// Args:
    /// * `backend` - The registry backend implementation.
    ///
    /// Usage:
    /// ```ignore
    /// let resolver = RegistryDidResolver::new(Arc::new(my_backend));
    /// ```
    pub fn new(backend: Arc<dyn RegistryBackend + Send + Sync>) -> Self {
        Self { backend }
    }
}

impl DidResolver for RegistryDidResolver {
    fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
        if did.starts_with("did:keri:") {
            let prefix = did.strip_prefix("did:keri:").unwrap();
            if prefix.is_empty() {
                return Err(DidResolverError::InvalidDidKeyFormat(
                    "Empty KERI prefix".into(),
                ));
            }
            let key_state = self
                .backend
                .get_key_state(&Prefix::new_unchecked(prefix.to_string()))
                .map_err(|e| DidResolverError::Repository(e.to_string()))?;
            let key_encoded = key_state.current_key().ok_or_else(|| {
                DidResolverError::Repository("No current key in key state".into())
            })?;
            let public_key = KeriPublicKey::parse(key_encoded)
                .map(|k| Ed25519PublicKey::from_bytes(*k.as_bytes()))
                .map_err(|e| DidResolverError::DidKeyDecodingFailed(e.to_string()))?;
            Ok(ResolvedDid {
                did: did.to_string(),
                public_key,
                method: DidMethod::Keri {
                    sequence: key_state.sequence,
                    can_rotate: key_state.can_rotate(),
                },
            })
        } else if did.starts_with("did:key:") {
            let public_key = did_key_to_ed25519(did)?;
            Ok(ResolvedDid {
                did: did.to_string(),
                public_key,
                method: DidMethod::Key,
            })
        } else {
            let method = did.split(':').nth(1).unwrap_or("unknown");
            Err(DidResolverError::UnsupportedMethod(method.to_string()))
        }
    }
}

/// Parse a did:key to extract the Ed25519 public key.
pub fn did_key_to_ed25519(did: &str) -> Result<Ed25519PublicKey, DidResolverError> {
    auths_crypto::did_key_to_ed25519(did)
        .map(|k| Ed25519PublicKey::from_bytes(k))
        .map_err(|e| DidResolverError::InvalidDidKey(e.to_string()))
}

/// Convert a 32-byte Ed25519 public key to `did:key` format.
pub fn ed25519_to_did_key(public_key: &[u8]) -> String {
    let array: [u8; 32] = public_key
        .try_into()
        .expect("ed25519_to_did_key requires exactly 32 bytes");
    auths_crypto::ed25519_pubkey_to_did_key(&array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::create_keri_identity;
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    #[test]
    fn did_key_roundtrip() {
        let key_bytes = [42u8; 32];
        let did = ed25519_to_did_key(&key_bytes);
        let decoded = did_key_to_ed25519(&did).unwrap();
        assert_eq!(*decoded.as_bytes(), key_bytes);
    }

    #[test]
    fn resolves_did_key_without_repo() {
        let resolver = DefaultDidResolver::new();

        let key = [1u8; 32];
        let did = ed25519_to_did_key(&key);

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(*resolved.public_key.as_bytes(), key);
        assert_eq!(resolved.method, DidMethod::Key);
    }

    #[test]
    fn resolves_did_keri_with_repo() {
        let (dir, repo) = setup_repo();

        let init = create_keri_identity(&repo, None).unwrap();
        let did = format!("did:keri:{}", init.prefix);

        let resolver = DefaultDidResolver::with_repo(dir.path());
        let resolved = resolver.resolve(&did).unwrap();

        assert_eq!(resolved.public_key.as_bytes().as_slice(), init.current_public_key.as_slice());
        assert!(matches!(
            resolved.method,
            DidMethod::Keri {
                sequence: 0,
                can_rotate: true
            }
        ));
    }

    #[test]
    fn did_keri_fails_without_repo() {
        let resolver = DefaultDidResolver::new();
        let result = resolver.resolve("did:keri:ETest123");
        assert!(matches!(result, Err(DidResolverError::Repository(_))));
    }

    #[test]
    fn rejects_unsupported_method() {
        let resolver = DefaultDidResolver::new();
        let result = resolver.resolve("did:web:example.com");
        assert!(matches!(
            result,
            Err(DidResolverError::UnsupportedMethod(_))
        ));
    }

    #[test]
    fn rejects_invalid_did_key() {
        let result = did_key_to_ed25519("did:key:invalid");
        assert!(matches!(result, Err(DidResolverError::InvalidDidKey(_))));
    }

    #[test]
    fn rejects_non_did_key_prefix() {
        let result = did_key_to_ed25519("did:web:example.com");
        assert!(matches!(result, Err(DidResolverError::InvalidDidKey(_))));
    }
}
