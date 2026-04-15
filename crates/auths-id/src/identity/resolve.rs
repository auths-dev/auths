//! DID resolution for did:key and did:keri.

use auths_keri::KeriPublicKey;
use git2::Repository;
use std::path::Path;

use std::sync::Arc;

use crate::keri::types::Prefix;
use crate::keri::{DidKeriResolution, resolve_did_keri};
use crate::storage::registry::RegistryBackend;

pub use auths_core::signing::{DidResolver, DidResolverError, ResolvedDid};

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
        // Decode did:key for any supported curve
        let decoded = auths_crypto::did_key_decode(did)
            .map_err(|e| DidResolverError::DidKeyDecodingFailed(e.to_string()))?;
        let public_key_bytes = match decoded {
            auths_crypto::DecodedDidKey::Ed25519(pk) => pk.to_vec(),
            auths_crypto::DecodedDidKey::P256(pk) => pk,
        };
        Ok(ResolvedDid::Key {
            did: did.to_string(),
            public_key_bytes,
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

        Ok(ResolvedDid::Keri {
            did: did.to_string(),
            public_key_bytes: resolution.public_key,
            sequence: resolution.sequence,
            can_rotate: resolution.can_rotate,
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
            let Some(prefix) = did.strip_prefix("did:keri:") else {
                unreachable!("starts_with guard ensures strip_prefix succeeds");
            };
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
            let parsed = KeriPublicKey::parse(key_encoded.as_str())
                .map_err(|e| DidResolverError::DidKeyDecodingFailed(e.to_string()))?;
            Ok(ResolvedDid::Keri {
                did: did.to_string(),
                public_key_bytes: parsed.into_bytes(),
                sequence: key_state.sequence,
                can_rotate: key_state.can_rotate(),
            })
        } else if did.starts_with("did:key:") {
            let decoded = auths_crypto::did_key_decode(did)
                .map_err(|e| DidResolverError::DidKeyDecodingFailed(e.to_string()))?;
            let public_key_bytes = match decoded {
                auths_crypto::DecodedDidKey::Ed25519(pk) => pk.to_vec(),
                auths_crypto::DecodedDidKey::P256(pk) => pk,
            };
            Ok(ResolvedDid::Key {
                did: did.to_string(),
                public_key_bytes,
            })
        } else {
            let method = did.split(':').nth(1).unwrap_or("unknown");
            Err(DidResolverError::UnsupportedMethod(method.to_string()))
        }
    }
}

// `did_key_to_ed25519` and `ed25519_to_did_key` wrappers were deleted.
// Callers should use `auths_crypto::did_key_decode` (returns curve-tagged
// `DecodedDidKey`) and `auths_crypto::{ed25519_pubkey_to_did_key, p256_pubkey_to_did_key}`
// directly — there is no need for a re-export layer that hardcodes Ed25519.

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::create_keri_identity_with_curve;
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
        let did = auths_crypto::ed25519_pubkey_to_did_key(&key_bytes);
        let decoded = auths_crypto::did_key_to_ed25519(&did).unwrap();
        assert_eq!(decoded, key_bytes);
    }

    #[test]
    fn resolves_did_key_without_repo() {
        let resolver = DefaultDidResolver::new();

        let key = [1u8; 32];
        let did = auths_crypto::ed25519_pubkey_to_did_key(&key);

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.public_key_bytes(), &key);
        assert!(resolved.is_key());
    }

    #[test]
    fn resolves_did_keri_with_repo() {
        let (dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        let did = format!("did:keri:{}", init.prefix);

        let resolver = DefaultDidResolver::with_repo(dir.path());
        let resolved = resolver.resolve(&did).unwrap();

        assert_eq!(
            resolved.public_key_bytes(),
            init.current_public_key.as_slice()
        );
        assert!(matches!(
            resolved,
            ResolvedDid::Keri {
                sequence: 0,
                can_rotate: true,
                ..
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
        let result = auths_crypto::did_key_decode("did:key:invalid");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_did_key_prefix() {
        let result = auths_crypto::did_key_decode("did:web:example.com");
        assert!(result.is_err());
    }
}
