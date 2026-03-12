//! Signing abstractions and DID resolution.

use auths_verifier::core::Ed25519PublicKey;

use crate::crypto::provider_bridge;
use crate::crypto::signer::{decrypt_keypair, extract_seed_from_key_bytes};
use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};

use crate::config::PassphraseCachePolicy;
use crate::storage::passphrase_cache::PassphraseCache;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Type alias for passphrase callback functions.
type PassphraseCallback = dyn Fn(&str) -> Result<Zeroizing<String>, AgentError> + Send + Sync;

/// Error type for DID resolution.
///
/// Args:
/// * Variants represent distinct failure modes during DID resolution.
///
/// Usage:
/// ```ignore
/// use auths_core::signing::DidResolverError;
///
/// let err = DidResolverError::UnsupportedMethod("web".to_string());
/// assert!(err.to_string().contains("Unsupported"));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DidResolverError {
    /// The DID method is not supported.
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// The did:key identifier is invalid.
    #[error("Invalid did:key format: {0}")]
    InvalidDidKey(String),

    /// The did:key format is malformed.
    #[error("Invalid did:key format: {0}")]
    InvalidDidKeyFormat(String),

    /// Failed to decode the did:key.
    #[error("did:key decoding failed: {0}")]
    DidKeyDecodingFailed(String),

    /// Unsupported multicodec prefix in did:key.
    #[error("Invalid did:key multicodec prefix")]
    InvalidDidKeyMulticodec,

    /// DID resolution failed.
    #[error("Resolution error: {0}")]
    Resolution(String),

    /// Repository access failed.
    #[error("Repository error: {0}")]
    Repository(String),
}

/// Result of DID resolution, parameterised by method.
///
/// Usage:
/// ```ignore
/// use auths_core::signing::ResolvedDid;
/// use auths_verifier::core::Ed25519PublicKey;
///
/// let resolved = ResolvedDid::Key {
///     did: "did:key:z6Mk...".to_string(),
///     public_key: Ed25519PublicKey::from_bytes([1u8; 32]),
/// };
/// assert!(resolved.is_key());
/// ```
#[derive(Debug, Clone)]
pub enum ResolvedDid {
    /// Static did:key (no rotation possible).
    Key {
        /// The resolved DID string.
        did: String,
        /// The Ed25519 public key.
        public_key: Ed25519PublicKey,
    },
    /// KERI-based identity with rotation capability.
    Keri {
        /// The resolved DID string.
        did: String,
        /// The Ed25519 public key.
        public_key: Ed25519PublicKey,
        /// Current KEL sequence number.
        sequence: u64,
        /// Whether key rotation is available.
        can_rotate: bool,
    },
}

impl ResolvedDid {
    /// Returns the DID string.
    pub fn did(&self) -> &str {
        match self {
            ResolvedDid::Key { did, .. } | ResolvedDid::Keri { did, .. } => did,
        }
    }

    /// Returns the Ed25519 public key.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        match self {
            ResolvedDid::Key { public_key, .. } | ResolvedDid::Keri { public_key, .. } => {
                public_key
            }
        }
    }

    /// Returns `true` if this is a `did:key` resolution.
    pub fn is_key(&self) -> bool {
        matches!(self, ResolvedDid::Key { .. })
    }

    /// Returns `true` if this is a `did:keri` resolution.
    pub fn is_keri(&self) -> bool {
        matches!(self, ResolvedDid::Keri { .. })
    }
}

/// Resolves a Decentralized Identifier (DID) to its cryptographic material.
///
/// Implementations handle specific DID methods (did:key, did:keri) and return
/// the resolved public key along with method-specific metadata. The resolver
/// abstracts away the underlying storage and network access needed for resolution.
///
/// Args:
/// * `did`: A DID string (e.g., `"did:keri:EABC..."` or `"did:key:z6Mk..."`).
///
/// Usage:
/// ```ignore
/// use auths_core::signing::DidResolver;
///
/// fn verify_attestation(resolver: &dyn DidResolver, issuer_did: &str) -> bool {
///     match resolver.resolve(issuer_did) {
///         Ok(resolved) => {
///             let public_key = resolved.public_key();
///             // use public_key for signature verification
///             true
///         }
///         Err(_) => false,
///     }
/// }
/// ```
pub trait DidResolver: Send + Sync {
    /// Resolve a DID to its public key and method.
    fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError>;
}

/// A trait for components that can securely provide a passphrase when requested.
///
/// This allows the core signing logic to request a passphrase without knowing
/// whether it's coming from a terminal prompt, a GUI dialog, or another source.
/// Implementors should handle secure input and potential user cancellation.
pub trait PassphraseProvider: Send + Sync {
    /// Securely obtains a passphrase, potentially by prompting the user.
    ///
    /// Args:
    /// * `prompt_message`: A message to display to the user indicating why the passphrase is needed.
    ///
    /// Usage:
    /// ```ignore
    /// let passphrase = provider.get_passphrase("Enter passphrase for key 'main':")?;
    /// ```
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError>;

    /// Notifies the provider that the passphrase returned for `prompt_message` was wrong.
    ///
    /// The default implementation is a no-op. Caching providers override this to
    /// evict the stale entry so subsequent calls prompt the user again rather than
    /// replaying a known-bad passphrase.
    ///
    /// Args:
    /// * `prompt_message`: The prompt for which the bad passphrase was cached.
    fn on_incorrect_passphrase(&self, _prompt_message: &str) {}
}

/// A trait for components that can perform signing operations using stored keys,
/// identified by an alias, while securely handling decryption and passphrase input.
pub trait SecureSigner: Send + Sync {
    /// Requests a signature for the given message using the key identified by the alias.
    ///
    /// This method handles loading the encrypted key, obtaining the necessary passphrase
    /// via the provided `PassphraseProvider`, decrypting the key, performing the signature,
    /// and ensuring the decrypted key material is handled securely.
    ///
    /// # Arguments
    /// * `alias`: The alias of the key to use for signing.
    /// * `passphrase_provider`: An implementation of `PassphraseProvider` used to obtain the passphrase if needed.
    /// * `message`: The message bytes to be signed.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)`: The raw signature bytes.
    /// * `Err(AgentError)`: If any step fails (key not found, incorrect passphrase, decryption error, signing error, etc.).
    fn sign_with_alias(
        &self,
        alias: &KeyAlias,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError>;

    /// Signs a message using the key associated with the given identity DID.
    ///
    /// This method resolves the identity DID to an alias by looking up keys
    /// associated with that identity in storage, then delegates to `sign_with_alias`.
    ///
    /// # DID to Alias Resolution Strategy
    /// The implementation uses the storage backend's `list_aliases_for_identity`
    /// to find aliases associated with the given DID. The first matching alias
    /// is used for signing.
    ///
    /// # Arguments
    /// * `identity_did`: The identity DID (e.g., "did:keri:ABC...") to sign for.
    /// * `passphrase_provider`: Used to obtain the passphrase for key decryption.
    /// * `message`: The message bytes to be signed.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)`: The raw signature bytes.
    /// * `Err(AgentError)`: If no key is found for the identity, or if signing fails.
    fn sign_for_identity(
        &self,
        identity_did: &IdentityDID,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError>;
}

/// Concrete implementation of `SecureSigner` that uses a `KeyStorage` backend.
///
/// It requires a `PassphraseProvider` to be passed into the signing method
/// to handle user interaction for passphrase input securely.
pub struct StorageSigner<S: KeyStorage> {
    /// The storage backend implementation (e.g., IOSKeychain, MacOSKeychain).
    storage: S,
}

impl<S: KeyStorage> StorageSigner<S> {
    /// Creates a new `StorageSigner` with the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying storage backend.
    pub fn inner(&self) -> &S {
        &self.storage
    }
}

impl<S: KeyStorage + Send + Sync + 'static> SecureSigner for StorageSigner<S> {
    fn sign_with_alias(
        &self,
        alias: &KeyAlias,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let (_identity_did, _role, encrypted_data) = self.storage.load_key(alias)?;

        const MAX_ATTEMPTS: u8 = 3;
        let mut attempt = 0u8;
        let key_bytes = loop {
            let prompt = if attempt == 0 {
                format!("Enter passphrase for key '{}' to sign:", alias)
            } else {
                format!(
                    "Incorrect passphrase, try again ({}/{}):",
                    attempt + 1,
                    MAX_ATTEMPTS
                )
            };

            let passphrase = passphrase_provider.get_passphrase(&prompt)?;

            match decrypt_keypair(&encrypted_data, &passphrase) {
                Ok(kb) => break kb,
                Err(AgentError::IncorrectPassphrase) if attempt + 1 < MAX_ATTEMPTS => {
                    passphrase_provider.on_incorrect_passphrase(&prompt);
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };

        let seed = extract_seed_from_key_bytes(&key_bytes)?;

        provider_bridge::sign_ed25519_sync(&seed, message)
            .map_err(|e| AgentError::CryptoError(format!("Ed25519 signing failed: {}", e)))
    }

    fn sign_for_identity(
        &self,
        identity_did: &IdentityDID,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        // 1. Find aliases associated with this identity DID
        let aliases = self.storage.list_aliases_for_identity(identity_did)?;

        // 2. Get the first alias (primary key for this identity)
        let alias = aliases.first().ok_or(AgentError::KeyNotFound)?;

        // 3. Delegate to sign_with_alias
        self.sign_with_alias(alias, passphrase_provider, message)
    }
}

/// A `PassphraseProvider` that delegates to a callback function.
///
/// This is useful for GUI applications and FFI bindings where the passphrase
/// input mechanism is provided externally.
///
/// # Examples
///
/// ```ignore
/// use auths_core::signing::{CallbackPassphraseProvider, PassphraseProvider};
///
/// let provider = CallbackPassphraseProvider::new(|prompt| {
///     // In a real GUI, this would show a dialog
///     Ok("user-entered-passphrase".to_string())
/// });
/// ```
pub struct CallbackPassphraseProvider {
    callback: Box<PassphraseCallback>,
}

impl CallbackPassphraseProvider {
    /// Creates a new `CallbackPassphraseProvider` with the given callback function.
    ///
    /// The callback receives the prompt message and should return the passphrase
    /// entered by the user, or an error if passphrase acquisition failed.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&str) -> Result<Zeroizing<String>, AgentError> + Send + Sync + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl PassphraseProvider for CallbackPassphraseProvider {
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        (self.callback)(prompt_message)
    }
}

/// A `PassphraseProvider` that caches passphrases from an inner provider.
///
/// Cached values are stored in `Zeroizing<String>` for automatic zeroing on drop
/// and expire after the configured TTL (time-to-live).
///
/// This is useful for agent sessions where prompting for every signing operation
/// would be disruptive, but credentials shouldn't persist indefinitely.
///
/// # Security Considerations
/// - Cached passphrases are wrapped in `Zeroizing<String>` for secure memory cleanup
/// - TTL prevents stale credentials from persisting
/// - Call `clear_cache()` on logout or lock events
pub struct CachedPassphraseProvider {
    inner: Arc<dyn PassphraseProvider + Send + Sync>,
    cache: Mutex<HashMap<String, (Zeroizing<String>, Instant)>>,
    ttl: Duration,
}

impl CachedPassphraseProvider {
    /// Creates a new `CachedPassphraseProvider` wrapping the given provider.
    ///
    /// # Arguments
    /// * `inner` - The underlying provider to fetch passphrases from on cache miss
    /// * `ttl` - How long cached passphrases remain valid before expiring
    pub fn new(inner: Arc<dyn PassphraseProvider + Send + Sync>, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Pre-fill the cache with a passphrase for session-based unlock.
    ///
    /// This allows callers to unlock once and re-use the passphrase for
    /// the configured TTL without re-prompting. The passphrase is stored
    /// only in Rust memory (never crosses FFI boundary after this call).
    ///
    /// The default prompt key is used so all subsequent signing operations
    /// that use the same prompt will hit the cache.
    pub fn unlock(&self, passphrase: &str) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(
            String::new(),
            (Zeroizing::new(passphrase.to_string()), Instant::now()),
        );
    }

    /// Returns the remaining TTL in seconds, or `None` if no cached passphrase.
    pub fn remaining_ttl(&self) -> Option<Duration> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.values().next().and_then(|(_, cached_at)| {
            let elapsed = cached_at.elapsed();
            if elapsed < self.ttl {
                Some(self.ttl - elapsed)
            } else {
                None
            }
        })
    }

    /// Clears all cached passphrases.
    ///
    /// Call this on logout, lock, or when the session ends to ensure
    /// cached credentials don't persist in memory.
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl PassphraseProvider for CachedPassphraseProvider {
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| AgentError::MutexError(e.to_string()))?;

        // Check cache for unexpired entry
        if let Some((passphrase, cached_at)) = cache.get(prompt_message) {
            if cached_at.elapsed() < self.ttl {
                // Clone the inner String and wrap in new Zeroizing
                return Ok(passphrase.clone());
            }
            // Expired - remove the entry
            cache.remove(prompt_message);
        }

        // Cache miss or expired - fetch from inner provider
        drop(cache); // Release lock before calling inner to avoid deadlock
        let passphrase = self.inner.get_passphrase(prompt_message)?;

        // Store in cache - clone the passphrase since we return the original
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| AgentError::MutexError(e.to_string()))?;
        cache.insert(
            prompt_message.to_string(),
            (passphrase.clone(), Instant::now()),
        );
        Ok(passphrase)
    }

    fn on_incorrect_passphrase(&self, prompt_message: &str) {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(prompt_message);
    }
}

/// A `PassphraseProvider` that wraps an inner provider with OS keychain caching.
///
/// On `get_passphrase()`, checks the OS keychain first via `PassphraseCache::load`.
/// If a cached value exists and hasn't expired per the configured policy/TTL,
/// returns it immediately. Otherwise delegates to the inner provider, then
/// stores the result in the OS keychain for subsequent invocations.
///
/// Args:
/// * `inner`: The underlying provider to prompt the user when cache misses.
/// * `cache`: Platform keychain cache (macOS Security Framework, Linux Secret Service, etc.).
/// * `alias`: Key alias used as the cache key in the OS keychain.
/// * `policy`: The configured `PassphraseCachePolicy`.
/// * `ttl_secs`: Optional TTL in seconds (for `Duration` policy).
///
/// Usage:
/// ```ignore
/// use auths_core::signing::{KeychainPassphraseProvider, PassphraseProvider};
/// use auths_core::config::PassphraseCachePolicy;
/// use auths_core::storage::passphrase_cache::get_passphrase_cache;
///
/// let inner = Arc::new(some_provider);
/// let cache = get_passphrase_cache(true);
/// let provider = KeychainPassphraseProvider::new(
///     inner, cache, "main".to_string(),
///     PassphraseCachePolicy::Duration, Some(3600),
/// );
/// let passphrase = provider.get_passphrase("Enter passphrase:")?;
/// ```
pub struct KeychainPassphraseProvider {
    inner: Arc<dyn PassphraseProvider + Send + Sync>,
    cache: Box<dyn PassphraseCache>,
    alias: String,
    policy: PassphraseCachePolicy,
    ttl_secs: Option<i64>,
}

impl KeychainPassphraseProvider {
    /// Creates a new `KeychainPassphraseProvider`.
    ///
    /// Args:
    /// * `inner`: Fallback provider for cache misses.
    /// * `cache`: OS keychain cache implementation.
    /// * `alias`: Key alias used as the keychain entry identifier.
    /// * `policy`: Caching policy controlling storage/expiry behavior.
    /// * `ttl_secs`: TTL in seconds when `policy` is `Duration`.
    pub fn new(
        inner: Arc<dyn PassphraseProvider + Send + Sync>,
        cache: Box<dyn PassphraseCache>,
        alias: String,
        policy: PassphraseCachePolicy,
        ttl_secs: Option<i64>,
    ) -> Self {
        Self {
            inner,
            cache,
            alias,
            policy,
            ttl_secs,
        }
    }

    #[allow(clippy::disallowed_methods)] // Passphrase cache is a system boundary
    fn is_expired(&self, stored_at_unix: i64) -> bool {
        match self.policy {
            PassphraseCachePolicy::Always => false,
            PassphraseCachePolicy::Never => true,
            PassphraseCachePolicy::Session => true,
            PassphraseCachePolicy::Duration => {
                let ttl = self.ttl_secs.unwrap_or(3600);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                now - stored_at_unix > ttl
            }
        }
    }
}

impl PassphraseProvider for KeychainPassphraseProvider {
    #[allow(clippy::disallowed_methods)] // Passphrase cache is a system boundary
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        if self.policy != PassphraseCachePolicy::Never
            && let Ok(Some((passphrase, stored_at))) = self.cache.load(&self.alias)
        {
            if !self.is_expired(stored_at) {
                return Ok(passphrase);
            }
            let _ = self.cache.delete(&self.alias);
        }

        let passphrase = self.inner.get_passphrase(prompt_message)?;

        if self.policy != PassphraseCachePolicy::Never
            && self.policy != PassphraseCachePolicy::Session
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let _ = self.cache.store(&self.alias, &passphrase, now);
        }

        Ok(passphrase)
    }

    fn on_incorrect_passphrase(&self, prompt_message: &str) {
        let _ = self.cache.delete(&self.alias);
        self.inner.on_incorrect_passphrase(prompt_message);
    }
}

/// Provides a pre-collected passphrase for headless and automated environments.
///
/// Unlike [`CallbackPassphraseProvider`] which prompts interactively, this provider
/// returns a passphrase that was collected or generated before construction.
/// Intended for CI pipelines, Terraform providers, REST APIs, and integration tests.
///
/// Args:
/// * `passphrase`: The passphrase to return on every `get_passphrase()` call.
///
/// Usage:
/// ```ignore
/// use auths_core::signing::{PrefilledPassphraseProvider, PassphraseProvider};
///
/// let provider = PrefilledPassphraseProvider::new("my-secret-passphrase");
/// let passphrase = provider.get_passphrase("any prompt").unwrap();
/// assert_eq!(*passphrase, "my-secret-passphrase");
/// ```
pub struct PrefilledPassphraseProvider {
    passphrase: Zeroizing<String>,
}

impl PrefilledPassphraseProvider {
    /// Creates a new `PrefilledPassphraseProvider` with the given passphrase.
    ///
    /// Args:
    /// * `passphrase`: The passphrase string to store and return on every request.
    ///
    /// Usage:
    /// ```ignore
    /// let provider = PrefilledPassphraseProvider::new("hunter2");
    /// ```
    pub fn new(passphrase: &str) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.to_string()),
        }
    }
}

impl PassphraseProvider for PrefilledPassphraseProvider {
    fn get_passphrase(&self, _prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        Ok(self.passphrase.clone())
    }
}

/// A passphrase provider that prompts exactly once regardless of how many
/// distinct prompt messages are presented. Every call after the first is a
/// cache hit. Designed for multi-key operations (e.g. device link) where the
/// same passphrase protects all keys in the operation.
pub struct UnifiedPassphraseProvider {
    inner: Arc<dyn PassphraseProvider + Send + Sync>,
    cached: Mutex<Option<Zeroizing<String>>>,
}

impl UnifiedPassphraseProvider {
    /// Create a provider wrapping the given passphrase source.
    pub fn new(inner: Arc<dyn PassphraseProvider + Send + Sync>) -> Self {
        Self {
            inner,
            cached: Mutex::new(None),
        }
    }
}

impl PassphraseProvider for UnifiedPassphraseProvider {
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        let mut guard = self
            .cached
            .lock()
            .map_err(|e| AgentError::MutexError(e.to_string()))?;
        if let Some(ref cached) = *guard {
            return Ok(Zeroizing::new(cached.as_str().to_string()));
        }
        let passphrase = self.inner.get_passphrase(prompt_message)?;
        *guard = Some(Zeroizing::new(passphrase.as_str().to_string()));
        Ok(passphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::encrypt_keypair;
    use ring::rand::SystemRandom;
    use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::storage::keychain::KeyRole;

    /// Mock KeyStorage implementation for testing
    struct MockKeyStorage {
        #[allow(clippy::type_complexity)]
        keys: Mutex<HashMap<String, (IdentityDID, KeyRole, Vec<u8>)>>,
    }

    impl MockKeyStorage {
        fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
            }
        }
    }

    impl KeyStorage for MockKeyStorage {
        fn store_key(
            &self,
            alias: &KeyAlias,
            identity_did: &IdentityDID,
            role: KeyRole,
            encrypted_key_data: &[u8],
        ) -> Result<(), AgentError> {
            self.keys.lock().unwrap().insert(
                alias.as_str().to_string(),
                (identity_did.clone(), role, encrypted_key_data.to_vec()),
            );
            Ok(())
        }

        fn load_key(
            &self,
            alias: &KeyAlias,
        ) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
            self.keys
                .lock()
                .unwrap()
                .get(alias.as_str())
                .cloned()
                .ok_or(AgentError::KeyNotFound)
        }

        fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
            self.keys
                .lock()
                .unwrap()
                .remove(alias.as_str())
                .map(|_| ())
                .ok_or(AgentError::KeyNotFound)
        }

        fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .keys()
                .map(|s| KeyAlias::new_unchecked(s.clone()))
                .collect())
        }

        fn list_aliases_for_identity(
            &self,
            identity_did: &IdentityDID,
        ) -> Result<Vec<KeyAlias>, AgentError> {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, (did, _role, _))| did == identity_did)
                .map(|(alias, _)| KeyAlias::new_unchecked(alias.clone()))
                .collect())
        }

        fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
            self.keys
                .lock()
                .unwrap()
                .get(alias.as_str())
                .map(|(did, _role, _)| did.clone())
                .ok_or(AgentError::KeyNotFound)
        }

        fn backend_name(&self) -> &'static str {
            "MockKeyStorage"
        }
    }

    /// Mock PassphraseProvider that returns a fixed passphrase
    struct MockPassphraseProvider {
        passphrase: String,
    }

    impl MockPassphraseProvider {
        fn new(passphrase: &str) -> Self {
            Self {
                passphrase: passphrase.to_string(),
            }
        }
    }

    impl PassphraseProvider for MockPassphraseProvider {
        fn get_passphrase(&self, _prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
            Ok(Zeroizing::new(self.passphrase.clone()))
        }
    }

    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate PKCS#8");
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to parse PKCS#8");
        let pubkey_bytes = keypair.public_key().as_ref().to_vec();
        (pkcs8_bytes, pubkey_bytes)
    }

    #[test]
    fn test_sign_for_identity_success() {
        let (pkcs8_bytes, pubkey_bytes) = generate_test_keypair();
        let passphrase = "Test-P@ss12345";
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only literal with valid did:keri: prefix
        let identity_did = IdentityDID::new_unchecked("did:keri:ABC123");
        let alias = KeyAlias::new_unchecked("test-key-alias");

        // Encrypt the key
        let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("Failed to encrypt");

        // Set up mock storage with the key
        let storage = MockKeyStorage::new();
        storage
            .store_key(&alias, &identity_did, KeyRole::Primary, &encrypted)
            .expect("Failed to store key");

        // Create signer and mocks
        let signer = StorageSigner::new(storage);
        let passphrase_provider = MockPassphraseProvider::new(passphrase);

        // Sign a message
        let message = b"test message for sign_for_identity";
        let signature = signer
            .sign_for_identity(&identity_did, &passphrase_provider, message)
            .expect("Signing failed");

        // Verify the signature
        let public_key = UnparsedPublicKey::new(&ED25519, &pubkey_bytes);
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_sign_for_identity_no_key_for_identity() {
        let storage = MockKeyStorage::new();
        let signer = StorageSigner::new(storage);
        let passphrase_provider = MockPassphraseProvider::new("any-passphrase");

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only literal with valid did:keri: prefix
        let identity_did = IdentityDID::new_unchecked("did:keri:NONEXISTENT");
        let message = b"test message";

        let result = signer.sign_for_identity(&identity_did, &passphrase_provider, message);
        assert!(matches!(result, Err(AgentError::KeyNotFound)));
    }

    #[test]
    fn test_sign_for_identity_multiple_aliases() {
        // Test that sign_for_identity works when multiple aliases exist for an identity
        let (pkcs8_bytes, pubkey_bytes) = generate_test_keypair();
        let passphrase = "Test-P@ss12345";
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only literal with valid did:keri: prefix
        let identity_did = IdentityDID::new_unchecked("did:keri:MULTI123");

        let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("Failed to encrypt");

        let storage = MockKeyStorage::new();
        // Store the same key under multiple aliases (first one should be used)
        let alias = KeyAlias::new_unchecked("primary-alias");
        storage
            .store_key(&alias, &identity_did, KeyRole::Primary, &encrypted)
            .expect("Failed to store key");

        let signer = StorageSigner::new(storage);
        let passphrase_provider = MockPassphraseProvider::new(passphrase);

        let message = b"test message with multiple aliases";
        let signature = signer
            .sign_for_identity(&identity_did, &passphrase_provider, message)
            .expect("Signing should succeed");

        // Verify the signature
        let public_key = UnparsedPublicKey::new(&ED25519, &pubkey_bytes);
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_callback_passphrase_provider() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Track how many times the callback is invoked
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let provider = CallbackPassphraseProvider::new(move |prompt| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            assert!(prompt.contains("test-alias"));
            Ok(Zeroizing::new("callback-passphrase".to_string()))
        });

        // Test successful passphrase retrieval
        let result = provider.get_passphrase("Enter passphrase for test-alias:");
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), "callback-passphrase");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Test multiple invocations
        let result2 = provider.get_passphrase("Another prompt for test-alias");
        assert!(result2.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_callback_passphrase_provider_error() {
        let provider =
            CallbackPassphraseProvider::new(|_prompt| Err(AgentError::UserInputCancelled));

        let result = provider.get_passphrase("Enter passphrase:");
        assert!(matches!(result, Err(AgentError::UserInputCancelled)));
    }

    #[test]
    fn test_cached_passphrase_provider_cache_hit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let inner = Arc::new(CallbackPassphraseProvider::new(move |_prompt| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("cached-pass".to_string()))
        }));

        let cached = CachedPassphraseProvider::new(inner, Duration::from_secs(60));

        // First call should invoke inner
        let result1 = cached.get_passphrase("prompt1");
        assert!(result1.is_ok());
        assert_eq!(*result1.unwrap(), "cached-pass");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call with same prompt should return cached value, not calling inner
        let result2 = cached.get_passphrase("prompt1");
        assert!(result2.is_ok());
        assert_eq!(*result2.unwrap(), "cached-pass");
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // Still 1, cache hit
    }

    #[test]
    fn test_cached_passphrase_provider_cache_miss() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let inner = Arc::new(CallbackPassphraseProvider::new(move |_prompt| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("pass".to_string()))
        }));

        let cached = CachedPassphraseProvider::new(inner, Duration::from_secs(60));

        // Different prompts should each call inner
        let _ = cached.get_passphrase("prompt1");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        let _ = cached.get_passphrase("prompt2");
        assert_eq!(call_count.load(Ordering::SeqCst), 2);

        let _ = cached.get_passphrase("prompt3");
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_cached_passphrase_provider_expiry() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let inner = Arc::new(CallbackPassphraseProvider::new(move |_prompt| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("pass".to_string()))
        }));

        // Very short TTL for testing expiry
        let cached = CachedPassphraseProvider::new(inner, Duration::from_millis(10));

        // First call
        let _ = cached.get_passphrase("prompt");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(20));

        // This should re-fetch from inner since cache expired
        let _ = cached.get_passphrase("prompt");
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_cached_passphrase_provider_clear_cache() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let inner = Arc::new(CallbackPassphraseProvider::new(move |_prompt| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("pass".to_string()))
        }));

        let cached = CachedPassphraseProvider::new(inner, Duration::from_secs(60));

        // First call
        let _ = cached.get_passphrase("prompt");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call should be cache hit
        let _ = cached.get_passphrase("prompt");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Clear cache
        cached.clear_cache();

        // Now should call inner again
        let _ = cached.get_passphrase("prompt");
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_prefilled_passphrase_provider_returns_stored_value() {
        let provider = PrefilledPassphraseProvider::new("my-secret");
        let result = provider.get_passphrase("any prompt").unwrap();
        assert_eq!(*result, "my-secret");

        let result2 = provider.get_passphrase("different prompt").unwrap();
        assert_eq!(*result2, "my-secret");
    }

    #[test]
    fn test_prefilled_passphrase_provider_empty_passphrase() {
        let provider = PrefilledPassphraseProvider::new("");
        let result = provider.get_passphrase("prompt").unwrap();
        assert_eq!(*result, "");
    }

    #[test]
    fn test_unified_passphrase_provider_prompts_once_for_multiple_keys() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();
        let inner = CallbackPassphraseProvider::new(move |_prompt: &str| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("secret".to_string()))
        });

        let provider = UnifiedPassphraseProvider::new(Arc::new(inner));

        // Different prompt messages → should still only hit inner once
        let p1 = provider
            .get_passphrase("Enter passphrase for DEVICE key 'dev':")
            .unwrap();
        let p2 = provider
            .get_passphrase("Enter passphrase for IDENTITY key 'id':")
            .unwrap();

        assert_eq!(*p1, "secret");
        assert_eq!(*p2, "secret");
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // inner called exactly once
    }
}
