use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Registry for tracking OIDC JWT IDs (jti) to detect token replay attacks.
///
/// # Usage
///
/// ```ignore
/// use auths_sdk::oidc_jti_registry::JtiRegistry;
///
/// let registry = JtiRegistry::new();
/// registry.register_jti("token-123")?;
/// registry.register_jti("token-123")?; // Error: replay detected
/// ```
pub struct JtiRegistry {
    inner: Arc<RwLock<JtiRegistryInner>>,
}

struct JtiRegistryInner {
    jtis: HashMap<String, DateTime<Utc>>,
    expiry_queue: VecDeque<(String, DateTime<Utc>)>,
    max_entries: usize,
}

impl JtiRegistry {
    /// Create a new JTI registry with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Create a new JTI registry with specified capacity.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(JtiRegistryInner {
                jtis: HashMap::new(),
                expiry_queue: VecDeque::new(),
                max_entries,
            })),
        }
    }

    /// Register a JTI token, returning an error if it's already been seen.
    ///
    /// # Args
    ///
    /// * `jti`: The JWT ID from the token
    /// * `expires_at`: When the token expires
    pub fn register_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<(), String> {
        let mut inner = self.inner.write();

        if let Some(&registered_at) = inner.jtis.get(jti) {
            return Err(format!(
                "Token JTI '{}' already registered at {}",
                jti, registered_at
            ));
        }

        inner.jtis.insert(jti.to_string(), expires_at);
        inner.expiry_queue.push_back((jti.to_string(), expires_at));

        if inner.jtis.len() > inner.max_entries
            && let Some((old_jti, _)) = inner.expiry_queue.pop_front()
        {
            inner.jtis.remove(&old_jti);
        }

        Ok(())
    }

    /// Check if a JTI is in the registry without registering it.
    pub fn is_seen(&self, jti: &str) -> bool {
        let inner = self.inner.read();
        inner.jtis.contains_key(jti)
    }

    /// Clean up expired entries from the registry.
    pub fn cleanup_expired(&self, now: DateTime<Utc>) {
        let mut inner = self.inner.write();

        while let Some((_jti, expires_at)) = inner.expiry_queue.front() {
            if *expires_at <= now {
                if let Some((removed_jti, _)) = inner.expiry_queue.pop_front() {
                    inner.jtis.remove(&removed_jti);
                }
            } else {
                break;
            }
        }
    }

    /// Get the number of JTIs currently tracked.
    pub fn len(&self) -> usize {
        let inner = self.inner.read();
        inner.jtis.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read();
        inner.jtis.is_empty()
    }
}

impl Default for JtiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for JtiRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_jti_registry_new() {
        let registry = JtiRegistry::new();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_register_jti() {
        let registry = JtiRegistry::new();
        #[allow(clippy::disallowed_methods)] // test code
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        registry.register_jti("token-123", expires).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.is_seen("token-123"));
    }

    #[test]
    fn test_replay_detection() {
        let registry = JtiRegistry::new();
        #[allow(clippy::disallowed_methods)] // test code
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        registry.register_jti("token-123", expires).unwrap();
        let result = registry.register_jti("token-123", expires);
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let registry = JtiRegistry::new();
        #[allow(clippy::disallowed_methods)] // test code
        let now = Utc::now();
        let past = now - Duration::hours(1);
        let future = now + Duration::hours(1);

        registry.register_jti("old-token", past).unwrap();
        registry.register_jti("new-token", future).unwrap();
        assert_eq!(registry.len(), 2);

        registry.cleanup_expired(now);
        assert_eq!(registry.len(), 1);
        assert!(registry.is_seen("new-token"));
        assert!(!registry.is_seen("old-token"));
    }

    #[test]
    fn test_clone() {
        let registry = JtiRegistry::new();
        #[allow(clippy::disallowed_methods)] // test code
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        registry.register_jti("token-123", expires).unwrap();

        let cloned = registry.clone();
        assert_eq!(cloned.len(), 1);
        assert!(cloned.is_seen("token-123"));
    }
}
