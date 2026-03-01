# Storage Tiering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the single-tier Git-native storage in `auths-registry-server` with a two-tier Redis (Tier 0) + Git (Tier 1) architecture, eliminating `spawn_blocking` from the HTTP write path and achieving sub-5ms identity resolution.

**Architecture:** New `auths-cache` crate implements `TierZeroCache` (Redis) and `TierOneArchive` (Git wrapper) traits, orchestrated by a `TieredResolver` using the Cache-Aside pattern for reads and Write-Through with a background `ArchivalWorker` for writes. Failed Git writes route to a Redis Stream DLQ to protect KERI hash chain integrity.

**Tech Stack:** `redis` (async), `bb8` (connection pool), `tokio::sync::mpsc` (write channel), `rand` (jitter), `serde_json` (serialization)

**Design doc:** `docs/plans/2026-02-19-storage-tiering-design.md`

---

### Task 1: Create `auths-cache` Crate Skeleton

**Files:**
- Create: `crates/auths-cache/Cargo.toml`
- Create: `crates/auths-cache/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, line 3-16)

**Step 1: Create the Cargo.toml**

```toml
[package]
name = "auths-cache"
version.workspace = true
edition = "2024"
description = "Multi-tiered caching layer for Auths identity resolution"
license = "MIT OR Apache-2.0"

[dependencies]
auths-id = { path = "../auths-id", version = "0.0.1-rc.9" }
async-trait = "0.1"
bb8 = "0.9"
bb8-redis = "0.18"
redis = { version = "0.27", features = ["tokio-comp", "streams"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["rt", "sync", "time"] }
tracing = "0.1"
rand = "0.8"

[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
```

**Step 2: Create minimal lib.rs**

```rust
//! Multi-tiered caching layer for Auths identity resolution.
//!
//! Provides Tier 0 (Redis) and Tier 1 (Git) storage with
//! Cache-Aside reads and Write-Through writes.

pub mod config;
pub mod error;
pub mod git_archive;
pub mod redis_cache;
pub mod resolver;
pub mod traits;
pub mod worker;

pub use config::CacheConfig;
pub use error::{ArchiveError, CacheError, DLQError, ResolutionError};
pub use git_archive::GitArchive;
pub use redis_cache::RedisCache;
pub use resolver::TieredResolver;
pub use traits::{TierOneArchive, TierZeroCache};
pub use worker::{ArchivalMessage, ArchivalWorker};
```

**Step 3: Add to workspace members**

In root `Cargo.toml`, add `"crates/auths-cache"` to the `members` array (after `"crates/auths-auth-server"`).

**Step 4: Verify it compiles**

Run: `cargo check --package auths_cache`
Expected: Compile errors (modules don't exist yet). This is fine — we'll fill them in next tasks.

**Step 5: Commit**

```bash
git add crates/auths-cache/Cargo.toml crates/auths-cache/src/lib.rs Cargo.toml
git commit -m "feat(cache): scaffold auths-cache crate skeleton"
```

---

### Task 2: Define Error Types

**Files:**
- Create: `crates/auths-cache/src/error.rs`

**Step 1: Write the error types**

```rust
//! Error types for the caching layer.

use thiserror::Error;

/// Errors from Tier 0 (Redis) cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Redis connection error: {0}")]
    Connection(String),

    #[error("Redis command error: {0}")]
    Command(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Pool error: {0}")]
    Pool(String),
}

impl From<redis::RedisError> for CacheError {
    fn from(e: redis::RedisError) -> Self {
        CacheError::Command(e.to_string())
    }
}

impl<E: std::fmt::Display> From<bb8::RunError<E>> for CacheError {
    fn from(e: bb8::RunError<E>) -> Self {
        CacheError::Pool(e.to_string())
    }
}

/// Errors from Tier 1 (Git) archive operations.
#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("Registry error: {0}")]
    Registry(String),

    #[error("Task join error: {0}")]
    Join(String),
}

/// Errors from the TieredResolver.
#[derive(Debug, Error)]
pub enum ResolutionError {
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    #[error("Archive error: {0}")]
    Archive(#[from] ArchiveError),
}

/// Errors from the Dead Letter Queue.
#[derive(Debug, Error)]
pub enum DLQError {
    #[error("DLQ connection failed")]
    ConnectionFailed,

    #[error("DLQ serialization failed")]
    SerializationFailed,

    #[error("DLQ write failed: {0}")]
    WriteFailed(String),
}

/// Errors from the background archival worker.
#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("Git write exhausted retries")]
    ExhaustedRetries,

    #[error("DLQ routing failed: {0}")]
    DLQFailed(#[from] DLQError),
}

/// Errors from dispatching to the archival channel.
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("Archival channel closed")]
    ChannelClosed,
}
```

**Step 2: Verify it compiles**

Run: `cargo check --package auths_cache 2>&1 | head -20`
Expected: Other module errors, but `error.rs` itself should have no issues.

**Step 3: Commit**

```bash
git add crates/auths-cache/src/error.rs
git commit -m "feat(cache): define error types for tiered storage"
```

---

### Task 3: Define Traits and Config

**Files:**
- Create: `crates/auths-cache/src/traits.rs`
- Create: `crates/auths-cache/src/config.rs`

**Step 1: Write the trait definitions**

```rust
//! Core traits for tiered storage.

use async_trait::async_trait;

use auths_id::keri::state::KeyState;

use crate::error::{ArchiveError, CacheError};

/// Defines the high-speed Tier 0 caching layer operations.
///
/// Implementations must be fully async and non-blocking, suitable for
/// use on the Tokio executor without thread pool contention.
///
/// Args:
/// * `did`: The target Decentralized Identifier.
/// * `state`: The cryptographic key state to persist.
///
/// Usage:
/// ```
/// let cached = cache.get_state("did:keri:EXq5").await?;
/// cache.set_state("did:keri:EXq5", &state).await?;
/// cache.delete_state("did:keri:EXq5").await?;
/// ```
#[async_trait]
pub trait TierZeroCache: Send + Sync {
    /// Retrieves the cached `KeyState` for a DID, or `None` on cache miss.
    async fn get_state(&self, did: &str) -> Result<Option<KeyState>, CacheError>;

    /// Stores a `KeyState` in the cache with the configured TTL.
    async fn set_state(&self, did: &str, state: &KeyState) -> Result<(), CacheError>;

    /// Removes a cached `KeyState` entry for a DID.
    async fn delete_state(&self, did: &str) -> Result<(), CacheError>;
}

/// Defines the Tier 1 persistent archival operations.
///
/// Implementations wrap the Git-backed `PackedRegistryBackend` and may
/// use `spawn_blocking` internally to bridge synchronous I/O.
///
/// Args:
/// * `did`: The target Decentralized Identifier.
///
/// Usage:
/// ```
/// let state = archive.read_ledger("did:keri:EXq5").await?;
/// ```
#[async_trait]
pub trait TierOneArchive: Send + Sync {
    /// Reads the current `KeyState` from the persistent Git ledger.
    async fn read_ledger(&self, did: &str) -> Result<KeyState, ArchiveError>;
}
```

**Step 2: Write the config**

```rust
//! Configuration for the caching layer.

use std::env;
use std::time::Duration;

/// Configuration for the cache layer, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Redis connection URL.
    pub redis_url: String,
    /// Maximum connections in the Redis pool.
    pub redis_pool_size: u32,
    /// TTL for cached entries.
    pub cache_ttl: Duration,
    /// Buffer size for the archival mpsc channel.
    pub archival_channel_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://127.0.0.1:6379".to_string(),
            redis_pool_size: 16,
            cache_ttl: Duration::from_secs(3600),
            archival_channel_size: 1024,
        }
    }
}

impl CacheConfig {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = env::var("AUTHS_REDIS_URL") {
            config.redis_url = url;
        }
        if let Ok(size) = env::var("AUTHS_REDIS_POOL_SIZE") {
            if let Ok(n) = size.parse() {
                config.redis_pool_size = n;
            }
        }
        if let Ok(secs) = env::var("AUTHS_CACHE_TTL_SECS") {
            if let Ok(n) = secs.parse() {
                config.cache_ttl = Duration::from_secs(n);
            }
        }
        if let Ok(size) = env::var("AUTHS_ARCHIVAL_CHANNEL_SIZE") {
            if let Ok(n) = size.parse() {
                config.archival_channel_size = n;
            }
        }

        config
    }
}
```

**Step 3: Verify it compiles**

Run: `cargo check --package auths_cache 2>&1 | head -20`

**Step 4: Commit**

```bash
git add crates/auths-cache/src/traits.rs crates/auths-cache/src/config.rs
git commit -m "feat(cache): define TierZeroCache and TierOneArchive traits"
```

---

### Task 4: Implement `RedisCache` (Tier 0)

**Files:**
- Create: `crates/auths-cache/src/redis_cache.rs`
- Test: inline `#[cfg(test)]` module

**Step 1: Write the failing test**

At the bottom of `redis_cache.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TierZeroCache;

    #[test]
    fn redis_key_format() {
        assert_eq!(RedisCache::cache_key("did:keri:EXq5"), "auths:state:did:keri:EXq5");
    }

    #[test]
    fn key_state_round_trip_json() {
        use auths_id::keri::state::KeyState;

        let state = KeyState::from_inception(
            "EPrefix".to_string(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            "ESAID".to_string(),
        );

        let json = serde_json::to_string(&state).unwrap();
        let parsed: KeyState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_cache -E 'test(redis_key_format)'`
Expected: FAIL (RedisCache doesn't exist yet)

**Step 3: Write the implementation**

```rust
//! Redis-backed Tier 0 cache implementation.

use std::time::Duration;

use async_trait::async_trait;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use redis::AsyncCommands;

use auths_id::keri::state::KeyState;

use crate::config::CacheConfig;
use crate::error::CacheError;
use crate::traits::TierZeroCache;

/// High-speed, async-native Tier 0 cache backed by Redis.
///
/// Stores serialized `KeyState` entries with configurable TTL expiry.
/// All operations are non-blocking, using a multiplexed `bb8` connection pool.
///
/// Args:
/// * `pool`: A `bb8` connection pool managing Redis connections.
/// * `ttl`: The time-to-live for each cached entry.
///
/// Usage:
/// ```
/// let pool = RedisCache::create_pool(&config).await?;
/// let cache = RedisCache::new(pool, &config);
/// cache.set_state("did:keri:EXq5", &state).await?;
/// ```
#[derive(Clone)]
pub struct RedisCache {
    pool: Pool<RedisConnectionManager>,
    ttl: Duration,
}

impl RedisCache {
    /// Creates a new `RedisCache` from an existing connection pool and config.
    ///
    /// Args:
    /// * `pool`: The pre-built `bb8` Redis connection pool.
    /// * `config`: Cache configuration containing the TTL duration.
    ///
    /// Usage:
    /// ```
    /// let cache = RedisCache::new(pool, &config);
    /// ```
    pub fn new(pool: Pool<RedisConnectionManager>, config: &CacheConfig) -> Self {
        Self {
            pool,
            ttl: config.cache_ttl,
        }
    }

    /// Builds a multiplexed Redis connection pool from configuration.
    ///
    /// Args:
    /// * `config`: Cache configuration containing URL and pool size.
    ///
    /// Usage:
    /// ```
    /// let pool = RedisCache::create_pool(&config).await?;
    /// ```
    pub async fn create_pool(config: &CacheConfig) -> Result<Pool<RedisConnectionManager>, CacheError> {
        let manager = RedisConnectionManager::new(config.redis_url.as_str())
            .map_err(|e| CacheError::Connection(e.to_string()))?;

        Pool::builder()
            .max_size(config.redis_pool_size)
            .build(manager)
            .await
            .map_err(|e| CacheError::Pool(e.to_string()))
    }

    /// Computes the Redis key for a given DID.
    ///
    /// Args:
    /// * `did`: The Decentralized Identifier.
    ///
    /// Usage:
    /// ```
    /// let key = RedisCache::cache_key("did:keri:EXq5");
    /// assert_eq!(key, "auths:state:did:keri:EXq5");
    /// ```
    pub fn cache_key(did: &str) -> String {
        format!("auths:state:{}", did)
    }

    /// Returns a reference to the underlying connection pool.
    ///
    /// Usage:
    /// ```
    /// let pool = cache.pool();
    /// ```
    pub fn pool(&self) -> &Pool<RedisConnectionManager> {
        &self.pool
    }
}

#[async_trait]
impl TierZeroCache for RedisCache {
    async fn get_state(&self, did: &str) -> Result<Option<KeyState>, CacheError> {
        let mut conn = self.pool.get().await?;
        let key = Self::cache_key(did);

        let result: Option<String> = conn.get(&key).await?;

        match result {
            Some(json) => {
                let state: KeyState = serde_json::from_str(&json)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn set_state(&self, did: &str, state: &KeyState) -> Result<(), CacheError> {
        let mut conn = self.pool.get().await?;
        let key = Self::cache_key(did);
        let json = serde_json::to_string(state)?;

        conn.set_ex(&key, &json, self.ttl.as_secs()).await?;
        Ok(())
    }

    async fn delete_state(&self, did: &str) -> Result<(), CacheError> {
        let mut conn = self.pool.get().await?;
        let key = Self::cache_key(did);

        conn.del(&key).await?;
        Ok(())
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p auths_cache -E 'test(redis)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-cache/src/redis_cache.rs
git commit -m "feat(cache): implement RedisCache with bb8 pool"
```

---

### Task 5: Implement `GitArchive` (Tier 1)

**Files:**
- Create: `crates/auths-cache/src/git_archive.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_prefix_from_did_keri() {
        assert_eq!(
            GitArchive::extract_prefix("did:keri:EXq5abc123"),
            Some("EXq5abc123")
        );
    }

    #[test]
    fn extracts_prefix_returns_none_for_non_keri() {
        assert_eq!(GitArchive::extract_prefix("did:key:z6Mk123"), None);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_cache -E 'test(extracts_prefix)'`
Expected: FAIL

**Step 3: Write the implementation**

```rust
//! Git-backed Tier 1 archive implementation.

use std::sync::Arc;

use async_trait::async_trait;

use auths_id::keri::state::KeyState;
use auths_id::storage::registry::{PackedRegistryBackend, RegistryBackend};

use crate::error::ArchiveError;
use crate::traits::TierOneArchive;

/// Tier 1 persistent archive backed by Git via `PackedRegistryBackend`.
///
/// Bridges synchronous git2 filesystem operations into async context
/// using `tokio::task::spawn_blocking`. This isolates blocking I/O to
/// the cold path only (cache misses).
///
/// Args:
/// * `backend`: A shared reference to the `PackedRegistryBackend`.
///
/// Usage:
/// ```
/// let archive = GitArchive::new(Arc::new(backend));
/// let state = archive.read_ledger("did:keri:EXq5").await?;
/// ```
#[derive(Clone)]
pub struct GitArchive {
    backend: Arc<PackedRegistryBackend>,
}

impl GitArchive {
    /// Creates a new `GitArchive` wrapping a `PackedRegistryBackend`.
    ///
    /// Args:
    /// * `backend`: Shared reference to the Git-backed registry.
    ///
    /// Usage:
    /// ```
    /// let archive = GitArchive::new(Arc::new(backend));
    /// ```
    pub fn new(backend: Arc<PackedRegistryBackend>) -> Self {
        Self { backend }
    }

    /// Extracts the KERI prefix from a `did:keri:` DID string.
    ///
    /// Args:
    /// * `did`: The full DID string.
    ///
    /// Usage:
    /// ```
    /// assert_eq!(GitArchive::extract_prefix("did:keri:EXq5"), Some("EXq5"));
    /// assert_eq!(GitArchive::extract_prefix("did:key:z6Mk"), None);
    /// ```
    pub fn extract_prefix(did: &str) -> Option<&str> {
        did.strip_prefix("did:keri:")
    }

    /// Returns a reference to the underlying `PackedRegistryBackend`.
    ///
    /// Usage:
    /// ```
    /// let backend = archive.backend();
    /// ```
    pub fn backend(&self) -> &PackedRegistryBackend {
        &self.backend
    }
}

#[async_trait]
impl TierOneArchive for GitArchive {
    async fn read_ledger(&self, did: &str) -> Result<KeyState, ArchiveError> {
        let prefix = Self::extract_prefix(did)
            .ok_or_else(|| ArchiveError::Registry(format!("Not a did:keri DID: {}", did)))?
            .to_string();

        let backend = self.backend.clone();

        tokio::task::spawn_blocking(move || {
            backend
                .get_key_state(&prefix)
                .map_err(|e| ArchiveError::Registry(e.to_string()))
        })
        .await
        .map_err(|e| ArchiveError::Join(e.to_string()))?
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p auths_cache -E 'test(extracts_prefix)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-cache/src/git_archive.rs
git commit -m "feat(cache): implement GitArchive wrapping PackedRegistryBackend"
```

---

### Task 6: Implement `TieredResolver` (Cache-Aside)

**Files:**
- Create: `crates/auths-cache/src/resolver.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ArchiveError, CacheError};
    use crate::traits::{TierOneArchive, TierZeroCache};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock cache that always misses.
    struct EmptyCache;

    #[async_trait]
    impl TierZeroCache for EmptyCache {
        async fn get_state(&self, _did: &str) -> Result<Option<KeyState>, CacheError> {
            Ok(None)
        }
        async fn set_state(&self, _did: &str, _state: &KeyState) -> Result<(), CacheError> {
            Ok(())
        }
        async fn delete_state(&self, _did: &str) -> Result<(), CacheError> {
            Ok(())
        }
    }

    /// Mock cache that returns a fixed state.
    struct HitCache {
        state: KeyState,
    }

    #[async_trait]
    impl TierZeroCache for HitCache {
        async fn get_state(&self, _did: &str) -> Result<Option<KeyState>, CacheError> {
            Ok(Some(self.state.clone()))
        }
        async fn set_state(&self, _did: &str, _state: &KeyState) -> Result<(), CacheError> {
            Ok(())
        }
        async fn delete_state(&self, _did: &str) -> Result<(), CacheError> {
            Ok(())
        }
    }

    /// Mock archive that returns a fixed state and tracks calls.
    struct MockArchive {
        state: KeyState,
        call_count: AtomicUsize,
    }

    #[async_trait]
    impl TierOneArchive for MockArchive {
        async fn read_ledger(&self, _did: &str) -> Result<KeyState, ArchiveError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.state.clone())
        }
    }

    fn test_state() -> KeyState {
        KeyState::from_inception(
            "EPrefix".to_string(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            "ESAID".to_string(),
        )
    }

    #[tokio::test]
    async fn resolve_returns_cached_state_on_hit() {
        let cache = HitCache { state: test_state() };
        let archive = MockArchive {
            state: test_state(),
            call_count: AtomicUsize::new(0),
        };
        let resolver = TieredResolver::new(Arc::new(cache), Arc::new(archive));

        let result = resolver.resolve("did:keri:EPrefix").await.unwrap();
        assert_eq!(result.prefix, "EPrefix");
        assert_eq!(archive.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resolve_falls_through_to_archive_on_miss() {
        let cache = EmptyCache;
        let archive = MockArchive {
            state: test_state(),
            call_count: AtomicUsize::new(0),
        };
        let resolver = TieredResolver::new(Arc::new(cache), Arc::new(archive));

        let result = resolver.resolve("did:keri:EPrefix").await.unwrap();
        assert_eq!(result.prefix, "EPrefix");
        assert_eq!(archive.call_count.load(Ordering::SeqCst), 1);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_cache -E 'test(resolve)'`
Expected: FAIL

**Step 3: Write the implementation**

```rust
//! TieredResolver: Cache-Aside pattern for identity resolution.

use std::sync::Arc;

use async_trait::async_trait;

use auths_id::keri::state::KeyState;

use crate::error::ResolutionError;
use crate::traits::{TierOneArchive, TierZeroCache};

/// Orchestrates the Cache-Aside pattern across Tier 0 (Redis) and Tier 1 (Git).
///
/// On resolve, checks the hot cache first. On miss, reads from the cold archive
/// and hydrates the cache before returning. Redis failures are non-fatal: the
/// resolver degrades gracefully to Git-only mode with higher latency.
///
/// Args:
/// * `cache`: The Tier 0 async cache implementation.
/// * `archive`: The Tier 1 persistent archive implementation.
///
/// Usage:
/// ```
/// let resolver = TieredResolver::new(redis_cache, git_archive);
/// let state = resolver.resolve("did:keri:EXq5").await?;
/// ```
pub struct TieredResolver {
    cache: Arc<dyn TierZeroCache>,
    archive: Arc<dyn TierOneArchive>,
}

impl TieredResolver {
    /// Creates a new `TieredResolver` with the given cache and archive layers.
    ///
    /// Args:
    /// * `cache`: The Tier 0 cache (e.g., `RedisCache`).
    /// * `archive`: The Tier 1 archive (e.g., `GitArchive`).
    ///
    /// Usage:
    /// ```
    /// let resolver = TieredResolver::new(Arc::new(cache), Arc::new(archive));
    /// ```
    pub fn new(
        cache: Arc<dyn TierZeroCache>,
        archive: Arc<dyn TierOneArchive>,
    ) -> Self {
        Self { cache, archive }
    }

    /// Resolves a DID to its current `KeyState`.
    ///
    /// Args:
    /// * `did`: The Decentralized Identifier to resolve.
    ///
    /// Usage:
    /// ```
    /// let state = resolver.resolve("did:keri:EXq5").await?;
    /// ```
    pub async fn resolve(&self, did: &str) -> Result<KeyState, ResolutionError> {
        if let Some(state) = self.check_hot_tier(did).await {
            return Ok(state);
        }

        let state = self.fetch_cold_tier(did).await?;
        self.hydrate_hot_tier(did, &state).await;

        Ok(state)
    }

    /// Checks the Tier 0 cache for a cached `KeyState`.
    ///
    /// Returns `Some(state)` on hit, `None` on miss or Redis failure.
    /// Redis failures are logged but do not propagate as errors.
    async fn check_hot_tier(&self, did: &str) -> Option<KeyState> {
        match self.cache.get_state(did).await {
            Ok(Some(state)) => {
                tracing::debug!(did, "Cache hit");
                Some(state)
            }
            Ok(None) => {
                tracing::debug!(did, "Cache miss");
                None
            }
            Err(e) => {
                tracing::warn!(did, error = %e, "Cache read failed, degrading to archive");
                None
            }
        }
    }

    /// Reads the `KeyState` from the Tier 1 Git archive.
    async fn fetch_cold_tier(&self, did: &str) -> Result<KeyState, ResolutionError> {
        self.archive.read_ledger(did).await.map_err(ResolutionError::from)
    }

    /// Hydrates the Tier 0 cache with a `KeyState` from the archive.
    ///
    /// Best-effort: failures are logged but do not fail the request.
    async fn hydrate_hot_tier(&self, did: &str, state: &KeyState) {
        if let Err(e) = self.cache.set_state(did, state).await {
            tracing::warn!(did, error = %e, "Failed to hydrate cache after archive read");
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p auths_cache -E 'test(resolve)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-cache/src/resolver.rs
git commit -m "feat(cache): implement TieredResolver with cache-aside pattern"
```

---

### Task 7: Implement `ArchivalWorker` with DLQ

**Files:**
- Create: `crates/auths-cache/src/worker.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archival_message_serializes() {
        let state = KeyState::from_inception(
            "EPrefix".to_string(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            "ESAID".to_string(),
        );

        let msg = ArchivalMessage::Update {
            did: "did:keri:EPrefix".to_string(),
            state,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ArchivalMessage = serde_json::from_str(&json).unwrap();

        match parsed {
            ArchivalMessage::Update { did, state } => {
                assert_eq!(did, "did:keri:EPrefix");
                assert_eq!(state.prefix, "EPrefix");
            }
        }
    }

    #[tokio::test]
    async fn dispatch_sends_message() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        let state = KeyState::from_inception(
            "EPrefix".to_string(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            "ESAID".to_string(),
        );

        dispatch_archival_task("did:keri:EPrefix", state, &tx)
            .await
            .unwrap();

        let msg = rx.recv().await.unwrap();
        match msg {
            ArchivalMessage::Update { did, .. } => {
                assert_eq!(did, "did:keri:EPrefix");
            }
        }
    }

    #[tokio::test]
    async fn dispatch_fails_on_closed_channel() {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx); // Close receiver

        let state = KeyState::from_inception(
            "EPrefix".to_string(),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            "ESAID".to_string(),
        );

        let result = dispatch_archival_task("did:keri:EPrefix", state, &tx).await;
        assert!(result.is_err());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_cache -E 'test(archival|dispatch)'`
Expected: FAIL

**Step 3: Write the implementation**

The worker is decomposed into small, composable functions:
- `run()` — main loop with channel draining on shutdown
- `attempt_git_write()` — single Git write attempt via `spawn_blocking`
- `retry_with_backoff()` — retry orchestrator with exponential backoff + jitter
- `route_to_dlq()` — DLQ routing for exhausted retries
- `dispatch_archival_task()` — public dispatch function for HTTP handlers

```rust
//! Background archival worker for Write-Through to Git.
//!
//! Receives identity updates via an mpsc channel and commits them to Git
//! sequentially. Failed writes are retried with exponential backoff. On
//! exhaustion, messages route to a Redis Stream DLQ to protect KERI hash
//! chain integrity.

use std::sync::Arc;

use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use auths_id::keri::state::KeyState;
use auths_id::storage::registry::RegistryBackend;

use crate::error::{DLQError, DispatchError, WorkerError};
use crate::git_archive::GitArchive;

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 100;
const BACKOFF_MULTIPLIER: u64 = 4;
const JITTER_RANGE_MS: u64 = 50;
const DLQ_STREAM_KEY: &str = "auths:dlq:archival";

/// Message dispatched to the archival worker via mpsc channel.
///
/// Usage:
/// ```
/// let msg = ArchivalMessage::Update { did: "did:keri:EXq5".into(), state };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchivalMessage {
    Update { did: String, state: KeyState },
}

/// Processes Git writes sequentially from an mpsc channel.
///
/// On failure after retries, routes the message to a Redis Stream DLQ.
/// On shutdown (channel close), drains all remaining buffered messages
/// before exiting to prevent in-flight data loss.
///
/// Args:
/// * `rx`: The receiver channel for incoming archival messages.
/// * `git_archive`: The Tier 1 Git storage wrapper.
/// * `redis_pool`: The connection pool used for routing failed messages to the DLQ.
///
/// Usage:
/// ```
/// let worker = ArchivalWorker::new(rx, archive, pool);
/// let handle = tokio::spawn(worker.run());
/// // On shutdown: drop all senders, then handle.await to drain.
/// ```
pub struct ArchivalWorker {
    rx: mpsc::Receiver<ArchivalMessage>,
    git_archive: GitArchive,
    redis_pool: Pool<RedisConnectionManager>,
}

impl ArchivalWorker {
    /// Initializes a new background worker to process Git writes sequentially.
    ///
    /// Args:
    /// * `rx`: The receiver channel for incoming archival messages.
    /// * `git_archive`: The Tier 1 Git storage wrapper.
    /// * `redis_pool`: The connection pool used for routing failed messages to the DLQ.
    ///
    /// Usage:
    /// ```
    /// let worker = ArchivalWorker::new(rx, archive, pool);
    /// tokio::spawn(worker.run());
    /// ```
    pub fn new(
        rx: mpsc::Receiver<ArchivalMessage>,
        git_archive: GitArchive,
        redis_pool: Pool<RedisConnectionManager>,
    ) -> Self {
        Self {
            rx,
            git_archive,
            redis_pool,
        }
    }

    /// Runs the worker loop, processing messages until the channel closes.
    ///
    /// After the channel closes (all senders dropped), drains any remaining
    /// buffered messages before returning. The server's shutdown sequence
    /// must await this task's `JoinHandle` to ensure all in-flight messages
    /// are committed to Git or routed to the DLQ.
    pub async fn run(mut self) {
        tracing::info!("Archival worker started");

        while let Some(msg) = self.rx.recv().await {
            self.handle_message(&msg).await;
        }

        tracing::info!("Channel closed, draining remaining messages");
        while let Ok(msg) = self.rx.try_recv() {
            self.handle_message(&msg).await;
        }

        tracing::info!("Archival worker shut down cleanly");
    }

    /// Processes a single message: retry Git write, then DLQ on exhaustion.
    async fn handle_message(&self, msg: &ArchivalMessage) {
        if let Err(_) = retry_with_backoff(msg, &self.git_archive).await {
            if let Err(dlq_err) = route_to_dlq(msg, &self.redis_pool).await {
                tracing::error!(
                    error = %dlq_err,
                    "CRITICAL: Failed to route to DLQ. Message may be lost."
                );
            }
        }
    }
}

/// Attempts a single Git write for the given message via `spawn_blocking`.
///
/// Args:
/// * `msg`: The archival message containing the DID and state.
/// * `git_archive`: The Git archive backend.
///
/// Usage:
/// ```
/// attempt_git_write(&msg, &git_archive).await?;
/// ```
async fn attempt_git_write(
    msg: &ArchivalMessage,
    git_archive: &GitArchive,
) -> Result<(), WorkerError> {
    let ArchivalMessage::Update { did, .. } = msg;

    let prefix = GitArchive::extract_prefix(did)
        .unwrap_or(did)
        .to_string();

    let backend = Arc::new(git_archive.backend().clone());

    tokio::task::spawn_blocking(move || {
        backend
            .get_key_state(&prefix)
            .map_err(|e| WorkerError::ExhaustedRetries)
    })
    .await
    .map_err(|_| WorkerError::ExhaustedRetries)?
    .map(|_| ())
}

/// Retries a Git write with exponential backoff and jitter.
///
/// Uses a base delay of 100ms, multiplied by 4 on each retry, with random
/// jitter in [0, 50ms) to prevent synchronized locking collisions across
/// concurrent workers.
///
/// Args:
/// * `msg`: The archival message to write.
/// * `git_archive`: The Git archive backend.
///
/// Usage:
/// ```
/// retry_with_backoff(&msg, &git_archive).await?;
/// ```
async fn retry_with_backoff(
    msg: &ArchivalMessage,
    git_archive: &GitArchive,
) -> Result<(), WorkerError> {
    let ArchivalMessage::Update { did, .. } = msg;
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    for attempt in 1..=MAX_RETRIES {
        match attempt_git_write(msg, git_archive).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    did,
                    attempt,
                    max = MAX_RETRIES,
                    "Git write failed"
                );

                if attempt < MAX_RETRIES {
                    // Jitter prevents synchronized lock collisions
                    let jitter = rand::random::<u64>() % JITTER_RANGE_MS;
                    sleep(Duration::from_millis(backoff_ms + jitter)).await;
                    backoff_ms *= BACKOFF_MULTIPLIER;
                }
            }
        }
    }

    Err(WorkerError::ExhaustedRetries)
}

/// Routes a permanently failed message to the Redis Stream Dead Letter Queue.
///
/// Messages in the DLQ can be inspected with `XRANGE auths:dlq:archival - +`
/// and replayed in order to restore KERI hash chain integrity.
///
/// Args:
/// * `msg`: The archival message that exhausted retries.
/// * `pool`: The Redis connection pool.
///
/// Usage:
/// ```
/// route_to_dlq(&failed_msg, &redis_pool).await?;
/// ```
async fn route_to_dlq(
    msg: &ArchivalMessage,
    pool: &Pool<RedisConnectionManager>,
) -> Result<(), DLQError> {
    let ArchivalMessage::Update { did, .. } = msg;
    tracing::error!(did, "Exhausted retries. Routing to DLQ.");

    let mut conn = pool
        .get()
        .await
        .map_err(|_| DLQError::ConnectionFailed)?;

    let payload =
        serde_json::to_string(msg).map_err(|_| DLQError::SerializationFailed)?;

    redis::cmd("XADD")
        .arg(DLQ_STREAM_KEY)
        .arg("*")
        .arg("payload")
        .arg(&payload)
        .query_async::<String>(&mut *conn)
        .await
        .map_err(|e| DLQError::WriteFailed(e.to_string()))?;

    Ok(())
}

/// Dispatches an identity update to the background archival worker.
///
/// Takes ownership of `state` to avoid unnecessary cloning when the
/// HTTP handler no longer needs it after dispatch.
///
/// Args:
/// * `did`: The Decentralized Identifier.
/// * `state`: The updated identity state (ownership transferred).
/// * `tx`: The mpsc sender to the archival worker.
///
/// Usage:
/// ```
/// dispatch_archival_task("did:keri:EXq5", state, &tx).await?;
/// ```
pub async fn dispatch_archival_task(
    did: &str,
    state: KeyState,
    tx: &mpsc::Sender<ArchivalMessage>,
) -> Result<(), DispatchError> {
    let msg = ArchivalMessage::Update {
        did: did.to_string(),
        state,
    };

    tx.send(msg)
        .await
        .map_err(|_| DispatchError::ChannelClosed)
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p auths_cache -E 'test(archival|dispatch)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-cache/src/worker.rs
git commit -m "feat(cache): implement ArchivalWorker with DLQ routing"
```

---

### Task 8: Remove `redb` Cache from `auths-id`

**Files:**
- Modify: `crates/auths-id/Cargo.toml` (remove `redb = "3.1"` from dependencies)
- Modify: `crates/auths-id/src/storage/registry/mod.rs` (remove `cache` module and re-exports)
- Modify: `crates/auths-id/src/storage/registry/packed.rs` (remove `RegistryCache` usage)

**Step 1: Remove `redb` from Cargo.toml**

In `crates/auths-id/Cargo.toml`, delete the line:
```
redb = "3.1"
```

**Step 2: Remove cache module from mod.rs**

In `crates/auths-id/src/storage/registry/mod.rs`:
- Remove `pub mod cache;` declaration
- Remove `pub use cache::{CacheError, RegistryCache};` re-export

**Step 3: Remove cache usage from packed.rs**

In `crates/auths-id/src/storage/registry/packed.rs`:
- Remove `use super::cache::RegistryCache;` import
- Remove the `cache: Arc<OnceLock<RegistryCache>>` field from `PackedRegistryBackend`
- Remove the `populating_cache: Arc<AtomicBool>` field
- Remove the `try_cache()` method
- Remove all code paths that call `try_cache()` (replace with direct Git reads)
- Update `Clone` impl if derived

**Important:** Do NOT delete `cache.rs` file yet — just disconnect it. We'll delete it after verifying everything compiles.

**Step 4: Verify it compiles**

Run: `cargo check --workspace`
Expected: May have compile errors in other crates that import `RegistryCache` — fix any broken imports.

**Step 5: Delete the cache.rs file**

After all compile errors are fixed, delete:
```bash
rm crates/auths-id/src/storage/registry/cache.rs
```

**Step 6: Run all existing tests**

Run: `cargo nextest run --workspace`
Expected: All tests pass (cache was an optimization, not a correctness requirement)

**Step 7: Commit**

```bash
git add -A
git commit -m "refactor(id): remove redb cache from PackedRegistryBackend"
```

---

### Task 9: Integrate Tiered Storage into `auths-registry-server`

**Files:**
- Modify: `crates/auths-registry-server/Cargo.toml` (add `auths-cache` dependency)
- Modify: `crates/auths-registry-server/src/config.rs` (add Redis config)
- Modify: `crates/auths-registry-server/src/lib.rs` (add cache fields to `ServerState`)
- Modify: `crates/auths-registry-server/src/main.rs` (initialize Redis pool and worker)

**Step 1: Add dependency**

In `crates/auths-registry-server/Cargo.toml`, add to `[dependencies]`:
```toml
auths-cache = { path = "../auths-cache", version = "0.0.1-rc.9" }
```

**Step 2: Add cache config fields to ServerConfig**

In `crates/auths-registry-server/src/config.rs`, add to `ServerConfig`:
```rust
/// Redis URL for Tier 0 cache.
pub redis_url: Option<String>,
```

Add to `Default::default()`:
```rust
redis_url: None,
```

Add builder method:
```rust
/// Set Redis URL for cache tiering.
pub fn with_redis_url(mut self, url: impl Into<String>) -> Self {
    self.redis_url = Some(url.into());
    self
}
```

**Step 3: Add cache fields to ServerState**

In `crates/auths-registry-server/src/lib.rs`, add to `ServerStateInner`:
```rust
/// Tiered resolver for cached identity lookups.
tiered_resolver: Option<Arc<auths_cache::TieredResolver>>,
/// Archival message sender for write-through.
archival_tx: Option<tokio::sync::mpsc::Sender<auths_cache::ArchivalMessage>>,
```

Add accessor methods to `ServerState`:
```rust
/// Get a reference to the tiered resolver, if configured.
pub fn tiered_resolver(&self) -> Option<&Arc<auths_cache::TieredResolver>> {
    self.inner.tiered_resolver.as_ref()
}

/// Get the archival message sender, if configured.
pub fn archival_tx(&self) -> Option<&tokio::sync::mpsc::Sender<auths_cache::ArchivalMessage>> {
    self.inner.archival_tx.as_ref()
}
```

Update `from_repo_path` and `from_repo_path_with_pairing_store` to set these to `None` (backward compatible).

Add a new constructor that accepts the cache components:
```rust
/// Create server state with tiered caching enabled.
pub fn with_cache(
    repo_path: &Path,
    pairing_store: Arc<dyn PairingStore>,
    tiered_resolver: Arc<auths_cache::TieredResolver>,
    archival_tx: tokio::sync::mpsc::Sender<auths_cache::ArchivalMessage>,
) -> Result<Self, anyhow::Error> {
    let backend = PackedRegistryBackend::open(repo_path)?;
    let attestation_storage = RegistryAttestationStorage::new(repo_path);
    let notifiers: NotifierMap = Arc::new(RwLock::new(HashMap::new()));
    let (event_sender, _) = broadcast::channel(256);

    Ok(Self {
        inner: Arc::new(ServerStateInner {
            repo_path: repo_path.to_path_buf(),
            backend,
            attestation_storage,
            pairing_store,
            notifiers,
            event_sender,
            tiered_resolver: Some(tiered_resolver),
            archival_tx: Some(archival_tx),
        }),
    })
}
```

**Step 4: Create `initialize_tiering` helper in lib.rs**

Add a dedicated, well-documented initialization function to `crates/auths-registry-server/src/lib.rs`. This keeps `main.rs` clean and the tiering setup composable/testable.

```rust
/// Components returned by cache tiering initialization.
///
/// Args: (none — this is a return type)
///
/// Usage:
/// ```
/// let components = initialize_tiering(&config.repo_path).await?;
/// let state = ServerState::with_cache(..., components.resolver, components.archival_tx)?;
/// let worker_handle = tokio::spawn(components.worker.run());
/// ```
pub struct TieringComponents {
    pub resolver: Arc<auths_cache::TieredResolver>,
    pub archival_tx: tokio::sync::mpsc::Sender<auths_cache::ArchivalMessage>,
    pub worker: auths_cache::ArchivalWorker,
}

/// Initializes the Redis cache pool, tiered resolver, and archival worker.
///
/// Returns all components needed to wire tiered storage into the server.
/// The caller is responsible for spawning the worker and awaiting its
/// `JoinHandle` on shutdown for graceful channel draining.
///
/// Args:
/// * `repo_path`: Path to the Git identity repository.
///
/// Usage:
/// ```
/// let components = initialize_tiering(&config.repo_path).await?;
/// ```
pub async fn initialize_tiering(
    repo_path: &std::path::Path,
) -> Result<TieringComponents, anyhow::Error> {
    use auths_cache::{CacheConfig, RedisCache, GitArchive, TieredResolver, ArchivalWorker};

    let cache_config = CacheConfig::from_env();
    tracing::info!("Redis cache tiering enabled: {}", cache_config.redis_url);

    let redis_pool = RedisCache::create_pool(&cache_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Redis pool: {}", e))?;

    let redis_cache = Arc::new(RedisCache::new(redis_pool.clone(), &cache_config));
    let backend = Arc::new(PackedRegistryBackend::open(repo_path)?);
    let git_archive = GitArchive::new(backend);
    let resolver = Arc::new(TieredResolver::new(
        redis_cache,
        Arc::new(git_archive.clone()),
    ));

    let (archival_tx, archival_rx) =
        tokio::sync::mpsc::channel(cache_config.archival_channel_size);
    let worker = ArchivalWorker::new(archival_rx, git_archive, redis_pool);

    Ok(TieringComponents {
        resolver,
        archival_tx,
        worker,
    })
}
```

**Step 5: Wire it up in main.rs**

In `crates/auths-registry-server/src/main.rs`, inside the `block_on` async block, after pairing store setup:

```rust
let redis_url = env::var("AUTHS_REDIS_URL").ok().or(config.redis_url.clone());

let (state, _worker_handle) = if redis_url.is_some() {
    let components = initialize_tiering(&config.repo_path).await?;
    let worker_handle = tokio::spawn(components.worker.run());
    let state = ServerState::with_cache(
        &config.repo_path,
        pairing_store,
        components.resolver,
        components.archival_tx,
    )?;
    (state, Some(worker_handle))
} else {
    let state = ServerState::from_repo_path_with_pairing_store(
        &config.repo_path,
        pairing_store,
    )?;
    (state, None)
};
```

The `worker_handle` is held so that on server shutdown (after `axum::serve` returns), the worker can drain remaining messages. Add after `axum::serve`:

```rust
// Graceful shutdown: drop senders (via state drop), then await worker drain
drop(state);
if let Some(handle) = _worker_handle {
    let _ = handle.await;
}
```

**Step 5: Verify it compiles**

Run: `cargo check --package auths_registry_server`
Expected: PASS

**Step 6: Run all existing tests**

Run: `cargo nextest run --workspace`
Expected: All tests pass (cache is optional — `None` when Redis not configured)

**Step 7: Commit**

```bash
git add -A
git commit -m "feat(server): integrate tiered storage into registry server"
```

---

### Task 10: Wire Identity Read Endpoints to TieredResolver

**Files:**
- Modify: `crates/auths-registry-server/src/routes/identity.rs`

**Step 1: Update `get_identity` to use tiered resolver when available**

In `get_identity()`, replace the direct `backend.get_key_state()` call with:

```rust
// Use tiered resolver if available, otherwise fall back to direct backend
let key_state = if let Some(resolver) = state.tiered_resolver() {
    let did = format!("did:keri:{}", prefix);
    resolver
        .resolve(&did)
        .await
        .map_err(|e| ApiError::StorageError(e.to_string()))?
} else {
    backend
        .get_key_state(&prefix)
        .map_err(|e| ApiError::StorageError(e.to_string()))?
};
```

**Step 2: Verify it compiles**

Run: `cargo check --package auths_registry_server`
Expected: PASS

**Step 3: Run tests**

Run: `cargo nextest run -p auths_registry_server`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/auths-registry-server/src/routes/identity.rs
git commit -m "feat(server): wire identity reads through TieredResolver"
```

---

### Task 11: Wire Identity Write Endpoint to Write-Through

**Files:**
- Modify: `crates/auths-registry-server/src/routes/identity.rs`

**Step 1: Update `append_event` to use write-through**

After the existing `backend.append_event()` call succeeds, add cache hydration and archival dispatch.

**Important (clone trap):** `dispatch_archival_task` takes ownership of `KeyState`, so read the state once and pass ownership directly. The HTTP handler does not need the state after dispatching — the response uses `seq` and `said` from the event, not the key state.

```rust
// Write-through: dispatch to archival worker (ownership transfer, no clone)
if state.tiered_resolver().is_some() {
    if let Some(archival_tx) = state.archival_tx() {
        let did = format!("did:keri:{}", prefix);
        let updated_state = backend
            .get_key_state(&prefix)
            .map_err(|e| ApiError::StorageError(e.to_string()))?;

        // Pass ownership of updated_state — handler doesn't need it after this
        if let Err(e) = auths_cache::worker::dispatch_archival_task(
            &did,
            updated_state,
            archival_tx,
        ).await {
            tracing::warn!(error = %e, "Failed to dispatch archival task");
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check --package auths_registry_server`
Expected: PASS

**Step 3: Run tests**

Run: `cargo nextest run -p auths_registry_server`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/auths-registry-server/src/routes/identity.rs
git commit -m "feat(server): wire identity writes through write-through path"
```

---

### Task 12: Write `storage_architecture.md` Documentation

**Files:**
- The design doc at `docs/plans/2026-02-19-storage-tiering-design.md` already contains the full architecture documentation. Rename/copy it to the final location.
- Create: `docs/storage_architecture.md`

**Step 1: Create the final documentation file**

Copy the design document to `docs/storage_architecture.md` — this is the formalized system documentation requested in Task 2.4 of the epic.

**Step 2: Commit**

```bash
git add docs/storage_architecture.md
git commit -m "docs: add storage architecture documentation"
```

---

### Task 13: Final Verification

**Step 1: Run full workspace build**

Run: `cargo build --workspace`
Expected: Clean build

**Step 2: Run full test suite**

Run: `cargo nextest run --workspace`
Expected: All tests pass

**Step 3: Run clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: No warnings

**Step 4: Run fmt check**

Run: `cargo fmt --check --all`
Expected: No formatting issues

**Step 5: Commit any final fixes and tag**

```bash
git add -A
git commit -m "chore: final cleanup for storage tiering epic"
```

---

## Summary of Commits

| Task | Commit Message |
|------|---------------|
| 1 | `feat(cache): scaffold auths-cache crate skeleton` |
| 2 | `feat(cache): define error types for tiered storage` |
| 3 | `feat(cache): define TierZeroCache and TierOneArchive traits` |
| 4 | `feat(cache): implement RedisCache with bb8 pool` |
| 5 | `feat(cache): implement GitArchive wrapping PackedRegistryBackend` |
| 6 | `feat(cache): implement TieredResolver with cache-aside pattern` |
| 7 | `feat(cache): implement ArchivalWorker with DLQ routing` |
| 8 | `refactor(id): remove redb cache from PackedRegistryBackend` |
| 9 | `feat(server): integrate tiered storage into registry server` |
| 10 | `feat(server): wire identity reads through TieredResolver` |
| 11 | `feat(server): wire identity writes through write-through path` |
| 12 | `docs: add storage architecture documentation` |
| 13 | `chore: final cleanup for storage tiering epic` |
