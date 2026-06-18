//! Pluggable storage behind the relay's HTTP surface.
//!
//! Two backends, one async API:
//! - [`MemoryStore`] — the in-memory [`MailboxStore`] + a prekey map. The dev/hermetic
//!   default (the 13-leg `serve` self-test and the `NET-1` probe drive it). No durability.
//! - [`RedisStore`] — a durable, shared backlog in Redis so a relay restart loses nothing
//!   and many stateless relay processes share one store. Production.
//!
//! The relay stays *untrusted*: both backends only ever hold an opaque mailbox id and
//! opaque ciphertext — never plaintext, a sender AID, or a phone number. Redis at rest is
//! opaque bytes keyed by AID-unlinkable mailbox handles.
//!
//! Backend selection is by config: no `MURMUR_RELAY_REDIS_URL` → [`MemoryStore`]; a URL →
//! [`RedisStore`]. See `docs/PRD-durable-relay.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use murmur_core::{
    DepositOutcome, MailboxId, MailboxStore, OuterEnvelope, RelayLimits, RelayRequest,
};
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};

/// Why a store operation could not complete. Mapped to an HTTP status by the handlers —
/// always **fail-closed**: a deposit that could not be durably stored is never answered
/// `queued`, so the sender's outbox keeps and retries it.
#[derive(Debug)]
pub enum StoreError {
    /// The backend is unreachable (connection dropped/refused, timeout, IO). → `503`.
    Unavailable(String),
    /// The backend is at its memory cap and refused the write (Redis OOM). → `507`.
    OutOfMemory(String),
    /// A backend/protocol error we did not expect. → `500`.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unavailable(s) => write!(f, "store unavailable: {s}"),
            StoreError::OutOfMemory(s) => write!(f, "store out of memory: {s}"),
            StoreError::Backend(s) => write!(f, "store error: {s}"),
        }
    }
}

/// Tunable relay configuration, read from the environment (defaults match the in-memory
/// store so behavior is unchanged when nothing is set).
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// `redis://[:pass@]host:port[/db]` or `rediss://…` (TLS). `None` → in-memory.
    pub redis_url: Option<String>,
    /// Sliding TTL (seconds) on a mailbox's queue — an undrained backlog expires this long
    /// after its last deposit.
    pub msg_ttl_secs: u64,
    /// How long (seconds) a per-mailbox dedup window survives after its last deposit.
    pub dedup_ttl_secs: u64,
    /// How many recent fingerprints the per-mailbox dedup window keeps (a count-bounded
    /// sliding window, like the in-memory backend). Small by default since the authoritative
    /// dedup is app-side by `message_id`; ≤128 keeps the zset listpack-compact.
    pub dedup_window: usize,
    /// Published prekey-bundle TTL (seconds); the app republishes on launch.
    pub prekey_ttl_secs: u64,
    /// Per-mailbox cap on undrained messages.
    pub max_msgs_per_mailbox: usize,
    /// Per-mailbox cap on undrained ciphertext bytes.
    pub max_bytes_per_mailbox: usize,
    /// Key namespace (test isolation / multi-tenant). Default `mr`.
    pub key_prefix: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        let limits = RelayLimits::default();
        RelayConfig {
            redis_url: None,
            msg_ttl_secs: 30 * 24 * 60 * 60,
            dedup_ttl_secs: 24 * 60 * 60,
            dedup_window: 128,
            prekey_ttl_secs: 30 * 24 * 60 * 60,
            max_msgs_per_mailbox: limits.max_messages_per_mailbox,
            max_bytes_per_mailbox: limits.max_bytes_per_mailbox,
            key_prefix: "mr".to_string(),
        }
    }
}

impl RelayConfig {
    /// Read config from the environment, falling back to the defaults.
    pub fn from_env() -> Self {
        let d = RelayConfig::default();
        fn env_u64(key: &str, default: u64) -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        fn env_usize(key: &str, default: usize) -> usize {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        RelayConfig {
            redis_url: std::env::var("MURMUR_RELAY_REDIS_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            msg_ttl_secs: env_u64("MURMUR_RELAY_MSG_TTL_SECS", d.msg_ttl_secs),
            dedup_ttl_secs: env_u64("MURMUR_RELAY_DEDUP_TTL_SECS", d.dedup_ttl_secs),
            dedup_window: env_usize("MURMUR_RELAY_DEDUP_WINDOW", d.dedup_window),
            prekey_ttl_secs: env_u64("MURMUR_RELAY_PREKEY_TTL_SECS", d.prekey_ttl_secs),
            max_msgs_per_mailbox: env_usize(
                "MURMUR_RELAY_MAX_MSGS_PER_MAILBOX",
                d.max_msgs_per_mailbox,
            ),
            max_bytes_per_mailbox: env_usize(
                "MURMUR_RELAY_MAX_BYTES_PER_MAILBOX",
                d.max_bytes_per_mailbox,
            ),
            key_prefix: std::env::var("MURMUR_RELAY_KEY_PREFIX")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or(d.key_prefix),
        }
    }
}

/// The largest prekey bundle the directory will store (a few keys + a signature).
pub const MAX_PREKEY_BYTES: usize = 8 * 1024;

/// The storage backend behind the relay. Cheaply cloneable (handles/Arcs inside).
#[derive(Clone)]
pub enum RelayStore {
    Memory(MemoryStore),
    Redis(RedisStore),
}

impl RelayStore {
    /// A fresh in-memory store (dev / hermetic / tests).
    pub fn memory() -> Self {
        RelayStore::Memory(MemoryStore::new())
    }

    /// Build the backend from config: a Redis URL → connect and use Redis (fail-fast if
    /// the first connection fails); otherwise in-memory.
    pub async fn from_config(cfg: RelayConfig) -> Result<Self, String> {
        match &cfg.redis_url {
            Some(url) => Ok(RelayStore::Redis(
                RedisStore::connect(url, cfg.clone()).await?,
            )),
            None => Ok(RelayStore::memory()),
        }
    }

    /// A short label for the boot banner.
    pub fn label(&self) -> &'static str {
        match self {
            RelayStore::Memory(_) => "in-memory (no durability)",
            RelayStore::Redis(_) => "redis (durable)",
        }
    }

    pub async fn deposit(&self, env: &OuterEnvelope) -> Result<DepositOutcome, StoreError> {
        match self {
            RelayStore::Memory(m) => Ok(m.deposit(env)),
            RelayStore::Redis(r) => r.deposit(env).await,
        }
    }

    pub async fn drain(&self, mailbox: &str) -> Result<Vec<OuterEnvelope>, StoreError> {
        match self {
            RelayStore::Memory(m) => Ok(m.drain(mailbox)),
            RelayStore::Redis(r) => r.drain(mailbox).await,
        }
    }

    pub async fn put_prekey(&self, aid: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        match self {
            RelayStore::Memory(m) => {
                m.put_prekey(aid, bytes);
                Ok(())
            }
            RelayStore::Redis(r) => r.put_prekey(aid, bytes).await,
        }
    }

    pub async fn get_prekey(&self, aid: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match self {
            RelayStore::Memory(m) => Ok(m.get_prekey(aid)),
            RelayStore::Redis(r) => r.get_prekey(aid).await,
        }
    }

    /// Liveness of the backend (Redis: `PING`). In-memory is always healthy.
    pub async fn health(&self) -> Result<(), StoreError> {
        match self {
            RelayStore::Memory(_) => Ok(()),
            RelayStore::Redis(r) => r.health().await,
        }
    }
}

/// The in-memory backend — today's behavior, unchanged. No durability across restarts.
#[derive(Clone)]
pub struct MemoryStore {
    store: Arc<Mutex<MailboxStore>>,
    prekeys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore {
            store: Arc::new(Mutex::new(MailboxStore::new())),
            prekeys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn deposit(&self, env: &OuterEnvelope) -> DepositOutcome {
        self.store
            .lock()
            .expect("relay store poisoned")
            .deposit(env)
    }

    fn drain(&self, mailbox: &str) -> Vec<OuterEnvelope> {
        self.store
            .lock()
            .expect("relay store poisoned")
            .handle(&RelayRequest::Drain(MailboxId::new(mailbox)))
    }

    fn put_prekey(&self, aid: &str, bytes: Vec<u8>) {
        self.prekeys
            .lock()
            .expect("prekey directory poisoned")
            .insert(aid.to_string(), bytes);
    }

    fn get_prekey(&self, aid: &str) -> Option<Vec<u8>> {
        self.prekeys
            .lock()
            .expect("prekey directory poisoned")
            .get(aid)
            .cloned()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        MemoryStore::new()
    }
}

/// Atomic deposit (dedup → quota → queue) as one Lua script — so concurrent deposits to a
/// mailbox cannot race the quota or double-count.
///
/// Dedup is a **single per-mailbox bounded sorted-set** (`s`), not one TTL'd key per
/// message: ZADD the binary fingerprint scored by arrival, keep only the newest
/// `dedup_window` (ZREMRANGEBYRANK). This restores the in-memory backend's bounded sliding
/// window, costs one compact (listpack) key per mailbox instead of ~185 B/message, and a
/// replay after a drain is still dropped while it's in the window. The authoritative dedup
/// is app-side by `message_id`; this is the cheap network-replay guard.
///
/// KEYS = [queue, bytes, dedup_zset]; ARGV = [payload, size, fp, score, max_msgs,
/// max_bytes, msg_ttl_ms, dedup_window, dedup_ttl_ms]. Returns the outcome.
const DEPOSIT_LUA: &str = r#"
local q = KEYS[1]
local b = KEYS[2]
local s = KEYS[3]
local payload = ARGV[1]
local size = tonumber(ARGV[2])
local fp = ARGV[3]
local score = tonumber(ARGV[4])
local max_msgs = tonumber(ARGV[5])
local max_bytes = tonumber(ARGV[6])
local msg_ttl_ms = tonumber(ARGV[7])
local dedup_window = tonumber(ARGV[8])
local dedup_ttl_ms = tonumber(ARGV[9])
if redis.call('ZSCORE', s, fp) then
  return 'deduped'
end
local n = redis.call('LLEN', q)
local mb = tonumber(redis.call('GET', b) or '0')
if n >= max_msgs or (mb + size) > max_bytes then
  return 'quota'
end
redis.call('RPUSH', q, payload)
redis.call('INCRBY', b, size)
redis.call('ZADD', s, score, fp)
redis.call('ZREMRANGEBYRANK', s, 0, -dedup_window - 1)
redis.call('PEXPIRE', q, msg_ttl_ms)
redis.call('PEXPIRE', b, msg_ttl_ms)
redis.call('PEXPIRE', s, dedup_ttl_ms)
return 'queued'
"#;

/// Atomic drain (return all + delete the queue and its byte counter). The dedup keys are
/// NOT cleared, so a replay after a drain is still dropped within the dedup horizon.
/// KEYS = [queue, bytes]. Returns the list of JSON envelopes.
const DRAIN_LUA: &str = r#"
local q = KEYS[1]
local b = KEYS[2]
local items = redis.call('LRANGE', q, 0, -1)
if #items > 0 then
  redis.call('DEL', q)
  redis.call('DEL', b)
end
return items
"#;

/// The durable Redis backend. Cloneable (the `ConnectionManager` is a cheap, multiplexed,
/// auto-reconnecting handle shared across clones).
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
    cfg: Arc<RelayConfig>,
    deposit: Arc<redis::Script>,
    drain: Arc<redis::Script>,
}

impl RedisStore {
    /// Connect (and **fail fast** if Redis is unreachable — the relay should crash-loop on a
    /// dead Redis, not serve 503s forever). `ConnectionManager` retries in the background, so
    /// a one-shot bounded preflight ping is what makes startup deterministic.
    pub async fn connect(url: &str, cfg: RelayConfig) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("redis url: {e}"))?;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut c = client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| format!("redis connect: {e}"))?;
            let pong: String = redis::cmd("PING")
                .query_async(&mut c)
                .await
                .map_err(|e| format!("redis ping: {e}"))?;
            if pong == "PONG" {
                Ok(())
            } else {
                Err(format!("unexpected PING reply: {pong}"))
            }
        })
        .await
        .map_err(|_| "redis preflight timed out".to_string())??;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| format!("redis connect: {e}"))?;
        Ok(RedisStore {
            conn,
            cfg: Arc::new(cfg),
            deposit: Arc::new(redis::Script::new(DEPOSIT_LUA)),
            drain: Arc::new(redis::Script::new(DRAIN_LUA)),
        })
    }

    // Hash-tagged keys: every key for a mailbox shares the `{<mbx>}` tag so one multi-key
    // Lua script stays in a single Redis Cluster slot.
    fn qkey(&self, mbx: &str) -> String {
        format!("{}:{{{}}}:q", self.cfg.key_prefix, mbx)
    }
    fn bkey(&self, mbx: &str) -> String {
        format!("{}:{{{}}}:b", self.cfg.key_prefix, mbx)
    }
    /// The per-mailbox dedup sorted-set (one key per mailbox, not per message).
    fn skey(&self, mbx: &str) -> String {
        format!("{}:{{{}}}:s", self.cfg.key_prefix, mbx)
    }
    fn pkkey(&self, aid: &str) -> String {
        format!("{}:{{{}}}:pk", self.cfg.key_prefix, aid)
    }

    async fn deposit(&self, env: &OuterEnvelope) -> Result<DepositOutcome, StoreError> {
        let mbx = env.to_mailbox.as_str();
        let fp = fingerprint(&env.ciphertext); // raw 16-byte truncated SHA-256
        // Store the RAW ciphertext (the mailbox is the key); no JSON/redundant mailbox.
        let size = env.ciphertext.len();
        let score = now_millis(); // arrival order for the bounded dedup window
        let mut conn = self.conn.clone();
        let outcome: String = self
            .deposit
            .key(self.qkey(mbx))
            .key(self.bkey(mbx))
            .key(self.skey(mbx))
            .arg(env.ciphertext.as_slice())
            .arg(size)
            .arg(fp.as_slice())
            .arg(score)
            .arg(self.cfg.max_msgs_per_mailbox)
            .arg(self.cfg.max_bytes_per_mailbox)
            .arg(self.cfg.msg_ttl_secs.saturating_mul(1000))
            .arg(self.cfg.dedup_window)
            .arg(self.cfg.dedup_ttl_secs.saturating_mul(1000))
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        match outcome.as_str() {
            "queued" => Ok(DepositOutcome::Queued),
            "deduped" => Ok(DepositOutcome::DedupedReplay),
            "quota" => Ok(DepositOutcome::QuotaExceeded),
            other => Err(StoreError::Backend(format!(
                "unexpected deposit result: {other}"
            ))),
        }
    }

    async fn drain(&self, mailbox: &str) -> Result<Vec<OuterEnvelope>, StoreError> {
        let mut conn = self.conn.clone();
        // Each list element is the raw ciphertext; rebuild the envelope with the mailbox
        // from the key (binary-safe `Vec<u8>` items, not strings).
        let items: Vec<Vec<u8>> = self
            .drain
            .key(self.qkey(mailbox))
            .key(self.bkey(mailbox))
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        Ok(items
            .into_iter()
            .map(|ciphertext| OuterEnvelope {
                to_mailbox: MailboxId::new(mailbox),
                ciphertext,
            })
            .collect())
    }

    async fn put_prekey(&self, aid: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        redis::cmd("SET")
            .arg(self.pkkey(aid))
            .arg(bytes)
            .arg("EX")
            .arg(self.cfg.prekey_ttl_secs)
            .query_async::<()>(&mut conn)
            .await
            .map_err(map_redis_err)
    }

    async fn get_prekey(&self, aid: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let mut conn = self.conn.clone();
        redis::cmd("GET")
            .arg(self.pkkey(aid))
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
            .map_err(map_redis_err)
    }

    async fn health(&self) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err(StoreError::Backend(format!(
                "unexpected PING reply: {pong}"
            )))
        }
    }
}

/// `hex(SHA256(ciphertext))` — the same dedup fingerprint rule the in-memory store uses
/// (over the opaque ciphertext only, never the mailbox id or anything inside it).
/// The dedup fingerprint: the first 16 bytes (128 bits) of `SHA-256(ciphertext)`, raw (not
/// hex). 128 bits is collision-proof for a per-mailbox replay window, and raw bytes are half
/// the size of hex. Over the opaque ciphertext only — never the mailbox id or its contents.
fn fingerprint(ciphertext: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(ciphertext);
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&digest[..16]);
    fp
}

/// Milliseconds since the Unix epoch (the relay's clock) — the arrival score for the
/// bounded dedup window. Monotonic enough for "keep the newest N"; ties are harmless.
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Map a Redis error to a fail-closed [`StoreError`] — OOM is distinguished (so the relay
/// can answer `507`), connection/IO failures are `Unavailable` (`503`).
fn map_redis_err(e: redis::RedisError) -> StoreError {
    if e.code() == Some("OOM") {
        return StoreError::OutOfMemory(e.to_string());
    }
    if matches!(e.kind(), redis::ErrorKind::IoError)
        || e.is_connection_dropped()
        || e.is_connection_refusal()
        || e.is_timeout()
    {
        return StoreError::Unavailable(e.to_string());
    }
    StoreError::Backend(e.to_string())
}
