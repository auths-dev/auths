 Unified Storage Architecture: Ports & Adapters Refactor

 Context

 The Auths codebase has organic storage fragmentation:
 - auth-server and chat-server resolve identities via HTTP (RegistryIdentityResolver) on every request - no caching
 - WitnessStorage (auths-core/src/witness/storage.rs) is a concrete SQLite struct with no trait abstraction
 - SQLite stores across servers duplicate connection init, WAL pragma setup, and error mapping patterns
 - A redb cache (auths-id/src/storage/registry/cache.rs) already exists with population logic and read-through methods, but
  isn't exposed as a port trait
 - The ReceiptStorage trait exists in auths-id but isn't integrated with the witness verification flow
 - All three servers already use a ports/adapters directory structure, but the trait definitions are server-local (not
 shared)

 This refactor unifies these into a strict Hexagonal Architecture where application logic depends only on domain traits
 (ports), and storage technologies (SQLite, redb, Git) are contained entirely within adapter implementations.

 ---
 Phase 1: Define Unified Port Traits

 1.1 Create IdentityCachePort trait in auths-id/src/storage/registry/

 File: crates/auths-id/src/storage/registry/cache_port.rs

 /// Port for O(1) identity and KEL lookups.
 ///
 /// Implementations may be backed by redb (local cache), HTTP (remote registry),
 /// or in-memory (testing). The cache is a derived view - it can be rebuilt
 /// from the authoritative Git KEL at any time.
 #[async_trait]
 pub trait IdentityCachePort: Send + Sync {
     /// Get the current key state for an identity prefix.
     async fn get_key_state(&self, prefix: &str) -> Result<Option<KeyState>, CachePortError>;

     /// Get tip info (sequence number, SAID) for an identity.
     async fn get_tip(&self, prefix: &str) -> Result<Option<TipInfo>, CachePortError>;

     /// Get a device attestation by device DID.
     async fn get_attestation(&self, device_did: &str) -> Result<Option<Attestation>, CachePortError>;

     /// Get a single KEL event by prefix and sequence number.
     async fn get_event(&self, prefix: &str, seq: u64) -> Result<Option<Event>, CachePortError>;

     /// Ensure the cache is fresh (rebuild from source if stale).
     async fn ensure_fresh(&self) -> Result<(), CachePortError>;
 }

 Also define CachePortError with variants: NotFound, Stale, Internal.

 Re-export from crates/auths-id/src/storage/registry/mod.rs.

 1.2 Create WitnessStorePort trait in auths-core/src/witness/

 File: crates/auths-core/src/witness/witness_port.rs

 Extract the existing WitnessStorage methods into a trait:

 /// Port for witness duplicity detection and receipt storage.
 ///
 /// Implementations track first-seen events per (prefix, seq) to detect
 /// equivocation, and store/retrieve witness receipts.
 pub trait WitnessStorePort: Send + Sync {
     fn record_first_seen(&self, prefix: &str, seq: u64, said: &str) -> Result<(), WitnessError>;
     fn get_first_seen(&self, prefix: &str, seq: u64) -> Result<Option<String>, WitnessError>;
     fn check_duplicity(&self, prefix: &str, seq: u64, said: &str) -> Result<Option<String>, WitnessError>;
     fn store_receipt(&self, prefix: &str, receipt: &Receipt) -> Result<(), WitnessError>;
     fn get_receipt(&self, prefix: &str, event_said: &str) -> Result<Option<Receipt>, WitnessError>;
     fn get_latest_seq(&self, prefix: &str) -> Result<Option<u64>, WitnessError>;
 }

 Then impl WitnessStorePort for WitnessStorage - the existing concrete struct becomes the SQLite adapter.

 1.3 Create shared IdentityResolver trait in auths-core (or a new auths-ports module)

 File: crates/auths-core/src/identity/resolver.rs (new module)

 Currently IdentityResolver is defined independently in both auths-auth-server/src/ports/identity_resolver.rs and
 auths-chat-server/src/adapters/registry_resolver.rs. Unify into a single shared trait:

 /// Resolves the current signing public key for a DID.
 ///
 /// This is the shared interface consumed by edge servers for identity
 /// verification. Implementations may be HTTP-based (remote registry),
 /// redb-based (local cache), or in-memory (testing).
 #[async_trait]
 pub trait IdentityResolver: Send + Sync {
     async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError>;
 }

 Move ResolveError here too, since both servers define identical copies.

 1.4 No new EphemeralStorePort or AuthoritativeStorePort

 The existing server-local traits (SessionStore, MessageStore, UserStore, PairingStore) are domain-specific and correctly
 scoped to their respective servers. Abstracting them further into a generic "EphemeralStorePort" would lose type safety
 without meaningful reuse. Instead, we'll share the infrastructure patterns (connection init, error mapping) via helper
 functions (Phase 3).

 The RegistryBackend trait already serves as the authoritative store port - it's well-defined, frozen, and used correctly.

 ---
 Phase 2: Build the redb Adapter for IdentityCachePort

 2.1 Implement IdentityCachePort on RegistryCache

 File: crates/auths-id/src/storage/registry/cache_port.rs (extend)

 The existing RegistryCache in cache.rs already has all the read methods (get_key_state, get_tip, get_attestation,
 get_event) and population logic (populate_from). Wrap it to implement the new port trait:

 /// redb-backed implementation of IdentityCachePort.
 ///
 /// Wraps RegistryCache with a reference to the authoritative backend
 /// for automatic refresh on cache miss.
 pub struct RedbIdentityCache {
     cache: RegistryCache,
     backend: Arc<PackedRegistryBackend>,
     repo_path: PathBuf,
 }

 - ensure_fresh() checks is_valid_for() against current Git ref OID, calls populate_from() if stale
 - Read methods delegate to RegistryCache methods, falling back to backend on cache miss
 - All async methods use spawn_blocking since redb is synchronous

 2.2 Implement IdentityResolver for RedbIdentityCache

 File: crates/auths-id/src/storage/registry/cache_port.rs (or separate file)

 Implement the shared IdentityResolver trait on RedbIdentityCache:

 impl IdentityResolver for RedbIdentityCache {
     async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
         // Extract prefix from did:keri:EPREFIX
         // Call self.get_key_state(prefix)
         // Parse KERI key format (D + base64url) -> raw 32 bytes
     }
 }

 This is the critical piece: edge servers can now resolve identities from the local redb cache instead of making HTTP calls
  to the registry server.

 ---
 Phase 3: Unify SQLite Infrastructure Patterns

 3.1 Create shared SQLite helpers in auths-core

 File: crates/auths-core/src/storage/sqlite_helpers.rs (new)

 Extract the duplicated patterns into reusable functions:

 /// Open a SQLite connection with standard configuration.
 ///
 /// Enables WAL mode for concurrent reads and sets recommended pragmas.
 pub fn open_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
     let conn = Connection::open(path)?;
     conn.pragma_update(None, "journal_mode", "WAL")?;
     Ok(conn)
 }

 /// Open an in-memory SQLite connection (for testing).
 pub fn open_in_memory() -> Result<Connection, rusqlite::Error> {
     let conn = Connection::open_in_memory()?;
     Ok(conn)
 }

 3.2 Refactor existing SQLite adapters to use shared helpers

 Update these files to call the shared helpers instead of duplicating WAL setup:
 - ~~crates/auths-auth-server/src/adapters/sqlite_session_store.rs~~ — **REMOVED**: auth-server migrated to PostgreSQL (`postgres_session_store.rs`); no longer uses SQLite.
 - crates/auths-chat-server/src/adapters/sqlite_store.rs
 - crates/auths-registry-server/src/adapters/sqlite_pairing_store.rs
 - crates/auths-core/src/witness/storage.rs

 The schema creation and query logic stays in each adapter (domain-specific), but connection initialization is DRY.

 ---
 Phase 4: Implement Witness Storage Port Integration

 4.1 Add WitnessStorePort trait and implement on WitnessStorage

 As described in Phase 1.2. The existing WitnessStorage struct becomes the SQLite adapter implementation.

 File: crates/auths-core/src/witness/mod.rs - add pub mod witness_port; and re-export the trait.

 4.2 Hook witness verification into registry event flow

 File: crates/auths-registry-server/src/routes/identity.rs (modify append_kel_event)

 Before accepting an event into the registry:
 1. Check WitnessStorePort::check_duplicity() for the (prefix, seq, said) tuple
 2. If duplicity detected, reject with ApiError::DuplicityDetected
 3. If configured witness threshold > 0, check ReceiptStorage::has_quorum()
 4. Record the event via WitnessStorePort::record_first_seen()

 The WitnessStorePort is injected into ServerState (Phase 5).

 ---
 Phase 5: Dependency Injection & Server Refactoring

 5.1 Update ServerState in auths-registry-server

 File: crates/auths-registry-server/src/lib.rs

 Add witness store to state:

 struct ServerStateInner {
     // ... existing fields ...
     witness_store: Arc<dyn WitnessStorePort>,
     identity_cache: Arc<dyn IdentityCachePort>,  // optional, for cache-accelerated reads
 }

 Update factory methods to accept injected dependencies.

 5.2 Update AuthServerState in auths-auth-server

 File: crates/auths-auth-server/src/lib.rs

 Change IdentityResolver to use the shared trait from auths-core:

 struct AuthServerStateInner {
     resolver: Box<dyn auths_core::identity::IdentityResolver>,  // shared trait
     sessions: Box<dyn SessionStore>,
     config: AuthServerConfig,
 }

 5.3 Update ChatServerState in auths-chat-server

 File: crates/auths-chat-server/src/lib.rs

 Same change - use the shared IdentityResolver trait.

 5.4 Update main.rs files with flexible DI

 Auth-server main.rs:
 // Can now choose between HTTP resolver (existing) or redb cache (new)
 let resolver: Box<dyn IdentityResolver> = if let Some(cache_path) = &config.cache_path {
     Box::new(RedbIdentityCache::open(cache_path, &repo_path)?)
 } else {
     Box::new(RegistryIdentityResolver::new(&config.registry_url))
 };

 Chat-server main.rs: Same pattern.

 Registry-server main.rs:
 let witness_store = Arc::new(WitnessStorage::open(&witness_db_path)?);
 let state = ServerState::from_repo_path_with_stores(
     &config.repo_path,
     pairing_store,
     witness_store,
 )?;

 ---
 Files to Create
 ┌────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┐
 │                        File                        │                       Purpose                       │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-id/src/storage/registry/cache_port.rs │ IdentityCachePort trait + RedbIdentityCache adapter │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-core/src/witness/witness_port.rs      │ WitnessStorePort trait                              │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-core/src/identity/resolver.rs         │ Shared IdentityResolver trait + ResolveError        │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-core/src/identity/mod.rs              │ Module declaration                                  │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-core/src/storage/sqlite_helpers.rs    │ Shared SQLite connection helpers                    │
 ├────────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
 │ crates/auths-core/src/storage/mod.rs               │ Module declaration (if not exists)                  │
 └────────────────────────────────────────────────────┴─────────────────────────────────────────────────────┘
 Files to Modify
 ┌───────────────────────────────────────────────────────────────────┬───────────────────────────────────────────────┐
 │                               File                                │                    Change                     │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-id/src/storage/registry/mod.rs                       │ Add pub mod cache_port; and re-exports        │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-core/src/witness/mod.rs                              │ Add pub mod witness_port; and re-export trait │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-core/src/witness/storage.rs                          │ impl WitnessStorePort for WitnessStorage      │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-core/src/lib.rs                                      │ Add pub mod identity; and pub mod storage;    │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/lib.rs                               │ Use shared IdentityResolver                   │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/ports/identity_resolver.rs           │ Re-export from auths-core (backward compat)   │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ ~~crates/auths-auth-server/src/adapters/sqlite_session_store.rs~~ │ REMOVED — replaced by postgres_session_store  │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-auth-server/Cargo.toml                               │ Add auths-core dependency                     │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-chat-server/src/lib.rs                               │ Use shared IdentityResolver                   │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-chat-server/src/adapters/sqlite_store.rs             │ Use shared sqlite_helpers                     │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-chat-server/src/adapters/registry_resolver.rs        │ Implement shared trait                        │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-registry-server/src/lib.rs                           │ Add witness_store to state, update factories  │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-registry-server/src/routes/identity.rs               │ Add witness check before event append         │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-registry-server/src/adapters/sqlite_pairing_store.rs │ Use shared sqlite_helpers                     │
 ├───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────┤
 │ crates/auths-registry-server/Cargo.toml                           │ Add auths-core witness dependency             │
 └───────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────┘
 Verification Plan

 1. Unit tests: cargo test --all - all existing tests must pass
 2. Build check: cargo build --all-targets - no compilation errors
 3. Clippy: cargo clippy --all-targets --all-features -- -D warnings
 4. Format: cargo fmt --check --all
 5. Specific crate tests:
   - cargo test --package auths-core - witness port tests
   - cargo test --package auths-id - cache port tests
   - cargo test --package auths-registry-server - integration tests with witness verification
 6. WASM check: cargo check --package auths_verifier --target wasm32-unknown-unknown --features wasm (ensure no
 regressions)

 Implementation Order

 1. Phase 1.3 (shared IdentityResolver in auths-core) - foundation trait
 2. Phase 1.2 (WitnessStorePort) - extract witness trait
 3. Phase 3.1 (SQLite helpers) - shared infra
 4. Phase 3.2 (refactor SQLite adapters) - DRY up existing code
 5. Phase 1.1 + Phase 2 (IdentityCachePort + RedbIdentityCache) - the big value add
 6. Phase 4 (witness integration) - security improvement
 7. Phase 5 (DI wiring) - connect everything
