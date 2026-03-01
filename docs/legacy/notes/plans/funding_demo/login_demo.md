 Login with Auths — Funding Demo

 Context

 Build a "Login with Auths" demo that proves un-phishable authentication via KERI identities. Three actors: a mock bank website
 (HTML+JS), an auth server (new Rust crate), and a mobile app (Swift via UniFFI). The auth server must properly resolve identity keys
 by fetching KELs from the registry server over HTTP — no shortcuts, no local Git access. Architecture follows ports/adapters for
 testability and clean separation of concerns.

 Why: This is the funding demo. It shows "scan QR code → FaceID → logged in" with cryptographic proof that the login cannot be phished,
  replayed, or MITM'd.

 ---
 Sequence Diagram

 Mobile App              Auth Server             Registry Server       Mock Bank (Browser)
     |                       |                        |                      |
     |                       |                        |              1. POST /auth/init
     |                       |<-----------------------------------------------|
     |                       |--- create challenge --->|                      |
     |                       |--- return {id, challenge, domain} ------------>|
     |                       |                        |              2. Render QR code
     |                       |                        |              3. Poll GET /auth/status/:id
     |  4. Scan QR code      |                        |                      |
     |  5. FaceID prompt     |                        |                      |
     |  6. Sign challenge    |                        |                      |
     |--- POST /auth/verify {id, did, sig, pk} ----->|                      |
     |                       |--- GET /v1/identities/:prefix/kel ----------->|
     |                       |<-- KEL events ------------------------------ -|
     |                       |--- verify KEL, extract current key            |
     |                       |--- verify sig(challenge) with key             |
     |                       |--- session.status = Verified                  |
     |<-- 200 OK ------------|                        |                      |
     |                       |                        |              7. Poll returns "verified"
     |                       |                        |              8. Show "Welcome, did:keri:..."

 ---
 Step 1: Create crates/auths-auth-server/ crate skeleton

 New crate with ports/adapters layout. Depends only on auths-verifier (not auths-id or auths-core) to prove the auth server can run
 without Git access.

 1a. Cargo.toml

 [package]
 name = "auths-auth-server"
 version = "0.0.1-rc.9"
 edition = "2024"
 publish = false

 [[bin]]
 name = "auths-auth-server"
 path = "src/main.rs"

 [lib]
 name = "auths_auth_server"
 path = "src/lib.rs"

 [dependencies]
 auths-verifier = { path = "../auths-verifier", version = "0.0.1-rc.9" }

 axum = "0.8"
 chrono = { version = "0.4", features = ["serde"] }
 hex = "0.4"
 json-canon = "0.1"
 reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
 ring = "0.17.14"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
 thiserror = "2"
 tokio = { version = "1", features = ["full"] }
 tower-http = { version = "0.6", features = ["trace", "cors", "fs"] }
 tracing = "0.1"
 tracing-subscriber = { version = "0.3", features = ["env-filter"] }
 uuid = { version = "1", features = ["v4"] }

 [dev-dependencies]
 tower = { version = "0.5", features = ["util"] }
 http-body-util = "0.1"

 1b. Add to workspace

 Edit Cargo.toml (workspace root) — add "crates/auths-auth-server" to the members list.

 1c. File layout

 crates/auths-auth-server/
   src/
     main.rs              # Binary entry point, env config, tracing
     lib.rs               # Re-exports: AuthServerState, run_server, config, error, routes
     config.rs            # AuthServerConfig { bind_addr, registry_url, challenge_ttl_secs }
     error.rs             # AuthApiError enum + IntoResponse (mirrors registry-server pattern)
     domain/
       mod.rs             # Re-exports
       types.rs           # AuthChallenge, AuthResponse, AuthSession, SessionStatus
     ports/
       mod.rs             # Re-exports
       identity_resolver.rs  # trait IdentityResolver { async fn resolve_current_key(did) -> Result<Vec<u8>> }
       session_store.rs      # trait SessionStore { create, get, update }
     adapters/
       mod.rs             # Re-exports
       registry_resolver.rs  # RegistryIdentityResolver — HTTP call to GET /v1/identities/:prefix
       memory_store.rs       # InMemorySessionStore — DashMap<Uuid, AuthSession>
     routes/
       mod.rs             # router() function
       init.rs            # POST /auth/init
       verify.rs          # POST /auth/verify
       status.rs          # GET /auth/status/:id
   static/
     index.html           # Mock bank UI (single file, inline JS)

 ---
 Step 2: Domain types (domain/types.rs)

 pub struct AuthChallenge {
     pub id: Uuid,
     pub nonce: String,           // 32 random bytes, hex-encoded
     pub domain: String,          // Origin domain (anti-phishing binding)
     pub created_at: DateTime<Utc>,
     pub expires_at: DateTime<Utc>,
 }

 pub enum SessionStatus {
     Pending,
     Verified { did: String, verified_at: DateTime<Utc> },
     Expired,
 }

 pub struct AuthSession {
     pub challenge: AuthChallenge,
     pub status: SessionStatus,
 }

 The challenge includes domain so the mobile app signs over nonce || domain, binding the signature to a specific origin. This is the
 anti-phishing mechanism.

 ---
 Step 3: Port traits

 3a. ports/identity_resolver.rs

 #[async_trait::async_trait]
 pub trait IdentityResolver: Send + Sync {
     /// Given a did:keri:EPREFIX, fetch the current signing public key.
     /// Returns the raw 32-byte Ed25519 public key.
     async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError>;
 }

 pub enum ResolveError {
     NotFound(String),
     RegistryUnavailable(String),
     InvalidKel(String),
 }

 3b. ports/session_store.rs

 pub trait SessionStore: Send + Sync {
     fn create(&self, session: AuthSession) -> Result<(), StoreError>;
     fn get(&self, id: &Uuid) -> Result<Option<AuthSession>, StoreError>;
     fn update_status(&self, id: &Uuid, status: SessionStatus) -> Result<(), StoreError>;
 }

 ---
 Step 4: Adapters

 4a. adapters/registry_resolver.rs — RegistryIdentityResolver

 This is the key piece that fetches KELs over HTTP. It:

 1. Parses the DID prefix from did:keri:EPREFIX
 2. Calls GET {registry_url}/v1/identities/{prefix} using reqwest
 3. Deserializes the IdentityResponse (which contains key_state.current_keys)
 4. Decodes the KERI key encoding ("D" + base64url → raw Ed25519 bytes)
 5. Returns the 32-byte public key

 Existing code to reuse: The registry server already has GET /v1/identities/:prefix that returns KeyStateResponse.current_keys
 (KERI-encoded). See crates/auths-registry-server/src/routes/identity.rs:74-100.

 The KERI key decoding ("D" prefix = Ed25519, base64url-encoded) is already understood by auths-verifier. We decode the first entry in
 current_keys.

 pub struct RegistryIdentityResolver {
     client: reqwest::Client,
     registry_url: String,  // e.g. "http://localhost:3000"
 }

 4b. adapters/memory_store.rs — InMemorySessionStore

 Uses DashMap<Uuid, AuthSession> for lock-free concurrent access. Matches the pattern used by PairingSessionStore in the registry
 server (crates/auths-registry-server/src/routes/pairing.rs).

 ---
 Step 5: Routes

 5a. POST /auth/init (routes/init.rs)

 Request: { "domain": "bank.example.com" } (optional — defaults to server's own domain)

 Logic:
 1. Generate Uuid::new_v4() as session ID
 2. Generate 32 random bytes → hex-encode as nonce
 3. Create AuthChallenge { id, nonce, domain, created_at, expires_at: now + ttl }
 4. Create AuthSession { challenge, status: Pending }
 5. Store in SessionStore

 Response: { "id": "uuid", "challenge": "hex-nonce", "domain": "bank.example.com", "expires_at": "ISO8601" }

 The mock bank renders this as a QR code: auths://auth?id={id}&c={challenge}&d={domain}&e={auth_server_url}

 5b. POST /auth/verify (routes/verify.rs)

 Request:
 {
   "id": "uuid",
   "did": "did:keri:EPREFIX",
   "signature": "hex-encoded-ed25519-sig",
   "public_key": "hex-encoded-32-byte-pk"
 }

 Logic:
 1. Look up session by ID → 404 if missing
 2. Check session not expired → 410 Gone if expired
 3. Check session is Pending → 409 Conflict if already verified
 4. Resolve identity via IdentityResolver::resolve_current_key(did)
 5. Compare resolved key with presented public_key → reject if mismatch
 6. Reconstruct signed payload: json_canon::to_string({ "nonce": challenge.nonce, "domain": challenge.domain })
 7. Verify signature against canonical bytes using ring::signature::UnparsedPublicKey
 8. Update session status to Verified { did, verified_at: now }

 Response: { "verified": true }

 Why step 5 matters: The auth server doesn't blindly trust the presented public key. It asks the registry "what is the current key for
 this DID?" and only accepts if they match. This prevents key impersonation.

 5c. GET /auth/status/:id (routes/status.rs)

 Response:
 {
   "id": "uuid",
   "status": "pending" | "verified" | "expired",
   "did": "did:keri:..." // only when verified
 }

 The mock bank polls this every 2 seconds.

 ---
 Step 6: Server state and wiring (lib.rs)

 pub struct AuthServerState {
     inner: Arc<AuthServerStateInner>,
 }

 struct AuthServerStateInner {
     resolver: Box<dyn IdentityResolver>,
     sessions: Box<dyn SessionStore>,
     config: AuthServerConfig,
 }

 Pattern mirrors ServerState in crates/auths-registry-server/src/lib.rs:78-93.

 The router() function in routes/mod.rs:
 - POST /auth/init → init::init_auth
 - POST /auth/verify → verify::verify_auth
 - GET /auth/status/:id → status::auth_status
 - GET / → serve static/index.html via tower_http::services::ServeDir
 - CORS enabled (browser needs to call these endpoints)
 - TraceLayer for request logging

 ---
 Step 7: Mock bank UI (static/index.html)

 Single HTML file with inline CSS and JS (~200 lines). No build step, no npm.

 States: idle → QR displayed → polling → success/expired

 Flow:
 1. User clicks "Login with Auths"
 2. JS calls POST /auth/init with { "domain": window.location.hostname }
 3. Receives { id, challenge, domain, expires_at }
 4. Renders QR code containing auths://auth?id={id}&c={challenge}&d={domain}&e={auth_server_url_base64}
 5. Starts polling GET /auth/status/{id} every 2 seconds
 6. On "verified" → shows "Welcome, {did}" with green checkmark
 7. On timeout → shows "Session expired, try again"

 QR code rendered via <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js">.

 ---
 Step 8: Mobile FFI addition (crates/auths-mobile-ffi/src/lib.rs)

 Add new UniFFI-exported function for signing auth challenges.

 8a. New types

 #[derive(Debug, uniffi::Record)]
 pub struct AuthChallengeInput {
     pub nonce: String,    // hex-encoded challenge nonce
     pub domain: String,   // domain from QR code
 }

 #[derive(Debug, uniffi::Record)]
 pub struct SignedAuthChallenge {
     pub signature_hex: String,     // Ed25519 signature of canonical JSON
     pub public_key_hex: String,    // 32-byte public key
     pub did: String,               // did:keri:... from identity
 }

 8b. New function

 #[uniffi::export]
 pub fn sign_auth_challenge(
     current_key_pkcs8_hex: String,
     identity_did: String,
     challenge: AuthChallengeInput,
 ) -> Result<SignedAuthChallenge, MobileError>

 Logic:
 1. Decode PKCS8 hex → Ed25519KeyPair
 2. Build canonical payload: json_canon::to_string({ "nonce": challenge.nonce, "domain": challenge.domain })
 3. Sign canonical bytes
 4. Extract public key from keypair
 5. Return SignedAuthChallenge { signature_hex, public_key_hex, did: identity_did }

 New dependency: Add json-canon = "0.1" to crates/auths-mobile-ffi/Cargo.toml.

 The existing sign_with_identity() function (lib.rs:329-341) signs raw bytes. The new function adds canonical JSON construction so
 mobile and server agree on the exact bytes being signed.

 8c. Swift integration (AuthLoginService.swift — reference only)

 The Swift side (not in this repo, lives in the iOS app) would:
 1. Parse QR code → extract id, challenge, domain, auth_server_url
 2. Prompt FaceID
 3. Load PKCS8 key from Keychain
 4. Call signAuthChallenge(currentKeyPkcs8Hex:, identityDid:, challenge:)
 5. POST to {auth_server_url}/auth/verify with { id, did, signature, public_key }

 ---
 Step 9: main.rs — binary entry point

 Pattern mirrors crates/auths-registry-server/src/main.rs.

 Env vars:
 - AUTH_SERVER_BIND (default 0.0.0.0:3001 — different port from registry)
 - AUTH_SERVER_REGISTRY_URL (default http://localhost:3000)
 - AUTH_SERVER_CHALLENGE_TTL (default 300 seconds)
 - AUTH_SERVER_LOG_LEVEL (default info)

 ---
 Step 10: Integration tests

 Using tower::ServiceExt::oneshot() pattern from the registry server (dev-dependencies in
 crates/auths-registry-server/Cargo.toml:48-50).

 Test: Full auth flow with mock resolver

 #[tokio::test]
 async fn test_full_auth_flow() {
     // 1. Create state with MockIdentityResolver (returns known key)
     // 2. POST /auth/init → get challenge
     // 3. Sign challenge with Ed25519 keypair
     // 4. POST /auth/verify → expect 200
     // 5. GET /auth/status/:id → expect "verified"
 }

 Test: Reject wrong key

 #[tokio::test]
 async fn test_reject_wrong_key() {
     // MockResolver returns key A, but request presents key B → 422
 }

 Test: Expired session

 #[tokio::test]
 async fn test_expired_session() {
     // Create session with TTL=0 → immediate expiry → POST /auth/verify → 410
 }

 MockIdentityResolver

 struct MockIdentityResolver {
     keys: HashMap<String, Vec<u8>>,
 }

 #[async_trait]
 impl IdentityResolver for MockIdentityResolver {
     async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
         self.keys.get(did).cloned().ok_or(ResolveError::NotFound(did.to_string()))
     }
 }

 ---
 Files Summary
 ┌────────────────────────────────────────────────────────────┬──────────────────────────────────────────────────┐
 │                            File                            │                      Action                      │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ Cargo.toml (workspace)                                     │ Edit — add "crates/auths-auth-server" to members │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/Cargo.toml                        │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/main.rs                       │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/lib.rs                        │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/config.rs                     │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/error.rs                      │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/domain/mod.rs                 │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/domain/types.rs               │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/ports/mod.rs                  │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/ports/identity_resolver.rs    │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/ports/session_store.rs        │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/adapters/mod.rs               │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/adapters/registry_resolver.rs │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/adapters/memory_store.rs      │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/routes/mod.rs                 │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/routes/init.rs                │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/routes/verify.rs              │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/src/routes/status.rs              │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-auth-server/static/index.html                 │ Create                                           │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-mobile-ffi/src/lib.rs                         │ Edit — add sign_auth_challenge() + types         │
 ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
 │ crates/auths-mobile-ffi/Cargo.toml                         │ Edit — add json-canon = "0.1" + serde_json       │
 └────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────┘
 Total: 19 new files, 2 edited files.

 ---
 Implementation Sequence

 Phase A — Auth server crate (Steps 1-6, 9):
 1. Create crate skeleton + Cargo.toml + workspace member
 2. Domain types
 3. Port traits
 4. Error types + config
 5. InMemorySessionStore adapter
 6. RegistryIdentityResolver adapter
 7. Route handlers (init, verify, status)
 8. Router + state wiring + main.rs

 Phase B — Mock bank + Mobile FFI (Steps 7-8):
 1. Static HTML mock bank
 2. Mobile FFI sign_auth_challenge() function

 Phase C — Tests (Step 10):
 1. Integration tests with MockIdentityResolver
 2. cargo test -p auths-auth-server
 3. cargo build -p auths-auth-server

 ---
 Verification

 1. cargo build -p auths-auth-server — compiles without errors
 2. cargo test -p auths-auth-server — all integration tests pass
 3. cargo clippy -p auths-auth-server -- -D warnings — no warnings
 4. cargo fmt --check -p auths-auth-server — formatted
 5. Manual smoke test:
   - Start registry server: cargo run -p auths-registry-server -- --cors
   - Start auth server: AUTH_SERVER_REGISTRY_URL=http://localhost:3000 cargo run -p auths-auth-server
   - Open http://localhost:3001 in browser → see mock bank
   - Click "Login" → QR code appears
   - Verify polling works (status returns "pending")
 6. cargo build -p auths-mobile-ffi — FFI crate still builds with new function

 ---
 Existing Code Reused
 What: ApiError / ErrorResponse pattern
 Where: crates/auths-registry-server/src/error.rs
 How: Mirror same error→status-code mapping
 ────────────────────────────────────────
 What: ServerState (Arc) pattern
 Where: crates/auths-registry-server/src/lib.rs:78-93
 How: Same pattern for AuthServerState
 ────────────────────────────────────────
 What: ServerConfig builder pattern
 Where: crates/auths-registry-server/src/config.rs
 How: Same env-override pattern
 ────────────────────────────────────────
 What: Router with TraceLayer + CorsLayer
 Where: crates/auths-registry-server/src/routes/mod.rs:26-104
 How: Same layering approach
 ────────────────────────────────────────
 What: GET /v1/identities/:prefix response
 Where: crates/auths-registry-server/src/routes/identity.rs:74-100
 How: RegistryResolver consumes this
 ────────────────────────────────────────
 What: sign_with_identity()
 Where: crates/auths-mobile-ffi/src/lib.rs:329-341
 How: Pattern for new sign_auth_challenge()
 ────────────────────────────────────────
 What: json_canon::to_string()
 Where: crates/auths-verifier/src/core.rs:326
 How: Same canonical JSON approach for challenge signing
 ────────────────────────────────────────
 What: MobileError enum
 Where: crates/auths-mobile-ffi/src/lib.rs:25-49
 How: Extend with new variant if needed
 ────────────────────────────────────────
 What: tower::ServiceExt::oneshot testing
 Where: crates/auths-registry-server/Cargo.toml:48-49
 How: Same test pattern
