 auths-chat: Cross-Device KERI Messaging App

 Context

 The goal is to prove that the same KERI identity works across multiple devices by building a Telegram/Signal-like messaging app. A
 user creates a did:keri: identity on one device (e.g., iPhone), pairs their MacBook via QR code, and both devices can send/receive
 messages under the same identity. Messages are end-to-end encrypted (X25519 + AES-256-GCM) and signed, with bubbles showing which
 device sent each message.

 The existing codebase provides the building blocks: KERI identity (auths-id), X25519 ECDH (auths-core/pairing), AES-256-GCM encryption
  (auths-core/crypto/encryption.rs), UniFFI iOS bridge (auths-mobile-ffi), QR pairing protocol, and an Axum server template
 (auths-auth-server).

 Architecture

               auths-chat-server (Rust/Axum, port 3002)
              ┌──────────────────────────────────────────┐
              │  REST: register, conversations, keys      │
              │  WebSocket: real-time encrypted messages   │
              │  SQLite: user/device/conversation storage  │
              │  Server CANNOT read messages (E2E)         │
              └───────────┬──────────────┬────────────────┘
                          │              │
                    WS/REST│              │WS/REST
                          │              │
           ┌──────────────┘              └─────────────────┐
           │                                                │
   ┌───────┴──────────┐                     ┌──────────────┴──────┐
   │ macOS SwiftUI    │                     │ iPhone SwiftUI      │
   │ did:keri:EABC... │  ◄── QR pairing ──►│ did:keri:EABC...    │
   │ device: did:key  │                     │ device: did:key     │
   │ X25519 + AES-GCM │                     │ X25519 + AES-GCM   │
   └──────────────────┘                     └─────────────────────┘

 What we're building

 Working directory: /Users/bordumb/workspace/repositories/auths-base/auths-chat

 Three components:
 1. auths-chat-server — Rust Axum crate (encrypted message relay + identity verification)
 2. auths-chat-ffi — Rust UniFFI crate (extends auths-mobile-ffi with E2E encryption + chat signing)
 3. SwiftUI multiplatform app — Single codebase targeting iOS + macOS

 ---
 Step 1: Chat Server Crate

 Create /auths-base/auths/crates/auths-chat-server/

 Follow the hexagonal architecture from auths-auth-server (auths/crates/auths-auth-server/src/lib.rs lines 14-59).

 auths-chat-server/src/
 ├── main.rs              # Entry: env config, tracing, run server
 ├── lib.rs               # ChatServerState (Arc<Inner> pattern from auths-auth-server)
 ├── config.rs            # ChatServerConfig (bind addr, registry URL, DB path)
 ├── error.rs             # ChatApiError
 ├── domain/
 │   ├── mod.rs
 │   ├── types.rs         # User, DeviceRegistration, Message, Conversation
 │   └── events.rs        # ClientEvent, ServerEvent (WebSocket JSON)
 ├── ports/
 │   ├── mod.rs
 │   ├── message_store.rs # trait MessageStore
 │   └── user_store.rs    # trait UserStore
 ├── adapters/
 │   ├── mod.rs
 │   └── sqlite_store.rs  # SQLite impl of both store traits
 ├── routes/
 │   ├── mod.rs           # router() with all routes
 │   ├── auth.rs          # POST /auth/register, POST /auth/challenge
 │   ├── messages.rs      # GET/POST /messages (server stores ciphertext blobs)
 │   ├── conversations.rs # GET/POST /conversations
 │   ├── devices.rs       # GET/POST /devices
 │   └── keys.rs          # GET/POST /keys (X25519 pre-key bundles for E2E)
 └── ws/
     ├── mod.rs
     ├── handler.rs       # Per-connection WebSocket logic
     └── hub.rs           # Connection hub: route msgs to all devices of an identity

 Cargo.toml dependencies:
 [dependencies]
 auths-verifier = { path = "../auths-verifier", version = "0.0.1-rc.9" }
 axum = { version = "0.8", features = ["ws"] }
 chrono = { version = "0.4", features = ["serde"] }
 hex = "0.4"
 ring = "0.17.14"
 rusqlite = { version = "0.32", features = ["bundled"] }
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
 thiserror = "2"
 tokio = { version = "1", features = ["full"] }
 tower-http = { version = "0.6", features = ["trace", "cors"] }
 tracing = "0.1"
 tracing-subscriber = { version = "0.3", features = ["env-filter"] }
 uuid = { version = "1", features = ["v4", "serde"] }
 base64 = "0.22"
 json-canon = "0.1"

 Add to workspace: Edit /auths-base/auths/Cargo.toml to add "crates/auths-chat-server" to members.

 SQLite schema:
 CREATE TABLE users (did TEXT PRIMARY KEY, display_name TEXT NOT NULL, registered_at TEXT NOT NULL);
 CREATE TABLE devices (id TEXT PRIMARY KEY, user_did TEXT NOT NULL REFERENCES users(did),
     device_did TEXT NOT NULL UNIQUE, device_name TEXT NOT NULL, platform TEXT NOT NULL,
     public_key_hex TEXT NOT NULL, registered_at TEXT NOT NULL, last_seen TEXT NOT NULL);
 CREATE TABLE conversations (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, last_message_at TEXT);
 CREATE TABLE conversation_participants (conversation_id TEXT NOT NULL, user_did TEXT NOT NULL,
     PRIMARY KEY (conversation_id, user_did));
 CREATE TABLE messages (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL,
     sender_did TEXT NOT NULL, sender_device_did TEXT NOT NULL,
     ciphertext_b64 TEXT NOT NULL, -- Server stores encrypted blobs, cannot read content
     signature_hex TEXT NOT NULL, timestamp TEXT NOT NULL);
 CREATE TABLE prekeys (id TEXT PRIMARY KEY, user_did TEXT NOT NULL, device_did TEXT NOT NULL,
     x25519_pubkey_b64 TEXT NOT NULL, uploaded_at TEXT NOT NULL, used INTEGER DEFAULT 0);

 CREATE INDEX idx_messages_conversation ON messages(conversation_id, timestamp);
 CREATE INDEX idx_devices_user ON devices(user_did);
 CREATE INDEX idx_prekeys_user ON prekeys(user_did, used);

 Server is E2E-unaware: Messages are stored as opaque ciphertext_b64 blobs. The server only handles routing, pre-key distribution, and
 device registration. It cannot read message content.

 Key endpoint for E2E — routes/keys.rs:
 - POST /keys/prekeys — Upload a batch of X25519 one-time pre-keys
 - GET /keys/prekeys/{user_did} — Fetch a pre-key for initiating an encrypted conversation
 - Server deletes consumed pre-keys after returning them (one-time use)

 WebSocket hub: Maps device_did → sender channel and user_did → set of device_dids. When a message arrives for Alice, the hub delivers
 the ciphertext to ALL of Alice's connected devices — both can decrypt with the shared conversation key.

 Reuse from auths-auth-server:
 - src/lib.rs lines 14-59 — AuthServerState Arc pattern → ChatServerState
 - src/routes/verify.rs — Challenge-response auth flow for device authentication
 - src/adapters/registry_resolver.rs — DID resolution against registry
 - src/config.rs — Config pattern with env vars
 - Cargo.toml — Dependency structure

 ---
 Step 2: Chat FFI Crate (E2E Encryption + Chat Signing)

 Create /auths-base/auths/crates/auths-chat-ffi/

 This is the core crypto layer for the Swift app. It reuses existing primitives:

 Existing code to reuse directly:
 Existing Code: X25519 ECDH key exchange
 File: auths-core/src/pairing/response.rs lines 59-69
 What it provides: EphemeralSecret::random_from_rng(OsRng), PublicKey::from(), .diffie_hellman()
 ────────────────────────────────────────
 Existing Code: X25519 types
 File: auths-core/src/pairing/token.rs lines 6-7
 What it provides: x25519_dalek::{EphemeralSecret, PublicKey}
 ────────────────────────────────────────
 Existing Code: AES-256-GCM encryption
 File: auths-core/src/crypto/encryption.rs lines 1-4, 34-61
 What it provides: Aes256Gcm::new_from_slice(), .encrypt(), .decrypt()
 ────────────────────────────────────────
 Existing Code: HKDF key derivation
 File: auths-core/src/crypto/encryption.rs lines 7, 40-43
 What it provides: Hkdf::<Sha256>::new(), .expand()
 ────────────────────────────────────────
 Existing Code: Nonce/key constants
 File: auths-core/src/crypto/encryption.rs lines 16-20
 What it provides: NONCE_LEN=12, SYMMETRIC_KEY_LEN=32
 ────────────────────────────────────────
 Existing Code: Ed25519 signing
 File: auths-mobile-ffi/src/lib.rs
 What it provides: Ed25519KeyPair::from_pkcs8(), .sign()
 ────────────────────────────────────────
 Existing Code: Identity creation
 File: auths-mobile-ffi/src/lib.rs
 What it provides: create_identity(), get_public_key_from_pkcs8(), generate_device_did()
 ────────────────────────────────────────
 Existing Code: Pairing
 File: auths-mobile-ffi/src/lib.rs
 What it provides: create_pairing_response(), parse_pairing_uri()
 ────────────────────────────────────────
 Existing Code: Auth challenges
 File: auths-mobile-ffi/src/lib.rs
 What it provides: sign_auth_challenge(), parse_auth_challenge_uri()
 Cargo.toml (same dependencies as auths-mobile-ffi, plus aes-gcm and hkdf):

 [package]
 name = "auths-chat-ffi"
 version = "0.0.1-rc.9"
 edition = "2024"

 [workspace]  # Exclude from main workspace — built separately with UniFFI

 [lib]
 name = "auths_chat_ffi"
 crate-type = ["lib", "staticlib", "cdylib"]

 [dependencies]
 uniffi = { version = "0.28", features = ["cli"] }
 serde = { version = "1.0", features = ["derive"] }
 serde_json = "1.0"
 json-canon = "0.1"
 hex = "0.4.3"
 base64 = "0.21"
 ring = "0.17.14"
 blake3 = "1.5"
 x25519-dalek = { version = "2", features = ["static_secrets"] }
 rand = "0.8"
 zeroize = "1.8"
 bs58 = "0.5.1"
 thiserror = "2.0"
 chrono = { version = "0.4", features = ["serde"] }
 # E2E encryption (same versions as auths-core)
 aes-gcm = "0.10.3"
 hkdf = "0.12.4"
 sha2 = "0.10"

 [[bin]]
 name = "uniffi-bindgen"
 path = "uniffi-bindgen.rs"

 FFI functions — src/lib.rs structure:

 auths-chat-ffi/src/
 ├── lib.rs               # uniffi::setup_scaffolding!(), module declarations, re-exports
 ├── identity.rs          # create_identity(), get_public_key_from_pkcs8(), generate_device_did()
 │                          (port from auths-mobile-ffi)
 ├── pairing.rs           # create_pairing_response(), parse_pairing_uri()
 │                          (port from auths-mobile-ffi)
 ├── auth.rs              # sign_auth_challenge(), parse_auth_challenge_uri()
 │                          (port from auths-mobile-ffi)
 ├── signing.rs           # sign_chat_message(), verify_chat_message(), sign_with_identity()
 │                          (new: message signing for chat)
 ├── encryption.rs        # NEW: E2E encryption module
 │   ├── generate_x25519_keypair() → X25519KeyPair { secret_hex, public_b64 }
 │   ├── derive_shared_secret(my_secret_hex, their_public_b64) → String (hex)
 │   ├── derive_message_key(shared_secret_hex, conversation_id) → String (hex)
 │   │     Uses HKDF with conversation_id as info (same pattern as encryption.rs:40-43)
 │   ├── encrypt_message(key_hex, plaintext) → String (base64 ciphertext)
 │   │     Uses AES-256-GCM (same pattern as encryption.rs:48-61)
 │   └── decrypt_message(key_hex, ciphertext_b64) → String (plaintext)
 │         Uses AES-256-GCM decrypt (same pattern as encryption.rs:208-216)
 └── uniffi-bindgen.rs    # UniFFI CLI binary

 E2E Encryption Protocol (simplified X3DH):

 Key exchange when starting a conversation:
 1. Alice wants to message Bob. She fetches Bob's X25519 pre-key from the server (GET /keys/prekeys/{bob_did})
 2. Alice calls generate_x25519_keypair() → ephemeral keypair
 3. Alice calls derive_shared_secret(alice_ephemeral_secret, bob_prekey_public) → shared secret (X25519 DH)
 4. Alice calls derive_message_key(shared_secret, conversation_id) → AES-256 key (HKDF)
 5. Alice calls encrypt_message(key, plaintext) → ciphertext
 6. Alice sends {ciphertext, alice_ephemeral_public} to server
 7. Bob receives {ciphertext, alice_ephemeral_public}
 8. Bob calls derive_shared_secret(bob_prekey_secret, alice_ephemeral_public) → same shared secret
 9. Bob calls derive_message_key(shared_secret, conversation_id) → same AES-256 key
 10. Bob calls decrypt_message(key, ciphertext) → plaintext

 Multi-device key sync: When Alice has two devices (iPhone + MacBook), both devices share the same conversation key because they both
 have access to the same X25519 secret (synced during device pairing via the ECDH shared secret from PairingResponse::create() in
 auths-core/src/pairing/response.rs lines 47-98). The pairing shared secret is used to encrypt and transfer the conversation keys
 between devices.

 Build xcframework for both platforms:
 - aarch64-apple-ios (iPhone)
 - aarch64-apple-ios-sim (Simulator)
 - aarch64-apple-darwin (macOS Apple Silicon)

 ---
 Step 3: SwiftUI Multiplatform App

 Create /auths-base/auths-chat/AuthsChat/

 Xcode project targeting iOS 16+ and macOS 13+. Single codebase with #if os(iOS) / #if os(macOS) for platform-specific code.

 AuthsChat/
 ├── Shared/
 │   ├── AuthsChatApp.swift          # @main entry
 │   ├── Config.swift                # Server URL config (reuse pattern from auths-mobile Config.swift)
 │   ├── FFI/auths_chat_ffi.swift    # UniFFI generated
 │   ├── Models/
 │   │   ├── Identity.swift          # Copy from auths-mobile/ios/Auths/Models/Identity.swift
 │   │   ├── Message.swift           # id, conversationId, senderDid, senderDeviceDid, content, timestamp
 │   │   └── Conversation.swift      # id, participantDids, lastMessage, unreadCount
 │   ├── Services/
 │   │   ├── KeychainService.swift   # Copy from auths-mobile/ios/Auths/Services/KeychainService.swift
 │   │   │                             Change service name to "dev.auths.chat"
 │   │   ├── ChatAPIService.swift    # REST client (URLSession, pattern from auths-mobile APIService.swift)
 │   │   ├── WebSocketService.swift  # URLSessionWebSocketTask (works iOS 13+ / macOS 10.15+)
 │   │   ├── IdentityService.swift   # Wraps FFI: createIdentity, signMessage, getPublicKey
 │   │   ├── EncryptionService.swift # NEW: Wraps FFI encryption functions
 │   │   │   - generatePreKeys() → [X25519KeyPair], store secrets in Keychain
 │   │   │   - uploadPreKeys(apiService) → POST to server
 │   │   │   - initiateConversation(recipientDid) → fetch prekey, DH, derive key
 │   │   │   - encryptMessage(content, conversationId) → ciphertext
 │   │   │   - decryptMessage(ciphertext, conversationId) → plaintext
 │   │   │   - Keychain stores: conversation keys as "conv_key_{conversation_id}"
 │   │   └── PairingService.swift    # Copy from auths-mobile, adapt for macOS
 │   └── Views/
 │       ├── ContentView.swift              # Router: onboarding vs main
 │       ├── ConversationListView.swift     # NavigationSplitView (macOS) / List (iOS)
 │       ├── MessageThreadView.swift        # Chat bubbles + compose bar
 │       ├── MessageBubbleView.swift        # Shows content, device label, verified badge
 │       ├── NewConversationView.swift      # Enter recipient DID to start chat
 │       ├── SettingsView.swift             # Identity info + QR pairing + server config
 │       ├── PairDeviceView.swift           # QR display/scan for pairing
 │       └── Camera/QRCodeScanner.swift     # iOS only (AVFoundation, from auths-mobile)
 ├── iOS/Info.plist                         # Camera, FaceID, Local Network permissions
 ├── macOS/Info.plist                       # Camera, Local Network permissions
 ├── AuthsChatFfi.xcframework/             # Built from auths-chat-ffi crate
 └── justfile                               # Build xcframework recipe

 Reuse from auths-mobile/ios (with paths):
 - auths-mobile/ios/Auths/Services/KeychainService.swift → Copy, change service name
 - auths-mobile/ios/Auths/Services/PairingService.swift → Copy, adapt for macOS
 - auths-mobile/ios/Auths/Models/Identity.swift → Copy
 - auths-mobile/ios/Auths/Views/Camera/QRCodeScanner.swift → Copy for iOS
 - auths-mobile/ios/Auths/Views/Camera/QRScannerViewController.swift → Copy for iOS
 - auths-mobile/ios/Auths/Config.swift → Copy, adapt for chat server URL

 Platform differences:
 ┌─────────────┬───────────────────────────┬────────────────────────────────────┐
 │   Feature   │            iOS            │               macOS                │
 ├─────────────┼───────────────────────────┼────────────────────────────────────┤
 │ QR scanning │ AVFoundation camera       │ Manual URI paste + optional camera │
 ├─────────────┼───────────────────────────┼────────────────────────────────────┤
 │ Navigation  │ TabView + NavigationStack │ NavigationSplitView (sidebar)      │
 ├─────────────┼───────────────────────────┼────────────────────────────────────┤
 │ Biometrics  │ Face ID / Touch ID        │ Touch ID (if available)            │
 ├─────────────┼───────────────────────────┼────────────────────────────────────┤
 │ Device name │ UIDevice.current.name     │ Host.current().localizedName       │
 └─────────────┴───────────────────────────┴────────────────────────────────────┘
 ---
 Step 4: Cross-Device Pairing & Identity Proof

 Reuse the existing pairing protocol from auths-core/src/pairing/:

 1. Device A (e.g., iPhone) generates PairingToken via PairingToken::generate() (token.rs:52-58) → displays as QR code:
 auths://pair?d={did}&e={endpoint}&k={pubkey}&sc={code}&x={expires}&c={caps}
 2. Device B (e.g., MacBook) scans/pastes → calls create_pairing_response() which internally calls PairingResponse::create()
 (response.rs:47-98) doing ECDH + signed binding
 3. The ECDH shared secret (response.rs:68-69) is used to encrypt and transfer the identity's signing key from Device A → Device B, so
 both devices can sign as the same identity
 4. Device B POSTs response to chat server → server verifies and links device to identity
 5. Both devices now authenticate under the same did:keri: identity

 Multi-device message delivery: When Alice sends from iPhone, the server delivers the ciphertext to ALL Alice's connected devices
 (iPhone + MacBook). Both devices hold the conversation decryption key, so both can read incoming messages. Message bubbles show "from
 iPhone" or "from MacBook" label.

 ---
 Step 5: Demo Justfile Recipe

 Add chatdemo recipe to /auths-base/auths/justfile (following logindemo pattern, lines 7-154):

 1. Build auths-registry-server + auths-chat-server
 2. Init persistent registry at ~/.auths-demo (reuse logindemo logic)
 3. Start registry on port 3000, chat server on port 3002
 4. Detect LAN IP for cross-device connectivity (reuse logindemo lines 37-51)
 5. Print instructions: "Pair devices and send encrypted messages"

 ---
 Files to Modify
 ┌──────────────────┬─────────────────────────────────────────────────────┐
 │       File       │                       Action                        │
 ├──────────────────┼─────────────────────────────────────────────────────┤
 │ auths/Cargo.toml │ Add "crates/auths-chat-server" to workspace members │
 ├──────────────────┼─────────────────────────────────────────────────────┤
 │ auths/justfile   │ Add chatdemo recipe                                 │
 └──────────────────┴─────────────────────────────────────────────────────┘
 Files to Create
 ┌─────────────────────────────────┬──────────────────────────────────────────────────┬───────┐
 │            Directory            │                      Files                       │ Count │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths/crates/auths-chat-server/ │ Cargo.toml + ~14 source files                    │ 15    │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths/crates/auths-chat-ffi/    │ Cargo.toml + ~6 source files + uniffi-bindgen.rs │ 8     │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths-chat/AuthsChat/Shared/    │ ~15 Swift files (views, services, models)        │ 15    │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths-chat/AuthsChat/iOS/       │ Info.plist                                       │ 1     │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths-chat/AuthsChat/macOS/     │ Info.plist                                       │ 1     │
 ├─────────────────────────────────┼──────────────────────────────────────────────────┼───────┤
 │ auths-chat/                     │ justfile (build xcframework)                     │ 1     │
 └─────────────────────────────────┴──────────────────────────────────────────────────┴───────┘
 Total: ~41 new files

 Build Order

 1. auths-chat-server crate → cargo build --package auths-chat-server
 2. auths-chat-ffi crate → cargo build (separate workspace)
 3. Build xcframework → just build-xcframework (from auths-chat/)
 4. SwiftUI app → Xcode build for iOS + macOS
 5. chatdemo justfile recipe → integration test

 Verification

 1. Server compiles: cargo build --package auths-chat-server
 2. Server tests pass: cargo test --package auths-chat-server
 3. FFI compiles: cd auths/crates/auths-chat-ffi && cargo build
 4. xcframework builds: cd auths-chat && just build-xcframework
 5. Demo runs: cd auths && just chatdemo starts registry + chat server
 6. iPhone app: Install, create identity, connect to chat server, pair with MacBook via QR
 7. MacBook app: Install, paste pairing URI, verify same identity appears
 8. E2E encryption: Send message from iPhone → appears decrypted on MacBook, server stores only ciphertext
 9. Multi-device proof: Both devices show same conversations, each bubble labeled with source device

 # Runbook

   Here's the verification path, from quickest wins to full end-to-end demo:

  1. Rust compilation (already verified)

  cd auths && cargo build --package auths-chat-server

  2. FFI unit tests (already verified — 25/25 pass)

  cd auths/crates/auths-chat-ffi && cargo test

  These cover identity creation, X25519 key exchange, AES-256-GCM encrypt/decrypt round-trips, message signing/verification, and pairing
   URI parsing.

  3. Run the demo servers

  cd auths && just chatdemo

  This starts the registry on port 3000 and chat server on port 3002. You can then hit the REST API directly:

  # Health check
  curl http://localhost:3002/health

  # Register a user
  curl -X POST http://localhost:3002/auth/register \
    -H 'Content-Type: application/json' \
    -d '{"did":"did:keri:test123","display_name":"Alice"}'

  # Register a device
  curl -X POST http://localhost:3002/devices \
    -H 'Content-Type: application/json' \
    -d
  '{"user_did":"did:keri:test123","device_did":"did:key:z6Mk...","device_name":"iPhone","platform":"ios","public_key_hex":"abcd1234"}'

  # Create a conversation
  curl -X POST http://localhost:3002/conversations \
    -H 'Content-Type: application/json' \
    -d '{"participant_dids":["did:keri:test123","did:keri:bob456"]}'

  # Send an encrypted message (ciphertext is opaque to the server)
  curl -X POST http://localhost:3002/messages \
    -H 'Content-Type: application/json' \
    -d '{"conversation_id":"<id-from-above>","sender_did":"did:keri:test123","sender_device_did":"did:key:z6Mk...","ciphertext_b64":"SGV
  sbG8gV29ybGQ=","signature_hex":"deadbeef"}'

  # Fetch messages
  curl http://localhost:3002/conversations/<id>/messages

  4. WebSocket real-time test

  Connect with websocat or any WS client:

  websocat ws://localhost:3002/ws

  Send a JSON message and observe it broadcast to other connected clients.

  5. Build the xcframework (for the Swift app)

  cd auths-chat && just build-xcframework

  This requires the Rust iOS/macOS cross-compilation targets installed:
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin

  6. Full end-to-end (requires Xcode project)

  The Swift files are all in auths-chat/AuthsChat/ but need an Xcode project to build. To create one:

  1. Open Xcode → File → New → Project → Multiplatform App
  2. Add the Swift files from Shared/, iOS/, macOS/
  3. Link the AuthsChatFfi.xcframework from step 5
  4. Build for iOS simulator + macOS

  The Swift services (IdentityService, EncryptionService) currently use mock implementations — once the xcframework is linked, swap the
  mock calls for the real FFI functions (createIdentity(), encryptMessage(), etc.).

  What each layer proves:
  ```
  ┌─────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────┐
  │              Layer              │                                         What it proves                                         │
  ├─────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ FFI tests (25/25)               │ X25519 ECDH + AES-256-GCM encryption round-trips correctly; identity creation and signing work │
  ├─────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Chat server compiles + REST API │ Message routing, device registration, pre-key distribution, SQLite storage all work            │
  ├─────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ just chatdemo                   │ Registry + chat server integrate on the local network                                          │
  ├─────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ WebSocket test                  │ Real-time message delivery to multiple connected devices                                       │
  ├─────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Full Swift app                  │ Same did:keri: identity on iPhone + MacBook, E2E encrypted messages with device labels         │
  └─────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘
  ```

  The strongest proof is step 3 — running just chatdemo and hitting the API with curl demonstrates the server stores only opaque
