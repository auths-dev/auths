# Architecture Overview

How Auths is built: crate dependency graph, data flow, and system-level design.

## System Diagram

```mermaid
flowchart TD
    subgraph Presentation["Presentation Layer"]
        CLI["auths-cli<br/><small>auths, auths-sign, auths-verify</small>"]
    end

    subgraph Domain["Domain Layer"]
        SDK["auths-sdk<br/><small>workflows, clock injection</small>"]
        ID["auths-id<br/><small>identity, attestation, KERI, Git storage</small>"]
        POLICY["auths-policy<br/><small>authorization evaluation</small>"]
        INDEX["auths-index<br/><small>SQLite O(1) attestation lookups</small>"]
    end

    subgraph Core["Core Layer"]
        CORE["auths-core<br/><small>keychains, signing, SAID</small>"]
        CRYPTO["auths-crypto<br/><small>CryptoProvider, DID encoding</small>"]
    end

    subgraph Verification["Verification Layer (standalone)"]
        VERIFIER["auths-verifier<br/><small>FFI, WASM, minimal deps</small>"]
    end

    subgraph Infrastructure["Infrastructure Layer"]
        INFRA_GIT["auths-infra-git<br/><small>Git transport</small>"]
        INFRA_HTTP["auths-infra-http<br/><small>HTTP transport</small>"]
        STORAGE["auths-storage<br/><small>storage adapters</small>"]
    end

    CLI --> SDK
    SDK --> ID
    SDK --> CORE
    ID --> CORE
    ID --> POLICY
    ID --> VERIFIER
    CORE --> CRYPTO
    VERIFIER --> CRYPTO
    INDEX --> ID
    CLI --> INFRA_GIT
    CLI --> INFRA_HTTP
    ID --> STORAGE
```

## Crate Dependency Graph

The workspace contains 14 crates organized into clear layers. Dependencies flow strictly downward -- core and domain crates never reference presentation layer crates.

| Crate | Role | Key Dependencies |
|-------|------|------------------|
| `auths-cli` | Three binaries: `auths`, `auths-sign`, `auths-verify` | auths-sdk, auths-id, clap |
| `auths-sdk` | Orchestration workflows, clock boundary | auths-core, auths-id |
| `auths-id` | Identity, attestation, KERI protocol, Git storage | auths-core, auths-verifier, git2 |
| `auths-core` | Keychains, signing, SAID computation, encryption | auths-crypto, ring, blake3 |
| `auths-crypto` | `CryptoProvider` trait, DID encoding, KERI key parsing | ring (optional), bs58, base64 |
| `auths-verifier` | Standalone verification for FFI/WASM embedding | auths-crypto, json-canon, blake3 |
| `auths-policy` | Authorization policy evaluation | auths-verifier |
| `auths-index` | SQLite-backed O(1) attestation lookups | auths-id |
| `auths-infra-git` | Git transport adapters | git2 |
| `auths-infra-http` | HTTP transport adapters | reqwest |
| `auths-storage` | Storage backend abstractions | - |
| `auths-telemetry` | Observability and metrics | - |
| `auths-radicle` | Radicle protocol integration | auths-id |
| `auths-test-utils` | Shared test helpers | auths-crypto |

## Data Flow

### Identity Initialization

```mermaid
sequenceDiagram
    participant User
    participant CLI as auths-cli
    participant SDK as auths-sdk
    participant KERI as auths-id::keri
    participant Git as ~/.auths (Git repo)

    User->>CLI: auths init
    CLI->>SDK: create_identity()
    SDK->>KERI: create_keri_identity(repo)
    KERI->>KERI: Generate current Ed25519 keypair
    KERI->>KERI: Generate next Ed25519 keypair (pre-rotation)
    KERI->>KERI: Compute next-key commitment (Blake3)
    KERI->>KERI: Build IcpEvent, compute SAID, sign
    KERI->>Git: Store at refs/did/keri/<prefix>/kel
    KERI-->>SDK: InceptionResult { prefix, keypairs }
    SDK->>SDK: Store keys in platform keychain
    SDK-->>CLI: did:keri:E...
    CLI-->>User: Identity created
```

### Commit Signing

```mermaid
sequenceDiagram
    participant Git as git commit
    participant Sign as auths-sign
    participant Core as auths-core
    participant Keychain as Platform Keychain

    Git->>Sign: Invoke as gpg.program
    Sign->>Keychain: Retrieve device signing key
    Keychain-->>Sign: Ed25519 seed
    Sign->>Core: sign_ed25519(seed, commit_data)
    Core-->>Sign: 64-byte signature
    Sign-->>Git: Signature (SSHSIG format)
```

### Verification

```mermaid
sequenceDiagram
    participant Caller
    participant Verifier as auths-verifier
    participant Crypto as auths-crypto

    Caller->>Verifier: verify_chain(attestations, identity_pk)
    loop Each attestation in chain
        Verifier->>Verifier: Reconstruct canonical JSON (json-canon)
        Verifier->>Crypto: verify_ed25519(identity_pk, canonical, identity_sig)
        Verifier->>Crypto: verify_ed25519(device_pk, canonical, device_sig)
        Verifier->>Verifier: Check expiration, revocation
    end
    Verifier-->>Caller: Ok(VerifiedAttestation) or Err
```

## Layering Rules

1. **No reverse dependencies.** Core and SDK must never reference presentation layer crates.

2. **Domain-specific errors only.** `thiserror` enums in Core/SDK. No `anyhow::Error` or `Box<dyn Error>` below the CLI boundary.

3. **`thiserror`/`anyhow` translation boundary.** The CLI and server crates use `anyhow::Context` for operational context, but always wrap the underlying typed error -- never discard it.

4. **Clock injection.** `Utc::now()` is banned in `auths-core` and `auths-id`. All time-sensitive functions accept `now: DateTime<Utc>` as their first parameter. The CLI calls `Utc::now()` at the presentation boundary.

5. **Crypto provider abstraction.** Domain crates depend on the `CryptoProvider` trait from `auths-crypto`, not on `ring` directly. This enables WASM builds with `WebCryptoProvider` and native builds with `RingCryptoProvider`.

## Feature Flags

| Crate | Flag | Effect |
|-------|------|--------|
| `auths-core` | `keychain-file-fallback` | File-based key storage fallback |
| `auths-core` | `keychain-windows` | Windows Credential Manager support |
| `auths-core` | `crypto-secp256k1` | secp256k1 curve support |
| `auths-core` | `test-utils` | Test helper exports |
| `auths-id` | `git-storage` | Git-backed storage (inception, KEL, rotation) |
| `auths-id` | `indexed-storage` | SQLite-indexed attestation lookups |
| `auths-id` | `witness-client` | Witness receipt collection |
| `auths-crypto` | `native` | ring-based Ed25519 (default) |
| `auths-crypto` | `wasm` | WebCrypto-based Ed25519 |
| `auths-verifier` | `native` | ring-based verification (default) |
| `auths-verifier` | `ffi` | C FFI exports via libc |
| `auths-verifier` | `wasm` | WASM exports via wasm-bindgen |
