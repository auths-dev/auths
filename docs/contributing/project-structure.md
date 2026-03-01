# Project Structure

## Directory layout

```
auths/
├── crates/
│   ├── auths/                   Re-export facade crate
│   ├── auths-core/              Cryptography, keychains, encryption, storage ports
│   ├── auths-crypto/            CryptoProvider trait + ring-based implementation
│   ├── auths-id/                Identity logic, attestations, KERI, Git ref storage
│   ├── auths-cli/               CLI binaries (auths, auths-sign, auths-verify)
│   ├── auths-sdk/               High-level SDK orchestrating core + id
│   ├── auths-verifier/          Minimal-dep verification (FFI, WASM)
│   ├── auths-index/             SQLite-backed O(1) attestation lookups
│   ├── auths-policy/            Policy engine
│   ├── auths-radicle/           Radicle P2P integration
│   ├── auths-telemetry/         Telemetry and diagnostics
│   ├── auths-storage/           Storage abstraction layer
│   ├── auths-infra-git/         Git infrastructure adapter
│   ├── auths-infra-http/        HTTP infrastructure adapter
│   ├── auths-test-utils/        Shared test helpers (fakes, mocks, fixtures)
│   └── xtask/                   Build automation tasks
│
├── packages/
│   ├── auths-verifier-python/   Python bindings (PyO3)
│   ├── auths-verifier-ts/       TypeScript bindings (WASM)
│   ├── auths-verifier-go/       Go bindings (CGo)
│   ├── auths-verifier-swift/    Swift/Kotlin bindings (UniFFI)
│   └── auths-mobile-swift/      iOS identity creation (UniFFI)
│
├── docs/                        MkDocs documentation
├── scripts/                     Build and test scripts
├── actions/                     GitHub Actions
└── examples/                    Example code
```

## Crate dependency graph

```
auths-core  →  auths-id  →  auths-cli
    │              │
    │              ├── auths-index
    │              └── auths-radicle
    │
    └── auths-verifier (standalone, minimal deps)
              │
              ├── packages/auths-verifier-python
              ├── packages/auths-verifier-ts
              ├── packages/auths-verifier-go
              └── packages/auths-verifier-swift
```

## Crate responsibilities

| Crate | Responsibility |
|-------|---------------|
| `auths-core` | Ed25519 crypto (via `ring`), platform keychains (macOS Security Framework, Linux Secret Service, Windows Credential Manager), key encryption, storage port traits (`BlobReader`, `BlobWriter`, `RefReader`, `RefWriter`, `EventLogReader`, `EventLogWriter`) |
| `auths-crypto` | `CryptoProvider` trait abstraction, `RingCryptoProvider` implementation with `spawn_blocking` dispatch, `SecureSeed` newtype |
| `auths-id` | DID derivation, attestation create/verify, KERI Key Event Log (`GitKel`), Git ref storage under `refs/auths/` and `refs/keri/`. Key traits: `IdentityStorage`, `AttestationSource`, `AttestationSink` |
| `auths-sdk` | High-level orchestration layer. Calls `clock.now()` and injects time into domain functions |
| `auths-cli` | Clap-based CLI with three binaries: `auths`, `auths-sign`, `auths-verify`. The only crate that prints to stdout or reads from stdin |
| `auths-verifier` | Pure verification with no `git2` or platform dependencies. Supports FFI (`ffi` feature) and WASM (`wasm` feature). Core functions: `verify_chain()`, `verify_with_keys()`, `did_key_to_ed25519()` |
| `auths-index` | SQLite-backed attestation lookups for O(1) query performance |
| `auths-policy` | Policy evaluation engine |
| `auths-radicle` | Radicle P2P bridge. Feature-gated; zero coupling to `auths-id` or `auths-core` |
| `auths-telemetry` | Telemetry event emission and schema |
| `auths-storage` | Storage abstraction layer |
| `auths-infra-git` | Git infrastructure adapter implementing storage port traits |
| `auths-infra-http` | HTTP infrastructure adapter |
| `auths-test-utils` | Shared test helpers: crypto fakes, mock storage, Git repo fixtures |
| `xtask` | CI setup automation and build tasks |

## Dependency rules

- `auths-verifier` must NOT depend on `git2`, `clap`, or platform-specific crates.
- `auths-core` owns all keychain and storage port implementations.
- `auths-id` owns all Git storage logic (ref management, KEL storage).
- `auths-cli` is the only crate that performs direct I/O (stdout, stdin, filesystem prompts).
- SDK packages (`packages/`) wrap `auths-verifier` only -- they never import `auths-core` or `auths-id`.
- Core and SDK must never reference presentation layer crates (no reverse dependencies).

## Feature flags

| Crate | Feature | Purpose |
|-------|---------|---------|
| `auths-core` | `keychain-file-fallback` | File-based keychain for environments without OS keychain |
| `auths-core` | `keychain-windows` | Windows Credential Manager support |
| `auths-core` | `crypto-secp256k1` | secp256k1 curve support |
| `auths-core` | `test-utils` | Expose test helpers from core |
| `auths-id` | `auths-radicle` | Enable Radicle integration |
| `auths-id` | `indexed-storage` | SQLite-indexed attestation storage |
| `auths-verifier` | `ffi` | C-ABI foreign function interface (enables libc) |
| `auths-verifier` | `wasm` | WebAssembly target (enables wasm-bindgen) |

## Workspace configuration

All crates share a workspace `Cargo.toml` at the repository root. Common dependencies and versions are declared under `[workspace.dependencies]`:

- Current workspace version: `0.0.1-rc.5`
- Rust edition: implied by `rust-version = "1.93"`
- Workspace resolver: `3`
