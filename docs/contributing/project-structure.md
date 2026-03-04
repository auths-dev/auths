# Project Structure

## Directory layout

```
auths/
├── crates/
│   ├── auths/                   Re-export facade crate
│   ├── auths-crypto/            CryptoProvider trait + ring-based implementation
│   ├── auths-verifier/          Minimal-dep verification (FFI, WASM)
│   ├── auths-core/              Keychains, signing, policy ports, encryption
│   ├── auths-id/                Identity logic, attestations, KERI, trait definitions
│   ├── auths-policy/            Policy engine
│   ├── auths-index/             SQLite-backed O(1) attestation lookups
│   ├── auths-storage/           Git and SQL storage adapters
│   ├── auths-sdk/               High-level SDK orchestrating core + id
│   ├── auths-infra-git/         Git infrastructure adapter
│   ├── auths-infra-http/        HTTP infrastructure adapter
│   ├── auths-telemetry/         Telemetry and diagnostics
│   ├── auths-cli/               CLI binaries (auths, auths-sign, auths-verify)
│   ├── auths-radicle/           Radicle P2P integration (excluded from workspace)
│   └── xtask/                   Build automation tasks (publish = false)
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
Layer 0: auths-crypto            (cryptographic primitives, DID:key encoding)
Layer 1: auths-verifier          (standalone verification, FFI/WASM)
Layer 2: auths-core              (keychains, signing, policy ports)
Layer 3: auths-id, auths-policy  (identity, attestation, KERI, trait definitions)
Layer 4: auths-storage, auths-sdk (storage adapters, application services)
Layer 5: auths-infra-git, auths-infra-http (infrastructure adapters)
Layer 6: auths-cli               (user commands)
```

Dependencies flow strictly downward. The publish order follows the same layer ordering.

```
auths-crypto
    ↑
auths-verifier
    ↑
auths-core ──────────────────────┐
    ↑                            │
auths-id ───── auths-policy      │
    ↑                            │
auths-storage   auths-sdk ───────┘
    ↑              ↑
auths-infra-git  auths-infra-http
    ↑              ↑
    └── auths-cli ─┘

Standalone: auths-index, auths-telemetry
Bindings:   packages/auths-verifier-{python,ts,go,swift}
```

## Crate responsibilities

| Crate | Responsibility |
|-------|---------------|
| `auths-crypto` | `CryptoProvider` trait abstraction, `RingCryptoProvider` with `spawn_blocking` dispatch, KERI key parsing, DID:key encoding, `SecureSeed` newtype |
| `auths-verifier` | Pure verification with no `git2` or platform dependencies. Supports FFI (`ffi` feature) and WASM (`wasm` feature). Core functions: `verify_chain()`, `verify_with_keys()`, `did_key_to_ed25519()` |
| `auths-core` | Platform keychains (macOS Security Framework, Linux Secret Service, Windows Credential Manager), key encryption, signing, storage port traits (`BlobReader`, `BlobWriter`, `RefReader`, `RefWriter`, `EventLogReader`, `EventLogWriter`) |
| `auths-id` | DID derivation, attestation create/verify, KERI Key Event Log (`GitKel`). Defines key traits: `IdentityStorage`, `AttestationSource`, `AttestationSink`. Trait definitions are ungated; KERI and Git operations require the `git-storage` feature |
| `auths-storage` | Concrete storage adapters: `GitAttestationStorage`, `GitIdentityStorage`, `GitRefSink`, `GitRegistryBackend`. Implements traits defined in `auths-id` |
| `auths-sdk` | High-level orchestration layer. Calls `clock.now()` and injects time into domain functions |
| `auths-cli` | Clap-based CLI with three binaries: `auths`, `auths-sign`, `auths-verify`. The only crate that prints to stdout or reads from stdin |
| `auths-policy` | Policy evaluation engine |
| `auths-index` | SQLite-backed attestation lookups for O(1) query performance |
| `auths-telemetry` | Telemetry event emission and schema |
| `auths-infra-git` | Git infrastructure adapter (commit log walking, audit) |
| `auths-infra-http` | HTTP infrastructure adapter |
| `xtask` | CI setup automation and build tasks (not published) |

## Dependency rules

- `auths-verifier` must NOT depend on `git2`, `clap`, or platform-specific crates.
- `auths-id` defines storage traits (`IdentityStorage`, `AttestationSource`, `AttestationSink`); `auths-storage` provides the implementations.
- `auths-id` tests use in-memory fakes only -- no dev-dependency on `auths-storage`.
- `auths-storage` tests use contract test macros exported from `auths-id`.
- `auths-cli` is the only crate that performs direct I/O (stdout, stdin, filesystem prompts).
- SDK packages (`packages/`) wrap `auths-verifier` only -- they never import `auths-core` or `auths-id`.
- Core and SDK must never reference presentation layer crates (no reverse dependencies).

## Feature flags

| Crate | Feature | Purpose |
|-------|---------|---------|
| `auths-crypto` | `native` | ring-based Ed25519 (default) |
| `auths-crypto` | `wasm` | WebCrypto-based Ed25519 |
| `auths-crypto` | `test-utils` | Expose `get_shared_keypair`, `create_test_keypair` |
| `auths-verifier` | `native` | ring-based verification (default) |
| `auths-verifier` | `ffi` | C-ABI foreign function interface (enables libc) |
| `auths-verifier` | `wasm` | WebAssembly target (enables wasm-bindgen) |
| `auths-verifier` | `test-utils` | Expose `MockClock` |
| `auths-core` | `keychain-file-fallback` | File-based keychain for environments without OS keychain |
| `auths-core` | `keychain-windows` | Windows Credential Manager support |
| `auths-core` | `crypto-secp256k1` | secp256k1 curve support |
| `auths-core` | `test-utils` | Expose test helpers (fakes, in-memory storage) |
| `auths-id` | `git-storage` | Git-backed KERI, rotation, attestation operations (default) |
| `auths-id` | `indexed-storage` | SQLite-indexed attestation storage |
| `auths-id` | `witness-client` | Witness receipt collection |
| `auths-id` | `test-utils` | Expose fakes, mocks, fixtures, contract test macros |
| `auths-storage` | `backend-git` | Git-backed storage (git2, fs2, tempfile) |
| `auths-storage` | `backend-postgres` | PostgreSQL storage (sqlx) |
| `auths-sdk` | `test-utils` | Expose `FakeGitLogProvider` and contract macros |

## Workspace configuration

All crates share a workspace `Cargo.toml` at the repository root. Common dependencies and versions are declared under `[workspace.dependencies]`:

- Current workspace version: `0.0.1-rc.3`
- Rust edition: 2024 (implied by `rust-version = "1.93"`)
- Workspace resolver: `3`
