# Repo Layout

Auths is a Cargo workspace with multiple crates and language-specific packages.

## Structure

```
auths/
├── crates/
│   ├── auths-core/          Core cryptography, keychains, encryption
│   ├── auths-id/            Identity logic, attestations, Git storage
│   ├── auths-cli/           CLI binaries (auths, auths-sign, auths-verify)
│   ├── auths-verifier/      Minimal-dep verification (FFI, WASM)
│   ├── auths-index/         SQLite-backed attestation lookups
│   ├── auths-nostr/         Nostr protocol integration
│   ├── auths-policy/        Policy engine
│   ├── auths-radicle/       Radicle integration
│   └── auths-registry-server/  Registry server
│
├── packages/
│   ├── auths-verifier-python/   Python bindings (PyO3)
│   ├── auths-verifier-ts/       TypeScript bindings (WASM)
│   ├── auths-verifier-go/       Go bindings (CGo)
│   ├── auths-verifier-swift/    Swift/Kotlin bindings (UniFFI)
│   └── auths-mobile-swift/      iOS identity creation (UniFFI)
│
├── docs/                    MkDocs documentation (this site)
├── notes/                   Internal notes, ADRs, guides
├── scripts/                 Build and test scripts
├── actions/                 GitHub Actions
└── examples/                Example code
```

## Crate dependency graph

```
auths-core  →  auths-id  →  auths-cli
    │              │
    │              └─── auths-index
    │              └─── auths-radicle
    │
    └─── auths-verifier (standalone, minimal deps)
              │
              ├─── packages/auths-verifier-python
              ├─── packages/auths-verifier-ts
              ├─── packages/auths-verifier-go
              └─── packages/auths-verifier-swift
```

## What goes where

| Crate | Responsibility |
|-------|---------------|
| `auths-core` | Ed25519 crypto, platform keychains, key encryption, `Storage` trait |
| `auths-id` | DID derivation, attestation create/verify, Git ref storage, `IdentityStorage`/`AttestationSource`/`AttestationSink` traits |
| `auths-cli` | Clap-based CLI, user interaction, passphrase prompts |
| `auths-verifier` | Pure verification (no git2, no platform deps). FFI and WASM entry points. |

## Rules

- `auths-verifier` must NOT depend on `git2`, `clap`, or platform-specific crates
- `auths-core` owns all keychain/storage implementations
- `auths-id` owns all Git storage logic
- `auths-cli` is the only crate that prints to stdout or reads from stdin
- SDK packages wrap `auths-verifier` only -- they never import `auths-core` or `auths-id`
