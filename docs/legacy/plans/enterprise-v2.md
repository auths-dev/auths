# Enterprise Hexagonal Refactoring Plan v2

> Technical Due Diligence Audit & M&A Readiness Transformation
> Date: 2026-02-26

## Executive Summary

This plan details the transformation of the auths codebase from a developer-centric CLI tool into an enterprise-grade, headless-first identity and policy engine. The goal: make the Core IP (KERI identity verification, decentralized policy evaluation, cryptographic challenge-response pipelines) fully embeddable by tier-one identity providers (Okta, Ping Identity, Cloudflare) and global edge network operators.

The codebase already has **strong architectural foundations** — 19 crates, a ports/adapters pattern in `auths-core` with `StorageDriver` and `NetworkDriver` traits (7 storage traits, 3 network traits), dedicated `auths-infra-git` and `auths-infra-http` adapter crates, and a well-structured `auths-sdk` orchestration layer. The `auths-policy` crate is functionally pure with zero inter-crate dependencies and correctly injects `now: DateTime<Utc>` via `EvalContext`. The `auths-verifier` is already FFI/WASM-ready with minimal dependencies.

However, the audit reveals three categories of deal-killer violations:

1. **Business logic in CLI** — 4 fat command handlers trap critical orchestration logic (artifact signing, online pairing, device extension, identity rotation) inside terminal-specific code
2. **Deep git2 coupling in auths-id** — 18 files directly import git2, preventing WASM compilation and locking the identity engine to local filesystem storage
3. **Side-effect pollution in core** — 6 production `std::env::var` reads, 13 `Utc::now()` calls, 25+ `std::fs` operations, and hardcoded stdout in telemetry

Enterprise acquirers evaluate integration friction. They need core IP that can be lifted and embedded into distributed control planes without dragging along terminal dependencies, hardcoded file paths, or synchronous blocking I/O.

---

## Current Architecture (What's Good)

```
auths-crypto          → (no inter-crate deps, pure crypto primitives)
auths-policy          → (no inter-crate deps, pure policy AST, deterministic eval)
auths-telemetry       → (no inter-crate deps, event pipeline)
auths-verifier        → auths-crypto (minimal, FFI/WASM ready)

auths-core            → auths-crypto, auths-verifier
  └─ ports/storage/   → BlobReader, BlobWriter, RefReader, RefWriter, EventLogReader, EventLogWriter
  └─ ports/network/   → IdentityResolver, WitnessClient, RegistryClient

auths-infra-git       → auths-core, auths-sdk (GitBlobStore, GitRefStore, GitEventLog, Git2LogProvider)
auths-infra-http      → auths-core (HttpIdentityResolver, HttpWitnessClient, HttpRegistryClient)

auths-id              → auths-core, auths-crypto, auths-policy, auths-verifier
auths-sdk             → auths-core, auths-id, auths-crypto, auths-verifier
auths-cli             → auths-sdk, auths-core, auths-id, auths-infra-git, auths-infra-http
```

**What's already clean:**
- `auths-core` does NOT directly depend on git2 — its storage/network ports are abstract
- `auths-infra-git` cleanly maps `git2::Error → StorageError` in `error.rs`
- `auths-infra-http` implements network ports via `reqwest` with clean error mapping
- `auths-policy` has zero side effects — `EvalContext` injects time, no I/O
- `auths-verifier` partially supports time injection (`at` parameter in `verify_chain_with_witnesses`)
- `auths-sdk` already has `ports/` (GitLogProvider, ArtifactSource, diagnostics) and `workflows/` (audit, artifact, diagnostics)
- All `println!`/`eprintln!` in core crates are in doc comments only — zero production print macros remain

---

## Audit Findings Summary

| Category | Actual Count | Severity | Crates Affected |
|----------|-------------|----------|-----------------|
| Business logic in CLI | 4 fat handlers | HIGH | auths-cli |
| git2 coupling in auths-id | 18 files | CRITICAL | auths-id |
| git2 in auths-sdk | 1 file (setup.rs) | MEDIUM | auths-sdk |
| std::env::var in core (production) | 7 instances | HIGH | auths-core (6), auths-id (1) |
| Utc::now() in core (production) | 13 instances | MEDIUM | auths-core (1), auths-id (2), auths-sdk (7), auths-verifier (3) |
| std::fs:: in core (production) | 25+ instances | HIGH | auths-core, auths-id |
| std::process::Command in core | 2 production instances | HIGH | auths-core, auths-sdk |
| Hardcoded stdout in telemetry | 1 critical path | MEDIUM | auths-telemetry |
| anyhow in SDK error variants | 4 variants | MEDIUM | auths-sdk |
| reqwest in core | 1 file (witness/http_client.rs) | MEDIUM | auths-core |

> **Correction from prior audit**: The previous plan claimed "20+ println!/eprintln! instances" in production core code. Actual finding: **zero production print macros** in core crates. All 25 instances found are in `/// Usage:` doc comment examples. This is a significant positive — the codebase has already been cleaned of UX side effects in production paths.

---

## Mandatory Structural Principles

### 1. Dependency Direction (Strict Hexagonal Hierarchy)

```
Presentation Layer          SDK/Orchestration         Core Domain           Infrastructure
(auths-cli,                 (auths-sdk)               (auths-core,          (auths-infra-git,
 auths-auth-server,                                    auths-id,             auths-infra-http)
 auths-registry-server)                                auths-verifier,
                                                       auths-policy,
                                                       auths-crypto)
```

Dependencies flow strictly inward. Core never imports SDK. SDK never imports CLI/servers. Infrastructure implements Core traits but never leaks backend-specific types across port boundaries.

### 2. The Port-Adapter Pattern

All external system interactions must be formalized as traits (ports) within Core/SDK. Concrete implementations (adapters) reside exclusively in infrastructure or presentation crates.

| Subsystem | Current State | Target Port |
|-----------|---------------|-------------|
| Registry Storage | `git2::Repository` in 18 auths-id files | `RegistryBackend` trait (already exists — needs git2 types removed from impls) |
| Time/Clocks | `Utc::now()` in 13 locations | `ClockProvider` trait in `auths-core::ports` |
| Environment Config | `std::env::var` in 7 production locations | `EnvironmentConfig` struct injected at SDK boundary |
| Telemetry Sink | Hardcoded `tokio::io::stdout()` in emitter.rs:78 | `EventSink` trait in `auths-telemetry::ports` |
| SSH Agent | `Command::new("ssh-add")` in runtime.rs | `SshAgentProvider` trait in `auths-core::ports` |
| Git Config | `Command::new("git")` in setup.rs | `GitConfigProvider` trait in `auths-sdk::ports` |
| HTTP Witness | `reqwest::Client` in `auths-core::witness::http_client` | Move to `auths-infra-http` (should not be in core) |

### 3. DRY & Composable

Monolithic procedural functions must be decomposed into granular, composable SDK workflows. The CLI should only: parse clap arguments → instantiate adapters → call one SDK function → format output. Each trapped CLI handler becomes a discrete SDK workflow callable from any interface (gRPC, web dashboard, cloud-native control plane).

### 4. Headless-First Testability

SDK and Core layers must be testable with entirely in-memory data structures and fakes. If a test requires physical filesystem, initialized Git repository, or live network — the architectural boundaries have failed. Contract test suites must run against both fakes and real adapters to prevent mock drift.

### 5. Domain-Specific Errors

`thiserror` enums only in Core/SDK. The existing `anyhow::Error` wrapping in `SetupError::StorageError`, `DeviceError::StorageError`, `RegistrationError::NetworkError`, and `RegistrationError::LocalDataError` must be migrated to typed variants. The `map_storage_err()` and `map_device_storage_err()` helpers in `auths-sdk/src/error.rs` should be replaced with `From` impls on domain storage errors. `anyhow::Context` is appropriate only at the CLI/server translation boundary.

---

## Epic 5: CI Guardrails & Regression Prevention

**Objective**: Encode architectural boundaries into CI to prevent future regressions.

### Story 5.1: Enforce Architectural Boundaries via Clippy Lints

> **Why not shell grep**: Shell `grep` is brittle — it flags rustdoc examples, string literals, and inline comments. Clippy's AST-level lints understand Rust syntax and respect `#[cfg(test)]` boundaries.

**Add to top of each core crate's `lib.rs`:**
```rust
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::exit)]
#![deny(clippy::dbg_macro)]
```

**Additional CI enforcement** — For checks Clippy cannot express:

```yaml
# Ban env var reads in core crates
- name: Check no env vars in core
  run: |
    if grep -rn 'std::env::var\b' \
      crates/auths-core/src crates/auths-id/src crates/auths-policy/src \
      crates/auths-verifier/src crates/auths-sdk/src \
      --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v '/// '; then
      echo "ERROR: env var reads found in core crates"
      exit 1
    fi

# Ban reverse dependencies
- name: Check no reverse deps
  run: |
    if grep -rE 'auths.cli|auths.auth.server' \
      crates/auths-sdk crates/auths-core \
      --include='*.toml'; then
      echo "ERROR: reverse dependency detected"
      exit 1
    fi
```

**Files to change:**
- `crates/auths-core/src/lib.rs` — Add lint denials
- `crates/auths-id/src/lib.rs` — Add lint denials
- `crates/auths-policy/src/lib.rs` — Add lint denials
- `crates/auths-verifier/src/lib.rs` — Add lint denials
- `crates/auths-sdk/src/lib.rs` — Add lint denials

### Story 5.2: Add cargo-deny Rules ([S])

**Files to change:**
- `deny.toml` — Ban `git2` from `auths-id`, `auths-core`, `auths-policy`, `auths-verifier`. Add this check to /Users/bordumb/workspace/repositories/auths-base/auths/.pre-commit-config.yaml

### Story 5.3: Create ARCHITECTURE.md ([S])

**Content**: Layer diagram, dependency direction rule, port inventory, crate purpose table, decision guide for "where does feature X go?"

**Files to change:**
- `ARCHITECTURE.md` — **NEW**

### Story 5.4: API Stability Contract (MSRV & SemVer Policy) ([S])

**Why**: For enterprise consumers to depend on `auths-sdk` and `auths-core`, these crates need predictable API evolution. Currently only `auths-oidc-bridge` and `auths-registry-server` declare `rust-version = "1.85"`.

**Changes:**
1. Add `rust-version = "1.93"` to `[workspace.package]` in root `Cargo.toml`
2. Create `RELEASES.md` with SemVer policy for stable crates
3. Add `cargo-semver-checks` to CI for `auths-core` and `auths-sdk`

**Files to change:**
- `Cargo.toml` (workspace root) — Add `rust-version = "1.93"`
- `RELEASES.md` — **NEW** — SemVer policy
- `.github/workflows/ci.yml` — Add `cargo-semver-checks`

---

## PR Sequencing Plan

Ordered to minimize risk and merge conflicts. Each PR is independently shippable.

| PR | Scope | Risk | Depends On | Epic |
|----|-------|------|------------|------|
| **PR-1** | Define new SDK ports (`GitConfigProvider`, `SshAgentProvider`) and `EnvironmentConfig` | Low | — | 2 |
| **PR-2** | Decouple telemetry sinks (`EventSink` trait, `StdoutSink`, `MemorySink`) | Medium | — | 2 |
| **PR-3** | Purge `std::env::var` from core/SDK; introduce `EnvironmentConfig` at SDK boundary | High | PR-1 | 2 |
| **PR-4** | Enforce pure time injection (`ClockProvider` trait, `MockClock`) | Medium | — | 2 |
| **PR-5** | Move HTTP witness client from `auths-core` to `auths-infra-http` | Low | — | 2 |
| **PR-6** | Standardize SDK error types (replace `anyhow` wrapping with typed variants) | Medium | — | 2 |
| **PR-7** | Extract artifact signing from CLI to SDK workflow | Medium | PR-1 | 1 |
| **PR-8** | Extract online pairing from CLI to SDK | Medium | PR-1 | 1 |
| **PR-9** | Extract device extension and identity rotation from CLI to SDK | Medium | PR-1 | 1 |
| **PR-10** | Extract git2 implementations from `auths-id` to `auths-infra-git` | **High** | PR-4 | 3 |
| **PR-11** | Abstract filesystem operations in `auths-id` | Medium | PR-10 | 3 |
| **PR-12** | Remove git2 from `auths-sdk/src/setup.rs` | Low | PR-10 | 3 |
| **PR-13** | Create fakes library (`FakeRegistryBackend`, `MemoryEventSink`, `MockClock`, etc.) | Low | PR-2, PR-4, PR-10 | 4 |
| **PR-14** | Contract test suites (run against both fakes and real adapters) | Medium | PR-10, PR-13 | 4 |
| **PR-15** | Migrate SDK tests to fakes | Medium | PR-13, PR-14 | 4 |
| **PR-16** | Registry state migration pipeline (`migrate_registry()`) | Medium | PR-10 | 3 |
| **PR-17** | CI guardrails (clippy lint denials, grep checks, cargo-deny) | Low | PR-3, PR-4, PR-10 | 5 |
| **PR-18** | `ARCHITECTURE.md` + API stability contract | Low | PR-1, PR-10 | 5 |

---

## File Inventory

### New Files (38)

| File | Epic | Purpose |
|------|------|---------|
| `crates/auths-core/src/ports/clock.rs` | 2 | `ClockProvider` trait + `SystemClock` |
| `crates/auths-core/src/ports/ssh_agent.rs` | 2 | `SshAgentProvider` trait |
| `crates/auths-sdk/src/config.rs` | 2 | `EnvironmentConfig` (unified config context) |
| `crates/auths-sdk/src/ports/git_config.rs` | 2 | `GitConfigProvider` trait |
| `crates/auths-sdk/src/workflows/rotation.rs` | 1 | Identity rotation workflow |
| `crates/auths-sdk/src/workflows/migration.rs` | 3 | Registry state migration pipeline |
| `crates/auths-cli/src/adapters/mod.rs` | 1 | Adapter module root |
| `crates/auths-cli/src/adapters/ssh_agent.rs` | 2 | SSH agent system adapter |
| `crates/auths-cli/src/adapters/git_config.rs` | 2 | Git config system adapter |
| `crates/auths-telemetry/src/ports.rs` | 2 | `EventSink` trait |
| `crates/auths-telemetry/src/sinks/mod.rs` | 2 | Sink module root |
| `crates/auths-telemetry/src/sinks/stdout.rs` | 2 | `StdoutSink` |
| `crates/auths-telemetry/src/sinks/memory.rs` | 2 | `MemorySink` |
| `crates/auths-infra-git/src/registry.rs` | 3 | `PackedRegistryBackend` (moved from auths-id) |
| `crates/auths-infra-git/src/identity_storage.rs` | 3 | Git identity storage (moved) |
| `crates/auths-infra-git/src/keri_storage.rs` | 3 | KEL git storage (moved) |
| `crates/auths-infra-git/src/attestation_storage.rs` | 3 | Git attestation ops (moved) |
| `crates/auths-test-utils/src/fakes/mod.rs` | 4 | Fakes module root |
| `crates/auths-test-utils/src/fakes/registry.rs` | 4 | `FakeRegistryBackend` |
| `crates/auths-test-utils/src/fakes/telemetry.rs` | 4 | `MemoryEventSink` |
| `crates/auths-test-utils/src/fakes/session.rs` | 4 | `InMemorySessionStore` |
| `crates/auths-test-utils/src/fakes/git.rs` | 4 | `FakeGitLogProvider` |
| `crates/auths-test-utils/src/fakes/subprocess.rs` | 4 | `MockSubprocess` |
| `crates/auths-test-utils/src/fakes/clock.rs` | 2 | `MockClock` |
| `crates/auths-test-utils/src/contracts/mod.rs` | 4 | Contract test module root |
| `crates/auths-test-utils/src/contracts/registry.rs` | 4 | `registry_backend_contract_tests!` macro |
| `crates/auths-test-utils/src/contracts/git_log.rs` | 4 | `git_log_provider_contract_tests!` macro |
| `crates/auths-test-utils/src/contracts/event_sink.rs` | 4 | `event_sink_contract_tests!` macro |
| `crates/auths-test-utils/src/contracts/session.rs` | 4 | `session_store_contract_tests!` macro |
| `ARCHITECTURE.md` | 5 | High-level architectural map |
| `RELEASES.md` | 5 | SemVer policy |

### Files to Modify (40+)

| File | Epic | Change |
|------|------|--------|
| `crates/auths-core/src/ports/mod.rs` | 2 | Add `pub mod clock;`, `pub mod ssh_agent;` |
| `crates/auths-core/src/paths.rs` | 2 | Accept `auths_home` parameter |
| `crates/auths-core/src/storage/encrypted_file.rs` | 2 | Accept passphrase via parameter |
| `crates/auths-core/src/storage/keychain.rs` | 2 | Accept `&KeychainConfig` struct |
| `crates/auths-core/src/api/runtime.rs` | 2 | Use injected `SshAgentProvider`; accept config |
| `crates/auths-core/src/witness/http_client.rs` | 2 | Move to `auths-infra-http` |
| `crates/auths-id/src/freeze.rs` | 2, 3 | Accept `ClockProvider`; use storage port for fs |
| `crates/auths-id/src/keri/cache.rs` | 2 | Accept home path parameter |
| `crates/auths-id/src/storage/registry/packed.rs` | 3 | Move to `auths-infra-git` |
| `crates/auths-id/src/storage/registry/tree_ops.rs` | 3 | Move to `auths-infra-git` |
| `crates/auths-id/src/storage/identity.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/keri.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/attestation.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/receipts.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/git_refs.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/keri/kel.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/keri/incremental.rs` | 3 | Replace `git2::Oid` with domain type |
| `crates/auths-id/src/keri/inception.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/keri/anchor.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/keri/resolve.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/keri/rotation.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/identity/initialize.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/identity/resolve.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/identity/helpers.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/identity/rotate.rs` | 3 | Accept trait ref instead of `&Repository` |
| `crates/auths-id/src/witness.rs` | 3 | Replace `git2::Oid` with domain `EventHash` |
| `crates/auths-id/Cargo.toml` | 3 | Remove `git2` dependency |
| `crates/auths-infra-git/Cargo.toml` | 3 | Add `auths-id` dependency |
| `crates/auths-sdk/src/error.rs` | 2 | Replace `anyhow` sources with typed errors |
| `crates/auths-sdk/src/setup.rs` | 2, 3 | Use injected `GitConfigProvider`; remove `git2` |
| `crates/auths-sdk/src/device.rs` | 2 | Accept `&dyn ClockProvider` |
| `crates/auths-sdk/src/platform.rs` | 2 | Accept `&dyn ClockProvider` |
| `crates/auths-sdk/src/pairing.rs` | 1, 2 | Extract online pairing; accept `&dyn ClockProvider` |
| `crates/auths-sdk/src/signing.rs` | 1 | Add `sign_artifact()` orchestration |
| `crates/auths-sdk/src/lib.rs` | 1 | Add workflow modules |
| `crates/auths-sdk/src/workflows/mod.rs` | 1, 3 | Add `pub mod rotation;`, `pub mod migration;` |
| `crates/auths-cli/src/commands/artifact/sign.rs` | 1 | Reduce to thin wrapper |
| `crates/auths-cli/src/commands/device/pair/online.rs` | 1 | Reduce to thin wrapper |
| `crates/auths-cli/src/commands/device/authorization.rs` | 1 | Extract `handle_extend` |
| `crates/auths-cli/src/commands/id/identity.rs` | 1 | Reduce Rotate to thin wrapper |
| `crates/auths-verifier/src/verify.rs` | 2 | Replace `Utc::now()` with `ClockProvider` |
| `crates/auths-telemetry/src/emitter.rs` | 2 | Accept `EventSink` |
| `crates/auths-telemetry/src/event.rs` | 2 | Add optional `trace_id` field |
| `crates/auths-telemetry/src/lib.rs` | 2 | Update exports |
| `crates/auths-core/src/lib.rs` | 5 | Add clippy lint denials |
| `crates/auths-id/src/lib.rs` | 5 | Add clippy lint denials |
| `crates/auths-policy/src/lib.rs` | 5 | Add clippy lint denials |
| `crates/auths-verifier/src/lib.rs` | 5 | Add clippy lint denials |
| `crates/auths-sdk/src/lib.rs` | 5 | Add clippy lint denials |
| `.github/workflows/ci.yml` | 5 | Add grep checks, `cargo-semver-checks` |
| `Cargo.toml` (workspace root) | 5 | Add `rust-version = "1.93"` |
| `crates/auths-test-utils/Cargo.toml` | 4 | Add `async-lock` dependency |
| `TESTING_STRATEGY.md` | 4 | Add contract test section |

---

## Code Standards (Enforced)

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK. Example: `DomainError::InvalidSignature`, `StorageError::ConcurrentModification`.
5. **`thiserror`/`anyhow` Translation Boundary**: The ban on `anyhow` in Core/SDK is strict, but the CLI and API servers (`auths-auth-server`, `auths-registry-server`) **must** define a clear translation boundary where domain errors are wrapped with operational context. The CLI and server crates continue using `anyhow::Context` to collect system-level information (paths, environment, subprocess output), but always wrap the domain `thiserror` errors cleanly — never discard the typed error:
    ```rust
    // auths-cli/src/commands/sign.rs (Presentation Layer)
    let signature = sign_artifact(&config, data)
        .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
    ```
    The existing SDK error types (`SetupError`, `DeviceError`, `RegistrationError` in `crates/auths-sdk/src/error.rs`) currently wrap `anyhow::Error` in their `StorageError` and `NetworkError` variants (e.g., `StorageError(#[source] anyhow::Error)`). These must be migrated to domain-specific `thiserror` variants during Epic 2 execution — the `anyhow` wrapping is a transitional pattern, not a permanent design. The `map_storage_err()` and `map_device_storage_err()` helper functions should be replaced with direct `From` impls on the domain storage errors.
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
