# Sans-IO Specification

## Rule

Domain crates must not perform direct I/O. All I/O goes through port traits.

**Domain crates (sans-IO):** `auths-sdk`, `auths-crypto`, `auths-id`, `auths-core`
- No `std::fs` (file reads/writes)
- No `std::process::Command` (shelling out to git, ssh-keygen, etc.)
- No `dirs::home_dir()` or hardcoded paths
- No `std::io` (except in error types)
- No `tokio::fs`, `tokio::process`, `reqwest`, or any network/disk library

**Adapter crates (I/O allowed):** `auths-infra-git`, `auths-infra-http`, `auths-cli/src/adapters/`
- Implement port traits with real I/O
- This is the only place `std::fs`, `Command::new`, `reqwest`, `git2`, etc. should appear

**Presentation layer:** `auths-cli/src/commands/`
- Calls SDK workflows, formats and prints results
- Wires adapters into workflows (composition)
- No business logic

## Why

1. **Testability.** Workflows can be tested with in-memory stubs. No temp directories, no real git repos, no network mocking.
2. **Embeddability.** The SDK compiles to WASM (no `std::fs` or `std::process` available), C-FFI, and cloud environments. Direct I/O would break this.
3. **Portability.** Swapping git storage for Postgres, or local keychain for cloud KMS, requires only a new adapter — zero workflow changes.
4. **Determinism.** Clock, UUID, and passphrase are all injected via traits. Tests are reproducible.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  auths-cli                                      │
│  ┌────────────┐  ┌──────────────────────────┐   │
│  │ commands/   │  │ adapters/                │   │
│  │ (present)   │  │ (impl port traits)       │   │
│  └─────┬──────┘  └──────────┬───────────────┘   │
│        │ calls               │ implements        │
├────────┼────────────────────┼───────────────────┤
│  auths-sdk                  │                    │
│  ┌─────┴──────┐  ┌─────────┴───────────────┐   │
│  │ workflows/  │  │ ports/                   │   │
│  │ (logic)     │──│ (trait definitions)      │   │
│  └────────────┘  └─────────────────────────┘   │
├─────────────────────────────────────────────────┤
│  auths-infra-git, auths-infra-http              │
│  (adapter crates — implement port traits)       │
└─────────────────────────────────────────────────┘
```

Dependency direction: adapters depend on ports, never the reverse.

## How It Works Today

### Port traits (`auths-sdk/src/ports/`)

8 port traits define all I/O boundaries:

| Port | File | What it abstracts |
|------|------|-------------------|
| `AgentSigningPort` | `ports/agent.rs` | IPC with signing agent (Unix socket / noop) |
| `AgentTransport` | `ports/agent.rs` | Connection acceptance for agent daemon |
| `GitLogProvider` | `ports/git.rs` | Reading commit history |
| `GitConfigProvider` | `ports/git_config.rs` | Setting git config values |
| `ArtifactSource` | `ports/artifact.rs` | Artifact digest computation |
| `GitDiagnosticProvider` | `ports/diagnostics.rs` | Git version, config checks |
| `CryptoDiagnosticProvider` | `ports/diagnostics.rs` | SSH keygen availability |
| `DiagnosticFix` | `ports/diagnostics.rs` | Auto-fix for failed checks |

### DI container (`auths-sdk/src/context.rs`)

`AuthsContext` holds all injected dependencies as `Arc<dyn Trait>`:

```rust
pub struct AuthsContext {
    pub registry: Arc<dyn RegistryBackend + Send + Sync>,
    pub key_storage: Arc<dyn KeyStorage + Send + Sync>,
    pub clock: Arc<dyn ClockProvider + Send + Sync>,
    pub event_sink: Arc<dyn EventSink>,
    pub identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    pub attestation_sink: Arc<dyn AttestationSink + Send + Sync>,
    pub attestation_source: Arc<dyn AttestationSource + Send + Sync>,
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    pub uuid_provider: Arc<dyn UuidProvider + Send + Sync>,
    pub agent_signing: Arc<dyn AgentSigningPort + Send + Sync>,
}
```

Built via a typestate builder that enforces required fields at compile time. Optional fields default to no-op implementations (`NoopSink`, `NoopAgentProvider`, etc.).

### Composition root (`auths-cli/src/factories/mod.rs`)

Single module where adapters are instantiated and wired into workflows:
- `build_config()` — selects passphrase provider (interactive vs. prefilled)
- `build_agent_provider()` — returns platform-specific adapter
- `init_audit_sinks()` — builds telemetry pipeline

### Workflow pattern

Every workflow accepts port traits as generics — never concrete types:

```rust
// Good: generic over provider trait
pub struct DiagnosticsWorkflow<G: GitDiagnosticProvider, C: CryptoDiagnosticProvider> {
    git: G,
    crypto: C,
}

// Good: uses injected context
pub struct CommitSigningContext {
    pub key_storage: Arc<dyn KeyStorage + Send + Sync>,
    pub agent_signing: Arc<dyn AgentSigningPort + Send + Sync>,
}
```

## Current Violations

Two places in domain crates do direct I/O that should eventually be abstracted:

| Crate | File | Violation | Severity |
|-------|------|-----------|----------|
| `auths-core` | `src/config.rs` | `std::fs::read_to_string`, `std::fs::write` for config loading/saving | Medium — blocks config testing |
| `auths-sdk` | `src/workflows/allowed_signers.rs` | `std::fs::read_to_string`, `std::fs::create_dir_all` for signers file | Medium — blocks mocking in tests |

These work fine today but should be refactored to use port traits if testing or WASM compatibility becomes a priority.

## Adding New Workflows: Checklist

When adding a new workflow that needs I/O:

1. **Define a port trait** in `auths-sdk/src/ports/`
   - Trait methods should be small and focused (Interface Segregation)
   - Return domain types, not I/O types (e.g., `Result<String>` not `Result<File>`)
   - Include `Send + Sync` bounds for async compatibility

2. **Write the workflow** in `auths-sdk/src/workflows/`
   - Accept the port trait as a generic parameter or field
   - Return a structured report (not formatted strings)
   - No `use std::fs`, no `use std::process`, no `use dirs`

3. **Implement the adapter** in `auths-cli/src/adapters/`
   - This is where `std::fs`, `Command::new`, `dirs::home_dir` go
   - One adapter per port trait (or combine if they share I/O concerns)

4. **Wire it up** in `auths-cli/src/commands/` or `factories/`
   - Instantiate adapter, pass to workflow, print results

5. **Verify sans-IO**
   - `grep -r "std::fs" crates/auths-sdk/src/` should return nothing
   - `grep -r "Command::new" crates/auths-sdk/src/` should return nothing
   - Same for `auths-crypto`, `auths-id`, `auths-core`

## Example: Diagnostics

The diagnostics system is the cleanest example of the full pattern:

**Port** (`auths-sdk/src/ports/diagnostics.rs`):
```rust
pub trait GitDiagnosticProvider: Send + Sync {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError>;
    fn get_git_config(&self, key: &str) -> Result<Option<String>, DiagnosticError>;
}
```

**Workflow** (`auths-sdk/src/workflows/diagnostics.rs`):
```rust
pub struct DiagnosticsWorkflow<G: GitDiagnosticProvider, C: CryptoDiagnosticProvider> {
    git: G,
    crypto: C,
}

impl<G: GitDiagnosticProvider, C: CryptoDiagnosticProvider> DiagnosticsWorkflow<G, C> {
    pub fn run(&self) -> Result<DiagnosticReport, DiagnosticError> {
        let mut checks = Vec::new();
        checks.push(self.git.check_git_version()?);
        checks.push(self.crypto.check_ssh_keygen_available()?);
        self.check_git_signing_config(&mut checks)?;
        Ok(DiagnosticReport { checks })
    }
}
```

**Adapter** (`auths-cli/src/adapters/system_diagnostic.rs`):
```rust
impl GitDiagnosticProvider for SystemGitDiagnostic {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        let output = Command::new("git").args(["--version"]).output()
            .map_err(|e| DiagnosticError::ExecutionFailed(e.to_string()))?;
        // parse output, return CheckResult
    }
}
```

**CLI** (`auths-cli/src/commands/doctor.rs`):
```rust
let git = SystemGitDiagnostic::new();
let crypto = SystemCryptoDiagnostic::new();
let workflow = DiagnosticsWorkflow::new(git, crypto);
let report = workflow.run()?;
// print report to user
```

The workflow has zero I/O. Swap `SystemGitDiagnostic` for a mock and you can test every code path without touching the filesystem.

## Enforcing via Clippy

The workspace already uses `disallowed-methods` in `clippy.toml` to enforce similar patterns (e.g., `ClockProvider` instead of `Utc::now()`, `UuidProvider` instead of `Uuid::new_v4()`). The same mechanism can enforce sans-IO per crate.

### How it works

Clippy walks up from each source file to find the nearest `clippy.toml`. A file at `crates/auths-sdk/clippy.toml` overrides the workspace root one for that crate only. This means per-crate files must **duplicate** the shared workspace rules (clippy does not merge configs).

### Which crates get per-crate files

| Crate | Gets sans-IO clippy.toml? |
|-------|--------------------------|
| `auths-sdk` | Yes — already perfectly sans-IO |
| `auths-crypto` | Yes — pure computation, no I/O |
| `auths-id` | Yes — uses ports |
| `auths-core` | Not yet — has 2 violations (`config.rs`, `allowed_signers.rs`) to fix first |
| `auths-infra-git` | No — adapter crate, I/O is correct |
| `auths-infra-http` | No — adapter crate, I/O is correct |
| `auths-cli` | No — adapters + presentation, I/O is correct |

### What to disallow

Each per-crate `clippy.toml` should include:

**Shared workspace rules** (duplicated from root `clippy.toml`):
```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
```

**`disallowed-methods`** — ban I/O free functions:
```toml
disallowed-methods = [
  # Shared workspace rules
  { path = "chrono::offset::Utc::now", reason = "inject ClockProvider", allow-invalid = true },
  { path = "std::time::SystemTime::now", reason = "inject ClockProvider", allow-invalid = true },
  { path = "std::env::var", reason = "use EnvironmentConfig abstraction", allow-invalid = true },
  { path = "uuid::Uuid::new_v4", reason = "use UuidProvider::new_id()" },

  # Sans-IO: filesystem
  { path = "std::fs::read", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::read_to_string", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::write", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::create_dir", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::create_dir_all", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::remove_file", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::remove_dir", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::remove_dir_all", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::copy", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::rename", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::metadata", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::read_dir", reason = "sans-IO crate — use a port trait" },
  { path = "std::fs::canonicalize", reason = "sans-IO crate — use a port trait" },

  # Sans-IO: process
  { path = "std::process::Command::new", reason = "sans-IO crate — use a port trait" },
  { path = "std::process::exit", reason = "sans-IO crate — return errors instead" },

  # Sans-IO: dirs
  { path = "dirs::home_dir", reason = "sans-IO crate — inject paths via config", allow-invalid = true },
  { path = "dirs::config_dir", reason = "sans-IO crate — inject paths via config", allow-invalid = true },
  { path = "dirs::data_dir", reason = "sans-IO crate — inject paths via config", allow-invalid = true },

  # Sans-IO: network
  { path = "reqwest::Client::new", reason = "sans-IO crate — use a port trait for HTTP", allow-invalid = true },
  { path = "reqwest::get", reason = "sans-IO crate — use a port trait for HTTP", allow-invalid = true },
]
```

**`disallowed-types`** — ban I/O types entirely:
```toml
disallowed-types = [
  { path = "std::fs::File", reason = "sans-IO crate — use a port trait" },
  { path = "std::process::Command", reason = "sans-IO crate — use a port trait" },
  { path = "std::net::TcpStream", reason = "sans-IO crate — use a port trait" },
  { path = "std::net::TcpListener", reason = "sans-IO crate — use a port trait" },
]
```

### Rollout

1. Add `clippy.toml` to `crates/auths-sdk/` and `crates/auths-crypto/` first (already clean)
2. Run `cargo clippy -p auths-sdk -p auths-crypto` to confirm no violations
3. Add to `crates/auths-id/` — fix any violations surfaced
4. Fix the 2 violations in `auths-core` (`config.rs`, `allowed_signers.rs`), then add its `clippy.toml`

## Testing Improvements

Sans-IO enables faster, more deterministic tests. The infrastructure is partially built — here's what exists and what's missing.

### What exists today

**Fakes** (`auths-sdk/src/testing/fakes/`):

| Fake | Port it stubs | Features |
|------|--------------|----------|
| `FakeGitLogProvider` | `GitLogProvider` | In-memory commits, configurable via `with_commits()`, `poisoned()` for error paths |
| `FakeAgentProvider` | `AgentSigningPort` | Canned signing results, **call recording** via `AgentCall` enum |
| `FakeCryptoDiagnosticProvider` | `CryptoDiagnosticProvider` | Configurable ssh-keygen check results |
| `FakeGitDiagnosticProvider` | `GitDiagnosticProvider` | Configurable git version and config lookups |

**Fakes** (`auths-id/src/testing/`):

| Fake | What it stubs | Features |
|------|--------------|----------|
| `FakeRegistryBackend` | `RegistryBackend` | In-memory event storage, key state derivation, attestation tracking |
| `FakeIdentityStorage` | `IdentityStorage` | In-memory identity store |
| `FakeAttestationSink/Source` | `AttestationSink/Source` | In-memory attestation storage |

**Fixtures** (`auths-id/src/testing/fixtures.rs`):
- `test_inception_event()` — generates valid signed KERI events
- `test_attestation()` — builds minimal attestation fixtures

**Contract test macros** (`auths-sdk/src/testing/contracts/`):
- `git_log_provider_contract_tests!` — generates 3 test cases that any `GitLogProvider` implementation must pass (walk all, walk with limit=1, walk with limit=0)

**Context builder** (`auths-sdk/src/context.rs`):
- Optional fields default to no-ops (`NoopSink`, `NoopAgentProvider`)
- Tests use `PrefilledPassphraseProvider` + `MemoryKeychainHandle`

### What's missing

**Missing fakes — no stub exists for these ports:**

| Port | Crate | Impact |
|------|-------|--------|
| `GitConfigProvider` | `auths-sdk` | Can't test git config workflows without real `git config` |
| `ArtifactSource` | `auths-sdk` | Tests inline throwaway `InMemoryArtifact` structs instead of using a shared fake |
| `PairingRelayClient` | `auths-core` | Can't test pairing workflows without a relay |
| `OAuthDeviceFlowProvider` | `auths-core` | Can't test platform claim flows without real OAuth |
| `RegistryClaimClient` | `auths-core` | Can't test registry registration without real HTTP |
| `SshConfigProvider` | `auths-sdk` | New port from cli_cleanup Task 1 — needs a fake from the start |
| `RegistrySyncProvider` | `auths-sdk` | New port from cli_cleanup Task 6 — needs a fake from the start |
| `IdentityResetProvider` | `auths-sdk` | New port from cli_cleanup Task 4 — needs a fake from the start |

**Missing contract test macros:**
- Only `GitLogProvider` has a contract macro. Every port trait should have one so that fakes and real adapters are tested against the same behavioral spec.

**Integration tests still use real I/O:**
- `auths-sdk/tests/cases/helpers.rs` creates real git repos via `tempfile::TempDir` + `git2::Repository`
- ~20 references to `tempfile::TempDir` across integration tests
- These are slow (disk I/O, git init) and flaky (temp dir cleanup, git state)

### Improvement plan

#### 1. Add missing fakes for existing ports

For each port without a fake, add one to `auths-sdk/src/testing/fakes/` or `auths-id/src/testing/`. Follow the `FakeAgentProvider` pattern — it's the most complete:
- Constructor with sensible defaults
- Builder methods for configuring responses (`with_commits()`, `sign_fails_with()`, etc.)
- Call recording where useful (lets tests assert "this method was called with these args")

```rust
// Example: FakeGitConfigProvider
pub struct FakeGitConfigProvider {
    configs: HashMap<String, String>,
    set_calls: Mutex<Vec<(String, String)>>,
}

impl FakeGitConfigProvider {
    pub fn new() -> Self { /* empty config */ }
    pub fn with_config(mut self, key: &str, value: &str) -> Self { /* ... */ }
    pub fn set_calls(&self) -> Vec<(String, String)> { /* ... */ }
}

impl GitConfigProvider for FakeGitConfigProvider {
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError> {
        self.set_calls.lock().unwrap().push((key.into(), value.into()));
        Ok(())
    }
}
```

#### 2. Add contract test macros for all ports

Extend the `git_log_provider_contract_tests!` pattern to every port trait. Each macro generates tests that both fakes and real adapters must pass:

```rust
// In auths-sdk/src/testing/contracts/git_config.rs
macro_rules! git_config_provider_contract_tests {
    ($provider_factory:expr) => {
        #[test]
        fn set_and_read_roundtrip() {
            let provider = $provider_factory();
            provider.set("gpg.format", "ssh").unwrap();
            // contract: after set, value should be retrievable
        }
    };
}
```

This ensures fakes behave identically to real adapters.

#### 3. Add fakes for new ports (cli_cleanup plan)

Every new port trait from the cli_cleanup plan should ship with a fake on day one:

| New port | Fake | Key test scenarios |
|----------|------|-------------------|
| `SshConfigProvider` | `FakeSshConfigProvider` | Config with/without UseKeychain, empty config, write succeeds/fails |
| `RegistrySyncProvider` | `FakeRegistrySyncProvider` | Fetch succeeds/fails, push succeeds/fails, no remote |
| `IdentityResetProvider` | `FakeIdentityResetProvider` | Identity exists/doesn't, stale signers entries, ref exists/doesn't |
| `KeyBackupProvider` | `FakeKeyBackupProvider` | Backup not yet done, backup already done, export fails |

#### 4. Migrate integration tests off real I/O

The `build_test_context()` helper in `auths-sdk/tests/cases/helpers.rs` creates real git repos. Migrate tests that don't need real git to use `FakeRegistryBackend` + `FakeIdentityStorage` instead:

- **Keep real I/O for:** true end-to-end tests (signing a real commit, verifying a real signature)
- **Move to fakes for:** workflow logic tests (what happens when registry is missing, when signers file has stale entries, when reset is called with no repo)

Target: tests that currently take seconds (temp dir + git init) should run in microseconds with in-memory fakes.

#### 5. Consolidate inline fakes

Several test files define throwaway fake structs (e.g., `InMemoryArtifact` in artifact tests). Move these to `auths-sdk/src/testing/fakes/` so they're shared and maintained in one place.

---

## Source Map

| Area | File | What it does |
|------|------|-------------|
| Config violation | `crates/auths-core/src/config.rs` | `std::fs::read_to_string` (L321), `create_dir_all` (L340), `write` (L344) |
| Allowed signers violation | `crates/auths-sdk/src/workflows/allowed_signers.rs` | `std::fs::read_to_string` (L282), `create_dir_all` (L305) |
| SDK ports module | `crates/auths-sdk/src/ports/mod.rs` | Exports: agent, artifact, diagnostics, git, git_config, pairing, platform |
| GitDiagnosticProvider | `crates/auths-sdk/src/ports/diagnostics.rs` | Trait (L64): `check_git_version()`, `get_git_config()` |
| CryptoDiagnosticProvider | `crates/auths-sdk/src/ports/diagnostics.rs` | Trait (L78): `check_ssh_keygen_available()` |
| GitConfigProvider | `crates/auths-sdk/src/ports/git_config.rs` | Trait (L19): `set(key, value)` |
| SDK fakes | `crates/auths-sdk/src/testing/fakes/` | `agent.rs`, `diagnostics.rs`, `git.rs` |
| ID fakes | `crates/auths-id/src/testing/fakes/` | `attestation.rs`, `identity_storage.rs`, `registry.rs` |
| ID fixtures | `crates/auths-id/src/testing/fixtures.rs` | `test_inception_event()` (L31), `test_attestation()` |
| Contract macros | `crates/auths-sdk/src/testing/contracts/` | `git_log_provider_contract_tests!` |
| Integration helpers | `crates/auths-sdk/tests/cases/helpers.rs` | `build_test_context()` (L24), `tempfile::TempDir` (L77, L91) |
| Composition root | `crates/auths-cli/src/factories/mod.rs` | `build_config()` (L37), `build_agent_provider()` (L103), `init_audit_sinks()` (L80) |
| Workspace clippy | `clippy.toml` | 4 `disallowed-methods` rules (ClockProvider, UuidProvider, etc.) |

## Execution Order

Tasks have dependencies. Do them in this order:

1. **Task 1** (clippy enforcement for `auths-sdk` + `auths-crypto`) — standalone, these crates are already clean
2. **Task 2** (missing fakes for existing ports) — standalone, no deps
3. **Task 3** (contract test macros) — after task 2 (macros test the fakes)
4. **Task 4** (fix `allowed_signers.rs` violation) — after task 2 (needs a fake to test the refactored code)
5. **Task 5** (fix `config.rs` violation) — after task 2 (same reason)
6. **Task 6** (clippy enforcement for `auths-id`) — after tasks 4, 5 (may surface violations)
7. **Task 7** (clippy enforcement for `auths-core`) — after task 5 (config.rs must be fixed first)
8. **Task 8** (consolidate inline fakes) — after task 2 (builds on shared fakes)
9. **Task 9** (migrate integration tests off real I/O) — last (needs all fakes in place)

## Tasks

### Task 1: Add per-crate clippy.toml to `auths-sdk` and `auths-crypto`

**Problem:** No compile-time enforcement prevents someone from adding `std::fs` to these crates.

**Files to create:**
- `crates/auths-sdk/clippy.toml`
- `crates/auths-crypto/clippy.toml`

Both files have identical content. They must duplicate the workspace rules (clippy does not merge configs) and add sans-IO bans. Use the exact config from the "What to disallow" section above.

**Verify:**
```bash
cargo clippy -p auths-sdk -p auths-crypto 2>&1 | grep "disallowed"
# Should return nothing — these crates are already clean
```

**Done when:** `cargo clippy -p auths-sdk -p auths-crypto` passes with zero warnings.

---

### Task 2: Add missing fakes for existing ports

**Problem:** 3 existing port traits have no fake implementation, making workflows hard to test without real I/O.

**Files to create:**

**2a. `FakeGitConfigProvider`**

**File:** `crates/auths-sdk/src/testing/fakes/git_config.rs` (new)

Implements `GitConfigProvider` (defined at `crates/auths-sdk/src/ports/git_config.rs` L19).

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use crate::ports::git_config::{GitConfigProvider, GitConfigError};

pub struct FakeGitConfigProvider {
    configs: Mutex<HashMap<String, String>>,
    set_calls: Mutex<Vec<(String, String)>>,
    fail_on_set: Mutex<Option<String>>,
}

impl FakeGitConfigProvider {
    pub fn new() -> Self {
        Self {
            configs: Mutex::new(HashMap::new()),
            set_calls: Mutex::new(Vec::new()),
            fail_on_set: Mutex::new(None),
        }
    }

    pub fn with_config(self, key: &str, value: &str) -> Self {
        self.configs.lock().unwrap().insert(key.into(), value.into());
        self
    }

    pub fn set_fails_with(self, msg: &str) -> Self {
        *self.fail_on_set.lock().unwrap() = Some(msg.into());
        self
    }

    pub fn set_calls(&self) -> Vec<(String, String)> {
        self.set_calls.lock().unwrap().clone()
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.configs.lock().unwrap().get(key).cloned()
    }
}

impl GitConfigProvider for FakeGitConfigProvider {
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError> {
        if let Some(msg) = self.fail_on_set.lock().unwrap().as_ref() {
            return Err(GitConfigError::CommandFailed(msg.clone()));
        }
        self.set_calls.lock().unwrap().push((key.into(), value.into()));
        self.configs.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
}
```

Follow the `FakeAgentProvider` pattern (call recording, builder methods, configurable failures).

**2b. `FakeArtifactSource`**

**File:** `crates/auths-sdk/src/testing/fakes/artifact.rs` (new)

Implements `ArtifactSource` (defined at `crates/auths-sdk/src/ports/artifact.rs`). Replace the inline `InMemoryArtifact` structs scattered across test files.

```rust
use crate::ports::artifact::{ArtifactSource, ArtifactDigest, ArtifactMetadata, ArtifactError};

pub struct FakeArtifactSource {
    digest: ArtifactDigest,
    metadata: ArtifactMetadata,
}

impl FakeArtifactSource {
    pub fn new(name: &str, content: &[u8]) -> Self {
        // compute sha256 of content, build digest + metadata
        todo!()
    }
}

impl ArtifactSource for FakeArtifactSource {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> { Ok(self.digest.clone()) }
    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> { Ok(self.metadata.clone()) }
}
```

**2c. Register in mod.rs**

**File:** `crates/auths-sdk/src/testing/fakes/mod.rs`

Add exports:
```rust
mod git_config;
mod artifact;
pub use git_config::FakeGitConfigProvider;
pub use artifact::FakeArtifactSource;
```

**Verify:**
```bash
cargo test -p auths-sdk 2>&1 | tail -5
# Should compile and all existing tests still pass
```

**Done when:** Both fakes compile, are exported from `auths_sdk::testing::fakes`, and existing tests pass.

---

### Task 3: Add contract test macros for all ports

**Problem:** Only `GitLogProvider` has a contract macro (`crates/auths-sdk/src/testing/contracts/`). Fakes can silently diverge from real adapter behavior.

**Files to create:**

One file per port trait in `crates/auths-sdk/src/testing/contracts/`:
- `git_config.rs` — tests for `GitConfigProvider`
- `diagnostics.rs` — tests for `GitDiagnosticProvider` and `CryptoDiagnosticProvider`
- `artifact.rs` — tests for `ArtifactSource`

**Pattern to follow** (from `crates/auths-sdk/src/testing/contracts/git_log.rs`):

```rust
// crates/auths-sdk/src/testing/contracts/git_config.rs
#[macro_export]
macro_rules! git_config_provider_contract_tests {
    ($provider_factory:expr) => {
        #[test]
        fn set_stores_value() {
            let provider = $provider_factory();
            let result = provider.set("gpg.format", "ssh");
            assert!(result.is_ok());
        }

        #[test]
        fn set_overwrites_existing() {
            let provider = $provider_factory();
            provider.set("gpg.format", "ssh").unwrap();
            provider.set("gpg.format", "gpg").unwrap();
            // contract: second set should not error
        }
    };
}
```

**Register:** Add modules to `crates/auths-sdk/src/testing/contracts/mod.rs`.

**Use in fake tests:**
```rust
// In crates/auths-sdk/src/testing/fakes/git_config.rs (bottom of file)
#[cfg(test)]
mod tests {
    use super::*;
    git_config_provider_contract_tests!(|| FakeGitConfigProvider::new());
}
```

**Verify:**
```bash
cargo test -p auths-sdk contract 2>&1
# Should show contract tests passing for all fakes
```

**Done when:** Every port trait with a fake also has a contract macro, and the fake passes all contract tests.

---

### Task 4: Fix `allowed_signers.rs` violation

**Problem:** `crates/auths-sdk/src/workflows/allowed_signers.rs` calls `std::fs::read_to_string` (L282) and `std::fs::create_dir_all` (L305) directly.

**Fix:**

**4a. Define port trait**

**File:** `crates/auths-sdk/src/ports/allowed_signers.rs` (new)

```rust
use crate::ports::diagnostics::DiagnosticError;

pub trait AllowedSignersStore: Send + Sync {
    /// Read the allowed_signers file content. Returns empty string if file doesn't exist.
    fn read(&self, path: &std::path::Path) -> Result<String, std::io::Error>;

    /// Write content to the allowed_signers file, creating parent dirs as needed.
    fn write(&self, path: &std::path::Path, content: &str) -> Result<(), std::io::Error>;
}
```

Register in `crates/auths-sdk/src/ports/mod.rs`:
```rust
pub mod allowed_signers;
```

**4b. Refactor workflow to accept trait**

**File:** `crates/auths-sdk/src/workflows/allowed_signers.rs`

Change `AllowedSigners` to accept the store as a generic or `Arc<dyn AllowedSignersStore>`:

- Replace `std::fs::read_to_string(&path)` at L282 with `store.read(&path)`
- Replace `std::fs::create_dir_all(parent)` at L305 + the tempfile write with `store.write(&path, &content)`

**4c. Create adapter**

**File:** `crates/auths-cli/src/adapters/allowed_signers_store.rs` (new)

```rust
pub struct FileAllowedSignersStore;

impl AllowedSignersStore for FileAllowedSignersStore {
    fn read(&self, path: &Path) -> Result<String, std::io::Error> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e),
        }
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Use tempfile for atomic write (preserve existing behavior from L314-328)
        let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
        std::io::Write::write_all(&mut tmp, content.as_bytes())?;
        tmp.persist(path)?;
        Ok(())
    }
}
```

**4d. Create fake**

**File:** `crates/auths-sdk/src/testing/fakes/allowed_signers_store.rs` (new)

```rust
pub struct FakeAllowedSignersStore {
    files: Mutex<HashMap<PathBuf, String>>,
}

impl FakeAllowedSignersStore {
    pub fn new() -> Self { Self { files: Mutex::new(HashMap::new()) } }
    pub fn with_file(self, path: &Path, content: &str) -> Self { /* ... */ }
    pub fn content(&self, path: &Path) -> Option<String> { /* ... */ }
}

impl AllowedSignersStore for FakeAllowedSignersStore {
    fn read(&self, path: &Path) -> Result<String, std::io::Error> {
        Ok(self.files.lock().unwrap().get(path).cloned().unwrap_or_default())
    }
    fn write(&self, path: &Path, content: &str) -> Result<(), std::io::Error> {
        self.files.lock().unwrap().insert(path.to_path_buf(), content.into());
        Ok(())
    }
}
```

**4e. Wire up in composition root**

**File:** `crates/auths-cli/src/factories/mod.rs` — or wherever `AllowedSigners` is instantiated. Pass `FileAllowedSignersStore` as the adapter.

**Verify:**
```bash
grep -r "std::fs" crates/auths-sdk/src/workflows/allowed_signers.rs
# Should return nothing
cargo test -p auths-sdk 2>&1 | tail -5
# All tests pass
```

**Done when:** `allowed_signers.rs` has zero `std::fs` calls, all tests pass, and `FakeAllowedSignersStore` exists.

---

### Task 5: Fix `config.rs` violation

**Problem:** `crates/auths-core/src/config.rs` calls `std::fs::read_to_string` (L321), `create_dir_all` (L340), `write` (L344) directly.

**Fix:**

**5a. Define port trait**

**File:** `crates/auths-core/src/ports/config_store.rs` (new, or add to existing ports module)

```rust
pub trait ConfigStore: Send + Sync {
    fn load(&self) -> Result<Option<String>, std::io::Error>;
    fn save(&self, content: &str) -> Result<(), std::io::Error>;
}
```

**5b. Refactor** `load_config()` and `save_config()` to accept `&dyn ConfigStore` instead of reading/writing files directly.

**5c. Create adapter**

**File:** `crates/auths-cli/src/adapters/config_store.rs` (new)

```rust
pub struct FileConfigStore {
    path: PathBuf,
}

impl ConfigStore for FileConfigStore {
    fn load(&self) -> Result<Option<String>, std::io::Error> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn save(&self, content: &str) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, content)
    }
}
```

**5d. Create fake**

**File:** `crates/auths-core/src/testing/` (or wherever auths-core testing lives)

```rust
pub struct FakeConfigStore {
    content: Mutex<Option<String>>,
}
```

**Verify:**
```bash
grep -r "std::fs" crates/auths-core/src/config.rs
# Should return nothing
cargo test -p auths-core 2>&1 | tail -5
```

**Done when:** `config.rs` has zero `std::fs` calls, all tests pass, `FakeConfigStore` exists.

---

### Task 6: Add per-crate clippy.toml to `auths-id`

**Problem:** `auths-id` should be sans-IO but has no compile-time enforcement.

**File to create:** `crates/auths-id/clippy.toml`

Same content as Task 1 (duplicate workspace rules + sans-IO bans).

**Verify:**
```bash
cargo clippy -p auths-id 2>&1 | grep "disallowed"
# Fix any violations found. Likely in hooks.rs (install_cache_hooks uses std::fs).
# Note: hooks.rs may need to stay in auths-id with an #[allow] or move to an adapter.
```

**Done when:** `cargo clippy -p auths-id` passes with zero `disallowed` warnings (either by fixing violations or moving I/O code to an infra crate).

---

### Task 7: Add per-crate clippy.toml to `auths-core`

**Problem:** `auths-core` should be sans-IO but has no compile-time enforcement. Depends on Task 5 (config.rs must be fixed first).

**File to create:** `crates/auths-core/clippy.toml`

Same content as Task 1.

**Verify:**
```bash
cargo clippy -p auths-core 2>&1 | grep "disallowed"
# Should pass after Task 5 is done
```

**Done when:** `cargo clippy -p auths-core` passes with zero `disallowed` warnings.

---

### Task 8: Consolidate inline fakes

**Problem:** Test files define throwaway fake structs (e.g., `InMemoryArtifact`) instead of using shared fakes.

**Steps:**
1. Search for `struct.*Fake\|struct.*Mock\|struct.*InMemory\|struct.*Stub` in test files under `crates/auths-sdk/tests/`
2. For each inline fake, check if a shared fake exists in `crates/auths-sdk/src/testing/fakes/`
3. If yes, replace the inline fake with the shared one
4. If no, move the inline fake to the shared fakes module

**Verify:**
```bash
cargo test -p auths-sdk 2>&1 | tail -5
# All tests pass with shared fakes
```

**Done when:** No inline fake structs remain in test files that duplicate shared fakes.

---

### Task 9: Migrate integration tests off real I/O

**Problem:** `crates/auths-sdk/tests/cases/helpers.rs` creates real git repos via `tempfile::TempDir` (L77, L91) + `git2::Repository::init` (L43). These tests are slow and non-deterministic.

**Steps:**

1. Identify which tests actually need real git (signing a real commit, verifying a real signature) vs. which just test workflow logic
2. For workflow logic tests, replace `build_test_context()` / `build_empty_test_context()` with a version that uses `FakeRegistryBackend` + `FakeIdentityStorage` (from `auths-id/src/testing/fakes/`)
3. Keep `build_test_context()` for true end-to-end tests, but add a `build_fake_test_context()` alternative

```rust
// crates/auths-sdk/tests/cases/helpers.rs
pub fn build_fake_test_context() -> AuthsContext {
    let registry = Arc::new(FakeRegistryBackend::new());
    let identity = Arc::new(FakeIdentityStorage::new());
    let attestation_sink = Arc::new(FakeAttestationSink::new());
    let attestation_source = Arc::new(FakeAttestationSource::new());
    // ... wire up with AuthsContext::builder()
}
```

4. Migrate tests one by one. Target: tests that don't assert on git state should use fakes.

**Verify:**
```bash
cargo test -p auths-sdk 2>&1 | tail -5
# All tests pass
# Bonus: measure time before/after — fake-based tests should be 10-100x faster
```

**Done when:** Workflow logic tests use in-memory fakes. `tempfile::TempDir` usage is limited to true end-to-end tests only.
