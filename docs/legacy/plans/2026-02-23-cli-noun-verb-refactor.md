# CLI Noun-Verb Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure the CLI from a flat 28-command namespace into a predictable `auths <noun> <verb>` grammar with a shared `ExecutableCommand` trait, slim `CliConfig`, and clean module boundaries.

**Architecture:** Extract the monolithic `main.rs` (350 lines, 28-arm match) into `cli.rs` (parser), `config.rs` (slim global context), and per-noun command modules each implementing an `ExecutableCommand` trait. Top-level workflow commands (`init`, `sign`, `verify`, `status`, `doctor`, `tutorial`, `completions`, `emergency`) act as ergonomic shortcuts. All other commands follow noun-verb grammar. Hidden namespaces (`commit`, `debug`) serve machine and plumbing use cases.

**Tech Stack:** Rust 1.93, clap 4 (derive), tokio 1 (rt-multi-thread), anyhow, native async traits (no async_trait macro).

**Worktree:** `.worktrees/refactor-cli` on branch `refactor/cli-cleanup`

**Design doc:** `docs/plans/2026-02-23-cli-noun-verb-refactor-design.md`

---

## Conventions Used Throughout This Plan

**All file paths** are relative to `crates/auths-cli/` unless otherwise noted.

**The migration pattern** for every command group is identical:
1. Create `src/commands/<noun>/mod.rs` with a `<Noun>Cmd` struct + subcommand enum
2. Implement `ExecutableCommand` on `<Noun>Cmd` which delegates to subcommand variants
3. Each subcommand variant implements `ExecutableCommand` with the existing handler body
4. The existing `handle_<noun>()` function's logic moves into `execute()`
5. Parameters that were previously threaded from `main.rs` are resolved inside `execute()` from `CliConfig` (globals) or from `self` (command-specific args)

**Registry overrides** (identity_ref, identity_blob, attestation_prefix, attestation_blob) are currently global CLI flags but only used by ~5 commands. In the new design, commands that need them declare a shared `RegistryOverrides` struct via `#[command(flatten)]`.

---

## Task 1: Create the ExecutableCommand trait and CliConfig

**Files:**
- Create: `src/commands/executable.rs`
- Create: `src/config.rs`

**Step 1: Write `src/commands/executable.rs`**

```rust
use anyhow::Result;
use crate::config::CliConfig;

pub trait ExecutableCommand {
    fn execute(&self, ctx: &CliConfig) -> impl std::future::Future<Output = Result<()>> + Send;
}
```

Note: This is Rust 1.93's native async-in-trait using RPITIT. No `#[async_trait]` needed.

**Step 2: Write `src/config.rs`**

```rust
use std::path::PathBuf;
use std::sync::Arc;
use std::io::IsTerminal;

use auths_core::signing::PassphraseProvider;

/// Output format for command results.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Slim global context. Domain-specific args stay in command structs.
pub struct CliConfig {
    pub repo_path: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub is_interactive: bool,
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
}

impl CliConfig {
    pub fn is_json(&self) -> bool {
        matches!(self.output_format, OutputFormat::Json)
    }
}
```

**Step 3: Create `src/commands/registry_overrides.rs`**

Shared flattened args struct for commands that need identity/attestation overrides:

```rust
use clap::Args;

/// Shared overrides for commands that interact with the identity registry.
///
/// These were previously global CLI flags. Now they live on the commands
/// that actually use them.
#[derive(Args, Debug, Clone, Default)]
pub struct RegistryOverrides {
    #[arg(
        long = "identity-ref",
        value_name = "GIT_REF",
        help = "Override Git ref for the identity commit [default: refs/auths/identity]"
    )]
    pub identity_ref: Option<String>,

    #[arg(
        long = "identity-blob",
        value_name = "FILENAME",
        help = "Override blob filename for identity data [default: identity.json]"
    )]
    pub identity_blob: Option<String>,

    #[arg(
        long = "attestation-prefix",
        value_name = "GIT_REF_PREFIX",
        help = "Override base Git ref prefix for device authorizations [default: refs/auths/devices/nodes]"
    )]
    pub attestation_prefix: Option<String>,

    #[arg(
        long = "attestation-blob",
        value_name = "FILENAME",
        help = "Override blob filename for device authorization data [default: attestation.json]"
    )]
    pub attestation_blob: Option<String>,
}
```

**Step 4: Build to verify**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
Expected: May have unused warnings but should compile.

**Step 5: Commit**

```bash
git add src/commands/executable.rs src/config.rs src/commands/registry_overrides.rs
git commit -m "feat(cli): add ExecutableCommand trait, CliConfig, and RegistryOverrides"
```

---

## Task 2: Create core/ module (move provider, types, pubkey_cache)

**Files:**
- Create: `src/core/mod.rs`
- Move: `src/provider.rs` -> `src/core/provider.rs`
- Move: `src/types.rs` -> `src/core/types.rs`
- Move: `src/pubkey_cache.rs` -> `src/core/pubkey_cache.rs`
- Modify: `src/lib.rs` (update module declarations and re-exports)
- Modify: `src/main.rs` (update imports)

**Step 1: Create directory and move files**

```bash
mkdir -p src/core
git mv src/provider.rs src/core/provider.rs
git mv src/types.rs src/core/types.rs
git mv src/pubkey_cache.rs src/core/pubkey_cache.rs
```

**Step 2: Write `src/core/mod.rs`**

```rust
pub mod provider;
pub mod pubkey_cache;
pub mod types;
```

**Step 3: Update `src/lib.rs`**

Replace the old module declarations with:

```rust
pub mod commands;
pub mod config;
pub mod core;
pub mod error;
pub mod error_renderer;
pub mod output;

pub use core::pubkey_cache::{cache_pubkey, clear_cached_pubkey, get_cached_pubkey};
pub use core::types::ExportFormat;
pub use output::{Output, set_json_mode};
```

**Step 4: Update `src/main.rs` imports**

Replace:
```rust
mod provider;
mod types;
```
with:
```rust
mod core;
```

And update the `use` statements:
- `crate::provider::*` -> `crate::core::provider::*`
- `crate::types::*` -> `crate::core::types::*`

**Step 5: Update all internal references**

Search for `crate::provider` and `crate::types` across all command files and update to `crate::core::provider` and `crate::core::types`. Key files:
- `src/commands/init.rs`: uses `crate::provider::CliPassphraseProvider`
- `src/commands/key.rs`: uses `crate::types::ExportFormat`
- `src/main.rs`: uses both

**Step 6: Update `src/bin/sign.rs`**

Change: `use auths_cli::pubkey_cache::*` -> `use auths_cli::core::pubkey_cache::*`

Note: The `lib.rs` re-exports (`pub use core::pubkey_cache::...`) keep the old paths working for external consumers, but internal code should use the new paths. Since `bin/sign.rs` uses `auths_cli::pubkey_cache::cache_pubkey` via the re-export, it will still work. Verify with build.

**Step 7: Build to verify**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
Expected: PASS

**Step 8: Commit**

```bash
git add -A
git commit -m "refactor(cli): move provider, types, pubkey_cache into core/ module"
```

---

## Task 3: Create ux/ module (move output.rs)

**Files:**
- Create: `src/ux/mod.rs`
- Create: `src/ux/format.rs` (from `src/output.rs`)
- Create: `src/ux/dialogs.rs` (empty placeholder)
- Modify: `src/lib.rs`
- Modify: All files that import `crate::output::*`

**Step 1: Create directory and move**

```bash
mkdir -p src/ux
git mv src/output.rs src/ux/format.rs
```

**Step 2: Write `src/ux/mod.rs`**

```rust
pub mod dialogs;
pub mod format;

pub use format::{JsonResponse, Output, is_json_mode, set_json_mode};
```

**Step 3: Write `src/ux/dialogs.rs`**

```rust
// Placeholder for shared UX components (spinners, prompts, progress bars).
// Will be populated as commands are migrated.
```

**Step 4: Update `src/lib.rs`**

Replace `pub mod output;` with `pub mod ux;` and update re-exports:

```rust
pub use ux::format::{Output, set_json_mode};
```

**Step 5: Create a backward-compat `src/output.rs` shim**

To avoid updating every consumer at once, create a thin re-export:

```rust
pub use crate::ux::format::*;
```

This lets us migrate consumers incrementally. Keep `pub mod output;` in `lib.rs` temporarily alongside `pub mod ux;`.

**Step 6: Update `src/main.rs`**

Change `mod output;` to `mod ux;` and `mod output;` (keep both during transition), and update the direct import:

```rust
use crate::ux::format::set_json_mode;
```

**Step 7: Build to verify**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
Expected: PASS (shim keeps old paths working)

**Step 8: Run tests**

Run: `cargo nextest run -p auths-cli --no-fail-fast 2>&1 | tail -20`
Expected: Same 127 pass / 1 pre-existing fail as baseline.

**Step 9: Commit**

```bash
git add -A
git commit -m "refactor(cli): move output.rs into ux/format.rs with backward-compat shim"
```

---

## Task 4: Create errors/ module (move error.rs, error_renderer.rs)

**Files:**
- Create: `src/errors/mod.rs`
- Move: `src/error.rs` -> `src/errors/cli_error.rs`
- Move: `src/error_renderer.rs` -> `src/errors/renderer.rs`
- Modify: `src/lib.rs`
- Create backward-compat shims: `src/error.rs`, `src/error_renderer.rs`

**Step 1: Create directory and move**

```bash
mkdir -p src/errors
git mv src/error.rs src/errors/cli_error.rs
git mv src/error_renderer.rs src/errors/renderer.rs
```

**Step 2: Write `src/errors/mod.rs`**

```rust
pub mod cli_error;
pub mod renderer;

pub use cli_error::CliError;
```

**Step 3: Create backward-compat shims**

`src/error.rs`:
```rust
pub use crate::errors::cli_error::*;
```

`src/error_renderer.rs`:
```rust
pub use crate::errors::renderer::*;
```

**Step 4: Update `src/lib.rs`**

Add `pub mod errors;` alongside existing `pub mod error;` and `pub mod error_renderer;`.

**Step 5: Update internal references in `src/errors/renderer.rs`**

Change: `use crate::error::CliError;` -> `use crate::errors::cli_error::CliError;`
Change: `use crate::output::Output;` -> `use crate::ux::format::Output;`

**Step 6: Update `src/bin/sign.rs`**

Change: `auths_cli::error_renderer::render_error` — this still works via re-export in lib.rs. Verify with build.

**Step 7: Build and test**

Run: `cargo build --package auths-cli && cargo nextest run -p auths-cli --no-fail-fast 2>&1 | tail -20`
Expected: Compile + same test results as baseline.

**Step 8: Commit**

```bash
git add -A
git commit -m "refactor(cli): move error.rs and error_renderer.rs into errors/ module"
```

---

## Task 5: Create the new cli.rs router

This is the declarative parser. We build it alongside the old `main.rs` so both can coexist during migration.

**Files:**
- Create: `src/cli.rs`

**Step 1: Write `src/cli.rs`**

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::config::OutputFormat;

// Re-use existing command structs during migration.
// These imports will change as commands migrate to new module paths.
use crate::commands::agent::AgentCommand;
use crate::commands::artifact::ArtifactCommand;
use crate::commands::audit::AuditCommand;
use crate::commands::cache::CacheCommand;
use crate::commands::completions::CompletionsCommand;
use crate::commands::device::DeviceCommand;
use crate::commands::doctor::DoctorCommand;
use crate::commands::emergency::EmergencyCommand;
use crate::commands::git::GitCommand;
use crate::commands::id::IdCommand;
use crate::commands::index::IndexCommand;
use crate::commands::init::InitCommand;
use crate::commands::key::KeyCommand;
use crate::commands::learn::LearnCommand;
use crate::commands::migrate::MigrateCommand;
use crate::commands::org::OrgCommand;
use crate::commands::pair::PairCommand;
use crate::commands::policy::PolicyCommand;
use crate::commands::sign::SignCommand;
use crate::commands::status::StatusCommand;
use crate::commands::trust::TrustCommand;
use crate::commands::unified_verify::UnifiedVerifyCommand;
use crate::commands::utils::UtilCommand;
use crate::commands::verify::VerifyCommand;
use crate::commands::verify_commit::VerifyCommitCommand;
use crate::commands::witness::WitnessCommand;

#[derive(Parser, Debug)]
#[command(name = "auths")]
#[command(
    about = "auths \u{2014} cryptographic identity for developers",
    long_about = "Commands:\n  init       Set up your cryptographic identity and Git signing\n  sign       Sign a Git commit or artifact\n  verify     Verify a signed commit or attestation\n  status     Show identity and signing status\n  doctor     Run health checks\n  tutorial   Interactive tutorial\n\nDomain commands:\n  auths id, auths device, auths key, auths policy, auths git, ...\n\nRun `auths <command> --help` for details."
)]
#[command(version)]
pub struct AuthsCli {
    #[command(subcommand)]
    pub command: RootCommand,

    /// Output format (text or json).
    #[arg(long, value_enum, default_value = "text", global = true, help_heading = "Global Options")]
    pub output: OutputFormat,

    /// Shorthand for --output json.
    #[arg(long, global = true, help_heading = "Global Options")]
    pub json: bool,

    /// Path to the identity repository.
    #[arg(long, value_parser, global = true, help_heading = "Global Options")]
    pub repo: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
pub enum RootCommand {
    // === Top-level workflows (visible) ===
    /// Set up your cryptographic identity and Git signing.
    Init(InitCommand),
    /// Sign a Git commit or artifact.
    Sign(SignCommand),
    /// Verify a signed commit or attestation.
    Verify(UnifiedVerifyCommand),
    /// Show identity and signing status.
    Status(StatusCommand),
    /// Interactive tutorial to learn Auths concepts.
    Tutorial(LearnCommand),
    /// Run comprehensive health checks.
    Doctor(DoctorCommand),
    /// Generate shell completions.
    Completions(CompletionsCommand),
    /// Emergency incident response commands.
    Emergency(EmergencyCommand),

    // === Noun-verb domain (visible) ===
    /// Manage your cryptographic identity.
    Id(IdCommand),
    /// Manage authorized devices.
    Device(DeviceCommand),
    /// Manage keys in the platform keychain.
    Key(KeyCommand),
    /// Sign and verify arbitrary artifacts.
    Artifact(ArtifactCommand),
    /// Manage authorization policies.
    Policy(PolicyCommand),
    /// Git integration (allowed-signers, hooks).
    Git(GitCommand),
    /// Manage trusted identity roots.
    Trust(TrustCommand),
    /// Manage organizations.
    Org(OrgCommand),
    /// Generate signing audit reports.
    Audit(AuditCommand),
    /// SSH agent daemon management.
    Agent(AgentCommand),
    /// Manage the KERI witness server.
    Witness(WitnessCommand),

    // === Hidden (machine/internal) ===
    /// Git commit signing/verification (for .gitconfig bindings).
    #[command(hide = true)]
    Commit(CommitCmd),
    /// Low-level debugging commands.
    #[command(hide = true)]
    Debug(DebugCmd),
}

// --- Temporary stubs for new command groups ---
// These will be replaced with proper implementations in later tasks.

/// Hidden commands for .gitconfig integration.
#[derive(clap::Args, Debug)]
pub struct CommitCmd {
    #[command(subcommand)]
    pub command: CommitSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum CommitSubcommand {
    /// Sign a git commit (called by git via gpg.program).
    Sign(SignCommand),
    /// Verify a git commit signature.
    Verify(VerifyCommitCommand),
}

/// Hidden commands for low-level diagnostics.
#[derive(clap::Args, Debug)]
pub struct DebugCmd {
    #[command(subcommand)]
    pub command: DebugSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum DebugSubcommand {
    /// Manage local identity history cache.
    Cache(CacheCommand),
    /// Manage the device authorization index.
    Index(IndexCommand),
    /// Utility commands (derive identity ID, etc).
    Util(UtilCommand),
}
```

Note: This file initially re-uses all existing command structs. As we migrate each command group, the imports will shift to new module paths. The `pair` and `migrate` commands are absorbed into `device` and `id` respectively in later tasks.

**Step 2: Add `mod cli;` to `src/main.rs`**

Add at the top of `src/main.rs`: `mod cli;` — just the module declaration. Don't use it yet.

**Step 3: Build to verify**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
Expected: PASS (cli.rs is declared but not wired in yet)

**Step 4: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat(cli): add new declarative cli.rs router alongside existing main.rs"
```

---

## Task 6: Migrate the `id` command group (pattern-setting task)

This is the template for all subsequent command migrations. It demonstrates:
- Renaming `id init` to `id create`
- Absorbing `migrate` into `id migrate`
- Implementing `ExecutableCommand` on the new `IdCmd`
- Moving handler logic into `execute()`

**Files:**
- Create: `src/commands/id/mod.rs` (new directory)
- Move: `src/commands/id.rs` -> `src/commands/id/identity.rs` (rename to avoid collision)
- Move: `src/commands/migrate.rs` -> `src/commands/id/migrate.rs`
- Modify: `src/commands/mod.rs`

**Step 1: Restructure the id directory**

```bash
# Move old id.rs content into new directory
mkdir -p src/commands/id
git mv src/commands/id.rs src/commands/id/identity.rs
git mv src/commands/migrate.rs src/commands/id/migrate.rs
```

**Step 2: Write `src/commands/id/mod.rs`**

This module re-exports the existing structs and handler functions. The key changes:
- `IdSubcommand::Init` is renamed to `IdSubcommand::Create`
- `MigrateCommand` is added as `IdSubcommand::Migrate`

```rust
pub mod identity;
pub mod migrate;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::executable::ExecutableCommand;
use crate::commands::registry_overrides::RegistryOverrides;
use crate::config::CliConfig;

// Re-export the original types and handlers for backward compat during migration
pub use identity::{IdCommand as LegacyIdCommand, IdSubcommand as LegacyIdSubcommand, handle_id, LayoutPreset};
pub use migrate::{MigrateCommand, handle_migrate};

#[derive(Args, Debug)]
#[command(about = "Manage your cryptographic identity")]
pub struct IdCmd {
    #[command(subcommand)]
    pub command: IdSubcommand,

    #[command(flatten)]
    pub overrides: RegistryOverrides,
}

#[derive(Subcommand, Debug)]
pub enum IdSubcommand {
    /// Create a new cryptographic identity.
    Create {
        // Mirror args from the old IdSubcommand::Init
        // (these are the clap args from identity.rs Init variant)
    },
    /// Display current identity status.
    Show {
        // Mirror args from identity.rs Show variant
    },
    /// Rotate cryptographic keys.
    Rotate {
        // Mirror args from identity.rs Rotate variant
    },
    /// Import existing GPG or SSH keys into the identity.
    Migrate(MigrateCommand),
}
```

**IMPORTANT:** The above is a sketch. The actual implementation must copy the exact `#[arg(...)]` attributes from the existing `IdSubcommand::Init`, `Show`, and `Rotate` variants in `src/commands/id/identity.rs`. Read that file carefully for the full field definitions.

**Step 3: Implement `ExecutableCommand` on `IdCmd`**

The `execute()` method delegates to the existing handler functions. The key transformation: parameters that were threaded from `main.rs` (`repo_opt`, `identity_ref_override`, etc.) now come from `self.overrides` and `ctx`:

```rust
impl ExecutableCommand for IdCmd {
    async fn execute(&self, ctx: &CliConfig) -> Result<()> {
        // Build the legacy command struct and call the existing handler
        // This avoids rewriting all business logic at once
        let legacy_cmd = build_legacy_id_command(&self.command);
        handle_id(
            legacy_cmd,
            ctx.repo_path.clone(),
            self.overrides.identity_ref.clone(),
            self.overrides.identity_blob.clone(),
            self.overrides.attestation_prefix.clone(),
            self.overrides.attestation_blob.clone(),
            ctx.passphrase_provider.clone(),
        )
    }
}
```

Where `build_legacy_id_command` translates the new `IdSubcommand` variants into the old `LegacyIdSubcommand` variants. This is a bridging strategy that lets us migrate the router without rewriting every handler's internals.

**Step 4: Build to verify**

Run: `cargo build --package auths-cli 2>&1 | tail -5`

**Step 5: Commit**

```bash
git add -A
git commit -m "refactor(cli): migrate id command group with create/show/rotate/migrate subcommands"
```

---

## Task 7: Migrate the `device` command group (absorbs `pair`)

**Files:**
- Create: `src/commands/device/mod.rs` (new directory)
- Move: `src/commands/device.rs` -> `src/commands/device/authorization.rs`
- Move: `src/commands/pair/` -> `src/commands/device/pair/`
- Move: `src/commands/verify.rs` -> `src/commands/device/verify.rs` (attestation verification)
- Modify: `src/commands/mod.rs`

**Key changes:**
- `DeviceSubcommand::Link` stays as-is
- `PairCommand` becomes `DeviceSubcommand::Pair`
- `VerifyCommand` (verify-attestation) becomes `DeviceSubcommand::Verify`
- Implement `ExecutableCommand` using same bridging pattern as Task 6

**Step 1: Restructure**

```bash
mkdir -p src/commands/device
git mv src/commands/device.rs src/commands/device/authorization.rs
git mv src/commands/pair src/commands/device/pair
git mv src/commands/verify.rs src/commands/device/verify_attestation.rs
```

**Step 2: Write `src/commands/device/mod.rs`**

Create `DeviceCmd` with subcommands: `List`, `Pair`, `Revoke`, `Extend`, `Verify`.
Implement `ExecutableCommand` that delegates to existing handlers via bridging.

**Step 3: Build and commit**

```bash
cargo build --package auths-cli
git add -A
git commit -m "refactor(cli): migrate device command group, absorb pair and verify-attestation"
```

---

## Task 8: Migrate simple command groups (key, trust, policy, audit, emergency)

These are straightforward: each already has subcommands. The migration is:
1. Create directory, move the .rs file into it as `mod.rs` (or as a child module)
2. Create a `<Noun>Cmd` wrapper implementing `ExecutableCommand`
3. Bridge to existing handler

**For each of: key, trust, policy, audit, emergency:**

```bash
# Example for key:
mkdir -p src/commands/key
git mv src/commands/key.rs src/commands/key/mod.rs
# Then add ExecutableCommand impl at the bottom of the file
```

**Key-specific notes:**
- `key.rs` currently exports `KeyCommand`, `handle_key` — rename struct to `KeyCmd`
- `trust.rs` currently exports `TrustCommand`, `handle_trust` — rename to `TrustCmd`
- `policy.rs` currently exports `PolicyCommand`, `handle_policy` — rename to `PolicyCmd`
- `audit.rs` currently exports `AuditCommand`, `handle_audit` — rename to `AuditCmd`
- `emergency.rs` currently exports `EmergencyCommand`, `handle_emergency` — rename to `EmergencyCmd`

**For each file, add at the bottom:**

```rust
use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for KeyCmd {
    async fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_key(/* self fields */)
    }
}
```

**Build after each move.** Commit after all five are done:

```bash
git add -A
git commit -m "refactor(cli): migrate key, trust, policy, audit, emergency into noun directories"
```

---

## Task 9: Migrate remaining noun groups (git, org, agent, witness, artifact)

Same pattern as Task 8 but some require `RegistryOverrides`:

- **git** — uses `repo_override`, `attestation_prefix_override`, `attestation_blob_name_override`. Add `#[command(flatten)] overrides: RegistryOverrides`.
- **org** — uses all 6 overrides + passphrase_provider. Add `RegistryOverrides`.
- **agent** — no overrides needed. Simple move.
- **witness** — uses `repo_opt`. Gets it from `ctx.repo_path`.
- **artifact** — uses `repo_opt` + passphrase_provider. Gets both from `ctx`.

```bash
# Move each
for cmd in git org agent witness; do
    mkdir -p src/commands/$cmd
    git mv src/commands/$cmd.rs src/commands/$cmd/mod.rs
done
# artifact is already a directory — just add ExecutableCommand impl
```

**Commit:**

```bash
git add -A
git commit -m "refactor(cli): migrate git, org, agent, witness, artifact command groups"
```

---

## Task 10: Migrate top-level workflow commands

These stay as standalone files in `src/commands/`:

**init.rs** — Add `ExecutableCommand` impl:
```rust
impl ExecutableCommand for InitCommand {
    async fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_init(/* clone self into the expected struct */)
    }
}
```

Also absorb `provision.rs` by adding `--config` flag:
```rust
/// Path to a TOML config for headless provisioning.
#[clap(long)]
pub config: Option<PathBuf>,
```

When `config` is `Some`, call the provision logic. When `None`, run the interactive wizard.

**status.rs** — Add `ExecutableCommand` impl. Currently takes `repo: Option<PathBuf>` — get from `ctx.repo_path`.

**sign.rs** — Smart router. Already dispatches to artifact/commit signing. Add `ExecutableCommand` impl. Gets `repo_opt` and `passphrase_provider` from `ctx`.

**unified_verify.rs** — Rename file to `verify.rs` (the router). Already dispatches. Add `ExecutableCommand`.

**learn.rs** — Rename to `tutorial.rs`. Add `ExecutableCommand`.

**doctor.rs** — Add `ExecutableCommand`.

**completions.rs** — Add `ExecutableCommand`. Note: `handle_completions` is generic over `CommandFactory`. It needs the top-level CLI struct type. Pass `AuthsCli` from `cli.rs`.

**Commit:**

```bash
git add -A
git commit -m "refactor(cli): add ExecutableCommand to all top-level workflow commands"
```

---

## Task 11: Create hidden command groups (commit, debug)

**Files:**
- Create: `src/commands/commit/mod.rs`
- Create: `src/commands/debug/mod.rs`

**commit/mod.rs:**
Routes to existing sign (git commit signing) and verify_commit handlers.

```rust
use clap::{Args, Subcommand};
use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::Result;

#[derive(Args, Debug)]
#[command(about = "Git commit signing/verification (for .gitconfig bindings)")]
pub struct CommitCmd {
    #[command(subcommand)]
    pub command: CommitSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum CommitSubcommand {
    /// Sign a commit (called by git via gpg.program).
    Sign(crate::commands::sign::SignCommand),
    /// Verify a commit signature.
    Verify(crate::commands::verify_commit::VerifyCommitCommand),
}

impl ExecutableCommand for CommitCmd {
    async fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            CommitSubcommand::Sign(cmd) => {
                crate::commands::sign::handle_sign_unified(
                    /* bridge */)
            }
            CommitSubcommand::Verify(cmd) => {
                crate::commands::verify_commit::handle_verify_commit(cmd.clone())
            }
        }
    }
}
```

**debug/mod.rs:**
Routes to existing cache, index, util handlers.

```rust
use clap::{Args, Subcommand};
use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::Result;

#[derive(Args, Debug)]
#[command(about = "Low-level debugging commands")]
pub struct DebugCmd {
    #[command(subcommand)]
    pub command: DebugSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum DebugSubcommand {
    /// Manage local identity history cache.
    Cache(crate::commands::cache::CacheCommand),
    /// Manage device authorization index.
    Index(crate::commands::index::IndexCommand),
    /// Utility commands.
    Util(crate::commands::utils::UtilCommand),
}

impl ExecutableCommand for DebugCmd {
    async fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            DebugSubcommand::Cache(cmd) => crate::commands::cache::handle_cache(cmd.clone()),
            DebugSubcommand::Index(cmd) => {
                crate::commands::index::handle_index(
                    cmd.clone(),
                    ctx.repo_path.clone(),
                    None, // attestation overrides — add if needed
                    None,
                )
            }
            DebugSubcommand::Util(cmd) => crate::commands::utils::handle_util(cmd.clone()),
        }
    }
}
```

**Commit:**

```bash
git add -A
git commit -m "feat(cli): add hidden commit/ and debug/ command groups"
```

---

## Task 12: Wire up the new main.rs

This is the swap. Replace the old monolithic `main.rs` with the new thin bootstrapper.

**Files:**
- Rewrite: `src/main.rs`

**Step 1: Rewrite `src/main.rs`**

```rust
mod cli;
mod commands;
mod config;
mod core;
mod errors;
mod output; // backward-compat shim
mod ux;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use cli::{AuthsCli, RootCommand};
use commands::executable::ExecutableCommand;
use config::{CliConfig, OutputFormat};
use core::provider::{CliPassphraseProvider, PrefilledPassphraseProvider};
use ux::format::set_json_mode;

use auths_core::signing::{CachedPassphraseProvider, PassphraseProvider};

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    let cli = AuthsCli::parse();

    let output_format = if cli.json {
        OutputFormat::Json
    } else {
        cli.output
    };

    if matches!(output_format, OutputFormat::Json) {
        set_json_mode(true);
    }

    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        if let Ok(passphrase) = std::env::var("AUTHS_PASSPHRASE") {
            Arc::new(PrefilledPassphraseProvider::new(zeroize::Zeroizing::new(passphrase)))
        } else {
            let inner = Arc::new(CliPassphraseProvider::new());
            Arc::new(CachedPassphraseProvider::new(inner, Duration::from_secs(3600)))
        };

    let ctx = CliConfig {
        repo_path: cli.repo.clone(),
        output_format,
        is_interactive: std::io::IsTerminal::is_terminal(&std::io::stdin()),
        passphrase_provider,
    };

    let result = dispatch(cli.command, &ctx).await;

    if let Err(e) = result {
        errors::renderer::render_error(&e, ctx.is_json());
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn dispatch(command: RootCommand, ctx: &CliConfig) -> anyhow::Result<()> {
    match command {
        // Top-level workflows
        RootCommand::Init(cmd) => cmd.execute(ctx).await,
        RootCommand::Sign(cmd) => cmd.execute(ctx).await,
        RootCommand::Verify(cmd) => cmd.execute(ctx).await,
        RootCommand::Status(cmd) => cmd.execute(ctx).await,
        RootCommand::Tutorial(cmd) => cmd.execute(ctx).await,
        RootCommand::Doctor(cmd) => cmd.execute(ctx).await,
        RootCommand::Completions(cmd) => cmd.execute(ctx).await,
        RootCommand::Emergency(cmd) => cmd.execute(ctx).await,

        // Noun-verb domain
        RootCommand::Id(cmd) => cmd.execute(ctx).await,
        RootCommand::Device(cmd) => cmd.execute(ctx).await,
        RootCommand::Key(cmd) => cmd.execute(ctx).await,
        RootCommand::Artifact(cmd) => cmd.execute(ctx).await,
        RootCommand::Policy(cmd) => cmd.execute(ctx).await,
        RootCommand::Git(cmd) => cmd.execute(ctx).await,
        RootCommand::Trust(cmd) => cmd.execute(ctx).await,
        RootCommand::Org(cmd) => cmd.execute(ctx).await,
        RootCommand::Audit(cmd) => cmd.execute(ctx).await,
        RootCommand::Agent(cmd) => cmd.execute(ctx).await,
        RootCommand::Witness(cmd) => cmd.execute(ctx).await,

        // Hidden
        RootCommand::Commit(cmd) => cmd.execute(ctx).await,
        RootCommand::Debug(cmd) => cmd.execute(ctx).await,
    }
}
```

**Step 2: Remove the old `Commands` enum and global override flags**

The old `Cli` struct, `Commands` enum, and `run()` function are no longer needed. They're replaced by `AuthsCli`, `RootCommand`, and `dispatch()`.

**Step 3: Build**

Run: `cargo build --package auths-cli 2>&1 | tail -10`
Expected: Should compile. Fix any import errors.

**Step 4: Run tests**

Run: `cargo nextest run -p auths-cli --no-fail-fast 2>&1 | tail -20`
Expected: Most tests pass. Some integration tests may fail if they reference old subcommand names (like `verify-attestation`).

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(cli): wire up new main.rs with ExecutableCommand dispatch"
```

---

## Task 13: Update lib.rs for external consumers

The `auths-sign` and `auths-verify` binaries import from `auths_cli`. Update `src/lib.rs` to expose the new module structure while maintaining backward-compat re-exports.

**Files:**
- Modify: `src/lib.rs`

**Step 1: Update `src/lib.rs`**

```rust
pub mod cli;
pub mod commands;
pub mod config;
pub mod core;
pub mod errors;
pub mod ux;

// Backward-compat re-exports for bin/sign.rs and bin/verify.rs
pub mod error {
    pub use crate::errors::cli_error::*;
}
pub mod error_renderer {
    pub use crate::errors::renderer::*;
}
pub mod output {
    pub use crate::ux::format::*;
}
pub mod provider {
    pub use crate::core::provider::*;
}
pub mod pubkey_cache {
    pub use crate::core::pubkey_cache::*;
}
pub mod types {
    pub use crate::core::types::*;
}

pub use core::pubkey_cache::{cache_pubkey, clear_cached_pubkey, get_cached_pubkey};
pub use core::types::ExportFormat;
pub use ux::format::{Output, set_json_mode};
```

**Step 2: Build all binaries**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
This builds `auths`, `auths-sign`, and `auths-verify`.

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "refactor(cli): update lib.rs with new module structure and backward-compat re-exports"
```

---

## Task 14: Delete dead files and clean up

**Files to delete:**
- `src/commands/provision.rs` (absorbed into init `--config`)
- `src/commands/unified_verify.rs` (replaced by `src/commands/verify.rs` router)
- `src/commands/verify_helpers.rs` (moved into appropriate module or `core/`)
- `src/commands/learn.rs` (renamed to `tutorial.rs`)
- Old backward-compat shim files once all consumers are updated

**Step 1: Remove dead module declarations from `src/commands/mod.rs`**

Update to reflect only the new module structure:

```rust
pub mod executable;
pub mod registry_overrides;

// Top-level workflow commands
pub mod init;
pub mod status;
pub mod sign;
pub mod verify;
pub mod tutorial;
pub mod doctor;
pub mod completions;

// Noun-verb domain commands
pub mod agent;
pub mod artifact;
pub mod audit;
pub mod device;
pub mod emergency;
pub mod git;
pub mod id;
pub mod key;
pub mod org;
pub mod policy;
pub mod trust;
pub mod witness;

// Hidden command groups
pub mod commit;
pub mod debug;
```

**Step 2: Delete dead files**

```bash
git rm src/commands/provision.rs
git rm src/commands/learn.rs        # now tutorial.rs
git rm src/commands/unified_verify.rs  # now verify.rs
git rm src/commands/cache.rs        # now debug/cache.rs
git rm src/commands/index.rs        # now debug/index.rs
git rm src/commands/utils.rs        # now debug/util.rs
git rm src/commands/migrate.rs      # now id/migrate.rs
git rm src/commands/pair            # now device/pair/
git rm src/commands/verify_commit.rs # now commit/verify.rs
```

**Step 3: Build and test**

Run: `cargo build --package auths-cli && cargo nextest run -p auths-cli --no-fail-fast 2>&1 | tail -20`

**Step 4: Commit**

```bash
git add -A
git commit -m "chore(cli): delete dead files after command migration"
```

---

## Task 15: Update integration tests

**Files:**
- Modify: `tests/cases/verify.rs` — fix the broken `advanced` subcommand test
- Review all integration tests for subcommand name changes

**Step 1: Fix `test_verify_with_roots_json_explicit_policy`**

This test calls `auths advanced verify-attestation`. In the new structure, this becomes `auths device verify`. Update the test command.

**Step 2: Audit all integration tests**

Search all test files for old subcommand names:

```bash
grep -rn "verify-attestation\|verify-commit\|learn\|provision" tests/
```

Update any references to use new command paths.

**Step 3: Run full test suite**

Run: `cargo nextest run -p auths-cli --no-fail-fast 2>&1 | tail -30`
Expected: All 251 tests pass (including the previously broken one).

**Step 4: Commit**

```bash
git add -A
git commit -m "test(cli): update integration tests for noun-verb command structure"
```

---

## Task 16: Run full workspace verification

**Step 1: Format**

Run: `cargo fmt --all`

**Step 2: Clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tail -20`
Fix any warnings.

**Step 3: Full test suite**

Run: `cargo nextest run --workspace --no-fail-fast 2>&1 | tail -30`
Expected: All tests pass across all crates.

**Step 4: Build all binaries**

Run: `cargo build --package auths-cli 2>&1 | tail -5`
Verify `auths`, `auths-sign`, and `auths-verify` all build.

**Step 5: Smoke test the CLI**

```bash
cargo run --package auths-cli --bin auths -- --help
cargo run --package auths-cli --bin auths -- id --help
cargo run --package auths-cli --bin auths -- device --help
cargo run --package auths-cli --bin auths -- doctor --help
cargo run --package auths-cli --bin auths -- debug --help
```

Verify the help output matches the expected hierarchy.

**Step 6: Commit**

```bash
git add -A
git commit -m "chore(cli): pass fmt, clippy, and full test suite after noun-verb refactor"
```

---

## Task 17: Remove backward-compat shims

Now that everything compiles and passes, remove the temporary re-export shims.

**Step 1: Update `src/bin/sign.rs` and `src/bin/verify.rs`**

Change all imports to use the new module paths:
- `auths_cli::commands::agent::*` -> `auths_cli::commands::agent::*` (unchanged — already a directory)
- `auths_cli::pubkey_cache::*` -> `auths_cli::core::pubkey_cache::*`
- `auths_cli::error_renderer::*` -> `auths_cli::errors::renderer::*`

**Step 2: Update `src/lib.rs`**

Remove the backward-compat module shims. Keep only the clean re-exports:

```rust
pub mod cli;
pub mod commands;
pub mod config;
pub mod core;
pub mod errors;
pub mod ux;

// Public API re-exports
pub use core::pubkey_cache::{cache_pubkey, clear_cached_pubkey, get_cached_pubkey};
pub use core::types::ExportFormat;
pub use ux::format::{Output, set_json_mode};
pub use errors::renderer::render_error;
```

**Step 3: Build and test**

Run: `cargo build --package auths-cli && cargo nextest run -p auths-cli --no-fail-fast`

**Step 4: Commit**

```bash
git add -A
git commit -m "chore(cli): remove backward-compat shims, clean up lib.rs exports"
```

---

## Summary of Commits

| # | Message | What changes |
|---|---------|--------------|
| 1 | `feat(cli): add ExecutableCommand trait, CliConfig, and RegistryOverrides` | Scaffolding |
| 2 | `refactor(cli): move provider, types, pubkey_cache into core/ module` | core/ reorg |
| 3 | `refactor(cli): move output.rs into ux/format.rs with backward-compat shim` | ux/ reorg |
| 4 | `refactor(cli): move error.rs and error_renderer.rs into errors/ module` | errors/ reorg |
| 5 | `feat(cli): add new declarative cli.rs router alongside existing main.rs` | New router |
| 6 | `refactor(cli): migrate id command group with create/show/rotate/migrate` | id + migrate |
| 7 | `refactor(cli): migrate device command group, absorb pair and verify-attestation` | device + pair |
| 8 | `refactor(cli): migrate key, trust, policy, audit, emergency` | 5 simple groups |
| 9 | `refactor(cli): migrate git, org, agent, witness, artifact` | 5 medium groups |
| 10 | `refactor(cli): add ExecutableCommand to all top-level workflow commands` | Workflows |
| 11 | `feat(cli): add hidden commit/ and debug/ command groups` | New groups |
| 12 | `feat(cli): wire up new main.rs with ExecutableCommand dispatch` | Router swap |
| 13 | `refactor(cli): update lib.rs with new module structure` | Exports |
| 14 | `chore(cli): delete dead files after command migration` | Cleanup |
| 15 | `test(cli): update integration tests for noun-verb command structure` | Test fixes |
| 16 | `chore(cli): pass fmt, clippy, and full test suite` | Verification |
| 17 | `chore(cli): remove backward-compat shims, clean up lib.rs exports` | Final cleanup |
