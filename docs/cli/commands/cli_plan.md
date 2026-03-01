# CLI Primary/Advanced Restructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the bare-bones `init` command with the comprehensive `setup` command (renamed to `init`), promote `status` to the primary surface, and drop witness flags from the onboarding path.

**Architecture:** `commands/setup.rs` becomes the new `commands/init.rs`. The old `commands/init.rs` (bare-bones identity creation with witness flags) is deleted. `main.rs` is updated to wire `Status` into the top-level `Commands` enum alongside `Init`, `Sign`, and `Verify`. The `AdvancedCommands` enum loses `Setup` and the old `Init`.

**Tech Stack:** Rust, clap 4, cargo nextest

---

## Baseline

Before touching anything, run the full test suite and save the result so you know what was passing before.

```bash
cargo nextest run --workspace 2>&1 | tail -20
cargo build --package auths_cli 2>&1
```

Expected: clean build, all tests pass (or note any pre-existing failures).

---

## Task 1: Delete `commands/init.rs` (old bare-bones wizard)

**Files:**
- Delete: `crates/auths-cli/src/commands/init.rs`

This file contains `InitCommand`, `InitConfig`, `SetupPreset`, and `handle_init`. All of it is superseded by `setup.rs`. Dropping it also drops the witness flags (`--witness`, `--witness-threshold`, `--witness-policy`) from the onboarding path — intentional.

**Step 1: Delete the file**

```bash
rm crates/auths-cli/src/commands/init.rs
```

**Step 2: Verify it's gone**

```bash
ls crates/auths-cli/src/commands/init.rs
```

Expected: `No such file or directory`

---

## Task 1.5: Purge orphaned tests referencing old `init` flags

Before writing any new code, find every test that exercises the old bare-bones `init` flags (`--witness`, `--witness-threshold`, `--witness-policy`, `--setup-preset`, `--metadata-file`, `--no-prompt`) so they don't silently break after Task 1.

**Step 1: Search the entire workspace for references**

```bash
grep -r "init.*--witness\|--witness.*init\|--setup-preset\|--metadata-file\|--no-prompt\|handle_init\|InitCommand\|InitConfig\|SetupPreset" \
  crates/auths-cli/tests/ crates/ --include="*.rs" -l
```

Expected: any file listed is a candidate for cleanup.

**Step 2: For each file found, do one of the following**

- If the test exercises the old bare-bones wizard flow → **delete the test**.
- If the test exercises something still valid (e.g. `--key-alias`, `--force`) → **update the call site** to use the new `auths init --profile developer` equivalent.

**Step 3: Verify no stale references remain**

```bash
grep -r "SetupPreset\|InitConfig\|--witness-threshold\|--witness-policy" \
  crates/auths-cli/tests/ crates/ --include="*.rs"
```

Expected: no matches.

---

## Task 2: Rename `setup.rs` → `init.rs` and update types inside it

**Files:**
- Create: `crates/auths-cli/src/commands/init.rs` (from setup.rs content)
- Delete: `crates/auths-cli/src/commands/setup.rs`

**Step 1: Copy setup.rs to init.rs**

```bash
cp crates/auths-cli/src/commands/setup.rs crates/auths-cli/src/commands/init.rs
```

**Step 2: Rename types inside `init.rs`**

In `crates/auths-cli/src/commands/init.rs`, make these four renames (all occurrences in the file):

| Old name | New name |
|----------|----------|
| `SetupCommand` | `InitCommand` |
| `SetupProfile` | `InitProfile` |
| `handle_setup` | `handle_init` |
| `#[command(name = "setup", ...)]` | `#[command(name = "init", ...)]` |

The `about` text on the command attribute should become:
```rust
#[command(name = "init", about = "Set up your cryptographic identity and Git signing")]
```

The module-level doc comment at the top of the file should become:
```rust
//! One-command guided setup wizard for Auths.
//!
//! Provides three profiles (developer, ci, agent) with sensible defaults,
//! enabling zero-to-signing-commits in under 60 seconds.
```

**Step 3: Update rustdoc on `handle_init` and `InitCommand`**

In `crates/auths-cli/src/commands/init.rs`, replace the doc comment block immediately above `pub struct InitCommand` and `pub fn handle_init` with the following (adapt the DID placeholder to whatever the test produces):

```rust
/// Initializes Auths identity with a guided setup wizard.
///
/// Supports three profiles (developer, ci, agent) covering the most common
/// deployment scenarios. Interactive by default; pass `--non-interactive` for
/// scripted or CI use.
///
/// Args:
/// * `non_interactive`: Skip all interactive prompts and apply profile defaults.
/// * `profile`: Which setup profile to run (`developer`, `ci`, or `agent`).
/// * `key_alias`: Alias for the identity key stored in the platform keychain.
/// * `force`: Proceed even when an identity already exists.
/// * `dry_run`: Preview agent configuration without creating any files.
///
/// Usage:
/// ```ignore
/// // Guided interactive setup for a developer workstation:
/// auths init
///
/// // Fully non-interactive developer setup:
/// auths init --profile developer --non-interactive
///
/// // CI ephemeral identity (reads passphrase from AUTHS_PASSPHRASE env var):
/// auths init --profile ci --non-interactive
/// ```
pub struct InitCommand { ... }
```

```rust
/// Handle the `init` command.
///
/// Args:
/// * `cmd`: Parsed [`InitCommand`] from the CLI.
///
/// Usage:
/// ```ignore
/// handle_init(cmd)?;
/// ```
pub fn handle_init(cmd: InitCommand) -> Result<()> { ... }
```

Remove any inline comments inside the function body that merely restate what the code does. Keep only comments that explain a non-obvious side-effect (e.g. the `unsafe` env-var set for CI keychain).

**Step 4: Delete the now-redundant `setup.rs`**

```bash
rm crates/auths-cli/src/commands/setup.rs
```

**Step 4: Verify only `init.rs` exists**

```bash
ls crates/auths-cli/src/commands/init.rs crates/auths-cli/src/commands/setup.rs
```

Expected: `init.rs` present, `setup.rs` → `No such file or directory`

---

## Task 3: Update `commands/mod.rs`

**Files:**
- Modify: `crates/auths-cli/src/commands/mod.rs`

**Step 1: Read the current file**

Current contents:
```
pub mod agent;
pub mod artifact;
pub mod audit;
pub mod cache;
pub mod completions;
pub mod device;
pub mod doctor;
pub mod emergency;
pub mod git;
pub mod id;
pub mod index;
pub mod init;       ← old bare-bones init (deleted)
pub mod key;
pub mod learn;
pub mod migrate;
pub mod org;
pub mod pair;
pub mod policy;
pub mod provision;
pub mod setup;      ← old setup (deleted, now init)
pub mod sign;
pub mod status;
pub mod trust;
pub mod unified_verify;
pub mod utils;
pub mod verify;
pub mod verify_commit;
pub mod verify_helpers;
pub mod witness;
```

**Step 2: Replace with updated contents**

The file should have `pub mod init;` (the new comprehensive init, was setup) and no `pub mod setup;`. Everything else stays the same:

```rust
pub mod agent;
pub mod artifact;
pub mod audit;
pub mod cache;
pub mod completions;
pub mod device;
pub mod doctor;
pub mod emergency;
pub mod git;
pub mod id;
pub mod index;
pub mod init;
pub mod key;
pub mod learn;
pub mod migrate;
pub mod org;
pub mod pair;
pub mod policy;
pub mod provision;
pub mod sign;
pub mod status;
pub mod trust;
pub mod unified_verify;
pub mod utils;
pub mod verify;
pub mod verify_commit;
pub mod verify_helpers;
pub mod witness;
```

---

## Task 4: Update `main.rs` — imports

**Files:**
- Modify: `crates/auths-cli/src/main.rs`

**Step 1: Remove old init and setup imports, add new init import**

Find and remove these two lines:
```rust
use commands::init::{InitCommand, handle_init};
use commands::setup::{SetupCommand, handle_setup};
```

Replace with:
```rust
use commands::init::{InitCommand, handle_init};
```

(`InitCommand` and `handle_init` now live in the new `init.rs`, which is what was `setup.rs`.)

---

## Task 5: Update `main.rs` — `Commands` enum

**Files:**
- Modify: `crates/auths-cli/src/main.rs`

**Step 1: Locate the `Commands` enum**

It currently reads:
```rust
#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
enum Commands {
    /// Initialize your cryptographic identity.
    Init(InitCommand),

    /// Sign a Git commit or artifact.
    Sign(SignCommand),

    /// Verify a signed commit or attestation.
    Verify(UnifiedVerifyCommand),

    /// Full suite of advanced commands.
    #[command(subcommand, name = "advanced")]
    Advanced(AdvancedCommands),
}
```

**Step 2: Add `Status` and update `Init` doc**

Replace the enum body with:
```rust
#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
enum Commands {
    /// Set up your cryptographic identity and Git signing.
    Init(InitCommand),

    /// Sign a Git commit or artifact.
    Sign(SignCommand),

    /// Verify a signed commit or attestation.
    Verify(UnifiedVerifyCommand),

    /// Show identity and signing status.
    Status(StatusCommand),

    /// Full suite of advanced commands.
    #[command(subcommand, name = "advanced")]
    Advanced(AdvancedCommands),
}
```

---

## Task 6: Update `main.rs` — `AdvancedCommands` enum

**Files:**
- Modify: `crates/auths-cli/src/main.rs`

**Step 1: Locate `AdvancedCommands`**

It currently contains a `Setup(SetupCommand)` variant. Remove it entirely.

Before (excerpt):
```rust
    /// Unified setup for developers, CI, and agents.
    Setup(SetupCommand),
    /// Show identity and agent status overview.
    Status(StatusCommand),
```

After (both lines removed — `Setup` gone, `Status` promoted to primary):
```rust
    // (no Setup variant)
    // (no Status variant)
```

The full enum after the change should be (in this order):
```rust
#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
enum AdvancedCommands {
    /// SSH agent daemon management (start, stop, status).
    Agent(AgentCommand),
    /// Sign and verify arbitrary artifacts (tarballs, binaries, etc.).
    Artifact(ArtifactCommand),
    /// Generate signing audit reports for compliance.
    Audit(AuditCommand),
    /// Manage local identity history cache.
    Cache(CacheCommand),
    /// Generate shell completions for bash, zsh, fish, or powershell.
    Completions(CompletionsCommand),
    /// Manage device authorizations within an identity repository.
    Device(DeviceCommand),
    /// Run comprehensive health checks.
    Doctor(DoctorCommand),
    /// Emergency incident response commands.
    Emergency(EmergencyCommand),
    /// Git integration commands (allowed-signers, hooks).
    Git(GitCommand),
    /// Manage identities stored in Git repositories.
    Id(IdCommand),
    /// Manage the device authorization index for fast lookups.
    Index(IndexCommand),
    /// Manage local cryptographic keys in secure storage.
    Key(KeyCommand),
    /// Interactive tutorial to learn Auths concepts.
    Learn(LearnCommand),
    /// Import existing GPG or SSH keys into Auths.
    Migrate(MigrateCommand),
    Org(OrgCommand),
    /// Link devices to your identity via QR code or short code.
    Pair(PairCommand),
    /// Manage authorization policies.
    Policy(PolicyCommand),
    /// Declarative headless provisioning for enterprise deployments.
    Provision(ProvisionCommand),
    /// Manage trusted identity roots.
    Trust(TrustCommand),
    /// Utility commands (e.g., derive identity ID from seed).
    Util(UtilCommand),
    /// Verify device authorization signatures (attestation).
    #[command(name = "verify-attestation")]
    VerifyAttestation(VerifyCommand),
    /// Verify Git commit signatures against Auths identity.
    #[command(name = "verify-commit")]
    VerifyCommit(VerifyCommitCommand),
    /// Manage the KERI witness server.
    Witness(WitnessCommand),
}
```

---

## Task 7: Update `main.rs` — match arms

**Files:**
- Modify: `crates/auths-cli/src/main.rs`

**Step 1: Locate the top-level match block**

Currently:
```rust
    match cli.command {
        Commands::Init(cmd) => handle_init(cmd, cli.repo, Arc::clone(&passphrase_provider))?,
        Commands::Sign(cmd) => {
            handle_sign_unified(cmd, cli.repo.clone(), Arc::clone(&passphrase_provider))?
        }
        Commands::Verify(cmd) => handle_verify_unified(cmd)?,
        Commands::Advanced(adv) => match adv {
            ...
        },
    }
```

**Step 2: Add `Status` arm, update `Init` arm**

The `Init` arm changes signature — new `handle_init` (was `handle_setup`) takes only `cmd`, not `(cmd, repo, passphrase_provider)`. Check `setup.rs`/new `init.rs`'s `handle_setup` signature:

```rust
pub fn handle_setup(cmd: SetupCommand) -> Result<()>
```

So the `Init` arm becomes:
```rust
Commands::Init(cmd) => handle_init(cmd)?,
```

Add a `Status` arm:
```rust
Commands::Status(cmd) => handle_status(cmd, cli.repo.clone())?,
```

Full updated top-level match:
```rust
    match cli.command {
        Commands::Init(cmd) => handle_init(cmd)?,
        Commands::Sign(cmd) => {
            handle_sign_unified(cmd, cli.repo.clone(), Arc::clone(&passphrase_provider))?
        }
        Commands::Verify(cmd) => handle_verify_unified(cmd)?,
        Commands::Status(cmd) => handle_status(cmd, cli.repo.clone())?,
        Commands::Advanced(adv) => match adv {
            ...
        },
    }
```

**Step 3: Verify `handle_status` argument signature before wiring**

Before adding the `Commands::Status` arm, confirm the exact signature of `handle_status` in `crates/auths-cli/src/commands/status.rs`:

```bash
grep -n "^pub fn handle_status" crates/auths-cli/src/commands/status.rs
```

It is expected to be:
```rust
pub fn handle_status(cmd: StatusCommand, repo: Option<PathBuf>) -> Result<()>
```

If the signature differs (e.g. it also takes a `passphrase_provider`), update the call site in `main.rs` to match exactly — do not guess. The promoted arm must compile on the first attempt.

**Step 4: Remove `AdvancedCommands::Setup` and `AdvancedCommands::Status` match arms**

In the inner `match adv` block, remove:
```rust
AdvancedCommands::Setup(cmd) => handle_setup(cmd)?,
AdvancedCommands::Status(cmd) => handle_status(cmd, cli.repo)?,
```

(`Status` is now handled at the top level; `Setup` no longer exists.)

---

## Task 8: Verify it builds and `--help` looks right

**Step 1: Build**

```bash
cargo build --package auths_cli 2>&1
```

Expected: zero errors, zero warnings about unused imports.

**Step 2: Check primary help**

```bash
./target/debug/auths --help
```

Expected output shape:
```
auths — cryptographic identity for developers

Commands:
  init     Set up your cryptographic identity and Git signing
  sign     Sign a Git commit or artifact
  verify   Verify a signed commit or attestation
  status   Show identity and signing status

Advanced:
  auths advanced --help   (device, key, org, policy, trust, witness, ...)
```

**Step 3: Check advanced help**

```bash
./target/debug/auths advanced --help
```

Expected: `setup` is NOT listed. `status` is NOT listed. All other advanced commands are present.

**Step 4: Check init help**

```bash
./target/debug/auths init --help
```

Expected: shows `--profile`, `--key-alias`, `--non-interactive`, `--force`, `--dry-run`. Does NOT show `--witness` or `--witness-threshold`.

---

## Task 9: Run full test suite

```bash
cargo nextest run --workspace 2>&1
```

Expected: same pass/fail as baseline (Task 0). Any new failures are regressions to fix before committing.

---

## Task 10: Update docs

**Files:**
- Rename: `docs/cli/commands/auths-setup.md` → `docs/cli/commands/auths-init.md`
- Modify: `docs/cli/commands/auths-init.md` — update title, command name, and any references to `auths setup` → `auths init`

**Step 1: Rename**

```bash
mv docs/cli/commands/auths-setup.md docs/cli/commands/auths-init.md
```

**Step 2: Update content in `auths-init.md`**

- Title line: `# auths setup` → `# auths init`
- All occurrences of `auths setup` → `auths init`
- All occurrences of `auths setup --profile` → `auths init --profile`

**Step 3: Sweep all docs and root README for stale references**

The command rename ripples beyond the one renamed file — catch every cross-reference in a single pass:

```bash
grep -r "auths setup\|auths-setup" docs/ README.md 2>/dev/null
```

For each match:
- Inline code like `` `auths setup` `` → `` `auths init` ``
- Markdown links like `[Setup](auths-setup.md)` → `[Init](auths-init.md)`
- CI snippet blocks showing `auths setup --profile ci` → `auths init --profile ci`

**Step 4: Verify no stale references remain**

```bash
grep -r "auths setup\|auths-setup" docs/ README.md 2>/dev/null
```

Expected: no matches.

---

## Task 11: Commit

```bash
git add \
  crates/auths-cli/src/commands/init.rs \
  crates/auths-cli/src/commands/mod.rs \
  crates/auths-cli/src/main.rs \
  docs/cli/commands/auths-init.md

git rm crates/auths-cli/src/commands/setup.rs

git commit -m "refactor(cli): rename setup→init, promote status to primary surface

- commands/setup.rs renamed to commands/init.rs (SetupCommand→InitCommand etc.)
- Old bare-bones init.rs dropped (superseded by the comprehensive setup flow)
- Status promoted from advanced to primary Commands enum
- Witness flags (--witness, --witness-threshold, --witness-policy) removed from
  onboarding surface; accessible via auths advanced witness
- docs/cli/commands/auths-setup.md renamed to auths-init.md"
```
