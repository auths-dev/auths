# CLI Cleanup Plan

## Design Principle

> **All business logic lives in `auths-sdk`. The `auths-cli` is a thin presentation layer.**
>
> SDK workflows return structured results (reports, status enums). CLI calls SDK, then formats and prints the results. CLI never does file I/O, git operations, or config parsing directly — it delegates to SDK.

## Source Map

Key files an implementer needs to know about:

| Area | File | What it does |
|------|------|-------------|
| `auths init` handler | `crates/auths-cli/src/commands/init/mod.rs` | Entry point: `handle_init()` (L141), `run_developer_setup()` (L166) |
| `auths init` helpers | `crates/auths-cli/src/commands/init/helpers.rs` | `write_allowed_signers()` (L99), `set_git_config()` (L137) |
| `auths doctor` handler | `crates/auths-cli/src/commands/doctor.rs` | `handle_doctor()` (L43), `run_checks()` (L97) |
| Doctor fix adapters | `crates/auths-cli/src/adapters/doctor_fixes.rs` | `GitSigningConfigFix::apply()` (L99), `AllowedSignersFix::apply()` (L37) |
| Allowed signers workflow | `crates/auths-sdk/src/workflows/allowed_signers.rs` | `AllowedSigners` struct (L254), `sync()` (L376), `save()` (L302) |
| SDK setup / init | `crates/auths-sdk/src/setup.rs` | `initialize()` (L49) — orchestrates identity creation |
| Registry ref store | `crates/auths-infra-git/src/ref_store.rs` | `GitRefStore` — reads/writes `refs/auths/registry` |
| Identity init | `crates/auths-id/src/identity/initialize.rs` | `initialize_registry_identity()` (L104) |
| Git hooks | `crates/auths-id/src/storage/registry/hooks.rs` | `install_cache_hooks()` (L60), `install_linearity_hook()` (L271) |
| Diagnostics workflow | `crates/auths-sdk/src/workflows/diagnostics.rs` | `DiagnosticsWorkflow` — used by `auths doctor` |
| SSH config workflow | `crates/auths-sdk/src/workflows/ssh_config.rs` | **New.** `SshConfigWorkflow::ensure_config()`, `check_config()` |
| Registry sync workflow | `crates/auths-sdk/src/workflows/registry_sync.rs` | **New.** `RegistrySyncWorkflow::sync_to_repo()` |
| Key backup workflow | `crates/auths-sdk/src/workflows/key_backup.rs` | **New.** `KeyBackupWorkflow::export()`, `is_backed_up()` |

## Execution Order

Tasks have dependencies. Do them in this order:

1. **Task 1** (SSH config) — standalone, no deps
2. **Task 3** (repo allowed_signers) — standalone, no deps
3. **Task 6** (auto-push registry on init) — standalone, no deps
4. **Task 2** (pre-push hook) — after task 6 (same area, don't want conflicts)
5. **Task 5** (doctor checks) — after tasks 1, 3, 6 (doctor needs to check what they write)
6. **Task 4** (identity reset) — after tasks 3, 5, 6 (uses all the new cleanup logic)
7. **Task 7** (umbrella: single-command onboarding) — after all above (integration)
8. **Task 8** (pre-rotation backup nudge) — independent, can be done anytime

## Testing

For each task, verify by running the end-to-end flow on a **clean machine** (or with `rm -rf ~/.auths`):

```bash
# 1. Fresh init
auths init

# 2. Check everything was set up
auths doctor          # should pass all checks
cat ~/.ssh/config     # should have IgnoreUnknown UseKeychain
cat .auths/allowed_signers  # should have the new key
git for-each-ref refs/auths/  # should have registry ref

# 3. Make a signed commit and push
git commit --allow-empty -m "test: signed commit"
git push origin main  # should also push refs/auths/registry

# 4. Verify the commit
auths verify HEAD     # should pass
```

---

## Tasks

### 1. SSH config: add `IgnoreUnknown UseKeychain`

## Problem

`auths init` writes `UseKeychain yes` to `~/.ssh/config` under a `Host *` block. This is a macOS-specific OpenSSH option. If the user's SSH version doesn't recognize it, **all git+SSH operations fail**:

```
/Users/.../.ssh/config: line 7: Bad configuration option: usekeychain
/Users/.../.ssh/config: terminating, 1 bad configuration options
fatal: Could not read from remote repository.
```

## Fix

### 1. `auths init` (onboarding)
When writing the SSH config, prepend `IgnoreUnknown UseKeychain` on the same `Host *` block:

```
Host *
  IgnoreUnknown UseKeychain
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_ed25519_...
```

This tells SSH to silently skip `UseKeychain` if unsupported, rather than failing.

### 2. `auths doctor` (diagnostics)
`auths doctor` should check for this condition:
- If `~/.ssh/config` contains `UseKeychain` without a preceding `IgnoreUnknown UseKeychain`, flag it as a warning
- Print the location of the SSH config and suggest adding the directive
- Users who break their auths setup will likely reach for `auths doctor` first, so this is an important diagnostic to surface

## Implementation

### Design note

All business logic goes in **auths-sdk**. The CLI is a thin presentation layer that calls SDK functions and prints output.

### `auths init` — write SSH config (SDK)

**File:** `crates/auths-sdk/src/workflows/ssh_config.rs` (new file)

There is currently **no function that writes `~/.ssh/config`**. The existing `write_allowed_signers()` in CLI helpers (L99) only writes `~/.ssh/allowed_signers`. Create a new SDK workflow:

```rust
pub struct SshConfigWorkflow;

impl SshConfigWorkflow {
    /// Ensures ~/.ssh/config has IgnoreUnknown UseKeychain and the identity file.
    /// Returns a description of what was changed, or None if no change needed.
    pub fn ensure_config(identity_file: &Path) -> Result<Option<String>> {
        let home = dirs::home_dir().context("no home directory")?;
        let ssh_dir = home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir)?;
        let config_path = ssh_dir.join("config");

        let existing = std::fs::read_to_string(&config_path).unwrap_or_default();

        // Skip if IgnoreUnknown UseKeychain already present
        if existing.contains("IgnoreUnknown UseKeychain") {
            return Ok(None);
        }

        let block = format!(
            "\nHost *\n  IgnoreUnknown UseKeychain\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile {}\n",
            identity_file.display()
        );

        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&config_path)?;
        f.write_all(block.as_bytes())?;
        Ok(Some(format!("Added IgnoreUnknown UseKeychain to {}", config_path.display())))
    }

    /// Checks if UseKeychain exists without IgnoreUnknown. Returns diagnostic info.
    pub fn check_config() -> Result<SshConfigStatus> { /* ... */ }
}
```

Register the module in `crates/auths-sdk/src/workflows/mod.rs`.

**CLI caller** (`crates/auths-cli/src/commands/init/mod.rs`, post-setup phase ~L236):
```rust
if let Some(msg) = SshConfigWorkflow::ensure_config(&ssh_key_path)? {
    out.println(&format!("✓ {msg}"));
}
```

### `auths doctor` — check SSH config

**File:** `crates/auths-sdk/src/workflows/diagnostics.rs`

Add a new check method alongside `check_git_signing_config()` (L72):

```rust
fn check_ssh_config(&self, checks: &mut Vec<CheckResult>) -> Result<(), DiagnosticError> {
    let home = dirs::home_dir().ok_or_else(|| DiagnosticError::ExecutionFailed("no home".into()))?;
    let config_path = home.join(".ssh").join("config");
    let content = std::fs::read_to_string(&config_path).unwrap_or_default();

    let has_usekeychain = content.lines().any(|l| l.trim().eq_ignore_ascii_case("usekeychain yes"));
    let has_ignore = content.lines().any(|l| l.trim().starts_with("IgnoreUnknown") && l.contains("UseKeychain"));

    if has_usekeychain && !has_ignore {
        checks.push(CheckResult {
            name: "ssh_config_usekeychain".into(),
            passed: false,
            message: Some(format!(
                "~/.ssh/config has UseKeychain without IgnoreUnknown UseKeychain. Add 'IgnoreUnknown UseKeychain' to the Host * block in {}",
                config_path.display()
            )),
            config_issues: vec![ConfigIssue::Absent("IgnoreUnknown UseKeychain".into())],
        });
    } else {
        checks.push(CheckResult { name: "ssh_config_usekeychain".into(), passed: true, message: None, config_issues: vec![] });
    }
    Ok(())
}
```

Register in `available_checks()` (L31) and call from `run()` (L61).

**File:** `crates/auths-cli/src/adapters/doctor_fixes.rs`

Add `SshConfigFix` implementing `DiagnosticFix` (same pattern as `AllowedSignersFix`). Register it in `build_available_fixes()` in `crates/auths-cli/src/commands/doctor.rs` (L193).

## Context

Discovered while dogfooding the `@auths-dev/verify` widget. After wiping and re-creating an identity, `git push` failed due to this SSH config issue.


### 2. Pre-push hook to sync `refs/auths/registry`

## Problem

After `auths init`, the registry (`refs/auths/registry`) is written to `~/.auths/.git`, not to the current project repo. Users must manually run:

```bash
git fetch ~/.auths refs/auths/registry:refs/auths/registry
git push origin refs/auths/registry --force
```

This is undiscoverable — nothing in the CLI tells users they need to do this, and downstream tools (e.g., the `@auths-dev/verify` widget) silently fail because the project repo on GitHub has no `refs/auths/registry`.

## Proposal

Add a **pre-push Git hook** that automatically syncs `refs/auths/registry` from `~/.auths` into the project repo before pushing.

### Why pre-push (not pre-commit)

- Not every commit needs the registry synced — only when pushing to a remote
- Catches all pushes including direct-to-main workflows
- Pre-commit would be too frequent and noisy

### Suggested behavior

1. On `git push`, the hook checks if `~/.auths/.git/refs/auths/registry` exists
2. If so, fetch it into the local repo: `git fetch ~/.auths refs/auths/registry:refs/auths/registry`
3. Include `refs/auths/registry` in the push
4. If `~/.auths` has no registry, skip silently (user hasn't run `auths init`)

### Installation

The hook could be installed automatically by `auths init` or `auths git setup`, similar to how git signing is configured.

## Implementation

**File:** `crates/auths-id/src/storage/registry/hooks.rs`

Follow the existing pattern from `install_cache_hooks()` (L60) and `install_linearity_hook()` (L271):

1. Add a constant for the hook marker:
```rust
const REGISTRY_SYNC_MARKER: &str = "# auths-registry-sync";
```

2. Add hook script:

Does this work for Mac, Linux and Windows? (e.g. `$HOME`)
```rust
const REGISTRY_SYNC_HOOK: &str = r#"#!/bin/sh
# auths-registry-sync
# Syncs refs/auths/registry from ~/.auths into this repo before pushing

AUTHS_HOME="$HOME/.auths"
REGISTRY_REF="refs/auths/registry"

if [ -d "$AUTHS_HOME/.git" ] && git --git-dir="$AUTHS_HOME/.git" rev-parse --verify "$REGISTRY_REF" >/dev/null 2>&1; then
    git fetch "$AUTHS_HOME" "$REGISTRY_REF:$REGISTRY_REF" --quiet 2>/dev/null || true
    # Read push args from stdin (pre-push receives: <local ref> <local sha> <remote ref> <remote sha>)
    # After the normal push completes, push the registry ref too
    REMOTE="$1"
    git push "$REMOTE" "$REGISTRY_REF" --force --quiet 2>/dev/null || true
fi
"#;
```

3. Add installation function following the same pattern as `install_cache_hooks()`:
```rust
pub fn install_pre_push_hook(repo_path: &Path) -> Result<()> {
    let git_dir = find_git_dir(repo_path)?;
    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    install_hook(&hooks_dir, "pre-push", REGISTRY_SYNC_HOOK, REGISTRY_SYNC_MARKER)?;
    Ok(())
}
```

The `install_hook()` helper (L87) already handles idempotency (checks for marker), appending to existing hooks, and setting `0o755` permissions.

**Caller:** Add to `run_developer_setup()` in `crates/auths-cli/src/commands/init/mod.rs` (L236, post-setup phase). Only install when running inside a git repo (check `.git` exists in cwd or parents).

## Context

Discovered while dogfooding the verify widget (`@auths-dev/verify`) with the [example-verify-badge](https://github.com/auths-dev/example-verify-badge) repo. The widget fetches `refs/auths/registry` from the GitHub API to verify attestations, but the ref was missing from the remote because the manual sync step was not documented or automated.

### 3. Auto-populate `.auths/allowed_signers` in repo

## Problem

After running `auths init`, the user's signing key is added to `~/.ssh/allowed_signers` (global), but the repo's `.auths/allowed_signers` is not created or updated. This means:

1. The GitHub Action (`auths-verify-github-action`) can't verify commits because it reads `.auths/allowed_signers` from the repo
2. The user has to manually figure out the correct format (`<principal> namespaces="git" ssh-ed25519 <key>`)
3. New contributors have no obvious way to add their key

## Expected behavior

`auths init` should:
- Create `.auths/allowed_signers` in the current repo if it doesn't exist
- Append the user's device DID principal + SSH public key in the correct format
- Match the format used in `~/.ssh/allowed_signers` (e.g., `z6Mk...@auths.local namespaces="git" ssh-ed25519 AAAA...`)

## Implementation

### Design note

All business logic goes in **auths-sdk**. The CLI is a thin presentation layer.

**File:** `crates/auths-sdk/src/workflows/allowed_signers.rs`

The `AllowedSigners` struct (L254) and `sync()` (L376) already exist and handle the correct format: `<principal>@auths.local namespaces="git" ssh-ed25519 <key>`. Add a convenience method to the existing workflow:

```rust
impl AllowedSigners {
    /// Sync allowed_signers for a specific repo's .auths/ directory.
    /// Creates .auths/allowed_signers if it doesn't exist.
    /// Returns the number of signers added.
    pub fn sync_repo(repo_root: &Path) -> Result<SyncReport> {
        let auths_dir = repo_root.join(".auths");
        std::fs::create_dir_all(&auths_dir)?;
        let signers_path = auths_dir.join("allowed_signers");

        let home = auths_core::paths::auths_home()?;
        let storage = RegistryAttestationStorage::new(&home);
        let mut signers = AllowedSigners::load(&signers_path)
            .unwrap_or_else(|_| AllowedSigners::new(&signers_path));
        let report = signers.sync(&storage)?;
        signers.save()?;
        Ok(report)
    }
}
```

This belongs in the SDK because it reuses `AllowedSigners`, `RegistryAttestationStorage`, and `sync()` — all SDK types.

**CLI caller** (`crates/auths-cli/src/commands/init/mod.rs`, post-setup phase ~L236):
```rust
if let Ok(repo_root) = detect_repo_root() {
    let report = AllowedSigners::sync_repo(&repo_root)?;
    out.println(&format!("✓ Wrote {} signer(s) to .auths/allowed_signers", report.added));
}
```

## Context

Discovered during dogfooding. The example repos had placeholder keys in `.auths/allowed_signers` that had to be manually replaced with real keys before the GitHub Action would pass.

### 4. Identity reset (`auths init --reset`)

## Problem

When a user needs to wipe and recreate their identity (e.g., during development or after key compromise), the process is manual and error-prone:

1. Must manually `rm -rf ~/.auths` to remove the old identity
2. `auths init --force` creates a new identity but doesn't clean up stale data:
   - Old `refs/auths/registry` refs remain in repos with mismatched attestations
   - Old entries in `~/.ssh/allowed_signers` accumulate (though this is harmless)
   - Old SSH key files remain in `~/.ssh/`
   - `.auths/allowed_signers` in repos still references the old key
3. Must manually `git update-ref -d refs/auths/registry` in each repo, then re-push
4. Multiple `auths init` runs can accumulate broken attestations in the registry

## Expected behavior

Provide a clean reset path:

- `auths init --reset` that:
  - Removes the old identity from `~/.auths`
  - Cleans up `refs/auths/registry` in the current repo
  - Updates `~/.ssh/allowed_signers` (removes old entry, adds new)
  - Updates `.auths/allowed_signers` in the current repo
  - Warns about other repos that may still reference the old identity

## Implementation

### Design note

All business logic goes in **auths-sdk**. The CLI only adds the `--reset` flag and calls SDK.

### SDK — reset workflow

**File:** `crates/auths-sdk/src/setup.rs`

Add `reset()` alongside the existing `initialize()` (L49). It's the inverse operation:

```rust
/// Result of resetting an identity. CLI uses this to display what happened.
pub struct ResetReport {
    pub identity_removed: bool,
    pub registry_cleaned: bool,
    pub global_signers_cleaned: usize,   // number of entries removed
    pub repo_signers_cleaned: usize,     // number of entries removed
}

/// Wipe the current identity and clean up all artifacts.
/// Call this before `initialize()` to do a full reset+reinit.
pub fn reset(repo_root: Option<&Path>) -> Result<ResetReport> {
    let mut report = ResetReport { identity_removed: false, registry_cleaned: false, global_signers_cleaned: 0, repo_signers_cleaned: 0 };
    let home = auths_core::paths::auths_home()?;

    // 1. Remove old identity
    if home.exists() {
        std::fs::remove_dir_all(&home)?;
        report.identity_removed = true;
    }

    // 2. Clean refs/auths/registry in current repo
    if let Some(root) = repo_root {
        let status = Command::new("git")
            .current_dir(root)
            .args(["update-ref", "-d", "refs/auths/registry"])
            .status();
        report.registry_cleaned = status.map(|s| s.success()).unwrap_or(false);
    }

    // 3. Clean old entries from ~/.ssh/allowed_signers
    let ssh_signers = dirs::home_dir().unwrap().join(".ssh/allowed_signers");
    if ssh_signers.exists() {
        let content = std::fs::read_to_string(&ssh_signers)?;
        let original_count = content.lines().count();
        let filtered: Vec<&str> = content.lines()
            .filter(|l| !l.contains("@auths.local"))
            .collect();
        report.global_signers_cleaned = original_count - filtered.len();
        std::fs::write(&ssh_signers, filtered.join("\n") + "\n")?;
    }

    // 4. Clean .auths/allowed_signers in current repo
    if let Some(root) = repo_root {
        let repo_signers = root.join(".auths/allowed_signers");
        if repo_signers.exists() {
            let content = std::fs::read_to_string(&repo_signers)?;
            let original_count = content.lines().count();
            let filtered: Vec<&str> = content.lines()
                .filter(|l| !l.contains("@auths.local"))
                .collect();
            report.repo_signers_cleaned = original_count - filtered.len();
            std::fs::write(&repo_signers, filtered.join("\n") + "\n")?;
        }
    }

    Ok(report)
}
```

### CLI — thin wrapper

**File:** `crates/auths-cli/src/commands/init/mod.rs`

1. Add `--reset` flag to `InitCommand` struct (around L101):
```rust
/// Reset and reinitialize identity (implies --force)
#[clap(long)]
pub reset: bool,
```

2. Add reset logic at the top of `handle_init()` (L141), before profile selection:
```rust
if cmd.reset {
    cmd.force = true;
    let repo_root = detect_repo_root().ok();
    let report = auths_sdk::setup::reset(repo_root.as_deref())?;

    // CLI only does presentation
    if report.identity_removed { out.println("Removed old identity."); }
    if report.registry_cleaned { out.println("Cleaned refs/auths/registry."); }
    if report.global_signers_cleaned > 0 { out.println(&format!("Removed {} old entries from ~/.ssh/allowed_signers.", report.global_signers_cleaned)); }
    if report.repo_signers_cleaned > 0 { out.println(&format!("Removed {} old entries from .auths/allowed_signers.", report.repo_signers_cleaned)); }
    out.println("Warning: other repos may still reference the old identity. Run 'auths doctor' in each repo.");
}
```

After reset, the normal `auths init` flow continues and creates a fresh identity.

## Context

During dogfooding, multiple identity recreations left stale attestations in the registry. The widget showed "InvalidSignature" because old attestations referenced a different identity's key. Had to manually `git update-ref -d refs/auths/registry` and re-init to fix.


### 5. Expand `auths doctor` checks

## Problem

`auths doctor` is the natural place users go when things break, but it currently doesn't catch several common issues discovered during dogfooding:

## Checks to add

### SSH config
- Detect `UseKeychain` without `IgnoreUnknown UseKeychain` (see #74)
- Verify the SSH identity file referenced in config actually exists
- Check `gpg.format = ssh` and `commit.gpgsign = true` in git config

### Registry
- Check if `refs/auths/registry` exists in the current repo
- Verify the identity in the registry matches the current active identity
- Warn if the registry has attestations signed by a different identity (stale data from identity recreation)
- Check if registry is pushed to the remote

### Allowed signers
- Check if `~/.ssh/allowed_signers` exists and contains the current device's key
- Check if `.auths/allowed_signers` exists in the current repo
- Warn if repo's allowed_signers has placeholder/example keys
- Verify format is correct (`<principal> namespaces="git" ssh-ed25519 <key>`)

### Signing
- Verify a test signature can be created and verified (round-trip check)
- Check that `git log --show-signature` works for recent commits

## Implementation

### Architecture

The diagnostics system has three layers:

1. **Provider traits** (`crates/auths-sdk/src/ports/diagnostics.rs`): `GitDiagnosticProvider` (L64) and `CryptoDiagnosticProvider` (L78) — define what the system can check
2. **Workflow** (`crates/auths-sdk/src/workflows/diagnostics.rs`): `DiagnosticsWorkflow` — orchestrates checks, returns `DiagnosticReport`
3. **Fix adapters** (`crates/auths-cli/src/adapters/doctor_fixes.rs`): Implement `DiagnosticFix` trait — each fix addresses a specific `CheckResult`

Currently only 3 checks exist: `git_version`, `ssh_keygen`, `git_signing_config`. Add the new ones below.

### New checks to add

For each check, add a method to `DiagnosticsWorkflow` following the pattern of `check_git_signing_config()` (L72):

**1. `check_ssh_config`** — See Task 1 implementation above.

**2. `check_ssh_identity_file`** — Verify the SSH key file referenced in `~/.ssh/config` exists:
```rust
// Read ~/.ssh/config, find IdentityFile lines, check each file exists
```

**3. `check_registry_exists`** — Check `refs/auths/registry` in current repo:
```rust
fn check_registry(&self, checks: &mut Vec<CheckResult>) -> Result<(), DiagnosticError> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "refs/auths/registry"])
        .output();
    // If fails, push ConfigIssue::Absent("refs/auths/registry")
    // Also: compare identity in registry with active identity from ~/.auths
}
```

**4. `check_repo_allowed_signers`** — Check `.auths/allowed_signers` exists and has current key:
```rust
// Read .auths/allowed_signers, check for current device DID principal
// Warn if contains placeholder keys (e.g., "ssh-ed25519 AAAA..." with no real principal)
```

**5. `check_signing_roundtrip`** — Verify sign + verify works:
```rust
// Create a temp file, sign it with ssh-keygen, verify it — confirms the full chain works
```

**6. `check_pre_rotation_backup`** (Task 8) — Gentle nudge about backup.

### Extending the provider traits

Some new checks (registry, allowed signers) don't fit neatly into `GitDiagnosticProvider` or `CryptoDiagnosticProvider`. Options:
- Add methods to the existing traits
- Add a new `IdentityDiagnosticProvider` trait
- Keep the checks as standalone methods in `DiagnosticsWorkflow` that use `Command::new("git")` directly (simplest, matches the pattern of `check_git_signing_config`)

Recommended: keep them as private methods on `DiagnosticsWorkflow` (simplest). Only add new traits if the checks need mocking in tests.

### Fix adapters

For each new check that has a fix, add a struct implementing `DiagnosticFix` in `doctor_fixes.rs` and register it in `build_available_fixes()` (doctor.rs L193). Follow the pattern:

```rust
pub struct RegistryFix { /* fields */ }

impl DiagnosticFix for RegistryFix {
    fn name(&self) -> &str { "registry_sync" }
    fn is_safe(&self) -> bool { true }
    fn can_fix(&self, check: &CheckResult) -> bool { check.name == "registry_exists" && !check.passed }
    fn apply(&self) -> Result<String, DiagnosticError> {
        // git fetch ~/.auths refs/auths/registry:refs/auths/registry
        Ok("Synced registry from ~/.auths".into())
    }
}
```

### Updating `available_checks()`

Update the static slice in `available_checks()` (L31) to include all new check names, and add dispatch branches in `run_single()` (L38).

## Context

During dogfooding, every one of these issues was hit. `auths doctor` surfacing them with actionable fix commands would have saved significant debugging time.

### 6. Auto-push registry on `auths init`

## Problem

`auths init` creates the identity and writes attestations to `refs/auths/registry` in `~/.auths/.git`, but the user must manually:

1. `git fetch ~/.auths refs/auths/registry:refs/auths/registry` — pull registry into the project repo
2. `git push origin refs/auths/registry` — push to remote

This is non-obvious and undiscoverable. New users don't know the registry exists in `~/.auths`, and the fetch-from-local-path pattern is uncommon.

## Expected behavior

After `auths init` (when run inside a git repo):
- Automatically copy `refs/auths/registry` from `~/.auths` into the current repo
- Prompt or auto-push to the remote

This is related to but distinct from #73 (pre-push hook for ongoing sync). This issue is about the **initial setup** experience.

## Implementation

### Design note

All business logic goes in **auths-sdk**. The CLI is a thin presentation layer.

### SDK — registry sync workflow

**File:** `crates/auths-sdk/src/workflows/registry_sync.rs` (new file)

```rust
pub struct RegistrySyncReport {
    pub fetched: bool,
    pub pushed: bool,
    pub skipped_reason: Option<String>,
}

pub struct RegistrySyncWorkflow;

impl RegistrySyncWorkflow {
    /// Sync refs/auths/registry from ~/.auths into the given repo, optionally push to remote.
    pub fn sync_to_repo(repo_root: &Path) -> Result<RegistrySyncReport> {
        let home = auths_core::paths::auths_home()?;
        let mut report = RegistrySyncReport { fetched: false, pushed: false, skipped_reason: None };

        // Fetch registry from ~/.auths into this repo
        let status = Command::new("git")
            .current_dir(repo_root)
            .args(["fetch", &home.to_string_lossy(), "refs/auths/registry:refs/auths/registry"])
            .status()?;
        if !status.success() {
            report.skipped_reason = Some("could not fetch registry from ~/.auths".into());
            return Ok(report);
        }
        report.fetched = true;

        // Push to remote (if remote exists)
        let remote_check = Command::new("git")
            .current_dir(repo_root)
            .args(["remote", "get-url", "origin"])
            .output()?;
        if remote_check.status.success() {
            let push_status = Command::new("git")
                .current_dir(repo_root)
                .args(["push", "origin", "refs/auths/registry", "--force"])
                .status()?;
            report.pushed = push_status.success();
        }

        Ok(report)
    }
}
```

Register the module in `crates/auths-sdk/src/workflows/mod.rs`.

### CLI — thin wrapper

**CLI caller** (`crates/auths-cli/src/commands/init/mod.rs`, post-setup phase ~L236):
```rust
if let Ok(repo_root) = detect_repo_root() {
    let report = RegistrySyncWorkflow::sync_to_repo(&repo_root)?;
    if report.fetched { out.println("✓ Synced refs/auths/registry into this repo."); }
    if report.pushed { out.println("✓ Pushed refs/auths/registry to origin."); }
    if let Some(reason) = report.skipped_reason { out.println(&format!("⚠ Registry sync skipped: {reason}")); }
}
```

**Note:** This is related to Task 2 (pre-push hook) but handles the **initial** sync. Task 2 handles **ongoing** sync on subsequent pushes. Both should be implemented.

## Context

During dogfooding, `auths init --force` completed successfully but the widget showed errors because the registry was never pushed to the remote. Required manual git plumbing to fix.

### 7. Single-command onboarding (`auths init` in a repo)

## Problem

The current onboarding flow requires multiple manual steps that aren't documented in sequence:

1. `auths init` — create identity, configure git signing
2. Manually create/update `.auths/allowed_signers` in the repo
3. Manually fetch registry from `~/.auths` into the project repo
4. Manually push `refs/auths/registry` to the remote
5. Manually add `.github/workflows/verify-commits.yml`
6. Manually fix SSH config if `UseKeychain` breaks

A first-time user hitting any of these steps without guidance will get stuck.

## Expected behavior

`auths init` (when run in a git repo) should handle the full happy path:

1. Create identity + configure signing (already works)
2. Write `.auths/allowed_signers` with the new key (#77)
3. Copy registry into the repo and push to remote (#80)
4. Fix SSH config issues (#74)
5. Optionally scaffold the CI workflow (or print the command to do so)

Each step should have clear output showing what was done. If any step fails, `auths doctor` (#79) should catch it.

## Non-goals

- Don't force GitHub Pages setup (that's for the widget, not core signing)
- Don't require network access for the identity creation itself

## Implementation

### Design note

This is an **integration task**. The CLI orchestrates SDK functions and displays results. All business logic lives in SDK workflows (Tasks 1, 3, 6) and auths-id (Task 2).

**File:** `crates/auths-cli/src/commands/init/mod.rs`

Update `run_developer_setup()` (L166) to add new steps after identity creation. The current flow has 5 phases. Add to the POST-SETUP phase (L236):

```rust
// === POST-SETUP (existing) ===
offer_shell_completions(interactive, &out)?;
write_allowed_signers(&config)?;          // existing: writes ~/.ssh/allowed_signers

// === NEW STEPS — CLI calls SDK, then prints results ===

// Task 1: SSH config (SDK: SshConfigWorkflow)
if let Some(msg) = SshConfigWorkflow::ensure_config(&ssh_key_path)? {
    out.println(&format!("✓ {msg}"));
}

// Task 3: Repo allowed_signers (SDK: AllowedSigners::sync_repo)
if let Ok(repo_root) = detect_repo_root() {
    let report = AllowedSigners::sync_repo(&repo_root)?;
    out.println(&format!("✓ Wrote {} signer(s) to .auths/allowed_signers", report.added));

    // Task 6: Registry sync (SDK: RegistrySyncWorkflow)
    let sync = RegistrySyncWorkflow::sync_to_repo(&repo_root)?;
    if sync.fetched { out.println("✓ Synced refs/auths/registry into this repo."); }
    if sync.pushed { out.println("✓ Pushed refs/auths/registry to origin."); }
    if let Some(reason) = sync.skipped_reason { out.println(&format!("⚠ Registry sync: {reason}")); }

    // Task 2: Pre-push hook (auths-id: install_pre_push_hook)
    install_pre_push_hook(&repo_root)?;
    out.println("✓ Pre-push hook installed");
}

// Optional: print CI workflow instructions
out.println("\nTo add CI verification, create .github/workflows/verify-commits.yml:");
out.println("  See: https://github.com/marketplace/actions/verify-commit-signatures-with-auths");
```

Each step should be wrapped in error handling that warns but doesn't fail the overall init (non-fatal). The init should complete even if, e.g., the user has no remote configured.

**Output:** Each step prints what it did. On failure, print a warning and suggest running `auths doctor` for diagnosis.

## Context

End-to-end dogfooding session: took ~2 hours to get from `auths init` to a working verification badge, mostly due to undocumented manual steps between the init and the verification actually working.

### 8. Pre-rotation key backup nudge

## Problem

KERI pre-rotation is one of the strongest features of the identity model — the next rotation key is committed to at inception, so key compromise doesn't mean identity loss. But currently, users are never prompted to back up or even know about their pre-rotation key.

We shouldn't surface this during onboarding. The `auths init` flow should stay fast and frictionless — like how `ssh-keygen` lets you skip the passphrase and most tutorials tell you to. Security-conscious users set one later. Same principle: don't front-load complexity that blocks adoption.

## Proposed behavior

### 1. `auths doctor` — gentle nudge
After identity creation, `auths doctor` should include a check:
> "You have a pre-rotation key but haven't backed it up. Run `auths key backup` to export it."

Low severity, informational — not a blocker.

### 2. `auths key backup` / `auths recovery export` — explicit command
A dedicated command to export the pre-rotation key material when the user is ready. Clear warnings about what it is and how to store it safely.

### 3. Post-rotation prompt
After a user performs their first key rotation (`auths key rotate`), prompt them:
> "You just rotated keys. Your new pre-rotation commitment is set. Run `auths key backup` to save your recovery key."

This is the natural moment where pre-rotation becomes concrete and meaningful.

### 4. Enterprise/team docs
For organizations that need formal key ceremony procedures, document the pre-rotation backup as part of team onboarding — but keep it out of the individual developer fast path.

## Implementation

### `auths doctor` — backup check

**File:** `crates/auths-sdk/src/workflows/diagnostics.rs`

Add `check_pre_rotation_backup()` as a private method on `DiagnosticsWorkflow`:

```rust
fn check_pre_rotation_backup(&self, checks: &mut Vec<CheckResult>) -> Result<(), DiagnosticError> {
    let home = auths_core::paths::auths_home()
        .map_err(|e| DiagnosticError::ExecutionFailed(e.to_string()))?;

    // Check if a backup marker file exists (e.g., ~/.auths/.backup_exported)
    let backup_marker = home.join(".backup_exported");
    if home.exists() && !backup_marker.exists() {
        checks.push(CheckResult {
            name: "pre_rotation_backup".into(),
            passed: true, // informational, not a failure
            message: Some(
                "You have a pre-rotation key but haven't backed it up. Run `auths key backup` to export it.".into()
            ),
            config_issues: vec![],
        });
    }
    Ok(())
}
```

This is informational only — `passed: true` means it won't fail the doctor run, but the message will be displayed.

### `auths key backup` — new command

#### SDK — export logic

**File:** `crates/auths-sdk/src/workflows/key_backup.rs` (new file)

```rust
pub struct KeyBackupResult {
    pub key_material: Vec<u8>,   // the exported pre-rotation private key
    pub key_hash: String,        // the pre-rotation commitment hash
}

pub struct KeyBackupWorkflow;

impl KeyBackupWorkflow {
    /// Export the pre-rotation key material. Marks backup as completed.
    pub fn export() -> Result<KeyBackupResult> {
        let home = auths_core::paths::auths_home()?;
        // Read the next_key_hash from state.json (the pre-rotation commitment)
        // Export the pre-rotation private key from the keychain
        // Touch ~/.auths/.backup_exported as marker
        todo!()
    }

    /// Check if backup has been performed.
    pub fn is_backed_up() -> Result<bool> {
        let home = auths_core::paths::auths_home()?;
        Ok(home.join(".backup_exported").exists())
    }
}
```

Register the module in `crates/auths-sdk/src/workflows/mod.rs`.

#### CLI — thin wrapper

**File:** `crates/auths-cli/src/commands/mod.rs` — register new subcommand
**File:** `crates/auths-cli/src/commands/key/backup.rs` — new file

```rust
pub fn handle_key_backup() -> Result<()> {
    let out = Output::new();
    out.println("⚠ This exports your pre-rotation recovery key.");
    out.println("  Store it securely (password manager, hardware token, etc.).");
    out.println("  Anyone with this key can recover your identity after key rotation.\n");

    let result = KeyBackupWorkflow::export()?;
    // Display key material to user
    out.println(&format!("Pre-rotation key hash: {}", result.key_hash));
    // ... display key_material in a safe format
    Ok(())
}
```

### Post-rotation prompt

**File:** wherever `auths key rotate` is handled — after successful rotation, print:
```
You just rotated keys. Your new pre-rotation commitment is set.
Run `auths key backup` to save your recovery key.
```

## Non-goals

- Don't require backup during `auths init`
- Don't block any workflow on missing backup
- Don't make the user think about key management before they've signed their first commit
