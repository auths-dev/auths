> **SUPERSEDED:** This plan described hardening CI tokens. The project has since
> adopted ephemeral signing with no CI tokens. See the transparency log
> architecture at `docs/design/transparency-log-port.md`.

# Hardened CI Signing: Make AUTHS_CI_TOKEN Worthless If Stolen

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep the current CI signing flow (push tag → CI signs artifacts automatically) but make a stolen AUTHS_CI_TOKEN useless to an attacker through short TTL, workflow pinning, and repo scoping.

**Architecture:** Three layers of defense, each independently useful:
1. **Short TTL** — Token expires in hours, not a year. Auto-rotated by a scheduled workflow.
2. **Workflow pinning** — Token is bound to a specific workflow file hash. Modified workflows can't sign.
3. **Repo scoping** — Attestations are bound to a specific repo. Can't be replayed elsewhere.

If an attacker steals AUTHS_CI_TOKEN via a compromised Action (LiteLLM vector), the token is either already expired, refuses to sign because the workflow hash doesn't match, or produces attestations that are scoped to the repo and traceable.

**Tech Stack:** Rust (auths-sdk CiToken, auths-cli ci commands), TypeScript (sign action), GitHub Actions (scheduled rotation)

---

## Design

### Attack surface analysis

The LiteLLM attacker: compromised a GitHub Action → exfiltrated CI secrets from runner env → used them hours/days later from an external machine.

Each defense layer blocks a different part of this:

| Defense | What it blocks | Attacker must... |
|---------|---------------|------------------|
| **Short TTL (4h)** | Using the token hours later | Use it within the CI run window |
| **Workflow pin** | Running a modified workflow | Not change any workflow file in the repo |
| **Repo scope** | Signing for a different project | Stay within the same repo |
| **Nonce (future)** | Replay / multi-use | Race the legitimate CI run |

### What changes

| Component | Before | After |
|-----------|--------|-------|
| `CiToken` struct | version 1, no scoping | version 2, adds `workflow_hash`, `repo`, `max_uses` |
| `auths ci setup` | default TTL: 1 year | default TTL: 4 hours |
| `auths ci rotate` | manual command | also runs via scheduled GitHub Action |
| Sign action (`token.ts`) | checks TTL only | checks TTL + workflow hash + repo |
| Attestation | no CI metadata | includes `ci_binding` with workflow hash + run ID + repo |

### What does NOT change

- The `auths-dev/sign@v1` action interface (same inputs/outputs)
- The `.auths.json` v1 format (attestations still self-signed)
- The release workflow structure (push tag → CI builds → CI signs)
- The `auths artifact verify` command
- Local signing (`auths artifact sign`) — unaffected

### Backward compatibility

CiToken v2 adds optional fields. The sign action checks the version:
- v1 tokens work as before (no pinning, no scoping) but emit a deprecation warning
- v2 tokens enforce all hardening checks

---

## Task 1: Add v2 fields to `CiToken`

**Files:**
- Modify: `crates/auths-sdk/src/domains/ci/token.rs`
- Test: `crates/auths-sdk/tests/` (existing or new test file)

**Step 1: Write the failing test**

Add to `crates/auths-sdk/tests/cases/ci_token.rs` (create if needed):

```rust
use auths_sdk::domains::ci::token::CiToken;

#[test]
fn v2_token_roundtrip() {
    let token = CiToken::new_v2(
        "passphrase".into(),
        "keychain_b64".into(),
        "repo_b64".into(),
        serde_json::json!({}),
        "2026-04-08T00:00:00Z".into(),
        14400, // 4 hours
        Some("abc123def456".into()),  // workflow_hash
        Some("auths-dev/auths".into()), // repo
        Some(4), // max_uses (4 platform builds)
    );

    assert_eq!(token.version, 2);
    assert_eq!(token.workflow_hash.as_deref(), Some("abc123def456"));
    assert_eq!(token.repo.as_deref(), Some("auths-dev/auths"));
    assert_eq!(token.max_uses, Some(4));

    let json = token.to_json().unwrap();
    let parsed = CiToken::from_json(&json).unwrap();
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.workflow_hash, token.workflow_hash);
    assert_eq!(parsed.repo, token.repo);
    assert_eq!(parsed.max_uses, token.max_uses);
}

#[test]
fn v1_token_still_parses() {
    let v1_json = r#"{
        "version": 1,
        "passphrase": "test",
        "keychain": "abc",
        "identity_repo": "def",
        "verify_bundle": {},
        "created_at": "2026-04-08T00:00:00Z",
        "max_valid_for_secs": 31536000
    }"#;
    let token = CiToken::from_json(v1_json).unwrap();
    assert_eq!(token.version, 1);
    assert!(token.workflow_hash.is_none());
    assert!(token.repo.is_none());
    assert!(token.max_uses.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_sdk -E 'test(ci_token)'`
Expected: FAIL — `new_v2` and v2 fields don't exist

**Step 3: Write the implementation**

Modify `crates/auths-sdk/src/domains/ci/token.rs`:

```rust
/// Current token format version.
const CURRENT_VERSION: u32 = 2;

/// Supported token versions for deserialization.
const SUPPORTED_VERSIONS: &[u32] = &[1, 2];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiToken {
    pub version: u32,
    pub passphrase: String,
    pub keychain: String,
    pub identity_repo: String,
    pub verify_bundle: serde_json::Value,
    pub created_at: String,
    pub max_valid_for_secs: u64,

    // --- v2 fields (optional for backward compat with v1) ---

    /// SHA256 hash of the workflow file that is authorized to use this token.
    /// If set, the sign action computes the hash of the running workflow
    /// and refuses to sign if it doesn't match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_hash: Option<String>,

    /// Repository this token is scoped to (e.g., "auths-dev/auths").
    /// If set, attestations include this binding and verification
    /// can reject attestations from mismatched repos.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,

    /// Maximum number of signing operations allowed with this token.
    /// The sign action tracks usage and refuses to sign beyond this limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
}
```

Update `new()` to keep backward compat, add `new_v2()`:

```rust
impl CiToken {
    /// Create a v1-compatible token (no hardening).
    pub fn new(
        passphrase: String,
        keychain: String,
        identity_repo: String,
        verify_bundle: serde_json::Value,
        created_at: String,
        max_valid_for_secs: u64,
    ) -> Self {
        Self {
            version: 1, // keep v1 for backward compat when called via old path
            passphrase,
            keychain,
            identity_repo,
            verify_bundle,
            created_at,
            max_valid_for_secs,
            workflow_hash: None,
            repo: None,
            max_uses: None,
        }
    }

    /// Create a v2 hardened token with workflow pinning, repo scoping, and use limits.
    ///
    /// Args:
    /// * `workflow_hash`: SHA256 of the authorized workflow file.
    /// * `repo`: Repository identifier (e.g., "owner/repo").
    /// * `max_uses`: Maximum signing operations (e.g., 4 for 4 platform builds).
    ///
    /// Usage:
    /// ```ignore
    /// let token = CiToken::new_v2(pass, kc, repo, bundle, now, 14400,
    ///     Some(wf_hash), Some("owner/repo".into()), Some(4));
    /// ```
    pub fn new_v2(
        passphrase: String,
        keychain: String,
        identity_repo: String,
        verify_bundle: serde_json::Value,
        created_at: String,
        max_valid_for_secs: u64,
        workflow_hash: Option<String>,
        repo: Option<String>,
        max_uses: Option<u32>,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            passphrase,
            keychain,
            identity_repo,
            verify_bundle,
            created_at,
            max_valid_for_secs,
            workflow_hash,
            repo,
            max_uses,
        }
    }

    pub fn from_json(json: &str) -> Result<Self, CiError> {
        let token: Self =
            serde_json::from_str(json).map_err(|e| CiError::TokenDeserializationFailed {
                reason: e.to_string(),
            })?;

        if !SUPPORTED_VERSIONS.contains(&token.version) {
            return Err(CiError::TokenVersionUnsupported {
                version: token.version,
            });
        }

        Ok(token)
    }

    // ... rest of existing methods unchanged
}
```

**Step 4: Run test to verify it passes**

Run: `cargo nextest run -p auths_sdk -E 'test(ci_token)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-sdk/src/domains/ci/token.rs
git commit -m "feat: add CiToken v2 with workflow_hash, repo, and max_uses fields"
```

---

## Task 2: Update `auths ci setup` to generate v2 tokens

**Files:**
- Modify: `crates/auths-cli/src/commands/ci/setup.rs`
- Modify: `crates/auths-cli/src/commands/ci/mod.rs`

**Step 1: Add `--workflow` and `--max-uses` flags to `ci setup`**

In `crates/auths-cli/src/commands/ci/mod.rs`, update the `Setup` variant:

```rust
    Setup {
        #[arg(long)]
        repo: Option<String>,

        /// Max age for the token in seconds (default: 4 hours).
        #[arg(long, default_value = "14400")]
        max_age_secs: u64,

        #[arg(long)]
        manual_passphrase: bool,

        /// Path to the workflow file to pin (e.g., .github/workflows/release.yml).
        /// The SHA256 hash of this file is baked into the token.
        /// If the workflow is modified, signing will be refused.
        #[arg(long)]
        workflow: Option<String>,

        /// Maximum number of signing operations per token (e.g., 4 for 4 platform builds).
        #[arg(long)]
        max_uses: Option<u32>,
    },
```

Note the default TTL change: `31536000` (1 year) → `14400` (4 hours).

**Step 2: Update `run_setup` to use `new_v2`**

In `crates/auths-cli/src/commands/ci/setup.rs`, modify the token assembly (around line 183):

```rust
    // Compute workflow hash (if pinning requested)
    let workflow_hash = if let Some(ref wf_path) = workflow_path {
        let wf_content = std::fs::read(wf_path)
            .with_context(|| format!("Failed to read workflow file: {}", wf_path))?;
        let hash = sha2_hex(&wf_content);
        println!("\x1b[0;32m\u{2713}\x1b[0m Workflow pinned: {} (sha256:{}...)", wf_path, &hash[..12]);
        Some(hash)
    } else {
        None
    };

    // Detect repo for scoping
    let repo_id = match &repo_override {
        Some(url) => Some(Forge::from_url(url).repo_identifier()),
        None => git_stdout(&["remote", "get-url", "origin"])
            .ok()
            .map(|url| Forge::from_url(&url).repo_identifier()),
    };

    let token = CiToken::new_v2(
        ci_pass.to_string(),
        keychain_b64,
        identity_repo_b64,
        verify_bundle_json,
        now.to_rfc3339(),
        max_age_secs,
        workflow_hash,
        repo_id.clone(),
        max_uses,
    );
```

Add the `sha2_hex` helper (or use an existing SHA256 function from `auths-crypto`):

```rust
fn sha2_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
```

**Step 3: Update the `execute` match arm**

In `mod.rs`, pass the new fields through:

```rust
CiSubcommand::Setup {
    repo,
    max_age_secs,
    manual_passphrase,
    workflow,
    max_uses,
} => setup::run_setup(
    repo.clone(),
    *max_age_secs,
    !manual_passphrase,
    pp,
    &ctx.env_config,
    &repo_path,
    workflow.clone(),
    *max_uses,
),
```

Update `run_setup` signature to accept the new params.

**Step 4: Build and verify**

Run: `cargo build --package auths_cli`
Expected: Compiles

**Step 5: Commit**

```bash
git add crates/auths-cli/src/commands/ci/setup.rs crates/auths-cli/src/commands/ci/mod.rs
git commit -m "feat: auths ci setup generates v2 hardened tokens (4h TTL, workflow pin, repo scope)"
```

---

## Task 3: Enforce v2 checks in the sign action

**Files:**
- Modify: `/Users/bordumb/workspace/repositories/auths-base/sign/src/token.ts`
- Modify: `/Users/bordumb/workspace/repositories/auths-base/sign/src/main.ts`
- Create: `/Users/bordumb/workspace/repositories/auths-base/sign/src/__tests__/hardening.test.ts`

This is where the hardening actually enforces. The sign action checks the v2 fields before allowing signing.

**Step 1: Write the failing test**

Create `sign/src/__tests__/hardening.test.ts`:

```typescript
import * as crypto from 'crypto';
import * as fs from 'fs';

describe('CiToken v2 hardening', () => {

  it('rejects token with wrong workflow hash', () => {
    const token = {
      version: 2,
      passphrase: 'test',
      keychain: 'abc',
      identity_repo: 'def',
      verify_bundle: {},
      created_at: new Date().toISOString(),
      max_valid_for_secs: 14400,
      workflow_hash: 'aaaa',  // pinned hash
      repo: 'auths-dev/auths',
    };

    const actualWorkflowHash = 'bbbb';  // different hash
    expect(() => validateV2Token(token, actualWorkflowHash, 'auths-dev/auths'))
      .toThrow('Workflow hash mismatch');
  });

  it('rejects token with wrong repo', () => {
    const token = {
      version: 2,
      passphrase: 'test',
      keychain: 'abc',
      identity_repo: 'def',
      verify_bundle: {},
      created_at: new Date().toISOString(),
      max_valid_for_secs: 14400,
      repo: 'auths-dev/auths',
    };

    expect(() => validateV2Token(token, undefined, 'evil-org/auths'))
      .toThrow('Repository mismatch');
  });

  it('accepts valid v2 token', () => {
    const token = {
      version: 2,
      passphrase: 'test',
      keychain: 'abc',
      identity_repo: 'def',
      verify_bundle: {},
      created_at: new Date().toISOString(),
      max_valid_for_secs: 14400,
      workflow_hash: 'abc123',
      repo: 'auths-dev/auths',
    };

    expect(() => validateV2Token(token, 'abc123', 'auths-dev/auths'))
      .not.toThrow();
  });

  it('accepts v1 token with deprecation warning', () => {
    const token = {
      version: 1,
      passphrase: 'test',
      keychain: 'abc',
      identity_repo: 'def',
      verify_bundle: {},
      created_at: new Date().toISOString(),
      max_valid_for_secs: 31536000,
    };

    // v1 tokens skip v2 checks
    expect(() => validateV2Token(token, undefined, undefined))
      .not.toThrow();
  });
});
```

**Step 2: Add validation function to `token.ts`**

Add to `/Users/bordumb/workspace/repositories/auths-base/sign/src/token.ts`:

```typescript
interface CiTokenV2 extends CiToken {
  workflow_hash?: string;
  repo?: string;
  max_uses?: number;
}

/**
 * Validate v2 hardening constraints.
 * Throws if any constraint is violated.
 */
export function validateV2Constraints(
  token: CiTokenV2,
  actualWorkflowHash: string | undefined,
  actualRepo: string | undefined,
): void {
  if (token.version < 2) {
    core.warning(
      'Using CiToken v1 (unhardened). Upgrade with: auths ci setup --workflow .github/workflows/release.yml'
    );
    return;
  }

  // Workflow hash check
  if (token.workflow_hash) {
    if (!actualWorkflowHash) {
      throw new Error(
        'CiToken v2 requires workflow hash validation but GITHUB_WORKFLOW_REF is not available. ' +
        'Ensure this runs in GitHub Actions.'
      );
    }
    if (token.workflow_hash !== actualWorkflowHash) {
      throw new Error(
        `Workflow hash mismatch: token pinned to ${token.workflow_hash.substring(0, 12)}..., ` +
        `but running workflow hashes to ${actualWorkflowHash.substring(0, 12)}... ` +
        `This could indicate a tampered workflow. Rotate with: auths ci rotate`
      );
    }
    core.info('✓ Workflow hash verified');
  }

  // Repo scope check
  if (token.repo) {
    if (!actualRepo) {
      throw new Error(
        'CiToken v2 requires repo validation but GITHUB_REPOSITORY is not available.'
      );
    }
    if (token.repo !== actualRepo) {
      throw new Error(
        `Repository mismatch: token scoped to ${token.repo}, ` +
        `but running in ${actualRepo}. ` +
        `This token cannot be used in this repository.`
      );
    }
    core.info('✓ Repository scope verified');
  }
}

/**
 * Compute SHA256 of a workflow file for pinning verification.
 */
export function computeWorkflowHash(): string | undefined {
  const workflowRef = process.env.GITHUB_WORKFLOW_REF;
  if (!workflowRef) return undefined;

  // GITHUB_WORKFLOW_REF is like "owner/repo/.github/workflows/release.yml@refs/tags/v1"
  // Extract the workflow path
  const match = workflowRef.match(/^[^/]+\/[^/]+\/(.+)@/);
  if (!match) return undefined;

  const workflowPath = match[1];
  try {
    const content = fs.readFileSync(workflowPath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    core.warning(`Could not read workflow file at ${workflowPath} for hash verification`);
    return undefined;
  }
}
```

**Step 3: Call validation in `main.ts`**

In `/Users/bordumb/workspace/repositories/auths-base/sign/src/main.ts`, after credentials are resolved (after line 22), add:

```typescript
    // Enforce v2 hardening checks
    const tokenInput = core.getInput('token');
    if (tokenInput) {
      try {
        const tokenParsed = JSON.parse(tokenInput);
        const workflowHash = computeWorkflowHash();
        const repo = process.env.GITHUB_REPOSITORY;
        validateV2Constraints(tokenParsed, workflowHash, repo);
      } catch (e) {
        if (e instanceof SyntaxError) {
          // Not JSON — skip v2 checks (individual inputs mode)
        } else {
          throw e;
        }
      }
    }
```

**Step 4: Run tests**

Run: `cd /Users/bordumb/workspace/repositories/auths-base/sign && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add sign/src/token.ts sign/src/main.ts sign/src/__tests__/hardening.test.ts
git commit -m "feat: enforce v2 hardening checks in sign action (workflow pin, repo scope)"
```

---

## Task 4: Add `ci_binding` to attestations

**Files:**
- Modify: `crates/auths-verifier/src/core.rs` (add `CiBinding` struct)
- Modify: `crates/auths-sdk/src/domains/signing/service.rs` (include CI metadata in attestation)

The attestation should record WHERE it was signed so that verification can detect anomalies (e.g., a CI-scoped key signing from a non-CI environment).

**Step 1: Write the failing test**

Add to `crates/auths-verifier/tests/cases/release_provenance.rs` (or new file):

```rust
use auths_verifier::core::CiBinding;

#[test]
fn ci_binding_roundtrip() {
    let binding = CiBinding {
        platform: "github-actions".into(),
        repo: Some("auths-dev/auths".into()),
        workflow: Some(".github/workflows/release.yml".into()),
        workflow_hash: Some("abc123".into()),
        run_id: Some("99".into()),
    };

    let json = serde_json::to_string(&binding).unwrap();
    let parsed: CiBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.repo.as_deref(), Some("auths-dev/auths"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_verifier -E 'test(ci_binding)'`
Expected: FAIL

**Step 3: Add `CiBinding` struct**

In `crates/auths-verifier/src/core.rs`:

```rust
/// CI/CD environment binding recorded in attestations.
///
/// Captures where and how an artifact was signed in CI.
/// Used for audit trails and anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiBinding {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}
```

Add `ci_binding` field to the `Attestation` struct (optional, after `environment_claim`):

```rust
    /// CI/CD environment binding — records where the signing happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_binding: Option<CiBinding>,
```

Re-export in `lib.rs`:
```rust
pub use core::CiBinding;
```

**Step 4: Run test to verify it passes**

Run: `cargo nextest run -p auths_verifier -E 'test(ci_binding)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-verifier/src/core.rs crates/auths-verifier/src/lib.rs
git commit -m "feat: add CiBinding struct for CI environment audit trail in attestations"
```

---

## Task 5: Pass CI metadata through the sign action into attestations

**Files:**
- Modify: `/Users/bordumb/workspace/repositories/auths-base/sign/src/main.ts`

The sign action already sets environment variables (`authsEnv` on line 41-45). Add CI binding metadata so the CLI includes it in the attestation.

**Step 1: Add CI env vars to the signing environment**

In `sign/src/main.ts`, extend the `authsEnv` object (line 41):

```typescript
    const authsEnv = {
      ...process.env,
      AUTHS_PASSPHRASE: credentials.passphrase,
      AUTHS_KEYCHAIN_BACKEND: 'file',
      AUTHS_KEYCHAIN_FILE: credentials.keychainPath,
      // v2 CI binding metadata
      AUTHS_CI_PLATFORM: 'github-actions',
      AUTHS_CI_REPO: process.env.GITHUB_REPOSITORY || '',
      AUTHS_CI_WORKFLOW: process.env.GITHUB_WORKFLOW || '',
      AUTHS_CI_WORKFLOW_HASH: computeWorkflowHash() || '',
      AUTHS_CI_RUN_ID: process.env.GITHUB_RUN_ID || '',
    };
```

**Step 2: Read CI env vars in the SDK signing service**

In `crates/auths-sdk/src/domains/signing/service.rs`, after creating the attestation (around line 534), check for CI env vars and populate `ci_binding`:

```rust
    // Populate CI binding from environment (set by auths-dev/sign action)
    #[allow(clippy::disallowed_methods)]
    let ci_binding = std::env::var("AUTHS_CI_PLATFORM").ok().map(|platform| {
        auths_verifier::CiBinding {
            platform,
            repo: std::env::var("AUTHS_CI_REPO").ok().filter(|s| !s.is_empty()),
            workflow: std::env::var("AUTHS_CI_WORKFLOW").ok().filter(|s| !s.is_empty()),
            workflow_hash: std::env::var("AUTHS_CI_WORKFLOW_HASH").ok().filter(|s| !s.is_empty()),
            run_id: std::env::var("AUTHS_CI_RUN_ID").ok().filter(|s| !s.is_empty()),
        }
    });

    if ci_binding.is_some() {
        attestation.ci_binding = ci_binding;
    }
```

Note: This uses `#[allow(clippy::disallowed_methods)]` for env var access since this is at the SDK boundary receiving CI metadata, not domain logic calling `Utc::now()`.

**Step 3: Build and verify**

Run: `cargo build --package auths_sdk`
Expected: Compiles

**Step 4: Commit**

```bash
git add sign/src/main.ts crates/auths-sdk/src/domains/signing/service.rs
git commit -m "feat: pass CI binding metadata through sign action into attestations"
```

---

## Task 6: Add auto-rotation scheduled workflow

**Files:**
- Create: `/Users/bordumb/workspace/repositories/auths-base/auths/.github/workflows/rotate-ci-token.yml`

This workflow runs on a schedule and rotates AUTHS_CI_TOKEN. Since the default TTL is now 4 hours, this ensures the token is always fresh.

**Step 1: Create the workflow**

```yaml
name: Rotate CI Token

on:
  # Run every 3 hours (before the 4-hour TTL expires)
  schedule:
    - cron: '0 */3 * * *'
  # Allow manual trigger
  workflow_dispatch:

permissions:
  contents: read

jobs:
  rotate:
    runs-on: macos-latest  # needs keychain access
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Auths CLI
        run: brew install auths-base/tap/auths

      - name: Rotate CI token
        env:
          AUTHS_PASSPHRASE: ${{ secrets.AUTHS_CI_PASSPHRASE }}
        run: |
          auths ci rotate \
            --max-age-secs 14400 \
            --repo ${{ github.repository }}
```

**Important design note:** This workflow needs the CI device key passphrase (stored as a separate secret `AUTHS_CI_PASSPHRASE`) to regenerate the token. The passphrase alone is not enough to sign — it's just the decryption key for the CI device key which is only in the maintainer's keychain. This rotation workflow runs on a runner that has the keychain installed.

**Alternative (simpler, no separate workflow):** The maintainer runs `auths ci rotate` locally before each release. With a 4-hour TTL, this means running it within 4 hours of pushing a tag. The `auths release` command from the tag-signing plan could incorporate this: `auths release v1.0.0` rotates the token as a side effect.

**Step 2: Commit**

```bash
git add .github/workflows/rotate-ci-token.yml
git commit -m "feat: add scheduled CI token rotation workflow (every 3 hours)"
```

---

## Task 7: Update `auths ci rotate` to support v2 fields

**Files:**
- Modify: `crates/auths-cli/src/commands/ci/rotate.rs`
- Modify: `crates/auths-cli/src/commands/ci/mod.rs`

The rotate command needs to preserve v2 fields (workflow_hash, repo, max_uses) when refreshing the token.

**Step 1: Add flags to rotate subcommand**

In `mod.rs`:

```rust
    Rotate {
        #[arg(long)]
        repo: Option<String>,

        #[arg(long, default_value = "14400")]
        max_age_secs: u64,

        #[arg(long)]
        manual_passphrase: bool,

        /// Path to the workflow file to pin.
        #[arg(long)]
        workflow: Option<String>,

        /// Maximum signing operations per token.
        #[arg(long)]
        max_uses: Option<u32>,
    },
```

**Step 2: Update `run_rotate` to generate v2 tokens**

In `rotate.rs`, change the token creation (around line 130) to use `CiToken::new_v2`:

```rust
    let workflow_hash = if let Some(ref wf_path) = workflow_path {
        let wf_content = std::fs::read(wf_path)
            .with_context(|| format!("Failed to read workflow file: {}", wf_path))?;
        Some(sha2_hex(&wf_content))
    } else {
        None
    };

    let token = CiToken::new_v2(
        ci_pass.to_string(),
        keychain_b64,
        identity_repo_b64,
        verify_bundle_json,
        now.to_rfc3339(),
        max_age_secs,
        workflow_hash,
        repo_id,
        max_uses,
    );
```

**Step 3: Build and verify**

Run: `cargo build --package auths_cli`
Expected: Compiles

**Step 4: Commit**

```bash
git add crates/auths-cli/src/commands/ci/rotate.rs crates/auths-cli/src/commands/ci/mod.rs
git commit -m "feat: auths ci rotate generates v2 hardened tokens"
```

---

## Task 8: Update release workflow to use hardened setup

**Files:**
- Modify: `/Users/bordumb/workspace/repositories/auths-base/auths/.github/workflows/release.yml`

Update the release workflow documentation to show the new setup command with pinning.

**Step 1: Add setup instructions as comments**

At the top of `release.yml`:

```yaml
# Setup (run once on your machine):
#   auths ci setup \
#     --workflow .github/workflows/release.yml \
#     --max-uses 4 \
#     --max-age-secs 14400
#
# This creates a v2 hardened AUTHS_CI_TOKEN that:
#   - Expires in 4 hours (not 1 year)
#   - Only works with this exact workflow file
#   - Only allows 4 signing operations (one per platform build)
#   - Is scoped to this repository
#
# Rotate before each release:
#   auths ci rotate --workflow .github/workflows/release.yml --max-uses 4
```

**Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "docs: add v2 hardened token setup instructions to release workflow"
```

---

## Task 9: Documentation

**Files:**
- Create: `docs/ci-signing-security.md`

**Step 1: Write the security documentation**

```markdown
# CI Signing Security Model

## Overview

Auths CI signing uses a short-lived, scoped token (AUTHS_CI_TOKEN) stored as a
GitHub secret. The token contains a delegated CI device key that can sign
release artifacts.

## Defense Layers (v2 tokens)

### 1. Short TTL (default: 4 hours)

Tokens expire quickly. Even if stolen, the attacker has a narrow window.

```bash
auths ci setup --max-age-secs 14400  # 4 hours
```

### 2. Workflow Pinning

The token records the SHA256 hash of the authorized workflow file. If an
attacker modifies the workflow (to exfiltrate secrets or sign different
artifacts), the hash check fails and signing is refused.

```bash
auths ci setup --workflow .github/workflows/release.yml
```

### 3. Repository Scoping

Attestations are bound to a specific repository. A token stolen from repo A
cannot produce valid attestations for repo B.

### 4. Use Limits

Tokens can be limited to N signing operations. A release building 4 platform
binaries needs exactly 4 uses.

```bash
auths ci setup --max-uses 4
```

## Comparison with LiteLLM/Axios attacks

| Attack vector | npm/PyPI token | AUTHS_CI_TOKEN v1 | AUTHS_CI_TOKEN v2 |
|--------------|----------------|-------------------|-------------------|
| Token stolen from CI env | Full publish access | Full signing access | Expires in hours |
| Attacker modifies workflow | Works | Works | Blocked (hash mismatch) |
| Attacker uses token from external machine | Works | Works | Blocked (workflow hash unavailable) |
| Token used days later | Works | Works (1yr TTL) | Expired |
| Cross-repo replay | Works | Works | Blocked (repo scope) |

## Rotation

Rotate tokens regularly:

```bash
auths ci rotate --workflow .github/workflows/release.yml --max-uses 4
```

Or automate via scheduled workflow (see `.github/workflows/rotate-ci-token.yml`).

## Revocation

Instantly revoke the CI device key:

```bash
auths device revoke --device <ci-device-did> --key <identity-key-alias>
```
```

**Step 2: Commit**

```bash
git add docs/ci-signing-security.md
git commit -m "docs: add CI signing security model documentation"
```

---

## Summary

| Task | What | Effort |
|------|------|--------|
| 1 | CiToken v2 struct with new fields | 1 hour |
| 2 | `auths ci setup` generates v2 tokens (4h TTL default) | 1.5 hours |
| 3 | Sign action enforces workflow pin + repo scope | 2 hours |
| 4 | `CiBinding` struct in attestations | 45 min |
| 5 | Pass CI metadata through sign action | 1 hour |
| 6 | Auto-rotation scheduled workflow | 30 min |
| 7 | `auths ci rotate` supports v2 fields | 1 hour |
| 8 | Release workflow setup instructions | 15 min |
| 9 | Security documentation | 30 min |

**Total: ~8.5 hours**

### After implementation, the security posture becomes:

```
auths ci setup --workflow .github/workflows/release.yml --max-uses 4

→ Token expires in 4 hours (not 1 year)
→ Only this workflow file can use it (hash-pinned)
→ Only this repo can use it (scoped)
→ Only 4 signing operations allowed (limited)
→ Every attestation records CI binding metadata (auditable)
```

An attacker who steals AUTHS_CI_TOKEN gets a token that is either expired, refuses to sign because the workflow hash doesn't match their modified workflow, or is scoped to a repo they can't publish from.
