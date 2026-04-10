# Tag-Signed Releases: Eliminate AUTHS_CI_TOKEN

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace CI-based artifact signing (AUTHS_CI_TOKEN) with local tag signing, so the signing key never leaves the maintainer's device.

**Architecture:** The maintainer signs a git tag locally using their hardware-keychain-bound device key. CI builds artifacts from the signed tag, generates provenance `.auths.json` files that reference the tag attestation (no key material needed), and publishes everything to GitHub Release. Verification chains: signed tag → artifact hash → trust.

**Tech Stack:** Rust (auths-cli, auths-sdk, auths-verifier), TypeScript (GitHub Actions), Git refs (`refs/auths/tags/`)

---

## Design

### What changes

| Before | After |
|--------|-------|
| Maintainer runs `git tag v0.1.0 && git push origin v0.1.0` | Maintainer runs `auths release v0.1.0` (creates tag + signs + pushes) |
| CI uses `auths-dev/sign@v1` with `AUTHS_CI_TOKEN` secret | CI uses `auths-dev/attest@v1` with zero secrets |
| `.auths.json` is a self-signed attestation (contains Ed25519 signatures) | `.auths.json` is a provenance doc referencing the signed tag |
| Verification checks the artifact signature directly | Verification checks: tag signature → artifact hash match |
| `AUTHS_CI_TOKEN` in GitHub secrets (stealable) | No secrets needed for signing |

### Trust model

```
auths release v0.1.0  (maintainer's machine, hardware keychain)
    ↓
creates git tag v0.1.0 pointing at commit SHA
    ↓
creates attestation at refs/auths/tags/v0.1.0 containing:
  - tag name, commit SHA, maintainer DID
  - Ed25519 signature from device key
  - capabilities: [sign_release]
    ↓
pushes tag + attestation refs to origin
    ↓
CI triggers on v* tag push (same as today)
    ↓
CI builds artifacts, computes SHA256 hashes
    ↓
CI generates .auths.json per artifact (NO key needed):
  {
    "version": 2,
    "type": "release-provenance",
    "tag": "v0.1.0",
    "tag_attestation_ref": "refs/auths/tags/v0.1.0",
    "artifact": { "name": "...", "digest": { "sha256": "..." } },
    "builder": { "platform": "github-actions", "run_id": "..." }
  }
    ↓
Verification: fetch tag attestation → verify signature → check artifact hash
```

### What does NOT change

- The `auths-dev/verify@v1` action (it verifies commits, not artifacts — unaffected)
- The `auths artifact sign` command (still works for local signing)
- The `auths artifact verify` command (gains v2 support, keeps v1 backward compat)
- The existing v1 `.auths.json` format (still valid, still verifiable)
- The Attestation struct in `auths-verifier` (we ADD a new struct, not modify)

---

## Task 1: Add `ReleaseProvenance` type to `auths-verifier`

**Files:**
- Modify: `crates/auths-verifier/src/core.rs`
- Test: `crates/auths-verifier/tests/cases/` (new file: `release_provenance.rs`)
- Modify: `crates/auths-verifier/tests/cases/mod.rs`

**Step 1: Write the failing test**

Create `crates/auths-verifier/tests/cases/release_provenance.rs`:

```rust
use auths_verifier::core::ReleaseProvenance;

#[test]
fn deserialize_release_provenance() {
    let json = r#"{
        "version": 2,
        "type": "release-provenance",
        "tag": "v0.1.0",
        "commit": "abc123def456abc123def456abc123def456abc1",
        "tag_attestation_ref": "refs/auths/tags/v0.1.0",
        "artifact": {
            "name": "auths-linux-x86_64.tar.gz",
            "digest": {
                "algorithm": "sha256",
                "hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "size": 12345678
        },
        "builder": {
            "platform": "github-actions",
            "workflow": ".github/workflows/release.yml",
            "run_id": "12345"
        }
    }"#;

    let prov: ReleaseProvenance = serde_json::from_str(json).unwrap();
    assert_eq!(prov.version, 2);
    assert_eq!(prov.provenance_type, "release-provenance");
    assert_eq!(prov.tag, "v0.1.0");
    assert_eq!(prov.commit, "abc123def456abc123def456abc123def456abc1");
    assert_eq!(prov.tag_attestation_ref, "refs/auths/tags/v0.1.0");
    assert_eq!(prov.artifact.name, "auths-linux-x86_64.tar.gz");
    assert_eq!(prov.artifact.digest.algorithm, "sha256");
    assert_eq!(prov.builder.platform, "github-actions");
}

#[test]
fn serialize_roundtrip() {
    let prov = ReleaseProvenance {
        version: 2,
        provenance_type: "release-provenance".to_string(),
        tag: "v0.1.0".to_string(),
        commit: "abc123def456abc123def456abc123def456abc1".to_string(),
        tag_attestation_ref: "refs/auths/tags/v0.1.0".to_string(),
        artifact: ProvenanceArtifact {
            name: "test.tar.gz".to_string(),
            digest: ProvenanceDigest {
                algorithm: "sha256".to_string(),
                hex: "deadbeef".to_string(),
            },
            size: Some(1024),
        },
        builder: ProvenanceBuilder {
            platform: "github-actions".to_string(),
            workflow: Some(".github/workflows/release.yml".to_string()),
            run_id: Some("99".to_string()),
        },
    };

    let json = serde_json::to_string(&prov).unwrap();
    let deser: ReleaseProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.tag, prov.tag);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p auths_verifier -E 'test(release_provenance)'`
Expected: FAIL — `ReleaseProvenance` not found

**Step 3: Write the implementation**

Add to `crates/auths-verifier/src/core.rs` (after the existing `Attestation` struct):

```rust
/// A release provenance document (version 2 `.auths.json`).
///
/// Unlike v1 attestations which contain their own Ed25519 signatures,
/// provenance documents derive trust from a signed git tag. CI generates
/// these without any key material.
///
/// Args:
/// * `tag` — The git tag name (e.g., "v0.1.0")
/// * `commit` — The commit SHA the tag points to
/// * `tag_attestation_ref` — Git ref containing the signed tag attestation
/// * `artifact` — Artifact name, digest, and size
/// * `builder` — CI platform metadata
///
/// Usage:
/// ```ignore
/// let prov: ReleaseProvenance = serde_json::from_str(&json)?;
/// assert_eq!(prov.tag, "v0.1.0");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseProvenance {
    pub version: u32,
    #[serde(rename = "type")]
    pub provenance_type: String,
    pub tag: String,
    pub commit: String,
    pub tag_attestation_ref: String,
    pub artifact: ProvenanceArtifact,
    pub builder: ProvenanceBuilder,
}

/// Artifact metadata within a release provenance document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceArtifact {
    pub name: String,
    pub digest: ProvenanceDigest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Digest within provenance artifact metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceDigest {
    pub algorithm: String,
    pub hex: String,
}

/// CI builder metadata within a release provenance document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceBuilder {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}
```

Also add the re-export in `crates/auths-verifier/src/lib.rs`:
```rust
pub use core::{ReleaseProvenance, ProvenanceArtifact, ProvenanceDigest, ProvenanceBuilder};
```

Register the test module in `crates/auths-verifier/tests/cases/mod.rs`:
```rust
mod release_provenance;
```

**Step 4: Run test to verify it passes**

Run: `cargo nextest run -p auths_verifier -E 'test(release_provenance)'`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/auths-verifier/src/core.rs crates/auths-verifier/src/lib.rs crates/auths-verifier/tests/cases/release_provenance.rs crates/auths-verifier/tests/cases/mod.rs
git commit -m "feat: add ReleaseProvenance type for v2 .auths.json format"
```

---

## Task 2: Add `auths release` CLI command (tag signing)

**Files:**
- Create: `crates/auths-cli/src/commands/release.rs`
- Modify: `crates/auths-cli/src/commands/mod.rs`
- Modify: `crates/auths-cli/src/cli.rs`
- Modify: `crates/auths-cli/src/main.rs`

This task is the core of the feature. The `auths release <tag>` command:
1. Creates an annotated git tag
2. Signs it with the maintainer's device key (hardware keychain)
3. Stores the attestation at `refs/auths/tags/<tag>`
4. Pushes tag + attestation refs to origin

**Step 1: Write the failing test**

Add `crates/auths-cli/tests/cases/release.rs` (if the test structure allows — otherwise this will be tested via the integration test pattern used by other commands):

```rust
// Integration test: verify the release command creates a tag attestation.
// This test is validated manually / via E2E since it requires git + keychain.
// See Task 6 for E2E test.
```

For now, we validate via the E2E flow in Task 6. The command itself is a thin CLI layer over SDK logic.

**Step 2: Create the command**

Create `crates/auths-cli/src/commands/release.rs`:

```rust
//! `auths release` — sign a release tag with the maintainer's device key.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::path::Path;
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::signing::service::{SigningKeyMaterial, sign_artifact};
use auths_sdk::keychain::KeyAlias;
use auths_sdk::signing::PassphraseProvider;

use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::subprocess::git_stdout;

/// Sign a release tag with your device key and push it.
///
/// Creates an annotated git tag, signs it with an Auths attestation
/// stored at `refs/auths/tags/<tag>`, and pushes both to origin.
/// No secrets are needed in CI — the signing happens here, on your device.
///
/// Usage:
///   auths release v0.1.0
///   auths release v0.1.0 --note "Production release"
///   auths release v0.1.0 --no-push    # sign locally, push later
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Sign a release tag with your device key.",
    after_help = "Examples:\n  auths release v1.0.0\n  auths release v1.0.0 --note 'First stable release'\n  auths release v1.0.0 --no-push"
)]
pub struct ReleaseCommand {
    /// Tag name (e.g., v0.1.0). Will be created if it doesn't exist.
    pub tag: String,

    /// Optional note for the attestation.
    #[arg(long)]
    pub note: Option<String>,

    /// Device key alias to sign with (auto-detected if omitted).
    #[arg(long, default_value = "default")]
    pub device_key: String,

    /// Skip pushing to origin after signing.
    #[arg(long)]
    pub no_push: bool,

    /// Optional message for the annotated tag.
    #[arg(long, short = 'm')]
    pub message: Option<String>,
}

impl crate::commands::executable::ExecutableCommand for ReleaseCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_release(self.clone(), ctx)
    }
}

fn handle_release(cmd: ReleaseCommand, ctx: &CliConfig) -> Result<()> {
    let auths_repo = ctx
        .repo_path
        .clone()
        .unwrap_or_else(|| {
            auths_sdk::paths::auths_home_with_config(&ctx.env_config)
                .unwrap_or_else(|_| std::path::PathBuf::from(".auths"))
        });

    // 1. Resolve HEAD commit
    let commit_sha = git_stdout(&["rev-parse", "HEAD"])
        .context("Failed to resolve HEAD commit")?;

    // 2. Create annotated tag (if it doesn't exist)
    let tag_message = cmd.message.clone().unwrap_or_else(|| format!("Release {}", cmd.tag));
    let tag_exists = git_stdout(&["rev-parse", &format!("refs/tags/{}", cmd.tag)]).is_ok();

    if tag_exists {
        println!("\x1b[2mTag {} already exists — signing existing tag.\x1b[0m", cmd.tag);
    } else {
        let tag_result = std::process::Command::new("git")
            .args(["tag", "-a", &cmd.tag, "-m", &tag_message])
            .status()
            .context("Failed to create git tag")?;

        if !tag_result.success() {
            return Err(anyhow!("Failed to create tag {}", cmd.tag));
        }
        println!("\x1b[0;32m\u{2713}\x1b[0m Created tag {}", cmd.tag);
    }

    // 3. Build auths context and sign
    let auths_ctx = build_auths_context(
        &auths_repo,
        &ctx.env_config,
        Some(ctx.passphrase_provider.clone()),
    )
    .context("Failed to initialize auths context. Run `auths init` first.")?;

    let identity = auths_ctx
        .identity_storage
        .load_identity()
        .map_err(|_| anyhow!("No auths identity found. Run `auths init` first."))?;

    let identity_did = identity.controller_did.to_string();

    // 4. Resolve device key and sign the tag data
    let tag_data = format!("{}:{}:{}", cmd.tag, commit_sha, identity_did);
    let tag_data_bytes = tag_data.as_bytes();

    // Use the existing artifact signing infrastructure to create the attestation.
    // The "artifact" is the tag data string; the attestation proves the maintainer
    // approved this tag.
    let artifact = auths_sdk::ports::artifact::BytesArtifact::new(
        tag_data_bytes.to_vec(),
        format!("tag:{}", cmd.tag),
    );

    let params = auths_sdk::domains::signing::service::ArtifactSigningParams {
        artifact: Arc::new(artifact),
        identity_key: None, // auto-detect
        device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(&cmd.device_key)),
        expires_in: None,
        note: cmd.note.clone().or_else(|| Some(format!("Release tag {}", cmd.tag))),
        commit_sha: Some(commit_sha.clone()),
    };

    let result = sign_artifact(params, &auths_ctx)
        .map_err(|e| anyhow!("Failed to sign tag: {e}"))?;

    println!("\x1b[0;32m\u{2713}\x1b[0m Signed tag {} (issuer: {})", cmd.tag, identity_did);

    // 5. Store attestation at refs/auths/tags/<tag>
    store_tag_attestation(&cmd.tag, &result.attestation_json)
        .context("Failed to store tag attestation in git ref")?;

    println!(
        "\x1b[0;32m\u{2713}\x1b[0m Attestation stored at refs/auths/tags/{}",
        cmd.tag
    );

    // 6. Push (unless --no-push)
    if !cmd.no_push {
        let push_tag = std::process::Command::new("git")
            .args(["push", "origin", &format!("refs/tags/{}", cmd.tag)])
            .status()
            .context("Failed to push tag")?;

        if !push_tag.success() {
            return Err(anyhow!("Failed to push tag {} to origin", cmd.tag));
        }

        let push_ref = std::process::Command::new("git")
            .args([
                "push", "origin",
                &format!("refs/auths/tags/{}:refs/auths/tags/{}", cmd.tag, cmd.tag),
            ])
            .status()
            .context("Failed to push attestation ref")?;

        if !push_ref.success() {
            return Err(anyhow!("Failed to push attestation ref"));
        }

        println!("\x1b[0;32m\u{2713}\x1b[0m Pushed tag + attestation to origin");
    } else {
        println!("\x1b[2mSkipped push (--no-push). Push manually:\x1b[0m");
        println!("  git push origin refs/tags/{}", cmd.tag);
        println!(
            "  git push origin refs/auths/tags/{}:refs/auths/tags/{}",
            cmd.tag, cmd.tag
        );
    }

    println!();
    println!("CI will build artifacts from this signed tag.");
    println!("No AUTHS_CI_TOKEN needed — the signature is in the tag attestation.");

    Ok(())
}

/// Store the tag attestation JSON as a git ref.
///
/// Creates a git blob + tree + commit at `refs/auths/tags/<tag>`.
/// Follows the same pattern as `refs/auths/commits/<sha>`.
fn store_tag_attestation(tag: &str, attestation_json: &str) -> Result<()> {
    // Write attestation to a temp file, then use git hash-object + update-ref
    let tmp = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
    std::fs::write(tmp.path(), attestation_json)?;

    let blob_hash = git_stdout(&[
        "hash-object", "-w", "--stdin",
    ]);

    // Use git plumbing to create the ref
    // 1. Create blob
    let blob = std::process::Command::new("git")
        .args(["hash-object", "-w"])
        .arg(tmp.path())
        .output()
        .context("git hash-object failed")?;
    let blob_sha = String::from_utf8(blob.stdout)?.trim().to_string();

    // 2. Create tree containing the blob as "attestation.json"
    let tree_input = format!("100644 blob {}\tattestation.json\n", blob_sha);
    let tree = std::process::Command::new("git")
        .args(["mktree"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("git mktree failed")?;

    let mut tree_proc = tree;
    {
        use std::io::Write;
        tree_proc
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("Failed to open stdin for mktree"))?
            .write_all(tree_input.as_bytes())?;
    }
    let tree_output = tree_proc.wait_with_output()?;
    let tree_sha = String::from_utf8(tree_output.stdout)?.trim().to_string();

    // 3. Create commit with the tree
    let commit = std::process::Command::new("git")
        .args(["commit-tree", &tree_sha, "-m", &format!("auths: tag attestation for {}", tag)])
        .output()
        .context("git commit-tree failed")?;
    let commit_sha = String::from_utf8(commit.stdout)?.trim().to_string();

    // 4. Update ref
    let ref_name = format!("refs/auths/tags/{}", tag);
    let update = std::process::Command::new("git")
        .args(["update-ref", &ref_name, &commit_sha])
        .status()
        .context("git update-ref failed")?;

    if !update.success() {
        return Err(anyhow!("Failed to update ref {}", ref_name));
    }

    Ok(())
}
```

**Step 3: Register the command**

Add to `crates/auths-cli/src/commands/mod.rs`:
```rust
pub mod release;
```

Add to `crates/auths-cli/src/cli.rs` imports:
```rust
use crate::commands::release::ReleaseCommand;
```

Add to `RootCommand` enum (in the Primary section):
```rust
    Release(ReleaseCommand),
```

Add to `crates/auths-cli/src/main.rs` match arms:
```rust
        RootCommand::Release(cmd) => cmd.execute(&ctx),
```

Add to `audit_action`:
```rust
        RootCommand::Release(_) => Some("release_signed"),
```

**Step 4: Check `BytesArtifact` exists — if not, add it**

Check if `auths_sdk::ports::artifact::BytesArtifact` exists. If not, add to `crates/auths-sdk/src/ports/artifact.rs`:

```rust
/// In-memory artifact for signing arbitrary byte data.
///
/// Args:
/// * `data` — The raw bytes to sign
/// * `name` — A human-readable name for the artifact
///
/// Usage:
/// ```ignore
/// let art = BytesArtifact::new(b"hello".to_vec(), "tag:v0.1.0".into());
/// let meta = art.metadata()?;
/// ```
pub struct BytesArtifact {
    data: Vec<u8>,
    name: String,
}

impl BytesArtifact {
    pub fn new(data: Vec<u8>, name: String) -> Self {
        Self { data, name }
    }
}

impl ArtifactSource for BytesArtifact {
    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> {
        let digest = sha256_hex(&self.data);
        Ok(ArtifactMetadata {
            artifact_type: "tag".to_string(),
            digest: ArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: digest,
            },
            name: self.name.clone(),
            size: Some(self.data.len() as u64),
        })
    }

    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        let hex = sha256_hex(&self.data);
        Ok(ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex,
        })
    }
}
```

**Step 5: Build and verify**

Run: `cargo build --package auths_cli`
Expected: Compiles without errors

**Step 6: Commit**

```bash
git add crates/auths-cli/src/commands/release.rs crates/auths-cli/src/commands/mod.rs crates/auths-cli/src/cli.rs crates/auths-cli/src/main.rs
git commit -m "feat: add auths release command for tag-signed releases"
```

---

## Task 3: Add v2 provenance verification to `auths artifact verify`

**Files:**
- Modify: `crates/auths-cli/src/commands/artifact/verify.rs`

The artifact verify command already checks for `offline_bundle` in the JSON (line 90). We add a similar check for `"type": "release-provenance"` to handle v2 `.auths.json` files.

**Step 1: Write the failing test**

The test will be in the verifier crate integration tests. Add to `crates/auths-verifier/tests/cases/release_provenance.rs`:

```rust
#[test]
fn detect_v2_provenance_type() {
    let json = r#"{"version": 2, "type": "release-provenance", "tag": "v1.0"}"#;
    let val: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(val.get("type").and_then(|t| t.as_str()), Some("release-provenance"));
    assert_eq!(val.get("version").and_then(|v| v.as_u64()), Some(2));
}
```

**Step 2: Add v2 handling to artifact verify**

In `crates/auths-cli/src/commands/artifact/verify.rs`, after the `offline_bundle` check (line 90-92), add:

```rust
    // Check for v2 release provenance format
    if sig_value.get("type").and_then(|t| t.as_str()) == Some("release-provenance") {
        return handle_provenance_verify(file, &sig_content).await;
    }
```

Then add the handler function:

```rust
/// Verify a v2 release provenance `.auths.json`.
///
/// Trust chain: fetch tag attestation from git ref → verify signature
/// → check artifact hash matches.
async fn handle_provenance_verify(file: &Path, sig_content: &str) -> Result<()> {
    let file_str = file.to_string_lossy().to_string();

    let prov: auths_verifier::ReleaseProvenance = match serde_json::from_str(sig_content) {
        Ok(p) => p,
        Err(e) => {
            return output_error(&file_str, 2, &format!("Failed to parse provenance: {}", e));
        }
    };

    // 1. Compute file digest and compare with provenance
    let file_artifact = FileArtifact::new(file);
    let file_digest = match file_artifact.digest() {
        Ok(d) => d,
        Err(e) => {
            return output_error(&file_str, 2, &format!("Failed to compute file digest: {}", e));
        }
    };

    if file_digest.hex != prov.artifact.digest.hex {
        return output_result(
            1,
            VerifyArtifactResult {
                file: file_str,
                valid: false,
                digest_match: Some(false),
                chain_valid: None,
                chain_report: None,
                capability_valid: None,
                witness_quorum: None,
                issuer: None,
                commit_sha: Some(prov.commit.clone()),
                commit_verified: None,
                error: Some(format!(
                    "Digest mismatch: file={}, provenance={}",
                    file_digest.hex, prov.artifact.digest.hex
                )),
            },
        );
    }

    // 2. Fetch tag attestation from git ref
    let ref_name = &prov.tag_attestation_ref;
    let attestation_json = match crate::subprocess::git_stdout(&[
        "show", &format!("{}:attestation.json", ref_name),
    ]) {
        Ok(json) => json,
        Err(_) => {
            // Try fetching from remote first
            let _ = std::process::Command::new("git")
                .args(["fetch", "origin", &format!("{}:{}", ref_name, ref_name)])
                .status();

            match crate::subprocess::git_stdout(&[
                "show", &format!("{}:attestation.json", ref_name),
            ]) {
                Ok(json) => json,
                Err(_) => {
                    return output_error(
                        &file_str,
                        2,
                        &format!(
                            "Tag attestation not found at {}. \
                             Fetch with: git fetch origin {}:{}",
                            ref_name, ref_name, ref_name
                        ),
                    );
                }
            }
        }
    };

    // 3. Parse the tag attestation (this is a v1 Attestation — the signed one)
    let tag_attestation: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(a) => a,
        Err(e) => {
            return output_error(
                &file_str,
                2,
                &format!("Failed to parse tag attestation: {}", e),
            );
        }
    };

    // 4. Resolve identity key and verify the tag attestation signature
    let (root_pk, _identity_did) = match resolve_identity_key(&None, &tag_attestation) {
        Ok(v) => v,
        Err(e) => {
            return output_error(&file_str, 2, &e.to_string());
        }
    };

    let chain = vec![tag_attestation.clone()];
    let chain_result =
        verify_chain_with_capability(&chain, &Capability::sign_release(), &root_pk).await;

    let (chain_valid, chain_report, capability_valid) = match chain_result {
        Ok(report) => {
            let is_valid = report.is_valid();
            (Some(is_valid), Some(report), Some(true))
        }
        Err(auths_verifier::error::AttestationError::MissingCapability { .. }) => {
            let report = verify_chain(&chain, &root_pk).await.ok();
            let chain_ok = report.as_ref().map(|r| r.is_valid());
            (chain_ok, report, Some(false))
        }
        Err(e) => {
            return output_error(&file_str, 1, &format!("Tag attestation verification failed: {}", e));
        }
    };

    let valid = chain_valid.unwrap_or(false) && capability_valid.unwrap_or(true);

    output_result(
        if valid { 0 } else { 1 },
        VerifyArtifactResult {
            file: file_str,
            valid,
            digest_match: Some(true),
            chain_valid,
            chain_report,
            capability_valid,
            witness_quorum: None,
            issuer: Some(tag_attestation.issuer.to_string()),
            commit_sha: Some(prov.commit),
            commit_verified: None,
            error: if valid { None } else { Some("Tag attestation signature invalid".to_string()) },
        },
    )
}
```

**Step 3: Build and verify**

Run: `cargo build --package auths_cli`
Expected: Compiles

**Step 4: Commit**

```bash
git add crates/auths-cli/src/commands/artifact/verify.rs
git commit -m "feat: add v2 release provenance verification to artifact verify"
```

---

## Task 4: Create `auths-dev/attest@v1` GitHub Action (replaces sign for CI)

**Files:**
- Create: `/Users/bordumb/workspace/repositories/auths-base/sign/src/attest.ts` (new)
- Modify: `/Users/bordumb/workspace/repositories/auths-base/sign/action.yml` (add attest mode)

This is the CI-side action. It needs ZERO secrets. It:
1. Computes SHA256 of each artifact
2. Reads the tag name from `GITHUB_REF`
3. Generates a v2 `.auths.json` provenance file per artifact

**Step 1: Create the attest module**

Create `/Users/bordumb/workspace/repositories/auths-base/sign/src/attest.ts`:

```typescript
import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as glob from '@actions/glob';

export interface AttestOptions {
  files: string[];
  tag: string;
  commit: string;
  runId: string;
  workflow: string;
}

export interface AttestResult {
  attestedFiles: string[];
  provenanceFiles: string[];
}

/**
 * Generate v2 release provenance .auths.json files for artifacts.
 * No signing key needed — trust derives from the signed git tag.
 */
export async function attestArtifacts(options: AttestOptions): Promise<AttestResult> {
  const attestedFiles: string[] = [];
  const provenanceFiles: string[] = [];

  for (const file of options.files) {
    const digest = computeSha256(file);
    const stat = fs.statSync(file);
    const basename = path.basename(file);

    const provenance = {
      version: 2,
      type: 'release-provenance',
      tag: options.tag,
      commit: options.commit,
      tag_attestation_ref: `refs/auths/tags/${options.tag}`,
      artifact: {
        name: basename,
        digest: {
          algorithm: 'sha256',
          hex: digest,
        },
        size: stat.size,
      },
      builder: {
        platform: 'github-actions',
        workflow: options.workflow,
        run_id: options.runId,
      },
    };

    const provenancePath = `${file}.auths.json`;
    fs.writeFileSync(provenancePath, JSON.stringify(provenance, null, 2));

    attestedFiles.push(file);
    provenanceFiles.push(provenancePath);

    core.info(`✓ ${basename} → ${path.basename(provenancePath)}`);
    core.info(`  SHA256: ${digest}`);
  }

  return { attestedFiles, provenanceFiles };
}

function computeSha256(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}
```

**Step 2: Create a standalone attest action entry point**

Create `/Users/bordumb/workspace/repositories/auths-base/sign/src/attest-main.ts`:

```typescript
import * as core from '@actions/core';
import * as github from '@actions/github';
import * as glob from '@actions/glob';
import * as path from 'path';
import { attestArtifacts } from './attest';

async function run(): Promise<void> {
  try {
    const filePatterns = core.getMultilineInput('files').filter(p => p.trim());
    if (filePatterns.length === 0) {
      throw new Error('`files` input is required');
    }

    // Resolve tag from GITHUB_REF (e.g., refs/tags/v0.1.0 → v0.1.0)
    const ref = process.env.GITHUB_REF || '';
    const tagMatch = ref.match(/^refs\/tags\/(.+)$/);
    const tag = core.getInput('tag') || (tagMatch ? tagMatch[1] : '');
    if (!tag) {
      throw new Error('Could not determine tag. Set the `tag` input or run on a tag push event.');
    }

    const commit = process.env.GITHUB_SHA || '';
    const runId = process.env.GITHUB_RUN_ID || '';
    const workflow = process.env.GITHUB_WORKFLOW || '';

    // Glob files
    const patterns = filePatterns.join('\n');
    const globber = await glob.create(patterns, { followSymbolicLinks: false });
    let files = await globber.glob();

    // Workspace containment
    const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
    files = files.filter(f => {
      const resolved = path.resolve(f);
      if (!resolved.startsWith(workspace + path.sep) && resolved !== workspace) {
        core.warning(`Skipping path outside workspace: ${f}`);
        return false;
      }
      return true;
    });

    files = [...new Set(files)];

    if (files.length === 0) {
      core.warning('No files matched the provided glob patterns');
      return;
    }

    core.info(`Found ${files.length} file(s) to attest`);

    const result = await attestArtifacts({
      files,
      tag,
      commit,
      runId,
      workflow,
    });

    // Set outputs
    core.setOutput('attested-files', JSON.stringify(result.attestedFiles));
    core.setOutput('provenance-files', JSON.stringify(result.provenanceFiles));

    // Step summary
    const lines = [
      '## Auths Release Provenance',
      '',
      `**Tag:** \`${tag}\` | **Commit:** \`${commit.substring(0, 8)}\``,
      '',
      '| Artifact | SHA256 | Provenance |',
      '|----------|--------|------------|',
    ];

    for (let i = 0; i < result.attestedFiles.length; i++) {
      const file = path.basename(result.attestedFiles[i]);
      const prov = path.basename(result.provenanceFiles[i]);
      lines.push(`| \`${file}\` | ✅ | \`${prov}\` |`);
    }

    lines.push('');
    lines.push(`**${result.attestedFiles.length}** artifact(s) attested. No signing secrets used.`);
    lines.push('');
    lines.push(`Trust chain: \`refs/auths/tags/${tag}\` (signed by maintainer) → artifact hash`);

    await core.summary.addRaw(lines.join('\n')).write();

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred');
    }
  }
}

run();
```

**Step 3: Create `attest/action.yml`**

Create `/Users/bordumb/workspace/repositories/auths-base/sign/attest/action.yml`:

```yaml
name: 'Attest with Auths'
description: 'Generate release provenance .auths.json files — no secrets needed'
author: 'auths'

inputs:
  files:
    description: 'Glob patterns for files to attest, one per line'
    required: true
  tag:
    description: 'Tag name (auto-detected from GITHUB_REF if on a tag push)'
    required: false
    default: ''

outputs:
  attested-files:
    description: 'JSON array of attested file paths'
  provenance-files:
    description: 'JSON array of provenance file paths (.auths.json)'

runs:
  using: 'node20'
  main: '../dist/attest-index.js'

branding:
  icon: 'shield'
  color: 'green'
```

**Step 4: Commit**

```bash
git add sign/src/attest.ts sign/src/attest-main.ts sign/attest/action.yml
git commit -m "feat: add auths-dev/attest action for zero-secret release provenance"
```

---

## Task 5: Update release workflow to use tag signing

**Files:**
- Modify: `/Users/bordumb/workspace/repositories/auths-base/auths/.github/workflows/release.yml`

Replace the `auths-dev/sign@v1` step with `auths-dev/sign/attest@v1` (or inline SHA256 generation + provenance JSON).

**Step 1: Update the workflow**

Replace the "Sign artifact" step (lines 100-107) with:

```yaml
      - name: Generate release provenance (Unix)
        if: matrix.ext == '.tar.gz'
        uses: auths-dev/sign/attest@v1
        with:
          files: ${{ matrix.asset_name }}${{ matrix.ext }}
```

And for Windows (add after the Windows checksum step):

```yaml
      - name: Generate release provenance (Windows)
        if: matrix.ext == '.zip'
        uses: auths-dev/sign/attest@v1
        with:
          files: ${{ matrix.asset_name }}${{ matrix.ext }}
```

Remove `AUTHS_CI_TOKEN` from all references.

The `update-homebrew` job at line 137 currently extracts hashes from `.auths.json` attestation files. Update the hash extraction to use the v2 format:

```yaml
          extract_hash() { python3 -c "import json; d=json.load(open('$1')); print(d['artifact']['digest']['hex'])"; }
```

(Changed from `d['payload']['digest']['hex']` to `d['artifact']['digest']['hex']`)

**Step 2: Verify the workflow is syntactically correct**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: No errors

**Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: replace AUTHS_CI_TOKEN signing with tag-based provenance in release workflow"
```

---

## Task 6: E2E test — full release flow

**Files:**
- Create: `tests/e2e/test_release_flow.py` (or add to existing E2E suite)

This validates the complete flow: `auths release v0.0.1-test` → verify the tag attestation exists → generate provenance → verify provenance.

**Step 1: Write the E2E test script**

```python
"""E2E test: tag-signed release flow."""
import json
import os
import subprocess
import tempfile

def test_release_tag_signing():
    """Test that auths release creates a signed tag with attestation ref."""
    # This test runs in a git repo with auths identity initialized.

    # 1. Create a release tag
    result = subprocess.run(
        ["auths", "release", "v0.0.1-e2e-test", "--no-push", "-m", "E2E test release"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"auths release failed: {result.stderr}"
    assert "Signed tag" in result.stdout
    assert "refs/auths/tags/v0.0.1-e2e-test" in result.stdout

    # 2. Verify the tag exists
    tag_check = subprocess.run(
        ["git", "rev-parse", "refs/tags/v0.0.1-e2e-test"],
        capture_output=True, text=True
    )
    assert tag_check.returncode == 0, "Tag was not created"

    # 3. Verify the attestation ref exists
    ref_check = subprocess.run(
        ["git", "show", "refs/auths/tags/v0.0.1-e2e-test:attestation.json"],
        capture_output=True, text=True
    )
    assert ref_check.returncode == 0, "Attestation ref not found"

    attestation = json.loads(ref_check.stdout)
    assert "issuer" in attestation
    assert "device_signature" in attestation
    assert attestation.get("capabilities") == ["sign_release"]

    # 4. Create a fake artifact and generate provenance
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        f.write(b"fake artifact content for testing")
        artifact_path = f.name

    # The provenance would normally be generated by CI action.
    # For this test, verify the artifact verify command can handle v2 format.
    import hashlib
    digest = hashlib.sha256(b"fake artifact content for testing").hexdigest()

    provenance = {
        "version": 2,
        "type": "release-provenance",
        "tag": "v0.0.1-e2e-test",
        "commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "tag_attestation_ref": "refs/auths/tags/v0.0.1-e2e-test",
        "artifact": {
            "name": os.path.basename(artifact_path),
            "digest": {"algorithm": "sha256", "hex": digest},
            "size": 32,
        },
        "builder": {
            "platform": "test",
            "workflow": "e2e",
            "run_id": "1",
        },
    }

    provenance_path = f"{artifact_path}.auths.json"
    with open(provenance_path, "w") as pf:
        json.dump(provenance, pf)

    # 5. Verify the artifact using the provenance
    verify_result = subprocess.run(
        ["auths", "artifact", "verify", artifact_path, "--json"],
        capture_output=True, text=True
    )

    verify_json = json.loads(verify_result.stdout)
    assert verify_json["valid"] is True, f"Verification failed: {verify_json}"
    assert verify_json["digest_match"] is True

    # Cleanup
    os.unlink(artifact_path)
    os.unlink(provenance_path)
    subprocess.run(["git", "tag", "-d", "v0.0.1-e2e-test"], capture_output=True)
    subprocess.run(["git", "update-ref", "-d", "refs/auths/tags/v0.0.1-e2e-test"], capture_output=True)
```

**Step 2: Run the E2E test**

Run: `cd tests/e2e && python3 -m pytest test_release_flow.py -v`
Expected: PASS (requires auths identity to be initialized in test environment)

**Step 3: Commit**

```bash
git add tests/e2e/test_release_flow.py
git commit -m "test: add E2E test for tag-signed release flow"
```

---

## Task 7: Documentation update

**Files:**
- Modify: `README.md` (add release signing section)
- Modify: `docs/E2E_TEST_CHECKLIST.md` (add release flow checklist)

**Step 1: Add release section to README**

Add after the existing signing documentation:

```markdown
## Release Signing

Sign releases with your device key — no CI secrets needed:

```bash
auths release v1.0.0
```

This creates a signed git tag, stores the attestation at `refs/auths/tags/v1.0.0`,
and pushes both to origin. CI builds artifacts and generates provenance files
that chain back to your signed tag. No `AUTHS_CI_TOKEN` required.

Verify a release artifact:

```bash
auths artifact verify ./auths-linux-x86_64.tar.gz
# ✅ Valid — signed by did:keri:... via tag v1.0.0
```
```

**Step 2: Commit**

```bash
git add README.md docs/E2E_TEST_CHECKLIST.md
git commit -m "docs: add release signing documentation"
```

---

## Task 8: Deprecate `auths ci setup` for signing (keep for verify-only tokens)

**Files:**
- Modify: `crates/auths-cli/src/commands/ci/setup.rs`

**Step 1: Add deprecation warning**

At the top of `run_setup()`, add:

```rust
    eprintln!("\x1b[1;33mNote:\x1b[0m For release artifact signing, consider using `auths release` instead.");
    eprintln!("  `auths release` signs tags with your device key — no CI secrets needed.");
    eprintln!("  `auths ci setup` is still useful for commit signing in CI.");
    eprintln!();
```

**Step 2: Commit**

```bash
git add crates/auths-cli/src/commands/ci/setup.rs
git commit -m "chore: add deprecation note to auths ci setup for artifact signing"
```

---

## Summary

| Task | What | Effort |
|------|------|--------|
| 1 | `ReleaseProvenance` type in auths-verifier | 1 hour |
| 2 | `auths release` CLI command | 3 hours |
| 3 | v2 provenance verification in artifact verify | 2 hours |
| 4 | `auths-dev/attest@v1` GitHub Action | 2 hours |
| 5 | Update release workflow | 30 min |
| 6 | E2E test | 1 hour |
| 7 | Documentation | 30 min |
| 8 | Deprecation note on ci setup | 15 min |

**Total: ~10 hours**

### After implementation, the release flow becomes:

```
Maintainer:  auths release v1.0.0        # one command, device key, hardware keychain
CI:          builds + attests artifacts   # zero secrets
Consumer:    auths artifact verify ...    # checks tag signature → artifact hash
```

No `AUTHS_CI_TOKEN`. No secrets in CI. No key material to steal. The signing key never leaves the maintainer's device.
