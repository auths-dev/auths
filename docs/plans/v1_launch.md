# Auths v1.0 Launch Plan: Competitive Moat & Valuation Roadmap

## Part 1: Competitive Landscape & Moat Analysis

### 1.1 The Competitors

| Competitor | Model | Weakness `auths` Exploits |
|---|---|---|
| **Legacy GPG** | Manual key management, WoT, `gpg --gen-key` ceremony | Unusable DX. <5% of GitHub commits are signed. No delegation, no rotation, no revocation without manual coordination. |
| **SSH Signing (GitHub native)** | `git config gpg.format ssh` + `allowed_signers` file | No identity lifecycle. Keys are opaque strings. No attestation chain, no capability scoping, no KERI rotation. Signing key = authentication key (no separation of concerns). |
| **Sigstore / Gitsign** | Keyless OIDC-based signing via Fulcio CA + Rekor transparency log. Ephemeral certs tied to OIDC identity. | **Requires network for every sign and verify.** Fulcio is a central CA. Rekor is a central log. If Google's infrastructure goes down, your pipeline stops. Cannot work offline, air-gapped, or in sovereign environments. Identity is borrowed from Google/GitHub/Microsoft OIDC -- not self-sovereign. No delegation chain. |
| **Centralized IAM** (Okta, Azure AD, AWS IAM) | Federated identity with SAML/OIDC tokens. | Not developer-native. Cannot sign Git commits. No cryptographic proof of authorship. Identity lives in a vendor silo. Switching costs are the moat, not technical merit. |
| **OriginVault DID SDK** | TypeScript SDK for DID management and VC signing. | JavaScript-only. No Git integration. No CLI. No CI/CD story. Academic DID implementation without a developer workflow. |
| **Chainguard** | $3.5B valuation -- hardened container images + Sigstore-based signing for supply chain. | Focuses on container/artifact signing, not developer identity. Doesn't solve commit signing, key lifecycle, or decentralized trust. Complementary, not competitive. |

### 1.2 The Differentiator: Why `auths` Wins

The `auths` architecture has five structural advantages that no competitor replicates:

**1. Zero-Network Stateless Verification**

The `auths-verifier` crate (`crates/auths-verifier/`) is a 11-dep, 8,657-line verification engine that compiles to native, FFI, and WASM targets. The `--identity-bundle` flag (implemented in `auths-cli/src/commands/verify.rs` and consumed by `auths-verify-github-action/src/verifier.ts`) enables completely offline verification. No Fulcio. No Rekor. No network calls. The bundle contains the full attestation chain + root public key -- everything a verifier needs is in the bundle itself.

This is structurally impossible with Sigstore, where verification requires querying Rekor's transparency log and validating Fulcio certificate chains online.

**2. Git-Native Storage (No External Infrastructure)**

All identity state lives in Git refs (`refs/auths/`, `refs/keri/`) as implemented in `crates/auths-storage/src/git/paths.rs`. The `~/.auths` directory is itself a Git repository. This means:
- Full audit trail via `git log`
- Distributed replication via `git push`/`git pull`
- No database, no server, no SaaS dependency
- Works with any Git forge (GitHub, GitLab, Gitea, Radicle)

The ref layout from `crates/auths-storage/src/git/adapter.rs` uses 2-character DID sharding to avoid pathspec performance cliffs at scale:
```
refs/auths/registry/v1/identities/{2-char-shard}/{sanitized-did}/events/
refs/auths/registry/v1/devices/{2-char-shard}/{sanitized-did}/attestation.json
```

**3. KERI-Inspired Cryptographic Identity Lifecycle**

Unlike GPG/SSH (where key compromise = identity compromise), `auths` implements pre-rotation via KERI Key Event Logs in `crates/auths-keri/`. The `KeriEvent` enum supports `Inception`, `Rotation`, and `Interaction` events. Key rotation doesn't break the identity -- old signatures remain verifiable because the KEL establishes the key authority at the time of signing.

The E2E test `tests/e2e/test_key_rotation.py::TestKeyRotation::test_verify_old_commit_after_rotation` explicitly validates this: sign a commit, rotate keys, verify the old commit still passes.

**4. Delegation Chains with Capability Scoping**

`auths-verifier` implements `verify_chain()` and `verify_chain_with_capability()` to walk attestation chains from root identity to leaf device. Each attestation in the chain carries scoped `Capability` enums (`SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys`). This enables:
- A CI bot can sign commits but not rotate keys
- A junior dev can sign releases for staging but not production
- An MCP agent gets exactly the capabilities its attestation grants (enforced in `crates/auths-mcp-server/src/auth.rs`)

No competitor offers cryptographically-enforced capability delegation.

**5. Polyglot Verification Surface**

From a single Rust crate (`auths-verifier`), verification ships as:
- **Native binary**: `auths verify-commit` (CLI, via `ring` Ed25519)
- **C FFI**: `crates/auths-verifier/src/ffi.rs` (546 lines, integer error codes, panic-catching)
- **WASM**: `crates/auths-verifier/src/wasm.rs` (417 lines, `wasm-bindgen` exports)
- **npm widget**: `@auths-dev/verify` web component with WASM inlined as base64 (`auths-verify-widget/`)
- **GitHub Action**: `auths-verify-github-action/` downloads the CLI binary, verifies checksums, runs `auths verify-commit --json`
- **Mobile (UniFFI)**: `crates/auths-mobile-ffi/` generates Swift/Kotlin bindings

This means verification can happen in the browser, in CI, on mobile, in embedded systems -- anywhere, without network.

### 1.3 The Winning Strategy

**Phase 1: Own the Developer Signing Primitive**
- Make `auths init && auths sign` as easy as `ssh-keygen`. The CLI already has 23 root commands, a `tutorial`/`learn` command, and a `doctor` diagnostic.
- Ship the GitHub Action as the default CI gate. It already supports PR comments, step summaries, and fix instructions (copy-pasteable `git commit --amend -S` commands).
- Embed the verify widget (`<auths-verify>`) in READMEs, docs sites, and dashboards.

**Phase 2: Become the CI/CD Identity Layer**
- The `auths-mcp-server` already validates JWTs with capability-scoped claims (`OidcClaims` from `auths-jwt`). Extend this to become the identity provider for GitHub Actions, GitLab CI, and Buildkite.
- The policy engine (`auths-policy`) already supports `compile()`, `evaluate_strict()`, and `enforce()` with shadow policies. This is a full policy-as-code engine ready for enterprise CI gates.

**Phase 3: Replace IAM for Developer-Facing Workloads**
- SCIM 2.0 provisioning (`crates/auths-scim/`) bridges to enterprise IdPs (Okta, Azure AD).
- OIDC bridge (`auths-cloud/crates/auths-oidc-bridge/`) exchanges attestation chains for cloud-provider JWTs (AWS STS, GCP Workload Identity, Azure AD).
- Human-in-the-loop approval gates (`crates/auths-policy/src/approval.rs`) satisfy SOC 2 and SOX requirements.

---

## Part 2: Valuation Milestone Roadmap

### Market Context

- **Software Supply Chain Security TAM**: $2.16B in 2025, growing to $3.27B by 2034 (10.9% CAGR).
- **Comparable**: Chainguard at $3.5B valuation on $37M ARR (95x revenue multiple, supply chain security premium).
- **Comparable**: Snyk at $407.8M revenue in developer security tooling.
- **By 2028**: 85% of large enterprise software teams will deploy software supply chain security tools (up from 60% in 2025).

---

### Current Valuation Estimate: $2-4M (Pre-Seed / Technical Asset)

**Rationale**: Functional but pre-revenue. The codebase is the asset.

**What Exists Today** (grounded in code):

| Asset | Evidence |
|---|---|
| 22-crate Rust workspace | `Cargo.toml` workspace members, 512 Rust files |
| 1,218 passing tests | `cargo nextest run --workspace` output, 14 crates with integration test suites |
| 6-layer architecture | CLAUDE.md Layer 0-6 documentation, enforced by `deny.toml` dependency bans |
| 3 platform keychains | macOS Security Framework, Linux Secret Service, Windows Credential Manager (conditional compilation in `auths-core`) |
| FFI + WASM + UniFFI | `auths-verifier` features: `ffi`, `wasm`; `auths-mobile-ffi` with `uniffi` |
| Published npm widget | `@auths-dev/verify` v0.2.0 with 3 forge adapters (GitHub, Gitea, GitLab) |
| GitHub Action v1.0 | `auths-verify-github-action` on GitHub Marketplace, multi-platform binary caching |
| KERI CESR codec | `auths-keri` implementing Trust over IP KERI v0.9 spec with Blake3 SAID computation |
| Policy-as-code engine | `auths-policy` with `compile()`, `evaluate_strict()`, `enforce()`, approval gates |
| SCIM 2.0 provisioning | `auths-scim` crate with filter parser, patch operations, RFC 7643/7644 compliance |
| OIDC bridge | `auths-cloud/crates/auths-oidc-bridge/` with AWS/GCP/Azure token exchange |
| MCP authorization server | `auths-mcp-server` with JWT validation, capability-scoped tool authorization |
| CI-enforced quality | Pre-push hooks run clippy, deny, tests, WASM check, cross-compilation (aarch64-linux, windows, wasm32) |
| 7 E2E test suites | Python pytest: git signing, identity lifecycle, device attestation, approval gates, key rotation, policy engine, MCP server (42 test methods) |

**Gaps at Current State**:
- No published binary releases (users must `cargo install --path`)
- `auths-sdk` error types still wrap `anyhow::Error` in `StorageError`/`NetworkError` variants (noted as transitional in CLAUDE.md)
- No formal security audit
- No production deployments
- Version is `0.0.1-rc.7` -- not yet v0.1.0

---

### $10M Valuation: The Usable Developer Primitive

**Rationale**: v0.1.0 shipped. Developers can `brew install auths` and sign their first commit in under 60 seconds. The GitHub Action is battle-tested. First 50 OSS projects adopt.

#### Epic 1: Stabilize Core Architecture & Error Boundaries

**Task 1.1: Migrate SDK error types from `anyhow` to domain-specific `thiserror`**
- **Cite**: `crates/auths-sdk/src/error.rs` currently has `StorageError(#[source] anyhow::Error)` and `NetworkError(#[source] anyhow::Error)`. CLAUDE.md explicitly flags this: "These must be migrated to domain-specific thiserror variants during Epic 1/2 execution."
- **Action**: Replace `anyhow::Error` in `SdkStorageError`, `map_storage_err()`, and `map_device_storage_err()` with typed `From` impls on domain storage errors. This enables safe FFI error mapping where C callers need integer error codes (see `auths-verifier/src/ffi.rs` pattern: `ERR_VERIFY_ISSUER_SIG_FAIL = -4`).

**Task 1.2: Audit and eliminate `unwrap()` outside test boundaries**
- **Cite**: Workspace lint `unwrap_used = "warn"` in root `Cargo.toml`. CLI boundary (`auths-cli/src/main.rs`) explicitly allows it with `#![allow(clippy::unwrap_used)]`. Core crates should have zero `unwrap()` in non-test code.
- **Action**: Run `cargo clippy --all-targets -- -W clippy::unwrap_used` and convert all core/SDK `unwrap()` to `?` or explicit error handling. The `AuthsErrorInfo` trait (in `auths-core/src/error.rs`) provides `error_code()` and `suggestion()` for every variant -- use it.

**Task 1.3: Freeze public API surface for `auths-verifier` v1.0**
- **Cite**: `auths-verifier` exports 12 public modules with functions like `verify_chain()`, `verify_with_keys()`, `did_to_ed25519()`. These are consumed by `auths-verify-widget` (via WASM: `verifyAttestationWithResult()`, `verifyChainJson()`) and `auths-verify-github-action` (via CLI binary).
- **Action**: Add `#[non_exhaustive]` to `VerificationStatus` and `AttestationError` enums. Publish `auths-verifier` 0.1.0 to crates.io with semver guarantees. The release script (`scripts/releases/2_crates.py`) already handles batch publishing in dependency order.

**Task 1.4: Implement `--json` output for all CLI commands**
- **Cite**: `auths-verify-github-action/src/verifier.ts` already consumes `auths verify-commit --json` output and parses it into typed `VerifyResult[]` objects. But not all CLI commands have `--json` flags.
- **Action**: Add `--json` to `auths status`, `auths id show`, `auths device list`, `auths policy explain`. Use the existing `serde_json` serialization on domain types. CI pipelines depend on machine-parseable output.

#### Epic 2: Distribution & Installation

**Task 2.1: Ship cross-platform binary releases**
- **Cite**: `auths-verify-github-action/src/main.ts` already downloads from `auths-dev/auths-releases` with SHA256 checksum verification. The download function supports Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64).
- **Action**: Set up GitHub Actions release workflow. The existing `scripts/releases/2_crates.py` handles crates.io publishing. Add a parallel workflow for binary tarballs + Homebrew formula.

**Task 2.2: Publish `auths-verifier` to crates.io, npm, and PyPI**
- **Cite**: `packages/auths-verifier-ts/` is the TypeScript bridge consumed by `@auths-dev/verify` widget. `packages/auths-python/` exists as a PyO3 binding (detected in pre-push hooks: `cargo check (python bindings)`).
- **Action**: Publish `@auths/verifier` to npm (WASM bundle). Publish `auths-python` to PyPI (native extension). This gives every ecosystem a verification primitive.

#### Epic 3: Developer Experience

**Task 3.1: One-command onboarding**
- **Cite**: CLI has `InitCommand` in `auths-cli/src/commands/init.rs` and `LearnCommand`/`DoctorCommand` for diagnostics. The setup flow in `auths-sdk/src/setup.rs` handles developer, CI, and agent environments.
- **Action**: `auths init` should detect environment (developer laptop vs CI vs container), provision identity, configure `~/.gitconfig` for signing, and run `auths doctor` automatically. Target: sign first commit within 60 seconds of install.

**Task 3.2: VS Code extension for verification badges**
- **Cite**: The `<auths-verify>` web component (`auths-verify-widget/src/auths-verify.ts`) already renders badge/detail/tooltip modes with a shadow DOM state machine (`idle` -> `loading` -> `verified`/`invalid`/`error`). It resolves identity from Git refs via forge adapters.
- **Action**: Wrap the web component in a VS Code webview extension. Show verification badges inline in the Git log panel.

---

### $20M Valuation: Ecosystem Integration & Tooling

**Rationale**: Mobile authenticator app ships. `auths` becomes the identity primitive for 3+ external tools (GitHub Action, npm widget, mobile app). First enterprise pilot.

#### Epic 4: Mobile Authenticator via FFI

**Task 4.1: Complete `auths-mobile-ffi` UniFFI bindings**
- **Cite**: `crates/auths-mobile-ffi/` exists with `uniffi` proc-macro bindings, `IdentityResult` record type, `MobileError` thiserror enum. It generates Swift and Kotlin code automatically.
- **Action**: Expose the full pairing flow through UniFFI. The `auths-pairing-protocol` crate (`crates/auths-pairing-protocol/src/protocol.rs`) is already transport-agnostic -- it uses `PairingProtocol::initiate()` / `respond_to_pairing()` / `complete()` with serializable token/response types. No dynamic Rust traits cross the FFI boundary. The `EphemeralSecret` is non-Clone/non-Serialize by design, enforcing in-memory-only sessions.

**Task 4.2: QR code pairing between mobile and desktop**
- **Cite**: `auths-core` already depends on `qrcode` crate. The `PairingToken` from `auths-pairing-protocol/src/token.rs` has a `to_uri()` method for URL encoding and a 6-character short code for manual entry.
- **Action**: Mobile app scans QR code containing the pairing token URI. Desktop CLI displays QR via terminal (already has `qrcode` dep). X25519 ECDH key exchange completes over any transport (BLE, LAN, or relay server). Shared secret never leaves memory (`zeroize` on drop).

**Task 4.3: Abstract LAN discovery out of CLI**
- **Cite**: `auths-cli/src/commands/device/pair/` contains LAN pairing logic using `mdns-sd` and `axum`. These are CLI-specific I/O concerns that should not exist in the protocol layer.
- **Action**: The transport layer is already separated -- `auths-pairing-protocol` has zero network dependencies (only `auths-crypto`, `ring`, `x25519-dalek`, `serde_json`, `zeroize`, `chrono`, `thiserror`). Create a thin `auths-transport-lan` crate for mDNS discovery, keeping the protocol crate pure.

#### Epic 5: Forge Integrations

**Task 5.1: GitLab CI integration**
- **Cite**: `auths-verify-widget/src/resolvers/gitlab.ts` currently has limited support (GitLab API doesn't expose custom refs). Widget falls back to manual mode.
- **Action**: Build a GitLab CI template (`.gitlab-ci.yml`) that uses the `auths` binary directly (same pattern as the GitHub Action's `verifier.ts`). For the widget, implement a GitLab-specific resolver that uses the repository files API to read attestation data.

**Task 5.2: Radicle sovereign forge integration**
- **Cite**: `crates/auths-radicle/` exists but is excluded from the workspace (`Cargo.toml` exclude list). It contains `src/verify.rs` for Radicle-specific verification.
- **Action**: Bring `auths-radicle` into the workspace. Radicle's peer-to-peer Git model is the ideal environment for `auths` -- fully decentralized identity on a fully decentralized forge.

---

### $60M Valuation: Enterprise CI/CD Dominance

**Rationale**: Zero-network verification becomes the standard for air-gapped and regulated environments. First 10 enterprise customers. SOC 2 Type II compliance story.

#### Epic 6: Zero-Network Verification for CI/CD

**Task 6.1: Freeze `--identity-bundle` JSON contract**
- **Cite**: The identity bundle schema is defined in `auths-verifier/src/core.rs` (`IdentityBundle` struct) and consumed by `auths-verify-github-action` (input: `identity-bundle` / `identity-bundle-json` with TTL validation via `bundle_timestamp` + `max_valid_for_secs`).
- **Action**: Publish the `IdentityBundle` JSON schema (enabled by `auths-verifier` feature `schema` which uses `schemars`). Freeze the schema with a version field. CI pipelines should be able to pin to a bundle schema version and not break on upgrades.

**Task 6.2: Optimize `auths-verifier` binary size for GitHub Actions**
- **Cite**: The GitHub Action (`auths-verify-github-action/src/main.ts`) downloads the full `auths` CLI binary at runtime. This includes the entire CLI, SDK, storage layer, and keychain code -- none of which is needed for verification.
- **Action**: Ship a standalone `auths-verify` binary (already exists as `crates/auths-cli/src/bin/verify.rs` with only 2 imports). Strip it for CI: no keychain, no `git2`, no `reqwest`. Target: <5MB binary, <1s startup. The `auths-verifier` crate was explicitly designed for this: "Minimal-dependency verification library designed for embedding."

**Task 6.3: GitHub Actions OIDC integration for attestation minting**
- **Cite**: The OIDC bridge (`auths-cloud/crates/auths-oidc-bridge/`) already exchanges attestation chains for JWTs consumable by cloud providers. GitHub Actions provides short-lived OIDC tokens to runners automatically.
- **Action**: Create an `auths-attest-github-action` that receives the GitHub OIDC token, cross-references it with the repository's identity registry (stored in `refs/auths/`), and mints a scoped attestation for the CI run. This replaces long-lived secrets in CI with ephemeral cryptographic proofs.

#### Epic 7: Enterprise Compliance

**Task 7.1: Audit trail export**
- **Cite**: `auths-sdk/src/audit.rs` implements event emission via the `EventSink` trait (re-exported from `auths-telemetry`). `auths-telemetry/telemetry-schema.md` defines the event schema.
- **Action**: Add SIEM-compatible event formats (CEF, LEEF). Every signing, verification, rotation, and delegation event is already captured -- just needs formatting for Splunk/Datadog/Elastic ingestion.

**Task 7.2: Policy-as-code for compliance gates**
- **Cite**: `auths-policy` already implements `compile_from_json()`, `evaluate_strict()`, and `enforce()` with shadow policies for canary testing. The E2E tests (`tests/e2e/test_policy_engine.py`) validate `policy lint`, `policy compile`, `policy explain`, `policy test`, and `policy diff` CLI commands.
- **Action**: Build a GitHub App that runs `auths policy evaluate` as a required status check. Policies are stored in `.auths/policies/` in the repo. Changes to policies trigger `auths policy diff` and require approval (using the existing approval gate in `auths-policy/src/approval.rs`).

**Task 7.3: Human-in-the-loop approval gates for production deployments**
- **Cite**: `crates/auths-policy/src/approval.rs` implements `ApprovalAttestation` with `jti` (nonce), `approver_did`, `request_hash` (Blake3), `expires_at`, and `approved_capabilities`. `ApprovalScope` enum (Identity/Scoped/Full) controls hash computation. `crates/auths-storage/src/git/approval.rs` persists approval state in the Git registry tree.
- **Action**: Integrate with Slack/Teams/PagerDuty. When a CI pipeline hits a `RequiresApproval` policy decision, post a message with a one-time approval link. The approver signs with their `auths` identity, creating an `ApprovalAttestation` that satisfies the policy gate.

---

### $100M Valuation: The Standard for Decentralized Supply Chain

**Rationale**: `auths` identity is recognized by 2+ major forges. The verification widget is embedded in GitHub/GitLab UIs via browser extension. KERI event logs provide enterprise-grade key lifecycle. 50+ enterprise customers.

#### Epic 8: Major Forge Adoption

**Task 8.1: Propose `auths` verification as a Git signing format**
- **Cite**: GitHub currently supports GPG, SSH, and S/MIME for commit signing. The `auths` signing format uses SSHSIG (implemented in `auths-sdk/src/signing.rs`) which is already recognized by GitHub's SSH verification. But the attestation chain and KERI identity are invisible to GitHub.
- **Action**: Propose a `x-auths` signature format to GitHub that includes the attestation chain in the signature trailer. This would show "Verified by Auths" badges natively in the GitHub UI, replacing the need for the browser extension.

**Task 8.2: Scale KERI event logs for enterprise**
- **Cite**: `crates/auths-keri/src/event.rs` implements `Inception`, `Rotation`, and `Interaction` events with CESR serialization. `crates/auths-storage/src/git/adapter.rs` stores events as zero-padded sequence files (`events/00000000.json`, `events/00000001.json`).
- **Action**: For enterprises with thousands of identities and frequent rotations, the sequential file approach needs sharding. Implement batch KEL compaction (merge N events into a checkpoint file) and optional PostgreSQL backend (feature `backend-postgres` already exists in `auths-storage/Cargo.toml` with `sqlx` dep).

**Task 8.3: Witness network for Byzantine-tolerant verification**
- **Cite**: `auths-verifier/src/witness.rs` implements `WitnessReceipt` validation and `WitnessQuorum` checking. `auths-core` has a `witness-server` feature with `axum`-based witness endpoint. `verify_chain_with_witnesses()` requires N-of-M witness receipts.
- **Action**: Deploy a public witness network (3-5 nodes across cloud providers). Enterprise customers can run private witnesses. The quorum config is already pluggable via `WitnessConfig` parameter.

#### Epic 9: Supply Chain Artifact Signing

**Task 9.1: Container image signing with `auths` identity**
- **Cite**: The `auths-cli` has `artifact sign` and `artifact verify` commands (in `src/commands/artifact/`). The signing pipeline in `auths-sdk/src/signing.rs` is artifact-agnostic -- it signs arbitrary byte streams.
- **Action**: Build a Cosign-compatible output format. A container image signed with `auths` should be verifiable by existing Sigstore tooling, but the identity is an `auths` DID instead of an OIDC email. This provides a migration path from Sigstore without requiring infrastructure changes.

---

### $300M Valuation: Enterprise IAM Replacement

**Rationale**: `auths` replaces Okta/Azure AD for developer-facing workloads. Enterprises provision agent identities via SCIM, enforce policies via the policy engine, and bridge to cloud IAM via the OIDC bridge. 200+ enterprise customers. $20M+ ARR.

#### Epic 10: OIDC Bridge as Enterprise Identity Fabric

**Task 10.1: Production-grade OIDC bridge deployment**
- **Cite**: `auths-cloud/crates/auths-oidc-bridge/` implements RS256 JWT issuance, JWKS rotation (`src/jwks.rs`), audience detection for AWS/GCP/Azure (`src/audience.rs`), rate limiting (`src/rate_limit.rs`), and RFC 8693 OBO token exchange (`src/issuer.rs`). The bridge verifies attestation chains via `auths-verifier` and issues short-lived JWTs consumable by cloud providers.
- **Action**: Deploy as a managed service. Enterprises configure their AWS STS trust policy to accept JWTs from the `auths` OIDC bridge. Developers authenticate to cloud resources using their `auths` identity -- no IAM users, no long-lived credentials, no shared secrets.

**Task 10.2: SCIM provisioning for enterprise IdP integration**
- **Cite**: `crates/auths-scim/` implements RFC 7643/7644 with `ScimUser` resource type, `AuthsAgentExtension` (identity_did, capabilities), filter parsing (AND/OR/NOT/eq/ne/co/sw/pr), PATCH operations (add/replace/remove), and `ListResponse` pagination. `auths-cloud/crates/auths-scim-server/` is the HTTP server with SQLite backend and bearer token auth.
- **Action**: Connect to Okta/Azure AD SCIM provisioning. When an employee is added to the "Developers" group in Okta, an `auths` agent identity is automatically provisioned with the appropriate capabilities. When they leave, the identity is revoked.

**Task 10.3: SPIFFE/SPIRE integration for workload identity**
- **Cite**: `auths-cloud/crates/auths-oidc-bridge/src/spiffe.rs` implements X.509-SVID verification. The `OidcClaims` type (now in `crates/auths-jwt/src/claims.rs`) includes a `spiffe_id` field.
- **Action**: Bridge SPIFFE workload identity to `auths` attestation chains. A Kubernetes pod with a SPIFFE SVID can exchange it for an `auths` attestation, enabling workload-to-developer trust chains.

#### Epic 11: Multi-Tenancy & Org Management

**Task 11.1: Organization hierarchy with delegated administration**
- **Cite**: `auths-sdk/src/workflows/org.rs` implements org operations. `auths-storage/src/git/adapter.rs` stores org membership under `v1/orgs/{shard}/{did}/members/`. The `ManageMembers` capability in `auths-verifier` controls who can modify org membership.
- **Action**: Implement nested orgs (department -> team -> project). Each level can delegate a subset of capabilities downward. The policy engine already supports `delegated_by` context for evaluating delegation depth.

---

### $500M Valuation: Ubiquitous Protocol Adoption

**Rationale**: `auths` is the default cryptographic identity layer for developer tooling. The protocol specification is published and implemented by multiple parties. 500+ enterprise customers. $50M+ ARR. Strategic acquirer interest from GitHub/Microsoft, Google, or Hashicorp.

#### Epic 12: Protocol Ossification & Specification

**Task 12.1: Publish the Auths Identity Protocol specification**
- **Cite**: The codebase implicitly defines the protocol: attestation JSON format (`auths-verifier/src/core.rs`), KEL event format (`auths-keri/src/event.rs`), identity bundle format (`IdentityBundle`), capability taxonomy (`Capability` enum), and Git ref layout (`auths-storage/src/git/paths.rs`).
- **Action**: Extract these into a formal specification document (RFC-style). Submit to the Decentralized Identity Foundation (where KERI is already incubated). The specification should be implementable in any language from the document alone.

**Task 12.2: Third-party verifier implementations**
- **Cite**: The verification surface is intentionally minimal. `auths-verifier` has only 11 dependencies with the `native` feature. The core verification logic is pure Ed25519 signature checking + JSON canonicalization + chain walking.
- **Action**: Publish reference implementations in Go (for Kubernetes ecosystem), TypeScript (already exists via WASM), and Python (already exists via PyO3). The key insight: verification is cheap and stateless. Anyone can verify, only `auths` identities can sign.

**Task 12.3: Hardware security module (HSM) integration**
- **Cite**: `auths-core` already has a `keychain-pkcs11` feature with `cryptoki` dependency for HSM support. The `AgentError` enum in `auths-core/src/error.rs` includes HSM-specific variants: `HsmPinLocked`, `HsmDeviceRemoved`, `HsmSessionExpired`.
- **Action**: Certify `auths` with YubiKey, AWS CloudHSM, and Google Cloud KMS. Enterprise customers require FIPS 140-2 Level 2+ key storage. The PKCS#11 abstraction already exists -- it needs vendor-specific testing and documentation.

#### Epic 13: Extreme Modularity

**Task 13.1: `auths-verifier` as a syscall-free, no-std library**
- **Cite**: `auths-verifier` currently requires `ring` (which uses assembly) and `std`. The `wasm` feature already avoids native syscalls by using `WebCrypto`.
- **Action**: Create a `no-std` feature that uses a pure-Rust Ed25519 implementation (e.g., `ed25519-dalek`). This enables verification in bare-metal environments, TEEs (Trusted Execution Environments), and blockchain smart contracts. The verification logic itself is purely computational -- no I/O, no allocation beyond the attestation chain.

**Task 13.2: Embeddable policy engine**
- **Cite**: `auths-policy` has minimal dependencies (serde, blake3). The `CompiledPolicy` type is a self-contained, serializable evaluation unit.
- **Action**: Compile `auths-policy` to WASM for browser-side policy evaluation. Publish as a standalone npm package. CI tools can evaluate policies without installing the full `auths` CLI.

**Task 13.3: Git forge webhook receiver for real-time verification**
- **Cite**: The `auths-infra-http` crate implements async HTTP clients. The `auths-mcp-server` implements `axum`-based middleware with JWT authentication.
- **Action**: Build an `auths-webhook-server` that receives push webhooks from GitHub/GitLab/Gitea, verifies all new commits in real-time, and posts verification results back as commit statuses. This is the "always-on" counterpart to the "on-demand" GitHub Action.

---

## Summary: The Moat is Structural

| Valuation | Core Moat | Key Metric |
|---|---|---|
| **$10M** | Best DX for commit signing | 50 OSS adopters, v0.1.0 shipped |
| **$20M** | Multi-platform identity primitive (CLI + mobile + widget) | 3+ integrations, first enterprise pilot |
| **$60M** | Zero-network CI/CD verification standard | 10 enterprise customers, SOC 2 story |
| **$100M** | Forge-recognized identity format | 2+ forge integrations, witness network |
| **$300M** | Enterprise IAM replacement for dev workloads | 200 enterprises, $20M ARR |
| **$500M** | Ubiquitous protocol, multiple implementations | Published spec, 500 enterprises, $50M ARR |

The architectural decision to store identity in Git refs and verify without network access creates a structural moat that cannot be replicated by adding features to Sigstore (which is architecturally centralized) or to GitHub's SSH signing (which has no identity lifecycle). The codebase is already engineered for this trajectory -- the layered architecture, trait-based ports, and polyglot verification surface are not accidental. They are the foundation for a protocol-level business.

---

*Sources:*
- [Sigstore Gitsign](https://github.com/sigstore/gitsign)
- [Chainguard $3.5B Series D](https://news.crunchbase.com/cybersecurity/startup-chainguard-raise-venture-unicorn-kleiner/)
- [Software Supply Chain Security Market](https://www.custommarketinsights.com/report/software-supply-chain-security-market/)
- [Snyk Revenue](https://getlatka.com/companies/snyk)
- [Gartner 2025 SSCS Market Guide](https://apiiro.com/blog/gartner-software-supply-chain-security-guide-2025/)
- [GitHub Commit Signature Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [KERI Protocol](https://keri.one/)
- [KERI Foundation](https://keri.foundation/)
- [OriginVault DID SDK](https://www.npmjs.com/package/@originvault/ov-id-sdk)
- [Decentralized Identity Foundation](https://identity.foundation/)
