# Auths Codebase Review
**Version:** `0.0.1-rc.13` · **Lines of code:** ~121K · **Crates:** 22
**Date:** 2026-03-11

---

## Section 1: Code Quality Review

### 1.1 Architecture & Layering

**Verdict: Mostly sound with notable leakage.**

The SDK-first design is clearly intentional and mostly respected. `auths-sdk/src/workflows/` is where the real logic lives — signing, rotation, provisioning, audit, etc. — and the CLI delegates to those workflows through a dependency-injected `AuthsContext`. The `ExecutableCommand` trait is implemented consistently across every top-level command (including `WhoamiCommand`, `WitnessCommand`, and the newer commands like `RegistryOverrides`). Port traits in `auths-core/src/ports/` and `auths-sdk/src/ports/` are well-designed and free of implementation leakage.

**Specific issues:**

- **`Utc::now()` called directly throughout CLI command handlers** (not just entry points). Examples: `commands/id/identity.rs:9787`, `commands/device/pair/common.rs:5774`, `commands/emergency.rs:8193,8341,8355`, `commands/org.rs:14352,14416,14540,14621,14677,14687`. The `ClockProvider` port exists, and there is even a workspace lint banning `Utc::now()` in the SDK layers, but the CLI commands are exempt from this lint and call `Utc::now()` directly. This makes those code paths untestable without real time passing.

- **`commands/scim.rs:16435` spawns `auths-scim-server` as a child process** without any path validation. The binary name is hardcoded as a bare string. If `auths-scim-server` is not on `PATH`, the error message "Is it installed?" is the only guidance — no path, no suggestion to install via `cargo install`. This is a presentation-layer concern that is fine to keep in the CLI, but the spawn has no timeout and `child.wait()` will block indefinitely.

- **Business logic in CLI commands that should be in the SDK:** `commands/id/migrate.rs` (~1300 lines) contains substantial identity migration orchestration. `commands/device/pair/common.rs` builds pairing state machines inline. These would benefit from extraction into `auths-sdk/src/workflows/`.

---

### 1.2 Type Safety

**Verdict: Good foundational work; a gap in the domain boundary.**

Newtypes exist for the right things:
- `DeviceDID(pub String)` — `auths-verifier/src/types.rs:110819`
- `IdentityDID(pub String)` — `auths-verifier/src/types.rs:110720`
- `KeyAlias(String)` — `auths-core:32796`
- `EmailAddress(String)` — `auths-sdk:92064`
- `Ed25519PublicKey([u8; 32])` and `Ed25519Signature([u8; 64])` — `auths-verifier/src/types.rs`

**Specific issues:**

- **Raw `String` used at CLI-to-SDK boundaries for domain types.** In `commands/device/pair/common.rs` and throughout `commands/id/`:
  ```
  device_did: String        (line 4876)
  identity_key_alias: String (line 4862)
  controller_did: String    (line 9204)
  ```
  These fields cross module boundaries without being wrapped in their newtypes. This means validation is deferred past the point where it is cheapest to catch.

- **`pub` fields on `DeviceDID` and `IdentityDID`** — `DeviceDID(pub String)`. The inner `String` should be private, forcing construction through a validated `::new()` or `::parse()` that checks DID format at creation time.

- **`AgentSigningAdapter` in `auths-cli/src/adapters/agent.rs:608,612`** — stores `key_alias: String` directly instead of `KeyAlias`. The newtype exists but is not used here.

---

### 1.3 DRY / Duplication

**Three independent implementations of `expand_tilde`:**

| Location | Signature | Error type |
|---|---|---|
| `auths-cli/src/commands/git.rs:8977` | `pub(crate) fn expand_tilde(path: &Path) -> Result<PathBuf>` | `anyhow::Error` |
| `auths-cli/src/commands/witness.rs:19704` | `fn expand_tilde(path: &std::path::Path) -> Result<PathBuf>` | `anyhow::Error` |
| `auths-storage/src/git/config.rs:56667` | `fn expand_tilde(path: &std::path::Path) -> Result<PathBuf, StorageError>` | `StorageError` |

The first two are byte-for-byte identical. The third is identical in logic but returns a different error type. There is a natural home for this in `auths-core` or a `auths-cli/src/core/fs.rs` utility (the `core/fs.rs` file already exists but does not contain `expand_tilde`). This is a pre-launch cleanup item.

**Other duplication:**
- `generate_token_b64()` appears to be defined separately in `commands/scim.rs` and potentially other places — warrants audit.
- `mask_url()` in `commands/scim.rs` is a one-off utility with no shared home.
- JSON response helper `JsonResponse<T>` with `.error()` and `.success()` constructors exists alongside raw `serde_json::json!` construction in several command files.

---

### 1.4 Error Handling

**Verdict: Structurally good; a class of opaque `String` variants undermines the discipline.**

The `AuthsErrorInfo` trait (providing `error_code()` and `suggestion()`) is implemented on `AgentError`, `TrustError`, `SetupError`, `DeviceError`, and `AttestationError`. The layering of `anyhow` at the CLI and `thiserror` in the SDK/core is respected — no `anyhow` was found leaking into `auths-sdk`, `auths-id`, `auths-core`, or `auths-verifier`.

**Specific issues:**

- **Opaque `String` error variants** that lose structure and prevent `AuthsErrorInfo` from providing specific codes/suggestions:
  ```
  auths-core:  SecurityError(String), CryptoError(String), SigningFailed(String)
               StorageError(String), GitError(String), InvalidInput(String), Proto(String)
               (lines 27259–27295)
  auths-sdk:   StorageError(String), SigningFailed(String)  (lines 87350, 88263)
  auths-verifier: InvalidInput(String), CryptoError(String)  (lines 107893, 107897)
  ```
  Each of these should be a structured variant (e.g., `CryptoError { operation: &'static str, source: ring::error::Unspecified }`) so that `error_code()` can return a stable, documentable string.

- **`MutexError(String)` at `auths-core:27291`** — mutex poisoning is a programming error, not a user-facing error. It should panic or be mapped to an internal error code, not propagate a `String` to the user.

- **Errors in `commands/audit.rs` and `commands/org.rs` at lines 4105, 10234, 10332, 10627, 10736** construct JSON with `"created_at": chrono::Utc::now()` inline, mixing side-effectful timestamp generation into serialisation paths.

---

### 1.5 Testing

**Verdict: Unusually thorough for a solo project; two structural gaps.**

1,389 unit tests found across the workspace. Fakes exist for all core port traits: `FakeConfigStore`, `FakeAttestationSink`, `FakeAttestationSource`, `FakeIdentityStorage`, `FakeRegistryBackend` (in `auths-id`), plus `FakeAgent`, `FakeAllowedSignersStore`, `FakeGit`, `FakeGitConfig`, `FakeSigner` (in `auths-sdk/src/testing/fakes/`). Contract tests in `auths-sdk/src/testing/contracts/` provide a shared test suite for adapters.

Fuzz targets exist for `attestation_parse`, `did_parse`, and `verify_chain` in `auths-verifier/fuzz/`.

**Gaps:**

1. **CLI integration test coverage is thin — only ~50 lines** use `assert_cmd`/`Command::cargo_bin`. For a tool whose primary surface is a CLI, there should be end-to-end tests for at minimum `init`, `sign`, `verify`, `doctor`, and `device pair`. The happy path for the core user journey (`init` → `git commit` → `verify HEAD`) does not appear to have an integration test.

2. **`Utc::now()` called directly in ~35 CLI command sites** (detailed above). Because these are not injected through `ClockProvider`, time-sensitive logic (expiry checks, token freshness, freeze state) cannot be tested deterministically without mocking system time. This is the most significant testability gap.

---

### 1.6 Security

**Verdict: Strong fundamentals; three areas need hardening before public launch.**

**What's working well:**
- `Zeroizing<T>` and `ZeroizeOnDrop` are used consistently on `SecureSeed`, `Ed25519Keypair.secret_key_bytes`, and X25519 shared secrets.
- `validate_passphrase()` validates at the boundary.
- The KEL validation chain in `auths-id/src/keri/validate.rs` calls `verify_event_said()`, `verify_sequence()`, `verify_chain_linkage()`, and `verify_event_signature()` — the full chain is cryptographically verified, not just structurally present. Ed25519 signatures are verified with `ring` (`pk.verify()` at line `53210`).
- `auths-verifier` has fuzz targets.

**Issues requiring attention before launch:**

~~**P0 — `verify-options` pass-through in `auths-sign`:**~~
In `bin/sign.rs`, `args.verify_options` (a `Vec<String>` populated from CLI `--verify-option` flags) is passed directly as arguments to `ssh-keygen` via `.arg("-O").arg(opt)` (lines ~198–199 and ~230–231). While `Command::new` with explicit `.arg()` calls is not shell injection, a crafted `-O` value like `no-touch-required` or a future `ssh-keygen` flag could alter verification semantics. These options should be validated against an allowlist of known-safe `verify-time=<timestamp>` patterns before being passed through. This binary is callable from CI environments with attacker-influenced inputs.

~~**P1 — `DeviceDID` and `IdentityDID` inner values are publicly accessible:**~~
`DeviceDID(pub String)` and `IdentityDID(pub String)` can be constructed with arbitrary strings without parsing. The DID format (`did:keri:...`) is not validated at construction. A malformed DID that bypasses newtypes can reach storage and the KEL resolver.

~~**P2 — `commands/emergency.rs:8341` writes `frozen_at: chrono::Utc::now()` into a freeze record:**~~
This timestamp is written to the git ref store and is later used to compute `expires_description()`. Since the clock is not injected, replay or time-skew attacks on freeze state cannot be tested. This is lower severity but relevant for enterprise audit trail integrity.

---

## Section 2: v0.1.0 Launch Readiness

### Feature Completeness

The core end-to-end user journey is implemented:
- `auths init` — guided setup with SSH agent integration, key generation, git config.
- `git commit` → signed via `auths-sign` git-config hook.
- `auths verify HEAD` / `auths verify-commit` — full attestation chain verification.
- GitHub Action — working (per your confirmation).
- `auths doctor` — functional with fix suggestions.
- Device pairing — LAN, online relay, and offline QR modes implemented.
- Key rotation — `auths key rotate` with KEL append.
- Revocation — `auths emergency` with freeze/revoke semantics.

### API Stability

CLI flags are well-structured and consistently named. JSON output (`--json`) is present on the main verification paths. However, JSON schemas are generated by `xtask/src/gen_schema.rs` and appear to be in flux — the schema for attestation bundles and verification output should be frozen and versioned before public docs point to them.

SDK public types in `auths-verifier` are the most stable — these are what the WASM widget, Python SDK, and Node SDK consume. `auths-sdk` public types are less stable and should not be documented as stable external API at v0.1.0.

### Overall Readiness Rating: **7 / 10**

Blockers before shipping:

| # | Blocker | Severity |
|---|---|---|
| 1 | `verify-options` allowlist in `auths-sign` | P0 security |
| 2 | `DeviceDID`/`IdentityDID` with `pub` inner field — validate at construction | P0 type safety |
| 3 | End-to-end CLI integration test for core journey (`init` → `sign` → `verify`) | P0 launch confidence |
| 4 | `expand_tilde` triplicate — consolidate before adding a 4th | P1 DRY |
| 5 | `Utc::now()` in ~35 CLI command sites — at minimum the expiry and freeze paths need `ClockProvider` injection | P1 testability |
| 6 | Opaque `String` variants in error enums — replace the 10 identified with structured variants | P1 user experience |
| 7 | `commands/scim.rs` child process spawn — add timeout, better error message | P2 |
| 8 | JSON output schema versioning — freeze `--json` schemas before publishing docs | P2 |

Items 1–3 are hard blocks. Items 4–6 are strong recommendations. Items 7–8 can be post-launch.

---

## Section 3: Valuation & Product Strategy

### 3.1 Current Fair Valuation

**Range: $1.5M – $4M pre-money.**

Rationale:

- **Technical depth is real and rare.** A solo KERI-based cryptographic identity system in Rust with a working CLI, GitHub Action, WASM verifier, Python SDK, Node SDK, and multi-platform CI pipeline represents 6–12 months of senior engineering time minimum for a team. As a solo build over ~2.5 months with AI assistance, it demonstrates extraordinary execution velocity.
- **No revenue, no production users.** Pre-launch means no ARR multiple can be applied.
- **Comparable early-stage developer security tools** (Sigstore graduated into CNCF with Google/Purdue/Red Hat backing before it had revenue; Keybase raised at ~$10M with a working product but no clear business model). The comparable without institutional backing and without proven adoption is in the $1.5–4M range.
- **The KERI bet is a differentiator and a risk.** KERI is technically superior to X.509 for self-sovereign identity, but has almost no mainstream adoption. An investor will price in the education cost.
- **Upside scenario:** If the Hacker News launch generates measurable GitHub stars (>500), active users (>100 in first month), and PR integrations (even 2–3 notable repos), the valuation conversation shifts to $5–8M seed.

---

### 3.2 Path to $50M Valuation

$50M requires enterprise SaaS revenue or a clear path to it. Here is what needs to be true:

**Revenue model ($50M = ~$5M ARR at 10x, or ~$3M ARR at 15x for a growing company):**

- **Free tier:** Open source CLI, GitHub Action, WASM verifier, Python/Node SDKs. This is already the plan and is correct — developer adoption is the top of funnel.
- **Team tier ($29/user/month):** Managed witness infrastructure, org-level policy enforcement, audit log export (SOC 2 evidence), SAML/OIDC SSO, Slack/Teams alerts for signing anomalies. Target: engineering teams of 5–50.
- **Enterprise tier ($80–150/user/month or $50K–200K/year flat):** SCIM provisioning (already built!), self-hosted witness nodes, HSM integration, GitHub Enterprise + GitLab self-hosted connectors, SLA, priority support, CISO-friendly compliance exports (SLSA, SBOM attestation). Target: >500-engineer orgs with compliance mandates.
- **Infrastructure licensing ($500K+/year):** For financial services or defense contractors who cannot use SaaS — air-gapped deployment of the full Auths stack.

At $3M ARR from 50 enterprise customers averaging $60K/year, with 15x multiple on growing SaaS, $50M is credible.

**Market positioning:**

| Competitor | Weakness Auths exploits |
|---|---|
| **Sigstore / Cosign** | Certificate-authority dependent (Fulcio), not self-sovereign, Google-run trust root that enterprises cannot audit-own |
| **GitHub's built-in signing** | Tied to GitHub, no portability to GitLab/self-hosted, no org-level enforcement policy, no revocation story |
| **GPG commit signing** | Horrible UX, key distribution nightmare, no rotation story, no device binding |
| **Keybase** (effectively dead) | Centralized servers, no cryptographic revocation, no enterprise features, abandoned |
| **SpruceID / DIDKit** | Broader W3C DID focus, not git-native, no developer UX story |

Auths' moat is: **git-native storage + KERI-based self-sovereign rotation + developer UX that matches GPG simplicity without the GPG pain.**

**Adoption metrics an investor needs to see before $50M:**
- 2,000+ GitHub stars
- 500+ weekly active CLI users (telemetry)
- 10+ enterprise pilots (even unpaid)
- 3+ notable open-source repositories with Auths CI verification in their workflows
- Published CVE or security audit report showing the protocol is sound

**Team composition needed at $50M pitch:**
- 1 technical co-founder / CEO (you)
- 1 additional senior Rust engineer
- 1 developer advocate / growth engineer
- 1 enterprise sales / solutions engineer

**Technical moat (what's hard to replicate):**
1. KERI-based KEL with cryptographic rotation — competitors would have to rebuild from protocol foundations.
2. The `auths-verifier` WASM module that verifies anywhere with no server dependency — this is genuinely unusual.
3. Git-native storage means zero infrastructure cost for the user in the free tier — no server to maintain.
4. Multi-platform SDK surface (Rust, Python, Node, WASM) built from a single source of truth.

---

### 3.3 v1.0.0 Feature Requirements

These are the features that separate "impressive developer tool" from "enterprise-mandatable infrastructure."

---

~~#### Epic 1: Structured Error Codes and Actionable CLI Output~~
**Why it matters:** A CISO cannot mandate a tool their engineers curse at. Error messages must be searchable in docs.

**Scope:**
- Replace all 10+ opaque `String` error variants identified in Section 1.4 with structured enum variants. Each variant must carry typed fields (not strings) and implement `AuthsErrorInfo` with a stable `error_code()` (e.g., `E1042`) and a `suggestion()` string pointing to a docs URL.
- Every error emitted by the CLI must have a unique, stable, documented error code. Format: `[AUTHS-EXXX]` prefixed in terminal output.
- Add a `auths error <code>` subcommand that prints the full explanation and resolution steps for a given error code — identical to how the Rust compiler handles `rustc --explain E0XXX`.
- Error codes must be included in JSON output (`--json` flag) so CI systems can programmatically handle specific failure modes.

**Files to touch:**
- `crates/auths-core/src/error.rs` — replace `String` variants
- `crates/auths-sdk/src/ports/agent.rs`, `crates/auths-sdk/src/result.rs`
- `crates/auths-verifier/src/error.rs`
- `crates/auths-cli/src/commands/executable.rs` — add error code formatting to output
- New: `crates/auths-cli/src/commands/explain.rs`
- Docs: `docs/errors/` directory with one `.md` per error code. Look into automating error docs via a similar approach in `auths/crates/xtask/src/gen_docs.rs`, and should add new `{error}.md` files if we add errors to the code

---

~~#### Epic 2: `Utc::now()` Injection — Complete Clock Discipline~~
**Why it matters:** Every expiry check, freeze check, and token validity check in the CLI is currently untestable. This is a launch blocker for the freeze/revocation path and a pre-condition for writing meaningful integration tests.

**Scope:**
- Audit all `Utc::now()` call sites in `auths-cli` (~35 identified). For each:
  - If the call is in an `ExecutableCommand::execute()` entry point, it is acceptable to call `Utc::now()` once and pass the result down.
  - If the call is more than one function call deep from the entry point, it must accept a `DateTime<Utc>` parameter instead.
- Commands requiring specific attention: `emergency.rs` (freeze/revoke timestamps), `device/pair/common.rs` (paired_at, token expiry), `org.rs` (created_at, attestation expiry), `commands/id/identity.rs` (bundle_timestamp), `status.rs`.
- The workspace lint `{ path = "chrono::offset::Utc::now", reason = "inject ClockProvider..." }` already exists but exempts `auths-cli`. Remove the exemption and fix the resulting compilation errors.
- Update fakes: `auths-sdk/src/testing/fakes/` — add `FakeClock` (likely already partially exists given `ClockProvider` is in `auths-verifier/src/clock.rs`; confirm it is exposed in the testing module).

**Files to touch:**
- `crates/auths-cli/src/commands/emergency.rs`
- `crates/auths-cli/src/commands/device/pair/common.rs`
- `crates/auths-cli/src/commands/org.rs`
- `crates/auths-cli/src/commands/id/identity.rs`
- `crates/auths-cli/src/commands/status.rs`
- `crates/auths-cli/src/commands/id/migrate.rs`
- `crates/auths-cli/src/commands/device/authorization.rs`
- `Workspace.toml` — remove `auths-cli` exemption from `disallowed-methods` lint

---

~~#### Epic 3: CLI Integration Test Suite~~
**Why it matters:** With only ~50 lines of `assert_cmd` coverage across the entire CLI, you cannot confidently say the install-to-first-commit journey works on a clean machine. This is a launch confidence blocker.

**Scope:**
- Write integration tests using `assert_cmd` + `tempfile` for the following scenarios. Each test must use a real temporary git repository and a real temporary `$HOME`-equivalent directory (no global state):

  1. **`init` happy path** — `auths init --non-interactive` (or with scripted prompts) produces valid `~/.auths/` layout, sets `git config gpg.ssh.allowedSignersFile`, sets `git config gpg.format ssh`, sets `git config user.signingkey`.
  2. **`sign` + `verify` round trip** — after `init`, make a commit, run `auths verify HEAD`, assert exit 0 and JSON output contains `"status": "verified"`.
  3. **`doctor` detects misconfiguration** — remove `gpg.format` from git config, run `auths doctor`, assert it identifies the missing config and suggests a fix.
  4. **`key rotate` maintains verify** — rotate the signing key, make a new commit, verify both old and new commits pass (KEL replay).
  5. **`emergency revoke` blocks verify** — after revocation, `auths verify HEAD` on a pre-revocation commit must fail with a specific error code.
  6. **`--json` output schema** — assert that `auths verify HEAD --json` output is valid against the published JSON schema.

- Each test must be runnable in CI without network access (use `FakeWitness` or disable witness requirement).
- Tests must be in `crates/auths-cli/tests/` using `assert_cmd::Command::cargo_bin("auths")`.
- Add a `Makefile` target or `xtask` subcommand `cargo xtask test-integration` that runs these with appropriate environment isolation.

---

~~#### Epic 4: `expand_tilde` Consolidation and `auths-utils` Crate~~
**Why it matters:** Three implementations of the same function is a maintenance hazard. The right fix is a micro-crate or a shared module that all layers can depend on without introducing circular dependencies.

**Scope:**
- Create `crates/auths-utils/` as a new zero-dependency crate (no `auths-*` dependencies, only `std` + `dirs`).
- Move `expand_tilde` into `auths-utils/src/path.rs` with signature `pub fn expand_tilde(path: &Path) -> Result<PathBuf, ExpandTildeError>` where `ExpandTildeError` is a `thiserror` enum with a single `HomeDirNotFound` variant.
- Replace the three existing implementations with `use auths_utils::path::expand_tilde`.
- Also move `mask_url()` (currently inlined in `commands/scim.rs`) into `auths-utils/src/url.rs`.
- Add `auths-utils` as a `workspace` dependency.
- The crate should be `publish = false` — it is an internal utility, not a public API surface.

**Files to touch:**
- New: `crates/auths-utils/Cargo.toml` (model after other crates), `crates/auths-utils/src/lib.rs`, `crates/auths-utils/src/path.rs`, `crates/auths-utils/src/url.rs`, `README.md`
- `crates/auths-cli/src/commands/git.rs:8977` — delete `expand_tilde`, add `use auths_utils::path::expand_tilde`
- `crates/auths-cli/src/commands/witness.rs:19704` — same
- `crates/auths-storage/src/git/config.rs:56667` — delete `expand_tilde`, adapt error type
- `Cargo.toml` (workspace) — add `auths-utils` member and workspace dependency
- `auths/scripts/releases/2_crates.py` - add `crates/auths-utils` to the correct release ordering

---

~~#### Epic 5: `DeviceDID` and `IdentityDID` Validation at Construction~~
**Why it matters:** A DID newtype that accepts arbitrary strings provides false safety. Any malformed DID that reaches the KEL resolver or storage layer can cause confusing errors deep in the stack.

**Scope:**
- Make the inner fields of `DeviceDID` and `IdentityDID` private: change `DeviceDID(pub String)` to `DeviceDID(String)` in `auths-verifier/src/types.rs`.
- Add `DeviceDID::parse(s: &str) -> Result<Self, DidParseError>` that validates the string matches the `did:keri:<prefix>` pattern using the existing KERI prefix parsing logic.
- Add `DeviceDID::as_str(&self) -> &str` and implement `Display` and `FromStr`.
- Do the same for `IdentityDID`.
- Fix all construction sites in `commands/device/pair/common.rs`, `commands/id/identity.rs`, `commands/id/migrate.rs` that currently use `device_did: String` — replace with `DeviceDID::parse()`.
- Add unit tests: valid DID parses, invalid format returns `DidParseError`, `Display` round-trips through `FromStr`.

**Files to touch:**
- `crates/auths-verifier/src/types.rs` — make inner fields private, add `parse()`, `as_str()`, `Display`, `FromStr`
- `crates/auths-cli/src/commands/device/pair/common.rs` — fix construction sites
- `crates/auths-cli/src/commands/id/identity.rs` — fix construction sites
- `crates/auths-cli/src/commands/id/migrate.rs` — fix construction sites
- `crates/auths-cli/src/adapters/agent.rs` — replace `key_alias: String` with `KeyAlias`

---

#### Epic 6: `auths-sign` verify-options Allowlist (Security)
**Why it matters:** The `verify-options` flags are passed directly to `ssh-keygen` with no validation. In a GitHub Actions context, these values can originate from PR metadata or environment variables, making this a potential vector for altering verification semantics.

**Scope:**
- In `crates/auths-cli/src/bin/sign.rs`, before passing `args.verify_options` to `ssh-keygen`, validate each option against an allowlist.
- Permitted options: `verify-time=<unix_timestamp>` (digits only after `=`), `print-pubkeys`, `hashalg=sha256`, `hashalg=sha512`.
- Reject any option not on the allowlist with a specific error: `[AUTHS-E0031] Unsupported verify option '{opt}'. Allowed options: verify-time=<timestamp>`.
- Add unit tests in `bin/sign.rs` for: valid `verify-time=1700000000` passes, `verify-time=abc` fails, an unknown option fails, an injection attempt like `no-touch-required` fails.

**Files to touch:**
- `crates/auths-cli/src/bin/sign.rs` — add `validate_verify_option(opt: &str) -> Result<()>` and call it before the `ssh-keygen` spawn loop

---

#### Epic 7: Enterprise SAML/OIDC Identity Binding
**Why it matters:** A CISO cannot mandate Auths if device identity cannot be tied to the corporate IdP. This is the single most common enterprise procurement question for developer security tools.

**Scope:**
- Extend `commands/device/authorization.rs` (already has an `OAuthDeviceFlowProvider` port) to support SAML 2.0 assertion binding in addition to OIDC.
- The binding must produce an attestation event that records: IdP issuer, subject (employee email), authentication time, and authentication context class (e.g., `PasswordProtectedTransport`, `MultiFactor`).
- This attestation must be stored in the KEL as an `ixn` (interaction) event so it is part of the verifiable identity chain.
- Add `auths id bind-idp --provider <okta|azure-ad|google-workspace|generic-saml>` subcommand.
- The `auths verify` output must include `"idp_binding": { "issuer": "...", "subject": "...", "bound_at": "..." }` in `--json` mode.
- Supported IdPs for v1.0.0: Okta, Azure AD (Entra ID), Google Workspace. Generic SAML as a fourth option.
- The `auths-sdk` must expose `IdpBinding` as a public type so Python/Node SDKs can surface it.

**Files to touch:**
- `crates/auths-cli/src/commands/id/` — new `bind_idp.rs`
- `crates/auths-core/src/ports/platform.rs` — add `SamlAssertionProvider` port
- `crates/auths-infra-http/` — add Okta, Azure AD, Google Workspace OAuth/SAML adapters
- `crates/auths-sdk/src/workflows/` — new `idp_binding.rs` workflow
- `crates/auths-sdk/src/types.rs` — add `IdpBinding` public type
- `crates/auths-verifier/src/types.rs` — include `idp_binding` in `VerifiedIdentity`
- `crates/auths-verifier/src/verify.rs` — surface binding in verification output

---

#### Epic 8: SLSA Provenance and SBOM Attestation
**Why it matters:** Post-EO 14028 (US Executive Order on Cybersecurity), enterprises must produce software supply chain attestations. Auths is perfectly positioned to be the signing layer for SLSA Level 2+ provenance and SPDX/CycloneDX SBOMs. This is the "why not just use GPG" answer for a CISO.

**Scope:**
- Extend `commands/artifact/` (already exists with `sign`, `verify`, `publish`) to support structured attestation payloads conforming to:
  - SLSA Provenance v1.0 (`https://slsa.dev/provenance/v1`)
  - SPDX 2.3 SBOM
  - CycloneDX 1.5 SBOM
  - in-toto attestation framework (link layer)
- `auths artifact sign --slsa-provenance --builder-id <uri> --source-uri <uri>` must produce a signed attestation bundle that can be verified by `slsa-verifier` independently.
- `auths artifact verify --policy slsa-level=2` must check that the provenance attestation was signed by a key in the KEL and that the build parameters meet the specified SLSA level.
- Publish attestation bundles to OCI registries (via `oras` or direct OCI push) in addition to git refs, so container image attestations can be stored alongside the image.
- The `auths-verifier` WASM module must be able to verify SLSA attestations without a git repository present (pure in-memory from attestation bundle JSON).

**Files to touch:**
- `crates/auths-cli/src/commands/artifact/` — extend `sign.rs`, `verify.rs`, `publish.rs`
- `crates/auths-sdk/src/workflows/artifact.rs` — add SLSA/SBOM payload constructors
- `crates/auths-verifier/src/` — add `slsa.rs` for SLSA-specific verification
- New: `crates/auths-oci/` — OCI registry push/pull adapter
- Docs: `docs/attestation/slsa.md`, `docs/attestation/sbom.md`

---

#### Epic 9: GitLab, Bitbucket, and Forgejo Support
**Why it matters:** GitHub Action coverage is in place. But >40% of enterprise git usage is GitLab self-hosted or Bitbucket. Without parity, Auths is a GitHub-only tool in enterprise evaluation.

**Scope:**
- GitLab CI: provide a `.gitlab-ci.yml` template and a Docker image `ghcr.io/auths-dev/auths-verify:latest` that can be used as a GitLab CI include. Mirrors the GitHub Action interface exactly (same inputs/outputs, same JSON schema).
- Bitbucket Pipelines: provide a Bitbucket Pipe (`auths-dev/auths-verify-pipe`) published to the Atlassian Marketplace.
- Forgejo/Gitea: provide an Actions workflow compatible with Forgejo's GitHub Actions runner.
- The `auths-infra-git` crate should abstract over the specific platform — add a `GitPlatform` enum (`GitHub`, `GitLab`, `Bitbucket`, `Forgejo`, `Generic`) and use it to select the correct commit signing hook format and the correct CI template output from `auths git install-hooks`.
- `auths doctor` must detect which CI platform the current repo is configured for and check the appropriate template is installed.

**Files to touch:**
- `crates/auths-infra-git/src/` — add platform detection
- `crates/auths-cli/src/commands/git.rs` — extend `install-hooks` for multi-platform
- `crates/auths-cli/src/commands/doctor.rs` — add CI platform checks
- New: `.github/actions/verify/` (already exists), `gitlab/`, `bitbucket-pipe/`, `forgejo/` at repo root
- Docs: `docs/ci/gitlab.md`, `docs/ci/bitbucket.md`, `docs/ci/forgejo.md`

---

#### Epic 10: Managed Witness Infrastructure and SLA (Monetisation Layer)
**Why it matters:** The open-source free tier requires no server. The paid tier requires Auths to operate witness infrastructure. Without this, there is no business.

**Scope:**
- Operate `witness.auths.dev` as a high-availability witness service. Architecture: 3-node cluster, active-passive with automatic failover, 99.9% uptime SLA for Team tier, 99.99% for Enterprise.
- `auths witness` command gains `--use-managed` flag that registers with `witness.auths.dev` using the OAuth device flow, receives an API token, and stores it in config.
- Managed witness events are timestamped with an RFC 3161 trusted timestamp (e.g., from a public TSA like `timestamp.digicert.com`) so that witness events are independently verifiable even if the Auths service goes offline.
- Add `auths witness status` that shows the current witness configuration and health of the configured witness endpoint.
- Billing integration: Team tier allows up to N witness events/month (start with 10,000), Enterprise is unlimited. Over-limit requests receive a `[AUTHS-E4029] Witness quota exceeded` error with a link to upgrade.
- The witness protocol must be documented publicly so customers can self-host — this is the open-core safety valve that prevents vendor lock-in concerns blocking enterprise adoption.

**Files to touch:**
- `crates/auths-cli/src/commands/witness.rs` — add `--use-managed`, `status` subcommand
- `crates/auths-core/src/ports/` — add `ManagedWitnessPort` with quota error variant
- `crates/auths-infra-http/src/` — add managed witness HTTP adapter with auth header injection
- New: `services/witness-server/` — the server-side component (separate repo or workspace member)
- Docs: `docs/witness/self-hosting.md`, `docs/witness/managed.md`

---

## Appendix: Pre-Launch Checklist

| Item | Status |
|---|---|
| `auths init` → `sign` → `verify` end-to-end works | ✅ Implemented |
| GitHub Action CI verification | ✅ Confirmed working |
| WASM verifier (NPM widget) | ✅ Confirmed working |
| Python SDK | ✅ Confirmed working |
| Node.js SDK | ✅ Confirmed working |
| Documentation (quickstart → CI) | ✅ Confirmed complete |
| `auths doctor` | ✅ Functional |
| Device pairing (LAN + online + offline) | ✅ Implemented |
| Key rotation with KEL append | ✅ Implemented |
| Revocation (`emergency`) | ✅ Implemented |
| `verify-options` allowlist in `auths-sign` | ❌ Epic 6 — P0 |
| `DeviceDID`/`IdentityDID` private inner fields | ❌ Epic 5 — P0 |
| CLI integration test suite (init→sign→verify) | ❌ Epic 3 — P0 |
| `expand_tilde` triplicate consolidated | ❌ Epic 4 — P1 |
| `Utc::now()` injection in CLI commands | ❌ Epic 2 — P1 |
| Structured error codes + `auths error <code>` | ❌ Epic 1 — P1 |
| JSON schema versioned and frozen | ⚠️ Needs freeze before docs publish |
| SCIM server spawn timeout + error message | ⚠️ Low priority |
