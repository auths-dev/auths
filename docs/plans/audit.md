# Repository Audit — auths

**Date:** 2026-06-10 · **Scope:** full workspace (34 crates, ~208k LoC Rust, 920 files) + `packages/` polyglot SDKs · **Method:** 6 parallel dimension audits (architecture, code quality, security, testing, performance, docs/DevEx), with every Critical/High claim independently re-verified against source before inclusion. Analysis only; no code modified.

---

## Executive Summary

**Overall health: B+.** This is a genuinely well-engineered security-critical codebase: pinned crypto dependencies with documented bump procedure, custom tree-sitter CI enforcement (constant-time comparisons, curve-tag discipline, RFC 6979), panic-safe FFI, fuzzing, 2,982 tests with real adversarial cases, and a clean `cargo audit`. What keeps it from an A is a consistent pattern: **the project's own enforcement tooling exists but isn't fully wired into CI, and drift has already happened where it isn't** — `scripts/check-arch.sh` currently fails with 3 violation classes, a duplicate error code (E4801) shipped because `gen-error-docs` validation isn't gated, and the version-sync script misses a package that is already drifted (0.1.0 vs 0.1.2). The top 3 risks: (1) the newest layer — org control-plane and relying-party auth (`auths-rp`, `auths-jwt`, `auths-api`) — has materially thinner tests and an O(N×KEL) query cliff than the KERI core; (2) the pairing daemon's rate limiter has unbounded per-IP maps (memory DoS on an internet-facing service); (3) the 8-package polyglot release surface has outgrown its automation (missing lockfiles, missing CI, missing conformance vectors for TS/Python). The top 3 opportunities: wire the three existing-but-ungated checks into CI (hours of work, permanently stops drift), fix the N+1 KEL loading before any real org uses the fleet API, and adopt the orphaned `Capability` newtype at the ~45 sites still using raw `Vec<String>`. Being pre-launch with zero users, all of this is cheap to fix now and expensive later.

Two findings circulated by automated review were **disproven during verification** and are explicitly *not* in this report: `replay_to_seq`'s `validate_kel(&subset).ok()` (`crates/auths-verifier/src/credential.rs:629`) is fail-closed — a failed validation returns `None` and the signature verification returns `false`; and `auths tutorial` does exist (`crates/auths-cli/src/commands/learn.rs:15`).

---

## Repo Map

**Purpose:** Decentralized identity for developers and AI agents — KERI-inspired cryptographic commit signing and agent-passport request authentication, stored in Git refs (no server, no blockchain). Pre-launch, v0.1.2, zero users; published to crates.io/npm/PyPI/Homebrew.

**Stack:** Rust 1.93 workspace (resolver 3), 34 member crates; clap CLI; axum HTTP servers; git2 (vendored libgit2) storage; P-256 default / Ed25519 crypto; WASM + C FFI + UniFFI mobile targets; Python/TS/Go/Swift/Node verifier packages; mkdocs docs; GitHub Actions CI.

**Architecture (verified against Cargo.tomls — matches the documented model):**

```
L0   auths-crypto ──► L0.5 auths-keri ──► L1 auths-verifier ──► L1.5 auths-rp
                                                │                     │
L2   auths-core ◄───────────────────────────────┘                     │
L3   auths-id, auths-policy                                           │
L4   auths-storage, auths-sdk ◄───────────────────────────────────────┘
L5   auths-infra-git, auths-infra-http, auths-infra-rekor
L6   auths-cli (3 bins), auths-api, auths-mcp-server, auths-scim-server,
     auths-pairing-daemon, auths-witness, auths-checkpoint-cosigner, auths-monitor
```

**Key directories:**

| Path | What it is |
|---|---|
| `crates/auths-keri`, `auths-verifier`, `auths-crypto` | The cryptographic core — KEL validation, SAID/CESR, verification. Best-tested code in the repo. |
| `crates/auths-sdk` | Business-logic owner: workflows, domains (org, credentials, identity, pairing). |
| `crates/auths-rp`, `auths-jwt` | Relying-party transport + JWT claims — newest trust boundary. |
| `crates/auths-cli` | `auths`/`auths-sign`/`auths-verify` binaries. |
| `crates/auths-storage` | Git-as-database adapters (`refs/auths/*`); contains the largest file (`git/adapter.rs`, 4,630 lines, cohesive). |
| `crates/xtask` | Custom CI enforcement: curve-agnostic, constant-time, anchor-discipline, command-drift, schema gen, error-doc gen. |
| `packages/` | 8 polyglot packages: node, python, express, fastapi, verifier-{ts,go,swift}, mobile-swift. |
| `crates/auths-mobile-ffi` | Intentionally outside the workspace (own `[workspace]` block, UniFFI resolver concerns). |
| `tests/e2e` | Python pytest E2E suite driving the built binaries. |
| `docs/` | ~30 top-level entries + 17 subdirectories; mkdocs site. |

**Surprises found during mapping:** `scripts/check-arch.sh` exits 3 (failing) today; `auths-radicle` is in the workspace with zero dependents (deprecated per project direction); `crates/auths` is a 24-line placeholder facade; root-level `login_spec.md` is a design doc stranded outside `docs/`.

---

## Audit Report

Each finding: **what / where / why it matters / severity**, labeled **[fact]** (verified in source) or **[judgment]**.

### A. Architecture & design

**A1 — `check-arch.sh` fails with 3 violation classes, and isn't run in CI — High [fact]**
Running `bash scripts/check-arch.sh` today exits 3 with:
- Clock injection violations (banned by CLAUDE.md "Clock Injection"): `crates/auths-sdk/src/oidc_jti_registry.rs:135,147,159,177`, `crates/auths-sdk/src/workflows/ci/machine_identity.rs:330`, `crates/auths-sdk/src/workflows/status.rs:141,150,159,168` — 9 `Utc::now()` calls in SDK domain code.
- Filesystem I/O in the SDK layer: `crates/auths-sdk/src/workflows/roots.rs:39,94-95,169` and `crates/auths-sdk/src/workflows/transparency.rs:245,270,272,310,365,367` (plus a test-block `.unwrap()` chain at `transparency.rs:572`).
- Concrete storage types leaked into the SDK: `crates/auths-sdk/src/keri/resolver.rs:221,284` (imports/instantiates `GitRegistryBackend`), `crates/auths-sdk/src/storage.rs:9-10` (re-exports Git-concrete types).

Why it matters: the project's whole quality model is "rules enforced by automation, not discipline." These violations exist *because* this script never made it into `.github/workflows/ci.yml` (the `xtask-checks` job at `ci.yml:64-77` runs six other checks but not this one, nor `scripts/check_sdk_boundary.sh`). The clock violations break the testability guarantee the injection rule exists for; the fs I/O hardcodes local-disk assumptions into workflows agents/servers are supposed to reuse; the concrete-storage re-export blocks the documented SQL/in-memory backend path.

**A2 — `auths-cli` has direct Cargo dependencies on `auths-core` and `auths-id` — Medium [fact + judgment]**
`crates/auths-cli/Cargo.toml:40-41`. No *source* violations exist today (`scripts/check_sdk_boundary.sh` passes — no `auths_core::`/`auths_id::` references in CLI code), so this is latent, not active. But the deps being declared means any future PR can silently start importing domain internals; the boundary script only catches it if someone remembers to run it (it's not in CI either). An automated reviewer rated this Critical; that overstates it — the correct frame is "remove the unused deps and the leak becomes a compile error instead of a review question."

**A3 — Crate map in CLAUDE.md/ARCHITECTURE.md is missing ~10 newer crates — Low [fact]**
`auths-witness`, `auths-checkpoint-cosigner`, `auths-monitor`, `auths-scim(-server)`, `auths-jwt`, `auths-mcp-server`, `auths-index`, `auths-oidc-port`, `auths-transparency`, `auths-infra-rekor` are real workspace members absent from the documented layer model. New contributors can't tell where they sit or what may depend on them.

**A4 — `auths-radicle` is deprecated, has zero dependents, but remains a published workspace member — Low [fact]**
No crate depends on it (verified via grep over all `Cargo.toml`s); `publish = true` (`crates/auths-radicle/Cargo.toml:7`); it carries the repo's only git dependency (the `bordumb/heartwood` fork) and module-level `#[allow(clippy::unwrap_used)]`. Dead weight in CI minutes, deny.toml exceptions, and the dependency tree.

**What's healthy:** the documented dependency DAG is real — `auths-rp` depends only on `auths-verifier`, no reverse deps anywhere, the CLAUDE.md grep checks pass, `auths-verifier` is genuinely minimal (tokio optional, FFI/WASM-gated), and the largest files (`git/adapter.rs` 4,630 ln, `keri/validate.rs` 2,387 ln) are big but cohesive — no god objects. `auths-mobile-ffi`'s workspace exclusion is intentional and documented in its Cargo.toml.

### B. Security

This dimension is **strong**. `cargo audit` is clean (774 deps, 0 vulnerabilities; the one ignored advisory — RUSTSEC-2023-0071 via transitive `ssh-key` — is documented in `deny.toml:71-75`). No hardcoded secrets found anywhere including docs (the previously-leaked `sk_test` key is gone). FFI is exemplary: every `extern "C"` function in `crates/auths-verifier/src/ffi.rs` null-checks, length-caps (`MAX_ATTESTATION_JSON_SIZE`), and wraps in `catch_unwind` mapping panics to `ERR_VERIFY_PANIC`. Constant-time comparison is *mechanically enforced* (`crates/xtask/src/check_constant_time.rs` bans `==` on secret bytes; 11 verified `ct_eq` sites). Secrets use `Zeroize`/`ZeroizeOnDrop` (`crates/auths-crypto/src/key_ops.rs:21`). JWT validation pins `Algorithm::RS256` rather than trusting the token header, and enforces iss/aud/exp/required-claims (`crates/auths-mcp-server/src/auth.rs:167-173`). The `auths-rp` ChallengeStore is verified bounded + TTL-pruned + remove-on-read (`crates/auths-rp/src/challenge.rs:156-194`). Git subprocess calls use arg arrays, never shell strings (`crates/auths-cli/src/subprocess.rs:25-29`). Findings that remain are resource-exhaustion, not crypto:

**B1 — Pairing-daemon rate limiter maps grow without bound — High [fact]**
`crates/auths-pairing-daemon/src/rate_limiter.rs:135-152`: five `Mutex<HashMap<...>>` fields (`session_create`, `session_lookup`, `sas_submission`, `other`, `lookup_miss`) keyed by `IpAddr` or session ID. Verified: **zero** occurrences of `retain`/`remove`/`prune`/`evict` in the file. Window state ages logically but entries are never deleted. A botnet cycling unique source IPs grows daemon memory monotonically until OOM — an ironic failure mode for a component whose job is rate limiting. The neighboring `auths-rp` ChallengeStore got this exactly right; the pattern just wasn't reused.

**B2 — API idempotency cache unbounded — Medium [fact]**
`crates/auths-api/src/app.rs:54-56`: `idempotency: Arc<Mutex<HashMap<String, (u64, String)>>>`, documented as best-effort/non-durable but with no size bound or TTL. Every unique `Idempotency-Key` ever seen stays in RAM until restart.

**B3 — Shared-KEL threshold TODO is standing security debt — Medium [fact, known/accepted]**
`crates/auths-id/src/keri/shared_kel.rs:57` — "raise the threshold so compromising one device can't rotate." This is the documented kt=1 duplicity risk (`docs/architecture/multi_device_accepted_risks.md`), accepted deliberately; listed here so the audit trail is complete, not as a surprise.

**B4 — Audit-event serialization failure is silently swallowed — Low [fact]**
`crates/auths-sdk/src/audit.rs:20`: `serde_json::to_string(&event).unwrap_or_default()` emits an empty string to the event sink on failure. Practically unreachable (the struct is locally built with derived `Serialize`), but for a product selling compliance-as-query, the audit path should never have a silent-empty branch.

### C. Testing

**C1 — The relying-party trust boundary is the least-tested security code in the repo — High [fact]**
Test-function counts by crate: `auths-verifier` 331, `auths-keri` 306, `auths-id` 360, `auths-sdk` 319 — versus **`auths-rp` 17** (no `tests/` directory at all) and **`auths-jwt` 10**. `auths-rp` is the wire boundary for agent-passport authentication: nonce replay, audience confusion, expired-challenge, oversized-envelope, and malformed-base64url cases deserve the same adversarial treatment `auths-verifier` gives revocation tampering (`crates/auths-verifier/tests/cases/revocation_adversarial.rs` is the model — 3 tests asserting tampered fields *fail signature verification*). `auths-crypto` at 73 tests is also light for Layer 0. `auths-checkpoint-cosigner` has 5.

**C2 — No cross-language conformance vectors for TypeScript and Python verifiers — Medium [fact]**
Go does this right: `packages/auths-verifier-go/verifier_fixtures_test.go` loads `../../crates/auths-verifier/tests/fixtures/*.json` (presentation_valid, credential_valid, credential_revoked) and asserts verdict parity with Rust. `auths-verifier-ts` and `auths-python` use only inline fixtures — their verification behavior can drift from Rust with no signal. KERI-level interop is covered (40+ keripy fixtures in `crates/auths-keri/tests/fixtures/keripy/`), so the gap is specifically the verifier-verdict layer for TS/Python.

**C3 — Known nondeterminism bugs #252/#253 not explainable from key-state code — Medium [fact + judgment]**
Issues describe a delegate signing with a stale key / `get_public_key` "coin-flip." Static review found KEL replay and `KeyState` use ordered `Vec`s throughout `auths-keri` (`state.rs`, `validate.rs`) — no `HashMap` iteration in key-state paths. The nondeterminism source is therefore likely in event *collection/ordering* upstream (git-ref walk order or witness coordination), not state replay. Unresolved; the issues remain the tracking vehicle. Said plainly: this audit could not reproduce or localize the bug.

**C4 — Minor: 4 crates carry a second integration-test binary — Low [fact]**
`auths-api` (`control_plane_http.rs`), `auths-crypto` (`wasm_provider.rs`), `auths-sdk` (`sign_commit_attestation.rs`), `auths-verifier` (`wasm_bindings.rs`) vs. the single-binary convention in `TESTING.md`. The WASM ones are justified; the other two are link-time waste.

**What's healthy:** adversarial tests for revocation tampering and expiration boundaries (`expiration_skew.rs`: 10 boundary tests including exactly-at-boundary), contract-test macros preventing fake/real backend drift (`auths-test-utils/src/contracts/`), proptest usage, nightly fuzzing of the right targets (attestation JSON, DID parse, verify_chain, policy eval, CESR import — `.github/workflows/fuzz.yml`), no wall-clock in assertions (fixed `verify_at_time` reference times), and honest `xfail` markers referencing issue #219 in the Python suite. Sleeps in tests are few and short (10–200 ms).

### D. Performance

**D1 — N+1 full-KEL replay in fleet/agent listing — High [fact]**
`crates/auths-api/src/control_plane.rs:258-271` (`list_agents`) and `:301-321` (`list_fleet`): inside the per-agent pagination loop, each iteration calls `resolve_member_authority(&state.ctx, &org_prefix, &agent_prefix)` → `collect_kel` (`crates/auths-sdk/src/domains/org/delegation.rs:447-474`), which replays the **entire org KEL** via `visit_events(prefix, 0, ...)`, cloning every event (`delegation.rs:81`). `list_fleet` additionally calls `walk_delegation_chain` per agent (registry lookups per hop, `crates/auths-sdk/src/domains/org/trace.rs:111-152`). A page of 50 agents over a 1,000-event org KEL parses 50,000 events per request; cost is O(page × KEL × chain-depth). The codebase already acknowledges the class of problem in `crates/auths-sdk/src/domains/org/bundle.rs:19-22`. Rated High not Critical only because there are zero production orgs today — it must be fixed before there are.

**D2 — Batch credential verification reloads issuer KEL per credential — Medium [fact]**
`crates/auths-sdk/src/domains/credentials/verify.rs:205-210` (and `issue.rs:361`): `visit_events(prefix, 0, ...)` per call; verifying N credentials from one issuer loads that KEL N times. Same fix shape as D1.

**What's healthy:** no blocking I/O in async paths (the one `std::fs` use in `transparency.rs` is explicitly documented as CLI-context-only at line 217); HTTP clients have 5s timeouts (`crates/auths-infra-http/src/async_witness_client.rs:72-76`) and exponential backoff with Retry-After handling (`github_ssh_keys.rs:142-260`); dev-profile opt-level pinning for argon2/ring keeps tests fast; `auths-verifier`'s dependency tree is verified minimal.

### E. Code quality

**E1 — `Capability` newtype is orphaned while ~45 sites use raw `Vec<String>` — High [fact]**
Defined with validation/canonicalization at `crates/auths-verifier/src/core.rs:970`, imported by only ~3 sites; meanwhile raw `capabilities: Vec<String>` appears across the wire types that matter — `crates/auths-pairing-protocol/src/token.rs:17`, `crates/auths-jwt/src/claims.rs:65`, `crates/auths-scim/src/resource.rs:52`, and ~40 more. Every consumer must remember to call `Capability::parse()`; none are forced to. This is the headline of the 2026-06-08 parse-don't-validate audit and remains unaddressed. Capabilities are the *authorization* primitive — the one place stringly-typed data is most dangerous.

**E2 — 9 of 96 non-test `#[allow(clippy::unwrap_used/expect_used)]` lack the required INVARIANT comment — Medium [fact]**
91% compliance. Gaps: `crates/auths-verifier/src/ffi.rs:270`, module-level allow in `crates/auths-storage/src/git/remote.rs`, `crates/auths-cli/src/commands/org.rs:1260`, and `auths-radicle` (module-level, deprecated crate).

**E3 — FFI configuration-context TODO repeated 7× — Medium [fact]**
`crates/auths-core/src/api/ffi.rs:289,390,443,502,572,654,705` — "TODO: Refactor FFI to accept configuration context." Seven copies of the same debt marker means seven functions hardcoding context that mobile callers can't influence; it also blocks proper FFI testing.

**E4 — Misc dead weight — Low [fact]**
`crates/auths` is a 24-line placeholder facade; `#[allow(dead_code)]` at `crates/auths-storage/src/git/adapter.rs:1083,1090` references helpers "once they land" that haven't; deprecated `Capability::custom()`/`validate_custom()` (`core.rs:1085,1095`) and `c_str_to_str()` await deletion — pre-launch policy says rip them out.

**What's healthy:** 223 `INVARIANT:` comments documenting unsafe assumptions; consistent thiserror taxonomy with stable `AUTHS-Exxxx` codes; the SDK `anyhow` migration CLAUDE.md calls "transitional" is actually **complete** (`crates/auths-sdk/src/error.rs` is clean thiserror; zero `anyhow` in SDK source — the CLAUDE.md note is stale); complex functions cluster exactly where exhaustiveness is a feature (KEL validation).

### F. Dependencies, DevEx & operations

**F1 — Duplicate error code AUTHS-E4801, and the validator that would catch it isn't in CI — High [fact]**
`crates/auths-id/src/keri/resolve.rs:44` (`ResolveError::InvalidFormat`) and `crates/auths-id/src/keri/rotation.rs:71` (`RotationError::Kel`) both map to `"AUTHS-E4801"`. `crates/xtask/src/gen_error_docs.rs` has `validate_unique_codes()` (line 24) but the `xtask-checks` CI job (`ci.yml:64-77`) never invokes it — so the error-docs pipeline is known-broken and `docs/errors/AUTHS-E4801.md` is ambiguous for users. The tool exists; it just isn't gated.

**F2 — `packages/auths-fastapi` missing from version-sync; already drifted — High [fact]**
`scripts/releases/0_versions.py:74-82` covers node/verifier-ts/express/python/mobile-ffi but not fastapi; `packages/auths-fastapi/pyproject.toml:7` reads `version = "0.1.0"` against workspace 0.1.2, and the CI `version-sync` job (`ci.yml:37-43`) is structurally blind to it. Given the v0.1.2 release required six attempts due to exactly this category of latent automation gap, this is a known failure mode recurring.

**F3 — No lockfiles for auths-express, auths-fastapi, auths-verifier-go; no CI for express/fastapi — Medium [fact]**
`packages/auths-express/` has no `package-lock.json`; `auths-fastapi` pins only `fastapi>=0.110` with no lock; the Go module lacks a committed `go.sum`. Neither express nor fastapi has any workflow in `.github/workflows/`. Unreproducible builds + silently-broken releases for the middleware packages most likely to be a user's first touchpoint.

**F4 — Doc corpus describes three eras of the system — Medium [fact]**
Stale SSH/`allowed_signers`-era content presented as current: `docs/OIDC_COMMIT_SIGNING.md`, `docs/design/sigstore-comparison.md` ("allowed_signers are in the repo"), `docs/design/ephemeral-signing-threat-model.md`, `docs/cli/commands/primary.md` (documents an `--allowed-signers` flag), `docs/plans/wiring/*.md` — all predating the June-2026 KEL-native migration that `docs/architecture/identity-model.md` correctly describes. Plus structural sprawl: ~30 top-level `docs/` entries, `docs/essays/` and `docs/proposed-issues/` unindexed by `docs/index.md`, and `login_spec.md` stranded at repo root. The `check-command-drift` xtask scans `README.md` and CLI source but **not** `docs/cli/commands/*.md` (`crates/xtask/src/check_command_drift.rs:122-213`), so CLI docs under `docs/` can rot undetected.

**F5 — CLAUDE.md staleness — Low [fact]**
The "anyhow in SDK errors is transitional" paragraph describes a migration that's done (E-section above); the crate-layer table omits ~10 crates (A3); `TESTING_STRATEGY.md` is referenced but the file is `TESTING.md`.

**What's healthy:** `deny.toml` is excellent (tight license allowlist, per-crate dependency confinement for reqwest/axum/git2, documented advisory exception, unknown-registries denied); toolchain pinning is consistent (1.93 in `rust-toolchain.toml`, `rust-version`, and CI); `justfile` and `CONTRIBUTING.md` are accurate and complete; tracing (not println) throughout server crates with a `/health` endpoint on the API; single, justified git dependency; 774-crate lockfile with unremarkable duplicate-version profile.

---

## Improvement Strategy

### Theme 1: Close the enforcement loop (explains A1, A2, F1, F2, partially E2)
The repo's quality model is *automation as policy* — and it works everywhere it's wired (constant-time, curve-tags, schema drift, command drift). Every place a check exists but isn't gated, drift has already occurred. **Target state:** every check that exists runs in CI and is green; a rule that isn't CI-enforced is treated as not a rule. **Principle:** for a pre-launch team moving this fast, review-time discipline doesn't scale — compile errors and red CI do.

### Theme 2: Bring the newest layer up to the core's standard (explains B1, B2, C1, D1, D2, E1)
The KERI core (keri/verifier/id) got years of rigor; the org control-plane, relying-party transport, and pairing daemon — the newest epics — show the gap: thin tests, unbounded maps, N+1 queries, stringly-typed capabilities. **Target state:** `auths-rp`/`auths-jwt` have adversarial suites matching `revocation_adversarial.rs`; every in-memory map in a server crate is bounded (the ChallengeStore is the house pattern — reuse it); list endpoints load each KEL once. **Principle:** the trust boundary moved outward; the rigor has to move with it.

### Theme 3: The release surface must be fully automated or shrunk (explains F2, F3, C2)
Eight packages in five languages, and the v0.1.2 release needed six attempts. Each package not covered by version-sync + lockfile + CI + conformance vectors is a future failed release or a silent behavioral fork. **Target state:** `0_versions.py` covers every versioned artifact; every package has a lockfile and a CI workflow; TS/Python verifiers consume the same fixture vectors Go does. **Principle:** a package you can't release mechanically is a liability, not a feature — automate it or delete it.

### Theme 4: One era of documentation (explains F4, F5, A3)
**Target state:** `docs/` describes only the KEL-native present; pre-migration design docs are moved to an `archive/` with a banner; `docs/index.md` indexes everything; CLAUDE.md/ARCHITECTURE.md list all 34 crates. **Principle:** stale docs in a security product aren't just confusing — they're claims about guarantees the system no longer makes.

### Explicitly not fixing (and why)
- **kt=1 duplicity / no witnesses / mlock (B3)** — documented accepted risks with a written upgrade path (the shared-KEL threshold TODO at `shared_kel.rs:57` is part of this decision); re-litigating them isn't audit scope. Executors: record the deferral, do not attempt the threshold change.
- **God-file refactors** (`adapter.rs` 4,630 ln etc.) — verified cohesive; splitting them is churn-risk with no payoff now.
- **tokio "full" at workspace level** — fine for this shape; the crates that must stay minimal verifiably are.
- **WASM second test binaries (C4, WASM half)** — justified by runtime differences; the two non-WASM duplicates are fixed by T24.
- **hashbrown/rand duplicate versions in the lockfile** — normal transitive noise, not worth forcing.
- **Windows CI test leg** — `ci.yml:106` TODO; defer until a Windows user exists (build is already checked via `test-windows-build.yml`).

### Definition of done — measurable signals
1. `ci.yml` runs `check-arch.sh` (or xtask port), `check_sdk_boundary.sh`, and `gen-error-docs --check`; all green.
2. `grep -rn "Utc::now()" crates/auths-sdk/src --include=*.rs | grep -v test` → empty; `auths-core`/`auths-id` absent from `crates/auths-cli/Cargo.toml`.
3. Zero duplicate `AUTHS-E` codes (enforced, not just fixed).
4. `auths-rp` ≥ 40 tests incl. replay/audience/expiry/oversize negatives; `auths-jwt` ≥ 25 incl. malformed-claims negatives.
5. `list_fleet` over a 1,000-event KEL performs exactly 1 KEL replay per request (assert via a counting test double on `visit_events`).
6. Every map in `rate_limiter.rs` and the API idempotency cache has a capacity bound with a test, ChallengeStore-style.
7. `0_versions.py --check` covers all 8 packages; express/fastapi/go have committed lockfiles and a CI workflow.
8. TS and Python verifier test suites load `crates/auths-verifier/tests/fixtures/*.json`.
9. `rg -l "allowed_signers" docs/ --glob '!docs/archive/**' --glob '!docs/plans/audit.md' --glob '!docs/architecture/device-model.md' --glob '!docs/architecture/keri-only-roadmap.md'` → empty. (Signal refined during execution: the audit itself quotes the finding; `device-model.md` carries a historical-note banner and is retained as the verified pre-migration record; `keri-only-roadmap.md` is an active, ADR-referenced roadmap whose Epic B documents the migration *off* `allowed_signers` and whose interop item #209 is a live forward reference. Every other non-archive mention was fixed or rephrased — no doc presents `allowed_signers` as part of the current verification model.)
10. auths-crypto has negative tests for wrong-curve, truncated-signature, and bad-seed-length inputs (T23); `crates/auths-sdk/src/audit.rs` has no `unwrap_or_default()` on the emission path (T22).

---

## Task Plan

### Traceability matrix — every finding maps to a task or an explicit deferral

Execution rule: when working a task, mark the corresponding finding(s) closed; a finding with no row here is a process error, not a judgment call. Do not skip rows marked "Accepted risk" — record the deferral, don't attempt the fix.

| Finding | Closed by | Finding | Closed by |
|---|---|---|---|
| A1 check-arch.sh failing + ungated | T3, T6 | C4 duplicate test binaries | T24 (non-WASM); WASM half accepted (see trade-offs) |
| A2 CLI direct core/id deps | T9 | D1 N+1 KEL replay in list endpoints | T11 |
| A3 crate map missing ~10 crates | T20 | D2 batch credential KEL reload | T15 |
| A4 auths-radicle dead weight | T17 | E1 Capability newtype orphaned | T12 |
| B1 rate-limiter unbounded maps | T7 | E2 unannotated unwrap allows | T18 |
| B2 idempotency cache unbounded | T8 | E3 FFI context TODO ×7 | T19 |
| B3 shared-KEL threshold debt | **Accepted risk** (see trade-offs; do not attempt) | E4 dead code / stub crate | T21 + Open Question 2 |
| B4 emit_audit silent swallow | T22 | F1 E4801 dup + ungated validator | T1, T2 |
| C1 rp/jwt undertested (primary) | T4 | F2 fastapi version drift | T5 |
| C1 crypto/cosigner light (secondary) | T23 | F3 missing lockfiles + CI | T14 |
| C2 no TS/Python conformance vectors | T13 | F4 stale/sprawling docs | T16 |
| C3 nondeterministic KEL walk #252/#253 | T10 | F5 CLAUDE.md staleness | T20 |

### Milestone 0 — Safety net (wire the gates before touching code)

| ID | Task | Files/areas | Acceptance | Effort | Risk | Deps |
|----|------|-------------|------------|--------|------|------|
| T1 | Fix duplicate AUTHS-E4801 (closes F1, with T2) | `crates/auths-id/src/keri/rotation.rs:71` (reassign `RotationError::Kel` to a free code), regenerate `docs/errors/` | `cargo run -p xtask -- gen-error-docs` validates clean; both errors have distinct docs | S | Low (pre-launch: no users pinned to codes) | — |
| T2 | Gate gen-error-docs in CI (closes F1, with T1) | `.github/workflows/ci.yml` xtask-checks job | CI fails on any duplicate/undocumented error code | S | Low | T1 |
| T3 | Gate arch + boundary scripts in CI (closes A1, with T6) | `ci.yml`; optionally port `check-arch.sh`/`check_sdk_boundary.sh` into xtask for Windows-friendliness | CI red until T6 lands, then permanently green | S | Low | T6 (or land with `continue-on-error` first, flip after T6) |
| T4 | Adversarial test suites for auths-rp and auths-jwt (closes C1-primary) | new `crates/auths-rp/tests/integration.rs` + `cases/`; `crates/auths-jwt/tests/` | Done-signal #4: replay, wrong-audience, expired, oversize, malformed-b64, claim-type negatives | M | None (test-only) | — |
| T5 | Add fastapi to version sync + bump (closes F2) | `scripts/releases/0_versions.py:74-82`, `packages/auths-fastapi/pyproject.toml:7` | `0_versions.py --check` passes and covers fastapi at 0.1.2 | S | Low | — |

### Milestone 1 — Critical fixes (correctness & resource safety)

| ID | Task | Files/areas | Acceptance | Effort | Risk | Deps |
|----|------|-------------|------------|--------|------|------|
| T6 | Fix the 3 SDK architecture violations (closes A1, with T3) | `oidc_jti_registry.rs`, `workflows/{status,ci/machine_identity}.rs` (inject `clock`); `workflows/{roots,transparency}.rs` (introduce a small `LocalStatePort` trait, impl at CLI layer); `keri/resolver.rs` + `storage.rs` (move concrete Git types behind the existing `RegistryBackend` trait / re-export from auths-storage only) | `check-arch.sh` exits 0; T3 gate flips to enforcing | L | Medium — touches workflow signatures; SDK tests must pass | — |
| T7 | Bound pairing-daemon rate-limiter maps (closes B1) | `crates/auths-pairing-daemon/src/rate_limiter.rs` | Each map: prune-expired-on-insert + hard cap (copy ChallengeStore pattern, `challenge.rs:156-180`); test proves bound under unique-IP flood | S | Low — strictly tightens behavior | — |
| T8 | Bound API idempotency cache (closes B2) | `crates/auths-api/src/app.rs:54-56` | Cap + TTL eviction; test | S | Low | — |
| T9 | Remove auths-core/auths-id from CLI Cargo deps (closes A2) | `crates/auths-cli/Cargo.toml:40-41`; re-export any needed types via auths-sdk | CLI compiles with deps removed; boundary check structurally unnecessary | S–M | Medium — unknown how many type paths need SDK re-exports | — |
| T10 | Localize #252/#253 nondeterministic KEL walk (closes C3) | event collection/ordering in `auths-storage` ref-walk + `auths-sdk` KEL assembly (key-state replay already ruled out — ordered `Vec`s) | Root cause identified; fix or documented repro on the issues | M | Medium | — |

### Milestone 2 — High-leverage improvements

| ID | Task | Files/areas | Acceptance | Effort | Risk | Deps |
|----|------|-------------|------------|--------|------|------|
| T11 | Kill the N+1 KEL replay in list endpoints (closes D1) | `control_plane.rs:258-271,301-321`; `domains/org/delegation.rs` (`resolve_member_authority` accepts a pre-collected `&[Event]` / introduce `OrgKelSnapshot`); `trace.rs` walker reuses it | Done-signal #5: 1 replay per request, counting-double test | M | Medium — verification-adjacent code; behavior must be byte-identical | — |
| T12 | Adopt `Capability` newtype at wire types (closes E1) | `auths-verifier/src/core.rs:970` type; migrate `pairing-protocol/token.rs:17`, `jwt/claims.rs:65`, `scim/resource.rs:52`, + remaining ~40 sites; serde validates-on-deserialize, fail-closed (house style per typed-DID precedent) | `rg 'capabilities: Vec<String>' crates/` → empty; deserialization of invalid caps fails | L | Medium-High — touches wire formats; pre-launch makes it survivable, schemas regenerate | T2 (schema gate) |
| T13 | Conformance vectors for TS + Python verifiers (closes C2) | `packages/auths-verifier-ts/__test__/`, `packages/auths-python/tests/` consume `crates/auths-verifier/tests/fixtures/*.json` (mirror the Go pattern in `verifier_fixtures_test.go`) | Both suites assert verdict parity on valid/revoked/tampered fixtures | M | Low | — |
| T14 | Lockfiles + CI for express/fastapi/go (closes F3) | `packages/auths-express` (package-lock.json), `auths-fastapi` (uv lock), `auths-verifier-go` (go.sum); 2 new workflows modeled on `publish-typescript.yml`/`publish-python.yml` | Lockfiles committed; PRs touching those packages run their tests | M | Low | T5 |
| T15 | Batch credential verification KEL reuse (closes D2) | `domains/credentials/verify.rs:205`, `issue.rs:361` | Issuer KEL loaded once per batch | S–M | Medium | T11 (shares snapshot mechanism) |

### Milestone 3 — Quality & polish

| ID | Task | Files/areas | Acceptance | Effort | Risk | Deps |
|----|------|-------------|------------|--------|------|------|
| T16 | Archive pre-KEL-native docs, index the rest (closes F4) | move SSH-era docs (F4 list) to `docs/archive/` with banner; fix `docs/cli/commands/primary.md`; extend `check_command_drift.rs` to scan `docs/cli/`; index essays/proposed-issues; move `login_spec.md` → `docs/design/` | Done-signal #9; drift check covers docs/cli | M | Low | — |
| T17 | Remove auths-radicle from workspace (closes A4) | root `Cargo.toml:24`, crate dir, `deny.toml:85-86` fork exception | Workspace builds; git dependency count = 0 | S | Low (zero dependents, verified) | — |
| T18 | INVARIANT comments on 9 unannotated allows (closes E2) | `verifier/ffi.rs:270`, `storage/git/remote.rs` (replace module-level allow with per-site), `cli/commands/org.rs:1260` | 100% compliance; optionally an xtask check | S | None | — |
| T19 | FFI configuration-context refactor (closes E3) | `crates/auths-core/src/api/ffi.rs` (7 TODO sites) | Context param threaded; the 7 TODOs deleted; FFI tests added | L | Medium — C ABI change, but pre-launch | — |
| T20 | Update CLAUDE.md / ARCHITECTURE.md (closes A3 + F5) | stale anyhow paragraph, full 34-crate layer table, `TESTING_STRATEGY.md`→`TESTING.md` ref | Docs match verified reality from this audit | S | None | — |
| T21 | Delete deprecated/dead items (closes E4) | `Capability::custom/validate_custom`, `c_str_to_str`, stale `#[allow(dead_code)]` in `adapter.rs:1083,1090`, decide fate of `crates/auths` facade | No `#[deprecated]` items remain (pre-launch policy) | S | Low | T12 |
| T22 | Surface audit-emission serialization failure (closes B4) | `crates/auths-sdk/src/audit.rs:20` | `unwrap_or_default()` replaced — on serialization failure, emit a structured fallback event or log via tracing; no silent-empty branch remains; unit test | S | None | — |
| T23 | Negative-path tests for auths-crypto + baseline for checkpoint-cosigner (closes C1-secondary) | `crates/auths-crypto/tests/cases/`, `crates/auths-checkpoint-cosigner/tests/` | auths-crypto gains wrong-curve, truncated-signature, bad-seed-length, tampered-payload negatives; checkpoint-cosigner ≥ 15 tests covering its signing path | M | None (test-only) | — |
| T24 | Consolidate non-WASM second test binaries (closes C4) | merge `auths-api/tests/control_plane_http.rs` and `auths-sdk/tests/sign_commit_attestation.rs` into each crate's `tests/integration.rs` + `cases/` | each crate links one non-WASM integration binary; `cargo nextest run -p auths-api -p auths-sdk` passes | S | Low | — |

### Quick wins (do immediately — all S effort, high signal)
**T1** (E4801), **T2** (gate error docs), **T5** (fastapi version sync), **T7** (rate-limiter bound), **T8** (idempotency bound), **T17** (drop radicle), **T20** (CLAUDE.md truth-up). Combined: roughly one day, and they eliminate one High-severity DoS vector, two High-severity automation gaps, and a standing source of reviewer confusion.

### Implementation sketches — top 3

**T1+T2 — E4801 + gating.** Pick the next free code in the E48xx range (check `docs/errors/` and grep `AUTHS-E48` across `crates/auths-id`); reassign `RotationError::Kel` at `rotation.rs:71` (rotation is the newer mapping; `ResolveError::InvalidFormat` keeps E4801 so resolve-side docs stay stable). Run `cargo run -p xtask -- gen-error-docs`, commit regenerated `docs/errors/`. Add to `ci.yml` xtask-checks: `cargo run -p xtask -- gen-error-docs --check` (confirm the flag name in `gen_error_docs.rs:21` — check-mode logic exists). Gotcha: error-code tables may also be snapshotted in CLI snapshot tests (`crates/auths-cli/src/commands/snapshots/`) — regenerate with insta if so.

**T6 — SDK arch violations.** Three independent sub-changes; land separately. (1) *Clock:* `oidc_jti_registry`, `status`, `machine_identity` already live where `AuthsContext` (which carries `clock`) is reachable — change signatures to take `now: DateTime<Utc>` per house convention; callers at the CLI/API boundary pass `ctx.clock.now()`. (2) *Filesystem:* `roots.rs`/`transparency.rs` read/write small JSON/text state under `~/.auths` — define one minimal trait (e.g. `LocalStatePort { read(path)->Result<Option<String>>; write(path, &str) }`) in the SDK, std-fs impl in auths-cli (and a memory impl for tests). Don't over-abstract; two methods suffice. (3) *Concrete storage:* `storage.rs:9-10` re-exports move behind a feature or to auths-storage's own public API; `keri/resolver.rs:221,284` is the hard one — it *constructs* `GitRegistryBackend`; invert by accepting `impl RegistryBackend` from the caller. Then flip T3's CI gate from advisory to enforcing. Gotcha: `transparency.rs:572` is in a `#[cfg(test)]` block — the script flags it anyway; either exempt tests in the script or clean it up while there.

**T11 — N+1 KEL replay.** Introduce `OrgKelSnapshot` (collected events + lazily-memoized replay results) in `domains/org/`; collect once per request in `list_agents`/`list_fleet` before the loop; change `resolve_member_authority` to a snapshot method (or accept `&[Event]`), keeping the current single-agent signature as a thin wrapper that self-collects (other call sites unaffected). `walk_delegation_chain` per-hop registry loads should consult the same snapshot for hops within the org KEL, falling back to the registry for external hops. Verify with a test double counting `visit_events` invocations: exactly 1 per request regardless of page size. Gotcha: `list` (`all = list(&state.ctx)`) may *also* replay the KEL — fold it into the same snapshot; and don't cache across requests yet (staleness vs. the registry's mutation model is a separate decision).

---

## Open Questions (need a human decision)

1. **auths-radicle:** confirmed zero dependents — delete now (T17), or is there a strategic reason to keep the fork relationship alive?
2. **`crates/auths` facade:** populate with curated re-exports for a friendly single-crate API, or delete until post-launch?
3. **auths-express / auths-fastapi:** are these launch-critical? If not, consider removing them from the release train (Theme 3: automate or shrink) rather than building CI for them now.
4. **Error-code stability:** is the `AUTHS-Exxxx` registry meant to be frozen at launch (i.e., is reassigning one side of E4801 the *last* free reassignment)? Affects whether T2's gate should also forbid code *changes*, not just duplicates.
5. **Performance target for the fleet API:** is there an expected org scale (events in KEL, agents per org)? T11 is clearly needed; whether to also add cross-request KEL caching depends on a number.
6. **#252/#253 priority:** these are user-visible signing correctness bugs. Should T10 jump ahead of everything in M1? This audit could not localize the root cause statically — it likely needs runtime tracing of event-collection order.
7. **Windows test leg** (`ci.yml:106` TODO): in or out of launch scope?

---

## Review-depth disclosure

Deep review: auths-sdk, auths-verifier, auths-keri, auths-rp, auths-api control plane, auths-pairing-daemon, auths-cli boundaries, CI/xtask, packages/ metadata, docs structure. **Lighter review:** auths-witness, auths-checkpoint-cosigner, auths-monitor, auths-index, auths-telemetry, auths-scim(-server) internals, auths-mobile-ffi internals, `deploy/`, `examples/`, the mkdocs site content beyond staleness sampling. Findings in lightly-reviewed areas (e.g., test counts) are inventory-level, not line-level.
