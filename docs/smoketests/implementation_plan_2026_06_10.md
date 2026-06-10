# Implementation Plan — Golden-Path Fixes (2026-06-10)

Execution companion to `findings_2026_06_10.md` (the rationale; read it first, don't
relitigate its decisions). This file is written so a single session can implement
everything without re-deriving context: entry points are verified `file:line` references,
micro-decisions are resolved, acceptance criteria are keyed to smoke-test step names.

**Ground rules (from CLAUDE.md, non-negotiable):**
- Business logic lands in `auths-sdk`/`auths-core`/`auths-id`, never in `auths-cli`
  command handlers. Several fixes below are tempting to do in the CLI; resist.
- No `Utc::now()` in SDK/core — clock injection.
- Typed `thiserror` errors in SDK/core; CLI wraps with `anyhow::Context`.
- Per-crate compile check: `cargo build -p auths-<crate> --all-features 2>&1 | grep "^error\[E" -A 10`.

**The gate:** `python3 docs/smoketests/end_to_end.py` (after `cargo build -p auths-cli`).
Done = the acceptance column below, plus zero regressions among the 38 currently-passing
steps. Current baseline: 38 pass / 5 fail / 1 skip (`last_run.json`).

---

## Phase 1 — D2: Self-trust in verification

*Do this first: it flips 3 of 5 failures on its own and unblocks local testing of
everything else.*

**Entry points:**
- `crates/auths-sdk/src/workflows/commit_trust.rs` — the SDK commit-trust resolver; the
  verdict "root not pinned" comes from here. Self-trust belongs HERE, not in the CLI.
- `crates/auths-cli/src/commands/verify_helpers.rs:3` — `load_project_pinned_roots()`
  reads `<git-toplevel>/.auths/roots`; the resolver receives that set.
- `crates/auths-cli/src/commands/verify_commit.rs:162-172` — builds pinned roots + bundle
  roots before calling the resolver.
- `crates/auths-cli/src/commands/artifact/verify.rs:489-500` — artifact path; "Failed to
  resolve public key from issuer DID" comes from the issuer-resolution step here / in
  `unified_verify.rs`'s artifact branch.

**Change:** add the local identity's root DID as an implicit trusted root and a KEL
source. Concretely: a new SDK function (e.g. `commit_trust::local_self_root(ctx)`) that
loads the local identity DID from `ctx.identity_storage` (read-only, no passphrase) and
returns it as a trust root whose KEL resolves from the local registry
(`GitRegistryBackend::single_tenant(auths_home)` — the same backend
`verify_commit.rs:139-160` already builds). Both the commit path and the artifact
issuer-resolution path union this root with `.auths/roots` pins. If no local identity
exists, behavior is unchanged.

**Explicitly not:** an env var or flag to disable it. Self-trust is unconditional; it
trusts only keys the verifier itself controls.

**Acceptance (smoke steps flip to PASS):**
- `verify <file> (default sig discovery)`
- `verify <file.auths.json> (direct)`
- `verify <file> (after rotate)`
- `verify HEAD (after auths sign HEAD)` — passes once self-root is trusted, even before D3

## Phase 2 — D1 + D3: Trailers at commit time, auto-pin on first sign

**D1 entry points:**
- `crates/auths-sdk/src/domains/identity/service.rs:379-401` — `set_git_signing_config`,
  the 5-key git config block init writes. The hook install joins this.
- `crates/auths-cli/src/commands/sign.rs:65-110` — `commit_trailer_args` /
  `resolve_signer_trailer`: the exact trailer strings to reuse. Do not invent a second
  trailer format.
- `crates/auths-cli/src/bin/sign.rs` — unchanged; the shim stays a pure signer.

**Resolved micro-decisions:**
- **Mechanism:** global `core.hooksPath = ~/.auths/githooks`, set by init alongside the
  other git config. The directory contains one `prepare-commit-msg` (a small POSIX sh
  script, content owned by the SDK as a string constant, version-stamped in a comment).
- **Chaining:** the hook ends by exec'ing `"$GIT_DIR/hooks/prepare-commit-msg" "$@"` if
  that file is executable — repos with their own hooks keep working. The inverse case
  (repo sets *local* `core.hooksPath`, e.g. husky — git then ignores our global path
  entirely) is detected two ways: `auths doctor` warns per-repo, and the
  no-trailer verify error (verify_commit.rs:572 vicinity) gains one line telling the user
  to add the trailer hook to their hook manager's directory.
- **Trailer values:** the hook must not spawn `auths` (latency, recursion risk). Init —
  and anything that changes the device identity (`device add`, migration) — writes
  `~/.auths/commit-trailers` (the literal two `Auths-Id:`/`Auths-Device:` lines). The hook
  `cat`s it. Missing file → hook exits 0 silently (uninitialized users unaffected).
  Rotation does NOT change these values (root and device DIDs are rotation-stable).
- **Idempotency/amend:** apply with `git interpret-trailers --in-place --if-exists
  replace` so `--amend`, `cherry-pick`, and re-runs never duplicate.
- **`auths sign <ref>` survives** as backfill/repair for pre-hook commits. Its `--help`
  and the docs say exactly that; it stops appearing in any quickstart.

**D3 entry points:**
- `crates/auths-sdk/src/workflows/roots.rs` — `add_pinned_root`, already used by
  `commands/init/mod.rs:378-388` for the stand-in-this-repo-at-init-time case.

**Resolved micro-decisions:**
- The same `prepare-commit-msg` hook, before writing trailers, checks for
  `<git-toplevel>/.auths/roots`; if absent it calls `git rev-parse --show-toplevel`, writes
  the root pin via... no — the hook stays dumb (no auths invocation). Instead: the pin
  content is also static per-identity. Init writes `~/.auths/root-pin` (the JSON fragment
  for this identity); the hook copies it to `.auths/roots` if absent and runs
  `git add .auths/roots`, printing one stderr line:
  `auths: pinned your identity root in .auths/roots (committed with this commit)`.
- **Staging caveat (accepted):** `git commit <pathspec>` and `--only` commits use a
  temporary index; the pin then lands in the *next* commit. Acceptable — D2 covers local
  verification regardless; the pin is for teammates/CI, where one-commit lag is harmless.
- `auths sign <ref>` also ensures the pin (it already has full context; SDK call, not
  hook), covering repos where commits predate the hook.

**Collateral (update in the same PR):**
- `README.md` step 3 — keep `git commit` + `auths verify HEAD`, now true.
- `docs/getting-started/signing-commits.md` — describe hook + shim; remove any
  `auths sign HEAD` step from the happy path.
- Init success copy (`commands/init/display.rs:31-36`) — can now promise verification too.
- `auths doctor` — checks: global hooksPath set, hook file present + current version,
  repo-local hooksPath override warning, `~/.auths/commit-trailers` matches identity.
- Smoke test: `verify HEAD (README path: plain git commit)` is the regression test;
  remove the `note=` excuse on that step.

**Acceptance:**
- `verify HEAD (README path: plain git commit)` → PASS
- New smoke step: amend a commit, verify trailers are not duplicated (`git log -1
  --format=%B | grep -c Auths-Id` == 1) → PASS
- `.auths/roots` exists and is tracked in the demo repo after the first commit.

## Phase 3 — D4 + D5: Transactional init with passphrase preflight

**Entry points:**
- `crates/auths-sdk/src/domains/identity/service.rs:81-115` (`initialize_developer`),
  `:202-254` (`resolve_or_create_identity` / `derive_keys`) — note `derive_keys` calls
  `initialize_registry_identity` THEN `ctx.identity_storage.create_identity` — the
  half-state window.
- `crates/auths-id/src/identity/initialize.rs` — `initialize_registry_identity` (keys +
  KEL inception). Issue #250 (orphaned hardware keys) lives in this family; fix the
  pattern once.
- `crates/auths-core/src/crypto/encryption.rs:55-76` — the strength policy (≥12 chars,
  ≥3 of 4 classes) and the `WeakPassphrase` error (E3020,
  `auths-core/src/error.rs:104`).
- `crates/auths-sdk/src/domains/identity/error.rs` / `SetupError` — where the chain
  currently flattens WeakPassphrase into `StorageError` → E4203.

**Resolved micro-decisions:**
- **Operation order:** (1) preflight — validate passphrase against the policy *before any
  side effect*, as part of the prerequisites step; (2) create keys in keychain, recording
  every alias created this run; (3) stage identity record + KEL events + attestation in
  one `AtomicWriteBatch` (exists: `auths_id::storage::registry::backend::AtomicWriteBatch`,
  already used in `bind_device`, service.rs:320-347); (4) `commit_batch` — the commit
  point; (5) only after durable state: git config, hook install, trailers/root-pin files.
- **Rollback:** on failure after (2), delete the aliases created this run
  (`KeyStorage::delete_key`) best-effort, then return the original error. Expose the
  policy as a public `auths_core` function so init's preflight and the encryption path
  share one implementation.
- **Error surfacing (D5):** `SetupError` gains a typed variant that preserves
  `WeakPassphrase` (E3020) instead of wrapping into storage-error. CLI message names the
  source: "passphrase from AUTHS_PASSPHRASE" when env-sourced vs "entered passphrase",
  and prints the policy line. Delete the generic `fix: Check keychain access and
  passphrase` for this variant. While there: E5007's boilerplate `fix:` line (D7 evidence)
  gets the same treatment — specific message wins, generic line dropped.

**Acceptance:**
- New smoke scenario `init with weak AUTHS_PASSPHRASE`: expects rc≠0, stderr mentions
  `AUTHS-E3020`, `AUTHS_PASSPHRASE`, and "3 of 4"; then `status` in that HOME reports no
  identity and `key list` shows zero aliases. (Today: E4203 + healthy-looking orphan.)

## Phase 4 — Routing & surface polish (independent, any order)

### D7 — init Agent profile routes to delegation
- Entry: `commands/init/mod.rs:443-485` (`run_agent_setup`),
  `commands/init/gather.rs:108-144`, and the working delegation call
  `commands/id/agent.rs:118-145` → `auths_sdk::domains::agents::add_scoped`.
- Interactive: after capability selection, if an identity exists, call `add_scoped`
  (reuse selected capabilities; prompt for label, default `agent`); if none, say so and
  offer the developer flow first. Non-interactive keeps the E5007 guidance error
  (scripted callers should be explicit) — minus its boilerplate fix-line (Phase 3).
- SDK's `initialize_agent` dry-run preview path stays.
- Acceptance: smoke step `init --profile agent --non-interactive (expected to fail)`
  unchanged; manual check of the interactive route (document in PR description).

### D6 — no-hex trust pin; rich whoami
- Entry: `commands/trust.rs:58-74` (`TrustPinCommand`), `commands/whoami.rs`,
  `commands/key.rs:46-68` (`Export`).
- `trust pin --did <did>` alone: resolve the key from the local registry KEL (SDK
  function; the resolver from D2 gives you most of it). `--bundle <file>` accepted as a
  source. `--key <hex>` retained for air-gapped ceremony.
- `whoami --json` adds: `device_did`, `keys: [{alias, curve, public_key_hex}]` (SDK
  workflow returns it; CLI serializes).
- `key export --passphrase` becomes optional → interactive prompt when omitted (CLI
  boundary, `dialoguer`, same pattern as `reset`).
- Acceptance: smoke `trust pin` step un-skips (parse `whoami --json`) and the
  pin → list → show → remove cycle passes.

### D8 — CI env block to stdout
- Entry: `commands/init/display.rs:39-62` (`display_ci_result`) + `ux::format::Output`.
- The delimited env block prints to **stdout**; everything else stays stderr. `--json`
  emits `{"env": {...}}` via the existing `JsonResponse` envelope.
- Acceptance: smoke harness reverts to parsing stdout only for the env block
  (`parse_env_block(last_init.stdout)`) — that *is* the regression test; the
  `sign <file> using printed CI env block` step keeps passing.

### D9 — status counts this device
- Entry: SDK `workflows/status.rs` (`StatusWorkflow`) + the status display in
  `commands/status.rs`.
- Include the local device (derive device DID from the signing key alias, same as
  `derive_device_did` in `domains/identity/service.rs:256-270`). Display
  `Devices: this device (did:key:zDnae…)`; drop the "Link your first device" hint when
  the only device is the current one (suggest `auths pair` under "add another device"
  instead).
- Acceptance: new smoke assertion — `status` output after init does NOT contain
  `Devices:    none`.

### D10 — verify exit codes
- Entry: `commands/verify_commit.rs` `handle_error(…, 2, …)` call sites,
  `commands/artifact/verify.rs:445-448` (`std::process::exit(exit_code)`),
  `commands/unified_verify.rs` dispatch.
- Scheme: 0 = verified · 1 = verification failed (signature/trust verdict) ·
  2 = could not attempt (I/O, malformed input, missing repo). Today's "issuer not
  resolvable" rc=2 becomes rc=1 (it's a trust verdict). Document in `verify --help`
  long_about.
- Acceptance: new smoke assertions on rc per failure class (tamper a signature file →
  rc=1; verify nonexistent path → rc=2).

---

## Sequencing & dependency notes

1. **Phase 1 (D2)** — standalone, highest leverage, do first.
2. **Phase 2 (D1+D3)** — D1 testable locally only after D2; D3's hook copy depends on
   D1's hook existing.
3. **Phase 3 (D4+D5)** — independent of 1–2; touches init internals, so land before or
   after Phase 2, not interleaved.
4. **Phase 4** — independent items; D6 is partially obsoleted by D2/D3 (the pin loop is
   no longer on the golden path) — do it last and resist scope growth.

After each phase: `cargo build -p auths-cli` + run the smoke test; update the expected
pass-count in this file. After all phases: update `findings_2026_06_10.md` header with a
"resolved" stamp, re-run with `--keep` and spot-check a HOME by hand, and wire the smoke
test into CI (`.github/workflows/ci.yml`, new job: build debug CLI → run script →
non-zero exit fails the job).
