# PRD (mechanical) — endless-burndown-safe claims

> **Run mode: endless.** These claims have deterministic oracles and low
> blast radius — docs, CI/build guards, dependency bumps, dead-code
> removal, output formatting, read-only diagnostics, repro-backed bugfixes,
> tests, and renames. None require a policy decision or change
> crypto/verification *logic*. Safe for `/recurve-work` run-until-complete.
> The deliberation-required half is PRD-hard.md. Claim IDs are stable across
> both files; a cross-reference (e.g. a bugfix that cites CR-4) can point into
> the other file. Source of record: PRD.md.

## 3 · CR — Cryptographic core
The primitives are sound; the composition has holes an adversary aims at:
storage tampering, replay, malleability, split-view. These claims close them.

- CR-5: Release binaries must fail to compile when the test-utils feature is in the feature graph, keeping the weak Argon2 test parameters (m=8 KiB, t=1) out of shipping builds (auths-core/src/crypto/encryption.rs:63).
- CR-7: docs/security/primitive-inventory.md must exist, list every primitive with its pinned version, and be diffed against Cargo.lock in CI so the inventory cannot drift (SECURITY.md:7 references it; the file is absent).

## 5 · VF — Verification surface
Verification is the product's public face: it runs in strangers' CI, browsers,
and gateways. Every path needs the same answer to the same evidence, and the
whole surface needs to fail closed on tampered input.

- VF-4: A read-only auths kel validate command must check the local KEL and exit nonzero on stale encodings or broken chains, so identities stop failing silently at sign time (#211).
- VF-6: The verifier-ts suite must execute the WASM build in CI and fail the job when the module cannot load, ending the silent jest skip (#249).
- VF-10: auths verify must implement documented distinct exit codes — 0 verified, 1 invalid signature, 2 unsigned, 3 policy refusal — each covered by an e2e test (tests/e2e/GAPS.md).

## 6 · PQ — Post-quantum readiness and crypto agility
Harvest-now-decrypt-later does not threaten signatures, but a KERI identity
is a long-lived commitment chain: the pre-rotation digest committed today is
the key that signs in 2032. Agility work is cheap now and impossible later.

- PQ-1: Curve-specific code must stay behind the CryptoProvider trait: the existing xtask curve-agnostic check (AST-level, check-curve-agnostic) must report zero direct ed25519-dalek or p256 imports outside auths-crypto and the WASM verify leaf (#285).
- PQ-5: The pq-hybrid pairing feature should pin ml-kem exactly and state its unaudited status in the feature docs until an audited release exists.

## 7 · TL — Transparency and supply chain
Auths asks strangers to trust its evidence; the evidence chain has to be
independently checkable, starting with Auths' own releases and commits.

- TL-4: Every monorepo commit must carry Auths trailers that verify with the shipped toolchain, enforced by the verify-commits workflow on push (#259).
- TL-5: rmcp must move past RUSTSEC-2026-0189 (DNS rebinding, 8.8 high) and the matching ignore entry must leave .cargo/audit.toml (#362).
- TL-6: cargo deny and cargo audit must pass in CI with at most two accepted advisories, each ignore annotated with a written rationale and an expiry date.

## 8 · BG — Known broken routes
Each of these is a user-visible defect with a reproduction on file. They are
the cheapest trust repairs in this document.

- BG-1: Pairing join must work end to end: clients call the daemon's /lookup route, the dead by-code path is deleted from CLI, SDK, and both bindings, and an e2e pairing test passes (#219).
- BG-2: The LAN pairing server must stay up through the exchange: the cancel()-before-wait defect is fixed and a device pairs over LAN in the e2e suite (#194).
- BG-3: The Python SDK raw-seed sign_action to verify_action_envelope roundtrip must pass, with a regression test pinning the repaired signature path (#258).
- BG-4: Signing must never hang without feedback: a pending hardware prompt prints a waiting notice within 2 seconds, and a configurable timeout aborts with a named error (#266).
- BG-6: The GitHub SSH-key metadata check must perform its real comparison instead of returning the placeholder value (auths-infra-http/src/github_ssh_keys.rs:203).
- BG-7: auths status must report agent liveness on Windows by implementing is_process_running there, instead of returning false unconditionally (auths-cli/src/commands/status.rs:569).

## 9 · UX — Product experience
The golden path is genuinely 30 seconds; the paths beside it drop into
undocumented behavior. Machine consumers (CI, agents) are first-class users
here and need structured output everywhere a human gets prose.

- UX-1: auths init, status, and the device subcommands must accept --json and emit a documented schema so CI pipelines can parse their output (tests/e2e/GAPS.md).
- UX-2: A second auths init on an existing identity must exit 0 as a stated no-op, and re-initialization must demand an explicit --force flag (tests/e2e/GAPS.md).
- UX-3: auths doctor must print which identity home won — AUTHS_HOME, config file, or default — and why, ending the resolution confusion reported in #266.
- UX-4: docs/releases/AGENT_RUNBOOK.md must walk every release step with expected output, sized so an agent cuts a release without human diagnosis (#261).
- UX-5: auths init should verify GitLab accounts the way GitHub is verified today, replacing the coming-soon stub (auths-cli/src/commands/init/prompts.rs:147).
- UX-6: auths doctor must warn when a repo with verification enabled lacks the commit-trailer hook, naming the file to install (#266).

## 10 · FT — New product surfaces
Ordered by leverage: each unlocks a user class that today has no path at all.

- FT-10: The auths facade crate should re-export the supported SDK surface so a library consumer depends on one crate name (crates/auths/src/lib.rs).
- FT-11: auths could export a KEL-derived allowed_signers file so plain git and ssh verify signatures on machines without auths installed (#209).

## 11 · EH — Engineering hygiene
Drift between documentation, dead code, and reality is where unattended agent
loops go wrong; these claims keep the map matching the territory.

- EH-1: Domain logic must live in shared SDK services rather than the CLI and agent front doors, enforced by an architecture test banning domain imports in adapter layers (#350).
- EH-2: StatusWorkflow::query must either power the real status command or be deleted; a dead placeholder cannot stay in the public SDK (auths-sdk/src/workflows/status.rs:32).
- EH-3: ARCHITECTURE.md must describe only crates that exist: the auths-registry-server, auths-auth-server, and auths-cache sections get rewritten to match the workspace.
- EH-4: CI must run the exact pre-commit check set so a commit passing local hooks cannot fail CI on format or lint drift (#193).
- EH-5: The three disabled auth-server integration tests must be rewritten against the current attestation model and re-enabled (#320).
- EH-6: Stale crypto docs should be corrected: the CNSA TODO note (auths-crypto/src/provider.rs:531) and the superseded auths-keri/docs/spec_compliance_audit.md get updated or deleted.
- EH-7: The skipped e2e scenarios — OIDC token exchange, expired attestation, emergency freeze — must run in CI once the harness gains chain setup and time control (tests/e2e/GAPS.md).
- EH-8: The murmur crates should be renamed sasayaki ahead of crates.io publication, keeping the app name Murmur (#286).
