# PRD — Auths v0.2: harden the trust core, close the custody gaps, ship the missing surfaces

> **Reader:** a human deciding what Auths builds next, or a recurve loop turning
> these promises into gated claims (`recurve init --from-prd PRD.md`). Every
> requirement below is one sentence on one line, names an observable pass/fail,
> and cites its evidence (file:line or issue #). RFC 2119 keywords set claim
> severity in the ledger; security-relevant sentences arrive review-gated by
> default. Status here is prose — **the gate is the arbiter.**

Scope: the core Rust workspace at `auths/` (github.com/auths-dev/auths),
version 0.1.3, 34 workspace crates plus the `ee/` tier. File paths below are
relative to `auths/`. Issue numbers refer to that repo's tracker.

---

## 0 · Product context (what is true today)

Auths is decentralized cryptographic identity and signing for software supply
chains and AI agents: no CA, no server — a `did:keri` identity whose key
events live as Git refs, with keys in the OS keychain, devices joined by
signed KERI delegation, and verification available from a CLI, a WASM widget,
and native SDK bindings in six languages. Its users are developers signing
commits and releases, CI pipelines doing keyless deploys, AI agents holding
delegated sub-identities with capability caps, and relying parties verifying
`Auths-Presentation` headers instead of bearer keys.

The engineering baseline is unusually strong, and this PRD builds on it
rather than restating it: exact-pinned crypto dependencies with cross-provider
known-answer gating, workspace-wide clippy denial of `unwrap`/`expect`/`exit`,
Argon2id at OWASP parameters with per-blob parameter embedding, zeroize-on-drop
sealed secret types, CSPRNG-only randomness with lint-enforced bans, an xtask
scanner banning non-constant-time compares on secrets, and ~5,500 tests with
keripy cross-implementation conformance vectors.

The gaps concentrate in four places, and they define this document:

1. **Trust-core soundness** — local KEL replay trusts storage without
   re-verifying controller signatures; presentations carry no replay
   protection; malleable signature encodings are accepted; duplicity
   detection is fail-open and usually sees only one view.
2. **Custody lifecycle** — revocation checks skip raw-seed and hardware
   keys; the agent's unlock window signs for any same-user process; there is
   no recovery story past a single device.
3. **Broken and stubbed routes** — pairing join calls a removed route, the
   Python SDK roundtrip fails, Postgres and GitLab are stubs, Windows agent
   status is hardwired false.
4. **Missing product surfaces** — no independent transparency-log server, no
   verifiable-map lookup, no pairwise identifiers or selective disclosure,
   an API server that is only a health check.

## 1 · Goals

- A tampered artifact, KEL, or attestation fails verification with a named
  error on every path — CLI, SDK, WASM — with zero fail-open defaults left
  undocumented.
- Key custody has a full lifecycle: creation without orphans, revocation
  checked for every key type, recovery that survives total device loss.
- Every shipped command works on every supported platform, or states that it
  does not; zero silently-skipped test suites.
- The trust infrastructure a third party needs — transparency log, witness
  rotation, release proofs — exists as running open-source code, not roadmap.
- A post-quantum rotation path exists end to end behind a feature flag.

## 2 · Personas and user stories

**Dana, solo developer.** As a developer, I want `auths init` → `sign` →
`verify` to work in under a minute and never wedge on a hardware prompt, so
that signing stays cheaper than skipping it. (Covered by: BG-4, UX-2, UX-3,
KL-5.)

**Priya, org security lead.** As a security lead, I want revoked keys and
split-view identities to fail verification everywhere, so that my audit story
does not depend on which client checked. (Covered by: KL-1, CR-1, CR-4, VF-3,
VF-5.)

**An AI agent operator.** As an agent operator, I want each signature tied to
an authenticated request from the right process, so that a compromised
neighbor process on the same box gets nothing from the unlock window.
(Covered by: KL-2, CR-2.)

**A relying party.** As a relying party, I want to verify a presentation
offline in single-digit milliseconds against an independently-auditable log,
so that adopting Auths removes a server dependency instead of adding one.
(Covered by: VF-7, TL-1, TL-2, FT-4.)

---

## 3 · CR — Cryptographic core

The primitives are sound; the composition has holes an adversary aims at:
storage tampering, replay, malleability, split-view. These claims close them.

- CR-1: Local KEL replay must re-verify controller signatures on every event, so a stored event whose bytes were altered after ingestion fails replay with a named error (auths-keri/src/validate.rs:506,1244; #263).
- CR-2: Presentation verification must bind each envelope to a verifier-supplied nonce and audience, and a replayed envelope reusing a spent nonce must be refused (auths-verifier/src/verify.rs:27,281).
- CR-3: Signature checks must reject malleable encodings: ECDSA P-256 high-S values and Ed25519 non-strict forms are refused on native and WASM paths alike (Cargo.toml:25, auths-keri/src/keys.rs:319, auths-verifier/src/software_verify.rs:54).
- CR-4: Default verification must obtain a second independent KEL view (witness receipt or transparency log) so a split-view of one prefix is detected rather than warned past (#349).
- CR-5: Release binaries must fail to compile when the test-utils feature is in the feature graph, keeping the weak Argon2 test parameters (m=8 KiB, t=1) out of shipping builds (auths-core/src/crypto/encryption.rs:63).
- CR-6: Crypto call paths must be panic-free by type: the production expect() sites become typed errors or infallible constructions (auths-crypto/src/key_ops.rs:280, auths-crypto/src/signer.rs:39).
- CR-7: docs/security/primitive-inventory.md must exist, list every primitive with its pinned version, and be diffed against Cargo.lock in CI so the inventory cannot drift (SECURITY.md:7 references it; the file is absent).
- CR-8: The constant-time comparison gate must hold a measured separation margin of at least 10x across three consecutive CI runs, replacing today's thin margin near the control floor (#353).
- CR-9: Agent-held private keys should live in mlock'd non-swappable memory during the unlock window, retiring the documented accepted-risk entry in SECURITY.md.

## 4 · KL — Key lifecycle and custody

A signing product is its custody story. Today the gate that checks revocation
sees only keychain-resident keys, the agent trusts every same-user process,
and losing one device can mean losing the identity. Membership changes are
also tiered by volume: human device links ride establishment-grade rotation
events (superseding-recovery protection), while agent fleets join through
delegated inception or anchored interactions, so onboarding at scale never
burns the root's pre-rotation chain. The full custody architecture is three
layers, following the KERI org-identity design (keripy discussion 602) and
the measured scale data in tests/scale: a small control plane of
weighted-threshold officer and recovery keys governs the org root (KL-10 to
KL-12); human members and devices join as delegated identities with
rotation-grade membership (KL-8); agent and workflow fleets join behind
cohort anchors and, at the largest sizes, registrar shards (KL-9, KL-13).

- KL-1: The producer signing gate must check revocation and rotation state for raw-seed (Direct) and hardware or enclave-backed keys, and signing with a revoked key of any custody type must fail with a distinct error (#355).
- KL-2: The signing agent must require per-signature re-authentication or a process-bound capability, so a different same-user process requesting a signature during an unlock window is refused and audit-logged (#354).
- KL-3: Artifact signing must resolve the issuer key explicitly for multi-key identities, and an ambiguous resolution must abort naming the candidate keys instead of falling back to device_key (#352).
- KL-4: Inception must never orphan hardware keys: the git-direct initialize_keri_identity either binds every created hardware key into the KEL or deletes it on rollback (#250).
- KL-5: auths init must offer a recovery device during setup and record an explicit single-device-lockout acknowledgment in the audit log when the user declines (#321).
- KL-6: Guardian recovery must restore control after total device loss through an M-of-N guardian quorum, and any set of fewer than M guardian approvals must never rotate the identity (#278; mechanism per KL-10 split authority, keripy discussion 602).
- KL-7: Custody claims must be provable: enclave-backed keys carry a hardware attestation root (App Attest / Android Key Attestation), and a software key presenting an enclave custody claim fails verification (#277).
- KL-8: Human device membership must change through establishment events: link, unlink, and update land as rotations on the account KEL, and a membership change carried only by an interaction event fails verification for human identities.
- KL-9: Agent onboarding must not consume the root's pre-rotation chain: high-volume agent identities join through delegated inception or anchored interaction events, and provisioning 10k agents appends zero rotation events to the org root KEL (#255).
- KL-10: The org root must separate signing authority from rotation authority: officer keys sign routine events while a distinct quorum holds rotation, and a signing-only key that attempts a root rotation must be refused (#202; keripy discussion 602).
- KL-11: Root rotation must support weighted and nested thresholds so personnel changes rotate keys without changing the org identifier, and a rotation signed below threshold must be refused (#202; keripy discussion 602).
- KL-12: Removing a member from a multi-sig group must be a rotation that excludes their key, and the removed key's signature on any later group event must fail verification (keripy discussion 602).
- KL-13: Fleet enrollment should shard across delegated registrar identities, each appending cohort anchors to its own KEL in parallel, so the org root gains one event per registrar and no single KEL becomes the write bottleneck.
- KL-14: A KEL approaching 1,024 events should roll over to a new delegated identity so append and replay stay flat; the measured length-degradation curve lives in tests/scale/REPORT.md.

## 5 · VF — Verification surface

Verification is the product's public face: it runs in strangers' CI, browsers,
and gateways. Every path needs the same answer to the same evidence, and the
whole surface needs to fail closed on tampered input.

- VF-1: The verifier must accept kt>1 delegated devices: a 2-of-3 indexed signature set at threshold verifies, and a below-threshold 1-of-3 set is rejected (#207).
- VF-2: Artifact verification must be KEL-native like commit verification: the signer resolves through the KEL at signing time, and a signature from a rotated-away key fails (#206).
- VF-3: auths trust pin and auths verify must share one trust store, so a pin written by either surface is honored by both (#210).
- VF-4: A read-only auths kel validate command must check the local KEL and exit nonzero on stale encodings or broken chains, so identities stop failing silently at sign time (#211).
- VF-5: Every untrusted KEL transport must carry signatures on the wire: --oobi fetches, --remote stranger resolution, and the WASM device-link, credential, and presentation entry points refuse unsigned KEL bytes (#262).
- VF-6: The verifier-ts suite must execute the WASM build in CI and fail the job when the module cannot load, ending the silent jest skip (#249).
- VF-7: A lean verify build must finish a warm deep-chain verification in under 10 ms by dropping the enclave-framework linkage from the verify-only path (#272).
- VF-8: auths verify must support --require-rooted-signer so a bare did:key self-attestation is refused where policy demands a KERI-rooted identity (PR #324).
- VF-9: KEL validation must verify asymmetric key-count rotations through dual-index CESR signatures per SPEC Epic B, instead of rejecting every prior next-count mismatch (SPEC.md:126).
- VF-10: auths verify must implement documented distinct exit codes — 0 verified, 1 invalid signature, 2 unsigned, 3 policy refusal — each covered by an e2e test (tests/e2e/GAPS.md).

## 6 · PQ — Post-quantum readiness and crypto agility

Harvest-now-decrypt-later does not threaten signatures, but a KERI identity
is a long-lived commitment chain: the pre-rotation digest committed today is
the key that signs in 2032. Agility work is cheap now and impossible later.

- PQ-1: Curve-specific code must stay behind the CryptoProvider trait: the existing xtask curve-agnostic check (AST-level, check-curve-agnostic) must report zero direct ed25519-dalek or p256 imports outside auths-crypto and the WASM verify leaf (#285).
- PQ-2: auths-keri must define CESR derivation codes for ML-DSA-65 public keys and signatures so a post-quantum rotation target is expressible in a KEL event (#276).
- PQ-3: auths-crypto must ship an ML-DSA-65 signer behind a pq feature, validated by known-answer tests from the FIPS 204 vectors (#276).
- PQ-4: A KERI rotation from an Ed25519 root to ML-DSA keys must round-trip in an integration test, with later events verifying under the new key type.
- PQ-5: The pq-hybrid pairing feature should pin ml-kem exactly and state its unaudited status in the feature docs until an audited release exists.

## 7 · TL — Transparency and supply chain

Auths asks strangers to trust its evidence; the evidence chain has to be
independently checkable, starting with Auths' own releases and commits.

- TL-1: An open-source transparency-log server must implement the /v1/log/* endpoints so outside parties run an independent log, proven by a conformance suite against auths-transparency (#322).
- TL-2: Release attestations must carry a Rekor inclusion proof that auths verify --release checks offline against a pinned log key (#300).
- TL-3: Release signing must resolve to the org root: an ephemeral-only chain is refused for release artifacts, closing the chain-resolution shortcut (#302).
- TL-4: Every monorepo commit must carry Auths trailers that verify with the shipped toolchain, enforced by the verify-commits workflow on push (#259).
- TL-5: rmcp must move past RUSTSEC-2026-0189 (DNS rebinding, 8.8 high) and the matching ignore entry must leave .cargo/audit.toml (#362).
- TL-6: cargo deny and cargo audit must pass in CI with at most two accepted advisories, each ignore annotated with a written rationale and an expiry date.
- TL-7: Witness key rotation must exist in code (rct rot with CT re-pin), and receipts signed after rotation must fail against the pre-rotation witness key (#241).

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

- FT-1: Key-state lookup should ride a verifiable map (CONIKS-style) so current-key resolution costs an O(log n) proof instead of a full KEL replay (#268).
- FT-2: Credential rails should offer pairwise per-relying-party identifiers so two verifiers cannot correlate one holder by root AID and registry (#273).
- FT-3: Credentials should support selective disclosure: a holder reveals chosen fields under predicate proofs while issuer signatures still verify (#275).
- FT-4: An independent verifier must resolve a foreign issuer's live credential revocation state through a documented propagation surface (#274).
- FT-5: Cross-org introduction should run live: org B's gateway honors a scoped A-to-B introduction, proven by a two-gateway runtime test (#279).
- FT-6: The auth-server must persist sessions and OIDC clients in Postgres so a process restart preserves active sessions (#319).
- FT-7: Client registration must enforce the oidc:client:register capability again, refusing tokens that lack it (#318).
- FT-8: The single-org self-host Postgres registry backend should implement every port-trait method end to end for one org per instance, with no cross-tenant isolation layer, retiring the NotImplemented stubs (auths-storage/src/postgres/adapter.rs:46; decision 4 in section 13).
- FT-13: The existing witness-independence gate (spans_distinct over org/jurisdiction/infra) must also gate the KEL verdict, not only the CT-bundle path, so a KEL lacking an independent witness receipt verifies locally but fails an outside-view check (decision 4; ties CR-4, TL-7).
- FT-9: auths-api should mount the org control-plane routes promised in ARCHITECTURE.md layer 6, growing past the lone health check (crates/auths-api/src/lib.rs:1).
- FT-10: The auths facade crate should re-export the supported SDK surface so a library consumer depends on one crate name (crates/auths/src/lib.rs).
- FT-11: auths could export a KEL-derived allowed_signers file so plain git and ssh verify signatures on machines without auths installed (#209).
- FT-12: auths pair --offline could complete a pairing over KERI delegation with no network path, covered by an e2e test (#203).

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

---

## 12 · Non-goals (out of scope for this PRD)

- Witness-commons operator recruitment and SLA accounting (#235, #242) —
  organizational work, not gateable code.
- Full bidirectional X.509 bridge (#270) and SAML XML-DSig backend (#244).
- Epic F deferrals: IPEX grant/admit choreography, backed registries,
  dynamic schema registry, ACDC edge/rule content (#221–#229).
- Murmur/Sasayaki messenger features beyond the crate rename.
- Mobile app feature work beyond keeping the FFI crates building.
- New marketing or dashboard work in sibling repos; this PRD binds `auths/`
  only.

## 13 · Open decisions (adjudication material)

One human sentence each; the answer gets baked into the relevant probe.

1. Duplicity default: does v0.2 flip the verify verdict for a diverging KEL
   from warn to refuse (today: documented fail-open,
   auths-verifier/src/verify.rs:1)? CR-4 is written to detect either way;
   the default verdict is a policy call.
2. Per-signature re-auth (KL-2): biometric prompt per signature, or a
   process-bound capability token with a bounded lifetime — and if the
   latter, how many seconds?
3. PQ scheme order (PQ-2/3): ML-DSA-65 first, or SLH-DSA for the root and
   ML-DSA for devices?
4. Postgres registry target (FT-8): multi-tenant SaaS control plane, or
   single-org self-host? The schema and tenancy model diverge.
   **DECIDED (2026-07-04): single-org self-host.** One instance = one org;
   no cross-tenant isolation walls, no shared-infra "trust Auths the company"
   posture — this keeps the no-central-authority promise. Trust and
   availability beyond the org boundary come from opting into witnesses, not
   from a shared control plane. The witness opt-in exposes an independence
   ladder: (a) own witnesses (availability only), (b) shared witness commons
   (independent second view — this is what makes CR-4 duplicity detection
   real), (c) mutual org-to-org witnessing (federation). This settles the
   storage/tenancy fork; it does NOT settle decision 1 (the duplicity
   warn→refuse default), which stays open.
5. Pairwise identifiers (FT-2): default-on for new credentials, or opt-in
   flag at issuance?
6. Verifiable map operation (FT-1): run by the witness commons, or shipped
   as self-host-only alongside the transparency log (TL-1)?
7. Recovery custody (KL-6): are guardians other devices of the same user,
   other people, or both?

## 14 · Probe and trap conventions

For the recurve loop that consumes this document:

- A probe runs one focused check — a `cargo test -p <crate> <case>` filter,
  or a CLI invocation inside a hermetic `AUTHS_HOME` temp dir — and maps
  exit 0 to GREEN, 1 to RED, anything else BROKEN.
- Every probe keeps a trap fixture proving it knows how to fail: a KEL event
  with one flipped byte (CR-1), a high-S ECDSA signature (CR-3), a replayed
  presentation envelope (CR-2), a revoked raw-seed key that still signs
  (KL-1), an unsigned KEL blob on an untrusted transport (VF-5), a 1-of-3
  signature set (VF-1).
- Claims citing an issue number quote the issue's reproduction as the trap
  where one exists.
- Anything touching signing, verification, custody, or the trust store stays
  review-gated: a green gate is necessary, not sufficient, and a human signs
  off per the review protocol.

## 15 · Success metrics

- `cargo audit` and `cargo deny check` green with at most 2 time-boxed
  ignore entries (today: 8 ignored advisories across deny.toml and
  .cargo/audit.toml).
- Zero silently-skipped test suites: the WASM verifier tests, the 3 disabled
  auth-server tests, and the 3 skipped e2e scenarios all execute in CI.
- Warm deep-chain verification p50 under 10 ms in the lean build (today:
  6–16 ms process-startup floor before verification begins).
- 100% of monorepo commits on main carrying trailers that
  `auths verify` accepts (today: partial rollout, #259).
- Every BG claim GREEN — all seven known broken routes repaired with
  regression traps in place.
- Zero requirement lines in this PRD parked as un-probeable at baseline:
  each names its observable and its counterexample up front.

## 16 · Suggested suite map

One recurve suite per theme keeps the burndown legible and lets triage weigh
security claims against product claims explicitly:

| Suite | Sections | Character |
| --- | --- | --- |
| `trust-core` | CR, KL, VF | review-gated, adversarial traps mandatory |
| `supply-chain` | TL, PQ | infrastructure + agility, conformance-style probes |
| `repairs` | BG, UX | reproduction-driven, cheapest wins first |
| `expansion` | FT | new surfaces, e2e probes |
| `hygiene` | EH | drift guards, grep/architecture-test probes |

Severity inside each suite follows the requirement keyword; the triage loop
orders by severity, then unlock value. The BOOT scaffolding claims that
`recurve init` adds in front of these handle harness, build, and probe-run
bootstrapping — nothing here depends on them being restated.
