# Roadmap — device-bound, KERI-verifiable software-supply-chain identity

**Status:** Active roadmap (2026-06-02). Companion to `device-model.md`. Goal-driven: every epic is
graded against the product thesis, not against KERI purity in the abstract.

## North star

**Solve software-supply-chain security with device-bound signatures, using KERI.** A developer (and
later an AI agent, and later a layperson) signs commits and artifacts with a key that is **bound to a
specific device**, and **any third party** — CI, a package registry, a downstream consumer — can
verify that the signing device was authorized by that identity *at signing time*, with **no central CA
or transparency log to trust**. The bet: this becomes the de-facto developer identity, then extends to
AI agents (delegated identities) and laypeople (recoverable multi-device identities).

## The one principle that defines "done"

> **Every trust decision is made by replaying a KEL, performed by a party who never met the signer.**

Device-bound signatures only mean something if the binding lives in the identity's **verifiable
key-state** (not in an issuer-signed allowlist), and third parties can **obtain and trust** that
key-state. Each epic below moves a trust decision onto KEL replay.

## Where we are (verified, with anchors)

**Assets already built (the hard, expensive parts):**
- A real KERI KEL — `icp`/`rot`/`ixn`/`dip`/`drt` (`auths-keri/src/events.rs:790`), SAID + CESR
  encoding **byte-identical to keripy 1.3.4**, threshold logic, pre-rotation commitments.
- KEL-rooted identity: `did:keri:` *is* a KEL prefix. Replay/validation: `validate_kel`
  (`validate.rs:339`), `validate_kel_with_lookup` (`:347`), `replay_kel` (`:787`),
  `validate_signed_event` (`:963`), `KeyState` (`state.rs:18`).
- Shared-KEL controller model (devices as controllers): `shared_kel.rs` — `ControllerDescriptor`,
  `rot_add_controller`, `rot_remove_controller`, `rot_swap_controller`, `resolve_controller_index`
  (`:185`). Built and unit-tested, **zero callers**.
- True shrink-`k` removal: dual-index CESR signatures + binding validator +
  `rotate_registry_identity_multi(.., remove_indices)` — built, tested, keripy-verified.
- Per-device KELs (`device_kel.rs`); delegated-identity events `dip`/`drt` (`events.rs:632`).
- Witness agreement algorithm: KAWA, M-of-N receipt collection (`witness/agreement.rs`); provider
  traits (`witness/provider.rs:36`, `witness/async_provider.rs:68`); `Receipt` (`witness/receipt.rs`).
- KEL-from-git-refs resolution + replay logic exists in `auths-radicle/src/identity.rs:538`
  (`resolve_kel` / `resolve_keri_state`). **`auths-radicle` is being deprecated — do not depend on it;
  lift the generic git2 read-refs→validate→replay logic into auths proper.**

**Trust shortcuts shipped in place of the above (what this roadmap replaces):**
- Device binding = issuer-signed **attestation** (`device/service.rs:70` `link_device` →
  `create_signed_attestation`; pairing `pairing/mod.rs:384`), not a KEL controller.
- Commit trust = SSH **`allowed_signers`** allowlist (`verify_commit.rs:29`), generated *from
  attestations* (`allowed_signers.rs:363` `sync` → `load_all_attestations:382`).
- Commits carry **no identity** — the signer is just an SSH key; nothing records which KEL it belongs
  to (`commands/sign.rs`, `bin/sign.rs` write no `did:` trailer).
- Org/agent delegation rides on attestation `delegated_by` (`org/service.rs:376`), not `dip`/`drt`.

**Missing entirely:** KEL-native verification path; native remote KEL distribution; a real witness
service; ACDC/TEL credential layer.

| Capability | Today | Goal-native target | Status |
|---|---|---|---|
| Identity / rotation / anchoring | KEL `icp`/`rot`/`ixn` | same | ✅ done |
| Device membership | attestation | delegated identifier (`dip`, root-anchored) | primitives built, **unwired** (Epic A) |
| Device removal | error / attestation flag | shrink-`k` rotation | core built, **unwired** (Epic A) |
| Commit/artifact trust | `allowed_signers` allowlist | KEL replay → key authorized? | ❌ (Epic B) |
| Signer identity on a commit | none (bare SSH key) | `did:keri` in-band | ❌ (Epic B) |
| Third-party gets the KEL | trust-on-first-sight / bundle | native git-remote fetch + OOBI | ❌ (Epic C) |
| Duplicity / ordering | local first-seen | witness receipts (KAWA) | algorithm built, **no service** (Epic D) |
| Agent identity | attestation `delegated_by` | delegated KEL (`dip`/`drt`) | events built, **unwired** (Epic E) |
| Capabilities / roles / OIDC | attestation fields | ACDC + TEL | ❌ deferred (Epic F) |

## Critical path

```
Epic A (delegated devices) ─┐
                       ├─► MVP: device-bound, KEL-verifiable signing (KEL via bundle/local refs)
Epic B (KEL-native verify) ─┘        │  honest caveat: ordering = trust-on-first-sight until Epic D
                                     ▼
                  Epic C (native remote KEL distribution)  ─► verifiable by strangers at scale
                                     ▼
                  Epic D (witness receipting + duplicity)  ─► no trust-on-first-sight (high assurance)
                                     ▼
            Epic E (agent delegation)        Epic F (ACDC/TEL — only if credentials are promised)
```

**MVP cut line:** Epics **A + B** + a KEL source for the verifier (the existing `--identity-bundle`,
or Epic **C1** local/remote git fetch). Ships a genuinely device-bound, KEL-verifiable signing story.
**State the caveat in the product:** until Epic D, ordering/duplicity is trust-on-first-sight (the
documented `kt=1` risk).

---

## Epic A — KEL-native device membership

> **⚠️ Re-grounded 2026-06-03 → delegation (Model D).** A design pass found that one device cannot
> author a keripy-valid `rot` of a multi-device `k[]` — it can't reveal the *other* devices'
> pre-committed next keys (the old `rotate_registry_identity_multi` only "works" by assuming one host
> holds every key). So devices are now **KERI delegated identifiers**: each device runs its own KEL
> (`dip`/`drt`), and the root **anchors** the delegation via an `ixn` (add) or a revocation (remove) —
> single-author, keripy-valid, no pre-rotation reveal, no other device's key. This also **unifies
> devices with agents** (Epic E is the same `dip`/`drt` mechanism). The `k[]`/shrink-rotation task
> detail below is superseded; authoritative design + re-scoped tasks: `device-model.md` "Design
> decision (2026-06-03)". The primitives already exist (`DipEvent`, `validate_delegation`, the anchor
> machinery), so this builds on tested code.

**Goal:** a device's authority to sign is provable by KERI **delegation** — its delegated KEL chains to
a root-anchored delegation seal — replacing attestation-based binding.

**Why it matters:** "device-bound" is meaningless if the binding is an external allowlist. Delegation
makes the binding part of the identity's signed event log, keripy-faithfully.

**Already exists:** the whole controller model + dual-index removal (see Assets). It is dormant — these
tasks wire it into the product.

- **A1 — `init` incepts a single-controller *shared* KEL.**
  - *Files:* `auths-sdk/src/domains/identity/provision.rs:12`; CLI `commands/id/identity.rs:441`;
    `auths-id/src/identity/initialize.rs` (`initialize_registry_identity:126`,
    `initialize_registry_identity_multi:245`).
  - *Do:* route identity creation through the multi-controller inception with a single controller
    (curve = configured default), so every identity can grow/shrink controllers uniformly later.
  - *Verify:* `auths init` then `get_key_state` shows 1 controller; existing init tests stay green.
  - *Depends:* none.

- **A2 — `device link` / `pair` author a growth rotation (`rot_add_controller`).**
  - *Files:* `auths-sdk/src/domains/device/service.rs:70` (`link_device`); `auths-sdk/src/pairing/mod.rs:384`;
    `auths-id/src/keri/shared_kel.rs` (`rot_add_controller`).
  - *Do:* add an SDK `add_device()` that loads key-state and authors a rotation appending the new
    device's verkey to `k[]`. Keep the attestation only as optional metadata (email/label), not as the
    authority.
  - *Verify:* link → `k[]` length +1, KEL replays; the new device's key appears in `current_keys`.
  - *Depends:* A1.

- **A3 — SDK `remove_device()` workflow.**
  - *Files:* new fn in `auths-sdk/src/domains/device/service.rs`; `shared_kel.rs:185`
    (`resolve_controller_index`); `auths-id/src/identity/rotate.rs` (`rotate_registry_identity_multi`,
    `RotationShape { remove_indices }`).
  - *Do:* resolve target `did:keri:` → controller index → `RotationShape { remove_indices: vec![i] }`
    → author dual-index shrink rotation → persist.
  - *Verify:* a 3→2 removal replays to 2 controllers (auths-id test
    `shared_kel_removes_controller_three_to_two` already proves the authoring; add the SDK-level test).
  - *Depends:* A1.

- **A4 — CLI `auths device remove` → SDK `remove_device()`; retire `RemovalNotYetSupported`.**
  - *Files:* `commands/device/authorization.rs:320`; `commands/device/pair/lan.rs:57`;
    `shared_kel.rs:180` (the error variant).
  - *Do:* replace the error branch with the SDK call; delete the variant once unreferenced.
  - *Verify:* `cargo build -p auths-cli --all-features`; manual remove shrinks `k[]`.
  - *Depends:* A3.

- **A5 — `status` / `device list` read the controller set from KEL replay.**
  - *Files:* `commands/status.rs` (`load_devices_summary`, ~435–522); device-list handler.
  - *Do:* aggregate devices from replayed `k[]` (+ device KELs for labels), not from attestations.
  - *Verify:* `auths status` reflects controllers; removing one updates the count.
  - *Depends:* A2, A3.

**Acceptance:** a device's authority to sign is provable by replaying the identity KEL alone; add and
remove are rotations, not attestation writes.

---

## Epic B — KEL-native verification (move the trust root off `allowed_signers`)

**Goal:** verifying a commit/artifact = locate the signer's KEL, replay it, confirm the signing key is
authorized in current (or signing-time) key-state, and confirm the device→identity chain.

**Why it matters:** this is where the KERI value is delivered or thrown away. If a verifier trusts an
allowlist file, it is "Sigstore with extra steps." Replaying the KEL is the differentiator.

**Already exists:** all replay/key-state primitives (`validate_kel`, `replay_kel`, `KeyState`) and
`verify_device_link` (`auths-verifier/src/verify.rs:244`) which already validates a KEL and extracts
`current_keys`. The commit-verify path just doesn't use them.

- **B1 — put the signer identity in-band on the commit.**
  - *Files:* `commands/sign.rs`, `bin/sign.rs` (sign path; currently no trailer).
  - *Do:* write `did:keri:` (identity) + the device's `did:keri:` into the commit (git trailer, e.g.
    `Auths-Id:` / `Auths-Device:`, or the SSHSIG namespace), so a verifier knows which KEL to replay.
  - *Verify:* a signed commit carries the trailer; parse round-trips; signature still validates.
  - *Depends:* none (can precede A).

- **B2 — KEL-native verify function.**
  - *Files:* new `verify_commit_against_kel` in `auths-verifier/src/verify.rs` (reuse the
    `verify_device_link:244` replay logic); call it from `commands/verify_commit.rs`.
  - *Do:* given (commit, signature, signer `did`), replay the KEL → confirm the signing key ∈
    authorized key-state → confirm device→identity chain. Return a typed verdict.
  - *Verify:* a commit signed by a device in `k[]` verifies; one signed by a *removed* device fails;
    a key never in `k[]` fails.
  - *Depends:* A2/A3 (so `k[]` reflects devices), B1 (to know the KEL), B4 (KEL source).

- **B3 — demote `allowed_signers` to a KEL-derived cache (or drop it).**
  - *Files:* `auths-sdk/src/workflows/allowed_signers.rs:363` (`sync`), `:382` (`load_all_attestations`).
  - *Do:* regenerate entries from replayed controller key-state instead of attestations; or make verify
    bypass the file entirely (B2 is authoritative).
  - *Verify:* removing a controller drops its verify authority without manual allowlist edits.
  - *Depends:* A3, B2.

- **B4 — KEL source for the verifier (MVP).**
  - *Files:* `commands/verify_commit.rs:35` (`--identity-bundle`).
  - *Do:* for MVP, accept the KEL via the existing bundle or local refs; Epic C replaces this with
    remote fetch.
  - *Verify:* `auths verify` against a bundled KEL with no allowlist present.
  - *Depends:* none.

**Acceptance:** a third party holding the KEL verifies a commit purely by replay; `allowed_signers` is
no longer the trust root.

---

## Epic C — Native KEL distribution (verifiable by strangers, no central server)

**Goal:** a verifier who never saw the identity can fetch its KEL over the network, decentralized,
using auths' "Git as storage" model — **not** `auths-radicle`.

**Why it matters:** "de-facto developer identity, adopted by agents and laypeople" cannot run on
hand-delivered bundles. CI/registries/consumers must resolve KELs automatically.

**Already exists:** the *replay-from-git-refs* logic (read events from refs → validate prefix →
`replay_kel`) in `auths-radicle/src/identity.rs:538`. Lift the generic git2 parts into auths proper and
drop the Radicle transport.

- **C1 — native KEL resolver from git refs/remotes.**
  - *Files:* new resolver in `auths-storage` or `auths-id` (alongside `GitIdentityStorage`); borrow
    logic from `auths-radicle/src/identity.rs:538` (`resolve_kel` / `resolve_keri_state`), git2 only.
  - *Do:* given a `did:keri:`, fetch its KEL events from a configured git remote/registry, validate the
    prefix, `replay_kel` to `KeyState`. Wire into B4.
  - *Verify:* `auths verify <commit>` resolves the signer's KEL from a remote with no local pre-seeding.
  - *Depends:* B2.

- **C2 — OOBI-style resolution for non-git consumers.** *(real build)*
  - *Do:* a well-known/HTTP endpoint that serves a DID's KEL (or a signed pointer to it), so verifiers
    without the git remote can still resolve. Greenfield; define the URI scheme.
  - *Verify:* resolve a KEL by URL; tamper detection on mismatched prefix.
  - *Depends:* C1.

- **C3 — Key-State Notice (KSN) for thin verifiers.**
  - *Files:* `KeyState` (`state.rs:18`).
  - *Do:* a signed snapshot of current key-state so CI/thin clients trust state without the full log
    (and later, witness-receipted — Epic D).
  - *Verify:* a verifier accepts a KSN's key-state and rejects an unsigned/forged one.
  - *Depends:* C1; hardened by D.

**Acceptance:** verification resolves KELs over the network with no central CA and no `auths-radicle`.

---

## Epic D — Witness receipting & duplicity (remove trust-on-first-sight)

**Goal:** events are receipted by designated witnesses; verifiers require M-of-N witness agreement;
concurrent `kt=1` forks are detected, not silently accepted.

**Why it matters:** this is the high-assurance line. Without it, an attacker who forks a `kt=1` KEL can
present a divergent key-state to a verifier. Required for "trust this at supply-chain scale."

**Already exists:** KAWA agreement (`witness/agreement.rs` — receipt collection, M-of-N
`AgreementStatus`); provider traits; `NoOpAsyncWitness`; `Receipt`/`rct`; `detect_duplicity` (verifier).
The `b[]` (backers) / `bt` (backer threshold) fields already exist in `icp`/`rot`.

- **D1 — a real witness service.** *(largest build)*
  - *Do:* replace the doc-stub `HttpWitness` with a service that accepts events, validates, stores, and
    issues signed receipts; expose submit/get-receipt endpoints matching `AsyncWitnessProvider`
    (`async_provider.rs:68`). New crate (e.g. `auths-witness-server`).
  - *Verify:* submit an event → receive a valid `rct`; receipts persist and are queryable.
  - *Depends:* none (parallelizable with A–C).

- **D2 — `Rct` as a first-class, validated artifact in replay.**
  - *Files:* `events.rs:790` (`Event` enum has no `Rct`); `validate_kel*`; `witness/agreement.rs`.
  - *Do:* model receipts, validate witness signatures, and feed KAWA so `validate_kel` can require
    M-of-N agreement for an event to be "accepted" key-state.
  - *Verify:* an event with insufficient receipts is `Pending`, not accepted; M-of-N → accepted.
  - *Depends:* D1.

- **D3 — designate witnesses on `icp`/`rot` and collect receipts on every controller change.**
  - *Files:* event builders for `b[]`/`bt`; the A2/A3 authoring paths.
  - *Do:* set backers + threshold at inception; on add/remove/rotate, collect receipts via KAWA before
    treating the new key-state as final.
  - *Verify:* a rotation isn't "final" until M-of-N receipts collected.
  - *Depends:* D1, D2, A.

- **D4 — surface duplicity in add/remove + verify UX.**
  - *Files:* `auths_verifier::duplicity::detect_duplicity`; verify + device commands.
  - *Do:* on resolve/verify, run duplicity detection against witnessed receipts; warn/block on forks.
  - *Verify:* a forged concurrent rotation is flagged.
  - *Depends:* D2.

**Acceptance:** an identity designates witnesses; verification requires witness-receipted key-state;
duplicity is detected, not silently accepted.

---

## Epic E — Agent identity via delegation (the AI-agent audience)

**Goal:** an AI agent has its own KERI identity, **delegated** from a human/org identity, scoped and
revocable by the delegator through the KEL.

**Why it matters:** the second adoption wave. KERI delegated identifiers are the right primitive, and
the events already exist — agents shouldn't be modeled as attestations.

**Already exists:** `dip`/`drt` events (`events.rs:632`, replay in `keri/kel.rs`). Org delegation
currently mis-modeled as attestation `delegated_by` (`org/service.rs:376`).

- **E1 — delegated inception (`dip`) for an agent identity.**
  - *Files:* `events.rs:632` (`DipEvent`); new SDK agent-provision path under `domains/agents/`.
  - *Do:* author a `dip` whose delegator is the human/org KEL; anchor the delegation seal in the
    delegator's KEL.
  - *Verify:* the agent KEL chains to the delegator; replay validates the delegation.
  - *Depends:* A1.

- **E2 — delegated rotation (`drt`) for agent key rotation.** *Verify:* agent rotates; chain holds.
  *Depends:* E1.

- **E3 — migrate org/team delegation off attestation `delegated_by` onto `dip`/`drt`.**
  - *Files:* `org/service.rs:376`. *Verify:* org membership/authority is provable by KEL replay.
  *Depends:* E1.

- **E4 — minimal agent scope/expiry** ("may sign for repo X until T"). Decide: attestation-carried
  (interim) vs ACDC (Epic F). *Depends:* E1.

**Acceptance:** an agent identity is a delegated KEL, verifiable and revocable by its delegator via the
KEL.

---

## Epic F — ACDC + TEL (deferred; only if credential-grade features are promised)

**Goal:** capabilities, roles, OIDC bindings, and fine-grained agent scopes become verifiable
credentials (ACDC) with KERI-native revocation (TEL).

**Not required for the core thesis.** Device-bound artifact signing needs none of it. Pull in only when
the product advertises credential-grade authorization.

- **F1 — ACDC credential type + issuance/verification.**
- **F2 — TEL (transaction event log) registry for issuance + revocation.**
- **F3 — migrate attestation-borne capabilities/roles/OIDC → ACDC.**

**Acceptance:** capabilities are issued/verified/revoked as ACDCs anchored to KELs.

---

## Sequencing & effort

| Epic | Delivers | Effort | Gates the thesis? |
|---|---|---|---|
| A | device ∈ KEL | bounded (core built) | yes — *is* the product |
| B | KEL-native verify | bounded (primitives exist) | yes — *is* the product |
| C | strangers can resolve KELs | C1 small (lift logic); C2/C3 real builds | yes — for adoption |
| D | no trust-on-first-sight | large (witness service) | high-assurance; required at scale |
| E | agent identities | moderate (events exist) | second wave |
| F | credentials | large | only if promised |

**Recommended order:** A → B (in parallel where possible) → C1 → ship MVP with the duplicity caveat →
D (and C2/C3) → E → F if needed. D1 can start any time (independent service).

## Assets already paid for (build *on* these; don't re-derive)

KEL core + keripy byte-interop · KEL-rooted `did:keri` · shared-KEL controller model · dual-index
shrink removal (tested) · per-device KELs · `dip`/`drt` delegation events · KAWA witness-agreement
algorithm · `verify_device_link` replay logic · KEL-from-git-refs resolution logic (lift from
`auths-radicle` before deprecation).

## Working agreement (for any session picking this up cold)

- **Build/test:** `cargo nextest run -p <crate>`; full macOS gate
  `cargo nextest run --workspace --features test-utils,witness-client` (**not** `--all-features` — FIPS
  can't sign through SIP-protected git on macOS). Doc tests: `cargo test --all --doc`.
- **Lint/format:** `cargo clippy --all-targets --all-features -- -D warnings`; `cargo fmt --all`;
  `cargo run -p xtask -- check-curve-agnostic` (0 violations).
- **TDD:** write the failing test first, watch it fail, then implement (this repo's standard).
- **Architecture rules (CLAUDE.md):** SDK orchestrates, core/id implements; no business logic in CLI;
  inject `now: DateTime<Utc>` (no `Utc::now()` in core/id); every on-wire pubkey/sig carries its curve
  tag in-band (never dispatch on byte length).
- **Commits:** `git -c commit.gpgsign=false commit --no-verify`; stage files explicitly (exclude
  `.auths/allowed_signers`); no `Co-Authored-By`; **no `.flow` task IDs (`fn-N.M`) in code or commit
  messages** — epic labels (`A2`, `B1`) and finding IDs are fine.
- **Pre-launch, zero users:** no backwards-compat constraints — refactor freely.

See `device-model.md` for the verified current state and the Epic-A wiring detail.
