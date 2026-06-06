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
| Commit trust | KEL replay → key authorized? (in-process SSHSIG) | KEL replay → key authorized? | ✅ (Epic B); artifact-path → [#206](https://github.com/bordumb/auths/issues/206) |
| Signer identity on a commit | `did:keri` in-band (`Auths-Id` + `Auths-Device`) | `did:keri` in-band | ✅ (Epic B) |
| Third-party gets the KEL | trust-on-first-sight / bundle | native git-remote fetch + OOBI | ❌ (Epic C) |
| Duplicity / ordering | local first-seen | witness receipts (KAWA) | **receipt-gated replay + verify wired** (Epic D); CESR interop (D.10) + e2e (D.12) remain |
| Agent identity | attestation `delegated_by` | delegated KEL (`dip`/`drt`) | ✅ delivered (Epic E — agents & org members are `dip`-delegated AIDs; [ADR 007](ADRs/007-agent-identity-via-delegation.md)) |
| Capabilities / roles | attestation fields | ACDC + TEL | ✅ delivered (Epic F — holder-bound, lifecycle-witnessed, fresh, dual-curve; [ADR 008](ADRs/008-acdc-tel-credentials.md)). OIDC binding stays on the attestation (deferred). |

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
            Epic E (agent delegation)        Epic F (ACDC/TEL credentials — delivered)
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

## Epic A2 — Device add & delegation pairing (precursor to B)

> **Added 2026-06-03.** Epic A delivered the delegation *engine* (`incept_delegated_device`,
> `add_device`/`remove_device`/`list_delegated_devices`, CLI `device remove`) but **nothing in the binary
> delegates a device** — the only CLI "add" is `id expand --add-device`, which is the old shared-`k[]`
> rotation, not delegation. This epic completes the device-bound surface: a device joins as a delegated
> KERI identifier, added **locally** (a host-held slot) or **paired remotely so the device holds its own
> key**. Epic B (verification) depends on this — you can't verify delegation-based signing until devices
> can be delegated. Closes #199 + #201.

**Goal:** a device becomes a delegated AID of the root (its own KEL, `dip` anchored by the root via
`ixn`), holding its **own** key in the remote case. Reuses the Epic A engine + the existing
`auths device pair` transport; replaces attestation-based pairing.

**Already exists:** SDK `add_device` (local-generate) / `remove_device` / `list_delegated_devices`;
`incept_delegated_device` + `validate_delegation`; `auths device pair` LAN/online/offline transport
(attestation-based today, `pairing/mod.rs:334 create_pairing_attestation`); `dip`/`drt` events.

- **A2.1 — Local `auths device add` (CLI → SDK), well-engineered.** Generate a device key on this host,
  delegate it (root anchors the `dip`), store metadata (label). UX: `auths device add --label "…"
  [--curve] [--key <root-alias>]` → prints the device DID. Dedup (reject re-delegating a key already in
  the set); typed errors; tests. Closes the local half of #201.
- **A2.2 — Delegated device key rotation (`drt`).** A delegated device must rotate its own key: ensure
  `add_device` records the device's pre-committed next key, and add `drt` authoring anchored by the root.
- **A2.3 — Remote pairing onto delegation.** Rewire `auths device pair` (LAN/online/offline): the joining
  device generates its **own** key + next-commitment, builds its `dip` (delegated by the root prefix),
  and transmits it over the pairing channel; the initiator (root) anchors it. Mutual verification (device
  verifies the root; root verifies the device's `dip`, channel-bound). Replaces
  `create_pairing_attestation`. Closes #199.
- **A2.4 — `device list` / `status` from the delegation set.** Wire `auths device list` + the `status`
  device summary to `list_delegated_devices` (live = delegated − revoked); surface
  `auths_verifier::duplicity::detect_duplicity` as a non-fatal warning. Closes #201's display tail.
- **A2.5 — Recovery (stolen device).** Revoke the lost device's delegation + pair a replacement (the
  `auths device pair --recover` flow, now meaningful under delegation).

**Acceptance:** `auths device add` delegates a local device; `auths device pair` pairs a *remote* device
that holds its own key (proven by `validate_delegation` against a key the initiator never held);
`auths device list` shows the live set; `auths device remove` revokes — all end-to-end through the binary.

---

## Epic B — KEL-native verification (move the trust root off `allowed_signers`)

> **Refresh (2026-06-03, post-delegation pivot):** B2 below was written for the shared-`k[]` model
> ("device in `k[]`"). Under delegation (Model D), verification resolves the signer's **device KEL →
> root-anchored delegation** (`validate_delegation`) **minus revocation** — not membership in a shared
> `k[]`. This is issue #200. Depends on Epic A2 (delegated devices must exist to verify them).

> **✅ Done (2026-06-03, Epic B):** `Auths-Id` + `Auths-Device` in-band `did:keri:` trailers (B1);
> `verify_commit_against_kel` in `auths-verifier/src/commit_kel.rs` resolving device KEL →
> `validate_delegation` against the root → not-revoked → signing key is current (B2); `allowed_signers`
> **dropped entirely** — Option B, not demoted to a cache (B3); local-refs KEL source (B4, remote fetch
> is Epic C). Trust = KEL replay + the committed `.auths/roots` pin + in-process SSHSIG; no `ssh-keygen`,
> no allowlist. **Closes [#200](https://github.com/bordumb/auths/issues/200).** Deferred:
> signing-time verification [#205], artifact-path verify [#206], `kt>1` multi-key devices [#207],
> remote/OOB KEL resolution [#208], opt-in `allowed_signers` export for native git interop [#209].

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
  - *Do:* given (commit, signature, signer device `did`), resolve the device's delegated KEL →
    `validate_delegation` against the root (the root anchored its `dip`) → confirm **not revoked** →
    confirm the signing key is the device's current key. Return a typed verdict.
  - *Verify:* a commit signed by a *delegated* device verifies; one signed by a *revoked* device fails;
    a device the root never delegated fails.
  - *Depends:* Epic A2 (delegated devices exist), B1 (signer `did` on the commit), B4 (KEL source).

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

> **Delivered (status correction).** The framing below — "D1, a real witness service, *largest build /
> unbuilt*" — was **wrong**: the witness *service* (axum server, SQLite receipt store, parallel collector,
> HTTP client, KAWA engine, `rct` type) was already built. The real work was **closing the trust loop**, not
> building a server. What Epic D actually delivered (see the epic plan and
> `ADRs/006-witness-receipting-and-duplicity.md`):
> witness identity as a pinned AID (D.1); receipt **signing** + provenance + collection-time signature
> verification (D.2); `b[]`/`bt`/`br`/`ba` designation on `icp`/`rot` (D.3/D.4); a sync `WitnessReceiptLookup`
> seam (D.5); **receipt-gated replay** `validate_kel_with_receipts` (M-of-N → KeyState) (D.6); verify-path
> wiring with a verifier-side warn/`--require-witnesses` policy (D.7); cross-source + conflicting-receipt
> duplicity refusal in the resolver (D.8); CLI surfacing of quorum + fork status (D.9); KSN
> `Witnessed` trust level (D.13). Remaining at time of writing: CESR `-C`/`-B` receipt-couplet interop
> (D.10) and the end-to-end convergence integration test (D.12). Treat the per-`Dn` bullets below as the
> *original* sketch, superseded by the epic plan.

**Already existed (reused, not re-derived):** KAWA agreement (`witness/agreement.rs` — receipt collection,
M-of-N `AgreementStatus`); provider traits; `NoOpAsyncWitness`; `Receipt`/`rct`; `detect_duplicity`
(verifier); the witness server + receipt store + collector + HTTP client. The `b[]` (backers) / `bt`
(backer threshold) fields already exist in `icp`/`rot`.

- **D1 — a real witness service.** *(already built before Epic D — see the status note above)*
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

## Epic E — Agent identity via delegation (the AI-agent audience) ✅ delivered

**Goal:** an AI agent has its own KERI identity, **delegated** from a human/org identity, scoped and
revocable by the delegator through the KEL.

**Why it matters:** the second adoption wave. KERI delegated identifiers are the right primitive, and
agents must not be modeled as attestations or bearer-token sessions.

**Delivered state:** the `dip`/`drt`/anchor/revoke/list/validate engine in `auths-id/keri/delegation.rs`
was already built and **generic** (not device-specific). Epic E wired an agent + org-member surface onto
it, deleted two legacy "agent" models (a bearer-token session model and a standalone-`icp` +
attestation `delegated_by` model), and fixed one shared correctness gap (the reciprocal source seal). The
eight load-bearing decisions are recorded in
[ADR 007](ADRs/007-agent-identity-via-delegation.md).

- **E1 — reciprocal source seal + bilateral `validate_delegation`.** ✅ `dip`/`drt` carry the delegate-side
  `-G` `SealSourceCouple`; `validate_delegation` enforces both directions; round-trips a keripy 1.3.4
  fixture.
- **E2 — legacy bearer-token agents model deleted** (+ `auths-api /v1/agents` removed). ✅
- **E3 — SDK `agents::add` + CLI `auths id agent add` (agent as a `dip` delegated by the root).** ✅
  Thin wrapper over the generic `incept_delegated_device`; retired the standalone-`icp` provisioning.
- **E4 — SDK `agents::rotate` + CLI `auths id agent rotate` (`drt`).** ✅
- **E5 — `agents::revoke`/`list` + CLI; agents distinguishable from devices.** ✅
- **E6 — verifier orders the signing event vs the revocation seal by KEL position** (`Auths-Anchor-Seq`
  trailer; `SignedAfterRevocation` verdict). ✅
- **E7 — agent scope/expiry via a delegator-anchored scope seal**; verifier `OutsideAgentScope` /
  `AgentExpired` verdicts (expiry via injected `now`). ✅
- **E8 — KERI-native org members via `dip` delegated by the org AID (`kt=1`)** + `delegated_by` readers
  migrated fail-closed (KEL authoritative, never OR-fallback to a stale attestation); `kt≥2` orgs →
  typed `OrgThresholdDelegationUnsupported`. ✅
- **E9 — docs, ADR 007, legacy-doc rewrite, deferred-issue tracking.** ✅

**Acceptance (met):** an agent (and an org member) is a delegated KEL — verifiable and revocable by its
delegator purely by KEL replay, scoped by a delegator-anchored seal, with no bearer tokens anywhere.

**Deferred (tracked in [ADR 007](ADRs/007-agent-identity-via-delegation.md)):** multi-sig (`kt≥2`) org
anchoring; ACDC/TEL scope (Epic F); **remote/CI headless provisioning** (priority follow-on); cascade
revocation; a signer-type trailer discriminator; delegation depth cap + sub-agent delegators.

---

## Epic F — ACDC + TEL credentials ✅ delivered (v1 robust slice)

**Goal:** capabilities and roles become verifiable credentials (ACDC) with KERI-native per-credential
revocation (TEL), anchored to the issuer's KEL.

**Not required for the core thesis.** Device-bound artifact signing needs none of it — but when shipped it
was built **first-class, robust**: minimal trust surface, maximal trust guarantees. The eight load-bearing
decisions (D1–D8), the RegistryBackend freeze-touch resolution, the `agentscope:`-vs-ACDC caps precedence,
the full threat model, and the composed witness claim are recorded in
[ADR 008](ADRs/008-acdc-tel-credentials.md).

**Delivered v1 robust slice** — the non-negotiable security properties shipped, not just the happy path:

- **F.1 — holder-bound ACDC `{v,d,i,ri,s,a}`** (subject `a.i` = KERI AID) + forward-compatible most-compact
  SAID (parameterized `ACDC10JSON` protocol tag; all KEL SAIDs unchanged) + pinned embedded JSON-Schema-2020-12;
  keripy 1.3.4 byte-equal fixtures, **both curves**. ✅
- **F.2 — backerless (`NB`) TEL `vcp`/`iss`/`rev`** + insertion-order SAID + chain validation; keripy
  byte-interop, both curves. ✅
- **F.3 — TEL storage + KEL anchoring** (lazy `vcp`); the frozen `RegistryBackend` was extended with the
  documented atomicity justification (ACDC blob + TEL event + KEL `ixn` land in one commit); `kt≥2` issuer →
  typed error. ✅
- **F.4 — SDK `credentials::issue/revoke/list/verify` + CLI** (`auths credential …`). `verify` is the
  resolution + **freshness** layer the pure verifier can't be: resolves to the witnessed tip and owns
  `StaleOrUnresolvable` (fail-closed). ✅
- **F.5 — pure WASM-safe ACDC verification + lifecycle witness-quorum.** SAID + embedded schema +
  issuer signing-time key + TEL status by KEL position + **witness-quorum over the `vcp`/`iss`/`rev`
  anchoring ixns** (the F.9 finding: ixns aren't gated by the core, so the verifier quorum-checks them via
  KAWA) + `detect_duplicity`. Both curves. ✅
- **F.6 — `context_from_credential` holder-proof policy bridge.** Authority enters a decision **only** from a
  holder-verified presentation, never a raw ACDC; documents the `CapsSource` precedence (ACDC authoritative,
  `agentscope:` seal advisory). ✅
- **F.8 — holder-binding + presentation signature** (no bearer tokens). Proof of current subject-key control
  via challenge-response (single-use nonce) over `(cred-SAID, audience, nonce)`; non-interactive short-TTL
  path with a documented residual. ✅
- **F.9 — Epic-D witness pre-flight** proving the composed witness claim is achievable (establishment events
  gate + fail closed; ixns don't, so F.5 quorum-checks the lifecycle anchors). ✅
- **F.10 — migrate caps/role authority readers off attestations** (single authority source: ACDC via the F.6
  bridge; `agentscope:` advisory fast path kept). ✅
- **F.11 — remove caps/role from the attestation write path.** ✅
- **F.7 — ADR 008 (threat model + composed witness claim + Epic-D dependency), docs, deferred-issue filing.** ✅

**Acceptance (met):** a capability is issued as a holder-bound ACDC anchored to the issuer KEL via a
backerless TEL, verified purely by replay (SAID + schema + signing-time key + KEL-position TEL status +
witness-quorum), honored only against a holder-verified presentation, and revoked per-credential via a
KEL-anchored `rev` ordered by KEL position. Both curves pass issue → verify → revoke.

**NOT deferred — shipped:** holder-binding, lifecycle witness-quorum, and revocation freshness.

**Deferred (tracked in [ADR 008](ADRs/008-acdc-tel-credentials.md), issues filed):** backed registries
(`bis`/`brv`/`vrt`); ACDC edge (`e`) + rule (`r`) **content** (additive — SAID stays forward-compatible);
selective/graduated disclosure (`u`/`A`) **content** (a **SAID-breaking v2**, not additive); full IPEX
grant/admit (the v1 presentation *signature* shipped in F.8); TEL escrow; `Auths-Credential` commit trailer;
OIDC→ACDC; dynamic/`oneOf` schema registry; `delegated_by`→ACDC edge; and re-introducing an ACDC-sourced
capability gate for artifact/device verification ([#220](https://github.com/auths-dev/auths/issues/220)).

---

## Sequencing & effort

| Epic | Delivers | Effort | Gates the thesis? |
|---|---|---|---|
| A | device ∈ KEL | bounded (core built) | yes — *is* the product |
| B | KEL-native verify | bounded (primitives exist) | yes — *is* the product |
| C | strangers can resolve KELs | C1 small (lift logic); C2/C3 real builds | yes — for adoption |
| D | no trust-on-first-sight | large (witness service) | high-assurance; required at scale |
| E | agent identities | moderate (events exist) | second wave |
| F | credentials | large | delivered (holder-bound, witnessed, fresh) |

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
