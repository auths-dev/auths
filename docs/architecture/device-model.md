# Device model: attestations vs. KEL controllers

**Status:** Decision *recorded, not yet taken* (2026-06-02). This note is the authoritative
description of how devices actually relate to an identity **today**, and the scoped plan for
making the shared-KEL controller model live if/when we choose to.

> **Corrects the record:** `multi_device_accepted_risks.md` describes a "Stage 1 shipped" world
> where "the user's identity is a shared KEL whose controllers are those device DIDs." That is
> *aspirational — ahead of the code*. The shared-KEL controller machinery exists and is unit-tested
> in `auths-id`, but **no command or workflow calls it**. Device management is 100% attestation-based
> in the shipping product. See §1.

---

## TL;DR

- **Commit signing is decoupled from the device model.** `auths-sign` signs with a local keychain
  key and never reads attestations or the KEL. Switching models cannot break signing.
- **Verification trusts `.auths/allowed_signers`**, which is *generated from attestations* today.
  This is the single coupling point: change the device model and you must repoint the generator.
- **The two models are complementary, not rival.** `k[]` holds keys; attestations hold metadata
  (email, capabilities, expiry, OIDC binding). A controller model would keep attestations anyway.
- **The hard part is already built.** Dual-index CESR signatures + true shrink-`k` removal authoring
  (Epic B) are done and tested. What's missing is the *wiring* that creates a multi-controller shared
  KEL in the first place — a bounded feature, not a rewrite.

---

## 1. What's actually true today (verified against the code)

### 1.1 Signing — independent of the device model

`crates/auths-cli/src/bin/sign.rs` resolves a keychain alias (`auths:<alias>`), signs the git
buffer, and emits an SSHSIG. It loads no identity, no attestation, no KEL. **Any device-model change
is invisible to the signing path.**

### 1.2 Verification — anchored on `allowed_signers`

`crates/auths-cli/src/commands/verify_commit.rs` verifies in two phases:

1. **Always:** the SSH signature is checked against `.auths/allowed_signers`
   (`verify_commit.rs:29-30`, via `ssh-keygen -Y find-principals|verify`). This is the load-bearing
   trust decision for commit verification.
2. **Optional (`--identity-bundle`):** a device→identity attestation chain is checked via
   `verify_chain`. Not used in the common path.

Commit verification **does not read KEL key-state.** It reads `allowed_signers`.

### 1.3 `allowed_signers` is generated *from attestations*

`crates/auths-sdk/src/workflows/allowed_signers.rs::sync` (`:363`) calls
`storage.load_all_attestations()` (`:382`) and emits one entry per attestation —
`principal_from_attestation()` + `att.device_public_key` (`:387,:390,:497`).

**This is the only place the device model touches verification.** Verification keeps working for
*any* source, as long as `allowed_signers` stays populated.

### 1.4 The shared-KEL controller model is dormant

`crates/auths-id/src/keri/shared_kel.rs` defines `ControllerDescriptor`, `rot_add_controller`,
`rot_remove_controller`, `rot_swap_controller`, `apply_shared_kel_change`, and
`resolve_controller_index` (`:185`). `initialize_registry_identity_multi`
(`identity/initialize.rs:245`) incepts a multi-controller KEL.

**None of these have a caller outside their own unit tests.** `auths init` uses the single-controller
`initialize_registry_identity` (`:126`). `auths device link` creates an **attestation**
(`domains/device/service.rs:70` → `create_signed_attestation`). `revoke`/`extend` mutate attestations
(`:135`, `:202`). No command grows or shrinks a controller set.

### 1.5 Blast radius, honestly scoped

| Path | Source of truth today | Under a controller model |
|------|----------------------|--------------------------|
| `auths sign` / commit signing | local keychain key | **no change** |
| `auths verify` | `.auths/allowed_signers` | **no change** *if* `allowed_signers` stays populated |
| `allowed_signers` generation | attestations (`sync`) | repoint to `k[]`, or dual-source |
| `auths status`, `device list` | attestations | cosmetic — read `k[]` |
| `device link` / `revoke` / `extend` | create/mutate attestations | unchanged, *or* also author a rotation |
| `device remove` | returns `RemovalNotYetSupported` (`authorization.rs:320`) | real shrink-`k` rotation |
| `auths init`, `rotate`, `id show`, `agent` | not device-model dependent | **no change** |

---

## 2. The two models are layers, not rivals

**Attestation** (`crates/auths-verifier/src/core.rs::Attestation`) — an issuer-signed, device-
counter-signed record binding a device `did:key:` to an identity `did:keri:`, carrying metadata:
email, capabilities, expiry, revocation, OIDC binding. Stored as a git ref; cheap to write; self-
contained for offline verification.

**KEL controller** (`ControllerDescriptor`) — a slot in the identity KEL's `k[]`. Membership is part
of the signed event log: provable from the KEL alone, ordered, and removable by rotation. Holds
*keys*, not metadata.

These answer different questions. "Is this device cryptographically part of the identity?" is a `k[]`
question. "What is this device allowed to do, and what's its email/expiry?" is an attestation
question. A controller model **adds** the first; it does not remove the need for the second.

---

## 3. Gains vs. costs of moving membership into `k[]`

**Gains**
- Device membership is provable from the KEL itself — no separately-signed ref to fetch/trust.
- Removal is a real, ordered KEL event (not a revocation flag), verifiable offline from the log.
- Threshold policies become expressible (`kt=2`, "2-of-3 devices must sign").

**Costs**
- Every add/remove is a **KEL rotation** — heavier than writing an attestation ref (advances key
  state, consumes a pre-committed next-key).
- Offline verifiers need each device's KEL present to resolve its current key — more state to ship
  than a self-contained attestation.
- The **kt=1 duplicity risk** (`multi_device_accepted_risks.md`) becomes consensus-critical the moment
  membership lives in `k[]`.
- `k[]` can't hold email/capabilities/expiry — attestations stay regardless, so you run both layers.

---

## 4. Recommended posture

**Keep attestations as the metadata + `allowed_signers` layer. Treat KEL controllership as an opt-in
security upgrade** for devices you want cryptographically bound to the identity. The two coexist:
`allowed_signers` can be dual-sourced (attestation-derived **and** controller-derived entries) so
neither path regresses. This avoids a rip-and-replace and lets controllership land incrementally.

---

## 5. Scoped wiring plan (for whoever picks this up)

### Already done (Epic B — dual-index CESR signatures)
- `IndexedSignature` carries `prior_index`; dual-index `2A`/`2E` emission + a code-directed parser,
  byte-identical to keripy 1.3.4.
- The validator binds each rotation signature to the prior commitment it reveals and meets the prior
  threshold over the prior `n[]` (shrink-`k` removal is accepted).
- `rotate_registry_identity_multi(..., RotationShape { remove_indices, .. })` authors a true shrink
  rotation; `rot_remove_controller` is unblocked. End-to-end test: a 3-controller shared KEL rotates
  to 2 and replays (`auths-id` `shared_kel_removes_controller_three_to_two`).

### Missing — the wiring that makes it live
1. **An "add controller" path.** Nothing creates a multi-controller shared KEL today. Decide where
   the first controller comes from (convert `auths init` to incept a single-controller *shared* KEL,
   or lazily promote on first device add), then have `device link`/`pair` author a growth rotation via
   `rot_add_controller` instead of (or alongside) the attestation.
2. **SDK `remove_device()` workflow** in `domains/device/service.rs` (sibling of `link/revoke/extend`):
   load KEL state → `resolve_controller_index(target_did)` → `RotationShape { remove_indices }` →
   `rotate_registry_identity_multi` → persist. All orchestration in the SDK, per the layering rules.
3. **CLI `auths device remove`** → call SDK `remove_device()`; delete the `RemovalNotYetSupported`
   branch (`authorization.rs:320`). Presentation only.
4. **Repoint `allowed_signers::sync`** to include controller-derived entries (dual-source), so removing
   a controller actually drops its verify authority.
5. **`auths status` / `device list`** to surface the controller set alongside attestations.
6. **Retire `RemovalNotYetSupported`** once `authorization.rs:320` and `pair/lan.rs:57` no longer
   reference it.

### Decisions to settle *before* building
- Does `auths init` always create a shared KEL (uniform model), or only multi-device identities?
- What does `device revoke` mean once controllers exist — attestation revocation, `k[]` removal, or
  both? (They are distinct trust events.)
- Is controllership default-on for every device, or opt-in for "trusted" devices only?
- Do we stay `kt=1` (accept the duplicity risk) or move to `kt≥2` (and pay the coordination cost)?
  The threshold upgrade path is sketched in `essays/design/multi_device.md`.

### Suggested sequence
Settle the decisions above → (1) add-controller path with dual-sourced `allowed_signers` → (2)+(3)
remove path end-to-end → (5) status/list surfacing → (6) cleanup. Each step is independently testable
and shippable; the cryptographic core it rests on is already verified.

---

## 6. Open questions

- **Migration of existing identities.** If `init` starts creating shared KELs, what happens to
  identities incepted single-controller? (Pre-launch, zero users — likely a non-issue, but record it.)
- **Verifier state distribution.** Controller-based verification needs device KELs available offline;
  define how a verifier obtains them (bundle? registry fetch?).
- **Duplicity surfacing.** `auths_verifier::duplicity::detect_duplicity` exists; wire it into the
  controller add/remove UX before membership becomes consensus-critical.
