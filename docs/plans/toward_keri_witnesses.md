# Plan: toward KERI witnesses — Stage 1 (per-device KELs + shared identity KEL)

Status: **draft plan, not yet executed**. Written so any fresh reader (human or LLM) can pick up cold.

## What this document is

This is the implementation plan for **Stage 1 of the multi-device design ladder**. The architectural motivation lives in `/Users/bordumb/workspace/repositories/auths-base/essays/design/multi_device.md` — read that first if you're new to the problem; it has diagrams, decision-axis tables, and a market-comparison section against OAuth Device Grant and WebAuthn. This document skips the "why" and focuses on the "what to do and where."

The goal is to replace the current asymmetric one-KEL-with-device-subjects model with a symmetric one where every device has its own `did:keri:` KEL and the user's identity is a shared KEL whose controllers are the devices. Stage 1 stops short of witness infrastructure — the security boundary at this stage is Secure Enclave + biometric on each device. Witnesses arrive in Stage 2; see the design doc for the full ladder.

## TL;DR for a fresh reader

- **Today**: Mac holds the single controller KEL. Phone is a subject (`did:key:` derived from its SE pubkey). Rotation uses a `supersedes_attestation_rid` pointer. Works for Mac→phone, broken for phone→new-Mac (stolen-laptop case).
- **Stage 1 target**: Every device runs its own KEL with pre-rotation. A separate shared identity KEL (`did:keri:You`) lists both devices as controllers, `kt = 1`. Pairing = `rot` on the shared KEL adding a controller. Device rotation = `rot` on the device's own KEL. Stolen-laptop recovery = surviving device signs a `rot` on the shared KEL to swap controllers.
- **Pre-launch with zero users.** No migration. Rip out `DeviceDID` and everything that depended on it.
- **What's in Stage 1**: protocol types, storage, FFI, pair/rotate/revoke ceremonies, `DeviceDID` removal.
- **What's out of Stage 1**: witnesses, `kt ≥ 2`, OOBI discovery. Those are Stages 2–4.

## Required reading before writing code

1. **`/Users/bordumb/workspace/repositories/auths-base/essays/design/multi_device.md`** — the architectural context. Key sections: "Option B — Multi-sig controller over a shared identity KEL," "Market comparison," "Direction of travel — incremental upgrade ladder." The Stage 1 section of that doc is the source of truth for the target; this plan operationalizes it.
2. **`/Users/bordumb/workspace/repositories/auths-base/essays/philosophy/reply_to_isi_pre_rotation.md`** — the semantic distinction between linking (delegation), updating (rotation), and unlinking (revocation). Pre-rotation's cryptographic guarantee only applies to update. This shapes how the new code should name events and validate them.
3. **`docs/api-spec.yaml`** — current wire format for pair sessions. Stage 1 extends this; don't regress it.
4. **`/Users/bordumb/workspace/repositories/auths-base/essays/design/multi_device.md` § "What Stage 1 needs to answer before a plan is written"** — four decisions that should be resolved before detailed coding. This plan gives defaults for each; flag to the user if the defaults are wrong.

## Hard constraints

- **iOS Secure Enclave is P-256 only.** Non-extractable keys. Biometric-gated per use (we keep this policy).
- **Curve-agnostic code.** Enforced by `cargo run --bin xtask -- check-curve-agnostic`. No `p256::...` or `ed25519::...` imports outside `auths-crypto`, `auths-core/src/crypto`, and `auths-mobile-ffi`. Use `auths_crypto::CurveType` and `RingCryptoProvider::p256_verify` in CLI/SDK code.
- **CLI cannot import `auths_core`, `auths_id`, `auths_storage` directly.** Route through `auths_sdk::*` re-exports. Enforced by the `check-sdk-boundary` pre-commit hook.
- **No backwards-compatibility hedges.** User has confirmed pre-launch posture: remove fields and types rather than add `Option<T>` migration shims. If a field becomes wire-required, make it required — no `#[serde(default)]` for "legacy messages."

## Current state — surveyed files to know

### Rust (Mac side)

| File | What it does today |
|---|---|
| `crates/auths-verifier/src/types.rs` | `DeviceDID` (transparent String, `did:key:` form), `IdentityDID`, `CanonicalDid`, `DevicePublicKey`. |
| `crates/auths-verifier/src/core.rs` | `Attestation` struct. Fields: `subject: CanonicalDid`, `device_public_key: DevicePublicKey`, `supersedes_attestation_rid: Option<ResourceId>`, `capabilities`, `role`, etc. `CanonicalAttestationData` is what the signature covers. |
| `crates/auths-id/src/attestation/create.rs` | `create_signed_attestation`, `create_superseding_attestation` (the rotation helper we added last session). Signs canonical attestation data with a `SecureSigner`. |
| `crates/auths-id/src/attestation/revoke.rs` | `create_signed_revocation` — exists, wired via `auths_sdk::attestation::create_signed_revocation`. Not yet surfaced in any UI. |
| `crates/auths-id/src/identity/initialize.rs` | `initialize_registry_identity` — creates a controller KEL + primary key + pre-rotation key, stores encrypted in keychain. This is the pattern to mirror for device KELs. |
| `crates/auths-id/src/identity/rotate.rs` | KEL-level rotation for the controller's own keys (3-phase: compute event, apply to registry + keychain). Reusable for device KELs since a device KEL is structurally the same thing. |
| `crates/auths-id/src/keri/inception.rs` | `create_keri_identity_with_curve` — raw KERI inception helper (generates keys, builds `icp` event, signs). Used inside `initialize_registry_identity`. |
| `crates/auths-pairing-protocol/src/types.rs` | `CreateSessionRequest` (now with `mode: SessionMode`), `SubmitResponseRequest` (now with `new_device_signing_pubkey: Option<Base64UrlEncoded>`), `SessionMode::{Pair, Rotate}`. |
| `crates/auths-pairing-protocol/src/token.rs` | `PairingToken` + the `auths://pair?d=…&e=…&k=…&sc=…&sid=…` URI format. The URI carries `controller_did` today; Stage 1 will extend it to carry an inception event. |
| `crates/auths-pairing-daemon/src/handlers.rs` | HTTP handlers: `handle_submit_response`, `handle_submit_confirmation`, `handle_get_session`, `handle_lookup_hmac`. Verifies `Auths-Sig` / `Auths-HMAC`. Curve- and mode-agnostic at this layer. |
| `crates/auths-pairing-daemon/src/server.rs` | `PairingDaemonHandle` exposes `session_mode()` for CLI dispatch. |
| `crates/auths-cli/src/commands/device/pair/lan.rs` | The Mac LAN flow. Starts daemon, renders QR, waits for `/response` + `/confirm`, dispatches to pair or rotate handler. |
| `crates/auths-cli/src/commands/device/pair/common.rs` | `handle_pairing_response` — post-`/response`: verifies binding signature, completes ECDH, derives SAS, creates attestation. |
| `crates/auths-cli/src/commands/device/pair/rotate.rs` | `handle_rotation_response` — the rotation post-handler; creates `create_superseding_attestation`. **This whole file is legacy after Stage 1** — native KEL rotation doesn't need supersedes. |
| `crates/auths-mobile-ffi/src/identity_context.rs` | Phone-side KERI identity inception: `createIdentity`, `P256IdentityInceptionContext`, `assemble_p256_identity`, `build_p256_identity_inception_payload`. **Critical**: the phone can already create its own `did:keri:`. Reuse this. |
| `crates/auths-mobile-ffi/src/pairing_context.rs` | Pair binding construction: `build_pairing_binding_message`, `assemble_pairing_response_body`, plus the rotation variants `build_rotation_binding_message` / `assemble_rotation_response_body` added last session. |

### Swift (iOS)

| File | What it does today |
|---|---|
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/DeviceDIDBootstrap.swift` | SE bootstrap key + rotation primitives (`beginRotation`, `commitRotation`, `rollbackRotation`, `signWithOldKey`). `BootstrapKeyVersion` counter increments on successful commit. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/SecureEnclaveService.swift` | Low-level SE key management. Key configs (`bootstrapDID`, `bootstrapDIDStaged`), `generateKeyPair`, `publicKeyDER`, `sign`. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/IdentityService.swift` | Calls FFI `createIdentity` to build the phone's own `did:keri:` — **already does this today** as part of first-launch flow when the user chooses "create identity." When the user pairs instead, this path isn't used and the phone's own `did:keri:` is overwritten by the controller's. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/PairingService.swift` | `completePairing`, `rotateKey`, `completePairingByShortCode`. Centralizes daemon client + Auths-Sig signing. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/DaemonClient.swift` | Centralized URL hygiene + diagnostic errors for daemon connections. Reuse as-is. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/CreateIdentityView.swift` | Onboarding "create identity on this phone" path. `IdentityStorage` struct lives here (fields: `did`, `prefix`, `deviceName`, `createdAt`, `peerDevices`, etc.). |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/PairDeviceView.swift` | Onboarding "pair with an existing identity" path. Scans QR from Mac. |
| `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/RotateKeyView.swift` | Current rotation UX. Legacy after Stage 1 (rotation becomes a local KEL `rot`, no cross-device ceremony). |
| `AuthsApp.swift` | `AppState` — in-memory identity model. `loadLocalIdentity` reads `IdentityStorage` from keychain. |

### Mobile FFI surface (critical — already has what we need)

The FFI already supports phone-side KERI inception. Specifically:

- `createIdentity(deviceName: String) -> IdentityResult` — creates a fresh P-256 KERI identity with inception event and returns `(prefix, did, device_name, inception_event_json)`.
- `P256IdentityInceptionContext` — opaque handle for the two-step identity-inception dance (build payload, sign, assemble).
- `build_p256_identity_inception_payload` / `assemble_p256_identity` — the SE-signs-it-externally flow for identity inception.

What's *missing* for Stage 1:
- A way for the phone to sign a `rot` event on a **shared KEL** (not its own KEL) using its device key as a controller.
- A way for the phone to export its own inception event for the Mac to read during pairing.
- A way for the phone to replicate the shared KEL locally.

## Target state — what "Stage 1 done" looks like

Every reference below is to the end state, not the migration.

### Type system

- **`DeviceDID` does not exist.** Every type that previously carried a `DeviceDID` now carries an `IdentityDID` (our `did:keri:` wrapper).
- **`Attestation.subject` stays `CanonicalDID`** — but in practice it only holds `did:keri:` now. There's no `did:key:` in the attestation graph.
- **`Attestation.supersedes_attestation_rid` is removed.** Rotation no longer produces a superseded attestation — it produces a `rot` event in the rotating device's own KEL. The device's DID is stable across rotations (that's exactly what pre-rotation gives us).
- **Pair and rotation ceremonies converge.** There's no separate "rotate" mode on the session layer — every "pair new thing to identity" is a `rot` on the shared KEL that adds a controller. "Rotate my keys" is a local `rot` on the device's own KEL, done without a session.

### Wire / session protocol

The pairing URI carries enough to bootstrap mutual verification:

```
auths://pair?sid=SID&sc=SHORTCODE&x=EXPIRES_AT
            &did_mac=did:keri:MAC
            &icp_mac=BASE64URL(MacInceptionEventJson)
            &ep=BASE64URL(EndpointURL)
```

The phone scans, verifies Mac's inception event self-consistency, sends its own inception event back. Mac verifies. Both sign a `rot` on the shared KEL to add the other as a controller. For the *very first pair* (no shared KEL yet), the initiating side inceptions the shared KEL first; the `rot` that adds the second device follows immediately in the same flow.

### Storage

On Mac (`~/.auths/`):
- The Mac's own device KEL (independent, non-shared).
- The shared identity KEL (replicated state).
- Encrypted keychain entries for Mac's device key + pre-rotation key AND for Mac's signing participation in the shared KEL (the "my piece of the shared identity" key).

On iPhone:
- The phone's own device KEL (SE-backed; already exists).
- The shared identity KEL (replicated state, stored in iOS Keychain).
- The phone's SE bootstrap key is the phone's identity-key material; no separate "controller key" at this stage.

### Ceremonies (end state)

- **`auths init` on a fresh Mac**: create Mac's own device KEL. No shared KEL yet — that gets born at first pair.
- **First-ever `auths pair` between Mac and phone**:
  - Phone already has its own device KEL from first-launch bootstrap.
  - Mac has its own device KEL from `auths init`.
  - Pair ceremony: mutual verification of inception events → Mac signs `icp` for shared KEL with itself + phone as co-controllers → shared KEL replicated to phone.
- **Subsequent `auths pair` on Mac with a second phone**:
  - Mac has own KEL + shared KEL with phone_A as co-controller.
  - Phone_B runs for the first time, creates own KEL.
  - Pair ceremony: Mac (or phone_A — any controller can do it at `kt=1`) signs a `rot` on the shared KEL adding phone_B as a controller.
- **Rotating a device's own keys**: local `rot` on that device's KEL. No session, no ceremony. Pre-rotation is revealed, new pre-rotation is committed. Other devices re-learn on their next verify.
- **Removing a device**: any controller signs a `rot` on the shared KEL dropping the target device from the controller set. `auths device remove <did:keri:...>` on Mac, or Settings → Devices → Remove on phone.
- **Stolen-laptop recovery**: phone (the surviving controller) signs a `rot` on the shared KEL that removes the lost Mac's `did:keri:` and adds a new Mac's `did:keri:`. Done via `auths pair --recover` on the new Mac + confirmation on phone.

## Open questions (defaults provided; flag if wrong)

1. **Storage layout on Mac.** Default: both the device KEL and the shared KEL live under `~/.auths/`, separate refs (`refs/auths/device-kel/*` vs `refs/auths/shared-kel/*`). Reusable from `auths-id/src/storage/git_refs.rs`.
2. **Storage on iPhone.** Default: extend `IdentityStorage` to hold both the phone's own KEL state and the shared KEL state. Persist to iOS Keychain as JSON blobs. Two separate Keychain items: `dev.auths.device-kel.v1` and `dev.auths.shared-kel.v1`.
3. **Pair URI shape.** Default: the Mac's QR carries `did_mac + icp_mac` (its own KEL's inception). The phone sends back its `did_phone + icp_phone` via the existing `/v1/pairing/sessions/{id}/response` body. The existing `SubmitResponseRequest` gains fields `initiator_inception_event`, `responder_inception_event`. If pair-is-first-pair, one side also includes `shared_kel_inception` on the next POST.
4. **kt=1 with cross-device coordination.** At `kt=1` any single controller can sign. Initiating device signs the `rot` that adds the new device. No co-signing in Stage 1.
5. **Attestation layer.** Kept. Attestations are still the mechanism for "this identity grants capability X to this device" (distinct from controllership). A device can be a controller of the shared KEL and separately hold one or more attestations for specific capabilities.
6. **Name scheme for `did:keri:You`.** The SAID (self-addressing identifier) of the shared KEL's inception event. Deterministic from the inception content; no user-picked name.
7. **Who inceptions the shared KEL first?** The Mac. When `auths pair` is invoked and no shared KEL exists yet, the Mac creates the `icp` event locally, signs it with its device key, the phone receives and verifies it, then the `rot` adding the phone lands immediately. Alternative: the first-invoked device (could be phone). Default is Mac for implementation simplicity — the Mac already has KEL-management machinery in `auths-id`.
8. **Revocation of the lost device.** When replacing a stolen Mac, the surviving phone issues `rot` on shared KEL with `OldMac` removed, `NewMac` added. `OldMac`'s device KEL continues to exist (we can't stop it); the shared KEL no longer lists it as a controller, which is sufficient — verifiers trust the current controller set, not the historical one.

## Implementation plan — chunks

Each chunk is scoped to a single reviewable piece. Run `cargo check --workspace --all-targets && cargo clippy --workspace --all-targets && cargo test --workspace --lib && cargo run --bin xtask -- check-curve-agnostic` after every chunk. The `auths pair` end-to-end test (Mac + real iPhone) should be re-run after Chunks 5 and 6.

### Chunk 1 — Protocol types (wire-format foundation)

Update `crates/auths-pairing-protocol/src/types.rs`:

- Remove `SessionMode` entirely (pair/rotate-mode distinction goes away — pair is just "add a controller to the shared KEL").
- Remove `SubmitResponseRequest.new_device_signing_pubkey` (rotation-specific field; no longer needed).
- Add `initiator_inception_event: String` and `responder_inception_event: String` fields to `SubmitResponseRequest` (base64url-no-pad JSON blobs of each side's `icp` event from their own device KEL).
- Add a new message type `SharedKelSetupRequest { icp_event: String }` carried on a new endpoint (or inlined into `/response` conditionally when no shared KEL exists yet).
- Update `docs/api-spec.yaml` in the same PR (ADR 004 requirement).
- Regenerate schemas: `cargo run --bin xtask -- generate-schemas`.

Verification: `cargo test --workspace --lib` green; the `spec-drift` pre-commit gate is green.

### Chunk 2 — Rust-side storage for device + shared KELs

New / modified files:
- `crates/auths-id/src/keri/device_kel.rs` (new): thin wrapper around existing KEL-creation logic that names the resulting entity a "device" for clarity. Reuses `create_keri_identity_with_curve`. Storage goes under `refs/auths/device-kel/{prefix}/*`.
- `crates/auths-id/src/keri/shared_kel.rs` (new): shared-KEL operations — inception with multiple controllers, `rot` to add/remove controllers. `kt=1` hardcoded for Stage 1 (flag TODO for `kt` upgrade path). Storage under `refs/auths/shared-kel/{prefix}/*`.
- `crates/auths-id/src/storage/git_refs.rs`: add path constants for the two new ref namespaces.
- `crates/auths-id/src/identity/initialize.rs`: refactor to call the new `device_kel::create` + remove attestation-based initialization.

The existing `create_keri_identity_with_curve` and `initialize_registry_identity` code paths provide 90% of what's needed; we're renaming and splitting, not rewriting.

Verification: new unit tests in `crates/auths-id/tests/` covering device-KEL inception, shared-KEL inception, and `rot`-add-controller with kt=1.

### Chunk 3 — Mobile FFI extensions

In `crates/auths-mobile-ffi/src/`:
- Rename `identity_context.rs` → `device_kel_context.rs`. Its existing `createIdentity` becomes the phone's device-KEL inception (which is what it structurally already is).
- New `shared_kel_context.rs`: FFI entry points for shared-KEL operations. `build_shared_kel_inception_payload(device_kel_didkeri, peer_didkeri) -> SignatureRequest`, `assemble_shared_kel_inception(signatures) -> SharedKelEvent`. Similar two-step for rotations.
- Remove `pairing_context.rs` rotation helpers (`build_rotation_binding_message`, `assemble_rotation_response_body`). Replaced by shared-KEL ops.
- Update `lib.rs` exports.
- Regenerate Swift bindings: `just build-xcframework` in the `auths-mobile/` repo.

Verification: `cargo check -p auths-mobile-ffi` green; `just build-xcframework` succeeds; resulting `auths_mobile_ffi.swift` includes the new functions.

### Chunk 4 — CLI rewrite for pair / rotate / revoke

Files to rewrite:
- `crates/auths-cli/src/commands/device/pair/lan.rs`: replace current pair-then-attest flow with pair-then-rot-shared-KEL.
- `crates/auths-cli/src/commands/device/pair/common.rs`: replace `handle_pairing_response` with `handle_pair_response` that does mutual inception verification + shared-KEL `rot`.
- **DELETE** `crates/auths-cli/src/commands/device/pair/rotate.rs`. Its purpose is gone — native KEL rotation doesn't need a session.
- Remove `--rotate` flag from `PairCommand` in `mod.rs`.
- Add `auths identity rotate` command that calls `auths-id/src/identity/rotate.rs` on the caller's own device KEL (no session, no ceremony — just local key rotation with pre-rotation reveal).
- Add `auths device remove <did:keri:...>` command that signs a `rot` on the shared KEL dropping the named controller.

Verification: `auths init` then `auths pair` on Mac + `PairDeviceView` scan on iPhone → shared KEL created with both as controllers. `auths identity rotate` on Mac → Mac's device KEL rotates, shared KEL unchanged. `auths device remove` → target dropped from controller set.

### Chunk 5 — iOS Swift rewrite for pair / rotate / revoke

Files:
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/DeviceDIDBootstrap.swift`: rename / refactor. It's no longer a "bootstrap DID" — it's the phone's device KEL. Keep the SE key management but delete the rotation scaffolding (`beginRotation`, `commitRotation`, `rollbackRotation`, `signWithOldKey`, `BootstrapKeyVersion`). Rotation is now a `rot` event on the phone's own KEL via FFI, not a staged-key dance.
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Services/PairingService.swift`: rewrite `completePairing` to do mutual inception verification + participate in shared KEL `rot`. Delete `rotateKey`.
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/RotateKeyView.swift`: **DELETE**. Rotation is a settings action on the phone's own KEL, not a multi-device ceremony. Replace with a simpler Settings → Advanced → "Rotate signing key" button that triggers a local FFI call.
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/CreateIdentityView.swift`: unchanged conceptually — still creates the phone's own KEL at first launch. The `IdentityStorage` struct gets new fields for shared-KEL state.
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/IdentityView.swift`: update to display the shared identity DID and the controller set.
- `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/DevicesView.swift`: "Remove" action per device — calls into a new `SharedKELService` that signs a `rot` on the shared KEL via FFI.
- Add `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/ios/Auths/Views/Settings/ForgetIdentityView.swift`: the "nuclear reset" — wipes the phone's device KEL and shared-KEL copy, returns to onboarding.

Verification: end-to-end on real iPhone — pair, rotate locally, remove-device, forget-identity — all complete cleanly.

### Chunk 6 — Delete `DeviceDID` and dead code

Now that nothing consumes `DeviceDID` in production:

- `crates/auths-verifier/src/types.rs`: delete `DeviceDID` type, `from_public_key` for device DIDs, `ref_name`, `matches_sanitized_ref`, `signer_hex_to_did`.
- Delete the multicodec prefix machinery (0xED 0x01 for Ed25519, 0x80 0x24 for P-256) since we're not deriving `did:key:` anymore.
- `crates/auths-verifier/src/core.rs`: `Attestation.subject` changes to `CanonicalDid`, but `supersedes_attestation_rid` gets deleted (rotation no longer produces superseded attestations).
- `crates/auths-id/src/attestation/create.rs`: delete `create_superseding_attestation`.
- `crates/auths-storage/src/git/attestation_adapter.rs`: update ref paths from `did_key_z…` sanitized form to `did_keri_E…` sanitized form. Storage is keyed by `did:keri:` now.
- Audit the workspace for lingering `DeviceDID` references: `rg -w DeviceDID crates/ packages/` — should return zero after this chunk.

Regenerate schemas, update `docs/api-spec.yaml` for the removed `new_device_signing_pubkey` and `supersedes_attestation_rid` fields.

Verification: workspace-wide `cargo check --all-targets` + `cargo test --workspace --lib` + `cargo clippy --workspace --all-targets` + `cargo run --bin xtask -- check-curve-agnostic` + `cargo run --bin xtask -- generate-schemas` (producing zero diff if schemas already match).

### Chunk 7 — Attestation reshape

With `DeviceDID` gone and no subject surrogate, decide what attestations are *for* in Stage 1:

- **Controllership is tracked by the shared KEL.** Adding/removing a device is a `rot`, not an attestation.
- **Capabilities** (`sign_commit`, etc.) are still meaningful as attestations issued by `did:keri:You` (the shared identity) against a specific controller device's `did:keri:`.
- **Git-commit attestations** stay as before — the commit-signer is a controller of the identity, not the identity itself.

Stage 1 work: make sure `Attestation.subject = did:keri:…` works end-to-end for capability attestations, and that the storage layer indexes correctly.

### Chunk 8 — Verifier audit

Walk `crates/auths-verifier/src/verify.rs` and cross-check:
- Verifying an attestation now requires resolving a `did:keri:` subject to its KEL and checking the signing key is a current key in that KEL.
- Verifying a KEL event walks the `icp`/`rot`/`ixn` chain and validates each against the prior state.
- The shared KEL's `rot` events are verified against their prior controller set + `kt`.

Add integration tests that simulate a full pair + rotate + remove flow and verify every resulting attestation under the new verifier path.

### Chunk 9 — UX polish + verification

- `auths status` updated to show shared-KEL current state (controllers, `kt`, `nt`).
- iOS `IdentityView` shows shared-KEL DID + controller list + `kt` value.
- End-to-end tested on real iPhone + Mac:
  - Fresh `auths init` + first pair.
  - Pair a second phone.
  - Rotate Mac's keys locally (`auths identity rotate`).
  - Remove a paired device.
  - Stolen-laptop recovery: `auths pair --recover` on new Mac + phone confirms.
  - Forget identity on phone (wipes its device KEL + shared-KEL copy).

## Verification summary

At the end of Stage 1, the full check matrix should pass:

```bash
cd /Users/bordumb/workspace/repositories/auths-base/auths
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets
cargo test --workspace --lib
cargo run --bin xtask -- check-curve-agnostic
cargo run --bin xtask -- generate-schemas  # should produce no diff
cargo run --bin xtask -- validate-schemas
```

Plus in the `packages/` subworkspaces:

```bash
cd packages/auths-node && cargo clippy --all-targets
cd packages/auths-python && cargo clippy --all-targets
```

Plus the pre-commit hooks: cargo fmt, SDK boundary, spec drift gate, schema validation.

End-to-end tests on device: covered in Chunk 9's checklist.

## Things deliberately NOT in Stage 1

- **Witnesses of any kind.** Neither Rekor-as-anchor (Stage 2a) nor KERI-native witnesses (Stage 2b). The shared KEL is unanchored; dispute resolution relies on "whichever valid `rot` reaches a given verifier first" and on Secure Enclave hardness. This is the honest Stage 1 tradeoff; don't paper over it.
- **`kt ≥ 2`.** Stage 3. With kt=1, any controller can solo-rotate. Lock-out risk = zero; single-device-compromise blast radius = full. Accepted tradeoff at this scope.
- **OOBI discovery.** Not needed when the shared KEL's full replica lives on every controller device. Stage 2b adds OOBI when witnesses arrive.
- **Multi-hop supersedes / history crawling.** Gone with `supersedes_attestation_rid`. Rotation history is in the device's own KEL `s` sequence.
- **External identity federation.** `did:keri:You` is stable but we're not yet publishing it to any federation or third-party RP. That's downstream of witnesses.

## Developer migration

Pre-launch means pre-launch — there is no back-compat shim and no auto-migration tool. Dev machines that created an `~/.auths` tree under the old `refs/auths/devices/nodes/*` layout or signed commits with `did:key:z…` trailers must reset:

```bash
rm -rf ~/.auths
auths init
# then re-pair devices, re-sign any commits you want verifiable
```

Running `auths-index rebuild` against an old tree hard-fails with a message naming the deprecated prefix and suggesting the reset. The ref-sanitization scheme is also canonicalized on this branch (single function `sanitize_did` replacing the two ad-hoc variants previously scattered around the repo), so any ref-name tooling that crawled the old layout needs to be re-run after reinitialization.

Git commit trailers also change format: `Auths-Signer: did:key:z…` becomes `Auths-Signer: did:keri:E…` once attestation subjects flip to the new DID type. Old signed commits do not verify after the type flip.

## Handoff notes for a fresh LLM

If you're picking this up cold:

1. Read the two essays mentioned in "Required reading" above. They give you the architectural and historical context this plan skips.
2. Before writing any code, run `git log --oneline -20` on the `auths/` repo to see what landed in the rotation UX polish session (immediately prior work). That rotation work is what Chunk 6 mostly deletes.
3. The user has explicit "rip out, no back-compat" posture. Do not add `Option<T>` wrappers for fields that become wire-required — make them required. Do not leave deprecation shims for `DeviceDID`. Delete outright.
4. The user wants pre-commit hooks to pass cleanly. If you hit a gate, fix it in the same chunk; don't leave it for later chunks to clean up.
5. When in doubt on an open question (the 8 above), ask the user — don't silently pick. Defaults above are reasonable but not committed.
6. Work chunk by chunk. Do not interleave multiple chunks — they depend on each other.
7. For chunks that touch Swift (5 and beyond), remember that the XCFramework in the iOS project is a pre-built artifact. Every FFI change requires `just build-xcframework` in `/Users/bordumb/workspace/repositories/auths-base/auths-mobile/` + adding any new Swift files to the Xcode project's `.pbxproj` (PBXBuildFile, PBXFileReference, parent-group children, Sources build phase — four locations per new file).

## Cross-references

- Design: `/Users/bordumb/workspace/repositories/auths-base/essays/design/multi_device.md`
- Prior work (shipped): `~/.claude/plans/abundant-tumbling-peacock.md` (rotation UX polish — done, superseded by this plan)
- Philosophical framing: `/Users/bordumb/workspace/repositories/auths-base/essays/philosophy/reply_to_isi_pre_rotation.md`
- KERI spec for the `icp` / `rot` event grammar: https://github.com/WebOfTrust/keri
- KERI paper (pre-rotation, self-certifying identifiers): Smith, S. M. (2019), arXiv:1907.02143.
