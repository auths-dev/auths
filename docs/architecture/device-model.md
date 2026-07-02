# Device model: KERI delegated identifiers

Devices — and agents — are KERI **delegated identifiers** anchored by the root identity. This note describes the model as it ships today, then retains the design decision that chose it.

> **Status:** Model **D (delegation)** is **implemented and shipping.** `auths init` delegates a first device (device #0); commit verification is KEL replay against the `.auths/roots` pin; devices are independently revocable. The pre-migration attestation-based device management and `.auths/allowed_signers` allowlist described in earlier revisions of this note **no longer ship** for commit trust. Identity primitives: [identity-model.md](identity-model.md). For the broader "every trust decision KERI-native" picture (witnesses + OOBI, ACDC/TEL), see `keri-only-roadmap.md` — this is its Tier 1.

---

## The current model

### Devices are delegated identifiers

- Each device is a delegated identifier (`dip`) with its own `did:keri:` AID and its own KEL, anchored by the root via an `ixn` on the root KEL (`validate_delegation` checks both sides of the binding).
- `auths init` (developer profile) delegates **device #0** automatically, so a fresh identity already has `identity_did != device_did`. Device #0's key is stored under the device's own AID (alias `<root>-device`, e.g. `main-device`); the root key (`main`) is touched only to add or revoke a device, so it stays cold.
- Devices rotate independently (`drt`). **Agents are the same primitive** with a role marker — `device` and `agent` are one `dip`/`drt` concept, distinguished by a `DelegatedRole` (`list_delegated_devices` filters `Device`; agent listing filters `Agent`).

### Commit signing — device #0 signs, the root stays cold

- `git commit` signs with **device #0's** key: `auths init` sets git `user.signingkey = auths:<device#0 alias>` and `gpg.ssh.program = auths-sign`, so a commit gets an SSHSIG from device #0. `auths sign HEAD` then writes the in-band trailers.
- Trailers: **`Auths-Id`** = the root `did:keri:` (the policy authority), **`Auths-Device`** = the signer's `did:keri:` (device #0), **`Auths-Anchor-Seq`** = the root KEL tip observed at signing (lets a verifier order a commit against a later revocation).
- `resolve_local_signer` picks the signer uniformly: on a developer machine it is delegated **device #0** (root cold); a root with no delegated device — e.g. a CI identity — signs directly (`signer == root`); on a paired machine it is that machine's own delegated device, chaining to its delegator (`dip.di`).

### Commit verification — KEL replay against a pinned root

- Verification reads the `Auths-Id`/`Auths-Device` trailers, replays the **device** KEL (a `dip` is replayed *with the delegator lookup*, so the device's key state resolves without the root co-signing) and the **root** KEL, then checks the SSHSIG against the device's current key.
- Trust is a **pin, not an allowlist**: the root must be in `.auths/roots`, and the trailer-claimed root may only *select* a pinned root. There is **no `ssh-keygen` subprocess and no `.auths/allowed_signers`** — the `commit_trust` workflow is the successor to that allowlist.
- The result is a `CommitVerdict` (`RootNotPinned`, `RootAbandoned`, `DelegationSealNotFound`, superseded/revoked-device, valid, …).

### Revocation — independent, root-authored, order-aware

- `auths device remove --device-did <d> --key <root-key>` revokes a delegated device: a single `ixn` on the root KEL anchoring a `Seal::Digest` of the device prefix (`revoke_delegated_device`). No device key is needed, and the root identity survives.
- Revocation is **order-aware**: a commit signed *before* the revocation (its `Auths-Anchor-Seq` precedes it) stays valid; a *new* commit from a revoked device is rejected fail-closed, and signing with a revoked device is refused at sign time (`AUTHS-E5857`).

> **Use `auths device remove`, not `auths emergency`.** The registry-aware revocation path is `device remove`. The legacy `auths emergency rotate-now` / `revoke-device` commands use a separate GitKel backend that cannot see registry-backed delegated devices; rotating a delegated device's key is not yet supported.

### Attestations — still the artifact & metadata layer

Attestations did not go away; they moved off the commit-trust path.

- **Artifact signing** (`auths sign <file>`) produces a **dual-signed** attestation: the **issuer** is the root identity (its key co-signs the issuer slot) and the **device** is device #0 (its key signs the device slot). The issuer must be the root — a bundle / pinned-root verifier resolves the *issuer*, so an attestation self-issued under a delegated device does not verify statelessly.
- Attestations still carry **metadata** — capabilities, expiry, revocation, OIDC binding — that a KEL cannot hold.
- Attestations are **no longer the trust source for commit verification** (that is KEL replay + pinned roots).

---

## The design decision (Model D) — recorded 2026-06-03, implemented since

Two coherent multi-device models were considered:

- **Model D — Delegation (chosen).** Each device is a KERI delegated identifier (`dip`) of the root; the root **anchors** a delegation seal (`ixn`) to authorize a device, and a revocation `ixn` to remove it. Each device runs its own KEL and rotates independently (`drt`). This is keripy-valid, truly device-bound (each device holds only its own key), gives **single-author set changes** (an `ixn` signed by the root's *current* key — no pre-rotation reveal, no other device's private key), and **unifies devices with agents**. Its one tradeoff is a root/primary asymmetry — desirable for a developer identity (a clear root of trust); root-key loss is a recovery concern, not a per-operation one.
- **Model S — Per-device-custody shared KEL (rejected).** Keep `k[]` = device verkeys and grow/shrink the set by rotation. This founders on KERI **pre-rotation**: a rotation's new `k[]` must reveal the pre-images of prior `n[]` commitments, but a single device holds only *its own* pre-committed next key — it cannot author a keripy-valid `rot` that rotates a multi-device `k[]`. Carrying the other controllers' slots forward from public state is *auths*-valid but **not keripy-valid**.

keripy-faithfulness is a stated project value (byte-interop with keripy 1.3.4), so Model D — keripy-native, device-bound, independently rotatable, and unifying devices with agents — was chosen over formalizing a shared-KEL divergence. The delegation primitives it rests on (`DipEvent`/`DrtEvent`, `validate_delegated_inception`, `validate_delegation`, the `ixn` anchoring machinery) already existed and were tested lower in the stack; the shared-`k[]` controller helpers (`shared_kel.rs`) are retired for multi-device.

---

## Attestations vs. delegation: two layers, not rivals

They answer different questions:

- **"Is this device cryptographically part of the identity?"** — a **delegation** question, provable from the KEL alone: the device's `dip` plus the root's anchoring `ixn`, ordered, and revocable by a further `ixn`.
- **"What is this device allowed to do, and what is its email / expiry / OIDC binding?"** — an **attestation** question: metadata a KEL cannot hold.

Delegation supplies cryptographic membership; attestations supply metadata. Both stay.

---

## Open questions & accepted risks

- **kt=1 duplicity.** The root KEL runs `kt=1` with no witnesses in the default posture; concurrent rotations on different hosts can fork it. `auths_verifier::duplicity::detect_duplicity` surfaces divergence; full detail in `multi_device_accepted_risks.md`, and the threshold (`kt≥2`) upgrade path in `essays/design/multi_device.md`.
- **Stateless verification needs the device KEL.** A `--identity-bundle` verifier resolves trust from the bundle's root, but replaying a delegated-device signature needs that device's KEL and the root's anchoring `ixn` available (from a trusted registry or the bundle). How bundles carry delegated-device KELs for fully offline verification is worth confirming as the stateless path is exercised.
- **Delegated-device key rotation** is not yet supported (see the revocation note above); the current remediation for a compromised device is `device remove` + pairing a new device.
