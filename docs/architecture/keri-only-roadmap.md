# What "KERI only" actually costs — roadmap

**Status:** Scoping record (2026-06-02). Companion to `device-model.md`. This is the honest gap
between today's product and the claim *"a KERI-based identity platform that does everything it does
today, with KERI only."*

**Thesis.** "KERI only" means **every trust decision is derived by replaying a KEL** — never from a
side channel. Two side channels carry trust today, and two KERI subsystems that the claim depends on
do not exist yet:

- **Attestations** (issuer-signed JSON) bind devices *and* carry capabilities, roles, OIDC bindings,
  and org/agent delegation.
- **`allowed_signers`** (an SSH allowlist) is the trust root for commit verification.
- **Witnesses / OOBI** — KERI's mechanism for a third party to obtain and trust your KEL — is a noop.
- **ACDC / TEL** — KERI's credential and revocation-registry layer — does not exist.

## What each capability rides on today

| Capability | Trust mechanism today | KERI-native target | Exists? |
|---|---|---|---|
| Identity inception | KEL `icp` | KEL `icp` | ✅ already KERI |
| Key rotation | KEL `rot` | KEL `rot` | ✅ already KERI |
| Data anchoring | KEL `ixn` seals | KEL `ixn` seals | ✅ already KERI |
| Device membership | issuer-signed attestation | shared-KEL controllers (`k[]`) | model exists, **dormant** |
| Device removal / revocation | attestation `revoked_at` flag | shrink-`k` rotation | **core built** (Epic B), unwired |
| Commit-signing trust | SSH `allowed_signers` allowlist | KEL replay → "is this key authorized now?" | ❌ |
| Capabilities / roles | attestation fields | ACDC credential | ❌ |
| OIDC binding (CI / agents) | attestation field | ACDC credential | ❌ |
| Org / team / agent delegation | attestation `delegated_by` | KERI `dip`/`drt` (or ACDC) | events exist, **unused for this** |
| Third-party verifiability | trust-on-first-sight (local KEL) | witnesses + OOBI | ❌ (noop client only) |
| Credential revocation | in-memory registry / flag | TEL registry | ❌ |

The KEL today is a thin spine (inception + rotation + anchoring). Everything about *who may act for an
identity* is decided off the KEL.

---

## Tier 1 — Make the KEL the trust root (identity · devices · commit verification)

**Goal:** device membership and commit-signing authority are read from KEL replay, not from
attestations and `allowed_signers`.

**Already exists:**
- Shared-KEL controller model (`shared_kel.rs`: `ControllerDescriptor`, `rot_add_controller`,
  `rot_remove_controller`, `resolve_controller_index`) — built and unit-tested, **zero callers**.
- True shrink-`k` removal: dual-index CESR signatures + a validator that binds each signature to the
  prior commitment it reveals, plus `rotate_registry_identity_multi(.., remove_indices)` authoring —
  **built, tested, keripy-byte-verified** (Epic B).
- Per-device KELs (`device_kel.rs`), full `icp`/`rot`/`ixn`/`dip`/`drt` event surface, replay + validation.

**Work items:**
- `auths init` incepts the identity as a (single-controller) **shared** KEL, so the model is uniform.
- `auths device link` / `pair` → growth rotation (`rot_add_controller`); the device joins `k[]`.
- `auths device remove` / `revoke` → shrink rotation: SDK `remove_device()` workflow + CLI wiring;
  retire `RemovalNotYetSupported`.
- **Rewrite commit verification** to locate the controlling KEL, replay it, and confirm the signing
  key is currently authorized — then confirm the chain to the claimed identity. Demote `allowed_signers`
  to a derived cache regenerated from KEL state, or remove it.
- Resolve device → identity by KEL chain, not attestation lookup; `status` / `device list` read `k[]`.

**Decisions to settle first** (see `device-model.md` §5): `revoke` vs `remove` semantics, `kt=1`
vs `kt≥2`, whether `init` is always-shared.

**Size:** bounded epic. The cryptographic core is done; the rest is wiring and a verification rewrite.

---

## Tier 2 — Witnesses + OOBI (third-party verifiability without trust-on-first-sight)

**Goal:** a verifier who has never seen your identity can **obtain and trust** your KEL state, and
duplicity is detectable beyond one local replica. This is what makes it KERI rather than "a KEL we
hand around."

**Already exists:**
- Witness *client* abstraction (`WitnessProvider` / `AsyncWitnessProvider`), `NoOpAsyncWitness`
  (returns a dummy `rct`), first-seen tracking and agreement scaffolding (`first_seen.rs`,
  `agreement.rs`), a `Receipt` type, and an `auths witness` CLI surface.
- `auths_verifier::duplicity::detect_duplicity` (local read-only fork detector).

**Work items:**
- A **real witness service** (only a doc-comment `HttpWitness` stub exists today): accept events,
  store and serve receipts.
- Make `Rct` (receipt) a first-class, validated artifact — receipts are not replayable KEL events today.
- **OOBI** discovery/resolution so verifiers can fetch KELs they've never seen (none today).
- **Key State Notices** / query-reply so a verifier gets current state without the full log.
- Make witness receipts the ordering source for `detect_duplicity`, wired into controller add/remove
  and verification.

**Size:** serious infrastructure build. **Required either way** — without it, any verification by
someone other than you is trust-on-first-sight, which is the documented `kt=1` duplicity hole.

---

## Tier 3 — ACDC + TEL (the non-identity features attestations secretly carry)

**Goal:** capabilities, roles, OIDC bindings, and org/agent delegation become KERI-family verifiable
credentials with KERI-native revocation — not bespoke attestations. This is the part hiding inside the
word *"everything."* Attestations are doing **credential** work, which KERI proper pushes to ACDC.

**Already exists:** nothing for ACDC or TEL. (`dip`/`drt` delegation events exist in the KEL but org
delegation rides on attestation `delegated_by`, not those events. The only "revoke" today is an
in-memory agent-registry call.)

**Work items:**
- **ACDC** credential type + issuance/verification, replacing attestation-borne capabilities, roles,
  and OIDC bindings.
- **TEL** (transaction event logs) / credential registries for issuance and revocation.
- Migrate org / team / agent **delegation** onto KERI `dip`/`drt` (events already exist) and/or ACDC,
  off attestation `delegated_by`.

**Size:** a second protocol subsystem, effectively from scratch — the multi-quarter part.

---

## The decision this forces

You cannot honestly say *"everything it does today, with KERI only"* without **Tier 3**, because
attestations carry credential-grade features (capabilities, roles, OIDC, delegation), not just device
identity. So the choice is product scope, not engineering:

- **Option A — narrow the claim to Tier 1 + 2.** "KERI identity, device membership, and commit-signing
  trust, verifiable by anyone." Honest, achievable; Tier 1's hard part is done. You drop or defer
  capabilities/roles/OIDC/org-delegation as advertised "KERI" features (they remain, as a non-KERI
  layer, but you don't claim them under the banner).
- **Option B — commit to Tier 3.** Build ACDC + TEL so every advertised feature is KERI-family. The
  full-fidelity, much larger path.

**Tier 2 is required under either option** the moment a third party needs to verify anything.

See `device-model.md` for the verified current state and the Tier-1 wiring detail.
