# Security Review: Auths Identity & Attestation System

| | |
|---|---|
| **Document** | Internal Security Review — Findings Report |
| **Scope** | `auths-verifier`, `auths-id` (attestation/KERI), `auths-pairing-protocol`, `auths-pairing-daemon`, CLI pairing surface |
| **Branch reviewed** | `dev-keriCompliantDevices` |
| **Review type** | Manual source audit (white-box), design review |
| **Reviewer** | Staff Security Engineer |
| **Date** | 2026-06-01 |
| **Status** | Draft for triage |

---

## 1. Executive Summary

Auths is a decentralized, Git-native identity and code-signing system. The cryptographic core is well-constructed: signatures cover a comprehensive canonical envelope (role, capabilities, delegation, and signer-type fields are all signed and tamper-tested), curve tags are carried in-band, key material is zeroized, and the verifier is a dependency-minimal pure function suitable for embedding. The team also maintains an unusually candid internal risk register (`docs/architecture/multi_device_accepted_risks.md`), which materially improved the quality of this review.

That said, the audit identified **one Critical authorization-bypass** in the verification path, along with several High and Medium issues concentrated in three themes: (1) **fail-open defaults** in the verifier, (2) **opt-in rather than default-on security checks**, and (3) **revocation and freshness** weaknesses inherent to the serverless model that are currently unmitigated at the verifier boundary.

The Critical finding (AUTHS-2026-001) is the priority: the verifier silently skips issuer-authorization when an attestation omits its issuer signature, which allows forgery of "trusted identity vouches for attacker device" attestations. This should be fixed before any external launch.

### Findings at a glance

| ID | Severity | Title | Primary location |
|----|----------|-------|------------------|
| AUTHS-2026-001 | **Critical** | Issuer authorization skipped when `identity_signature` is absent | `auths-verifier/src/verify.rs:357` |
| AUTHS-2026-002 | **High** | Capability confinement is opt-in; default chain verification ignores capabilities | `auths-verifier/src/verify.rs:124` |
| AUTHS-2026-003 | **High** | No revocation propagation / freshness guarantee at the verifier boundary | `auths-verifier/src/verify.rs:323` |
| AUTHS-2026-004 | **High** | Fail-open duplicity policy accepts signatures from a forked shared KEL | `auths-verifier/src/duplicity.rs`; `verify.rs:1` |
| AUTHS-2026-005 | **Medium** | Attestations with no `expires_at` never expire | `auths-verifier/src/verify.rs:330` |
| AUTHS-2026-006 | **Medium** | SAS/MITM verification disabled by default during pairing | `auths-cli/.../pair/common.rs:235` |
| AUTHS-2026-007 | **Medium** | Short-code entropy (~30 bits) requires strict relay-side attempt limiting | `auths-pairing-protocol/src/token.rs:13` |
| AUTHS-2026-008 | **Low** | Divergent `ATTESTATION_VERSION` constants; no version gate at verify time | `auths-id/.../create.rs:18` vs `auths-verifier/src/core.rs:287` |
| AUTHS-2026-009 | **Low** | KERI wire-format divergence (`1AAI` code reuse, in-body `dt`) | `multi_device_accepted_risks.md`; `auths-keri` |
| AUTHS-2026-010 | **Info** | `is_device_listed` trusts caller-verified input (API-misuse hazard) | `auths-verifier/src/verify.rs:154` |

### Severity definitions

- **Critical** — Remotely/locally exploitable bypass of a core security guarantee (authentication, authorization, integrity) with no special preconditions.
- **High** — Exploitable under realistic conditions, or a security control that fails open by default; meaningful blast radius.
- **Medium** — Requires preconditions, narrows to a specific deployment mode, or weakens defense-in-depth.
- **Low** — Limited impact, correctness/hardening, or hard-to-reach.
- **Info** — Not a vulnerability; hardening guidance or misuse hazard.

---

## 2. Detailed Findings

### AUTHS-2026-001 — Issuer authorization is skipped when `identity_signature` is absent

- **Severity:** Critical
- **Component:** `auths-verifier` (core verification path)
- **Files:**
  - `crates/auths-verifier/src/verify.rs:357-371` (the skip)
  - `crates/auths-verifier/src/verify.rs:417-479` (`verify_chain_inner`)
  - `crates/auths-verifier/src/verify.rs:514-551` (`verify_single_attestation`)
  - `crates/auths-id/src/attestation/create.rs:163,193-195` (produces empty-issuer-signature attestations)

**Description.**
Attestations are designed to be dual-signed: an `identity_signature` proving the *issuer authorized* the attestation, and a `device_signature` proving the *subject device possesses* its key. The verifier checks the device signature unconditionally, but gates the issuer signature on its presence:

```rust
// verify.rs:357
if !att.identity_signature.is_empty() {
    verify_signature_by_curve(issuer_pk, data_to_verify,
        att.identity_signature.as_bytes(), provider, SignatureRole::Issuer).await?;
} else {
    debug!("(Verify) No identity signature present (device-only attestation), skipping issuer check.");
}
```

When `identity_signature` is empty, the issuer-authorization check is **silently skipped** and verification proceeds to validate only the device signature. The `Ed25519Signature::empty()` constructor and the `skip_serializing_if = "is_empty"` serde attribute on the field make an empty issuer signature a normal, serializable wire state — and `create.rs:193-195` deliberately emits exactly this shape whenever no identity alias is supplied ("device-only attestation").

The verifier provides no typed distinction between a *device-only self-assertion* (legitimately verified against the device's own key) and an *authority-bearing delegation* (which must carry an issuer signature). `verify_chain`, `verify_with_keys`, `verify_device_authorization`, and `verify_device_link` all route through `verify_with_keys_at` and therefore all inherit the skip.

**Impact.**
An attacker who controls *any* device key can forge an attestation that a trusted identity never authorized:

1. Construct `att { issuer = <victim root DID>, subject = <attacker device>, device_public_key = <attacker key>, identity_signature = empty, device_signature = <attacker self-signature over the canonical data> }`.
2. Call `verify_chain(&[att], &victim_root_pk)`.
3. At step 0, the issuer check (against `victim_root_pk`) is skipped because the signature is empty; the device signature validates against the attacker's own key; the function returns `VerificationStatus::Valid`.

The result is a complete bypass of issuer authorization — "root vouches for attacker's device with capability X" — accepted by every consumer of the verifier, including the WASM/FFI builds embedded in CI gates, git hooks, and mobile clients. The same construction forges interior chain links (set `issuer = prev.subject`) and forges device-authorization in `verify_device_link` (subject matches, issuer check skipped). The existing test `verify_at_time_signature_always_checked` (`verify.rs:933`) only exercises a *tampered* (non-empty, invalid) signature; no test asserts that an *absent* issuer signature is rejected in an authority context.

**Recommendation.**
Make the absence of an issuer signature a verification failure in any authority-bearing path. Concretely:

1. In `verify_with_keys_at`, treat an empty `identity_signature` as `AttestationError::IssuerSignatureFailed("missing issuer signature")` by default. Do **not** skip.
2. If device-only self-assertions are a genuine use case, model them as a distinct, explicit API (e.g. `verify_self_attestation(att)`), which requires `issuer == subject` and `device_public_key` to match, and which callers must opt into deliberately — never reachable through `verify_chain` / `verify_device_authorization`.
3. Add negative tests: an attestation with `identity_signature = empty()` must fail `verify_chain` and `verify_device_link`.
4. Consider making `identity_signature` a non-optional field on the authority-bearing attestation type so "absent" is unrepresentable at the type level.

---

### AUTHS-2026-002 — Capability confinement is opt-in; default chain verification ignores capabilities

- **Severity:** High
- **Component:** `auths-verifier`
- **Files:** `crates/auths-verifier/src/verify.rs:124-131` (`verify_chain`), `:73-82` (`verify_chain_with_capability`)

**Description.**
Attestations carry a signed `capabilities` list (`sign_commit`, `sign_release`, `manage_members`, `rotate_keys`) intended to scope what a delegated key may do. Capability enforcement, however, lives only in the `*_with_capability` variants. The default `verify_chain` / `verify_with_keys` entry points validate signatures and chain linkage but **do not check capabilities at all**, and they do not enforce capability *attenuation* down the chain except in the opt-in path (`verify_chain_with_capability` computes an intersection — see test `verify_chain_with_capability_uses_intersection`, `verify.rs:1356`).

**Impact.**
A consumer that calls the obvious, default `verify_chain` to validate a release-signing operation will accept a key that was only ever delegated `sign_commit`, because capabilities are never consulted on that path. Capability scoping is a primary authorization control here; making it opt-in means the secure behavior depends on every caller remembering to choose the longer function name. This is a classic "insecure default" — the safe path should be the default path.

**Recommendation.**
- Require callers to pass the operation's required capability (or an explicit `Capability::None`/"any" sentinel) so that omitting the check is a deliberate, visible choice rather than the default.
- Enforce capability attenuation (child capabilities ⊆ parent capabilities) inside `verify_chain_inner` so an interior link cannot amplify authority, independent of the final capability assertion.
- Document, at the API level, that `verify_chain` alone does not authorize an *action* — only an identity binding.

---

### AUTHS-2026-003 — No revocation propagation / freshness guarantee at the verifier boundary

- **Severity:** High
- **Component:** `auths-verifier`, design
- **Files:** `crates/auths-verifier/src/verify.rs:322-327` (revocation check), `:514-529` (`verify_single_attestation`)

**Description.**
Revocation is modeled as a field (`revoked_at`) on the attestation and as a separate signed revocation attestation. The verifier honors `revoked_at` when it is present on the object in hand:

```rust
// verify.rs:323
if let Some(revoked_at) = att.revoked_at && revoked_at <= reference_time {
    return Err(AttestationError::AttestationRevoked);
}
```

But in a serverless, Git-replicated trust model there is no mechanism that *guarantees the verifier has seen the revocation.* A verifier holding a stale clone (or handed only the original attestation bytes, as in the FFI/WASM `ffi_verify_chain_json` entry points) will validate a credential the issuer has already revoked. There is no CRL, no OCSP-equivalent, no transparency-log freshness proof, and no "this attestation must be re-checked against current KEL state" requirement at the verification boundary.

**Impact.**
Revocation is the control you reach for *after* a compromise. If a verifier can be kept from learning about a revocation — by network partition, a stale mirror, or simply being passed the raw attestation without the surrounding repository — a revoked (e.g. stolen-laptop) device key continues to verify as valid. For a system whose recovery story depends on `auths device remove` / revocation, the lack of a freshness guarantee materially weakens that story.

**Recommendation.**
- Define and document a **freshness contract** for high-assurance verification: require the verifier to be supplied current shared-KEL/registry state as of a stated timestamp, and surface that timestamp in `VerificationReport`.
- For embedded (FFI/WASM) verification, accept an explicit revocation set / KEL tip and fail-closed (or warn) when it is absent, rather than silently verifying against only the attestation bytes.
- Consider short default `expires_at` lifetimes (see AUTHS-2026-005) so that absent-revocation exposure is time-bounded by design — short-lived credentials are the standard mitigation when revocation propagation is weak.

---

### AUTHS-2026-004 — Fail-open duplicity policy accepts signatures from a forked shared KEL

- **Severity:** High (accepted risk — documented; raised here for completeness and to track the mitigation)
- **Component:** `auths-verifier`
- **Files:** `crates/auths-verifier/src/duplicity.rs` (detector), `crates/auths-verifier/src/verify.rs:1-11` (policy rationale)

**Description.**
The shared identity KEL runs with key threshold `kt=1` and no witnesses, so two controllers can each sign a valid `rot` at the same sequence number, permanently forking the log. `detect_duplicity` (`duplicity.rs:82`) correctly identifies divergence — grouping by `(prefix, seq)` and reporting differing SAIDs as `DuplicityReport::Diverging` — but the policy is **fail-open by design** (`verify.rs:3-11`): a diverging KEL is surfaced as `VerificationReport::duplicity_warning` and does **not** invalidate an otherwise-valid signature.

The rationale is documented and defensible (fail-closed would convert one bad rotation into a workspace-wide outage). It is recorded here because, until the threshold upgrade lands, it remains an accepted but real gap: a malicious or compromised controller can present a forked controller set, and verifiers will accept signatures from it pending out-of-band human resolution.

**Impact.**
Bounded — each controller replicates the full shared KEL, so the universe of conflicting claims is the identity's own devices, not arbitrary third parties. Nonetheless, "first valid event seen locally" is the only ordering, and a compromised controller that rotates first can present an attacker-favorable controller set until the user runs `auths device remove`.

**Recommendation.**
- Track to closure via the planned `kt ≥ m`-of-`n` threshold upgrade (Epic 2 in the risk register), which eliminates the fork by construction — no single controller can satisfy threshold.
- In the interim, ensure `duplicity_warning` is *surfaced prominently* (CLI status non-zero exit, CI gate failure option, mobile banner) rather than buried in a structured field that downstreams may ignore — give security-sensitive consumers an easy way to choose fail-closed.

---

### AUTHS-2026-005 — Attestations with no `expires_at` never expire

- **Severity:** Medium
- **Component:** `auths-verifier`, `auths-id`
- **Files:** `crates/auths-verifier/src/verify.rs:330-336`, `:531-542`; `crates/auths-id/src/attestation/create.rs:155`

**Description.**
`expires_at` is `Option`. Expiry is only enforced when it is `Some` (`verify.rs:330`). An attestation minted without an expiry is valid forever, subject only to (unreliable — see AUTHS-2026-003) revocation.

**Impact.**
Non-expiring credentials maximize the blast radius of any key compromise and remove the natural backstop for weak revocation propagation. Combined with AUTHS-2026-003, an attacker holding a non-expiring, un-revoked (because un-propagated) attestation retains validity indefinitely.

**Recommendation.**
- Require `expires_at` for device and delegation attestations (make it non-optional on those types), or enforce a maximum lifetime at creation time in `create_signed_attestation`.
- Default to short lifetimes with renewal, consistent with modern short-lived-credential practice.

---

### AUTHS-2026-006 — SAS / MITM verification is disabled by default during pairing

- **Severity:** Medium
- **Component:** CLI pairing
- **Files:** `crates/auths-cli/src/commands/device/pair/common.rs:235-250`, `:80-107` (`prompt_sas_confirmation`)

**Description.**
Pairing derives a Short Authentication String from the ECDH transcript to detect a man-in-the-middle. By default (`verify_sas = false`), the SAS is *printed for reference* but no confirmation blocks completion; the interactive check is reachable only via `auths pair --verify`:

```rust
// common.rs:235
if verify_sas {
    let confirmed = prompt_sas_confirmation(&sas_bytes)?;
    if !confirmed { display_sas_mismatch_warning(); drop(transport_key); anyhow::bail!(...); }
} else {
    // print SAS, continue
}
```

The design treats the QR scan as the authenticated out-of-band channel (the Signal/WhatsApp model), which is a reasonable product decision for LAN pairing where the QR travels screen-to-camera. The risk concentrates in **relay/online mode**, where the channel is not inherently out-of-band and an active network attacker between the two devices is in scope.

**Impact.**
In relay mode without `--verify`, a MITM who can sit between initiator and responder during the 5-minute window could complete a pairing the user believes is authenticated. The attestation payload itself is protected by a ChaCha20-Poly1305 transport key derived from the ECDH secret, so confidentiality of the payload holds against a passive attacker — but an *active* MITM that completes its own ECDH with each side is precisely what the SAS exists to catch, and that catch is off by default.

**Recommendation.**
- Make SAS confirmation **default-on for relay/online pairing**, and opt-out (`--no-verify`) rather than opt-in. LAN-with-QR may retain the streamlined default.
- Where SAS is skipped, state explicitly in the UI which channel is being trusted as out-of-band, so the user can judge whether that assumption holds on their network.

---

### AUTHS-2026-007 — Short-code entropy (~30 bits) depends on strict relay-side attempt limiting

- **Severity:** Medium
- **Component:** `auths-pairing-protocol`, `auths-pairing-daemon`
- **Files:** `crates/auths-pairing-protocol/src/token.rs:13-14`

**Description.**
The pairing short code is 6 characters over a 31-symbol confusable-free alphabet:

```rust
const SHORT_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ"; // 31 symbols
const SHORT_CODE_LEN: usize = 6;
```

That is 31⁶ ≈ 8.9×10⁸ combinations, ≈ **29.7 bits** of entropy. For LAN mode this is comfortable. For relay mode, where a remote party may attempt to join a session by short code, ~30 bits is only safe if the relay enforces strict per-session attempt limits and short expiry; without that, it is within reach of online guessing against a pool of concurrent sessions.

**Impact.**
If the daemon/relay does not tightly bound guesses per session and per source, an attacker could brute-force or pool-attack active pairing sessions to hijack a join. (This review did not locate explicit rate-limit constants via grep in the daemon crate; that absence should be confirmed, not assumed — see methodology.)

**Recommendation.**
- Confirm and document the relay's per-session attempt limit, lockout, and session TTL. Fail-closed after a small number of wrong codes; bind attempts to the session ID and source.
- Consider raising the code to 8 characters (~40 bits) for relay mode, or gating relay joins behind the full pairing token rather than the short code alone.

---

### AUTHS-2026-008 — Divergent `ATTESTATION_VERSION` constants and no version gate at verification

- **Severity:** Low
- **Component:** `auths-id`, `auths-verifier`
- **Files:** `crates/auths-id/src/attestation/create.rs:18` (`= 1`), `crates/auths-verifier/src/core.rs:287` (`= 2`)

**Description.**
Two constants named `ATTESTATION_VERSION` disagree: the creation path stamps `version = 1` while the verifier crate declares `2`. The `version` field is part of the signed canonical envelope, but the verifier does not appear to gate on a supported-version set during `verify_with_keys_at` — it verifies whatever version it is given as long as the signature matches.

**Impact.**
Low today (pre-launch, zero users, no compatibility burden), but the divergence is a latent correctness/interoperability hazard: producers and verifiers labeling the same wire format with different version numbers undermines any future version-based migration or rejection logic, and the absence of a version gate means a future deprecated/insecure version could not be cleanly refused.

**Recommendation.**
- Collapse to a single source-of-truth constant (re-export from one crate).
- Add an explicit supported-version check at the start of verification; reject unknown versions with a typed error.

---

### AUTHS-2026-009 — KERI wire-format divergence from ToIP spec

- **Severity:** Low (correctness/interop; not directly exploitable)
- **Component:** `auths-keri`, identity event encoding
- **Files:** `docs/architecture/multi_device_accepted_risks.md`; `docs/plans/keri_compliance.md`; `auths-keri/src/keys.rs`, `said.rs`

**Description.**
The risk register documents several deviations from ToIP KERI v1.1: an in-body `dt` timestamp that enters the SAID, a signing path that clears `d`/`i` after computing the version string, a mobile FFI duplicate of `IcpEvent` carrying an in-body `x` signature, and the use of CESR code `1AAI` (the spec's *non-transferable* P-256 verkey code) for transferable identities. The team's own assessment: internally consistent, but cross-implementation interop with KERIpy/KERIox/Signify is currently broken.

**Impact.**
Primarily interoperability and semantic correctness rather than direct exploitability. The `1AAI` reuse is the one with security flavor: a strict third-party KERI verifier could misinterpret transferability (treating a rotatable identity as non-transferable, or vice versa), which is a silent-correctness hazard if Auths identities are ever consumed outside the Auths verifier.

**Recommendation.**
- Track to the planned KERI-compliance epic. Prioritize correcting the `1AAI`/transferable mismatch and removing in-body fields from the SAID preimage, as those carry semantic rather than merely cosmetic risk.
- Until parity is reached, document clearly that Auths identities are only safely verified by the Auths verifier.

---

### AUTHS-2026-010 — `is_device_listed` trusts caller-verified input (API-misuse hazard)

- **Severity:** Informational
- **Component:** `auths-verifier`
- **Files:** `crates/auths-verifier/src/verify.rs:154-181`

**Description.**
`is_device_listed` operates over `&[VerifiedAttestation]` and applies issuer/subject/revocation/expiry filters — but it performs no signature verification itself; it relies on the `VerifiedAttestation` type having been produced through a real verification path. The type-state pattern is good, but `VerifiedAttestation::dangerous_from_unchecked` (used in tests) exists, and a careless caller could construct the "verified" wrapper without verifying.

**Impact.**
Not a vulnerability in itself; a misuse hazard. If a consumer ever wraps unverified attestations in `VerifiedAttestation`, every downstream check that trusts the type is bypassed.

**Recommendation.**
- Keep `dangerous_from_unchecked` `#[cfg(test)]`-only or `#[doc(hidden)]` with a deny-by-default lint, so it cannot be reached from production code.
- Document the type-state contract on `VerifiedAttestation` explicitly.

---

## 3. Positive Observations

A security review should record what is done well; these reduce risk and should not regress.

- **Comprehensive signed envelope.** `role`, `capabilities`, `delegated_by`, `signer_type`, and `commit_sha` are included in the canonical signing data, with explicit tamper tests (`verify.rs:1417-1504`) proving each field is signature-protected. This closes a large class of field-injection attacks.
- **In-band curve tagging.** The architecture forbids length-based curve dispatch and parses to curve-aware typed values (`KeriPublicKey`, `DecodedDidKey`, `TypedSeed`). This eliminates a real silent-misrouting hazard.
- **Key zeroization.** `TypedSeed` and the pairing `TransportKey` are `Zeroize`/`ZeroizeOnDrop` and move-consumed, preventing reuse and reducing memory-exposure windows.
- **Pre-rotation.** The next-key commitment model (`rotation.rs`) means a stolen *current* signing key cannot rotate the identity — strong forward security for the identity itself.
- **Minimal-dependency verifier.** No `git2`, no HTTP in the verification core; pure-function verification suitable for WASM/FFI sandboxing.
- **Clock injection.** `Utc::now()` is banned in domain code; time is injected, making time-dependent logic testable and deterministic (`MAX_SKEW_SECS`, `verify_at_time`).
- **Honest internal risk register.** `multi_device_accepted_risks.md` documents the `kt=1`, no-witness, and interop gaps in plain language. This is rare and valuable.

---

## 4. Prioritized Remediation Plan

| Priority | Findings | Rationale |
|----------|----------|-----------|
| **P0 — before launch** | AUTHS-2026-001 | Critical authorization bypass; small, well-scoped fix. |
| **P1 — before launch** | 002, 003 | Insecure defaults / freshness gaps in the core authorization story. |
| **P2 — fast follow** | 004, 005, 006, 007 | Threshold upgrade (004) is the strategic fix; 005–007 are bounded hardening. |
| **P3 — backlog** | 008, 009, 010 | Correctness, interop, and API-misuse hardening. |

---

## 5. Methodology & Caveats

- **Approach:** White-box manual source review of the verification, attestation-creation, duplicity-detection, and pairing paths, plus design review against the project's architecture and risk documents.
- **Directly read and confirmed:** `auths-verifier/src/verify.rs` (verification logic, lines cited), `auths-verifier/src/duplicity.rs`, `auths-id/src/attestation/create.rs` (signing path), `auths-pairing-protocol/src/token.rs` (short-code parameters), `auths-cli/.../pair/common.rs` (SAS gating).
- **Caveats:** Line numbers reference the reviewed branch and will drift. Findings AUTHS-2026-007 (relay rate-limiting) and AUTHS-2026-009 (KERI interop) are partly informed by project documentation and a targeted grep rather than exhaustive reading of the daemon and `auths-keri` internals; both are flagged for confirmation rather than asserted as exploitable. No dynamic testing, fuzzing, or proof-of-concept exploitation was performed — findings are from static analysis and should be validated with regression tests as part of remediation.
- **Not in scope this pass:** keychain/platform-credential integration, the registry/storage adapters' concurrency and atomic-write guarantees, witness-receipt validation internals, and the OIDC binding path. Recommend a follow-up pass covering these.
