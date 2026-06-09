# Compliance & Federation: Accepted Risks

This document is the operational source of truth for the tradeoffs we ship with in
the compliance-as-a-query and federation-as-attestor surfaces. It mirrors
`docs/architecture/multi_device_accepted_risks.md`: each risk is stated plainly,
with the mitigation that is **enforced by code**, not asserted by prose.

The governing principle — *"the objection we most fear is answered by code, not
marketing"* — is enforced by the honesty-surface regression test
(`crates/auths-sdk/tests/cases/honesty_surface.rs`), which fails CI if any surface
reintroduces an over-claim.

---

## 1. Single-operator witness gate (until ≥3 independent operators)

**Risk.** Our append-only, non-equivocated transparency log is, today, cosigned by
witnesses we run ourselves. A third party is right to call self-run witnesses
"theatre": three signatures from one operator in one infrastructure zone are **not**
independence.

**What we ship.** Full single-org / internal-audit value, immediately. Every
compliance surface (evidence packs, framework reports, the monitor, CLI output)
carries an honest `equivocation_visibility` / `HonestyCeiling` computed from the
**live** witness-policy load:

- With the placeholder / single-operator policy (the reality today),
  `WitnessPolicy::load` fails closed and the ceiling renders `policy_met: false`
  ("single-operator — not yet independent"). No surface emits a bare
  `non_equivocation: true`.
- The strong third-party non-equivocation claim **lights up automatically** only
  when ≥3 real, independent operator keys land (`spans_distinct` over distinct
  operators / organizations / jurisdictions / infra zones passes, and the pinned
  key is no longer the `REPLACE_WITH_…` placeholder).

**Enforced by.** `load_witness_policy` / `ceiling_for_policy_load` (fail-closed);
`auths-monitor` disclaims independence (`policy_met == false` →
"fork-detection only; does NOT assert independent-operator non-equivocation"); the
honesty-surface test bans the bypass paths (`.unwrap_or(unconstrained())`, a bare
non-equivocation flag, a `Utc::now()` in pack generation).

**Out of scope here.** Recruiting and pinning ≥3 unaffiliated operators is an
org-process milestone (Epic W / fn-156), tracked in the out-of-scope issue — it
gates *claims*, not *code*.

---

## 2. SCIM static-bearer provisioning channel

**Risk.** SCIM clients (Okta, Entra) speak only a static bearer token — a tension
with our DeviceDID-signature default. A leaked token lets an attacker drive the
provisioning control channel.

**What we ship.** The bearer token authenticates the **channel only**; the
provisioned *identity* is always a real delegated KERI identity (`add_member`), never
a fake DID. The token is:

- per-tenant and scoped to the provisioning control channel only;
- stored only as a SHA-256 hash (the plaintext never lives in server state),
  compared in constant time;
- rotatable (`auths scim rotate-token`).

A breach of the channel can provision or deprovision members, but it cannot forge
the org root, rotate keys, or mint authority — those require the org signing key.

**Enforced by.** `auths-scim-server` (`TenantConfig` hashes at rest; `authenticate_token`
is constant-time); the KEL is authoritative; any Postgres index is a derived
`externalId → prefix` idempotency cache only.

---

## 3. Soft-disable is not revocation

**Risk.** Treating a SCIM `active:false` (deprovision) as a cryptographic
off-boarding would over-claim: a deprovisioned member whose KERI identity is not yet
revoked is **still authority-bearing**.

**What we ship.** Deprovision ≠ revocation, honestly surfaced:

- `PATCH {active:false}` and `DELETE` are reversible soft-disables that **never**
  touch the KEL; `GET /Users/{id}` reports `active:false revoked:false` — still
  KERI-authoritative until hard-revoked.
- A distinct, explicit `POST /Users/{id}/revoke` triggers the irreversible
  `revoke_member` (a signed `SignedOffboardingRecord`); reactivation after a
  hard-revoke is rejected (re-onboard required).

**Enforced by.** `auths-scim-server::lifecycle` (the server-authoritative `revoked`
extension flag; the soft-disable test proves no `SignedOffboardingRecord` is emitted).

---

## 4. Point-in-time authority requires an in-band signing position

**Risk.** "Was the signer authorized **at release**?" is the #1 compliance trap.
Re-resolving authority against HEAD would retroactively invalidate artifacts a
since-revoked member signed while authorized — or worse, silently bless artifacts
signed after revocation.

**What we ship.** Authority-at-release is ordered strictly by **KEL position**, never
wall-clock, via `classify_authority_at_signing`. Its `RejectedRevokedPositionUnknown`
arm **fail-closes**: an artifact lacking an in-band signing position
(`Auths-Anchor-Seq`) cannot be ordered, so it is conservatively rejected, not assumed
authorized. Framework predicates (SLSA VSA) carry the pack's classification verbatim —
no HEAD re-resolution.

**Enforced by.** `domains/org/audit.rs` (`AuthorityAtSigning`, KEL-position ordered);
the compliance-query tests (`revoked_member_still_shows_authorized_at_release`,
`vsa_preserves_point_in_time_authority`).

---

## 5. Transparency-layer curve map (by key-holder and hardware)

**Risk.** The transparency stack mixes curves, which looks like it contradicts the
P-256 default. It does not — each curve is dictated by *who holds the key and on what
hardware*, and every byte is in-band curve-tagged (we never dispatch on key length).

| Key | Curve | Holder / hardware | Why |
|-----|-------|-------------------|-----|
| Identity / device signing key | **P-256** | The user, on the iOS Secure Enclave | The Secure Enclave only does P-256 (not Ed25519). Hardware-backed mobile pairing + laptop-loss-recovery-via-mobile **require** P-256 — this is *why* P-256 is the default. |
| Rekor **checkpoint** signature | **ECDSA-P256** (alg `0x02`) | The log operator's server key | The public Sigstore Rekor log signs its checkpoints with ECDSA-P256; we verify against it (fn-157.6). |
| Witness **cosignature** | **Ed25519** (C2SP alg `0x04`) | The commons operators' server keys | C2SP tlog-witness mandates Ed25519 cosignatures. These are server keys — no Secure Enclave involved. A mobile device **never** signs a cosignature; it only *verifies* one. |

The Ed25519 witness requirement is **externally mandated** (C2SP), in-band-tagged, and
**orthogonal** to the iOS P-256 constraint. It is **not** a violation of the P-256
default: the default governs the user's identity/device keys, not third-party log or
witness server keys.

**Enforced by.** The wire-format curve-tagging rule (`docs/architecture/cryptography.md`);
`compute_key_id` / checkpoint verification carries the algorithm tag in-band.

---

## 6. What a compliance pack does NOT prove

A compliance evidence pack proves **continuity, authority-at-release, and
(eventually) non-equivocation** over the org's own append-only log. It deliberately
does **not** prove:

- **Real-world identity.** A `did:keri:` is a self-certifying key, not a verified
  legal person. The IdP federation layer adds *attestations* about a subject
  (employed / group-member / suspended), but an IdP attestation is a **signal**, never
  a capability grant — there is no `IdpAttestation → Grant` path (the
  `idp_attestation_cannot_grant` test enforces this).
- **Third-party non-equivocation**, while the witness commons is single-operator
  (§1). The pack says `SingleOperator`, not "independently non-equivocated".
- **Capability or behaviour.** The pack records *who was authorized to sign what, and
  when by KEL order* — not that the artifact is free of vulnerabilities or that the
  signer behaved correctly.

---

## References

- Witness commons (operator recruitment): `.flow/specs/fn-156.md`, Epic W
- Honesty surface test: `crates/auths-sdk/tests/cases/honesty_surface.rs`
- Multi-device template + P-256 rationale: `docs/architecture/multi_device_accepted_risks.md`
- Wire-format curve tagging: `docs/architecture/cryptography.md`
- Point-in-time authority: `crates/auths-sdk/src/domains/org/audit.rs`
