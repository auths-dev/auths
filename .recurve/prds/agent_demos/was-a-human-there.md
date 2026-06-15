# PRD: was-a-human-there? — making "a human approved" a checkable fact

> **One line:** an agent is about to wire the money / merge to prod / drop the
> database, policy says a human must approve, and today "a human approved" is a
> row in a log you *trust* — here the approval carries a **verifiable custody
> attestation**, so a remote verifier can cryptographically tell *enclave key +
> human-presence gate* from *software key / server automation*, with no biometric
> ever leaving the device.
>
> **Honest status up front:** this is a **SPIKED / research-grade** demo. It rides
> on aspirational claim **AGT-2**, whose baseline (2026-06-14) found that **no
> custody dimension exists in a verifier verdict today** — `PresentationVerdict`
> (`../auths/crates/auths-verifier/src/presentation.rs:140`) has variants for key,
> audience, nonce, TTL, and credential validity, and *nothing* for presence/custody.
> Closing AGT-2 means signing a new custody class into the attestation **and**
> teaching the verifier a custody dimension — real platform surface, not a wiring
> tweak. This demo is therefore the **most likely entry to PARK** in a burndown:
> it needs the Secure-Enclave simulator (from `lost-the-laptop`) present to even
> probe, and the property it proves does not exist yet. We say so on stage. No hype.

---

## 1. One line + the scenario

**The moment.** 02:14 on a Saturday. An incident-response agent has root on the
billing cluster and a remediation that ends in `DROP TABLE ledger_shadow`. Policy
is unambiguous: *a destructive production action requires a human to approve.* The
agent pauses, raises an approval request, and a human on call — phone in hand —
taps **Approve**, passing Face ID. The action proceeds. The ledger survives.

**How it breaks today.** Three weeks later, in the post-incident review, someone
asks the only question that matters: *was a human actually there, or did a
runbook auto-approve itself at 2am?* The answer is a row in an audit log:
`approved_by=oncall-rotation, method=mobile, ts=...`. That row was **written by
the same system being audited**. A service account with the on-call's token, a
CI job replaying a saved approval, a compromised automation that flips
`approved=true` — every one of them produces a byte-identical log entry. "A human
approved" is a *trusted assertion*, not a *checkable fact*. The auditor, the
regulator, the insurer, the counterparty: none of them can verify it
independently. They take the platform's word.

**What auths does.** The human's **Approve** tap is a signature from a key that
lives in the device's Secure Enclave, released only behind a biometric/presence
gate, and the approval carries a **signed custody class** — `enclave+presence` —
bound into the delegated credential at issuance. A remote verifier, replaying the
presentation, surfaces a **custody dimension** in its verdict:
`custody=human-present (enclave)`. A server automation signing with a software key
and *claiming* the enclave class is **rejected on custody grounds** — its
attestation does not root in an enclave-anchored custody seal. "A human was in
the loop" stops being a log entry you trust and becomes a property a stranger can
check. And the biometric itself **never leaves the device** — only the
enclave-gated signature does.

---

## 2. The property it proves — and who can't match it

**Property: verifiable human-present custody attestation.** A third-party verifier
can cryptographically distinguish a signature produced by *an enclave key released
behind a human-presence/biometric gate* from one produced by *a software key or
server automation* — and the biometric never crosses the FFI boundary or the wire.
The verdict carries a **custody class**, not just a boolean "valid".

**Why incumbents structurally can't make this claim:**

- **Apple passkeys / Secure Enclave.** Apple *has* the hardware: a Secure Enclave
  P-256 key, released only behind LocalAuthentication / biometric, is exactly the
  primitive. But Apple exposes **no third-party-checkable custody class.** A
  relying party gets a WebAuthn assertion with `UV` (user-verified) and `UP` flags
  — *Apple's* attestation, meaningful only inside Apple's ceremony to a server that
  trusts Apple's attestation root. There is no portable, self-certifying object a
  *remote* verifier can replay offline to assert "this signature was human-present"
  about an arbitrary agent action on an arbitrary registry. The enclave is there;
  the **verifiable custody class for third parties is not.**
- **OIDC `amr` / `acr` claims.** `amr=["mfa","hwk"]` / `acr=...` *say* "a human
  authenticated with a hardware key" — but they are **IdP-asserted strings in a
  token the IdP minted.** They are exactly the "trust the log" failure with a JWT
  wrapper: the assurance is only as good as your trust in the issuing IdP, and the
  IdP can mint `amr=mfa` for a service account. No cryptographic binding to an
  actual enclave-gated signature on *this specific action* travels with the claim.
- **Generic "human approved" audit logs / approval gates.** Self-asserted by the
  audited system. Forgeable by anyone who can write the log.

auths' difference is *self-certifying*: the custody class is signed **into the
delegation/attestation** and verified by replay against a KEL the verifier already
trusts — no IdP, no Apple attestation root, no phone-home, offline-checkable.

---

## 3. Goals

- **G1 — Reuse the real enclave simulator.** The custody signal comes from the
  Secure-Enclave / mobile-FFI harness `lost-the-laptop` **already built**
  (`app/LostLaptop/Core/DeviceKey.swift` — a true `SecureEnclave.P256.Signing`
  key on device, software-backed and *labelled as such* on the simulator;
  `../auths/crates/auths-mobile-ffi/src/signature.rs` converting the SE's DER
  signature to wire form). **Do NOT invent a new fake enclave.** The honest
  simulator-emulation disclosure (`lost-the-laptop` GAPS LTL-7, `permanent`) is
  inherited verbatim.
- **G2 — A verifier verdict that carries a custody dimension.** Extend the
  presentation/verdict path so a successful verify surfaces a custody class
  (`human-present (enclave)` vs `software` vs `ephemeral-ci`) — the dimension
  AGT-2's baseline found absent.
- **G3 — The forgery this claim exists to prevent is rejected.** A **software key
  claiming the enclave custody class is REJECTED on custody grounds** — not merely
  flagged, not downgraded silently. This is the load-bearing adversarial result:
  without it, the custody class is theater.

---

## 4. Functional requirements as claims

Each FR is a probe-able **observable** (accept) plus an **adversarial twin**
(fail-closed). All map to **AGT-2**. Probes follow the `death-of-the-api-key` /
`lost-the-laptop` house style (exit `0` GREEN, `1` RED, `2` BROKEN). The probe
filename convention mirrors the demos: `probes/wht-<n>.sh`.

> **NON-NEGOTIABLE — do not stub the enclave.** A *faked* attestation is the exact
> fabrication AGT-2 exists to prevent. The custody signal MUST come from the real
> `lost-the-laptop` SE harness (`SecureEnclave.isAvailable` true, software-backed
> on sim, disclosed). **If the enclave simulator is unavailable, the probe MUST
> exit BROKEN(2) — never GREEN.** Absence of the enclave is absence of evidence,
> not evidence of presence. A probe that synthesizes a custody attestation in
> shell is itself the forgery the claim forbids and is a hard failure of review.

- **FR-1 (AGT-2) — `probes/wht-1.sh` — a human-present approval carries a
  verifiable custody class.**
  **Accept:** an approval signed by the SE-backed key behind the presence gate
  produces an attestation whose custody class is `enclave+presence`, and
  `auths verify` of the resulting presentation surfaces `custody=human-present
  (enclave)` in its verdict. **Adversarial twin:** the *same* verify of a
  software-key / automation approval surfaces `custody=software` (or `ephemeral`),
  never `human-present` — the two are distinguishable by a stranger.
  *BROKEN(2) if the SE sim is not present.*

- **FR-2 (AGT-2) — `probes/wht-2.sh` — a software key claiming enclave custody is
  rejected on custody grounds (the core forgery).**
  **Accept (the rejection IS the accept):** a software/automation key that mints an
  attestation *asserting* the `enclave+presence` custody class — without an
  enclave-anchored custody seal — is **REJECTED** by `auths verify`, with a verdict
  that names *custody* as the reason (not a generic invalid-signature). **Adversarial
  twin:** the honest enclave approval from FR-1 still verifies — the gate rejects the
  forgery without breaking the real one (no false-positive that would make the gate
  worthless). *BROKEN(2) if the SE sim is not present — never silently GREEN.*

- **FR-3 (AGT-2) — `probes/wht-3.sh` — the biometric never leaves the device.**
  **Accept:** across the full approve→present→verify flow, the only material
  crossing the FFI boundary / the wire is a *public key* and a *signature* (the
  `lost-the-laptop` invariant: Rust sees public keys and signatures only). A scan
  of the FFI boundary and the on-wire presentation finds **no biometric template,
  no raw private key, no enclave secret.** **Adversarial twin:** an attempt to
  exfiltrate or reconstruct presence/biometric data from the presentation yields
  nothing usable — the custody class is an *attestation about* presence, not the
  presence data itself. *BROKEN(2) if the SE sim is not present.*

- **FR-4 (AGT-2) — `probes/wht-4.sh` — custody binds to the action, and a saved
  approval cannot be replayed onto a new action.**
  **Accept:** the custody attestation is bound to *this* approval request (audience
  + nonce + the action's content), so it verifies for the action it approved.
  **Adversarial twin:** a verbatim replay of a prior human-present approval onto a
  *different* high-stakes action is rejected (reuses the platform's existing
  single-use/nonce path, `NonceMismatchOrConsumed` — custody does not grant a
  reusable "a human is generally present" badge). *BROKEN(2) if the SE sim is not
  present.*

---

## 5. The auths surfaces

Named precisely from `../auths/crates`. **EXISTS** vs **BUILD** is the honest line
AGT-2 draws.

**EXISTS today (reused, not built):**
- **Per-environment key custody, real but unsurfaced.** The SE key on device vs a
  software key vs an ephemeral CI key is a genuine, observable distinction in the
  harness today: `../auths/crates/auths-mobile-ffi/src/signature.rs`
  (`ecdsa_p256_der_to_raw` — converts the *real* Secure-Enclave DER signature to
  wire form) and `lost-the-laptop/app/LostLaptop/Core/DeviceKey.swift` (true
  `SecureEnclave.P256.Signing.PrivateKey`, with the honest simulator-emulation
  banner). The private key *never crosses the FFI boundary* — Rust sees public keys
  and signatures only. **But that custody fact is not signed into anything and not
  surfaced by any verdict.**
- **The verifier presentation/verdict path.** `auths-verifier`
  (`../auths/crates/auths-verifier/src/presentation.rs:140` —
  `enum PresentationVerdict`: `Valid{...}`, `HolderNotCurrentKey`, `WrongAudience`,
  `NonceMismatchOrConsumed`, `Expired`, `SubjectKelInvalid`,
  `CredentialNotValid`). The verdict already carries grant facts and an
  `attestation` concept (`../auths/crates/auths-verifier/src/types.rs`).
- **The human-approval CLI gate.** `auths approval list / grant`
  (`../auths/crates/auths-cli/src/commands/approval.rs`; exit `75` =
  `EXIT_APPROVAL_REQUIRED` / TEMPFAIL) — the existing surface that *pauses* an
  agent action for a human. Today the grant is a record, not a custody-bearing
  signature.
- **The mobile FFI approval/signature plumbing.** `auths-mobile-ffi`
  (`auth_challenge_context.rs`, `signature.rs`) — the SE signs a challenge; this
  demo makes that challenge an *approval over a specific action*.

**Must BUILD (this is the AGT-2 work, and why this PARKs):**
1. **A signed, verifiable custody class in the attestation.** A custody-class field
   (`enclave+presence` | `software` | `ephemeral-ci`) bound into the
   delegation/credential **at issuance**, signed so it cannot be self-asserted by
   the holder at presentation time. This is net-new — `presentation.rs` /
   `types.rs` carry *no* custody/presence field today (AGT-2 evidence:
   "zero occurrences of custody/presence").
2. **A custody dimension in the verifier verdict.** `PresentationVerdict::Valid`
   (or a sibling) gains a custody class the verifier *derives by replay* (from the
   signed seal), plus a distinct fail-closed outcome — a software key claiming
   enclave custody resolves to a **custody-rejection verdict**, not `Valid`, not a
   generic signature error. This is the gate FR-2 probes.

---

## 6. Non-goals

- **NOT shipping biometric data.** No biometric template, vector, or raw presence
  signal ever leaves the device or crosses the FFI. The wire carries an
  *attestation about* presence (a signed custody class) — never the presence data.
- **NOT a new enclave harness.** This demo **reuses `lost-the-laptop`'s** Secure-
  Enclave / mobile-FFI simulator verbatim. Building a second, fakeable enclave
  stand-in is explicitly forbidden (it would be the forgery AGT-2 exists to catch).
- **NOT claiming hardware on the simulator.** The simulator's SE is
  software-backed (`lost-the-laptop` LTL-7, `permanent`); the app says so on
  screen. On a real iPhone the key is in hardware. The "FFI never holds the private
  key" and "custody class is signed, not self-asserted" properties hold on both.
- **NOT a liveness / anti-deepfake claim.** This proves *enclave custody behind a
  presence gate*, i.e. "the gated key signed." It does not prove *which* human, nor
  defeat a coerced tap. Identity-of-the-human and coercion-resistance are out of
  scope (and partly belong to HUM-1 guardian work).
- **NOT a live LLM agent.** Per the demos' offline-first norm, the agent's intents
  are scripted; every signature, custody class, and verdict is real and live
  (`death-of-the-api-key` DOTAK-9 precedent, disclosed on stage).

---

## 7. The narrative / run.sh dramaturgy

Staged like `death-of-the-api-key` (acts, hands-off `DEMO_AUTO=1`, every verdict
real CLI/FFI output) and `lost-the-laptop` (the SE app on the simulator). Ends on
the verifier surfacing custody — and the forgery failing closed.

- **Act 0 — the high-stakes action.** The agent reaches `DROP TABLE` / `deploy
  prod` / wire-transfer. `auths approval` gates it: exit `75`, "a human must
  approve." The agent halts. *(disclosure card: intents scripted; crypto live.)*
- **Act 1 — the human approves, on the phone.** The reviewer taps **Approve** in
  the `lost-the-laptop` SE app; the presence gate releases the enclave key; the
  enclave signs the approval over *this specific action* (audience + nonce + action
  digest). On screen: the same honest "Secure Enclave (simulator-emulated)" banner.
- **Act 2 — the action proceeds.** Approval verifies; the destructive action runs.
  The ledger survives. Ordinary so far — this is what every system shows.
- **Act 3 — the audit (the turn).** A third party — who trusts *nothing* the
  platform logged — runs `auths verify` on the approval presentation. Verdict:
  **`Valid · custody = human-present (enclave)`.** Not a log row. A replayed,
  self-certifying fact. *(beat: contrast with the OIDC `amr` string / the audit row
  it replaces.)*
- **Act 4 — the forgery, rejected.** A server automation re-runs the same approval
  with a **software key claiming `enclave+presence`**. `auths verify` →
  **REJECTED on custody grounds** (custody-rejection verdict, named reason). The
  automation cannot mint "a human was here." *(this is the climax.)*
- **Act 5 — the replay, rejected.** A captured *genuine* human approval is replayed
  onto a *different* action → **rejected** (`NonceMismatchOrConsumed`). Presence is
  bound to the action, not a reusable badge.
- **Closing line.** "'A human was in the loop' — and that is something a stranger
  can check, offline, without ever seeing the human." Plus the honest tag: *this is
  spiked; AGT-2 is open; the custody verdict is the platform work it demands.*

---

## 8. Success metrics

The demo succeeds iff **both** verdicts are real, live, and reproducible:

- **Accept verdict:** the enclave+presence approval verifies **with a custody
  class** — `auths verify` surfaces `custody = human-present (enclave)` (FR-1), the
  biometric never leaves the device (FR-3), and the custody attestation is bound to
  the approved action (FR-4 accept).
- **Reject verdict (the load-bearing one):** the **software-key-claims-enclave**
  forgery is **rejected on custody grounds** — a custody-named rejection verdict,
  not a generic invalid-signature, not a silent downgrade (FR-2); and a replayed
  genuine approval onto a new action is rejected (FR-4 twin).
- **Integrity gate:** with the SE simulator **absent**, every probe is **BROKEN(2)**,
  never GREEN — proven by a run with the sim torn down. A green run with no enclave
  is a failed demo, not a passing one.
- **Honesty gate (inherited):** the two sacred spaces (`~/.auths` + global git
  config; the user's own simulators) are untouched, proven by before/after
  fingerprints, exactly as `lost-the-laptop` does it.

A single number for the burndown: **2 verdicts** — `human-present-enclave verifies
WITH custody` AND `software-claims-enclave rejected ON custody` — both real, or the
demo has not landed.

---

## 9. Recurve gap sketch

Draft claims in `riclib` gap style, ready for `recurve init --from-prd`. All
extend **AGT-2** (`covers: ["AGT-2"]`). Status `open` ⇒ probe expected RED today;
`reads: ffi` because the custody signal originates in the mobile FFI / SE harness.
Probe BROKEN(2) if the enclave sim is unavailable — **never** GREEN on a stub.

```yaml
- id: AGENT-HUMAN-1
  title: "A human-present approval carries a verifiable custody class the verifier surfaces"
  class: missing-surface
  status: open
  severity: headline
  reads: ffi
  covers: ["AGT-2"]
  one_line: >
    An approval signed by the SE-backed key behind the presence gate produces an
    attestation whose custody class is enclave+presence, and `auths verify`
    surfaces `custody=human-present (enclave)` in its verdict.
  probe: probes/wht-1.sh
  accept: >
    enclave+presence approval → verify surfaces custody=human-present (enclave);
    a software/automation approval surfaces custody=software (distinguishable).
  adversarial: >
    the two custody classes are NOT interchangeable — a stranger can tell them
    apart from the verdict alone. BROKEN(2) if the SE sim is absent.

- id: AGENT-HUMAN-2
  title: "A software key claiming enclave custody is rejected on custody grounds"
  class: missing-surface
  status: open
  severity: headline
  reads: ffi
  covers: ["AGT-2"]
  one_line: >
    A software/automation key minting an attestation that asserts the
    enclave+presence custody class — with no enclave-anchored custody seal — is
    REJECTED by the verifier, with custody named as the reason.
  probe: probes/wht-2.sh
  accept: >
    the forged software-claims-enclave attestation is rejected with a
    custody-named verdict (not a generic invalid-signature, not a silent downgrade).
  adversarial: >
    the honest enclave approval still verifies (no false-positive that voids the
    gate). NEVER stub the enclave — a faked attestation is the exact fabrication
    this claim forbids; BROKEN(2) if the SE sim is absent.

- id: AGENT-HUMAN-3
  title: "The biometric never leaves the device — only an attestation about presence does"
  class: missing-surface
  status: open
  severity: feature
  reads: ffi
  covers: ["AGT-2"]
  one_line: >
    Across approve→present→verify, only a public key + signature cross the FFI
    boundary and the wire; no biometric template, raw private key, or enclave
    secret appears anywhere.
  probe: probes/wht-3.sh
  accept: >
    scan of the FFI boundary + on-wire presentation finds no biometric/private
    material — the custody class is an attestation ABOUT presence, not the data.
  adversarial: >
    an attempt to reconstruct presence/biometric data from the presentation
    yields nothing usable. BROKEN(2) if the SE sim is absent.

- id: AGENT-HUMAN-4
  title: "Custody binds to the action — a saved human approval cannot be replayed onto a new action"
  class: missing-surface
  status: open
  severity: feature
  reads: ffi
  covers: ["AGT-2"]
  one_line: >
    The custody attestation is bound to this approval request (audience + nonce +
    action digest), so it verifies for the action it approved and nothing else.
  probe: probes/wht-4.sh
  accept: >
    the human-present approval verifies for its own action with custody surfaced.
  adversarial: >
    a verbatim replay of the approval onto a DIFFERENT high-stakes action is
    rejected (NonceMismatchOrConsumed) — presence is not a reusable badge.
    BROKEN(2) if the SE sim is absent.
```

---

*Generated 2026-06-14. Companion to AGT-2 in
`roadmap/aspirational_claims/gaps.yaml`. House style: `death-of-the-api-key`
(probe / gaps.yaml / run.sh) and `lost-the-laptop` (the reused Secure-Enclave /
mobile-FFI simulator harness). This is a spiked, research-grade demo: it rides on
an OPEN headline claim and is the most likely entry to PARK in a burndown — said
plainly, not buried. No probe here is GREEN today; AGT-2 baseline confirms no
custody dimension exists in a verdict yet.*
