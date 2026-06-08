# Witness Commons Charter

This charter defines the **Witness Commons**: the set of independently-operated
witnesses that receipt key events (KERI `rct`) and cosign transparency-log
checkpoints (CT) for the Auths ecosystem. Its purpose is to make the commons a
durable social institution — not a set of servers one company quietly controls.

A witness quorum is only a non-equivocation guarantee if its members are
**genuinely independent**. This document states how independence is *verified*
(not merely declared), who attests it, how keys are custodied and rotated, what
happens when equivocation is detected, and — bluntly — what the cryptography does
and does not prove today.

The machine-checkable parts of this charter are encoded in
[`admission-policy.schema.json`](admission-policy.schema.json) (W.4.2), the
binding contract. That governance schema is **separate** from the runtime
verifier quorum file `auths-transparency/data/witness_policy.json`: different
file, different consumer (governance admission vs. runtime trust). Neither may be
silently weakened to make a verify pass.

## 1. Funding and economics

- The commons is funded by **enterprise revenue** from Auths' commercial
  offerings; operating it is a cost of providing a trustworthy ecosystem, not a
  profit center.
- Witnesses are **operated by neutral institutions** (independent companies,
  non-profits, universities, foundations) under their own legal and operational
  control. Auths funds and coordinates; it does not operate a majority of the
  quorum, and a single funder must never be able to satisfy the quorum alone.
- Operators receive a predictable stipend/grant covering infrastructure and
  on-call; funding is structured so withdrawal of one funder cannot collapse the
  commons (runway + diversified support).

## 2. Independence — verified, not declared

"Operator independence" is auditable, not a self-asserted string. A quorum is
independent only when its **actual cosigning members** (not merely the configured
roster) span all three axes:

1. **Distinct legal entities.** Each operator is a separate legal entity with
   separate beneficial ownership. Two brands of one parent are **one** operator.
2. **Distinct jurisdictions.** The quorum spans ≥2 legal/governance
   jurisdictions, so no single legal order (subpoena, injunction) can compel the
   whole quorum.
3. **Distinct infrastructure.** The quorum spans ≥2 infrastructure zones —
   distinct ASNs or cloud-provider+region pairs. Three distinct legal entities
   all hosted in one cloud region are **not** independent for censorship or
   correlated-failure purposes; a single region outage or a single provider's
   compliance action takes them all down at once.

These are the same three axes the runtime gate enforces
(`auths_keri::witness::independence::spans_distinct`) and the admission schema
encodes, so governance and code cannot drift.

### What evidence is required, and who attests it

| Axis | Evidence required | Attested by |
|------|-------------------|-------------|
| Legal entity | Registration/incorporation record; beneficial-ownership declaration | Operator, on admission; re-attested annually |
| Jurisdiction | Stated jurisdiction of incorporation **and** of primary hosting | Operator; spot-checked by the governance steward |
| Infrastructure | ASN and cloud-provider+region of the witness host | Operator; corroborated from the monitor's observed network path |
| Key custody | How the signing key is held (HSM / KMS / sealed file) and who can access it | Operator key-custody attestation |

A pinned witness with any axis missing **cannot prove independence** and is
treated as failing — never as "assume distinct" (fail closed). The current
honesty ceiling (§6) reflects exactly which axes are satisfied today.

## 3. Admission and exit

- **Lifecycle:** `pending → qualified → usable → retired/rejected`. An operator
  is `usable` (eligible to be pinned) only after all three independence axes and
  a key-custody attestation are verified against the admission schema.
- **Admission** requires: the evidence in §2, a signed key-custody attestation,
  and agreement to this charter and the SLA (§4).
- **Exit / sunset** is graceful (§4): a signed `rotation_notice` with
  `status: retired` published ≥30 days before removal, so clients re-pin without
  a trust gap. Emergency removal (§5) is the exception, used only on
  non-repudiable equivocation evidence.
- Admission and exit decisions are recorded publicly (an append-only governance
  log) so the membership of the commons is itself transparent.

## 4. Key custody, rotation/sunset, and SLA

- **Custody.** Each operator custodies its witness signing key in an HSM or KMS
  where feasible; at minimum a sealed, access-controlled file. The custody method
  is attested on admission. (The v1 reference binary uses a `0600` file/`env`
  seed; an HSM/KMS backend is tracked in W.0.)
- **Rotation / sunset without breaking pins.** A key is rotated or retired via a
  signed `rotation_notice` naming the old and new key and an **overlap window**
  during which both verify, followed by the re-pin flow clients follow. Clients
  must be able to re-pin before the old key stops signing. (The rotation
  *mechanism in code* — the rct `rot`/CT re-pin distribution — is tracked in W.0;
  this charter sets the policy that mechanism must satisfy.)
- **SLA / availability.** Each operator targets **≥99% availability over a
  rolling 90-day window** (the Chrome-CT-style bar). The monitor's liveness
  signal (W.3.1) measures reachability and latency per operator; sustained
  breach moves an operator toward `retired`. (Full rolling-window SLA accounting
  is tracked in W.0; W.3.1 provides the live up/down signal it builds on.)

## 5. Equivocation-response runbook

Wired to the W.3 monitor. The monitor cross-reads operators and flags
same-sequence / different-SAID forks.

1. **Sampled flag (W.3.1).** The cross-read monitor emits typed
   `DuplicityEvidence` naming the disagreeing operators. This is a **sampled**
   tripwire (a targeted partition can evade it), so a flag opens an
   investigation; it is not yet, by itself, grounds for removal.
2. **Non-repudiable evidence (W.3 gossip).** When the gossip layer produces
   non-repudiable cross-operator evidence of equivocation:
   - The governance steward and all operators are **notified** immediately.
   - The implicated operator is **suspended** from the usable set (its key is
     marked `retired` in the policy) pending review.
   - Clients **re-pin** off the suspended key via the published policy update;
     identities that designated it in `b[]` are advised to rotate witnesses.
3. **Review and removal.** A documented review determines whether the
   equivocation was a compromise, misconfiguration, or malice, and whether
   removal is permanent. The decision and evidence are published.

## 6. Honesty statement — what the cryptography proves, and what it does not

Lifted from `roadmap/README.md` and the design paper (§16.6, §17):

The cryptography proves **continuity** (this identity's key history is
self-consistent and unforked in the views we can see), **non-equivocation to the
extent the witness quorum is independent and honest**, and **capability** (this
key was authorized to act). It does **not** prove real-world identity — that a
key belongs to a specific human or company is a separate, social claim.

**Current honesty ceiling.** The commons is **bootstrapping**. Until ≥3 genuinely
independent operators (distinct entity + jurisdiction + infrastructure) are
admitted and cosigning, the quorum is **not yet independent**, and every surface
must say so (the shared `HonestyCeiling` renders "not yet independent" and
"equivocation sampled, not yet non-repudiable"). The shipped default policy
**fails closed** rather than presenting a single-operator quorum as if it were
independent. This charter describes the target end-state; it does not assert the
guarantee is in force today.

## 7. Stewardship

A governance steward (initially Auths, transitioning to a neutral body as the
commons matures) maintains the admission log, the schema, and this charter;
runs the admission/exit process; and triggers the equivocation runbook. Changes
to this charter or the admission schema are themselves published and versioned.

## References

- [`admission-policy.schema.json`](admission-policy.schema.json) — the binding,
  machine-readable contract for the checkable parts (W.4.2).
- `docs/security/witness-diversity.md` — onboarding/rotation/sunset detail.
- `auths-transparency/data/witness_policy.json` — the **runtime** verifier quorum
  (separate from this governance contract).
- Chrome CT log-operator policy; transparency.dev witness governance — precedent.
