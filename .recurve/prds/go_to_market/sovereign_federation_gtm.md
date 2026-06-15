# GTM Plan — Sovereign, Federated Trust Infrastructure

> **Status:** plan / pre-suite. This document is written to be decomposed into a
> recurve **gap suite** (prefix `GTM-`). Every market-readiness assertion below is
> phrased as a *falsifiable, demonstrable* claim with a probe definition, a trap, and
> federated-gate dependencies — so "roll this into a gap analysis" is a mechanical
> translation, not a re-think. Where a section is **not** probeable (sales, pricing,
> partnerships), it is fenced off explicitly so the loop never pretends to own it.

---

## 0. Thesis (the positioning this plan sells)

auths-witness lets anyone stand up a **witness node in one command**, *behind their own
perimeter* (VPN / on-prem / air-gap). The operator sets their own threshold, admission,
and revocation policy — so the node is not just a corroborator, it is a **trust-policy
control plane the org fully owns**. Because the identities underneath are self-certifying
and witness-receipted, anything that node vouches for is **verifiable by outsiders with no
shared broker and no prior federation handshake**.

That is the whole pitch in one line: **own your control plane (inside), federate
cryptographically (across).** "Sovereign but federated."

**Why this re-categorizes the product.** This is *not* the "self-sovereign identity for
everyone" story (fifteen years, no buyers). It maps onto a category enterprises already
budget for: **private PKI / an internal trust plane** — but KERI-grade (self-certifying,
pre-rotation, no brittle CA hierarchy) and *natively federatable*, which private CAs are
miserable at. The buyer's mental model is "my internal CA, but it survives key compromise
and can talk to my partner's without a manual cross-cert dance."

**Why it has a wedge (the cold-start escape).** Network-effects identity normally needs
relying parties before it has value. The self-hosted-witness model sidesteps that: **a
single org gets value with zero external adoption** — intra-org machine and agent identity,
behind its own firewall, on day one — then extends to its supply chain when partners are
ready. Useful solo, network effects later (the Terraform/Kubernetes adoption curve).

**The honest limit, encoded as a permanent trap (see GTM-C4).** Cross-domain *verification*
is brokerless; cross-domain *trust* is not automatic. Company B can verify Company A's
identity with no shared root, but B still must **decide** to trust A's root for a purpose.
The cryptography removes the *plumbing* of federation; it does not remove the *policy*
decision. This plan refuses to let any probe pretend otherwise.

### Relationship to the other GTM docs
- `roadmap/go_to_market/go_to_market.md` — the **developer last-mile** (drift elimination,
  install, first-five-minutes). That is the *substrate*: a buyer who can't `brew install`
  never reaches this plan. It must be green first; this plan assumes it.
- This doc — the **enterprise / agent wedge**: the demonstrable proof package that a CISO,
  a platform team, or a cross-org integration owner runs and believes.

---

## 1. What "passing" means (the proof-gated GTM contract)

This suite inverts the usual GTM artifact. Instead of *assertions a deck makes*, every
readiness claim is *a thing a skeptical buyer's own security team can re-run and watch go
GREEN.* The deck becomes a thin narrator over a reproducible ledger.

A claim **passes** when **all three** hold (the standard recurve gate):

1. **Probe GREEN** — its probe script exits `0` having *behaviorally* demonstrated the claim
   end-to-end (run the real `auths witness …` commands against the real fixture; never a
   mock, never a grep-for-the-happy-string unless the claim is *about* strings).
2. **Trap RED** — its adversarial twin (the counterexample fixture) exits non-zero. A claim
   with no honest trap carries a `trap_waiver` and shows up as visible debt.
3. **Federated gate green** — the change does not regress the platform: `rictl matrix --gate`
   (demos, 46), `ictl matrix --gate` (interop, 27), and the witness suite all stay green.

A **block** passes when all its claims are `closed`. The **suite** passes when every block is
closed **and the proof bundle (GTM-G1) reproduces GREEN in a clean, network-isolated
environment.** At that point the suite *is* the GTM evidence package.

**Classes** (the closed six — GTM claims map onto them, no new enum):
`missing-surface` (the capability/command/endpoint does not exist) · `wire-mismatch`
(federation/interop payload does not cross-verify against the oracle/peer) · `broken-route`
(a surface exists but errors) · `friction` (exists but the operator path is too slow /
jargon-heavy / many-stepped) · `staging` (the proof is staged — e.g. two "orgs" on one box
— accepted with a trap) · `security-tradeoff` (a loosening or trust-default that a human
must sign off — the loop will not work these unattended).

**Probeable metrics** (thresholds become probe assertions, not slideware):
`time_to_standup ≤ 10 min cold` · `time_to_first_federated_verify ≤ 15 min cold` ·
`external_egress_packets = 0` (sovereignty) · `steps_to_value ≤ N documented` ·
`teardown_residue = 0`. Business KPIs (pipeline, ARR, logo count) are **not** in scope here
— see §6.

---

## 2. The shared probe harness — the "two-perimeter rig"

Most GTM claims need more than the witness suite's single fixture. They need to *prove
sovereignty and federation*, which requires perimeters and an egress conscience. This is the
suite's `BOOT` equivalent and is built first.

| Component | What it is | Why a claim needs it |
|---|---|---|
| `org-a`, `org-b` | two independent compose networks / netns, each with its own node(s), **no shared volume, no shared registry, distinct seeds → distinct roots** | federation must be *between strangers*, not two views of one state |
| **egress firewall** | per-perimeter default-deny egress with a declared allow-list; a packet counter to any non-perimeter host | the **sovereignty** proof (GTM-A2) and the **no-broker** proof (GTM-C1) are *egress assertions* |
| `stranger` netns | a clean namespace: no auths state, no network | the **offline-verify** proof (carries a receipt in, verifies with no network) — extends the closed `WIT-N2` |
| **punch-through** | a single declared ingress exposing only the federation surface | the **selective-exposure** proof (GTM-C3) port-scans this |
| **timing harness** | wall-clock around standup / first-federated-verify | turns the §1 metrics into pass/fail |
| **cold-operator runner** | a *fresh container* with ONLY the published install artifact + the published docs — **no repo checkout, no tribal env** | the **time-to-value** proof (GTM-F1): runs the quickstart verbatim and asserts the end state |

Harness claims:

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-H1` | two independent perimeters stand up with distinct roots and no shared state | staging | feature | `org-a` and `org-b` each healthy, roots differ, no shared volume/registry mount | a fixture where both "orgs" share a volume/registry (one identity wearing two hats) |
| `GTM-H2` | egress firewall provably blocks + counts non-perimeter traffic | missing-surface | feature | a deliberate outbound call from inside is blocked and the counter increments | egress counter that misses a known outbound call (a blind firewall) |
| `GTM-H3` | cold-operator runner executes only published artifacts | staging | feature | runner has no repo checkout; `which auths` resolves to the released binary only | a runner that falls back to a workspace build |

> **Adjudication (ADJ-GTM-2):** is two-perimeters-on-one-box acceptable staging, or must
> the federation proofs run on two real hosts? Default proposed: **on-box netns is
> acceptable** for the suite (cheap, deterministic) **provided** `GTM-H1`'s trap guarantees
> no shared state; a separate, human-run *two-host* confirmation is a release checklist item,
> not a loop probe. Human confirms.

---

## 3. The claim blocks

Each block lists draft claims ready for `gaps.draft.yaml`. `depends` names the underlying
platform work (existing witness suite `WIT-*`, demos, interop) the claim composes — recurve
uses these to order the burndown.

### GTM-A — Sovereign one-command standup (activation)
*The "I did it myself, behind my firewall, in ten minutes" proof.* `depends: WIT-N1, WIT-I, GTM-H*`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-A1` | one command stands up a production-shaped node, ≤10 min cold, health GREEN | missing-surface | headline | timed cold run on a fresh host reaches a healthy node from a single `auths witness up` | a node reporting healthy *before* its identity/KEL is actually minted |
| `GTM-A2` | the node stands up and runs lifecycle with **zero external egress** | security-tradeoff | headline | standup + issue + verify complete with default-deny egress; external packet count = 0 | a node that silently calls an external bootstrap / registry / telemetry host |
| `GTM-A3` | the shipped IaC reproduces an identical node on a second host; teardown leaves nothing | missing-surface | feature | same config on two hosts → identical advertised capabilities; `down` → 0 residue | teardown that leaves a dangling container / volume / port |
| `GTM-A4` | the node survives reboot + process kill, recovering identity + receipts | friction | feature | kill+restart preserves the *same* identity and all receipts (operator-facing FR-13) | a restart that mints a new identity or drops receipts |

### GTM-B — Sovereign lifecycle & policy behind the perimeter
*The "I run my own trust plane and my own rules" proof.* `depends: WIT-N, WIT-T, WIT-D`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-B1` | full identity lifecycle (issue → pre-rotate → revoke) runs fully air-gapped | missing-surface | headline | inside the no-egress perimeter, issue+rotate+revoke each verify on-node | a lifecycle op that requires reaching an external service |
| `GTM-B2` | the org sets its own M-of-N threshold; sub-threshold verification fails closed | missing-surface | headline | threshold=3-of-5: 2 receipts → rejected, 3 → accepted | a forged / under-threshold receipt-set accepted (over-permissive) |
| `GTM-B3` | the org controls its trust domain: admission is org-signed | missing-surface | feature | B joins via an org-signed admission; an unsigned/forged admission is rejected | a self-asserted admission (no org signature) accepted |
| `GTM-B4` | a custom authorization policy gates a real resource on the verification verdict | missing-surface | feature | policy allows valid, denies revoked / stale / foreign-root | policy that fails **open** on an unknown/un-handled verdict |

### GTM-C — Cross-domain federation (the differentiator)
*The "Company A ↔ Company B with no shared broker" proof.* `depends: WIT-N2 (closed), WIT-D, GTM-H*`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-C1` | two independent nodes cross-verify identities **offline, no shared registry** | wire-mismatch | headline | `org-b` verifies `org-a`'s identity using only A's carried-over KEL+receipts — egress to any broker = 0 | a cross-verify that succeeds *only* by calling a central registry |
| `GTM-C2` | revocation propagates across domains within the **operator-published, negotiated** staleness bound | wire-mismatch | headline | A revokes; B rejects within **A's published** bound (read from A's directory metadata, not hardcoded); a B snapshot older than that bound **fails closed** | B honoring a revoked-at-A identity beyond A's published bound (fail-open), **or** a consumer assuming/hardcoding a bound instead of reading A's published value |
| `GTM-C3` | selective exposure: only the federation surface is reachable from outside | missing-surface | feature | external scan → only declared key-state/receipt endpoints answer; admin/ops unreachable | any non-federation (admin/metrics/ops) endpoint reachable from outside the perimeter |
| `GTM-C4` | **verification ≠ trust**: an unconfigured peer verifies-but-denies until policy is set | security-tradeoff | headline | unconfigured B *verifies* A yet *denies* access; after B sets policy, allows | **(PERMANENT)** an unconfigured B that auto-grants access to any cryptographically-valid foreign identity |

> `GTM-C4`'s trap is **permanent** — it is the encoded honesty of the whole pitch. It can
> never be "closed away." See ADJ-GTM-1.

### GTM-D — Agent / M2M cross-org spearhead (the lead use case)
*The one place auths is early, not late.* `depends: GTM-C, WIT-T, DOTAK delegation, DOTAK-3`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-D1` | A's agent authenticates to B's service with a delegated, revocable credential (no API key, no hand-exchanged cert) | missing-surface | headline | A's agent presents; B verifies the delegation chain roots in A's *admitted* root and grants per policy | B accepting an agent whose delegation chain does **not** root in A's admitted root |
| `GTM-D2` | revoking the agent at A → B rejects it on the next call | missing-surface | headline | revoke at A; B's next call → denied | B honoring a revoked agent (depends on the `DOTAK-3` delegator-revocation decision) |
| `GTM-D3` | the agent credential is scoped/attenuated; B enforces least privilege | missing-surface | feature | in-scope request allowed, out-of-scope denied | an out-of-scope request honored |

### GTM-E — Migration / coexistence (lower the switching cost)
*The "I don't have to rip out my PKI" proof.* `depends: interop L9, X.509 bridge`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-E1` | an auths identity bridges from the org's existing internal X.509 CA (coexist, not replace) | missing-surface | feature | an auths identity carries a verifiable binding to an X.509 cert chaining to the org CA; verifier accepts the bridge | a bridge claim that does **not** actually chain to the org CA, accepted |
| `GTM-E2` | an auths-rooted identity is presented over a standard the buyer already runs (mTLS) | wire-mismatch | feature | mTLS handshake where the client cert roots in an auths KEL; verifier rejects a KEL-invalid/revoked client | a revoked-KEL mTLS client accepted (ties to interop `IOP-L9a..d`) |

### GTM-F — Operator proof & onboarding (time-to-value)
*The "a platform engineer can evaluate it in an afternoon" proof.* `depends: WIT-N5, WIT-O, go_to_market.md`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-F1` | cold operator reaches first **federated** verification in ≤N steps / ≤M min, no tribal knowledge | friction | headline | the cold-operator runner executes the published quickstart verbatim → a cross-domain verify, within thresholds | a quickstart step needing a repo checkout / unpublished artifact / undocumented env |
| `GTM-F2` | a single command demos sovereign+federated end-to-end on the buyer's laptop | friction | feature | one command brings up *two real* perimeters + a narrated cross-domain verify | a "demo" that fakes federation with one node wearing two hats |
| `GTM-F3` | the node exposes the metrics/health/audit an ops team needs | missing-surface | feature | documented metrics endpoint exposes the named series; audit log records every lifecycle event | a lifecycle event (e.g. revoke) **absent** from the audit log |
| `GTM-F4` | zero protocol jargon in the operator happy path (federation + agent flows) | friction | feature | case-insensitive scan of all GTM-flow operator output → no KERI vocabulary | jargon (KEL/SAID/CESR/verkey/…) in any happy-path output (extends `WIT-N5`) |

### GTM-G — Evidence & trust collateral (the buyer's proof bundle)
*The artifact the human GTM motion stands on.* `depends: WIT-N4, recurve report`

| id | title (claim) | class | sev | GREEN means | trap (stays RED) |
|---|---|---|---|---|---|
| `GTM-G1` | a reproducible, signed proof bundle a buyer's security team can re-run | missing-surface | headline | `recurve report` emits a signed bundle of all GTM claims; re-running the suite in a clean isolated env reproduces GREEN | a bundle claiming GREEN that does **not** reproduce in a clean env |
| `GTM-G2` | every threat-model line is backed by a probe id or a permanent trap | security-tradeoff | feature | each documented threat maps to a probe/trap; no unbacked assertion | a threat-model claim with no probe/trap behind it |
| `GTM-G3` | supply-chain provenance: the node binary carries a verifiable SBOM + signed attestation | missing-surface | feature | the binary's version+digest+SBOM attestation verifies via `auths witness status` and an external verifier | a tampered binary whose attestation still "verifies" (extends `WIT-N4`) |

---

## 4. Sequencing — phases mapped to dependencies

The order maximizes *demonstrable value per phase* and respects the underlying witness build.

| Phase | Theme | Blocks | Gated on | The thing you can show after |
|---|---|---|---|---|
| **G-1 Wedge** | *Stand up your own sovereign trust plane* | `GTM-H*`, `A`, `B1`, `F1`, `F4` | `WIT-N1/N2` (done), `WIT-I` | "One command, behind my firewall, full lifecycle, zero egress." Day-one value, **no external adoption needed.** |
| **G-2 Federation** | *Two orgs, no broker* | `C`, `B2`, `B3`, `F2` | `WIT-T`, `WIT-D` | "Company A and Company B cross-verify and revoke with no shared root." The differentiator. |
| **G-3 Spearhead** | *Cross-org agents* | `D`, `B4` | `DOTAK-3` (HUMAN-D3), `WIT-T` (HUMAN-D5) | "A's agent calls B's service — no API key — and dies on revoke." The lead use case. |
| **G-4 Coexist + collateral** | *Lower switching cost, hand over the proof* | `E`, `F3`, `G` | interop `L9`, `WIT-N4`, `WIT-O` | "Bridges your existing CA; here's a signed proof bundle your team can re-run." |

**Critical-path note:** G-2 and G-3 are gated on two of the open **HUMAN_DECISIONS**:
`WIT-T` (D5, the threshold) and `DOTAK-3` (D3, delegator-revocation). This plan does not
unblock itself — those calls do.

---

## 5. Converting this plan into a recurve suite (mechanical steps)

When you green-light it, the translation is:

1. **Suite scaffold** — a `.recurve/` (single-tree, interop-style, like `auths-network`)
   with `claims/gtm/`. `recurve.toml`:
   - `[target] tree = "../auths"` (claims drive product capability into the platform);
     `forbidden_strings = ["GTM-", "ADJ-GTM-", "recurve"]` (loop vocabulary must not leak
     into product code/comments).
   - `[reads.cli]` content-hash on the feature-enabled `auths` (same as the witness suite —
     the federation/agent surfaces are feature-gated witness-node territory).
   - `[suites.gtm] rebuild = "bash claims/gtm/harness/rebuild.sh"` (builds the feature `auths`
     **and** the two-perimeter rig).
   - `[gate] traps = "required"`, `[commit] policy = "unsigned-per-cycle"`.
2. **Draft ledger** — the tables in §2–§3 become `gaps.draft.yaml` entries (id, title, class,
   severity, smallest_fix = the "GREEN means" cell, plus a trap fixture per the "trap" cell).
   Each carries `depends`/`unlocks` so the burndown orders itself behind the witness suite.
3. **Harness first** — `GTM-H1..H3` are the suite's bootstrap (the two-perimeter rig +
   egress conscience + cold-operator runner), promoted and closed before any A–G claim.
4. **ADJUDICATE** — the four forks in §7 go in `ADJUDICATE.md`; `baseline` warns until each is
   decided. The `security-tradeoff` claims (`A2`, `C4`, `C2`-bound, `G2`) stay review-gated.
5. **Federated gate** — every cycle runs demos + interop + witness gates (this suite composes
   them; it must never regress them).

The result: pointing the existing burndown loop at the `gtm` suite produces the same
artifact discipline you already trust — probe-gated, trap-guarded, federated — but the claims
are *market-readiness proofs* instead of protocol conformance.

---

## 6. The honesty boundary — what recurve does NOT own

recurve gates the **evidence**; humans run the **motion**. This fence is load-bearing: if the
loop ever appears to "do GTM," it is lying. These are explicitly **out of suite**:

- **Pricing & packaging** — open-core (self-host free, managed/support paid)? per-node?
  per-federation-edge? A human decision; recurve can only prove the self-host path *works*.
- **Design-partner recruitment** — the 3 lighthouse accounts (proposed archetypes: one
  security-maximalist enterprise that wants Okta *off* its books; one infra-mature platform
  team; one *pair* of orgs with a real cross-boundary agent/M2M need to anchor G-2/G-3).
- **The sales motion & champion enablement** — the proof bundle (`GTM-G1`) is the *ammunition*;
  firing it is human.
- **Positioning & narrative content** — the "private PKI that federates" deck, the Okta
  counter-position. recurve proves the claims the narrative cites; it does not write the deck.
- **Standards & community** — KERI / Trust-over-IP / the CESR community engagement.
- **Analyst relations / category creation.**

A useful way to hold it: **every numbered claim that goes GREEN is a sentence the GTM team is
now allowed to say without lying.** The suite's job is to keep that list of permitted
sentences honest and growing. It is not the team.

---

## 7. Open adjudication forks (human decisions this plan introduces)

These roll into the same review flow as `HUMAN_DECISIONS.md`. Each becomes an `ADJUDICATE`
entry; the suite's `baseline` warns until decided.

- **ADJ-GTM-1 — cross-domain trust default.** `GTM-C4` proposes **verify-but-deny-until-policy**
  (fail-closed) as the default, with a permanent auto-trust trap. Confirm, vs allowing a
  configurable "auto-trust within a named federation" (a real loosening that would need its
  own review). *Recommendation: keep fail-closed default; named-federation auto-trust is a
  later, separately-reviewed `security-tradeoff`.*
  **DECIDED 2026-06-14 (HUMAN-D9): A** — fail-closed verify-but-deny is the default; `GTM-C4`'s
  auto-trust trap is permanent. Named-federation auto-trust is deferred to a later,
  separately-reviewed trade-off.
- **ADJ-GTM-2 — staged vs real two-host federation.** On-box netns acceptable for the suite
  (with `GTM-H1`'s no-shared-state trap) + a human two-host release check, vs require two real
  hosts in the loop. *Recommendation: on-box + release-check.*
  **DECIDED 2026-06-14 (HUMAN-D10): A** — on-box two-namespace staging for the loop (guarded by
  `GTM-H1`'s no-shared-state trap) + a human two-host check at release. Two-host follow-up
  tracked: [auths-dev/auths#269](https://github.com/auths-dev/auths/issues/269).
- **ADJ-GTM-3 — revocation staleness bound.** `GTM-C2` accepts "stale within bound." What *is*
  the published bound, and is accepting any stale state a loosening that needs review?
  *Recommendation: pick an explicit conservative bound; treat "accept stale within bound" as a
  reviewed `security-tradeoff` with the beyond-bound fail-closed trap permanent.*
  **DECIDED 2026-06-14 (HUMAN-D11): A, REVISED** — the staleness bound is **not a hardcoded N**.
  It is a parameter each witness / federation operator **chooses, negotiates with peers, and
  publishes** (carried in the directory / admission metadata, `WIT-D`). The reviewed
  `security-tradeoff` is "accept stale within the **published** bound"; the **permanent** trap
  is "honor state beyond the published bound → must fail closed." A consumer that hardcodes or
  assumes a bound rather than reading the peer's published value is itself a defect. `GTM-C2` is
  reworded accordingly.
- **ADJ-GTM-4 — X.509 bridge scope.** `GTM-E1`: full bidirectional bridge vs attestation-only
  (auths identity *attested by* the org CA, not auths *issuing into* X.509). *Recommendation:
  attestation-only for v1 — coexistence without inheriting X.509's revocation pain.*
  **DECIDED 2026-06-14 (HUMAN-D12): A** — attestation-only for v1 (coexist beside the org PKI,
  no X.509 revocation inheritance). Full bidirectional bridge follow-up tracked:
  [auths-dev/auths#270](https://github.com/auths-dev/auths/issues/270).

---

## 8. Definition of done

The suite is **done** when:

1. Every `GTM-*` claim is `closed` (or `permanent` for the honesty traps), trap RED.
2. The federated gate (demos 46 + interop 27 + witness suite) is green.
3. `GTM-G1` reproduces the full proof bundle GREEN in a **clean, network-isolated**
   environment a third party controls.

At that point the deliverable is not a document — it is a **command a buyer's security team
runs that turns the entire pitch GREEN on their own hardware, behind their own firewall.**
That is the most defensible GTM artifact this product can have, and it is the one the loop can
actually build.

---

*Generated 2026-06-14. Decomposes into a `gtm` recurve suite (prefix `GTM-`). Depends on the
witness suite (`WIT-*`), interop `L9`, and the `DOTAK-3` / `WIT-T` human decisions in
`HUMAN_DECISIONS.md`. Sits above `go_to_market.md` (the developer last-mile).*
