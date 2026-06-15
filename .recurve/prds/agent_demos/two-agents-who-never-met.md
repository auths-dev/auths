# Two Agents Who Never Met — auths agent demo PRD

> **One line:** Company A's agent cold-calls Company B's tool server — no shared
> IdP, no MSA, no pre-exchanged keys, never met — and in **one round trip** each
> side verifies the other's chain to its *own* org root, scoped caps apply both
> directions, and either side's revoke instantly kills the relationship.

> **Honest scope (read first):** this demo is **SPIKED / aspirational.** It rides
> on the **live leg of claim `AGT-3`**, which **does not exist yet.** AGT-3's
> *offline-bundle impersonation* half was hardened this cycle (a forged
> "I am A" bundle now fails closed via `BundleTrust`'s RT-005 self-certification —
> `auths/crates/auths-cli/src/commands/artifact/verify.rs:606`,
> `auths/crates/auths-verifier/src/commit_bundle.rs:77`). The **live, in-band,
> mutual-introduction runtime** — two strangers' agents establishing *scoped,
> bidirectional, revocable* trust in one exchange — is the missing capability this
> demo would build. Discovery (OOBI) is **done** and conformant; this *composes*
> it. Every "must build" below is named as such. No hype.

---

## 1. One-line + scenario

**Scenario — cold contact between two real companies.** Northwind Logistics runs
an autonomous dispatch agent. At 02:14, a shipment exception fires: the agent
needs a live rate quote from **Pier 9 Freight**, a carrier Northwind has *never*
done business with. There is no MSA. No one at either company has met. There is
no shared identity provider, no exchanged API key, no IT ticket. The agent has a
delegation chain — `Northwind-org → ops-team-dev → dispatch-agent`, scoped to
`quote:read` — and Pier 9's tool server has its own: `Pier9-org →
integrations-dev → rate-tool`, scoped to `quote:serve`.

**The moment of first contact.** Northwind's agent opens a connection and, in the
*same* exchange, hands over its introduction (its delegation chain back to the
Northwind org root) and receives Pier 9's. Each side independently replays the
other's key-event history to a root it can name and decide to trust — **its
counterpart's *own* org root, not a shared third party.** Northwind's agent
confirms the responder really is Pier9-org's rate tool, scoped to serve quotes;
Pier 9's server confirms the caller really is Northwind-org's dispatch agent,
scoped to read quotes. The quote returns. Total elapsed: one round trip.

**How this breaks today:**

- **OAuth / SAML federation:** requires a *prior* legal + technical relationship —
  a signed agreement, a federation config, client registration, exchanged
  metadata, an IT project measured in **weeks**. Two strangers' agents at 02:14
  cannot federate; there is nothing to federate *through*.
- **A shared API key:** a **bearer secret** — whoever holds the string is "trusted."
  No attenuation (the key can't say "quote:read only"), no per-actor identity (the
  log shows the key, not *which* agent), no instant revocation that the *other*
  side honors, and no way for Pier 9 to prove *itself* back to Northwind. It's a
  password mailed between strangers.

**What auths does:** the introduction *is* the proof. Each party carries a
self-certifying delegation chain it can present cold; the counterpart verifies it
from itself + its KEL + witness receipts, rooted in the counterpart's org —
**no CA, no IdP, no broker.** Scope is structural (caps in the credential, not in
a policy server someone has to share). Revocation is one signed event the next
verification already sees, in **both** directions.

---

## 2. The property it proves

**Cross-org scoped mutual trust in one round trip, no shared IdP, mutually
revocable.** Concretely: two parties that share *no* prior relationship each
present a delegation chain rooting in their *own* org; each independently
verifies the *other's* chain to a root it names; scoped capabilities are enforced
**both directions**; and a revoke on *either* side kills the relationship at the
next verification. This is the **network-effect** claim — value grows with every
published identity, because any two published identities can transact cold, with
**no central broker** sitting in the path. It is the agentic-internet / A2A thesis
made concrete.

**Why incumbents can't match it:**

| Incumbent | Why it can't |
|---|---|
| **OAuth / SAML federation** | Trust is *pre-negotiated*: a shared federation config + legal agreement must exist *before* the first call. There is no "verify a stranger you've never federated with." It is a club with a membership step, not a waist. |
| **Okta / Auth0 B2B (org-to-org)** | Still routes both parties through a **shared broker / directory** the two orgs must both onboard to. Mutual cold trust with *no* common IdP is outside the model; the broker *is* the central party this demo removes. |
| **Shared API keys** | Bearer secret: no attenuation, no per-actor identity, no mutual proof (one side proves nothing back), and "revocation" is the holder rotating a string — the *other* party has no cryptographic event to observe. |

auths replaces the shared broker with **self-certifying identifiers** + **discovery
(OOBI)** + **in-band credential exchange (IPEX)**: each side roots the other to a
root *it* chooses, no third party in the trust path.

---

## 3. Goals

- **G1 — Two genuine strangers.** Stand up **two fresh registries** (Northwind,
  Pier 9) that have *genuinely never met*: no shared witness, no shared IdP, no
  pre-exchanged keys, no prior OOBI, no prior credential exchange.
- **G2 — A scoped call completes BOTH directions.** Northwind's `quote:read`
  agent calls Pier 9's `quote:serve` tool; each side verifies the other's chain to
  the other's **own** org root; the quote returns. The handshake authenticates
  *both* parties in *one* round trip.
- **G3 — The impersonator is rejected.** A **third** registry (Contoso) forges an
  introduction claiming to be Northwind. Pier 9 rejects it — the forged chain does
  not root in the org root it actually verifies. Fail-closed.
- **G4 — Either side's revoke kills it.** When Northwind revokes its agent's
  delegation **or** Pier 9 revokes its tool's, the *next* cold call dies — the
  relationship is mutually revocable, no restart, no out-of-band notice.

---

## 4. Functional requirements (as claims)

Each FR is a probe-able **observable (accept)** with an **adversarial twin
(fail-closed)**. All map to **`AGT-3` (the live leg — not yet built)**; all
**compose** OOBI (discovery — done, conformant in `tests/conformance/`) and
**IPEX** (in-band credential grant/admit — wire format present, runtime to be
wired). Claimify-ready.

- **FR-1 — Cold mutual introduction (one round trip).**
  *Accept:* two never-met registries exchange introductions in a single round
  trip; each side resolves + replays the other's delegation chain to the *other's*
  own org root and accepts.
  *Adversarial twin:* a party whose chain roots in **no root the verifier admits**
  is rejected — no "trust on first contact." (Maps AGT-3 live · composes OOBI.)

- **FR-2 — Impersonator rejected (a third registry claiming to be A).**
  *Accept:* the legit caller (Northwind) is verified as Northwind.
  *Adversarial twin:* a **third registry (Contoso)** presenting a forged "I am
  Northwind" introduction is **rejected** — the carried KEL does not self-certify
  to the claimed org root. This reuses the *already-hardened* AGT-3 mechanism
  (`BundleTrust` RT-005 self-certification) and extends it onto the **live** path.
  (Maps AGT-3 live + hardened offline leg.)

- **FR-3 — Scoped call succeeds — both directions.**
  *Accept:* Northwind's `quote:read` agent invokes Pier 9's `quote:serve` tool and
  the quote returns; the server log names the verified `did:keri:` principal and
  its caps; Northwind likewise confirms the responder's `quote:serve` scope.
  *Adversarial twin:* an **out-of-scope** call (Northwind's agent asks Pier 9 to
  `book` a shipment, a cap it does not hold) is **rejected** — attenuation is
  structural, enforced at verify. (Maps AGT-3 live · composes IPEX.)

- **FR-4 — Either side's revoke kills the relationship.**
  *Accept (baseline):* before revocation, the cold scoped call returns the quote.
  *Adversarial twin A:* after **Northwind** revokes its agent's delegation, the
  next cold call **dies** (Pier 9 sees the revocation event on Northwind's chain).
  *Adversarial twin B:* after **Pier 9** revokes its tool's delegation, the next
  cold call **dies** (Northwind sees it on Pier 9's chain). Mutually revocable, no
  restart. (Maps AGT-3 live + OPS revocation propagation.)

- **FR-5 — No shared IdP / no broker in the trust path.**
  *Accept:* the full handshake completes with each party verifying against **its
  own** trusted registry replica — no common witness, directory, or broker is
  consulted.
  *Adversarial twin:* any path that *requires* a shared third party (a common IdP
  call, a central directory lookup, a broker token) to complete the handshake
  **fails the claim** — it would mean the network effect is broker-gated, not
  peer-to-peer. (Maps AGT-3 live · the network-effect property.)

---

## 5. The auths surfaces

Read against `../auths/crates`. Distinguishing **what exists** from **what this
demo must build** is the whole honesty of this PRD.

**Exists today (compose, don't rebuild):**

- **OOBI discovery — DONE, conformant.** `auths oobi resolve` (fetch + replay a
  peer's KEL → key-state) and `auths oobi endpoint` (serve an AID's introduction):
  `auths/crates/auths-cli/src/commands/oobi.rs`, `auths/crates/auths-keri/src/oobi.rs`.
  Byte-exact keripy/KERIA conformance in `auths/tests/conformance/` (surfaces
  `oobi-loc-scheme`, `oobi-end-role`). This is the *discovery* leg — done.
- **IPEX grant/admit — wire format present, conformant.** `auths ipex grant` /
  `auths ipex admit`: `auths/crates/auths-cli/src/commands/ipex.rs`,
  `auths/crates/auths-keri/src/ipex.rs` (`IpexGrant` / `IpexAdmit`). Conformance
  vectors `ipex-grant` / `ipex-admit`. The *messages* exist; the live
  mutual-introduction *runtime* that drives them is not wired.
- **Single-org presentation auth — DONE.** `KeriToolAuth`
  (`auths/crates/auths-mcp-server/src/keri_auth.rs`) verifies an
  `Auths-Presentation` (single-use challenge, audience-binding, revocation) via
  `auths_sdk::domains::credentials::authenticate_presentation`
  (`auths/crates/auths-sdk/src/domains/credentials/authenticate.rs:96`) and
  `present_credential` (`.../present.rs:158`). **Constraint:** `KeriToolAuth` is
  pinned to **one** `issuer_alias` / namespace (`keri_auth.rs:33,44`) — it
  verifies callers against the *server's own* registry. There is **no second leg**
  where the *caller* roots the *server* to a *different* org, and no
  cross-registry mutual exchange.
- **Offline-bundle impersonation — HARDENED this cycle (AGT-3 closed leg).**
  `artifact verify --identity-bundle` authenticates the bundle before believing
  its `identity_did`: `resolve_identity_key`
  (`auths/crates/auths-cli/src/commands/artifact/verify.rs:606`) parses it through
  `auths_verifier::BundleTrust::parse`
  (`auths/crates/auths-verifier/src/commit_bundle.rs:77`) — RT-005
  self-certification kills a DID rewritten to a victim. This is the *offline*,
  *one-directional* impersonation guard. FR-2 reuses this mechanism on the live
  path.

**Must BUILD (the AGT-3 live leg — does not exist):**

- **The live in-band mutual-introduction runtime.** A handshake that, in one round
  trip, drives OOBI resolution **both ways**, exchanges introductions over IPEX,
  and verifies **each** party's chain to the **other's own** org root — not the
  single pinned issuer `KeriToolAuth` assumes today. New surface: a cross-org
  authorizer that takes *two* root anchors (mine, theirs) and produces *two*
  verified principals from *one* exchange.
- **Cross-registry verification on the live path.** Today the live presentation
  path (`KeriToolAuth` → `authenticate_presentation`) replays the subject against
  the server's *own* registry. The demo must let a verifier replay a *foreign*
  registry's chain (resolved cold via OOBI) and root it in a *named foreign* org —
  carrying the AGT-3 hardened RT-005 / `BundleTrust` self-certification check onto
  this path so FR-2 holds.
- **Bidirectional scope + mutual revocation observation.** Cap enforcement and
  revocation-event observation on **both** legs (FR-3, FR-4) — the server honors
  the caller's caps *and* the caller honors the server's, and each watches the
  other's chain for revocation (composing `auths-rp` registry-sync, the mechanism
  the death-of-the-api-key demo already uses for one-directional propagation).

SDK / CLI verbs the demo orchestrates: `auths oobi resolve|endpoint`,
`auths ipex grant|admit`, `credential present`, plus the new cross-org
authenticate/present surface this demo must add to `auths-sdk` /
`auths-mcp-server`.

---

## 6. Non-goals

- **Not a live LLM driving intents.** Offline-first, like death-of-the-api-key:
  the agent's *intents* are scripted; every introduction, signature, OOBI replay,
  IPEX exchange, and verdict is real and live.
- **Not human identity, recovery, or guardians.** Agents only; this is the wedge.
- **Not the universal-resolution (`RES`) claim.** OOBI discovery here is *seeded*
  per-party (each side resolves the other cold via OOBI), not introduction-free
  global resolution. Brokerless trust ≠ registryless resolution; that is a
  separate, harder claim.
- **Not quantitative caps (AGT-4).** Scope here is *kind* (`quote:read` vs `book`),
  not *amount/rate* — that is AGT-4, still open.
- **Not a production carrier integration.** Northwind / Pier 9 are staged on one
  box (two isolated registries, two replicas); a literal second box swaps only the
  OOBI URL scheme, exactly as death-of-the-api-key documents for `auths-rp`.
- **Not touching `../auths` source, the running burndown, or `~/.auths` from this
  PRD.** This document specifies; it builds nothing.

---

## 7. The narrative / run.sh dramaturgy

Staged like death-of-the-api-key (self-performing, gates on Enter interactively,
auto-plays non-TTY). Ends on the cold scoped handshake completing **both
directions** and the impersonator **rejected**.

- **Act 0 — Two strangers.** Stand up two fresh registries side by side. Show the
  proof of strangerhood: no shared witness, no shared IdP, disjoint OOBI caches,
  no prior credential exchange. "These two companies have never met."
- **Act 1 — The cold call.** Northwind's dispatch agent (scope `quote:read`) opens
  a connection to Pier 9's rate tool (scope `quote:serve`). On screen: OOBI
  resolution *both ways*, introductions exchanged over IPEX, each side replaying
  the other's chain to the *other's own* org root. **The quote returns — 200.**
  Both server logs name the verified `did:keri:` principal + caps. *One round trip,
  both directions authenticated.* (Pledge-before-proof: state the stakes, then fire.)
- **Act 2 — The impostor.** A third registry, Contoso, forges an "I am Northwind"
  introduction and calls Pier 9. **Rejected** — the carried KEL does not
  self-certify to Northwind's org root (the AGT-3 RT-005 trap, now on the live
  path). Show the exact rejection line.
- **Act 3 — Out of scope.** Northwind's agent asks Pier 9 to `book` a shipment.
  **Rejected** — `book` is not in its credential. Attenuation is structural.
- **Act 4 — Either side pulls the cord.** Pledge, then revoke. **Beat A:**
  Northwind revokes its agent's delegation → next cold call dies. **Beat B:** Pier 9
  revokes its tool's delegation → next cold call dies. Mutually revocable; no
  restart; the *other* side observes the revocation event on the chain it watches.
- **Close.** "Two companies, no contract, no shared login, no exchanged secret —
  one signed introduction each way, and either can end it in one event. This is
  the agentic internet: every published identity makes the next cold handshake
  possible, with no one in the middle."

---

## 8. Success metrics (the verdicts)

- **V1 — Cold mutual call, both ways:** two never-met registries complete a scoped
  call in **one round trip**; each side's log names the *other's* verified
  `did:keri:` principal rooted in the *other's own* org. (FR-1, FR-3, FR-5.)
- **V2 — Impersonator rejected:** a third registry's forged "I am A" introduction
  fails closed with an RT-005 self-certification error on the **live** path.
  (FR-2.)
- **V3 — Out-of-scope rejected:** a cap the credential does not carry is denied at
  verify. (FR-3 twin.)
- **V4 — Revoke kills it — both sides:** after *either* party revokes, the next
  cold call dies, no restart. (FR-4.)
- **V5 — No broker consulted:** the handshake completes with each party verifying
  against its **own** registry replica; no shared IdP / directory / broker is in
  the path. (FR-5.)

Every verdict produced by real auths verification code over real KEL/TEL events in
real registries — nothing mocked, slept-then-printed, or hardcoded (the
death-of-the-api-key bar).

---

## 9. Recurve gap sketch

Draft claims, riclib style — ready for `recurve init --from-prd`. RED today; each
names the smallest platform reality it asserts. (`id` prefix `AGENT-XORG-`.)

```yaml
- id: AGENT-XORG-1
  title: "AGT — two never-met registries complete a scoped call in one round trip, each rooting the other to the OTHER's own org root (no shared IdP)"
  class: missing-surface
  status: open
  covers: ["AGT-3-live"]
  one_line: The live in-band mutual-introduction runtime that AGT-3's closed leg presupposed but does not yet build.
  probe: probes/agent-xorg-1.sh
  accept: two fresh registries exchange introductions; each verifies the other's delegation chain to the other's own org root; the scoped call returns 200, both directions authenticated in one exchange.
  adversarial: a caller whose chain roots in NO root the verifier admits is rejected — no trust-on-first-contact.

- id: AGENT-XORG-2
  title: "AGT — a third registry forging 'I am A' is rejected on the LIVE cross-org path (RT-005 self-certification, not just offline bundles)"
  class: missing-surface
  status: open
  covers: ["AGT-3-live"]
  one_line: Extend the hardened offline BundleTrust RT-005 trap onto the live mutual-introduction path.
  probe: probes/agent-xorg-2.sh
  accept: the legit caller A is verified as A across registries.
  adversarial: a third registry C presenting a forged 'I am A' introduction is rejected (carried KEL does not self-certify to A's org root) — fail-closed.

- id: AGENT-XORG-3
  title: "AGT — scoped capabilities are enforced in BOTH directions across orgs (caller honors server scope, server honors caller scope)"
  class: missing-surface
  status: open
  covers: ["AGT-3-live"]
  one_line: Bidirectional attenuation on the cross-org path, not single-issuer one-way.
  probe: probes/agent-xorg-3.sh
  accept: A's quote:read agent calls B's quote:serve tool → quote returns; each side's verified principal + caps logged.
  adversarial: an out-of-scope call (A asks B to 'book', a cap A lacks) is rejected at verify.

- id: AGENT-XORG-4
  title: "AGT — either side's revocation kills the cold relationship at the next call (mutually revocable, no restart)"
  class: missing-surface
  status: open
  covers: ["AGT-3-live", "OPS"]
  one_line: Mutual revocation observation — each party watches the other's chain for the revoking event.
  probe: probes/agent-xorg-4.sh
  accept: before revoke, the cold scoped call returns the quote.
  adversarial: after A revokes its agent's delegation the next call dies; after B revokes its tool's delegation the next call dies — both directions, no server restart.

- id: AGENT-XORG-5
  title: "AGT — the cross-org handshake completes with NO shared IdP / directory / broker in the trust path (the network-effect property)"
  class: missing-surface
  status: open
  covers: ["AGT-3-live"]
  one_line: Each party verifies against its own trusted registry replica; no common third party is consulted.
  probe: probes/agent-xorg-5.sh
  accept: the full handshake completes; each side verifies against its own registry replica; no shared witness/directory/broker call is made.
  adversarial: any path that REQUIRES a shared third party to complete the handshake fails the claim (broker-gated trust is not the network effect).
```

---

*Generated 2026-06-14. Companion to `roadmap/aspirational_claims/the_missing_layer.md`
(this is the `WED`/`AGT-3` wedge made concrete) and the death-of-the-api-key demo
(house style: narrative + recurve `gaps.yaml` + accept/adversarial probes + staged
`run.sh`). **SPIKED/aspirational:** rides on the AGT-3 **live leg**, which does not
exist yet. OOBI discovery is done and composed; IPEX wire format exists; the live
cross-org mutual-introduction runtime is the build.*
