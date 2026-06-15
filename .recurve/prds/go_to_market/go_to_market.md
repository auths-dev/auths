# auths — Go-to-Market Strategy & Product Planning Input

> **How to use this doc (for a planning LLM or a human).** This is both a GTM
> strategy and a planning input. Sections 1–6 set the thesis (the *why* and the
> *what-must-be-true*). Sections 7–8 are the actionable backlog — product
> features and go-to-market motions concrete enough to decompose into epics.
> Sections 9–11 phase the work, define success, and flag the decisions a planner
> must NOT guess. When you plan from this, anchor every feature to the adoption
> lever it serves (§6) — features that serve no lever are out of scope.
>
> **Epistemic status.** This is derived from auths's demonstrated capabilities
> (the five demos + the platform crates) and general developer-infrastructure
> go-to-market patterns. It is **not** based on internal traction, revenue,
> funding, or roadmap data — those are unknown here. Treat the wedge choice and
> sequencing as strong recommendations with stated reasoning, not settled fact;
> §11 lists what must be validated with real data.

---

## 1. Positioning & the wedge decision

**One line:** *auths is verifiable, revocable identity for the things developers
and their agents sign — built so anyone can verify it with no trusted third
party.*

**The wedge (lead with ONE):** **identity for AI agents** — issue an agent a
real, scoped, instantly-revocable identity, and verify what it did without
trusting any central server.

**Why this wedge and not the others:** auths is a *horizontal* primitive (one
KERI-based identity engine; five demo domains). Horizontal is a technical
strength and a go-to-market **weakness** — five half-markets is not a beachhead,
and breadth is how infrastructure dies of diffuseness. Exactly one demo domain is
a *screaming, unserved, switching-cheap pain where you are early*: agent
identity. The agent explosion is creating a brand-new identity problem that the
incumbents (API keys, OAuth-built-for-humans, SPIFFE-built-for-pods) handle
badly. Lead there. **Demote the other four demos to proof-points** ("the same
primitive also signs your commits, your releases, your compliance evidence"),
not parallel sales motions.

**KERI is the engine, not the pitch.** The word "KERI" must not appear in a
new user's first five minutes. The entire SSI/DID/PGP generation died of *visible
complexity* — users had to understand the model to use it. auths's demos already
hide KERI behind `git commit`, OIDC, and a mobile app; that instinct is the most
important thing the project does right. Productize invisibility.

---

## 2. Why now (the market window)

- **Agents are proliferating faster than their identity story.** Autonomous and
  semi-autonomous agents need identity, scoped capability, and instant
  revocation. The default today is "give the agent an API key" (valid
  everywhere, revocable nowhere) or a human-shaped OAuth token. Security teams
  are visibly alarmed by agent credential sprawl. This is an acute, *new*, fast-
  growing pain with no entrenched incumbent.
- **MCP is becoming the agent-tool protocol**, and its authentication story is
  immature. "The auth layer for MCP servers" is a concrete, timely, ownable
  niche — and auths already has `auths-mcp-server` shipping KERI-presentation
  auth.
- **Supply-chain security is hot** (post-SolarWinds / xz) — but Sigstore owns it.
- **Regulated digital identity is moving** (EU eIDAS 2.0 / EUDI wallet; GLEIF's
  vLEI) on KERI/ACDC rails — a separate, top-down, compliance-forced tailwind.

The window is the agent moment. It closes as someone else productizes agent
identity (or as the agent frameworks bake in their own).

---

## 3. Ideal Customer Profile

**Wedge ICP (sell here first):** engineering/platform/security teams shipping
**AI agents, MCP servers, or autonomous workflows into production** who already
feel credential-sprawl pain — many agents, many tools, no good way to scope or
revoke. Buyer: the platform/security lead who owns "how do our agents
authenticate and what can they do." Technical, early-adopter, switching cost low
because there's often *nothing there yet* (greenfield).

**Expansion ICPs (the proof-points, later):**
- Dev-platform teams who sign commits/releases and have been burned by key/CA/IdP
  pain (→ code & supply-chain signing).
- Compliance/GRC teams wanting offline-verifiable evidence (→ the auditor demo;
  hard channel, conservative buyers, incumbent-owned workflow).
- Regulated orgs needing verifiable organizational identity (→ vLEI / eIDAS,
  top-down).

---

## 4. Competitive landscape & how to position

| Incumbent | What they own | auths's wedge framing |
| --- | --- | --- |
| **SPIFFE/SPIRE** (CNCF workload identity) | Service-to-service identity rooted in *infrastructure attestation* (k8s node, cloud metadata) | "SPIFFE for things that live in your cluster; **auths for agents that don't** — portable, self-certifying identity that travels across hosts/clouds and survives key loss." |
| **API keys / secrets managers** (Vault, cloud secrets) | Bearer-token access | "A bearer token is valid everywhere and revocable nowhere. auths gives a *signed presentation* you can revoke with one event." |
| **OIDC / IdPs** (Okta, Auth0, Entra, Clerk) | Human + workload SSO, central IdP as arbiter | Complement then compete: *use* OIDC to bootstrap, but remove the standing central arbiter for delegated/agent auth. |
| **Sigstore / cosign / Rekor** (CNCF) | Supply-chain artifact signing (ephemeral OIDC certs + transparency log) | Don't fight head-on early. Differentiator is *persistent, self-controlled* identity with native rotation/delegation vs ephemeral re-minted certs — subtle, only felt at rotation/revocation pain. A proof-point, not the wedge. |
| **GPG/SSH git signing** | Commit signing | Strictly better: KEL-replay verification vs failed web-of-trust / vendor "Verified" badge, behind a plain `git commit`. Proof-point. |
| **SSI/DID, KERI itself, vLEI** | The decentralized-identity lineage auths is built on | Be a *conformant member*, not a fork (see `interop/plan.md`). Ride the vLEI/eIDAS tailwind; don't reinvent. |

**The differentiation that is always true and worth leading with:** *verification
is a computation you run, not an assertion you trust* — no CA, no IdP, no vendor
server in the trust path at verify time. Everything else is a consequence.

---

## 5. The two adoption vectors

1. **Bottom-up (developers / agents / MCP) — the fast lane.** Land via the agent
   wedge: MCP-native auth + agent-framework SDKs + minutes-to-value. Network
   effects from a growing set of published identities to verify against.
2. **Top-down (regulated identity / vLEI / eIDAS) — the slow but tailwind lane.**
   KERI/ACDC conformance lets auths ride GLEIF/eIDAS mandates into compliance-
   forced adoption. "auths holds a vLEI" is the bridge artifact.

**Sequencing recommendation:** win the bottom-up agent wedge first (speed,
greenfield, low switching cost), keep top-down conformance work alive in parallel
(it's cheap insurance + credibility + a second engine), converge them once the
wedge has traction.

---

## 6. The adoption gauntlet — what must be true (the levers)

Almost none of this is technology; the tech is the easy part. In priority order:

- **L1 — Focus on one wedge.** Agent identity. Everything else is a proof-point.
- **L2 — Time-to-first-value in minutes, KERI invisible.** A 5-minute "aha"
  (issue an agent identity → revoke it → watch the next call die) with no
  concepts to learn first. This is the single highest-leverage UX bar.
- **L3 — Integration where developers already are.** MCP, agent frameworks,
  CI/CD, package registries. Identity infra is worth exactly what it plugs into.
- **L4 — The operational trust-root backbone.** Witnesses/watchers/OOBI discovery
  must be *run for you* (hosted) or *trivially self-hostable*. Today it's staged
  (single-registry, no witnesses). This is the unglamorous backbone that decides
  whether the model is operable in production.
- **L5 — Credibility + neutral governance.** A named-firm security audit; spec
  presence; and — sharper for auths than for normal SaaS — **neutral governance
  for the trust-critical core**, because "trust no third party" and "trust this
  one startup" cannot both be true. This is load-bearing, not optional polish.
- **L6 — Enterprise table-stakes.** SDKs everywhere, console (RBAC/SSO/audit
  logs), observability, SLAs, auths's own compliance certs.
- **L7 — A lighthouse customer** in the wedge whose name + story you can publish.

---

## 7. Product feature backlog (planning input)

> Decompose each theme into epics. Priorities: **P0** = required for the wedge to
> land; **P1** = required to scale/expand; **P2** = maturity. Each item names the
> adoption lever (L1–L7) it serves.

### 7.1 Onboarding & time-to-first-value — **P0** (serves L2)
- Single-command install across ecosystems: Homebrew, `cargo install`, `pipx`,
  `npm`/`npx` — one binary, no toolchain.
- `auths init` / quickstart that delivers the agent "aha" in ≤5 minutes, zero
  KERI vocabulary, copy-paste-able.
- **MCP server starter template** with auth built in (`create-auths-mcp` or
  equivalent) — the fastest path to the wedge.
- A hosted, zero-install **interactive playground / sandbox** (issue → present →
  revoke → verify) for the docs site.
- The five demos refactored into **copy-paste starters**, each one-command.
- A "KERI-invisible" UX/copy audit: every user-facing string, error, and concept
  reviewed so nothing leaks the model before the user is hooked.

### 7.2 The agent-identity wedge product — **P0** (serves L1, L3)
- **Agent identity issuance** (CLI + API + SDK): mint a delegated, self-certifying
  identity for an agent under an org/service root.
- **Scoped capability credentials** (ACDC-backed): caps + TTL + audience,
  attenuable down a delegation chain (org → service → agent).
- **One-call instant revocation** with a verifiable, KEL-anchored verdict (the
  "death of the API key" beat as a product, not a demo).
- **Presentation-verification middleware/SDK** (the MCP `keri_auth` path,
  generalized): drop-in auth for an agent endpoint that verifies a presentation
  offline.
- **Agent-framework integrations/SDKs**: MCP (first), then LangChain/LlamaIndex/
  CrewAI and the OpenAI/Anthropic agent SDKs. Each: "give your agent an identity
  in 3 lines."
- **Key custody per environment**: Secure Enclave on device, KMS/HSM for servers,
  the FFI-never-holds-the-key property preserved everywhere.
- **Agent action audit trail**: every signed action verifiable + queryable.
- **Console "agents" view**: see every agent identity, its scope, its delegation
  chain, revoke from a button.

### 7.3 Trust-root backbone — **P0/P1** (serves L4)
- **Hosted witness/observer network** (managed): availability for the trust root
  without each org running infra. (Business model + a centralization tension to
  resolve — see §11.)
- **One-command self-hostable** witness/watcher (the Tailscale-grade "just works"
  alternative for orgs that won't trust a hosted root).
- **OOBI discovery service** + **KSN (key-state-notice) endpoints** — how parties
  find and stay current on each other's key state.
- **Productized registry** of published trust roots / identities (the
  network-effect flywheel: more published → more worth verifying against).
- Availability targets / SLAs for the backbone.
- *Note:* witness/KSN conformance is also the mechanism the demos' hardest
  security gap needs (witness-anchored revocation) — build it once, it serves
  both product and the platform's own roadmap.

### 7.4 Ecosystem & interop — **P1** (serves L3, L5; top-down vector)
- **KERI conformance** end to end — execute `interop/plan.md` (keripy + keriox +
  KERIA/signify + cesride). Be a *member*, not a fork.
- **vLEI holder capability** + **did:webs resolution** — the regulated-identity
  bridge + standard DID resolvability.
- **Contributions to WebOfTrust / the KERI & ACDC specs**, and to the **MCP auth
  spec** — standards presence is credibility.

### 7.5 Enterprise table-stakes — **P1/P2** (serves L6)
- SDKs in every major language; reference docs; OpenAPI/typed clients.
- **Console**: org/team management, RBAC, SSO, **audit logs**, policy/approval
  surfaces (the platform already has `policy`/`approval`/`org` primitives —
  productize them).
- Observability: metrics, logs, traces for verifications/revocations.
- SLAs, support tiers, and **auths's own SOC2/ISO** (you can dogfood the
  compliance demo for this).

### 7.6 Credibility & governance — **P0 (start now), ongoing** (serves L5)
- **Third-party security audit** by a recognized firm; publish it.
- **Public threat model** + the honest "what we do and don't guarantee" doc
  (extend the demos' GAPS.md discipline to the product).
- **Open-source the verifier/core** (the trust-critical, must-be-inspectable
  parts) — define the open-core boundary (§11).
- **Neutral-governance plan** for the trust-critical core (e.g. CNCF sandbox / a
  foundation), with a credible timeline — this is load-bearing for the core
  claim, not marketing.

---

## 8. Go-to-market motions & processes (planning input)

### 8.1 Developer relations & content (serves L1, L2, L7)
- A docs site whose hero is the agent quickstart and the "verification is a
  computation" thesis; the playground embedded.
- Thought-leadership on **agent identity** (the wedge), not on KERI. Talks at AI-
  agent, platform-eng, and supply-chain venues; plus IIW/KERI community for the
  top-down credibility.
- An example gallery (the demos-as-starters) and integration recipes per agent
  framework.

### 8.2 Design-partner / lighthouse program (serves L7)
- Recruit **3–5 teams shipping agents to production**; co-build the integration;
  instrument time-to-value; produce published case studies. Land one marquee
  "our agent fleet runs on auths" reference.

### 8.3 Open-source & community (serves L3, L5)
- Define the **open-core split** (verifier/core open; hosted backbone/console
  commercial — decision in §11).
- Join the **WebOfTrust** community; contribute via the interop work; presence in
  the **MCP ecosystem** (registry, examples, spec).

### 8.4 Distribution (serves L2, L3)
- A **GitHub App + Action** (the OIDC→delegation path already targets CI).
- Package-manager presence (brew/cargo/pip/npm), the **MCP registry**, and
  relevant marketplaces.

### 8.5 Standards participation (serves L5; top-down vector)
- Track/contribute to KERI/CESR/ACDC IETF drafts, the MCP auth spec, and the
  eIDAS 2.0 / EUDI conversation where KERI/vLEI is in play.

### 8.6 Pricing & packaging (serves adoption economics — decision in §11)
- A **free tier** generous enough that the "aha" needs no sales call, individuals
  and OSS never pay.
- A usage metric that does **not** punish network-effect growth (avoid per-seat
  for a primitive used by many agents; consider per-active-identity or per-
  verification, validated with design partners).

### 8.7 Security & trust assurance (serves L5)
- Schedule the audit early; bug-bounty; public incident/transparency posture
  consistent with a trust vendor.

---

## 9. Phasing & milestones (roadmap skeleton)

- **Phase 0 — Sharpen the wedge (now).** Pick agent identity (confirm via §11);
  the 5-minute MCP quickstart; refactor demos to proof-points; start the audit +
  governance plan. *Exit:* a stranger ships an agent identity + revocation in ≤5
  min with no KERI vocabulary; one design partner committed.
- **Phase 1 — Land the wedge.** Agent SDKs (MCP first), presentation middleware,
  console agents view, hosted-or-self-hostable trust backbone MVP, 3–5 design
  partners in production, security audit published. *Exit:* a published lighthouse
  reference; weekly-active identities growing; first paid usage.
- **Phase 2 — Credibility & interop.** Execute `interop/plan.md` (KERI
  conformance), vLEI holder + did:webs, neutral-governance move underway, enterprise
  console (RBAC/SSO/audit), auths's own SOC2. *Exit:* "auths holds a vLEI";
  conformance matrix green; an enterprise logo.
- **Phase 3 — Expand to proof-points + top-down.** Code/release signing and
  supply-chain (vs Sigstore, where rotation/revocation pain is felt); the
  regulated-identity / eIDAS motion. *Exit:* multi-domain customers; a second
  vector producing pipeline.

---

## 10. Success metrics (per phase)

- **TTFV**: minutes from install to first revoked-agent "aha" (target ≤5).
- **Activation**: weekly active identities; agents under management.
- **Integration breadth**: frameworks/registries shipped; MCP servers using auths.
- **Design partners → production → references** (count + named).
- **Interop conformance**: % of `interop/plan.md` layers green; "holds a vLEI" Y/N.
- **Credibility**: audit published Y/N; governance move announced Y/N.
- **Commercial**: paid usage; expansion from wedge to proof-point domains.

---

## 11. Open decisions a planner must NOT guess

Resolve these with real data/leadership before building broadly:
1. **Is agent identity the confirmed wedge?** (Recommended; validate against your
   actual inbound/pipeline and where pain is loudest.)
2. **Hosted trust backbone vs self-host-only** — and how to reconcile a hosted
   root with the "no trusted third party" ethos. Core tension.
3. **Open-core boundary** — exactly which crates/services are open (verifier/core
   should be) vs commercial (hosted backbone/console likely).
4. **Governance model + timing** — foundation/CNCF vs company-owned, and when. The
   core trust claim depends on the answer.
5. **Pricing metric** — per-identity / per-verification / usage; validate it
   doesn't tax network-effect growth.
6. **KERI-conformance-first vs ship-fast** — how much to invest in interop before
   the wedge has traction (recommend: keep conformance alive in parallel, cheap;
   don't block the wedge on it).
7. **Build a witness network vs ride the existing KERI witness ecosystem** —
   interop (the plan) may let you avoid building the backbone alone.

---

## 12. How this connects to the existing repo

- **The five demos (`auths-demos/`)** are the proof that the platform is real and
  the philosophy coherent. Re-cast them per §1: the agent demo
  (`death-of-the-api-key`) is the **wedge spearhead**; the others are
  **proof-points**. Each becomes a copy-paste starter (§7.1).
- **The recursive-improvement loop (`auths-demos/recursive_improvement/`)** is how
  the platform keeps its promises with no asterisks — it hardens `../auths`
  against the demos' own claims. GTM credibility (L5) rests on the platform
  actually doing what it says; the loop is the engine that guarantees it. Extend
  its GAPS.md honesty discipline to the *product*, not just the demos.
- **The interop plan (`interop/plan.md`)** is the precondition for L5 (credibility)
  and the top-down vector (vLEI/eIDAS) — and it unblocks the demos' hardest
  security gap (witness-anchored revocation) and the trust-root backbone (§7.3).
  It converts "is auths a fork?" into "auths is a conformant KERI member."

---

## 13. Anti-goals (what NOT to do)

- **Don't sell horizontally to everyone.** Five half-markets is the failure mode.
  One wedge, proof-points behind it.
- **Don't lead with KERI / cryptography.** Lead with the agent pain solved. The
  model stays invisible until the user is hooked.
- **Don't be the only trusted root.** "Trust no third party" and "trust this
  startup's server" cannot both be true — governance + self-hostability resolve it.
- **Don't fight Sigstore head-on early.** Supply chain is a proof-point in Phase
  3, not the wedge.
- **Don't gate the "aha" behind a sales call or a concept lesson.** Time-to-value
  in minutes is the whole game; the SSI graveyard is full of better tech that
  asked users to learn the model first.

---

### References / related docs
- `auths-demos/` — the five demos (the proof; the wedge + proof-points).
- `auths-demos/recursive_improvement/` — the platform-hardening loop (`rictl`,
  `RUN.md`, `RUN-AUTO.md`); the engine behind "no asterisks."
- `interop/plan.md` — KERI conformance plan (credibility + top-down vector +
  trust-root backbone precondition).
- `../auths` — the platform (the identity engine being taken to market).
