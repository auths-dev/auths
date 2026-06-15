# PRD: auths-mcp — the bounded-agent MCP gateway (a go-to-market product)

> **One line:** a *real* LLM agent, running a *real* tool loop over MCP, is handed a
> **scoped, budget-bound, instantly-revocable delegation** by its parent — and when the
> model itself *decides* to exceed its scope, overspend its budget, or keep working after
> it's been revoked, the **gateway refuses the tool call at the protocol boundary**,
> cryptographically, from the chain alone. The over-reach is the *model's*, not a hardcoded
> string. Every brokered call leaves a verifiable receipt.
>
> **What this is — read first.** `auths-mcp` is a **go-to-market product**: the thing a developer
> installs (`npx @auths/mcp`) to bound a **live agent's own decisions** at the MCP tool boundary.
> Its **engine is Rust crates in the `auths` monorepo** (next to `auths-verifier`/`auths-sdk`,
> where they're cheap to maintain); **`auths-mcp` is a thin npm/distribution repo** — the launcher,
> per-client config glue, examples, and install smoke — so users get a one-line install with no
> toolchain. **Nothing lands in `auths-demos`.** Contrast the five shipped agent demos
> (`the-intern-that-couldnt`, …): *honest scripted proofs* with **hardcoded intent**
> (`worker_commit … admin`) — the **unit tests of the wedge**. They don't answer "why would a
> developer reach for this," because the agent isn't real and the thing isn't installable.
> `auths-mcp` is the installable answer, and the **"one-call agent SDK"** from `launch_ideas.md`,
> made concrete against the agent↔tool boundary winning in 2026: **MCP**. (Bonus: it ships
> scope/budget/kill-switch scenarios as ~20-line **configs** of one gateway, giving each scripted
> demo a real installable counterpart.)
>
> **Honest scope & cost.** This is a **product, not a demo costume** — real software (two new Rust
> crates in the monorepo + a thin npm wrapper repo + a live-agent harness), a bigger lift than any
> single `run.sh`, sized and reviewed as a shippable integration. It earns the cost by being the
> *one* installable surface every wedge scenario instantiates, instead of N bespoke narrations.
>
> **Deliberate departure from house style:** the scripted demos are "offline-first, no live
> LLM." This one's whole reason to exist is the opposite — **a live model must really decide
> to misbehave.** That is reconciled for CI by a **recorded-transcript replay mode** (§7): the
> show runs a live agent; the *gate/probe* runs a frozen transcript of the agent's decisions,
> so enforcement is verified hermetically and deterministically.
>
> **A crate already exists — and it isn't real MCP.** `crates/auths-mcp-server` (~1.7k LOC,
> axum) is a "reference MCP tool server" whose **KERI-presentation auth core** (offline
> delegated-credential verify + revocation + capability gate + sandbox) is excellent and
> **reusable** — but its *transport* is HTTP + `Authorization: Bearer/Auths-Presentation` to REST
> endpoints, **not** the MCP wire protocol, so no real MCP client (Claude Desktop, the Agents
> SDK, Cursor) can connect to it. Pre-launch ⇒ **no back-compat**: the plan **harvests only the
> KERI-presentation core** (the no-issuer path) into the new engine crates, **replaces the
> transport** with real MCP, and **drops the JWT/OIDC mode** from the gateway (§5, §10) — the
> gateway trusts no issuer; OIDC stays an optional door-step exchange, not a mode.
>
> **Authoring scope:** READ-ONLY on `../auths` for this PRD. The recurve loop is **multi-tree**
> (§10): `[target] = auths` (the engine crates, sculpted + read by probes) and
> `[sculpts.auths-mcp] = ../auths-mcp` (the npm wrapper repo, built + gated + committed there, and
> sculptable for wrapper-side gaps) — the two trees feed each other through one ledger and a
> federated gate. Nothing lands in `auths-demos`.

---

## 1. One line + scenario

A developer runs an agent — a real Claude (or any MCP-speaking model) in a real tool loop.
The agent has tools: a filesystem server, a GitHub server, a payments/“paid-API” server,
all reached over **MCP**. Today the agent holds those tools' **API keys** (ambient, total
authority) or an **OAuth bearer token** (asserted scopes the tool must trust). If the model
is buggy, prompt-injected, or just over-eager, nothing at the tool boundary can re-derive
that *this* agent was only ever allowed to read, or to spend $5, or that it was revoked
thirty seconds ago.

Now insert the **auths gateway** between the agent and its tools. The parent — the human, or
an orchestrator agent — mints the working agent a **delegation**: `scope = {fs.read,
github.comment}`, `budget = $5.00`, `ttl = 30m`, anchored in the parent's KEL. The agent's
MCP client points at the gateway instead of at the raw tool servers — and the **gateway custodies
the downstream tool's credential while the agent holds only the delegation**, so a misbehaving agent
cannot route around it (§12). Every `tools/call` the
model emits is intercepted, checked against the agent's **delegator-anchored grant**, signed
into a per-call proof, and forwarded **only if it is inside scope, inside budget, unexpired,
and unrevoked** — otherwise it comes back as a fail-closed MCP error the model can read and
react to.

Then the realistic failure, *driven by the model itself*: the agent, mid-task, decides it
needs to `fs.write` (it was granted only `read`), or it loops a paid tool past `$5`, or the
human hits "kill" and the agent tries one more call. **The signature on each attempt is
valid. The MCP envelope is well-formed. It is asking for more than its parent ever anchored
— so the gateway refuses, from the chain alone, offline.**

**How it breaks today (MCP's own auth story):** MCP's auth spec is OAuth 2.1 — the agent
presents a **bearer token** the tool server validates against an authorization server it
trusts. Bearer = ambient: steal the token, hold the authority; the proof isn't bound to the
*action*. Scopes are **strings the AS asserted**, not containment the tool can re-derive.
Budgets are **boolean** ("has the `payments` scope") — OAuth cannot say "≤ $5." Revocation
has a **propagation window** (token TTL + introspection cache). And in practice most MCP
servers today don't even do OAuth — they read an **API key from an env var**. None of these
can prove, at the tool boundary, that link *N+1* holds no more than link *N*.

**What auths does:** the tool call *is* a signed artifact. The gateway resolves the agent's
delegated KEL **and** its delegator's KEL, replays with delegator-aware lookup, reads the
**delegator-anchored scope/budget/expiry seal**, and judges the call against it — returning a
distinct verdict (`OutsideAgentScope` / `UsageCapExceeded` / `AgentExpired` / `Revoked`). The
authority the model is trying to exercise **was never anchored for it by its parent, so it
does not exist** — no matter how the model "decided."

---

## 2. The property it proves

**A real agent runtime, bounded at the protocol boundary by cryptographic delegation —
enforced per tool-call, offline, from the signed chain.** The agent is a live model making
its own decisions; the bound is not a confirmation dialog, not a policy engine, not the
issuer's good behaviour, but the same parent→child containment the scripted demos prove —
now applied **where agents actually run**, on the artifact that actually matters (the tool
call). The bound is identical whether a live model or a script emits the call — what the runtime adds
is believability and packaging, not a stronger property (see below, and §12 for the trust model).

What the live runtime adds over the scripted demos is not a stronger property — the enforcement is
identical — but **believability** (the over-reach is the model's own, genuinely emergent) and
**packaging** (a drop-in gateway in front of an existing MCP toolchain). The trust model that makes
that gateway unbypassable is §12.

**Why the incumbents structurally can't match it:**

| Incumbent (the actual 2026 MCP auth story) | Where authority lives | Why it can't bound a real agent's tool calls |
|---|---|---|
| **OAuth 2.1 bearer tokens** (the MCP auth spec) | a token the AS minted; scopes are asserted strings | Bearer = ambient: the proof isn't bound to the action, so a leaked token is full authority. The tool trusts the AS to have granted only what it should; it can't re-derive containment. Scopes are boolean — **no quantitative budget**. Revocation lags (TTL + cache). |
| **API keys in env vars** (what most MCP servers really use) | nowhere — possession is the grant | No parent, no chain, no attenuation, no budget, no per-call binding. An injected agent with the key has everything the key has. |
| **Human-in-the-loop approval dialogs** (today's UX answer to over-reach) | a person clicking "allow" | Doesn't scale to a fleet or to autonomous runs, is not cryptographic, leaves no verifiable receipt, and is exactly what agents exist to remove. Approval ≠ containment. |

None lets a **stranger tool server**, offline, prove from signatures alone that *this*
agent's call is within a budget and a scope its parent provably anchored — and revoke it with
no window. That is what makes a 10,000-agent fleet *insurable* and a paid-tool integration
*safe to expose*.

---

## 3. Goals — what makes it believable

- **G1 — A real model, a real loop, a real tool.** The agent is a live MCP-speaking model in
  an actual `tools/call` loop against at least one real downstream MCP server (filesystem or
  GitHub) plus one "paid" tool (a metered server). No mocked agent; the decisions are the
  model's. (CI uses a *recorded transcript* of those decisions — §7 — never a fake model.)
- **G2 — The over-reach is emergent, then bounded.** The compelling beat is a tool call the
  *model* chose — out of scope, over budget, or post-revocation — refused at the gateway with
  a distinct verdict, while a valid in-bounds call from the same agent passes. *The model
  decided; the chain refused.*
- **G3 — Drop-in, not a rewrite.** Adopting it is repointing the agent's MCP client at the
  gateway URL + holding a delegation, not re-instrumenting the toolchain. The gateway proxies
  arbitrary downstream MCP servers; the enforcement is additive.
- **G4 — Every call is receipted.** Each brokered call (allowed *or* refused) emits a signed,
  independently-verifiable receipt — who acted, under which grant, on what action, with what
  verdict — replayable offline with `auths verify`. The audit trail is cryptographic, not log
  scraping.
- **G5 — Scenarios are configs, shipped as examples.** The `intern` (scope), `credit-limit`
  (budget), and `kill-switch` (revocation) scenarios each run as a **~20-line config of this one
  gateway**, shipped in `auths-mcp/examples/` — proving the O(n)-bash-demos → O(1)-product
  collapse and giving each scripted demo a real, installable counterpart.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with an **observable (accept)** and an **adversarial twin
(fail-closed)**. IDs `AGENT-MCP-*`. They reuse the already-closed primitives **AGT-1**
(scope), **AGENT-MCP-3↦AGT-4** (caps), **OPS-1** (revocation), **AGT-3** (cross-org).
**AGENT-MCP-1 is load-bearing: it builds the gateway and the MCP↔auths binding.**

- **AGENT-MCP-1 — The gateway brokers a real MCP tool call with a signed, verified proof (THE
  BUILD).** *Maps: new integration surface (rides AGT-1's artifact verify path).* An agent
  holding a delegation calls a downstream tool **through the gateway**; the gateway signs the
  serialized `tools/call` as an auths artifact, verifies it against the agent's
  delegator-anchored grant, forwards it to the real downstream server, and returns the real
  result plus a receipt.
  - **Observable (accept):** an in-scope, in-budget call (`fs.read("README")`) round-trips —
    real downstream result returned, receipt emitted (`device=agent`, `identity=parent-root`),
    `auths verify` of the receipt accepts.
  - **Adversarial twin:** with the gateway removed (raw passthrough) the same call is
    *unauthenticated* — no proof, no receipt; with the gateway in place a malformed/forged
    proof is rejected **at the boundary before the downstream server is touched** (the tool is
    never invoked on a bad proof).

- **AGENT-MCP-2 — An out-of-scope tool call is refused at the boundary with a distinct
  verdict.** *Maps: AGT-1.* The agent holds `{fs.read}`; the model emits `fs.write(...)`.
  - **Observable (accept):** the in-scope `fs.read` call passes.
  - **Adversarial twin:** the `fs.write` call returns a fail-closed MCP error carrying
    **`OutsideAgentScope`**, naming the offending capability — **the downstream filesystem
    server is never called** — despite a valid signature and a well-formed envelope.

- **AGENT-MCP-3 — One quantitative budget, enforced by pre-authorization, across a session *and
  across rails*.** *Maps: AGT-4 (+ AGT-1 for the cross-rail attenuation).* The agent holds a single
  `budget = $5.00` (or `≤ N calls`); its metered downstreams are **two different payment rails** (e.g.
  Stripe test-mode and x402/USDC). The counter is **two-part**: a monotonic **settled** total (AGT-4's
  verifier-held high-water ledger, keyed to the agent's delegation — atomic, rollback-protected,
  checkpoint-anchored; **no per-call chain write, no log growth**) and a transient set of **reserved**
  holds. `available = cap − settled − Σ(active holds)`. Before each paid call the gateway **reserves** a
  hold for the known cost (or a ceiling, for metered calls) — refusing if it would exceed `available` —
  lets it proceed, then on the response **settles** the *actual* into the monotonic total and **releases
  the slack** (a hold expires if its call never returns). Monotonicity applies to *settled*; *reserved*
  is the transient auth-hold, so the two don't conflict. The cap is anchored once in the credential; the
  settled total's digest is **checkpoint-anchored periodically** (D8), tamper-evident and
  offline-verifiable without a write per payment. **Honest cost & bound:** a periodic checkpoint, not a
  per-call write; un-exceedable only when per-call cost is known or reservable as a ceiling; and on a
  counter-integrity failure, **max *uncaught* overspend ≤ one checkpoint interval — detection is not
  reversal** (§12). Rails are *wrapped, not built* — §11.
  - **Observable (accept):** calls whose *combined reserved* cost across both rails is ≤ $5 pass and
    settle; the running cross-rail total is in each receipt.
  - **Adversarial twin:** the call that would *reserve past* $5 — **on either rail** — is refused
    **`UsageCapExceeded`** and **never settled** (the reservation fails before the rail is touched);
    `$4.99`-on-Stripe `+ $0.02`-on-x402 is refused, where two siloed per-rail budgets each still read
    "$0 spent." The counter is monotonic — a replayed/lower total is rejected
    (`UsageCounterRolledBack`). Stronger still (the moat): a sub-agent handed a `$2` slice provably
    cannot exceed it on *any* rail, and one revoke stops spend everywhere at once.

- **AGENT-MCP-4 — Revocation is instant, mid-session, with no propagation window.** *Maps:
  OPS-1.* The parent revokes the agent's delegation while the loop is running.
  - **Observable (accept):** calls before revocation pass.
  - **Adversarial twin:** the **very next** `tools/call` after the revocation event is refused
    **`Revoked`** — no token still valid for its TTL, no introspection-cache lag; the gateway
    re-derives liveness from the chain on every call.

- **AGENT-MCP-5 — The over-reach is the model's, and it reproduces deterministically.**
  *Maps: the “real agentic framework” property itself (the gap this whole PRD closes).* In the
  live show, a real model — given an injectable/over-eager task — *itself* emits the
  out-of-bounds call. For CI, the recorded transcript of that exact decision drives the same
  gateway to the same verdicts. (Honesty: this is **believability, not a stronger property** — the
  gateway sees the identical `tools/call` whether a model or a script emits it; the live model proves
  the over-reach is *genuinely emergent*, the transcript is what tests the enforcement.)
  - **Observable (accept):** live mode: a real model run produces ≥1 genuinely emergent
    out-of-bounds call that the gateway refuses (disclosed: model + prompt on screen).
  - **Adversarial twin:** replay mode over the frozen transcript yields **byte-stable
    verdicts** in CI with no network/model dependency — and a transcript edited to remove the
    proof, or to forge a wider scope, still fails closed.

- **AGENT-MCP-6 — Cross-org: org A's agent is bounded by an A→B scoped introduction (STRETCH).**
  *Maps: AGT-3 (live leg).* The agent is delegated by org A and calls a gateway operated by
  org B, which honors a scoped A→B introduction.
  - **Observable (accept):** a call within the A→B grant passes at B's gateway.
  - **Adversarial twin:** a call exceeding the A→B grant is refused at B — A cannot widen its
    own introduction, and B never trusts A's self-asserted scope. *(Rides AGT-3's open live
    half; PARK rather than stub if the mutual-introduction runtime isn't ready.)*

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy`; exact paths pinned during the sculpt (this PRD is
read-only). **Pre-launch ⇒ no back-compat: existing surfaces are harvested and reshaped for the
right product, not preserved.**

### Exists — the enforcement primitives are closed; this integration consumes them
- **`crates/auths-mcp-server` already exists** (~1.7k LOC, axum). Its **KERI-presentation auth
  core is the reusable gold**: an agent presents an `Auths-Presentation` (the no-issuer passport),
  verified **offline** via `auths_sdk::domains::credentials::authenticate_presentation` against
  the KERI registry — single-use challenge/nonce, audience binding, **revocation** — behind a
  per-tool **capability gate** (`keri_auth.rs`, `auth.rs`, `middleware.rs`), with a traversal-safe
  `Sandbox` (`tools.rs`). **Harvest this.**
- **Artifact sign/verify over arbitrary bytes** — `auths artifact verify` (hardened by the AGT-3
  fix to authenticate the KEL via `BundleTrust::parse`). A serialized MCP `tools/call` is just an
  artifact → the gateway's sign/verify substrate, not only git commits.
- **Delegated, scoped agents** — `id agent add --scope --expires-in` →
  `auths_sdk::domains::agents::add_scoped` (delegator-anchored seal; subset rule hardened in
  `AGENT-ATTEN-3`).
- **Fail-closed verdicts** — `OutsideAgentScope`, `AgentExpired` (auths-verifier); the **AGT-4**
  quantitative usage-cap verdict (`15bc605c`, plus the `AGENT-CAP-1` malformed-predicate issuance
  guard `00de275c`); the **OPS-1** revocation path.
- **An OIDC→auths bridge already exists** — the `auths-oidc-port` crate (with `auths-jwt`,
  `auths-rp`). This is the *door-step exchange* (OIDC token → bounded no-issuer delegation), so the
  gateway never needs a JWT mode of its own.

### The issues with the existing crate (fixed as part of the plan — no back-compat owed)
1. **It isn't real MCP.** Tools are exposed over HTTP with `Authorization:
   Bearer/Auths-Presentation` to REST endpoints — **not** MCP's JSON-RPC 2.0
   (`initialize`/`tools/list`/`tools/call`) over stdio + Streamable HTTP. A real MCP client cannot
   connect. → **replace the transport** with the official Rust MCP SDK (`rmcp`).
2. **It's a tool *host*, not a *proxy*.** It serves 3 demo tools (read/write/deploy-mock). Wide
   adoption means **bounding existing downstream tools**, not reimplementing them. → **add proxy /
   passthrough** to arbitrary downstream MCP servers.
3. **Boolean capability gate only** — no quantitative budget (AGT-4), no signed per-call receipts.
   → **add session budget accounting + receipts**.
4. **JWT mode reintroduces an issuer** (an OIDC bridge + JWKS in the trust path) — the exact thing
   auths removes. **DECIDED:** the gateway is **purely no-issuer**; JWT/JWKS is **dropped** from
   it. OIDC shops are served by a separate, optional **door-step exchange** (reuse
   `auths-oidc-port`: trade an OIDC token for a bounded no-issuer delegation *once*, then every
   `tools/call` is verified with zero issuer in the path). An adoption on-ramp, never a hot-path mode.

### Build — the deliverables (engine crates in `auths`; the npm wrapper in `auths-mcp`)
1. **`auths/crates/auths-mcp-core` (lib): the reusable enforcement.** Harvest the
   `auths-mcp-server` KERI-presentation core (offline presentation verify + revocation + the
   capability gate + `Sandbox`); add the **one per-`tools/call` gate** — scope ⊆ parent (AGT-1),
   quantitative budget (AGT-4), expiry with injected `now`, revocation (OPS-1) — and emit a
   **signed per-call receipt**. Workspace path-dep on `auths-verifier`/`auths-sdk` (in-tree).
2. **`auths/crates/auths-mcp-gateway` (bin): the real-MCP proxy.** Speaks MCP JSON-RPC up to the
   agent and down to N downstream servers; on each `tools/call` canonicalizes + signs the call,
   runs `auths-mcp-core`, forwards only on pass, else returns a fail-closed MCP error + receipt.
   It also carries the `wrap` subcommand (`auths-mcp-gateway wrap --scope … --budget … -- <downstream cmd>`).
3. **A programmatic action-verify** in `auths/crates/auths-verifier`: verify an action descriptor
   (tool + canonical args hash) with injected `now` + a supplied cumulative-usage counter → a
   machine-readable verdict (a thin extension of `artifact verify`, not new crypto).
4. **Cross-rail budget accounting** (D8, resolved) — a single monotonic **settled** counter keyed to
   the agent delegation (reuse AGT-4's verifier-held high-water ledger, `usage_ledger.rs`;
   rollback-protected) summing spend across rails, plus a transient **reserved**-holds set for the
   auth-hold lifecycle; the settled total's digest is **checkpoint-anchored** periodically (no per-call
   chain write, no log growth). Pin the checkpoint interval (it bounds max uncaught overspend on a
   counter-integrity failure — §12) and the on-detection action.
5. **The `auths-mcp` npm wrapper repo** — the launcher (`@auths/mcp`, prebuilt-binary-per-platform,
   the esbuild/Biome pattern), per-client config glue (Claude Desktop / Claude Code / Cursor /
   Codex), the `README` quickstart, and the **install-and-wrap smoke** (`./run.sh --check` = fetch
   the gateway the way a user would, wrap a stub downstream, replay a transcript, assert verdicts).
   Built, gated, and committed in `auths-mcp` (the `[sculpts.*]` tree).
6. **The live/replay agent harness + the 3 scenario configs** in `auths-mcp/examples/` (the
   product's own examples — **not** `auths-demos`).

The old `crates/auths-mcp-server` in `auths` is **retired** (its KERI-presentation core harvested
into `auths-mcp-core`; its JWT path dropped); pre-launch, no back-compat owed. Any surface that
already suffices → reclassified to a closed regression guard at baseline (the DOTAK precedent),
never dropped.

---

## 6. Non-goals

- **NOT a new agent framework.** auths is the authorization substrate; this integrates with an
  existing runtime (MCP), it does not build orchestration, planning, or memory.
- **NOT a fork of MCP.** The gateway speaks stock MCP both directions; enforcement is additive
  middleware, not a protocol change. A non-auths client still works (unauthenticated, no
  receipt) so adoption is incremental.
- **NOT a payment processor / wallet.** auths-mcp *bounds* spend and emits receipts; it never holds
  funds or settles — payment rails (Stripe, x402, crypto) are wrapped downstream tools (§11).
- **NOT replacing the scripted demos.** They remain the hermetic, CI-gated *unit proofs* of
  each primitive. This sits above them as the *product/integration* proof.
- **NOT a hosted service (yet).** This is the local/self-hosted gateway + harness. The hosted
  multi-tenant version and the witness-network dependency are separate (`auths_network`).
- **NOT model-quality claims.** Nothing here asserts the agent is *good*; it asserts that
  whatever the agent decides, the tool boundary holds. The model can be as adversarial as you
  like.
- **NOT a perf claim.** Per-call sign+verify latency is noted but not the property; correctness
  of containment is.

---

## 7. The harness / dramaturgy

Two modes, one gateway — shipped in `auths-mcp/examples/` (the product's own examples, **not**
`auths-demos`). `./run.sh` (the live show), `./run.sh --check` (the hermetic gate), `./run.sh reset`.

- **Live mode (the show).** A real MCP-speaking model runs a short task against tools behind
  the gateway. Disclosed on screen: the model, the system prompt, the injected/over-eager
  instruction. The audience watches the model *itself* emit an out-of-bounds `tools/call` and
  the gateway refuse it with a named verdict, then watch an in-bounds call succeed and produce
  a real downstream result + a receipt. Driven by a thin **Anthropic (Claude) API tool-loop**
  (D7); this live leg is **evidence-only, never gated** — the gate runs the recorded transcript
  (replay mode).
- **Replay mode (the gate / `--check`, hermetic, the recurve probe entrypoint).** Drives the
  gateway from a **frozen transcript** of a prior live run's `tools/call` sequence — no network,
  no model, deterministic verdicts. This is what CI and `matrix --gate` run. The transcript is
  committed; editing it to drop a proof or forge a wider scope still fails closed (the
  adversarial guard).

**Scenario configs (G5 — the collapse made visible):** three tiny config files over the *same*
gateway + harness —
  - `scope.config` → the **intern**: grant `{fs.read}`, model tries `fs.write` → `OutsideAgentScope`.
  - `budget.config` → the **credit-limit**: one `$5` cap spanning a **Stripe test-mode** *and* an **x402/USDC** server (real APIs, no real money); the agent overspends *across both rails* → `UsageCapExceeded`, payment never made (§11).
  - `killswitch.config` → the **agent-that-wouldnt-die**: revoke mid-run → next call `Revoked`.
Each is ~20 lines and reuses one binary, demonstrating that new scenarios are configs, not new
demos.

**The close:** "Every one of these calls was a real model's real decision. Every refusal came
from the chain — offline, per call, with a receipt — not from a dialog box or a policy server.
That is the boundary no bearer token can hold."

---

## 8. Success metrics

- **M1 (brokered + receipted):** an in-bounds tool call round-trips through the gateway to a
  real downstream server and produces a receipt that `auths verify` independently accepts
  (AGENT-MCP-1).
- **M2 (scope, distinct verdict):** an out-of-scope call is refused `OutsideAgentScope` **before
  the downstream tool is invoked** (AGENT-MCP-2). *Signature valid; tool never touched.*
- **M3 (cross-rail budget):** with one `$5` cap spanning two rails, the call that would *reserve
  past* it — on *either* rail — is refused `UsageCapExceeded` before the rail is touched; the
  **combined** running total is in the receipts (AGENT-MCP-3).
- **M4 (revocation, no window):** the first call after a mid-session revocation is refused
  `Revoked` (AGENT-MCP-4).
- **M5 (real + reproducible):** live mode produces ≥1 emergent out-of-bounds call that is
  refused; replay mode reproduces the full verdict sequence byte-stably in CI with no model
  (AGENT-MCP-5).
- **M6 (stretch):** an org-A agent is bounded by its A→B introduction at org-B's gateway
  (AGENT-MCP-6), or the claim is PARKED with the AGT-3 live-runtime reason.
- **M0 (the meta-metric):** a developer can put the gateway in front of an existing MCP
  toolchain and bound a live agent **without re-instrumenting the tools** — the "installable
  product" bar the scripted demos can't reach.

Every verdict is produced by real `auths-verifier` code over real KEL/TEL events; every tool
result in the show comes from a real downstream MCP server. Nothing about the *enforcement* is
mocked. (The model is real in live mode and a recorded transcript in gate mode — disclosed.)

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): the canonical
fields are `class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with
`evidence` (file:line into the target) and `unlocks` (what gets stronger). The **accept +
adversarial paths live in each probe** (the probe contract: an accept path + a `.trap/`
counterexample) and are specified per-FR in §4 — *not* in the gap entry. IDs `AGENT-MCP-*`;
`reads: gateway` names a content-hash rule over the built `auths-mcp-gateway` binary (§10).
`AGENT-MCP-1` is the load-bearing build; reclassify any claim already GREEN at baseline to a
`closed` regression guard (the DOTAK precedent). Probes drive the gateway in **replay mode**
(hermetic).

```yaml
- id: AGENT-MCP-1
  title: "The gateway brokers a real MCP tools/call end-to-end with a signed, verified per-call proof"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the real-MCP proxy (auths-mcp-gateway): speak MCP JSON-RPC
    (initialize/tools/list/tools/call) up to the agent and down to a downstream server; on each
    tools/call canonicalize + sign the call as an auths artifact, verify it against the agent's
    delegator-anchored grant via auths-mcp-core, forward only on pass, and emit a receipt.
  unlocks: "A live agent can be bound at a real MCP boundary at all — the floor for MCP-2..6."
  evidence:
    - "crates/auths-mcp-server/src/keri_auth.rs — reusable offline presentation verify, but its transport is HTTP+Bearer, not MCP JSON-RPC, so no MCP client can connect"
  covers: [gateway-broker]
  probe: probes/agent-mcp-1.sh

- id: AGENT-MCP-2
  title: "An out-of-scope tool call is refused at the boundary with the distinct OutsideAgentScope verdict"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    In auths-mcp-core's per-call gate, map the requested tool to a capability and enforce it
    against the agent's delegator-anchored scope; return OutsideAgentScope (naming the capability)
    and do NOT forward to the downstream server.
  unlocks: "Scope (AGT-1) holds at the MCP boundary, not only on git commits."
  evidence:
    - "maps AGT-1; OutsideAgentScope already exists in auths-verifier — this wires it to tools/call"
  covers: [scope-boundary]
  probe: probes/agent-mcp-2.sh

- id: AGENT-MCP-3
  title: "One cross-rail quantitative budget is un-exceedable across a session (pre-auth, checkpoint-anchored)"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Enforce one cap across rails by pre-authorization against a single monotonic SETTLED counter
    keyed to the agent delegation (reuse AGT-4's verifier-held high-water ledger usage_ledger.rs;
    rollback-protected → UsageCounterRolledBack) plus a transient RESERVED holds set: reserve the
    cost (or a ceiling, for metered calls) before the rail is touched, settle the actual after,
    release the slack (holds expire if a call never returns). Checkpoint-anchor the settled total's
    digest periodically (NO per-call chain write, NO log growth). A call that would reserve past the
    cap on either rail is refused UsageCapExceeded before the downstream is invoked.
  unlocks: "AGT-4 caps bind a live agent's CROSS-RAIL spend, not just one credential; max uncaught overspend bounded by the checkpoint interval (§12)."
  evidence:
    - "maps AGT-4 (caps at verify, auths 15bc605c; verifier-held high-water ledger usage_ledger.rs) + AGENT-CAP-1 malformed-predicate guard (00de275c)"
  covers: [budget-boundary]
  probe: probes/agent-mcp-3.sh

- id: AGENT-MCP-4
  title: "Revocation is instant mid-session with no propagation window"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Re-derive liveness from the KERI registry on every tools/call (reuse keri_auth's revocation
    check) so the first call after a revocation event is refused Revoked — no cached token TTL,
    no introspection lag.
  unlocks: "OPS-1 instant kill applies to a running agent loop."
  evidence:
    - "maps OPS-1; keri_auth.rs already checks revocation on presentation — bind it per call"
  covers: [revocation-boundary]
  probe: probes/agent-mcp-4.sh

- id: AGENT-MCP-5
  title: "The over-reach is a real model's decision and reproduces deterministically in CI"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Build the live-mode tool loop (real model) + a transcript recorder/replayer; the probe drives
    the gateway from the committed transcript (no model/network) to byte-stable verdicts, and a
    transcript edited to drop the proof or forge a wider scope still fails closed.
  unlocks: "The 'real agentic framework' bar the scripted demos cannot reach."
  evidence:
    - "the gap this whole PRD closes (maps WED — the agent wedge); live-leg evidence is out-of-band, only replay is gated"
  covers: [real-and-reproducible]
  probe: probes/agent-mcp-5.sh

- id: AGENT-MCP-6
  title: "Cross-org: org A's agent is bounded by its A->B scoped introduction at org B's gateway"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Honor a scoped A->B introduction at B's gateway so a call within the grant passes and one
    exceeding it is refused at B (A cannot widen its own introduction; B never trusts A's
    self-asserted scope). PARK — do not stub — if the AGT-3 live introduction runtime is absent.
  unlocks: "Stranger orgs bound each other's agents — the network leg (AGT-3)."
  evidence:
    - "maps AGT-3 (live mutual-introduction leg, not yet built — likely PARK)"
  covers: [cross-org-boundary]
  probe: probes/agent-mcp-6.sh

- id: AGENT-MCP-8
  title: "Live-wire counter parity — the live wrap path enforces the cross-rail budget via the durable CrossRailBudget, matching the hermetic gate"
  class: wire-mismatch
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Replace the v0 in-memory guard (proxy.rs GatewayProxy::spent_cents) with the durable
    verifier-held CrossRailBudget (auths-mcp-core/budget.rs) on the live `wrap` path so the
    live wire enforces the cross-rail cap from the SAME counter the hermetic gate uses; live-wire
    budget verdicts (allowed / usage-cap-exceeded / usage-counter-rolled-back) match the gate's
    for the same call sequence. If the live wrap MCP session cannot be driven fully hermetically,
    gate the counter-SOURCE parity (the live wrap references the durable counter, the v0 spent_cents
    tally is gone) and keep the full live-wire verdict match as out-of-band evidence — do NOT fake it.
  unlocks: "The live wire cannot allow what the gate refuses (#281) — the durable cross-rail counter (D8) binds the agent on the real MCP wire, not only in replay."
  evidence:
    - "maps #281; crates/auths-mcp-gateway/src/proxy.rs GatewayProxy::spent_cents is a v0 in-memory cap guard, NOT the durable CrossRailBudget the replay gate drives"
  covers: [budget-boundary]
  probe: probes/agent-mcp-8.sh

- id: AGENT-PAY-1
  title: "The Stripe-test rail is metered — the gateway extracts the charge amount from a Stripe-test charge response and reserves/settles it against the cross-rail cap"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the gateway-side Stripe-charge cost extraction: given a Stripe-test charge RESPONSE
    (the shape Stripe's agent-toolkit MCP server returns), extract the charge amount
    (charge.amount_captured, cents) and RESERVE/SETTLE it against the cross-rail CrossRailBudget
    (D8). Accept: an in-budget charge settles + is metered (amount in the receipt, rail=stripe,
    charge id named). The real defense (§11): the reservation refuses usage-cap-exceeded BEFORE
    Stripe is invoked, so an over-cap charge is never charged. auths-mcp-core holds ZERO payment
    code — Stripe stays a wrapped downstream; a live Stripe-test charge is evidence-only, deferred (D7).
  unlocks: "AGT-4/D8 caps bind a real payment rail (Stripe-test) at the MCP boundary — the first rail of the cross-rail credit-limit flagship (§11)."
  evidence:
    - "maps §11 (bound, don't build); the core meters a pre-supplied cost_cents but does NOT extract the amount from a recorded Stripe charge response (amount_captured) — the near-pluggable Stripe adapter is not built"
    - "hermetic over a recorded Stripe TEST-MODE charge fixture authored against the documented Charge object shape (docs.stripe.com/api/charges/object) — no live Stripe call"
  covers: [budget-boundary]
  probe: probes/agent-pay-1.sh

- id: AGENT-PAY-2
  title: "The x402/USDC rail is metered into the SAME cross-rail cap as Stripe (cross-rail summing, testnet-flagged) — the gateway extracts the x402 amount and sums it cross-rail"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the gateway-side x402 cost extraction: given a recorded x402/USDC settlement RESPONSE,
    extract the paid amount (the SettlementResponse / PaymentRequirements maxAmountRequired, atomic
    USDC at 6 decimals → cents) and RESERVE/SETTLE it into the SAME cross-rail CrossRailBudget (D8)
    the Stripe rail (AGENT-PAY-1) meters into — so a call that would reserve PAST the cap ACROSS rails
    is refused usage-cap-exceeded BEFORE the x402 facilitator settles, even when a per-rail x402 silo
    reads in-budget (the moat). FLAG (smallest_fix/observed): the LIVE x402 leg additionally needs a
    FUNDED USDC TESTNET WALLET (base-sepolia) — OUT OF HERMETIC SCOPE; the hermetic probe proves
    cost-extraction + cross-rail metering ONLY; the funded-wallet live settle is evidence-only, deferred.
  unlocks: "ONE cap binds a live agent's CROSS-RAIL spend across Stripe AND x402 (§11) — the credit-limit flagship's moat a per-rail processor budget cannot express."
  evidence:
    - "maps §11 (the cross-rail moat); no extraction of the x402 amount from a recorded settlement response, no atomic-USDC→cents, no cross-rail summing into the Stripe rail's cap — not built"
    - "hermetic over a recorded x402 settlement fixture authored against the x402 SettlementResponse + PaymentRequirements shapes (coinbase/x402 specs, network=base-sepolia) — no live x402 call"
    - "LIVE-SCOPE FLAG: the live x402 rail needs a funded USDC testnet wallet (base-sepolia) — out of hermetic scope; the probe proves cost-extraction + cross-rail metering only"
  covers: [budget-boundary]
  probe: probes/agent-pay-2.sh

- id: AGENT-PAY-3
  title: "The inverted payment-mode default — REAL money is the DEFAULT (Stripe live / x402 base mainnet), TEST is a single opt-in flag; the cross-rail cap is the MANDATORY safety seatbelt; the mode is DISCLOSED so real money is never silent"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the inverted payment-mode default over a CLEAN PaymentMode port/adapter (§11): (1) REAL is
    the DEFAULT — no flag → Stripe LIVE (api.stripe.com, sk_live_… expected) + x402 on base MAINNET
    (real USDC); TEST is a SINGLE opt-in — `--test-mode` on `auths-mcp wrap` AND `AUTHS_MCP_TEST_MODE=1`
    for the adapter → sk_test_… / base-sepolia. (2) The cross-rail budget cap is the MANDATORY seatbelt
    — the gateway REFUSES to wrap a payment rail without a `--budget` (fail-closed, budget-required), in
    BOTH modes; with a `--budget` it is accepted. (3) The mode is DISCLOSED — a startup banner + a
    `mode=real|test` field (receipt + the `wrap --show-mode` resolve+disclose dry-run). Hermetic probe
    needs NO real money: it reads the resolve+disclose dry-run (default→mode=real, --test-mode→mode=test;
    budget-less wrap refused budget-required in both modes), never a live charge. The docs update
    (real-focus, test-note-at-bottom) is part of the build.
  unlocks: "An operator can default to REAL money safely — real is the default, the cap is a mandatory seatbelt that cannot be skipped, and the mode is never silent (§11). Test mode is a single, deliberate opt-in."
  evidence:
    - "THE DECISION (a deliberate operator inversion, §11): real money is the DEFAULT, test is a single opt-in flag; because real is the default the cross-rail cap is the mandatory seatbelt and the mode must be disclosed"
    - "NOT BUILT: crates/auths-mcp-gateway/src/main.rs WrapArgs has no --test-mode and no --show-mode/PaymentMode-resolution disclosure surface, and `budget: Option<String>` is OPTIONAL — a payment rail can be wrapped UNCAPPED today (the seatbelt is skippable); the wrap/replay output carries no `mode=` field (silent real money)"
    - "hermetic over a MODE-DISCLOSURE / DRY-RUN surface (`wrap --show-mode` — resolve + disclose, never serve, never charge); expected shapes recorded under probes/fixtures/payment-mode-{real,test,cap-omitted}.expected.json — no live charge"
  covers: [budget-boundary]
  probe: probes/agent-pay-3.sh
```

---

## 10. Repo, crate & recurve-tree layout

**The engine is Rust crates in the `auths` monorepo; `auths-mcp` is a thin npm/distribution repo.**
The split is by language and by churn: all enforcement logic lives in one workspace (one
`cargo build`, one CI, `auths-verifier`/`auths-sdk` as in-tree path-deps — no cross-repo version
dance), and the near-static packaging/glue gets its own publishable home.

```
auths/                                   recurve [target] — engine, built + read by probes + sculpted
  crates/
    auths-mcp-core/      NEW lib   harvested KERI-presentation auth + the one per-tools/call gate
                                   (scope ⊆ parent · budget · expiry · revocation) + receipts
    auths-mcp-gateway/   NEW bin   real-MCP (rmcp) proxy + `wrap` subcommand; calls -core per call
    auths-mcp-server/    RETIRED   presentation core harvested out; JWT transport dropped
    auths-verifier/      sculpt    + programmatic action-verify (injected now + usage counter)
    auths-oidc-port/     reuse     the optional OIDC→auths door-step exchange (NOT in the gateway)

auths-mcp/                               recurve [sculpts.auths-mcp] — npm wrapper, built + gated + committed here
  packages/auths-mcp/    @auths/mcp launcher — prebuilt-binary-per-platform (esbuild/Biome pattern)
  clients/               config glue: Claude Desktop / Claude Code / Cursor / Codex snippets
  examples/              live show + --check replay (the probe) + 3 scenario configs
  run.sh                 install-and-wrap smoke = the [sculpts.*] gate
  README.md              the install + quickstart landing page
```

recurve config (home in `auths/.recurve`, alongside the other suites):

```toml
[target]                          # the ENGINE — built, read by probes, sculpted
tree = "."                        # auths
rebuild = "cargo build --release -p auths-mcp-gateway"
[reads.gateway]                   # artifact path is suite-relative (under [suites.*].dir)
method   = "content-hash"
artifact = "bin/auths-mcp-gateway"
source   = "target/release/auths-mcp-gateway"

[sculpts.auths-mcp]               # the WRAPPER repo — built, gated, committed there, AND sculpted
tree    = "../auths-mcp"
branch  = "main"
rebuild = "npm ci && npm run build"
gate    = "npm run smoke -- --check"   # install-the-way-a-user-would + wrap a stub + replay → federated

[suites.auths-mcp]
dir = ".recurve/claims/auths-mcp"
```

**Multi-tree, feedback both ways.** One ledger + one federated gate span both trees: a gap's
`smallest_fix` lands in `auths` (an engine capability/flag/error the wrapper needs) *or* in
`auths-mcp` (a packaging/UX fix), and the gate stays red until **both** the engine probes and the
wrapper smoke are green — so the wrapper pulls the engine forward and the engine can't drift away
from the user-facing contract. Engine changes commit to `auths` (`dev-privacy`); wrapper changes
commit to `auths-mcp` (`main`).

**Install UX (what a user actually does).** `auths-mcp` ships `@auths/mcp` on npm with a prebuilt
binary per platform, so there's no Rust toolchain. The pitch is a drop-in wrapper around a line
they already have — prepend `auths wrap …` to any MCP server in their client config:

```json
"filesystem": {
  "command": "npx",
  "args": ["-y", "@auths/mcp", "wrap", "--scope", "fs.read", "--budget", "$5", "--ttl", "30m",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/proj"]
}
```

`brew install auths-mcp` (persistent binary) and `uvx auths-mcp` (PyPI) are fast-follows; the
cross-compiled binaries are produced by the `auths` monorepo's release CI and referenced by the
wrapper.

---

## 11. Payments — one cross-rail budget over a unified agent authority

A per-rail processor already enforces a per-rail budget — Stripe Issuing does spend caps, velocity,
and merchant-category limits today. So "give your Stripe MCP a `$5` cap" is **not** the
differentiator; Stripe does that. The differentiator is that auths bounds the **agent**, not a
card: **one budget across every rail and tool**, enforced at the boundary, attenuable, and
verifiable without trusting any processor.

**Bound, don't build.** Each rail is a wrapped downstream MCP server — Stripe's agent toolkit + MCP
server, x402 (pay-per-request over USDC), a crypto server. `auths-mcp-core` holds **zero payment
code**; it enforces the *one* cap across all rails by **pre-authorization** — reserve the call's cost
(or a ceiling) against a single cross-rail monotonic counter *before* the rail is touched, settle the
actual after (D8, AGENT-MCP-3). The counter is bumped locally (no per-call chain write, no log
growth); its running total is **checkpoint-anchored to the chain periodically**, so it's
offline-verifiable without a write per payment — at the honest cost of a periodic checkpoint and a
detection window between them (§12). Settlement is the rail's job; cross-rail spend *authorization* is
auths's.

**What a per-rail processor budget structurally cannot do:**

| | Per-rail processor budget (e.g. Stripe Issuing) | auths cross-rail budget |
|---|---|---|
| Spans Stripe **and** x402 **and** a metered API as one cap | no — N siloed budgets | **yes — one cap, all rails** |
| Same authority also bounds non-payment tools (fs, deploy) | no | **yes — spend is one facet of scope + budget + ttl** |
| Sub-agent gets a provable slice a non-trusting party can verify | central, card-only, "the processor says so" | **cryptographic, offline, cross-rail** |
| One revoke stops spend **everywhere** at once | per-card/key | **the agent's next call fails on every rail + tool** |

An agent at `$4.99` on Stripe **and** `$4.99` on x402 has "spent `$0` of `$5`" in each silo; under
auths it has spent `$9.98` of `$5` and the next call on *either* rail is refused. **That gap is the
product.**

**The flagship example (`auths-mcp/examples/payments`):** one agent, one `$5` authority, spending
across a **Stripe test-mode** server *and* an **x402/USDC-testnet** server at once (real APIs, no
real money); a **sub-agent handed a `$2` slice** provably cannot exceed it on either rail; one
**revoke** stops both mid-run. Payment is the visceral beat ("real charges, cut off"); the
**cross-rail unification + attenuation + revocation** is the point — none of it routes trust
through a processor. The rails stay example configs over the one gateway; the core stays
rail-agnostic.

**The mode default is inverted: real money is the DEFAULT, test is a single opt-in (AGENT-PAY-3).**
A deliberate operator inversion over a clean **PaymentMode port/adapter**: with **no flag** the gateway
resolves to **REAL** — Stripe **live** (`api.stripe.com`, `sk_live_…`), x402 on **base mainnet** (real
USDC); **test mode is the single opt-in** — `--test-mode` on `auths-mcp wrap` *and* `AUTHS_MCP_TEST_MODE=1`
for the adapter → Stripe test (`sk_test_…`), x402 on **base-sepolia**. Two safety obligations follow from
real-by-default, and both are part of this contract:

- **The cap is the mandatory seatbelt.** Because real money is the default, the gateway **refuses to wrap a
  payment rail without a `--budget`** — fail-closed, a distinct `budget-required` error, in **both** modes.
  The cross-rail cap can never be silently skipped (the regression `cap-omitted-allowed` forbids).
- **The mode is disclosed.** A startup **banner** plus a machine-readable **`mode=real|test`** field (on the
  receipt and on the `wrap --show-mode` resolve-and-disclose dry-run) so an operator *always* knows whether
  real money is live — real money is never silent (the regression `mode-not-disclosed` forbids).

The hermetic probe (AGENT-PAY-3) needs **no real money**: it reads the `--show-mode` resolve-and-disclose
dry-run (mode selection, the mandatory-cap guard, the disclosure), never a live charge. The docs update
(real-focus, the test note at the bottom) is part of the build.

**Honest scoping:** single-rail and you trust your processor → use the processor's controls. auths
earns its place when spend is **multi-rail, multi-party, trust-minimized, or one dimension of a
unified agent authority**.

---

## 12. Trust model & deployment — the custody broker

The gateway is an in-path chokepoint, which sits in tension with auths's usual "untrusted transport,
trust from the re-check" thesis — so state the split plainly:

- **Detection is unconditional.** Every brokered call emits a chain-anchored receipt anyone can
  verify offline, *whether or not they trust the gateway*. The auths re-check property, intact.
- **Prevention requires the gateway.** Refusing an out-of-bounds call in real time is the gateway's
  job; if it is bypassed or compromised, you keep offline-verifiable **detection** but lose real-time
  **prevention**. In one line: *prevention if you run/trust the gateway, offline-verifiable detection
  if you don't.*

**What makes prevention unbypassable: credential custody.** The gateway is not just a proxy — it is a
**credential-custody broker**. It holds the downstream tool's secret (API key, OAuth token, wallet
key); the agent holds **only** its scoped/budgeted/revocable auths delegation. A prompt-injected
agent that points its MCP client straight at the raw downstream **has no credential for it** — the
call fails. The boundary is unbypassable *by construction*, not by trusting the model. This flips the
weakest tools — the "API key in an env var" majority — into the strongest pitch: **auths-mcp is the
thing that takes the ambient key out of the agent's hands.** An agent can't leak or misuse a key it
never held.

**Honest limit:** custody makes a resource unbypassable only if that resource is reachable *solely*
through the custodied credential. A truly public endpoint (an open RPC, a free API) the agent can hit
directly — there, the gateway is **detection-only**.

**The budget's failure bound (the detection window is a re-spend window).** Checkpoint-anchoring makes
counter tampering *tamper-evident*, not *prevented*: if the counter's integrity fails (a compromised, or
crashed-and-restored-from-stale-snapshot, gateway), spend can roll back to the last checkpoint and the
agent can overspend by **up to one checkpoint-interval's worth** before the next checkpoint catches it —
and by then the money has moved on the rails. **Detection is not reversal.** So state the bound (*max
uncaught overspend ≤ the checkpoint interval*; tighten it to shrink the window — for high-value rails set
interval = per-payment for a zero window), and on a detected mismatch the gateway **halts/revokes the
agent and alarms** — the receipts make the exact overspend *provable* for out-of-band clawback/dispute,
even though it wasn't prevented.

**Who runs it (this defines the trust model):**
- **Primary — agent-owner-run (bound your own fleet).** You custody your fleet's downstream
  credentials and run the gateway in front of them; you are bounding *your own* agents. The
  insurable-fleet / treasury story (§11), needing no third party to trust.
- **Co-primary — tool-provider-run.** The tool/API provider runs it in front of *their* resource,
  enforcing per-agent scope and spend on something they own. Strong for the same reason.
- **Third-party-run** multiplies trust questions and is **not** the lead deployment.

---

## Decisions & open questions

**Decided 2026-06-15 (review):**
- **D1 — Runtime: real MCP** (JSON-RPC 2.0 via the official Rust SDK `rmcp`), not the existing
  crate's HTTP+Bearer shim. A second seam (OpenAI Agents SDK / LangGraph) is a later option.
- **D2 — Binding: native, in-process** — `auths-mcp-core` calls `auths-verifier`/`auths-sdk`
  directly (workspace path-deps); no shelling.
- **D3 — Engine in Rust, in the `auths` monorepo; distribution via npm.** Lead channel
  `npx @auths/mcp` (prebuilt binary per platform); `brew install auths-mcp` alongside; `uvx`
  fast-follow. The gateway stays native; a JS/Python *client* SDK can come later.
- **D4 — `auths-mcp` is its own repo, wired multi-tree** (`[target]=auths`,
  `[sculpts.auths-mcp]=../auths-mcp`), the two trees feeding each other through one ledger and a
  federated gate (§10).
- **D5 — Purely no-issuer gateway.** JWT/JWKS dropped from the gateway; OIDC shops use the
  optional `auths-oidc-port` door-step exchange (token → bounded no-issuer delegation, once).
- **D6 — Names:** repo `auths-mcp`, package `@auths/mcp`, binary `auths-mcp-gateway`, lib
  `auths-mcp-core`, recurve suite `auths-mcp`. A marketing name can sit on top later.

- **D7 — Live show: a thin Anthropic (Claude) API tool-loop.** The gate runs the **recorded
  transcript** (hermetic); the live model run is **evidence-only, never gated** (§7).
- **D8 — Budget counter: verifier-held monotonic counter, checkpoint-anchored (NOT per-call).**
  Reuse AGT-4's usage ledger — a high-water mark bumped locally per call (atomic, **no chain write,
  no log growth**), rollback-protected (`UsageCounterRolledBack`). The cap itself is anchored once in
  the credential. The running total is made tamper-evident + offline-verifiable by **periodically
  anchoring its digest** (a checkpoint every N calls / $X / T — the hash-chain-head pattern), *not* a
  KEL/TEL event per payment. Between checkpoints, un-exceedability leans on the verifier's counter
  (the §12 split); the chain gives tamper-evident detection at checkpoint granularity. Net-new over
  AGT-4: the checkpoint-anchoring, and a counter **keyed to the agent delegation that sums all rails**
  (AGT-4's is per-credential). The counter is two-part — monotonic **settled** (rollback-protected,
  checkpoint-anchored) + transient **reserved** holds (expire/release the auth-hold slack); **max
  uncaught overspend on a counter-integrity failure ≤ one checkpoint interval** — detection ≠ reversal
  (§12).
- **D9 — First scenario shipped: budget** (the cross-rail credit-limit) — the most visceral lead.

*All review-stage open questions resolved 2026-06-15.*

---

*Drafted 2026-06-15. A go-to-market product — engine crates in the `auths` monorepo, distribution
via the `auths-mcp` npm wrapper repo (multi-tree, §10) — filed under `prds/go_to_market/`.
Companion to `launch_ideas.md` (the "one-call agent SDK" punch-list item) and to
`roadmap/aspirational_claims/gaps.yaml` (consumes AGT-1, AGT-4, OPS-1, AGT-3). The scripted
`agent_demos/` remain the separate hermetic proofs of each primitive. Deliberately departs from
the "offline-first, no live LLM" stance — see the status block — reconciled for CI by the
recorded-transcript replay mode. Surfaces named against `../auths` @ `dev-privacy`; exact paths
pinned during the sculpt.*
