# PRD: The Self-Monetizing Agent — an agent you can delegate real capital to, because the downside is provably capped

> **One line:** an agent runs a useful paid service — a data feed, a monitor, a research
> or generation tool — and **charges per call over x402** (an inbound USDC stream); it
> **reinvests its own costs** up to a delegated cap (the compute/APIs it needs) and
> **accrues net profit to the principal's custody** — a self-sustaining micro-business
> that the agent runs but **never holds the keys to**: bounded spend authority outbound,
> a custodied inbound stream it cannot divert. Recurring revenue = the inbound x402 meter
> going **up**.
>
> **The revenue framing — read first (PROFIT center, not a cost center).** This use case
> *makes money*. The auths primitives are what make it **safe to delegate real capital to
> an agent**: the **cap = the maximum drawdown** (the most the agent can ever spend); the
> **custody-broker = the agent never holds your wallet**, only bounded spend authority on
> the outbound rail and *zero* withdraw authority on the inbound; **instant revoke =
> clawback** (one event stops all spend everywhere at once); the **aggregate cap = a whole
> fleet of these agents bounded by your total risk**; and **signed per-call receipts = a
> verifiable P&L** — every dollar in and every dollar out, independently auditable. That
> is the unlock: not "an agent that spends," but "an agent you can hand a real wallet's
> *worth of work* to, knowing the worst case is a number you chose."
>
> **Be honest about what auths is and isn't.** auths is the **safety + the rails, not the
> alpha.** It does **not** make the strategy profitable — the service the agent runs (the
> feed, the monitor, the model) is what people pay for; *that* is the alpha, and the agent
> (or its author) brings it. What auths does is make it **safe to delegate real capital to
> an agent that runs the strategy**: it bounds the downside to a chosen cap, gives instant
> clawback, custodies both directions so the agent can't run off with the float, and emits
> a cryptographic P&L. The agent earns; auths makes the earning *delegable*.
>
> **This rides the `auths-mcp` gateway** (`go_to_market/auths-mcp-gateway.md`): the
> bounded-agent MCP gateway — scoped / budget-capped / revocable / custodied delegation,
> the cross-rail metering (Stripe + x402/USDC), the cross-rail moat, the aggregate cap,
> sub-delegation/attenuation, signed per-call receipts, the custody-broker, `mode=real/test`.
> **The net-new surface here is the INBOUND leg:** the gateway already meters *outbound*
> spend (an agent paying for tools); this proves the gateway can also **custody an inbound
> x402 stream** (the agent *earning*), nett it against the agent's delegated costs, and
> accrue the **net** to the principal — *custody in both directions*, so the agent can
> spend up to its cap and earn without limit, holding the keys to **neither** float.
>
> **Authoring scope:** READ-ONLY on `../auths` for this PRD. Hermetic probes only —
> **recorded fixtures, no live money** (no live Stripe charge, no funded testnet wallet);
> the live earn/spend legs are evidence-only, deferred. House style: a sibling of
> `the-agent-with-a-credit-limit` / `the-intern-that-couldnt` — narrative + falsifiable
> recurve `gaps.yaml` + accept/adversarial probes + a staged `run.sh`. The recurve loop
> sculpts `../auths` (the gateway engine crates) to turn these claims GREEN.

---

## 1. One line + scenario

A builder ships a small, genuinely useful **paid service** an agent operates end to end:
a real-time price/anomaly **monitor**, a curated **data feed**, a **research/summarization**
endpoint, or a **generation** tool. The service is exposed over MCP behind the **auths
gateway**, and it **charges per request over x402** — pay-per-call in USDC, no account, no
invoice, settle-on-request. Other agents (and humans) hit it; each call pays. That inbound
stream is the **recurring revenue**.

The service is not free to run. To answer a call the agent must spend: an upstream data
API, an LLM token budget, a block-explorer query, compute. So the agent has *two* money
flows — **inbound** (what callers pay it over x402) and **outbound** (what it pays its own
suppliers, over x402 or Stripe). A self-sustaining micro-business is exactly: *inbound >
outbound, sustained.* The principal wants to **delegate the whole loop to the agent** and
walk away — collect the net, not babysit the spend.

**Why you cannot safely do this today.** To let an agent earn-and-spend autonomously you
must hand it credentials: the **inbound wallet's key** (so it can receive — and therefore
*withdraw*, *drain*, *misroute*), and the **outbound payment key** (an API key / a hot
wallet with no amount semantics — possession is unlimited spend). A buggy, prompt-injected,
or over-eager agent with those keys can **empty the float**, **overspend its costs into a
loss**, or **keep spending after you tried to stop it** (token TTL, key already copied).
There is no number at the boundary that says "this agent may spend at most $X total, may
**never** withdraw the inbound, and stops *now* when revoked." The downside is **unbounded**,
so a rational principal **won't delegate real capital** — and the micro-business never gets
off the ground.

**What auths does — custody both directions, bound only the outbound.** The principal mints
the agent a delegation: `scope = {feed.serve, data.fetch, llm.call}`, `spend_budget =
$50.00` (the **max drawdown**), `ttl`, anchored in the principal's KEL. The gateway is a
**credential-custody broker**: it holds the **outbound** supplier credentials *and* the
**inbound** x402 receiving address — the agent holds **only** its bounded delegation. So:

- **Outbound** is **capped**: every paid supplier call is pre-authorized against the agent's
  delegator-anchored `$50` cap (the cross-rail counter from `auths-mcp-gateway` §11). The
  agent **cannot spend past `$50`, ever**, on any rail — that is the entire downside.
- **Inbound** is **custodied and un-divertable**: callers pay into an address the *gateway*
  controls; the agent has `serve` scope (it can *answer* paid calls and thereby *earn*) but
  **no `withdraw`/`transfer` capability** — it literally cannot move the received funds. The
  inbound meter goes **up**; the agent never touches the float.
- **Net accrues to the principal**: the gateway nets `inbound − outbound` and the **profit
  settles to the principal's custody**, not the agent's. The agent is a *worker* on the
  principal's micro-business, not its treasurer.

Every call — inbound earn or outbound spend — leaves a **signed per-call receipt**: who
paid/was paid, under which grant, how much, on which rail, with what verdict. Replay them
and you have a **cryptographic P&L** the principal (or an underwriter, or a tax auditor)
verifies offline, trusting no processor and no log.

Then the realistic failures, *all bounded by construction*: the agent tries to **withdraw
the inbound** (no capability → refused, `OutsideAgentScope`); it loops a supplier past its
**`$50` cost cap** (refused, `UsageCapExceeded`, across rails — `$49.99` Stripe + `$0.02`
x402 is still over); the principal **revokes** mid-stream and the **next** spend is refused
`Revoked` with no window. The agent kept earning; it could never overspend, never drain,
never outlive its kill-switch.

---

## 2. The property it proves

**An agent can be delegated bounded SPEND authority to cover its own costs while accruing
inbound REVENUE it never holds the keys to divert — custody in both directions, enforced
per call, offline, from the signed chain.** Concretely: the agent's *outbound* spend is
un-exceedably capped at a chosen max-drawdown across every rail; its *inbound* x402 earnings
are custodied to the principal and the agent has no capability to move them; the net settles
to the principal; and every leg emits a receipt that reconstructs a verifiable P&L. The
recurring-revenue signal is the **inbound meter going up while the outbound cap holds** —
a delegable, self-sustaining micro-business whose worst case is a number the principal set.

**Honest delineation of the property:** auths is the **safety and the rails**, *not* the
alpha. The property is not "this agent is profitable" — profitability is the service's, and
auths asserts nothing about it. The property is "**delegating real capital to an agent that
runs this service is safe**": capped downside, instant clawback, two-way custody, a
verifiable P&L. The strength here over the outbound-only `auths-mcp-gateway` flagship is the
**inbound custody leg** — proving the gateway custodies an *earning* stream the agent cannot
divert, not just a *spending* one it cannot exceed.

**Why the incumbents structurally can't make this delegable:**

| Incumbent (how you'd "let an agent earn & spend" today) | Where authority lives | Why you still can't safely hand it real capital |
|---|---|---|
| **Hot wallet / private key held by the agent** | the key — possession *is* total authority | To *receive* x402 the holder can also *withdraw*: inbound and outbound are the same key. A compromised agent drains the float. No cap on spend, no clawback that beats key-copying, no per-call receipt. Custody is all-or-nothing and the agent holds all. |
| **API key + a card (Stripe) for outbound; a payout account for inbound** | the key (ambient) + the processor's account | The card has no amount grammar the *boundary* enforces ("≤ $50 total" lives in app code — bypassable/forgeable/forgotten — exactly `AGT-4`'s gap), per-rail silos can't express *one* cross-rail cap, revocation lags a TTL, and the payout account is a withdraw credential the agent must hold to be paid. Two siloed budgets each read "$0 spent" at $4.99+$4.99. |
| **OAuth 2.1 bearer (the MCP auth spec)** | a token the AS minted; scopes are asserted strings | Bearer = ambient (steal it, hold it); scopes are **boolean** — there is no `scope` shape for "≤ $50" or for "may serve-and-earn but may **not** withdraw"; revocation has a propagation window. The relying party trusts the AS, not a re-derivable containment. |
| **A custodial agent platform (the platform holds funds, "trust us")** | the platform's database + good behaviour | Centralizes both directions in a party you must trust; no offline, cryptographic, per-call proof that *this* agent's spend stayed under *this* cap or that it never touched the float; the "P&L" is the platform's log, not a verifiable receipt chain. |

None lets a **stranger relying party** (an underwriter pricing a 10,000-agent earning fleet,
a co-investor, a tax authority), **offline, from signatures alone**, prove three things at
once: the agent's outbound spend never exceeded a cap its principal anchored; the agent never
held the authority to divert the inbound; and the net P&L is exactly these receipts. **That**
triad — capped drawdown + two-way custody + verifiable P&L — is what turns "an agent that
spends money" (scary, undelegable) into "an agent you can delegate real capital to" (an
insurable, self-sustaining micro-business). auths supplies the triad; the agent supplies the
service that earns.

---

## 3. Goals — what makes it believable

- **G1 — A real inbound stream, custodied, that the agent cannot divert.** The agent serves
  real (recorded, in CI) x402-paid calls; the inbound USDC lands in a gateway-custodied
  address; the agent's delegation carries `serve`/`earn` scope but **no** `withdraw`/`transfer`
  capability. The visceral beat: the agent *earns* on every call and **provably cannot move a
  cent of it**. The inbound meter going up *is* the recurring revenue.
- **G2 — Outbound spend un-exceedably capped at the chosen max-drawdown, cross-rail.** The
  agent's own costs (data API, LLM, compute) are paid over Stripe *and* x402 against **one**
  `$50` cap (the `auths-mcp-gateway` cross-rail counter); the call that would reserve past
  `$50` on *either* rail is refused before the rail is touched. The cap **is** the worst case.
- **G3 — Net accrues to the principal; a verifiable P&L falls out.** The gateway nets
  `inbound − outbound`; the **net settles to the principal's custody**, never the agent's;
  and the full receipt chain (every earn + every spend) replays offline with `auths verify`
  into a P&L a stranger can audit. *Recurring revenue = a receipt chain that trends up.*
- **G4 — Instant clawback and a fleet-level aggregate cap.** One revoke stops the agent's
  spend on every rail at once (no window); and an **aggregate cap** bounds a *fleet* of these
  micro-business agents by the principal's **total** risk — so "100 earning agents" is still
  one number of downside, the thing that makes the fleet insurable.
- **G5 — Honest staging, hermetic gate.** The live show may run a real model and (disclosed)
  testnet rails; the **gate/probe runs recorded fixtures — no live money** (no live Stripe
  charge, no funded wallet). Every *verdict* (scope, cap, revoke, net-settlement, P&L digest)
  is real `auths-verifier` code over real KEL/TEL events; only the money is recorded.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an **adversarial
twin (fail-closed)** — both live in the probe (§9), specified here. IDs `AGENT-EARN-*`. They
**reuse** the closed `auths-mcp-gateway` primitives — **AGT-1** (scope), **AGT-4 / D8** (the
cross-rail settled+reserved counter, `usage_ledger.rs`), **OPS-1** (revocation), the signed
receipt, the custody-broker — and add the **inbound custody + net-settlement + P&L** leg.
**AGENT-EARN-1 is load-bearing: it builds inbound x402 custody + cross-direction netting.**

- **AGENT-EARN-1 — The gateway custodies an inbound x402 payment, meters it as REVENUE, and
  nets it against the agent's outbound costs (THE BUILD).**
  *Maps: new inbound surface; rides AGT-4/D8's counter + the gateway receipt path.* An agent
  serving a paid call receives x402 USDC into a **gateway-custodied** address; the gateway
  records the inbound as a signed receipt (`direction=inbound`, `rail=x402`, amount), and
  maintains a per-agent **net** ledger `net = Σ inbound − Σ outbound`.
  - **Observable (accept):** a recorded inbound x402 settlement is custodied and metered —
    the inbound amount appears in a receipt (`direction=inbound`), the running **net** rises,
    and `auths verify` of the receipt accepts; the **net settles to the principal**, not the
    agent (the accrual receipt names the principal as beneficiary).
  - **Adversarial twin:** the inbound is **custodied, not held by the agent** — a transcript
    in which the agent attempts to redirect the inbound settlement address (or to mark itself
    beneficiary) is refused; and an inbound receipt is *never* counted toward the agent's
    *spend* cap (revenue is not budget — the direction is signed, not inferable).

- **AGENT-EARN-2 — The agent cannot WITHDRAW or divert the inbound stream (custody, scope).**
  *Maps: AGT-1.* The agent holds `{feed.serve, data.fetch, llm.call}` — **no**
  `wallet.withdraw` / `funds.transfer`. The model emits a withdraw/transfer of the custodied
  inbound.
  - **Observable (accept):** an in-scope `feed.serve` call (which *earns*) passes and is
    metered inbound.
  - **Adversarial twin:** a `wallet.withdraw` / `funds.transfer` `tools/call` is refused at
    the boundary with **`OutsideAgentScope`**, naming the capability — **the custody wallet is
    never touched**, despite a valid signature and a well-formed envelope. *The agent earns;
    it cannot drain.* (The custody-broker, `auths-mcp-gateway` §12: the agent never held the
    inbound key, so even bypassing the gateway it has nothing to withdraw *with*.)

- **AGENT-EARN-3 — Outbound costs are un-exceedably capped at the max-drawdown, cross-rail.**
  *Maps: AGT-4 (+ AGT-1 for cross-rail attenuation), D8.* The agent holds a single
  `spend_budget = $50.00`; its cost suppliers are **two rails** (Stripe test-mode + x402/USDC).
  Spend is pre-authorized against the cross-rail **settled** counter (rollback-protected) plus
  transient **reserved** holds.
  - **Observable (accept):** supplier calls whose *combined reserved* outbound cost across both
    rails is ≤ `$50` pass and settle; the running cross-rail **spend** total is in each receipt,
    distinct from the inbound revenue total.
  - **Adversarial twin:** the outbound call that would *reserve past* `$50` — on **either** rail
    — is refused **`UsageCapExceeded`** and **never settled** (the reservation fails before the
    rail is touched); `$49.99`-Stripe `+ $0.02`-x402 is refused where two siloed per-rail budgets
    each still read "$0 spent." A replayed/lower settled total is rejected
    (`UsageCounterRolledBack`). **Earned revenue does NOT raise the spend cap** — a profitable
    agent still cannot overspend its delegated drawdown (the cap bounds *cost*, not *net*).

- **AGENT-EARN-4 — Net profit accrues to the principal's custody and the P&L is verifiable.**
  *Maps: AGT-4 counter + receipt chain.* The gateway maintains `net = Σ inbound − Σ outbound`
  and **settles the net to the principal**, periodically **checkpoint-anchored** (D8: no
  per-call chain write, no log growth).
  - **Observable (accept):** after a recorded session of N inbound + M outbound calls, replaying
    the receipt chain with `auths verify` reconstructs `Σ inbound`, `Σ outbound`, and `net`
    byte-stably; the net-accrual receipt names the **principal** as beneficiary; the checkpoint
    digest matches.
  - **Adversarial twin:** a receipt chain **edited** to inflate inbound, drop an outbound, or
    re-beneficiary the net to the *agent* fails verification (the digest/checkpoint breaks); and
    the net counter is **monotonic at checkpoint granularity** — a rewound checkpoint is rejected.
    *The P&L cannot be cooked.* (Honest bound, `auths-mcp-gateway` §12: detection ≠ reversal —
    max *uncaught* discrepancy ≤ one checkpoint interval; receipts make any overspend *provable*
    for out-of-band clawback.)

- **AGENT-EARN-5 — One revoke is instant clawback; an aggregate cap bounds the fleet.**
  *Maps: OPS-1 (revoke) + AGT-4 (aggregate cap).* The principal revokes the agent mid-stream;
  separately, a fleet of N earning agents shares one **aggregate** spend cap.
  - **Observable (accept):** outbound calls before revocation pass; under an aggregate cap,
    per-agent spend that stays within the fleet total passes.
  - **Adversarial twin:** the **very next** outbound `tools/call` after the revoke event is
    refused **`Revoked`** — no token-TTL window, no introspection lag (liveness re-derived from
    the chain per call); and a fleet whose **combined** spend would exceed the aggregate cap is
    refused **`UsageCapExceeded`** on the agent that crosses it — even if *that* agent's own slice
    is in-budget. *Clawback is instant; the fleet's downside is one number.* (Inbound earning is
    **never** halted by the spend revoke/cap — revoking spend authority stops costs, not the
    custodied revenue already received; the directions are independent.)

- **AGENT-EARN-6 — A sub-delegated worker agent gets a provable spend slice and cannot exceed
  it on any rail (attenuation, STRETCH).**
  *Maps: AGT-1 (attenuation) + AGT-4.* The earning agent sub-delegates a helper a `$10` slice of
  its `$50` to do a sub-task; the helper serves/earns under the parent.
  - **Observable (accept):** the helper's outbound within its `$10` slice passes; its inbound
    earnings accrue up to the **same principal** (custody is inherited, not re-rooted).
  - **Adversarial twin:** the helper's outbound past `$10` is refused `UsageCapExceeded` on any
    rail (a child cannot exceed its parent's slice — `AGENT-ATTEN-3`'s subset rule); and the
    helper **cannot self-widen** its slice or re-beneficiary its inbound to itself. *(Rides the
    attenuation runtime; PARK rather than stub if sub-delegated cross-rail accounting isn't ready.)*

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy`; exact paths pinned during the sculpt (this PRD is
read-only). **Pre-launch ⇒ no back-compat:** existing surfaces are harvested and reshaped, not
preserved. This demo is a **consumer of the `auths-mcp-gateway`** engine crates plus a net-new
**inbound-custody + netting** surface.

### Exists — the spend-side primitives are closed; this consumes them
- **The bounded-agent gateway** — `auths-mcp-gateway` (real-MCP proxy) + `auths-mcp-core` (the
  per-`tools/call` gate: scope ⊆ parent · budget · expiry · revocation · receipts). The
  **outbound** half of this demo is a *config* of that gateway, not new code.
- **The cross-rail budget counter (D8)** — the verifier-held monotonic **settled** counter keyed
  to the agent delegation (`auths-mcp-core/budget.rs`, AGT-4's `usage_ledger.rs`), rollback-
  protected (`UsageCounterRolledBack`), plus the transient **reserved** holds; checkpoint-anchored
  (no per-call chain write). The **outbound** cap (`spend_budget = $50`) reuses this directly.
- **The signed per-call receipt** — every brokered call emits a chain-anchored, offline-verifiable
  receipt (`device=agent`, `identity=principal-root`); the substrate for the P&L (AGENT-EARN-4).
- **Delegated, scoped agents + the subset rule** — `id agent add --scope --expires-in` →
  `auths_sdk::domains::agents::add_scoped` (delegator-anchored seal; `enforce_scope_subset`,
  hardened in `AGENT-ATTEN-3`). The agent's `serve`-but-not-`withdraw` scope and the sub-agent
  `$10` slice (AGENT-EARN-6) ride this.
- **Fail-closed verdicts** — `OutsideAgentScope`, `AgentExpired` (auths-verifier); the AGT-4
  `UsageCapExceeded` / `UsageCounterRolledBack`; the OPS-1 `Revoked` path. **All reused; none new.**
- **The custody-broker model** — `auths-mcp-gateway` §12: the gateway holds the downstream secret,
  the agent holds only its delegation. **Net-new application:** custody the **inbound** x402
  receiving key the same way (the agent never holds it) — see Build.
- **The x402 cost-extraction adapter (OUTBOUND)** — `AGENT-PAY-2`: extract the paid amount from a
  recorded x402 settlement and meter it cross-rail. The **inbound** leg mirrors this read in the
  opposite direction (an *inbound* settlement, credited not debited).
- **`mode=real/test`** — the inverted payment-mode default (`AGENT-PAY-3`): real is the default,
  test is one opt-in flag, the cap is the mandatory seatbelt, the mode is disclosed. The earning
  agent's inbound/outbound rails inherit this mode resolution unchanged.

### Build — the net-new inbound + netting surface (engine in `auths`)
1. **Inbound x402 custody + metering** (`auths-mcp-core`, the load-bearing build, AGENT-EARN-1/2).
   Custody the **inbound** receiving address (the agent never holds the key — the §12 broker, in
   the receive direction); on a (recorded) inbound x402 settlement, emit a **`direction=inbound`**
   receipt and credit a per-agent **revenue** tally — *separate from* the spend counter (revenue
   is not budget). Enforce that the agent's scope grants `serve`/`earn` but that
   `wallet.withdraw`/`funds.transfer` is **absent** → `OutsideAgentScope` (no new verdict; a scope
   gate over a custodied resource).
2. **The net ledger + principal accrual** (`auths-mcp-core`/`auths-verifier`, AGENT-EARN-4).
   `net = Σ inbound − Σ outbound`, settled to the **principal's** custody (beneficiary named in the
   accrual receipt, not the agent); checkpoint-anchor the net digest periodically (reuse D8's
   checkpoint pattern). A programmatic **P&L verify**: replay the receipt chain → `(Σ inbound, Σ
   outbound, net)` + a beneficiary check (a thin extension of receipt `verify`, not new crypto).
3. **The aggregate (fleet) cap** (`auths-mcp-core`, AGENT-EARN-5) — bind a *shared* cap across N
   agent delegations (the cross-agent sum of AGT-4's per-delegation counter), refusing the agent
   whose call crosses the **fleet** total. (If AGT-4's ledger is strictly per-delegation today,
   this is the smallest aggregation extension; PARK the *fleet* half if the shared-counter keying
   isn't ready, keeping per-agent revoke/cap.)
4. **The self-monetizing harness + scenario config** in `auths-mcp/examples/self-monetizing/` (the
   *product's* examples — **not** `auths-demos`): a `serve.config` that wraps one paid service over
   the gateway with `--scope feed.serve,data.fetch,llm.call --budget $50 --inbound x402` and the
   live/replay harness driving inbound earns + outbound spends to the receipts/verdicts of §4.

Any surface already sufficient at baseline → reclassified to a **closed regression guard** (the
DOTAK precedent), never dropped. If the inbound leg turns out partly built on the gateway already,
the load-bearing gap narrows to whatever is genuinely missing.

---

## 6. Non-goals

- **NOT a claim that the strategy is profitable — auths is the safety + rails, not the alpha.**
  Nothing here asserts the agent's service earns more than it costs; that is the *service's*
  property, brought by the agent/author. auths asserts only that delegating capital to run it is
  *safe* (capped drawdown, two-way custody, instant clawback, verifiable P&L). State this plainly
  on screen.
- **NOT a payment processor, wallet, or exchange.** auths **custodies and bounds**; it never
  *settles* or *holds funds as a business*. Settlement is the rail's (Stripe / x402 facilitator);
  custody here means *the agent doesn't hold the key*, brokered by the gateway the principal runs.
- **NOT live money in the gate.** Per the hermetic constraint: **recorded fixtures only** — no live
  Stripe charge, no funded base-sepolia/mainnet wallet. The live earn/spend legs are *evidence-only,
  deferred* (the `AGENT-PAY-*` precedent). Every *verdict* is live; only the money is recorded.
- **NOT a new agent framework or a fork of MCP.** Rides the existing `auths-mcp` gateway; enforcement
  is additive middleware on inbound + outbound `tools/call`s.
- **NOT trading/market-making semantics.** "Net profit" here is *inbound receipts − outbound receipts*
  for a service business; no positions, no settlement risk, no market data correctness claim.
- **NOT cross-org discovery.** The sub-delegation (AGENT-EARN-6) attenuates *within* one principal's
  tree; stranger-org mutual introduction is AGT-3 / `AGENT-MCP-6`, out of scope.
- **NOT a hosted multi-tenant earning service.** This is the local/self-hosted gateway + harness; the
  hosted "earning-agents-as-a-service" and the witness network are separate.
- **NOT a perf claim.** Per-call sign+verify latency on the inbound/outbound legs is noted, not the
  property; correctness of the capped-drawdown + custody + P&L triad is.

---

## 7. The harness / run.sh dramaturgy

Two modes, one gateway — shipped in `auths-mcp/examples/self-monetizing/` (the product's own
examples, **not** `auths-demos`). `./run.sh` (the live show), `./run.sh --check` (the hermetic
gate / recurve probe entrypoint, recorded fixtures, no live money), `./run.sh reset` (pristine).
Auto / non-TTY plays itself. Ends on **the meter trending up while the cap holds and the agent
provably can't touch the float.**

- **Act 0 — The micro-business, delegated (disclosed).** Build the gateway from `../auths`. The
  principal mints the agent a delegation: `scope = {feed.serve, data.fetch, llm.call}`,
  `spend_budget = $50` (announced as **"the maximum this can ever cost you — the worst case"**),
  a `ttl`, an **inbound x402 address the gateway custodies**. Print the agent's scope and note,
  out loud, **what is absent**: no `wallet.withdraw`, no `funds.transfer`. Disclose: intents
  scripted, rails recorded, **every crypto verdict live**.
- **Act 1 — It earns (the inbound meter goes up).** Callers hit the paid service over x402; each
  recorded inbound settlement is custodied and metered — a green `direction=inbound` receipt, the
  **revenue** total ticking up: `+$0.05 … +$0.10 … +$0.15`. On screen: *"This is recurring
  revenue. The agent earned it. Watch what it cannot do with it."*
- **Act 2 — It pays its own costs (capped).** To answer, the agent spends on its suppliers — a
  data API (Stripe test-mode) and an LLM endpoint (x402) — each pre-authorized against the **one
  `$50` cap**, cross-rail. Green outbound receipts; the **spend** total rising *separately* from
  revenue. *"It reinvests its costs — but never past the cap."*
- **Act 3 — The net accrues to YOU.** Show the running P&L: `net = revenue − cost`, **settling to
  the principal's custody**. Replay the receipt chain with `auths verify` → the same `(Σ inbound,
  Σ outbound, net)` falls out, beneficiary = principal. *"A verifiable P&L — every dollar in and
  out, audited offline, trusting no processor."*
- **Act 4 — The drain that couldn't (custody).** The agent goes wrong — bug / injection / over-eager
  — and emits `wallet.withdraw(all)` on the custodied inbound. **Pledge before proof:** *"the
  signature is valid; it is asking to move money it was never given authority over."* →
  **`OutsideAgentScope`**, the custody wallet **never touched**. *"It earned every cent and can
  move none of it."*
- **Act 5 — The overspend that couldn't (the cap = max drawdown).** A retry storm makes the agent
  attempt the supplier call that crosses `$50` — `$49.99` Stripe `+ $0.02` x402. → **`UsageCapExceeded`**,
  before the rail is touched, *even though the agent is in profit* (revenue doesn't raise the cap).
  *"The most this can ever cost you is the number you set."*
- **Act 6 — The clawback (revoke) & the fleet (aggregate cap).** The principal revokes mid-stream →
  the **next** spend is **`Revoked`**, no window — *inbound already-earned is untouched* (directions
  independent). Then: 100 such agents under **one aggregate cap** — the agent that crosses the fleet
  total is refused even in its own per-agent budget. Close on the line: **"The agent brought the
  service. auths made it safe to hand it real capital: a capped downside, instant clawback, custody
  it can't pierce in either direction, and a P&L you can prove. That is an agent you can delegate to
  — and a business that runs itself."**

The climax is **Act 1 against Act 4**: the meter visibly *earning* while the agent *provably cannot
touch the float* — earn without limit, divert nothing.

---

## 8. Success metrics

Every verdict produced by real `auths-verifier` code over real KEL/TEL events in a real registry;
every money amount from a **recorded fixture** (no live charge, no funded wallet). The show + probes
assert these:

- **M1 (inbound custodied + metered, net to principal):** a recorded inbound x402 settlement is
  custodied, emits a `direction=inbound` receipt, raises the **revenue** total, and the net settles
  to the **principal** (not the agent); `auths verify` accepts the receipt (AGENT-EARN-1).
- **M2 (the agent can't divert the inbound):** a `wallet.withdraw`/`funds.transfer` call is refused
  **`OutsideAgentScope`** and the custody wallet is never touched — *signature valid, float
  untouched* (AGENT-EARN-2).
- **M3 (outbound capped at max-drawdown, cross-rail):** the outbound call that would reserve past
  `$50` on *either* rail is refused **`UsageCapExceeded`** before the rail is touched; `$49.99`+`$0.02`
  is refused; earned revenue does **not** raise the cap; the cross-rail spend total is in the receipts
  (AGENT-EARN-3).
- **M4 (verifiable P&L):** replaying the receipt chain reconstructs `(Σ inbound, Σ outbound, net)`
  byte-stably with beneficiary = principal; an edited chain (inflated inbound / dropped outbound /
  re-beneficiaried net) fails verification (AGENT-EARN-4).
- **M5 (instant clawback + fleet aggregate cap):** the first outbound after a mid-stream revoke is
  **`Revoked`** with no window (inbound untouched); a fleet crossing its aggregate cap is refused on
  the crossing agent even when its own slice is in-budget (AGENT-EARN-5).
- **M6 (sub-delegated slice, STRETCH):** a helper's outbound past its `$10` slice is refused on any
  rail and it cannot self-widen or re-beneficiary its inbound — or the claim is **PARKED** with the
  attenuation-runtime reason (AGENT-EARN-6).
- **M0 (the meta-metric — the unlock):** a principal can **delegate real capital to an agent that
  runs a paid service** and walk away — the inbound meter trends *up*, the outbound cap *holds*, the
  agent touches *neither* float key, and the net + P&L are *verifiable* — the "safe to delegate"
  bar no hot-wallet, no card+payout, no custodial platform can reach.

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): the canonical fields
are `id` / `title` / `class` / `status` / `severity` / `smallest_fix` (required) + `reads` / `probe`
/ `evidence` (file:line into the target) / `unlocks`. The **accept + adversarial paths live in each
probe** (the probe contract: an accept path + a `.trap/` counterexample) and are specified per-FR in
§4 — *not* in the gap entry. IDs `AGENT-EARN-*`; `reads: gateway` names a content-hash rule over the
built `auths-mcp-gateway` binary (`auths-mcp-gateway` §10). `AGENT-EARN-1` is the load-bearing build;
reclassify any claim already GREEN at baseline to a `closed` regression guard (the DOTAK precedent).
Probes are **hermetic** — recorded inbound/outbound settlement fixtures, **no live money**.

```yaml
- id: AGENT-EARN-1
  title: "The gateway custodies an inbound x402 payment, meters it as REVENUE, and nets it against outbound costs"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the INBOUND leg in auths-mcp-core: custody the inbound x402 receiving address (the agent
    never holds the key — the §12 custody-broker, receive direction); on a recorded inbound x402
    settlement, extract the amount (mirror AGENT-PAY-2's cost-extraction, credited not debited),
    emit a direction=inbound receipt, and credit a per-agent REVENUE tally kept SEPARATE from the
    spend counter (revenue is not budget). Maintain net = Σ inbound − Σ outbound and settle the net
    to the PRINCIPAL's custody (beneficiary in the accrual receipt), never the agent.
  unlocks: "An agent can EARN a custodied inbound stream at the MCP boundary at all — the floor for EARN-2..6 (recurring revenue = the inbound meter going up)."
  evidence:
    - "auths-mcp-core/budget.rs meters OUTBOUND cost only (AGENT-PAY-2 extracts a SPEND amount); no inbound/receive custody, no direction=inbound receipt, no separate revenue tally, no net-to-principal accrual — the earning leg is not built"
    - "maps the §12 custody-broker (the gateway holds the downstream secret) applied in the RECEIVE direction — net-new"
  covers: [inbound-custody, net-ledger]
  probe: probes/agent-earn-1.sh

- id: AGENT-EARN-2
  title: "The agent cannot WITHDRAW or divert the custodied inbound stream (custody + scope)"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Enforce that the agent's delegator-anchored scope grants serve/earn but that
    wallet.withdraw / funds.transfer is ABSENT: map a withdraw/transfer tools/call to a capability,
    gate it against the agent scope, and return OutsideAgentScope (naming the capability) WITHOUT
    touching the custodied inbound wallet. Reuse AGT-1's scope gate over the custodied receive
    resource (no new verdict).
  unlocks: "Two-way custody — the agent earns without limit and provably cannot move a cent of the float (the drain-that-couldn't beat)."
  evidence:
    - "maps AGT-1; OutsideAgentScope exists (auths-verifier) — this wires it to a withdraw/transfer call over the §12-custodied INBOUND wallet, which the agent never holds the key to"
  covers: [inbound-custody, scope-boundary]
  probe: probes/agent-earn-2.sh

- id: AGENT-EARN-3
  title: "Outbound costs are un-exceedably capped at the chosen max-drawdown across rails; earned revenue does NOT raise the cap"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Enforce the agent's outbound spend_budget against the SAME cross-rail settled+reserved counter
    as AGENT-MCP-3 / D8 (auths-mcp-core/budget.rs, AGT-4 usage_ledger.rs; rollback-protected →
    UsageCounterRolledBack), keeping the revenue tally (EARN-1) STRICTLY separate so net profit never
    raises available spend: a call that would reserve PAST the cap on either rail is refused
    UsageCapExceeded before the rail is touched, regardless of inbound revenue.
  unlocks: "The cap IS the max drawdown — a profitable agent still cannot overspend its delegated cost budget on any rail (the overspend-that-couldn't)."
  evidence:
    - "maps AGT-4 / D8 (cross-rail settled counter, auths 15bc605c, usage_ledger.rs) + AGENT-CAP-1 malformed-predicate guard (00de275c)"
    - "net-new: the spend cap must read ONLY the outbound tally, never net — the directions must not be conflated so revenue cannot reopen budget"
  covers: [budget-boundary]
  probe: probes/agent-earn-3.sh

- id: AGENT-EARN-4
  title: "Net profit accrues to the principal's custody and the P&L is offline-verifiable from the receipt chain"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build a programmatic P&L verify in auths-verifier: replay the per-agent receipt chain →
    (Σ inbound, Σ outbound, net) plus a beneficiary check (net settles to the principal, not the
    agent); checkpoint-anchor the net digest periodically (reuse D8's checkpoint pattern — no
    per-call chain write). A chain edited to inflate inbound, drop an outbound, or re-beneficiary the
    net fails; the net counter is monotonic at checkpoint granularity (a rewound checkpoint rejected).
  unlocks: "Recurring revenue = a receipt chain that trends up, verifiable by a stranger (underwriter / co-investor / auditor) trusting no processor — the P&L half of 'safe to delegate'."
  evidence:
    - "maps the gateway receipt path + D8 checkpoint-anchoring; no cross-direction P&L verify (Σ inbound − Σ outbound) and no net-beneficiary-is-principal check exists — the verifiable-P&L surface is not built"
    - "honest bound (§12): detection ≠ reversal — max uncaught discrepancy ≤ one checkpoint interval; receipts make any overspend provable for out-of-band clawback"
  covers: [net-ledger]
  probe: probes/agent-earn-4.sh

- id: AGENT-EARN-5
  title: "One revoke is instant clawback (no window); an aggregate cap bounds the whole earning fleet by total risk"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    (a) Re-derive liveness from the KERI registry on every OUTBOUND tools/call (reuse keri_auth's
    revocation check) so the first spend after a revoke event is Revoked — no token TTL, no lag —
    while INBOUND already-earned custody is untouched (directions independent). (b) Bind a SHARED
    aggregate cap across N agent delegations (cross-agent sum of AGT-4's per-delegation counter),
    refusing the agent whose call crosses the FLEET total even when its own slice is in-budget. PARK
    the fleet half — do not stub — if the shared-counter keying is absent, keeping per-agent revoke.
  unlocks: "Instant clawback + a fleet of earning agents bounded by ONE number of downside — the insurable-fleet story (OPS-1 + AGT-4)."
  evidence:
    - "maps OPS-1 (revocation) + AGT-4 (caps); keri_auth.rs checks revocation per presentation; AGT-4's ledger is per-delegation — the cross-agent AGGREGATE sum is the net-new aggregation (likely PARK if shared-counter keying absent)"
  covers: [revocation-boundary, budget-boundary]
  probe: probes/agent-earn-5.sh

- id: AGENT-EARN-6
  title: "A sub-delegated worker gets a provable spend slice it cannot exceed on any rail, with inbound inherited to the same principal"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Let the earning agent sub-delegate a helper a $10 slice of its $50 (attenuation): the helper's
    outbound within $10 passes and its inbound accrues to the SAME principal (custody inherited, not
    re-rooted); the helper's outbound past $10 is refused UsageCapExceeded on any rail (subset rule,
    AGENT-ATTEN-3) and it cannot self-widen its slice or re-beneficiary its inbound to itself. PARK —
    do not stub — if sub-delegated cross-rail accounting / inbound inheritance isn't ready.
  unlocks: "Agents earning from agents, safely composable — a parent can spin up sub-workers each provably bounded, the recursive micro-business (AGT-1 attenuation + AGT-4)."
  evidence:
    - "maps AGT-1 (attenuation, AGENT-ATTEN-3 subset rule) + AGT-4; no sub-delegated cross-rail spend slice and no inbound-custody inheritance to the root principal exists — likely PARK on the attenuation runtime"
  covers: [scope-boundary, budget-boundary, inbound-custody]
  probe: probes/agent-earn-6.sh
```

---

*Drafted 2026-06-15. A go-to-market agent use case filed under `prds/go_to_market/agents/`. Rides
the `auths-mcp-gateway` bounded-agent gateway (scope · cross-rail budget · revocation · custody-broker
· receipts · `mode=real/test`) and adds the net-new **inbound x402 custody + cross-direction netting +
verifiable-P&L** leg — the agent that **earns**. Consumes the closed primitives AGT-1 (scope), AGT-4 /
D8 (cross-rail counter), OPS-1 (revocation), and the `AGENT-PAY-*` rail adapters. House style mirrors
`agent_demos/the-agent-with-a-credit-limit` and `the-intern-that-couldnt`: narrative + falsifiable
`gaps.yaml` + accept/adversarial probes + a staged `run.sh`. Hermetic probes only — recorded
inbound/outbound settlement fixtures, **no live money**; the live earn/spend legs are evidence-only,
deferred. The recurve loop sculpts `../auths` (the gateway engine crates) to turn `AGENT-EARN-*` GREEN.
**The honest core:** auths is the safety + the rails, not the alpha — it does not make the strategy
profitable; it makes it safe to delegate real capital to an agent that runs it (capped drawdown,
instant clawback, two-way custody, a verifiable P&L). The agent brings the alpha; auths bounds the
downside.*
