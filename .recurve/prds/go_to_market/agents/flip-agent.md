# PRD: The Flip Agent — delegate real capital to a resale bot, downside capped by construction

> **One line:** a developer hands a resale agent a **scoped, budget-capped, instantly-revocable
> delegation** and turns it loose on a real marketplace — it buys underpriced goods (sneakers,
> GPUs, domains, collectibles) and resells at a markup, *spending real money to buy inventory* —
> and because the agent holds **only bounded spend authority and never the wallet itself**, the
> worst it can ever do is lose the cap you set, the cap binds **across every rail at once**
> (Stripe to buy, x402/USDC inbound on the sale), one **revoke** is an instant clawback, and every
> flip leaves a **signed, verifiable P&L receipt**.
>
> **What this is — read first.** This is a **go-to-market agent scenario** that rides on the
> `auths-mcp` bounded-agent gateway (`prds/go_to_market/auths-mcp-gateway.md`): the agent's MCP
> client points at the gateway, the gateway **custodies the buy-rail credential** while the agent
> holds only the delegation, and every `tools/call` — every *purchase* — is checked against the
> agent's **delegator-anchored scope + cross-rail budget** before any rail is touched. The flip use
> case is shipped as **example configs over that one gateway** (`auths-mcp/examples/flip`), not a
> bespoke runtime. Nothing new lands in `auths-demos`.
>
> **REVENUE, stated honestly — auths is the SAFETY + the RAILS, not the alpha.** This is a *profit
> center*: capital becomes **inventory that sells** (buy $80 → sell $120 → +$40, repeat), and x402
> pay-per-request lets the agent **earn** an inbound stream, not just spend. But be plain:
> **auths does not make the strategy profitable.** The agent brings the alpha — finding the
> underpriced good is the agent's job and its risk. What auths does is make it *safe to delegate
> real capital* to an agent that runs that strategy: the cap **is** your max drawdown, custody means
> the agent **never holds your wallet** (only bounded spend authority), instant revoke **is** the
> clawback, the aggregate cap **is** a fleet bounded by your total risk, and the signed receipts
> **are** a verifiable P&L. auths bounds the downside; it does not manufacture the upside.
>
> **Status — honest:** this scenario rides on the `auths-mcp` build (load-bearing `AGENT-MCP-1`
> gateway) and on the closed primitives **AGT-1** (scope), **AGT-4 / D8** (the cross-rail
> checkpoint-anchored budget counter), **OPS-1** (instant revocation), **AGT-5/aggregate** (the
> fleet cap). Where a primitive is GREEN, this scenario is a thin config + probe over it; where the
> *two-sided commerce* binding (inbound x402 earnings metered into the same authority as outbound
> spend) is net-new, the gap names exactly what GREEN requires. Hermetic probes only — **recorded
> fixtures, no live money** (a live Stripe-test buy or a funded x402 testnet sale is evidence-only,
> deferred, exactly as `AGENT-PAY-1/2` scope it).
>
> **Authoring scope:** READ-ONLY on `../auths` for this PRD. The recurve loop sculpts the engine
> crates (`auths-mcp-core` / `auths-mcp-gateway` / `auths-verifier`) and the wrapper repo to turn
> these gaps GREEN. House style mirrors `agent_demos/the-intern-that-couldnt`: narrative +
> falsifiable gaps + accept/adversarial probes + a staged `run.sh`.

---

## 1. One line + scenario

A developer runs a **resale agent** — a real MCP-speaking model in a real tool loop. Its job is
ancient and simple: **buy low, sell high, on real goods.** It watches feeds for underpriced
real-world inventory — a sneaker drop listed below resale, a used GPU under spot, an expiring
domain, an undervalued collectible, a face-value event ticket in a resale-legal jurisdiction —
**buys it** on a payment rail, then **lists and sells it** at a markup. The capital is not "gone"
when it spends: an $80 buy becomes an $80 piece of inventory that sells for $120, and the cycle
repeats. Two-sided commerce: **outbound** to acquire, **inbound** on the sale.

The developer wants to delegate this to the agent *and walk away*. The thing stopping every
developer alive from doing that today is the obvious one: **you have to give the bot a way to
spend your money**, and the moment you do, a buggy, prompt-injected, or over-eager model can drain
the account, buy the wrong thing, buy ten of the right thing, or keep buying after you tried to
stop it. The agent's API key to the payment rail is *ambient, total authority* — possession is
permission, with no cap and no parent.

Now insert the **auths gateway** between the agent and its rails. The developer mints the agent a
**delegation**: `scope = {marketplace.buy, marketplace.list, marketplace.sell}`, `budget = $500`
(the **inventory cap** = the max capital at risk), `ttl = 24h`, anchored in the developer's KEL.
The agent's MCP client points at the gateway, not at the raw Stripe/marketplace servers — and the
**gateway custodies the buy-rail credential while the agent holds only the delegation**, so a
misbehaving agent cannot route around it. Every purchase the model emits is intercepted, checked
against the agent's **delegator-anchored grant**, *reserved* against the cross-rail budget *before
the rail is touched*, signed into a per-flip receipt, and forwarded **only if it is inside scope,
inside budget, unexpired, and unrevoked.**

Then the realistic failure, *driven by the model itself*: the agent, mid-run, decides to buy a
$700 GPU when it has $500 of authority; or it loops a hot drop and tries to buy the eleventh pair
past the cap; or the human sees a bad streak and hits "kill" and the agent tries one more buy.
**The signature on each attempt is valid. The MCP envelope is well-formed. It is asking to spend
more than its parent ever anchored — so the gateway refuses, from the chain alone, offline, before
a cent moves.**

And the *upside* side: when the agent **sells**, the inbound payment arrives over **x402/USDC** as
a pay-per-request settlement; the gateway meters that **earning** into the *same* agent authority's
ledger, so the receipt is a real two-sided P&L (−$80 buy, +$120 sale, +$40 realized) — verifiable
offline, by anyone, without trusting the marketplace or the processor.

**How it breaks today.** To let a bot spend, you hand it a card number or a payment-rail API key.
That key is ambient: steal it, hold it, *that is the authority* — there is no cap bound to the
*action*, no parent the rail can re-derive containment against, and revocation lags a token TTL +
an introspection cache. A per-rail processor budget (Stripe Issuing spend caps) bounds *one card*,
not *the agent* — and it cannot span the buy rail and the sell rail as one number. Human-approval
dialogs don't scale to a bot meant to flip a hundred items a day and leave no cryptographic
receipt. None of these can prove, at the rail boundary, that *this* agent's buy is within a cap its
parent provably anchored, across *every* rail, revocable with no window.

**What auths does.** The purchase *is* a signed artifact. The gateway resolves the agent's
delegated KEL **and** its delegator's KEL, replays with delegator-aware lookup, reads the
**delegator-anchored scope + cross-rail budget seal**, and judges the buy against it — returning a
distinct verdict (`OutsideAgentScope` / `UsageCapExceeded` / `AgentExpired` / `Revoked`). The
spend authority the model is trying to exercise **was never anchored for it by its parent, so it
does not exist** — no matter how the model "decided," and no matter how good or bad the trade was.

---

## 2. The property it proves

**You can delegate REAL capital to an autonomous agent because the downside is provably capped —
and you can do it across every rail at once, revoke it instantly, and read a verifiable P&L.** The
agent is a live model making its own buy/sell decisions; the bound is not a confirmation dialog,
not a policy engine, not a processor's good behaviour, but the same parent→child containment the
scripted demos prove — now applied to **the act of spending and earning real money.** Concretely:

- **cap = MAX DRAWDOWN.** The budget anchored in the delegation is the most the agent can ever
  lose. Not "should" — *can*. It is enforced by pre-authorization at the rail boundary, from the
  chain, offline.
- **custody = the agent never holds your wallet.** The gateway custodies the buy-rail credential;
  the agent holds *only* bounded spend authority. An injected agent that points straight at the raw
  rail has no credential — the buy fails. The wallet was never in the agent's hands to drain.
- **instant revoke = clawback.** One revocation event and the agent's *very next* buy fails on
  *every* rail, with no token-TTL window. You can stop a runaway mid-run.
- **aggregate cap = a fleet bounded by your total risk.** Run 100 flip agents under one developer
  root with a single aggregate cap; the fleet's *combined* spend cannot exceed your total
  authority, even though each sub-agent thinks locally.
- **signed receipts = a verifiable P&L.** Every flip (buy *and* sale) emits a signed receipt —
  rail, amount, counterparty, verdict, running total — replayable offline with `auths verify`. The
  agent's books are cryptographic, not log-scraping.

**Said plainly (the honesty that makes it credible): auths is the SAFETY + the RAILS, not the
alpha.** It does not find the underpriced sneaker, does not predict resale value, does not make a
single trade profitable. The agent brings the strategy and owns its outcome. What auths makes
possible is the thing a treasurer actually needs before delegating a budget to software: a
**provable floor under the loss**, an instant kill, a cross-rail cap, and a receipt — so "let a bot
trade real money" stops being reckless and becomes *insurable*.

**Why the incumbents structurally can't match it:**

| Incumbent | Where the spend authority lives | Why it can't bound a real capital-deploying agent |
|---|---|---|
| **Payment-rail API key / card number** (what a bot gets today) | nowhere — possession *is* the grant | Ambient, total authority with no parent, no cap bound to the action, no chain. An injected agent with the key can drain the account. There is no "max drawdown," only "max balance." |
| **Per-rail processor budget** (Stripe Issuing spend caps) | a policy on *one card* in the processor's evaluator | Bounds a card, not *the agent*; cannot span the buy rail **and** the sell rail as one number; the relying party trusts the processor's central engine, not a cryptographic parent→child cap. $499 on Stripe + $499 on a second rail each reads "in budget." |
| **OAuth 2.1 bearer (MCP's own auth spec)** | a token the AS minted; scopes are asserted strings | Bearer = ambient; the proof isn't bound to the *purchase*. Scopes are **boolean** — OAuth cannot say "≤ $500." Revocation lags TTL + cache, so a "killed" agent keeps buying for its token's lifetime. |
| **Human-in-the-loop approval** | a person clicking "allow" on each buy | Doesn't scale to a bot meant to flip dozens of items a day, isn't cryptographic, leaves no verifiable receipt, and is exactly the toil agents exist to remove. Approval ≠ a provable cap. |

None lets a **stranger relying party** — an underwriter, an auditor, a co-investor — prove offline,
from signatures alone, that *this* agent's capital deployment is bounded by a cap its owner provably
anchored, across every rail, with instant clawback and a verifiable P&L. That is the property that
makes "delegate $500 (or $5M) of working capital to a resale bot" a priceable risk instead of an
act of faith.

---

## 3. Goals — what makes it believable

- **G1 — A real model, a real loop, a real two-sided flip.** The agent is a live MCP-speaking model
  in an actual `tools/call` loop: it *buys* underpriced inventory on a metered buy rail (Stripe
  test-mode) and *sells* it on an inbound rail (x402/USDC testnet), against real marketplace MCP
  servers. No mocked agent; the buy/sell decisions are the model's. (CI uses a recorded transcript
  of those decisions — §7 — never a fake model, never live money.)
- **G2 — The over-spend is emergent, then capped.** The compelling beat is a *purchase the model
  chose* — over budget, out of scope, or post-revocation — refused at the gateway with a distinct
  verdict, **before the rail is touched and before a cent moves**, while a within-cap buy from the
  same agent passes and settles. *The model decided to overspend; the chain refused.*
- **G3 — Capital is inventory, not loss — and the P&L is on the receipt.** The show makes the
  profit-center framing concrete and *honest*: a buy is a −$ outbound receipt; the matching sale is
  a +$ inbound receipt; the realized margin is the difference, on chain-anchored receipts anyone can
  verify. The agent's job is to make that margin positive; auths's job is to prove it and bound the
  downside. We never claim auths made the margin.
- **G4 — One cap across both sides of the trade.** The buy (Stripe) and the sell (x402/USDC) are
  metered into **one** cross-rail authority — the inventory cap bounds outbound spend; the inbound
  earnings are receipted into the same ledger, so the agent's *net* position is one verifiable
  number, not two siloed processor balances.
- **G5 — Instant clawback + a fleet bounded by total risk.** One revoke stops the agent's spend on
  every rail at once (the kill-switch). And an aggregate cap over a fleet of flip agents under one
  root bounds the *combined* capital at risk to the developer's total — sub-delegation/attenuation
  means each agent provably cannot exceed its slice.
- **G6 — Scenarios are configs.** The `inventory-cap` (budget), `wrong-buy` (scope),
  `kill-the-flipper` (revocation), and `fleet-cap` (aggregate) scenarios each run as a ~20-line
  **config of the one `auths-mcp` gateway**, shipped in `auths-mcp/examples/flip/` — proving the
  product collapse and giving the flip story a real, installable counterpart.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an **adversarial twin
(fail-closed, rejected)**. IDs `AGENT-FLIP-*`. They reuse the `auths-mcp` gateway build
(`AGENT-MCP-1`) and the closed primitives **AGT-1** (scope), **AGT-4 / D8** (cross-rail
checkpoint-anchored budget), **OPS-1** (revocation), **AGT-5/aggregate** (fleet cap). **FR-1 is
load-bearing: it binds the *buy* (capital deployment) to the cross-rail cap.** All probes drive the
gateway in **replay mode** over recorded fixtures — **no live money.**

- **FR-1 — A buy is pre-authorized against the inventory cap before the rail is touched (THE
  BUILD).** *Maps: AGT-4/D8 (+ AGENT-MCP-1 gateway, AGT-1 for cross-rail attenuation).* The agent
  holds a single `budget = $500` (the inventory cap). Its buy rail is a metered Stripe-test
  downstream; before each purchase the gateway **reserves** the charge amount against the single
  monotonic cross-rail SETTLED counter (keyed to the agent delegation), lets the buy proceed only if
  it fits, then **settles** the actual on the charge response and releases the slack.
  - **Observable (accept):** a buy whose reserved cost keeps cumulative spend ≤ $500 passes,
    settles, and the running cross-rail total appears in the flip receipt (`rail=stripe`, charge id
    named, `device=agent`, `identity=developer-root`); `auths verify` of the receipt accepts.
  - **Adversarial twin:** a buy that would **reserve past** $500 is refused **`UsageCapExceeded`**
    and **never settled** — the reservation fails *before* Stripe is invoked, so the over-cap charge
    is never charged. The counter is monotonic: a replayed/lower total is rejected
    (`UsageCounterRolledBack`). *The signature was valid; the money never moved.*

- **FR-2 — A buy outside scope is refused with a distinct verdict.** *Maps: AGT-1.* The agent holds
  `scope = {marketplace.buy, marketplace.list, marketplace.sell}`; the model emits a call to a
  capability it was never granted (e.g. `wallet.withdraw` / `marketplace.transfer` — moving funds
  *out* rather than buying inventory).
  - **Observable (accept):** an in-scope `marketplace.buy` call passes the scope gate.
  - **Adversarial twin:** the `wallet.withdraw` call returns a fail-closed MCP error carrying
    **`OutsideAgentScope`**, naming the offending capability — **the downstream server is never
    called** — despite a valid signature and a well-formed envelope. *A resale bot cannot quietly
    become a withdrawal bot.*

- **FR-3 — The inbound sale is metered into the SAME authority as the outbound buy (the
  two-sided/cross-rail moat).** *Maps: AGT-4/D8 cross-rail (+ AGENT-PAY-2 x402 leg).* The buy
  settles on Stripe; the sale settles inbound on x402/USDC; both meter into one cross-rail ledger so
  the agent's net position is one number, and the cap bounds outbound across rails.
  - **Observable (accept):** a buy on Stripe (−$80) and a sale on x402/USDC (+$120) both appear in
    the receipts metered into the *same* delegation's ledger; the realized margin (+$40) is derivable
    from the chain-anchored receipts, offline.
  - **Adversarial twin:** a buy that would push *outbound* spend past the cap is refused on **either**
    rail — `$499`-on-Stripe `+ $0.02`-on-a-second-buy-rail is refused `UsageCapExceeded`, where two
    siloed per-rail budgets each still read "in budget." Inbound earnings are **receipted, not
    credited back into spendable headroom** unless the policy explicitly says so — the cap is a *risk
    bound on capital deployed*, and a forged "+$1000 sale" receipt cannot silently widen the buy cap
    (the sale's settlement is verified from the rail, not asserted by the agent).

- **FR-4 — Revocation is an instant clawback, mid-run, with no propagation window.** *Maps: OPS-1.*
  The developer revokes the agent's delegation while the flip loop is running.
  - **Observable (accept):** buys before the revocation event pass and settle.
  - **Adversarial twin:** the **very next** buy after revocation is refused **`Revoked`** — no token
    still valid for its TTL, no introspection-cache lag; the gateway re-derives liveness from the
    chain on every call. *A bad streak is stoppable in one event, not one token-lifetime later.*

- **FR-5 — A fleet of flip agents is bounded by one aggregate cap (sub-delegation/attenuation).**
  *Maps: AGT-5/aggregate (+ AGT-1 attenuation).* A developer root delegates an aggregate
  `budget = $2000` and sub-delegates four flip agents a `$500` slice each; the aggregate counter
  bounds *combined* spend.
  - **Observable (accept):** four agents each spending within their `$500` slice, summing ≤ $2000,
    all pass; each sub-agent's slice is a provable subset of the root's authority.
  - **Adversarial twin:** a sub-agent attempting to spend past its `$500` slice is refused
    `UsageCapExceeded` (it cannot exceed its parent); and once the *combined* fleet spend reaches
    `$2000`, the next buy by *any* agent is refused against the aggregate counter — even though that
    agent's own slice still reads in-budget. *A fleet provably cannot exceed your total risk; a
    sub-agent provably cannot widen its own slice.*

- **FR-6 — Every flip leaves a signed, independently-verifiable P&L receipt.** *Maps: AGENT-MCP-1
  receipts (+ AGT-4 running total).* Each brokered buy and sale (allowed *or* refused) emits a
  signed receipt — actor, grant, action, rail, amount, verdict, running cross-rail total.
  - **Observable (accept):** the buy and sale receipts for a completed flip `auths verify` accept
    offline, and reconstruct the realized margin without trusting the marketplace or the processor.
  - **Adversarial twin:** a receipt edited to forge a wider cap, drop the proof, or fabricate a sale
    amount **fails verify** — the P&L cannot be quietly cooked; the spend total is the verifier-held
    monotonic counter, not an agent-asserted number.

> **On the over-reach being the model's (the believability leg).** As in `auths-mcp` §4
> (`AGENT-MCP-5`): in live mode a real model — given an over-eager/injectable resale task —
> *itself* emits the over-cap or out-of-scope buy; the recorded transcript of that exact decision
> drives the same gateway to the same verdicts in CI. This is **believability, not a stronger
> property** — the gateway sees the identical `tools/call` whether a live model or a script emits
> it. The live model proves the over-spend is genuinely emergent; the transcript is what tests the
> enforcement, hermetically, with no money.

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy`; exact paths pinned during the sculpt (this PRD is
read-only). This scenario is **mostly a config + probe layer over the `auths-mcp` gateway** — it
*consumes* the gateway build and the closed primitives, and *builds* only the two-sided
(inbound-earnings) binding and the flip-specific framing/examples.

### Exists — the enforcement primitives this scenario consumes
- **The `auths-mcp` gateway + core** (`prds/go_to_market/auths-mcp-gateway.md`, `AGENT-MCP-1`): the
  real-MCP proxy that custodies the downstream credential and runs the per-`tools/call` gate
  (`auths-mcp-core`) — scope ⊆ parent, cross-rail budget, expiry, revocation — and emits signed
  per-call receipts. **The flip buy/sell calls are exactly the `tools/call`s this gateway brokers.**
- **The cross-rail budget counter (D8, AGT-4)** — a single monotonic verifier-held high-water
  SETTLED ledger keyed to the agent delegation (`usage_ledger.rs`), rollback-protected
  (`UsageCounterRolledBack`), checkpoint-anchored (no per-call chain write), plus the transient
  RESERVED-holds set for the reserve-then-settle auth-hold lifecycle. **This is the inventory cap.**
- **The metered rails (`AGENT-PAY-1`, `AGENT-PAY-2`)** — gateway-side cost extraction from a
  recorded Stripe-test charge response (`amount_captured` → cents) and from a recorded x402/USDC
  settlement response (atomic USDC at 6 decimals → cents), both reserving/settling into the *same*
  cross-rail cap. **The buy rail (Stripe) and the cross-rail summing are AGENT-PAY surfaces.**
- **The inverted payment-mode default + mandatory-cap seatbelt (`AGENT-PAY-3`)** — real money is the
  default, test is the single opt-in, and the gateway **refuses to wrap a payment rail without a
  `--budget`** (fail-closed `budget-required`), with `mode=real|test` disclosed. **A flip agent can
  never be wrapped uncapped.**
- **Fail-closed verdicts** — `OutsideAgentScope`, `AgentExpired` (`auths-verifier`); the AGT-4
  `UsageCapExceeded` / `UsageCounterRolledBack`; the OPS-1 `Revoked` path.
- **Delegated, scoped, attenuating agents** — `id agent add --scope --expires-in --budget` →
  `auths_sdk::domains::agents::add_scoped` (delegator-anchored seal; subset rule hardened in
  `AGENT-ATTEN-3`) — the sub-delegation/attenuation the fleet cap (FR-5) rides on.

### Build — the deliverables this scenario adds
1. **The inbound-earnings binding (FR-3, FR-6) — the net-new piece.** Today the cross-rail counter
   is built for *outbound spend* (reserve→settle a cost). The two-sided flip needs the **sale**
   (an *inbound* x402/USDC settlement) metered into the **same** delegation's ledger as a credited
   receipt line, so the P&L reconstructs offline. Decide + encode the policy: inbound earnings are
   **receipted into the P&L but do NOT silently widen the outbound risk cap** (the cap is a bound on
   *capital deployed*, not net position) unless an explicit `--reinvest` policy says so. This is a
   thin extension of the receipt + ledger surfaces, not new crypto.
2. **The flip scenario configs (G6)** in `auths-mcp/examples/flip/`: `inventory-cap.config`
   (FR-1/3), `wrong-buy.config` (FR-2), `kill-the-flipper.config` (FR-4), `fleet-cap.config`
   (FR-5) — each a ~20-line config over the one gateway, plus the buy/sell marketplace-MCP stubs.
3. **The live/replay flip harness + recorded fixtures** — a thin live tool-loop (real model buys &
   sells; evidence-only, never gated) and the **committed transcript + recorded Stripe-test charge
   and x402-settlement fixtures** that the hermetic probes replay. **No live money in the gate.**
4. **The `run.sh` dramaturgy + the `AGENT-FLIP-*` probes** (§7, §9).

Any surface that already suffices end-to-end at baseline → reclassified to a **closed regression
guard** (the DOTAK precedent), never quietly dropped.

---

## 6. Non-goals & honest constraints

- **NOT the alpha. NOT a trading/valuation engine.** auths does not find underpriced goods, predict
  resale value, or make any flip profitable. The agent owns the strategy and its losses-within-cap.
  This is repeated deliberately: **auths is the safety + the rails, not the edge.**
- **NOT a payment processor / wallet / custodian of funds.** The gateway *bounds* spend, *custodies
  the downstream credential*, and *receipts* the flow; it never holds or settles funds. Stripe and
  x402 are wrapped downstream tools (`auths-mcp` §11). "Custody" here means custody of the *spend
  credential*, not of the *money*.
- **NOT a live-money probe.** Per the status block and `AGENT-PAY-1/2`: every probe is hermetic over
  recorded fixtures. A live Stripe-test buy or a funded x402 testnet sale is **evidence-only,
  deferred** (the live x402 leg needs a funded base-sepolia USDC wallet — out of hermetic scope).
- **NOT a claim that inbound earnings widen the risk cap.** By default the inventory cap bounds
  *capital deployed*; a sale's proceeds are receipted but do not auto-refill spendable headroom
  unless an explicit `--reinvest` policy is set (FR-3). We do not silently let "profit" raise the
  drawdown bound.
- **Legal-gray markets are the operator's responsibility, fenced in config — not a property claim.**
  Some resale is jurisdiction-restricted: **event-ticket resale** is capped or barred in places
  (e.g. several US states and EU markets restrict above-face or bot-bought ticket resale; the US
  BOTS Act bars circumventing ticket purchase limits), and some marketplaces' ToS forbid automated
  buying. auths bounds *how much* an agent can spend and proves *what* it did — it does **not**
  determine *legality*. The flip examples treat ticket resale as an **opt-in, jurisdiction-flagged
  config** (default: sneakers/GPUs/domains/collectibles, which are broadly resale-legal); the
  operator is responsible for compliance with marketplace ToS and local law. We state this on screen
  and in the README; we make no representation that any configured flip is lawful in the operator's
  jurisdiction.
- **NOT a new agent framework.** This integrates with MCP via the `auths-mcp` gateway; it builds no
  orchestration, planning, or inventory-management runtime of its own.
- **NOT a perf claim.** Per-buy sign+verify latency is noted, not the property; correctness of the
  cap, the clawback, and the receipt is.

---

## 7. The narrative / run.sh dramaturgy

Self-performing, staged in acts (like `the-intern-that-couldnt` / `death-of-the-api-key`):
`./run.sh` (the live show, evidence-only), `./run.sh --check` (the hermetic gate, replay mode, the
recurve probe entrypoint), `./run.sh reset` (pristine). Auto/non-TTY plays itself. Disclosed on
screen: the model + prompt are real (live mode); the gate runs a frozen transcript over recorded
fixtures; **no live money anywhere in the gate.**

- **Act 1 — The mandate, signed.** Show the delegation being minted:
  `developer-root → flip-agent`, a real `dip` anchored by an `ixn`, carrying
  `scope = {marketplace.buy, list, sell}`, `budget = $500` (the inventory cap = max drawdown),
  `ttl = 24h`. `git log --oneline refs/auths/*` shows the anchor. Disclose the honesty up front:
  *the cap is the most this bot can ever lose; auths does not make it win.*

- **Act 2 — The flip (capital becomes inventory, then profit).** The agent finds an underpriced
  good and **buys** it: a Stripe-test charge for $80, **reserved against the cap before the rail is
  touched**, then settled → an outbound receipt (−$80, running total $80/$500). It lists and
  **sells** it: an x402/USDC inbound settlement of $120 → an inbound receipt (+$120) metered into the
  *same* authority. Print the P&L line: **−$80 buy, +$120 sale, +$40 realized — on chain-anchored
  receipts anyone can verify.** The honest caption: *the +$40 is the agent's edge; the receipt is
  auths's.*

- **Act 3 — The overspend (the model reaches past the cap).** Mid-run the agent — framed as
  over-eager planner / bad feed / prompt injection — tries to buy a $700 GPU on a $500 authority (or
  the eleventh hot-drop pair past the cap). **Pledge before proof:** "its signature is valid, its
  delegation is valid; it is asking to spend more than its parent ever anchored. The reservation will
  fail before Stripe is ever called. Expect rejection, and expect *no charge*." Gateway →
  **`UsageCapExceeded`**, the buy **never settled**, the rail **never touched**. *The model decided
  to overspend; the money never moved.*

- **Act 4 — The wrong tool (scope, not just amount).** The agent tries `wallet.withdraw` — moving
  funds *out* instead of buying inventory (a resale bot quietly trying to become a withdrawal bot).
  Gateway → **`OutsideAgentScope`**, naming the capability, downstream **never called**. *A valid
  signature for an authority it was never granted.*

- **Act 5 — The kill (instant clawback).** A bad streak; the developer hits revoke mid-run. The very
  next buy → **`Revoked`** — no TTL window, no cache lag. *One event, and spend stops on every rail
  at once.*

- **Act 6 — The fleet, bounded by total risk.** Four flip agents under one root, each a `$500`
  slice of a `$2000` aggregate. A sub-agent tries to spend past its slice → refused (cannot exceed
  its parent); the fleet's combined spend hits `$2000` → the next buy by *any* agent is refused
  against the aggregate counter, *even though its own slice still reads in-budget*. Close on the
  line: **"Every one of these was a real model's real decision to spend real money. The cap was the
  most it could lose, the revoke was an instant clawback, the receipts are a verifiable P&L — and
  none of it trusted a processor, a token, or the model's good behaviour. auths didn't pick the
  trades. It made it safe to let a bot make them."**

The climax is Act 3: a **valid signature, real intent to spend, refused before a cent moves** — the
moment that makes delegating real capital sane.

---

## 8. Success metrics

The show and the probes assert these verdicts (not P&L outcomes — the agent owns those):

- **M1 (buy capped, distinct verdict):** a buy that would reserve past the inventory cap is refused
  **`UsageCapExceeded`** **before the rail is touched and with no charge settled** (FR-1 twin); a
  within-cap buy settles and is metered, with the running total in the receipt. *Signature valid;
  money never moved.*
- **M2 (scope):** an out-of-scope call (`wallet.withdraw`) is refused **`OutsideAgentScope`** before
  the downstream is invoked (FR-2 twin).
- **M3 (two-sided / cross-rail P&L):** a buy (Stripe) and a sale (x402/USDC) meter into one
  delegation's ledger; the realized margin reconstructs offline from chain-anchored receipts; an
  over-cap buy is refused on *either* rail even when each per-rail silo reads in-budget (FR-3).
- **M4 (instant clawback):** the first buy after a mid-run revocation is refused **`Revoked`** with
  no window (FR-4 twin).
- **M5 (fleet cap):** a sub-agent cannot exceed its slice, and the fleet's combined spend cannot
  exceed the aggregate cap (FR-5 twin).
- **M6 (verifiable P&L):** the flip receipts `auths verify` accept offline; an edited/forged receipt
  fails verify (FR-6 twin).
- **M0 (the meta-metric):** a developer can **delegate real capital to a live resale agent and walk
  away**, because the cap is a provable max drawdown, custody keeps the wallet out of the agent's
  hands, revoke is an instant clawback, the aggregate cap bounds the fleet, and every flip is a
  verifiable P&L — *the bar an API key, a processor budget, or an approval dialog cannot reach.*

Every verdict is produced by real `auths-verifier` code over real KEL/TEL events; every rail amount
in the gate comes from a recorded Stripe-test / x402-settlement fixture. Nothing about the
*enforcement* is mocked. (The model is real in live mode and a recorded transcript in gate mode;
all money is fixtures — disclosed.)

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): canonical fields are
`class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with `evidence`
(file:line into the target) and `unlocks` (what gets stronger). **The accept + adversarial paths
live in each probe** (the probe contract: an accept path + a `.trap/` counterexample) and are
specified per-FR in §4 — not in the gap entry. IDs `AGENT-FLIP-*`; `reads: gateway` names the
content-hash rule over the built `auths-mcp-gateway` binary (`auths-mcp` §10). `AGENT-FLIP-1` is the
load-bearing build; reclassify any claim already GREEN at baseline to a `closed` regression guard
(the DOTAK precedent). Probes drive the gateway in **replay mode** over recorded fixtures
(**hermetic, no live money**).

```yaml
- id: AGENT-FLIP-1
  title: "A buy is pre-authorized against the inventory cap (max drawdown) before the rail is touched, and the over-cap buy is never charged"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Drive the flip BUY through the auths-mcp gateway as a metered Stripe-test tools/call: reserve
    the charge amount against the single monotonic cross-rail SETTLED counter (AGT-4/D8
    usage_ledger.rs) keyed to the agent delegation BEFORE Stripe is invoked, settle the actual
    (amount_captured) on the response, release the slack. A buy that would reserve past the cap is
    refused UsageCapExceeded and never settled; the counter is rollback-protected
    (UsageCounterRolledBack). The cap IS the max drawdown.
  unlocks: "Real capital can be delegated to a resale agent with a provable floor under the loss — the floor for FLIP-2..6."
  evidence:
    - "maps AGT-4/D8 (crates/.../usage_ledger.rs reserve→settle) + AGENT-MCP-1 (gateway broker) + AGENT-PAY-1 (Stripe-test cost extraction amount_captured→cents)"
    - "the BUY-as-capital-deployment binding (reserve before the rail is touched) is the flip's load-bearing surface; hermetic over a recorded Stripe TEST-MODE charge fixture — no live money"
  covers: [budget-boundary, capital-cap]
  probe: probes/agent-flip-1.sh

- id: AGENT-FLIP-2
  title: "A buy outside the resale scope is refused OutsideAgentScope before the downstream is called (a resale bot cannot become a withdrawal bot)"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    In auths-mcp-core's per-call gate, map the flip tools (marketplace.buy/list/sell) to capabilities
    and enforce them against the agent's delegator-anchored scope; an out-of-scope call
    (wallet.withdraw / marketplace.transfer) returns OutsideAgentScope naming the capability and is
    NOT forwarded to the downstream.
  unlocks: "Scope (AGT-1) bounds WHAT a capital-deploying agent can do, not just how much — funds-out is not buy-inventory."
  evidence:
    - "maps AGT-1; OutsideAgentScope exists in auths-verifier — this wires it to the flip tool surface"
  covers: [scope-boundary]
  probe: probes/agent-flip-2.sh

- id: AGENT-FLIP-3
  title: "Two-sided commerce on one authority — the inbound x402/USDC sale is metered into the SAME ledger as the outbound Stripe buy, and the cap bounds outbound across both rails"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Extend the cross-rail counter/receipt surface so an INBOUND x402/USDC settlement (a SALE) is
    metered into the SAME delegation ledger as the OUTBOUND Stripe buy — as a credited receipt line —
    so realized margin reconstructs offline. DECIDED: inbound earnings are RECEIPTED into the P&L but
    do NOT silently widen the outbound risk cap (the cap bounds capital DEPLOYED) unless an explicit
    --reinvest policy is set; a forged sale receipt cannot widen the buy cap (the settlement is
    verified from the rail, not asserted by the agent). An over-cap buy is refused on EITHER rail even
    when each per-rail silo reads in-budget.
  unlocks: "ONE authority bounds a live agent's CROSS-RAIL, TWO-SIDED commerce (spend to buy + earn on sale) — the moat a per-rail processor budget cannot express; the verifiable P&L."
  evidence:
    - "maps AGT-4/D8 cross-rail summing + AGENT-PAY-2 (x402 SettlementResponse amount → cents); the INBOUND (earnings) metering into the same ledger is net-new — the core meters outbound spend, not inbound credit"
    - "hermetic over a recorded x402 settlement fixture (network=base-sepolia) + the Stripe buy fixture — no live money; live funded-testnet sale is evidence-only, deferred (AGENT-PAY-2 live flag)"
  covers: [budget-boundary, two-sided-commerce]
  probe: probes/agent-flip-3.sh

- id: AGENT-FLIP-4
  title: "Revocation is an instant clawback — the first buy after a mid-run revoke is refused Revoked with no propagation window"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Re-derive liveness from the KERI registry on every flip tools/call (reuse keri_auth's revocation
    check) so the first BUY after a mid-run revocation event is refused Revoked — no cached token TTL,
    no introspection lag. Revoke = clawback of spend authority on every rail at once.
  unlocks: "OPS-1 instant kill is an instant clawback for a running capital-deploying agent — a bad streak is stoppable in one event."
  evidence:
    - "maps OPS-1; keri_auth.rs already checks revocation on presentation — bind it per buy"
  covers: [revocation-boundary]
  probe: probes/agent-flip-4.sh

- id: AGENT-FLIP-5
  title: "A fleet of flip agents is bounded by one aggregate cap — a sub-agent cannot exceed its slice, and combined fleet spend cannot exceed the developer's total risk"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Sub-delegate N flip agents a budgeted slice each under a root aggregate cap (AGT-5/aggregate +
    AGT-1 attenuation): a sub-agent's buy past its slice is refused UsageCapExceeded (cannot exceed
    its parent), and once combined fleet spend reaches the aggregate cap the next buy by ANY agent is
    refused against the aggregate counter even when that agent's own slice still reads in-budget.
    PARK — do not stub — if the aggregate-counter primitive (AGT-5) is not yet GREEN at baseline.
  unlocks: "A fleet of capital-deploying agents is bounded by your TOTAL risk, attenuably and verifiably — the insurable-fleet story."
  evidence:
    - "maps AGT-5/aggregate (the fleet/aggregate cap) + AGT-1 (sub-delegation/attenuation, AGENT-ATTEN-3 subset rule); the aggregate-across-fleet counter binding may PARK on AGT-5 readiness"
  covers: [budget-boundary, aggregate-cap]
  probe: probes/agent-flip-5.sh

- id: AGENT-FLIP-6
  title: "Every flip leaves a signed, independently-verifiable P&L receipt — and a cooked receipt fails verify"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Emit a signed per-flip receipt for each brokered buy and sale (actor, grant, action, rail,
    amount, verdict, running cross-rail total) that auths verify accepts offline and from which the
    realized margin reconstructs without trusting the marketplace or processor. A receipt edited to
    forge a wider cap, drop the proof, or fabricate a sale amount fails verify — the spend total is
    the verifier-held monotonic counter, not an agent-asserted number.
  unlocks: "The agent's books are cryptographic (a verifiable P&L), not log-scraping — the audit trail an underwriter can price."
  evidence:
    - "maps AGENT-MCP-1 receipts + AGT-4 running total; the per-flip (buy+sale) receipt + offline-reconstructable margin is the flip-specific extension"
  covers: [receipts, verifiable-pnl]
  probe: probes/agent-flip-6.sh
```

---

*Drafted 2026-06-15. A go-to-market agent scenario riding on `prds/go_to_market/auths-mcp-gateway.md`
(the bounded-agent MCP gateway) and the closed primitives `roadmap/aspirational_claims/gaps.yaml`
(AGT-1 scope, AGT-4/D8 cross-rail budget, OPS-1 revocation, AGT-5 aggregate cap). Shipped as example
configs + hermetic probes over the one gateway in `auths-mcp/examples/flip/` — nothing new in
`auths-demos`. House style mirrors `agent_demos/the-intern-that-couldnt`. The honest through-line:
**auths is the safety + the rails, not the alpha** — it makes it safe to delegate real capital to an
agent that runs a resale strategy (cap = max drawdown, custody = the wallet stays out of the agent's
hands, revoke = instant clawback, aggregate cap = a fleet bounded by total risk, receipts = a
verifiable P&L); the agent brings the edge, auths bounds the downside. Surfaces named against
`../auths` @ `dev-privacy`; exact paths pinned during the sculpt. Probes are hermetic over recorded
fixtures — no live money.*
