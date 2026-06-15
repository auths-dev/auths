# PRD: The Arbitrage Agent — delegate real capital, capped at the max you can lose

> **One line:** an autonomous market-making / arbitrage agent is handed a **scoped,
> budget-capped, instantly-revocable delegation** over *real* capital across *multiple
> rails* (fiat ↔ USDC ↔ markets) — and when it captures a spread, the trade rides the
> **auths-mcp gateway**, which custodies the wallet/exchange keys, meters every leg
> against **one cross-rail cap that equals your maximum drawdown**, and emits a **signed
> per-call receipt** that is your verifiable P&L. The agent can spend up to the cap and
> earn over x402 — but it provably cannot exceed the cap, on any rail, and one revoke is
> a clawback that stops it everywhere at once.
>
> **Be honest — auths is the SAFETY + the RAILS, NOT the alpha.** auths does **not** make
> the strategy profitable. The agent brings the alpha (the spread model, the venue
> selection, the timing). auths makes it **safe to delegate real capital** to that agent:
> the **cap is the max drawdown** (a number you choose and the chain enforces), **custody**
> means the agent holds *bounded spend authority*, never your wallet, **instant revoke** is
> the clawback, the **aggregate cap** bounds a whole fleet by your total risk, and the
> **signed receipts** are a P&L anyone can verify offline. If the alpha is zero you lose
> nothing you didn't authorize; if the alpha is real you've delegated it with a seatbelt
> bolted on. That, and only that, is what this PRD claims.
>
> **What this is.** A **go-to-market use case** of the bounded-agent MCP gateway
> (`auths-mcp`, the GTM product): no new engine. This rides the gateway's
> scoped/budget-capped/revocable/custodied delegation, its **cross-rail metering** (Stripe
> test-mode + x402/USDC), the **cross-rail moat** (one cap spanning every rail), the
> **aggregate cap** (a fleet bounded by your total risk), **sub-delegation / attenuation** (a
> sub-strategy gets a provable slice), **signed per-call receipts**, the **custody-broker**
> trust model, and `mode=real|test`. The arbitrage / market-making use case is the *reason a
> developer reaches for it with real money on the line*: the cross-rail capability is
> **directly the enabler** — the spread lives *between* ecosystems, so the agent must act on
> two rails at once, and that is exactly the boundary one auths cap can bound and N siloed
> processor budgets cannot.
>
> **Status — honest:** this use case **rides on already-specified primitives** — it adds
> **no new crypto and no new gateway code**. Its claims map to `auths-mcp`'s
> **AGENT-MCP-3** (one cross-rail cap, pre-authorized, checkpoint-anchored), **AGENT-PAY-1/2**
> (Stripe-test + x402/USDC cost-extraction metered into the *same* cap), **AGENT-PAY-3**
> (`mode=real|test`, the mandatory-cap seatbelt), **AGENT-MCP-4↦OPS-1** (instant revoke), and
> the **attenuation** primitive (AGT-1). What is *new here* is a **profit-direction framing
> and two profit-shaped probes** the gateway PRD doesn't carry: an **inbound earn leg** (the
> agent *earns* over x402, not just spends — the cap bounds *net* exposure) and an
> **aggregate-cap-over-a-fleet** leg (one risk budget across several strategy sub-agents).
> Both are **hermetic, recorded-fixture probes — no live money.** Where a claim is fully
> covered by an existing `auths-mcp` gap, this PRD says so and reclassifies it to a closed
> regression guard at baseline (the DOTAK precedent), never re-implementing it.
>
> **Authoring scope:** READ-ONLY on `../auths`. The recurve loop sculpts the `auths` engine
> crates (`auths-mcp-core`/`auths-mcp-gateway`) and the `auths-mcp` wrapper, exactly as the
> gateway PRD's multi-tree config (§10 there); **nothing lands in `auths-demos`.** Hermetic
> probes drive the gateway in **replay mode** over **recorded settlement fixtures** — no live
> charge, no funded wallet, no real capital.

---

## 1. One line + scenario

A treasury desk (or a solo operator) has capital it would like an agent to put to work
capturing **cross-ecosystem spreads** — fiat ↔ USDC ↔ on-chain/market venues — or
**providing liquidity** (earning the bid-ask + fees). The opportunity is real but
*structurally cross-rail*: the cheap side is on one rail (a Stripe-settled fiat leg, a CEX),
the rich side is on another (an x402/USDC settlement, a DEX). Capturing it means an agent
that can act on **both rails inside one decision** — and that is precisely the thing today's
tooling cannot bound with one number.

**The thing the operator is actually afraid of.** Delegating capital to an autonomous agent
means the agent can move money. The fears are concrete: a buggy or prompt-injected loop
that drains the account; a strategy that quietly runs past its risk budget by **splitting
spend across rails** so each per-rail control still reads "in budget"; a wallet key the agent
holds that leaks; a kill switch that lags long enough for one more catastrophic trade; a P&L
you have to take the agent's (or the venue's) word for. Every one of these is a reason desks
*don't* hand real capital to an LLM-in-a-loop today.

Now insert the **auths-mcp gateway** between the agent and its rails. The operator mints the
agent a delegation: `scope = {stripe.charge, x402.pay, market.quote}`, **`budget = $250`
(= the chosen max drawdown)**, `ttl = 4h`, anchored in the operator's KEL. The agent's MCP
client points at the gateway, which **custodies the exchange API key and the USDC wallet key
while the agent holds only the delegation**. Every leg of every trade — the Stripe-test
charge, the x402/USDC settle, the quote — is intercepted, **reserved against one cross-rail
cap before the rail is touched**, settled at the actual after, and **receipted**. The agent
spends up to `$250` across *all* rails combined; it earns inbound over x402 (an x402 server
*charges* the agent's counterparties, an inbound stream); and it provably **cannot** exceed
the cap on any rail.

**How it breaks today.** A per-rail processor budget (Stripe Issuing spend caps, an exchange
API key with a withdrawal limit) is **siloed per rail**: an agent at `$249` on Stripe *and*
`$249` on x402 has "spent `$0` of its limit" in *each* silo, while it has actually committed
`$498` against a `$250` risk budget — and no per-rail control can see the other rail. API
keys are ambient: the agent that holds the wallet key holds *all* of it, with no cap, no
attenuation, no per-call binding, and a revoke that means "rotate the key and hope." A
human-approval dialog doesn't scale to a strategy that fires every few seconds, leaves no
verifiable P&L, and is exactly what an autonomous desk exists to remove.

**What auths does.** Each trade leg *is* a signed artifact. The gateway resolves the agent's
delegated KEL **and** its delegator's KEL, replays with delegator-aware lookup, reads the
**delegator-anchored scope/budget/expiry seal**, **reserves the leg's cost against the single
cross-rail counter** (`available = cap − settled − Σ holds`), and forwards **only if** the
trade is in scope, would *not* reserve past the cap **on any rail combined**, is unexpired,
and unrevoked — otherwise a distinct fail-closed verdict (`UsageCapExceeded` /
`OutsideAgentScope` / `AgentExpired` / `Revoked`). The `$4.99`-Stripe `+ $0.02`-x402 trade
that two siloed budgets each wave through is **refused**, because under auths it is one
`$5.01` charge against one cap. Every leg — allowed *or* refused — emits a signed receipt:
**that is the verifiable P&L.** And one revoke stops spend on *every* rail at once: the
**clawback**.

---

## 2. The property it proves

**Real capital can be delegated to an autonomous agent because the downside is provably
capped, cross-rail, and instantly revocable — and the P&L is verifiable from the chain
alone, offline.** The agent is free to run whatever cross-ecosystem spread strategy it
likes; the bound is not a processor's siloed limit, not a confirmation dialog, not the
venue's good behaviour, but the same parent→child containment the gateway already enforces —
now expressed as a **single risk budget that equals the operator's maximum acceptable
drawdown** and is enforced **across every rail at once**, before any rail is touched.

**Stated as plainly as the brief demands:** auths is the **safety** (cap = max drawdown;
custody = the agent never holds the wallet, only bounded spend authority; instant revoke =
clawback; aggregate cap = a fleet bounded by your total risk) and the **rails** (cross-rail
metering + x402 inbound earn), **not the alpha**. It does not make the strategy profitable.
It makes it *safe to delegate real capital* to an agent that runs the strategy. The agent
brings the alpha; auths bounds the downside, gives instant clawback, and a verifiable P&L.

**Why the incumbents structurally can't match it:**

| Incumbent | Where the limit lives | Why it can't bound a cross-rail capital agent |
|---|---|---|
| **Per-rail processor budget** (Stripe Issuing caps, an exchange withdrawal limit) | a control inside *one* processor, per card/key | **Siloed per rail.** `$249` on Stripe + `$249` on x402 reads "in budget" in each silo while `$498` of a `$250` risk budget is committed — no per-rail control sees the other rail. Cannot express *one* cap spanning rails. No cryptographic attenuation a non-trusting party can verify; one revoke is per-card, not "everywhere at once." |
| **API key / wallet key in the agent** | nowhere — possession *is* the capital | Ambient, total authority: the agent that holds the key holds all the funds, with no cap, no parent, no attenuation, no per-call binding. A prompt-injected agent drains the wallet. Revoke = rotate the key and hope nothing fired in the window. No verifiable P&L — just logs. |
| **Human-in-the-loop approval** | a person clicking "allow" | Doesn't scale to a strategy firing every few seconds; not cryptographic; leaves no verifiable receipt; and is exactly what an autonomous desk exists to remove. Approval ≠ a cap, ≠ a clawback, ≠ a P&L. |

None lets a **non-trusting party** (an underwriter, a treasury risk officer, a fund LP),
offline, prove from signatures alone that *this* agent's committed exposure is within a
single risk budget its principal anchored — across every rail — and be clawed back with no
window. That is what makes a fleet of strategy agents *insurable*: an underwriter can price
"a sub-strategy provably cannot exceed its slice on any rail, and one revoke stops the fleet"
— they cannot price "we configured a per-rail limit correctly in three processors we don't
control." auths is the substrate that turns "delegate capital to an agent" from a leap of
faith into a **bounded, verifiable, clawback-able** position.

---

## 3. Goals — what makes it believable

- **G1 — The cap is the max drawdown, and it is one number across all rails.** A single
  `budget = $250` anchored in the operator's KEL bounds the agent's *combined* committed
  exposure across a Stripe-test rail **and** an x402/USDC rail. The visceral proof: a trade
  that is in-budget on each rail *separately* but over-budget *combined* is **refused**
  (`UsageCapExceeded`) before either rail is touched. (Rides **AGENT-MCP-3 / AGENT-PAY-1/2**.)
- **G2 — The agent never holds the wallet — only bounded spend authority.** The gateway
  **custodies** the exchange key and the USDC wallet key; the agent holds only its
  scoped/capped/revocable delegation. A prompt-injected agent that points straight at the raw
  rail **has no credential** and the leg fails. Custody = the agent can't drain what it never
  held (the §12 custody-broker, applied to capital).
- **G3 — One revoke is a clawback that stops spend everywhere at once.** The operator hits
  revoke mid-strategy; the **very next** trade leg — on *any* rail — is refused `Revoked`, no
  token-TTL window, no key-rotation race. (Rides **AGENT-MCP-4 ↦ OPS-1**.)
- **G4 — The agent can EARN, not just spend (the inbound leg).** x402 is pay-*per-request*:
  an x402 server the agent operates *charges* its counterparties (inbound USDC), so the agent
  runs an inbound stream while its outbound spend stays capped. The receipts carry **net**
  flow (inbound − outbound), and the cap bounds *outbound exposure* — proving auths bounds a
  *profit center*, not a cost center. (New profit-direction probe; hermetic.)
- **G5 — A fleet is bounded by your total risk (the aggregate cap).** Several strategy
  sub-agents, each handed a **provable slice** of one parent risk budget via
  sub-delegation/attenuation, **cannot in aggregate exceed the parent cap** — the slices sum
  to the whole and the chain enforces it. One revoke at the parent stops the whole fleet.
  (New aggregate-cap probe over the attenuation primitive; hermetic.)
- **G6 — The receipt is the P&L.** Every leg (allowed *or* refused) emits a signed,
  independently-verifiable receipt — who traded, under which grant, on what rail, for how
  much, with what verdict — replayable offline with `auths verify`. The audit trail is
  cryptographic, not exchange-statement scraping.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an **adversarial
twin (fail-closed)**. The accept + adversarial paths **live in each probe** (the probe
contract); they are specified here per-FR and named, not duplicated, in §9. IDs `AGENT-ARB-*`.
Most FRs **ride an already-specified `auths-mcp` primitive** and are noted as such — where a
claim is *fully* covered by an existing gateway gap, it is a **closed regression guard at
baseline** (the DOTAK precedent), not new code. **FR-1 is the load-bearing framing build;
FR-4 and FR-5 are the net-new profit-shaped probes.** All probes are **hermetic** (recorded
settlement fixtures, replay mode, no live money).

- **FR-1 — One cross-rail cap = the max drawdown bounds a trade that splits across rails (THE
  FRAMING BUILD).** *Rides: AGENT-MCP-3 + AGENT-PAY-1/2 (Stripe-test + x402/USDC into the same
  `CrossRailBudget`).* The agent holds `budget = $5.00` (standing in for the operator's chosen
  max drawdown) and trades across a Stripe-test rail and an x402/USDC rail.
  - **Observable (accept):** a trade whose *combined reserved* cost across both rails is ≤ $5
    passes and settles; each receipt carries the running **cross-rail** total and `rail=`.
  - **Adversarial twin:** the trade that would *reserve past* $5 **combined** — e.g.
    `$4.99`-on-Stripe `+ $0.02`-on-x402 — is refused **`UsageCapExceeded`** and **never
    settled** (the reservation fails before the rail is touched), *even though two siloed
    per-rail budgets each still read "$0 spent."* The counter is monotonic — a replayed/lower
    settled total is rejected `UsageCounterRolledBack`.

- **FR-2 — The agent never holds the rail credential (custody = unbypassable cap).** *Rides:
  §12 custody-broker.* The gateway custodies the exchange key + the USDC wallet key; the agent
  holds only the delegation.
  - **Observable (accept):** an in-scope, in-budget trade leg round-trips through the gateway
    to the (recorded) rail and returns a result + receipt.
  - **Adversarial twin:** a trade leg that bypasses the gateway (points at the raw rail) has
    **no credential** and fails — the agent cannot move capital it was never custodied for;
    and a forged proof is rejected **at the boundary before the rail is invoked** (the rail is
    never touched on a bad proof).

- **FR-3 — Instant revoke is a cross-rail clawback (no window).** *Rides: AGENT-MCP-4 ↦
  OPS-1.* The operator revokes the agent's delegation mid-strategy.
  - **Observable (accept):** trade legs before revocation pass.
  - **Adversarial twin:** the **very next** leg after the revocation event — on *either* rail
    — is refused **`Revoked`**; no token still valid for its TTL, no key-rotation race, no
    introspection lag. Liveness is re-derived from the chain on every leg.

- **FR-4 — The agent EARNS inbound over x402, and the cap bounds NET exposure (THE PROFIT
  LEG — NEW).** *Maps: a new profit-direction probe over the x402 metering surface (extends
  AGENT-PAY-2's cost-extraction to the inbound/credit direction).* The agent operates an x402
  endpoint that **charges its counterparties** (inbound USDC settlements) while it also spends
  outbound; the budget bounds **outbound committed exposure**, and the receipt ledger carries
  **net** flow.
  - **Observable (accept):** over a recorded transcript of N inbound x402 settlements and M
    outbound legs, the receipt ledger reports a correct **net** (inbound − outbound) and the
    **outbound** total is `≤ cap`; an inbound settlement **credits the P&L** (it does not
    consume the outbound cap) and is metered with `direction=inbound`, `rail=x402`.
  - **Adversarial twin:** an *outbound* leg that would reserve past the cap is still refused
    **`UsageCapExceeded`** — inbound earnings **do not silently raise the outbound cap** (the
    cap is the *max drawdown* obligation, not net worth); and a transcript edited to re-label
    an outbound spend as inbound (to dodge the cap) is rejected because direction is read from
    the *signed* settlement artifact, not asserted by the agent.

- **FR-5 — An aggregate cap bounds a fleet of strategy sub-agents (THE FLEET LEG — NEW).**
  *Maps: a new aggregate-cap probe over the sub-delegation/attenuation primitive (AGT-1) +
  the cross-rail counter (AGENT-MCP-3).* A parent risk budget `= $5` is sub-delegated as
  provable slices to several strategy sub-agents (e.g. `$3` + `$2`); slices sum to the parent.
  - **Observable (accept):** each sub-agent trading within its slice passes; the **sum of the
    sub-agents' committed exposure ≤ the parent cap**, verifiable from the chain; a sub-agent's
    slice is itself cross-rail (Stripe + x402 against *its* slice).
  - **Adversarial twin:** a sub-agent attempting to delegate or spend *more than its slice* is
    refused (subset rule at issuance / `UsageCapExceeded` at verify) — a child cannot exceed
    its parent; and the **aggregate** is refused once the *combined* fleet spend would exceed
    the parent cap, even if each sub-agent is individually under its own slice (the slices were
    provably issued to sum to the whole). One revoke at the parent refuses the **next leg of
    every sub-agent**.

- **FR-6 — Real money is the default; the cap is a mandatory seatbelt; the mode is disclosed.**
  *Rides: AGENT-PAY-3.* The capital use case is the one that most needs real-by-default with a
  mandatory cap.
  - **Observable (accept):** the `wrap --show-mode` resolve-and-disclose dry-run reports
    `mode=real` with **no flag** (Stripe live / x402 base-mainnet expected) and `mode=test`
    under `--test-mode`; a wrap *with* a `--budget` is accepted; the receipt carries
    `mode=real|test`.
  - **Adversarial twin:** a wrap of a payment rail **without `--budget`** is refused
    `budget-required` in **both** modes — for a capital agent the cap (= max drawdown) can
    **never** be silently skipped; and a real-mode wrap that emits no `mode=` field is rejected
    (real money is never silent). *(Hermetic: reads the dry-run / disclosure surface, never a
    live charge.)*

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy` and against the `auths-mcp` gateway PRD (whose engine
crates this use case consumes). Exact paths pinned during the sculpt (this PRD is read-only).
**This use case adds NO new engine and NO new gateway transport — it consumes the gateway and
adds two profit-shaped probes + the capital framing.**

### Exists — the primitives this use case rides (closed or specified in `auths-mcp`)
- **`auths/crates/auths-mcp-core` (the per-`tools/call` gate)** — scope ⊆ parent (AGT-1),
  quantitative **cross-rail budget** (AGENT-MCP-3 / D8), expiry with injected `now`,
  revocation (OPS-1), and a **signed per-call receipt**. The trade-leg cap, custody check, and
  receipt are *exactly* this gate; a trade leg is just a `tools/call`.
- **`auths/crates/auths-mcp-core/budget.rs` — `CrossRailBudget`** (D8): one monotonic
  **settled** counter keyed to the agent delegation + a transient **reserved**-holds set;
  `available = cap − settled − Σ holds`; rollback-protected (`UsageCounterRolledBack`);
  checkpoint-anchored (no per-call chain write). The cross-rail cap *is* the max-drawdown cap.
- **Rail cost-extraction adapters** — **AGENT-PAY-1** (Stripe-test charge → `amount_captured`
  cents, reserve/settle into the cap) and **AGENT-PAY-2** (x402/USDC settlement →
  `maxAmountRequired` atomic-USDC→cents, summed into the **same** cap). The arbitrage legs are
  these two adapters; `auths-mcp-core` holds **zero payment code** (rails are wrapped
  downstreams).
- **`mode=real|test` + the mandatory-cap seatbelt** — **AGENT-PAY-3**: real money is the
  default, `--budget` is required to wrap a payment rail, the mode is disclosed.
- **Sub-delegation / attenuation** — `id agent add --scope --expires-in` →
  `auths_sdk::domains::agents::add_scoped` (delegator-anchored seal; subset rule, hardened by
  the attenuation work). A strategy sub-agent's slice is a sub-delegation; the cap slice rides
  the same containment.
- **Instant revoke** — the OPS-1 revocation path, re-derived from the KERI registry on every
  leg (no token-TTL window). The clawback.
- **Signed receipts + `auths verify`** — the gateway's per-call receipt, independently
  verifiable offline. The verifiable P&L.
- **The live/replay harness + replay-mode probe entrypoint** — the gateway's `run.sh`
  (`--check` = hermetic replay over a frozen transcript). The capital scenarios are *configs*
  over this one gateway.

### Build — what is net-new for THIS use case (small; rides the gateway)
1. **Two profit-shaped, hermetic probes** the gateway PRD does not carry:
   - **FR-4 — the inbound/earn + net-exposure probe** (`AGENT-ARB-NET-1`): assert the receipt
     ledger reports a correct **net** (inbound − outbound) over a recorded transcript and that
     **inbound x402 credits do not raise the outbound cap**; direction is read from the signed
     settlement artifact. A thin extension of AGENT-PAY-2's cost-extraction to the *credit*
     direction + a net-rollup over receipts. *No new crypto.*
   - **FR-5 — the aggregate-cap-over-a-fleet probe** (`AGENT-ARB-AGG-1`): assert several
     strategy sub-agents' **combined** committed exposure ≤ the parent cap from the chain, and
     that one parent revoke refuses the next leg of every sub-agent. A rollup over the existing
     attenuation + cross-rail-counter surfaces. *No new crypto.*
2. **The capital scenario configs + recorded fixtures** in `auths-mcp/examples/arbitrage/`
   (the product's own examples — **not** `auths-demos`): a `treasury-rebalance.config`
   (cross-rail cap = max drawdown), a `market-maker.config` (inbound x402 earn + capped
   outbound), a `fleet.config` (aggregate cap over sub-agents), each ~20 lines over the one
   gateway, plus the recorded Stripe-test + x402/USDC settlement fixtures the probes replay.
3. **The capital framing in docs/run.sh narration** — the dramaturgy (§7) and the honest
   "auths is the safety + rails, not the alpha" framing, threaded into the gateway's existing
   `examples/payments` story as the *capital-delegation* lens.

Any surface that already suffices at baseline → reclassified to a **closed regression guard**
(the DOTAK precedent), never re-implemented. If a probe turns out already-GREEN on the current
checkout (because the gateway primitive fully covers it), it is a regression guard, not a
build.

---

## 6. Non-goals

- **NOT alpha. NOT a trading strategy. NOT a profitability claim.** auths supplies the
  **safety + the rails**, never the edge. This PRD asserts *bounded downside, instant
  clawback, verifiable P&L, cross-rail metering* — it asserts **nothing** about whether the
  strategy makes money. The agent brings the alpha; if there is none, the cap still holds and
  you lose only what you authorized.
- **NOT high-frequency / microsecond arbitrage — and this is a real limit, stated plainly.**
  An LLM-in-a-loop, with a per-call sign+verify and a network round-trip, is **far too slow**
  for HFT or latency-sensitive market-making where the edge decays in microseconds. This use
  case is for **slower cross-ecosystem spreads, treasury rebalancing, and liquidity provision
  on horizons of seconds-to-minutes** where the spread persists long enough for an agentic
  loop and the *bounding* (not the speed) is the value. Anyone pitching this for HFT is
  misrepresenting it.
- **NOT a payment processor, wallet, exchange, or custodian of funds.** auths-mcp *bounds*
  spend, *custodies the credential* (so the agent never holds the wallet), and emits receipts
  — it **never holds or settles funds**. Settlement is the rail's job. The "custody" here is
  *credential* custody (the key), not *fund* custody.
- **NOT a regulatory or compliance clearance — and the regulatory exposure is real.** Running
  an agent that moves real capital across rails can implicate money-transmission, securities,
  market-manipulation, KYC/AML, and tax-reporting obligations that **vary by jurisdiction and
  by what the agent trades**. auths gives you a *verifiable audit trail and a hard cap*, which
  **help** a compliance posture — but they are **not** legal cover, not a license, and not
  advice. The operator is responsible for the legality of the strategy; this PRD makes no
  claim that auths makes any trade lawful.
- **NOT live money in the probes.** Following the gateway's hermetic stance: the gate runs a
  **recorded transcript** over **recorded Stripe-test + x402/USDC settlement fixtures** — no
  live charge, no funded testnet wallet, no real capital. The live leg (a real charge, a
  funded base-sepolia wallet) is **evidence-only, deferred** (the gateway's D7 / AGENT-PAY-2
  live-scope flag).
- **NOT a new gateway or a fork of it.** This is a *use case* of `auths-mcp` — configs +
  two probes + framing. No new engine crate, no new transport, no protocol change.
- **NOT a perf claim.** Per-leg sign+verify latency is noted (and is exactly why this is
  not HFT); the property is *correctness of the cross-rail bound + the clawback + the P&L*,
  not milliseconds.
- **NOT a hosted multi-tenant service.** Local/self-hosted gateway, agent-owner-run (you bound
  *your own* capital fleet — the §12 primary deployment). Hosted is separate.

---

## 7. The narrative / run.sh dramaturgy

A scenario suite over the **one** `auths-mcp` gateway, shipped in
`auths-mcp/examples/arbitrage/` (the product's own examples, **not** `auths-demos`).
`./run.sh` (the live show), `./run.sh --check` (the hermetic gate / probe entrypoint over the
recorded fixtures), `./run.sh reset`. Auto/non-TTY plays itself. The live leg is
evidence-only; the gate runs the recorded transcript.

- **Act 0 — The fear, named.** Open on the honest fear: *delegating capital to an autonomous
  agent means it can move your money.* State the one honesty up front: **auths is the safety +
  the rails, not the alpha** — the agent brings the edge, auths bounds the downside. Disclose:
  in the gate, the transcript and settlement fixtures are recorded; no live money.
- **Act 1 — The grant = the max drawdown.** The operator mints the agent
  `--scope stripe.charge,x402.pay,market.quote --budget $5 --ttl 4h` and **wraps the rails
  through the gateway, which custodies the exchange key + the USDC wallet key.** Show
  `mode=test` (the opt-in) on screen, and that the wrap **refuses without `--budget`**: the
  cap is the seatbelt. Pledge: *"$5 is the most this agent can lose. Watch."*
- **Act 2 — The agent captures a spread, cross-rail — verified + receipted.** The agent buys
  cheap on the Stripe-test rail and sells rich on the x402/USDC rail inside one decision; each
  leg is reserved against the **one** cap, settled, and **receipted**. Print the running
  **cross-rail** total and `auths verify` of a receipt. Framing: *every leg is bounded and
  receipted from the chain, not from the agent's word.*
- **Act 3 — The split-rail overspend (the moat).** The agent tries the trade that is in-budget
  on each rail *separately* but over-budget *combined* — `$4.99`-Stripe `+ $0.02`-x402.
  **Pledge before proof:** *"Two siloed processor budgets each say '$0 spent.' Under one auths
  cap this is $5.01. Expect refusal — before either rail is touched."* → **`UsageCapExceeded`**,
  no settlement. The unsee-able beat: *one cap saw both rails.*
- **Act 4 — The agent earns (the inbound leg).** Flip to the market-maker config: the agent's
  x402 endpoint **charges counterparties** (inbound USDC) while its outbound stays capped.
  Print the **net** P&L (inbound − outbound) from the receipts, and show that **inbound
  earnings do not raise the outbound cap** — the cap is the max-drawdown obligation, not net
  worth. Framing: *auths bounds a profit center; x402 lets the agent earn, not just spend.*
- **Act 5 — The fleet, bounded by total risk (the aggregate cap).** Sub-delegate the `$5`
  parent budget as provable slices (`$3` + `$2`) to two strategy sub-agents. Show each trading
  within its slice; show the **aggregate** refused once the *combined* fleet spend would exceed
  the parent cap; show a sub-agent **cannot** widen its slice (subset rule). *One risk budget,
  a whole fleet.*
- **Act 6 — The clawback.** Mid-strategy, the operator hits **revoke** at the parent. The
  **very next** leg of **every** sub-agent — on **every** rail — is refused **`Revoked`**. No
  window, no key rotation. Close on the line: **"Every trade here was the agent's own
  decision. The cap, the clawback, and the P&L came from the chain — offline, per leg, with a
  receipt — not from a processor we don't control. auths didn't make the strategy profitable.
  It made it safe to find out with real money. That is the boundary no per-rail budget can
  hold."**

The climax is Act 3 (the split-rail overspread refused by one cap) and Act 6 (the
cross-rail clawback) — the two moments a per-rail processor budget *structurally cannot*
produce.

---

## 8. Success metrics

The show and the probes assert these verdicts (not timings); every verdict is produced by
real `auths-mcp-core` / `auths-verifier` code over real KEL/TEL events, every rail result is
a recorded settlement fixture (hermetic).

- **M1 (cross-rail cap = max drawdown):** with one `$5` cap spanning Stripe-test and x402, a
  trade that would *reserve past* it **combined** is refused `UsageCapExceeded` before either
  rail is touched; the **combined** running total is in each receipt (FR-1). *Two siloed
  budgets each read "$0."*
- **M2 (custody = unbypassable):** an in-bounds leg round-trips; a bypass-the-gateway leg has
  **no credential** and fails; a forged proof is refused **before the rail is invoked** (FR-2).
- **M3 (clawback, no window):** the first leg on *any* rail after a mid-strategy revoke is
  refused `Revoked` (FR-3).
- **M4 (the agent earns; net exposure):** the receipt ledger reports a correct **net**
  (inbound − outbound); inbound x402 credits **do not** raise the outbound cap; a relabeled
  spend is rejected because direction is read from the signed artifact (FR-4). *auths bounds a
  profit center.*
- **M5 (aggregate cap over a fleet):** several sub-agents' **combined** committed exposure ≤
  the parent cap from the chain; a sub-agent cannot exceed its slice; one parent revoke
  refuses the next leg of every sub-agent (FR-5).
- **M6 (real-by-default + mandatory cap + disclosed mode):** `wrap --show-mode` resolves
  `mode=real` with no flag and `mode=test` under `--test-mode`; a payment-rail wrap **without
  `--budget`** is refused `budget-required` in both modes; the receipt carries `mode=`
  (FR-6).
- **M0 (the meta-metric):** an operator can delegate **real capital** to an autonomous agent
  with the downside **provably capped at a chosen max drawdown across every rail**, an
  **instant cross-rail clawback**, and a **verifiable P&L** — the bar that turns "delegate
  capital to an agent" from a leap of faith into an insurable, bounded position.

Nothing about the *enforcement* is mocked; the alpha is not claimed; the money in the gate is
recorded fixtures, disclosed.

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): canonical
fields `class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with
`evidence` (file:line into the target) and `unlocks` (what gets stronger). The **accept +
adversarial paths live in each probe** (specified per-FR in §4) — *not* in the gap entry. IDs
`AGENT-ARB-*`; `reads: gateway` names a content-hash rule over the built `auths-mcp-gateway`
binary (the gateway PRD's §10). Probes drive the gateway in **replay mode over recorded
settlement fixtures** (hermetic — no live money). Most entries **ride an already-specified
`auths-mcp` gap**; reclassify any claim already GREEN at baseline (because the gateway
primitive fully covers it) to a `closed` regression guard (the DOTAK precedent). The two
**net-new** builds are `AGENT-ARB-NET-1` (the earn/net-exposure leg) and `AGENT-ARB-AGG-1`
(the aggregate-cap-over-a-fleet leg).

```yaml
- id: AGENT-ARB-1
  title: "One cross-rail cap = the max drawdown bounds a trade that splits across Stripe-test and x402/USDC"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Wire the arbitrage cross-rail scenario as a config over the gateway's CrossRailBudget
    (auths-mcp-core/budget.rs): one cap spanning a Stripe-test rail (AGENT-PAY-1 cost
    extraction) and an x402/USDC rail (AGENT-PAY-2) summed into the SAME counter. A trade
    that would reserve PAST the cap COMBINED (e.g. $4.99-Stripe + $0.02-x402) is refused
    UsageCapExceeded before either rail is touched, even though each siloed per-rail budget
    reads "$0 spent". Rides AGENT-MCP-3 + AGENT-PAY-1/2 — reclassify to a closed regression
    guard if those fully cover it at baseline.
  unlocks: "The capital agent's downside is provably bounded by one max-drawdown cap across every rail — the moat a per-rail processor budget cannot express (§2)."
  evidence:
    - "rides auths-mcp AGENT-MCP-3 (cross-rail cap) + AGENT-PAY-1/2 (Stripe-test + x402 metered into the same CrossRailBudget); no new crypto — a scenario config + recorded fixtures over the existing counter"
    - "hermetic over recorded Stripe-test charge + x402/USDC settlement fixtures (the gateway's documented shapes) — no live charge, no funded wallet"
  covers: [budget-boundary]
  probe: probes/agent-arb-1.sh

- id: AGENT-ARB-2
  title: "Custody — the agent never holds the rail credential, so the cap is unbypassable by construction"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Exercise the custody-broker (§12) for capital: the gateway custodies the exchange key +
    USDC wallet key, the agent holds only the delegation. An in-bounds leg round-trips; a
    bypass-the-gateway leg has NO credential and fails; a forged proof is refused at the
    boundary BEFORE the rail is invoked. Rides the existing custody/presentation-verify
    surface — reclassify to a closed regression guard if fully covered at baseline.
  unlocks: "The agent cannot move capital it was never custodied for — custody makes the cross-rail cap unbypassable, not trust in the model (G2, §12)."
  evidence:
    - "rides auths-mcp §12 custody-broker + AGENT-MCP-1/2 (boundary refusal before the downstream is touched); no new code — a capital-framed probe over the custodied-credential path"
    - "hermetic — recorded rail fixtures; the bypass leg fails on absent credential, the forged proof is refused pre-invoke"
  covers: [custody-boundary]
  probe: probes/agent-arb-2.sh

- id: AGENT-ARB-3
  title: "Instant revoke is a cross-rail clawback — the next leg on any rail is refused with no window"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Apply OPS-1 revocation to the capital scenario: the operator revokes the agent's
    delegation mid-strategy; the VERY NEXT trade leg on EITHER rail is refused Revoked — no
    token-TTL window, no key-rotation race, liveness re-derived from the KERI registry per
    leg. Rides AGENT-MCP-4 ↦ OPS-1 — reclassify to a closed regression guard if fully covered.
  unlocks: "One revoke stops spend on every rail at once — the clawback a per-card/per-key limit cannot give (G3, §11)."
  evidence:
    - "rides auths-mcp AGENT-MCP-4 (instant mid-session revoke, no window) ↦ OPS-1; no new code — a capital-framed cross-rail revoke probe"
    - "hermetic — recorded transcript; the post-revoke leg on each rail is refused Revoked"
  covers: [revocation-boundary]
  probe: probes/agent-arb-3.sh

- id: AGENT-ARB-NET-1
  title: "The agent EARNS inbound over x402 and the cap bounds NET outbound exposure (the profit leg — NEW)"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Extend the x402 cost-extraction (AGENT-PAY-2) to the CREDIT direction: from a recorded
    x402 inbound settlement response, extract the received amount and record it as an INBOUND
    credit (direction=inbound, rail=x402) in the receipt ledger WITHOUT consuming the outbound
    CrossRailBudget; roll up a NET (inbound − outbound) over receipts. An inbound credit MUST
    NOT raise the outbound cap (the cap is the max-drawdown obligation, not net worth), and
    direction is read from the SIGNED settlement artifact (a relabeled outbound→inbound is
    rejected). Net-new over the gateway: the inbound/credit direction + the net rollup; NO new
    crypto.
  unlocks: "auths bounds a PROFIT center, not a cost center — x402 lets the agent earn an inbound stream while outbound stays capped; the cap bounds net exposure (G4, the revenue framing)."
  evidence:
    - "auths-mcp AGENT-PAY-2 extracts the x402 amount in the SPEND direction only; the inbound/credit direction + the net-exposure rollup over receipts are NOT built"
    - "hermetic over a recorded x402 INBOUND settlement fixture + an outbound transcript — no funded wallet, no live x402 call; the live earn leg is evidence-only, deferred"
  covers: [budget-boundary]
  probe: probes/agent-arb-net-1.sh

- id: AGENT-ARB-AGG-1
  title: "An aggregate cap bounds a fleet of strategy sub-agents — combined exposure ≤ parent cap, one revoke stops all (the fleet leg — NEW)"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the aggregate-cap rollup over sub-delegation/attenuation (AGT-1) + the cross-rail
    counter (AGENT-MCP-3): sub-delegate a parent risk budget as provable slices ($3 + $2) to
    several strategy sub-agents; assert from the chain that the SUM of the sub-agents'
    committed exposure ≤ the parent cap, that a sub-agent cannot widen its slice (subset rule
    at issuance / UsageCapExceeded at verify), that the AGGREGATE is refused once combined
    fleet spend would exceed the parent cap (even if each is individually under its slice),
    and that one parent revoke refuses the next leg of EVERY sub-agent. Net-new over the
    gateway: the cross-sub-agent aggregate rollup; NO new crypto.
  unlocks: "A whole fleet is bounded by your TOTAL risk — the aggregate cap that makes a fleet of strategy agents insurable (G5, the revenue framing)."
  evidence:
    - "rides AGT-1 attenuation (delegator-anchored subset, add_scoped) + AGENT-MCP-3 cross-rail counter; the cross-SUB-AGENT aggregate rollup (Σ slices ≤ parent, fleet-wide revoke) is NOT built"
    - "hermetic — recorded transcripts per sub-agent + the parent revoke; the aggregate is asserted from the chain, no live money"
  covers: [budget-boundary]
  probe: probes/agent-arb-agg-1.sh

- id: AGENT-ARB-MODE-1
  title: "Real money is the default, the cap is a mandatory seatbelt, and the mode is disclosed — for a capital agent"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Exercise AGENT-PAY-3 for the capital scenario over the wrap --show-mode resolve-and-
    disclose dry-run: no flag → mode=real (Stripe live / x402 base-mainnet expected),
    --test-mode → mode=test; a payment-rail wrap WITHOUT --budget is refused budget-required
    in BOTH modes (for a capital agent the cap = max drawdown can never be skipped); the
    receipt carries mode=real|test. Rides AGENT-PAY-3 — reclassify to a closed regression
    guard if fully covered at baseline.
  unlocks: "An operator delegating real capital defaults to real money safely — the cap is a mandatory seatbelt and the mode is never silent (G1/FR-6, §11)."
  evidence:
    - "rides auths-mcp AGENT-PAY-3 (inverted mode default + mandatory-cap + disclosure); no new code — a capital-framed probe over the --show-mode dry-run surface"
    - "hermetic — reads the resolve+disclose dry-run / disclosure shapes, never a live charge"
  covers: [budget-boundary]
  probe: probes/agent-arb-mode-1.sh
```

---

*Drafted 2026-06-15. A go-to-market **use case** of `prds/go_to_market/auths-mcp-gateway.md`
(the bounded-agent MCP gateway) — it adds no new engine, riding the gateway's cross-rail cap
(AGENT-MCP-3 / D8), the Stripe-test + x402/USDC rail adapters (AGENT-PAY-1/2), `mode=real|test`
(AGENT-PAY-3), instant revoke (AGENT-MCP-4 ↦ OPS-1), the custody-broker (§12), and the
attenuation primitive (AGT-1); it contributes two net-new profit-shaped probes
(`AGENT-ARB-NET-1` earn/net-exposure, `AGENT-ARB-AGG-1` aggregate-cap-over-a-fleet) and the
capital-delegation framing. Honest throughout: **auths is the safety + the rails, not the
alpha** — it bounds the downside at a chosen max drawdown across every rail, gives an instant
cross-rail clawback, and a verifiable P&L; it does not make the strategy profitable.
Deliberately **not** for HFT (an LLM-in-a-loop is too slow — this is for slower
cross-ecosystem spreads, treasury rebalancing, and liquidity provision), with the regulatory
exposure stated plainly (§6). Probes are hermetic (recorded Stripe-test + x402/USDC settlement
fixtures, replay mode); no live money, no funded wallet — the live charge / funded base-sepolia
leg is evidence-only, deferred (the gateway's D7 / AGENT-PAY-2 live-scope flag). House style
mirrors `agent_demos/the-intern-that-couldnt`; surfaces named against `../auths` @
`dev-privacy` and the `auths-mcp` gateway PRD; exact paths pinned during the sculpt. Nothing
lands in `auths-demos`.*
