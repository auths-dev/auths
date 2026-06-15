# PRD: The Autonomous Merchant — a dropshipping agent you can hand real capital, because the downside is capped

> **One line:** a fully-autonomous merchant agent runs the whole order loop — inbound
> customer order (Stripe) → outbound supplier purchase (Stripe/USDC) → keep the margin —
> and you delegate it **real spend authority** without it being able to drain you, because
> the supplier-spend cap *is* the max drawdown, the agent never holds your wallet (only a
> bounded spend authority you custody), one revoke is an instant clawback, and every order
> leaves a signed, independently-verifiable P&L receipt.
>
> **What this proves — and what it does NOT.** auths is the **safety + the rails, NOT the
> alpha.** It does not make a dropshipping business profitable — the *agent* brings the
> alpha (sourcing, pricing, the order stream). auths makes it **safe to delegate real
> capital** to an agent that runs that strategy: it bounds the downside to a number you
> chose, gives you instant clawback, and produces a P&L anyone can verify offline from the
> chain. The recurring revenue is the order stream; the unlock is that a bounded delegation
> is what lets a fully-autonomous merchant run *at all* without the supplier side being a
> drain vector.
>
> **What this rides on.** This is a go-to-market *use case* of the bounded-agent gateway
> (`auths-mcp-gateway.md`): scoped + budget-capped + revocable + custodied delegation,
> **cross-rail metering** (Stripe + x402/USDC under one cap), the cross-rail moat, the
> aggregate fleet cap, sub-delegation/attenuation, signed per-call receipts, the
> **custody-broker** trust model, and `mode=real|test`. It adds **no new crypto** — it is
> the merchant-shaped instantiation of those primitives.
>
> **Honest scope.** A hermetic demo: recorded Stripe-test + x402/USDC-testnet fixtures, no
> live money in the gate. The agent's order-loop *intents* are scripted (or a real model in
> the evidence-only live leg); every delegation, cap reservation, settlement, revocation,
> and receipt is real auths code over real KEL/TEL events. **Authoring scope:** READ-ONLY
> on `../auths`. The recurve loop sculpts the engine crates to turn these gaps GREEN; the
> probes drive the gateway in replay mode. Nothing lands in `auths-demos`.

---

## 1. One line + scenario

A solo operator wants to run a dropshipping store but never touch an order. They stand up
an **autonomous merchant agent**: it lists products, takes customer orders, buys the
matching item from a supplier, ships it, and keeps the spread. The business is a stream —
*recurring revenue*, order after order, with no human in the loop per sale.

The whole reason this is unthinkable today is the **supplier side**. To let an agent buy
from suppliers autonomously, you must hand it a way to spend money. Hand it your card / a
Stripe key / a funded wallet and a buggy, prompt-injected, or over-eager agent can **drain
you** — buy 10,000 units, pay a phantom supplier, loop a paid API until the account is
empty. The customer side is comparatively safe (money flows *in*); the supplier side is
where an autonomous agent becomes an existential liability. So operators either don't
automate it, or they babysit every purchase — which defeats the point.

Now insert the **auths gateway** between the merchant agent and its rails. The operator —
the human owner — mints the agent a **delegation**: `scope = {stripe.charge.read,
supplier.purchase}`, `budget = $X across all rails`, `ttl`, anchored in the owner's KEL.
Critically, the gateway is a **custody broker**: it holds the supplier-side credentials
(the Stripe key that pays suppliers, the USDC wallet key); the agent holds **only** its
bounded delegation. Customer payments accrue to the **owner's** custody, never the
agent's. So the agent can run the full loop — read the inbound order, reserve the supplier
cost against its cap, settle the purchase, keep the margin in the owner's account — but it
**cannot spend a cent past the cap on any rail**, and the owner can revoke it mid-stream.

Then the realistic failure, *driven by the agent itself*: mid-loop the agent decides to
buy more than it sold (a runaway reorder), or to pay a supplier on a *second* rail to dodge
a per-rail limit, or it keeps trying after the owner hit "kill." **Every signature is
valid. Every Stripe/x402 envelope is well-formed. It is trying to spend more than its
parent ever anchored — so the gateway refuses, from the chain alone, offline,** with a
distinct verdict (`UsageCapExceeded` / `OutsideAgentScope` / `Revoked`), and the supplier
is **never charged** because the reservation fails *before* the rail is touched.

**How it breaks today.** To automate supplier purchasing you give the agent a payment
credential, and a payment credential is ambient authority: a Stripe secret key or a funded
wallet is *all-or-nothing*. Stripe Issuing can put a per-card cap on, but that's **one
silo** — the agent at `$4.99` on the card *and* `$4.99` on a USDC wallet has "spent $0 of
$5" in each, while it has actually spent `$9.98`. Revocation of an API key lags (rotate +
propagate); a wallet key, once leaked to a prompt-injected agent, is gone. And none of it
produces a P&L an underwriter — or you — can verify without trusting the processor's
dashboard.

**What auths does.** The supplier purchase *is* a signed artifact. The gateway resolves
the agent's delegated KEL **and** the owner's KEL, replays with delegator-aware lookup,
reads the **delegator-anchored scope/budget/expiry seal**, reserves the cost against **one
cross-rail counter** before the rail is touched, and forwards only if it's inside scope,
inside the *combined* budget, unexpired, and unrevoked. The cap *is* the max drawdown. The
agent never held your wallet. One revoke is the clawback. Every order — sale and purchase
— leaves a signed receipt that reconstructs the P&L offline.

---

## 2. The property it proves

**You can delegate REAL capital to a fully-autonomous merchant agent because the downside
is provably capped — by construction, offline, per call, across every rail.** The bound is
not a dashboard limit you trust the processor to honor, not a confirmation dialog, not the
agent's good behaviour: it is the same parent→child containment the wedge proves, applied
to the artifact that actually moves money (the supplier purchase). Concretely the unlock
is four properties an operator can *price*:

- **The cap = max drawdown.** The supplier-spend budget is a single cross-rail cap; the
  agent cannot reserve past it on *any* rail. Your worst case is a number you chose, not
  "however much the agent decided to spend."
- **Custody = the agent never holds your wallet.** The gateway custodies the supplier-side
  credentials; the agent holds only a bounded spend authority. A prompt-injected agent
  that points straight at the raw rail **has no credential** — the call fails by
  construction, not by trusting the model (the custody-broker, §12 of the gateway PRD).
- **Instant revoke = clawback.** The owner revokes mid-stream and the *very next* supplier
  purchase on every rail is refused `Revoked`, no token-TTL window.
- **Signed receipts = a verifiable P&L.** Every sale and purchase emits a chain-anchored
  receipt; the margin is reconstructable and *auditable offline by a stranger* — an
  underwriter, a lender, a co-investor — without trusting your books.

Be plain: **auths is the safety + the rails, not the alpha.** It does not make the strategy
profitable. It makes a fully-autonomous merchant *safe to fund*, because the supplier side
— the drain vector — is bounded to your max drawdown, instantly clawback-able, and produces
a P&L you don't have to take on faith.

**Why the incumbents structurally can't match it:**

| Incumbent (how you'd fund an autonomous merchant today) | Where the spend authority lives | Why it can't safely bound the supplier side |
|---|---|---|
| **Stripe key / funded wallet handed to the agent** | the agent holds the secret — ambient, all-or-nothing | The agent *has your wallet*. A bug/injection drains it to zero. No cap, no per-action binding; revocation = rotate-and-propagate (a window), and a leaked wallet key has no revocation at all. |
| **Stripe Issuing per-card cap** | the processor's central evaluator, one card | A real per-card budget — but **one silo per rail**. `$4.99` on the card + `$4.99` on a USDC wallet reads "$0 of $5" in each; there is no *cross-rail* cap. It also can't bound non-payment scope, can't be cryptographically sub-delegated to a fleet, and the P&L is "the processor's dashboard says so." |
| **Human approves each supplier purchase** | a person clicking "buy" | Doesn't scale to an order *stream* (the whole revenue model), isn't cryptographic, leaves no verifiable receipt, and is exactly the per-sale human auths exists to remove. Approval ≠ a bounded delegation. |

None lets a **stranger** — an underwriter, a lender, a platform — prove offline, from
signatures alone, that *this* merchant agent's spend is bounded by a cap its owner anchored,
across **every** rail, with instant clawback and a verifiable P&L. That is what turns "I
have an autonomous store" from an uninsurable liability into a **fundable, insurable, fleet-able
position**: an underwriter can price "the supplier side provably cannot exceed $X and one
revoke stops it everywhere" — they cannot price "we trust the agent not to drain the wallet."

---

## 3. Goals — what makes it believable

- **G1 — The full order loop, real rails.** The agent runs inbound order (Stripe) →
  outbound supplier purchase (Stripe and/or x402/USDC) → margin retained, against real
  Stripe-test and x402/USDC-testnet APIs (no live money). The order stream is the recurring
  revenue; each order is one pass of the loop.
- **G2 — The cap is the max drawdown, and it's un-exceedable cross-rail.** One supplier
  budget spans both rails; the call that would reserve past it — on *either* rail — is
  refused before the rail is touched, even when each per-rail silo still reads in-budget.
  *The cap you set is the most you can lose.*
- **G3 — The agent never holds your wallet.** The gateway custodies the supplier-side
  credentials; the agent holds only its delegation. A purchase routed around the gateway
  fails for lack of a credential — drain-proof by construction, not by trusting the model.
- **G4 — Margin-bounded supplier spend.** The agent cannot buy more than it sold + a float:
  the supplier-cost reservation is checked against the **realized inbound revenue + a
  configured float**, so a runaway reorder is refused — the merchant is structurally
  prevented from buying into a loss/drain beyond your float.
- **G5 — Instant clawback + a verifiable P&L.** A mid-stream revoke stops the next supplier
  purchase on every rail; every sale and purchase emits a signed receipt from which the
  P&L (revenue − supplier cost = margin) is reconstructed and verified offline by a
  stranger.
- **G6 — A fleet bounded by your total risk (stretch).** N merchant agents, each a
  sub-delegated `$k` slice of one **aggregate** cap, such that the *fleet's* total supplier
  spend provably cannot exceed your aggregate — and one revoke at the parent stops the whole
  fleet.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an
**adversarial twin (fail-closed)**. IDs `AGENT-MERCHANT-*`. They reuse the already-closed /
in-flight gateway primitives — **AGT-1** (scope), **AGT-4 + D8 / AGENT-MCP-3** (cross-rail
cap), **OPS-1** (revocation), **§12** (custody) — and instantiate them in the merchant
shape. **AGENT-MERCHANT-1 is load-bearing: it builds the order-loop harness over the
gateway.** Accept + adversarial paths live in each probe; the §9 gap entries reference them.

- **AGENT-MERCHANT-1 — The agent runs the full order loop through the gateway, with a P&L
  receipt (THE BUILD).** *Maps: AGENT-MCP-1 (the gateway broker) in the merchant shape.* An
  agent holding a supplier-spend delegation processes one order: reads an inbound Stripe
  charge (the sale), reserves + settles the matching supplier purchase against its cap,
  retains the margin in the owner's custody, and emits a receipt.
  - **Observable (accept):** an in-budget order round-trips — inbound sale read, supplier
    purchase settled on the rail, a receipt emitted (`device=agent`, `identity=owner-root`)
    carrying `revenue`, `supplier_cost`, `margin`, and `rail`; `auths verify` of the receipt
    accepts and the P&L reconstructs.
  - **Adversarial twin:** with the gateway removed (agent points at the raw rail) the
    supplier purchase has **no custodied credential** and fails — the agent cannot pay
    around the gateway; with the gateway in place a forged/malformed purchase proof is
    rejected **before the rail is touched** (the supplier is never charged on a bad proof).

- **AGENT-MERCHANT-2 — One cross-rail supplier cap is un-exceedable (the cap = max
  drawdown).** *Maps: AGENT-MCP-3 / AGT-4 / D8.* The agent holds one `budget = $5` spanning a
  Stripe-test supplier server *and* an x402/USDC supplier server; the counter is the durable
  verifier-held cross-rail ledger (reserve-before-rail, settle-after).
  - **Observable (accept):** supplier purchases whose *combined reserved* cost across both
    rails is ≤ $5 settle; the running cross-rail total is in each receipt.
  - **Adversarial twin:** the purchase that would *reserve past* $5 — **on either rail** — is
    refused **`UsageCapExceeded`** and **never settled** (the reservation fails before the
    rail is touched); `$4.99`-on-Stripe `+ $0.02`-on-x402 is refused, where two siloed
    per-rail budgets each still read "$0 spent." A replayed/lower total is rejected
    (`UsageCounterRolledBack`). *The cap is the max drawdown — it cannot be exceeded on any
    rail.*

- **AGENT-MERCHANT-3 — The agent never holds your wallet (custody-broker, drain-proof).**
  *Maps: gateway §12 (custody broker).* The supplier-side credential (Stripe key / USDC
  wallet key) is held by the gateway; the agent holds only its delegation.
  - **Observable (accept):** the agent's supplier purchase *through* the gateway succeeds
    (the gateway supplies the custodied credential).
  - **Adversarial twin:** the same agent attempting the supplier purchase **directly**
    (bypassing the gateway, as a prompt-injected agent would) **has no credential for the
    rail and the purchase fails** — the wallet was never in the agent's hands, so it cannot
    be leaked or drained around the cap. *An agent can't misuse a key it never held.*

- **AGENT-MERCHANT-4 — Supplier spend is bounded by realized revenue + a float (can't buy
  more than it sold).** *Maps: AGT-4 / D8, the budget keyed to realized inbound.* The agent's
  supplier-spend allowance for the loop is `realized_revenue + float`, not an open budget.
  - **Observable (accept):** a supplier purchase whose cost ≤ (the order's realized inbound
    revenue + the configured float) settles.
  - **Adversarial twin:** a runaway reorder whose cost exceeds `realized_revenue + float` is
    refused **`UsageCapExceeded`** before the rail is touched — the merchant is structurally
    prevented from buying into a drain beyond the float, *driven by the agent's own
    over-eager decision.*

- **AGENT-MERCHANT-5 — Instant revoke = clawback; mid-stream, no window.** *Maps: OPS-1 /
  AGENT-MCP-4.* The owner revokes the agent's delegation while the order stream is running.
  - **Observable (accept):** supplier purchases before the revocation settle.
  - **Adversarial twin:** the **very next** supplier purchase after the revocation event —
    **on every rail** — is refused **`Revoked`**; no API-key rotation window, no token TTL.
    The receipts up to that point make the realized position provable for out-of-band
    reconciliation. *Revocation is the clawback.*

- **AGENT-MERCHANT-6 — The receipts reconstruct a verifiable P&L (a stranger can audit
  it).** *Maps: AGENT-MCP-1 receipts + the §12 detection property.* Every sale and purchase
  in the order stream emits a signed receipt.
  - **Observable (accept):** over a stream of N orders, summing the receipts yields
    `Σrevenue − Σsupplier_cost = Σmargin`, and each receipt `auths verify`-accepts offline —
    no access to the operator's books required.
  - **Adversarial twin:** a receipt edited to inflate the margin (lower the supplier cost,
    raise the revenue) **fails verify** — the P&L is signed end-to-end, so a doctored book
    is detectable by a stranger. *A verifiable P&L, not a dashboard you trust.*

- **AGENT-MERCHANT-7 — A fleet is bounded by your total risk; one revoke stops all (STRETCH).**
  *Maps: the aggregate cap + sub-delegation/attenuation (AGT-1 + D8 aggregate).* The owner
  delegates N merchant sub-agents, each a `$k` slice of one **aggregate** supplier cap.
  - **Observable (accept):** each sub-agent spends within its `$k` slice; the fleet's
    combined supplier spend stays ≤ the aggregate cap.
  - **Adversarial twin:** a sub-agent attempting to exceed its `$k` slice is refused
    (attenuation — a child cannot exceed its parent), the *fleet* cannot collectively
    exceed the aggregate, and **one revoke at the parent** stops every sub-agent's next
    supplier purchase on every rail. *(Rides the aggregate-cap leg; PARK rather than stub if
    the aggregate-counter runtime isn't ready.)*

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy`; exact paths pinned during the sculpt (this PRD is
read-only). This use case **adds no new crypto** — it is the merchant-shaped harness +
config over the bounded-agent gateway. **Pre-launch ⇒ no back-compat:** surfaces are
harvested and reshaped, not preserved.

### Exists — the enforcement primitives this use case consumes
- **The bounded-agent gateway** (`auths-mcp-gateway.md`) — `auths-mcp-core` (offline
  delegated-credential verify + the one per-call gate: scope ⊆ parent · cross-rail budget ·
  expiry · revocation + signed receipts) and `auths-mcp-gateway` (the real-MCP proxy + `wrap`
  subcommand). The merchant's supplier servers are *wrapped downstream MCP servers*.
- **Cross-rail budget accounting (D8 / AGENT-MCP-3)** — the durable verifier-held
  `CrossRailBudget` (reuse AGT-4's high-water `usage_ledger.rs`): one monotonic **settled**
  counter keyed to the agent delegation + transient **reserved** holds; reserve-before-rail,
  settle-after, rollback-protected (`UsageCounterRolledBack`), checkpoint-anchored. **This is
  the cap = max-drawdown engine.**
- **Scope (AGT-1)** — `id agent add --scope --expires-in` →
  `auths_sdk::domains::agents::add_scoped` (delegator-anchored seal; subset rule). The
  supplier-purchase capability is a scope the owner anchors.
- **Fail-closed verdicts** — `OutsideAgentScope`, `AgentExpired`, the **AGT-4**
  `UsageCapExceeded` / `UsageCounterRolledBack`, the **OPS-1** `Revoked` path.
- **The custody broker (gateway §12)** — the gateway holds the downstream credential; the
  agent holds only the delegation. **This is the agent-never-holds-your-wallet property.**
- **Per-call receipts (AGENT-MCP-1)** — the signed, offline-verifiable per-call proof; the
  P&L is a *projection* over the receipt stream.
- **Payment-mode (`mode=real|test`, AGENT-PAY-3)** — real money is the default, test is the
  single opt-in; the cap is the mandatory seatbelt (the gateway refuses to wrap a payment
  rail without a `--budget`); the mode is disclosed. **The merchant runs in `test` for the
  gate; `real` for production, with the cap mandatory.**
- **Stripe + x402 rail metering (AGENT-PAY-1 / AGENT-PAY-2)** — the gateway extracts the
  charge amount from a Stripe-test charge response and the paid amount from an x402/USDC
  settlement response, summing both into the one cross-rail cap.

### Build — the merchant-specific deliverables (harness + config; engine stays in `auths`)
1. **The order-loop harness (AGENT-MERCHANT-1, the load-bearing build).** A scripted (and
   evidence-only live) merchant loop that, per order: reads an inbound Stripe-test charge
   (the sale), reserves the matching supplier cost against the cross-rail cap, settles the
   supplier purchase on the chosen rail, retains the margin in the owner's custody, and
   emits a receipt. Drives the gateway in replay mode for the gate.
2. **The margin-bound rule (AGENT-MERCHANT-4).** Key the per-loop supplier allowance to
   `realized_revenue + float` (a thin policy over the existing `CrossRailBudget` — the cap
   for the loop is computed from the inbound, not a static number), so "can't buy more than
   it sold + a float" is enforced by the same reserve-before-rail gate.
3. **The P&L projection (AGENT-MERCHANT-6).** A receipt-stream → P&L reducer
   (`Σrevenue − Σsupplier_cost = Σmargin`) and its offline verify, plus the tamper probe (a
   doctored receipt fails). No new crypto — a projection over the signed receipts.
4. **The aggregate-cap / sub-delegation harness (AGENT-MERCHANT-7, stretch).** N sub-agents,
   each a `$k` slice of one aggregate counter; the fleet-total bound + one-revoke-stops-all.
   PARK if the aggregate-counter runtime isn't ready.
5. **The 1 scenario config + the staged dramaturgy** — `merchant.config` (~20 lines over the
   one gateway) and the `run.sh` acts (§7), shipped as a gateway *example*
   (`auths-mcp/examples/merchant`), **not** in `auths-demos`.

Any surface that already suffices → reclassified to a closed regression guard at baseline
(the DOTAK precedent), never quietly dropped.

---

## 6. Non-goals

- **NOT a claim that auths makes dropshipping profitable.** auths is the **safety + the
  rails, not the alpha.** Sourcing, pricing, demand, supplier reliability — the *agent's*
  strategy — determine whether there's a margin at all. This PRD asserts only that the
  *downside is capped, the wallet is custodied, revoke is instant, and the P&L is
  verifiable*; it makes no profitability claim.
- **NOT a payment processor / wallet / escrow.** auths *bounds* supplier spend and *receipts*
  the P&L; it never holds customer funds or settles. Customer payments accrue to the owner's
  own Stripe custody; rails (Stripe, x402/USDC) are wrapped downstream tools.
- **NOT order fulfillment / logistics / a storefront.** No inventory system, shipping
  integration, catalog, or tax engine. The "order loop" here is the *spend-authority* loop
  (sale read → bounded supplier purchase → margin), which is the part auths bounds.
- **NOT live money in the gate.** Hermetic over recorded Stripe-test + x402/USDC-testnet
  fixtures; a live charge / funded-wallet settle is evidence-only, deferred (the gateway D7
  stance). `mode=real` is the production default but the *gate* runs `test`.
- **NOT a new agent framework or a fork of MCP.** It instantiates the existing gateway; the
  enforcement is the gateway's, unchanged.
- **NOT model-quality claims.** Nothing asserts the agent picks good products or prices well.
  Whatever it decides, the supplier side stays bounded to the cap.
- **NOT a perf claim.** Per-order sign+verify latency is noted, not the property; correctness
  of the bound is.

---

## 7. The narrative / run.sh dramaturgy

Self-performing, staged in acts (house style): `./run.sh` (the live show, evidence-only),
`./run.sh --check` (the hermetic gate, the recurve probe entrypoint — frozen
transcript/fixtures, deterministic verdicts), `./run.sh reset`. Auto/non-TTY plays itself.
Shipped in `auths-mcp/examples/merchant` (a gateway example, **not** `auths-demos`).

- **Act 0 — The pitch, stated honestly.** On screen: "auths is the **safety + the rails,
  not the alpha**. The agent brings the strategy; auths makes it safe to fund. The cap is
  your max drawdown. The agent never holds your wallet. One revoke is the clawback." Disclose
  the one honesty: rails are test-mode/testnet, fixtures recorded; every delegation, cap,
  settlement, and receipt is real.
- **Act 1 — The delegation, signed.** The owner mints the merchant agent its delegation:
  `--scope supplier.purchase --budget $5 --ttl …`, anchored in the owner's KEL. Print the
  agent's *anchored* cap, read back from the **owner's** KEL, and show the gateway holds the
  supplier credentials while the agent holds only the delegation (`git log refs/auths/*`).
- **Act 2 — The order stream (recurring revenue).** Order after order: inbound Stripe-test
  charge read (the sale), supplier cost **reserved** against the cross-rail cap, supplier
  purchase **settled** on the rail, margin retained in the owner's custody. Each order prints
  a receipt: `revenue`, `supplier_cost`, `margin`, `rail`, running cross-rail total. The
  honest framing: *the order stream is the revenue; every order is re-verified from the
  chain, not a session.*
- **Act 3 — The cap = max drawdown (cross-rail).** The agent, over-eager, tries to buy on a
  *second* rail to dodge the limit: `$4.99` on Stripe **+** `$0.02` on x402. **Pledge before
  proof:** "each per-rail silo reads '$0 of $5.' Under one auths cap it's $9.98 of $5. Expect
  refusal." → **`UsageCapExceeded`**, supplier **never charged**, before the rail is touched.
- **Act 4 — Can't buy more than it sold.** A runaway reorder: the agent tries to buy
  supplier stock costing more than the order's realized revenue + float. → refused
  `UsageCapExceeded`. "The supplier side is bounded by what actually came in."
- **Act 5 — The clawback.** The owner hits **revoke** mid-stream. The agent's next supplier
  purchase — **on every rail** — is refused **`Revoked`**, instantly, no window. The receipts
  to that point make the realized P&L provable. "One revoke. Spend stops everywhere. The
  position is provable."
- **Act 6 — The verifiable P&L (the close).** Sum the receipt stream offline:
  `Σrevenue − Σsupplier_cost = Σmargin`, each receipt `auths verify`-accepted *without the
  operator's books*; then a **doctored** receipt is shown failing verify. Close on:
  **"Every order was a real decision. The downside was a number you chose. The agent never
  held your wallet. One revoke clawed it back. And the P&L is verifiable by a stranger — from
  the chain alone, offline. auths didn't make the strategy profitable. It made it safe to
  hand the strategy real money. That is the boundary no card cap can hold."**

The climax is Act 3 (the cross-rail cap holding where two siloed budgets each say "$0
spent") and Act 5 (the instant clawback) — the two beats that make a fully-autonomous
merchant *fundable*.

---

## 8. Success metrics

The show and the probes assert these verdicts (not timings):

- **M1 (full loop + P&L receipt):** an in-budget order round-trips through the gateway —
  inbound sale read, supplier purchase settled on a real test rail — and emits a receipt
  (`device=agent`, `identity=owner-root`, `revenue`/`supplier_cost`/`margin`/`rail`) that
  `auths verify` independently accepts (AGENT-MERCHANT-1).
- **M2 (cap = max drawdown, cross-rail):** with one `$5` cap spanning two rails, the
  purchase that would *reserve past* it — on *either* rail — is refused `UsageCapExceeded`
  before the rail is touched; the **combined** running total is in the receipts
  (AGENT-MERCHANT-2). *`$4.99` + `$0.02` is refused where each silo reads "$0 spent."*
- **M3 (custody / drain-proof):** the agent's supplier purchase *through* the gateway
  succeeds; the same purchase **direct** (bypassing the gateway) fails for lack of a
  custodied credential (AGENT-MERCHANT-3). *The wallet was never in the agent's hands.*
- **M4 (margin-bound):** a supplier purchase ≤ realized revenue + float settles; a runaway
  reorder beyond it is refused `UsageCapExceeded` (AGENT-MERCHANT-4).
- **M5 (instant clawback):** the first supplier purchase after a mid-stream revocation is
  refused `Revoked` on every rail, no window (AGENT-MERCHANT-5).
- **M6 (verifiable P&L):** summing N receipts yields `Σrevenue − Σsupplier_cost = Σmargin`,
  each receipt accepts offline, and a doctored receipt fails verify (AGENT-MERCHANT-6).
- **M7 (fleet/aggregate, stretch):** N sub-agents each bounded by their `$k` slice, the
  fleet bounded by the aggregate, one revoke stops all — or PARKED with the aggregate-counter
  reason (AGENT-MERCHANT-7).
- **M0 (the meta-metric):** an operator can put a merchant agent in front of real rails and
  hand it **real capital** with the downside provably capped, the wallet custodied, revoke
  instant, and a verifiable P&L — the "fundable autonomous merchant" bar that an ambient
  payment credential cannot reach.

Every verdict is produced by real `auths-verifier` / `auths-mcp-core` code over real KEL/TEL
events; every rail interaction is a real Stripe-test / x402-testnet call (or recorded
fixture in the gate). Nothing about the *enforcement* is mocked — the agent's intents are
scripted (or a real model in the evidence-only live leg), disclosed on screen.

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): canonical
fields `class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with
`evidence` (file:line into the target), `unlocks` (what gets stronger), and `covers` (the
GAPS.md / PRD anchors). The **accept + adversarial paths live in each probe** (the probe
contract: an accept path + a `.trap/` counterexample) and are specified per-FR in §4 — *not*
in the gap entry. IDs `AGENT-MERCHANT-*`; `reads: gateway` names the content-hash rule over
the built `auths-mcp-gateway` binary (the gateway PRD §10). `AGENT-MERCHANT-1` is the
load-bearing build; reclassify any claim already GREEN at baseline to a `closed` regression
guard (the DOTAK precedent). Probes drive the gateway in **replay mode** (hermetic; recorded
Stripe-test + x402-testnet fixtures, no live money).

```yaml
- id: AGENT-MERCHANT-1
  title: "The merchant agent runs the full order loop through the gateway and emits a verifiable P&L receipt"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the order-loop harness over auths-mcp-gateway: per order, read an inbound
    Stripe-test charge (the sale), reserve the matching supplier cost against the cross-rail
    CrossRailBudget, settle the supplier purchase on the rail, retain the margin in the
    owner's custody, and emit a receipt carrying revenue/supplier_cost/margin/rail. The
    probe drives the gateway in replay mode and asserts the receipt auths-verifies
    (device=agent, identity=owner-root). Adversarial: the supplier purchase made DIRECT
    (gateway removed) has no custodied credential and fails; a forged purchase proof is
    rejected before the rail is touched.
  unlocks: "A fully-autonomous merchant can run the supplier loop bounded at all — the floor for MERCHANT-2..7."
  evidence:
    - "maps AGENT-MCP-1 (the gateway broker) in the merchant shape; the gateway brokers a tools/call but the order-loop harness + P&L receipt projection is not built"
  covers: [G1, FR-1]
  probe: probes/agent-merchant-1.sh

- id: AGENT-MERCHANT-2
  title: "One cross-rail supplier cap is un-exceedable on any rail — the cap is the max drawdown"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Wrap two supplier rails (Stripe-test + x402/USDC-testnet) under ONE budget keyed to the
    agent delegation via the durable CrossRailBudget (reserve-before-rail, settle-after,
    rollback-protected). A supplier purchase that would reserve past the cap on EITHER rail
    is refused UsageCapExceeded before the rail is touched; the combined running total is in
    each receipt. Adversarial: $4.99-on-Stripe + $0.02-on-x402 is refused where two siloed
    per-rail budgets each read "$0 spent"; a replayed/lower total → UsageCounterRolledBack.
  unlocks: "The cap = max drawdown — a fully-autonomous merchant's worst case is a number the owner chose, across every rail (the cross-rail moat a per-card cap can't express)."
  evidence:
    - "maps AGENT-MCP-3 / AGT-4 / D8 (the durable cross-rail CrossRailBudget, usage_ledger.rs); the merchant cap is the same counter in the supplier-spend shape"
  covers: [G2, FR-2]
  probe: probes/agent-merchant-2.sh

- id: AGENT-MERCHANT-3
  title: "The agent never holds the wallet — the gateway custodies supplier credentials (drain-proof by construction)"
  class: security-tradeoff
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    The gateway custodies the supplier-side credential (Stripe key / USDC wallet key); the
    agent holds only its delegation. A supplier purchase THROUGH the gateway succeeds (the
    gateway supplies the credential); the SAME purchase made DIRECT by the agent (bypassing
    the gateway, as a prompt-injected agent would) fails for lack of a credential. Honest
    limit (gateway §12): custody is drain-proof only for a rail reachable solely through the
    custodied credential; a public endpoint is detection-only.
  unlocks: "An agent can't leak or misuse a wallet it never held — the supplier side stops being a drain vector, so real capital can be delegated."
  evidence:
    - "maps the gateway custody-broker (auths-mcp-gateway.md §12); the merchant instantiates it on the supplier rail — the agent holds only the delegation"
  covers: [G3, FR-3]
  probe: probes/agent-merchant-3.sh

- id: AGENT-MERCHANT-4
  title: "Supplier spend is bounded by realized revenue + a float — the agent can't buy more than it sold"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Compute the per-loop supplier allowance as realized_inbound_revenue + a configured float
    (a thin policy over CrossRailBudget — the loop's cap is derived from the order's inbound,
    not a static number), enforced by the same reserve-before-rail gate. A purchase ≤
    (revenue + float) settles; a runaway reorder above it is refused UsageCapExceeded before
    the rail is touched, driven by the agent's own over-eager decision.
  unlocks: "The merchant is structurally prevented from buying into a drain beyond the float — the supplier side can never outrun what came in."
  evidence:
    - "maps AGT-4 / D8 with the cap keyed to realized inbound; the revenue-derived per-loop allowance is the net-new policy over the existing counter"
  covers: [G4, FR-4]
  probe: probes/agent-merchant-4.sh

- id: AGENT-MERCHANT-5
  title: "Instant revoke is the clawback — the next supplier purchase on every rail is refused mid-stream with no window"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Re-derive the agent delegation's liveness from the KERI registry on every supplier
    purchase (reuse the gateway's per-call revocation check) so the VERY NEXT purchase after
    a mid-stream revocation event — on EVERY rail — is refused Revoked, with no API-key
    rotation window and no token TTL. Accept: purchases before revocation settle. Adversarial:
    the first purchase after revoke is Revoked on both rails; the receipts up to that point
    make the realized position provable for out-of-band reconciliation.
  unlocks: "Revocation = clawback — an owner can stop a fully-autonomous merchant's spend everywhere at once, the instant kill an ambient key can't give."
  evidence:
    - "maps OPS-1 / AGENT-MCP-4 (per-call revocation); the merchant instantiates it as the clawback on the supplier rails"
  covers: [G5, FR-5]
  probe: probes/agent-merchant-5.sh

- id: AGENT-MERCHANT-6
  title: "The receipt stream reconstructs a verifiable P&L a stranger can audit offline"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Build the P&L projection over the signed receipt stream: summing N order receipts yields
    Σrevenue − Σsupplier_cost = Σmargin, and each receipt auths-verifies offline WITHOUT the
    operator's books. Adversarial: a receipt edited to inflate the margin (lower supplier
    cost / raise revenue) fails verify — the P&L is signed end-to-end, so a doctored book is
    detectable by a stranger. A projection over the existing signed receipts; no new crypto.
  unlocks: "A verifiable P&L (not a dashboard you trust) — an underwriter / lender / co-investor can price the position from the chain alone."
  evidence:
    - "maps AGENT-MCP-1 receipts + the gateway §12 detection property; the receipt → P&L reducer + its tamper probe is the net-new projection"
  covers: [G5, FR-6]
  probe: probes/agent-merchant-6.sh

- id: AGENT-MERCHANT-7
  title: "A merchant fleet is bounded by the owner's aggregate cap, each sub-agent a verifiable slice, one revoke stops all (STRETCH)"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Sub-delegate N merchant agents, each a $k slice of ONE aggregate supplier cap
    (attenuation — a child cannot exceed its parent), summed into the aggregate
    CrossRailBudget. Accept: each sub-agent spends within its $k slice; the fleet's combined
    supplier spend stays ≤ the aggregate. Adversarial: a sub-agent exceeding its $k slice is
    refused, the fleet cannot collectively exceed the aggregate, and ONE revoke at the parent
    stops every sub-agent's next purchase on every rail. PARK — do not stub — if the
    aggregate-counter runtime is absent.
  unlocks: "A fleet bounded by your total risk — N autonomous merchants insurable as one position, with a single kill switch."
  evidence:
    - "maps AGT-1 attenuation + the D8 aggregate counter (aggregate-cap runtime likely PARK if not yet built)"
  covers: [G6, FR-7]
  probe: probes/agent-merchant-7.sh
```

---

*Drafted 2026-06-15. A go-to-market **use case** of the bounded-agent gateway
(`go_to_market/auths-mcp-gateway.md`) — the autonomous-merchant (dropshipping) instantiation
of scoped/budget-capped/revocable/custodied delegation, cross-rail metering, the aggregate
cap, sub-delegation, signed receipts, the custody broker, and `mode=real|test`. Consumes
AGT-1, AGT-4 + D8 / AGENT-MCP-3, OPS-1, and the gateway §12 custody model; adds **no new
crypto** — the merchant-shaped harness + config + P&L projection are the net-new build. The
scripted `agent_demos/` remain the separate hermetic proofs of each primitive; this sits
above them as the merchant *use-case* proof, shipped as a gateway example
(`auths-mcp/examples/merchant`), **not** in `auths-demos`. auths is the **safety + the rails,
NOT the alpha** — it bounds the downside, gives instant clawback, and produces a verifiable
P&L; the agent brings the strategy. Surfaces named against `../auths` @ `dev-privacy`; exact
paths pinned during the sculpt. Authoring scope: READ-ONLY on `../auths`.*
