# PRD: The Yield Agent — delegate real capital, cap the drawdown, clawback in one call

> **One line:** you hand an autonomous agent **real USDC** to deploy into lending/staking/yield
> and let it earn and compound — but the agent **never holds your wallet**, only a
> **scoped, principal-capped, instantly-revocable** spend authority; the agent brings the
> alpha, **auths bounds the downside** (cap = max drawdown), gives a **one-call clawback**,
> and a **signed, verifiable position ledger** of every deployment and every dollar earned.
>
> **Be honest — read first.** *auths is the safety and the rails, **not** the alpha.* It does
> **not** make the strategy profitable and it does **not** make the yield safe — protocol/
> smart-contract risk and stablecoin de-peg are real and **out of auths's reach** (§6). What
> auths changes is the one thing that today blocks you from delegating *real* capital to an
> autonomous agent: it makes the **downside provably bounded** and the position **provably
> auditable**, so the deploy decision becomes "is the strategy good?" instead of "do I trust
> this process with my wallet?". The agent runs the strategy; auths bounds the principal,
> clamps the blast radius, and claws it back on demand.
>
> **What this is.** A **profit-center** scenario of the already-built bounded-agent MCP
> gateway (`prds/go_to_market/auths-mcp-gateway.md`). The yield/treasury rails (an
> Aave/Compound-style lending server, a staking server, a redemption server) are **wrapped
> downstream MCP servers**; the agent reaches them only through the gateway, which custodies
> the deploy credential and enforces one cross-rail **principal cap**, expiry, revocation, and
> a per-action receipt. The agent earns an **inbound** yield stream it could not earn if you
> couldn't safely delegate to it. **Nothing new in `auths-demos`** — this ships as a
> scenario config + one yield rail adapter in `auths-mcp/examples/treasury`, gated by the
> recurve loop in `../auths`.
>
> **Deliberate departure from house style (inherited from the gateway):** the scripted demos
> are "offline-first, no live LLM." This one's beat is a *live* model deciding to deploy,
> compound, over-deploy, or keep deploying after revocation — reconciled for CI by the
> gateway's **recorded-transcript replay mode** (§7): the show runs a live agent against
> **test-mode** rails (testnet USDC / Stripe-test settlement, no real money); the *gate/probe*
> runs a **frozen transcript** + **recorded rail-response fixtures**, so enforcement is verified
> hermetically and deterministically, **never against live money**.
>
> **Authoring scope:** READ-ONLY on `../auths` for this PRD. The recurve loop sculpts the
> engine crates in `../auths` and the wrapper/example in `../auths-mcp`; this demo's gaps ride
> the gateway's already-closed primitives (cross-rail cap, scope, revocation, receipts,
> PaymentMode) and add the **yield-rail cost/earnings extraction** + the **treasury scenario**.

---

## 1. One line + scenario

A fund, a DAO treasury, or a solo operator has **idle USDC** and a strategy: deploy it into
lending markets and staking, harvest the interest, **compound**. The obvious move is to let an
autonomous agent run it 24/7 — rates move, positions need rebalancing, rewards need
re-deploying, and a human can't sit on it. The obvious move is also the one nobody makes,
because **handing an autonomous agent your wallet is handing it everything**: a buggy planner,
a prompt-injected step, or an over-eager loop can drain the treasury, and the API key or signer
the agent holds *is* the authority — possession is permission, with no parent and no ceiling.

Now insert the **auths gateway** between the agent and its yield rails. You — the treasury
owner, or an orchestrator agent — mint the working agent a **delegation**: `scope =
{lend.deposit, stake.deposit, yield.claim}`, `principal_cap = $50,000`, `ttl = 7d`, anchored in
your KEL. The agent's MCP client points at the gateway, not at the raw lending/staking servers,
and the **gateway custodies the deploy credential** (the wallet's spend key / the rail API key)
while the agent holds **only** the delegation. Every `tools/call` the model emits — *deposit
$10k into the lending market*, *stake $5k*, *claim and re-deploy rewards* — is intercepted,
checked against the **delegator-anchored cap**, signed into a per-call receipt, and forwarded
**only if** it is inside scope, **would not reserve the cumulative deployed principal past the
cap**, unexpired, and unrevoked. Otherwise it comes back as a fail-closed MCP error the model
reads and reacts to. The agent **earns** — yield flows back as an inbound stream the position
ledger records — and it **compounds**, all inside a box whose walls you set.

Then the realistic failures, *driven by the agent itself*: it decides to deploy a 51st thousand
past the `$50k` cap (a bug, an injected instruction, an over-eager rebalance); or it tries to
call `withdraw.to_external` (an unscoped capability — moving funds *off* to an address you never
authorized); or you see a protocol you don't like and hit **revoke**, and the agent tries one
more deposit. **The signature on each attempt is valid. The MCP envelope is well-formed. It is
asking for more authority — more principal, a wider capability — than your delegation ever
anchored, so the gateway refuses, from the chain alone, offline.** And because the gateway
custodies the deploy credential, a prompt-injected agent that points straight at the raw rail
**has no key for it** — the box is unbypassable by construction (§12), not by trusting the model.

**How it breaks today.** Hand the agent a hot wallet / signer key and it has *all* of it —
ambient authority, no cap, no parent, no clawback short of moving the funds yourself.
Hand it a rail API key from an env var (the majority case) and an injected agent has everything
the key has. "Approve each transaction in a dialog" doesn't scale to a 24/7 compounding loop and
leaves no cryptographic receipt. None of these can prove, at the rail boundary, that *this*
deploy keeps the cumulative principal under a ceiling its parent anchored — or revoke it with no
window.

**What auths does.** The deploy call *is* a signed artifact. The gateway resolves the agent's
delegated KEL **and** your KEL, replays with delegator-aware lookup, reads the
**delegator-anchored scope + principal cap + expiry seal**, and judges the call against a single
**cross-rail monotonic counter** (settled deployed principal + transient reserved holds):
returns a distinct verdict (`OutsideAgentScope` / `UsageCapExceeded` / `AgentExpired` / `Revoked`)
and a receipt. **The principal the agent is trying to commit past your cap was never anchored for
it — so that authority does not exist**, no matter how the model "decided."

---

## 2. The property it proves

**You can delegate *real capital* to an autonomous agent because the downside is provably
bounded, the position is provably auditable, and the authority is instantly revocable —
enforced per deploy-call, offline, from the signed chain.** Concretely, the four auths primitives
map one-to-one onto the four things that otherwise make capital-delegation unthinkable:

| Capital-delegation fear | The auths primitive that bounds it |
|---|---|
| "It could drain the treasury." | **Cross-rail principal cap = max drawdown.** Cumulative deployed principal can never reserve past the cap, across *every* rail at once; a 51st thousand is refused before the rail is touched. |
| "It holds my wallet." | **Custody broker.** The agent holds *only* a bounded spend delegation; the gateway custodies the deploy credential. The agent can't move what it never held. |
| "I can't pull out fast enough." | **Instant revoke = clawback.** The very next deploy call after revocation is refused `Revoked` — no token-TTL, no cache lag. (Revoke stops *new* deployment everywhere at once; recall of *already-deployed* funds is the agent's `redeem` scope, also bounded — §6.) |
| "I can't audit what it did." | **Signed per-action receipts = a verifiable P&L.** Every deploy, claim, and refusal is a chain-anchored receipt anyone can verify offline — a cryptographic position ledger, not log scraping. |

And one earns: **x402 pay-per-request lets the agent take an *inbound* stream** (e.g. serving a
priced data/strategy endpoint), so the same bounded authority that caps spend can meter income —
the agent is a **profit center**, not a cost center.

**Said plainly, for the record:** auths does **not** make the strategy profitable and does
**not** make the yield safe. The agent brings the alpha; the protocol carries its own risk. auths
makes it **safe to delegate real capital to an agent that runs the strategy** — bounded downside,
one-call clawback, verifiable P&L.

**Why the incumbents structurally can't match it:**

| Incumbent | Where authority lives | Why it can't bound capital handed to an autonomous agent |
|---|---|---|
| **Hot wallet / signer key handed to the agent** | the key the agent holds — possession *is* authority | No parent, no cap, no per-action ceiling, no clawback short of you moving the funds. A bug or injection spends everything. There is no "max drawdown" to anchor. |
| **Rail API key in an env var** (the common case) | nowhere — possession is the grant | An injected agent with the key has everything the key has. No principal cap, no per-deploy binding, no revocation that beats the key's own lifetime. |
| **Per-rail processor / protocol spend limit** (e.g. a per-market cap) | a limit inside *one* venue's control plane | N siloed caps, not one. `$49k` deployed in lending **and** `$49k` staked each reads "under a $50k venue cap," while the *agent* has deployed `$98k`. No single cross-rail drawdown bound; no offline-verifiable receipt the agent's *delegator* anchored. |
| **Human-approves-each-tx dialog** | a person clicking "allow" | Doesn't scale to a 24/7 compounding loop, isn't cryptographic, leaves no verifiable receipt, and is exactly what an autonomous treasury agent exists to remove. Approval ≠ a bounded, revocable, attenuable grant. |

None lets a **stranger relying party**, offline, prove from signatures alone that *this* agent's
deploy keeps the treasury's cumulative principal under a ceiling the owner provably anchored —
and revoke it with no window. That is what makes a capital-deploying agent **insurable**: an
underwriter can price "max drawdown ≤ the anchored cap, clawback in one call, every position
receipted" — they cannot price "we trusted a wallet key to a model."

---

## 3. Goals — what makes it believable

- **G1 — A real agent, a real deploy loop, real yield rails.** The agent is a live
  MCP-speaking model in an actual `tools/call` loop against wrapped **yield** downstream servers:
  a lending-market server (deposit / claim) and a staking server (deposit / claim), plus a
  redemption server. **Test-mode** rails (testnet USDC / Stripe-test settlement) so the show
  moves real test-money on real APIs with **no real funds**. The decisions are the model's; CI
  uses a recorded transcript + recorded rail-response fixtures (§7), never a fake agent.
- **G2 — The over-deploy is emergent, then bounded.** The compelling beat is a deploy call the
  *model* chose — past the principal cap, or out of scope, or post-revocation — refused at the
  gateway with a distinct verdict, while a valid in-bounds deploy from the same agent passes and
  the position ledger ticks up. *The model decided to over-commit the treasury; the chain refused.*
- **G3 — It actually earns and compounds.** The agent claims yield and re-deploys it; the
  receipts show principal deployed, yield harvested, and the **net position** — a real
  compounding loop, not a one-shot deposit. The cap binds *deployed principal* (the drawdown
  axis), while *earnings* flow inbound and are recorded — the profit center made legible.
- **G4 — One cross-rail cap is the max drawdown.** `$49k` in lending **plus** `$2k` staked is
  `$51k` deployed against a `$50k` cap → the next deploy on *either* rail is refused, even though
  each venue's own silo reads "under limit." The single cross-rail ceiling **is** the
  delegator's max acceptable drawdown.
- **G5 — Instant clawback + a verifiable P&L.** A mid-run revoke stops all new deployment on the
  next call (`Revoked`); every deploy/claim/refusal is a signed receipt `auths verify` accepts
  offline — the position ledger is cryptographic, replayable, and attributable to the exact grant.
- **G6 — Drop-in, real-by-default-but-test-for-the-show.** Adopting it is repointing the agent's
  MCP client at the gateway + holding a delegation, not re-instrumenting the rails; and the
  inherited PaymentMode means **real capital is the default** with a mandatory cap seatbelt — the
  show explicitly opts into `--test-mode` and discloses it on screen, so no real money is ever
  silent (the gateway's AGENT-PAY-3 contract).

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an **adversarial
twin (fail-closed)**. IDs `AGENT-YIELD-*`. They **reuse the gateway's already-closed primitives**
— scope (AGT-1), the cross-rail quantitative cap (AGENT-MCP-3 ↦ AGT-4 / D8), revocation (OPS-1),
receipts, and the PaymentMode contract (AGENT-PAY-3). **AGENT-YIELD-1 is load-bearing: it builds
the yield-rail adapter — the cost/earnings extraction that meters a deposit/claim into the
cross-rail counter — the only net-new engine surface this demo needs.** The accept + adversarial
paths are the probe contract; they are specified here and live in each probe (§9). Probes drive
the gateway in **replay mode** over recorded fixtures (hermetic, no live money).

- **AGENT-YIELD-1 — The yield rail is metered: a deposit reserves/settles its principal into the
  cross-rail cap (THE BUILD).** *Maps: §11 of the gateway PRD (bound, don't build) + AGT-4 / D8.*
  Given a lending/staking **deposit RESPONSE** (the shape the wrapped yield MCP server returns),
  the gateway extracts the **deployed principal amount** and **reserves it before the rail is
  touched / settles the actual after** against the agent's delegator-anchored `CrossRailBudget`
  — `auths-mcp-core` holds **zero yield-protocol code**; the yield server stays a wrapped
  downstream.
  - **Observable (accept):** an in-cap deposit (`lend.deposit($10,000)`) reserves, settles, and
    is metered — the deployed amount, rail (`rail=lend`), and the running **cumulative deployed
    principal** appear in the receipt; `auths verify` of the receipt accepts (`device=agent`,
    `identity=owner-root`).
  - **Adversarial twin:** a deposit whose extracted principal would **reserve past the cap is
    refused `UsageCapExceeded` before the lending server is invoked** (the deposit is never made);
    a settle below the recorded high-water is refused `UsageCounterRolledBack`. A transcript edited
    to under-report the deposit amount still settles the *recorded* (higher) figure — the cap can't
    be cheated by lying about the deposit.

- **AGENT-YIELD-2 — One cross-rail principal cap is the max drawdown across lending AND staking.**
  *Maps: AGENT-MCP-3 ↦ AGT-4 / D8.* The agent holds one `principal_cap = $50,000`; its deploys
  span **two rails** (the lending server and the staking server), summed into one counter.
  - **Observable (accept):** deposits whose *combined reserved* principal is ≤ `$50k` across both
    rails pass and settle; the **combined** cumulative deployed total is in each receipt.
  - **Adversarial twin:** the deposit that would *reserve past* `$50k` — **on either rail** — is
    refused `UsageCapExceeded` and never settled; `$49k`-lent `+ $2k`-staked is refused, where two
    siloed per-venue caps each still read "under limit." The moat: a **sub-agent handed a `$10k`
    slice** provably cannot deploy past it on *any* rail, and one revoke stops deployment everywhere
    at once.

- **AGENT-YIELD-3 — Recall/withdraw to an external address is out of scope and refused.** *Maps:
  AGT-1.* The agent holds `{lend.deposit, stake.deposit, yield.claim, redeem.to_treasury}` but
  **not** `withdraw.to_external`; the model emits `withdraw.to_external(<addr>)` (the
  drain-the-treasury move, by bug or injection).
  - **Observable (accept):** an in-scope `yield.claim` (harvest interest back to the treasury) and
    an in-scope `redeem.to_treasury` (pull principal back to the *owner's* address) pass.
  - **Adversarial twin:** `withdraw.to_external` returns a fail-closed MCP error carrying
    **`OutsideAgentScope`**, naming the offending capability — **the rail is never called** —
    despite a valid signature and a well-formed envelope. Moving funds *off* to an unanchored
    address is authority the delegation never held.

- **AGENT-YIELD-4 — Revocation is instant clawback of deploy authority, mid-loop, no window.**
  *Maps: OPS-1.* The owner revokes the agent's delegation while the compounding loop is running.
  - **Observable (accept):** deploys before revocation pass and settle.
  - **Adversarial twin:** the **very next** `tools/call` after the revocation event is refused
    **`Revoked`** — no token still valid for its TTL, no introspection-cache lag; the gateway
    re-derives liveness from the chain on every call. (Honest bound, §6: revoke stops *new*
    deployment instantly; recall of already-deployed principal is the agent's bounded `redeem`
    scope or the owner's own custody key — auths clamps the blast radius, it does not unwind a
    settled on-chain position for you.)

- **AGENT-YIELD-5 — It earns and compounds, and the P&L is a verifiable ledger.** *Maps: the
  profit-center property — the receipts as a position ledger.* Over a multi-step loop the agent
  deploys, **claims yield**, and **re-deploys** the claimed amount (compounding); optionally serves
  a priced endpoint over **x402** for an inbound stream.
  - **Observable (accept):** the receipt sequence reconstructs a coherent P&L — `principal_deployed`,
    `yield_claimed`, `net_position`, and (if present) `x402_earned` — each receipt independently
    `auths verify`-accepted; a claimed-and-redeployed amount is metered as new deployment under the
    same cap; an inbound x402 receipt is recorded as **earned**, not counted against the spend cap.
  - **Adversarial twin:** a receipt edited to overstate yield (or to drop a deploy from the ledger)
    fails verification — the P&L cannot be inflated without breaking a signature; and a redeploy that
    pushes cumulative principal past the cap is still refused `UsageCapExceeded` (compounding does not
    escape the drawdown bound).

- **AGENT-YIELD-6 — Real-by-default, test-for-the-show, cap mandatory, mode disclosed.** *Maps:
  AGENT-PAY-3 (inherited).* The treasury rails resolve via the gateway's PaymentMode port.
  - **Observable (accept):** with **no flag** the wrap resolves to **real** capital
    (mainnet/live rail) and refuses to start **without a `--principal-cap`** (`budget-required`);
    `--test-mode` resolves to testnet/Stripe-test; both modes carry a disclosed `mode=real|test`
    field on the receipt and the `wrap --show-mode` dry-run.
  - **Adversarial twin:** wrapping a yield rail **without a cap is refused `budget-required`** in
    *both* modes (the drawdown seatbelt cannot be skipped); and a real-mode run with no disclosed
    `mode=` field is forbidden (`mode-not-disclosed`) — real capital is never silent.

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy`; exact paths pinned during the sculpt (this PRD is
read-only). **The bounded-agent gateway is already built** (its own PRD's crates landed in the
monorepo); this demo *consumes* it and adds one yield-rail adapter + the treasury scenario.

### Exists — the gateway and its primitives are built; this scenario consumes them
- **`crates/auths-mcp-core`** — the per-`tools/call` gate: scope ⊆ parent (AGT-1), the cross-rail
  quantitative budget, expiry, revocation, and signed receipts.
  - `budget.rs` — the **`CrossRailBudget` / `SettledCounter`**: the verifier-held monotonic
    **settled** high-water (rollback-protected → `UsageCounterRolledBack`) + transient **reserved**
    holds (`available = cap − settled − Σ holds`), checkpoint-anchorable digest (D8). *This is
    exactly the principal-cap engine; "deployed principal" is the cents it sums.*
  - `gate.rs` — the per-call scope/cap/expiry/revocation gate returning the distinct verdicts.
  - `rail.rs` — the rail abstraction (where a **yield rail's cost/earnings extraction** plugs in,
    beside the existing Stripe/x402 extraction).
  - `receipt.rs` — the signed per-call receipt (the position-ledger row).
  - `paymode.rs` — the **real-by-default / test-opt-in PaymentMode** port + the mandatory-cap and
    disclosure obligations (AGENT-PAY-3).
- **`crates/auths-mcp-gateway`** — the real-MCP (`rmcp`) proxy + the `wrap` subcommand; `proxy.rs`,
  `replay.rs`, `transcript.rs`, `chain.rs` (the live wire + the hermetic replay-mode entrypoint the
  probes drive).
- **Delegated, scoped, capped agents** — `id agent add --scope --expires-in` →
  `auths_sdk::domains::agents` (`delegation.rs` / `scope.rs`: delegator-anchored seal, subset rule
  at issuance, TTL); `auths-sdk/src/domains/credentials/usage_ledger.rs` (the AGT-4 high-water
  ledger the cross-rail counter reuses).
- **Fail-closed verdicts** — `OutsideAgentScope`, `AgentExpired`, `UsageCapExceeded`,
  `UsageCounterRolledBack`, `Revoked` in `auths-verifier` / `auths-mcp-core`.
- **The custody broker + the trust split** — §12 of the gateway PRD: the gateway custodies the
  deploy credential; the agent holds only the delegation. Inherited wholesale.

### Build — the deliverables (one engine adapter in `auths`; the scenario in `auths-mcp`)
1. **The yield-rail cost/earnings extraction (`auths-mcp-core/src/rail.rs`, AGENT-YIELD-1).** Given
   a lending/staking **deposit/claim response** (the shape the wrapped yield MCP server returns),
   extract the **deployed-principal amount** (for `reserve`/`settle` against the cross-rail cap) and
   the **claimed-yield amount** (recorded as *earned*, not counted against the cap). A near-sibling
   of the existing Stripe `amount_captured` / x402 `maxAmountRequired` extractors — **bound, don't
   build**: `auths-mcp-core` holds zero yield-protocol code; the yield server stays a wrapped
   downstream. Authored against the documented response shapes of a lending/staking MCP server;
   hermetic over recorded fixtures.
2. **The treasury scenario config + harness** in `auths-mcp/examples/treasury` — a `treasury.config`
   (~20 lines) wrapping the lending + staking + redemption rails under one gateway with one
   `--scope`, one `--principal-cap`, one `--ttl`; the live show (a real model deploy/claim/compound
   loop) + the `--check` replay (the probe) over recorded transcript + rail-response fixtures.
   Built, gated, and committed in `auths-mcp` (the `[sculpts.auths-mcp]` tree).
3. **The P&L receipt projection (AGENT-YIELD-5)** — a tiny reader over the receipt stream that
   reconstructs `principal_deployed / yield_claimed / net_position / x402_earned`, so the demo can
   *show* the verifiable position ledger; pure read over receipts, no new crypto.

Any surface that already suffices end-to-end at baseline → reclassified to a **closed regression
guard** (the DOTAK precedent), never dropped. If AGENT-YIELD-1's extraction turns out to be a
trivial reuse of the Stripe/x402 path, its gap reclassifies to a guard that the yield response
shape is metered identically.

---

## 6. Non-goals — and the honest limits of what auths bounds

- **NOT a yield strategy and NOT alpha.** auths picks no markets, predicts no rates, and makes no
  return. The agent brings the strategy; auths bounds the principal at risk and receipts the
  positions. *Stated plainly so it is never mistaken for a money-maker: auths is the safety + the
  rails, not the edge.*
- **NOT a guarantee the yield is safe.** **Smart-contract / protocol risk is real and outside
  auths's reach** — an exploited lending contract, a bridge failure, a malicious upgrade can lose
  deployed principal regardless of any cap. auths bounds **how much principal is *exposed*** (the
  cap = max deployed = max drawdown to protocol risk) and gives a **verifiable record of exactly
  what was deployed where**; it does **not** make the protocol solvent.
- **NOT de-peg protection.** If the deployed stablecoin **de-pegs**, the dollar value of a
  position can fall even though the cap (denominated in the asset's units) was honored. auths
  caps the *units deployed* and receipts them; it does not insure their market value. Disclosed on
  screen.
- **NOT a fund custodian or a wallet.** auths never holds funds and never settles. The gateway
  *custodies the deploy credential* and *bounds spend authority*; the rails move the money. Recall
  of already-deployed principal is the agent's bounded `redeem` scope or the owner's own custody
  key — **revoke clamps new deployment instantly; it does not auto-unwind a settled on-chain
  position** (the §2 clawback is of *authority*, with bounded recall, not a guaranteed instant
  liquidation).
- **NOT a per-call chain write.** The cross-rail counter is checkpoint-anchored (D8); between
  checkpoints, un-exceedability leans on the verifier's counter (the gateway §12 split), and on a
  counter-integrity failure **max uncaught over-deployment ≤ one checkpoint interval — detection is
  not reversal.** For a high-value treasury, set the checkpoint interval to per-deploy for a
  zero window.
- **NOT a live LLM in the gate.** Following the gateway's stance: the live model run is
  evidence-only and **test-mode** (testnet/Stripe-test, no real money); the gate runs the recorded
  transcript + recorded rail-response fixtures. Disclosed on screen.
- **NOT a new rail.** Each yield rail is a wrapped downstream MCP server; `auths-mcp-core` stays
  rail-agnostic and payment-protocol-free (bound, don't build).
- **NOT a perf claim.** Per-deploy sign+verify latency is noted, not the property; correctness of
  the principal-cap containment + revocation is.

---

## 7. The harness / dramaturgy

Two modes, one gateway — shipped in `auths-mcp/examples/treasury` (the product's own example, **not**
`auths-demos`). `./run.sh` (the live show, **test-mode**), `./run.sh --check` (the hermetic gate),
`./run.sh reset`. Auto/non-TTY plays itself.

- **Act 1 — The treasury, and the box you put around the agent.** Show the owner minting the
  agent's delegation: `scope = {lend.deposit, stake.deposit, yield.claim, redeem.to_treasury}`,
  `principal_cap = $50,000`, `ttl = 7d`, anchored in the owner's KEL (`git log refs/auths/*` shows
  the anchor). Disclose the honesty up front: **`--test-mode`** (testnet USDC / Stripe-test
  settlement, *no real money*), and the banner prints `mode=test` (the inverted default would be
  real — AGENT-YIELD-6). Pledge: *the agent never holds the wallet; it holds only this delegation,
  and the gateway custodies the deploy key.*
- **Act 2 — It deploys, and earns.** The agent's live loop deposits `$10k` into the lending market
  and `$5k` into staking — each call brokered, metered, receipted; the running **cumulative
  deployed principal** prints from the chain, not from the agent. Then it **claims yield** and
  **re-deploys** it: *the box earns and compounds.* The honest framing: *every deploy is
  re-verified from the chain, and every dollar is in a signed receipt — a P&L you can verify
  offline.*
- **Act 3 — The cap is the max drawdown (the cross-rail beat).** The agent, over-eager (or
  injected), tries to push past `$50k` — `$49k` already lent `+ a new $2k` stake. **Pledge before
  proof:** "each venue's own limit reads 'under,' but the *agent* has deployed `$51k`; expect
  refusal." The gateway refuses **`UsageCapExceeded`** on the staking rail *before the deposit is
  made* — one cross-rail ceiling, the owner's true max drawdown. *(Sub-agent variant: a `$10k`-slice
  sub-agent is refused at its slice on either rail.)*
- **Act 4 — The drain that couldn't (out of scope).** The agent goes wrong — bug / injection /
  over-eager — and emits `withdraw.to_external(<attacker_addr>)`. **Pledge:** "its signature is
  valid, its delegation is valid; it is trying to move funds *off* to an address your delegation
  never anchored. Expect rejection." → **`OutsideAgentScope`**, naming `withdraw.to_external`, the
  rail never called.
- **Act 5 — The clawback (revoke mid-loop).** While the compounding loop runs, the owner hits
  **revoke**. The very next deploy call → **`Revoked`**, no window. "New deployment stops on the
  next call, everywhere at once; the receipts make the exact position provable for recall." (Honest
  note on screen: revoke clamps *new* deployment; recall of deployed principal is the bounded
  `redeem` path.)
- **Act 6 — The verifiable P&L.** Replay the receipt stream offline: `principal_deployed`,
  `yield_claimed`, `net_position`, `x402_earned` — each `auths verify`-accepted, each attributable
  to the exact grant. Close on the line: **"Every signature here was valid. Three were still
  refused — because a child cannot deploy more principal than its parent anchored, cannot reach a
  capability it was never given, and stops the instant it's revoked — checked on every deploy, from
  the chain alone, offline. The agent brought the strategy. auths bounded the downside, gave the
  clawback, and signed the P&L. That is what makes delegating real capital to an agent thinkable."**

The climax is Act 3 + Act 5: a **valid signature, refused** because it would breach the drawdown
cap, and an **instant clawback** mid-loop — the two beats that turn "never hand an agent your
wallet" into "delegate, bounded."

---

## 8. Success metrics

The show and the probes assert these verdicts (not timings):

- **M1 (metered + receipted):** an in-cap deposit round-trips through the gateway to the wrapped
  yield rail, its deployed principal is reserved/settled into the cross-rail counter, and the
  receipt — carrying the running cumulative deployed total — is independently `auths verify`-accepted
  (AGENT-YIELD-1).
- **M2 (cross-rail drawdown cap):** with one `$50k` cap spanning lending + staking, the deposit that
  would *reserve past* it — on *either* rail — is refused `UsageCapExceeded` before the rail is
  touched; `$49k`-lent `+ $2k`-staked is refused where two siloed venue caps each read "under";
  the **combined** total is in the receipts (AGENT-YIELD-2). *The signature was valid.*
- **M3 (scope, distinct verdict):** `withdraw.to_external` is refused `OutsideAgentScope` **before
  the rail is invoked** (AGENT-YIELD-3).
- **M4 (instant clawback):** the first deploy call after a mid-loop revocation is refused `Revoked`,
  no window (AGENT-YIELD-4).
- **M5 (earns, compounds, verifiable P&L):** the receipt stream reconstructs a coherent
  `principal_deployed / yield_claimed / net_position / (x402_earned)` ledger, each receipt
  verify-accepted; a tampered receipt fails; a compounding redeploy past the cap is still refused
  (AGENT-YIELD-5).
- **M6 (real-by-default, cap mandatory, mode disclosed):** wrapping a yield rail without a cap is
  refused `budget-required` in both modes; the resolved `mode=real|test` is disclosed; the show runs
  `mode=test` (AGENT-YIELD-6).
- **M0 (the meta-metric):** a treasury owner can put the gateway in front of real yield rails and
  **delegate real capital to an autonomous agent with a provably bounded drawdown, a one-call
  clawback, and a verifiable P&L** — the profit-center bar the cost-center framing (and the
  scripted demos) can't reach.

Every verdict is produced by real `auths-mcp-core` / `auths-verifier` code over real KEL/TEL events;
every rail response in the gate comes from a recorded fixture and in the show from a real test-mode
rail. Nothing about the *enforcement* is mocked. (The model is real in the live show and a recorded
transcript in gate mode — disclosed.)

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): canonical fields
`class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with `evidence`
(file:line into the target) and `unlocks` (what gets stronger). The **accept + adversarial paths
live in each probe** (the probe contract: an accept path + a `.trap/` counterexample) and are
specified per-FR in §4 — *not* in the gap entry. IDs `AGENT-YIELD-*`; `reads: gateway` names the
content-hash rule over the built `auths-mcp-gateway` binary (gateway PRD §10). `AGENT-YIELD-1` is
the load-bearing build; reclassify any claim already GREEN at baseline to a `closed` regression
guard (the DOTAK precedent). Probes drive the gateway in **replay mode** over recorded transcript +
rail-response fixtures (hermetic; **no live money**).

```yaml
- id: AGENT-YIELD-1
  title: "The yield rail is metered — the gateway extracts deployed principal from a lending/staking deposit response and reserves/settles it against the cross-rail cap"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Build the gateway-side yield-deposit cost extraction (auths-mcp-core/src/rail.rs): given a
    lending/staking deposit RESPONSE (the shape a wrapped yield MCP server returns), extract the
    deployed-principal amount (atomic USDC, 6 decimals -> cents) and RESERVE it before the rail is
    touched / SETTLE the actual after into the cross-rail CrossRailBudget (budget.rs), and extract
    the claimed-yield amount on a claim response as EARNED (recorded, not counted against the cap).
    A near-sibling of the Stripe amount_captured / x402 maxAmountRequired extractors. auths-mcp-core
    holds ZERO yield-protocol code; the yield server stays a wrapped downstream — bound, don't build.
  unlocks: "A real deploy decision is bounded by the drawdown cap at the MCP boundary — the floor for YIELD-2..6; AGT-4/D8 caps bind a yield rail."
  evidence:
    - "maps gateway PRD §11 (bound, don't build) + AGT-4/D8; auths-mcp-core/src/rail.rs meters Stripe/x402 but has no extractor for a yield deposit/claim response (deployed principal / claimed yield)"
    - "hermetic over recorded lending/staking deposit + claim fixtures authored against the wrapped yield MCP server's documented response shapes — no live deploy, no real money"
  covers: [yield-rail-metering, budget-boundary]
  probe: probes/agent-yield-1.sh

- id: AGENT-YIELD-2
  title: "One cross-rail principal cap is the max drawdown across lending AND staking"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Sum deployed principal across the lending and staking rails into ONE CrossRailBudget keyed to
    the agent delegation (reuse budget.rs settled/reserved): a deposit that would reserve PAST the
    cap on EITHER rail is refused UsageCapExceeded before the rail is touched, even when a per-venue
    silo reads in-budget; a settle below the high-water is UsageCounterRolledBack; a sub-agent's
    slice is provably un-exceedable on any rail. The single cross-rail ceiling IS the owner's max
    acceptable drawdown.
  unlocks: "The cap = max drawdown across every yield rail at once — the property a per-venue limit cannot express (the moat)."
  evidence:
    - "maps AGENT-MCP-3 -> AGT-4/D8; budget.rs CrossRailBudget already sums rails — this binds the lending+staking rails to one principal cap"
  covers: [budget-boundary, cross-rail-moat]
  probe: probes/agent-yield-2.sh

- id: AGENT-YIELD-3
  title: "Recall/withdraw to an external address is out of scope and refused with the distinct OutsideAgentScope verdict"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Map withdraw.to_external to a capability and enforce it against the agent's delegator-anchored
    scope in the per-call gate (gate.rs): an agent holding {lend.deposit, stake.deposit, yield.claim,
    redeem.to_treasury} but NOT withdraw.to_external is refused OutsideAgentScope (naming the
    capability) and the rail is NOT called — moving funds off to an unanchored address is authority
    the delegation never held.
  unlocks: "The drain-the-treasury move (off to an attacker address) is structurally unreachable — scope (AGT-1) bounds capital movement, not just commits."
  evidence:
    - "maps AGT-1; OutsideAgentScope exists in auths-verifier/auths-mcp-core gate.rs — this wires the off-ramp capability to the yield scenario"
  covers: [scope-boundary]
  probe: probes/agent-yield-3.sh

- id: AGENT-YIELD-4
  title: "Revocation is instant clawback of deploy authority mid-loop with no propagation window"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Re-derive liveness from the KERI registry on every deploy tools/call (reuse the keri revocation
    check) so the first deploy after a mid-loop revocation event is refused Revoked — no cached token
    TTL, no introspection lag. Honest bound: revoke clamps NEW deployment instantly; recall of
    already-deployed principal is the bounded redeem scope (detection/receipts make the position
    provable for recall) — NOT an auto-unwind.
  unlocks: "OPS-1 instant kill = a one-call clawback of a running capital-deploying agent's authority."
  evidence:
    - "maps OPS-1; the gateway already re-derives revocation per tools/call — bind it to the yield deploy loop"
  covers: [revocation-boundary]
  probe: probes/agent-yield-4.sh

- id: AGENT-YIELD-5
  title: "The agent earns and compounds, and the receipt stream is a verifiable P&L that cannot be inflated"
  class: missing-surface
  status: open
  severity: feature
  reads: gateway
  smallest_fix: >
    Project the signed per-call receipt stream into a P&L (principal_deployed / yield_claimed /
    net_position / x402_earned): a claimed-and-redeployed amount is metered as new deployment under
    the same cap (compounding does not escape the drawdown bound); an inbound x402 receipt is recorded
    as EARNED, not counted against the spend cap; each receipt is independently auths verify-accepted.
    A tampered receipt (overstated yield, or a dropped deploy) fails verification.
  unlocks: "The profit-center proof: a verifiable, attributable P&L of a capital-deploying agent — earnings legible, drawdown still bounded."
  evidence:
    - "maps the profit-center property; receipt.rs emits signed per-call receipts — this projects them into an attributable position ledger (no new crypto)"
  covers: [verifiable-pnl, real-and-reproducible]
  probe: probes/agent-yield-5.sh

- id: AGENT-YIELD-6
  title: "Real capital by default, test-mode for the show, the principal cap is the mandatory seatbelt, and the mode is disclosed"
  class: missing-surface
  status: open
  severity: headline
  reads: gateway
  smallest_fix: >
    Resolve the yield rails through the inherited PaymentMode port (paymode.rs, AGENT-PAY-3): no flag
    -> REAL capital (mainnet/live rail); --test-mode -> testnet/Stripe-test. The gateway REFUSES to
    wrap a yield rail without a --principal-cap (fail-closed budget-required) in BOTH modes (the
    drawdown seatbelt cannot be skipped), and DISCLOSES the resolved mode=real|test on the receipt and
    the wrap --show-mode dry-run (real capital is never silent). Hermetic over the resolve+disclose
    dry-run — never a live deploy.
  unlocks: "An operator can default to REAL capital safely — real is the default, the drawdown cap is a mandatory seatbelt, the mode is never silent; the show opts into test."
  evidence:
    - "maps AGENT-PAY-3 (inherited); paymode.rs carries the real-by-default/mandatory-cap/disclosure contract — this binds it to the yield rails and the --principal-cap flag"
    - "hermetic over a mode-disclosure / dry-run surface (wrap --show-mode); fixtures under probes/fixtures/yield-mode-{real,test,cap-omitted}.expected.json — no live deploy"
  covers: [budget-boundary, payment-mode]
  probe: probes/agent-yield-6.sh
```

---

*Drafted 2026-06-15. A **profit-center** agent scenario in the house format of the
`agent_demos/` (mirrors `the-intern-that-couldnt`), riding the bounded-agent gateway product
(`prds/go_to_market/auths-mcp-gateway.md`) and consuming its already-closed primitives — the
cross-rail cap (AGENT-MCP-3 ↦ AGT-4 / D8), scope (AGT-1), revocation (OPS-1), receipts, and the
PaymentMode contract (AGENT-PAY-3). The single net-new engine surface is the yield-rail
cost/earnings extraction (AGENT-YIELD-1); the rest is the treasury scenario config + the P&L
receipt projection, shipped in `auths-mcp/examples/treasury` (multi-tree, gateway PRD §10) — nothing
lands in `auths-demos`. Surfaces named against `../auths` @ `dev-privacy`; exact paths pinned during
the sculpt. Honest throughout: **auths is the safety + the rails, not the alpha** — it bounds the
principal at risk, gives a one-call clawback, and signs the P&L; it does not make the yield safe
(protocol/smart-contract risk and de-peg are §6 constraints) and it does not make the strategy
profitable. The agent brings the alpha; auths makes delegating real capital to it thinkable.*
