# PRD: The Agent Treasury — a fund-of-agents whose max drawdown is cryptographic

> **One line:** a **manager** agent runs a capped treasury and **allocates capital across a
> swarm of bounded revenue sub-agents** (a flip-bot, a self-monetizing x402 service, a yield
> farmer, an arbitrageur), handing each a **provable slice** by sub-delegation — and the
> **aggregate cap** guarantees the worst case is *"down ≤ your cap,"* never *"wiped out."*
> The manager **rebalances toward winners** — pulling capital from the losers, feeding the
> earners — driven by **signed per-agent P&L receipts**, not by trusting any agent's
> self-report. An autonomous fund whose **max drawdown is cryptographic** and whose **books
> are verifiable**.
>
> **Be honest up front — auths is the safety + the rails, NOT the alpha.** auths does *not*
> make any strategy profitable. The sub-agents bring the alpha (or don't); auths makes it
> *safe to delegate real capital* to an agent that runs a strategy: the budget cap **is** the
> max drawdown, custody means **the agent never holds your wallet** (only a bounded spend
> authority), **instant revoke is clawback**, the **aggregate cap** bounds a whole fleet by
> your total risk, and **signed receipts are a verifiable P&L**. And x402 pay-per-request lets
> a sub-agent **earn** (an inbound revenue stream), not only spend. The pitch is not "auths
> prints money" — it is **"now you can let an agent run real capital, because the downside is
> provably bounded and the books can't lie."**
>
> **What this is.** A **go-to-market product** and the **headliner of the fund-of-agents**
> family: the manager + sub-agent allocation + rebalancing + a dashboard, riding on the
> bounded-agent MCP gateway (`auths-mcp-gateway.md`) — *each sub-agent is a bounded auths-mcp
> gateway agent* — and on the `auths` engine. It is a **new base repo**,
> `agent-treasury`, which DEPENDS ON `auths-mcp` (the gateway wrapper) and `auths` (the
> engine). Nothing lands in `auths-demos`.
>
> **Status — honest.** The load-bearing claim **AGENT-TREASURY-1** is **RED today for a real
> engine reason**: the budget cap in auths is **per-delegation** (one agent, one cap). A
> treasury needs **aggregate-capped *reallocation*** — a manager moving a *slice* from
> sub-agent A to sub-agent B while the **sum provably stays ≤ the parent budget**, each slice
> independently revocable. Scope *attenuation* exists; a **quantitative aggregate cap across
> sub-agents that is *reallocatable*** is the likely **net-new primitive in auths**. This PRD
> names exactly what GREEN requires.
>
> **Authoring scope:** READ-ONLY on `../auths` and `../auths-mcp` for this PRD. The recurve
> loop is **multi-tree** (§10): `[target] = agent-treasury` (the manager/allocation/dashboard,
> sculpted + read by probes), `[sculpts.auths] = ../auths` (the engine — where the aggregate
> cap is built), `[sculpts.auths-mcp] = ../auths-mcp` (the gateway wrapper). One ledger, one
> federated gate. Hermetic probes — **recorded fixtures, no live money**.

---

## 1. One line + scenario

A capital allocator — a fund, a desk, a solo operator — wants to run **autonomous revenue
agents** but cannot, today, hand an agent **real capital**: an API key or a hot wallet is
*all-or-nothing*, a bug or a prompt injection can drain it, and there is no provable ceiling
on the loss. So agentic "funds" stay paper, or stay tiny, or stay manual.

Now stand up an **agent treasury**. A human (or an orchestrator) mints a **manager** agent a
delegation with a **treasury cap** — say `$10,000`, anchored in the human's KEL. The manager
runs a **swarm of revenue sub-agents**, each a bounded `auths-mcp` gateway agent:

- a **flip** sub-agent (buy-low/sell-high across a metered market MCP),
- a **self-monetizing x402** sub-agent (it *sells* a service over x402 — an **inbound** USDC
  stream),
- a **yield** sub-agent (deposits into a metered yield venue),
- an **arbitrage** sub-agent (cross-venue spread capture).

The manager hands each one a **slice** of the treasury by **sub-delegation/attenuation**:
`flip ≤ $4,000`, `x402 ≤ $1,000`, `yield ≤ $3,000`, `arb ≤ $2,000`. Two invariants the
human is promised, and that the *verifier* enforces from the chain alone:

1. **Aggregate cap.** `Σ slices ≤ $10,000`, *always* — the worst case across the entire
   swarm is **down ≤ $10,000**, never wiped out. No combination of sub-agents, no
   reallocation, no race, can make the swarm's committed authority exceed the parent.
2. **Reallocatable.** The manager **rebalances**: the `yield` agent is flat, the `flip` agent
   is up 8% — so the manager **pulls $2,000 from `yield` and feeds it to `flip`**. The move is
   atomic at the cap: `flip`'s slice rises to `$6,000`, `yield`'s falls to `$1,000`, and the
   **sum is still ≤ $10,000** at every instant. Each slice stays **independently revocable**.

The signal the manager rebalances on is **not** an agent's self-report. Every brokered
spend/earn is a **signed per-call receipt** (`auths-mcp`'s receipt), so each sub-agent has a
**signed, independently-verifiable P&L** — *who* spent/earned, *under which slice*, *on what
action*, with *what verdict*. The manager (and an auditor, and an underwriter) reads the
**verifiable books**, not the agent's word, to decide who gets more capital and who gets cut.

**The realistic failure, driven by the swarm itself.** A sub-agent is buggy, injected, or
just greedy and tries to spend past its slice — **refused** at the gateway (`auths-mcp`'s
`UsageCapExceeded`). Worse, the **manager** itself over-reaches: it tries a reallocation that
would push `Σ slices` to `$11,000` (feed a winner without first pulling from a loser). **That
reallocation is refused** — the sum would exceed the parent cap, so it does not commit. The
human's `$10,000` ceiling holds **even against the manager**.

**How it breaks today.** Give four bots four API keys and a shared wallet and there is **no
aggregate ceiling** — each key is all-or-nothing, the "fund's total risk" lives only in
hope and app logic, and a single compromised bot drains everything. Per-card processor
budgets (Stripe Issuing) can cap *one card*, but cannot express *"these four agents together
≤ $10k, and I can move budget between them without ever exceeding the total."* And none of
them give you a **verifiable P&L** to rebalance on, or **instant cross-fleet clawback**.

**What auths does.** The treasury cap is a **quantitative aggregate cap** anchored in the
parent's KEL; each sub-agent's slice is a sub-delegation **attenuated** under it; the
verifier enforces, on every call and every reallocation, that `Σ slices ≤ parent_cap` and
that each call is within its own live slice — **from the chain alone, offline**. Revoke is a
chain event: one revoke stops a sub-agent's spend **everywhere at once** (clawback). The
P&L is the stream of **signed receipts**. *The agent brings the alpha; auths bounds the
downside, gives instant clawback, and a verifiable P&L.*

---

## 2. The property it proves

**A swarm of autonomous capital agents whose aggregate downside is cryptographically
bounded, whose budget is *reallocatable* across the swarm without ever exceeding the parent
cap, and whose P&L is verifiable from signed receipts — all enforced at the verify boundary,
offline, from the chain alone.**

Concretely: (a) every sub-agent's slice is `≤` its parent and `Σ slices ≤ parent_cap` at all
times; (b) a manager **reallocation** that moves a slice from A to B commits **only if** the
post-move sum still `≤ parent_cap`, atomically, each slice still independently revocable; (c)
a reallocation that would let `Σ slices` exceed the parent is **refused** (the headline
adversarial twin); (d) one revoke stops a sub-agent everywhere; (e) the P&L is a stream of
signed receipts an underwriter can verify without trusting the manager.

**This is the line auths can state and no incumbent can:** *"the maximum this autonomous fund
can lose is `$X`, cryptographically — not because we configured it carefully, but because no
sub-agent, no reallocation, and no compromise can make the swarm's committed authority exceed
`$X`, and a stranger can verify that offline."* That is what makes a fleet of capital agents
**insurable** and a fund-of-agents **fundable**.

**Why incumbents structurally can't match it:**

| Incumbent | Where the "fund total" lives | Why it can't bound a *reallocatable* swarm |
|---|---|---|
| **N API keys / a shared hot wallet** | nowhere — each key is all-or-nothing, the wallet is total authority | No aggregate ceiling at all. "The fund's max loss" is app logic + hope; one compromised bot drains the wallet. No attenuation, no per-slice revoke, no verifiable P&L. |
| **Per-card processor budgets** (Stripe Issuing) | a cap per card, in the processor's central evaluator | Caps *one card*. Cannot express "these N agents together ≤ `$X`," cannot move budget between cards while holding the sum, is single-rail (no x402/USDC), routes trust through the processor, and emits no cross-rail verifiable P&L. |
| **IAM service-control / budget policies** (AWS Budgets, SCPs) | a policy document in the provider's evaluator | Budgets are *alerting*, not *prevention* (they notify after spend), evaluated by the provider's central engine against policies the provider mutates; a stranger can't re-derive the aggregate containment cryptographically, and there's no per-sub-agent attenuated slice you can revoke and re-allocate at the verify boundary. |
| **Treasury / OTC desks (human)** | a mandate in a contract + a human's discretion | Not autonomous, not per-call, not cryptographic; "max drawdown" is a promise, not a proof; the books are the desk's word, audited after the fact. |

None of the four lets a **stranger relying party** (an underwriter, an LP, an auditor),
offline, prove from signatures alone that **the sum of a reallocatable swarm's live spend
authority never exceeds the parent cap** and that **the P&L is real**. That is the property,
and it is the property that makes the max drawdown of an autonomous fund a *number you can
underwrite*, not a number you hope holds.

---

## 3. Goals — what makes it believable

- **G1 — A real swarm under a real aggregate cap.** A genuine chain
  **human → manager → {flip, x402, yield, arb}** sub-agents, each a real KERI sub-delegation
  anchored in the manager's KEL, each handed an attenuated quantitative slice, with the
  treasury-level invariant `Σ slices ≤ parent_cap` **enforced by the verifier**, not asserted.
  The audience can `git log` the anchors and read each slice back from the *manager's* KEL.
- **G2 — Reallocation that provably can't breach the cap.** The manager moves a slice from a
  loser to a winner; the post-move sum is re-checked `≤ parent_cap` and commits atomically.
  The compelling beat is the *refused* reallocation: a move that would push `Σ slices` over
  the parent is rejected — **the human's ceiling holds even against the manager.**
- **G3 — Rebalancing on a verifiable P&L, not a self-report.** The manager's allocation
  decision is driven by the **signed per-agent receipts** (spend *and* x402 inbound earn),
  not by any agent claiming "I'm up." The dashboard shows the P&L an auditor would
  independently verify; the manager pulls from the losers and feeds the earners on that
  signal.
- **G4 — Earn, not only spend (x402 inbound).** At least one sub-agent (the self-monetizing
  x402 service) produces an **inbound** revenue stream of signed receipts, so the P&L has a
  credit side — the treasury *grows* from agent revenue, and that growth is as verifiable as
  the spend.
- **G5 — Custody + clawback are visceral.** The sub-agents never hold the treasury's wallet —
  the gateway **custodies** the downstream credential; each agent holds only its bounded slice
  authority. A `revoke` is **clawback**: the targeted sub-agent's *next* call fails on every
  rail at once, mid-run, no window. *Down ≤ your cap; cut anyone instantly.*

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an **adversarial
twin (fail-closed)**. IDs `AGENT-TREASURY-*`. They reuse the closed MCP-gateway primitives
(**AGENT-MCP-1** brokered+receipted, **AGENT-MCP-3/AGT-4** caps, **AGENT-MCP-4/OPS-1**
revocation) and the attenuation primitive (**AGT-1 / AGENT-ATTEN-3**). **AGENT-TREASURY-1 is
the load-bearing build: the net-new aggregate-capped *reallocation* primitive in `auths`.**
All probes are **hermetic — recorded fixtures, no live money** (§7).

- **AGENT-TREASURY-1 — Aggregate-capped reallocation: a manager moves a slice from A to B and
  the sum provably stays ≤ the parent cap (THE BUILD / load-bearing).**
  *Maps: NEW engine primitive in `auths` — a quantitative aggregate cap across sub-delegations
  that is reallocatable, on top of AGT-1 attenuation + AGT-4 quantitative caps.* The manager
  holds a treasury cap `$10,000` and sub-delegates four slices summing to `$10,000`; it then
  **reallocates** `$2,000` from `yield` to `flip` (yield `$3,000→$1,000`, flip `$4,000→$6,000`).
  - **Observable (accept):** the four initial slices verify and `Σ slices = $10,000 ≤ cap`;
    the reallocation commits atomically; post-move `flip=$6,000`, `yield=$1,000`,
    `Σ slices = $10,000 ≤ cap`; each slice remains independently revocable; a brokered call
    under the *new* `flip=$6,000` slice (between `$4,000` and `$6,000`) now passes.
  - **Adversarial twin:** a reallocation that **feeds a winner without first pulling from a
    loser** — raising `flip` to `$6,000` while `yield` stays `$3,000`, so `Σ slices = $12,000 > $10,000`
    — is **refused** with a distinct verdict (`AggregateCapExceeded`), and **does not
    commit** (the swarm's committed authority is unchanged); equivalently, the manager
    attempting to issue a *fifth* slice when the four already sum to the cap is refused.
    *No combination, no race (concurrent reallocations are serialized at the cap), lets
    `Σ slices` exceed the parent.*

- **AGENT-TREASURY-2 — A sub-agent provably cannot exceed its own slice (per-slice spend
  cap).** *Maps: AGENT-MCP-3 / AGT-4 at the gateway boundary, attenuated per sub-agent.* The
  `flip` sub-agent holds a `$4,000` slice and runs a metered market MCP behind its gateway.
  - **Observable (accept):** calls whose reserved cost keeps the slice's settled total `≤ $4,000`
    pass and settle; the running per-slice total is in each receipt.
  - **Adversarial twin:** the call that would reserve the slice **past `$4,000`** is refused
    `UsageCapExceeded` **before the rail is touched** (never settled), even though the *parent*
    treasury still has headroom — a sub-agent is bounded by *its* slice, not the treasury total.
    *A `$2` sub-agent handed by attenuation cannot exceed `$2` on any rail.*

- **AGENT-TREASURY-3 — The P&L is a stream of signed receipts the manager rebalances on, and
  it can't be forged.** *Maps: AGENT-MCP-1 (signed per-call receipts).* Each sub-agent's
  spend and (for x402) earn produces a signed receipt; the manager's allocation is a function
  of the **verified** per-agent net.
  - **Observable (accept):** for a recorded run, each sub-agent's receipts independently
    `auths verify`; the dashboard's per-agent P&L equals the sum over *verified* receipts
    (`device=sub-agent`, `identity=manager-root`); the manager's reallocation (TREASURY-1) is
    the one its P&L inputs imply (pull from the lowest net, feed the highest).
  - **Adversarial twin:** a sub-agent that **self-reports** a higher P&L (a transcript edited
    to inflate earn, or a receipt with a forged/missing proof) is **rejected** at verify and
    **excluded** from the rebalancing signal — the manager moves capital on the *verified*
    books only; a forged "I earned `$500`" receipt does not move a dollar.

- **AGENT-TREASURY-4 — x402 inbound: a sub-agent *earns*, and the credit lands in the
  verifiable P&L.** *Maps: AGENT-PAY-2 (x402 rail) on the credit side.* The self-monetizing
  x402 sub-agent *sells* a service; an inbound x402/USDC settlement is metered as a **credit**
  in its P&L (testnet-flagged; hermetic over a recorded settlement fixture).
  - **Observable (accept):** a recorded inbound x402 settlement is extracted (atomic USDC →
    cents), credited to the sub-agent's receipted P&L, and raises its net — increasing its
    share in the next rebalancing; the inbound amount is in the receipt (`direction=inbound`,
    `rail=x402`).
  - **Adversarial twin:** an inbound receipt with a settlement amount not matching the
    recorded x402 `SettlementResponse` (a padded credit) is rejected — earn is metered from
    the *recorded settlement*, not the agent's claim; a fabricated inbound stream cannot pump
    a sub-agent's allocation. **LIVE-SCOPE FLAG:** a live x402 inbound leg needs a funded USDC
    testnet wallet (base-sepolia) — out of hermetic scope, evidence-only, deferred; the probe
    proves credit-extraction + P&L crediting only.

- **AGENT-TREASURY-5 — Instant clawback: revoking a sub-agent stops its spend everywhere and
  returns its slice to the treasury's free pool.** *Maps: AGENT-MCP-4 / OPS-1.* The manager
  (or human) revokes the `arb` sub-agent mid-run.
  - **Observable (accept):** `arb`'s calls before the revoke pass; after the revoke its slice
    is released so the **freed `$2,000` is re-allocatable** under the aggregate cap (it can be
    fed to a survivor without breaching `Σ slices ≤ parent_cap`).
  - **Adversarial twin:** the **very next** brokered call by `arb` after the revocation event
    is refused `Revoked` — no token still valid for its TTL, no introspection lag; and a
    reallocation of the freed slice that would *still* exceed the parent (because the freed
    amount was double-counted) is refused `AggregateCapExceeded`. *One revoke = clawback,
    everywhere, instantly; the freed budget can be recommitted but never over-committed.*

- **AGENT-TREASURY-6 — Depth attenuation: a sub-agent cannot sub-delegate more than it holds
  (the swarm can nest).** *Maps: AGT-1 / AGENT-ATTEN-3 (subset rule at issuance), quantitative.*
  The `flip` sub-agent (holding `$4,000`) spins up its own child worker.
  - **Observable (accept):** `flip` sub-delegating a child `$1,500` (a subset of its slice)
    succeeds; the child's in-slice calls verify; `flip`'s own `Σ child slices ≤ $4,000` holds.
  - **Adversarial twin:** `flip` sub-delegating a child `$5,000` (more than `flip` holds) is
    **refused at issuance** by the subset rule, and a hand-forged child slice seal not signed
    by `flip`'s key fails verify — a mid-swarm key-holder cannot mint budget it was never
    given, at any depth. *The aggregate cap holds transitively down the tree.*

---

## 5. The auths surfaces — exists vs build

Named against `../auths` @ `dev-privacy` and `../auths-mcp` @ `main`; exact paths pinned
during the sculpt (this PRD is read-only). **Pre-launch ⇒ no back-compat: surfaces are
harvested and reshaped, not preserved.**

### Exists — the primitives this treasury composes
- **The bounded-agent MCP gateway** (`auths-mcp`, per `auths-mcp-gateway.md`): each sub-agent
  is a wrapped gateway agent — per-`tools/call` scope + budget + expiry + revocation, signed
  per-call receipts, the **custody broker** (the agent holds only its delegation, the gateway
  custodies the downstream credential), and the cross-rail counter (D8). The treasury's
  sub-agents *are* `auths-mcp wrap`'d processes; this PRD does not rebuild the gateway.
- **Delegated, scoped, sub-delegatable agents with the subset rule** —
  `id agent add --scope --expires-in` → `auths_sdk::domains::agents::add_scoped`
  (delegator-anchored seal; the subset rule at issuance hardened in `AGENT-ATTEN-3`). Gives us
  attenuation and depth for free — the *categorical* half of a slice.
- **The quantitative per-delegation cap (AGT-4)** — the verifier-held monotonic high-water
  usage ledger (`usage_ledger.rs`), rollback-protected (`UsageCounterRolledBack`),
  checkpoint-anchored, with the `UsageCapExceeded` verdict and the `AGENT-CAP-1` malformed-
  predicate issuance guard. Gives us the *quantitative* half of **one** slice.
- **Cross-rail metering** — AGENT-PAY-1 (Stripe-test), AGENT-PAY-2 (x402/USDC), the cross-rail
  `CrossRailBudget` (D8) summing spend across rails into one cap; AGENT-PAY-3 (real-by-default
  mode + mandatory-cap seatbelt + disclosure). Gives sub-agents real rails, capped.
- **Instant revocation (OPS-1)** — liveness re-derived from the KERI registry on every call;
  the `Revoked` verdict. Gives us per-slice clawback.
- **Signed per-call receipts (AGENT-MCP-1)** — `device`/`identity`/action/verdict, offline-
  verifiable with `auths verify`. Gives us the verifiable P&L's atoms.

### The load-bearing gap — what does NOT exist (the net-new engine primitive)
**Today the budget cap is PER-DELEGATION: one agent, one cap.** AGT-4's counter is keyed to
*a* credential; the cross-rail `CrossRailBudget` sums rails *within one agent's authority*.
There is **no aggregate cap across sub-delegations**, and **no reallocation** of budget between
sub-agents that holds the parent sum. Specifically, missing:

1. **An aggregate quantitative cap across a set of sub-delegations** — a parent-anchored
   ceiling `parent_cap` with the verifier invariant `Σ committed sub-slices ≤ parent_cap`,
   re-derivable offline from the parent's KEL alone (the categorical subset rule exists; the
   *quantitative sum* constraint does not).
2. **A reallocation operation** — an atomic move of `Δ` from sub-slice A to sub-slice B
   (`A -= Δ`, `B += Δ`) that **commits only if the post-move sum ≤ parent_cap**, is anchored
   as a parent KEL event (so it's verifiable + ordered), serializes concurrent moves at the
   cap (no race opens budget), and leaves each slice independently revocable — with a freed
   slice (on revoke) returning to the parent's *free pool* (`parent_cap − Σ live slices`)
   without double-counting.
3. **A distinct `AggregateCapExceeded` verdict** for a reallocation/issuance that would breach
   the parent sum (sibling to `UsageCapExceeded`, which is *within one* slice).

This is **AGENT-TREASURY-1**'s `smallest_fix` and lands in **`auths`** (the engine), reusing
AGT-4's ledger machinery (a parent-keyed aggregate counter beside the per-slice counters) and
the AGT-1 anchoring/subset path. It is the *likely net-new primitive in auths* the whole
fund-of-agents family needs.

### Build — the deliverables
1. **`auths` (engine, `[sculpts.auths]`): the aggregate-capped reallocation primitive** —
   the parent-anchored aggregate cap, the `reallocate(A,B,Δ)` operation with the
   `Σ ≤ parent_cap` invariant + serialization + free-pool accounting, the `AggregateCapExceeded`
   verdict, and the issuance guard that refuses an over-sum slice. Reuses `usage_ledger.rs` and
   the AGT-1 anchoring path; rollback-protected and checkpoint-anchored like AGT-4.
2. **`auths-mcp` (gateway wrapper, `[sculpts.auths-mcp]`): per-slice wiring** — surface the
   aggregate cap + reallocation to the sub-agent gateways so each wrapped sub-agent's
   per-`tools/call` budget reads its *current* slice (post-reallocation), and the cross-rail
   counter is keyed to the slice. Likely small (mostly consuming the new engine surface).
3. **`agent-treasury` (`[target]`, NEW base repo): the manager + swarm + dashboard.**
   - the **manager** — a scripted allocator that mints the treasury cap, sub-delegates the four
     slices, rebalances on the **verified** P&L (TREASURY-3), and issues `reallocate` /
     `revoke` operations;
   - the four **sub-agents** as `auths-mcp wrap` configs (flip / x402 / yield / arb);
   - the **dashboard** — a read-only view of the live tree (slices, free pool, per-agent
     verified P&L, the aggregate-cap invariant) rendered from receipts + the parent KEL;
   - the **harness**: live mode (a real model drives the manager's allocation decisions over a
     real tool loop) + **replay mode** (a frozen transcript drives the same operations to
     byte-stable verdicts — the hermetic probe entrypoint), and the staged `run.sh`.

If, during the sculpt, any claim already passes at baseline (e.g. per-slice caps via AGT-4),
reclassify it to a **closed regression guard** (the DOTAK precedent), never dropped. The
aggregate-cap primitive (TREASURY-1) is the one expected genuinely RED net-new build.

---

## 6. Non-goals

- **NOT alpha.** This PRD makes **zero** claim that any strategy is profitable. auths is the
  **safety + the rails** — bounded downside, clawback, verifiable books — *not* the trading
  edge. A losing swarm under this treasury still loses (down to ≤ the cap); auths guarantees
  the *bound* and the *books*, not the return. Stated plainly so no reader mistakes it.
- **NOT a custodian / wallet / exchange.** The treasury **bounds and receipts** spend/earn; it
  never holds funds or settles. Custody of the *downstream credential* is the gateway's
  custody-broker role (§12 of `auths-mcp-gateway.md`); custody of *funds* is the rail's.
- **NOT a new payment rail.** Rails (Stripe, x402/USDC, a metered venue) are **wrapped**
  downstream MCP servers (`auths-mcp` §11); `agent-treasury` holds zero payment code.
- **NOT live money in the gate.** Following the house stance: probes are **hermetic over
  recorded fixtures**. The live legs (a real model allocating, a funded x402 testnet wallet)
  are **evidence-only, never gated**, and disclosed on screen.
- **NOT a new agent framework.** The manager and sub-agents ride MCP + `auths-mcp`; this builds
  *allocation/rebalancing/dashboard* over them, not orchestration/planning/memory.
- **NOT a perf claim.** Reallocation/verify latency is noted, not the property; correctness of
  the aggregate-cap invariant is.
- **NOT model-quality claims.** Nothing asserts the manager allocates *well*; it asserts that
  whatever it decides, `Σ slices ≤ parent_cap` holds and the P&L it acts on is verified.

---

## 7. The harness / run.sh dramaturgy

Self-performing, staged in acts (like `death-of-the-api-key` / `the-intern-that-couldnt`):
`./run.sh` (the live show), `./run.sh --check` (the hermetic gate — replay mode, the recurve
probe entrypoint), `./run.sh reset` (pristine). Auto/non-TTY plays itself.

- **Act 1 — The treasury, signed.** A human mints the **manager** a `$10,000` treasury cap;
  the manager sub-delegates four slices — `flip $4k`, `x402 $1k`, `yield $3k`, `arb $2k` — each
  a real KERI sub-delegation anchored by an `ixn` in the manager's KEL.
  `git log --oneline refs/auths/*` shows the anchors; the dashboard shows
  `Σ slices = $10,000 ≤ $10,000 cap`, free pool `$0`. Disclose the one honesty: *intents are
  scripted (or a live model in show mode); every delegation, cap, receipt, and verdict is real.*
- **Act 2 — The swarm earns and spends, receipted.** Each sub-agent runs behind its gateway
  over a recorded fixture: `flip` and `yield` spend within slice (settled, receipted); the
  **x402** agent takes an **inbound** settlement (a *credit*). The dashboard shows a per-agent
  **verified** P&L — every line independently `auths verify`-able, not a self-report.
- **Act 3 — The over-spender (per-slice cap).** A sub-agent (bug / injection / greed) tries to
  spend past its slice → **`UsageCapExceeded`**, before the rail is touched, *even though the
  treasury has headroom*. A sub-agent is bounded by **its** slice.
- **Act 4 — The rebalance (the headline).** `yield` is flat, `flip` is up. The manager
  **pulls `$2,000` from `yield` and feeds `flip`** — driven by the **verified** P&L. The move
  commits atomically: `flip $4k→$6k`, `yield $3k→$1k`, `Σ = $10,000 ≤ cap`. **Pledge before
  proof:** *"watch the sum — it cannot exceed the human's `$10,000`, even when the manager
  reallocates."* A call now passes under the new `flip $6k` slice.
- **Act 5 — The manager overreaches (the unsee-able moment).** The manager tries to feed a
  winner **without pulling from a loser** — a reallocation that would push `Σ slices` to
  `$12,000`. **Refused: `AggregateCapExceeded`.** It does not commit; the dashboard sum is
  unchanged. *The human's ceiling holds even against the manager.*
- **Act 6 — The clawback.** The human **revokes** the `arb` sub-agent mid-run. Its next
  brokered call → **`Revoked`** (no window); its `$2,000` slice returns to the free pool and is
  **re-allocatable** to a survivor — but never *over*-committable (a double-count reallocation
  is refused). Close on the line:
  **"This swarm could earn or lose — auths makes no promise about which. What it proves: the
  most this fund can lose is its cap, no agent and no reallocation can breach it, the books
  are signed, and any one agent can be cut instantly. The agent brings the alpha; auths bounds
  the downside, gives instant clawback, and a verifiable P&L. That is the line no incumbent can
  state."**

The climax is **Act 5**: a manager — a legitimate, fully-signed actor — *refused* because its
reallocation would exceed the parent cap.

---

## 8. Success metrics

The show and the probes assert these verdicts (not timings):

- **M1 (aggregate cap holds, reallocation commits):** four slices verify with
  `Σ = parent_cap`; a manager reallocation of `Δ` between two slices commits atomically and the
  post-move sum is still `≤ parent_cap`; a call under the grown slice passes (TREASURY-1 accept).
- **M2 (over-sum reallocation refused, distinct verdict):** a reallocation/issuance that would
  push `Σ slices > parent_cap` is refused **`AggregateCapExceeded`** and does **not** commit —
  *the manager is a valid signer; the move is still rejected* (TREASURY-1 twin). **The headline.**
- **M3 (per-slice cap):** a sub-agent's call past its own slice is refused `UsageCapExceeded`
  before the rail is touched, even with treasury headroom (TREASURY-2 twin).
- **M4 (verifiable P&L drives rebalancing):** each receipt independently `auths verify`s; the
  dashboard P&L equals the verified-receipt sum; a forged/self-reported P&L is excluded from
  the rebalancing signal (TREASURY-3).
- **M5 (x402 inbound earn):** a recorded inbound x402 settlement is credited to the
  sub-agent's verified P&L and raises its allocation share; a padded credit is rejected
  (TREASURY-4).
- **M6 (clawback + free-pool):** the next call after a mid-run revoke is refused `Revoked`; the
  freed slice is re-allocatable but a double-counting reallocation of it is refused
  `AggregateCapExceeded` (TREASURY-5).
- **M7 (depth attenuation):** a sub-agent sub-delegating more than it holds is refused at
  issuance; the aggregate cap holds transitively (TREASURY-6).
- **M0 (the meta-metric):** **AGENT-TREASURY-1 goes RED → GREEN** — `auths` gains a
  quantitative *aggregate cap across sub-delegations that is reallocatable*, so a manager can
  move real capital across a swarm while the worst case is provably **"down ≤ your cap."** The
  whole reason the treasury exists.

Every verdict is produced by real `auths-verifier` code over real KEL/TEL events; every receipt
is independently verifiable; every fixture is recorded (no live money). Nothing about the
*enforcement* is mocked.

---

## 9. Recurve gap sketch

Draft gaps in **recurve gap-schema style** (`recurve/schema/gap.schema.json`): canonical fields
`class` / `status` / `severity` / `reads` / `smallest_fix` (required) / `probe`, with `evidence`
(file:line into the target) and `unlocks` (what gets stronger). The **accept + adversarial paths
live in each probe** (an accept path + a `.trap/` counterexample) and are specified per-FR in §4
— *not* in the gap entry. IDs `AGENT-TREASURY-*`; `reads: cli` names a content-hash rule over the
built treasury/gateway binary. **AGENT-TREASURY-1 is the load-bearing build** (the net-new
aggregate-cap primitive in `auths`); reclassify any claim already GREEN at baseline to a `closed`
regression guard (the DOTAK precedent). Probes drive the harness in **replay mode** (hermetic,
recorded fixtures, no live money).

```yaml
- id: AGENT-TREASURY-1
  title: "Aggregate-capped reallocation — a manager moves a slice between sub-agents and Σ slices provably stays ≤ the parent cap"
  class: missing-surface
  status: open
  severity: headline
  reads: cli
  smallest_fix: >
    Build the net-new aggregate-cap primitive in auths: a parent-anchored quantitative ceiling
    with the verifier invariant Σ(committed sub-slices) ≤ parent_cap (re-derivable offline from
    the parent KEL), and an atomic reallocate(A,B,Δ) operation (A-=Δ, B+=Δ) that commits ONLY if
    the post-move sum ≤ parent_cap, is anchored as a parent KEL event, serializes concurrent moves
    at the cap, keeps each slice independently revocable, and returns a freed (revoked) slice to
    the free pool without double-counting. Add the distinct AggregateCapExceeded verdict (sibling
    to UsageCapExceeded). Reuse AGT-4's usage_ledger.rs (a parent-keyed aggregate counter beside
    the per-slice counters) and the AGT-1 anchoring/subset path.
  unlocks: "A manager can move REAL capital across a swarm while the worst case is provably 'down ≤ your cap' — the floor for the whole fund-of-agents family."
  evidence:
    - "auths AGT-4 usage ledger (usage_ledger.rs) caps PER-DELEGATION (one agent, one cap); cross-rail CrossRailBudget sums rails WITHIN one agent — there is NO aggregate cap across sub-delegations and NO reallocation that holds the parent sum"
    - "AGT-1 / AGENT-ATTEN-3 gives the categorical subset rule at issuance, but the QUANTITATIVE sum constraint Σ slices ≤ parent_cap and the reallocate operation are not built"
  covers: [aggregate-cap]
  probe: probes/agent-treasury-1.sh

- id: AGENT-TREASURY-2
  title: "A sub-agent provably cannot exceed its own attenuated slice (per-slice spend cap at the gateway)"
  class: missing-surface
  status: open
  severity: headline
  reads: cli
  smallest_fix: >
    Wire each sub-agent's auths-mcp gateway budget to its CURRENT slice (post-reallocation), keyed
    to the slice so the cross-rail counter enforces the per-slice cap; a call that would reserve the
    slice past its amount is refused UsageCapExceeded before the rail is touched, even when the
    parent treasury still has headroom.
  unlocks: "Each sub-agent is bounded by ITS slice, not the treasury total — attenuation made quantitative per agent."
  evidence:
    - "maps AGENT-MCP-3 / AGT-4; the per-call cap exists per credential but is not yet keyed to a reallocatable per-sub-agent slice"
  covers: [per-slice-cap]
  probe: probes/agent-treasury-2.sh

- id: AGENT-TREASURY-3
  title: "The per-agent P&L is a stream of signed receipts the manager rebalances on, and a self-reported/forged P&L is excluded"
  class: missing-surface
  status: open
  severity: headline
  reads: cli
  smallest_fix: >
    Build the manager's allocation signal as a function of VERIFIED receipts only: aggregate each
    sub-agent's signed per-call receipts (spend + x402 inbound earn) into a per-agent net that
    `auths verify` confirms (device=sub-agent, identity=manager-root); the rebalance pulls from the
    lowest verified net and feeds the highest. A receipt with a forged/missing proof, or a transcript
    edited to inflate earn, is rejected at verify and excluded from the signal.
  unlocks: "Capital moves on VERIFIABLE books, not an agent's self-report — the P&L an underwriter can audit."
  evidence:
    - "maps AGENT-MCP-1 (signed per-call receipts, offline-verifiable); the manager-side verified-P&L aggregation + rebalance-on-verified-net is not built"
  covers: [verifiable-pnl]
  probe: probes/agent-treasury-3.sh

- id: AGENT-TREASURY-4
  title: "x402 inbound — a sub-agent EARNS and the credit lands in its verifiable P&L (testnet-flagged, hermetic)"
  class: missing-surface
  status: open
  severity: feature
  reads: cli
  smallest_fix: >
    Build the inbound (credit) side of x402 metering: given a recorded x402/USDC SettlementResponse
    for a service the sub-agent SOLD, extract the paid amount (atomic USDC at 6 decimals → cents),
    credit it to the sub-agent's receipted P&L (direction=inbound, rail=x402), and raise its
    rebalancing share. A credit not matching the recorded settlement (a padded earn) is rejected.
    LIVE-SCOPE FLAG: the live inbound leg needs a funded USDC testnet wallet (base-sepolia) — OUT OF
    hermetic scope, evidence-only, deferred; the probe proves credit-extraction + P&L crediting only.
  unlocks: "The treasury GROWS from agent revenue (x402 inbound), and the growth is as verifiable as the spend — the credit side of the books."
  evidence:
    - "maps AGENT-PAY-2 (x402/USDC rail, debit side built); the INBOUND credit extraction + P&L crediting is not built"
    - "hermetic over a recorded x402 SettlementResponse fixture (coinbase/x402 spec, network=base-sepolia) — no live x402 call"
  covers: [x402-inbound]
  probe: probes/agent-treasury-4.sh

- id: AGENT-TREASURY-5
  title: "Instant clawback — revoking a sub-agent stops its spend everywhere and returns its slice to the free pool without over-committing"
  class: missing-surface
  status: open
  severity: headline
  reads: cli
  smallest_fix: >
    On a parent revoke of a sub-agent, refuse its very next brokered call (Revoked, no window —
    reuse OPS-1 liveness-per-call) AND release its slice to the parent free pool
    (parent_cap − Σ live slices) so the freed amount is re-allocatable; a reallocation that
    double-counts the freed slice (would push Σ > parent_cap) is refused AggregateCapExceeded.
  unlocks: "One revoke = clawback everywhere instantly, and the freed budget can be recommitted but never over-committed."
  evidence:
    - "maps AGENT-MCP-4 / OPS-1 (instant revocation per call); the free-pool release + non-double-counting reallocation of a freed slice is part of the TREASURY-1 aggregate accounting, not yet built"
  covers: [clawback, aggregate-cap]
  probe: probes/agent-treasury-5.sh

- id: AGENT-TREASURY-6
  title: "Depth attenuation — a sub-agent cannot sub-delegate more budget than it holds (the aggregate cap holds transitively)"
  class: missing-surface
  status: open
  severity: feature
  reads: cli
  smallest_fix: >
    Extend the subset rule at issuance to the QUANTITATIVE slice: a sub-agent sub-delegating a child
    a slice ≤ its own (and Σ child slices ≤ its own) succeeds and the child's in-slice calls verify;
    a child slice larger than the parent sub-agent holds is refused at issuance, and a hand-forged
    child seal not signed by the sub-agent's key fails verify. The aggregate-cap invariant holds at
    every depth of the tree.
  unlocks: "The swarm can nest — a sub-agent can run its own bounded workers — and the cryptographic max-drawdown bound holds transitively down the whole tree."
  evidence:
    - "maps AGT-1 / AGENT-ATTEN-3 (categorical subset rule at issuance); the quantitative per-depth Σ-child ≤ self constraint rides the TREASURY-1 aggregate primitive"
  covers: [depth-attenuation, aggregate-cap]
  probe: probes/agent-treasury-6.sh
```

---

## 10. Repo, crate & recurve-tree layout

**`agent-treasury` is a NEW base repo = the recurve `[target]`** (the manager + sub-agent
allocation + rebalancing + dashboard). It **depends on** `auths-mcp` (each sub-agent is a
bounded `auths-mcp` gateway agent) and `auths` (the engine, where the aggregate-cap primitive
is built). The split is by churn and by language: the **net-new enforcement** (the aggregate
cap + reallocation) lands in the `auths` engine; the **gateway wiring** in `auths-mcp`; the
**fund logic + dashboard** in `agent-treasury`.

```
agent-treasury/                          recurve [target] — manager + swarm + dashboard, built + read by probes + sculpted
  manager/               the scripted (or live-model) allocator: mint cap, sub-delegate slices,
                         rebalance on VERIFIED P&L, issue reallocate / revoke
  agents/                the four sub-agents as auths-mcp wrap configs (flip / x402 / yield / arb)
  dashboard/             read-only view: slices, free pool, per-agent verified P&L, the Σ ≤ cap invariant
  examples/              live show + --check replay (the probe) over recorded fixtures (no live money)
  probes/                agent-treasury-1..6 (hermetic, replay mode)
  run.sh                 the staged show + the [target] gate
  .recurve/              recurve home (config below)

auths-mcp/                               recurve [sculpts.auths-mcp] — gateway wrapper, built + gated + committed there
  (per auths-mcp-gateway.md)             per-slice budget wiring: read the CURRENT slice, key the cross-rail counter to it

auths/                                   recurve [sculpts.auths] — the ENGINE, sculpted + read by probes
  crates/
    auths-verifier/      sculpt   + the aggregate cap: Σ slices ≤ parent_cap, AggregateCapExceeded verdict
    auths-sdk/           sculpt   + reallocate(A,B,Δ) issuance op (anchored, serialized, free-pool accounting)
    usage_ledger.rs      reuse    AGT-4 high-water machinery → a parent-keyed aggregate counter beside per-slice counters
```

recurve config (home in `agent-treasury/.recurve`):

```toml
[target]                          # the FUND — manager + dashboard, built, read by probes, sculpted
tree    = "."                     # agent-treasury
rebuild = "cargo build --release -p agent-treasury"   # (or the harness's build)
gate    = "./run.sh --check"      # hermetic replay over recorded fixtures, no live money

[sculpts.auths]                   # the ENGINE — where the aggregate-cap primitive is built
tree    = "../auths"
branch  = "dev-privacy"
rebuild = "cargo build --release -p auths-verifier -p auths-sdk"
gate    = "<the auths gate>"      # the auths suite gate (federated)

[sculpts.auths-mcp]               # the GATEWAY WRAPPER — per-slice budget wiring
tree    = "../auths-mcp"
branch  = "main"
rebuild = "npm ci && npm run build"
gate    = "npm run smoke -- --check"   # the auths-mcp gate (federated)

[suites.agent-treasury]
dir = ".recurve/claims/agent-treasury"
```

**Multi-tree, feedback three ways.** ONE ledger + ONE federated gate span all three trees: a
gap's `smallest_fix` lands in `auths` (the aggregate-cap engine primitive TREASURY-1 needs),
in `auths-mcp` (per-slice gateway wiring), *or* in `agent-treasury` (manager/dashboard logic),
and the **federated gate stays red until ALL of the treasury probes + the auths gate + the
auths-mcp gate are green** — so the fund pulls the engine forward and the engine can't drift
from the fund's contract. **Per-repo commits:** engine changes commit to `auths`
(`dev-privacy`), gateway changes to `auths-mcp` (`main`), fund changes to `agent-treasury`.

---

## 11. The revenue framing — profit center, not cost center (honest)

The use case **generates recurring revenue**: an autonomous fund-of-agents runs continuously,
the x402 sub-agent earns an inbound stream, the spending sub-agents pursue returns. auths is
what makes it possible to point **real capital** at that swarm. Said plainly, with the honesty
the reader is owed:

- **The cap is the max drawdown.** A `$10,000` treasury cap is not a config knob — it is the
  cryptographic worst case. *Down ≤ `$10,000`*, provably, against every agent, reallocation,
  race, and compromise. That is the number an underwriter prices and an LP can trust.
- **Custody is "the agent never holds your wallet."** Sub-agents hold only bounded spend
  authority; the gateway custodies the wallet/credential. A drained or injected agent can lose
  *at most its live slice*, never the treasury — because it never held the keys.
- **Instant revoke is clawback.** One chain event stops a sub-agent's spend on every rail at
  once, mid-run, no window; the freed slice returns to the pool. Cut a misbehaving or
  underperforming agent **instantly**.
- **The aggregate cap is a fleet bounded by your total risk.** Not N independent budgets you
  hope sum correctly — *one* ceiling the whole swarm provably stays under, even as the manager
  moves budget between agents.
- **Signed receipts are a verifiable P&L.** The books can't lie: every spend and every x402
  earn is a signed, offline-verifiable receipt. The manager rebalances on *verified* net; an
  auditor, an LP, an underwriter reads the *same* verified books. No "trust our dashboard."
- **x402 lets the agent EARN.** Pay-per-request inbound is a revenue stream the treasury *grows*
  from — the credit side of the verifiable P&L — not only a spend it bounds.

**The one-sentence honesty, again:** *auths is the **safety + the rails**, not the alpha. It
does not make the strategy profitable; it makes it **safe to delegate real capital** to an
agent that runs the strategy.* The agent brings the alpha; auths bounds the downside, gives
instant clawback, and a verifiable P&L. That is precisely what unlocks the revenue: capital
that would never be handed to an unbounded agent can be handed to a **provably-bounded** one.

---

## 12. Trust model — inherits the custody broker

The treasury inherits the gateway's trust split (`auths-mcp-gateway.md` §12) and adds the
aggregate dimension:

- **Detection is unconditional.** Every brokered spend/earn and every reallocation/revoke is a
  chain-anchored, offline-verifiable event — anyone can audit the fund's P&L and confirm the
  `Σ slices ≤ parent_cap` invariant *without trusting the manager*. The verifiable-books
  property is intact even against a compromised manager.
- **Prevention requires the gateway + the engine's serialization.** Refusing an over-slice call
  or an over-sum reallocation in real time is the gateway/engine's job; the aggregate counter
  is checkpoint-anchored (D8), so on a counter-integrity failure the bound is *max uncaught
  overspend ≤ one checkpoint interval* — **detection is not reversal** (for a treasury, set the
  checkpoint interval tight, or per-reallocation for a zero window). On a detected mismatch the
  manager **halts/revokes the swarm and alarms**; the receipts make the exact breach provable
  for out-of-band clawback/dispute.
- **Custody makes the slice unbypassable.** A sub-agent that points its MCP client at the raw
  rail has **no credential** for it (the gateway custodies it) — it can lose at most its live
  slice, and only through the gateway that meters it. *An agent can't drain a wallet it never
  held.*
- **Who runs it (the lead deployment):** **agent-owner-run** — you custody your fleet's
  downstream credentials and run the manager + gateways over *your own* swarm. The
  insurable-fund / treasury story needs **no third party to trust**: you bound your own capital,
  and a stranger (LP, underwriter, auditor) verifies the bound and the books offline.

---

## Decisions & open questions

**Decided 2026-06-15 (authoring):**
- **D1 — `agent-treasury` is a NEW base repo = the recurve `[target]`**, depending on
  `auths-mcp` (each sub-agent is a bounded gateway agent) and `auths` (the engine). Nothing in
  `auths-demos`.
- **D2 — Multi-tree, three trees, one federated gate:** `[target]=agent-treasury`,
  `[sculpts.auths]=../auths`, `[sculpts.auths-mcp]=../auths-mcp`; per-repo commits (§10).
- **D3 — The load-bearing net-new primitive is in `auths`:** a **quantitative aggregate cap
  across sub-delegations that is reallocatable** (`Σ slices ≤ parent_cap`, `reallocate(A,B,Δ)`,
  `AggregateCapExceeded`), reusing AGT-4's ledger + AGT-1's anchoring. This is AGENT-TREASURY-1.
- **D4 — Hermetic probes, recorded fixtures, no live money.** Live legs (a real model
  allocating, a funded x402 testnet wallet) are evidence-only, never gated, disclosed.
- **D5 — Honesty is load-bearing:** the PRD states in §1 status, §6, and §11 that **auths is
  the safety + the rails, not the alpha** — it does not make the strategy profitable; it makes
  it safe to delegate real capital. This framing is non-negotiable.
- **D6 — The four sub-agents** (flip / self-monetizing-x402 / yield / arb) are `auths-mcp wrap`
  configs; the x402 agent carries the **inbound** (earn) leg for the credit side of the P&L.

**Open (resolved during the sculpt):**
- **O1 — Reallocation concurrency model.** Serialize at the cap (a parent KEL-anchored,
  ordered op) so no race opens budget; confirm the exact ordering/locking surface in
  `auths-sdk` during the sculpt.
- **O2 — Free-pool accounting on revoke.** A revoked slice returns to `parent_cap − Σ live
  slices`; pin the exact accounting so a freed slice is re-allocatable but never double-counted
  (covered by TREASURY-5's adversarial twin).
- **O3 — Checkpoint interval for the aggregate counter.** Inherit D8's checkpoint-anchoring;
  pick the treasury interval (likely per-reallocation for a near-zero window, §12).

---

*Drafted 2026-06-15. The **headliner** of the fund-of-agents family — a go-to-market product:
a new base repo `agent-treasury` (the recurve `[target]`) riding on the bounded-agent MCP
gateway (`auths-mcp-gateway.md`, each sub-agent a wrapped gateway agent) and the `auths`
engine, wired **multi-tree** (`[sculpts.auths]`, `[sculpts.auths-mcp]`, §10). The load-bearing
build (AGENT-TREASURY-1) is the net-new **aggregate-capped reallocation** primitive in `auths`
— a quantitative aggregate cap across sub-delegations that is reallocatable, on top of AGT-1
attenuation + AGT-4 quantitative caps. Hermetic probes, recorded fixtures, no live money.
Surfaces named against `../auths` @ `dev-privacy` and `../auths-mcp` @ `main`; exact paths
pinned during the sculpt. The honesty that defines it: **auths is the safety + the rails, not
the alpha.***
</content>
</invoke>
