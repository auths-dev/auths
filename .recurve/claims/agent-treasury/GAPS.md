# agent-treasury — the fund-of-agents claims

A **manager** agent runs a capped treasury and allocates capital across a swarm of
bounded revenue sub-agents (flip / x402 / yield / arb). The aggregate downside is
**cryptographic**: no sub-agent, no reallocation, and no compromise can make the
swarm's committed authority exceed the parent cap, and a stranger can verify it
offline. auths is the **safety + the rails, not the alpha** — it does not make any
strategy profitable; it makes it safe to delegate real capital to an agent that
runs one.

## Conventions
- Claims are tested against the built `auths` binary (staged at `bin/auths`,
  content-hashed against `target/release/auths`). Probes drive a throwaway
  `--repo` / sandboxed HOME — never `~/.auths`.
- **Unit:** the enforced unit is the call-count cap (`calls:N`), the proven AGT-4
  quantitative cap. The fund's dollar amounts are narration: `calls:10` is the
  "$10,000" treasury, `calls:4` is a "$4,000" slice. The property under test —
  Σ slices ≤ parent, reallocatable, distinct verdict — is unit-agnostic.
- Hermetic: no network, no model, no live money. The x402 inbound leg runs over a
  **recorded** SettlementResponse fixture.
- Every probe keeps a `*.trap/` counterexample it must turn RED.

## AGENT-TREASURY-1 — Aggregate-capped reallocation (the load-bearing build)
A manager holds a treasury cap (`calls:10`) and sub-delegates four slices summing
to it (flip 4, x402 1, yield 3, arb 2). It **reallocates** 2 from yield to flip
(yield 3→1, flip 4→6) and the sum provably stays ≤ the parent cap. The headline
adversarial twin: a reallocation that **feeds a winner without pulling from a
loser** (Σ→12 > 10) is refused with the distinct `aggregate_cap_exceeded` and does
not commit — *the human's ceiling holds even against the manager.* This is the
net-new engine primitive (a quantitative aggregate cap across sub-delegations that
is reallocatable) — `auths` has only a **per-delegation** cap today.

## AGENT-TREASURY-2 — Per-slice spend cap
The flip sub-agent holds a `calls:4` slice. Its four in-slice calls verify; the
5th is refused `cap_exceeded` before the rail is touched — even though the parent
treasury still has unspent headroom in the other slices. A sub-agent is bounded by
**its** slice, not the treasury total. Rides the proven AGT-4 machinery (expected
GREEN at baseline → a closed regression guard).

## AGENT-TREASURY-3 — Verifiable P&L, forged receipts excluded
A real slice receipt verifies (the verifiable P&L atom); a fabricated SAID and a
foreign-issuer receipt do **not** verify against the manager's registry. The
manager rebalances on the verified books only — a self-reported or forged P&L
moves no capital. Rides AGENT-MCP-1 signed receipts (expected GREEN at baseline →
a closed regression guard).

## AGENT-TREASURY-4 — x402 inbound (the credit side)
Given a **recorded** x402/USDC SettlementResponse for a service the self-monetizing
sub-agent sold, the engine extracts the paid amount (atomic USDC → cents) and
credits it to the sub-agent's verifiable P&L (`direction=inbound`, `rail=x402`),
raising its rebalancing share. A padded credit (amount ≠ the recorded settlement)
is rejected. **LIVE-SCOPE FLAG:** a live inbound leg needs a funded USDC testnet
wallet (base-sepolia) — out of hermetic scope, evidence-only, deferred. Net-new
credit side (expected RED at baseline).

## AGENT-TREASURY-5 — Instant clawback + free-pool
Revoking the arb sub-agent refuses its very next brokered call (`revoked`, no
window) **and** returns its slice to the treasury free pool
(`parent_cap − Σ live slices`), re-allocatable to a survivor — but a reallocation
that double-counts the freed slice (Σ > parent) is refused `aggregate_cap_exceeded`.
The free-pool accounting rides the TREASURY-1 primitive (expected RED at baseline).

## AGENT-TREASURY-6 — Depth attenuation (transitive cap)
The flip sub-agent (holding `calls:4`) sub-delegates a child worker. A child slice
≤ flip's own (`calls:2`) is minted and verifies; a child slice larger than flip
holds (`calls:5`) is refused at issuance with `aggregate_cap_exceeded`, and a forged
child seal fails verify. The aggregate cap holds transitively down the tree. The
quantitative per-depth subset rides the TREASURY-1 primitive (expected RED at baseline).
