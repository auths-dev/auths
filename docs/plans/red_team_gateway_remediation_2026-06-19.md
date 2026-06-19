# Red-Team Gateway Remediation — 2026-06-19

Addresses the three **gateway** money-path findings in `red_team_2026-06-18.md` (RT-A-01 CRITICAL,
RT-A-02 HIGH, RT-A-03 MEDIUM). The treasury (RT-T-*) and relay (RT-R-*) findings are a separate
track and out of scope here. Each item was adversarially re-analysed against source before acting.

## 1 — Cap bypass via an omitted spend amount — ✅ FIXED + PROVEN
**auths `7b166010` · auths-mcp `29d9258`**

With an operator-declared rail every call is metered, but the reserve ceiling was read from the
agent's own request and defaulted to zero when omitted — and the gate treated a zero ceiling as
*non-metered*, so it neither reserved nor settled while the call still forwarded and the rail still
charged. An agent could omit one field and spend past the cross-rail cap unmetered (detection by the
offline audit only — after the money left).

Fixed in the shared `judge`: when a payment rail is set, a call that declares no amount cannot be
bounded before the rail is touched, so it is refused fail-closed (`metered-amount-required`) instead
of forwarded. Only a wrap with no rail is non-metered. Every *forwarded* metered call therefore holds
a reservation, so the actual charge always settles into the durable cap. Proven by a new live-wire
cap check (undeclared metered call refused, the rail never touched; a declared call settles; the cap
reflects only the real charge), wired into `./run.sh --check` alongside the other live-wire checks.

Decision worth a reviewer's eye: chose **deny-on-undeclared** over the softer "reserve the remaining
budget." The gate must decide before forwarding, and an undeclared charge genuinely cannot be
bounded — deny is the only outcome a rail charging more than the remaining budget cannot defeat, and
a legitimate x402 call always declares its amount, so nothing real breaks.

## 2 — Cost bound only in a side settlement — 🅿️ PARKED (part (a) subsumed; part (b) is the real fix)

The per-call signature covers `{tool, args}`; the settled cost lives in a separate agent-signed
settlement and the audit re-extracts ground truth from the operator-supplied rail response. A party
that is both agent *and* operator can fabricate a consistent (response, settlement) pair and
under-report magnitude.

**Part (a) — bind the declared cost into the signed call proof — is marginal, not done.** The
declared amount is *already* agent-signed (it is in `args`, covered by the canonical body), and the
settled cost is *already* agent-signed (in the settlement). A second agent-signed copy of the cost
adds no independent check against the agent-is-operator case (same key controls all of them). The one
thing it would catch — a *dropped* settlement — is caught more cleanly by the durable-counter
cross-check in item 3. So part (a) on its own would be motion without security.

**Part (b) — verify the rail/facilitator's own attestation of the charged amount — is the real fix
and a genuine lift.** Design (executable):
- For x402: the settlement already carries the on-chain `settlement.transaction`. The audit verifies
  the transferred amount on that tx (an RPC `eth_getTransactionByHash` + decode of the EIP-3009
  `transferWithAuthorization` value, or a facilitator-signed receipt captured at settle time) equals
  the settled cost. The on-chain transfer is attested by the network — not forgeable by an operator
  who is also the agent. This is the only thing that defeats the consistent-liar.
- For a generic rail: capture and verify the facilitator's signature over `{payment-id, amount}` at
  settle time, store it in the record, and have the audit verify it.
- Supervised: it adds a network/receipt dependency to the audit and must keep the audit runnable
  offline (prefer a captured signed receipt over a live RPC, or make the RPC check an opt-in
  online pass).

## 3 — Spend-log tail-truncation — 🅿️ PARKED (real fix, entangled with counter keying)

Records are back-linked (edit / middle-drop / reorder are caught), but the audit's "claimed total" is
just the last surviving record's cumulative, so dropping the *tail* lowers both the re-derived and
claimed totals together and audits green. This same gap lets a dropped settlement (item 2) hide spend.

**The real fix is a durable-counter cross-check** — and it is the strongest fix for the whole
drop/truncate/under-report class: compare the audit's re-derived `settled` against the verifier-held
durable counter (`SettledCounter::settled_cents`), which truncating the *log* does not touch, so a
truncated tail makes re-derived < counter → a mismatch.

**Why it is parked, not a clean local change:** the counter's location and key differ across paths.
The replay gate co-locates it under the chain's `org_repo` keyed by `agent_did` (so the verify-spend
CLI, given `--registry` + `--agent`, can open it). The live wire puts it under a *separate* verifier
repo keyed by `wire_delegation_key` (`"wrap-session"` by default — the deferred live-agent-binding
leg). The standalone CLI — the tool that re-audits a truncated log — cannot reliably locate the live
counter from `--registry`/`--agent`, so a naive cross-check would miss live logs or false-positive
them (breaking the live-wire checks). So this is entangled with reconciling the counter keying, which
is the same deferred delegation leg parked in the production-hardening pass.

Design (executable):
1. Reconcile the counter's location + key so `--registry` + `--agent` locate it on **both** paths:
   key the live counter by the real `agent_did` under the chain's `org_repo` (this also resolves the
   deferred live-agent-binding leg — pre-provisioned delegation).
2. Thread `durable_settled_cents: Option<u64>` into `audit_spend_log`; the verify-spend CLI and the
   replay self-audit open `SettledCounter::open(registry, agent)` and pass `settled_cents()`; a
   mismatch returns `BudgetMismatch { recomputed, claimed: durable }`.
3. Add a `run.sh` red-team: truncate the tail of the written log, re-audit, assert the mismatch.

Caveat (do not over-claim): the counter is verifier/gateway-held, so this raises the bar — an operator
must tamper the log **and** the monotonic counter consistently — but is not a complete defence against
an operator who controls both. The cryptographically complete fix is a signed running HEAD/count
anchor in the log itself (a further step), which the back-link's residual note already flags.

## Status

| Finding | Severity | Status |
|---|---|---|
| Cap bypass via omitted amount | CRITICAL | ✅ fixed + proven (`7b166010` / `29d9258`) |
| Cost in a side settlement | HIGH | 🅿️ parked — part (a) subsumed, part (b) is the real fix (design above) |
| Spend-log tail-truncation | MEDIUM | 🅿️ parked — real fix entangled with counter keying / the deferred delegation leg (design above) |

Reviewed through: 7b166010 (auths) · 29d9258 (auths-mcp)
