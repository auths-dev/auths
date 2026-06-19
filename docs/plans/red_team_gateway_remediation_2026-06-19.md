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

**Hardened to compile-impossible (auths `69f93284`).** The runtime guard above is now carried by the
*type*. The proxy parses each call at the wire boundary into
`CallCost { Free | Metered { rail, ceiling: NonZeroCents, settle } | AmountRequired { rail } }`, and
the gate's `judge` takes a `Meter` whose metered arm carries a `NonZeroCents` ceiling — so "a metered
rail with a zero/absent amount" is no longer a constructible state ("a rail with no amount" and "an
amount with no rail" are both unrepresentable), and the gate's former `reserve_ceiling.is_zero()`
branch is deleted. An undeclared metered call parses to `AmountRequired` and is refused
`metered-amount-required` (still signed + persisted as a refused record) *before* the gate. The
two metered settle sources (operator-rail RESPONSE vs a per-call declared cost) are distinct
`SettleSource` variants, not a fallthrough. `./run.sh --check` stays green incl. the live-wire cap
check (the undeclared call is refused, the rail untouched, the audit reflects only the declared
charge).

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

**Offline mechanism landed (auths `c600f5b1`).** `Attested<Cents>` is a cost obtainable ONLY by
verifying the rail facilitator's signature over the canonical `{reference, amount}` — there is no
other constructor (no `Attested::new`), so a party that is both agent and operator cannot enter an
un-attested number into the audited total. The spend-log record carries an optional facilitator
attestation; when one is present and a facilitator key is configured, the offline audit re-verifies it
and sums the FACILITATOR-attested amount, cross-checked against the agent-signed cost (a disagreement →
`cost-mismatch`; an altered attestation → `tampered-proof`). **Mutation-tested:** unit tests prove a
lowered amount, a swapped reference, a tampered signature, and the wrong facilitator key are each
caught (removing the signature check lets a lowered amount through — the red-team goes red).
🅿️ **PARKED precisely:** (1) capturing a REAL facilitator attestation on the live wire + the hermetic
fixtures (so every settled call is attested by default, not just when present) and supplying the
pinned facilitator key to the `verify-spend` CLI; (2) the on-chain SECOND layer
(`eth_getTransactionByHash` + EIP-3009 `transferWithAuthorization` decode). The on-chain leg needs a
funded base-sepolia wallet / live facilitator that cannot be stood up and proven green unattended; the
offline verification + the type guarantee run without it.

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

**Step 1 landed — the counter is now located ONE way (auths `62798337`, auths-mcp `b0c619d`).** A
`CounterKey` newtype (a validated, sentinel-free key derived from the agent `did:keri:`) plus a
`CounterRef` (`registry` + key) are the single way to open the counter — `SettledCounter` /
`CrossRailBudget` can no longer be opened any other way. The live wire builds its delegation chain
*before* the budget and keys the counter to the real `agent_did` under the chain's `org_repo` (the
same place the spend log and the printed verify-spend command point); the separate verifier repo, the
`"wrap-session"` placeholder, and the `--agent-delegation` flag are removed. The cap check now asserts
the printed verify-spend `--registry`/`--agent` resolve to the SAME counter file the wire advanced
($1.50). This unblocks step 2 (the cross-check) — done as **item B** below.

**Pre-provisioned delegation — 🅿️ PARKED (cross-session durability only).** `Chain::build` still mints
a fresh org→agent each session, so the counter is durable + locatable *within* a session (what the
cross-check needs) but does not accumulate *across* sessions — that needs a STABLE `agent_did`. The
strong version: an operator provisions an org→agent once into a persistent registry + keychain, and
the gateway `Chain::resolve`s it and signs with the pre-existing agent key instead of minting. Recipe:
`auths --repo <persistent> id create --metadata-file <org.json> --local-key-alias root`, then
`auths --repo <persistent> id agent add --label agent --key root --curve ed25519 --scope <cap>…` → a
stable `agent_did`; the gateway would `Chain::resolve(<persistent>, <agent_did>)` and reuse that key.
Parked because it needs a persistent operator-provisioned registry + a loadable keychain key that
cannot be set up and proven green unattended; the within-session locatability the cross-check requires
is fully landed.

**Step 2 landed — the audit cross-checks the durable counter (auths `20a99f82`, auths-mcp `879c36a`).**
`audit_spend_log` is now a parser returning a proof: `AuditVerdict::Consistent(ConsistentProof)` has
private fields and a `pub(crate)` constructor, so a "consistent" verdict can only be MINTED by the
audit after the per-record proof checks, the back-link continuity check, AND a cross-check of the
re-derived total against the durable counter (opened via the step-1 `CounterRef`) all pass. Truncating
the tail re-derives BELOW the counter — which the log truncation does not touch — → `budget-mismatch`.
A `run.sh` red-team proves it (drop the last settled record → `budget-mismatch`); disabling the
cross-check turns it red. A counter that cannot be read fails closed.

**Layer 2 (signed checkpoint anchor) — 🅿️ PARKED (operator==verifier).** The cross-check raises the bar
— an attacker must now tamper the log AND roll the durable counter back consistently — but does not
defend an operator who holds BOTH. The cryptographically complete fix anchors a signed running
`{count, cumulative}` OUTSIDE the operator's control (a witness / transparency log / on-chain); the
per-settlement agent-signed `Auths-Settle-Cumulative` already partially mitigates (the operator cannot
forge a lower signed cumulative without the agent key, only drop tail records). Building the external
anchor needs a witness/transparency dependency that cannot be stood up and proven green unattended —
parked; the `spend_log.rs` residual note records it.

## Status

| Finding | Severity | Status |
|---|---|---|
| Cap bypass via omitted amount | CRITICAL | ✅ fixed + proven (`7b166010` / `29d9258`), then made compile-impossible by the ceiling enum (`69f93284`) |
| Cost in a side settlement | HIGH | ✅ offline part (b) landed — `Attested<Cents>` (facilitator-signed, mutation-tested) the audit sums (`c600f5b1`); live capture + on-chain layer parked |
| Spend-log tail-truncation | MEDIUM | ✅ caught by the durable cross-check + proof-carrying audit (`20a99f82` / `879c36a`); Layer 2 (operator==verifier anchor) parked |

The durable counter the audit cross-checks is located one way by `CounterKey`/`CounterRef`
(`62798337` / `b0c619d`); pre-provisioned cross-session delegation parked.

Reviewed through: 69f93284 → 62798337 → 20a99f82 → c600f5b1 (auths) · b0c619d → 879c36a (auths-mcp)
