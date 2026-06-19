# Continue here — type-driven gateway hardening (session handoff)

A session handoff. Work is on branch **`dev-agentMoney`** in both repos
(`/Users/bordumb/workspace/repositories/auths-base/auths` and `.../auths-mcp`). Commit there, never
push, never a new branch.

## How to resume in a NEW session

Paste exactly this into the new session:

> Read `/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/continue_typedriven_2026-06-19.md`
> in full, then run the `/loop` prompt inside it.

(That's all the new session's LLM needs — this file points it at the three context docs and gives it
the prompt. Alternatively, paste the fenced `/loop …` block below directly.)

## State — already DONE (committed + green; do NOT redo)

- **Cap-bypass fix (CRITICAL):** an agent could spend past the cross-rail cap by omitting
  `amount_atomic` (a zero ceiling was mis-treated as non-metered, skipping reserve + settle while the
  rail still charged). Fixed in the shared `judge` (a metered rail with no declared amount is refused
  before the rail is touched), proven by a live-wire cap check, mutation-tested. — auths `7b166010`,
  auths-mcp `29d9258`.
- **Money path is type-driven:** `Cents` / `AtomicUsdc` / `NonZeroCents` newtypes (in
  `auths-mcp-core/src/money.rs`) — checked/saturating arithmetic, total atomic→cents conversions that
  refuse a sub-cent residue, no `Default` that yields a dangerous zero. Threaded through the gate,
  durable budget + settled counter, audit, receipt, session, and the gateway (proxy/replay/chain/
  transcript/spend_log) — ~95 sites. `#[serde(transparent)]`, so the spend-log/receipt/transcript
  JSON is byte-identical. — auths `aef9f40f` + `b3325a96`.
- **Gate (the regression bar, must stay green):**
  `cd /Users/bordumb/workspace/repositories/auths-base/auths-mcp && ./run.sh --check`
  → **12 ✓, exit 0** (replay assertions + the 3 live-wire node checks incl. the cap-bypass check).
- Both repos are clean on `dev-agentMoney` except unrelated untracked files (red-team docs, an audit
  PDF, a pre-existing `record.py` edit) — leave those.

## Context docs (the prompt references these — read them first)

- `auths/docs/plans/red_team_gateway_remediation_2026-06-19.md` — the spec + executable designs for
  items A/B/C and their robustness caveats. **This is the authority for the remaining work.**
- `auths/docs/plans/red_team_2026-06-18.md` — the original findings (RT-A-02 HIGH, RT-A-03 MEDIUM) with
  exact file:line + attack/acceptance.
- `auths/docs/plans/architectural_review_2026-06-18.md` — coherence/debt (the brokered-call spine D1 —
  there are TWO `CallCost` structs, proxy + replay; the `.mjs` harness dup D3 — extract
  `examples/live/lib.mjs` when you touch the examples).

## The `/loop` prompt (run this)

```
/loop Finish the type-driven gateway hardening on the EXISTING dev-agentMoney branch (both repos auths/ + auths-mcp/; commit there, never a new branch, NEVER push). My OWN adversarial review per item (must-review security). PARK-DON'T-FAKE. Keep ./run.sh --check (replay + live-wire incl. the cap check; 12 ✓, exit 0) GREEN throughout. When a type change breaks call sites or tests, KEEP the type-driven design and fix the breakage (propagate the types; NEVER weaken a type back to a bare primitive to dodge a compile error).

REFERENCE — READ before starting + on every resume; check work against them:
- /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/red_team_gateway_remediation_2026-06-19.md — the spec + executable designs for items A/B/C + robustness caveats.
- /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/red_team_2026-06-18.md — findings (RT-A-02 HIGH, RT-A-03 MEDIUM) + file:line.
- /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/architectural_review_2026-06-18.md — coherence/debt (brokered-call spine D1 = two CallCost structs; .mjs dup D3).
- /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/continue_typedriven_2026-06-19.md — the handoff (what's already done; do NOT redo the cap fix or the Cents conversion).

ALREADY DONE (do not redo): the cap-bypass fix (committed, proven) and the full Cents/AtomicUsdc/NonZeroCents money conversion (committed; auths-mcp-core/src/money.rs has the newtypes). Start from the ceiling enum below.

TYPE-DRIVEN METHOD (the discipline; the adversarial review must confirm each held): PARSE, DON'T VERIFY (validate once at the boundary into a type carrying the proof; downstream cannot re-encounter the invalid case — no unwrap_or, no implicit sentinels). ILLEGAL STATES UNREPRESENTABLE. NEWTYPE the security-critical scalars (the counter key, the agent DID, a rail, an attested amount). PROOF-CARRYING TYPES via SMART CONSTRUCTORS (the audit returns a parsed Consistent proof, not a bool; an attested cost is an Attested<Cents> only the verifier can mint; a located counter is a CounterRef derivable one way). TOTAL + EXHAUSTIVE (no unwrap/expect on the security path; exhaustive matches; #[must_use] on proofs).

ROBUSTNESS BAR (the goal the types serve): INDEPENDENT attestation over self-attestation; CRYPTOGRAPHIC completeness over trust-the-gateway; OFFLINE-verifiable; FAIL-CLOSED; EVERY property proven by a red-team that goes RED when its check is disabled (mutation-test it). Build the strong version; PARK a leg only if it needs an external dependency you cannot satisfy unattended, landing the strongest OFFLINE-provable slice + a precise design; where the robust fix hits a real cryptographic limit (tamper-evidence when the operator also holds the verifier counter), say so plainly and land the strongest tractable layer — never over-claim completeness.

SCOPE: the GATEWAY only (auths-mcp-gateway + auths-mcp-core). Treasury (auths-sdk) + murmur-relay out of scope.

COMMENT/COMMIT STYLE (hard rule): comments, docstrings, commit subjects describe what the code DOES. NEVER write red-team finding IDs (RT-A-0x), report names/paths, task IDs, PRD/section numbers, milestone labels, or review notes in code or commit subjects.

Order — each item: build → gate → my own adversarial review (confirm the type-driven properties + mutation-test any red-team) → fix every finding + every breakage (keep the types) → commit → update the remediation doc.

ITEM 0 (finish) — THE CEILING ENUM (make the cap-bypass class compile-impossible). Model the proxy's CallCost as an enum { Free, Metered { ceiling: NonZeroCents, rail }, AmountRequired { rail } } so a metered call ALWAYS carries a non-zero ceiling + a rail — "metered with a zero/absent amount" stops being constructible. call_cost PARSES the agent's declared amount into this at the boundary (a metered rail with no non-zero amount → AmountRequired); call_tool matches (AmountRequired → refuse with the existing metered-amount-required verdict BEFORE judge; Metered → judge; Free → non-metered). NOTE the two complications and handle them cleanly: (a) there are TWO CallCost structs (proxy.rs + replay.rs, the D1 spine) — decide whether to unify into one core type or keep replay's separate (replay carries settle_cents/charge_ref/extracted/rail_response from a fixture; it always produces a valid Metered/Free, never AmountRequired); (b) the Metered settle source differs (operator --rail settles from the rail RESPONSE; a per-call _auths_cost settles its declared cost) — model both without a fallthrough. The gate's judge should then take the metered ceiling as NonZeroCents (delete the runtime is_zero check — the type makes it impossible). Keep ./run.sh --check (incl. the cap check) green; the cap check must still refuse an undeclared metered call. Adversarial review + commit.

ITEM A — ONE durable counter the audit can locate, in types (foundation for B; resolves the deferred live-agent-binding leg). The counter lives in two places keyed two ways (replay: chain org_repo by agent_did; live: a separate verifier repo by wire_delegation_key "wrap-session"), so the verify-spend CLI cannot locate the live counter. Introduce a CounterKey newtype + a single smart constructor CounterKey::for_agent(&Did) (no Default, no "wrap-session" String) + a CounterRef the audit, CLI, replay, and live wire all derive the SAME way from (registry, Did). Reorder serve() to build the chain before opening the budget; key the live counter by the real agent did:keri under the chain's org_repo. ASSESS pre-provisioned delegation (Chain::resolve an operator-provisioned org→agent + sign with its key, vs mint-fresh): build it + a provisioning recipe IF clean, else land the CounterRef re-keying NOW + park provisioning with a precise note. GATE incl. a check that the printed verify-spend-cmd opens the SAME counter the wire advanced. Review + commit.

ITEM B — Tail-truncation: the audit is a PARSER returning a proof, cross-checked against the durable counter, + the strongest tamper-evidence you can land (RT-A-03). Layer 1: audit_spend_log returns a Consistent proof (private fields/smart constructor, NOT a bool) carrying SettledCents, constructible only after the continuity check AND a DurableSettled(Cents) cross-check (opened via CounterRef from Item A) pass; mismatch → a typed verdict. Layer 2 (assess/build-if-clean/else park precisely): a signed SignedCheckpoint{count,cumulative} anchor so an operator who ALSO holds the counter can't roll it back to match a truncated log without breaking a signature — be HONEST that full tamper-evidence when operator==verifier is a genuine lift; land the strongest slice + park the residual precisely (do NOT claim completeness you didn't build). RED-TEAMS (mutation-tested): truncate the tail → caught; (if Layer 2) truncate + roll back the counter → caught. Update spend_log.rs residual note. Review + commit.

ITEM C — Independent rail attestation as a proof-carrying type (RT-A-02 part b — the magnitude lie). Attested<Cents> whose ONLY constructor verifies an independent attestation (a facilitator-signed receipt over {payment-id/tx, amount}, or a decoded on-chain tx value); the audited total can ONLY sum Attested<Cents>, so an un-attested number can't enter — the trust-the-operator-bytes path is removed at the TYPE level. Capture the attestation at settle time, store it in the record, the audit re-verifies it OFFLINE; an online eth_getTransactionByHash + EIP-3009 transferWithAuthorization decode is an opt-in SECOND layer that never blocks the offline audit. Land the OFFLINE mechanism + a mutation-tested red-team (altering the recorded attestation is caught). If end-to-end needs a genuine on-chain attestation, do ≤1 real base-sepolia settle (--test-mode ONLY, NEVER mainnet, ≤1 cent; load auths/.env, filter output grep -vF "$X402_WALLET_PRIVATE_KEY", NEVER log/commit the key); else PARK the live capture + land the offline path. Review + commit.

THEN finalize red_team_gateway_remediation_2026-06-19.md (each item: which types/layers landed / what's parked + SHAs) + STOP with a summary.

HARD RULES: keep the type-driven design through every breakage (NEVER weaken a type to dodge a compile error). PARK-DON'T-FAKE; never fake a green/tx/test. base-sepolia TESTNET ONLY (--test-mode), NO mainnet, ≤1 real 1-cent settle (Item C only). NEVER log/commit .env/the key. Keep ./run.sh --check + all live-wire checks green at every commit. NO push/publish. Comments + commit subjects describe behavior, never finding-IDs/report-names/section-numbers. STOP on all-items-done-or-parked or 2 consecutive failures, then finalize + summarize.
```
