# PRD: The Agent With a Credit Limit — un-exceedable quantitative caps at the verify boundary

> **One line:** give a procurement agent a hard budget — `≤ $500/day`, `≤ 100 calls/hour`,
> `≤ 3 deploys` — and make **exceeding it cryptographically unverifiable**: the (N+1)th
> action does not verify, enforced at the verify boundary against a *signed usage counter*,
> not by trusting the agent or the app. "Exceeding the limit is unverifiable," not "we
> logged that it went over."
>
> **Maps to claim `AGT-4`** (`roadmap/aspirational_claims/gaps.yaml`). Demo style follows
> `auths-demos/death-of-the-api-key`: narrative + recurve `gaps.yaml` + behavioral probes
> (accept + adversarial) + staged `run.sh`.
>
> **Honesty up front:** auths today has *boolean* capabilities only — `a.capability` is an
> opaque string with no amount/window/limit, and `verify_presentation_sync` binds the cap
> as a present/absent token. The quantitative predicate **and** the counter-bound check at
> verify are **net-new** and must be built. This PRD says so wherever it matters.

---

## 1. One line + scenario

A finance team hands its autonomous procurement agent a card and a rule: **≤ $500 of
spend per day.** The agent does real work — it reconciles invoices, tops up cloud credits,
buys a SaaS seat — each a signed call to a payments/tool service. Calls 1..N stay under the
ceiling and clear. Then, mid-afternoon, a retry storm (or a prompt-injected supplier
invoice, or a plain bug) makes the agent attempt the purchase that would push the day to
**$540**. That is call **N+1**.

**Today, nothing stops it at the boundary that matters.** The agent's credential is an API
key or an OAuth token. *An API key has no amount and no rate semantics* — it says "this
caller may call `/charge`," never "this caller may charge up to $500/day." The $500 ceiling
lives in **app-level logic**: an `if dailySpend + amount > 500` somewhere in the service,
or a counter in a Redis the agent's own platform owns. That ceiling can be **bypassed**
(call a second endpoint, a different region, a sibling service that forgot the check),
**misconfigured** (`500` vs `50000`, the check shipped disabled), or **forgotten** (the new
`/charge_v2` route never got it). When it fails, the failure mode is *the money already
moved and we have a log line saying it went over.*

**With auths, the budget IS the verify boundary.** The agent's spend authority is a
quantitative predicate inside its delegated credential — `spend_usd ≤ 500 per rolling 24h`
— and every call presents the credential **bound to a signed usage counter** that has been
anchored into the agent's own hash-chained key log. At call N+1 the verifier replays the
counter, evaluates `prior_spend + amount ≤ cap`, finds `540 > 500`, and returns a **distinct
fail-closed verdict**. The (N+1)th presentation is **unverifiable** — it never reaches the
charge executor. There is no "we logged it." The over-cap action cannot be made to verify.

---

## 2. The property it proves

**An agent provably cannot exceed a quantitative cap (spend / rate / count), enforced at
verify time against a signed, replay-resistant usage counter.** Concretely: within-cap
presentations verify; the first over-cap presentation fails verification with a verdict
distinct from "wrong audience / revoked / expired"; and a presentation that carries a
*replayed earlier counter state* (to "rewind" spend and reopen budget) is rejected.

**Why incumbents cannot match this:**

- **API keys** are an *identity-of-caller* bearer secret with **no quantitative grammar at
  all.** A key never expresses "$500/day"; the amount lives entirely in the app. Stealing or
  replaying the key replays the full authority. There is no verify step that knows the cap.
- **OAuth scopes are boolean.** `scope=charge` is present or absent. There is no `scope`
  shape for "≤ $500/day" or "≤ 100 calls/hour"; the resource server is *trusted* to add the
  arithmetic, exactly the app-level logic we are trying to remove from the trust base.
- **App rate-limiters / spend gates** (Redis counter, API-gateway quota, a `usage` table)
  *do* hold a number, but it is enforced by the **app, behind the verify boundary**, owned by
  whoever runs that service. It is bypassable (another path), forgeable (no signature binds
  the count to the agent's key history), and rewindable (the store is mutable). The
  underwriter has to trust the operator's plumbing, not a proof.

auths moves the number **in front of** the verify boundary and binds it to the agent's
**self-certifying, hash-chained identity**, so the count cannot be forged, the predicate
cannot be skipped, and an old count cannot be replayed as current. This is the guarantee an
**agentic-commerce underwriter / insurer** needs to let an agent spend real money: not "the
operator promises a limit," but "going over does not verify."

---

## 3. Goals

A real, end-to-end demonstration — no mocked verdicts, every signature and verdict from
real auths verification code (the `death-of-the-api-key` bar):

- **G1 — A real cap in the credential.** A delegated credential carries a *quantitative*
  predicate (e.g. `calls ≤ 3` in the headline, with `spend_usd ≤ 500 / 24h` as the
  commerce framing) — not an opaque capability string.
- **G2 — A real signed counter.** Each authorized use anchors a usage increment into a
  signed, hash-chained log (the agent's KEL via an interaction event), so "how much has
  been spent" is a verifiable fact, not an app's private number.
- **G3 — The (N+1)th call FAILS VERIFICATION** — not "is logged," not "is alerted." The
  over-cap presentation returns a distinct fail-closed verdict and never reaches the
  executor.
- **G4 — A replayed older counter is rejected.** Re-presenting an earlier counter state to
  reopen budget (monotonicity / freshness attack) fails closed with its own verdict.
- **G5 — Honest staging.** Whatever is scripted (the agent's *intents*) is disclosed on
  screen; every challenge, counter anchor, signature, and verdict is live.

---

## 4. Functional requirements as claims (probe-able, claimify-ready)

Each FR is a falsifiable claim with an **accept observable** and an **adversarial twin**.
All map to **`AGT-4`**. "Verdict" = a `PresentationVerdict` (or its CLI/JSON projection)
returned by real `auths-verifier` code.

- **FR-1 — A credential can carry a quantitative cap predicate.**
  *Claim:* a credential issued with `calls ≤ 3` (resp. `spend_usd ≤ 500` over a window) is
  *issuable and verifiable* — the predicate survives issue → verify, not rejected as
  `schema_invalid`.
  **Accept:** `credential issue --cap-quant 'calls<=3'` succeeds; `credential verify` of it
  returns valid with the predicate parsed and surfaced.
  **Adversarial twin:** a malformed / non-monotone predicate (`calls<=` , `calls<=-1`,
  `calls>=3`) is **refused at issuance**, loudly — never silently accepted as an opaque
  string. *(Maps `AGT-4`.)*

- **FR-2 — Within-cap presentations verify.**
  *Claim:* calls 1..N (N=3) each present the credential bound to the current signed counter
  and **verify** (`Valid`), and the executor runs.
  **Accept:** three presentations with counter states `0→1→2` (each pre-increment under the
  cap) return `Valid`; the protected action succeeds three times.
  **Adversarial twin:** a within-cap presentation whose **counter is unsigned / not anchored
  in the subject's KEL** (forged number) fails closed — the count must be a verifiable fact,
  not a claimed integer. *(Maps `AGT-4`.)*

- **FR-3 — The (N+1)th, over-cap presentation is unverifiable.**
  *Claim:* the 4th call (which would make `count = 4 > 3`, resp. `spend 540 > 500`) **fails
  verification** with a distinct verdict (proposed `CapExceeded`), not `Valid`, not
  `WrongAudience`, not `Expired`, not `CredentialNotValid`.
  **Accept:** the 4th presentation returns the `CapExceeded` verdict; the executor never
  runs; no charge / deploy / call occurs.
  **Adversarial twin:** the over-cap call cannot be coerced to `Valid` by re-signing, by a
  fresh challenge/nonce, or by re-presenting with a *lower claimed amount than the real
  pending action* — the verdict stays fail-closed. *(Maps `AGT-4`.)*

- **FR-4 — A replayed earlier counter state is rejected.**
  *Claim:* presenting a **stale, lower counter** (an earlier anchored state, to "rewind" the
  budget) is rejected with a distinct verdict (proposed `CounterReplayed` / `CounterStale`),
  even though that older state was itself once `Valid`.
  **Accept:** after counter reaches `3`, re-presenting the `1`-state counter returns the
  replay/stale verdict; budget is **not** reopened.
  **Adversarial twin:** the replay also fails when the stale counter is *correctly signed and
  internally valid* — freshness/monotonicity is enforced against the latest anchored state,
  not merely "is this signature good." *(Maps `AGT-4`.)*

- **FR-5 — The cap binds to identity, not to the app.**
  *Claim:* the predicate and counter are evaluated **inside the verifier**, before the
  protected executor, so a relying party that runs *only* the auths verify path (no app-level
  spend check) still fail-closes at N+1.
  **Accept:** with the demo server's app-level limit explicitly disabled, calls 1..N verify
  and N+1 fails — the boundary is the verifier alone.
  **Adversarial twin:** routing the over-cap call to a *second tool/endpoint* on the same
  credential does **not** bypass the cap — the counter is per-credential-authority, not
  per-route. *(Maps `AGT-4`.)*

---

## 5. The auths surfaces (precise)

Read against `auths/crates`. Distinguishing **EXISTS** from **MUST BUILD**:

**EXISTS (and is the reason today's caps are opaque):**

- **Capability is a validated *string*.** `auths-keri/src/capability.rs` — `pub struct
  Capability(String)`; alphanumeric + `:` `-` `_`, ≤ 64 chars. No amount / window / limit
  field. A cap is **present or absent**, full stop.
- **The ACDC capability schema treats the cap as opaque.**
  `auths-keri/src/acdc_capability_schema.json` — `a.capability` is `{ "type": "string" }`,
  with `a.required = [d, i, capability]`. No quantitative sub-schema.
- **The verifier binds the cap as a boolean.** `auths-verifier/src/presentation.rs:270`
  `verify_presentation_sync(...)` chains `verify_credential_sync` then proves holder control
  and audience/nonce/TTL; it surfaces `caps: Vec<Capability>` in the `Valid` arm. **There is
  no usage-counter predicate anywhere in this path.**
- **`PresentationVerdict`** (`presentation.rs:140`) variants today: `Valid`,
  `HolderNotCurrentKey`, `WrongAudience`, `NonceMismatchOrConsumed`, `Expired`,
  `SubjectKelInvalid`, `CredentialNotValid(CredentialVerdict)`. **No cap-exceeded / counter
  variant.**
- **A signed, hash-chained audit substrate already exists.** `auths-keri/src/events.rs` —
  Interaction events (**IXN**) anchor external data through **`Seal`** (`Seal::Digest`,
  `Seal::Event`, ...) into the subject's KEL, which is hash-chained and witness-receiptable.
  The SDK already appends signed events (`append_signed_event`,
  `pairing/delegation.rs:encode_anchor_ixn`). **This is the counter's storage substrate** —
  a usage counter can be anchored as a signed IXN, replayable by any verifier, monotone by
  sequence number.
- **CLI credential verbs** (`auths-cli/src/commands/credential.rs`): `Issue`, `Revoke`,
  `List`, `Verify`, `Present` (emits the `Auths-Presentation` header). No counter/usage verb.
- **The MCP relying-party surface** (`auths-mcp-server`) already mounts the presentation +
  challenge path and gates per-tool capability — the place an over-cap verdict would land
  before an executor runs.

**MUST BUILD (this demo's net-new surface):**

1. **A quantitative cap predicate** in the credential — a structured `a.cap` (e.g.
   `{metric: "spend_usd" | "calls" | "deploys", op: "<=", limit: N, window: "24h" | null}`)
   plus schema + a parser that **refuses malformed/non-monotone predicates at issuance**
   (FR-1). Extends, not replaces, the boolean `capability`.
2. **A signed usage counter bound to the credential** — anchor each authorized use as an IXN
   `Seal` over `{credential_said, metric, cumulative, seq}` in the subject's KEL; the
   presentation carries (or references) the latest anchored counter.
3. **Verifier-side predicate enforcement** — in/under `verify_presentation_sync`, replay the
   counter from the subject KEL, evaluate `cumulative + pending ≤ limit` within window, and
   enforce **monotonicity/freshness** against the latest anchored seq.
4. **Two new `PresentationVerdict` variants** — `CapExceeded` (FR-3) and
   `CounterReplayed` / `CounterStale` (FR-4) — distinct from the existing fail verdicts, so
   the verdict *names the budget* as the cause.
5. **CLI/RP glue** — a way to anchor a counter increment and to present/verify with it
   (e.g. `credential use --cap calls --amount 1` anchoring the IXN, and `--counter-ref` on
   present/verify), so the demo and probes drive it end-to-end without app trust.

---

## 6. Non-goals

- **Not a payments rail.** No real card network, settlement, or PSP integration. "Spend" is
  a metric the cap governs; the demo proves the *authorization* boundary, not money movement.
- **Not multi-cap arithmetic / cost models.** One predicate per credential authority is
  enough to prove the property; combined budgets, currency conversion, and pricing oracles
  are out.
- **Not distributed counter consensus.** The counter is anchored in the agent's own KEL and
  read by the verifier; concurrent multi-verifier write-races and global double-spend across
  unrelated registries are a separate problem (note it; do not solve it here).
- **Not a live LLM.** Per the house offline-first constraint, the agent's *intents* are
  scripted and disclosed; every signature/anchor/verdict is live.
- **Not revocation / attenuation / cross-org trust** — those are `AGT-1..3` and the existing
  demos. This demo is the *quantitative cap* alone.

---

## 7. The narrative / run.sh dramaturgy

Staged, self-performing (the `death-of-the-api-key` pattern: gates on Enter interactively,
`DEMO_AUTO=1` plays the operator itself). Ends on **call N+1 failing VERIFICATION** and the
**replay rejected**.

- **Act 0 — Setup (disclosed).** Build the `auths` CLI from `../auths`. Org creates a
  delegated procurement agent and issues it a credential carrying a **real quantitative cap**:
  `calls ≤ 3` (framed on screen as the `≤ $500/day` budget). Print the cap predicate from the
  credential — it is in the credential, not in the app. Disclose: intents scripted, crypto
  live.

- **Act 1 — Within budget (calls 1..3 verify).** The agent makes three real calls. Before
  each, it anchors a signed counter increment (IXN) into its KEL; it presents bound to that
  counter; the verifier returns **`Valid`** and the executor runs. Show counter `0→1→2→3` and
  three green verdicts. *The budget is being spent, verifiably.*

- **Act 2 — The boundary (call N+1 is unverifiable).** The agent attempts call 4 — the one
  that would make `count = 4 > 3` (the $540 purchase). It anchors the would-be increment and
  presents. The verifier replays the counter, evaluates the predicate, and returns
  **`CapExceeded`** — a verdict distinct from revoked/expired/wrong-audience. **The executor
  never runs. No charge.** On screen: *"Exceeding the limit is unverifiable" — the budget is
  the boundary, not a log line.*

- **Act 3 — The rewind attempt (replay rejected).** The operator (playing attacker) re-presents
  an **earlier, correctly-signed counter** (state `1`) to reopen budget. The verifier checks
  freshness/monotonicity against the latest anchored state and returns
  **`CounterReplayed` / `CounterStale`** — budget stays closed. *You cannot rewind spend.*

- **Act 4 — Curtain.** Recap the verdict ledger: calls 1..3 `Valid`; call 4 `CapExceeded`;
  replay `CounterReplayed`. Optionally show the app-level limit disabled to prove the verifier
  alone fail-closes (FR-5).

`run.sh` modes mirror `death-of-the-api-key`: `./run.sh` (the show), `./run.sh check`
(preflight), `./run.sh reset` (pristine; never touches `~/.auths` or global git config — all
state under `state/`).

---

## 8. Success metrics

The demo passes iff **every verdict below is produced by real verifier code**, with no
mocked/slept-then-printed output:

- **Calls 1..N verify:** N=3 presentations return `Valid`; the protected executor runs
  exactly N times. (FR-2)
- **Call N+1 fails verification with a *distinct* verdict:** the 4th presentation returns
  `CapExceeded` (not `Valid`, not `WrongAudience`, not `Expired`, not `CredentialNotValid`);
  the executor runs **0** additional times; no charge/deploy/call occurs. (FR-3)
- **Replayed counter rejected:** re-presenting an earlier anchored counter returns
  `CounterReplayed` / `CounterStale`; budget is not reopened; the executor does not run. (FR-4)
- **Issuance refuses bad predicates:** malformed / non-monotone caps are rejected at
  `credential issue`, loudly, never accepted as opaque strings. (FR-1)
- **Cap binds to the verifier, not the app:** with the demo server's app-level spend check
  disabled, the 1..N-then-N+1 outcome is unchanged. (FR-5)
- **Reproducible & clean:** captured transcripts pin the `../auths` rev; a before/after
  fingerprint around a full run is bit-identical outside `state/`.

---

## 9. Recurve gap sketch (ready for `recurve init --from-prd`)

riclib style (cf. `auths-demos/death-of-the-api-key/gaps.yaml`): each gap names a RED-today
probe that turns GREEN once `../auths` is sculpted; paths in evidence are relative to
`../auths`. All `covers: ["AGT-4"]`.

```yaml
- id: AGENT-CAP-1
  title: "Credentials carry no quantitative cap predicate — caps are opaque strings"
  class: missing-surface
  status: open
  severity: headline
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-keri/src/acdc_capability_schema.json:36  # a.capability is {type:string} — no amount/window/limit
    - auths/crates/auths-keri/src/capability.rs                   # Capability(String): present/absent only
  probe: probes/agent-cap-1.sh   # issue --cap-quant 'calls<=3' then verify
  accept: "a credential with 'calls<=3' issues AND verifies with the predicate parsed/surfaced"
  adversarial: "a malformed/non-monotone predicate (calls<=, calls<=-1, calls>=3) is REFUSED at issuance, not accepted as an opaque string"
  unlocks: "the budget lives in the credential, not in app code"

- id: AGENT-CAP-2
  title: "No signed usage counter bound to a credential's authority"
  class: missing-surface
  status: open
  severity: headline
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-keri/src/events.rs        # IXN + Seal exist (anchor substrate) but no usage-counter anchor
    - auths/crates/auths-cli/src/commands/credential.rs  # Issue/Revoke/List/Verify/Present — no `use`/counter verb
  probe: probes/agent-cap-2.sh   # anchor a counter increment as a signed IXN; re-read it from the KEL
  accept: "an authorized use anchors a signed, hash-chained counter increment {credential_said,metric,cumulative,seq} readable by any verifier"
  adversarial: "an unsigned / unanchored counter (a claimed integer) is not treated as a usage fact"
  unlocks: "spend is a verifiable fact, not the app's private number"

- id: AGENT-CAP-3
  title: "Within-cap presentations must verify against the counter (accept path)"
  class: missing-surface
  status: open
  severity: feature
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-verifier/src/presentation.rs:270  # verify_presentation_sync — no counter predicate
  probe: probes/agent-cap-3.sh   # 3 presentations at counter 0->1->2, cap calls<=3
  accept: "calls 1..N (N=3) each return Valid and the executor runs N times"
  adversarial: "a within-cap call carrying a forged/unanchored counter fails closed (no Valid)"
  unlocks: "authorized spend keeps working under the new enforcement"

- id: AGENT-CAP-4
  title: "The (N+1)th over-cap presentation must be UNVERIFIABLE with a distinct verdict"
  class: missing-surface
  status: open
  severity: headline
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-verifier/src/presentation.rs:140  # PresentationVerdict has no CapExceeded variant
  probe: probes/agent-cap-4.sh   # 4th call would make count=4>3
  accept: "the 4th presentation returns CapExceeded (distinct from Valid/WrongAudience/Expired/CredentialNotValid); executor runs 0 more times; no charge"
  adversarial: "the over-cap call cannot be coerced to Valid by re-signing, a fresh nonce, or under-claiming the amount"
  unlocks: "'we configured a limit' becomes 'exceeding the limit is unverifiable'"

- id: AGENT-CAP-5
  title: "A replayed earlier counter state must be rejected (freshness/monotonicity)"
  class: missing-surface
  status: open
  severity: headline
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-verifier/src/presentation.rs:270  # no monotonic counter freshness check
  probe: probes/agent-cap-5.sh   # after counter=3, re-present the 1-state counter
  accept: "re-presenting an earlier anchored counter returns CounterReplayed/CounterStale; budget not reopened"
  adversarial: "the replay fails EVEN WHEN the stale counter is correctly signed and internally valid (monotonicity, not just signature)"
  unlocks: "an agent cannot rewind its own spend to buy more budget"

- id: AGENT-CAP-6
  title: "Cap is enforced by the verifier, not the app (bypass-proof)"
  class: missing-surface
  status: open
  severity: feature
  covers: ["AGT-4"]
  evidence:
    - auths/crates/auths-mcp-server/src/routes.rs  # per-tool gate runs on the presentation path; cap must precede the executor
  probe: probes/agent-cap-6.sh   # disable app-level limit; route over-cap call to a second tool
  accept: "with the app-level spend check disabled, calls 1..N verify and N+1 fails — verifier alone fail-closes"
  adversarial: "routing the over-cap call to a different tool/endpoint on the same credential does NOT bypass the cap (per-authority counter, not per-route)"
  unlocks: "the underwriter trusts a proof, not the operator's plumbing"
```

---

*Generated 2026-06-14. Companion to `roadmap/aspirational_claims/gaps.yaml` (claim `AGT-4`)
and the `auths-demos/death-of-the-api-key` demo pattern. Drafts, not gaps — probes are RED
until `../auths` is sculpted; no baseline transcript or pinned rev yet.*
