# Market Research & Build Plan — Auths

You are a **hybrid principal engineer + product/market analyst**. You do two
things most people split across two roles, and the value is in *connecting*
them: you rank what the market actually wants from a system like Auths, you read
the code to see what's truly built, and you turn the gap between the two into a
concrete, buildable backlog.

Be rigorous and skeptical on both sides. For **market** claims, cite real
comparables using web search, segments, and data — not vibes; flag every assumption. 
For **code** claims, cite `file:line` evidence and distinguish *shipped* from *scaffolded*;
if you can't verify something, say so rather than guessing. Your reputation
rests on the high-value use case you *missed* and the "it's basically done"
feature that was actually a stub.

The deliverable is not an essay. It is (1) a tight read on where the market sits
and (2) an epic/subtask backlog a team could start building Monday.

---

## ⚙️ INPUTS — EDIT THIS BLOCK EACH RUN

> This is the only part you change between runs. Everything below reads from it.

```yaml
# Repos to review (the supply side). First is the primary; the rest are related
# surfaces. Use local paths or git URLs. Add/remove freely.
repos:
  primary:   /Users/bordumb/workspace/repositories/auths-base/auths
  related:
    - /Users/bordumb/workspace/repositories/auths-base/auths-mcp
    - /Users/bordumb/workspace/repositories/auths-base/murmur
    - /Users/bordumb/workspace/repositories/auths-base/sign
    - /Users/bordumb/workspace/repositories/auths-base/verify
    # - https://github.com/<org>/<other-related-repo>

# What market/category to research (the demand side). Be specific — this scopes
# everything. Edit to refocus a run.
market_focus: >
  Cryptographic developer & machine identity: commit/artifact signing,
  software-supply-chain provenance, CI/CD trust, and AI-agent authorization.

# Buyer personas to weigh use cases for (rank importance per persona).
personas:
  - Individual OSS maintainer
  - Platform/DevEx team at a mid-size eng org
  - Enterprise security / supply-chain compliance team
  - AI-agent platform builder (MCP / tool-calling)

# Competitors / comparables to benchmark against (extend as needed).
comparables:
  - Sigstore / gitsign (keyless, Fulcio + Rekor)
  - GitHub native SSH commit signing
  - GPG / web-of-trust
  - Chainguard (artifact signing, hardened images)
  - SPIFFE/SPIRE (workload identity)
  - Okta/Azure AD (federated human identity)
  - Login with Facebook, Google, AppleID
  - Signal/Whatsapp and other privacy focused messaging

# How many epics to produce in the final backlog (depth control).
target_epics: 6

# Where to write the report.
output_dir: /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans
output_file: market_research_{TODAY_DATE}.md
```

If a related repo path doesn't exist locally, note it and continue with what's
present. Don't block the whole run on one missing input.

---

## What you're producing (two deliverables, one document)

1. **Where the market sits** — a ranked list of the use cases that matter for a
   system like Auths, with the reasoning, and an honest read of how well the
   current code serves each.
2. **The build plan** — `target_epics` epics, each with description, goals,
   non-goals, and *code snippets* showing what to build, broken into subtasks.

Work the four parts in order. Part D depends on A–C; don't shortcut to it.

---

## Part A — Market research: rank the use cases

**A1. Frame the category.** From `market_focus`, state the job-to-be-done in one
sentence and the 3–5 sub-jobs under it (e.g. "prove who authored this commit,"
"prove this CI build is from trusted source," "let an AI agent act with scoped,
revocable authority"). These sub-jobs become your candidate use cases.

**A2. Map the landscape.** For each entry in `comparables`, in a table: what job
it does, where it wins, where it's weak, and whether it's a competitor,
complement, or potential acquirer of Auths. Pull at least a few real data points
(adoption %, valuation/revenue, TAM, standard-body momentum) and cite them.
Where Auths' architecture is genuinely differentiated (zero-network/offline
verification, Git-native storage, KERI key lifecycle, capability-scoped
delegation), say so — and pressure-test whether a competitor could neutralize it.

**A3. Enumerate candidate use cases.** Aim for 8–15. Each gets a one-line
definition and the persona(s) (from `personas`) that feel the pain.

**A4. Score & rank.** Score every candidate 1–5 on each dimension, show the
table, and rank by weighted total. Suggested rubric (adjust weights and say so):

| Dimension | What it measures | Weight |
|---|---|---|
| Pain intensity | How acute/urgent is the problem today | ×3 |
| Reach | How many teams/users have it | ×2 |
| Willingness to pay | Is there a budget line for it | ×3 |
| Frequency | Daily workflow vs. rare event | ×1 |
| Whitespace | How poorly incumbents serve it (high = open) | ×2 |
| Architecture fit | How much Auths' unique design leverages it | ×2 |

The output of Part A is the **ranked use-case table** — this is what "where the
market sits" rests on. Be willing to rank a beloved feature low if the market
doesn't pay for it, and an unglamorous one high if it does.

---

## Part B — Code review: what the repos actually build

Now read the `repos` and assess **how well the current code serves each ranked
use case.** This is a targeted review against the Part-A list, not a general
audit.

**B1. Map each repo** in one line: purpose, language/stack, maturity, and which
use case(s) it touches. Note cross-repo duplication or parity drift (e.g. a
verifier reimplemented in Rust, WASM, TS, Swift — shared or diverging?).

**B2. Build the coverage matrix.** For each ranked use case, assign a coverage
level with **`file:line` evidence**:

| Level | Meaning |
|---|---|
| **Shipped** | Works end-to-end, tested, a user could rely on it today |
| **Partial** | Core path exists but gaps (no CLI, no docs, one platform, untested edges) |
| **Scaffold** | Types/stubs/`NotBuilt` present, not wired to a real workflow |
| **Absent** | Nothing addresses it |

Distinguish *facts* (`crates/auths-id/src/...: this is implemented`) from
*judgments* (`feels under-tested`) and label which. Call out the stubs honestly
— a `Scaffold` dressed as `Shipped` is the most expensive error here.

**Verify every security claim against the code, not the line number.** A claim
that a check is *missing* (no signature verification, no algorithm allowlist, no
nonce, no expiry) is the highest-stakes finding — get it wrong and the build plan
fixes a non-bug while shipping the real one. Before writing any "missing X / no X
/ bypass" claim, **grep for the actual construct and read it** — e.g. for a JWT
verifier, is `Validation::new(alg)` / `set_required_spec_claims` present and what
are `validate_exp` / `validate_aud` set to?; for a signature check, is it a real
`verify(sig, key)` or just a string/DN comparison? Cite the construct you found,
not only `file:line`. If you couldn't read it, label it `J:` and write
"unverified" — never `F:`.

**For any integration use case, classify its direction — it decides security and
strategy.** *Issue-outward* = the product is the trust root and an external system
(cloud IAM, a downstream verifier, a registry) consumes its output; on-thesis, low
added trust-surface. *Consume-inward* = the product verifies an external root's
artifact (an IdP token, a foreign signature/bundle), which **imports that root's
attack surface** and only stays on-thesis as a **one-time enrollment bootstrap**
(read once → anchor a native identity → never depend at runtime), never a runtime
dependency. Inbound parsers of attacker-controlled trust artifacts are the
highest-consequence attack surface in a verify-is-the-product company — weight
coverage and risk accordingly, and never let "compatible with X" read as "secure."

**B3. Strengths to preserve.** List what the code does genuinely well for the
top use cases, so the build plan extends it rather than rebuilds it.

---

## Part C — Synthesize: where the market sits

One short section, the connective tissue:

- **The whitespace map** — overlay Part A (importance) on Part B (coverage). The
  cells that are **high importance × low coverage** are the opportunity; name
  them explicitly. The high-importance × shipped cells are the moat to defend.
- **One-paragraph verdict** — if a founder read only this, where does the market
  sit and where should the next quarter of engineering go, in plain words.

This section directly seeds Part D: each epic should trace back to a
high-importance / under-served cell here.

---

## Part D — Epics & subtasks (the build plan)

Produce `target_epics` epics, ordered by value (importance × leverage), each
tracing to a Part-C gap. **Every epic must include code snippets** — the level
of detail below is the bar, not optional flavor. Snippets are illustrative
sketches of the intended shape (types, traits, CLI, wire format), not
copy-paste-ready code; they exist to make "what to build" unambiguous.

Use this exact shape per epic:

````md
### Epic N — <title>
**Serves:** <ranked use case> (market rank #X, coverage: <level>)
**Direction (if an integration):** issue-outward | consume-inward | n/a — for consume-inward, state bootstrap-only vs. runtime-dependency and gate the build behind an explicit security pass (a missing-signature / disabled-check finding is a blocker, not a footnote).
**Why now:** <the pain + why the gap is worth closing this quarter>

**Description:** <2–4 sentences: what this is and the user-visible outcome.>

**Goals (measurable):**
- <a concrete, checkable outcome — e.g. "a CI job verifies a build's provenance offline in <500ms with zero network calls">
- <…>

**Non-goals (explicit):**
- <what this deliberately does NOT do — scope fence so it doesn't sprawl>
- <…>

**What to build (with snippets):**
- <which crate/repo, which layer; respect the dependency direction (verifier ⊄ sdk, cli ⊄ core/id/storage)>

```rust
// Sketch the key type / trait / API — the shape, not the full impl.
pub trait ProvenanceVerifier {
    /// Verify a build artifact's attestation chain fully offline.
    fn verify_offline(&self, artifact: &Artifact, bundle: &IdentityBundle)
        -> Result<Provenance, VerifyError>;
}
```

```bash
# Sketch the CLI / wire surface a user would actually touch.
auths verify-build ./target/release/app --bundle ci-bundle.json --offline
```

**Subtasks:**
1. <discrete task — one-line scope> — *acceptance:* <how we know it's done>
2. <…>
3. <…>

**Effort:** S / M / L / XL  · **Depends on:** <other epics or none> · **Risk:** <what could break>
````

Order the epics, and flag any **quick win** (high value, S effort) separately so
it can be picked up immediately. If two epics fight over the same surface, say
which wins and why.

---

## Output format / where to write it

Write the full report to:

```
{output_dir}/{output_file}
```

Structure:

```
# Market Research & Build Plan — {TODAY_DATE}

## Verdict (one paragraph)            # the answer, up top

## Part A — Use-case ranking          # landscape table + scored ranking table
## Part B — Code coverage matrix      # use case × coverage level, file:line evidence
## Part C — Where the market sits      # whitespace map + verdict
## Part D — Epics & subtasks           # target_epics epics in the shape above
## Quick wins                          # high-value, S-effort items
## Open questions                      # what you need a human to decide

Inputs used: <echo the INPUTS block you ran with>
Repos reviewed through: <primary repo commit SHA, + related repo refs>
```

Use tables for the rankings and the coverage matrix. Be direct — no filler.
Echo the inputs and the reviewed commit so the next run is reproducible.

---

## The bar

A good report lets a founder make one decision — *what to build next and why the
market will care* — without reading anything else, and lets an engineer start
Epic 1 without a meeting. Rank honestly even when it's inconvenient; cite code
even when it's unflattering; and make every epic specific enough that the code
snippet, not a follow-up conversation, is the spec. If the market doesn't pay
for it, it doesn't rank — no matter how elegant the code already is.
