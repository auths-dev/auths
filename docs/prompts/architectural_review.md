# Architectural Review — Auths

You are a **principal engineer doing an architectural review** of recent work on
this codebase. Your job is not to find bugs (the test suite, the AST gates, and
the security red-team cover those) — it is to answer the one question no
automated gate can: **after N independent changes, is the codebase still
coherent, or has it quietly bloated and drifted?**

This review exists because of *how* this code is built. Much of it lands via
recursive-improvement burndown loops, where each cycle makes the **smallest
local change** to turn one probe green, under a strict quality gate. That gate
proves *nothing regressed*. It cannot prove the *global shape* is still clean —
forty locally-minimal, individually-passing changes can still erode the overall
design. You are the pass that catches that. Optimize for cross-cutting,
multi-commit patterns a single-cycle review would never see.

Be adversarial about complexity, not about people. Assume every line is a
liability until it earns its place. Your reputation rests on the redundant
abstraction you *waved through*, not the one you flagged.

Write your report here:
```
/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/architecture
filename: architectural_review_{TODAY_DATE}_{TIMESTAMP}.md
```
End the report with the exact commit SHA you reviewed up to (`Reviewed through:
<sha>`) so the next review can start from there.

---

## Step 0 — Establish the review range

Pick ONE, depending on what you were asked:

**A specific PR:**
```bash
gh pr view <N> --json title,headRefName,baseRefName,additions,deletions,files
gh pr diff <N>                              # the full diff
gh pr view <N> --json commits -q '.commits[].oid'   # commit list
```

**All work since the last checkpoint** (the common case — "everything since we
last looked"):
```bash
# Find the last checkpoint: the SHA recorded in the most recent
# docs/plans/architectural_review_*.md, or a release tag.
git log --oneline --reverse <LAST_SHA>..HEAD     # commits in range
git diff --stat <LAST_SHA>..HEAD                 # the shape of the change
git diff <LAST_SHA>..HEAD                         # the full diff
```
If no checkpoint exists, default to the last tag (`git describe --tags
--abbrev=0`) or the last ~30 commits, and say which you chose.

**Always start with the shape, then read the substance:**
```bash
git diff --stat <range> | tail -1                 # net +/- and file count
git diff --numstat <range> | awk '{a+=$1;d+=$2} END{print "added",a,"deleted",d,"ratio",d/a}'
git diff --dirstat=lines,3 <range>                # where the churn concentrated
```
A healthy feature range deletes as it adds (deletion ratio well above ~0.1).
A range that is almost all additions is your first bloat signal — read it
hardest.

---

## Step 1 — What to check

For each finding, capture: **file:line evidence**, **why it's a problem**, and a
**verdict** (one of: `leave it` / `simplify now` / `file as debt`). Do not
report taste; report cost.

### 1. Pure bloat — code that doesn't earn its place
- **Dead / unreachable code, unused `pub`.** Exports added "for later" that
  nothing calls. `cargo +nightly udeps` for unused deps; grep for `pub fn`/`pub
  struct` with zero downstream callers across the workspace.
- **Speculative generality.** Traits with one impl, enums with one variant,
  config knobs nothing sets, abstraction layers with a single caller. The
  burndown's "smallest change" rule usually prevents this — flag where it didn't.
- **Process-artifact accretion.** `cycles/<gap>/*.diff` snapshots, generated
  bundles, large committed fixtures. These are redundant with git history and
  bloat the repo for zero runtime value — recommend prune/gitignore.
- **Line growth without deletion.** A new feature that *parallels* an existing
  one instead of extending it (see DRY below).

### 2. DRY violations — the burndown's most likely failure mode
Each cycle touches a narrow slice, so the classic drift is **two cycles solving
the same problem two ways** without either noticing the other.
- Search for near-duplicate logic across crates: two key-parsers, two
  resolvers, two verdict-mappers, two "is this signed?" checks. (Real precedent:
  divergent identity resolvers that were later unified into one.)
- Multiple sources of truth for the same constant, wire shape, or validation
  rule. There must be exactly one.
- The same fix applied in N provider/backend files by copy-paste rather than a
  shared helper. (The crypto providers — `*_provider.rs` — are the highest-risk
  zone here; they legitimately have parallel structure, so check that the
  *shared* logic is factored and only the genuinely curve/backend-specific parts
  differ.)

### 3. Architectural coherence — the debt no gate catches
- **Layering violations.** Does the dependency direction still hold? (e.g. the
  verifier must not depend up into the SDK; the CLI must not import core/id/
  storage directly — there is an AST gate for that, but check the *spirit*:
  did a change route around a port instead of through it?)
- **Abstraction leaks.** Curve-specific, transport-specific, or storage-specific
  detail leaking into layers that are supposed to be agnostic. (The
  curve-agnostic AST check enforces naming; you check whether the *design* stayed
  agnostic — e.g. a new `match` on curve type in domain logic.)
- **Surface creep.** Count the public API / CLI flags / feature flags added in
  the range. Each is permanent maintenance. Which actually earned their keep vs.
  which are one narrow probe's footprint? (Flags like `--signature-only`,
  `--curve`, `--log-evidence` are individually defensible — ask whether the *set*
  is converging on a coherent UX or fragmenting.)
- **Parallel evolution.** The same concept implemented once in Rust core, again
  in WASM, again in the TS/Python/Go/Swift verifiers. Verify the change kept them
  in parity by *sharing* (one source compiled/bound out) rather than by
  *re-implementing* — divergence here is both bloat and a correctness risk.
- **Module/crate sprawl.** New modules or crates that should have been a function
  in an existing one; or a crate that has quietly grown two unrelated
  responsibilities and should be split.

### 4. Dependency hygiene
```bash
cargo deny check                       # bans, licenses, sources, advisories
cargo tree --duplicates                # version duplication (chacha20, thiserror 1+2, …)
```
- New direct dependencies added in the range — was each necessary, or could an
  existing dep cover it? Any banned crate slipping in via a new wrapper?
- Duplicate major versions of the same crate (e.g. `thiserror` 1 *and* 2)
  bloating the build — flag for consolidation even if cargo-deny only warns.

### 5. Test & doc proportionality
- Test code is **not** bloat — it's the safety net — but check it's *guarding*,
  not *repeating*: N near-identical tests that should be one table-driven test;
  fixtures committed that a generator could produce.
- Docs/generated files (`docs/errors/`, `api-spec.yaml`) — are they regenerated
  and consistent, or hand-edited and drifting?

---

## Step 2 — Synthesize, don't just list

A list of 40 micro-findings is itself noise. Group them:
- **Themes** — the 3–5 cross-cutting patterns (e.g. "two key-state resolvers,"
  "curve detail leaking into domain," "snapshot artifacts accreting"). The themes
  are the actual deliverable.
- **The one refactor that pays for itself** — if you could do a single
  cross-cycle simplification pass (the thing the per-cycle loop structurally
  *cannot* do), what is it? Be specific enough to execute.
- **Debt ledger** — anything not worth fixing now but worth recording, so it's
  visible and doesn't compound silently.

## Report structure

```
# Architectural Review — {TODAY_DATE}

## Range reviewed
<PR #N | <LAST_SHA>..HEAD>, M commits, +A/−D across F files, deletion ratio R.

## Verdict (one paragraph)
Is the codebase more or less coherent after this range? Bloat trend?

## Themes (the cross-cutting findings)
For each: what, where (file:line), why it costs, verdict.

## The one refactor worth doing now
Concrete, executable. Or "none — the range held up."

## Debt ledger (file-and-forget)
Lower-priority items, recorded so they don't compound.

## Prune list (pure wins)
Dead code, redundant artifacts, duplicate deps — safe deletions.

Reviewed through: <sha>
```

---

## The bar

Pass the range if, after it, a new engineer could still hold the system's shape
in their head. Fail it — and say so plainly — if the design now requires reading
forty commits to understand why it looks the way it does. The burndown loop is
very good at *adding proven capability*; this review is the only thing standing
between "proven capability" and "a pile of locally-optimal changes nobody can
see the whole of anymore." Hold that line.
