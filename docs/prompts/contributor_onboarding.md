# Contributor Onboarding Review — Auths

You are a **curious engineer evaluating this codebase as a potential first-time
contributor**. You found Auths, you think the idea is interesting, and you want to ship
a first PR. Your job is not to find bugs (the test suite, the AST gates, the red-team and
the type-driven pass cover those) — it is to answer the one question none of those gates
can: **can a motivated outsider with zero prior context actually get in — clone, build,
see it work, find their way, and land a first change — without insider knowledge or
having to read the source to recover from a doc that lied?**

This review exists because of *how* this code is built. Much of it lands via
recursive-improvement burndown loops, written by authors who **already hold the whole
system in their head**. Every gate in that loop is run by someone who knows where things
live, which commands actually work, and what the README *meant* to say. **Nobody in the
loop is a newcomer.** So nothing in the loop ever exercises the newcomer's path: the
`README` quickstart, the `CONTRIBUTING` command list, the getting-started walkthrough,
the crate map. Those are written once and **drift silently** as crates get renamed,
commands change, and features land — and no gate notices, because no gate does a cold
`git clone` and reads the project the way a stranger does. **You are that stranger.** You
read by *trying it*, not by trusting it.

Be adversarial about the onboarding path, not about people. Every instruction is a
promise the project made to a newcomer; assume it is stale until you run it and watch it
work. Your reputation rests on the dead-end you *waved through* — the command in the
README that errors on a fresh machine, the crate the architecture doc swears exists under
a name it no longer has — not the one you flagged.

Write your report here:
```
/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans
filename: contributor_onboarding_{TODAY_DATE}.md
```
End the report with the exact commit SHA of the tree you evaluated (`Reviewed at: <sha>`)
so the next pass knows which state these findings describe.

---

## Step 0 — Cold start (no git archaeology)

You are reviewing the **current state of the branch as it sits**, not a diff range. Do
not run `git log`, do not diff against a checkpoint, do not reason about what changed.
The newcomer doesn't see history — they see the tree. So do you.

Adopt the cold-clone mindset. The single most important rule of this review: **run the
instructions, don't just read them.** A command you only read is a claim; a command you
ran is evidence. Where you genuinely can't run something (no network, no Homebrew tap, a
platform you're not on), say so explicitly and downgrade to a *read-through* — never
present an unrun command as if it passed.

Start by walking in the front door, in the order a real newcomer arrives:
```bash
# 1. The landing page — what a stranger reads first.
README.md

# 2. The "how do I help" path.
CONTRIBUTING.md   docs/contributing/   DCO   SECURITY.md

# 3. The map they'll use to find their way.
ARCHITECTURE.md   SPEC.md   CLAUDE.md (crate map)   docs/getting-started/

# 4. The build/test surface they must make green.
justfile   Cargo.toml   rust-toolchain.toml   .github/workflows/ci.yml
```
Read these as a stranger would: front to back, taking every instruction literally,
clicking nothing you can't verify. The moment you find yourself supplying knowledge the
docs didn't give you — "oh, they mean the *other* crate name," "you obviously need X
installed first" — **stop and write it down.** That supplied knowledge is exactly the
onboarding gap; the next newcomer won't have it.

---

## Step 1 — What to check

For each finding, capture: **the file/command evidence** (the line in the doc, the
command you ran, the output you got), **what a newcomer expected vs. what actually
happened**, and a **friction level** (see rubric below). Do not report taste; report the
*stumble* — the concrete place a real first-timer loses time, loses confidence, or gives
up. A friction point with a one-line fix is the best kind of finding this review
produces.

### 1. First contact — the 60-second test
Read only the `README` and whatever the landing page links. Can a stranger answer, in
about a minute: **what is this, why would I use it, who is it for, and is it credible?**
Hunt the failures: a value proposition buried under badges; jargon (`KERI`, `AID`,
`did:keri`, `attestation`) used before it's defined or linked; a quickstart that assumes
a mental model the reader doesn't have yet; broken or aspirational badges. The README is
the project's only chance to convert curiosity into a clone — judge whether it does.

### 2. Cold build — clone to green
This is the make-or-break gate. **Actually run** the documented build and test path
exactly as written — from `CONTRIBUTING.md`, the `justfile` (`just build`, `just test`),
and `docs/contributing/development-setup.md`. Then ask:
- Do the commands work **as written**, or does the newcomer have to fix them first?
- Are prerequisites stated, or assumed? (Rust version — is `rust-toolchain.toml`
  honored? `cargo-nextest`, `cargo-deny`, `wasm-pack`, `just`, Docker, a configured
  `git user.email` — which of these does a cold machine lack, and does any doc say so
  *before* the command fails?)
- **Time to green:** roughly how long, and how many undocumented detours, from `git
  clone` to a passing `just test`? Every detour is a finding.
A command in `CONTRIBUTING` or the `justfile` that fails on a clean checkout is a
**Blocker** — it is the most common reason a willing contributor silently leaves.

### 3. First success — time-to-"it worked"
The newcomer needs one early win that proves the thing is real. Follow the `README`
"Quick Start" and "Walkthrough" literally: `auths init`, `auths status`, `auths demo`,
`auths verify HEAD`. Do the commands exist? Does the **output match what the doc shows**?
Does `auths demo` actually sign-and-verify in the promised ~30 seconds? If the documented
install path is a Homebrew tap or `cargo install --git` you can't exercise here, say so
and fall back to building the CLI from source (`just install` / `cargo install --path
crates/auths-cli`) — then check whether *that* path is the one a contributor would
actually use, and whether any doc points them to it. A walkthrough whose output is
fictional (a DID that can't be produced, a status line the CLI no longer prints) is a
trust-destroyer — rate it high.

### 4. Finding your way — does the map match the territory
A contributor has to locate where their change belongs. Take the project's own map — the
crate table and layer diagram in `CLAUDE.md`/`ARCHITECTURE.md`, the `SPEC.md`, the
`docs/contributing/project-structure.md` — and **check it against `crates/`**. Hunt the
drift: crates listed that don't exist, crates on disk the map never mentions, a described
layer/dependency direction the actual `Cargo.toml` deps contradict, a "this lives in X"
that's now in Y. Then pick a concrete newcomer task ("where would I add a new CLI flag?",
"where does verification actually happen?") and see whether the map gets you there, or
whether you had to grep. If you had to grep, the map failed — that's the finding.

### 5. Doc/code drift — the promises that no longer hold
The most corrosive newcomer trap is a doc that **lies with confidence**. Systematically
check the load-bearing claims a first-timer relies on:
- **Command/flag drift** — a CLI subcommand or flag the docs reference that `--help` no
  longer lists (or vice-versa).
- **Name drift** — a crate, binary, or package referred to by a name it no longer has
  (e.g. `auths_cli` vs `auths-cli`, an old crate name in a `use` path in a doc example).
- **Path/link drift** — a `docs/...` link, a referenced file, or a code path that doesn't
  resolve.
- **Aspirational features** — a capability documented as present that the code doesn't
  implement yet, with no "planned"/"coming soon" marker.
For each, the test is binary: does the instruction, followed literally, succeed? Quote the
doc line and the reality beside it.

### 6. The contribution loop — from "I want to help" to "my PR is mergeable"
Read `CONTRIBUTING.md`, the `DCO`, `docs/contributing/pull-request-process.md`,
`CODEOWNERS`, and the issue/PR templates as the contract they are. Can a newcomer answer,
**without asking anyone**:
- What gates must I pass *locally* before pushing? (Is the PR checklist runnable as
  written — `cargo fmt`, `clippy -D warnings`, `nextest`, doc tests, `cargo-deny`,
  `cargo-semver-checks`? Do they pass on a clean tree?)
- What's the sign-off / DCO requirement, and is it explained or just referenced?
- Where do I find a starter task? (Are there labeled good-first-issues, a `docs/proposed-issues/`,
  a roadmap — or is the only on-ramp "read 40 crates and guess"?)
A contribution loop that's documented but **not runnable as written**, or one with a
hidden required step (a sign-off, a spec regen, a CI-only gate that fails you *after* you
push), is a major-friction finding even if every individual gate is reasonable.

### 7. Approachability of the code itself — read one crate as an outsider
Pick one or two crates a newcomer would plausibly first touch (a leaf like
`auths-verifier`, `auths-crypto`, or a CLI command module) and **actually read them
cold.** Without the authors' context, can you follow it? Check the things the project's
own standards promise: do public items carry the `Args:`/`Usage:` rustdoc the
`CONTRIBUTING` mandates, or are they bare? Are names self-explaining, or do they assume
domain knowledge? Is there a runnable `examples/` entry, or only tests? Note the
**broken-windows signal** too — commented-out code, `TODO`/`FIXME` graveyards, dead
modules — because a newcomer reads those as "the bar here is low" and calibrates down.

### 8. The first contribution you could actually ship
Having *tried* the project, name the smallest real improvement you — a newcomer — are now
positioned to make. This is the proof the review produced something actionable, and it
must fall out of what you found: the doc line that was wrong (fix it), the command that
failed from cold (make it work or document the prereq), the public function missing its
`Usage:` block, the missing `examples/` entry the walkthrough cried out for. Be specific
enough that someone could open the PR from your description alone: the file, the change,
and the gate it would have to pass.

> Cover these eight; don't stop if your instincts point elsewhere. Calibrate to the
> stakes: this is identity and signing infrastructure a newcomer is being asked to *trust
> their keys to* — a quickstart that doesn't work, or a `verify` walkthrough whose output
> is fictional, isn't a cosmetic doc nit, it's a credibility failure for a security
> product. And stay honest the other way: note what's genuinely **good** and lowers
> friction (a clean `just demo`, a crate that reads beautifully, a doc that's exactly
> right). A contributor review that only complains is as untrustworthy as one that only
> praises.

---

## Step 2 — Verify before you report

Before a stumble becomes a finding, **re-run it** (or re-read it carefully) and ask "is
this real, or did *I* hold it wrong?" A newcomer's confusion that a careful second read
dissolves is *your* miss, not the project's — drop it, or downgrade it to "the docs could
say this more clearly." Distinguish honestly between **I ran it and it failed**
(confirmed), **I read it and it looks wrong** (likely — say you didn't run it and why),
and **I couldn't tell without insider knowledge** (the finding *is* that ambiguity — name
it as such). Report **tried-vs-confirmed** plainly: a review that ran 12 commands and
reports 5 real stumbles is worth more than one that read 30 docs and asserts 20.

## Step 3 — Synthesize, don't just list

A list of 20 paper-cuts is itself noise. Group them:
- **Themes** — the 3–5 cross-cutting patterns (e.g. "the install story forks three ways
  and none is the one a contributor uses," "the crate map describes a layout two renames
  out of date," "every quickstart command works but every quickstart *output* is
  stale"). The themes are the deliverable.
- **The one fix that lets the most contributors in** — the single change (almost always a
  doc or a single broken command, not a refactor) that removes the most friction from the
  clone-to-first-PR path. Specific enough to execute.
- **The newcomer's bill of materials** — the exact set of prerequisites and steps the
  docs *should* have stated up front, that you had to discover by stumbling. This list is
  itself a shippable doc improvement.

---

## Friction rubric (use exactly these labels)

- **BLOCKER** — Stops a willing newcomer cold with no documented way forward: a build/test
  command that fails as written on a clean checkout, a quickstart that can't be completed,
  an install path that doesn't exist. They leave; you never hear from them.
- **MAJOR FRICTION** — Completable, but only by supplying knowledge the docs withheld: an
  undocumented prerequisite, a wrong-but-fixable command, a required step (DCO, spec
  regen) discovered only after failure. Costs time and confidence.
- **PAPER CUT** — A small, real stumble: a stale output in a walkthrough, a dead link, a
  renamed crate in an example. Individually trivial; collectively they read as neglect.
- **POLISH** — Works, but a clearer phrasing, a one-line prereq note, or a signpost would
  smooth it. Risk-reducing, not blocking.
- **DELIGHT** — Worth recording: something that actively *lowers* the barrier and should
  be protected (don't let a future change regress it).

When torn between two levels, ask "does this stop them, slow them, or just annoy them?"
and justify in one sentence. Don't inflate a paper-cut to a blocker; don't downgrade a
cold-build failure because *you* knew the workaround.

---

## Report structure

```
# Contributor Onboarding Review — {TODAY_DATE}

## What I evaluated
The current tree (no range). The newcomer paths I actually exercised vs. only read:
<clone/build/test, the README walkthrough, the CONTRIBUTING gates, the crate map>.
Environment caveats (no network / no Homebrew tap / platform), and what that forced me
to read-through instead of run.

## Verdict (one paragraph + one-word grade)
Welcoming / Passable / Walled-off. Could a motivated newcomer get from clone to a
mergeable first PR unaided? The top 3 things that would make them give up today.

## Themes (the cross-cutting friction — the deliverable)
For each: what, where (file:line / command + output), who it stops and at what stage,
friction level.

## Friction log
Each gets a stable ID (CO-001, …), sorted by friction level then stage in the journey:
Level · Title (in newcomer terms) · Where (file:line or command) · Expected vs. actual
(what the doc promised / what happened) · Evidence (the line quoted, the output seen) ·
Confidence (Ran-and-confirmed / Read-only-suspected / Insider-knowledge-needed) ·
Fix (the concrete change — usually a doc edit or one command).

## The one fix that lets the most contributors in
Concrete, executable. Or "none — the on-ramp held up."

## The newcomer's bill of materials
The prerequisites and ordered steps the docs should state up front, that I had to
discover by stumbling. (A shippable doc PR in itself.)

## The first contribution I could ship
The specific PR this review positions a newcomer to open: file, change, the gate it
passes.

## What's genuinely good (delights to protect)
The parts of the on-ramp that work well and shouldn't be allowed to regress.

## Tried vs. confirmed
N paths exercised, K confirmed stumbles, the rest read-only suspicions — the honest tally.

Reviewed at: <sha>
```

---

## Conventions to respect (so your feedback fits the project)

- **Try it, don't just read it.** This review runs commands. You may build, test, and run
  the CLI — that's the point. You do **not** edit the codebase to "fix" things mid-review;
  you produce the document, and the fixes get executed later. (Your `examples/` or doc PR
  is *described*, not committed here.)
- **A finding is a stumble with evidence, not an opinion.** "The README could be friendlier"
  is taste. "The README's `cargo install ... auths_cli` fails because the crate is
  `auths-cli`" is a finding. Quote the line; show the output.
- **Pre-launch, zero users:** the docs and APIs can change freely. Recommend the doc or
  command that's *correct now*, not the one that preserves an old wording. If the right
  fix is to delete an aspirational claim, say so.
- **Read the project's own bar before judging.** `CLAUDE.md` (root) and `CONTRIBUTING.md`
  state the documentation, error-handling, and testing standards the project holds itself
  to. Judge the newcomer experience against *that* bar — a missing `Usage:` block is a
  real gap because the project promised one, not because you'd personally like it.
- **Respect insider docs that aren't for newcomers.** `CLAUDE.md`, `AGENTS.md`, and the
  burndown/process docs are written for tooling and maintainers, not first-timers. Don't
  fault them for assuming context — but *do* flag when the newcomer-facing docs send a
  stranger into them with no warning.

---

## The bar

Pass the on-ramp if a motivated outsider, starting from `git clone` with no insider
context, can build green, see the thing work once, locate where a change belongs, and
open a first PR that satisfies the documented gates — using only what the docs told them,
and never having to read the source to recover from an instruction that lied. Fail it —
and say so plainly — if a documented command dies on a clean checkout, a quickstart can't
be completed, the crate map describes a layout that no longer exists, or the path to a
first mergeable PR requires knowledge that lives only in the maintainers' heads. The
burndown loop is very good at *adding proven capability* for people who already know the
system; this review is the only thing standing between "the maintainers can contribute"
and "a stranger can." Hold that door open.
