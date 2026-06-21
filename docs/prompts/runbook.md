# Build-Loop Runbook (general)

Operating procedure for **any** `/loop` (or autonomous loop) that burns down a **plan** into a
**progress ledger**. The plan says *what*; this says *how the loop runs*. It is loop-agnostic:
it fits a feature build, a security-gate burndown, a market-research backlog, or a review-findings
remediation — anything shaped like the two reference ledgers
(`go_to_market/20260620/market_research_progress.md`, `go_to_market/20260621/progress.md`).

**Coding rules you MUST follow (the bar every change is held to):**
`/Users/bordumb/workspace/repositories/auths-base/auths/docs/prompts/meta_prompt.md`

---

## The three artifacts the loop reads

1. **The plan / spec** — *what* to build (linked at the top of the ledger). The source of scope.
2. **The ledger** (a single markdown file of rows) — the **single source of truth for status and
   the stop condition.** Rows are `ID | Item | Status | Gate | Notes`, grouped into epics/milestones
   with a **build order**. The loop updates it **every iteration** and **stops when every row is
   `merged` or `gated`.**
3. **The coding rules** (`meta_prompt.md`) — non-negotiable, every change.

A row's `Notes` is a running log: premise corrections, what merged (commit/PR), what's left, and any
design decision surfaced to the human. Keep it honest and current — a future iteration (or a human)
reads it cold.

---

## Status vocabulary

- `todo` — not started.
- `wip` — in progress this iteration.
- `code-done` — built + locally green, not yet merged.
- `ci-green` — the PR is green on remote CI (informational; not the gate — see below).
- `merged` — landed on the mainline.
- `proof-gate` — merges when its **strengthened battery is green + red-team-dry** — *the tests are the
  gate, no human.* The battery tests the **live wired path end-to-end** (not just the helper); for a
  verifier / crypto path it adds **differential-oracle + fuzz + a constant-time check** (see "How
  correctness is gated"). The default for **all** security-touching code, including verifiers.
- `audit-flag` — an informational tag on a `proof-gate` row whose surface (a verifier / new crypto path)
  also belongs in the **one batched pre-launch crypto audit**. It **does not block the merge** — the row
  merges on its battery; the audit is a milestone, not a per-row gate.
- `decide-default` — a product/scope call that has a **documented recommended default**: the loop
  **proceeds on the default and flags it for override**, it does not pause. (Most "decision" rows are this.)
- `needs-human-decision` — reserved for a true **one-way door** only (a public API/wire shape consumers
  will build on; actually shipping or publishing a security surface). Surface it and pause. Everything
  reversible is `decide-default` instead.
- `secrets-scan` — an automated secrets-in-content scan must come up clean before merge (file moves /
  relicense).
- `gated-ext` — **externally-gated; do NOT attempt.** The code is closeable; the *acceptance* needs a
  live external system the loop can't reach (cloud creds, testnet, code-signing, hosting, publishing, a
  human/org key ceremony). A capability limit, not a review.
- `blocked` — waiting on another row; name it.

`merged` and `gated` (any `gated-*`) are the only terminal states. The loop stops when **every** row is
one of them.

---

## How correctness is gated: lean into testing; one batched human audit pre-launch

**The loop owns correctness and discharges it by *proving* it — on the live, wired path.** Adversarial,
test-first, `RED → GREEN`, fuzzed, red-teamed until dry. A reviewer skims a diff; the battery executes
every enumerated attack, a fuzzer thousands more, and a differential oracle millions. This is *stricter*
than per-PR human review, not looser — **and it does not stall the loop.**

**Why testing can finish the work — including verifiers.** Look at what actually slips (the `20260621`
findings): an *open registration endpoint whose own test was commented out*; a *verifier fed an unsigned
timestamp*; a *presentation path that gated on `is_valid()` instead of `is_trusted()`*. None of those is
"a human saw what tests can't" — each is a **testing-discipline miss**: the test was at the wrong level
(a unit test on the helper, not an **end-to-end test on the wired path**) or it was disabled. Test the
wired path and they all turn RED. So the lever is *better tests*, not a human gate. Four upgrades make
testing strong enough to finish a verifier:

1. **End-to-end on the live wired path.** The test drives the *real caller* and asserts the *real verdict
   is consumed correctly*, not just that a helper returns the right value in isolation. The single
   highest-value upgrade — it catches the wiring/composition class (verifier correct, but fed the wrong
   input or its result ignored) that unit tests structurally miss.
2. **Differential testing against an independent, trusted oracle.** Run the verifier against a reference
   implementation (keripy / RFC test vectors / another impl) over many inputs; any divergence is a bug.
   This catches *unimagined* forgery classes — the oracle rejects what you didn't think to test, turning
   "rejects the forgeries I imagined" into "agrees with a trusted reference." (Needs an independent oracle
   to exist; where none does, lean harder on fuzz + property tests.)
3. **Coverage-guided fuzzing** over attacker-controlled bytes (`cargo-fuzz`), run long, invariant *never
   accept an unsigned/forged input, never panic.*
4. **A constant-time / side-channel check** on every secret/MAC/token comparison (a `dudect`-style test,
   or a "must use `subtle::ConstantTimeEq`" lint).

A verifier change merges on this battery green — **no per-PR human gate.**

**The honest residual — a milestone, not a per-row block.** Two classes resist *functional* testing:
**(a) timing / side-channels** — the answer is right, the leak is in the timing; the catch is a *tool*
(upgrade #4), not a human; and **(b) a genuinely novel cryptographic break** the fuzzer and oracle both
miss (they can share a blind spot). Only (b) needs a human cryptographer — and this product is
**pre-launch with zero users**, so the cost of a residual is "fix it before launch," not "harm a user."
So (b) is handled by **one batched crypto audit over the whole verifier surface as a pre-launch
milestone**, tagged `audit-flag` on the relevant rows — *not* a gate that stalls each verifier PR. The
loop runs to completion; the audit is the last thing before you have users.

**Decisions are not test problems — but most aren't gates either.** A test proves a *chosen* design
correct; it can't *choose* it. But when the ledger carries a **recommended default**, the loop **decides
on it and proceeds, flagging for override** (`decide-default`) — it does not pause. Only a true **one-way
door** — a public API/wire shape consumers will build on, or actually shipping/publishing a security
surface — pauses as `needs-human-decision`. Everything reversible is decided-and-flagged. Anything
untestable in-repo (live external acceptance) stays `gated-ext`, never assumed.

---

## Prime directives (every iteration)

1. **Prove on the wired path, don't ask.** No trust-decision / verification / auth change is "done"
   until: **(a)** its adversarial cases were written as tests **first**, **end-to-end on the live wired
   path** (drive the real caller, assert the real verdict is *consumed* correctly) — not only on the
   helper in isolation; **(b)** each was shown **RED against the current (vulnerable) code** (it *wrongly
   passes the forgery* today); **(c)** the fix turns them **GREEN**; **(d)** an independent red-team pass
   ran **≥2 dry rounds** finding no new forgery; **(e)** for a verifier / crypto path, the battery adds
   **differential-oracle + fuzz + a constant-time check** (see "How correctness is gated"). This replaces
   sign-off and is more stringent. The most common real miss is testing the *helper* not the *wired path*
   — default to end-to-end.
2. **Verify before you build (premise correction).** Re-confirm the row against `HEAD` first. Work
   is *often already done, or the property is already locked at a load-bearing layer* — don't rebuild
   what exists, don't add a redundant test for an invariant a lower layer already enforces. Record the
   correction in the row's Notes and move on. (Both reference ledgers are full of "premise corrected /
   already proven at the load-bearing layer" — expect it.)
3. **Finish the wiring, don't delete.** A mechanism that is built + tested but **not yet wired to the
   live path** is **unfinished work to complete** (the commit's stated aim), not bloat to delete. The
   default is to finish the wiring; deletion is a *deliberate* fallback only if the team decides a
   given mechanism won't be completed. (A green test on an unwired helper proves the *helper* works,
   not that production *uses* it.)
4. **Green is guilty until proven honest.** A passing test, a closed row, a green CI run, a README "✅"
   is **evidence of nothing** until the property is confirmed against the **real code**. The same author
   wrote the impl and the test; a test can pass while the property is violated (a `verify()` that returns
   `Ok` without checking, a gate that's never called, a security suite **commented out of the build**).
5. **Decide on the default; surface only one-way doors.** A decision row with a documented recommended
   default → **proceed on it and flag for override** (`decide-default`), don't pause. Only a true one-way
   door (public API/wire shape, shipping a security surface) or a `blocked` row is surfaced and skipped —
   never code against an undecided *irreversible* contract.
6. **Never attempt an externally-gated item.** Mark `gated-ext`, surface, skip — write the *code + local
   test*, stop at the live-external boundary.
7. **No silent caps.** If an iteration bounds coverage (sampled, skipped a hard case, left a TODO),
   `log` it in the row's Notes. A silent truncation reads as "covered everything" when it didn't.
8. **Local tests are the gate — not remote CI.** Mirror the project's **full** check surface locally
   (below); merge when local is green. Don't block on remote CI; a CI-only failure gets a **follow-up
   PR**, never a held loop.
9. **Code carries no process metadata.** Source, docstrings, and comments describe **what the code does**,
   plainly — **never** the plan, an epic/task/finding ID, a proof-battery/runbook reference, or
   red-team/process language. The tree must read as if it were always written this way. Plan vocabulary
   lives in the commit message + PR body only. Before committing, grep the staged diff for your
   loop's ID scheme + process words and confirm it's empty
   (e.g. `git diff --cached | grep -inE '\b(epic|task|finding|proof-battery|red.?team|runbook)\b|<your-ID-regex>'`).
10. **No AI attribution.** Commits, PR descriptions, and the tree carry no mention of Claude / Claude
    Code / any AI tooling.
11. **Update the ledger every iteration.** It is the source of truth. Stop only when every row is
    `merged` or `gated`.

---

## Build order discipline

Follow the ledger's **build order** — it usually encodes hard gates (e.g. a security/foundation gate
that **blocks** downstream consumers: *you do not add trust-consumers to a fail-open gate; you do not
ship consumers against an undecided *one-way-door* contract*). Honor a `needs-human-decision` (a one-way
door) that gates a row before its dependents; a `decide-default` row proceeds on its default and does not
gate. **Don't parallelize rows that touch the same crate/area.**

---

## The per-row loop — six stages

1. **Validate / confirm the premise** vs `HEAD` (directive 2). If it's already done, record and close.
2. **RED (test-first).** Write the acceptance criteria **and** the adversarial attack cases as tests;
   run them; confirm each fails *for the right reason*. A security fix's attack test **must fail against
   the current (vulnerable) code** — that proves the test detects the bug, not just the absence of one.
3. **GREEN.** The minimal change until all tests pass, honoring `meta_prompt.md` (typed/parse-don't-
   validate, fail-closed, no `unwrap`/`expect` in prod, curve-agnostic, layering, **plain-language
   comments — no process IDs, directive 9**).
4. **RED-TEAM until dry.** An **independent** pass tries to forge / bypass / replay / fuzz / starve —
   for a verifier/crypto row, an independent *agent* that didn't write the code, plus the
   differential-oracle and coverage-guided fuzz from "How correctness is gated." Each success becomes a
   new `RED → GREEN` test. Repeat until **≥2 consecutive rounds find nothing.** Mandatory for any
   trust/verify/auth row; best-effort elsewhere.
5. **Local check-surface green-gate** — the project's **full** surface (below), not just `build`.
6. **Commit → push → PR → merge** (git workflow below) when local is green **and** (for security rows)
   the strengthened battery is green + red-team-dry. **No per-PR human gate**; a verifier-surface row also
   carries an `audit-flag` for the pre-launch crypto audit (which does **not** block the merge).

---

## The proof-battery pattern (what "proven" requires)

For any **trust-decision / verification / auth / parsing-of-untrusted-input** change, enumerate the
attack classes and write **each as a RED-first test** (fails on the old code, passes after). **Pick the
test *level* to match the bug class** — this is what makes testing strong enough to finish the work,
including a verifier:

- **Unit** — the helper rejects a forgery in isolation. Necessary, never sufficient.
- **End-to-end on the wired path** — drive the *real caller* and assert the *real verdict is consumed*
  (the presentation path actually gates on `is_trusted`; a mutated bundle timestamp actually fails the
  freshness grade). Catches the *wiring/composition* class a unit test can't see (verifier correct, but
  fed the wrong input or its result ignored). **Default here for any "is it actually wired?" property.**
- **Differential vs an independent oracle** — agree with a trusted reference (keripy / RFC vectors /
  another impl) over many inputs. Catches *unimagined* forgery classes.
- **Coverage-guided fuzz** over attacker bytes — never accept an unsigned/forged input, never panic.
- **Constant-time check** on secret/MAC/token comparisons — the one class functional tests can't see.

Then cover the universal attack-class checklist — what applies, plus what your domain demands:

- **Fail-open vs fail-closed** — every `unknown` / `error` / `missing field` / `ambiguous` resolves to
  **refuse**, never accept. (Accept-on-uncertainty on a trust path is *Critical by default*.)
- **Forged / tampered** input that is internally consistent but signed by the wrong key → **rejected**.
- **Expired / revoked / stale / replayed** input → **rejected** (and a *positional* check — "is it in the
  slice I hold?" — is not freshness; the verdict must say what it could and couldn't confirm).
- **Algorithm / type confusion** — `alg:none`, HMAC-with-a-public-key, length-dispatch-on-curve,
  wrong-audience / wrong-subject / wrong-nonce → **rejected**.
- **Malformed / truncated / oversized / duplicated / reordered** bytes → **rejected, no panic.**
- **Resource abuse** — unbounded input on a network/parse path (a cheap request that costs the server a
  lot) → **bounded**.
- **Fuzz / property** test over attacker-controlled bytes → never accepts an unsigned/forged input.
- **Parity** — where the same decision exists in two places (native + WASM/FFI, two languages), a
  *forge-once-bypass-everywhere* test that both reject the same forgery.
- **The positive case** — a valid input is **accepted** (so the gate isn't just "reject everything").

Each security PR **records the battery it ran** (the *levels* and the attack classes), so coverage is
auditable. A verifier-surface row also lands on the **pre-launch crypto-audit** list (`audit-flag`) —
recorded for the one batched human pass, never blocking the merge.

---

## Local check-surface green-gate

`build` + `lint` alone is **not** the gate — it misses the surfaces that bite (separate sub-workspaces,
formatting, generated-doc drift, dependency/license bans, doc tests, FFI/packaging crates). **Discover
the project's full gate surface** from `CLAUDE.md` and the CI config, and **mirror ALL of it locally**
before a PR is mergeable. (The auths instance is in the appendix.) Never merge if the **local** mirror
is red. Don't wait on remote CI; close CI-only failures with a follow-up PR.

---

## Git workflow (branch → local-green → unsigned commit → push → PR → merge)

One branch **per epic/row**, in the **repo that row touches** (a loop can span repos). Then:

1. **Branch off the mainline:** `git checkout -b loop/<area>-<short-desc>`.
2. **Do the work** — the six stages above.
3. **Gate = the local check-surface green-gate.** That is the bar; remote CI is **not** — don't wait on it.
4. **Commit unsigned, skip hooks** (so it needs no fingerprint / survives a broken hook):
   `git commit --no-gpg-sign --no-verify -m "<what changed, in plain terms>"`.
5. **Push, skip the local hook:** `git push -u origin <branch> --no-verify`.
6. **Open a PR for the record:** `gh pr create --fill` — do **not** wait for its checks.
7. **Merge to the mainline** once the local mirror is green (+ proof-gate for security rows). Most
   reliable: `git checkout main && git merge <branch> --no-edit && git push origin main --no-verify`
   (or `gh pr merge <#> --merge --admin` if branch protection allows). A later CI flag → **follow-up
   PR**, never a held loop. **No per-PR human gate** — a verifier row merges on its strengthened battery
   and carries `audit-flag` for the pre-launch audit.

Invariants: never merge if the **local** mirror is red; never merge a security row until its
strengthened battery is green + red-team-dry; never code against an undecided *one-way-door* contract; one branch
per epic; don't parallelize same-crate epics.

---

## File moves / relicense (automated gate, not human)

If the plan calls for moving or relicensing a crate, the loop executes it: `mv` it (the old `.git`
stays behind), set the `Cargo.toml`/manifest `license` field, add headers. **The gate is an automated
`secrets-scan`** of everything that moved — it must come up clean, fail-closed if not. Making a
repo/registry **public** is the human's separate act, outside the loop.

---

## How a loop *ends*: the cross-cutting reviews

When every row is `merged`/`gated`, run the two passes a per-cycle gate **structurally cannot** —
because each cycle only ever made the smallest local change to turn one probe green, and the global
shape is invisible to it:

1. **Architectural review** over the whole range — is the codebase still coherent, or did 40
   locally-minimal changes erode the design? (Bloat, DRY drift, layering, "finish the wiring" debt.)
2. **Red-team review** over the whole range — *green is guilty until proven honest*: independently
   re-derive every "done" security claim against the real code; the worst finding is a claim that
   stays green while the property is violated.

Use the project's review prompts for these (auths: `architectural_review.md`, `red_team_general.md`).
**Their output — the findings, grouped into epics ordered by attack — becomes the next loop's ledger.**
(The `20260621/progress.md` reference ledger is exactly that: the output of these two passes fed back in.
The loop is self-feeding.) These reviews **diagnose and report; they do not auto-fix** — findings land
as new rows for the next loop; verifier/crypto findings carry an `audit-flag` for the pre-launch audit,
not a per-row block.

**The pre-launch crypto audit (the one batched human step).** Once before launch — *not* per-PR — a human
cryptographer reviews the whole verifier/crypto surface (every `audit-flag` row) in one pass: the residual
*novel-break* class no fuzzer/oracle catches. It never stalls the loop (rows merged on their batteries
long before); it is a milestone you schedule when the verifier surface is stable and users are imminent.
Pre-launch, zero users, no backward-compat (per `CLAUDE.md`) is exactly what makes one batched audit —
fix-before-launch — correct, instead of a gate on every verifier PR.

---

## Residual risk (honest, because the loop owns it)

Proof-by-test catches the enumerated + fuzzed + red-teamed classes, not an unknown class — no suite can.
The defenses are breadth and *level*: the attack-class checklist, **end-to-end tests on the wired path**
(the class that actually slips), **differential testing against an independent oracle** + coverage-guided
fuzz over attacker bytes, a **constant-time check** for the timing class, ≥2 dry rounds from an
independent red-team agent, the "verify the construct, never the comment" discipline, and — for the lone
residual a fuzzer/oracle can't reach — the **one batched pre-launch crypto audit** over the verifier
surface (the only human step, and it never stalls the loop). Every security PR records the levels +
classes it ran, so coverage is auditable.

## Stop condition

Every ledger row is `merged` or `gated-*`. The loop writes a final summary, then (optionally) hands off
to the cross-cutting reviews — whose findings open the next ledger.

---

## Appendix — project specifics (auths)

The general rules above are universal; these are *this repo's instance*. A different project substitutes
its own.

**The local check-surface green-gate (auths):** `cargo build --workspace` + clippy is not enough — mirror
all of:
```bash
cargo build --workspace                                                  # DEFAULT features (--all-features trips an auths-crypto fips/cnsa compile_error)
cargo clippy --workspace --all-targets --exclude murmur-ffi -- -D warnings # murmur-ffi test targets trip a macOS-only Xcode module-map redefinition (not on Linux CI); its lib is covered by the check below
( cd packages/auths-node     && cargo check )   # pyo3/napi: separate workspace, link-fails as build → use check
( cd packages/auths-python   && cargo check )
( cd crates/murmur-ffi       && cargo check )
( cd crates/auths-mobile-ffi && cargo check )
cargo fmt --all --check
( cd packages/auths-node && cargo fmt --all --check ); ( cd packages/auths-python && cargo fmt --all --check )
cargo run -q -p xtask -- gen-error-docs --check
cargo deny check
```
A pre-existing **macOS-only** `SwiftBridging` module-map error under `clippy --all-targets` (murmur-ffi
swift test target) is env-only and Linux-CI-unaffected — excluded from the mirror.

**Repos a row may touch (auths):** `auths/` (most), the `verify/` Action repo, the `murmur/` app repo,
the `ee/` source-available tier (its own workspace; nothing in OSS `crates/` may depend *up* into it).

**`gated-ext` examples (auths):** on-chain/testnet settlement; cloud-IAM acceptance (AWS STS / GCP WIF /
Azure AD of a live JWT); a `spiffe` Go consumer accepting an issued SVID; binary code-signing + release
CI; a hosted log/registry server; republishing a released bundle; provisioning a real release-signing
identity.

**Test tooling for the strengthened battery (auths):**
- *End-to-end on the wired path* — the per-crate `tests/integration.rs` + `tests/cases/<topic>.rs` layout
  (`TESTING.md`); drive the real CLI/SDK/RP caller, not the verifier helper alone. Run with
  `cargo nextest run --workspace`.
- *Differential oracle* — KERI events/KELs against the **keripy byte fixtures** (`meta_prompt.md` §V: "pin
  to reference fixtures, not your own output"); JWT/OIDC against RFC vectors; SVID against a `spiffe`
  reference. The independent oracle is what catches the unimagined class.
- *Fuzz* — `cargo-fuzz` targets over attacker-controlled bytes on every parse/verify boundary
  (`auths-verifier`, KEL/CESR parsing, presentation envelope), invariant *never accept an unsigned input,
  never panic*.
- *Constant-time* — `subtle::ConstantTimeEq` on every secret/MAC/token compare (already used in
  `auths-scim-server`); a lint or `dudect`-style test guards it.
- *Pre-launch crypto audit (`audit-flag`)* — one batched human pass over `auths-verifier` + the crypto
  providers + the trust-anchor paths, scheduled when the verifier surface is stable and launch is near.

**Review prompts (auths):** `docs/prompts/architectural_review.md`, `docs/prompts/red_team_general.md`
(or `red_team.md`). **Coding rules:** `docs/prompts/meta_prompt.md`.
