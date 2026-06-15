# Auths — Go-to-Market First-Run Checklist

> Re-verified live on **2026-06-09** (`auths 0.0.1-rc.12`, macOS 15.2). Supersedes `go_to_market.md`.
> Every task is **polish / fix / merge / release — no new features.** Evidence is inline (`file:line`,
> command, or output) so any item can be picked up cold.

**Tags:** priority `P0` (bounce in first 5 min) · `P1` (credible launch) · `P2` (polish) ·
effort `S/M/L` · kind `EDIT` (reversible) / `OPS` (push/tag/release/deploy — irreversible).

**The one thing to know:** most fixes were already *written* — they're **stranded on unmerged branches**
(`sign` `fn-152-b2`, `verify` `fn-152-b1`, widget `fn-152-c1`) and never released. So `@v1`, npm, and brew
all still serve the *old* broken artifacts. Remaining work ≈ 60% merge/release OPS + 40% finishing the
cleanup the branches missed.

### The golden path today (what a new dev actually hits)
1. `brew install auths` — ⚠️ installs **rc.9** (3 behind); `get.auths.dev` curl → **404**
2. `auths init` — ⚠️ works, but the success screen says "Next step: `auths git setup`" (a command that errors)
3. `auths demo` ("30-second aha") — ❌ **hangs forever** on a Touch ID prompt, zero output
4. sign a commit (README: `auths git setup`) — ❌ `unrecognized subcommand 'git'`
5. verify (README: `auths verify-commit HEAD`) — ❌ `unrecognized subcommand 'verify-commit'`
6. browser badge — ❌ wrong SRI hash blocks the script; flagship demo shows 3 red error pills

### Start here (critical path order)
`AU-1` demo hang → `AU-4`/`AU-5` README + dead strings → `AU-8` drift lint → `VER-1`/`SIGN-1` release the
actions → `DOCS-1`/`DOCS-2`/`DOCS-3` docs → `WID-1` SRI → `BADGE-1` release asset → `AU-12`/`BREW-1` install.

### 🚫 Do not ship until green (P0s)
`AU-1` `AU-4` `AU-5` `AU-12` · `SIGN-1` `VER-1` · `WID-1` `BADGE-1` · `DOCS-1` `DOCS-2` `DOCS-3` · `BREW-1`

---

## Repo: `auths` (the CLI — `crates/`, `README.md`, `packages/`, `scripts/`)

### Epic A — First-run "aha" & CLI UX
- [x] **AU-1 — `auths demo` hangs on Touch ID** · `P0 · EDIT · M`
  **Broken:** the headline "Try sign + verify in 30 seconds" command hangs indefinitely with zero output.
  Process sample: `DemoCommand::execute → sign_artifact → secure_enclave::sign_with_handle → seSign →
  NSXPCConnection __WAITING_FOR_A_SYNCHRONOUS_REPLY__` (LocalAuthentication / Touch ID). Dead-ends in any
  CI/SSH/no-biometric context.
  **Fix:** make `demo` mint an ephemeral in-process **software** key (the Memory keychain backend already
  exists — `--profile ci` uses it) so it signs + verifies in-process and never touches the Secure Enclave.
  Done when: `auths demo` runs green on a TTY-less shell in <5 s with no prompt.

- [x] **AU-2 — `init --profile ci` → `sign` dead-ends** · `P1 · EDIT · M`
  **Broken:** the only non-biometric path is broken. `init --profile ci` mints an **in-memory (ephemeral)**
  key *and ignores the global `--repo` flag* (writes `.auths-ci/` in CWD). The follow-up `auths sign` →
  `[ERROR] No identity found. Run auths init`. The two commands don't connect.
  **Fix:** honor `--repo`; persist a file-backed CI key by default; or have `sign` re-print the env-var
  export block when it detects a half-finished ci setup. Done when: a documented 2-command CI sequence
  produces a verifiable signature headlessly.

- [x] **AU-3 — `auths --help` shows an empty "CI/CD:" section** · `P2 · EDIT · S`
  **Broken:** top-level help prints a `CI/CD:` heading with no commands under it (looks unfinished).
  **Fix:** drop the empty section (or populate it).

### Epic B — Kill README / CLI command drift (+ ratchet)
- [x] **AU-4 — README quickstart breaks on copy-paste** · `P0 · EDIT · S`
  **Broken:** `README.md:71,84,113-127` tell users to run `auths git setup`, `verify-commit`, `device link`,
  `signers …`. Live: `auths git setup` → `unrecognized subcommand 'git'`, `verify-commit` → same, `signers
  list` → same. The `status` sample output is also fake (`Devices: 1 linked` / "Ready to sign commits" vs
  real `Devices: none`). Real tree: `cli.rs:88-160` (init/sign/verify/status/whoami/pair/trust/doctor/demo).
  **Fix:** rewrite the quickstart + commands table to the real tree; note `init` already configures Git (so
  there's no separate setup step); fix the sample output.

- [x] **AU-5 — CLI prints dead commands** · `P0 · EDIT · S`
  *(2026-06-09: all listed sites fixed + extra drift the new lint caught — `auths id migrate`/`identity
  forget`/`debug index rebuild`/`auths tutorial`/`trust pin`/`key import --seed-file`/`id rotate
  --next-key-alias`, plus after_help examples in policy/key/org/trust and `doctor` suggestions.)*
  **Broken:** the user's own terminal lies. Sites: `init/display.rs:31` (post-init "Next step … `auths git
  setup`"), `learn.rs:240,459`, `key_detect.rs:72`, `bin/verify.rs:154`, `emergency.rs:479`,
  `errors/cli_error.rs:21,43,45` (suggests `auths device link --device-alias/--capability` — flags that
  don't exist), `id/identity.rs:782`, `id/migrate.rs:896`.
  **Fix:** replace every dead string with a real command. Done when: `rg 'git setup|verify-commit|signers
  (sync|list|add)'` over `crates/auths-cli/src` returns nothing user-facing.

- [x] **AU-6 — In-CLI doc links 404** · `P1 · EDIT · S`
  *(2026-06-09: all subpath links parked on the live docs root — only `/` returns 200 today; restore deep
  links when the docs site ships routes.)*
  **Broken:** `auths sign`'s "No identity found" error links to `https://docs.auths.dev/getting-started/
  quickstart/` → **404** (also `/docs/quickstart` → 404; only the root → 200).
  **Fix:** point CLI links at a live URL; confirm where `auths-docs` is actually deployed.

- [x] **AU-7 — Personal Fly URL is the default registry** · `P1 · EDIT · S`
  *(2026-06-09: default → `https://registry.auths.dev`, hardcoded fly.dev literals consolidated to
  `DEFAULT_REGISTRY_URL`, `AUTHS_REGISTRY_URL` env override added (flag > env > default); `--register` was
  already opt-in. DNS for registry.auths.dev still needs pointing at the Fly app.)*
  **Broken:** `https://auths-registry.fly.dev` is the baked-in default (`init --help`, `publish.rs:35`,
  `org.rs:257`, SDK `DEFAULT_REGISTRY_URL`).
  **Fix:** neutral/overridable default; make `--register` opt-in; document offline-first.

- [x] **AU-8 — Build the xtask command-drift lint (ratchet)** · `P1 · EDIT · M`
  **Broken:** there's no `xtask/` dir; nothing stops AU-4/AU-5 from regressing (the planned ratchet was
  never built).
  **Fix:** an xtask that fails the build if any user-facing string (`println!`/help/README) names a command
  not in `RootCommand`; drive AU-4/AU-5 to green against it.
  *(2026-06-09: `cargo run -p xtask -- check-command-drift` — note `crates/xtask/` already existed, the
  claim above was stale. Validates `auths <cmd> [<sub>] [--flags]` in README + every auths-cli string
  literal against the tree discovered from `--help-all`; wired into the CI `xtask-checks` job; found 18
  violations on first run, all fixed, now green. Side-finding: `cargo xtask gen-error-docs` is broken on a
  pre-existing duplicate error code — AUTHS-E4801..05 used by both `auths-id::ResolveError` and
  `::RotationError` — needs renumbering.)*

### Epic C — SDK & verifier packages (`packages/*`)
- [x] **AU-9 — TS verifier wrong name & unpublished** · `P1 · EDIT/OPS · S`
  *(2026-06-10: @auths-dev/verifier published (0.1.2))*
  *(2026-06-09: EDIT done — renamed to `@auths-dev/verifier` across all 21 refs incl. docs; the missing
  `publish-typescript.yml` workflow added. OPS pending: publish via `epic_c_publish_runbook.md` §1.)*
  **Broken:** `packages/auths-verifier-ts/package.json:2` = `@auths/verifier` (wrong org); not published
  under either name; docs say `npm install @auths/verifier` (`docs/sdk/verifier/wasm.md:8`) → 404.
  (Distinct from the published *browser widget* `@auths-dev/verify`.)
  **Fix:** rename to `@auths-dev/verifier`, publish, fix every install doc.

- [x] **AU-10 — Go module path doesn't resolve** · `P1 · EDIT · S`
  *(2026-06-10: module path fixed; tags packages/auths-verifier-go/v0.1.2 pushed; go get resolves)*
  *(2026-06-09: EDIT done — module path → `github.com/auths-dev/auths/...` in go.mod/README/build.sh (+ a
  stray ref in the auths-verifier-swift README); README documents the `packages/auths-verifier-go/vX.Y.Z`
  nested-module tag convention. OPS pending: push the tag — runbook §5.)*
  **Broken:** `packages/auths-verifier-go/go.mod:1` = `github.com/auths/auths/...`; org `auths/auths`
  doesn't exist; `go get` fails (README repeats the bad path).
  **Fix:** use the `auths-dev` org; flatten/tag so the subpath resolves.

- [x] **AU-11 — SDKs frozen + squat stubs** · `P1 · OPS · M`
  *(2026-06-09: EDIT done — `@auths-dev/express` rename (11 refs), python+node SDKs bumped to 0.2.0,
  `npm-stubs/` sources deleted. OPS pending: republish SDKs + `npm deprecate` the policy/react stubs —
  see `roadmap/go_to_market/plans/epic_c_publish_runbook.md` §2–§4.)*
  **Broken:** PyPI `auths` stuck at 0.1.0 (2026-04-03); npm `@auths-dev/sdk` 0.1.0; `@auths-dev/policy` and
  `@auths-dev/react` published as **throw-on-import** "coming soon" stubs (`npm-stubs/`); `@auths/express`
  wrong org (`packages/auths-express/package.json:2`).
  **Fix:** republish the SDKs to match the CLI; retire or ship the stubs; fix the express org.

### Epic D — Install & release plumbing
- [x] **AU-12 — Deploy the curl installer** · `P0 · OPS · M`
  *(2026-06-09: DEPLOYED + verified — `curl -fsSL https://get.auths.dev | sh` installs rc.12 end-to-end
  (checksum-verified, `auths --version` green). Hosted as a Vercel edge function (`deploy/get-auths-dev/`),
  NOT the planned Cloudflare Worker: the `auths.dev` zone lives on Vercel DNS, so CF can't bind the domain;
  the worker was deleted. Serves `scripts/install.sh` from `main` at request time (5-min edge cache) — no
  per-release action. Checksum/`AUTHS_VERSION`-pin docs added to `docs/getting-started/install.md`.)*
  **Broken:** `curl -fsSL https://get.auths.dev | sh` → **404**. `scripts/install.sh` is written but never
  deployed (referenced in `docs/index.md:33` and `install.sh:3`).
  **Fix:** DNS + host `install.sh` at `get.auths.dev`; add checksum/version-pin docs.

- [x] **AU-14 — crates.io drift + no publish automation** · `P2 · EDIT/OPS · M`
  *(2026-06-10: full 25-crate stack on crates.io at 0.1.2 incl. auths-cli (publish=false blockers flipped; topological publish-crates job))*
  *(2026-06-09: done — tag-gated `publish-crates.yml` added (wraps the layer-ordered, idempotent
  `scripts/releases/2_crates.py`; also `workflow_dispatch` dry-run/publish); `install.md:123` rc.10 string
  replaced with a non-pinned expected output. OPS pending: add the `CARGO_REGISTRY_TOKEN` repo secret —
  crates.io stays at rc.8 until the next `v*` tag, per owner decision not to backfill rc.12.)*
  **Broken:** `cargo install auths-cli` installs **rc.8** (4 behind); no `cargo publish` job exists; docs
  recommend it (`docs/getting-started/install.md:23`, and `:123` tells users to expect rc.10).
  **Fix:** add a tag-gated, layer-ordered cargo-publish job (or stop recommending the registry path); fix
  the version strings.

- [x] **AU-15 — Release-sync ratchet** · `P1 · EDIT/OPS · M`
  *(2026-06-09: done — `scripts/releases/0_versions.py` syncs npm/PyPI/mobile-ffi versions to the workspace
  version (`--check` gate in ci.yml + publish-crates.yml; `just release-versions` to stamp); brew formula now
  pushed directly to the tap from release.yml (PR flow removed — bot PRs were never merged); one `v*` tag now
  fans out to binaries+brew, crates, npm, PyPI — flow documented in `scripts/releases/README.md`. The sign/
  verify `v1` action tags are SIGN-1/VER-1 scope. PyPI note: stale `auths` 0.1.0 sorts above `0.0.1rc12` —
  yank it at AU-11 republish time or `pip install auths` keeps resolving 0.1.0.)*
  **Broken:** every CLI release leaves brew + PyPI + npm + crates + the `v1` tags behind — the root cause of
  most of the OPS backlog.
  **Fix:** one release job that bumps them all together.

---

## Repo: `sign` (GitHub Action)

### Epic — Ship the action
- [x] **SIGN-1 — Merge + release the fix branch** · `P0 · OPS · S`
  *(2026-06-09: v1.1.0 released, v1 moved; later pins bumped to auths 0.1.2)*
  **Broken:** the `fail-on-unanchored`/`RootNotPinned` feature, LICENSE, CHANGELOG, examples, and the
  v1.1.0 bump are all committed on `fn-152-b2` but **unpushed**. Remote HEAD and `@v1` = `3f49d2d`
  (2026-04-15, pre-feature); `gh release list` tops at v1.0.2. So `@v1` users get a bundle that contradicts
  `action.yml`/README.
  **Fix:** merge `fn-152-b2` → main (clean fast-forward), push, tag `v1.1.0` (`release.yml:80-85` moves the
  floating `v1`). Done when: `@v1` contains `RootNotPinned` and a v1.1.0 release exists.

- [x] **SIGN-2 — README Quick Start is non-runnable** · `P1 · EDIT · S`
  *(2026-06-09: complete runnable workflow in README)*
  **Broken:** `README.md:6-18` shows only `permissions:` + `steps:` — no `jobs:`, `runs-on:`, or
  `actions/checkout@v4`. Copying it yields an invalid workflow with nothing checked out.
  **Fix:** make it a complete workflow, or point readers to `examples/.github/workflows/auths.yml`.

- [x] **SIGN-3 — Stale installer JSDoc** · `P2 · EDIT · S`
  *(2026-06-09: JSDoc corrected)*
  **Broken:** `installer.ts:15` says "or empty for latest" but `:33-37` throws when version is empty.
  **Fix:** correct the doc comment.

---

## Repo: `verify` (GitHub Action)

### Epic — Ship the action
- [x] **VER-1 — Merge + release the fix branch** · `P0 · OPS · S`
  *(2026-06-10: fn-152-b1 merged, v1.4.0 then v1.4.1 released, v1 moved; action pins auths 0.1.2 and ships stateless KEL-carrying bundle verification)*
  **Broken:** the `token`→`identity-bundle` rename, `auths-version` pins, Apache license, CHANGELOG, dynamic
  badge, and v1.4.0 are committed on `fn-152-b1` but **unpublished**. Published `action.yml` input is still
  `token:` (main) / `identity:` (`@v1`); package.json is MIT/1.0.2. `@v1` = `c4f8b83` (2026-04-15). The
  *current* README (which uses `identity-bundle` + `auths-version`) will not run against `@v1`.
  **Fix:** merge `fn-152-b1` → main, cut a real `v1.4.0` release, move `v1` (`release.yml:70-75`).

- [x] **VER-2 — README Outputs table incomplete** · `P2 · EDIT · S`
  *(2026-06-10: artifacts-verified/artifact-results rows added)*
  **Broken:** omits real outputs `artifacts-verified` / `artifact-results` (`action.yml:58,60`).
  **Fix:** add the rows.

- [x] **VER-3 — Metadata + badge polish** · `P2 · EDIT · S`
  *(2026-06-10: author/keywords fixed; static endpoint.json badge dropped for the live workflow badge)*
  **Broken:** stale `ssh-signatures` keyword (`package.json:16`); `author` mismatch (`package.json:18`
  "auths" vs `action.yml:3` "auths-dev"); the "dynamic" badge is a fixed JSON file (`endpoint.json` =
  `{"message":"auths"}`), so it never reflects pass/fail.
  **Fix:** accurate keyword/author; point the README badge at the genuinely-dynamic workflow-status badge or
  drop it.

---

## Repo: `auths-verify-widget` (the browser embed)

### Epic — Make the embed actually render
- [x] **WID-1 — SRI hash mismatch browser-blocks the embed** · `P0 · EDIT · S`
  *(2026-06-10: 0.4.0 published via the new dispatch workflow; SRI computed from the registry tarball and byte-verified against unpkg AND jsDelivr (sha384-C6a5GC…); README + Embed Builder constants updated)*
  **Broken:** the README `integrity` hash `sha384-M1UJ…` (`README.md:18,41`) does **not** match the
  published `@auths-dev/verify@0.3.0` bytes `sha384-SoPr…`, so the browser refuses the script and nothing
  renders. `examples/embed-snippet.ts:13` hardcodes the same wrong hash, so the Embed Builder emits poisoned
  snippets too.
  **Fix:** regenerate the SRI from the *published* artifact; bake `npm run sri` against the published tarball
  into the release process. Done when: the README snippet loads with `integrity` enabled.

- [x] **WID-2 — Land the fix branch (CI is red)** · `P1 · EDIT/OPS · M`
  *(2026-06-10: cross-repo WasmModule drift fixed in auths (validateKelJson), fn-152-c1 merged at 0.4.0, CI green)*
  **Broken:** the resolver-doc fix, SRI guidance, and Embed Builder are stranded on `fn-152-c1`; its CI
  fails typecheck (`Property 'verifyKelJson' is missing … WasmModule`, `gh run view 27172660495`) from
  cross-repo WASM drift. origin/main and published npm 0.3.0 still tell the old `refs/auths/*` story.
  **Fix:** rebuild `build:wasm` against current `auths` / reconcile the `WasmModule` type; get CI green;
  merge; republish.

- [x] **WID-3 — Embed Builder link is a 404** · `P1 · OPS · S`
  *(2026-06-10: Pages enabled via API (build_type=workflow), builder live at auths-dev.github.io/auths-verify-widget)*
  **Broken:** `README.md:76` links the Embed Builder at `auths-dev.github.io/auths-verify-widget/` → 404
  (Pages not enabled; `pages.yml` self-notes this).
  **Fix:** enable Pages (Source = GitHub Actions); re-point the builder's default away from the no-asset repo.

---

## Repo: `example-verify-badge` (the flagship demo)

### Epic — Make the flagship demo green
- [x] **BADGE-1 — No release asset → demo errors** · `P0 · OPS · S`
  *(2026-06-10: release v0.1.0 published with signed *.auths.json attestation asset; verify gate migrated to verify@v1 + KEL bundle and green)*
  **Broken:** `gh release list` → `[]`; `releases/latest` → 404. The Pages site is up (200), so every
  visitor sees **3 red error pills** instead of green badges.
  **Fix:** sign the repo and publish the `*.auths.json` release asset the resolver fetches.

- [x] **BADGE-2 — README/demo lie + anti-pattern** · `P1 · EDIT · S`
  *(2026-06-10: demo + README pin @auths-dev/verify@0.4.0 with integrity + crossorigin; README rewritten to the Releases-asset model (user WIP incorporated))*
  **Broken:** `README.md:21` still claims resolution from `refs/auths/registry`; the demo + README use
  unpinned `@latest` with no SRI (contradicting the widget's own "never `@latest`" guidance).
  **Fix:** rewrite to the Releases-asset model; pin `@0.3.0` + SRI + `crossorigin`.

---

## Repo: `auths-docs` (the docs site)

### Epic — Truthful docs
> The markdown was fixed in a prior pass; the **React components were not** — that's where the worst drift lives.
- [x] **DOCS-1 — Leaked Stripe-style API key** · `P0 · EDIT · S`
  ✅ 2026-06-10: deleted the entire `/docs/authentication` CodeExamples entry (leaked key gone) (fn-4 merged → main, commit 3833c91; NOTE: site not yet deployed anywhere — docs.auths.dev serves mkdocs from the auths repo; Vercel setup tracked in auths-docs#2).
  **Broken:** `components/docs/CodeExamples.tsx:11-28` renders `Auths.apiKey = "sk_test_51TGscvIB…"` live on
  `/docs/authentication` — a page whose own body says "there is no `sk_live_…` to leak." Credibility kill.
  **Fix:** delete the `/docs/authentication` example entry.

- [x] **DOCS-2 — ~11 dead commands in the right-sidebar component** · `P0 · EDIT · M`
  ✅ 2026-06-10: all 5 sidebar entries rewritten to real commands (verify HEAD, trust pin, export-bundle, id agent add, sign@v1/verify@v1 @0.1.2, cargo install auths-cli, doctor) (fn-4 merged → main, commit 3833c91).
  **Broken:** `CodeExamples.tsx:30-124` shows `auths verify-commit`, `auths health`, `auths prove`, `auths
  verify-branch`, `auths agent create`, `auths identity create`, `cargo install auths`, and
  `auths-dev/auths-action@v1` on every guide page — none exist.
  **Fix:** rewrite each example to real commands (mirror the already-correct `.md` files).

- [x] **DOCS-3 — `auths trust add` wrong in 4 guides** · `P0 · EDIT · S`
  ✅ 2026-06-10: all 4 guides now use `auths trust pin --did <> --key <pubkey-hex>` with share-your-key copy (fn-4 merged → main, commit 3833c91).
  **Broken:** `sign-commits.md:52`, `team-identities.md:26`, `prove-provenance.md:20`, `authentication.md:27`
  use `auths trust add`; the real command is `auths trust pin --did <> --key <>` (`trust.rs:43`).
  **Fix:** correct the command (the core team/trust flow currently fails on copy-paste).

- [x] **DOCS-4 — Anthropic branding + wrong CTA** · `P1 · EDIT · S`
  ✅ 2026-06-10: CTA → /docs/quickstart; footer → auths.dev link, © 2026 auths-dev (fn-4 merged → main, commit 3833c91).
  **Broken:** footer is "© 2024 Anthropic" with an anthropic.com link (`app/page.tsx:134-144`); the hero
  "Get Started" CTA points at `/docs/installation`, not the canonical `/docs/quickstart` (`app/page.tsx:34`).
  **Fix:** rebrand to auths-dev/2026; repoint the CTA to quickstart.

- [x] **DOCS-5 — Newcomer accuracy & stubs** · `P2 · EDIT · M`
  ✅ 2026-06-10: `--non-interactive` fix, did:keri/KEL/attestation glosses, 5 stubs marked 🚧 with real pointers (cli.md now has command tables); also bumped stale rc.12 pins → 0.1.2 (fn-4 merged → main, commit 3833c91).
  **Broken:** quickstart claims `auths init --profile developer` "skips the prompts" (it doesn't —
  `--non-interactive` does; `quickstart.md:35-39`); jargon (`did:keri:`, KEL, attestation) appears with no
  gloss; concept + CLI-reference pages are "coming soon" stubs.
  **Fix:** correct the flag claim; add one-line glosses on first use; fill or clearly mark the stubs.

---

## Repo: `homebrew-auths-cli` (the brew tap)

### Epic — Current, consistent tap
- [x] **BREW-1 — Formula is 3 versions stale** · `P0 · OPS · S`
  *(2026-06-10: formula at 0.1.2 (manual push; HOMEBREW_TAP_TOKEN expired — regenerate for auto-bump))*
  **Broken:** `Formula/auths.rb:4` pins **rc.9**; latest release is rc.12. The auto-update PR
  (`release.yml:227-239`) only *opens*, never merges; an rc.11 bump was even reverted (`ac59297`).
  **Fix:** bump to rc.12 and enable auto-merge on the bot PR (or commit directly — pre-launch, no review
  gate). Done when: `brew install auths` installs the latest release.

- [x] **BREW-2 — Repo refs say `bordumb`, not `auths-dev`** · `P1 · EDIT · S`
  *(2026-06-09: all bordumb/ refs rewritten to auths-dev/; quickstart example updated to verify@v1 + bundle)*
  **Broken:** `README.md:3,8,14`, `QUICKSTART.md`, and `justfile:13` (which points at a nonexistent
  `bordumb/auths-releases`) use the wrong org; the canonical docs say `auths-dev`.
  **Fix:** rewrite all `bordumb/…` references to `auths-dev/…`.

---

## Repo: `auths-mobile` (iOS hero demo; Android cut)

### Epic — iOS: LAN demo & TestFlight
- [x] **IOS-1 — Write the LAN pairing hero-demo runbook** · `P1 · content · S`
  ✅ 2026-06-10: docs/LAN_PAIRING_RUNBOOK.md written against live `auths pair -h` (QR + short-code paths, SAS verify, Authenticate-tab login, troubleshooting table); recovery noted as relay-only, out of demo scope (dev-securityHardening d262574, signed+pushed).
  **Broken:** pairing works *today* (Bonjour `PairingService.swift:41-151`, Secure-Enclave device
  signatures, committed `AuthsMobileFfi.xcframework`) but there's no runbook to follow.
  **Fix:** write a reproducible "pair phone ↔ laptop and sign in over LAN, zero backend" runbook. Scope to
  pairing/login — **not** lose-laptop recovery (that half is stubbed; see IOS-4).

- [x] **IOS-2 — Unblock TestFlight** · `P1 · EDIT · M`
  ✅ 2026-06-10: Assets.xcassets (generated 1024px placeholder AppIcon + AccentColor) + Auths.entitlements (aps-environment dev, keychain group) wired into pbxproj; simulator build green (icon compiled, entitlements embedded). Note: xcframework has no x86_64 sim slice — build arm64 sim (dev-securityHardening d262574, signed+pushed).
  **Broken:** no `Assets.xcassets` (pbxproj references `AppIcon`/`AccentColor` at `:511-512`); no
  `*.entitlements` (the app calls `registerForRemoteNotifications()` at `PushNotificationService.swift:32`
  with no `aps-environment` → runtime failure). Both are hard submission blockers.
  **Fix:** add the asset catalog (AppIcon + AccentColor) and an `Auths.entitlements` (aps-environment +
  Keychain access group).

- [x] **IOS-3 — Wire the XCTest target** · `P2 · EDIT · M`
  ✅ 2026-06-10: AuthsTests PBXNativeTarget + shared scheme hand-wired (9 test files); `just test-ios` green (justfile sim bumped iPhone 15→16, all suites pass) (dev-securityHardening d262574, signed+pushed).
  **Broken:** `just test-ios` runs a scheme `AuthsTests` that isn't in the pbxproj; 8 test files sit
  uncompiled.
  **Fix:** add the test target + scheme (the tests already exist).

### Epic — Cut dead surfaces
- [x] **IOS-4 — Cut the dead-backend UI + fix the README** · `P1 · EDIT · M`
  ✅ 2026-06-10: Emergency Controls NavigationLink removed, dead APIService revoke path cut from DevicesView (replaced with `auths device remove` hint), CreateIdentityView copy honest, README rewritten local-first (Bearer/REST catalog deleted) (dev-securityHardening d262574, signed+pushed).
  **Broken:** Emergency Freeze (`EmergencyView.swift:155`) and device-revoke (`DevicesView.swift:67`) call
  `api.auths.io` bearer endpoints — a host that doesn't exist and an auth model the design rejects. The root
  `README.md:12,83-93` sells that bearer/REST model. The "Recovery ready" onboarding copy
  (`CreateIdentityView.swift:60-62`) is unsubstantiated (recovery is stubbed: `SharedKELService.swift:37-40`
  throws `removalNotYetSupported`).
  **Fix:** hide Emergency Freeze + device-revoke for launch; rewrite the README to the LAN/device-signature
  model; soften the recovery copy.

- [x] **IOS-5 — Cut Android from GTM** · `P1 · decision`
  ✅ 2026-06-10: DECISION: Android out of launch scope — README section reduced to a note; android/ scaffold kept in tree as roadmap item (dev-securityHardening d262574, signed+pushed).
  **Broken:** bindings-free scaffold (no uniffi/`.so`); `ApiService.kt:18` hardcodes `api.auths.io` bearer;
  pairing is a `"test-qr-data"` mock. A rebuild, not a fix.
  **Fix:** remove Android from launch scope (the rebuild is a roadmap item, not GTM).

---

## Carry-forward (verify before launch)
- [x] **D-7 — `auths-agent-demo`** wasn't in this run's live-walk set. Re-check its `did:key:` assertion and
  ✅ 2026-06-10: venv + published PyPI wheel auths==0.1.2: demo restructured (capabilities are operator-side grants now — 0.1.2 attestations no longer carry them; did:key assertions still pass) and prints ALL ASSERTIONS PASSED, stable 4/4 runs; found+filed 2 SDK bugs it works around: #252 delegate_agent signs with stale key post-rotation, #253 get_public_key nondeterministic KEL walk; README install switched to `pip install auths`
  `pip install -e .` path before linking it as the canonical hello-world.
</content>
