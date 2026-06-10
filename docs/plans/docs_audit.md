# Docs Audit — mkdocs site vs. codebase reality (2026-06-10)

> **STATUS: IMPLEMENTED (2026-06-10, same day).** All phases executed: internal docs
> excluded from the published site (`exclude_docs`), error docs regenerated (E5008,
> nav collapsed to one line via the generator), factual corrections applied with
> outputs regenerated from the real binary, device model rewritten delegation-first,
> nav restructured (Concepts + Reference sections, glossary surfaced), six new pages
> written (verify-and-trust, agents, artifacts, troubleshooting, orgs, uninstall),
> Radicle guide archived with a removal banner. `mkdocs build`: zero warnings.

Honest review of the docs site (`mkdocs.yml` + `docs/`), written to be executed by an LLM
in phase order. Each item has: file → problem → fix → how to verify. Do the phases in
sequence — Phase 1's factual corrections must land before Phase 4 moves content around,
or you'll touch every file twice.

**Verification harness for every phase:** `cargo build -p auths-cli` then check claims
against `./target/debug/auths <cmd> --help` and `python3 docs/smoketests/end_to_end.py`
(54/54 is the current baseline; the smoke test exercises the exact flows the docs teach).
`cargo run -p xtask -- check-command-drift` validates CLI strings + README but does NOT
cover `docs/` pages — do not assume a page is correct because drift CI is green.

---

## Facts the executor must hold (the docs contradict several of these)

1. **P-256 is the default curve**, not Ed25519 (`crates/auths-crypto/src/provider.rs`;
   chosen because iOS Secure Enclave is P-256-only). Default device DIDs look like
   `did:key:zDna…`, not `did:key:z6Mk…`. Ed25519 is supported, not default.
2. **KERI delegation is the device model.** A device's authoritative identity is its
   delegated `did:keri:` AID (`dip` event anchored by the root). The dual-signed
   attestation + `auths device link` flow is **legacy** (`device add` help text says so).
   Attestation-based pairing was removed in Epic A2.
3. **As of 2026-06-10 (this branch), plain `git commit` → `auths verify HEAD` works**:
   `auths init` installs a `prepare-commit-msg` hook (global `core.hooksPath` →
   `~/.auths/githooks/`) that injects `Auths-Id`/`Auths-Device` trailers and seeds the
   repo's committed `.auths/roots` on first commit. Verification has **self-trust** (your
   own identity is always a trusted root locally). `auths sign <ref>` is a
   backfill/repair tool that rewrites commits. `docs/getting-started/signing-commits.md`
   is already updated to this reality — use it as the reference for tone and content.
4. **Verify exit codes are a contract**: 0 = verified, 1 = verification failed (includes
   untrusted/unresolvable signer), 2 = could not attempt. Documented in `verify --help`.
5. **`trust pin --did <did>` alone works** (key resolved from the local KEL); `--bundle
   <file>` accepted; `--key <hex>` is the air-gap fallback only.
6. **Registration is opt-in** (`--register`), never automatic, and the default registry
   `https://registry.auths.dev` is not live yet (404). Do not document registry flows as
   the happy path.
7. **`auths-radicle` is deleted** from the workspace (this branch). The Radicle
   integration no longer exists in tree.
8. **KERI event signatures ride in CESR attachments**, not in an `x` field on the event
   JSON. Any sample event showing `"x": "<signature>"` is showing a wire format that
   never ships (and sig-payload drift caused a real release bug — precision here matters).
9. `status` now reports `Devices: this device (did:keri:…)` — never `Devices: none` after
   init. `whoami --json` exposes `device_did`, `public_key_hex`, `curve`.
10. CI profile init prints the env block to **stdout** (pipeable), 15 vars including
    `core.hooksPath`. A weak `AUTHS_PASSPHRASE` fails preflight with **AUTHS-E5008**
    naming the env var (policy: ≥12 chars, ≥3 of 4 character classes).

---

## Phase 0 — Stop the bleeding (publishing + generation hygiene)

### 0.1 Internal documents are published on the public docs site
`mkdocs.yml` defines a `nav`, but mkdocs **builds every file under `docs/`** regardless —
non-nav pages are reachable by URL and indexed by site search. Currently published:
`docs/plans/` (including `plans/audit.md`, an internal audit with letter grades),
`docs/prompts/`, `docs/smoketests/` (including this branch's findings), `docs/proposed-issues/`,
`docs/deployment/`, `docs/E2E_TEST_CHECKLIST.md`.
**Fix:** add the `exclude` mkdocs plugin (or `mkdocs-exclude`) excluding `plans/*`,
`prompts/*`, `smoketests/*`, `deployment/*`, `E2E_TEST_CHECKLIST.md` — or move those
directories out of `docs/` entirely (preferred; they are repo docs, not site docs).
Keep `design/`, `essays/`, `proposed-issues/`, `archive/` only if intentionally public
(index.md links them deliberately — confirm with owner; default keep).
**Verify:** `mkdocs build 2>&1 | grep "not included in the nav"` lists nothing internal;
search the built `site/` dir for "audit.md".

### 0.2 Error docs are stale and the nav is malformed
- `AUTHS-E5008` (WeakPassphrase at setup, added this branch) has no page and no nav entry.
- The Error Codes nav repeats section keys (`auths-crypto` twice, `auths-core` four
  times, `auths-keri` twice) — duplicate-label sections render confusingly.
- 400+ nav lines for error stubs drown the rest of the nav.
**Fix:** run `cargo run -p xtask -- gen-error-docs` to regenerate pages + nav block.
Then collapse the nav to a single entry — `- Error Codes: errors/index.md` — and let
`errors/index.md` (generated table) link the per-code pages. Per-code pages stay on disk
and reachable; they don't need 370 nav lines.
**Verify:** `auths error show AUTHS-E5008` works and `docs/errors/AUTHS-E5008.md` exists;
`mkdocs build` clean.

### 0.3 Decide the orphans
`docs/getting-started/credentials.md`, `docs/architecture/device-model.md`,
`docs/architecture/keri-only-roadmap.md`, `docs/OIDC_COMMIT_SIGNING.md` exist but are not
in the nav. Either nav them (device-model.md belongs under Architecture → Design) or
mark them draft/move them. Don't leave them half-published.

---

## Phase 1 — Factual corrections (page by page; wrong → right)

### 1.1 The curve error (systemic — fix every instance in one sweep)
`grep -rn "Ed25519" docs/getting-started docs/guides docs/architecture docs/contributing docs/index.md`
and audit each hit. The pattern to apply:
- "generates an Ed25519 keypair" → "generates a P-256 keypair (Ed25519 available via
  `--curve ed25519`)" — in `your-first-identity.md:19`, `how-it-works.md:13`,
  `identity-lifecycle.md`, `profiles.md` (developer profile step 4), `trust-model.md:33`.
- `did:key:z6Mk…` examples → `did:key:zDna…` where illustrating the *default*; keep one
  table showing both encodings (`z6Mk` = Ed25519, `zDna` = P-256), e.g. in
  `how-it-works.md` "Two kinds of DID".
- `contributing/glossary.md`: "Ed25519 … used for all Auths signing operations" is flatly
  wrong → describe both curves with P-256 default + why (Secure Enclave). Same for the
  `did:key` and Multicodec entries (`0xED01` is Ed25519-only; P-256 is `0x1200`).
**Verify:** `auths init` in a temp HOME, `auths whoami --json` → `curve: "p256"`, device
DID starts `did:key:zDna`.

### 1.2 `docs/index.md` — the Quick Tour doesn't run
- `auths sign` bare → error (TARGET required). `# Sign a commit (after configuring Git)`
  comment is stale (init configures Git; nothing more to do).
- Missing the actual 30-second aha: `auths demo` (9 ms, zero setup) appears nowhere on
  the entire site.
**Fix:** Quick Tour becomes:
```bash
auths init        # one-time: identity + git signing + commit hook
git commit        # signed and trailered automatically
auths verify HEAD # green
auths demo        # or: try sign+verify in-process, zero setup
```
- "Multi-Device Identity" card: "link … via signed attestations" → "delegated under your
  root identity (KERI delegation)".
**Verify:** every command in the page runs cleanly in a fresh HOME.

### 1.3 `getting-started/your-first-identity.md`
- Step list: "generates an Ed25519 keypair" (1.1); add step: "installs the
  commit-trailer hook (`core.hooksPath`)".
- "Non-interactive mode … automatic registry registration" → **wrong**, registration is
  opt-in via `--register`; remove the claim.
- `auths status` sample output is stale → real output now includes
  `Devices:    this device (did:keri:…)`, `Key aliases: main, main--next-0`, Agent line,
  Next steps. Paste actual output from a fresh init.
- `auths doctor` sample is stale → regenerate from a real run (now includes "Commit
  trailer hook" and "Repo hook override" advisory checks; exit codes 0/1/2 documented in
  `doctor --help`).
- `auths key list` sample shows only `main` → real output includes `main--next-0`; add
  one sentence: "`main--next-0` is your pre-committed rotation key — KERI pre-rotation
  means the next key is promised in advance" (this preempts a guaranteed user question).
**Verify:** run each command in a fresh temp HOME; samples must match modulo DIDs.

### 1.4 `getting-started/sharing-your-identity.md`
- "your identity was registered automatically during setup" → false; registration is
  opt-in and the public registry is not yet live. Reframe the page: the **identity
  bundle** (`auths id export-bundle`) is the working way to share identity today
  (teammates `trust pin --bundle`, CI verifies `--identity-bundle`); registry is "coming
  soon".
- Sample output shows `https://auths-registry.fly.dev` → default is now
  `https://registry.auths.dev` (and mark the registry section as not-yet-live).
- `auths device link` example (line ~102) → delegation flow (`auths device add` /
  `auths pair`), see Phase 3.

### 1.5 `getting-started/how-it-works.md` + `getting-started/trust-model.md`
- Inception-event JSON samples show an `"x": "<signature>"` field — there is no `x`
  field; signatures travel as CESR attachments alongside the event. Fix the sample and
  the two ASCII diagrams in trust-model.md (drop `x` from the event box; add one line:
  "signatures ride beside the event as CESR attachments").
- `"v": "KERI10JSON"` → real version strings are like `KERI10JSON0000fb_` (sized).
- trust-model.md "Verification without a central authority" never mentions **what decides
  which roots are trusted**: the committed `.auths/roots` pin file, self-trust for your
  own identity, and `--identity-bundle` for stateless CI. That's the actual trust
  decision in the product — add a section "Who do you trust? The pinned-roots model"
  covering all three, plus the duplicity caveat (kt=1, no witnesses → see
  `docs/architecture/multi_device_accepted_risks.md`, link it).
- Capability examples `sign:commit`, `deploy:staging` → real capability names are
  `sign_commit`, `sign_release`, `manage_members`, `rotate_keys`.

### 1.6 `guides/git/verifying-commits.md`
- Mostly good (bare `auths verify` defaulting to HEAD is correct — verified). Add:
  self-trust (your own commits verify with zero setup), the `.auths/roots` requirement
  for *other people's* roots, the no-trailer failure mode + hook explanation (use the
  real error text from `verify_commit.rs`), and the exit-code contract (0/1/2) replacing
  the current "0 or 1" claim.
- JSON output field list (`ssh_valid`, `chain_valid`…) — regenerate from a real
  `auths verify HEAD --json` run; fields have drifted.

### 1.7 `guides/git/team-workflows.md` + `guides/git/signing-configuration.md`
- Every `trust pin --did … --key <hex>` example (lines ~26, 64, 177, 336) → lead with
  `trust pin --did <did>` (KEL resolution) and `--bundle <file>`; keep one `--key <hex>`
  example labeled "air-gapped ceremony".
- team-workflows: the team-onboarding story should now center on the committed
  `.auths/roots` file (auto-seeded by the first signed commit; teammates inherit it by
  cloning) — that's the actual mechanism, and it's a *good* story. Hex-key exchange is
  dead.
- signing-configuration.md: add `core.hooksPath` to the list of config init sets; document
  the husky/repo-local-hooksPath caveat + `auths doctor` detection; mention
  `auths sign <ref>` rewrites SHAs (never suggest it post-push without a warning).

### 1.8 `guides/identity/key-rotation.md`
- "Run `auths device link` on each device to create fresh attestations" (lines ~104,
  161) → wrong model; delegated devices don't need re-linking after a root rotation
  (delegation is anchored in the KEL; verification replays it). Rewrite the
  post-rotation checklist against actual behavior — the smoke test proves sign+verify
  works immediately after `id rotate` with no extra steps.

### 1.9 `guides/platforms/ci-cd.md`
- Content verified correct (`artifact sign --ci --commit` exists; verify@v1 real). Two
  gaps: "device-bound Ed25519 key" → P-256/curve-neutral wording; and add a section (or
  cross-link a new page) for the **`init --profile ci` flow**: pipeable env block
  (`auths init --profile ci > secrets.env`), what the 15 vars do, hook-in-CI via
  `core.hooksPath` GIT_CONFIG entries, and AUTHS-E5008 if `AUTHS_PASSPHRASE` is weak.

### 1.10 `guides/identity/profiles.md`
- Agent profile section: must reflect the new routing — interactive `auths init` →
  Agent now **delegates an agent under your existing root** (label prompt, reuses
  selected capabilities); with no root it directs you to create one;
  `--non-interactive` intentionally errors with the `id agent add` guidance.
- Developer profile step list: curve fix + hook step + registration-is-opt-in.

---

## Phase 2 — Kill the legacy device model in teaching material

Affected: `getting-started/identity-lifecycle.md` ("Phase 2: Device linking" teaches
`device link` + dual-signed attestation as THE flow), `getting-started/how-it-works.md`
("Attestations bind identities to devices" section), `guides/identity/multi-device.md`
(table row "Manual linking `auths device link`"), `getting-started/delegation.md`
(audit it for the same; it's likely closest to correct already).

**The rewrite, applied consistently:**
- Primary story: a device is a **delegated identifier** — `auths pair` (QR/short-code)
  or `auths device add` creates a `dip` KEL anchored by your root. Commit trailers carry
  the delegated `did:keri:`.
- Attestations still exist (artifact signing, platform claims) — reposition the
  attestation section around what they're actually for now, not device binding.
- `device link` gets one mention: "legacy attestation flow, kept for compatibility"
  (matching its own `--help` text).
- Update the storage-layout tables that only show `refs/auths/devices/...` attestation
  refs; the KEL refs for delegated devices are the interesting part now.
**Verify:** `auths device add --help` and `auths pair --help` for the real flags; the
delegation language in `crates/auths-cli/src/commands/device/authorization.rs:66-71`.

---

## Phase 3 — Approachability restructure (the intimidation problem)

Honest assessment: the *writing* is good, but the **sequencing front-loads KERI theory**.
Getting Started is 8 pages and half of them are protocol explainers (How It Works,
Identity Lifecycle, Delegation, Trust Model). A newcomer meets SAID, Blake3, CESR,
inception, pre-rotation, and dual-signing before they've verified their second commit.
Meanwhile the glossary — the thing that makes jargon survivable — is buried under
*Contributing*.

### 3.1 Re-sequence the nav
```yaml
- Getting Started:
    - Installation
    - Your First Identity        # do, not learn
    - Signing Commits            # do
    - Verify & Trust Basics      # NEW thin page: verify HEAD, self-trust, .auths/roots in 1 screen
    - Sharing Your Identity      # bundles first, registry "coming soon"
- Concepts:                      # NEW section: the four theory pages move here
    - How It Works
    - Identity Lifecycle
    - Delegation & Devices
    - Trust Model
- Guides: (as now, minus radicle)
- Reference:
    - CLI Commands (primary/advanced)
    - Glossary                   # moved out of Contributing
    - Error Codes: errors/index.md
```
Getting Started becomes purely "do things"; theory is one click away, clearly labeled.

### 3.2 Progressive disclosure inside the theory pages
Pattern to apply in How It Works / Trust Model / Lifecycle:
- First screen: plain-language summary ("your identity is a tamper-evident logbook of
  your keys; the logbook's first page's fingerprint is your ID") with ZERO of: SAID,
  CESR, Blake3, inception, AID.
- KERI terms introduced with a one-line gloss on first use + link to the Glossary
  (mkdocs `abbr` extension is already enabled — use it for AID/KEL/SAID).
- Wire-format JSON and validation-rule tables move into collapsed
  `??? info "The KERI details"` admonitions (pymdownx.details is enabled), each ending
  with a link to the source (`crates/auths-keri/src/validate.rs`, `events.rs`) for the
  people who want ground truth.
- Glossary gets first-use links from every theory page.

### 3.3 Lead with the demo
`auths demo` is the best onboarding asset the product has (9 ms, zero prompts, zero
setup) and the docs never mention it. Put it: index.md Quick Tour (1.2), top of
Installation ("prove it works before configuring anything"), and Your First Identity.

---

## Phase 4 — Missing content (in priority order)

### 4.1 Agents guide — the biggest gap on the site
The hero says "Portable Identity for Developers, **Agents**, and Workflows"; there is no
agent page anywhere. Write `guides/agents/agent-identities.md`:
- `auths id agent add --label <name> --key main --scope sign_commit --expires-in <secs>`
  (delegated AID, scoped, expiring), `id agent list/rotate/revoke`.
- The interactive path (`auths init` → Agent profile → routes to delegation).
- How agent commits verify (scope trailer / `OutsideAgentScope`), and the
  `Auths-Presentation` / relying-party story (auths-rp) at overview level.
- MCP server existence (`auths-mcp-server`) at least as a pointer.
**Source of truth:** `crates/auths-cli/src/commands/id/agent.rs`,
`crates/auths-sdk/src/domains/agents/delegation.rs`.

### 4.2 Artifact signing guide
`auths sign <file>` / `auths verify <file>` (sidecar `.auths.json`), self-trust locally,
`--identity-bundle` for consumers, `artifact verify --offline --roots` (fn-154 shipped
it; only the CI page hints at artifacts today). New page under Guides.

### 4.3 Troubleshooting page
doctor (exit codes, the two new hook checks), the stale-binary trap (`auths --version`
vs docs; `cargo install --path` reminder), husky/hooksPath override, weak-passphrase
E5008, "no trailers" remediation, `auths reset --force`. Most of this text already
exists in error messages — collect it.

### 4.4 Orgs & compliance (overview level)
`auths org audit`, offboarding log, evidence bundles, `artifact verify --offline`
(fn-154/157 shipped, zero docs). One overview page; deep-dives can wait.

### 4.5 Uninstall / reset
`auths reset --force` semantics (what's deleted: ~/.auths, git config, hooks), keychain
cleanup. Half a page; absence is conspicuous for a security tool.

---

## Phase 5 — Deletions

- **`guides/platforms/radicle.md`**: the `auths-radicle` crate is deleted. Move the page
  to `archive/` with a deprecation banner (the RIP-X storage-layout preset still exists
  in code — `LayoutPreset::Radicle` — so keep one paragraph about the layout preset in
  storage docs if needed). Remove from nav.
- Sweep for `auths-registry.fly.dev` (replace with `registry.auths.dev` + not-yet-live
  framing) and any remaining `rc.N` version strings in nav-reachable pages
  (`grep -rn "rc\.[0-9]" docs/cli docs/getting-started docs/guides docs/sdk`).
- `archive/` and `essays/` are fine — clearly labeled history/opinion.

---

## What's genuinely good (don't churn it)

- `cli/commands/{primary,advanced}.md` are generated and drift-checked — current.
- `getting-started/signing-commits.md` was rewritten 2026-06-10 against the shipped
  behavior — it's the model for the rest.
- `install.md`, error-code pages, and the contributing section are in decent shape.
- The writing quality across the theory pages is high; the problem is sequencing and a
  handful of factual drifts, not prose.

## Suggested commit sequence for the executor

1. Phase 0 (publishing hygiene + error-docs regen) — one commit, zero prose changes.
2. Phase 1 (factual corrections) — one commit per subsection is fine; re-run each
   command before pasting output.
3. Phase 2 (device model) — one commit.
4. Phase 3 (nav restructure + disclosure) — one commit; `mkdocs build --strict` must pass.
5. Phase 4 (new pages) — one commit per page.
6. Phase 5 (deletions/sweeps) — final commit; re-run the full grep list from this audit
   to confirm zero hits.
