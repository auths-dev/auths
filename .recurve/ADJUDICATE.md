# ADJUDICATE — policy forks the spec left open

> **Reader:** the spec's human owner. Each fork needs ONE sentence on
> the DECIDED line. The decision then gets encoded into the probe (the
> rejected path exits RED citing the policy) — the probe is the only
> place an agent cannot rationalize around. `baseline` warns while any
> fork is pending. This skim is also a security review: it is the last
> point where hostile spec text can be kept out of the loop's
> instruction stream.

## ADJUDICATE-1 — where the witness node + operator CLI live

PRD Open Question 1. Originally framed as "a separate witness binary vs a
platform subcommand." **Re-decided 2026-06-13** after recognizing a
witness node is *core trust infrastructure* (witnesses are central to the
KERI model), not a peripheral consumer like the demos — so it belongs in the
platform workspace, and a cargo feature (not a separate binary) is how auths
already keeps optional heavy components out of the lean default build
(precedent: `auths-rp`'s `git-sync` git2 feature; the fips/cnsa/bulk crypto
provider features).

**DECIDED (2026-06-13, supersedes the standalone-binary decision):**
- **Witness node + threshold verification** → a **feature-gated Rust crate in
  the platform workspace**, `auths/crates/auths-witness-node`, behind a
  `witness-node` cargo feature. The lean default `auths` build never pulls it;
  operators install a feature-enabled build (`cargo install auths --features
  witness-node`, shipped as an `auths-witness` release binary). It composes
  the platform's public crate APIs (`auths-witness`, `auths-keri`,
  `auths-verifier`) — it does not re-implement protocol (WIT-B1).
- **Operator CLI** → **unified into the main `auths` CLI** as `auths witness …`
  subcommands (NOT a separate binary). The subcommand *surface* is
  always compiled in (thin clap definitions, no heavy deps); the *handler* is
  feature-split — with the feature it runs the node, without it returns a
  helpful error pointing operators at the witness-enabled build. Lean default
  AND unified UX; the false dichotomy ("separate binary for leanness") is
  resolved.
- **IaC** (OpenTofu `.tf`) → embedded with the node crate
  (`auths-witness-node/deploy/`), shipped with the feature build.
- **Dashboard + public directory + operator console** (Next.js/TS) → **`auths-network/web/`**
  (a sibling to `.recurve/` in THIS repo), never the Rust workspace.
  **REVISED 2026-06-14 (HUMAN): home the witness frontend HERE, not in a separate web tier.**
  Rationale: the witness network is one product — node + conformance suite + frontend belong
  together (the operator's two tools are the `auths` CLI and this frontend). The `.recurve/`
  dir stays product-code-free (claims / probes / harness only); the frontend lives beside it
  in `web/`, and the recurve suite gains a SECOND build-target (`[suites.web]`) so the
  WIT-D / WIT-O / WIT-V cycles drive and gate it. The frontend still imports verification ONLY
  through the published `@auths-dev/verify` package — never platform internals (WIT-B3) — and
  reuses the design language in PRD §6 under the WIT-V design gate.

**What this means for this suite:** `auths-network/.recurve/` is no longer a
product repo — it is a **conformance/integration suite, structurally like
`interop/`**, whose probes drive building the `auths-witness-node` crate +
`auths witness` commands in the workspace and gate them against demos +
interop. The **frontend** (dashboard / directory / operator console) lives in
`auths-network/web/` — a sibling to `.recurve/`, the suite's *second* build-target — while
`.recurve/` itself stays product-code-free. The node still builds in `../auths`; no cross-repo
commits. Future neutral-governance extraction to a separate governed repo remains possible —
extracting a crate later is easy; start coupled.

## ADJUDICATE-2 — directory admission policy v1

PRD Open Question 2. Who may join the public directory at v1, checked
how, and who signs admissions until governance exists? Sketch on the
table: verified operator org identity + reachable endpoints + ToS
signature, admissions signed by the auths org identity (disclosed as
interim, replaced by governance later). Gates: WIT-D2 (`register` is
blocked until this is decided).

**DECIDED (2026-06-13):** v1 admission requires a verified operator org identity + reachable endpoints + a signed ToS acknowledgment, with admissions counter-signed by the auths org identity as the explicitly-disclosed interim authority — to be replaced by neutral governance before the directory opens permissionlessly; the interim status must be visible in the directory itself.

## ADJUDICATE-3 — classification of the WIT-T block

Per this suite's default-closed convention, the threshold-verification
claims (WIT-T1..T5) start as `security-tradeoff` (review-gated — the
unattended loop will NOT work them). Counter-argument from the house
precedent: these claims ADD fail-closed checks rather than loosening
any, which in the demos/interop convention is ordinary green-gate work;
the only true loosening (accepting pre-revocation history) lives in
lost-the-laptop LTL-1/LTL-2 and keeps its own review protocol
regardless. Decide: keep WIT-T1..T5 review-gated (slower, maximally
cautious) or downgrade them to their natural classes
(missing-surface/wire-mismatch) so the loop can burn them down, with
WIT-T5's trap as the permanent guard. Gates: whether the autonomous
burndown can touch the suite's headline block at all.

**DECIDED (2026-06-13):** Split — WIT-T1..T4 downgraded to `missing-surface` so the loop builds the threshold *mechanism* autonomously (they ADD fail-closed checks: a bug fails loud as over-strict, never silently permissive — the safe direction), while WIT-T5 stays `security-tradeoff` so a human confirms the headline outcome (the forged-ordering fixture genuinely dies) and it remains a permanent forgery trap. The one true loosening — accepting pre-revocation history — is NOT here; it lives in auths-demos LTL-1/LTL-2 and keeps its own review protocol regardless. **Sanity-check me on this one** — it is the load-bearing security call; if you'd rather a human design the whole threshold block, revert WIT-T1..T4 to `security-tradeoff`.

**CONFIRMED BY HUMAN — 2026-06-14 (HUMAN-D5): A.** The split stands: the loop builds WIT-T1..T4, the human confirms WIT-T5 (the forgery trap). **Added mandate — the threshold mechanism carries a raised testing bar.** Because it is the single most load-bearing security block (and the corroboration source LTL-1/LTL-2 will lean on), each WIT-T claim must be backed by *robust, multi-level tests*, not just its behavioral probe: **unit** (the M-of-N arithmetic and boundary conditions: 0, M-1, M, N, N+1, duplicate/equivocating witnesses), **integration** (the node composing auths-witness/auths-keri/auths-verifier under threshold), **end-to-end** (against the live 3-witness fixture, incl. the kill-node FR-13 lever at threshold), and **domain/property** (e.g. proptest: no forged or under-threshold receipt-set is ever accepted; over-strict failure is acceptable, silently-permissive is never). A WIT-T cycle that greens its probe without these layers is **not done** — the probe asserts the test layers exist and pass. WIT-T5's forgery trap stays permanent and is the human's personal pre-merge check.
