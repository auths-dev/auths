# PRD: auths-network — the witness network

> **⚠ ARCHITECTURE UPDATE (2026-06-13) — supersedes the standalone-repo framing below.**
> The *what* in this PRD is unchanged (one-command witness standup, M-of-N
> threshold, public directory, the WIT-T mechanism that unblocks LTL-1/LTL-2).
> Only the *where* changed (see ADJUDICATE-1, re-decided):
> - **Witness node + threshold** → a feature-gated crate **`auths/crates/auths-witness-node`** (behind a `witness-node` cargo feature), NOT a standalone repo. Lean default build; operators install the feature-enabled `auths` / `auths-witness` build.
> - **Operator CLI** → **`auths witness …` subcommands in the main `auths` CLI** (feature-gated handler; the lean build returns a helpful "install the witness build" error). There is no separate `anet` binary — the command is `auths witness …`, full stop.
> - **IaC** (`.tf`) → embedded with the node crate (`…/deploy/`). **Dashboard + directory UI + operator console** → **`auths-network/web/`** (REVISED 2026-06-14, see ADJUDICATE-1 — was "web tier / auths-site"), a sibling to this `.recurve/` suite and the suite's second build-target, never the Rust workspace.
> - **This `.recurve/` suite** is now a conformance/integration suite (like `interop/`) that drives the in-workspace crate — single tree, no cross-repo commits. The "Why a separate repo" note in §1 and the repo-boundary framing in §7 are superseded by ADJUDICATE-1.

> **One line:** make it one command to stand up a witness node, make the
> network of witnesses publicly discoverable, and make verifiers able to
> demand M-of-N independent receipts — so that key-event ordering becomes
> unforgeable without collusion, and the agentic-trust flywheel can start
> turning.
>
> **Build method:** recurve (claims-driven, probe-gated). This PRD is written
> to be *claimified*: every requirement names an observable and its
> adversarial twin, so the build IS the burndown. Cycles build the
> `auths-witness-node` crate + `auths witness …` commands IN `../auths` and
> sculpt the platform as needed (exactly as `auths-demos` did); this `.recurve/`
> dir holds only the suite (claims, probes, harness). Dashboard → `auths-network/web/` (a sibling dir; the suite's second build-target).
>
> **Scope decisions (adjudicated 2026-06-12):** v1 = node + directory +
> threshold verification, dashboard read-only (operator console + public
> directory). Standup targets local Docker Compose AND `--cloud` via embedded
> OpenTofu. First network = 1 auths-operated node + 2 independent partner
> nodes (real 2-of-3 from day one).

---

## 1. Introduction / Overview

Today the auths trust root is **staged**: a single registry, no independent
witnesses. Three consequences, all already named in the ledgers:

- Revocation *ordering* is signer-stamped and forgeable (`lost-the-laptop`
  LTL-1/LTL-2, review-gated) — a thief can claim "signed before revocation."
- Duplicity (an identity showing two histories) is detectable in code but
  fail-open on key paths (`verify-the-world` V1, review-gated).
- Every enterprise conversation eventually hits "who runs the
  infrastructure?" (GTM lever L4 — the unglamorous backbone).

The witness network fixes all three with one mechanism: **independent
operators receipt key events; verifiers require receipts at a threshold the
identity controller designates (e.g. 2-of-3); forged ordering then requires
collusion of M witnesses.** Because each identity designates its *own*
witness set in its event log, the network is permissionless-by-design and
incrementally adoptable — no global consensus, no chain. A witness is closer
to an NTP server than a blockchain validator.

The flywheel this unlocks: more cross-org agent traffic → more value in
running your own witness (stop trusting a competitor's view of key state) →
more independent witnesses → stronger ordering/duplicity guarantees →
higher-value agent transactions become safe → more traffic. The product's
job is to make each turn of that wheel one command cheaper.

**Why an in-workspace crate (not a separate repo):** a witness node is core
trust infrastructure, not a peripheral consumer — it belongs in the platform
workspace as the feature-gated `auths-witness-node` crate (ADJUDICATE-1).
This `.recurve/` suite mirrors `interop/`: it holds the claims, probes, and
harness that *drive* building that crate, and federates into the same gate as
demos + interop (shared tree → one gate, one loop at a time, lockfile rule).

## 2. Goals

- **G1 — One-command witness.** A stranger with Docker (or a cloud account)
  goes from nothing to a receipting, directory-registered witness node in
  one command and ≤10 minutes, with zero protocol vocabulary required.
- **G2 — Real 2-of-3 by launch.** Three live nodes (auths + 2 independent
  operators), and at least one identity verifying at a 2-of-3 threshold in
  production use.
- **G3 — Threshold verification in the platform.** `auths-verifier` can
  require M-of-N receipts from a designated witness set, and a forged
  ordering FAILS without collusion of M witnesses — probed, with traps.
- **G4 — The directory as a verifiable artifact.** The public witness
  directory is itself signed and offline-verifiable (we eat our own
  dogfood; the directory is not a trusted web page).
- **G5 — Feed the platform.** Every platform gap discovered lands in a
  ledger with a RED probe and gets burned down by the recurve loop — and
  this work unblocks the parked review-gated gaps (LTL-1, LTL-2, V1) by
  providing the corroboration mechanism they require.
- **G6 — Operable, honestly.** Operator console + public directory expose
  real health/receipt metrics; a node that lies about uptime is caught by
  probes, not marketing.

## 3. User Stories

### US-001: Operator stands up a local witness in one command
**Description:** As an infrastructure operator at a partner org, I want
`auths witness up` to take me from a blank VPS to a running, healthy witness node so
that joining the network costs minutes, not a project.

**Acceptance Criteria:**
- [ ] `auths witness up` on a machine with Docker brings up the witness node +
      monitor sidecar via embedded Compose; exits 0 with a printed health URL
- [ ] `auths witness status` reports: node identity, health, receipts issued, peers,
      KSN endpoint reachability
- [ ] Node identity is generated at first boot (enclave/KMS-backed where
      available, file-key fallback with a stern warning)
- [ ] Total wall-clock command→healthy ≤ 10 min on a clean VPS (probed,
      scripted cold-start — TTV discipline)
- [ ] No KERI vocabulary in any output of the happy path (leak-gate probe,
      same grep discipline as TTV-1 in `roadmap/aspirational_claims/`)
- [ ] Adversarial: `auths witness up` on a box where the port is taken / Docker
      absent fails with a one-line actionable error, not a stack trace

### US-002: Operator provisions to a cloud in one command
**Description:** As an operator without spare hardware, I want
`auths witness up --cloud aws|gcp|hetzner|fly` to provision and start the node via
embedded IaC so the cloud path is the same single command.

**Acceptance Criteria:**
- [ ] Embedded OpenTofu modules per provider; `auths witness up --cloud <p>` plans,
      applies, boots, health-checks — one command, idempotent on re-run
- [ ] `auths witness down --cloud <p>` tears down cleanly (probed: re-run `up` after
      `down` succeeds; no orphaned billable resources — verified via
      provider inventory diff in the harness)
- [ ] State stored locally by default (documented), with `--state` escape
      hatch; no auths-operated state service in the loop
- [ ] Adversarial: invalid credentials fail BEFORE any resource is created

### US-003: Witness receipts events and serves key state
**Description:** As an identity controller, I want a witness I designate to
receipt my key events and serve signed key-state notices so verifiers can
corroborate ordering without trusting me.

**Acceptance Criteria:**
- [ ] Node ingests a designated identity's events and returns receipts
      (non-transferable witness key, standard `B`-code — requires interop
      IOP-L3b, referenced not duplicated)
- [ ] Node serves KERI-conformant KSN at a stable endpoint (requires
      IOP-L3c; cross-verified against the keripy oracle in `interop/peers/`)
- [ ] Receipts verify offline on a stranger's machine from the receipt +
      the witness's published identity alone
- [ ] Adversarial: a receipt with a bit-flipped signature is rejected; a
      KSN for a stale state is detected as stale by a verifier holding a
      newer receipt

### US-004: Org designates its witness set and threshold
**Description:** As an org admin, I want to designate my witness set and
threshold (e.g. 2-of-3: us, partner A, partner B) in my org identity so
that my key-event ordering is corroborated by operators I chose.

**Acceptance Criteria:**
- [ ] `auths org witness set <id...> --threshold M` writes the designation
      into the org KEL (platform sculpt; CLI surface in `../auths`)
- [ ] Designation is itself a signed, anchored event (history shows when
      the witness set changed, forever)
- [ ] Rotating the witness set is one command and takes effect at a
      provable log position
- [ ] Adversarial: a witness NOT in the designated set producing receipts
      does not satisfy the threshold

### US-005: Verifier enforces M-of-N receipts
**Description:** As a relying party, I want verification to fail closed
when an identity's events lack threshold receipts so that forged ordering
requires collusion, not just a stolen key.

**Acceptance Criteria:**
- [ ] `auths-verifier` exposes a threshold policy: given a designated set +
      M, verification of ordering-sensitive verdicts (SignedBefore /
      SignedAfterRevocation) requires M valid receipts
- [ ] The LTL-2 forgery (signer-stamped low anchor-seq) FAILS under
      threshold policy — this is the trap fixture, kept forever
- [ ] Verdict distinguishes "unreceipted" from "invalid" (operators can fix
      the former; the latter is an attack)
- [ ] Overhead: threshold check adds ≤ 50ms p99 to verification on the
      pinned rig (perf probe with hysteresis)
- [ ] Adversarial: M−1 receipts do not verify; receipts from one operator's
      two nodes count once under the diversity rule (see FR-9)

### US-006: Anyone browses the public witness directory
**Description:** As anyone evaluating the network, I want a public
directory of witnesses — operator, jurisdiction, uptime, receipt volume —
so I can choose a diverse witness set and see the network grow.

**Acceptance Criteria:**
- [ ] Directory page lists nodes with: operator name + verified org
      identity, region/jurisdiction, status, uptime %, receipts (7d),
      KSN endpoint
- [ ] The directory dataset is a **signed artifact in a git repo**, fetched
      and verified client-side (WASM verifier) — the page renders only what
      verifies; "trust me" pages are off-brand
- [ ] Registration: `auths witness register` opens a signed entry (PR-style) against
      the directory repo; admission per governance policy (Open Question 2)
- [ ] Verify in browser using dev-browser skill
- [ ] Adversarial: a tampered directory entry renders as a verification
      failure, visibly, not as data

### US-007: Operator console (read-only v1)
**Description:** As a node operator, I want a dashboard for MY node —
health, receipts issued, identities served, peer reachability, version —
so I can run it like real infrastructure.

**Acceptance Criteria:**
- [ ] Console reads node metrics endpoint (Prometheus-compatible; complete
      the `auths-monitor` daemon as the collector — it is currently a
      394-LoC framework with incomplete handlers)
- [ ] Views: health timeline, receipts/day, identities served, KSN request
      rate, last-seen-by-peers
- [ ] Alert hooks: webhook on unhealthy > N minutes (no paging product in
      v1 — webhook only)
- [ ] Verify in browser using dev-browser skill
- [ ] Adversarial: console against a dead node shows DOWN within 60s; never
      stale-green

### US-008: The recurve loop builds it
**Description:** As the platform team, I want every requirement here to
exist as a claim with a RED probe in this repo's suite so the autonomous
loop can burn it down and the platform inherits the hardening — exactly the
auths-demos pattern.

**Acceptance Criteria:**
- [ ] `auths-network/claims/` suite scaffolded (gaps.yaml + GAPS.md +
      probes/ + harness/), federated into the shared gate with demos +
      interop (one tree, one gate, lockfile — never concurrent loops)
- [ ] Bootstrap/scaffolding gaps filed first ("harness boots 3 local
      witnesses", "probe can run at all") so cycle 1 never faces a wall of
      BROKEN — greenfield rule from `recurve/plan.md` §7.B
- [ ] Every FR below maps to ≥1 ledger entry; `coverage --gate` green
- [ ] Platform-side gaps reference, never duplicate, interop entries
      (IOP-L3b/L3c/L4a are prerequisites owned by `interop/`)
- [ ] The run that closes WIT-T* explicitly unblocks the review protocol
      for LTL-1/LTL-2/V1 (they stay review-gated; the mechanism now exists)

## 4. Functional Requirements

**Node & standup**
- FR-1: `auths witness up` stands up witness + monitor via embedded Docker Compose;
  `auths witness up --cloud aws|gcp|hetzner|fly` provisions via embedded OpenTofu
  modules. Both paths: one command, idempotent, health-checked exit.
- FR-2: `auths witness down`, `auths witness status`, `auths witness register`, `auths witness logs` complete
  the operator verb set. No other verbs in v1.
- FR-3: The witness node is the hardened `auths-witness` server plus: KSN
  serving (per IOP-L3c), receipt issuance with non-transferable keys (per
  IOP-L3b), Prometheus metrics, and a signed version/build attestation
  (the node proves what binary it runs — dogfood `artifact sign --ci`).
- FR-4: Node key custody: KMS/enclave where the platform provides it;
  file-backed fallback requires `--accept-file-key` acknowledgment.

**Directory**
- FR-5: The directory is a git repo of signed entries; the dashboard
  renders only entries that verify client-side (WASM). Hosting is static.
- FR-6: Entries carry: operator org identity (auths identity, verified),
  endpoints, region/jurisdiction labels, admission timestamp.
- FR-7: Uptime/receipt stats are computed by an open prober (part of this
  repo) whose results are themselves signed and published — observers can
  re-run the prober and get the same answer.

**Threshold verification (platform sculpt)**
- FR-8: KEL-designated witness sets + threshold M (US-004); verifier
  enforcement (US-005) with distinct verdicts for unreceipted vs invalid.
- FR-9: Diversity rule shipped as the DEFAULT verifier policy: receipts
  counting toward M must come from distinct operators (by directory
  identity), with jurisdiction-diversity as an optional stricter mode. A
  threshold met by one operator's three nodes is the CA oligopoly rebuilt —
  default-closed against it.
- FR-10: Graceful degradation policy is explicit and conservative: if
  fewer than M designated witnesses are reachable, ordering-sensitive
  verdicts fail closed with `InsufficientReceipts`; non-ordering verdicts
  (signature validity, capability checks) proceed and say so. No silent
  downgrade.

**Dashboard**
- FR-11: One Next.js app **in `auths-network/web/`** (the recurve suite's second
  build-target — see ADJUDICATE-1, revised 2026-06-14), following the §6 design language —
  its OWN tokens, simple like an Apple product page, explicitly NOT auths-site — under the
  WIT-V design gate, and the
  published `@auths-dev/verify` widget for ALL verdicts (WIT-B3 — never re-implementing
  verification). Two surfaces: `/directory` (public, US-006) and `/node` (operator console,
  US-007). Read-only in v1 — no mutating control-panel actions.

**Recurve integration**
- FR-12: Suite layout, probe contract (GREEN 0 / RED 1 / BROKEN 2, traps,
  freshness `reads:` keys), draft→baseline ceremony, and per-cycle
  snapshots all follow the house pattern; claim blocks: WIT-N* (node),
  WIT-I* (IaC), WIT-D* (directory), WIT-T* (threshold), WIT-O* (ops).
- FR-13: The harness can stand up a 3-witness local network (Compose) as
  the probe fixture, with failure injection: kill 1 node (threshold still
  met), kill 2 (fails closed), forged ordering (trap).

## 5. Non-Goals (Out of Scope for v1)

- **No org-facing control panel UI.** Witness-set designation is CLI-only
  (US-004); the panel is v2 after the org console exists.
- **No permissionless directory admission.** Day one is auths + 2 partners;
  the admission policy is governed (Open Question 2), not open.
- **No incentive/token layer, no billing.** Witness economics in v1 =
  self-interest + partnership. Paid managed witnessing is a later SKU.
- **No global consensus, no chain, no gossip protocol.** Witnesses are
  independent receipt servers; the threshold lives in the verifier.
- **No Kubernetes/Helm artifact** (Compose + OpenTofu only; Helm when a
  platform-team operator asks).
- **No paging/alerting product** (webhook only).
- **No new cryptography.** Everything composes existing platform
  primitives; if a claim seems to need novel crypto, it's mis-scoped — file
  it for adjudication.

## 6. Design Considerations

- **KERI-invisible carries over.** Operators see "witness", "receipt",
  "key state", "threshold" — never KEL/KSN/CESR in the happy path. The
  leak-gate grep is a standing probe (same rule that productized TTV-1).
- **Directory = front door.** It will be screenshotted, linked, and used as
  the network's growth chart. Design for "number going up": nodes,
  operators, jurisdictions, receipts/day — rendered in the §6 design language
  (its own clean tokens, simple and Apple-like, NOT borrowed from auths-site).
- **The dashboard renders proofs, not assertions** — every green element in
  both surfaces is backed by a client-side verification or a signed prober
  result. This is the brand, enforced by probes.

### Design language — neutral, safe, inviting, powerful

**The reference is a simple Apple product page — NOT auths-site, NOT any
existing marketing site.** This is trust infrastructure; the surfaces must
look like something you'd let your bank run, and like a single, refined,
quietly powerful piece of well-designed technology. The register is
Apple-grade restraint: form *is* function here, because a page that renders
cryptographic proofs has to look incapable of lying. Sleek, calm, neutral and
trustworthy, generous with space, fast — and **never themed "crypto" or
"hacker"** (no terminal cosplay, no spectacle) and **never inheriting
auths-site's look**. Power reads through clarity and density-on-demand, not
decoration. The four words, mechanized: *neutral* = a neutral, trustworthy
palette and voice; *safe* = accessibility and fail-closed visuals; *inviting* =
whitespace, type, and speed; *powerful* = real data, progressively disclosed,
proofs rendered inline. The whole, in one line: **simple yet powerful, sleek,
refined, trustworthy.**

The qualities are deliberately quantified below — "simple" and "beautiful"
are not probeable; the following are:

- Design tokens must be the single source of visual truth (color, type,
  spacing, radius, motion) in one file; components must consume tokens only,
  and a hardcoded color or font in a component is a gate failure (grep
  probe, same discipline as the leak gate).
- The palette must be neutral-first: one near-white light surface, one calm
  dark surface, ONE accent color, and semantic state colors reserved
  exclusively for verification verdicts — color must carry meaning, never
  decoration.
- The UI must never ship a green-on-black terminal aesthetic, glitch/
  scanline/matrix effects, ASCII-art banners, hex-dump decoration, or
  monospace as body text — monospace is reserved for identifiers, receipts,
  and code (standing anti-trope probe over stylesheets and components).
- Typography must use at most two typefaces with a documented modular
  scale; body text must be ≥ 16px with line-height ≥ 1.5.
- Layout must breathe: spacing only from an 8px scale, a content max-width
  on every reading surface, and operator-console density delivered through
  progressive disclosure — the public directory stays calm at every
  viewport.
- Every text/background pair must meet WCAG 2.2 AA contrast (≥ 4.5:1 body,
  ≥ 3:1 large text) in BOTH color schemes, probed on rendered pages, not
  in the token file alone.
- Keyboard navigation must reach every interactive element with a visible
  focus state, and both surfaces must honor prefers-reduced-motion and
  prefers-color-scheme.
- Motion must be functional only: state transitions in the 150–300ms range,
  and zero looping or decorative animation anywhere.
- Speed is part of the design language: directory and console must hold
  LCP ≤ 2.5s and CLS ≤ 0.1 on a mid-range device profile (headless-browser
  probe in the harness; a beautiful page that janks is off-brand).
- Verification verdicts must render through one shared component with one
  vocabulary (verified / failed / unreceipted) across both surfaces, and a
  failure must be the most visually prominent element on the page when
  present — calm, specific, unmissable, never alarmist.
- Microcopy must be plain and declarative: no exclamation marks, no
  protocol vocabulary (KERI-invisible extends to copy), no fear-based
  framing — safety is demonstrated by proofs rendering, never asserted by
  adjectives.
- Adversarial twin for the whole section: a change introducing a hardcoded
  color, a third typeface, a sub-AA pair, decorative animation, or any
  anti-trope element must fail the design gate before it lands.

Relationship to FR-11: this section is the SOLE source of the witness frontend's
design language. It does NOT inherit, reuse, extend, or align with the
`auths-site` design system or any other marketing site — the frontend defines its
own tokens from scratch to the rules above. (Generic, identity-free primitives are
fine — the `@auths-dev/verify` widget for verdicts, a headless/unstyled component
library — but never another site's visual identity, palette, or "look".)

## 7. Technical Considerations

- **Reuse over build:** `auths-witness` (real, 101 LoC wrapper over shared
  core), `auths-checkpoint-cosigner` (real, C2SP cosigs), `auths-transparency`
  (RFC 6962), `auths-monitor` (complete it — currently framework-only),
  the `@auths-dev/verify` widget, interop's keripy oracle + `versions.lock`
  convention for KSN conformance probes. (The **visual design system is NOT
  reused** — it is defined fresh in §6: simple/Apple-like, neutral, NOT auths-site.)
- **Dependency order:** IOP-L3b → IOP-L3c (interop suite, platform sculpts)
  → WIT-N receipts/KSN → WIT-T threshold → WIT-D directory stats. IaC
  (WIT-I) and dashboard (WIT-O/D UI) parallelize after WIT-N.
- **Shared-tree discipline:** this suite's cycles sculpt `../auths`; the
  burndown must run under the same lockfile/federated-gate regime as demos
  + interop. Never two loops on the tree (recurve plan §11.13).
- **Partner reality:** 2 independent operators means real-world keys,
  firewalls, and time zones. Budget a human onboarding runbook (RUNBOOK.md)
  and treat partner onboarding as part of v1 acceptance, not aftermath.
- **Review-gated handling unchanged:** closing WIT-T provides the
  corroboration mechanism LTL-1/LTL-2/V1 require, but their promotion still
  goes through the adversarial review protocol — the loop must not
  auto-promote them.

### Repo boundary — `../auths` decides, this repo operates

The seam is protocol vs. operation, not frontend vs. backend:
**`../auths` owns anything that must be correct for strangers; this repo
owns anything that must be convenient for operators.** Three tests make the
boundary mechanical:

1. **Verifier test:** if a third party verifying a receipt offline needs the
   code to be correct, it is platform (threshold policy, receipt/KSN
   formats, diversity rule, directory *entry* format — all `../auths`).
2. **Second-network test:** code a different witness network would reuse
   unchanged is platform (the witness binary, the verifier); what they would
   replace is this repo (directory instance + governance, IaC, dashboard,
   prober, runbooks).
3. **Cadence test:** protocol changes are slow and conformance-gated;
   dashboards and OpenTofu modules change weekly. Different velocity,
   different security posture — npm supply chain never enters the trust
   kernel's review boundary.

Consequences, made concrete:

- The witness server, threshold verification, KEL witness designation, and
  `auths-monitor` live in `../auths` (the "platform sculpts" column of
  Appendix A). Threshold logic lives in `auths-verifier` specifically, so
  WASM, FFI, and CLI verdicts are one implementation — the dashboard renders
  proofs *through the published verifier*, never beside it.
Boundary discipline lives in WIT-B1–B4, reframed for the in-workspace model:
- **WIT-B1:** `auths-witness-node` composes the platform's PUBLIC crate APIs
  (`auths-witness`, `auths-keri`, `auths-verifier`) — depending on them IS the
  integration. It reimplements zero protocol: a message the platform doesn't
  expose is a missing public API → add the surface, never inline the bytes.
- **WIT-B2:** the `witness-node` cargo feature is purely additive — no core
  crate depends on the node crate, and a default `auths` build pulls none of
  its heavy deps (the lean install stays lean).
- **WIT-B3:** the dashboard (`auths-network/web/`) verifies only through the published
  `@auths-dev/verify` WASM package — never a forked verdict path.
- **WIT-B4:** standup deploys released, attested binaries, never source builds.

Violation checks (the WIT-B probes):

```bash
grep -rnE "fn .*\bsaid\b|parse.*cesr|decode.*receipt" auths/crates/auths-witness-node/src/  # hand-rolled protocol → RED (B1)
cargo tree -p auths-cli | grep -q auths-witness-node && echo RED   # node in DEFAULT deps → RED (B2)
grep -rE "verify|threshold" auths-network/web/src/ | grep -v "@auths-dev/verify"  # forked verdict → RED (B3)
grep -rE "cargo build|--path" deploy/   # source build in standup → RED (B4)
```

One tempting move, banned: implementing threshold checks in the dashboard
backend "to iterate faster" — that forks verification truth, and the fork is
the one in the screenshot. (The witness server itself correctly lives in the
platform now — `auths-witness` + `auths-witness-node` — inside the
conformance/audit boundary; that's the ADJUDICATE-1 decision, not a violation.)

## 8. Success Metrics

- Operator TTV: command → healthy, registered node ≤ 10 min local /
  ≤ 20 min cloud (scripted, probed, on every release).
- Network: 3 live nodes, ≥ 2 independent operators, ≥ 1 org verifying at
  2-of-3 in production by v1 close.
- Security: the LTL-2 forged-ordering trap fails under threshold policy —
  permanently RED-guarded; review protocol for LTL-1/LTL-2/V1 unblocked.
- Verification overhead: ≤ 50ms p99 added by threshold checks (pinned rig).
- Recurve health: 100% of FRs covered by ledger entries; coverage gate
  green; zero TODOs (discoveries become filed gaps).
- Honesty: directory uptime numbers reproducible by an external observer
  re-running the open prober.

## 9. Open Questions

1. **CLI naming:** ✅ RESOLVED (ADJUDICATE-1) — unified `auths witness …`
   subcommands in the main CLI, feature-gated (lean default build, helpful
   error without the feature). No separate binary.
2. **Directory admission policy v1:** what are the criteria (verified org
   identity + reachable endpoints + ToS signature?), and who signs
   admissions until governance exists? Needs a human decision recorded as
   an ADJUDICATE entry before `auths witness register` is built.
3. **Partner selection:** which two independent operators? (Design partner
   + OSS foundation per the GTM lighthouse motion — names needed.)
4. **Witness ToS/liability:** what does a receipt legally attest? Needs
   counsel input before partners sign; engineering proceeds regardless.
5. **Jurisdiction labels:** self-declared vs verified? (v1: self-declared
   with display caveat; revisit when diversity-strict mode matters.)
6. **Does the prober live in this repo or as a third "observer" role?**
   (v1: this repo; an independent observer network is the v2 version of
   the same flywheel.)

---

## Appendix A — Claim-block map (for the claimify pass)

| Block | Claims (sketch) | Probes live in | Platform sculpts |
| --- | --- | --- | --- |
| WIT-N | one-command local standup; receipts verify offline; KSN conformant; build attestation | `claims/network/probes/` | `auths-witness`, KSN surfaces (after IOP-L3b/c) |
| WIT-I | cloud up/down idempotent; no orphan resources; creds fail-before-create | same | none (tooling-only) |
| WIT-D | directory signed + client-verified; tamper renders as failure; stats reproducible | same | none / minor |
| WIT-T | M-of-N enforced; LTL-2 trap fails; M−1 insufficient; diversity default; ≤50ms p99 | same | `auths-verifier` threshold policy, KEL witness designation, CLI |
| WIT-O | console never stale-green; DOWN ≤ 60s; metrics complete | same | `auths-monitor` completion |
| WIT-V | design gate: tokens-only · AA contrast both schemes · anti-trope grep · LCP/CLS budgets · reduced-motion honored | same | none (dashboard-only) |
| WIT-B | boundary gate: auths witness imports no platform internals · platform never points back · dashboard verifies only via published verifier · standup deploys released attested binaries | same | none (boundary-only) |

## Appendix B — Relationship to existing ledgers

- **Depends on (owned elsewhere, do not duplicate):** interop IOP-L3b
  (non-transferable witness verkeys), IOP-L3c (KSN wire), IOP-L4a (OOBI —
  helpful for discovery, not blocking v1).
- **Unblocks (still review-gated, mechanism provided):** lost-the-laptop
  LTL-1/LTL-2, verify-the-world V1.
- **Extends:** `roadmap/aspirational_claims/` — file WIT-1 ("M-of-N receipt
  threshold makes forged ordering require collusion") and WIT-2 (diversity
  default) there as the cross-reference stubs pointing at this suite as
  owner.
