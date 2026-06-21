# Grounding Doc — the Auths constitution (the setpoint)

> The **setpoint** of the recursive build system (`recursive_design.md`). Every cycle is read against
> this doc at **two** points: the **planner** reads it to know what is in-scope to build; the **reviews**
> read it to detect drift. It defines *direction* — the mission, the invariants, the anti-goals, the
> boundaries, and the destination — never implementation detail or the current backlog (those live in the
> cycle ledger).
>
> **Two rules that make it a setpoint, not a wiki:**
> 1. **The loop may not edit this file.** It changes only by a deliberate human act — that is how you
>    *steer*. A loop that can rewrite its own goal has no fixed point.
> 2. **It changes rarely.** If it churns every cycle, it isn't a setpoint. Implementation lives downstream.
>
> Sources: `docs/plans/go_to_market/20260620/future_vision.md`, the repo `CLAUDE.md`, the architecture
> ADRs/accepted-risks, and the standing review findings. `TODO(human)` marks a genuinely strategic call
> left for you to set rather than one I should infer.

---

## 1. Mission (one sentence)

**Auths turns trust from a service you rent into a property you own — provable anywhere, to anyone, with
no one in the loop.** The entire company is downstream of one claim being *true*: **we verify correctly
when no one else is in the room.** Harden that, and every product on top is leverage; compromise it, and
nothing else matters.

## 2. The primitive (what we actually are)

A `did:keri` self-certifying identity with a signed, **capability-scoped** delegation chain that **any
embedded verifier — native, WASM, FFI, a browser tag — checks with zero network calls.** One
cryptographic core, one verifier, many products. Everything else (Sign, Verify, Agent, Workload, Bridge,
Receipts, Murmur) is a *surface* on this primitive. If a proposed change does not strengthen, embed, or
sell *this* primitive, it is probably out of scope.

---

## 3. What Auths IS — the invariants (must always hold; the reviews enforce these)

Each is phrased so a planner can refuse work that breaks it and a red-team can test for drift.

1. **Offline, no-one-in-the-loop verification.** A verdict is reachable with **no IdP, no CA, no
   transparency log, no Auths server** reachable at verify time. "Verify like it's an airplane" is a
   correctness invariant, not marketing.
2. **The verifier is a pure function of the bytes it is given.** No clock, no network, no disk inside the
   verifier — time/RNG/I/O are injected at the edge. This is *why* one implementation runs in native,
   WASM, and FFI; preserve it.
3. **The root is the holder's.** Trust is rooted in a KEL the holder controls (`did:keri`), self-certifying,
   no external authority vouching. Auths issues and verifies against *itself*, never against a third party.
4. **Authority is capability-scoped and attenuating.** A delegate's authority is `⊆` its parent's; a key
   can never widen its own authority. Scope · budget · TTL · revocation are first-class and enforced
   *before* the action, not logged after.
5. **Fail closed, always.** Unknown / missing / ambiguous / error → refuse, with a typed verdict. An empty
   or unrecognized input never widens authority. (Full doctrine: `meta_prompt.md`.)
6. **Honest verdicts under uncertainty.** Offline verification ⊥ guaranteed revocation-freshness — a
   permanent tradeoff, not a stop-gap. So a verdict is **never a bare `Valid`**: it carries
   `{as_of, freshness}`, the verifier sets the freshness policy, and offline+stale resolves to
   `Valid(freshness unknown)`, never a silent accept (ADR 009).
7. **Curve-agnostic to the core.** P-256 default, Ed25519 today, open to curves that don't exist yet
   (incl. post-quantum). The curve travels in-band with the key; never dispatch on byte length.
8. **One verifier, in lockstep.** The same trust decision in native / WASM / FFI must stay in parity — a
   forge rejected in one is rejected in all. Divergence is a forge-once-bypass-everywhere bug, not a
   cosmetic one.
9. **Every action is re-derivable by a stranger.** Signed, hash-linked, offline-verifiable receipts —
   "compliance evidence that doesn't trust the thing producing it." Editing or deleting one entry breaks
   the chain, provable without the server that wrote it.
10. **Git-native, server-optional.** Identity and attestations live as Git refs; there is no central
    server the trust path depends on.

## 4. What Auths IS NOT — the anti-goals (must refuse to build toward; reject at plan-time)

These are the directional failures the loop is most likely to walk into. Each is a hard "do not."

1. **Not an IdP you keep logging into.** Auths does **not** become an ongoing consumer or issuer of
   foreign auth on the runtime path. Being-the-live-IdP is the *incumbents'* business model and the exact
   thing our offline root replaces — adopting it would delete our reason to exist. (This anti-goal is why
   `auths-auth-server` — a hosted passwordless "Login with Auths" server — was ruled **discard**; its
   resurrection produced the RT-001 CRITICAL. A change that re-introduces a hosted human-login/IdP service
   is out of scope by default.)
2. **No central server, CA, or log in the trust path.** Anything that makes verification *require* an
   Auths-hosted service to be live contradicts invariant #1. Optional/opt-in services (witness commons,
   managed control plane) are fine **only** as enhancements a verifier can ignore.
3. **No vendored, phone-home trust.** No design where a verdict depends on reaching Fulcio/Rekor, an IdP,
   or a per-domain CA at verify time. "Online verify" is a competitor's constraint, not ours.
4. **Witnesses hold liveness, never authority.** A witness/checkpoint network provides anti-equivocation
   and ordering; it must never become a thing that *grants* trust. Centralizing authority into witnesses
   is an anti-goal even as the network bootstraps concentrated.
5. **No fabricated trust, ever.** No placeholder DID that prints as real, no green badge for an unverified
   identity, no `Ok` from a verify path that didn't verify. (This is also `meta_prompt.md`'s prime
   directive — it is load-bearing enough to be a constitutional anti-goal.)
6. **Not a key-custody / babysit-the-key product.** Rotation must not break old signatures; a stolen
   current key must not be able to rotate the identity (pre-rotation). Designs that reintroduce
   "guard this one key forever" defeat the point.

## 5. Strategic boundaries — "bridge to, don't become" (the technical frontier)

The single most important boundary, stated as a decidable technical rule, because it is where the loop
drifts:

- **Consume-inward is bootstrap-only.** When Auths reads a foreign credential (an OIDC/JWT token from
  Okta/Google/Entra, a SPIFFE SVID, a GitHub OIDC token), it is **a one-time onboarding bridge**: read
  the old world **once, at enrollment**, to bootstrap a native `did:keri` identity (an
  anchorable binding attestation) — and then **the runtime path makes zero calls to the foreign root.**
  *Compatibility is the bridge; native is the destination.* **Enforce it with a test:** the runtime/request
  path must make **zero** calls to the inbound verifier/JWKS, and a test goes CI-red if it ever does. An
  inbound binding can **anchor** an identity; it can **never widen capability**.
- **Issue-outward is on-thesis and unbounded.** Minting a short-lived RS256 JWT / SVID from a KERI chain
  that AWS STS / GCP WIF / Azure AD / a SPIFFE consumer already accepts is the safe adoption wedge — Auths
  stays the trust root, the cloud is just a consumer. *"Your identity. Their IAM. No migration."* Build
  this freely.
- **The governance asymmetry:** issue-outward keeps us the root (safe, ship when green); consume-inward
  points the trust arrow the wrong way (gated — bootstrap-only, behind a security pass, never on the
  runtime path). Treat the two oppositely.
- **Open-core boundary.** Primitives + the verifier + the *outward* bridge are the **Apache-2.0** giveaway
  that drives adoption. The managed control plane + enterprise IdP-binding orchestration are
  **source-available / commercial** (the `ee/` tier). A new crate defaults to Apache-2.0 unless it is
  control-plane/enterprise-orchestration, which defaults to the `ee/` source-available tier; nothing in
  OSS `crates/` may depend *up* into `ee/`.

## 6. The product surface (one root, many products) — what is in scope to build

One root powers seven surfaces. This bounds the backlog: work should advance one of these *on the
primitive*, in roughly this priority.

| # | Surface | One line | Status posture |
|---|---|---|---|
| **Foundation** | **The gate / verifier** | "We verify correctly when no one's in the room." | **Always #1.** Everything is downstream of this being true. Harden before adding surfaces. |
| 1 | **Auths Agent (Reins)** | A leash + wallet + receipt for every agent call (scope⊆parent · budget · TTL · revocation). | **The wedge.** The paid spearhead; finish it end-to-end. |
| 2 | **Auths Sign** | "Prove you wrote it" — commit/artifact signing on an identity you own. | Free top-of-funnel. |
| 3 | **Auths Verify** | The verifier as a product (Action, web component, WASM, C-ABI). | Free, embeddable; makes the badge portable. |
| 4 | **Auths Bridge** | "Bring your own root to any cloud" — issue-outward to cloud IAM/SPIFFE. | On-thesis adoption on-ramp (issue-outward, §5). |
| 5 | **Auths Workload (82:1)** | KERI-rooted SVIDs a stock SPIFFE consumer accepts. | The biggest NHI budget. |
| 6 | **Auths Receipts / Ledger** | An audit trail a stranger can re-derive, offline. | Promote the agent gate's receipts platform-wide. |
| 7 | **Murmur** | Messaging that forgets — deniability on a self-owned root. | `TODO(human)`: keep as a halo demo of the thesis, or grow to a product? Default: **halo demo**, not the wedge. |

**The arc (sequencing the destination):**
- **Now:** make the verification foundation unimpeachable; finish the agent gate (Reins) end-to-end; ship
  the outward bridge.
- **6–12 months:** "verified offline by Auths" is a recognized badge; Reins is the default way teams put an
  agent in prod with a budget + kill-switch; the bridge is live in a few mid-cloud enterprises.
- **2–3 years:** Auths is the decentralized root the agent platforms / supply-chain tools / workload meshes
  *consume* — the offline, no-CA property incumbents structurally can't build.

## 7. The destination — "done-enough" (when a phase / the recursion stops)

The recursion is a means; this is the end it serves. A phase is done when:
- **Foundation:** the verifier rejects its own forgeries under the strengthened battery (e2e on the wired
  path + differential vs an independent oracle + fuzz + constant-time), the freshness verdict is honest on
  every live trust path, and parity holds across native/WASM/FFI. *This gates everything else — no new
  surface ships on an unhardened gate.*
- **Wedge:** Reins enforces scope⊆parent · budget · TTL · revocation per call and emits a verifiable
  receipt for pass *and* deny, end-to-end, with a one-line install.
- **Bridge:** issue-outward to at least one cloud IAM is accepted by a stock consumer; consume-inward is
  bootstrap-only with the zero-runtime-call test green.
- **Launch readiness:** the one batched **pre-launch crypto audit** over the verifier/crypto surface is
  clean. `TODO(human):` the precise v1 launch scope (which surfaces are in the first release) — default
  reading of the arc: **Foundation + Reins + free Sign/Verify + the outward Bridge.**

When a full review cycle yields only LOW/INFO findings *and* the destination criteria for the current
phase are met, **stop the recursion for that phase** (or drop to on-demand) — do not manufacture work.

## 8. Decision defaults (so `decide-default` proceeds without pausing)

Documented defaults that let the loop decide reversible calls itself and flag for override:

- **An archived / off-thesis / superseded crate → discard** (revivable from git), not resurrect. Never
  re-introduce a discarded product line to close a finding. *(This is the `auths-auth-server` / A0 case.)*
- **A new inbound (consume-inward) verifier → bootstrap-only, gated behind a security pass**, with the
  zero-runtime-call test. Never on the runtime path. *(§5.)*
- **A new surface → behind the hardened gate.** No trust-consumer ships against a fail-open or unproven
  verification path; the foundation gates the surfaces.
- **A new crate's license → Apache-2.0**, unless it is control-plane/enterprise-orchestration → `ee/`
  source-available. *(§5.)*
- **A verifier/crypto change → merge on the strengthened battery + `audit-flag`** for the pre-launch
  audit; no per-PR human gate. *(runbook.md.)*
- **Built-but-unwired mechanism → finish the wiring** (the commit's intent), not delete. *(runbook.md.)*
- **A true one-way door** (a public API/wire shape consumers will build on; actually shipping/publishing a
  security surface) → **pause** (`needs-human-decision`). Everything reversible → decide-and-flag.

## 9. Doctrines (how, not what — pointers, enforced elsewhere)

These are *how* every change is built; they live in their own files and the loop must honor them:
- **Engineering bar:** `meta_prompt.md` (parse-don't-validate, typed fail-closed errors, no
  `unwrap`/`expect` in prod, functional core, prove-with-tests, curve-agnostic, honesty).
- **Operating procedure:** `runbook.md` (per-row loop, the strengthened test battery, gates, git workflow,
  no process-metadata-in-the-tree, no AI attribution).
- **Standing maxims:** *fail-closed is the law · curve is a parameter · prove on the wired path · green is
  guilty until proven honest · finish the wiring · the verifier reaches the network never.*

## 10. Accepted risks (stable posture — drift past these is a finding, not a re-litigation)

The default posture runs a shared identity KEL with `kt=1` and **no active witnesses**; duplicity under
`kt=1` is surfaced (`detect_duplicity`) and resolved by `device remove`; witnessed verification is opt-in
(`--require-witnesses`). Full detail: `docs/architecture/multi_device_accepted_risks.md`. The threshold
upgrade that eliminates duplicity is a roadmap item, not a default. `TODO(human):` the timing of the
witness-network bootstrap (concentrated → decentralized) and the `kt=1 → kt=N` upgrade — both are
direction calls, not loop calls.

---

## What is NOT in this doc

The current backlog, file:line detail, per-cycle status — those live in `plans/<area>/<timestamp>/
progress.md`. Implementation choices live in the code. This doc answers *"where are we going and what must
stay true,"* not *"what are we doing this week."* To change direction, a human edits this file; everything
downstream re-plans against the new setpoint on the next cycle.
