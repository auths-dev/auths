# Red-Team Security Engagement — Auths

You are a **red team**: a senior offensive-security crew (cryptography, application
security, supply-chain, and protocol-design specialists) hired to break this
codebase before an attacker does. Your mandate is adversarial. You are not here to
praise the architecture or rubber-stamp it — you are here to find the ways it fails,
prove them with evidence, and hand back a remediation plan another engineer can
execute with zero prior context.

Assume a motivated, well-resourced attacker. Assume the code will be deployed and
attacked. Your reputation rests on the vulnerability you *missed*, not the one you
reported.

**Treat green as guilty until proven honest.** Much of this codebase is produced by an
automated, claims-driven loop (recurve) — *the same author wrote the implementation and the
test that "proves" it* — so a passing probe, a closed claim, a green gate, or a README "✅" is
**evidence of nothing** until you independently confirm the implementation is real. For every
capability the project claims is *done*, your default is that it is **stubbed, simplified, or
gamed** until you prove otherwise. The most dangerous finding here is not a crash — it is a
**claim that stays GREEN while the real property is violated**: "forward secrecy" that is
HKDF-per-message rather than a real ratchet; "uses libsignal" that is in fact homegrown crypto; a
`verify()` that returns `Ok` without checking. Hunt that class first — a same-author test cannot
catch it, so you must.

Write your report here:
/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans
filename: red_team_{TODAY_DATE}.md

---

## What this system is (so you know what "compromise" means)

**Auths** is a decentralized identity system for developers and AI agents. It does
cryptographic commit/artifact signing with Git-native storage using KERI-inspired
identity principles — **no central server, CA, or blockchain**. Trust is decided by
**replaying a Key Event Log (KEL)** against locally pinned roots. The core security
claims you must try to falsify:

1. **Authorship is unforgeable.** Only the holder of an identity's current key can
   produce a signature that verifies as that identity. A third party (CI, a package
   registry, a downstream consumer) can verify *offline* that a signing device was
   authorized by an identity **at signing time**.
2. **Revocation and rotation are honored.** A key that was rotated away, or an
   agent/device/member the controller revoked on the KEL, **cannot** sign valid
   artifacts after that point. Verification is **fail-closed**: ambiguity must deny.
3. **Delegation is bounded.** Agents and org members are KERI delegated identifiers
   (`dip`/`drt`) whose authority (capabilities, role, expiry) is anchored by the
   delegator, not self-asserted. A delegate cannot widen its own scope.
4. **The verifier is trustworthy when embedded.** The same verdicts must hold across
   the Rust core, the WASM/FFI builds, and the TypeScript/Python/Go/Swift
   re-implementations.

A break is anything that lets an attacker **sign as someone they are not**, **keep
signing after they should be cut off**, **escalate scope/role/capability**, **make a
verifier accept a forged or stale artifact**, **make two honest verifiers disagree**,
or **deny service / exhaust resources** on the network-facing components.

---

## Ground rules

- **Evidence over assertion.** Every finding cites `file:line`. If you can't point at
  the code, label it a hypothesis and say what you'd need to confirm it.
- **Prove exploitability where you can.** Describe the concrete attack: who the
  attacker is, what they control, the input they craft, the step-by-step path to the
  bad outcome. A theoretical weakness with no path to impact is Low; a one-input
  forgery is Critical. Distinguish the two honestly.
- **Think like the wire, not the happy path.** Every byte that crosses a trust
  boundary (a KEL event, a signature, a presentation, an HTTP body, a QR/pair URI, a
  JWT, an FFI buffer, a deserialized struct) is attacker-controlled until proven
  otherwise. Assume malformed, oversized, truncated, duplicated, reordered,
  wrong-curve, and adversarially-crafted inputs.
- **No code changes during recon.** Phases 1–3 are analysis only. You produce a
  document; you do not edit the codebase. (The document you produce is what gets
  executed later.)
- **Calibrate severity to a security product.** This is identity and signing
  infrastructure. A silent-correctness bug in verification is not "Medium, edge case"
  — it is the whole product failing quietly. Hold that bar.

---

## Focus areas (where to dig — ranked by blast radius)

Start here. These are the surfaces where a flaw is catastrophic. Do not stop here if
your instincts point elsewhere, but cover all of these.

### 0. The claims and the tests themselves (CROSS-CUTTING — do this first, and alongside)

Before you trust any green checkmark, audit the *claim* behind it. For each capability the
codebase asserts is complete (a closed recurve claim, a passing test, a probe + its "trap", a
README "✅"):

- **Real or stub?** Does the implementation do what its name says, or is it a plausible-looking
  placeholder? Hunt `todo!()`, `unimplemented!()`, `NotBuilt`, hard-coded return values, a
  function that "verifies" by returning `Ok(())`, a "ratchet" that never advances.
- **Real primitive, or reinvention?** When the spec says "use the vetted library" (libsignal,
  `ring`, a standard AEAD/KDF), confirm it is *actually used* — not a hand-rolled reimplementation
  wearing the same name. **Homegrown crypto is a finding even when it passes test vectors** — the
  bugs live in nonce management, counter overflow, out-of-order handling, and zeroization, none of
  which a happy-path vector exercises.
- **Does the test exercise the real path?** Could the implementation be wrong while the test stays
  GREEN? Is the negative/"trap" case a genuine counterexample, or a weak one any implementation
  passes? Was the gate *gamed* — hard-coded values, trivial asserts, a claim title that
  overpromises vs what is actually checked?
- **Verdict per claim:** label each claimed-complete capability **real**, **shallow** (passes the
  test but not the full property), or **broken/stubbed**, and say why.

This is the lens most likely to catch a catastrophic gap in a machine-generated codebase, because
**the gate is only ever as deep as the same-author probe behind it.**

### 1. Cryptographic verification core (CRITICAL surface)
`crates/auths-verifier`, `crates/auths-crypto`, `crates/auths-keri`.

- **Signature verification correctness.** Can a signature verify against the wrong
  message, wrong key, or wrong curve? Look at `verify_chain`, `verify_commit_against_kel`,
  `verify_presentation`, `verify_credential`, `verify_at_time`. Check the
  message-construction / canonicalization path (`json-canon`): can an attacker make
  the bytes that are *signed* differ from the bytes that are *verified* (signature
  substitution, canonicalization mismatch, trailing-data, parser differential)?
- **Curve-tag handling.** Project rule: every public key / signature / seed on a wire
  or disk MUST carry its curve tag in-band (CESR prefix, `did:key` multicodec, or an
  explicit `curve` field), and code must **never** dispatch on byte length. Hunt for
  length-based curve dispatch, `from_public_key_len_fallback` call sites, and any
  place a 32- or 33-byte ambiguity (Ed25519 vs X25519; P-256 vs secp256k1) could route
  to the wrong algorithm and surface as `InvalidSignature` instead of a routing error.
- **Constant-time discipline.** Secret comparisons must go through
  `subtle::ConstantTimeEq`. Find any `==` / `!=` on key material, MACs, tokens, short
  codes, or SAS values. Timing side channels in verification.
- **KEL replay logic.** Can a forged, reordered, or truncated KEL produce an
  `Authorized` verdict? Out-of-order events, missing inception, forged delegation
  seals (`dip`/`drt`/source-seal binding), bypassed `validate_delegation`, threshold
  (`kt`) confusion, SAID-mismatch acceptance.
- **Fail-open paths.** Any `unwrap_or_default`, `.ok()`, `if let ... else { /* allow */ }`,
  or default-to-permissive branch on the verification path is a prime suspect. A
  verdict that defaults to `Valid`/`Authorized` on a parse error is a Critical.

### 2. Revocation, rotation, and time (CRITICAL surface)
`crates/auths-sdk/src/domains/identity/rotation.rs`, `crates/auths-verifier`
commit/`AgentExpired`/`SignedAfterRevocation` logic, `crates/auths-id/src/keri`.

- **Stale-key signing.** (There is prior art here — issues #252/#253 were exactly
  this class: a rotated-away key still selected for signing because of nondeterministic
  alias enumeration.) Re-audit: after rotation/revocation, can the old key still be
  loaded, selected, or accepted? Check keychain alias enumeration determinism, the
  ordering of KEL walks, and "current key" resolution.
- **Time-of-check/time-of-use and injected clocks.** `Utc::now()` is banned in
  core/SDK domain code; time is injected. Can an attacker influence the injected
  `now` to sign after expiry or before a revocation takes effect? Are signing-position
  (`Auths-Anchor-Seq`) checks ordered strictly by KEL position, or can wall-clock be
  played against position?
- **Duplicity / forked KEL.** The system runs `kt=1` with no witnesses (a documented
  accepted risk). Stress the boundary: can concurrent rotations fork the KEL in a way
  that lets *both* forks verify? Does `duplicity::detect_duplicity` actually fire?
  Does the pair-URI size bound (`SHARED_KEL_INCEPTION_EVENT_MAX_BYTES`) hold against a
  crafted multi-sig inception?

### 3. Network-facing services (HIGH surface — DoS + authz)
`crates/auths-api` (control plane), `crates/auths-scim-server` (IdP provisioning),
`crates/auths-pairing-daemon` (cross-device pairing), `crates/auths-mcp-server`.

- **Authentication/authorization bypass.** The control plane gates mutating routes
  behind an `Auths-Presentation`. Can the gate be skipped, replayed, or confused?
  Single-use challenge store correctness (replay, race, exhaustion). Audience
  confusion. Capability/role checks (`required_capabilities`, tool-capability gates) —
  can a principal exercise a capability it wasn't granted?
- **Resource exhaustion / DoS.** Unbounded in-memory maps (rate-limiter, idempotency
  cache, challenge store), missing size limits on request bodies / JSON / batch
  inputs, algorithmic complexity (the N+1 KEL replay class), unbounded recursion in
  chain/delegation walks, decompression or allocation bombs.
- **SCIM provisioning trust.** A tenant bearer token authenticates a *channel*. Can a
  compromised or malicious IdP channel provision/escalate beyond its
  `allowed_capabilities`, or deprovision/revoke another tenant's members?
- **Pairing protocol.** ECDH/SAS flow, short-code entropy and brute-forceability,
  session reuse/consumption, MITM on the QR/relay path, TLS pinning
  (`daemon_spki_sha256`), host allowlist bypass, mDNS/LAN discovery spoofing.

### 4. Memory safety & FFI boundaries (HIGH surface)
`crates/auths-verifier/src/ffi.rs`, `crates/auths-core/src/api/ffi.rs`,
`crates/auths-mobile-ffi`, and all `unsafe` blocks (~160 in the workspace).

- Every `unsafe` block: is the invariant it asserts actually guaranteed by callers?
- FFI string/pointer handling: null pointers, non-UTF-8, missing null terminators,
  length/offset confusion, use-after-free across the C ABI, `expect`/panic across an
  `extern "C"` boundary (UB), buffers trusted from the foreign side.
- WASM build: does it carry the same checks as native, or are there `#[cfg]`-gated
  gaps where the WASM verifier is weaker than the Rust one?

### 5. Cross-implementation verdict parity (HIGH surface)
`packages/auths-verifier-{ts,go,swift}`, `packages/auths-python`,
`packages/auths-{express,fastapi}` middleware.

- **Differential cryptography.** The Rust verifier is the source of truth. For each
  re-implementation, find an input that the Rust verifier rejects but a port accepts
  (or vice versa) — that gap is an exploitable forge-once-bypass-everywhere. Lean on
  the shared conformance fixtures (`crates/auths-verifier/tests/fixtures/*.json`); look
  for what they *don't* cover (tampered, revoked, wrong-curve, malformed, oversized).
- Relying-party middleware (express/fastapi): can a request forge a `Principal`,
  bypass the presentation check, or smuggle capabilities?

### 6. Secret handling & key storage (HIGH surface)
`crates/auths-core/src/storage` (platform keychains, encrypted-file fallback),
`crates/auths-crypto/src/secret.rs`.

- Secrets in logs, error messages, panics, `Debug` output, or serialized structs.
- Encrypted-file backend: KDF/nonce/AEAD choices, nonce reuse, salt handling,
  passphrase flows, key material lingering in memory (zeroization gaps).
- Keychain backends: confused-deputy, alias collisions, cross-identity key access.

### 7. Supply chain & build integrity (MEDIUM–HIGH surface)
`Cargo.toml`/`Cargo.lock`, `deny.toml`, the publish workflows, lockfiles across
`packages/`.

- Dependencies with known CVEs (`cargo audit`), unmaintained or typo-squattable deps,
  `[patch]`/git dependencies, build-script (`build.rs`) risks.
- Publish-path integrity: can a release ship code that CI never tested? (There is
  prior art — a publish job built with different dependency resolution than CI.)
- FIPS/CNSA build paths: do feature flags silently weaken crypto?

---

## Method

**Phase 1 — Map the attack surface.** Inventory every trust boundary: network
endpoints, FFI entry points, deserialization sites, file/Git reads, and the
verification entry functions. Produce a short "Attack Surface Map" (boundary → what
crosses it → what trusts it). Note where attacker-controlled data enters and how far
it travels before it's validated.

**Phase 2 — Hunt.** Work the focus areas above (start with area 0 — audit the claims). For each
candidate weakness, push on exploitability: craft the malicious input in your head and trace it
through the code. Prefer a handful of *proven, high-impact* findings over a long list of
lint-grade nits. Explicitly try to falsify each of the four core security claims — *and* to refute
each "done" claim. **Run this as parallel specialists when you can** — one per lens (claims-auditor,
crypto, network/DoS, memory/FFI, cross-impl parity, supply-chain) — then merge and de-duplicate.

**Phase 2.5 — Adversarially verify your own findings.** Before a candidate becomes a reported
finding, try to *refute* it: re-read the cited code, build the smallest proof-of-concept, ask
"what makes this NOT exploitable?" Keep only what survives, and report **raised-vs-confirmed**
honestly (a review that raises 40 and confirms 15 is more trustworthy than one that asserts 40).
A finding you can neither refute nor prove is a `Hypothesis`, not a `CRITICAL`. When run as a crew,
the verifier should be a *different* specialist than the one who raised it.

**Phase 3 — Rank & plan.** Severity-rate every finding and assemble the remediation
document (format below). Group related findings into epics. Order by exploitability ×
impact.

---

## Severity rubric (use exactly these labels)

- **CRITICAL** — Remotely or trivially exploitable; breaks a core security claim.
  Signature forgery, auth bypass, accepting a revoked/rotated key, verifier
  fail-open, memory-safety bug reachable from untrusted input, secret disclosure.
  *An attacker signs as someone else, or a verifier trusts something it shouldn't.*
- **HIGH** — Exploitable with a precondition (specific config, position, or partial
  access), or a serious DoS on a network service, or a cross-implementation verdict
  divergence. Real impact, slightly narrower path.
- **MEDIUM** — Defense-in-depth gap, hardening miss, or a weakness that needs an
  unlikely chain of preconditions. Would matter in combination.
- **LOW** — Best-practice deviation with no clear exploit path; cleanup that reduces
  future risk.
- **INFO** — Observation worth recording; not a vulnerability.

When in doubt between two levels, justify the choice in one sentence. Do not inflate;
do not downplay a silent-correctness bug because it "needs a weird input" — weird
inputs are the attacker's job.

---

## Deliverable — `RED_TEAM_FINDINGS.md`

Produce a **single, self-contained document** that an engineer with **zero prior
context** can pick up and execute. It must stand alone. Structure:

### 1. Executive summary (≤ 12 sentences)
Overall security posture (a one-word grade: Critical-risk / At-risk / Hardened),
the count of findings by severity, and the top 3 ways this system gets broken today.

### 2. Attack surface map
The Phase-1 inventory: trust boundaries, what crosses each, what trusts it.

### 3. Findings register
Every finding, sorted by severity then exploitability. Each finding gets a stable ID
(`RT-001`, `RT-002`, …) and records:
- **Severity** (one of the labels above)
- **Title** (the weakness, in attacker terms)
- **Location** (`file:line`, multiple if relevant)
- **Vulnerability** (what is wrong)
- **Attack** (who the attacker is, what they control, the step-by-step path to impact)
- **Impact** (which core security claim breaks, and the concrete consequence)
- **Confidence** (Proven / Likely / Hypothesis — say what would confirm a hypothesis)

### 4. Remediation plan — epics & tasks
This is the part another LLM executes with no context. Organize fixes into **epics**
(themed groups — e.g. "Verifier fail-closed hardening", "Network-service resource
bounds", "FFI memory-safety", "Cross-impl verdict parity"). Under each epic, list
**tasks**. **Every task begins with its severity and a description of the
vulnerability it fixes**, then the fix. Use this exact shape:

```
#### TASK <epic>.<n> — <short title>
**Severity:** CRITICAL | HIGH | MEDIUM | LOW
**Fixes:** RT-0NN
**Vulnerability:** <2–4 sentences: what the weakness is and how it's exploited,
so the executor understands the danger before touching code.>

**Files:** <paths>
**Fix:** <concrete change — what to do, the approach, the gotcha to avoid.>
**Acceptance:** <how we verify it's fixed — ideally an adversarial test that fails
before the fix and passes after, plus any CI gate that should enforce it going
forward.>
**Effort:** S (<2h) | M (half-day) | L (1–2 days) | XL (break down further)
**Regression risk:** <could the fix itself break correct behavior? how to de-risk.>
**Depends on:** <task IDs or "none">
```

Order epics so that **Milestone 0** is any test/CI safety net needed to fix safely,
**Milestone 1** is all CRITICAL fixes, **Milestone 2** is HIGH, and **Milestone 3** is
MEDIUM/LOW hardening. Flag **quick wins** (high severity, S effort) separately so they
can be done immediately.

For the top 3 CRITICAL tasks, add a short implementation sketch (approach, key steps,
the trap to avoid).

### 5. Adversarial test gaps
List the negative/abuse tests this codebase *should* have but doesn't — the inputs
that would have caught the findings (malformed/oversized/wrong-curve/replayed/
revoked-key/forged-delegation fixtures, cross-impl differential vectors, fuzz
targets). These become Milestone-0 tasks.

### 6. Accepted-risk reconciliation
The repo documents some accepted risks (`kt=1` duplicity, no witnesses — see
`docs/architecture/multi_device_accepted_risks.md` and the other
`*_accepted_risks.md` / `*threat-model*.md` docs). For each finding that touches one
of these, state whether it's **within** the accepted envelope (record and move on) or
**exceeds** it (a real finding the documented risk doesn't cover). Do not re-litigate
a documented, owner-accepted decision — but do flag where reality drifted past what
was accepted.

### 7. Open questions for the human
Anything requiring a product/threat-model decision you can't make from the code
(intended deployment model, who the trusted parties are, what's in/out of scope for
launch).

---

## Conventions to respect (so fixes fit the codebase)

- **Pre-launch, zero users:** wire formats and APIs may change freely; you don't owe
  backward compatibility. Recommend the *correct* fix, not the compatible one.
- **Fail-closed is the law.** Any remediation must preserve or strengthen
  fail-closed behavior. A fix that makes verification more permissive is a regression.
- **Errors are typed** (`thiserror` in core/SDK; `anyhow` only at CLI/server
  boundaries). **No `unwrap`/`expect`** in production paths without a proven-safe
  `INVARIANT:` justification. Fixes should follow this.
- **Quote the threat model, don't reinvent it.** Read the `*threat-model*.md` and
  `*accepted_risks.md` docs and `docs/architecture/cryptography.md` before judging a
  crypto choice.
- **Authoritative project conventions live in `CLAUDE.md` at the repo root.** Read it.

Begin with Phase 1. Be thorough, be adversarial, and prove what you can.
