# IdentityDID single-door — finish the sweep + lock (self-paced loop spec)

Self-paced. Each iteration: (1) re-derive real state from the code, (2) do the next test-first / mechanical increment, (3) run the verify gate green, (4) advance. STOP only at the Definition of Done. Do NOT commit the DID work — leave it in the tree for review.

## Goal
Make the *validated* constructor `IdentityDID`'s ONLY door. Today `IdentityDID::new_unchecked(...)` (defined in `auths-verifier::types`) lets an unvalidated `String` flow into a `did:keri:`-contracted type; a `clippy.toml` `disallowed-methods` ban discourages it but is waived per-site with `#[allow(clippy::disallowed_methods)]`. Finish closing the door:
1. Sweep the remaining internal `IdentityDID::new_unchecked(...)` call sites onto a validated path, removing each migrated site's `#[allow(clippy::disallowed_methods)]` waiver.
2. Add a `pub(crate)` visibility lock to `IdentityDID::new_unchecked` so no crate *outside* `auths-verifier` can call it at all — the ban then enforces structurally, not just by lint.

This completes the IdentityDID hardening whose first half (the `TryFrom<&Prefix>` / `TryFrom<Prefix>` door, the keychain read-validation, and the six `auths-id` inception/rotation/delegation sites routed through `prefix_to_did`) is already done.

## FINAL STATUS — sweep complete across all 7 crates; pub(crate) lock pending FLAG-1
Every crate with `IdentityDID::new_unchecked` was swept onto validated construction and is green (build + nextest + clippy, default or per-crate features — NOT workspace `--all-features`, which trips a pre-existing auths-crypto fips/cnsa `compile_error!`):

| Crate | Result |
|---|---|
| auths-storage | 10 sites → parse-on-read fail-closed; 2 regression tests; Route-C where already typed. Zero remaining. |
| auths-index | 8 sites → parse with new `InvalidDid` error variant; 3 regression tests; fixed an invalid `did:key` test literal. Zero. |
| auths-cli | 4 sites → try_from/parse fail-closed; one Route-C clone. Zero. |
| auths-sdk | 14 sites → prefix_to_did/parse, several String round-trips eliminated; 4 tests + new error variant. **1 site = FLAG-1.** |
| auths-transparency | 4 prod (fail-closed `ChainBroken`) + 4 test literals; 2 regression tests over a real Merkle chain. Zero. |
| auths-core | prod (pkcs11/secure-enclave/ffi) parse fail-closed; **negative tests restructured to write the bad string to the store and assert load() rejects it** (intent preserved, boundary-tested); caught 2 latent type-confusions. Zero. |
| auths-id | prod → prefix_to_did/parse; `did:key` negative test now asserts `parse(...).is_err()`; new `CacheError::InvalidDid` + tests. **prefix_to_did (types.rs:22) intentionally left.** |

**Only TWO `IdentityDID::new_unchecked` remain outside auths-verifier:** `prefix_to_did` (auths-id/keri/types.rs:22 — the shared helper) and **FLAG-1** (auths-sdk).

### Applying the pub(crate) lock (do this AFTER you resolve FLAG-1)
The lock cannot be applied while FLAG-1 exists (it's an external call). Once FLAG-1 is decided:
1. Resolve FLAG-1 (see below).
2. Move `prefix_to_did` INTO `auths-verifier` (it only needs `auths_keri::Prefix`, which auths-verifier can see) so its `new_unchecked` becomes crate-internal; update the `prefix_to_did` import paths at its call sites (auths-id/sdk/index/storage).
3. Change `IdentityDID::new_unchecked` to `pub(crate)` in `auths-verifier/src/types.rs`; update its rustdoc to say external callers use `parse`/`TryFrom`.
4. Confirm `grep -rn 'IdentityDID::new_unchecked' crates/*/src | grep -v auths-verifier` is empty, then whole-workspace `cargo build` + `cargo clippy --all-targets -- -D warnings` (default features) green.

### FLAG-2 (soft — optional, no blocker)
`auths-id` `MemberInvalidReason::IssuerMismatch { expected_issuer, actual_issuer: IdentityDID }`: `actual_issuer` could more faithfully be a `CanonicalDid` (to hold a non-keri claimed issuer), but that enum is constructed in auths-storage, so retyping ripples cross-crate. Left as-is, handled fail-closed (unparseable issuer → `Other`). Optional future improvement; not required for the lock.

## Increment-1 findings (recorded — do not re-derive from scratch)
- **The door EXISTS** in `crates/auths-verifier/src/types.rs`: `impl TryFrom<&auths_keri::Prefix> for IdentityDID` (line ~293), `TryFrom<auths_keri::Prefix>` (~301), plus `TryFrom<&str>` (~258) and `TryFrom<String>` (~266); `DidParseError::EmptyIdentifier` is present (rejects the empty placeholder). So PR #289's hardening is on this branch — NO door to establish. Skip that prerequisite.
- **89** `IdentityDID::new_unchecked` sites outside `auths-verifier` to sweep (precise count).
- **`prefix_to_did(&Prefix)` (auths-id/keri/types.rs:19) ITSELF calls `new_unchecked`** with a justified `#[allow]`/INVARIANT. This is the load-bearing decision for the lock: once `new_unchecked` is `pub(crate)` in auths-verifier, `prefix_to_did` (in auths-id) can no longer call it. Resolve by EITHER (a) replacing `prefix_to_did(&p)` call sites with `IdentityDID::try_from(&p)?` and removing the helper (cleanest "single door", but makes those sites fallible — add fail-closed handling/tests), OR (b) moving the infallible helper into auths-verifier so it keeps crate-internal access. Decide this BEFORE the lock; the sweep direction (toward TryFrom at call sites) favors (a).

## Sweep progress + FLAGS (update as crates land)
- Swept + reviewed GREEN (zero IdentityDID::new_unchecked, fail-closed parse-on-read, regression tests): **auths-storage**, **auths-index**, **auths-cli**, **auths-sdk** (all but FLAG-1), **auths-transparency**, **auths-core** (negative tests restructured to assert rejection at the parse/load boundary — write the bad string to the store, assert load() errors).
- In progress: **auths-id** (everything except prefix_to_did's types.rs:22).
- Then: the pub(crate) lock (BLOCKED by FLAG-1).

**Verify-gate caveat:** `cargo clippy --all-features` / `cargo build --all-features` for the WHOLE workspace FAILS on a PRE-EXISTING `compile_error!` in `auths-crypto` (the `fips` + `cnsa` features are mutually exclusive) — unrelated to this work. For the final whole-workspace check use default features: `cargo build` and `cargo clippy --all-targets -- -D warnings`. Per-crate `--all-features` is fine for crates that don't pull both fips and cnsa.

### FLAG-1 (needs a human decision; BLOCKS the pub(crate) lock)
`crates/auths-sdk/src/domains/signing/service.rs:766` builds an `IdentityDID` from a **`did:key:`** (an ephemeral key acting as its own issuer): `IdentityDID::new_unchecked(device_did.as_str())` where `device_did` is a `CanonicalDid` did:key. `IdentityDID::parse`/`TryFrom` accept ONLY `did:keri:`, so the validated door cannot construct this value — it is a type-contract mismatch, not a missing validation. Forcing parse() would break it. RESOLUTION (pick one, your call): (a) change the artifact-metadata issuer field from `IdentityDID` to `CanonicalDid` (accepts both `did:key:` and `did:keri:`) and store `device_did` directly — the type-correct fix, but it ripples through the artifact metadata struct + serialization + consumers; or (b) keep this single `new_unchecked` as a documented proven-safe exception, in which case the `pub(crate)` lock cannot be applied (the clippy ban + INVARIANT waiver stays as the enforcement for this one site). Until decided, the lock step stays blocked; everything else can complete.

## Verified landscape (re-confirm at execution time — counts shift)
- `IdentityDID::new_unchecked` is defined in `auths-verifier` (`auths_verifier::types::IdentityDID`). The `pub(crate)` lock goes THERE.
- `clippy.toml` already bans it (`disallowed-methods`, with `allow-invalid = true`); proven-safe sites carry `#[allow(clippy::disallowed_methods)]` + an `INVARIANT:` comment.
- The DRY validated routes:
  - `auths_id::keri::types::prefix_to_did(&Prefix) -> IdentityDID` (infallible; for a `Prefix` known non-empty).
  - `IdentityDID::try_from(&Prefix)` / `TryFrom<Prefix>` — the fallible door (rejects the empty placeholder `Prefix` as `EmptyIdentifier`). **VERIFY this exists on the branch first** (it is in whichever crate owns `Prefix`); if it is NOT present, that is a prerequisite — establish it (mirroring the existing `prefix_to_did`) before the sweep, or stop and report.
  - `IdentityDID::parse(s)` — for a `String`/`&str` of unknown provenance (returns a validation error).
- A broad `grep new_unchecked` over-counts: it also matches `DeviceDID`/`CanonicalDid`/`CommitOid`/`PublicKeyHex`. **Filter to `IdentityDID::new_unchecked` specifically.** Likely concentrations: `auths-sdk`, `auths-cli`, `auths-index`, `auths-transparency` (and any others the precise grep surfaces).

## Approach — per call site, pick the right validated route (DRY)
- Building from a `&Prefix` known non-empty (e.g. a freshly-derived inception prefix): `prefix_to_did(&prefix)`.
- Building from a `Prefix` that could be the empty placeholder: `IdentityDID::try_from(&prefix)?` (propagate the error fail-closed; never paper over `EmptyIdentifier`).
- Building from a stored/external `String`: `IdentityDID::parse(&s)?`.
- Remove the `#[allow(clippy::disallowed_methods)]` waiver at every migrated site.
- A genuinely proven-safe site that cannot use the door (e.g. a compile-time-constant literal DID in a test) MAY keep `new_unchecked` with an `INVARIANT:` comment — but after the `pub(crate)` lock those can only remain *inside* `auths-verifier`. An external proven-safe need that survives is a signal the door is missing a case: extend the door rather than keep a waiver.

## The lock (do LAST, after the sweep is complete)
Change `IdentityDID::new_unchecked` to `pub(crate)` in `auths-verifier`. This is only possible once NO external crate calls it. Internal `auths-verifier` uses keep the clippy ban + `INVARIANT` waivers. Re-confirm the `clippy.toml` ban entry still makes sense (external crates now *cannot* reference the path; the entry still guards the internal `auths-verifier` sites). Update the rustdoc on `new_unchecked` to say it is crate-internal and external callers must use `parse`/`TryFrom`.

## Rules
- Mostly mechanical + behavior-identical. Where a migration changes a signature to fallible (`?`), add/extend a test proving the fail-closed path (a malformed/empty input is rejected, not silently accepted). The existing `load_rejects_tampered_identity_did` regression is the model.
- DRY: route through `prefix_to_did` / `TryFrom` / `parse`; do not hand-build `format!("did:keri:{prefix}")`.
- Comments/docstrings: plain language, what + non-obvious why. NEVER put workflow IDs (TD-, AGT-, PR numbers, fn-, etc.), ticket numbers, or document/temp-file names in code or comments.
- Keep every crate green at each step; do the sweep crate-by-crate so the tree never sits broken across iterations longer than one increment.
- Do NOT commit the DID work — leave it for review.

## Verify gate (every increment; full set before done)
- `cargo build` (workspace — the migrations touch many crates; the lock must not break any consumer)
- `cargo nextest run -p <crate>` for each crate swept (and the whole workspace before declaring done)
- `cargo clippy --all-targets --all-features -- -D warnings` (workspace — this is what enforces the `disallowed-methods` ban; it must be clean with the waivers removed)
- confirm a precise `grep -rn 'IdentityDID::new_unchecked' crates/*/src` outside `auths-verifier` returns ZERO before adding the `pub(crate)` lock.

## Definition of Done (stop only when ALL hold)
- Every internal `IdentityDID::new_unchecked` site outside `auths-verifier` is migrated to a validated route and its `#[allow(clippy::disallowed_methods)]` waiver removed; the precise grep returns zero external sites.
- `IdentityDID::new_unchecked` is `pub(crate)` in `auths-verifier`; the workspace builds and `clippy -D warnings` is clean.
- Any signature that became fallible has a fail-closed test; existing tests stay green.
- Not committed (DID work). Summarize: sites swept per crate, the route chosen, the lock, and the green results.

## Kickoff — how this loop STARTS (the money→DID handoff)
This loop begins only after the money type-safety loop has reached ITS Definition of Done (all three pieces green, uncommitted on `dev-moneyTyping`) and the user has not yet returned. To start cleanly without tangling the two efforts:
1. **Checkpoint the money work** so it is preserved and reviewable (it is green but uncommitted): `git add -A && git commit -m "money type-safety: Ceiling/Actual newtypes, Settlement enum, non-zero settlement" --no-verify` on `dev-moneyTyping`. (This is a local checkpoint to enable the branch switch — flag it in the summary so the user can review / re-sign / amend with their commit identity.)
2. **Branch the DID work off a clean base:** `git checkout main` then `git checkout -b dev-IdentityDidHardTypes`. (Do NOT carry money changes into this branch.)
3. Run the verify gate once on the fresh branch to confirm a green starting point, then begin increment 1 (verify the door exists; precise-grep the `IdentityDID::new_unchecked` sites; start the first crate).

## Increments (re-derive real state each iteration)
1. Verify the `TryFrom<&Prefix>` door + `prefix_to_did` exist; precise-grep the external `IdentityDID::new_unchecked` sites; list them per crate.
2. Sweep `auths-sdk` sites → validated routes, drop waivers. Green.
3. Sweep `auths-cli` sites. Green.
4. Sweep `auths-index`, `auths-transparency`, and any other crates the grep surfaced. Green.
5. Confirm zero external sites; add the `pub(crate)` lock in `auths-verifier`; workspace build + clippy green.
6. Docs sweep + full gate.
