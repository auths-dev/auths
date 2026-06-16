# Architectural Review — 2026-06-16

## Range reviewed

`fcbea865..88cd4f4a` — the Murmur messenger work (last PR **#283** "messenger build, crypto hardening,
migration PRDs", merged to main, **plus** the current `dev-chatPrivacy` branch: the vodozemac/Olm
migration). ~30 commits, **+17,889 / −1,035 across 117 files, deletion ratio 0.058**. Code-only
(`crates/`): **+12,090 / −0**. The prior review checkpoint (`2197d511`, 2026-06-13) predates all of
this, so there is no overlap.

The 0.058 ratio is below the ~0.1 "healthy" line, but the honest read is: **`murmur-core` is a
greenfield crate** — it did not exist before this range — so additions-only is structural, not drift.
The right question here is not "did it erode a prior shape" but "is the new crate internally coherent, or
did ~20 burndown cycles + a migration leave locally-optimal sprawl." I read it on that bar.

## Verdict

**Coherent, with one real structural issue and three smaller ones.** The crate is cleanly decomposed —
19 focused modules, one responsibility each (`address`, `identity`, `prekey`, `ratchet`, `dh_ratchet`,
`session`, `channel`, `olm_backend`, `relay`, `rotation`, `trust`, `kel`, `delegation`, `corroboration`,
`leakcheck`, `number_free`, `envelope`, `vetted`). The crypto is not copy-pasted across providers; the
hardening cycles (A–E) edited in place rather than paralleling. A new engineer can hold each module in
their head. **The one thing that fails the "hold the shape in your head" bar is the public API of
`murmur-core` itself**: it is ~95% a hermetic *proof harness* for the recurve gate, not the engine — the
burndown's signature, where each probe accreted a `pub fn` entry point. That, plus a migration that
(correctly) runs two parallel join implementations and a trait abstraction that nothing yet consumes, are
the findings. None are alarming; one is worth fixing now.

## Themes

### 1. The public API is a proof harness, not the engine (surface creep) — **the finding**
`crates/murmur-core/src/lib.rs` is **2,295 lines**. Of its public surface, **11 `pub fn` are
`deliver_*` / `prove_*` / `hold_*`** (lib.rs:354–1622) each with a paired **`pub struct *Receipt`** (11
of them), totalling ~1,940 lines from line 354 on. Their **only caller anywhere is
`crates/murmur-relay/src/main.rs`** — the relay self-test binary that the gate's probes drive. The
*actual* engine API a real app calls — `impl Endpoint` (`seal_to`/`open`) — is **~103 lines**.

So a new engineer opening the engine crate's public surface meets `deliver_forward_secret`,
`prove_post_compromise_healing`, `hold_relay_boundary`, `prove_witnessed_keystate`, … before they find
`Endpoint`. These functions are real (they exercise real paths) and they *should* exist — but they are
**test/proof infrastructure living in the library's permanent public API**, one per closed claim. This is
exactly the "one narrow probe's footprint" the review prompt names, multiplied by 11.

- **Why it costs:** every `pub` proof fn + Receipt is permanent maintenance and public-API surface; it
  doubles the apparent size of the engine; it's what a future FFI/app author has to wade past; and it
  blurs "what is the engine" vs "what is the gate's evidence."
- **Verdict: `simplify now`.** Move the proof harness behind `#[cfg(feature = "proofs")] pub mod proofs`
  (or a sibling `murmur-proofs` module the relay enables), leaving `murmur-core`'s default public surface
  = the engine (`Endpoint`, `Identity`, `prekey`, `relay`, `trust`, `kel`, `delegation`, `rotation`,
  `olm_backend`). `murmur-relay` builds with the feature; the gate is unchanged. ~1,500 lines leave the
  default public API. (This is the "one refactor" below.)

### 2. Two parallel KERI joins (DRY) — transient migration cost, factor-able
The vodozemac migration added a second join alongside the homegrown one, near-identical in shape:

| Concept | Homegrown (`prekey.rs`) | Olm (`olm_backend.rs`) |
| --- | --- | --- |
| signing bytes | `bundle_signing_bytes` (:114) | `olm_bundle_signing_bytes` (:83) |
| bundle | `PrekeyBundle` (:64) | `OlmPrekeyBundle` (:108) |
| verify | `verify_rooted -> RootedBundle` (:168/:200) | `verify_rooted -> OlmRootedBundle` (:140/:172) |

Both do: build `context ‖ aid ‖ '\n' ‖ key-material`, then `hygiene-check + verify_sender → a
capability struct whose only constructor is verify_rooted`. Only the key material differs (X25519
identity+signed-prekey vs Curve25519 identity+OTK+fallback).

- **Why it costs:** it's the burndown's classic "two ways to solve one problem," *and* it doubles the
  audited-join surface (the join is the ENC-7 audit scope — auditing it twice, or auditing one and
  shipping the other, is a real risk). It is **acceptable as migration-transient** (the homegrown join is
  slated for deletion at M6 cutover per `vodozemac_migration.md` §9), but only if cutover actually
  happens; a stalled cutover makes this permanent drift.
- **Verdict: `file as debt`** with a trigger: at M6, delete the homegrown join; if M6 slips past the next
  review, factor the shared shape into one `rooted_bundle(context, aid, &[key_bytes], sig)` +
  `verify_rooted_inner(...)` helper both joins call, so there is **one** audited join shape.

### 3. `SecureChannel` + `RatchetChannel` — abstraction with no consumer yet (speculative generality)
`channel.rs` defines `SecureChannel` (encrypt/decrypt) with two impls — `OlmChannel` (real) and
`RatchetChannel`. But **nothing consumes the trait**: no function takes `impl/dyn SecureChannel`;
`OlmChannel` is used via its inherent methods. And **`RatchetChannel` has zero non-test callers** (grep:
only its own module + the `pub use` re-export). It exists to give the trait a second impl.

- **Why it costs:** a trait + a wrapper type that no caller depends on is the "abstraction layer with a
  single caller" the prompt flags — it reads as load-bearing but isn't, and `RatchetChannel` is ~40 lines
  of public surface guarding one test.
- **Verdict: `simplify now` (small).** Keep the `SecureChannel` trait — it's tiny and it's the *planned*
  FFI seam (`murmur_vodozemac_integration.md` §4) — but **drop `RatchetChannel`** until something actually
  consumes the trait through the abstraction (the FFI's `OlmEndpoint`). Re-add it the day a caller needs
  the in-tree backend behind the trait, not before. (Or, at minimum, stop re-exporting it from `lib.rs`.)

### 4. Generated + process artifacts committed (accretion)
- **`murmur_ffi.swift` is committed in two places** — `crates/murmur-ffi/generated/murmur_ffi.swift`
  (24 KB) *and* `murmur/Murmur/Sources/Shared/murmur_ffi.swift` — both **regenerated** by
  `uniffi-bindgen` in `build-ffi.sh`. Two committed copies of a generated artifact is double accretion +
  a drift risk (they can diverge from the crate they're generated from).
- **`.recurve/claims/murmur/cycles/`** — 38 files, 172 KB of per-cycle `plan.md` / `outcome.md` /
  `record.json` journals (9.5% of the range's churn). The `record.json` ledger has provenance value; the
  `plan.md`/`outcome.md` prose is largely redundant with the commit messages + the gap ledger.
- **Verdict: `prune` (see list).** Gitignore the generated bindings (regenerate at build); keep
  `record.json`, gitignore or prune the `plan.md`/`outcome.md` prose going forward.

### 5. Dependency footprint — the vodozemac tree (leave, record)
The `olm` feature pulls vodozemac (`=0.10.0`) + ~83 transitive crates, of which a dozen are genuinely new
(aes/cbc, prost, rand). This is the cost of an *audited* ratchet and is justified — and it's **off by
default** (`cfg(feature = "olm")`), so the default build and the gate don't carry it. One pre-existing
duplication surfaced: **`thiserror` v1 *and* v2** both in the tree (workspace-wide, not introduced here).
`cargo deny check bans` passes (one unrelated `unused-wrapper` warning). **Verdict: `leave it`**; record
the thiserror 1+2 consolidation as workspace debt (not murmur's to fix).

## The one refactor worth doing now

**Lift the proof harness out of `murmur-core`'s default public API (Theme 1).** Concretely:
1. Create `crates/murmur-core/src/proofs.rs`; move the 11 `deliver_*`/`prove_*`/`hold_*` fns + their 11
   `*Receipt` structs there. Gate it: `#[cfg(feature = "proofs")] pub mod proofs;` and re-export under the
   same feature.
2. Add `[features] proofs = []` to `murmur-core`; have `murmur-relay` depend on
   `murmur-core = { features = ["proofs"] }`.
3. `lib.rs` shrinks to the engine: `Endpoint`, the type re-exports, `Directory`. The hermetic-test paths
   move with the harness (or stay as `#[cfg(test)]`).

Payoff: `murmur-core`'s public surface becomes ~the engine, not ~the gate; lib.rs drops from 2,295 to
~well under 1,000; the relay and gate are unchanged; and the eventual FFI author sees the real API first.
This is precisely the cross-cycle consolidation the per-cycle loop *cannot* do (each cycle was required
to add its proof fn; none could remove the accumulated surface). Estimated effort: **S–M**, mechanical,
behind a green gate.

## Debt ledger (file-and-forget)

- **D1** — Two KERI joins (Theme 2): delete the homegrown `prekey.rs` join at M6 cutover; if M6 slips,
  factor the shared `verify_rooted`/signing-bytes shape into one helper. Trigger: next review.
- **D2** — `thiserror` v1+v2 duplication (workspace-wide). Consolidate on v2.
- **D3** — `lib.rs` integration tests (the `#[cfg(test)] mod tests` at the tail) are large and live next
  to the proof harness; when Theme 1 lands, decide whether they move to `tests/`.
- **D4** — `vetted.rs` (555 lines) proves ENC-6's homegrown ratchet against KATs; once M6 deletes the
  homegrown ratchet, `vetted.rs` and ENC-6 should be re-pointed at the Olm backend or retired. Track with
  the cutover.

## Prune list (pure wins)

- **P1** — `crates/murmur-ffi/generated/*` (`.swift`/`.h`/`.modulemap`, 46 KB) — gitignore; regenerate in
  `build-ffi.sh`. Removes a committed generated artifact + its drift risk.
- **P2** — The duplicate `murmur/Murmur/Sources/Shared/murmur_ffi.swift` — single-source it from the
  build, don't commit two copies.
- **P3** — `RatchetChannel` (`channel.rs`) + its `lib.rs:70` re-export — drop until a through-trait caller
  exists (Theme 3).
- **P4** — `.recurve/claims/murmur/cycles/*/plan.md`+`outcome.md` — gitignore/prune the prose journals
  (keep `record.json`); 38 files → ~13.

Reviewed through: 88cd4f4a2118aceb92a329673e3a8a4ba3694963
