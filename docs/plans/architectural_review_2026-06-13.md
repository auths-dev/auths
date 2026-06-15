# Architectural Review — 2026-06-13

## Range reviewed

`v0.1.3..HEAD`, **39 commits**, **+16,845 / −3,437 across 222 files**, deletion ratio **0.20**.
HEAD = `2197d51183d7beb98e13a92cdd1d2273e5919b02`.

Churn concentrated in `auths-verifier` (tlog + bundle surfaces, ~11%),
`auths-mobile-ffi` (~9%), `auths-cli/commands` (~8%), `auths-transparency`
(~8%). 43 new files; the largest are offline-verification surfaces
(`evidence_pack.rs` 784L, `tlog/merkle.rs` 691L, `commit_bundle.rs` 586L) and
the mobile-FFI KEL-verify contexts (~1,578L across three files).

This is the first architectural review on record — no prior checkpoint SHA
existed, so the range was taken from the explicit `v0.1.3` tag.

## Verdict

**Pass — the codebase is still coherent after this range, and a new engineer
could hold its shape in their head.** The range is additive (ratio 0.20, above
the 0.1 bloat floor but not deleting much), yet the additions are genuine new
capability — offline/air-gapped bundle verification, an RFC 6962 transparency
log, mobile-FFI delegated-KEL verification, OIDC-subject policy anchoring,
SOC 2 / ISO 27001 compliance predicates — and they **consistently reused shared
cores instead of forking them.** Every new bundle/FFI/transparency surface
bottoms out in the same `auths_keri::validate_signed_kel` engine; the Merkle
math has exactly one implementation; and the two highest-risk DRY zones — the
crypto providers and the capability codec — were *consolidated* in this range,
not copy-pasted. The burndown loop behaved.

There is **one real structural regression**: a complete, dormant registry-sync
subsystem in `auths-rp` (554 lines, behind an unused feature flag, zero
consumers) that parallels the live registry-sync path in `auths-storage`. That
is the single cross-cycle artifact the per-cycle loop could not see, and it is
the one thing worth fixing now. Everything else is small, recordable debt.

## Themes (the cross-cutting findings)

### 1. Duplicate registry-sync subsystem — the one real bloat regression
**What:** Two independent registry-sync implementations now ship. The **live**
one (`auths-storage/src/git/sync.rs:113,204` → `push_registry`/`pull_registry`,
surfaced via `auths_sdk::storage` and the `auths registry push/pull` CLI) is
wired and used. The **dormant** one (`auths-rp/src/registry_sync.rs:122,176,255`
→ `RegistrySync` port + `RegistryWatcher` poll loop + `GitRegistrySync` adapter,
re-exported at `auths-rp/src/lib.rs:28-31`, gated behind the `git-sync` feature)
has **zero downstream consumers** — no crate enables `auths-rp/git-sync`, and no
`auths_rp::{RegistrySync,RegistryWatcher,GitRegistrySync}` import exists outside
auths-rp's own tests.
**Where:** `auths-rp/src/registry_sync.rs` (554L, new), `auths-rp/Cargo.toml`
(`git-sync = ["dep:git2"]`, new optional `git2`).
**Why it costs:** 554 lines + a feature flag + an optional heavyweight dep
(`git2`) of permanent maintenance for code nothing calls, *and* it forces the
next reader to answer "why are there two registry syncs?" before they can trust
either. Provenance shows the seam clearly: commit `4747df21` added the rp
"registry-sync surface" as a probe; commit `d6c7b352` (LTL-8) then built the
actually-used path in storage. Neither cycle saw it was duplicating the other.
**Verdict:** `simplify now`. (Layering itself is clean — the rp surface does no
KEL merge and respects the `rp → verifier-only` rule; it's the *duplication*,
not a violation.)

### 2. `rehydrate_source_seal` triplication — a cross-crate drift seam
**What:** The identical `match event { Dip | Drt => set source_seal }` body lives
in three crates, byte-for-byte, and the delegated-attachment-pairing shim around
it is forked alongside it.
**Where:** `auths-verifier/src/org_bundle/verify.rs:155` (its own comment:
*"Mirrors the storage layer's rehydrate_source_seal"*),
`auths-storage/src/git/adapter.rs:888`,
`auths-mobile-ffi/src/kel_verification.rs:192`. The FFI also re-states
`AttachmentError::CountMismatch` (`kel_verification.rs:166`) because it could not
reuse `auths_keri::pair_kel_attachments` (that helper uses the plain attachment
parser, not the delegated one).
**Why it costs:** No correctness divergence *today* (all three are identical and
all funnel into `validate_signed_kel`), but a future change to the delegated
source-seal format needs three synchronized edits in three crates — the exact
shape that silently diverges.
**Verdict:** `file as debt`. Hoist `rehydrate_event_source_seal(event, Option<SourceSeal>)`
and a `pair_delegated_kel_attachments(events, attachments)` into `auths_keri`
(all three already depend on it). ~40 lines, collapses 3→1.

### 3. Consolidation wins — the burndown did the right thing (counter-evidence to bloat)
Record these so the next reviewer knows these zones are healthy and need no
re-audit:
- **Crypto providers (the prompt's highest-risk zone):** PWNTS-4 routed P-256
  SSH verify *through the provider port* (`auths-verifier/src/commit.rs:75-99`)
  so both curve arms are one-line `provider.verify_*` calls — it deleted a
  direct-backend `#[cfg(native)]` branch, and rewrote the WASM `verify_p256`
  (`webcrypto_provider.rs:97`, **−60 lines**) to mirror the Ring path "one source
  of truth." The providers got *less* duplicated in this range.
- **Capability codec:** DOTAK-2 collapsed three divergent grammars (join on
  issue, split on list, single-wrap on verify) into one inverse pair
  `Capability::join_claim`/`parse_claim` (`auths-keri/src/capability.rs:218-249`)
  and deleted the inline parsers at `issue.rs:110,403` and `credential.rs:329`.
  Fail-closed (`parse_claim` errors rather than silently dropping).
**Verdict:** `leave it` — exemplary.

### 4. Verifier bundle + transparency surfaces layer cleanly (single source of truth)
**What:** Despite three new "bundle" surfaces and two Merkle modules, the
verification cores are shared, not parallel:
- `evidence_pack → org_bundle::verify_org_bundle → validate_signed_kel`
  (`evidence_pack.rs:368`); `commit_bundle → {validate_signed_kel (commit_bundle.rs:131),
  commit_kel}`. evidence_pack adds only the orthogonal transparency-inclusion axis.
- Merkle math exists **once** in `auths-verifier/src/tlog/merkle.rs` (RFC 6962
  `0x00`/`0x01` domain separation at lines 9/11); `auths-transparency` is pure
  re-export shims depending *down* onto the verifier
  (`auths-transparency/Cargo.toml` → `auths-verifier`). A cross-crate round-trip
  test (`auths-transparency/src/writer.rs:349`) guards byte-parity.
- `oidc_policy` is a textbook writer/reader split: the matching logic lives once
  in the verifier (`oidc_policy.rs:128-182`); the SDK copy
  (`domains/org/oidc_policy.rs`) **imports** the type and only adds KEL
  anchoring/resolution. Matches the "SDK orchestrates, verifier implements" rule.
**Where:** `auths-verifier/src/{evidence_pack,commit_bundle,oidc_policy,tlog/*}`,
`auths-verifier/src/org_bundle/*`.
**Verdict:** `leave it`. Minor: the pin-membership check (`is this DID in
pinned_roots?`) is inlined three times (`commit_bundle.rs:351`,
`org_bundle/verify.rs:279`, `evidence_pack.rs:370`) — a one-line
`root_is_pinned` helper → debt.

### 5. Process-artifact accretion vs. clean generated docs
**What:** Two opposite patterns landed together.
- **Prune:** `docs/plans/blockers/fixes.md` (316L) and `revolutionary.md` (69L)
  are hand-written, rev-pinned process snapshots — self-admittedly rotting
  (*"verified against source at rev 861c430f … line numbers drift … re-grep if
  files have moved"*, `fixes.md:5-7`). They are an adversarial planning review of
  an external demo repo, redundant with git history, not gitignored.
- **Keep:** the 12 new `docs/errors/AUTHS-E*.md` are the opposite — generated by
  `xtask gen-error-docs` (header banner + freeze-checked `registry.lock`), every
  code maps to real source bindings. Three removed docs (E5619–E5621) are
  legitimate retirements from the `OrgBundleError` crate move.
**Verdict:** `prune` the `blockers/*.md` (gitignore or relocate to `.flow/`);
`leave it` for the error docs.

## The one refactor worth doing now

**Resolve the duplicate registry-sync (Theme 1).** Pick the live
`auths-storage` implementation as the single owner. Then either:
- **(a) Prune** the `auths-rp` `RegistrySync` / `RegistryWatcher` /
  `GitRegistrySync` surface (`registry_sync.rs`, the `lib.rs:28-31` re-exports,
  the `git-sync` feature, and the optional `git2` dep) — risk is low, there are
  no callers; **or**
- **(b) Wire it** into the plausible consumer this cycle (the pairing daemon or
  MCP server is the natural home for the `RegistryWatcher` poll loop) so it stops
  being dead code.

Shipping both is the liability. This is exactly the cross-cycle simplification
the per-cycle loop structurally cannot perform — it requires seeing commit
`4747df21` and `d6c7b352` as two solutions to one problem.

## Debt ledger (file-and-forget)

- **`rehydrate_source_seal` ×3 + delegated-attachment pairing fork** → hoist to
  `auths_keri` (Theme 2). The verifier's own comment is the standing TODO.
- **`pk_from_hex_wasm` length-dispatch** (`auths-verifier/src/wasm.rs:18-32`):
  infers curve from key byte-length (`32 → Ed25519`, `33|65 → P256`) — a direct
  violation of the load-bearing CLAUDE.md rule *"Never dispatch on pubkey byte
  length as a curve tag"* (33 bytes is ambiguous P-256 vs secp256k1). **This is
  pre-existing — not introduced in this range** — but the range's PWNTS-4
  expansion of WASM P-256 verification makes it newly load-bearing. Should accept
  a CESR-tagged key or explicit `curve` param. Flag for the curve-agnostic AST
  gate owner; it's a correctness-adjacent rule violation, not stylistic.
- **`root_is_pinned` pin-membership check** inlined ×3 (Theme 4).
- **Inline `match curve → TypedSeed`** at `auths-sdk/src/domains/signing/service.rs:337`
  and `auths-sdk/src/keys.rs:82` (predate range) → route through
  `TypedSeed::from_curve`, which this range introduced for the ephemeral path.
- **Inline registry refspec assembly** in `auths-storage/src/git/{sync.rs,remote.rs}`
  (3 sites) → a `registry_refspec(force: bool)` helper next to the `REGISTRY_REF`
  constant.
- **`auths-id/src/policy/mod.rs:798`** test reimplements the capability split
  instead of calling `Capability::parse_claim` — make the test exercise the real
  codec.
- **CLI surface watch:** `--oidc-policy` vs `--oidc-policy-did` are two
  policy-source flags (file vs KEL-resolved); coherent now via `conflicts_with`,
  but revisit if a third source lands. `--print-uri` (`id rotate`,
  feature-gated, hidden) is a narrow scripting escape hatch — fold into a
  `--output uri|qr` once a second delivery mode exists.

## Prune list (pure wins)

- `auths-rp` `RegistrySync`/`RegistryWatcher`/`GitRegistrySync` (554L) +
  `git-sync` feature + optional `git2` — if no watcher consumer is imminent
  (Theme 1 / the one refactor). **Safe: zero external callers.**
- `docs/plans/blockers/fixes.md` (316L) + `docs/plans/blockers/revolutionary.md`
  (69L) — rotting process snapshots; gitignore or move to `.flow/`.
- **Dependency duplication** (mostly transitive and pre-existing — this range
  did not materially worsen it, but worth a consolidation glance):
  `thiserror` **1 + 2** (the prompt explicitly calls this out — chase the v1
  holdout), `hashbrown` ×4 (0.14/0.15/0.16/0.17), `rand`/`rand_core` ×3,
  `getrandom` ×3, `der` 0.7/0.8, `const-oid` 0.9/0.10, `security-framework`
  2/3, `webpki-roots` 0.26/1.0. Note: this range deliberately added
  `getrandom_02` (0.2) for the WASM verifier — that one is justified, not drift.

Reviewed through: 2197d51183d7beb98e13a92cdd1d2273e5919b02
