# Cycle WIT-N5 — zero protocol vocabulary in the operator happy path

- **Date:** 2026-06-14
- **Gap:** `WIT-N5` (class `friction`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored greenfield (+ jargon-leak
  trap), baselined RED, driven GREEN; the trap stays RED; the BOOT, WIT-N1,
  WIT-N2, WIT-N3, WIT-N4 probes still GREEN; all gates green (suite probes 8/8
  GREEN + 5/5 traps RED, demos `rictl matrix --gate` → exit 0, interop
  `ictl matrix --gate` → exit 0). `open → closed` in `gaps.yaml`; GAPS.md
  §WIT-N5 rewritten to the closed reality.
- **auths rev:** branch `dev-auths-network` (parent `aa5eeb46`).

## The claim, and why it was genuinely RED

An operator stands a witness up, checks on it, registers it, reads its logs, and
tears it down — and must never need the trust kernel's **vocabulary** to do any
of it (PRD §US-001, §6). The words a verifier speaks (key event logs, key-state
notices, self-addressing identifiers, the CESR wire, signing thresholds) are
correct *inside* the kernel and pure friction in an operator's face.

The subtlety: the operator happy-path *output* was already clean. The genuine RED
was structural — the rule it was held to had **no single owner the probe could
anchor to**. There were three divergent, hand-maintained jargon lists — one in
`lib.rs`'s health-URL test, one in `build.rs`'s verdict-summary test, one inline
in the WIT-N1 probe — each a partial (6-term) copy free to drift from the surface
it guarded. A vocabulary guarantee whose denylist lives in three ad-hoc copies is
a hope, not a guarantee.

The probe (`probes/wit-n5.sh`, authored this cycle) scans the LIVE operator happy
path against the denylist **extracted from the product source**, so probe and
surface cannot drift. At baseline — with no canonical owner present — it was
honestly RED:

```
$ NO_COLOR=1 bash probes/wit-n5.sh        # canonical denylist owner absent
ours=no-canonical-denylist expected=one-owner — the product exposes no single
source of truth for the operator-vocabulary rule (expected
…/auths-witness-node/src/vocabulary.rs); a rule with no owner is a hope, not a
guarantee                                                         (exit 1 RED)
```

## The fix (smallest honest change in `../auths`)

Lift the operator-vocabulary rule into one place; make every check consume it.

1. **One source of truth** (`auths-witness-node/src/vocabulary.rs`, new): the
   canonical `PROTOCOL_VOCABULARY` denylist (the kernel's wire/ceremony
   vocabulary an operator must never see — `keri kel ksn said cesr oobi acdc tel
   verkey prefix threshold` and more) and `scan_for_protocol_vocabulary` —
   **whole-word, case-insensitive**, so benign substrings (`prefixed`,
   `did:key:…`, `received`, `unsaid`) are never false positives. Re-exported from
   the crate root.
2. **The crate's own happy-path tests consume it; their divergent copies are
   deleted** (quality §3/§4): `lib.rs`'s `health_url_has_no_protocol_vocabulary`
   and `build.rs`'s `verdict_summary_carries_no_protocol_vocabulary` now call
   `scan_for_protocol_vocabulary` instead of carrying their own inline term
   arrays. The rule has exactly one place to change.
3. **Full coverage, not a subset.** Where the ad-hoc checks named six terms, the
   canonical list names the load-bearing vocabulary the spec calls out — including
   `threshold` (an operator runs a node; M-of-N is the verifier's language) and
   `acdc`/`tel`/`verkey`/`prefix`.

No operator-facing output string changed — none needed to; the happy path was
already vocabulary-free by construction. What changed is that the rule keeping it
that way is now a single enforced contract the probe anchors to.

The `witness-node` feature stays additive — `cargo tree -p auths-cli` (default)
pulls no `auths-witness-node` (0 occurrences); only `--features witness-node`
does (1) (WIT-B2). The lean default build is unchanged. No protocol is hand-rolled
(WIT-B1). No loop vocabulary leaked into the tree.

## The adversarial twin (kept RED)

`probes/wit-n5.trap/jargon-leak/happy-path.out` — a captured happy-path transcript
where one line leaked `KEL`, `threshold`, `verkey`, `prefix` among otherwise-clean
lines. Scanned against the same product-owned denylist, the probe rejects it:

```
ours=trap:kel expected=RED — the captured transcript leaks protocol vocabulary
(whole-word, case-insensitive); the scanner caught it, so this trap stays RED
                                                                  (exit 1 RED)
```

A probe that called a jargon-laden transcript clean would be one whose denylist is
cosmetic. The trap is anchored to the product's own list, so it forbids precisely
the words the surface forbids.

## Gate (the conjunction, in order)

- Suite probes → **8/8 GREEN** (boot-1..3, wit-n1..n5); **5/5 traps RED**
  (wit-n1, wit-n2, wit-n3, wit-n4, wit-n5). `boot-3` (the meta-probe that runs
  every sibling) GREEN, so wit-n5 decides inside the baseline too.
- demos `rictl matrix --gate` → **exit 0** (after rebuilding the three stale demo
  web bundles — auditor / pipeline-with-nothing-to-steal / verify-the-world —
  whose `auths_verifier.js` predated `../auths`; that staleness was pre-existing,
  not from this cycle): regressions 0, broken 0, stale 0.
- interop `./scripts/build.sh && ./ictl matrix --gate` → **exit 0**: regressions
  0, broken 0, stale 0 (a first run flagged IOP-L3c as a transient KSN-oracle
  fixture flake; a direct re-run and a clean full re-run both GREEN).
- Build + clippy clean (`-D warnings`) on `auths-witness-node` (26 tests pass,
  incl. 4 new `vocabulary` tests) and the feature-enabled `auths-cli`.

## Files

- `../auths/crates/auths-witness-node/src/vocabulary.rs` (new) — canonical
  `PROTOCOL_VOCABULARY` + `scan_for_protocol_vocabulary` (whole-word,
  case-insensitive) + tests.
- `../auths/crates/auths-witness-node/src/lib.rs` — `pub mod vocabulary`,
  re-export, and `health_url` test consumes the canonical scanner.
- `../auths/crates/auths-witness-node/src/build.rs` — verdict-summary test
  consumes the canonical scanner (its inline jargon array deleted).
- Suite: `probes/wit-n5.sh`, `probes/wit-n5.trap/jargon-leak/happy-path.out`,
  `probes/wit-n5.trap/README.md`, `gaps.yaml` (WIT-N5 closed),
  `gaps.draft.yaml` (promotion note), `GAPS.md` (§WIT-N5 rewritten).
