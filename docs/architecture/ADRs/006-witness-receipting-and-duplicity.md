# ADR 006 — Witness receipting & duplicity (Epic D)

**Status:** Accepted
**Context:** Epic D ("remove trust-on-first-sight"). Closes the `kt=1` / "no
witnesses" accepted risk by making establishment events witness-receipted and
gating verification on M-of-N witness agreement.

## Context

Before Epic D the witness *plumbing* existed (an axum witness server, a SQLite
receipt store, a parallel collector, the KAWA M-of-N engine, the `rct` receipt
type, `b[]`/`bt` event fields) but **nothing consulted a receipt on the trust
path**: `validate_kel` replayed with zero receipt awareness, KAWA was called by
nobody, receipts were unsigned, and backers were authored empty. Verification was
trust-on-first-sight.

Epic D wires the loop closed. The decisions below were surfaced during gap
analysis and are recorded here as the load-bearing trust choices.

## Decisions

1. **Mechanism = KERI-native `b[]`/`bt` backers + `rct`/KAWA.** Witnessing uses
   the KERI-native backer set and the KAWA M-of-N algorithm — *not* the
   CT/Sigsum-style organizational/jurisdictional diversity quorum sketched in
   `docs/security/witness-diversity.md`. CT-style transparency diversity is an
   explicit **non-goal** of Epic D and a possible future layer (see Deferrals).

2. **Witness identity = pinned AID.** A witness is identified by its curve-tagged
   CESR verkey **AID**, not a URL. `auths witness add` resolves the AID from the
   server's `/health` (`witness_did`) and pins it; `WitnessConfig` carries
   `(url, aid)` pairs. The AID is what `b[]` designates, what KAWA dedupes quorum
   by, and what a collected receipt's signature is verified against. (D.1)

3. **Delegation witnesses = root-inherited.** A device's delegated `dip`/`drt`
   carries `b=[]`, `bt=0`; trust flows through the **receipted root `ixn`** that
   anchors the delegation. Devices do not run their own witnesses in this epic.

4. **Verifier policy = warn-default, fail-closed opt-in.** A verifier cannot
   trust the signer's self-declared `WitnessPolicy` (that lives in the signer's
   config). Verification has its **own** policy: default **Warn** (an under-quorum
   signer KEL verifies with a non-fatal warning, preserving the trust-on-first-
   sight caveat during rollout); `--require-witnesses` opts into **fail-closed**
   (under-quorum is a typed verification failure). (D.7)

5. **Receipt provenance = stored witness AID, verified at a single chokepoint.**
   The wire `rct` body stays spec-shaped `[v,t,d,i,s]` (its `i` is the *controller*
   AID). The verifying **witness AID** travels alongside the receipt out-of-band,
   as `StoredReceipt { signed, witness }`. Verification is a single chokepoint —
   `auths_core::witness::verify_receipt`, the **only** constructor of
   `VerifiedReceipt` — which checks the receipted SAID against the submitted event
   and the signature against the pinned (curve-tagged) witness key, never the
   controller `i`. `ReceiptCollector::collect` returns `Vec<VerifiedReceipt>`, and
   the quorum counter accepts only `VerifiedReceipt`, so counting a forged,
   foreign-key, or wrong-event receipt is **unrepresentable** rather than merely
   filtered downstream. (D.2)

6. **Annex-A superseding recovery = deferred.** Epic D *detects and refuses* on
   irreconcilable duplicity (first-seen + flag/refuse). It does **not** implement
   rotation-supersedes-interaction recovery or the toad-vs-first-seen tiebreak.
   See Deferrals.

## Consequences (assurance, stated precisely)

- A `bt=0` identity is **trust-on-first-sight** (the baseline) — no witnesses to
  satisfy. A witnessed KSN with `bt=0` stays `TrustOnFirstSight`. (D.13)
- `N=1` witness tolerates `F=0` faulty witnesses and **does not** stop
  controller+witness collusion (a single operator can still equivocate with a
  colluding controller).
- `N=3, bt=2` is the smallest real BFT-flavored config: it tolerates one bad or
  unavailable witness.
- KAWA gives **accountability**, not consensus: there is no global ordering or
  chain. A `Witnessed` key-state is never authoritative *over* a resolvable KEL
  (replay the log), and a delegated-device `Witnessed` KSN still cannot prove
  non-revocation (a root-KEL `ixn` fact). (D.13)
- Cross-source forks (local vs remote) and conflicting witness receipts are
  refused rather than silently disambiguated. (D.8)

## Deferrals (tracked)

- **Annex-A superseding recovery** (rotation-supersedes-interaction;
  toad-vs-first-seen tiebreak) — out of scope per decision 6. **Action:** file a
  tracking GitHub issue; until then this ADR is the record. The roadmap's
  "no trust-on-first-sight" claim holds for *detection*; *automatic recovery* is
  the deeper follow-up.
- **CT/Sigsum diversity quorum** (`docs/security/witness-diversity.md`) — was a
  future layer, not the Epic-D mechanism (decision 1). **SUPERSEDED by Epic W
  (Witness Commons, fn-156):** the organizational/jurisdictional/**infrastructure**
  diversity quorum is now implemented — a typed independence model
  (`auths_keri::witness::independence::spans_distinct`) evaluated over the *actual*
  cosigning quorum in the CT gate (`auths-transparency` `verify_witnesses`), a
  fail-closed `witness_policy.json` loader, a ratified machine-readable admission
  schema + CI enforcer, and a cross-operator equivocation monitor + gossip. So
  decision 1's "CT-style diversity is a non-goal" no longer holds; Epic W is the
  layer it deferred. Remaining non-code/governance items are tracked in the Epic W
  issues (auths-dev/auths#235–#243).

> The Annex-A recovery deferral above remains a human-gated follow-up; record it as
> a tracking issue and back-reference this ADR. (The Epic W deferrals were filed as
> auths-dev/auths#235–#243.)

## Reconciliation

- The older witness epic (roadmap "Epic D" ≡ accepted-risk doc "Epic 3") is
  superseded by this epic. Its still-open todos — "verify witness receipt
  signatures", "wire receipts + KAWA into the verifier path", and "single
  Auths-operated witness + minimal OOBI" — are delivered here (receipt signing +
  collection-time verification, receipt-gated replay + verify-path wiring, and
  the already-built witness service + pinned-AID resolution respectively). Its
  typed-`bt`, typed-`Receipt.t`, and first-seen-replay todos shipped earlier.
- "Epic 3" (in `multi_device_accepted_risks.md`) and "Epic D" (in
  `keri-only-roadmap.md`) are the **same** witnessing epic under two labels.

## References

- `docs/architecture/keri-only-roadmap.md` §"Epic D"
- `docs/architecture/multi_device_accepted_risks.md` ("No witnesses" risk)
- `docs/security/witness-diversity.md` (CT model — future layer, non-goal here)
- `docs/architecture/cryptography.md` → "Wire-format Curve Tagging"
