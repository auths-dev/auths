# ADR 009 — Freshness verdict model (bounded freshness, verifier-set policy)

**Status:** Accepted
**Context:** Milestone 0 — Security S5/S9 (freshness/revocation at the verifier
boundary). Sources: `docs/essays/security-review-2026-06.md` (AUTHS-2026-003 / V1),
`security_testing/key-compromise-recovery/REPORT.md` (D2/D6). This ADR freezes the
verdict shape **before any verdict-consuming code ships** (the gate below).

## Context

The verifier is offline-first — zero network calls at verify time is the whole product
thesis. But **offline verification and guaranteed real-time freshness cannot both
hold**: a verifier only knows what is in the bundle/slice it was handed. A relying party
presented a *pre-revoke* slice still gets `Valid` (REPORT D2), because a positive verdict
today does not surface *how fresh* it is. `CredentialVerdict::Valid` already carries an
`as_of` (the issuer-KEL tip it was decided against); `CommitVerdict::Valid` carries none —
both are, for trust purposes, a **bare `Valid`**.

The two naive fixes are both wrong: **hard-rejecting a stale slice breaks offline
verification** (the core thesis), and **silently passing it is the bug**. The correct
move is to make the verdict *name its own freshness bound*, and to put the *tolerance*
decision where it belongs — with the **relying party**, never the signer.

## Decisions

1. **D1 — Never a bare `Valid`.** Every positive verdict carries (a) `as_of`: the issuer
   KEL tip *sequence* the decision was made against, and (b) `freshness: Fresh | Unknown |
   Stale`. `is_valid()` alone is no longer sufficient for a trust decision.
2. **D2 — Freshness threshold is verifier policy, never signer-set.** A `FreshnessPolicy`
   (relying-party / org / app config) sets the window. **Default 24h.** Configurable:
   strict (require a witness/checkpoint head), N-hours, or lenient. The signer or bundle
   producer **cannot** set or widen it — this is what kills the "1-year bundle" anti-pattern
   (S5): the producer states a `max_valid_for_secs`, but the *verifier* caps trust.
3. **D3 — Offline + cannot-confirm → `Unknown`, not reject.** When the verifier has no
   fresher source than the supplied slice, freshness is `Unknown` and the verdict NAMES the
   oracle ("valid as of seq N; freshness unknown — no source fresher than the supplied
   slice"). A *strict* policy treats `Unknown` as deny; a *lenient* one accepts within the
   window. The verifier does not silently pass and does not hard-reject.
4. **D4 — `Stale` when provably past the window.** If the slice's bound (bundle timestamp,
   or an `as_of` older than the policy admits) exceeds the policy window, freshness is
   `Stale`. Default-deny for most policies; surfaced, never swallowed.
5. **D5 — High-assurance freshness is opt-in.** Real-time-ish freshness comes only from a
   witness head / checkpoint / transparency-log tip supplied to the verifier. Absent that,
   the strongest an offline verifier may assert is `Unknown` (bounded by the slice).
6. **D6 — Memoize the walk, never liveness.** A cache may record "this chain replays to
   this key-state at tip SAID X" (keyed on the tip), but MUST re-evaluate freshness every
   time — a tip-keyed cache cannot see a later revocation (REPORT D6).
7. **D7 (the gate) — Consumers branch on `freshness`, not `is_valid()`.** No
   verdict-consuming code — including the Epic 1 agent gate — ships before this verdict
   shape is frozen and adopted. Provide a single helper, `is_trusted(&FreshnessPolicy)`,
   that combines validity + freshness so callers cannot accidentally trust a bare `Valid`.

## Consequences

- `CommitVerdict::Valid` and `CredentialVerdict::Valid` gain `{ as_of, freshness }`
  (`CredentialVerdict` already has `as_of`; add `freshness`). A `Freshness` enum and a
  `FreshnessPolicy` (default 24h) are added to `auths-verifier`; policy is threaded into the
  verify entry points at the boundary (pure: the policy + any witness head are *inputs*, the
  verifier never reads a clock or the network itself).
- Proof obligation (the test that NAMES the oracle): offline + a pre-revoke slice →
  `Valid { freshness: Unknown }` (not bare `Valid`, not a silent pass, not a hard reject);
  a fresh slice within window → `Fresh`; a slice older than the policy window → `Stale`;
  a strict policy denies `Unknown`/`Stale`; a revoked-at-or-before-`as_of` credential →
  `Revoked` (unchanged — positional revocation within the held slice still fails closed).
- `is_valid()` callers across the workspace are audited and migrated to `is_trusted(policy)`
  where a trust decision is made (mechanical but load-bearing — this is why D7 gates E1).

## Alternatives considered

- **Hard-reject any stale slice** — breaks offline verification (the core thesis). Rejected.
- **Silently pass (status quo)** — the REPORT D2 bug. Rejected.
- **Signer/bundle-set TTL as the trust window** — lets the producer widen the trust window
  (the 1-year-bundle anti-pattern, S5). Rejected: freshness tolerance is the relying party's
  call, not the signer's.

> Provenance: records decision **D1 (2026-06-21)** from the go-to-market security ledger
> (`docs/plans/go_to_market/market_research_progress.md`, S5/S9), validated against
> `auths-verifier/src/credential.rs` (the existing `as_of`) and `commit_kel.rs`.
