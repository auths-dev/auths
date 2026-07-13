# Product PRD — resolved decisions

> Adjudications for the section-13 open decisions, recorded ahead of baseline.
> When `/recurve-work` claimifies the PRD it generates `.recurve/ADJUDICATE.md`;
> fold each RESOLVED item below into that file (or run
> `recurve adjudicate <gap_id> --decision "…"` once the gap is ledgered) so the
> decision is encoded into the probe. Items still OPEN must be answered before
> their claims baseline.

## RESOLVED

### D4 — Postgres registry target (FT-8) → single-org self-host
**2026-07-04.** One Postgres instance serves one organization. No multi-tenant
control plane, no cross-tenant isolation walls, no shared "trust Auths the
company" infrastructure — self-host preserves the no-central-authority promise
and drops the SaaS schema complexity (tenancy, per-customer billing, data-wall
enforcement).

Trust and availability *beyond* the org boundary come from **opting into
witnesses**, not from shared infrastructure. The opt-in exposes an independence
ladder, because a witness's value scales with its independence:

- **(a) own witnesses** — extra copies across the org's own infra → availability
  only (they can't catch a stolen-key fork; they're all you).
- **(b) shared witness commons** — unaffiliated operators → a genuinely
  independent second view. *This is the mechanism that makes CR-4 / #349
  duplicity detection real.*
- **(c) mutual org-to-org witnessing** — A witnesses B and vice versa →
  federation.

Encoded as: FT-8 sharpened to single-org self-host; new FT-13 for the witness
opt-in ladder. Does NOT resolve D1 (duplicity default) — see OPEN.

## OPEN (answer before these claims baseline)

- ~~**D1 — Duplicity default (CR-4)**~~ **RESOLVED 2026-07-04: fail-closed by
  default.** Pre-launch, no users → no `--strict`-first dance; `verify` refuses a
  diverging KEL outright. (See [[auths-prelaunch-no-backcompat]].)
- **D3 — PQ scheme order (PQ-2/3):** ML-DSA-65 first, or SLH-DSA for root? Lean:
  ML-DSA-65. Needs confirmation — mints permanent CESR derivation codes.

## RESOLVED by default (building on stated answer, no confirmation needed)

- **D2 — Per-signature re-auth (KL-2):** process-bound capability token, 60s TTL.
- **D5 — Pairwise identifiers (FT-2):** opt-in at issuance (non-breaking).
- **D6 — Verifiable map (FT-1):** self-host-first, witness-commons later.
- **D7 — Recovery custody (KL-6):** guardians may be other devices AND other
  people.
