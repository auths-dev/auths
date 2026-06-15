# REVIEW — the adversarial protocol for review-gated gaps

You are the INDEPENDENT reviewer of a `security-tradeoff` change in
**auths-network**. Your first action: `recurve review <ID>` for the brief.
Your job is to BREAK the change, not to confirm it. Your stop condition: a
verdict — "broken, here's how" or "could not break it, and here is everything
I tried."

## Why this class is different

A green gate proves the INTENDED case works. A loosened check can pass every
existing probe and still accept something it must not — the hole is in what
no probe tests yet. That is why a green `recurve matrix --gate` is necessary
but NOT sufficient here, and why unattended cycles never sculpt these gaps.

## The protocol

1. **Independence.** The reviewer must not be the implementer — different
   agent, different session, no shared context beyond the brief.
2. **Enumerate the delta.** List everything the new check accepts that the
   old one rejected. For each: is that acceptance always legitimate?
3. **Attack beyond the floor.** The suite's existing adversarial probes are a
   floor, not a ceiling — invent NEW attacks: replay, reorder, forge,
   substitute identity, downgrade, truncate.
4. **Attack the corroboration.** If the change relies on a witness, log,
   receipt, or any second source of truth — attack THAT source's trust
   assumption, not just the happy path.
5. **Re-read the original refusal.** Whatever made this fail-closed named a
   threat. Confirm the loosening doesn't re-open exactly that.

## Promotion — only if ALL hold

- The reviewer could not break it, and said so explicitly.
- `recurve matrix --gate` is green fleet-wide.
- **Every attack tried became a new probe** (RED against the attack, kept as
  a trap or guard forever) — the next loosening must face everything this one
  faced.
- The decision is recorded in three synchronized places via
  `recurve adjudicate <ID>`: the ledger's `smallest_fix` (DECIDED <date>),
  the prose (Adjudicated:), and the probe itself.

Otherwise: leave it open and record the finding. An unresolved review is a
result, not a failure.

---

## Murmur — the §10 external-audit RELEASE GATE (hard real-user-release blocker)

This is **not** a probe and never will be: it is a **human gate**, recorded here
because no green `recurve matrix --gate` can ever satisfy it. It blocks putting
Murmur in front of a **single real user who believes it is private** — the demo
on internal/demo devices (§0) is allowed without it; a non-demo user is not.

> **The KERI↔Signal join and the multi-device key lifecycle must pass an
> EXTERNAL cryptographic review before any non-demo user.** (PRD §10.)

Why a green ENC gate is necessary but **not sufficient**: ENC-1..6 are written by
the same people who wrote the wiring, and consumer messaging is exactly where
"we tested it ourselves" has burned people. The review must cover not just the
**static** join (the AID key signs a *distinct* Signal identity key; no
signing↔DH reuse — ENC-1) but the **combinatorial multi-device state machine**
where the subtle break hides (ENC-7): N delegated devices, each with its own
Signal identity key and prekey bundles, and a continuity story that must hold
across **rotation AND delegation simultaneously**.

- The ledger gap that carries this is **ENC-7** (`class: security-tradeoff`,
  REVIEW-GATED). Its probe asserts only the falsifiable FLOOR (the lifecycle is
  *specified* at `cycles/enc-7/key-lifecycle.md`) plus a recorded external-audit
  verdict at `cycles/enc-7/external-audit.md`. **A green gate never promotes it.**
- Until an external auditor records `AUDIT PASSED` there, the build stays a
  **proof on demo/internal devices only** — never marketed as the product, never
  put in front of a real user who is told the channel is private.
- The dependent correctness root is **WIT-1** (forked/stale KEL rejected by the
  witness threshold) and the on-rotation re-key/prekey-reverify of **MSG-2**; the
  external review should treat those as in-scope, since the join's safety rests
  on them.

The cost of rounding up here isn't a weak demo — it's someone trusting a channel
with a hole in the part we built.
