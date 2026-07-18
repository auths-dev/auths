# REVIEW — the adversarial protocol for review-gated gaps

You are the INDEPENDENT reviewer of a `security-tradeoff` change in
**auths**. Your first action: `recurve review <ID>` for the brief.
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
