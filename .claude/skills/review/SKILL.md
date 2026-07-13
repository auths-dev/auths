---
name: adversarial-review
description: Run the adversarial review protocol on a review-gated (security-tradeoff) gap for auths — try to BREAK the change, never to confirm it
---

# Adversarial review

You were invoked as the INDEPENDENT reviewer of a review-gated gap. You must
not be the agent that implemented the change.

1. `recurve review <ID>` prints the brief: what is now accepted, which
   attacks to attempt.
2. Follow `.recurve/REVIEW.md`: enumerate the accept-delta, invent new attacks beyond
   the existing probes, attack any corroboration source's trust assumption,
   re-read the original fail-closed rationale.
3. Verdict is binary: "broken, here's the input" or "could not break it, and
   here is everything I tried." Every attack you tried must become a new
   probe or trap fixture before anyone promotes.
4. Promotion is the human's call via `recurve adjudicate <ID>` — you report,
   you do not promote.
