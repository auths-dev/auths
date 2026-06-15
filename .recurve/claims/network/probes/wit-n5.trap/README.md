# wit-n5 trap — the operator was shown protocol jargon

A probe that has never been seen RED is not yet evidence. This fixture feeds the
WIT-N5 probe a known-bad captured operator happy-path transcript (via
`TRAP_FIXTURE`) that it MUST reject.

- `jargon-leak/happy-path.out` — a captured `witness up|status|register|logs|down`
  transcript where one line leaked the trust kernel's vocabulary: it names a
  **KEL**, a signing **threshold**, a **verkey**, and a **prefix** — exactly the
  words §US-001 and §6 say an operator must never see. Most lines are clean; the
  leak hides among them, the way a real regression would.

The probe consumes the fixture by scanning `happy-path.out` against the
product's own canonical `PROTOCOL_VOCABULARY` denylist (whole-word,
case-insensitive) in place of running the live happy path, and applies the same
rule: any denylisted term standing as a whole word is RED.

If this ever went GREEN, WIT-N5 would be blessing a happy path that showed an
operator the protocol's vocabulary — the exact friction the vocabulary-invisible
rule exists to prevent. The scanner being anchored to the product's own denylist
(not a private copy) is what keeps the trap honest: it forbids precisely the
words the surface forbids.
