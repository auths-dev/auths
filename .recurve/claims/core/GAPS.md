# core — claims & gaps

> **Reader:** a human deciding what this suite promises and what is still
> unproven. Your next action: read §1; every section below it is one claim
> with a stable anchor that a ledger entry `covers`.
>
> The prose here is for humans deciding; `gaps.yaml` is for the loop
> executing. They must never drift — `recurve coverage --gate` fails on a
> section without a ledger entry (an orphan is invisible to the loop and
> therefore never fixed).

## Conventions

- One section per claim, numbered with a stable anchor (`## 3. …` or
  `## T-TOKEN — …`). The anchor never changes once a ledger entry covers it.
- Every claim names its **observable** ("user can X and sees Y"), never its
  implementation ("uses library Z").
- Every claim states its **negative space**: what a wrong input does
  ("…and a tampered W is rejected with a distinct error").
- Sections map to the closed class enum via this table when the fit isn't
  obvious; new domains document their mapping here, never new classes.
- A closed claim's section is rewritten to describe the new reality and its
  heading gains "(CLOSED)". An adjudicated fork records "Adjudicated: …" in
  the section the decision touched.
- A retired claim leaves a tombstone: "Retired <date>: superseded by X."

<!-- First claim template — copy out of this comment, de-indent, number, and
     fill in. A real `## N.` heading becomes a coverage obligation:
     `recurve coverage --gate` fails until a ledger entry covers it. That is
     the point.

    ## 1. <claim title: the observable, not the implementation>

    What the user/consumer can observe today: <quote actual output, dated>.

    What this suite claims should happen: <the observable>.

    And the negative space: <what a wrong/tampered/absent input must do>.

    Smallest fix: <the minimal honest change that closes this>.
-->

