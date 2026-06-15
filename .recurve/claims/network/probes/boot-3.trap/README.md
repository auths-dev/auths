# boot-3 trap — a baseline that swallowed a BROKEN probe

A probe that has never been seen RED is not yet evidence. This fixture feeds the
BOOT-3 meta-probe a known-bad probe set (via `TRAP_FIXTURE`) that it MUST
reject.

- `broken-sibling/cannot-measure.sh` — a sibling probe that exits **2
  (BROKEN)**: it announces it could not measure (missing oracle/fixture/build)
  and returns the undecidable verdict. This is exactly the verdict BOOT-3 exists
  to forbid in a clean baseline.

BOOT-3 consumes the fixture by running every `*.sh` under `$TRAP_FIXTURE`
instead of its live sibling set, then applies the same decision check: a probe
that did not exit 0 or 1 is a BROKEN baseline. So it exits **RED** here.

If this ever went GREEN, BOOT-3 would be certifying a baseline as clean while a
sibling silently could-not-measure — the burndown would start on a lie, the one
failure this claim exists to prevent.
