# boot-1 trap — counterexamples the probe must turn RED

A probe that has never been seen RED is not yet evidence. These fixtures feed
the boot-1 probe a known-bad node roster (via `TRAP_FIXTURE`) that it MUST
reject.

- `cloned-identity/` — three node `/health` responses that all advertise the
  SAME `witness_did`. Three nodes are not a witness network if they are one
  operator's three clones; the diversity the threshold story rests on is
  absent. The probe asserts three DISTINCT identities, so it exits RED here.
  If this ever goes GREEN, the harness would be blessing an oligopoly disguised
  as a network — the exact failure the suite exists to prevent.
