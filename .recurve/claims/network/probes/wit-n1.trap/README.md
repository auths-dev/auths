# wit-n1 trap — `up` claimed success on an occupied port

A probe that has never been seen RED is not yet evidence. This fixture feeds the
WIT-N1 probe a known-bad captured standup (via `TRAP_FIXTURE`) that it MUST
reject.

- `occupied-port/` — a captured `witness up` run that **printed a health URL and
  exited 0 while the port was already taken** (`up.out` + `up.code=0`). That is
  the partial-state lie WIT-N1 forbids: `up` exiting 0 is not success; a fresh
  node answering is. On an occupied port the only acceptable behavior is a
  single actionable line and a non-zero exit, standing nothing up.

The probe consumes the fixture by reading `up.out`/`up.code` in place of running
`up` live, then applies the same rule: a zero exit on an occupied port is RED.

If this ever went GREEN, WIT-N1 would be blessing an `up` that reports success
without a healthy node — the exact failure the headline standup claim exists to
prevent.
