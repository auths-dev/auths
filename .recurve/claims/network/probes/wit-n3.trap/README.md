# wit-n3 trap — a stale key-state notice that must stay RED

A probe that has never been seen RED is not yet evidence. This fixture feeds the
WIT-N3 probe a known-bad **stale** key-state notice (via `TRAP_FIXTURE`) that the
node's freshness gate MUST reject.

- `stale-ksn/ksn.json` — a genuine, KERI-conformant key-state notice the keripy
  oracle published, at **sequence 0**.
- `stale-ksn/last_seen` — `1`: the verifier already trusts sequence 1 (it holds a
  newer receipt). Ingesting the seq-0 notice would rewind below that — a stale or
  replayed view of the identity.

The probe runs `auths key-state --ingest stale-ksn/ksn.json --reject-stale-below 1`
and asserts a non-zero exit with a distinct "stale" reason. A zero exit here means
the node accepted a rewound key-state as fresh — exactly the silent-downgrade the
WIT-N3 adversarial twin forbids ("a stale key-state notice is detected as stale by
a verifier holding a newer receipt"). If this ever goes GREEN, a thin client could
be handed an old key-state and told it is current — the freshness column the
directory rests on stops being trustworthy.
