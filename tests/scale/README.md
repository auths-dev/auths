# scale-bench — bulk agent-onboarding benchmark (issue #255 / PRD KL-9)

Measures the org-root KEL write path for N-agent onboarding and the read
paths that pay for it afterwards, so `main` and comparison branches can be
A/B-compared on both **deterministic invariants** and **timings**.

## Run

```bash
cd tests/scale
cargo run --release -- --agents 100  --label main-smoke --out runs/main-smoke.json
cargo run --release -- --agents 10000 --label main-10k  --out runs/main-10k.json
```

The registry (a fresh git-backed `.auths` store) is created under
`runs/<label>-<epoch>/registry` unless `--registry-dir` is given. Every run
requires a fresh dir — the tool refuses to reuse one.

## Action suite

1. bare org root inception (`initialize_registry_identity`, no device #0)
2. provision N delegated agents (`agents::add` — dip + root anchor ixns)
3. cold full root-KEL replay (`visit_events`) — the independent verifier's cost
4. chain-verify sample: `validate_delegation(dip, root_kel)`
5. sign sample: each sampled agent signs with its own key
6. individual revocations (`agents::revoke`), from the tail of the fleet
7. batch revocation (`agents::revoke_batch`) — one ixn carrying many seals
8. `fleet_metrics` — correctness gate: total / revoked / live must match

The run **fails** (nonzero exit) if any correctness assertion fails, so a
branch that speeds up onboarding by breaking verification cannot "win".

## What to compare across branches

| Metric | Kind | Why it matters |
| --- | --- | --- |
| `root_anchor_events_per_agent` | invariant | main ≈ 3 (dip anchor + role marker + attestation); a bulk path drives this toward 1/batch_size |
| `root_kel_events_final` | invariant | every future cold verifier replays this |
| `registry_git_commits` | invariant | main ≈ 3–4 commits/agent; bulk ≈ 1/batch |
| `provision_agents_per_sec` | timing | the issue #255 events/sec number |
| `cold_root_kel_replay_ms` | timing | read-path cost as a function of KEL length |
| `chain_verify` p50/p95 | timing | per-agent verification against the grown KEL |
| `fleet_total/revoked/live` | correctness | must equal N / R+B / N−R−B on every branch |

## Caveats (recorded in the JSON)

- Built with `auths-core/test-utils`, which selects the weak Argon2 test
  parameters — KDF cost is deliberately excluded. Identical on all branches,
  so A/B deltas are unaffected; absolute sign latencies are not
  production-representative.
- Timings use `Instant` (macOS `CLOCK_UPTIME_RAW`), which does not advance
  across system sleep; run with the lid open for clean wall-clock numbers.
- Single process, single writer — this measures the KERI-ordering serialization
  ceiling from issue #255, not concurrent-writer behavior.
