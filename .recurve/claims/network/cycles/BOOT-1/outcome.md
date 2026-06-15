# Cycle BOOT-1 — the harness exists: 3-witness local fixture boots, oracles pinned

- **Date:** 2026-06-13
- **Gap:** `BOOT-1` (class `staging`, severity `feature`)
- **Result:** **CLOSED — promoted.** The probe is GREEN against a live 3-node
  fixture, the cloned-identity trap stays RED, and both required federated gates
  (demos, interop) are GREEN. Status promoted `open` → `closed`; the probe stays
  as the regression guard (it re-ups the fixture when it runs).
- **auths rev:** branch `dev-auths-network` — untouched this cycle (the harness
  lives entirely in the suite). `.dockerignore` was the only earlier platform
  change and remains in place as build hygiene; no Rust source touched.

## What closed it

The prior cycle built the whole harness (env, Compose fixture, kill-node lever,
versions.lock, probe, trap) and baselined RED, but could not drive GREEN because
the local Docker engine had been corrupted by a build-context disk overrun
(before `auths/.dockerignore` existed). That environment fault has since
recovered: Docker is HEALTHY, the witness image `auths-witness:net-fixture` is
built and cached, and `auths/.dockerignore` keeps the build context source-only.

With a healthy engine, `harness/up.sh` booted the three nodes — but the probe
surfaced a REAL (non-Docker) bug in the fixture that the RED baseline had never
been able to reach: the kill-node lever's **recovery** half.

### The bug (and the minimal fix — no probe weakened)

- The compose fixture mounted the receipts DB on a bare `tmpfs: - /data`. That
  tmpfs is root-owned `0755`. The runtime image is distroless `nonroot`
  (uid/gid 65532).
- On the **first** `up`, the node could write `/data/receipts.db` — Docker seeds
  the image's declared `VOLUME ["/data"]` permissions onto the tmpfs at container
  create. So bring-up looked healthy.
- After a `docker compose stop` + `start` (which is exactly what
  `kill-node.sh N stop` then `kill-node.sh N start` do), the tmpfs re-mounts
  fresh as root-owned, the `nonroot` uid can no longer create the DB file, and
  the node exits 1 with `witness state: storage error: failed to open database:
  unable to open database file (code 14)` — `SQLITE_CANTOPEN`.
- The probe caught this at its final assertion: `node 1 did not recover after
  kill-node.sh 1 start`. The standup was fine; the FR-13 "restart recovers"
  behavior under test was silently broken.
- **Fix:** pin the tmpfs to the node's user —
  `tmpfs: - /data:uid=65532,gid=65532,mode=0700`. `/data` is now writable on
  every (re)start, so a stopped node truly recovers. Verified in isolation
  (run → stop → start, container stays Up) and end-to-end via the probe. The
  probe assertions were not relaxed.

## Verification (GREEN, dated 2026-06-13)

```
$ bash harness/up.sh
✓ wit1 healthy on :3331 — identity did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S
✓ wit2 healthy on :3332 — identity did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK
✓ wit3 healthy on :3333 — identity did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5

$ bash probes/boot-1.sh
harness GREEN: 3 distinct witness nodes healthy (did:key:z6MktUL… z6MkqGC… z6Mkg49…),
kill-node lever proven, oracle keripy=1.3.4 pinned and installed   (exit 0)

$ TRAP_FIXTURE=…/boot-1.trap/cloned-identity bash probes/boot-1.sh
ours=1-distinct oracle=3-distinct — roster is not 3 independent identities: …   (exit 1)
```

Three nodes, three DISTINCT seed-derived identities; killing node 1 leaves 2-of-3
healthy and a restart recovers; the trap (three clones of one operator) is
rejected RED.

## Gate status at close

- BOOT-1 probe → **GREEN** (exit 0); cloned-identity trap → **RED** (exit 1).
- Demos `rictl matrix --gate` → **exit 0, GATE OK** (46 holding, 0 regressions).
- Interop `ictl matrix --gate` → **exit 0, GATE OK** (27 holding, 0 regressions).
- AUTHS untouched this cycle — the gates are unaffected by definition.

## Teardown

The 3-node fixture was torn down (`harness/down.sh`) after promotion; the probe
re-ups it on demand when it runs as a regression guard. The image stays cached.
The operator's other live containers (nested_learning-*, dataing-*) were never
touched — only the `auths-witness-net` project's wit1/wit2/wit3.
