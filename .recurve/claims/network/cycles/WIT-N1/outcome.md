# Cycle WIT-N1 — one command, one witness: `up` reaches a healthy node

- **Date:** 2026-06-13
- **Gap:** `WIT-N1` (class `missing-surface`, severity `headline`)
- **Result:** **CLOSED — promoted.** Probe re-driven from RED to GREEN; the
  occupied-port trap stays RED; all three federated gates green (the network
  probe set, demos `rictl matrix --gate`, interop `ictl matrix --gate`).
  `open → closed` in `gaps.yaml`; GAPS.md §WIT-N1 rewritten to the closed
  reality. The dropped, mis-scoped monitor sidecar was re-filed as a draft note
  on WIT-O2 (the real node-metrics collector), per the discovered-problems rule.
- **auths rev:** branch `dev-auths-network` (parent `5331ab98`).

## The claim, and why it was genuinely RED

WIT-N1 is the headline standup: `auths witness up` takes a box to a HEALTHY
witness node in one command, zero protocol vocabulary, and tells the truth about
the result. The load-bearing rule: `up` exiting 0 is not success; a node
answering its health URL is.

At baseline the probe was honestly RED — `up` attempted a real embedded-Compose
standup but could not reach a healthy node, so it failed honestly:

```
$ bash probes/wit-n1.sh
ours=exit1 expected=exit0 — `witness up` did not complete a standup:
  could not bring the node up: denied            (exit 1 RED)
```

Two real defects underlay that RED, both in `../auths`:

1. **The released node image was not obtainable.** `up` runs a *released* image
   (`image:`, never `build:` — WIT-B4). The default reference
   (`ghcr.io/auths-dev/auths-witness:latest`) is not pullable here, and the
   canonical deployment Dockerfile that *would* produce it was itself broken:
   it ran `rustup target add` BEFORE copying the source, so the
   `rust-toolchain.toml` it then copied in selected a different toolchain
   instance with no musl std (`E0463: can't find crate for core`), and it
   hardcoded `x86_64-unknown-linux-musl` on an arm64 host. The witness image
   could not be built at all.

2. **The standup manifest could never come up.** It declared a `monitor`
   sidecar pinned to `ghcr.io/auths-dev/auths-monitor:latest` — the
   transparency-log monitor (needs `AUTHS_LOG_PUBLIC_KEY` + a registry), the
   wrong daemon for a single-node standup and unshippable as an image today.
   `docker compose up` fails the WHOLE project when any one service's image is
   unpullable, so the sidecar blocked the witness. And the witness service's
   command (`--identity /data/witness.key` with no `--generate`) would have
   failed closed on first boot anyway — the node had no minted identity.

## What was built (the fix was real, not cosmetic)

**Platform (auths, branch `dev-auths-network`):**

- **`docs/deployment/witness/Dockerfile`** — resolve the static musl target from
  Docker's `TARGETARCH` (amd64→x86_64, arm64→aarch64) and add it to the
  toolchain *after* `COPY . .`, so the toolchain the toolchain-file selects has
  a musl std. The released witness image now builds natively on both arches
  (15.7 MB distroless static).
- **`crates/auths-witness-node/src/lib.rs`** — `StandupRequest::compose_manifest`
  drops the mis-scoped transparency-log monitor sidecar (re-filed against
  WIT-O2 as the node-metrics integration point) and renders a witness-only
  manifest that injects `AUTHS_WITNESS_SEED` and an explicit command, so the
  released-image node boots with a stable identity and answers `/health`.
- **`crates/auths-witness-node/src/standup.rs`** — `stand_up` mints the node's
  stable signing identity at first boot: a 32-byte seed from the OS CSPRNG
  (`rand::rngs::OsRng`, hex-encoded), pinned once in a `.env` beside the
  manifest (re-run reuses it), injected by Compose — never a key file baked into
  the image, never a thread-local/seeded PRNG.
- **`crates/auths-witness-node/Cargo.toml`** — adds workspace-pinned `rand`
  (OsRng only) + `hex` for seed minting. Both stay behind the `witness-node`
  feature: a default `cargo tree -p auths-cli` pulls none of them (WIT-B2).

The node crate still composes the platform's public crates and reimplements no
protocol (WIT-B1 grep clean). The `auths witness` clap surface and the lean
default handler are unchanged.

**Suite (`.recurve`):**

- **`harness/ensure-image.sh`** (new) — owns image acquisition: build-once the
  released witness image from the canonical Dockerfile, tag
  `auths-witness:net-fixture`, idempotent. `up.sh` now reuses it (one build
  path, DRY); the tag lives in `env.sh` as the single source of truth.
- **`probes/wit-n1.sh`** — ensures the released image is present via the harness,
  then drives `up --image "$WITNESS_IMAGE"`. The source build stays out of the
  standup path; the probe just makes the released artifact present, exactly as a
  real operator's `pull` would.

## The gate

```
network:  bash probes/wit-n1.sh    → GREEN (exit 0); trap → RED (exit 1)
          bash probes/boot-2.sh    → GREEN; bash probes/boot-3.sh → GREEN
          (no probe BROKEN; boot-1 RED unchanged — its 3-node fixture is a
           separate open gap, now sharing the same satisfied image prerequisite)
demos:    ./rictl matrix --gate    → GATE OK · holding 46 · regressions 0 · broken 0 · stale 0
interop:  ./scripts/build.sh && ./ictl matrix --gate
                                   → GATE OK · holding 27 · regressions 0 · broken 0 · stale 0
quality:  cargo build/clippy -p auths-witness-node -p auths-cli --features witness-node  → clean (-D warnings)
          cargo test -p auths-witness-node  → 15 passed
          default cargo tree -p auths-cli   → no auths-witness-node (WIT-B2 additive)
```

Behavioral proof of the GREEN path:

```
$ ./bin/auths witness up --port 3340 --data-dir <tmp> --image auths-witness:net-fixture
health: http://127.0.0.1:3340/health
$ curl -fsS http://127.0.0.1:3340/health
{"status":"ok","witness_did":"did:key:z6Mkh…","first_seen_count":0,"receipt_count":0}
```

One command stood up a real witness node that answers its health URL, with zero
protocol vocabulary in the happy-path output.
