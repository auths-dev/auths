# auths-witness

A slim, hardened **KERI-`rct` witness server** binary. It does exactly one job:
receive a key event → validate it → sign an `rct` receipt → store it. It runs the
**same** `auths-core` witness library as `auths witness start` (no forked logic),
packaged as a standalone binary so an internet-facing deployment carries a minimal
attack surface.

It is one of two independently-deployable witness binaries:

- **this crate** — the KERI-`rct` *witness* (key-event receipting), and
- **`auths-checkpoint-cosigner`** — the CT-checkpoint *cosigner* (log cosigning).

They are distinct subsystems with distinct protocols and keys. (Note: the crate
name `auths-witness` is the rct binary; the CT cosigner is the separate
`auths-checkpoint-cosigner`.)

## Curve

The rct witness defaults to **P-256** (the workspace default), with Ed25519 also
supported — the signing key is curve-tagged in-band. (Contrast the CT cosigner,
which is Ed25519-only per the C2SP spec.)

## Minimal attack surface

The binary enables only `auths-core`'s `witness-server` feature. Because
`auths-core` declares `default = []`, the dependency tree excludes the platform
keychains (Secret Service / Windows / PKCS#11 / Secure Enclave), the `auths` CLI
subcommands, ssh-agent, and the pairing crates. Audit with
`cargo tree -p auths-witness -e normal`.

## What it adds over the shared library

The witness *logic* is all `auths-core`. This crate adds:

- **The binary entrypoint** — `--identity` (stable W.1.1 keystore) / `--generate`
  / `--curve` / `--bind` / `--persist`, plus `AUTHS_WITNESS_SEED` for container
  key injection. A deployed witness **requires** a stable, pinnable identity
  (fail-closed; no ephemeral key behind a `--identity` path).
- **Application-level DoS limits** (`hardened_witness_app`) — the endpoint ingests
  untrusted POST bodies, so OS sandboxing alone is not enough: a 64 KiB body cap
  (413, no unbounded buffering), a global concurrency cap, and a per-request
  timeout (Slowloris). Per-IP rate limiting terminates at the reverse proxy.

## How it fits in the architecture

```
auths-witness (THIS CRATE — lib `hardened_witness_app` + `auths-witness` binary)
  |
  +-- depends on: auths-core[witness-server] (router, handlers, receipt signing,
  |               duplicity detection, the W.1.1 stable-identity loader),
  |               auths-crypto (CurveType / TypedSignerKey), axum/tower(-http)
  +-- watched by: auths-monitor (cross-operator equivocation, CT side)
```

**Dependency direction**: depends only on `auths-core` (witness-server slice) +
`auths-crypto` + the HTTP stack. Nothing depends back on it.

## Usage

```bash
# First start: generate + persist a stable identity.
auths-witness --identity ./witness.key --generate \
  --bind 127.0.0.1:3333 --persist ./receipts.db

# Restarts load the same key → identical /health AID (pinnable in b[]).
auths-witness --identity ./witness.key --bind 127.0.0.1:3333 --persist ./receipts.db
```

```rust,ignore
// Embedding the hardened app directly.
use auths_witness::hardened_witness_app;
let app = hardened_witness_app(state); // witness_router + body/concurrency/timeout layers
axum::serve(listener, app).await?;
```

TLS terminates at a reverse proxy. Deployment (distroless container / hardened
systemd, `systemd-analyze security` target < 3.0) follows the kit in
[`docs/deployment/witness/`](../../docs/deployment/witness/README.md).
