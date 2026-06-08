# auths-monitor

A transparency-log **monitor**: it cross-reads operators' checkpoints, verifies
they are consistent (an append-only log never regresses or forks), and — when two
pinned operators present the same tree size with different roots — emits a
portable, **third-party-verifiable equivocation evidence** artifact.

This is the watcher for the **CT-checkpoint** witness commons. It is intentionally
*non-authoritative*: the evidence it emits stands on the operators' own
signatures, so anyone (an auditor, a second monitor) can confirm equivocation
without trusting this monitor.

## What's in it

- **Single-registry consistency** (`lib.rs`) — fetches the latest checkpoint and
  verifies it against the last-seen one using the shipped
  `auths_transparency::verify_consistency` (RFC 6962). The math is *reused*, not
  re-implemented.
- **`evidence`** —
  - `checkpoint_transition` classifies a transition **positionally** (by tree
    size + root, never by wall-clock timestamp): `Continue` /
    `SizeRegression` / `Equivocation`.
  - `detect_cross_operator_equivocation` finds two operators at the same size with
    different roots — a fork no single witness sees alone.
  - `EquivocationEvidence` (a versioned artifact carrying both operators' signed
    checkpoints) + `verify_equivocation_evidence(evidence, pinned_operators)` —
    **zero trust in the monitor**: the verdict is the two cosignatures over the
    conflicting checkpoint note bodies; the monitor's note is provenance only.
- **`gossip`** — operator-to-operator gossip (`GossipState::ingest`): authenticates
  a gossiper by its pinned cosignature, enforces **append-only** state (rejects a
  size rollback or a rewritten root), and emits the non-repudiable evidence on
  conflict. `gossip_detection_strength` gates the upgrade from "sampled" to
  "non-repudiable".

Scope is operator-to-operator; client-echo / partition-resistant gossip is a
documented limitation (tracked upstream). Cross-operator coverage is tested
against fixtures — a live multi-operator log / Rekor target is a documented
upstream dependency.

## How it fits in the architecture

```
auths-monitor (THIS CRATE — lib + `auths-monitor` binary)
  |
  +-- depends on: auths-transparency (verify_consistency, checkpoint types),
  |               auths-verifier (Ed25519 types), reqwest (fetch)
  +-- NO keychain / git2 / sqlite — slim by design
```

**Dependency direction**: depends only on `auths-transparency` + `auths-verifier`
(plus `reqwest`/`tokio` for fetching). Nothing depends back on it.

## Usage

```rust,ignore
use auths_monitor::{detect_cross_operator_equivocation, verify_equivocation_evidence};

if let Some(evidence) = detect_cross_operator_equivocation(&observations) {
    // Independently verifiable by anyone holding the pinned operator keys.
    assert!(verify_equivocation_evidence(&evidence, &pinned_operator_keys));
}
```

Run the monitor binary with `AUTHS_REGISTRY_URL` (+ related env). Deployment
(container/systemd) reuses the hardened pattern in
[`docs/deployment/witness/`](../../docs/deployment/witness/README.md).
