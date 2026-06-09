# auths-transparency

Append-only **transparency-log** primitives for Auths: RFC 6962 Merkle math,
C2SP-style checkpoints and witness cosignatures, tile storage, offline-bundle
verification, and the witness-diversity (independence) gate.

This is the **CT-checkpoint** half of Auths' two witness subsystems. (The other is
the KERI-`rct` key-event receipting layer in `auths-core::witness` /
`auths-keri::witness` — a separate protocol with separate keys. Don't conflate
them.)

## What's in it

- **`merkle`** — RFC 6962 leaf/node hashing, inclusion proofs
  (`verify_inclusion`), and **consistency proofs** (`verify_consistency`) between
  two tree sizes. Pure, no-I/O, WASM-safe.
- **`checkpoint`** — `Checkpoint` (origin/size/root/timestamp), its C2SP
  signed-note body, `SignedCheckpoint` (log signature + Ed25519 or ECDSA-P256),
  and `WitnessCosignature`.
- **`tile` / `store`** — C2SP static tile layout + `TileStore` (filesystem, and
  S3 under the `s3` feature) for serving a log.
- **`bundle` / `verify`** — `OfflineBundle` + `verify_bundle`: a synchronous,
  I/O-free verification of signature, inclusion, checkpoint, witness quorum, and
  namespace against a pinned `TrustRoot`. This is the embeddable verifier path.
- **`witness`** (native feature) — the C2SP `tlog-witness` cosignature protocol
  types (`CosignRequest`/`CosignResponse`, `cosignature_signed_message`).
- **`witness_policy`** — a typed, **fail-closed** loader for
  `data/witness_policy.json` (the runtime diversity policy). Rejects a missing
  file, unparseable JSON, unknown schema version, or a placeholder `pubkey_b64`.
- **Independence gate** — `verify_bundle`'s witness check layers
  `auths_keri::witness::independence::spans_distinct` (distinct
  organizations / jurisdictions / infrastructure) **on top of** the `n/2+1`
  count, evaluated over the *actual cosigning quorum*. A count-met-but-correlated
  quorum returns `WitnessStatus::NotIndependent`.

> The runtime `data/witness_policy.json` (who is trusted to cosign now) is
> deliberately separate from the governance `docs/governance/admission_policy.json`
> (who may *become* a witness). Neither may be weakened to make a verify pass.

## How it fits in the architecture

```
auths-sdk / auths-cli / auths-monitor / auths-checkpoint-cosigner
  |
  +-- auths-transparency (THIS CRATE)
        |
        +-- depends on: auths-verifier (types, Ed25519/ECDSA), auths-crypto,
        |               auths-keri (the shared independence model)
        +-- default-features=false → WASM-safe verify path (no ring/tokio)
        +-- "native" feature → tile stores, witness cosigner protocol, async
```

**Dependency direction**: depends downward on `auths-verifier`/`auths-crypto`/
`auths-keri`; nothing in those depends back on it. The verify path is designed for
minimal-dependency embedding (FFI/WASM), so it stays free of `ring`/`tokio` unless
`native` is enabled.

## Usage

```rust,ignore
use auths_transparency::{verify_bundle, OfflineBundle, TrustRoot};

// Offline, I/O-free verification against a pinned trust root.
let report = verify_bundle(&bundle, &trust_root, now);
assert!(report.is_valid());

// Consistency between two checkpoints of the same log.
use auths_transparency::verify_consistency;
verify_consistency(old_size, new_size, old_root, new_root, &proof)?;

// Load the runtime witness-diversity policy (fail-closed).
use auths_transparency::WitnessPolicy;
let policy = WitnessPolicy::load(std::path::Path::new("data/witness_policy.json"))?;
```

Consumers: `auths-sdk` (bundle verification workflows), `auths-monitor`
(cross-operator consistency), `auths-checkpoint-cosigner` (the cosigner), and the
verifier embeddings.
