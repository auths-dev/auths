# auths-checkpoint-cosigner

A slim **C2SP `tlog-witness` checkpoint cosigner** — the CT transparency-log
witness. It does exactly four things: receive a checkpoint from the log operator,
verify it is a consistent extension of the last-seen checkpoint, sign a
timestamped **Ed25519 cosignature**, and persist the new last-seen checkpoint.

It is one of two independently-deployable witness binaries:

- **this crate** — the CT-checkpoint *cosigner* (log cosigning), and
- **`auths-witness`** — the KERI-`rct` *witness* (key-event receipting).

They are distinct subsystems with distinct protocols and keys. (The crate name
`auths-witness` is the rct binary; this CT cosigner is `auths-checkpoint-cosigner`.)

## Curve

CT witness **cosignatures are Ed25519-only — because that is what the verifier
accepts**: `auths_transparency::WitnessCosignature` is typed
`Ed25519PublicKey`/`Ed25519Signature`, and `verify_witnesses` checks cosignatures
with Ed25519. This matches the C2SP `signed-note` / `tlog-witness` cosignature
ecosystem (transparency.dev and Go sumdb witnesses are Ed25519). It is
intentional — not curve drift and not a departure to be "fixed" toward the
workspace P-256 default.

Scope matters: only the *cosignature* is Ed25519. The checkpoint's *log
signature* supports both Ed25519 and ECDSA-P256
(`SignatureAlgorithm::EcdsaP256`), so P-256 is still used in this layer — just not
for witness cosignatures. The cosigner's signing key is a PKCS#8 Ed25519 key.

## Minimal attack surface

By design the crate depends only on `auths-transparency` (the cosignature path +
`verify_consistency`) and `auths-verifier` (key types) — no platform keychain, no
`git2`, no `sqlite`, no CLI tail. Audit with
`cargo tree -p auths-checkpoint-cosigner -e normal`.

## How it fits in the architecture

```
auths-checkpoint-cosigner (THIS CRATE — lib + `auths-checkpoint-cosigner` binary)
  |
  +-- depends on: auths-transparency[native] (CosignRequest/Response,
  |               cosignature_signed_message, verify_consistency, SignedCheckpoint),
  |               auths-verifier (Ed25519 types)
  +-- watched by: auths-monitor (cross-operator equivocation detection)
```

**Dependency direction**: depends only on `auths-transparency` + `auths-verifier`.
Nothing depends back on it.

## Usage

```rust,ignore
use auths_checkpoint_cosigner::{WitnessConfig, WitnessState, build_router};

let state = WitnessState::new(&WitnessConfig {
    signing_key_hex: std::env::var("AUTHS_WITNESS_SIGNING_KEY")?, // PKCS#8 Ed25519
    witness_name: "witness-1".into(),
    checkpoint_path: "/data/last_checkpoint.json".into(),
    bind_addr: "0.0.0.0:8080".into(),
})?;
let app = build_router(state);
axum::serve(listener, app).await?;
```

**Fail-closed:** a missing `AUTHS_WITNESS_SIGNING_KEY` is a hard startup error;
consistency against the persisted last-seen checkpoint is verified before any
cosignature is issued. Deployment (distroless container / hardened systemd)
follows the kit in
[`docs/deployment/checkpoint-cosigner/`](../../docs/deployment/checkpoint-cosigner/README.md).
