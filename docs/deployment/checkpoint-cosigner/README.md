# auths-checkpoint-cosigner deployment kit

A slim **C2SP tlog-witness checkpoint cosigner** (the CT transparency-log
witness). It receives checkpoints from the log operator, verifies consistency
against the last-seen checkpoint (RFC 6962 `verify_consistency`), and returns a
timestamped Ed25519 **cosignature**. Nothing else.

> This is the CT-checkpoint cosigner — distinct from the KERI-`rct` witness
> (`auths-witness`, see `docs/deployment/witness/`). The two are separate
> subsystems with separate keys and protocols.

## Minimal attack surface

By design the crate depends only on `auths-transparency` + `auths-verifier` — no
platform keychain, no `git2`, no `sqlite`, no CLI tail. Audit with
`cargo tree -p auths-checkpoint-cosigner -e normal` before each release.

## Curve

CT witness **cosignatures are Ed25519-only — because that is what the verifier
accepts** (`auths_transparency::WitnessCosignature` is typed Ed25519, and
`verify_witnesses` checks cosignatures with Ed25519), matching the C2SP
`signed-note` / `tlog-witness` cosignature ecosystem. Intentional — not curve
drift, not a departure to be "fixed" toward the workspace P-256 default. Note:
only the cosignature is Ed25519; the checkpoint's *log signature* still supports
ECDSA-P256. The signing key is a PKCS#8 Ed25519 key.

## Configuration / secrets

| Variable                        | Purpose                                                  | Notes |
|---------------------------------|----------------------------------------------------------|-------|
| `AUTHS_WITNESS_SIGNING_KEY`     | Hex-encoded PKCS#8 Ed25519 signing key (**required**).   | Injected as a secret; never baked into an image. Stable across restarts → stable cosigner identity. |
| `AUTHS_WITNESS_NAME`            | Cosigner name used in cosignature lines.                 | Default `auths-witness`. |
| `AUTHS_WITNESS_CHECKPOINT_PATH` | Path persisting the last-seen checkpoint.                | Mount on a writable volume / `StateDirectory`. |
| `AUTHS_WITNESS_BIND_ADDR`       | Listen address (plaintext; TLS at the proxy).            | Default `0.0.0.0:8080`. |

**Fail-closed posture:** a missing `AUTHS_WITNESS_SIGNING_KEY` is a hard startup
error. Consistency verification against the persisted last-seen checkpoint runs
before any cosignature is issued, so the cosigner never signs a checkpoint that
is not a consistent extension of what it last saw.

## Run it

```bash
export AUTHS_WITNESS_SIGNING_KEY=$(hex-encoded PKCS#8 Ed25519 key)
auths-checkpoint-cosigner   # or set the env vars above
```

**Container** — reuse the W.1.3 hardened pattern (`docs/deployment/witness/Dockerfile`):
distroless-static, non-root, read-only rootfs, key injected via secret/env, a
writable `/data` volume for the persisted checkpoint, TLS terminated at a reverse
proxy. **systemd** — reuse `docs/deployment/witness/auths-witness.service` with
`ExecStart=/usr/local/bin/auths-checkpoint-cosigner` and the
`AUTHS_WITNESS_SIGNING_KEY` injected via `LoadCredentialEncrypted=`/`Environment`.
