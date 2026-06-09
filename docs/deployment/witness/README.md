# auths-witness deployment kit

A slim, hardened KERI **rct-witness** server. It does exactly four things:
receive a key event → validate it → sign a receipt → store it. Nothing else.

It runs the **same** `auths-core` witness library as `auths witness start` (no
forked logic), packaged as a standalone `auths-witness` binary so an
internet-facing deployment carries a minimal attack surface.

> This is the KERI-`rct` witness (key-event receipting). The CT-checkpoint
> *cosigner* is a separate component.

## What it does today

- Serves `POST /witness/{prefix}/event`, `GET /witness/{prefix}/head`,
  `GET /witness/{prefix}/said/{seq}`, `GET /witness/{prefix}/receipt/{said}`,
  and `GET /health`.
- Advertises a **stable AID** at `/health` derived from a persisted signing key,
  so it can be pinned in identities' `b[]`. The AID survives restarts.
- Verifies inbound inception self-signatures by the in-band curve tag (P-256 /
  Ed25519), never by byte length.

It does **not** terminate TLS (use a reverse proxy), do per-IP rate limiting (see
below), gossip with other witnesses, or run the CT-checkpoint cosigner.

## Minimal attack surface

`auths-core` declares `default = []`, and this binary enables only
`features = ["witness-server"]`. The dependency tree therefore excludes:

- the platform keychains (Secret Service / Windows Credential Manager / PKCS#11 /
  Secure Enclave) — all behind `keychain-*` features that stay off;
- the `auths` CLI subcommands, ssh-agent, and the pairing daemon/protocol crates.

Audit with `cargo tree -p auths-witness -e normal` before each release; the kit
intentionally has no `secret-service`, `windows`, `cryptoki`, or
`auths-pairing-*` nodes.

## Identity / secrets

| Variable / flag        | Purpose                                                        | Notes |
|------------------------|----------------------------------------------------------------|-------|
| `--identity <path>`    | Persisted curve-tagged signing keystore (`0600`).              | The AID derives from this key. |
| `--generate`           | Create the keystore at `--identity` if absent.                 | Without it, a missing keystore **fails closed** (no fresh key). |
| `--curve <p256\|ed25519>` | Curve for a newly generated identity.                       | Default `p256`. |
| `--persist <path>`     | SQLite receipts database.                                      | Mount on a writable volume / `StateDirectory`. |
| `--bind <addr>`        | Listen address (plaintext; TLS at the proxy).                  | Default `127.0.0.1:3333`. |
| `AUTHS_WITNESS_SEED`   | Hex 32-byte signing seed injected out-of-band (containers).    | Takes precedence over `--identity`; never bake into an image. |

**Fail-closed posture:** a missing keystore (without `--generate`), a corrupt
keystore, or an invalid injected seed is a hard startup error — the witness never
silently mints a fresh, unpinnable identity. The signing key is injected at
runtime (secret/volume or env), never baked into the image.

> Key backend is a file/env seed, not the interactive platform keychain (a server
> has no login session). A KMS/HSM backend is tracked as future work.

## Application-level DoS limits

The endpoint ingests untrusted POST bodies, so OS sandboxing alone is not enough.
The binary applies, in code (`hardened_witness_app`):

- **Body-size cap** — `64 KiB` (an event is well under 1 KiB). Over-size requests
  are rejected **413** without unbounded buffering.
- **Global concurrency cap** — `256` in-flight requests; bursts beyond it are
  shed rather than exhausting CPU/memory.
- **Per-request timeout** — `10s`, guarding slow-write (Slowloris) clients.

**Per-IP rate limiting terminates at the reverse proxy.** Recommended proxy
limits (nginx / Caddy / Envoy):

- `limit_req` ~ 10 req/s per IP, small burst;
- `client_max_body_size 64k;` (defense in depth with the in-app cap);
- request read timeout ≤ 10s; TLS 1.3.

## Run it

**Binary**
```bash
auths-witness --identity ./witness.key --generate \
  --bind 127.0.0.1:3333 --persist ./receipts.db
# subsequent starts (no --generate) load the same key → same /health AID
auths-witness --identity ./witness.key --bind 127.0.0.1:3333 --persist ./receipts.db
```

**Docker** (`Dockerfile` in this directory — distroless-static, non-root)
```bash
docker build -f docs/deployment/witness/Dockerfile -t auths-witness .
docker run --read-only --cap-drop ALL \
  -v auths_witness_data:/data -p 3333:3333 auths-witness
```

**systemd** (`auths-witness.service` in this directory)
```bash
install -m0755 target/release/auths-witness /usr/local/bin/auths-witness
cp docs/deployment/witness/auths-witness.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now auths-witness
systemd-analyze security auths-witness.service   # exposure target < 3.0
```

The unit runs `DynamicUser=yes`, `NoNewPrivileges`, `ProtectSystem=strict`,
`SystemCallFilter=@system-service`, an empty `CapabilityBoundingSet`, and confines
writes to its `StateDirectory` (key + DB).
