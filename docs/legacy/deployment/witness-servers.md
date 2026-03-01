# Witness Server Deployment

## Configuring Witnesses on an Identity

### During Initialization

Pass one or more `--witness` flags when creating an identity:

```bash
auths init \
  --witness http://witness1.example.com:3333 \
  --witness http://witness2.example.com:3333 \
  --witness-threshold 2 \
  --witness-policy enforce
```

- `--witness` (repeatable): URL of a witness server.
- `--witness-threshold`: Minimum receipts required (k-of-n). Defaults to the number of witnesses if omitted.
- `--witness-policy`: One of `enforce` (fail if quorum not met), `warn` (log and continue), or `skip` (disable collection). Defaults to `enforce`.

The witness configuration is stored in identity metadata and automatically used during key rotation.

### Managing Witnesses Post-Init

Add or remove witness URLs after initialization:

```bash
# Add a witness
auths witness add --url http://witness3.example.com:3333

# Remove a witness
auths witness remove --url http://witness1.example.com:3333

# List configured witnesses
auths witness list
```

The threshold is adjusted automatically when removing witnesses would put it above the witness count.

### Witness Policy

| Policy    | Behavior                                           |
|-----------|----------------------------------------------------|
| `enforce` | Inception/rotation fails if quorum is not met.     |
| `warn`    | Logs a warning but allows the operation to proceed.|
| `skip`    | Skips receipt collection entirely.                 |

### Key Rotation

When rotating keys, the witness configuration is loaded from identity metadata automatically. Receipts are collected for the rotation event using the same threshold and policy:

```bash
auths id rotate --alias main
```

## Starting a Witness Server

```bash
auths witness serve --bind 0.0.0.0:3333 --db-path /var/lib/auths/witness.db
```

The server auto-generates a DID and Ed25519 keypair on startup. To use a specific DID:

```bash
auths witness serve --bind 0.0.0.0:3333 --witness-did did:key:z6Mk...
```

## TLS Configuration

The witness server supports two TLS deployment models:

### Option 1: Reverse Proxy (Recommended)

Terminate TLS at a reverse proxy (nginx, Caddy, cloud load balancer) and run the witness server on plain HTTP behind it. This is the recommended approach for production deployments.

Example nginx configuration:

```nginx
server {
    listen 443 ssl;
    server_name witness.example.com;

    ssl_certificate     /etc/ssl/certs/witness.pem;
    ssl_certificate_key /etc/ssl/private/witness-key.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The witness server exposes `GET /health` for proxy liveness checks.

### Option 2: Native TLS (Feature Flag)

Enable the `tls` feature flag on `auths-core` to use built-in rustls TLS termination:

```toml
auths-core = { version = "0.0.1-rc.9", features = ["witness-server", "tls"] }
```

Then configure TLS in `WitnessServerConfig`:

```rust
use auths_core::witness::server::{WitnessServerConfig, WitnessServerState, run_server_tls};
use std::path::PathBuf;

let config = WitnessServerConfig {
    witness_did: "did:key:z6Mk...".into(),
    keypair_pkcs8: pkcs8_bytes,
    db_path: PathBuf::from("/var/lib/auths/witness.db"),
    tls_cert_path: Some(PathBuf::from("/etc/ssl/certs/witness.pem")),
    tls_key_path: Some(PathBuf::from("/etc/ssl/private/witness-key.pem")),
};

let state = WitnessServerState::new(config)?;
let addr = "0.0.0.0:443".parse().unwrap();
run_server_tls(state, addr, cert_path, key_path).await?;
```

Certificate and key files must be PEM-encoded. The server will refuse to start if the files are missing, unreadable, or contain invalid PEM data.

## Health Check

All deployment modes expose:

```
GET /health
```

Returns:

```json
{
  "status": "ok",
  "witness_did": "did:key:z6Mk...",
  "first_seen_count": 42,
  "receipt_count": 38
}
```
