# Enterprise Provisioning

The `auths provision` command enables declarative, headless identity provisioning for enterprise fleet deployments. It reads a TOML configuration file and reconciles the node's identity state to match — no interactive prompts, no human intervention.

## Quick Start

```bash
# Create a config file
cat > node.toml <<'EOF'
[identity]
key_alias = "main"
repo_path = "/data/auths"

[witness]
urls = ["https://witness1.example.com"]
threshold = 1
policy = "enforce"
EOF

# Validate without applying
auths provision --config node.toml --dry-run

# Apply
auths provision --config node.toml
```

## TOML Schema Reference

### `[identity]` (required)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `key_alias` | string | `"main"` | Alias for the Ed25519 key stored in the platform keychain |
| `repo_path` | string | `~/.auths` | Path to the Git repository storing identity data |
| `preset` | string | `"default"` | Storage layout preset: `default`, `radicle`, `gitoxide` |

### `[identity.metadata]` (optional)

Arbitrary key-value pairs attached to the identity. All values are strings.

```toml
[identity.metadata]
name = "prod-node-01"
environment = "production"
region = "us-east-1"
```

### `[witness]` (optional)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `urls` | string[] | `[]` | Witness server URLs |
| `threshold` | integer | `1` | Minimum witness receipts required (k-of-n) |
| `timeout_ms` | integer | `5000` | Per-witness timeout in milliseconds |
| `policy` | string | `"enforce"` | `enforce` (fail if quorum not met), `warn` (log and continue), `skip` (no witnesses) |

## Environment Variable Overrides

All TOML values can be overridden via environment variables using the prefix `AUTHS_` and double-underscore `__` separator for nested keys.

| Environment Variable | Overrides |
|---------------------|-----------|
| `AUTHS_IDENTITY__KEY_ALIAS` | `identity.key_alias` |
| `AUTHS_IDENTITY__REPO_PATH` | `identity.repo_path` |
| `AUTHS_IDENTITY__PRESET` | `identity.preset` |
| `AUTHS_WITNESS__THRESHOLD` | `witness.threshold` |
| `AUTHS_WITNESS__TIMEOUT_MS` | `witness.timeout_ms` |
| `AUTHS_WITNESS__POLICY` | `witness.policy` |

The passphrase for key encryption is provided via `AUTHS_PASSPHRASE` (standard across all `auths` commands).

## CLI Flags

```
auths provision [OPTIONS]

Options:
  --config <PATH>    Path to the TOML config file (required)
  --dry-run          Validate config and print resolved state without applying
  --force            Overwrite existing identity if present
```

## Idempotency

By default, `auths provision` is idempotent:

- If an identity already exists at the configured `repo_path` and matches the config, the command succeeds without changes.
- If no identity exists, one is created.
- Use `--force` to overwrite an existing identity regardless.

## Deployment Examples

### Kubernetes Init Container

```yaml
apiVersion: v1
kind: Pod
spec:
  initContainers:
    - name: auths-provision
      image: your-org/auths:latest
      command: ["auths", "provision", "--config", "/etc/auths/node.toml"]
      env:
        - name: AUTHS_PASSPHRASE
          valueFrom:
            secretKeyRef:
              name: auths-secrets
              key: passphrase
      volumeMounts:
        - name: auths-config
          mountPath: /etc/auths
        - name: auths-data
          mountPath: /data/auths
  volumes:
    - name: auths-config
      configMap:
        name: auths-node-config
    - name: auths-data
      persistentVolumeClaim:
        claimName: auths-pvc
```

### Docker Compose

```yaml
services:
  auths-node:
    image: your-org/auths:latest
    command: auths provision --config /etc/auths/node.toml
    environment:
      AUTHS_PASSPHRASE: ${AUTHS_PASSPHRASE}
      AUTHS_IDENTITY__REPO_PATH: /data/auths
    volumes:
      - ./node.toml:/etc/auths/node.toml:ro
      - auths-data:/data/auths
volumes:
  auths-data:
```

### Terraform (via `local-exec`)

```hcl
resource "null_resource" "auths_provision" {
  provisioner "local-exec" {
    command = "auths provision --config ${path.module}/node.toml"
    environment = {
      AUTHS_PASSPHRASE           = var.auths_passphrase
      AUTHS_IDENTITY__KEY_ALIAS  = var.key_alias
      AUTHS_IDENTITY__REPO_PATH  = var.repo_path
    }
  }
}
```
