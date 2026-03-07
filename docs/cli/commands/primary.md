# Primary Commands

## auths init

```bash
auths init
```

<!-- BEGIN GENERATED: auths init -->
| Flag | Default | Description |
|------|---------|-------------|
| `--non-interactive` | — |  |
| `--profile <PROFILE>` | — |  |
| `- developer: Full local development setup with keychain, identity, device linking, and git signing` | — |  |
| `- ci:` | — | Ephemeral identity for CI/CD pipelines |
| `- agent:` | — | Scoped identity for AI agents with capability restrictions |
| `--key-alias <KEY_ALIAS>` | — |  |
| `--force` | — |  |
| `--dry-run` | — |  |
| `--registry <REGISTRY>` | — |  |
| `--skip-registration` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths init -->

---

## auths verify

```bash
auths verify
```

<!-- BEGIN GENERATED: auths verify -->
| Flag | Default | Description |
|------|---------|-------------|
| `--allowed-signers <ALLOWED_SIGNERS>` | — |  |
| `--identity-bundle <IDENTITY_BUNDLE>` | — |  |
| `--issuer-pk <ISSUER_PK>` | — |  |
| `--issuer-did <ISSUER_DID>` | — |  |
| `--witness-receipts <WITNESS_RECEIPTS>` | — |  |
| `--witness-threshold <WITNESS_THRESHOLD>` | — |  |
| `--witness-keys <WITNESS_KEYS>...` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths verify -->

---

## auths status

```bash
auths status
```

<!-- BEGIN GENERATED: auths status -->
| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths status -->
