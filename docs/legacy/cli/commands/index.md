# CLI Commands

Auths exposes five primary commands for day-to-day use. Additional commands are available directly as `auths device`, `auths key`, `auths policy`, etc.

```
auths --help

Commands:
  init     Set up your cryptographic identity and Git signing
  sign     Sign a Git commit or artifact
  verify   Verify a signed commit or attestation
  status   Show identity and signing status
```

## Primary commands

| Command | Description |
|---------|-------------|
| [`auths init`](primary.md#auths-init) | Guided setup — creates identity, links device, configures Git signing |
| [`auths sign`](primary.md#auths-sign) | SSH signing binary invoked automatically by Git |
| [`auths verify`](primary.md#auths-verify) | Verify attestations and commit signatures |
| [`auths status`](primary.md#auths-status) | Show current identity, device, and signing health |
| [`auths pair`](primary.md#auths-pair) | Link a new device via QR code or short code |

→ [Primary commands reference](primary.md)

## Advanced commands

Accessed via `auths <command>`. Useful for power users, key management, and incident response.

| Command | Description |
|---------|-------------|
| [`auths device`](advanced.md#auths-device) | Link, revoke, and extend device authorizations |
| [`auths id`](advanced.md#auths-id) | Manage your cryptographic identity (init, show, rotate) |
| [`auths key`](advanced.md#auths-key) | Manage keys in the platform keychain |
| [`auths policy`](advanced.md#auths-policy) | Lint, compile, test, and diff authorization policies |
| [`auths emergency`](advanced.md#auths-emergency) | Incident response — revoke devices, rotate keys, freeze signing |

→ [Advanced commands reference](advanced.md)

## Global flags

These flags work on every command:

| Flag | Description |
|------|-------------|
| `--output json` / `--json` | Machine-readable JSON output |
| `--repo <PATH>` | Override the Auths repository path (default: `~/.auths`) |
| `--help` | Show help for any command or subcommand |
| `--version` | Show the installed version |
