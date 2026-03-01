# CLI Overview

The `auths` CLI is the primary interface for managing your identity, keys, devices, and Git signing.

## What the CLI owns

| Responsibility | CLI | SDKs |
|----------------|-----|------|
| Create identity | Yes | No |
| Manage keys | Yes | No |
| Link/revoke devices | Yes | No |
| Sign commits | Yes | No |
| Verify attestations | Yes | Yes |
| Verify chains | Yes | Yes |
| Rotate keys | Yes | No |

The CLI handles identity lifecycle. SDKs handle verification only.

## Binaries

Installing `auths_cli` produces three binaries:

| Binary | Purpose |
|--------|---------|
| `auths` | Main CLI for all identity and key management |
| `auths-sign` | SSH signing program (used by `gpg.ssh.program`) |
| `auths-verify` | Standalone signature verification |

!!! note
    You should almost never call `auths-sign` directly — it exists to satisfy Git's `gpg.ssh.program` interface. Git calls it automatically when you run `git commit -S`. If you want to sign something, just commit normally with signing enabled.

## Command groups

```
auths
├── init              Initialize identity (guided setup)
├── status            Show identity and device overview
├── id
│   ├── init-did      Create identity with full control
│   ├── show          Display identity details
│   ├── show-devices  List linked devices
│   └── rotate        Rotate identity keys
├── key
│   ├── list          List stored keys
│   ├── import        Import a key from seed
│   ├── export        Export key (public or PEM)
│   └── delete        Remove a key from keychain
├── device
│   ├── link          Link a device to your identity
│   ├── revoke        Revoke a device
│   └── extend        Renew a device attestation
├── verify            Verify an attestation file
├── verify-commit     Verify a Git commit signature
├── git
│   ├── setup         Configure Git for Auths signing
│   └── allowed-signers  Generate allowed-signers file
└── util
    ├── derive-did    Derive DID from seed
    └── derive-pk-bytes  Derive public key bytes from seed
```

## Global flags

Every command accepts these layout flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <PATH>` | `~/.auths` | Git repository path |
| `--identity-ref <REF>` | `refs/auths/identity` | Identity commit ref |
| `--identity-blob <NAME>` | `identity.json` | Identity blob filename |
| `--attestation-prefix <PREFIX>` | `refs/auths/devices/nodes` | Attestation ref prefix |
| `--attestation-blob <NAME>` | `attestation.json` | Attestation blob filename |

## Passphrase handling

Commands that access encrypted keys prompt for a passphrase via `/dev/tty`. This works in interactive terminals. For non-interactive environments, set `AUTHS_PASSPHRASE` or use `--passphrase`.

## Output format

Most commands output human-readable text by default. Use `--output json` for machine-readable JSON output.

## Help

```bash
auths --help              # All commands
auths <command> --help    # Command-specific help
```
