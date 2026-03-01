# Git Layouts

Auths stores identity and attestation data as Git refs. The exact ref names are configurable, allowing Auths to interoperate with different systems.

## Default layout

```
~/.auths/                              (bare Git repository)
  refs/
    auths/
      identity                         → identity commit (identity.json blob)
      devices/
        nodes/
          <device-did>/
            signatures                 → attestation commits (attestation.json blobs)
    keri/
      id                               → primary DID string
      kel                              → Key Event Log
```

| Ref | Content |
|-----|---------|
| `refs/auths/identity` | Identity commit with `identity.json` blob |
| `refs/auths/devices/nodes/<did>/signatures` | Attestation history for a device |
| `refs/keri/id` | Primary DID string |
| `refs/keri/kel` | Key Event Log entries |

## Radicle layout

Auths can store data in a Radicle-compatible layout:

```
refs/
  rad/
    id                                 → identity commit (radicle-identity.json blob)
    multidevice/
      nodes/
        <device-did>/
          signatures                   → attestation commits (link-attestation.json)
```

| Default ref | Radicle ref |
|-------------|-------------|
| `refs/auths/identity` | `refs/rad/id` |
| `identity.json` | `radicle-identity.json` |
| `refs/auths/devices/nodes` | `refs/rad/multidevice/nodes` |
| `attestation.json` | `link-attestation.json` |

## Configuring the layout

Every CLI command accepts layout flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | `~/.auths` | Path to the Git repository |
| `--identity-ref` | `refs/auths/identity` | Ref for the identity commit |
| `--identity-blob` | `identity.json` | Blob name for identity data |
| `--attestation-prefix` | `refs/auths/devices/nodes` | Base ref prefix for device attestations |
| `--attestation-blob` | `attestation.json` | Blob name for attestation data |

## Custom layouts

You can define any layout. For example, to store attestations in a project repo instead of `~/.auths`:

```bash
auths id init-did \
  --repo /path/to/project/.git \
  --identity-ref refs/identity/main \
  --identity-blob id.json \
  --attestation-prefix refs/identity/devices \
  --attestation-blob device.json \
  --local-key-alias project-key \
  --metadata-file meta.json
```

## Why configurable?

Different systems use different Git ref conventions. By making the layout configurable, Auths can:

- Coexist with Radicle identity storage
- Store data in project repos instead of a separate `~/.auths` repo
- Adapt to organizational conventions
- Support migration between layouts
