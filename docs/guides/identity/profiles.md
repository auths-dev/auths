# Profiles

Auths supports three setup profiles for different environments: **developer**, **CI**, and **agent**. Each profile creates a distinct type of identity optimized for its use case. Organizations can layer on top of any individual identity.

## Setup profiles

The `auths init` command offers an interactive profile selector, or you can specify one directly:

```bash
auths init --profile developer
auths init --profile ci
auths init --profile agent
```

### Developer profile

The default for local development. Creates a full identity with platform keychain integration, device linking, and Git signing configuration.

```bash
auths init
# or explicitly:
auths init --profile developer
```

What it does:

1. Verifies keychain access (macOS Keychain, Linux Secret Service, Windows Credential Manager, or encrypted file fallback)
2. Checks Git version compatibility
3. Prompts for a key name (default: `main`)
4. Generates an Ed25519 keypair with KERI pre-rotation
5. Links the current device to the identity
6. Configures Git signing (`gpg.format`, `gpg.ssh.program`, `user.signingKey`, `commit.gpgSign`)
7. Optionally links your GitHub account for identity verification
8. Optionally registers the identity on the public Auths Registry

Interactive prompts include:

- **Key name** -- the local name for your signing key
- **Conflict policy** -- reuse an existing identity or create a new one
- **Git scope** -- configure signing for this repository only (`--local`) or all repositories (`--global`)
- **Platform verification** -- link your GitHub account for identity discovery

For non-interactive use:

```bash
auths init --profile developer --non-interactive --key-alias my-key
```

| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias` | `main` | Alias for the identity key |
| `--force` | `false` | Overwrite existing identity |
| `--non-interactive` | `false` | Skip all prompts, use defaults |
| `--registry` | `https://auths-registry.fly.dev` | Registry URL for identity registration |
| `--register` | `false` | Register identity with the Auths Registry |

### CI profile

Creates an ephemeral identity for CI/CD pipelines. Uses an in-memory keychain backend and produces environment variable blocks for injecting into CI secrets.

```bash
auths init --profile ci --non-interactive
```

What it does:

1. Detects the CI environment (GitHub Actions, GitLab CI, or custom)
2. Sets `AUTHS_KEYCHAIN_BACKEND=memory` for the session
3. Creates an ephemeral identity in `.auths-ci/` within the working directory
4. Outputs environment variables to add to your CI secrets

The CI profile reads the passphrase from the `AUTHS_PASSPHRASE` environment variable (falling back to a default for ephemeral use).

!!! note "CI identities are ephemeral by design"
    The in-memory keychain does not persist between runs. Each CI job creates a fresh identity. For persistent CI signing, use the developer profile with `auths key copy-backend` to provision a file-based keychain.

### Agent profile

Creates a scoped identity for AI agents with restricted capabilities and an expiration time.

```bash
auths init --profile agent
```

What it does:

1. Prompts for capability scope (or auto-selects in non-interactive mode)
2. Generates a keypair with alias `agent`
3. Creates a device attestation with the selected capabilities and a 1-year default expiry
4. Outputs the agent configuration

Available capabilities are presented as an interactive checklist. Common capabilities include `sign_commit` and `sign_tag`.

Use `--dry-run` to preview the configuration without creating files:

```bash
auths init --profile agent --dry-run
```

After setup, manage the agent with:

```bash
auths agent start
auths agent status
```

## Organization identities

Organizations are separate identities that can authorize members with role-based capabilities.

### Creating an organization

```bash
auths org init --name "my-org"
```

This creates a new `did:keri` identity for the organization, stored in its own Git repository. The creator receives an admin attestation with all capabilities:

- `SignCommit` -- sign Git commits
- `SignRelease` -- sign releases/tarballs
- `ManageMembers` -- add or revoke members
- `RotateKeys` -- perform key rotation

Optionally provide a custom key alias or additional metadata:

```bash
auths org init \
  --name "my-org" \
  --key org-myorg \
  --metadata-file org-metadata.json
```

### Adding members

Admins (users with the `ManageMembers` capability) can add members:

```bash
auths org add-member \
  --org "did:keri:E..." \
  --member "did:keri:E..." \
  --role member
```

| Role | Default capabilities |
|------|---------------------|
| `admin` | `SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys` |
| `member` | `SignCommit`, `SignRelease` |
| `readonly` | *(none)* |

Override default capabilities with `--capabilities`:

```bash
auths org add-member \
  --org "did:keri:E..." \
  --member "did:keri:E..." \
  --role member \
  --capabilities sign_commit
```

### Revoking members

```bash
auths org revoke-member \
  --org "did:keri:E..." \
  --member "did:keri:E..." \
  --note "Access removed"
```

### Listing members

```bash
auths org list-members --org "did:keri:E..."
auths org list-members --org "did:keri:E..." --include-revoked
```

Output shows a tree with role, delegation chain, and capabilities:

```
Members (3 total):
----
|- did:keri:Eabc... [admin]
|  |- did:keri:Edef... [member] [SignCommit, SignRelease]
|     delegated by: did:keri:Eabc...
|- did:keri:Eghi... [readonly]
----
```

## When to use each profile

| Scenario | Profile | Reason |
|----------|---------|--------|
| Daily development on your laptop | Developer | Full keychain integration, Git signing, platform verification |
| GitHub Actions / GitLab CI pipeline | CI | Ephemeral, no persistent secrets needed on the runner |
| AI coding assistant (Copilot, Claude, etc.) | Agent | Scoped capabilities, automatic expiration |
| Team or company signing policy | Organization + Developer | Centralized member management with delegated signing |

## Managing multiple profiles

A single machine can host multiple identities. The active identity is determined by the `~/.auths` repository (or the `--repo` flag).

### Switching between identities

Use the `--repo` flag to point at a different identity repository:

```bash
# Use default identity
auths status

# Use org identity
auths status --repo ~/orgs/my-org/.auths

# Use a project-specific identity
auths status --repo /path/to/project/.auths
```

### Environment variable overrides

| Variable | Description |
|----------|-------------|
| `AUTHS_HOME` | Override the default `~/.auths` identity repository path |
| `AUTHS_KEYCHAIN_BACKEND` | Override the keychain backend (`file`, `memory`) |
| `AUTHS_KEYCHAIN_FILE` | Path for the encrypted file keychain |
| `AUTHS_PASSPHRASE` | Passphrase for the file keychain backend |

### Per-repository Git signing

During `auths init`, choose "This repository only" at the Git scope prompt to configure signing for a single repository. This writes to `.git/config` instead of `~/.gitconfig`, allowing different identities per project:

```bash
# In project A (uses identity A)
cd ~/projects/project-a
auths init --profile developer
# Select: "This repository only"

# In project B (uses identity B)
cd ~/projects/project-b
auths init --profile developer --repo ~/alt-identity/.auths
# Select: "This repository only"
```

### Checking the active identity

```bash
auths status
```

Output shows the identity DID, agent status, and linked device count:

```
Identity:   did:keri:EnXNx...
Agent:      stopped
Devices:    2 linked
```
