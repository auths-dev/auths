# Git as Storage

How Auths uses Git refs as a database: reference layout, consistency model, and why this design was chosen.

## Why Git

Auths stores all identity data, attestations, and key event logs as Git refs in a bare repository at `~/.auths`. This is not incidental -- Git is the storage engine, not just a transport.

**Append-only history.** Git's commit graph is naturally append-only. Each commit references its parent by SHA hash, forming a tamper-evident chain. This mirrors KERI's hash-chained Key Event Log exactly.

**Content-addressable.** Every blob, tree, and commit in Git is addressed by its SHA hash. This provides built-in integrity verification for all stored data.

**Replication is built in.** `git fetch` and `git push` replicate refs between repositories. Identity data can be shared between machines or backed up to a remote without building custom sync infrastructure.

**Offline-first.** All operations work locally. No server, no network, no blockchain. Verification needs nothing but the Git repository.

**Tooling.** Standard Git tooling (reflog, fsck, gc) works on identity data. Debugging and inspection use the same tools developers already know.

## Reference Layout

### KERI Key Event Logs

KERI data follows the RIP-5 convention for DID document storage in Git:

```
refs/did/keri/<prefix>/kel                    # Key Event Log
refs/did/keri/<prefix>/receipts/<event-said>  # Witness receipts per event
refs/did/keri/<prefix>/document               # Cached DID document (optional)
```

Where `<prefix>` is the KERI identifier prefix (the SAID of the inception event, e.g., `EXq5YqaL6L48pf0fu7IUhL0JRaU2`).

The KEL ref points to the tip of a Git commit chain. Each commit in the chain contains a single file:

```
refs/did/keri/EXq5Yqa.../kel
  |
  v
  commit (KERI rotation: s=2)
    |-- tree
    |     \-- event.json (RotEvent)
    |
    \-- parent: commit (KERI interaction: s=1)
                  |-- tree
                  |     \-- event.json (IxnEvent)
                  |
                  \-- parent: commit (KERI inception: EXq5Yqa...)
                                |-- tree
                                      \-- event.json (IcpEvent)
```

The commit chain mirrors the KERI event chain. Walking from tip to root (oldest first) reproduces the full KEL.

### Identity and Device Attestations

Identity and attestation data uses a configurable layout with sensible defaults:

```
refs/auths/identity                                    # Primary identity metadata
refs/auths/devices/nodes/<device-did>/signatures       # Device attestations
```

Each device attestation ref points to a commit containing `attestation.json`:

```
refs/auths/devices/nodes/did_key_z6MkDevice.../signatures
  |
  v
  commit
    \-- tree
          \-- attestation.json (Attestation JSON blob)
```

### Organization Members

Organization membership attestations are stored under:

```
refs/auths/org/<org-did-sanitized>/identity            # Organization identity
refs/auths/org/<org-did-sanitized>/members/<member-did> # Per-member attestation
```

DIDs are sanitized for Git ref compatibility by replacing non-alphanumeric characters with underscores (e.g., `did:keri:EOrg123` becomes `did_keri_EOrg123`).

### Device Namespaces (Forks)

Per-device fork storage uses Git namespaces:

```
refs/namespaces/<nid>/refs/...
```

Where `<nid>` is the DID with colons replaced by hyphens (e.g., `did:key:z6MkDevice` becomes `did-key-z6MkDevice`).

### Configurable Layouts

The `StorageLayoutConfig` struct allows alternative ref layouts for interoperability:

| Preset | Identity Ref | Attestation Prefix | Use Case |
|--------|-------------|-------------------|----------|
| Default | `refs/auths/identity` | `refs/auths/devices/nodes` | Standard Auths |
| Radicle | `refs/rad/id` | `refs/keys` | Radicle integration |
| Gitoxide | `refs/auths/id` | `refs/auths/devices` | Gitoxide tooling |

## Consistency Model

### KEL Integrity

The KEL has strict consistency requirements enforced at the protocol level:

1. **Linear history only.** KEL commits must have exactly 0 parents (inception) or 1 parent. Merge commits (>1 parent) are rejected as chain integrity violations.

2. **Monotonic sequence numbers.** Events must appear as 0, 1, 2, ... with no gaps or duplicates.

3. **Hash chain linkage.** Each event's `p` field must reference the previous event's `d` (SAID). Breaking any link invalidates the chain.

4. **Self-addressing.** Each event's `d` field must equal the Blake3 hash of its canonical serialization.

If any of these invariants are violated, the `validate_kel` function returns a `ValidationError` and the identity is considered corrupt.

### Attestation Lifecycle

Attestation state is tracked through the commit history of the attestation ref:

- **Creation**: First commit on the ref contains the signed attestation
- **Extension**: New commit updates `expires_at` with fresh signatures
- **Revocation**: New commit sets `revoked_at` with fresh signatures

The commit chain provides an audit trail of the attestation's lifecycle.

### Concurrent Access

Git repositories support concurrent readers. Writers use Git's built-in reference locking (lock files under `.git/refs/`). Multiple processes can safely read the KEL while one process appends a new event.

## Storage Location

The default storage location is `~/.auths`, resolved by:

1. If `--repo` argument is provided, use that path
2. Otherwise, use `$HOME/.auths`

This directory is a standard Git repository (may be bare or non-bare). The `auths-id` crate interacts with it through `git2` (libgit2 bindings).

## Complete Reference Map

| Data | Git Ref Pattern | Blob Filename | Format |
|------|----------------|---------------|--------|
| Key Event Log | `refs/did/keri/<prefix>/kel` | `event.json` | KERI Event JSON |
| Witness receipts | `refs/did/keri/<prefix>/receipts/<said>` | receipt blob | Receipt JSON |
| DID document cache | `refs/did/keri/<prefix>/document` | document blob | DID Document JSON |
| Primary identity | `refs/auths/identity` | `identity.json` | Identity JSON |
| Device attestation | `refs/auths/devices/nodes/<did>/signatures` | `attestation.json` | Attestation JSON |
| Org identity | `refs/auths/org/<org>/identity` | - | Identity JSON |
| Org member | `refs/auths/org/<org>/members/<member>` | - | Attestation JSON |
| Device namespace | `refs/namespaces/<nid>/refs/...` | - | Varies |
| Threshold policies | `refs/auths/policies/threshold/<policy_id>` | - | Policy JSON |
