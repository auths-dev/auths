# Git Linearity Enforcement

Auths uses Git as the storage substrate for KERI Key Event Logs (KELs) and identity data. Append-only semantics are essential: if an attacker can rewrite, reorder, or delete events, they can forge key rotations and compromise identity integrity.

This document describes the three layers of defense that enforce linearity.

## Threat model

| Attack | Vector | Impact |
|--------|--------|--------|
| Force push | `git push --force` to the bare repo | Replaces KEL tip, enables undetectable key rotation |
| Ref deletion | `git update-ref -d refs/keri/...` | Destroys identity entirely |
| History rewrite | `git rebase` / `git filter-branch` | Reorders or removes events, breaks chain linkage |
| Merge commits | Manual merge into KEL ref | Introduces non-linear history, ambiguous event ordering |

## Layer 1: Registry backend (Rust, server-side)

The `append_event()` method in the packed registry backend (`crates/auths-id/src/storage/registry/packed.rs`) enforces:

- **Monotonic sequence numbers** — each event's `sn` must equal the previous event's `sn + 1`. Out-of-order or duplicate events are rejected.
- **SAID chain linkage** — each event's `p` (prior) field must match the SAID of the previous event. Broken chains are rejected.
- **Cryptographic signature verification** — the event signature is verified against the current public key in the KEL state. Invalid signatures are rejected.

These checks run inside the Rust process that owns the Git repository. They protect against malformed events submitted through the registry API.

**Limitation:** These checks do not run during a raw `git push`. If an attacker has write access to the bare Git repository (SSH, filesystem, or a misconfigured Git hosting platform), they can bypass the Rust logic entirely.

## Layer 2: Client-side KEL validation (Rust, read-path)

The `get_state()` method in `crates/auths-id/src/keri/kel.rs` and the incremental validator in `crates/auths-id/src/keri/incremental.rs` enforce:

- **Linear history** — every commit in the KEL must have exactly one parent (except the inception commit, which has zero). Merge commits trigger a hard `ChainIntegrity` error.
- **Full event replay** — all events are replayed from inception to tip, verifying signatures, sequence numbers, and pre-rotation commitments at each step.

This layer detects corruption after the fact. If a force push or merge introduces non-linear history, the next client that reads the KEL will reject it.

**Limitation:** Detection is reactive, not preventive. The damage (rewritten KEL) has already occurred by the time a client detects it.

## Layer 3: Git pre-receive hook (automatic, push-time)

The `install_linearity_hook()` function in `crates/auths-id/src/storage/registry/hooks.rs` writes a pre-receive hook into the Git repository's `hooks/` directory. This happens automatically during `auths init` and `auths id init-did` — no manual installation step is required.

The hook runs before Git accepts any pushed refs, rejecting:

- **Non-fast-forward pushes** to any protected ref namespace. This prevents `git push --force` from rewriting history.
- **Ref deletions** of any protected ref. This prevents `git update-ref -d` from destroying identity data.

Installation is best-effort and idempotent: if the hook is already present it is not duplicated, and if an existing pre-receive hook exists the linearity logic is appended without overwriting it.

### Protected namespaces

| Prefix | Content |
|--------|---------|
| `refs/keri/` | KERI Key Event Log refs (legacy layout) |
| `refs/auths/` | Identity, attestation, and organization refs |
| `refs/did/keri/` | KERI DID refs (RIP-5 layout) |

New ref creation (e.g., a new identity's inception event) is allowed. Refs outside these namespaces are not affected.

### How it is installed

The hook is embedded as a shell script constant in the Rust source (`LINEARITY_HOOK_SCRIPT` in `hooks.rs`). When the CLI initializes a repository, it calls `install_linearity_hook(&repo_path)` alongside `install_cache_hooks()`. This writes the script to `.git/hooks/pre-receive` (or appends to it) and sets the executable bit.

Call sites:

- `crates/auths-cli/src/commands/init.rs` — `auths init`
- `crates/auths-cli/src/commands/setup.rs` — `auths id init-did` (both human and agent identity flows)

### Git hosting platforms

For repositories hosted on platforms where you cannot control the hooks directory, configure ref protection rules instead:

- **GitHub Enterprise**: Custom pre-receive hooks via admin settings
- **GitLab**: Settings > Repository > Protected branches/tags, or a server-side hook in `custom_hooks/pre-receive`
- **Gitea/Forgejo**: Repository Settings > Branches > Branch Protection, or a server-side hook

## Defense in depth summary

| Check | When | Prevents | Detects |
|-------|------|----------|---------|
| Pre-receive hook | Push time | Force push, ref deletion | — |
| Registry backend | Event append | Malformed events, broken chains | — |
| Client KEL validation | Read time | — | Non-linear history, forged events |
| Witness receipts | Async | — | Duplicity (conflicting event histories) |

No single layer is sufficient. The pre-receive hook prevents Git-level attacks. The registry backend prevents API-level attacks. Client validation catches anything that slips through. Witness receipts provide independent corroboration across trust boundaries.
