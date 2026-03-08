# Auths-Radicle Integration Learnings

This document captures hard-won knowledge from integrating Auths' KERI-based
identity system into Radicle's Heartwood node, HTTP daemon, and web explorer.
It is intended as a reference for anyone maintaining or extending this
integration.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [The DID Type Bridge](#2-the-did-type-bridge)
3. [Device Attestations and the Packed Registry](#3-device-attestations-and-the-packed-registry)
4. [KERI Serialization Constraints](#4-keri-serialization-constraints)
5. [Heartwood Integration](#5-heartwood-integration)
6. [radicle-httpd Integration](#6-radicle-httpd-integration)
7. [Frontend (radicle-explorer) Integration](#7-frontend-radicle-explorer-integration)
8. [Seed Node Deployment](#8-seed-node-deployment)
9. [Cargo Dependency Wiring](#9-cargo-dependency-wiring)
10. [Debugging Silent Failures](#10-debugging-silent-failures)
11. [Future Work](#11-future-work)

---

## 1. Architecture Overview

The integration spans four repositories and three runtime processes:

```
auths-base/auths          -- KERI identity, attestations, verification
radicle-base/heartwood    -- Radicle node, CLI, storage, radicle-core types
radicle-base/radicle-explorer
  ├─ radicle-httpd/       -- HTTP API serving identity + repo data
  └─ src/                 -- Svelte frontend (explorer UI)
radicle-base/fly-seed-node -- Docker + Fly.io deployment
```

Data flows:

1. **Identity creation**: `auths` CLI creates a KERI inception event and
   Ed25519 key pair. The `rad auth` command in Heartwood calls
   `Profile::ensure_keri_identity()` to auto-migrate `did:key` profiles to
   `did:keri`.

2. **Device linking**: An attestation JSON blob is written to the packed
   registry at `refs/auths/registry` inside the identity repo (usually
   `~/.auths` or the radicle storage copy of the auths repo). This links a
   `did:key` (device) to a `did:keri` (controller identity).

3. **Resolution at request time**: `radicle-httpd` uses
   `RadicleIdentityResolver` to resolve any DID. For `did:key` queries, it
   reads the packed registry to discover the controller `did:keri`. For
   `did:keri` queries, it replays the KERI event log (KEL) or falls back to
   cached key state in the registry.

4. **Frontend display**: The explorer checks `isKeri` and `controllerDid` from
   the API response to decide whether to show KERI badges, linked devices, and
   person-vs-device view toggles.

---

## 2. The DID Type Bridge

### The problem

Radicle's published types (`radicle::identity::Did`) and Auths' core types
(`radicle_core::Did`) are **different Rust types** that happen to serialize
identically for `did:key`. The published type only supports `did:key`; the core
type is an enum with `Key(PublicKey)` and `Keri(String)` variants.

```rust
// radicle-core (extended by this integration)
#[serde(into = "String", try_from = "String")]
pub enum Did {
    Key(PublicKey),
    Keri(String),
}
```

### What we learned

- **String comparison is safe** for matching delegates. Both types serialize
  `did:key` identically, so `repo.doc.delegates().iter().any(|d|
  match_strings.contains(&d.to_string()))` works correctly.

- The `Did::decode()` method validates `did:keri:` prefixes: non-empty,
  alphanumeric plus `-` and `_`. KERI prefixes like
  `EHBZWg7FaePMC1_KSFiEhXTps4IkanAKcxn3Rvspga0c` contain underscores, which
  is valid.

- `Did::public_key()` panics on `Did::Keri` -- it exists as a migration shim.
  Always use `did.as_key()` (returns `Option`) or pattern-match explicitly.

### Key file

`heartwood/crates/radicle-core/src/identity.rs`

---

## 3. Device Attestations and the Packed Registry

### Structure

Attestations live in a Git tree at `refs/auths/registry` inside the identity
repo. The tree uses a 2-level shard for scalability:

```
refs/auths/registry (commit -> tree)
└── v1/
    ├── devices/
    │   └── {key_part[0..2]}/          # e.g. "z6"
    │       └── {key_part[2..4]}/      # e.g. "Mk"
    │           └── did_key_{full}/     # colons replaced with underscores
    │               ├── attestation.json
    │               └── history/
    │                   └── {timestamp}_.auths.json
    ├── identities/
    │   └── {prefix[0..2]}/{prefix[2..4]}/{prefix}/
    │       ├── events/00000000.json
    │       ├── metadata.json
    │       ├── state.json
    │       └── tip.json
    └── metadata.json
```

### Attestation JSON format

```json
{
  "version": 1,
  "rid": ".auths",
  "issuer": "did:keri:EHBZWg7FaePMC1_KSFiEhXTps4IkanAKcxn3Rvspga0c",
  "subject": "did:key:z6Mkio7WpoPy5EfeMJwhiZzePFch7xxuDeF9tpAf9q15nnHf",
  "device_public_key": "4084b7edcd80af70b3a33ae653d2a96d458161630984158f57ec0de748be4462",
  "identity_signature": "aabbcc...128 hex chars...",
  "device_signature": "ddeeff...128 hex chars...",
  "timestamp": "2026-03-08T14:00:00.000000Z",
  "note": "Radicle primary device"
}
```

### Critical serialization rules

| Field | Type | JSON encoding | Exact size |
|-------|------|---------------|------------|
| `device_public_key` | `Ed25519PublicKey` | hex string | 64 hex chars (32 bytes) |
| `identity_signature` | `Ed25519Signature` | hex string | 128 hex chars (64 bytes) |
| `device_signature` | `Ed25519Signature` | hex string | 128 hex chars (64 bytes) |

**Lesson learned the hard way**: A signature field with 130 hex chars (65
bytes) instead of 128 (64 bytes) causes `serde_json::from_slice` to fail
silently when the resolver uses `.ok()?`. The error message is:

```
expected 64 bytes, got 65 at line 7 column 156
```

Always validate hex string lengths when constructing attestations manually.

### The `identity_signature` field

Marked with `#[serde(default, skip_serializing_if = "Ed25519Signature::is_empty")]`.
An empty (all-zero) signature is valid for the serde round-trip but semantically
means the attestation is unsigned by the identity. The resolver's
`find_controller_for_device` does **not** verify signatures -- it only reads
the `issuer` field. Verification happens separately in the frontend via WASM.

### Shard path derivation

```rust
let sanitized = did.to_string().replace(':', "_");
// "did:key:z6Mkio7..." -> "did_key_z6Mkio7..."
let key_part = sanitized.strip_prefix("did_key_").unwrap();
// key_part = "z6Mkio7..."
let s1 = &key_part[..2];  // "z6"
let s2 = &key_part[2..4];  // "Mk"
let path = format!("v1/devices/{s1}/{s2}/{sanitized}/attestation.json");
```

### Key files

- `auths-radicle/src/identity.rs` -- `read_device_attestation()`, `registry_tree()`
- `auths-verifier/src/core.rs` -- `Attestation` struct definition

---

## 4. KERI Serialization Constraints

### Event format

KERI events are stored as individual commits in Git refs. The resolver supports
two blob formats per commit: `event.cesr` (CESR-encoded) and `event.json`
(JSON fallback). The `read_events_from_chain` method walks the commit chain
backwards, collecting events.

### Key state resolution

Two paths to resolve a `did:keri` to its current key state:

1. **KEL replay** (`resolve_keri_state`): Reads from per-prefix ref
   `refs/did/keri/{PREFIX}/kel` or flat ref `refs/keri/kel`. Replays all
   events via `replay_kel()` and validates the prefix matches.

2. **Registry cache fallback** (`resolve_keri_state_from_registry`): Reads
   pre-computed key state from `v1/identities/{s1}/{s2}/{prefix}/state.json`
   in the packed registry. This is faster but may be stale.

### The `is_abandoned` flag

A KERI identity can be rotated to a null key set, marking it as abandoned. The
`is_abandoned` field in `KeyState` propagates through to the API response and
is displayed as a yellow badge in the explorer UI.

### Key conversion: KERI public key to did:key

KERI uses CESR-encoded public keys (e.g., `DKxd3bR2ij...`). To convert to
Radicle's `did:key` format:

```rust
let keri_pk = auths_crypto::KeriPublicKey::parse(key_str)?;
let public_key = PublicKey::try_from(keri_pk.into_bytes().as_slice())?;
let did = Did::from(public_key);
// -> Did::Key(PublicKey) -> "did:key:z6Mk..."
```

---

## 5. Heartwood Integration

### Profile auto-migration

`Profile::ensure_keri_identity()` (in `radicle/src/profile.rs`) runs on every
`rad auth` invocation. It:

1. Checks if a KERI inception event already exists at the expected KEL ref.
2. If not, derives a KERI identity from the existing Ed25519 key pair.
3. Writes the inception event and initial key state.
4. Updates `profile.did()` to return `Did::Keri(...)` instead of `Did::Key(...)`.

This is idempotent -- calling it multiple times produces the same result.

### CLI changes

- `rad auth`: Calls `ensure_keri_identity()` after creating or loading a
  profile, both in interactive mode and when `RAD_PASSPHRASE` is set.
- `rad sync` / `rad announce`: Changed from `profile.did().public_key()` to
  `profile.public_key` to avoid the panic on KERI DIDs.
- Terminal formatting: `did()` formatter handles both `did:key:z6Mk...` (truncated)
  and `did:keri:E...` (truncated) display.

### Key files

- `heartwood/crates/radicle/src/profile.rs` -- `ensure_keri_identity()`
- `heartwood/crates/radicle-cli/src/commands/auth.rs` -- auth flow
- `heartwood/crates/radicle-core/src/identity.rs` -- `Did` enum

---

## 6. radicle-httpd Integration

### Context initialization

The `Context` struct holds an optional `auths_home: Option<PathBuf>`, resolved
once at startup:

```rust
let auths_home = std::env::var("AUTHS_HOME")
    .ok()
    .map(PathBuf::from)
    .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".auths")));
```

This path points to the Git repository containing `refs/auths/registry`.

### Delegate handler

`GET /delegates/{did}` and `GET /users/{did}` both route to the same handler:

```rust
let mut resolver = RadicleIdentityResolver::new(ctx.profile.storage.path());
if let Some(home) = ctx.auths_home() {
    resolver = resolver.with_identity_repo(home);
}
let identity = resolver.resolve(&did.to_string())?;
```

The resolver uses `identity_repo_path` (from `AUTHS_HOME`) for the packed
registry, and `repo_path` (radicle storage root) for per-repo identity docs.

### The `isKeri` response field

For `did:key` queries, `RadicleIdentity::is_keri()` returns `false` because
the DID itself is `Did::Key(...)`. However, the device may have a KERI
controller. The httpd extends the check:

```rust
is_keri: identity.is_keri()
    || identity.controller_did.as_ref()
        .map_or(false, |d| d.to_string().starts_with("did:keri:")),
```

This ensures the frontend shows KERI UI elements when a `did:key` device has a
`did:keri` controller, even when the URL uses the bare node ID.

### Delegate repo matching

For `did:keri` queries to `/delegates/{did}/repos`, the handler resolves the
KERI identity to all its device `did:key` DIDs, then matches repos against any
of them. This uses string comparison (see Section 2).

### Key files

- `radicle-explorer/radicle-httpd/src/api.rs` -- `Context`, `auths_home()`
- `radicle-explorer/radicle-httpd/src/api/v1/delegates.rs` -- handlers

---

## 7. Frontend (radicle-explorer) Integration

### DID parsing

The frontend parses DIDs into a discriminated union:

```typescript
type ParsedDid =
  | { type: "key"; prefix: "did:key:"; pubkey: string }
  | { type: "keri"; prefix: "did:keri:"; keriPrefix: string };
```

### KERI detection

```typescript
$: isKeri = did.prefix === "did:keri:" || (userResponse?.isKeri ?? false);
```

This is checked on every reactive update. When `isKeri` is true, the UI shows:
- KERI verification badge (verified/unverified)
- Controller DID section
- Linked devices list
- Person vs. Device view toggle

### URL routing

- `/users/{did:keri:...}` -> user (person) view
- `/users/{z6Mk...}` -> redirects to `/devices/{did:key:z6Mk...}` unless the
  API reports `isKeri: true` (has a KERI controller)
- `/devices/{did:key:...}` -> device view with controller breadcrumb

### Verification flow

The frontend uses a WASM module (`@auths/verifier`) to verify device links:

1. Fetches KEL events from `GET /identity/{did}/kel`
2. Fetches attestations from `GET /identity/{did}/attestations`
3. For each attestation, calls `verifyDeviceLink(kelJson, attestationJson, deviceDid)`
4. Displays aggregate verification status

### NodeId component

The `NodeId.svelte` component performs lazy controller resolution:
- Fetches `getUser(did)` to find `controllerDid`
- If a controller exists, routes to the person view
- Caches results to avoid redundant API calls

### Key files

- `radicle-explorer/src/views/users/View.svelte` -- person view
- `radicle-explorer/src/views/devices/View.svelte` -- device view
- `radicle-explorer/src/lib/auths.ts` -- WASM verification
- `radicle-explorer/src/lib/utils.ts` -- DID parsing
- `radicle-explorer/http-client/index.ts` -- API client

---

## 8. Seed Node Deployment

### Docker build context

The Dockerfile needs source from three sibling repos. `deploy.sh` sets the
build context to the `repositories/` parent directory and creates a
`.dockerignore` that allowlists only what's needed:

```
*
!radicle-base/heartwood/
!radicle-base/radicle-explorer/
!radicle-base/fly-seed-node/entrypoint.sh
!auths-base/auths/
```

### Path rewriting in Dockerfile

Local `[patch]` paths (e.g., `/Users/bordumb/workspace/...`) must be rewritten
to container paths (`/build/...`) before `cargo build`. The Dockerfile uses
`sed -i` to perform this substitution on all `Cargo.toml` files.

### AUTHS_HOME on the seed node

The identity repo on the seed node is the radicle storage copy of the auths
repo:

```bash
export AUTHS_HOME=/home/seed/.radicle/storage/zhwpncWV4iiD7C8cNH2zfHAShxqo
```

A symlink is also created: `/home/seed/.auths -> $AUTHS_HOME`.

The `refs/auths/registry` ref must exist in this repo. It does NOT sync via
Radicle's protocol (which only syncs `refs/rad/*`). It must be created or
updated manually on the seed node.

### Environment variable preservation

`su seed -c "radicle-httpd ..."` does **not** preserve environment variables.
The httpd process would not see `AUTHS_HOME`. Fix: use `su -p seed -c "..."`.

### Seeding policy

`seedingPolicy.default: "allow"` causes the node to sync every repo it
discovers from peers. Use `"block"` and explicitly `rad seed` only the repos
you want:

```bash
su seed -c "rad seed rad:z48wLPJNF8eS3Q4aDMWxHgFrcgKqg" || true  # multi-device-demo
su seed -c "rad seed rad:zhwpncWV4iiD7C8cNH2zfHAShxqo" || true  # auths
su seed -c "rad seed rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5" || true  # heartwood
su seed -c "rad seed rad:z4V1sjrXqjvFdnCUbxPFqd5p4DtH5" || true  # radicle-explorer
```

### Stale control socket

If the container restarts without clean shutdown, a stale
`$RAD_HOME/node/control.sock` prevents the node from starting. The entrypoint
removes it unconditionally before launch.

### Ownership

Fly.io mounts the persistent volume as root. The entrypoint runs
`chown -R seed:seed /home/seed` before any `su seed` commands. Also,
`config.json` is written by root (via `cat >`) and must be re-chowned.

### Git safe.directory

Running `git` commands as root on repos owned by seed triggers the "dubious
ownership" error. Fix: `git config --global --add safe.directory '*'`.

### Key files

- `fly-seed-node/entrypoint.sh`
- `fly-seed-node/Dockerfile`
- `fly-seed-node/deploy.sh`
- `fly-seed-node/fly.toml`

---

## 9. Cargo Dependency Wiring

### The diamond dependency problem

`auths-radicle` depends on `radicle-core` (from the `bordumb/heartwood` fork).
`radicle-httpd` depends on `radicle` (from the same fork). If they resolve to
different copies of `radicle-core`, you get duplicate type errors where
`radicle_core::Did` from one copy is incompatible with the other.

### The patch solution

All three repos use `[patch]` sections to force local path resolution:

**heartwood/Cargo.toml:**
```toml
[patch."https://github.com/auths-dev/auths"]
auths-radicle = { path = "/Users/bordumb/.../auths/crates/auths-radicle" }

[patch."https://github.com/bordumb/heartwood"]
radicle-core = { path = "crates/radicle-core" }
radicle-crypto = { path = "crates/radicle-crypto" }
```

**radicle-httpd/Cargo.toml:**
```toml
[patch."https://github.com/auths-dev/auths"]
auths-radicle = { path = "/Users/bordumb/.../auths/crates/auths-radicle" }
auths-id = { path = "/Users/bordumb/.../auths/crates/auths-id" }
auths-verifier = { path = "/Users/bordumb/.../auths/crates/auths-verifier" }

[patch.crates-io]
radicle = { path = "/Users/bordumb/.../heartwood/crates/radicle" }
radicle-term = { path = "/Users/bordumb/.../heartwood/crates/radicle-term" }
# ... more crates ...

[patch."https://github.com/bordumb/heartwood"]
radicle-core = { path = "/Users/bordumb/.../heartwood/crates/radicle-core" }
radicle-crypto = { path = "/Users/bordumb/.../heartwood/crates/radicle-crypto" }
```

### Docker path rewriting

The Dockerfile rewrites all absolute local paths to container paths via `sed`:
```bash
sed -i 's|/Users/bordumb/workspace/repositories/auths-base/auths|/build/auths-base/auths|g' \
    /build/radicle-base/heartwood/Cargo.toml
```

This is fragile -- any new `[patch]` entry with a local path must be added to
the sed commands.

---

## 10. Debugging Silent Failures

### The `.ok()?` anti-pattern

The resolver's `find_controller_for_device` originally chained `.ok()?` on
every fallible operation:

```rust
fn find_controller_for_device(&self, device_did: &Did) -> Option<Did> {
    let id_path = self.identity_repo_path.as_ref().unwrap_or(&self.repo_path);
    let repo = Repository::open(id_path).ok()?;
    let att = self.read_device_attestation(&repo, device_did)?;
    att.issuer.to_string().parse::<Did>().ok()
}
```

When this returns `None`, there is no indication of which step failed:
repository open, ref lookup, tree traversal, blob read, or JSON
deserialization.

### Diagnostic approach

We added `eprintln!("[auths-debug] ...")` statements at each fallible step.
This immediately revealed the root cause: a hex string that was 130 characters
(65 bytes) instead of 128 (64 bytes), causing `Ed25519Signature` deserialization
to fail.

### Lesson

For functions that return `Option` and touch I/O (filesystem, git, serde),
prefer `match` with error logging over `.ok()?` -- at least behind a feature
flag or `tracing::debug!`. The cost of a log line is negligible compared to
hours of blind debugging on a remote container.

---

## 11. Future Work

### 11.1 Automatic registry sync via Radicle protocol

**Problem**: `refs/auths/registry` does not sync via Radicle's gossip protocol
because it only replicates `refs/rad/*`. Attestation data must be manually
pushed to each seed node.

**Proposal**: Extend Radicle's ref sync whitelist to include `refs/auths/*`, or
implement a dedicated "identity gossip" channel. Alternatively, store
attestations under `refs/rad/auths/registry` so they ride the existing sync
infrastructure. This would make identity data propagate automatically when a
repo is seeded, eliminating manual intervention.

### 11.2 CLI command: `rad identity`

**Problem**: Linking a device to a KERI identity currently requires manual Git
index manipulation (`git hash-object`, `git update-index`, `git write-tree`,
`git commit-tree`, `git update-ref`). This is error-prone and developer-hostile.

**Proposal**: A `rad identity link` command that:
1. Reads the device's `did:key` from the local Radicle profile.
2. Prompts for (or auto-discovers) the controller `did:keri`.
3. Constructs a properly-formatted attestation with correct hex lengths.
4. Commits it to `refs/auths/registry` in the identity repo.
5. Syncs to peers.

Similarly, `rad identity show` could display the current identity chain, and
`rad identity verify` could run local verification.

### 11.3 Eliminate the `[patch]` dependency maze

**Problem**: Three repos with cross-referencing `[patch]` sections using
absolute local paths. Docker builds require sed-based path rewriting. Adding a
new crate means updating patches in multiple Cargo.toml files and the
Dockerfile.

**Proposal**: Move to a Cargo workspace that spans all three repos, or publish
`auths-radicle`, `auths-verifier`, and `auths-id` to crates.io (even as
pre-release versions). This would replace `[patch]` with normal versioned
dependencies. For development, `cargo --config 'patch...'` can override at the
CLI level without polluting committed Cargo.toml files.

### 11.4 Structured error responses from the resolver

**Problem**: The resolver returns `Option<Did>` from
`find_controller_for_device`, collapsing all errors into `None`. The httpd
can't distinguish "no attestation exists" from "attestation is malformed" from
"repository is inaccessible."

**Proposal**: Return `Result<Option<Did>, IdentityError>` so the httpd can:
- Return 404 for "no attestation" (legitimate missing data).
- Return 500 for "repo open failed" or "deserialization error" (operational
  issues).
- Log actionable error details in production.

### 11.5 Signature verification in the resolver

**Problem**: `find_controller_for_device` reads the `issuer` field from the
attestation but does not verify the `identity_signature` or
`device_signature`. A malformed or tampered attestation would still be trusted.
Verification currently only happens in the frontend WASM module.

**Proposal**: Add an optional `verify: bool` parameter (or a separate
`verify_device_attestation` method) that checks both signatures against the
known public keys before returning the controller DID. This provides
defense-in-depth -- the backend would reject invalid attestations even if the
frontend is bypassed.

### 11.6 First-run identity bootstrap for seed nodes

**Problem**: When a seed node starts fresh, there is no attestation data. The
`refs/auths/registry` ref must be manually created via SSH. This makes seed
node provisioning a multi-step manual process.

**Proposal**: The entrypoint script could:
1. Check if `refs/auths/registry` exists in the identity repo.
2. If not, fetch it from a known peer (e.g., the user's primary node) via
   `git fetch`.
3. Or, accept a bootstrap bundle (a small tar/git-bundle) as a Fly.io secret
   that gets unpacked on first run.

### 11.7 Hot-reload identity data without restart

**Problem**: After updating `refs/auths/registry` on a running seed node, the
httpd immediately picks up the change (git2 opens the repo fresh on each
request). However, the `AUTHS_HOME` path is resolved once at startup. If the
path changes, the httpd must be restarted.

**Proposal**: This is mostly fine today since `AUTHS_HOME` doesn't change at
runtime. But if we support multiple identity repos in the future, the `Context`
could periodically re-scan or accept a reload signal.

### 11.8 Unified DID type across the ecosystem

**Problem**: `radicle::identity::Did` (published crate, `did:key` only) and
`radicle_core::Did` (fork, `did:key` + `did:keri`) are separate types. Code
must use string comparison to bridge them.

**Proposal**: Upstream the `Did::Keri` variant into the published
`radicle::identity::Did` type. This would eliminate the string bridge, enable
direct type-safe comparisons, and allow `repo.doc.delegates()` to return KERI
DIDs natively.

### 11.9 Attestation schema validation tooling

**Problem**: Manually constructing attestation JSON is fragile (see the 130 vs
128 hex char bug). There is no offline validation tool.

**Proposal**: An `auths attestation validate <file.json>` CLI command that:
1. Parses the JSON against the `Attestation` struct.
2. Validates hex field lengths (32 bytes for public keys, 64 bytes for
   signatures).
3. Optionally verifies signatures if public keys are available.
4. Prints a clear pass/fail report.

This could also be exposed as a `#[test]` helper for integration tests.

### 11.10 End-to-end integration test

**Problem**: There is no single test that exercises the full flow: create KERI
identity -> link device -> write attestation -> resolve via httpd -> verify in
frontend.

**Proposal**: A Docker Compose-based integration test that:
1. Spins up a Radicle node with a test profile.
2. Creates a KERI identity and device attestation.
3. Starts radicle-httpd pointed at the test storage.
4. Queries the `/delegates/{did}` endpoint and asserts `isKeri: true`.
5. Optionally runs a headless browser check against the explorer.

This would catch regressions in the serialization format, dependency wiring,
and end-to-end resolution path.
