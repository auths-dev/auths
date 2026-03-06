# Audit Prompt: Intuitive Platform Design

You are auditing the `auths` codebase for naming consistency, API intuitiveness, and
"Pit of Success" design — the principle that correct usage should be the path of least
resistance and mistakes should be hard to make accidentally.

The goal is to produce a concrete list of changes: renames, interface additions, missing
lifecycle steps, and inconsistencies — ordered by impact. Do not produce vague
recommendations. Every finding must cite a specific file and line number.

We want to build the "Stripe for identity" - intuitive, deep, and easy of use

---

## What auths Is

`auths` is a decentralized identity system for developers, agents, and CI pipelines. It
enables cryptographic commit signing with Git-native storage. No central server, no
blockchain — just Git and Ed25519 cryptography.

**Core concepts** (learn these before auditing):
- **Identity**: A root `did:keri:...` key pair stored in `~/.auths` (a Git repo)
- **Device**: A delegated `did:key:z...` key that signs on behalf of the identity
- **Attestation**: A signed JSON record linking a device to an identity, with scoped capabilities
- **Capability**: What a device is allowed to do — `SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys`
- **Bundle**: A self-contained JSON file with the full attestation chain, for offline verification
- **Allowed signers**: An ssh-keygen formatted file derived from the bundle, used for `git verify-commit`

**User personas**:
1. **Developer** — runs `auths` on a laptop, signs commits, manages devices, rotates keys
2. **Agent** — an MCP tool or CI bot that signs artifacts, publishes attestations, exchanges tokens
3. **CI pipeline** — GitHub Actions or similar, verifies commits in a range, enforces signing policy

---

## Codebase Map

Read these files to understand each layer before auditing:

```
Layer 0: crates/auths-crypto/src/         — Ed25519, DID:key encoding
Layer 1: crates/auths-verifier/src/       — standalone verify (FFI/WASM safe)
Layer 2: crates/auths-core/src/           — keychains, signing, port traits
Layer 3: crates/auths-id/src/             — identity lifecycle, attestations, KERI
         crates/auths-policy/src/         — policy expression engine
Layer 4: crates/auths-storage/src/        — Git storage adapters
         crates/auths-sdk/src/            — application workflows
Layer 5: crates/auths-infra-http/src/     — HTTP client adapters
Layer 6: crates/auths-cli/src/            — CLI commands (thin presentation layer)

Python SDK: packages/auths-python/python/auths/
Rust FFI:   crates/auths-mobile-ffi/src/lib.rs
            packages/auths-verifier-swift/src/lib.rs
```

**Key files to read first**:
- `crates/auths-sdk/src/workflows/` — the canonical SDK API surface
- `crates/auths-sdk/src/context.rs` — `AuthsContext` (the main SDK entry point)
- `packages/auths-python/python/auths/__init__.py` — Python public API
- `packages/auths-python/python/auths/_client.py` — `Auths` class (Python entry point)
- `crates/auths-cli/src/commands/` — CLI commands (mirrors what SDK should expose)
- `crates/auths-core/src/ports/` — port trait definitions

---

## Audit Goals

### 1. Full Lifecycle Completeness

For each of the three personas, map whether the SDK exposes every step of their lifecycle.
A persona should be able to complete their entire workflow using only `auths-sdk` (Rust) or
the `Auths` class (Python) — without dropping down to lower layers.

**Developer lifecycle**:
```
init identity → attest device → sign commit → verify commit → rotate keys → revoke device
```

**Agent lifecycle**:
```
get token → sign artifact → publish artifact attestation → verify artifact
```

**CI lifecycle**:
```
generate allowed_signers → verify commit range → enforce policy → report results
```

For each step in each lifecycle, answer:
- Does the SDK have a function for this? What is it called?
- Does the Python `Auths` class expose it? What is it called?
- Does the CLI have a command for this? What is it called?
- Is there a gap (missing at any layer)?
- Is the name at each layer consistent with the names at other layers?

Produce a table:

| Step | SDK function | Python method | CLI command | Gap? |
|------|-------------|---------------|-------------|------|
| init identity | `setup::initialize()` | `Auths().init()` | `auths init` | — |
| ... | ... | ... | ... | ... |

---

### 2. Naming Consistency Audit

Audit naming across the full stack. For each concept, the name should be the same word at
every layer (SDK → Python → CLI). If they differ, flag it.

**Check these concepts specifically**:

| Concept | What to look for |
|---------|-----------------|
| Identity creation | Is it `init`, `initialize`, `create`, `setup`? Is it consistent? |
| Device attestation | Is it `attest`, `delegate`, `authorize`, `provision`? |
| Commit signing | Is it `sign`, `sign_commit`, `commit_sign`? |
| Commit verification | Is it `verify`, `verify_commit`, `check`? |
| Key rotation | Is it `rotate`, `rotate_keys`, `key_rotate`? |
| Device revocation | Is it `revoke`, `revoke_device`, `remove`? |
| Allowed signers | Is it `generate_allowed_signers`, `allowed_signers_file`, `signers`? |
| Identity bundle | Is it `bundle`, `identity_bundle`, `export_bundle`? |
| Token exchange | Is it `get_token`, `exchange_token`, `token`? |
| Artifact signing | Is it `sign_artifact`, `artifact_sign`, `sign`? |
| Artifact publishing | Is it `publish_artifact`, `artifact_publish`, `publish`? |

For each inconsistency, cite:
- The SDK name and file
- The Python name and file
- The CLI name and file
- Your recommended canonical name

---

### 3. "Pit of Success" Design Audit

Identify places where a user can make a mistake that the API design could have prevented.

**Check**:

**a) Error messages**: When a function fails, does the error tell the user what to do next?
   - Check `crates/auths-core/src/error.rs` — does `AuthsErrorInfo::suggestion()` return
     actionable text for every variant?
   - Check Python `packages/auths-python/python/auths/_errors.py` — do error classes have
     useful `__str__` output?

**b) Missing guards**: Are there functions that will silently do the wrong thing if called
   in the wrong order?
   - Example: Can a user call `sign_artifact` before `init`? What happens?
   - Example: Can a user call `verify_commit` with no allowed_signers and get a confusing error?

**c) Discoverability**: If a user imports `from auths import Auths`, can they discover all
   available operations via tab completion / `help()`? Check:
   - `packages/auths-python/python/auths/__init__.py` — is `__all__` complete?
   - `packages/auths-python/python/auths/_client.py` — does `Auths` have methods for every
     lifecycle step, or do some require importing submodules?

**d) Default arguments**: Do functions have sensible defaults so the happy path requires
   minimal arguments?
   - Example: `verify_commit_range("HEAD~1..HEAD")` should work with no other arguments.
   - Flag any required argument that should have a default.

**e) Kwarg-only dangerous parameters**: Parameters that change behavior significantly
   (like `mode="warn"` vs `mode="enforce"`) should be keyword-only in Python.

---

### 4. Consistency of Feature Depth

Check that the SDK and Python SDK have feature parity — not that every internal function is
exposed, but that every user-facing capability at one layer is reachable from the other.

Compare:
- Every `auths-sdk/src/workflows/*.rs` public function → is there a Python equivalent?
- Every `Auths` class method → is there an SDK workflow backing it?
- Every CLI command in `crates/auths-cli/src/commands/` → is there an SDK workflow for it?

Flag gaps in either direction. A CLI command with no SDK backing is a violation of the
architecture. An SDK workflow with no Python binding is a missing feature.

---

### 5. FFI / Mobile API Surface

Read `crates/auths-mobile-ffi/src/lib.rs` and `packages/auths-verifier-swift/src/lib.rs`.

**Check**:
- Do the exported function names match the naming convention established in the SDK?
- Is the full developer lifecycle (init → attest → sign → verify) achievable from the FFI?
- Is the agent lifecycle (sign artifact → publish → get token) achievable from the FFI?
- Are there functions that exist in the FFI but not the SDK (logic that should be extracted)?

---

## Output Format

Produce your findings in four sections:

### Section A: Lifecycle Coverage Matrix

The table from Audit Goal 1 above. One row per lifecycle step, columns for SDK / Python / CLI
/ Gap.

### Section B: Naming Inconsistencies

For each inconsistency, one entry:
```
Concept: [name]
SDK:     [function name] in [file:line]
Python:  [method name] in [file:line]
CLI:     [command name] in [file:line]
Fix:     rename [X] to [Y] in [file]
```

### Section C: Pit of Success Issues

For each issue, one entry:
```
Issue: [short title]
Location: [file:line]
Problem: [what can go wrong]
Fix: [concrete change — add default, improve error message, make kwarg-only, etc.]
```

### Section D: Feature Gaps

For each gap, one entry:
```
Gap: [description]
Missing from: [SDK | Python | CLI | FFI]
Closest existing: [file:line if partial]
Recommended: add [function/method/command name] to [location]
```

---

## Constraints

- Every finding must cite a file path and line number. Do not make general observations.
- If you see a missing lifecycle step, note it. But try to refrain from
  suggesting new features that don't exist at any layer. Focus on missing steps for a full use case/lifecycle.
- Do not recommend renaming things that are already consistent. Only flag genuine
  inconsistencies.
- Prioritize findings by user impact. Developer lifecycle gaps are higher priority than
  FFI naming nits.
- Keep Section B and C findings actionable and small. The goal is a list of specific
  changes, not an essay.
