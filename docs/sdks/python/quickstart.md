# Python SDK

Python library for verifying Auths attestations, powered by Rust via PyO3.

## Installation

```bash
pip install auths-verifier
```

Requirements: Python 3.8+

## Quick start

```python
from auths_verifier import verify_attestation, verify_chain

# Verify a single attestation
result = verify_attestation(attestation_json, issuer_public_key_hex)
if result.valid:
    print("Attestation is valid!")
else:
    print(f"Verification failed: {result.error}")
```

## Verify a chain

```python
report = verify_chain([att1_json, att2_json], root_public_key_hex)
if report.is_valid():
    print("Chain verified!")
else:
    print(f"Chain invalid: {report.status.status_type}")
```

## Check device membership

```python
from auths_verifier import is_device_listed

listed = is_device_listed(
    identity_did="did:key:z6Mk...",
    device_did="did:key:z6MK...",
    attestations_json=[att1_json, att2_json]
)
```

!!! warning
    `is_device_listed()` does NOT verify cryptographic signatures. Use `verify_device_authorization()` for full verification.

## Full device authorization

```python
from auths_verifier import verify_device_authorization

report = verify_device_authorization(
    identity_did="did:key:z6Mk...",
    device_did="did:key:z6MK...",
    attestations_json=[att1_json, att2_json],
    identity_pk_hex=identity_public_key_hex
)
if report.is_valid():
    print("Device is cryptographically authorized!")
```

## Verify commit signatures

The `verify_commit_range()` function verifies SSH signatures on git commits -- ideal for CI pipelines.

```python
from auths_verifier import verify_commit_range

result = verify_commit_range(
    "origin/main..HEAD",
    identity_bundle=".auths/identity-bundle.json",
    mode="enforce"   # or "warn" for gradual rollout
)

print(result.summary)  # "3/3 commits verified"
print(result.passed)   # True/False (policy decision)

for c in result.commits:
    if not c.is_valid:
        print(f"FAIL {c.commit_sha[:8]}: {c.error_code} -- {c.error}")
```

Requires `git` and `ssh-keygen` on PATH (both available on GitHub Actions `ubuntu-latest`).

### Policy modes

| Mode | Behavior |
|------|----------|
| `enforce` | `passed=False` if any commit fails. CI exits non-zero. |
| `warn` | `passed=True` always. Failures are logged but don't block merges. |

Start with `warn` during rollout, then switch to `enforce` team-by-team.

### Error codes

Each failed `CommitResult` carries a stable `error_code` for automation:

| Code | Meaning | Remediation |
|------|---------|-------------|
| `UNSIGNED` | No signature at all | Enable SSH signing: `git config commit.gpgsign true` |
| `GPG_NOT_SUPPORTED` | Uses GPG, not SSH | Switch to SSH signing |
| `UNKNOWN_SIGNER` | Signer not in allowed_signers | Export a new identity bundle |
| `INVALID_SIGNATURE` | Signature verification failed | Re-sign the commit |
| `NO_ATTESTATION_FOUND` | Valid key, no Auths attestation | Run `auths device add` |
| `DEVICE_REVOKED` | Device was revoked | Contact security team |
| `DEVICE_EXPIRED` | Device attestation expired | Renew attestation |
| `LAYOUT_DISCOVERY_FAILED` | No `.auths/` data in repo | Run `auths id export-bundle --output .auths/identity-bundle.json` |

### CI recipe

```yaml
name: Verify Commit Signatures
on: [pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: pip install auths-verifier
      - run: |
          python -c "
          from auths_verifier import verify_commit_range
          result = verify_commit_range('origin/main..HEAD',
              identity_bundle='.auths/identity-bundle.json',
              mode='enforce')
          print(result.summary)
          for c in result.commits:
              if not c.is_valid:
                  print(f'  FAIL {c.commit_sha[:8]}: {c.error_code} -- {c.error}')
          raise SystemExit(0 if result.passed else 1)
          "
```

For org-wide rollout, use the [reusable workflow](../../cloud-ci/ci-verification.md).

### Layout discovery

If you don't pass `identity_bundle` or `allowed_signers` explicitly, the SDK auto-discovers Auths data:

1. Checks `.auths/identity-bundle.json` (file-based convention)
2. Checks `refs/auths/*` (Git ref storage)
3. Returns `LAYOUT_DISCOVERY_FAILED` with a remediation command if nothing found

```python
from auths_verifier import discover_layout

info = discover_layout()  # LayoutInfo(bundle=".auths/identity-bundle.json", source="file")
```

## API reference

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `verify_attestation(json, pk_hex)` | `VerificationResult` | Verify single attestation |
| `verify_chain(jsons, root_pk_hex)` | `VerificationReport` | Verify attestation chain |
| `is_device_listed(id_did, dev_did, jsons)` | `bool` | Check device membership (no crypto) |
| `is_device_authorized(id_did, dev_did, jsons)` | `bool` | *Deprecated* |
| `verify_device_authorization(id_did, dev_did, jsons, pk_hex)` | `VerificationReport` | Full crypto device auth |
| `verify_commit_range(range, bundle?, signers?, mode?)` | `VerifyResult` | Verify git commit signatures |
| `discover_layout(repo_root?)` | `LayoutInfo` | Find Auths identity data |

### Types

**`VerificationResult`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `valid` | `bool` | Whether verification succeeded |
| `error` | `Optional[str]` | Error message if failed |

Supports `if result:` syntax via `__bool__()`.

**`VerificationStatus`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `status_type` | `str` | `"Valid"`, `"Expired"`, `"Revoked"`, `"InvalidSignature"`, `"BrokenChain"` |
| `at` | `Optional[str]` | Timestamp for Expired/Revoked |
| `step` | `Optional[int]` | Step number for InvalidSignature |
| `missing_link` | `Optional[str]` | Link ID for BrokenChain |

**`VerificationReport`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `status` | `VerificationStatus` | Overall status |
| `chain` | `List[ChainLink]` | Per-link details |
| `warnings` | `List[str]` | Non-fatal warnings |

**`VerifyResult`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `commits` | `List[CommitResult]` | Per-commit verification results |
| `passed` | `bool` | Policy decision: allow merge? |
| `mode` | `str` | `"enforce"` or `"warn"` |
| `summary` | `str` | Human-readable summary |

**`CommitResult`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `commit_sha` | `str` | Full commit SHA (or `"<layout>"` for config errors) |
| `is_valid` | `bool` | Whether signature is valid |
| `signer` | `Optional[str]` | Identified signer principal |
| `error` | `Optional[str]` | Error message if failed |
| `error_code` | `Optional[str]` | One of `ErrorCode` constants |

**`LayoutInfo`**

| Attribute | Type | Description |
|-----------|------|-------------|
| `bundle` | `Optional[str]` | Path to identity-bundle.json |
| `refs` | `Optional[List[str]]` | List of refs/auths/* refs |
| `source` | `str` | `"file"` or `"git-refs"` |

## Type checking

This package includes PEP 561 type stubs. `mypy` and `pyright` will use them automatically.

## Building from source

```bash
pip install maturin
maturin develop         # Development mode
maturin build --release # Release wheel
```
