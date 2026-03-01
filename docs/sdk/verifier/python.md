# Python Bindings

The `auths-verifier` Python package provides native-speed attestation verification via PyO3 bindings to the Rust `auths-verifier` crate. It also includes a pure-Python module for verifying SSH commit signatures against Auths identity bundles.

## Installation

```bash
pip install auths-verifier
```

Requirements: Python 3.8+

The package ships pre-built wheels for common platforms. If no wheel is available, `pip` falls back to a source build (requires the Rust toolchain and `maturin`).

## Quick start

```python
from auths_verifier import verify_attestation, verify_chain

# Verify a single attestation
result = verify_attestation(attestation_json, issuer_public_key_hex)
if result.valid:
    print("Attestation is valid!")
else:
    print(f"Verification failed: {result.error}")

# Verify a chain of attestations
report = verify_chain([att1_json, att2_json], root_public_key_hex)
if report.is_valid():
    print("Chain verified!")
```

## API reference

### Verification functions

#### `verify_attestation(attestation_json, issuer_pk_hex)`

Verify a single attestation against an issuer's Ed25519 public key.

```python
from auths_verifier import verify_attestation

result = verify_attestation(
    '{"version":1,"rid":"...","issuer":"did:keri:E...","subject":"did:key:z6Mk...","device_public_key":"...","identity_signature":"...","device_signature":"...","revoked":false}',
    'a1b2c3d4e5f67890...'  # 64 hex characters (32-byte Ed25519 key)
)

if result.valid:
    print("Valid!")
else:
    print(f"Error: {result.error}")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `attestation_json` | `str` | The attestation as a JSON string |
| `issuer_pk_hex` | `str` | Issuer's Ed25519 public key in hex (64 characters) |

Returns a `VerificationResult`. Raises `ValueError` for invalid inputs (bad JSON, invalid hex, wrong key length).

#### `verify_chain(attestations_json, root_pk_hex)`

Verify an ordered chain of attestations from a root identity to a leaf device.

```python
from auths_verifier import verify_chain

report = verify_chain(
    [att1_json, att2_json, att3_json],
    root_public_key_hex
)

if report.is_valid():
    print(f"Chain verified with {len(report.chain)} links")
else:
    print(f"Chain invalid: {report.status.status_type}")
    for link in report.chain:
        if not link.valid:
            print(f"  Failed: {link.issuer} -> {link.subject}: {link.error}")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `attestations_json` | `list[str]` | List of attestation JSON strings |
| `root_pk_hex` | `str` | Root identity's Ed25519 public key in hex |

Returns a `VerificationReport`. Raises `ValueError` for invalid inputs, `RuntimeError` for internal errors.

#### `verify_device_authorization(identity_did, device_did, attestations_json, identity_pk_hex)`

Full cryptographic verification that a device is authorized under an identity.

```python
from auths_verifier import verify_device_authorization

report = verify_device_authorization(
    "did:keri:Eabc123...",        # identity DID
    "did:key:z6Mk...",            # device DID
    [att1_json, att2_json],       # attestation chain
    "a1b2c3d4e5f67890..."         # identity public key hex
)

if report.is_valid():
    print("Device is cryptographically authorized!")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `identity_did` | `str` | The identity DID string |
| `device_did` | `str` | The device DID string |
| `attestations_json` | `list[str]` | List of attestation JSON strings |
| `identity_pk_hex` | `str` | Identity's Ed25519 public key in hex (64 characters) |

Returns a `VerificationReport`. Raises `ValueError` for invalid inputs, `RuntimeError` for internal errors.

### Signing functions

#### `sign_bytes(private_key_hex, message)`

Sign arbitrary bytes with an Ed25519 private key.

```python
from auths_verifier import sign_bytes

signature_hex = sign_bytes(
    "deadbeef" * 8,  # 64 hex characters (32-byte Ed25519 seed)
    b"hello world"
)
assert len(signature_hex) == 128  # 64-byte signature, hex-encoded
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `private_key_hex` | `str` | Ed25519 seed as hex string (64 characters = 32 bytes) |
| `message` | `bytes` | The bytes to sign |

Returns a hex-encoded Ed25519 signature (128 characters = 64 bytes).

**Security note:** Python strings are immutable and not zeroizable. For production use, store keys in a secure enclave or secret manager rather than passing them as hex strings.

#### `sign_action(private_key_hex, action_type, payload_json, identity_did)`

Sign an action envelope per the Auths action envelope specification. Uses JSON Canonicalization (RFC 8785) for deterministic signing input.

```python
from auths_verifier import sign_action

envelope_json = sign_action(
    private_key_hex,
    "tool_call",
    '{"tool": "read_file", "path": "/etc/config.json"}',
    "did:keri:EBf7Y2p..."
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `private_key_hex` | `str` | Ed25519 seed as hex (64 characters) |
| `action_type` | `str` | Application-defined action type (e.g. `"tool_call"`) |
| `payload_json` | `str` | JSON string for the payload field |
| `identity_did` | `str` | Signer's identity DID |

Returns a JSON string of the complete signed envelope containing `version`, `type`, `identity`, `payload`, `timestamp`, and `signature` fields.

#### `verify_action_envelope(envelope_json, public_key_hex)`

Verify an action envelope's Ed25519 signature.

```python
from auths_verifier import verify_action_envelope

result = verify_action_envelope(envelope_json, public_key_hex)
if result.valid:
    print("Action verified!")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `envelope_json` | `str` | The complete action envelope as a JSON string |
| `public_key_hex` | `str` | Signer's Ed25519 public key in hex (64 characters) |

Returns a `VerificationResult`.

### Git commit verification

#### `verify_commit_range(commit_range, identity_bundle=None, allowed_signers=".auths/allowed_signers", mode="enforce")`

Verify SSH signatures for every commit in a git revision range. Requires `git` and `ssh-keygen` on PATH.

```python
from auths_verifier import verify_commit_range

result = verify_commit_range(
    "origin/main..HEAD",
    identity_bundle=".auths/identity-bundle.json",
    mode="enforce"
)

print(result.summary)  # e.g. "3/3 commits verified"
for commit in result.commits:
    if not commit.is_valid:
        print(f"  FAIL {commit.commit_sha[:8]}: {commit.error_code} -- {commit.error}")

if not result.passed:
    raise SystemExit(1)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `commit_range` | `str` | required | Git revision range (e.g. `origin/main..HEAD`) |
| `identity_bundle` | `str \| None` | `None` | Path to identity-bundle JSON file |
| `allowed_signers` | `str` | `".auths/allowed_signers"` | Path to ssh-keygen allowed_signers file |
| `mode` | `str` | `"enforce"` | `"enforce"` or `"warn"` |

When `identity_bundle` is provided, device keys from the attestation chain are used for verification and each device's revocation/expiration status is checked.

#### `discover_layout(repo_root=".")`

Find Auths identity data in a repository by checking for `.auths/identity-bundle.json` then `refs/auths/*`.

```python
from auths_verifier import discover_layout, LayoutError

try:
    layout = discover_layout(".")
    print(f"Found via {layout.source}: bundle={layout.bundle}, refs={layout.refs}")
except LayoutError as e:
    print(f"No identity data: {e}")
```

### Types

#### `VerificationResult`

Result of a single attestation verification.

| Attribute | Type | Description |
|-----------|------|-------------|
| `valid` | `bool` | Whether the attestation is valid |
| `error` | `str \| None` | Error message if verification failed |

Supports boolean context: `if result:` is equivalent to `if result.valid:`.

#### `VerificationStatus`

Status of a verification operation.

| Attribute | Type | Description |
|-----------|------|-------------|
| `status_type` | `str` | One of: `Valid`, `Expired`, `Revoked`, `InvalidSignature`, `BrokenChain`, `InsufficientWitnesses` |
| `at` | `str \| None` | ISO 8601 timestamp for `Expired`/`Revoked` |
| `step` | `int \| None` | Chain step index for `InvalidSignature` |
| `missing_link` | `str \| None` | Description for `BrokenChain` |
| `required` | `int \| None` | Witness count for `InsufficientWitnesses` |
| `verified` | `int \| None` | Witness count for `InsufficientWitnesses` |

Has an `is_valid()` method that returns `True` when `status_type == "Valid"`.

#### `ChainLink`

A single link in the attestation chain.

| Attribute | Type | Description |
|-----------|------|-------------|
| `issuer` | `str` | Issuer DID |
| `subject` | `str` | Subject DID |
| `valid` | `bool` | Whether this link verified |
| `error` | `str \| None` | Error message if failed |

#### `VerificationReport`

Complete verification report for chain verification.

| Attribute | Type | Description |
|-----------|------|-------------|
| `status` | `VerificationStatus` | Overall status |
| `chain` | `list[ChainLink]` | Details of each link |
| `warnings` | `list[str]` | Non-fatal warnings |

Has an `is_valid()` method that returns `True` when `status.status_type == "Valid"`.

#### `VerifyResult`

Wrapper around commit verification results.

| Attribute | Type | Description |
|-----------|------|-------------|
| `commits` | `list[CommitResult]` | Per-commit results |
| `passed` | `bool` | `True` if policy allows merge |
| `mode` | `str` | `"enforce"` or `"warn"` |
| `summary` | `str` | Human-readable summary |

#### `CommitResult`

Result of verifying a single commit's SSH signature.

| Attribute | Type | Description |
|-----------|------|-------------|
| `commit_sha` | `str` | Full commit SHA |
| `is_valid` | `bool` | Whether the commit signature is valid |
| `signer` | `str \| None` | Principal who signed |
| `error` | `str \| None` | Error message if failed |
| `error_code` | `str \| None` | Machine-readable error code |

### Error codes

Error codes from `ErrorCode` for commit verification failures:

| Code | Meaning |
|------|---------|
| `UNSIGNED` | Commit has no signature |
| `GPG_NOT_SUPPORTED` | Commit uses GPG, not SSH |
| `UNKNOWN_SIGNER` | Signed, but signer not in allowed_signers |
| `INVALID_SIGNATURE` | Signature present but verification failed |
| `NO_ATTESTATION_FOUND` | Valid key, but no matching Auths attestation |
| `DEVICE_REVOKED` | Device attestation was revoked |
| `DEVICE_EXPIRED` | Device attestation expired |
| `LAYOUT_DISCOVERY_FAILED` | No `.auths/` data found in repo |

## CI integration

### GitHub Actions

```yaml
# .github/workflows/verify-signatures.yml
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

Start with `mode='warn'` during rollout (logs failures but does not block merges), then switch to `mode='enforce'` when ready.

## Building from source

The Python package uses [maturin](https://github.com/PyO3/maturin) to build the PyO3 Rust extension:

```bash
cd packages/auths-verifier-python

# Install maturin
pip install maturin

# Development mode (editable install, debug build)
maturin develop

# Release wheel
maturin build --release

# Install the release wheel
pip install target/wheels/auths_verifier-*.whl
```

The Rust source lives in `packages/auths-verifier-python/src/lib.rs` and depends on the `auths-verifier` crate at `crates/auths-verifier`. The package is built separately from the main Cargo workspace (it declares its own `[workspace]` in `Cargo.toml`).

### Build configuration

Key settings from `pyproject.toml`:

| Setting | Value | Description |
|---------|-------|-------------|
| Build backend | `maturin` | PyO3 build tool |
| Module name | `auths_verifier._native` | Native extension target |
| Python ABI | `abi3-py38` | Stable ABI, single wheel for Python 3.8+ |
| Strip symbols | `true` | Smaller release binaries |

## Type checking

The package includes PEP 561 type stubs (`__init__.pyi` and `py.typed`). Type checkers such as `mypy` and `pyright` pick them up automatically:

```bash
mypy your_script.py  # type stubs are discovered via py.typed marker
```

## Architecture

The native module (`_native`) is a PyO3 extension that bridges synchronous Python calls to the async Rust verification core via an internal Tokio runtime:

```
Python call
  -> PyO3 function (src/lib.rs)
    -> tokio::runtime::Runtime::new().block_on(...)
      -> auths_verifier::verify_with_keys / verify_chain / ...
    <- Result mapped to PyResult
  <- VerificationResult / VerificationReport
```

The git commit verification module (`auths_verifier.git`) is pure Python. It shells out to `git` and `ssh-keygen` for signature extraction and verification, then checks device attestation status against identity bundle data.
