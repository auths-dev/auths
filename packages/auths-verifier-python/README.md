# auths-verifier

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

# Verify a chain of attestations
report = verify_chain([att1_json, att2_json], root_public_key_hex)
if report.is_valid():
    print("Chain verified!")
```

## Verify commit signatures in CI

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

Start with `mode='warn'` during rollout (logs failures but doesn't block merges), then switch to `mode='enforce'` when ready.

## API reference

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `verify_attestation(json, pk_hex)` | `VerificationResult` | Verify single attestation |
| `verify_chain(jsons, root_pk_hex)` | `VerificationReport` | Verify attestation chain |
| `is_device_listed(id_did, dev_did, jsons)` | `bool` | Check device membership (no crypto) |
| `is_device_authorized(id_did, dev_did, jsons)` | `bool` | *Deprecated* -- use `is_device_listed` or `verify_device_authorization` |
| `verify_device_authorization(id_did, dev_did, jsons, pk_hex)` | `VerificationReport` | Full cryptographic device authorization |
| `verify_commit_range(range, bundle?, signers?, mode?)` | `VerifyResult` | Verify SSH signatures on git commits |
| `discover_layout(repo_root?)` | `LayoutInfo` | Find Auths identity data in a repo |

### Types

**`VerificationResult`** -- `valid: bool`, `error: Optional[str]`. Supports `if result:` syntax.

**`VerificationReport`** -- `status: VerificationStatus`, `chain: list[ChainLink]`, `warnings: list[str]`. Call `report.is_valid()`.

**`VerifyResult`** -- `commits: list[CommitResult]`, `passed: bool`, `mode: str`, `summary: str`. The `passed` field reflects the policy decision.

**`CommitResult`** -- `commit_sha: str`, `is_valid: bool`, `signer: Optional[str]`, `error: Optional[str]`, `error_code: Optional[str]`.

### Error codes

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

## Building from source

```bash
pip install maturin
maturin develop         # Development mode
maturin build --release # Release wheel
```

## Type checking

This package includes PEP 561 type stubs. `mypy` and `pyright` will use them automatically.

## License

MIT -- see [LICENSE](../../LICENSE).

## Links

- [Documentation](https://github.com/bordumb/auths/tree/main/packages/auths-verifier-python)
- [Repository](https://github.com/bordumb/auths)
