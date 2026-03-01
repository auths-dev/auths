# Security Notes

Security-sensitive areas of the codebase and practices for contributors.

## Key handling

**Private keys never leave the keychain.**

The signing flow:

1. `auths-core` loads the encrypted key from the platform keychain
2. The key is decrypted in a `Zeroizing<>` container (memory cleared on drop)
3. Signing happens in protected memory
4. Only the signature is returned

Contributors must never:

- Log or print private key bytes
- Store keys in plain text
- Bypass the `SecureSigner` abstraction

## Unsafe code

Unsafe code is restricted to:

| Location | Purpose |
|----------|---------|
| `auths-verifier/src/ffi.rs` | C FFI boundary (feature-gated) |
| `auths-core` keychain FFI | macOS Security Framework calls |

All FFI boundaries must:

- Validate pointer arguments (null checks)
- Validate buffer lengths
- Use `panic::catch_unwind()` to prevent panics from crossing FFI
- Be gated behind feature flags

## Canonical JSON

Attestation signatures depend on canonical JSON serialization (`json-canon`). Changes to the `CanonicalAttestationData` struct or serialization logic can silently break all existing signatures.

**Before modifying**: Ensure the canonical representation includes all fields that should be signed. Test against existing attestation fixtures.

## Dependency policy

| Category | Policy |
|----------|--------|
| Crypto (`ring`) | Pin to audited versions. Update promptly for security fixes. |
| Serialization (`serde_json`, `json-canon`) | Stable, widely audited. |
| Platform FFI | Minimize unsafe surface. Use high-level wrappers where possible. |
| New dependencies | Minimize. `auths-verifier` must stay lightweight. |

## Clock sensitivity

The verifier allows 5-minute clock skew (`MAX_SKEW_SECS = 300`). Changes to this constant affect all timestamp validation.

## Reporting vulnerabilities

Report security issues privately via GitHub Security Advisories or email. Do not open public issues for security vulnerabilities.

## Threat model

See the full [threat model](../security/threat-model.md) for:

- Trust boundaries
- Attack vectors and mitigations
- Dependency analysis
- Audit checklist
