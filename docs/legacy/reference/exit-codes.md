# Exit Codes and Error Codes

## CLI exit codes

| Exit code | Meaning |
|-----------|---------|
| `0` | Success |
| `1` | Error (see error message for details) |

## Error codes

All Auths errors follow the format `AUTHS_<CATEGORY>`.

### Agent errors (auths-core)

| Code | Description | Suggestion |
|------|-------------|------------|
| `AUTHS_KEY_NOT_FOUND` | Key does not exist in storage | `auths key list` |
| `AUTHS_INCORRECT_PASSPHRASE` | Wrong passphrase | Re-enter correct passphrase |
| `AUTHS_MISSING_PASSPHRASE` | Passphrase required but not provided | Use `--passphrase` or `AUTHS_PASSPHRASE` |
| `AUTHS_SECURITY_ERROR` | Security constraint violation | |
| `AUTHS_CRYPTO_ERROR` | Cryptographic operation failed | |
| `AUTHS_KEY_DESERIALIZATION_ERROR` | Failed to parse stored key | |
| `AUTHS_SIGNING_FAILED` | Signature operation failed | |
| `AUTHS_PROTOCOL_ERROR` | Agent protocol error | |
| `AUTHS_IO_ERROR` | File system or I/O failure | |
| `AUTHS_GIT_ERROR` | Git operation failed | Ensure you're in a Git repository |
| `AUTHS_INVALID_INPUT` | Invalid input | |
| `AUTHS_STORAGE_ERROR` | Key storage failed | Check file permissions and disk space |
| `AUTHS_USER_CANCELLED` | User cancelled | |
| `AUTHS_BACKEND_UNAVAILABLE` | Keychain not accessible | `auths doctor` |
| `AUTHS_STORAGE_LOCKED` | Keychain is locked | Unlock platform keychain |
| `AUTHS_BACKEND_INIT_FAILED` | Keychain init failed | `auths doctor` |
| `AUTHS_CREDENTIAL_TOO_LARGE` | Credential exceeds platform limit | |
| `AUTHS_AGENT_LOCKED` | Agent idle timeout | `auths agent unlock` |

### Attestation errors (auths-verifier)

| Code | Description | Suggestion |
|------|-------------|------------|
| `AUTHS_VERIFICATION_ERROR` | Signature verification failed | Check key and attestation |
| `AUTHS_MISSING_CAPABILITY` | Required capability missing | Request attestation with capability |
| `AUTHS_SIGNING_ERROR` | Failed to create signature | |
| `AUTHS_DID_RESOLUTION_ERROR` | Cannot resolve DID | Check DID format |
| `AUTHS_SERIALIZATION_ERROR` | Serialization failure | |
| `AUTHS_INTERNAL_ERROR` | Unexpected internal error | |
| `AUTHS_ORG_VERIFICATION_FAILED` | Org attestation invalid | Check org identity config |
| `AUTHS_ORG_ATTESTATION_EXPIRED` | Org attestation expired | Request new org attestation |
| `AUTHS_ORG_DID_RESOLUTION_FAILED` | Cannot resolve org DID | Check org DID config |

## JSON error format

With `--output json`, errors are structured:

```json
{
  "success": false,
  "command": "key show",
  "error": "Key not found"
}
```

## Programmatic handling

### Rust

```rust
use auths_core::{AgentError, AuthsErrorInfo};

let code = err.error_code();           // "AUTHS_KEY_NOT_FOUND"
let suggestion = err.suggestion();      // Some("Run `auths key list`...")
```

### Shell

```bash
result=$(auths --output json key show my-key 2>&1)
success=$(echo "$result" | jq -r '.success')
if [ "$success" = "false" ]; then
    echo "Error: $(echo "$result" | jq -r '.error')"
fi
```
