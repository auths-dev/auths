# Auths Error Codes

This document provides a comprehensive reference for all Auths error codes, their meanings, and suggested resolutions.

## Error Code Format

All Auths errors follow the naming convention:

```
AUTHS_<CATEGORY>
```

Where `<CATEGORY>` describes the error type. Error codes are stable identifiers that can be used for:

- **Programmatic error handling** in scripts and automation
- **Internationalization** of error messages
- **Logging and debugging** to correlate issues

## Agent Errors (auths-core)

These errors originate from the Auths agent and core library operations.

| Code | Description | Suggestion |
|------|-------------|------------|
| `AUTHS_KEY_NOT_FOUND` | Requested key does not exist in storage | Run `auths key list` to see available keys |
| `AUTHS_INCORRECT_PASSPHRASE` | Provided passphrase does not match | Check your passphrase and try again |
| `AUTHS_MISSING_PASSPHRASE` | Operation requires a passphrase but none was provided | Provide a passphrase with `--passphrase` or set `AUTHS_PASSPHRASE` |
| `AUTHS_SECURITY_ERROR` | Security constraint violation | — |
| `AUTHS_CRYPTO_ERROR` | Cryptographic operation failed | — |
| `AUTHS_KEY_DESERIALIZATION_ERROR` | Failed to parse stored key data | — |
| `AUTHS_SIGNING_FAILED` | Signature operation failed | — |
| `AUTHS_PROTOCOL_ERROR` | Agent protocol communication error | — |
| `AUTHS_IO_ERROR` | File system or I/O operation failed | — |
| `AUTHS_GIT_ERROR` | Git operation failed | Ensure you're in a Git repository |
| `AUTHS_INVALID_INPUT` | Invalid input provided | — |
| `AUTHS_MUTEX_ERROR` | Internal lock contention error | — |
| `AUTHS_STORAGE_ERROR` | Key storage operation failed | Check file permissions and disk space |
| `AUTHS_USER_CANCELLED` | User cancelled the operation | Run the command again and provide the required input |
| `AUTHS_BACKEND_UNAVAILABLE` | Keychain backend is not available | Run `auths doctor` to diagnose keychain issues |
| `AUTHS_STORAGE_LOCKED` | Storage is locked and requires authentication | Authenticate with your platform keychain |
| `AUTHS_BACKEND_INIT_FAILED` | Failed to initialize keychain backend | Run `auths doctor` to diagnose keychain issues |
| `AUTHS_CREDENTIAL_TOO_LARGE` | Credential exceeds platform size limit | — |
| `AUTHS_AGENT_LOCKED` | Agent is locked due to idle timeout | Run `auths agent unlock` or restart with `auths agent start` |

## Attestation Errors (auths-verifier)

These errors originate from attestation verification operations.

| Code | Description | Suggestion |
|------|-------------|------------|
| `AUTHS_VERIFICATION_ERROR` | Signature verification failed | Verify the attestation was signed with the correct key |
| `AUTHS_MISSING_CAPABILITY` | Required capability not present in attestation | Request an attestation with the required capability |
| `AUTHS_SIGNING_ERROR` | Failed to create signature | — |
| `AUTHS_DID_RESOLUTION_ERROR` | Could not resolve DID to public key | Check that the DID is valid and resolvable |
| `AUTHS_SERIALIZATION_ERROR` | Failed to serialize/deserialize data | — |
| `AUTHS_INVALID_INPUT` | Invalid input provided | — |
| `AUTHS_CRYPTO_ERROR` | Cryptographic operation failed | — |
| `AUTHS_INTERNAL_ERROR` | Unexpected internal error | — |
| `AUTHS_ORG_VERIFICATION_FAILED` | Organizational attestation verification failed | Verify organizational identity is properly configured |
| `AUTHS_ORG_ATTESTATION_EXPIRED` | Organizational attestation has expired | Request a new organizational attestation from the admin |
| `AUTHS_ORG_DID_RESOLUTION_FAILED` | Could not resolve organization's DID | Check that the organization's DID is correctly configured |

## Exit Codes

Auths CLI commands use standard exit codes:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success |
| `1` | General error (see error message for details) |

## Programmatic Error Handling

### Rust

When using `auths-core` or `auths-verifier` as libraries, you can access error metadata via the `AuthsErrorInfo` trait:

```rust
use auths_core::{AgentError, AuthsErrorInfo};

fn handle_error(err: AgentError) {
    // Get the stable error code
    let code = err.error_code();
    println!("Error code: {}", code);

    // Get actionable suggestion if available
    if let Some(suggestion) = err.suggestion() {
        println!("Suggestion: {}", suggestion);
    }

    // Match on specific error codes
    match code {
        "AUTHS_KEY_NOT_FOUND" => {
            // Handle missing key
        }
        "AUTHS_AGENT_LOCKED" => {
            // Prompt user to unlock
        }
        _ => {
            // Generic error handling
        }
    }
}
```

### Shell Scripts

When using the CLI with `--output json`, errors are returned in a structured format:

```bash
#!/bin/bash

result=$(auths --output json key show my-key 2>&1)
success=$(echo "$result" | jq -r '.success')

if [ "$success" = "false" ]; then
    error=$(echo "$result" | jq -r '.error')
    echo "Operation failed: $error"
    exit 1
fi
```

### JSON Error Format

When using `--output json`, errors are returned as:

```json
{
  "success": false,
  "command": "key show",
  "error": "Key not found"
}
```

## Troubleshooting Common Errors

### AUTHS_KEY_NOT_FOUND

This error occurs when attempting to use a key that doesn't exist.

**Solutions:**
1. List available keys: `auths key list`
2. Generate a new key: `auths key generate --alias <name>`
3. Check the key alias spelling

### AUTHS_BACKEND_UNAVAILABLE

This error indicates the platform keychain cannot be accessed.

**Solutions:**
1. Run diagnostics: `auths doctor`
2. Check keychain access permissions
3. On macOS: Ensure Keychain Access is unlocked
4. On Linux: Verify the Secret Service daemon is running

### AUTHS_AGENT_LOCKED

The agent has locked itself due to inactivity timeout.

**Solutions:**
1. Unlock the agent: `auths agent unlock`
2. Restart the agent: `auths agent start`
3. Adjust timeout: `auths agent start --timeout <seconds>`

### AUTHS_GIT_ERROR

Git operations require being inside a valid repository.

**Solutions:**
1. Navigate to a Git repository
2. Initialize a new repository: `git init`
3. Check Git installation: `git --version`
