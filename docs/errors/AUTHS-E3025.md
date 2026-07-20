# AUTHS-E3025

**Crate:** `auths-core`

**Type:** `AgentError::HardwareKeyNotExportable`

## Message

Operation '{operation}' requires a software-backed key; hardware-backed keys (e.g. Secure Enclave) cannot export raw material

## Suggestion

Use a software-backed keychain backend for this operation, or re-initialize your identity without Secure Enclave
