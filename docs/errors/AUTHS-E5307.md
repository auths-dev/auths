# AUTHS-E5307

**Crate:** `auths-sdk`

**Type:** `RotationError::HardwareKeyNotRotatable`

## Message

rotation requires a software-backed key; alias '{alias}' is hardware-backed (Secure Enclave) and cannot export the raw key material rotation needs

## Suggestion

Hardware-backed keys (Secure Enclave / HSM) cannot be rotated in-place; provision a software-backed identity or rotate by creating a new identity
