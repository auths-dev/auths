# Agent Provisioning

## Overview

Agent provisioning creates scoped, time-limited cryptographic identities for AI agents, CI/CD runners, and automated workloads. Each agent receives an attestation that grants specific capabilities (e.g., `sign:commit`) and can be revoked independently of the human identity that issued it.

## Identity Hierarchy

```
Human Identity (did:keri:E...)
├── Device 1 (did:key:z6Mk...)  ← laptop
│   └── Agent A (did:key:z6Mk...)  ← CI bot, scoped to sign:commit
├── Device 2 (did:key:z6Mk...)  ← phone
└── Workload (did:key:z6Mk...)  ← server process, scoped to deploy:staging
```

| Level | DID Method | Key Lifecycle | Storage |
|-------|-----------|---------------|---------|
| Human | `did:keri:E...` | KERI rotation | HSM or software keychain |
| Device | `did:key:z6Mk...` | Attested by human | Platform keychain |
| Agent | `did:key:z6Mk...` | Ephemeral or semi-persistent | File or environment |
| Workload | `did:key:z6Mk...` | Short-lived, auto-provisioned | Environment variable |

## Provisioning Flow

### 1. Create Human Identity

```bash
# Software-backed (default)
auths init --profile developer

# HSM-backed (PKCS#11)
export AUTHS_KEYCHAIN_BACKEND=pkcs11
export AUTHS_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
export AUTHS_PKCS11_TOKEN_LABEL=auths
export AUTHS_PKCS11_PIN=12345678
auths init --profile developer
```

### 2. Provision Agent with Scoped Attestation

```bash
auths attest \
  --subject did:key:z6MkAgent... \
  --capabilities "sign:commit" \
  --signer-type agent \
  --expires-in 24h
```

The attestation is dual-signed by the issuer's identity key and the device key.

### 3. Agent Receives OIDC Token (Optional)

If the OIDC bridge is running, the agent exchanges its attestation chain for a JWT:

```bash
curl -X POST http://localhost:3000/api/v1/token \
  -H "Content-Type: application/json" \
  -d '{"attestation_chain": [...], "root_public_key": "...", "requested_capabilities": ["sign:commit"]}'
```

### 4. Agent Signs with Scoped Capabilities

The agent's signing operations are policy-evaluated. Each signature checks:
- Attestation chain is valid
- Agent is not revoked
- Attestation has not expired
- Requested capability is in scope

### 5. Revocation

```bash
# Revoke an agent
auths revoke --subject did:key:z6MkAgent...

# Verify revocation took effect
auths device list --include-revoked
```

Revocation is immediate. Existing signatures remain valid (they were valid at signing time), but new signing operations fail.

## Attestation Structure

```json
{
  "version": "1.0",
  "rid": "unique-attestation-id",
  "issuer": "did:keri:EHumanIdentity...",
  "subject": "did:key:z6MkAgent...",
  "device_public_key": "z6MkDevice...",
  "identity_signature": "base64...",
  "device_signature": "base64...",
  "capabilities": ["sign:commit"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

## HSM-Backed Provisioning

When using PKCS#11, the human identity key never leaves hardware:

| Operation | Key Location |
|-----------|-------------|
| Key generation | On HSM token |
| Attestation signing | Delegated to HSM via `CKM_EDDSA` |
| Key rotation | New key generated on HSM |
| Key export | Blocked (`CKA_EXTRACTABLE=false`) |

Compatible HSMs: YubiKey HSM2, Thales Luna, Nitrokey HSM, SoftHSMv2 (testing).

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AUTHS_PKCS11_LIBRARY` | Path to PKCS#11 shared library |
| `AUTHS_PKCS11_SLOT` | Numeric slot ID (mutually exclusive with token label) |
| `AUTHS_PKCS11_TOKEN_LABEL` | Token label for slot lookup |
| `AUTHS_PKCS11_PIN` | User PIN for HSM authentication |
| `AUTHS_PKCS11_KEY_LABEL` | Label for the Ed25519 key object |

## Policy Evaluation

Policies control what agents can do:

```json
{
  "and": [
    {"is_agent": true},
    {"has_capability": "sign:commit"},
    {"not_revoked": true},
    {"not_expired": true},
    {"max_chain_depth": 2}
  ]
}
```

```bash
# Lint a policy
auths policy lint policy.json

# Explain a policy decision
auths policy explain policy.json --context context.json
```

## CLI Quick Reference

```bash
# Initialize identity
auths init --profile developer --non-interactive

# Provision agent
auths attest --subject <agent-did> --capabilities "sign:commit" --expires-in 24h

# List devices and agents
auths device list
auths device list --include-revoked

# Revoke an agent
auths revoke --subject <agent-did>

# Export identity bundle
auths id export-bundle --output bundle.json

# Verify a commit
auths verify HEAD
```
