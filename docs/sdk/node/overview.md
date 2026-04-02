# Node SDK Overview

Full-featured Node.js SDK for Auths decentralized identity, backed by Rust via napi-rs. Create identities, sign commits and artifacts, verify attestation chains, and manage organizations — all from TypeScript/JavaScript.

## Installation

```bash
npm install @auths-dev/sdk
```

Pre-built native binaries for Linux, macOS, and Windows (x86_64 and aarch64). No Rust toolchain required. Requires Node.js 20+.

## Quick taste

```typescript
import { Auths } from '@auths-dev/sdk'

const auths = new Auths()
const identity = auths.identities.create({ label: 'laptop' })
const result = auths.commits.sign({
  data: commitBytes,
  identityKeyAlias: identity.did,
})
console.log(result.signaturePem)
```

## What you can do

| Feature | Service | API Reference |
|---------|---------|---------------|
| Create and rotate identities | `auths.identities` | [API Reference](api/index.md#identityservice) |
| Link, extend, and revoke devices | `auths.devices` | [API Reference](api/index.md#deviceservice) |
| Query attestation chains | `auths.attestations` | [API Reference](api/index.md#attestationservice) |
| Sign commits and artifacts | `auths.commits`, `auths.artifacts` | [API Reference](api/index.md#commitservice) |
| Verify attestations and chains | `auths.verify()`, `verifyChain()` | [API Reference](api/index.md#verifychain) |
| Build authorization policies | `PolicyBuilder` | [API Reference](api/index.md#policybuilder) |
| Manage organizations | `auths.orgs` | [API Reference](api/index.md#orgservice) |
| Cross-device pairing | `auths.pairing` | [API Reference](api/index.md#pairingservice) |
| Trust store management | `auths.trust` | [API Reference](api/index.md#trustservice) |
| Repository audit reports | `auths.audit` | [API Reference](api/index.md#auditservice) |

## Architecture

The Node SDK is a thin TypeScript wrapper over the Rust `auths-sdk` crate via napi-rs. All cryptographic operations happen in Rust — the TypeScript layer provides idiomatic service classes, typed interfaces, and error mapping.

```text
TypeScript (lib/*.ts)  →  napi-rs bridge (native)  →  Rust (auths-sdk)
```

The SDK uses a Stripe-style API design: a single `Auths` client provides access to domain-specific services via properties (`auths.identities`, `auths.devices`, `auths.signing`, etc.).

## Configuration

```typescript
// Auto-discover (uses ~/.auths)
const auths = new Auths()

// Explicit repo path
const auths = new Auths({ repoPath: '/path/to/identity-repo' })

// With passphrase (or set AUTHS_PASSPHRASE env var)
const auths = new Auths({ passphrase: 'my-secret' })
```

For headless/CI environments without a system keychain, set `AUTHS_KEYCHAIN_BACKEND=file`.

## Next steps

- [Quickstart](quickstart.md) — end-to-end walkthrough
- [API Reference](api/index.md) — full class and function docs
- [Errors](errors.md) — error hierarchy and codes
