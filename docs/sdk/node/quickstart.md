# Node SDK Quickstart

Get from `npm install` to verified attestation in under 2 minutes.

## Install

```bash
npm install @auths-dev/sdk
```

Requires Node 18+. Native Ed25519 via Rust (N-API) — no OpenSSL dependency.

## Verify an attestation (no client needed)

The most common use case: you have a `.auths.json` file and want to check if it's valid.

```typescript
import { verifyAttestation } from '@auths-dev/sdk'

import { readFileSync } from 'fs'
const attestationJson = readFileSync('release.tar.gz.auths.json', 'utf8')

const result = verifyAttestation(attestationJson, issuerPublicKeyHex)
console.log(result.valid)  // true
console.log(result.error)  // undefined
```

## Verify an attestation chain

Check that a device was authorized by an identity, with full delegation chain verification:

```typescript
import { verifyChain } from '@auths-dev/sdk'

const report = verifyChain([att1Json, att2Json], rootPublicKeyHex)

for (const link of report.chain) {
  const mark = link.valid ? '✓' : '✗'
  console.log(`  ${mark} ${link.issuer} → ${link.subject}`)
}
```

## Create an identity and link a device

```typescript
import { Auths } from '@auths-dev/sdk'

const auths = new Auths()
const identity = auths.identities.create({ label: 'laptop' })

const device = auths.devices.link({
  identityDid: identity.did,
  capabilities: ['sign', 'verify'],
  expiresInDays: 90,
})
console.log(`Identity: ${identity.did}`)
console.log(`Device:   ${device.did}`)
```

## Sign and verify artifacts

```typescript
const signed = auths.artifacts.sign({
  filePath: './release.tar.gz',
  identityDid: identity.did,
  expiresInDays: 365,
})
console.log(`RID:    ${signed.rid}`)
console.log(`Digest: ${signed.digest}`)
// -> release.tar.gz.auths.json created
```

## Sign and verify actions (API auth)

The same identity that signs artifacts can authenticate API requests:

```typescript
import { EphemeralIdentity, verifyActionEnvelope } from '@auths-dev/sdk'

// Client: sign an action
const id = new EphemeralIdentity()
const envelope = id.signAction(
  'api_call',
  JSON.stringify({ endpoint: '/resource' })
)

// Server: verify — one function call, no token lookup
const { valid } = verifyActionEnvelope(envelope, id.publicKeyHex)
console.log(valid)  // true
```

## Delegate an agent

```typescript
const agent = auths.identities.delegateAgent({
  identityDid: identity.did,
  name: 'deploy-bot',
  capabilities: ['sign'],
})
console.log(`Agent: ${agent.did}`)

// Sign as the agent
const sig = auths.signing.signAsAgent({
  message: Buffer.from('deploy payload'),
  keyAlias: agent.keyAlias,
})
```

## Build a policy

```typescript
import { PolicyBuilder } from '@auths-dev/sdk'

const policy = new PolicyBuilder()
  .notRevoked()
  .notExpired()
  .requireCapability('deploy:production')
  .requireIssuer(identity.did)
  .build()
```

## Ephemeral identities (testing & demos)

No keychain or filesystem needed — generate a throwaway identity in-memory:

```typescript
import { EphemeralIdentity } from '@auths-dev/sdk'

const alice = new EphemeralIdentity()
console.log(alice.did)           // did:key:z6Mk...
console.log(alice.publicKeyHex)  // 64-char hex

const sig = alice.sign(Buffer.from('hello'))
const envelope = alice.signAction('tool_call', '{"tool": "web_search"}')
const result = alice.verifyAction(envelope)
console.log(result.valid)  // true
```

## Error handling

```typescript
import { Auths, CryptoError, KeychainError, AuthsError } from '@auths-dev/sdk'

try {
  auths.signing.signAsIdentity({
    message: Buffer.from('test'),
    identityDid: 'did:keri:nonexistent',
  })
} catch (e) {
  if (e instanceof KeychainError) {
    console.log('Unlock your keychain or set AUTHS_KEYCHAIN_BACKEND=file')
  } else if (e instanceof AuthsError) {
    console.log(`Auths error (${e.code}): ${e.message}`)
  }
}
```

All errors inherit from `AuthsError`. See [Error Reference](errors.md) for the full hierarchy.

## Next steps

| Guide | Description |
|-------|-------------|
| [API Reference](api/index.md) | Full class and function documentation |
| [Overview](overview.md) | Architecture and feature list |
| [Errors](errors.md) | Error hierarchy and codes |
