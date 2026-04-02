# Auths Node SDK

Decentralized identity for developers and AI agents. Sign, verify, and manage cryptographic identities with Git-native storage.

## Install

```bash
npm install @auths-dev/sdk
```

## Quick start

```typescript
import { Auths, verifyAttestation } from '@auths-dev/sdk'

const auths = new Auths()

// Verify an attestation
const result = verifyAttestation(attestationJson, publicKeyHex)
console.log(result.valid) // true

// Create an identity and sign
const identity = auths.identities.create({ label: 'laptop' })
const sig = auths.signAs({ message: Buffer.from('hello world'), identityDid: identity.did })
console.log(sig.signature) // hex-encoded Ed25519 signature
```

## Identity management

```typescript
import { Auths } from '@auths-dev/sdk'

const auths = new Auths({ repoPath: '~/.auths' })

// Create a cryptographic identity
const identity = auths.identities.create({ label: 'laptop' })
console.log(identity.did) // did:keri:EBfd...

// Provision an agent (for CI, MCP servers, etc.)
const agent = auths.identities.delegateAgent({
  identityDid: identity.did,
  name: 'deploy-bot',
  capabilities: ['sign'],
})

// Sign using the keychain-stored identity key
const result = auths.signAs({
  message: Buffer.from('hello world'),
  identityDid: identity.did,
})

// Link and manage devices
const device = auths.devices.link({
  identityDid: identity.did,
  capabilities: ['sign'],
})
auths.devices.revoke({
  deviceDid: device.did,
  identityDid: identity.did,
  note: 'replaced',
})
```

## Policy engine

```typescript
import { PolicyBuilder, evaluatePolicy } from '@auths-dev/sdk'

// Build a standard policy
const policy = PolicyBuilder.standard('sign_commit')

// Evaluate against a context
const decision = policy.evaluate({
  issuer: 'did:keri:EOrg',
  subject: 'did:key:zDevice',
  capabilities: ['sign_commit'],
})
console.log(decision.allowed) // true

// Compose complex policies
const ciPolicy = new PolicyBuilder()
  .notRevoked()
  .notExpired()
  .requireCapability('sign')
  .requireAgent()
  .requireRepo('org/repo')
  .toJson()
```

## Organization management

```typescript
const org = auths.orgs.create({ label: 'my-team' })

const member = auths.orgs.addMember({
  orgDid: org.orgDid,
  memberDid: devIdentity.did,
  role: 'member',
  memberPublicKeyHex: devIdentity.publicKey,
})

const members = auths.orgs.listMembers({ orgDid: org.orgDid })
```

## Verification

```typescript
import {
  verifyAttestation,
  verifyChain,
  verifyAttestationWithCapability,
} from '@auths-dev/sdk'

// Single attestation
const result = verifyAttestation(attestationJson, issuerPublicKeyHex)

// Attestation chain
const report = verifyChain(attestationChain, rootPublicKeyHex)
console.log(report.status.statusType) // 'Valid' | 'Invalid' | ...

// Capability-scoped verification
const capResult = verifyAttestationWithCapability(
  attestationJson, issuerPublicKeyHex, 'sign_commit'
)
```

## Error handling

```typescript
import { Auths, VerificationError, CryptoError, NetworkError } from '@auths-dev/sdk'

const auths = new Auths()
try {
  const result = auths.signAs({ message: data, identityDid: did })
} catch (e) {
  if (e instanceof CryptoError) {
    console.log(e.code)    // 'key_not_found'
    console.log(e.message) // 'No key found for identity...'
  }
  if (e instanceof NetworkError && e.shouldRetry) {
    // safe to retry
  }
}
```

All errors inherit from `AuthsError` and carry `.code` and `.message`.

## Configuration

```typescript
// Auto-discover (uses ~/.auths)
const auths = new Auths()

// Explicit repo path
const auths = new Auths({ repoPath: '/path/to/identity-repo' })

// With passphrase (or set AUTHS_PASSPHRASE env var)
const auths = new Auths({ passphrase: 'my-secret' })

// Headless / CI mode
// Set AUTHS_KEYCHAIN_BACKEND=file for environments without a system keychain
```

## License

Apache-2.0
