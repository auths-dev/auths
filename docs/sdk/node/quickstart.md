# Node SDK Quickstart

## Install

```bash
npm install @auths-dev/node
```

## Create an identity and sign a commit

```typescript
import { Auths } from '@auths-dev/node'

const auths = new Auths()
const identity = auths.identities.create({ label: 'laptop' })

// Sign commit data (returns SSHSIG PEM)
const result = auths.commits.sign({
  data: commitBytes,
  identityKeyAlias: identity.did,
})
console.log(result.signaturePem)
```

## Link a device

```typescript
const device = auths.devices.link({
  identityDid: identity.did,
  capabilities: ['sign', 'verify'],
  expiresInDays: 90,
})
console.log(`Device: ${device.did}`)
```

## Verify a single attestation

```typescript
import { verifyAttestation } from '@auths-dev/node'

const result = await verifyAttestation(attestationJson, publicKeyHex)
console.log(`Valid: ${result.valid}`)
```

## Verify a chain

```typescript
import { verifyChain } from '@auths-dev/node'

const report = await verifyChain(attestationChain, rootPublicKeyHex)
console.log(`Chain status: ${report.status.statusType}`) // 'Valid'
```

## Build a policy

```typescript
import { PolicyBuilder } from '@auths-dev/node'

const policy = new PolicyBuilder()
  .notRevoked()
  .notExpired()
  .requireCapability('deploy:production')
  .requireIssuer(identity.did)
  .build()
```

## Sign an artifact

```typescript
const signed = auths.artifacts.sign({
  filePath: './release.tar.gz',
  identityDid: identity.did,
  expiresInDays: 365,
})
console.log(`RID: ${signed.rid}`)
console.log(`Digest: ${signed.digest}`)
```

## Delegate an agent

```typescript
const agent = auths.identities.delegateAgent({
  identityDid: identity.did,
  name: 'deploy-bot',
  capabilities: ['sign'],
})
console.log(`Agent: ${agent.agentDid}`)

// Sign as the agent
const sig = auths.signAsAgent({
  message: Buffer.from('deploy payload'),
  keyAlias: agent.keyAlias,
})
```

## Organization management

```typescript
const org = auths.orgs.create({ label: 'my-team' })

auths.orgs.addMember({
  orgDid: org.orgDid,
  memberDid: identity.did,
  role: 'member',
  memberPublicKeyHex: publicKey,
})

const members = auths.orgs.listMembers({ orgDid: org.orgDid })
```

## Error handling

```typescript
import { Auths, CryptoError, KeychainError, AuthsError } from '@auths-dev/node'

try {
  auths.signAs({ message: data, identityDid: 'did:keri:nonexistent' })
} catch (e) {
  if (e instanceof KeychainError) {
    console.log('Unlock your keychain or set AUTHS_KEYCHAIN_BACKEND=file')
  } else if (e instanceof CryptoError) {
    console.log(`Crypto issue (${e.code}): ${e.message}`)
  } else if (e instanceof AuthsError) {
    console.log(`Auths error (${e.code}): ${e.message}`)
  }
}
```

## Next steps

- [API Reference](api/index.md) — full class and function documentation
- [Errors](errors.md) — error hierarchy and codes
- [Overview](overview.md) — architecture and feature list
