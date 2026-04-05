# @auths-dev/node

## Classes

### ArtifactService

Signs artifacts (files or raw bytes) to produce verifiable attestations.

Access via [Auths.artifacts](#artifacts).

#### Example

```typescript
const result = auths.artifacts.sign({
  filePath: './release.tar.gz',
  identityDid: identity.did,
})
console.log(result.digest) // content hash
```

#### Constructors

##### Constructor

```ts
new ArtifactService(client): ArtifactService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`ArtifactService`](#artifactservice)

#### Methods

##### sign()

```ts
sign(opts): ArtifactResult;
```

Signs a file at the given path.

###### Parameters

###### opts

[`SignArtifactOptions`](#signartifactoptions)

Signing options.

###### Returns

[`ArtifactResult`](#artifactresult)

The artifact attestation with digest and metadata.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

###### Example

```typescript
const result = auths.artifacts.sign({
  filePath: './build/app.wasm',
  identityDid: identity.did,
  expiresInDays: 365,
})
```

##### signBytes()

```ts
signBytes(opts): ArtifactResult;
```

Signs raw bytes (e.g. an in-memory buffer).

###### Parameters

###### opts

[`SignArtifactBytesOptions`](#signartifactbytesoptions)

Signing options.

###### Returns

[`ArtifactResult`](#artifactresult)

The artifact attestation with digest and metadata.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

###### Example

```typescript
const result = auths.artifacts.signBytes({
  data: Buffer.from('binary content'),
  identityDid: identity.did,
})
```

***

### AttestationService

Queries attestations stored in the local registry.

Access via [Auths.attestations](#attestations).

#### Example

```typescript
const atts = auths.attestations.list()
const latest = auths.attestations.getLatest(device.did)
```

#### Constructors

##### Constructor

```ts
new AttestationService(client): AttestationService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`AttestationService`](#attestationservice)

#### Methods

##### getLatest()

```ts
getLatest(deviceDid): AttestationInfo | null;
```

Retrieves the latest attestation for a device.

###### Parameters

###### deviceDid

`string`

DID of the device.

###### Returns

[`AttestationInfo`](#attestationinfo) \| `null`

The latest attestation, or `null` if none found.

###### Throws

[StorageError](#storageerror) if the operation fails.

##### list()

```ts
list(): AttestationInfo[];
```

Lists all attestations in the local registry.

###### Returns

[`AttestationInfo`](#attestationinfo)[]

Array of attestation records.

###### Throws

[StorageError](#storageerror) if the operation fails.

##### listByDevice()

```ts
listByDevice(deviceDid): AttestationInfo[];
```

Lists attestations for a specific device.

###### Parameters

###### deviceDid

`string`

DID of the device to filter by.

###### Returns

[`AttestationInfo`](#attestationinfo)[]

Array of attestation records for the device.

###### Throws

[StorageError](#storageerror) if the operation fails.

***

### AuditService

Audits Git repositories for commit signature compliance.

Access via [Auths.audit](#audit).

#### Example

```typescript
const report = auths.audit.report({ targetRepoPath: '/path/to/repo' })
console.log(report.summary.unsigned_commits)
```

#### Constructors

##### Constructor

```ts
new AuditService(client): AuditService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`AuditService`](#auditservice)

#### Methods

##### isCompliant()

```ts
isCompliant(opts): boolean;
```

Checks whether all commits in a repository are signed.

###### Parameters

###### opts

[`AuditComplianceOptions`](#auditcomplianceoptions)

Compliance check options.

###### Returns

`boolean`

`true` if every commit is signed, `false` otherwise.

###### Example

```typescript
if (auths.audit.isCompliant({ targetRepoPath: '/path/to/repo' })) {
  console.log('All commits signed')
}
```

##### report()

```ts
report(opts): AuditReport;
```

Generates an audit report for a Git repository's commit signatures.

###### Parameters

###### opts

[`AuditReportOptions`](#auditreportoptions)

Audit options.

###### Returns

[`AuditReport`](#auditreport)

The audit report with per-commit details and summary statistics.

###### Throws

[VerificationError](#verificationerror) if the audit fails.

###### Example

```typescript
const report = auths.audit.report({ targetRepoPath: '/path/to/repo' })
console.log(report.summary.total_commits)
```

***

### Auths

Primary entry point for all Auths SDK operations.

Provides access to identity management, device authorization, signing,
verification, policy evaluation, organizations, and more through
service properties.

#### Example

```typescript
import { Auths } from '@auths-dev/node'

const auths = new Auths()

// Create an identity
const identity = auths.identities.create({ label: 'laptop' })

// Sign a message
const sig = auths.signAs({
  message: Buffer.from('hello world'),
  identityDid: identity.did,
})
console.log(sig.signature) // hex-encoded Ed25519 signature
```

#### Constructors

##### Constructor

```ts
new Auths(config?): Auths;
```

Creates a new Auths client.

###### Parameters

###### config?

[`ClientConfig`](#clientconfig) = `{}`

Client configuration.

###### Returns

[`Auths`](#auths)

###### Example

```typescript
// Auto-discover (~/.auths)
const auths = new Auths()

// Explicit configuration
const auths = new Auths({
  repoPath: '/path/to/identity-repo',
  passphrase: 'my-secret',
})
```

#### Properties

##### artifacts

```ts
readonly artifacts: ArtifactService;
```

Artifact signing.

##### attestations

```ts
readonly attestations: AttestationService;
```

Attestation queries.

##### audit

```ts
readonly audit: AuditService;
```

Repository audit reports.

##### commits

```ts
readonly commits: CommitService;
```

Git commit signing.

##### devices

```ts
readonly devices: DeviceService;
```

Device authorization (link, revoke, extend).

##### identities

```ts
readonly identities: IdentityService;
```

Identity management (create, rotate, delegate agents).

##### orgs

```ts
readonly orgs: OrgService;
```

Organization management.

##### pairing

```ts
readonly pairing: PairingService;
```

Cross-device pairing.

##### passphrase

```ts
readonly passphrase: string | undefined;
```

Passphrase for key operations, if set.

##### repoPath

```ts
readonly repoPath: string;
```

Path to the Auths Git registry.

##### signing

```ts
readonly signing: SigningService;
```

Message and action signing.

##### trust

```ts
readonly trust: TrustService;
```

Trust store for pinned identities.

##### witnesses

```ts
readonly witnesses: WitnessService;
```

Witness node management.

#### Methods

##### doctor()

```ts
doctor(): string;
```

Runs diagnostics on the Auths installation and returns a report.

###### Returns

`string`

A human-readable diagnostics string.

##### getPublicKey()

```ts
getPublicKey(opts): string;
```

Convenience method to get an identity's public key.

###### Parameters

###### opts

[`GetPublicKeyOptions`](#getpublickeyoptions)

Lookup options.

###### Returns

`string`

Hex-encoded Ed25519 public key.

###### Throws

[CryptoError](#cryptoerror) if the key cannot be found.

##### signActionAs()

```ts
signActionAs(opts): ActionEnvelope;
```

Convenience method to sign an action as an identity.

###### Parameters

###### opts

[`SignActionAsIdentityOptions`](#signactionasidentityoptions)

Action signing options.

###### Returns

[`ActionEnvelope`](#actionenvelope)

The signed action envelope.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

##### signActionAsAgent()

```ts
signActionAsAgent(opts): ActionEnvelope;
```

Convenience method to sign an action as an agent.

###### Parameters

###### opts

[`SignActionAsAgentOptions`](#signactionasagentoptions)

Agent action signing options.

###### Returns

[`ActionEnvelope`](#actionenvelope)

The signed action envelope.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

##### signAs()

```ts
signAs(opts): SignResult;
```

Convenience method to sign a message as an identity.

###### Parameters

###### opts

[`SignAsIdentityOptions`](#signasidentityoptions)

Signing options.

###### Returns

[`SignResult`](#signresult)

The signature and signer DID.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

###### Example

```typescript
const result = auths.signAs({
  message: Buffer.from('hello world'),
  identityDid: identity.did,
})
```

##### signAsAgent()

```ts
signAsAgent(opts): SignResult;
```

Convenience method to sign a message as an agent.

###### Parameters

###### opts

[`SignAsAgentOptions`](#signasagentoptions)

Agent signing options.

###### Returns

[`SignResult`](#signresult)

The signature and signer DID.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

##### verify()

```ts
verify(opts): Promise<VerificationResult>;
```

Verifies a single attestation with optional capability and time constraints.

###### Parameters

###### opts

[`VerifyOptions`](#verifyoptions)

Verification options.

###### Returns

`Promise`\<[`VerificationResult`](#verificationresult)\>

The verification result.

###### Throws

[VerificationError](#verificationerror) if verification encounters an error.

###### Example

```typescript
const result = await auths.verify({
  attestationJson: json,
  issuerKey: publicKeyHex,
})
console.log(result.valid)
```

##### verifyChain()

```ts
verifyChain(opts): Promise<VerificationReport>;
```

Verifies an attestation chain with optional capability and witness constraints.

###### Parameters

###### opts

[`VerifyChainOptions`](#verifychainoptions)

Chain verification options.

###### Returns

`Promise`\<[`VerificationReport`](#verificationreport)\>

The verification report.

###### Throws

[VerificationError](#verificationerror) if verification encounters an error.

***

### AuthsError

Base error for all Auths SDK operations.

All errors thrown by the SDK inherit from this class, carrying a
machine-readable [code](#code) and human-readable
[message](#message).

#### Example

```typescript
import { Auths, AuthsError } from '@auths-dev/node'

try {
  auths.signAs({ message: data, identityDid: did })
} catch (e) {
  if (e instanceof AuthsError) {
    console.log(e.code, e.message)
  }
}
```

#### Extends

- `Error`

#### Extended by

- [`VerificationError`](#verificationerror)
- [`CryptoError`](#cryptoerror)
- [`KeychainError`](#keychainerror)
- [`StorageError`](#storageerror)
- [`NetworkError`](#networkerror)
- [`IdentityError`](#identityerror)
- [`OrgError`](#orgerror)
- [`PairingError`](#pairingerror)

#### Constructors

##### Constructor

```ts
new AuthsError(message, code): AuthsError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`AuthsError`](#authserror)

###### Overrides

```ts
Error.constructor
```

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

```ts
Error.cause
```

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

##### message

```ts
message: string;
```

###### Inherited from

```ts
Error.message
```

##### name

```ts
name: string;
```

###### Inherited from

```ts
Error.name
```

##### stack?

```ts
optional stack: string;
```

###### Inherited from

```ts
Error.stack
```

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

```ts
Error.stackTraceLimit
```

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

```ts
Error.captureStackTrace
```

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

```ts
Error.prepareStackTrace
```

***

### CommitService

Signs Git commits using Auths identities.

Access via [Auths.commits](#commits).

#### Example

```typescript
const result = auths.commits.sign({
  data: commitBuffer,
  identityDid: identity.did,
})
console.log(result.signaturePem) // PEM-encoded signature
```

#### Constructors

##### Constructor

```ts
new CommitService(client): CommitService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`CommitService`](#commitservice)

#### Methods

##### sign()

```ts
sign(opts): CommitSignResult;
```

Signs raw Git commit data, producing a PEM-encoded signature.

###### Parameters

###### opts

[`SignCommitOptions`](#signcommitoptions)

Signing options.

###### Returns

[`CommitSignResult`](#commitsignresult)

The commit signature with method and namespace metadata.

###### Throws

[CryptoError](#cryptoerror) if the key is missing or signing fails.

###### Example

```typescript
const result = auths.commits.sign({
  data: Buffer.from(commitContent),
  identityDid: identity.did,
})
```

***

### CryptoError

Raised when a cryptographic operation fails.

Common codes: `'invalid_key'`, `'key_not_found'`, `'signing_failed'`.

#### Example

```typescript
import { Auths, CryptoError } from '@auths-dev/node'

try {
  auths.signAs({ message: data, identityDid: did })
} catch (e) {
  if (e instanceof CryptoError && e.code === 'key_not_found') {
    console.log('Identity key not in keychain')
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new CryptoError(message, code): CryptoError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`CryptoError`](#cryptoerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### DeviceService

Manages device authorization lifecycle: link, revoke, and extend.

Access via [Auths.devices](#devices).

#### Example

```typescript
const device = auths.devices.link({
  identityDid: identity.did,
  capabilities: ['sign'],
  expiresInDays: 90,
})
```

#### Constructors

##### Constructor

```ts
new DeviceService(client): DeviceService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`DeviceService`](#deviceservice)

#### Methods

##### extend()

```ts
extend(opts): DeviceExtension;
```

Extends a device's authorization period.

###### Parameters

###### opts

[`ExtendDeviceOptions`](#extenddeviceoptions)

Extension options.

###### Returns

[`DeviceExtension`](#deviceextension)

The extension result with new and previous expiration times.

###### Throws

[IdentityError](#identityerror) if extension fails.

###### Example

```typescript
const ext = auths.devices.extend({
  deviceDid: device.did,
  identityDid: identity.did,
  days: 60,
})
console.log(ext.newExpiresAt) // RFC 3339 timestamp
```

##### link()

```ts
link(opts): Device;
```

Links a new device to an identity with scoped capabilities.

###### Parameters

###### opts

[`LinkDeviceOptions`](#linkdeviceoptions)

Link options.

###### Returns

[`Device`](#device)

The linked device with its DID and attestation ID.

###### Throws

[IdentityError](#identityerror) if linking fails.

###### Example

```typescript
const device = auths.devices.link({
  identityDid: identity.did,
  capabilities: ['sign'],
  expiresInDays: 90,
})
console.log(device.did) // did:key:z...
```

##### revoke()

```ts
revoke(opts): void;
```

Revokes a device's authorization under an identity.

###### Parameters

###### opts

[`RevokeDeviceOptions`](#revokedeviceoptions)

Revocation options.

###### Returns

`void`

###### Throws

[IdentityError](#identityerror) if revocation fails.

###### Example

```typescript
auths.devices.revoke({
  deviceDid: device.did,
  identityDid: identity.did,
  note: 'replaced',
})
```

***

### IdentityError

Raised when an identity or device operation fails.

Common codes: `'identity_not_found'`, `'unknown'`.

#### Example

```typescript
import { Auths, IdentityError } from '@auths-dev/node'

try {
  auths.devices.link({ identityDid: did, capabilities: ['sign'] })
} catch (e) {
  if (e instanceof IdentityError) {
    console.log('Identity error:', e.code)
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new IdentityError(message, code): IdentityError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`IdentityError`](#identityerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### IdentityService

Manages cryptographic identities, agents, and key rotation.

Access via [Auths.identities](#identities).

#### Example

```typescript
const auths = new Auths()
const identity = auths.identities.create({ label: 'laptop' })
console.log(identity.did) // did:keri:EBfd...
```

#### Constructors

##### Constructor

```ts
new IdentityService(client): IdentityService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`IdentityService`](#identityservice)

#### Methods

##### create()

```ts
create(opts?): Identity;
```

Creates a new cryptographic identity backed by an Ed25519 keypair.

###### Parameters

###### opts?

[`CreateIdentityOptions`](#createidentityoptions) = `{}`

Creation options.

###### Returns

[`Identity`](#identity)

The newly created identity.

###### Throws

[IdentityError](#identityerror) if the identity cannot be created.

###### Example

```typescript
const identity = auths.identities.create({ label: 'laptop' })
console.log(identity.did)       // did:keri:EBfd...
console.log(identity.publicKey) // hex-encoded Ed25519 key
```

##### createAgent()

```ts
createAgent(opts): AgentIdentity;
```

Creates a standalone agent identity with a self-signed attestation.

###### Parameters

###### opts

[`CreateAgentOptions`](#createagentoptions)

Agent creation options.

###### Returns

[`AgentIdentity`](#agentidentity)

The agent identity with its attestation.

###### Throws

[IdentityError](#identityerror) if the agent cannot be created.

###### Example

```typescript
const agent = auths.identities.createAgent({
  name: 'ci-bot',
  capabilities: ['sign'],
})
console.log(agent.did) // did:keri:...
```

##### delegateAgent()

```ts
delegateAgent(opts): DelegatedAgent;
```

Delegates an agent under an existing identity with scoped capabilities.

###### Parameters

###### opts

[`DelegateAgentOptions`](#delegateagentoptions)

Delegation options.

###### Returns

[`DelegatedAgent`](#delegatedagent)

The delegated agent with its signed attestation.

###### Throws

[IdentityError](#identityerror) if delegation fails.

###### Example

```typescript
const agent = auths.identities.delegateAgent({
  identityDid: identity.did,
  name: 'deploy-bot',
  capabilities: ['sign'],
  expiresInDays: 90,
})
```

##### getPublicKey()

```ts
getPublicKey(opts): string;
```

Retrieves the hex-encoded Ed25519 public key for an identity.

###### Parameters

###### opts

[`GetPublicKeyOptions`](#getpublickeyoptions)

Lookup options.

###### Returns

`string`

Hex-encoded public key string (64 characters).

###### Throws

[CryptoError](#cryptoerror) if the key cannot be found.

###### Example

```typescript
const pk = auths.identities.getPublicKey({ identityDid: identity.did })
console.log(pk.length) // 64
```

##### rotate()

```ts
rotate(opts?): RotationResult;
```

Rotates the signing keys for an identity, advancing the KERI event log.

###### Parameters

###### opts?

[`RotateKeysOptions`](#rotatekeysoptions) = `{}`

Rotation options.

###### Returns

[`RotationResult`](#rotationresult)

The rotation result with old and new key fingerprints.

###### Throws

[IdentityError](#identityerror) if rotation fails.

###### Example

```typescript
const result = auths.identities.rotate({ identityDid: identity.did })
console.log(result.sequence) // incremented sequence number
```

***

### KeychainError

Raised when the platform keychain is inaccessible or locked.

Common codes: `'keychain_locked'`.

#### Example

```typescript
import { Auths, KeychainError } from '@auths-dev/node'

try {
  auths.identities.create({ label: 'main' })
} catch (e) {
  if (e instanceof KeychainError) {
    console.log('Unlock your keychain or set AUTHS_KEYCHAIN_BACKEND=file')
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new KeychainError(message, code): KeychainError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`KeychainError`](#keychainerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### NetworkError

Raised when a network operation fails (e.g. witness communication).

Common codes: `'server_error'`.

#### Example

```typescript
import { NetworkError } from '@auths-dev/node'

try {
  // network operation
} catch (e) {
  if (e instanceof NetworkError && e.shouldRetry) {
    // safe to retry
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new NetworkError(
   message,
   code,
   shouldRetry?): NetworkError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### shouldRetry?

`boolean` = `true`

###### Returns

[`NetworkError`](#networkerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### shouldRetry

```ts
shouldRetry: boolean;
```

Whether the operation is safe to retry. Defaults to `true`.

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### OrgError

Raised when an organization operation fails.

Common codes: `'org_error'`.

#### Example

```typescript
import { Auths, OrgError } from '@auths-dev/node'

try {
  auths.orgs.addMember({ orgDid, memberDid, role: 'member' })
} catch (e) {
  if (e instanceof OrgError) {
    console.log('Org error:', e.message)
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new OrgError(message, code): OrgError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`OrgError`](#orgerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### OrgService

Manages organizations and their membership.

Access via [Auths.orgs](#orgs).

#### Example

```typescript
const org = auths.orgs.create({ label: 'my-team' })
auths.orgs.addMember({
  orgDid: org.orgDid,
  memberDid: dev.did,
  role: 'member',
  memberPublicKeyHex: dev.publicKey,
})
```

#### Constructors

##### Constructor

```ts
new OrgService(client): OrgService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`OrgService`](#orgservice)

#### Methods

##### addMember()

```ts
addMember(opts): OrgMember;
```

Adds a member to an organization.

###### Parameters

###### opts

[`AddOrgMemberOptions`](#addorgmemberoptions)

Member options.

###### Returns

[`OrgMember`](#orgmember)

The new member record.

###### Throws

[OrgError](#orgerror) if the operation fails.

###### Example

```typescript
const member = auths.orgs.addMember({
  orgDid: org.orgDid,
  memberDid: dev.did,
  role: 'member',
  memberPublicKeyHex: dev.publicKey,
})
```

##### create()

```ts
create(opts): OrgResult;
```

Creates a new organization.

###### Parameters

###### opts

[`CreateOrgOptions`](#createorgoptions)

Organization options.

###### Returns

[`OrgResult`](#orgresult)

The created organization.

###### Throws

[OrgError](#orgerror) if creation fails.

###### Example

```typescript
const org = auths.orgs.create({ label: 'engineering' })
console.log(org.orgDid) // did:keri:...
```

##### listMembers()

```ts
listMembers(opts): OrgMember[];
```

Lists members of an organization.

###### Parameters

###### opts

[`ListOrgMembersOptions`](#listorgmembersoptions)

List options.

###### Returns

[`OrgMember`](#orgmember)[]

Array of member records.

###### Throws

[OrgError](#orgerror) if the operation fails.

###### Example

```typescript
const members = auths.orgs.listMembers({ orgDid: org.orgDid })
console.log(members.length)
```

##### revokeMember()

```ts
revokeMember(opts): OrgMember;
```

Revokes a member's access to an organization.

###### Parameters

###### opts

[`RevokeOrgMemberOptions`](#revokeorgmemberoptions)

Revocation options.

###### Returns

[`OrgMember`](#orgmember)

The updated member record with `revoked: true`.

###### Throws

[OrgError](#orgerror) if the operation fails.

***

### PairingError

Raised when a device pairing operation fails or times out.

Common codes: `'pairing_error'`, `'timeout'`.

#### Example

```typescript
import { PairingError } from '@auths-dev/node'

try {
  await auths.pairing.createSession({ bindAddress: '127.0.0.1' })
} catch (e) {
  if (e instanceof PairingError && e.shouldRetry) {
    // safe to retry
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new PairingError(
   message,
   code,
   shouldRetry?): PairingError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### shouldRetry?

`boolean` = `true`

###### Returns

[`PairingError`](#pairingerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### shouldRetry

```ts
shouldRetry: boolean;
```

Whether the operation is safe to retry. Defaults to `true`.

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### PairingService

Handles device pairing for cross-device identity authorization.

The pairing flow: controller creates a session, device joins with the
short code, controller completes pairing to authorize the device.

Access via [Auths.pairing](#pairing).

#### Example

```typescript
const session = await auths.pairing.createSession({
  bindAddress: '127.0.0.1',
  capabilities: ['sign:commit'],
})
console.log(session.shortCode) // e.g. 'A3F7K2'

// On the device side:
const response = await auths.pairing.join({
  shortCode: 'A3F7K2',
  endpoint: session.endpoint,
  token: session.token,
})
```

#### Constructors

##### Constructor

```ts
new PairingService(client): PairingService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`PairingService`](#pairingservice)

#### Methods

##### \[asyncDispose\]()

```ts
asyncDispose: Promise<void>;
```

###### Returns

`Promise`\<`void`\>

##### \[dispose\]()

```ts
dispose: void;
```

###### Returns

`void`

##### complete()

```ts
complete(opts): Promise<PairingResult>;
```

Completes pairing by authorizing the connected device.

###### Parameters

###### opts

[`CompletePairingOptions`](#completepairingoptions)

Completion options with device identity and capabilities.

###### Returns

`Promise`\<[`PairingResult`](#pairingresult)\>

The pairing result with the device's authorization attestation.

###### Throws

[PairingError](#pairingerror) if no session is active or completion fails.

##### createSession()

```ts
createSession(opts?): Promise<PairingSession>;
```

Creates a pairing session and starts listening for device connections.

###### Parameters

###### opts?

[`CreatePairingSessionOptions`](#createpairingsessionoptions)

Session options.

###### Returns

`Promise`\<[`PairingSession`](#pairingsession)\>

The active pairing session with its short code and endpoint.

###### Throws

[PairingError](#pairingerror) if session creation fails.

###### Example

```typescript
const session = await auths.pairing.createSession({
  bindAddress: '127.0.0.1',
  enableMdns: false,
})
console.log(session.shortCode) // 6-char code
```

##### join()

```ts
join(opts): Promise<PairingResponse>;
```

Joins an existing pairing session from the device side.

###### Parameters

###### opts

[`JoinPairingOptions`](#joinpairingoptions)

Join options with short code and endpoint from the controller.

###### Returns

`Promise`\<[`PairingResponse`](#pairingresponse)\>

The pairing response with device identity information.

###### Throws

[PairingError](#pairingerror) if joining fails.

###### Example

```typescript
const response = await auths.pairing.join({
  shortCode: 'A3F7K2',
  endpoint: 'http://127.0.0.1:8080',
  token: sessionToken,
})
```

##### stop()

```ts
stop(): Promise<void>;
```

Stops the active pairing session. Idempotent — safe to call multiple times.

###### Returns

`Promise`\<`void`\>

###### Throws

[PairingError](#pairingerror) if stopping the session fails.

##### waitForResponse()

```ts
waitForResponse(opts?): Promise<PairingResponse>;
```

Waits for a device to connect to the active pairing session.

###### Parameters

###### opts?

[`WaitForPairingResponseOptions`](#waitforpairingresponseoptions)

Wait options.

###### Returns

`Promise`\<[`PairingResponse`](#pairingresponse)\>

The connecting device's information.

###### Throws

[PairingError](#pairingerror) if no session is active or timeout is reached.

***

### PolicyBuilder

Fluent builder for composing authorization policies.

Policies are built by chaining predicates, then compiled and evaluated
against an attestation context to produce an allow/deny decision.

#### Example

```typescript
import { PolicyBuilder } from '@auths-dev/node'

// Quick standard policy
const policy = PolicyBuilder.standard('sign_commit')
const decision = policy.evaluate({
  issuer: 'did:keri:EOrg',
  subject: 'did:key:zDevice',
  capabilities: ['sign_commit'],
})
console.log(decision.allowed) // true

// Complex composed policy
const ciPolicy = new PolicyBuilder()
  .notRevoked()
  .notExpired()
  .requireCapability('sign')
  .requireAgent()
  .requireRepo('org/repo')
  .build()
```

#### Constructors

##### Constructor

```ts
new PolicyBuilder(): PolicyBuilder;
```

###### Returns

[`PolicyBuilder`](#policybuilder)

#### Methods

##### attrEquals()

```ts
attrEquals(key, value): PolicyBuilder;
```

Requires an attestation attribute to equal a specific value.

###### Parameters

###### key

`string`

Attribute key.

###### value

`string`

Required attribute value.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### attrIn()

```ts
attrIn(key, values): PolicyBuilder;
```

Requires an attestation attribute to be one of the given values.

###### Parameters

###### key

`string`

Attribute key.

###### values

`string`[]

Acceptable attribute values.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### build()

```ts
build(): string;
```

Compiles the policy for evaluation using the native policy engine.

###### Returns

`string`

Compiled policy JSON string.

###### Throws

[AuthsError](#authserror) if compilation fails.

###### Throws

Error if the policy has no predicates.

##### evaluate()

```ts
evaluate(context): PolicyDecision;
```

Builds and evaluates the policy against a context in one step.

###### Parameters

###### context

[`EvalContextOpts`](#evalcontextopts)

The evaluation context.

###### Returns

[`PolicyDecision`](#policydecision)

The policy decision.

###### Throws

[AuthsError](#authserror) if compilation or evaluation fails.

###### Example

```typescript
const decision = PolicyBuilder.standard('sign').evaluate({
  issuer: 'did:keri:EOrg',
  subject: 'did:key:zDevice',
  capabilities: ['sign'],
})
console.log(decision.allowed) // true
```

##### expiresAfter()

```ts
expiresAfter(seconds): PolicyBuilder;
```

Requires the attestation to expire after the given number of seconds from now.

###### Parameters

###### seconds

`number`

Minimum remaining lifetime in seconds.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### issuedWithin()

```ts
issuedWithin(seconds): PolicyBuilder;
```

Requires the attestation to have been issued within the given time window.

###### Parameters

###### seconds

`number`

Maximum age in seconds.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### maxChainDepth()

```ts
maxChainDepth(depth): PolicyBuilder;
```

Limits the maximum attestation chain depth.

###### Parameters

###### depth

`number`

Maximum allowed chain depth.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### negate()

```ts
negate(): PolicyBuilder;
```

Negates this policy — passes when the original would deny, and vice versa.

###### Returns

[`PolicyBuilder`](#policybuilder)

A new negated builder.

##### notExpired()

```ts
notExpired(): PolicyBuilder;
```

Requires the attestation to not be expired.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### notRevoked()

```ts
notRevoked(): PolicyBuilder;
```

Requires the attestation to not be revoked.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### orPolicy()

```ts
orPolicy(other): PolicyBuilder;
```

Combines this policy with another using OR logic.

###### Parameters

###### other

[`PolicyBuilder`](#policybuilder)

The other policy builder.

###### Returns

[`PolicyBuilder`](#policybuilder)

A new builder that passes if either policy passes.

##### pathAllowed()

```ts
pathAllowed(patterns): PolicyBuilder;
```

Restricts allowed file paths.

###### Parameters

###### patterns

`string`[]

Glob patterns for allowed paths.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### refMatches()

```ts
refMatches(pattern): PolicyBuilder;
```

Requires the Git ref to match a pattern.

###### Parameters

###### pattern

`string`

Ref pattern (e.g. `'refs/heads/main'`).

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireAgent()

```ts
requireAgent(): PolicyBuilder;
```

Requires the signer to be an agent.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireAllCapabilities()

```ts
requireAllCapabilities(caps): PolicyBuilder;
```

Requires the subject to hold all of the given capabilities.

###### Parameters

###### caps

`string`[]

Array of required capability strings.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireAnyCapability()

```ts
requireAnyCapability(caps): PolicyBuilder;
```

Requires the subject to hold at least one of the given capabilities.

###### Parameters

###### caps

`string`[]

Array of acceptable capability strings.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireCapability()

```ts
requireCapability(cap): PolicyBuilder;
```

Requires the subject to hold a specific capability.

###### Parameters

###### cap

`string`

Capability string (e.g. `'sign'`, `'sign_commit'`).

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireDelegatedBy()

```ts
requireDelegatedBy(did): PolicyBuilder;
```

Requires the attestation to have been delegated by a specific identity.

###### Parameters

###### did

`string`

DID of the required delegator.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireEnv()

```ts
requireEnv(env): PolicyBuilder;
```

Requires a specific deployment environment.

###### Parameters

###### env

`string`

Environment name (e.g. `'production'`).

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireEnvIn()

```ts
requireEnvIn(envs): PolicyBuilder;
```

Requires one of the given deployment environments.

###### Parameters

###### envs

`string`[]

Acceptable environment names.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireHuman()

```ts
requireHuman(): PolicyBuilder;
```

Requires the signer to be a human.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireIssuer()

```ts
requireIssuer(did): PolicyBuilder;
```

Requires the issuer to match a specific DID.

###### Parameters

###### did

`string`

Required issuer DID.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireIssuerIn()

```ts
requireIssuerIn(dids): PolicyBuilder;
```

Requires the issuer to be one of the given DIDs.

###### Parameters

###### dids

`string`[]

Acceptable issuer DIDs.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireRepo()

```ts
requireRepo(repo): PolicyBuilder;
```

Requires the operation to target a specific repository.

###### Parameters

###### repo

`string`

Repository identifier (e.g. `'org/repo'`).

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireRepoIn()

```ts
requireRepoIn(repos): PolicyBuilder;
```

Requires the operation to target one of the given repositories.

###### Parameters

###### repos

`string`[]

Acceptable repository identifiers.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireSubject()

```ts
requireSubject(did): PolicyBuilder;
```

Requires the subject to match a specific DID.

###### Parameters

###### did

`string`

Required subject DID.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### requireWorkload()

```ts
requireWorkload(): PolicyBuilder;
```

Requires the signer to be a workload identity.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### toJson()

```ts
toJson(): string;
```

Serializes the policy to JSON without compiling.

###### Returns

`string`

JSON string representation of the policy expression.

###### Throws

Error if the policy has no predicates.

##### workloadClaimEquals()

```ts
workloadClaimEquals(key, value): PolicyBuilder;
```

Requires a workload attestation claim to equal a specific value.

###### Parameters

###### key

`string`

Claim key.

###### value

`string`

Required claim value.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### workloadIssuerIs()

```ts
workloadIssuerIs(did): PolicyBuilder;
```

Requires the workload attestation issuer to match a specific DID.

###### Parameters

###### did

`string`

Required workload issuer DID.

###### Returns

[`PolicyBuilder`](#policybuilder)

##### anyOf()

```ts
static anyOf(...builders): PolicyBuilder;
```

Creates a policy that passes if any of the given policies pass.

###### Parameters

###### builders

...[`PolicyBuilder`](#policybuilder)[]

Policies to OR together.

###### Returns

[`PolicyBuilder`](#policybuilder)

A new builder combining the policies.

##### standard()

```ts
static standard(capability): PolicyBuilder;
```

Creates a standard policy requiring not-revoked, not-expired, and a capability.

###### Parameters

###### capability

`string`

Required capability string.

###### Returns

[`PolicyBuilder`](#policybuilder)

A new builder with the standard predicates.

###### Example

```typescript
const policy = PolicyBuilder.standard('sign_commit')
```

***

### SigningService

Signs messages and actions using identity or agent keys.

Access via [Auths.signing](#signing).

#### Example

```typescript
const result = auths.signing.signAsIdentity({
  message: Buffer.from('hello world'),
  identityDid: identity.did,
})
console.log(result.signature) // hex-encoded Ed25519 signature
```

#### Constructors

##### Constructor

```ts
new SigningService(client): SigningService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`SigningService`](#signingservice)

#### Methods

##### signActionAsAgent()

```ts
signActionAsAgent(opts): ActionEnvelope;
```

Signs a structured action as an agent.

###### Parameters

###### opts

[`SignActionAsAgentOptions`](#signactionasagentoptions)

Agent action signing options.

###### Returns

[`ActionEnvelope`](#actionenvelope)

The signed action envelope.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

###### Example

```typescript
const envelope = auths.signing.signActionAsAgent({
  actionType: 'tool_call',
  payloadJson: '{"tool":"execute"}',
  keyAlias: agent.keyAlias,
  agentDid: agent.did,
})
```

##### signActionAsIdentity()

```ts
signActionAsIdentity(opts): ActionEnvelope;
```

Signs a structured action as an identity, producing a verifiable envelope.

###### Parameters

###### opts

[`SignActionAsIdentityOptions`](#signactionasidentityoptions)

Action signing options.

###### Returns

[`ActionEnvelope`](#actionenvelope)

The signed action envelope.

###### Throws

[CryptoError](#cryptoerror) if signing fails.

###### Example

```typescript
const envelope = auths.signing.signActionAsIdentity({
  actionType: 'tool_call',
  payloadJson: '{"tool":"read_file"}',
  identityDid: identity.did,
})
```

##### signAsAgent()

```ts
signAsAgent(opts): SignResult;
```

Signs a message as an agent using its keychain alias.

###### Parameters

###### opts

[`SignAsAgentOptions`](#signasagentoptions)

Agent signing options.

###### Returns

[`SignResult`](#signresult)

The signature and signer DID.

###### Throws

[CryptoError](#cryptoerror) if the key is missing or signing fails.

###### Example

```typescript
const result = auths.signing.signAsAgent({
  message: Buffer.from('payload'),
  keyAlias: agent.keyAlias,
})
```

##### signAsIdentity()

```ts
signAsIdentity(opts): SignResult;
```

Signs a message as an identity.

###### Parameters

###### opts

[`SignAsIdentityOptions`](#signasidentityoptions)

Signing options.

###### Returns

[`SignResult`](#signresult)

The signature and signer DID.

###### Throws

[CryptoError](#cryptoerror) if the key is missing or signing fails.

###### Example

```typescript
const result = auths.signing.signAsIdentity({
  message: Buffer.from('hello'),
  identityDid: identity.did,
})
```

***

### StorageError

Raised when a storage or registry operation fails.

Common codes: `'repo_not_found'`, `'trust_error'`, `'witness_error'`.

#### Example

```typescript
import { Auths, StorageError } from '@auths-dev/node'

try {
  auths.trust.pin({ did: 'did:keri:ENOTREAL' })
} catch (e) {
  if (e instanceof StorageError) {
    console.log('Storage error:', e.message)
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new StorageError(message, code): StorageError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`StorageError`](#storageerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### TrustService

Manages the local trust store for pinning and querying trusted identities.

Access via [Auths.trust](#trust).

#### Example

```typescript
auths.trust.pin({ did: peer.did, label: 'alice' })
const entries = auths.trust.list()
```

#### Constructors

##### Constructor

```ts
new TrustService(client): TrustService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`TrustService`](#trustservice)

#### Methods

##### get()

```ts
get(did): PinnedIdentity | null;
```

Looks up a specific pinned identity by DID.

###### Parameters

###### did

`string`

DID to look up.

###### Returns

[`PinnedIdentity`](#pinnedidentity) \| `null`

The pinned identity entry, or `null` if not found.

###### Throws

[StorageError](#storageerror) if the operation fails.

###### Example

```typescript
const entry = auths.trust.get('did:keri:EBfd...')
if (entry) console.log(entry.label)
```

##### list()

```ts
list(): PinnedIdentity[];
```

Lists all pinned identities in the local trust store.

###### Returns

[`PinnedIdentity`](#pinnedidentity)[]

Array of pinned identity entries.

###### Throws

[StorageError](#storageerror) if the operation fails.

##### pin()

```ts
pin(opts): PinnedIdentity;
```

Pins an identity as trusted in the local store.

###### Parameters

###### opts

[`PinIdentityOptions`](#pinidentityoptions)

Pin options.

###### Returns

[`PinnedIdentity`](#pinnedidentity)

The pinned identity entry.

###### Throws

[StorageError](#storageerror) if the pin operation fails.

###### Example

```typescript
const entry = auths.trust.pin({ did: identity.did, label: 'my-peer' })
console.log(entry.trustLevel) // 'tofu'
```

##### remove()

```ts
remove(did): void;
```

Removes a pinned identity from the local trust store.

###### Parameters

###### did

`string`

DID of the identity to unpin.

###### Returns

`void`

###### Throws

[StorageError](#storageerror) if the operation fails.

***

### VerificationError

Raised when attestation or chain verification fails.

Common codes: `'invalid_signature'`, `'expired_attestation'`,
`'revoked_device'`, `'missing_capability'`.

#### Example

```typescript
import { verifyAttestation, VerificationError } from '@auths-dev/node'

try {
  await verifyAttestation(json, publicKey)
} catch (e) {
  if (e instanceof VerificationError) {
    console.log('Verification failed:', e.code)
  }
}
```

#### Extends

- [`AuthsError`](#authserror)

#### Constructors

##### Constructor

```ts
new VerificationError(message, code): VerificationError;
```

###### Parameters

###### message

`string`

###### code

`string`

###### Returns

[`VerificationError`](#verificationerror)

###### Overrides

[`AuthsError`](#authserror).[`constructor`](#constructor-4)

#### Properties

##### cause?

```ts
optional cause: unknown;
```

###### Inherited from

[`AuthsError`](#authserror).[`cause`](#cause)

##### code

```ts
code: string;
```

Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`).

###### Inherited from

[`AuthsError`](#authserror).[`code`](#code)

##### message

```ts
message: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`message`](#message)

##### name

```ts
name: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`name`](#name)

##### stack?

```ts
optional stack: string;
```

###### Inherited from

[`AuthsError`](#authserror).[`stack`](#stack)

##### stackTraceLimit

```ts
static stackTraceLimit: number;
```

The `Error.stackTraceLimit` property specifies the number of stack frames
collected by a stack trace (whether generated by `new Error().stack` or
`Error.captureStackTrace(obj)`).

The default value is `10` but may be set to any valid JavaScript number. Changes
will affect any stack trace captured _after_ the value has been changed.

If set to a non-number value, or set to a negative number, stack traces will
not capture any frames.

###### Inherited from

[`AuthsError`](#authserror).[`stackTraceLimit`](#stacktracelimit)

#### Methods

##### captureStackTrace()

```ts
static captureStackTrace(targetObject, constructorOpt?): void;
```

Creates a `.stack` property on `targetObject`, which when accessed returns
a string representing the location in the code at which
`Error.captureStackTrace()` was called.

```js
const myObject = {};
Error.captureStackTrace(myObject);
myObject.stack;  // Similar to `new Error().stack`
```

The first line of the trace will be prefixed with
`${myObject.name}: ${myObject.message}`.

The optional `constructorOpt` argument accepts a function. If given, all frames
above `constructorOpt`, including `constructorOpt`, will be omitted from the
generated stack trace.

The `constructorOpt` argument is useful for hiding implementation
details of error generation from the user. For instance:

```js
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // Create an error without stack trace to avoid calculating the stack trace twice.
  const { stackTraceLimit } = Error;
  Error.stackTraceLimit = 0;
  const error = new Error();
  Error.stackTraceLimit = stackTraceLimit;

  // Capture the stack trace above function b
  Error.captureStackTrace(error, b); // Neither function c, nor b is included in the stack trace
  throw error;
}

a();
```

###### Parameters

###### targetObject

`object`

###### constructorOpt?

`Function`

###### Returns

`void`

###### Inherited from

[`AuthsError`](#authserror).[`captureStackTrace`](#capturestacktrace)

##### prepareStackTrace()

```ts
static prepareStackTrace(err, stackTraces): any;
```

###### Parameters

###### err

`Error`

###### stackTraces

`CallSite`[]

###### Returns

`any`

###### See

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

###### Inherited from

[`AuthsError`](#authserror).[`prepareStackTrace`](#preparestacktrace)

***

### WitnessService

Manages witness nodes for receipt-based verification.

Access via [Auths.witnesses](#witnesses).

#### Example

```typescript
auths.witnesses.add({ url: 'http://witness.example.com:3333' })
const witnesses = auths.witnesses.list()
```

#### Constructors

##### Constructor

```ts
new WitnessService(client): WitnessService;
```

###### Parameters

###### client

[`Auths`](#auths)

###### Returns

[`WitnessService`](#witnessservice)

#### Methods

##### add()

```ts
add(opts): WitnessEntry;
```

Adds a witness node. Idempotent — adding the same URL twice is a no-op.

###### Parameters

###### opts

[`AddWitnessOptions`](#addwitnessoptions)

Witness options.

###### Returns

[`WitnessEntry`](#witnessentry)

The witness entry.

###### Throws

[StorageError](#storageerror) if the operation fails.

###### Example

```typescript
const w = auths.witnesses.add({ url: 'http://witness.example.com:3333' })
console.log(w.url) // http://witness.example.com:3333
```

##### list()

```ts
list(): WitnessEntry[];
```

Lists all registered witnesses.

###### Returns

[`WitnessEntry`](#witnessentry)[]

Array of witness entries.

###### Throws

[StorageError](#storageerror) if the operation fails.

##### remove()

```ts
remove(url): void;
```

Removes a witness by URL.

###### Parameters

###### url

`string`

URL of the witness to remove.

###### Returns

`void`

###### Throws

[StorageError](#storageerror) if the operation fails.

## Interfaces

### ActionEnvelope

A signed action envelope containing the payload and its signature.

#### Properties

##### envelopeJson

```ts
envelopeJson: string;
```

JSON-serialized envelope with action metadata.

##### signatureHex

```ts
signatureHex: string;
```

Hex-encoded signature over the envelope.

##### signerDid

```ts
signerDid: string;
```

DID of the signer.

***

### AddOrgMemberOptions

Options for [OrgService.addMember](#addmember).

#### Properties

##### capabilities?

```ts
optional capabilities: string[];
```

Capabilities to grant the member.

##### memberDid

```ts
memberDid: string;
```

DID of the member to add.

##### memberPublicKeyHex?

```ts
optional memberPublicKeyHex: string;
```

Hex-encoded public key of the member (required for cross-repo adds).

##### note?

```ts
optional note: string;
```

Optional note for the membership record.

##### orgDid

```ts
orgDid: string;
```

DID of the organization.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### role

```ts
role: string;
```

Role to assign (e.g. `'admin'`, `'member'`).

***

### AddWitnessOptions

Options for [WitnessService.add](#add).

#### Properties

##### label?

```ts
optional label: string;
```

Optional label for the witness.

##### url

```ts
url: string;
```

URL of the witness endpoint (e.g. `'http://witness.example.com:3333'`).

***

### AgentIdentity

A standalone agent identity with its self-signed attestation.

#### Properties

##### attestation

```ts
attestation: string;
```

JSON-serialized self-signed attestation.

##### did

```ts
did: string;
```

The agent's KERI decentralized identifier.

##### keyAlias

```ts
keyAlias: string;
```

Keychain alias for the agent's signing key.

##### publicKey

```ts
publicKey: string;
```

Hex-encoded Ed25519 public key.

***

### ArtifactResult

Result of signing an artifact.

#### Properties

##### attestationJson

```ts
attestationJson: string;
```

JSON-serialized attestation for the signed artifact.

##### digest

```ts
digest: string;
```

Content digest (hash) of the artifact.

##### fileSize

```ts
fileSize: number;
```

Size of the artifact in bytes.

##### rid

```ts
rid: string;
```

Unique resource identifier of the attestation.

***

### AttestationInfo

An attestation record from the local registry.

#### Properties

##### capabilities

```ts
capabilities: string[];
```

List of capabilities granted (e.g. `['sign']`).

##### createdAt

```ts
createdAt: string | null;
```

Creation timestamp (RFC 3339), or `null`.

##### delegatedBy

```ts
delegatedBy: string | null;
```

DID of the identity that delegated this attestation, or `null`.

##### deviceDid

```ts
deviceDid: string;
```

DID of the device this attestation applies to.

##### expiresAt

```ts
expiresAt: string | null;
```

Expiration timestamp (RFC 3339), or `null` if no expiry.

##### issuer

```ts
issuer: string;
```

DID of the issuer (identity that signed the attestation).

##### json

```ts
json: string;
```

Raw JSON-serialized attestation.

##### revokedAt

```ts
revokedAt: string | null;
```

Revocation timestamp (RFC 3339), or `null` if not revoked.

##### rid

```ts
rid: string;
```

Unique resource identifier of the attestation.

##### signerType

```ts
signerType: string | null;
```

Signer type: `'human'`, `'agent'`, or `'workload'`, or `null`.

##### subject

```ts
subject: string;
```

DID of the subject (device or agent being attested).

***

### AuditCommit

Audit information for a single Git commit.

#### Properties

##### author\_email

```ts
author_email: string;
```

Commit author email.

##### author\_name

```ts
author_name: string;
```

Commit author name.

##### date

```ts
date: string;
```

Commit date (ISO 8601).

##### message

```ts
message: string;
```

Commit message (first line).

##### oid

```ts
oid: string;
```

Git object ID (SHA).

##### signature\_type

```ts
signature_type: string | null;
```

Signature type (`'auths'`, `'gpg'`, `'ssh'`), or `null` if unsigned.

##### signer\_did

```ts
signer_did: string | null;
```

DID of the signer, or `null` if not an Auths signature.

##### verified

```ts
verified: boolean | null;
```

Whether the signature verified successfully, or `null` if unsigned.

***

### AuditComplianceOptions

Options for [AuditService.isCompliant](#iscompliant).

#### Properties

##### author?

```ts
optional author: string;
```

Only include commits by this author.

##### since?

```ts
optional since: string;
```

Only include commits after this date (ISO 8601).

##### targetRepoPath

```ts
targetRepoPath: string;
```

Path to the Git repository to audit.

##### until?

```ts
optional until: string;
```

Only include commits before this date (ISO 8601).

***

### AuditReport

Full audit report for a Git repository's commit signatures.

#### Properties

##### commits

```ts
commits: AuditCommit[];
```

Individual commit audit entries.

##### summary

```ts
summary: AuditSummary;
```

Aggregate signature statistics.

***

### AuditReportOptions

Options for [AuditService.report](#report).

#### Properties

##### author?

```ts
optional author: string;
```

Only include commits by this author.

##### limit?

```ts
optional limit: number;
```

Maximum number of commits to analyze.

##### since?

```ts
optional since: string;
```

Only include commits after this date (ISO 8601).

##### targetRepoPath

```ts
targetRepoPath: string;
```

Path to the Git repository to audit.

##### until?

```ts
optional until: string;
```

Only include commits before this date (ISO 8601).

***

### AuditSummary

Aggregate statistics from an audit report.

#### Properties

##### auths\_signed

```ts
auths_signed: number;
```

Number of Auths-signed commits.

##### gpg\_signed

```ts
gpg_signed: number;
```

Number of GPG-signed commits.

##### signed\_commits

```ts
signed_commits: number;
```

Number of signed commits (any method).

##### ssh\_signed

```ts
ssh_signed: number;
```

Number of SSH-signed commits.

##### total\_commits

```ts
total_commits: number;
```

Total number of commits analyzed.

##### unsigned\_commits

```ts
unsigned_commits: number;
```

Number of unsigned commits.

##### verification\_failed

```ts
verification_failed: number;
```

Number of signatures that failed verification.

##### verification\_passed

```ts
verification_passed: number;
```

Number of signatures that passed verification.

***

### ChainLink

A single link in a verified attestation chain.

#### Properties

##### error?

```ts
optional error: string | null;
```

Error message if this link failed, or `null`.

##### issuer

```ts
issuer: string;
```

DID of the issuer at this link.

##### subject

```ts
subject: string;
```

DID of the subject at this link.

##### valid

```ts
valid: boolean;
```

Whether this link verified successfully.

***

### ClientConfig

Configuration for the [Auths](#auths) client.

#### Properties

##### passphrase?

```ts
optional passphrase: string;
```

Passphrase for key encryption. Can also be set via `AUTHS_PASSPHRASE` env var.

##### repoPath?

```ts
optional repoPath: string;
```

Path to the Auths Git registry. Defaults to `'~/.auths'`.

***

### CommitSignResult

Result of signing a Git commit.

#### Properties

##### method

```ts
method: string;
```

Signing method identifier.

##### namespace

```ts
namespace: string;
```

Namespace for the signature (e.g. `'auths'`).

##### signaturePem

```ts
signaturePem: string;
```

PEM-encoded signature for the commit.

***

### CompletePairingOptions

Options for [PairingService.complete](#complete).

#### Properties

##### capabilities?

```ts
optional capabilities: string[];
```

Capabilities to grant the device.

##### deviceDid

```ts
deviceDid: string;
```

DID of the device to authorize.

##### devicePublicKeyHex

```ts
devicePublicKeyHex: string;
```

Hex-encoded Ed25519 public key of the device.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### CreateAgentOptions

Options for [IdentityService.createAgent](#createagent).

#### Properties

##### capabilities

```ts
capabilities: string[];
```

Capabilities to grant (e.g. `['sign']`).

##### name

```ts
name: string;
```

Name for the agent identity.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### CreateIdentityOptions

Options for [IdentityService.create](#create).

#### Properties

##### label?

```ts
optional label: string;
```

Human-readable label. Defaults to `'main'`.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### repoPath?

```ts
optional repoPath: string;
```

Override the client's repo path.

***

### CreateOrgOptions

Options for [OrgService.create](#create-1).

#### Properties

##### label

```ts
label: string;
```

Human-readable label for the organization.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### repoPath?

```ts
optional repoPath: string;
```

Override the client's repo path.

***

### CreatePairingSessionOptions

Options for [PairingService.createSession](#createsession).

#### Properties

##### bindAddress?

```ts
optional bindAddress: string;
```

Bind address for the pairing server (e.g. `'127.0.0.1'`).

##### capabilities?

```ts
optional capabilities: string[];
```

Capabilities to offer the pairing device (e.g. `['sign:commit']`).

##### enableMdns?

```ts
optional enableMdns: boolean;
```

Whether to enable mDNS discovery.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### timeoutSecs?

```ts
optional timeoutSecs: number;
```

Timeout in seconds for the session.

***

### DelegateAgentOptions

Options for [IdentityService.delegateAgent](#delegateagent).

#### Properties

##### capabilities

```ts
capabilities: string[];
```

Capabilities to grant (e.g. `['sign']`).

##### expiresInDays?

```ts
optional expiresInDays: number;
```

Optional expiration in days.

##### identityDid

```ts
identityDid: string;
```

DID of the parent identity that delegates authority.

##### name

```ts
name: string;
```

Name for the delegated agent.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### DelegatedAgent

An agent delegated under an existing identity.

#### Properties

##### attestation

```ts
attestation: string;
```

JSON-serialized delegation attestation signed by the parent identity.

##### did

```ts
did: string;
```

The delegated agent's DID (typically `did:key:z...`).

##### keyAlias

```ts
keyAlias: string;
```

Keychain alias for the agent's signing key.

##### publicKey

```ts
publicKey: string;
```

Hex-encoded Ed25519 public key.

***

### Device

Result of linking a device to an identity.

#### Properties

##### attestationId

```ts
attestationId: string;
```

Unique identifier of the attestation granting device authorization.

##### did

```ts
did: string;
```

The device's DID (typically `did:key:z...`).

***

### DeviceExtension

Result of extending a device's authorization period.

#### Properties

##### deviceDid

```ts
deviceDid: string;
```

The device's DID.

##### newExpiresAt

```ts
newExpiresAt: string;
```

New expiration timestamp (RFC 3339).

##### previousExpiresAt

```ts
previousExpiresAt: string | null;
```

Previous expiration timestamp, or `null` if there was none.

***

### EvalContextOpts

Context for policy evaluation.

#### Properties

##### capabilities?

```ts
optional capabilities: string[];
```

Capabilities held by the subject.

##### chainDepth?

```ts
optional chainDepth: number;
```

Depth of the attestation chain.

##### delegatedBy?

```ts
optional delegatedBy: string;
```

DID of the delegating identity.

##### environment?

```ts
optional environment: string;
```

Deployment environment (e.g. `'production'`).

##### expiresAt?

```ts
optional expiresAt: string;
```

Expiration timestamp (RFC 3339).

##### issuer

```ts
issuer: string;
```

DID of the attestation issuer.

##### repo?

```ts
optional repo: string;
```

Repository scope (e.g. `'org/repo'`).

##### revoked?

```ts
optional revoked: boolean;
```

Whether the attestation has been revoked.

##### role?

```ts
optional role: string;
```

Role of the subject (e.g. `'admin'`, `'member'`).

##### signerType?

```ts
optional signerType: "human" | "agent" | "workload";
```

Signer type constraint.

##### subject

```ts
subject: string;
```

DID of the attestation subject.

***

### ExtendDeviceOptions

Options for [DeviceService.extend](#extend).

#### Properties

##### days?

```ts
optional days: number;
```

Number of days to extend by. Defaults to 90.

##### deviceDid

```ts
deviceDid: string;
```

DID of the device to extend.

##### identityDid

```ts
identityDid: string;
```

DID of the authorizing identity.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### GetPublicKeyOptions

Options for [IdentityService.getPublicKey](#getpublickey-1).

#### Properties

##### identityDid

```ts
identityDid: string;
```

DID of the identity whose public key to retrieve.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### Identity

A cryptographic identity anchored in a KERI key event log.

#### Properties

##### did

```ts
did: string;
```

The KERI decentralized identifier (e.g. `did:keri:EBfd...`).

##### keyAlias

```ts
keyAlias: string;
```

Keychain alias used to retrieve the signing key.

##### label

```ts
label: string;
```

Human-readable label for this identity.

##### publicKey

```ts
publicKey: string;
```

Hex-encoded Ed25519 public key.

##### repoPath

```ts
repoPath: string;
```

Path to the Git registry that stores this identity.

***

### JoinPairingOptions

Options for [PairingService.join](#join).

#### Properties

##### deviceName?

```ts
optional deviceName: string;
```

Optional name for this device.

##### endpoint

```ts
endpoint: string;
```

HTTP endpoint of the pairing session.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### shortCode

```ts
shortCode: string;
```

Six-character short code from the pairing session.

##### token

```ts
token: string;
```

Authentication token for the session.

***

### LinkDeviceOptions

Options for [DeviceService.link](#link).

#### Properties

##### capabilities?

```ts
optional capabilities: string[];
```

Capabilities to grant the device (e.g. `['sign']`).

##### expiresInDays?

```ts
optional expiresInDays: number;
```

Optional expiration in days.

##### identityDid

```ts
identityDid: string;
```

DID of the identity to link the device under.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### ListOrgMembersOptions

Options for [OrgService.listMembers](#listmembers).

#### Properties

##### includeRevoked?

```ts
optional includeRevoked: boolean;
```

Whether to include revoked members. Defaults to `false`.

##### orgDid

```ts
orgDid: string;
```

DID of the organization.

***

### OrgMember

An organization member record.

#### Properties

##### attestationRid

```ts
attestationRid: string;
```

Resource identifier of the membership attestation.

##### capabilities

```ts
capabilities: string[];
```

Capabilities granted to this member.

##### expiresAt

```ts
expiresAt: string | null;
```

Expiration timestamp (RFC 3339), or `null` if no expiry.

##### issuerDid

```ts
issuerDid: string;
```

DID of the admin who added this member.

##### memberDid

```ts
memberDid: string;
```

DID of the member.

##### revoked

```ts
revoked: boolean;
```

Whether the membership has been revoked.

##### role

```ts
role: string;
```

Role within the organization (e.g. `'admin'`, `'member'`).

***

### OrgResult

Result of creating an organization.

#### Properties

##### label

```ts
label: string;
```

Human-readable label.

##### orgDid

```ts
orgDid: string;
```

The organization's KERI DID.

##### orgPrefix

```ts
orgPrefix: string;
```

Internal prefix for the organization.

##### repoPath

```ts
repoPath: string;
```

Path to the registry storing the organization.

***

### PairingResponse

Response received when a device connects to a pairing session.

#### Properties

##### deviceDid

```ts
deviceDid: string;
```

DID of the connecting device.

##### deviceName

```ts
deviceName: string | null;
```

Optional name of the device, or `null`.

##### devicePublicKeyHex

```ts
devicePublicKeyHex: string;
```

Hex-encoded Ed25519 public key of the device.

***

### PairingResult

Result of completing a pairing and authorizing the device.

#### Properties

##### attestationRid

```ts
attestationRid: string;
```

Resource identifier of the authorization attestation.

##### deviceDid

```ts
deviceDid: string;
```

DID of the paired device.

##### deviceName

```ts
deviceName: string | null;
```

Optional name of the device, or `null`.

***

### PairingSession

An active pairing session awaiting a device connection.

#### Properties

##### controllerDid

```ts
controllerDid: string;
```

DID of the controller identity running the session.

##### endpoint

```ts
endpoint: string;
```

HTTP endpoint the device connects to.

##### sessionId

```ts
sessionId: string;
```

Unique session identifier.

##### shortCode

```ts
shortCode: string;
```

Six-character code the device enters to pair.

##### token

```ts
token: string;
```

Authentication token for the session.

***

### PinIdentityOptions

Options for [TrustService.pin](#pin).

#### Properties

##### did

```ts
did: string;
```

DID of the identity to pin.

##### label?

```ts
optional label: string;
```

Optional label for the pinned identity.

##### trustLevel?

```ts
optional trustLevel: "tofu" | "manual" | "org_policy";
```

Trust level to assign. Defaults to `'tofu'`.

***

### PinnedIdentity

A pinned (trusted) identity in the local trust store.

#### Properties

##### did

```ts
did: string;
```

The pinned identity's DID.

##### firstSeen

```ts
firstSeen: string;
```

ISO 8601 timestamp when this identity was first seen.

##### kelSequence

```ts
kelSequence: number | null;
```

KERI event log sequence number at time of pinning, or `null`.

##### label

```ts
label: string | null;
```

Optional label for the pinned identity.

##### pinnedAt

```ts
pinnedAt: string;
```

ISO 8601 timestamp when this identity was pinned.

##### trustLevel

```ts
trustLevel: string;
```

Trust level: `'tofu'`, `'manual'`, or `'org_policy'`.

***

### PolicyDecision

Result of evaluating a policy against a context.

#### Properties

##### allowed

```ts
allowed: boolean;
```

Convenience: `true` when `outcome === 'allow'`.

##### denied

```ts
denied: boolean;
```

Convenience: `true` when `outcome === 'deny'`.

##### message

```ts
message: string;
```

Human-readable explanation of the decision.

##### outcome

```ts
outcome: string;
```

Raw outcome string (`'allow'` or `'deny'`).

##### reason

```ts
reason: string;
```

Machine-readable reason code.

***

### RevokeDeviceOptions

Options for [DeviceService.revoke](#revoke).

#### Properties

##### deviceDid

```ts
deviceDid: string;
```

DID of the device to revoke.

##### identityDid

```ts
identityDid: string;
```

DID of the identity that authorized the device.

##### note?

```ts
optional note: string;
```

Optional revocation note.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### RevokeOrgMemberOptions

Options for [OrgService.revokeMember](#revokemember).

#### Properties

##### memberDid

```ts
memberDid: string;
```

DID of the member to revoke.

##### memberPublicKeyHex?

```ts
optional memberPublicKeyHex: string;
```

Hex-encoded public key of the member.

##### note?

```ts
optional note: string;
```

Optional revocation note.

##### orgDid

```ts
orgDid: string;
```

DID of the organization.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### RotateKeysOptions

Options for [IdentityService.rotate](#rotate).

#### Properties

##### identityDid?

```ts
optional identityDid: string;
```

DID of the identity to rotate. Defaults to the primary identity.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### RotationResult

Result of a key rotation operation.

#### Properties

##### controllerDid

```ts
controllerDid: string;
```

The controller DID whose keys were rotated.

##### newKeyFingerprint

```ts
newKeyFingerprint: string;
```

Fingerprint of the new signing key.

##### previousKeyFingerprint

```ts
previousKeyFingerprint: string;
```

Fingerprint of the previous signing key.

##### sequence

```ts
sequence: number;
```

New KERI event sequence number after rotation.

***

### SignActionAsAgentOptions

Options for [SigningService.signActionAsAgent](#signactionasagent-1).

#### Properties

##### actionType

```ts
actionType: string;
```

Action type label (e.g. `'tool_call'`).

##### agentDid

```ts
agentDid: string;
```

DID of the agent identity.

##### keyAlias

```ts
keyAlias: string;
```

Keychain alias of the agent key.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### payloadJson

```ts
payloadJson: string;
```

JSON-serialized action payload.

***

### SignActionAsIdentityOptions

Options for [SigningService.signActionAsIdentity](#signactionasidentity).

#### Properties

##### actionType

```ts
actionType: string;
```

Action type label (e.g. `'tool_call'`).

##### identityDid

```ts
identityDid: string;
```

DID of the identity to sign with.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

##### payloadJson

```ts
payloadJson: string;
```

JSON-serialized action payload.

***

### SignArtifactBytesOptions

Options for [ArtifactService.signBytes](#signbytes).

#### Properties

##### data

```ts
data: Buffer;
```

Raw bytes to sign.

##### expiresInDays?

```ts
optional expiresInDays: number;
```

Optional expiration in days.

##### identityDid

```ts
identityDid: string;
```

DID of the identity to sign with.

##### note?

```ts
optional note: string;
```

Optional note attached to the attestation.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### SignArtifactOptions

Options for [ArtifactService.sign](#sign).

#### Properties

##### expiresInDays?

```ts
optional expiresInDays: number;
```

Optional expiration in days.

##### filePath

```ts
filePath: string;
```

Path to the file to sign.

##### identityDid

```ts
identityDid: string;
```

DID of the identity to sign with.

##### note?

```ts
optional note: string;
```

Optional note attached to the attestation.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### SignAsAgentOptions

Options for [SigningService.signAsAgent](#signasagent-1).

#### Properties

##### keyAlias

```ts
keyAlias: string;
```

Keychain alias of the agent key.

##### message

```ts
message: Buffer;
```

The message bytes to sign.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### SignAsIdentityOptions

Options for [SigningService.signAsIdentity](#signasidentity).

#### Properties

##### identityDid

```ts
identityDid: string;
```

DID of the identity to sign with.

##### message

```ts
message: Buffer;
```

The message bytes to sign.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### SignCommitOptions

Options for [CommitService.sign](#sign-1).

#### Properties

##### data

```ts
data: Buffer;
```

Raw commit data to sign.

##### identityDid

```ts
identityDid: string;
```

DID of the identity to sign with.

##### passphrase?

```ts
optional passphrase: string;
```

Override the client's passphrase.

***

### SignResult

Result of a signing operation.

#### Properties

##### signature

```ts
signature: string;
```

Hex-encoded Ed25519 signature.

##### signerDid

```ts
signerDid: string;
```

DID of the signer.

***

### VerificationReport

Full report from a chain verification.

#### Properties

##### chain

```ts
chain: ChainLink[];
```

Individual chain link results.

##### status

```ts
status: VerificationStatus;
```

Overall verification status.

##### warnings

```ts
warnings: string[];
```

Non-fatal warnings encountered during verification.

***

### VerificationResult

Result of verifying a single attestation.

#### Properties

##### error?

```ts
optional error: string | null;
```

Error message if verification failed, or `null`.

##### errorCode?

```ts
optional errorCode: string | null;
```

Machine-readable error code, or `null`.

##### valid

```ts
valid: boolean;
```

Whether the attestation is valid.

***

### VerificationStatus

Status summary of a chain verification.

#### Properties

##### at?

```ts
optional at: string | null;
```

Timestamp context for the status, or `null`.

##### missingLink?

```ts
optional missingLink: string | null;
```

DID of the missing link in the chain, or `null`.

##### required?

```ts
optional required: number | null;
```

Number of required witnesses, or `null`.

##### statusType

```ts
statusType: string;
```

Status type: `'Valid'`, `'Invalid'`, `'Expired'`, etc.

##### step?

```ts
optional step: number | null;
```

Chain step where verification failed, or `null`.

##### verified?

```ts
optional verified: number | null;
```

Number of verified witnesses, or `null`.

***

### VerifyChainOptions

Options for [Auths.verifyChain](#verifychain).

#### Properties

##### attestations

```ts
attestations: string[];
```

Array of JSON-serialized attestations (leaf to root).

##### requiredCapability?

```ts
optional requiredCapability: string;
```

Optional capability the leaf attestation must grant.

##### rootKey

```ts
rootKey: string;
```

Hex-encoded Ed25519 public key of the root identity.

##### witnesses?

```ts
optional witnesses: WitnessConfig;
```

Optional witness configuration for receipt-based verification.

***

### VerifyOptions

Options for [Auths.verify](#verify).

#### Properties

##### at?

```ts
optional at: string;
```

Optional RFC 3339 timestamp to verify at.

##### attestationJson

```ts
attestationJson: string;
```

JSON-serialized attestation to verify.

##### issuerKey

```ts
issuerKey: string;
```

Hex-encoded Ed25519 public key of the issuer.

##### requiredCapability?

```ts
optional requiredCapability: string;
```

Optional capability the attestation must grant.

***

### WaitForPairingResponseOptions

Options for [PairingService.waitForResponse](#waitforresponse).

#### Properties

##### timeoutSecs?

```ts
optional timeoutSecs: number;
```

Timeout in seconds to wait for a device.

***

### WitnessConfig

Configuration for witness-backed chain verification.

#### Properties

##### keys

```ts
keys: WitnessKey[];
```

Witness public keys.

##### receipts

```ts
receipts: string[];
```

JSON-serialized witness receipts.

##### threshold

```ts
threshold: number;
```

Minimum number of witness receipts required.

***

### WitnessEntry

A witness node entry in the local registry.

#### Properties

##### did

```ts
did: string | null;
```

DID of the witness, or `null` if not yet resolved.

##### label

```ts
label: string | null;
```

Optional label for the witness.

##### url

```ts
url: string;
```

URL of the witness endpoint.

***

### WitnessKey

Public key of a witness node.

#### Properties

##### did

```ts
did: string;
```

DID of the witness.

##### publicKeyHex

```ts
publicKeyHex: string;
```

Hex-encoded Ed25519 public key of the witness.

## Variables

### version()

```ts
const version: () => string = native.version;
```

#### Returns

`string`

## Functions

### compilePolicy()

```ts
function compilePolicy(policyJson): string;
```

Compiles a raw policy JSON string for use with [evaluatePolicy](#evaluatepolicy).

#### Parameters

##### policyJson

`string`

JSON string of the policy expression.

#### Returns

`string`

Compiled policy JSON.

#### Throws

[AuthsError](#authserror) if the policy is invalid.

***

### evaluatePolicy()

```ts
function evaluatePolicy(compiledPolicyJson, context): PolicyDecision;
```

Evaluates a compiled policy against an attestation context.

#### Parameters

##### compiledPolicyJson

`string`

Compiled policy from [compilePolicy](#compilepolicy) or [PolicyBuilder.build](#build).

##### context

[`EvalContextOpts`](#evalcontextopts)

The evaluation context.

#### Returns

[`PolicyDecision`](#policydecision)

The policy decision with `allowed`/`denied` convenience booleans.

#### Throws

[AuthsError](#authserror) if evaluation fails.

#### Example

```typescript
import { compilePolicy, evaluatePolicy } from '@auths-dev/node'

const compiled = compilePolicy(policyJson)
const decision = evaluatePolicy(compiled, {
  issuer: 'did:keri:EOrg',
  subject: 'did:key:zDevice',
})
```

***

### mapNativeError()

```ts
function mapNativeError(err, defaultCls?): AuthsError;
```

Maps a native napi-rs error into a typed [AuthsError](#authserror) subclass.

Parses the `[AUTHS_CODE] message` format emitted by the Rust layer
and instantiates the appropriate error class with a machine-readable code.

#### Parameters

##### err

`unknown`

The raw error from the native binding.

##### defaultCls?

(`message`, `code`) => [`AuthsError`](#authserror)

Fallback error class when the code is unrecognized.

#### Returns

[`AuthsError`](#authserror)

A typed [AuthsError](#authserror) instance.

***

### verifyAttestation()

```ts
function verifyAttestation(attestationJson, issuerPkHex): Promise<VerificationResult>;
```

Verifies a single attestation against an issuer's public key.

#### Parameters

##### attestationJson

`string`

JSON-serialized attestation.

##### issuerPkHex

`string`

Hex-encoded Ed25519 public key of the issuer.

#### Returns

`Promise`\<[`VerificationResult`](#verificationresult)\>

The verification result.

#### Throws

[VerificationError](#verificationerror) if verification encounters an error.

#### Example

```typescript
import { verifyAttestation } from '@auths-dev/node'

const result = await verifyAttestation(attestationJson, publicKeyHex)
console.log(result.valid) // true
```

***

### verifyAttestationWithCapability()

```ts
function verifyAttestationWithCapability(
   attestationJson,
   issuerPkHex,
requiredCapability): Promise<VerificationResult>;
```

Verifies a single attestation with a required capability check.

#### Parameters

##### attestationJson

`string`

JSON-serialized attestation.

##### issuerPkHex

`string`

Hex-encoded Ed25519 public key of the issuer.

##### requiredCapability

`string`

Capability the attestation must grant.

#### Returns

`Promise`\<[`VerificationResult`](#verificationresult)\>

The verification result.

#### Throws

[VerificationError](#verificationerror) if verification fails.

***

### verifyAtTime()

```ts
function verifyAtTime(
   attestationJson,
   issuerPkHex,
atRfc3339): Promise<VerificationResult>;
```

Verifies a single attestation at a specific point in time.

#### Parameters

##### attestationJson

`string`

JSON-serialized attestation.

##### issuerPkHex

`string`

Hex-encoded Ed25519 public key of the issuer.

##### atRfc3339

`string`

RFC 3339 timestamp to verify at.

#### Returns

`Promise`\<[`VerificationResult`](#verificationresult)\>

The verification result.

#### Throws

[VerificationError](#verificationerror) if verification fails.

***

### verifyAtTimeWithCapability()

```ts
function verifyAtTimeWithCapability(
   attestationJson,
   issuerPkHex,
   atRfc3339,
requiredCapability): Promise<VerificationResult>;
```

Verifies an attestation at a specific time with a required capability.

#### Parameters

##### attestationJson

`string`

JSON-serialized attestation.

##### issuerPkHex

`string`

Hex-encoded Ed25519 public key of the issuer.

##### atRfc3339

`string`

RFC 3339 timestamp to verify at.

##### requiredCapability

`string`

Capability the attestation must grant.

#### Returns

`Promise`\<[`VerificationResult`](#verificationresult)\>

The verification result.

#### Throws

[VerificationError](#verificationerror) if verification fails.

***

### verifyChain()

```ts
function verifyChain(attestationsJson, rootPkHex): Promise<VerificationReport>;
```

Verifies an attestation chain from leaf to root.

#### Parameters

##### attestationsJson

`string`[]

Array of JSON-serialized attestations (leaf to root).

##### rootPkHex

`string`

Hex-encoded Ed25519 public key of the root identity.

#### Returns

`Promise`\<[`VerificationReport`](#verificationreport)\>

The verification report with chain link details.

#### Throws

[VerificationError](#verificationerror) if verification encounters an error.

#### Example

```typescript
import { verifyChain } from '@auths-dev/node'

const report = await verifyChain(attestationChain, rootPublicKeyHex)
console.log(report.status.statusType) // 'Valid'
```

***

### verifyChainWithCapability()

```ts
function verifyChainWithCapability(
   attestationsJson,
   rootPkHex,
requiredCapability): Promise<VerificationReport>;
```

Verifies an attestation chain with a required capability at the leaf.

#### Parameters

##### attestationsJson

`string`[]

Array of JSON-serialized attestations (leaf to root).

##### rootPkHex

`string`

Hex-encoded Ed25519 public key of the root identity.

##### requiredCapability

`string`

Capability the leaf attestation must grant.

#### Returns

`Promise`\<[`VerificationReport`](#verificationreport)\>

The verification report.

#### Throws

[VerificationError](#verificationerror) if verification fails.

***

### verifyChainWithWitnesses()

```ts
function verifyChainWithWitnesses(
   attestationsJson,
   rootPkHex,
witnesses): Promise<VerificationReport>;
```

Verifies an attestation chain with witness receipt validation.

#### Parameters

##### attestationsJson

`string`[]

Array of JSON-serialized attestations (leaf to root).

##### rootPkHex

`string`

Hex-encoded Ed25519 public key of the root identity.

##### witnesses

[`WitnessConfig`](#witnessconfig)

Witness configuration with receipts, keys, and threshold.

#### Returns

`Promise`\<[`VerificationReport`](#verificationreport)\>

The verification report.

#### Throws

[VerificationError](#verificationerror) if verification fails.

#### Example

```typescript
import { verifyChainWithWitnesses } from '@auths-dev/node'

const report = await verifyChainWithWitnesses(chain, rootKey, {
  receipts: witnessReceipts,
  keys: [{ did: witnessDid, publicKeyHex: witnessKey }],
  threshold: 1,
})
```

***

### verifyDeviceAuthorization()

```ts
function verifyDeviceAuthorization(
   identityDid,
   deviceDid,
   attestationsJson,
identityPkHex): Promise<VerificationReport>;
```

Verifies that a device is authorized by an identity through an attestation chain.

#### Parameters

##### identityDid

`string`

DID of the authorizing identity.

##### deviceDid

`string`

DID of the device to verify.

##### attestationsJson

`string`[]

Array of JSON-serialized attestations.

##### identityPkHex

`string`

Hex-encoded Ed25519 public key of the identity.

#### Returns

`Promise`\<[`VerificationReport`](#verificationreport)\>

The verification report.

#### Throws

[VerificationError](#verificationerror) if verification fails.
