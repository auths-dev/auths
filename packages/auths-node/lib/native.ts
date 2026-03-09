// Type declarations for native napi-rs bindings (auto-generated at build time)
// This file provides typed access to the Rust #[napi] functions

export interface NapiVerificationResult {
  valid: boolean
  error?: string | null
  errorCode?: string | null
}

export interface NapiVerificationStatus {
  statusType: string
  at?: string | null
  step?: number | null
  missingLink?: string | null
  required?: number | null
  verified?: number | null
}

export interface NapiChainLink {
  issuer: string
  subject: string
  valid: boolean
  error?: string | null
}

export interface NapiVerificationReport {
  status: NapiVerificationStatus
  chain: NapiChainLink[]
  warnings: string[]
}

export interface NapiIdentityResult {
  did: string
  keyAlias: string
  publicKeyHex: string
}

export interface NapiAgentIdentityBundle {
  agentDid: string
  keyAlias: string
  attestationJson: string
  publicKeyHex: string
  repoPath?: string | null
}

export interface NapiDelegatedAgentBundle {
  agentDid: string
  keyAlias: string
  attestationJson: string
  publicKeyHex: string
  repoPath?: string | null
}

export interface NapiRotationResult {
  controllerDid: string
  newKeyFingerprint: string
  previousKeyFingerprint: string
  sequence: number
}

export interface NapiLinkResult {
  deviceDid: string
  attestationId: string
}

export interface NapiExtensionResult {
  deviceDid: string
  newExpiresAt: string
  previousExpiresAt?: string | null
}

export interface NapiCommitSignResult {
  signature: string
  signerDid: string
}

export interface NapiActionEnvelope {
  envelopeJson: string
  signatureHex: string
  signerDid: string
}

export interface NativeBindings {
  version(): string

  // Identity
  createIdentity(keyAlias: string, repoPath: string, passphrase?: string | null): NapiIdentityResult
  createAgentIdentity(agentName: string, capabilities: string[], repoPath: string, passphrase?: string | null): NapiAgentIdentityBundle
  delegateAgent(agentName: string, capabilities: string[], parentRepoPath: string, passphrase?: string | null, expiresInDays?: number | null, identityDid?: string | null): NapiDelegatedAgentBundle
  rotateIdentityKeys(repoPath: string, identityKeyAlias?: string | null, nextKeyAlias?: string | null, passphrase?: string | null): NapiRotationResult
  getIdentityPublicKey(identityDid: string, passphrase?: string | null): string

  // Device
  linkDeviceToIdentity(identityKeyAlias: string, capabilities: string[], repoPath: string, passphrase?: string | null, expiresInDays?: number | null): NapiLinkResult
  revokeDeviceFromIdentity(deviceDid: string, identityKeyAlias: string, repoPath: string, passphrase?: string | null, note?: string | null): void
  extendDeviceAuthorization(deviceDid: string, identityKeyAlias: string, days: number, repoPath: string, passphrase?: string | null): NapiExtensionResult

  // Signing
  signAsIdentity(message: Buffer, identityDid: string, repoPath: string, passphrase?: string | null): NapiCommitSignResult
  signActionAsIdentity(actionType: string, payloadJson: string, identityDid: string, repoPath: string, passphrase?: string | null): NapiActionEnvelope
  signAsAgent(message: Buffer, keyAlias: string, passphrase?: string | null): NapiCommitSignResult
  signActionAsAgent(actionType: string, payloadJson: string, keyAlias: string, agentDid: string, passphrase?: string | null): NapiActionEnvelope

  // Verification
  verifyAttestation(attestationJson: string, issuerPkHex: string): NapiVerificationResult
  verifyChain(attestationsJson: string[], rootPkHex: string): NapiVerificationReport
  verifyDeviceAuthorization(identityDid: string, deviceDid: string, attestationsJson: string[], identityPkHex: string): NapiVerificationReport
  verifyAttestationWithCapability(attestationJson: string, issuerPkHex: string, requiredCapability: string): NapiVerificationResult
  verifyChainWithCapability(attestationsJson: string[], rootPkHex: string, requiredCapability: string): NapiVerificationReport
  verifyAtTime(attestationJson: string, issuerPkHex: string, atRfc3339: string): NapiVerificationResult
  verifyAtTimeWithCapability(attestationJson: string, issuerPkHex: string, atRfc3339: string, requiredCapability: string): NapiVerificationResult
  verifyChainWithWitnesses(attestationsJson: string[], rootPkHex: string, receiptsJson: string[], witnessKeysJson: string[], threshold: number): NapiVerificationReport
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
const native: NativeBindings = require('../../index.js')

export default native
