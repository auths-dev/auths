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

export interface NapiCommitSignPemResult {
  signaturePem: string
  method: string
  namespace: string
}

export interface NapiOrgResult {
  orgPrefix: string
  orgDid: string
  label: string
  repoPath: string
}

export interface NapiOrgMember {
  memberDid: string
  role: string
  capabilitiesJson: string
  issuerDid: string
  attestationRid: string
  revoked: boolean
  expiresAt?: string | null
}

export interface NapiAttestation {
  rid: string
  issuer: string
  subject: string
  deviceDid: string
  capabilities: string[]
  signerType?: string | null
  expiresAt?: string | null
  revokedAt?: string | null
  createdAt?: string | null
  delegatedBy?: string | null
  json: string
}

export interface NapiPinnedIdentity {
  did: string
  label?: string | null
  trustLevel: string
  firstSeen: string
  kelSequence?: number | null
  pinnedAt: string
}

export interface NapiWitnessResult {
  url: string
  did?: string | null
  label?: string | null
}

export interface NapiArtifactResult {
  attestationJson: string
  rid: string
  digest: string
  fileSize: number
}

export interface NapiPolicyDecision {
  outcome: string
  reason: string
  message: string
}

export interface NapiPairingSession {
  sessionId: string
  shortCode: string
  endpoint: string
  token: string
  controllerDid: string
}

export interface NapiPairingResponse {
  deviceDid: string
  deviceName?: string | null
  devicePublicKeyHex: string
}

export interface NapiPairingResult {
  deviceDid: string
  deviceName?: string | null
  attestationRid: string
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

  // Commit signing
  signCommit(data: Buffer, identityKeyAlias: string, repoPath: string, passphrase?: string | null): NapiCommitSignPemResult

  // Org
  createOrg(label: string, repoPath: string, passphrase?: string | null): NapiOrgResult
  addOrgMember(orgDid: string, memberDid: string, role: string, repoPath: string, capabilitiesJson?: string | null, passphrase?: string | null, note?: string | null, memberPublicKeyHex?: string | null): NapiOrgMember
  revokeOrgMember(orgDid: string, memberDid: string, repoPath: string, passphrase?: string | null, note?: string | null, memberPublicKeyHex?: string | null): NapiOrgMember
  listOrgMembers(orgDid: string, includeRevoked: boolean, repoPath: string): string

  // Attestation query
  listAttestations(repoPath: string): NapiAttestation[]
  listAttestationsByDevice(repoPath: string, deviceDid: string): NapiAttestation[]
  getLatestAttestation(repoPath: string, deviceDid: string): NapiAttestation | null

  // Trust
  pinIdentity(did: string, repoPath: string, label?: string | null, trustLevel?: string | null): NapiPinnedIdentity
  removePinnedIdentity(did: string, repoPath: string): void
  listPinnedIdentities(repoPath: string): string
  getPinnedIdentity(did: string, repoPath: string): NapiPinnedIdentity | null

  // Witness
  addWitness(urlStr: string, repoPath: string, label?: string | null): NapiWitnessResult
  removeWitness(urlStr: string, repoPath: string): void
  listWitnesses(repoPath: string): string

  // Artifact
  signArtifact(filePath: string, identityKeyAlias: string, repoPath: string, passphrase?: string | null, expiresInDays?: number | null, note?: string | null): NapiArtifactResult
  signArtifactBytes(data: Buffer, identityKeyAlias: string, repoPath: string, passphrase?: string | null, expiresInDays?: number | null, note?: string | null): NapiArtifactResult

  // Audit
  generateAuditReport(targetRepoPath: string, authsRepoPath: string, since?: string | null, until?: string | null, author?: string | null, limit?: number | null): string

  // Diagnostics
  runDiagnostics(repoPath: string): string

  // Policy
  compilePolicy(policyJson: string): string
  evaluatePolicy(compiledPolicyJson: string, issuer: string, subject: string, capabilities?: string[] | null, role?: string | null, revoked?: boolean | null, expiresAt?: string | null, repo?: string | null, environment?: string | null, signerType?: string | null, delegatedBy?: string | null, chainDepth?: number | null): NapiPolicyDecision

  // Pairing
  createPairingSession(repoPath: string, capabilitiesJson?: string | null, timeoutSecs?: number | null, bindAddress?: string | null, enableMdns?: boolean | null, passphrase?: string | null): NapiPairingSession
  waitForPairingResponse(timeoutSecs?: number | null): NapiPairingResponse
  stopPairingSession(): void
  joinPairingSession(shortCode: string, endpoint: string, token: string, repoPath: string, deviceName?: string | null, passphrase?: string | null): NapiPairingResponse
  completePairing(deviceDid: string, devicePublicKeyHex: string, repoPath: string, capabilitiesJson?: string | null, passphrase?: string | null): NapiPairingResult

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
