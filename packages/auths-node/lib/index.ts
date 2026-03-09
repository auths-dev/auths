export { Auths, type ClientConfig } from './client'
export { IdentityService, type Identity, type AgentIdentity, type DelegatedAgent, type RotationResult } from './identity'
export { DeviceService, type Device, type DeviceExtension } from './devices'
export { SigningService, type SignResult, type ActionEnvelope } from './signing'
export { OrgService, type OrgResult, type OrgMember } from './org'
export { TrustService, type PinnedIdentity } from './trust'
export { WitnessService, type WitnessEntry } from './witness'
export { AttestationService, type AttestationInfo } from './attestations'
export { ArtifactService, type ArtifactResult } from './artifacts'
export { CommitService, type CommitSignResult } from './commits'
export { AuditService, type AuditReport, type AuditCommit, type AuditSummary } from './audit'
export {
  verifyAttestation,
  verifyAttestationWithCapability,
  verifyChain,
  verifyChainWithCapability,
  verifyDeviceAuthorization,
  verifyAtTime,
  verifyAtTimeWithCapability,
  verifyChainWithWitnesses,
  type VerificationResult,
  type VerificationReport,
  type VerificationStatus,
  type ChainLink,
  type WitnessConfig,
  type WitnessKey,
} from './verify'
export {
  AuthsError,
  VerificationError,
  CryptoError,
  KeychainError,
  StorageError,
  NetworkError,
  IdentityError,
  OrgError,
  PairingError,
  mapNativeError,
} from './errors'

import native from './native'
export const version: () => string = native.version
