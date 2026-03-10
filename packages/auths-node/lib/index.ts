export { Auths, type ClientConfig, type VerifyOptions, type VerifyChainOptions } from './client'
export {
  IdentityService,
  type Identity,
  type AgentIdentity,
  type DelegatedAgent,
  type RotationResult,
  type CreateIdentityOptions,
  type CreateAgentOptions,
  type DelegateAgentOptions,
  type RotateKeysOptions,
  type GetPublicKeyOptions,
} from './identity'
export {
  DeviceService,
  type Device,
  type DeviceExtension,
  type LinkDeviceOptions,
  type RevokeDeviceOptions,
  type ExtendDeviceOptions,
} from './devices'
export {
  SigningService,
  type SignResult,
  type ActionEnvelope,
  type SignAsIdentityOptions,
  type SignActionAsIdentityOptions,
  type SignAsAgentOptions,
  type SignActionAsAgentOptions,
} from './signing'
export {
  OrgService,
  isAdmin,
  type OrgResult,
  type OrgMember,
  type CreateOrgOptions,
  type AddOrgMemberOptions,
  type RevokeOrgMemberOptions,
  type ListOrgMembersOptions,
} from './org'
export { TrustService, TrustLevel, type PinnedIdentity, type PinIdentityOptions } from './trust'
export { WitnessService, type WitnessEntry, type AddWitnessOptions } from './witness'
export { AttestationService, type AttestationInfo } from './attestations'
export {
  ArtifactService,
  type ArtifactResult,
  type SignArtifactOptions,
  type SignArtifactBytesOptions,
} from './artifacts'
export { CommitService, type CommitSignResult, type SignCommitOptions } from './commits'
export {
  AuditService,
  parseIdentityBundle,
  parseIdentityBundleInfo,
  type AuditReport,
  type AuditCommit,
  type AuditSummary,
  type AuditReportOptions,
  type AuditComplianceOptions,
  type IdentityBundleInfo,
} from './audit'
export {
  PolicyBuilder,
  Outcome,
  ReasonCode,
  compilePolicy,
  evaluatePolicy,
  evalContextFromCommitResult,
  type PolicyDecision,
  type EvalContextOpts,
  type CommitResultLike,
} from './policy'
export {
  PairingService,
  type PairingSession,
  type PairingResponse,
  type PairingResult,
  type CreatePairingSessionOptions,
  type WaitForPairingResponseOptions,
  type JoinPairingOptions,
  type CompletePairingOptions,
} from './pairing'
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

export {
  parseIdentityDid,
  parseDeviceDid,
  SignerType,
  Role,
  WellKnownCapability,
  type IdentityDID,
  type DeviceDID,
  type BundleAttestation,
  type IdentityBundle,
} from './types'

import native from './native'
export const version: () => string = native.version
