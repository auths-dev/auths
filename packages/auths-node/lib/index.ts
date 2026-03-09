export { Auths, type ClientConfig } from './client'
export { IdentityService, type Identity, type AgentIdentity, type DelegatedAgent, type RotationResult } from './identity'
export { DeviceService, type Device, type DeviceExtension } from './devices'
export { SigningService, type SignResult, type ActionEnvelope } from './signing'
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
