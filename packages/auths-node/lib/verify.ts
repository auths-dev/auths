import native from './native'
import type { NapiVerificationResult, NapiVerificationReport } from './native'
import { mapNativeError, VerificationError } from './errors'

export interface VerificationResult {
  valid: boolean
  error?: string | null
  errorCode?: string | null
}

export interface VerificationStatus {
  statusType: string
  at?: string | null
  step?: number | null
  missingLink?: string | null
  required?: number | null
  verified?: number | null
}

export interface ChainLink {
  issuer: string
  subject: string
  valid: boolean
  error?: string | null
}

export interface VerificationReport {
  status: VerificationStatus
  chain: ChainLink[]
  warnings: string[]
}

export interface WitnessKey {
  did: string
  publicKeyHex: string
}

export interface WitnessConfig {
  receipts: string[]
  keys: WitnessKey[]
  threshold: number
}

export function verifyAttestation(attestationJson: string, issuerPkHex: string): VerificationResult {
  try {
    return native.verifyAttestation(attestationJson, issuerPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyAttestationWithCapability(attestationJson: string, issuerPkHex: string, requiredCapability: string): VerificationResult {
  try {
    return native.verifyAttestationWithCapability(attestationJson, issuerPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyChain(attestationsJson: string[], rootPkHex: string): VerificationReport {
  try {
    return native.verifyChain(attestationsJson, rootPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyChainWithCapability(attestationsJson: string[], rootPkHex: string, requiredCapability: string): VerificationReport {
  try {
    return native.verifyChainWithCapability(attestationsJson, rootPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyDeviceAuthorization(identityDid: string, deviceDid: string, attestationsJson: string[], identityPkHex: string): VerificationReport {
  try {
    return native.verifyDeviceAuthorization(identityDid, deviceDid, attestationsJson, identityPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyAtTime(attestationJson: string, issuerPkHex: string, atRfc3339: string): VerificationResult {
  try {
    return native.verifyAtTime(attestationJson, issuerPkHex, atRfc3339)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyAtTimeWithCapability(attestationJson: string, issuerPkHex: string, atRfc3339: string, requiredCapability: string): VerificationResult {
  try {
    return native.verifyAtTimeWithCapability(attestationJson, issuerPkHex, atRfc3339, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export function verifyChainWithWitnesses(attestationsJson: string[], rootPkHex: string, witnesses: WitnessConfig): VerificationReport {
  const keysJson = witnesses.keys.map(k =>
    JSON.stringify({ did: k.did, public_key_hex: k.publicKeyHex }),
  )
  try {
    return native.verifyChainWithWitnesses(
      attestationsJson,
      rootPkHex,
      witnesses.receipts,
      keysJson,
      witnesses.threshold,
    )
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}
