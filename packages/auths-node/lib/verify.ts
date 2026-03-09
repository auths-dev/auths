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

export async function verifyAttestation(attestationJson: string, issuerPkHex: string): Promise<VerificationResult> {
  try {
    return await native.verifyAttestation(attestationJson, issuerPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyAttestationWithCapability(attestationJson: string, issuerPkHex: string, requiredCapability: string): Promise<VerificationResult> {
  try {
    return await native.verifyAttestationWithCapability(attestationJson, issuerPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyChain(attestationsJson: string[], rootPkHex: string): Promise<VerificationReport> {
  try {
    return await native.verifyChain(attestationsJson, rootPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyChainWithCapability(attestationsJson: string[], rootPkHex: string, requiredCapability: string): Promise<VerificationReport> {
  try {
    return await native.verifyChainWithCapability(attestationsJson, rootPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyDeviceAuthorization(identityDid: string, deviceDid: string, attestationsJson: string[], identityPkHex: string): Promise<VerificationReport> {
  try {
    return await native.verifyDeviceAuthorization(identityDid, deviceDid, attestationsJson, identityPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyAtTime(attestationJson: string, issuerPkHex: string, atRfc3339: string): Promise<VerificationResult> {
  try {
    return await native.verifyAtTime(attestationJson, issuerPkHex, atRfc3339)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyAtTimeWithCapability(attestationJson: string, issuerPkHex: string, atRfc3339: string, requiredCapability: string): Promise<VerificationResult> {
  try {
    return await native.verifyAtTimeWithCapability(attestationJson, issuerPkHex, atRfc3339, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

export async function verifyChainWithWitnesses(attestationsJson: string[], rootPkHex: string, witnesses: WitnessConfig): Promise<VerificationReport> {
  const keysJson = witnesses.keys.map(k =>
    JSON.stringify({ did: k.did, public_key_hex: k.publicKeyHex }),
  )
  try {
    return await native.verifyChainWithWitnesses(
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
