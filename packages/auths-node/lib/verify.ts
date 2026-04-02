import native from './native'
import type { NapiVerificationResult, NapiVerificationReport } from './native'
import { mapNativeError, VerificationError } from './errors'

/** Result of verifying a single attestation. */
export interface VerificationResult {
  /** Whether the attestation is valid. */
  valid: boolean
  /** Error message if verification failed, or `null`. */
  error?: string | null
  /** Machine-readable error code, or `null`. */
  errorCode?: string | null
}

/** Status summary of a chain verification. */
export interface VerificationStatus {
  /** Status type: `'Valid'`, `'Invalid'`, `'Expired'`, etc. */
  statusType: string
  /** Timestamp context for the status, or `null`. */
  at?: string | null
  /** Chain step where verification failed, or `null`. */
  step?: number | null
  /** DID of the missing link in the chain, or `null`. */
  missingLink?: string | null
  /** Number of required witnesses, or `null`. */
  required?: number | null
  /** Number of verified witnesses, or `null`. */
  verified?: number | null
}

/** A single link in a verified attestation chain. */
export interface ChainLink {
  /** DID of the issuer at this link. */
  issuer: string
  /** DID of the subject at this link. */
  subject: string
  /** Whether this link verified successfully. */
  valid: boolean
  /** Error message if this link failed, or `null`. */
  error?: string | null
}

/** Full report from a chain verification. */
export interface VerificationReport {
  /** Overall verification status. */
  status: VerificationStatus
  /** Individual chain link results. */
  chain: ChainLink[]
  /** Non-fatal warnings encountered during verification. */
  warnings: string[]
}

/** Public key of a witness node. */
export interface WitnessKey {
  /** DID of the witness. */
  did: string
  /** Hex-encoded Ed25519 public key of the witness. */
  publicKeyHex: string
}

/** Configuration for witness-backed chain verification. */
export interface WitnessConfig {
  /** JSON-serialized witness receipts. */
  receipts: string[]
  /** Witness public keys. */
  keys: WitnessKey[]
  /** Minimum number of witness receipts required. */
  threshold: number
}

/**
 * Verifies a single attestation against an issuer's public key.
 *
 * @param attestationJson - JSON-serialized attestation.
 * @param issuerPkHex - Hex-encoded Ed25519 public key of the issuer.
 * @returns The verification result.
 * @throws {@link VerificationError} if verification encounters an error.
 *
 * @example
 * ```typescript
 * import { verifyAttestation } from '@auths-dev/sdk'
 *
 * const result = await verifyAttestation(attestationJson, publicKeyHex)
 * console.log(result.valid) // true
 * ```
 */
export async function verifyAttestation(attestationJson: string, issuerPkHex: string): Promise<VerificationResult> {
  try {
    return await native.verifyAttestation(attestationJson, issuerPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies a single attestation with a required capability check.
 *
 * @param attestationJson - JSON-serialized attestation.
 * @param issuerPkHex - Hex-encoded Ed25519 public key of the issuer.
 * @param requiredCapability - Capability the attestation must grant.
 * @returns The verification result.
 * @throws {@link VerificationError} if verification fails.
 */
export async function verifyAttestationWithCapability(attestationJson: string, issuerPkHex: string, requiredCapability: string): Promise<VerificationResult> {
  try {
    return await native.verifyAttestationWithCapability(attestationJson, issuerPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies an attestation chain from leaf to root.
 *
 * @param attestationsJson - Array of JSON-serialized attestations (leaf to root).
 * @param rootPkHex - Hex-encoded Ed25519 public key of the root identity.
 * @returns The verification report with chain link details.
 * @throws {@link VerificationError} if verification encounters an error.
 *
 * @example
 * ```typescript
 * import { verifyChain } from '@auths-dev/sdk'
 *
 * const report = await verifyChain(attestationChain, rootPublicKeyHex)
 * console.log(report.status.statusType) // 'Valid'
 * ```
 */
export async function verifyChain(attestationsJson: string[], rootPkHex: string): Promise<VerificationReport> {
  try {
    return await native.verifyChain(attestationsJson, rootPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies an attestation chain with a required capability at the leaf.
 *
 * @param attestationsJson - Array of JSON-serialized attestations (leaf to root).
 * @param rootPkHex - Hex-encoded Ed25519 public key of the root identity.
 * @param requiredCapability - Capability the leaf attestation must grant.
 * @returns The verification report.
 * @throws {@link VerificationError} if verification fails.
 */
export async function verifyChainWithCapability(attestationsJson: string[], rootPkHex: string, requiredCapability: string): Promise<VerificationReport> {
  try {
    return await native.verifyChainWithCapability(attestationsJson, rootPkHex, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies that a device is authorized by an identity through an attestation chain.
 *
 * @param identityDid - DID of the authorizing identity.
 * @param deviceDid - DID of the device to verify.
 * @param attestationsJson - Array of JSON-serialized attestations.
 * @param identityPkHex - Hex-encoded Ed25519 public key of the identity.
 * @returns The verification report.
 * @throws {@link VerificationError} if verification fails.
 */
export async function verifyDeviceAuthorization(identityDid: string, deviceDid: string, attestationsJson: string[], identityPkHex: string): Promise<VerificationReport> {
  try {
    return await native.verifyDeviceAuthorization(identityDid, deviceDid, attestationsJson, identityPkHex)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies a single attestation at a specific point in time.
 *
 * @param attestationJson - JSON-serialized attestation.
 * @param issuerPkHex - Hex-encoded Ed25519 public key of the issuer.
 * @param atRfc3339 - RFC 3339 timestamp to verify at.
 * @returns The verification result.
 * @throws {@link VerificationError} if verification fails.
 */
export async function verifyAtTime(attestationJson: string, issuerPkHex: string, atRfc3339: string): Promise<VerificationResult> {
  try {
    return await native.verifyAtTime(attestationJson, issuerPkHex, atRfc3339)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies an attestation at a specific time with a required capability.
 *
 * @param attestationJson - JSON-serialized attestation.
 * @param issuerPkHex - Hex-encoded Ed25519 public key of the issuer.
 * @param atRfc3339 - RFC 3339 timestamp to verify at.
 * @param requiredCapability - Capability the attestation must grant.
 * @returns The verification result.
 * @throws {@link VerificationError} if verification fails.
 */
export async function verifyAtTimeWithCapability(attestationJson: string, issuerPkHex: string, atRfc3339: string, requiredCapability: string): Promise<VerificationResult> {
  try {
    return await native.verifyAtTimeWithCapability(attestationJson, issuerPkHex, atRfc3339, requiredCapability)
  } catch (err) {
    throw mapNativeError(err, VerificationError)
  }
}

/**
 * Verifies an attestation chain with witness receipt validation.
 *
 * @param attestationsJson - Array of JSON-serialized attestations (leaf to root).
 * @param rootPkHex - Hex-encoded Ed25519 public key of the root identity.
 * @param witnesses - Witness configuration with receipts, keys, and threshold.
 * @returns The verification report.
 * @throws {@link VerificationError} if verification fails.
 *
 * @example
 * ```typescript
 * import { verifyChainWithWitnesses } from '@auths-dev/sdk'
 *
 * const report = await verifyChainWithWitnesses(chain, rootKey, {
 *   receipts: witnessReceipts,
 *   keys: [{ did: witnessDid, publicKeyHex: witnessKey }],
 *   threshold: 1,
 * })
 * ```
 */
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
