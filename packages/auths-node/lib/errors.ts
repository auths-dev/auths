/**
 * Base error for all Auths SDK operations.
 *
 * All errors thrown by the SDK inherit from this class, carrying a
 * machine-readable {@link AuthsError.code | code} and human-readable
 * {@link AuthsError.message | message}.
 *
 * @example
 * ```typescript
 * import { Auths, AuthsError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.signAs({ message: data, identityDid: did })
 * } catch (e) {
 *   if (e instanceof AuthsError) {
 *     console.log(e.code, e.message)
 *   }
 * }
 * ```
 */
export class AuthsError extends Error {
  /** Machine-readable error code (e.g. `'key_not_found'`, `'invalid_signature'`). */
  code: string
  constructor(message: string, code: string) {
    super(message)
    this.name = 'AuthsError'
    this.code = code
  }
}

/**
 * Raised when attestation or chain verification fails.
 *
 * Common codes: `'invalid_signature'`, `'expired_attestation'`,
 * `'revoked_device'`, `'missing_capability'`.
 *
 * @example
 * ```typescript
 * import { verifyAttestation, VerificationError } from '@auths-dev/sdk'
 *
 * try {
 *   await verifyAttestation(json, publicKey)
 * } catch (e) {
 *   if (e instanceof VerificationError) {
 *     console.log('Verification failed:', e.code)
 *   }
 * }
 * ```
 */
export class VerificationError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'VerificationError'
  }
}

/**
 * Raised when a cryptographic operation fails.
 *
 * Common codes: `'invalid_key'`, `'key_not_found'`, `'signing_failed'`.
 *
 * @example
 * ```typescript
 * import { Auths, CryptoError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.signAs({ message: data, identityDid: did })
 * } catch (e) {
 *   if (e instanceof CryptoError && e.code === 'key_not_found') {
 *     console.log('Identity key not in keychain')
 *   }
 * }
 * ```
 */
export class CryptoError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'CryptoError'
  }
}

/**
 * Raised when the platform keychain is inaccessible or locked.
 *
 * Common codes: `'keychain_locked'`.
 *
 * @example
 * ```typescript
 * import { Auths, KeychainError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.identities.create({ label: 'main' })
 * } catch (e) {
 *   if (e instanceof KeychainError) {
 *     console.log('Unlock your keychain or set AUTHS_KEYCHAIN_BACKEND=file')
 *   }
 * }
 * ```
 */
export class KeychainError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'KeychainError'
  }
}

/**
 * Raised when a storage or registry operation fails.
 *
 * Common codes: `'repo_not_found'`, `'trust_error'`, `'witness_error'`.
 *
 * @example
 * ```typescript
 * import { Auths, StorageError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.trust.pin({ did: 'did:keri:ENOTREAL' })
 * } catch (e) {
 *   if (e instanceof StorageError) {
 *     console.log('Storage error:', e.message)
 *   }
 * }
 * ```
 */
export class StorageError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'StorageError'
  }
}

/**
 * Raised when a network operation fails (e.g. witness communication).
 *
 * Common codes: `'server_error'`.
 *
 * @example
 * ```typescript
 * import { NetworkError } from '@auths-dev/sdk'
 *
 * try {
 *   // network operation
 * } catch (e) {
 *   if (e instanceof NetworkError && e.shouldRetry) {
 *     // safe to retry
 *   }
 * }
 * ```
 */
export class NetworkError extends AuthsError {
  /** Whether the operation is safe to retry. Defaults to `true`. */
  shouldRetry: boolean
  constructor(message: string, code: string, shouldRetry = true) {
    super(message, code)
    this.name = 'NetworkError'
    this.shouldRetry = shouldRetry
  }
}

/**
 * Raised when an identity or device operation fails.
 *
 * Common codes: `'identity_not_found'`, `'unknown'`.
 *
 * @example
 * ```typescript
 * import { Auths, IdentityError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.devices.link({ identityDid: did, capabilities: ['sign'] })
 * } catch (e) {
 *   if (e instanceof IdentityError) {
 *     console.log('Identity error:', e.code)
 *   }
 * }
 * ```
 */
export class IdentityError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'IdentityError'
  }
}

/**
 * Raised when an organization operation fails.
 *
 * Common codes: `'org_error'`.
 *
 * @example
 * ```typescript
 * import { Auths, OrgError } from '@auths-dev/sdk'
 *
 * try {
 *   auths.orgs.addMember({ orgDid, memberDid, role: 'member' })
 * } catch (e) {
 *   if (e instanceof OrgError) {
 *     console.log('Org error:', e.message)
 *   }
 * }
 * ```
 */
export class OrgError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'OrgError'
  }
}

/**
 * Raised when a device pairing operation fails or times out.
 *
 * Common codes: `'pairing_error'`, `'timeout'`.
 *
 * @example
 * ```typescript
 * import { PairingError } from '@auths-dev/sdk'
 *
 * try {
 *   await auths.pairing.createSession({ bindAddress: '127.0.0.1' })
 * } catch (e) {
 *   if (e instanceof PairingError && e.shouldRetry) {
 *     // safe to retry
 *   }
 * }
 * ```
 */
export class PairingError extends AuthsError {
  /** Whether the operation is safe to retry. Defaults to `true`. */
  shouldRetry: boolean
  constructor(message: string, code: string, shouldRetry = true) {
    super(message, code)
    this.name = 'PairingError'
    this.shouldRetry = shouldRetry
  }
}

const ERROR_CODE_MAP: Record<string, [string, new (message: string, code: string) => AuthsError]> = {
  AUTHS_ISSUER_SIG_FAILED: ['invalid_signature', VerificationError],
  AUTHS_DEVICE_SIG_FAILED: ['invalid_signature', VerificationError],
  AUTHS_ATTESTATION_EXPIRED: ['expired_attestation', VerificationError],
  AUTHS_ATTESTATION_REVOKED: ['revoked_device', VerificationError],
  AUTHS_TIMESTAMP_IN_FUTURE: ['future_timestamp', VerificationError],
  AUTHS_MISSING_CAPABILITY: ['missing_capability', VerificationError],
  AUTHS_CRYPTO_ERROR: ['invalid_key', CryptoError],
  AUTHS_DID_RESOLUTION_ERROR: ['invalid_key', CryptoError],
  AUTHS_INVALID_INPUT: ['invalid_signature', VerificationError],
  AUTHS_SERIALIZATION_ERROR: ['invalid_signature', VerificationError],
  AUTHS_BUNDLE_EXPIRED: ['expired_attestation', VerificationError],
  AUTHS_KEY_NOT_FOUND: ['key_not_found', CryptoError],
  AUTHS_INCORRECT_PASSPHRASE: ['signing_failed', CryptoError],
  AUTHS_SIGNING_FAILED: ['signing_failed', CryptoError],
  AUTHS_SIGNING_ERROR: ['signing_failed', CryptoError],
  AUTHS_INPUT_TOO_LARGE: ['invalid_signature', VerificationError],
  AUTHS_INTERNAL_ERROR: ['unknown', VerificationError],
  AUTHS_ORG_VERIFICATION_FAILED: ['invalid_signature', VerificationError],
  AUTHS_ORG_ATTESTATION_EXPIRED: ['expired_attestation', VerificationError],
  AUTHS_ORG_DID_RESOLUTION_FAILED: ['invalid_key', CryptoError],
  AUTHS_REGISTRY_ERROR: ['repo_not_found', StorageError],
  AUTHS_KEYCHAIN_ERROR: ['keychain_locked', KeychainError],
  AUTHS_IDENTITY_ERROR: ['identity_not_found', IdentityError],
  AUTHS_DEVICE_ERROR: ['unknown', IdentityError],
  AUTHS_ROTATION_ERROR: ['unknown', IdentityError],
  AUTHS_NETWORK_ERROR: ['server_error', NetworkError],
  AUTHS_VERIFICATION_FAILED: ['invalid_signature', VerificationError],
  AUTHS_ORG_ERROR: ['org_error', OrgError],
  AUTHS_PAIRING_ERROR: ['pairing_error', PairingError],
  AUTHS_PAIRING_TIMEOUT: ['timeout', PairingError],
  AUTHS_TRUST_ERROR: ['trust_error', StorageError],
  AUTHS_WITNESS_ERROR: ['witness_error', StorageError],
  AUTHS_AUDIT_ERROR: ['audit_error', VerificationError],
  AUTHS_DIAGNOSTIC_ERROR: ['diagnostic_error', VerificationError],
}

/**
 * Maps a native napi-rs error into a typed {@link AuthsError} subclass.
 *
 * Parses the `[AUTHS_CODE] message` format emitted by the Rust layer
 * and instantiates the appropriate error class with a machine-readable code.
 *
 * @param err - The raw error from the native binding.
 * @param defaultCls - Fallback error class when the code is unrecognized.
 * @returns A typed {@link AuthsError} instance.
 */
export function mapNativeError(err: unknown, defaultCls: new (message: string, code: string) => AuthsError = VerificationError): AuthsError {
  const msg = err instanceof Error ? err.message : String(err)

  // Parse [AUTHS_CODE] prefix from native errors
  if (msg.startsWith('[AUTHS_') && msg.includes('] ')) {
    const code = msg.substring(1, msg.indexOf(']'))
    const message = msg.substring(msg.indexOf('] ') + 2)
    const mapping = ERROR_CODE_MAP[code]
    if (mapping) {
      const [pyCode, Cls] = mapping
      return new Cls(message, pyCode)
    }
  }

  // Fallback heuristics
  const low = msg.toLowerCase()
  if (low.includes('public key') || low.includes('private key') || low.includes('invalid key') || low.includes('hex')) {
    return new CryptoError(msg, 'invalid_key')
  }

  return new defaultCls(msg, 'unknown')
}
