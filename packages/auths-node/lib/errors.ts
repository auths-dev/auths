export class AuthsError extends Error {
  code: string
  constructor(message: string, code: string) {
    super(message)
    this.name = 'AuthsError'
    this.code = code
  }
}

export class VerificationError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'VerificationError'
  }
}

export class CryptoError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'CryptoError'
  }
}

export class KeychainError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'KeychainError'
  }
}

export class StorageError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'StorageError'
  }
}

export class NetworkError extends AuthsError {
  shouldRetry: boolean
  constructor(message: string, code: string, shouldRetry = true) {
    super(message, code)
    this.name = 'NetworkError'
    this.shouldRetry = shouldRetry
  }
}

export class IdentityError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'IdentityError'
  }
}

export class OrgError extends AuthsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'OrgError'
  }
}

export class PairingError extends AuthsError {
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
