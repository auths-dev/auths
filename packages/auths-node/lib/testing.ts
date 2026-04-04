/**
 * Testing helpers — lightweight, no filesystem/keychain/Git required.
 */
import native from './native'
import type { NapiInMemoryKeypair, NapiVerificationResult } from './native'

/**
 * In-memory identity for tests, demos, and CI.
 *
 * Generates a fresh Ed25519 keypair on construction. The resulting DID is
 * `did:key:z...` (not `did:keri:`), which is valid for `signActionRaw`
 * and `verifyActionEnvelope` but cannot be used with KERI operations.
 *
 * @example
 * ```ts
 * import { EphemeralIdentity } from '@auths/node/testing'
 *
 * const alice = new EphemeralIdentity()
 * const sig = alice.sign(Buffer.from('hello'))
 * const envelope = alice.signAction('tool_call', '{"tool": "web_search"}')
 * const result = alice.verifyAction(envelope)
 * console.log(result.valid) // true
 * ```
 */
export class EphemeralIdentity {
  private readonly _keypair: NapiInMemoryKeypair

  constructor() {
    this._keypair = native.generateInmemoryKeypair()
  }

  /** The `did:key:z...` identifier for this ephemeral identity. */
  get did(): string {
    return this._keypair.did
  }

  /** Hex-encoded 32-byte Ed25519 public key. */
  get publicKeyHex(): string {
    return this._keypair.publicKeyHex
  }

  /** Hex-encoded 32-byte Ed25519 seed (private key). */
  get privateKeyHex(): string {
    return this._keypair.privateKeyHex
  }

  /** Sign arbitrary bytes. Returns hex-encoded signature. */
  sign(message: Buffer): string {
    return native.signBytesRaw(this._keypair.privateKeyHex, message)
  }

  /** Sign an action envelope. Returns JSON envelope string. */
  signAction(actionType: string, payloadJson: string): string {
    return native.signActionRaw(
      this._keypair.privateKeyHex,
      actionType,
      payloadJson,
      this._keypair.did,
    )
  }

  /** Verify an action envelope against this identity's public key. */
  verifyAction(envelopeJson: string): NapiVerificationResult {
    return native.verifyActionEnvelope(envelopeJson, this._keypair.publicKeyHex)
  }
}
