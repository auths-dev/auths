import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

/** Result of a signing operation. */
export interface SignResult {
  /** Hex-encoded Ed25519 signature. */
  signature: string
  /** DID of the signer. */
  signerDid: string
}

/** A signed action envelope containing the payload and its signature. */
export interface ActionEnvelope {
  /** JSON-serialized envelope with action metadata. */
  envelopeJson: string
  /** Hex-encoded signature over the envelope. */
  signatureHex: string
  /** DID of the signer. */
  signerDid: string
}

/** Options for {@link SigningService.signAsIdentity}. */
export interface SignAsIdentityOptions {
  /** The message bytes to sign. */
  message: Buffer
  /** DID of the identity to sign with. */
  identityDid: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link SigningService.signActionAsIdentity}. */
export interface SignActionAsIdentityOptions {
  /** Action type label (e.g. `'tool_call'`). */
  actionType: string
  /** JSON-serialized action payload. */
  payloadJson: string
  /** DID of the identity to sign with. */
  identityDid: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link SigningService.signAsAgent}. */
export interface SignAsAgentOptions {
  /** The message bytes to sign. */
  message: Buffer
  /** Keychain alias of the agent key. */
  keyAlias: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link SigningService.signActionAsAgent}. */
export interface SignActionAsAgentOptions {
  /** Action type label (e.g. `'tool_call'`). */
  actionType: string
  /** JSON-serialized action payload. */
  payloadJson: string
  /** Keychain alias of the agent key. */
  keyAlias: string
  /** DID of the agent identity. */
  agentDid: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/**
 * Signs messages and actions using identity or agent keys.
 *
 * Access via {@link Auths.signing}.
 *
 * @example
 * ```typescript
 * const result = auths.signing.signAsIdentity({
 *   message: Buffer.from('hello world'),
 *   identityDid: identity.did,
 * })
 * console.log(result.signature) // hex-encoded Ed25519 signature
 * ```
 */
export class SigningService {
  constructor(private client: Auths) {}

  /**
   * Signs a message as an identity.
   *
   * @param opts - Signing options.
   * @returns The signature and signer DID.
   * @throws {@link CryptoError} if the key is missing or signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.signing.signAsIdentity({
   *   message: Buffer.from('hello'),
   *   identityDid: identity.did,
   * })
   * ```
   */
  signAsIdentity(opts: SignAsIdentityOptions): SignResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.signAsIdentity(
        opts.message,
        opts.identityDid,
        this.client.repoPath,
        pp,
      )
      return { signature: result.signature, signerDid: result.signerDid }
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

  /**
   * Signs a structured action as an identity, producing a verifiable envelope.
   *
   * @param opts - Action signing options.
   * @returns The signed action envelope.
   * @throws {@link CryptoError} if signing fails.
   *
   * @example
   * ```typescript
   * const envelope = auths.signing.signActionAsIdentity({
   *   actionType: 'tool_call',
   *   payloadJson: '{"tool":"read_file"}',
   *   identityDid: identity.did,
   * })
   * ```
   */
  signActionAsIdentity(opts: SignActionAsIdentityOptions): ActionEnvelope {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signActionAsIdentity(
        opts.actionType,
        opts.payloadJson,
        opts.identityDid,
        this.client.repoPath,
        pp,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

  /**
   * Signs a message as an agent using its keychain alias.
   *
   * @param opts - Agent signing options.
   * @returns The signature and signer DID.
   * @throws {@link CryptoError} if the key is missing or signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.signing.signAsAgent({
   *   message: Buffer.from('payload'),
   *   keyAlias: agent.keyAlias,
   * })
   * ```
   */
  signAsAgent(opts: SignAsAgentOptions): SignResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.signAsAgent(opts.message, opts.keyAlias, this.client.repoPath, pp)
      return { signature: result.signature, signerDid: result.signerDid }
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

  /**
   * Signs a structured action as an agent.
   *
   * @param opts - Agent action signing options.
   * @returns The signed action envelope.
   * @throws {@link CryptoError} if signing fails.
   *
   * @example
   * ```typescript
   * const envelope = auths.signing.signActionAsAgent({
   *   actionType: 'tool_call',
   *   payloadJson: '{"tool":"execute"}',
   *   keyAlias: agent.keyAlias,
   *   agentDid: agent.did,
   * })
   * ```
   */
  signActionAsAgent(opts: SignActionAsAgentOptions): ActionEnvelope {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signActionAsAgent(
        opts.actionType,
        opts.payloadJson,
        opts.keyAlias,
        opts.agentDid,
        this.client.repoPath,
        pp,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
