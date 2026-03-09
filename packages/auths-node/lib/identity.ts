import native from './native'
import { mapNativeError, CryptoError, IdentityError } from './errors'
import type { Auths } from './client'

/** A cryptographic identity anchored in a KERI key event log. */
export interface Identity {
  /** The KERI decentralized identifier (e.g. `did:keri:EBfd...`). */
  did: string
  /** Keychain alias used to retrieve the signing key. */
  keyAlias: string
  /** Human-readable label for this identity. */
  label: string
  /** Path to the Git registry that stores this identity. */
  repoPath: string
  /** Hex-encoded Ed25519 public key. */
  publicKey: string
}

/** A standalone agent identity with its self-signed attestation. */
export interface AgentIdentity {
  /** The agent's KERI decentralized identifier. */
  did: string
  /** Keychain alias for the agent's signing key. */
  keyAlias: string
  /** JSON-serialized self-signed attestation. */
  attestation: string
  /** Hex-encoded Ed25519 public key. */
  publicKey: string
}

/** An agent delegated under an existing identity. */
export interface DelegatedAgent {
  /** The delegated agent's DID (typically `did:key:z...`). */
  did: string
  /** Keychain alias for the agent's signing key. */
  keyAlias: string
  /** JSON-serialized delegation attestation signed by the parent identity. */
  attestation: string
  /** Hex-encoded Ed25519 public key. */
  publicKey: string
}

/** Result of a key rotation operation. */
export interface RotationResult {
  /** The controller DID whose keys were rotated. */
  controllerDid: string
  /** Fingerprint of the new signing key. */
  newKeyFingerprint: string
  /** Fingerprint of the previous signing key. */
  previousKeyFingerprint: string
  /** New KERI event sequence number after rotation. */
  sequence: number
}

/** Options for {@link IdentityService.create}. */
export interface CreateIdentityOptions {
  /** Human-readable label. Defaults to `'main'`. */
  label?: string
  /** Override the client's repo path. */
  repoPath?: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link IdentityService.createAgent}. */
export interface CreateAgentOptions {
  /** Name for the agent identity. */
  name: string
  /** Capabilities to grant (e.g. `['sign']`). */
  capabilities: string[]
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link IdentityService.delegateAgent}. */
export interface DelegateAgentOptions {
  /** DID of the parent identity that delegates authority. */
  identityDid: string
  /** Name for the delegated agent. */
  name: string
  /** Capabilities to grant (e.g. `['sign']`). */
  capabilities: string[]
  /** Optional expiration in days. */
  expiresInDays?: number
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link IdentityService.rotate}. */
export interface RotateKeysOptions {
  /** DID of the identity to rotate. Defaults to the primary identity. */
  identityDid?: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link IdentityService.getPublicKey}. */
export interface GetPublicKeyOptions {
  /** DID of the identity whose public key to retrieve. */
  identityDid: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/**
 * Manages cryptographic identities, agents, and key rotation.
 *
 * Access via {@link Auths.identities}.
 *
 * @example
 * ```typescript
 * const auths = new Auths()
 * const identity = auths.identities.create({ label: 'laptop' })
 * console.log(identity.did) // did:keri:EBfd...
 * ```
 */
export class IdentityService {
  constructor(private client: Auths) {}

  /**
   * Creates a new cryptographic identity backed by an Ed25519 keypair.
   *
   * @param opts - Creation options.
   * @returns The newly created identity.
   * @throws {@link IdentityError} if the identity cannot be created.
   *
   * @example
   * ```typescript
   * const identity = auths.identities.create({ label: 'laptop' })
   * console.log(identity.did)       // did:keri:EBfd...
   * console.log(identity.publicKey) // hex-encoded Ed25519 key
   * ```
   */
  create(opts: CreateIdentityOptions = {}): Identity {
    const rp = opts.repoPath ?? this.client.repoPath
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.createIdentity(opts.label ?? 'main', rp, pp)
      return {
        did: result.did,
        keyAlias: result.keyAlias,
        label: opts.label ?? 'main',
        repoPath: rp,
        publicKey: result.publicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  /**
   * Creates a standalone agent identity with a self-signed attestation.
   *
   * @param opts - Agent creation options.
   * @returns The agent identity with its attestation.
   * @throws {@link IdentityError} if the agent cannot be created.
   *
   * @example
   * ```typescript
   * const agent = auths.identities.createAgent({
   *   name: 'ci-bot',
   *   capabilities: ['sign'],
   * })
   * console.log(agent.did) // did:keri:...
   * ```
   */
  createAgent(opts: CreateAgentOptions): AgentIdentity {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const bundle = native.createAgentIdentity(
        opts.name,
        opts.capabilities,
        this.client.repoPath,
        pp,
      )
      return {
        did: bundle.agentDid,
        keyAlias: bundle.keyAlias,
        attestation: bundle.attestationJson,
        publicKey: bundle.publicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  /**
   * Delegates an agent under an existing identity with scoped capabilities.
   *
   * @param opts - Delegation options.
   * @returns The delegated agent with its signed attestation.
   * @throws {@link IdentityError} if delegation fails.
   *
   * @example
   * ```typescript
   * const agent = auths.identities.delegateAgent({
   *   identityDid: identity.did,
   *   name: 'deploy-bot',
   *   capabilities: ['sign'],
   *   expiresInDays: 90,
   * })
   * ```
   */
  delegateAgent(opts: DelegateAgentOptions): DelegatedAgent {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const bundle = native.delegateAgent(
        opts.name,
        opts.capabilities,
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
        opts.identityDid,
      )
      return {
        did: bundle.agentDid,
        keyAlias: bundle.keyAlias,
        attestation: bundle.attestationJson,
        publicKey: bundle.publicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  /**
   * Rotates the signing keys for an identity, advancing the KERI event log.
   *
   * @param opts - Rotation options.
   * @returns The rotation result with old and new key fingerprints.
   * @throws {@link IdentityError} if rotation fails.
   *
   * @example
   * ```typescript
   * const result = auths.identities.rotate({ identityDid: identity.did })
   * console.log(result.sequence) // incremented sequence number
   * ```
   */
  rotate(opts: RotateKeysOptions = {}): RotationResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.rotateIdentityKeys(
        this.client.repoPath,
        opts.identityDid ?? null,
        null,
        pp,
      )
      return {
        controllerDid: result.controllerDid,
        newKeyFingerprint: result.newKeyFingerprint,
        previousKeyFingerprint: result.previousKeyFingerprint,
        sequence: result.sequence,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  /**
   * Retrieves the hex-encoded Ed25519 public key for an identity.
   *
   * @param opts - Lookup options.
   * @returns Hex-encoded public key string (64 characters).
   * @throws {@link CryptoError} if the key cannot be found.
   *
   * @example
   * ```typescript
   * const pk = auths.identities.getPublicKey({ identityDid: identity.did })
   * console.log(pk.length) // 64
   * ```
   */
  getPublicKey(opts: GetPublicKeyOptions): string {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.getIdentityPublicKey(opts.identityDid, this.client.repoPath, pp)
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
