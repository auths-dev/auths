import { IdentityService, type GetPublicKeyOptions } from './identity'
import { DeviceService } from './devices'
import {
  SigningService,
  type SignResult,
  type ActionEnvelope,
  type SignAsIdentityOptions,
  type SignActionAsIdentityOptions,
  type SignAsAgentOptions,
  type SignActionAsAgentOptions,
} from './signing'
import { OrgService } from './org'
import { TrustService } from './trust'
import { WitnessService } from './witness'
import { AttestationService } from './attestations'
import { ArtifactService } from './artifacts'
import { CommitService } from './commits'
import { AuditService } from './audit'
import { PairingService } from './pairing'
import { mapNativeError, CryptoError, VerificationError } from './errors'
import {
  verifyAttestation,
  verifyAttestationWithCapability,
  verifyAtTime,
  verifyAtTimeWithCapability,
  verifyChain as verifyChainFn,
  verifyChainWithCapability,
  verifyChainWithWitnesses,
  type VerificationResult,
  type VerificationReport,
  type WitnessConfig,
} from './verify'
import native from './native'

/** Configuration for the {@link Auths} client. */
export interface ClientConfig {
  /** Path to the Auths Git registry. Defaults to `'~/.auths'`. */
  repoPath?: string
  /** Passphrase for key encryption. Can also be set via `AUTHS_PASSPHRASE` env var. */
  passphrase?: string
}

/** Options for {@link Auths.verify}. */
export interface VerifyOptions {
  /** JSON-serialized attestation to verify. */
  attestationJson: string
  /** Hex-encoded Ed25519 public key of the issuer. */
  issuerKey: string
  /** Optional capability the attestation must grant. */
  requiredCapability?: string
  /** Optional RFC 3339 timestamp to verify at. */
  at?: string
}

/** Options for {@link Auths.verifyChain}. */
export interface VerifyChainOptions {
  /** Array of JSON-serialized attestations (leaf to root). */
  attestations: string[]
  /** Hex-encoded Ed25519 public key of the root identity. */
  rootKey: string
  /** Optional capability the leaf attestation must grant. */
  requiredCapability?: string
  /** Optional witness configuration for receipt-based verification. */
  witnesses?: WitnessConfig
}

/**
 * Primary entry point for all Auths SDK operations.
 *
 * Provides access to identity management, device authorization, signing,
 * verification, policy evaluation, organizations, and more through
 * service properties.
 *
 * @example
 * ```typescript
 * import { Auths } from '@auths-dev/sdk'
 *
 * const auths = new Auths()
 *
 * // Create an identity
 * const identity = auths.identities.create({ label: 'laptop' })
 *
 * // Sign a message
 * const sig = auths.signAs({
 *   message: Buffer.from('hello world'),
 *   identityDid: identity.did,
 * })
 * console.log(sig.signature) // hex-encoded Ed25519 signature
 * ```
 */
export class Auths {
  /** Path to the Auths Git registry. */
  readonly repoPath: string
  /** Passphrase for key operations, if set. */
  readonly passphrase: string | undefined

  /** Identity management (create, rotate, delegate agents). */
  readonly identities: IdentityService
  /** Device authorization (link, revoke, extend). */
  readonly devices: DeviceService
  /** Message and action signing. */
  readonly signing: SigningService
  /** Organization management. */
  readonly orgs: OrgService
  /** Trust store for pinned identities. */
  readonly trust: TrustService
  /** Witness node management. */
  readonly witnesses: WitnessService
  /** Attestation queries. */
  readonly attestations: AttestationService
  /** Artifact signing. */
  readonly artifacts: ArtifactService
  /** Git commit signing. */
  readonly commits: CommitService
  /** Repository audit reports. */
  readonly audit: AuditService
  /** Cross-device pairing. */
  readonly pairing: PairingService

  /**
   * Creates a new Auths client.
   *
   * @param config - Client configuration.
   *
   * @example
   * ```typescript
   * // Auto-discover (~/.auths)
   * const auths = new Auths()
   *
   * // Explicit configuration
   * const auths = new Auths({
   *   repoPath: '/path/to/identity-repo',
   *   passphrase: 'my-secret',
   * })
   * ```
   */
  constructor(config: ClientConfig = {}) {
    this.repoPath = config.repoPath ?? '~/.auths'
    this.passphrase = config.passphrase

    this.identities = new IdentityService(this)
    this.devices = new DeviceService(this)
    this.signing = new SigningService(this)
    this.orgs = new OrgService(this)
    this.trust = new TrustService(this)
    this.witnesses = new WitnessService(this)
    this.attestations = new AttestationService(this)
    this.artifacts = new ArtifactService(this)
    this.commits = new CommitService(this)
    this.audit = new AuditService(this)
    this.pairing = new PairingService(this)
  }

  /**
   * Verifies a single attestation with optional capability and time constraints.
   *
   * @param opts - Verification options.
   * @returns The verification result.
   * @throws {@link VerificationError} if verification encounters an error.
   *
   * @example
   * ```typescript
   * const result = await auths.verify({
   *   attestationJson: json,
   *   issuerKey: publicKeyHex,
   * })
   * console.log(result.valid)
   * ```
   */
  async verify(opts: VerifyOptions): Promise<VerificationResult> {
    if (opts.at && opts.requiredCapability) {
      return verifyAtTimeWithCapability(opts.attestationJson, opts.issuerKey, opts.at, opts.requiredCapability)
    }
    if (opts.at) {
      return verifyAtTime(opts.attestationJson, opts.issuerKey, opts.at)
    }
    if (opts.requiredCapability) {
      return verifyAttestationWithCapability(opts.attestationJson, opts.issuerKey, opts.requiredCapability)
    }
    return verifyAttestation(opts.attestationJson, opts.issuerKey)
  }

  /**
   * Verifies an attestation chain with optional capability and witness constraints.
   *
   * @param opts - Chain verification options.
   * @returns The verification report.
   * @throws {@link VerificationError} if verification encounters an error.
   */
  async verifyChain(opts: VerifyChainOptions): Promise<VerificationReport> {
    if (opts.witnesses) {
      return verifyChainWithWitnesses(opts.attestations, opts.rootKey, opts.witnesses)
    }
    if (opts.requiredCapability) {
      return verifyChainWithCapability(opts.attestations, opts.rootKey, opts.requiredCapability)
    }
    return verifyChainFn(opts.attestations, opts.rootKey)
  }

  /**
   * Convenience method to sign a message as an identity.
   *
   * @param opts - Signing options.
   * @returns The signature and signer DID.
   * @throws {@link CryptoError} if signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.signAs({
   *   message: Buffer.from('hello world'),
   *   identityDid: identity.did,
   * })
   * ```
   */
  signAs(opts: SignAsIdentityOptions): SignResult {
    return this.signing.signAsIdentity({
      message: opts.message,
      identityDid: opts.identityDid,
      passphrase: opts.passphrase,
    })
  }

  /**
   * Convenience method to sign an action as an identity.
   *
   * @param opts - Action signing options.
   * @returns The signed action envelope.
   * @throws {@link CryptoError} if signing fails.
   */
  signActionAs(opts: SignActionAsIdentityOptions): ActionEnvelope {
    return this.signing.signActionAsIdentity({
      actionType: opts.actionType,
      payloadJson: opts.payloadJson,
      identityDid: opts.identityDid,
      passphrase: opts.passphrase,
    })
  }

  /**
   * Convenience method to sign a message as an agent.
   *
   * @param opts - Agent signing options.
   * @returns The signature and signer DID.
   * @throws {@link CryptoError} if signing fails.
   */
  signAsAgent(opts: SignAsAgentOptions): SignResult {
    return this.signing.signAsAgent({
      message: opts.message,
      keyAlias: opts.keyAlias,
      passphrase: opts.passphrase,
    })
  }

  /**
   * Convenience method to sign an action as an agent.
   *
   * @param opts - Agent action signing options.
   * @returns The signed action envelope.
   * @throws {@link CryptoError} if signing fails.
   */
  signActionAsAgent(opts: SignActionAsAgentOptions): ActionEnvelope {
    return this.signing.signActionAsAgent(opts)
  }

  /**
   * Convenience method to get an identity's public key.
   *
   * @param opts - Lookup options.
   * @returns Hex-encoded Ed25519 public key.
   * @throws {@link CryptoError} if the key cannot be found.
   */
  getPublicKey(opts: GetPublicKeyOptions): string {
    return this.identities.getPublicKey(opts)
  }

  /**
   * Runs diagnostics on the Auths installation and returns a report.
   *
   * @returns A human-readable diagnostics string.
   */
  doctor(): string {
    return native.runDiagnostics(this.repoPath, this.passphrase)
  }

  /**
   * Returns the list of known diagnostic check names.
   *
   * @returns Array of check name strings.
   */
  static availableChecks(): string[] {
    return ['git_version', 'ssh_keygen', 'git_signing_config']
  }
}
