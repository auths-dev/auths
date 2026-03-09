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

export interface ClientConfig {
  repoPath?: string
  passphrase?: string
}

export interface VerifyOptions {
  attestationJson: string
  issuerKey: string
  requiredCapability?: string
  at?: string
}

export interface VerifyChainOptions {
  attestations: string[]
  rootKey: string
  requiredCapability?: string
  witnesses?: WitnessConfig
}

export class Auths {
  readonly repoPath: string
  readonly passphrase: string | undefined

  readonly identities: IdentityService
  readonly devices: DeviceService
  readonly signing: SigningService
  readonly orgs: OrgService
  readonly trust: TrustService
  readonly witnesses: WitnessService
  readonly attestations: AttestationService
  readonly artifacts: ArtifactService
  readonly commits: CommitService
  readonly audit: AuditService
  readonly pairing: PairingService

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

  async verifyChain(opts: VerifyChainOptions): Promise<VerificationReport> {
    if (opts.witnesses) {
      return verifyChainWithWitnesses(opts.attestations, opts.rootKey, opts.witnesses)
    }
    if (opts.requiredCapability) {
      return verifyChainWithCapability(opts.attestations, opts.rootKey, opts.requiredCapability)
    }
    return verifyChainFn(opts.attestations, opts.rootKey)
  }

  signAs(opts: SignAsIdentityOptions): SignResult {
    return this.signing.signAsIdentity({
      message: opts.message,
      identityDid: opts.identityDid,
      passphrase: opts.passphrase,
    })
  }

  signActionAs(opts: SignActionAsIdentityOptions): ActionEnvelope {
    return this.signing.signActionAsIdentity({
      actionType: opts.actionType,
      payloadJson: opts.payloadJson,
      identityDid: opts.identityDid,
      passphrase: opts.passphrase,
    })
  }

  signAsAgent(opts: SignAsAgentOptions): SignResult {
    return this.signing.signAsAgent({
      message: opts.message,
      keyAlias: opts.keyAlias,
      passphrase: opts.passphrase,
    })
  }

  signActionAsAgent(opts: SignActionAsAgentOptions): ActionEnvelope {
    return this.signing.signActionAsAgent(opts)
  }

  getPublicKey(opts: GetPublicKeyOptions): string {
    return this.identities.getPublicKey(opts)
  }

  doctor(): string {
    return native.runDiagnostics(this.repoPath, this.passphrase)
  }
}
