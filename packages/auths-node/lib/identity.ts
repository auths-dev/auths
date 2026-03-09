import native from './native'
import { mapNativeError, CryptoError, IdentityError } from './errors'
import type { Auths } from './client'

export interface Identity {
  did: string
  keyAlias: string
  label: string
  repoPath: string
  publicKey: string
}

export interface AgentIdentity {
  did: string
  keyAlias: string
  attestation: string
  publicKey: string
}

export interface DelegatedAgent {
  did: string
  keyAlias: string
  attestation: string
  publicKey: string
}

export interface RotationResult {
  controllerDid: string
  newKeyFingerprint: string
  previousKeyFingerprint: string
  sequence: number
}

export class IdentityService {
  constructor(private client: Auths) {}

  create(opts: {
    label?: string
    repoPath?: string
    passphrase?: string
  } = {}): Identity {
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

  createAgent(opts: {
    name: string
    capabilities: string[]
    passphrase?: string
  }): AgentIdentity {
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

  delegateAgent(opts: {
    identityDid: string
    name: string
    capabilities: string[]
    expiresInDays?: number
    passphrase?: string
  }): DelegatedAgent {
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

  rotate(opts: {
    identityDid?: string
    passphrase?: string
  } = {}): RotationResult {
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

  getPublicKey(opts: {
    identityDid: string
    passphrase?: string
  }): string {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.getIdentityPublicKey(opts.identityDid, this.client.repoPath, pp)
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
