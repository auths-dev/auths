import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

export interface SignResult {
  signature: string
  signerDid: string
}

export interface ActionEnvelope {
  envelopeJson: string
  signatureHex: string
  signerDid: string
}

export interface SignAsIdentityOptions {
  message: Buffer
  identityDid: string
  passphrase?: string
}

export interface SignActionAsIdentityOptions {
  actionType: string
  payloadJson: string
  identityDid: string
  passphrase?: string
}

export interface SignAsAgentOptions {
  message: Buffer
  keyAlias: string
  passphrase?: string
}

export interface SignActionAsAgentOptions {
  actionType: string
  payloadJson: string
  keyAlias: string
  agentDid: string
  passphrase?: string
}

export class SigningService {
  constructor(private client: Auths) {}

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

  signAsAgent(opts: SignAsAgentOptions): SignResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.signAsAgent(opts.message, opts.keyAlias, this.client.repoPath, pp)
      return { signature: result.signature, signerDid: result.signerDid }
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

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
