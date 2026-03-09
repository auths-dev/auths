import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

export interface CommitSignResult {
  signaturePem: string
  method: string
  namespace: string
}

export interface SignCommitOptions {
  data: Buffer
  identityDid: string
  passphrase?: string
}

export class CommitService {
  constructor(private client: Auths) {}

  sign(opts: SignCommitOptions): CommitSignResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signCommit(
        opts.data,
        opts.identityDid,
        this.client.repoPath,
        pp,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
