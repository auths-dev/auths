import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

export interface CommitSignResult {
  signaturePem: string
  method: string
  namespace: string
}

export class CommitService {
  constructor(private client: Auths) {}

  sign(opts: {
    data: Buffer
    identityDid: string
    passphrase?: string
  }): CommitSignResult {
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
