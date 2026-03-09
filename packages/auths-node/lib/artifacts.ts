import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

export interface ArtifactResult {
  attestationJson: string
  rid: string
  digest: string
  fileSize: number
}

export class ArtifactService {
  constructor(private client: Auths) {}

  sign(opts: {
    filePath: string
    identityDid: string
    expiresInDays?: number
    note?: string
    passphrase?: string
  }): ArtifactResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signArtifact(
        opts.filePath,
        opts.identityDid,
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
        opts.note ?? null,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

  signBytes(opts: {
    data: Buffer
    identityDid: string
    expiresInDays?: number
    note?: string
    passphrase?: string
  }): ArtifactResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signArtifactBytes(
        opts.data,
        opts.identityDid,
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
        opts.note ?? null,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
