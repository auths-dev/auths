import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

/** Result of signing a Git commit. */
export interface CommitSignResult {
  /** PEM-encoded signature for the commit. */
  signaturePem: string
  /** Signing method identifier. */
  method: string
  /** Namespace for the signature (e.g. `'auths'`). */
  namespace: string
}

/** Options for {@link CommitService.sign}. */
export interface SignCommitOptions {
  /** Raw commit data to sign. */
  data: Buffer
  /** DID of the identity to sign with. */
  identityDid: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/**
 * Signs Git commits using Auths identities.
 *
 * Access via {@link Auths.commits}.
 *
 * @example
 * ```typescript
 * const result = auths.commits.sign({
 *   data: commitBuffer,
 *   identityDid: identity.did,
 * })
 * console.log(result.signaturePem) // PEM-encoded signature
 * ```
 */
export class CommitService {
  constructor(private client: Auths) {}

  /**
   * Signs raw Git commit data, producing a PEM-encoded signature.
   *
   * @param opts - Signing options.
   * @returns The commit signature with method and namespace metadata.
   * @throws {@link CryptoError} if the key is missing or signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.commits.sign({
   *   data: Buffer.from(commitContent),
   *   identityDid: identity.did,
   * })
   * ```
   */
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
