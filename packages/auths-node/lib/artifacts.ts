import native from './native'
import { mapNativeError, CryptoError } from './errors'
import type { Auths } from './client'

/** Result of signing an artifact. */
export interface ArtifactResult {
  /** JSON-serialized attestation for the signed artifact. */
  attestationJson: string
  /** Unique resource identifier of the attestation. */
  rid: string
  /** Content digest (hash) of the artifact. */
  digest: string
  /** Size of the artifact in bytes. */
  fileSize: number
}

/** Options for {@link ArtifactService.sign}. */
export interface SignArtifactOptions {
  /** Path to the file to sign. */
  filePath: string
  /** DID of the identity to sign with. */
  identityDid: string
  /** Optional expiration in days. */
  expiresInDays?: number
  /** Optional note attached to the attestation. */
  note?: string
  /** Override the client's passphrase. */
  passphrase?: string
  /** Optional commit SHA to bind the attestation to. */
  commitSha?: string
}

/** Options for {@link ArtifactService.signBytes}. */
export interface SignArtifactBytesOptions {
  /** Raw bytes to sign. */
  data: Buffer
  /** DID of the identity to sign with. */
  identityDid: string
  /** Optional expiration in days. */
  expiresInDays?: number
  /** Optional note attached to the attestation. */
  note?: string
  /** Override the client's passphrase. */
  passphrase?: string
  /** Optional commit SHA to bind the attestation to. */
  commitSha?: string
}

/**
 * Signs artifacts (files or raw bytes) to produce verifiable attestations.
 *
 * Access via {@link Auths.artifacts}.
 *
 * @example
 * ```typescript
 * const result = auths.artifacts.sign({
 *   filePath: './release.tar.gz',
 *   identityDid: identity.did,
 * })
 * console.log(result.digest) // content hash
 * ```
 */
export class ArtifactService {
  constructor(private client: Auths) {}

  /**
   * Signs a file at the given path.
   *
   * @param opts - Signing options.
   * @returns The artifact attestation with digest and metadata.
   * @throws {@link CryptoError} if signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.artifacts.sign({
   *   filePath: './build/app.wasm',
   *   identityDid: identity.did,
   *   expiresInDays: 365,
   * })
   * ```
   */
  sign(opts: SignArtifactOptions): ArtifactResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signArtifact(
        opts.filePath,
        opts.identityDid,
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
        opts.note ?? null,
        opts.commitSha ?? null,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }

  /**
   * Signs raw bytes (e.g. an in-memory buffer).
   *
   * @param opts - Signing options.
   * @returns The artifact attestation with digest and metadata.
   * @throws {@link CryptoError} if signing fails.
   *
   * @example
   * ```typescript
   * const result = auths.artifacts.signBytes({
   *   data: Buffer.from('binary content'),
   *   identityDid: identity.did,
   * })
   * ```
   */
  signBytes(opts: SignArtifactBytesOptions): ArtifactResult {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.signArtifactBytes(
        opts.data,
        opts.identityDid,
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
        opts.note ?? null,
        opts.commitSha ?? null,
      )
    } catch (err) {
      throw mapNativeError(err, CryptoError)
    }
  }
}
