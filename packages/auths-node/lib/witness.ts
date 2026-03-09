import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

/** A witness node entry in the local registry. */
export interface WitnessEntry {
  /** URL of the witness endpoint. */
  url: string
  /** DID of the witness, or `null` if not yet resolved. */
  did: string | null
  /** Optional label for the witness. */
  label: string | null
}

/** Options for {@link WitnessService.add}. */
export interface AddWitnessOptions {
  /** URL of the witness endpoint (e.g. `'http://witness.example.com:3333'`). */
  url: string
  /** Optional label for the witness. */
  label?: string
}

/**
 * Manages witness nodes for receipt-based verification.
 *
 * Access via {@link Auths.witnesses}.
 *
 * @example
 * ```typescript
 * auths.witnesses.add({ url: 'http://witness.example.com:3333' })
 * const witnesses = auths.witnesses.list()
 * ```
 */
export class WitnessService {
  constructor(private client: Auths) {}

  /**
   * Adds a witness node. Idempotent — adding the same URL twice is a no-op.
   *
   * @param opts - Witness options.
   * @returns The witness entry.
   * @throws {@link StorageError} if the operation fails.
   *
   * @example
   * ```typescript
   * const w = auths.witnesses.add({ url: 'http://witness.example.com:3333' })
   * console.log(w.url) // http://witness.example.com:3333
   * ```
   */
  add(opts: AddWitnessOptions): WitnessEntry {
    try {
      const result = native.addWitness(opts.url, this.client.repoPath, opts.label ?? null)
      return {
        url: result.url,
        did: result.did ?? null,
        label: result.label ?? null,
      }
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Removes a witness by URL.
   *
   * @param url - URL of the witness to remove.
   * @throws {@link StorageError} if the operation fails.
   */
  remove(url: string): void {
    try {
      native.removeWitness(url, this.client.repoPath)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Lists all registered witnesses.
   *
   * @returns Array of witness entries.
   * @throws {@link StorageError} if the operation fails.
   */
  list(): WitnessEntry[] {
    try {
      const json = native.listWitnesses(this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }
}
