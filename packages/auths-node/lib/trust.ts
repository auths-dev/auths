import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

/**
 * Trust level for a pinned identity.
 *
 * Values match the Rust `TrustLevel` enum in `auths-core/src/trust/pinned.rs`.
 */
export const TrustLevel = {
  /** Accepted on first use (interactive prompt). */
  Tofu: 'tofu',
  /** Manually pinned via CLI or `--issuer-pk`. */
  Manual: 'manual',
  /** Loaded from roots.json org policy file. */
  OrgPolicy: 'org_policy',
} as const
export type TrustLevel = (typeof TrustLevel)[keyof typeof TrustLevel]

/** A pinned (trusted) identity in the local trust store. */
export interface PinnedIdentity {
  /** The pinned identity's DID. */
  did: string
  /** Optional label for the pinned identity. */
  label: string | null
  /** Trust level: `'tofu'`, `'manual'`, or `'org_policy'`. */
  trustLevel: string
  /** ISO 8601 timestamp when this identity was first seen. */
  firstSeen: string
  /** KERI event log sequence number at time of pinning, or `null`. */
  kelSequence: number | null
  /** ISO 8601 timestamp when this identity was pinned. */
  pinnedAt: string
}

/** Options for {@link TrustService.pin}. */
export interface PinIdentityOptions {
  /** DID of the identity to pin. */
  did: string
  /** Optional label for the pinned identity. */
  label?: string
  /** Trust level to assign. Defaults to `'tofu'`. */
  trustLevel?: 'tofu' | 'manual' | 'org_policy'
}

/**
 * Manages the local trust store for pinning and querying trusted identities.
 *
 * Access via {@link Auths.trust}.
 *
 * @example
 * ```typescript
 * auths.trust.pin({ did: peer.did, label: 'alice' })
 * const entries = auths.trust.list()
 * ```
 */
export class TrustService {
  constructor(private client: Auths) {}

  /**
   * Pins an identity as trusted in the local store.
   *
   * @param opts - Pin options.
   * @returns The pinned identity entry.
   * @throws {@link StorageError} if the pin operation fails.
   *
   * @example
   * ```typescript
   * const entry = auths.trust.pin({ did: identity.did, label: 'my-peer' })
   * console.log(entry.trustLevel) // 'tofu'
   * ```
   */
  pin(opts: PinIdentityOptions): PinnedIdentity {
    try {
      const result = native.pinIdentity(
        opts.did,
        this.client.repoPath,
        opts.label ?? null,
        opts.trustLevel ?? null,
      )
      return {
        did: result.did,
        label: result.label ?? null,
        trustLevel: result.trustLevel,
        firstSeen: result.firstSeen,
        kelSequence: result.kelSequence ?? null,
        pinnedAt: result.pinnedAt,
      }
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Removes a pinned identity from the local trust store.
   *
   * @param did - DID of the identity to unpin.
   * @throws {@link StorageError} if the operation fails.
   */
  remove(did: string): void {
    try {
      native.removePinnedIdentity(did, this.client.repoPath)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Lists all pinned identities in the local trust store.
   *
   * @returns Array of pinned identity entries.
   * @throws {@link StorageError} if the operation fails.
   */
  list(): PinnedIdentity[] {
    try {
      const json = native.listPinnedIdentities(this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Looks up a specific pinned identity by DID.
   *
   * @param did - DID to look up.
   * @returns The pinned identity entry, or `null` if not found.
   * @throws {@link StorageError} if the operation fails.
   *
   * @example
   * ```typescript
   * const entry = auths.trust.get('did:keri:EBfd...')
   * if (entry) console.log(entry.label)
   * ```
   */
  get(did: string): PinnedIdentity | null {
    try {
      const result = native.getPinnedIdentity(did, this.client.repoPath)
      if (!result) return null
      return {
        did: result.did,
        label: result.label ?? null,
        trustLevel: result.trustLevel,
        firstSeen: result.firstSeen,
        kelSequence: result.kelSequence ?? null,
        pinnedAt: result.pinnedAt,
      }
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }
}
