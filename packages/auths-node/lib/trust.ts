import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

export interface PinnedIdentity {
  did: string
  label: string | null
  trustLevel: string
  firstSeen: string
  kelSequence: number | null
  pinnedAt: string
}

export class TrustService {
  constructor(private client: Auths) {}

  pin(opts: {
    did: string
    label?: string
    trustLevel?: 'tofu' | 'manual' | 'org_policy'
  }): PinnedIdentity {
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

  remove(did: string): void {
    try {
      native.removePinnedIdentity(did, this.client.repoPath)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  list(): PinnedIdentity[] {
    try {
      const json = native.listPinnedIdentities(this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

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
