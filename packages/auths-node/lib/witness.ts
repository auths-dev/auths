import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

export interface WitnessEntry {
  url: string
  did: string | null
  label: string | null
}

export class WitnessService {
  constructor(private client: Auths) {}

  add(opts: { url: string; label?: string }): WitnessEntry {
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

  remove(url: string): void {
    try {
      native.removeWitness(url, this.client.repoPath)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  list(): WitnessEntry[] {
    try {
      const json = native.listWitnesses(this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }
}
