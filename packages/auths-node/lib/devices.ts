import native from './native'
import { mapNativeError, IdentityError } from './errors'
import type { Auths } from './client'

export interface Device {
  did: string
  attestationId: string
}

export interface DeviceExtension {
  deviceDid: string
  newExpiresAt: string
  previousExpiresAt: string | null
}

export interface LinkDeviceOptions {
  identityDid: string
  capabilities?: string[]
  expiresInDays?: number
  passphrase?: string
}

export interface RevokeDeviceOptions {
  deviceDid: string
  identityDid: string
  note?: string
  passphrase?: string
}

export interface ExtendDeviceOptions {
  deviceDid: string
  identityDid: string
  days?: number
  passphrase?: string
}

export class DeviceService {
  constructor(private client: Auths) {}

  link(opts: LinkDeviceOptions): Device {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.linkDeviceToIdentity(
        opts.identityDid,
        opts.capabilities ?? [],
        this.client.repoPath,
        pp,
        opts.expiresInDays ?? null,
      )
      return {
        did: result.deviceDid,
        attestationId: result.attestationId,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  revoke(opts: RevokeDeviceOptions): void {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      native.revokeDeviceFromIdentity(
        opts.deviceDid,
        opts.identityDid,
        this.client.repoPath,
        pp,
        opts.note ?? null,
      )
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }

  extend(opts: ExtendDeviceOptions): DeviceExtension {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.extendDeviceAuthorization(
        opts.deviceDid,
        opts.identityDid,
        opts.days ?? 90,
        this.client.repoPath,
        pp,
      )
      return {
        deviceDid: result.deviceDid,
        newExpiresAt: result.newExpiresAt,
        previousExpiresAt: result.previousExpiresAt ?? null,
      }
    } catch (err) {
      throw mapNativeError(err, IdentityError)
    }
  }
}
