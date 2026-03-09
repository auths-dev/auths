import native from './native'
import { mapNativeError, IdentityError } from './errors'
import type { Auths } from './client'

/** Result of linking a device to an identity. */
export interface Device {
  /** The device's DID (typically `did:key:z...`). */
  did: string
  /** Unique identifier of the attestation granting device authorization. */
  attestationId: string
}

/** Result of extending a device's authorization period. */
export interface DeviceExtension {
  /** The device's DID. */
  deviceDid: string
  /** New expiration timestamp (RFC 3339). */
  newExpiresAt: string
  /** Previous expiration timestamp, or `null` if there was none. */
  previousExpiresAt: string | null
}

/** Options for {@link DeviceService.link}. */
export interface LinkDeviceOptions {
  /** DID of the identity to link the device under. */
  identityDid: string
  /** Capabilities to grant the device (e.g. `['sign']`). */
  capabilities?: string[]
  /** Optional expiration in days. */
  expiresInDays?: number
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link DeviceService.revoke}. */
export interface RevokeDeviceOptions {
  /** DID of the device to revoke. */
  deviceDid: string
  /** DID of the identity that authorized the device. */
  identityDid: string
  /** Optional revocation note. */
  note?: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link DeviceService.extend}. */
export interface ExtendDeviceOptions {
  /** DID of the device to extend. */
  deviceDid: string
  /** DID of the authorizing identity. */
  identityDid: string
  /** Number of days to extend by. Defaults to 90. */
  days?: number
  /** Override the client's passphrase. */
  passphrase?: string
}

/**
 * Manages device authorization lifecycle: link, revoke, and extend.
 *
 * Access via {@link Auths.devices}.
 *
 * @example
 * ```typescript
 * const device = auths.devices.link({
 *   identityDid: identity.did,
 *   capabilities: ['sign'],
 *   expiresInDays: 90,
 * })
 * ```
 */
export class DeviceService {
  constructor(private client: Auths) {}

  /**
   * Links a new device to an identity with scoped capabilities.
   *
   * @param opts - Link options.
   * @returns The linked device with its DID and attestation ID.
   * @throws {@link IdentityError} if linking fails.
   *
   * @example
   * ```typescript
   * const device = auths.devices.link({
   *   identityDid: identity.did,
   *   capabilities: ['sign'],
   *   expiresInDays: 90,
   * })
   * console.log(device.did) // did:key:z...
   * ```
   */
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

  /**
   * Revokes a device's authorization under an identity.
   *
   * @param opts - Revocation options.
   * @throws {@link IdentityError} if revocation fails.
   *
   * @example
   * ```typescript
   * auths.devices.revoke({
   *   deviceDid: device.did,
   *   identityDid: identity.did,
   *   note: 'replaced',
   * })
   * ```
   */
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

  /**
   * Extends a device's authorization period.
   *
   * @param opts - Extension options.
   * @returns The extension result with new and previous expiration times.
   * @throws {@link IdentityError} if extension fails.
   *
   * @example
   * ```typescript
   * const ext = auths.devices.extend({
   *   deviceDid: device.did,
   *   identityDid: identity.did,
   *   days: 60,
   * })
   * console.log(ext.newExpiresAt) // RFC 3339 timestamp
   * ```
   */
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
