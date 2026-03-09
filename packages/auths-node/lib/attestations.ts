import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

/** An attestation record from the local registry. */
export interface AttestationInfo {
  /** Unique resource identifier of the attestation. */
  rid: string
  /** DID of the issuer (identity that signed the attestation). */
  issuer: string
  /** DID of the subject (device or agent being attested). */
  subject: string
  /** DID of the device this attestation applies to. */
  deviceDid: string
  /** List of capabilities granted (e.g. `['sign']`). */
  capabilities: string[]
  /** Signer type: `'human'`, `'agent'`, or `'workload'`, or `null`. */
  signerType: string | null
  /** Expiration timestamp (RFC 3339), or `null` if no expiry. */
  expiresAt: string | null
  /** Revocation timestamp (RFC 3339), or `null` if not revoked. */
  revokedAt: string | null
  /** Creation timestamp (RFC 3339), or `null`. */
  createdAt: string | null
  /** DID of the identity that delegated this attestation, or `null`. */
  delegatedBy: string | null
  /** Raw JSON-serialized attestation. */
  json: string
}

/**
 * Queries attestations stored in the local registry.
 *
 * Access via {@link Auths.attestations}.
 *
 * @example
 * ```typescript
 * const atts = auths.attestations.list()
 * const latest = auths.attestations.getLatest(device.did)
 * ```
 */
export class AttestationService {
  constructor(private client: Auths) {}

  /**
   * Lists all attestations in the local registry.
   *
   * @returns Array of attestation records.
   * @throws {@link StorageError} if the operation fails.
   */
  list(): AttestationInfo[] {
    try {
      return native.listAttestations(this.client.repoPath).map(a => ({
        rid: a.rid,
        issuer: a.issuer,
        subject: a.subject,
        deviceDid: a.deviceDid,
        capabilities: a.capabilities,
        signerType: a.signerType ?? null,
        expiresAt: a.expiresAt ?? null,
        revokedAt: a.revokedAt ?? null,
        createdAt: a.createdAt ?? null,
        delegatedBy: a.delegatedBy ?? null,
        json: a.json,
      }))
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Lists attestations for a specific device.
   *
   * @param deviceDid - DID of the device to filter by.
   * @returns Array of attestation records for the device.
   * @throws {@link StorageError} if the operation fails.
   */
  listByDevice(deviceDid: string): AttestationInfo[] {
    try {
      return native.listAttestationsByDevice(this.client.repoPath, deviceDid).map(a => ({
        rid: a.rid,
        issuer: a.issuer,
        subject: a.subject,
        deviceDid: a.deviceDid,
        capabilities: a.capabilities,
        signerType: a.signerType ?? null,
        expiresAt: a.expiresAt ?? null,
        revokedAt: a.revokedAt ?? null,
        createdAt: a.createdAt ?? null,
        delegatedBy: a.delegatedBy ?? null,
        json: a.json,
      }))
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }

  /**
   * Retrieves the latest attestation for a device.
   *
   * @param deviceDid - DID of the device.
   * @returns The latest attestation, or `null` if none found.
   * @throws {@link StorageError} if the operation fails.
   */
  getLatest(deviceDid: string): AttestationInfo | null {
    try {
      const a = native.getLatestAttestation(this.client.repoPath, deviceDid)
      if (!a) return null
      return {
        rid: a.rid,
        issuer: a.issuer,
        subject: a.subject,
        deviceDid: a.deviceDid,
        capabilities: a.capabilities,
        signerType: a.signerType ?? null,
        expiresAt: a.expiresAt ?? null,
        revokedAt: a.revokedAt ?? null,
        createdAt: a.createdAt ?? null,
        delegatedBy: a.delegatedBy ?? null,
        json: a.json,
      }
    } catch (err) {
      throw mapNativeError(err, StorageError)
    }
  }
}
