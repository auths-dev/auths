import native from './native'
import { mapNativeError, StorageError } from './errors'
import type { Auths } from './client'

export interface AttestationInfo {
  rid: string
  issuer: string
  subject: string
  deviceDid: string
  capabilities: string[]
  signerType: string | null
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string | null
  delegatedBy: string | null
  json: string
}

export class AttestationService {
  constructor(private client: Auths) {}

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
