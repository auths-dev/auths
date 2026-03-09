import native from './native'
import { mapNativeError, OrgError } from './errors'
import type { Auths } from './client'

export interface OrgResult {
  orgPrefix: string
  orgDid: string
  label: string
  repoPath: string
}

export interface OrgMember {
  memberDid: string
  role: string
  capabilities: string[]
  issuerDid: string
  attestationRid: string
  revoked: boolean
  expiresAt: string | null
}

export interface CreateOrgOptions {
  label: string
  repoPath?: string
  passphrase?: string
}

export interface AddOrgMemberOptions {
  orgDid: string
  memberDid: string
  role: string
  capabilities?: string[]
  passphrase?: string
  note?: string
  memberPublicKeyHex?: string
}

export interface RevokeOrgMemberOptions {
  orgDid: string
  memberDid: string
  passphrase?: string
  note?: string
  memberPublicKeyHex?: string
}

export interface ListOrgMembersOptions {
  orgDid: string
  includeRevoked?: boolean
}

export class OrgService {
  constructor(private client: Auths) {}

  create(opts: CreateOrgOptions): OrgResult {
    const rp = opts.repoPath ?? this.client.repoPath
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.createOrg(opts.label, rp, pp)
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }

  addMember(opts: AddOrgMemberOptions): OrgMember {
    const pp = opts.passphrase ?? this.client.passphrase
    const capsJson = opts.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      const result = native.addOrgMember(
        opts.orgDid,
        opts.memberDid,
        opts.role,
        this.client.repoPath,
        capsJson,
        pp,
        opts.note ?? null,
        opts.memberPublicKeyHex ?? null,
      )
      return {
        memberDid: result.memberDid,
        role: result.role,
        capabilities: JSON.parse(result.capabilitiesJson || '[]'),
        issuerDid: result.issuerDid,
        attestationRid: result.attestationRid,
        revoked: result.revoked,
        expiresAt: result.expiresAt ?? null,
      }
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }

  revokeMember(opts: RevokeOrgMemberOptions): OrgMember {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.revokeOrgMember(
        opts.orgDid,
        opts.memberDid,
        this.client.repoPath,
        pp,
        opts.note ?? null,
        opts.memberPublicKeyHex ?? null,
      )
      return {
        memberDid: result.memberDid,
        role: result.role,
        capabilities: JSON.parse(result.capabilitiesJson || '[]'),
        issuerDid: result.issuerDid,
        attestationRid: result.attestationRid,
        revoked: result.revoked,
        expiresAt: result.expiresAt ?? null,
      }
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }

  listMembers(opts: ListOrgMembersOptions): OrgMember[] {
    try {
      const json = native.listOrgMembers(opts.orgDid, opts.includeRevoked ?? false, this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }
}
