import native from './native'
import { mapNativeError, OrgError } from './errors'
import type { Auths } from './client'

/** Result of creating an organization. */
export interface OrgResult {
  /** Internal prefix for the organization. */
  orgPrefix: string
  /** The organization's KERI DID. */
  orgDid: string
  /** Human-readable label. */
  label: string
  /** Path to the registry storing the organization. */
  repoPath: string
}

/** An organization member record. */
export interface OrgMember {
  /** DID of the member. */
  memberDid: string
  /** Role within the organization (e.g. `'admin'`, `'member'`). */
  role: string
  /** Capabilities granted to this member. */
  capabilities: string[]
  /** DID of the admin who added this member. */
  issuerDid: string
  /** Resource identifier of the membership attestation. */
  attestationRid: string
  /** Whether the membership has been revoked. */
  revoked: boolean
  /** Expiration timestamp (RFC 3339), or `null` if no expiry. */
  expiresAt: string | null
}

/**
 * Check whether an organization member has admin role.
 *
 * @param member - The organization member to check.
 * @returns `true` if the member's role is `'admin'`.
 */
export function isAdmin(member: OrgMember): boolean {
  return member.role === 'admin'
}

/** Options for {@link OrgService.create}. */
export interface CreateOrgOptions {
  /** Human-readable label for the organization. */
  label: string
  /** Override the client's repo path. */
  repoPath?: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link OrgService.addMember}. */
export interface AddOrgMemberOptions {
  /** DID of the organization. */
  orgDid: string
  /** DID of the member to add. */
  memberDid: string
  /** Role to assign (e.g. `'admin'`, `'member'`). */
  role: string
  /** Capabilities to grant the member. */
  capabilities?: string[]
  /** Override the client's passphrase. */
  passphrase?: string
  /** Optional note for the membership record. */
  note?: string
  /** Hex-encoded public key of the member (required for cross-repo adds). */
  memberPublicKeyHex?: string
}

/** Options for {@link OrgService.revokeMember}. */
export interface RevokeOrgMemberOptions {
  /** DID of the organization. */
  orgDid: string
  /** DID of the member to revoke. */
  memberDid: string
  /** Override the client's passphrase. */
  passphrase?: string
  /** Optional revocation note. */
  note?: string
  /** Hex-encoded public key of the member. */
  memberPublicKeyHex?: string
}

/** Options for {@link OrgService.listMembers}. */
export interface ListOrgMembersOptions {
  /** DID of the organization. */
  orgDid: string
  /** Whether to include revoked members. Defaults to `false`. */
  includeRevoked?: boolean
}

/**
 * Manages organizations and their membership.
 *
 * Access via {@link Auths.orgs}.
 *
 * @example
 * ```typescript
 * const org = auths.orgs.create({ label: 'my-team' })
 * auths.orgs.addMember({
 *   orgDid: org.orgDid,
 *   memberDid: dev.did,
 *   role: 'member',
 *   memberPublicKeyHex: dev.publicKey,
 * })
 * ```
 */
export class OrgService {
  constructor(private client: Auths) {}

  /**
   * Creates a new organization.
   *
   * @param opts - Organization options.
   * @returns The created organization.
   * @throws {@link OrgError} if creation fails.
   *
   * @example
   * ```typescript
   * const org = auths.orgs.create({ label: 'engineering' })
   * console.log(org.orgDid) // did:keri:...
   * ```
   */
  create(opts: CreateOrgOptions): OrgResult {
    const rp = opts.repoPath ?? this.client.repoPath
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      return native.createOrg(opts.label, rp, pp)
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }

  /**
   * Adds a member to an organization.
   *
   * @param opts - Member options.
   * @returns The new member record.
   * @throws {@link OrgError} if the operation fails.
   *
   * @example
   * ```typescript
   * const member = auths.orgs.addMember({
   *   orgDid: org.orgDid,
   *   memberDid: dev.did,
   *   role: 'member',
   *   memberPublicKeyHex: dev.publicKey,
   * })
   * ```
   */
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

  /**
   * Revokes a member's access to an organization.
   *
   * @param opts - Revocation options.
   * @returns The updated member record with `revoked: true`.
   * @throws {@link OrgError} if the operation fails.
   */
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

  /**
   * Lists members of an organization.
   *
   * @param opts - List options.
   * @returns Array of member records.
   * @throws {@link OrgError} if the operation fails.
   *
   * @example
   * ```typescript
   * const members = auths.orgs.listMembers({ orgDid: org.orgDid })
   * console.log(members.length)
   * ```
   */
  listMembers(opts: ListOrgMembersOptions): OrgMember[] {
    try {
      const json = native.listOrgMembers(opts.orgDid, opts.includeRevoked ?? false, this.client.repoPath)
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }
}
