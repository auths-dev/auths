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
  /** Delegated `did:keri:` AID minted by the org for this member. */
  memberDid: string
  /** Role within the organization (e.g. `'admin'`, `'member'`). */
  role: string
  /** Capabilities granted to this member. */
  capabilities: string[]
  /** DID of the organization that owns this membership. */
  orgDid: string
  /** KERI prefix of the member's delegated identity. */
  memberPrefix: string
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
  /** Human-readable alias for the member key minted by the org. */
  memberLabel: string
  /** Role to assign (e.g. `'admin'`, `'member'`). */
  role: string
  /** Capabilities to grant the member. If omitted, role defaults are used. */
  capabilities?: string[]
  /** Override the client's passphrase. */
  passphrase?: string
  /** Optional Unix timestamp (seconds) at which the membership expires. */
  expiresAt?: number
}

/** Options for {@link OrgService.revokeMember}. */
export interface RevokeOrgMemberOptions {
  /** DID of the organization. */
  orgDid: string
  /** Delegated DID of the member to revoke. */
  memberDid: string
  /** Override the client's passphrase. */
  passphrase?: string
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
 * The organization mints a fresh delegated key for each member from a label;
 * callers do not provide member public keys.
 *
 * Access via {@link Auths.orgs}.
 *
 * @example
 * ```typescript
 * const org = auths.orgs.create({ label: 'my-team' })
 * auths.orgs.addMember({
 *   orgDid: org.orgDid,
 *   memberLabel: 'alice',
 *   role: 'member',
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
   * Adds a member to an organization. The org mints a fresh delegated key for
   * the member from `memberLabel`; the returned `memberDid` is the new AID.
   *
   * @param opts - Member options.
   * @returns The new member record.
   * @throws {@link OrgError} if the operation fails.
   *
   * @example
   * ```typescript
   * const member = auths.orgs.addMember({
   *   orgDid: org.orgDid,
   *   memberLabel: 'alice',
   *   role: 'member',
   * })
   * ```
   */
  addMember(opts: AddOrgMemberOptions): OrgMember {
    const pp = opts.passphrase ?? this.client.passphrase
    const capsJson = opts.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      const result = native.addOrgMember(
        opts.orgDid,
        opts.memberLabel,
        opts.role,
        this.client.repoPath,
        capsJson,
        pp,
        opts.expiresAt ?? null,
      )
      return this.toMember(result)
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
      const result = native.revokeOrgMember(opts.orgDid, opts.memberDid, this.client.repoPath, pp)
      return this.toMember(result)
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
      const json = native.listOrgMembers(
        opts.orgDid,
        opts.includeRevoked ?? false,
        this.client.repoPath,
        this.client.passphrase,
      )
      const raw = JSON.parse(json) as Array<Record<string, unknown>>
      return raw.map((m) => ({
        memberDid: m.member_did as string,
        role: (m.role as string) ?? 'member',
        capabilities: (m.capabilities as string[]) ?? [],
        orgDid: opts.orgDid,
        memberPrefix: (m.member_prefix as string) ?? '',
        revoked: m.revoked as boolean,
        expiresAt: (m.expires_at as string | null) ?? null,
      }))
    } catch (err) {
      throw mapNativeError(err, OrgError)
    }
  }

  private toMember(result: import('./native').NapiOrgMember): OrgMember {
    return {
      memberDid: result.memberDid,
      role: result.role,
      capabilities: JSON.parse(result.capabilitiesJson || '[]'),
      orgDid: result.issuerDid,
      memberPrefix: result.attestationRid,
      revoked: result.revoked,
      expiresAt: result.expiresAt ?? null,
    }
  }
}
