import { readFileSync } from 'node:fs'
import native from './native'
import { mapNativeError, VerificationError } from './errors'
import type { Auths } from './client'

/** Full audit report for a Git repository's commit signatures. */
export interface AuditReport {
  /** Individual commit audit entries. */
  commits: AuditCommit[]
  /** Aggregate signature statistics. */
  summary: AuditSummary
}

/** Audit information for a single Git commit. */
export interface AuditCommit {
  /** Git object ID (SHA). */
  oid: string
  /** Commit author name. */
  author_name: string
  /** Commit author email. */
  author_email: string
  /** Commit date (ISO 8601). */
  date: string
  /** Commit message (first line). */
  message: string
  /** Signature type (`'auths'`, `'gpg'`, `'ssh'`), or `null` if unsigned. */
  signature_type: string | null
  /** DID of the signer, or `null` if not an Auths signature. */
  signer_did: string | null
  /** Whether the signature verified successfully, or `null` if unsigned. */
  verified: boolean | null
}

/** Aggregate statistics from an audit report. */
export interface AuditSummary {
  /** Total number of commits analyzed. */
  total_commits: number
  /** Number of signed commits (any method). */
  signed_commits: number
  /** Number of unsigned commits. */
  unsigned_commits: number
  /** Number of Auths-signed commits. */
  auths_signed: number
  /** Number of GPG-signed commits. */
  gpg_signed: number
  /** Number of SSH-signed commits. */
  ssh_signed: number
  /** Number of signatures that passed verification. */
  verification_passed: number
  /** Number of signatures that failed verification. */
  verification_failed: number
}

/** Options for {@link AuditService.report}. */
export interface AuditReportOptions {
  /** Path to the Git repository to audit. */
  targetRepoPath: string
  /** Only include commits after this date (ISO 8601). */
  since?: string
  /** Only include commits before this date (ISO 8601). */
  until?: string
  /** Only include commits by this author. */
  author?: string
  /** Maximum number of commits to analyze. */
  limit?: number
  /** Path to an Auths identity-bundle JSON file for signer DID resolution. */
  identityBundlePath?: string
}

/** Parsed identity bundle metadata. */
export interface IdentityBundleInfo {
  /** Identity DID (`did:keri:...`). */
  did: string
  /** Hex-encoded Ed25519 public key. */
  publicKeyHex: string
  /** Human-readable identity label. */
  label: string | null
  /** Number of device attestations in the chain. */
  deviceCount: number
}

/**
 * Parse an Auths identity-bundle JSON file.
 *
 * @param path - Path to the identity-bundle JSON file.
 * @returns The parsed bundle object.
 *
 * @example
 * ```typescript
 * const bundle = parseIdentityBundle('.auths/identity-bundle.json')
 * console.log(bundle.did)
 * ```
 */
export function parseIdentityBundle(path: string): Record<string, unknown> {
  const content = readFileSync(path, 'utf-8')
  return JSON.parse(content) as Record<string, unknown>
}

/**
 * Parse an identity bundle into a typed {@link IdentityBundleInfo}.
 *
 * @param path - Path to the identity-bundle JSON file.
 * @returns Typed bundle metadata.
 */
export function parseIdentityBundleInfo(path: string): IdentityBundleInfo {
  const bundle = parseIdentityBundle(path)
  const pkHex = (bundle.public_key_hex ?? bundle.publicKeyHex ?? '') as string
  const chain = (bundle.attestation_chain ?? []) as unknown[]
  return {
    did: (bundle.did ?? '') as string,
    publicKeyHex: pkHex,
    label: (bundle.label ?? null) as string | null,
    deviceCount: chain.length,
  }
}

/** Options for {@link AuditService.isCompliant}. */
export interface AuditComplianceOptions {
  /** Path to the Git repository to audit. */
  targetRepoPath: string
  /** Only include commits after this date (ISO 8601). */
  since?: string
  /** Only include commits before this date (ISO 8601). */
  until?: string
  /** Only include commits by this author. */
  author?: string
}

/**
 * Audits Git repositories for commit signature compliance.
 *
 * Access via {@link Auths.audit}.
 *
 * @example
 * ```typescript
 * const report = auths.audit.report({ targetRepoPath: '/path/to/repo' })
 * console.log(report.summary.unsigned_commits)
 * ```
 */
export class AuditService {
  constructor(private client: Auths) {}

  /**
   * Generates an audit report for a Git repository's commit signatures.
   *
   * @param opts - Audit options.
   * @returns The audit report with per-commit details and summary statistics.
   * @throws {@link VerificationError} if the audit fails.
   *
   * @example
   * ```typescript
   * const report = auths.audit.report({ targetRepoPath: '/path/to/repo' })
   * console.log(report.summary.total_commits)
   * ```
   */
  report(opts: AuditReportOptions): AuditReport {
    try {
      const json = native.generateAuditReport(
        opts.targetRepoPath,
        this.client.repoPath,
        opts.since ?? null,
        opts.until ?? null,
        opts.author ?? null,
        opts.limit ?? null,
      )
      return JSON.parse(json)
    } catch (err) {
      throw mapNativeError(err, VerificationError)
    }
  }

  /**
   * Checks whether all commits in a repository are signed.
   *
   * @param opts - Compliance check options.
   * @returns `true` if every commit is signed, `false` otherwise.
   *
   * @example
   * ```typescript
   * if (auths.audit.isCompliant({ targetRepoPath: '/path/to/repo' })) {
   *   console.log('All commits signed')
   * }
   * ```
   */
  isCompliant(opts: AuditComplianceOptions): boolean {
    const report = this.report(opts)
    return report.summary.unsigned_commits === 0
  }
}
