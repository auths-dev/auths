import native from './native'
import { mapNativeError, VerificationError } from './errors'
import type { Auths } from './client'

export interface AuditReport {
  commits: AuditCommit[]
  summary: AuditSummary
}

export interface AuditCommit {
  oid: string
  author_name: string
  author_email: string
  date: string
  message: string
  signature_type: string | null
  signer_did: string | null
  verified: boolean | null
}

export interface AuditSummary {
  total_commits: number
  signed_commits: number
  unsigned_commits: number
  auths_signed: number
  gpg_signed: number
  ssh_signed: number
  verification_passed: number
  verification_failed: number
}

export interface AuditReportOptions {
  targetRepoPath: string
  since?: string
  until?: string
  author?: string
  limit?: number
}

export interface AuditComplianceOptions {
  targetRepoPath: string
  since?: string
  until?: string
  author?: string
}

export class AuditService {
  constructor(private client: Auths) {}

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

  isCompliant(opts: AuditComplianceOptions): boolean {
    const report = this.report(opts)
    return report.summary.unsigned_commits === 0
  }
}
