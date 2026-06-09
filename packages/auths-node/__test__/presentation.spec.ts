import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  verifyPresentation,
  verifyCredential,
  PresentationStatus,
  CredentialStatus,
} from '../index.js'

// Cross-language fixture vectors emitted by the Rust builders (fn-153.5).
const fixtures = join(import.meta.dirname, '..', '..', '..', 'crates', 'auths-verifier', 'tests', 'fixtures')
const read = (name: string): string => readFileSync(join(fixtures, name), 'utf8')

describe('verifyPresentation / verifyCredential (typed)', () => {
  it('verifies a valid presentation and carries the typed grant facts', () => {
    const report = verifyPresentation(read('presentation_valid.json'))
    expect(report.status).toBe(PresentationStatus.Valid)
    expect(report.subject).toMatch(/^did:keri:/)
    expect(report.caps).toEqual(['sign'])
  })

  it('verifies a valid credential', () => {
    const report = verifyCredential(read('credential_valid.json'))
    expect(report.status).toBe(CredentialStatus.Valid)
    expect(report.caps).toEqual(['sign'])
  })

  it('reports a revoked credential as a typed status (not a throw)', () => {
    const report = verifyCredential(read('credential_revoked.json'))
    expect(report.status).toBe(CredentialStatus.CredentialRevoked)
    expect(report.revokedAt).toBeTypeOf('number')
  })

  it('returns a typed malformedRequest verdict for bad input (no unhandled throw)', () => {
    const report = verifyPresentation('{not json')
    expect(report.status).toBe(PresentationStatus.MalformedRequest)
    expect(report.message).toBeTruthy()
  })
})
