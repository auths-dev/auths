import { describe, it, expect } from 'vitest'
import {
  verifyAttestation,
  verifyChain,
  verifyDeviceAuthorization,
  verifyAttestationWithCapability,
  verifyChainWithCapability,
  verifyAtTime,
  verifyAtTimeWithCapability,
} from '../lib/verify'
import type { VerificationResult, VerificationReport } from '../lib/verify'

describe('verifyAttestation', () => {
  it('invalid JSON returns error result', () => {
    const result: VerificationResult = verifyAttestation('not valid json', 'a'.repeat(64))
    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('invalid hex key throws VerificationError', () => {
    expect(() => verifyAttestation('{}', 'not-hex')).toThrow()
  })

  it('wrong key length throws VerificationError', () => {
    expect(() => verifyAttestation('{}', 'abcd')).toThrow()
  })

  it('empty attestation returns invalid', () => {
    const result = verifyAttestation('{}', 'a'.repeat(64))
    expect(result.valid).toBe(false)
  })
})

describe('verifyChain', () => {
  it('empty chain returns report', () => {
    const report: VerificationReport = verifyChain([], 'a'.repeat(64))
    expect(report.status).toBeDefined()
    expect(report.status.statusType).toBeDefined()
    expect(Array.isArray(report.chain)).toBe(true)
    expect(Array.isArray(report.warnings)).toBe(true)
  })

  it('invalid JSON in chain throws', () => {
    expect(() => verifyChain(['not valid json'], 'a'.repeat(64))).toThrow()
  })

  it('invalid root key throws', () => {
    expect(() => verifyChain([], 'not-hex')).toThrow()
  })
})

describe('verifyDeviceAuthorization', () => {
  it('empty attestations returns report', () => {
    const report = verifyDeviceAuthorization(
      'did:key:identity', 'did:key:device', [], 'a'.repeat(64),
    )
    expect(report.status).toBeDefined()
    expect(report.status.statusType).not.toBe('Valid')
  })
})

describe('verifyAttestationWithCapability', () => {
  it('invalid attestation returns error', () => {
    const result = verifyAttestationWithCapability('{}', 'a'.repeat(64), 'sign')
    expect(result.valid).toBe(false)
  })
})

describe('verifyChainWithCapability', () => {
  it('empty chain returns report', () => {
    const report = verifyChainWithCapability([], 'a'.repeat(64), 'sign')
    expect(report.status).toBeDefined()
  })
})

describe('verifyAtTime', () => {
  it('invalid attestation returns error', () => {
    const result = verifyAtTime('{}', 'a'.repeat(64), '2025-01-01T00:00:00Z')
    expect(result.valid).toBe(false)
  })
})

describe('verifyAtTimeWithCapability', () => {
  it('invalid attestation returns error', () => {
    const result = verifyAtTimeWithCapability('{}', 'a'.repeat(64), '2025-01-01T00:00:00Z', 'sign')
    expect(result.valid).toBe(false)
  })
})
