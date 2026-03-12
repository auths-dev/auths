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
  it('invalid JSON returns error result', async () => {
    const result: VerificationResult = await verifyAttestation('not valid json', 'a'.repeat(64))
    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('invalid hex key throws VerificationError', async () => {
    await expect(verifyAttestation('{}', 'not-hex')).rejects.toThrow()
  })

  it('wrong key length throws VerificationError', async () => {
    await expect(verifyAttestation('{}', 'abcd')).rejects.toThrow()
  })

  it('empty attestation returns invalid', async () => {
    const result = await verifyAttestation('{}', 'a'.repeat(64))
    expect(result.valid).toBe(false)
  })
})

describe('verifyChain', () => {
  it('empty chain returns report', async () => {
    const report: VerificationReport = await verifyChain([], 'a'.repeat(64))
    expect(report.status).toBeDefined()
    expect(report.status.statusType).toBeDefined()
    expect(Array.isArray(report.chain)).toBe(true)
    expect(Array.isArray(report.warnings)).toBe(true)
  })

  it('invalid JSON in chain throws', async () => {
    await expect(verifyChain(['not valid json'], 'a'.repeat(64))).rejects.toThrow()
  })

  it('invalid root key throws', async () => {
    await expect(verifyChain([], 'not-hex')).rejects.toThrow()
  })
})

describe('verifyDeviceAuthorization', () => {
  it('empty attestations returns report', async () => {
    const report = await verifyDeviceAuthorization(
      'did:keri:Eidentity', 'did:key:zDevice', [], 'a'.repeat(64),
    )
    expect(report.status).toBeDefined()
    expect(report.status.statusType).not.toBe('Valid')
  })
})

describe('verifyAttestationWithCapability', () => {
  it('invalid attestation returns error', async () => {
    const result = await verifyAttestationWithCapability('{}', 'a'.repeat(64), 'sign')
    expect(result.valid).toBe(false)
  })
})

describe('verifyChainWithCapability', () => {
  it('empty chain returns report', async () => {
    const report = await verifyChainWithCapability([], 'a'.repeat(64), 'sign')
    expect(report.status).toBeDefined()
  })
})

describe('verifyAtTime', () => {
  it('invalid attestation returns error', async () => {
    const result = await verifyAtTime('{}', 'a'.repeat(64), '2025-01-01T00:00:00Z')
    expect(result.valid).toBe(false)
  })
})

describe('verifyAtTimeWithCapability', () => {
  it('invalid attestation returns error', async () => {
    const result = await verifyAtTimeWithCapability('{}', 'a'.repeat(64), '2025-01-01T00:00:00Z', 'sign')
    expect(result.valid).toBe(false)
  })
})
