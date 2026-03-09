import { describe, it, expect } from 'vitest'
import * as auths from '../lib/index'

describe('top-level exports', () => {
  it('exports Auths client', () => {
    expect(auths.Auths).toBeDefined()
  })

  it('exports service classes', () => {
    expect(auths.IdentityService).toBeDefined()
    expect(auths.DeviceService).toBeDefined()
    expect(auths.SigningService).toBeDefined()
    expect(auths.OrgService).toBeDefined()
    expect(auths.TrustService).toBeDefined()
    expect(auths.WitnessService).toBeDefined()
    expect(auths.AttestationService).toBeDefined()
    expect(auths.ArtifactService).toBeDefined()
    expect(auths.CommitService).toBeDefined()
    expect(auths.AuditService).toBeDefined()
    expect(auths.PairingService).toBeDefined()
  })

  it('exports PolicyBuilder and policy functions', () => {
    expect(auths.PolicyBuilder).toBeDefined()
    expect(auths.compilePolicy).toBeDefined()
    expect(auths.evaluatePolicy).toBeDefined()
  })

  it('exports verification functions', () => {
    expect(auths.verifyAttestation).toBeDefined()
    expect(auths.verifyChain).toBeDefined()
    expect(auths.verifyDeviceAuthorization).toBeDefined()
    expect(auths.verifyAttestationWithCapability).toBeDefined()
    expect(auths.verifyChainWithCapability).toBeDefined()
    expect(auths.verifyAtTime).toBeDefined()
    expect(auths.verifyAtTimeWithCapability).toBeDefined()
    expect(auths.verifyChainWithWitnesses).toBeDefined()
  })

  it('exports error classes', () => {
    expect(auths.AuthsError).toBeDefined()
    expect(auths.VerificationError).toBeDefined()
    expect(auths.CryptoError).toBeDefined()
    expect(auths.KeychainError).toBeDefined()
    expect(auths.StorageError).toBeDefined()
    expect(auths.NetworkError).toBeDefined()
    expect(auths.IdentityError).toBeDefined()
    expect(auths.OrgError).toBeDefined()
    expect(auths.PairingError).toBeDefined()
    expect(auths.mapNativeError).toBeDefined()
  })

  it('exports version function', () => {
    expect(auths.version).toBeDefined()
    expect(typeof auths.version).toBe('function')
  })
})
