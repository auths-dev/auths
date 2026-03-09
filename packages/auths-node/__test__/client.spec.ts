import { describe, it, expect } from 'vitest'
import { Auths } from '../lib/client'
import {
  AuthsError,
  VerificationError,
  CryptoError,
  KeychainError,
  StorageError,
  NetworkError,
  IdentityError,
  OrgError,
  PairingError,
} from '../lib/errors'

describe('Auths client', () => {
  it('instantiates with defaults', () => {
    const auths = new Auths()
    expect(auths.repoPath).toBe('~/.auths')
    expect(auths.passphrase).toBeUndefined()
  })

  it('instantiates with custom config', () => {
    const auths = new Auths({ repoPath: '/tmp/test-repo', passphrase: 'secret' })
    expect(auths.repoPath).toBe('/tmp/test-repo')
    expect(auths.passphrase).toBe('secret')
  })

  it('exposes all service properties', () => {
    const auths = new Auths()
    expect(auths.identities).toBeDefined()
    expect(auths.devices).toBeDefined()
    expect(auths.signing).toBeDefined()
    expect(auths.orgs).toBeDefined()
    expect(auths.trust).toBeDefined()
    expect(auths.witnesses).toBeDefined()
    expect(auths.attestations).toBeDefined()
    expect(auths.artifacts).toBeDefined()
    expect(auths.commits).toBeDefined()
    expect(auths.audit).toBeDefined()
    expect(auths.pairing).toBeDefined()
  })
})

describe('error hierarchy', () => {
  it('all error subclasses extend AuthsError', () => {
    for (const Cls of [
      VerificationError,
      CryptoError,
      KeychainError,
      StorageError,
      NetworkError,
      IdentityError,
      OrgError,
      PairingError,
    ]) {
      const err = new Cls('test')
      expect(err).toBeInstanceOf(AuthsError)
      expect(err).toBeInstanceOf(Error)
    }
  })

  it('AuthsError has code and message', () => {
    const err = new AuthsError('something broke')
    err.code = 'AUTHS_TEST'
    expect(err.message).toBe('something broke')
    expect(err.code).toBe('AUTHS_TEST')
  })

  it('NetworkError has shouldRetry', () => {
    const err = new NetworkError('timeout')
    expect(err.shouldRetry).toBe(true)
  })

  it('PairingError has shouldRetry', () => {
    const err = new PairingError('session expired')
    expect(err.shouldRetry).toBe(true)
  })
})
