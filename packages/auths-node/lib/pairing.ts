import native from './native'
import { mapNativeError, PairingError } from './errors'
import type { Auths } from './client'

export interface PairingSession {
  sessionId: string
  shortCode: string
  endpoint: string
  token: string
  controllerDid: string
}

export interface PairingResponse {
  deviceDid: string
  deviceName: string | null
  devicePublicKeyHex: string
}

export interface PairingResult {
  deviceDid: string
  deviceName: string | null
  attestationRid: string
}

export class PairingService {
  constructor(private client: Auths) {}

  createSession(opts?: {
    capabilities?: string[]
    timeoutSecs?: number
    bindAddress?: string
    enableMdns?: boolean
    passphrase?: string
  }): PairingSession {
    const pp = opts?.passphrase ?? this.client.passphrase
    const capsJson = opts?.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      const result = native.createPairingSession(
        this.client.repoPath,
        capsJson,
        opts?.timeoutSecs ?? null,
        opts?.bindAddress ?? null,
        opts?.enableMdns ?? null,
        pp,
      )
      return {
        sessionId: result.sessionId,
        shortCode: result.shortCode,
        endpoint: result.endpoint,
        token: result.token,
        controllerDid: result.controllerDid,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  waitForResponse(opts?: { timeoutSecs?: number }): PairingResponse {
    try {
      const result = native.waitForPairingResponse(opts?.timeoutSecs ?? null)
      return {
        deviceDid: result.deviceDid,
        deviceName: result.deviceName ?? null,
        devicePublicKeyHex: result.devicePublicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  stop(): void {
    try {
      native.stopPairingSession()
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  join(opts: {
    shortCode: string
    endpoint: string
    token: string
    deviceName?: string
    passphrase?: string
  }): PairingResponse {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = native.joinPairingSession(
        opts.shortCode,
        opts.endpoint,
        opts.token,
        this.client.repoPath,
        opts.deviceName ?? null,
        pp,
      )
      return {
        deviceDid: result.deviceDid,
        deviceName: result.deviceName ?? null,
        devicePublicKeyHex: result.devicePublicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  complete(opts: {
    deviceDid: string
    devicePublicKeyHex: string
    capabilities?: string[]
    passphrase?: string
  }): PairingResult {
    const pp = opts.passphrase ?? this.client.passphrase
    const capsJson = opts.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      const result = native.completePairing(
        opts.deviceDid,
        opts.devicePublicKeyHex,
        this.client.repoPath,
        capsJson,
        pp,
      )
      return {
        deviceDid: result.deviceDid,
        deviceName: result.deviceName ?? null,
        attestationRid: result.attestationRid,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }
}
