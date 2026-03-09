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
  private handle: any | null = null

  constructor(private client: Auths) {}

  async createSession(opts?: {
    capabilities?: string[]
    timeoutSecs?: number
    bindAddress?: string
    enableMdns?: boolean
    passphrase?: string
  }): Promise<PairingSession> {
    const pp = opts?.passphrase ?? this.client.passphrase
    const capsJson = opts?.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      this.handle = await native.NapiPairingHandle.createSession(
        this.client.repoPath,
        capsJson,
        opts?.timeoutSecs ?? null,
        opts?.bindAddress ?? null,
        opts?.enableMdns ?? null,
        pp,
      )
      const session = this.handle.session
      return {
        sessionId: session.sessionId,
        shortCode: session.shortCode,
        endpoint: session.endpoint,
        token: session.token,
        controllerDid: session.controllerDid,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  async waitForResponse(opts?: { timeoutSecs?: number }): Promise<PairingResponse> {
    if (!this.handle) {
      throw new PairingError('No active pairing session. Call createSession first.', 'AUTHS_PAIRING_ERROR')
    }
    try {
      const result = await this.handle.waitForResponse(opts?.timeoutSecs ?? null)
      return {
        deviceDid: result.deviceDid,
        deviceName: result.deviceName ?? null,
        devicePublicKeyHex: result.devicePublicKeyHex,
      }
    } catch (err) {
      throw mapNativeError(err, PairingError)
    }
  }

  async stop(): Promise<void> {
    if (this.handle) {
      try {
        await this.handle.stop()
      } catch (err) {
        throw mapNativeError(err, PairingError)
      } finally {
        this.handle = null
      }
    }
  }

  async join(opts: {
    shortCode: string
    endpoint: string
    token: string
    deviceName?: string
    passphrase?: string
  }): Promise<PairingResponse> {
    const pp = opts.passphrase ?? this.client.passphrase
    try {
      const result = await native.joinPairingSession(
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

  async complete(opts: {
    deviceDid: string
    devicePublicKeyHex: string
    capabilities?: string[]
    passphrase?: string
  }): Promise<PairingResult> {
    if (!this.handle) {
      throw new PairingError('No active pairing session. Call createSession first.', 'AUTHS_PAIRING_ERROR')
    }
    const pp = opts.passphrase ?? this.client.passphrase
    const capsJson = opts.capabilities ? JSON.stringify(opts.capabilities) : null
    try {
      const result = await this.handle.complete(
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

  [Symbol.dispose](): void {
    // Fire-and-forget stop for sync dispose
    this.stop().catch(() => {})
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.stop()
  }
}
