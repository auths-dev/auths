import native from './native'
import { mapNativeError, PairingError } from './errors'
import type { Auths } from './client'

/** An active pairing session awaiting a device connection. */
export interface PairingSession {
  /** Unique session identifier. */
  sessionId: string
  /** Six-character code the device enters to pair. */
  shortCode: string
  /** HTTP endpoint the device connects to. */
  endpoint: string
  /** Authentication token for the session. */
  token: string
  /** DID of the controller identity running the session. */
  controllerDid: string
}

/** Response received when a device connects to a pairing session. */
export interface PairingResponse {
  /** DID of the connecting device. */
  deviceDid: string
  /** Optional name of the device, or `null`. */
  deviceName: string | null
  /** Hex-encoded Ed25519 public key of the device. */
  devicePublicKeyHex: string
}

/** Result of completing a pairing and authorizing the device. */
export interface PairingResult {
  /** DID of the paired device. */
  deviceDid: string
  /** Optional name of the device, or `null`. */
  deviceName: string | null
  /** Resource identifier of the authorization attestation. */
  attestationRid: string
}

/** Options for {@link PairingService.createSession}. */
export interface CreatePairingSessionOptions {
  /** Capabilities to offer the pairing device (e.g. `['sign:commit']`). */
  capabilities?: string[]
  /** Timeout in seconds for the session. */
  timeoutSecs?: number
  /** Bind address for the pairing server (e.g. `'127.0.0.1'`). */
  bindAddress?: string
  /** Whether to enable mDNS discovery. */
  enableMdns?: boolean
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link PairingService.waitForResponse}. */
export interface WaitForPairingResponseOptions {
  /** Timeout in seconds to wait for a device. */
  timeoutSecs?: number
}

/** Options for {@link PairingService.join}. */
export interface JoinPairingOptions {
  /** Six-character short code from the pairing session. */
  shortCode: string
  /** HTTP endpoint of the pairing session. */
  endpoint: string
  /** Authentication token for the session. */
  token: string
  /** Optional name for this device. */
  deviceName?: string
  /** Override the client's passphrase. */
  passphrase?: string
}

/** Options for {@link PairingService.complete}. */
export interface CompletePairingOptions {
  /** DID of the device to authorize. */
  deviceDid: string
  /** Hex-encoded Ed25519 public key of the device. */
  devicePublicKeyHex: string
  /** Capabilities to grant the device. */
  capabilities?: string[]
  /** Override the client's passphrase. */
  passphrase?: string
}

/**
 * Handles device pairing for cross-device identity authorization.
 *
 * The pairing flow: controller creates a session, device joins with the
 * short code, controller completes pairing to authorize the device.
 *
 * Access via {@link Auths.pairing}.
 *
 * @example
 * ```typescript
 * const session = await auths.pairing.createSession({
 *   bindAddress: '127.0.0.1',
 *   capabilities: ['sign:commit'],
 * })
 * console.log(session.shortCode) // e.g. 'A3F7K2'
 *
 * // On the device side:
 * const response = await auths.pairing.join({
 *   shortCode: 'A3F7K2',
 *   endpoint: session.endpoint,
 *   token: session.token,
 * })
 * ```
 */
export class PairingService {
  private handle: any | null = null

  constructor(private client: Auths) {}

  /**
   * Creates a pairing session and starts listening for device connections.
   *
   * @param opts - Session options.
   * @returns The active pairing session with its short code and endpoint.
   * @throws {@link PairingError} if session creation fails.
   *
   * @example
   * ```typescript
   * const session = await auths.pairing.createSession({
   *   bindAddress: '127.0.0.1',
   *   enableMdns: false,
   * })
   * console.log(session.shortCode) // 6-char code
   * ```
   */
  async createSession(opts?: CreatePairingSessionOptions): Promise<PairingSession> {
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

  /**
   * Waits for a device to connect to the active pairing session.
   *
   * @param opts - Wait options.
   * @returns The connecting device's information.
   * @throws {@link PairingError} if no session is active or timeout is reached.
   */
  async waitForResponse(opts?: WaitForPairingResponseOptions): Promise<PairingResponse> {
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

  /**
   * Stops the active pairing session. Idempotent — safe to call multiple times.
   *
   * @throws {@link PairingError} if stopping the session fails.
   */
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

  /**
   * Joins an existing pairing session from the device side.
   *
   * @param opts - Join options with short code and endpoint from the controller.
   * @returns The pairing response with device identity information.
   * @throws {@link PairingError} if joining fails.
   *
   * @example
   * ```typescript
   * const response = await auths.pairing.join({
   *   shortCode: 'A3F7K2',
   *   endpoint: 'http://127.0.0.1:8080',
   *   token: sessionToken,
   * })
   * ```
   */
  async join(opts: JoinPairingOptions): Promise<PairingResponse> {
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

  /**
   * Completes pairing by authorizing the connected device.
   *
   * @param opts - Completion options with device identity and capabilities.
   * @returns The pairing result with the device's authorization attestation.
   * @throws {@link PairingError} if no session is active or completion fails.
   */
  async complete(opts: CompletePairingOptions): Promise<PairingResult> {
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
