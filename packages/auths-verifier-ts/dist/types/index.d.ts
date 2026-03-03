/**
 * @auths/verifier - Attestation verification for TypeScript/JavaScript
 *
 * This package provides WASM-powered cryptographic verification of Auths attestations.
 *
 * @example
 * ```typescript
 * import { init, verifyAttestation, verifyChain } from '@auths/verifier';
 *
 * // Initialize the WASM module (required before verification)
 * await init();
 *
 * // Verify a single attestation
 * const result = verifyAttestation(attestationJson, issuerPublicKeyHex);
 * if (!result.valid) {
 *   console.error('Verification failed:', result.error);
 * }
 *
 * // Verify a chain of attestations
 * const report = verifyChain(attestationsArray, rootPublicKeyHex);
 * if (report.status.type !== 'Valid') {
 *   console.error('Chain verification failed:', report.status);
 * }
 * ```
 */
export * from './types';
import type { VerificationResult, VerificationReport, KeriKeyState, DeviceLinkResult } from './types';
/**
 * Initialize the WASM module. Must be called before any verification functions.
 *
 * @throws Error if WASM initialization fails
 *
 * @example
 * ```typescript
 * await init();
 * // Now verification functions can be used
 * ```
 */
export declare function init(): Promise<void>;
/**
 * Check if the WASM module is initialized
 */
export declare function isInitialized(): boolean;
/**
 * Verify a single attestation against an issuer's public key.
 *
 * @param attestationJson - The attestation as a JSON string
 * @param issuerPublicKeyHex - The issuer's Ed25519 public key in hex format (64 characters)
 * @returns VerificationResult with valid flag and optional error
 *
 * @example
 * ```typescript
 * const result = verifyAttestation(
 *   JSON.stringify(attestation),
 *   'a1b2c3d4...' // 64 hex characters
 * );
 *
 * if (result.valid) {
 *   console.log('Attestation is valid!');
 * } else {
 *   console.error('Invalid:', result.error);
 * }
 * ```
 */
export declare function verifyAttestation(attestationJson: string, issuerPublicKeyHex: string): Promise<VerificationResult>;
/**
 * Verify a single attestation, throwing on failure.
 *
 * @param attestationJson - The attestation as a JSON string
 * @param issuerPublicKeyHex - The issuer's Ed25519 public key in hex format
 * @throws Error if verification fails
 *
 * @example
 * ```typescript
 * try {
 *   verifyAttestationOrThrow(attestationJson, issuerPk);
 *   console.log('Valid!');
 * } catch (error) {
 *   console.error('Invalid:', error.message);
 * }
 * ```
 */
export declare function verifyAttestationOrThrow(attestationJson: string, issuerPublicKeyHex: string): Promise<void>;
/**
 * Verify a chain of attestations from a root identity to a leaf device.
 *
 * @param attestations - Array of attestations (as JSON strings or objects)
 * @param rootPublicKeyHex - The root identity's Ed25519 public key in hex format
 * @returns VerificationReport with status, chain details, and warnings
 *
 * @example
 * ```typescript
 * const report = verifyChain(
 *   [rootToIdentityAtt, identityToDeviceAtt],
 *   rootPublicKeyHex
 * );
 *
 * if (report.status.type === 'Valid') {
 *   console.log('Chain verified!');
 * } else {
 *   console.error('Chain invalid:', report.status);
 * }
 *
 * // Check individual links
 * report.chain.forEach((link, i) => {
 *   console.log(`Link ${i}: ${link.valid ? 'OK' : link.error}`);
 * });
 * ```
 */
export declare function verifyChain(attestations: (string | object)[], rootPublicKeyHex: string): Promise<VerificationReport>;
/**
 * Helper to check if a verification report indicates success
 *
 * @param report - The verification report to check
 * @returns true if the status is Valid
 */
export declare function isVerificationValid(report: VerificationReport): boolean;
/**
 * Verify a KERI Key Event Log and return the resulting key state.
 *
 * @param kelJson - JSON array of KEL events (inception, rotation, interaction)
 * @returns KeriKeyState with the current public key and sequence number
 * @throws Error if KEL parsing or verification fails
 *
 * @example
 * ```typescript
 * const keyState = await verifyKel(kelEventsJson);
 * console.log('Current key:', keyState.current_key_encoded);
 * console.log('Sequence:', keyState.sequence);
 * ```
 */
export declare function verifyKel(kelJson: string): Promise<KeriKeyState>;
/**
 * Verify that a device is cryptographically linked to a KERI identity.
 *
 * Composes KEL verification, attestation signature verification, device DID matching,
 * and seal anchoring. Returns a result object — never throws for verification failures.
 *
 * @param kelJson - JSON array of KEL events for the identity
 * @param attestationJson - JSON attestation linking the identity to the device
 * @param deviceDid - Expected device DID string (e.g. "did:key:z6Mk...")
 * @returns DeviceLinkResult with valid flag, optional key state, and seal info
 *
 * @example
 * ```typescript
 * const result = await verifyDeviceLink(kelJson, attestationJson, 'did:key:z6Mk...');
 * if (result.valid) {
 *   console.log('Device verified! Identity key:', result.key_state?.current_key_encoded);
 *   if (result.seal_sequence !== undefined) {
 *     console.log('Attestation anchored at KEL sequence:', result.seal_sequence);
 *   }
 * } else {
 *   console.error('Verification failed:', result.error);
 * }
 * ```
 */
export declare function verifyDeviceLink(kelJson: string, attestationJson: string, deviceDid: string): Promise<DeviceLinkResult>;
//# sourceMappingURL=index.d.ts.map