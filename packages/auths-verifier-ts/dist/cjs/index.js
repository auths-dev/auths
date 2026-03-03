"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.init = init;
exports.isInitialized = isInitialized;
exports.verifyAttestation = verifyAttestation;
exports.verifyAttestationOrThrow = verifyAttestationOrThrow;
exports.verifyChain = verifyChain;
exports.isVerificationValid = isVerificationValid;
exports.verifyKel = verifyKel;
exports.verifyDeviceLink = verifyDeviceLink;
__exportStar(require("./types"), exports);
// WASM module state
let wasmModule = null;
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
async function init() {
    if (wasmModule) {
        return; // Already initialized
    }
    try {
        const wasm = await Promise.resolve().then(() => __importStar(require('../wasm/auths_verifier.js')));
        wasmModule = wasm;
    }
    catch (error) {
        throw new Error(`Failed to initialize WASM module: ${error}`);
    }
}
/**
 * Check if the WASM module is initialized
 */
function isInitialized() {
    return wasmModule !== null;
}
function ensureInitialized() {
    if (!wasmModule) {
        throw new Error('WASM module not initialized. Call init() first and await its completion.');
    }
    return wasmModule;
}
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
async function verifyAttestation(attestationJson, issuerPublicKeyHex) {
    const wasm = ensureInitialized();
    try {
        const resultJson = await wasm.verifyAttestationWithResult(attestationJson, issuerPublicKeyHex);
        return JSON.parse(resultJson);
    }
    catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
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
async function verifyAttestationOrThrow(attestationJson, issuerPublicKeyHex) {
    const wasm = ensureInitialized();
    try {
        await wasm.verifyAttestationJson(attestationJson, issuerPublicKeyHex);
    }
    catch (error) {
        throw new Error(`Attestation verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}
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
async function verifyChain(attestations, rootPublicKeyHex) {
    const wasm = ensureInitialized();
    const attestationsJson = JSON.stringify(attestations.map(att => (typeof att === 'string' ? JSON.parse(att) : att)));
    try {
        const reportJson = await wasm.verifyChainJson(attestationsJson, rootPublicKeyHex);
        return JSON.parse(reportJson);
    }
    catch (error) {
        return {
            status: {
                type: 'BrokenChain',
                missing_link: error instanceof Error ? error.message : String(error),
            },
            chain: [],
            warnings: [],
        };
    }
}
/**
 * Helper to check if a verification report indicates success
 *
 * @param report - The verification report to check
 * @returns true if the status is Valid
 */
function isVerificationValid(report) {
    return report.status.type === 'Valid';
}
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
async function verifyKel(kelJson) {
    const wasm = ensureInitialized();
    try {
        const resultJson = await wasm.verifyKelJson(kelJson);
        return JSON.parse(resultJson);
    }
    catch (error) {
        throw new Error(`KEL verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}
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
async function verifyDeviceLink(kelJson, attestationJson, deviceDid) {
    const wasm = ensureInitialized();
    try {
        const resultJson = await wasm.verifyDeviceLink(kelJson, attestationJson, deviceDid);
        return JSON.parse(resultJson);
    }
    catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
//# sourceMappingURL=index.js.map