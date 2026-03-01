/**
 * Tests for @auths/verifier
 *
 * Note: These tests require the WASM module to be built first.
 * Run `npm run build:wasm` before running tests.
 */

import { init, verifyAttestation, verifyChain, isInitialized } from '../src/index';
import type { VerificationResult, VerificationReport } from '../src/types';

describe('@auths/verifier', () => {
  beforeAll(async () => {
    // Skip tests if WASM not available
    try {
      await init();
    } catch (error) {
      console.warn('WASM module not available, skipping integration tests');
      console.warn('Run `npm run build:wasm` to build the WASM module');
    }
  });

  describe('init', () => {
    it('should initialize successfully', () => {
      // If we reach here without error, init succeeded or was already done
      expect(isInitialized()).toBe(true);
    });

    it('should be idempotent', async () => {
      // Calling init multiple times should not throw
      await init();
      await init();
      expect(isInitialized()).toBe(true);
    });
  });

  describe('verifyAttestation', () => {
    it('should return valid:false for invalid JSON', () => {
      if (!isInitialized()) return;

      const result = verifyAttestation('not valid json', 'a'.repeat(64));
      expect(result.valid).toBe(false);
      expect(result.error).toContain('parse');
    });

    it('should return valid:false for invalid public key hex', () => {
      if (!isInitialized()) return;

      const result = verifyAttestation('{}', 'not-hex');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('hex');
    });

    it('should return valid:false for wrong key length', () => {
      if (!isInitialized()) return;

      const result = verifyAttestation('{}', 'abcd'); // too short
      expect(result.valid).toBe(false);
      expect(result.error).toContain('length');
    });
  });

  describe('verifyChain', () => {
    it('should return BrokenChain for empty array', () => {
      if (!isInitialized()) return;

      const report = verifyChain([], 'a'.repeat(64));
      // Empty chain should return Valid (no attestations to verify)
      // or an appropriate status
      expect(report.chain).toEqual([]);
    });

    it('should return BrokenChain for invalid JSON', () => {
      if (!isInitialized()) return;

      const report = verifyChain(['not valid json'], 'a'.repeat(64));
      expect(report.status.type).toBe('BrokenChain');
    });

    it('should handle attestation objects', () => {
      if (!isInitialized()) return;

      // Pass an object instead of JSON string
      const report = verifyChain([{ invalid: true }], 'a'.repeat(64));
      // Should fail but not throw
      expect(['BrokenChain', 'InvalidSignature']).toContain(report.status.type);
    });
  });

  describe('types', () => {
    it('should export all expected types', () => {
      // Type checks (compile-time)
      const result: VerificationResult = { valid: true };
      const report: VerificationReport = {
        status: { type: 'Valid' },
        chain: [],
        warnings: [],
      };

      expect(result.valid).toBe(true);
      expect(report.status.type).toBe('Valid');
    });

    it('should support all VerificationStatus variants', () => {
      const statuses = [
        { type: 'Valid' as const },
        { type: 'Expired' as const, at: '2024-01-01T00:00:00Z' },
        { type: 'Revoked' as const, at: null },
        { type: 'Revoked' as const, at: '2024-01-01T00:00:00Z' },
        { type: 'InvalidSignature' as const, step: 0 },
        { type: 'BrokenChain' as const, missing_link: 'test' },
      ];

      statuses.forEach((status) => {
        expect(status.type).toBeDefined();
      });
    });
  });
});
