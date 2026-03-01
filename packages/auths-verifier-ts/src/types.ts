/**
 * Result of a single attestation verification
 */
export interface VerificationResult {
  /** Whether the attestation is valid */
  valid: boolean;
  /** Error message if verification failed */
  error?: string;
}

/**
 * Status of a verification operation
 */
export type VerificationStatus =
  | { type: "Valid" }
  | { type: "Expired"; at: string }
  | { type: "Revoked"; at?: string | null }
  | { type: "InvalidSignature"; step: number }
  | { type: "BrokenChain"; missing_link: string };

/**
 * Represents a single link in the attestation chain
 */
export interface ChainLink {
  /** Issuer DID */
  issuer: string;
  /** Subject DID */
  subject: string;
  /** Whether this link verified successfully */
  valid: boolean;
  /** Error message if verification failed */
  error?: string | null;
}

/**
 * Complete verification report for chain verification
 */
export interface VerificationReport {
  /** Overall status of the verification */
  status: VerificationStatus;
  /** Details of each link in the chain */
  chain: ChainLink[];
  /** Warnings (non-fatal issues) */
  warnings: string[];
}

/**
 * Attestation structure (for reference)
 */
export interface Attestation {
  version: number;
  rid: string;
  issuer: string;
  subject: string;
  device_public_key: string;
  identity_signature: string;
  device_signature: string;
  revoked: boolean;
  expires_at?: string | null;
  timestamp?: string | null;
  note?: string | null;
  payload?: unknown;
}
