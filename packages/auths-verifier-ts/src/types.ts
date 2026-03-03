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

/**
 * KERI key state after replaying a Key Event Log.
 * Returned by verifyKel() on successful KEL verification.
 */
export interface KeriKeyState {
  /** The KERI prefix (self-addressing identifier) */
  prefix: string;
  /** Current public key in KERI encoding (e.g. "D..." base64url) */
  current_key_encoded: string;
  /** Next-key commitment hash, null if identity is abandoned */
  next_commitment: string | null;
  /** Current sequence number in the KEL */
  sequence: number;
  /** Whether the identity has been abandoned (no next-key commitment) */
  is_abandoned: boolean;
  /** SAID of the last processed event */
  last_event_said: string;
}

/**
 * Result of verifying a device's link to a KERI identity.
 * Verification failures are expressed as valid=false with an error message,
 * never as thrown exceptions.
 */
export interface DeviceLinkResult {
  /** Whether the device link verified successfully */
  valid: boolean;
  /** Human-readable error if verification failed */
  error?: string;
  /** KERI key state after KEL replay (present on success) */
  key_state?: KeriKeyState;
  /** Sequence number of the IXN event anchoring the attestation seal (if found) */
  seal_sequence?: number;
}
