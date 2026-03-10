/**
 * Branded DID types and identity bundle type definitions.
 *
 * These types mirror the JSON schema at `auths/schemas/identity-bundle-v1.json`
 * and the Rust DID type system in `auths-verifier/src/types.rs`.
 *
 * @module
 */

// ── Branded DID Types ─────────────────────────────────────────────────

declare const __brand: unique symbol
type Brand<T, B extends string> = T & { readonly [__brand]: B }

/**
 * Identity DID — always `did:keri:...` format.
 *
 * Represents a KERI-based decentralized identity. Used for organizations
 * and individual identities. Parse with {@link parseIdentityDid}.
 */
export type IdentityDID = Brand<string, 'IdentityDID'>

/**
 * Device DID — always `did:key:z...` format.
 *
 * Represents a device's ephemeral key-based identity. Used for device
 * attestations and signing keys. Parse with {@link parseDeviceDid}.
 */
export type DeviceDID = Brand<string, 'DeviceDID'>

/**
 * Parse and validate an identity DID string.
 *
 * @param raw - A DID string that should start with `did:keri:`.
 * @returns The validated DID as an `IdentityDID` branded type.
 * @throws Error if the string does not start with `did:keri:`.
 *
 * @example
 * ```typescript
 * const did = parseIdentityDid('did:keri:EOrg123')
 * // did is typed as IdentityDID
 * ```
 */
export function parseIdentityDid(raw: string): IdentityDID {
  if (!raw.startsWith('did:keri:')) {
    throw new Error(`Expected did:keri: prefix, got: ${raw.slice(0, 20)}`)
  }
  return raw as IdentityDID
}

/**
 * Parse and validate a device DID string.
 *
 * @param raw - A DID string that should start with `did:key:z`.
 * @returns The validated DID as a `DeviceDID` branded type.
 * @throws Error if the string does not start with `did:key:z`.
 *
 * @example
 * ```typescript
 * const did = parseDeviceDid('did:key:z6MkDevice...')
 * // did is typed as DeviceDID
 * ```
 */
export function parseDeviceDid(raw: string): DeviceDID {
  if (!raw.startsWith('did:key:z')) {
    throw new Error(`Expected did:key:z prefix, got: ${raw.slice(0, 20)}`)
  }
  return raw as DeviceDID
}

// ── Signer Type ───────────────────────────────────────────────────────

/** The type of entity that produced a signature. */
export const SignerType = {
  Human: 'Human',
  Agent: 'Agent',
  Workload: 'Workload',
} as const
export type SignerType = (typeof SignerType)[keyof typeof SignerType]

// ── Role ──────────────────────────────────────────────────────────────

/** Organization member role. */
export const Role = {
  Admin: 'admin',
  Member: 'member',
  Readonly: 'readonly',
} as const
export type Role = (typeof Role)[keyof typeof Role]

// ── Capability ────────────────────────────────────────────────────────

/**
 * Well-known capability identifiers.
 *
 * Custom capabilities can be any valid string (alphanumeric + `:` + `-` + `_`, max 64 chars).
 * The `auths:` prefix is reserved.
 */
export const WellKnownCapability = {
  SignCommit: 'sign_commit',
  SignRelease: 'sign_release',
  ManageMembers: 'manage_members',
  RotateKeys: 'rotate_keys',
} as const

// ── Identity Bundle ───────────────────────────────────────────────────

/**
 * An attestation in the identity bundle's chain.
 *
 * Represents a 2-way key attestation between a primary identity and a device key.
 * Matches `auths/schemas/attestation-v1.json`.
 */
export interface BundleAttestation {
  /** Record identifier linking this attestation to its storage ref. */
  rid: string
  /** Schema version. */
  version: number
  /** DID of the issuing identity (`did:keri:...`). */
  issuer: string
  /** DID of the device being attested (`did:key:z...`). */
  subject: string
  /** Ed25519 public key of the device (32 bytes, hex-encoded). */
  device_public_key: string
  /** Device's Ed25519 signature over the canonical attestation data (hex-encoded). */
  device_signature: string
  /** Issuer's Ed25519 signature over the canonical attestation data (hex-encoded). */
  identity_signature?: string
  /** Capabilities this attestation grants. */
  capabilities?: string[]
  /** Role for org membership attestations. */
  role?: Role | null
  /** The type of entity that produced this signature. */
  signer_type?: SignerType | null
  /** DID of the attestation that delegated authority. */
  delegated_by?: string | null
  /** Creation timestamp (ISO 8601). */
  timestamp?: string | null
  /** Expiration timestamp (ISO 8601). */
  expires_at?: string | null
  /** Timestamp when the attestation was revoked (ISO 8601). */
  revoked_at?: string | null
  /** Optional human-readable note. */
  note?: string | null
  /** Optional arbitrary JSON payload. */
  payload?: unknown
}

/**
 * Identity bundle for stateless verification in CI/CD environments.
 *
 * Contains all the information needed to verify commit signatures without
 * requiring access to the identity repository or daemon.
 *
 * Matches `auths/schemas/identity-bundle-v1.json`.
 *
 * @example
 * ```typescript
 * import { readFileSync } from 'node:fs'
 * import type { IdentityBundle } from '@auths-dev/node'
 *
 * const bundle: IdentityBundle = JSON.parse(
 *   readFileSync('.auths/identity-bundle.json', 'utf-8')
 * )
 * console.log(bundle.identity_did) // did:keri:E...
 * ```
 */
export interface IdentityBundle {
  /** The DID of the identity (`did:keri:...`). */
  identity_did: string
  /** The public key in hex format for signature verification (32 bytes, hex). */
  public_key_hex: string
  /** Chain of attestations linking the signing key to the identity. */
  attestation_chain: BundleAttestation[]
  /** UTC timestamp when this bundle was created (ISO 8601). */
  bundle_timestamp: string
  /** Maximum age in seconds before this bundle is considered stale. */
  max_valid_for_secs: number
}
