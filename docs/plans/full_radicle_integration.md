# Full Radicle + Auths Integration Plan

## Executive Summary

The goal is to provide **invisible multi-device identity** for Radicle users. A user should be able to manage their identity across multiple machines (laptop, desktop, server) using standard Radicle commands, without needing to understand KERI, attestations, or the underlying `auths` infrastructure.

Currently, the integration is at the "Bridge" level (verification only). This plan outlines the path to full "Lifecycle" integration (creation, pairing, and management).

## Feedback on Current Approach

1.  **Bridge Architecture (Excellent):** The "Zero New Crypto" principle and the clean trait-based boundary between Heartwood and `auths-radicle` are correct. It prevents dependency bloat and keeps Radicle's core cryptographic assumptions intact.
2.  **Two-CLI Barrier (Needs Improvement):** Requiring users to install and run both `rad` and `auths` (as seen in `radicle-e2e.sh`) is a significant friction point.
3.  **Manual Key Import (Needs Automation):** The manual step of `auths key import --seed-file` is error-prone and exposes sensitive data. `rad` already has the seed; it should handle this internally.

## Proposed "Invisible" User Workflow

### 1. Initial Identity Creation
**Command:** `rad auth`
- **Current:** Creates an Ed25519 keypair and a `did:key:z6Mk...`.
- **Integrated:** 
  1. Creates the Radicle keypair.
  2. Automatically initializes a KERI identity (Controller DID).
  3. Links the Radicle key as the first "device".
  4. Stores all state in the standard Radicle storage location (`~/.radicle/storage`).

### 2. Adding a Second Device
**Command:** `rad auth device pair` (on the new machine)
- **Workflow:**
  1. The new machine generates its own `did:key`.
  2. It starts a local discovery service (mDNS/LAN).
  3. The user runs `rad auth device pair --accept` on the *existing* machine.
  4. The machines perform a secure handshake.
  5. The existing machine (controller) signs a linking attestation for the new device and gossips it.

### 3. Revocation
**Command:** `rad auth device revoke <nid>`
- **Workflow:** Marks the device as revoked in the KERI log. All subsequent fetches by peers will automatically reject signatures from that NID.

---

## Technical Integration Plan

### Phase 1: Bridge Finalization (Current Focus)
- Complete `auths-radicle` implementation.
- Finalize `CompositeAuthorityChecker` in Heartwood to use the bridge.
- Align RIP-X ref paths across both codebases.
- **Status:** In progress (Tasks fn-1.x and fn-2.x).

### Phase 2: CLI & SDK Embedding
- **Goal:** Move `auths` logic into the `rad` binary.
- **Action:** Heartwood's `rad` CLI should depend on `auths-sdk` and `auths-id`.
- **Action:** Implement `rad auth` subcommands that wrap `auths-sdk` functionality.
- **Action:** Automate "Seed to Keychain" flow. `rad` should pass the seed directly to `auths-id`'s keychain without writing to temporary files.

### Phase 3: Storage Layout Unification
- **Goal:** Single source of truth for identity state.
- **Action:** Default all `auths` operations to use Radicle's storage layout:
  - KEL: `refs/keri/kel`
  - Attestations: `refs/rad/multidevice/nodes/<nid>/link-attestation.json`
  - Identity Repo: A dedicated Radicle repo (RID) for the user's identity state.

### Phase 4: Identity Document Evolution
- **Goal:** Formalize `did:keri` in Radicle.
- **Action:** Update Radicle's Identity Document schema to allow `did:keri:...` as a delegate.
- **Action:** When a `did:keri` is a delegate, Radicle's fetch pipeline automatically invokes the bridge to verify which `did:key` is currently authorized.

### Phase 5: P2P Gossip & Sync
- **Goal:** Instant revocation propagation.
- **Action:** Integrate KERI event propagation into Radicle's gossip protocol.
- **Action:** Ensure `rad sync` prioritized fetching the identity repository to prevent "Quarantine" states during fetch.

---

## Strategic Feedback: The "Device" as a Delegate

The most important conceptual shift is treating the **Radicle Node (NID)** as a transient "Device" and the **KERI Identity** as the permanent "User".

- **Legacy Mode:** `Doc.delegates = [did:key:z6Mk...node1]`
- **Multi-Device Mode:** `Doc.delegates = [did:keri:E...user]`

By making this change, Radicle can support:
- Rotating keys without updating every project's ID document.
- Revoking lost laptops instantly.
- Shared organization accounts with threshold signatures (M-of-N devices).

## Next Steps for Development

1.  **Refactor `auths-cli` commands** into reusable library functions in `auths-sdk` that take `AuthsStorage` and `Keychain` as arguments.
2.  **Create a `rad-auths-integration` crate** (or expand `auths-radicle`) that provides the high-level `pair`, `link`, and `revoke` logic specifically for the `rad` CLI.
3.  **Update `scripts/radicle-e2e.sh`** to use the unified `rad` commands once they are implemented, slowly phasing out the use of the `auths` binary.
