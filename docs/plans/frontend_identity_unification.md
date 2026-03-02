# Detailed Plan: Frontend Identity Unification (did:keri)

This plan outlines the multi-repository effort to unify decentralized multi-device identity under a single `did:keri` profile in the Radicle frontend.

## Required Repositories
1.  `/Users/bordumb/workspace/repositories/auths-base/auths/crates`: The identity and bridge logic.
2.  `/Users/bordumb/workspace/repositories/heartwood/crates`: The Radicle node, storage, and API.
3.  `/Users/bordumb/workspace/repositories/radicle.xyz`: The Svelte-based frontend (or relevant UI repo).

## Phase 1: Bridge & Logic (Repository: `auths-base/auths`)

**Objective:** Finalize the resolution logic and provide the WASM-ready verifier for the frontend.

### 1.1 Complete `did:keri` resolution in `auths-radicle`
*   **File:** `crates/auths-radicle/src/identity.rs`
*   **Change:** Implement the `resolve_keri` arm to replay the KEL and derive the controller DID.
*   **Pseudo-code:**
    ```rust
    // identity.rs
    impl RadicleIdentityResolver {
        pub fn resolve(&self, did: &str) -> Result<RadicleIdentity, IdentityError> {
            match did {
                d if d.starts_with("did:key:") => self.resolve_key(d),
                d if d.starts_with("did:keri:") => self.resolve_keri(d), // <--- NEW
                _ => Err(IdentityError::UnsupportedMethod),
            }
        }

        fn resolve_keri(&self, did: &str) -> Result<RadicleIdentity, IdentityError> {
            let prefix = extract_prefix(did);
            let kel = self.storage.load_kel(prefix)?;
            let state = validate_kel(&kel)?; // From auths-id
            Ok(RadicleIdentity {
                did: did.to_string(),
                keys: state.current_keys.iter().map(|k| k.to_did()).collect(),
                metadata: state.metadata,
            })
        }
    }
    ```

### 1.2 Prepare WASM Verifier
*   **File:** `crates/auths-verifier/Cargo.toml`
*   **Action:** Ensure the `wasm` feature flag is robust and exports necessary bindings for `auths-verifier-ts`.
*   **Pseudo-code:**
    ```rust
    #[wasm_bindgen]
    pub fn verify_device_link(kel_json: &str, attestation_json: &str, device_did: &str) -> bool {
        let kel = deserialize_kel(kel_json);
        let attestation = deserialize_attestation(attestation_json);
        auths_verifier::core::verify(&kel, &attestation, device_did).is_ok()
    }
    ```

---

## Phase 2: API & Data Serving (Repository: `heartwood`)

**Objective:** Update the Radicle node to serve identity data and recognize the `did:keri` hierarchy.

### 2.1 Update Node API to expose Controller
*   **File:** `radicle-node/src/api/v1/users.rs` (in `heartwood`)
*   **Action:** When a user profile (`did:key`) is requested, look up its controller.
*   **Pseudo-code:**
    ```rust
    // Users API handler
    #[get("/users/:did")]
    fn get_user(did: Did) -> Json<UserResponse> {
        let controller = bridge.find_identity_for_device(&did, &repo_id);
        UserResponse {
            did: did,
            controller_did: controller, // <--- NEW: did:keri:...
            is_keri: did.is_keri(),
            devices: if did.is_keri() { bridge.list_devices(did) } else { vec![] }
        }
    }
    ```

### 2.2 Serve KEL and Attestations over HTTP
*   **File:** `radicle-node/src/api/v1/identity.rs`
*   **Action:** Add raw blob access for the frontend verifier.
*   **Endpoints:**
    - `GET /v1/identity/:did/kel` -> returns `refs/keri/kel` commit chain
    - `GET /v1/identity/:did/attestations` -> returns all `refs/keys/*/signatures/*` blobs

---

## Phase 3: Client-Side UI (Repository: `radicle.xyz`)

**Objective:** Unify the UI around the controller identity and verify links locally.

### 3.1 Unify Profile Rendering
*   **File:** `src/lib/views/User.svelte`
*   **Action:** If a `did:key` is visited, check if it has a `controller_did`. If so, render the controller's profile name/bio.
*   **Pseudo-code:**
    ```javascript
    // User.svelte
    async function loadProfile(did) {
        const user = await api.get(`/users/${did}`);
        if (user.controller_did) {
            // Unify: Fetch the Person's profile instead of the Device's
            this.profile = await api.get(`/users/${user.controller_did}`);
            this.is_device = true;
            this.device_did = did;
        }
    }
    ```

### 3.2 Implement Client-Side Verification
*   **File:** `src/lib/auths.ts`
*   **Action:** Use `auths-verifier-ts` to prove the identity link.
*   **Pseudo-code:**
    ```javascript
    import { verify_device_link } from 'auths-verifier-ts';

    async function verifyUser(did_keri, did_key) {
        const kel = await api.get(`/identity/${did_keri}/kel`);
        const attest = await api.get(`/identity/${did_key}/attestations`);
        const isValid = verify_device_link(kel, attest, did_key);
        return isValid; // UI shows a "Verified" badge if true
    }
    ```

---

## Phase 4: Integration & E2E (Script: `radicle-e2e.sh`)

**Objective:** Validate the 3-repo cycle using the existing E2E framework.

### 4.1 Update E2E script to check API and UI
*   **File:** `scripts/radicle-e2e.sh`
*   **Action:**
    1.  Perform the multi-device link.
    2.  Query the local `radicle-node` API for `NODE1_DID`.
    3.  **Assert:** The `controller_did` in the JSON response equals `CONTROLLER_DID`.
    4.  (Optional) Run a headless browser check to ensure the same Profile Name appears on both device pages.

### 4.2 Validate Revocation UI
*   **Action:**
    1.  Revoke `NODE2_DID` via `auths device revoke`.
    2.  Query API for `NODE2_DID`.
    3.  **Assert:** The response marks the device as `revoked: true` or the `controller_did` lookup now returns `None`.

---

## Remaining Tasks (Detailed)

### Phase 1: Logic & WASM (In Progress)
- [ ] **Refactor `RadicleIdentity`**: Update the struct in `auths-radicle/src/identity.rs` to include KERI-specific fields (current key set, sequence number) to support the unified profile view.
- [ ] **Expose `resolve_keri`**: Make the KERI resolution logic public and ensure it returns the enriched `RadicleIdentity` instead of a flat `ResolvedDid`.
- [ ] **WASM Binding Audit**: Ensure `wasm_verify_device_link` in `auths-verifier` returns exactly the JSON structure required by Phase 3.2.

### Phase 2: Heartwood API (Pending)
- [ ] **Locate API Routes**: Find the `radicle-httpd` or `radicle-node` API v1 implementation (likely in a separate `radicle-httpd` repository or internal module).
- [ ] **Extend User Endpoint**: Modify `GET /v1/users/:did` to perform a bridge lookup for the controller identity.
- [ ] **New Identity Endpoints**:
    - Implement `GET /v1/identity/:did/kel` to serve the full KERI Event Log from the identity repo.
    - Implement `GET /v1/identity/:did/attestations` to serve all device signatures for that identity.

### Phase 3: Frontend / UI (Pending)
- [ ] **`auths-verifier-ts` Integration**: Add the WASM verifier dependency to the frontend `package.json`.
- [ ] **Profile Unification**: Update the User profile component to check for `controller_did` and toggle between "Device View" and "Person View".
- [ ] **Local Verification Link**: Implement the `auths.ts` helper to fetch KEL/Attestations and run the WASM verifier on page load.

### Phase 4: Verification & E2E (Pending)
- [ ] **API Assertions**: Add `curl` checks to `scripts/radicle-e2e.sh` to verify that `controller_did` is correctly populated after a `pair` operation.
- [ ] **UI Integration Test**: (Optional) Add a basic Playwright/Cypress test to verify the "Verified" badge appears in the browser.
