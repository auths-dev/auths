//! RIP-X ref path constants and helpers for the Radicle identity repository layout.
//!
//! These constants define the Git ref paths used by KERI identity repositories
//! and project-level namespace bindings as specified in RIP-X. Both auths-radicle
//! and Heartwood must agree on these paths for interoperability.
//!
//! ## Identity repository layout (RIP-X Section 2)
//!
//! ```text
//! <rid>
//! └─ refs
//!    ├─ keri
//!    │  └─ kel                    # KEL commit chain (tip = latest event)
//!    └─ keys
//!       └─ <nid>
//!          └─ signatures
//!             ├─ did-key          # Device's signature blob
//!             └─ did-keri         # Identity's signature blob
//! ```
//!
//! ## Project namespace layout (RIP-X Section 2)
//!
//! ```text
//! <project-rid>
//! └─ refs
//!    └─ namespaces
//!       └─ did-keri-<prefix>
//!          └─ refs
//!             └─ rad
//!                └─ id            # Blob containing identity repo RID
//! ```

/// Git ref for the KERI Key Event Log commit chain.
///
/// The KEL is stored as a linear commit history under this ref. The tip commit
/// contains the latest event (inception, rotation, or interaction).
///
/// RIP-X Section 2: Identity repository layout.
///
/// Usage:
/// ```ignore
/// let kel_ref = auths_radicle::refs::KERI_KEL_REF;
/// assert_eq!(kel_ref, "refs/keri/kel");
/// ```
pub const KERI_KEL_REF: &str = "refs/keri/kel";

/// Root ref prefix for device attestation keys.
///
/// Device attestations are stored under `refs/keys/<nid>/signatures/`.
///
/// RIP-X Section 2: Identity repository layout.
///
/// Usage:
/// ```ignore
/// let prefix = auths_radicle::refs::KEYS_PREFIX;
/// assert_eq!(prefix, "refs/keys");
/// ```
pub const KEYS_PREFIX: &str = "refs/keys";

/// Subdirectory name for attestation signatures under a device key ref.
///
/// Combined with a device NID: `refs/keys/<nid>/signatures/`.
///
/// RIP-X Section 2: Identity repository layout.
///
/// Usage:
/// ```ignore
/// let sig_dir = auths_radicle::refs::SIGNATURES_DIR;
/// assert_eq!(sig_dir, "signatures");
/// ```
pub const SIGNATURES_DIR: &str = "signatures";

/// Blob name for the device's Ed25519 signature in a 2-way attestation.
///
/// Stored at `refs/keys/<nid>/signatures/did-key`. Contains the raw signature
/// bytes where the device key signs `(RID, did:keri)`.
///
/// RIP-X Section 2: 2-way attestation format.
///
/// Usage:
/// ```ignore
/// let blob = auths_radicle::refs::DID_KEY_BLOB;
/// assert_eq!(blob, "did-key");
/// ```
pub const DID_KEY_BLOB: &str = "did-key";

/// Blob name for the identity's Ed25519 signature in a 2-way attestation.
///
/// Stored at `refs/keys/<nid>/signatures/did-keri`. Contains the raw signature
/// bytes where the KERI identity key signs `(RID, did:key)`.
///
/// RIP-X Section 2: 2-way attestation format.
///
/// Usage:
/// ```ignore
/// let blob = auths_radicle::refs::DID_KERI_BLOB;
/// assert_eq!(blob, "did-keri");
/// ```
pub const DID_KERI_BLOB: &str = "did-keri";

/// Git ref for the identity pointer blob inside a DID namespace.
///
/// The blob at this ref contains the RID (Radicle Repository ID) of the KERI
/// identity repository. Nodes use this to discover which identity repo to fetch.
///
/// RIP-X Section 2: Project namespace layout.
///
/// Usage:
/// ```ignore
/// let rad_id = auths_radicle::refs::RAD_ID_REF;
/// assert_eq!(rad_id, "refs/rad/id");
/// ```
pub const RAD_ID_REF: &str = "refs/rad/id";

/// Returns the signatures ref for a device.
///
/// Args:
/// * `nid`: The device's Node ID (e.g., `z6MkhaXg...`).
///
/// Usage:
/// ```ignore
/// let r = auths_radicle::refs::device_signatures_ref("z6MkhaXg");
/// assert_eq!(r, "refs/keys/z6MkhaXg/signatures");
/// ```
pub fn device_signatures_ref(nid: &str) -> String {
    format!("{KEYS_PREFIX}/{nid}/{SIGNATURES_DIR}")
}

/// Returns the `did-key` signature blob ref for a device.
///
/// Args:
/// * `nid`: The device's Node ID.
///
/// Usage:
/// ```ignore
/// let r = auths_radicle::refs::device_did_key_ref("z6MkhaXg");
/// assert_eq!(r, "refs/keys/z6MkhaXg/signatures/did-key");
/// ```
pub fn device_did_key_ref(nid: &str) -> String {
    format!("{KEYS_PREFIX}/{nid}/{SIGNATURES_DIR}/{DID_KEY_BLOB}")
}

/// Returns the `did-keri` signature blob ref for a device.
///
/// Args:
/// * `nid`: The device's Node ID.
///
/// Usage:
/// ```ignore
/// let r = auths_radicle::refs::device_did_keri_ref("z6MkhaXg");
/// assert_eq!(r, "refs/keys/z6MkhaXg/signatures/did-keri");
/// ```
pub fn device_did_keri_ref(nid: &str) -> String {
    format!("{KEYS_PREFIX}/{nid}/{SIGNATURES_DIR}/{DID_KERI_BLOB}")
}

/// Returns the namespace ref prefix for a KERI identity in a project repo.
///
/// Replaces `:` with `-` in the input to produce a valid Git ref component,
/// per the RIP-X convention (e.g., `did:keri:EXq5...` → `did-keri-EXq5...`).
/// If the input is already a bare prefix (no colons), it is used as-is.
///
/// RIP-X Section 2: Project namespace layout.
///
/// Args:
/// * `keri_prefix`: Either a full DID (`did:keri:EXq5...`) or bare prefix (`EXq5...`).
///
/// Usage:
/// ```ignore
/// // With full DID
/// let r = auths_radicle::refs::identity_namespace_prefix("did:keri:EXq5abc");
/// assert_eq!(r, "refs/namespaces/did-keri-EXq5abc");
///
/// // With bare prefix
/// let r = auths_radicle::refs::identity_namespace_prefix("EXq5abc");
/// assert_eq!(r, "refs/namespaces/did-keri-EXq5abc");
/// ```
pub fn identity_namespace_prefix(keri_prefix: &str) -> String {
    // Strip the "did:keri:" method prefix if present, then reconstruct with dashes
    let bare_prefix = keri_prefix
        .strip_prefix("did:keri:")
        .unwrap_or(keri_prefix);
    format!("refs/namespaces/did-keri-{bare_prefix}")
}

/// Returns the `refs/rad/id` pointer ref inside a KERI identity namespace.
///
/// The blob at this ref contains the RID of the identity repository.
///
/// RIP-X Section 2: Project namespace layout.
///
/// Args:
/// * `keri_prefix`: Either a full DID (`did:keri:EXq5...`) or bare prefix (`EXq5...`).
///
/// Usage:
/// ```ignore
/// let r = auths_radicle::refs::identity_rad_id_ref("EXq5abc");
/// assert_eq!(r, "refs/namespaces/did-keri-EXq5abc/refs/rad/id");
/// ```
pub fn identity_rad_id_ref(keri_prefix: &str) -> String {
    format!("{}/{RAD_ID_REF}", identity_namespace_prefix(keri_prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_rip_x_spec() {
        assert_eq!(KERI_KEL_REF, "refs/keri/kel");
        assert_eq!(KEYS_PREFIX, "refs/keys");
        assert_eq!(SIGNATURES_DIR, "signatures");
        assert_eq!(DID_KEY_BLOB, "did-key");
        assert_eq!(DID_KERI_BLOB, "did-keri");
        assert_eq!(RAD_ID_REF, "refs/rad/id");
    }

    #[test]
    fn device_ref_helpers() {
        let nid = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        assert_eq!(
            device_signatures_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures"
        );
        assert_eq!(
            device_did_key_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures/did-key"
        );
        assert_eq!(
            device_did_keri_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures/did-keri"
        );
    }

    #[test]
    fn identity_namespace_with_bare_prefix() {
        assert_eq!(
            identity_namespace_prefix("EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
        );
    }

    #[test]
    fn identity_namespace_with_full_did() {
        assert_eq!(
            identity_namespace_prefix("did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
        );
    }

    #[test]
    fn character_replacement_colon_to_dash() {
        // Verifies the `:` to `-` replacement per RIP-X spec
        let result = identity_namespace_prefix("did:keri:ABC123");
        assert_eq!(result, "refs/namespaces/did-keri-ABC123");
        assert!(!result.contains(':'), "colons must be replaced with dashes");
    }

    #[test]
    fn identity_rad_id_ref_produces_full_path() {
        assert_eq!(
            identity_rad_id_ref("EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148/refs/rad/id"
        );
    }

    #[test]
    fn heartwood_compatibility() {
        // The output of identity_namespace_prefix() must be compatible with
        // Heartwood's IdentityNamespace::from_ref_component() which parses
        // "did-keri-<prefix>" from the component after "refs/namespaces/".
        let prefix = "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148";
        let full_ref = identity_namespace_prefix(prefix);
        let component = full_ref
            .strip_prefix("refs/namespaces/")
            .expect("must start with refs/namespaces/");
        assert!(
            component.starts_with("did-keri-"),
            "component must start with did-keri-"
        );
        let extracted = component
            .strip_prefix("did-keri-")
            .expect("must have did-keri- prefix");
        assert_eq!(extracted, prefix, "round-trip must preserve the KERI prefix");
    }

    #[test]
    fn refs_contain_no_invalid_characters() {
        let nid = "z6MkTest";
        let prefix = "EXq5Test";

        // Git refnames cannot contain: space, ~, ^, :, ?, *, [, \, or ..
        let refs_to_check = [
            device_signatures_ref(nid),
            device_did_key_ref(nid),
            device_did_keri_ref(nid),
            identity_namespace_prefix(prefix),
            identity_rad_id_ref(prefix),
        ];

        for r in &refs_to_check {
            assert!(!r.contains(' '), "ref contains space: {r}");
            assert!(!r.contains('~'), "ref contains ~: {r}");
            assert!(!r.contains('^'), "ref contains ^: {r}");
            assert!(!r.contains(':'), "ref contains colon: {r}");
            assert!(!r.contains('?'), "ref contains ?: {r}");
            assert!(!r.contains('*'), "ref contains *: {r}");
            assert!(!r.contains('['), "ref contains [: {r}");
            assert!(!r.contains('\\'), "ref contains backslash: {r}");
            assert!(!r.contains(".."), "ref contains ..: {r}");
        }
    }
}
