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

/// Blob name for the Radicle identity document inside `refs/rad/id`.
///
/// RIP-X Section 2: Project namespace layout.
pub const IDENTITY_BLOB: &str = "radicle-identity.json";

/// Compatibility function for `Layout::radicle().device_did_key_ref(nid)`.
pub fn device_did_key_ref(nid: &str) -> String {
    Layout::radicle().device_did_key_ref(nid)
}

/// Compatibility function for `Layout::radicle().device_did_keri_ref(nid)`.
pub fn device_did_keri_ref(nid: &str) -> String {
    Layout::radicle().device_did_keri_ref(nid)
}

/// Configuration for the Radicle identity repository and namespace layout.
///
/// This struct holds the ref path components used by the bridge and storage
/// to discover KELs and attestations. It defaults to the RIP-X specification.
///
/// Usage:
/// ```ignore
/// use auths_radicle::refs::Layout;
///
/// let layout = Layout::radicle(); // RIP-X defaults
/// let kel = layout.keri_kel_ref();
/// assert_eq!(kel, "refs/keri/kel");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Ref for the KERI Key Event Log (e.g., "refs/keri/kel")
    pub keri_kel_ref: String,
    /// Root ref prefix for device keys (e.g., "refs/keys")
    pub keys_prefix: String,
    /// Subdirectory name for signatures (e.g., "signatures")
    pub signatures_dir: String,
    /// Blob name for device signature (e.g., "did-key")
    pub did_key_blob: String,
    /// Blob name for identity signature (e.g., "did-keri")
    pub did_keri_blob: String,
    /// Blob name for Radicle identity document (e.g., "radicle-identity.json")
    pub identity_blob: String,
    /// Ref for identity pointer in namespaces (e.g., "refs/rad/id")
    pub rad_id_ref: String,
}

impl Default for Layout {
    fn default() -> Self {
        Self::radicle()
    }
}

impl Layout {
    /// Create a new Layout with RIP-X defaults.
    pub fn radicle() -> Self {
        Self {
            keri_kel_ref: KERI_KEL_REF.to_string(),
            keys_prefix: KEYS_PREFIX.to_string(),
            signatures_dir: SIGNATURES_DIR.to_string(),
            did_key_blob: DID_KEY_BLOB.to_string(),
            did_keri_blob: DID_KERI_BLOB.to_string(),
            identity_blob: IDENTITY_BLOB.to_string(),
            rad_id_ref: RAD_ID_REF.to_string(),
        }
    }

    /// Returns the signatures ref for a device NID.
    ///
    /// Usage: `refs/keys/<nid>/signatures`
    pub fn device_signatures_ref(&self, nid: &str) -> String {
        format!("{}/{}/{}", self.keys_prefix, nid, self.signatures_dir)
    }

    /// Returns the `did-key` signature blob ref for a device NID.
    ///
    /// Usage: `refs/keys/<nid>/signatures/did-key`
    pub fn device_did_key_ref(&self, nid: &str) -> String {
        format!("{}/{}", self.device_signatures_ref(nid), self.did_key_blob)
    }

    /// Returns the `did-keri` signature blob ref for a device NID.
    ///
    /// Usage: `refs/keys/<nid>/signatures/did-keri`
    pub fn device_did_keri_ref(&self, nid: &str) -> String {
        format!("{}/{}", self.device_signatures_ref(nid), self.did_keri_blob)
    }

    /// Returns the namespace ref prefix for a KERI identity prefix.
    ///
    /// Usage: `refs/namespaces/did-keri-<prefix>`
    pub fn identity_namespace_prefix(&self, keri_prefix: &str) -> String {
        let bare_prefix = keri_prefix.strip_prefix("did:keri:").unwrap_or(keri_prefix);
        format!("refs/namespaces/did-keri-{bare_prefix}")
    }

    /// Returns the full ref path for the identity pointer inside a namespace.
    ///
    /// Usage: `refs/namespaces/did-keri-<prefix>/refs/rad/id`
    pub fn identity_rad_id_ref(&self, keri_prefix: &str) -> String {
        format!("{}/{}", self.identity_namespace_prefix(keri_prefix), self.rad_id_ref)
    }
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
        let layout = Layout::radicle();
        let nid = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        assert_eq!(
            layout.device_signatures_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures"
        );
        assert_eq!(
            layout.device_did_key_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures/did-key"
        );
        assert_eq!(
            layout.device_did_keri_ref(nid),
            "refs/keys/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/signatures/did-keri"
        );
    }

    #[test]
    fn identity_namespace_with_bare_prefix() {
        let layout = Layout::radicle();
        assert_eq!(
            layout.identity_namespace_prefix("EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
        );
    }

    #[test]
    fn identity_namespace_with_full_did() {
        let layout = Layout::radicle();
        assert_eq!(
            layout.identity_namespace_prefix("did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
        );
    }

    #[test]
    fn character_replacement_colon_to_dash() {
        let layout = Layout::radicle();
        // Verifies the `:` to `-` replacement per RIP-X spec
        let result = layout.identity_namespace_prefix("did:keri:ABC123");
        assert_eq!(result, "refs/namespaces/did-keri-ABC123");
        assert!(!result.contains(':'), "colons must be replaced with dashes");
    }

    #[test]
    fn identity_rad_id_ref_produces_full_path() {
        let layout = Layout::radicle();
        assert_eq!(
            layout.identity_rad_id_ref("EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"),
            "refs/namespaces/did-keri-EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148/refs/rad/id"
        );
    }

    #[test]
    fn heartwood_compatibility() {
        let layout = Layout::radicle();
        // The output of identity_namespace_prefix() must be compatible with
        // Heartwood's IdentityNamespace::from_ref_component() which parses
        // "did-keri-<prefix>" from the component after "refs/namespaces/".
        let prefix = "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148";
        let full_ref = layout.identity_namespace_prefix(prefix);
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
        assert_eq!(
            extracted, prefix,
            "round-trip must preserve the KERI prefix"
        );
    }

    #[test]
    fn refs_contain_no_invalid_characters() {
        let layout = Layout::radicle();
        let nid = "z6MkTest";
        let prefix = "EXq5Test";

        // Git refnames cannot contain: space, ~, ^, :, ?, *, [, \, or ..
        let refs_to_check = [
            layout.device_signatures_ref(nid),
            layout.device_did_key_ref(nid),
            layout.device_did_keri_ref(nid),
            layout.identity_namespace_prefix(prefix),
            layout.identity_rad_id_ref(prefix),
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
