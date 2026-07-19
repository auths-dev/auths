#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
#![warn(missing_docs)]

//! Operator orchestration for running a hardened witness node.
//!
//! This crate is the seam between a node *operator* (who wants one command to a
//! healthy, registered node) and the platform's protocol crates (which must be
//! correct for strangers). It owns the *operation*: the embedded standup
//! manifest (the released witness node), the node's key-custody policy, the
//! identity minted at first boot, and the node's operator-facing health surface.
//!
//! It owns no *protocol*. Every byte a stranger must verify — the receipt
//! format, the key-state notice, signature checking — comes from the platform's
//! public crate APIs, which this crate composes:
//!
//! * [`auths_witness`] — the hardened receipt server this node runs, and the
//!   request-hardening constants ([`auths_witness::MAX_BODY_BYTES`] et al.) the
//!   standup manifest is configured against.
//! * [`auths_keri`] — the key-state notice ([`auths_keri::KeyStateNotice`]) and
//!   its wire version the node serves at its stable endpoint.
//! * [`auths_verifier`] — the witness-quorum policy
//!   ([`auths_verifier::WitnessQuorum`]) the node exists to let relying parties
//!   demand.
//!
//! If a standup task ever needs a protocol message the platform does not
//! expose, that is a missing *platform* API: add the public surface there,
//! never inline the bytes here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod anchor_role;
pub mod anchor_store;
pub mod build;
pub mod engine;
pub mod receipt;
pub mod registry;
pub mod signer;
pub mod sqlite_store;
pub mod standup;
pub mod vocabulary;

pub use anchor_role::{AnchorService, ServiceError, SubmitOutcome};
pub use anchor_store::InMemoryAnchorStore;
pub use build::{BuildAttestation, NodeBuildVerdict};
pub use engine::{DockerEngine, SocketHealthCheck, SocketHttpFetch};
pub use receipt::ReceiptBundle;
pub use registry::controller_keys_for_party;
pub use signer::{FileSigner, Signer};
pub use sqlite_store::SqliteAnchorStore;
pub use standup::{
    ContainerEngine, HealthCheck, HttpFetch, HttpResponse, StandupError, StandupOutcome, stand_up,
    tear_down,
};
pub use vocabulary::{PROTOCOL_VOCABULARY, scan_for_protocol_vocabulary};

// Compose the platform's public protocol surface. These re-exports make the
// composition explicit and give the operator CLI one import path for the
// protocol types it renders, all sourced from the trust kernel.
pub use auths_keri::{KERI_KEY_STATE_VERSION, KSN_TYPE, KeyStateNotice, SignedKsn};
pub use auths_verifier::{
    OfflineBuildVerdict, OfflineReceiptVerdict, SignedReceipt, WitnessQuorum, WitnessReceiptResult,
    verify_build_attestation_offline, verify_receipt_offline,
};
pub use auths_witness::{MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT};

/// The released, attested witness image a node runs.
///
/// Standup deploys *released* binaries, never source builds: the operator runs
/// what the platform shipped, provably (the digest is what a build attestation
/// is checked against before boot). The default points at the platform's
/// hardened distroless witness image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessImage {
    /// Fully-qualified image reference (registry/name:tag).
    pub reference: String,
    /// Container port the witness server binds inside the image.
    pub container_port: u16,
}

impl Default for WitnessImage {
    fn default() -> Self {
        Self {
            // The canonical hardened witness image (see docs/deployment/witness).
            reference: "ghcr.io/auths-dev/auths-witness:latest".to_string(),
            container_port: 3333,
        }
    }
}

/// How the node's stable signing identity is custodied at first boot.
///
/// A deployed witness must have a stable, pinnable identity. The safe default
/// is a managed key (KMS/enclave) where the host provides one; a file-backed
/// key is a deliberate downgrade that an operator must acknowledge — it never
/// happens silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KeyCustody {
    /// Key managed by a host KMS / secure enclave (the default, where available).
    #[default]
    Managed,
    /// Key persisted to a file on the node — an explicit, acknowledged downgrade.
    File,
}

/// A request to stand up one witness node.
///
/// This is the parsed, fully-formed operator intent — built once at the I/O
/// edge (the CLI), validated, then handed to the runtime. Nothing downstream
/// re-checks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandupRequest {
    /// The released, attested image to run.
    pub image: WitnessImage,
    /// Host port the node's witness endpoint is published on.
    pub host_port: u16,
    /// Key custody for the node's stable identity.
    pub custody: KeyCustody,
    /// Where the node's receipts/keystore volume is mounted on the host.
    pub data_dir: PathBuf,
    /// Host path to the signed build attestation for the released image's binary
    /// (`auths artifact sign` output). When set, standup mounts it into the node
    /// and points the binary at it, so the node serves a `/build` proof of which
    /// binary it runs. `None` stands a node up without that surface.
    pub build_attestation: Option<PathBuf>,
}

impl StandupRequest {
    /// A local-Docker standup on the default port with managed custody.
    ///
    /// Args:
    /// * `data_dir`: host directory for the node's persistent volume.
    pub fn local(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            image: WitnessImage::default(),
            host_port: 3333,
            custody: KeyCustody::default(),
            data_dir: data_dir.into(),
            build_attestation: None,
        }
    }

    /// The operator-facing health URL a freshly stood-up node answers on.
    ///
    /// Zero protocol vocabulary by construction — it is a plain HTTP health
    /// endpoint an operator can open in a browser.
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.host_port)
    }

    /// Render the embedded Compose manifest that brings the node up.
    ///
    /// The witness service is the platform's released image — the manifest
    /// declares it `image:`, never `build:`, so standup is never a source
    /// build. The body-size cap the server enforces
    /// ([`auths_witness::MAX_BODY_BYTES`]) is surfaced here as the front-proxy
    /// hint so the two limits cannot drift.
    ///
    /// The node's stable signing identity is injected at first boot (the
    /// `WITNESS_SEED` environment value), so the node advertises the same
    /// identity across restarts without a key file baked into the image. A
    /// file-backed custody downgrade is surfaced in the manifest header so an
    /// operator reading it sees the posture they acknowledged.
    pub fn compose_manifest(&self) -> String {
        let WitnessImage {
            reference,
            container_port,
        } = &self.image;
        let custody = match self.custody {
            KeyCustody::Managed => "managed (KMS/enclave)",
            KeyCustody::File => "file (acknowledged downgrade)",
        };
        // When a build attestation is supplied, mount it read-only into the node
        // and point the binary at it, so the node serves a `/build` proof of
        // which binary it runs. The attestation is data the node serves, never a
        // secret, so a plain read-only bind is right.
        let (attestation_env, attestation_volume) = match &self.build_attestation {
            Some(path) => (
                format!(
                    "\x20\x20\x20\x20\x20\x20AUTHS_WITNESS_BUILD_ATTESTATION: \"{ATTESTATION_CONTAINER_PATH}\"\n"
                ),
                format!(
                    "\x20\x20\x20\x20volumes:\n\
                     \x20\x20\x20\x20\x20\x20- \"{host}:{ATTESTATION_CONTAINER_PATH}:ro\"\n",
                    host = path.display(),
                ),
            ),
            None => (String::new(), String::new()),
        };
        format!(
            "# Embedded witness standup — one node, released image only.\n\
             # Never a source build; identity custody: {custody}.\n\
             # Max accepted body at the proxy mirrors the server cap: {max_body} bytes.\n\
             services:\n\
             \x20\x20witness:\n\
             \x20\x20\x20\x20image: {reference}\n\
             \x20\x20\x20\x20read_only: true\n\
             \x20\x20\x20\x20ports:\n\
             \x20\x20\x20\x20\x20\x20- \"127.0.0.1:{host_port}:{container_port}\"\n\
             \x20\x20\x20\x20environment:\n\
             \x20\x20\x20\x20\x20\x20AUTHS_WITNESS_SEED: \"${{WITNESS_SEED}}\"\n\
             {attestation_env}\
             \x20\x20\x20\x20command: [\"--bind\", \"0.0.0.0:{container_port}\", \"--curve\", \"ed25519\", \"--persist\", \"/data/receipts.db\"]\n\
             {attestation_volume}\
             \x20\x20\x20\x20tmpfs:\n\
             \x20\x20\x20\x20\x20\x20- /data\n",
            custody = custody,
            max_body = MAX_BODY_BYTES,
            reference = reference,
            host_port = self.host_port,
            container_port = container_port,
            attestation_env = attestation_env,
            attestation_volume = attestation_volume,
        )
    }
}

/// The fixed in-container path the build attestation is mounted at and the node
/// reads from. One constant so the mount target and the env value cannot drift.
const ATTESTATION_CONTAINER_PATH: &str = "/build-attestation.json";

/// The KERI wire version of the key-state notice this node serves.
///
/// Sourced from the platform, never redeclared here — the node serves exactly
/// what the trust kernel defines.
pub fn served_ksn_version() -> [u32; 2] {
    KERI_KEY_STATE_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_standup_uses_managed_custody_and_default_image() {
        let req = StandupRequest::local("/tmp/witness-data");
        assert_eq!(req.custody, KeyCustody::Managed);
        assert_eq!(req.image, WitnessImage::default());
        assert_eq!(req.host_port, 3333);
    }

    #[test]
    fn health_url_has_no_protocol_vocabulary() {
        // The operator-vocabulary rule lives in one place; this asserts the
        // health URL the operator opens is held to it, not to a private copy.
        let url = StandupRequest::local("/tmp/d").health_url();
        assert_eq!(
            scan_for_protocol_vocabulary(&url),
            None,
            "health URL leaked protocol vocabulary"
        );
    }

    #[test]
    fn compose_manifest_is_released_image_never_source_build() {
        let manifest = StandupRequest::local("/srv/witness").compose_manifest();
        assert!(
            manifest.contains("image:"),
            "manifest must declare a released image"
        );
        assert!(
            !manifest.contains("build:"),
            "standup must never build from source"
        );
        // The node mints its identity at first boot via an injected seed, never
        // a key file baked into the image.
        assert!(
            manifest.contains("AUTHS_WITNESS_SEED"),
            "the node identity must be injected at boot"
        );
        // The proxy body cap is sourced from the platform server constant.
        assert!(manifest.contains(&MAX_BODY_BYTES.to_string()));
        // With no build attestation, the node serves no `/build` surface — the
        // manifest neither mounts one nor points the binary at it.
        assert!(!manifest.contains("AUTHS_WITNESS_BUILD_ATTESTATION"));
    }

    #[test]
    fn compose_manifest_mounts_a_supplied_build_attestation() {
        let mut req = StandupRequest::local("/srv/witness");
        req.build_attestation = Some(PathBuf::from("/host/build.auths.json"));
        let manifest = req.compose_manifest();
        // The node is pointed at the in-container attestation path …
        assert!(manifest.contains("AUTHS_WITNESS_BUILD_ATTESTATION"));
        assert!(manifest.contains(ATTESTATION_CONTAINER_PATH));
        // … and the host file is bind-mounted read-only to that path.
        assert!(manifest.contains(&format!(
            "/host/build.auths.json:{ATTESTATION_CONTAINER_PATH}:ro"
        )));
        // Still a released image, never a source build.
        assert!(manifest.contains("image:"));
        assert!(!manifest.contains("build:"));
    }

    #[test]
    fn served_ksn_version_is_the_platform_version() {
        assert_eq!(served_ksn_version(), KERI_KEY_STATE_VERSION);
    }

    #[test]
    fn quorum_type_is_the_verifier_type() {
        // The node exists to let relying parties demand this quorum — the type
        // is the verifier's, not a fork.
        let q = WitnessQuorum {
            required: 2,
            verified: 0,
            receipts: Vec::<WitnessReceiptResult>::new(),
        };
        assert_eq!(q.required, 2);
    }
}
