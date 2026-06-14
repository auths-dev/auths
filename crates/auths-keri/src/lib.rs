// crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
#![warn(missing_docs)]

//! KERI protocol types, SAID computation, and CESR translation for Auths.
//!
//! The default feature set provides pure KERI types and SAID utilities with
//! no heavy dependencies — suitable for WASM and FFI embedding.
//!
//! Enable the `cesr` feature for bidirectional conversion between Auths'
//! internal JSON event representation and spec-compliant CESR streams
//! (Trust over IP KERI v0.9).
//!
//! Usage (default, no CESR):
//! ```ignore
//! use auths_keri::{Prefix, Said, compute_said};
//!
//! let said = compute_said(&event_json)?;
//! ```
//!
//! Usage (with CESR feature):
//! ```ignore
//! use auths_keri::{CesrV1Codec, export_kel_as_cesr};
//!
//! let codec = CesrV1Codec::new();
//! let cesr_stream = export_kel_as_cesr(&codec, &events)?;
//! ```

/// ACDC (Authentic Chained Data Container) credential type, SAID-ification, and
/// the pinned v1 capability schema.
pub mod acdc;
/// Validated capability identifiers — the atomic unit of authorization in Auths.
pub mod capability;
mod crypto;
/// `did:webs` DID-document projection of a resolved KERI key-state.
pub mod did_webs;
mod error;
mod events;
pub mod kel_io;
mod keys;
/// Key-State Notice (KSN) — signed snapshot of current key-state for thin clients.
pub mod ksn;
/// Routed KERI message types (qry, rpy, pro, bar, xip, exn).
pub mod messages;
/// Out-Of-Band Introduction (OOBI) — KERI discovery: resolve/serve AID endpoints.
pub mod oobi;
mod said;
mod state;
/// Backerless TEL (Transaction Event Log) credential-status events: `vcp`/`iss`/`rev`.
pub mod tel;
mod types;
mod validate;
/// Witness protocol types: receipts, providers, and error reporting for split-view defense.
pub mod witness;

/// CESR-correct primitive encoding (verkeys, digests, SAIDs) via `cesride` — the
/// byte-interoperable wire format that replaces the legacy naive base64 scheme.
mod cesr_encode;

#[cfg(feature = "cesr")]
mod codec;
#[cfg(feature = "cesr")]
mod event;
#[cfg(feature = "cesr")]
mod roundtrip;
#[cfg(feature = "cesr")]
mod stream;
#[cfg(feature = "cesr")]
mod version;

pub use acdc::{
    ACDC_KERIPY_REVISION, ACDC_VERSION_PREFIX, Acdc, AcdcError, Attributes, CAPABILITY_SCHEMA,
    compute_capability_schema_said, compute_schema_said,
};
pub use capability::{
    Capability, CapabilityError, MANAGE_MEMBERS, ROTATE_KEYS, SIGN_COMMIT, SIGN_RELEASE,
};
pub use crypto::{compute_next_commitment, verify_commitment};
pub use did_webs::{DidWebsDocument, PublicKeyJwk, VerificationMethod};
pub use error::{KeriTranslationError, TelError};
pub use events::{
    AgentScope, DipEvent, DipEventInit, DrtEvent, DrtEventInit, Event, IcpEvent, IcpEventInit,
    IndexedSignature, IxnEvent, KERI_VERSION_PREFIX, KeriSequence, RotEvent, RotEventInit, Seal,
    SignedEvent, SourceSeal, WireSignedDip, WireSignedRot, decode_agent_scope, decode_signed_dip,
    decode_signed_rot, encode_agent_scope, encode_signed_dip, encode_signed_rot,
    pair_kel_attachments, parse_attachment, parse_delegated_attachment, parse_source_seal_couples,
    serialize_attachment, serialize_source_seal_couples,
};
pub use keys::{KeriDecodeError, KeriPublicKey};
pub use ksn::{
    KERI_KEY_STATE_VERSION, KSN_TYPE, KSN_VERSION, KeyStateNotice, KeyStateRecord, KsnError,
    LatestEstablishmentEvent, SignedKsn,
};
pub use oobi::{
    EndRoleReply, LocSchemeReply, Oobi, OobiEndpoint, OobiError, OobiResolution, Role,
    ingest_oobi_stream,
};
pub use said::{
    Protocol, SAID_PLACEHOLDER, compute_said, compute_said_with_protocol, compute_section_said,
    verify_said,
};
pub use state::{AnchorStatus, KeyState};
pub use tel::{
    Iss, Rev, TEL_KERIPY_REVISION, TRAIT_NO_BACKERS, TelAnchorSeal, TelEvent, TelState, Vcp,
    encode_nonce as encode_tel_nonce, to_wire_bytes as tel_to_wire_bytes, validate_tel,
};
pub use types::{
    CesrKey, ConfigTrait, Fraction, FractionError, KeriTypeError, Prefix, Said, Threshold,
    VersionString,
};
pub use validate::{
    DelegatorKelLookup, KelPolicy, KelSealIndex, TrustedKel, ValidationError, WitnessedReplay,
    compute_event_said, finalize_dip_event, finalize_drt_event, finalize_icp_event,
    finalize_ixn_event, finalize_rot_event, find_seal_in_kel, parse_kel_json,
    serialize_for_signing, validate_delegation, validate_for_append, validate_signed_event,
    validate_signed_kel, verify_event_crypto, verify_event_said,
};

#[cfg(feature = "cesr")]
pub use codec::{CesrCodec, CesrV1Codec, DecodedPrimitive, DigestType, KeyType, SigType};
#[cfg(feature = "cesr")]
pub use event::{SerializedEvent, decode_cesr_key, serialize_for_cesr};
#[cfg(feature = "cesr")]
pub use roundtrip::{export_kel_as_cesr, import_cesr_to_events};
#[cfg(feature = "cesr")]
pub use stream::{AttachmentGroup, CesrStream, assemble_cesr_stream};
#[cfg(feature = "cesr")]
pub use version::compute_version_string;
