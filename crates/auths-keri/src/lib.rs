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
//! use auths_keri::{Prefix, Said, compute_said, compute_spec_said};
//!
//! let said = compute_said(event_bytes);
//! let spec_said = compute_spec_said(&event_json)?;
//! ```
//!
//! Usage (with CESR feature):
//! ```ignore
//! use auths_keri::{CesrV1Codec, export_kel_as_cesr};
//!
//! let codec = CesrV1Codec::new();
//! let cesr_stream = export_kel_as_cesr(&codec, &events)?;
//! ```

mod crypto;
mod error;
mod events;
pub mod kel_io;
mod keys;
mod said;
mod state;
mod types;
mod validate;
/// Witness protocol types: receipts, providers, and error reporting for split-view defense.
pub mod witness;

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

pub use crypto::{compute_next_commitment, compute_said, verify_commitment};
pub use error::KeriTranslationError;
pub use events::{Event, IcpEvent, IxnEvent, KERI_VERSION, KeriSequence, RotEvent, Seal, SealType};
pub use keys::{KeriDecodeError, KeriPublicKey};
pub use said::{SAID_PLACEHOLDER, compute_spec_said, verify_spec_said};
pub use state::KeyState;
pub use types::{KeriTypeError, Prefix, Said};
pub use validate::{
    ValidationError, compute_event_said, finalize_icp_event, find_seal_in_kel, parse_kel_json,
    replay_kel, serialize_for_signing, validate_for_append, validate_kel, verify_event_crypto,
    verify_event_said,
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
