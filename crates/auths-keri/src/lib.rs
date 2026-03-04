#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
#![warn(missing_docs)]

//! KERI CESR translation layer for Auths.
//!
//! Provides bidirectional conversion between Auths' internal JSON event
//! representation and spec-compliant CESR streams (Trust over IP KERI v0.9).
//!
//! The core identity crates (`auths-id`, `auths-verifier`) are unchanged.
//! This crate wraps their types for export/import without replacing them.
//!
//! Usage:
//! ```ignore
//! use auths_keri::{CesrV1Codec, export_kel_as_cesr};
//!
//! let codec = CesrV1Codec::new();
//! let cesr_stream = export_kel_as_cesr(&codec, &events)?;
//! ```

mod codec;
mod error;
mod event;
mod roundtrip;
mod said;
mod stream;
mod version;

pub use codec::{CesrCodec, CesrV1Codec, DecodedPrimitive, DigestType, KeyType, SigType};
pub use error::KeriTranslationError;
pub use event::{SerializedEvent, decode_cesr_key, serialize_for_cesr};
pub use roundtrip::{export_kel_as_cesr, import_cesr_to_events};
pub use said::{compute_spec_said, verify_spec_said};
pub use stream::{AttachmentGroup, CesrStream, assemble_cesr_stream};
pub use version::compute_version_string;
