use thiserror::Error;

/// Errors during translation between Auths events and CESR streams.
#[derive(Debug, Error)]
pub enum KeriTranslationError {
    /// A cryptographic primitive could not be CESR-encoded.
    #[error("CESR encoding failed for {primitive_kind}: {detail}")]
    EncodingFailed {
        /// Which primitive type failed encoding.
        primitive_kind: &'static str,
        /// Details about the encoding failure.
        detail: String,
    },

    /// A CESR-encoded primitive could not be decoded.
    #[error("CESR decoding failed: {0}")]
    DecodingFailed(String),

    /// JSON serialization or canonicalization failed.
    #[error("JSON serialization failed: {0}")]
    SerializationFailed(#[from] serde_json::Error),

    /// SAID computation produced a value inconsistent with the event.
    #[error("SAID mismatch: computed {computed}, found {found}")]
    SaidMismatch {
        /// The SAID computed from the event body.
        computed: String,
        /// The SAID found in the event's `d` field.
        found: String,
    },

    /// The version string could not be computed.
    #[error("version string error: {0}")]
    VersionStringError(String),

    /// An event is missing required fields for CESR export.
    #[error("event missing required field '{field}' for CESR export")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// A signature could not be parsed from the internal format.
    #[error("signature parse error: {0}")]
    SignatureParseError(String),

    /// Round-trip validation failed.
    #[error("round-trip validation failed at event sequence {sequence}: {detail}")]
    RoundTripFailed {
        /// The event sequence number where the failure occurred.
        sequence: u64,
        /// Details about the round-trip failure.
        detail: String,
    },
}
