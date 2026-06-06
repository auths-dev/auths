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
        sequence: u128,
        /// Details about the round-trip failure.
        detail: String,
    },
}

/// Errors raised while constructing, SAID-ifying, or validating a backerless TEL.
///
/// A Transaction Event Log (TEL) is the KERI-native credential-status registry.
/// These variants are distinct so a verifier can react to *why* a chain is
/// invalid (a missing inception vs. a broken back-link vs. a tampered SAID)
/// rather than collapsing every failure into one opaque rejection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TelError {
    /// A `rev` event referenced a credential that was never issued in this TEL.
    #[error("revocation references credential {credential} that was never issued")]
    RevWithoutIss {
        /// The credential SAID the `rev` event names.
        credential: String,
    },

    /// An `iss` event named a registry that was not inceptioned by a leading `vcp`.
    #[error("issuance references registry {registry} with no matching vcp inception")]
    IssWithoutRegistry {
        /// The registry SAID the `iss` event names.
        registry: String,
    },

    /// The same credential was issued twice in one TEL.
    #[error("credential {credential} issued more than once")]
    DoubleIss {
        /// The doubly-issued credential SAID.
        credential: String,
    },

    /// The same credential was revoked twice in one TEL.
    #[error("credential {credential} revoked more than once")]
    DoubleRev {
        /// The doubly-revoked credential SAID.
        credential: String,
    },

    /// The prior-event back-link (`p`) or the monotonic sequence (`s`) is broken.
    #[error("broken TEL chain for credential {credential}: {detail}")]
    BrokenChain {
        /// The credential SAID whose chain is broken.
        credential: String,
        /// Why the chain is broken (bad `p` back-link or non-monotonic `s`).
        detail: String,
    },

    /// A TEL event's carried `d` SAID does not match a fresh recomputation.
    #[error("TEL {event_type} SAID mismatch: computed {computed}, found {found}")]
    SaidMismatch {
        /// Which TEL event type mismatched (`vcp`/`iss`/`rev`).
        event_type: &'static str,
        /// The SAID recomputed from the event body.
        computed: String,
        /// The SAID carried in the event's `d` field.
        found: String,
    },

    /// A TEL event body could not be (de)serialized or SAID-ified.
    #[error("TEL SAID computation failed: {0}")]
    Said(String),

    /// The TEL was empty or did not begin with a `vcp` registry inception.
    #[error("TEL must begin with a vcp registry inception")]
    MissingInception,
}

impl From<KeriTranslationError> for TelError {
    fn from(e: KeriTranslationError) -> Self {
        TelError::Said(e.to_string())
    }
}

impl From<serde_json::Error> for TelError {
    fn from(e: serde_json::Error) -> Self {
        TelError::Said(e.to_string())
    }
}
