//! Pairing protocol facade — re-exports from `auths-pairing-protocol`
//! plus transport-specific QR rendering and error types.

mod error;
mod qr;

// Re-export protocol types
pub use auths_pairing_protocol::types;
pub use auths_pairing_protocol::{
    Base64UrlEncoded, CreateSessionRequest, CreateSessionResponse, GetSessionResponse,
    PairingResponse, PairingSession, PairingToken, ProtocolError, SessionStatus,
    SubmitResponseRequest, SuccessResponse, normalize_short_code,
};

// Local exports
pub use error::PairingError;
pub use qr::{QrOptions, format_pairing_qr, render_qr, render_qr_from_data};
