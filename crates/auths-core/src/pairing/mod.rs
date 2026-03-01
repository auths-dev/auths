//! Pairing protocol for cross-device identity linking.
//!
//! This module implements a secure pairing protocol that allows users to link
//! multiple devices to the same identity. The protocol uses X25519 ECDH key
//! exchange with Ed25519 signature binding to ensure secure device authentication
//! and forward secrecy.
//!
//! # Protocol Flow
//!
//! 1. **Initiating device** generates a `PairingToken` with:
//!    - Controller DID (identity of the initiator)
//!    - X25519 ephemeral public key
//!    - Alphanumeric short code (6-char, no ambiguous chars)
//!    - Capabilities to grant
//!    - 5-minute expiry
//!
//! 2. **Initiating device** displays the token as:
//!    - QR code (preferred)
//!    - Alphanumeric short code (fallback)
//!
//! 3. **Responding device** scans/enters the token and creates a `PairingResponse`:
//!    - Generates its own X25519 ephemeral key
//!    - Performs ECDH with initiator's key → shared secret
//!    - Signs binding message (short_code || initiator_x25519 || device_x25519)
//!    - Includes its Ed25519 public key and DID
//!
//! 4. **Initiating device** verifies the response and completes ECDH:
//!    - Verifies Ed25519 signature binding
//!    - Performs ECDH with responder's X25519 key → same shared secret
//!    - Creates device attestation
//!
//! # Example
//!
//! ```no_run
//! use auths_core::pairing::{PairingToken, PairingResponse, format_pairing_qr};
//!
//! // On initiating device
//! let mut session = PairingToken::generate(
//!     "did:keri:controller123".to_string(),
//!     "http://localhost:3000".to_string(),
//!     vec!["sign_commit".to_string()],
//! ).unwrap();
//! let display = format_pairing_qr(&session.token).unwrap();
//! print!("{}", display);
//!
//! // Get the URI for QR code
//! let uri = session.token.to_uri();
//! ```

mod error;
mod qr;
mod response;
mod token;
pub mod types;

pub use error::PairingError;
pub use qr::{QrOptions, format_pairing_qr, render_qr, render_qr_from_data};
pub use response::PairingResponse;
pub use token::{PairingSession, PairingToken, normalize_short_code};
pub use types::*;
