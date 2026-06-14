//! TLS channel binding for session proofs (anti-relay).
//!
//! A pairing session runs *inside* a TLS connection, but the cryptographic
//! proofs it carries (the AEAD-sealed [`crate::envelope::Envelope`]s) are, by
//! themselves, transport-agnostic: a proof captured on one TLS connection and
//! replayed onto a *different* TLS connection would still open, because nothing
//! ties the proof to the channel it was minted on. That is the classic
//! relay / MITM attack — an attacker terminates the victim's TLS session,
//! lifts a valid proof off it, and presents it on its own session to a
//! third party.
//!
//! The fix is **channel binding**: fold a per-connection secret that *only the
//! two TLS endpoints know* into the proof, so a proof minted on channel A
//! cannot be opened on channel B. The secret is the **TLS exporter** —
//! exported keying material per RFC 5705 (TLS ≤1.2) / RFC 8446 §7.5 (TLS 1.3),
//! using the RFC 9266 `tls-exporter` label. Both endpoints of a TLS connection
//! derive the *same* exporter value; two independent connections derive
//! *different* values. Folding it into the envelope key (and AAD) makes the
//! proof open only on the channel that minted it. This is the same shape as
//! token-binding (RFC 8471) and DPoP (RFC 9449): a possession proof scoped to
//! its transport.
//!
//! # Wire / interop parameters (NORMATIVE)
//!
//! - **Label:** [`TLS_EXPORTER_LABEL`] = `EXPORTER-Channel-Binding` (RFC 9266
//!   §3). This is the registered label a stock TLS stack uses for the
//!   `tls-exporter` channel binding; matching it byte-for-byte is what lets an
//!   auths endpoint interoperate with any RFC 9266 peer.
//! - **Context:** *absent* (not empty). RFC 5705 distinguishes an absent
//!   context from a zero-length one; RFC 9266 specifies the exporter with no
//!   context value, so the adapter MUST pass "no context", not `b""`.
//! - **Length:** [`TLS_EXPORTER_LEN`] = 32 bytes.
//!
//! # Ports and adapters
//!
//! This crate is transport-agnostic (no TLS stack dependency). The act of
//! *extracting* the exporter from a live connection is therefore a **port**:
//! [`ChannelBindingProvider`]. The TLS-aware crates (the pairing daemon, the
//! CLI LAN server, the mobile client) implement it as a thin **adapter** over
//! their concrete stack's `export_keying_material` — `rustls`'s
//! `ConnectionCommon::export_keying_material`, OpenSSL's
//! `SslRef::export_keying_material`, Go's `ConnectionState.ExportKeyingMaterial`.
//! The core protocol only ever sees a parsed [`ChannelBinding`].

use zeroize::{Zeroize, Zeroizing};

/// RFC 9266 §3 exporter label for the `tls-exporter` channel binding.
///
/// A stock TLS stack producing a `tls-exporter` channel binding exports keying
/// material under exactly this label. Byte-identical use here is what makes an
/// auths endpoint's binding match an arbitrary RFC 9266 peer's.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Length, in bytes, of the exported keying material used as the binding.
///
/// 32 bytes = 256 bits, matching the suite's TLS oracle and leaving no
/// shortfall against the AEAD key it is folded into.
pub const TLS_EXPORTER_LEN: usize = 32;

/// HKDF `info` domain separator for folding a channel binding into a derived
/// key. Distinct from every other label in [`crate::domain_separation`] so a
/// channel-bound key can never collide with an unbound one.
pub const CHANNEL_BINDING_INFO: &[u8] = b"auths-pairing-channel-binding-v1";

/// Errors from parsing a channel binding or extracting one from a transport.
#[derive(Debug, thiserror::Error)]
pub enum ChannelBindingError {
    /// The exporter material was not exactly [`TLS_EXPORTER_LEN`] bytes.
    #[error("channel binding must be {expected} bytes of TLS exporter material, got {got}")]
    WrongLength {
        /// Required length ([`TLS_EXPORTER_LEN`]).
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },

    /// The underlying TLS stack refused to export keying material (no
    /// handshake completed, the connection is not TLS 1.3-capable, or the
    /// exporter is otherwise unavailable). A session that cannot produce a
    /// binding MUST NOT fall back to an unbound proof — that would silently
    /// reopen the relay hole. Surface this and refuse.
    #[error("TLS exporter unavailable from transport: {0}")]
    ExporterUnavailable(String),
}

/// A parsed TLS channel binding: the RFC 9266 `tls-exporter` keying material
/// for one connection.
///
/// Parse, don't validate: the only way to hold a `ChannelBinding` is through
/// [`ChannelBinding::from_exporter`], which enforces the length. Downstream
/// code (the envelope key derivation) can therefore trust the bytes without
/// re-checking. Two `ChannelBinding`s compare equal iff their exporter bytes
/// match — i.e. iff they came from the *same* TLS connection. The comparison
/// is constant-time so a relay attacker learns nothing from timing.
#[derive(Clone)]
pub struct ChannelBinding {
    exporter: Zeroizing<[u8; TLS_EXPORTER_LEN]>,
}

impl ChannelBinding {
    /// Parse raw TLS exporter material into a channel binding.
    ///
    /// `material` MUST be the keying material a TLS stack exported under
    /// [`TLS_EXPORTER_LABEL`] with an *absent* context and length
    /// [`TLS_EXPORTER_LEN`] — see the module docs for the normative
    /// parameters. Any other length is rejected so an invalid binding is
    /// unrepresentable past this boundary.
    pub fn from_exporter(material: &[u8]) -> Result<Self, ChannelBindingError> {
        if material.len() != TLS_EXPORTER_LEN {
            return Err(ChannelBindingError::WrongLength {
                expected: TLS_EXPORTER_LEN,
                got: material.len(),
            });
        }
        let mut buf = [0u8; TLS_EXPORTER_LEN];
        buf.copy_from_slice(material);
        let cb = Self {
            exporter: Zeroizing::new(buf),
        };
        buf.zeroize();
        Ok(cb)
    }

    /// The raw exporter bytes, for folding into a key derivation as HKDF
    /// `info`-adjacent material. Not part of any serialized wire format — the
    /// binding never travels; each endpoint recomputes it from its own TLS
    /// connection.
    pub fn as_bytes(&self) -> &[u8; TLS_EXPORTER_LEN] {
        &self.exporter
    }
}

// Manual `Debug` that redacts the exporter. The value is a per-connection
// secret; logging it would hand a relay attacker the binding it needs to
// recompute.
impl std::fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelBinding")
            .field(
                "exporter",
                &format_args!("<{TLS_EXPORTER_LEN} bytes redacted>"),
            )
            .finish()
    }
}

/// Constant-time equality: equal iff the two bindings come from the same TLS
/// connection. Constant-time so a relay attacker probing "is my forged binding
/// close to the real one?" learns nothing from response timing.
impl PartialEq for ChannelBinding {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.exporter.ct_eq(other.exporter.as_ref()).into()
    }
}

impl Eq for ChannelBinding {}

/// Port: extract the channel binding from a live transport.
///
/// Implemented by the TLS-aware crates as an adapter over their concrete
/// stack. The core protocol depends only on this trait, never on a TLS
/// library — ports and adapters at the transport edge.
///
/// The adapter MUST call its stack's keying-material exporter with
/// [`TLS_EXPORTER_LABEL`], an *absent* context, and length
/// [`TLS_EXPORTER_LEN`], then hand the bytes to
/// [`ChannelBinding::from_exporter`]. An adapter that cannot produce a binding
/// (handshake incomplete, not TLS 1.3) MUST return
/// [`ChannelBindingError::ExporterUnavailable`] — never a placeholder — so the
/// caller fails closed instead of minting an unbound, relay-able proof.
pub trait ChannelBindingProvider {
    /// The current connection's RFC 9266 channel binding.
    fn channel_binding(&self) -> Result<ChannelBinding, ChannelBindingError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_length() {
        let err = ChannelBinding::from_exporter(&[0u8; 16]).unwrap_err();
        assert!(matches!(
            err,
            ChannelBindingError::WrongLength {
                expected: TLS_EXPORTER_LEN,
                got: 16
            }
        ));
    }

    #[test]
    fn same_exporter_is_equal() {
        let a = ChannelBinding::from_exporter(&[0x11; TLS_EXPORTER_LEN]).unwrap();
        let b = ChannelBinding::from_exporter(&[0x11; TLS_EXPORTER_LEN]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_exporter_is_unequal() {
        // Two TLS connections export different keying material → distinct
        // bindings. This is the property the anti-relay check rests on.
        let a = ChannelBinding::from_exporter(&[0x11; TLS_EXPORTER_LEN]).unwrap();
        let b = ChannelBinding::from_exporter(&[0x22; TLS_EXPORTER_LEN]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn label_is_the_rfc9266_registered_value() {
        // Lock the wire label: a drift here silently breaks interop with every
        // stock TLS stack producing a `tls-exporter` binding.
        assert_eq!(TLS_EXPORTER_LABEL, b"EXPORTER-Channel-Binding");
        assert_eq!(TLS_EXPORTER_LEN, 32);
    }

    #[test]
    fn debug_redacts_exporter() {
        let cb = ChannelBinding::from_exporter(&[0xAB; TLS_EXPORTER_LEN]).unwrap();
        let s = format!("{cb:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("ab"));
        assert!(!s.contains("AB"));
    }
}
