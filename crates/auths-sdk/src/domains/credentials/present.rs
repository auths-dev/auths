//! Credential presentation + holder-binding challenge issuance (Epic F.8).
//!
//! A credential's authority is honored only on proof of current control of the subject
//! AID — never on mere possession (bearer tokens are banned). This module is the SDK-
//! orchestrates side of F.8: the subject signs `(credential-SAID || audience || nonce)`
//! with its signing-time key to produce a [`PresentationEnvelope`], and the verifier-
//! side challenge is issued + consumed as **session-held state** ([`ChallengeSession`]).
//! The pure check lives in `auths_verifier::verify_presentation`; this module owns only
//! the signing orchestration and the one-shot challenge lifecycle.
//!
//! ## Challenge-response state model (the v1 default)
//!
//! The verifier issues a fresh random nonce that lives in a [`ChallengeSession`] it
//! holds privately — NOT a global seen-cache. The session binds the nonce to a single
//! `(audience, credential_said)` and exposes it exactly once: [`ChallengeSession::consume`]
//! returns the expected nonce and marks the session spent, so a replayed or second
//! presentation finds nothing to match against and is rejected by the pure verifier with
//! `NonceMismatchOrConsumed`. Because the nonce is held by the calling session and the
//! pure verifier is merely handed `Some(nonce)`, the verify path stays WASM-safe.

use auths_core::storage::keychain::{KeyAlias, sign_with_key};
use auths_verifier::{PresentationBinding, PresentationEnvelope};
use chrono::{DateTime, Utc};
use ring::rand::SecureRandom;

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;

/// The byte length of a verifier-issued / subject-chosen presentation nonce.
const NONCE_LEN: usize = 32;

/// A verifier-held, single-use challenge for the interactive presentation path.
///
/// Holds a fresh random nonce bound to one `(audience, credential_said)` as the
/// verifier's own ephemeral per-session state. It is consumed exactly once: after
/// [`ChallengeSession::consume`] the session yields `None`, so a replayed presentation
/// cannot be matched (the pure verifier rejects it with `NonceMismatchOrConsumed`).
#[derive(Debug, Clone)]
pub struct ChallengeSession {
    nonce: Vec<u8>,
    audience: String,
    credential_said: String,
    consumed: bool,
}

impl ChallengeSession {
    /// Issue a fresh single-use challenge bound to `(audience, credential_said)`.
    ///
    /// The nonce is drawn from the system CSPRNG; it is the verifier's ephemeral state,
    /// never persisted or shared across sessions.
    ///
    /// Args:
    /// * `audience`: The relying-party / verifier identifier the presentation must bind to.
    /// * `credential_said`: The credential SAID the challenge is scoped to.
    ///
    /// Usage:
    /// ```ignore
    /// let session = ChallengeSession::issue("audience.example", "ECred…")?;
    /// let nonce = session.nonce().to_vec();
    /// ```
    pub fn issue(audience: &str, credential_said: &str) -> Result<Self, CredentialError> {
        let mut nonce = vec![0u8; NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| CredentialError::SchemaUnknown)?;
        Ok(Self {
            nonce,
            audience: audience.to_string(),
            credential_said: credential_said.to_string(),
            consumed: false,
        })
    }

    /// The nonce to hand to the subject (so it can sign over it).
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The audience this challenge is bound to.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The credential SAID this challenge is scoped to.
    pub fn credential_said(&self) -> &str {
        &self.credential_said
    }

    /// Consume the challenge once, returning the expected nonce to hand the verifier.
    ///
    /// The first call returns `Some(nonce)` and marks the session spent; every later call
    /// returns `None`. Pass the result as `verify_presentation`'s `expected_challenge`:
    /// a `None` (already-consumed) makes any challenge-bound presentation fail with
    /// `NonceMismatchOrConsumed`, which is the one-shot replay protection.
    ///
    /// Usage:
    /// ```ignore
    /// if let Some(nonce) = session.consume() {
    ///     let verdict = verify_presentation(/* … */, Some(&nonce), now, &provider).await;
    /// }
    /// ```
    pub fn consume(&mut self) -> Option<Vec<u8>> {
        if self.consumed {
            return None;
        }
        self.consumed = true;
        Some(self.nonce.clone())
    }

    /// Whether the challenge has already been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

/// How the subject binds a presentation: a verifier challenge or a self-asserted TTL.
///
/// The interactive challenge is the v1 default and gives genuine single-use replay
/// protection. The TTL mode is for audiences where no challenge round-trip is possible;
/// it carries the within-TTL same-audience replay residual documented on
/// [`auths_verifier::PresentationBinding`].
#[derive(Debug, Clone)]
pub enum PresentationChallenge {
    /// Sign over the verifier-issued nonce (interactive, single-use).
    Challenge {
        /// The nonce the verifier handed out for this presentation.
        nonce: Vec<u8>,
    },
    /// Sign over a freshly drawn nonce bound to a short TTL (non-interactive).
    Ttl {
        /// The presentation's expiry (`now + ttl`), injected at the boundary.
        not_after: DateTime<Utc>,
    },
}

/// Present a credential by proving current control of the subject AID.
///
/// The subject signs `(credential-SAID || audience || nonce)` with the signing key under
/// `subject_alias` (its current signing-time key), producing a [`PresentationEnvelope`]
/// the pure `auths_verifier::verify_presentation` checks against the subject KEL. No raw
/// ACDC is ever handed downstream as authority — only this signed, audience-bound
/// envelope. The *how* of signing stays in `auths-core`; this only orchestrates.
///
/// Args:
/// * `ctx`: Auths context (key storage + passphrase provider for the subject signer).
/// * `subject_alias`: Keychain alias of the subject (holder) AID's current signing key.
/// * `credential_said`: The SAID (`acdc.d`) of the credential being presented.
/// * `audience`: The relying-party / verifier identifier the presentation binds to.
/// * `challenge`: The interactive verifier nonce, or a non-interactive TTL window.
///
/// Usage:
/// ```ignore
/// let envelope = present_credential(
///     &ctx, &subject_alias, "ECred…", "audience.example",
///     PresentationChallenge::Challenge { nonce: session.nonce().to_vec() },
/// )?;
/// ```
pub fn present_credential(
    ctx: &AuthsContext,
    subject_alias: &KeyAlias,
    credential_said: &str,
    audience: &str,
    challenge: PresentationChallenge,
) -> Result<PresentationEnvelope, CredentialError> {
    let binding = match challenge {
        PresentationChallenge::Challenge { nonce } => PresentationBinding::Challenge { nonce },
        PresentationChallenge::Ttl { not_after } => {
            let mut nonce = vec![0u8; NONCE_LEN];
            ring::rand::SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| CredentialError::SchemaUnknown)?;
            PresentationBinding::Ttl { nonce, not_after }
        }
    };

    let message = signed_message(credential_said, audience, binding_nonce(&binding));
    let (signature, _pk, _curve) = sign_with_key(
        ctx.key_storage.as_ref(),
        subject_alias,
        ctx.passphrase_provider.as_ref(),
        &message,
    )?;

    Ok(PresentationEnvelope {
        credential_said: credential_said.to_string(),
        audience: audience.to_string(),
        binding,
        signature,
    })
}

/// The nonce carried by a binding (challenge or TTL).
fn binding_nonce(binding: &PresentationBinding) -> &[u8] {
    match binding {
        PresentationBinding::Challenge { nonce } => nonce,
        PresentationBinding::Ttl { nonce, .. } => nonce,
    }
}

/// The canonical presentation message: `credential-SAID || NUL || audience || NUL || nonce`.
///
/// Mirrors the pure verifier's framing exactly so a subject-produced envelope verifies;
/// the NUL separators keep field boundaries unambiguous.
fn signed_message(credential_said: &str, audience: &str, nonce: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(credential_said.len() + audience.len() + nonce.len() + 2);
    message.extend_from_slice(credential_said.as_bytes());
    message.push(0);
    message.extend_from_slice(audience.as_bytes());
    message.push(0);
    message.extend_from_slice(nonce);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_session_consumes_once() {
        let mut session = ChallengeSession::issue("aud", "ECred").expect("issue challenge session");
        assert!(!session.is_consumed());
        let first = session.consume();
        assert!(first.is_some(), "first consume yields the nonce");
        assert!(session.is_consumed());
        assert!(
            session.consume().is_none(),
            "a consumed challenge yields nothing (one-shot)"
        );
    }

    #[test]
    fn issued_nonce_is_full_length_and_random() {
        let a = ChallengeSession::issue("aud", "ECred").unwrap();
        let b = ChallengeSession::issue("aud", "ECred").unwrap();
        assert_eq!(a.nonce().len(), NONCE_LEN);
        assert_ne!(a.nonce(), b.nonce(), "nonces must differ across sessions");
    }
}
