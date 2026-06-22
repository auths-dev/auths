//! Verified principal + denial mapping.
//!
//! Turns a shipped `auths_verifier::PresentationVerdict` into a [`VerifiedPrincipal`] —
//! constructible ONLY from a `Valid` verdict, so *possessing one is proof* of current key
//! control. Authorization yields a [`Grant`] (a capability proof), never a bool. Every
//! non-`Valid` verdict maps to a typed [`Denied`] with the correct HTTP class: 401 for
//! authentication failures, 403 for insufficient capability.
//!
//! The actual `verify_presentation` call lives in the server consumer (which holds the
//! crypto provider + the loaded KELs); this module owns only the verdict → principal mapping
//! and the authorization decision, so it stays free of KEL/provider/HTTP dependencies.

use std::collections::HashSet;

use auths_verifier::{CanonicalDid, Capability, Freshness, PresentationVerdict};

/// A principal obtainable ONLY from a successful presentation verdict.
///
/// There is no public constructor other than [`VerifiedPrincipal::from_verdict`]; holding a
/// `VerifiedPrincipal` therefore proves the holder cryptographically demonstrated current
/// control of the subject AID's key. Subject + capabilities are parsed into the shipped
/// `auths_verifier` domain types at this boundary (no stringly-typed authority downstream).
#[derive(Debug, Clone)]
pub struct VerifiedPrincipal {
    subject: CanonicalDid,
    capabilities: HashSet<Capability>,
    freshness: Freshness,
}

impl VerifiedPrincipal {
    /// Parse the SHIPPED `PresentationVerdict` into a proof or a typed [`Denied`].
    ///
    /// Every non-`Valid` arm is mapped explicitly (no `_ =>` catch-all) so a new upstream
    /// verdict variant fails to compile until handled here. The `Valid` arm re-parses the
    /// verdict's `subject`/`caps` strings into `CanonicalDid`/`Capability`; once the shipped
    /// verdict carries those types directly (the recorded upstream-tightening decision), the
    /// re-parse collapses to a move.
    ///
    /// Args:
    /// * `verdict`: The outcome of `auths_verifier::verify_presentation`.
    pub fn from_verdict(verdict: PresentationVerdict) -> Result<Self, Denied> {
        match verdict {
            // The verifier already parsed `subject`/`caps` into their typed forms (fn-153.2),
            // so the verdict carries validated values — move them through with no re-parse and
            // no silent capability drop. A malformed cap now fails the verdict in the verifier.
            PresentationVerdict::Valid {
                subject,
                caps,
                freshness,
                ..
            } => Ok(Self {
                subject,
                capabilities: caps.into_iter().collect(),
                freshness,
            }),
            PresentationVerdict::WrongAudience => Err(Denied::WrongAudience),
            PresentationVerdict::NonceMismatchOrConsumed => Err(Denied::Replayed),
            PresentationVerdict::Expired => Err(Denied::Expired),
            PresentationVerdict::HolderNotCurrentKey => Err(Denied::NotCurrentKey),
            PresentationVerdict::SubjectKelInvalid => Err(Denied::SubjectKelInvalid),
            PresentationVerdict::CredentialNotValid(_) => Err(Denied::CredentialInvalid),
        }
    }

    /// The verified subject (holder) identity.
    pub fn subject(&self) -> &CanonicalDid {
        &self.subject
    }

    /// The capabilities the presentation granted.
    pub fn capabilities(&self) -> &HashSet<Capability> {
        &self.capabilities
    }

    /// The freshness of the honored verdict that produced this principal (ADR 009).
    ///
    /// The presentation cleared the relying party's freshness policy to become a principal, but
    /// the *grade* is surfaced here so a caller can tell a [`Freshness::Fresh`] principal from a
    /// (policy-tolerated) [`Freshness::Unknown`] one and, e.g., demand re-presentation for a
    /// high-stakes action. It is never a bare honored verdict.
    pub fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// Authorize a required capability, yielding a [`Grant`] proof (never a bool).
    ///
    /// Args:
    /// * `needed`: The capability the route/tool requires.
    pub fn authorize(&self, needed: &Capability) -> Result<Grant, Denied> {
        if self.capabilities.contains(needed) {
            Ok(Grant {
                subject: self.subject.clone(),
                exercised: needed.clone(),
            })
        } else {
            Err(Denied::MissingCapability {
                needed: needed.clone(),
            })
        }
    }
}

/// Proof that `subject` was authorized to exercise `exercised`. A handler that requires a
/// `Grant` to act cannot be reached on an un-authorized path.
#[derive(Debug, Clone)]
pub struct Grant {
    subject: CanonicalDid,
    exercised: Capability,
}

impl Grant {
    /// The authorized subject.
    pub fn subject(&self) -> &CanonicalDid {
        &self.subject
    }

    /// The capability exercised.
    pub fn exercised(&self) -> &Capability {
        &self.exercised
    }
}

/// Closed denial set — the HTTP layer maps each arm to a status class exhaustively.
///
/// Authentication failures are 401; an authenticated principal lacking a capability is 403.
/// Callers should surface a coarse status externally and keep the specific arm in logs.
#[derive(Debug, thiserror::Error)]
pub enum Denied {
    /// The presentation was bound to a different audience than the server's.
    #[error("presentation bound to a different audience")]
    WrongAudience,
    /// The challenge nonce was replayed or already consumed.
    #[error("challenge replayed or already consumed")]
    Replayed,
    /// The non-interactive presentation has expired.
    #[error("presentation expired")]
    Expired,
    /// The presenter does not control the subject AID's current key.
    #[error("presenter does not control the subject's current key")]
    NotCurrentKey,
    /// The subject KEL was missing, forked, or invalid.
    #[error("subject KEL invalid or unresolvable")]
    SubjectKelInvalid,
    /// The presented credential itself was not valid (revoked, expired, unanchored, …).
    #[error("credential not valid")]
    CredentialInvalid,
    /// The principal lacks the capability the route/tool requires (403, not 401).
    #[error("missing capability: {needed:?}")]
    MissingCapability {
        /// The capability the action required.
        needed: Capability,
    },
}

impl Denied {
    /// The HTTP status class: 403 for an authenticated-but-insufficient principal, else 401.
    pub fn http_status(&self) -> u16 {
        match self {
            Denied::MissingCapability { .. } => 403,
            Denied::WrongAudience
            | Denied::Replayed
            | Denied::Expired
            | Denied::NotCurrentKey
            | Denied::SubjectKelInvalid
            | Denied::CredentialInvalid => 401,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_verifier::IdentityDID;

    use super::*;

    fn valid_verdict(subject: &str, caps: &[&str]) -> PresentationVerdict {
        PresentationVerdict::Valid {
            issuer: IdentityDID::parse("did:keri:Eissuer").expect("valid test issuer"),
            subject: CanonicalDid::parse(subject).expect("valid test subject"),
            caps: caps
                .iter()
                .map(|c| Capability::parse(c).expect("valid test capability"))
                .collect(),
            role: None,
            expires_at: None,
            freshness: Freshness::Unknown,
        }
    }

    #[test]
    fn principal_surfaces_the_verdict_freshness() {
        let fresh = PresentationVerdict::Valid {
            issuer: IdentityDID::parse("did:keri:Eissuer").expect("issuer"),
            subject: CanonicalDid::parse("did:keri:Eagent").expect("subject"),
            caps: vec![],
            role: None,
            expires_at: None,
            freshness: Freshness::Fresh,
        };
        assert_eq!(
            VerifiedPrincipal::from_verdict(fresh).unwrap().freshness(),
            Freshness::Fresh
        );
        assert_eq!(
            VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &[]))
                .unwrap()
                .freshness(),
            Freshness::Unknown,
            "an offline-resolved honored verdict surfaces Unknown, distinguishable from Fresh"
        );
    }

    #[test]
    fn valid_verdict_yields_principal_and_grant() {
        let principal =
            VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &["acme:read"]))
                .expect("valid verdict -> principal");
        assert_eq!(principal.subject().as_str(), "did:keri:Eagent");

        let read = Capability::parse("acme:read").unwrap();
        let grant = principal.authorize(&read).expect("authorized for held cap");
        assert_eq!(grant.exercised().as_str(), "acme:read");

        let write = Capability::parse("acme:write").unwrap();
        match principal.authorize(&write) {
            Err(Denied::MissingCapability { needed }) => {
                assert_eq!(needed.as_str(), "acme:write")
            }
            other => panic!("expected MissingCapability, got {other:?}"),
        }
    }

    #[test]
    fn missing_capability_is_403_others_401() {
        let principal =
            VerifiedPrincipal::from_verdict(valid_verdict("did:keri:Eagent", &["acme:read"]))
                .unwrap();
        let denied = principal
            .authorize(&Capability::parse("acme:write").unwrap())
            .unwrap_err();
        assert_eq!(denied.http_status(), 403);

        for verdict in [
            PresentationVerdict::WrongAudience,
            PresentationVerdict::NonceMismatchOrConsumed,
            PresentationVerdict::Expired,
            PresentationVerdict::HolderNotCurrentKey,
            PresentationVerdict::SubjectKelInvalid,
        ] {
            let denied = VerifiedPrincipal::from_verdict(verdict).unwrap_err();
            assert_eq!(denied.http_status(), 401);
        }
    }

    #[test]
    fn wrong_audience_and_replayed_map_correctly() {
        assert!(matches!(
            VerifiedPrincipal::from_verdict(PresentationVerdict::WrongAudience),
            Err(Denied::WrongAudience)
        ));
        assert!(matches!(
            VerifiedPrincipal::from_verdict(PresentationVerdict::NonceMismatchOrConsumed),
            Err(Denied::Replayed)
        ));
    }
}
