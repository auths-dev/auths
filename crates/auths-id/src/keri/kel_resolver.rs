//! Transport-agnostic KEL resolution.
//!
//! A [`KelResolver`] yields a `did:keri:`'s raw KEL events (sequence 0 onward)
//! from some source — the local registry today; a git remote or HTTP/OOBI
//! endpoint in later tasks. The caller (the commit verifier) replays the
//! returned events itself: a device KEL is `dip`-rooted and needs a delegator
//! lookup, so this layer deliberately does **not** replay.
//!
//! Every resolver MUST enforce [`verify_prefix_binding`] — the resolved
//! inception event's self-addressing SAID must equal the requested prefix. This
//! is the transport tamper-detection seam: a source that serves a *different*
//! identity's KEL under the requested DID is rejected with
//! [`KelResolveError::PrefixMismatch`], distinctly from "not found". The guard
//! re-derives the SAID rather than trusting the event's stored `i` field, which
//! a malicious source could forge.

use std::ops::ControlFlow;

use super::Event;
use super::compute_event_said;
use super::resolve::parse_did_keri;
use super::types::Prefix;
use crate::ports::registry::{RegistryBackend, RegistryError};

/// Errors a [`KelResolver`] can return.
///
/// Transport-agnostic; richer transport variants (network, oversized, rollback,
/// duplicity) are layered on by the SDK resolver orchestration in a later task.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KelResolveError {
    /// The identifier is not a `did:keri:` string.
    #[error("'{0}' is not a did:keri identifier")]
    InvalidDid(String),

    /// No KEL is available for the requested identifier.
    #[error("KEL not found for {0}")]
    NotFound(String),

    /// The resolved KEL's inception SAID does not match the requested prefix —
    /// the source served a *different* identity's KEL (tamper / substitution).
    #[error(
        "resolved KEL is for a different identity: requested {requested}, derived {derived}"
    )]
    PrefixMismatch {
        /// The prefix the caller asked for.
        requested: String,
        /// The prefix actually derived from the resolved inception event.
        derived: String,
    },

    /// The resolved events could not be processed (serialization / SAID derivation).
    #[error("KEL processing failed: {0}")]
    Replay(String),

    /// A remote transport (git fetch / HTTP) failed to reach or read the source.
    #[error("could not reach the remote KEL source: {0}")]
    Network(String),

    /// The resolved KEL exceeds a configured size bound (DoS guard).
    #[error("resolved KEL exceeds the size bound: {0}")]
    Oversized(String),

    /// The resolved KEL is missing its inception (seq 0) — a truncated fetch.
    #[error("resolved KEL is truncated (inception missing)")]
    Truncated,

    /// A remote served a KEL strictly older than the locally-trusted state — a
    /// rollback / withholding attempt. Local trust is never overridden by an
    /// older remote.
    #[error(
        "remote KEL is older than the locally-trusted state (rollback): \
         local tip seq {local_tip}, remote tip seq {remote_tip}"
    )]
    Rollback {
        /// The locally-trusted tip sequence.
        local_tip: u128,
        /// The (rejected) remote tip sequence.
        remote_tip: u128,
    },

    /// The underlying source (registry/transport) failed.
    #[error("KEL source error: {0}")]
    Backend(String),
}

/// Resolves a `did:keri:` to its raw KEL events (no replay).
///
/// Args:
/// * `did`: The `did:keri:` identifier to resolve.
///
/// Usage:
/// ```ignore
/// let events = resolver.resolve_kel("did:keri:E...")?;
/// ```
pub trait KelResolver {
    /// Resolve the full KEL (from sequence 0) for `did`, enforcing the
    /// prefix-binding guard.
    fn resolve_kel(&self, did: &str) -> Result<Vec<Event>, KelResolveError>;
}

/// Collect a prefix's full KEL from a [`RegistryBackend`] (every event from
/// sequence 0).
///
/// Maps a not-found backend error *or* an empty chain to
/// [`KelResolveError::NotFound`]; any other backend failure to
/// [`KelResolveError::Backend`]. Backends differ on which they return for an
/// unknown identity, so both are normalized here.
///
/// Args:
/// * `registry`: The backend to read from.
/// * `prefix`: The identifier prefix.
///
/// Usage:
/// ```ignore
/// let events = collect_kel(&registry, &prefix)?;
/// ```
pub fn collect_kel(
    registry: &dyn RegistryBackend,
    prefix: &Prefix,
) -> Result<Vec<Event>, KelResolveError> {
    let mut events = Vec::new();
    match registry.visit_events(prefix, 0, &mut |event| {
        events.push(event.clone());
        ControlFlow::Continue(())
    }) {
        Ok(()) => {}
        Err(RegistryError::NotFound { .. }) => {
            return Err(KelResolveError::NotFound(format!("did:keri:{prefix}")));
        }
        Err(e) => return Err(KelResolveError::Backend(e.to_string())),
    }
    if events.is_empty() {
        return Err(KelResolveError::NotFound(format!("did:keri:{prefix}")));
    }
    Ok(events)
}

/// The prefix-binding guard: re-derive the inception event's self-addressing
/// SAID and require it to equal `prefix`.
///
/// This is the transport tamper-detection check every resolver runs. It
/// re-derives the SAID via [`compute_event_said`] (which blanks `i` for
/// `icp`/`dip`) rather than trusting the event's stored `i` field — so a source
/// serving a forged-`i` or wholly substituted KEL is caught here, distinctly
/// from a "not found".
///
/// Args:
/// * `prefix`: The requested identifier prefix.
/// * `events`: The resolved KEL (the first event must be the inception).
///
/// Usage:
/// ```ignore
/// verify_prefix_binding(&prefix, &events)?;
/// ```
pub fn verify_prefix_binding(prefix: &Prefix, events: &[Event]) -> Result<(), KelResolveError> {
    let Some(inception) = events.first() else {
        return Err(KelResolveError::NotFound(format!("did:keri:{prefix}")));
    };
    let derived =
        compute_event_said(inception).map_err(|e| KelResolveError::Replay(e.to_string()))?;
    if derived.as_str() != prefix.as_str() {
        return Err(KelResolveError::PrefixMismatch {
            requested: prefix.as_str().to_string(),
            derived: derived.as_str().to_string(),
        });
    }
    Ok(())
}

/// A [`KelResolver`] backed by a local [`RegistryBackend`] — the packed registry
/// the verifier already reads (`refs/auths/registry`).
///
/// Reuses `visit_events` and adds the prefix-binding guard, so the local path
/// gets the same tamper-detection a remote path needs.
pub struct LocalKelResolver<'a> {
    registry: &'a dyn RegistryBackend,
}

impl<'a> LocalKelResolver<'a> {
    /// Wrap a registry backend as a local KEL resolver.
    ///
    /// Args:
    /// * `registry`: The backend holding the identities' KELs.
    ///
    /// Usage:
    /// ```ignore
    /// let resolver = LocalKelResolver::new(&registry);
    /// ```
    pub fn new(registry: &'a dyn RegistryBackend) -> Self {
        Self { registry }
    }
}

impl KelResolver for LocalKelResolver<'_> {
    fn resolve_kel(&self, did: &str) -> Result<Vec<Event>, KelResolveError> {
        let prefix =
            parse_did_keri(did).map_err(|_| KelResolveError::InvalidDid(did.to_string()))?;
        let events = collect_kel(self.registry, &prefix)?;
        verify_prefix_binding(&prefix, &events)?;
        Ok(events)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{KelResolveError, KelResolver, LocalKelResolver, verify_prefix_binding};
    use auths_keri::{
        CesrKey, Event, IcpEvent, IcpEventInit, KeriPublicKey, KeriSequence, Prefix, Said,
        Threshold, VersionString, compute_next_commitment, finalize_icp_event,
    };

    fn cesr(pk: &KeriPublicKey) -> CesrKey {
        CesrKey::new_unchecked(pk.to_qb64().expect("qb64"))
    }

    fn dummy_key(seed: u8) -> KeriPublicKey {
        KeriPublicKey::ed25519(&[seed; 32]).expect("ed25519")
    }

    /// A finalized inception event (its `d`/`i` are the self-addressing SAID).
    fn icp_event() -> IcpEvent {
        finalize_icp_event(IcpEvent::new(IcpEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![cesr(&dummy_key(1))],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&dummy_key(2))],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        }))
        .expect("icp")
    }

    #[test]
    fn prefix_binding_accepts_matching_prefix() {
        let icp = icp_event();
        let prefix = icp.i.clone();
        let events = vec![Event::Icp(icp)];
        assert!(verify_prefix_binding(&prefix, &events).is_ok());
    }

    #[test]
    fn prefix_binding_rejects_substituted_kel() {
        let icp = icp_event();
        let wrong = Prefix::new_unchecked("ENotTheRightPrefixAtAll0000000000000000000000".to_string());
        let events = vec![Event::Icp(icp)];
        let err = verify_prefix_binding(&wrong, &events).unwrap_err();
        assert!(matches!(err, KelResolveError::PrefixMismatch { .. }));
    }

    #[test]
    fn prefix_binding_rejects_empty_kel() {
        let prefix = Prefix::new_unchecked("EwhateverPrefix000000000000000000000000000000".to_string());
        let err = verify_prefix_binding(&prefix, &[]).unwrap_err();
        assert!(matches!(err, KelResolveError::NotFound(_)));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn local_resolver_rejects_non_keri_did() {
        // The did is rejected before any lookup; a backend is only needed to
        // construct the resolver.
        let registry = crate::testing::fakes::FakeRegistryBackend::new();
        let resolver = LocalKelResolver::new(&registry);
        let err = resolver
            .resolve_kel("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .unwrap_err();
        assert!(matches!(err, KelResolveError::InvalidDid(_)));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn local_resolver_returns_known_kel() {
        use crate::ports::registry::RegistryBackend;
        let icp = icp_event();
        let prefix = icp.i.clone();
        let did = format!("did:keri:{prefix}");
        let event = Event::Icp(icp);

        let registry = crate::testing::fakes::FakeRegistryBackend::new();
        registry.append_event(&prefix, &event).expect("append");

        let resolver = LocalKelResolver::new(&registry);
        let events = resolver.resolve_kel(&did).expect("resolve");
        assert_eq!(events, vec![event]);
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn local_resolver_unknown_identity_is_not_found() {
        let registry = crate::testing::fakes::FakeRegistryBackend::new();
        let resolver = LocalKelResolver::new(&registry);
        let err = resolver
            .resolve_kel("did:keri:ENeverWasInTheRegistry00000000000000000000000")
            .unwrap_err();
        assert!(matches!(err, KelResolveError::NotFound(_)));
    }
}
