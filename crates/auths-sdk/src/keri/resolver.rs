//! KEL resolver orchestration — the seam the verifier resolves signer KELs
//! through.
//!
//! Resolution is **local-only**: the local registry is the trusted store, and a
//! KEL that is not local arrives in-band (a committed/explicit identity bundle,
//! authenticated via `validate_signed_kel` at its ingestion boundary) before it
//! ever reaches this chain. There is no network transport here — the removed
//! `--remote`/`--oobi` stranger feeds carried bare, unsigned events, which is
//! exactly the replay-by-structure hole the verify path bans (RT-002).
//!
//! Within a single stream, the non-fatal "warn, prefer local" duplicity signal
//! is surfaced downstream by `verify_commit_against_kel`'s `detect_duplicity`.
//! This layer sequences the read; `auths-id` implements the registry read and
//! the prefix-binding guard.

use auths_id::keri::{Event, KelResolveError, KelResolver, LocalKelResolver};
use auths_id::ports::registry::RegistryBackend;

/// Resolves a signer's KEL from the local registry, enforcing the
/// prefix-binding guard.
pub struct KelResolverChain<'a> {
    registry: &'a dyn RegistryBackend,
}

impl<'a> KelResolverChain<'a> {
    /// A local-only chain backed by the registry the verifier reads. No network.
    ///
    /// Args:
    /// * `registry`: The backend holding the identities' KELs.
    ///
    /// Usage:
    /// ```ignore
    /// let chain = KelResolverChain::local(&registry);
    /// ```
    pub fn local(registry: &'a dyn RegistryBackend) -> Self {
        Self { registry }
    }

    /// Resolve the full KEL for `did`, enforcing the prefix-binding guard.
    ///
    /// Args:
    /// * `did`: The `did:keri:` to resolve.
    pub fn resolve_kel(&self, did: &str) -> Result<Vec<Event>, KelResolveError> {
        LocalKelResolver::new(self.registry).resolve_kel(did)
    }
}

/// Failure resolving a DID's current signing key from its locally-replayed KEL.
#[derive(Debug, thiserror::Error)]
pub enum CurrentKeyError {
    /// The DID's KEL could not be resolved from the registry.
    #[error("KEL for {did} could not be resolved: {source}")]
    Resolve {
        /// The DID whose KEL was requested.
        did: String,
        /// The underlying resolver error.
        source: KelResolveError,
    },
    /// The resolved KEL failed replay validation.
    #[error("KEL for {did} failed validation: {reason}")]
    InvalidKel {
        /// The DID whose KEL failed validation.
        did: String,
        /// The validation failure, rendered for display.
        reason: String,
    },
    /// The replayed key state holds no current signing key (abandoned identity).
    #[error("KEL for {did} has no current signing key")]
    NoCurrentKey {
        /// The DID whose key state is empty.
        did: String,
    },
    /// The current key uses a CESR code this build cannot decode.
    #[error("current key for {did} could not be decoded: {reason}")]
    UnsupportedKey {
        /// The DID whose key could not be decoded.
        did: String,
        /// The decode failure, rendered for display.
        reason: String,
    },
}

/// Resolve a DID's *current* signing public key by replaying its KEL from the
/// local registry.
///
/// This is the self-trust primitive: a verifier resolving its own identity (or
/// any identity whose KEL the local registry holds) gets the post-rotation
/// current key, never a stale inception key. Local-only — no network.
///
/// Args:
/// * `registry`: The backend holding the identity's KEL.
/// * `did`: The `did:keri:` whose current key to resolve.
///
/// Usage:
/// ```ignore
/// let (pk_bytes, curve) = resolve_current_public_key(registry.as_ref(), &did)?;
/// ```
pub fn resolve_current_public_key(
    registry: &dyn RegistryBackend,
    did: &str,
) -> Result<(Vec<u8>, auths_crypto::CurveType), CurrentKeyError> {
    let kel = KelResolverChain::local(registry)
        .resolve_kel(did)
        .map_err(|source| CurrentKeyError::Resolve {
            did: did.to_string(),
            source,
        })?;
    // A delegated device's KEL opens with a `dip` whose validation needs the delegator
    // (root) KEL to confirm the anchoring seal — a plain `icp` root needs no lookup.
    // Resolve the delegator from the same registry and seed a seal-index lookup so the
    // device's own signing key state replays without the root having to co-sign.
    let delegator_kel = match kel.first() {
        Some(Event::Dip(dip)) => Some(
            KelResolverChain::local(registry)
                .resolve_kel(&format!("did:keri:{}", dip.di))
                .map_err(|source| CurrentKeyError::Resolve {
                    did: did.to_string(),
                    source,
                })?,
        ),
        _ => None,
    };
    let lookup = delegator_kel
        .as_deref()
        .map(auths_keri::KelSealIndex::from_events);
    let state = auths_keri::TrustedKel::from_trusted_source(&kel)
        .replay_with_lookup(
            lookup
                .as_ref()
                .map(|l| l as &dyn auths_keri::DelegatorKelLookup),
        )
        .map_err(|e| CurrentKeyError::InvalidKel {
            did: did.to_string(),
            reason: e.to_string(),
        })?;
    let key = state
        .current_key()
        .ok_or_else(|| CurrentKeyError::NoCurrentKey {
            did: did.to_string(),
        })?;
    let parsed = key.parse().map_err(|e| CurrentKeyError::UnsupportedKey {
        did: did.to_string(),
        reason: e.to_string(),
    })?;
    let (bytes, curve) = match parsed {
        auths_keri::KeriPublicKey::Ed25519 { key: pk, .. } => {
            (pk.to_vec(), auths_crypto::CurveType::Ed25519)
        }
        auths_keri::KeriPublicKey::P256 { key, .. } => {
            (key.to_vec(), auths_crypto::CurveType::P256)
        }
    };
    Ok((bytes, curve))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_id::testing::fakes::FakeRegistryBackend;
    use auths_keri::{
        CesrKey, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold, VersionString,
        compute_next_commitment, finalize_icp_event,
    };

    fn icp_and_prefix(seed: u8) -> (Event, Prefix) {
        let key = KeriPublicKey::ed25519(&[seed; 32]).unwrap();
        let next = KeriPublicKey::ed25519(&[seed.wrapping_add(1); 32]).unwrap();
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    #[test]
    fn local_only_resolves_from_local() {
        let (event, prefix) = icp_and_prefix(1);
        let did = format!("did:keri:{prefix}");
        let registry = FakeRegistryBackend::new();
        registry.append_event(&prefix, &event).unwrap();

        let chain = KelResolverChain::local(&registry);
        assert_eq!(chain.resolve_kel(&did).unwrap(), vec![event]);
    }

    #[test]
    fn local_only_unknown_is_not_found() {
        let registry = FakeRegistryBackend::new();
        let chain = KelResolverChain::local(&registry);
        let err = chain
            .resolve_kel("did:keri:ENotHere0000000000000000000000000000000000")
            .unwrap_err();
        assert!(matches!(err, KelResolveError::NotFound(_)));
    }
}
