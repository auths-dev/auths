//! KEL resolver orchestration — the seam the verifier resolves signer KELs
//! through.
//!
//! The chain is **local-first**: it always reads the local registry first. The
//! local registry is the trusted floor — a remote can never roll it back.
//!
//! When a remote is configured (`--remote <url>`):
//! - **stranger case** (local has no KEL): the remote result is used, after the
//!   prefix-binding guard. This is what lets a verifier check a commit from an
//!   identity it has never seen, with no local pre-seeding.
//! - **refresh case** (local has a KEL): the remote may only *advance* the state.
//!   A remote tip older than the local tip is a rollback/withholding attempt and
//!   is rejected ([`KelResolveError::Rollback`]); a strictly-newer remote is
//!   accepted (a legitimate rotation/anchor the local cache hasn't seen); an
//!   equal-or-shorter remote leaves local authoritative (prefer-local).
//!
//! Same-sequence forks (the `kt=1` duplicity case) are detected **across
//! sources** here (Epic D): if the local and remote streams present different
//! event SAIDs at the same sequence, resolution refuses with
//! [`KelResolveError::Diverging`] rather than silently picking a side. Within a
//! single stream, the non-fatal "warn, prefer local" duplicity signal is still
//! surfaced downstream by `verify_commit_against_kel`'s `detect_duplicity`. This
//! layer sequences sources, enforces the rollback floor, and refuses cross-source
//! forks; `auths-id` implements each read + the prefix-binding guard.

use auths_id::keri::{
    Event, KelResolveError, KelResolver, LocalKelResolver, Prefix, parse_did_keri,
    verify_prefix_binding,
};
use auths_id::ports::registry::RegistryBackend;
use auths_storage::git::{RemoteKelError, RemoteKelSource};
use auths_verifier::duplicity::{DuplicityReport, KelEventRef, detect_duplicity};

/// Resolves a signer's KEL through an ordered set of sources (local, then an
/// optional git remote), enforcing the prefix-binding guard and the rollback
/// floor.
pub struct KelResolverChain<'a> {
    registry: &'a dyn RegistryBackend,
    remote: Option<RemoteKelSource>,
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
        Self {
            registry,
            remote: None,
        }
    }

    /// A chain that falls back to (and refreshes from) a git remote when the
    /// `--remote <url>` opt-in is given. Local stays the trusted floor.
    ///
    /// Args:
    /// * `registry`: The local backend (trusted floor).
    /// * `remote_url`: The git remote to fetch the packed registry from.
    ///
    /// Usage:
    /// ```ignore
    /// let chain = KelResolverChain::with_remote(&registry, "https://git.example/registry.git");
    /// let kel = chain.resolve_kel(stranger_did)?; // resolves with no local pre-seeding
    /// ```
    pub fn with_remote(registry: &'a dyn RegistryBackend, remote_url: impl Into<String>) -> Self {
        Self {
            registry,
            remote: Some(RemoteKelSource::new(remote_url)),
        }
    }

    /// Resolve the full KEL for `did`, enforcing the prefix-binding guard and the
    /// rollback floor.
    ///
    /// Args:
    /// * `did`: The `did:keri:` to resolve.
    pub fn resolve_kel(&self, did: &str) -> Result<Vec<Event>, KelResolveError> {
        let local = LocalKelResolver::new(self.registry).resolve_kel(did);
        match &self.remote {
            None => local,
            Some(remote) => self.reconcile(did, local, remote),
        }
    }

    /// Reconcile a local result with a remote fetch under the local-first +
    /// rollback-floor policy.
    fn reconcile(
        &self,
        did: &str,
        local: Result<Vec<Event>, KelResolveError>,
        remote: &RemoteKelSource,
    ) -> Result<Vec<Event>, KelResolveError> {
        let prefix =
            parse_did_keri(did).map_err(|_| KelResolveError::InvalidDid(did.to_string()))?;
        let remote = fetch_remote_guarded(remote, &prefix);
        match (local, remote) {
            (Ok(local_kel), Ok(remote_kel)) => {
                // Cross-source fork: same `(i,s)` with different SAIDs across the
                // local and remote streams → refuse, do not silently pick a side.
                if let Some((sequence, saids)) = cross_source_fork(&prefix, &local_kel, &remote_kel)
                {
                    return Err(KelResolveError::Diverging { sequence, saids });
                }
                choose_newer_no_rollback(local_kel, remote_kel)
            }
            // Local present, remote failed: a remote hiccup is non-fatal when we
            // already hold a locally-trusted KEL.
            (Ok(local_kel), Err(_)) => Ok(local_kel),
            // Stranger case: nothing local, remote resolved → use the remote KEL.
            (Err(KelResolveError::NotFound(_)), Ok(remote_kel)) => Ok(remote_kel),
            // Local hard-errored (not a plain miss) → surface that, not the remote.
            (Err(local_err), Ok(_)) => Err(local_err),
            // Both failed: a bare local miss yields the (more informative) remote
            // error; any other local error wins.
            (Err(KelResolveError::NotFound(_)), Err(remote_err)) => Err(remote_err),
            (Err(local_err), Err(_)) => Err(local_err),
        }
    }
}

/// Fetch from a remote and immediately apply the prefix-binding guard, mapping
/// transport errors into the unified [`KelResolveError`] taxonomy.
fn fetch_remote_guarded(
    remote: &RemoteKelSource,
    prefix: &Prefix,
) -> Result<Vec<Event>, KelResolveError> {
    let events = remote.fetch_kel(prefix).map_err(map_remote_err)?;
    verify_prefix_binding(prefix, &events)?;
    Ok(events)
}

/// The rollback floor: a remote KEL must not be older than the locally-trusted
/// state. On a strictly-older remote tip → [`KelResolveError::Rollback`].
/// Otherwise prefer the strictly-newer chain; on a tie, prefer local.
fn choose_newer_no_rollback(
    local_kel: Vec<Event>,
    remote_kel: Vec<Event>,
) -> Result<Vec<Event>, KelResolveError> {
    let local_tip = tip_seq(&local_kel);
    let remote_tip = tip_seq(&remote_kel);
    if remote_tip < local_tip {
        return Err(KelResolveError::Rollback {
            local_tip,
            remote_tip,
        });
    }
    Ok(if remote_tip > local_tip {
        remote_kel
    } else {
        local_kel
    })
}

/// The tip (highest) sequence number across a KEL (0 for a lone inception).
fn tip_seq(events: &[Event]) -> u128 {
    events.last().map(|e| e.sequence().value()).unwrap_or(0)
}

/// Detect a cross-source fork: the same `(i,s)` carrying different event SAIDs
/// across the local and remote streams. Reuses the verifier's `detect_duplicity`
/// over the union of both sources. Returns `(sequence, conflicting_saids)` on a
/// fork, or `None` when the sources agree on every shared sequence.
fn cross_source_fork(
    prefix: &Prefix,
    local: &[Event],
    remote: &[Event],
) -> Option<(u128, Vec<String>)> {
    let refs: Vec<KelEventRef> = local
        .iter()
        .chain(remote.iter())
        .map(|e| KelEventRef {
            prefix: prefix.as_str(),
            seq: e.sequence().value() as u64,
            said: e.said().as_str(),
        })
        .collect();
    match detect_duplicity(&refs) {
        DuplicityReport::Clean => None,
        DuplicityReport::Diverging {
            seq, event_saids, ..
        } => Some((seq as u128, event_saids)),
    }
}

/// Map a transport-specific [`RemoteKelError`] into the unified resolver taxonomy.
fn map_remote_err(err: RemoteKelError) -> KelResolveError {
    match err {
        RemoteKelError::Fetch { url, source } => {
            KelResolveError::Network(format!("{url}: {source}"))
        }
        RemoteKelError::Setup(e) => KelResolveError::Network(e.to_string()),
        RemoteKelError::NoRegistry { reference } => {
            KelResolveError::NotFound(format!("remote has no {reference}"))
        }
        RemoteKelError::NotFound(s) => KelResolveError::NotFound(s),
        RemoteKelError::Oversized { what } => KelResolveError::Oversized(what),
        RemoteKelError::Truncated => KelResolveError::Truncated,
        RemoteKelError::Read(e) => KelResolveError::Backend(e.to_string()),
        RemoteKelError::Serialize(s) => KelResolveError::Replay(s),
        // `RemoteKelError` is #[non_exhaustive]; map any future transport variant
        // to a generic backend error via its Display.
        other => KelResolveError::Backend(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_id::testing::fakes::FakeRegistryBackend;
    use auths_keri::{
        CesrKey, IcpEvent, IxnEvent, KeriPublicKey, KeriSequence, Said, Seal, Threshold,
        VersionString, compute_next_commitment, finalize_icp_event, finalize_ixn_event,
    };
    use auths_storage::git::{GitRegistryBackend, RegistryConfig};
    use tempfile::TempDir;

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

    fn ixn_at(prefix: &Prefix, seq: u128, prev: &Said) -> Event {
        let ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: prev.clone(),
            a: vec![],
        };
        Event::Ixn(finalize_ixn_event(ixn).unwrap())
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

    #[test]
    fn remote_fallback_resolves_with_no_local_seeding() {
        // Source registry on disk (the "remote").
        let src = TempDir::new().unwrap();
        let source =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(src.path()));
        source.init_if_needed().unwrap();
        let (event, prefix) = icp_and_prefix(2);
        source.append_event(&prefix, &event).unwrap();
        let url = format!("file://{}", src.path().display());

        // Empty local registry → the chain must fall back to the remote.
        let local = FakeRegistryBackend::new();
        let chain = KelResolverChain::with_remote(&local, url);
        let did = format!("did:keri:{prefix}");
        assert_eq!(chain.resolve_kel(&did).unwrap(), vec![event]);
    }

    #[test]
    fn monotonicity_rejects_older_remote() {
        let (icp, prefix) = icp_and_prefix(3);
        let icp_said = match &icp {
            Event::Icp(e) => e.d.clone(),
            _ => unreachable!(),
        };
        let local_kel = vec![icp.clone(), ixn_at(&prefix, 1, &icp_said)]; // tip 1
        let remote_kel = vec![icp]; // tip 0 — a rollback

        let err = choose_newer_no_rollback(local_kel, remote_kel).unwrap_err();
        assert!(matches!(err, KelResolveError::Rollback { .. }));
    }

    #[test]
    fn monotonicity_accepts_strictly_newer_remote() {
        let (icp, prefix) = icp_and_prefix(4);
        let icp_said = match &icp {
            Event::Icp(e) => e.d.clone(),
            _ => unreachable!(),
        };
        let local_kel = vec![icp.clone()]; // tip 0
        let newer = vec![icp, ixn_at(&prefix, 1, &icp_said)]; // tip 1

        let chosen = choose_newer_no_rollback(local_kel, newer.clone()).unwrap();
        assert_eq!(chosen, newer);
    }

    #[test]
    fn equal_tip_prefers_local() {
        let (icp, _prefix) = icp_and_prefix(5);
        let local_kel = vec![icp.clone()];
        let remote_kel = vec![icp];
        // Distinguish by pointer identity is overkill; equal tips → local returned.
        let chosen = choose_newer_no_rollback(local_kel.clone(), remote_kel).unwrap();
        assert_eq!(chosen, local_kel);
    }

    #[test]
    fn remote_error_maps_into_taxonomy() {
        assert!(matches!(
            map_remote_err(RemoteKelError::Truncated),
            KelResolveError::Truncated
        ));
        assert!(matches!(
            map_remote_err(RemoteKelError::NotFound("x".into())),
            KelResolveError::NotFound(_)
        ));
        assert!(matches!(
            map_remote_err(RemoteKelError::Oversized { what: "big".into() }),
            KelResolveError::Oversized(_)
        ));
    }

    /// A distinct seq-1 event (different anchors → different SAID) for fork tests.
    fn conflicting_ixn_at(prefix: &Prefix, seq: u128, prev: &Said) -> Event {
        let ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: prev.clone(),
            a: vec![Seal::digest("EConflictingAnchor")],
        };
        Event::Ixn(finalize_ixn_event(ixn).unwrap())
    }

    #[test]
    fn cross_source_fork_flagged() {
        let (icp, prefix) = icp_and_prefix(7);
        let icp_said = match &icp {
            Event::Icp(e) => e.d.clone(),
            _ => unreachable!(),
        };
        let local = vec![icp.clone(), ixn_at(&prefix, 1, &icp_said)];
        let remote = vec![icp, conflicting_ixn_at(&prefix, 1, &icp_said)];

        let fork = cross_source_fork(&prefix, &local, &remote);
        assert!(fork.is_some(), "a same-seq SAID mismatch must be flagged");
        let (seq, saids) = fork.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(saids.len(), 2);
    }

    #[test]
    fn clean_multi_source_resolves() {
        let (icp, prefix) = icp_and_prefix(8);
        let icp_said = match &icp {
            Event::Icp(e) => e.d.clone(),
            _ => unreachable!(),
        };
        let local = vec![icp.clone(), ixn_at(&prefix, 1, &icp_said)];
        let remote = local.clone(); // identical streams — no fork
        assert!(cross_source_fork(&prefix, &local, &remote).is_none());
    }

    #[test]
    fn first_seen_retained_without_conflict() {
        // No fork → first-seen (local) is retained at an equal tip.
        let (icp, prefix) = icp_and_prefix(9);
        let local = vec![icp.clone()];
        let remote = vec![icp];
        assert!(cross_source_fork(&prefix, &local, &remote).is_none());
        let chosen = choose_newer_no_rollback(local.clone(), remote).unwrap();
        assert_eq!(chosen, local);
    }
}
