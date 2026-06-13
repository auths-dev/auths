//! Native git-remote KEL fetch (greenfield transport).
//!
//! Given a git remote URL and a `did:keri:` prefix, fetch the remote's packed
//! registry ref (`refs/auths/registry`) into a throwaway temp repository, then
//! read the prefix's KEL via the existing [`GitRegistryBackend`] read path.
//!
//! Fetched events are returned **in memory** and are NEVER written back into the
//! caller's persistent registry: `append_event` performs no replay validation,
//! so persisting unvalidated remote events would poison later reads. The caller
//! (the SDK resolver chain) applies the prefix-binding guard and monotonicity
//! before trusting the result. Size caps bound memory against a hostile remote;
//! a truncation guard rejects a KEL whose inception (seq 0) is absent.

use auths_id::keri::kel_resolver::{KelResolveError, collect_kel_capped};
use auths_id::ports::registry::RegistryError;
use auths_keri::{Event, Prefix};
use git2::Repository;
use tempfile::TempDir;

use super::{GitRegistryBackend, REGISTRY_REF, RegistryConfig};

/// Maximum number of events in a single fetched KEL (DoS bound).
pub const MAX_KEL_EVENTS: usize = 10_000;

/// Maximum total serialized size of a single fetched KEL, in bytes (DoS bound).
pub const MAX_KEL_BYTES: usize = 4 * 1024 * 1024;

/// Errors fetching a KEL from a git remote.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteKelError {
    /// The git fetch (or temp-repo init) against the remote failed.
    #[error("git fetch from '{url}' failed: {source}")]
    Fetch {
        /// The remote URL.
        url: String,
        /// The underlying git2 error.
        #[source]
        source: git2::Error,
    },

    /// The remote did not advertise / serve the registry ref.
    #[error("remote has no registry ref ({reference})")]
    NoRegistry {
        /// The expected ref name.
        reference: String,
    },

    /// No KEL is present on the remote for the requested identifier.
    #[error("KEL not found on remote for {0}")]
    NotFound(String),

    /// The fetched KEL exceeds a configured size bound.
    #[error("fetched KEL exceeds size bound ({what})")]
    Oversized {
        /// Which bound was exceeded.
        what: String,
    },

    /// The fetched KEL is missing its inception (seq 0) event.
    #[error("fetched KEL is truncated: inception (seq 0) is missing")]
    Truncated,

    /// Temp-repository setup failed.
    #[error("temp repository setup failed: {0}")]
    Setup(#[source] std::io::Error),

    /// Reading the fetched KEL out of the temp registry failed.
    #[error("reading fetched KEL failed: {0}")]
    Read(#[source] RegistryError),

    /// An event could not be serialized while measuring against the byte cap.
    #[error("event serialization failed: {0}")]
    Serialize(String),
}

/// A KEL source backed by a configured git remote.
///
/// Holds the remote URL (the config surface for C1); the SDK resolver chain
/// threads the `--remote`/configured URL in here and applies the prefix-binding
/// guard to the returned events.
pub struct RemoteKelSource {
    remote_url: String,
}

impl RemoteKelSource {
    /// Build a remote source for the given git URL (e.g. `https://…`, `file://…`).
    ///
    /// Args:
    /// * `remote_url`: The git remote to fetch the packed registry from.
    ///
    /// Usage:
    /// ```ignore
    /// let kel = RemoteKelSource::new("file:///srv/registry.git").fetch_kel(&prefix)?;
    /// ```
    pub fn new(remote_url: impl Into<String>) -> Self {
        Self {
            remote_url: remote_url.into(),
        }
    }

    /// The remote URL this source fetches from.
    pub fn url(&self) -> &str {
        &self.remote_url
    }

    /// Fetch the prefix's full KEL from the remote registry.
    ///
    /// Fetches `refs/auths/registry` into a fresh temp repo, then reads the
    /// prefix's events (from sequence 0) via [`GitRegistryBackend`]. Enforces the
    /// size caps and the truncation guard. Does NOT write to any persistent
    /// store — the temp repo is discarded when this returns.
    ///
    /// Args:
    /// * `prefix`: The identifier prefix to read.
    pub fn fetch_kel(&self, prefix: &Prefix) -> Result<Vec<Event>, RemoteKelError> {
        let snapshot = self.fetch_snapshot()?;
        read_kel_capped(snapshot.backend(), prefix, MAX_KEL_EVENTS, MAX_KEL_BYTES)
    }

    /// Fetch the remote's whole packed registry into a throwaway snapshot.
    ///
    /// The snapshot is a read-only [`GitRegistryBackend`] over a temp repo —
    /// the registry-wide primitive `registry pull` merges from. It is
    /// **untrusted**: callers must run the validated merge (or the per-KEL
    /// guards) before persisting anything it serves; the temp repo is deleted
    /// when the snapshot drops.
    pub fn fetch_snapshot(&self) -> Result<RegistrySnapshot, RemoteKelError> {
        let tmp = TempDir::new().map_err(RemoteKelError::Setup)?;
        let repo = Repository::init(tmp.path()).map_err(|e| RemoteKelError::Fetch {
            url: self.remote_url.clone(),
            source: e,
        })?;
        fetch_registry_ref(&repo, &self.remote_url)?;

        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(tmp.path()));
        Ok(RegistrySnapshot { _tmp: tmp, backend })
    }
}

/// A fetched remote registry held in a temp repo — read-only, untrusted,
/// deleted on drop.
pub struct RegistrySnapshot {
    /// Owns the temp repo for the snapshot's lifetime.
    _tmp: TempDir,
    backend: GitRegistryBackend,
}

impl RegistrySnapshot {
    /// The backend reading the fetched registry.
    pub fn backend(&self) -> &GitRegistryBackend {
        &self.backend
    }
}

/// Fetch only the packed registry ref from `url` into `repo`.
fn fetch_registry_ref(repo: &Repository, url: &str) -> Result<(), RemoteKelError> {
    let mut remote = repo
        .remote_anonymous(url)
        .map_err(|e| RemoteKelError::Fetch {
            url: url.to_string(),
            source: e,
        })?;
    let refspec = format!("+{REGISTRY_REF}:{REGISTRY_REF}");
    remote
        .fetch(&[refspec.as_str()], None, None)
        .map_err(|e| RemoteKelError::Fetch {
            url: url.to_string(),
            source: e,
        })?;
    if repo.find_reference(REGISTRY_REF).is_err() {
        return Err(RemoteKelError::NoRegistry {
            reference: REGISTRY_REF.to_string(),
        });
    }
    Ok(())
}

/// Read a prefix's KEL out of a fetched snapshot under the shared untrusted-read
/// guards ([`collect_kel_capped`]: caps + truncation), mapped into this
/// adapter's error vocabulary.
///
/// Args:
/// * `backend`: The (just-fetched) registry to read from.
/// * `prefix`: The identifier prefix.
/// * `max_events`: Hard cap on event count.
/// * `max_bytes`: Hard cap on total serialized KEL size.
fn read_kel_capped(
    backend: &GitRegistryBackend,
    prefix: &Prefix,
    max_events: usize,
    max_bytes: usize,
) -> Result<Vec<Event>, RemoteKelError> {
    collect_kel_capped(backend, prefix, max_events, max_bytes).map_err(|e| match e {
        KelResolveError::NotFound(id) => RemoteKelError::NotFound(id),
        KelResolveError::Oversized(what) => RemoteKelError::Oversized { what },
        KelResolveError::Truncated => RemoteKelError::Truncated,
        KelResolveError::Backend(reason) => RemoteKelError::Read(RegistryError::Internal(reason)),
        other => RemoteKelError::Serialize(other.to_string()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_id::ports::registry::RegistryBackend;
    use auths_keri::{
        CesrKey, IcpEvent, KeriPublicKey, KeriSequence, Said, Threshold, VersionString,
        compute_next_commitment, finalize_icp_event,
    };

    /// A finalized inception event + its self-addressing prefix.
    fn icp_event() -> (Event, Prefix) {
        let key = KeriPublicKey::ed25519(&[7u8; 32]).unwrap();
        let next = KeriPublicKey::ed25519(&[8u8; 32]).unwrap();
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

    /// Build a source registry on disk holding one identity's inception.
    fn source_registry() -> (TempDir, Event, Prefix) {
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        let (event, prefix) = icp_event();
        backend.append_event(&prefix, &event).unwrap();
        (dir, event, prefix)
    }

    #[test]
    fn fetches_kel_from_file_remote_with_no_local_seeding() {
        let (src, event, prefix) = source_registry();
        let url = format!("file://{}", src.path().display());

        let fetched = RemoteKelSource::new(url).fetch_kel(&prefix).unwrap();
        assert_eq!(fetched, vec![event]);
    }

    #[test]
    fn unknown_identity_on_remote_is_not_found() {
        let (src, _event, _prefix) = source_registry();
        let url = format!("file://{}", src.path().display());
        let missing =
            Prefix::new_unchecked("ENeverProvisionedHere000000000000000000000000".to_string());

        let err = RemoteKelSource::new(url).fetch_kel(&missing).unwrap_err();
        assert!(matches!(err, RemoteKelError::NotFound(_)));
    }

    #[test]
    fn event_cap_rejects_oversized_kel() {
        // A real backend with one event, read under a zero-event cap → Oversized.
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        let (event, prefix) = icp_event();
        backend.append_event(&prefix, &event).unwrap();

        let err = read_kel_capped(&backend, &prefix, 0, MAX_KEL_BYTES).unwrap_err();
        assert!(matches!(err, RemoteKelError::Oversized { .. }));
    }

    #[test]
    fn byte_cap_rejects_oversized_kel() {
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        let (event, prefix) = icp_event();
        backend.append_event(&prefix, &event).unwrap();

        let err = read_kel_capped(&backend, &prefix, MAX_KEL_EVENTS, 1).unwrap_err();
        assert!(matches!(err, RemoteKelError::Oversized { .. }));
    }
}
