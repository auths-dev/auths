//! Relying-party registry synchronization — revocation propagation over a wire.
//!
//! A relying party verifies presentations against its **own** registry replica; revocation
//! freshness is the pull cadence (see `auths_sdk::authenticate_presentation`). This module is
//! that cadence, shaped as a port + adapter + loop:
//!
//! - [`RegistrySync`] is the port: one pull attempt of the remote registry into the local
//!   replica, reported as a typed [`SyncOutcome`].
//! - [`RegistryWatcher`] is the loop: a background thread that calls the port on a fixed
//!   interval until stopped, handing every result to an observer callback.
//! - `GitRegistrySync` (feature `git-sync`) is the shipped adapter: a git fetch of
//!   [`AUTHS_REFS_GLOB`] (`refs/auths/*`) from the authoritative remote — the same packed
//!   refs the operator's registry writes — into the relying party's repository.
//!
//! Trust stays in verification, never in transport: a fetched KEL/TEL is still replayed and
//! signature-checked by the verifier on every request, so a hostile remote cannot mint
//! validity. The transport itself is fail-closed against rollback: the fetch refspec is
//! **non-forced**, so a remote that rewinds its history (e.g. to resurrect a revoked
//! credential by serving an older tip) is rejected and the replica keeps the newest state it
//! has seen.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

/// The glob covering every ref the auths registry publishes (KELs, TELs, credentials,
/// identity metadata all live under the packed registry ref inside this namespace).
pub const AUTHS_REFS_GLOB: &str = "refs/auths/*";

/// A non-empty git remote URL the relying party pulls its registry from.
///
/// Constructed only via [`RemoteUrl::parse`], so an empty remote is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUrl(String);

impl RemoteUrl {
    /// Parse a non-empty remote URL (e.g. `https://…`, `ssh://…`, `file:///srv/registry`).
    ///
    /// Args:
    /// * `s`: The git remote URL of the authoritative registry.
    ///
    /// Usage:
    /// ```
    /// # use auths_rp::RemoteUrl;
    /// assert!(RemoteUrl::parse("file:///srv/registry").is_ok());
    /// assert!(RemoteUrl::parse("").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, SyncError> {
        if s.is_empty() {
            return Err(SyncError::EmptyRemoteUrl);
        }
        Ok(Self(s.to_string()))
    }

    /// The remote URL as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RemoteUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What one sync attempt did to the local replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// At least one `refs/auths/*` ref moved — new registry events arrived.
    Updated {
        /// How many refs changed under [`AUTHS_REFS_GLOB`].
        refs_changed: usize,
    },
    /// The replica already matched the remote.
    Unchanged,
}

impl std::fmt::Display for SyncOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncOutcome::Updated { refs_changed } => {
                write!(f, "updated ({refs_changed} ref(s) moved)")
            }
            SyncOutcome::Unchanged => f.write_str("unchanged"),
        }
    }
}

/// Registry-sync errors (`thiserror`, closed at the port boundary).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The remote URL was empty.
    #[error("empty registry remote URL")]
    EmptyRemoteUrl,
    /// The local replica repository could not be opened, initialized, or read.
    #[error("registry replica repository error: {detail}")]
    Repository {
        /// The underlying error text.
        detail: String,
    },
    /// The fetch from the remote failed (unreachable, refused non-fast-forward, …).
    #[error("registry fetch from '{url}' failed: {detail}")]
    Transport {
        /// The remote URL the fetch targeted.
        url: String,
        /// The underlying error text.
        detail: String,
    },
}

/// One sync attempt's result, as handed to a [`RegistryWatcher`] observer.
pub type SyncResult = Result<SyncOutcome, SyncError>;

/// The registry-sync port: one pull of the authoritative registry into the local replica.
///
/// `GitRegistrySync` (feature `git-sync`) is the shipped adapter; a deployment with a
/// different distribution channel (witness receipts, an object store, …) supplies its own
/// implementation and the [`RegistryWatcher`] loop works unchanged.
pub trait RegistrySync: Send + Sync {
    /// Pull the remote registry once, reporting whether the replica changed.
    fn sync(&self) -> SyncResult;

    /// The remote this sync pulls from (for logging/diagnostics).
    fn remote_url(&self) -> &RemoteUrl;
}

/// Coordinated stop flag for the watcher thread (interruptible interval sleep).
struct StopFlag {
    stopped: Mutex<bool>,
    bell: Condvar,
}

impl StopFlag {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            bell: Condvar::new(),
        }
    }

    /// Sleep up to `interval`, returning early — and `true` — once stop is requested.
    fn wait(&self, interval: Duration) -> bool {
        let mut stopped = self.stopped.lock();
        if *stopped {
            return true;
        }
        self.bell.wait_for(&mut stopped, interval);
        *stopped
    }

    fn raise(&self) {
        *self.stopped.lock() = true;
        self.bell.notify_all();
    }
}

/// The registry watch loop: polls a [`RegistrySync`] on a fixed interval, on its own thread.
///
/// Every poll's [`SyncResult`] goes to the observer callback (the host decides how to log
/// an update or a transient fetch failure; the loop itself never prints). The first poll
/// happens one `interval` after spawn — do an explicit blocking [`RegistrySync::sync`]
/// first when the host must boot with a current replica.
///
/// Dropping the watcher signals the thread to stop without blocking; [`RegistryWatcher::stop`]
/// signals and joins.
///
/// Usage:
/// ```ignore
/// let sync: Arc<dyn RegistrySync> = Arc::new(GitRegistrySync::open_or_init(replica, remote)?);
/// sync.sync()?; // prime the replica before serving
/// let watcher = RegistryWatcher::spawn(sync, Duration::from_millis(250), Box::new(|r| log(r)))?;
/// ```
pub struct RegistryWatcher {
    stop: Arc<StopFlag>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RegistryWatcher {
    /// Spawn the watch thread: poll `sync` every `interval`, reporting each result to
    /// `on_sync`, until stopped.
    ///
    /// Args:
    /// * `sync`: The registry-sync port to poll.
    /// * `interval`: The pull cadence (also the worst-case revocation propagation lag).
    /// * `on_sync`: Observer for every poll result (logging, metrics).
    pub fn spawn(
        sync: Arc<dyn RegistrySync>,
        interval: Duration,
        on_sync: Box<dyn Fn(&SyncResult) + Send>,
    ) -> std::io::Result<Self> {
        let stop = Arc::new(StopFlag::new());
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("auths-rp-registry-watcher".to_string())
            .spawn(move || poll_registry(&*sync, interval, &*on_sync, &thread_stop))?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    /// Signal the watch thread to stop and join it.
    pub fn stop(mut self) {
        self.stop.raise();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RegistryWatcher {
    fn drop(&mut self) {
        // Signal without joining: drop must not block on an in-flight fetch.
        self.stop.raise();
    }
}

/// The watch-loop body: interval-sleep (interruptible), then one sync, until stopped.
fn poll_registry(
    sync: &dyn RegistrySync,
    interval: Duration,
    on_sync: &(dyn Fn(&SyncResult) + Send),
    stop: &StopFlag,
) {
    loop {
        if stop.wait(interval) {
            return;
        }
        let result = sync.sync();
        on_sync(&result);
    }
}

#[cfg(feature = "git-sync")]
pub use git::GitRegistrySync;

#[cfg(feature = "git-sync")]
mod git {
    //! The shipped git adapter: fetch `refs/auths/*` from the remote into the replica.

    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::{AUTHS_REFS_GLOB, RegistrySync, RemoteUrl, SyncError, SyncOutcome, SyncResult};

    /// A registry replica kept current by git fetch — the shipped [`RegistrySync`] adapter.
    ///
    /// Holds the replica path and remote URL only; the repository is opened per sync, so the
    /// adapter is `Send + Sync` and the replica is always read fresh (matching the
    /// verify-side per-request re-read discipline). The fetch refspec is non-forced:
    /// a non-fast-forward remote (a rewound registry) is an error, never a rollback.
    pub struct GitRegistrySync {
        local_repo: PathBuf,
        remote: RemoteUrl,
    }

    impl GitRegistrySync {
        /// Open the replica repository at `local_repo`, initializing an empty one if absent.
        ///
        /// Args:
        /// * `local_repo`: The relying party's own registry repository path.
        /// * `remote`: The authoritative registry remote to pull from.
        ///
        /// Usage:
        /// ```ignore
        /// let sync = GitRegistrySync::open_or_init("/var/lib/rp/registry", remote)?;
        /// ```
        pub fn open_or_init(
            local_repo: impl Into<PathBuf>,
            remote: RemoteUrl,
        ) -> Result<Self, SyncError> {
            let local_repo = local_repo.into();
            if git2::Repository::open(&local_repo).is_err() {
                git2::Repository::init(&local_repo).map_err(|e| SyncError::Repository {
                    detail: format!("init {} failed: {e}", local_repo.display()),
                })?;
            }
            Ok(Self { local_repo, remote })
        }

        /// The replica repository path.
        pub fn local_repo(&self) -> &std::path::Path {
            &self.local_repo
        }
    }

    impl RegistrySync for GitRegistrySync {
        fn sync(&self) -> SyncResult {
            let repo =
                git2::Repository::open(&self.local_repo).map_err(|e| SyncError::Repository {
                    detail: format!("open {} failed: {e}", self.local_repo.display()),
                })?;
            let before = auths_ref_tips(&repo)?;

            let transport = |e: git2::Error| SyncError::Transport {
                url: self.remote.as_str().to_string(),
                detail: e.to_string(),
            };
            let mut remote = repo
                .remote_anonymous(self.remote.as_str())
                .map_err(transport)?;
            remote.connect(git2::Direction::Fetch).map_err(transport)?;
            let advertised: BTreeMap<String, git2::Oid> = remote
                .list()
                .map_err(transport)?
                .iter()
                .filter(|head| is_auths_ref(head.name()))
                .map(|head| (head.name().to_string(), head.oid()))
                .collect();
            // Non-forced refspec (no leading '+'): libgit2 silently SKIPS any
            // non-fast-forward update, so the replica can never be rolled back.
            let refspec = format!("{AUTHS_REFS_GLOB}:{AUTHS_REFS_GLOB}");
            remote
                .fetch(&[refspec.as_str()], None, None)
                .map_err(transport)?;

            let after = auths_ref_tips(&repo)?;
            // A skipped update means the remote diverged from (rewound below) the
            // replica — e.g. serving a pre-revocation registry. Silence here would be
            // silent staleness forever; fail loud instead.
            for (name, oid) in &advertised {
                if after.get(name) != Some(oid) {
                    return Err(SyncError::Transport {
                        url: self.remote.as_str().to_string(),
                        detail: format!(
                            "remote rewound {name} (non-fast-forward); refusing rollback"
                        ),
                    });
                }
            }
            let refs_changed = after
                .iter()
                .filter(|(name, oid)| before.get(*name) != Some(oid))
                .count()
                + before.keys().filter(|k| !after.contains_key(*k)).count();
            if refs_changed == 0 {
                Ok(SyncOutcome::Unchanged)
            } else {
                Ok(SyncOutcome::Updated { refs_changed })
            }
        }

        fn remote_url(&self) -> &RemoteUrl {
            &self.remote
        }
    }

    /// Whether a ref name falls under [`AUTHS_REFS_GLOB`] (prefix derived from the glob).
    fn is_auths_ref(name: &str) -> bool {
        name.starts_with(AUTHS_REFS_GLOB.trim_end_matches('*'))
    }

    /// Snapshot the OIDs of every ref under [`AUTHS_REFS_GLOB`].
    fn auths_ref_tips(repo: &git2::Repository) -> Result<BTreeMap<String, git2::Oid>, SyncError> {
        let mut tips = BTreeMap::new();
        let refs = repo
            .references_glob(AUTHS_REFS_GLOB)
            .map_err(|e| SyncError::Repository {
                detail: format!("listing {AUTHS_REFS_GLOB} failed: {e}"),
            })?;
        for r in refs {
            let r = r.map_err(|e| SyncError::Repository {
                detail: format!("reading ref failed: {e}"),
            })?;
            if let (Ok(name), Some(oid)) = (r.name(), r.target()) {
                tips.insert(name.to_string(), oid);
            }
        }
        Ok(tips)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn empty_remote_url_rejected() {
        assert!(matches!(
            RemoteUrl::parse(""),
            Err(SyncError::EmptyRemoteUrl)
        ));
        assert_eq!(
            RemoteUrl::parse("file:///srv/reg").unwrap().as_str(),
            "file:///srv/reg"
        );
    }

    struct CountingSync {
        url: RemoteUrl,
        calls: AtomicUsize,
    }

    impl CountingSync {
        fn new() -> Self {
            Self {
                url: RemoteUrl::parse("file:///dev/null").unwrap(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl RegistrySync for CountingSync {
        fn sync(&self) -> SyncResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SyncOutcome::Unchanged)
        }

        fn remote_url(&self) -> &RemoteUrl {
            &self.url
        }
    }

    #[test]
    fn watcher_polls_then_stops() {
        let sync = Arc::new(CountingSync::new());
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_in_cb = Arc::clone(&observed);
        let watcher = RegistryWatcher::spawn(
            Arc::clone(&sync) as Arc<dyn RegistrySync>,
            Duration::from_millis(5),
            Box::new(move |result| {
                assert!(result.is_ok());
                observed_in_cb.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .unwrap();

        // Wait (bounded) until at least two polls happened.
        let mut spins = 0;
        while sync.calls.load(Ordering::SeqCst) < 2 && spins < 400 {
            std::thread::sleep(Duration::from_millis(5));
            spins += 1;
        }
        assert!(
            sync.calls.load(Ordering::SeqCst) >= 2,
            "watcher never polled"
        );

        watcher.stop();
        let after_stop = sync.calls.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            sync.calls.load(Ordering::SeqCst),
            after_stop,
            "watcher kept polling after stop"
        );
        assert_eq!(observed.load(Ordering::SeqCst), after_stop);
    }

    #[cfg(feature = "git-sync")]
    mod git_sync {
        use super::super::{GitRegistrySync, RegistrySync, RemoteUrl, SyncError, SyncOutcome};

        const REGISTRY_REF: &str = "refs/auths/registry";

        /// Commit an empty tree onto `reference` (parented on its current tip, if any).
        fn commit_on(repo: &git2::Repository, reference: &str, message: &str) -> git2::Oid {
            let sig = git2::Signature::now("test", "test@example.com").unwrap();
            let tree_id = repo.treebuilder(None).unwrap().write().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            let parent = repo
                .find_reference(reference)
                .ok()
                .and_then(|r| r.peel_to_commit().ok());
            let parents: Vec<&git2::Commit> = parent.iter().collect();
            repo.commit(Some(reference), &sig, &sig, message, &tree, &parents)
                .unwrap()
        }

        fn origin_with_one_commit() -> (tempfile::TempDir, git2::Repository) {
            let dir = tempfile::TempDir::new().unwrap();
            let repo = git2::Repository::init(dir.path()).unwrap();
            commit_on(&repo, REGISTRY_REF, "registry event 1");
            (dir, repo)
        }

        fn file_url(dir: &tempfile::TempDir) -> RemoteUrl {
            RemoteUrl::parse(&format!("file://{}", dir.path().display())).unwrap()
        }

        #[test]
        fn pulls_updates_then_reports_unchanged() {
            let (origin_dir, origin) = origin_with_one_commit();
            let replica_dir = tempfile::TempDir::new().unwrap();
            let replica = replica_dir.path().join("rp-registry");

            let sync = GitRegistrySync::open_or_init(&replica, file_url(&origin_dir)).unwrap();
            assert!(matches!(
                sync.sync().unwrap(),
                SyncOutcome::Updated { refs_changed: 1 }
            ));
            assert!(matches!(sync.sync().unwrap(), SyncOutcome::Unchanged));

            // A new registry event on the origin propagates on the next pull.
            let new_tip = commit_on(&origin, REGISTRY_REF, "registry event 2 (revocation)");
            assert!(matches!(
                sync.sync().unwrap(),
                SyncOutcome::Updated { refs_changed: 1 }
            ));
            let replica_repo = git2::Repository::open(&replica).unwrap();
            let replica_tip = replica_repo
                .find_reference(REGISTRY_REF)
                .unwrap()
                .target()
                .unwrap();
            assert_eq!(
                replica_tip, new_tip,
                "replica tip must match the origin tip"
            );
        }

        #[test]
        fn rewound_remote_is_rejected_not_rolled_back() {
            let (origin_dir, origin) = origin_with_one_commit();
            let replica_dir = tempfile::TempDir::new().unwrap();
            let replica = replica_dir.path().join("rp-registry");

            let sync = GitRegistrySync::open_or_init(&replica, file_url(&origin_dir)).unwrap();
            commit_on(&origin, REGISTRY_REF, "registry event 2 (revocation)");
            sync.sync().unwrap();
            let replica_repo = git2::Repository::open(&replica).unwrap();
            let tip_before = replica_repo
                .find_reference(REGISTRY_REF)
                .unwrap()
                .target()
                .unwrap();

            // The remote rewrites history to an unrelated root — e.g. trying to serve a
            // pre-revocation registry. The non-forced fetch must refuse the rollback.
            origin
                .find_reference(REGISTRY_REF)
                .unwrap()
                .delete()
                .unwrap();
            commit_on(&origin, REGISTRY_REF, "rewritten history");
            let err = sync.sync().unwrap_err();
            assert!(matches!(err, SyncError::Transport { .. }), "got: {err:?}");

            let tip_after = git2::Repository::open(&replica)
                .unwrap()
                .find_reference(REGISTRY_REF)
                .unwrap()
                .target()
                .unwrap();
            assert_eq!(tip_before, tip_after, "replica must keep the newest state");
        }
    }
}
