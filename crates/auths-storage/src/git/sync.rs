//! Registry propagation over a git remote — push/pull of `refs/auths/registry`.
//!
//! The wire is plain git, so any git remote (a bare repo over `file://`,
//! `git://`, `ssh://`, `https://`) can carry a registry between machines —
//! no shared filesystem.
//!
//! **Push** publishes the local packed registry ref, fast-forward only: the
//! registry is append-only, so a non-fast-forward means the histories
//! diverged and the push is refused ([`RegistrySyncError::Diverged`]) rather
//! than forced.
//!
//! **Pull** fetches the remote's ref into a throwaway snapshot and runs the
//! validated KEL merge ([`merge_registries`]) into the local registry —
//! prefix binding, authenticated replay, rollback floor, fork refusal.
//! Nothing from the remote is ever persisted unvalidated.

use std::cell::RefCell;
use std::path::Path;

use auths_id::keri::sync::{KelCaps, MergedKel, RegistryMergeError, merge_registries};
use auths_id::ports::registry::RegistryError;
use git2::Repository;

use super::remote::{MAX_KEL_BYTES, MAX_KEL_EVENTS, RemoteKelError, RemoteKelSource};
use super::{GitRegistryBackend, REGISTRY_REF, RegistryConfig};

/// Errors pushing or pulling a registry over a git remote.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrySyncError {
    /// The local registry repo could not be opened.
    #[error("could not open the local registry at '{path}': {source}")]
    OpenLocal {
        /// The local registry path.
        path: String,
        /// The underlying git2 error.
        #[source]
        source: git2::Error,
    },

    /// The local registry has no packed registry ref to push.
    #[error("local registry has no '{reference}' to push (run `auths init` first)")]
    NothingToPush {
        /// The expected ref name.
        reference: String,
    },

    /// A git transport operation (connect / fetch / push) failed.
    #[error("git transport with '{url}' failed: {source}")]
    Transport {
        /// The remote URL.
        url: String,
        /// The underlying git2 error.
        #[source]
        source: git2::Error,
    },

    /// The remote's registry history is not an ancestor of the local one —
    /// pushing would discard remote events. The registry is append-only;
    /// reconcile by pulling first.
    #[error(
        "remote registry has diverged from the local one (non-fast-forward); \
         pull first, then push"
    )]
    Diverged,

    /// The remote refused the ref update.
    #[error("remote rejected the push of {reference}: {status}")]
    PushRejected {
        /// The ref the remote refused.
        reference: String,
        /// The remote's status message.
        status: String,
    },

    /// Fetching the remote registry snapshot failed.
    #[error(transparent)]
    Fetch(#[from] RemoteKelError),

    /// The validated merge refused the fetched registry.
    #[error(transparent)]
    Merge(#[from] RegistryMergeError),

    /// The local registry backend failed.
    #[error("local registry error: {0}")]
    Storage(#[from] RegistryError),
}

/// The result of a registry push.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    /// The remote's registry ref was advanced (or created).
    Updated,
    /// The remote already holds the local tip — nothing to send.
    AlreadyCurrent,
}

/// Push the local packed registry ref to `url`, fast-forward only.
///
/// Refuses with [`RegistrySyncError::Diverged`] when the remote holds history
/// the local registry does not — the registry is append-only, so a push never
/// rewrites a remote.
///
/// Args:
/// * `local_root`: The local registry root (the `~/.auths` repo).
/// * `url`: The git remote to publish to.
///
/// Usage:
/// ```ignore
/// let outcome = push_registry(&auths_home, "git://wire.local/registry.git")?;
/// ```
pub fn push_registry(local_root: &Path, url: &str) -> Result<PushOutcome, RegistrySyncError> {
    let repo = Repository::open(local_root).map_err(|e| RegistrySyncError::OpenLocal {
        path: local_root.display().to_string(),
        source: e,
    })?;
    let local_oid = repo
        .find_reference(REGISTRY_REF)
        .ok()
        .and_then(|r| r.target())
        .ok_or_else(|| RegistrySyncError::NothingToPush {
            reference: REGISTRY_REF.to_string(),
        })?;

    let transport = |source: git2::Error| RegistrySyncError::Transport {
        url: url.to_string(),
        source,
    };
    let mut remote = repo.remote_anonymous(url).map_err(transport)?;

    // Learn the remote tip (if any) before deciding what a push would do:
    // fetch the remote's registry ref into a throwaway local ref. A remote
    // without the ref is a fresh wire — the fetch is a no-op and the temp ref
    // never appears. (Deliberately not `Remote::list()`: that needs a second
    // connection and an empty remote advertises zero refs.)
    const INCOMING_REF: &str = "refs/auths/sync/incoming";
    remote
        .fetch(&[format!("+{REGISTRY_REF}:{INCOMING_REF}")], None, None)
        .map_err(transport)?;
    let remote_oid = repo
        .find_reference(INCOMING_REF)
        .ok()
        .and_then(|r| r.target());
    if let Ok(mut incoming) = repo.find_reference(INCOMING_REF) {
        let _ = incoming.delete();
    }

    if let Some(remote_oid) = remote_oid {
        if remote_oid == local_oid {
            return Ok(PushOutcome::AlreadyCurrent);
        }
        // Fast-forward check — the remote commit is in the local odb from the
        // fetch above.
        let fast_forward = repo
            .graph_descendant_of(local_oid, remote_oid)
            .map_err(transport)?;
        if !fast_forward {
            return Err(RegistrySyncError::Diverged);
        }
    }

    // Plain (non-force) refspec: the ancestry was proven above, and the remote
    // side's own fast-forward rule stays in force as a second guard.
    let rejection: RefCell<Option<(String, String)>> = RefCell::new(None);
    {
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.push_update_reference(|reference, status| {
            if let Some(status) = status {
                *rejection.borrow_mut() = Some((reference.to_string(), status.to_string()));
            }
            Ok(())
        });
        let mut options = git2::PushOptions::new();
        options.remote_callbacks(callbacks);
        remote
            .push(
                &[format!("{REGISTRY_REF}:{REGISTRY_REF}")],
                Some(&mut options),
            )
            .map_err(transport)?;
    }
    if let Some((reference, status)) = rejection.into_inner() {
        return Err(RegistrySyncError::PushRejected { reference, status });
    }
    Ok(PushOutcome::Updated)
}

/// Pull the remote registry at `url` and merge its KELs into the local
/// registry under the validated-merge guards.
///
/// Provisions the local registry if it does not exist yet, so a fresh machine
/// can pull before it ever runs `auths init`. Returns the per-identity merge
/// report.
///
/// Args:
/// * `local_root`: The local registry root (the `~/.auths` repo).
/// * `url`: The git remote to fetch from.
///
/// Usage:
/// ```ignore
/// let merged = pull_registry(&auths_home, "git://wire.local/registry.git")?;
/// ```
pub fn pull_registry(local_root: &Path, url: &str) -> Result<Vec<MergedKel>, RegistrySyncError> {
    let snapshot = RemoteKelSource::new(url).fetch_snapshot()?;
    let local =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(local_root));
    local.init_if_needed()?;
    let caps = KelCaps {
        max_events: MAX_KEL_EVENTS,
        max_bytes: MAX_KEL_BYTES,
    };
    Ok(merge_registries(snapshot.backend(), &local, &caps)?)
}
