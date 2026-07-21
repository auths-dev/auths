//! Registry sync: populate the witness's `--registry` with the parties' public
//! KELs by fetching the custom `refs/auths/*` namespace.
//!
//! The anchor role resolves a submitter's keys from the per-prefix KEL refs
//! (`refs/auths/kel/<s1>/<prefix>`) and the aggregated `refs/auths/registry`
//! tree (see [`crate::registry`]). A plain `git clone` only fetches
//! `refs/heads/*` + tags, so it leaves that namespace — and therefore every
//! identity — absent, which is why an operator who "cloned" the registry still
//! 422s every submission. This fetches the `refs/auths/*` namespace explicitly,
//! in-process (git2's own HTTPS transport — no `git` binary needed), mirroring
//! the SDK's `fetch_registry`. Witness→witness, this is replication: each
//! node's write bridge populates its own per-prefix refs, and peers pick them
//! up with the same one fetch.

use std::path::Path;

use crate::registry::registry_ready;

/// Ensure `registry` is an initialized git repo (idempotent).
///
/// An empty registry is a valid state — a witness with no members yet — so this
/// is what lets a fresh node (the first in a network, with no peer to sync from)
/// bootstrap cleanly: it starts serving/resolving an empty `refs/auths/*` that
/// receipts, a later peer sync, or a maintainer push then populate. `git init`
/// on an existing repo is a no-op, so this is safe to call on every start.
///
/// Args:
/// * `registry`: the local dir the node reads/serves with `--registry`.
pub fn ensure_registry(registry: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(registry)
        .map_err(|e| anyhow::anyhow!("create registry dir {}: {e}", registry.display()))?;
    git2::Repository::init(registry)
        .map_err(|e| anyhow::anyhow!("init registry dir {}: {e}", registry.display()))?;
    Ok(())
}

/// Fetch or refresh the parties' public registry at `registry` from `url`.
///
/// Idempotent: creates and initializes the repo if absent, then force-fetches
/// `refs/auths/*` (the namespace [`crate::registry`] reads). Confirms the
/// result is an openable, resolvable registry before returning. An EMPTY
/// remote namespace is a valid sync (a fresh peer with no members yet — the
/// write path populates it); only an unopenable repo or a storage fault fails
/// here.
///
/// Args:
/// * `url`: the aggregated registry's git URL (must expose `refs/auths/*`).
/// * `registry`: the local dir the node serves with `--registry`.
///
/// Usage:
/// ```ignore
/// sync_registry("https://github.com/auths-dev/registry", Path::new("/data/registry"))?;
/// ```
pub fn sync_registry(url: &str, registry: &Path) -> anyhow::Result<()> {
    ensure_registry(registry)?;
    let repo = git2::Repository::open(registry)
        .map_err(|e| anyhow::anyhow!("open registry dir {}: {e}", registry.display()))?;
    let mut remote = repo
        .remote_anonymous(url)
        .map_err(|e| anyhow::anyhow!("open remote {url}: {e}"))?;
    // Force-fetch the custom namespace the backend reads. NOT a plain clone.
    remote
        .fetch(&["+refs/auths/*:refs/auths/*"], None, None)
        .map_err(|e| anyhow::anyhow!("fetch refs/auths/* from {url}: {e}"))?;
    drop(remote);
    registry_ready(registry).map_err(|e| {
        anyhow::anyhow!(
            "registry synced from {url} but is not resolvable \
             (does the remote expose refs/auths/*?): {e}"
        )
    })?;
    Ok(())
}
