//! Registry sync: populate the witness's `--registry` with the parties' public
//! KELs by fetching the custom `refs/auths/*` namespace.
//!
//! The anchor role resolves a submitter's keys from the tree at
//! `refs/auths/registry` (see [`crate::registry`]). A plain `git clone` only
//! fetches `refs/heads/*` + tags, so it leaves that ref — and therefore every
//! identity — absent, which is why an operator who "cloned" the registry still
//! 422s every submission. This fetches the `refs/auths/*` namespace explicitly,
//! in-process (git2's own HTTPS transport — no `git` binary needed), mirroring
//! the SDK's `fetch_registry`.

use std::path::Path;

use crate::registry::registry_ready;

/// Fetch or refresh the parties' public registry at `registry` from `url`.
///
/// Idempotent: creates and initializes the repo if absent, then force-fetches
/// `refs/auths/*` (the namespace [`crate::registry`] reads). Confirms the sync
/// produced a resolvable registry (`refs/auths/registry` present) before
/// returning, so a wrong URL or an empty remote fails loudly here rather than
/// as a later 422 on every submission.
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
    std::fs::create_dir_all(registry)
        .map_err(|e| anyhow::anyhow!("create registry dir {}: {e}", registry.display()))?;
    let repo = git2::Repository::init(registry)
        .map_err(|e| anyhow::anyhow!("init registry dir {}: {e}", registry.display()))?;
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
             (does the remote expose refs/auths/registry?): {e}"
        )
    })?;
    Ok(())
}
