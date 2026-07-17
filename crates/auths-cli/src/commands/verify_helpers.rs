use anyhow::{Context, Result, anyhow};

/// The project's pinned trusted roots, read from `<git-toplevel>/.auths/roots` — the
/// committed trust declaration seeded by `auths init`. Empty when run outside a repo or
/// when nothing is pinned (so every commit is `RootNotPinned` until a root is pinned).
///
/// Usage:
/// ```ignore
/// let roots = load_project_pinned_roots();
/// ```
pub fn load_project_pinned_roots() -> Vec<String> {
    let Ok(output) = crate::subprocess::git_command(&["rev-parse", "--show-toplevel"]).output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let root = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    auths_sdk::workflows::roots::load_pinned_roots(
        &crate::adapters::config_store::FileConfigStore,
        &root.join(".auths"),
    )
    .unwrap_or_default()
}

/// The current repository's `origin` URL, when there is one.
///
/// Used as the default KEL transport: a repo carries its signer's KEL on the same
/// remote it carries its code (the managed `pre-push` hook mirrors
/// `refs/auths/registry` there), but a plain `git clone` fetches only
/// `refs/heads/*` and `refs/tags/*` — so the ref is on the remote and not in the
/// clone. Without this, `auths verify` in a fresh clone fails with "KEL not found"
/// while the KEL sits one fetch away on the remote it was cloned from.
///
/// Resolution stays local-first: the chain only reaches for the remote when the
/// KEL is absent locally, and the local registry remains the trusted floor.
///
/// Usage:
/// ```ignore
/// let fallback = repo_origin_url();
/// ```
pub fn repo_origin_url() -> Option<String> {
    let output = crate::subprocess::git_command(&["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!url.is_empty()).then_some(url)
}

/// The human-readable label for a surfaced freshness verdict (ADR 009).
///
/// Shared by every verify command so an offline verdict renders "freshness unknown"
/// identically across the CLI — never a bare success that reads as real-time fresh.
///
/// Args:
/// * `freshness`: the verdict's classified freshness.
///
/// Usage:
/// ```ignore
/// let label = freshness_label(report.freshness());
/// ```
pub fn freshness_label(freshness: auths_verifier::Freshness) -> &'static str {
    match freshness {
        auths_verifier::Freshness::Fresh => "fresh",
        auths_verifier::Freshness::Unknown => "unknown",
        auths_verifier::Freshness::Stale => "stale",
    }
}

/// Parse witness key arguments ("did:key:z6Mk...:abcd1234...") into (DID, pk_bytes) tuples.
pub fn parse_witness_keys(keys: &[String]) -> Result<Vec<(String, Vec<u8>)>> {
    keys.iter()
        .map(|s| {
            // Find the last ':' to split DID from hex key
            let last_colon = s
                .rfind(':')
                .ok_or_else(|| anyhow!("Invalid witness key format '{}': expected format: <did>:<public_key_hex> (e.g. did:key:z6Mk...:abcd1234)", s))?;
            let did = &s[..last_colon];
            let pk_hex = &s[last_colon + 1..];
            let pk_bytes = hex::decode(pk_hex)
                .with_context(|| format!("Invalid hex in witness key for '{}'", did))?;
            Ok((did.to_string(), pk_bytes))
        })
        .collect()
}
