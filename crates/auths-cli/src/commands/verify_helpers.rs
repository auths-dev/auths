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

/// The committed identity bundle, when the repository carries one.
///
/// A repo that commits `.auths/ci-bundle.json` (produced by
/// `auths id export-bundle`) ships its signer's KEL with the code, so a fresh
/// clone verifies with no flags and no network. The bundle stays evidence-only:
/// its root must still match an independently pinned root (`.auths/roots` or
/// self-trust), exactly as with an explicit `--identity-bundle`, which always
/// wins over discovery.
///
/// Usage:
/// ```ignore
/// let bundle = cmd.identity_bundle.clone().or_else(discover_project_bundle);
/// ```
pub fn discover_project_bundle() -> Option<std::path::PathBuf> {
    let output = crate::subprocess::git_command(&["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let bundle = root.join(".auths").join("ci-bundle.json");
    bundle.is_file().then_some(bundle)
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

/// The registry URL to use, or an actionable error when none is configured.
///
/// There is no default registry: auths is offline-first, and the one that used to
/// be baked in (`https://registry.auths.dev`) returned HTTP 404 — a default that
/// looks configured and fails at the network. Registry-dependent verbs resolve
/// through here so the refusal is stated once, at the CLI boundary, in terms of
/// what the user can do about it.
///
/// Args:
/// * `configured`: The value of `--registry` / `AUTHS_REGISTRY_URL`, if any.
///
/// Usage:
/// ```ignore
/// let registry = require_registry(cmd.registry.clone())?;
/// ```
pub fn require_registry(configured: Option<String>) -> Result<String> {
    configured.ok_or_else(|| {
        anyhow!(
            "{}",
            auths_sdk::domains::identity::error::RegistrationError::NoRegistryConfigured
        )
    })
}
