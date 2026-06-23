//! Guardrail: a storage-touching command must not silently ignore the global `--repo` flag.
//!
//! The `--repo` confused-deputy class recurred because nothing enforced the rule — several commands
//! resolved storage from the default location and dropped `--repo`, so an operator's per-repo scoping was
//! silently ignored. This test walks the command sources and fails the build if a file that touches a
//! storage backend neither resolves `--repo` (`resolve_repo_path` / `repo_path`) nor explicitly rejects
//! it. New storage commands therefore cannot regress this class without a deliberate, reviewed exemption.

use std::fs;
use std::path::{Path, PathBuf};

/// Markers that a file talks to a real storage backend (registry, keychain, or pin store).
const STORAGE_MARKERS: &[&str] = &[
    "PinnedIdentityStore::new",
    "get_platform_keychain",
    "build_auths_context",
    "GitRegistryBackend::",
    "resolve_registry_path",
];

/// Markers that a file is `--repo`-aware: it threads the override (directly, or via an `env_config`
/// whose `auths_home` the command entry already resolved from `--repo`) or deliberately rejects it.
const REPO_AWARE: &[&str] = &[
    "resolve_repo_path", "repo_path", "repo_opt", "ctx.repo", "--repo", "auths_home_with_config",
];

/// Storage-touching command sources with a known, reviewed reason for not threading `--repo`, matched by
/// path suffix under `commands/`. Adding an entry requires a reason — this list is the audit trail of
/// `--repo` exceptions, not a place to hide new ones.
const EXEMPT: &[(&str, &str)] = &[
    ("verify_commit.rs", "read-only verification; reads pinned roots from the resolved registry"),
    ("artifact/verify.rs", "read-only artifact verification"),
    ("device/verify_attestation.rs", "read-only device-attestation verification (pin lookup)"),
    ("device/pair/common.rs", "pairing internals; the store is resolved by the command entry"),
    ("multi_sig.rs", "multi-sig session storage; --repo applicability under review"),
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn storage_commands_handle_repo_flag() {
    let cmd_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    let mut files = Vec::new();
    rs_files(&cmd_dir, &mut files);
    assert!(!files.is_empty(), "no command sources found under {cmd_dir:?}");

    let mut offenders = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(&cmd_dir).unwrap_or(f).to_string_lossy().replace('\\', "/");
        let body = fs::read_to_string(f).unwrap_or_default();
        let touches_storage = STORAGE_MARKERS.iter().any(|m| body.contains(m));
        let repo_aware = REPO_AWARE.iter().any(|m| body.contains(m));
        let exempt = EXEMPT.iter().any(|(suffix, _)| rel.ends_with(suffix));
        if touches_storage && !repo_aware && !exempt {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "these commands touch storage but neither resolve nor reject `--repo` \
         (thread `resolve_repo_path`, or add a reviewed entry to EXEMPT): {offenders:?}"
    );
}
