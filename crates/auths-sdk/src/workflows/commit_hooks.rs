//! Commit-time trailer injection — the machinery that makes a plain `git commit`
//! produce a verifiable commit with **zero new verbs**.
//!
//! The `gpg.ssh.program` shim (`auths-sign`) can only return signature bytes; it
//! cannot edit the commit message. The `Auths-Id` / `Auths-Device` trailers that
//! KEL-native verification replays therefore go in at commit time via a
//! `prepare-commit-msg` hook installed under `<auths_home>/githooks` and wired
//! through the global `core.hooksPath`. The hook is deliberately dumb — it reads
//! two static files written at init (no `auths` process spawn per commit):
//!
//! - `<auths_home>/commit-trailers` — the literal trailer lines to inject
//! - `<auths_home>/root-pin`        — the `.auths/roots` content to seed into a
//!   repo on first signed commit (the committed trust declaration teammates and
//!   CI inherit)
//!
//! The hook chains to the repo's own `$GIT_DIR/hooks/prepare-commit-msg` when one
//! exists. Repos that set a *local* `core.hooksPath` (husky-style managers)
//! bypass the global path entirely; `auths doctor` detects that and the
//! missing-trailer verify error explains the remedy.
//!
//! `Auths-Anchor-Seq` is intentionally NOT in the static trailer file: it is the
//! root-KEL tip position *at signing time*, which changes as the KEL grows. The
//! explicit `auths sign <ref>` repair path still embeds it.

use std::path::{Path, PathBuf};

use crate::ports::git_config::{GitConfigError, GitConfigProvider};

/// File under `auths_home` holding the trailer lines the hook injects.
pub const TRAILERS_FILE: &str = "commit-trailers";
/// File under `auths_home` holding the `.auths/roots` seed content.
pub const ROOT_PIN_FILE: &str = "root-pin";
/// Directory under `auths_home` that `core.hooksPath` points at.
pub const HOOKS_DIR: &str = "githooks";

/// The managed `prepare-commit-msg` hook. Version-stamped so `auths doctor` can
/// detect a stale install; bump the version when editing.
pub const PREPARE_COMMIT_MSG_HOOK: &str = r#"#!/bin/sh
# auths prepare-commit-msg hook v1 — managed by `auths init`, checked by
# `auths doctor`. Injects the Auths-Id / Auths-Device trailers so `auths verify`
# can replay the signer's KEL, and seeds the repo's committed .auths/roots trust
# pin on first use. Chains to the repo's own hook when one exists.

MSG_FILE="$1"
AUTHS_HOME="${AUTHS_REPO:-$HOME/.auths}"
TRAILERS="$AUTHS_HOME/commit-trailers"

if [ -f "$TRAILERS" ]; then
    TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)"
    if [ -n "$TOPLEVEL" ] && [ -f "$AUTHS_HOME/root-pin" ] && [ ! -e "$TOPLEVEL/.auths/roots" ]; then
        mkdir -p "$TOPLEVEL/.auths" &&
            cp "$AUTHS_HOME/root-pin" "$TOPLEVEL/.auths/roots" &&
            git add -- "$TOPLEVEL/.auths/roots" >/dev/null 2>&1 &&
            echo "auths: pinned your identity root in .auths/roots (committed with this commit)" >&2
    fi
    while IFS= read -r trailer; do
        case "$trailer" in
        '' | '#'*) ;;
        *) git interpret-trailers --in-place --if-exists replace --trailer "$trailer" "$MSG_FILE" ;;
        esac
    done <"$TRAILERS"
fi

REPO_HOOK="$(git rev-parse --git-dir 2>/dev/null)/hooks/prepare-commit-msg"
if [ -x "$REPO_HOOK" ]; then
    exec "$REPO_HOOK" "$@"
fi
exit 0
"#;

/// Failure installing the commit hook or writing its data files.
#[derive(Debug, thiserror::Error)]
pub enum CommitHookError {
    /// A hook or data file could not be written.
    #[error("could not write {path}: {source}")]
    Write {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Setting `core.hooksPath` failed.
    #[error("could not set core.hooksPath: {0}")]
    GitConfig(#[from] GitConfigError),
    /// The hooks directory path is not representable as UTF-8 for git config.
    #[error("hooks path is not valid UTF-8: {0}")]
    NonUtf8Path(PathBuf),
    /// The local signing identity could not be resolved for a trailer refresh.
    #[error("could not resolve the local signer: {0}")]
    Signer(String),
}

fn write_file(path: &Path, content: &str) -> Result<(), CommitHookError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CommitHookError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, content).map_err(|source| CommitHookError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Path of the managed hook file under `auths_home`.
///
/// Args:
/// * `auths_home`: The auths data directory (`~/.auths` or a CI registry path).
///
/// Usage:
/// ```ignore
/// let hook = hook_path(&auths_home);
/// ```
pub fn hook_path(auths_home: &Path) -> PathBuf {
    auths_home.join(HOOKS_DIR).join("prepare-commit-msg")
}

/// Whether the managed hook file exists with the current script content.
///
/// Args:
/// * `auths_home`: The auths data directory.
///
/// Usage:
/// ```ignore
/// if !hook_is_current(&auths_home) { /* doctor: re-run auths init */ }
/// ```
pub fn hook_is_current(auths_home: &Path) -> bool {
    std::fs::read_to_string(hook_path(auths_home))
        .map(|content| content == PREPARE_COMMIT_MSG_HOOK)
        .unwrap_or(false)
}

/// Install the `prepare-commit-msg` hook under `<auths_home>/githooks` and write
/// the trailer + root-pin data files it reads.
///
/// Idempotent: rewrites the managed files unconditionally (a stale hook version
/// is replaced). Does NOT touch git config — pair with
/// [`enable_commit_trailers`] for the full wiring.
///
/// Args:
/// * `auths_home`: The auths data directory the hook reads from at commit time.
/// * `root_did`: The local identity's root `did:keri:` (the `Auths-Id` value).
/// * `device_did`: This device's DID (the `Auths-Device` value).
///
/// Usage:
/// ```ignore
/// let hooks_dir = install_commit_hooks(&auths_home, &root_did, &device_did)?;
/// ```
pub fn install_commit_hooks(
    auths_home: &Path,
    root_did: &str,
    device_did: &str,
) -> Result<PathBuf, CommitHookError> {
    let hook = hook_path(auths_home);
    write_file(&hook, PREPARE_COMMIT_MSG_HOOK)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).map_err(
            |source| CommitHookError::Write {
                path: hook.clone(),
                source,
            },
        )?;
    }
    write_file(
        &auths_home.join(TRAILERS_FILE),
        &format!("Auths-Id: {root_did}\nAuths-Device: {device_did}\n"),
    )?;
    write_file(
        &auths_home.join(ROOT_PIN_FILE),
        &format!("# Pinned by auths init — the trusted root for this identity.\n{root_did}\n"),
    )?;
    Ok(auths_home.join(HOOKS_DIR))
}

/// Rewrite the trailer data file from the locally-resolved signer, including
/// the current root-KEL position as `Auths-Anchor-Seq`.
///
/// Call this after any operation that advances the root KEL or changes the
/// signing identity — rotation, device add/remove, agent add/revoke, pairing —
/// so hook-stamped commits carry an up-to-date anchor position (the verifier
/// uses it to order commits against later revocations). A missing anchor seq
/// (non-transferable roots) simply omits the line.
///
/// Args:
/// * `ctx`: Auths context (identity storage + registry, read-only).
/// * `auths_home`: The auths data directory holding `commit-trailers`.
///
/// Usage:
/// ```ignore
/// refresh_commit_trailers(&ctx, &auths_home)?;
/// ```
pub fn refresh_commit_trailers(
    ctx: &crate::context::AuthsContext,
    auths_home: &Path,
) -> Result<(), CommitHookError> {
    let signer = crate::domains::identity::local::resolve_local_signer(ctx)
        .map_err(|e| CommitHookError::Signer(e.to_string()))?;
    let mut content = format!(
        "Auths-Id: {}\nAuths-Device: {}\n",
        signer.root_did, signer.signer_did
    );
    if let Some(seq) = signer.anchor_seq {
        content.push_str(&format!("{}\n", auths_verifier::anchor_seq_trailer(seq)));
    }
    write_file(&auths_home.join(TRAILERS_FILE), &content)?;
    write_file(
        &auths_home.join(ROOT_PIN_FILE),
        &format!(
            "# Pinned by auths init — the trusted root for this identity.\n{}\n",
            signer.root_did
        ),
    )
}

/// Full commit-trailer wiring: install the hook + data files and point
/// `core.hooksPath` at the managed hooks directory.
///
/// After this, a plain `git commit` produces a commit `auths verify` can replay —
/// no extra commands, no per-repo setup.
///
/// Args:
/// * `auths_home`: The auths data directory.
/// * `root_did`: The local identity's root `did:keri:`.
/// * `device_did`: This device's DID.
/// * `git_config`: Git configuration provider (global or local scope).
///
/// Usage:
/// ```ignore
/// enable_commit_trailers(&auths_home, &root_did, &device_did, git_config)?;
/// ```
pub fn enable_commit_trailers(
    auths_home: &Path,
    root_did: &str,
    device_did: &str,
    git_config: &dyn GitConfigProvider,
) -> Result<(), CommitHookError> {
    let hooks_dir = install_commit_hooks(auths_home, root_did, device_did)?;
    let hooks_dir_str = hooks_dir
        .to_str()
        .ok_or_else(|| CommitHookError::NonUtf8Path(hooks_dir.clone()))?;
    git_config.set("core.hooksPath", hooks_dir_str)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_writes_hook_and_data_files() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let home = tmp.path();
        let hooks_dir =
            install_commit_hooks(home, "did:keri:Eroot", "did:keri:Edevice").expect("install");
        assert_eq!(hooks_dir, home.join(HOOKS_DIR));
        assert!(hook_is_current(home));
        let trailers = std::fs::read_to_string(home.join(TRAILERS_FILE)).expect("trailers");
        assert_eq!(
            trailers,
            "Auths-Id: did:keri:Eroot\nAuths-Device: did:keri:Edevice\n"
        );
        let pin = std::fs::read_to_string(home.join(ROOT_PIN_FILE)).expect("pin");
        assert!(pin.lines().any(|l| l == "did:keri:Eroot"));
    }

    #[test]
    fn stale_hook_is_not_current_and_reinstall_replaces_it() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let home = tmp.path();
        install_commit_hooks(home, "did:keri:Eroot", "did:keri:Edevice").expect("install");
        std::fs::write(hook_path(home), "#!/bin/sh\n# old version\n").expect("overwrite");
        assert!(!hook_is_current(home));
        install_commit_hooks(home, "did:keri:Eroot", "did:keri:Edevice").expect("reinstall");
        assert!(hook_is_current(home));
    }

    #[cfg(unix)]
    #[test]
    fn hook_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().expect("temp dir");
        install_commit_hooks(tmp.path(), "did:keri:Eroot", "did:keri:Edevice").expect("install");
        let mode = std::fs::metadata(hook_path(tmp.path()))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "hook must be executable");
    }
}
