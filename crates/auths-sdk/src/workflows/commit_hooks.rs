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
///
/// The pin block is a **repair path only** — `auths init` owns pinning and staging
/// via `roots::pin_root_in_repo`. It exists for repos entered after init ran
/// elsewhere. Two constraints shape it, both learned the hard way:
///
/// 1. It keys off **tracked-ness, not existence**. The previous version skipped
///    when `.auths/roots` merely existed — which `auths init` had just created —
///    so the pin was never staged and never travelled.
/// 2. A `git add` here lands in the **next** commit, not this one: git has already
///    snapshotted the index by the time `prepare-commit-msg` runs. The message says
///    so rather than claiming otherwise.
pub const PREPARE_COMMIT_MSG_HOOK: &str = r#"#!/bin/sh
# auths prepare-commit-msg hook v2 — managed by `auths init`, checked by
# `auths doctor`. Injects the Auths-Id / Auths-Device trailers so `auths verify`
# can replay the signer's KEL, and repairs a missing/untracked .auths/roots trust
# pin (the committed trust declaration teammates and CI inherit).
# Chains to the repo's own hook when one exists.

MSG_FILE="$1"
AUTHS_HOME="${AUTHS_HOME:-${AUTHS_REPO:-$HOME/.auths}}"
TRAILERS="$AUTHS_HOME/commit-trailers"

if [ -f "$TRAILERS" ]; then
    TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)"
    if [ -n "$TOPLEVEL" ] && [ -f "$AUTHS_HOME/root-pin" ]; then
        PIN="$TOPLEVEL/.auths/roots"
        [ -e "$PIN" ] || {
            mkdir -p "$TOPLEVEL/.auths" && cp "$AUTHS_HOME/root-pin" "$PIN"
        }
        # Stage only when git isn't tracking it yet. This lands in the NEXT commit:
        # git snapshotted the index before this hook ran.
        if [ -e "$PIN" ] && ! git ls-files --error-unmatch -- "$PIN" >/dev/null 2>&1; then
            git add -- "$PIN" >/dev/null 2>&1 &&
                echo "auths: staged .auths/roots — your trust pin lands in your next commit" >&2
        fi
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

/// The managed `pre-push` hook. Exists only to chain: `core.hooksPath`
/// *replaces* `.git/hooks`, so a managed hook that did not chain would silently
/// disable every repo-local pre-push (husky, pre-commit, prek) on the machine.
///
/// It used to mirror `refs/auths/registry` to the push remote, but that mirror
/// silently no-oped against real (ssh/https) remotes — the CLI's git layer links
/// no network transport — so the published ref drifted from the signer's real
/// KEL. KEL distribution is the committed identity bundle now
/// (`auths id export-bundle` → `.auths/ci-bundle.json`), which travels with the
/// code and needs no side-channel push.
pub const PRE_PUSH_HOOK: &str = r#"#!/bin/sh
# auths pre-push hook v1 — managed by `auths init`, checked by `auths doctor`.
# Chains to the repo's own pre-push hook: core.hooksPath replaces .git/hooks,
# so without this the managed hooks would disable repo-local ones.

REPO_HOOK="$(git rev-parse --git-dir 2>/dev/null)/hooks/pre-push"
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

    /// `core.hooksPath` already points somewhere else — a hook manager owns it.
    #[error(
        "core.hooksPath is already set to {existing} (a hook manager like husky, pre-commit or prek owns it). Auths will not overwrite it: core.hooksPath replaces .git/hooks entirely, so doing so would silently disable every hook it installed. Copy the auths prepare-commit-msg and pre-push hooks from {wanted} into {existing}, or re-run with --git-scope skip and wire them yourself."
    )]
    HooksPathOccupied {
        /// The path already configured.
        existing: String,
        /// The managed hooks directory auths wanted to point at.
        wanted: String,
    },
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

/// Write a hook script and mark it executable (no-op on non-unix).
fn write_executable(path: &Path, content: &str) -> Result<(), CommitHookError> {
    write_file(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(
            |source| CommitHookError::Write {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
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

/// Path of the managed `pre-push` hook file under `auths_home`.
///
/// Args:
/// * `auths_home`: The auths data directory (`~/.auths` or a CI registry path).
///
/// Usage:
/// ```ignore
/// let hook = pre_push_hook_path(&auths_home);
/// ```
pub fn pre_push_hook_path(auths_home: &Path) -> PathBuf {
    auths_home.join(HOOKS_DIR).join("pre-push")
}

/// Whether both managed hook files exist with the current script content.
///
/// Covers `prepare-commit-msg` *and* `pre-push`: a stale or missing pre-push
/// means the signer's KEL never reaches the remote, which `auths doctor` should
/// surface as an actionable "re-run auths init" rather than a silent gap.
///
/// Args:
/// * `auths_home`: The auths data directory.
///
/// Usage:
/// ```ignore
/// if !hook_is_current(&auths_home) { /* doctor: re-run auths init */ }
/// ```
pub fn hook_is_current(auths_home: &Path) -> bool {
    let matches = |path: PathBuf, expected: &str| {
        std::fs::read_to_string(path)
            .map(|content| content == expected)
            .unwrap_or(false)
    };
    matches(hook_path(auths_home), PREPARE_COMMIT_MSG_HOOK)
        && matches(pre_push_hook_path(auths_home), PRE_PUSH_HOOK)
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
    write_executable(&hook_path(auths_home), PREPARE_COMMIT_MSG_HOOK)?;
    write_executable(&pre_push_hook_path(auths_home), PRE_PUSH_HOOK)?;
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

    // Never clobber a core.hooksPath we did not write. `core.hooksPath` *replaces*
    // .git/hooks, so pointing it at ours would silently disable every hook a
    // manager (husky, pre-commit, prek) had installed — a class of breakage the
    // user would experience as "my pre-commit checks stopped running" with nothing
    // to connect it to `auths init`. Refuse, and let the caller explain.
    if let Some(existing) = git_config.get("core.hooksPath")?
        && existing != hooks_dir_str
    {
        return Err(CommitHookError::HooksPathOccupied {
            existing,
            wanted: hooks_dir_str.to_string(),
        });
    }

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

    /// The hook must key the pin repair off *tracked-ness*, not existence. The v1
    /// hook skipped whenever `.auths/roots` existed — which `auths init` had just
    /// created — so the pin was never staged and third-party verification was
    /// impossible. Guard the fix so it cannot silently regress.
    #[test]
    fn hook_repairs_pin_on_tracked_ness_not_existence() {
        assert!(
            PREPARE_COMMIT_MSG_HOOK.contains("ls-files --error-unmatch"),
            "pin repair must test tracked-ness, not mere existence"
        );
        assert!(
            !PREPARE_COMMIT_MSG_HOOK.contains("[ ! -e \"$TOPLEVEL/.auths/roots\" ]"),
            "the v1 existence guard defeated the mechanism it guarded"
        );
    }

    /// `git add` inside prepare-commit-msg lands in the NEXT commit — git has
    /// already snapshotted the index. The hook must not claim otherwise.
    #[test]
    fn hook_does_not_claim_the_pin_lands_in_this_commit() {
        assert!(
            !PREPARE_COMMIT_MSG_HOOK.contains("committed with this commit"),
            "false: a git add here lands in the next commit, not this one"
        );
        assert!(
            PREPARE_COMMIT_MSG_HOOK.contains("next commit"),
            "the hook must tell the truth about when the pin lands"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hook_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().expect("temp dir");
        install_commit_hooks(tmp.path(), "did:keri:Eroot", "did:keri:Edevice").expect("install");
        for path in [hook_path(tmp.path()), pre_push_hook_path(tmp.path())] {
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "{} must be executable", path.display());
        }
    }

    #[test]
    fn install_writes_the_pre_push_hook() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        install_commit_hooks(tmp.path(), "did:keri:Eroot", "did:keri:Edevice").expect("install");
        let hook = std::fs::read_to_string(pre_push_hook_path(tmp.path())).expect("pre-push");
        assert_eq!(hook, PRE_PUSH_HOOK);
        assert!(hook_is_current(tmp.path()));
    }

    #[test]
    fn stale_pre_push_is_detected_by_hook_is_current() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        install_commit_hooks(tmp.path(), "did:keri:Eroot", "did:keri:Edevice").expect("install");
        std::fs::write(pre_push_hook_path(tmp.path()), "#!/bin/sh\n# old\n").expect("overwrite");
        assert!(
            !hook_is_current(tmp.path()),
            "a stale pre-push means the KEL never reaches the remote; doctor must see it"
        );
    }

    /// `core.hooksPath` *replaces* `.git/hooks`, so a managed hook that does not
    /// chain silently disables every repo-local hook on the machine (husky,
    /// pre-commit, prek). Both managed hooks must exec the repo's own.
    #[test]
    fn managed_hooks_chain_to_the_repos_own_hook() {
        for (name, hook) in [
            ("prepare-commit-msg", PREPARE_COMMIT_MSG_HOOK),
            ("pre-push", PRE_PUSH_HOOK),
        ] {
            assert!(
                hook.contains(&format!("hooks/{name}")) && hook.contains("exec \"$REPO_HOOK\""),
                "{name} must chain to the repo's own hook"
            );
        }
    }

    /// `core.hooksPath` *replaces* `.git/hooks`, so pointing it at ours when a hook
    /// manager already owns it silently disables every hook that manager installed.
    /// The user experiences that as "my pre-commit checks stopped running", with
    /// nothing connecting it to `auths init`. Refuse, and say what to do instead.
    #[test]
    fn enable_refuses_to_clobber_a_hook_managers_hooks_path() {
        use crate::testing::fakes::FakeGitConfigProvider;

        let tmp = tempfile::TempDir::new().expect("temp dir");
        let git_config = FakeGitConfigProvider::new();
        git_config
            .set("core.hooksPath", "/repo/.husky")
            .expect("pre-existing hook manager");

        let err = enable_commit_trailers(
            tmp.path(),
            "did:keri:Eroot",
            "did:keri:Edevice",
            &git_config,
        )
        .expect_err("must refuse to clobber");

        assert!(matches!(err, CommitHookError::HooksPathOccupied { .. }));
        assert_eq!(
            GitConfigProvider::get(&git_config, "core.hooksPath").expect("get"),
            Some("/repo/.husky".to_string()),
            "the hook manager's path must survive untouched"
        );
        // The message has to be actionable, not just a refusal.
        let msg = err.to_string();
        assert!(msg.contains("/repo/.husky") && msg.contains("--git-scope skip"));
    }

    #[test]
    fn enable_is_idempotent_when_hooks_path_is_already_ours() {
        use crate::testing::fakes::FakeGitConfigProvider;

        let tmp = tempfile::TempDir::new().expect("temp dir");
        let ours = tmp.path().join(HOOKS_DIR);
        let git_config = FakeGitConfigProvider::new();
        git_config
            .set("core.hooksPath", &ours.to_string_lossy())
            .expect("ours already");

        enable_commit_trailers(
            tmp.path(),
            "did:keri:Eroot",
            "did:keri:Edevice",
            &git_config,
        )
        .expect("re-running init over our own config must be fine");
    }

    /// The pre-push hook chains and never blocks: no mirror, no network, no
    /// side effects — its whole job is keeping repo-local hooks alive under
    /// core.hooksPath.
    #[test]
    fn pre_push_only_chains_and_exits_clean() {
        assert!(
            PRE_PUSH_HOOK.contains("hooks/pre-push"),
            "the managed hook must chain to the repo-local pre-push"
        );
        assert!(
            PRE_PUSH_HOOK.trim_end().ends_with("exit 0"),
            "a missing repo hook must exit clean, never fail the push"
        );
        assert!(
            !PRE_PUSH_HOOK.contains("registry push"),
            "the mirror is gone — KEL distribution is the committed bundle, not a pushed ref"
        );
    }
}
