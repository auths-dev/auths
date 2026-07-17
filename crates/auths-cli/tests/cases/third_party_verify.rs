//! CLI e2e for the property the whole product rests on: **someone who is not the
//! signer can verify.**
//!
//! Every other verification test in this suite runs as the signer, with a populated
//! `~/.auths`. That is exactly why a total failure of this property shipped
//! undetected: `auths init` wrote `<repo>/.auths/roots` but never staged it, so the
//! trust pin never reached a cloner; and nothing mirrored `refs/auths/registry` to
//! the remote, so the KEL never travelled either. A fresh clone failed with "KEL not
//! found" while the engine itself was correct the whole time.
//!
//! These tests play the *second person*: a machine with no auths identity, a plain
//! `git clone`, and no flags. They must keep failing closed when trust is absent.
//!
//! Runs hermetically — `TestEnv`'s keychain is file-backed with `AUTHS_PASSPHRASE`,
//! so signing is non-interactive (no macOS keychain / SIP gate).

use std::path::{Path, PathBuf};

use super::helpers::TestEnv;

/// An identity that has signed HEAD and pushed it to a bare origin.
///
/// Returns the signer's env and the origin path. The push goes through a plain
/// `git push`: the managed pre-push hook is what mirrors `refs/auths/registry`, and
/// this test would be worthless if it pushed the registry by hand.
fn signer_with_pushed_commit() -> (TestEnv, PathBuf) {
    let alice = TestEnv::new();
    alice.init_identity();

    let origin = alice.home.path().join("origin.git");
    let init_bare = std::process::Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&origin)
        .output()
        .unwrap();
    assert!(init_bare.status.success(), "git init --bare failed");

    std::fs::write(alice.repo_path.join("main.rs"), "fn main() {}").unwrap();
    let add = alice.git_cmd().args(["add", "main.rs"]).output().unwrap();
    assert!(add.status.success(), "git add failed");

    // A plain signed commit — no `auths sign`. The pin must ride along on its own.
    let commit = alice
        .git_cmd()
        .args(["commit", "-m", "feat: add main"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let branch = alice
        .git_cmd()
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .unwrap();
    let branch = String::from_utf8_lossy(&branch.stdout).trim().to_string();

    let push = alice
        .git_cmd()
        .arg("push")
        .arg(&origin)
        .arg(&branch)
        .output()
        .unwrap();
    assert!(
        push.status.success(),
        "git push failed: {}",
        String::from_utf8_lossy(&push.stderr)
    );

    // Point the bare repo's HEAD at the branch we pushed, as any real origin does.
    // Without this the clone checks out a branch that does not exist and lands empty.
    let head = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(&origin)
        .args(["symbolic-ref", "HEAD"])
        .arg(format!("refs/heads/{branch}"))
        .output()
        .unwrap();
    assert!(head.status.success(), "could not set origin HEAD");

    (alice, origin)
}

/// A machine with **no auths identity**, holding a plain clone of `origin`.
fn observer_cloning(origin: &Path) -> TestEnv {
    // `TestEnv::new()` never creates an identity — only `init_identity()` does.
    let mut bob = TestEnv::new();
    let clone = bob.home.path().join("clone");
    let out = std::process::Command::new("git")
        .arg("clone")
        .arg("-q")
        .arg(origin)
        .arg(&clone)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git clone failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bob.repo_path = clone;
    bob
}

/// The headline property. No identity, no flags, no setup.
#[test]
fn a_second_person_verifies_a_plain_clone_with_no_identity_and_no_flags() {
    let (_alice, origin) = signer_with_pushed_commit();
    let bob = observer_cloning(&origin);

    let out = bob.cmd("auths").args(["verify", "HEAD"]).output().unwrap();

    assert!(
        out.status.success(),
        "a second person must be able to verify a clone with no flags.\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("verified"),
        "expected a verified verdict, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The pin must be *in the clone* — that is what makes it a trust declaration the
/// repo carries rather than a file on the signer's laptop.
#[test]
fn the_trust_pin_travels_with_the_repository() {
    let (_alice, origin) = signer_with_pushed_commit();
    let bob = observer_cloning(&origin);

    let pin = bob.repo_path.join(".auths").join("roots");
    assert!(
        pin.is_file(),
        ".auths/roots must be committed, or a cloner has nothing to anchor trust to"
    );
    let content = std::fs::read_to_string(&pin).unwrap();
    assert!(
        content.contains("did:keri:"),
        "pin must name a did:keri root, got: {content:?}"
    );
}

/// The KEL must reach the remote the code went to, via the managed pre-push hook —
/// not via a manual `auths registry push`.
#[test]
fn a_plain_push_mirrors_the_registry_to_the_remote() {
    let (alice, origin) = signer_with_pushed_commit();

    let refs = alice
        .git_cmd()
        .arg("ls-remote")
        .arg(&origin)
        .output()
        .unwrap();
    let refs = String::from_utf8_lossy(&refs.stdout);
    assert!(
        refs.contains("refs/auths/registry"),
        "a plain `git push` must mirror the signer's KEL to the remote, got:\n{refs}"
    );
}

/// Fail closed: strip the pin and the same clone must refuse. An `Auths-Id` trailer
/// is attacker-controllable — it may *select* among pinned roots, never *establish*
/// one — so an unpinned root is untrusted no matter how good the signature is.
#[test]
fn an_unpinned_root_still_fails_closed() {
    let (_alice, origin) = signer_with_pushed_commit();
    let bob = observer_cloning(&origin);

    std::fs::remove_file(bob.repo_path.join(".auths").join("roots")).unwrap();

    let out = bob.cmd("auths").args(["verify", "HEAD"]).output().unwrap();

    assert!(
        !out.status.success(),
        "an unpinned root must not verify — this is the TOFU-on-the-root guard.\n\
         stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
