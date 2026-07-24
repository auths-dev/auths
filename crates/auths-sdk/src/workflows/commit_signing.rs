//! Workflow for retrofitting raw Git commits with Auths trailers and signatures.

#![cfg(not(target_arch = "wasm32"))]

use anyhow::{Context, Result, anyhow};
use std::process::Command;

use crate::domains::identity::local::LocalSigner;

/// Build a `git` command with `LC_ALL=C` pre-set.
fn git_command(args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(args).env("LC_ALL", "C");
    cmd
}

/// Reject capability scope values that carry control characters.
fn validate_scope(scope: &[String]) -> Result<()> {
    for value in scope {
        if value.chars().any(char::is_control) {
            anyhow::bail!(
                "Invalid --scope value {value:?}: control characters (including newlines) are not allowed"
            );
        }
    }
    Ok(())
}

/// Build the in-band signer trailers for the local machine's signing identity.
fn commit_trailer_args(signer: &LocalSigner, scope: &[String]) -> Vec<String> {
    let mut trailers = vec![
        format!("Auths-Id: {}", signer.root_did),
        format!("Auths-Device: {}", signer.signer_did),
    ];
    if let Some(seq) = signer.anchor_seq {
        trailers.push(auths_verifier::anchor_seq_trailer(seq));
    }
    if !scope.is_empty() {
        trailers.push(auths_verifier::scope_trailer(scope));
    }
    trailers
}

/// Execute `git rebase --exec` to re-sign a range, embedding the signer trailers
/// per commit (the amend re-signs over the trailered message).
fn execute_git_rebase(base: &str, trailers: &[String]) -> Result<()> {
    let trailer_flags: String = trailers
        .iter()
        .map(|t| format!(" --trailer '{}'", t))
        .collect();
    let exec_cmd = format!(
        "git -c trailer.ifexists=replace commit --amend -C HEAD --no-verify{trailer_flags}"
    );
    let output = git_command(&["rebase", "--exec", &exec_cmd, base])
        .output()
        .context("Failed to spawn git rebase")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to re-sign commits. Check for uncommitted changes or rebase conflicts.\n\nGit reported: {}",
            stderr.trim()
        ));
    }
    Ok(())
}

/// Resolve a git ref/range into the list of commit SHAs the amend rewrote.
fn resolve_signed_range_shas(range: &str) -> Result<Vec<String>> {
    let rev_arg = if range.contains("..") {
        range.to_string()
    } else {
        format!("{range}^!")
    };
    let output = git_command(&["rev-list", &rev_arg])
        .output()
        .context("Failed to list commits to confirm signing")?;
    if !output.status.success() {
        return Err(anyhow!(
            "Could not resolve '{}' to confirm the signature landed.\n\nGit reported: {}",
            range,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// Confirm every commit in `range` actually carries an SSH signature after the amend.
fn ensure_commits_signed(range: &str) -> Result<()> {
    let shas = resolve_signed_range_shas(range)?;
    for sha in &shas {
        let raw = read_raw_commit_object(sha)?;
        if !auths_verifier::commit_object_is_signed(&raw) {
            return Err(anyhow!(
                "Commit {} was amended but no signature was attached, so `auths verify` would \
                 call it unsigned. Configure git SSH signing first — run `auths doctor --fix` \
                 (sets gpg.format=ssh, gpg.ssh.program=auths-sign, commit.gpgsign=true).",
                short_sha(sha)
            ));
        }
    }
    Ok(())
}

/// The raw git commit object using git2.
fn read_raw_commit_object(sha: &str) -> Result<String> {
    let repo = git2::Repository::discover(".").context("failed to discover git repository")?;
    let oid = git2::Oid::from_str(sha).context("invalid SHA format")?;
    let odb = repo.odb().context("failed to get git ODB")?;
    let obj = odb
        .read(oid)
        .context("Failed to read commit object to confirm signing")?;
    String::from_utf8(obj.data().to_vec()).context("Commit object is not valid UTF-8")
}

/// First 8 chars of a SHA for human-readable messages.
fn short_sha(sha: &str) -> &str {
    sha.get(..8).unwrap_or(sha)
}

/// Sign a Git commit range, embedding the `Auths-Id` / `Auths-Device` trailers
/// in-band so a verifier knows which KEL to replay.
pub fn sign_commit_range(
    range: &str,
    signer: &LocalSigner,
    scope: &[String],
    autostash: bool,
) -> Result<()> {
    validate_scope(scope)?;

    let mut stashed = false;
    if autostash
        && let Ok(out) = git_command(&["status", "--porcelain"]).output()
        && !out.stdout.is_empty()
    {
        let _ = git_command(&["stash", "push", "-m", "auths-autostash"]).output();
        stashed = true;
    }

    let trailers = commit_trailer_args(signer, scope);
    let is_range = range.contains("..");
    let res = if is_range {
        let parts: Vec<&str> = range.splitn(2, "..").collect();
        let base = parts[0];
        execute_git_rebase(base, &trailers)
    } else {
        let mut args: Vec<&str> = vec![
            "-c",
            "trailer.ifexists=replace",
            "commit",
            "--amend",
            "--no-edit",
            "--no-verify",
        ];
        for trailer in &trailers {
            args.push("--trailer");
            args.push(trailer);
        }
        let output = git_command(&args)
            .output()
            .context("Failed to spawn git commit --amend")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!(
                "Failed to amend commit with signature. Ensure you have a commit to amend and no conflicting changes.\n\nGit reported: {}",
                stderr.trim()
            ))
        } else {
            Ok(())
        }
    };

    if stashed {
        let _ = git_command(&["stash", "pop"]).output();
    }

    res?;

    // Verify the signatures landed
    ensure_commits_signed(range)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_trailer_args_emit_auths_id_and_device() {
        let signer = LocalSigner {
            signer_did: "did:keri:Edevice".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers[0], "Auths-Id: did:keri:Eroot");
        assert_eq!(trailers[1], "Auths-Device: did:keri:Edevice");
        assert_eq!(
            trailers.len(),
            2,
            "no anchor seq + no scope → only Auths-Id/Auths-Device"
        );
    }

    #[test]
    fn trailer_carries_signing_sequence() {
        let signer = LocalSigner {
            signer_did: "did:keri:Edevice".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: Some(7),
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers.len(), 3);
        assert_eq!(trailers[2], "Auths-Anchor-Seq: 7");
    }

    #[test]
    fn commit_trailer_args_emit_scope_claim() {
        let signer = LocalSigner {
            signer_did: "did:keri:Eagent".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: Some(3),
        };
        let trailers =
            commit_trailer_args(&signer, &["sign_commit".to_string(), "open-PR".to_string()]);
        assert_eq!(trailers.len(), 4);
        assert_eq!(trailers[3], "Auths-Scope: sign_commit,open-PR");
        assert_eq!(
            trailers[3],
            auths_verifier::scope_trailer(&["sign_commit".to_string(), "open-PR".to_string()])
        );
    }

    #[test]
    fn commit_trailer_args_no_scope_omits_trailer() {
        let signer = LocalSigner {
            signer_did: "did:keri:Eagent".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert!(
            !trailers.iter().any(|t| t.starts_with("Auths-Scope")),
            "no scope claim → no Auths-Scope trailer (backward compatible)"
        );
    }

    #[test]
    fn validate_scope_rejects_control_chars() {
        assert!(validate_scope(&["legit\nAuths-Id: did:keri:Eattacker".to_string()]).is_err());
        assert!(validate_scope(&["carriage\rreturn".to_string()]).is_err());
        assert!(validate_scope(&["tab\there".to_string()]).is_err());
        assert!(validate_scope(&["sign_commit".to_string(), "open-PR".to_string()]).is_ok());
        assert!(validate_scope(&[]).is_ok());
    }

    #[test]
    fn commit_trailer_args_root_machine_signs_directly() {
        let signer = LocalSigner {
            signer_did: "did:keri:Eroot".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers[0], "Auths-Id: did:keri:Eroot");
        assert_eq!(trailers[1], "Auths-Device: did:keri:Eroot");
    }
}
