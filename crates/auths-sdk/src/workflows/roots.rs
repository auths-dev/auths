//! Trusted-root pinning — the `roots` allowlist of root `did:keri:` prefixes a
//! verifier accepts as delegation anchors.
//!
//! This is the successor to `allowed_signers` as the **root** of trust. Under the
//! delegation model a commit carries its signer's root in the `Auths-Id` trailer,
//! but that trailer is attacker-controllable: it may only **select** among pinned
//! roots, never **establish** a new one. TOFS on a device is bounded (the root can
//! revoke it); TOFS on the root is unbounded — so the trusted root set is pinned
//! out-of-band in `<auths_dir>/roots`, one `did:keri:` per line (blank lines and
//! `#` comments ignored).

use std::path::{Path, PathBuf};

const ROOTS_FILE: &str = "roots";

/// Path to the pin file within `auths_dir`.
fn roots_path(auths_dir: &Path) -> PathBuf {
    auths_dir.join(ROOTS_FILE)
}

/// Load the pinned trusted-root `did:keri:` set. Empty when the file is absent.
///
/// Blank lines and `#`-prefixed comments are ignored; entries are trimmed.
///
/// Args:
/// * `auths_dir`: Directory holding the `roots` pin file.
///
/// Usage:
/// ```ignore
/// let roots = load_pinned_roots(&auths_dir)?;
/// ```
pub fn load_pinned_roots(auths_dir: &Path) -> std::io::Result<Vec<String>> {
    let path = roots_path(auths_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(parse_roots(&content))
}

/// Parse pin-file content into the trusted-root set (pure; no I/O).
///
/// Args:
/// * `content`: Raw `roots` file contents.
///
/// Usage:
/// ```ignore
/// let roots = parse_roots("did:keri:Eabc\n# note\n\n");
/// assert_eq!(roots, vec!["did:keri:Eabc".to_string()]);
/// ```
pub fn parse_roots(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Whether `did` (a `did:keri:` string) is a pinned trusted root.
///
/// Args:
/// * `auths_dir`: Directory holding the `roots` pin file.
/// * `did`: The candidate root `did:keri:`.
///
/// Usage:
/// ```ignore
/// if is_pinned_root(&auths_dir, &trailer_root_did)? { /* trust it */ }
/// ```
pub fn is_pinned_root(auths_dir: &Path, did: &str) -> std::io::Result<bool> {
    Ok(load_pinned_roots(auths_dir)?.iter().any(|root| root == did))
}

/// Pin a trusted root `did:keri:` (idempotent — never duplicates an existing entry).
///
/// Creates `auths_dir` if needed. Used by `auths init` to seed the local root.
///
/// Args:
/// * `auths_dir`: Directory holding the `roots` pin file.
/// * `did`: The root `did:keri:` to pin.
///
/// Usage:
/// ```ignore
/// add_pinned_root(&auths_dir, &controller_did)?;
/// ```
pub fn add_pinned_root(auths_dir: &Path, did: &str) -> std::io::Result<()> {
    let mut roots = load_pinned_roots(auths_dir)?;
    if roots.iter().any(|root| root == did) {
        return Ok(());
    }
    roots.push(did.to_string());
    std::fs::create_dir_all(auths_dir)?;
    std::fs::write(roots_path(auths_dir), format!("{}\n", roots.join("\n")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roots_ignores_blanks_and_comments() {
        let content = "did:keri:Eaaa\n\n# a comment\n  did:keri:Ebbb  \n";
        assert_eq!(
            parse_roots(content),
            vec!["did:keri:Eaaa".to_string(), "did:keri:Ebbb".to_string()]
        );
    }

    #[test]
    fn add_and_membership_roundtrip() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let dir = tmp.path();

        // Absent file → empty + not pinned.
        assert!(load_pinned_roots(dir).expect("load").is_empty());
        assert!(!is_pinned_root(dir, "did:keri:Eroot").expect("check"));

        add_pinned_root(dir, "did:keri:Eroot").expect("add");
        assert!(is_pinned_root(dir, "did:keri:Eroot").expect("check pinned"));
        assert!(!is_pinned_root(dir, "did:keri:Eother").expect("check unpinned"));

        // Idempotent.
        add_pinned_root(dir, "did:keri:Eroot").expect("add again");
        assert_eq!(load_pinned_roots(dir).expect("load").len(), 1);

        // A second distinct root.
        add_pinned_root(dir, "did:keri:Esecond").expect("add second");
        assert_eq!(load_pinned_roots(dir).expect("load").len(), 2);
    }
}
