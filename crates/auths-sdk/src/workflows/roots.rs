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

use auths_verifier::IdentityDID;

use crate::ports::{ConfigStore, ConfigStoreError};

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
/// * `store`: File-access port for the pin file.
/// * `auths_dir`: Directory holding the `roots` pin file.
///
/// Usage:
/// ```ignore
/// let roots = load_pinned_roots(&store, &auths_dir)?;
/// ```
pub fn load_pinned_roots(
    store: &dyn ConfigStore,
    auths_dir: &Path,
) -> Result<Vec<String>, ConfigStoreError> {
    match store.read(&roots_path(auths_dir))? {
        Some(content) => Ok(parse_roots(&content)),
        None => Ok(Vec::new()),
    }
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
/// * `store`: File-access port for the pin file.
/// * `auths_dir`: Directory holding the `roots` pin file.
/// * `did`: The candidate root `did:keri:`.
///
/// Usage:
/// ```ignore
/// if is_pinned_root(&store, &auths_dir, &trailer_root_did)? { /* trust it */ }
/// ```
pub fn is_pinned_root(
    store: &dyn ConfigStore,
    auths_dir: &Path,
    did: &str,
) -> Result<bool, ConfigStoreError> {
    Ok(load_pinned_roots(store, auths_dir)?
        .iter()
        .any(|root| root == did))
}

/// Pin a trusted root `did:keri:` (idempotent — never duplicates an existing entry).
///
/// Creates `auths_dir` if needed (the store's `write` creates parent directories).
/// Used by `auths init` to seed the local root.
///
/// Args:
/// * `store`: File-access port for the pin file.
/// * `auths_dir`: Directory holding the `roots` pin file.
/// * `did`: The root `did:keri:` to pin.
///
/// Usage:
/// ```ignore
/// add_pinned_root(&store, &auths_dir, &controller_did)?;
/// ```
pub fn add_pinned_root(
    store: &dyn ConfigStore,
    auths_dir: &Path,
    did: &str,
) -> Result<(), ConfigStoreError> {
    let mut roots = load_pinned_roots(store, auths_dir)?;
    if roots.iter().any(|root| root == did) {
        return Ok(());
    }
    roots.push(did.to_string());
    store.write(&roots_path(auths_dir), &format!("{}\n", roots.join("\n")))
}

/// Failure loading the typed pinned-root set: a line that is not a well-formed
/// `did:keri:` identity DID is rejected (fail-closed) rather than silently skipped.
#[derive(Debug, thiserror::Error)]
pub enum RootsError {
    /// The `roots` pin file could not be read.
    #[error("could not read roots pin file: {0}")]
    Store(#[from] ConfigStoreError),

    /// A non-comment, non-blank line is not a valid `did:keri:` root.
    #[error("roots pin line {line} ({value:?}) is not a valid did:keri: root: {source}")]
    MalformedRoot {
        /// 1-based line number in the pin file.
        line: usize,
        /// The offending (trimmed) line content.
        value: String,
        /// The underlying DID parse error.
        #[source]
        source: auths_verifier::DidParseError,
    },
}

/// Parse pin-file content into typed trusted-root identities (pure; no I/O).
///
/// Each non-blank, non-`#` line must be a well-formed `did:keri:` identity DID;
/// a malformed line fails closed with [`RootsError::MalformedRoot`]. The pin file
/// names **identities only** — capabilities come from the presented credential's
/// scope seal, never this file.
///
/// Args:
/// * `content`: Raw `roots` file contents.
///
/// Usage:
/// ```ignore
/// let roots = parse_roots_typed("did:keri:Eabc\n")?;
/// ```
pub fn parse_roots_typed(content: &str) -> Result<Vec<IdentityDID>, RootsError> {
    content
        .lines()
        .enumerate()
        .map(|(idx, raw)| (idx + 1, raw.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(line, value)| {
            IdentityDID::parse(value).map_err(|source| RootsError::MalformedRoot {
                line,
                value: value.to_string(),
                source,
            })
        })
        .collect()
}

/// Load the pinned trusted-root set as typed [`IdentityDID`]s, failing closed on a
/// malformed line. Empty when the file is absent.
///
/// This is the typed successor to [`load_pinned_roots`]: the relying-party middleware
/// pins delegation anchors by parsed identity, so a malformed pin is a hard error at
/// load rather than a silently-dropped root.
///
/// Args:
/// * `store`: File-access port for the pin file.
/// * `auths_dir`: Directory holding the `roots` pin file.
///
/// Usage:
/// ```ignore
/// let roots = load_pinned_roots_typed(&store, &auths_dir)?;
/// ```
pub fn load_pinned_roots_typed(
    store: &dyn ConfigStore,
    auths_dir: &Path,
) -> Result<Vec<IdentityDID>, RootsError> {
    match store.read(&roots_path(auths_dir))? {
        Some(content) => parse_roots_typed(&content),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FsStore;

    impl ConfigStore for FsStore {
        fn read(&self, path: &Path) -> Result<Option<String>, ConfigStoreError> {
            match std::fs::read_to_string(path) {
                Ok(content) => Ok(Some(content)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(ConfigStoreError::Read {
                    path: path.to_path_buf(),
                    source: e,
                }),
            }
        }

        fn write(&self, path: &Path, content: &str) -> Result<(), ConfigStoreError> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ConfigStoreError::Write {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            }
            std::fs::write(path, content).map_err(|e| ConfigStoreError::Write {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }

    #[test]
    fn parse_roots_ignores_blanks_and_comments() {
        let content = "did:keri:Eaaa\n\n# a comment\n  did:keri:Ebbb  \n";
        assert_eq!(
            parse_roots(content),
            vec!["did:keri:Eaaa".to_string(), "did:keri:Ebbb".to_string()]
        );
    }

    #[test]
    fn typed_roots_parse_valid_did_keri() {
        let roots = parse_roots_typed("did:keri:Eaaa\n# c\n  did:keri:Ebbb \n").expect("parse");
        assert_eq!(
            roots.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            ["did:keri:Eaaa", "did:keri:Ebbb"]
        );
    }

    #[test]
    fn typed_roots_reject_malformed_line_fail_closed() {
        // A non-did:keri line is a hard error (with its line number), never skipped.
        let err = parse_roots_typed("did:keri:Eaaa\nnot-a-did\n").expect_err("must fail closed");
        assert!(
            matches!(err, RootsError::MalformedRoot { line: 2, .. }),
            "expected MalformedRoot at line 2, got {err:?}"
        );
    }

    #[test]
    fn typed_roots_absent_file_is_empty() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        assert!(
            load_pinned_roots_typed(&FsStore, tmp.path())
                .expect("load")
                .is_empty()
        );
    }

    #[test]
    fn add_and_membership_roundtrip() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let dir = tmp.path();
        let store = FsStore;

        // Absent file → empty + not pinned.
        assert!(load_pinned_roots(&store, dir).expect("load").is_empty());
        assert!(!is_pinned_root(&store, dir, "did:keri:Eroot").expect("check"));

        add_pinned_root(&store, dir, "did:keri:Eroot").expect("add");
        assert!(is_pinned_root(&store, dir, "did:keri:Eroot").expect("check pinned"));
        assert!(!is_pinned_root(&store, dir, "did:keri:Eother").expect("check unpinned"));

        // Idempotent.
        add_pinned_root(&store, dir, "did:keri:Eroot").expect("add again");
        assert_eq!(load_pinned_roots(&store, dir).expect("load").len(), 1);

        // A second distinct root.
        add_pinned_root(&store, dir, "did:keri:Esecond").expect("add second");
        assert_eq!(load_pinned_roots(&store, dir).expect("load").len(), 2);
    }
}
