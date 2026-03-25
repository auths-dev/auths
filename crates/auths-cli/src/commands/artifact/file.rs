//! File artifact adapter.
//!
//! Re-exports `LocalFileArtifact` from the adapters layer for
//! backwards compatibility with existing command code.

pub use crate::adapters::local_file::LocalFileArtifact as FileArtifact;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_sdk::ports::artifact::ArtifactSource;
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn file_artifact_digest_is_deterministic() {
        let cap_root = capsec::test_root();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();

        let a = FileArtifact::new(tmp.path(), cap_root.fs_read().make_send());
        let d1 = a.digest().unwrap();
        let d2 = a.digest().unwrap();

        assert_eq!(d1, d2);
        assert_eq!(d1.algorithm, "sha256");
        assert_eq!(
            d1.hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn file_artifact_metadata_includes_name_and_size() {
        let cap_root = capsec::test_root();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"some content").unwrap();
        tmp.flush().unwrap();

        let a = FileArtifact::new(tmp.path(), cap_root.fs_read().make_send());
        let meta = a.metadata().unwrap();

        assert_eq!(meta.artifact_type, "file");
        assert!(meta.name.is_some());
        assert_eq!(meta.size, Some(12));
    }

    #[test]
    fn file_artifact_nonexistent_returns_error() {
        let cap_root = capsec::test_root();
        let a = FileArtifact::new(
            Path::new("/nonexistent/path/to/file.txt"),
            cap_root.fs_read().make_send(),
        );
        assert!(a.digest().is_err());
    }
}
