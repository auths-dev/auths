/// Contract test suite for [`ArtifactSource`] implementations.
///
/// Args:
/// * `$name` — identifier for the generated module.
/// * `$setup` — expression that returns `(impl ArtifactSource, _guard)`.
///
/// Usage:
/// ```ignore
/// artifact_source_contract_tests!(
///     fake,
///     { (FakeArtifactSource::new("test.bin", "sha256", "abc123", 42), ()) },
/// );
/// ```
#[macro_export]
macro_rules! artifact_source_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use $crate::ports::artifact::ArtifactSource as _;

            use super::*;

            #[test]
            fn contract_digest_returns_valid_result() {
                let (source, _guard) = $setup;
                let digest = source.digest().unwrap();
                assert!(
                    !digest.algorithm.is_empty(),
                    "digest algorithm should not be empty"
                );
                assert!(!digest.hex.is_empty(), "digest hex should not be empty");
            }

            #[test]
            fn contract_digest_is_deterministic() {
                let (source, _guard) = $setup;
                let d1 = source.digest().unwrap();
                let d2 = source.digest().unwrap();
                assert_eq!(d1, d2, "consecutive digest calls should return same value");
            }

            #[test]
            fn contract_metadata_returns_valid_result() {
                let (source, _guard) = $setup;
                let meta = source.metadata().unwrap();
                assert!(
                    !meta.artifact_type.is_empty(),
                    "artifact_type should not be empty"
                );
                assert_eq!(
                    meta.digest,
                    source.digest().unwrap(),
                    "metadata digest should match direct digest call"
                );
            }
        }
    };
}
