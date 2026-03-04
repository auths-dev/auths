//! Manual test for passphrase cache — run directly, not via nextest.
//! cargo test -p auths-core --test passphrase_cache_manual -- --nocapture

#[cfg(target_os = "macos")]
#[test]
fn test_passphrase_cache_store_and_load_no_biometric() {
    use auths_core::storage::passphrase_cache::get_passphrase_cache;

    let cache = get_passphrase_cache(false);
    let alias = "test-no-bio";
    let _ = cache.delete(alias);

    let result = cache.store(alias, "test-pass", 1700000000);
    assert!(result.is_ok(), "store failed: {:?}", result.err());

    let loaded = cache.load(alias);
    assert!(loaded.is_ok());
    let (pass, ts) = loaded.unwrap().expect("should find cached passphrase");
    assert_eq!(*pass, "test-pass");
    assert_eq!(ts, 1700000000);

    let _ = cache.delete(alias);
}

#[cfg(target_os = "macos")]
#[test]
fn test_passphrase_cache_biometric_falls_back_to_plain() {
    use auths_core::storage::passphrase_cache::get_passphrase_cache;

    // Biometric store will fail with -34018 (missing entitlement) in test binaries,
    // but should fall back to non-biometric storage automatically.
    let cache = get_passphrase_cache(true);
    let alias = "test-bio-fallback";
    let _ = cache.delete(alias);

    let result = cache.store(alias, "bio-pass", 1700000000);
    assert!(
        result.is_ok(),
        "store (with fallback) failed: {:?}",
        result.err()
    );

    let loaded = cache.load(alias);
    assert!(loaded.is_ok());
    let (pass, ts) = loaded.unwrap().expect("fallback should store and load");
    assert_eq!(*pass, "bio-pass");
    assert_eq!(ts, 1700000000);

    let _ = cache.delete(alias);
}
