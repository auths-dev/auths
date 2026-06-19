//! Approval ref-segment validation.

use auths_storage::git::approval::{NonceId, Sha256Hex};

#[test]
fn a_request_hash_that_escapes_the_ref_namespace_is_rejected() {
    // A request hash becomes a git ref path segment, so a "/" or ".." would escape the approvals
    // namespace or overwrite another ref; only 64-character lowercase hex is accepted.
    assert!(Sha256Hex::parse(&"a".repeat(64)).is_ok());
    assert!(Sha256Hex::parse("../../refs/heads/main").is_err());
    assert!(Sha256Hex::parse("abc/def").is_err());
    assert!(Sha256Hex::parse(&"A".repeat(64)).is_err());
    assert!(Sha256Hex::parse(&"a".repeat(63)).is_err());
}

#[test]
fn a_nonce_id_that_escapes_the_ref_namespace_is_rejected() {
    assert!(NonceId::parse("uuid-123-abc").is_ok());
    assert!(NonceId::parse("../consumed/evil").is_err());
    assert!(NonceId::parse("a/b").is_err());
    assert!(NonceId::parse("..").is_err());
    assert!(NonceId::parse("").is_err());
}
