//! A signer must be able to see what they are authorizing — a legible summary derived from the
//! exact bytes being signed, not just a digest.

use auths_verifier::AuthorizationSummary;

#[test]
fn summarizes_a_signed_action_request_from_its_bytes() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": "1.0",
        "type": "agent_call",
        "identity": "did:keri:Eagent",
        "payload": { "capability": "payments.transfer", "budget_cents": 1000, "target": "acct:42" },
        "timestamp": "2025-01-01T00:00:00Z"
    }))
    .unwrap();
    match AuthorizationSummary::from_signed_bytes(&bytes) {
        AuthorizationSummary::Action {
            action_type,
            identity,
            details,
        } => {
            assert_eq!(action_type, "agent_call");
            assert_eq!(identity, "did:keri:Eagent");
            assert!(
                details
                    .iter()
                    .any(|(k, v)| k == "capability" && v == "payments.transfer"),
                "the legible capability must be surfaced: {details:?}"
            );
            assert!(
                details
                    .iter()
                    .any(|(k, v)| k == "budget_cents" && v == "1000")
            );
        }
        other => panic!("expected an Action summary, got {other:?}"),
    }
}

#[test]
fn summarizes_a_signed_commit_object_from_its_bytes() {
    let bytes = b"tree abc123\n\
        author Test User <test@example.com> 1700000000 +0000\n\
        committer Test User <test@example.com> 1700000000 +0000\n\
        \n\
        Fix the thing\n";
    match AuthorizationSummary::from_signed_bytes(bytes) {
        AuthorizationSummary::Commit { author, message } => {
            assert!(author.contains("Test User"), "author: {author}");
            assert!(message.contains("Fix the thing"), "message: {message}");
        }
        other => panic!("expected a Commit summary, got {other:?}"),
    }
}

#[test]
fn opaque_bytes_are_named_by_digest_never_silently_blank() {
    // Bytes whose content is not legible from the signature (an artifact attestation binds a
    // digest, not content) are summarized by their digest — consent is never silently blank.
    let bytes = b"\x00\x01\x02 not legible signed bytes";
    match AuthorizationSummary::from_signed_bytes(bytes) {
        AuthorizationSummary::Opaque { digest_hex } => {
            assert_eq!(digest_hex.len(), 64, "lowercase sha256 hex");
            assert!(digest_hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
        other => panic!("expected an Opaque summary, got {other:?}"),
    }
}
