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
fn commit_summary_excludes_the_unverified_git_author() {
    // The git `author` line is an attacker-controllable self-claim, not the authorizing identity
    // (that is the verdict's cryptographically-verified signer). It must not appear in the consent
    // summary; only the legible message is carried.
    let bytes = b"tree abc123\n\
        author Attacker Name <attacker@evil.example> 1700000000 +0000\n\
        committer Attacker Name <attacker@evil.example> 1700000000 +0000\n\
        \n\
        Fix the thing\n";
    let summary = AuthorizationSummary::from_signed_bytes(bytes);
    match &summary {
        AuthorizationSummary::Commit { message } => {
            assert!(message.contains("Fix the thing"), "message: {message}");
        }
        other => panic!("expected a Commit summary, got {other:?}"),
    }
    assert!(
        !summary.to_string().contains("Attacker"),
        "the unverified git author must not appear in the consent summary, got {summary}"
    );
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
