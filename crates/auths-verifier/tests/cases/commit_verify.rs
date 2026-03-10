use auths_verifier::commit::{extract_ssh_signature, verify_commit_signature};
use auths_verifier::commit_error::CommitVerificationError;
use auths_verifier::core::Ed25519PublicKey;

const FIXTURE_COMMIT: &str = include_str!("../fixtures/signed_commit.txt");
const FIXTURE_PAYLOAD: &str = include_str!("../fixtures/payload.txt");
const FIXTURE_PUBKEY_HEX: &str = include_str!("../fixtures/pubkey.hex");

fn fixture_pubkey() -> Ed25519PublicKey {
    let bytes = hex::decode(FIXTURE_PUBKEY_HEX.trim()).unwrap();
    Ed25519PublicKey::try_from_slice(&bytes).unwrap()
}

#[test]
fn extract_signature_from_real_commit() {
    let extracted = extract_ssh_signature(FIXTURE_COMMIT).unwrap();
    assert!(
        extracted
            .signature_pem
            .contains("-----BEGIN SSH SIGNATURE-----")
    );
    assert!(
        extracted
            .signature_pem
            .contains("-----END SSH SIGNATURE-----")
    );
    assert!(!extracted.signed_payload.contains("gpgsig"));
    assert!(extracted.signed_payload.contains("tree 4b825dc642cb6eb"));
    assert!(extracted.signed_payload.contains("test commit message"));
}

#[test]
fn extracted_payload_matches_original() {
    let extracted = extract_ssh_signature(FIXTURE_COMMIT).unwrap();
    assert_eq!(
        extracted.signed_payload, FIXTURE_PAYLOAD,
        "payload must match the original pre-signing content exactly"
    );
}

#[test]
fn extract_preserves_trailing_newline() {
    let extracted = extract_ssh_signature(FIXTURE_COMMIT).unwrap();
    assert!(
        extracted.signed_payload.ends_with('\n'),
        "payload must end with newline"
    );
}

#[test]
fn extract_returns_unsigned_for_plain_commit() {
    let commit = "tree abc123\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nmsg\n";
    let err = extract_ssh_signature(commit).unwrap_err();
    assert!(matches!(err, CommitVerificationError::UnsignedCommit));
}

#[test]
fn extract_returns_unsigned_for_empty() {
    let err = extract_ssh_signature("").unwrap_err();
    assert!(matches!(err, CommitVerificationError::UnsignedCommit));
}

#[tokio::test]
async fn verify_real_signed_commit() {
    let provider = auths_crypto::RingCryptoProvider;
    let key = fixture_pubkey();
    let result = verify_commit_signature(FIXTURE_COMMIT.as_bytes(), &[key], &provider, None).await;
    let verified = result.unwrap();
    assert_eq!(verified.signer_key, key);
}

#[tokio::test]
async fn verify_rejects_unknown_signer() {
    let provider = auths_crypto::RingCryptoProvider;
    let wrong_key = Ed25519PublicKey::from_bytes([0x99; 32]);
    let result =
        verify_commit_signature(FIXTURE_COMMIT.as_bytes(), &[wrong_key], &provider, None).await;
    assert!(matches!(
        result,
        Err(CommitVerificationError::UnknownSigner)
    ));
}

#[tokio::test]
async fn verify_rejects_tampered_content() {
    let provider = auths_crypto::RingCryptoProvider;
    let key = fixture_pubkey();
    let tampered = FIXTURE_COMMIT.replace("test commit message", "tampered message");
    let result = verify_commit_signature(tampered.as_bytes(), &[key], &provider, None).await;
    assert!(matches!(
        result,
        Err(CommitVerificationError::SignatureInvalid)
    ));
}

#[tokio::test]
async fn verify_rejects_gpg_commit() {
    let provider = auths_crypto::RingCryptoProvider;
    let gpg_commit = b"tree abc\ngpgsig -----BEGIN PGP SIGNATURE-----\n iQEz\n -----END PGP SIGNATURE-----\n\nmsg\n";
    let result = verify_commit_signature(gpg_commit, &[], &provider, None).await;
    assert!(matches!(
        result,
        Err(CommitVerificationError::GpgNotSupported)
    ));
}

#[tokio::test]
async fn verify_rejects_unsigned() {
    let provider = auths_crypto::RingCryptoProvider;
    let unsigned = b"tree abc\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nmsg\n";
    let result = verify_commit_signature(unsigned, &[], &provider, None).await;
    assert!(matches!(
        result,
        Err(CommitVerificationError::UnsignedCommit)
    ));
}
