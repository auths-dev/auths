use auths_verifier::commit_error::CommitVerificationError;
use auths_verifier::ssh_sig::parse_sshsig_pem;

const FIXTURE_SIG: &str = include_str!("../fixtures/signature.pem");
const FIXTURE_PUBKEY_HEX: &str = include_str!("../fixtures/pubkey.hex");

#[test]
fn parse_real_sshsig_pem() {
    let envelope = parse_sshsig_pem(FIXTURE_SIG).unwrap();
    assert_eq!(envelope.namespace, "git");
    assert_eq!(envelope.hash_algorithm, "sha512");

    let expected_key = hex::decode(FIXTURE_PUBKEY_HEX.trim()).unwrap();
    assert_eq!(envelope.public_key.as_bytes().as_slice(), &expected_key);
    assert_eq!(envelope.signature.len(), 64);
}

#[test]
fn rejects_invalid_magic() {
    let bad_pem = FIXTURE_SIG.replace("U1NIU0lH", "AAAAAAAA");
    let err = parse_sshsig_pem(&bad_pem).unwrap_err();
    assert!(
        err.to_string().contains("magic"),
        "expected magic error, got: {err}"
    );
}

#[test]
fn rejects_empty_input() {
    let err = parse_sshsig_pem("").unwrap_err();
    assert!(err.to_string().contains("no PEM body"));
}

#[test]
fn rejects_pem_with_no_markers() {
    let err = parse_sshsig_pem("not a pem block at all").unwrap_err();
    assert!(err.to_string().contains("no PEM body"));
}

#[test]
fn error_codes_are_correct() {
    use auths_verifier::error::AuthsErrorInfo;

    let err = CommitVerificationError::UnsignedCommit;
    assert_eq!(err.error_code(), "AUTHS_UNSIGNED_COMMIT");

    let err = CommitVerificationError::GpgNotSupported;
    assert_eq!(err.error_code(), "AUTHS_GPG_NOT_SUPPORTED");

    let err = CommitVerificationError::UnknownSigner;
    assert_eq!(err.error_code(), "AUTHS_UNKNOWN_SIGNER");

    let err = CommitVerificationError::SignatureInvalid;
    assert_eq!(err.error_code(), "AUTHS_SIGNATURE_INVALID");

    let err = CommitVerificationError::UnsupportedKeyType {
        found: "ssh-rsa".into(),
    };
    assert_eq!(err.error_code(), "AUTHS_UNSUPPORTED_KEY_TYPE");
}
