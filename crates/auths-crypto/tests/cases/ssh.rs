use auths_crypto::ssh::{SshKeyError, openssh_pub_to_raw_ed25519};

#[test]
fn parses_valid_ed25519_key() {
    // Generated with: ssh-keygen -t ed25519 -C "" -f /tmp/test_key -N ""
    let openssh_pub =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let result = openssh_pub_to_raw_ed25519(openssh_pub);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    let raw = result.unwrap();
    assert_eq!(raw.len(), 32);
}

#[test]
fn rejects_wrong_key_type() {
    // An RSA key line (abbreviated) — key type is ssh-rsa, not ssh-ed25519
    let openssh_pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC comment";
    let err = openssh_pub_to_raw_ed25519(openssh_pub).unwrap_err();
    // ssh-key will reject malformed RSA data as InvalidFormat; an actual valid RSA key
    // would return UnsupportedKeyType. Both are acceptable rejections for this input.
    assert!(
        matches!(
            err,
            SshKeyError::UnsupportedKeyType | SshKeyError::InvalidFormat(_)
        ),
        "unexpected error variant: {:?}",
        err
    );
}

#[test]
fn rejects_malformed_base64() {
    let openssh_pub = "ssh-ed25519 !!!not_base64!!! comment";
    let err = openssh_pub_to_raw_ed25519(openssh_pub).unwrap_err();
    assert!(
        matches!(err, SshKeyError::InvalidFormat(_)),
        "unexpected error variant: {:?}",
        err
    );
}
