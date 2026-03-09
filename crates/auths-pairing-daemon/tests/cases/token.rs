use auths_pairing_daemon::generate_transport_token;

#[test]
fn generates_valid_base64url_token() {
    let (raw_bytes, b64_string) = generate_transport_token().unwrap();

    assert_eq!(raw_bytes.len(), 16);
    assert_eq!(b64_string.len(), 22); // 16 bytes = 22 base64url chars (no padding)
    assert!(
        b64_string
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "token contains non-base64url characters: {b64_string}"
    );
}

#[test]
fn generates_unique_tokens() {
    let (_, a) = generate_transport_token().unwrap();
    let (_, b) = generate_transport_token().unwrap();
    assert_ne!(a, b);
}
