use auths_transparency::note::{
    build_signature_line, compute_key_id, parse_signed_note, serialize_signed_note,
};

#[test]
fn key_id_matches_c2sp_spec_construction() {
    // key_id = SHA-256("auths.dev/log\n" + 0x01 + pubkey)[0..4]
    let pubkey = [0x42; 32];
    let key_id = compute_key_id("auths.dev/log", &pubkey);

    let mut data = Vec::new();
    data.extend_from_slice(b"auths.dev/log\n");
    data.push(0x01);
    data.extend_from_slice(&pubkey);

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&data);
    assert_eq!(key_id, hash[..4]);
}

#[test]
fn key_id_deterministic() {
    let pubkey = [0xaa; 32];
    let id1 = compute_key_id("test/log", &pubkey);
    let id2 = compute_key_id("test/log", &pubkey);
    assert_eq!(id1, id2);
}

#[test]
fn key_id_varies_with_key_name() {
    let pubkey = [0xaa; 32];
    let id1 = compute_key_id("auths.dev/log", &pubkey);
    let id2 = compute_key_id("other.dev/log", &pubkey);
    assert_ne!(id1, id2);
}

#[test]
fn key_id_varies_with_pubkey() {
    let id1 = compute_key_id("auths.dev/log", &[0xaa; 32]);
    let id2 = compute_key_id("auths.dev/log", &[0xbb; 32]);
    assert_ne!(id1, id2);
}

#[test]
fn signed_note_full_roundtrip() {
    let body = "auths.dev/log\n100\nabababababababababababababababababababababababababababababababababab\n";
    let key_id = compute_key_id("auths.dev/log", &[0x42; 32]);
    let sig = [0xdd; 64];

    let sig_line = build_signature_line("auths.dev/log", &key_id, &sig);
    let note = serialize_signed_note(body, &[sig_line]);

    let (parsed_body, parsed_sigs) = parse_signed_note(&note).unwrap();
    assert_eq!(parsed_body, body);
    assert_eq!(parsed_sigs.len(), 1);
    assert_eq!(parsed_sigs[0].key_name, "auths.dev/log");
    assert_eq!(parsed_sigs[0].algorithm, 0x01);
    assert_eq!(parsed_sigs[0].key_id, key_id);
    assert_eq!(parsed_sigs[0].signature.len(), 64);
    assert_eq!(&parsed_sigs[0].signature[..], &sig[..]);
}

#[test]
fn signed_note_multiple_signatures() {
    let body = "log\n1\n0000000000000000000000000000000000000000000000000000000000000000\n";
    let key_id1 = [0x01, 0x02, 0x03, 0x04];
    let key_id2 = [0x05, 0x06, 0x07, 0x08];
    let sig1 = [0xaa; 64];
    let sig2 = [0xbb; 64];

    let line1 = build_signature_line("log-operator", &key_id1, &sig1);
    let line2 = build_signature_line("witness-1", &key_id2, &sig2);
    let note = serialize_signed_note(body, &[line1, line2]);

    let (_, parsed_sigs) = parse_signed_note(&note).unwrap();
    assert_eq!(parsed_sigs.len(), 2);
    assert_eq!(parsed_sigs[0].key_name, "log-operator");
    assert_eq!(parsed_sigs[1].key_name, "witness-1");
}

#[test]
fn parse_note_rejects_missing_signatures() {
    let note = "just a body\nno signature\n";
    assert!(parse_signed_note(note).is_err());
}
