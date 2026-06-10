use auths_rp::{
    AUTHS_PRESENTATION_SCHEME, Audience, NONCE_LEN, Nonce, WireBinding, WireError,
    WirePresentation, parse_presentation_header,
};
use auths_verifier::PresentationBinding;
use base64::Engine;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sample_wire(binding: WireBinding) -> WirePresentation {
    WirePresentation {
        credential_said: "ECredSAID".into(),
        audience: "api.example.com".into(),
        binding,
        signature_b64: b64url(&[9u8; 64]),
    }
}

fn challenge_binding() -> WireBinding {
    WireBinding::Challenge {
        nonce: Nonce::from_bytes([7u8; NONCE_LEN]).to_b64url(),
    }
}

#[test]
fn audience_empty_string_rejected() {
    assert!(matches!(
        Audience::parse("").unwrap_err(),
        WireError::EmptyAudience
    ));
}

#[test]
fn wire_with_empty_audience_rejected_before_binding_checks() {
    let mut wire = sample_wire(WireBinding::Challenge {
        nonce: "definitely-not-a-nonce".into(),
    });
    wire.audience = String::new();
    assert!(matches!(
        wire.parse().unwrap_err(),
        WireError::EmptyAudience
    ));
}

#[test]
fn nonce_shorter_than_32_bytes_rejected_with_length() {
    let wire = sample_wire(WireBinding::Challenge {
        nonce: b64url(&[1u8; 31]),
    });
    match wire.parse().unwrap_err() {
        WireError::NonceLength { got } => assert_eq!(got, 31),
        other => panic!("expected NonceLength, got {other:?}"),
    }
}

#[test]
fn nonce_longer_than_32_bytes_rejected_with_length() {
    let wire = sample_wire(WireBinding::Challenge {
        nonce: b64url(&[1u8; 33]),
    });
    match wire.parse().unwrap_err() {
        WireError::NonceLength { got } => assert_eq!(got, 33),
        other => panic!("expected NonceLength, got {other:?}"),
    }
}

#[test]
fn empty_nonce_rejected_with_zero_length() {
    let wire = sample_wire(WireBinding::Challenge {
        nonce: String::new(),
    });
    match wire.parse().unwrap_err() {
        WireError::NonceLength { got } => assert_eq!(got, 0),
        other => panic!("expected NonceLength, got {other:?}"),
    }
}

#[test]
fn nonce_in_standard_base64_alphabet_rejected() {
    let standard_alphabet = "ab+/cdefghijklmnopqrstuvwxyzABCDEFGHIJK";
    let wire = sample_wire(WireBinding::Challenge {
        nonce: standard_alphabet.into(),
    });
    assert!(matches!(wire.parse().unwrap_err(), WireError::BadBase64));
}

#[test]
fn nonce_b64url_with_trailing_padding_tolerated() {
    let padded = format!("{}=", Nonce::from_bytes([5u8; NONCE_LEN]).to_b64url());
    let nonce = Nonce::parse_b64url(&padded).unwrap();
    assert_eq!(nonce.as_bytes(), &[5u8; NONCE_LEN]);
}

#[test]
fn ttl_garbage_not_after_rejected_as_bad_timestamp() {
    let wire = sample_wire(WireBinding::Ttl {
        nonce: Nonce::from_bytes([3u8; NONCE_LEN]).to_b64url(),
        not_after: "tomorrow-ish".into(),
    });
    assert!(matches!(wire.parse().unwrap_err(), WireError::BadTimestamp));
}

#[test]
fn ttl_unix_timestamp_integer_rejected_as_bad_timestamp() {
    let wire = sample_wire(WireBinding::Ttl {
        nonce: Nonce::from_bytes([3u8; NONCE_LEN]).to_b64url(),
        not_after: "1893456000".into(),
    });
    assert!(matches!(wire.parse().unwrap_err(), WireError::BadTimestamp));
}

#[test]
fn ttl_offset_timestamp_normalized_to_utc() {
    let wire = sample_wire(WireBinding::Ttl {
        nonce: Nonce::from_bytes([3u8; NONCE_LEN]).to_b64url(),
        not_after: "2030-01-01T02:00:00+02:00".into(),
    });
    let (envelope, _aud) = wire.parse().unwrap();
    match envelope.binding {
        PresentationBinding::Ttl { not_after, .. } => {
            assert_eq!(not_after.to_rfc3339(), "2030-01-01T00:00:00+00:00");
        }
        PresentationBinding::Challenge { .. } => panic!("expected TTL binding"),
    }
}

#[test]
fn signature_in_standard_base64_alphabet_rejected() {
    let mut wire = sample_wire(challenge_binding());
    wire.signature_b64 = "sig+with/standard==".into();
    assert!(matches!(wire.parse().unwrap_err(), WireError::BadBase64));
}

#[test]
fn signature_with_embedded_whitespace_rejected() {
    let mut wire = sample_wire(challenge_binding());
    wire.signature_b64 = "AAAA BBBB".into();
    assert!(matches!(wire.parse().unwrap_err(), WireError::BadBase64));
}

#[test]
fn oversized_signature_is_not_length_limited_at_wire_layer() {
    let mut wire = sample_wire(challenge_binding());
    wire.signature_b64 = b64url(&vec![0xAB; 10_240]);
    let (envelope, _aud) = wire.parse().unwrap();
    assert_eq!(envelope.signature.len(), 10_240);
}

#[test]
fn empty_signature_passes_wire_parse_as_zero_bytes() {
    let mut wire = sample_wire(challenge_binding());
    wire.signature_b64 = String::new();
    let (envelope, _aud) = wire.parse().unwrap();
    assert!(envelope.signature.is_empty());
}

#[test]
fn token_in_standard_base64_alphabet_rejected() {
    assert!(matches!(
        WirePresentation::from_token("ab+/cd").unwrap_err(),
        WireError::BadBase64
    ));
}

#[test]
fn token_decoding_to_truncated_json_rejected() {
    let token = b64url(br#"{"credential_said":"ECred","audience":"#);
    assert!(matches!(
        WirePresentation::from_token(&token).unwrap_err(),
        WireError::BadJson(_)
    ));
}

#[test]
fn token_decoding_to_json_array_rejected() {
    let token = b64url(br#"["not","an","object"]"#);
    assert!(matches!(
        WirePresentation::from_token(&token).unwrap_err(),
        WireError::BadJson(_)
    ));
}

#[test]
fn token_with_missing_signature_field_rejected() {
    let json = serde_json::json!({
        "credential_said": "ECred",
        "audience": "api.example.com",
        "binding": { "challenge": { "nonce": Nonce::from_bytes([1u8; NONCE_LEN]).to_b64url() } }
    });
    let token = b64url(json.to_string().as_bytes());
    assert!(matches!(
        WirePresentation::from_token(&token).unwrap_err(),
        WireError::BadJson(_)
    ));
}

#[test]
fn token_with_unknown_binding_variant_rejected() {
    let json = serde_json::json!({
        "credential_said": "ECred",
        "audience": "api.example.com",
        "binding": { "bearer": {} },
        "signature_b64": "AAAA"
    });
    let token = b64url(json.to_string().as_bytes());
    assert!(matches!(
        WirePresentation::from_token(&token).unwrap_err(),
        WireError::BadJson(_)
    ));
}

#[test]
fn token_with_numeric_audience_rejected() {
    let json = serde_json::json!({
        "credential_said": "ECred",
        "audience": 42,
        "binding": { "challenge": { "nonce": Nonce::from_bytes([1u8; NONCE_LEN]).to_b64url() } },
        "signature_b64": "AAAA"
    });
    let token = b64url(json.to_string().as_bytes());
    assert!(matches!(
        WirePresentation::from_token(&token).unwrap_err(),
        WireError::BadJson(_)
    ));
}

#[test]
fn header_with_bearer_scheme_rejected() {
    assert!(matches!(
        parse_presentation_header("Bearer abc.def").unwrap_err(),
        WireError::WrongScheme
    ));
}

#[test]
fn header_scheme_match_is_case_sensitive() {
    assert!(matches!(
        parse_presentation_header("auths-presentation AAAA").unwrap_err(),
        WireError::WrongScheme
    ));
}

#[test]
fn header_with_scheme_but_no_token_rejected() {
    assert!(matches!(
        parse_presentation_header(AUTHS_PRESENTATION_SCHEME).unwrap_err(),
        WireError::MissingHeader
    ));
}

#[test]
fn header_with_scheme_and_only_whitespace_rejected() {
    let header = format!("{AUTHS_PRESENTATION_SCHEME}    ");
    assert!(matches!(
        parse_presentation_header(&header).unwrap_err(),
        WireError::MissingHeader
    ));
}

#[test]
fn header_with_undelimited_garbage_after_scheme_does_not_authenticate() {
    let header = format!("{AUTHS_PRESENTATION_SCHEME}Foo");
    assert!(parse_presentation_header(&header).is_err());
}

#[test]
fn challenge_envelope_round_trips_through_token_and_parse() {
    let wire = sample_wire(challenge_binding());
    let token = wire.to_token().unwrap();
    let header = format!("{AUTHS_PRESENTATION_SCHEME} {token}");
    let decoded = parse_presentation_header(&header).unwrap();
    assert_eq!(decoded, wire);

    let (envelope, audience) = decoded.parse().unwrap();
    assert_eq!(audience.as_str(), "api.example.com");
    let rebuilt = WirePresentation::from_envelope(&envelope);
    assert_eq!(rebuilt, wire);
}

#[test]
fn ttl_envelope_round_trips_through_from_envelope() {
    let wire = sample_wire(WireBinding::Ttl {
        nonce: Nonce::from_bytes([8u8; NONCE_LEN]).to_b64url(),
        not_after: "2030-06-15T12:30:45+00:00".into(),
    });
    let (envelope, _aud) = wire.clone().parse().unwrap();
    let rebuilt = WirePresentation::from_envelope(&envelope);
    assert_eq!(rebuilt, wire);
}

#[test]
fn nonce_b64url_round_trips_exact_bytes() {
    let original = Nonce::from_bytes([0xC4; NONCE_LEN]);
    let reparsed = Nonce::parse_b64url(&original.to_b64url()).unwrap();
    assert_eq!(reparsed, original);
    assert_eq!(reparsed.as_bytes(), &[0xC4; NONCE_LEN]);
}
