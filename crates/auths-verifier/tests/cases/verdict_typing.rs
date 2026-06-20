//! fn-153.2 wire-compatibility: the verdicts now carry `IdentityDID`/`CanonicalDid`/
//! `Capability` instead of `String`/`Vec<String>`. This proves the change is byte-identical
//! on the wire (each typed field serializes exactly as the string it replaced) and that the
//! validating `Deserialize` rejects malformed input rather than silently keeping it.

use auths_verifier::{CanonicalDid, Capability, IdentityDID};

#[test]
fn typed_identity_fields_serialize_as_their_did_string() {
    let issuer = IdentityDID::parse("did:keri:Eissuer").unwrap();
    let subject = CanonicalDid::new_unchecked("did:keri:Esubject");

    // Byte-identical to the `String` fields these replaced.
    assert_eq!(
        serde_json::to_string(&issuer).unwrap(),
        "\"did:keri:Eissuer\""
    );
    assert_eq!(
        serde_json::to_string(&subject).unwrap(),
        "\"did:keri:Esubject\""
    );
}

#[test]
fn typed_capabilities_serialize_as_a_string_array() {
    let caps = vec![
        Capability::parse("sign_commit").unwrap(),
        Capability::parse("acme:deploy").unwrap(),
    ];
    // Byte-identical to the `Vec<String>` it replaced.
    assert_eq!(
        serde_json::to_string(&caps).unwrap(),
        "[\"sign_commit\",\"acme:deploy\"]"
    );
}

#[test]
fn deserialize_round_trips_what_serialize_emits() {
    let issuer: IdentityDID = serde_json::from_str("\"did:keri:Eissuer\"").unwrap();
    assert_eq!(issuer.as_str(), "did:keri:Eissuer");
    let subject: CanonicalDid = serde_json::from_str("\"did:keri:Esubject\"").unwrap();
    assert_eq!(subject.as_str(), "did:keri:Esubject");
    let caps: Vec<Capability> = serde_json::from_str("[\"sign_commit\"]").unwrap();
    assert_eq!(
        caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        ["sign_commit"]
    );
}

#[test]
fn validating_deserialize_rejects_malformed_input() {
    // A DID that does not parse is a hard error on the wire — never silently accepted.
    assert!(serde_json::from_str::<IdentityDID>("\"not-a-did\"").is_err());
    assert!(serde_json::from_str::<CanonicalDid>("\"\"").is_err());
    // A capability that does not parse is likewise rejected (kills the old silent drop).
    assert!(serde_json::from_str::<Vec<Capability>>("[\"\"]").is_err());
}
