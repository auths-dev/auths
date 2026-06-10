use auths_jwt::{ActorClaim, IdpBindingClaim, OidcClaims, WitnessQuorumClaim};
use serde_json::{Value, json};

fn minimal_claims_json() -> Value {
    json!({
        "iss": "https://auth.example.com",
        "sub": "did:keri:ETest",
        "aud": "api.example.com",
        "exp": 1_700_000_000u64,
        "iat": 1_699_999_000u64,
        "jti": "jti-1",
        "keri_prefix": "ETest",
        "capabilities": ["sign-commit"]
    })
}

fn fully_populated_claims() -> OidcClaims {
    OidcClaims {
        iss: "https://auth.example.com".into(),
        sub: "did:keri:ETest".into(),
        aud: "api.example.com".into(),
        exp: 1_700_000_000,
        iat: 1_699_999_000,
        jti: "jti-full".into(),
        keri_prefix: "ETest".into(),
        target_provider: Some("aws".into()),
        capabilities: vec!["sign-commit".into(), "deploy".into()],
        witness_quorum: Some(WitnessQuorumClaim {
            required: 3,
            verified: 3,
        }),
        github_actor: Some("alice".into()),
        github_repository: Some("acme/widgets".into()),
        act: Some(ActorClaim {
            sub: "did:keri:Eagent".into(),
            signer_type: Some("agent".into()),
            act: Some(Box::new(ActorClaim {
                sub: "did:keri:Edevice".into(),
                signer_type: None,
                act: None,
            })),
        }),
        spiffe_id: Some("spiffe://trust.example/workload".into()),
        idp_binding: Some(IdpBindingClaim {
            idp_issuer: "https://company.okta.com".into(),
            idp_protocol: "oidc".into(),
            subject: "oid@tid".into(),
            subject_email: Some("alice@company.com".into()),
            auth_time: 1_699_998_000,
            auth_context_class: Some("urn:example:acr".into()),
        }),
    }
}

#[test]
fn fully_populated_claims_round_trip_to_identical_json() {
    let claims = fully_populated_claims();
    let first = serde_json::to_value(&claims).unwrap();
    let reparsed: OidcClaims = serde_json::from_value(first.clone()).unwrap();
    let second = serde_json::to_value(&reparsed).unwrap();
    assert_eq!(first, second);
}

#[test]
fn fully_populated_claims_round_trip_preserves_nested_fields() {
    let claims = fully_populated_claims();
    let json = serde_json::to_string(&claims).unwrap();
    let parsed: OidcClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.iss, claims.iss);
    assert_eq!(parsed.sub, claims.sub);
    assert_eq!(parsed.aud, claims.aud);
    assert_eq!(parsed.exp, claims.exp);
    assert_eq!(parsed.iat, claims.iat);
    assert_eq!(parsed.jti, claims.jti);
    assert_eq!(parsed.keri_prefix, claims.keri_prefix);
    assert_eq!(parsed.target_provider.as_deref(), Some("aws"));
    assert_eq!(parsed.capabilities, vec!["sign-commit", "deploy"]);

    let quorum = parsed.witness_quorum.unwrap();
    assert_eq!(quorum.required, 3);
    assert_eq!(quorum.verified, 3);

    let act = parsed.act.unwrap();
    assert_eq!(act.sub, "did:keri:Eagent");
    assert_eq!(act.signer_type.as_deref(), Some("agent"));
    let nested = act.act.unwrap();
    assert_eq!(nested.sub, "did:keri:Edevice");
    assert!(nested.act.is_none());

    let binding = parsed.idp_binding.unwrap();
    assert_eq!(binding.idp_issuer, "https://company.okta.com");
    assert_eq!(binding.auth_time, 1_699_998_000);
}

#[test]
fn minimal_claims_deserialize_with_all_optionals_none() {
    let claims: OidcClaims = serde_json::from_value(minimal_claims_json()).unwrap();
    assert!(claims.target_provider.is_none());
    assert!(claims.witness_quorum.is_none());
    assert!(claims.github_actor.is_none());
    assert!(claims.github_repository.is_none());
    assert!(claims.act.is_none());
    assert!(claims.spiffe_id.is_none());
    assert!(claims.idp_binding.is_none());
}

#[test]
fn missing_iss_rejected() {
    let mut v = minimal_claims_json();
    v.as_object_mut().unwrap().remove("iss");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn missing_sub_rejected() {
    let mut v = minimal_claims_json();
    v.as_object_mut().unwrap().remove("sub");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn missing_exp_rejected() {
    let mut v = minimal_claims_json();
    v.as_object_mut().unwrap().remove("exp");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn missing_jti_rejected() {
    let mut v = minimal_claims_json();
    v.as_object_mut().unwrap().remove("jti");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn missing_keri_prefix_rejected() {
    let mut v = minimal_claims_json();
    v.as_object_mut().unwrap().remove("keri_prefix");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn absent_capabilities_rejected_while_empty_capabilities_accepted() {
    let mut absent = minimal_claims_json();
    absent.as_object_mut().unwrap().remove("capabilities");
    assert!(serde_json::from_value::<OidcClaims>(absent).is_err());

    let mut empty = minimal_claims_json();
    empty["capabilities"] = json!([]);
    let claims: OidcClaims = serde_json::from_value(empty).unwrap();
    assert!(claims.capabilities.is_empty());
}

#[test]
fn exp_as_string_rejected() {
    let mut v = minimal_claims_json();
    v["exp"] = json!("1700000000");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn negative_exp_rejected() {
    let mut v = minimal_claims_json();
    v["exp"] = json!(-1);
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn fractional_exp_rejected() {
    let mut v = minimal_claims_json();
    v["exp"] = json!(1.5);
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn numeric_jti_rejected() {
    let mut v = minimal_claims_json();
    v["jti"] = json!(12345);
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn null_jti_rejected() {
    let mut v = minimal_claims_json();
    v["jti"] = Value::Null;
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn capabilities_as_string_rejected() {
    let mut v = minimal_claims_json();
    v["capabilities"] = json!("sign-commit");
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn capabilities_with_non_string_element_rejected() {
    let mut v = minimal_claims_json();
    v["capabilities"] = json!(["sign-commit", 42]);
    assert!(serde_json::from_value::<OidcClaims>(v).is_err());
}

#[test]
fn null_optional_field_deserializes_to_none() {
    let mut v = minimal_claims_json();
    v["target_provider"] = Value::Null;
    let claims: OidcClaims = serde_json::from_value(v).unwrap();
    assert!(claims.target_provider.is_none());
}

#[test]
fn unknown_fields_are_ignored() {
    let mut v = minimal_claims_json();
    v["x_custom_extension"] = json!({"nested": true});
    let claims: OidcClaims = serde_json::from_value(v).unwrap();
    assert_eq!(claims.jti, "jti-1");
}

#[test]
fn optional_fields_omitted_from_serialized_minimal_claims() {
    let claims: OidcClaims = serde_json::from_value(minimal_claims_json()).unwrap();
    let json = serde_json::to_string(&claims).unwrap();
    for absent in [
        "target_provider",
        "witness_quorum",
        "github_actor",
        "github_repository",
        "\"act\"",
        "spiffe_id",
        "idp_binding",
    ] {
        assert!(!json.contains(absent), "expected {absent} to be omitted");
    }
}

#[test]
fn actor_claim_three_hop_delegation_round_trips() {
    let chain = ActorClaim {
        sub: "did:keri:Eouter".into(),
        signer_type: Some("agent".into()),
        act: Some(Box::new(ActorClaim {
            sub: "did:keri:Emiddle".into(),
            signer_type: None,
            act: Some(Box::new(ActorClaim {
                sub: "did:keri:Einner".into(),
                signer_type: Some("device".into()),
                act: None,
            })),
        })),
    };
    let json = serde_json::to_string(&chain).unwrap();
    let parsed: ActorClaim = serde_json::from_str(&json).unwrap();
    let middle = parsed.act.unwrap();
    let inner = middle.act.unwrap();
    assert_eq!(parsed.sub, "did:keri:Eouter");
    assert_eq!(middle.sub, "did:keri:Emiddle");
    assert_eq!(inner.sub, "did:keri:Einner");
    assert_eq!(inner.signer_type.as_deref(), Some("device"));
}

#[test]
fn actor_claim_missing_sub_rejected() {
    assert!(serde_json::from_value::<ActorClaim>(json!({"signer_type": "agent"})).is_err());
}

#[test]
fn witness_quorum_negative_count_rejected() {
    assert!(
        serde_json::from_value::<WitnessQuorumClaim>(json!({"required": -1, "verified": 0}))
            .is_err()
    );
}

#[test]
fn idp_binding_missing_required_fields_rejected() {
    let missing_issuer = json!({
        "idp_protocol": "oidc",
        "subject": "alice",
        "auth_time": 1_699_998_000u64
    });
    assert!(serde_json::from_value::<IdpBindingClaim>(missing_issuer).is_err());

    let missing_auth_time = json!({
        "idp_issuer": "https://company.okta.com",
        "idp_protocol": "oidc",
        "subject": "alice"
    });
    assert!(serde_json::from_value::<IdpBindingClaim>(missing_auth_time).is_err());
}

#[test]
fn idp_binding_auth_time_as_rfc3339_string_rejected() {
    let v = json!({
        "idp_issuer": "https://company.okta.com",
        "idp_protocol": "oidc",
        "subject": "alice",
        "auth_time": "2023-11-14T22:00:00Z"
    });
    assert!(serde_json::from_value::<IdpBindingClaim>(v).is_err());
}
