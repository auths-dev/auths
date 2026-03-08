use auths_verifier::core::{
    Attestation, Capability, Ed25519PublicKey, Ed25519Signature, ResourceId, Role, ThresholdPolicy,
};
use auths_verifier::types::{DeviceDID, IdentityDID};
use chrono::{DateTime, TimeZone, Utc};
use proptest::prelude::*;

// Arbitrary generators for core types

/// Generate arbitrary valid DID strings
fn arb_did() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("did:key:".to_string()),
        Just("did:keri:".to_string()),
        Just("did:auths:".to_string()),
    ]
    .prop_flat_map(|prefix| {
        proptest::string::string_regex("[a-zA-Z0-9]{32,64}")
            .unwrap()
            .prop_map(move |suffix| format!("{}{}", prefix, suffix))
    })
}

/// Generate arbitrary IdentityDID
fn arb_identity_did() -> impl Strategy<Value = IdentityDID> {
    arb_did().prop_map(IdentityDID::new)
}

/// Generate arbitrary DeviceDID
fn arb_device_did() -> impl Strategy<Value = DeviceDID> {
    arb_did().prop_map(DeviceDID::new)
}

/// Generate arbitrary 32-byte public key
fn arb_public_key() -> impl Strategy<Value = Ed25519PublicKey> {
    proptest::collection::vec(any::<u8>(), 32)
        .prop_map(|v| Ed25519PublicKey::try_from_slice(&v).unwrap())
}

/// Generate arbitrary signature (64 bytes for Ed25519)
fn arb_signature() -> impl Strategy<Value = Ed25519Signature> {
    proptest::collection::vec(any::<u8>(), 64)
        .prop_map(|v| Ed25519Signature::try_from_slice(&v).unwrap())
}

/// Generate arbitrary optional DateTime in valid range
fn arb_optional_datetime() -> impl Strategy<Value = Option<DateTime<Utc>>> {
    prop_oneof![
        Just(None),
        // Generate timestamps between 2020 and 2030
        (1577836800i64..1893456000i64).prop_map(|secs| Some(Utc.timestamp_opt(secs, 0).unwrap()))
    ]
}

/// Generate arbitrary optional note
fn arb_optional_note() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        proptest::string::string_regex("[a-zA-Z0-9 ]{0,100}")
            .unwrap()
            .prop_map(Some)
    ]
}

/// Generate arbitrary Capability
fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        Just(Capability::sign_commit()),
        Just(Capability::sign_release()),
        Just(Capability::manage_members()),
        Just(Capability::rotate_keys()),
        // Valid custom capabilities (filter out auths: prefix and parse)
        proptest::string::string_regex("[a-z][a-z0-9_:-]{0,30}")
            .unwrap()
            .prop_filter_map("valid custom capability", |s| {
                // Skip auths: prefixed strings (reserved namespace)
                if s.starts_with("auths:") {
                    None
                } else {
                    Capability::parse(&s).ok()
                }
            }),
    ]
}

/// Generate arbitrary RID
fn arb_rid() -> impl Strategy<Value = ResourceId> {
    proptest::string::string_regex("[a-zA-Z0-9-]{8,32}")
        .unwrap()
        .prop_map(|s| ResourceId::new(format!("rid-{}", s)))
}

/// Generate arbitrary optional Role
fn arb_optional_role() -> impl Strategy<Value = Option<Role>> {
    prop_oneof![
        Just(None),
        Just(Some(Role::Admin)),
        Just(Some(Role::Member)),
        Just(Some(Role::Readonly)),
    ]
}

/// Generate arbitrary Attestation
fn arb_attestation() -> impl Strategy<Value = Attestation> {
    // Split into two tuples to stay under 12-element limit
    let core_fields = (
        arb_rid(),               // rid
        arb_identity_did(),      // issuer
        arb_device_did(),        // subject
        arb_public_key(),        // device_public_key
        arb_signature(),         // identity_signature
        arb_signature(),         // device_signature
        arb_optional_datetime(), // revoked_at
    );

    let optional_fields = (
        arb_optional_datetime(),                           // expires_at
        arb_optional_datetime(),                           // timestamp
        arb_optional_note(),                               // note
        arb_optional_role(),                               // role
        proptest::collection::vec(arb_capability(), 0..4), // capabilities
        proptest::option::of(arb_identity_did()),          // delegated_by
    );

    (core_fields, optional_fields).prop_map(
        |(
            (
                rid,
                issuer,
                subject,
                device_public_key,
                identity_signature,
                device_signature,
                revoked_at,
            ),
            (expires_at, timestamp, note, role, capabilities, delegated_by),
        )| {
            Attestation {
                version: 1,
                rid,
                issuer,
                subject,
                device_public_key,
                identity_signature,
                device_signature,
                revoked_at,
                expires_at,
                timestamp,
                note,
                payload: None,
                role,
                capabilities,
                delegated_by,
                signer_type: None,
                environment_claim: None,
            }
        },
    )
}

/// Generate arbitrary ThresholdPolicy
fn arb_threshold_policy() -> impl Strategy<Value = ThresholdPolicy> {
    // Generate between 1-5 signers
    proptest::collection::vec(arb_did(), 1..=5).prop_flat_map(|signers| {
        let n = signers.len();
        // Threshold must be 1..=n
        (1..=n as u8).prop_flat_map(move |threshold| {
            let signers = signers.clone();
            proptest::string::string_regex("[a-zA-Z0-9-]{4,32}")
                .unwrap()
                .prop_map(move |policy_id| {
                    ThresholdPolicy::new(threshold, signers.clone(), policy_id)
                })
        })
    })
}

proptest! {
    /// Test that Attestation serializes and deserializes correctly
    #[test]
    fn attestation_json_roundtrip(att in arb_attestation()) {
        let json = serde_json::to_string(&att).expect("serialization should succeed");
        let parsed: Attestation = serde_json::from_str(&json).expect("deserialization should succeed");

        prop_assert_eq!(att.version, parsed.version);
        prop_assert_eq!(att.rid, parsed.rid);
        prop_assert_eq!(att.issuer, parsed.issuer);
        prop_assert_eq!(att.subject, parsed.subject);
        prop_assert_eq!(att.device_public_key, parsed.device_public_key);
        prop_assert_eq!(att.identity_signature, parsed.identity_signature);
        prop_assert_eq!(att.device_signature, parsed.device_signature);
        prop_assert_eq!(att.revoked_at, parsed.revoked_at);
        prop_assert_eq!(att.expires_at, parsed.expires_at);
        prop_assert_eq!(att.timestamp, parsed.timestamp);
        prop_assert_eq!(att.note, parsed.note);
        prop_assert_eq!(att.role, parsed.role);
        prop_assert_eq!(att.capabilities, parsed.capabilities);
        prop_assert_eq!(att.delegated_by, parsed.delegated_by);
    }

    /// Test that Capability serializes and deserializes correctly
    #[test]
    fn capability_json_roundtrip(cap in arb_capability()) {
        let json = serde_json::to_string(&cap).expect("serialization should succeed");
        let parsed: Capability = serde_json::from_str(&json).expect("deserialization should succeed");
        prop_assert_eq!(cap, parsed);
    }

    /// Test that ThresholdPolicy serializes and deserializes correctly
    #[test]
    fn threshold_policy_json_roundtrip(policy in arb_threshold_policy()) {
        let json = serde_json::to_string(&policy).expect("serialization should succeed");
        let parsed: ThresholdPolicy = serde_json::from_str(&json).expect("deserialization should succeed");

        prop_assert_eq!(policy.threshold, parsed.threshold);
        prop_assert_eq!(policy.signers, parsed.signers);
        prop_assert_eq!(policy.policy_id, parsed.policy_id);
        prop_assert_eq!(policy.scope, parsed.scope);
        prop_assert_eq!(policy.ceremony_endpoint, parsed.ceremony_endpoint);
    }

    /// Test that all generated ThresholdPolicies are valid
    #[test]
    fn threshold_policy_always_valid(policy in arb_threshold_policy()) {
        prop_assert!(policy.is_valid(), "Generated policy should be valid: {:?}", policy);
    }

    /// Test that m_of_n returns correct values
    #[test]
    fn threshold_policy_m_of_n_correct(policy in arb_threshold_policy()) {
        let (m, n) = policy.m_of_n();
        prop_assert_eq!(m, policy.threshold);
        prop_assert_eq!(n, policy.signers.len());
        prop_assert!(m as usize <= n, "Threshold should be <= signers count");
    }

    /// Test that DID strings maintain format through DeviceDID
    #[test]
    fn device_did_preserves_string(did_str in arb_did()) {
        let device_did = DeviceDID::new(did_str.clone());
        prop_assert_eq!(device_did.as_str(), &did_str);
    }

    /// Test Attestation from_json matches direct deserialization
    #[test]
    fn attestation_from_json_matches_serde(att in arb_attestation()) {
        let json_bytes = serde_json::to_vec(&att).expect("serialization should succeed");
        let from_json = Attestation::from_json(&json_bytes).expect("from_json should succeed");
        let from_serde: Attestation = serde_json::from_slice(&json_bytes).expect("from_slice should succeed");

        prop_assert_eq!(from_json.rid, from_serde.rid);
        prop_assert_eq!(from_json.issuer, from_serde.issuer);
        prop_assert_eq!(from_json.subject, from_serde.subject);
    }
}
