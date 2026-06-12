//! fn-157.8 — Compliance-as-a-query: evidence-pack authority-at-release,
//! offline verification, and DSSE org-signing, exercised against a real org KEL.

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::types::Prefix;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::compliance::dsse::{
    sign_evidence_pack, sign_framework_report, verify_signed_evidence_pack_offline,
};
use auths_sdk::domains::compliance::frameworks::{
    SPDX_VERSION, SignerVerifierAllowList, VsaParams, build_framework_report, sbom_document_sha256,
};
use auths_sdk::domains::compliance::query::{
    ComplianceFramework, EvidencePack, ReleaseRecord, build_evidence_pack,
    build_offline_evidence_pack, load_witness_policy, verify_evidence_pack_offline,
};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::audit::AuthorityAtSigning;
use auths_sdk::domains::org::{add_member, revoke_member};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_verifier::IdentityDID;
use auths_verifier::core::Role;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

/// Initialize a developer identity to act as the **org** AID (the delegator).
fn setup_org_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(keychain.clone()));
    let result = match initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!(),
    };
    (result.key_alias, keychain)
}

/// `(ctx, org signing alias, org prefix, org did, tmp)` for a fresh org AID delegator.
fn setup() -> (
    AuthsContext,
    KeyAlias,
    Prefix,
    IdentityDID,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let (org_alias, keychain) = setup_org_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));
    let managed = ctx.identity_storage.load_identity().expect("org identity");
    let org_prefix = Prefix::new_unchecked(
        managed
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    let org_did = IdentityDID::from_prefix(org_prefix.as_str()).expect("org did");
    (ctx, org_alias, org_prefix, org_did, tmp)
}

/// Add a member and return its KEL prefix.
fn add_test_member(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    alias: &str,
) -> Prefix {
    let member = add_member(
        ctx,
        org_prefix,
        org_alias,
        &KeyAlias::new_unchecked(alias.to_string()),
        CurveType::Ed25519,
        Role::Member,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add member");
    Prefix::new_unchecked(member.member_prefix)
}

#[test]
fn revoked_member_still_shows_authorized_at_release() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "frank");

    // Revoke the member; the artifact was signed strictly BEFORE the revocation.
    let signed = revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", member.as_str()),
        None,
    )
    .expect("revoke")
    .expect("fresh revoke writes a record");
    let revoked_at = signed.record.revoked_at_seq;

    let releases = vec![
        // Signed before the revocation position → authorized at release.
        ReleaseRecord {
            artifact_digest: "sha256:aa".into(),
            signer_prefix: member.clone(),
            signed_at: Some(revoked_at - 1),
            transparency: None,
        },
        // Signed at/after the revocation → rejected at release.
        ReleaseRecord {
            artifact_digest: "sha256:bb".into(),
            signer_prefix: member.clone(),
            signed_at: Some(revoked_at),
            transparency: None,
        },
        // No in-band position → unclassifiable, NOT assumed authorized.
        ReleaseRecord {
            artifact_digest: "sha256:cc".into(),
            signer_prefix: member.clone(),
            signed_at: None,
            transparency: None,
        },
    ];

    let policy = load_witness_policy(None);
    let pack = build_evidence_pack(
        &ctx,
        org_did,
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build pack");

    assert_eq!(
        pack.rows[0].authority_at_release,
        AuthorityAtSigning::AuthorizedBeforeRevocation,
        "an artifact signed before revocation stays authorized-at-release even though the signer is revoked now"
    );
    assert_eq!(
        pack.rows[1].authority_at_release,
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at }
    );
    assert_eq!(
        pack.rows[2].authority_at_release,
        AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at },
        "no signing position → unclassifiable, never assumed authorized"
    );

    // The honest witness verdict is single-operator (placeholder policy), not a bare flag.
    assert!(!pack.equivocation_visibility.policy_met);
    let json = pack.canonicalize().unwrap();
    assert!(!json.contains("non_equivocation"));
}

#[test]
fn offline_pack_round_trips_and_verifies_with_zero_network() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "grace");

    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:dd".into(),
        signer_prefix: member.clone(),
        signed_at: Some(0),
        transparency: None,
    }];

    let policy = load_witness_policy(None);
    let pack = build_offline_evidence_pack(
        &ctx,
        org_did.clone(),
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build offline pack");
    assert!(
        pack.org_bundle.is_some(),
        "offline pack embeds the org KEL bundle"
    );

    // Serialize → deserialize → verify offline against the org as pinned root.
    let canonical = pack.canonicalize().unwrap();
    let reloaded = EvidencePack::from_json(&canonical).expect("reload pack");
    let verdicts = verify_evidence_pack_offline(&reloaded, std::slice::from_ref(&org_did), None)
        .expect("offline verify");
    assert_eq!(verdicts.len(), 1);
    assert!(
        verdicts[0].authority_consistent,
        "re-derived authority must match the recorded row"
    );
    assert_eq!(verdicts[0].transparency_verified, None);

    // A non-pinned root fails closed.
    let stranger = IdentityDID::new_unchecked("did:keri:EStranger".to_string());
    assert!(
        verify_evidence_pack_offline(&reloaded, &[stranger], None).is_err(),
        "an unpinned org must fail offline verification"
    );
}

#[test]
fn offline_verify_catches_a_tampered_row() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "heidi");

    // Revoke so the honest row is "rejected at release"; tampering will flip it to authorized.
    let signed = revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", member.as_str()),
        None,
    )
    .expect("revoke")
    .expect("record");
    let revoked_at = signed.record.revoked_at_seq;

    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:ee".into(),
        signer_prefix: member.clone(),
        signed_at: Some(revoked_at),
        transparency: None,
    }];
    let policy = load_witness_policy(None);
    let pack = build_offline_evidence_pack(
        &ctx,
        org_did.clone(),
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build offline pack");

    // Tamper: rewrite the row to claim authorized-before-revocation.
    let mut tampered: serde_json::Value =
        serde_json::from_str(&pack.canonicalize().unwrap()).unwrap();
    tampered["rows"][0]["authority_at_release"] =
        serde_json::json!({ "authority_at_signing": "authorized_before_revocation" });
    let tampered_pack = EvidencePack::from_json(&tampered.to_string()).unwrap();

    let verdicts =
        verify_evidence_pack_offline(&tampered_pack, &[org_did], None).expect("verify runs");
    assert!(
        !verdicts[0].authority_consistent,
        "re-deriving authority from the embedded KEL must expose the tampered row"
    );
}

#[test]
fn offline_verify_binds_transparency_proofs_to_the_rows_artifact() {
    use auths_sdk::domains::compliance::query::TransparencyInclusion;
    use auths_verifier::tlog::{
        Checkpoint, InclusionProof, LogOrigin, MerkleHash, SignedCheckpoint, compute_root,
        hash_leaf, prove_inclusion,
    };
    use auths_verifier::{Ed25519PublicKey, Ed25519Signature};

    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "judy");

    // A two-leaf log: leaf 0 is THIS row's digest, leaf 1 is some other artifact.
    let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let leaves = [hash_leaf(digest.as_bytes()), hash_leaf(b"sha256:other")];
    let root = compute_root(&leaves);
    let signed_checkpoint = SignedCheckpoint {
        checkpoint: Checkpoint {
            origin: LogOrigin::new("test.example/log").unwrap(),
            size: 2,
            root,
            timestamp: now(),
        },
        log_signature: Ed25519Signature::from_bytes([0u8; 64]),
        log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        witnesses: vec![],
        ecdsa_checkpoint_signature: None,
        ecdsa_checkpoint_key: None,
    };
    let inclusion_for = |index: u64, leaf: MerkleHash| TransparencyInclusion {
        leaf_hash: leaf,
        inclusion_proof: InclusionProof {
            index,
            size: 2,
            root,
            hashes: prove_inclusion(&leaves, index).unwrap(),
        },
        signed_checkpoint: signed_checkpoint.clone(),
        consistency_proof: None,
    };

    let releases = vec![
        ReleaseRecord {
            artifact_digest: digest.into(),
            signer_prefix: member.clone(),
            signed_at: Some(0),
            transparency: Some(inclusion_for(0, leaves[0])),
        },
        // A perfectly valid Merkle proof — but over the OTHER leaf. A row must
        // not borrow inclusion evidence that was minted for a different artifact.
        ReleaseRecord {
            artifact_digest: digest.into(),
            signer_prefix: member,
            signed_at: Some(0),
            transparency: Some(inclusion_for(1, leaves[1])),
        },
    ];
    let policy = load_witness_policy(None);
    let pack = build_offline_evidence_pack(
        &ctx,
        org_did.clone(),
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build offline pack");

    let verdicts = verify_evidence_pack_offline(&pack, std::slice::from_ref(&org_did), None)
        .expect("offline verify");
    assert_eq!(
        verdicts[0].transparency_verified,
        Some(true),
        "a proof over this row's own digest verifies"
    );
    assert_eq!(
        verdicts[1].transparency_verified,
        Some(false),
        "a valid proof over a different leaf must NOT count as this row's evidence"
    );
    assert_eq!(
        verdicts[0].checkpoint_attested, None,
        "with no pinned log key the verdict honestly reports membership only"
    );

    // Pin a log key this checkpoint was NOT signed by: Merkle membership still
    // verifies, but the operator axis fails — a forged/backdated checkpoint is
    // cryptographically visible, never silently green.
    let pinned = Ed25519PublicKey::from_bytes([3u8; 32]);
    let verdicts = verify_evidence_pack_offline(&pack, &[org_did], Some(&pinned))
        .expect("offline verify with a pinned log key");
    assert_eq!(
        verdicts[0].transparency_verified,
        Some(true),
        "membership math is unchanged by the pinned key"
    );
    assert_eq!(
        verdicts[0].checkpoint_attested,
        Some(false),
        "a checkpoint not signed by the pinned operator must fail the attestation axis"
    );
}

#[test]
fn dsse_sign_and_verify_round_trips() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "ivan");

    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:ff".into(),
        signer_prefix: member,
        signed_at: Some(0),
        transparency: None,
    }];
    let policy = load_witness_policy(None);
    let pack = build_evidence_pack(
        &ctx,
        org_did.clone(),
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build pack");

    let (org_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("org pubkey");

    let envelope = sign_evidence_pack(&ctx, org_did.as_str(), &org_alias, org_curve, &pack)
        .expect("org-sign the pack");

    envelope
        .verify(&org_pk, org_curve)
        .expect("the org DSSE signature verifies");

    // Tampering the payload breaks the signature.
    let mut tampered = envelope.clone();
    use base64::Engine;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(tampered.payload.as_bytes())
        .unwrap();
    bytes[0] ^= 0xff;
    tampered.payload = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(
        tampered.verify(&org_pk, org_curve).is_err(),
        "a tampered DSSE payload must fail verification"
    );
}

#[test]
fn signed_offline_pack_verifies_end_to_end_from_envelope_and_roots_alone() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "judy");

    // Revoke the member so the pack carries an honestly-damned row: the pack
    // must still verify as AUTHENTIC (the log telling the truth is the system
    // working), with the row's authority re-derivation consistent.
    let signed = revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", member.as_str()),
        None,
    )
    .expect("revoke")
    .expect("record");
    let revoked_at = signed.record.revoked_at_seq;

    let releases = vec![
        ReleaseRecord {
            artifact_digest: "sha256:gg".into(),
            signer_prefix: member.clone(),
            signed_at: Some(revoked_at - 1),
            transparency: None,
        },
        ReleaseRecord {
            artifact_digest: "sha256:hh".into(),
            signer_prefix: member,
            signed_at: Some(revoked_at),
            transparency: None,
        },
    ];
    let policy = load_witness_policy(None);
    let pack = build_offline_evidence_pack(
        &ctx,
        org_did.clone(),
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &releases,
        &policy,
        now(),
    )
    .expect("build offline pack");

    let (_org_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("org pubkey");
    let envelope = sign_evidence_pack(&ctx, org_did.as_str(), &org_alias, org_curve, &pack)
        .expect("org-sign the pack");
    let raw = envelope.to_canonical_json().expect("canonical envelope");

    // The auditor's whole input: the envelope bytes + a pinned root. No
    // keychain, no registry, no context.
    let verified = verify_signed_evidence_pack_offline(&raw, std::slice::from_ref(&org_did), None)
        .expect("signed pack verifies offline");
    assert_eq!(verified.verdicts.len(), 2);
    assert!(
        verified.verdicts.iter().all(|v| v.authority_consistent),
        "honest rows re-derive consistently — including the damned one"
    );
    assert_eq!(
        verified.verdicts[1].authority_at_release,
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at },
        "the post-revocation row is damned by the evidence itself"
    );
    assert!(
        verified.authentic(),
        "a pack honestly reporting a damned row is still authentic"
    );

    // Cook the books: mutate one row inside the payload (valid JSON, changed
    // bytes) — the DSSE signature over the PAE must refuse.
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut statement: serde_json::Value =
        serde_json::from_slice(&engine.decode(envelope.payload.as_bytes()).unwrap()).unwrap();
    statement["predicate"]["rows"][0]["artifact_digest"] = serde_json::json!("sha256:00");
    let mut tampered = envelope.clone();
    tampered.payload = engine.encode(statement.to_string().as_bytes());
    let raw_tampered = tampered.to_canonical_json().unwrap();
    assert!(
        verify_signed_evidence_pack_offline(&raw_tampered, std::slice::from_ref(&org_did), None)
            .is_err(),
        "a tampered payload must fail the DSSE signature check"
    );

    // An auditor who pinned a different root rejects the whole pack.
    let stranger = IdentityDID::new_unchecked("did:keri:EStranger".to_string());
    assert!(
        verify_signed_evidence_pack_offline(&raw, &[stranger], None).is_err(),
        "an unpinned org must fail closed"
    );
}

/// A fixed presentation-boundary timestamp (the domain never calls `Utc::now`).
fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

// ── fn-157.9: framework predicates (SLSA provenance + VSA, SPDX SBOM, CRA) ──

const VERIFIER: &str = "https://auths.dev/compliance";

/// Build a pack with the given framework from the supplied releases.
fn pack_with(
    ctx: &AuthsContext,
    org_did: &IdentityDID,
    org_prefix: &Prefix,
    framework: ComplianceFramework,
    releases: &[ReleaseRecord],
) -> EvidencePack {
    build_evidence_pack(
        ctx,
        org_did.clone(),
        org_prefix,
        "2026-Q3",
        framework,
        releases,
        &load_witness_policy(None),
        now(),
    )
    .expect("build pack")
}

fn vsa(allow_list: SignerVerifierAllowList) -> VsaParams {
    VsaParams {
        verifier_id: VERIFIER.to_string(),
        time_verified: now(),
        allow_list,
    }
}

#[test]
fn slsa_report_has_provenance_and_vsa_per_release() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let live = add_test_member(&ctx, &org_prefix, &org_alias, "judy");
    let gone = add_test_member(&ctx, &org_prefix, &org_alias, "mallory");
    revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", gone.as_str()),
        None,
    )
    .expect("revoke");

    let releases = vec![
        ReleaseRecord {
            artifact_digest: "sha256:aa".into(),
            signer_prefix: live,
            signed_at: Some(2),
            transparency: None,
        },
        // Signed AFTER revocation by KEL position → rejected.
        ReleaseRecord {
            artifact_digest: "sha256:bb".into(),
            signer_prefix: gone,
            signed_at: Some(9999),
            transparency: None,
        },
    ];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let pred = &report.statement["predicate"];
    assert_eq!(
        report.statement["predicateType"],
        "https://auths.dev/compliance/slsa/v1"
    );
    assert_eq!(pred["provenance"].as_array().unwrap().len(), 2);
    let vsas = pred["verificationSummaries"].as_array().unwrap();
    assert_eq!(vsas.len(), 2);
    let results: Vec<&str> = vsas
        .iter()
        .map(|v| v["verificationResult"].as_str().unwrap())
        .collect();
    assert!(results.contains(&"PASSED"), "the authorized release passes");
    assert!(results.contains(&"FAILED"), "the revoked-at-release fails");

    // Honesty: a single-operator pack carries the ceiling, never a third-party
    // non-equivocation claim.
    let canonical = report.to_intoto_statement().unwrap();
    assert!(canonical.contains("\"policy_met\":false"));
    assert!(!canonical.contains("non_equivocation"));
}

#[test]
fn slsa_vsa_carries_injected_timestamp_and_verifier() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "niaj");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:cc".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let v = &report.statement["predicate"]["verificationSummaries"][0];
    assert_eq!(v["verifier"]["id"], VERIFIER);
    assert!(
        v["timeVerified"]
            .as_str()
            .unwrap()
            .starts_with("2026-06-08"),
        "the injected verification timestamp is recorded"
    );
}

#[test]
fn vsa_rows_tagged_timeless_vs_time_sensitive() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "olivia");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:dd".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let pred = &report.statement["predicate"];
    assert_eq!(pred["provenance"][0]["timeliness"], "timeless");
    assert_eq!(
        pred["verificationSummaries"][0]["timeliness"],
        "time_sensitive"
    );
}

#[test]
fn vsa_enforces_signer_verifier_allow_list() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "peggy");
    let signer_did = format!("did:keri:{}", m.as_str());
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:ee".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );

    // A configured list that does NOT pair this signer with our verifier → FAILED.
    let denied = SignerVerifierAllowList::new().allow("did:keri:ESomeoneElse", VERIFIER);
    let report = build_framework_report(&pack, &vsa(denied)).unwrap();
    assert_eq!(
        report.statement["predicate"]["verificationSummaries"][0]["verificationResult"],
        "FAILED"
    );

    // The correct pairing → PASSED.
    let allowed = SignerVerifierAllowList::new().allow(&signer_did, VERIFIER);
    let report = build_framework_report(&pack, &vsa(allowed)).unwrap();
    assert_eq!(
        report.statement["predicate"]["verificationSummaries"][0]["verificationResult"],
        "PASSED"
    );
}

#[test]
fn vsa_preserves_point_in_time_authority() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let gone = add_test_member(&ctx, &org_prefix, &org_alias, "quinn");
    revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", gone.as_str()),
        None,
    )
    .expect("revoke");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:f0".into(),
        signer_prefix: gone,
        signed_at: Some(9999),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    // The VSA carries the pack's point-in-time classification verbatim — never a
    // HEAD re-resolution.
    let authority =
        &report.statement["predicate"]["verificationSummaries"][0]["authorityAtRelease"];
    assert_eq!(
        authority["authority_at_signing"],
        "rejected_after_revocation"
    );
}

#[test]
fn slsa_report_dsse_signs_and_verifies() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "rupert");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:f1".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Slsa,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let (org_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .unwrap();
    let envelope =
        sign_framework_report(&ctx, org_did.as_str(), &org_alias, org_curve, &report).unwrap();
    envelope
        .verify(&org_pk, org_curve)
        .expect("the framework predicate verifies on the same DSSE path");
}

#[test]
fn sbom_report_pins_spdx_version_and_hashes_exact_bytes() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "sybil");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:f2".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Sbom,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let pred = &report.statement["predicate"];
    assert_eq!(pred["spdxVersion"], SPDX_VERSION);
    let recorded = pred["documentSha256"].as_str().unwrap();
    let recomputed = sbom_document_sha256(&pred["document"]).unwrap();
    assert_eq!(
        recorded, recomputed,
        "the anchored hash covers the exact document bytes"
    );
    assert_eq!(report.sbom_sha256.as_deref(), Some(recorded));
}

#[test]
fn sbom_regenerated_bytes_mismatch_is_detected() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "trent");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:f3".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Sbom,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let mut tampered = report.statement["predicate"]["document"].clone();
    tampered["name"] = serde_json::json!("tampered-sbom");
    assert_ne!(
        sbom_document_sha256(&tampered).unwrap(),
        report.sbom_sha256.unwrap(),
        "a regenerated SBOM differing by one byte must not match the anchored hash"
    );
}

#[test]
fn cra_report_maps_obligations_and_ssdf_practices() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "victor");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:f4".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Cra,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let obligations = report.statement["predicate"]["obligations"]
        .as_array()
        .unwrap();
    assert!(!obligations.is_empty());
    assert!(
        obligations.iter().any(|o| o["ssdf_practices"]
            .as_array()
            .is_some_and(|p| !p.is_empty())),
        "obligations reference NIST SSDF practice IDs"
    );
    let canonical = report.to_intoto_statement().unwrap();
    assert!(canonical.contains("\"policy_met\":false"));
    assert!(!canonical.contains("non_equivocation"));
}

#[test]
fn soc2_report_maps_trust_services_criteria() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "trent");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:c2".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Soc2,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let criteria = report.statement["predicate"]["trustServicesCriteria"]
        .as_array()
        .unwrap();
    assert!(!criteria.is_empty());
    // The off-boarding controls the demo names must be present.
    let ids: Vec<&str> = criteria.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(ids.contains(&"CC6.2") && ids.contains(&"CC6.3"));
    assert_eq!(
        report.predicate_type,
        "https://auths.dev/compliance/soc2/v1"
    );
    let canonical = report.to_intoto_statement().unwrap();
    assert!(canonical.contains("\"policy_met\":false"));
    assert!(!canonical.contains("non_equivocation"));
}

#[test]
fn iso27001_report_maps_annex_a_controls() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let m = add_test_member(&ctx, &org_prefix, &org_alias, "peggy");
    let releases = vec![ReleaseRecord {
        artifact_digest: "sha256:15".into(),
        signer_prefix: m,
        signed_at: Some(2),
        transparency: None,
    }];
    let pack = pack_with(
        &ctx,
        &org_did,
        &org_prefix,
        ComplianceFramework::Iso27001,
        &releases,
    );
    let report = build_framework_report(&pack, &vsa(SignerVerifierAllowList::new())).unwrap();

    let controls = report.statement["predicate"]["annexAControls"]
        .as_array()
        .unwrap();
    assert!(!controls.is_empty());
    let ids: Vec<&str> = controls.iter().filter_map(|c| c["id"].as_str()).collect();
    // The 2022 identity/access-rights controls the demo names.
    assert!(ids.contains(&"A.5.16") && ids.contains(&"A.5.18"));
    assert_eq!(
        report.predicate_type,
        "https://auths.dev/compliance/iso27001/v1"
    );
    let canonical = report.to_intoto_statement().unwrap();
    assert!(canonical.contains("\"policy_met\":false"));
    assert!(!canonical.contains("non_equivocation"));
}

// ── Anchored releases: attest at signing time, discover at report time ──────

use auths_sdk::domains::compliance::releases::{ArtifactDigest, attest_release, discover_releases};

/// A parsed `sha256:` digest of one repeated hex character (test fixture).
fn digest_of(c: char) -> ArtifactDigest {
    ArtifactDigest::parse(&format!("sha256:{}", c.to_string().repeat(64))).expect("valid digest")
}

#[test]
fn attest_then_discover_derives_signed_at_from_the_org_kel() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "judy");

    let d1 = digest_of('a');
    let d2 = digest_of('b');
    let a1 = attest_release(&ctx, &org_prefix, &org_alias, d1.clone(), member.clone())
        .expect("attest release 1");
    let a2 = attest_release(&ctx, &org_prefix, &org_alias, d2.clone(), member.clone())
        .expect("attest release 2");
    assert!(
        a2.signed_at > a1.signed_at,
        "each attestation anchors at a strictly later KEL position"
    );

    // add_test_member anchored a membership attestation in the same KEL — only
    // the release attestations may be discovered.
    let records = discover_releases(ctx.registry.as_ref(), &org_prefix).expect("discover");
    assert_eq!(records.len(), 2, "exactly the attested releases discovered");
    assert_eq!(records[0].artifact_digest, d1.as_str());
    assert_eq!(records[0].signer_prefix, member);
    assert_eq!(
        records[0].signed_at,
        Some(a1.signed_at),
        "signed_at IS the anchoring position, never caller input"
    );
    assert_eq!(records[1].artifact_digest, d2.as_str());
    assert_eq!(records[1].signed_at, Some(a2.signed_at));

    // The discovered rows classify as authorized — the member was live at both
    // anchored positions.
    let policy = load_witness_policy(None);
    let pack = build_evidence_pack(
        &ctx,
        org_did,
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &records,
        &policy,
        now(),
    )
    .expect("build pack from discovered releases");
    assert!(
        pack.rows
            .iter()
            .all(|r| r.authority_at_release == AuthorityAtSigning::AuthorizedBeforeRevocation)
    );
}

#[test]
fn release_attested_after_revocation_is_damned_by_discovery() {
    let (ctx, org_alias, org_prefix, org_did, _tmp) = setup();
    let member = add_test_member(&ctx, &org_prefix, &org_alias, "kevin");

    let before = attest_release(
        &ctx,
        &org_prefix,
        &org_alias,
        digest_of('c'),
        member.clone(),
    )
    .expect("attest before revocation");

    let signed = revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &format!("did:keri:{}", member.as_str()),
        None,
    )
    .expect("revoke")
    .expect("fresh revoke writes a record");
    let revoked_at = signed.record.revoked_at_seq;
    assert!(before.signed_at < revoked_at);

    let after = attest_release(
        &ctx,
        &org_prefix,
        &org_alias,
        digest_of('d'),
        member.clone(),
    )
    .expect("attest after revocation");
    assert!(after.signed_at >= revoked_at);

    let records = discover_releases(ctx.registry.as_ref(), &org_prefix).expect("discover");
    assert_eq!(records.len(), 2);

    let policy = load_witness_policy(None);
    let pack = build_evidence_pack(
        &ctx,
        org_did,
        &org_prefix,
        "2026-Q3",
        ComplianceFramework::Slsa,
        &records,
        &policy,
        now(),
    )
    .expect("build pack");
    assert_eq!(
        pack.rows[0].authority_at_release,
        AuthorityAtSigning::AuthorizedBeforeRevocation,
        "the pre-revocation release stays authorized at its anchored position"
    );
    assert_eq!(
        pack.rows[1].authority_at_release,
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at },
        "a release anchored after revocation is damned by the log itself"
    );
}
