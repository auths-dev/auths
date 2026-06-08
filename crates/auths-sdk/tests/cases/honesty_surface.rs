//! fn-157.10 — Honesty-surface capstone.
//!
//! The objection we most fear — *self-run witnesses ≠ independence* — is answered by
//! code, not prose. This cross-cutting regression asserts that with the placeholder /
//! single-operator witness policy, NO E2 surface (evidence pack, framework report,
//! monitor) emits a third-party non-equivocation claim, and that the bypass paths
//! stay closed: no `.unwrap_or(unconstrained())`, no public `Grant` constructor, no
//! `Utc::now()` in pack generation. It runs in CI as part of the normal test sweep.
//!
//! The `IdpAttestation -> Grant` isolation is asserted behaviourally by
//! `cases::federation::idp_attestation_cannot_grant`; here we add the structural guard.

use std::fs;
use std::path::PathBuf;

use auths_sdk::workflows::compliance::{
    ComplianceFramework, EvidencePack, SignerVerifierAllowList, VsaParams, build_framework_report,
    load_witness_policy,
};
use auths_verifier::IdentityDID;

/// The bare flag a surface must NEVER emit while the commons is single-operator.
const FORBIDDEN_FLAG: &str = "non_equivocation";

/// Read a workspace file relative to the crates/ root (`CARGO_MANIFEST_DIR` = crates/auths-sdk).
fn workspace_file(rel: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn fixed_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// A pack under the placeholder witness policy → honest single-operator ceiling.
fn single_operator_pack(framework: ComplianceFramework) -> EvidencePack {
    let policy = load_witness_policy(None);
    let ceiling = auths_transparency::ceiling_for_policy_load(&policy);
    assert!(
        !ceiling.policy_met,
        "the placeholder policy must render a single-operator ceiling"
    );
    EvidencePack {
        schema_version: 1,
        org: IdentityDID::new_unchecked("did:keri:EHonestyCapstoneOrg".to_string()),
        period: "2026-Q3".to_string(),
        framework,
        equivocation_visibility: ceiling,
        generated_at: fixed_now(),
        rows: vec![],
        org_bundle: None,
    }
}

#[test]
fn honesty_single_operator_pack_emits_no_third_party_claim() {
    let json = single_operator_pack(ComplianceFramework::Slsa)
        .canonicalize()
        .unwrap();
    assert!(
        json.contains("\"policy_met\":false"),
        "carries the honest ceiling"
    );
    assert!(
        !json.contains(FORBIDDEN_FLAG),
        "never a bare non-equivocation flag"
    );
}

#[test]
fn honesty_framework_reports_emit_no_third_party_claim() {
    let vsa = VsaParams {
        verifier_id: "https://auths.dev/compliance".to_string(),
        time_verified: fixed_now(),
        allow_list: SignerVerifierAllowList::new(),
    };
    for fw in [
        ComplianceFramework::Slsa,
        ComplianceFramework::Sbom,
        ComplianceFramework::Cra,
    ] {
        let pack = single_operator_pack(fw);
        let stmt = build_framework_report(&pack, &vsa)
            .unwrap()
            .to_intoto_statement()
            .unwrap();
        assert!(
            stmt.contains("\"policy_met\":false"),
            "{fw:?} carries the ceiling"
        );
        assert!(
            !stmt.contains(FORBIDDEN_FLAG),
            "{fw:?} emits no bare non-equivocation flag"
        );
        assert!(
            !stmt.to_lowercase().contains("independent operators"),
            "{fw:?} claims no independent operators under a single-operator policy"
        );
    }
}

#[test]
fn honesty_no_utc_now_in_pack_generation() {
    for rel in [
        "auths-sdk/src/domains/compliance/query.rs",
        "auths-sdk/src/domains/compliance/frameworks.rs",
        "auths-sdk/src/domains/compliance/dsse.rs",
        "auths-sdk/src/domains/federation/oidc.rs",
        "auths-sdk/src/domains/federation/anchor.rs",
        "auths-sdk/src/domains/federation/saml.rs",
        "auths-sdk/src/domains/federation/signal.rs",
        "auths-sdk/src/domains/federation/types.rs",
    ] {
        let src = workspace_file(rel);
        for (i, line) in src.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // doc/line comments may reference the banned call by name
            }
            assert!(
                !line.contains("Utc::now"),
                "{rel}:{} uses Utc::now in domain code — inject the clock instead",
                i + 1
            );
        }
    }
}

#[test]
fn honesty_no_unconstrained_fallback_bypass() {
    for rel in [
        "auths-monitor/src/main.rs",
        "auths-checkpoint-cosigner/src/lib.rs",
        "auths-sdk/src/domains/compliance/query.rs",
        "auths-sdk/src/domains/compliance/frameworks.rs",
    ] {
        let src = workspace_file(rel);
        for (i, line) in src.lines().enumerate() {
            let bypass = line.contains("unwrap_or") && line.contains("unconstrained");
            assert!(
                !bypass,
                "{rel}:{} reintroduces a .unwrap_or(...unconstrained()) independence bypass",
                i + 1
            );
        }
    }
}

#[test]
fn honesty_grant_constructor_is_private() {
    let src = workspace_file("auths-rp/src/principal.rs");
    let start = src.find("pub struct Grant {").expect("Grant struct exists");
    let rest = &src[start..];
    let open = rest.find('{').expect("Grant struct body opens");
    let end = rest.find('}').expect("Grant struct closes");
    let fields = &rest[open + 1..end];
    assert!(
        !fields.contains("pub "),
        "Grant fields must be private — no public constructor can mint a Grant outside auths-rp"
    );
}

#[test]
fn honesty_monitor_disclaims_independence_when_policy_unmet() {
    let src = workspace_file("auths-monitor/src/main.rs");
    assert!(
        src.contains("ceiling_for_policy_load"),
        "the monitor computes the honest ceiling from the live policy load"
    );
    assert!(
        src.contains("does NOT assert independent-operator non-equivocation"),
        "the monitor explicitly disclaims independence when the policy is unmet"
    );
}

#[test]
fn honesty_accepted_risks_doc_exists() {
    let doc = workspace_file("../docs/architecture/compliance_federation_accepted_risks.md");
    for required in [
        "Single-operator witness gate",
        "SCIM static-bearer",
        "Soft-disable is not revocation",
        "in-band signing position",
        "curve map",
        "does NOT prove",
    ] {
        assert!(
            doc.contains(required),
            "accepted-risks doc must cover: {required}"
        );
    }
}
