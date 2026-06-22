//! Honesty tripwire: no public positive trust verdict is a bare `Valid`.
//!
//! Invariant #6 — a positive verdict never says only "valid"; it names its freshness
//! (`Fresh` / `Unknown` / `Stale`) so a relying party can apply its own tolerance. This
//! battery enumerates every public positive verdict the verifier emits and asserts each
//! one carries a named freshness, then pins the externally-observable JSON verdict wire
//! (`verify_presentation_json` / `verify_credential_json`) so the FFI/WASM surfaces carry
//! it in lockstep. If a future change adds a positive verdict that drops freshness, this
//! goes RED — structurally (the construction loses its field) or on the wire (the JSON
//! verdict loses its key).
//!
//! The one documented exception is the witness/build corroboration-or-measurement set,
//! which is NOT a time-bounded authority claim (see [`NON_FRESHNESS_BEARING_POSITIVE_VERDICTS`]).

use auths_verifier::{
    CanonicalDid, Capability, CommitVerdict, CredentialVerdict, Freshness, IdentityDID,
    PresentationVerdict, VerificationReport, verify_credential_json, verify_presentation_json,
};

const CREDENTIAL_VALID: &str = include_str!("../fixtures/credential_valid.json");
const PRESENTATION_VALID: &str = include_str!("../fixtures/presentation_valid.json");

/// Positive verdicts that are deliberately NOT freshness-bearing: a witness receipt *is*
/// freshness evidence and a build-digest match is a self-measurement, neither a
/// time-bounded authority claim. Documented on the types themselves; listed here so the
/// tripwire's scope is explicit and auditable rather than a silent omission.
const NON_FRESHNESS_BEARING_POSITIVE_VERDICTS: &[&str] =
    &["OfflineReceiptVerdict::Verified", "OfflineBuildVerdict::Verified"];

fn did(s: &str) -> IdentityDID {
    IdentityDID::parse(s).expect("did")
}

fn subject(s: &str) -> CanonicalDid {
    CanonicalDid::parse(s).expect("subject")
}

#[test]
fn presentation_valid_names_a_freshness() {
    let verdict = PresentationVerdict::Valid {
        issuer: did("did:keri:Eissuer"),
        subject: subject("did:keri:Eholder"),
        caps: vec![Capability::parse("acme:read").expect("cap")],
        role: None,
        expires_at: None,
        freshness: Freshness::Unknown,
    };
    assert_eq!(verdict.freshness(), Some(Freshness::Unknown));
}

#[test]
fn credential_valid_names_a_freshness() {
    let verdict = CredentialVerdict::Valid {
        issuer: did("did:keri:Eissuer"),
        subject: subject("did:keri:Eholder"),
        caps: vec![],
        as_of: 0,
        freshness: Freshness::Unknown,
    };
    assert_eq!(verdict.freshness(), Freshness::Unknown);
}

#[test]
fn commit_valid_names_a_freshness() {
    let verdict = CommitVerdict::Valid {
        signer_did: "did:keri:Edev".to_string(),
        root_did: "did:keri:Eroot".to_string(),
        duplicitous_root: false,
        as_of: 0,
        freshness: Freshness::Unknown,
    };
    assert_eq!(verdict.freshness(), Freshness::Unknown);
}

#[test]
fn verification_report_valid_names_a_freshness() {
    let report = VerificationReport::valid(vec![]);
    assert!(report.is_valid());
    assert_eq!(report.freshness(), Freshness::Unknown);
}

#[test]
fn presentation_json_valid_verdict_carries_freshness_on_the_wire() {
    let verdict: serde_json::Value =
        serde_json::from_str(&verify_presentation_json(PRESENTATION_VALID)).expect("verdict json");
    assert_eq!(verdict["kind"], "valid", "fixture must be a valid presentation");
    assert!(
        verdict.get("freshness").and_then(|f| f.as_str()).is_some(),
        "a valid presentation JSON verdict must name its freshness, got {verdict}"
    );
}

#[test]
fn credential_json_valid_verdict_carries_freshness_on_the_wire() {
    let verdict: serde_json::Value =
        serde_json::from_str(&verify_credential_json(CREDENTIAL_VALID)).expect("verdict json");
    assert_eq!(verdict["kind"], "valid", "fixture must be a valid credential");
    assert!(
        verdict.get("freshness").and_then(|f| f.as_str()).is_some(),
        "a valid credential JSON verdict must name its freshness in lockstep with the \
         presentation wire, got {verdict}"
    );
}

#[test]
fn non_freshness_allowlist_is_explicit() {
    // The allowlist is the only sanctioned way a positive verdict omits freshness; keep it
    // small and named so a new bare-positive verdict cannot hide as "obviously fine".
    assert_eq!(
        NON_FRESHNESS_BEARING_POSITIVE_VERDICTS.len(),
        2,
        "extending the non-freshness allowlist is a deliberate, reviewed act"
    );
}
