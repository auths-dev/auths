//! Honesty tripwire: no public positive trust verdict is a bare `Valid`.
//!
//! Invariant #6 — a positive verdict never says only "valid"; it carries the **`{as_of, freshness}`**
//! pair: *how current* the slice is (the KEL position it was verified as-of) and *how fresh*
//! (`Fresh` / `Unknown` / `Stale`), so a relying party can both apply its own tolerance and see
//! against what position the grade holds. This battery enumerates every public positive verdict the
//! verifier emits and asserts each carries both, then pins the externally-observable JSON verdict wire
//! (`verify_presentation_json` / `verify_credential_json`) so the FFI/WASM surfaces carry them in
//! lockstep. If a future change adds a positive verdict that drops `as_of` or `freshness`, this goes
//! RED — structurally (the construction loses its field) or on the wire (the JSON verdict loses its key).
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
const NON_FRESHNESS_BEARING_POSITIVE_VERDICTS: &[&str] = &[
    "OfflineReceiptVerdict::Verified",
    "OfflineBuildVerdict::Verified",
];

fn did(s: &str) -> IdentityDID {
    IdentityDID::parse(s).expect("did")
}

fn subject(s: &str) -> CanonicalDid {
    CanonicalDid::parse(s).expect("subject")
}

#[test]
fn presentation_valid_names_as_of_and_freshness() {
    let verdict = PresentationVerdict::Valid {
        issuer: did("did:keri:Eissuer"),
        subject: subject("did:keri:Eholder"),
        subject_root: subject("did:keri:Eholder"),
        caps: vec![Capability::parse("acme:read").expect("cap")],
        role: None,
        expires_at: None,
        freshness: Freshness::Unknown,
        as_of: 4,
    };
    assert_eq!(verdict.freshness(), Some(Freshness::Unknown));
    assert_eq!(
        verdict.as_of(),
        Some(4),
        "an honored verdict names the slice position it is as-of"
    );
}

#[test]
fn credential_valid_names_as_of_and_freshness() {
    let verdict = CredentialVerdict::Valid {
        issuer: did("did:keri:Eissuer"),
        subject: subject("did:keri:Eholder"),
        caps: vec![],
        as_of: 3,
        freshness: Freshness::Unknown,
    };
    assert_eq!(verdict.freshness(), Freshness::Unknown);
    assert_eq!(verdict.as_of(), Some(3));
}

#[test]
fn commit_valid_names_as_of_and_freshness() {
    let verdict = CommitVerdict::Valid {
        signer_did: "did:keri:Edev".to_string(),
        root_did: "did:keri:Eroot".to_string(),
        duplicitous_root: false,
        as_of: 2,
        freshness: Freshness::Unknown,
    };
    assert_eq!(verdict.freshness(), Freshness::Unknown);
    assert_eq!(verdict.as_of(), Some(2));
}

#[test]
fn duplicitous_root_is_not_trusted_even_when_fresh() {
    use auths_verifier::freshness::FreshnessPolicy;
    let verdict = CommitVerdict::Valid {
        signer_did: "did:keri:Edev".to_string(),
        root_did: "did:keri:Eroot".to_string(),
        duplicitous_root: true,
        as_of: 2,
        freshness: Freshness::Fresh,
    };
    // Fail-closed: a forked root KEL is not trusted even with a fresh, valid signature —
    // the relying party cannot tell which branch is real.
    assert!(!verdict.is_trusted(&FreshnessPolicy::default()));
    // is_valid() stays true: the signature/chain verified; only the trust gate fails closed.
    assert!(verdict.is_valid());
}

#[test]
fn verification_report_valid_names_as_of_and_freshness() {
    let report = VerificationReport::valid(vec![]);
    assert!(report.is_valid());
    assert_eq!(report.freshness(), Freshness::Unknown);
    // The pure chain verifier reports no slice position, so `as_of` is honestly `None`; the
    // verdict still *carries* the position channel, and a caller with the slice stamps it.
    assert_eq!(report.as_of(), None);
    assert_eq!(
        report.with_as_of(9).as_of(),
        Some(9),
        "a report can carry its verified position"
    );
}

#[test]
fn presentation_json_valid_verdict_carries_as_of_and_freshness_on_the_wire() {
    let verdict: serde_json::Value =
        serde_json::from_str(&verify_presentation_json(PRESENTATION_VALID)).expect("verdict json");
    assert_eq!(
        verdict["kind"], "valid",
        "fixture must be a valid presentation"
    );
    assert!(
        verdict.get("freshness").and_then(|f| f.as_str()).is_some(),
        "a valid presentation JSON verdict must name its freshness, got {verdict}"
    );
    assert!(
        verdict.get("asOf").and_then(|a| a.as_u64()).is_some(),
        "a valid presentation JSON verdict must carry its slice position (camelCase asOf), got {verdict}"
    );
}

#[test]
fn credential_json_valid_verdict_carries_as_of_and_freshness_on_the_wire() {
    let verdict: serde_json::Value =
        serde_json::from_str(&verify_credential_json(CREDENTIAL_VALID)).expect("verdict json");
    assert_eq!(
        verdict["kind"], "valid",
        "fixture must be a valid credential"
    );
    assert!(
        verdict.get("freshness").and_then(|f| f.as_str()).is_some(),
        "a valid credential JSON verdict must name its freshness in lockstep with the \
         presentation wire, got {verdict}"
    );
    assert!(
        verdict.get("asOf").and_then(|a| a.as_u64()).is_some(),
        "a valid credential JSON verdict must carry its slice position in lockstep, got {verdict}"
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
