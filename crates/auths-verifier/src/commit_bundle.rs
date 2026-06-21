//! Stateless commit verification against an identity bundle — no git, no
//! identity store, no network.
//!
//! An exported identity bundle carries everything a verifier with nothing
//! installed needs to decide "commit ← maintainer": the identity's KEL, one
//! CESR signature attachment per event, and a freshness window. This module
//! turns that bundle into a [`BundleTrust`] — a parsed trust anchor whose
//! existence proves the bundle was fresh, self-certifying (RT-005), and
//! signature-authenticated (RT-002) — and then verifies a raw commit object
//! against it with [`verify_commit_against_kel`]. The same path serves the CLI
//! (`--identity-bundle` on a bare CI runner) and the browser (the
//! `verifyCommitJson` WASM export), so the verdict cannot drift between
//! transports.

use auths_keri::{Event, compute_event_said, pair_kel_attachments, validate_signed_kel};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::commit_kel::{CommitVerdict, commit_signer_trailers, verify_commit_against_kel};
use crate::core::{IdentityBundle, MAX_JSON_BATCH_SIZE};
use crate::freshness::{Freshness, FreshnessEvidence, FreshnessPolicy};
use auths_crypto::CryptoProvider;

/// Why an identity bundle could not become a trust anchor. Fails closed: an
/// unusable bundle is rejected, never silently treated as "no constraint".
#[derive(Debug, thiserror::Error)]
pub enum BundleTrustError {
    /// The bundle is past its own TTL.
    #[error("bundle is stale: {0}")]
    Stale(String),

    /// RT-005: the bundle's `identity_did` does not name the inception its KEL
    /// carries, so it could pair a victim's DID with an attacker-authored KEL.
    #[error("bundle does not self-certify: {0}")]
    NotSelfCertifying(String),

    /// RT-002: the bundle's KEL events could not be authenticated against the
    /// controlling key-state (missing, malformed, or forged signature
    /// attachments). Re-export with a current `auths id export-bundle`.
    #[error("bundle KEL failed signature authentication (RT-002): {0}")]
    KelUnauthenticated(String),
}

/// A parsed, authenticated trust anchor extracted from an identity bundle.
///
/// Constructing one ([`BundleTrust::parse`]) proves three things, so callers
/// never re-check them:
///
/// 1. **Freshness** — the bundle is within its own TTL.
/// 2. **Self-certification (RT-005)** — the bundle's `identity_did` names the
///    inception event its KEL carries (SAID for `E…` prefixes, controller
///    field otherwise), so a bundle cannot pair a victim's DID with an
///    attacker-authored KEL.
/// 3. **KEL authentication (RT-002)** — every KEL event is signed by its
///    controlling key-state, verified via [`validate_signed_kel`]; a stripped
///    or forged attachment fails closed here.
///
/// The bundle is *evidence for* a pinned root, never the source of the pin:
/// callers must still require [`BundleTrust::root_did`] to be in their
/// independently pinned root set.
pub struct BundleTrust {
    root_did: String,
    kel: Vec<Event>,
}

impl BundleTrust {
    /// Parse a bundle into a trust anchor: freshness + RT-005 + RT-002.
    ///
    /// Args:
    /// * `bundle`: The deserialized identity bundle (attacker-controlled input).
    /// * `now`: Current time, injected at the boundary.
    ///
    /// Usage:
    /// ```ignore
    /// let trust = BundleTrust::parse(&bundle, Utc::now())?;
    /// assert!(pinned_roots.contains(&trust.root_did().to_string()));
    /// ```
    pub fn parse(bundle: &IdentityBundle, now: DateTime<Utc>) -> Result<Self, BundleTrustError> {
        bundle
            .check_freshness(now)
            .map_err(|e| BundleTrustError::Stale(e.to_string()))?;

        // RT-005 — self-certification: the DID the caller is about to treat as
        // a root MUST actually name the inception the bundle carries. For a
        // self-addressing (`E`) root the DID MUST equal the inception SAID; for
        // a basic-derivation root it MUST equal the inception's controller
        // field (and replay independently enforces `i == k[0]`).
        if let Some(inception) = bundle.kel.first() {
            let claimed = bundle.identity_did.to_string();
            let prefix = claimed
                .strip_prefix("did:keri:")
                .unwrap_or(claimed.as_str());
            if prefix.starts_with('E') {
                let said = compute_event_said(inception).map_err(|e| {
                    BundleTrustError::NotSelfCertifying(format!(
                        "bundle KEL inception has no computable SAID: {e}"
                    ))
                })?;
                if prefix != said.as_str() {
                    return Err(BundleTrustError::NotSelfCertifying(format!(
                        "bundle identity_did {claimed} does not self-certify to its \
                         inception SAID did:keri:{said}"
                    )));
                }
            } else {
                let inception_i = inception.prefix().as_str();
                if prefix != inception_i {
                    return Err(BundleTrustError::NotSelfCertifying(format!(
                        "bundle identity_did {claimed} does not match its inception \
                         controller {inception_i}"
                    )));
                }
            }
        }

        // RT-002 — authenticate the KEL: every event must carry a valid CESR
        // signature from its controlling key-state. The count-mismatch refusal
        // (absent/short attachment list ⇒ unauthenticated KEL) lives once, in
        // `pair_kel_attachments` — never re-implemented here.
        if !bundle.kel.is_empty() {
            let attachment_bytes: Vec<Vec<u8>> = bundle
                .kel_attachments
                .iter()
                .map(|att_hex| {
                    hex::decode(att_hex).map_err(|e| {
                        BundleTrustError::KelUnauthenticated(format!(
                            "non-hex KEL signature attachment: {e}"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?;
            let signed = pair_kel_attachments(bundle.kel.clone(), &attachment_bytes)
                .map_err(|e| BundleTrustError::KelUnauthenticated(e.to_string()))?;
            validate_signed_kel(&signed, None)
                .map_err(|e| BundleTrustError::KelUnauthenticated(e.to_string()))?;
        }

        Ok(Self {
            root_did: bundle.identity_did.to_string(),
            kel: bundle.kel.clone(),
        })
    }

    /// The root `did:keri:` this bundle self-certifies to. Evidence for a pin,
    /// never the pin itself.
    pub fn root_did(&self) -> &str {
        &self.root_did
    }

    /// The authenticated KEL events, oldest first.
    pub fn kel(&self) -> &[Event] {
        &self.kel
    }

    /// Consume the anchor into `(root_did, kel)` for callers that thread the
    /// parts separately (the CLI's stateless resolver).
    pub fn into_parts(self) -> (String, Vec<Event>) {
        (self.root_did, self.kel)
    }
}

/// The tagged JSON envelope returned by [`verify_commit_with_bundle_json`]:
/// `kind: "verdict"` carries the commit verdict; `kind: "error"` means the
/// inputs never reached a verdict (unusable bundle, unpinned root, bad JSON).
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum CommitBundleEnvelope {
    Verdict {
        valid: bool,
        verdict: &'static str,
        detail: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signer_did: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        root_did: Option<String>,
        /// The freshness grade of a positive verdict; the relying party's policy, not the
        /// bundle's TTL, decides whether it clears (ADR 009).
        #[serde(skip_serializing_if = "Option::is_none")]
        freshness: Option<Freshness>,
        /// The signer-KEL tip the verdict was decided against.
        #[serde(skip_serializing_if = "Option::is_none")]
        as_of: Option<u128>,
    },
    Error {
        error: String,
    },
}

fn envelope_to_string(envelope: &CommitBundleEnvelope) -> String {
    serde_json::to_string(envelope)
        .unwrap_or_else(|_| r#"{"kind":"error","error":"serialization failed"}"#.to_string())
}

/// A stable machine code for each [`CommitVerdict`] variant. Thin alias over the
/// canonical [`CommitVerdict::code`] so the bundle-JSON `kind` and the CLI `status`
/// field share one source of truth.
fn verdict_code(verdict: &CommitVerdict) -> &'static str {
    verdict.code()
}

/// A human-readable one-liner for each [`CommitVerdict`] variant.
fn verdict_detail(verdict: &CommitVerdict) -> String {
    match verdict {
        CommitVerdict::Valid {
            signer_did,
            root_did,
            duplicitous_root,
            ..
        } => {
            let fork = if *duplicitous_root {
                " (warning: root KEL shows a fork)"
            } else {
                ""
            };
            format!("commit signed by {signer_did}, chained to pinned root {root_did}{fork}")
        }
        CommitVerdict::Unsigned => "commit carries no SSH signature".to_string(),
        CommitVerdict::SshSignatureInvalid => "SSH signature did not validate".to_string(),
        CommitVerdict::GpgUnsupported => "PGP-signed commit (unsupported)".to_string(),
        CommitVerdict::DeviceKelInvalid(e) => format!("device KEL invalid: {e}"),
        CommitVerdict::RootKelInvalid(e) => format!("root KEL invalid: {e}"),
        CommitVerdict::RootNotPinned(did) => format!("root {did} is not pinned"),
        CommitVerdict::RootAbandoned => "root identity is abandoned".to_string(),
        CommitVerdict::NotDelegatedByClaimedRoot {
            device_did,
            root_did,
        } => format!("{device_did} is not delegated by {root_did}"),
        CommitVerdict::DelegationSealNotFound => {
            "root never anchored the device's delegation".to_string()
        }
        CommitVerdict::DeviceRevoked => "the signer's delegation is revoked".to_string(),
        CommitVerdict::SignedAfterRevocation {
            signed_at,
            revoked_at,
            ..
        } => format!("signed at KEL position {signed_at}, revoked at {revoked_at}"),
        CommitVerdict::OutsideAgentScope { capability, .. } => {
            format!("capability {capability} is outside the agent's anchored scope")
        }
        CommitVerdict::AgentExpired { expired_at, .. } => {
            format!("agent delegation expired at {expired_at}")
        }
        CommitVerdict::SignerKeyMismatch => {
            "SSH signer key is not the device's current key".to_string()
        }
        CommitVerdict::SignedBySupersededKey => {
            "SSH signer key was superseded by a device rotation".to_string()
        }
        CommitVerdict::WitnessQuorumNotMet {
            collected,
            required,
            ..
        } => format!("witness quorum not met: {collected} of {required}"),
    }
}

fn verdict_envelope(verdict: CommitVerdict) -> CommitBundleEnvelope {
    let (signer_did, root_did, as_of, freshness) = match &verdict {
        CommitVerdict::Valid {
            signer_did,
            root_did,
            as_of,
            freshness,
            ..
        } => (
            Some(signer_did.clone()),
            Some(root_did.clone()),
            Some(*as_of),
            Some(*freshness),
        ),
        _ => (None, None, None, None),
    };
    CommitBundleEnvelope::Verdict {
        // The relying party's policy caps trust, not the bundle's self-declared TTL: a bundle
        // older than the default window is not trusted even though it verified (ADR 009).
        valid: verdict.is_trusted(&FreshnessPolicy::default()),
        verdict: verdict_code(&verdict),
        detail: verdict_detail(&verdict),
        signer_did,
        root_did,
        freshness,
        as_of,
    }
}

/// Verify a raw git commit object against an identity bundle, fully stateless,
/// returning the tagged JSON envelope (`kind`: `"verdict"` | `"error"`).
///
/// The bundle is attacker-controlled input: it is parsed into a
/// [`BundleTrust`] (freshness + RT-005 self-certification + RT-002 KEL
/// authentication) and is **evidence only** — its root must already be in
/// `pinned_roots_json` or verification refuses before any signature check.
/// The commit's `Auths-Id`/`Auths-Device` trailers may only *select* the
/// bundle identity: a trailer naming any other DID cannot be resolved without
/// an identity store and fails closed.
///
/// Args:
/// * `commit_text`: The raw git commit object (headers + message + `gpgsig`),
///   exactly as produced by `git cat-file commit <sha>`.
/// * `bundle_json`: The identity bundle JSON (from `auths id export-bundle`).
/// * `pinned_roots_json`: JSON array of independently pinned `did:keri:` roots.
/// * `now`: Current time, injected at the boundary.
/// * `provider`: Crypto provider for in-process SSH-signature verification.
pub async fn verify_commit_with_bundle_json(
    commit_text: &str,
    bundle_json: &str,
    pinned_roots_json: &str,
    now: DateTime<Utc>,
    provider: &dyn CryptoProvider,
) -> String {
    match verify_commit_with_bundle_inner(
        commit_text,
        bundle_json,
        pinned_roots_json,
        now,
        provider,
    )
    .await
    {
        Ok(verdict) => envelope_to_string(&verdict_envelope(verdict)),
        Err(error) => envelope_to_string(&CommitBundleEnvelope::Error { error }),
    }
}

async fn verify_commit_with_bundle_inner(
    commit_text: &str,
    bundle_json: &str,
    pinned_roots_json: &str,
    now: DateTime<Utc>,
    provider: &dyn CryptoProvider,
) -> Result<CommitVerdict, String> {
    for (name, input) in [
        ("commit", commit_text),
        ("bundle", bundle_json),
        ("pinned roots", pinned_roots_json),
    ] {
        if input.len() > MAX_JSON_BATCH_SIZE {
            return Err(format!(
                "{name} input too large: {} bytes, max {MAX_JSON_BATCH_SIZE}",
                input.len()
            ));
        }
    }

    let bundle: IdentityBundle = serde_json::from_str(bundle_json)
        .map_err(|e| format!("identity bundle is not valid JSON: {e}"))?;
    let pinned_roots: Vec<String> = serde_json::from_str(pinned_roots_json)
        .map_err(|e| format!("pinned roots is not a JSON array of DIDs: {e}"))?;

    let trust = BundleTrust::parse(&bundle, now).map_err(|e| e.to_string())?;

    // Evidence-only (RT-005): the bundle never becomes its own trust anchor —
    // otherwise the anchor and the evidence both come from the same
    // attacker-supplied input.
    if !pinned_roots.iter().any(|r| r == trust.root_did()) {
        return Err(format!(
            "bundle root {} is not independently pinned: a bundle is evidence \
             for a pinned root, never the source of the pin",
            trust.root_did()
        ));
    }

    let (root_did, device_did) = commit_signer_trailers(commit_text).ok_or_else(|| {
        "commit carries no Auths-Id/Auths-Device trailer — it was not signed by auths".to_string()
    })?;

    // Stateless resolution: the bundle carries exactly one identity's KEL, so a
    // trailer may only select that identity. Anything else needs an identity
    // store and fails closed here.
    for (role, did) in [("root", &root_did), ("device", &device_did)] {
        if did != trust.root_did() {
            return Err(format!(
                "{role} KEL for {did} is not carried by the bundle (bundle \
                 identity is {}); stateless verification resolves only the \
                 bundle identity",
                trust.root_did()
            ));
        }
    }

    let verdict = verify_commit_against_kel(
        commit_text.as_bytes(),
        trust.kel(),
        trust.kel(),
        &pinned_roots,
        provider,
    )
    .await;

    // Grade the verdict from the bundle's age against the verifier's freshness policy: the
    // verifier caps trust, never the bundle's self-declared TTL (ADR 009). A bundle older
    // than the policy window is Stale and a strict/default relying party rejects it.
    let age = (now - bundle.bundle_timestamp).to_std().unwrap_or_default();
    Ok(verdict.with_freshness(
        &FreshnessPolicy::default(),
        FreshnessEvidence::SourceAge(age),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::PublicKeyHex;
    use crate::types::IdentityDID;

    const ROOT: &str = "did:keri:Eroot00000000000000000000000000000000000000";

    fn test_bundle(did: &str, ts: DateTime<Utc>, ttl: u64) -> IdentityBundle {
        IdentityBundle {
            identity_did: IdentityDID::new_unchecked(did.to_string()),
            public_key_hex: PublicKeyHex::new_unchecked("ab".repeat(32)),
            curve: auths_crypto::CurveType::P256,
            attestation_chain: Vec::new(),
            kel: Vec::new(),
            kel_attachments: Vec::new(),
            bundle_timestamp: ts,
            max_valid_for_secs: ttl,
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    #[test]
    fn fresh_bundle_parses_to_its_root_did() {
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let now = t + chrono::Duration::seconds(100);
        let trust = BundleTrust::parse(&bundle, now).expect("fresh");
        assert_eq!(trust.root_did(), ROOT);
        assert!(trust.kel().is_empty());
    }

    #[test]
    fn stale_bundle_fails_closed() {
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let now = t + chrono::Duration::seconds(7200);
        assert!(matches!(
            BundleTrust::parse(&bundle, now),
            Err(BundleTrustError::Stale(_))
        ));
    }

    #[test]
    fn bundle_rejects_did_not_matching_its_kel_inception() {
        // RT-005 self-certification: a bundle that pairs a DID with a KEL whose
        // inception names a DIFFERENT controller must fail closed, so a bundle
        // can never become the trust anchor for an attacker-authored KEL.
        use auths_keri::{
            CesrKey, Event, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold,
            VersionString, compute_next_commitment, finalize_icp_event,
        };
        let key = KeriPublicKey::ed25519(&[7u8; 32]).unwrap();
        let next = KeriPublicKey::ed25519(&[8u8; 32]).unwrap();
        let inception = finalize_icp_event(IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        })
        .unwrap();
        let t = fixed_time();
        // Pair that inception with an unrelated `D…` DID it does not certify.
        let mut bundle = test_bundle("did:keri:DAttackerKey", t, 3600);
        bundle.kel = vec![Event::Icp(inception)];
        let now = t + chrono::Duration::seconds(100);
        assert!(matches!(
            BundleTrust::parse(&bundle, now),
            Err(BundleTrustError::NotSelfCertifying(_))
        ));
    }

    #[test]
    fn bundle_with_stripped_attachments_fails_rt002() {
        // RT-002: a KEL without its signature attachments is unauthenticated —
        // refused outright, never degraded to a structural-only replay.
        use auths_keri::{
            CesrKey, Event, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold,
            VersionString, compute_next_commitment, finalize_icp_event,
        };
        let key = KeriPublicKey::ed25519(&[7u8; 32]).unwrap();
        let next = KeriPublicKey::ed25519(&[8u8; 32]).unwrap();
        let inception = finalize_icp_event(IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        })
        .unwrap();
        let did = format!("did:keri:{}", inception.d.as_str());
        let t = fixed_time();
        let mut bundle = test_bundle(&did, t, 3600);
        bundle.kel = vec![Event::Icp(inception)];
        // kel_attachments stays empty: self-certifies (RT-005 passes) but
        // cannot be authenticated (RT-002 fails).
        let now = t + chrono::Duration::seconds(100);
        assert!(matches!(
            BundleTrust::parse(&bundle, now),
            Err(BundleTrustError::KelUnauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn unpinned_bundle_root_is_an_error_envelope() {
        // Evidence-only: a coherent bundle whose root is not pinned must refuse
        // before any signature work.
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let bundle_json = serde_json::to_string(&bundle).unwrap();
        let out = verify_commit_with_bundle_json(
            "tree abc\n\nsubject\n",
            &bundle_json,
            "[]",
            t + chrono::Duration::seconds(10),
            &auths_crypto::RingCryptoProvider,
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["kind"], "error");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("not independently pinned"),
            "unexpected error: {out}"
        );
    }

    #[tokio::test]
    async fn trailerless_commit_is_an_error_envelope() {
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let bundle_json = serde_json::to_string(&bundle).unwrap();
        let pinned = format!("[\"{ROOT}\"]");
        let out = verify_commit_with_bundle_json(
            "tree abc\n\nsubject, no trailers\n",
            &bundle_json,
            &pinned,
            t + chrono::Duration::seconds(10),
            &auths_crypto::RingCryptoProvider,
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["kind"], "error");
        assert!(
            v["error"].as_str().unwrap().contains("Auths-Id"),
            "unexpected error: {out}"
        );
    }

    #[tokio::test]
    async fn foreign_trailer_did_fails_closed() {
        // A commit claiming a signer the bundle does not carry cannot be
        // resolved statelessly — refused, never silently verified against the
        // bundle's unrelated KEL.
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let bundle_json = serde_json::to_string(&bundle).unwrap();
        let pinned = format!("[\"{ROOT}\"]");
        let commit =
            "tree abc\n\nsubject\n\nAuths-Id: did:keri:Eother\nAuths-Device: did:keri:Eother\n";
        let out = verify_commit_with_bundle_json(
            commit,
            &bundle_json,
            &pinned,
            t + chrono::Duration::seconds(10),
            &auths_crypto::RingCryptoProvider,
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["kind"], "error");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("not carried by the bundle"),
            "unexpected error: {out}"
        );
    }

    fn valid_verdict() -> CommitVerdict {
        CommitVerdict::Valid {
            signer_did: "did:keri:Edev".to_string(),
            root_did: ROOT.to_string(),
            duplicitous_root: false,
            as_of: 7,
            freshness: Freshness::Unknown,
        }
    }

    #[test]
    fn bundle_age_grades_the_commit_verdict_against_the_verifier_policy() {
        let policy = FreshnessPolicy::default(); // 24h
        // A bundle older than the policy window grades Stale and is trusted by no policy —
        // the verifier caps trust regardless of the bundle's self-declared TTL.
        let stale = valid_verdict().with_freshness(
            &policy,
            FreshnessEvidence::SourceAge(std::time::Duration::from_secs(25 * 3600)),
        );
        assert_eq!(stale.freshness(), Freshness::Stale);
        assert!(!stale.is_trusted(&policy));
        // A bundle within the window grades Fresh and is trusted.
        let fresh = valid_verdict().with_freshness(
            &policy,
            FreshnessEvidence::SourceAge(std::time::Duration::from_secs(3600)),
        );
        assert_eq!(fresh.freshness(), Freshness::Fresh);
        assert!(fresh.is_trusted(&policy));
        // No oracle (a direct verify) → Unknown: the default tolerates it, strict denies it.
        let unknown = valid_verdict().with_freshness(&policy, FreshnessEvidence::Offline);
        assert_eq!(unknown.freshness(), Freshness::Unknown);
        assert!(unknown.is_trusted(&policy));
        assert!(
            !unknown.is_trusted(&FreshnessPolicy::strict(std::time::Duration::from_secs(
                3600
            )))
        );
    }

    #[test]
    fn verdict_envelope_caps_trust_at_the_policy_and_surfaces_freshness() {
        // A stale-graded verdict: the envelope reports it not-valid (the verifier policy caps
        // trust) and surfaces the freshness grade and as-of for the consumer.
        let stale = valid_verdict().with_freshness(
            &FreshnessPolicy::default(),
            FreshnessEvidence::SourceAge(std::time::Duration::from_secs(25 * 3600)),
        );
        let json = envelope_to_string(&verdict_envelope(stale));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["valid"], false,
            "a stale bundle is not trusted under the default policy"
        );
        assert_eq!(v["freshness"], "stale");
        assert_eq!(v["as_of"], 7);

        // A fresh-graded verdict: trusted and surfaced.
        let fresh = valid_verdict().with_freshness(
            &FreshnessPolicy::default(),
            FreshnessEvidence::SourceAge(std::time::Duration::from_secs(3600)),
        );
        let v: serde_json::Value =
            serde_json::from_str(&envelope_to_string(&verdict_envelope(fresh))).unwrap();
        assert_eq!(v["valid"], true);
        assert_eq!(v["freshness"], "fresh");
    }
}
