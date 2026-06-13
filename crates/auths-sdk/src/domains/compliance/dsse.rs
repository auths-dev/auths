//! DSSE (Dead Simple Signing Envelope) wrapper for compliance evidence packs.
//!
//! Wraps the in-toto Statement form of an [`EvidencePack`] in a DSSE envelope,
//! org-signed over the DSSE **PAE** (pre-authentication encoding) so the signature
//! commits to both the payload type and the exact payload bytes — not the bare
//! JSON, which would be malleable. The signature's curve travels in-band
//! ([`DsseSignature::curve`]) per the wire-format rule; it is never inferred from
//! byte length.
//!
//! This mirrors the org-signing pattern of
//! [`crate::domains::org::offboarding::sign_offboarding_record`]: a `StorageSigner`
//! over the org's keychain alias, the curve carried alongside the signature.

use std::sync::Arc;

use auths_core::signing::{SecureSigner, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;
use auths_keri::KeriPublicKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::compliance::frameworks::{FrameworkReport, INTOTO_STATEMENT_TYPE};
use crate::domains::compliance::query::{
    ComplianceQueryError, EvidencePack, RowVerdict, verify_evidence_pack_offline,
};
use auths_verifier::{Ed25519PublicKey, IdentityDID};

/// The in-toto Statement payload type carried in the DSSE envelope.
pub const DSSE_INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// DSSE pre-authentication encoding (PAE) per the DSSE spec:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`, where `SP` is a
/// single space and `LEN` is the ASCII-decimal byte length.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// The in-band curve tag for a signature (never infer curve from byte length).
fn curve_tag(curve: CurveType) -> &'static str {
    match curve {
        CurveType::Ed25519 => "ed25519",
        CurveType::P256 => "p256",
    }
}

/// Parse a curve tag back to a [`CurveType`]; unknown/missing defaults to P-256.
fn curve_from_tag(tag: &str) -> CurveType {
    match tag {
        "ed25519" => CurveType::Ed25519,
        _ => CurveType::P256,
    }
}

/// A single DSSE signature with an in-band curve tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Key identifier — the signer's `did:keri:` (the org DID).
    pub keyid: String,
    /// In-band curve tag (`"ed25519"` / `"p256"`) — never inferred from length.
    pub curve: String,
    /// Base64-encoded signature over the DSSE PAE.
    pub sig: String,
}

/// A DSSE envelope wrapping an org-signed in-toto compliance statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// Payload type URI (`application/vnd.in-toto+json`).
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded in-toto Statement payload.
    pub payload: String,
    /// Signatures over the PAE of (`payload_type`, decoded `payload`).
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Decode the base64 payload to the raw in-toto Statement bytes.
    pub fn decoded_payload(&self) -> Result<Vec<u8>, ComplianceQueryError> {
        BASE64
            .decode(self.payload.as_bytes())
            .map_err(|e| ComplianceQueryError::Decode(format!("dsse payload base64: {e}")))
    }

    /// Serialize the envelope to canonical JSON (`json-canon`).
    pub fn to_canonical_json(&self) -> Result<String, ComplianceQueryError> {
        json_canon::to_string(self).map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))
    }

    /// Parse an envelope from its JSON form.
    pub fn from_json(json: &str) -> Result<Self, ComplianceQueryError> {
        serde_json::from_str(json).map_err(|e| ComplianceQueryError::Decode(e.to_string()))
    }

    /// Verify a signature in this envelope against the org's verkey.
    ///
    /// Recomputes the PAE over the decoded payload and checks that `org_public_key`
    /// signed it. The curve travels in-band on each signature and must match
    /// `org_curve` for that signature to be considered.
    ///
    /// Args:
    /// * `org_public_key`: The org's current verkey bytes (resolved from its KEL).
    /// * `org_curve`: The org key's curve.
    ///
    /// Usage:
    /// ```ignore
    /// envelope.verify(&org_pk, org_curve)?;
    /// ```
    pub fn verify(
        &self,
        org_public_key: &[u8],
        org_curve: CurveType,
    ) -> Result<(), ComplianceQueryError> {
        let payload = self.decoded_payload()?;
        let to_verify = pae(&self.payload_type, &payload);
        let key = KeriPublicKey::from_verkey_bytes(org_public_key, org_curve)
            .map_err(|e| ComplianceQueryError::Verification(e.to_string()))?;
        for s in &self.signatures {
            if curve_from_tag(&s.curve) != org_curve {
                continue;
            }
            let sig = BASE64
                .decode(s.sig.as_bytes())
                .map_err(|e| ComplianceQueryError::Decode(format!("dsse sig base64: {e}")))?;
            if key.verify_signature(&to_verify, &sig).is_ok() {
                return Ok(());
            }
        }
        Err(ComplianceQueryError::Verification(
            "no DSSE signature verified against the org key".into(),
        ))
    }
}

/// A DSSE-signed evidence pack that has passed full offline verification —
/// this value cannot exist unless the embedded org KEL authenticated (RT-002),
/// the envelope signature verified over its PAE bytes against the KEL-resolved
/// org verkey, the org was pinned, and no duplicity was detected.
///
/// Per-row tamper/transparency findings are verdicts, not errors: a pack that
/// honestly reports a rejected-after-revocation release is still *verified* —
/// the log telling the truth about a damned signature is the system working.
/// [`Self::authentic`] folds the rows into the auditor's single verdict.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedEvidencePack {
    /// The verified pack (safe to render — its bytes are what the org signed).
    pub pack: EvidencePack,
    /// The authenticated org KEL position the verdict is derived as-of.
    pub org_kel_seq: u128,
    /// One verdict per evidence row, re-derived from the embedded KEL.
    pub verdicts: Vec<RowVerdict>,
}

impl VerifiedEvidencePack {
    /// The auditor's single verdict: every row's authority re-derivation matched
    /// the recorded row, every transparency proof present verified, and — when a
    /// log key was pinned — every row's checkpoint signature attested.
    pub fn authentic(&self) -> bool {
        self.verdicts.iter().all(|v| {
            v.authority_consistent
                && v.transparency_verified.unwrap_or(true)
                && v.checkpoint_attested.unwrap_or(true)
        })
    }
}

/// Verify a DSSE-signed offline evidence pack with **zero network**, trusting
/// nothing but `pinned_roots` and mathematics.
///
/// The auditor-side chain, in trust order:
/// 1. Parse the envelope and locate the embedded org KEL — the one
///    self-certifying structure in the payload (its prefix commits to its
///    inception keys; every later event is signature-chained). No other pack
///    claim is trusted yet.
/// 2. Authenticate that KEL (RT-002) and resolve the org's **current** verkey
///    from it — never from a keychain, a server, or a config file.
/// 3. Verify the DSSE signature over the PAE bytes against that verkey.
/// 4. Run [`verify_evidence_pack_offline`]: org root pinned, KEL duplicity,
///    per-row authority re-derivation, transparency proofs where present —
///    and, with a pinned log key, each row's checkpoint signature against the
///    pinned log operator.
///
/// Fail-closed: a missing bundle, an unauthenticated KEL, a signature that does
/// not verify, an unpinned org, or duplicity is an `Err` — never a verdict.
///
/// Args:
/// * `envelope_json`: The DSSE envelope as produced by [`sign_evidence_pack`].
/// * `pinned_roots`: The verifier's pinned trust roots (its only trust input).
/// * `pinned_log_key`: The log operator's Ed25519 key, pinned out of band;
///   `None` keeps the transparency verdict membership-only (and it says so).
///
/// Usage:
/// ```ignore
/// let verified = verify_signed_evidence_pack_offline(&raw, &roots, Some(&log_key))?;
/// assert!(verified.authentic());
/// ```
pub fn verify_signed_evidence_pack_offline(
    envelope_json: &str,
    pinned_roots: &[IdentityDID],
    pinned_log_key: Option<&Ed25519PublicKey>,
) -> Result<VerifiedEvidencePack, ComplianceQueryError> {
    let envelope = DsseEnvelope::from_json(envelope_json)?;
    let payload = envelope.decoded_payload()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| ComplianceQueryError::Decode(format!("dsse payload is not JSON: {e}")))?;
    if statement["_type"] != INTOTO_STATEMENT_TYPE {
        return Err(ComplianceQueryError::Decode(format!(
            "dsse payload is not an in-toto Statement ({INTOTO_STATEMENT_TYPE})"
        )));
    }
    let pack: EvidencePack =
        serde_json::from_value(statement["predicate"].clone()).map_err(|e| {
            ComplianceQueryError::Decode(format!(
                "statement predicate is not an evidence pack: {e}"
            ))
        })?;
    let bundle = pack.org_bundle.as_ref().ok_or_else(|| {
        ComplianceQueryError::OfflineVerification(
            "pack carries no embedded org bundle — not an offline-verifiable pack".into(),
        )
    })?;

    // The org verkey, from the authenticated embedded KEL alone.
    let state = bundle
        .authenticated_org_state()
        .map_err(|e| ComplianceQueryError::OfflineVerification(e.to_string()))?;
    let cesr = state.current_key().ok_or_else(|| {
        ComplianceQueryError::Verification("org KEL resolves to no current key".into())
    })?;
    let org_key = KeriPublicKey::parse(cesr.as_str())
        .map_err(|e| ComplianceQueryError::Decode(format!("org verkey decode: {e}")))?;
    let org_curve = match org_key {
        KeriPublicKey::Ed25519 { .. } => CurveType::Ed25519,
        KeriPublicKey::P256 { .. } => CurveType::P256,
    };
    envelope.verify(org_key.as_bytes(), org_curve)?;

    // Only now is the payload trusted enough to re-derive every row from it.
    let verdicts = verify_evidence_pack_offline(&pack, pinned_roots, pinned_log_key)?;
    Ok(VerifiedEvidencePack {
        org_kel_seq: state.sequence,
        pack,
        verdicts,
    })
}

/// Sign a compliance evidence pack as a DSSE-wrapped in-toto Statement, org-signed.
///
/// The payload is the canonical in-toto Statement ([`EvidencePack::to_intoto_statement`]);
/// the org signs its DSSE PAE. The signature's curve travels in-band.
///
/// Args:
/// * `ctx`: Auths context (key storage, passphrase provider).
/// * `org_did`: The org's `did:keri:` — recorded as the signature `keyid`.
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `org_curve`: The org key's curve (carried in-band).
/// * `pack`: The evidence pack to wrap and sign.
///
/// Usage:
/// ```ignore
/// let env = sign_evidence_pack(&ctx, "did:keri:EOrg", &org_alias, org_curve, &pack)?;
/// std::fs::write("pack.dsse.json", env.to_canonical_json()?)?;
/// ```
pub fn sign_evidence_pack(
    ctx: &AuthsContext,
    org_did: &str,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    pack: &EvidencePack,
) -> Result<DsseEnvelope, ComplianceQueryError> {
    sign_intoto_statement(
        ctx,
        org_did,
        org_alias,
        org_curve,
        &pack.to_intoto_statement()?,
    )
}

/// Org-sign a rendered framework report (SLSA / SPDX / CRA) as a DSSE-wrapped
/// in-toto Statement.
///
/// The framework predicate rides the **same** DSSE envelope and PAE as a raw
/// evidence pack, so one [`DsseEnvelope::verify`] path validates any of them.
///
/// Args:
/// * `ctx`: Auths context (key storage, passphrase provider).
/// * `org_did`: The org's `did:keri:` — recorded as the signature `keyid`.
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `org_curve`: The org key's curve (carried in-band).
/// * `report`: The rendered framework report.
///
/// Usage:
/// ```ignore
/// let env = sign_framework_report(&ctx, "did:keri:EOrg", &org_alias, org_curve, &report)?;
/// ```
pub fn sign_framework_report(
    ctx: &AuthsContext,
    org_did: &str,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    report: &FrameworkReport,
) -> Result<DsseEnvelope, ComplianceQueryError> {
    sign_intoto_statement(
        ctx,
        org_did,
        org_alias,
        org_curve,
        &report.to_intoto_statement()?,
    )
}

/// Sign a canonical in-toto Statement string as a DSSE envelope (the shared path).
fn sign_intoto_statement(
    ctx: &AuthsContext,
    org_did: &str,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    statement: &str,
) -> Result<DsseEnvelope, ComplianceQueryError> {
    let payload = statement.as_bytes();
    let to_sign = pae(DSSE_INTOTO_PAYLOAD_TYPE, payload);
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let sig = signer
        .sign_with_alias(org_alias, ctx.passphrase_provider.as_ref(), &to_sign)
        .map_err(|e| ComplianceQueryError::Signing(e.to_string()))?;
    Ok(DsseEnvelope {
        payload_type: DSSE_INTOTO_PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid: org_did.to_string(),
            curve: curve_tag(org_curve).to_string(),
            sig: BASE64.encode(&sig),
        }],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_spec_layout() {
        // DSSEv1 SP 4 SP TYPE SP 5 SP hello  (type len 4 = "demo")
        let got = pae("demo", b"hello");
        assert_eq!(got, b"DSSEv1 4 demo 5 hello");
    }

    #[test]
    fn pae_is_length_prefixed_not_delimiter_ambiguous() {
        // A payload containing spaces must not be confusable with the framing.
        let a = pae("t", b"a b");
        let b = pae("t", b"a  b");
        assert_ne!(
            a, b,
            "PAE length-prefix must distinguish differing payloads"
        );
    }

    #[test]
    fn curve_tag_round_trips() {
        assert_eq!(
            curve_from_tag(curve_tag(CurveType::Ed25519)),
            CurveType::Ed25519
        );
        assert_eq!(curve_from_tag(curve_tag(CurveType::P256)), CurveType::P256);
        // Unknown/missing tag defaults to P-256 (workspace default).
        assert_eq!(curve_from_tag("unknown"), CurveType::P256);
    }
}
