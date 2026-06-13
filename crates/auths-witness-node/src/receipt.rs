//! The self-contained receipt artifact a node hands a third party.
//!
//! A witness receipt is only *corroboration* if someone who does not trust the
//! node can check it alone — on a clean machine, with no network and no
//! registry. This module owns the operator-facing *bundle* that makes that
//! possible: the witness's signed receipt paired with the witness's own
//! published identity. Everything a stranger needs to decide is in one file.
//!
//! It owns no protocol. The decision — does this signature verify against the
//! key the published identity embeds? — is made by the platform verifier
//! ([`auths_verifier::verify_receipt_offline`]), composed here. The node crate
//! only frames the artifact and renders the verdict.

use auths_verifier::{OfflineReceiptVerdict, SignedReceipt, verify_receipt_offline};
use serde::{Deserialize, Serialize};

/// A witness receipt paired with the witness's published identity — the
/// complete, self-contained artifact a third party verifies offline.
///
/// The two fields together are sufficient and self-describing: the published
/// `identity` is a `did:key` that *embeds* the witness's verification key, so a
/// holder needs no directory lookup and no network call to recover the key the
/// `receipt` was signed with. The receipt body itself names only the
/// *controller* it attests (`receipt.receipt.i`), never the witness — so the
/// bundle cannot self-attest, and the identity is the single trust input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBundle {
    /// The witness's signed receipt (spec `rct` body + detached signature).
    pub receipt: SignedReceipt,
    /// The witness's published `did:key:z…` identity (as advertised at its
    /// health endpoint), embedding the key the receipt was signed with. Named
    /// `witness` to match the platform's stored-receipt vocabulary — one word
    /// for "who attested this".
    pub witness: String,
}

impl ReceiptBundle {
    /// Parse a bundle from its JSON wire form, failing loudly on malformed input.
    ///
    /// Parse-don't-validate: a returned `ReceiptBundle` is fully formed; nothing
    /// downstream re-checks its shape.
    ///
    /// Args:
    /// * `json`: the bundle JSON bytes.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }

    /// Verify this receipt offline against the published identity it carries.
    ///
    /// No network, no registry: the verdict is computed by the platform verifier
    /// from the bundle's own bytes alone. The result is a parsed sum type, so a
    /// caller renders exactly why a receipt failed without re-inspecting it.
    pub fn verify_offline(&self) -> OfflineReceiptVerdict {
        verify_receipt_offline(&self.receipt, &self.witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A genuine bundle captured from a real witness node: a signed receipt and
    // the node's published did:key identity, which embeds the signing key. This
    // is data (a real artifact), not a re-implementation of any protocol.
    const GENUINE_BUNDLE: &str = r#"{
        "receipt": {
            "receipt": {
                "v": "KERI10JSON000000_",
                "t": "rct",
                "d": "EPVOwKzgOeQ2rD5nv_fXzD036LBYcIgyaD3AgD0ghToU",
                "i": "EProbeControllerWITN2000000000000000000000000",
                "s": "0"
            },
            "signature": "3828f4b8c9156f3603060e3c71f38324bc968ea6547fe3144ee059f3219879e9dd824d49db705478d71c0b597d5bc30ff53f79841266ded9275782259f5b270c"
        },
        "witness": "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S"
    }"#;

    #[test]
    fn a_genuine_bundle_verifies_offline() {
        let bundle = ReceiptBundle::from_json(GENUINE_BUNDLE.as_bytes()).unwrap();
        let verdict = bundle.verify_offline();
        assert!(
            verdict.is_verified(),
            "a genuine receipt + published identity must verify alone: {verdict:?}"
        );
    }

    #[test]
    fn a_bit_flipped_signature_is_rejected() {
        let mut bundle = ReceiptBundle::from_json(GENUINE_BUNDLE.as_bytes()).unwrap();
        bundle.receipt.signature[0] ^= 0x01;
        assert!(
            !bundle.verify_offline().is_verified(),
            "a tampered signature must not verify"
        );
    }

    #[test]
    fn a_foreign_identity_is_rejected() {
        // The genuine receipt, but carried with a different witness's identity
        // (one of the fixture's other nodes) — must not verify.
        let mut bundle = ReceiptBundle::from_json(GENUINE_BUNDLE.as_bytes()).unwrap();
        bundle.witness = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK".to_string();
        assert!(
            !bundle.verify_offline().is_verified(),
            "a receipt carried with the wrong witness identity must not verify"
        );
    }
}
