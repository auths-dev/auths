//! The §9.2 acceptance rule — pure, clock-injected (CLAUDE.md), storage behind
//! the port.
//!
//! A witness decides one anchor request against its prior co-signed state for
//! the seed. The rule is total and side-effect-free: current keys, prior
//! anchor, and `now` are inputs; the caller does the I/O (sign, CAS-store, log,
//! gossip) after a `CoSign`, or refuses and publishes after a `Duplicity`
//! (I-DUP-2). The KEL→[`ControllerKeys`] resolution is the caller's job (see
//! [`crate::keystate`]).

use chrono::{DateTime, Utc};

use crate::duplicity::DuplicityProof;
use crate::error::AnchorError;
use crate::types::{Anchor, AnchorReq, ControllerKeys};
use crate::verify::verify_signature;

/// The decision the pure rule reaches for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// The request is well-ordered and authorized — the caller should sign,
    /// CAS-store, log, and gossip it.
    CoSign(Box<Anchor>),
    /// The request equivocates against the prior anchor at the same index — the
    /// caller must refuse and publish the proof.
    Duplicity(Box<DuplicityProof>),
}

/// Decide one [`AnchorReq`] against this witness's prior state for the seed.
///
/// Args:
/// * `req`: the incoming anchor request.
/// * `keys`: the party's KEL-derived current keys at `req.timestamp`.
/// * `prior`: this witness's last co-signed anchor for the seed, if any.
/// * `now`: injected clock (reserved for skew policy; phase-0 ordering derives
///   from the anchors themselves, never wall-clock).
///
/// Usage:
/// ```ignore
/// match accept_anchor(&req, &keys, prior.as_ref(), clock.now())? {
///     Acceptance::CoSign(anchor) => { /* sign, CAS-store, log, gossip */ }
///     Acceptance::Duplicity(proof) => { /* refuse + publish (I-DUP-2) */ }
/// }
/// ```
pub fn accept_anchor(
    req: &AnchorReq,
    keys: &ControllerKeys,
    prior: Option<&Anchor>,
    now: DateTime<Utc>,
) -> Result<Acceptance, AnchorError> {
    let _ = now;
    verify_party_signature(req, keys)?;
    if let Some(last) = prior {
        if req.index == last.index && req.head != last.head {
            return Ok(Acceptance::Duplicity(Box::new(DuplicityProof::new(
                last, req,
            )?)));
        }
        if req.index <= last.index {
            return Err(AnchorError::NonMonotoneIndex {
                got: req.index,
                prior: last.index,
            });
        }
        if req.cumulative < last.cumulative {
            return Err(AnchorError::CumulativeRegression {
                got: req.cumulative,
                prior: last.cumulative,
            });
        }
        if req.timestamp < last.timestamp {
            return Err(AnchorError::TimestampRegression);
        }
    }
    Ok(Acceptance::CoSign(Box::new(req.clone())))
}

/// Verify the party signature binds to a *current* key of the controller.
///
/// The key must appear in `keys` (matched by curve and full bytes — never
/// length) and the signature must verify over the anchor's party message. This
/// is the I-DUP-3 authorization gate.
fn verify_party_signature(req: &Anchor, keys: &ControllerKeys) -> Result<(), AnchorError> {
    let curve = req.sig_party.curve;
    let public_key = req.sig_party.public_key.as_slice();
    if !keys.contains(curve, public_key) {
        return Err(AnchorError::PartyKeyNotCurrent);
    }
    let message = req.party_signing_bytes()?;
    if verify_signature(curve, public_key, &message, &req.sig_party.signature)? {
        Ok(())
    } else {
        Err(AnchorError::PartySignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{controller_keys_for, sample_anchor, sample_anchor_with_head};

    fn now() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_800_000_000, 0).unwrap()
    }

    #[test]
    fn first_anchor_cosigns() {
        let req = sample_anchor(1);
        let keys = controller_keys_for(&req);
        assert!(matches!(
            accept_anchor(&req, &keys, None, now()).unwrap(),
            Acceptance::CoSign(_)
        ));
    }

    #[test]
    fn monotone_growth_cosigns() {
        let prior = sample_anchor(1);
        let keys = controller_keys_for(&prior);
        let next = sample_anchor(2);
        assert!(matches!(
            accept_anchor(&next, &keys, Some(&prior), now()).unwrap(),
            Acceptance::CoSign(_)
        ));
    }

    #[test]
    fn same_index_different_head_is_duplicity() {
        let prior = sample_anchor_with_head(5, [1u8; 32]);
        let keys = controller_keys_for(&prior);
        let fork = sample_anchor_with_head(5, [2u8; 32]);
        match accept_anchor(&fork, &keys, Some(&prior), now()).unwrap() {
            Acceptance::Duplicity(proof) => proof.verify().unwrap(),
            Acceptance::CoSign(_) => panic!("expected duplicity"),
        }
    }

    #[test]
    fn index_regression_is_rejected() {
        let prior = sample_anchor(5);
        let keys = controller_keys_for(&prior);
        let stale = sample_anchor(3);
        assert!(matches!(
            accept_anchor(&stale, &keys, Some(&prior), now()),
            Err(AnchorError::NonMonotoneIndex { got: 3, prior: 5 })
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut req = sample_anchor(1);
        let keys = controller_keys_for(&req);
        req.sig_party.signature[0] ^= 0xff;
        assert!(matches!(
            accept_anchor(&req, &keys, None, now()),
            Err(AnchorError::PartySignatureInvalid)
        ));
    }

    #[test]
    fn unknown_key_is_rejected() {
        let req = sample_anchor(1);
        let keys = ControllerKeys::default(); // controller has no keys
        assert!(matches!(
            accept_anchor(&req, &keys, None, now()),
            Err(AnchorError::PartyKeyNotCurrent)
        ));
    }
}
