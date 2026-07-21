//! Resolving a declared witness set from a replayed KEL (I-TRUST-3).
//!
//! A [`crate::types::WitnessSet`] carried inside a finalized anchor proves
//! itself *self-addressing*, but only a seal in the party's own KEL proves the
//! party *declared* it — without that seal, a party can present different sets
//! to different verifiers. The declaration is one `ixn` anchoring the set's
//! content SAID as a digest seal. These helpers are the single place the
//! resolution rule lives: extract every `ixn`-anchored digest-seal SAID from a
//! replayed KEL, then look the committed set SAID up in that list and feed the
//! match to [`crate::finalize::verify_finalized`] as `declared_said`.
//!
//! Pure and I/O-free: callers replay the KEL themselves (registry backend,
//! embedded bundle evidence, fetched registry copy) and pass the events in.

use auths_keri::{Event, Seal};

/// Every digest-seal SAID anchored by an `ixn` in a replayed KEL, in event
/// order. Establishment-event seals are excluded: a witness-set declaration is
/// authored as an interaction event, and scanning only `ixn`s keeps the
/// resolved surface exactly the one the declare flow writes.
///
/// Args:
/// * `events`: the replayed KEL, oldest first.
///
/// Usage:
/// ```ignore
/// let seals = ixn_digest_seals(&kel_events);
/// let declared = find_witness_set_seal(&seals, &committed_said);
/// ```
pub fn ixn_digest_seals<'a>(events: impl IntoIterator<Item = &'a Event>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::Ixn(ixn) => Some(&ixn.a),
            _ => None,
        })
        .flatten()
        .filter_map(|seal| match seal {
            Seal::Digest { d } => Some(d.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// Find the witness-set SAID a party declared on its KEL: the entry in the
/// KEL's `ixn`-anchored digest seals equal to `expected_said`. `None` means
/// the party never anchored this set — a verifier must refuse the anchor
/// rather than trust a set only the anchor itself asserts.
///
/// Args:
/// * `kel_digest_seals`: the `ixn`-anchored digest-seal SAIDs
///   ([`ixn_digest_seals`]) from the party's replayed KEL.
/// * `expected_said`: the set SAID the anchor commits to
///   ([`crate::types::WitnessSet::computed_said`]).
///
/// Usage:
/// ```ignore
/// let declared = find_witness_set_seal(&seals, &finalized.anchor.witness_set.said)
///     .ok_or(NotDeclared)?;
/// verify_finalized(&finalized, Some(declared))?;
/// ```
pub fn find_witness_set_seal<'a>(
    kel_digest_seals: &'a [String],
    expected_said: &str,
) -> Option<&'a str> {
    kel_digest_seals
        .iter()
        .map(String::as_str)
        .find(|seal| *seal == expected_said)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_keri::{IxnEvent, KeriSequence, Prefix, Said, VersionString};

    fn ixn_with_seals(seals: Vec<Seal>) -> Event {
        Event::Ixn(IxnEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked("EIxnSaid".to_string()),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EPrior".to_string()),
            a: seals,
        })
    }

    #[test]
    fn digest_seal_in_an_ixn_is_found() {
        let kel = vec![ixn_with_seals(vec![Seal::Digest {
            d: Said::new_unchecked("ESetSaid".to_string()),
        }])];
        let seals = ixn_digest_seals(&kel);
        assert_eq!(find_witness_set_seal(&seals, "ESetSaid"), Some("ESetSaid"));
    }

    #[test]
    fn a_different_said_is_not_found() {
        let kel = vec![ixn_with_seals(vec![Seal::Digest {
            d: Said::new_unchecked("ESetSaid".to_string()),
        }])];
        let seals = ixn_digest_seals(&kel);
        assert_eq!(find_witness_set_seal(&seals, "EOtherSaid"), None);
    }

    #[test]
    fn non_digest_seals_are_ignored() {
        let kel = vec![ixn_with_seals(vec![
            Seal::KeyEvent {
                i: Prefix::new_unchecked("EDevice".to_string()),
                s: KeriSequence::new(0),
                d: Said::new_unchecked("EDipSaid".to_string()),
            },
            Seal::SourceEvent {
                s: KeriSequence::new(2),
                d: Said::new_unchecked("ESourceSaid".to_string()),
            },
        ])];
        assert!(ixn_digest_seals(&kel).is_empty());
    }

    #[test]
    fn empty_kel_resolves_nothing() {
        let seals = ixn_digest_seals(&[]);
        assert_eq!(find_witness_set_seal(&seals, "EAnything"), None);
    }
}
