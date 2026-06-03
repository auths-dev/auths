//! Pluggable witness-receipt lookup for receipt-gated KEL replay.
//!
//! Receipt-gated validation (D.6) must ask "which witnesses have receipted this
//! establishment event?" from inside `validate_kel` — but `auths-keri` is
//! Layer-0.5 and stays dependency-light and WASM-safe (no `tokio`, no storage).
//! So, exactly like [`crate::DelegatorKelLookup`], we inject the receipt source
//! through a **sync** trait: data in, data out, no I/O. The storage-backed
//! implementation (reading the receipt store / SQLite) lives in higher layers.

use crate::{KeriSequence, Prefix, Said};

/// A witness receipt as the replay gate sees it: who attested, and the raw
/// signature they produced over the receipted event.
///
/// This is the witness-attributed view (the wire `rct` body carries the
/// *controller* AID, not the witness — see [`crate::witness::SignedReceipt`]);
/// the storage layer pairs each stored receipt with its verifying witness AID
/// and hands those pairs here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReceipt {
    /// The witness's AID (curve-tagged CESR verkey prefix). The KAWA quorum
    /// dedupe key.
    pub witness: Prefix,
    /// The witness's detached signature over the receipted event.
    pub signature: Vec<u8>,
}

/// Pluggable receipt source for witness-gated replay.
///
/// Mirrors [`crate::DelegatorKelLookup`]: a sync, storage-agnostic seam the
/// validator calls to find an event's witness receipts. Returning an empty
/// vector means "no receipts known" — the caller (KAWA) decides whether that
/// meets the in-force `bt`-of-`b` threshold.
pub trait WitnessReceiptLookup {
    /// The witness receipts known for the event identified by
    /// `(controller, sn, event_said)`.
    ///
    /// Args:
    /// * `controller`: The AID whose KEL is being replayed.
    /// * `sn`: The sequence number of the receipted event.
    /// * `event_said`: The SAID of the receipted event.
    fn receipts_for(
        &self,
        controller: &Prefix,
        sn: KeriSequence,
        event_said: &Said,
    ) -> Vec<WitnessReceipt>;
}

/// A [`WitnessReceiptLookup`] that knows no receipts.
///
/// Used by the non-witness verify path and by existing `validate_kel` callers,
/// so the zero-witness (`bt=0`) path and back-compat behavior are unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoWitnessReceipts;

impl WitnessReceiptLookup for NoWitnessReceipts {
    fn receipts_for(&self, _: &Prefix, _: KeriSequence, _: &Said) -> Vec<WitnessReceipt> {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_impl_returns_no_receipts() {
        let lookup = NoWitnessReceipts;
        let got = lookup.receipts_for(
            &Prefix::new_unchecked("EController0000000000000000000000000000000000".to_string()),
            KeriSequence::new(0),
            &Said::new_unchecked("EEvent00000000000000000000000000000000000000".to_string()),
        );
        assert!(got.is_empty());
    }

    /// A trivial keyed impl to prove the trait carries `(witness, signature)`
    /// pairs through to a caller.
    struct MapLookup {
        by_said: HashMap<String, Vec<WitnessReceipt>>,
    }

    impl WitnessReceiptLookup for MapLookup {
        fn receipts_for(
            &self,
            _controller: &Prefix,
            _sn: KeriSequence,
            event_said: &Said,
        ) -> Vec<WitnessReceipt> {
            self.by_said
                .get(event_said.as_str())
                .cloned()
                .unwrap_or_default()
        }
    }

    #[test]
    fn returns_pairs_for_event() {
        let said = "EEvent00000000000000000000000000000000000000";
        let mut by_said = HashMap::new();
        by_said.insert(
            said.to_string(),
            vec![WitnessReceipt {
                witness: Prefix::new_unchecked("BWit000000000000000000000000000000000000000".to_string()),
                signature: vec![1u8; 64],
            }],
        );
        let lookup = MapLookup { by_said };
        let got = lookup.receipts_for(
            &Prefix::new_unchecked("EController0000000000000000000000000000000000".to_string()),
            KeriSequence::new(1),
            &Said::new_unchecked(said.to_string()),
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].signature, vec![1u8; 64]);
    }
}
