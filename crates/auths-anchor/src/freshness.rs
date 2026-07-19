//! Freshness math — a separate, labeled result (A5, D5, I-VERIFY-3).
//!
//! Freshness answers "is the evidence I hold current with the best anchor a
//! quorum finalized?" It is a pure index comparison, computed with no network,
//! and reported *beside* — never inside — the authorization verdict. A `stale`
//! result is the withholding/rollback signal; it is distinct from
//! `inconsistent` (a fork), which is duplicity's job, not freshness's.

use serde::{Deserialize, Serialize};

/// The freshness of a bundle relative to the best reachable finalized anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Freshness {
    /// The bundle head is at or beyond the best finalized anchor — current.
    Fresh {
        /// The index of the finalized anchor the bundle is current with.
        #[serde(rename = "anchorIndex")]
        anchor_index: u64,
    },
    /// A finalized anchor exists at a higher index than the bundle reflects —
    /// the holder is behind (withholding or rollback).
    Stale {
        /// The index the bundle head reaches.
        #[serde(rename = "bundleIndex")]
        bundle_index: u64,
        /// The higher index a quorum has already finalized.
        #[serde(rename = "anchorIndex")]
        anchor_index: u64,
    },
    /// No finalized anchor is reachable for this seed — freshness is unknown,
    /// which is never the same as `fresh`.
    Unanchored,
}

impl Freshness {
    /// The kebab/lowercase wire status string.
    pub fn status(&self) -> &'static str {
        match self {
            Freshness::Fresh { .. } => "fresh",
            Freshness::Stale { .. } => "stale",
            Freshness::Unanchored => "unanchored",
        }
    }

    /// True only for [`Freshness::Fresh`].
    pub fn is_fresh(&self) -> bool {
        matches!(self, Freshness::Fresh { .. })
    }
}

/// Compute freshness from a bundle's head index and the best reachable
/// finalized-anchor index.
///
/// - no anchor ⇒ [`Freshness::Unanchored`]
/// - `bundle_index ≥ anchor_index` ⇒ [`Freshness::Fresh`] (the bundle extends
///   the anchored prefix)
/// - `bundle_index < anchor_index` ⇒ [`Freshness::Stale`]
///
/// This is purely a reachability/index judgement; that the bundle actually
/// *extends* (rather than forks) the anchored head is a separate consistency
/// check whose failure surfaces as duplicity, not staleness.
///
/// Args:
/// * `bundle_index`: the record index the bundle's head reaches, if any.
/// * `best_anchor_index`: the highest finalized-anchor index reachable, if any.
///
/// Usage:
/// ```
/// # use auths_anchor::{freshness, Freshness};
/// assert!(matches!(freshness(Some(9), Some(7)), Freshness::Fresh { .. }));
/// assert!(matches!(freshness(Some(5), Some(7)), Freshness::Stale { .. }));
/// assert_eq!(freshness(Some(5), None), Freshness::Unanchored);
/// ```
pub fn freshness(bundle_index: Option<u64>, best_anchor_index: Option<u64>) -> Freshness {
    match best_anchor_index {
        None => Freshness::Unanchored,
        Some(anchor_index) => {
            let bundle_index = bundle_index.unwrap_or(0);
            if bundle_index >= anchor_index {
                Freshness::Fresh { anchor_index }
            } else {
                Freshness::Stale {
                    bundle_index,
                    anchor_index,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanchored_when_no_anchor() {
        assert_eq!(freshness(Some(10), None), Freshness::Unanchored);
        assert_eq!(freshness(None, None), Freshness::Unanchored);
    }

    #[test]
    fn fresh_when_bundle_at_or_beyond_anchor() {
        assert_eq!(
            freshness(Some(7), Some(7)),
            Freshness::Fresh { anchor_index: 7 }
        );
        assert_eq!(
            freshness(Some(12), Some(7)),
            Freshness::Fresh { anchor_index: 7 }
        );
    }

    #[test]
    fn stale_when_bundle_behind_anchor() {
        assert_eq!(
            freshness(Some(5), Some(7)),
            Freshness::Stale {
                bundle_index: 5,
                anchor_index: 7
            }
        );
        // No bundle head at all, but an anchor exists ⇒ behind.
        assert_eq!(
            freshness(None, Some(7)),
            Freshness::Stale {
                bundle_index: 0,
                anchor_index: 7
            }
        );
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(freshness(Some(7), Some(7)).status(), "fresh");
        assert_eq!(freshness(Some(1), Some(7)).status(), "stale");
        assert_eq!(freshness(None, None).status(), "unanchored");
    }
}
