//! Freshness model for verification verdicts (ADR 009 — bounded freshness, verifier-set
//! policy).
//!
//! Offline verification cannot guarantee real-time freshness: a verifier only knows what
//! is in the slice it was handed. So a positive verdict carries a freshness bound, and the
//! *tolerance* is the relying party's policy — never the signer's. See
//! `docs/architecture/ADRs/009-freshness-verdict-model.md`.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How fresh a positive verdict is, relative to the verifier's freshness policy. A positive
/// verdict is never bare: it is always qualified by one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// The supplied freshness evidence is within the policy window.
    Fresh,
    /// No source fresher than the supplied slice was available (offline). The verdict is
    /// valid as-of its bound, but freshness cannot be confirmed — this is named, never a
    /// silent pass and never a hard reject.
    Unknown,
    /// The supplied freshness evidence is provably older than the policy window.
    Stale,
}

/// The relying party's freshness tolerance. Verifier-set, never signer-set: a bundle
/// producer states an age, but the verifier caps the trust window (ADR 009 D2 — this is what
/// kills the "1-year bundle" anti-pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    /// Maximum age of the freshness evidence before the verdict is [`Freshness::Stale`].
    pub max_age: Duration,
    /// Whether [`Freshness::Unknown`] (offline / unconfirmable) is trusted. A strict relying
    /// party sets this to `false`; the offline-friendly default tolerates it.
    pub trust_unknown: bool,
}

impl Default for FreshnessPolicy {
    /// ADR 009 D2 default: a 24-hour window, tolerating `Unknown` (offline-friendly).
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(24 * 60 * 60),
            trust_unknown: true,
        }
    }
}

impl FreshnessPolicy {
    /// A strict policy: a short window, and `Unknown` is denied (requires a fresh source —
    /// a witness/checkpoint head).
    ///
    /// Args:
    /// * `max_age`: the maximum age of freshness evidence before it is `Stale`.
    pub fn strict(max_age: Duration) -> Self {
        Self {
            max_age,
            trust_unknown: false,
        }
    }

    /// Classify the freshness of a verdict from the age of its freshness evidence.
    ///
    /// `evidence_age` is `None` when no source fresher than the supplied slice is available
    /// (offline) — that NAMES the oracle as [`Freshness::Unknown`], never a silent pass and
    /// never a hard reject.
    ///
    /// Args:
    /// * `evidence_age`: age of the freshness evidence (e.g. a bundle timestamp, or a
    ///   witness/checkpoint head), or `None` when none is available.
    ///
    /// Usage:
    /// ```ignore
    /// let f = policy.classify(Some(bundle_age));
    /// ```
    pub fn classify(&self, evidence_age: Option<Duration>) -> Freshness {
        match evidence_age {
            None => Freshness::Unknown,
            Some(age) if age <= self.max_age => Freshness::Fresh,
            Some(_) => Freshness::Stale,
        }
    }

    /// Whether a freshness level clears this policy for a trust decision.
    ///
    /// Args:
    /// * `freshness`: the classified freshness of an otherwise-valid verdict.
    pub fn trusts(&self, freshness: Freshness) -> bool {
        match freshness {
            Freshness::Fresh => true,
            Freshness::Unknown => self.trust_unknown,
            Freshness::Stale => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_names_the_oracle_offline_is_unknown() {
        let p = FreshnessPolicy::default(); // 24h, tolerates unknown
        // Offline — no fresher source than the slice → Unknown (named), never a silent pass
        // and never a hard reject.
        assert_eq!(p.classify(None), Freshness::Unknown);
        // Within the window → Fresh.
        assert_eq!(
            p.classify(Some(Duration::from_secs(3600))),
            Freshness::Fresh
        );
        // Older than the window → Stale.
        assert_eq!(
            p.classify(Some(Duration::from_secs(25 * 3600))),
            Freshness::Stale
        );
    }

    #[test]
    fn strict_denies_unknown_and_stale_default_tolerates_unknown() {
        let strict = FreshnessPolicy::strict(Duration::from_secs(3600));
        assert!(strict.trusts(Freshness::Fresh));
        assert!(
            !strict.trusts(Freshness::Unknown),
            "strict denies offline-unknown"
        );
        assert!(!strict.trusts(Freshness::Stale));
        // The offline-friendly default tolerates Unknown but never Stale.
        assert!(FreshnessPolicy::default().trusts(Freshness::Unknown));
        assert!(!FreshnessPolicy::default().trusts(Freshness::Stale));
    }

    #[test]
    fn the_default_window_is_24h() {
        assert_eq!(
            FreshnessPolicy::default().max_age,
            Duration::from_secs(86_400)
        );
    }
}
