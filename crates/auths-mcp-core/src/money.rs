//! The money types the gateway meters in. Newtypes so a security-critical amount can never be
//! confused with a bare count, mixed between units, or silently defaulted to a dangerous zero, and
//! so every money sum is checked — a wrap on the spend total would defeat the cap.
//!
//! `Cents` is the canonical unit the cross-rail cap, the settlements, and the audit all reason in.
//! `AtomicUsdc` is a rail-native unit (USDC has 6 decimals) that only reaches `Cents` through a
//! total conversion that refuses a sub-cent residue rather than truncating it. `NonZeroCents` is the
//! ceiling a *metered* call must carry — it cannot hold zero, so "metered with no amount" is not a
//! representable state.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

/// A monetary amount in whole cents — the canonical money unit. Serializes transparently as its
/// inner number, so the spend-log and receipt JSON shape is unchanged. No `Default`: a zero amount
/// is written explicitly with [`Cents::ZERO`], never conjured by a derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cents(u64);

impl Cents {
    /// The zero amount — a non-metered call's cost.
    pub const ZERO: Cents = Cents(0);

    /// The zero amount, as a function — the `#[serde(default)]` for an optional cents
    /// field (e.g. a `tools/call`'s `cost_cents` defaulting to non-metered). `Cents`
    /// has no `Default` derive on purpose, so a zero is always written explicitly.
    pub const fn zero() -> Cents {
        Cents::ZERO
    }

    /// Wrap a raw cent count.
    pub const fn new(cents: u64) -> Cents {
        Cents(cents)
    }

    /// The raw cent count, for formatting / FFI / the durable counter's `u64` ledger.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// True for the zero amount (a non-metered call).
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Add two amounts, saturating at `u64::MAX` — money never wraps to a small number.
    #[must_use]
    pub const fn saturating_add(self, other: Cents) -> Cents {
        Cents(self.0.saturating_add(other.0))
    }

    /// Add two amounts, or `None` on overflow — for the path that must refuse rather than saturate.
    #[must_use]
    pub const fn checked_add(self, other: Cents) -> Option<Cents> {
        match self.0.checked_add(other.0) {
            Some(v) => Some(Cents(v)),
            None => None,
        }
    }
}

impl fmt::Display for Cents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}.{:02}", self.0 / 100, self.0 % 100)
    }
}

/// The ceiling a metered call reserves — cents that cannot be zero. A metered call always carries
/// one, so "a payment rail is set but the amount is zero/absent" cannot be constructed: the gate
/// parses the agent's declared amount into this once, at the boundary, or refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NonZeroCents(NonZeroU64);

impl NonZeroCents {
    /// Parse an amount into a metered ceiling, or `None` if it is zero (which a metered call must
    /// not be — the caller refuses fail-closed).
    pub fn new(cents: Cents) -> Option<NonZeroCents> {
        NonZeroU64::new(cents.0).map(NonZeroCents)
    }

    /// The ceiling as a plain amount.
    pub const fn get(self) -> Cents {
        Cents(self.0.get())
    }
}

impl fmt::Display for NonZeroCents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

/// USDC has 6 decimals, so `1_000_000` atomic = 1 USDC = 100 cents, and the atomic-per-cent divisor
/// is `1e6 / 100`.
const USDC_ATOMIC_PER_CENT: u64 = 10_000;

/// An amount in atomic USDC units (the rail-native unit a metered x402 call declares and settles
/// in). Reaches [`Cents`] only through the conversions below — a bare `u64` of atomic units can
/// never be summed into the cents-denominated cap by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AtomicUsdc(u64);

impl AtomicUsdc {
    /// Wrap a raw atomic-USDC count (e.g. read from an agent's `amount_atomic` arg or a rail's
    /// `maxAmountRequired`).
    pub const fn new(atomic: u64) -> AtomicUsdc {
        AtomicUsdc(atomic)
    }

    /// The raw atomic count.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Convert to cents rounding UP — the reserve ceiling the gateway holds before a metered call,
    /// so the hold always covers the amount the settle reports.
    pub const fn to_cents_ceiling(self) -> Cents {
        Cents(self.0.div_ceil(USDC_ATOMIC_PER_CENT))
    }

    /// Convert to cents EXACTLY, or `None` if there is a sub-cent residue — the settle refuses a
    /// fractional cent rather than silently truncating it.
    pub fn to_cents_exact(self) -> Option<Cents> {
        if self.0.is_multiple_of(USDC_ATOMIC_PER_CENT) {
            Some(Cents(self.0 / USDC_ATOMIC_PER_CENT))
        } else {
            None
        }
    }

    /// The reserve ceiling (rounds UP), carried as a [`Ceiling`] so it cannot be settled by
    /// mistake — the typed form of [`AtomicUsdc::to_cents_ceiling`].
    pub const fn to_ceiling(self) -> Ceiling {
        Ceiling::new(self.to_cents_ceiling())
    }

    /// The settle actual (EXACT, or `None` on a sub-cent residue), carried as an [`Actual`] so it
    /// cannot be reserved by mistake — the typed form of [`AtomicUsdc::to_cents_exact`].
    pub fn to_actual(self) -> Option<Actual> {
        self.to_cents_exact().map(Actual::new)
    }
}

/// The amount a metered call RESERVES before the rail is touched — the upper bound the
/// pre-authorization hold covers. A distinct type from [`Actual`] so a reserve ceiling can never
/// be passed where a settled actual is expected, and vice versa: a reserve↔settle swap is a
/// compile error, not a silent money bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ceiling(Cents);

impl Ceiling {
    /// Carry a cents amount as a reserve ceiling.
    pub const fn new(cents: Cents) -> Ceiling {
        Ceiling(cents)
    }

    /// The ceiling as a plain amount, for arithmetic against the cap.
    pub const fn cents(self) -> Cents {
        self.0
    }
}

impl fmt::Display for Ceiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The ACTUAL cost a metered call SETTLES after the downstream returns. A distinct type from
/// [`Ceiling`] so a settled actual can never be reserved, nor a ceiling settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Actual(Cents);

impl Actual {
    /// Carry a cents amount as a settled actual.
    pub const fn new(cents: Cents) -> Actual {
        Actual(cents)
    }

    /// The actual as a plain amount, for the counter advance and receipt.
    pub const fn cents(self) -> Cents {
        self.0
    }
}

impl fmt::Display for Actual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cents_display_is_dollars() {
        assert_eq!(Cents::new(150).to_string(), "$1.50");
        assert_eq!(Cents::new(5).to_string(), "$0.05");
    }

    #[test]
    fn cents_add_saturates_not_wraps() {
        assert_eq!(
            Cents::new(u64::MAX).saturating_add(Cents::new(10)),
            Cents::new(u64::MAX)
        );
        assert_eq!(Cents::new(u64::MAX).checked_add(Cents::new(1)), None);
    }

    #[test]
    fn nonzero_cents_rejects_zero() {
        assert!(NonZeroCents::new(Cents::ZERO).is_none());
        assert_eq!(
            NonZeroCents::new(Cents::new(3)).map(|c| c.get()),
            Some(Cents::new(3))
        );
    }

    #[test]
    fn atomic_usdc_ceiling_and_exact() {
        assert_eq!(
            AtomicUsdc::new(1_500_000).to_cents_ceiling(),
            Cents::new(150)
        );
        assert_eq!(
            AtomicUsdc::new(1_500_000).to_cents_exact(),
            Some(Cents::new(150))
        );
        // A sub-cent residue: rounds up for the ceiling, refused for the exact settle.
        assert_eq!(
            AtomicUsdc::new(1_505_000).to_cents_ceiling(),
            Cents::new(151)
        );
        assert_eq!(AtomicUsdc::new(1_505_000).to_cents_exact(), None);
    }

    #[test]
    fn ceiling_and_actual_are_distinct_typed_views_of_cents() {
        assert_eq!(Ceiling::new(Cents::new(150)).cents(), Cents::new(150));
        assert_eq!(Actual::new(Cents::new(120)).cents(), Cents::new(120));
    }

    #[test]
    fn atomic_usdc_produces_a_typed_ceiling_and_actual() {
        // The reserve ceiling rounds up; the settle actual is exact-or-refused — the same split as
        // the bare-cents conversions, but now carried in distinct types.
        assert_eq!(
            AtomicUsdc::new(1_500_000).to_ceiling().cents(),
            Cents::new(150)
        );
        assert_eq!(
            AtomicUsdc::new(1_500_000).to_actual().map(Actual::cents),
            Some(Cents::new(150))
        );
        assert_eq!(
            AtomicUsdc::new(1_505_000).to_ceiling().cents(),
            Cents::new(151)
        );
        assert_eq!(AtomicUsdc::new(1_505_000).to_actual(), None);
    }
}
