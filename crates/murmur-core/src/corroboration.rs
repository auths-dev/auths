//! Where a revocation verdict came *from* — witness-corroborated key-state, or a
//! relay's cache (PRD §6.5, §6.6, §3.1's launch-centralization asterisk).
//!
//! Revocation is **detection, not prevention** (PRD §6.5). When you lose the Mac
//! and revoke it, a contact stops accepting the Mac's messages only when they
//! **re-resolve** your key-state — and the clawback is only *safe* if they get the
//! **witness-corroborated** delegation set rather than a relay's stale cache. A
//! malicious or merely lagging relay can serve a delegation set that predates the
//! revocation; a contact who trusts that cache as if it were corroborated would
//! keep accepting a revoked device. So the resolved state is not enough — *where it
//! came from* is part of the verdict.
//!
//! ## The honest boundary this module makes load-bearing
//!
//! [`DelegationState`](crate::delegation::DelegationState) already rejects a revoked
//! device once the revocation is in the set. What it cannot say by itself is whether
//! that set is *current*. This module pairs a delegation set with its
//! [`Provenance`]:
//!
//!  * [`Provenance::WitnessCorroborated`] — the revocation set was confirmed by at
//!    least a threshold of the AID's witnesses (the receipts a KEL replay carries,
//!    PRD §6.6 `replay_with_receipts`). A revoked device resolved from here is
//!    **rejected** with certainty: the clawback holds, corroborated.
//!  * [`Provenance::RelayCache`] — the set came from a relay's cache, which may be
//!    **stale** (it predates a revocation the witnesses have already receipted). The
//!    verdict from such a source is never silently treated as safe: it **discloses
//!    the stale-served window** (PRD §6.5) rather than waving the device through.
//!
//! The trap this closes: a revoked device **accepted** from corroborated state, a
//! relay cache **trusted over** the witnesses, or a stale window **hidden** — each
//! must fail. A verdict that claims `corroborated` while resolving from a relay's
//! cache, or that hides a known-stale window, is exactly the over-sold "instant
//! global kill" the PRD refuses to claim.

use crate::address::Aid;
use crate::delegation::DelegationState;
use crate::{CoreError, CoreResult};

/// Where a delegation/revocation set was resolved from — the provenance that
/// decides whether a clawback is *corroborated* or merely *cached*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// The set was confirmed by the AID's witnesses: at least `confirmed` of
    /// `threshold` witnesses receipted the key-state carrying it (PRD §6.6). A
    /// revocation resolved from here is corroborated — the clawback holds.
    WitnessCorroborated {
        /// How many witnesses receipted this key-state.
        confirmed: u8,
        /// The witness threshold the AID's key-state requires to be corroborated.
        threshold: u8,
    },
    /// The set came from a relay's cache, which may lag the witnessed truth. The
    /// honest window the PRD names: an offline contact, or one served this stale
    /// cache, still has a window before it re-resolves corroborated state.
    RelayCache {
        /// How many revocations the witnesses have receipted that this cache has
        /// **not** yet caught up to — the measurable size of the stale window. Zero
        /// means the cache happens to be current, but it is *still* a cache: the
        /// verdict discloses that it was not corroborated against the witnesses.
        revocations_behind_witnesses: u32,
    },
}

impl Provenance {
    /// True iff this provenance meets the witness threshold — the only source a
    /// clawback may be called *corroborated* from. A relay cache is never
    /// corroborated, even when it happens to be current: it was not checked
    /// against the witnesses, so it cannot certify a revocation.
    pub fn is_corroborated(&self) -> bool {
        match self {
            Provenance::WitnessCorroborated {
                confirmed,
                threshold,
            } => threshold > &0 && confirmed >= threshold,
            Provenance::RelayCache { .. } => false,
        }
    }

    /// A short, machine-greppable token naming the provenance, for the verdict line.
    fn token(&self) -> &'static str {
        match self {
            Provenance::WitnessCorroborated { .. } => "witness-corroborated",
            Provenance::RelayCache { .. } => "relay-cache",
        }
    }
}

/// How a revocation resolved when the *provenance* of the key-state is part of the
/// verdict. Either the device was rejected from corroborated state (the safe
/// clawback), or the verdict came from a relay's cache and the honest stale window
/// is disclosed — never a silent "safe".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationResolution {
    /// The revoked device was **rejected from witness-corroborated key-state** — the
    /// clawback holds, corroborated. This is the only outcome that may be treated as
    /// a safe drop.
    RevokedFromCorroboratedState {
        /// The device that was clawed back.
        device_aid: Aid,
        /// The root that revoked it.
        root_aid: Aid,
        /// How many witnesses corroborated the revocation set.
        witnesses_confirmed: u8,
    },
    /// The verdict was resolved from a relay's cache, so the stale-served window is
    /// **disclosed** rather than silently treated as safe (PRD §6.5). The device may
    /// or may not yet appear revoked in the cache; either way the contact is told the
    /// source was not corroborated and how far behind it may be.
    StaleWindowDisclosed {
        /// The device whose revocation status the cache was asked about.
        device_aid: Aid,
        /// Whether the cache *did* show the device as revoked — disclosed alongside
        /// the fact that the showing was not witness-corroborated.
        cache_shows_revoked: bool,
        /// How many witnessed revocations this cache lags behind — the measurable
        /// window before the contact re-resolves corroborated state.
        revocations_behind_witnesses: u32,
    },
}

impl RevocationResolution {
    /// True iff the revoked device was rejected from witness-corroborated state — the
    /// only outcome that is a *safe* clawback. A disclosed stale window is honest, not
    /// safe.
    pub fn is_corroborated_rejection(&self) -> bool {
        matches!(
            self,
            RevocationResolution::RevokedFromCorroboratedState { .. }
        )
    }

    /// True iff this resolution disclosed a stale-served window rather than treating a
    /// relay's cache as corroborated.
    pub fn discloses_stale_window(&self) -> bool {
        matches!(self, RevocationResolution::StaleWindowDisclosed { .. })
    }
}

/// A delegation set paired with the [`Provenance`] of where a contact resolved it.
/// This is the type the contact actually holds: not a bare
/// [`DelegationState`](crate::delegation::DelegationState) it implicitly trusts, but
/// one tagged with whether it was corroborated by the witnesses or served from a
/// relay's cache — so a revocation verdict can never silently launder a stale cache
/// into a corroborated clawback.
#[derive(Debug, Clone)]
pub struct CorroboratedState {
    state: DelegationState,
    provenance: Provenance,
}

impl CorroboratedState {
    /// Pair a resolved delegation `state` with the `provenance` it came from.
    pub fn new(state: DelegationState, provenance: Provenance) -> Self {
        CorroboratedState { state, provenance }
    }

    /// The provenance this state was resolved from.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Resolve a revocation verdict for `(device AID, device key)`, with the
    /// provenance folded into the answer.
    ///
    /// The contract that makes the clawback honest:
    ///
    ///  * **Witness-corroborated source.** The device is resolved against the
    ///    underlying [`DelegationState`]. If the state rejects it (revoked, or never
    ///    anchored), the verdict is [`RevocationResolution::RevokedFromCorroboratedState`]
    ///    — a corroborated clawback. If the device *still resolves* to the root from
    ///    corroborated state, that means it is **not** revoked there, and this returns
    ///    [`CoreError::Rejected`]: it is a bug to ask this for a live device, and we
    ///    will never report "revoked from corroborated state" for a device the
    ///    corroborated state still accepts. (The corroborated *accept* path is
    ///    `DelegationState::resolve_device_to_root` — this method is the *revocation*
    ///    verdict.)
    ///  * **Relay-cache source.** The verdict is **never** corroborated. Whether or
    ///    not the cache shows the device revoked, the answer is
    ///    [`RevocationResolution::StaleWindowDisclosed`], carrying how far the cache
    ///    lags the witnesses — the honest window the PRD insists on disclosing rather
    ///    than waving through as safe.
    ///
    /// So a revoked device is **rejected from corroborated state**, and a relay's
    /// cache is **disclosed as a window**, never trusted over the witnesses. The two
    /// failure modes the trap records — a revoked device accepted from corroborated
    /// state, or a relay cache passed off as corroborated — are both unreachable here.
    pub fn resolve_revocation(
        &self,
        device_aid: &Aid,
        device_key: &[u8],
    ) -> CoreResult<RevocationResolution> {
        match &self.provenance {
            Provenance::WitnessCorroborated {
                confirmed,
                threshold,
            } => {
                if !self.provenance.is_corroborated() {
                    // The source claims to be witness-corroborated but does not meet
                    // the threshold — it is not corroborated, and we refuse to treat
                    // it as such. Fail closed rather than launder a sub-threshold set.
                    return Err(CoreError::Rejected(
                        "the witness set is below threshold — not corroborated, cannot certify a revocation",
                    ));
                }
                match self.state.resolve_device_to_root(device_aid, device_key) {
                    // The corroborated state still accepts the device — it is NOT
                    // revoked there. Asking for a revocation verdict on a live device
                    // is a caller bug; we never fabricate "revoked from corroborated".
                    Ok(_) => Err(CoreError::Rejected(
                        "the device still resolves from corroborated state — it is not revoked, no clawback to report",
                    )),
                    // The corroborated state rejects the device: the clawback holds,
                    // corroborated by the witnesses.
                    Err(CoreError::Rejected(_)) => {
                        Ok(RevocationResolution::RevokedFromCorroboratedState {
                            device_aid: device_aid.clone(),
                            root_aid: self.state.root_aid().clone(),
                            witnesses_confirmed: *confirmed.min(threshold),
                        })
                    }
                    Err(other) => Err(other),
                }
            }
            Provenance::RelayCache {
                revocations_behind_witnesses,
            } => {
                // A relay's cache can never certify a revocation. Disclose the window
                // — whether or not the cache happens to show the device revoked — so a
                // contact never mistakes a cache for corroboration.
                let cache_shows_revoked = self
                    .state
                    .resolve_device_to_root(device_aid, device_key)
                    .is_err();
                Ok(RevocationResolution::StaleWindowDisclosed {
                    device_aid: device_aid.clone(),
                    cache_shows_revoked,
                    revocations_behind_witnesses: *revocations_behind_witnesses,
                })
            }
        }
    }

    /// A one-line, machine-greppable disclosure of this verdict for the relay
    /// binary's self-test and the apps' diagnostics. The witness-corroborated path
    /// carries the `revoked-from-corroborated-state` token; the relay-cache path
    /// carries the `stale-window-disclosed` token. Neither line ever claims a relay
    /// cache was corroborated.
    pub fn disclose(resolution: &RevocationResolution) -> String {
        match resolution {
            RevocationResolution::RevokedFromCorroboratedState {
                device_aid,
                root_aid,
                witnesses_confirmed,
            } => format!(
                "revoked-from-corroborated-state: device {device} was rejected as a revoked \
                 delegate of {root} from witness-corroborated key-state ({n} witnesses \
                 corroborated the revocation) — the clawback holds, corroborated, not from a \
                 relay's cache",
                device = device_aid.as_str(),
                root = root_aid.as_str(),
                n = witnesses_confirmed,
            ),
            RevocationResolution::StaleWindowDisclosed {
                device_aid,
                cache_shows_revoked,
                revocations_behind_witnesses,
            } => format!(
                "stale-window-disclosed: a revocation verdict for device {device} was resolved \
                 from a relay's cache (cache_shows_revoked={shown}), which is NOT \
                 witness-corroborated and lags the witnesses by {behind} revocation(s) — the honest \
                 stale-served window before the contact re-resolves corroborated state, disclosed, \
                 never waved through as safe",
                device = device_aid.as_str(),
                shown = cache_shows_revoked,
                behind = revocations_behind_witnesses,
            ),
        }
    }
}

/// The provenance token of a [`CorroboratedState`], exposed so a caller can assert
/// which source a verdict was resolved from without matching the enum.
pub fn provenance_token(state: &CorroboratedState) -> &'static str {
    state.provenance.token()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{DelegatedDevice, DelegationAnchor, DeviceRevocation};
    use crate::identity::Identity;

    fn root() -> Identity {
        Identity::from_seed([0x01u8; 32]).unwrap()
    }

    fn device(seed: u8, root_aid: &Aid) -> DelegatedDevice {
        DelegatedDevice::new(Identity::from_seed([seed; 32]).unwrap(), root_aid.clone())
    }

    /// Build a delegation state for `root` that admits `device` and (optionally)
    /// revokes it.
    fn state_with(root: &Identity, device: &DelegatedDevice, revoked: bool) -> DelegationState {
        let anchor = DelegationAnchor::issue(root, device).unwrap();
        let mut state = DelegationState::for_root(root);
        state.admit_device(anchor).unwrap();
        if revoked {
            let revocation = DeviceRevocation::issue(root, device.device_aid()).unwrap();
            state.revoke_device(revocation).unwrap();
        }
        state
    }

    #[test]
    fn a_revoked_device_is_rejected_from_corroborated_state() {
        let root = root();
        let mac = device(0x02, root.aid());
        let state = state_with(&root, &mac, true);
        let corroborated = CorroboratedState::new(
            state,
            Provenance::WitnessCorroborated {
                confirmed: 3,
                threshold: 2,
            },
        );
        let resolution = corroborated
            .resolve_revocation(mac.device_aid(), mac.device_key())
            .unwrap();
        assert!(resolution.is_corroborated_rejection());
        assert!(!resolution.discloses_stale_window());
        let line = CorroboratedState::disclose(&resolution);
        assert!(line.contains("revoked-from-corroborated-state"));
        // The corroborated path NEVER reads like a relay cache.
        assert!(!line.contains("relay-cache"));
    }

    #[test]
    fn a_relay_cache_is_disclosed_as_a_window_never_corroborated() {
        let root = root();
        let mac = device(0x02, root.aid());
        // The relay's cache is STALE: it predates the revocation, so it still shows
        // the device as live. The verdict must disclose the window, not wave it
        // through.
        let stale = state_with(&root, &mac, false);
        let cache = CorroboratedState::new(
            stale,
            Provenance::RelayCache {
                revocations_behind_witnesses: 1,
            },
        );
        let resolution = cache
            .resolve_revocation(mac.device_aid(), mac.device_key())
            .unwrap();
        assert!(resolution.discloses_stale_window());
        assert!(!resolution.is_corroborated_rejection());
        if let RevocationResolution::StaleWindowDisclosed {
            cache_shows_revoked,
            revocations_behind_witnesses,
            ..
        } = &resolution
        {
            assert!(!cache_shows_revoked); // the stale cache had not caught up
            assert_eq!(*revocations_behind_witnesses, 1);
        } else {
            panic!("expected a disclosed stale window");
        }
        let line = CorroboratedState::disclose(&resolution);
        assert!(line.contains("stale-window-disclosed"));
        // The disclosure NEVER claims a corroborated clawback — it discloses the
        // window from a relay's cache, never certifying the revocation.
        assert!(!line.contains("revoked-from-corroborated-state"));
        assert!(line.contains("relay's cache"));
    }

    #[test]
    fn a_relay_cache_that_happens_to_show_revoked_is_still_only_disclosed() {
        // Even when the relay's cache *does* show the device revoked, it is not
        // corroborated — it was never checked against the witnesses, so the verdict
        // discloses the window rather than certifying the clawback.
        let root = root();
        let mac = device(0x02, root.aid());
        let cache_state = state_with(&root, &mac, true);
        let cache = CorroboratedState::new(
            cache_state,
            Provenance::RelayCache {
                revocations_behind_witnesses: 0,
            },
        );
        let resolution = cache
            .resolve_revocation(mac.device_aid(), mac.device_key())
            .unwrap();
        assert!(resolution.discloses_stale_window());
        assert!(!resolution.is_corroborated_rejection());
        if let RevocationResolution::StaleWindowDisclosed {
            cache_shows_revoked,
            ..
        } = &resolution
        {
            assert!(cache_shows_revoked); // the cache shows revoked …
        } else {
            panic!("expected a disclosed stale window");
        }
        // … but it is NOT a corroborated rejection.
        assert!(!resolution.is_corroborated_rejection());
    }

    #[test]
    fn a_live_device_from_corroborated_state_has_no_clawback_to_report() {
        // Asking for a revocation verdict on a device the corroborated state still
        // accepts is a caller bug — we never fabricate "revoked from corroborated".
        let root = root();
        let mac = device(0x02, root.aid());
        let state = state_with(&root, &mac, false); // not revoked
        let corroborated = CorroboratedState::new(
            state,
            Provenance::WitnessCorroborated {
                confirmed: 2,
                threshold: 2,
            },
        );
        assert!(matches!(
            corroborated.resolve_revocation(mac.device_aid(), mac.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_sub_threshold_witness_set_is_not_corroborated() {
        // A "witness-corroborated" source that does not meet the threshold is not
        // corroborated — it cannot certify a revocation, and fails closed rather than
        // laundering a sub-threshold set into a corroborated clawback.
        let root = root();
        let mac = device(0x02, root.aid());
        let state = state_with(&root, &mac, true);
        let under = CorroboratedState::new(
            state,
            Provenance::WitnessCorroborated {
                confirmed: 1,
                threshold: 3,
            },
        );
        assert!(!under.provenance().is_corroborated());
        assert!(matches!(
            under.resolve_revocation(mac.device_aid(), mac.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_relay_cache_is_never_corroborated_even_when_current() {
        // The provenance, not the contents, decides corroboration: a relay cache that
        // happens to be perfectly current is still a cache.
        assert!(
            !Provenance::RelayCache {
                revocations_behind_witnesses: 0
            }
            .is_corroborated()
        );
        assert!(
            Provenance::WitnessCorroborated {
                confirmed: 2,
                threshold: 2
            }
            .is_corroborated()
        );
    }
}
