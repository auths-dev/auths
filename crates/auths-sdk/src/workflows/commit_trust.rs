//! KEL-native commit-trust resolution — the single path that decides whether a
//! git commit is authorized by a pinned trusted root.
//!
//! Read the in-band `Auths-Id` / `Auths-Device` trailers, replay the device + root
//! KELs from the registry, and check the signature against the pinned `.auths/roots`
//! set. This is the successor to the `.auths/allowed_signers` SSH allowlist: trust is
//! rooted in the replayed KEL, never an out-of-band list of keys. The verdict logic
//! itself lives in `auths_verifier::verify_commit_against_kel`; this workflow owns the
//! orchestration (trailer parse → KEL resolution → verdict).

use auths_verifier::IdentityBundle;
use chrono::{DateTime, Utc};

use crate::keri::parse_trailers;

// `verify_commit_local` resolves KELs through `KelResolverChain`, which is only
// compiled with the git registry backend; gate it and its imports accordingly so
// `auths-sdk` still builds without `backend-git` (the pure helpers below do not).
#[cfg(feature = "backend-git")]
use crate::keri::KelResolverChain;
#[cfg(feature = "backend-git")]
use crate::ports::RegistryBackend;
#[cfg(feature = "backend-git")]
use auths_crypto::CryptoProvider;
#[cfg(feature = "backend-git")]
use auths_verifier::{CommitVerdict, verify_commit_against_kel};

/// Failure resolving commit trust before a verdict can be reached.
#[derive(Debug, thiserror::Error)]
pub enum CommitTrustError {
    /// The commit carries no `Auths-Id` / `Auths-Device` trailer pair.
    #[error(
        "commit carries no Auths-Id/Auths-Device trailer — it was not signed by `auths` \
         (or predates KEL-native signing)"
    )]
    MissingTrailers,

    /// A supplied identity bundle was unreadable, malformed, or stale. Fails
    /// closed — an unusable trust anchor must never silently downgrade trust.
    #[error("identity bundle is not a usable trust anchor: {0}")]
    BundleInvalid(String),

    /// A signer's KEL could not be resolved from the registry.
    #[error("{role} KEL for {did} could not be resolved: {reason}")]
    KelUnresolved {
        /// Which KEL failed to resolve — `"device"` or `"root"`.
        role: &'static str,
        /// The `did:keri:` / `did:key:` whose KEL could not be resolved.
        did: String,
        /// The underlying resolver error, rendered for display.
        reason: String,
    },
}

/// Extract `(root_did, device_did)` from a commit's `Auths-Id` / `Auths-Device`
/// trailers. Returns `None` when either trailer is absent (a commit not signed by
/// `auths`).
///
/// Args:
/// * `raw_commit`: The raw git commit object (headers + message).
///
/// Usage:
/// ```ignore
/// if let Some((root, device)) = commit_signer_trailers(commit) { /* trusted? */ }
/// ```
pub fn commit_signer_trailers(raw_commit: &str) -> Option<(String, String)> {
    let message = raw_commit
        .split_once("\n\n")
        .map(|(_, m)| m)
        .unwrap_or(raw_commit);
    let trailers = parse_trailers(message);
    let find = |key: &str| {
        trailers
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.trim().to_string())
    };
    Some((find("Auths-Id")?, find("Auths-Device")?))
}

/// The trusted root `did:keri:` a CI/stateless identity bundle pins.
///
/// The bundle's `identity_did` is a self-certifying KERI prefix (the prefix *is* the
/// digest of its inception event), so trusting it as a pinned root is sound: any KEL
/// resolved for that DID must self-certify to the same prefix or fail prefix-binding.
/// The bundle is freshness-checked against `now` and fails **closed** — a stale or
/// malformed anchor is rejected, never silently treated as "no constraint".
///
/// Args:
/// * `bundle`: The parsed identity bundle supplied via `--identity-bundle`.
/// * `now`: Current time, injected at the presentation boundary.
///
/// Usage:
/// ```ignore
/// let root = trusted_root_from_bundle(&bundle, clock.now())?;
/// pinned_roots.push(root);
/// ```
pub fn trusted_root_from_bundle(
    bundle: &IdentityBundle,
    now: DateTime<Utc>,
) -> Result<String, CommitTrustError> {
    bundle
        .check_freshness(now)
        .map_err(|e| CommitTrustError::BundleInvalid(e.to_string()))?;
    Ok(bundle.identity_did.to_string())
}

/// Verify a commit against the locally-replayed KEL and the pinned trusted roots.
///
/// Local-only (no network, no witness gate): resolves the device and root KELs from
/// `registry`, then replays them to decide whether the commit's signer is a device
/// delegated under a root pinned in `pinned_roots`. This is the trust primitive the
/// artifact-provenance path uses for the human-signed commit an ephemeral attestation
/// is bound to. Witnessed and transport-aware verification (the `auths verify`
/// command) layers `--remote`/`--oobi` and witness receipts on top of the same
/// `auths_verifier` KEL primitive.
///
/// Args:
/// * `registry`: The registry backend holding identity KELs.
/// * `pinned_roots`: Trusted root `did:keri:` strings (from `.auths/roots`).
/// * `raw_commit`: The raw git commit object bytes (with the `gpgsig` signature).
/// * `provider`: Crypto provider for in-process signature verification.
///
/// Usage:
/// ```ignore
/// let verdict = verify_commit_local(&registry, &roots, commit_bytes, &provider).await?;
/// assert!(verdict.is_valid());
/// ```
#[cfg(feature = "backend-git")]
pub async fn verify_commit_local(
    registry: &dyn RegistryBackend,
    pinned_roots: &[String],
    raw_commit: &[u8],
    provider: &dyn CryptoProvider,
) -> Result<CommitVerdict, CommitTrustError> {
    let commit_str = String::from_utf8_lossy(raw_commit);
    let (root_did, device_did) =
        commit_signer_trailers(&commit_str).ok_or(CommitTrustError::MissingTrailers)?;

    let chain = KelResolverChain::local(registry);
    let device_kel =
        chain
            .resolve_kel(&device_did)
            .map_err(|e| CommitTrustError::KelUnresolved {
                role: "device",
                did: device_did.clone(),
                reason: e.to_string(),
            })?;
    let root_kel = chain
        .resolve_kel(&root_did)
        .map_err(|e| CommitTrustError::KelUnresolved {
            role: "root",
            did: root_did.clone(),
            reason: e.to_string(),
        })?;

    Ok(verify_commit_against_kel(raw_commit, &device_kel, &root_kel, pinned_roots, provider).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "did:keri:Eroot00000000000000000000000000000000000000";
    const DEVICE: &str = "did:key:z6MkDevice000000000000000000000000000000000";

    fn commit_with_trailers(root: &str, device: &str) -> String {
        format!(
            "tree abc\nauthor T <t@e.com> 0 +0000\n\nsubject\n\nAuths-Id: {root}\nAuths-Device: {device}\n"
        )
    }

    #[test]
    fn extracts_both_trailers() {
        let commit = commit_with_trailers(ROOT, DEVICE);
        assert_eq!(
            commit_signer_trailers(&commit),
            Some((ROOT.to_string(), DEVICE.to_string()))
        );
    }

    #[test]
    fn missing_device_trailer_yields_none() {
        let commit = "tree abc\n\nsubject\n\nAuths-Id: did:keri:Eroot\n";
        assert!(commit_signer_trailers(commit).is_none());
    }

    #[test]
    fn no_trailers_yields_none() {
        assert!(commit_signer_trailers("tree abc\n\njust a message\n").is_none());
    }

    #[test]
    fn last_trailer_wins_on_duplicates() {
        let commit = format!(
            "tree abc\n\nsubject\n\nAuths-Id: did:keri:Eold\nAuths-Device: {DEVICE}\nAuths-Id: {ROOT}\n"
        );
        assert_eq!(
            commit_signer_trailers(&commit),
            Some((ROOT.to_string(), DEVICE.to_string()))
        );
    }

    #[allow(clippy::disallowed_methods)] // INVARIANT: fixed test strings, never external input
    fn test_bundle(did: &str, ts: DateTime<Utc>, ttl: u64) -> IdentityBundle {
        IdentityBundle {
            identity_did: auths_verifier::IdentityDID::new_unchecked(did.to_string()),
            public_key_hex: auths_verifier::PublicKeyHex::new_unchecked("00".to_string()),
            curve: auths_crypto::CurveType::P256,
            attestation_chain: Vec::new(),
            bundle_timestamp: ts,
            max_valid_for_secs: ttl,
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    #[test]
    fn fresh_bundle_yields_its_root_did() {
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let now = t + chrono::Duration::seconds(100);
        assert_eq!(trusted_root_from_bundle(&bundle, now).expect("fresh"), ROOT);
    }

    #[test]
    fn stale_bundle_fails_closed() {
        let t = fixed_time();
        let bundle = test_bundle(ROOT, t, 3600);
        let now = t + chrono::Duration::seconds(7200);
        assert!(matches!(
            trusted_root_from_bundle(&bundle, now),
            Err(CommitTrustError::BundleInvalid(_))
        ));
    }
}
