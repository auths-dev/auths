use crate::identity::resolve::DidResolver;
use auths_verifier::core::Attestation;
use auths_verifier::error::AttestationError;
use chrono::{DateTime, Duration, Utc};
use log::debug;
use ring::signature::{ED25519, UnparsedPublicKey};

/// Maximum allowed time skew for attestation timestamps.
const MAX_SKEW_SECS: i64 = 5 * 60;

/// Verifies an attestation's signatures, revocation status, expiry, and timestamp validity.
///
/// **Timestamp threat model:** Past timestamps are accepted by default because attestations
/// stored in Git are routinely verified days or months after issuance. Only future timestamps
/// (beyond `MAX_SKEW_SECS`) are rejected to guard against clock drift. To enforce freshness,
/// callers can pass `max_age` — or use the `IssuedWithin` policy expression at a higher layer.
///
/// **Limitation:** `timestamp` is self-reported by the issuer and can be backdated. For
/// stronger guarantees, combine with Git commit timestamps or witness receipts.
///
/// Args:
/// * `now`: Current wall-clock time (injected for testability).
/// * `resolver`: Resolves issuer DIDs to public keys.
/// * `att`: The attestation to verify.
/// * `max_age`: If `Some`, rejects attestations older than this duration.
///
/// Usage:
/// ```ignore
/// // Accept any age:
/// verify_with_resolver(now, &resolver, &att, None)?;
/// // Require issued within last hour:
/// verify_with_resolver(now, &resolver, &att, Some(Duration::hours(1)))?;
/// ```
pub fn verify_with_resolver(
    now: DateTime<Utc>,
    resolver: &dyn DidResolver,
    att: &Attestation,
    max_age: Option<Duration>,
) -> Result<(), AttestationError> {
    if att.is_revoked() {
        return Err(AttestationError::AttestationRevoked);
    }
    if let Some(exp) = att.expires_at
        && now > exp
    {
        return Err(AttestationError::AttestationExpired {
            at: exp.to_rfc3339(),
        });
    }
    if let Some(ts) = att.timestamp
        && ts > now + Duration::seconds(MAX_SKEW_SECS)
    {
        return Err(AttestationError::TimestampInFuture {
            at: ts.to_rfc3339(),
        });
    }
    if let Some(max) = max_age
        && let Some(ts) = att.timestamp
    {
        let age = now - ts;
        if age > max {
            return Err(AttestationError::AttestationTooOld {
                age_secs: age.num_seconds().unsigned_abs(),
                max_secs: max.num_seconds().unsigned_abs(),
            });
        }
    }

    // 2. Resolve issuer's public key
    let resolved = resolver.resolve(&att.issuer).map_err(|e| {
        AttestationError::DidResolutionError(format!("Resolver error for {}: {}", att.issuer, e))
    })?;
    let issuer_pk_bytes = resolved.public_key_bytes();

    // 3. Reconstruct canonical data (single source of truth via canonical_data())
    let canonical_json_string = json_canon::to_string(&att.canonical_data()).map_err(|e| {
        AttestationError::SerializationError(format!(
            "Failed to create canonical JSON for verification: {}",
            e
        ))
    })?;
    let data_to_verify = canonical_json_string.as_bytes();
    debug!(
        "(Verify) Canonical data for verification: {}",
        canonical_json_string
    );

    // 4. Verify issuer signature
    let issuer_public_key_ring = UnparsedPublicKey::new(&ED25519, &issuer_pk_bytes);
    issuer_public_key_ring
        .verify(data_to_verify, att.identity_signature.as_bytes())
        .map_err(|e| AttestationError::IssuerSignatureFailed(e.to_string()))?;
    debug!(
        "(Verify) Issuer signature verified successfully for {}",
        att.issuer
    );

    // 5. Verify subject (device) signature using stored public key
    let device_public_key_ring = UnparsedPublicKey::new(&ED25519, att.device_public_key.as_bytes());
    device_public_key_ring
        .verify(data_to_verify, att.device_signature.as_bytes())
        .map_err(|e| AttestationError::DeviceSignatureFailed(e.to_string()))?;
    debug!(
        "(Verify) Device signature verified successfully for {}",
        att.subject.as_str()
    );

    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_core::signing::{DidResolverError, ResolvedDid};
    use auths_verifier::AttestationBuilder;

    struct StubResolver;
    impl DidResolver for StubResolver {
        fn resolve(&self, did: &str) -> Result<ResolvedDid, DidResolverError> {
            Err(DidResolverError::InvalidDidKey(format!("stub: {}", did)))
        }
    }

    fn base_attestation() -> Attestation {
        AttestationBuilder::default()
            .rid("test")
            .issuer("did:keri:Estub")
            .subject("did:key:zDevice")
            .build()
    }

    #[test]
    fn max_age_none_skips_check() {
        let mut att = base_attestation();
        att.timestamp = Some(Utc::now() - Duration::days(365));
        let result = verify_with_resolver(Utc::now(), &StubResolver, &att, None);
        // Should pass the timestamp checks and fail on DID resolution (not max_age)
        assert!(matches!(
            result,
            Err(AttestationError::DidResolutionError(_))
        ));
    }

    #[test]
    fn max_age_rejects_old_attestation() {
        let now = Utc::now();
        let mut att = base_attestation();
        att.timestamp = Some(now - Duration::hours(2));
        let result = verify_with_resolver(now, &StubResolver, &att, Some(Duration::hours(1)));
        match result {
            Err(AttestationError::AttestationTooOld { age_secs, max_secs }) => {
                assert!(age_secs >= 7200);
                assert_eq!(max_secs, 3600);
            }
            other => panic!("Expected AttestationTooOld, got {:?}", other),
        }
    }

    #[test]
    fn max_age_accepts_fresh_attestation() {
        let now = Utc::now();
        let mut att = base_attestation();
        att.timestamp = Some(now - Duration::minutes(30));
        let result = verify_with_resolver(now, &StubResolver, &att, Some(Duration::hours(1)));
        // Should pass max_age and fail on DID resolution
        assert!(matches!(
            result,
            Err(AttestationError::DidResolutionError(_))
        ));
    }

    #[test]
    fn max_age_skips_when_no_timestamp() {
        let att = base_attestation(); // timestamp is None
        let result =
            verify_with_resolver(Utc::now(), &StubResolver, &att, Some(Duration::hours(1)));
        // No timestamp → max_age check skipped, fails on DID resolution
        assert!(matches!(
            result,
            Err(AttestationError::DidResolutionError(_))
        ));
    }
}
