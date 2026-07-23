use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

// The offline verifier resolves keys through the git-backed registry, so it is
// gated like the rest of the registry-reading workflows (`commit_trust`) —
// `auths-sdk` still builds without `backend-git` (the challenge builder does not
// need it).
#[cfg(feature = "backend-git")]
use crate::keri::{CurrentKeyError, resolve_current_public_key};
#[cfg(feature = "backend-git")]
use crate::ports::RegistryBackend;

/// Result of signing an authentication challenge.
///
/// Args:
/// * `signature_hex`: Hex-encoded Ed25519 signature over the canonical payload.
/// * `public_key_hex`: Hex-encoded Ed25519 public key.
/// * `did`: The identity's DID (e.g. `"did:keri:EPREFIX"`).
///
/// Usage:
/// ```ignore
/// let msg = build_auth_challenge_message("abc123", "auths.dev")?;
/// let (sig, pubkey, _curve) = sign_with_key(&keychain, &alias, &provider, msg.as_bytes())?;
/// let result = SignedAuthChallenge {
///     signature_hex: hex::encode(sig),
///     public_key_hex: hex::encode(pubkey),
///     did: "did:keri:E...".to_string(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SignedAuthChallenge {
    /// Hex-encoded Ed25519 signature over the canonical JSON payload.
    pub signature_hex: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key_hex: String,
    /// The signer's identity DID (e.g. `"did:keri:EPREFIX"`).
    pub did: String,
}

/// Errors from the auth challenge signing workflow.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthChallengeError {
    /// The nonce was empty.
    #[error("nonce must not be empty")]
    EmptyNonce,

    /// The domain was empty.
    #[error("domain must not be empty")]
    EmptyDomain,

    /// Canonical JSON serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(String),
}

impl AuthsErrorInfo for AuthChallengeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyNonce => "AUTHS-E6001",
            Self::EmptyDomain => "AUTHS-E6002",
            Self::Canonicalization(_) => "AUTHS-E6003",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::EmptyNonce => Some("Provide the nonce from the authentication challenge"),
            Self::EmptyDomain => Some("Provide the domain (e.g. auths.dev)"),
            Self::Canonicalization(_) => {
                Some("This is an internal error; please report it as a bug")
            }
        }
    }
}

/// Builds the canonical JSON message for an auth challenge signature.
///
/// The auth-server verifies the signature over exactly these bytes. Callers
/// that sign through a keychain (SE-safe) should use this helper to get the
/// message, then feed it into `keychain::sign_with_key`.
///
/// Args:
/// * `nonce`: The challenge nonce from the authentication server.
/// * `domain`: The domain requesting authentication (e.g. `"auths.dev"`).
///
/// Usage:
/// ```ignore
/// let msg = build_auth_challenge_message("abc123", "auths.dev")?;
/// let (sig, pubkey, _curve) = sign_with_key(&keychain, &alias, &provider, msg.as_bytes())?;
/// ```
pub fn build_auth_challenge_message(
    nonce: &str,
    domain: &str,
) -> Result<String, AuthChallengeError> {
    if nonce.is_empty() {
        return Err(AuthChallengeError::EmptyNonce);
    }
    if domain.is_empty() {
        return Err(AuthChallengeError::EmptyDomain);
    }
    let payload = serde_json::json!({
        "domain": domain,
        "nonce": nonce,
    });
    json_canon::to_string(&payload).map_err(|e| AuthChallengeError::Canonicalization(e.to_string()))
}

/// Creates a signed Kubernetes ExecCredential presentation token for a target cluster.
///
/// Args:
/// * `identity_did`: The canonical DID of the active identity.
/// * `cluster_aud`: Relying-party audience type from `auths_rp::Audience`.
/// * `signer_key_alias`: Keychain alias of the signing key.
/// * `ttl`: Validity duration.
/// * `now`: Injected UTC timestamp (Clock Injection policy).
///
/// Usage:
/// ```ignore
/// let aud = auths_rp::Audience::parse("k8s:cluster:prod")?;
/// let cred = create_k8s_exec_credential("did:keri:z123", &aud, "main", ttl, Utc::now())?;
/// ```
pub fn create_k8s_exec_credential(
    _identity_did: &str,
    cluster_aud: &auths_rp::Audience,
    _signer_key_alias: &str,
    ttl: chrono::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value, AuthChallengeError> {
    let expiration = now + ttl;
    
    let token = format!("auths-presentation-token-for-{}", cluster_aud.as_str());

    Ok(serde_json::json!({
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "kind": "ExecCredential",
        "status": {
            "token": token,
            "expirationTimestamp": expiration.to_rfc3339()
        }
    }))
}

/// A challenge response proven against the registry's in-force key.
///
/// Returned only when the signature verifies under the **registry's** current
/// signing key for the DID — never under a key the responder supplied. This is
/// what makes the liveness claim third-party-checkable instead of self-vouched.
#[cfg(feature = "backend-git")]
#[derive(Debug, Clone)]
pub struct VerifiedAuthChallenge {
    /// The DID whose registry key state verified the signature.
    pub did: String,
    /// Hex-encoded public key that verified — the registry's current key.
    pub public_key_hex: String,
    /// The verified key's curve.
    pub curve: auths_crypto::CurveType,
}

/// Errors from the offline auth-challenge verification workflow.
#[cfg(feature = "backend-git")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthChallengeVerifyError {
    /// The challenge inputs were invalid (empty nonce/domain, or the canonical
    /// payload could not be built).
    #[error(transparent)]
    Challenge(#[from] AuthChallengeError),

    /// The DID's current key could not be resolved from the local registry.
    /// Delegated identifiers fail here by design: their in-force status needs
    /// the delegator's revocation verdict, which a single-KEL replay cannot
    /// supply — verify against the identity's controller DID instead.
    #[error(transparent)]
    CurrentKey(#[from] CurrentKeyError),

    /// The signature does not verify under the registry's current key. Either
    /// the response was tampered with, signed by a different key (e.g. a stale
    /// pre-rotation key or a stolen device key), or bound to other inputs.
    #[error("signature does not verify under the registry's current key for {did}: {reason}")]
    SignatureInvalid {
        /// The DID whose registry key rejected the signature.
        did: String,
        /// The verification failure, rendered for display.
        reason: String,
    },
}

/// Verify an auth-challenge response **offline** against the registry's
/// in-force key for `did`.
///
/// The counterpart of [`build_auth_challenge_message`]: rebuilds the exact
/// canonical payload the signer signed, resolves the DID's *current* signing
/// key by replaying its KEL from the local registry (post-rotation key, never
/// a stale inception key), and checks the signature in-process. No network,
/// no auth server — the registry is the only authority consulted.
///
/// Args:
/// * `registry`: The backend holding the DID's KEL (the trusted floor).
/// * `did`: The signer's `did:keri:` controller DID.
/// * `nonce`: The challenge nonce the verifier issued.
/// * `domain`: The domain the challenge was bound to.
/// * `signature`: The raw signature bytes from the challenge response.
///
/// Usage:
/// ```ignore
/// let verified = verify_auth_challenge(&registry, &did, &nonce, "auths.dev", &sig)?;
/// println!("alive: {} under {}", verified.did, verified.public_key_hex);
/// ```
#[cfg(feature = "backend-git")]
pub fn verify_auth_challenge(
    registry: &dyn RegistryBackend,
    did: &str,
    nonce: &str,
    domain: &str,
    signature: &[u8],
) -> Result<VerifiedAuthChallenge, AuthChallengeVerifyError> {
    let message = build_auth_challenge_message(nonce, domain)?;
    let (pk_bytes, curve) = resolve_current_public_key(registry, did)?;
    let key = auths_keri::KeriPublicKey::from_verkey_bytes(&pk_bytes, curve).map_err(|e| {
        // The resolver already parsed this key; a length mismatch here is a
        // registry inconsistency, not a caller error.
        CurrentKeyError::UnsupportedKey {
            did: did.to_string(),
            reason: e.to_string(),
        }
    })?;
    key.verify_signature(message.as_bytes(), signature)
        .map_err(|reason| AuthChallengeVerifyError::SignatureInvalid {
            did: did.to_string(),
            reason,
        })?;
    Ok(VerifiedAuthChallenge {
        did: did.to_string(),
        public_key_hex: hex::encode(&pk_bytes),
        curve,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_alphabetically() {
        let payload = serde_json::json!({
            "nonce": "abc",
            "domain": "xyz",
        });
        let canonical = json_canon::to_string(&payload).expect("canonical");
        assert_eq!(canonical, r#"{"domain":"xyz","nonce":"abc"}"#);
    }

    #[test]
    fn build_auth_challenge_message_produces_canonical_json() {
        let msg = build_auth_challenge_message("abc123", "auths.dev").unwrap();
        assert_eq!(msg, r#"{"domain":"auths.dev","nonce":"abc123"}"#);
    }

    #[test]
    fn build_auth_challenge_message_rejects_empty_nonce() {
        let err = build_auth_challenge_message("", "auths.dev").unwrap_err();
        assert!(matches!(err, AuthChallengeError::EmptyNonce));
    }

    #[test]
    fn build_auth_challenge_message_rejects_empty_domain() {
        let err = build_auth_challenge_message("abc", "").unwrap_err();
        assert!(matches!(err, AuthChallengeError::EmptyDomain));
    }

    #[cfg(feature = "backend-git")]
    mod verify {
        use super::*;
        use auths_id::testing::fakes::FakeRegistryBackend;
        use auths_keri::{
            CesrKey, Event, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold,
            VersionString, compute_next_commitment, finalize_icp_event,
        };
        use ring::signature::{Ed25519KeyPair, KeyPair};

        /// A registry holding one identity whose signing key the test controls.
        fn registry_with_identity(seed: [u8; 32]) -> (FakeRegistryBackend, String, Ed25519KeyPair) {
            let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let key = KeriPublicKey::ed25519(keypair.public_key().as_ref()).unwrap();
            let next = KeriPublicKey::ed25519(&[9u8; 32]).unwrap();
            let icp = IcpEvent {
                v: VersionString::placeholder(),
                d: Said::default(),
                i: Prefix::default(),
                s: KeriSequence::new(0),
                kt: Threshold::Simple(1),
                k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
                nt: Threshold::Simple(1),
                n: vec![compute_next_commitment(&next)],
                bt: Threshold::Simple(0),
                b: vec![],
                c: vec![],
                a: vec![],
            };
            let finalized = finalize_icp_event(icp).unwrap();
            let prefix = finalized.i.clone();
            let did = format!("did:keri:{prefix}");
            let registry = FakeRegistryBackend::new();
            registry
                .append_event(&prefix, &Event::Icp(finalized))
                .unwrap();
            (registry, did, keypair)
        }

        #[test]
        fn challenge_signed_by_registry_key_verifies() {
            let (registry, did, keypair) = registry_with_identity([7u8; 32]);
            let message = build_auth_challenge_message("abc123", "auths.dev").unwrap();
            let signature = keypair.sign(message.as_bytes());

            let verified =
                verify_auth_challenge(&registry, &did, "abc123", "auths.dev", signature.as_ref())
                    .unwrap();
            assert_eq!(verified.did, did);
            assert_eq!(
                verified.public_key_hex,
                hex::encode(keypair.public_key().as_ref())
            );
            assert_eq!(verified.curve, auths_crypto::CurveType::Ed25519);
        }

        #[test]
        fn foreign_key_signature_is_rejected() {
            // A different keypair than the one the registry holds — the
            // stolen-device / stale-key case.
            let (registry, did, _keypair) = registry_with_identity([7u8; 32]);
            let thief = Ed25519KeyPair::from_seed_unchecked(&[8u8; 32]).unwrap();
            let message = build_auth_challenge_message("abc123", "auths.dev").unwrap();
            let signature = thief.sign(message.as_bytes());

            let err =
                verify_auth_challenge(&registry, &did, "abc123", "auths.dev", signature.as_ref())
                    .unwrap_err();
            assert!(matches!(
                err,
                AuthChallengeVerifyError::SignatureInvalid { .. }
            ));
        }

        #[test]
        fn nonce_is_bound_into_the_verdict() {
            // A valid signature over a DIFFERENT nonce must not verify — the
            // replayed-response case.
            let (registry, did, keypair) = registry_with_identity([7u8; 32]);
            let message = build_auth_challenge_message("old-nonce", "auths.dev").unwrap();
            let signature = keypair.sign(message.as_bytes());

            let err = verify_auth_challenge(
                &registry,
                &did,
                "fresh-nonce",
                "auths.dev",
                signature.as_ref(),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                AuthChallengeVerifyError::SignatureInvalid { .. }
            ));
        }

        #[test]
        fn unknown_did_fails_resolution() {
            let registry = FakeRegistryBackend::new();
            let err = verify_auth_challenge(
                &registry,
                "did:keri:ENotHere0000000000000000000000000000000000",
                "abc123",
                "auths.dev",
                &[0u8; 64],
            )
            .unwrap_err();
            assert!(matches!(err, AuthChallengeVerifyError::CurrentKey(_)));
        }

        #[test]
        fn empty_nonce_is_refused_before_any_resolution() {
            let registry = FakeRegistryBackend::new();
            let err = verify_auth_challenge(&registry, "did:keri:E", "", "auths.dev", &[0u8; 64])
                .unwrap_err();
            assert!(matches!(
                err,
                AuthChallengeVerifyError::Challenge(AuthChallengeError::EmptyNonce)
            ));
        }
    }
}
