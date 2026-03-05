//! OIDC token issuer: chain verification + JWT issuance.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use uuid::Uuid;

use crate::audience::{AudienceValidation, validate_audience_format};
use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::jwks::KeyManager;
use crate::token::{
    ExchangeRequest, OidcClaims, TokenResponse, WitnessQuorumClaim, extract_keri_prefix,
};

/// Clock function type: returns current Unix timestamp in seconds.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Issues OIDC JWTs after verifying KERI attestation chains.
pub struct OidcIssuer {
    encoding_key: EncodingKey,
    kid: String,
    issuer_url: String,
    default_audience: Option<String>,
    allowed_audiences: Option<Vec<String>>,
    default_ttl_secs: u64,
    max_ttl_secs: u64,
    audience_validation: AudienceValidation,
    clock: ClockFn,
}

impl OidcIssuer {
    /// Create a new issuer from config and key manager using the system clock.
    #[allow(clippy::disallowed_methods)]
    pub fn new(config: &BridgeConfig, key_manager: &KeyManager) -> Result<Self, BridgeError> {
        Self::new_with_clock(
            config,
            key_manager,
            Arc::new(|| chrono::Utc::now().timestamp() as u64),
        )
    }

    /// Create a new issuer with an injectable clock function.
    pub fn new_with_clock(
        config: &BridgeConfig,
        key_manager: &KeyManager,
        clock: ClockFn,
    ) -> Result<Self, BridgeError> {
        let encoding_key = EncodingKey::from_rsa_pem(key_manager.private_key_pem())
            .map_err(|e| BridgeError::KeyError(format!("failed to create encoding key: {e}")))?;

        Ok(Self {
            encoding_key,
            kid: key_manager.jwk.kid.clone(),
            issuer_url: config.issuer_url.clone(),
            default_audience: config.default_audience.clone(),
            allowed_audiences: config.allowed_audiences.clone(),
            default_ttl_secs: config.default_ttl_secs,
            max_ttl_secs: config.max_ttl_secs,
            audience_validation: config.audience_validation,
            clock,
        })
    }

    /// Exchange an attestation chain for an OIDC JWT.
    ///
    /// Args:
    /// * `request`: The exchange request containing the attestation chain.
    /// * `workload_policy`: Optional compiled policy to evaluate before issuance (oidc-policy feature).
    /// * `github_cross_ref`: Optional GitHub OIDC cross-reference result (github-oidc feature).
    ///
    /// Usage:
    /// ```ignore
    /// let response = issuer.exchange(&request, None, None)?;
    /// ```
    pub async fn exchange(
        &self,
        request: &ExchangeRequest,
        #[cfg(feature = "oidc-trust")] trust_registry: Option<&auths_policy::TrustRegistry>,
        #[cfg(feature = "oidc-policy")] workload_policy: Option<&auths_policy::CompiledPolicy>,
        #[cfg(feature = "github-oidc")] github_cross_ref: Option<
            &crate::cross_reference::CrossReferenceResult,
        >,
    ) -> Result<TokenResponse, BridgeError> {
        // 1. Decode hex root public key
        let root_pk = hex::decode(&request.root_public_key).map_err(|e| {
            BridgeError::InvalidRootKey(format!("failed to decode hex public key: {e}"))
        })?;

        // 2. Determine and validate audience
        let audience = self.resolve_audience(request)?;
        let audience_kind = validate_audience_format(&audience, &self.audience_validation)?;

        // 3. Determine and validate TTL
        let ttl_secs = self.resolve_ttl(request)?;

        // 4. Verify the attestation chain
        let report = self.verify_chain(request, &root_pk).await?;

        // 5. Check report validity
        if !report.is_valid() {
            return Err(BridgeError::ChainVerificationFailed(format!(
                "verification status: {:?}",
                report.status
            )));
        }

        // 6. Extract subject from chain[0].issuer
        let chain = &request.attestation_chain;
        let subject = chain
            .first()
            .map(|a| a.issuer.to_string())
            .unwrap_or_default();

        // 7. Extract capabilities from last attestation
        let chain_granted: Vec<String> = chain
            .last()
            .map(|a| {
                a.capabilities
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect()
            })
            .unwrap_or_default();

        // 7.5. Trust registry: narrow capabilities and cap TTL
        #[cfg(feature = "oidc-trust")]
        let (chain_granted, ttl_secs) = if let Some(registry) = trust_registry {
            let provider = request.provider_issuer.as_deref().ok_or_else(|| {
                BridgeError::InvalidRequest(
                    "provider_issuer is required when trust registry is configured".into(),
                )
            })?;

            let entry =
                registry
                    .lookup(provider)
                    .ok_or_else(|| BridgeError::ProviderNotTrusted {
                        provider: provider.to_string(),
                    })?;

            if let Some(ref repo) = request.repository
                && !entry.repo_allowed(repo)
            {
                return Err(BridgeError::RepositoryNotAllowed {
                    repo: repo.clone(),
                    provider: provider.to_string(),
                });
            }

            let narrowed: Vec<String> = chain_granted
                .iter()
                .filter(|c| {
                    entry
                        .allowed_capabilities
                        .iter()
                        .any(|a| a.as_str() == c.as_str())
                })
                .cloned()
                .collect();

            if narrowed.is_empty() && !chain_granted.is_empty() {
                return Err(BridgeError::CapabilityNotAllowed {
                    requested: chain_granted,
                    allowed: entry
                        .allowed_capabilities
                        .iter()
                        .map(|c| c.as_str().to_string())
                        .collect(),
                });
            }

            let capped_ttl = std::cmp::min(ttl_secs, entry.max_token_ttl_seconds);
            (narrowed, capped_ttl)
        } else {
            (chain_granted, ttl_secs)
        };

        // 7.6. Apply scope-down
        let capabilities =
            Self::scope_capabilities(&chain_granted, request.requested_capabilities.as_deref())?;

        // 8. Build claims
        let now = (self.clock)();
        let keri_prefix = extract_keri_prefix(&subject);

        let witness_quorum = report.witness_quorum.as_ref().map(|wq| WitnessQuorumClaim {
            required: wq.required,
            verified: wq.verified,
        });

        #[cfg(feature = "github-oidc")]
        let (gh_actor, gh_repo) = github_cross_ref
            .map(|cr| (Some(cr.actor.clone()), Some(cr.repository.clone())))
            .unwrap_or((None, None));

        #[allow(clippy::disallowed_methods)]
        let jti = Uuid::new_v4().to_string();

        let claims = OidcClaims {
            iss: self.issuer_url.clone(),
            sub: subject.clone(),
            aud: audience,
            exp: now + ttl_secs,
            iat: now,
            jti,
            keri_prefix,
            target_provider: audience_kind.provider_name().map(String::from),
            capabilities,
            witness_quorum,
            #[cfg(feature = "github-oidc")]
            github_actor: gh_actor,
            #[cfg(feature = "github-oidc")]
            github_repository: gh_repo,
            #[cfg(not(feature = "github-oidc"))]
            github_actor: None,
            #[cfg(not(feature = "github-oidc"))]
            github_repository: None,
        };

        // 9. Evaluate workload policy (if configured)
        #[cfg(feature = "oidc-policy")]
        if let Some(policy) = workload_policy {
            // INVARIANT: u64 epoch seconds always fits in DateTime (overflows at ~292 billion years)
            #[allow(clippy::expect_used)]
            let now_dt = chrono::DateTime::from_timestamp(now as i64, 0)
                .expect("u64 epoch seconds always fits in DateTime");
            let ctx = crate::policy_adapter::build_eval_context_from_oidc(&claims, now_dt)?;
            let decision = auths_policy::evaluate_strict(policy, &ctx);
            if decision.outcome != auths_policy::Outcome::Allow {
                tracing::info!(reason = %decision.message, "auths.exchange.policy_denied");
                return Err(BridgeError::PolicyDenied(decision.message));
            }
        }

        // 10. Sign JWT with RS256
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| BridgeError::SigningFailed(format!("JWT encoding failed: {e}")))?;

        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: ttl_secs,
            subject,
        })
    }

    fn resolve_audience(&self, request: &ExchangeRequest) -> Result<String, BridgeError> {
        let audience = request
            .audience
            .as_deref()
            .or(self.default_audience.as_deref())
            .unwrap_or("auths")
            .to_string();

        if let Some(ref allowed) = self.allowed_audiences
            && !allowed.contains(&audience)
        {
            return Err(BridgeError::AudienceNotAllowed(audience));
        }

        Ok(audience)
    }

    /// Scope capabilities: intersect chain-granted with requested (if any).
    fn scope_capabilities(
        chain_granted: &[String],
        requested: Option<&[String]>,
    ) -> Result<Vec<String>, BridgeError> {
        let Some(requested) = requested else {
            // No scope-down requested: return all chain-granted capabilities
            return Ok(chain_granted.to_vec());
        };

        if requested.is_empty() {
            return Err(BridgeError::InsufficientCapabilities {
                requested: vec![],
                granted: chain_granted.to_vec(),
            });
        }

        let intersection: Vec<String> = requested
            .iter()
            .filter(|r| chain_granted.contains(r))
            .cloned()
            .collect();

        if intersection.is_empty() {
            return Err(BridgeError::InsufficientCapabilities {
                requested: requested.to_vec(),
                granted: chain_granted.to_vec(),
            });
        }

        Ok(intersection)
    }

    fn resolve_ttl(&self, request: &ExchangeRequest) -> Result<u64, BridgeError> {
        let ttl = request.ttl_secs.unwrap_or(self.default_ttl_secs);
        if ttl > self.max_ttl_secs {
            return Err(BridgeError::TtlExceedsMax {
                requested: ttl,
                max: self.max_ttl_secs,
            });
        }
        Ok(ttl)
    }

    async fn verify_chain(
        &self,
        request: &ExchangeRequest,
        root_pk: &[u8],
    ) -> Result<auths_verifier::VerificationReport, BridgeError> {
        let chain = &request.attestation_chain;

        if chain.is_empty() {
            return Err(BridgeError::InvalidChain("empty attestation chain".into()));
        }

        // If witness data is provided, use witness-aware verification
        if let (Some(receipts), Some(keys), Some(threshold)) = (
            &request.witness_receipts,
            &request.witness_keys,
            request.witness_threshold,
        ) {
            let witness_keys: Result<Vec<(String, Vec<u8>)>, BridgeError> = keys
                .iter()
                .map(|k| {
                    let pk = hex::decode(&k.public_key_hex).map_err(|e| {
                        BridgeError::InvalidRequest(format!(
                            "invalid witness key hex for {}: {e}",
                            k.did
                        ))
                    })?;
                    Ok((k.did.clone(), pk))
                })
                .collect();
            let witness_keys = witness_keys?;

            let config = auths_verifier::WitnessVerifyConfig {
                receipts,
                witness_keys: &witness_keys,
                threshold,
            };

            auths_verifier::verify_chain_with_witnesses(chain, root_pk, &config)
                .await
                .map_err(|e| {
                    BridgeError::ChainVerificationFailed(format!("verification error: {e}"))
                })
        } else {
            auths_verifier::verify_chain(chain, root_pk)
                .await
                .map_err(|e| {
                    BridgeError::ChainVerificationFailed(format!("verification error: {e}"))
                })
        }
    }
}
