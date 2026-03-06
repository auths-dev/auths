//! OIDC token issuer: chain verification + JWT issuance.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::audience::{AudienceValidation, validate_audience_format};
use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::jwks::KeyManager;
use crate::token::{
    ActorClaim, ExchangeRequest, OAuthErrorResponse, OidcClaims, TokenExchangeRequest,
    TokenExchangeResponse, TokenResponse, WitnessQuorumClaim, build_act_claim, extract_keri_prefix,
};

/// Clock function type: returns current Unix timestamp in seconds.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// RFC 8693 grant type URI.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 JWT token type URI.
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

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
    max_delegation_depth: u32,
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
            max_delegation_depth: config.max_delegation_depth,
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
        let root_pk = hex::decode(&request.root_public_key).map_err(|e| {
            BridgeError::InvalidRootKey(format!("failed to decode hex public key: {e}"))
        })?;

        let audience = self.resolve_audience(request)?;
        let audience_kind = validate_audience_format(&audience, &self.audience_validation)?;
        let ttl_secs = self.resolve_ttl(request)?;
        let report = self.verify_chain(request, &root_pk).await?;

        if !report.is_valid() {
            return Err(BridgeError::ChainVerificationFailed(format!(
                "verification status: {:?}",
                report.status
            )));
        }

        let chain = &request.attestation_chain;
        let subject = chain
            .first()
            .map(|a| a.issuer.to_string())
            .unwrap_or_default();

        let chain_granted: Vec<String> = chain
            .last()
            .map(|a| {
                a.capabilities
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect()
            })
            .unwrap_or_default();

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

        let capabilities =
            Self::scope_capabilities(&chain_granted, request.requested_capabilities.as_deref())?;

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

        let act = build_act_claim(chain);

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
            act,
            spiffe_id: None,
        };

        #[cfg(feature = "oidc-policy")]
        if let Some(policy) = workload_policy {
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

    /// RFC 8693 token exchange: exchange a subject_token (+ optional actor_token) for a new JWT.
    ///
    /// Args:
    /// * `request`: The form-encoded token exchange request.
    /// * `decoding_key`: RSA public key for self-verification of subject_token.
    ///
    /// Usage:
    /// ```ignore
    /// let response = issuer.exchange_token(&request, &decoding_key)?;
    /// ```
    pub fn exchange_token(
        &self,
        request: &TokenExchangeRequest,
        decoding_key: &DecodingKey,
    ) -> Result<TokenExchangeResponse, OAuthErrorResponse> {
        if request.grant_type != GRANT_TYPE_TOKEN_EXCHANGE {
            return Err(OAuthErrorResponse {
                error: "unsupported_grant_type".into(),
                error_description: format!("expected {GRANT_TYPE_TOKEN_EXCHANGE}"),
            });
        }

        if request.subject_token_type != TOKEN_TYPE_JWT {
            return Err(OAuthErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("subject_token_type must be {TOKEN_TYPE_JWT}"),
            });
        }

        // Self-verify the subject_token (issued by this bridge)
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer_url]);
        // Accept any audience for self-issued tokens
        validation.validate_aud = false;

        let subject_data =
            jsonwebtoken::decode::<OidcClaims>(&request.subject_token, decoding_key, &validation)
                .map_err(|e| OAuthErrorResponse {
                error: "invalid_grant".into(),
                error_description: format!("subject_token validation failed: {e}"),
            })?;

        let subject_claims = subject_data.claims;
        let now = (self.clock)();

        // Check subject_token expiry
        if subject_claims.exp <= now {
            return Err(OAuthErrorResponse {
                error: "invalid_grant".into(),
                error_description: "subject_token has expired".into(),
            });
        }

        let remaining_secs = subject_claims.exp - now;

        // Parse requested scope (space-separated capabilities)
        let requested_caps: Option<Vec<String>> = request
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect());

        // Capability intersection
        let capabilities = match requested_caps {
            Some(ref requested) => {
                let intersection: Vec<String> = requested
                    .iter()
                    .filter(|r| subject_claims.capabilities.contains(r))
                    .cloned()
                    .collect();
                if intersection.is_empty() {
                    return Err(OAuthErrorResponse {
                        error: "invalid_scope".into(),
                        error_description: "requested scope not available in subject_token".into(),
                    });
                }
                intersection
            }
            None => subject_claims.capabilities.clone(),
        };

        // Token lifetime: min(max_ttl, remaining_secs)
        let ttl_secs = std::cmp::min(self.max_ttl_secs, remaining_secs);

        // Build actor claim for the exchanged token
        let act = if let Some(ref actor_token_str) = request.actor_token {
            let actor_data =
                jsonwebtoken::decode::<OidcClaims>(actor_token_str, decoding_key, &validation)
                    .map_err(|e| OAuthErrorResponse {
                        error: "invalid_grant".into(),
                        error_description: format!("actor_token validation failed: {e}"),
                    })?;

            let actor_claims = actor_data.claims;

            // Check delegation depth
            let existing_depth = count_act_depth(&subject_claims.act);
            if existing_depth + 1 > self.max_delegation_depth {
                return Err(OAuthErrorResponse {
                    error: "invalid_grant".into(),
                    error_description: format!(
                        "delegation depth {} exceeds max {}",
                        existing_depth + 1,
                        self.max_delegation_depth
                    ),
                });
            }

            // Build nested act: actor acts on behalf, wrapping existing act chain
            Some(ActorClaim {
                sub: actor_claims.sub.clone(),
                signer_type: None,
                act: subject_claims.act.map(Box::new),
            })
        } else {
            subject_claims.act.clone()
        };

        #[allow(clippy::disallowed_methods)]
        let jti = Uuid::new_v4().to_string();

        let new_claims = OidcClaims {
            iss: self.issuer_url.clone(),
            sub: subject_claims.sub.clone(),
            aud: subject_claims.aud.clone(),
            exp: now + ttl_secs,
            iat: now,
            jti,
            keri_prefix: subject_claims.keri_prefix.clone(),
            target_provider: subject_claims.target_provider.clone(),
            capabilities: capabilities.clone(),
            witness_quorum: subject_claims.witness_quorum.clone(),
            github_actor: subject_claims.github_actor.clone(),
            github_repository: subject_claims.github_repository.clone(),
            act,
            spiffe_id: subject_claims.spiffe_id.clone(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let token =
            jsonwebtoken::encode(&header, &new_claims, &self.encoding_key).map_err(|e| {
                OAuthErrorResponse {
                    error: "server_error".into(),
                    error_description: format!("JWT encoding failed: {e}"),
                }
            })?;

        let scope_str = if requested_caps.is_some() {
            Some(capabilities.join(" "))
        } else {
            None
        };

        Ok(TokenExchangeResponse {
            access_token: token,
            issued_token_type: TOKEN_TYPE_JWT.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: ttl_secs,
            scope: scope_str,
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

fn count_act_depth(act: &Option<ActorClaim>) -> u32 {
    match act {
        None => 0,
        Some(a) => 1 + count_act_depth(&a.act.as_deref().cloned()),
    }
}
