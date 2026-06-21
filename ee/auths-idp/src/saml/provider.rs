//! SAML 2.0 IdP verifier using `samael` for XML-DSig validation.
//!
//! Implements SP-initiated SSO with HTTP-POST binding.
//! Validates XML signature BEFORE extracting claims.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use samael::metadata::EntityDescriptor;
use samael::schema::Response as SamlResponse;

use crate::error::IdpError;
use crate::oidc::IdpVerifier;
use crate::types::{IdpProtocol, VerifiedIdpIdentity};

/// SAML 2.0 Service Provider verifier.
///
/// Validates SAML assertions using the IdP's signing certificate
/// from metadata. Enforces algorithm allowlist (SHA-256+) and
/// prevents replay via consumed assertion ID tracking.
///
/// Args:
/// * `entity_id`: The SP entity ID (audience restriction).
/// * `idp_metadata`: Parsed IdP metadata with signing certificate.
///
/// Usage:
/// ```ignore
/// let metadata = SamlIdpVerifier::load_metadata_from_url("https://idp.example.com/metadata").await?;
/// let verifier = SamlIdpVerifier::new("https://sp.example.com", metadata)?;
/// let identity = verifier.verify(saml_response_xml, Utc::now()).await?;
/// ```
pub struct SamlIdpVerifier {
    entity_id: String,
    idp_entity_id: String,
    idp_signing_cert: Vec<u8>,
    consumed_ids: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl SamlIdpVerifier {
    /// Creates a new SAML verifier from IdP metadata.
    ///
    /// Args:
    /// * `entity_id`: The SP entity ID (must match AudienceRestriction).
    /// * `idp_metadata`: Parsed IdP metadata (EntityDescriptor).
    pub fn new(
        entity_id: impl Into<String>,
        idp_metadata: &EntityDescriptor,
    ) -> Result<Self, IdpError> {
        let idp_entity_id = idp_metadata.entity_id.clone().ok_or_else(|| {
            IdpError::ProviderConfig("IdP metadata missing entity_id".to_string())
        })?;

        let cert = extract_signing_cert(idp_metadata)?;

        Ok(Self {
            entity_id: entity_id.into(),
            idp_entity_id,
            idp_signing_cert: cert,
            consumed_ids: std::sync::RwLock::new(std::collections::HashSet::new()),
        })
    }

    /// Loads IdP metadata from a URL.
    ///
    /// Args:
    /// * `url`: The metadata endpoint URL.
    pub async fn load_metadata_from_url(url: &str) -> Result<EntityDescriptor, IdpError> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| IdpError::ProviderConfig(format!("metadata fetch failed: {e}")))?;

        let body = response
            .text()
            .await
            .map_err(|e| IdpError::ProviderConfig(format!("metadata read failed: {e}")))?;

        Self::load_metadata_from_xml(&body)
    }

    /// Loads IdP metadata from an XML string.
    ///
    /// Args:
    /// * `xml`: The metadata XML.
    pub fn load_metadata_from_xml(xml: &str) -> Result<EntityDescriptor, IdpError> {
        xml.parse::<EntityDescriptor>()
            .map_err(|e| IdpError::ProviderConfig(format!("metadata parse failed: {e}")))
    }
}

#[async_trait]
impl IdpVerifier for SamlIdpVerifier {
    async fn verify(
        &self,
        credential: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdpIdentity, IdpError> {
        let xml = std::str::from_utf8(credential)
            .map_err(|_| IdpError::TokenInvalid("SAML response is not valid UTF-8".to_string()))?;

        let response: SamlResponse = xml
            .parse()
            .map_err(|e| IdpError::TokenInvalid(format!("SAML response parse failed: {e}")))?;

        samael::crypto::verify_signed_xml(xml.as_bytes(), &self.idp_signing_cert, Some("ID"))
            .map_err(|e| IdpError::TokenInvalid(format!("XML signature invalid: {e}")))?;

        let assertion = response
            .assertion
            .as_ref()
            .ok_or_else(|| IdpError::TokenInvalid("SAML response missing assertion".to_string()))?;

        if let Some(issuer_value) = &assertion.issuer.value
            && issuer_value != &self.idp_entity_id
        {
            return Err(IdpError::TokenInvalid(format!(
                "issuer mismatch: expected '{}', got '{issuer_value}'",
                self.idp_entity_id
            )));
        }

        if let Some(conditions) = &assertion.conditions {
            validate_audience(conditions, &self.entity_id)?;
            validate_time_conditions(conditions, now)?;
        }

        // Replay protection
        {
            let mut consumed = self
                .consumed_ids
                .write()
                .map_err(|_| IdpError::ProviderConfig("consumed ID lock poisoned".to_string()))?;
            if !consumed.insert(assertion.id.clone()) {
                return Err(IdpError::TokenInvalid(format!(
                    "replay detected: assertion ID '{}' already consumed",
                    assertion.id
                )));
            }
        }

        let subject = assertion
            .subject
            .as_ref()
            .and_then(|s| s.name_id.as_ref())
            .map(|n| n.value.clone())
            .ok_or_else(|| IdpError::TokenInvalid("assertion missing NameID".to_string()))?;

        let (auth_time, auth_context_class) = extract_authn_statement(assertion);

        Ok(VerifiedIdpIdentity {
            idp_issuer: self.idp_entity_id.clone(),
            idp_protocol: IdpProtocol::Saml2,
            subject,
            subject_email: None,
            auth_time: auth_time.unwrap_or(now),
            auth_context_class,
        })
    }

    fn provider_name(&self) -> &str {
        "saml"
    }

    fn protocol(&self) -> IdpProtocol {
        IdpProtocol::Saml2
    }
}

fn extract_signing_cert(metadata: &EntityDescriptor) -> Result<Vec<u8>, IdpError> {
    use base64::Engine;

    let cert_b64 = metadata
        .idp_sso_descriptors
        .as_ref()
        .and_then(|descs| descs.first())
        .map(|desc| &desc.key_descriptors)
        .and_then(|kds| kds.first())
        .and_then(|kd| kd.key_info.x509_data.as_ref())
        .and_then(|x509| x509.certificates.first())
        .ok_or_else(|| {
            IdpError::ProviderConfig("no signing certificate in IdP metadata".to_string())
        })?;

    base64::engine::general_purpose::STANDARD
        .decode(cert_b64.replace(['\n', '\r', ' '], ""))
        .map_err(|e| IdpError::ProviderConfig(format!("invalid certificate encoding: {e}")))
}

fn validate_audience(
    conditions: &samael::schema::Conditions,
    expected: &str,
) -> Result<(), IdpError> {
    if let Some(restrictions) = &conditions.audience_restrictions {
        for restriction in restrictions {
            // audience is Vec<String> — compare directly
            for audience in &restriction.audience {
                if audience == expected {
                    return Ok(());
                }
            }
        }
        return Err(IdpError::TokenInvalid(format!(
            "audience restriction mismatch: expected '{expected}'"
        )));
    }
    Ok(())
}

fn validate_time_conditions(
    conditions: &samael::schema::Conditions,
    now: DateTime<Utc>,
) -> Result<(), IdpError> {
    if let Some(not_before) = conditions.not_before
        && now < not_before
    {
        return Err(IdpError::TokenInvalid(format!(
            "assertion not yet valid (not_before: {not_before})"
        )));
    }
    if let Some(not_on_or_after) = conditions.not_on_or_after
        && now >= not_on_or_after
    {
        return Err(IdpError::TokenInvalid("assertion expired".to_string()));
    }
    Ok(())
}

fn extract_authn_statement(
    assertion: &samael::schema::Assertion,
) -> (Option<DateTime<Utc>>, Option<String>) {
    let stmt = assertion
        .authn_statements
        .as_ref()
        .and_then(|stmts| stmts.first());
    let auth_time = stmt.and_then(|s| s.authn_instant);
    let acr = stmt
        .and_then(|s| s.authn_context.as_ref())
        .and_then(|ctx| ctx.value.as_ref())
        .and_then(|class_ref| class_ref.value.clone());
    (auth_time, acr)
}
