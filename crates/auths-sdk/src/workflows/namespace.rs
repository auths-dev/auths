//! Namespace management workflows: claim, delegate, transfer, and lookup.
//!
//! These workflows build transparency log entries for namespace operations,
//! canonicalize and sign them, and return the signed payload ready for
//! submission to a registry server at `/v1/log/entries`.

use chrono::{DateTime, Utc};

use auths_core::ports::namespace::{
    Ecosystem, NamespaceOwnershipProof, NamespaceVerifier, NamespaceVerifyError, PackageName,
    PlatformContext, VerificationChallenge,
};
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_transparency::entry::{EntryBody, EntryContent, EntryType};
use auths_verifier::CanonicalDid;
use auths_verifier::types::IdentityDID;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

/// Errors from namespace management workflows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NamespaceError {
    /// The namespace is already claimed by another identity.
    #[error("namespace '{ecosystem}/{package_name}' is already claimed")]
    AlreadyClaimed {
        /// The package ecosystem (e.g. "npm", "crates.io").
        ecosystem: String,
        /// The package name within the ecosystem.
        package_name: String,
    },

    /// The namespace was not found in the registry.
    #[error("namespace '{ecosystem}/{package_name}' not found")]
    NotFound {
        /// The package ecosystem.
        ecosystem: String,
        /// The package name.
        package_name: String,
    },

    /// The caller is not authorized to manage this namespace.
    #[error("not authorized to manage namespace '{ecosystem}/{package_name}'")]
    Unauthorized {
        /// The package ecosystem.
        ecosystem: String,
        /// The package name.
        package_name: String,
    },

    /// The ecosystem string is invalid.
    #[error("invalid ecosystem: {0}")]
    InvalidEcosystem(String),

    /// The package name string is invalid.
    #[error("invalid package name: {0}")]
    InvalidPackageName(String),

    /// A network operation failed.
    #[error("network error: {0}")]
    NetworkError(String),

    /// A signing operation failed.
    #[error("signing error: {0}")]
    SigningError(String),

    /// Serialization or canonicalization failed.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Namespace verification failed (wraps port-level error).
    #[error("verification failed: {0}")]
    VerificationFailed(#[from] NamespaceVerifyError),
}

/// Command to delegate namespace authority to another identity.
///
/// Args:
/// * `ecosystem`: Package ecosystem identifier.
/// * `package_name`: Package name within the ecosystem.
/// * `delegate_did`: DID of the identity receiving delegation.
/// * `registry_url`: Base URL of the registry server.
///
/// Usage:
/// ```ignore
/// let cmd = DelegateNamespaceCommand {
///     ecosystem: "npm".into(),
///     package_name: "my-package".into(),
///     delegate_did: "did:keri:Edelegate...".into(),
///     registry_url: "https://registry.example.com".into(),
/// };
/// ```
pub struct DelegateNamespaceCommand {
    /// Package ecosystem identifier.
    pub ecosystem: String,
    /// Package name within the ecosystem.
    pub package_name: String,
    /// DID of the identity receiving delegation.
    pub delegate_did: String,
    /// Base URL of the registry server.
    pub registry_url: String,
}

/// Command to transfer namespace ownership to a new identity.
///
/// Args:
/// * `ecosystem`: Package ecosystem identifier.
/// * `package_name`: Package name within the ecosystem.
/// * `new_owner_did`: DID of the identity receiving ownership.
/// * `registry_url`: Base URL of the registry server.
///
/// Usage:
/// ```ignore
/// let cmd = TransferNamespaceCommand {
///     ecosystem: "npm".into(),
///     package_name: "my-package".into(),
///     new_owner_did: "did:keri:Enewowner...".into(),
///     registry_url: "https://registry.example.com".into(),
/// };
/// ```
pub struct TransferNamespaceCommand {
    /// Package ecosystem identifier.
    pub ecosystem: String,
    /// Package name within the ecosystem.
    pub package_name: String,
    /// DID of the identity receiving ownership.
    pub new_owner_did: String,
    /// Base URL of the registry server.
    pub registry_url: String,
}

/// Result of a successful namespace claim.
///
/// Args:
/// * `ecosystem`: The claimed ecosystem.
/// * `package_name`: The claimed package name.
/// * `owner_did`: DID of the new owner.
/// * `log_sequence`: Sequence number assigned by the transparency log.
pub struct NamespaceClaimResult {
    /// The claimed ecosystem.
    pub ecosystem: String,
    /// The claimed package name.
    pub package_name: String,
    /// DID of the new owner.
    pub owner_did: String,
    /// Sequence number assigned by the transparency log.
    pub log_sequence: u128,
}

/// Namespace information returned by a lookup.
///
/// Args:
/// * `ecosystem`: The namespace's ecosystem.
/// * `package_name`: The namespace's package name.
/// * `owner_did`: DID of the current owner.
/// * `delegates`: DIDs of identities with delegated authority.
pub struct NamespaceInfo {
    /// The namespace's ecosystem.
    pub ecosystem: String,
    /// The namespace's package name.
    pub package_name: String,
    /// DID of the current owner.
    pub owner_did: String,
    /// DIDs of identities with delegated authority.
    pub delegates: Vec<String>,
}

/// A signed entry ready for submission to the registry.
///
/// Contains the serialized entry content and the base64-encoded actor signature.
/// Submit this to `POST /v1/log/entries` as `{ "content": ..., "actor_sig": "..." }`.
///
/// Args:
/// * `content`: The serialized entry content as a JSON value.
/// * `actor_sig`: Base64-encoded Ed25519 signature over the canonical content.
pub struct SignedEntry {
    /// The serialized entry content as a JSON value.
    pub content: serde_json::Value,
    /// Base64-encoded Ed25519 signature over the canonical content.
    pub actor_sig: String,
}

impl SignedEntry {
    /// Serialize to the JSON body expected by `POST /v1/log/entries`.
    ///
    /// Usage:
    /// ```ignore
    /// let body = signed_entry.to_request_body();
    /// // POST body to registry
    /// ```
    pub fn to_request_body(&self) -> serde_json::Value {
        serde_json::json!({
            "content": self.content,
            "actor_sig": self.actor_sig,
        })
    }
}

fn validate_ecosystem(ecosystem: &str) -> Result<(), NamespaceError> {
    if ecosystem.is_empty() {
        return Err(NamespaceError::InvalidEcosystem(
            "ecosystem must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_package_name(package_name: &str) -> Result<(), NamespaceError> {
    if package_name.is_empty() {
        return Err(NamespaceError::InvalidPackageName(
            "package name must not be empty".into(),
        ));
    }
    Ok(())
}

fn build_and_sign_entry(
    content: &EntryContent,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    signer_alias: &KeyAlias,
) -> Result<SignedEntry, NamespaceError> {
    let canonical_bytes = content
        .canonicalize()
        .map_err(|e| NamespaceError::SerializationError(e.to_string()))?;

    let sig_bytes = signer
        .sign_with_alias(signer_alias, passphrase_provider, &canonical_bytes)
        .map_err(|e| NamespaceError::SigningError(e.to_string()))?;

    let content_value = serde_json::to_value(content)
        .map_err(|e| NamespaceError::SerializationError(e.to_string()))?;

    Ok(SignedEntry {
        content: content_value,
        actor_sig: BASE64.encode(&sig_bytes),
    })
}

/// Build and sign a `NamespaceDelegate` entry.
///
/// Creates an `EntryContent` with a `NamespaceDelegate` body, canonicalizes
/// it, and signs it with the caller's key.
///
/// Args:
/// * `cmd`: The delegate command with ecosystem, package name, delegate DID, and registry URL.
/// * `actor_did`: The DID of the current namespace owner.
/// * `signer`: Signing backend for creating the cryptographic signature.
/// * `passphrase_provider`: Provider for obtaining key decryption passphrases.
/// * `signer_alias`: Keychain alias of the signing key.
///
/// Usage:
/// ```ignore
/// let signed = sign_namespace_delegate(cmd, &actor_did, &signer, provider, &alias)?;
/// ```
pub fn sign_namespace_delegate(
    cmd: &DelegateNamespaceCommand,
    actor_did: &IdentityDID,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    signer_alias: &KeyAlias,
) -> Result<SignedEntry, NamespaceError> {
    validate_ecosystem(&cmd.ecosystem)?;
    validate_package_name(&cmd.package_name)?;

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: delegate_did is from CLI input, validated at presentation boundary
    let delegate_identity = IdentityDID::new_unchecked(&cmd.delegate_did);

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: actor_did is an IdentityDID from storage, always valid
    let canonical_actor = CanonicalDid::new_unchecked(actor_did.as_str());

    let content = EntryContent {
        entry_type: EntryType::NamespaceDelegate,
        body: EntryBody::NamespaceDelegate {
            ecosystem: cmd.ecosystem.clone(),
            package_name: cmd.package_name.clone(),
            delegate_did: delegate_identity,
        },
        actor_did: canonical_actor,
    };

    build_and_sign_entry(&content, signer, passphrase_provider, signer_alias)
}

/// Build and sign a `NamespaceTransfer` entry.
///
/// Creates an `EntryContent` with a `NamespaceTransfer` body, canonicalizes
/// it, and signs it with the caller's key.
///
/// Args:
/// * `cmd`: The transfer command with ecosystem, package name, new owner DID, and registry URL.
/// * `actor_did`: The DID of the current namespace owner.
/// * `signer`: Signing backend for creating the cryptographic signature.
/// * `passphrase_provider`: Provider for obtaining key decryption passphrases.
/// * `signer_alias`: Keychain alias of the signing key.
///
/// Usage:
/// ```ignore
/// let signed = sign_namespace_transfer(cmd, &actor_did, &signer, provider, &alias)?;
/// ```
pub fn sign_namespace_transfer(
    cmd: &TransferNamespaceCommand,
    actor_did: &IdentityDID,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    signer_alias: &KeyAlias,
) -> Result<SignedEntry, NamespaceError> {
    validate_ecosystem(&cmd.ecosystem)?;
    validate_package_name(&cmd.package_name)?;

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: new_owner_did is from CLI input, validated at presentation boundary
    let new_owner_identity = IdentityDID::new_unchecked(&cmd.new_owner_did);

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: actor_did is an IdentityDID from storage, always valid
    let canonical_actor = CanonicalDid::new_unchecked(actor_did.as_str());

    let content = EntryContent {
        entry_type: EntryType::NamespaceTransfer,
        body: EntryBody::NamespaceTransfer {
            ecosystem: cmd.ecosystem.clone(),
            package_name: cmd.package_name.clone(),
            new_owner_did: new_owner_identity,
        },
        actor_did: canonical_actor,
    };

    build_and_sign_entry(&content, signer, passphrase_provider, signer_alias)
}

/// Parse a registry response JSON into a [`NamespaceClaimResult`].
///
/// Args:
/// * `ecosystem`: The claimed ecosystem.
/// * `package_name`: The claimed package name.
/// * `owner_did`: DID of the claiming identity.
/// * `response`: The JSON response body from the registry.
///
/// Usage:
/// ```ignore
/// let result = parse_claim_response("npm", "pkg", "did:keri:E...", &response_json)?;
/// ```
pub fn parse_claim_response(
    ecosystem: &str,
    package_name: &str,
    owner_did: &str,
    response: &serde_json::Value,
) -> NamespaceClaimResult {
    let log_sequence: u128 = response
        .get("sequence")
        .and_then(|v| v.as_u64())
        .map(u128::from)
        .unwrap_or(0);

    NamespaceClaimResult {
        ecosystem: ecosystem.to_string(),
        package_name: package_name.to_string(),
        owner_did: owner_did.to_string(),
        log_sequence,
    }
}

/// Parse a registry lookup response JSON into a [`NamespaceInfo`].
///
/// Args:
/// * `ecosystem`: The queried ecosystem.
/// * `package_name`: The queried package name.
/// * `body`: The JSON response body from the registry.
///
/// Usage:
/// ```ignore
/// let info = parse_lookup_response("npm", "pkg", &response_json);
/// ```
pub fn parse_lookup_response(
    ecosystem: &str,
    package_name: &str,
    body: &serde_json::Value,
) -> NamespaceInfo {
    let owner_did = body
        .get("owner_did")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let delegates = body
        .get("delegates")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    NamespaceInfo {
        ecosystem: ecosystem.to_string(),
        package_name: package_name.to_string(),
        owner_did,
        delegates,
    }
}

/// An in-progress namespace verification session.
///
/// Returned by [`initiate_namespace_claim`]. The CLI displays the challenge
/// instructions, waits for user confirmation, then calls [`complete`](Self::complete).
///
/// Usage:
/// ```ignore
/// let session = initiate_namespace_claim(&verifier, eco, pkg, did, platform).await?;
/// println!("{}", session.challenge.instructions);
/// // wait for user...
/// let result = session.complete(&verifier, &signer, &passphrase, &alias).await?;
/// ```
pub struct NamespaceVerificationSession {
    /// The verification challenge issued by the adapter.
    pub challenge: VerificationChallenge,
    /// The ecosystem being verified.
    pub ecosystem: Ecosystem,
    /// The package being claimed.
    pub package_name: PackageName,
    /// The DID claiming ownership.
    pub controller_did: CanonicalDid,
    /// Platform identity context for cross-referencing.
    pub platform: PlatformContext,
}

impl NamespaceVerificationSession {
    /// Complete the verification after the user has performed the challenge.
    ///
    /// Borrows `self` so the caller can retry on transient failures.
    /// Calls `verifier.verify()`, then signs the namespace claim entry
    /// with the proof attached.
    ///
    /// Args:
    /// * `now`: Current time (injected at presentation boundary).
    /// * `verifier`: The namespace verifier adapter.
    /// * `signer`: Signing backend for creating the cryptographic signature.
    /// * `passphrase_provider`: Provider for obtaining key decryption passphrases.
    /// * `signer_alias`: Keychain alias of the signing key.
    pub async fn complete_ref(
        &self,
        now: DateTime<Utc>,
        verifier: &dyn NamespaceVerifier,
        signer: &dyn SecureSigner,
        passphrase_provider: &dyn PassphraseProvider,
        signer_alias: &KeyAlias,
    ) -> Result<VerifiedClaimResult, NamespaceError> {
        let proof = verifier
            .verify(
                now,
                &self.package_name,
                &self.controller_did,
                &self.platform,
                &self.challenge,
            )
            .await?;

        let content = EntryContent {
            entry_type: EntryType::NamespaceClaim,
            body: EntryBody::NamespaceClaim {
                ecosystem: self.ecosystem.as_str().to_string(),
                package_name: self.package_name.as_str().to_string(),
                proof_url: proof.proof_url.to_string(),
                verification_method: format!("{:?}", proof.method),
            },
            actor_did: self.controller_did.clone(),
        };

        let signed = build_and_sign_entry(&content, signer, passphrase_provider, signer_alias)?;

        Ok(VerifiedClaimResult {
            signed_entry: signed,
            proof,
        })
    }
}

/// Result of a successful verified namespace claim.
pub struct VerifiedClaimResult {
    /// The signed entry ready for submission to the registry.
    pub signed_entry: SignedEntry,
    /// The ownership proof from the verifier adapter.
    pub proof: NamespaceOwnershipProof,
}

/// Phase 1: Initiate namespace verification.
///
/// Returns a [`NamespaceVerificationSession`] that the CLI can display
/// (challenge instructions), then complete after user action.
///
/// Args:
/// * `now`: Current time (injected at presentation boundary).
/// * `verifier`: The namespace verifier adapter for the target ecosystem.
/// * `ecosystem`: The ecosystem being claimed.
/// * `package_name`: The package to claim.
/// * `controller_did`: The DID making the claim.
/// * `platform`: Verified platform identity context.
///
/// Usage:
/// ```ignore
/// let session = initiate_namespace_claim(now, &verifier, eco, pkg, did, ctx).await?;
/// ```
pub async fn initiate_namespace_claim(
    now: DateTime<Utc>,
    verifier: &dyn NamespaceVerifier,
    ecosystem: Ecosystem,
    package_name: PackageName,
    controller_did: CanonicalDid,
    platform: PlatformContext,
) -> Result<NamespaceVerificationSession, NamespaceError> {
    let challenge = verifier
        .initiate(now, &package_name, &controller_did, &platform)
        .await?;

    Ok(NamespaceVerificationSession {
        challenge,
        ecosystem,
        package_name,
        controller_did,
        platform,
    })
}
