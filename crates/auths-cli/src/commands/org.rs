use anyhow::{Context, Result, anyhow};
use auths_sdk::attestation::create_signed_attestation;
use auths_sdk::attestation::create_signed_revocation;
use auths_sdk::identity::DidResolver;
use auths_sdk::registration::DEFAULT_REGISTRY_URL;
use chrono::{DateTime, Utc};
use clap::{ArgAction, Parser, Subcommand};
use serde_json;
use std::fs;
use std::path::PathBuf;

use auths_sdk::attestation::AttestationGroup;
use auths_sdk::identity::DefaultDidResolver;
use auths_sdk::keychain::{KeyAlias, get_platform_keychain};
use auths_sdk::ports::{AttestationMetadata, AttestationSource, IdentityStorage, RegistryBackend};
use auths_sdk::signing::StorageSigner;
use auths_sdk::storage_layout::{StorageLayoutConfig, layout};

use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_sdk::workflows::commit_trust::commit_signer_trailers;
use auths_sdk::workflows::org::{
    AuthorityAtSigning, Role, add_member, build_org_bundle, classify_authority_at_signing,
    create_org, fleet_metrics, list_members, list_offboarding_records, load_offboarding_record,
    load_org_policy, member_role_order, org_slug_alias, resolve_org_signing_alias, revoke_member,
    set_org_oidc_policy, set_org_policy, walk_delegation_chain,
};

use crate::factories::storage::build_auths_context;
use auths_verifier::Prefix;
use auths_verifier::types::CanonicalDid;

use clap::ValueEnum;

/// CLI-level role wrapper that derives `ValueEnum` for argument parsing.
///
/// Converts to `auths_sdk::workflows::org::Role` at the CLI boundary.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum CliRole {
    Admin,
    Member,
    Readonly,
}

impl From<CliRole> for Role {
    fn from(r: CliRole) -> Self {
        match r {
            CliRole::Admin => Role::Admin,
            CliRole::Member => Role::Member,
            CliRole::Readonly => Role::Readonly,
        }
    }
}

/// The `org` subcommand, handling member authorizations.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Manage organization identities and memberships",
    after_help = "Examples:
  auths org create --name 'My Organization'
                        # Create a new org identity
  auths org add-member --org did:keri:EOrg --member did:keri:EMember --role admin --key orgkey
                        # Add a member with admin role
  auths org revoke-member --org did:keri:EOrg --member did:keri:EMember --key orgkey
                        # Revoke a member's access

Related:
  auths id        — Manage individual identities
  auths namespace — Claim and manage package namespaces
  auths policy    — Define capability policies"
)]
pub struct OrgCommand {
    #[clap(subcommand)]
    pub subcommand: OrgSubcommand,

    #[command(flatten)]
    pub overrides: crate::commands::registry_overrides::RegistryOverrides,
}

/// Subcommands for managing authorizations issued by this identity.
#[derive(Subcommand, Debug, Clone)]
pub enum OrgSubcommand {
    /// Create a new organization identity
    #[command(visible_alias = "init")]
    Create {
        /// Organization name
        #[arg(long)]
        name: String,

        /// Alias for the local signing key (auto-generated if not provided)
        #[arg(long)]
        key: Option<String>,

        /// Optional metadata file (if provided, merged with org metadata)
        #[arg(long)]
        metadata_file: Option<PathBuf>,
    },
    Attest {
        #[arg(long = "subject", visible_alias = "subject-did")]
        subject_did: String,
        #[arg(long)]
        payload_file: PathBuf,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        key: Option<String>,
    },
    Revoke {
        #[arg(long = "subject", visible_alias = "subject-did")]
        subject_did: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        key: Option<String>,
    },
    Show {
        #[arg(long = "subject", visible_alias = "subject-did")]
        subject_did: String,
        #[arg(long, action = ArgAction::SetTrue)]
        include_revoked: bool,
    },
    List {
        #[arg(long, action = ArgAction::SetTrue)]
        include_revoked: bool,
    },
    /// Add a member to an organization
    AddMember {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Member identity ID to add
        #[arg(long = "member", visible_alias = "member-did")]
        member_did: String,

        /// Role to assign (admin, member, readonly)
        #[arg(long, value_enum)]
        role: CliRole,

        /// Override default capabilities (comma-separated)
        #[arg(long, value_delimiter = ',')]
        capabilities: Option<Vec<auths_keri::Capability>>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        key: Option<String>,

        /// Optional note for the authorization
        #[arg(long)]
        note: Option<String>,
    },

    /// Revoke a member from an organization
    RevokeMember {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Member identity ID to revoke
        #[arg(long = "member", visible_alias = "member-did")]
        member_did: String,

        /// Reason for revocation
        #[arg(long)]
        note: Option<String>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        key: Option<String>,

        /// Preview actions without making changes.
        #[arg(long)]
        dry_run: bool,
    },

    /// List members of an organization
    ListMembers {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Include revoked members
        #[arg(long, action = ArgAction::SetTrue)]
        include_revoked: bool,
    },

    /// Classify a member's authority at an artifact's signing position (by KEL position)
    Audit {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Member identity ID to classify
        #[arg(long = "member", visible_alias = "member-did")]
        member_did: String,

        /// Artifact path (shown in the report for context)
        #[arg(long)]
        artifact: Option<PathBuf>,

        /// The artifact's in-band signing KEL position (e.g. a commit's `Auths-Anchor-Seq`)
        #[arg(long)]
        signed_at: Option<u128>,

        /// Emit the typed verdict as JSON
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },

    /// List durable off-boarding records for an organization
    OffboardingLog {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Restrict to a single member
        #[arg(long = "member", visible_alias = "member-did")]
        member_did: Option<String>,

        /// Emit the records as JSON
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },

    /// Produce a self-contained, air-gapped provenance bundle for an organization
    Bundle {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Output path for the bundle file
        #[arg(long)]
        out: PathBuf,
    },

    /// Join an organization using an invite code
    Join {
        /// Invite code (e.g. from `auths org join --code C23BD59F`)
        #[arg(long)]
        code: String,

        /// Registry URL to contact
        #[arg(long, env = "AUTHS_REGISTRY_URL", default_value = DEFAULT_REGISTRY_URL)]
        registry: String,
    },

    /// Manage the org-wide authorization policy (anchored on the org KEL)
    Policy {
        /// Policy action (set/show)
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Anchor the org's OIDC-subject policy on its KEL (who may sign keylessly).
    /// Verifiers resolve it with `auths artifact verify --oidc-policy-did <org-did>`
    /// — the witnessed log is the policy's source of truth, not a pinned file.
    AnchorOidcPolicy {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Path to the OIDC-subject policy JSON (issuer + repository, optional workflow_ref)
        #[arg(long)]
        file: PathBuf,

        /// Org signing key alias (defaults to the org slug alias)
        #[arg(long)]
        key: Option<String>,
    },

    /// Show fleet governance metrics for an organization
    Metrics {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Emit the metrics as JSON
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },

    /// Trace an agent's delegation chain to the authorizing root + live-at-signing
    Trace {
        /// A signed commit SHA — traces its signer (`Auths-Device`) at its anchor-seq
        #[arg(long)]
        commit: Option<String>,

        /// A member/agent identity ID to trace directly
        #[arg(long = "member", visible_alias = "member-did")]
        member: Option<String>,

        /// The in-band signing KEL position (used with `--member`; `--commit` reads it
        /// from the commit's `Auths-Anchor-Seq` trailer)
        #[arg(long)]
        signed_at: Option<u128>,

        /// Emit the chain as JSON
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
}

/// Actions for the org-wide authorization policy.
#[derive(Subcommand, Debug, Clone)]
pub enum PolicyAction {
    /// Anchor a new org-wide policy from a JSON file (a serialized policy `Expr`)
    Set {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Path to the policy JSON file (a serialized `Expr`)
        #[arg(long)]
        file: PathBuf,

        /// Org signing key alias (defaults to the org slug alias)
        #[arg(long)]
        key: Option<String>,
    },

    /// Show the org's currently-anchored policy
    Show {
        /// Organization identity ID
        #[arg(long)]
        org: String,

        /// Emit the raw policy JSON
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
}

/// single-verifier helper. Resolves the issuer DID,
/// constructs a typed `DevicePublicKey`, and calls `auths_verifier::verify_with_keys`.
/// Returns one of: "✅ valid", "🛑 revoked", "⌛ expired", "❌ invalid".
fn verify_attestation_via_resolver(
    att: &auths_verifier::Attestation,
    resolver: &auths_sdk::identity::DefaultDidResolver,
    anchor_set: Option<&std::collections::HashSet<auths_keri::Said>>,
) -> String {
    use auths_sdk::identity::DidResolver;
    let resolved = match resolver.resolve(att.issuer.as_str()) {
        Ok(r) => r,
        Err(_) => return "❌ invalid".to_string(),
    };
    let pk_bytes: Vec<u8> = resolved.public_key_bytes().to_vec();
    let resolved_curve = resolved.curve();
    let issuer_pk = match auths_verifier::decode_public_key_bytes(&pk_bytes, resolved_curve) {
        Ok(pk) => pk,
        Err(_) => return "❌ invalid".to_string(),
    };
    #[allow(clippy::expect_used)]
    // INVARIANT: current-thread runtime creation only fails on resource
    // exhaustion, which is unrecoverable at the CLI boundary.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let base = match rt.block_on(auths_verifier::verify_with_keys(att, &issuer_pk)) {
        Ok(_) => "✅ valid",
        Err(e) if e.to_string().contains("revoked") => "🛑 revoked",
        Err(e) if e.to_string().contains("expired") => "⌛ expired",
        Err(_) => "❌ invalid",
    };
    let anchor_suffix = match anchor_set {
        Some(set) => {
            let anchored =
                auths_sdk::attestation::canonical_said(att).is_some_and(|said| set.contains(&said));
            if anchored { "" } else { " (unanchored)" }
        }
        None => "",
    };
    format!("{base}{anchor_suffix}")
}

/// Handles `org` commands for issuing or revoking member authorizations.
pub fn handle_org(
    cmd: OrgCommand,
    ctx: &crate::config::CliConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
    let passphrase_provider = ctx.passphrase_provider.clone();

    let mut config = StorageLayoutConfig::default();
    if let Some(r) = &cmd.overrides.identity_ref {
        config.identity_ref = r.clone().into();
    }
    if let Some(b) = &cmd.overrides.identity_blob {
        config.identity_blob_name = b.clone().into();
    }
    if let Some(p) = &cmd.overrides.attestation_prefix {
        config.device_attestation_prefix = p.clone().into();
    }
    if let Some(b) = &cmd.overrides.attestation_blob {
        config.attestation_blob_name = b.clone().into();
    }

    let _attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
    let resolver: DefaultDidResolver = DefaultDidResolver::with_repo(&repo_path);

    match cmd.subcommand {
        OrgSubcommand::Create {
            name,
            key,
            metadata_file,
        } => {
            let key_alias = key.unwrap_or_else(|| org_slug_alias(&name));

            println!("🏛️  Initializing new organization identity...");
            println!("   Organization Name: {name}");
            println!("   Repository path:   {repo_path:?}");
            println!("   Local Key Alias:   {key_alias}");

            use crate::factories::storage::ensure_git_repo;
            ensure_git_repo(&repo_path).context("Failed to initialize Git repository")?;

            let extra_metadata = match &metadata_file {
                Some(mf) if mf.exists() => {
                    let raw = fs::read_to_string(mf)
                        .with_context(|| format!("Failed to read metadata file: {mf:?}"))?;
                    let value: serde_json::Value = serde_json::from_str(&raw)
                        .with_context(|| format!("Invalid JSON in metadata file: {mf:?}"))?;
                    println!("   Merged additional metadata from {mf:?}");
                    Some(value)
                }
                _ => None,
            };

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let created = create_org(
                &sdk_ctx,
                &name,
                &KeyAlias::new_unchecked(key_alias),
                auths_crypto::CurveType::default(),
                extra_metadata,
            )
            .with_context(|| format!("Failed to create organization '{name}'"))?;

            println!("\n✅ Organization identity initialized successfully!");
            println!("   Org Identity ID:    {}", created.org_did);
            println!("   Org Name:           {name}");
            println!("   Repo Path:          {repo_path:?}");
            println!("   Key Alias:          {}", created.key_alias);
            println!("   Admin Role:         Granted with all capabilities");
            println!(
                "   KEL Ref:            '{}'",
                layout::keri_kel_ref(&Prefix::new_unchecked(created.org_prefix.clone()))
            );
            println!("   Identity Ref:       '{}'", config.identity_ref);
            if let Ok(org_did) = CanonicalDid::parse(&created.org_did) {
                println!(
                    "   Member Ref:         '{}'",
                    config.org_member_ref(&created.org_did, &org_did)
                );
            }
            println!("\n🔑 Store your key passphrase securely.");
            println!(
                "   You can now add members with: auths org add-member --org {} --member <identity-id> --role <role>",
                created.org_did
            );

            Ok(())
        }

        OrgSubcommand::Attest {
            subject_did,  // The subject DID (String)
            payload_file, // Path to the JSON payload
            note,         // Optional note (String)
            expires_at,   // Optional RFC3339 expiration string
            key,          // Alias of the org's signing key in keychain
        } => {
            let signer_alias =
                key.ok_or_else(|| anyhow!("Signer key alias must be provided with --key"))?;
            let signer_alias = KeyAlias::new_unchecked(signer_alias);

            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let managed_identity = identity_storage
                .load_identity()
                .context("Failed to load org identity from Git repository")?;
            let controller_did = managed_identity.controller_did;
            let rid = managed_identity.storage_id;

            let payload_str = fs::read_to_string(&payload_file)
                .with_context(|| format!("Failed to read payload file {:?}", payload_file))?;
            let payload: serde_json::Value =
                serde_json::from_str(&payload_str).context("Invalid JSON in payload file")?;

            let key_storage = get_platform_keychain()?;
            let (stored_did, _role, _encrypted_key) = key_storage
                .load_key(&signer_alias)
                .with_context(|| format!("Failed to load signer key '{}'", signer_alias))?;

            if stored_did != controller_did {
                return Err(anyhow!(
                    "Signer key alias '{}' belongs to DID '{}', but loaded org identity is '{}'",
                    signer_alias,
                    stored_did,
                    controller_did
                ));
            }

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: subject_did accepts both did:key and did:keri
            let subject_device_did = CanonicalDid::new_unchecked(subject_did.clone());

            // --- Resolve device public key using the custom resolver IF did:key ---
            let device_resolved = resolver.resolve(&subject_did).with_context(|| {
                format!("Failed to resolve public key for subject: {}", subject_did)
            })?;
            let device_pk_bytes = device_resolved.public_key_bytes().to_vec();
            let device_curve = device_resolved.curve();

            let meta = AttestationMetadata {
                note,
                timestamp: Some(now),
                expires_at: expires_at
                    .as_deref()
                    .map(DateTime::parse_from_rfc3339)
                    .transpose()
                    .map_err(|e| anyhow!("Invalid RFC3339 datetime string: {}", e))?
                    .map(|dt| dt.with_timezone(&Utc)),
            };

            let signer = StorageSigner::new(key_storage);
            let attestation = create_signed_attestation(
                now,
                auths_sdk::attestation::AttestationInput {
                    rid: &rid,
                    identity_did: &controller_did,
                    subject: &subject_device_did,
                    device_public_key: &device_pk_bytes,
                    device_curve,
                    payload: Some(payload),
                    meta: &meta,
                    identity_alias: Some(&signer_alias),
                    device_alias: None, // No device signature for org attestations
                    delegated_by: None,
                    commit_sha: None,
                    signer_type: None,
                    oidc_binding: None,
                },
                &signer,
                passphrase_provider.as_ref(),
            )
            .context("Failed to create signed attestation object")?;

            {
                let backend = GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo_path),
                );
                let mut batch = auths_sdk::keri::AtomicWriteBatch::new();
                batch.stage_attestation(attestation);
                if let Ok(prefix) = auths_sdk::keri::parse_did_keri(controller_did.as_str()) {
                    let _ = auths_sdk::keri::try_stage_anchor(
                        &backend,
                        &signer,
                        &signer_alias,
                        passphrase_provider.as_ref(),
                        &prefix,
                        &serde_json::json!({}),
                        &mut batch,
                    );
                }
                backend
                    .commit_batch(&batch)
                    .context("Failed to write attestation")?;
            }

            println!(
                "\n✅ Org attestation created successfully from '{}' → '{}'",
                controller_did, subject_device_did
            );

            Ok(())
        }

        OrgSubcommand::Revoke {
            subject_did,
            note,
            key,
        } => {
            println!("🛑 Revoking org authorization for subject: {subject_did}");
            println!("   Using Repository:         {:?}", repo_path);
            println!("   Using Identity Ref:       '{}'", config.identity_ref);
            println!(
                "   Using Attestation Prefix: '{}'",
                config.device_attestation_prefix
            );

            let signer_alias =
                key.ok_or_else(|| anyhow!("Signer key alias must be provided for revocation"))?;
            let signer_alias = KeyAlias::new_unchecked(signer_alias);

            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let managed_identity = identity_storage
                .load_identity()
                .context("Failed to load identity from Git repository")?;
            let controller_did = managed_identity.controller_did;
            let rid = managed_identity.storage_id;

            #[allow(clippy::disallowed_methods)] // INVARIANT: accepts both did:key and did:keri
            let subject_device_did = CanonicalDid::new_unchecked(subject_did.clone());

            // Look up the subject's public key from existing attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let existing = attestation_storage
                .load_attestations_for_device(&subject_device_did)
                .context("Failed to load attestations for subject")?;
            let device_public_key = existing
                .iter()
                .find(|a| !a.device_public_key.is_zero())
                .map(|a| a.device_public_key.clone())
                .unwrap_or_default();

            println!("🔏 Creating signed revocation...");
            let signer = StorageSigner::new(get_platform_keychain()?);
            let attestation = create_signed_revocation(
                auths_sdk::attestation::RevocationInput {
                    rid: &rid,
                    identity_did: &controller_did,
                    subject: &subject_device_did,
                    device_public_key: device_public_key.as_bytes(),
                    device_curve: device_public_key.curve(),
                    note,
                    payload: None,
                    timestamp: now,
                    identity_alias: &signer_alias,
                },
                &signer,
                passphrase_provider.as_ref(),
            )
            .context("Failed to create revocation")?;

            println!("💾 Writing revocation to Git...");
            {
                let backend = GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo_path),
                );
                let mut batch = auths_sdk::keri::AtomicWriteBatch::new();
                batch.stage_attestation(attestation);
                if let Ok(prefix) = auths_sdk::keri::parse_did_keri(controller_did.as_str()) {
                    let _ = auths_sdk::keri::try_stage_anchor(
                        &backend,
                        &signer,
                        &signer_alias,
                        passphrase_provider.as_ref(),
                        &prefix,
                        &serde_json::json!({}),
                        &mut batch,
                    );
                }
                backend
                    .commit_batch(&batch)
                    .context("Failed to write revocation")?;
            }

            println!("\n✅ Revoked authorization for subject {subject_did}");

            Ok(())
        }

        OrgSubcommand::Show {
            subject_did,
            include_revoked,
        } => {
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let resolver = DefaultDidResolver::with_repo(&repo_path);
            let group = AttestationGroup::from_list(
                attestation_storage
                    .load_all_enriched()
                    .map(|v| v.into_iter().map(|e| e.attestation).collect::<Vec<_>>())?,
            );

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: subject_did from CLI arg, used for lookup only
            let subject_device_did = CanonicalDid::new_unchecked(subject_did.clone());
            if let Some(list) = group.by_device.get(subject_device_did.as_str()) {
                for (i, att) in list.iter().enumerate() {
                    if !include_revoked
                        && (att.is_revoked() || att.expires_at.is_some_and(|e| now > e))
                    {
                        continue;
                    }

                    let status = verify_attestation_via_resolver(att, &resolver, None);

                    println!("{i}. [{}] @ {}", status, att.timestamp.unwrap_or(now));
                    if let Some(note) = &att.note {
                        println!("   📝 {}", note);
                    }
                    if let Some(payload) = &att.payload {
                        println!("   📦 {}", serde_json::to_string_pretty(payload)?);
                    }
                }
            } else {
                println!("No authorizations found for subject: {}", subject_did);
            }

            Ok(())
        }

        OrgSubcommand::List { include_revoked } => {
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let resolver = DefaultDidResolver::with_repo(&repo_path);
            let group = AttestationGroup::from_list(
                attestation_storage
                    .load_all_enriched()
                    .map(|v| v.into_iter().map(|e| e.attestation).collect::<Vec<_>>())?,
            );

            for (subject, list) in group.by_device.iter() {
                let Some(latest) = list.last() else {
                    continue;
                };
                if !include_revoked
                    && (latest.is_revoked() || latest.expires_at.is_some_and(|e| now > e))
                {
                    continue;
                }

                let status = verify_attestation_via_resolver(latest, &resolver, None);

                println!("- {} [{}]", subject, status);
            }

            Ok(())
        }

        OrgSubcommand::AddMember {
            org,
            member_did: member_label,
            role: cli_role,
            capabilities,
            key,
            note: _note,
        } => {
            let role = Role::from(cli_role);
            println!("👥 Adding member to organization...");
            println!("   Org:   {}", org);
            println!("   Label: {}", member_label);
            println!("   Role:  {}", role);

            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let member_alias = KeyAlias::new_unchecked(member_label.clone());

            let capability_strings = capabilities.unwrap_or_else(|| role.default_capabilities());

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let org_alias =
                resolve_org_signing_alias(sdk_ctx.key_storage.as_ref(), org_prefix.as_str(), key)?;
            let result = add_member(
                &sdk_ctx,
                &org_prefix,
                &org_alias,
                &member_alias,
                auths_crypto::CurveType::Ed25519,
                role,
                &capability_strings,
                None,
            )
            .context("Failed to add member")?;

            println!("\n✅ Member added as a KERI delegated identifier!");
            println!("   Member DID:   {}", result.member_did);
            println!("   Role:         {}", role);
            println!(
                "   Capabilities: {}",
                capability_strings
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("\nThe org anchored this member's delegation in its KEL.");

            Ok(())
        }

        OrgSubcommand::RevokeMember {
            org,
            member_did: member,
            note,
            key,
            dry_run,
        } => {
            println!("🛑 Revoking member from organization...");
            println!("   Org:    {}", org);
            println!("   Member: {}", member);

            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let invoker_did = identity_storage
                .load_identity()
                .context("Failed to load identity. Are you running this from an org repository?")?
                .controller_did;

            if dry_run {
                return display_dry_run_revoke_member(&org, &member, invoker_did.as_ref());
            }

            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let org_alias =
                resolve_org_signing_alias(sdk_ctx.key_storage.as_ref(), org_prefix.as_str(), key)?;
            let record = revoke_member(&sdk_ctx, &org_prefix, &org_alias, &member, note)
                .context("Failed to revoke member")?;

            match record {
                Some(signed) => {
                    println!("\n✅ Member revoked (revocation anchored in the org KEL):");
                    println!("   Member:        {}", member);
                    println!("   Revoked by:    {}", invoker_did);
                    println!(
                        "   Revoked at:    KEL seq {} (authority ends after this position, not by wall-clock)",
                        signed.record.revoked_at_seq
                    );
                    println!("   Seal SAID:     {}", signed.record.revocation_seal_said);
                    let role = signed.record.prior_role.as_deref().unwrap_or("unknown");
                    println!("   Lost role:     {role}");
                    if !signed.record.prior_caps.is_empty() {
                        println!(
                            "   Lost caps:     {}",
                            signed
                                .record
                                .prior_caps
                                .iter()
                                .map(|c| c.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                    println!("   Off-boarding record stored (signed, retrievable by org/member).");
                }
                None => {
                    println!("\nℹ️  Member already revoked — no change (idempotent).");
                    println!("   Member: {member}");
                }
            }

            Ok(())
        }

        OrgSubcommand::ListMembers {
            org,
            include_revoked,
        } => {
            println!("📋 Listing members of organization: {}", org);

            // KEL-authoritative: members are `dip`s the org anchored. Revocation and
            // role/capabilities are read from the org KEL, never from an attestation.
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let all_members =
                list_members(&sdk_ctx, &org_prefix).context("Failed to list members")?;
            let revoked_count = all_members.iter().filter(|m| m.revoked).count();

            let mut members: Vec<_> = all_members
                .into_iter()
                .filter(|m| include_revoked || !m.revoked)
                .collect();

            if members.is_empty() {
                println!("\nNo members found for organization.");
                return Ok(());
            }

            members.sort_by(|a, b| {
                member_role_order(&a.role)
                    .cmp(&member_role_order(&b.role))
                    .then_with(|| a.member_did.cmp(&b.member_did))
            });

            println!("\nOrg: {}", org);
            println!("\nMembers ({} total):", members.len());
            println!("─────────────────────────────────────────");

            for m in &members {
                let role_str = m.role.as_ref().map(|r| r.as_str()).unwrap_or("unknown");
                let status = if m.revoked { " (revoked)" } else { "" };
                let caps_str = if m.capabilities.is_empty() {
                    String::new()
                } else {
                    format!(
                        " [{}]",
                        m.capabilities
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };

                println!("├─ {} [{}]{}{}", m.member_did, role_str, status, caps_str);
                println!("│     delegated by: {}", m.delegated_by_org);
            }

            println!("─────────────────────────────────────────");

            if !include_revoked && revoked_count > 0 {
                println!(
                    "\n({} revoked member(s) hidden. Use --include-revoked to show.)",
                    revoked_count
                );
            }

            Ok(())
        }

        OrgSubcommand::Audit {
            org,
            member_did,
            artifact,
            signed_at,
            json,
        } => {
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let member_prefix = Prefix::new_unchecked(
                member_did
                    .strip_prefix("did:keri:")
                    .unwrap_or(&member_did)
                    .to_string(),
            );
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let verdict =
                classify_authority_at_signing(&sdk_ctx, &org_prefix, &member_prefix, signed_at)
                    .context("Failed to classify authority at signing")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&verdict)?);
                return Ok(());
            }

            if let Some(path) = &artifact {
                println!("Artifact: {path:?}");
            }
            println!("Member:   {member_did}");
            match &verdict {
                AuthorityAtSigning::AuthorizedBeforeRevocation => println!(
                    "Verdict:  ✅ AuthorizedBeforeRevocation — authority was live at the signing position"
                ),
                AuthorityAtSigning::RejectedAfterRevocation { revoked_at } => println!(
                    "Verdict:  🛑 RejectedAfterRevocation {{ revoked_at: {revoked_at} }} — signed at/after the revocation KEL position"
                ),
                AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at } => println!(
                    "Verdict:  🛑 RejectedRevokedPositionUnknown {{ revoked_at: {revoked_at} }} — revoked; artifact carries no in-band signing position"
                ),
                AuthorityAtSigning::NeverDelegated => {
                    println!("Verdict:  ❌ NeverDelegated — the org never delegated this member")
                }
            }
            Ok(())
        }

        OrgSubcommand::OffboardingLog {
            org,
            member_did,
            json,
        } => {
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;

            let records = match &member_did {
                Some(m) => {
                    let member_prefix =
                        Prefix::new_unchecked(m.strip_prefix("did:keri:").unwrap_or(m).to_string());
                    load_offboarding_record(&sdk_ctx, &org_prefix, &member_prefix)
                        .context("Failed to load off-boarding record")?
                        .into_iter()
                        .collect::<Vec<_>>()
                }
                None => list_offboarding_records(&sdk_ctx, &org_prefix)
                    .context("Failed to list off-boarding records")?,
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
                return Ok(());
            }

            if records.is_empty() {
                println!("No off-boarding records for organization {org}.");
                return Ok(());
            }

            println!("Off-boarding records for {org} ({} total):", records.len());
            for r in &records {
                println!("─────────────────────────────────────────");
                println!("  Member:     {}", r.record.member_did);
                println!(
                    "  Revoked at: KEL seq {} (by position, not wall-clock)",
                    r.record.revoked_at_seq
                );
                println!("  Seal SAID:  {}", r.record.revocation_seal_said);
                if let Some(reason) = &r.record.reason {
                    println!("  Reason:     {reason}");
                }
                let role = r.record.prior_role.as_deref().unwrap_or("unknown");
                println!("  Lost role:  {role}");
                if !r.record.prior_caps.is_empty() {
                    println!(
                        "  Lost caps:  {}",
                        r.record
                            .prior_caps
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                println!("  Recorded:   {}", r.record.recorded_at);
            }
            Ok(())
        }

        OrgSubcommand::Bundle { org, out } => {
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let bundle =
                build_org_bundle(&sdk_ctx, &org_prefix).context("Failed to build org bundle")?;
            let json = bundle
                .to_canonical_json()
                .context("Failed to canonicalize org bundle")?;
            fs::write(&out, json).with_context(|| format!("Failed to write bundle to {out:?}"))?;

            println!("✅ Air-gapped org bundle written to {out:?}");
            println!("   Org:            {}", bundle.org_did.as_str());
            println!("   Built as-of:    KEL seq {}", bundle.built_at_org_seq);
            println!("   Member KELs:    {}", bundle.member_kels.len());
            println!("   Off-boardings:  {}", bundle.offboarding_records.len());
            println!("   Pinned roots:   {}", bundle.pinned_roots.len());
            println!(
                "   Verifies offline (no network): auths artifact verify {out:?} --offline --roots .auths/roots"
            );
            Ok(())
        }

        OrgSubcommand::Join { code, registry } => {
            handle_join(&code, &registry, passphrase_provider.as_ref())
        }

        OrgSubcommand::Policy { action } => match action {
            PolicyAction::Set { org, file, key } => {
                let org_prefix = Prefix::new_unchecked(
                    org.strip_prefix("did:keri:").unwrap_or(&org).to_string(),
                );
                let policy_json = fs::read(&file)
                    .with_context(|| format!("Failed to read policy file {file:?}"))?;

                let sdk_ctx = build_auths_context(
                    &repo_path,
                    &ctx.env_config,
                    Some(passphrase_provider.clone()),
                )?;
                let org_alias = resolve_org_signing_alias(
                    sdk_ctx.key_storage.as_ref(),
                    org_prefix.as_str(),
                    key,
                )?;
                let result = set_org_policy(&sdk_ctx, &org_prefix, &org_alias, &policy_json)
                    .context("Failed to set org policy")?;

                println!("✅ Org policy anchored on the KEL:");
                println!("   Org:         {}", result.org_did);
                println!("   Policy hash: {}", result.policy_hash);
                println!("   Requires:\n{}", result.description);
                Ok(())
            }

            PolicyAction::Show { org, json } => {
                let org_prefix = Prefix::new_unchecked(
                    org.strip_prefix("did:keri:").unwrap_or(&org).to_string(),
                );
                let sdk_ctx = build_auths_context(
                    &repo_path,
                    &ctx.env_config,
                    Some(passphrase_provider.clone()),
                )?;

                match load_org_policy(&sdk_ctx, &org_prefix).context("Failed to load org policy")? {
                    Some(policy) => {
                        if json {
                            println!("{}", policy.source_json);
                        } else {
                            println!("Org:         did:keri:{}", org_prefix.as_str());
                            println!("Policy hash: {}", policy.policy_hash);
                            println!("Requires:\n{}", policy.compiled.describe());
                        }
                    }
                    None => println!("No policy anchored for organization {org}."),
                }
                Ok(())
            }
        },

        OrgSubcommand::AnchorOidcPolicy { org, file, key } => {
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let policy_json = fs::read(&file)
                .with_context(|| format!("Failed to read OIDC policy file {file:?}"))?;

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let org_alias =
                resolve_org_signing_alias(sdk_ctx.key_storage.as_ref(), org_prefix.as_str(), key)?;
            let result = set_org_oidc_policy(&sdk_ctx, &org_prefix, &org_alias, &policy_json)
                .context("Failed to anchor OIDC-subject policy")?;

            println!("✅ OIDC-subject policy anchored on the org KEL:");
            println!("   Org:           {}", result.org_did);
            println!("   Policy digest: {}", result.policy_digest);
            println!(
                "   Trusts:        {} via issuer {}",
                result.policy.repository(),
                result.policy.issuer()
            );
            println!(
                "\nVerifiers resolve it from the witnessed log:\n   auths artifact verify <artifact> --oidc-policy-did {}",
                result.org_did
            );
            Ok(())
        }

        OrgSubcommand::Metrics { org, json } => {
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;
            let m =
                fleet_metrics(&sdk_ctx, &org_prefix).context("Failed to compute fleet metrics")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&m)?);
                return Ok(());
            }
            println!("Fleet metrics for {}", m.org_did);
            println!("  Agents (total):           {}", m.agents_total);
            println!("  Agents (live):            {}", m.agents_live);
            println!("  Agents (revoked):         {}", m.agents_revoked);
            println!(
                "  Traceable to a human:     {}/{} ({:.0}%)",
                m.agents_traceable_to_human,
                m.agents_live,
                m.traceability_fraction * 100.0
            );
            println!(
                "  Revocation-to-effect:     {} KEL positions (positional — effective at the anchor)",
                m.revocation_effect_latency_positions
            );
            Ok(())
        }

        OrgSubcommand::Trace {
            commit,
            member,
            signed_at,
            json,
        } => {
            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;

            let (leaf_prefix, position) = if let Some(sha) = commit {
                let raw = read_commit_object(&sha)?;
                let (_root, device) = commit_signer_trailers(&raw).ok_or_else(|| {
                    anyhow!("commit {sha} carries no Auths-Id/Auths-Device trailer")
                })?;
                let pos = parse_anchor_seq_trailer(&raw);
                let prefix = Prefix::new_unchecked(
                    device
                        .strip_prefix("did:keri:")
                        .unwrap_or(&device)
                        .to_string(),
                );
                (prefix, pos)
            } else if let Some(m) = member {
                let prefix =
                    Prefix::new_unchecked(m.strip_prefix("did:keri:").unwrap_or(&m).to_string());
                (prefix, signed_at)
            } else {
                return Err(anyhow!("provide --commit <sha> or --member <did> to trace"));
            };

            let chain = walk_delegation_chain(&sdk_ctx, &leaf_prefix, position)
                .context("Failed to walk the delegation chain")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&chain)?);
                return Ok(());
            }

            println!("Trace: {}", chain.leaf_did);
            match position {
                Some(p) => println!("  Signed at:       KEL position {p}"),
                None => println!(
                    "  Signed at:       (no in-band position — upstream revocations fail closed)"
                ),
            }
            println!("  Root:            {}", chain.root_did);
            println!("  Depth:           {} hop(s)", chain.depth);
            for hop in &chain.hops {
                let role = hop.role.as_deref().unwrap_or("-");
                let caps = if hop.capabilities.is_empty() {
                    String::new()
                } else {
                    format!(
                        " caps=[{}]",
                        hop.capabilities
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                println!(
                    "    {} ← {} [{}]{}  authority={:?}",
                    hop.child_did, hop.delegator_did, role, caps, hop.authority_at_signing
                );
            }
            if chain.live_at_signing {
                println!("  Live at signing: ✅ yes");
            } else {
                println!(
                    "  Live at signing: 🛑 no (a chain authority was revoked at/by the signing position)"
                );
            }
            Ok(())
        }
    }
}

/// Read a raw git commit object (`git cat-file commit <sha>`).
fn read_commit_object(sha: &str) -> Result<String> {
    let out = std::process::Command::new("git")
        .args(["cat-file", "commit", sha])
        .output()
        .context("failed to run git cat-file")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git cat-file commit {sha} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).context("commit object is not valid UTF-8")
}

/// Parse the `Auths-Anchor-Seq` trailer value from a raw commit, if present.
fn parse_anchor_seq_trailer(raw: &str) -> Option<u128> {
    raw.lines()
        .rev()
        .find_map(|l| l.strip_prefix("Auths-Anchor-Seq:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Handles the `org join` subcommand by looking up and accepting an invite
/// via the registry HTTP API.
///
/// Args:
/// * `code`: Invite code to redeem.
/// * `registry`: Base URL of the registry HTTP API.
/// * `passphrase_provider`: Injected provider used to unlock the signing key
///   when producing the bearer token; respects SE-backed and P-256 keys.
///
/// Usage:
/// ```ignore
/// handle_join(&code, &registry, ctx.passphrase_provider.as_ref())?;
/// ```
fn handle_join(
    code: &str,
    registry: &str,
    passphrase_provider: &dyn auths_sdk::signing::PassphraseProvider,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let client = reqwest::Client::new();
    let base = registry.trim_end_matches('/');

    // 1. Look up invite details.
    let details_url = format!("{}/v1/invites/{}", base, code);
    let details_resp = rt
        .block_on(async { client.get(&details_url).send().await })
        .context("failed to contact registry")?;

    if details_resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "Invite code '{}' not found. Check the code and try again.",
            code
        );
    }
    if !details_resp.status().is_success() {
        let status = details_resp.status();
        let body = rt.block_on(details_resp.text()).unwrap_or_default();
        anyhow::bail!("Failed to look up invite ({}): {}", status, body);
    }

    let details: serde_json::Value = rt
        .block_on(details_resp.json())
        .context("invalid response from registry")?;

    let org_name = details["display_name"].as_str().unwrap_or("Unknown");
    let role = details["role"].as_str().unwrap_or("member");
    let status = details["status"].as_str().unwrap_or("unknown");

    if status == "expired" {
        anyhow::bail!("This invite has expired. Ask the org admin for a new one.");
    }
    if status == "accepted" {
        anyhow::bail!("This invite has already been accepted.");
    }

    println!("Organization: {}", org_name);
    println!("Role:         {}", role);
    println!("Status:       {}", status);
    println!();

    // 2. Accept the invite. This requires auth — build a signed bearer token.
    let repo_path = layout::resolve_repo_path(None)?;
    let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
    let managed_identity = identity_storage
        .load_identity()
        .context("no local identity found — run `auths init` first")?;
    let did = managed_identity.controller_did.to_string();

    let key_storage = get_platform_keychain()?;
    let primary_alias = KeyAlias::new_unchecked("main");

    #[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
    let timestamp = Utc::now().to_rfc3339();
    let message = format!("{}\n{}", did, timestamp);

    let (sig_bytes, _pubkey, _curve) = auths_sdk::keychain::sign_with_key(
        key_storage.as_ref(),
        &primary_alias,
        passphrase_provider,
        message.as_bytes(),
    )
    .context("failed to sign invite bearer token")?;

    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    let bearer_payload = serde_json::json!({
        "did": did,
        "timestamp": timestamp,
        "signature": signature,
    });
    let bearer_token = serde_json::to_string(&bearer_payload)?;

    let accept_url = format!("{}/v1/invites/{}/accept", base, code);
    let accept_resp = rt
        .block_on(async {
            client
                .post(&accept_url)
                .header("Authorization", format!("Bearer {}", bearer_token))
                .header("Content-Type", "application/json")
                .send()
                .await
        })
        .context("failed to contact registry")?;

    if !accept_resp.status().is_success() {
        let status = accept_resp.status();
        let body = rt.block_on(accept_resp.text()).unwrap_or_default();
        anyhow::bail!("Failed to accept invite ({}): {}", status, body);
    }

    println!("✅ Successfully joined {} as {}", org_name, role);
    println!("   Your DID: {}", did);

    Ok(())
}

fn display_dry_run_revoke_member(org: &str, member: &str, invoker_did: &str) -> Result<()> {
    use crate::ux::format::{JsonResponse, is_json_mode};

    if is_json_mode() {
        JsonResponse::success(
            "org revoke-member",
            &serde_json::json!({
                "dry_run": true,
                "org": org,
                "member_did": member,
                "invoker_did": invoker_did,
                "actions": [
                    "Create signed revocation for member",
                    "Store revocation in Git repository",
                    "Member will lose all org capabilities"
                ]
            }),
        )
        .print()
        .map_err(anyhow::Error::from)
    } else {
        let out = crate::ux::format::Output::new();
        out.print_info("Dry run mode — no changes will be made");
        out.newline();
        out.println(&format!("   Org:    {}", org));
        out.println(&format!("   Member: {}", member));
        out.newline();
        out.println("Would perform the following actions:");
        out.println(&format!(
            "  1. Create signed revocation for member {}",
            member
        ));
        out.println("  2. Store revocation in Git repository");
        out.println("  3. Member will lose all org capabilities");
        Ok(())
    }
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for OrgCommand {
    #[allow(clippy::disallowed_methods)]
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_org(self.clone(), ctx, Utc::now())
    }
}
