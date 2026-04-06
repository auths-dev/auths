use anyhow::{Context, Result, anyhow};
use auths_sdk::attestation::create_signed_attestation;
use auths_sdk::attestation::create_signed_revocation;
use auths_sdk::crypto::decrypt_keypair;
use auths_sdk::identity::DidResolver;
use auths_sdk::identity::initialize_registry_identity;
use chrono::{DateTime, Utc};
use clap::{ArgAction, Parser, Subcommand};
use serde_json;
use std::fs;
use std::path::PathBuf;

use auths_sdk::attestation::{AttestationGroup, AttestationSink, verify_with_resolver};
use auths_sdk::identity::DefaultDidResolver;
use auths_sdk::keychain::{KeyAlias, get_platform_keychain};
use auths_sdk::ports::{AttestationMetadata, AttestationSource, IdentityStorage};
use auths_sdk::signing::StorageSigner;
use auths_sdk::storage_layout::{StorageLayoutConfig, layout};

use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_sdk::workflows::org::{
    AddMemberCommand, OrgContext, RevokeMemberCommand, Role, add_organization_member,
    member_role_order, revoke_organization_member,
};
use auths_verifier::types::DeviceDID;
use auths_verifier::{Capability, Ed25519PublicKey, Prefix, PublicKeyHex};

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
  auths org add-member --org-key orgkey --subject did:keri:EMember --role admin
                        # Add a member with admin role
  auths org revoke-member --org-key orgkey --subject did:keri:EMember
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
        capabilities: Option<Vec<String>>,

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

    /// Join an organization using an invite code
    Join {
        /// Invite code (e.g. from `auths org join --code C23BD59F`)
        #[arg(long)]
        code: String,

        /// Registry URL to contact
        #[arg(long, default_value = "https://auths-registry.fly.dev")]
        registry: String,
    },
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
            // Generate a key alias if not provided
            let key_alias = key.unwrap_or_else(|| {
                format!(
                    "org-{}",
                    name.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_lowercase()
                )
            });

            println!("🏛️  Initializing new organization identity...");
            println!("   Organization Name: {}", name);
            println!("   Repository path:   {:?}", repo_path);
            println!("   Local Key Alias:   {}", key_alias);
            println!("   Using Identity Ref: '{}'", config.identity_ref);

            // --- Ensure Git repo exists ---
            use crate::factories::storage::{ensure_git_repo, open_git_repo};

            let identity_storage_check = RegistryIdentityStorage::new(repo_path.clone());
            if repo_path.exists() {
                match open_git_repo(&repo_path) {
                    Ok(_) => {
                        println!("   Git repository found.");
                        if identity_storage_check.load_identity().is_ok() {
                            return Err(anyhow!(
                                "An identity already exists at {:?}. Aborting.",
                                repo_path
                            ));
                        }
                    }
                    Err(_) => {
                        println!("   Path exists but is not a Git repo. Initializing...");
                        ensure_git_repo(&repo_path)
                            .context("Failed to initialize Git repository")?;
                    }
                }
            } else {
                println!("   Creating Git repo directory...");
                ensure_git_repo(&repo_path)
                    .context("Failed to create and initialize Git repository")?;
            }

            // --- Build org metadata ---
            let mut metadata_json = serde_json::json!({
                "type": "org",
                "name": name,
                "created_at": now.to_rfc3339()
            });

            // Merge with additional metadata file if provided
            if let Some(ref mf) = metadata_file
                && mf.exists()
            {
                let metadata_content = fs::read_to_string(mf)
                    .with_context(|| format!("Failed to read metadata file: {:?}", mf))?;
                let additional: serde_json::Value = serde_json::from_str(&metadata_content)
                    .with_context(|| format!("Invalid JSON in metadata file: {:?}", mf))?;

                // Merge additional metadata (preserving type and name)
                if let (Some(base), Some(add)) =
                    (metadata_json.as_object_mut(), additional.as_object())
                {
                    for (k, v) in add {
                        if k != "type" && k != "name" {
                            base.insert(k.clone(), v.clone());
                        }
                    }
                }
                println!("   Merged additional metadata from {:?}", mf);
            }

            println!(
                "   Org metadata: {}",
                serde_json::to_string(&metadata_json)?
            );

            // --- Generate KERI Identity ---
            println!("   Creating KERI-based organization identity (did:keri)...");

            let backend = std::sync::Arc::new(GitRegistryBackend::from_config_unchecked(
                RegistryConfig::single_tenant(&repo_path),
            ));
            let key_alias = KeyAlias::new_unchecked(key_alias);
            let (controller_did, alias) = initialize_registry_identity(
                backend,
                &key_alias,
                passphrase_provider.as_ref(),
                &get_platform_keychain()?,
                None,
            )
            .context("Failed to initialize org identity")?;

            // --- Create admin self-attestation ---
            println!("   Creating admin attestation for organization creator...");

            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let managed_identity = identity_storage
                .load_identity()
                .context("Failed to load newly created org identity")?;
            let rid = managed_identity.storage_id;

            // Resolve the org's own public key for self-attestation
            let org_resolved = resolver.resolve(controller_did.as_str()).with_context(|| {
                format!(
                    "Failed to resolve public key for org identity: {}",
                    controller_did
                )
            })?;
            let org_pk_bytes = *org_resolved.public_key();

            let admin_capabilities = vec![
                Capability::sign_commit(),
                Capability::sign_release(),
                Capability::manage_members(),
                Capability::rotate_keys(),
            ];

            let meta = AttestationMetadata {
                note: Some(format!("Organization '{}' root admin", name)),
                timestamp: Some(now),
                expires_at: None, // Admin attestation doesn't expire
            };

            let signer = StorageSigner::new(get_platform_keychain()?);
            #[allow(clippy::disallowed_methods)] // INVARIANT: controller_did from storage
            let org_did = DeviceDID::new_unchecked(controller_did.to_string());

            let attestation = create_signed_attestation(
                now,
                &rid,
                &controller_did,
                &org_did,
                org_pk_bytes.as_bytes(),
                Some(serde_json::json!({
                    "org_role": "admin",
                    "org_name": name
                })),
                &meta,
                &signer,
                passphrase_provider.as_ref(),
                Some(&alias),
                None, // Self-attestation, no device signature
                admin_capabilities,
                Some(Role::Admin),
                None, // Root admin has no delegator
                None, // commit_sha
            )
            .context("Failed to create admin attestation")?;

            // Export to Git at the org member ref path
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
                .context("Failed to export admin attestation to Git")?;

            println!("\n✅ Organization identity initialized successfully!");
            println!("   Org Identity ID:    {}", controller_did);
            println!("   Org Name:           {}", name);
            println!("   Repo Path:          {:?}", repo_path);
            println!("   Key Alias:          {}", alias);
            println!("   Admin Role:         Granted with all capabilities");

            if let Some(did_prefix) = controller_did.as_str().strip_prefix("did:keri:") {
                println!(
                    "   KEL Ref:            '{}'",
                    layout::keri_kel_ref(&Prefix::new_unchecked(did_prefix.to_string()))
                );
            }

            println!("   Identity Ref:       '{}'", config.identity_ref);
            println!(
                "   Member Ref:         '{}'",
                config.org_member_ref(controller_did.as_str(), &org_did)
            );
            println!("\n🔑 Store your key passphrase securely.");
            println!(
                "   You can now add members with: auths org add-member --org {} --member <identity-id> --role <role>",
                controller_did
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
            let (stored_did, _role, encrypted_key) = key_storage
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

            let passphrase = passphrase_provider.get_passphrase(&format!(
                "Enter passphrase for org identity key '{}':",
                signer_alias
            ))?;
            let _pkcs8_bytes = decrypt_keypair(&encrypted_key, &passphrase)
                .context("Failed to decrypt signer key (invalid passphrase?)")?;

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: subject_did accepts both did:key and did:keri
            let subject_device_did = DeviceDID::new_unchecked(subject_did.clone());

            // --- Resolve device public key using the custom resolver IF did:key ---
            let device_resolved = resolver.resolve(&subject_did).with_context(|| {
                format!("Failed to resolve public key for subject: {}", subject_did)
            })?;
            let device_pk_bytes = *device_resolved.public_key();

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
                &rid,
                &controller_did,
                &subject_device_did,
                device_pk_bytes.as_bytes(),
                Some(payload),
                &meta,
                &signer,
                passphrase_provider.as_ref(),
                Some(&signer_alias),
                None, // No device signature for org attestations
                vec![],
                None,
                None,
                None, // commit_sha
            )
            .context("Failed to create signed attestation object")?;

            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
                .context("Failed to export attestation to Git")?;

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

            let encrypted_key = get_platform_keychain()?
                .load_key(&signer_alias)
                .context("Failed to load signer key")?
                .2;
            let pass = passphrase_provider.get_passphrase(&format!(
                "Enter passphrase for identity key '{}':",
                signer_alias
            ))?;
            let _pkcs8_bytes =
                decrypt_keypair(&encrypted_key, &pass).context("Failed to decrypt identity key")?;

            #[allow(clippy::disallowed_methods)] // INVARIANT: accepts both did:key and did:keri
            let subject_device_did = DeviceDID::new_unchecked(subject_did.clone());

            // Look up the subject's public key from existing attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let existing = attestation_storage
                .load_attestations_for_device(&subject_device_did)
                .context("Failed to load attestations for subject")?;
            let device_public_key = existing
                .iter()
                .find(|a| !a.device_public_key.is_zero())
                .map(|a| a.device_public_key)
                .unwrap_or_else(|| Ed25519PublicKey::from_bytes([0u8; 32]));

            println!("🔏 Creating signed revocation...");
            let signer = StorageSigner::new(get_platform_keychain()?);
            let attestation = create_signed_revocation(
                &rid,
                &controller_did,
                &subject_device_did,
                device_public_key.as_bytes(),
                note,
                None,
                now,
                &signer,
                passphrase_provider.as_ref(),
                &signer_alias,
            )
            .context("Failed to create revocation")?;

            println!("💾 Writing revocation to Git...");
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
                .context("Failed to write revocation")?;

            println!("\n✅ Revoked authorization for subject {subject_did}");

            Ok(())
        }

        OrgSubcommand::Show {
            subject_did,
            include_revoked,
        } => {
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let resolver = DefaultDidResolver::with_repo(&repo_path);
            let group = AttestationGroup::from_list(attestation_storage.load_all_attestations()?);

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: subject_did from CLI arg, used for lookup only
            let subject_device_did = DeviceDID::new_unchecked(subject_did.clone());
            if let Some(list) = group.by_device.get(subject_device_did.as_str()) {
                for (i, att) in list.iter().enumerate() {
                    if !include_revoked
                        && (att.is_revoked() || att.expires_at.is_some_and(|e| now > e))
                    {
                        continue;
                    }

                    let status = match verify_with_resolver(now, &resolver, att, None) {
                        Ok(_) => "✅ valid",
                        Err(e) if e.to_string().contains("revoked") => "🛑 revoked",
                        Err(e) if e.to_string().contains("expired") => "⌛ expired",
                        Err(_) => "❌ invalid",
                    };

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
            let group = AttestationGroup::from_list(attestation_storage.load_all_attestations()?);

            for (subject, list) in group.by_device.iter() {
                let Some(latest) = list.last() else {
                    continue;
                };
                if !include_revoked
                    && (latest.is_revoked() || latest.expires_at.is_some_and(|e| now > e))
                {
                    continue;
                }

                let status = match verify_with_resolver(now, &resolver, latest, None) {
                    Ok(_) => "✅ valid",
                    Err(e) if e.to_string().contains("revoked") => "🛑 revoked",
                    Err(e) if e.to_string().contains("expired") => "⌛ expired",
                    Err(_) => "❌ invalid",
                };

                println!("- {} [{}]", subject, status);
            }

            Ok(())
        }

        OrgSubcommand::AddMember {
            org,
            member_did: member,
            role: cli_role,
            capabilities,
            key,
            note,
        } => {
            let role = Role::from(cli_role);
            println!("👥 Adding member to organization...");
            println!("   Org:    {}", org);
            println!("   Member: {}", member);
            println!("   Role:   {}", role);

            let signer_alias = KeyAlias::new_unchecked(key.unwrap_or_else(|| {
                format!(
                    "org-{}",
                    org.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_lowercase()
                )
            }));

            let key_storage = get_platform_keychain()?;
            let (stored_did, _role, _encrypted_key) = key_storage
                .load_key(&signer_alias)
                .with_context(|| format!("Failed to load signer key '{}'", signer_alias))?;
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: hex::encode of resolved Ed25519 pubkey always produces valid hex
            let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
                resolver
                    .resolve(stored_did.as_str())
                    .with_context(|| {
                        format!("Failed to resolve public key for admin: {}", stored_did)
                    })?
                    .public_key()
                    .as_bytes(),
            ));

            let member_resolved = resolver
                .resolve(&member)
                .with_context(|| format!("Failed to resolve public key for member: {}", member))?;
            let member_pk = *member_resolved.public_key();

            let capability_strings = if let Some(cap_strs) = capabilities {
                cap_strs
            } else {
                role.default_capabilities()
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect()
            };

            let org_prefix = org.strip_prefix("did:keri:").unwrap_or(&org).to_string();

            let signer = StorageSigner::new(key_storage);
            let uuid_provider = auths_sdk::ports::SystemUuidProvider;

            let org_ctx = OrgContext {
                registry: &*std::sync::Arc::new(GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo_path),
                )),
                clock: &auths_sdk::ports::SystemClock,
                uuid_provider: &uuid_provider,
                signer: &signer,
                passphrase_provider: passphrase_provider.as_ref(),
            };

            let attestation = add_organization_member(
                &org_ctx,
                AddMemberCommand {
                    org_prefix: org_prefix.clone(),
                    member_did: member.clone(),
                    member_public_key: Ed25519PublicKey::try_from_slice(member_pk.as_bytes())
                        .context("Invalid member public key")?,
                    role,
                    capabilities: capability_strings.clone(),
                    admin_public_key_hex: admin_pk_hex,
                    signer_alias,
                    note,
                },
            )
            .context("Failed to add member")?;

            #[allow(clippy::disallowed_methods)] // INVARIANT: member DID from org registry
            let member_did = DeviceDID::new_unchecked(member.clone());
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(
                    &auths_verifier::VerifiedAttestation::dangerous_from_unchecked(
                        attestation.clone(),
                    ),
                )
                .context("Failed to export member attestation to Git")?;

            println!("\n✅ Member added successfully!");
            println!("   Member ID:    {}", member);
            println!("   Role:         {}", role);
            println!("   Capabilities: {}", capability_strings.join(", "));
            println!(
                "   Stored at:    {}",
                config.org_member_ref(&org, &member_did)
            );

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

            let signer_alias = KeyAlias::new_unchecked(key.unwrap_or_else(|| {
                format!(
                    "org-{}",
                    org.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_lowercase()
                )
            }));

            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let invoker_did = identity_storage
                .load_identity()
                .context("Failed to load identity. Are you running this from an org repository?")?
                .controller_did;

            if dry_run {
                return display_dry_run_revoke_member(&org, &member, invoker_did.as_ref());
            }

            let key_storage = get_platform_keychain()?;
            let (stored_did, _role, _encrypted_key) = key_storage
                .load_key(&signer_alias)
                .with_context(|| format!("Failed to load signer key '{}'", signer_alias))?;
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: hex::encode of resolved Ed25519 pubkey always produces valid hex
            let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
                resolver
                    .resolve(stored_did.as_str())
                    .with_context(|| {
                        format!("Failed to resolve public key for admin: {}", stored_did)
                    })?
                    .public_key()
                    .as_bytes(),
            ));

            let member_resolved = resolver
                .resolve(&member)
                .with_context(|| format!("Failed to resolve public key for member: {}", member))?;
            let member_pk = *member_resolved.public_key();

            let org_prefix = org.strip_prefix("did:keri:").unwrap_or(&org).to_string();

            let signer = StorageSigner::new(key_storage);
            let uuid_provider = auths_sdk::ports::SystemUuidProvider;

            let org_ctx = OrgContext {
                registry: &*std::sync::Arc::new(GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo_path),
                )),
                clock: &auths_sdk::ports::SystemClock,
                uuid_provider: &uuid_provider,
                signer: &signer,
                passphrase_provider: passphrase_provider.as_ref(),
            };

            #[allow(clippy::disallowed_methods)] // INVARIANT: member DID from org registry
            let member_did = DeviceDID::new_unchecked(member.clone());
            let revocation = revoke_organization_member(
                &org_ctx,
                RevokeMemberCommand {
                    org_prefix: org_prefix.clone(),
                    member_did: member.clone(),
                    member_public_key: Ed25519PublicKey::try_from_slice(member_pk.as_bytes())
                        .context("Invalid member public key")?,
                    admin_public_key_hex: admin_pk_hex,
                    signer_alias,
                    note: note.clone(),
                },
            )
            .context("Failed to revoke member")?;

            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(revocation))
                .context("Failed to export revocation to Git")?;

            println!("\n✅ Member revoked successfully!");
            println!("   Member ID:  {}", member);
            println!("   Revoked by: {}", invoker_did);
            if let Some(n) = note {
                println!("   Note:       {}", n);
            }
            println!(
                "   Stored at:  {}",
                config.org_member_ref(&org, &member_did)
            );

            Ok(())
        }

        OrgSubcommand::ListMembers {
            org,
            include_revoked,
        } => {
            println!("📋 Listing members of organization: {}", org);

            // Load all attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let all_attestations = attestation_storage.load_all_attestations()?;

            // Build member list with delegation info
            #[allow(clippy::type_complexity)]
            let mut members: Vec<(
                String,
                Option<Role>,
                Option<String>,
                bool,
                Vec<Capability>,
            )> = Vec::new();

            for att in &all_attestations {
                // Skip if revoked and not including revoked
                if att.is_revoked() && !include_revoked {
                    continue;
                }

                // Skip expired attestations
                if att.expires_at.is_some_and(|e| now > e) && !include_revoked {
                    continue;
                }

                members.push((
                    att.subject.to_string(),
                    att.role,
                    att.delegated_by.as_ref().map(|d| d.to_string()),
                    att.is_revoked(),
                    att.capabilities.clone(),
                ));
            }

            if members.is_empty() {
                println!("\nNo members found for organization.");
                return Ok(());
            }

            members.sort_by(|a, b| {
                member_role_order(&a.1)
                    .cmp(&member_role_order(&b.1))
                    .then_with(|| a.0.cmp(&b.0))
            });

            println!("\nOrg: {}", org);
            println!("\nMembers ({} total):", members.len());
            println!("─────────────────────────────────────────");

            for (member_did, role, delegated_by, revoked, capabilities) in &members {
                let role_str = role.as_ref().map(|r| r.as_str()).unwrap_or("unknown");
                let status = if *revoked { " (revoked)" } else { "" };

                // Determine tree prefix based on delegator
                let prefix = if delegated_by.is_none() {
                    "├─ "
                } else {
                    "│  └─ "
                };

                // Format capabilities
                let caps: Vec<String> = capabilities.iter().map(|c| format!("{:?}", c)).collect();
                let caps_str = if caps.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", caps.join(", "))
                };

                println!(
                    "{}{} [{}]{}{}",
                    prefix, member_did, role_str, status, caps_str
                );

                if let Some(delegator) = delegated_by {
                    println!("│     delegated by: {}", delegator);
                }
            }

            println!("─────────────────────────────────────────");

            if !include_revoked {
                let revoked_count = all_attestations.iter().filter(|a| a.is_revoked()).count();
                if revoked_count > 0 {
                    println!(
                        "\n({} revoked member(s) hidden. Use --include-revoked to show.)",
                        revoked_count
                    );
                }
            }

            Ok(())
        }

        OrgSubcommand::Join { code, registry } => handle_join(&code, &registry),
    }
}

/// Handles the `org join` subcommand by looking up and accepting an invite
/// via the registry HTTP API.
fn handle_join(code: &str, registry: &str) -> Result<()> {
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
    let (_stored_did, _role, encrypted_key) = key_storage
        .load_key(&primary_alias)
        .context("failed to load signing key — run `auths init` first")?;

    let passphrase =
        rpassword::prompt_password("Enter passphrase: ").context("failed to read passphrase")?;
    let pkcs8_bytes = decrypt_keypair(&encrypted_key, &passphrase).context("wrong passphrase")?;

    let pkcs8 = auths_crypto::Pkcs8Der::new(&pkcs8_bytes[..]);
    let seed = auths_sdk::crypto::extract_seed_from_pkcs8(&pkcs8)
        .context("failed to extract seed from key material")?;

    // Create a signed bearer payload: { did, timestamp, signature }
    #[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
    let timestamp = Utc::now().to_rfc3339();
    let message = format!("{}\n{}", did, timestamp);
    let signature = {
        use ring::signature::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes())
            .map_err(|e| anyhow!("invalid key: {e}"))?;
        let sig = kp.sign(message.as_bytes());
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
    };

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
