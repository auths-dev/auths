use anyhow::{Context, Result, anyhow};
use auths_core::crypto::signer::decrypt_keypair;
use auths_id::attestation::create::create_signed_attestation;
use auths_id::attestation::revoke::create_signed_revocation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::identity::resolve::DidResolver;
use chrono::{DateTime, Utc};
use clap::{ArgAction, Parser, Subcommand};
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
use auths_id::{
    attestation::{export::AttestationSink, group::AttestationGroup, verify::verify_with_resolver},
    identity::resolve::DefaultDidResolver,
    storage::git_refs::AttestationMetadata,
    storage::{
        attestation::AttestationSource,
        identity::IdentityStorage,
        layout::{self, StorageLayoutConfig},
    },
};

use auths_sdk::workflows::org::{Role, member_role_order};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::types::DeviceDID;
use auths_verifier::{Capability, Ed25519PublicKey, Prefix};

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
pub struct OrgCommand {
    #[clap(subcommand)]
    pub subcommand: OrgSubcommand,

    #[command(flatten)]
    pub overrides: crate::commands::registry_overrides::RegistryOverrides,
}

/// Subcommands for managing authorizations issued by this identity.
#[derive(Subcommand, Debug, Clone)]
pub enum OrgSubcommand {
    /// Initialize a new organization identity
    Init {
        /// Organization name
        #[arg(long)]
        name: String,

        /// Alias for the local signing key (auto-generated if not provided)
        #[arg(long)]
        local_key_alias: Option<String>,

        /// Optional metadata file (if provided, merged with org metadata)
        #[arg(long)]
        metadata_file: Option<PathBuf>,
    },
    Attest {
        #[arg(long)]
        subject: String,
        #[arg(long)]
        payload_file: PathBuf,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        signer_alias: Option<String>,
    },
    Revoke {
        #[arg(long)]
        subject: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        signer_alias: Option<String>,
    },
    Show {
        #[arg(long)]
        subject: String,
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
        #[arg(long)]
        member: String,

        /// Role to assign (admin, member, readonly)
        #[arg(long, value_enum)]
        role: CliRole,

        /// Override default capabilities (comma-separated)
        #[arg(long, value_delimiter = ',')]
        capabilities: Option<Vec<String>>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        signer_alias: Option<String>,

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
        #[arg(long)]
        member: String,

        /// Reason for revocation
        #[arg(long)]
        note: Option<String>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        signer_alias: Option<String>,
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
}

/// Handles `org` commands for issuing or revoking member authorizations.
pub fn handle_org(
    cmd: OrgCommand,
    repo_opt: Option<PathBuf>,
    identity_ref_override: Option<String>,
    identity_blob_name_override: Option<String>,
    attestation_prefix_override: Option<String>,
    attestation_blob_name_override: Option<String>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
) -> Result<()> {
    let repo_path = layout::resolve_repo_path(repo_opt)?;

    let mut config = StorageLayoutConfig::default();
    if let Some(r) = identity_ref_override {
        config.identity_ref = r.into();
    }
    if let Some(b) = identity_blob_name_override {
        config.identity_blob_name = b.into();
    }
    if let Some(p) = attestation_prefix_override {
        config.device_attestation_prefix = p.into();
    }
    if let Some(b) = attestation_blob_name_override {
        config.attestation_blob_name = b.into();
    }

    let _attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
    let resolver: DefaultDidResolver = DefaultDidResolver::with_repo(&repo_path);

    match cmd.subcommand {
        OrgSubcommand::Init {
            name,
            local_key_alias,
            metadata_file,
        } => {
            // Generate a key alias if not provided
            let key_alias = local_key_alias.unwrap_or_else(|| {
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
                "created_at": Utc::now().to_rfc3339()
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
            let org_resolved = resolver
                .resolve(controller_did.as_str())
                .with_context(|| {
                    format!(
                        "Failed to resolve public key for org identity: {}",
                        controller_did
                    )
                })?;
            let org_pk_bytes = *org_resolved.public_key();

            let now = Utc::now();
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
            let org_did = DeviceDID::new(controller_did.to_string());

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
            subject,      // The subject DID (String)
            payload_file, // Path to the JSON payload
            note,         // Optional note (String)
            expires_at,   // Optional RFC3339 expiration string
            signer_alias, // Alias of the org's signing key in keychain
        } => {
            let signer_alias = signer_alias
                .ok_or_else(|| anyhow!("Signer key alias must be provided with --signer-alias"))?;
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
            let (stored_did, encrypted_key) = key_storage
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

            let subject_did = DeviceDID::new(subject.clone());

            // --- Resolve device public key using the custom resolver IF did:key ---
            let device_resolved = resolver
                .resolve(&subject)
                .with_context(|| format!("Failed to resolve public key for subject: {}", subject))?;
            let device_pk_bytes = *device_resolved.public_key();

            let now = Utc::now();
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
                &subject_did,
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
            )
            .context("Failed to create signed attestation object")?;

            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
                .context("Failed to export attestation to Git")?;

            println!(
                "\n✅ Org attestation created successfully from '{}' → '{}'",
                controller_did, subject_did
            );

            Ok(())
        }

        OrgSubcommand::Revoke {
            subject,
            note,
            signer_alias,
        } => {
            println!("🛑 Revoking org authorization for subject: {subject}");
            println!("   Using Repository:         {:?}", repo_path);
            println!("   Using Identity Ref:       '{}'", config.identity_ref);
            println!(
                "   Using Attestation Prefix: '{}'",
                config.device_attestation_prefix
            );

            let signer_alias = signer_alias
                .ok_or_else(|| anyhow!("Signer key alias must be provided for revocation"))?;
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
                .1;
            let pass = passphrase_provider.get_passphrase(&format!(
                "Enter passphrase for identity key '{}':",
                signer_alias
            ))?;
            let _pkcs8_bytes =
                decrypt_keypair(&encrypted_key, &pass).context("Failed to decrypt identity key")?;

            // Allow both did:key and did:keri as subject input
            let subject_did = DeviceDID::new(subject.clone());
            let now = Utc::now();

            // Look up the subject's public key from existing attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let existing = attestation_storage
                .load_attestations_for_device(&subject_did)
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
                &subject_did,
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

            println!("\n✅ Revoked authorization for subject {subject}");

            Ok(())
        }

        OrgSubcommand::Show {
            subject,
            include_revoked,
        } => {
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let resolver = DefaultDidResolver::with_repo(&repo_path);
            let group = AttestationGroup::from_list(attestation_storage.load_all_attestations()?);

            let subject_did = DeviceDID(subject.clone());
            if let Some(list) = group.by_device.get(subject_did.as_str()) {
                for (i, att) in list.iter().enumerate() {
                    if !include_revoked
                        && (att.is_revoked() || att.expires_at.is_some_and(|e| Utc::now() > e))
                    {
                        continue;
                    }

                    let status = match verify_with_resolver(Utc::now(), &resolver, att) {
                        Ok(_) => "✅ valid",
                        Err(e) if e.to_string().contains("revoked") => "🛑 revoked",
                        Err(e) if e.to_string().contains("expired") => "⌛ expired",
                        Err(_) => "❌ invalid",
                    };

                    println!(
                        "{i}. [{}] @ {}",
                        status,
                        att.timestamp.unwrap_or(Utc::now())
                    );
                    if let Some(note) = &att.note {
                        println!("   📝 {}", note);
                    }
                    if let Some(payload) = &att.payload {
                        println!("   📦 {}", serde_json::to_string_pretty(payload)?);
                    }
                }
            } else {
                println!("No authorizations found for subject: {}", subject);
            }

            Ok(())
        }

        OrgSubcommand::List { include_revoked } => {
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let resolver = DefaultDidResolver::with_repo(&repo_path);
            let group = AttestationGroup::from_list(attestation_storage.load_all_attestations()?);

            for (subject, list) in group.by_device.iter() {
                let latest = list.last().unwrap();
                if !include_revoked
                    && (latest.is_revoked() || latest.expires_at.is_some_and(|e| Utc::now() > e))
                {
                    continue;
                }

                let status = match verify_with_resolver(Utc::now(), &resolver, latest) {
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
            member,
            role: cli_role,
            capabilities,
            signer_alias,
            note,
        } => {
            let role = Role::from(cli_role);
            println!("👥 Adding member to organization...");
            println!("   Org:    {}", org);
            println!("   Member: {}", member);
            println!("   Role:   {}", role);

            // Load invoker's identity and key
            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let managed_identity = identity_storage
                .load_identity()
                .context("Failed to load identity. Are you running this from an org repository?")?;
            let invoker_did = managed_identity.controller_did.clone();
            let rid = managed_identity.storage_id;

            // Determine signer alias
            let signer_alias = KeyAlias::new_unchecked(signer_alias.unwrap_or_else(|| {
                // Try to derive alias from org name in identity metadata
                format!(
                    "org-{}",
                    org.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_lowercase()
                )
            }));

            // Verify invoker has ManageMembers capability
            // First, load the invoker's own org attestation to check capabilities
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let invoker_did_device = DeviceDID::new(invoker_did.to_string());
            let invoker_attestations = attestation_storage.load_all_attestations()?;

            // Find invoker's attestation for this org
            let invoker_has_manage_members = invoker_attestations.iter().any(|att| {
                att.subject.as_str() == invoker_did_device.as_str()
                    && !att.is_revoked()
                    && att.capabilities.contains(&Capability::manage_members())
            });

            if !invoker_has_manage_members {
                return Err(anyhow!(
                    "You don't have ManageMembers capability for org '{}'. Only org admins can add members.",
                    org
                ));
            }

            // Load signer key and verify passphrase
            let key_storage = get_platform_keychain()?;
            let (stored_did, encrypted_key) = key_storage
                .load_key(&signer_alias)
                .with_context(|| format!("Failed to load signer key '{}'", signer_alias))?;

            if stored_did != invoker_did {
                return Err(anyhow!(
                    "Signer key alias '{}' belongs to DID '{}', but loaded identity is '{}'",
                    signer_alias,
                    stored_did,
                    invoker_did
                ));
            }

            let passphrase = passphrase_provider
                .get_passphrase(&format!("Enter passphrase for org key '{}':", signer_alias))?;
            let _pkcs8_bytes = decrypt_keypair(&encrypted_key, &passphrase)
                .context("Failed to decrypt signer key (invalid passphrase?)")?;

            // Resolve member's public key
            let member_did = DeviceDID::new(member.clone());
            let member_resolved = resolver
                .resolve(&member)
                .with_context(|| format!("Failed to resolve public key for member: {}", member))?;
            let member_pk_bytes = *member_resolved.public_key();


            // Determine capabilities: use override if provided, otherwise use role defaults
            let member_capabilities = if let Some(cap_strs) = capabilities {
                cap_strs
                    .iter()
                    .map(|s| {
                        s.parse::<Capability>().unwrap_or_else(|e| {
                            eprintln!("error: {e}");
                            std::process::exit(2);
                        })
                    })
                    .collect()
            } else {
                role.default_capabilities()
            };

            println!(
                "   Capabilities: {:?}",
                member_capabilities
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            // Create the attestation
            let now = Utc::now();
            let meta = AttestationMetadata {
                note: note.or_else(|| Some(format!("Added as {} by {}", role, invoker_did))),
                timestamp: Some(now),
                expires_at: None, // Member attestations don't expire by default
            };

            let signer = StorageSigner::new(key_storage);
            let attestation = create_signed_attestation(
                now,
                &rid,
                &invoker_did,
                &member_did,
                member_pk_bytes.as_bytes(),
                Some(serde_json::json!({
                    "org_role": role.to_string(),
                    "org_did": org
                })),
                &meta,
                &signer,
                passphrase_provider.as_ref(),
                Some(&signer_alias),
                None, // No device signature for org membership attestations
                member_capabilities.clone(),
                Some(role),
                Some(invoker_did.clone()),
            )
            .context("Failed to create member attestation")?;

            // Export to Git at the org member ref path
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            attestation_storage
                .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
                .context("Failed to export member attestation to Git")?;

            println!("\n✅ Member added successfully!");
            println!("   Member ID:    {}", member);
            println!("   Role:         {}", role);
            println!(
                "   Capabilities: {}",
                member_capabilities
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("   Delegated by: {}", invoker_did);
            println!(
                "   Stored at:    {}",
                config.org_member_ref(&org, &member_did)
            );

            Ok(())
        }

        OrgSubcommand::RevokeMember {
            org,
            member,
            note,
            signer_alias,
        } => {
            println!("🛑 Revoking member from organization...");
            println!("   Org:    {}", org);
            println!("   Member: {}", member);

            // Load invoker's identity and key
            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let managed_identity = identity_storage
                .load_identity()
                .context("Failed to load identity. Are you running this from an org repository?")?;
            let invoker_did = managed_identity.controller_did.clone();
            let rid = managed_identity.storage_id;

            // Determine signer alias
            let signer_alias = KeyAlias::new_unchecked(signer_alias.unwrap_or_else(|| {
                format!(
                    "org-{}",
                    org.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_lowercase()
                )
            }));

            // Verify invoker has ManageMembers capability
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let invoker_did_device = DeviceDID::new(invoker_did.to_string());
            let all_attestations = attestation_storage.load_all_attestations()?;

            // Find invoker's attestation for this org
            let invoker_has_manage_members = all_attestations.iter().any(|att| {
                att.subject.as_str() == invoker_did_device.as_str()
                    && !att.is_revoked()
                    && att.capabilities.contains(&Capability::manage_members())
            });

            if !invoker_has_manage_members {
                return Err(anyhow!(
                    "You don't have ManageMembers capability for org '{}'. Only org admins can revoke members.",
                    org
                ));
            }

            // Check if member exists and is not already revoked
            let member_did = DeviceDID::new(member.clone());
            let member_attestation = all_attestations
                .iter()
                .find(|att| att.subject.as_str() == member_did.as_str());

            match member_attestation {
                None => {
                    return Err(anyhow!(
                        "Member '{}' is not a member of org '{}'. Cannot revoke.",
                        member,
                        org
                    ));
                }
                Some(att) if att.is_revoked() => {
                    return Err(anyhow!(
                        "Member '{}' is already revoked from org '{}'.",
                        member,
                        org
                    ));
                }
                Some(_) => {} // Member exists and is active, proceed
            }

            // Load signer key and verify passphrase
            let key_storage = get_platform_keychain()?;
            let (stored_did, encrypted_key) = key_storage
                .load_key(&signer_alias)
                .with_context(|| format!("Failed to load signer key '{}'", signer_alias))?;

            if stored_did != invoker_did {
                return Err(anyhow!(
                    "Signer key alias '{}' belongs to DID '{}', but loaded identity is '{}'",
                    signer_alias,
                    stored_did,
                    invoker_did
                ));
            }

            let passphrase = passphrase_provider
                .get_passphrase(&format!("Enter passphrase for org key '{}':", signer_alias))?;
            let _pkcs8_bytes = decrypt_keypair(&encrypted_key, &passphrase)
                .context("Failed to decrypt signer key (invalid passphrase?)")?;

            // Look up the member's public key from existing attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let existing = attestation_storage
                .load_attestations_for_device(&member_did)
                .context("Failed to load attestations for member")?;
            let member_public_key = existing
                .iter()
                .find(|a| !a.device_public_key.is_zero())
                .map(|a| a.device_public_key)
                .unwrap_or_else(|| Ed25519PublicKey::from_bytes([0u8; 32]));

            // Create revocation
            let now = Utc::now();
            let signer = StorageSigner::new(key_storage);

            println!("🔏 Creating signed revocation...");
            let revocation = create_signed_revocation(
                &rid,
                &invoker_did,
                &member_did,
                member_public_key.as_bytes(),
                note.clone(),
                None, // No expiration for revocations
                now,
                &signer,
                passphrase_provider.as_ref(),
                &signer_alias,
            )
            .context("Failed to create revocation")?;

            // Export to Git
            println!("💾 Writing revocation to Git...");
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
                if att.expires_at.is_some_and(|e| Utc::now() > e) && !include_revoked {
                    continue;
                }

                members.push((
                    att.subject.to_string(),
                    att.role.clone(),
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
    }
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for OrgCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_org(
            self.clone(),
            ctx.repo_path.clone(),
            self.overrides.identity_ref.clone(),
            self.overrides.identity_blob.clone(),
            self.overrides.attestation_prefix.clone(),
            self.overrides.attestation_blob.clone(),
            ctx.passphrase_provider.clone(),
        )
    }
}
