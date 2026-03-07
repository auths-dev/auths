//! PKCS#11 HSM key storage and signing backend.
//!
//! Provides [`Pkcs11KeyRef`] (implements [`KeyStorage`]) for managing Ed25519 keys
//! on a PKCS#11 hardware security module, and [`Pkcs11Signer`] (implements
//! [`SecureSigner`](crate::signing::SecureSigner)) for delegating signing to the HSM.

use crate::config::Pkcs11Config;
use crate::error::AgentError;
use crate::signing::{PassphraseProvider, SecureSigner};
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use log::info;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// JSON-serializable reference to a key stored on a PKCS#11 token.
///
/// Stored in the `encrypted_key_data` field of `KeyStorage::store_key` in place
/// of actual encrypted bytes — the real key never leaves the HSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11KeyReference {
    /// Numeric PKCS#11 slot that holds the token.
    pub slot_id: u64,
    /// Human-readable label of the token.
    pub token_label: String,
    /// Label of the private key object on the token.
    pub key_label: String,
}

/// Ed25519 OID for PKCS#11 EC params (`edwards25519` as PrintableString).
const ED25519_EC_PARAMS: &[u8] = &[
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
];

/// PKCS#11 key storage backend.
///
/// Manages Ed25519 keys resident on a PKCS#11 HSM. Keys are generated on-token
/// and never exported. The `KeyStorage` trait stores serialised
/// [`Pkcs11KeyReference`] structs rather than encrypted key material.
///
/// Args:
/// * `config`: A [`Pkcs11Config`] with library path, slot/token, PIN, and key label.
///
/// Usage:
/// ```ignore
/// let config = Pkcs11Config::from_env();
/// let keyref = Pkcs11KeyRef::new(&config)?;
/// let aliases = keyref.list_aliases()?;
/// ```
pub struct Pkcs11KeyRef {
    ctx: Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: AuthPin,
    token_label: String,
}

impl std::fmt::Debug for Pkcs11KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11KeyRef")
            .field("slot", &self.slot)
            .field("token_label", &self.token_label)
            .finish_non_exhaustive()
    }
}

impl Pkcs11KeyRef {
    /// Creates a new PKCS#11 key storage backend.
    ///
    /// Validates that the library loads, the slot exists, the token is present,
    /// and `CKM_EDDSA` is supported.
    ///
    /// Args:
    /// * `config`: PKCS#11 configuration from environment variables.
    ///
    /// Usage:
    /// ```ignore
    /// let keyref = Pkcs11KeyRef::new(&Pkcs11Config::from_env())?;
    /// ```
    pub fn new(config: &Pkcs11Config) -> Result<Self, AgentError> {
        let library_path =
            config
                .library_path
                .as_ref()
                .ok_or_else(|| AgentError::BackendInitFailed {
                    backend: "pkcs11",
                    error: "AUTHS_PKCS11_LIBRARY not set".into(),
                })?;

        let ctx = Pkcs11::new(library_path).map_err(|e| AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!(
                "failed to load PKCS#11 library {}: {}",
                library_path.display(),
                e
            ),
        })?;

        pkcs11_initialize(&ctx)?;

        let slot = resolve_slot(&ctx, config)?;

        let pin_str = config.pin.as_deref().unwrap_or("");
        let pin = AuthPin::new(pin_str.into());

        let token_label = config
            .token_label
            .clone()
            .unwrap_or_else(|| "auths".to_string());

        validate_eddsa_support(&ctx, slot)?;

        Ok(Self {
            ctx,
            slot,
            pin,
            token_label,
        })
    }

    fn open_rw_session(&self) -> Result<Session, AgentError> {
        let session = self
            .ctx
            .open_rw_session(self.slot)
            .map_err(map_session_error)?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(map_login_error)?;
        Ok(session)
    }

    fn open_ro_session(&self) -> Result<Session, AgentError> {
        let session = self
            .ctx
            .open_ro_session(self.slot)
            .map_err(map_session_error)?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(map_login_error)?;
        Ok(session)
    }

    fn find_private_key_by_label(
        session: &Session,
        label: &str,
    ) -> Result<ObjectHandle, AgentError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let objects = session.find_objects(&template).map_err(map_session_error)?;
        objects.into_iter().next().ok_or(AgentError::KeyNotFound)
    }

    fn find_public_key_by_label(
        session: &Session,
        label: &str,
    ) -> Result<ObjectHandle, AgentError> {
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let objects = session.find_objects(&template).map_err(map_session_error)?;
        objects.into_iter().next().ok_or(AgentError::KeyNotFound)
    }
}

impl KeyStorage for Pkcs11KeyRef {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        _role: KeyRole,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let session = self.open_rw_session()?;
        let label = alias.as_str().as_bytes().to_vec();
        let id = identity_did.as_str().as_bytes().to_vec();

        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
            Attribute::EcParams(ED25519_EC_PARAMS.to_vec()),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label),
            Attribute::Id(id),
        ];

        session
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &pub_template,
                &priv_template,
            )
            .map_err(|e| AgentError::CryptoError(format!("PKCS#11 key generation failed: {e}")))?;

        info!("generated Ed25519 key pair on PKCS#11 token for alias '{alias}'");
        Ok(())
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let session = self.open_ro_session()?;
        let handle = Self::find_public_key_by_label(&session, alias.as_str())?;

        let attrs = session
            .get_attributes(handle, &[AttributeType::Id])
            .map_err(map_session_error)?;

        let id_bytes = attrs
            .iter()
            .find_map(|a| match a {
                Attribute::Id(v) => Some(v.clone()),
                _ => None,
            })
            .ok_or(AgentError::KeyNotFound)?;

        let identity_did = IdentityDID::new(
            String::from_utf8(id_bytes)
                .map_err(|e| AgentError::KeyDeserializationError(e.to_string()))?,
        );

        let reference = Pkcs11KeyReference {
            slot_id: 0, // filled from context
            token_label: self.token_label.clone(),
            key_label: alias.as_str().to_string(),
        };
        let ref_bytes = serde_json::to_vec(&reference)
            .map_err(|e| AgentError::KeyDeserializationError(e.to_string()))?;

        // HSM keys are always Primary
        Ok((identity_did, KeyRole::Primary, ref_bytes))
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let session = self.open_rw_session()?;

        if let Ok(handle) = Self::find_private_key_by_label(&session, alias.as_str()) {
            session.destroy_object(handle).map_err(map_session_error)?;
        }
        if let Ok(handle) = Self::find_public_key_by_label(&session, alias.as_str()) {
            session.destroy_object(handle).map_err(map_session_error)?;
        }

        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        let session = self.open_ro_session()?;
        let template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let objects = session.find_objects(&template).map_err(map_session_error)?;

        let mut aliases = Vec::new();
        for handle in objects {
            let attrs = session
                .get_attributes(handle, &[AttributeType::Label])
                .map_err(map_session_error)?;
            if let Some(Attribute::Label(label_bytes)) = attrs.into_iter().next()
                && let Ok(label) = String::from_utf8(label_bytes)
            {
                aliases.push(KeyAlias::new_unchecked(label));
            }
        }
        Ok(aliases)
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let session = self.open_ro_session()?;
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(identity_did.as_str().as_bytes().to_vec()),
        ];
        let objects = session.find_objects(&template).map_err(map_session_error)?;

        let mut aliases = Vec::new();
        for handle in objects {
            let attrs = session
                .get_attributes(handle, &[AttributeType::Label])
                .map_err(map_session_error)?;
            if let Some(Attribute::Label(label_bytes)) = attrs.into_iter().next()
                && let Ok(label) = String::from_utf8(label_bytes)
            {
                aliases.push(KeyAlias::new_unchecked(label));
            }
        }
        Ok(aliases)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let session = self.open_ro_session()?;
        let handle = Self::find_private_key_by_label(&session, alias.as_str())?;

        let attrs = session
            .get_attributes(handle, &[AttributeType::Id])
            .map_err(map_session_error)?;

        let id_bytes = attrs
            .iter()
            .find_map(|a| match a {
                Attribute::Id(v) => Some(v.clone()),
                _ => None,
            })
            .ok_or(AgentError::KeyNotFound)?;

        Ok(IdentityDID::new(String::from_utf8(id_bytes).map_err(
            |e| AgentError::KeyDeserializationError(e.to_string()),
        )?))
    }

    fn backend_name(&self) -> &'static str {
        "pkcs11"
    }
}

/// PKCS#11 signing backend.
///
/// Delegates Ed25519 signing to the HSM via `CKM_EDDSA`. The private key never
/// leaves hardware. Implements [`SecureSigner`] — the `passphrase_provider`
/// parameter is ignored because HSM authentication uses the PIN from config.
///
/// Args:
/// * `config`: A [`Pkcs11Config`] with library path, slot/token, and PIN.
///
/// Usage:
/// ```ignore
/// let signer = Pkcs11Signer::new(&Pkcs11Config::from_env())?;
/// let sig = signer.sign_with_alias(&alias, &provider, b"hello")?;
/// ```
pub struct Pkcs11Signer {
    ctx: Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: AuthPin,
}

impl Pkcs11Signer {
    /// Creates a new PKCS#11 signer.
    ///
    /// Args:
    /// * `config`: PKCS#11 configuration.
    ///
    /// Usage:
    /// ```ignore
    /// let signer = Pkcs11Signer::new(&config)?;
    /// ```
    pub fn new(config: &Pkcs11Config) -> Result<Self, AgentError> {
        let library_path =
            config
                .library_path
                .as_ref()
                .ok_or_else(|| AgentError::BackendInitFailed {
                    backend: "pkcs11",
                    error: "AUTHS_PKCS11_LIBRARY not set".into(),
                })?;

        let ctx = Pkcs11::new(library_path).map_err(|e| AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!("failed to load PKCS#11 library: {e}"),
        })?;

        pkcs11_initialize(&ctx)?;

        let slot = resolve_slot(&ctx, config)?;
        let pin_str = config.pin.as_deref().unwrap_or("");
        let pin = AuthPin::new(pin_str.into());

        validate_eddsa_support(&ctx, slot)?;

        Ok(Self { ctx, slot, pin })
    }

    fn open_session_and_login(&self) -> Result<Session, AgentError> {
        let session = self
            .ctx
            .open_ro_session(self.slot)
            .map_err(map_session_error)?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(map_login_error)?;
        Ok(session)
    }
}

impl SecureSigner for Pkcs11Signer {
    fn sign_with_alias(
        &self,
        alias: &KeyAlias,
        _passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let session = self.open_session_and_login()?;
        let handle = Pkcs11KeyRef::find_private_key_by_label(&session, alias.as_str())?;

        let signature = session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
                handle,
                message,
            )
            .map_err(|e| AgentError::SigningFailed(format!("PKCS#11 sign failed: {e}")))?;

        Ok(signature)
    }

    fn sign_for_identity(
        &self,
        identity_did: &IdentityDID,
        _passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let session = self.open_session_and_login()?;

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(identity_did.as_str().as_bytes().to_vec()),
        ];
        let objects = session.find_objects(&template).map_err(map_session_error)?;
        let handle = objects.into_iter().next().ok_or(AgentError::KeyNotFound)?;

        let signature = session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
                handle,
                message,
            )
            .map_err(|e| AgentError::SigningFailed(format!("PKCS#11 sign failed: {e}")))?;

        Ok(signature)
    }
}

/// CKR_CRYPTOKI_ALREADY_INITIALIZED is safe to ignore — the library is usable.
fn pkcs11_initialize(ctx: &Pkcs11) -> Result<(), AgentError> {
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => Ok(()),
        Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(()),
        Err(e) => Err(AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!("C_Initialize failed: {e}"),
        }),
    }
}

fn resolve_slot(ctx: &Pkcs11, config: &Pkcs11Config) -> Result<cryptoki::slot::Slot, AgentError> {
    if let Some(slot_id) = config.slot_id {
        let slots = ctx
            .get_all_slots()
            .map_err(|e| AgentError::BackendInitFailed {
                backend: "pkcs11",
                error: format!("failed to enumerate slots: {e}"),
            })?;
        return slots
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or_else(|| AgentError::BackendInitFailed {
                backend: "pkcs11",
                error: format!("slot {slot_id} not found"),
            });
    }

    if let Some(ref label) = config.token_label {
        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| AgentError::BackendInitFailed {
                backend: "pkcs11",
                error: format!("failed to enumerate token slots: {e}"),
            })?;
        for slot in slots {
            if let Ok(info) = ctx.get_token_info(slot) {
                let token_label = info.label().trim();
                if token_label == label {
                    return Ok(slot);
                }
            }
        }
        return Err(AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!("no token with label '{label}' found"),
        });
    }

    // Default: first slot with a token
    let slots = ctx
        .get_slots_with_token()
        .map_err(|e| AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!("failed to enumerate slots: {e}"),
        })?;
    slots
        .into_iter()
        .next()
        .ok_or_else(|| AgentError::BackendUnavailable {
            backend: "pkcs11",
            reason: "no PKCS#11 tokens found".into(),
        })
}

fn validate_eddsa_support(ctx: &Pkcs11, slot: cryptoki::slot::Slot) -> Result<(), AgentError> {
    let mechs = ctx
        .get_mechanism_list(slot)
        .map_err(|e| AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: format!("failed to list mechanisms: {e}"),
        })?;

    let has_eddsa = mechs.contains(&cryptoki::mechanism::MechanismType::EDDSA);

    if !has_eddsa {
        return Err(AgentError::HsmUnsupportedMechanism(
            "CKM_EDDSA not supported by this token".into(),
        ));
    }
    Ok(())
}

fn map_session_error(e: cryptoki::error::Error) -> AgentError {
    let msg = e.to_string();
    if msg.contains("TOKEN_NOT_PRESENT") || msg.contains("DEVICE_REMOVED") {
        AgentError::HsmDeviceRemoved
    } else if msg.contains("SESSION_CLOSED") || msg.contains("SESSION_HANDLE_INVALID") {
        AgentError::HsmSessionExpired
    } else {
        AgentError::SecurityError(format!("PKCS#11 error: {msg}"))
    }
}

fn map_login_error(e: cryptoki::error::Error) -> AgentError {
    let msg = e.to_string();
    if msg.contains("PIN_LOCKED") {
        AgentError::HsmPinLocked
    } else if msg.contains("PIN_INCORRECT") {
        AgentError::IncorrectPassphrase
    } else {
        map_session_error(e)
    }
}

/// Creates a `Pkcs11Config` from individual arguments (useful for CLI wiring).
///
/// Args:
/// * `library`: Path to the PKCS#11 shared library.
/// * `token_label`: Token label for slot lookup.
/// * `pin`: User PIN for authentication.
/// * `key_label`: Default key label.
///
/// Usage:
/// ```ignore
/// let config = pkcs11_config_from_args("/usr/lib/libsofthsm2.so", "auths", "1234", "default");
/// let keyref = Pkcs11KeyRef::new(&config)?;
/// ```
pub fn pkcs11_config_from_args(
    library: &str,
    token_label: &str,
    pin: &str,
    key_label: &str,
) -> Pkcs11Config {
    Pkcs11Config {
        library_path: Some(PathBuf::from(library)),
        slot_id: None,
        token_label: Some(token_label.to_string()),
        pin: Some(pin.to_string()),
        key_label: Some(key_label.to_string()),
    }
}
