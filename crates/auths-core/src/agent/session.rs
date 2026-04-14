//! SSH agent session handler.
//!
//! This module provides `AgentSession`, which implements the `ssh_agent_lib::agent::Session`
//! trait to handle SSH agent protocol requests.

use crate::agent::AgentHandle;
use crate::error::AgentError as AuthsAgentError;
use log::{debug, error, warn};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError as SSHAgentError;
use ssh_agent_lib::proto::{AddIdentity, Credential, Identity, RemoveIdentity, SignRequest};
use ssh_key::private::KeypairData;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, Signature};
use std::convert::TryInto;
use std::io;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Wraps an `AgentHandle` to implement the `ssh_agent_lib::agent::Session` trait.
///
/// Each `AgentSession` holds a reference to an `AgentHandle`, enabling multiple
/// independent agent instances to coexist.
#[derive(Clone)]
pub struct AgentSession {
    /// Reference to the agent handle
    handle: Arc<AgentHandle>,
}

impl AgentSession {
    /// Creates a new AgentSession wrapping the given AgentHandle.
    pub fn new(handle: Arc<AgentHandle>) -> Self {
        Self { handle }
    }

    /// Returns a reference to the underlying agent handle.
    pub fn handle(&self) -> &AgentHandle {
        &self.handle
    }
}

impl std::fmt::Debug for AgentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSession")
            .field("socket_path", self.handle.socket_path())
            .field("is_running", &self.handle.is_running())
            .finish()
    }
}

/// Build a PKCS#8 v2 DER encoding for an Ed25519 key from seed and public key.
///
/// Ring's `Ed25519KeyPair::from_pkcs8()` requires v2 format (RFC 8410) which
/// includes the public key. Produces the fixed 85-byte structure:
pub use auths_crypto::build_ed25519_pkcs8_v2;

#[ssh_agent_lib::async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SSHAgentError> {
        let core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        let pubkey_byte_vectors = core.public_keys();
        debug!(
            "request_identities: Agent core has {} keys.",
            pubkey_byte_vectors.len()
        );

        let identities = pubkey_byte_vectors
            .into_iter()
            .filter_map(|pubkey_bytes| {
                let key_data = match pubkey_bytes.len() {
                    32 => {
                        let key_bytes_array: &[u8; 32] = pubkey_bytes.as_slice().try_into().ok()?;
                        KeyData::Ed25519(Ed25519PublicKey(*key_bytes_array))
                    }
                    33 | 65 => {
                        // P-256: try to parse as ECDSA SEC1 point
                        let ecdsa_pk =
                            ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&pubkey_bytes).ok()?;
                        KeyData::Ecdsa(ecdsa_pk)
                    }
                    n => {
                        warn!("request_identities: unsupported key length ({n}). Skipping.");
                        return None;
                    }
                };
                let comment = format!(
                    "auths-key-{}",
                    hex::encode(&pubkey_bytes[..4.min(pubkey_bytes.len())])
                );
                debug!("Adding identity with comment: {}", comment);
                Some(Identity {
                    pubkey: key_data,
                    comment,
                })
            })
            .collect();

        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, SSHAgentError> {
        debug!(
            "Handling sign request for key type: {:?}",
            request.pubkey.algorithm()
        );

        let (pubkey_bytes_to_sign_with, algorithm) = match &request.pubkey {
            KeyData::Ed25519(key) => (key.as_ref().to_vec(), Algorithm::Ed25519),
            KeyData::Ecdsa(ecdsa_key) => {
                let point_bytes = ecdsa_key.as_ref();
                (
                    point_bytes.to_vec(),
                    Algorithm::Ecdsa {
                        curve: ssh_key::EcdsaCurve::NistP256,
                    },
                )
            }
            other_key_type => {
                let err_msg = format!(
                    "Unsupported key type requested for signing: {:?}",
                    other_key_type.algorithm()
                );
                error!("{}", err_msg);
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    err_msg,
                )));
            }
        };

        let core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        match core.sign(&pubkey_bytes_to_sign_with, &request.data) {
            Ok(signature_bytes) => {
                debug!("Successfully signed data using agent core.");
                Signature::new(algorithm, signature_bytes).map_err(|e| {
                    let err_msg = format!(
                        "Internal error: Failed to create ssh_key::Signature from core signature: {}",
                        e
                    );
                    error!("{}", err_msg);
                    SSHAgentError::other(io::Error::new(io::ErrorKind::InvalidData, err_msg))
                })
            }
            Err(AuthsAgentError::KeyNotFound) => {
                warn!("Sign request failed: Key not found in agent core.");
                Err(SSHAgentError::Failure)
            }
            Err(other_core_error) => {
                let err_msg = format!("Agent core signing error: {}", other_core_error);
                error!("{}", err_msg);
                Err(SSHAgentError::other(io::Error::other(err_msg)))
            }
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), SSHAgentError> {
        debug!("Handling add_identity request");

        let pkcs8_bytes: Vec<u8> = match &identity.credential {
            Credential::Key { privkey, .. } => match privkey {
                KeypairData::Ed25519(kp) => {
                    let seed = kp.private.to_bytes();
                    let pubkey = kp.public.0;
                    build_ed25519_pkcs8_v2(&seed, &pubkey)
                }
                KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
                    private, ..
                }) => {
                    use auths_crypto::{TypedSeed, TypedSignerKey};
                    let scalar_bytes = private.as_slice();
                    if scalar_bytes.len() != 32 {
                        let err_msg = format!(
                            "Invalid P-256 scalar length: expected 32, got {}",
                            scalar_bytes.len()
                        );
                        error!("{}", err_msg);
                        return Err(SSHAgentError::other(io::Error::new(
                            io::ErrorKind::InvalidData,
                            err_msg,
                        )));
                    }
                    #[allow(clippy::expect_used)] // INVARIANT: length checked above
                    let mut scalar = [0u8; 32];
                    scalar.copy_from_slice(scalar_bytes);
                    let signer =
                        TypedSignerKey::from_seed(TypedSeed::P256(scalar)).map_err(|e| {
                            let err_msg = format!("P-256 signer construction failed: {}", e);
                            error!("{}", err_msg);
                            SSHAgentError::other(io::Error::other(err_msg))
                        })?;
                    let pkcs8 = signer.to_pkcs8().map_err(|e| {
                        let err_msg = format!("P-256 PKCS8 encoding failed: {}", e);
                        error!("{}", err_msg);
                        SSHAgentError::other(io::Error::other(err_msg))
                    })?;
                    pkcs8.as_ref().to_vec()
                }
                other => {
                    let err_msg = format!(
                        "Unsupported key type for add_identity: {:?}",
                        other.algorithm()
                    );
                    error!("{}", err_msg);
                    return Err(SSHAgentError::other(io::Error::new(
                        io::ErrorKind::Unsupported,
                        err_msg,
                    )));
                }
            },
            Credential::Cert { .. } => {
                error!("Certificate credentials are not supported for add_identity");
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Certificate credentials are not supported",
                )));
            }
        };

        self.handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .map_err(|e| {
                let err_msg = format!("Failed to register key in agent: {}", e);
                error!("{}", err_msg);
                SSHAgentError::other(io::Error::other(err_msg))
            })?;

        debug!("Successfully added identity to agent");
        Ok(())
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), SSHAgentError> {
        debug!("Handling remove_identity request");

        let pubkey_bytes = match &identity.pubkey {
            KeyData::Ed25519(key) => key.as_ref().to_vec(),
            KeyData::Ecdsa(key) => key.as_ref().to_vec(),
            other => {
                let err_msg = format!(
                    "Unsupported key type for remove_identity: {:?}",
                    other.algorithm()
                );
                error!("{}", err_msg);
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    err_msg,
                )));
            }
        };

        let mut core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        core.unregister_key(&pubkey_bytes).map_err(|e| {
            let err_msg = format!("Failed to remove key from agent: {}", e);
            error!("{}", err_msg);
            SSHAgentError::other(io::Error::new(io::ErrorKind::NotFound, err_msg))
        })?;

        debug!("Successfully removed identity from agent");
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), SSHAgentError> {
        debug!("Handling remove_all_identities request");

        let mut core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        core.clear_keys();
        debug!("Successfully removed all identities from agent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use ssh_key::private::Ed25519Keypair as SshEd25519Keypair;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    fn generate_test_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate PKCS#8");
        pkcs8_doc.as_ref().to_vec()
    }

    #[test]
    fn test_agent_session_new() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test.sock")));
        let session = AgentSession::new(handle.clone());

        assert_eq!(
            session.handle().socket_path(),
            &PathBuf::from("/tmp/test.sock")
        );
    }

    #[test]
    fn test_agent_session_clone_shares_handle() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test.sock")));

        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        let session1 = AgentSession::new(handle.clone());
        let session2 = session1.clone();

        // Both sessions share the same handle
        assert_eq!(session1.handle().key_count().unwrap(), 1);
        assert_eq!(session2.handle().key_count().unwrap(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_add_identity_round_trip() {
        // Generate a test seed and create an SSH keypair from it
        let seed: [u8; 32] = {
            let pkcs8 = generate_test_pkcs8();
            // Extract seed from the PKCS#8 bytes (bytes 16..48 in ring's format)
            let mut s = [0u8; 32];
            s.copy_from_slice(&pkcs8[16..48]);
            s
        };

        let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
        let pubkey_bytes = ssh_keypair.public.0;

        // Build an AddIdentity request (what the client sends over the wire)
        let identity = AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ed25519(ssh_keypair),
                comment: "test-key".to_string(),
            },
        };

        // Create session with empty handle
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-add.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Verify no keys initially
        assert_eq!(handle.key_count().unwrap(), 0);

        // Add the identity via the session (this is what was broken before)
        session.add_identity(identity).await.unwrap();

        // Verify the key is now registered
        assert_eq!(handle.key_count().unwrap(), 1);

        // Sign data via the session and verify the signature
        let sign_request = SignRequest {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
            data: b"test data for signing".to_vec(),
            flags: 0,
        };

        let signature = session.sign(sign_request).await.unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        assert!(!signature.as_bytes().is_empty());

        // Verify the signature using ring
        let ring_pubkey =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey_bytes);
        ring_pubkey
            .verify(b"test data for signing", signature.as_bytes())
            .expect("Signature verification failed");
    }

    #[tokio::test]
    async fn test_remove_identity() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-rm.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Add a key via add_identity
        let seed: [u8; 32] = {
            let pkcs8 = generate_test_pkcs8();
            let mut s = [0u8; 32];
            s.copy_from_slice(&pkcs8[16..48]);
            s
        };
        let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
        let pubkey_bytes = ssh_keypair.public.0;

        let identity = AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ed25519(ssh_keypair),
                comment: "test-key".to_string(),
            },
        };
        session.add_identity(identity).await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 1);

        // Remove it
        let remove = RemoveIdentity {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
        };
        session.remove_identity(remove).await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_remove_all_identities() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-rmall.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Add two keys
        for _ in 0..2 {
            let seed: [u8; 32] = {
                let pkcs8 = generate_test_pkcs8();
                let mut s = [0u8; 32];
                s.copy_from_slice(&pkcs8[16..48]);
                s
            };
            let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
            let identity = AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ed25519(ssh_keypair),
                    comment: "test-key".to_string(),
                },
            };
            session.add_identity(identity).await.unwrap();
        }
        assert_eq!(handle.key_count().unwrap(), 2);

        // Remove all
        session.remove_all_identities().await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 0);
    }
}
