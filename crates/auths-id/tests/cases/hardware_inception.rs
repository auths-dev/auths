//! Regression: hardware-backed inception must put the KEYCHAIN's key in the KEL.
//!
//! The original hardware path generated an in-memory software keypair, incepted
//! the KEL with it, then called `store_key` — which hardware backends ignore,
//! minting a fresh internal key instead. The KEL's signing key was dropped on
//! the floor: every Secure-Enclave identity was born unable to produce a
//! signature matching its own KEL. These tests drive inception through a mock
//! hardware backend (same semantics as the SE: `store_key` generates
//! internally, material never leaves) and pin the invariants.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use auths_core::error::AgentError;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::testing::TestPassphraseProvider;
use auths_crypto::CurveType;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::keri::Event;
use auths_id::keri::serialize_for_signing;
use auths_id::keri::types::Prefix;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_id::witness_config::WitnessParams;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;

/// A mock hardware keychain with Secure-Enclave semantics: `store_key`
/// IGNORES the supplied material and generates a key internally; private
/// material is never exposed; signing happens "inside the hardware".
#[derive(Default)]
struct FakeHardwareKeychain {
    keys: Mutex<HashMap<String, (IdentityDID, KeyRole, SigningKey)>>,
    counter: Mutex<u8>,
    signed_messages: Mutex<Vec<Vec<u8>>>,
}

impl FakeHardwareKeychain {
    fn public_key_compressed(&self, alias: &str) -> Vec<u8> {
        let keys = self.keys.lock().expect("lock");
        let (_, _, sk) = keys.get(alias).expect("key exists");
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }
}

impl KeyStorage for FakeHardwareKeychain {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        // Mirror SE: material is ignored; a fresh key is generated internally.
        let mut counter = self.counter.lock().expect("lock");
        *counter += 1;
        let mut seed = [42u8; 32];
        seed[31] = *counter;
        let sk = SigningKey::from_slice(&seed)
            .map_err(|e| AgentError::CryptoError(format!("keygen: {e}")))?;
        self.keys
            .lock()
            .expect("lock")
            .insert(alias.as_str().to_string(), (identity_did.clone(), role, sk));
        Ok(())
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let keys = self.keys.lock().expect("lock");
        let (did, role, _) = keys.get(alias.as_str()).ok_or(AgentError::KeyNotFound)?;
        Ok((did.clone(), *role, vec![0u8; 8])) // opaque handle
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        self.keys.lock().expect("lock").remove(alias.as_str());
        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        Ok(self
            .keys
            .lock()
            .expect("lock")
            .keys()
            .map(KeyAlias::new_unchecked)
            .collect())
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        Ok(self
            .keys
            .lock()
            .expect("lock")
            .iter()
            .filter(|(_, (did, _, _))| did == identity_did)
            .map(|(a, _)| KeyAlias::new_unchecked(a.clone()))
            .collect())
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let (did, _, _) = self.load_key(alias)?;
        Ok(did)
    }

    fn backend_name(&self) -> &'static str {
        "fake-hardware"
    }

    fn is_hardware_backend(&self) -> bool {
        true
    }

    fn export_public_key(&self, alias: &KeyAlias) -> Result<Vec<u8>, AgentError> {
        let keys = self.keys.lock().expect("lock");
        let (_, _, sk) = keys.get(alias.as_str()).ok_or(AgentError::KeyNotFound)?;
        // SE returns the uncompressed SEC1 point; the inception path must
        // normalize it to the 33-byte compressed form KERI carries.
        Ok(sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn sign_raw(&self, alias: &KeyAlias, message: &[u8]) -> Result<Vec<u8>, AgentError> {
        let keys = self.keys.lock().expect("lock");
        let (_, _, sk) = keys.get(alias.as_str()).ok_or(AgentError::KeyNotFound)?;
        let sig: p256::ecdsa::Signature = sk.sign(message);
        self.signed_messages
            .lock()
            .expect("lock")
            .push(message.to_vec());
        Ok(sig.to_bytes().to_vec())
    }

    fn rebind_identity(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
    ) -> Result<(), AgentError> {
        // Mirror the SE override: rewrite the association only, never the key.
        let mut keys = self.keys.lock().expect("lock");
        let entry = keys
            .get_mut(alias.as_str())
            .ok_or(AgentError::KeyNotFound)?;
        entry.0 = identity_did.clone();
        Ok(())
    }
}

fn collect_kel(backend: &(dyn RegistryBackend + Send + Sync), prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk KEL");
    events
}

#[test]
fn hardware_inception_uses_the_keychain_key() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = FakeHardwareKeychain::default();
    let provider = TestPassphraseProvider::new("unused");
    let alias = KeyAlias::new_unchecked("main");

    let (did, returned_alias) = initialize_registry_identity(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        WitnessParams::Disabled,
        CurveType::P256,
        chrono::Utc::now(),
    )
    .expect("hardware inception succeeds");
    assert_eq!(returned_alias, alias);

    let prefix = Prefix::new_unchecked(
        did.as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    );
    let kel = collect_kel(backend.as_ref(), &prefix);
    assert_eq!(kel.len(), 1, "exactly the inception event");

    // THE regression invariant: the KEL's current key must be the key that
    // actually lives in the (hardware) keychain — not a software key that was
    // generated on the side and lost.
    let Event::Icp(icp) = &kel[0] else {
        panic!("first event must be icp");
    };
    let keychain_pub = keychain.public_key_compressed("main");
    let expected_cesr =
        auths_keri::KeriPublicKey::from_verkey_bytes(&keychain_pub, CurveType::P256)
            .expect("compressed key parses")
            .to_qb64()
            .expect("encodes");
    assert_eq!(
        icp.k[0].as_str(),
        expected_cesr,
        "KEL inception key must be the keychain's key"
    );

    // The inception event must have been signed BY the hardware (the only
    // place the private key exists).
    let canonical = serialize_for_signing(&kel[0]).expect("canonical");
    let signed = keychain.signed_messages.lock().expect("lock");
    assert!(
        signed.iter().any(|m| m == &canonical),
        "icp event must be signed through the hardware backend"
    );

    // Both stored keys must be rebound from the placeholder to the real DID.
    assert_eq!(
        keychain
            .get_identity_for_alias(&alias)
            .expect("main exists")
            .as_str(),
        did.as_str()
    );
    assert_eq!(
        keychain
            .get_identity_for_alias(&KeyAlias::new_unchecked("main--next-0"))
            .expect("next exists")
            .as_str(),
        did.as_str()
    );
}

#[test]
fn hardware_inception_rejects_non_p256() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = FakeHardwareKeychain::default();
    let provider = TestPassphraseProvider::new("unused");

    let res = initialize_registry_identity(
        backend,
        &KeyAlias::new_unchecked("main"),
        &provider,
        &keychain,
        WitnessParams::Disabled,
        CurveType::Ed25519,
        chrono::Utc::now(),
    );
    assert!(res.is_err(), "hardware inception is P-256 only");
}
