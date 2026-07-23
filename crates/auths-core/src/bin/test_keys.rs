use auths_core::storage::encrypted_file::EncryptedFileStorage;
use auths_core::storage::keychain::{KeyStorage, KeyAlias};
use zeroize::Zeroizing;
use std::path::PathBuf;

fn main() {
    let path = PathBuf::from("/Users/bordumb/.auths-agents/auths-agent/keys.enc");
    let storage = EncryptedFileStorage::with_path(path).unwrap();
    storage.set_password(Zeroizing::new("Seamus4444$$".to_string()));
    
    let alias = KeyAlias::new_unchecked("auths-agent");
    match storage.load_key(&alias) {
        Ok((did, role, data)) => {
            println!("Success! DID: {}", did.as_str());
        },
        Err(e) => {
            println!("Failed to load key: {:?}", e);
        }
    }
}
