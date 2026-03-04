pub mod attestation;
pub mod driver;
#[cfg(feature = "git-storage")]
pub mod git_refs;
pub mod identity;
#[cfg(feature = "git-storage")]
pub mod receipts;

pub use driver::{StorageDriver, StorageError};
#[cfg(feature = "git-storage")]
pub use receipts::{
    GitReceiptStorage, ReceiptStorage, check_receipt_consistency, verify_receipt_signature,
};
#[cfg(feature = "indexed-storage")]
pub mod indexed;
#[cfg(feature = "git-storage")]
pub mod keri;
pub mod layout;
pub mod registry;
