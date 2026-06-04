/// KAWA witness agreement algorithm.
pub mod agreement;
mod async_provider;
/// CESR receipt attachment groups (`-L`/`-K`) for keripy interop.
pub mod cesr_receipt;
mod error;
mod first_seen;
mod hash;
mod provider;
mod receipt;
mod receipt_lookup;

pub use async_provider::{AsyncWitnessProvider, NoOpAsyncWitness};
pub use cesr_receipt::{
    encode_ed25519_sig, encode_nontrans_receipt_couples, parse_nontrans_receipt_couples,
    witness_idx_sigs_counter,
};
pub use error::{DuplicityEvidence, WitnessError, WitnessReport};
pub use first_seen::{FirstSeenConflict, FirstSeenPolicy, InMemoryFirstSeen};
pub use hash::{EventHash, EventHashParseError};
pub use provider::WitnessProvider;
pub use receipt::{
    RECEIPT_TYPE, Receipt, ReceiptBuilder, ReceiptTag, SignedReceipt, StoredReceipt,
};
pub use receipt_lookup::{NoWitnessReceipts, WitnessReceipt, WitnessReceiptLookup};
