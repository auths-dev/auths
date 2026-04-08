/// KAWA witness agreement algorithm.
pub mod agreement;
mod async_provider;
mod error;
mod first_seen;
mod hash;
mod provider;
mod receipt;

pub use async_provider::{AsyncWitnessProvider, NoOpAsyncWitness};
pub use error::{DuplicityEvidence, WitnessError, WitnessReport};
pub use first_seen::{FirstSeenConflict, FirstSeenPolicy, InMemoryFirstSeen};
pub use hash::{EventHash, EventHashParseError};
pub use provider::WitnessProvider;
pub use receipt::{RECEIPT_TYPE, Receipt, ReceiptBuilder, SignedReceipt};
