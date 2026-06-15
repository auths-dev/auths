pub mod dialogs;
pub mod format;
pub mod ident;

pub use format::{JsonResponse, Output, is_json_mode, set_json_mode};
pub use ident::product_id;
