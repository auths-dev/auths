// fn-114: allow during curve-agnostic refactor; removed in fn-114.40.
#![allow(clippy::disallowed_methods)]

#[cfg(not(target_arch = "wasm32"))]
mod cases;
