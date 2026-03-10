//! Policy Expression Engine for Auths.
//!
//! This crate provides a composable policy expression language for authorization
//! logic. Policies are defined as expressions that can be serialized to JSON/TOML,
//! compiled into an efficient evaluation target, and evaluated against a context.
//!
//! # Architecture
//!
//! ```text
//!    JSON/TOML file          Rust types (validated)
//!    ┌──────────┐   parse    ┌──────────────┐   compile   ┌────────────────┐
//!    │  Expr    │──────────▶│  Expr (AST)  │────────────▶│ CompiledPolicy │
//!    │  (serde) │           │  (strings)   │             │ (typed/canon)  │
//!    └──────────┘           └──────────────┘             └────────────────┘
//!                                                              │
//!                                                     evaluate │
//!                                                              ▼
//!                                                       ┌──────────┐
//!                                                       │ Decision │
//!                                                       └──────────┘
//! ```
//!
//! # Modules
//!
//! - [`types`]: Canonical types for DIDs, capabilities, and glob patterns
//! - [`decision`]: Authorization decision types with structured reason codes
//! - [`expr`]: Serializable policy expression AST
//! - [`compiled`]: Compiled policy expressions ready for evaluation
//! - [`compile`]: Compile `Expr` to `CompiledPolicy`
//! - [`eval`]: Policy evaluation functions
//! - [`glob`]: Hardened glob matcher for path/ref matching
//! - [`context`]: Typed evaluation context
//! - [`enforce`]: Production enforcement with optional shadow evaluation

pub mod approval;
pub mod builder;
pub mod compile;
pub mod compiled;
pub mod context;
pub mod decision;
pub mod enforce;
pub mod eval;
pub mod expr;
pub mod glob;
pub mod trust;
pub mod types;

pub use approval::{ApprovalAttestation, compute_request_hash};
pub use builder::PolicyBuilder;
pub use compile::{
    CompileError, PolicyLimits, compile, compile_from_json, compile_from_json_with_limits,
    compile_with_limits,
};
pub use compiled::{ApprovalScope, CompiledExpr, CompiledPolicy};
pub use context::EvalContext;
pub use decision::{Decision, Outcome, ReasonCode};
pub use enforce::{Divergence, enforce, enforce_simple};
pub use eval::{evaluate_batch, evaluate_strict, evaluate3};
pub use expr::Expr;
pub use glob::glob_match;
pub use trust::{TrustRegistry, TrustRegistryEntry, ValidatedIssuerUrl};
pub use types::{
    CanonicalCapability, CanonicalDid, CapabilityParseError, DidParseError, GlobParseError,
    QuorumPolicy, SignerType, ValidatedGlob,
};
