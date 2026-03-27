//! Compile `Expr` to `CompiledPolicy`.
//!
//! One-shot validation. Every string parsed, every constraint checked,
//! recursion bounded.

use crate::compiled::{CompiledExpr, CompiledPolicy};
use crate::expr::Expr;
use crate::types::{AssuranceLevel, CanonicalCapability, CanonicalDid, ValidatedGlob};

/// Maximum length for attribute keys.
const MAX_ATTR_KEY_LEN: usize = 64;

/// Maximum allowed value for `MaxChainDepth` expressions.
pub const MAX_CHAIN_DEPTH_LIMIT: u32 = 16;

/// Hard limits enforced at compile time.
///
/// These are not configurable — they're safety bounds.
/// Any policy exceeding them is rejected. The numbers are
/// generous for legitimate use and tight for abuse.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLimits {
    /// Maximum recursion depth for nested expressions.
    pub max_depth: u32,
    /// Maximum total number of AST nodes.
    pub max_total_nodes: u32,
    /// Maximum items in any single list (And, Or, IssuerIn, etc.).
    pub max_list_items: usize,
    /// Maximum size of policy JSON before deserialization.
    pub max_json_bytes: usize,
    /// Maximum allowed value for `MaxChainDepth` expressions.
    pub max_chain_depth_value: u32,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 256,
            max_json_bytes: 64 * 1024, // 64 KB
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        }
    }
}

/// Error that occurred during policy compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// Path to the error in the expression tree (e.g., "root.and[0].issuer_is").
    pub path: String,
    /// Human-readable error message.
    pub message: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at {}: {}", self.path, self.message)
    }
}

impl std::error::Error for CompileError {}

/// Compile a serializable `Expr` into a validated `CompiledPolicy`.
///
/// Uses default `PolicyLimits`. For custom limits, use `compile_with_limits`.
///
/// Fails eagerly on:
/// - Invalid DIDs, capabilities, or glob patterns
/// - Recursion depth exceeding limits
/// - Total nodes exceeding limits
/// - List items exceeding limits
/// - Invalid attribute keys
/// - Empty `And`/`Or` children (ambiguous semantics)
///
/// # Errors
///
/// Returns a vector of all compilation errors found.
pub fn compile(expr: &Expr) -> Result<CompiledPolicy, Vec<CompileError>> {
    compile_with_limits(expr, &PolicyLimits::default())
}

/// Compile from raw JSON bytes with size check.
///
/// Rejects input larger than `PolicyLimits::max_json_bytes` before
/// attempting deserialization. This prevents allocation bombs from
/// untrusted policy files.
///
/// # Errors
///
/// Returns a vector of all compilation errors found.
pub fn compile_from_json(json: &[u8]) -> Result<CompiledPolicy, Vec<CompileError>> {
    compile_from_json_with_limits(json, &PolicyLimits::default())
}

/// Compile from raw JSON bytes with custom limits.
///
/// # Errors
///
/// Returns a vector of all compilation errors found.
pub fn compile_from_json_with_limits(
    json: &[u8],
    limits: &PolicyLimits,
) -> Result<CompiledPolicy, Vec<CompileError>> {
    if json.len() > limits.max_json_bytes {
        return Err(vec![CompileError {
            path: "root".into(),
            message: format!(
                "policy JSON is {} bytes, max {} bytes",
                json.len(),
                limits.max_json_bytes
            ),
        }]);
    }

    let expr: Expr = serde_json::from_slice(json).map_err(|e| {
        vec![CompileError {
            path: "root".into(),
            message: format!("invalid JSON: {}", e),
        }]
    })?;

    compile_with_limits(&expr, limits)
}

/// Compile with custom limits.
///
/// # Errors
///
/// Returns a vector of all compilation errors found.
pub fn compile_with_limits(
    expr: &Expr,
    limits: &PolicyLimits,
) -> Result<CompiledPolicy, Vec<CompileError>> {
    let mut errors = Vec::new();
    let mut node_count: u32 = 0;
    let compiled = compile_inner(expr, "root", 0, limits, &mut node_count, &mut errors);

    if errors.is_empty() {
        let source_json = serde_json::to_vec(expr).unwrap_or_default();
        let source_hash = compute_hash(&source_json);
        Ok(CompiledPolicy::new(compiled, source_hash))
    } else {
        Err(errors)
    }
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn compile_inner(
    expr: &Expr,
    path: &str,
    depth: u32,
    limits: &PolicyLimits,
    node_count: &mut u32,
    errors: &mut Vec<CompileError>,
) -> CompiledExpr {
    // Check depth limit
    if depth > limits.max_depth {
        errors.push(CompileError {
            path: path.to_string(),
            message: format!("recursion depth exceeds {}", limits.max_depth),
        });
        return CompiledExpr::False;
    }

    // Increment and check total node count
    *node_count += 1;
    if *node_count > limits.max_total_nodes {
        errors.push(CompileError {
            path: path.to_string(),
            message: format!("total nodes exceed {}", limits.max_total_nodes),
        });
        return CompiledExpr::False;
    }

    match expr {
        Expr::True => CompiledExpr::True,
        Expr::False => CompiledExpr::False,

        Expr::And(children) => {
            if children.is_empty() {
                errors.push(CompileError {
                    path: path.into(),
                    message: "And with no children is ambiguous".into(),
                });
            }
            check_list_items(children.len(), limits, path, errors);
            let compiled: Vec<_> = children
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    compile_inner(
                        c,
                        &format!("{}.and[{}]", path, i),
                        depth + 1,
                        limits,
                        node_count,
                        errors,
                    )
                })
                .collect();
            CompiledExpr::And(compiled)
        }

        Expr::Or(children) => {
            if children.is_empty() {
                errors.push(CompileError {
                    path: path.into(),
                    message: "Or with no children is ambiguous".into(),
                });
            }
            check_list_items(children.len(), limits, path, errors);
            let compiled: Vec<_> = children
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    compile_inner(
                        c,
                        &format!("{}.or[{}]", path, i),
                        depth + 1,
                        limits,
                        node_count,
                        errors,
                    )
                })
                .collect();
            CompiledExpr::Or(compiled)
        }

        Expr::Not(inner) => {
            if matches!(inner.as_ref(), Expr::ApprovalGate { .. }) {
                errors.push(CompileError {
                    path: path.into(),
                    message: "Not cannot wrap an ApprovalGate expression".into(),
                });
            }
            let compiled = compile_inner(
                inner,
                &format!("{}.not", path),
                depth + 1,
                limits,
                node_count,
                errors,
            );
            CompiledExpr::Not(Box::new(compiled))
        }

        Expr::HasCapability(s) => match CanonicalCapability::parse(s) {
            Ok(cap) => CompiledExpr::HasCapability(cap),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::HasAllCapabilities(caps) => {
            check_list_items(caps.len(), limits, path, errors);
            let compiled: Vec<_> = caps
                .iter()
                .filter_map(|s| match CanonicalCapability::parse(s) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        errors.push(CompileError {
                            path: path.into(),
                            message: e.to_string(),
                        });
                        None
                    }
                })
                .collect();
            CompiledExpr::HasAllCapabilities(compiled)
        }

        Expr::HasAnyCapability(caps) => {
            check_list_items(caps.len(), limits, path, errors);
            let compiled: Vec<_> = caps
                .iter()
                .filter_map(|s| match CanonicalCapability::parse(s) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        errors.push(CompileError {
                            path: path.into(),
                            message: e.to_string(),
                        });
                        None
                    }
                })
                .collect();
            CompiledExpr::HasAnyCapability(compiled)
        }

        Expr::IssuerIs(s) => match CanonicalDid::parse(s) {
            Ok(did) => CompiledExpr::IssuerIs(did),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::IssuerIn(dids) => {
            check_list_items(dids.len(), limits, path, errors);
            let compiled: Vec<_> = dids
                .iter()
                .filter_map(|s| match CanonicalDid::parse(s) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        errors.push(CompileError {
                            path: path.into(),
                            message: e.to_string(),
                        });
                        None
                    }
                })
                .collect();
            CompiledExpr::IssuerIn(compiled)
        }

        Expr::SubjectIs(s) => match CanonicalDid::parse(s) {
            Ok(did) => CompiledExpr::SubjectIs(did),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::DelegatedBy(s) => match CanonicalDid::parse(s) {
            Ok(did) => CompiledExpr::DelegatedBy(did),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::RefMatches(s) => match ValidatedGlob::parse(s) {
            Ok(g) => CompiledExpr::RefMatches(g),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::PathAllowed(patterns) => {
            check_list_items(patterns.len(), limits, path, errors);
            let compiled: Vec<_> = patterns
                .iter()
                .filter_map(|s| match ValidatedGlob::parse(s) {
                    Ok(g) => Some(g),
                    Err(e) => {
                        errors.push(CompileError {
                            path: path.into(),
                            message: e.to_string(),
                        });
                        None
                    }
                })
                .collect();
            CompiledExpr::PathAllowed(compiled)
        }

        Expr::AttrEquals { key, value } => {
            validate_attr_key(key, path, errors);
            CompiledExpr::AttrEquals {
                key: key.clone(),
                value: value.clone(),
            }
        }

        Expr::AttrIn { key, values } => {
            validate_attr_key(key, path, errors);
            check_list_items(values.len(), limits, path, errors);
            CompiledExpr::AttrIn {
                key: key.clone(),
                values: values.clone(),
            }
        }

        Expr::WorkloadIssuerIs(s) => match CanonicalDid::parse(s) {
            Ok(did) => CompiledExpr::WorkloadIssuerIs(did),
            Err(e) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: e.to_string(),
                });
                CompiledExpr::False
            }
        },

        Expr::WorkloadClaimEquals { key, value } => {
            validate_attr_key(key, path, errors);
            CompiledExpr::WorkloadClaimEquals {
                key: key.clone(),
                value: value.clone(),
            }
        }

        // Pass-through variants (no string validation needed)
        Expr::NotRevoked => CompiledExpr::NotRevoked,
        Expr::NotExpired => CompiledExpr::NotExpired,
        Expr::ExpiresAfter(s) => CompiledExpr::ExpiresAfter(*s),
        Expr::IssuedWithin(s) => CompiledExpr::IssuedWithin(*s),
        Expr::RoleIs(s) => CompiledExpr::RoleIs(s.clone()),
        Expr::RoleIn(v) => {
            check_list_items(v.len(), limits, path, errors);
            CompiledExpr::RoleIn(v.clone())
        }
        Expr::RepoIs(s) => CompiledExpr::RepoIs(s.clone()),
        Expr::RepoIn(v) => {
            check_list_items(v.len(), limits, path, errors);
            CompiledExpr::RepoIn(v.clone())
        }
        Expr::EnvIs(s) => CompiledExpr::EnvIs(s.clone()),
        Expr::EnvIn(v) => {
            check_list_items(v.len(), limits, path, errors);
            CompiledExpr::EnvIn(v.clone())
        }
        // Pass-through signer type variants (no validation needed)
        Expr::IsAgent => CompiledExpr::IsAgent,
        Expr::IsHuman => CompiledExpr::IsHuman,
        Expr::IsWorkload => CompiledExpr::IsWorkload,

        Expr::MaxChainDepth(d) => {
            if *d > limits.max_chain_depth_value {
                errors.push(CompileError {
                    path: path.into(),
                    message: format!(
                        "MaxChainDepth({}) exceeds limit of {}",
                        d, limits.max_chain_depth_value
                    ),
                });
            }
            CompiledExpr::MaxChainDepth(*d)
        }

        Expr::MinAssurance(s) => match s.parse::<AssuranceLevel>() {
            Ok(level) => CompiledExpr::MinAssurance(level),
            Err(_) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: format!(
                        "invalid assurance level '{}': expected one of: sovereign, authenticated, token_verified, self_asserted",
                        s
                    ),
                });
                CompiledExpr::False
            }
        },

        Expr::AssuranceLevelIs(s) => match s.parse::<AssuranceLevel>() {
            Ok(level) => CompiledExpr::AssuranceLevelIs(level),
            Err(_) => {
                errors.push(CompileError {
                    path: path.into(),
                    message: format!(
                        "invalid assurance level '{}': expected one of: sovereign, authenticated, token_verified, self_asserted",
                        s
                    ),
                });
                CompiledExpr::False
            }
        },

        Expr::ApprovalGate {
            inner,
            approvers,
            ttl_seconds,
            scope,
        } => {
            if matches!(inner.as_ref(), Expr::Not(_)) {
                errors.push(CompileError {
                    path: path.into(),
                    message: "ApprovalGate cannot wrap a Not expression".into(),
                });
            }
            let compiled_inner = compile_inner(
                inner,
                &format!("{}.approval_gate", path),
                depth + 1,
                limits,
                node_count,
                errors,
            );
            let compiled_approvers: Vec<_> = approvers
                .iter()
                .filter_map(|s| match CanonicalDid::parse(s) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        errors.push(CompileError {
                            path: path.into(),
                            message: e.to_string(),
                        });
                        None
                    }
                })
                .collect();
            let compiled_scope = match scope.as_deref() {
                Some("identity") | None => crate::compiled::ApprovalScope::Identity,
                Some("scoped") => crate::compiled::ApprovalScope::Scoped,
                Some("full") => crate::compiled::ApprovalScope::Full,
                Some(other) => {
                    errors.push(CompileError {
                        path: path.into(),
                        message: format!(
                            "invalid approval scope '{}', expected 'identity', 'scoped', or 'full'",
                            other
                        ),
                    });
                    crate::compiled::ApprovalScope::Identity
                }
            };
            CompiledExpr::ApprovalGate {
                inner: Box::new(compiled_inner),
                approvers: compiled_approvers,
                ttl_seconds: *ttl_seconds,
                scope: compiled_scope,
            }
        }
    }
}

fn check_list_items(len: usize, limits: &PolicyLimits, path: &str, errors: &mut Vec<CompileError>) {
    if len > limits.max_list_items {
        errors.push(CompileError {
            path: path.into(),
            message: format!("list has {} items, max {}", len, limits.max_list_items),
        });
    }
}

fn validate_attr_key(key: &str, path: &str, errors: &mut Vec<CompileError>) {
    if key.is_empty() || key.len() > MAX_ATTR_KEY_LEN {
        errors.push(CompileError {
            path: path.into(),
            message: format!("attr key must be 1-{} chars", MAX_ATTR_KEY_LEN),
        });
    }
    if !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
        errors.push(CompileError {
            path: path.into(),
            message: format!(
                "attr key '{}' contains invalid chars (alphanum + _ only)",
                key
            ),
        });
    }
    if key.contains('.') || key.contains('/') {
        errors.push(CompileError {
            path: path.into(),
            message: "attr keys must not contain dot-paths or slashes".into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_true() {
        let expr = Expr::True;
        let policy = compile(&expr).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::True));
    }

    #[test]
    fn compile_false() {
        let expr = Expr::False;
        let policy = compile(&expr).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::False));
    }

    #[test]
    fn compile_has_capability_valid() {
        let expr = Expr::HasCapability("sign_commit".into());
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::HasCapability(cap) => assert_eq!(cap.as_str(), "sign_commit"),
            _ => panic!("expected HasCapability"),
        }
    }

    #[test]
    fn compile_has_capability_invalid() {
        let expr = Expr::HasCapability("invalid capability!".into());
        let errors = compile(&expr).unwrap_err();
        assert!(!errors.is_empty());
    }

    #[test]
    fn compile_issuer_is_valid() {
        let expr = Expr::IssuerIs("did:keri:EOrg123".into());
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::IssuerIs(did) => assert_eq!(did.as_str(), "did:keri:EOrg123"),
            _ => panic!("expected IssuerIs"),
        }
    }

    #[test]
    fn compile_issuer_is_invalid() {
        let expr = Expr::IssuerIs("not-a-did".into());
        let errors = compile(&expr).unwrap_err();
        assert!(!errors.is_empty());
    }

    #[test]
    fn compile_ref_matches_valid() {
        let expr = Expr::RefMatches("refs/heads/*".into());
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::RefMatches(g) => assert_eq!(g.as_str(), "refs/heads/*"),
            _ => panic!("expected RefMatches"),
        }
    }

    #[test]
    fn compile_ref_matches_path_traversal() {
        let expr = Expr::RefMatches("refs/../secrets".into());
        let errors = compile(&expr).unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("path traversal"));
    }

    #[test]
    fn compile_and_valid() {
        let expr = Expr::And(vec![Expr::NotRevoked, Expr::NotExpired]);
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::And(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compile_and_empty() {
        let expr = Expr::And(vec![]);
        let errors = compile(&expr).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("ambiguous")));
    }

    #[test]
    fn compile_or_empty() {
        let expr = Expr::Or(vec![]);
        let errors = compile(&expr).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("ambiguous")));
    }

    #[test]
    fn compile_not() {
        let expr = Expr::Not(Box::new(Expr::True));
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::Not(inner) => assert!(matches!(**inner, CompiledExpr::True)),
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn compile_nested() {
        let expr = Expr::And(vec![
            Expr::NotRevoked,
            Expr::Or(vec![
                Expr::HasCapability("admin".into()),
                Expr::HasCapability("write".into()),
            ]),
        ]);
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 2);
                assert!(matches!(children[1], CompiledExpr::Or(_)));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compile_depth_exceeded() {
        // Create deeply nested expression
        let mut expr = Expr::True;
        for _ in 0..100 {
            expr = Expr::Not(Box::new(expr));
        }
        let errors = compile(&expr).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("recursion depth")));
    }

    #[test]
    fn compile_attr_equals_valid() {
        let expr = Expr::AttrEquals {
            key: "team".into(),
            value: "platform".into(),
        };
        let policy = compile(&expr).unwrap();
        match policy.expr() {
            CompiledExpr::AttrEquals { key, value } => {
                assert_eq!(key, "team");
                assert_eq!(value, "platform");
            }
            _ => panic!("expected AttrEquals"),
        }
    }

    #[test]
    fn compile_attr_equals_invalid_key() {
        let expr = Expr::AttrEquals {
            key: "invalid.key".into(),
            value: "value".into(),
        };
        let errors = compile(&expr).unwrap_err();
        assert!(!errors.is_empty());
    }

    #[test]
    fn compile_multiple_errors() {
        let expr = Expr::And(vec![
            Expr::IssuerIs("bad-did".into()),
            Expr::HasCapability("bad cap!".into()),
        ]);
        let errors = compile(&expr).unwrap_err();
        assert!(errors.len() >= 2);
    }

    #[test]
    fn policy_has_source_hash() {
        let expr = Expr::True;
        let policy = compile(&expr).unwrap();
        let hash = policy.source_hash();
        // Hash should be non-zero
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn same_expr_same_hash() {
        let expr1 = Expr::HasCapability("sign_commit".into());
        let expr2 = Expr::HasCapability("sign_commit".into());

        let policy1 = compile(&expr1).unwrap();
        let policy2 = compile(&expr2).unwrap();

        assert_eq!(policy1.source_hash(), policy2.source_hash());
    }

    #[test]
    fn different_expr_different_hash() {
        let expr1 = Expr::HasCapability("sign_commit".into());
        let expr2 = Expr::HasCapability("read".into());

        let policy1 = compile(&expr1).unwrap();
        let policy2 = compile(&expr2).unwrap();

        assert_ne!(policy1.source_hash(), policy2.source_hash());
    }

    // Complexity bounds tests

    #[test]
    fn policy_limits_default() {
        let limits = PolicyLimits::default();
        assert_eq!(limits.max_depth, 64);
        assert_eq!(limits.max_total_nodes, 1024);
        assert_eq!(limits.max_list_items, 256);
        assert_eq!(limits.max_json_bytes, 64 * 1024);
        assert_eq!(limits.max_chain_depth_value, MAX_CHAIN_DEPTH_LIMIT);
    }

    #[test]
    fn compile_max_chain_depth_zero() {
        let expr = Expr::MaxChainDepth(0);
        let policy = compile(&expr).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::MaxChainDepth(0)));
    }

    #[test]
    fn compile_max_chain_depth_at_limit() {
        let expr = Expr::MaxChainDepth(16);
        let policy = compile(&expr).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::MaxChainDepth(16)));
    }

    #[test]
    fn compile_max_chain_depth_exceeds_limit() {
        let expr = Expr::MaxChainDepth(17);
        let errors = compile(&expr).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("MaxChainDepth(17) exceeds limit"))
        );
    }

    #[test]
    fn compile_with_custom_limits() {
        let limits = PolicyLimits {
            max_depth: 2,
            max_total_nodes: 10,
            max_list_items: 5,
            max_json_bytes: 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::And(vec![Expr::NotRevoked, Expr::NotExpired]);
        let policy = compile_with_limits(&expr, &limits).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::And(_)));
    }

    #[test]
    fn compile_exceeds_max_total_nodes() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 3,
            max_list_items: 256,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        // 5 nodes: And + 4 children
        let expr = Expr::And(vec![
            Expr::NotRevoked,
            Expr::NotExpired,
            Expr::True,
            Expr::False,
        ]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("total nodes")));
    }

    #[test]
    fn compile_exceeds_max_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::And(vec![Expr::NotRevoked, Expr::NotExpired, Expr::True]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_from_json_valid() {
        let json = r#"{"op": "True"}"#;
        let policy = compile_from_json(json.as_bytes()).unwrap();
        assert!(matches!(policy.expr(), CompiledExpr::True));
    }

    #[test]
    fn compile_from_json_exceeds_max_bytes() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 256,
            max_json_bytes: 10,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let json = r#"{"op": "true"}"#;
        let errors = compile_from_json_with_limits(json.as_bytes(), &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("bytes")));
    }

    #[test]
    fn compile_from_json_invalid_json() {
        let json = r#"{"op": "true""#; // missing closing brace
        let errors = compile_from_json(json.as_bytes()).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("invalid JSON")));
    }

    #[test]
    fn compile_issuer_in_exceeds_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::IssuerIn(vec![
            "did:keri:E1".into(),
            "did:keri:E2".into(),
            "did:keri:E3".into(),
        ]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_role_in_exceeds_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::RoleIn(vec!["admin".into(), "user".into(), "guest".into()]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_path_allowed_exceeds_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::PathAllowed(vec!["src/*".into(), "docs/*".into(), "tests/*".into()]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_has_all_capabilities_exceeds_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::HasAllCapabilities(vec!["read".into(), "write".into(), "execute".into()]);
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_attr_in_exceeds_list_items() {
        let limits = PolicyLimits {
            max_depth: 64,
            max_total_nodes: 1024,
            max_list_items: 2,
            max_json_bytes: 64 * 1024,
            max_chain_depth_value: MAX_CHAIN_DEPTH_LIMIT,
        };
        let expr = Expr::AttrIn {
            key: "team".into(),
            values: vec!["alpha".into(), "beta".into(), "gamma".into()],
        };
        let errors = compile_with_limits(&expr, &limits).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("list has")));
    }

    #[test]
    fn compile_from_json_with_has_capability() {
        let json = r#"{"op": "HasCapability", "args": "sign_commit"}"#;
        let policy = compile_from_json(json.as_bytes()).unwrap();
        match policy.expr() {
            CompiledExpr::HasCapability(cap) => assert_eq!(cap.as_str(), "sign_commit"),
            _ => panic!("expected HasCapability"),
        }
    }

    #[test]
    fn compile_from_json_with_and() {
        let json = r#"{"op": "And", "args": [{"op": "NotRevoked"}, {"op": "NotExpired"}]}"#;
        let policy = compile_from_json(json.as_bytes()).unwrap();
        match policy.expr() {
            CompiledExpr::And(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compile_flat_policy_within_bounds() {
        // A policy with many children but within limits
        let limits = PolicyLimits::default();
        let children: Vec<_> = (0..100).map(|_| Expr::NotRevoked).collect();
        let expr = Expr::And(children);
        let policy = compile_with_limits(&expr, &limits).unwrap();
        match policy.expr() {
            CompiledExpr::And(children) => assert_eq!(children.len(), 100),
            _ => panic!("expected And"),
        }
    }
}
