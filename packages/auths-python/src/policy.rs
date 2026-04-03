use auths_policy::{
    CanonicalCapability, CanonicalDid, CompiledPolicy, EvalContext, SignerType, compile_from_json,
    enforce_simple,
};
use chrono::Utc;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
pub struct PyCompiledPolicy {
    inner: CompiledPolicy,
    source_json: String,
}

#[pymethods]
impl PyCompiledPolicy {
    fn check(&self, context: &PyEvalContext) -> PyResult<PyDecision> {
        let decision = enforce_simple(&self.inner, &context.inner);
        Ok(PyDecision {
            outcome: decision.outcome.to_string().to_lowercase(),
            reason: format!("{:?}", decision.reason),
            message: decision.message,
        })
    }

    fn to_json(&self) -> PyResult<String> {
        Ok(self.source_json.clone())
    }

    fn __repr__(&self) -> String {
        format!(
            "CompiledPolicy(hash='{}')",
            hex::encode(&self.inner.source_hash()[..8])
        )
    }
}

#[pyclass]
pub struct PyEvalContext {
    inner: EvalContext,
}

#[pymethods]
impl PyEvalContext {
    #[new]
    #[pyo3(signature = (issuer, subject, *, capabilities=None, role=None, revoked=false, expires_at=None, repo=None, environment=None, signer_type=None, delegated_by=None, chain_depth=None))]
    #[allow(clippy::too_many_arguments)] // PyO3 constructor mirrors Python kwargs
    fn new(
        issuer: &str,
        subject: &str,
        capabilities: Option<Vec<String>>,
        role: Option<String>,
        revoked: bool,
        expires_at: Option<String>,
        repo: Option<String>,
        environment: Option<String>,
        signer_type: Option<String>,
        delegated_by: Option<String>,
        chain_depth: Option<u32>,
    ) -> PyResult<Self> {
        let issuer_did = CanonicalDid::parse(issuer)
            .map_err(|e| PyValueError::new_err(format!("Invalid issuer DID: {e}")))?;
        let subject_did = CanonicalDid::parse(subject)
            .map_err(|e| PyValueError::new_err(format!("Invalid subject DID: {e}")))?;

        #[allow(clippy::disallowed_methods)] // Presentation boundary
        let now = Utc::now();
        let mut ctx = EvalContext::new(now, issuer_did, subject_did).revoked(revoked);

        if let Some(caps) = capabilities {
            for cap_str in &caps {
                let cap = CanonicalCapability::parse(cap_str).map_err(|e| {
                    PyValueError::new_err(format!("Invalid capability '{cap_str}': {e}"))
                })?;
                ctx = ctx.capability(cap);
            }
        }

        if let Some(r) = role {
            ctx = ctx.role(r);
        }

        if let Some(exp) = expires_at {
            let ts: chrono::DateTime<Utc> = exp.parse().map_err(|_| {
                PyValueError::new_err(format!("Invalid expires_at RFC 3339: {exp}"))
            })?;
            ctx = ctx.expires_at(ts);
        }

        if let Some(r) = repo {
            ctx = ctx.repo(r);
        }

        if let Some(env) = environment {
            ctx = ctx.environment(env);
        }

        if let Some(st) = signer_type {
            let parsed = match st.to_lowercase().as_str() {
                "human" => SignerType::Human,
                "agent" => SignerType::Agent,
                "workload" => SignerType::Workload,
                _ => {
                    return Err(PyValueError::new_err(format!(
                        "Invalid signer_type: '{st}'. Must be 'Human', 'Agent', or 'Workload'"
                    )));
                }
            };
            ctx = ctx.signer_type(parsed);
        }

        if let Some(d) = delegated_by {
            let did = CanonicalDid::parse(&d)
                .map_err(|e| PyValueError::new_err(format!("Invalid delegated_by DID: {e}")))?;
            ctx = ctx.delegated_by(did);
        }

        if let Some(depth) = chain_depth {
            ctx = ctx.chain_depth(depth);
        }

        Ok(Self { inner: ctx })
    }

    fn __repr__(&self) -> String {
        let issuer = self.inner.issuer.as_str();
        let subject = self.inner.subject.as_str();
        let i_short = &issuer[..issuer.len().min(20)];
        let s_short = &subject[..subject.len().min(20)];
        format!("EvalContext(issuer='{i_short}...', subject='{s_short}...')")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyDecision {
    #[pyo3(get)]
    pub outcome: String,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub message: String,
}

#[pymethods]
impl PyDecision {
    #[getter]
    fn allowed(&self) -> bool {
        self.outcome == "allow"
    }

    #[getter]
    fn denied(&self) -> bool {
        self.outcome == "deny"
    }

    fn __bool__(&self) -> bool {
        self.outcome == "allow"
    }

    fn __repr__(&self) -> String {
        format!(
            "Decision(outcome='{}', reason='{}')",
            self.outcome, self.reason
        )
    }
}

/// Compile a policy from a JSON string.
///
/// Args:
/// * `policy_json`: JSON policy expression string.
///
/// Usage:
/// ```ignore
/// let policy = compile_policy(py, r#"{"op":"NotRevoked"}"#)?;
/// ```
#[pyfunction]
pub fn compile_policy(_py: Python<'_>, policy_json: &str) -> PyResult<PyCompiledPolicy> {
    let compiled = compile_from_json(policy_json.as_bytes()).map_err(|errors| {
        let msgs: Vec<String> = errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.message))
            .collect();
        PyValueError::new_err(format!("Policy compilation failed: {}", msgs.join("; ")))
    })?;

    Ok(PyCompiledPolicy {
        inner: compiled,
        source_json: policy_json.to_string(),
    })
}
