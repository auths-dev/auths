use auths_sdk::domains::agent_guard::error::AgentGuardError;
use capsec::{Ambient, CapSecError, Permission, RuntimeCap, TimedCap};
use std::sync::OnceLock;
use std::time::Duration;

struct SyncCapRoot(capsec::CapRoot);
// INVARIANT: CapRoot is initialized once at startup and used solely to grant child capability tokens
unsafe impl Send for SyncCapRoot {}
unsafe impl Sync for SyncCapRoot {}

static CAPSEC_ROOT: OnceLock<Option<SyncCapRoot>> = OnceLock::new();

fn get_or_init_root() -> Result<&'static capsec::CapRoot, AgentGuardError> {
    let opt = CAPSEC_ROOT.get_or_init(|| {
        #[cfg(debug_assertions)]
        {
            Some(SyncCapRoot(capsec::test_root()))
        }
        #[cfg(not(debug_assertions))]
        {
            capsec::try_root().map(SyncCapRoot)
        }
    });

    opt.as_ref()
        .map(|s| &s.0)
        .ok_or_else(|| AgentGuardError::CapsecViolation("Failed to initialize process CapSec root".into()))
}

/// Holds runtime capability bounds for an active MCP agent tool execution session.
pub struct McpCapsecGuard<P: Permission = Ambient> {
    /// Agent identity DID string backing this session
    pub agent_did: String,
    /// Time-bounded validity token enforcing --ttl
    pub timed_cap: TimedCap<P>,
    /// Revocable capability token for instant remote kill switch
    pub runtime_cap: RuntimeCap<P>,
}

impl<P: Permission> McpCapsecGuard<P> {
    /// Check if the capability guard is still valid before forwarding tool call.
    ///
    /// Usage:
    /// ```ignore
    /// guard.validate_execution()?;
    /// ```
    pub fn validate_execution(&self) -> Result<(), AgentGuardError> {
        let _cap1 = self
            .timed_cap
            .try_cap()
            .map_err(|e: CapSecError| AgentGuardError::CapsecViolation(e.to_string()))?;
        let _cap2 = self
            .runtime_cap
            .try_cap()
            .map_err(|e: CapSecError| AgentGuardError::CapsecViolation(e.to_string()))?;
        Ok(())
    }
}

impl McpCapsecGuard<Ambient> {
    /// Create a new capability guard for an MCP tool invocation.
    ///
    /// Args:
    /// * `agent_did`: Canonical DID string of the agent.
    /// * `ttl`: Duration representing the time-to-live for tool execution.
    ///
    /// Usage:
    /// ```ignore
    /// let guard = McpCapsecGuard::new("did:key:z1".into(), Duration::from_secs(1800))?;
    /// ```
    pub fn new(agent_did: String, ttl: Duration) -> Result<Self, AgentGuardError> {
        let root = get_or_init_root()?;

        let cap1 = root.grant::<Ambient>();
        let cap2 = root.grant::<Ambient>();

        let timed_cap = TimedCap::new(cap1, ttl);
        let (runtime_cap, _revoker) = RuntimeCap::new(cap2);
        Ok(Self {
            agent_did,
            timed_cap,
            runtime_cap,
        })
    }
}
