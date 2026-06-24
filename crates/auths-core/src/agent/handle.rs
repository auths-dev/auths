//! Agent handle for lifecycle management.
//!
//! This module provides `AgentHandle`, a wrapper around `AgentCore` that enables
//! proper lifecycle management (start/stop/restart) for the SSH agent daemon.

use crate::agent::AgentCore;
use crate::error::AgentError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Default idle timeout (30 minutes)
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Default absolute cap on how long a single unlock keeps signing capability,
/// measured from the last unlock and independent of activity (8 hours).
pub const DEFAULT_MAX_UNLOCK_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// A handle to an agent instance that manages its lifecycle.
///
/// `AgentHandle` wraps an `AgentCore` and provides:
/// - Socket path and PID file tracking
/// - Lifecycle management (shutdown, status checks)
/// - Thread-safe access to the underlying `AgentCore`
/// - Idle timeout and key locking
///
/// Unlike the previous global static pattern, multiple `AgentHandle` instances
/// can coexist, enabling proper testing and multi-agent scenarios.
pub struct AgentHandle {
    /// The underlying agent core wrapped in a mutex for thread-safe access
    core: Arc<Mutex<AgentCore>>,
    /// Path to the Unix domain socket
    socket_path: PathBuf,
    /// Path to the PID file (optional)
    pid_file: Option<PathBuf>,
    /// Whether the agent is currently running
    running: Arc<AtomicBool>,
    /// Timestamp of last activity (for idle timeout, shared across clones)
    last_activity: Arc<Mutex<Instant>>,
    /// Idle timeout duration (0 = never timeout)
    idle_timeout: Duration,
    /// Timestamp of the last unlock (for the absolute unlock cap, shared across clones)
    unlocked_at: Arc<Mutex<Instant>>,
    /// Absolute cap on how long a single unlock keeps signing capability (0 = no cap)
    max_unlock_ttl: Duration,
    /// Whether the agent is currently locked (shared across clones)
    locked: Arc<AtomicBool>,
}

impl std::fmt::Debug for AgentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentHandle")
            .field("socket_path", &self.socket_path)
            .field("pid_file", &self.pid_file)
            .field("running", &self.is_running())
            .field("locked", &self.is_agent_locked())
            .field("idle_timeout", &self.idle_timeout)
            .field("max_unlock_ttl", &self.max_unlock_ttl)
            .finish_non_exhaustive()
    }
}

impl AgentHandle {
    /// Creates a new agent handle with the specified socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        Self::with_timeout(socket_path, DEFAULT_IDLE_TIMEOUT)
    }

    /// Creates a new agent handle with the specified socket path and idle timeout,
    /// using the default absolute unlock cap.
    pub fn with_timeout(socket_path: PathBuf, idle_timeout: Duration) -> Self {
        Self::with_unlock_cap(socket_path, idle_timeout, DEFAULT_MAX_UNLOCK_TTL)
    }

    /// Creates a new agent handle with an explicit idle timeout and absolute unlock cap.
    ///
    /// The idle timeout locks the agent after a period of no signing (a "walked away"
    /// control); the unlock cap locks it a fixed time after it was last unlocked,
    /// regardless of activity, so continuous signing cannot keep it unlocked forever.
    ///
    /// Args:
    /// * `socket_path`: The Unix-domain socket path.
    /// * `idle_timeout`: Sliding inactivity timeout (0 disables).
    /// * `max_unlock_ttl`: Absolute cap measured from the last unlock (0 disables).
    ///
    /// Usage:
    /// ```ignore
    /// let handle = AgentHandle::with_unlock_cap(path, idle, cap);
    /// ```
    pub fn with_unlock_cap(
        socket_path: PathBuf,
        idle_timeout: Duration,
        max_unlock_ttl: Duration,
    ) -> Self {
        Self {
            core: Arc::new(Mutex::new(AgentCore::default())),
            socket_path,
            pid_file: None,
            running: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            idle_timeout,
            unlocked_at: Arc::new(Mutex::new(Instant::now())),
            max_unlock_ttl,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a new agent handle with socket and PID file paths.
    pub fn with_pid_file(socket_path: PathBuf, pid_file: PathBuf) -> Self {
        Self {
            core: Arc::new(Mutex::new(AgentCore::default())),
            socket_path,
            pid_file: Some(pid_file),
            running: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            unlocked_at: Arc::new(Mutex::new(Instant::now())),
            max_unlock_ttl: DEFAULT_MAX_UNLOCK_TTL,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a new agent handle with socket, PID file, and custom timeout.
    pub fn with_pid_file_and_timeout(
        socket_path: PathBuf,
        pid_file: PathBuf,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            core: Arc::new(Mutex::new(AgentCore::default())),
            socket_path,
            pid_file: Some(pid_file),
            running: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            idle_timeout,
            unlocked_at: Arc::new(Mutex::new(Instant::now())),
            max_unlock_ttl: DEFAULT_MAX_UNLOCK_TTL,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates an agent handle from an existing `AgentCore`.
    pub fn from_core(core: AgentCore, socket_path: PathBuf) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
            socket_path,
            pid_file: None,
            running: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            unlocked_at: Arc::new(Mutex::new(Instant::now())),
            max_unlock_ttl: DEFAULT_MAX_UNLOCK_TTL,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the socket path for this agent.
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Returns the PID file path, if configured.
    pub fn pid_file(&self) -> Option<&PathBuf> {
        self.pid_file.as_ref()
    }

    /// Sets the PID file path.
    pub fn set_pid_file(&mut self, path: PathBuf) {
        self.pid_file = Some(path);
    }

    /// Acquires a lock on the agent core.
    ///
    /// # Errors
    /// Returns `AgentError::MutexError` if the mutex is poisoned.
    pub fn lock(&self) -> Result<MutexGuard<'_, AgentCore>, AgentError> {
        self.core
            .lock()
            .map_err(|_| AgentError::MutexError("Agent core mutex poisoned".to_string()))
    }

    /// Returns a clone of the inner `Arc<Mutex<AgentCore>>` for sharing.
    pub fn core_arc(&self) -> Arc<Mutex<AgentCore>> {
        Arc::clone(&self.core)
    }

    /// Returns whether the agent is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Marks the agent as running.
    pub fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::SeqCst);
    }

    // --- Idle Timeout and Locking ---

    /// Returns the configured idle timeout duration.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Records activity, resetting the idle timer.
    pub fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    /// Returns the duration since the last activity.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Returns whether the agent has exceeded the idle timeout.
    pub fn is_idle_timed_out(&self) -> bool {
        // A timeout of 0 means never timeout
        if self.idle_timeout.is_zero() {
            return false;
        }
        self.idle_duration() >= self.idle_timeout
    }

    /// Returns the absolute cap on how long a single unlock keeps signing capability.
    pub fn max_unlock_ttl(&self) -> Duration {
        self.max_unlock_ttl
    }

    /// Returns the time elapsed since the agent was last unlocked.
    pub fn unlock_age(&self) -> Duration {
        self.unlocked_at
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Returns whether the agent has been unlocked longer than its absolute cap.
    ///
    /// Unlike the idle timeout, this does not reset on activity — it bounds the total
    /// lifetime of a single unlock so continuous signing cannot keep the agent unlocked
    /// indefinitely. A cap of 0 disables it.
    pub fn is_unlock_window_expired(&self) -> bool {
        if self.max_unlock_ttl.is_zero() {
            return false;
        }
        self.unlock_age() >= self.max_unlock_ttl
    }

    /// Returns whether the agent is currently locked.
    pub fn is_agent_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// Locks the agent, clearing all keys from memory.
    ///
    /// After locking, sign operations will fail with `AgentError::AgentLocked`.
    pub fn lock_agent(&self) -> Result<(), AgentError> {
        log::info!("Locking agent (clearing keys from memory)");

        // Clear all keys (zeroizes sensitive data)
        {
            let mut core = self.lock()?;
            core.clear_keys();
        }

        // Mark as locked
        self.locked.store(true, Ordering::SeqCst);
        log::debug!("Agent locked");
        Ok(())
    }

    /// Unlocks the agent (marks as unlocked).
    ///
    /// Note: This only clears the locked flag. Keys must be re-loaded separately
    /// using `register_key` or the CLI `auths agent unlock` command.
    pub fn unlock_agent(&self) {
        log::info!("Unlocking agent");
        self.locked.store(false, Ordering::SeqCst);
        self.touch(); // Reset idle timer
        if let Ok(mut unlocked) = self.unlocked_at.lock() {
            *unlocked = Instant::now(); // Start the absolute unlock window
        }
    }

    /// Locks the agent if its unlock window has ended, clearing its keys.
    ///
    /// The agent locks when it has been idle past the idle timeout (a "walked away"
    /// control) or when it has been unlocked longer than the absolute cap (a backstop
    /// so continuous signing cannot keep it unlocked indefinitely). Call this
    /// periodically from a background task. Neither control stops a process running as
    /// the same user from using the agent within the window — they only bound the window.
    pub fn check_idle_timeout(&self) -> Result<bool, AgentError> {
        if (self.is_idle_timed_out() || self.is_unlock_window_expired()) && !self.is_agent_locked() {
            log::info!(
                "Locking agent: idle for {:?}, unlocked for {:?}",
                self.idle_duration(),
                self.unlock_age()
            );
            self.lock_agent()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Shuts down the agent, clearing all keys and resources.
    ///
    /// This method:
    /// 1. Clears all keys from the agent core (zeroizing sensitive data)
    /// 2. Marks the agent as not running
    /// 3. Optionally removes the socket file and PID file
    #[allow(clippy::disallowed_methods)] // INVARIANT: daemon lifecycle — socket/PID cleanup is inherently I/O
    pub fn shutdown(&self) -> Result<(), AgentError> {
        log::info!("Shutting down agent at {:?}", self.socket_path);

        // Clear all keys (zeroizes sensitive data)
        {
            let mut core = self.lock()?;
            core.clear_keys();
            log::debug!("Cleared all keys from agent core");
        }

        // Mark as not running
        self.set_running(false);

        // Remove socket file if it exists
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                log::warn!("Failed to remove socket file {:?}: {}", self.socket_path, e);
            } else {
                log::debug!("Removed socket file {:?}", self.socket_path);
            }
        }

        // Remove PID file if it exists
        if let Some(ref pid_file) = self.pid_file
            && pid_file.exists()
        {
            if let Err(e) = std::fs::remove_file(pid_file) {
                log::warn!("Failed to remove PID file {:?}: {}", pid_file, e);
            } else {
                log::debug!("Removed PID file {:?}", pid_file);
            }
        }

        log::info!("Agent shutdown complete");
        Ok(())
    }

    /// Returns the number of keys currently loaded in the agent.
    pub fn key_count(&self) -> Result<usize, AgentError> {
        let core = self.lock()?;
        Ok(core.key_count())
    }

    /// Returns all public key bytes currently registered.
    pub fn public_keys(&self) -> Result<Vec<Vec<u8>>, AgentError> {
        let core = self.lock()?;
        Ok(core.public_keys())
    }

    /// Registers a key in the agent core.
    pub fn register_key(&self, pkcs8_bytes: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        {
            let mut core = self.lock()?;
            core.register_key(pkcs8_bytes)?;
        }
        if let Ok(mut unlocked) = self.unlocked_at.lock() {
            *unlocked = Instant::now(); // Loading a key starts the absolute unlock window
        }
        Ok(())
    }

    /// Signs data using a key in the agent core.
    ///
    /// # Errors
    /// Returns `AgentError::AgentLocked` if the agent is locked.
    pub fn sign(&self, pubkey: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        // Check if agent is locked
        if self.is_agent_locked() {
            return Err(AgentError::AgentLocked);
        }

        let core = self.lock()?;
        let result = core.sign(pubkey, data);

        // Touch on successful sign to reset idle timer
        if result.is_ok() {
            self.touch();
        }

        result
    }
}

impl Clone for AgentHandle {
    fn clone(&self) -> Self {
        Self {
            core: Arc::clone(&self.core),
            socket_path: self.socket_path.clone(),
            pid_file: self.pid_file.clone(),
            running: Arc::clone(&self.running),
            last_activity: Arc::clone(&self.last_activity),
            idle_timeout: self.idle_timeout,
            unlocked_at: Arc::clone(&self.unlocked_at),
            max_unlock_ttl: self.max_unlock_ttl,
            locked: Arc::clone(&self.locked),
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use tempfile::TempDir;

    fn generate_test_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate PKCS#8");
        pkcs8_doc.as_ref().to_vec()
    }

    #[test]
    fn test_agent_handle_new() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(handle.socket_path(), &PathBuf::from("/tmp/test.sock"));
        assert!(handle.pid_file().is_none());
        assert!(!handle.is_running());
    }

    #[test]
    fn test_agent_handle_with_pid_file() {
        let handle = AgentHandle::with_pid_file(
            PathBuf::from("/tmp/test.sock"),
            PathBuf::from("/tmp/test.pid"),
        );
        assert_eq!(handle.socket_path(), &PathBuf::from("/tmp/test.sock"));
        assert_eq!(handle.pid_file(), Some(&PathBuf::from("/tmp/test.pid")));
    }

    #[test]
    fn test_agent_handle_running_state() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        assert!(!handle.is_running());

        handle.set_running(true);
        assert!(handle.is_running());

        handle.set_running(false);
        assert!(!handle.is_running());
    }

    #[test]
    fn test_agent_handle_key_operations() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));

        assert_eq!(handle.key_count().unwrap(), 0);

        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        assert_eq!(handle.key_count().unwrap(), 1);

        let pubkeys = handle.public_keys().unwrap();
        assert_eq!(pubkeys.len(), 1);
    }

    #[test]
    fn test_agent_handle_clone_shares_state() {
        let handle1 = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        let handle2 = handle1.clone();

        let pkcs8_bytes = generate_test_pkcs8();
        handle1
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        // Both handles should see the same key
        assert_eq!(handle1.key_count().unwrap(), 1);
        assert_eq!(handle2.key_count().unwrap(), 1);
    }

    #[test]
    fn test_agent_handle_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create a dummy socket file
        std::fs::write(&socket_path, "dummy").unwrap();

        let handle = AgentHandle::new(socket_path.clone());
        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");
        handle.set_running(true);

        assert_eq!(handle.key_count().unwrap(), 1);
        assert!(handle.is_running());
        assert!(socket_path.exists());

        handle.shutdown().expect("Shutdown failed");

        assert_eq!(handle.key_count().unwrap(), 0);
        assert!(!handle.is_running());
        assert!(!socket_path.exists());
    }

    #[test]
    fn test_multiple_handles_independent() {
        let handle1 = AgentHandle::new(PathBuf::from("/tmp/agent1.sock"));
        let handle2 = AgentHandle::new(PathBuf::from("/tmp/agent2.sock"));

        let pkcs8_bytes = generate_test_pkcs8();
        handle1
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        // Handles are independent - handle2 should have no keys
        assert_eq!(handle1.key_count().unwrap(), 1);
        assert_eq!(handle2.key_count().unwrap(), 0);
    }

    #[test]
    fn test_agent_handle_lock_unlock() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));

        // Initially not locked
        assert!(!handle.is_agent_locked());

        // Add a key
        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");
        assert_eq!(handle.key_count().unwrap(), 1);

        // Lock the agent
        handle.lock_agent().expect("Lock failed");
        assert!(handle.is_agent_locked());
        assert_eq!(handle.key_count().unwrap(), 0); // Keys cleared

        // Unlock the agent
        handle.unlock_agent();
        assert!(!handle.is_agent_locked());
    }

    #[test]
    fn test_agent_handle_sign_when_locked() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));

        // Add a key
        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        // Get pubkey for signing
        let pubkeys = handle.public_keys().unwrap();
        let pubkey = &pubkeys[0];

        // Sign should work when not locked
        let result = handle.sign(pubkey, b"test data");
        assert!(result.is_ok());

        // Lock and try to sign
        handle.lock_agent().expect("Lock failed");
        let result = handle.sign(pubkey, b"test data");
        assert!(matches!(result, Err(AgentError::AgentLocked)));
    }

    #[test]
    fn test_agent_handle_idle_timeout() {
        // Create handle with very short timeout for testing
        let handle =
            AgentHandle::with_timeout(PathBuf::from("/tmp/test.sock"), Duration::from_millis(10));

        // Initially not timed out
        assert!(!handle.is_idle_timed_out());
        assert!(!handle.is_agent_locked());

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        // Should be timed out now
        assert!(handle.is_idle_timed_out());

        // Touch resets the timer
        handle.touch();
        assert!(!handle.is_idle_timed_out());
    }

    #[test]
    fn test_agent_handle_zero_timeout_never_expires() {
        // Create handle with zero timeout (never expires)
        let handle = AgentHandle::with_timeout(PathBuf::from("/tmp/test.sock"), Duration::ZERO);

        // Wait a bit
        std::thread::sleep(Duration::from_millis(10));

        // Should never be timed out
        assert!(!handle.is_idle_timed_out());
    }

    #[test]
    fn test_clone_shares_locked_state() {
        let handle_a = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        let handle_b = handle_a.clone();

        assert!(!handle_b.is_agent_locked());
        handle_a.lock_agent().unwrap();
        assert!(handle_b.is_agent_locked());

        handle_a.unlock_agent();
        assert!(!handle_b.is_agent_locked());
    }

    #[test]
    fn test_clone_shares_last_activity() {
        let handle_a =
            AgentHandle::with_timeout(PathBuf::from("/tmp/test.sock"), Duration::from_millis(50));
        let handle_b = handle_a.clone();

        std::thread::sleep(Duration::from_millis(60));
        assert!(handle_b.is_idle_timed_out());

        // Touch on clone A resets timer visible from clone B
        handle_a.touch();
        assert!(!handle_b.is_idle_timed_out());
    }

    #[test]
    fn test_clone_sign_returns_locked_after_other_clone_locks() {
        let handle_a = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        let handle_b = handle_a.clone();

        let pkcs8_bytes = generate_test_pkcs8();
        handle_a.register_key(Zeroizing::new(pkcs8_bytes)).unwrap();

        let pubkeys = handle_a.public_keys().unwrap();
        let pubkey = &pubkeys[0];

        assert!(handle_b.sign(pubkey, b"test data").is_ok());

        handle_a.lock_agent().unwrap();
        let result = handle_b.sign(pubkey, b"test data");
        assert!(matches!(result, Err(AgentError::AgentLocked)));
    }

    #[test]
    fn absolute_cap_locks_despite_continuous_activity() {
        // Idle timeout effectively never; only the absolute unlock cap can fire.
        let handle = AgentHandle::with_unlock_cap(
            PathBuf::from("/tmp/test.sock"),
            Duration::from_secs(3600),
            Duration::from_millis(80),
        );
        handle
            .register_key(Zeroizing::new(generate_test_pkcs8()))
            .unwrap();

        // Continuous activity keeps resetting the sliding idle timer.
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(25));
            handle.touch();
        }

        assert!(
            handle.is_unlock_window_expired(),
            "unlock window should be expired ~150ms past an 80ms cap"
        );
        let locked = handle.check_idle_timeout().unwrap();
        assert!(
            locked,
            "the absolute unlock cap must lock the agent regardless of activity"
        );
        assert!(handle.is_agent_locked());
        assert_eq!(handle.key_count().unwrap(), 0);
    }

    #[test]
    fn public_keys_empty_after_lock() {
        let handle = AgentHandle::new(PathBuf::from("/tmp/test.sock"));
        handle
            .register_key(Zeroizing::new(generate_test_pkcs8()))
            .unwrap();
        assert_eq!(handle.public_keys().unwrap().len(), 1);

        handle.lock_agent().unwrap();

        // Locking must clear keys before flipping the locked flag, so a listing request
        // observed while locked cannot leak the key set.
        assert!(handle.is_agent_locked());
        assert!(
            handle.public_keys().unwrap().is_empty(),
            "locking must clear keys so the key list cannot leak while locked"
        );
    }
}
